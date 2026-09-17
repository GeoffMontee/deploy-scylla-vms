import inspect
import json
from dataclasses import replace
from pathlib import Path

import pytest
from test_ansible import _executable
from test_ansible_operation_binding import _OPERATION_ID
from test_ansible_operation_coordinator import (
    FakeCoordinatorRunner,
    _coordinate,
    _results,
)
from test_ansible_operation_coordinator import (
    _prepare as _prepare_coordinator,
)
from test_ansible_operation_execution import SimulatedCrash
from test_ansible_operation_finalization import (
    _complete,
    _finalize,
    _read_journal,
)
from test_ansible_operation_orchestrator import (
    _orchestrate,
    _successful_results,
)
from test_ansible_operation_preparation import (
    _call as _prepare_checkpoints,
)
from test_ansible_operation_preparation import (
    _prepare as _prepare_journal,
)
from test_check_jump_hosts import _prepared_state, _recap

import scylla_vms.ansible.operation_lifecycle as lifecycle_module
from scylla_vms.ansible.operation_authorization import OperationAuthorizationStore
from scylla_vms.ansible.operation_binding import OperationPlanBindingStore
from scylla_vms.ansible.operation_context import (
    OPERATION_CONTEXT_UNMODELED,
    OperationContextStore,
)
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.operation_evidence import OperationEvidenceStore
from scylla_vms.ansible.operation_execution import (
    ExecutionAttemptState,
    OperationExecutionStore,
)
from scylla_vms.ansible.operation_finalization import (
    OperationFinalizationStore,
    finalize_prepared_check_jump_hosts,
)
from scylla_vms.ansible.operation_lifecycle import (
    ANSIBLE_CHECK_JUMP_HOSTS_LIFECYCLE_REPORT_SCHEMA_VERSION,
    CheckJumpHostsLifecycleState,
    LifecycleEvidenceState,
    LifecycleExecutionState,
    LifecycleFinalizationState,
    LifecyclePreparationState,
    coordinate_check_jump_hosts_lifecycle,
)
from scylla_vms.ansible.operation_orchestrator import (
    orchestrate_prepared_check_jump_hosts,
)
from scylla_vms.ansible.operation_preparation import (
    prepare_ansible_operation_checkpoints,
)
from scylla_vms.cli import parse_operation_request
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import JournalStatus, OperationJournalStore, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import serialize_json
from scylla_vms.process import ProcessResult, ProcessTimeoutError
from scylla_vms.state import StatePaths

_PRIVATE_PATH = "/private/operator/id_ed25519"
_SECRET = "obviously-fake-secret-value"


def _executables(tmp_path: Path) -> ControlledAnsibleExecutables:
    return ControlledAnsibleExecutables(
        _executable(tmp_path, "ansible-playbook"),
        _executable(tmp_path, "ansible-inventory"),
    )


def _call_lifecycle(
    paths: StatePaths,
    runner: FakeCoordinatorRunner,
    executables: ControlledAnsibleExecutables,
    *,
    request=None,
):
    with ClusterLock(paths, "check-jump-hosts", 0) as lock:
        return coordinate_check_jump_hosts_lifecycle(
            paths.state_root,
            paths.cluster_root.name,
            _OPERATION_ID,
            request,
            lock,
            runner=runner,
            executables=executables,
        )


def _fresh_results(prepared) -> list[ProcessResult]:
    return [*_results(prepared)[:4], *_successful_results(prepared)]


def _operation_snapshot(paths: StatePaths) -> dict[str, bytes]:
    return {
        path.name: path.read_bytes()
        for path in paths.operations.iterdir()
        if path.is_file()
    }


def test_fresh_fake_lifecycle_orders_components_tools_and_redacted_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare_journal(tmp_path)
    executables = _executables(tmp_path)
    runner = FakeCoordinatorRunner(_fresh_results(prepared))
    component_order: list[str] = []
    originals = (
        prepare_ansible_operation_checkpoints,
        orchestrate_prepared_check_jump_hosts,
        finalize_prepared_check_jump_hosts,
    )

    def prepare(*args, **kwargs):
        component_order.append("prepare")
        return originals[0](*args, **kwargs)

    def orchestrate(*args, **kwargs):
        component_order.append("orchestrate")
        return originals[1](*args, **kwargs)

    def finalize(*args, **kwargs):
        component_order.append("finalize")
        return originals[2](*args, **kwargs)

    monkeypatch.setattr(
        lifecycle_module, "prepare_ansible_operation_checkpoints", prepare
    )
    monkeypatch.setattr(
        lifecycle_module, "orchestrate_prepared_check_jump_hosts", orchestrate
    )
    monkeypatch.setattr(
        lifecycle_module, "finalize_prepared_check_jump_hosts", finalize
    )

    report = _call_lifecycle(
        prepared.paths,
        runner,
        executables,
        request=prepared.request,
    )

    assert report.schema_version == (
        ANSIBLE_CHECK_JUMP_HOSTS_LIFECYCLE_REPORT_SCHEMA_VERSION
    )
    assert report.state is CheckJumpHostsLifecycleState.SUCCEEDED
    assert report.preparation_state is LifecyclePreparationState.CREATED
    assert report.execution_stage_state is LifecycleExecutionState.EXECUTED
    assert report.evidence_state is LifecycleEvidenceState.SEMANTIC_EVIDENCE_READY
    assert report.finalization_state is LifecycleFinalizationState.CREATED
    assert report.journal_status is JournalStatus.SUCCEEDED
    assert report.journal_phase is OperationPhase.JOURNAL
    assert report.execution_state is ExecutionAttemptState.SUCCEEDED
    assert report.planned_step_count == report.succeeded_step_count == 2
    assert report.coordinator_call_count == 2
    assert (
        report.preparation_call_count,
        report.orchestration_call_count,
        report.finalization_call_count,
    ) == (1, 1, 1)
    assert component_order == ["prepare", "orchestrate", "finalize"]
    assert runner.specs is not None
    assert len(runner.specs) == 14
    playbooks = [
        " ".join(spec.argv) for spec in runner.specs if "--extra-vars" in spec.argv
    ]
    assert len(playbooks) == 2
    assert "inventory-preflight.yml" in playbooks[0]
    assert "connectivity-check.yml" in playbooks[1]
    assert not OperationAuthorizationStore(prepared.paths, _OPERATION_ID).path.exists()
    encoded = json.dumps(report.to_object(), sort_keys=True)
    for forbidden in (
        "10.0.0.",
        "203.0.113.",
        "PRIVATE KEY",
        "ansible-playbook",
        "command_digest",
        "environment",
        "known_hosts",
        "route_mode",
        "stdout",
        "variables_digest",
        _PRIVATE_PATH,
        _SECRET,
        str(prepared.paths.state_root),
    ):
        assert forbidden not in encoded


def test_existing_context_prefix_reconstructs_request_and_reuses_preparation(
    tmp_path: Path,
) -> None:
    prepared = _prepare_journal(tmp_path)
    _prepare_checkpoints(prepared)
    runner = FakeCoordinatorRunner(_fresh_results(prepared))

    report = _call_lifecycle(
        prepared.paths,
        runner,
        _executables(tmp_path),
        request=None,
    )

    assert report.state is CheckJumpHostsLifecycleState.SUCCEEDED
    assert report.preparation_state is LifecyclePreparationState.REUSED
    assert report.preparation_call_count == 1
    assert report.coordinator_call_count == 2


def test_binding_only_prefix_resumes_with_exact_caller_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare_journal(tmp_path)

    with monkeypatch.context() as scoped:
        scoped.setattr(
            OperationContextStore,
            "write_locked",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                StatePersistenceError("injected context pause")
            ),
        )
        with pytest.raises(StatePersistenceError, match="context pause"):
            _prepare_checkpoints(prepared)

    assert OperationPlanBindingStore(prepared.paths, _OPERATION_ID).path.exists()
    assert not OperationContextStore(prepared.paths, _OPERATION_ID).path.exists()
    runner = FakeCoordinatorRunner(_fresh_results(prepared))

    report = _call_lifecycle(
        prepared.paths,
        runner,
        _executables(tmp_path),
        request=prepared.request,
    )

    assert report.state is CheckJumpHostsLifecycleState.SUCCEEDED
    assert report.preparation_state is LifecyclePreparationState.RESUMED
    assert report.coordinator_call_count == 2


def test_succeeded_execution_prefix_resumes_only_remaining_step(tmp_path: Path) -> None:
    prepared = _prepare_coordinator(tmp_path)
    _coordinate(prepared, FakeCoordinatorRunner(_results(prepared)))
    runner = FakeCoordinatorRunner(_results(prepared, ProcessResult(0, _recap(), "")))

    report = _call_lifecycle(
        prepared.paths,
        runner,
        prepared.executables,
        request=None,
    )

    assert report.state is CheckJumpHostsLifecycleState.SUCCEEDED
    assert report.preparation_state is LifecyclePreparationState.NOT_REQUIRED
    assert report.execution_stage_state is LifecycleExecutionState.RESUMED
    assert report.preparation_call_count == 0
    assert report.coordinator_call_count == 1
    assert runner.specs is not None and len(runner.specs) == 5


def test_semantic_evidence_ready_skips_tools_and_proceeds_to_finalization(
    tmp_path: Path,
) -> None:
    prepared = _prepare_coordinator(tmp_path)
    _orchestrate(prepared, FakeCoordinatorRunner(_successful_results(prepared)))
    runner = FakeCoordinatorRunner([])

    report = _call_lifecycle(
        prepared.paths,
        runner,
        prepared.executables,
        request=None,
    )

    assert report.state is CheckJumpHostsLifecycleState.SUCCEEDED
    assert report.execution_stage_state is LifecycleExecutionState.REUSED
    assert report.coordinator_call_count == 0
    assert report.orchestration_call_count == 1
    assert report.finalization_state is LifecycleFinalizationState.CREATED
    assert runner.specs == []


def test_legacy_complete_execution_without_semantic_evidence_stops(
    tmp_path: Path,
) -> None:
    prepared = _prepare_coordinator(tmp_path)
    _orchestrate(prepared, FakeCoordinatorRunner(_successful_results(prepared)))
    OperationEvidenceStore(prepared.paths, _OPERATION_ID).path.unlink()
    runner = FakeCoordinatorRunner([])

    report = _call_lifecycle(
        prepared.paths,
        runner,
        prepared.executables,
        request=None,
    )

    assert report.state is CheckJumpHostsLifecycleState.EXECUTION_STOPPED
    assert report.blockers == ("semantic-evidence-missing",)
    assert report.evidence_state is LifecycleEvidenceState.POST_VERIFICATION_PENDING
    assert report.manual_recovery_required
    assert report.finalization_call_count == 0
    assert runner.specs == []


@pytest.mark.parametrize("partial", ["companion-only", "verify-prefix"])
def test_finalization_partials_resume_without_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    partial: str,
) -> None:
    prepared = _complete(tmp_path / partial)
    original = OperationJournalStore.write

    def fail_journal(self, record, **kwargs):
        if partial == "companion-only" or record.status is JournalStatus.SUCCEEDED:
            raise StatePersistenceError(f"injected {partial} pause")
        return original(self, record, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(OperationJournalStore, "write", fail_journal)
        with pytest.raises(StatePersistenceError, match="injected"):
            _finalize(prepared)

    journal = _read_journal(prepared)
    assert journal.record.phase is (
        OperationPhase.PLAN if partial == "companion-only" else OperationPhase.VERIFY
    )
    runner = FakeCoordinatorRunner([])

    report = _call_lifecycle(
        prepared.paths,
        runner,
        prepared.executables,
        request=None,
    )

    assert report.state is CheckJumpHostsLifecycleState.SUCCEEDED
    assert report.finalization_state is LifecycleFinalizationState.REUSED
    assert report.preparation_call_count == report.orchestration_call_count == 0
    assert report.finalization_call_count == 1
    assert runner.specs == []


def test_terminal_success_reentry_has_zero_writes_and_zero_tool_calls(
    tmp_path: Path,
) -> None:
    prepared = _complete(tmp_path)
    _finalize(prepared)
    before = _operation_snapshot(prepared.paths)
    runner = FakeCoordinatorRunner([])

    report = _call_lifecycle(
        prepared.paths,
        runner,
        prepared.executables,
        request=None,
    )

    assert report.state is CheckJumpHostsLifecycleState.SUCCEEDED
    assert report.finalization_state is LifecycleFinalizationState.REUSED
    assert _operation_snapshot(prepared.paths) == before
    assert runner.specs == []


@pytest.mark.parametrize("case", ["wrong-kind", "wrong-class"])
def test_wrong_request_kind_or_class_blocks_before_writes_or_tools(
    tmp_path: Path,
    case: str,
) -> None:
    prepared = _prepare_journal(tmp_path)
    if case == "wrong-kind":
        request = parse_operation_request(
            [
                "--cluster-name",
                "example",
                "--state-dir",
                str(prepared.paths.state_root),
                "show",
            ],
            environ={},
        )
        blocker = OPERATION_CONTEXT_UNMODELED
    else:
        request = replace(
            prepared.request,
            operation=replace(
                prepared.request.operation,
                classification=OperationClassification.MUTATING,
            ),
        )
        blocker = "operation-classification-conflict"
    before = _operation_snapshot(prepared.paths)
    runner = FakeCoordinatorRunner([])

    report = _call_lifecycle(
        prepared.paths,
        runner,
        _executables(tmp_path),
        request=request,
    )

    assert report.state is CheckJumpHostsLifecycleState.BLOCKED
    assert blocker in report.blockers
    assert _operation_snapshot(prepared.paths) == before
    assert runner.specs == []


def test_missing_journal_is_a_stable_no_write_prerequisite_blocker(
    tmp_path: Path,
) -> None:
    paths, _, _ = _prepared_state(tmp_path)
    before = _operation_snapshot(paths)
    runner = FakeCoordinatorRunner([])

    report = _call_lifecycle(paths, runner, _executables(tmp_path), request=None)

    assert report.state is CheckJumpHostsLifecycleState.BLOCKED
    assert report.blockers == ("operation-journal-missing",)
    assert report.journal_status is None
    assert _operation_snapshot(paths) == before
    assert runner.specs == []


def test_forbidden_authorization_and_request_at_reconstructable_stage_block(
    tmp_path: Path,
) -> None:
    prepared = _prepare_journal(tmp_path)
    _prepare_checkpoints(prepared)
    authorization = OperationAuthorizationStore(prepared.paths, _OPERATION_ID).path
    authorization.write_text("{}\n", encoding="utf-8")
    authorization.chmod(0o600)
    runner = FakeCoordinatorRunner([])

    report = _call_lifecycle(
        prepared.paths,
        runner,
        _executables(tmp_path),
        request=None,
    )
    assert report.blockers == ("read-only-authorization-forbidden",)
    assert runner.specs == []

    authorization.unlink()
    report = _call_lifecycle(
        prepared.paths,
        runner,
        _executables(tmp_path),
        request=prepared.request,
    )
    assert report.blockers == ("operation-request-unexpected",)
    assert runner.specs == []


@pytest.mark.parametrize(
    ("exit_code", "recap", "expected"),
    [
        (2, _recap(failed=1), ExecutionAttemptState.FAILED),
        (4, _recap(unreachable=1), ExecutionAttemptState.UNREACHABLE),
        (0, "malformed output\n", ExecutionAttemptState.MALFORMED_RESULT),
    ],
)
def test_uncertain_execution_stops_without_retry_or_finalization(
    tmp_path: Path,
    exit_code: int,
    recap: str,
    expected: ExecutionAttemptState,
) -> None:
    prepared = _prepare_coordinator(tmp_path)
    _orchestrate(
        prepared,
        FakeCoordinatorRunner(
            [
                *_results(prepared),
                *_results(prepared, ProcessResult(exit_code, recap, "")),
            ]
        ),
    )
    runner = FakeCoordinatorRunner([])

    report = _call_lifecycle(
        prepared.paths,
        runner,
        prepared.executables,
        request=None,
    )

    assert report.state is CheckJumpHostsLifecycleState.EXECUTION_STOPPED
    assert report.execution_stage_state is LifecycleExecutionState.STOPPED
    assert report.execution_state is expected
    assert report.manual_recovery_required
    assert not report.automatic_retry_allowed
    assert report.finalization_call_count == 0
    assert not OperationFinalizationStore(prepared.paths, _OPERATION_ID).path.exists()
    assert runner.specs == []


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ProcessTimeoutError("simulated timeout"), ExecutionAttemptState.TIMED_OUT),
        (KeyboardInterrupt(), ExecutionAttemptState.INTERRUPTED),
    ],
)
def test_timeout_and_interrupt_stop_without_lifecycle_retry(
    tmp_path: Path,
    error: BaseException,
    expected: ExecutionAttemptState,
) -> None:
    prepared = _prepare_coordinator(tmp_path)
    runner = FakeCoordinatorRunner(
        _results(prepared)[:4],
        fail_at=5,
        error=error,  # type: ignore[arg-type]
    )
    _orchestrate(prepared, runner)
    retry = FakeCoordinatorRunner([])

    report = _call_lifecycle(
        prepared.paths,
        retry,
        prepared.executables,
        request=None,
    )

    assert report.state is CheckJumpHostsLifecycleState.EXECUTION_STOPPED
    assert report.execution_state is expected
    assert report.manual_recovery_required
    assert report.coordinator_call_count == 0
    assert retry.specs == []


def test_started_ambiguity_is_observed_without_retry(tmp_path: Path) -> None:
    prepared = _prepare_coordinator(tmp_path)
    runner = FakeCoordinatorRunner(
        _results(prepared)[:4],
        fail_at=5,
        error=SimulatedCrash(),
    )
    with pytest.raises(SimulatedCrash):
        _orchestrate(prepared, runner)
    retry = FakeCoordinatorRunner([])

    report = _call_lifecycle(
        prepared.paths,
        retry,
        prepared.executables,
        request=None,
    )

    assert report.state is CheckJumpHostsLifecycleState.EXECUTION_STOPPED
    assert report.execution_state is ExecutionAttemptState.STARTED
    assert report.manual_recovery_required
    assert report.coordinator_call_count == 0
    assert retry.specs == []


@pytest.mark.parametrize("boundary", ["preparation", "orchestration", "finalization"])
def test_component_failure_boundaries_preserve_exact_durable_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    case_path = tmp_path / boundary
    case_path.mkdir(mode=0o700)
    prepared = _prepare_journal(case_path)
    runner = FakeCoordinatorRunner(_fresh_results(prepared))
    target = {
        "preparation": "prepare_ansible_operation_checkpoints",
        "orchestration": "orchestrate_prepared_check_jump_hosts",
        "finalization": "finalize_prepared_check_jump_hosts",
    }[boundary]
    original = getattr(lifecycle_module, target)

    def fail(*args, **kwargs):
        if boundary == "preparation":
            raise StatePersistenceError("injected preparation boundary")
        if boundary == "orchestration":
            raise StatePersistenceError("injected orchestration boundary")
        raise StatePersistenceError("injected finalization boundary")

    monkeypatch.setattr(lifecycle_module, target, fail)
    with pytest.raises(StatePersistenceError, match=f"injected {boundary}"):
        _call_lifecycle(
            prepared.paths,
            runner,
            _executables(case_path),
            request=prepared.request,
        )
    monkeypatch.setattr(lifecycle_module, target, original)

    binding = OperationPlanBindingStore(prepared.paths, _OPERATION_ID).path
    context = OperationContextStore(prepared.paths, _OPERATION_ID).path
    execution = OperationExecutionStore(prepared.paths, _OPERATION_ID).path
    finalization = OperationFinalizationStore(prepared.paths, _OPERATION_ID).path
    if boundary == "preparation":
        assert not binding.exists() and not context.exists()
    elif boundary == "orchestration":
        assert binding.exists() and context.exists() and not execution.exists()
    else:
        assert execution.exists() and not finalization.exists()


def test_api_lock_path_permissions_and_symlink_guards(tmp_path: Path) -> None:
    api_path = tmp_path / "api"
    api_path.mkdir(mode=0o700)
    prepared = _prepare_journal(api_path)
    parameters = inspect.signature(coordinate_check_jump_hosts_lifecycle).parameters
    assert tuple(parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "request",
        "lock",
        "runner",
        "executables",
    )
    for forbidden in (
        "plan",
        "steps",
        "paths",
        "commands",
        "variables",
        "environment",
        "evidence",
        "finalization",
    ):
        assert forbidden not in parameters
    unlocked = ClusterLock(prepared.paths, "check-jump-hosts", 0)
    with pytest.raises(StateLockError):
        coordinate_check_jump_hosts_lifecycle(
            prepared.paths.state_root,
            "example",
            _OPERATION_ID,
            prepared.request,
            unlocked,
            runner=FakeCoordinatorRunner([]),
            executables=_executables(api_path),
        )
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong,
        pytest.raises(StateLockError, match="matching operation"),
    ):
        coordinate_check_jump_hosts_lifecycle(
            prepared.paths.state_root,
            "example",
            _OPERATION_ID,
            prepared.request,
            wrong,
            runner=FakeCoordinatorRunner([]),
            executables=_executables(api_path),
        )
    journal = prepared.paths.operations / f"{_OPERATION_ID}.json"
    journal.chmod(0o644)
    with pytest.raises(UnsafePathError, match="0600"):
        _call_lifecycle(
            prepared.paths,
            FakeCoordinatorRunner([]),
            _executables(api_path),
            request=prepared.request,
        )

    symlink_path = tmp_path / "symlink"
    symlink_path.mkdir(mode=0o700)
    symlinked = _prepare_journal(symlink_path)
    binding = OperationPlanBindingStore(symlinked.paths, _OPERATION_ID).path
    target = tmp_path / "outside-binding.json"
    target.write_bytes(serialize_json({}))
    target.chmod(0o600)
    binding.symlink_to(target)
    with pytest.raises(UnsafePathError, match="symbolic link"):
        _call_lifecycle(
            symlinked.paths,
            FakeCoordinatorRunner([]),
            _executables(symlink_path),
            request=symlinked.request,
        )


def test_context_binding_drift_stops_before_tool_probe(tmp_path: Path) -> None:
    prepared = _prepare_journal(tmp_path)
    _prepare_checkpoints(prepared)
    context_path = OperationContextStore(prepared.paths, _OPERATION_ID).path
    document = json.loads(context_path.read_text(encoding="utf-8"))
    document["binding_digest"] = "sha256:" + "b" * 64
    context_path.write_bytes(serialize_json(document))
    context_path.chmod(0o600)
    runner = FakeCoordinatorRunner([])

    with pytest.raises(StateConflictError, match="binding"):
        _call_lifecycle(
            prepared.paths,
            runner,
            _executables(tmp_path),
            request=None,
        )

    assert runner.specs == []


def test_rendered_controller_drift_stops_before_tool_probe_or_checkpoint(
    tmp_path: Path,
) -> None:
    prepared = _prepare_journal(tmp_path)
    prepared.paths.ansible_config.write_text("tampered\n", encoding="utf-8")
    prepared.paths.ansible_config.chmod(0o600)
    runner = FakeCoordinatorRunner([])

    with pytest.raises(StatePersistenceError, match="config"):
        _call_lifecycle(
            prepared.paths,
            runner,
            _executables(tmp_path),
            request=prepared.request,
        )

    assert runner.specs == []
    assert not OperationPlanBindingStore(prepared.paths, _OPERATION_ID).path.exists()
    assert not OperationContextStore(prepared.paths, _OPERATION_ID).path.exists()
