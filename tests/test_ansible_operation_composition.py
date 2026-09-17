import inspect
import json
import uuid
from pathlib import Path

import pytest
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
)
from test_ansible_operation_initiation import (
    _OTHER_OPERATION_ID,
    _initiate,
    _request,
    _second_cluster,
)
from test_ansible_operation_lifecycle import (
    _executables,
    _fresh_results,
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
from test_check_jump_hosts import (
    FakeRunner,
    _prepared_state,
    _recap,
    _run,
)
from test_check_jump_hosts import (
    _results as _public_results,
)

import scylla_vms.ansible.operation_composition as composition_module
from scylla_vms.ansible.operation_authorization import OperationAuthorizationStore
from scylla_vms.ansible.operation_binding import OperationPlanBindingStore
from scylla_vms.ansible.operation_composition import (
    ANSIBLE_CHECK_JUMP_HOSTS_OPERATION_REPORT_SCHEMA_VERSION,
    CheckJumpHostsInitiationStageState,
    CheckJumpHostsOperationState,
    coordinate_check_jump_hosts_operation,
)
from scylla_vms.ansible.operation_context import OperationContextStore
from scylla_vms.ansible.operation_execution import ExecutionAttemptState
from scylla_vms.ansible.operation_finalization import OperationFinalizationStore
from scylla_vms.ansible.operation_initiation import (
    initiate_check_jump_hosts_operation,
)
from scylla_vms.ansible.operation_lifecycle import (
    CheckJumpHostsLifecycleState,
    LifecycleEvidenceState,
    LifecycleExecutionState,
    LifecycleFinalizationState,
    LifecyclePreparationState,
    coordinate_check_jump_hosts_lifecycle,
)
from scylla_vms.cli import parse_operation_request
from scylla_vms.errors import (
    ExitCode,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.journal import JournalStatus, OperationJournalStore, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.process import ProcessResult, ProcessTimeoutError
from scylla_vms.state import StatePaths

_PRIVATE_PATH = "/private/operator/id_ed25519"
_SECRET = "obviously-fake-secret-value"


def _call(
    paths: StatePaths,
    request,
    runner: FakeCoordinatorRunner,
    executables,
    *,
    operation_id: uuid.UUID = _OPERATION_ID,
):
    with ClusterLock(paths, "check-jump-hosts", 0) as lock:
        return coordinate_check_jump_hosts_operation(
            paths.state_root,
            paths.cluster_root.name,
            operation_id,
            request,
            lock,
            runner=runner,
            executables=executables,
        )


def _snapshot(paths: StatePaths) -> dict[str, bytes]:
    return {
        item.name: item.read_bytes()
        for item in paths.operations.iterdir()
        if item.is_file()
    }


def _fresh(tmp_path: Path):
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    prepared = _prepare_journal(tmp_path)
    (prepared.paths.operations / f"{_OPERATION_ID}.json").unlink()
    return prepared


def _prepared_journal_at(tmp_path: Path):
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return _prepare_journal(tmp_path)


def test_fresh_one_call_orders_components_and_returns_redacted_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _fresh(tmp_path)
    runner = FakeCoordinatorRunner(_fresh_results(prepared))
    order: list[str] = []

    def initiate(*args, **kwargs):
        order.append("initiate")
        return initiate_check_jump_hosts_operation(*args, **kwargs)

    def lifecycle(*args, **kwargs):
        order.append("lifecycle")
        return coordinate_check_jump_hosts_lifecycle(*args, **kwargs)

    monkeypatch.setattr(
        composition_module, "initiate_check_jump_hosts_operation", initiate
    )
    monkeypatch.setattr(
        composition_module, "coordinate_check_jump_hosts_lifecycle", lifecycle
    )

    report = _call(
        prepared.paths,
        prepared.request,
        runner,
        _executables(tmp_path),
    )

    assert report.schema_version == (
        ANSIBLE_CHECK_JUMP_HOSTS_OPERATION_REPORT_SCHEMA_VERSION
    )
    assert report.state is CheckJumpHostsOperationState.SUCCEEDED
    assert report.initiation_state is CheckJumpHostsInitiationStageState.CREATED
    assert report.lifecycle_state is CheckJumpHostsLifecycleState.SUCCEEDED
    assert report.preparation_state is LifecyclePreparationState.CREATED
    assert report.execution_stage_state is LifecycleExecutionState.EXECUTED
    assert report.evidence_state is LifecycleEvidenceState.SEMANTIC_EVIDENCE_READY
    assert report.finalization_state is LifecycleFinalizationState.CREATED
    assert report.journal_status is JournalStatus.SUCCEEDED
    assert report.journal_phase is OperationPhase.JOURNAL
    assert report.target_count == 0
    assert report.planned_step_count == report.succeeded_step_count == 2
    assert (
        report.initiation_call_count,
        report.lifecycle_call_count,
        report.preparation_call_count,
        report.orchestration_call_count,
        report.coordinator_call_count,
        report.finalization_call_count,
    ) == (1, 1, 1, 1, 2, 1)
    assert order == ["initiate", "lifecycle"]
    stored = OperationJournalStore(prepared.paths, _OPERATION_ID).read(
        expected_cluster_uuid=prepared.metadata.record.cluster_uuid,
        expected_cluster_name=prepared.metadata.record.cluster_name,
    )
    assert stored.record.generation == 4
    assert runner.specs is not None and len(runner.specs) == 14
    playbooks = [
        " ".join(spec.argv) for spec in runner.specs if "--extra-vars" in spec.argv
    ]
    assert len(playbooks) == 2
    assert "inventory-preflight.yml" in playbooks[0]
    assert "connectivity-check.yml" in playbooks[1]

    encoded = json.dumps(report.to_object(), sort_keys=True)
    for forbidden in (
        "10.0.0.",
        "203.0.113.",
        "PRIVATE KEY",
        "ansible-playbook",
        "command_digest",
        "environment",
        "known_hosts",
        "route",
        "stdout",
        "variables_digest",
        _PRIVATE_PATH,
        _SECRET,
        str(prepared.paths.state_root),
        str(_OPERATION_ID),
    ):
        assert forbidden not in encoded


def test_generation_one_resume_reuses_initiation_then_completes(tmp_path: Path) -> None:
    prepared = _fresh(tmp_path)
    _initiate(prepared.paths, prepared.request)
    runner = FakeCoordinatorRunner(_fresh_results(prepared))

    report = _call(
        prepared.paths,
        prepared.request,
        runner,
        _executables(tmp_path),
    )

    assert report.state is CheckJumpHostsOperationState.SUCCEEDED
    assert report.initiation_state is CheckJumpHostsInitiationStageState.REUSED
    assert report.initiation_call_count == report.lifecycle_call_count == 1


def test_binding_only_and_prepared_prefixes_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding_only = _prepared_journal_at(tmp_path / "binding")
    with monkeypatch.context() as scoped:
        scoped.setattr(
            OperationContextStore,
            "write_locked",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                StatePersistenceError("injected context pause")
            ),
        )
        with pytest.raises(StatePersistenceError, match="context pause"):
            _prepare_checkpoints(binding_only)
    binding_report = _call(
        binding_only.paths,
        binding_only.request,
        FakeCoordinatorRunner(_fresh_results(binding_only)),
        _executables(tmp_path / "binding"),
    )
    assert binding_report.initiation_state is (
        CheckJumpHostsInitiationStageState.NOT_REQUIRED
    )
    assert binding_report.preparation_state is LifecyclePreparationState.RESUMED
    assert binding_report.initiation_call_count == 0

    prepared = _prepared_journal_at(tmp_path / "prepared")
    _prepare_checkpoints(prepared)
    prepared_report = _call(
        prepared.paths,
        prepared.request,
        FakeCoordinatorRunner(_fresh_results(prepared)),
        _executables(tmp_path / "prepared"),
    )
    assert prepared_report.state is CheckJumpHostsOperationState.SUCCEEDED
    assert prepared_report.preparation_state is LifecyclePreparationState.REUSED
    assert prepared_report.initiation_call_count == 0


def test_succeeded_execution_prefix_resumes_only_remaining_step(tmp_path: Path) -> None:
    prepared = _prepare_coordinator(tmp_path)
    _coordinate(prepared, FakeCoordinatorRunner(_results(prepared)))
    runner = FakeCoordinatorRunner(_results(prepared, ProcessResult(0, _recap(), "")))

    report = _call(
        prepared.paths,
        prepared.request,
        runner,
        prepared.executables,
    )

    assert report.state is CheckJumpHostsOperationState.SUCCEEDED
    assert report.initiation_state is (CheckJumpHostsInitiationStageState.NOT_REQUIRED)
    assert report.execution_stage_state is LifecycleExecutionState.RESUMED
    assert report.coordinator_call_count == 1
    assert runner.specs is not None and len(runner.specs) == 5


def test_semantic_evidence_ready_resumes_without_tools(tmp_path: Path) -> None:
    prepared = _prepare_coordinator(tmp_path)
    _orchestrate(prepared, FakeCoordinatorRunner(_successful_results(prepared)))
    runner = FakeCoordinatorRunner([])

    report = _call(
        prepared.paths,
        prepared.request,
        runner,
        prepared.executables,
    )

    assert report.state is CheckJumpHostsOperationState.SUCCEEDED
    assert report.execution_stage_state is LifecycleExecutionState.REUSED
    assert report.evidence_state is LifecycleEvidenceState.SEMANTIC_EVIDENCE_READY
    assert report.finalization_state is LifecycleFinalizationState.CREATED
    assert runner.specs == []


@pytest.mark.parametrize("partial", ["companion-only", "verify-prefix"])
def test_finalization_prefixes_resume_without_tools(
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

    runner = FakeCoordinatorRunner([])
    report = _call(
        prepared.paths,
        prepared.request,
        runner,
        prepared.executables,
    )

    assert report.state is CheckJumpHostsOperationState.SUCCEEDED
    assert report.finalization_state is LifecycleFinalizationState.REUSED
    assert report.finalization_call_count == 1
    assert runner.specs == []


def test_terminal_reentry_is_zero_write_zero_tool_and_skips_initiation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _complete(tmp_path)
    _finalize(prepared)
    before = _snapshot(prepared.paths)
    runner = FakeCoordinatorRunner([])

    def refuse_initiation(*args, **kwargs):
        raise AssertionError("terminal resume must not re-enter initiation")

    monkeypatch.setattr(
        composition_module,
        "initiate_check_jump_hosts_operation",
        refuse_initiation,
    )
    report = _call(
        prepared.paths,
        prepared.request,
        runner,
        prepared.executables,
    )

    assert report.state is CheckJumpHostsOperationState.SUCCEEDED
    assert report.initiation_state is (CheckJumpHostsInitiationStageState.NOT_REQUIRED)
    assert report.initiation_call_count == 0
    assert report.lifecycle_call_count == 1
    assert report.coordinator_call_count == 0
    assert _snapshot(prepared.paths) == before
    assert runner.specs == []


def test_initiation_block_prevents_lifecycle_and_preserves_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _fresh(tmp_path)
    _initiate(
        prepared.paths,
        prepared.request,
        operation_id=_OTHER_OPERATION_ID,
    )
    before = _snapshot(prepared.paths)

    def refuse_lifecycle(*args, **kwargs):
        raise AssertionError("blocked initiation must prevent lifecycle")

    monkeypatch.setattr(
        composition_module,
        "coordinate_check_jump_hosts_lifecycle",
        refuse_lifecycle,
    )
    report = _call(
        prepared.paths,
        prepared.request,
        FakeCoordinatorRunner([]),
        _executables(tmp_path),
    )

    assert report.state is CheckJumpHostsOperationState.BLOCKED
    assert report.initiation_state is CheckJumpHostsInitiationStageState.BLOCKED
    assert report.blockers == ("active-operation-conflict",)
    assert report.lifecycle_state is None
    assert report.initiation_call_count == 1
    assert report.lifecycle_call_count == 0
    assert _snapshot(prepared.paths) == before


@pytest.mark.parametrize("boundary", ["initiation", "lifecycle"])
def test_component_exception_preserves_exact_durable_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    prepared = _fresh(tmp_path)

    if boundary == "initiation":
        monkeypatch.setattr(
            composition_module,
            "initiate_check_jump_hosts_operation",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                StatePersistenceError("safe injected initiation boundary")
            ),
        )
    else:
        monkeypatch.setattr(
            composition_module,
            "coordinate_check_jump_hosts_lifecycle",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                StatePersistenceError("safe injected lifecycle boundary")
            ),
        )

    with pytest.raises(StatePersistenceError, match=f"safe injected {boundary}"):
        _call(
            prepared.paths,
            prepared.request,
            FakeCoordinatorRunner([]),
            _executables(tmp_path),
        )

    journal = prepared.paths.operations / f"{_OPERATION_ID}.json"
    assert journal.exists() is (boundary == "lifecycle")
    assert not OperationPlanBindingStore(prepared.paths, _OPERATION_ID).path.exists()
    assert not OperationContextStore(prepared.paths, _OPERATION_ID).path.exists()


def test_changed_request_target_kind_cluster_and_uuid_replay_fail_closed(
    tmp_path: Path,
) -> None:
    prepared = _prepared_journal_at(tmp_path / "changed")
    for changed in (
        _request(prepared.paths, "--jump-host", "jump-host-1"),
        _request(prepared.paths, "--connect-timeout-seconds", "3.5"),
    ):
        runner = FakeCoordinatorRunner([])
        with pytest.raises(StateConflictError, match="checkpoint drifted"):
            _call(prepared.paths, changed, runner, _executables(tmp_path / "changed"))
        assert runner.specs == []

    show = parse_operation_request(
        [
            "--cluster-name",
            "example",
            "--state-dir",
            str(prepared.paths.state_root),
            "show",
        ],
        environ={},
    )
    with pytest.raises(StateConflictError, match="kind conflicts"):
        _call(
            prepared.paths,
            show,
            FakeCoordinatorRunner([]),
            _executables(tmp_path / "changed"),
        )

    other = _second_cluster(prepared.paths)
    with pytest.raises(StateConflictError, match="identity conflicts"):
        _call(
            prepared.paths,
            _request(other),
            FakeCoordinatorRunner([]),
            _executables(tmp_path / "changed"),
        )

    replay = _fresh(tmp_path / "replay")
    other_replay = _second_cluster(replay.paths)
    _initiate(replay.paths, replay.request)
    with (
        ClusterLock(other_replay, "check-jump-hosts", 0) as lock,
        pytest.raises(StateConflictError, match="another cluster"),
    ):
        coordinate_check_jump_hosts_operation(
            other_replay.state_root,
            "other",
            _OPERATION_ID,
            _request(other_replay),
            lock,
            runner=FakeCoordinatorRunner([]),
            executables=_executables(tmp_path / "replay"),
        )


def test_authorization_and_companion_drift_stop_before_tools(tmp_path: Path) -> None:
    prepared = _prepare_journal(tmp_path)
    _prepare_checkpoints(prepared)
    authorization = OperationAuthorizationStore(prepared.paths, _OPERATION_ID).path
    authorization.write_text("{}\n", encoding="utf-8")
    authorization.chmod(0o600)
    runner = FakeCoordinatorRunner([])

    report = _call(
        prepared.paths,
        prepared.request,
        runner,
        _executables(tmp_path),
    )
    assert report.state is CheckJumpHostsOperationState.BLOCKED
    assert report.blockers == ("read-only-authorization-forbidden",)
    assert runner.specs == []

    authorization.unlink()
    context = OperationContextStore(prepared.paths, _OPERATION_ID).path
    document = json.loads(context.read_text(encoding="utf-8"))
    document["binding_digest"] = "sha256:" + "b" * 64
    context.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    context.chmod(0o600)
    with pytest.raises(StateConflictError, match="binding"):
        _call(
            prepared.paths,
            prepared.request,
            runner,
            _executables(tmp_path),
        )
    assert runner.specs == []


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (ProcessResult(2, _recap(failed=1), ""), ExecutionAttemptState.FAILED),
        (
            ProcessResult(4, _recap(unreachable=1), ""),
            ExecutionAttemptState.UNREACHABLE,
        ),
        (
            ProcessResult(0, "malformed output\n", ""),
            ExecutionAttemptState.MALFORMED_RESULT,
        ),
    ],
)
def test_failed_unreachable_and_malformed_results_never_retry(
    tmp_path: Path,
    result: ProcessResult,
    expected: ExecutionAttemptState,
) -> None:
    prepared = _prepare_coordinator(tmp_path)
    first = FakeCoordinatorRunner(
        [*_results(prepared)[:4], *_results(prepared, result)]
    )

    report = _call(
        prepared.paths,
        prepared.request,
        first,
        prepared.executables,
    )
    assert report.state is CheckJumpHostsOperationState.EXECUTION_STOPPED
    assert report.execution_state is expected
    assert report.manual_recovery_required
    assert not report.automatic_retry_allowed
    assert not OperationFinalizationStore(prepared.paths, _OPERATION_ID).path.exists()

    retry = FakeCoordinatorRunner([])
    repeated = _call(
        prepared.paths,
        prepared.request,
        retry,
        prepared.executables,
    )
    assert repeated.execution_state is expected
    assert repeated.coordinator_call_count == 0
    assert retry.specs == []


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ProcessTimeoutError("simulated timeout"), ExecutionAttemptState.TIMED_OUT),
        (KeyboardInterrupt(), ExecutionAttemptState.INTERRUPTED),
    ],
)
def test_timeout_and_interrupt_preserve_manual_recovery_state(
    tmp_path: Path,
    error: BaseException,
    expected: ExecutionAttemptState,
) -> None:
    prepared = _prepare_coordinator(tmp_path)
    runner = FakeCoordinatorRunner(
        [*_results(prepared)[:4], *_results(prepared)],
        fail_at=9,
        error=error,  # type: ignore[arg-type]
    )

    report = _call(
        prepared.paths,
        prepared.request,
        runner,
        prepared.executables,
    )

    assert report.state is CheckJumpHostsOperationState.EXECUTION_STOPPED
    assert report.execution_state is expected
    assert report.manual_recovery_required
    assert not report.automatic_retry_allowed


def test_crash_left_started_is_observed_without_retry(tmp_path: Path) -> None:
    prepared = _prepare_coordinator(tmp_path)
    runner = FakeCoordinatorRunner(
        [*_results(prepared)[:4], *_results(prepared)],
        fail_at=9,
        error=SimulatedCrash(),
    )
    with pytest.raises(SimulatedCrash):
        _call(
            prepared.paths,
            prepared.request,
            runner,
            prepared.executables,
        )

    retry = FakeCoordinatorRunner([])
    report = _call(
        prepared.paths,
        prepared.request,
        retry,
        prepared.executables,
    )
    assert report.state is CheckJumpHostsOperationState.EXECUTION_STOPPED
    assert report.execution_state is ExecutionAttemptState.STARTED
    assert report.manual_recovery_required
    assert report.coordinator_call_count == 0
    assert retry.specs == []


def test_api_requires_matching_held_lock_without_nested_acquisition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _fresh(tmp_path)
    parameters = inspect.signature(coordinate_check_jump_hosts_operation).parameters
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
        "confirmation",
    ):
        assert forbidden not in parameters

    unlocked = ClusterLock(prepared.paths, "check-jump-hosts", 0)
    with pytest.raises(StateLockError, match="matching acquired"):
        coordinate_check_jump_hosts_operation(
            prepared.paths.state_root,
            "example",
            _OPERATION_ID,
            prepared.request,
            unlocked,
            runner=FakeCoordinatorRunner([]),
            executables=_executables(tmp_path),
        )
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong,
        pytest.raises(StateLockError, match="matching operation"),
    ):
        coordinate_check_jump_hosts_operation(
            prepared.paths.state_root,
            "example",
            _OPERATION_ID,
            prepared.request,
            wrong,
            runner=FakeCoordinatorRunner([]),
            executables=_executables(tmp_path),
        )
    with (
        ClusterLock(prepared.paths, "check-jump-hosts", 0),
        pytest.raises(StateLockError, match="cluster lock is held"),
    ):
        ClusterLock(prepared.paths, "check-jump-hosts", 0).acquire()

    with ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock:
        monkeypatch.setattr(
            ClusterLock,
            "acquire",
            lambda self: (_ for _ in ()).throw(
                AssertionError("composition must not reacquire the lock")
            ),
        )
        report = coordinate_check_jump_hosts_operation(
            prepared.paths.state_root,
            "example",
            _OPERATION_ID,
            prepared.request,
            lock,
            runner=FakeCoordinatorRunner(_fresh_results(prepared)),
            executables=_executables(tmp_path),
        )
    assert report.state is CheckJumpHostsOperationState.SUCCEEDED


def test_public_check_jump_hosts_remains_write_free(tmp_path: Path) -> None:
    paths, inventory, _ = _prepared_state(tmp_path)
    before = _snapshot(paths)

    result, _, _ = _run(paths, FakeRunner(_public_results(inventory, _recap())))

    assert result == ExitCode.SUCCESS
    assert _snapshot(paths) == before
