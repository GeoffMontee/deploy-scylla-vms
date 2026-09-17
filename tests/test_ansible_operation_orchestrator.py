import inspect
import json
from pathlib import Path

import pytest
from test_ansible_operation_binding import _OPERATION_ID
from test_ansible_operation_coordinator import (
    FakeCoordinatorRunner,
    PreparedCoordinator,
    _coordinate,
    _prepare,
    _read_execution,
    _results,
)
from test_ansible_operation_execution import SimulatedCrash
from test_check_jump_hosts import _recap

import scylla_vms.ansible.operation_orchestrator as orchestrator_module
from scylla_vms.ansible.operation_binding import OperationPlanBindingStore
from scylla_vms.ansible.operation_context import OperationContextStore
from scylla_vms.ansible.operation_evidence import OperationEvidenceStore
from scylla_vms.ansible.operation_execution import (
    ExecutionAttemptState,
    OperationExecutionStore,
)
from scylla_vms.ansible.operation_orchestrator import (
    ANSIBLE_CHECK_JUMP_HOSTS_ORCHESTRATION_REPORT_SCHEMA_VERSION,
    CheckJumpHostsFinalizationState,
    CheckJumpHostsOrchestrationState,
    orchestrate_prepared_check_jump_hosts,
)
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.persistence import serialize_json
from scylla_vms.process import ProcessResult, ProcessTimeoutError

_OTHER_DIGEST = "sha256:" + "b" * 64
_SECRET = "obviously-fake-secret-value"
_PRIVATE_PATH = "/private/operator/id_ed25519"


def _orchestrate(
    prepared: PreparedCoordinator,
    runner: FakeCoordinatorRunner,
):
    with ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock:
        return orchestrate_prepared_check_jump_hosts(
            prepared.paths.state_root,
            prepared.metadata.record.cluster_name,
            _OPERATION_ID,
            lock,
            runner=runner,
            executables=prepared.executables,
        )


def _successful_results(prepared: PreparedCoordinator) -> list[ProcessResult]:
    return [
        *_results(prepared),
        *_results(prepared, ProcessResult(0, _recap(), "")),
    ]


def _write_document(path: Path, document: dict[str, object]) -> None:
    path.write_bytes(serialize_json(document))
    path.chmod(0o600)


def test_orchestrator_drives_exact_multi_step_sequence_and_retains_semantic_evidence(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    journal_path = prepared.paths.operations / f"{_OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()
    runner = FakeCoordinatorRunner(_successful_results(prepared))

    report = _orchestrate(prepared, runner)

    assert (
        report.schema_version
        == ANSIBLE_CHECK_JUMP_HOSTS_ORCHESTRATION_REPORT_SCHEMA_VERSION
    )
    assert report.state is CheckJumpHostsOrchestrationState.STEPS_SUCCEEDED
    assert (
        report.finalization_state
        is CheckJumpHostsFinalizationState.SEMANTIC_EVIDENCE_READY
    )
    assert report.planned_step_count == 2
    assert report.succeeded_step_count == 2
    assert report.coordinator_call_count == 2
    assert report.latest_outcome is ExecutionAttemptState.SUCCEEDED
    assert not report.manual_recovery_required
    assert not report.automatic_retry_allowed
    assert runner.specs is not None
    assert len(runner.specs) == 10
    playbook_specs = [spec for spec in runner.specs if "--extra-vars" in spec.argv]
    assert len(playbook_specs) == 2
    assert "inventory-preflight.yml" in " ".join(playbook_specs[0].argv)
    assert "connectivity-check.yml" in " ".join(playbook_specs[1].argv)
    execution = _read_execution(prepared)
    assert tuple(item.step_sequence for item in execution.record.attempts) == (1, 2)
    assert tuple(item.playbook for item in execution.record.attempts) == (
        "inventory-preflight",
        "connectivity-check",
    )
    assert journal_path.read_bytes() == journal_before
    assert not (
        prepared.paths.operations
        / f"{_OPERATION_ID}.ansible-operation-authorization.json"
    ).exists()

    projected = report.to_object()
    assert projected["state"] == "steps-succeeded"
    assert projected["finalization"] == {
        "common_journal": "unchanged-plan",
        "healthy_claimed": False,
        "public_report_reconstructable": True,
        "state": "semantic-evidence-ready",
    }
    encoded = json.dumps(projected)
    assert _SECRET not in encoded
    assert _PRIVATE_PATH not in encoded
    assert str(_OPERATION_ID) not in encoded
    assert str(prepared.metadata.record.cluster_uuid) not in encoded
    assert "jump-host-1" not in encoded
    assert "deploy-scylla-vms.check-jump-hosts/v2" not in encoded


def test_orchestrator_continues_succeeded_prefix_and_complete_reentry_is_idempotent(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    _coordinate(prepared, FakeCoordinatorRunner(_results(prepared)))
    continuation = FakeCoordinatorRunner(
        _results(prepared, ProcessResult(0, _recap(), ""))
    )

    report = _orchestrate(prepared, continuation)

    assert report.state is CheckJumpHostsOrchestrationState.STEPS_SUCCEEDED
    assert report.coordinator_call_count == 1
    assert continuation.specs is not None
    assert len(continuation.specs) == 5
    assert (
        len([spec for spec in continuation.specs if "--extra-vars" in spec.argv]) == 1
    )

    reentry = FakeCoordinatorRunner([])
    repeated = _orchestrate(prepared, reentry)
    assert repeated.state is CheckJumpHostsOrchestrationState.STEPS_SUCCEEDED
    assert repeated.coordinator_call_count == 0
    assert repeated.to_object()["finalization"] == report.to_object()["finalization"]
    assert reentry.specs == []


def test_legacy_complete_execution_without_semantic_evidence_remains_pending(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    complete = FakeCoordinatorRunner(_successful_results(prepared))
    _orchestrate(prepared, complete)
    OperationEvidenceStore(prepared.paths, _OPERATION_ID).path.unlink()

    reentry = FakeCoordinatorRunner([])
    report = _orchestrate(prepared, reentry)

    assert report.state is CheckJumpHostsOrchestrationState.STEPS_SUCCEEDED
    assert (
        report.finalization_state
        is CheckJumpHostsFinalizationState.POST_VERIFICATION_PENDING
    )
    assert report.to_object()["finalization"]["public_report_reconstructable"] is False
    assert reentry.specs == []


@pytest.mark.parametrize(
    ("field", "value", "error_type"),
    [
        ("operation", "show", StateLockError),
        ("effective_classification", "mutating", StateConflictError),
    ],
)
def test_wrong_kind_or_class_is_refused_before_tool_probe(
    tmp_path: Path,
    field: str,
    value: str,
    error_type: type[Exception],
) -> None:
    prepared = _prepare(tmp_path)
    binding_path = OperationPlanBindingStore(prepared.paths, _OPERATION_ID).path
    document = json.loads(binding_path.read_text(encoding="utf-8"))
    document[field] = value
    _write_document(binding_path, document)
    runner = FakeCoordinatorRunner([])

    with pytest.raises(error_type):
        _orchestrate(prepared, runner)

    assert runner.specs == []
    assert not OperationExecutionStore(prepared.paths, _OPERATION_ID).path.exists()


@pytest.mark.parametrize(
    "artifact",
    [
        "missing-binding",
        "missing-context",
        "mismatched-context",
        "forbidden-authorization",
    ],
)
def test_missing_or_mismatched_prepared_checkpoint_is_refused(
    tmp_path: Path,
    artifact: str,
) -> None:
    prepared = _prepare(tmp_path)
    if artifact == "missing-binding":
        OperationPlanBindingStore(prepared.paths, _OPERATION_ID).path.unlink()
    elif artifact == "missing-context":
        OperationContextStore(prepared.paths, _OPERATION_ID).path.unlink()
    elif artifact == "mismatched-context":
        context_path = OperationContextStore(prepared.paths, _OPERATION_ID).path
        document = json.loads(context_path.read_text(encoding="utf-8"))
        document["binding_digest"] = _OTHER_DIGEST
        _write_document(context_path, document)
    else:
        authorization_path = (
            prepared.paths.operations
            / f"{_OPERATION_ID}.ansible-operation-authorization.json"
        )
        authorization_path.write_text("{}\n", encoding="utf-8")
        authorization_path.chmod(0o600)
    runner = FakeCoordinatorRunner([])

    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _orchestrate(prepared, runner)

    assert runner.specs == []
    assert not OperationExecutionStore(prepared.paths, _OPERATION_ID).path.exists()


@pytest.mark.parametrize("shape", ["none", "extra", "reordered"])
def test_no_extra_or_reordered_planned_steps_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    shape: str,
) -> None:
    prepared = _prepare(tmp_path)
    mappings = dict(orchestrator_module.OPERATION_PLAYBOOKS)
    current = mappings["check-jump-hosts"]
    mappings["check-jump-hosts"] = {
        "none": (),
        "extra": (*current, current[-1]),
        "reordered": tuple(reversed(current)),
    }[shape]
    monkeypatch.setattr(orchestrator_module, "OPERATION_PLAYBOOKS", mappings)
    runner = FakeCoordinatorRunner([])

    with pytest.raises(StateConflictError, match="step mapping drifted"):
        _orchestrate(prepared, runner)

    assert runner.specs == []
    assert not OperationExecutionStore(prepared.paths, _OPERATION_ID).path.exists()


def test_immutable_step_count_bounds_coordinator_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare(tmp_path)
    prefix_report = _coordinate(prepared, FakeCoordinatorRunner(_results(prepared)))
    monkeypatch.setattr(
        orchestrator_module,
        "coordinate_ansible_operation_step",
        lambda *args, **kwargs: prefix_report,
    )
    runner = FakeCoordinatorRunner([])

    with pytest.raises(StateConflictError, match="step-count bound"):
        _orchestrate(prepared, runner)

    assert runner.specs == []
    assert len(_read_execution(prepared).record.attempts) == 1


@pytest.mark.parametrize(
    ("mode", "playbook_result", "error", "state"),
    [
        (
            "failed",
            ProcessResult(2, _recap(failed=1), ""),
            None,
            ExecutionAttemptState.FAILED,
        ),
        (
            "timed-out",
            None,
            ProcessTimeoutError("simulated timeout"),
            ExecutionAttemptState.TIMED_OUT,
        ),
        (
            "interrupted",
            None,
            KeyboardInterrupt(),
            ExecutionAttemptState.INTERRUPTED,
        ),
        (
            "unreachable",
            ProcessResult(4, _recap(unreachable=1), ""),
            None,
            ExecutionAttemptState.UNREACHABLE,
        ),
        (
            "malformed",
            ProcessResult(0, "malformed output\n", ""),
            None,
            ExecutionAttemptState.MALFORMED_RESULT,
        ),
    ],
)
def test_terminal_outcomes_stop_without_retry(
    tmp_path: Path,
    mode: str,
    playbook_result: ProcessResult | None,
    error: BaseException | None,
    state: ExecutionAttemptState,
) -> None:
    prepared = _prepare(tmp_path / mode)
    _coordinate(prepared, FakeCoordinatorRunner(_results(prepared)))
    runner = FakeCoordinatorRunner(
        (
            _results(prepared, playbook_result)
            if playbook_result is not None
            else _results(prepared)[:4]
        ),
        fail_at=5 if error is not None else None,
        error=error,  # type: ignore[arg-type]
    )

    report = _orchestrate(prepared, runner)

    assert report.state is CheckJumpHostsOrchestrationState.EXECUTION_STOPPED
    assert report.finalization_state is CheckJumpHostsFinalizationState.NOT_REACHED
    assert report.latest_outcome is state
    assert report.succeeded_step_count == 1
    assert report.coordinator_call_count == 1
    assert report.manual_recovery_required
    assert not report.automatic_retry_allowed
    assert runner.specs is not None
    assert len(runner.specs) == 5
    attempts = _read_execution(prepared).record.attempts
    assert tuple(item.state for item in attempts) == (
        ExecutionAttemptState.SUCCEEDED,
        state,
    )

    retry = FakeCoordinatorRunner([])
    repeated = _orchestrate(prepared, retry)
    assert repeated.state is CheckJumpHostsOrchestrationState.EXECUTION_STOPPED
    assert repeated.coordinator_call_count == 0
    assert repeated.latest_outcome is state
    assert retry.specs == []


def test_crash_left_started_is_observed_but_never_retried(tmp_path: Path) -> None:
    prepared = _prepare(tmp_path)
    runner = FakeCoordinatorRunner(
        _results(prepared)[:4],
        fail_at=5,
        error=SimulatedCrash(),
    )

    with pytest.raises(SimulatedCrash):
        _orchestrate(prepared, runner)

    assert _read_execution(prepared).record.state is ExecutionAttemptState.STARTED
    retry = FakeCoordinatorRunner([])
    report = _orchestrate(prepared, retry)
    assert report.state is CheckJumpHostsOrchestrationState.EXECUTION_STOPPED
    assert report.latest_outcome is ExecutionAttemptState.STARTED
    assert report.succeeded_step_count == 0
    assert report.manual_recovery_required
    assert report.coordinator_call_count == 0
    assert retry.specs == []


def test_terminal_persistence_failure_preserves_started_ambiguity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare(tmp_path)
    original = OperationExecutionStore.write_locked

    def fail_terminal_write(self, record, **kwargs):
        if record.state is not ExecutionAttemptState.STARTED:
            raise StatePersistenceError("injected terminal persistence failure")
        return original(self, record, **kwargs)

    monkeypatch.setattr(OperationExecutionStore, "write_locked", fail_terminal_write)
    runner = FakeCoordinatorRunner(_results(prepared))
    with pytest.raises(StatePersistenceError, match="terminal persistence failure"):
        _orchestrate(prepared, runner)
    assert _read_execution(prepared).record.state is ExecutionAttemptState.STARTED
    assert runner.specs is not None
    assert len([spec for spec in runner.specs if "--extra-vars" in spec.argv]) == 1

    monkeypatch.undo()
    retry = FakeCoordinatorRunner([])
    report = _orchestrate(prepared, retry)
    assert report.latest_outcome is ExecutionAttemptState.STARTED
    assert report.coordinator_call_count == 0
    assert retry.specs == []


def test_api_surface_and_matching_lock_are_narrow(tmp_path: Path) -> None:
    prepared = _prepare(tmp_path)
    parameters = inspect.signature(orchestrate_prepared_check_jump_hosts).parameters
    assert tuple(parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "runner",
        "executables",
    )
    unlocked = ClusterLock(prepared.paths, "check-jump-hosts", 0)
    runner = FakeCoordinatorRunner([])
    with pytest.raises(StateLockError):
        orchestrate_prepared_check_jump_hosts(
            prepared.paths.state_root,
            prepared.metadata.record.cluster_name,
            _OPERATION_ID,
            unlocked,
            runner=runner,
            executables=prepared.executables,
        )
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError, match="matching operation"),
    ):
        orchestrate_prepared_check_jump_hosts(
            prepared.paths.state_root,
            prepared.metadata.record.cluster_name,
            _OPERATION_ID,
            wrong_lock,
            runner=runner,
            executables=prepared.executables,
        )
    with (
        ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock,
        pytest.raises(UnsafePathError, match="canonical"),
    ):
        orchestrate_prepared_check_jump_hosts(
            prepared.paths.state_root / ".." / "state",
            prepared.metadata.record.cluster_name,
            _OPERATION_ID,
            lock,
            runner=runner,
            executables=prepared.executables,
        )
    assert runner.specs == []


@pytest.mark.skipif(not hasattr(Path, "symlink_to"), reason="symlink support required")
def test_context_permissions_and_symlink_are_refused(tmp_path: Path) -> None:
    permissions = _prepare(tmp_path / "permissions")
    context_path = OperationContextStore(permissions.paths, _OPERATION_ID).path
    context_path.chmod(0o644)
    with pytest.raises(UnsafePathError, match="0600"):
        _orchestrate(permissions, FakeCoordinatorRunner([]))

    symlink = _prepare(tmp_path / "symlink")
    context_path = OperationContextStore(symlink.paths, _OPERATION_ID).path
    target = tmp_path / "outside-context.json"
    target.write_bytes(context_path.read_bytes())
    target.chmod(0o600)
    context_path.unlink()
    context_path.symlink_to(target)
    with pytest.raises(UnsafePathError, match="symbolic link"):
        _orchestrate(symlink, FakeCoordinatorRunner([]))
