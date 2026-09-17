import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from test_ansible import _inventory, _metadata, _paths, _readiness
from test_ansible_operation_authorization import _redeploy_request
from test_ansible_operation_binding import (
    _OPERATION_ID,
    PreparedBinding,
    _intents,
)
from test_ansible_operation_binding import (
    _prepare as prepare_read_only,
)

import scylla_vms.ansible.operation_binding as binding_module
from scylla_vms.ansible.operation_authorization import (
    InteractiveConfirmation,
    checkpoint_operation_authorization,
)
from scylla_vms.ansible.operation_binding import (
    OperationPlanBindingStore,
    StoredOperationPlanBinding,
    build_operation_plan_binding,
    normalized_operation_request_digest,
    validate_operation_plan_resume,
)
from scylla_vms.ansible.operation_context import (
    OperationContextStore,
    StoredOperationContext,
    build_operation_context,
)
from scylla_vms.ansible.operation_evidence import persist_operation_step_evidence
from scylla_vms.ansible.operation_execution import (
    ANSIBLE_OPERATION_EXECUTION_SCHEMA_VERSION,
    AuthorizationConsumption,
    ExecutionAttemptState,
    ExecutorReceiptStatus,
    OperationExecutionStore,
    OperationStepExecution,
    OperationStepExecutor,
    OperationStepInterrupted,
    OperationStepTimedOut,
    StoredOperationExecution,
    executor_result_receipt,
    handoff_operation_step,
)
from scylla_vms.ansible.orchestration import (
    AnsibleOperationPlan,
    AnsibleOperationPlanStatus,
    AnsibleOperationPlanStep,
    AnsibleOperationStepStatus,
    AnsibleStepIntent,
    ansible_operation_plan_checkpoint_evidence,
)
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.registry import OPERATION_PLAYBOOKS, get_playbook
from scylla_vms.ansible.service import (
    ConnectivityEvidence,
    ConnectivityStatus,
    HostConnectivityEvidence,
    HostConnectivityStatus,
    InventoryPreflightEvidence,
)
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import (
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    OperationRecord,
)
from scylla_vms.locking import ClusterLock, ClusterReadLock
from scylla_vms.models import OperationRequest
from scylla_vms.persistence import digest_bytes, serialize_json
from scylla_vms.state import StatePaths

_OTHER_DIGEST = "sha256:" + "b" * 64
_PRIVATE_PATH = "/private/operator/id_ed25519"
_SECRET = "obviously-fake-secret-value"


def _clock(second: int) -> datetime:
    return datetime(2026, 9, 18, 13, 0, second, tzinfo=UTC)


def _clock_sequence(*seconds: int) -> Callable[[], datetime]:
    values = iter(_clock(second) for second in seconds)
    return lambda: next(values)


@dataclass
class FakeExecutor:
    mode: str = "succeeded"
    checkpoint_path: Path | None = None
    calls: list[OperationStepExecution] = field(default_factory=list)
    evidence_callback: Callable[[OperationStepExecution], str] | None = None
    evidence_digest_override: str | None = None

    def execute(self, request: OperationStepExecution) -> Mapping[str, object]:
        self.calls.append(request)
        if self.checkpoint_path is not None:
            checkpoint = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
            assert checkpoint["attempts"][-1]["state"] == "started"
        if self.mode == "timed-out":
            raise OperationStepTimedOut
        if self.mode == "interrupted":
            raise OperationStepInterrupted
        if self.mode == "exception":
            raise RuntimeError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "malformed":
            return {
                "command_digest": request.command_digest,
                "exit_code": 0,
                "playbook": request.playbook,
                "schema_version": request.result_schema_version,
                "status": ExecutorReceiptStatus.SUCCEEDED.value,
                "step_sequence": request.step_sequence,
            }
        status = ExecutorReceiptStatus(self.mode)
        exit_code = 0 if status is ExecutorReceiptStatus.SUCCEEDED else 4
        evidence_digest = (
            self.evidence_callback(request)
            if status is ExecutorReceiptStatus.SUCCEEDED
            and self.evidence_callback is not None
            else digest_bytes(
                serialize_json(
                    {
                        "applied": status is ExecutorReceiptStatus.SUCCEEDED,
                        "private": _PRIVATE_PATH,
                        "secret": _SECRET,
                    }
                )
            )
        )
        if self.evidence_digest_override is not None:
            evidence_digest = self.evidence_digest_override
        return executor_result_receipt(
            request,
            status=status,
            exit_code=exit_code,
            evidence_digest=evidence_digest,
        )


class SimulatedCrash(BaseException):
    pass


class CrashExecutor:
    def execute(self, request: OperationStepExecution) -> Mapping[str, object]:
        del request
        raise SimulatedCrash


@dataclass(frozen=True)
class PreparedMutating:
    paths: StatePaths
    request: OperationRequest
    readiness: ReadinessReport
    plan: AnsibleOperationPlan
    intents: tuple[AnsibleStepIntent, ...]


def _synthetic_redeploy_plan(
    request: OperationRequest,
) -> tuple[AnsibleOperationPlan, tuple[AnsibleStepIntent, ...]]:
    steps: list[AnsibleOperationPlanStep] = []
    intents: list[AnsibleStepIntent] = []
    for sequence, mapped in enumerate(
        OPERATION_PLAYBOOKS[request.operation.name], start=1
    ):
        definition = get_playbook(mapped.playbook)
        selected = mapped.condition == "always"
        if selected:
            intent = AnsibleStepIntent(sequence, ("jump-host-1",), {}, check=False)
            intents.append(intent)
            steps.append(
                AnsibleOperationPlanStep(
                    sequence,
                    mapped.playbook,
                    mapped.condition,
                    definition.classification,
                    AnsibleOperationStepStatus.READY,
                    intent.limit,
                    (),
                    digest_bytes(serialize_json({})),
                    False,
                    (),
                )
            )
        else:
            steps.append(
                AnsibleOperationPlanStep(
                    sequence,
                    mapped.playbook,
                    mapped.condition,
                    definition.classification,
                    AnsibleOperationStepStatus.SKIPPED,
                    (),
                    (),
                    None,
                    None,
                    (),
                )
            )
    return (
        AnsibleOperationPlan(
            request.operation.name,
            request.operation.classification,
            request.operation.classification,
            True,
            (),
            AnsibleOperationPlanStatus.READY,
            (),
            tuple(steps),
        ),
        tuple(intents),
    )


def _prepare_mutating(tmp_path: Path, *, authorize: bool) -> PreparedMutating:
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    paths = _paths(tmp_path)
    request = _redeploy_request(paths, yes=True)
    plan, intents = _synthetic_redeploy_plan(request)
    readiness = _readiness(_inventory())
    journal_store = OperationJournalStore(paths, _OPERATION_ID)
    binding_store = OperationPlanBindingStore(paths, _OPERATION_ID)
    with ClusterLock(paths, request.operation.name, 0) as lock:
        pending = OperationRecord.create(
            operation_id=_OPERATION_ID,
            operation=request.operation.name,
            cluster_uuid=_metadata().cluster_uuid,
            cluster_name=_metadata().cluster_name,
            request_digest=normalized_operation_request_digest(request),
            clock=lambda: _clock(0),
        )
        initial = journal_store.write(
            pending, expected_generation=0, expected_digest=None
        )
        planned_record = pending.transition(
            status=JournalStatus.IN_PROGRESS,
            phase=OperationPhase.PLAN,
            evidence=(ansible_operation_plan_checkpoint_evidence(plan),),
            clock=lambda: _clock(1),
        )
        journal = journal_store.write(
            planned_record,
            expected_generation=initial.record.generation,
            expected_digest=initial.digest,
        )
        binding = build_operation_plan_binding(
            _metadata(),
            request,
            _OPERATION_ID,
            plan,
            readiness,
            journal,
            clock=lambda: _clock(2),
        )
        binding_store.write_locked(
            binding,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        if authorize:
            checkpoint_operation_authorization(
                lock,
                _metadata(),
                request,
                _OPERATION_ID,
                interactive=InteractiveConfirmation(),
                clock=lambda: _clock(3),
            )
    return PreparedMutating(paths, request, readiness, plan, intents)


def _handoff_read_only(
    prepared: PreparedBinding,
    executor: OperationStepExecutor,
    *,
    request: OperationRequest | None = None,
    plan: AnsibleOperationPlan | None = None,
    readiness: ReadinessReport | None = None,
    intents: tuple[AnsibleStepIntent, ...] | None = None,
    store: OperationExecutionStore | None = None,
) -> StoredOperationExecution:
    paths = prepared.paths
    selected_request = request or prepared.request
    checkpoint_path = OperationExecutionStore(paths, _OPERATION_ID).path
    completed_attempts = (
        len(json.loads(checkpoint_path.read_text(encoding="utf-8"))["attempts"])
        if checkpoint_path.exists()
        else 0
    )
    with ClusterLock(paths, selected_request.operation.name, 0) as lock:
        binding, operation_context = _ensure_context_locked(prepared, lock)
        if isinstance(executor, FakeExecutor) and executor.evidence_callback is None:
            selected_readiness = readiness or prepared.readiness
            executor.evidence_callback = lambda step: _persist_fake_evidence(
                lock,
                paths,
                binding,
                operation_context,
                selected_readiness,
                step,
            )
        return handoff_operation_step(
            lock,
            _metadata(),
            selected_request,
            _OPERATION_ID,
            plan or prepared.plan,
            readiness or prepared.readiness,
            intents or _intents(),
            executor,
            store=store,
            clock=_clock_sequence(
                4 + completed_attempts * 2, 5 + completed_attempts * 2
            ),
        )


def _ensure_context_locked(
    prepared: PreparedBinding,
    lock: ClusterLock,
) -> tuple[StoredOperationPlanBinding, StoredOperationContext]:
    binding = prepared.store.read_locked(
        lock,
        expected_cluster_uuid=_metadata().cluster_uuid,
        expected_cluster_name=_metadata().cluster_name,
        expected_operation=prepared.request.operation.name,
    )
    context_store = OperationContextStore(prepared.paths, _OPERATION_ID)
    operation_context = (
        context_store.read_locked(
            lock,
            expected_cluster_uuid=_metadata().cluster_uuid,
            expected_cluster_name=_metadata().cluster_name,
            expected_operation=prepared.request.operation.name,
        )
        if context_store.path.exists()
        else context_store.write_locked(
            build_operation_context(
                _metadata(),
                prepared.request,
                _OPERATION_ID,
                prepared.plan,
                binding,
                clock=lambda: _clock(3),
            ),
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    )
    return binding, operation_context


def _persist_fake_evidence(
    lock: ClusterLock,
    paths: StatePaths,
    binding: StoredOperationPlanBinding,
    operation_context: StoredOperationContext,
    readiness: ReadinessReport,
    step: OperationStepExecution,
) -> str:
    bound = binding.record
    evidence: object
    if step.playbook == "inventory-preflight":
        evidence = InventoryPreflightEvidence(
            "passed",
            len(_inventory().record.inventory.hosts),
            len(step.limit),
            cast(int, bound.inventory_generation),
            bound.inventory_digest,
            cast(int, bound.observation_generation),
            cast(str, bound.observation_digest),
        )
    else:
        evidence = ConnectivityEvidence(
            ConnectivityStatus.SUCCESS,
            tuple(
                HostConnectivityEvidence(item, HostConnectivityStatus.REACHABLE)
                for item in sorted(step.limit)
            ),
        )
    _, entry = persist_operation_step_evidence(
        lock,
        paths,
        binding,
        operation_context,
        readiness,
        step,
        evidence,
    )
    return entry.projection_digest


def _handoff_mutating(
    prepared: PreparedMutating,
    executor: OperationStepExecutor,
    *,
    store: OperationExecutionStore | None = None,
) -> StoredOperationExecution:
    checkpoint_path = OperationExecutionStore(prepared.paths, _OPERATION_ID).path
    completed_attempts = (
        len(json.loads(checkpoint_path.read_text(encoding="utf-8"))["attempts"])
        if checkpoint_path.exists()
        else 0
    )
    with ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock:
        return handoff_operation_step(
            lock,
            _metadata(),
            prepared.request,
            _OPERATION_ID,
            prepared.plan,
            prepared.readiness,
            prepared.intents,
            executor,
            store=store,
            clock=_clock_sequence(
                4 + completed_attempts * 2, 5 + completed_attempts * 2
            ),
        )


def _read_execution(
    paths: StatePaths, operation: str = "check-jump-hosts"
) -> StoredOperationExecution:
    store = OperationExecutionStore(paths, _OPERATION_ID)
    with ClusterReadLock(paths, 0) as lock:
        return store.read_locked(
            lock,
            expected_cluster_uuid=_metadata().cluster_uuid,
            expected_cluster_name=_metadata().cluster_name,
            expected_operation=operation,
        )


def test_read_only_handoff_persists_started_before_effect_and_strict_success(
    tmp_path: Path,
) -> None:
    prepared = prepare_read_only(tmp_path)
    store = OperationExecutionStore(prepared.paths, _OPERATION_ID)
    journal_before = (prepared.paths.operations / f"{_OPERATION_ID}.json").read_bytes()
    executor = FakeExecutor(checkpoint_path=store.path)

    stored = _handoff_read_only(prepared, executor)

    assert len(executor.calls) == 1
    assert stored.record.schema_version == ANSIBLE_OPERATION_EXECUTION_SCHEMA_VERSION
    assert stored.record.generation == 2
    assert stored.record.authorization_consumption is (
        AuthorizationConsumption.NOT_REQUIRED
    )
    assert stored.record.authorization_digest is None
    attempt = stored.record.attempts[0]
    assert attempt.state is ExecutionAttemptState.SUCCEEDED
    assert attempt.step_sequence == 1
    assert attempt.playbook == "inventory-preflight"
    assert attempt.exit_code == 0
    assert attempt.result_digest is not None
    assert store.path.stat().st_mode & 0o777 == 0o600
    assert (
        prepared.paths.operations / f"{_OPERATION_ID}.json"
    ).read_bytes() == journal_before
    encoded = json.dumps(stored.to_public_object())
    assert _PRIVATE_PATH not in encoded
    assert _SECRET not in encoded
    assert "result_digest" in encoded
    with (
        ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock,
        pytest.raises(StatePersistenceError, match="changed concurrently"),
    ):
        store.write_locked(
            replace(stored.record, generation=stored.record.generation + 1),
            expected_generation=stored.record.generation,
            expected_digest=_OTHER_DIGEST,
            lock=lock,
        )


def test_read_only_rejects_any_authorization_before_invocation(
    tmp_path: Path,
) -> None:
    prepared = prepare_read_only(tmp_path)
    with ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock:
        _ensure_context_locked(prepared, lock)
    authorization_path = (
        prepared.paths.operations
        / f"{_OPERATION_ID}.ansible-operation-authorization.json"
    )
    authorization_path.write_text("{}\n", encoding="utf-8")
    authorization_path.chmod(0o600)
    executor = FakeExecutor()

    with pytest.raises(StateConflictError, match="forbidden authorization"):
        _handoff_read_only(prepared, executor)

    assert executor.calls == []
    assert not OperationExecutionStore(prepared.paths, _OPERATION_ID).path.exists()


def test_mutating_authorization_is_required_consumed_once_and_not_replayed(
    tmp_path: Path,
) -> None:
    missing = _prepare_mutating(tmp_path / "missing", authorize=False)
    missing_executor = FakeExecutor()
    with pytest.raises(StateConflictError, match=r"authorization.*missing"):
        _handoff_mutating(missing, missing_executor)
    assert missing_executor.calls == []

    prepared = _prepare_mutating(tmp_path / "authorized", authorize=True)
    executor = FakeExecutor()
    first = _handoff_mutating(prepared, executor)
    consumed_at = first.record.authorization_consumed_at
    authorization_digest = first.record.authorization_digest
    assert consumed_at == "2026-09-18T13:00:04Z"
    assert authorization_digest is not None
    assert first.record.authorization_consumption is AuthorizationConsumption.CONSUMED

    for _ in range(len(prepared.intents) - 1):
        completed = _handoff_mutating(prepared, executor)
    assert len(completed.record.attempts) == len(prepared.intents)
    assert completed.record.authorization_consumed_at == consumed_at
    assert completed.record.authorization_digest == authorization_digest
    with pytest.raises(StateConflictError, match="fully consumed"):
        _handoff_mutating(prepared, executor)
    assert len(executor.calls) == len(prepared.intents)


@pytest.mark.parametrize(
    ("mode", "state"),
    [
        ("failed", ExecutionAttemptState.FAILED),
        ("timed-out", ExecutionAttemptState.TIMED_OUT),
        ("interrupted", ExecutionAttemptState.INTERRUPTED),
        ("unreachable", ExecutionAttemptState.UNREACHABLE),
        ("malformed", ExecutionAttemptState.MALFORMED_RESULT),
        ("exception", ExecutionAttemptState.FAILED),
    ],
)
def test_uncertain_outcomes_are_durable_redacted_and_never_retryable(
    tmp_path: Path, mode: str, state: ExecutionAttemptState
) -> None:
    prepared = prepare_read_only(tmp_path / mode)
    executor = FakeExecutor(mode=mode)
    if mode in {"malformed", "exception"}:
        with pytest.raises(
            AnsibleError,
            match=(
                "malformed strict result"
                if mode == "malformed"
                else "failed after invocation"
            ),
        ):
            _handoff_read_only(prepared, executor)
    else:
        _handoff_read_only(prepared, executor)

    stored = _read_execution(prepared.paths)
    attempt = stored.record.attempts[0]
    assert attempt.state is state
    assert attempt.manual_recovery_required
    assert not attempt.automatic_retry_allowed
    assert _PRIVATE_PATH not in json.dumps(stored.to_public_object())
    assert _SECRET not in json.dumps(stored.to_public_object())
    calls = len(executor.calls)
    with pytest.raises(StateConflictError, match="manual recovery review"):
        _handoff_read_only(prepared, executor)
    assert len(executor.calls) == calls


def test_zero_exit_without_strict_result_is_malformed(
    tmp_path: Path,
) -> None:
    prepared = prepare_read_only(tmp_path)
    executor = FakeExecutor(mode="malformed")
    with pytest.raises(AnsibleError):
        _handoff_read_only(prepared, executor)
    assert (
        _read_execution(prepared.paths).record.attempts[0].state
        is ExecutionAttemptState.MALFORMED_RESULT
    )


@pytest.mark.parametrize("mode", ["missing", "mismatched"])
def test_success_receipt_requires_exact_durable_semantic_evidence(
    tmp_path: Path,
    mode: str,
) -> None:
    prepared = prepare_read_only(tmp_path)
    executor = (
        FakeExecutor(evidence_callback=lambda _step: _OTHER_DIGEST)
        if mode == "missing"
        else FakeExecutor(evidence_digest_override=_OTHER_DIGEST)
    )

    with pytest.raises(AnsibleError, match="semantic evidence"):
        _handoff_read_only(prepared, executor)

    attempt = _read_execution(prepared.paths).record.attempts[0]
    assert attempt.state is ExecutionAttemptState.MALFORMED_RESULT
    assert attempt.manual_recovery_required
    assert not attempt.automatic_retry_allowed
    evidence_path = (
        prepared.paths.operations / f"{_OPERATION_ID}.ansible-operation-evidence.json"
    )
    assert evidence_path.exists() is (mode == "mismatched")


def test_persistence_failure_before_effect_prevents_invocation(
    tmp_path: Path,
) -> None:
    prepared = prepare_read_only(tmp_path)
    store = OperationExecutionStore(
        prepared.paths, _OPERATION_ID, token_factory=lambda: "collision"
    )
    temporary = store.path.with_name(f".{store.path.name}.collision.tmp")
    temporary.write_text("occupied", encoding="utf-8")
    temporary.chmod(0o600)
    executor = FakeExecutor()

    with pytest.raises(StatePersistenceError, match="temporary"):
        _handoff_read_only(prepared, executor, store=store)

    assert executor.calls == []
    assert not store.path.exists()


def test_persistence_failure_after_effect_preserves_started_ambiguity(
    tmp_path: Path,
) -> None:
    prepared = prepare_read_only(tmp_path)

    def fail_replace(source: Path, destination: Path) -> None:
        del source, destination
        raise OSError("injected durable outcome failure")

    store = OperationExecutionStore(
        prepared.paths, _OPERATION_ID, replace_file=fail_replace
    )
    executor = FakeExecutor()
    with pytest.raises(StatePersistenceError, match="atomic state write"):
        _handoff_read_only(prepared, executor, store=store)
    assert len(executor.calls) == 1
    started = _read_execution(prepared.paths).record.attempts[0]
    assert started.state is ExecutionAttemptState.STARTED
    assert started.manual_recovery_required
    with pytest.raises(StateConflictError, match="manual recovery review"):
        _handoff_read_only(prepared, executor)
    assert len(executor.calls) == 1


def test_crash_after_durable_start_remains_ambiguous_and_not_retryable(
    tmp_path: Path,
) -> None:
    prepared = prepare_read_only(tmp_path)
    with pytest.raises(SimulatedCrash):
        _handoff_read_only(prepared, CrashExecutor())
    attempt = _read_execution(prepared.paths).record.attempts[0]
    assert attempt.state is ExecutionAttemptState.STARTED
    assert attempt.completed_at is None
    assert attempt.manual_recovery_required
    with pytest.raises(StateConflictError, match="manual recovery review"):
        _handoff_read_only(prepared, FakeExecutor())


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ("request", "identity"),
        ("plan", "plan"),
        ("readiness", "readiness"),
        ("intent-target", "limit"),
        ("intent-variable", "variable"),
    ],
)
def test_exact_preflight_drift_fails_before_invocation(
    tmp_path: Path, change: str, message: str
) -> None:
    prepared = prepare_read_only(tmp_path)
    request = prepared.request
    plan = prepared.plan
    readiness = prepared.readiness
    intents = _intents()
    if change == "request":
        request = replace(request, cluster_name="other")
    elif change == "plan":
        plan = replace(plan, blockers=("changed",))
    elif change == "readiness":
        readiness = replace(readiness, observation_digest=_OTHER_DIGEST)
    elif change == "intent-target":
        intents = (replace(intents[0], limit=("jump-host-2",)), intents[1])
    else:
        intents = (replace(intents[0], variables={"unexpected": True}), intents[1])
    executor = FakeExecutor()

    with pytest.raises(
        (AnsibleError, StateConflictError, StatePersistenceError),
        match=message,
    ):
        _handoff_read_only(
            prepared,
            executor,
            request=request,
            plan=plan,
            readiness=readiness,
            intents=intents,
        )
    assert executor.calls == []


def test_source_and_catalog_drift_fail_before_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = prepare_read_only(tmp_path / "source")
    executor = FakeExecutor()
    source = load_ansible_source_bundle()
    monkeypatch.setattr(
        binding_module,
        "load_ansible_source_bundle",
        lambda: replace(source, digest=_OTHER_DIGEST),
    )
    with pytest.raises(StateConflictError, match="source"):
        _handoff_read_only(prepared, executor)
    assert executor.calls == []

    prepared = prepare_read_only(tmp_path / "catalog")
    monkeypatch.undo()
    monkeypatch.setattr(
        binding_module, "ansible_operation_catalog_digest", lambda: _OTHER_DIGEST
    )
    with pytest.raises(StateConflictError, match="catalog"):
        _handoff_read_only(prepared, executor)
    assert executor.calls == []


def test_requires_matching_operation_lock_and_canonical_paths(
    tmp_path: Path,
) -> None:
    prepared = prepare_read_only(tmp_path)
    executor = FakeExecutor()
    lock = ClusterLock(prepared.paths, "check-jump-hosts", 0)
    with pytest.raises(StateLockError):
        handoff_operation_step(
            lock,
            _metadata(),
            prepared.request,
            _OPERATION_ID,
            prepared.plan,
            prepared.readiness,
            _intents(),
            executor,
            clock=_clock_sequence(4, 5),
        )
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        handoff_operation_step(
            wrong_lock,
            _metadata(),
            prepared.request,
            _OPERATION_ID,
            prepared.plan,
            prepared.readiness,
            _intents(),
            executor,
            clock=_clock_sequence(4, 5),
        )
    forged = replace(
        prepared.request,
        paths=replace(
            prepared.paths,
            operations=prepared.paths.operations / ".." / "operations",
        ),
    )
    with pytest.raises(UnsafePathError, match="canonical"):
        OperationExecutionStore(forged.paths, _OPERATION_ID)
    assert executor.calls == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX state safety contract")
def test_execution_store_refuses_symlinks_and_bad_permissions(
    tmp_path: Path,
) -> None:
    prepared = prepare_read_only(tmp_path / "permissions")
    _handoff_read_only(prepared, FakeExecutor())
    store = OperationExecutionStore(prepared.paths, _OPERATION_ID)
    store.path.chmod(0o644)
    with (
        ClusterReadLock(prepared.paths, 0) as lock,
        pytest.raises(UnsafePathError, match="0600"),
    ):
        store.read_locked(
            lock,
            expected_cluster_uuid=_metadata().cluster_uuid,
            expected_cluster_name=_metadata().cluster_name,
        )

    prepared = prepare_read_only(tmp_path / "symlink")
    store = OperationExecutionStore(prepared.paths, _OPERATION_ID)
    target = prepared.paths.operations / "target.json"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    store.path.symlink_to(target)
    with ClusterReadLock(prepared.paths, 0) as lock, pytest.raises(UnsafePathError):
        store.read_locked(
            lock,
            expected_cluster_uuid=_metadata().cluster_uuid,
            expected_cluster_name=_metadata().cluster_name,
        )


def test_v1_journal_compatibility_and_resume_refusal_after_execution(
    tmp_path: Path,
) -> None:
    prepared = prepare_read_only(tmp_path)
    journal_path = prepared.paths.operations / f"{_OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()
    _handoff_read_only(prepared, FakeExecutor())

    journal = OperationJournalStore(prepared.paths, _OPERATION_ID).read(
        expected_cluster_uuid=_metadata().cluster_uuid,
        expected_cluster_name=_metadata().cluster_name,
    )
    assert journal_path.read_bytes() == journal_before
    assert journal.record.schema_version == "deploy-scylla-vms.operation/v1"
    assert journal.record.status is JournalStatus.IN_PROGRESS
    assert journal.record.phase is OperationPhase.PLAN
    with (
        ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock,
        pytest.raises(StateConflictError, match="execution-may-have-started"),
    ):
        validate_operation_plan_resume(
            lock,
            _metadata(),
            prepared.request,
            _OPERATION_ID,
            prepared.plan,
            prepared.readiness,
        )
