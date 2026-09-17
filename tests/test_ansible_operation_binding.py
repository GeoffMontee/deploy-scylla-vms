import json
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from test_ansible import (
    DIGEST,
    FakeRunner,
    _builder,
    _inventory,
    _metadata,
    _paths,
    _readiness,
)

import scylla_vms.ansible.operation_binding as binding_module
from scylla_vms.ansible.operation_binding import (
    ANSIBLE_OPERATION_BINDING_SCHEMA_VERSION,
    ANSIBLE_OPERATION_RESUME_SCHEMA_VERSION,
    ConfirmationState,
    ExecutionState,
    OperationPlanBinding,
    OperationPlanBindingStore,
    OperationResumeState,
    build_operation_plan_binding,
    classify_operation_resume_state,
    normalized_operation_request_digest,
    validate_operation_plan_resume,
)
from scylla_vms.ansible.orchestration import (
    AnsibleOperationPlan,
    AnsibleStepIntent,
    ansible_operation_plan_checkpoint_evidence,
)
from scylla_vms.ansible.readiness import EvidenceStatus, ReadinessReport
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.cli import parse_operation_request
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import (
    CheckpointEvidence,
    EvidenceResult,
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    OperationRecord,
    StoredOperationRecord,
)
from scylla_vms.locking import ClusterLock, ClusterReadLock
from scylla_vms.models import OperationRequest, OptionValue
from scylla_vms.operations import OperationClassification, get_operation
from scylla_vms.persistence import ClusterMetadata, digest_bytes, serialize_json
from scylla_vms.state import StatePaths

_OPERATION_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
_OTHER_DIGEST = "sha256:" + "b" * 64
_PRIVATE_PATH = "/private/operator/id_ed25519"
_SECRET = "obviously-fake-secret-value"


def _clock(minute: int = 0) -> datetime:
    return datetime(2026, 9, 18, 12, minute, tzinfo=UTC)


def _request(paths: StatePaths, *, secret: str | None = None) -> OperationRequest:
    environ = (
        {"DEPLOY_SCYLLA_VMS_MANAGER_AUTH_TOKEN": secret} if secret is not None else {}
    )
    return parse_operation_request(
        [
            "--cluster-name",
            "example",
            "--state-dir",
            str(paths.state_root),
            "check-jump-hosts",
        ],
        environ=environ,
    )


def _intents() -> tuple[AnsibleStepIntent, ...]:
    return (
        AnsibleStepIntent(1, ("jump-host-1",), {}, check=True),
        AnsibleStepIntent(
            2,
            ("jump-host-1",),
            {
                "deploy_scylla_vms_connect_timeout_seconds": 2.5,
                "deploy_scylla_vms_destination_probes": [],
                "deploy_scylla_vms_probe_timeout_seconds": 3,
            },
            check=True,
        ),
    )


@dataclass(frozen=True)
class PreparedBinding:
    paths: StatePaths
    request: OperationRequest
    readiness: ReadinessReport
    plan: AnsibleOperationPlan
    journal: StoredOperationRecord
    binding: OperationPlanBinding
    store: OperationPlanBindingStore
    runner: FakeRunner


def _prepare(
    tmp_path: Path,
    *,
    persist_binding: bool = True,
    secret: str | None = None,
) -> PreparedBinding:
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    paths = _paths(tmp_path)
    request = _request(paths, secret=secret)
    inventory = _inventory()
    readiness = _readiness(inventory)
    runner = FakeRunner()
    service = AnsibleService(_builder(tmp_path, paths), runner)
    journal_store = OperationJournalStore(paths, _OPERATION_ID)
    store = OperationPlanBindingStore(paths, _OPERATION_ID)

    with ClusterLock(paths, request.operation.name, 0) as lock:
        plan = service.plan_operation(
            lock,
            _metadata(),
            inventory,
            request.operation.name,
            readiness=readiness,
            active_conditions=(),
            intents=_intents(),
        )
        request_digest = normalized_operation_request_digest(request)
        pending = OperationRecord.create(
            operation_id=_OPERATION_ID,
            operation=request.operation.name,
            cluster_uuid=_metadata().cluster_uuid,
            cluster_name=_metadata().cluster_name,
            request_digest=request_digest,
            clock=lambda: _clock(),
        )
        planned = pending.transition(
            status=JournalStatus.IN_PROGRESS,
            phase=OperationPhase.PLAN,
            evidence=(ansible_operation_plan_checkpoint_evidence(plan),),
            clock=lambda: _clock(1),
        )
        initial = journal_store.write(
            pending, expected_generation=0, expected_digest=None
        )
        journal = journal_store.write(
            planned,
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
        if persist_binding:
            store.write_locked(
                binding,
                expected_generation=0,
                expected_digest=None,
                lock=lock,
            )
    return PreparedBinding(
        paths, request, readiness, plan, journal, binding, store, runner
    )


def _resume(prepared: PreparedBinding) -> binding_module.OperationResumeValidation:
    with ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock:
        return validate_operation_plan_resume(
            lock,
            _metadata(),
            prepared.request,
            _OPERATION_ID,
            prepared.plan,
            prepared.readiness,
        )


def _resume_raises(
    prepared: PreparedBinding,
    match: str,
    *,
    metadata: ClusterMetadata | None = None,
    request: OperationRequest | None = None,
    plan: AnsibleOperationPlan | None = None,
    readiness: ReadinessReport | None = None,
) -> None:
    with (
        ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock,
        pytest.raises(StateConflictError, match=match),
    ):
        validate_operation_plan_resume(
            lock,
            metadata or _metadata(),
            request or prepared.request,
            _OPERATION_ID,
            plan or prepared.plan,
            readiness or prepared.readiness,
        )


def _read_raises(
    prepared: PreparedBinding,
    error: type[Exception],
    match: str,
) -> None:
    with (
        ClusterReadLock(prepared.paths, 0) as lock,
        pytest.raises(error, match=match),
    ):
        prepared.store.read_locked(
            lock,
            expected_cluster_uuid=_metadata().cluster_uuid,
            expected_cluster_name="example",
        )


def _replace_request_option(
    request: OperationRequest, name: str, value: object
) -> OperationRequest:
    return replace(
        request,
        options=tuple(
            replace(option, value=cast(OptionValue, value))
            if option.name == name
            else option
            for option in request.options
        ),
    )


def _write_next_journal(
    prepared: PreparedBinding,
    *,
    status: JournalStatus,
    phase: OperationPhase,
    evidence: tuple[CheckpointEvidence, ...] | None = None,
    minute: int = 3,
) -> StoredOperationRecord:
    store = OperationJournalStore(prepared.paths, _OPERATION_ID)
    current = store.read(
        expected_cluster_uuid=_metadata().cluster_uuid,
        expected_cluster_name=_metadata().cluster_name,
    )
    candidate = current.record.transition(
        status=status,
        phase=phase,
        evidence=current.record.evidence if evidence is None else evidence,
        clock=lambda: _clock(minute),
    )
    return store.write(
        candidate,
        expected_generation=current.record.generation,
        expected_digest=current.digest,
    )


def test_binding_round_trip_and_happy_pre_execution_resume(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    assert prepared.store.path == (
        prepared.paths.operations / f"{_OPERATION_ID}.ansible-operation-binding.json"
    )
    assert prepared.store.path.stat().st_mode & 0o777 == 0o600

    with ClusterReadLock(prepared.paths, 0) as lock:
        stored = prepared.store.read_locked(
            lock,
            expected_cluster_uuid=_metadata().cluster_uuid,
            expected_cluster_name=_metadata().cluster_name,
            expected_operation="check-jump-hosts",
        )
    assert stored.record == prepared.binding
    assert stored.record.schema_version == ANSIBLE_OPERATION_BINDING_SCHEMA_VERSION
    assert stored.record.selected_stable_ids == ("jump-host-1",)
    assert stored.record.confirmation_state is ConfirmationState.NOT_COLLECTED
    assert stored.record.execution_state is ExecutionState.NOT_STARTED

    validation = _resume(prepared)
    assert validation.schema_version == ANSIBLE_OPERATION_RESUME_SCHEMA_VERSION
    assert validation.resume_state is OperationResumeState.RESUMABLE_PRE_EXECUTION
    assert validation.plan_digest == prepared.plan.plan_digest
    assert prepared.runner.specs == []


def test_binding_requires_matching_acquired_operation_lock(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path, persist_binding=False)
    unlocked = ClusterLock(prepared.paths, "check-jump-hosts", 0)
    with pytest.raises(StateLockError, match="matching acquired"):
        prepared.store.write_locked(
            prepared.binding,
            expected_generation=0,
            expected_digest=None,
            lock=unlocked,
        )
    with (
        ClusterLock(prepared.paths, "deploy", 0) as wrong_operation,
        pytest.raises(StateLockError, match="matching operation"),
    ):
        prepared.store.write_locked(
            prepared.binding,
            expected_generation=0,
            expected_digest=None,
            lock=wrong_operation,
        )
    assert not prepared.store.path.exists()


def test_binding_rejects_noncanonical_id_paths_symlink_and_permissions(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    forged = replace(prepared.paths, operations=tmp_path / "outside")
    with pytest.raises(UnsafePathError, match="not canonical"):
        OperationPlanBindingStore(forged, _OPERATION_ID)
    with pytest.raises(StatePersistenceError, match="must be a UUID"):
        OperationPlanBindingStore(prepared.paths, cast(uuid.UUID, "../escape"))

    original = prepared.store.path.read_bytes()
    prepared.store.path.unlink()
    outside = tmp_path / "outside-binding.json"
    outside.write_bytes(original)
    outside.chmod(0o600)
    prepared.store.path.symlink_to(outside)
    _read_raises(prepared, UnsafePathError, "symbolic link")

    prepared.store.path.unlink()
    prepared.store.path.write_bytes(original)
    prepared.store.path.chmod(0o644)
    _read_raises(prepared, UnsafePathError, "permissions must be 0600")


def test_resume_rejects_request_plan_target_and_evidence_drift(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    request = _replace_request_option(prepared.request, "log_level", "warning")
    _resume_raises(prepared, "request digest drifted", request=request)

    changed_step = replace(prepared.plan.steps[0], limit=("jump-host-2",))
    target_plan = replace(prepared.plan, steps=(changed_step, *prepared.plan.steps[1:]))
    _resume_raises(prepared, "target set drifted", plan=target_plan)

    plan = replace(prepared.plan, active_conditions=("changed",))
    _resume_raises(prepared, "plan binding drifted", plan=plan)

    readiness = replace(prepared.readiness, observation_digest=_OTHER_DIGEST)
    _resume_raises(prepared, "readiness or evidence drifted", readiness=readiness)

    stale = replace(prepared.readiness, source_status=EvidenceStatus.STALE)
    _resume_raises(prepared, "current fresh readiness", readiness=stale)


def test_resume_rejects_operation_mismatch(tmp_path: Path) -> None:
    prepared = _prepare(tmp_path)
    request = replace(prepared.request, operation=get_operation("show"))
    with (
        ClusterLock(prepared.paths, "show", 0) as lock,
        pytest.raises(StateConflictError, match="identity conflicts"),
    ):
        validate_operation_plan_resume(
            lock,
            _metadata(),
            request,
            _OPERATION_ID,
            prepared.plan,
            prepared.readiness,
        )


def test_resume_rejects_catalog_and_source_hash_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepare(tmp_path)
    monkeypatch.setattr(
        binding_module, "ansible_operation_catalog_digest", lambda: _OTHER_DIGEST
    )
    _resume_raises(prepared, "catalog binding drifted")

    monkeypatch.undo()
    source = replace(load_ansible_source_bundle(), digest=_OTHER_DIGEST)
    monkeypatch.setattr(binding_module, "load_ansible_source_bundle", lambda: source)
    _resume_raises(prepared, "source binding drifted")


def test_binding_rejects_malformed_unknown_schema_and_identity(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    with pytest.raises(StatePersistenceError, match="generation must be one"):
        replace(prepared.binding, generation=True)

    document = json.loads(prepared.store.path.read_text(encoding="utf-8"))
    document["schema_version"] = "deploy-scylla-vms.ansible-operation-binding/v999"
    prepared.store.path.write_bytes(serialize_json(document))
    prepared.store.path.chmod(0o600)
    _read_raises(prepared, StatePersistenceError, "unsupported")

    document["schema_version"] = ANSIBLE_OPERATION_BINDING_SCHEMA_VERSION
    document["unexpected"] = True
    prepared.store.path.write_bytes(serialize_json(document))
    prepared.store.path.chmod(0o600)
    _read_raises(prepared, StatePersistenceError, "fields do not match")

    document.pop("unexpected")
    prepared.store.path.write_bytes(serialize_json(document))
    prepared.store.path.chmod(0o600)
    other_metadata = cast(
        binding_module.ClusterMetadata,
        SimpleNamespace(
            cluster_uuid=uuid.UUID("22222222-2222-4222-8222-222222222222"),
            cluster_name="example",
            provider="oci",
        ),
    )
    with (
        ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock,
        pytest.raises(StatePersistenceError, match="identity mismatch"),
    ):
        validate_operation_plan_resume(
            lock,
            other_metadata,
            prepared.request,
            _OPERATION_ID,
            prepared.plan,
            prepared.readiness,
        )


@pytest.mark.parametrize(
    ("status", "phase", "expected"),
    [
        (
            JournalStatus.IN_PROGRESS,
            OperationPhase.CONFIRM,
            OperationResumeState.CONFIRMATION_STATE_AMBIGUOUS,
        ),
        (
            JournalStatus.IN_PROGRESS,
            OperationPhase.EXECUTE,
            OperationResumeState.EXECUTION_MAY_HAVE_STARTED,
        ),
        (
            JournalStatus.INTERRUPTED,
            OperationPhase.EXECUTE,
            OperationResumeState.INTERRUPTED,
        ),
        (
            JournalStatus.FAILED,
            OperationPhase.EXECUTE,
            OperationResumeState.FAILED,
        ),
    ],
)
def test_resume_refuses_advanced_failed_and_interrupted_history(
    tmp_path: Path,
    status: JournalStatus,
    phase: OperationPhase,
    expected: OperationResumeState,
) -> None:
    prepared = _prepare(tmp_path)
    if status is JournalStatus.INTERRUPTED:
        _write_next_journal(
            prepared,
            status=JournalStatus.IN_PROGRESS,
            phase=phase,
        )
        _write_next_journal(prepared, status=status, phase=phase, minute=4)
    else:
        _write_next_journal(prepared, status=status, phase=phase)
    _resume_raises(prepared, expected.value)


def test_resume_never_infers_completion_or_retries_destructive_boundary(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    verify = CheckpointEvidence(
        OperationPhase.VERIFY,
        EvidenceResult.COMPLETED,
        digest_bytes(b"verified"),
        "postconditions-verified",
    )
    _write_next_journal(
        prepared,
        status=JournalStatus.IN_PROGRESS,
        phase=OperationPhase.VERIFY,
        evidence=(*prepared.journal.record.evidence, verify),
    )
    _write_next_journal(
        prepared,
        status=JournalStatus.SUCCEEDED,
        phase=OperationPhase.JOURNAL,
        minute=4,
    )
    _resume_raises(prepared, OperationResumeState.COMPLETED.value)

    running = replace(
        prepared.journal.record,
        operation="destroy",
        status=JournalStatus.IN_PROGRESS,
        phase=OperationPhase.EXECUTE,
        evidence=(),
    )
    assert (
        classify_operation_resume_state(running, OperationClassification.DESTRUCTIVE)
        is OperationResumeState.DESTRUCTIVE_BOUNDARY_RECORDED
    )


def test_resume_rejects_missing_or_ambiguous_journal_history(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path / "changed")
    journal_path = prepared.paths.operations / f"{_OPERATION_ID}.json"
    document = json.loads(journal_path.read_text(encoding="utf-8"))
    journal_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    journal_path.chmod(0o600)
    _resume_raises(prepared, "history is ambiguous")

    prepared = _prepare(tmp_path / "missing")
    journal_path = prepared.paths.operations / f"{_OPERATION_ID}.json"
    journal_path.unlink()
    _resume_raises(prepared, "missing or ambiguous")


def test_binding_projection_and_persistence_redact_protected_values(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path, secret=_SECRET)
    persisted = prepared.store.path.read_text(encoding="utf-8")
    public = json.dumps(prepared.binding.to_public_object(), sort_keys=True)
    validation_public = json.dumps(_resume(prepared).to_public_object(), sort_keys=True)
    for protected in (
        _SECRET,
        _PRIVATE_PATH,
        str(prepared.paths.cluster_root),
        "203.0.113.10",
        "10.0.0.10",
        "ocid1.instance.oc1.iad.fakejump",
    ):
        assert protected not in persisted
        assert protected not in public
        assert protected not in validation_public
    assert "deploy_scylla_vms_connect_timeout_seconds" not in persisted
    assert '"2.5"' not in persisted


def test_binding_atomic_failure_does_not_publish_partial_record(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path, persist_binding=False)
    store = OperationPlanBindingStore(
        prepared.paths, _OPERATION_ID, token_factory=lambda: "fixed"
    )
    temporary = store.path.with_name(f".{store.path.name}.fixed.tmp")
    temporary.write_text("occupied", encoding="utf-8")
    temporary.chmod(0o600)
    with (
        ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock,
        pytest.raises(StatePersistenceError, match="temporary state file"),
    ):
        store.write_locked(
            prepared.binding,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    assert not store.path.exists()
    assert temporary.read_text(encoding="utf-8") == "occupied"


def test_binding_generation_digest_guards_and_idempotent_rewrite(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    with ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock:
        stored = prepared.store.read_locked(
            lock,
            expected_cluster_uuid=_metadata().cluster_uuid,
            expected_cluster_name="example",
        )
        assert (
            prepared.store.write_locked(
                prepared.binding,
                expected_generation=stored.record.generation,
                expected_digest=stored.digest,
                lock=lock,
            )
            == stored
        )
        with pytest.raises(StatePersistenceError, match="changed concurrently"):
            prepared.store.write_locked(
                prepared.binding,
                expected_generation=99,
                expected_digest=DIGEST,
                lock=lock,
            )
