import inspect
import json
import subprocess
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_ansible import DIGEST
from test_check_jump_hosts import _prepared_state

import scylla_vms.ansible.operation_binding as binding_module
import scylla_vms.ansible.operation_preparation as preparation_module
from scylla_vms.ansible.commands import validate_playbook_request_policy
from scylla_vms.ansible.operation_authorization import InteractiveConfirmation
from scylla_vms.ansible.operation_binding import (
    OperationPlanBindingStore,
    normalized_operation_request_digest,
)
from scylla_vms.ansible.operation_context import (
    OPERATION_CONTEXT_UNMODELED,
    OperationContextStore,
    resolve_operation_context_input,
)
from scylla_vms.ansible.operation_execution import OperationExecutionStore
from scylla_vms.ansible.operation_preparation import (
    ANSIBLE_OPERATION_PREPARATION_REPORT_SCHEMA_VERSION,
    PreparationStageState,
    PreparationState,
    prepare_ansible_operation_checkpoints,
)
from scylla_vms.ansible.orchestration import (
    AnsibleOperationPlan,
    AnsibleOperationPlanStatus,
    ansible_operation_plan_checkpoint_evidence,
    build_ansible_operation_plan,
)
from scylla_vms.ansible.readiness import (
    InventoryMachineEvidence,
    ReadinessReport,
    build_readiness_report,
)
from scylla_vms.ansible.registry import PlaybookDefinition
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.cli import parse_operation_request
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.journal import (
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    OperationRecord,
    StoredOperationRecord,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.models import OperationRequest
from scylla_vms.observed import ObservedStateStore
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import (
    ClusterMetadataStore,
    StoredClusterMetadata,
    serialize_json,
)
from scylla_vms.state import StatePaths

_OPERATION_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
_OTHER_DIGEST = "sha256:" + "b" * 64
_PRIVATE_PATH = "/private/operator/id_ed25519"
_SECRET = "obviously-fake-secret-value"


def _clock(second: int) -> datetime:
    return datetime(2026, 9, 18, 16, 0, second, tzinfo=UTC)


@dataclass(frozen=True)
class _PlanPolicy:
    paths: StatePaths

    def validate_playbook_request(
        self,
        name: str,
        *,
        limit: tuple[str, ...],
        tags: tuple[str, ...] = (),
        check: bool = False,
        diff: bool = False,
        verbosity: int = 0,
    ) -> tuple[PlaybookDefinition, str]:
        return validate_playbook_request_policy(
            name,
            limit=limit,
            tags=tags,
            check=check,
            diff=diff,
            verbosity=verbosity,
        )


@dataclass(frozen=True)
class Prepared:
    paths: StatePaths
    metadata: StoredClusterMetadata
    inventory: StoredInventoryRecord
    request: OperationRequest
    readiness: ReadinessReport
    plan: AnsibleOperationPlan
    journal: StoredOperationRecord


def _request(paths: StatePaths, *extra: str) -> OperationRequest:
    return parse_operation_request(
        [
            "--cluster-name",
            "example",
            "--state-dir",
            str(paths.state_root),
            "check-jump-hosts",
            *extra,
        ],
        environ={},
    )


def _prepare(
    tmp_path: Path,
    *,
    request_extra: tuple[str, ...] = (),
) -> Prepared:
    paths, inventory, trust = _prepared_state(tmp_path)
    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name="example",
        expected_provider="oci",
    )
    observed = ObservedStateStore(paths).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_provider=metadata.record.provider,
    )
    readiness = build_readiness_report(
        observed,
        inventory,
        trust,
        machine_evidence=InventoryMachineEvidence(
            DIGEST,
            DIGEST,
            len(inventory.record.inventory.hosts),
            len(inventory.record.inventory.groups),
        ),
    )
    request = _request(paths, *request_extra)
    context_input = resolve_operation_context_input(request, inventory)
    with ClusterLock(paths, request.operation.name, 0) as lock:
        plan = build_ansible_operation_plan(
            lock,
            _PlanPolicy(paths),
            metadata.record,
            inventory,
            request.operation.name,
            readiness=readiness,
            active_conditions=context_input.active_conditions,
            intents=context_input.intents,
        )
        journal = _write_plan_journal(
            paths,
            metadata,
            request,
            plan,
            lock,
        )
    return Prepared(paths, metadata, inventory, request, readiness, plan, journal)


def _write_plan_journal(
    paths: StatePaths,
    metadata: StoredClusterMetadata,
    request: OperationRequest,
    plan: AnsibleOperationPlan,
    lock: ClusterLock,
) -> StoredOperationRecord:
    lock.assert_held_for_operation(paths, request.operation.name)
    pending = OperationRecord.create(
        operation_id=_OPERATION_ID,
        operation=request.operation.name,
        cluster_uuid=metadata.record.cluster_uuid,
        cluster_name=metadata.record.cluster_name,
        request_digest=normalized_operation_request_digest(request),
        clock=lambda: _clock(0),
    )
    store = OperationJournalStore(paths, _OPERATION_ID)
    initial = store.write(pending, expected_generation=0, expected_digest=None)
    return store.write(
        pending.transition(
            status=JournalStatus.IN_PROGRESS,
            phase=OperationPhase.PLAN,
            evidence=(ansible_operation_plan_checkpoint_evidence(plan),),
            clock=lambda: _clock(1),
        ),
        expected_generation=initial.record.generation,
        expected_digest=initial.digest,
    )


def _call(prepared: Prepared):
    with ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock:
        return prepare_ansible_operation_checkpoints(
            prepared.paths.state_root,
            "example",
            _OPERATION_ID,
            prepared.request.operation.name,
            prepared.request,
            prepared.readiness,
            lock,
            clock=lambda: _clock(2),
        )


def _checkpoint_paths(paths: StatePaths) -> tuple[Path, Path, Path, Path]:
    return (
        OperationPlanBindingStore(paths, _OPERATION_ID).path,
        OperationContextStore(paths, _OPERATION_ID).path,
        paths.operations / f"{_OPERATION_ID}.ansible-operation-authorization.json",
        OperationExecutionStore(paths, _OPERATION_ID).path,
    )


def test_fresh_check_jump_preparation_orders_redacted_checkpoints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare(
        tmp_path,
        request_extra=(
            "--jump-host",
            "jump-host-1",
            "--destination",
            "scylla",
            "--depth",
            "route",
            "--destination-check",
            "scylla=9042",
        ),
    )
    journal_before = (prepared.paths.operations / f"{_OPERATION_ID}.json").read_bytes()
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("preparation must not invoke a subprocess")
        ),
    )

    report = _call(prepared)

    binding_path, context_path, authorization_path, execution_path = _checkpoint_paths(
        prepared.paths
    )
    assert report.schema_version == ANSIBLE_OPERATION_PREPARATION_REPORT_SCHEMA_VERSION
    assert report.state is PreparationState.PREPARED
    assert report.binding.state is PreparationStageState.CREATED
    assert report.context.state is PreparationStageState.CREATED
    assert report.authorization.state is PreparationStageState.NOT_REQUIRED
    assert report.resumable_pre_execution
    assert binding_path.exists() and context_path.exists()
    assert not authorization_path.exists()
    assert not execution_path.exists()
    assert (
        prepared.paths.operations / f"{_OPERATION_ID}.json"
    ).read_bytes() == journal_before
    public = json.dumps(report.to_object(), sort_keys=True)
    for forbidden in (
        "10.0.0.10",
        "10.0.3.10",
        "203.0.113.10",
        "ocid1.instance",
        str(prepared.paths.state_root),
        _PRIVATE_PATH,
        _SECRET,
        "ansible-playbook",
        "environment",
    ):
        assert forbidden not in public


def test_exact_reuse_is_byte_identical_and_does_not_advance_journal(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    first = _call(prepared)
    files = _checkpoint_paths(prepared.paths)[:2]
    before = {path: path.read_bytes() for path in files}
    journal_path = prepared.paths.operations / f"{_OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()

    second = _call(prepared)

    assert first.binding.digest == second.binding.digest
    assert second.binding.state is PreparationStageState.REUSED
    assert second.context.state is PreparationStageState.REUSED
    assert second.authorization.state is PreparationStageState.NOT_REQUIRED
    assert {path: path.read_bytes() for path in files} == before
    assert journal_path.read_bytes() == journal_before


def test_binding_only_partial_continues_after_context_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare(tmp_path)
    binding_path, context_path, authorization_path, execution_path = _checkpoint_paths(
        prepared.paths
    )

    with monkeypatch.context() as scoped:
        scoped.setattr(
            OperationContextStore,
            "write_locked",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                StatePersistenceError("injected context write failure")
            ),
        )
        with pytest.raises(StatePersistenceError, match="injected context"):
            _call(prepared)

    assert binding_path.exists()
    assert not context_path.exists()
    assert not authorization_path.exists()
    assert not execution_path.exists()
    binding_before = binding_path.read_bytes()

    report = _call(prepared)

    assert report.binding.state is PreparationStageState.REUSED
    assert report.context.state is PreparationStageState.CREATED
    assert binding_path.read_bytes() == binding_before


def test_failure_before_first_record_leaves_no_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare(tmp_path)
    with monkeypatch.context() as scoped:
        scoped.setattr(
            OperationPlanBindingStore,
            "write_locked",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                StatePersistenceError("injected binding write failure")
            ),
        )
        with pytest.raises(StatePersistenceError, match="injected binding"):
            _call(prepared)
    assert not any(path.exists() for path in _checkpoint_paths(prepared.paths))


def test_read_only_authorization_input_and_record_are_forbidden(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    with (
        ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock,
        pytest.raises(StateConflictError, match="must not receive"),
    ):
        prepare_ansible_operation_checkpoints(
            prepared.paths.state_root,
            "example",
            _OPERATION_ID,
            "check-jump-hosts",
            prepared.request,
            prepared.readiness,
            lock,
            authorization_proof=InteractiveConfirmation(ordinary_approved=True),
            clock=lambda: _clock(2),
        )
    assert not any(path.exists() for path in _checkpoint_paths(prepared.paths))

    authorization_path = _checkpoint_paths(prepared.paths)[2]
    authorization_path.write_text("{}\n", encoding="utf-8")
    authorization_path.chmod(0o600)
    with pytest.raises(StateConflictError, match="forbidden authorization"):
        _call(prepared)
    assert not _checkpoint_paths(prepared.paths)[0].exists()
    assert not _checkpoint_paths(prepared.paths)[1].exists()


def test_unmodeled_operation_returns_stable_blocker_before_writes(
    tmp_path: Path,
) -> None:
    paths, inventory, trust = _prepared_state(tmp_path)
    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name="example",
        expected_provider="oci",
    )
    observed = ObservedStateStore(paths).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_provider=metadata.record.provider,
    )
    readiness = build_readiness_report(
        observed,
        inventory,
        trust,
        machine_evidence=InventoryMachineEvidence(DIGEST, DIGEST, 4, 8),
    )
    request = parse_operation_request(
        [
            "--cluster-name",
            "example",
            "--state-dir",
            str(paths.state_root),
            "show",
        ],
        environ={},
    )
    plan = AnsibleOperationPlan(
        "show",
        OperationClassification.READ_ONLY,
        OperationClassification.READ_ONLY,
        True,
        (),
        AnsibleOperationPlanStatus.READY,
        (),
        (),
    )
    with ClusterLock(paths, "show", 0) as lock:
        _write_plan_journal(paths, metadata, request, plan, lock)
        report = prepare_ansible_operation_checkpoints(
            paths.state_root,
            "example",
            _OPERATION_ID,
            "show",
            request,
            readiness,
            lock,
            clock=lambda: _clock(2),
        )

    assert report.state is PreparationState.BLOCKED
    assert report.blockers == (OPERATION_CONTEXT_UNMODELED,)
    assert report.binding.state is PreparationStageState.BLOCKED
    assert report.context.state is PreparationStageState.BLOCKED
    assert not report.resumable_pre_execution
    assert not any(path.exists() for path in _checkpoint_paths(paths))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("status", JournalStatus.FAILED),
        ("status", JournalStatus.INTERRUPTED),
        ("status", JournalStatus.SUCCEEDED),
        ("phase", OperationPhase.CONFIRM),
    ),
)
def test_journal_terminal_status_and_phase_drift_refuse_without_writes(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    prepared = _prepare(tmp_path)
    path = prepared.paths.operations / f"{_OPERATION_ID}.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document[field] = value.value
    if value is JournalStatus.SUCCEEDED:
        document["phase"] = OperationPhase.JOURNAL.value
        document["evidence"].append(
            {
                "digest": DIGEST,
                "phase": OperationPhase.VERIFY.value,
                "result": "completed",
                "summary_code": "operation-verified",
            }
        )
    path.write_bytes(serialize_json(document))
    path.chmod(0o600)

    with pytest.raises(StateConflictError, match="IN_PROGRESS/PLAN"):
        _call(prepared)
    assert not any(item.exists() for item in _checkpoint_paths(prepared.paths))


def test_request_plan_evidence_and_readiness_drift_fail_before_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepare(tmp_path)
    changed_request = _request(
        prepared.paths,
        "--connect-timeout-seconds",
        "9",
    )
    changed = replace(prepared, request=changed_request)
    with pytest.raises(StateConflictError, match="IN_PROGRESS/PLAN"):
        _call(changed)

    changed_step = replace(prepared.plan.steps[0], check_mode=False)
    changed_plan = replace(
        prepared.plan,
        steps=(changed_step, *prepared.plan.steps[1:]),
    )
    with monkeypatch.context() as scoped:
        scoped.setattr(
            preparation_module,
            "build_ansible_operation_plan",
            lambda *args, **kwargs: changed_plan,
        )
        with pytest.raises(StateConflictError, match="journal checkpoint conflicts"):
            _call(prepared)

    journal_path = prepared.paths.operations / f"{_OPERATION_ID}.json"
    document = json.loads(journal_path.read_text(encoding="utf-8"))
    document["evidence"][0]["digest"] = _OTHER_DIGEST
    journal_path.write_bytes(serialize_json(document))
    journal_path.chmod(0o600)
    with pytest.raises(StateConflictError, match="journal checkpoint conflicts"):
        _call(prepared)

    document["evidence"][0]["digest"] = prepared.plan.plan_digest
    journal_path.write_bytes(serialize_json(document))
    journal_path.chmod(0o600)
    stale = replace(prepared.readiness, host_count=99)
    with pytest.raises(StateConflictError, match="readiness"):
        _call(replace(prepared, readiness=stale))
    assert not any(item.exists() for item in _checkpoint_paths(prepared.paths))


@pytest.mark.parametrize("kind", ("source", "catalog"))
def test_existing_checkpoint_source_or_catalog_drift_never_overwrites(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    prepared = _prepare(tmp_path)
    _call(prepared)
    before = {path: path.read_bytes() for path in _checkpoint_paths(prepared.paths)[:2]}
    if kind == "source":
        source = load_ansible_source_bundle()
        monkeypatch.setattr(
            binding_module,
            "load_ansible_source_bundle",
            lambda: replace(source, digest=_OTHER_DIGEST),
        )
    else:
        monkeypatch.setattr(
            binding_module,
            "ansible_operation_catalog_digest",
            lambda: _OTHER_DIGEST,
        )

    with pytest.raises(StateConflictError, match="binding drifted"):
        _call(prepared)
    assert {
        path: path.read_bytes() for path in _checkpoint_paths(prepared.paths)[:2]
    } == before


def test_existing_execution_refuses_before_any_checkpoint_write(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    execution_path = _checkpoint_paths(prepared.paths)[3]
    execution_path.write_text("{}\n", encoding="utf-8")
    execution_path.chmod(0o600)

    with pytest.raises(StatePersistenceError):
        _call(prepared)
    assert not _checkpoint_paths(prepared.paths)[0].exists()
    assert not _checkpoint_paths(prepared.paths)[1].exists()


def test_matching_lock_canonical_identity_permissions_and_duplicates(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    unlocked = ClusterLock(prepared.paths, "check-jump-hosts", 0)
    with pytest.raises(StateLockError, match="matching acquired"):
        prepare_ansible_operation_checkpoints(
            prepared.paths.state_root,
            "example",
            _OPERATION_ID,
            "check-jump-hosts",
            prepared.request,
            prepared.readiness,
            unlocked,
        )
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong,
        pytest.raises(StateLockError, match="matching operation"),
    ):
        prepare_ansible_operation_checkpoints(
            prepared.paths.state_root,
            "example",
            _OPERATION_ID,
            "check-jump-hosts",
            prepared.request,
            prepared.readiness,
            wrong,
        )
    forged = replace(
        prepared.request,
        paths=replace(prepared.paths, operations=tmp_path / "outside"),
    )
    with (
        ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock,
        pytest.raises(StateConflictError, match="identity conflicts"),
    ):
        prepare_ansible_operation_checkpoints(
            prepared.paths.state_root,
            "example",
            _OPERATION_ID,
            "check-jump-hosts",
            forged,
            prepared.readiness,
            lock,
        )

    duplicate = prepared.paths.operations / (
        f"{str(_OPERATION_ID).upper()}.ansible-operation-binding.json"
    )
    duplicate.write_text("{}\n", encoding="utf-8")
    duplicate.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous duplicate"):
        _call(prepared)
    duplicate.unlink()

    _call(prepared)
    binding_path = _checkpoint_paths(prepared.paths)[0]
    binding_path.chmod(0o644)
    with pytest.raises(UnsafePathError, match="0600"):
        _call(prepared)


def test_symlink_companion_and_public_api_surface_fail_closed(tmp_path: Path) -> None:
    prepared = _prepare(tmp_path)
    binding_path = _checkpoint_paths(prepared.paths)[0]
    target = tmp_path / "outside.json"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    binding_path.symlink_to(target)
    with pytest.raises(UnsafePathError, match="symlink"):
        _call(prepared)

    parameters = inspect.signature(prepare_ansible_operation_checkpoints).parameters
    for forbidden in (
        "plan",
        "paths",
        "commands",
        "variables",
        "environment",
        "inventory",
        "runner",
        "executables",
    ):
        assert forbidden not in parameters
