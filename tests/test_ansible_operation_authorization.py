import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from test_ansible import _inventory, _metadata, _paths, _readiness

from scylla_vms.ansible.operation_authorization import (
    ANSIBLE_OPERATION_AUTHORIZATION_SCHEMA_VERSION,
    AuthorizationProofKind,
    AuthorizationState,
    ConfirmationPolicy,
    InteractiveConfirmation,
    OperationAuthorization,
    OperationAuthorizationStore,
    build_operation_authorization,
    checkpoint_operation_authorization,
    confirmation_policy_for,
    validate_current_operation_authorization,
    validate_operation_authorization,
)
from scylla_vms.ansible.operation_binding import (
    ANSIBLE_OPERATION_RESUME_SCHEMA_VERSION,
    ConfirmationState,
    OperationPlanBindingStore,
    StoredOperationPlanBinding,
    build_operation_plan_binding,
    normalized_operation_request_digest,
    validate_operation_plan_resume,
)
from scylla_vms.ansible.orchestration import (
    AnsibleOperationPlan,
    AnsibleOperationPlanStatus,
    AnsibleOperationPlanStep,
    AnsibleOperationStepStatus,
    ansible_operation_plan_checkpoint_evidence,
)
from scylla_vms.ansible.readiness import EvidenceStatus, ReadinessReport
from scylla_vms.cli import parse_operation_request
from scylla_vms.errors import (
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
    StoredOperationRecord,
)
from scylla_vms.locking import ClusterLock, ClusterReadLock
from scylla_vms.models import OperationRequest, OptionValue
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import serialize_json
from scylla_vms.state import StatePaths

_OPERATION_ID = uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
_OTHER_OPERATION_ID = uuid.UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
_PRIVATE_PATH = "/private/operator/id_ed25519"
_SECRET = "obviously-fake-authorization-secret"
_DEVICE = "/dev/disk/by-id/obviously-fake-device"


def _clock(minute: int = 0) -> datetime:
    return datetime(2026, 9, 18, 13, minute, tzinfo=UTC)


def _parse(
    paths: StatePaths,
    operation: str,
    operation_arguments: list[str],
    *,
    non_interactive: bool = False,
    secret: str | None = None,
) -> OperationRequest:
    global_arguments = ["--non-interactive"] if non_interactive else []
    environment = (
        {"DEPLOY_SCYLLA_VMS_MANAGER_AUTH_TOKEN": secret} if secret is not None else {}
    )
    return parse_operation_request(
        [
            "--cluster-name",
            "example",
            "--state-dir",
            str(paths.state_root),
            *global_arguments,
            operation,
            *operation_arguments,
        ],
        environ=environment,
    )


def _add_request(
    paths: StatePaths,
    *,
    yes: bool = False,
    wipe: bool = False,
    non_interactive: bool = False,
    secret: str | None = None,
) -> OperationRequest:
    arguments = [
        "--oci-auth-mode",
        "instance-principal",
        "--node-id",
        "jump-host-1",
        "--zone",
        "AD-1",
    ]
    if yes:
        arguments.append("--yes")
    if wipe:
        arguments.extend(["--wipe-storage", "--confirm-wipe-device", _DEVICE])
    return _parse(
        paths,
        "add-node",
        arguments,
        non_interactive=non_interactive,
        secret=secret,
    )


def _destroy_node_request(
    paths: StatePaths,
    *,
    yes: bool = False,
    exact: bool = False,
    non_interactive: bool = False,
) -> OperationRequest:
    arguments = [
        "--oci-auth-mode",
        "instance-principal",
        "--node-id",
        "jump-host-1",
        "--removal-mode",
        "live",
        "--allow-destructive",
    ]
    if yes:
        arguments.append("--yes")
    if exact:
        arguments.extend(["--confirm-destroy-node", "jump-host-1"])
    return _parse(
        paths,
        "destroy-node",
        arguments,
        non_interactive=non_interactive,
    )


def _redeploy_request(paths: StatePaths, *, yes: bool = False) -> OperationRequest:
    arguments = [
        "--oci-auth-mode",
        "instance-principal",
        "--scope",
        "host",
        "--target-host",
        "jump-host-1",
        "--infrastructure",
        "configuration-only",
    ]
    if yes:
        arguments.append("--yes")
    return _parse(paths, "redeploy", arguments)


def _monitoring_restart_request(
    paths: StatePaths,
    *,
    yes: bool,
    explicit_restart: bool,
) -> OperationRequest:
    arguments = [
        "--oci-auth-mode",
        "instance-principal",
        "--service-action",
        "restart",
    ]
    if yes:
        arguments.append("--yes")
    if explicit_restart:
        arguments.append("--confirm-monitoring-restart")
    return _parse(paths, "refresh-monitoring", arguments)


def _read_only_request(paths: StatePaths) -> OperationRequest:
    return _parse(paths, "check-jump-hosts", [])


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


@dataclass(frozen=True)
class PreparedAuthorization:
    paths: StatePaths
    request: OperationRequest
    readiness: ReadinessReport
    plan: AnsibleOperationPlan
    journal: StoredOperationRecord
    binding: StoredOperationPlanBinding


def _synthetic_ready_plan(request: OperationRequest) -> AnsibleOperationPlan:
    classification = request.operation.classification
    return AnsibleOperationPlan(
        operation=request.operation.name,
        operation_classification=classification,
        effective_classification=classification,
        operation_implemented=True,
        active_conditions=(),
        status=AnsibleOperationPlanStatus.READY,
        blockers=(),
        steps=(
            AnsibleOperationPlanStep(
                sequence=1,
                playbook="inventory-preflight",
                condition="always",
                classification=classification,
                status=AnsibleOperationStepStatus.READY,
                limit=("jump-host-1",),
                variable_names=(),
                variables_digest=None,
                check_mode=False,
                blockers=(),
            ),
        ),
    )


def _prepare(
    tmp_path: Path,
    request_factory: Callable[[StatePaths], OperationRequest],
) -> PreparedAuthorization:
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    paths = _paths(tmp_path)
    request = request_factory(paths)
    plan = _synthetic_ready_plan(request)
    readiness = _readiness(_inventory())
    request_digest = normalized_operation_request_digest(request)
    journal_store = OperationJournalStore(paths, _OPERATION_ID)
    binding_store = OperationPlanBindingStore(paths, _OPERATION_ID)
    with ClusterLock(paths, request.operation.name, 0) as lock:
        pending = OperationRecord.create(
            operation_id=_OPERATION_ID,
            operation=request.operation.name,
            cluster_uuid=_metadata().cluster_uuid,
            cluster_name=_metadata().cluster_name,
            request_digest=request_digest,
            clock=lambda: _clock(),
        )
        initial = journal_store.write(
            pending, expected_generation=0, expected_digest=None
        )
        planned = pending.transition(
            status=JournalStatus.IN_PROGRESS,
            phase=OperationPhase.PLAN,
            evidence=(ansible_operation_plan_checkpoint_evidence(plan),),
            clock=lambda: _clock(1),
        )
        journal = journal_store.write(
            planned,
            expected_generation=initial.record.generation,
            expected_digest=initial.digest,
        )
        binding_record = build_operation_plan_binding(
            _metadata(),
            request,
            _OPERATION_ID,
            plan,
            readiness,
            journal,
            clock=lambda: _clock(2),
        )
        binding = binding_store.write_locked(
            binding_record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    return PreparedAuthorization(paths, request, readiness, plan, journal, binding)


def _checkpoint(
    prepared: PreparedAuthorization,
    *,
    interactive: InteractiveConfirmation | None = None,
) -> tuple[OperationAuthorizationStore, OperationAuthorization]:
    store = OperationAuthorizationStore(prepared.paths, _OPERATION_ID)
    with ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock:
        stored = checkpoint_operation_authorization(
            lock,
            _metadata(),
            prepared.request,
            _OPERATION_ID,
            interactive=interactive or InteractiveConfirmation(),
            clock=lambda: _clock(3),
        )
    return store, stored.record


@pytest.mark.parametrize(
    ("factory", "policy"),
    [
        (lambda paths: _add_request(paths, yes=True), ConfirmationPolicy.MUTATING),
        (
            lambda paths: _redeploy_request(paths, yes=True),
            ConfirmationPolicy.SENSITIVE,
        ),
        (
            lambda paths: _destroy_node_request(paths, yes=True, exact=True),
            ConfirmationPolicy.DESTRUCTIVE,
        ),
        (lambda paths: _read_only_request(paths), ConfirmationPolicy.NOT_REQUIRED),
    ],
)
def test_confirmation_policy_preserves_operation_classifications(
    tmp_path: Path,
    factory: Callable[[StatePaths], OperationRequest],
    policy: ConfirmationPolicy,
) -> None:
    prepared = _prepare(tmp_path, factory)
    assert confirmation_policy_for(prepared.request, prepared.binding.record) is policy


def test_authorization_checkpoint_is_owner_only_immutable_and_resumable(
    tmp_path: Path,
) -> None:
    prepared = _prepare(
        tmp_path,
        lambda paths: _add_request(paths, yes=True, non_interactive=True),
    )
    journal_before = (prepared.paths.operations / f"{_OPERATION_ID}.json").read_bytes()
    store, record = _checkpoint(prepared)
    assert store.path == (
        prepared.paths.operations
        / f"{_OPERATION_ID}.ansible-operation-authorization.json"
    )
    assert store.path.stat().st_mode & 0o777 == 0o600
    assert record.schema_version == ANSIBLE_OPERATION_AUTHORIZATION_SCHEMA_VERSION
    assert record.authorization_state is AuthorizationState.AUTHORIZED_PRE_EXECUTION
    assert record.execution_state.value == "not-started"
    assert record.journal_phase is OperationPhase.PLAN
    assert (
        prepared.paths.operations / f"{_OPERATION_ID}.json"
    ).read_bytes() == journal_before

    with ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock:
        validation = validate_operation_plan_resume(
            lock,
            _metadata(),
            prepared.request,
            _OPERATION_ID,
            prepared.plan,
            prepared.readiness,
        )
    assert validation.schema_version == ANSIBLE_OPERATION_RESUME_SCHEMA_VERSION
    assert validation.confirmation_state is ConfirmationState.AUTHORIZED
    assert validation.authorization_digest is not None
    assert validation.resume_state.value == "resumable-pre-execution"


def test_read_only_operation_does_not_create_authorization(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path, _read_only_request)
    store = OperationAuthorizationStore(prepared.paths, _OPERATION_ID)
    with (
        ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock,
        pytest.raises(StateConflictError, match="must not manufacture"),
    ):
        checkpoint_operation_authorization(
            lock,
            _metadata(),
            prepared.request,
            _OPERATION_ID,
            interactive=InteractiveConfirmation(),
            clock=lambda: _clock(3),
        )
    assert not store.path.exists()

    with ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock:
        validation = validate_operation_plan_resume(
            lock,
            _metadata(),
            prepared.request,
            _OPERATION_ID,
            prepared.plan,
            prepared.readiness,
        )
    assert validation.confirmation_state is ConfirmationState.NOT_REQUIRED
    assert validation.authorization_digest is None


def test_generic_yes_never_supplies_destructive_scope(
    tmp_path: Path,
) -> None:
    prepared = _prepare(
        tmp_path,
        lambda paths: _destroy_node_request(paths, yes=True, exact=False),
    )
    with pytest.raises(StateConflictError, match="exact destructive"):
        build_operation_authorization(
            _metadata(),
            prepared.request,
            prepared.binding,
            prepared.journal,
            interactive=InteractiveConfirmation(),
            clock=lambda: _clock(3),
        )

    interactive = _prepare(
        tmp_path / "interactive",
        lambda paths: _destroy_node_request(paths),
    )
    _, record = _checkpoint(
        interactive,
        interactive=InteractiveConfirmation(
            ordinary_approved=True,
            exact_scope_approved=True,
        ),
    )
    assert {proof.kind for proof in record.proofs} == {
        AuthorizationProofKind.ORDINARY_CONFIRMATION,
        AuthorizationProofKind.DESTRUCTIVE_CLASS,
        AuthorizationProofKind.EXACT_OPERATION_SCOPE,
    }


def test_storage_wipe_and_restart_consents_remain_separate(
    tmp_path: Path,
) -> None:
    wipe = _prepare(
        tmp_path / "wipe",
        lambda paths: _add_request(paths, yes=True, wipe=True),
    )
    wipe_store, wipe_record = _checkpoint(wipe)
    wipe_kinds = {proof.kind for proof in wipe_record.proofs}
    assert wipe_kinds == {
        AuthorizationProofKind.ORDINARY_CONFIRMATION,
        AuthorizationProofKind.STORAGE_WIPE,
    }
    assert AuthorizationProofKind.DESTRUCTIVE_CLASS not in wipe_kinds
    assert _DEVICE not in wipe_store.path.read_text(encoding="utf-8")

    restart = _prepare(
        tmp_path / "restart",
        lambda paths: _monitoring_restart_request(
            paths, yes=True, explicit_restart=True
        ),
    )
    _, restart_record = _checkpoint(restart)
    assert {proof.kind for proof in restart_record.proofs} == {
        AuthorizationProofKind.ORDINARY_CONFIRMATION,
        AuthorizationProofKind.MONITORING_RESTART,
    }

    restart_interactive = _prepare(
        tmp_path / "restart-interactive",
        lambda paths: _monitoring_restart_request(
            paths, yes=False, explicit_restart=False
        ),
    )
    _, interactive_record = _checkpoint(
        restart_interactive,
        interactive=InteractiveConfirmation(
            ordinary_approved=True,
            monitoring_restart_approved=True,
        ),
    )
    assert len(interactive_record.proofs) == 2


def test_missing_replayed_cross_scope_and_drifted_authorization_fail_closed(
    tmp_path: Path,
) -> None:
    prepared = _prepare(
        tmp_path,
        lambda paths: _add_request(paths, yes=True),
    )
    with (
        ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock,
        pytest.raises(StateConflictError, match="checkpoint is missing"),
    ):
        validate_current_operation_authorization(
            lock,
            _metadata(),
            prepared.request,
            prepared.binding,
            prepared.journal,
        )

    store, record = _checkpoint(prepared)
    drifted_request = _replace_request_option(prepared.request, "log_level", "warning")
    with (
        ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock,
        pytest.raises(StateConflictError, match="request binding drifted"),
    ):
        validate_current_operation_authorization(
            lock,
            _metadata(),
            drifted_request,
            prepared.binding,
            prepared.journal,
        )

    replay_store = OperationAuthorizationStore(prepared.paths, _OTHER_OPERATION_ID)
    replay_store.path.write_bytes(store.path.read_bytes())
    replay_store.path.chmod(0o600)
    with (
        ClusterReadLock(prepared.paths, 0) as lock,
        pytest.raises(StatePersistenceError, match="identity mismatch"),
    ):
        replay_store.read_locked(
            lock,
            expected_cluster_uuid=_metadata().cluster_uuid,
            expected_cluster_name="example",
        )

    with pytest.raises(StatePersistenceError, match="classification conflicts"):
        replace(
            record,
            operation_classification=OperationClassification.SENSITIVE,
        )

    wrong_cluster = replace(
        record,
        cluster_uuid=uuid.UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
    )
    with pytest.raises(StateConflictError, match="identity or provenance drifted"):
        validate_operation_authorization(
            _metadata(),
            prepared.request,
            prepared.binding,
            prepared.journal,
            wrong_cluster,
        )

    wrong_target = replace(record, selected_stable_ids=("other-host",))
    with pytest.raises(StateConflictError, match="identity or provenance drifted"):
        validate_operation_authorization(
            _metadata(),
            prepared.request,
            prepared.binding,
            prepared.journal,
            wrong_target,
        )


def test_stale_evidence_and_advanced_journal_refuse_authorization_resume(
    tmp_path: Path,
) -> None:
    prepared = _prepare(
        tmp_path,
        lambda paths: _add_request(paths, yes=True),
    )
    _checkpoint(prepared)
    stale = replace(prepared.readiness, source_status=EvidenceStatus.STALE)
    with (
        ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock,
        pytest.raises(StateConflictError, match="current fresh readiness"),
    ):
        validate_operation_plan_resume(
            lock,
            _metadata(),
            prepared.request,
            _OPERATION_ID,
            prepared.plan,
            stale,
        )

    journal_store = OperationJournalStore(prepared.paths, _OPERATION_ID)
    current = journal_store.read(
        expected_cluster_uuid=_metadata().cluster_uuid,
        expected_cluster_name="example",
    )
    advanced = current.record.transition(
        status=JournalStatus.IN_PROGRESS,
        phase=OperationPhase.CONFIRM,
        evidence=current.record.evidence,
        clock=lambda: _clock(4),
    )
    journal_store.write(
        advanced,
        expected_generation=current.record.generation,
        expected_digest=current.digest,
    )
    with (
        ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock,
        pytest.raises(StateConflictError, match="confirmation-state-ambiguous"),
    ):
        validate_operation_plan_resume(
            lock,
            _metadata(),
            prepared.request,
            _OPERATION_ID,
            prepared.plan,
            prepared.readiness,
        )


def test_authorization_requires_matching_lock_and_canonical_path(
    tmp_path: Path,
) -> None:
    prepared = _prepare(
        tmp_path,
        lambda paths: _add_request(paths, yes=True),
    )
    unlocked = ClusterLock(prepared.paths, prepared.request.operation.name, 0)
    with pytest.raises(StateLockError, match="matching acquired"):
        checkpoint_operation_authorization(
            unlocked,
            _metadata(),
            prepared.request,
            _OPERATION_ID,
            interactive=InteractiveConfirmation(),
            clock=lambda: _clock(3),
        )
    with (
        ClusterLock(prepared.paths, "deploy", 0) as wrong,
        pytest.raises(StateLockError, match="matching operation"),
    ):
        checkpoint_operation_authorization(
            wrong,
            _metadata(),
            prepared.request,
            _OPERATION_ID,
            interactive=InteractiveConfirmation(),
            clock=lambda: _clock(3),
        )
    forged = replace(prepared.paths, operations=tmp_path / "outside")
    with pytest.raises(UnsafePathError, match="not canonical"):
        OperationAuthorizationStore(forged, _OPERATION_ID)
    with pytest.raises(StatePersistenceError, match="must be a UUID"):
        OperationAuthorizationStore(prepared.paths, cast(uuid.UUID, "../escape"))


def test_authorization_symlink_permissions_malformed_schema_and_redaction(
    tmp_path: Path,
) -> None:
    prepared = _prepare(
        tmp_path,
        lambda paths: _add_request(paths, yes=True, wipe=True, secret=_SECRET),
    )
    store, record = _checkpoint(prepared)
    persisted = store.path.read_text(encoding="utf-8")
    public = json.dumps(record.to_public_object(), sort_keys=True)
    for protected in (
        _SECRET,
        _DEVICE,
        _PRIVATE_PATH,
        str(prepared.paths.cluster_root),
        "203.0.113.10",
        "10.0.0.10",
        "ocid1.instance.oc1.iad.fakejump",
    ):
        assert protected not in persisted
        assert protected not in public

    original = store.path.read_bytes()
    store.path.unlink()
    outside = tmp_path / "outside-authorization.json"
    outside.write_bytes(original)
    outside.chmod(0o600)
    store.path.symlink_to(outside)
    with (
        ClusterReadLock(prepared.paths, 0) as lock,
        pytest.raises(UnsafePathError, match="symbolic link"),
    ):
        store.read_locked(
            lock,
            expected_cluster_uuid=_metadata().cluster_uuid,
            expected_cluster_name="example",
        )

    store.path.unlink()
    store.path.write_bytes(original)
    store.path.chmod(0o644)
    with (
        ClusterReadLock(prepared.paths, 0) as lock,
        pytest.raises(UnsafePathError, match="permissions must be 0600"),
    ):
        store.read_locked(
            lock,
            expected_cluster_uuid=_metadata().cluster_uuid,
            expected_cluster_name="example",
        )

    store.path.chmod(0o600)
    document = json.loads(original)
    document["schema_version"] = (
        "deploy-scylla-vms.ansible-operation-authorization/v999"
    )
    store.path.write_bytes(serialize_json(document))
    store.path.chmod(0o600)
    with (
        ClusterReadLock(prepared.paths, 0) as lock,
        pytest.raises(StatePersistenceError, match="unsupported"),
    ):
        store.read_locked(
            lock,
            expected_cluster_uuid=_metadata().cluster_uuid,
            expected_cluster_name="example",
        )

    document["schema_version"] = ANSIBLE_OPERATION_AUTHORIZATION_SCHEMA_VERSION
    document["unexpected"] = True
    store.path.write_bytes(serialize_json(document))
    store.path.chmod(0o600)
    with (
        ClusterReadLock(prepared.paths, 0) as lock,
        pytest.raises(StatePersistenceError, match="fields do not match"),
    ):
        store.read_locked(
            lock,
            expected_cluster_uuid=_metadata().cluster_uuid,
            expected_cluster_name="example",
        )


def test_authorization_atomic_failure_and_generation_guards(
    tmp_path: Path,
) -> None:
    prepared = _prepare(
        tmp_path,
        lambda paths: _add_request(paths, yes=True),
    )
    store = OperationAuthorizationStore(
        prepared.paths, _OPERATION_ID, token_factory=lambda: "fixed"
    )
    record = build_operation_authorization(
        _metadata(),
        prepared.request,
        prepared.binding,
        prepared.journal,
        interactive=InteractiveConfirmation(),
        clock=lambda: _clock(3),
    )
    temporary = store.path.with_name(f".{store.path.name}.fixed.tmp")
    temporary.write_text("occupied", encoding="utf-8")
    temporary.chmod(0o600)
    with (
        ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock,
        pytest.raises(StatePersistenceError, match="temporary state file"),
    ):
        store.write_locked(
            record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
            request=prepared.request,
            metadata=_metadata(),
        )
    assert not store.path.exists()
    assert temporary.read_text(encoding="utf-8") == "occupied"

    temporary.unlink()
    with ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock:
        stored = store.write_locked(
            record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
            request=prepared.request,
            metadata=_metadata(),
        )
        assert (
            store.write_locked(
                record,
                expected_generation=stored.record.generation,
                expected_digest=stored.digest,
                lock=lock,
                request=prepared.request,
                metadata=_metadata(),
            )
            == stored
        )
        with pytest.raises(StatePersistenceError, match="changed concurrently"):
            store.write_locked(
                record,
                expected_generation=99,
                expected_digest=stored.digest,
                lock=lock,
                request=prepared.request,
                metadata=_metadata(),
            )
