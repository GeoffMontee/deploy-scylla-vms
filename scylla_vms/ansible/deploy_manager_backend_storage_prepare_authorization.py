"""Immutable authorization for Manager-local destructive storage preparation.

This internal owner derives its complete scope from the canonical Manager
backend storage-preflight reconciliation.  It records approval only: execution,
storage mutation, journal transitions, and public workflow wiring remain absent.
"""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import Enum, StrEnum
from pathlib import Path
from typing import Any

from scylla_vms.ansible.deploy_manager_backend_storage_preflight_execution import (
    _require_canonical_paths,
)
from scylla_vms.ansible.deploy_manager_backend_storage_preflight_reconciliation import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION,
    DeployManagerBackendStoragePreflightNextStatus,
    DeployManagerBackendStoragePreflightReconciliation,
    DeployManagerBackendStoragePreflightReconciliationStore,
    StoredDeployManagerBackendStoragePreflightReconciliation,
    _assert_operation_lock,
    reconcile_deploy_manager_backend_storage_preflight,
)
from scylla_vms.ansible.deploy_plan import _digest_object, _require_operation_id
from scylla_vms.ansible.registry import get_playbook
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.errors import StateConflictError, StatePersistenceError
from scylla_vms.journal import JOURNAL_SCHEMA_VERSION, JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import (
    AtomicJsonFile,
    format_timestamp,
    parse_timestamp,
    parse_uuid,
    require_exact_keys,
    require_string,
    validate_digest,
)
from scylla_vms.state import (
    StatePaths,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)

ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_GENERAL_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-prepare-general-proof/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_WIPE_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-prepare-wipe-proof/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-prepare-authorization/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_AUTHORIZATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-prepare-"
    "authorization-report/v1"
)
DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_AUTHORIZATION_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-storage-prepare-authorization.json"
)

_OPERATION = "deploy"
_STAGE = "manager-backend-storage-prepare-authorization"
_PLAYBOOK = "manager-backend-storage-prepare"
_AUTHORIZED = "authorized-pre-execution"
_UNCONSUMED = "unconsumed"
_UNAVAILABLE = "unavailable"
_NOT_STARTED = "not-started"
_NOT_PERFORMED = "not-performed"
_APPROVED = "approved"
_MATCHED = "matched"
_NOT_REQUIRED = "not-required"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class DeployManagerBackendStoragePrepareApprovalMethod(StrEnum):
    """PLAN-permitted ordinary approval methods."""

    INTERACTIVE = "interactive"
    CLI_YES = "cli-yes"


class DeployManagerBackendStoragePrepareAuthorizationArtifactState(StrEnum):
    """Immutable authorization persistence result."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStoragePrepareDestructiveScopeProof:
    """Address-free exact preparation scope acknowledged by the operator."""

    prepare_target_count: int
    preparation_target_set_digest: str
    preparation_scope_digest: str

    def __post_init__(self) -> None:
        if self.prepare_target_count != 1:
            raise StateConflictError(
                "Manager backend storage preparation requires one exact target"
            )
        validate_digest(
            self.preparation_target_set_digest,
            "Manager backend storage preparation proof target digest",
        )
        validate_digest(
            self.preparation_scope_digest,
            "Manager backend storage preparation proof scope digest",
        )

    @classmethod
    def from_reconciliation(
        cls,
        reconciliation: StoredDeployManagerBackendStoragePreflightReconciliation,
    ) -> DeployManagerBackendStoragePrepareDestructiveScopeProof:
        record = reconciliation.record
        return cls(
            record.preparation_target_count,
            record.preparation_target_set_digest,
            record.preparation_scope_digest,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStoragePrepareGeneralAuthorizationProof:
    """Normalized ordinary plus destructive approval without free-form input."""

    approval_method: DeployManagerBackendStoragePrepareApprovalMethod | None = None
    approved: bool = False
    allow_destructive: bool = False
    destructive_scope: (
        DeployManagerBackendStoragePrepareDestructiveScopeProof | None
    ) = None

    def __post_init__(self) -> None:
        if self.approval_method is not None and not isinstance(
            self.approval_method,
            DeployManagerBackendStoragePrepareApprovalMethod,
        ):
            raise StateConflictError(
                "Manager backend storage preparation approval method is invalid"
            )
        if (
            not isinstance(self.approved, bool)
            or not isinstance(self.allow_destructive, bool)
            or (
                self.destructive_scope is not None
                and not isinstance(
                    self.destructive_scope,
                    DeployManagerBackendStoragePrepareDestructiveScopeProof,
                )
            )
        ):
            raise StateConflictError(
                "Manager backend storage preparation proof is malformed"
            )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStoragePrepareWipeAuthorizationProof:
    """Separate exact wipe consent without a raw device identity."""

    consented: bool
    wipe_target_count: int
    wipe_target_set_digest: str
    wipe_scope_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.consented, bool) or self.wipe_target_count != 1:
            raise StateConflictError(
                "Manager backend storage preparation wipe proof is malformed"
            )
        validate_digest(
            self.wipe_target_set_digest,
            "Manager backend storage preparation wipe target digest",
        )
        validate_digest(
            self.wipe_scope_digest,
            "Manager backend storage preparation wipe scope digest",
        )

    @classmethod
    def from_reconciliation(
        cls,
        reconciliation: StoredDeployManagerBackendStoragePreflightReconciliation,
    ) -> DeployManagerBackendStoragePrepareWipeAuthorizationProof:
        record = reconciliation.record
        if not record.wipe_required or record.wipe_target_count != 1:
            raise StateConflictError(
                "Manager backend storage preparation wipe proof is not required"
            )
        return cls(
            True,
            record.wipe_target_count,
            record.wipe_target_set_digest,
            record.wipe_scope_digest,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStoragePrepareAuthorization:
    """Persisted immutable pre-execution authorization checkpoint."""

    generation: int
    created_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    stage: str
    classification: OperationClassification
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    reconciliation_schema_version: str
    reconciliation_artifact_digest: str
    reconciliation_record_digest: str
    validated_prior_chain_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    playbook_source_digest: str
    target_stable_id: str
    target_set_digest: str
    preparation_target_count: int
    preparation_target_set_digest: str
    preparation_scope_digest: str
    device_set_digest: str
    preparation_intent_digest: str
    wipe_required: bool
    wipe_target_count: int
    wipe_target_set_digest: str
    wipe_scope_digest: str
    general_proof_schema_version: str
    approval_method: DeployManagerBackendStoragePrepareApprovalMethod
    approval_state: str
    allow_destructive: bool
    destructive_scope_state: str
    general_proof_digest: str
    wipe_proof_schema_version: str | None
    wipe_consent_state: str
    wipe_proof_digest: str | None
    authorization_state: str
    authorization_consumption_state: str
    execution_state: str
    mutation_state: str
    journal_transition_state: str
    finalization_state: str
    public_workflow_state: str
    record_digest: str
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        definition = get_playbook(_PLAYBOOK)
        expected_wipe_schema = (
            ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_WIPE_PROOF_SCHEMA_VERSION
            if self.wipe_required
            else None
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.reconciliation_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
            or self.general_proof_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_GENERAL_PROOF_SCHEMA_VERSION
            or self.wipe_proof_schema_version != expected_wipe_schema
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.classification is not OperationClassification.DESTRUCTIVE
            or definition.classification is not self.classification
            or not definition.source_available
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
            or self.target_set_digest != _digest_object([self.target_stable_id])
            or self.preparation_target_count != 1
            or self.wipe_target_count != (1 if self.wipe_required else 0)
            or self.approval_state != _APPROVED
            or self.allow_destructive is not True
            or self.destructive_scope_state != _MATCHED
            or self.wipe_consent_state
            != (_MATCHED if self.wipe_required else _NOT_REQUIRED)
            or (self.wipe_required != (self.wipe_proof_digest is not None))
            or self.authorization_state != _AUTHORIZED
            or self.authorization_consumption_state != _UNCONSUMED
            or self.execution_state != _UNAVAILABLE
            or self.mutation_state != _NOT_PERFORMED
            or self.journal_transition_state != _NOT_PERFORMED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
            or self.record_digest != _record_digest(self)
        ):
            raise StatePersistenceError(
                "Manager backend storage preparation authorization conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        if self.journal_generation < 1:
            raise StatePersistenceError(
                "Manager backend storage preparation journal generation is invalid"
            )
        for name in self.__dataclass_fields__:
            if name.endswith("_digest"):
                value = getattr(self, name)
                if value is not None:
                    validate_digest(
                        value,
                        "Manager backend storage preparation authorization digest",
                    )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendStoragePrepareAuthorization:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend storage preparation authorization",
        )
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in {
                    "generation",
                    "journal_generation",
                    "preparation_target_count",
                    "wipe_target_count",
                }:
                    parsed[name] = _integer(item, name)
                elif name in {"cluster_uuid", "operation_id"}:
                    parsed[name] = parse_uuid(require_string(value, name), name)
                elif name == "classification":
                    parsed[name] = OperationClassification(require_string(value, name))
                elif name == "journal_status":
                    parsed[name] = JournalStatus(require_string(value, name))
                elif name == "journal_phase":
                    parsed[name] = OperationPhase(require_string(value, name))
                elif name == "approval_method":
                    parsed[name] = DeployManagerBackendStoragePrepareApprovalMethod(
                        require_string(value, name)
                    )
                elif name in {"allow_destructive", "wipe_required"}:
                    parsed[name] = _boolean(item, name)
                elif name in {
                    "wipe_proof_schema_version",
                    "wipe_proof_digest",
                }:
                    parsed[name] = _optional_string(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend storage preparation authorization enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendStoragePrepareAuthorization:
    record: DeployManagerBackendStoragePrepareAuthorization
    artifact_digest: str


class DeployManagerBackendStoragePrepareAuthorizationStore:
    """Owner-only immutable authorization persistence."""

    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        _require_canonical_paths(paths)
        self._paths = paths
        self._operation_id = _require_operation_id(operation_id)
        self._path = deploy_manager_backend_storage_prepare_authorization_path(
            paths, operation_id
        )
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployManagerBackendStoragePrepareAuthorization:
        value, digest = self._file.read()
        record = DeployManagerBackendStoragePrepareAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "Manager backend storage preparation authorization identity conflicts"
            )
        return StoredDeployManagerBackendStoragePrepareAuthorization(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendStoragePrepareAuthorization:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendStoragePrepareAuthorization,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerBackendStoragePrepareAuthorization,
        DeployManagerBackendStoragePrepareAuthorizationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Manager backend storage preparation authorization operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "Manager backend storage preparation authorization is immutable"
                )
            return (
                current,
                DeployManagerBackendStoragePrepareAuthorizationArtifactState.REUSED,
            )
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerBackendStoragePrepareAuthorization(record, digest),
            DeployManagerBackendStoragePrepareAuthorizationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStoragePrepareAuthorizationReport:
    operation_id: uuid.UUID
    artifact_state: DeployManagerBackendStoragePrepareAuthorizationArtifactState
    artifact_digest: str
    record_digest: str
    target_count: int
    target_set_digest: str
    preparation_scope_digest: str
    wipe_required: bool
    wipe_target_count: int
    wipe_scope_digest: str
    approval_method: DeployManagerBackendStoragePrepareApprovalMethod
    general_proof_digest: str
    wipe_proof_state: str
    wipe_proof_digest: str | None
    authorization_state: str
    authorization_consumption_state: str
    execution_state: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_AUTHORIZATION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_AUTHORIZATION_REPORT_SCHEMA_VERSION
            or self.target_count != 1
            or self.wipe_target_count != (1 if self.wipe_required else 0)
            or self.wipe_proof_state
            != (_MATCHED if self.wipe_required else _NOT_REQUIRED)
            or self.authorization_state != _AUTHORIZED
            or self.authorization_consumption_state != _UNCONSUMED
            or self.execution_state != _UNAVAILABLE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError(
                "Manager backend storage preparation authorization report conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)


def authorize_deploy_manager_backend_storage_prepare(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    general_proof: DeployManagerBackendStoragePrepareGeneralAuthorizationProof,
    wipe_proof: (
        DeployManagerBackendStoragePrepareWipeAuthorizationProof | None
    ) = None,
) -> DeployManagerBackendStoragePrepareAuthorizationReport:
    """Authorize the exact reconciled Manager storage scope without execution."""

    if not isinstance(
        general_proof,
        DeployManagerBackendStoragePrepareGeneralAuthorizationProof,
    ):
        raise StateConflictError(
            "Manager backend storage preparation general proof is malformed"
        )
    if wipe_proof is not None and not isinstance(
        wipe_proof,
        DeployManagerBackendStoragePrepareWipeAuthorizationProof,
    ):
        raise StateConflictError(
            "Manager backend storage preparation wipe proof is malformed"
        )
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_artifacts(paths, operation_id)

    # This replays the complete upstream validation chain and is zero-write for
    # an exact current reconciliation.
    reconcile_deploy_manager_backend_storage_preflight(
        state_root=state_root,
        cluster_name=cluster_name,
        operation_id=operation_id,
        lock=lock,
    )
    reconciliation_store = DeployManagerBackendStoragePreflightReconciliationStore(
        paths, operation_id
    )
    reconciliation = _read_reconciliation(reconciliation_store, lock=lock)
    record = reconciliation.record
    _validate_authorizable_reconciliation(record)
    _validate_general_proof(general_proof, reconciliation)
    _validate_wipe_proof(wipe_proof, reconciliation)

    store = DeployManagerBackendStoragePrepareAuthorizationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    existing = (
        store.read_locked(
            lock,
            expected_cluster_uuid=record.cluster_uuid,
            expected_cluster_name=record.cluster_name,
        )
        if store.path.exists()
        else None
    )
    expected = _build_authorization(
        reconciliation,
        general_proof=general_proof,
        wipe_proof=wipe_proof,
        created_at=(
            existing.record.created_at
            if existing is not None
            else format_timestamp(datetime.now(UTC))
        ),
    )
    if existing is not None:
        if existing.record != expected:
            raise StateConflictError(
                "Manager backend storage preparation authorization changed; "
                "use a new operation"
            )
        stored = existing
        state = DeployManagerBackendStoragePrepareAuthorizationArtifactState.REUSED
    else:
        stored, state = store.write_locked(expected, lock=lock)
    return _build_report(stored, state=state)


def deploy_manager_backend_storage_prepare_authorization_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}"
        f"{DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "Manager backend storage preparation authorization path is not canonical"
        )
    return path


def deploy_manager_backend_storage_prepare_authorization_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(
        DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_AUTHORIZATION_FILENAME_SUFFIX
    ):
        return None
    value = name[
        : -len(DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_AUTHORIZATION_FILENAME_SUFFIX)
    ]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _read_reconciliation(
    store: DeployManagerBackendStoragePreflightReconciliationStore,
    *,
    lock: ClusterLock,
) -> StoredDeployManagerBackendStoragePreflightReconciliation:
    value, _ = store._file.read()
    raw = store.read_locked(
        lock,
        expected_cluster_uuid=parse_uuid(
            require_string(value, "cluster_uuid"), "cluster_uuid"
        ),
        expected_cluster_name=require_string(value, "cluster_name"),
    )
    return raw


def _validate_authorizable_reconciliation(
    record: DeployManagerBackendStoragePreflightReconciliation,
) -> None:
    if (
        record.next_status
        is not DeployManagerBackendStoragePreflightNextStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        or record.preparation_target_count != 1
        or len(record.preparation_scopes) != 1
        or record.preparation_scopes[0].stable_id != record.target_stable_id
        or record.storage_preparation_source_state != "source-available"
        or record.storage_preparation_authorization_state != _UNAVAILABLE
        or record.journal_status is not JournalStatus.IN_PROGRESS
        or record.journal_phase is not OperationPhase.VERIFY
    ):
        raise StateConflictError(
            "Manager backend storage preparation is not authorization-ready"
        )


def _validate_general_proof(
    proof: DeployManagerBackendStoragePrepareGeneralAuthorizationProof,
    reconciliation: StoredDeployManagerBackendStoragePreflightReconciliation,
) -> None:
    if proof.approval_method is None:
        raise StateConflictError(
            "Manager backend storage preparation ordinary approval is required"
        )
    if not proof.approved:
        raise StateConflictError(
            "Manager backend storage preparation approval was denied"
        )
    if not proof.allow_destructive:
        raise StateConflictError(
            "Manager backend storage preparation requires --allow-destructive"
        )
    if proof.destructive_scope is None:
        raise StateConflictError(
            "Manager backend storage preparation requires exact destructive scope proof"
        )
    if proof.destructive_scope != (
        DeployManagerBackendStoragePrepareDestructiveScopeProof.from_reconciliation(
            reconciliation
        )
    ):
        raise StateConflictError(
            "Manager backend storage preparation destructive scope proof conflicts"
        )


def _validate_wipe_proof(
    proof: DeployManagerBackendStoragePrepareWipeAuthorizationProof | None,
    reconciliation: StoredDeployManagerBackendStoragePreflightReconciliation,
) -> None:
    record = reconciliation.record
    if not record.wipe_required:
        if proof is not None:
            raise StateConflictError("Manager backend storage wipe proof is over-broad")
        return
    if proof is None:
        raise StateConflictError(
            "Manager backend storage preparation requires separate exact wipe consent"
        )
    if not proof.consented:
        raise StateConflictError("Manager backend storage wipe consent was denied")
    if proof != (
        DeployManagerBackendStoragePrepareWipeAuthorizationProof.from_reconciliation(
            reconciliation
        )
    ):
        raise StateConflictError(
            "Manager backend storage wipe proof does not match the exact scope"
        )


def _build_authorization(
    reconciliation: StoredDeployManagerBackendStoragePreflightReconciliation,
    *,
    general_proof: DeployManagerBackendStoragePrepareGeneralAuthorizationProof,
    wipe_proof: DeployManagerBackendStoragePrepareWipeAuthorizationProof | None,
    created_at: str,
) -> DeployManagerBackendStoragePrepareAuthorization:
    record = reconciliation.record
    source = load_ansible_source_bundle()
    source_file = next(
        (
            item
            for item in source.files
            if item.path == f"playbooks/{get_playbook(_PLAYBOOK).filename}"
        ),
        None,
    )
    if source_file is None:
        raise StateConflictError(
            "Manager backend storage preparation source is unavailable"
        )
    general_values = {
        "allow_destructive": True,
        "approval_method": general_proof.approval_method.value,  # type: ignore[union-attr]
        "approval_state": _APPROVED,
        "destructive_scope_state": _MATCHED,
        "preparation_scope_digest": record.preparation_scope_digest,
        "preparation_target_count": record.preparation_target_count,
        "preparation_target_set_digest": record.preparation_target_set_digest,
        "reconciliation_artifact_digest": reconciliation.artifact_digest,
        "reconciliation_record_digest": record.record_digest,
        "schema_version": (
            ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_GENERAL_PROOF_SCHEMA_VERSION
        ),
    }
    wipe_values = (
        {
            "consent_state": _MATCHED,
            "reconciliation_artifact_digest": reconciliation.artifact_digest,
            "reconciliation_record_digest": record.record_digest,
            "schema_version": (
                ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_WIPE_PROOF_SCHEMA_VERSION
            ),
            "wipe_scope_digest": record.wipe_scope_digest,
            "wipe_target_count": record.wipe_target_count,
            "wipe_target_set_digest": record.wipe_target_set_digest,
        }
        if wipe_proof is not None
        else None
    )
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": record.cluster_uuid,
        "cluster_name": record.cluster_name,
        "operation_id": record.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "classification": OperationClassification.DESTRUCTIVE,
        "journal_generation": record.journal_generation,
        "journal_digest": record.journal_digest,
        "journal_status": record.journal_status,
        "journal_phase": record.journal_phase,
        "reconciliation_schema_version": record.schema_version,
        "reconciliation_artifact_digest": reconciliation.artifact_digest,
        "reconciliation_record_digest": record.record_digest,
        "validated_prior_chain_digest": record.full_chain_digest,
        "ansible_source_version": source.version,
        "ansible_source_digest": source.digest,
        "playbook_source_digest": source_file.digest,
        "target_stable_id": record.target_stable_id,
        "target_set_digest": record.target_set_digest,
        "preparation_target_count": record.preparation_target_count,
        "preparation_target_set_digest": record.preparation_target_set_digest,
        "preparation_scope_digest": record.preparation_scope_digest,
        "device_set_digest": record.device_set_digest,
        "preparation_intent_digest": record.preparation_intent_digest,
        "wipe_required": record.wipe_required,
        "wipe_target_count": record.wipe_target_count,
        "wipe_target_set_digest": record.wipe_target_set_digest,
        "wipe_scope_digest": record.wipe_scope_digest,
        "general_proof_schema_version": general_values["schema_version"],
        "approval_method": general_proof.approval_method,
        "approval_state": _APPROVED,
        "allow_destructive": True,
        "destructive_scope_state": _MATCHED,
        "general_proof_digest": _digest_object(general_values),
        "wipe_proof_schema_version": (
            wipe_values["schema_version"] if wipe_values is not None else None
        ),
        "wipe_consent_state": _MATCHED if wipe_values is not None else _NOT_REQUIRED,
        "wipe_proof_digest": (
            _digest_object(wipe_values) if wipe_values is not None else None
        ),
        "authorization_state": _AUTHORIZED,
        "authorization_consumption_state": _UNCONSUMED,
        "execution_state": _UNAVAILABLE,
        "mutation_state": _NOT_PERFORMED,
        "journal_transition_state": _NOT_PERFORMED,
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_values(values)
    return DeployManagerBackendStoragePrepareAuthorization(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployManagerBackendStoragePrepareAuthorization,
    *,
    state: DeployManagerBackendStoragePrepareAuthorizationArtifactState,
) -> DeployManagerBackendStoragePrepareAuthorizationReport:
    record = stored.record
    return DeployManagerBackendStoragePrepareAuthorizationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        artifact_digest=stored.artifact_digest,
        record_digest=record.record_digest,
        target_count=record.preparation_target_count,
        target_set_digest=record.preparation_target_set_digest,
        preparation_scope_digest=record.preparation_scope_digest,
        wipe_required=record.wipe_required,
        wipe_target_count=record.wipe_target_count,
        wipe_scope_digest=record.wipe_scope_digest,
        approval_method=record.approval_method,
        general_proof_digest=record.general_proof_digest,
        wipe_proof_state=record.wipe_consent_state,
        wipe_proof_digest=record.wipe_proof_digest,
        authorization_state=record.authorization_state,
        authorization_consumption_state=record.authorization_consumption_state,
        execution_state=record.execution_state,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
    )


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    expected = (
        f"{operation_id}"
        f"{DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    folded = expected.casefold()
    for entry in paths.operations.iterdir():
        if entry.name.casefold() == folded and entry.name != expected:
            raise StateConflictError(
                "Manager backend storage preparation authorization path is ambiguous"
            )


def _record_digest(
    record: DeployManagerBackendStoragePrepareAuthorization,
) -> str:
    return _record_digest_values(record.to_object())


def _record_digest_values(values: Mapping[str, object]) -> str:
    value = {
        name: (
            item.value
            if isinstance(item, Enum)
            else str(item)
            if isinstance(item, uuid.UUID)
            else item
        )
        for name, item in values.items()
    }
    value["record_digest"] = ""
    return _digest_object(value)


def _dataclass_object(value: Any) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, item in asdict(value).items():
        if isinstance(item, Enum):
            result[name] = item.value
        elif isinstance(item, uuid.UUID):
            result[name] = str(item)
        else:
            result[name] = item
    return result


def _integer(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise StatePersistenceError(f"{name} must be an integer")
    return value


def _boolean(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{name} must be a boolean")
    return value


def _optional_string(value: object, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise StatePersistenceError(f"{name} must be a non-empty string or null")
    return value
