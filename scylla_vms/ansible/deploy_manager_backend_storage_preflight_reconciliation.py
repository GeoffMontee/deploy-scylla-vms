"""Immutable reconciliation of Manager backend storage preflight evidence."""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import Enum, StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.deploy_manager_backend_storage_preflight_execution import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION,
    DeployManagerBackendStoragePreflightArtifactState,
    DeployManagerBackendStoragePreflightEvidenceStore,
    DeployManagerBackendStoragePreflightExecutionState,
    DeployManagerBackendStoragePreflightExecutionStore,
    StoredDeployManagerBackendStoragePreflightEvidence,
    StoredDeployManagerBackendStoragePreflightExecution,
    _load_execution_context,
    _require_canonical_paths,
    _validate_execution_prefix,
)
from scylla_vms.ansible.deploy_manager_backend_storage_preflight_execution import (
    _refuse_ambiguous_artifacts as _refuse_ambiguous_execution_artifacts,
)
from scylla_vms.ansible.deploy_manager_backend_storage_preflight_plan import (
    _load_planning_context,
)
from scylla_vms.ansible.deploy_plan import _digest_object, _require_operation_id
from scylla_vms.ansible.manager_backend_storage_preflight import (
    ManagerBackendStoragePreflightDisposition,
)
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.journal import JOURNAL_SCHEMA_VERSION, JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.persistence import (
    AtomicJsonFile,
    digest_bytes,
    format_timestamp,
    parse_timestamp,
    parse_uuid,
    require_exact_keys,
    require_string,
    serialize_json,
    validate_digest,
)
from scylla_vms.state import (
    StatePaths,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)

ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_PREPARATION_SCOPE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-"
    "preparation-scope/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-"
    "reconciliation/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-"
    "reconciliation-report/v1"
)

DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-storage-preflight-reconciliation.json"
)

_OPERATION = "deploy"
_STAGE = "manager-backend-storage-preflight-reconciliation"
_NEXT_BOUNDARY = "manager-backend-storage-prepare"
_AUTHORIZATION_BLOCKER = "manager-backend-storage-prepare-authorization-unavailable"
_PUBLIC_WORKFLOW_BLOCKER = "public-deploy-workflow-unavailable"
_PREFLIGHT_BLOCKER = "manager-backend-storage-preflight-blocked"
_WIPE_BLOCKER = "manager-backend-storage-wipe-review-required"
_SOURCE_AVAILABLE = "source-available"
_UNAVAILABLE = "unavailable"
_NOT_STARTED = "not-started"
_NOT_PERFORMED = "not-performed"
_PREPARATION_ACTIONS = (
    "create-xfs",
    "mount-scylla-data-root",
    "write-fstab",
    "write-manager-one-node-marker",
)
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")


class DeployManagerBackendStoragePreflightBoundaryStatus(StrEnum):
    SUCCEEDED = "succeeded"


class DeployManagerBackendStoragePreflightNextStatus(StrEnum):
    NOT_REQUIRED = "not-required"
    EVIDENCE_READY_AUTHORIZATION_REQUIRED = "evidence-ready-authorization-required"
    BLOCKED = "blocked"


class DeployManagerBackendStoragePreparationScopeState(StrEnum):
    DERIVED = "derived"
    NOT_REQUIRED = "not-required"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStoragePreparationScope:
    stable_id: str
    disposition: ManagerBackendStoragePreflightDisposition
    device_set_digest: str
    preparation_intent_digest: str
    scope_digest: str
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_PREPARATION_SCOPE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_PREPARATION_SCOPE_SCHEMA_VERSION
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.disposition
            is not ManagerBackendStoragePreflightDisposition.PREPARE_REQUIRED
            or self.scope_digest != _scope_digest(self)
        ):
            raise StatePersistenceError(
                "Manager backend storage preparation scope conflicts"
            )
        for value in (
            self.device_set_digest,
            self.preparation_intent_digest,
            self.scope_digest,
        ):
            validate_digest(value, "Manager backend storage preparation scope digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendStoragePreparationScope:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend storage preparation scope",
        )
        try:
            return cls(
                stable_id=require_string(value, "stable_id"),
                disposition=ManagerBackendStoragePreflightDisposition(
                    require_string(value, "disposition")
                ),
                device_set_digest=require_string(value, "device_set_digest"),
                preparation_intent_digest=require_string(
                    value, "preparation_intent_digest"
                ),
                scope_digest=require_string(value, "scope_digest"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend storage preparation scope enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStoragePreflightReconciliation:
    generation: int
    created_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    stage: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    preflight_context_artifact_digest: str
    preflight_context_record_digest: str
    preflight_plan_artifact_digest: str
    preflight_plan_digest: str
    discovery_reconciliation_artifact_digest: str
    discovery_reconciliation_record_digest: str
    execution_artifact_digest: str
    execution_binding_digest: str
    evidence_artifact_digest: str
    evidence_digest: str
    result_digest: str
    full_chain_digest: str
    source_digest: str
    playbook_source_digest: str
    toolchain_evidence_digest: str
    target_stable_id: str
    target_set_digest: str
    preflight_boundary_status: DeployManagerBackendStoragePreflightBoundaryStatus
    disposition: ManagerBackendStoragePreflightDisposition
    backend: str
    layout: str
    capacity_policy_state: str
    capacity_sufficiency_state: str
    desired_policy_digest: str
    manifest_digest: str
    discovery_digest: str
    device_set_digest: str
    status_digest: str
    preparation_intent_digest: str
    action_count: int
    action_digest: str
    source_blocker_count: int
    source_blocker_digest: str
    wipe_required: bool
    owned_noop_state: str
    preparation_scope_state: DeployManagerBackendStoragePreparationScopeState
    preparation_scopes: tuple[DeployManagerBackendStoragePreparationScope, ...]
    preparation_target_count: int
    preparation_target_set_digest: str
    preparation_scope_digest: str
    wipe_target_ids: tuple[str, ...]
    wipe_target_count: int
    wipe_target_set_digest: str
    wipe_scope_digest: str
    next_boundary: str
    next_status: DeployManagerBackendStoragePreflightNextStatus
    blockers: tuple[str, ...]
    blocker_count: int
    blocker_digest: str
    storage_preparation_source_state: str
    storage_preparation_authorization_state: str
    storage_preparation_execution_state: str
    storage_postcheck_state: str
    mutation_state: str
    journal_transition_state: str
    finalization_state: str
    public_workflow_state: str
    record_digest: str
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        owned = self.disposition is ManagerBackendStoragePreflightDisposition.OWNED_NOOP
        prepare = (
            self.disposition
            is ManagerBackendStoragePreflightDisposition.PREPARE_REQUIRED
        )
        blocked = self.disposition is ManagerBackendStoragePreflightDisposition.BLOCKED
        expected_scope_state = (
            DeployManagerBackendStoragePreparationScopeState.DERIVED
            if prepare
            else DeployManagerBackendStoragePreparationScopeState.NOT_REQUIRED
            if owned
            else DeployManagerBackendStoragePreparationScopeState.BLOCKED
        )
        expected_next = (
            DeployManagerBackendStoragePreflightNextStatus.NOT_REQUIRED
            if owned
            else DeployManagerBackendStoragePreflightNextStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            if prepare
            else DeployManagerBackendStoragePreflightNextStatus.BLOCKED
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.preflight_boundary_status
            is not DeployManagerBackendStoragePreflightBoundaryStatus.SUCCEEDED
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
            or self.target_set_digest != _digest_object([self.target_stable_id])
            or self.backend != "block-volume"
            or self.layout != "single"
            or self.capacity_policy_state != "operator-selected-allocation-conformance"
            or self.capacity_sufficiency_state != "not-proven"
            or self.action_count != (len(_PREPARATION_ACTIONS) if prepare else 0)
            or self.action_digest
            != _digest_object(list(_PREPARATION_ACTIONS) if prepare else [])
            or self.source_blocker_count < 0
            or self.owned_noop_state != ("not-required" if owned else "not-applicable")
            or self.preparation_scope_state is not expected_scope_state
            or len(self.preparation_scopes) != (1 if prepare else 0)
            or any(
                item.stable_id != self.target_stable_id
                for item in self.preparation_scopes
            )
            or self.preparation_target_count != len(self.preparation_scopes)
            or self.preparation_target_set_digest
            != _digest_object([item.stable_id for item in self.preparation_scopes])
            or self.preparation_scope_digest
            != _digest_object([item.to_object() for item in self.preparation_scopes])
            or self.wipe_target_ids
            != ((self.target_stable_id,) if self.wipe_required else ())
            or self.wipe_target_count != len(self.wipe_target_ids)
            or self.wipe_target_set_digest != _digest_object(list(self.wipe_target_ids))
            or self.wipe_scope_digest
            != _digest_object(
                [
                    {
                        "device_set_digest": self.device_set_digest,
                        "disposition": self.disposition.value,
                        "preparation_intent_digest": self.preparation_intent_digest,
                        "stable_id": item,
                    }
                    for item in self.wipe_target_ids
                ]
            )
            or self.next_boundary != _NEXT_BOUNDARY
            or self.next_status is not expected_next
            or self.blockers != tuple(sorted(set(self.blockers)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blockers)
            or self.blocker_count != len(self.blockers)
            or self.blocker_digest != _digest_object(list(self.blockers))
            or (owned and self.blockers)
            or (
                prepare
                and not {
                    _AUTHORIZATION_BLOCKER,
                    _PUBLIC_WORKFLOW_BLOCKER,
                }.issubset(self.blockers)
            )
            or (blocked and _PREFLIGHT_BLOCKER not in self.blockers)
            or (self.wipe_required and _WIPE_BLOCKER not in self.blockers)
            or self.storage_preparation_source_state != _SOURCE_AVAILABLE
            or self.storage_preparation_authorization_state != _UNAVAILABLE
            or self.storage_preparation_execution_state != _NOT_STARTED
            or self.storage_postcheck_state != _NOT_PERFORMED
            or self.mutation_state != _NOT_PERFORMED
            or self.journal_transition_state != _NOT_PERFORMED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
            or self.record_digest != _record_digest(self, "record_digest")
        ):
            raise StatePersistenceError(
                "Manager backend storage preflight reconciliation conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for value in (
            self.journal_generation,
            self.action_count,
            self.source_blocker_count,
            self.preparation_target_count,
            self.wipe_target_count,
            self.blocker_count,
        ):
            _nonnegative_integer(
                value, "Manager backend storage preflight reconciliation count"
            )
        for digest_value in _digest_fields(self):
            validate_digest(
                digest_value,
                "Manager backend storage preflight reconciliation digest",
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendStoragePreflightReconciliation:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend storage preflight reconciliation",
        )
        integers = {
            "generation",
            "journal_generation",
            "action_count",
            "source_blocker_count",
            "preparation_target_count",
            "wipe_target_count",
            "blocker_count",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in integers:
                    parsed[name] = _integer(item, name)
                elif name in {"cluster_uuid", "operation_id"}:
                    parsed[name] = parse_uuid(require_string(value, name), name)
                elif name == "journal_status":
                    parsed[name] = JournalStatus(require_string(value, name))
                elif name == "journal_phase":
                    parsed[name] = OperationPhase(require_string(value, name))
                elif name == "preflight_boundary_status":
                    parsed[name] = DeployManagerBackendStoragePreflightBoundaryStatus(
                        require_string(value, name)
                    )
                elif name == "disposition":
                    parsed[name] = ManagerBackendStoragePreflightDisposition(
                        require_string(value, name)
                    )
                elif name == "preparation_scope_state":
                    parsed[name] = DeployManagerBackendStoragePreparationScopeState(
                        require_string(value, name)
                    )
                elif name == "next_status":
                    parsed[name] = DeployManagerBackendStoragePreflightNextStatus(
                        require_string(value, name)
                    )
                elif name in {"wipe_required"}:
                    parsed[name] = _boolean(item, name)
                elif name in {"wipe_target_ids", "blockers"}:
                    parsed[name] = _string_tuple(item, name)
                elif name == "preparation_scopes":
                    parsed[name] = tuple(
                        DeployManagerBackendStoragePreparationScope.from_object(
                            _mapping(scope, "preparation scope")
                        )
                        for scope in _array(item, name)
                    )
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend storage preflight reconciliation enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendStoragePreflightReconciliation:
    record: DeployManagerBackendStoragePreflightReconciliation
    artifact_digest: str


class DeployManagerBackendStoragePreflightReconciliationStore:
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
        self._path = deploy_manager_backend_storage_preflight_reconciliation_path(
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
    ) -> StoredDeployManagerBackendStoragePreflightReconciliation:
        value, digest = self._file.read()
        record = DeployManagerBackendStoragePreflightReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "Manager backend storage preflight reconciliation identity conflicts"
            )
        return StoredDeployManagerBackendStoragePreflightReconciliation(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendStoragePreflightReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendStoragePreflightReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerBackendStoragePreflightReconciliation,
        DeployManagerBackendStoragePreflightArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Manager backend storage preflight reconciliation operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "Manager backend storage preflight reconciliation is immutable"
                )
            return (
                current,
                DeployManagerBackendStoragePreflightArtifactState.REUSED,
            )
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerBackendStoragePreflightReconciliation(record, digest),
            DeployManagerBackendStoragePreflightArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStoragePreflightReconciliationReport:
    operation_id: uuid.UUID
    artifact_state: DeployManagerBackendStoragePreflightArtifactState
    artifact_digest: str
    record_digest: str
    target_stable_id: str
    target_set_digest: str
    preflight_boundary_status: DeployManagerBackendStoragePreflightBoundaryStatus
    disposition: ManagerBackendStoragePreflightDisposition
    preparation_scope_state: DeployManagerBackendStoragePreparationScopeState
    preparation_scopes: tuple[DeployManagerBackendStoragePreparationScope, ...]
    preparation_target_set_digest: str
    preparation_scope_digest: str
    wipe_required: bool
    wipe_target_count: int
    wipe_target_set_digest: str
    wipe_scope_digest: str
    next_status: DeployManagerBackendStoragePreflightNextStatus
    capacity_sufficiency_state: str
    blocker_count: int
    blocker_digest: str
    storage_preparation_authorization_state: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_REPORT_SCHEMA_VERSION
            or self.preflight_boundary_status
            is not DeployManagerBackendStoragePreflightBoundaryStatus.SUCCEEDED
            or self.capacity_sufficiency_state != "not-proven"
            or self.storage_preparation_authorization_state != _UNAVAILABLE
            or self.blocker_count < 0
            or self.wipe_target_count not in {0, 1}
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError(
                "Manager backend storage preflight reconciliation report conflicts"
            )
        for value in (
            self.artifact_digest,
            self.record_digest,
            self.target_set_digest,
            self.preparation_target_set_digest,
            self.preparation_scope_digest,
            self.wipe_target_set_digest,
            self.wipe_scope_digest,
            self.blocker_digest,
        ):
            validate_digest(
                value,
                "Manager backend storage preflight reconciliation report digest",
            )

    def to_object(self) -> dict[str, object]:
        return {
            "artifact": {
                "digest": self.artifact_digest,
                "record_digest": self.record_digest,
                "state": self.artifact_state.value,
            },
            "blockers": {
                "count": self.blocker_count,
                "digest": self.blocker_digest,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "next": {
                "capacity_sufficiency_state": self.capacity_sufficiency_state,
                "status": self.next_status.value,
                "storage_preparation_authorization_state": (
                    self.storage_preparation_authorization_state
                ),
            },
            "operation_id": str(self.operation_id),
            "preflight": {
                "boundary_status": self.preflight_boundary_status.value,
                "disposition": self.disposition.value,
            },
            "preparation": {
                "scope_digest": self.preparation_scope_digest,
                "scope_state": self.preparation_scope_state.value,
                "scopes": [item.to_object() for item in self.preparation_scopes],
                "target_set_digest": self.preparation_target_set_digest,
            },
            "schema_version": self.schema_version,
            "scope": {
                "target_set_digest": self.target_set_digest,
                "target_stable_id": self.target_stable_id,
            },
            "wipe": {
                "required": self.wipe_required,
                "scope_digest": self.wipe_scope_digest,
                "target_count": self.wipe_target_count,
                "target_set_digest": self.wipe_target_set_digest,
            },
        }


@dataclass(frozen=True, slots=True)
class _ReconciliationContext:
    execution: StoredDeployManagerBackendStoragePreflightExecution
    evidence: StoredDeployManagerBackendStoragePreflightEvidence


def reconcile_deploy_manager_backend_storage_preflight(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployManagerBackendStoragePreflightReconciliationReport:
    """Persist exact preflight success and derive only immediate storage scope."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _refuse_ambiguous_execution_artifacts(paths, operation_id)
    _refuse_ambiguous_artifacts(paths, operation_id)
    context = _load_reconciliation_context(paths, operation_id, lock=lock)
    store = DeployManagerBackendStoragePreflightReconciliationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    existing = (
        store.read_locked(
            lock,
            expected_cluster_uuid=context.execution.record.binding.cluster_uuid,
            expected_cluster_name=context.execution.record.binding.cluster_name,
        )
        if store.path.exists()
        else None
    )
    record = _build_record(
        context, created_at=None if existing is None else existing.record.created_at
    )
    stored, state = store.write_locked(record, lock=lock)
    return _build_report(stored, state=state)


def deploy_manager_backend_storage_preflight_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}"
        f"{DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "Manager backend storage preflight reconciliation path is not canonical"
        )
    return path


def deploy_manager_backend_storage_preflight_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(
        DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_FILENAME_SUFFIX
    ):
        return None
    value = name[
        : -len(DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_FILENAME_SUFFIX)
    ]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _load_reconciliation_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
) -> _ReconciliationContext:
    planning = _load_planning_context(paths, operation_id, lock=lock)
    metadata = planning.current.metadata
    execution_store = DeployManagerBackendStoragePreflightExecutionStore(
        paths, operation_id
    )
    evidence_store = DeployManagerBackendStoragePreflightEvidenceStore(
        paths, operation_id
    )
    for path, label in (
        (execution_store.path, "execution"),
        (evidence_store.path, "semantic evidence"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                "Manager backend storage preflight reconciliation requires "
                f"complete {label}"
            )
    execution = execution_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    binding = execution.record.binding
    current = _load_execution_context(
        paths,
        operation_id,
        lock=lock,
        builder=None,
        toolchain_version=binding.toolchain_version,
        executable_identity_digest=binding.executable_identity_digest,
        toolchain_evidence_digest=binding.toolchain_evidence_digest,
    )
    evidence = evidence_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    _validate_execution_prefix(current, execution, evidence)
    if (
        execution.record.state
        is not DeployManagerBackendStoragePreflightExecutionState.SUCCEEDED
        or not execution.record.completed
        or execution.record.generation != 2
        or execution.record.manual_recovery_required
        or execution.record.automatic_retry_allowed
    ):
        raise StateConflictError(
            "Manager backend storage preflight reconciliation requires exact "
            "terminal success"
        )
    return _ReconciliationContext(execution, evidence)


def _preparation_scopes(
    evidence: StoredDeployManagerBackendStoragePreflightEvidence,
) -> tuple[DeployManagerBackendStoragePreparationScope, ...]:
    record = evidence.record
    if (
        record.disposition
        is not ManagerBackendStoragePreflightDisposition.PREPARE_REQUIRED
    ):
        return ()
    values: dict[str, object] = {
        "stable_id": record.stable_id,
        "disposition": record.disposition,
        "device_set_digest": record.device_set_digest,
        "preparation_intent_digest": record.preparation_intent_digest,
        "scope_digest": "",
    }
    values["scope_digest"] = _scope_digest_from_values(values)
    return (
        DeployManagerBackendStoragePreparationScope(**values),  # type: ignore[arg-type]
    )


def _build_record(
    context: _ReconciliationContext, *, created_at: str | None
) -> DeployManagerBackendStoragePreflightReconciliation:
    execution = context.execution
    evidence = context.evidence
    binding = execution.record.binding
    result = evidence.record
    scopes = _preparation_scopes(evidence)
    wipe_target_ids = (result.stable_id,) if result.wipe_required else ()
    if result.disposition is ManagerBackendStoragePreflightDisposition.OWNED_NOOP:
        blockers: tuple[str, ...] = ()
    elif (
        result.disposition is ManagerBackendStoragePreflightDisposition.PREPARE_REQUIRED
    ):
        blockers = tuple(sorted({_AUTHORIZATION_BLOCKER, _PUBLIC_WORKFLOW_BLOCKER}))
    else:
        blockers = tuple(
            sorted(
                {
                    _PREFLIGHT_BLOCKER,
                    *({_WIPE_BLOCKER} if result.wipe_required else set()),
                }
            )
        )
    wipe_projection = [
        {
            "device_set_digest": result.device_set_digest,
            "disposition": result.disposition.value,
            "preparation_intent_digest": result.preparation_intent_digest,
            "stable_id": item,
        }
        for item in wipe_target_ids
    ]
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at or format_timestamp(datetime.now(UTC)),
        "cluster_uuid": binding.cluster_uuid,
        "cluster_name": binding.cluster_name,
        "operation_id": binding.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "request_digest": binding.request_digest,
        "journal_generation": binding.journal_generation,
        "journal_digest": binding.journal_digest,
        "journal_status": binding.journal_status,
        "journal_phase": binding.journal_phase,
        "preflight_context_artifact_digest": (
            binding.preflight_context_artifact_digest
        ),
        "preflight_context_record_digest": binding.preflight_context_record_digest,
        "preflight_plan_artifact_digest": binding.preflight_plan_artifact_digest,
        "preflight_plan_digest": binding.preflight_plan_digest,
        "discovery_reconciliation_artifact_digest": (
            binding.discovery_reconciliation_artifact_digest
        ),
        "discovery_reconciliation_record_digest": (
            binding.discovery_reconciliation_record_digest
        ),
        "execution_artifact_digest": execution.artifact_digest,
        "execution_binding_digest": binding.binding_digest,
        "evidence_artifact_digest": evidence.artifact_digest,
        "evidence_digest": result.evidence_digest,
        "result_digest": result.result_digest,
        "full_chain_digest": binding.full_chain_digest,
        "source_digest": binding.source_digest,
        "playbook_source_digest": binding.playbook_source_digest,
        "toolchain_evidence_digest": binding.toolchain_evidence_digest,
        "target_stable_id": result.stable_id,
        "target_set_digest": binding.target_set_digest,
        "preflight_boundary_status": (
            DeployManagerBackendStoragePreflightBoundaryStatus.SUCCEEDED
        ),
        "disposition": result.disposition,
        "backend": result.backend,
        "layout": result.layout,
        "capacity_policy_state": result.capacity_policy_state,
        "capacity_sufficiency_state": result.capacity_sufficiency_state,
        "desired_policy_digest": result.desired_policy_digest,
        "manifest_digest": result.manifest_digest,
        "discovery_digest": result.discovery_digest,
        "device_set_digest": result.device_set_digest,
        "status_digest": result.status_digest,
        "preparation_intent_digest": result.preparation_intent_digest,
        "action_count": len(result.actions),
        "action_digest": _digest_object(list(result.actions)),
        "source_blocker_count": result.blocker_count,
        "source_blocker_digest": result.blocker_digest,
        "wipe_required": result.wipe_required,
        "owned_noop_state": (
            "not-required"
            if result.disposition
            is ManagerBackendStoragePreflightDisposition.OWNED_NOOP
            else "not-applicable"
        ),
        "preparation_scope_state": (
            DeployManagerBackendStoragePreparationScopeState.DERIVED
            if scopes
            else DeployManagerBackendStoragePreparationScopeState.NOT_REQUIRED
            if result.disposition
            is ManagerBackendStoragePreflightDisposition.OWNED_NOOP
            else DeployManagerBackendStoragePreparationScopeState.BLOCKED
        ),
        "preparation_scopes": scopes,
        "preparation_target_count": len(scopes),
        "preparation_target_set_digest": _digest_object(
            [item.stable_id for item in scopes]
        ),
        "preparation_scope_digest": _digest_object(
            [item.to_object() for item in scopes]
        ),
        "wipe_target_ids": wipe_target_ids,
        "wipe_target_count": len(wipe_target_ids),
        "wipe_target_set_digest": _digest_object(list(wipe_target_ids)),
        "wipe_scope_digest": _digest_object(wipe_projection),
        "next_boundary": _NEXT_BOUNDARY,
        "next_status": (
            DeployManagerBackendStoragePreflightNextStatus.NOT_REQUIRED
            if result.disposition
            is ManagerBackendStoragePreflightDisposition.OWNED_NOOP
            else DeployManagerBackendStoragePreflightNextStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            if result.disposition
            is ManagerBackendStoragePreflightDisposition.PREPARE_REQUIRED
            else DeployManagerBackendStoragePreflightNextStatus.BLOCKED
        ),
        "blockers": blockers,
        "blocker_count": len(blockers),
        "blocker_digest": _digest_object(list(blockers)),
        "storage_preparation_source_state": _SOURCE_AVAILABLE,
        "storage_preparation_authorization_state": _UNAVAILABLE,
        "storage_preparation_execution_state": _NOT_STARTED,
        "storage_postcheck_state": _NOT_PERFORMED,
        "mutation_state": _NOT_PERFORMED,
        "journal_transition_state": _NOT_PERFORMED,
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(values, "record_digest")
    return DeployManagerBackendStoragePreflightReconciliation(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployManagerBackendStoragePreflightReconciliation,
    *,
    state: DeployManagerBackendStoragePreflightArtifactState,
) -> DeployManagerBackendStoragePreflightReconciliationReport:
    record = stored.record
    return DeployManagerBackendStoragePreflightReconciliationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        artifact_digest=stored.artifact_digest,
        record_digest=record.record_digest,
        target_stable_id=record.target_stable_id,
        target_set_digest=record.target_set_digest,
        preflight_boundary_status=record.preflight_boundary_status,
        disposition=record.disposition,
        preparation_scope_state=record.preparation_scope_state,
        preparation_scopes=record.preparation_scopes,
        preparation_target_set_digest=record.preparation_target_set_digest,
        preparation_scope_digest=record.preparation_scope_digest,
        wipe_required=record.wipe_required,
        wipe_target_count=record.wipe_target_count,
        wipe_target_set_digest=record.wipe_target_set_digest,
        wipe_scope_digest=record.wipe_scope_digest,
        next_status=record.next_status,
        capacity_sufficiency_state=record.capacity_sufficiency_state,
        blocker_count=record.blocker_count,
        blocker_digest=record.blocker_digest,
        storage_preparation_authorization_state=(
            record.storage_preparation_authorization_state
        ),
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
    )


_StoredRecord = (
    DeployManagerBackendStoragePreparationScope
    | DeployManagerBackendStoragePreflightReconciliation
)


def _record_digest(record: _StoredRecord, digest_field: str) -> str:
    return _record_digest_from_values(
        cast(Mapping[str, object], asdict(record)), digest_field
    )


def _record_digest_from_values(values: Mapping[str, object], digest_field: str) -> str:
    copied = dict(values)
    for name in tuple(copied):
        if name == "schema_version" or name.endswith("_schema_version"):
            copied.pop(name)
    copied[digest_field] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(cast(Mapping[str, object], _jsonable(copied))))


def _scope_digest(scope: DeployManagerBackendStoragePreparationScope) -> str:
    return _scope_digest_from_values(scope.to_object())


def _scope_digest_from_values(values: Mapping[str, object]) -> str:
    copied = dict(values)
    copied.pop("schema_version", None)
    copied["scope_digest"] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(cast(Mapping[str, object], _jsonable(copied))))


def _dataclass_object(value: _StoredRecord) -> dict[str, object]:
    return cast(dict[str, object], _jsonable(asdict(value)))


def _jsonable(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, DeployManagerBackendStoragePreparationScope):
        return value.to_object()
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest_fields(
    value: DeployManagerBackendStoragePreflightReconciliation,
) -> tuple[str, ...]:
    return tuple(
        cast(str, field_value)
        for field_name, field_value in asdict(value).items()
        if field_name.endswith("_digest") and field_value is not None
    )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Manager backend storage preflight reconciliation requires "
            "an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list Manager backend storage preflight "
            "reconciliation artifacts"
        ) from error
    canonical = str(operation_id)
    suffix = DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_FILENAME_SUFFIX
    for entry in entries:
        if not entry.name.endswith(suffix):
            continue
        prefix = entry.name[: -len(suffix)]
        try:
            parsed = uuid.UUID(prefix)
        except ValueError:
            parsed = None
        if prefix != canonical and (
            parsed is None or parsed == operation_id or canonical in prefix
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "Manager backend storage preflight reconciliation artifacts "
                "are ambiguous"
            )


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise StatePersistenceError(f"{label} must be an array")
    return value


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise StatePersistenceError(f"{label} must be an array of strings")
    return tuple(cast(list[str], value))


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _nonnegative_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StatePersistenceError(f"{label} must be nonnegative")


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be a boolean")
    return value


__all__ = [
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_PREPARATION_SCOPE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION",
    "DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_FILENAME_SUFFIX",
    "DeployManagerBackendStoragePreflightBoundaryStatus",
    "DeployManagerBackendStoragePreflightNextStatus",
    "DeployManagerBackendStoragePreflightReconciliation",
    "DeployManagerBackendStoragePreflightReconciliationReport",
    "DeployManagerBackendStoragePreflightReconciliationStore",
    "DeployManagerBackendStoragePreparationScope",
    "DeployManagerBackendStoragePreparationScopeState",
    "StoredDeployManagerBackendStoragePreflightReconciliation",
    "deploy_manager_backend_storage_preflight_reconciliation_id_from_filename",
    "deploy_manager_backend_storage_preflight_reconciliation_path",
    "reconcile_deploy_manager_backend_storage_preflight",
]
