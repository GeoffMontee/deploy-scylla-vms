"""Immutable reconciliation of Manager backend storage discovery."""

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

from scylla_vms.ansible.deploy_manager_backend_storage_allocation_plan import (
    _load_storage_planning_context,
)
from scylla_vms.ansible.deploy_manager_backend_storage_discovery_execution import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION,
    DeployManagerBackendStorageDiscoveryArtifactState,
    DeployManagerBackendStorageDiscoveryEvidenceStore,
    DeployManagerBackendStorageDiscoveryExecutionState,
    DeployManagerBackendStorageDiscoveryExecutionStore,
    StoredDeployManagerBackendStorageDiscoveryEvidence,
    StoredDeployManagerBackendStorageDiscoveryExecution,
    _load_execution_context,
    _require_canonical_paths,
    _validate_execution_prefix,
)
from scylla_vms.ansible.deploy_manager_backend_storage_discovery_execution import (
    _refuse_ambiguous_artifacts as _refuse_ambiguous_execution_artifacts,
)
from scylla_vms.ansible.deploy_plan import _digest_object, _require_operation_id
from scylla_vms.ansible.manager_backend_storage_discover import (
    ManagerBackendStorageDiscoveryStatus,
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

ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-discovery-"
    "reconciliation/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-discovery-"
    "reconciliation-report/v1"
)

DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-storage-discovery-reconciliation.json"
)

_OPERATION = "deploy"
_STAGE = "manager-backend-storage-discovery-reconciliation"
_NEXT_BOUNDARY = "capacity-and-storage-preflight-planning"
_NEXT_IMPLEMENTATION_CONTRACT = (
    "manager-backend-capacity-storage-preflight-plan-contract"
)
_CAPACITY_BLOCKER = "manager-backend-capacity-policy-unknown"
_PREFLIGHT_SOURCE_BLOCKER = "manager-backend-storage-preflight-source-unavailable"
_PREPARATION_SOURCE_BLOCKER = "manager-backend-storage-preparation-source-unavailable"
_UNAVAILABLE = "unavailable"
_NOT_STARTED = "not-started"
_NOT_PERFORMED = "not-performed"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")


class DeployManagerBackendStorageDiscoveryBoundaryStatus(StrEnum):
    SUCCEEDED = "succeeded"
    BLOCKED = "blocked"


class DeployManagerBackendStorageDiscoveryNextStatus(StrEnum):
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStorageDiscoveryReconciliation:
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
    allocation_context_artifact_digest: str
    allocation_context_record_digest: str
    allocation_plan_artifact_digest: str
    allocation_plan_digest: str
    package_reconciliation_artifact_digest: str
    package_reconciliation_record_digest: str
    execution_artifact_digest: str
    execution_binding_digest: str
    evidence_artifact_digest: str
    evidence_digest: str
    result_digest: str
    target_stable_id: str
    target_set_digest: str
    allocation_decision_digest: str
    provider_allocation_identity_digest: str
    guest_identity_set_digest: str
    manifest_digest: str
    semantic_status: ManagerBackendStorageDiscoveryStatus
    discovery_boundary_status: DeployManagerBackendStorageDiscoveryBoundaryStatus
    device_count: int
    total_size_gib: int
    device_set_digest: str
    topology_digest: str
    provenance_digest: str
    capacity_policy_state: str
    capacity_adequacy_state: str
    storage_preflight_source_state: str
    storage_preflight_execution_state: str
    storage_preparation_source_state: str
    storage_preparation_authorization_state: str
    storage_preparation_execution_state: str
    wipe_safety_state: str
    owned_noop_state: str
    next_boundary: str
    next_status: DeployManagerBackendStorageDiscoveryNextStatus
    blockers: tuple[str, ...]
    blocker_count: int
    blocker_digest: str
    mutation_state: str
    journal_transition_state: str
    finalization_state: str
    public_workflow_state: str
    next_implementation_contract: str
    record_digest: str
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        discovered = (
            self.semantic_status is ManagerBackendStorageDiscoveryStatus.DISCOVERED
        )
        expected_boundary = (
            DeployManagerBackendStorageDiscoveryBoundaryStatus.SUCCEEDED
            if discovered
            else DeployManagerBackendStorageDiscoveryBoundaryStatus.BLOCKED
        )
        required_blockers = {
            _CAPACITY_BLOCKER,
            _PREFLIGHT_SOURCE_BLOCKER,
            _PREPARATION_SOURCE_BLOCKER,
        }
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
            or self.target_set_digest != _digest_object([self.target_stable_id])
            or self.semantic_status is ManagerBackendStorageDiscoveryStatus.FAILED
            or self.discovery_boundary_status is not expected_boundary
            or not 0 <= self.device_count <= 16
            or (discovered and self.device_count != 1)
            or self.total_size_gib < 0
            or self.capacity_policy_state != "unknown"
            or self.capacity_adequacy_state != "unknown"
            or self.storage_preflight_source_state != _UNAVAILABLE
            or self.storage_preflight_execution_state != _NOT_STARTED
            or self.storage_preparation_source_state != _UNAVAILABLE
            or self.storage_preparation_authorization_state != _UNAVAILABLE
            or self.storage_preparation_execution_state != _NOT_STARTED
            or self.wipe_safety_state != "not-evaluated"
            or self.owned_noop_state != "not-inferred"
            or self.next_boundary != _NEXT_BOUNDARY
            or self.next_status
            is not DeployManagerBackendStorageDiscoveryNextStatus.BLOCKED
            or self.blockers != tuple(sorted(set(self.blockers)))
            or not required_blockers.issubset(self.blockers)
            or any(_BLOCKER.fullmatch(item) is None for item in self.blockers)
            or self.blocker_count != len(self.blockers)
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.mutation_state != _NOT_PERFORMED
            or self.journal_transition_state != _NOT_PERFORMED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
            or self.next_implementation_contract != _NEXT_IMPLEMENTATION_CONTRACT
            or self.record_digest != _record_digest(self, "record_digest")
        ):
            raise StatePersistenceError(
                "Manager backend storage discovery reconciliation conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for value in (self.journal_generation, self.device_count, self.blocker_count):
            _nonnegative_integer(
                value, "Manager backend storage discovery reconciliation count"
            )
        for digest in _digest_fields(self):
            validate_digest(
                digest, "Manager backend storage discovery reconciliation digest"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls,
        value: Mapping[str, object],
    ) -> DeployManagerBackendStorageDiscoveryReconciliation:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend storage discovery reconciliation",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "device_count",
            "total_size_gib",
            "blocker_count",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in integer_fields:
                    parsed[name] = _integer(item, name)
                elif name in {"cluster_uuid", "operation_id"}:
                    parsed[name] = parse_uuid(require_string(value, name), name)
                elif name == "journal_status":
                    parsed[name] = JournalStatus(require_string(value, name))
                elif name == "journal_phase":
                    parsed[name] = OperationPhase(require_string(value, name))
                elif name == "semantic_status":
                    parsed[name] = ManagerBackendStorageDiscoveryStatus(
                        require_string(value, name)
                    )
                elif name == "discovery_boundary_status":
                    parsed[name] = DeployManagerBackendStorageDiscoveryBoundaryStatus(
                        require_string(value, name)
                    )
                elif name == "next_status":
                    parsed[name] = DeployManagerBackendStorageDiscoveryNextStatus(
                        require_string(value, name)
                    )
                elif name == "blockers":
                    parsed[name] = _string_tuple(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend storage discovery reconciliation enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendStorageDiscoveryReconciliation:
    record: DeployManagerBackendStorageDiscoveryReconciliation
    artifact_digest: str


class DeployManagerBackendStorageDiscoveryReconciliationStore:
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
        self._path = deploy_manager_backend_storage_discovery_reconciliation_path(
            paths, operation_id
        )
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendStorageDiscoveryReconciliation:
        value, digest = self._file.read()
        record = DeployManagerBackendStorageDiscoveryReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "Manager backend storage discovery reconciliation identity conflicts"
            )
        return StoredDeployManagerBackendStorageDiscoveryReconciliation(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendStorageDiscoveryReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendStorageDiscoveryReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerBackendStorageDiscoveryReconciliation,
        DeployManagerBackendStorageDiscoveryArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Manager backend storage discovery reconciliation operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "Manager backend storage discovery reconciliation is immutable"
                )
            return current, DeployManagerBackendStorageDiscoveryArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerBackendStorageDiscoveryReconciliation(record, digest),
            DeployManagerBackendStorageDiscoveryArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStorageDiscoveryReconciliationReport:
    operation_id: uuid.UUID
    artifact_state: DeployManagerBackendStorageDiscoveryArtifactState
    artifact_digest: str
    record_digest: str
    target_stable_id: str
    target_set_digest: str
    semantic_status: ManagerBackendStorageDiscoveryStatus
    discovery_boundary_status: DeployManagerBackendStorageDiscoveryBoundaryStatus
    next_boundary: str
    next_status: DeployManagerBackendStorageDiscoveryNextStatus
    capacity_policy_state: str
    capacity_adequacy_state: str
    storage_preflight_source_state: str
    storage_preparation_authorization_state: str
    blocker_count: int
    blocker_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_RECONCILIATION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_RECONCILIATION_REPORT_SCHEMA_VERSION
            or self.next_boundary != _NEXT_BOUNDARY
            or self.next_status
            is not DeployManagerBackendStorageDiscoveryNextStatus.BLOCKED
            or self.capacity_policy_state != "unknown"
            or self.capacity_adequacy_state != "unknown"
            or self.storage_preflight_source_state != _UNAVAILABLE
            or self.storage_preparation_authorization_state != _UNAVAILABLE
            or self.blocker_count < 3
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError(
                "Manager backend storage discovery reconciliation report conflicts"
            )
        for value in (
            self.artifact_digest,
            self.record_digest,
            self.target_set_digest,
            self.blocker_digest,
        ):
            validate_digest(
                value, "Manager backend storage discovery reconciliation report digest"
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
            "discovery": {
                "boundary_status": self.discovery_boundary_status.value,
                "semantic_status": self.semantic_status.value,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "next": {
                "boundary": self.next_boundary,
                "capacity_adequacy_state": self.capacity_adequacy_state,
                "capacity_policy_state": self.capacity_policy_state,
                "status": self.next_status.value,
                "storage_preflight_source_state": self.storage_preflight_source_state,
                "storage_preparation_authorization_state": (
                    self.storage_preparation_authorization_state
                ),
            },
            "operation_id": str(self.operation_id),
            "schema_version": self.schema_version,
            "scope": {
                "target_set_digest": self.target_set_digest,
                "target_stable_id": self.target_stable_id,
            },
        }


@dataclass(frozen=True, slots=True)
class _ReconciliationContext:
    execution: StoredDeployManagerBackendStorageDiscoveryExecution
    evidence: StoredDeployManagerBackendStorageDiscoveryEvidence


def reconcile_deploy_manager_backend_storage_discovery(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployManagerBackendStorageDiscoveryReconciliationReport:
    """Bind discovery evidence and evaluate only the immediate planning gate."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _refuse_ambiguous_execution_artifacts(paths, operation_id)
    _refuse_ambiguous_artifacts(paths, operation_id)
    context = _load_reconciliation_context(paths, operation_id, lock=lock)
    store = DeployManagerBackendStorageDiscoveryReconciliationStore(paths, operation_id)
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


def deploy_manager_backend_storage_discovery_reconciliation_path(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}"
        f"{DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_RECONCILIATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "Manager backend storage discovery reconciliation path is not canonical"
        )
    return path


def deploy_manager_backend_storage_discovery_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(
        DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_RECONCILIATION_FILENAME_SUFFIX
    ):
        return None
    value = name[
        : -len(DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_RECONCILIATION_FILENAME_SUFFIX)
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
    execution_store = DeployManagerBackendStorageDiscoveryExecutionStore(
        paths, operation_id
    )
    evidence_store = DeployManagerBackendStorageDiscoveryEvidenceStore(
        paths, operation_id
    )
    for path, label in (
        (execution_store.path, "execution"),
        (evidence_store.path, "semantic evidence"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                "Manager backend storage discovery reconciliation requires "
                f"complete {label}"
            )
    planning = _load_storage_planning_context(paths, operation_id, lock=lock)
    execution = execution_store.read_locked(
        lock,
        expected_cluster_uuid=planning.metadata.cluster_uuid,
        expected_cluster_name=planning.metadata.cluster_name,
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
        expected_cluster_uuid=binding.cluster_uuid,
        expected_cluster_name=binding.cluster_name,
    )
    _validate_execution_prefix(current, execution, evidence)
    if (
        execution.record.state
        is not DeployManagerBackendStorageDiscoveryExecutionState.SUCCEEDED
        or not execution.record.completed
        or execution.record.generation != 2
        or execution.record.manual_recovery_required
        or execution.record.automatic_retry_allowed
        or evidence.record.status is ManagerBackendStorageDiscoveryStatus.FAILED
    ):
        raise StateConflictError(
            "Manager backend storage discovery reconciliation requires exact "
            "terminal success"
        )
    return _ReconciliationContext(execution, evidence)


def _build_record(
    context: _ReconciliationContext,
    *,
    created_at: str | None,
) -> DeployManagerBackendStorageDiscoveryReconciliation:
    execution = context.execution
    evidence = context.evidence
    binding = execution.record.binding
    result = evidence.record
    discovered = result.status is ManagerBackendStorageDiscoveryStatus.DISCOVERED
    blockers = {
        _CAPACITY_BLOCKER,
        _PREFLIGHT_SOURCE_BLOCKER,
        _PREPARATION_SOURCE_BLOCKER,
        *result.blockers,
    }
    sorted_blockers = tuple(sorted(blockers))
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
        "allocation_context_artifact_digest": (
            binding.allocation_context_artifact_digest
        ),
        "allocation_context_record_digest": (binding.allocation_context_record_digest),
        "allocation_plan_artifact_digest": binding.allocation_plan_artifact_digest,
        "allocation_plan_digest": binding.allocation_plan_digest,
        "package_reconciliation_artifact_digest": (
            binding.package_reconciliation_artifact_digest
        ),
        "package_reconciliation_record_digest": (
            binding.package_reconciliation_record_digest
        ),
        "execution_artifact_digest": execution.artifact_digest,
        "execution_binding_digest": binding.binding_digest,
        "evidence_artifact_digest": evidence.artifact_digest,
        "evidence_digest": result.evidence_digest,
        "result_digest": result.result_digest,
        "target_stable_id": result.stable_id,
        "target_set_digest": binding.target_set_digest,
        "allocation_decision_digest": binding.allocation_decision_digest,
        "provider_allocation_identity_digest": (
            binding.provider_allocation_identity_digest
        ),
        "guest_identity_set_digest": binding.guest_identity_set_digest,
        "manifest_digest": result.manifest_digest,
        "semantic_status": result.status,
        "discovery_boundary_status": (
            DeployManagerBackendStorageDiscoveryBoundaryStatus.SUCCEEDED
            if discovered
            else DeployManagerBackendStorageDiscoveryBoundaryStatus.BLOCKED
        ),
        "device_count": result.device_count,
        "total_size_gib": result.total_size_gib,
        "device_set_digest": result.device_set_digest,
        "topology_digest": result.topology_digest,
        "provenance_digest": result.provenance_digest,
        "capacity_policy_state": "unknown",
        "capacity_adequacy_state": "unknown",
        "storage_preflight_source_state": _UNAVAILABLE,
        "storage_preflight_execution_state": _NOT_STARTED,
        "storage_preparation_source_state": _UNAVAILABLE,
        "storage_preparation_authorization_state": _UNAVAILABLE,
        "storage_preparation_execution_state": _NOT_STARTED,
        "wipe_safety_state": "not-evaluated",
        "owned_noop_state": "not-inferred",
        "next_boundary": _NEXT_BOUNDARY,
        "next_status": DeployManagerBackendStorageDiscoveryNextStatus.BLOCKED,
        "blockers": sorted_blockers,
        "blocker_count": len(sorted_blockers),
        "blocker_digest": _digest_object(list(sorted_blockers)),
        "mutation_state": _NOT_PERFORMED,
        "journal_transition_state": _NOT_PERFORMED,
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "next_implementation_contract": _NEXT_IMPLEMENTATION_CONTRACT,
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(values, "record_digest")
    return DeployManagerBackendStorageDiscoveryReconciliation(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployManagerBackendStorageDiscoveryReconciliation,
    *,
    state: DeployManagerBackendStorageDiscoveryArtifactState,
) -> DeployManagerBackendStorageDiscoveryReconciliationReport:
    record = stored.record
    return DeployManagerBackendStorageDiscoveryReconciliationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        artifact_digest=stored.artifact_digest,
        record_digest=record.record_digest,
        target_stable_id=record.target_stable_id,
        target_set_digest=record.target_set_digest,
        semantic_status=record.semantic_status,
        discovery_boundary_status=record.discovery_boundary_status,
        next_boundary=record.next_boundary,
        next_status=record.next_status,
        capacity_policy_state=record.capacity_policy_state,
        capacity_adequacy_state=record.capacity_adequacy_state,
        storage_preflight_source_state=record.storage_preflight_source_state,
        storage_preparation_authorization_state=(
            record.storage_preparation_authorization_state
        ),
        blocker_count=record.blocker_count,
        blocker_digest=record.blocker_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
    )


_StoredRecord = DeployManagerBackendStorageDiscoveryReconciliation


def _record_digest(record: _StoredRecord, digest_field: str) -> str:
    return _record_digest_from_values(
        cast(Mapping[str, object], asdict(record)), digest_field
    )


def _record_digest_from_values(
    values: Mapping[str, object],
    digest_field: str,
) -> str:
    copied = dict(values)
    for name in tuple(copied):
        if name == "schema_version" or name.endswith("_schema_version"):
            copied.pop(name)
    copied[digest_field] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(cast(Mapping[str, object], _jsonable(copied))))


def _dataclass_object(value: _StoredRecord) -> dict[str, object]:
    return cast(dict[str, object], _jsonable(asdict(value)))


def _jsonable(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest_fields(
    value: DeployManagerBackendStorageDiscoveryReconciliation,
) -> tuple[str, ...]:
    return tuple(
        cast(str, field_value)
        for field_name, field_value in asdict(value).items()
        if field_name.endswith("_digest") and field_value is not None
    )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Manager backend storage discovery reconciliation requires "
            "an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list Manager backend storage discovery "
            "reconciliation artifacts"
        ) from error
    canonical = str(operation_id)
    suffix = DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_RECONCILIATION_FILENAME_SUFFIX
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
                "Manager backend storage discovery reconciliation artifacts "
                "are ambiguous"
            )


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


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
