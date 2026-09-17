"""Operation-bound Manager backend storage discovery execution and evidence."""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from enum import Enum, StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.commands import (
    AnsibleCommandBuilder,
    ansible_command_intent_digest,
)
from scylla_vms.ansible.deploy_manager_backend_local_install_reconciliation import (
    _load_context as _load_package_reconciliation_context,
)
from scylla_vms.ansible.deploy_manager_backend_storage_allocation_plan import (
    DeployManagerBackendStorageAllocationContextStore,
    DeployManagerBackendStorageAllocationPlanStatus,
    DeployManagerBackendStorageAllocationPlanStore,
    DeployManagerBackendStorageAllocationState,
    DeployManagerBackendStorageDiscoverySourceState,
    DeployManagerBackendStorageGuestIdentityState,
    StoredDeployManagerBackendStorageAllocationContext,
    StoredDeployManagerBackendStorageAllocationPlan,
    _load_storage_planning_context,
    _StoragePlanningContext,
)
from scylla_vms.ansible.deploy_manager_backend_storage_allocation_plan import (
    _build_context_record as _build_allocation_context_record,
)
from scylla_vms.ansible.deploy_manager_backend_storage_allocation_plan import (
    _build_plan_record as _build_allocation_plan_record,
)
from scylla_vms.ansible.deploy_plan import (
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.manager_backend_storage_discover import (
    MANAGER_BACKEND_STORAGE_DISCOVERY_NOT_PERFORMED,
    MANAGER_BACKEND_STORAGE_DISCOVERY_SCHEMA_VERSION,
    ManagerBackendStorageDiscoveryStatus,
    ManagerBackendStorageMountStatus,
    ManagerBackendStorageOwnershipStatus,
    ManagerBackendStorageRootStatus,
    ManagerBackendStorageSignatureStatus,
    build_manager_backend_storage_discovery_payload,
)
from scylla_vms.ansible.operation_binding import readiness_binding_digest
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.service import (
    AnsibleExecutionResult,
    AnsibleResultError,
    AnsibleService,
    ProcessRunnerProtocol,
)
from scylla_vms.ansible.source import validate_ansible_config
from scylla_vms.ansible.toolchain import AnsibleToolchain
from scylla_vms.ansible.trust import TrustStore
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.journal import JOURNAL_SCHEMA_VERSION, JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import StoredObservedState
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import (
    AtomicJsonFile,
    ClusterMetadata,
    digest_bytes,
    format_timestamp,
    parse_timestamp,
    parse_uuid,
    require_exact_keys,
    require_string,
    serialize_json,
    validate_digest,
)
from scylla_vms.process import ProcessOutputError, ProcessTimeoutError
from scylla_vms.state import (
    StatePaths,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)
from scylla_vms.terraform.apply_readiness import (
    TERRAFORM_APPLY_READINESS_SCHEMA_VERSION,
    _executable_identity_digest,
    _toolchain_evidence_digest,
    _validate_toolchain_dependency,
)
from scylla_vms.terraform.inputs import StoredTerraformInput

ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-discovery-"
    "execution-binding/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-discovery-execution/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-discovery-evidence/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-discovery-"
    "execution-report/v1"
)

DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-storage-discovery-execution.json"
)
DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-storage-discovery-evidence.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "manager-backend-storage-discover"
_STEP_SEQUENCE = 1
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class DeployManagerBackendStorageDiscoveryExecutionState(StrEnum):
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"
    DRIFTED = "drifted"


class DeployManagerBackendStorageDiscoveryArtifactState(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStorageDiscoveryExecutionBinding:
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
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
    metadata_generation: int
    metadata_artifact_digest: str
    desired_spec_digest: str
    terraform_input_generation: int
    terraform_input_artifact_digest: str
    terraform_input_digest: str
    observation_generation: int
    observation_artifact_digest: str
    observation_manifest_digest: str
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    trust_generation: int
    trust_artifact_digest: str
    trust_entries_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    config_digest: str
    known_hosts_digest: str
    ssh_config_digest: str
    catalog_digest: str
    source_version: str
    source_digest: str
    playbook_source_digest: str
    toolchain_version: str
    executable_identity_digest: str
    toolchain_evidence_digest: str
    target_stable_id: str
    target_set_digest: str
    allocation_decision_digest: str
    provider_allocation_identity_digest: str
    guest_identity_set_digest: str
    manifest_digest: str
    variables_digest: str
    command_digest: str
    binding_digest: str
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_BINDING_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
            or self.target_set_digest != _digest_object([self.target_stable_id])
            or self.binding_digest != _binding_digest(self)
        ):
            raise StatePersistenceError(
                "Manager backend storage discovery execution binding conflicts"
            )
        validate_cluster_name(self.cluster_name)
        for value in (
            self.journal_generation,
            self.metadata_generation,
            self.terraform_input_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
        ):
            _positive_integer(value, "Manager backend storage discovery generation")
        for digest in _digest_fields(self):
            validate_digest(digest, "Manager backend storage discovery binding digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls,
        value: Mapping[str, object],
    ) -> DeployManagerBackendStorageDiscoveryExecutionBinding:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend storage discovery execution binding",
        )
        integer_fields = {
            "journal_generation",
            "metadata_generation",
            "terraform_input_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
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
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend storage discovery binding enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStorageDiscoveryExecution:
    generation: int
    created_at: str
    updated_at: str
    binding: DeployManagerBackendStorageDiscoveryExecutionBinding
    state: DeployManagerBackendStorageDiscoveryExecutionState
    invocation_count: int
    invocation_may_have_occurred: bool
    completed: bool
    exit_code: int | None
    result_digest: str | None
    evidence_digest: str | None
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION
            or self.generation not in {1, 2}
            or self.invocation_count != 1
            or not self.invocation_may_have_occurred
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "Manager backend storage discovery execution conflicts"
            )
        parse_timestamp(self.created_at)
        if parse_timestamp(self.updated_at) < parse_timestamp(self.created_at):
            raise StatePersistenceError(
                "Manager backend storage discovery execution timestamps conflict"
            )
        if self.state is DeployManagerBackendStorageDiscoveryExecutionState.STARTED:
            valid = (
                self.generation == 1
                and not self.completed
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.manual_recovery_required
            )
        elif self.state is DeployManagerBackendStorageDiscoveryExecutionState.SUCCEEDED:
            valid = (
                self.generation == 2
                and self.completed
                and self.exit_code == 0
                and self.result_digest is not None
                and self.evidence_digest is not None
                and not self.manual_recovery_required
            )
        else:
            process_failure = self.state in {
                DeployManagerBackendStorageDiscoveryExecutionState.FAILED,
                DeployManagerBackendStorageDiscoveryExecutionState.UNREACHABLE,
            }
            valid = (
                self.generation == 2
                and not self.completed
                and self.manual_recovery_required
                and self.result_digest is None
                and self.evidence_digest is None
                and (
                    (process_failure and self.exit_code not in {None, 0})
                    or (not process_failure and self.exit_code is None)
                )
            )
        if not valid:
            raise StatePersistenceError(
                "Manager backend storage discovery execution state conflicts"
            )
        for value in (self.result_digest, self.evidence_digest):
            if value is not None:
                validate_digest(
                    value, "Manager backend storage discovery result digest"
                )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls,
        value: Mapping[str, object],
    ) -> DeployManagerBackendStorageDiscoveryExecution:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend storage discovery execution",
        )
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                updated_at=require_string(value, "updated_at"),
                binding=DeployManagerBackendStorageDiscoveryExecutionBinding.from_object(
                    _mapping(value["binding"], "binding")
                ),
                state=DeployManagerBackendStorageDiscoveryExecutionState(
                    require_string(value, "state")
                ),
                invocation_count=_integer(
                    value["invocation_count"], "invocation count"
                ),
                invocation_may_have_occurred=_boolean(
                    value["invocation_may_have_occurred"],
                    "invocation may have occurred",
                ),
                completed=_boolean(value["completed"], "completed"),
                exit_code=_optional_integer(value["exit_code"], "exit code"),
                result_digest=_optional_string(value["result_digest"], "result digest"),
                evidence_digest=_optional_string(
                    value["evidence_digest"], "evidence digest"
                ),
                manual_recovery_required=_boolean(
                    value["manual_recovery_required"], "manual recovery required"
                ),
                automatic_retry_allowed=_boolean(
                    value["automatic_retry_allowed"], "automatic retry allowed"
                ),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend storage discovery execution enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStorageDiscoveryEvidence:
    generation: int
    created_at: str
    binding: DeployManagerBackendStorageDiscoveryExecutionBinding
    stable_id: str
    role: str
    status: ManagerBackendStorageDiscoveryStatus
    backend_type: str
    device_type: str
    device_count: int
    total_size_gib: int
    signature_status: ManagerBackendStorageSignatureStatus
    ownership_status: ManagerBackendStorageOwnershipStatus
    mount_status: ManagerBackendStorageMountStatus
    root_status: ManagerBackendStorageRootStatus
    device_set_digest: str
    topology_digest: str
    manifest_digest: str
    provenance_digest: str
    not_performed: tuple[str, ...]
    blockers: tuple[str, ...]
    capacity_policy_state: str
    capacity_evaluation_state: str
    result_digest: str
    evidence_digest: str
    result_schema_version: str = MANAGER_BACKEND_STORAGE_DISCOVERY_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        discovered = self.status is ManagerBackendStorageDiscoveryStatus.DISCOVERED
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION
            or self.result_schema_version
            != MANAGER_BACKEND_STORAGE_DISCOVERY_SCHEMA_VERSION
            or self.generation != 1
            or self.stable_id != self.binding.target_stable_id
            or self.role != "manager"
            or self.backend_type != "block-volume"
            or self.device_type not in {"disk", "unknown"}
            or not 0 <= self.device_count <= 16
            or not 0 <= self.total_size_gib <= 1024 * 1024
            or self.manifest_digest != self.binding.manifest_digest
            or self.not_performed != MANAGER_BACKEND_STORAGE_DISCOVERY_NOT_PERFORMED
            or self.blockers != tuple(sorted(set(self.blockers)))
            or self.capacity_policy_state != "unknown"
            or self.capacity_evaluation_state != "not-evaluated"
            or self.status is ManagerBackendStorageDiscoveryStatus.FAILED
            or (
                discovered
                and (
                    self.device_type != "disk"
                    or self.device_count != 1
                    or self.total_size_gib < 1
                    or self.signature_status
                    is not ManagerBackendStorageSignatureStatus.ABSENT
                    or self.ownership_status
                    not in {
                        ManagerBackendStorageOwnershipStatus.UNOWNED,
                        ManagerBackendStorageOwnershipStatus.MANAGER_OWNED,
                    }
                    or self.mount_status
                    is not ManagerBackendStorageMountStatus.UNMOUNTED
                    or self.root_status is not ManagerBackendStorageRootStatus.EXCLUDED
                    or self.blockers
                )
            )
            or (
                not discovered
                and (
                    self.status is not ManagerBackendStorageDiscoveryStatus.BLOCKED
                    or not self.blockers
                )
            )
            or self.result_digest != _semantic_result_digest(self)
            or self.evidence_digest != _evidence_digest(self)
        ):
            raise StatePersistenceError(
                "Manager backend storage discovery semantic evidence conflicts"
            )
        parse_timestamp(self.created_at)
        for value in (
            self.device_set_digest,
            self.topology_digest,
            self.manifest_digest,
            self.provenance_digest,
            self.result_digest,
            self.evidence_digest,
        ):
            validate_digest(value, "Manager backend storage discovery evidence digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls,
        value: Mapping[str, object],
    ) -> DeployManagerBackendStorageDiscoveryEvidence:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend storage discovery evidence",
        )
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in {"generation", "device_count", "total_size_gib"}:
                    parsed[name] = _integer(item, name)
                elif name == "binding":
                    parsed[name] = (
                        DeployManagerBackendStorageDiscoveryExecutionBinding.from_object(
                            _mapping(item, name)
                        )
                    )
                elif name == "status":
                    parsed[name] = ManagerBackendStorageDiscoveryStatus(
                        require_string(value, name)
                    )
                elif name == "signature_status":
                    parsed[name] = ManagerBackendStorageSignatureStatus(
                        require_string(value, name)
                    )
                elif name == "ownership_status":
                    parsed[name] = ManagerBackendStorageOwnershipStatus(
                        require_string(value, name)
                    )
                elif name == "mount_status":
                    parsed[name] = ManagerBackendStorageMountStatus(
                        require_string(value, name)
                    )
                elif name == "root_status":
                    parsed[name] = ManagerBackendStorageRootStatus(
                        require_string(value, name)
                    )
                elif name in {"not_performed", "blockers"}:
                    parsed[name] = _string_tuple(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend storage discovery evidence enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendStorageDiscoveryExecution:
    record: DeployManagerBackendStorageDiscoveryExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendStorageDiscoveryEvidence:
    record: DeployManagerBackendStorageDiscoveryEvidence
    artifact_digest: str


class DeployManagerBackendStorageDiscoveryExecutionStore:
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
        self._path = deploy_manager_backend_storage_discovery_execution_path(
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
    ) -> StoredDeployManagerBackendStorageDiscoveryExecution:
        value, digest = self._file.read()
        record = DeployManagerBackendStorageDiscoveryExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "Manager backend storage discovery execution identity conflicts"
            )
        return StoredDeployManagerBackendStorageDiscoveryExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendStorageDiscoveryExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendStorageDiscoveryExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployManagerBackendStorageDiscoveryExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Manager backend storage discovery execution operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if (
                current.record.generation != expected_generation
                or current.artifact_digest != expected_digest
                or current.record.state
                is not DeployManagerBackendStorageDiscoveryExecutionState.STARTED
                or record.generation != 2
                or record.created_at != current.record.created_at
                or record.binding != current.record.binding
            ):
                raise StateConflictError(
                    "Manager backend storage discovery execution transition conflicts"
                )
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
            or record.state
            is not DeployManagerBackendStorageDiscoveryExecutionState.STARTED
        ):
            raise StateConflictError(
                "Manager backend storage discovery initial execution conflicts"
            )
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployManagerBackendStorageDiscoveryExecution(record, digest)


class DeployManagerBackendStorageDiscoveryEvidenceStore:
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
        self._path = deploy_manager_backend_storage_discovery_evidence_path(
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
    ) -> StoredDeployManagerBackendStorageDiscoveryEvidence:
        value, digest = self._file.read()
        record = DeployManagerBackendStorageDiscoveryEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "Manager backend storage discovery evidence identity conflicts"
            )
        return StoredDeployManagerBackendStorageDiscoveryEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendStorageDiscoveryEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendStorageDiscoveryEvidence,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerBackendStorageDiscoveryEvidence,
        DeployManagerBackendStorageDiscoveryArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Manager backend storage discovery evidence operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "Manager backend storage discovery evidence is immutable"
                )
            return current, DeployManagerBackendStorageDiscoveryArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerBackendStorageDiscoveryEvidence(record, digest),
            DeployManagerBackendStorageDiscoveryArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStorageDiscoveryExecutionReport:
    operation_id: uuid.UUID
    execution_artifact_state: DeployManagerBackendStorageDiscoveryArtifactState
    evidence_artifact_state: DeployManagerBackendStorageDiscoveryArtifactState
    execution_state: DeployManagerBackendStorageDiscoveryExecutionState
    execution_artifact_digest: str
    evidence_artifact_digest: str
    binding_digest: str
    target_stable_id: str
    target_set_digest: str
    semantic_status: ManagerBackendStorageDiscoveryStatus
    device_count: int
    total_size_gib: int
    blocker_count: int
    blocker_digest: str
    invocation_count: int
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    capacity_policy_state: str
    capacity_evaluation_state: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_REPORT_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION
            or self.execution_state
            is not DeployManagerBackendStorageDiscoveryExecutionState.SUCCEEDED
            or self.semantic_status is ManagerBackendStorageDiscoveryStatus.FAILED
            or self.invocation_count != 1
            or self.manual_recovery_required
            or self.automatic_retry_allowed
            or self.capacity_policy_state != "unknown"
            or self.capacity_evaluation_state != "not-evaluated"
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError(
                "Manager backend storage discovery execution report conflicts"
            )
        for value in (
            self.execution_artifact_digest,
            self.evidence_artifact_digest,
            self.binding_digest,
            self.target_set_digest,
            self.blocker_digest,
        ):
            validate_digest(value, "Manager backend storage discovery report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "artifacts": {
                "evidence_digest": self.evidence_artifact_digest,
                "evidence_state": self.evidence_artifact_state.value,
                "execution_digest": self.execution_artifact_digest,
                "execution_state": self.execution_artifact_state.value,
            },
            "capacity": {
                "evaluation_state": self.capacity_evaluation_state,
                "policy_state": self.capacity_policy_state,
            },
            "execution": {
                "automatic_retry_allowed": self.automatic_retry_allowed,
                "binding_digest": self.binding_digest,
                "invocation_count": self.invocation_count,
                "manual_recovery_required": self.manual_recovery_required,
                "state": self.execution_state.value,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "operation_id": str(self.operation_id),
            "result": {
                "blocker_count": self.blocker_count,
                "blocker_digest": self.blocker_digest,
                "device_count": self.device_count,
                "status": self.semantic_status.value,
                "total_size_gib": self.total_size_gib,
            },
            "schema_version": self.schema_version,
            "schemas": {
                "evidence": self.evidence_schema_version,
                "execution": self.execution_schema_version,
            },
            "scope": {
                "target_set_digest": self.target_set_digest,
                "target_stable_id": self.target_stable_id,
            },
        }


@dataclass(frozen=True, slots=True)
class _ExecutionScope:
    target_stable_id: str
    variables: Mapping[str, object]
    variables_digest: str
    command_digest: str
    source_digest: str
    payload: dict[str, object]


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    allocation_context: StoredDeployManagerBackendStorageAllocationContext
    allocation_plan: StoredDeployManagerBackendStorageAllocationPlan
    binding: DeployManagerBackendStorageDiscoveryExecutionBinding
    metadata: ClusterMetadata
    terraform_input: StoredTerraformInput
    observation: StoredObservedState
    inventory: StoredInventoryRecord
    readiness: ReadinessReport
    scope: _ExecutionScope


def execute_deploy_manager_backend_storage_discovery(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployManagerBackendStorageDiscoveryExecutionReport:
    """Execute the exact read-only Manager backend volume discovery once."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _validate_toolchain_dependency(toolchain)
    executable_identity_digest = _executable_identity_digest(executables)
    toolchain_evidence_digest = _toolchain_evidence_digest(
        toolchain, executable_identity_digest
    )
    _refuse_ambiguous_artifacts(paths, operation_id)
    builder = AnsibleCommandBuilder(executables.playbook, executables.inventory, paths)
    context = _load_execution_context(
        paths,
        operation_id,
        lock=lock,
        builder=builder,
        toolchain_version=str(toolchain.core),
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    execution_store = DeployManagerBackendStorageDiscoveryExecutionStore(
        paths, operation_id
    )
    evidence_store = DeployManagerBackendStorageDiscoveryEvidenceStore(
        paths, operation_id
    )
    for path in (execution_store.path, evidence_store.path):
        validate_state_file(path, allow_missing=True)
    execution = (
        execution_store.read_locked(
            lock,
            expected_cluster_uuid=context.binding.cluster_uuid,
            expected_cluster_name=context.binding.cluster_name,
        )
        if execution_store.path.exists()
        else None
    )
    evidence = (
        evidence_store.read_locked(
            lock,
            expected_cluster_uuid=context.binding.cluster_uuid,
            expected_cluster_name=context.binding.cluster_name,
        )
        if evidence_store.path.exists()
        else None
    )
    _validate_execution_prefix(context, execution, evidence)
    if execution is not None:
        if (
            execution.record.state
            is DeployManagerBackendStorageDiscoveryExecutionState.SUCCEEDED
            and evidence is not None
        ):
            return _build_report(
                execution,
                evidence,
                execution_state=DeployManagerBackendStorageDiscoveryArtifactState.REUSED,
                evidence_state=DeployManagerBackendStorageDiscoveryArtifactState.REUSED,
            )
        raise StateConflictError(
            "Manager backend storage discovery requires manual recovery "
            "and cannot retry"
        )

    service = AnsibleService(builder, runner)
    if service.version(lock) != toolchain:
        raise StateConflictError(
            "Manager backend storage discovery Ansible toolchain drifted"
        )
    before = _load_execution_context(
        paths,
        operation_id,
        lock=lock,
        builder=builder,
        toolchain_version=str(toolchain.core),
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    if before.binding != context.binding:
        raise StateConflictError(
            "Manager backend storage discovery state drifted before invocation"
        )

    now = _timestamp()
    started = DeployManagerBackendStorageDiscoveryExecution(
        generation=1,
        created_at=now,
        updated_at=now,
        binding=context.binding,
        state=DeployManagerBackendStorageDiscoveryExecutionState.STARTED,
        invocation_count=1,
        invocation_may_have_occurred=True,
        completed=False,
        exit_code=None,
        result_digest=None,
        evidence_digest=None,
        manual_recovery_required=True,
        automatic_retry_allowed=False,
    )
    try:
        execution = execution_store.write_locked(
            started,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "Manager backend storage discovery started intent persistence "
            "failed before invocation"
        ) from error

    try:
        result = service.execute_manager_backend_storage_discovery(
            lock,
            context.metadata,
            context.terraform_input,
            context.observation,
            context.inventory,
            context.allocation_context,
            context.allocation_plan,
            limit=(context.scope.target_stable_id,),
            readiness=context.readiness,
            check=True,
            verbosity=0,
        )
    except KeyboardInterrupt:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployManagerBackendStorageDiscoveryExecutionState.INTERRUPTED,
            lock=lock,
        )
        raise AnsibleError(
            "Manager backend storage discovery was interrupted; "
            "manual recovery required"
        ) from None
    except AnsibleError as error:
        _persist_uncertain_or_raise(
            execution_store, execution, _failure_state(error), lock=lock
        )
        raise AnsibleError(
            "Manager backend storage discovery execution is uncertain; "
            "manual recovery required"
        ) from error

    try:
        after = _load_execution_context(
            paths,
            operation_id,
            lock=lock,
            builder=builder,
            toolchain_version=str(toolchain.core),
            executable_identity_digest=executable_identity_digest,
            toolchain_evidence_digest=toolchain_evidence_digest,
        )
        if after.binding != context.binding:
            raise StateConflictError(
                "Manager backend storage discovery state changed after invocation"
            )
    except (StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployManagerBackendStorageDiscoveryExecutionState.DRIFTED,
            lock=lock,
        )
        raise StateConflictError(
            "Manager backend storage discovery state changed after invocation; "
            "manual recovery required"
        ) from error

    if result.exit_code != 0:
        state = (
            DeployManagerBackendStorageDiscoveryExecutionState.UNREACHABLE
            if result.exit_code == 4
            else DeployManagerBackendStorageDiscoveryExecutionState.FAILED
        )
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            state,
            lock=lock,
            exit_code=result.exit_code,
        )
        raise AnsibleError(
            "Manager backend storage discovery failed; manual recovery required"
        )
    try:
        evidence_record = _build_semantic_evidence(context, result)
    except (AnsibleError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployManagerBackendStorageDiscoveryExecutionState.MALFORMED_RESULT,
            lock=lock,
        )
        raise AnsibleError(
            "Manager backend storage discovery result is malformed; "
            "manual recovery required"
        ) from error
    try:
        evidence, evidence_state = evidence_store.write_locked(
            evidence_record, lock=lock
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "Manager backend storage discovery evidence persistence failed; "
            "manual recovery required"
        ) from error
    terminal = replace(
        execution.record,
        generation=2,
        updated_at=_timestamp(),
        state=DeployManagerBackendStorageDiscoveryExecutionState.SUCCEEDED,
        completed=True,
        exit_code=0,
        result_digest=evidence.record.result_digest,
        evidence_digest=evidence.record.evidence_digest,
        manual_recovery_required=False,
    )
    try:
        execution = execution_store.write_locked(
            terminal,
            expected_generation=execution.record.generation,
            expected_digest=execution.artifact_digest,
            lock=lock,
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "Manager backend storage discovery terminal persistence failed; "
            "manual recovery required"
        ) from error
    return _build_report(
        execution,
        evidence,
        execution_state=DeployManagerBackendStorageDiscoveryArtifactState.UPDATED,
        evidence_state=evidence_state,
    )


def deploy_manager_backend_storage_discovery_execution_path(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}"
        f"{DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "Manager backend storage discovery execution path is not canonical"
        )
    return path


def deploy_manager_backend_storage_discovery_evidence_path(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}"
        f"{DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EVIDENCE_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "Manager backend storage discovery evidence path is not canonical"
        )
    return path


def deploy_manager_backend_storage_discovery_execution_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(
        name, DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_FILENAME_SUFFIX
    )


def deploy_manager_backend_storage_discovery_evidence_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(
        name, DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EVIDENCE_FILENAME_SUFFIX
    )


def _load_execution_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
    builder: AnsibleCommandBuilder | None,
    toolchain_version: str,
    executable_identity_digest: str,
    toolchain_evidence_digest: str,
) -> _ExecutionContext:
    loaded = _load_storage_planning_context(paths, operation_id, lock=lock)
    metadata = loaded.metadata
    context_store = DeployManagerBackendStorageAllocationContextStore(
        paths, operation_id
    )
    plan_store = DeployManagerBackendStorageAllocationPlanStore(paths, operation_id)
    for path, label in (
        (context_store.path, "allocation context"),
        (plan_store.path, "allocation plan"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"Manager backend storage discovery requires exact {label}"
            )
    allocation_context = context_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_context = _build_allocation_context_record(
        loaded, created_at=allocation_context.record.created_at
    )
    if allocation_context.record != expected_context:
        raise StateConflictError(
            "Manager backend storage discovery allocation context drifted"
        )
    allocation_plan = plan_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_plan = _build_allocation_plan_record(
        allocation_context,
        source=loaded.source,
        created_at=allocation_plan.record.created_at,
    )
    if allocation_plan.record != expected_plan:
        raise StateConflictError(
            "Manager backend storage discovery allocation plan drifted"
        )

    package_context = _load_package_reconciliation_context(
        paths, operation_id, lock=lock
    )
    current = package_context.authorization_context.planning.execution_context
    readiness_record = loaded.readiness.record
    if (
        current.metadata.cluster_uuid != metadata.cluster_uuid
        or current.metadata.cluster_name != metadata.cluster_name
        or current.observation.digest != loaded.observation.digest
        or current.inventory.digest != loaded.inventory.digest
        or readiness_binding_digest(current.readiness)
        != readiness_record.readiness_digest
        or readiness_record.playbook_version != toolchain_version
        or readiness_record.inventory_version != toolchain_version
        or readiness_record.executable_identity_digest != executable_identity_digest
        or readiness_record.toolchain_evidence_digest != toolchain_evidence_digest
        or readiness_record.remote_playbook_status != "not-performed"
        or readiness_record.config_digest != validate_ansible_config(paths)
    ):
        raise StateConflictError(
            "Manager backend storage discovery controller, readiness, "
            "or toolchain conflicts"
        )
    current.readiness.require_ready(OperationClassification.READ_ONLY)
    TrustStore(paths).validate_runtime(
        TrustStore(paths).read(
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
            expected_provider=metadata.provider,
        ),
        loaded.inventory,
    )
    scope = _derive_scope(
        loaded,
        allocation_context,
        allocation_plan,
        readiness=current.readiness,
        builder=builder,
    )
    context_record = allocation_context.record
    plan_record = allocation_plan.record
    package_record = loaded.package_reconciliation.record
    values: dict[str, object] = {
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_name": metadata.cluster_name,
        "operation_id": operation_id,
        "operation": _OPERATION,
        "request_digest": context_record.request_digest,
        "journal_generation": context_record.journal_generation,
        "journal_digest": context_record.journal_digest,
        "journal_status": context_record.journal_status,
        "journal_phase": context_record.journal_phase,
        "allocation_context_artifact_digest": allocation_context.artifact_digest,
        "allocation_context_record_digest": context_record.record_digest,
        "allocation_plan_artifact_digest": allocation_plan.artifact_digest,
        "allocation_plan_digest": plan_record.plan_digest,
        "package_reconciliation_artifact_digest": (
            loaded.package_reconciliation.artifact_digest
        ),
        "package_reconciliation_record_digest": package_record.record_digest,
        "metadata_generation": context_record.metadata_generation,
        "metadata_artifact_digest": context_record.metadata_artifact_digest,
        "desired_spec_digest": context_record.desired_spec_digest,
        "terraform_input_generation": context_record.terraform_input_generation,
        "terraform_input_artifact_digest": (
            context_record.terraform_input_artifact_digest
        ),
        "terraform_input_digest": context_record.terraform_input_digest,
        "observation_generation": context_record.observation_generation,
        "observation_artifact_digest": context_record.observation_artifact_digest,
        "observation_manifest_digest": context_record.observation_manifest_digest,
        "inventory_generation": context_record.inventory_generation,
        "inventory_artifact_digest": context_record.inventory_artifact_digest,
        "inventory_digest": context_record.inventory_digest,
        "trust_generation": context_record.trust_generation,
        "trust_artifact_digest": context_record.trust_artifact_digest,
        "trust_entries_digest": context_record.trust_entries_digest,
        "readiness_artifact_digest": context_record.readiness_artifact_digest,
        "readiness_record_digest": context_record.readiness_record_digest,
        "config_digest": readiness_record.config_digest,
        "known_hosts_digest": readiness_record.known_hosts_digest,
        "ssh_config_digest": readiness_record.ssh_config_digest,
        "catalog_digest": context_record.catalog_digest,
        "source_version": context_record.ansible_source_version,
        "source_digest": context_record.ansible_source_digest,
        "playbook_source_digest": scope.source_digest,
        "toolchain_version": toolchain_version,
        "executable_identity_digest": executable_identity_digest,
        "toolchain_evidence_digest": toolchain_evidence_digest,
        "target_stable_id": scope.target_stable_id,
        "target_set_digest": _digest_object([scope.target_stable_id]),
        "allocation_decision_digest": context_record.allocation.decision_digest,
        "provider_allocation_identity_digest": (
            context_record.allocation.provider_allocation_identity_digest
        ),
        "guest_identity_set_digest": (
            context_record.allocation.guest_identity_set_digest
        ),
        "manifest_digest": context_record.allocation.observed_manifest_digest,
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "binding_digest": "",
    }
    if values["provider_allocation_identity_digest"] is None:
        raise StateConflictError(
            "Manager backend storage discovery provider allocation is unavailable"
        )
    values["binding_digest"] = _binding_digest_from_values(values)
    return _ExecutionContext(
        allocation_context,
        allocation_plan,
        DeployManagerBackendStorageDiscoveryExecutionBinding(**values),  # type: ignore[arg-type]
        metadata,
        loaded.terraform_input,
        loaded.observation,
        loaded.inventory,
        current.readiness,
        scope,
    )


def _derive_scope(
    loaded: _StoragePlanningContext,
    allocation_context: StoredDeployManagerBackendStorageAllocationContext,
    allocation_plan: StoredDeployManagerBackendStorageAllocationPlan,
    *,
    readiness: ReadinessReport,
    builder: AnsibleCommandBuilder | None,
) -> _ExecutionScope:
    metadata = loaded.metadata
    terraform_input = loaded.terraform_input
    observation = loaded.observation
    inventory = loaded.inventory
    source = loaded.ansible_source
    target = allocation_context.record.manager_target_id
    plan = allocation_plan.record
    allocation = allocation_context.record.allocation
    definition = get_playbook(_PLAYBOOK)
    if (
        plan.status is not DeployManagerBackendStorageAllocationPlanStatus.ELIGIBLE
        or plan.source_state
        is not DeployManagerBackendStorageDiscoverySourceState.AVAILABLE
        or plan.discovery_target_ids != (target,)
        or plan.discovery_target_count != 1
        or plan.source_digest is None
        or allocation.state is not DeployManagerBackendStorageAllocationState.EXACT
        or allocation.guest_identity_state
        is not DeployManagerBackendStorageGuestIdentityState.AVAILABLE
        or allocation.provider_allocation_identity_digest is None
        or allocation.requested_path_only
        or allocation.shared_with_scylla
        or allocation.desired_backend != "block-volume"
        or allocation.terraform_backend != "block-volume"
        or allocation.observed_backend != "block-volume"
        or allocation.allocation_count != 1
        or allocation.expected_device_count != 1
        or definition.classification is not OperationClassification.READ_ONLY
        or definition.hosts != "manager"
        or definition.serial != 1
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.check_mode is not CheckMode.SUPPORTED
        or not definition.any_errors_fatal
        or not definition.source_available
    ):
        raise StateConflictError(
            "Manager backend storage discovery exact target or source policy conflicts"
        )
    payload = build_manager_backend_storage_discovery_payload(
        metadata,
        terraform_input,
        observation,
        inventory,
        readiness,
        allocation_context,
        allocation_plan,
        logical_id=target,
    )
    variables: dict[str, object] = {
        "deploy_scylla_vms_manager_backend_storage_discover": payload
    }
    if builder is not None:
        selected, validated, variables_digest, command_digest = (
            builder.validate_operation_step(
                _PLAYBOOK,
                step_sequence=_STEP_SEQUENCE,
                limit=(target,),
                variables=variables,
                tags=definition.tags,
                check=True,
                diff=False,
                verbosity=0,
            )
        )
    else:
        selected = definition
        validated = definition.validate_variables(variables)
        variables_digest = digest_bytes(serialize_json(validated))
        command_digest = ansible_command_intent_digest(
            definition,
            step_sequence=_STEP_SEQUENCE,
            limit=(target,),
            variables_digest=variables_digest,
            tags=definition.tags,
            check=True,
            diff=False,
            verbosity=0,
        )
    source_digest = _playbook_source_digest(source, _PLAYBOOK)
    if (
        selected != definition
        or source_digest != plan.source_digest
        or source_digest
        != next(
            (
                item.digest
                for item in source.files
                if item.path == f"playbooks/{definition.filename}"
            ),
            None,
        )
    ):
        raise StateConflictError(
            "Manager backend storage discovery command or source identity conflicts"
        )
    return _ExecutionScope(
        target,
        validated,
        variables_digest,
        command_digest,
        source_digest,
        payload,
    )


def _validate_execution_prefix(
    context: _ExecutionContext,
    execution: StoredDeployManagerBackendStorageDiscoveryExecution | None,
    evidence: StoredDeployManagerBackendStorageDiscoveryEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "Manager backend storage discovery evidence exists without execution"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError(
            "Manager backend storage discovery execution provenance is stale"
        )
    if evidence is not None:
        if (
            evidence.record.binding != context.binding
            or execution.record.state
            not in {
                DeployManagerBackendStorageDiscoveryExecutionState.STARTED,
                DeployManagerBackendStorageDiscoveryExecutionState.SUCCEEDED,
            }
            or (
                execution.record.result_digest is not None
                and execution.record.result_digest != evidence.record.result_digest
            )
            or (
                execution.record.evidence_digest is not None
                and execution.record.evidence_digest != evidence.record.evidence_digest
            )
        ):
            raise StateConflictError(
                "Manager backend storage discovery semantic evidence conflicts"
            )
    elif (
        execution.record.state
        is DeployManagerBackendStorageDiscoveryExecutionState.SUCCEEDED
    ):
        raise StateConflictError(
            "Manager backend storage discovery success evidence is missing"
        )


def _build_semantic_evidence(
    context: _ExecutionContext,
    result: AnsibleExecutionResult,
) -> DeployManagerBackendStorageDiscoveryEvidence:
    parsed = result.manager_backend_storage_discovery
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.READ_ONLY
        or not result.check_mode
        or result.stdout
        or result.stderr
        or result.exit_code != 0
        or parsed is None
        or parsed.logical_id != context.scope.target_stable_id
        or parsed.role != "manager"
        or parsed.status is ManagerBackendStorageDiscoveryStatus.FAILED
        or parsed.backend_type != "block-volume"
        or parsed.manifest_digest != context.binding.manifest_digest
        or parsed.capacity_policy_state != "unknown"
        or parsed.capacity_evaluation_state != "not-evaluated"
        or parsed.not_performed != MANAGER_BACKEND_STORAGE_DISCOVERY_NOT_PERFORMED
    ):
        raise AnsibleResultError(
            "Manager backend storage discovery result identity conflicts"
        )
    projection: dict[str, object] = {
        "stable_id": parsed.logical_id,
        "role": parsed.role,
        "status": parsed.status.value,
        "backend_type": parsed.backend_type,
        "device_type": parsed.device_type,
        "device_count": parsed.device_count,
        "total_size_gib": parsed.total_size_gib,
        "signature_status": parsed.signature_status.value,
        "ownership_status": parsed.ownership_status.value,
        "mount_status": parsed.mount_status.value,
        "root_status": parsed.root_status.value,
        "device_set_digest": parsed.device_set_digest,
        "topology_digest": parsed.topology_digest,
        "manifest_digest": parsed.manifest_digest,
        "provenance_digest": _digest_object(dict(parsed.provenance)),
        "not_performed": list(parsed.not_performed),
        "blockers": list(parsed.blockers),
        "capacity_policy_state": parsed.capacity_policy_state,
        "capacity_evaluation_state": parsed.capacity_evaluation_state,
    }
    values: dict[str, object] = {
        "generation": 1,
        "created_at": _timestamp(),
        "binding": context.binding,
        "stable_id": parsed.logical_id,
        "role": parsed.role,
        "status": parsed.status,
        "backend_type": parsed.backend_type,
        "device_type": parsed.device_type,
        "device_count": parsed.device_count,
        "total_size_gib": parsed.total_size_gib,
        "signature_status": parsed.signature_status,
        "ownership_status": parsed.ownership_status,
        "mount_status": parsed.mount_status,
        "root_status": parsed.root_status,
        "device_set_digest": parsed.device_set_digest,
        "topology_digest": parsed.topology_digest,
        "manifest_digest": parsed.manifest_digest,
        "provenance_digest": _digest_object(dict(parsed.provenance)),
        "not_performed": parsed.not_performed,
        "blockers": parsed.blockers,
        "capacity_policy_state": parsed.capacity_policy_state,
        "capacity_evaluation_state": parsed.capacity_evaluation_state,
        "result_digest": _digest_object(projection),
        "evidence_digest": "",
    }
    values["evidence_digest"] = _evidence_digest_from_values(values)
    return DeployManagerBackendStorageDiscoveryEvidence(**values)  # type: ignore[arg-type]


def _persist_uncertain_or_raise(
    store: DeployManagerBackendStorageDiscoveryExecutionStore,
    current: StoredDeployManagerBackendStorageDiscoveryExecution,
    state: DeployManagerBackendStorageDiscoveryExecutionState,
    *,
    lock: ClusterLock,
    exit_code: int | None = None,
) -> None:
    try:
        record = replace(
            current.record,
            generation=2,
            updated_at=_timestamp(),
            state=state,
            completed=False,
            exit_code=exit_code,
            result_digest=None,
            evidence_digest=None,
            manual_recovery_required=True,
        )
        store.write_locked(
            record,
            expected_generation=current.record.generation,
            expected_digest=current.artifact_digest,
            lock=lock,
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "Manager backend storage discovery uncertain outcome persistence "
            "failed; manual recovery required"
        ) from error


def _failure_state(
    error: AnsibleError,
) -> DeployManagerBackendStorageDiscoveryExecutionState:
    current: BaseException | None = error
    while current is not None:
        if isinstance(current, ProcessTimeoutError):
            return DeployManagerBackendStorageDiscoveryExecutionState.TIMED_OUT
        if isinstance(current, ProcessOutputError):
            return DeployManagerBackendStorageDiscoveryExecutionState.MALFORMED_RESULT
        current = current.__cause__
    return DeployManagerBackendStorageDiscoveryExecutionState.MALFORMED_RESULT


def _build_report(
    execution: StoredDeployManagerBackendStorageDiscoveryExecution,
    evidence: StoredDeployManagerBackendStorageDiscoveryEvidence,
    *,
    execution_state: DeployManagerBackendStorageDiscoveryArtifactState,
    evidence_state: DeployManagerBackendStorageDiscoveryArtifactState,
) -> DeployManagerBackendStorageDiscoveryExecutionReport:
    if (
        execution.record.state
        is not DeployManagerBackendStorageDiscoveryExecutionState.SUCCEEDED
        or execution.record.result_digest != evidence.record.result_digest
        or execution.record.evidence_digest != evidence.record.evidence_digest
    ):
        raise StateConflictError(
            "Manager backend storage discovery success evidence is incomplete"
        )
    binding = execution.record.binding
    record = evidence.record
    return DeployManagerBackendStorageDiscoveryExecutionReport(
        operation_id=binding.operation_id,
        execution_artifact_state=execution_state,
        evidence_artifact_state=evidence_state,
        execution_state=execution.record.state,
        execution_artifact_digest=execution.artifact_digest,
        evidence_artifact_digest=evidence.artifact_digest,
        binding_digest=binding.binding_digest,
        target_stable_id=binding.target_stable_id,
        target_set_digest=binding.target_set_digest,
        semantic_status=record.status,
        device_count=record.device_count,
        total_size_gib=record.total_size_gib,
        blocker_count=len(record.blockers),
        blocker_digest=_digest_object(list(record.blockers)),
        invocation_count=execution.record.invocation_count,
        manual_recovery_required=execution.record.manual_recovery_required,
        automatic_retry_allowed=execution.record.automatic_retry_allowed,
        capacity_policy_state=record.capacity_policy_state,
        capacity_evaluation_state=record.capacity_evaluation_state,
        journal_status=binding.journal_status,
        journal_phase=binding.journal_phase,
    )


def _binding_digest(
    binding: DeployManagerBackendStorageDiscoveryExecutionBinding,
) -> str:
    return _binding_digest_from_values(binding.to_object())


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    copied = dict(values)
    for name in (
        "journal_schema_version",
        "readiness_schema_version",
        "schema_version",
    ):
        copied.pop(name, None)
    copied["binding_digest"] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(cast(Mapping[str, object], _jsonable(copied))))


def _evidence_digest(
    record: DeployManagerBackendStorageDiscoveryEvidence,
) -> str:
    return _evidence_digest_from_values(record.to_object())


def _semantic_result_digest(
    record: DeployManagerBackendStorageDiscoveryEvidence,
) -> str:
    return _digest_object(
        {
            "stable_id": record.stable_id,
            "role": record.role,
            "status": record.status.value,
            "backend_type": record.backend_type,
            "device_type": record.device_type,
            "device_count": record.device_count,
            "total_size_gib": record.total_size_gib,
            "signature_status": record.signature_status.value,
            "ownership_status": record.ownership_status.value,
            "mount_status": record.mount_status.value,
            "root_status": record.root_status.value,
            "device_set_digest": record.device_set_digest,
            "topology_digest": record.topology_digest,
            "manifest_digest": record.manifest_digest,
            "provenance_digest": record.provenance_digest,
            "not_performed": list(record.not_performed),
            "blockers": list(record.blockers),
            "capacity_policy_state": record.capacity_policy_state,
            "capacity_evaluation_state": record.capacity_evaluation_state,
        }
    )


def _evidence_digest_from_values(values: Mapping[str, object]) -> str:
    copied = dict(values)
    copied.pop("result_schema_version", None)
    copied.pop("schema_version", None)
    copied["evidence_digest"] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(cast(Mapping[str, object], _jsonable(copied))))


_StoredRecord = (
    DeployManagerBackendStorageDiscoveryExecutionBinding
    | DeployManagerBackendStorageDiscoveryExecution
    | DeployManagerBackendStorageDiscoveryEvidence
)


def _dataclass_object(value: _StoredRecord) -> dict[str, object]:
    return cast(dict[str, object], _jsonable(asdict(value)))


def _jsonable(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(
        value,
        (
            DeployManagerBackendStorageDiscoveryExecutionBinding,
            DeployManagerBackendStorageDiscoveryExecution,
            DeployManagerBackendStorageDiscoveryEvidence,
        ),
    ):
        return value.to_object()
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest_fields(value: _StoredRecord) -> tuple[str, ...]:
    return tuple(
        cast(str, field_value)
        for field_name, field_value in asdict(value).items()
        if field_name.endswith("_digest") and field_value is not None
    )


def _timestamp() -> str:
    return format_timestamp(datetime.now(UTC))


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "Manager backend storage discovery paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Manager backend storage discovery requires an acquired deploy lock"
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
            "cannot safely list Manager backend storage discovery artifacts"
        ) from error
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EVIDENCE_FILENAME_SUFFIX,
    )
    for entry in entries:
        suffix = next(
            (candidate for candidate in suffixes if entry.name.endswith(candidate)),
            None,
        )
        if suffix is None:
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
                "Manager backend storage discovery artifacts are ambiguous"
            )


def _id_from_filename(name: str, suffix: str) -> uuid.UUID | None:
    if not name.endswith(suffix):
        return None
    value = name[: -len(suffix)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


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


def _positive_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be a boolean")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    if value is None:
        return None
    return _integer(value, label)


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise StatePersistenceError(f"{label} must be a string or null")
    return value
