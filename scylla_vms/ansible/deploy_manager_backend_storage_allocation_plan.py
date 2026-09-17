"""Immutable Manager-backend dedicated-storage allocation/discovery planning.

This owner is deliberately subprocess-free.  It reloads the exact successful
Manager-local package-install chain, binds current Terraform input and observed
storage identity, and plans at most one read-only Manager discovery target.
"""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, is_dataclass
from datetime import UTC, datetime
from enum import Enum, StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.deploy_manager_backend_local_install_reconciliation import (
    ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_SCHEMA_VERSION,
    DeployPostManagerBackendLocalInstallReconciliationStore,
    StoredDeployPostManagerBackendLocalInstallReconciliation,
)
from scylla_vms.ansible.deploy_manager_backend_local_install_reconciliation import (
    _build_record as _build_package_reconciliation_record,
)
from scylla_vms.ansible.deploy_manager_backend_local_install_reconciliation import (
    _build_steps as _build_package_reconciliation_steps,
)
from scylla_vms.ansible.deploy_manager_backend_local_install_reconciliation import (
    _load_context as _load_package_reconciliation_context,
)
from scylla_vms.ansible.orchestration import ansible_operation_catalog_digest
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.source import (
    ANSIBLE_SOURCE_VERSION,
    AnsibleSourceBundle,
    load_ansible_source_bundle,
)
from scylla_vms.ansible.trust import TrustStore
from scylla_vms.desired import ClusterSpec, HostRole, StorageBackend, StorageLayout
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.inventory import InventoryStore, StoredInventoryRecord
from scylla_vms.journal import (
    JOURNAL_SCHEMA_VERSION,
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    StoredOperationRecord,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import ObservedStateStore, StoredObservedState
from scylla_vms.oci import OciHostInput, OciTerraformInput
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import (
    AtomicJsonFile,
    ClusterMetadata,
    ClusterMetadataStore,
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
from scylla_vms.terraform.apply_readiness import (
    TERRAFORM_APPLY_READINESS_SCHEMA_VERSION,
    StoredTerraformApplyReadiness,
    TerraformApplyReadinessStore,
)
from scylla_vms.terraform.inputs import (
    TERRAFORM_TFVARS_SCHEMA_VERSION,
    StoredTerraformInput,
    TerraformInputStore,
)
from scylla_vms.terraform.outputs import (
    StorageDevice,
    StorageDeviceKind,
    StorageManifest,
    StorageSelectionStatus,
)

ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_DECISION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-allocation-decision/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_CONTEXT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-allocation-context/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_PLAN_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-allocation-plan/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_PLAN_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-allocation-plan-report/v1"
)

DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_CONTEXT_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-storage-allocation-context.json"
)
DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_PLAN_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-storage-allocation-plan.json"
)

_OPERATION = "deploy"
_STAGE = "manager-backend-storage-allocation-planning"
_BOUNDARY = "manager-backend-storage-discovery"
_SOURCE_NAME = "manager-backend-storage-discover"
_SOURCE_CONTRACT = "manager-backend-storage-discover-v1"
_CAPACITY_POLICY_STATE = "unknown"
_CAPACITY_EVALUATION_STATE = "not-evaluated"
_ROOT_FALLBACK_POLICY = "forbidden"
_LOCAL_NVME_POLICY = "forbidden"
_SHARED_SCYLLA_STORAGE_POLICY = "forbidden"
_NOT_STARTED = "not-started"
_NOT_PERFORMED = "not-performed"
_UNAVAILABLE = "unavailable"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")
_GUEST_IDENTITY_NAMES = ("expected-by-id", "expected-serial", "expected-wwn")


class DeployManagerBackendStorageAllocationArtifactState(StrEnum):
    """Immutable context/plan persistence result."""

    CREATED = "created"
    REUSED = "reused"


class DeployManagerBackendStorageAllocationState(StrEnum):
    """Provider allocation classification."""

    EXACT = "exact-dedicated-manager-block-volume"
    ABSENT = "dedicated-manager-block-volume-absent"
    AMBIGUOUS = "dedicated-manager-block-volume-ambiguous"
    FORBIDDEN = "dedicated-manager-storage-forbidden"


class DeployManagerBackendStorageGuestIdentityState(StrEnum):
    """Whether Terraform exposed a non-requested-path guest identity."""

    AVAILABLE = "non-path-guest-identity-available"
    UNAVAILABLE = "non-path-guest-identity-unavailable"


class DeployManagerBackendStorageDiscoverySourceState(StrEnum):
    """Availability of the distinct Manager-only discovery source."""

    AVAILABLE = "source-available"
    UNAVAILABLE = "source-unavailable"


class DeployManagerBackendStorageAllocationPlanStatus(StrEnum):
    """Closed discovery planning state."""

    ELIGIBLE = "eligible"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStorageAllocationDecision:
    """Address-free binding for one dedicated Manager Block Volume."""

    state: DeployManagerBackendStorageAllocationState
    desired_backend: str
    terraform_backend: str
    observed_backend: str
    allocation_count: int
    expected_device_count: int
    storage_generation: int
    size_gib: int
    desired_policy_digest: str
    terraform_storage_input_digest: str
    observed_manifest_digest: str
    target_provider_identity_digest: str
    provider_volume_identity_digest: str | None
    provider_attachment_identity_digest: str | None
    provider_allocation_identity_digest: str | None
    guest_identity_state: DeployManagerBackendStorageGuestIdentityState
    guest_identity_count: int
    guest_identity_set_digest: str
    requested_path_present: bool
    requested_path_only: bool
    shared_with_scylla: bool
    root_fallback_policy: str
    local_nvme_policy: str
    shared_scylla_storage_policy: str
    capacity_policy_state: str
    capacity_evaluation_state: str
    blockers: tuple[str, ...]
    blocker_digest: str
    decision_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_DECISION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        exact = self.state is DeployManagerBackendStorageAllocationState.EXACT
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_DECISION_SCHEMA_VERSION
            or self.allocation_count < 0
            or self.expected_device_count < 0
            or self.storage_generation < 0
            or self.size_gib < 0
            or self.guest_identity_count < 0
            or self.guest_identity_count > len(_GUEST_IDENTITY_NAMES)
            or self.root_fallback_policy != _ROOT_FALLBACK_POLICY
            or self.local_nvme_policy != _LOCAL_NVME_POLICY
            or self.shared_scylla_storage_policy != _SHARED_SCYLLA_STORAGE_POLICY
            or self.capacity_policy_state != _CAPACITY_POLICY_STATE
            or self.capacity_evaluation_state != _CAPACITY_EVALUATION_STATE
            or self.requested_path_only
            is not (self.requested_path_present and self.guest_identity_count == 0)
            or (
                self.guest_identity_state
                is DeployManagerBackendStorageGuestIdentityState.AVAILABLE
            )
            is not (self.guest_identity_count > 0)
            or self.blockers != tuple(sorted(set(self.blockers)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blockers)
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.decision_digest != _record_digest(self, "decision_digest")
        ):
            raise StatePersistenceError(
                "Manager backend storage allocation decision conflicts"
            )
        if exact:
            valid = (
                self.desired_backend == StorageBackend.BLOCK_VOLUME.value
                and self.terraform_backend == StorageBackend.BLOCK_VOLUME.value
                and self.observed_backend == StorageBackend.BLOCK_VOLUME.value
                and self.allocation_count == 1
                and self.expected_device_count == 1
                and self.storage_generation >= 1
                and self.size_gib >= 1
                and self.provider_volume_identity_digest is not None
                and self.provider_attachment_identity_digest is not None
                and self.provider_allocation_identity_digest is not None
                and not self.shared_with_scylla
                and not self.blockers
            )
        else:
            valid = (
                bool(self.blockers)
                and self.provider_allocation_identity_digest is None
                and (
                    self.state is not DeployManagerBackendStorageAllocationState.ABSENT
                    or self.allocation_count == 0
                )
            )
        if not valid:
            raise StatePersistenceError(
                "Manager backend storage allocation classification conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(value, "Manager backend storage allocation digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls,
        value: Mapping[str, object],
    ) -> DeployManagerBackendStorageAllocationDecision:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend storage allocation decision",
        )
        integer_fields = {
            "allocation_count",
            "expected_device_count",
            "storage_generation",
            "size_gib",
            "guest_identity_count",
        }
        boolean_fields = {
            "requested_path_present",
            "requested_path_only",
            "shared_with_scylla",
        }
        optional_fields = {
            "provider_volume_identity_digest",
            "provider_attachment_identity_digest",
            "provider_allocation_identity_digest",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in integer_fields:
                    parsed[name] = _integer(item, name)
                elif name in boolean_fields:
                    parsed[name] = _boolean(item, name)
                elif name in optional_fields:
                    parsed[name] = _optional_string(item, name)
                elif name == "state":
                    parsed[name] = DeployManagerBackendStorageAllocationState(
                        require_string(value, name)
                    )
                elif name == "guest_identity_state":
                    parsed[name] = DeployManagerBackendStorageGuestIdentityState(
                        require_string(value, name)
                    )
                elif name == "blockers":
                    parsed[name] = _string_tuple(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend storage allocation enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStorageAllocationContext:
    """Immutable current-state context for dedicated storage discovery."""

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
    package_reconciliation_artifact_digest: str
    package_reconciliation_record_digest: str
    package_reconciliation_effective_plan_digest: str
    package_evidence_digest: str
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
    catalog_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    manager_target_id: str
    manager_target_digest: str
    manager_provider_identity_digest: str
    allocation: DeployManagerBackendStorageAllocationDecision
    capacity_policy_state: str
    capacity_evaluation_state: str
    root_fallback_policy: str
    local_nvme_policy: str
    shared_scylla_storage_policy: str
    execution_state: str
    authorization_state: str
    mutation_state: str
    finalization_state: str
    public_workflow_state: str
    record_digest: str
    package_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_SCHEMA_VERSION
    )
    terraform_input_schema_version: str = TERRAFORM_TFVARS_SCHEMA_VERSION
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_CONTEXT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_CONTEXT_SCHEMA_VERSION
            or self.package_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_SCHEMA_VERSION
            or self.terraform_input_schema_version != TERRAFORM_TFVARS_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or _LOGICAL_ID.fullmatch(self.manager_target_id) is None
            or self.manager_target_digest != _digest_object([self.manager_target_id])
            or self.capacity_policy_state != _CAPACITY_POLICY_STATE
            or self.capacity_evaluation_state != _CAPACITY_EVALUATION_STATE
            or self.root_fallback_policy != _ROOT_FALLBACK_POLICY
            or self.local_nvme_policy != _LOCAL_NVME_POLICY
            or self.shared_scylla_storage_policy != _SHARED_SCYLLA_STORAGE_POLICY
            or self.execution_state != _NOT_STARTED
            or self.authorization_state != _UNAVAILABLE
            or self.mutation_state != _NOT_PERFORMED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
            or self.record_digest != _record_digest(self, "record_digest")
        ):
            raise StatePersistenceError(
                "Manager backend storage allocation context conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for value in (
            self.journal_generation,
            self.metadata_generation,
            self.terraform_input_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
        ):
            _positive_integer(value, "Manager backend storage context generation")
        for digest in _digest_fields(self):
            validate_digest(digest, "Manager backend storage context digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls,
        value: Mapping[str, object],
    ) -> DeployManagerBackendStorageAllocationContext:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend storage allocation context",
        )
        integer_fields = {
            "generation",
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
                elif name == "allocation":
                    parsed[name] = (
                        DeployManagerBackendStorageAllocationDecision.from_object(
                            _mapping(item, name)
                        )
                    )
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend storage context enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStorageAllocationPlan:
    """One immutable Manager-only read-only discovery boundary."""

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
    context_artifact_digest: str
    context_record_digest: str
    package_reconciliation_artifact_digest: str
    package_reconciliation_record_digest: str
    boundary: str
    source_contract: str
    source_state: DeployManagerBackendStorageDiscoverySourceState
    source_digest: str | None
    classification: OperationClassification
    manager_target_id: str
    candidate_target_count: int
    candidate_target_set_digest: str
    discovery_target_ids: tuple[str, ...]
    discovery_target_count: int
    discovery_target_set_digest: str
    allocation_state: DeployManagerBackendStorageAllocationState
    allocation_decision_digest: str
    provider_allocation_identity_digest: str | None
    guest_identity_state: DeployManagerBackendStorageGuestIdentityState
    guest_identity_count: int
    guest_identity_set_digest: str
    size_gib: int
    capacity_policy_state: str
    capacity_evaluation_state: str
    status: DeployManagerBackendStorageAllocationPlanStatus
    blockers: tuple[str, ...]
    blocker_count: int
    blocker_digest: str
    authorization_state: str
    execution_state: str
    evidence_state: str
    mutation_state: str
    journal_transition_state: str
    finalization_state: str
    public_workflow_state: str
    plan_digest: str
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_PLAN_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        eligible = (
            self.status is DeployManagerBackendStorageAllocationPlanStatus.ELIGIBLE
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_PLAN_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.boundary != _BOUNDARY
            or self.source_contract != _SOURCE_CONTRACT
            or self.classification is not OperationClassification.READ_ONLY
            or _LOGICAL_ID.fullmatch(self.manager_target_id) is None
            or self.candidate_target_count != 1
            or self.candidate_target_set_digest
            != _digest_object([self.manager_target_id])
            or self.discovery_target_ids
            != tuple(sorted(set(self.discovery_target_ids)))
            or self.discovery_target_count != len(self.discovery_target_ids)
            or self.discovery_target_set_digest
            != _digest_object(list(self.discovery_target_ids))
            or self.guest_identity_count < 0
            or self.size_gib < 0
            or self.capacity_policy_state != _CAPACITY_POLICY_STATE
            or self.capacity_evaluation_state != _CAPACITY_EVALUATION_STATE
            or self.blockers != tuple(sorted(set(self.blockers)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blockers)
            or self.blocker_count != len(self.blockers)
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.authorization_state != "not-required-read-only"
            or self.execution_state != _NOT_STARTED
            or self.evidence_state != _NOT_PERFORMED
            or self.mutation_state != _NOT_PERFORMED
            or self.journal_transition_state != _NOT_PERFORMED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
            or self.plan_digest != _record_digest(self, "plan_digest")
        ):
            raise StatePersistenceError(
                "Manager backend storage allocation plan conflicts"
            )
        if eligible:
            valid = (
                self.source_state
                is DeployManagerBackendStorageDiscoverySourceState.AVAILABLE
                and self.source_digest is not None
                and self.allocation_state
                is DeployManagerBackendStorageAllocationState.EXACT
                and self.provider_allocation_identity_digest is not None
                and self.guest_identity_state
                is DeployManagerBackendStorageGuestIdentityState.AVAILABLE
                and self.discovery_target_ids == (self.manager_target_id,)
                and not self.blockers
            )
        else:
            valid = self.discovery_target_count == 0 and bool(self.blockers)
        if not valid:
            raise StatePersistenceError(
                "Manager backend storage discovery status conflicts"
            )
        parse_timestamp(self.created_at)
        validate_cluster_name(self.cluster_name)
        for value in _digest_fields(self):
            validate_digest(value, "Manager backend storage plan digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls,
        value: Mapping[str, object],
    ) -> DeployManagerBackendStorageAllocationPlan:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend storage allocation plan",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "candidate_target_count",
            "discovery_target_count",
            "guest_identity_count",
            "size_gib",
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
                elif name == "source_state":
                    parsed[name] = DeployManagerBackendStorageDiscoverySourceState(
                        require_string(value, name)
                    )
                elif name == "classification":
                    parsed[name] = OperationClassification(require_string(value, name))
                elif name == "allocation_state":
                    parsed[name] = DeployManagerBackendStorageAllocationState(
                        require_string(value, name)
                    )
                elif name == "guest_identity_state":
                    parsed[name] = DeployManagerBackendStorageGuestIdentityState(
                        require_string(value, name)
                    )
                elif name == "status":
                    parsed[name] = DeployManagerBackendStorageAllocationPlanStatus(
                        require_string(value, name)
                    )
                elif (
                    name == "source_digest"
                    or name == "provider_allocation_identity_digest"
                ):
                    parsed[name] = _optional_string(item, name)
                elif name in {"discovery_target_ids", "blockers"}:
                    parsed[name] = _string_tuple(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend storage plan enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendStorageAllocationContext:
    record: DeployManagerBackendStorageAllocationContext
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendStorageAllocationPlan:
    record: DeployManagerBackendStorageAllocationPlan
    artifact_digest: str


class DeployManagerBackendStorageAllocationContextStore:
    """Owner-only immutable storage-allocation planning context."""

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
        self._path = deploy_manager_backend_storage_allocation_context_path(
            paths, operation_id
        )
        self._file = AtomicJsonFile(
            self._path,
            replace=replace_file,
            token_factory=token_factory,
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendStorageAllocationContext:
        value, artifact_digest = self._file.read()
        record = DeployManagerBackendStorageAllocationContext.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "Manager backend storage context identity conflicts"
            )
        return StoredDeployManagerBackendStorageAllocationContext(
            record, artifact_digest
        )

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendStorageAllocationContext:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendStorageAllocationContext,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerBackendStorageAllocationContext,
        DeployManagerBackendStorageAllocationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Manager backend storage context operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "Manager backend storage allocation context is immutable; "
                    "use a new operation"
                )
            return (
                current,
                DeployManagerBackendStorageAllocationArtifactState.REUSED,
            )
        artifact_digest = self._file.write(
            record.to_object(),
            expected_digest=None,
        )
        return (
            StoredDeployManagerBackendStorageAllocationContext(record, artifact_digest),
            DeployManagerBackendStorageAllocationArtifactState.CREATED,
        )


class DeployManagerBackendStorageAllocationPlanStore:
    """Owner-only immutable storage-discovery plan."""

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
        self._path = deploy_manager_backend_storage_allocation_plan_path(
            paths, operation_id
        )
        self._file = AtomicJsonFile(
            self._path,
            replace=replace_file,
            token_factory=token_factory,
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendStorageAllocationPlan:
        value, artifact_digest = self._file.read()
        record = DeployManagerBackendStorageAllocationPlan.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "Manager backend storage plan identity conflicts"
            )
        return StoredDeployManagerBackendStorageAllocationPlan(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendStorageAllocationPlan:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendStorageAllocationPlan,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerBackendStorageAllocationPlan,
        DeployManagerBackendStorageAllocationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Manager backend storage plan operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "Manager backend storage allocation plan is immutable; "
                    "use a new operation"
                )
            return (
                current,
                DeployManagerBackendStorageAllocationArtifactState.REUSED,
            )
        artifact_digest = self._file.write(
            record.to_object(),
            expected_digest=None,
        )
        return (
            StoredDeployManagerBackendStorageAllocationPlan(record, artifact_digest),
            DeployManagerBackendStorageAllocationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStorageAllocationPlanReport:
    """Bounded projection of allocation/discovery planning."""

    operation_id: uuid.UUID
    context_state: DeployManagerBackendStorageAllocationArtifactState
    plan_state: DeployManagerBackendStorageAllocationArtifactState
    context_artifact_digest: str
    context_record_digest: str
    plan_artifact_digest: str
    plan_digest: str
    allocation_state: DeployManagerBackendStorageAllocationState
    guest_identity_state: DeployManagerBackendStorageGuestIdentityState
    source_state: DeployManagerBackendStorageDiscoverySourceState
    status: DeployManagerBackendStorageAllocationPlanStatus
    candidate_target_count: int
    discovery_target_count: int
    size_gib: int
    capacity_policy_state: str
    capacity_evaluation_state: str
    blocker_count: int
    blocker_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    process_calls: int = 0
    authorization_created: bool = False
    execution_started: bool = False
    mutation_performed: bool = False
    journal_updated: bool = False
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_PLAN_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_PLAN_REPORT_SCHEMA_VERSION
            or self.candidate_target_count != 1
            or self.discovery_target_count not in {0, 1}
            or self.size_gib < 0
            or self.capacity_policy_state != _CAPACITY_POLICY_STATE
            or self.capacity_evaluation_state != _CAPACITY_EVALUATION_STATE
            or self.blocker_count < 0
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.process_calls
            or self.authorization_created
            or self.execution_started
            or self.mutation_performed
            or self.journal_updated
        ):
            raise StatePersistenceError(
                "Manager backend storage planning report conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(value, "Manager backend storage report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "allocation": {
                "capacity_evaluation_state": self.capacity_evaluation_state,
                "capacity_policy_state": self.capacity_policy_state,
                "guest_identity_state": self.guest_identity_state.value,
                "size_gib": self.size_gib,
                "state": self.allocation_state.value,
            },
            "artifacts": {
                "context": {
                    "artifact_digest": self.context_artifact_digest,
                    "record_digest": self.context_record_digest,
                    "state": self.context_state.value,
                },
                "plan": {
                    "artifact_digest": self.plan_artifact_digest,
                    "plan_digest": self.plan_digest,
                    "state": self.plan_state.value,
                },
            },
            "blockers": {
                "count": self.blocker_count,
                "digest": self.blocker_digest,
            },
            "discovery": {
                "candidate_target_count": self.candidate_target_count,
                "executable_target_count": self.discovery_target_count,
                "source_state": self.source_state.value,
                "status": self.status.value,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": self.journal_updated,
            },
            "operation_id": str(self.operation_id),
            "schema_version": self.schema_version,
            "side_effects": {
                "authorization_created": self.authorization_created,
                "execution_started": self.execution_started,
                "mutation_performed": self.mutation_performed,
                "process_calls": self.process_calls,
            },
        }


@dataclass(frozen=True, slots=True)
class _DiscoverySourceReference:
    state: DeployManagerBackendStorageDiscoverySourceState
    source_digest: str | None


@dataclass(frozen=True, slots=True)
class _StoragePlanningContext:
    metadata: ClusterMetadata
    package_reconciliation: StoredDeployPostManagerBackendLocalInstallReconciliation
    terraform_input: StoredTerraformInput
    observation: StoredObservedState
    inventory: StoredInventoryRecord
    trust_artifact_digest: str
    trust_generation: int
    trust_entries_digest: str
    readiness: StoredTerraformApplyReadiness
    journal: StoredOperationRecord
    ansible_source: AnsibleSourceBundle
    catalog_digest: str
    allocation: DeployManagerBackendStorageAllocationDecision
    source: _DiscoverySourceReference


_StoredRecord = (
    DeployManagerBackendStorageAllocationDecision
    | DeployManagerBackendStorageAllocationContext
    | DeployManagerBackendStorageAllocationPlan
    | DeployManagerBackendStorageAllocationPlanReport
)


def plan_deploy_manager_backend_storage_allocation(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployManagerBackendStorageAllocationPlanReport:
    """Persist or exactly reuse one Manager storage discovery plan."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    context_store = DeployManagerBackendStorageAllocationContextStore(
        paths, operation_id
    )
    plan_store = DeployManagerBackendStorageAllocationPlanStore(paths, operation_id)
    _refuse_ambiguous_or_later_artifacts(
        paths,
        operation_id,
        allowed={context_store.path.name, plan_store.path.name},
    )
    for path in (context_store.path, plan_store.path):
        validate_state_file(path, allow_missing=True)
    if plan_store.path.exists() and not context_store.path.exists():
        raise StateConflictError(
            "Manager backend storage allocation plan exists without its context"
        )

    loaded = _load_storage_planning_context(paths, operation_id, lock=lock)
    existing_context = (
        context_store.read_locked(
            lock,
            expected_cluster_uuid=loaded.metadata.cluster_uuid,
            expected_cluster_name=loaded.metadata.cluster_name,
        )
        if context_store.path.exists()
        else None
    )
    existing_plan = (
        plan_store.read_locked(
            lock,
            expected_cluster_uuid=loaded.metadata.cluster_uuid,
            expected_cluster_name=loaded.metadata.cluster_name,
        )
        if plan_store.path.exists()
        else None
    )
    created_at = (
        existing_context.record.created_at
        if existing_context is not None
        else format_timestamp(datetime.now(UTC))
    )
    context_record = _build_context_record(loaded, created_at=created_at)
    expected_context_digest = digest_bytes(serialize_json(context_record.to_object()))
    context_for_plan = StoredDeployManagerBackendStorageAllocationContext(
        context_record,
        expected_context_digest,
    )
    plan_record = _build_plan_record(
        context_for_plan,
        source=loaded.source,
        created_at=(
            existing_plan.record.created_at if existing_plan is not None else created_at
        ),
    )

    stored_context, context_state = context_store.write_locked(
        context_record,
        lock=lock,
    )
    if stored_context.artifact_digest != expected_context_digest:
        raise StateConflictError(
            "Manager backend storage allocation context bytes changed"
        )
    stored_plan, plan_state = plan_store.write_locked(plan_record, lock=lock)
    return _build_report(
        stored_context,
        stored_plan,
        context_state=context_state,
        plan_state=plan_state,
    )


def deploy_manager_backend_storage_allocation_context_path(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> Path:
    """Return the canonical operation-bound allocation context path."""

    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}"
        f"{DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_CONTEXT_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "Manager backend storage allocation context path is not canonical"
        )
    return path


def deploy_manager_backend_storage_allocation_plan_path(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> Path:
    """Return the canonical operation-bound allocation plan path."""

    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}"
        f"{DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_PLAN_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "Manager backend storage allocation plan path is not canonical"
        )
    return path


def deploy_manager_backend_storage_allocation_context_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(
        name,
        DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_CONTEXT_FILENAME_SUFFIX,
    )


def deploy_manager_backend_storage_allocation_plan_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(
        name,
        DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_PLAN_FILENAME_SUFFIX,
    )


def _load_storage_planning_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
) -> _StoragePlanningContext:
    package_context = _load_package_reconciliation_context(
        paths,
        operation_id,
        lock=lock,
    )
    package_steps = _build_package_reconciliation_steps(package_context)
    package_store = DeployPostManagerBackendLocalInstallReconciliationStore(
        paths,
        operation_id,
    )
    validate_state_file(package_store.path, allow_missing=True)
    if not package_store.path.exists():
        raise StateConflictError(
            "Manager backend storage planning requires exact post-package "
            "reconciliation"
        )
    chain_metadata = (
        package_context.authorization_context.planning.execution_context.metadata
    )
    package_reconciliation = package_store.read_locked(
        lock,
        expected_cluster_uuid=chain_metadata.cluster_uuid,
        expected_cluster_name=chain_metadata.cluster_name,
    )
    expected_package = _build_package_reconciliation_record(
        package_context,
        steps=package_steps,
        created_at=package_reconciliation.record.created_at,
    )
    if package_reconciliation.record != expected_package:
        raise StateConflictError("Manager backend post-package reconciliation drifted")

    metadata_stored = ClusterMetadataStore(paths).read(
        expected_cluster_name=chain_metadata.cluster_name,
        expected_cluster_uuid=chain_metadata.cluster_uuid,
        expected_provider=chain_metadata.provider,
    )
    metadata = metadata_stored.record
    terraform_input = TerraformInputStore(paths).read(
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
        expected_provider=metadata.provider,
    )
    observation = ObservedStateStore(paths).read(
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
        expected_provider=metadata.provider,
    )
    inventory = InventoryStore(paths).read(
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
        expected_provider=metadata.provider,
    )
    trust = TrustStore(paths).read(
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
        expected_provider=metadata.provider,
    )
    readiness = TerraformApplyReadinessStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    journal = OperationJournalStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    source = load_ansible_source_bundle()
    catalog_digest = ansible_operation_catalog_digest()
    record = package_reconciliation.record
    binding = package_context.execution.record.binding
    if (
        metadata_stored.digest != record.metadata_artifact_digest
        or metadata.generation != record.metadata_generation
        or metadata.desired_spec.digest() != record.desired_spec_digest
        or observation.digest != record.observation_artifact_digest
        or observation.record.generation != record.observation_generation
        or observation.record.manifest_digest != record.observation_manifest_digest
        or inventory.digest != record.inventory_artifact_digest
        or inventory.record.generation != record.inventory_generation
        or inventory.record.inventory_digest != record.inventory_digest
        or trust.digest != record.trust_artifact_digest
        or trust.record.generation != record.trust_generation
        or trust.record.entries_digest != record.trust_entries_digest
        or readiness.artifact_digest != record.readiness_artifact_digest
        or readiness.record.record_digest != record.readiness_record_digest
        or source.version != record.ansible_source_version
        or source.digest != record.ansible_source_digest
        or catalog_digest != record.catalog_digest
        or journal.record.generation != record.journal_generation
        or journal.digest != record.journal_digest
        or journal.record.status is not record.journal_status
        or journal.record.phase is not record.journal_phase
        or terraform_input.record.input_digest
        != terraform_input.record.terraform_input.digest()
        or readiness.record.inventory_artifact_digest != inventory.digest
        or readiness.record.inventory_digest != inventory.record.inventory_digest
        or readiness.record.trust_artifact_digest != trust.digest
        or readiness.record.trust_entries_digest != trust.record.entries_digest
        or readiness.record.observation_artifact_digest != observation.digest
        or readiness.record.observation_manifest_digest
        != observation.record.manifest_digest
        or binding.target_stable_id != record.target_stable_id
    ):
        raise StateConflictError(
            "Manager backend storage planning canonical provenance drifted"
        )
    TrustStore(paths).validate_runtime(trust, inventory)
    allocation = _derive_allocation_decision(
        metadata.desired_spec,
        terraform_input,
        observation,
        inventory,
        record.target_stable_id,
    )
    prior_storage = package_context.installation_context.record.storage_decision
    if prior_storage.dedicated_volume_identified is not (
        allocation.state is DeployManagerBackendStorageAllocationState.EXACT
    ):
        raise StateConflictError(
            "Manager backend storage allocation differs from the immutable "
            "installation decision"
        )
    discovery_source = _derive_discovery_source(source)
    return _StoragePlanningContext(
        metadata,
        package_reconciliation,
        terraform_input,
        observation,
        inventory,
        trust.digest,
        trust.record.generation,
        trust.record.entries_digest,
        readiness,
        journal,
        source,
        catalog_digest,
        allocation,
        discovery_source,
    )


def _derive_allocation_decision(
    desired: ClusterSpec,
    terraform_input: StoredTerraformInput,
    observation: StoredObservedState,
    inventory: StoredInventoryRecord,
    target: str,
) -> DeployManagerBackendStorageAllocationDecision:
    """Classify one provider-bound Manager allocation without path selection."""

    provider_input = terraform_input.record.terraform_input
    oci_input = (
        provider_input if isinstance(provider_input, OciTerraformInput) else None
    )
    desired_policies = tuple(
        policy for policy in desired.storage if policy.role is HostRole.MANAGER
    )
    input_hosts = (
        tuple(
            host
            for host in oci_input.hosts
            if host.logical_id == target and host.role is HostRole.MANAGER
        )
        if oci_input is not None
        else ()
    )
    observed_hosts = tuple(
        host
        for host in observation.record.manifest.hosts
        if host.logical_id == target and host.role is HostRole.MANAGER
    )
    inventory_hosts = tuple(
        host
        for host in inventory.record.inventory.hosts
        if host.logical_id == target and host.role is HostRole.MANAGER
    )
    policy = desired_policies[0] if len(desired_policies) == 1 else None
    input_host = input_hosts[0] if len(input_hosts) == 1 else None
    observed_host = observed_hosts[0] if len(observed_hosts) == 1 else None
    inventory_host = inventory_hosts[0] if len(inventory_hosts) == 1 else None
    storage = observed_host.storage if observed_host is not None else None
    devices = storage.devices if storage is not None else ()
    device = devices[0] if len(devices) == 1 else None
    desired_digest = _digest_object(
        policy.to_object()
        if policy is not None
        else {"role": HostRole.MANAGER.value, "state": "absent"}
    )
    input_digest = _digest_object(
        _oci_storage_projection(input_host)
        if input_host is not None
        else {"role": HostRole.MANAGER.value, "state": "absent"}
    )
    observed_digest = _digest_object(
        _storage_manifest_projection(storage)
        if storage is not None
        else {"role": HostRole.MANAGER.value, "state": "absent"}
    )
    provider_identity_digest = _digest_object(
        {
            "inventory_provider": (
                inventory_host.provider_id if inventory_host is not None else None
            ),
            "logical_id": target,
            "observed_provider": (
                observed_host.provider_id if observed_host is not None else None
            ),
            "role": HostRole.MANAGER.value,
        }
    )
    guest_values = (
        {
            "expected-by-id": device.expected_by_id,
            "expected-serial": device.expected_serial,
            "expected-wwn": device.expected_wwn,
        }
        if device is not None
        else {name: None for name in _GUEST_IDENTITY_NAMES}
    )
    guest_identities = tuple(
        sorted(
            (name, _digest_object(value))
            for name, value in guest_values.items()
            if value is not None
        )
    )
    requested_path_present = bool(
        device is not None and device.requested_path is not None
    )
    provider_volume_digest = (
        _digest_object(device.provider_volume_id)
        if device is not None and device.provider_volume_id is not None
        else None
    )
    provider_attachment_digest = (
        _digest_object(device.provider_attachment_id)
        if device is not None and device.provider_attachment_id is not None
        else None
    )
    shared_with_scylla = bool(
        device is not None
        and device.provider_volume_id is not None
        and any(
            other.role is HostRole.SCYLLA
            and any(
                candidate.provider_volume_id == device.provider_volume_id
                or (
                    device.provider_attachment_id is not None
                    and candidate.provider_attachment_id
                    == device.provider_attachment_id
                )
                for candidate in other.storage.devices
            )
            for other in observation.record.manifest.hosts
        )
    )
    exact_contract = bool(
        policy is not None
        and input_host is not None
        and observed_host is not None
        and inventory_host is not None
        and observed_host.provider_id == inventory_host.provider_id
        and policy.requested_backend is StorageBackend.BLOCK_VOLUME
        and policy.layout is StorageLayout.SINGLE
        and policy.block_volume is not None
        and policy.block_volume.count == 1
        and input_host.storage.requested_backend is StorageBackend.BLOCK_VOLUME
        and input_host.storage.selected_backend is StorageBackend.BLOCK_VOLUME
        and input_host.storage.layout == StorageLayout.SINGLE.value
        and input_host.storage.block_volume == policy.block_volume
        and storage is not None
        and input_host.storage.policy_digest == storage.policy_digest
        and storage.requested_backend is StorageBackend.BLOCK_VOLUME
        and storage.selected_backend is StorageBackend.BLOCK_VOLUME
        and storage.selection_status
        in {StorageSelectionStatus.PROVISIONAL, StorageSelectionStatus.FINAL}
        and storage.expected_device_count == 1
        and storage.layout == StorageLayout.SINGLE.value
        and storage.role_allocations == ("data",)
        and device is not None
        and device.kind is StorageDeviceKind.BLOCK_VOLUME
        and device.provider_volume_id is not None
        and device.provider_attachment_id is not None
        and not device.ephemeral
        and device.size_gib == policy.block_volume.size_gib
        and storage.raw_total_gib == policy.block_volume.size_gib
        and not shared_with_scylla
    )
    ambiguous = any(
        len(items) > 1
        for items in (
            desired_policies,
            input_hosts,
            observed_hosts,
            inventory_hosts,
            devices,
        )
    )
    blockers: set[str] = set()
    if exact_contract:
        state = DeployManagerBackendStorageAllocationState.EXACT
    elif ambiguous:
        state = DeployManagerBackendStorageAllocationState.AMBIGUOUS
        blockers.add("manager-backend-dedicated-storage-ambiguous")
    elif observed_host is None or storage is None or not devices:
        state = DeployManagerBackendStorageAllocationState.ABSENT
        blockers.add("manager-backend-dedicated-storage-absent")
    else:
        state = DeployManagerBackendStorageAllocationState.FORBIDDEN
        if any(
            backend is StorageBackend.BOOT_ONLY
            for backend in _backends(policy, input_host, storage)
        ):
            blockers.add("manager-backend-root-storage-forbidden")
        if any(
            backend is StorageBackend.LOCAL_NVME
            for backend in _backends(policy, input_host, storage)
        ):
            blockers.add("manager-backend-local-nvme-forbidden")
        if shared_with_scylla:
            blockers.add("manager-backend-shared-scylla-storage-forbidden")
        if len(devices) != 1:
            blockers.add("manager-backend-arbitrary-volume-forbidden")
        if not blockers:
            blockers.add("manager-backend-storage-binding-conflict")
    allocation_identity_digest = (
        _digest_object(
            {
                "attachment": device.provider_attachment_id,
                "guest_identity_set": guest_identities,
                "manifest": observed_digest,
                "provider_host": provider_identity_digest,
                "storage_generation": storage.storage_generation,
                "target": target,
                "terraform_input": input_digest,
                "volume": device.provider_volume_id,
            }
        )
        if exact_contract and device is not None and storage is not None
        else None
    )
    values: dict[str, object] = {
        "state": state,
        "desired_backend": (
            policy.requested_backend.value if policy is not None else "absent"
        ),
        "terraform_backend": (
            input_host.storage.selected_backend.value
            if input_host is not None
            else "absent"
        ),
        "observed_backend": (
            storage.selected_backend.value if storage is not None else "absent"
        ),
        "allocation_count": len(devices),
        "expected_device_count": (
            storage.expected_device_count if storage is not None else 0
        ),
        "storage_generation": storage.storage_generation if storage is not None else 0,
        "size_gib": device.size_gib if device is not None else 0,
        "desired_policy_digest": desired_digest,
        "terraform_storage_input_digest": input_digest,
        "observed_manifest_digest": observed_digest,
        "target_provider_identity_digest": provider_identity_digest,
        "provider_volume_identity_digest": provider_volume_digest,
        "provider_attachment_identity_digest": provider_attachment_digest,
        "provider_allocation_identity_digest": allocation_identity_digest,
        "guest_identity_state": (
            DeployManagerBackendStorageGuestIdentityState.AVAILABLE
            if guest_identities
            else DeployManagerBackendStorageGuestIdentityState.UNAVAILABLE
        ),
        "guest_identity_count": len(guest_identities),
        "guest_identity_set_digest": _digest_object(list(guest_identities)),
        "requested_path_present": requested_path_present,
        "requested_path_only": requested_path_present and not guest_identities,
        "shared_with_scylla": shared_with_scylla,
        "root_fallback_policy": _ROOT_FALLBACK_POLICY,
        "local_nvme_policy": _LOCAL_NVME_POLICY,
        "shared_scylla_storage_policy": _SHARED_SCYLLA_STORAGE_POLICY,
        "capacity_policy_state": _CAPACITY_POLICY_STATE,
        "capacity_evaluation_state": _CAPACITY_EVALUATION_STATE,
        "blockers": tuple(sorted(blockers)),
        "blocker_digest": _digest_object(list(sorted(blockers))),
        "decision_digest": "",
    }
    values["decision_digest"] = _record_digest_from_values(values, "decision_digest")
    return DeployManagerBackendStorageAllocationDecision(**values)  # type: ignore[arg-type]


def _derive_discovery_source(
    source: AnsibleSourceBundle,
) -> _DiscoverySourceReference:
    """Resolve the optional future source without weakening current planning."""

    try:
        definition = get_playbook(_SOURCE_NAME)
    except AnsibleError:
        return _DiscoverySourceReference(
            DeployManagerBackendStorageDiscoverySourceState.UNAVAILABLE,
            None,
        )
    if not definition.source_available:
        return _DiscoverySourceReference(
            DeployManagerBackendStorageDiscoverySourceState.UNAVAILABLE,
            None,
        )
    if (
        definition.name != _SOURCE_NAME
        or definition.target_groups != ("manager",)
        or definition.classification is not OperationClassification.READ_ONLY
        or definition.check_mode is not CheckMode.SUPPORTED
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.serial != 1
        or not definition.any_errors_fatal
    ):
        raise StateConflictError(
            "Manager backend storage discovery source policy conflicts"
        )
    expected_path = f"playbooks/{definition.filename}"
    files = tuple(item for item in source.files if item.path == expected_path)
    if len(files) != 1:
        raise StateConflictError(
            "Manager backend storage discovery source identity conflicts"
        )
    return _DiscoverySourceReference(
        DeployManagerBackendStorageDiscoverySourceState.AVAILABLE,
        files[0].digest,
    )


def _build_context_record(
    loaded: _StoragePlanningContext,
    *,
    created_at: str,
) -> DeployManagerBackendStorageAllocationContext:
    metadata = loaded.metadata
    reconciliation = loaded.package_reconciliation.record
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_name": metadata.cluster_name,
        "operation_id": reconciliation.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "request_digest": reconciliation.request_digest,
        "journal_generation": loaded.journal.record.generation,
        "journal_digest": loaded.journal.digest,
        "journal_status": loaded.journal.record.status,
        "journal_phase": loaded.journal.record.phase,
        "package_reconciliation_artifact_digest": (
            loaded.package_reconciliation.artifact_digest
        ),
        "package_reconciliation_record_digest": reconciliation.record_digest,
        "package_reconciliation_effective_plan_digest": (
            reconciliation.effective_plan_digest
        ),
        "package_evidence_digest": reconciliation.evidence_digest,
        "metadata_generation": metadata.generation,
        "metadata_artifact_digest": reconciliation.metadata_artifact_digest,
        "desired_spec_digest": metadata.desired_spec.digest(),
        "terraform_input_generation": loaded.terraform_input.record.generation,
        "terraform_input_artifact_digest": loaded.terraform_input.digest,
        "terraform_input_digest": loaded.terraform_input.record.input_digest,
        "observation_generation": loaded.observation.record.generation,
        "observation_artifact_digest": loaded.observation.digest,
        "observation_manifest_digest": loaded.observation.record.manifest_digest,
        "inventory_generation": loaded.inventory.record.generation,
        "inventory_artifact_digest": loaded.inventory.digest,
        "inventory_digest": loaded.inventory.record.inventory_digest,
        "trust_generation": loaded.trust_generation,
        "trust_artifact_digest": loaded.trust_artifact_digest,
        "trust_entries_digest": loaded.trust_entries_digest,
        "readiness_artifact_digest": loaded.readiness.artifact_digest,
        "readiness_record_digest": loaded.readiness.record.record_digest,
        "catalog_digest": loaded.catalog_digest,
        "ansible_source_version": loaded.ansible_source.version,
        "ansible_source_digest": loaded.ansible_source.digest,
        "manager_target_id": reconciliation.target_stable_id,
        "manager_target_digest": reconciliation.target_set_digest,
        "manager_provider_identity_digest": (
            loaded.allocation.target_provider_identity_digest
        ),
        "allocation": loaded.allocation,
        "capacity_policy_state": _CAPACITY_POLICY_STATE,
        "capacity_evaluation_state": _CAPACITY_EVALUATION_STATE,
        "root_fallback_policy": _ROOT_FALLBACK_POLICY,
        "local_nvme_policy": _LOCAL_NVME_POLICY,
        "shared_scylla_storage_policy": _SHARED_SCYLLA_STORAGE_POLICY,
        "execution_state": _NOT_STARTED,
        "authorization_state": _UNAVAILABLE,
        "mutation_state": _NOT_PERFORMED,
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(values, "record_digest")
    return DeployManagerBackendStorageAllocationContext(**values)  # type: ignore[arg-type]


def _build_plan_record(
    context: StoredDeployManagerBackendStorageAllocationContext,
    *,
    source: _DiscoverySourceReference,
    created_at: str,
) -> DeployManagerBackendStorageAllocationPlan:
    record = context.record
    allocation = record.allocation
    blockers = set(allocation.blockers)
    if (
        allocation.guest_identity_state
        is DeployManagerBackendStorageGuestIdentityState.UNAVAILABLE
    ):
        blockers.add("manager-backend-storage-guest-identity-unavailable")
    if source.state is DeployManagerBackendStorageDiscoverySourceState.UNAVAILABLE:
        blockers.add("manager-backend-storage-discovery-source-unavailable")
    eligible = not blockers
    targets = (record.manager_target_id,) if eligible else ()
    status = (
        DeployManagerBackendStorageAllocationPlanStatus.ELIGIBLE
        if eligible
        else DeployManagerBackendStorageAllocationPlanStatus.BLOCKED
    )
    sorted_blockers = tuple(sorted(blockers))
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": record.cluster_uuid,
        "cluster_name": record.cluster_name,
        "operation_id": record.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "request_digest": record.request_digest,
        "journal_generation": record.journal_generation,
        "journal_digest": record.journal_digest,
        "journal_status": record.journal_status,
        "journal_phase": record.journal_phase,
        "context_artifact_digest": context.artifact_digest,
        "context_record_digest": record.record_digest,
        "package_reconciliation_artifact_digest": (
            record.package_reconciliation_artifact_digest
        ),
        "package_reconciliation_record_digest": (
            record.package_reconciliation_record_digest
        ),
        "boundary": _BOUNDARY,
        "source_contract": _SOURCE_CONTRACT,
        "source_state": source.state,
        "source_digest": source.source_digest,
        "classification": OperationClassification.READ_ONLY,
        "manager_target_id": record.manager_target_id,
        "candidate_target_count": 1,
        "candidate_target_set_digest": record.manager_target_digest,
        "discovery_target_ids": targets,
        "discovery_target_count": len(targets),
        "discovery_target_set_digest": _digest_object(list(targets)),
        "allocation_state": allocation.state,
        "allocation_decision_digest": allocation.decision_digest,
        "provider_allocation_identity_digest": (
            allocation.provider_allocation_identity_digest
        ),
        "guest_identity_state": allocation.guest_identity_state,
        "guest_identity_count": allocation.guest_identity_count,
        "guest_identity_set_digest": allocation.guest_identity_set_digest,
        "size_gib": allocation.size_gib,
        "capacity_policy_state": _CAPACITY_POLICY_STATE,
        "capacity_evaluation_state": _CAPACITY_EVALUATION_STATE,
        "status": status,
        "blockers": sorted_blockers,
        "blocker_count": len(sorted_blockers),
        "blocker_digest": _digest_object(list(sorted_blockers)),
        "authorization_state": "not-required-read-only",
        "execution_state": _NOT_STARTED,
        "evidence_state": _NOT_PERFORMED,
        "mutation_state": _NOT_PERFORMED,
        "journal_transition_state": _NOT_PERFORMED,
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "plan_digest": "",
    }
    values["plan_digest"] = _record_digest_from_values(values, "plan_digest")
    return DeployManagerBackendStorageAllocationPlan(**values)  # type: ignore[arg-type]


def _build_report(
    context: StoredDeployManagerBackendStorageAllocationContext,
    plan: StoredDeployManagerBackendStorageAllocationPlan,
    *,
    context_state: DeployManagerBackendStorageAllocationArtifactState,
    plan_state: DeployManagerBackendStorageAllocationArtifactState,
) -> DeployManagerBackendStorageAllocationPlanReport:
    planned = plan.record
    return DeployManagerBackendStorageAllocationPlanReport(
        operation_id=planned.operation_id,
        context_state=context_state,
        plan_state=plan_state,
        context_artifact_digest=context.artifact_digest,
        context_record_digest=context.record.record_digest,
        plan_artifact_digest=plan.artifact_digest,
        plan_digest=planned.plan_digest,
        allocation_state=planned.allocation_state,
        guest_identity_state=planned.guest_identity_state,
        source_state=planned.source_state,
        status=planned.status,
        candidate_target_count=planned.candidate_target_count,
        discovery_target_count=planned.discovery_target_count,
        size_gib=planned.size_gib,
        capacity_policy_state=planned.capacity_policy_state,
        capacity_evaluation_state=planned.capacity_evaluation_state,
        blocker_count=planned.blocker_count,
        blocker_digest=planned.blocker_digest,
        journal_status=planned.journal_status,
        journal_phase=planned.journal_phase,
    )


def _oci_storage_projection(host: OciHostInput | None) -> object:
    if host is None:
        return {"state": "absent"}
    storage = host.storage
    return {
        "block_volume": (
            storage.block_volume.to_object()
            if storage.block_volume is not None
            else None
        ),
        "layout": storage.layout,
        "policy_digest": storage.policy_digest,
        "requested_backend": storage.requested_backend.value,
        "selected_backend": storage.selected_backend.value,
        "selection_algorithm": storage.selection_algorithm,
    }


def _storage_manifest_projection(storage: StorageManifest | None) -> object:
    if storage is None:
        return {"state": "absent"}
    return {
        "devices": [_storage_device_projection(device) for device in storage.devices],
        "expected_device_count": storage.expected_device_count,
        "layout": storage.layout,
        "policy_digest": storage.policy_digest,
        "raw_total_gib": storage.raw_total_gib,
        "requested_backend": storage.requested_backend.value,
        "role_allocations": list(storage.role_allocations),
        "selected_backend": storage.selected_backend.value,
        "selection_status": storage.selection_status.value,
        "storage_generation": storage.storage_generation,
        "usable_total_gib": storage.usable_total_gib,
    }


def _storage_device_projection(device: StorageDevice) -> object:
    return {
        "attachment_identity_digest": (
            _digest_object(device.provider_attachment_id)
            if device.provider_attachment_id is not None
            else None
        ),
        "ephemeral": device.ephemeral,
        "guest_identity_set_digest": _digest_object(
            [
                (name, _digest_object(value))
                for name, value in (
                    ("expected-by-id", device.expected_by_id),
                    ("expected-serial", device.expected_serial),
                    ("expected-wwn", device.expected_wwn),
                )
                if value is not None
            ]
        ),
        "kind": device.kind.value,
        "requested_path_present": device.requested_path is not None,
        "size_gib": device.size_gib,
        "volume_identity_digest": (
            _digest_object(device.provider_volume_id)
            if device.provider_volume_id is not None
            else None
        ),
    }


def _backends(
    policy: object,
    input_host: OciHostInput | None,
    storage: StorageManifest | None,
) -> tuple[StorageBackend, ...]:
    values: list[StorageBackend] = []
    requested = getattr(policy, "requested_backend", None)
    if isinstance(requested, StorageBackend):
        values.append(requested)
    if input_host is not None:
        values.append(input_host.storage.selected_backend)
    if storage is not None:
        values.append(storage.selected_backend)
    return tuple(values)


def _record_digest(value: _StoredRecord, digest_field: str) -> str:
    return _record_digest_from_values(
        cast(Mapping[str, object], asdict(value)),
        digest_field,
    )


def _record_digest_from_values(
    values: Mapping[str, object],
    digest_field: str,
) -> str:
    copied = {
        name: item
        for name, item in values.items()
        if name != "schema_version" and not name.endswith("_schema_version")
    }
    copied[digest_field] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(cast(Mapping[str, object], _jsonable(copied))))


def _dataclass_object(value: _StoredRecord) -> dict[str, object]:
    return cast(dict[str, object], _jsonable(asdict(value)))


def _jsonable(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, uuid.UUID):
        return str(value)
    if is_dataclass(value):
        return _dataclass_object(cast(_StoredRecord, value))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest_fields(value: _StoredRecord) -> tuple[str, ...]:
    return tuple(
        cast(str, item)
        for name, item in asdict(value).items()
        if name.endswith("_digest") and item is not None
    )


def _require_operation_id(value: uuid.UUID) -> uuid.UUID:
    if not isinstance(value, uuid.UUID):
        raise StatePersistenceError("operation ID must be a UUID")
    return value


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "Manager backend storage allocation paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Manager backend storage allocation planning requires the matching "
            "held deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_or_later_artifacts(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    allowed: set[str],
) -> None:
    prefix = f"{operation_id}."
    fragments = (
        ".ansible-deploy-manager-backend-storage",
        ".ansible-deploy-manager-backend-file-configuration",
        ".ansible-deploy-manager-backend-schema",
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list Manager backend storage planning history"
        ) from error
    for entry in entries:
        if (
            entry.name.startswith(prefix)
            and any(fragment in entry.name for fragment in fragments)
            and entry.name not in allowed
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "Manager backend storage allocation history is ambiguous or advanced"
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
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise StatePersistenceError(f"{label} must be an array of strings")
    return tuple(value)


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _positive_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be a boolean")
    return value


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise StatePersistenceError(f"{label} must be a string or null")
    return value


def _digest_object(value: object) -> str:
    return digest_bytes(
        serialize_json(cast(Mapping[str, object], {"value": _jsonable(value)}))
    )


__all__ = [
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_CONTEXT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_DECISION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_PLAN_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_PLAN_SCHEMA_VERSION",
    "DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_CONTEXT_FILENAME_SUFFIX",
    "DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_PLAN_FILENAME_SUFFIX",
    "DeployManagerBackendStorageAllocationArtifactState",
    "DeployManagerBackendStorageAllocationContext",
    "DeployManagerBackendStorageAllocationContextStore",
    "DeployManagerBackendStorageAllocationDecision",
    "DeployManagerBackendStorageAllocationPlan",
    "DeployManagerBackendStorageAllocationPlanReport",
    "DeployManagerBackendStorageAllocationPlanStatus",
    "DeployManagerBackendStorageAllocationPlanStore",
    "DeployManagerBackendStorageAllocationState",
    "DeployManagerBackendStorageDiscoverySourceState",
    "DeployManagerBackendStorageGuestIdentityState",
    "StoredDeployManagerBackendStorageAllocationContext",
    "StoredDeployManagerBackendStorageAllocationPlan",
    "deploy_manager_backend_storage_allocation_context_id_from_filename",
    "deploy_manager_backend_storage_allocation_context_path",
    "deploy_manager_backend_storage_allocation_plan_id_from_filename",
    "deploy_manager_backend_storage_allocation_plan_path",
    "plan_deploy_manager_backend_storage_allocation",
]
