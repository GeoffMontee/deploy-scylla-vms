"""Immutable Manager-local dedicated-storage preflight planning.

This subprocess-free owner binds the exact successful Manager backend storage
discovery chain to one reviewed single-device XFS layout and one distinct
read-only preflight source.  It deliberately does not own execution,
authorization, storage mutation, or a journal transition.
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

from scylla_vms.ansible.deploy_manager_backend_storage_allocation_plan import (
    DeployManagerBackendStorageAllocationContextStore,
    DeployManagerBackendStorageAllocationPlanStore,
    DeployManagerBackendStorageAllocationState,
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
from scylla_vms.ansible.deploy_manager_backend_storage_discovery_reconciliation import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION,
    DeployManagerBackendStorageDiscoveryBoundaryStatus,
    DeployManagerBackendStorageDiscoveryReconciliationStore,
    StoredDeployManagerBackendStorageDiscoveryReconciliation,
    _load_reconciliation_context,
)
from scylla_vms.ansible.deploy_manager_backend_storage_discovery_reconciliation import (
    _build_record as _build_discovery_reconciliation_record,
)
from scylla_vms.ansible.deploy_plan import _digest_object
from scylla_vms.ansible.manager_backend_storage_discover import (
    ManagerBackendStorageDiscoveryStatus,
)
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.source import (
    ANSIBLE_SOURCE_VERSION,
    AnsibleSourceBundle,
)
from scylla_vms.desired import HostRole, StorageBackend, StorageLayout
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.journal import JOURNAL_SCHEMA_VERSION, JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.oci import OciTerraformInput
from scylla_vms.operations import OperationClassification
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

ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_POLICY_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-policy/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_CONTEXT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-context/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_PLAN_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-plan/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_PLAN_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-plan-report/v1"
)

DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_CONTEXT_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-storage-preflight-context.json"
)
DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_PLAN_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-storage-preflight-plan.json"
)

_OPERATION = "deploy"
_STAGE = "manager-backend-storage-preflight-planning"
_BOUNDARY = "manager-backend-storage-preflight"
_SOURCE_NAME = "manager-backend-storage-preflight"
_SOURCE_CONTRACT = "manager-backend-storage-preflight-v1"
_FILESYSTEM = "xfs"
_MOUNT_BOUNDARY = "fixed-scylla-data-root"
_FSTAB_POLICY = "required"
_PARTITION_POLICY = "forbidden"
_RAID_POLICY = "forbidden"
_ROOT_FALLBACK_POLICY = "forbidden"
_LOCAL_NVME_POLICY = "forbidden"
_OWNERSHIP_MARKER_POLICY = "manager-local-one-node-required"
_ROLE_MARKER = "manager-local-one-node-backend"
_SIZE_POLICY = "operator-selected-allocation-conformance"
_CAPACITY_SUFFICIENCY = "not-proven"
_WIPE_POLICY = "separate-explicit-proof-if-required"
_PREPARATION_ACTIONS = (
    "create-xfs",
    "mount-scylla-data-root",
    "write-fstab",
    "write-manager-one-node-marker",
)
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")


class DeployManagerBackendStoragePreflightArtifactState(StrEnum):
    CREATED = "created"
    REUSED = "reused"


class DeployManagerBackendStoragePreflightSourceState(StrEnum):
    AVAILABLE = "source-available"
    UNAVAILABLE = "source-unavailable"


class DeployManagerBackendStoragePreflightPlanStatus(StrEnum):
    ELIGIBLE = "eligible"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStoragePreflightPolicy:
    """Value-free approved layout bound to exact desired and discovered sizes."""

    backend: str
    layout: str
    expected_device_count: int
    filesystem: str
    mount_boundary: str
    fstab_policy: str
    partition_policy: str
    raid_policy: str
    root_fallback_policy: str
    local_nvme_policy: str
    ownership_marker_policy: str
    role_marker: str
    requested_size_gib: int
    observed_size_gib: int
    discovered_size_gib: int
    size_policy_state: str
    capacity_sufficiency_state: str
    wipe_authorization_policy: str
    preparation_actions: tuple[str, ...]
    desired_policy_digest: str
    terraform_storage_input_digest: str
    observed_manifest_digest: str
    allocation_decision_digest: str
    provider_allocation_identity_digest: str
    discovery_evidence_digest: str
    device_set_digest: str
    preparation_intent_digest: str
    blockers: tuple[str, ...]
    blocker_digest: str
    policy_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_POLICY_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_POLICY_SCHEMA_VERSION
            or self.backend != StorageBackend.BLOCK_VOLUME.value
            or self.layout != StorageLayout.SINGLE.value
            or self.expected_device_count != 1
            or self.filesystem != _FILESYSTEM
            or self.mount_boundary != _MOUNT_BOUNDARY
            or self.fstab_policy != _FSTAB_POLICY
            or self.partition_policy != _PARTITION_POLICY
            or self.raid_policy != _RAID_POLICY
            or self.root_fallback_policy != _ROOT_FALLBACK_POLICY
            or self.local_nvme_policy != _LOCAL_NVME_POLICY
            or self.ownership_marker_policy != _OWNERSHIP_MARKER_POLICY
            or self.role_marker != _ROLE_MARKER
            or min(
                self.requested_size_gib,
                self.observed_size_gib,
                self.discovered_size_gib,
            )
            < 1
            or self.size_policy_state != _SIZE_POLICY
            or self.capacity_sufficiency_state != _CAPACITY_SUFFICIENCY
            or self.wipe_authorization_policy != _WIPE_POLICY
            or self.preparation_actions != _PREPARATION_ACTIONS
            or self.blockers != tuple(sorted(set(self.blockers)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blockers)
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.policy_digest != _record_digest(self, "policy_digest")
        ):
            raise StatePersistenceError(
                "Manager backend storage preflight policy conflicts"
            )
        equality = (
            self.requested_size_gib
            == self.observed_size_gib
            == self.discovered_size_gib
        )
        if equality is bool(self.blockers):
            raise StatePersistenceError(
                "Manager backend storage size-policy classification conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(value, "Manager backend storage preflight policy digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendStoragePreflightPolicy:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend storage preflight policy",
        )
        integers = {
            "expected_device_count",
            "requested_size_gib",
            "observed_size_gib",
            "discovered_size_gib",
        }
        parsed: dict[str, object] = {}
        for name in cls.__dataclass_fields__:
            item = value[name]
            if name in integers:
                parsed[name] = _integer(item, name)
            elif name in {"preparation_actions", "blockers"}:
                parsed[name] = _string_tuple(item, name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStoragePreflightContext:
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
    discovery_reconciliation_artifact_digest: str
    discovery_reconciliation_record_digest: str
    discovery_evidence_digest: str
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
    storage_policy: DeployManagerBackendStoragePreflightPolicy
    authorization_state: str
    execution_state: str
    evidence_state: str
    mutation_state: str
    journal_transition_state: str
    public_workflow_state: str
    record_digest: str
    discovery_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_CONTEXT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_CONTEXT_SCHEMA_VERSION
            or self.discovery_reconciliation_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or _LOGICAL_ID.fullmatch(self.manager_target_id) is None
            or self.manager_target_digest != _digest_object([self.manager_target_id])
            or self.authorization_state != "not-required-read-only"
            or self.execution_state != "not-started"
            or self.evidence_state != "not-performed"
            or self.mutation_state != "not-performed"
            or self.journal_transition_state != "not-performed"
            or self.public_workflow_state != "unavailable"
            or self.record_digest != _record_digest(self, "record_digest")
        ):
            raise StatePersistenceError(
                "Manager backend storage preflight context conflicts"
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
            _positive_integer(value, "Manager backend storage preflight generation")
        for digest in _digest_fields(self):
            validate_digest(digest, "Manager backend storage preflight context digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendStoragePreflightContext:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend storage preflight context",
        )
        integers = {
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
                if name in integers:
                    parsed[name] = _integer(item, name)
                elif name in {"cluster_uuid", "operation_id"}:
                    parsed[name] = parse_uuid(require_string(value, name), name)
                elif name == "journal_status":
                    parsed[name] = JournalStatus(require_string(value, name))
                elif name == "journal_phase":
                    parsed[name] = OperationPhase(require_string(value, name))
                elif name == "storage_policy":
                    parsed[name] = (
                        DeployManagerBackendStoragePreflightPolicy.from_object(
                            _mapping(item, name)
                        )
                    )
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend storage preflight context enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStoragePreflightPlan:
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
    discovery_reconciliation_artifact_digest: str
    discovery_reconciliation_record_digest: str
    boundary: str
    source_contract: str
    source_state: DeployManagerBackendStoragePreflightSourceState
    source_digest: str | None
    classification: OperationClassification
    manager_target_id: str
    target_count: int
    target_set_digest: str
    storage_policy_digest: str
    preparation_intent_digest: str
    device_set_digest: str
    requested_size_gib: int
    observed_size_gib: int
    discovered_size_gib: int
    size_policy_state: str
    capacity_sufficiency_state: str
    status: DeployManagerBackendStoragePreflightPlanStatus
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
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_PLAN_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        eligible = (
            self.status is DeployManagerBackendStoragePreflightPlanStatus.ELIGIBLE
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_PLAN_SCHEMA_VERSION
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
            or self.target_count != 1
            or self.target_set_digest != _digest_object([self.manager_target_id])
            or min(
                self.requested_size_gib,
                self.observed_size_gib,
                self.discovered_size_gib,
            )
            < 1
            or self.size_policy_state != _SIZE_POLICY
            or self.capacity_sufficiency_state != _CAPACITY_SUFFICIENCY
            or self.blockers != tuple(sorted(set(self.blockers)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blockers)
            or self.blocker_count != len(self.blockers)
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.authorization_state != "not-required-read-only"
            or self.execution_state != "not-started"
            or self.evidence_state != "not-performed"
            or self.mutation_state != "not-performed"
            or self.journal_transition_state != "not-performed"
            or self.finalization_state != "not-started"
            or self.public_workflow_state != "unavailable"
            or self.plan_digest != _record_digest(self, "plan_digest")
        ):
            raise StatePersistenceError(
                "Manager backend storage preflight plan conflicts"
            )
        if eligible:
            valid = (
                self.source_state
                is DeployManagerBackendStoragePreflightSourceState.AVAILABLE
                and self.source_digest is not None
                and not self.blockers
            )
        else:
            valid = bool(self.blockers)
        if not valid:
            raise StatePersistenceError(
                "Manager backend storage preflight plan status conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for value in _digest_fields(self):
            validate_digest(value, "Manager backend storage preflight plan digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendStoragePreflightPlan:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend storage preflight plan",
        )
        integers = {
            "generation",
            "journal_generation",
            "target_count",
            "requested_size_gib",
            "observed_size_gib",
            "discovered_size_gib",
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
                elif name == "source_state":
                    parsed[name] = DeployManagerBackendStoragePreflightSourceState(
                        require_string(value, name)
                    )
                elif name == "classification":
                    parsed[name] = OperationClassification(require_string(value, name))
                elif name == "status":
                    parsed[name] = DeployManagerBackendStoragePreflightPlanStatus(
                        require_string(value, name)
                    )
                elif name == "source_digest":
                    parsed[name] = _optional_string(item, name)
                elif name == "blockers":
                    parsed[name] = _string_tuple(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend storage preflight plan enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendStoragePreflightContext:
    record: DeployManagerBackendStoragePreflightContext
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendStoragePreflightPlan:
    record: DeployManagerBackendStoragePreflightPlan
    artifact_digest: str


class DeployManagerBackendStoragePreflightContextStore:
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
        self._path = deploy_manager_backend_storage_preflight_context_path(
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
    ) -> StoredDeployManagerBackendStoragePreflightContext:
        value, digest = self._file.read()
        record = DeployManagerBackendStoragePreflightContext.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "Manager backend storage preflight context identity conflicts"
            )
        return StoredDeployManagerBackendStoragePreflightContext(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendStoragePreflightContext:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendStoragePreflightContext,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerBackendStoragePreflightContext,
        DeployManagerBackendStoragePreflightArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Manager backend storage preflight context operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "Manager backend storage preflight context is immutable"
                )
            return current, DeployManagerBackendStoragePreflightArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerBackendStoragePreflightContext(record, digest),
            DeployManagerBackendStoragePreflightArtifactState.CREATED,
        )


class DeployManagerBackendStoragePreflightPlanStore:
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
        self._path = deploy_manager_backend_storage_preflight_plan_path(
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
    ) -> StoredDeployManagerBackendStoragePreflightPlan:
        value, digest = self._file.read()
        record = DeployManagerBackendStoragePreflightPlan.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "Manager backend storage preflight plan identity conflicts"
            )
        return StoredDeployManagerBackendStoragePreflightPlan(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendStoragePreflightPlan:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendStoragePreflightPlan,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerBackendStoragePreflightPlan,
        DeployManagerBackendStoragePreflightArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Manager backend storage preflight plan operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "Manager backend storage preflight plan is immutable"
                )
            return current, DeployManagerBackendStoragePreflightArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerBackendStoragePreflightPlan(record, digest),
            DeployManagerBackendStoragePreflightArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStoragePreflightPlanReport:
    operation_id: uuid.UUID
    context_state: DeployManagerBackendStoragePreflightArtifactState
    plan_state: DeployManagerBackendStoragePreflightArtifactState
    context_artifact_digest: str
    context_record_digest: str
    plan_artifact_digest: str
    plan_digest: str
    source_state: DeployManagerBackendStoragePreflightSourceState
    status: DeployManagerBackendStoragePreflightPlanStatus
    target_count: int
    requested_size_gib: int
    observed_size_gib: int
    discovered_size_gib: int
    size_policy_state: str
    capacity_sufficiency_state: str
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
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_PLAN_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_PLAN_REPORT_SCHEMA_VERSION
            or self.target_count != 1
            or min(
                self.requested_size_gib,
                self.observed_size_gib,
                self.discovered_size_gib,
            )
            < 1
            or self.size_policy_state != _SIZE_POLICY
            or self.capacity_sufficiency_state != _CAPACITY_SUFFICIENCY
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
                "Manager backend storage preflight report conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(value, "Manager backend storage preflight report digest")

    def to_object(self) -> dict[str, object]:
        return {
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
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": self.journal_updated,
            },
            "operation_id": str(self.operation_id),
            "policy": {
                "capacity_sufficiency_state": self.capacity_sufficiency_state,
                "discovered_size_gib": self.discovered_size_gib,
                "observed_size_gib": self.observed_size_gib,
                "requested_size_gib": self.requested_size_gib,
                "size_policy_state": self.size_policy_state,
            },
            "preflight": {
                "source_state": self.source_state.value,
                "status": self.status.value,
                "target_count": self.target_count,
            },
            "schema_version": self.schema_version,
            "side_effects": {
                "authorization_created": self.authorization_created,
                "execution_started": self.execution_started,
                "mutation_performed": self.mutation_performed,
                "process_calls": self.process_calls,
            },
        }


@dataclass(frozen=True, slots=True)
class _SourceReference:
    state: DeployManagerBackendStoragePreflightSourceState
    digest: str | None


@dataclass(frozen=True, slots=True)
class _PlanningContext:
    current: _StoragePlanningContext
    allocation_context: StoredDeployManagerBackendStorageAllocationContext
    allocation_plan: StoredDeployManagerBackendStorageAllocationPlan
    discovery_reconciliation: StoredDeployManagerBackendStorageDiscoveryReconciliation
    source_bundle: AnsibleSourceBundle
    policy: DeployManagerBackendStoragePreflightPolicy
    source: _SourceReference


_StoredRecord = (
    DeployManagerBackendStoragePreflightPolicy
    | DeployManagerBackendStoragePreflightContext
    | DeployManagerBackendStoragePreflightPlan
    | DeployManagerBackendStoragePreflightPlanReport
)


def plan_deploy_manager_backend_storage_preflight(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployManagerBackendStoragePreflightPlanReport:
    """Persist or exactly reuse the Manager-local storage preflight plan."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    context_store = DeployManagerBackendStoragePreflightContextStore(
        paths, operation_id
    )
    plan_store = DeployManagerBackendStoragePreflightPlanStore(paths, operation_id)
    _refuse_ambiguous_or_later_artifacts(
        paths,
        operation_id,
        allowed={context_store.path.name, plan_store.path.name},
    )
    for path in (context_store.path, plan_store.path):
        validate_state_file(path, allow_missing=True)
    if plan_store.path.exists() and not context_store.path.exists():
        raise StateConflictError(
            "Manager backend storage preflight plan exists without context"
        )

    loaded = _load_planning_context(paths, operation_id, lock=lock)
    metadata = loaded.current.metadata
    existing_context = (
        context_store.read_locked(
            lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
        )
        if context_store.path.exists()
        else None
    )
    existing_plan = (
        plan_store.read_locked(
            lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
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
    plan_record = _build_plan_record(
        StoredDeployManagerBackendStoragePreflightContext(
            context_record, expected_context_digest
        ),
        source=loaded.source,
        created_at=(
            existing_plan.record.created_at if existing_plan is not None else created_at
        ),
    )

    stored_context, context_state = context_store.write_locked(
        context_record, lock=lock
    )
    if stored_context.artifact_digest != expected_context_digest:
        raise StateConflictError(
            "Manager backend storage preflight context bytes changed"
        )
    stored_plan, plan_state = plan_store.write_locked(plan_record, lock=lock)
    return _build_report(
        stored_context,
        stored_plan,
        context_state=context_state,
        plan_state=plan_state,
    )


def deploy_manager_backend_storage_preflight_context_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_CONTEXT_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "Manager backend storage preflight context path is not canonical"
        )
    return path


def deploy_manager_backend_storage_preflight_plan_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_PLAN_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "Manager backend storage preflight plan path is not canonical"
        )
    return path


def deploy_manager_backend_storage_preflight_context_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(
        name, DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_CONTEXT_FILENAME_SUFFIX
    )


def deploy_manager_backend_storage_preflight_plan_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(
        name, DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_PLAN_FILENAME_SUFFIX
    )


def _load_planning_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
) -> _PlanningContext:
    current = _load_storage_planning_context(paths, operation_id, lock=lock)
    metadata = current.metadata
    allocation_context_store = DeployManagerBackendStorageAllocationContextStore(
        paths, operation_id
    )
    allocation_plan_store = DeployManagerBackendStorageAllocationPlanStore(
        paths, operation_id
    )
    discovery_store = DeployManagerBackendStorageDiscoveryReconciliationStore(
        paths, operation_id
    )
    for path, label in (
        (allocation_context_store.path, "allocation context"),
        (allocation_plan_store.path, "allocation plan"),
        (discovery_store.path, "successful discovery reconciliation"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"Manager backend storage preflight planning requires exact {label}"
            )
    allocation_context = allocation_context_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    allocation_plan = allocation_plan_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_allocation_context = _build_allocation_context_record(
        current, created_at=allocation_context.record.created_at
    )
    expected_allocation_plan = _build_allocation_plan_record(
        allocation_context,
        source=current.source,
        created_at=allocation_plan.record.created_at,
    )
    if (
        allocation_context.record != expected_allocation_context
        or allocation_plan.record != expected_allocation_plan
    ):
        raise StateConflictError(
            "Manager backend storage allocation planning provenance drifted"
        )

    reconciliation = discovery_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    reconciliation_context = _load_reconciliation_context(
        paths, operation_id, lock=lock
    )
    expected_reconciliation = _build_discovery_reconciliation_record(
        reconciliation_context,
        created_at=reconciliation.record.created_at,
    )
    record = reconciliation.record
    if (
        record != expected_reconciliation
        or record.semantic_status is not ManagerBackendStorageDiscoveryStatus.DISCOVERED
        or record.discovery_boundary_status
        is not DeployManagerBackendStorageDiscoveryBoundaryStatus.SUCCEEDED
        or record.device_count != 1
        or record.target_stable_id != allocation_context.record.manager_target_id
        or record.allocation_decision_digest
        != allocation_context.record.allocation.decision_digest
        or record.provider_allocation_identity_digest
        != allocation_context.record.allocation.provider_allocation_identity_digest
        or record.device_set_digest
        != reconciliation_context.evidence.record.device_set_digest
    ):
        raise StateConflictError(
            "Manager backend storage preflight requires exact successful discovery"
        )
    policy = _derive_policy(current, allocation_context, reconciliation)
    source = _derive_source(current.ansible_source)
    return _PlanningContext(
        current,
        allocation_context,
        allocation_plan,
        reconciliation,
        current.ansible_source,
        policy,
        source,
    )


def _derive_policy(
    current: _StoragePlanningContext,
    allocation_context: StoredDeployManagerBackendStorageAllocationContext,
    reconciliation: StoredDeployManagerBackendStorageDiscoveryReconciliation,
) -> DeployManagerBackendStoragePreflightPolicy:
    metadata = current.metadata
    terraform_input = current.terraform_input
    observation = current.observation
    target = allocation_context.record.manager_target_id
    desired = tuple(
        item for item in metadata.desired_spec.storage if item.role is HostRole.MANAGER
    )
    provider = terraform_input.record.terraform_input
    input_hosts = (
        tuple(
            item
            for item in provider.hosts
            if item.logical_id == target and item.role is HostRole.MANAGER
        )
        if isinstance(provider, OciTerraformInput)
        else ()
    )
    observed_hosts = tuple(
        item
        for item in observation.record.manifest.hosts
        if item.logical_id == target and item.role is HostRole.MANAGER
    )
    if len(desired) != 1 or len(input_hosts) != 1 or len(observed_hosts) != 1:
        raise StateConflictError(
            "Manager backend storage preflight policy identity is ambiguous"
        )
    desired_policy = desired[0]
    input_host = input_hosts[0]
    observed_host = observed_hosts[0]
    if (
        desired_policy.requested_backend is not StorageBackend.BLOCK_VOLUME
        or desired_policy.layout is not StorageLayout.SINGLE
        or desired_policy.block_volume is None
        or desired_policy.block_volume.count != 1
        or input_host.storage.requested_backend is not StorageBackend.BLOCK_VOLUME
        or input_host.storage.selected_backend is not StorageBackend.BLOCK_VOLUME
        or input_host.storage.layout != StorageLayout.SINGLE.value
        or input_host.storage.block_volume != desired_policy.block_volume
        or observed_host.storage.requested_backend is not StorageBackend.BLOCK_VOLUME
        or observed_host.storage.selected_backend is not StorageBackend.BLOCK_VOLUME
        or observed_host.storage.layout != StorageLayout.SINGLE.value
        or observed_host.storage.expected_device_count != 1
        or len(observed_host.storage.devices) != 1
        or allocation_context.record.allocation.state
        is not DeployManagerBackendStorageAllocationState.EXACT
    ):
        raise StateConflictError(
            "Manager backend storage preflight single-device policy conflicts"
        )
    requested_size = desired_policy.block_volume.size_gib
    observed_size = observed_host.storage.devices[0].size_gib
    discovered_size = reconciliation.record.total_size_gib
    blockers: set[str] = set()
    if observed_size != requested_size:
        blockers.add("manager-backend-observed-size-policy-conflict")
    if discovered_size < requested_size:
        blockers.add("manager-backend-device-size-below-desired")
    if discovered_size != observed_size:
        blockers.add("manager-backend-device-size-manifest-conflict")
    allocation = allocation_context.record.allocation
    provider_identity = allocation.provider_allocation_identity_digest
    if provider_identity is None:
        raise StateConflictError(
            "Manager backend storage preflight allocation identity is unavailable"
        )
    sorted_blockers = tuple(sorted(blockers))
    intent = _digest_object(
        {
            "allocation": provider_identity,
            "backend": StorageBackend.BLOCK_VOLUME.value,
            "cluster_uuid": str(metadata.cluster_uuid),
            "device_set": reconciliation.record.device_set_digest,
            "filesystem": _FILESYSTEM,
            "fstab": _FSTAB_POLICY,
            "layout": StorageLayout.SINGLE.value,
            "logical_id": target,
            "mount_boundary": _MOUNT_BOUNDARY,
            "ownership_marker": _OWNERSHIP_MARKER_POLICY,
            "partition": _PARTITION_POLICY,
            "policy_digest": observed_host.storage.policy_digest,
            "raid": _RAID_POLICY,
            "role_marker": _ROLE_MARKER,
            "size_gib": requested_size,
            "storage_generation": observed_host.storage.storage_generation,
        }
    )
    values: dict[str, object] = {
        "backend": StorageBackend.BLOCK_VOLUME.value,
        "layout": StorageLayout.SINGLE.value,
        "expected_device_count": 1,
        "filesystem": _FILESYSTEM,
        "mount_boundary": _MOUNT_BOUNDARY,
        "fstab_policy": _FSTAB_POLICY,
        "partition_policy": _PARTITION_POLICY,
        "raid_policy": _RAID_POLICY,
        "root_fallback_policy": _ROOT_FALLBACK_POLICY,
        "local_nvme_policy": _LOCAL_NVME_POLICY,
        "ownership_marker_policy": _OWNERSHIP_MARKER_POLICY,
        "role_marker": _ROLE_MARKER,
        "requested_size_gib": requested_size,
        "observed_size_gib": observed_size,
        "discovered_size_gib": discovered_size,
        "size_policy_state": _SIZE_POLICY,
        "capacity_sufficiency_state": _CAPACITY_SUFFICIENCY,
        "wipe_authorization_policy": _WIPE_POLICY,
        "preparation_actions": _PREPARATION_ACTIONS,
        "desired_policy_digest": _digest_object(desired_policy.to_object()),
        "terraform_storage_input_digest": _digest_object(
            input_host.storage.to_object()
        ),
        "observed_manifest_digest": allocation.observed_manifest_digest,
        "allocation_decision_digest": allocation.decision_digest,
        "provider_allocation_identity_digest": provider_identity,
        "discovery_evidence_digest": reconciliation.record.evidence_digest,
        "device_set_digest": reconciliation.record.device_set_digest,
        "preparation_intent_digest": intent,
        "blockers": sorted_blockers,
        "blocker_digest": _digest_object(list(sorted_blockers)),
        "policy_digest": "",
    }
    values["policy_digest"] = _record_digest_from_values(values, "policy_digest")
    return DeployManagerBackendStoragePreflightPolicy(**values)  # type: ignore[arg-type]


def _derive_source(source: AnsibleSourceBundle) -> _SourceReference:
    try:
        definition = get_playbook(_SOURCE_NAME)
    except AnsibleError:
        return _SourceReference(
            DeployManagerBackendStoragePreflightSourceState.UNAVAILABLE, None
        )
    if not definition.source_available:
        return _SourceReference(
            DeployManagerBackendStoragePreflightSourceState.UNAVAILABLE, None
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
            "Manager backend storage preflight source policy conflicts"
        )
    matches = tuple(
        item for item in source.files if item.path == f"playbooks/{definition.filename}"
    )
    if len(matches) != 1:
        raise StateConflictError(
            "Manager backend storage preflight source identity conflicts"
        )
    return _SourceReference(
        DeployManagerBackendStoragePreflightSourceState.AVAILABLE,
        matches[0].digest,
    )


def _build_context_record(
    loaded: _PlanningContext, *, created_at: str
) -> DeployManagerBackendStoragePreflightContext:
    allocation = loaded.allocation_context.record
    discovery = loaded.discovery_reconciliation.record
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": allocation.cluster_uuid,
        "cluster_name": allocation.cluster_name,
        "operation_id": allocation.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "request_digest": allocation.request_digest,
        "journal_generation": allocation.journal_generation,
        "journal_digest": allocation.journal_digest,
        "journal_status": allocation.journal_status,
        "journal_phase": allocation.journal_phase,
        "allocation_context_artifact_digest": loaded.allocation_context.artifact_digest,
        "allocation_context_record_digest": allocation.record_digest,
        "allocation_plan_artifact_digest": loaded.allocation_plan.artifact_digest,
        "allocation_plan_digest": loaded.allocation_plan.record.plan_digest,
        "discovery_reconciliation_artifact_digest": (
            loaded.discovery_reconciliation.artifact_digest
        ),
        "discovery_reconciliation_record_digest": discovery.record_digest,
        "discovery_evidence_digest": discovery.evidence_digest,
        "metadata_generation": allocation.metadata_generation,
        "metadata_artifact_digest": allocation.metadata_artifact_digest,
        "desired_spec_digest": allocation.desired_spec_digest,
        "terraform_input_generation": allocation.terraform_input_generation,
        "terraform_input_artifact_digest": allocation.terraform_input_artifact_digest,
        "terraform_input_digest": allocation.terraform_input_digest,
        "observation_generation": allocation.observation_generation,
        "observation_artifact_digest": allocation.observation_artifact_digest,
        "observation_manifest_digest": allocation.observation_manifest_digest,
        "inventory_generation": allocation.inventory_generation,
        "inventory_artifact_digest": allocation.inventory_artifact_digest,
        "inventory_digest": allocation.inventory_digest,
        "trust_generation": allocation.trust_generation,
        "trust_artifact_digest": allocation.trust_artifact_digest,
        "trust_entries_digest": allocation.trust_entries_digest,
        "readiness_artifact_digest": allocation.readiness_artifact_digest,
        "readiness_record_digest": allocation.readiness_record_digest,
        "catalog_digest": allocation.catalog_digest,
        "ansible_source_version": allocation.ansible_source_version,
        "ansible_source_digest": allocation.ansible_source_digest,
        "manager_target_id": allocation.manager_target_id,
        "manager_target_digest": allocation.manager_target_digest,
        "storage_policy": loaded.policy,
        "authorization_state": "not-required-read-only",
        "execution_state": "not-started",
        "evidence_state": "not-performed",
        "mutation_state": "not-performed",
        "journal_transition_state": "not-performed",
        "public_workflow_state": "unavailable",
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(values, "record_digest")
    return DeployManagerBackendStoragePreflightContext(**values)  # type: ignore[arg-type]


def _build_plan_record(
    context: StoredDeployManagerBackendStoragePreflightContext,
    *,
    source: _SourceReference,
    created_at: str,
) -> DeployManagerBackendStoragePreflightPlan:
    record = context.record
    policy = record.storage_policy
    blockers = set(policy.blockers)
    if source.state is DeployManagerBackendStoragePreflightSourceState.UNAVAILABLE:
        blockers.add("manager-backend-storage-preflight-source-unavailable")
    sorted_blockers = tuple(sorted(blockers))
    status = (
        DeployManagerBackendStoragePreflightPlanStatus.ELIGIBLE
        if not sorted_blockers
        else DeployManagerBackendStoragePreflightPlanStatus.BLOCKED
    )
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
        "discovery_reconciliation_artifact_digest": (
            record.discovery_reconciliation_artifact_digest
        ),
        "discovery_reconciliation_record_digest": (
            record.discovery_reconciliation_record_digest
        ),
        "boundary": _BOUNDARY,
        "source_contract": _SOURCE_CONTRACT,
        "source_state": source.state,
        "source_digest": source.digest,
        "classification": OperationClassification.READ_ONLY,
        "manager_target_id": record.manager_target_id,
        "target_count": 1,
        "target_set_digest": record.manager_target_digest,
        "storage_policy_digest": policy.policy_digest,
        "preparation_intent_digest": policy.preparation_intent_digest,
        "device_set_digest": policy.device_set_digest,
        "requested_size_gib": policy.requested_size_gib,
        "observed_size_gib": policy.observed_size_gib,
        "discovered_size_gib": policy.discovered_size_gib,
        "size_policy_state": policy.size_policy_state,
        "capacity_sufficiency_state": policy.capacity_sufficiency_state,
        "status": status,
        "blockers": sorted_blockers,
        "blocker_count": len(sorted_blockers),
        "blocker_digest": _digest_object(list(sorted_blockers)),
        "authorization_state": "not-required-read-only",
        "execution_state": "not-started",
        "evidence_state": "not-performed",
        "mutation_state": "not-performed",
        "journal_transition_state": "not-performed",
        "finalization_state": "not-started",
        "public_workflow_state": "unavailable",
        "plan_digest": "",
    }
    values["plan_digest"] = _record_digest_from_values(values, "plan_digest")
    return DeployManagerBackendStoragePreflightPlan(**values)  # type: ignore[arg-type]


def _build_report(
    context: StoredDeployManagerBackendStoragePreflightContext,
    plan: StoredDeployManagerBackendStoragePreflightPlan,
    *,
    context_state: DeployManagerBackendStoragePreflightArtifactState,
    plan_state: DeployManagerBackendStoragePreflightArtifactState,
) -> DeployManagerBackendStoragePreflightPlanReport:
    record = plan.record
    return DeployManagerBackendStoragePreflightPlanReport(
        operation_id=record.operation_id,
        context_state=context_state,
        plan_state=plan_state,
        context_artifact_digest=context.artifact_digest,
        context_record_digest=context.record.record_digest,
        plan_artifact_digest=plan.artifact_digest,
        plan_digest=record.plan_digest,
        source_state=record.source_state,
        status=record.status,
        target_count=record.target_count,
        requested_size_gib=record.requested_size_gib,
        observed_size_gib=record.observed_size_gib,
        discovered_size_gib=record.discovered_size_gib,
        size_policy_state=record.size_policy_state,
        capacity_sufficiency_state=record.capacity_sufficiency_state,
        blocker_count=record.blocker_count,
        blocker_digest=record.blocker_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
    )


def _record_digest(value: _StoredRecord, digest_field: str) -> str:
    return _record_digest_from_values(
        cast(Mapping[str, object], asdict(value)), digest_field
    )


def _record_digest_from_values(values: Mapping[str, object], digest_field: str) -> str:
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
            "Manager backend storage preflight paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Manager backend storage preflight planning requires the matching "
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
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list Manager backend storage preflight history"
        ) from error
    for entry in entries:
        if (
            entry.name.startswith(prefix)
            and (
                ".ansible-deploy-manager-backend-storage-preflight" in entry.name
                or ".ansible-deploy-manager-backend-storage-prepare" in entry.name
            )
            and entry.name not in allowed
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "Manager backend storage preflight history is ambiguous or advanced"
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


def _positive_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise StatePersistenceError(f"{label} must be a string or null")
    return value


__all__ = [
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_CONTEXT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_PLAN_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_PLAN_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_POLICY_SCHEMA_VERSION",
    "DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_CONTEXT_FILENAME_SUFFIX",
    "DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_PLAN_FILENAME_SUFFIX",
    "DeployManagerBackendStoragePreflightArtifactState",
    "DeployManagerBackendStoragePreflightContext",
    "DeployManagerBackendStoragePreflightContextStore",
    "DeployManagerBackendStoragePreflightPlan",
    "DeployManagerBackendStoragePreflightPlanReport",
    "DeployManagerBackendStoragePreflightPlanStatus",
    "DeployManagerBackendStoragePreflightPlanStore",
    "DeployManagerBackendStoragePreflightPolicy",
    "DeployManagerBackendStoragePreflightSourceState",
    "StoredDeployManagerBackendStoragePreflightContext",
    "StoredDeployManagerBackendStoragePreflightPlan",
    "deploy_manager_backend_storage_preflight_context_id_from_filename",
    "deploy_manager_backend_storage_preflight_context_path",
    "deploy_manager_backend_storage_preflight_plan_id_from_filename",
    "deploy_manager_backend_storage_preflight_plan_path",
    "plan_deploy_manager_backend_storage_preflight",
]
