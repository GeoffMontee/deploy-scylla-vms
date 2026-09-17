"""Operation-bound inventory generation after verified Terraform apply."""

from __future__ import annotations

import os
import uuid
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.trust import (
    TRUST_SCHEMA_VERSION,
    StoredTrustRecord,
    TrustStore,
)
from scylla_vms.desired import HostRole
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.inventory import (
    ANSIBLE_INVENTORY_SCHEMA_VERSION,
    INVENTORY_SCHEMA_VERSION,
    InventoryRefreshService,
    InventoryStore,
    StoredInventoryRecord,
)
from scylla_vms.journal import (
    JOURNAL_SCHEMA_VERSION,
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    StoredOperationRecord,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import (
    OBSERVED_STATE_SCHEMA_VERSION,
    ObservedStateStore,
    StoredObservedState,
)
from scylla_vms.persistence import (
    AtomicJsonFile,
    ClusterMetadataStore,
    StoredClusterMetadata,
    digest_bytes,
    format_timestamp,
    parse_timestamp,
    parse_uuid,
    require_exact_keys,
    require_string,
    serialize_json,
    validate_digest,
)
from scylla_vms.reconciliation import ReconciliationClass
from scylla_vms.state import (
    StatePaths,
    refuse_unexpected_terraform_state,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)
from scylla_vms.terraform.apply_execution import (
    TERRAFORM_APPLY_EXECUTION_SCHEMA_VERSION,
    StoredTerraformApplyExecution,
    TerraformApplyExecutionState,
    TerraformApplyExecutionStore,
    terraform_apply_execution_path,
)
from scylla_vms.terraform.apply_verification import (
    TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION,
    StoredTerraformApplyVerification,
    TerraformApplyVerificationStatus,
    TerraformApplyVerificationStore,
    terraform_apply_verification_path,
)
from scylla_vms.terraform.inputs import (
    TERRAFORM_TFVARS_SCHEMA_VERSION,
    StoredTerraformInput,
    TerraformInputStore,
)
from scylla_vms.terraform.outputs import MAXIMUM_HOSTS
from scylla_vms.terraform.plan import (
    TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION,
    StoredTerraformPlanCheckpoint,
    TerraformPlanChangeClass,
    TerraformPlanCheckpointStore,
    TerraformPlanDriftClass,
    capture_terraform_state_identity,
)
from scylla_vms.terraform.source import (
    TERRAFORM_SOURCE_RECORD_SCHEMA_VERSION,
    StoredTerraformSource,
    TerraformSourceStore,
)

TERRAFORM_APPLY_INVENTORY_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-apply-inventory/v1"
)
TERRAFORM_APPLY_INVENTORY_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-apply-inventory-report/v1"
)
TERRAFORM_APPLY_INVENTORY_FILENAME_SUFFIX = ".terraform-apply-inventory.json"

_OPERATION = "deploy"


class TerraformApplyInventoryCompanionState(StrEnum):
    CREATED = "created"
    REUSED = "reused"


class TerraformApplyInventoryState(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"


class TerraformApplyInventoryTrustStatus(StrEnum):
    MISSING = "missing"
    CURRENT = "current"
    STALE = "stale"
    CONFLICT = "conflict"


class TerraformApplyInventoryNextStep(StrEnum):
    TRUST_ESTABLISHMENT_REQUIRED = "ssh-trust-establishment-required"
    TRUST_REVALIDATION_REQUIRED = "ssh-trust-revalidation-required"
    MACHINE_VALIDATION_REQUIRED = "machine-inventory-validation-required"
    MANUAL_RECOVERY_REQUIRED = "manual-recovery-required"


@dataclass(frozen=True, slots=True)
class TerraformApplyInventory:
    """Immutable address-free binding for one generated inventory generation."""

    generation: int
    reconciled_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    verification_generation: int
    verification_artifact_digest: str
    verification_record_digest: str
    execution_generation: int
    execution_artifact_digest: str
    execution_record_digest: str
    execution_outcome_digest: str
    checkpoint_generation: int
    checkpoint_artifact_digest: str
    checkpoint_digest: str
    metadata_generation: int
    metadata_digest: str
    desired_spec_digest: str
    tfvars_generation: int
    tfvars_digest: str
    input_digest: str
    source_generation: int
    source_digest: str
    source_version: str
    source_bundle_digest: str
    observation_generation: int
    observation_artifact_digest: str
    observation_manifest_digest: str
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    host_count: int
    role_counts: tuple[tuple[str, int], ...]
    zone_count: int
    group_count: int
    group_digest: str
    topology_digest: str
    route_counts: tuple[tuple[str, int], ...]
    route_digest: str
    trust_status: TerraformApplyInventoryTrustStatus
    next_step: TerraformApplyInventoryNextStep
    record_digest: str
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    verification_schema_version: str = TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION
    execution_schema_version: str = TERRAFORM_APPLY_EXECUTION_SCHEMA_VERSION
    checkpoint_schema_version: str = TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
    tfvars_schema_version: str = TERRAFORM_TFVARS_SCHEMA_VERSION
    source_schema_version: str = TERRAFORM_SOURCE_RECORD_SCHEMA_VERSION
    observation_schema_version: str = OBSERVED_STATE_SCHEMA_VERSION
    inventory_schema_version: str = INVENTORY_SCHEMA_VERSION
    ansible_inventory_schema_version: str = ANSIBLE_INVENTORY_SCHEMA_VERSION
    schema_version: str = TERRAFORM_APPLY_INVENTORY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != TERRAFORM_APPLY_INVENTORY_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.verification_schema_version
            != TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION
            or self.execution_schema_version != TERRAFORM_APPLY_EXECUTION_SCHEMA_VERSION
            or self.checkpoint_schema_version
            != TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
            or self.tfvars_schema_version != TERRAFORM_TFVARS_SCHEMA_VERSION
            or self.source_schema_version != TERRAFORM_SOURCE_RECORD_SCHEMA_VERSION
            or self.observation_schema_version != OBSERVED_STATE_SCHEMA_VERSION
            or self.inventory_schema_version != INVENTORY_SCHEMA_VERSION
            or self.ansible_inventory_schema_version != ANSIBLE_INVENTORY_SCHEMA_VERSION
        ):
            raise StatePersistenceError(
                "unsupported Terraform apply inventory provenance"
            )
        if (
            self.generation != 1
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
            or self.operation != _OPERATION
        ):
            raise StatePersistenceError("Terraform apply inventory identity is invalid")
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.reconciled_at)
        for value in (
            self.journal_generation,
            self.verification_generation,
            self.execution_generation,
            self.checkpoint_generation,
            self.metadata_generation,
            self.tfvars_generation,
            self.source_generation,
            self.observation_generation,
            self.inventory_generation,
            self.host_count,
            self.zone_count,
            self.group_count,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise StatePersistenceError(
                    "Terraform apply inventory count or generation is invalid"
                )
        for label, digest_value in (
            ("operation request digest", self.request_digest),
            ("journal digest", self.journal_digest),
            ("verification artifact digest", self.verification_artifact_digest),
            ("verification record digest", self.verification_record_digest),
            ("execution artifact digest", self.execution_artifact_digest),
            ("execution record digest", self.execution_record_digest),
            ("execution outcome digest", self.execution_outcome_digest),
            ("checkpoint artifact digest", self.checkpoint_artifact_digest),
            ("checkpoint digest", self.checkpoint_digest),
            ("metadata digest", self.metadata_digest),
            ("desired specification digest", self.desired_spec_digest),
            ("tfvars digest", self.tfvars_digest),
            ("Terraform input digest", self.input_digest),
            ("source digest", self.source_digest),
            ("source bundle digest", self.source_bundle_digest),
            ("observation artifact digest", self.observation_artifact_digest),
            ("observation manifest digest", self.observation_manifest_digest),
            ("inventory artifact digest", self.inventory_artifact_digest),
            ("inventory digest", self.inventory_digest),
            ("inventory group digest", self.group_digest),
            ("inventory topology digest", self.topology_digest),
            ("inventory route digest", self.route_digest),
            ("inventory reconciliation record digest", self.record_digest),
        ):
            validate_digest(digest_value, label)
        expected_roles = tuple(sorted(role.value for role in HostRole))
        if (
            tuple(role for role, _ in self.role_counts) != expected_roles
            or any(
                isinstance(count, bool) or not isinstance(count, int) or count < 0
                for _, count in self.role_counts
            )
            or sum(count for _, count in self.role_counts) != self.host_count
            or tuple(name for name, _ in self.route_counts) != ("direct", "proxy-jump")
            or any(
                isinstance(count, bool) or not isinstance(count, int) or count < 0
                for _, count in self.route_counts
            )
            or sum(count for _, count in self.route_counts) != self.host_count
            or self.host_count > MAXIMUM_HOSTS
            or self.zone_count > self.host_count
            or self.group_count > 4 + (3 * self.host_count)
            or not self.source_version
            or not isinstance(self.trust_status, TerraformApplyInventoryTrustStatus)
            or not isinstance(self.next_step, TerraformApplyInventoryNextStep)
            or self.next_step is not _next_step(self.trust_status)
        ):
            raise StatePersistenceError("Terraform apply inventory summary is invalid")
        if self.record_digest != _inventory_companion_digest(self):
            raise StatePersistenceError(
                "Terraform apply inventory record digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "ansible_inventory_schema_version": self.ansible_inventory_schema_version,
            "checkpoint_artifact_digest": self.checkpoint_artifact_digest,
            "checkpoint_digest": self.checkpoint_digest,
            "checkpoint_generation": self.checkpoint_generation,
            "checkpoint_schema_version": self.checkpoint_schema_version,
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "desired_spec_digest": self.desired_spec_digest,
            "execution_artifact_digest": self.execution_artifact_digest,
            "execution_generation": self.execution_generation,
            "execution_outcome_digest": self.execution_outcome_digest,
            "execution_record_digest": self.execution_record_digest,
            "execution_schema_version": self.execution_schema_version,
            "generation": self.generation,
            "group_count": self.group_count,
            "group_digest": self.group_digest,
            "host_count": self.host_count,
            "input_digest": self.input_digest,
            "inventory_artifact_digest": self.inventory_artifact_digest,
            "inventory_digest": self.inventory_digest,
            "inventory_generation": self.inventory_generation,
            "inventory_schema_version": self.inventory_schema_version,
            "journal_digest": self.journal_digest,
            "journal_generation": self.journal_generation,
            "journal_schema_version": self.journal_schema_version,
            "metadata_digest": self.metadata_digest,
            "metadata_generation": self.metadata_generation,
            "next_step": self.next_step.value,
            "observation_artifact_digest": self.observation_artifact_digest,
            "observation_generation": self.observation_generation,
            "observation_manifest_digest": self.observation_manifest_digest,
            "observation_schema_version": self.observation_schema_version,
            "operation": self.operation,
            "operation_id": str(self.operation_id),
            "reconciled_at": self.reconciled_at,
            "record_digest": self.record_digest,
            "request_digest": self.request_digest,
            "role_counts": [
                {"count": count, "role": role} for role, count in self.role_counts
            ],
            "route_counts": [
                {"count": count, "mode": mode} for mode, count in self.route_counts
            ],
            "route_digest": self.route_digest,
            "schema_version": self.schema_version,
            "source_bundle_digest": self.source_bundle_digest,
            "source_digest": self.source_digest,
            "source_generation": self.source_generation,
            "source_schema_version": self.source_schema_version,
            "source_version": self.source_version,
            "tfvars_digest": self.tfvars_digest,
            "tfvars_generation": self.tfvars_generation,
            "tfvars_schema_version": self.tfvars_schema_version,
            "topology_digest": self.topology_digest,
            "trust_status": self.trust_status.value,
            "verification_artifact_digest": self.verification_artifact_digest,
            "verification_generation": self.verification_generation,
            "verification_record_digest": self.verification_record_digest,
            "verification_schema_version": self.verification_schema_version,
            "zone_count": self.zone_count,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> TerraformApplyInventory:
        require_exact_keys(
            value, set(_INVENTORY_COMPANION_KEYS), "Terraform apply inventory"
        )
        try:
            trust_status = TerraformApplyInventoryTrustStatus(
                require_string(value, "trust_status")
            )
            next_step = TerraformApplyInventoryNextStep(
                require_string(value, "next_step")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "Terraform apply inventory state is invalid"
            ) from error
        return cls(
            generation=_integer(value["generation"], "inventory companion generation"),
            reconciled_at=require_string(value, "reconciled_at"),
            cluster_uuid=parse_uuid(
                require_string(value, "cluster_uuid"), "inventory cluster UUID"
            ),
            cluster_name=require_string(value, "cluster_name"),
            operation_id=parse_uuid(
                require_string(value, "operation_id"), "inventory operation ID"
            ),
            operation=require_string(value, "operation"),
            request_digest=require_string(value, "request_digest"),
            journal_generation=_integer(
                value["journal_generation"], "journal generation"
            ),
            journal_digest=require_string(value, "journal_digest"),
            verification_generation=_integer(
                value["verification_generation"], "verification generation"
            ),
            verification_artifact_digest=require_string(
                value, "verification_artifact_digest"
            ),
            verification_record_digest=require_string(
                value, "verification_record_digest"
            ),
            execution_generation=_integer(
                value["execution_generation"], "execution generation"
            ),
            execution_artifact_digest=require_string(
                value, "execution_artifact_digest"
            ),
            execution_record_digest=require_string(value, "execution_record_digest"),
            execution_outcome_digest=require_string(value, "execution_outcome_digest"),
            checkpoint_generation=_integer(
                value["checkpoint_generation"], "checkpoint generation"
            ),
            checkpoint_artifact_digest=require_string(
                value, "checkpoint_artifact_digest"
            ),
            checkpoint_digest=require_string(value, "checkpoint_digest"),
            metadata_generation=_integer(
                value["metadata_generation"], "metadata generation"
            ),
            metadata_digest=require_string(value, "metadata_digest"),
            desired_spec_digest=require_string(value, "desired_spec_digest"),
            tfvars_generation=_integer(value["tfvars_generation"], "tfvars generation"),
            tfvars_digest=require_string(value, "tfvars_digest"),
            input_digest=require_string(value, "input_digest"),
            source_generation=_integer(value["source_generation"], "source generation"),
            source_digest=require_string(value, "source_digest"),
            source_version=require_string(value, "source_version"),
            source_bundle_digest=require_string(value, "source_bundle_digest"),
            observation_generation=_integer(
                value["observation_generation"], "observation generation"
            ),
            observation_artifact_digest=require_string(
                value, "observation_artifact_digest"
            ),
            observation_manifest_digest=require_string(
                value, "observation_manifest_digest"
            ),
            inventory_generation=_integer(
                value["inventory_generation"], "inventory generation"
            ),
            inventory_artifact_digest=require_string(
                value, "inventory_artifact_digest"
            ),
            inventory_digest=require_string(value, "inventory_digest"),
            host_count=_integer(value["host_count"], "host count"),
            role_counts=_counts(value["role_counts"], "role", "inventory role count"),
            zone_count=_integer(value["zone_count"], "zone count"),
            group_count=_integer(value["group_count"], "group count"),
            group_digest=require_string(value, "group_digest"),
            topology_digest=require_string(value, "topology_digest"),
            route_counts=_counts(
                value["route_counts"], "mode", "inventory route count"
            ),
            route_digest=require_string(value, "route_digest"),
            trust_status=trust_status,
            next_step=next_step,
            record_digest=require_string(value, "record_digest"),
            journal_schema_version=require_string(value, "journal_schema_version"),
            verification_schema_version=require_string(
                value, "verification_schema_version"
            ),
            execution_schema_version=require_string(value, "execution_schema_version"),
            checkpoint_schema_version=require_string(
                value, "checkpoint_schema_version"
            ),
            tfvars_schema_version=require_string(value, "tfvars_schema_version"),
            source_schema_version=require_string(value, "source_schema_version"),
            observation_schema_version=require_string(
                value, "observation_schema_version"
            ),
            inventory_schema_version=require_string(value, "inventory_schema_version"),
            ansible_inventory_schema_version=require_string(
                value, "ansible_inventory_schema_version"
            ),
            schema_version=require_string(value, "schema_version"),
        )


_INVENTORY_COMPANION_KEYS = frozenset(TerraformApplyInventory.__dataclass_fields__)


@dataclass(frozen=True, slots=True)
class StoredTerraformApplyInventory:
    record: TerraformApplyInventory
    artifact_digest: str


class TerraformApplyInventoryStore:
    """Owner-only immutable operation inventory companion."""

    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        _require_canonical_paths(paths)
        if not isinstance(operation_id, uuid.UUID):
            raise StatePersistenceError(
                "Terraform apply inventory operation ID must be a UUID"
            )
        self._paths = paths
        self._operation_id = operation_id
        self._path = terraform_apply_inventory_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredTerraformApplyInventory:
        value, artifact_digest = self._file.read()
        record = TerraformApplyInventory.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or record.operation != _OPERATION
        ):
            raise StatePersistenceError("Terraform apply inventory identity conflicts")
        return StoredTerraformApplyInventory(record, artifact_digest)

    def write_locked(
        self,
        record: TerraformApplyInventory,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredTerraformApplyInventory:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.terraform_plans)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Terraform apply inventory operation ID conflicts"
            )
        if self._path.exists():
            current = self.read(
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if (
                expected_generation != current.record.generation
                or expected_digest is None
                or expected_digest != current.artifact_digest
            ):
                raise StatePersistenceError(
                    "Terraform apply inventory changed concurrently"
                )
            if current.record == record:
                return current
            raise StatePersistenceError("Terraform apply inventory is immutable")
        if (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
        ):
            raise StatePersistenceError(
                "initial Terraform apply inventory requires generation one"
            )
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return StoredTerraformApplyInventory(record, artifact_digest)


@dataclass(frozen=True, slots=True)
class TerraformApplyInventoryReport:
    """Strict redacted result of operation-bound inventory generation."""

    operation_id: uuid.UUID
    companion_state: TerraformApplyInventoryCompanionState
    inventory_state: TerraformApplyInventoryState
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    observation_generation: int
    observation_artifact_digest: str
    observation_manifest_digest: str
    verification_artifact_digest: str
    verification_record_digest: str
    companion_artifact_digest: str
    companion_record_digest: str
    host_count: int
    role_counts: tuple[tuple[str, int], ...]
    zone_count: int
    group_count: int
    group_digest: str
    topology_digest: str
    route_counts: tuple[tuple[str, int], ...]
    route_digest: str
    trust_status: TerraformApplyInventoryTrustStatus
    next_step: TerraformApplyInventoryNextStep
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    recovered_inventory: bool
    safe_reentry_allowed: bool
    automatic_retry_allowed: bool
    manual_recovery_required: bool
    machine_validation_state: str
    readiness_state: str
    ansible_state: str
    finalization_state: str
    inventory_schema_version: str = INVENTORY_SCHEMA_VERSION
    observation_schema_version: str = OBSERVED_STATE_SCHEMA_VERSION
    verification_schema_version: str = TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION
    companion_schema_version: str = TERRAFORM_APPLY_INVENTORY_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = TERRAFORM_APPLY_INVENTORY_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != TERRAFORM_APPLY_INVENTORY_REPORT_SCHEMA_VERSION
            or self.companion_schema_version != TERRAFORM_APPLY_INVENTORY_SCHEMA_VERSION
            or self.inventory_schema_version != INVENTORY_SCHEMA_VERSION
            or self.observation_schema_version != OBSERVED_STATE_SCHEMA_VERSION
            or self.verification_schema_version
            != TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or not isinstance(self.operation_id, uuid.UUID)
            or not isinstance(
                self.companion_state, TerraformApplyInventoryCompanionState
            )
            or not isinstance(self.inventory_state, TerraformApplyInventoryState)
            or not isinstance(self.trust_status, TerraformApplyInventoryTrustStatus)
            or self.next_step is not _next_step(self.trust_status)
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or any(
                not isinstance(value, bool)
                for value in (
                    self.recovered_inventory,
                    self.safe_reentry_allowed,
                    self.automatic_retry_allowed,
                    self.manual_recovery_required,
                )
            )
            or not self.safe_reentry_allowed
            or self.automatic_retry_allowed
            or self.manual_recovery_required
            or self.machine_validation_state != "not-performed"
            or self.readiness_state != "not-performed"
            or self.ansible_state != "not-started"
            or self.finalization_state != "not-started"
        ):
            raise StatePersistenceError("Terraform apply inventory report is invalid")
        for value in (
            self.inventory_generation,
            self.observation_generation,
            self.host_count,
            self.zone_count,
            self.group_count,
            self.journal_generation,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise StatePersistenceError(
                    "Terraform apply inventory report count is invalid"
                )
        expected_roles = tuple(sorted(role.value for role in HostRole))
        if (
            self.host_count > MAXIMUM_HOSTS
            or self.zone_count > self.host_count
            or self.group_count > 4 + (3 * self.host_count)
            or tuple(role for role, _ in self.role_counts) != expected_roles
            or any(
                isinstance(count, bool) or not isinstance(count, int) or count < 0
                for _, count in self.role_counts
            )
            or sum(count for _, count in self.role_counts) != self.host_count
            or tuple(mode for mode, _ in self.route_counts) != ("direct", "proxy-jump")
            or any(
                isinstance(count, bool) or not isinstance(count, int) or count < 0
                for _, count in self.route_counts
            )
            or sum(count for _, count in self.route_counts) != self.host_count
        ):
            raise StatePersistenceError(
                "Terraform apply inventory report summary is invalid"
            )
        for digest_value in (
            self.inventory_artifact_digest,
            self.inventory_digest,
            self.observation_artifact_digest,
            self.observation_manifest_digest,
            self.verification_artifact_digest,
            self.verification_record_digest,
            self.companion_artifact_digest,
            self.companion_record_digest,
            self.group_digest,
            self.topology_digest,
            self.route_digest,
            self.journal_digest,
        ):
            validate_digest(digest_value, "Terraform apply inventory report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "companion": {
                "artifact_digest": self.companion_artifact_digest,
                "record_digest": self.companion_record_digest,
                "schema_version": self.companion_schema_version,
                "state": self.companion_state.value,
            },
            "inventory": {
                "artifact_digest": self.inventory_artifact_digest,
                "digest": self.inventory_digest,
                "generation": self.inventory_generation,
                "schema_version": self.inventory_schema_version,
                "state": self.inventory_state.value,
            },
            "journal": {
                "digest": self.journal_digest,
                "generation": self.journal_generation,
                "phase": self.journal_phase.value,
                "schema_version": self.journal_schema_version,
                "status": self.journal_status.value,
            },
            "next_step": self.next_step.value,
            "observation": {
                "artifact_digest": self.observation_artifact_digest,
                "generation": self.observation_generation,
                "manifest_digest": self.observation_manifest_digest,
                "schema_version": self.observation_schema_version,
            },
            "operation": {"id": str(self.operation_id), "kind": _OPERATION},
            "pending": {
                "ansible": self.ansible_state,
                "finalization": self.finalization_state,
                "machine_validation": self.machine_validation_state,
                "readiness": self.readiness_state,
            },
            "recovery": {
                "manual_recovery_required": self.manual_recovery_required,
                "recovered_inventory": self.recovered_inventory,
                "safe_reentry_allowed": self.safe_reentry_allowed,
                "automatic_retry_allowed": self.automatic_retry_allowed,
            },
            "schema_version": self.schema_version,
            "summary": {
                "group_count": self.group_count,
                "group_digest": self.group_digest,
                "host_count": self.host_count,
                "role_counts": [
                    {"count": count, "role": role} for role, count in self.role_counts
                ],
                "route_counts": [
                    {"count": count, "mode": mode} for mode, count in self.route_counts
                ],
                "route_digest": self.route_digest,
                "topology_digest": self.topology_digest,
                "zone_count": self.zone_count,
            },
            "trust": {
                "schema_version": (
                    TRUST_SCHEMA_VERSION
                    if self.trust_status
                    is not TerraformApplyInventoryTrustStatus.MISSING
                    else None
                ),
                "status": self.trust_status.value,
            },
            "verification": {
                "artifact_digest": self.verification_artifact_digest,
                "record_digest": self.verification_record_digest,
                "schema_version": self.verification_schema_version,
            },
        }


@dataclass(frozen=True, slots=True)
class _InventoryContext:
    metadata: StoredClusterMetadata
    journal: StoredOperationRecord
    verification: StoredTerraformApplyVerification
    execution: StoredTerraformApplyExecution
    checkpoint: StoredTerraformPlanCheckpoint
    tfvars: StoredTerraformInput
    source: StoredTerraformSource
    observation: StoredObservedState


def generate_deploy_inventory(
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> TerraformApplyInventoryReport:
    """Generate only the inventory bound to one verified deploy apply."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "Terraform apply inventory operation ID must be a UUID"
        )
    paths = StatePaths.derive(state_root, cluster_name)
    _assert_operation_lock(lock, paths)
    _validate_initialized_layout(paths)
    _refuse_ambiguous_artifacts(paths, operation_id)
    context = _load_context(paths, operation_id)
    store = TerraformApplyInventoryStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    companion_exists = store.path.exists()

    current_inventory = _read_optional_inventory(paths, context.metadata)
    if companion_exists and current_inventory is None:
        raise StateConflictError(
            "Terraform apply inventory companion exists without inventory"
        )
    current_trust = _read_optional_trust(paths, context.metadata, current_inventory)
    clock_value = max(
        datetime.now(UTC),
        parse_timestamp(context.verification.record.verified_at),
        parse_timestamp(context.observation.record.captured_at),
        *(
            (parse_timestamp(current_inventory.record.captured_at),)
            if current_inventory is not None
            else ()
        ),
    )
    refresh = InventoryRefreshService(paths).prepare(
        context.metadata.record,
        context.observation,
        current_inventory,
        clock=lambda: clock_value,
    )
    if (
        not refresh.conflict_free
        or refresh.reconciliation.status is not ReconciliationClass.MATCH
        or refresh.candidate is None
    ):
        raise StateConflictError(
            "verified Terraform observation cannot produce an exact inventory"
        )

    candidate = refresh.candidate
    if (
        current_inventory is not None
        and not refresh.fresh
        and current_inventory.record.inventory != candidate.inventory
    ):
        raise StateConflictError(
            "existing inventory identity, membership, topology, endpoint, or route "
            "conflicts with the verified observation"
        )
    if companion_exists and not refresh.fresh:
        raise StateConflictError(
            "Terraform apply inventory companion conflicts with current inventory"
        )
    if refresh.fresh:
        if current_inventory is None:
            raise StatePersistenceError("fresh inventory state is inconsistent")
        target_record = current_inventory.record
    else:
        target_record = candidate
    _classify_trust(
        current_trust,
        context.observation,
        StoredInventoryRecord(target_record, "sha256:" + "0" * 64),
    )

    recovered_inventory = (
        not companion_exists
        and refresh.fresh
        and current_inventory is not None
        and parse_timestamp(current_inventory.record.captured_at)
        >= parse_timestamp(context.verification.record.verified_at)
    )
    if refresh.fresh:
        assert current_inventory is not None
        inventory = current_inventory
        inventory_state = TerraformApplyInventoryState.REUSED
    else:
        inventory = InventoryRefreshService(paths).write(
            refresh,
            current_inventory,
            approved=True,
            lock=lock,
        )
        inventory_state = (
            TerraformApplyInventoryState.CREATED
            if current_inventory is None
            else TerraformApplyInventoryState.UPDATED
        )

    trust_status = _classify_trust(current_trust, context.observation, inventory)
    _reload_exact_context(paths, operation_id, context, inventory)
    companion = _create_companion(
        context=context,
        inventory=inventory,
        trust_status=trust_status,
        reconciled_at=format_timestamp(
            max(clock_value, parse_timestamp(inventory.record.captured_at))
        ),
    )
    if companion_exists:
        stored = store.read(
            expected_cluster_uuid=context.metadata.record.cluster_uuid,
            expected_cluster_name=context.metadata.record.cluster_name,
        )
        _require_companion_bindings(stored.record, companion)
        companion_state = TerraformApplyInventoryCompanionState.REUSED
    else:
        stored = store.write_locked(
            companion,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        companion_state = TerraformApplyInventoryCompanionState.CREATED
    _reload_exact_context(paths, operation_id, context, inventory)
    return _report(
        stored=stored,
        context=context,
        inventory=inventory,
        inventory_state=inventory_state,
        companion_state=companion_state,
        trust_status=trust_status,
        recovered_inventory=recovered_inventory,
    )


def terraform_apply_inventory_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    """Return the sole canonical apply-inventory companion path."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "Terraform apply inventory operation ID must be a UUID"
        )
    path = (
        paths.terraform_plans
        / f"{operation_id}{TERRAFORM_APPLY_INVENTORY_FILENAME_SUFFIX}"
    )
    if path.parent != paths.terraform_plans or path.resolve(strict=False) != path:
        raise UnsafePathError("Terraform apply inventory path is not canonical")
    return path


def _load_context(paths: StatePaths, operation_id: uuid.UUID) -> _InventoryContext:
    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name=paths.cluster_root.name,
        expected_provider="oci",
    )
    journal = OperationJournalStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )
    verification_path = terraform_apply_verification_path(paths, operation_id)
    validate_state_file(verification_path, allow_missing=True)
    if not verification_path.exists():
        raise StateConflictError(
            "Terraform apply inventory requires successful apply verification"
        )
    verification = TerraformApplyVerificationStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )
    execution = TerraformApplyExecutionStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )
    checkpoint = TerraformPlanCheckpointStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_operation=_OPERATION,
    )
    tfvars = TerraformInputStore(paths).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_provider=metadata.record.provider,
    )
    source = TerraformSourceStore(paths).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )
    observation = ObservedStateStore(paths).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_provider=metadata.record.provider,
    )
    context = _InventoryContext(
        metadata,
        journal,
        verification,
        execution,
        checkpoint,
        tfvars,
        source,
        observation,
    )
    _require_context_bindings(paths, context)
    return context


def _require_context_bindings(paths: StatePaths, context: _InventoryContext) -> None:
    metadata = context.metadata
    journal = context.journal
    verified = context.verification
    verification = verified.record
    executed = context.execution
    execution = executed.record
    checkpoint = context.checkpoint
    plan = checkpoint.record
    tfvars = context.tfvars
    source = context.source
    observation = context.observation
    if (
        journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
        or journal.record.operation != _OPERATION
        or journal.record.operation_id != verification.operation_id
        or journal.record.cluster_uuid != metadata.record.cluster_uuid
        or journal.record.cluster_name != metadata.record.cluster_name
        or journal.record.request_digest != verification.request_digest
        or journal.record.generation != verification.journal_generation
        or journal.digest != verification.journal_digest
        or verification.verification_status
        is not TerraformApplyVerificationStatus.INFRASTRUCTURE_OBSERVATION_RECONCILED
        or verification.reconciliation_status is not ReconciliationClass.MATCH
        or verification.operation != _OPERATION
        or verification.cluster_uuid != metadata.record.cluster_uuid
        or verification.cluster_name != metadata.record.cluster_name
        or verification.metadata_generation != metadata.record.generation
        or verification.metadata_digest != metadata.digest
        or verification.desired_spec_digest != metadata.record.desired_spec.digest()
        or verification.tfvars_generation != tfvars.record.generation
        or verification.tfvars_digest != tfvars.digest
        or verification.input_digest != tfvars.record.input_digest
        or verification.source_generation != source.record.generation
        or verification.source_digest != source.digest
        or verification.source_version != source.record.source_version
        or verification.source_bundle_digest != source.record.bundle_digest
        or verification.observation_generation != observation.record.generation
        or verification.observation_artifact_digest != observation.digest
        or verification.observation_manifest_digest
        != observation.record.manifest_digest
        or verification.output_manifest_digest != observation.record.manifest_digest
        or capture_terraform_state_identity(paths)
        != verification.post_apply_state_identity
        or verification.execution_generation != execution.generation
        or verification.execution_artifact_digest != executed.artifact_digest
        or verification.execution_record_digest != execution.record_digest
        or verification.execution_outcome_digest != execution.outcome_digest
        or execution.execution_state
        is not TerraformApplyExecutionState.PROCESS_SUCCEEDED_VERIFICATION_PENDING
        or execution.manual_recovery_required
        or execution.automatic_retry_allowed
        or not execution.authorization_consumed
        or not execution.verification_required
        or execution.operation_id != verification.operation_id
        or execution.request_digest != verification.request_digest
        or verification.checkpoint_artifact_digest != checkpoint.digest
        or verification.checkpoint_digest != plan.checkpoint_digest
        or execution.checkpoint_artifact_digest != checkpoint.digest
        or execution.checkpoint_digest != plan.checkpoint_digest
        or plan.operation_id != verification.operation_id
        or plan.request_digest != verification.request_digest
        or plan.metadata_generation != metadata.record.generation
        or plan.metadata_digest != metadata.digest
        or plan.desired_spec_digest != metadata.record.desired_spec.digest()
        or plan.tfvars_generation != tfvars.record.generation
        or plan.tfvars_digest != tfvars.digest
        or plan.input_digest != tfvars.record.input_digest
        or plan.source_generation != source.record.generation
        or plan.source_digest != source.digest
        or plan.source_version != source.record.source_version
        or plan.source_bundle_digest != source.record.bundle_digest
        or plan.summary.change_class is TerraformPlanChangeClass.NO_CHANGES
        or plan.summary.change_class is not verification.plan_change_class
        or plan.summary.drift_class is TerraformPlanDriftClass.CONFLICT
        or plan.summary.drift_class is not verification.plan_drift_class
        or not plan.summary.complete
        or not plan.summary.applyable
        or not source.record.planning_ready
    ):
        raise StateConflictError(
            "Terraform apply inventory verification binding is stale or conflicting"
        )


def _reload_exact_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    expected: _InventoryContext,
    inventory: StoredInventoryRecord,
) -> None:
    current = _load_context(paths, operation_id)
    if current != expected:
        raise StateConflictError(
            "Terraform apply inventory inputs changed during reconciliation"
        )
    reread = InventoryStore(paths).read(
        expected_cluster_uuid=expected.metadata.record.cluster_uuid,
        expected_cluster_name=expected.metadata.record.cluster_name,
        expected_provider=expected.metadata.record.provider,
    )
    if reread != inventory:
        raise StateConflictError("generated inventory changed during reconciliation")


def _read_optional_inventory(
    paths: StatePaths, metadata: StoredClusterMetadata
) -> StoredInventoryRecord | None:
    validate_state_file(paths.ansible_inventory, allow_missing=True)
    if not paths.ansible_inventory.exists():
        return None
    return InventoryStore(paths).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_provider=metadata.record.provider,
    )


def _read_optional_trust(
    paths: StatePaths,
    metadata: StoredClusterMetadata,
    inventory: StoredInventoryRecord | None,
) -> StoredTrustRecord | None:
    validate_state_file(paths.ansible_trust, allow_missing=True)
    if not paths.ansible_trust.exists():
        return None
    if inventory is None:
        raise StateConflictError("SSH trust exists without its bound inventory")
    return TrustStore(paths).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_provider=metadata.record.provider,
    )


def _classify_trust(
    trust: StoredTrustRecord | None,
    observation: StoredObservedState,
    inventory: StoredInventoryRecord,
) -> TerraformApplyInventoryTrustStatus:
    if trust is None:
        return TerraformApplyInventoryTrustStatus.MISSING
    record = trust.record
    hosts = {host.logical_id: host for host in inventory.record.inventory.hosts}
    entries = {entry.logical_id: entry for entry in record.entries}
    if set(entries) != set(hosts):
        raise StateConflictError(
            "SSH trust membership conflicts with verified inventory"
        )
    for logical_id, host in hosts.items():
        entry = entries[logical_id]
        if (
            entry.provider_id != host.provider_id
            or entry.endpoint.address != host.ansible_host
            or entry.endpoint.port != 22
            or entry.jump_host_id != host.jump_host_id
        ):
            raise StateConflictError(
                "SSH trust identity, endpoint, or route conflicts with verified "
                "inventory"
            )
    if (
        record.observation_generation > observation.record.generation
        or record.inventory_generation > inventory.record.generation
        or (
            record.observation_generation == observation.record.generation
            and record.observation_digest != observation.record.manifest_digest
        )
        or (
            record.inventory_generation == inventory.record.generation
            and record.inventory_digest != inventory.record.inventory_digest
        )
    ):
        raise StateConflictError(
            "SSH trust provenance conflicts with verified inventory"
        )
    if record.is_fresh_for(observation.record, inventory.record):
        return TerraformApplyInventoryTrustStatus.CURRENT
    return TerraformApplyInventoryTrustStatus.STALE


def _create_companion(
    *,
    context: _InventoryContext,
    inventory: StoredInventoryRecord,
    trust_status: TerraformApplyInventoryTrustStatus,
    reconciled_at: str,
) -> TerraformApplyInventory:
    hosts = inventory.record.inventory.hosts
    role_counter = Counter(host.role.value for host in hosts)
    route_counter = Counter(host.route_mode for host in hosts)
    role_counts = tuple(
        (role.value, role_counter[role.value])
        for role in sorted(HostRole, key=lambda item: item.value)
    )
    route_counts = tuple(
        (mode, route_counter[mode]) for mode in ("direct", "proxy-jump")
    )
    groups_value = [
        {"hosts": list(group.hosts), "name": group.name}
        for group in inventory.record.inventory.groups
    ]
    topology_value = [
        {
            "datacenter": host.scylla_datacenter,
            "logical_id": host.logical_id,
            "rack": host.scylla_rack,
            "role": host.role.value,
            "zone": host.zone,
        }
        for host in hosts
    ]
    routes_value = [
        {
            "jump_host_id": host.jump_host_id,
            "logical_id": host.logical_id,
            "mode": host.route_mode,
        }
        for host in hosts
    ]
    verification = context.verification.record
    execution = context.execution.record
    checkpoint = context.checkpoint.record
    if execution.outcome_digest is None:
        raise StateConflictError(
            "Terraform apply inventory requires an exact execution outcome"
        )
    values: dict[str, object] = {
        "ansible_inventory_schema_version": (inventory.record.inventory.schema_version),
        "checkpoint_artifact_digest": context.checkpoint.digest,
        "checkpoint_digest": checkpoint.checkpoint_digest,
        "checkpoint_generation": checkpoint.generation,
        "checkpoint_schema_version": checkpoint.schema_version,
        "cluster_name": verification.cluster_name,
        "cluster_uuid": str(verification.cluster_uuid),
        "desired_spec_digest": verification.desired_spec_digest,
        "execution_artifact_digest": context.execution.artifact_digest,
        "execution_generation": execution.generation,
        "execution_outcome_digest": execution.outcome_digest,
        "execution_record_digest": execution.record_digest,
        "execution_schema_version": execution.schema_version,
        "generation": 1,
        "group_count": len(inventory.record.inventory.groups),
        "group_digest": digest_bytes(
            serialize_json({"groups": cast(object, groups_value)})
        ),
        "host_count": len(hosts),
        "input_digest": verification.input_digest,
        "inventory_artifact_digest": inventory.digest,
        "inventory_digest": inventory.record.inventory_digest,
        "inventory_generation": inventory.record.generation,
        "inventory_schema_version": inventory.record.schema_version,
        "journal_digest": context.journal.digest,
        "journal_generation": context.journal.record.generation,
        "journal_schema_version": context.journal.record.schema_version,
        "metadata_digest": context.metadata.digest,
        "metadata_generation": context.metadata.record.generation,
        "next_step": _next_step(trust_status).value,
        "observation_artifact_digest": context.observation.digest,
        "observation_generation": context.observation.record.generation,
        "observation_manifest_digest": context.observation.record.manifest_digest,
        "observation_schema_version": context.observation.record.schema_version,
        "operation": verification.operation,
        "operation_id": str(verification.operation_id),
        "reconciled_at": reconciled_at,
        "record_digest": "sha256:" + "0" * 64,
        "request_digest": verification.request_digest,
        "role_counts": [{"count": count, "role": role} for role, count in role_counts],
        "route_counts": [
            {"count": count, "mode": mode} for mode, count in route_counts
        ],
        "route_digest": digest_bytes(
            serialize_json({"routes": cast(object, routes_value)})
        ),
        "schema_version": TERRAFORM_APPLY_INVENTORY_SCHEMA_VERSION,
        "source_bundle_digest": context.source.record.bundle_digest,
        "source_digest": context.source.digest,
        "source_generation": context.source.record.generation,
        "source_schema_version": context.source.record.schema_version,
        "source_version": context.source.record.source_version,
        "tfvars_digest": context.tfvars.digest,
        "tfvars_generation": context.tfvars.record.generation,
        "tfvars_schema_version": context.tfvars.record.schema_version,
        "topology_digest": digest_bytes(
            serialize_json({"topology": cast(object, topology_value)})
        ),
        "trust_status": trust_status.value,
        "verification_artifact_digest": context.verification.artifact_digest,
        "verification_generation": verification.generation,
        "verification_record_digest": verification.record_digest,
        "verification_schema_version": verification.schema_version,
        "zone_count": len({host.zone for host in hosts}),
    }
    values["record_digest"] = _inventory_companion_digest_object(values)
    return TerraformApplyInventory.from_object(values)


def _require_companion_bindings(
    current: TerraformApplyInventory,
    expected: TerraformApplyInventory,
) -> None:
    current_value = current.to_object()
    expected_value = expected.to_object()
    for key in ("next_step", "reconciled_at", "record_digest", "trust_status"):
        current_value.pop(key)
        expected_value.pop(key)
    if current_value != expected_value:
        raise StateConflictError("Terraform apply inventory companion binding changed")


def _report(
    *,
    stored: StoredTerraformApplyInventory,
    context: _InventoryContext,
    inventory: StoredInventoryRecord,
    inventory_state: TerraformApplyInventoryState,
    companion_state: TerraformApplyInventoryCompanionState,
    trust_status: TerraformApplyInventoryTrustStatus,
    recovered_inventory: bool,
) -> TerraformApplyInventoryReport:
    record = stored.record
    return TerraformApplyInventoryReport(
        operation_id=record.operation_id,
        companion_state=companion_state,
        inventory_state=inventory_state,
        inventory_generation=inventory.record.generation,
        inventory_artifact_digest=inventory.digest,
        inventory_digest=inventory.record.inventory_digest,
        observation_generation=context.observation.record.generation,
        observation_artifact_digest=context.observation.digest,
        observation_manifest_digest=context.observation.record.manifest_digest,
        verification_artifact_digest=context.verification.artifact_digest,
        verification_record_digest=context.verification.record.record_digest,
        companion_artifact_digest=stored.artifact_digest,
        companion_record_digest=stored.record.record_digest,
        host_count=record.host_count,
        role_counts=record.role_counts,
        zone_count=record.zone_count,
        group_count=record.group_count,
        group_digest=record.group_digest,
        topology_digest=record.topology_digest,
        route_counts=record.route_counts,
        route_digest=record.route_digest,
        trust_status=trust_status,
        next_step=_next_step(trust_status),
        journal_generation=context.journal.record.generation,
        journal_digest=context.journal.digest,
        journal_status=context.journal.record.status,
        journal_phase=context.journal.record.phase,
        recovered_inventory=recovered_inventory,
        safe_reentry_allowed=True,
        automatic_retry_allowed=False,
        manual_recovery_required=False,
        machine_validation_state="not-performed",
        readiness_state="not-performed",
        ansible_state="not-started",
        finalization_state="not-started",
    )


def _next_step(
    trust_status: TerraformApplyInventoryTrustStatus,
) -> TerraformApplyInventoryNextStep:
    return {
        TerraformApplyInventoryTrustStatus.MISSING: (
            TerraformApplyInventoryNextStep.TRUST_ESTABLISHMENT_REQUIRED
        ),
        TerraformApplyInventoryTrustStatus.CURRENT: (
            TerraformApplyInventoryNextStep.MACHINE_VALIDATION_REQUIRED
        ),
        TerraformApplyInventoryTrustStatus.STALE: (
            TerraformApplyInventoryNextStep.TRUST_REVALIDATION_REQUIRED
        ),
        TerraformApplyInventoryTrustStatus.CONFLICT: (
            TerraformApplyInventoryNextStep.MANUAL_RECOVERY_REQUIRED
        ),
    }[trust_status]


def _inventory_companion_digest(record: TerraformApplyInventory) -> str:
    return _inventory_companion_digest_object(record.to_object())


def _inventory_companion_digest_object(values: Mapping[str, object]) -> str:
    copied = dict(values)
    copied["record_digest"] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(copied))


def _counts(value: object, name_key: str, label: str) -> tuple[tuple[str, int], ...]:
    if not isinstance(value, list):
        raise StatePersistenceError(f"{label} must be an array")
    result: list[tuple[str, int]] = []
    for item in value:
        if not isinstance(item, dict):
            raise StatePersistenceError(f"{label} must contain objects")
        mapped = cast(dict[str, object], item)
        require_exact_keys(mapped, {"count", name_key}, label)
        result.append(
            (
                require_string(mapped, name_key),
                _integer(mapped["count"], label),
            )
        )
    return tuple(result)


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _validate_initialized_layout(paths: StatePaths) -> None:
    _require_canonical_paths(paths)
    for directory in paths.directory_paths:
        validate_state_directory(directory)
    for file_path in (
        paths.cluster_metadata,
        paths.terraform_tfvars,
        paths.terraform_source_record,
        paths.terraform_observed,
        paths.terraform_state,
    ):
        validate_state_file(file_path)
    refuse_unexpected_terraform_state(paths, (paths.cluster_root,))


def _require_canonical_paths(paths: StatePaths) -> None:
    expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
    if (
        expected != paths
        or paths.terraform_plans.parent != paths.terraform
        or paths.ansible_inventory.parent != paths.ansible
        or paths.ansible_trust.parent != paths.ansible
    ):
        raise UnsafePathError("Terraform apply inventory paths are not canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Terraform apply inventory requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    operation_allowed = {paths.operations / f"{operation_id}.json"}
    _refuse_matching_unknown(
        paths.operations,
        operation_id,
        operation_allowed,
        "Terraform apply inventory operation history",
    )
    plan_allowed = {
        paths.terraform_plans / f"{operation_id}.tfplan",
        paths.terraform_plans / f"{operation_id}.terraform-plan.json",
        paths.terraform_plans / f"{operation_id}.terraform-apply-authorization.json",
        paths.terraform_plans / f"{operation_id}.terraform-state-safeguard.json",
        terraform_apply_execution_path(paths, operation_id),
        terraform_apply_verification_path(paths, operation_id),
        terraform_apply_inventory_path(paths, operation_id),
        paths.terraform_plans / f"{operation_id}.terraform-apply-trust.json",
    }
    _refuse_matching_unknown(
        paths.terraform_plans,
        operation_id,
        plan_allowed,
        "Terraform apply inventory plan history",
    )
    backup_allowed = {paths.terraform_backups / f"{operation_id}.terraform.tfstate"}
    _refuse_matching_unknown(
        paths.terraform_backups,
        operation_id,
        backup_allowed,
        "Terraform apply inventory backup history",
    )


def _refuse_matching_unknown(
    directory: Path,
    operation_id: uuid.UUID,
    allowed: set[Path],
    label: str,
) -> None:
    try:
        entries = tuple(directory.iterdir())
    except OSError as error:
        raise StatePersistenceError(f"cannot safely list {label}") from error
    for entry in entries:
        validate_state_file(entry)
        if str(operation_id) in entry.name and entry not in allowed:
            raise StateConflictError(f"{label} is ambiguous")


__all__ = [
    "TERRAFORM_APPLY_INVENTORY_FILENAME_SUFFIX",
    "TERRAFORM_APPLY_INVENTORY_REPORT_SCHEMA_VERSION",
    "TERRAFORM_APPLY_INVENTORY_SCHEMA_VERSION",
    "StoredTerraformApplyInventory",
    "TerraformApplyInventory",
    "TerraformApplyInventoryCompanionState",
    "TerraformApplyInventoryNextStep",
    "TerraformApplyInventoryReport",
    "TerraformApplyInventoryState",
    "TerraformApplyInventoryStore",
    "TerraformApplyInventoryTrustStatus",
    "generate_deploy_inventory",
    "terraform_apply_inventory_path",
]
