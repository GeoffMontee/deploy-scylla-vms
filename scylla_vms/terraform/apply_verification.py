"""Strict post-apply Terraform state verification and observation reconciliation."""

from __future__ import annotations

import os
import uuid
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.desired import HostRole, NetworkMode, StorageBackend
from scylla_vms.errors import (
    StateConflictError,
    StatePersistenceError,
    ToolExecutionError,
    UnsafePathError,
)
from scylla_vms.journal import (
    JOURNAL_SCHEMA_VERSION,
    CheckpointEvidence,
    EvidenceResult,
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    StoredOperationRecord,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import (
    OBSERVED_STATE_SCHEMA_VERSION,
    ObservedStateRecord,
    ObservedStateStore,
    StoredObservedState,
)
from scylla_vms.oci import OciTerraformInput
from scylla_vms.persistence import (
    AtomicJsonFile,
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
from scylla_vms.process import ProcessResult, validate_executable
from scylla_vms.reconciliation import (
    ReconciliationClass,
    ReconciliationReport,
    reconcile_desired_observed,
)
from scylla_vms.state import (
    StatePaths,
    refuse_unexpected_terraform_state,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)
from scylla_vms.terraform.apply_execution import (
    _APPLY_VERIFY_BASELINE_ABSENT_SUMMARY_CODE,
    _APPLY_VERIFY_BASELINE_PRESENT_SUMMARY_PREFIX,
    TERRAFORM_APPLY_EXECUTION_SCHEMA_VERSION,
    StoredTerraformApplyExecution,
    TerraformApplyExecution,
    TerraformApplyExecutionState,
    TerraformApplyExecutionStore,
    _command_digest,
    _create_prepared_record,
    _ExecutionContext,
    _load_context,
    _require_static_execution_binding,
    _validate_toolchain,
    terraform_apply_execution_path,
)
from scylla_vms.terraform.commands import TerraformCommandBuilder
from scylla_vms.terraform.outputs import (
    HOST_MANIFEST_SCHEMA_VERSION,
    TERRAFORM_OUTPUT_SCHEMA_VERSION,
    TerraformHostManifest,
    TerraformImageSelection,
    TerraformNetworkEvidence,
    TerraformOutputBundle,
    parse_terraform_output_bundle,
)
from scylla_vms.terraform.plan import (
    TERRAFORM_PLAN_BACKEND_KIND,
    TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION,
    TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION,
    TerraformPlanChangeClass,
    TerraformPlanDriftClass,
    TerraformStateIdentity,
    TerraformStatePresence,
)
from scylla_vms.terraform.service import ProcessRunnerProtocol
from scylla_vms.terraform.state_safeguard import (
    TERRAFORM_STATE_SAFEGUARD_SCHEMA_VERSION,
    _read_owner_file,
    _StateSnapshot,
)
from scylla_vms.terraform.toolchain import TerraformToolchain

TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-apply-verification/v1"
)
TERRAFORM_APPLY_VERIFICATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-apply-verification-report/v1"
)
TERRAFORM_APPLY_VERIFICATION_FILENAME_SUFFIX = ".terraform-apply-verification.json"

_OPERATION = "deploy"
_MAXIMUM_STATE_BYTES = 64 * 1024 * 1024
_STATE_FORMAT_VERSION = 4
_ABSENT_OBSERVATION_DIGEST = digest_bytes(b"terraform-observation-absent/v1")


class TerraformStateProgression(StrEnum):
    INITIALIZED = "initialized"
    ADVANCED = "advanced"


class TerraformObservationWriteState(StrEnum):
    INITIAL = "initial"
    UPDATED = "updated"


class TerraformApplyVerificationCompanionState(StrEnum):
    CREATED = "created"
    RECOVERED_OBSERVATION = "recovered-observation"
    REUSED = "reused"


class TerraformApplyVerificationStatus(StrEnum):
    INFRASTRUCTURE_OBSERVATION_RECONCILED = "infrastructure-observation-reconciled"


@dataclass(frozen=True, slots=True)
class TerraformApplyVerification:
    """Immutable address-free proof of post-apply Terraform reconciliation."""

    generation: int
    verified_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    request_digest: str
    execution_generation: int
    execution_artifact_digest: str
    execution_record_digest: str
    execution_outcome_digest: str
    journal_generation: int
    journal_digest: str
    checkpoint_artifact_digest: str
    checkpoint_digest: str
    review_digest: str
    composition_digest: str
    authorization_artifact_digest: str
    authorization_digest: str
    safeguard_artifact_digest: str
    safeguard_digest: str
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
    backend_kind: str
    backend_digest: str
    terraform_version: str
    plan_format_version: str
    toolchain_digest: str
    plan_change_class: TerraformPlanChangeClass
    plan_drift_class: TerraformPlanDriftClass
    pre_apply_state_identity: TerraformStateIdentity
    pre_apply_state_identity_digest: str
    post_apply_state_identity: TerraformStateIdentity
    post_apply_state_identity_digest: str
    state_progression: TerraformStateProgression
    output_command_digest: str
    output_manifest_digest: str
    observation_generation: int
    observation_artifact_digest: str
    observation_manifest_digest: str
    observation_write_state: TerraformObservationWriteState
    reconciliation_status: ReconciliationClass
    desired_host_count: int
    observed_host_count: int
    role_counts: tuple[tuple[str, int], ...]
    verification_status: TerraformApplyVerificationStatus
    record_digest: str
    execution_schema_version: str = TERRAFORM_APPLY_EXECUTION_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    checkpoint_schema_version: str = TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
    review_schema_version: str = TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
    safeguard_schema_version: str = TERRAFORM_STATE_SAFEGUARD_SCHEMA_VERSION
    output_schema_version: str = TERRAFORM_OUTPUT_SCHEMA_VERSION
    manifest_schema_version: str = HOST_MANIFEST_SCHEMA_VERSION
    observation_schema_version: str = OBSERVED_STATE_SCHEMA_VERSION
    schema_version: str = TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION
            or self.execution_schema_version != TERRAFORM_APPLY_EXECUTION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.checkpoint_schema_version
            != TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
            or self.review_schema_version != TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
            or self.safeguard_schema_version != TERRAFORM_STATE_SAFEGUARD_SCHEMA_VERSION
            or self.output_schema_version != TERRAFORM_OUTPUT_SCHEMA_VERSION
            or self.manifest_schema_version != HOST_MANIFEST_SCHEMA_VERSION
            or self.observation_schema_version != OBSERVED_STATE_SCHEMA_VERSION
        ):
            raise StatePersistenceError(
                "unsupported Terraform apply verification provenance"
            )
        if (
            self.generation != 1
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
            or self.operation != _OPERATION
        ):
            raise StatePersistenceError(
                "Terraform apply verification identity is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.verified_at)
        for generation_value in (
            self.execution_generation,
            self.journal_generation,
            self.metadata_generation,
            self.tfvars_generation,
            self.source_generation,
            self.observation_generation,
        ):
            if (
                isinstance(generation_value, bool)
                or not isinstance(generation_value, int)
                or generation_value < 1
            ):
                raise StatePersistenceError(
                    "Terraform apply verification generation is invalid"
                )
        if (
            self.execution_generation != 3
            or self.journal_generation < 4
            or self.backend_kind != TERRAFORM_PLAN_BACKEND_KIND
            or not isinstance(self.plan_change_class, TerraformPlanChangeClass)
            or self.plan_change_class is TerraformPlanChangeClass.NO_CHANGES
            or not isinstance(self.plan_drift_class, TerraformPlanDriftClass)
            or self.plan_drift_class is TerraformPlanDriftClass.CONFLICT
            or not isinstance(self.state_progression, TerraformStateProgression)
            or not isinstance(
                self.observation_write_state, TerraformObservationWriteState
            )
            or not isinstance(self.reconciliation_status, ReconciliationClass)
            or self.reconciliation_status is not ReconciliationClass.MATCH
            or not isinstance(
                self.verification_status, TerraformApplyVerificationStatus
            )
        ):
            raise StatePersistenceError("Terraform apply verification state is invalid")
        for label, digest in (
            ("operation request digest", self.request_digest),
            ("execution artifact digest", self.execution_artifact_digest),
            ("execution record digest", self.execution_record_digest),
            ("execution outcome digest", self.execution_outcome_digest),
            ("journal digest", self.journal_digest),
            ("checkpoint artifact digest", self.checkpoint_artifact_digest),
            ("checkpoint digest", self.checkpoint_digest),
            ("review digest", self.review_digest),
            ("composition digest", self.composition_digest),
            ("authorization artifact digest", self.authorization_artifact_digest),
            ("authorization digest", self.authorization_digest),
            ("safeguard artifact digest", self.safeguard_artifact_digest),
            ("safeguard digest", self.safeguard_digest),
            ("metadata digest", self.metadata_digest),
            ("desired specification digest", self.desired_spec_digest),
            ("tfvars digest", self.tfvars_digest),
            ("Terraform input digest", self.input_digest),
            ("source digest", self.source_digest),
            ("source bundle digest", self.source_bundle_digest),
            ("backend digest", self.backend_digest),
            ("toolchain digest", self.toolchain_digest),
            ("pre-apply state identity digest", self.pre_apply_state_identity_digest),
            (
                "post-apply state identity digest",
                self.post_apply_state_identity_digest,
            ),
            ("output command digest", self.output_command_digest),
            ("output manifest digest", self.output_manifest_digest),
            ("observation artifact digest", self.observation_artifact_digest),
            ("observation manifest digest", self.observation_manifest_digest),
            ("verification record digest", self.record_digest),
        ):
            validate_digest(digest, label)
        if (
            self.pre_apply_state_identity_digest
            != _state_identity_digest(self.pre_apply_state_identity)
            or self.post_apply_state_identity_digest
            != _state_identity_digest(self.post_apply_state_identity)
            or self.post_apply_state_identity.presence
            is not TerraformStatePresence.PRESENT
            or self.output_manifest_digest != self.observation_manifest_digest
            or (
                self.observation_write_state is TerraformObservationWriteState.INITIAL
                and self.observation_generation != 1
            )
            or (
                self.observation_write_state is TerraformObservationWriteState.UPDATED
                and self.observation_generation < 2
            )
        ):
            raise StatePersistenceError(
                "Terraform apply verification derived binding conflicts"
            )
        if (
            isinstance(self.desired_host_count, bool)
            or not isinstance(self.desired_host_count, int)
            or self.desired_host_count < 1
            or isinstance(self.observed_host_count, bool)
            or not isinstance(self.observed_host_count, int)
            or self.observed_host_count != self.desired_host_count
            or not isinstance(self.role_counts, tuple)
            or tuple(name for name, _ in self.role_counts)
            != tuple(sorted(role.value for role in HostRole))
            or any(
                isinstance(count, bool) or not isinstance(count, int) or count < 0
                for _, count in self.role_counts
            )
            or sum(count for _, count in self.role_counts) != self.observed_host_count
        ):
            raise StatePersistenceError(
                "Terraform apply verification reconciliation counts are invalid"
            )
        if self.record_digest != _verification_digest(self):
            raise StatePersistenceError(
                "Terraform apply verification record digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "authorization_artifact_digest": self.authorization_artifact_digest,
            "authorization_digest": self.authorization_digest,
            "backend_digest": self.backend_digest,
            "backend_kind": self.backend_kind,
            "checkpoint_artifact_digest": self.checkpoint_artifact_digest,
            "checkpoint_digest": self.checkpoint_digest,
            "checkpoint_schema_version": self.checkpoint_schema_version,
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "composition_digest": self.composition_digest,
            "desired_host_count": self.desired_host_count,
            "desired_spec_digest": self.desired_spec_digest,
            "execution_artifact_digest": self.execution_artifact_digest,
            "execution_generation": self.execution_generation,
            "execution_outcome_digest": self.execution_outcome_digest,
            "execution_record_digest": self.execution_record_digest,
            "execution_schema_version": self.execution_schema_version,
            "generation": self.generation,
            "input_digest": self.input_digest,
            "journal_digest": self.journal_digest,
            "journal_generation": self.journal_generation,
            "journal_schema_version": self.journal_schema_version,
            "manifest_schema_version": self.manifest_schema_version,
            "metadata_digest": self.metadata_digest,
            "metadata_generation": self.metadata_generation,
            "observed_host_count": self.observed_host_count,
            "observation_artifact_digest": self.observation_artifact_digest,
            "observation_generation": self.observation_generation,
            "observation_manifest_digest": self.observation_manifest_digest,
            "observation_schema_version": self.observation_schema_version,
            "observation_write_state": self.observation_write_state.value,
            "operation": self.operation,
            "operation_id": str(self.operation_id),
            "output_command_digest": self.output_command_digest,
            "output_manifest_digest": self.output_manifest_digest,
            "output_schema_version": self.output_schema_version,
            "plan_change_class": self.plan_change_class.value,
            "plan_drift_class": self.plan_drift_class.value,
            "plan_format_version": self.plan_format_version,
            "post_apply_state_identity": self.post_apply_state_identity.to_object(),
            "post_apply_state_identity_digest": self.post_apply_state_identity_digest,
            "pre_apply_state_identity": self.pre_apply_state_identity.to_object(),
            "pre_apply_state_identity_digest": self.pre_apply_state_identity_digest,
            "reconciliation_status": self.reconciliation_status.value,
            "record_digest": self.record_digest,
            "request_digest": self.request_digest,
            "review_digest": self.review_digest,
            "review_schema_version": self.review_schema_version,
            "role_counts": [
                {"count": count, "role": role} for role, count in self.role_counts
            ],
            "safeguard_artifact_digest": self.safeguard_artifact_digest,
            "safeguard_digest": self.safeguard_digest,
            "safeguard_schema_version": self.safeguard_schema_version,
            "schema_version": self.schema_version,
            "source_bundle_digest": self.source_bundle_digest,
            "source_digest": self.source_digest,
            "source_generation": self.source_generation,
            "source_version": self.source_version,
            "state_progression": self.state_progression.value,
            "terraform_version": self.terraform_version,
            "tfvars_digest": self.tfvars_digest,
            "tfvars_generation": self.tfvars_generation,
            "toolchain_digest": self.toolchain_digest,
            "verification_status": self.verification_status.value,
            "verified_at": self.verified_at,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> TerraformApplyVerification:
        require_exact_keys(
            value, set(_VERIFICATION_KEYS), "Terraform apply verification"
        )
        pre_state = value["pre_apply_state_identity"]
        post_state = value["post_apply_state_identity"]
        role_counts_value = value["role_counts"]
        if (
            not isinstance(pre_state, dict)
            or not isinstance(post_state, dict)
            or not isinstance(role_counts_value, list)
        ):
            raise StatePersistenceError(
                "Terraform apply verification structured field is invalid"
            )
        role_counts: list[tuple[str, int]] = []
        for item in role_counts_value:
            if not isinstance(item, dict):
                raise StatePersistenceError(
                    "Terraform apply verification role count is invalid"
                )
            require_exact_keys(item, {"count", "role"}, "verification role count")
            role_counts.append(
                (
                    require_string(item, "role"),
                    _integer(item["count"], "verification role count"),
                )
            )
        try:
            change_class = TerraformPlanChangeClass(
                require_string(value, "plan_change_class")
            )
            drift_class = TerraformPlanDriftClass(
                require_string(value, "plan_drift_class")
            )
            progression = TerraformStateProgression(
                require_string(value, "state_progression")
            )
            write_state = TerraformObservationWriteState(
                require_string(value, "observation_write_state")
            )
            reconciliation = ReconciliationClass(
                require_string(value, "reconciliation_status")
            )
            verification_status = TerraformApplyVerificationStatus(
                require_string(value, "verification_status")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "Terraform apply verification enum is invalid"
            ) from error
        return cls(
            generation=_integer(value["generation"], "verification generation"),
            verified_at=require_string(value, "verified_at"),
            cluster_uuid=parse_uuid(
                require_string(value, "cluster_uuid"), "verification cluster UUID"
            ),
            cluster_name=require_string(value, "cluster_name"),
            operation_id=parse_uuid(
                require_string(value, "operation_id"), "verification operation ID"
            ),
            operation=require_string(value, "operation"),
            request_digest=require_string(value, "request_digest"),
            execution_generation=_integer(
                value["execution_generation"], "execution generation"
            ),
            execution_artifact_digest=require_string(
                value, "execution_artifact_digest"
            ),
            execution_record_digest=require_string(value, "execution_record_digest"),
            execution_outcome_digest=require_string(value, "execution_outcome_digest"),
            journal_generation=_integer(
                value["journal_generation"], "journal generation"
            ),
            journal_digest=require_string(value, "journal_digest"),
            checkpoint_artifact_digest=require_string(
                value, "checkpoint_artifact_digest"
            ),
            checkpoint_digest=require_string(value, "checkpoint_digest"),
            review_digest=require_string(value, "review_digest"),
            composition_digest=require_string(value, "composition_digest"),
            authorization_artifact_digest=require_string(
                value, "authorization_artifact_digest"
            ),
            authorization_digest=require_string(value, "authorization_digest"),
            safeguard_artifact_digest=require_string(
                value, "safeguard_artifact_digest"
            ),
            safeguard_digest=require_string(value, "safeguard_digest"),
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
            backend_kind=require_string(value, "backend_kind"),
            backend_digest=require_string(value, "backend_digest"),
            terraform_version=require_string(value, "terraform_version"),
            plan_format_version=require_string(value, "plan_format_version"),
            toolchain_digest=require_string(value, "toolchain_digest"),
            plan_change_class=change_class,
            plan_drift_class=drift_class,
            pre_apply_state_identity=TerraformStateIdentity.from_object(
                cast(dict[str, object], pre_state)
            ),
            pre_apply_state_identity_digest=require_string(
                value, "pre_apply_state_identity_digest"
            ),
            post_apply_state_identity=TerraformStateIdentity.from_object(
                cast(dict[str, object], post_state)
            ),
            post_apply_state_identity_digest=require_string(
                value, "post_apply_state_identity_digest"
            ),
            state_progression=progression,
            output_command_digest=require_string(value, "output_command_digest"),
            output_manifest_digest=require_string(value, "output_manifest_digest"),
            observation_generation=_integer(
                value["observation_generation"], "observation generation"
            ),
            observation_artifact_digest=require_string(
                value, "observation_artifact_digest"
            ),
            observation_manifest_digest=require_string(
                value, "observation_manifest_digest"
            ),
            observation_write_state=write_state,
            reconciliation_status=reconciliation,
            desired_host_count=_integer(
                value["desired_host_count"], "desired host count"
            ),
            observed_host_count=_integer(
                value["observed_host_count"], "observed host count"
            ),
            role_counts=tuple(role_counts),
            verification_status=verification_status,
            record_digest=require_string(value, "record_digest"),
            execution_schema_version=require_string(value, "execution_schema_version"),
            journal_schema_version=require_string(value, "journal_schema_version"),
            checkpoint_schema_version=require_string(
                value, "checkpoint_schema_version"
            ),
            review_schema_version=require_string(value, "review_schema_version"),
            safeguard_schema_version=require_string(value, "safeguard_schema_version"),
            output_schema_version=require_string(value, "output_schema_version"),
            manifest_schema_version=require_string(value, "manifest_schema_version"),
            observation_schema_version=require_string(
                value, "observation_schema_version"
            ),
            schema_version=require_string(value, "schema_version"),
        )


_VERIFICATION_KEYS = frozenset(
    {
        "authorization_artifact_digest",
        "authorization_digest",
        "backend_digest",
        "backend_kind",
        "checkpoint_artifact_digest",
        "checkpoint_digest",
        "checkpoint_schema_version",
        "cluster_name",
        "cluster_uuid",
        "composition_digest",
        "desired_host_count",
        "desired_spec_digest",
        "execution_artifact_digest",
        "execution_generation",
        "execution_outcome_digest",
        "execution_record_digest",
        "execution_schema_version",
        "generation",
        "input_digest",
        "journal_digest",
        "journal_generation",
        "journal_schema_version",
        "manifest_schema_version",
        "metadata_digest",
        "metadata_generation",
        "observed_host_count",
        "observation_artifact_digest",
        "observation_generation",
        "observation_manifest_digest",
        "observation_schema_version",
        "observation_write_state",
        "operation",
        "operation_id",
        "output_command_digest",
        "output_manifest_digest",
        "output_schema_version",
        "plan_change_class",
        "plan_drift_class",
        "plan_format_version",
        "post_apply_state_identity",
        "post_apply_state_identity_digest",
        "pre_apply_state_identity",
        "pre_apply_state_identity_digest",
        "reconciliation_status",
        "record_digest",
        "request_digest",
        "review_digest",
        "review_schema_version",
        "role_counts",
        "safeguard_artifact_digest",
        "safeguard_digest",
        "safeguard_schema_version",
        "schema_version",
        "source_bundle_digest",
        "source_digest",
        "source_generation",
        "source_version",
        "state_progression",
        "terraform_version",
        "tfvars_digest",
        "tfvars_generation",
        "toolchain_digest",
        "verification_status",
        "verified_at",
    }
)


@dataclass(frozen=True, slots=True)
class StoredTerraformApplyVerification:
    record: TerraformApplyVerification
    artifact_digest: str


class TerraformApplyVerificationStore:
    """Owner-only immutable verification companion."""

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
                "Terraform apply verification operation ID must be a UUID"
            )
        self._paths = paths
        self._operation_id = operation_id
        self._path = terraform_apply_verification_path(paths, operation_id)
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
    ) -> StoredTerraformApplyVerification:
        value, artifact_digest = self._file.read()
        record = TerraformApplyVerification.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or record.operation != _OPERATION
        ):
            raise StatePersistenceError(
                "Terraform apply verification identity conflicts"
            )
        return StoredTerraformApplyVerification(record, artifact_digest)

    def write_locked(
        self,
        record: TerraformApplyVerification,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredTerraformApplyVerification:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.terraform_plans)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Terraform apply verification operation ID conflicts"
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
                    "Terraform apply verification changed concurrently"
                )
            if current.record == record:
                return current
            raise StatePersistenceError("Terraform apply verification is immutable")
        if (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
        ):
            raise StatePersistenceError(
                "initial Terraform apply verification requires generation one"
            )
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return StoredTerraformApplyVerification(record, artifact_digest)


@dataclass(frozen=True, slots=True)
class TerraformApplyVerificationReport:
    """Strict redacted result of Terraform-only post-apply verification."""

    operation_id: uuid.UUID
    companion_state: TerraformApplyVerificationCompanionState
    verification_status: TerraformApplyVerificationStatus
    state_progression: TerraformStateProgression
    pre_apply_state_identity: TerraformStateIdentity
    post_apply_state_identity: TerraformStateIdentity
    observation_write_state: TerraformObservationWriteState
    observation_generation: int
    observation_artifact_digest: str
    observation_manifest_digest: str
    reconciliation_status: ReconciliationClass
    desired_host_count: int
    observed_host_count: int
    role_counts: tuple[tuple[str, int], ...]
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    execution_artifact_digest: str
    execution_record_digest: str
    verification_artifact_digest: str
    verification_record_digest: str
    output_command_digest: str
    runner_invoked: bool
    recovered_observation: bool
    output_retry_allowed: bool
    automatic_apply_retry_allowed: bool
    manual_review_required: bool
    inventory_state: str
    trust_state: str
    ansible_state: str
    finalization_state: str
    execution_schema_version: str = TERRAFORM_APPLY_EXECUTION_SCHEMA_VERSION
    observation_schema_version: str = OBSERVED_STATE_SCHEMA_VERSION
    output_schema_version: str = TERRAFORM_OUTPUT_SCHEMA_VERSION
    manifest_schema_version: str = HOST_MANIFEST_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    verification_schema_version: str = TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION
    schema_version: str = TERRAFORM_APPLY_VERIFICATION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != TERRAFORM_APPLY_VERIFICATION_REPORT_SCHEMA_VERSION
            or self.verification_schema_version
            != TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION
            or self.execution_schema_version != TERRAFORM_APPLY_EXECUTION_SCHEMA_VERSION
            or self.observation_schema_version != OBSERVED_STATE_SCHEMA_VERSION
            or self.output_schema_version != TERRAFORM_OUTPUT_SCHEMA_VERSION
            or self.manifest_schema_version != HOST_MANIFEST_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or not isinstance(self.operation_id, uuid.UUID)
            or not isinstance(
                self.companion_state, TerraformApplyVerificationCompanionState
            )
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.reconciliation_status is not ReconciliationClass.MATCH
            or self.inventory_state != "pending"
            or self.trust_state != "pending"
            or self.ansible_state != "not-started"
            or self.finalization_state != "not-started"
            or self.output_retry_allowed
            or self.automatic_apply_retry_allowed
            or self.manual_review_required
        ):
            raise StatePersistenceError(
                "Terraform apply verification report is invalid"
            )
        for count in (
            self.observation_generation,
            self.journal_generation,
            self.desired_host_count,
            self.observed_host_count,
        ):
            if isinstance(count, bool) or not isinstance(count, int) or count < 1:
                raise StatePersistenceError(
                    "Terraform apply verification report count is invalid"
                )
        for digest in (
            self.observation_artifact_digest,
            self.observation_manifest_digest,
            self.journal_digest,
            self.execution_artifact_digest,
            self.execution_record_digest,
            self.verification_artifact_digest,
            self.verification_record_digest,
            self.output_command_digest,
        ):
            validate_digest(digest, "Terraform apply verification report digest")
        if self.recovered_observation is (
            self.companion_state
            is not TerraformApplyVerificationCompanionState.RECOVERED_OBSERVATION
        ):
            raise StatePersistenceError(
                "Terraform apply verification recovery report conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "execution": {
                "artifact_digest": self.execution_artifact_digest,
                "record_digest": self.execution_record_digest,
                "schema_version": self.execution_schema_version,
            },
            "journal": {
                "digest": self.journal_digest,
                "generation": self.journal_generation,
                "phase": self.journal_phase.value,
                "schema_version": self.journal_schema_version,
                "status": self.journal_status.value,
            },
            "observation": {
                "artifact_digest": self.observation_artifact_digest,
                "generation": self.observation_generation,
                "manifest_digest": self.observation_manifest_digest,
                "manifest_schema_version": self.manifest_schema_version,
                "schema_version": self.observation_schema_version,
                "write_state": self.observation_write_state.value,
            },
            "operation": {"id": str(self.operation_id), "kind": _OPERATION},
            "output": {
                "command_digest": self.output_command_digest,
                "runner_invoked": self.runner_invoked,
                "schema_version": self.output_schema_version,
            },
            "pending": {
                "ansible": self.ansible_state,
                "finalization": self.finalization_state,
                "inventory": self.inventory_state,
                "trust": self.trust_state,
            },
            "reconciliation": {
                "desired_host_count": self.desired_host_count,
                "observed_host_count": self.observed_host_count,
                "role_counts": [
                    {"count": count, "role": role} for role, count in self.role_counts
                ],
                "status": self.reconciliation_status.value,
            },
            "recovery": {
                "automatic_apply_retry_allowed": self.automatic_apply_retry_allowed,
                "manual_review_required": self.manual_review_required,
                "output_retry_allowed": self.output_retry_allowed,
                "recovered_observation": self.recovered_observation,
            },
            "schema_version": self.schema_version,
            "state": {
                "post_apply": self.post_apply_state_identity.to_object(),
                "pre_apply": self.pre_apply_state_identity.to_object(),
                "progression": self.state_progression.value,
            },
            "verification": {
                "artifact_digest": self.verification_artifact_digest,
                "companion_state": self.companion_state.value,
                "record_digest": self.verification_record_digest,
                "schema_version": self.verification_schema_version,
                "status": self.verification_status.value,
            },
        }


def verify_deploy_apply(
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    terraform_executable: Path,
    toolchain: TerraformToolchain,
) -> TerraformApplyVerificationReport:
    """Verify one successful apply process and persist only reconciled evidence."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "Terraform apply verification operation ID must be a UUID"
        )
    paths = StatePaths.derive(state_root, cluster_name)
    _assert_operation_lock(lock, paths)
    executable = validate_executable(terraform_executable)
    _validate_toolchain(toolchain)
    if not callable(getattr(runner, "run", None)):
        raise StatePersistenceError("Terraform apply verification runner is invalid")
    _validate_initialized_layout(paths)
    _refuse_ambiguous_artifacts(paths, operation_id)

    execution = _load_successful_execution(paths, operation_id)
    context = _load_verified_context(
        paths, operation_id, executable, toolchain, execution
    )
    output_command = TerraformCommandBuilder(
        executable, paths, source=context.source
    ).output()
    output_command_digest = _command_digest(output_command)
    store = TerraformApplyVerificationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)

    with _StateSnapshot.open(paths) as snapshot:
        progression = _validate_post_apply_state(
            paths, execution.record, snapshot.identity, toolchain
        )
        snapshot.ensure_current()
        if store.path.exists():
            stored = store.read(
                expected_cluster_uuid=context.metadata.record.cluster_uuid,
                expected_cluster_name=context.metadata.record.cluster_name,
            )
            observation = _read_required_observation(paths, context)
            reconciliation = _reconcile_observation(context, observation, baseline=None)
            _require_verification_bindings(
                stored.record,
                context=context,
                execution=execution,
                observation=observation,
                post_state=snapshot.identity,
                progression=progression,
                reconciliation=reconciliation,
                output_command_digest=output_command_digest,
            )
            snapshot.ensure_current()
            return _verification_report(
                stored,
                execution=execution,
                journal=context.journal,
                companion_state=TerraformApplyVerificationCompanionState.REUSED,
                runner_invoked=False,
            )

        prior_observation = _read_optional_observation(paths, context)
        fresh_output_attempt = context.journal.record.phase is OperationPhase.EXECUTE
        context = _ensure_verify_journal(
            paths=paths,
            operation_id=operation_id,
            lock=lock,
            executable=executable,
            toolchain=toolchain,
            execution=execution,
            context=context,
            prior_observation=prior_observation,
        )
        snapshot.ensure_current()
        recovery_observation = _recoverable_observation(context, prior_observation)
        if recovery_observation is not None:
            observation = recovery_observation
            reconciliation = _reconcile_observation(context, observation, baseline=None)
            companion_state = (
                TerraformApplyVerificationCompanionState.RECOVERED_OBSERVATION
            )
            runner_invoked = False
        elif not fresh_output_attempt:
            raise StateConflictError(
                "Terraform output verification requires manual recovery review"
            )
        else:
            result = runner.run(output_command.process)
            if (
                not isinstance(result, ProcessResult)
                or result.exit_code != 0
                or result.exit_code not in output_command.process.allowed_exit_codes
                or not isinstance(result.stdout, str)
                or not isinstance(result.stderr, str)
            ):
                raise ToolExecutionError(
                    "Terraform output command did not return an exact successful result"
                )
            bundle = parse_terraform_output_bundle(
                result.stdout,
                expected_cluster_uuid=context.metadata.record.cluster_uuid,
                expected_spec=context.metadata.record.desired_spec,
            )
            _validate_output_bindings(bundle, context.tfvars.record.terraform_input)
            reconciliation = reconcile_desired_observed(
                context.metadata.record.desired_spec,
                bundle.manifest,
                baseline=(
                    prior_observation.record.manifest
                    if prior_observation is not None
                    else None
                ),
            )
            _require_match(reconciliation)
            snapshot.ensure_current()
            _reload_exact_verification_inputs(
                paths,
                operation_id,
                executable,
                toolchain,
                execution,
                snapshot.identity,
            )
            observation = _persist_observation(
                paths=paths,
                context=context,
                manifest=bundle.manifest,
                previous=prior_observation,
                lock=lock,
            )
            companion_state = TerraformApplyVerificationCompanionState.CREATED
            runner_invoked = True

        _require_current_state_identity(paths, snapshot.identity)
        context = _reload_exact_verification_inputs(
            paths,
            operation_id,
            executable,
            toolchain,
            execution,
            snapshot.identity,
        )
        current_observation = _read_required_observation(paths, context)
        if (
            current_observation.digest != observation.digest
            or current_observation.record != observation.record
        ):
            raise StateConflictError(
                "Terraform observation changed before verification publication"
            )
        reconciliation = _reconcile_observation(
            context, current_observation, baseline=None
        )
        verification = _create_verification(
            context=context,
            execution=execution,
            observation=current_observation,
            post_state=snapshot.identity,
            progression=progression,
            reconciliation=reconciliation,
            output_command_digest=output_command_digest,
        )
        stored = store.write_locked(
            verification,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        _require_current_state_identity(paths, snapshot.identity)
        return _verification_report(
            stored,
            execution=execution,
            journal=context.journal,
            companion_state=companion_state,
            runner_invoked=runner_invoked,
        )


def terraform_apply_verification_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the sole canonical verification-companion path."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "Terraform apply verification operation ID must be a UUID"
        )
    path = (
        paths.terraform_plans
        / f"{operation_id}{TERRAFORM_APPLY_VERIFICATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.terraform_plans or path.resolve(strict=False) != path:
        raise UnsafePathError("Terraform apply verification path is not canonical")
    return path


def _load_successful_execution(
    paths: StatePaths, operation_id: uuid.UUID
) -> StoredTerraformApplyExecution:
    metadata = _read_metadata(paths)
    execution_path = terraform_apply_execution_path(paths, operation_id)
    validate_state_file(execution_path, allow_missing=True)
    if not execution_path.exists():
        raise StateConflictError(
            "Terraform apply verification requires a durable execution record"
        )
    execution = TerraformApplyExecutionStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )
    record = execution.record
    if (
        record.execution_state
        is not TerraformApplyExecutionState.PROCESS_SUCCEEDED_VERIFICATION_PENDING
        or record.generation != 3
        or record.exit_code != 0
        or not record.authorization_consumed
        or not record.invocation_may_have_occurred
        or record.manual_recovery_required
        or not record.verification_required
        or record.automatic_retry_allowed
        or record.outcome_digest is None
    ):
        raise StateConflictError(
            "Terraform apply execution is not eligible for automatic verification"
        )
    return execution


def _load_verified_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    executable: Path,
    toolchain: TerraformToolchain,
    execution: StoredTerraformApplyExecution,
) -> _ExecutionContext:
    context = _load_context(
        paths=paths,
        operation_id=operation_id,
        executable=executable,
        toolchain=toolchain,
        intent_digest=execution.record.intent_digest,
        require_pre_apply_state=False,
        allow_verification_journal=True,
    )
    expected = _create_prepared_record(
        context, prepared_at=execution.record.prepared_at
    )
    _require_static_execution_binding(execution.record, expected)
    return context


def _validate_post_apply_state(
    paths: StatePaths,
    execution: TerraformApplyExecution,
    post_state: TerraformStateIdentity,
    toolchain: TerraformToolchain,
) -> TerraformStateProgression:
    pre_state = execution.pre_apply_state_identity
    if (
        post_state.presence is not TerraformStatePresence.PRESENT
        or post_state.state_format_version != _STATE_FORMAT_VERSION
        or post_state.terraform_version != str(toolchain.version)
        or post_state.serial is None
        or post_state.lineage_digest is None
        or post_state.state_digest is None
    ):
        raise StateConflictError(
            "Terraform post-apply state identity is missing or unsupported"
        )
    if pre_state.presence is TerraformStatePresence.PRESENT:
        if (
            pre_state.serial is None
            or pre_state.lineage_digest is None
            or pre_state.state_digest is None
            or post_state.lineage_digest != pre_state.lineage_digest
            or post_state.serial <= pre_state.serial
            or post_state.state_digest == pre_state.state_digest
        ):
            raise StateConflictError(
                "Terraform post-apply state did not advance the reviewed lineage"
            )
        progression = TerraformStateProgression.ADVANCED
    else:
        if (
            execution.plan_change_class is not TerraformPlanChangeClass.CREATE_ONLY
            or execution.plan_drift_class is not TerraformPlanDriftClass.NONE
            or post_state.serial < 1
        ):
            raise StateConflictError(
                "Terraform initial post-apply state conflicts with the reviewed plan"
            )
        progression = TerraformStateProgression.INITIALIZED
    validate_state_file(paths.terraform_state_backup, allow_missing=True)
    if paths.terraform_state_backup.exists():
        if pre_state.presence is TerraformStatePresence.ABSENT:
            raise StateConflictError(
                "initial Terraform apply produced conflicting backup state"
            )
        backup = _read_owner_file(
            paths.terraform_state_backup,
            maximum_bytes=_MAXIMUM_STATE_BYTES,
            label="Terraform canonical state backup",
        )
        if digest_bytes(backup) != pre_state.state_digest:
            raise StateConflictError(
                "Terraform canonical state backup conflicts with reviewed pre-state"
            )
    refuse_unexpected_terraform_state(paths, (paths.cluster_root,))
    return progression


def _ensure_verify_journal(
    *,
    paths: StatePaths,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    executable: Path,
    toolchain: TerraformToolchain,
    execution: StoredTerraformApplyExecution,
    context: _ExecutionContext,
    prior_observation: StoredObservedState | None,
) -> _ExecutionContext:
    record = context.journal.record
    if record.phase is OperationPhase.VERIFY:
        return context
    if (
        record.status is not JournalStatus.IN_PROGRESS
        or record.phase is not OperationPhase.EXECUTE
    ):
        raise StateConflictError(
            "Terraform apply verification journal is not at EXECUTE"
        )
    baseline_event = CheckpointEvidence(
        phase=OperationPhase.VERIFY,
        result=EvidenceResult.VALIDATED,
        digest=(
            prior_observation.digest
            if prior_observation is not None
            else _ABSENT_OBSERVATION_DIGEST
        ),
        summary_code=(
            (
                _APPLY_VERIFY_BASELINE_PRESENT_SUMMARY_PREFIX
                + str(prior_observation.record.generation)
            )
            if prior_observation is not None
            else _APPLY_VERIFY_BASELINE_ABSENT_SUMMARY_CODE
        ),
    )
    candidate = record.transition(
        status=JournalStatus.IN_PROGRESS,
        phase=OperationPhase.VERIFY,
        evidence=(*record.evidence, baseline_event),
        clock=lambda: datetime.now(UTC),
    )
    OperationJournalStore(paths, operation_id).write(
        candidate,
        expected_generation=record.generation,
        expected_digest=context.journal.digest,
    )
    return _load_verified_context(paths, operation_id, executable, toolchain, execution)


def _read_optional_observation(
    paths: StatePaths, context: _ExecutionContext
) -> StoredObservedState | None:
    validate_state_file(paths.terraform_observed, allow_missing=True)
    if not paths.terraform_observed.exists():
        return None
    return ObservedStateStore(paths).read(
        expected_cluster_uuid=context.metadata.record.cluster_uuid,
        expected_cluster_name=context.metadata.record.cluster_name,
        expected_provider=context.metadata.record.provider,
    )


def _read_required_observation(
    paths: StatePaths, context: _ExecutionContext
) -> StoredObservedState:
    observation = _read_optional_observation(paths, context)
    if observation is None:
        raise StateConflictError("Terraform apply verification observation is missing")
    return observation


def _recoverable_observation(
    context: _ExecutionContext, observation: StoredObservedState | None
) -> StoredObservedState | None:
    evidence = context.journal.record.evidence
    baseline = evidence[-1] if evidence else None
    if (
        context.journal.record.phase is not OperationPhase.VERIFY
        or observation is None
        or baseline is None
        or baseline.phase is not OperationPhase.VERIFY
        or baseline.result is not EvidenceResult.VALIDATED
        or parse_timestamp(observation.record.captured_at)
        <= parse_timestamp(context.journal.record.updated_at)
    ):
        return None
    if baseline.summary_code == _APPLY_VERIFY_BASELINE_ABSENT_SUMMARY_CODE:
        if (
            baseline.digest != _ABSENT_OBSERVATION_DIGEST
            or observation.record.generation != 1
        ):
            return None
    elif baseline.summary_code.startswith(
        _APPLY_VERIFY_BASELINE_PRESENT_SUMMARY_PREFIX
    ):
        generation_value = baseline.summary_code.removeprefix(
            _APPLY_VERIFY_BASELINE_PRESENT_SUMMARY_PREFIX
        )
        if (
            not generation_value.isdigit()
            or generation_value.startswith("0")
            or observation.record.generation != int(generation_value) + 1
            or observation.digest == baseline.digest
        ):
            return None
    else:
        return None
    return observation


def _persist_observation(
    *,
    paths: StatePaths,
    context: _ExecutionContext,
    manifest: TerraformHostManifest,
    previous: StoredObservedState | None,
    lock: ClusterLock,
) -> StoredObservedState:
    journal_time = parse_timestamp(context.journal.record.updated_at)
    observation_time = max(datetime.now(UTC), journal_time + timedelta(seconds=1))
    if previous is not None:
        observation_time = max(
            observation_time, parse_timestamp(previous.record.captured_at)
        )
    if previous is None:
        candidate = ObservedStateRecord.create(
            cluster_uuid=context.metadata.record.cluster_uuid,
            cluster_name=context.metadata.record.cluster_name,
            provider=context.metadata.record.provider,
            manifest=manifest,
            clock=lambda: observation_time,
        )
        expected_generation = 0
        expected_digest = None
    else:
        candidate = previous.record.next_generation(
            manifest=manifest, clock=lambda: observation_time
        )
        expected_generation = previous.record.generation
        expected_digest = previous.digest
    return ObservedStateStore(paths).write_locked(
        candidate,
        expected_generation=expected_generation,
        expected_digest=expected_digest,
        lock=lock,
    )


def _reload_exact_verification_inputs(
    paths: StatePaths,
    operation_id: uuid.UUID,
    executable: Path,
    toolchain: TerraformToolchain,
    execution: StoredTerraformApplyExecution,
    post_state: TerraformStateIdentity,
) -> _ExecutionContext:
    current_execution = _load_successful_execution(paths, operation_id)
    if (
        current_execution.artifact_digest != execution.artifact_digest
        or current_execution.record != execution.record
    ):
        raise StateConflictError(
            "Terraform apply execution changed during verification"
        )
    context = _load_verified_context(
        paths, operation_id, executable, toolchain, execution
    )
    current_state = _StateSnapshot.open(paths)
    try:
        if current_state.identity != post_state:
            raise StateConflictError(
                "Terraform post-apply state changed during verification"
            )
        current_state.ensure_current()
    finally:
        current_state.__exit__()
    return context


def _require_current_state_identity(
    paths: StatePaths, expected: TerraformStateIdentity
) -> None:
    with _StateSnapshot.open(paths) as current:
        if current.identity != expected:
            raise StateConflictError(
                "Terraform post-apply state changed during verification"
            )
        current.ensure_current()


def _validate_output_bindings(
    bundle: TerraformOutputBundle, terraform_input: object
) -> None:
    if not isinstance(terraform_input, OciTerraformInput):
        raise StateConflictError("Terraform output provider input is unsupported")
    _validate_image_bindings(bundle.image_selection, terraform_input)
    _validate_network_bindings(bundle.network, terraform_input)
    input_hosts = {host.logical_id: host for host in terraform_input.hosts}
    if set(input_hosts) != {host.logical_id for host in bundle.manifest.hosts}:
        raise StateConflictError("Terraform output host membership conflicts")
    for host in bundle.manifest.hosts:
        expected = input_hosts[host.logical_id]
        storage = host.storage
        input_storage = expected.storage
        if (
            host.role is not expected.role
            or host.zone != expected.zone
            or host.shape != expected.shape
            or host.scylla_datacenter != expected.scylla_datacenter
            or host.scylla_rack != expected.scylla_rack
            or storage.requested_backend is not input_storage.requested_backend
            or storage.selected_backend is not input_storage.selected_backend
            or storage.selection_algorithm != input_storage.selection_algorithm
            or storage.policy_digest != input_storage.policy_digest
            or storage.layout != input_storage.layout
        ):
            raise StateConflictError(
                "Terraform output host or storage input binding conflicts"
            )
        if input_storage.selected_backend is StorageBackend.BLOCK_VOLUME:
            block = input_storage.block_volume
            if (
                block is None
                or storage.expected_device_count != block.count
                or storage.raw_total_gib != block.count * block.size_gib
            ):
                raise StateConflictError(
                    "Terraform block-volume output binding conflicts"
                )
        elif input_storage.selected_backend is StorageBackend.LOCAL_NVME:
            if (
                storage.expected_device_count
                != input_storage.provider_local_device_count
                or storage.raw_total_gib != input_storage.provider_local_total_gib
            ):
                raise StateConflictError(
                    "Terraform local-NVMe output binding conflicts"
                )
        elif storage.expected_device_count != 0 or storage.raw_total_gib != 0:
            raise StateConflictError("Terraform boot-only output binding conflicts")


def _validate_image_bindings(
    images: TerraformImageSelection, terraform_input: OciTerraformInput
) -> None:
    expected_hosts = {host.logical_id: host for host in terraform_input.hosts}
    filters = dict(terraform_input.image_filters)
    if (
        images.cluster_uuid != terraform_input.cluster_uuid
        or images.cluster_name != terraform_input.cluster_name
        or images.provider != terraform_input.provider
        or set(expected_hosts) != {image.logical_id for image in images.images}
    ):
        raise StateConflictError("Terraform image output identity conflicts")
    for image in images.images:
        host = expected_hosts[image.logical_id]
        image_filter = filters[host.role]
        if (
            image.role is not host.role
            or image.shape != host.shape
            or image.image_id != host.image_id
            or image.image_name != host.image_name
            or image.image_time_created != host.image_time_created
            or image.operating_system != image_filter.operating_system
            or image.operating_system_version != image_filter.operating_system_version
            or image.version_match != image_filter.version_match.value
        ):
            raise StateConflictError("Terraform image output binding conflicts")


def _validate_network_bindings(
    network: TerraformNetworkEvidence, terraform_input: OciTerraformInput
) -> None:
    expected_network = terraform_input.network
    active_roles = {host.role.value for host in terraform_input.hosts}
    groups = dict(network.network_security_groups)
    if (
        network.cluster_uuid != terraform_input.cluster_uuid
        or network.cluster_name != terraform_input.cluster_name
        or network.provider != terraform_input.provider
        or network.mode != expected_network.mode
        or set(groups) != active_roles
        or len(set(groups.values())) != len(groups)
    ):
        raise StateConflictError("Terraform network output identity conflicts")
    if expected_network.mode == NetworkMode.EXISTING.value:
        expected_subnet_ids = dict(expected_network.subnet_ids)
        expected = {
            (
                host.zone,
                host.role.value,
                (
                    "public"
                    if host.role is HostRole.JUMP_HOST
                    and expected_network.allow_public_jump_hosts
                    else "private"
                ),
                expected_subnet_ids[host.role.value],
                False,
            )
            for host in terraform_input.hosts
        }
        if network.vcn_id != expected_network.vcn_id:
            raise StateConflictError("Terraform existing VCN output conflicts")
    else:
        private_zones = {host.zone for host in terraform_input.hosts}
        expected = {
            (zone, "private", "private", subnet.subnet_id, True)
            for zone in private_zones
            for subnet in network.subnets
            if subnet.zone == zone and subnet.role == "private"
        }
        if expected_network.allow_public_jump_hosts:
            expected.update(
                (
                    host.zone,
                    "jump-host",
                    "public",
                    subnet.subnet_id,
                    True,
                )
                for host in terraform_input.hosts
                if host.role is HostRole.JUMP_HOST
                for subnet in network.subnets
                if subnet.zone == host.zone and subnet.role == "jump-host"
            )
    actual = {
        (item.zone, item.role, item.access, item.subnet_id, item.owned)
        for item in network.subnets
    }
    if (
        actual != expected
        or len(actual) != len(network.subnets)
        or len({item.subnet_id for item in network.subnets}) != len(network.subnets)
    ):
        raise StateConflictError("Terraform network subnet output conflicts")


def _reconcile_observation(
    context: _ExecutionContext,
    observation: StoredObservedState,
    *,
    baseline: TerraformHostManifest | None,
) -> ReconciliationReport:
    report = reconcile_desired_observed(
        context.metadata.record.desired_spec,
        observation.record.manifest,
        baseline=baseline,
    )
    _require_match(report)
    return report


def _require_match(report: ReconciliationReport) -> None:
    if report.status is not ReconciliationClass.MATCH or not report.sensitive_ready:
        raise StateConflictError(
            "Terraform post-apply observation does not exactly match desired state"
        )


def _create_verification(
    *,
    context: _ExecutionContext,
    execution: StoredTerraformApplyExecution,
    observation: StoredObservedState,
    post_state: TerraformStateIdentity,
    progression: TerraformStateProgression,
    reconciliation: ReconciliationReport,
    output_command_digest: str,
) -> TerraformApplyVerification:
    record = execution.record
    role_counts = _role_counts(observation)
    values: dict[str, object] = {
        "authorization_artifact_digest": record.authorization_artifact_digest,
        "authorization_digest": record.authorization_digest,
        "backend_digest": record.backend_digest,
        "backend_kind": record.backend_kind,
        "checkpoint_artifact_digest": record.checkpoint_artifact_digest,
        "checkpoint_digest": record.checkpoint_digest,
        "checkpoint_schema_version": record.checkpoint_schema_version,
        "cluster_name": record.cluster_name,
        "cluster_uuid": str(record.cluster_uuid),
        "composition_digest": record.composition_digest,
        "desired_host_count": reconciliation.desired_host_count,
        "desired_spec_digest": record.desired_spec_digest,
        "execution_artifact_digest": execution.artifact_digest,
        "execution_generation": record.generation,
        "execution_outcome_digest": record.outcome_digest,
        "execution_record_digest": record.record_digest,
        "execution_schema_version": record.schema_version,
        "generation": 1,
        "input_digest": record.input_digest,
        "journal_digest": context.journal.digest,
        "journal_generation": context.journal.record.generation,
        "journal_schema_version": context.journal.record.schema_version,
        "manifest_schema_version": observation.record.manifest_schema_version,
        "metadata_digest": record.metadata_digest,
        "metadata_generation": record.metadata_generation,
        "observed_host_count": reconciliation.observed_host_count,
        "observation_artifact_digest": observation.digest,
        "observation_generation": observation.record.generation,
        "observation_manifest_digest": observation.record.manifest_digest,
        "observation_schema_version": observation.record.schema_version,
        "observation_write_state": (
            TerraformObservationWriteState.INITIAL.value
            if observation.record.generation == 1
            else TerraformObservationWriteState.UPDATED.value
        ),
        "operation": record.operation,
        "operation_id": str(record.operation_id),
        "output_command_digest": output_command_digest,
        "output_manifest_digest": observation.record.manifest_digest,
        "output_schema_version": observation.record.output_schema_version,
        "plan_change_class": record.plan_change_class.value,
        "plan_drift_class": record.plan_drift_class.value,
        "plan_format_version": record.plan_format_version,
        "post_apply_state_identity": post_state.to_object(),
        "post_apply_state_identity_digest": _state_identity_digest(post_state),
        "pre_apply_state_identity": record.pre_apply_state_identity.to_object(),
        "pre_apply_state_identity_digest": record.pre_apply_state_identity_digest,
        "reconciliation_status": reconciliation.status.value,
        "record_digest": "sha256:" + "0" * 64,
        "request_digest": record.request_digest,
        "review_digest": record.review_digest,
        "review_schema_version": record.review_schema_version,
        "role_counts": [{"count": count, "role": role} for role, count in role_counts],
        "safeguard_artifact_digest": record.safeguard_artifact_digest,
        "safeguard_digest": record.safeguard_digest,
        "safeguard_schema_version": record.safeguard_schema_version,
        "schema_version": TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION,
        "source_bundle_digest": record.source_bundle_digest,
        "source_digest": record.source_digest,
        "source_generation": record.source_generation,
        "source_version": record.source_version,
        "state_progression": progression.value,
        "terraform_version": record.terraform_version,
        "tfvars_digest": record.tfvars_digest,
        "tfvars_generation": record.tfvars_generation,
        "toolchain_digest": record.toolchain_digest,
        "verification_status": (
            TerraformApplyVerificationStatus.INFRASTRUCTURE_OBSERVATION_RECONCILED.value
        ),
        "verified_at": format_timestamp(
            max(datetime.now(UTC), parse_timestamp(observation.record.captured_at))
        ),
    }
    values["record_digest"] = _verification_digest_object(values)
    return TerraformApplyVerification.from_object(values)


def _require_verification_bindings(
    record: TerraformApplyVerification,
    *,
    context: _ExecutionContext,
    execution: StoredTerraformApplyExecution,
    observation: StoredObservedState,
    post_state: TerraformStateIdentity,
    progression: TerraformStateProgression,
    reconciliation: ReconciliationReport,
    output_command_digest: str,
) -> None:
    expected = _create_verification(
        context=context,
        execution=execution,
        observation=observation,
        post_state=post_state,
        progression=progression,
        reconciliation=reconciliation,
        output_command_digest=output_command_digest,
    )
    current = record.to_object()
    candidate = expected.to_object()
    current.pop("verified_at")
    candidate.pop("verified_at")
    current.pop("record_digest")
    candidate.pop("record_digest")
    if current != candidate:
        raise StateConflictError("Terraform apply verification binding changed")


def _verification_report(
    stored: StoredTerraformApplyVerification,
    *,
    execution: StoredTerraformApplyExecution,
    journal: StoredOperationRecord,
    companion_state: TerraformApplyVerificationCompanionState,
    runner_invoked: bool,
) -> TerraformApplyVerificationReport:
    record = stored.record
    return TerraformApplyVerificationReport(
        operation_id=record.operation_id,
        companion_state=companion_state,
        verification_status=record.verification_status,
        state_progression=record.state_progression,
        pre_apply_state_identity=record.pre_apply_state_identity,
        post_apply_state_identity=record.post_apply_state_identity,
        observation_write_state=record.observation_write_state,
        observation_generation=record.observation_generation,
        observation_artifact_digest=record.observation_artifact_digest,
        observation_manifest_digest=record.observation_manifest_digest,
        reconciliation_status=record.reconciliation_status,
        desired_host_count=record.desired_host_count,
        observed_host_count=record.observed_host_count,
        role_counts=record.role_counts,
        journal_generation=journal.record.generation,
        journal_digest=journal.digest,
        journal_status=journal.record.status,
        journal_phase=journal.record.phase,
        execution_artifact_digest=execution.artifact_digest,
        execution_record_digest=execution.record.record_digest,
        verification_artifact_digest=stored.artifact_digest,
        verification_record_digest=record.record_digest,
        output_command_digest=record.output_command_digest,
        runner_invoked=runner_invoked,
        recovered_observation=(
            companion_state
            is TerraformApplyVerificationCompanionState.RECOVERED_OBSERVATION
        ),
        output_retry_allowed=False,
        automatic_apply_retry_allowed=False,
        manual_review_required=False,
        inventory_state="pending",
        trust_state="pending",
        ansible_state="not-started",
        finalization_state="not-started",
    )


def _role_counts(observation: StoredObservedState) -> tuple[tuple[str, int], ...]:
    counts = Counter(host.role.value for host in observation.record.manifest.hosts)
    return tuple((role.value, counts[role.value]) for role in sorted(HostRole, key=str))


def _read_metadata(paths: StatePaths) -> StoredClusterMetadata:
    from scylla_vms.persistence import ClusterMetadataStore

    return ClusterMetadataStore(paths).read(
        expected_cluster_name=paths.cluster_root.name,
        expected_provider="oci",
    )


def _verification_digest(record: TerraformApplyVerification) -> str:
    return _verification_digest_object(record.to_object())


def _verification_digest_object(values: Mapping[str, object]) -> str:
    copied = dict(values)
    copied["record_digest"] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(copied))


def _state_identity_digest(identity: TerraformStateIdentity) -> str:
    return digest_bytes(serialize_json(identity.to_object()))


def _validate_initialized_layout(paths: StatePaths) -> None:
    _require_canonical_paths(paths)
    for directory in paths.directory_paths:
        validate_state_directory(directory)
    validate_state_file(paths.cluster_metadata)
    validate_state_file(paths.terraform_tfvars)
    validate_state_file(paths.terraform_source_record)
    validate_state_file(paths.terraform_state)
    refuse_unexpected_terraform_state(paths, (paths.cluster_root,))


def _require_canonical_paths(paths: StatePaths) -> None:
    expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
    if (
        expected != paths
        or paths.terraform_plans.parent != paths.terraform
        or paths.terraform_observed.parent != paths.terraform
    ):
        raise UnsafePathError("Terraform apply verification paths are not canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StatePersistenceError(
            "Terraform apply verification requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    allowed_operation = {paths.operations / f"{operation_id}.json"}
    _refuse_matching_unknown(
        paths.operations,
        operation_id,
        allowed_operation,
        "Terraform apply verification operation history",
    )
    allowed_plan = {
        paths.terraform_plans / f"{operation_id}.tfplan",
        paths.terraform_plans / f"{operation_id}.terraform-plan.json",
        paths.terraform_plans / f"{operation_id}.terraform-apply-authorization.json",
        paths.terraform_plans / f"{operation_id}.terraform-state-safeguard.json",
        terraform_apply_execution_path(paths, operation_id),
        terraform_apply_verification_path(paths, operation_id),
        paths.terraform_plans / f"{operation_id}.terraform-apply-inventory.json",
        paths.terraform_plans / f"{operation_id}.terraform-apply-trust.json",
    }
    _refuse_matching_unknown(
        paths.terraform_plans,
        operation_id,
        allowed_plan,
        "Terraform apply verification plan history",
    )
    allowed_backup = {paths.terraform_backups / f"{operation_id}.terraform.tfstate"}
    _refuse_matching_unknown(
        paths.terraform_backups,
        operation_id,
        allowed_backup,
        "Terraform apply verification backup history",
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


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


__all__ = [
    "TERRAFORM_APPLY_VERIFICATION_FILENAME_SUFFIX",
    "TERRAFORM_APPLY_VERIFICATION_REPORT_SCHEMA_VERSION",
    "TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION",
    "StoredTerraformApplyVerification",
    "TerraformApplyVerification",
    "TerraformApplyVerificationCompanionState",
    "TerraformApplyVerificationReport",
    "TerraformApplyVerificationStatus",
    "TerraformApplyVerificationStore",
    "TerraformObservationWriteState",
    "TerraformStateProgression",
    "terraform_apply_verification_path",
    "verify_deploy_apply",
]
