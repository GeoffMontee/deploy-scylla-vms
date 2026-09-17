"""Immutable pre-apply safeguards for canonical local Terraform state."""

from __future__ import annotations

import json
import os
import re
import stat
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from scylla_vms.errors import (
    ConfigurationError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import (
    JOURNAL_SCHEMA_VERSION,
    CheckpointEvidence,
    EvidenceResult,
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    OperationRecord,
    StoredOperationRecord,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification, get_operation
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
from scylla_vms.state import (
    StatePaths,
    refuse_unexpected_terraform_state,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)
from scylla_vms.terraform.apply_authorization import (
    TERRAFORM_APPLY_AUTHORIZATION_SCHEMA_VERSION,
    StoredTerraformApplyAuthorization,
    TerraformApplyAuthorizationState,
    TerraformApplyAuthorizationStore,
    terraform_apply_authorization_path,
)
from scylla_vms.terraform.plan import (
    TERRAFORM_PLAN_BACKEND_KIND,
    TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION,
    TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION,
    StoredTerraformPlanCheckpoint,
    TerraformPlanChangeClass,
    TerraformPlanCheckpointService,
    TerraformPlanCheckpointStore,
    TerraformPlanDriftClass,
    TerraformStateIdentity,
    TerraformStatePresence,
    capture_terraform_state_identity,
)

TERRAFORM_STATE_SAFEGUARD_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-state-safeguard/v1"
)
TERRAFORM_STATE_SAFEGUARD_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-state-safeguard-report/v1"
)
TERRAFORM_STATE_SAFEGUARD_FILENAME_SUFFIX = ".terraform-state-safeguard.json"
TERRAFORM_STATE_BACKUP_FILENAME_SUFFIX = ".terraform.tfstate"

_OPERATION = "deploy"
_PLAN_SUMMARY_CODE = "terraform-plan-reviewed"
_MAXIMUM_STATE_BYTES = 64 * 1024 * 1024
_FILE_MODE = 0o600
_AUTHORIZATION_CONSUMPTION = "unconsumed"
_AUTHORIZATION_NOT_REQUIRED = "not-required"
_EXECUTION_INTENT = "not-started"
_APPLY_EXECUTION = "unavailable"
_DESTRUCTIVE_BOUNDARY = "not-crossed"
_JSON_NUMBER = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")
_STATE_IDENTITY_FIELDS = frozenset(
    {"lineage", "serial", "terraform_version", "version"}
)


class TerraformStateSafeguardResult(StrEnum):
    """Whether a safeguard was created, reused, or unnecessary."""

    CREATED = "created"
    REUSED = "reused"
    NOT_REQUIRED = "not-required"


class TerraformStateBackupState(StrEnum):
    """Durable backup stage state."""

    CREATED = "created"
    REUSED = "reused"
    NOT_REQUIRED = "not-required"


class TerraformStateRecoveryPolicy(StrEnum):
    """Narrow recovery meaning of a safeguarded pre-apply state."""

    RESTORE_EXACT_BACKUP_BEFORE_REPLAN = "restore-exact-backup-before-replan"
    VERIFIED_ABSENT_INITIAL_STATE = "verified-absent-initial-state"


@dataclass(frozen=True, slots=True)
class TerraformStateSafeguard:
    """Immutable binding for an exact pre-apply state or verified absence."""

    generation: int
    created_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    operation_classification: OperationClassification
    request_digest: str
    journal_schema_version: str
    journal_generation: int
    journal_digest: str
    checkpoint_schema_version: str
    checkpoint_generation: int
    checkpoint_artifact_digest: str
    checkpoint_digest: str
    review_schema_version: str
    review_digest: str
    authorization_schema_version: str
    authorization_generation: int
    authorization_artifact_digest: str
    authorization_digest: str
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
    state_identity: TerraformStateIdentity
    state_identity_digest: str
    terraform_version: str
    plan_format_version: str
    toolchain_digest: str
    plan_binary_digest: str
    plan_json_digest: str
    plan_change_class: TerraformPlanChangeClass
    plan_drift_class: TerraformPlanDriftClass
    backup_digest: str | None
    backup_size_bytes: int | None
    absent_proof_digest: str | None
    recovery_policy: TerraformStateRecoveryPolicy
    safeguard_digest: str
    apply_required: bool = True
    authorization_consumption: str = _AUTHORIZATION_CONSUMPTION
    execution_intent: str = _EXECUTION_INTENT
    apply_execution: str = _APPLY_EXECUTION
    destructive_boundary: str = _DESTRUCTIVE_BOUNDARY
    schema_version: str = TERRAFORM_STATE_SAFEGUARD_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != TERRAFORM_STATE_SAFEGUARD_SCHEMA_VERSION
            or self.generation != 1
        ):
            raise StatePersistenceError("unsupported Terraform state safeguard schema")
        if not isinstance(self.cluster_uuid, uuid.UUID) or not isinstance(
            self.operation_id, uuid.UUID
        ):
            raise StatePersistenceError("Terraform state safeguard identity is invalid")
        try:
            validate_cluster_name(self.cluster_name)
            operation = get_operation(self.operation)
        except (ConfigurationError, KeyError) as error:
            raise StatePersistenceError(
                "Terraform state safeguard identity is invalid"
            ) from error
        if (
            self.operation != _OPERATION
            or operation.classification is not self.operation_classification
            or self.operation_classification is not OperationClassification.MUTATING
        ):
            raise StatePersistenceError("Terraform state safeguard operation conflicts")
        parse_timestamp(self.created_at)
        for generation in (
            self.journal_generation,
            self.checkpoint_generation,
            self.authorization_generation,
            self.metadata_generation,
            self.tfvars_generation,
            self.source_generation,
        ):
            if (
                isinstance(generation, bool)
                or not isinstance(generation, int)
                or generation < 1
            ):
                raise StatePersistenceError(
                    "Terraform state safeguard generation binding is invalid"
                )
        for label, value in (
            ("operation request digest", self.request_digest),
            ("operation journal digest", self.journal_digest),
            ("Terraform checkpoint artifact digest", self.checkpoint_artifact_digest),
            ("Terraform checkpoint digest", self.checkpoint_digest),
            ("Terraform review digest", self.review_digest),
            (
                "Terraform authorization artifact digest",
                self.authorization_artifact_digest,
            ),
            ("Terraform authorization digest", self.authorization_digest),
            ("cluster metadata digest", self.metadata_digest),
            ("desired specification digest", self.desired_spec_digest),
            ("Terraform tfvars digest", self.tfvars_digest),
            ("Terraform input digest", self.input_digest),
            ("Terraform source digest", self.source_digest),
            ("Terraform source bundle digest", self.source_bundle_digest),
            ("Terraform backend digest", self.backend_digest),
            ("Terraform state identity digest", self.state_identity_digest),
            ("Terraform toolchain digest", self.toolchain_digest),
            ("Terraform saved plan digest", self.plan_binary_digest),
            ("Terraform plan JSON digest", self.plan_json_digest),
            ("Terraform state safeguard digest", self.safeguard_digest),
        ):
            validate_digest(value, label)
        if (
            self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.journal_generation < 2
            or self.checkpoint_schema_version
            != TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
            or self.checkpoint_generation != 1
            or self.review_schema_version != TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
            or self.authorization_schema_version
            != TERRAFORM_APPLY_AUTHORIZATION_SCHEMA_VERSION
            or self.authorization_generation != 1
            or self.backend_kind != TERRAFORM_PLAN_BACKEND_KIND
            or not isinstance(self.state_identity, TerraformStateIdentity)
            or not isinstance(self.plan_change_class, TerraformPlanChangeClass)
            or not isinstance(self.plan_drift_class, TerraformPlanDriftClass)
            or not isinstance(self.recovery_policy, TerraformStateRecoveryPolicy)
        ):
            raise StatePersistenceError(
                "Terraform state safeguard provenance is invalid"
            )
        if (
            self.backend_digest
            != _backend_digest(self.backend_kind, self.state_identity)
            or self.state_identity_digest != _state_identity_digest(self.state_identity)
            or self.toolchain_digest
            != _toolchain_digest(self.terraform_version, self.plan_format_version)
        ):
            raise StatePersistenceError(
                "Terraform state safeguard derived binding conflicts"
            )
        if self.state_identity.presence is TerraformStatePresence.PRESENT:
            if (
                self.backup_digest is None
                or self.backup_size_bytes is None
                or self.backup_size_bytes < 1
                or self.backup_size_bytes > _MAXIMUM_STATE_BYTES
                or self.absent_proof_digest is not None
                or self.recovery_policy
                is not TerraformStateRecoveryPolicy.RESTORE_EXACT_BACKUP_BEFORE_REPLAN
                or self.backup_digest != self.state_identity.state_digest
            ):
                raise StatePersistenceError(
                    "present Terraform state safeguard backup conflicts"
                )
            validate_digest(self.backup_digest, "Terraform state backup digest")
        else:
            if (
                self.backup_digest is not None
                or self.backup_size_bytes is not None
                or self.absent_proof_digest is None
                or self.recovery_policy
                is not TerraformStateRecoveryPolicy.VERIFIED_ABSENT_INITIAL_STATE
                or self.plan_change_class is not TerraformPlanChangeClass.CREATE_ONLY
                or self.plan_drift_class is not TerraformPlanDriftClass.NONE
            ):
                raise StatePersistenceError(
                    "absent Terraform state safeguard proof conflicts"
                )
            validate_digest(
                self.absent_proof_digest, "Terraform absent-state proof digest"
            )
            if self.absent_proof_digest != _absent_proof_digest(self):
                raise StatePersistenceError(
                    "Terraform absent-state safeguard digest conflicts"
                )
        if (
            not self.apply_required
            or self.authorization_consumption != _AUTHORIZATION_CONSUMPTION
            or self.execution_intent != _EXECUTION_INTENT
            or self.apply_execution != _APPLY_EXECUTION
            or self.destructive_boundary != _DESTRUCTIVE_BOUNDARY
        ):
            raise StatePersistenceError(
                "Terraform state safeguard execution state conflicts"
            )
        if self.safeguard_digest != _safeguard_digest(self):
            raise StatePersistenceError("Terraform state safeguard digest conflicts")

    def to_object(self) -> dict[str, object]:
        return {
            "absent_proof_digest": self.absent_proof_digest,
            "apply_execution": self.apply_execution,
            "apply_required": self.apply_required,
            "authorization_artifact_digest": self.authorization_artifact_digest,
            "authorization_consumption": self.authorization_consumption,
            "authorization_digest": self.authorization_digest,
            "authorization_generation": self.authorization_generation,
            "authorization_schema_version": self.authorization_schema_version,
            "backend_digest": self.backend_digest,
            "backend_kind": self.backend_kind,
            "backup_digest": self.backup_digest,
            "backup_size_bytes": self.backup_size_bytes,
            "checkpoint_artifact_digest": self.checkpoint_artifact_digest,
            "checkpoint_digest": self.checkpoint_digest,
            "checkpoint_generation": self.checkpoint_generation,
            "checkpoint_schema_version": self.checkpoint_schema_version,
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "created_at": self.created_at,
            "desired_spec_digest": self.desired_spec_digest,
            "destructive_boundary": self.destructive_boundary,
            "execution_intent": self.execution_intent,
            "generation": self.generation,
            "input_digest": self.input_digest,
            "journal_digest": self.journal_digest,
            "journal_generation": self.journal_generation,
            "journal_schema_version": self.journal_schema_version,
            "metadata_digest": self.metadata_digest,
            "metadata_generation": self.metadata_generation,
            "operation": self.operation,
            "operation_classification": self.operation_classification.value,
            "operation_id": str(self.operation_id),
            "plan_binary_digest": self.plan_binary_digest,
            "plan_change_class": self.plan_change_class.value,
            "plan_drift_class": self.plan_drift_class.value,
            "plan_format_version": self.plan_format_version,
            "plan_json_digest": self.plan_json_digest,
            "recovery_policy": self.recovery_policy.value,
            "request_digest": self.request_digest,
            "review_digest": self.review_digest,
            "review_schema_version": self.review_schema_version,
            "safeguard_digest": self.safeguard_digest,
            "schema_version": self.schema_version,
            "source_bundle_digest": self.source_bundle_digest,
            "source_digest": self.source_digest,
            "source_generation": self.source_generation,
            "source_version": self.source_version,
            "state_identity": self.state_identity.to_object(),
            "state_identity_digest": self.state_identity_digest,
            "terraform_version": self.terraform_version,
            "tfvars_digest": self.tfvars_digest,
            "tfvars_generation": self.tfvars_generation,
            "toolchain_digest": self.toolchain_digest,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> TerraformStateSafeguard:
        require_exact_keys(value, set(_SAFEGUARD_KEYS), "Terraform state safeguard")
        state_value = value["state_identity"]
        if not isinstance(state_value, dict):
            raise StatePersistenceError(
                "Terraform state safeguard identity must be an object"
            )
        try:
            operation_classification = OperationClassification(
                require_string(value, "operation_classification")
            )
            change_class = TerraformPlanChangeClass(
                require_string(value, "plan_change_class")
            )
            drift_class = TerraformPlanDriftClass(
                require_string(value, "plan_drift_class")
            )
            recovery_policy = TerraformStateRecoveryPolicy(
                require_string(value, "recovery_policy")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "Terraform state safeguard enum is invalid"
            ) from error
        apply_required = value["apply_required"]
        if not isinstance(apply_required, bool):
            raise StatePersistenceError(
                "Terraform state safeguard apply-required state must be boolean"
            )
        return cls(
            generation=_integer(value["generation"], "safeguard generation"),
            created_at=require_string(value, "created_at"),
            cluster_uuid=parse_uuid(
                require_string(value, "cluster_uuid"), "cluster UUID"
            ),
            cluster_name=require_string(value, "cluster_name"),
            operation_id=parse_uuid(
                require_string(value, "operation_id"), "operation ID"
            ),
            operation=require_string(value, "operation"),
            operation_classification=operation_classification,
            request_digest=require_string(value, "request_digest"),
            journal_schema_version=require_string(value, "journal_schema_version"),
            journal_generation=_integer(
                value["journal_generation"], "journal generation"
            ),
            journal_digest=require_string(value, "journal_digest"),
            checkpoint_schema_version=require_string(
                value, "checkpoint_schema_version"
            ),
            checkpoint_generation=_integer(
                value["checkpoint_generation"], "checkpoint generation"
            ),
            checkpoint_artifact_digest=require_string(
                value, "checkpoint_artifact_digest"
            ),
            checkpoint_digest=require_string(value, "checkpoint_digest"),
            review_schema_version=require_string(value, "review_schema_version"),
            review_digest=require_string(value, "review_digest"),
            authorization_schema_version=require_string(
                value, "authorization_schema_version"
            ),
            authorization_generation=_integer(
                value["authorization_generation"], "authorization generation"
            ),
            authorization_artifact_digest=require_string(
                value, "authorization_artifact_digest"
            ),
            authorization_digest=require_string(value, "authorization_digest"),
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
            state_identity=TerraformStateIdentity.from_object(
                cast(dict[str, object], state_value)
            ),
            state_identity_digest=require_string(value, "state_identity_digest"),
            terraform_version=require_string(value, "terraform_version"),
            plan_format_version=require_string(value, "plan_format_version"),
            toolchain_digest=require_string(value, "toolchain_digest"),
            plan_binary_digest=require_string(value, "plan_binary_digest"),
            plan_json_digest=require_string(value, "plan_json_digest"),
            plan_change_class=change_class,
            plan_drift_class=drift_class,
            backup_digest=_optional_string(value, "backup_digest"),
            backup_size_bytes=_optional_integer(value, "backup_size_bytes"),
            absent_proof_digest=_optional_string(value, "absent_proof_digest"),
            recovery_policy=recovery_policy,
            safeguard_digest=require_string(value, "safeguard_digest"),
            apply_required=apply_required,
            authorization_consumption=require_string(
                value, "authorization_consumption"
            ),
            execution_intent=require_string(value, "execution_intent"),
            apply_execution=require_string(value, "apply_execution"),
            destructive_boundary=require_string(value, "destructive_boundary"),
            schema_version=require_string(value, "schema_version"),
        )


_SAFEGUARD_KEYS = frozenset(
    {
        "absent_proof_digest",
        "apply_execution",
        "apply_required",
        "authorization_artifact_digest",
        "authorization_consumption",
        "authorization_digest",
        "authorization_generation",
        "authorization_schema_version",
        "backend_digest",
        "backend_kind",
        "backup_digest",
        "backup_size_bytes",
        "checkpoint_artifact_digest",
        "checkpoint_digest",
        "checkpoint_generation",
        "checkpoint_schema_version",
        "cluster_name",
        "cluster_uuid",
        "created_at",
        "desired_spec_digest",
        "destructive_boundary",
        "execution_intent",
        "generation",
        "input_digest",
        "journal_digest",
        "journal_generation",
        "journal_schema_version",
        "metadata_digest",
        "metadata_generation",
        "operation",
        "operation_classification",
        "operation_id",
        "plan_binary_digest",
        "plan_change_class",
        "plan_drift_class",
        "plan_format_version",
        "plan_json_digest",
        "recovery_policy",
        "request_digest",
        "review_digest",
        "review_schema_version",
        "safeguard_digest",
        "schema_version",
        "source_bundle_digest",
        "source_digest",
        "source_generation",
        "source_version",
        "state_identity",
        "state_identity_digest",
        "terraform_version",
        "tfvars_digest",
        "tfvars_generation",
        "toolchain_digest",
    }
)


@dataclass(frozen=True, slots=True)
class StoredTerraformStateSafeguard:
    record: TerraformStateSafeguard
    artifact_digest: str


class TerraformStateSafeguardStore:
    """Owner-only immutable safeguard companion beside its reviewed plan."""

    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        _require_canonical_paths(paths)
        self._paths = paths
        self._operation_id = operation_id
        self._path = terraform_state_safeguard_path(paths, operation_id)
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
    ) -> StoredTerraformStateSafeguard:
        value, artifact_digest = self._file.read()
        record = TerraformStateSafeguard.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or record.operation != _OPERATION
        ):
            raise StatePersistenceError("Terraform state safeguard identity conflicts")
        return StoredTerraformStateSafeguard(record, artifact_digest)

    def write_locked(
        self, record: TerraformStateSafeguard, *, lock: ClusterLock
    ) -> StoredTerraformStateSafeguard:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.terraform_plans)
        validate_state_file(self._path, allow_missing=True)
        if self._path.exists():
            raise StatePersistenceError("Terraform state safeguard is immutable")
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return StoredTerraformStateSafeguard(record, artifact_digest)


@dataclass(frozen=True, slots=True)
class StoredTerraformStateBackup:
    digest: str
    size_bytes: int


class TerraformStateBackupStore:
    """Immutable operation-scoped byte-for-byte state backups."""

    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        _require_canonical_paths(paths)
        self._paths = paths
        self._path = terraform_state_backup_path(paths, operation_id)
        self._token_factory = token_factory or (lambda: uuid.uuid4().hex)

    @property
    def path(self) -> Path:
        return self._path

    def read(self) -> tuple[StoredTerraformStateBackup, bytes]:
        raw = _read_owner_file(
            self._path,
            maximum_bytes=_MAXIMUM_STATE_BYTES,
            label="Terraform state safeguard backup",
        )
        if not raw:
            raise StatePersistenceError("Terraform state safeguard backup is empty")
        return StoredTerraformStateBackup(digest_bytes(raw), len(raw)), raw

    def write_locked(
        self, raw: bytes, *, lock: ClusterLock
    ) -> StoredTerraformStateBackup:
        _assert_operation_lock(lock, self._paths)
        if not isinstance(raw, bytes) or not raw or len(raw) > _MAXIMUM_STATE_BYTES:
            raise StatePersistenceError("Terraform state backup bytes are invalid")
        validate_state_directory(self._paths.terraform_backups)
        validate_state_file(self._path, allow_missing=True)
        if self._path.exists():
            raise StatePersistenceError("Terraform state safeguard backup is immutable")
        _write_immutable_bytes(
            self._path,
            raw,
            token_factory=self._token_factory,
        )
        return StoredTerraformStateBackup(digest_bytes(raw), len(raw))


@dataclass(frozen=True, slots=True)
class TerraformStateSafeguardReport:
    """Strict redacted report for pre-apply state safeguarding."""

    operation_id: uuid.UUID
    result: TerraformStateSafeguardResult
    backup_state: TerraformStateBackupState
    state_identity: TerraformStateIdentity
    journal_generation: int
    journal_digest: str
    checkpoint_artifact_digest: str
    checkpoint_digest: str
    review_digest: str
    authorization_artifact_digest: str | None
    authorization_digest: str | None
    safeguard_artifact_digest: str | None
    safeguard_digest: str | None
    backup_digest: str | None
    backup_size_bytes: int | None
    recovery_policy: TerraformStateRecoveryPolicy | None
    recovered_backup_prefix: bool
    authorization_state: TerraformApplyAuthorizationState
    apply_required: bool
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    checkpoint_schema_version: str = TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
    review_schema_version: str = TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
    authorization_schema_version: str | None = None
    safeguard_schema_version: str | None = None
    authorization_consumption: str = _AUTHORIZATION_CONSUMPTION
    execution_intent: str = _EXECUTION_INTENT
    apply_execution: str = _APPLY_EXECUTION
    destructive_boundary: str = _DESTRUCTIVE_BOUNDARY
    automatic_restore_performed: bool = False
    automatic_retry_allowed: bool = False
    idempotent_reentry_allowed: bool = True
    manual_recovery_available: bool = False
    schema_version: str = TERRAFORM_STATE_SAFEGUARD_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != TERRAFORM_STATE_SAFEGUARD_REPORT_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.checkpoint_schema_version
            != TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
            or self.review_schema_version != TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
        ):
            raise StatePersistenceError(
                "unsupported Terraform state safeguard report schema"
            )
        if (
            not isinstance(self.operation_id, uuid.UUID)
            or not isinstance(self.result, TerraformStateSafeguardResult)
            or not isinstance(self.backup_state, TerraformStateBackupState)
            or not isinstance(self.state_identity, TerraformStateIdentity)
            or isinstance(self.journal_generation, bool)
            or not isinstance(self.journal_generation, int)
            or self.journal_generation < 2
            or not isinstance(self.recovered_backup_prefix, bool)
            or not isinstance(
                self.authorization_state, TerraformApplyAuthorizationState
            )
            or not isinstance(self.apply_required, bool)
        ):
            raise StatePersistenceError(
                "Terraform state safeguard report state is invalid"
            )
        for label, value in (
            ("operation journal digest", self.journal_digest),
            ("Terraform checkpoint artifact digest", self.checkpoint_artifact_digest),
            ("Terraform checkpoint digest", self.checkpoint_digest),
            ("Terraform review digest", self.review_digest),
        ):
            validate_digest(value, label)
        if self.result is TerraformStateSafeguardResult.NOT_REQUIRED:
            if (
                self.backup_state is not TerraformStateBackupState.NOT_REQUIRED
                or self.authorization_artifact_digest is not None
                or self.authorization_digest is not None
                or self.safeguard_artifact_digest is not None
                or self.safeguard_digest is not None
                or self.backup_digest is not None
                or self.backup_size_bytes is not None
                or self.recovery_policy is not None
                or self.authorization_schema_version is not None
                or self.safeguard_schema_version is not None
                or self.authorization_state
                is not TerraformApplyAuthorizationState.NOT_REQUIRED
                or self.apply_required
                or self.authorization_consumption != _AUTHORIZATION_NOT_REQUIRED
                or self.recovered_backup_prefix
                or self.manual_recovery_available
            ):
                raise StatePersistenceError(
                    "unnecessary Terraform state safeguard report conflicts"
                )
        else:
            for optional_label, optional_value in (
                (
                    "Terraform authorization artifact digest",
                    self.authorization_artifact_digest,
                ),
                ("Terraform authorization digest", self.authorization_digest),
                ("Terraform safeguard artifact digest", self.safeguard_artifact_digest),
                ("Terraform safeguard digest", self.safeguard_digest),
            ):
                if optional_value is None:
                    raise StatePersistenceError(
                        "Terraform state safeguard report binding is missing"
                    )
                validate_digest(optional_value, optional_label)
            if (
                self.authorization_schema_version
                != TERRAFORM_APPLY_AUTHORIZATION_SCHEMA_VERSION
                or self.safeguard_schema_version
                != TERRAFORM_STATE_SAFEGUARD_SCHEMA_VERSION
                or self.recovery_policy is None
                or self.authorization_state
                is not TerraformApplyAuthorizationState.AUTHORIZED_PRE_EXECUTION
                or not self.apply_required
                or self.authorization_consumption != _AUTHORIZATION_CONSUMPTION
            ):
                raise StatePersistenceError(
                    "Terraform state safeguard report binding conflicts"
                )
            if self.state_identity.presence is TerraformStatePresence.PRESENT:
                if (
                    self.backup_state is TerraformStateBackupState.NOT_REQUIRED
                    or self.backup_digest is None
                    or self.backup_size_bytes is None
                    or not self.manual_recovery_available
                ):
                    raise StatePersistenceError(
                        "Terraform state safeguard report backup conflicts"
                    )
                validate_digest(self.backup_digest, "Terraform state backup digest")
            elif (
                self.backup_state is not TerraformStateBackupState.NOT_REQUIRED
                or self.backup_digest is not None
                or self.backup_size_bytes is not None
                or self.manual_recovery_available
            ):
                raise StatePersistenceError(
                    "Terraform absent-state safeguard report conflicts"
                )
        if (
            self.execution_intent != _EXECUTION_INTENT
            or self.apply_execution != _APPLY_EXECUTION
            or self.destructive_boundary != _DESTRUCTIVE_BOUNDARY
            or self.automatic_restore_performed
            or self.automatic_retry_allowed
            or not self.idempotent_reentry_allowed
        ):
            raise StatePersistenceError(
                "Terraform state safeguard report safety state conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "authorization": {
                "artifact_digest": self.authorization_artifact_digest,
                "consumption": self.authorization_consumption,
                "digest": self.authorization_digest,
                "schema_version": self.authorization_schema_version,
                "state": self.authorization_state.value,
            },
            "execution": {
                "apply": self.apply_execution,
                "apply_command_available": False,
                "apply_required": self.apply_required,
                "destructive_boundary": self.destructive_boundary,
                "intent": self.execution_intent,
            },
            "operation": {"id": str(self.operation_id), "kind": _OPERATION},
            "provenance": {
                "checkpoint": {
                    "artifact_digest": self.checkpoint_artifact_digest,
                    "digest": self.checkpoint_digest,
                    "schema_version": self.checkpoint_schema_version,
                },
                "journal": {
                    "digest": self.journal_digest,
                    "generation": self.journal_generation,
                    "phase": OperationPhase.PLAN.value,
                    "schema_version": self.journal_schema_version,
                    "status": JournalStatus.IN_PROGRESS.value,
                },
                "review": {
                    "digest": self.review_digest,
                    "schema_version": self.review_schema_version,
                },
            },
            "recovery": {
                "automatic_restore_performed": self.automatic_restore_performed,
                "automatic_retry_allowed": self.automatic_retry_allowed,
                "idempotent_reentry_allowed": self.idempotent_reentry_allowed,
                "manual_recovery_available": self.manual_recovery_available,
                "policy": (
                    None if self.recovery_policy is None else self.recovery_policy.value
                ),
                "recovered_backup_prefix": self.recovered_backup_prefix,
            },
            "result": self.result.value,
            "safeguard": {
                "artifact_digest": self.safeguard_artifact_digest,
                "backup": {
                    "digest": self.backup_digest,
                    "size_bytes": self.backup_size_bytes,
                    "state": self.backup_state.value,
                },
                "digest": self.safeguard_digest,
                "schema_version": self.safeguard_schema_version,
            },
            "schema_version": self.schema_version,
            "state": self.state_identity.to_object(),
        }


def safeguard_deploy_apply_state(
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> TerraformStateSafeguardReport:
    """Safeguard exact canonical state after authorization, without applying."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "Terraform state safeguard operation ID must be a UUID"
        )
    paths = StatePaths.derive(state_root, cluster_name)
    _assert_operation_lock(lock, paths)
    _validate_initialized_layout(paths)
    _refuse_ambiguous_operation_artifacts(paths, operation_id)
    _refuse_ambiguous_plan_artifacts(paths, operation_id)
    _refuse_ambiguous_backup_artifacts(paths, operation_id)

    metadata, journal, checkpoint, review_digest = _load_reviewed_plan(
        paths, operation_id, lock
    )
    safeguard_store = TerraformStateSafeguardStore(paths, operation_id)
    backup_store = TerraformStateBackupStore(paths, operation_id)
    authorization_path = terraform_apply_authorization_path(paths, operation_id)
    validate_state_file(safeguard_store.path, allow_missing=True)
    validate_state_file(backup_store.path, allow_missing=True)
    validate_state_file(authorization_path, allow_missing=True)

    if checkpoint.record.summary.change_class is TerraformPlanChangeClass.NO_CHANGES:
        _require_no_change_safeguard_absence(
            checkpoint=checkpoint,
            authorization_path=authorization_path,
            safeguard_path=safeguard_store.path,
            backup_path=backup_store.path,
        )
        return _not_required_report(
            operation_id=operation_id,
            journal=journal,
            checkpoint=checkpoint,
            review_digest=review_digest,
        )

    if not authorization_path.exists():
        raise StateConflictError(
            "Terraform state safeguard requires exact unconsumed apply authorization"
        )
    authorization = TerraformApplyAuthorizationStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )
    _require_exact_authorization(
        metadata=metadata,
        journal=journal,
        checkpoint=checkpoint,
        review_digest=review_digest,
        authorization=authorization,
    )

    expected_identity = checkpoint.record.state_identity
    if expected_identity.presence is TerraformStatePresence.ABSENT:
        return _safeguard_absent_state(
            paths=paths,
            operation_id=operation_id,
            lock=lock,
            metadata=metadata,
            journal=journal,
            checkpoint=checkpoint,
            review_digest=review_digest,
            authorization=authorization,
            safeguard_store=safeguard_store,
            backup_store=backup_store,
        )
    return _safeguard_present_state(
        paths=paths,
        operation_id=operation_id,
        lock=lock,
        metadata=metadata,
        journal=journal,
        checkpoint=checkpoint,
        review_digest=review_digest,
        authorization=authorization,
        safeguard_store=safeguard_store,
        backup_store=backup_store,
    )


def terraform_state_safeguard_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    """Return the sole canonical path for an operation's safeguard record."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "Terraform state safeguard operation ID must be a UUID"
        )
    path = (
        paths.terraform_plans
        / f"{operation_id}{TERRAFORM_STATE_SAFEGUARD_FILENAME_SUFFIX}"
    )
    if path.parent != paths.terraform_plans or path.resolve(strict=False) != path:
        raise UnsafePathError("Terraform state safeguard path is not canonical")
    return path


def terraform_state_backup_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    """Return the sole canonical operation backup path."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "Terraform state backup operation ID must be a UUID"
        )
    path = (
        paths.terraform_backups
        / f"{operation_id}{TERRAFORM_STATE_BACKUP_FILENAME_SUFFIX}"
    )
    if path.parent != paths.terraform_backups or path.resolve(strict=False) != path:
        raise UnsafePathError("Terraform state backup path is not canonical")
    return path


def _safeguard_present_state(
    *,
    paths: StatePaths,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    metadata: StoredClusterMetadata,
    journal: StoredOperationRecord,
    checkpoint: StoredTerraformPlanCheckpoint,
    review_digest: str,
    authorization: StoredTerraformApplyAuthorization,
    safeguard_store: TerraformStateSafeguardStore,
    backup_store: TerraformStateBackupStore,
) -> TerraformStateSafeguardReport:
    if safeguard_store.path.exists() and not backup_store.path.exists():
        raise StateConflictError(
            "Terraform state safeguard record exists without its required backup"
        )
    with _StateSnapshot.open(paths) as snapshot:
        if snapshot.identity != checkpoint.record.state_identity:
            raise StateConflictError(
                "Terraform state changed after reviewed plan authorization"
            )
        backup_existed = backup_store.path.exists()
        if backup_existed:
            backup, backup_raw = backup_store.read()
            if backup_raw != snapshot.raw:
                raise StateConflictError(
                    "Terraform state safeguard backup conflicts with current state"
                )
            backup_state = TerraformStateBackupState.REUSED
        else:
            if safeguard_store.path.exists():
                raise StateConflictError(
                    "Terraform state safeguard record is missing its backup"
                )
            snapshot.ensure_current()
            backup = backup_store.write_locked(snapshot.raw, lock=lock)
            backup_state = TerraformStateBackupState.CREATED
        if backup.digest != snapshot.identity.state_digest or backup.size_bytes != len(
            snapshot.raw
        ):
            raise StateConflictError(
                "Terraform state safeguard backup digest conflicts"
            )
        snapshot.ensure_current()
        current = _reload_exact_bindings(
            paths=paths,
            operation_id=operation_id,
            lock=lock,
            expected_authorization=authorization,
        )
        metadata, journal, checkpoint, review_digest, authorization = current
        snapshot.ensure_current()
        if snapshot.identity != checkpoint.record.state_identity:
            raise StateConflictError(
                "Terraform state changed before safeguard persistence"
            )
        stored, result = _persist_or_reuse_safeguard(
            lock=lock,
            metadata=metadata,
            journal=journal,
            checkpoint=checkpoint,
            review_digest=review_digest,
            authorization=authorization,
            safeguard_store=safeguard_store,
            backup=backup,
        )
    return _completed_report(
        result=result,
        backup_state=backup_state,
        recovered_backup_prefix=backup_existed
        and result is TerraformStateSafeguardResult.CREATED,
        journal=journal,
        checkpoint=checkpoint,
        review_digest=review_digest,
        authorization=authorization,
        stored=stored,
    )


def _safeguard_absent_state(
    *,
    paths: StatePaths,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    metadata: StoredClusterMetadata,
    journal: StoredOperationRecord,
    checkpoint: StoredTerraformPlanCheckpoint,
    review_digest: str,
    authorization: StoredTerraformApplyAuthorization,
    safeguard_store: TerraformStateSafeguardStore,
    backup_store: TerraformStateBackupStore,
) -> TerraformStateSafeguardReport:
    if (
        checkpoint.record.summary.change_class
        is not TerraformPlanChangeClass.CREATE_ONLY
        or checkpoint.record.summary.drift_class is not TerraformPlanDriftClass.NONE
    ):
        raise StateConflictError(
            "absent Terraform state safeguard requires a drift-free create-only plan"
        )
    if backup_store.path.exists():
        raise StateConflictError(
            "absent Terraform state has a conflicting safeguard backup"
        )
    validate_state_file(paths.terraform_state_backup, allow_missing=True)
    if paths.terraform_state_backup.exists():
        raise StateConflictError(
            "absent Terraform state has conflicting canonical backup metadata"
        )
    current_identity = capture_terraform_state_identity(paths)
    refuse_unexpected_terraform_state(paths, (paths.cluster_root,))
    if current_identity.presence is not TerraformStatePresence.ABSENT:
        raise StateConflictError(
            "canonical Terraform state appeared before absent-state safeguard"
        )
    current = _reload_exact_bindings(
        paths=paths,
        operation_id=operation_id,
        lock=lock,
        expected_authorization=authorization,
    )
    metadata, journal, checkpoint, review_digest, authorization = current
    if (
        capture_terraform_state_identity(paths).presence
        is not TerraformStatePresence.ABSENT
        or backup_store.path.exists()
        or paths.terraform_state_backup.exists()
    ):
        raise StateConflictError(
            "canonical Terraform state changed before absent-state persistence"
        )
    stored, result = _persist_or_reuse_safeguard(
        lock=lock,
        metadata=metadata,
        journal=journal,
        checkpoint=checkpoint,
        review_digest=review_digest,
        authorization=authorization,
        safeguard_store=safeguard_store,
        backup=None,
    )
    return _completed_report(
        result=result,
        backup_state=TerraformStateBackupState.NOT_REQUIRED,
        recovered_backup_prefix=False,
        journal=journal,
        checkpoint=checkpoint,
        review_digest=review_digest,
        authorization=authorization,
        stored=stored,
    )


def _persist_or_reuse_safeguard(
    *,
    lock: ClusterLock,
    metadata: StoredClusterMetadata,
    journal: StoredOperationRecord,
    checkpoint: StoredTerraformPlanCheckpoint,
    review_digest: str,
    authorization: StoredTerraformApplyAuthorization,
    safeguard_store: TerraformStateSafeguardStore,
    backup: StoredTerraformStateBackup | None,
) -> tuple[StoredTerraformStateSafeguard, TerraformStateSafeguardResult]:
    if safeguard_store.path.exists():
        stored = safeguard_store.read(
            expected_cluster_uuid=metadata.record.cluster_uuid,
            expected_cluster_name=metadata.record.cluster_name,
        )
        expected = _create_safeguard(
            metadata=metadata,
            journal=journal,
            checkpoint=checkpoint,
            review_digest=review_digest,
            authorization=authorization,
            backup=backup,
            created_at=stored.record.created_at,
        )
        if stored.record != expected:
            raise StateConflictError(
                "Terraform state safeguard changed; create a new plan and operation"
            )
        return stored, TerraformStateSafeguardResult.REUSED
    record = _create_safeguard(
        metadata=metadata,
        journal=journal,
        checkpoint=checkpoint,
        review_digest=review_digest,
        authorization=authorization,
        backup=backup,
        created_at=format_timestamp(datetime.now(UTC)),
    )
    return (
        safeguard_store.write_locked(record, lock=lock),
        TerraformStateSafeguardResult.CREATED,
    )


def _create_safeguard(
    *,
    metadata: StoredClusterMetadata,
    journal: StoredOperationRecord,
    checkpoint: StoredTerraformPlanCheckpoint,
    review_digest: str,
    authorization: StoredTerraformApplyAuthorization,
    backup: StoredTerraformStateBackup | None,
    created_at: str,
) -> TerraformStateSafeguard:
    record = checkpoint.record
    state_identity = record.state_identity
    recovery_policy = (
        TerraformStateRecoveryPolicy.RESTORE_EXACT_BACKUP_BEFORE_REPLAN
        if state_identity.presence is TerraformStatePresence.PRESENT
        else TerraformStateRecoveryPolicy.VERIFIED_ABSENT_INITIAL_STATE
    )
    values: dict[str, object] = {
        "absent_proof_digest": None,
        "apply_execution": _APPLY_EXECUTION,
        "apply_required": True,
        "authorization_artifact_digest": authorization.artifact_digest,
        "authorization_consumption": _AUTHORIZATION_CONSUMPTION,
        "authorization_digest": authorization.record.authorization_digest,
        "authorization_generation": authorization.record.generation,
        "authorization_schema_version": authorization.record.schema_version,
        "backend_digest": _backend_digest(record.backend_kind, state_identity),
        "backend_kind": record.backend_kind,
        "backup_digest": None if backup is None else backup.digest,
        "backup_size_bytes": None if backup is None else backup.size_bytes,
        "checkpoint_artifact_digest": checkpoint.digest,
        "checkpoint_digest": record.checkpoint_digest,
        "checkpoint_generation": record.generation,
        "checkpoint_schema_version": record.schema_version,
        "cluster_name": record.cluster_name,
        "cluster_uuid": str(record.cluster_uuid),
        "created_at": created_at,
        "desired_spec_digest": record.desired_spec_digest,
        "destructive_boundary": _DESTRUCTIVE_BOUNDARY,
        "execution_intent": _EXECUTION_INTENT,
        "generation": 1,
        "input_digest": record.input_digest,
        "journal_digest": journal.digest,
        "journal_generation": journal.record.generation,
        "journal_schema_version": journal.record.schema_version,
        "metadata_digest": metadata.digest,
        "metadata_generation": metadata.record.generation,
        "operation": record.operation,
        "operation_classification": record.classification.value,
        "operation_id": str(record.operation_id),
        "plan_binary_digest": record.plan_binary_digest,
        "plan_change_class": record.summary.change_class.value,
        "plan_drift_class": record.summary.drift_class.value,
        "plan_format_version": record.summary.format_version,
        "plan_json_digest": record.plan_json_digest,
        "recovery_policy": recovery_policy.value,
        "request_digest": record.request_digest,
        "review_digest": review_digest,
        "review_schema_version": TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION,
        "safeguard_digest": "sha256:" + "0" * 64,
        "schema_version": TERRAFORM_STATE_SAFEGUARD_SCHEMA_VERSION,
        "source_bundle_digest": record.source_bundle_digest,
        "source_digest": record.source_digest,
        "source_generation": record.source_generation,
        "source_version": record.source_version,
        "state_identity": state_identity.to_object(),
        "state_identity_digest": _state_identity_digest(state_identity),
        "terraform_version": record.summary.terraform_version,
        "tfvars_digest": record.tfvars_digest,
        "tfvars_generation": record.tfvars_generation,
        "toolchain_digest": _toolchain_digest(
            record.summary.terraform_version, record.summary.format_version
        ),
    }
    if state_identity.presence is TerraformStatePresence.ABSENT:
        values["absent_proof_digest"] = _absent_proof_digest_object(values)
    values["safeguard_digest"] = _safeguard_digest_object(values)
    return TerraformStateSafeguard.from_object(values)


def _load_reviewed_plan(
    paths: StatePaths,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> tuple[
    StoredClusterMetadata,
    StoredOperationRecord,
    StoredTerraformPlanCheckpoint,
    str,
]:
    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name=paths.cluster_root.name,
        expected_provider="oci",
    )
    journal = OperationJournalStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )
    review = TerraformPlanCheckpointService(paths).revalidate_canonical_locked(
        operation_id=operation_id,
        operation=_OPERATION,
        lock=lock,
    )
    checkpoint = TerraformPlanCheckpointStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_operation=_OPERATION,
    )
    _require_exact_composed_plan(metadata, journal, checkpoint)
    return (
        metadata,
        journal,
        checkpoint,
        digest_bytes(serialize_json(review.to_object())),
    )


def _reload_exact_bindings(
    *,
    paths: StatePaths,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    expected_authorization: StoredTerraformApplyAuthorization,
) -> tuple[
    StoredClusterMetadata,
    StoredOperationRecord,
    StoredTerraformPlanCheckpoint,
    str,
    StoredTerraformApplyAuthorization,
]:
    _validate_initialized_layout(paths)
    metadata, journal, checkpoint, review_digest = _load_reviewed_plan(
        paths, operation_id, lock
    )
    authorization = TerraformApplyAuthorizationStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )
    _require_exact_authorization(
        metadata=metadata,
        journal=journal,
        checkpoint=checkpoint,
        review_digest=review_digest,
        authorization=authorization,
    )
    if authorization != expected_authorization:
        raise StateConflictError(
            "Terraform apply authorization changed before state safeguard persistence"
        )
    return metadata, journal, checkpoint, review_digest, authorization


def _require_exact_authorization(
    *,
    metadata: StoredClusterMetadata,
    journal: StoredOperationRecord,
    checkpoint: StoredTerraformPlanCheckpoint,
    review_digest: str,
    authorization: StoredTerraformApplyAuthorization,
) -> None:
    record = authorization.record
    plan = checkpoint.record
    if (
        record.cluster_uuid != metadata.record.cluster_uuid
        or record.cluster_name != metadata.record.cluster_name
        or record.operation_id != plan.operation_id
        or record.operation != plan.operation
        or record.operation_classification is not plan.classification
        or record.request_digest != plan.request_digest
        or record.journal_schema_version != journal.record.schema_version
        or record.journal_generation != journal.record.generation
        or record.journal_digest != journal.digest
        or record.journal_status is not JournalStatus.IN_PROGRESS
        or record.journal_phase is not OperationPhase.PLAN
        or record.checkpoint_schema_version != plan.schema_version
        or record.checkpoint_generation != plan.generation
        or record.checkpoint_artifact_digest != checkpoint.digest
        or record.checkpoint_digest != plan.checkpoint_digest
        or record.review_schema_version != TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
        or record.review_digest != review_digest
        or record.metadata_generation != metadata.record.generation
        or record.metadata_digest != metadata.digest
        or record.desired_spec_digest != plan.desired_spec_digest
        or record.tfvars_generation != plan.tfvars_generation
        or record.tfvars_digest != plan.tfvars_digest
        or record.input_digest != plan.input_digest
        or record.source_generation != plan.source_generation
        or record.source_digest != plan.source_digest
        or record.source_version != plan.source_version
        or record.source_bundle_digest != plan.source_bundle_digest
        or record.backend_kind != plan.backend_kind
        or record.backend_digest
        != _backend_digest(plan.backend_kind, plan.state_identity)
        or record.state_identity != plan.state_identity
        or record.state_identity_digest != _state_identity_digest(plan.state_identity)
        or record.terraform_version != plan.summary.terraform_version
        or record.plan_format_version != plan.summary.format_version
        or record.toolchain_digest
        != _toolchain_digest(
            plan.summary.terraform_version, plan.summary.format_version
        )
        or record.plan_binary_digest != plan.plan_binary_digest
        or record.plan_json_digest != plan.plan_json_digest
        or record.summary != plan.summary
        or record.authorization_state
        is not TerraformApplyAuthorizationState.AUTHORIZED_PRE_EXECUTION
        or not record.apply_required
        or record.execution_intent != _EXECUTION_INTENT
        or record.apply_execution != _APPLY_EXECUTION
        or record.state_backup != "unavailable"
        or record.destructive_boundary != _DESTRUCTIVE_BOUNDARY
    ):
        raise StateConflictError(
            "Terraform state safeguard authorization binding is stale or consumed"
        )


def _require_exact_composed_plan(
    metadata: StoredClusterMetadata,
    journal: StoredOperationRecord,
    checkpoint: StoredTerraformPlanCheckpoint,
) -> None:
    record = checkpoint.record
    expected_event = CheckpointEvidence(
        phase=OperationPhase.PLAN,
        result=EvidenceResult.VALIDATED,
        digest=record.checkpoint_digest,
        summary_code=_PLAN_SUMMARY_CODE,
    )
    if (
        record.operation != _OPERATION
        or record.operation_id != journal.record.operation_id
        or record.classification is not OperationClassification.MUTATING
        or record.cluster_uuid != metadata.record.cluster_uuid
        or record.cluster_name != metadata.record.cluster_name
        or record.request_digest != metadata.record.provenance.request_digest
        or record.metadata_generation != metadata.record.generation
        or record.metadata_digest != metadata.digest
        or record.desired_spec_digest != metadata.record.desired_spec.digest()
        or journal.record.operation != _OPERATION
        or journal.record.operation_id != record.operation_id
        or journal.record.cluster_uuid != record.cluster_uuid
        or journal.record.cluster_name != record.cluster_name
        or journal.record.request_digest != record.request_digest
        or journal.record.generation != record.journal_generation + 1
        or journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.PLAN
        or journal.record.resume_revalidation_digest is not None
        or journal.record.evidence != (expected_event,)
    ):
        raise StateConflictError(
            "Terraform state safeguard requires the exact composed PLAN checkpoint"
        )
    preimage = OperationRecord(
        generation=record.journal_generation,
        operation_id=journal.record.operation_id,
        operation=journal.record.operation,
        cluster_uuid=journal.record.cluster_uuid,
        cluster_name=journal.record.cluster_name,
        status=JournalStatus.IN_PROGRESS,
        phase=OperationPhase.PLAN,
        created_at=journal.record.created_at,
        updated_at=journal.record.created_at,
        request_digest=journal.record.request_digest,
        resume_revalidation_digest=None,
        evidence=(),
    )
    if digest_bytes(serialize_json(preimage.to_object())) != record.journal_digest:
        raise StateConflictError("Terraform state safeguard PLAN preimage conflicts")


def _require_no_change_safeguard_absence(
    *,
    checkpoint: StoredTerraformPlanCheckpoint,
    authorization_path: Path,
    safeguard_path: Path,
    backup_path: Path,
) -> None:
    if checkpoint.record.summary.drift_class is not TerraformPlanDriftClass.NONE:
        raise StateConflictError(
            "no-change Terraform plan with refresh drift requires reconciliation"
        )
    if authorization_path.exists():
        raise StateConflictError(
            "no-change Terraform plan has a forbidden authorization record"
        )
    if safeguard_path.exists() or backup_path.exists():
        raise StateConflictError(
            "no-change Terraform plan has a forbidden state safeguard artifact"
        )


def _not_required_report(
    *,
    operation_id: uuid.UUID,
    journal: StoredOperationRecord,
    checkpoint: StoredTerraformPlanCheckpoint,
    review_digest: str,
) -> TerraformStateSafeguardReport:
    return TerraformStateSafeguardReport(
        operation_id=operation_id,
        result=TerraformStateSafeguardResult.NOT_REQUIRED,
        backup_state=TerraformStateBackupState.NOT_REQUIRED,
        state_identity=checkpoint.record.state_identity,
        journal_generation=journal.record.generation,
        journal_digest=journal.digest,
        checkpoint_artifact_digest=checkpoint.digest,
        checkpoint_digest=checkpoint.record.checkpoint_digest,
        review_digest=review_digest,
        authorization_artifact_digest=None,
        authorization_digest=None,
        safeguard_artifact_digest=None,
        safeguard_digest=None,
        backup_digest=None,
        backup_size_bytes=None,
        recovery_policy=None,
        recovered_backup_prefix=False,
        authorization_state=TerraformApplyAuthorizationState.NOT_REQUIRED,
        apply_required=False,
        authorization_consumption=_AUTHORIZATION_NOT_REQUIRED,
    )


def _completed_report(
    *,
    result: TerraformStateSafeguardResult,
    backup_state: TerraformStateBackupState,
    recovered_backup_prefix: bool,
    journal: StoredOperationRecord,
    checkpoint: StoredTerraformPlanCheckpoint,
    review_digest: str,
    authorization: StoredTerraformApplyAuthorization,
    stored: StoredTerraformStateSafeguard,
) -> TerraformStateSafeguardReport:
    record = stored.record
    return TerraformStateSafeguardReport(
        operation_id=record.operation_id,
        result=result,
        backup_state=backup_state,
        state_identity=record.state_identity,
        journal_generation=journal.record.generation,
        journal_digest=journal.digest,
        checkpoint_artifact_digest=checkpoint.digest,
        checkpoint_digest=checkpoint.record.checkpoint_digest,
        review_digest=review_digest,
        authorization_artifact_digest=authorization.artifact_digest,
        authorization_digest=authorization.record.authorization_digest,
        safeguard_artifact_digest=stored.artifact_digest,
        safeguard_digest=record.safeguard_digest,
        backup_digest=record.backup_digest,
        backup_size_bytes=record.backup_size_bytes,
        recovery_policy=record.recovery_policy,
        recovered_backup_prefix=recovered_backup_prefix,
        authorization_state=authorization.record.authorization_state,
        apply_required=authorization.record.apply_required,
        authorization_schema_version=authorization.record.schema_version,
        safeguard_schema_version=record.schema_version,
        manual_recovery_available=(
            record.state_identity.presence is TerraformStatePresence.PRESENT
        ),
    )


class _StateSnapshot:
    """Keep the canonical state and parent descriptors stable through backup."""

    def __init__(
        self,
        paths: StatePaths,
        directory_descriptor: int,
        state_descriptor: int,
        directory_stat: os.stat_result,
        state_stat: os.stat_result,
        raw: bytes,
        identity: TerraformStateIdentity,
    ) -> None:
        self._paths = paths
        self._directory_descriptor = directory_descriptor
        self._state_descriptor = state_descriptor
        self._directory_stat = directory_stat
        self._state_stat = state_stat
        self.raw = raw
        self.identity = identity

    @classmethod
    def open(cls, paths: StatePaths) -> _StateSnapshot:
        if (
            os.name != "posix"
            or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_DIRECTORY")
            or os.open not in os.supports_dir_fd
            or os.stat not in os.supports_dir_fd
        ):
            raise StatePersistenceError(
                "secure Terraform state safeguard access is unavailable"
            )
        validate_state_directory(paths.terraform)
        validate_state_file(paths.terraform_state)
        directory_descriptor = -1
        state_descriptor = -1
        try:
            directory_descriptor = os.open(
                paths.terraform,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            directory_stat = os.fstat(directory_descriptor)
            _require_named_identity(paths.terraform, directory_stat, directory=True)
            state_descriptor = os.open(
                paths.terraform_state.name,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=directory_descriptor,
            )
            state_stat = os.fstat(state_descriptor)
            _validate_open_owner_file(state_stat, "Terraform state")
            raw = _read_descriptor(
                state_descriptor,
                maximum_bytes=_MAXIMUM_STATE_BYTES,
                label="Terraform state",
            )
            after = os.fstat(state_descriptor)
            if _stat_identity(state_stat) != _stat_identity(after):
                raise UnsafePathError("Terraform state changed during access")
            identity = _state_identity_from_bytes(raw)
            snapshot = cls(
                paths,
                directory_descriptor,
                state_descriptor,
                directory_stat,
                state_stat,
                raw,
                identity,
            )
            snapshot.ensure_current()
            return snapshot
        except Exception:
            if state_descriptor >= 0:
                os.close(state_descriptor)
            if directory_descriptor >= 0:
                os.close(directory_descriptor)
            raise

    def __enter__(self) -> _StateSnapshot:
        return self

    def __exit__(self, *args: object) -> None:
        os.close(self._state_descriptor)
        os.close(self._directory_descriptor)

    def ensure_current(self) -> None:
        directory_now = os.fstat(self._directory_descriptor)
        state_now = os.fstat(self._state_descriptor)
        if _stat_identity(self._directory_stat) != _stat_identity(directory_now):
            raise UnsafePathError("Terraform state directory changed during safeguard")
        if _stat_identity(self._state_stat) != _stat_identity(state_now):
            raise UnsafePathError("Terraform state changed during safeguard")
        _require_named_identity(self._paths.terraform, directory_now, directory=True)
        try:
            named_state = os.stat(
                self._paths.terraform_state.name,
                dir_fd=self._directory_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise UnsafePathError("Terraform state changed during safeguard") from error
        if stat.S_ISLNK(named_state.st_mode) or (
            named_state.st_dev,
            named_state.st_ino,
        ) != (state_now.st_dev, state_now.st_ino):
            raise UnsafePathError("Terraform state changed during safeguard")
        _validate_open_owner_file(state_now, "Terraform state")


def _state_identity_from_bytes(raw: bytes) -> TerraformStateIdentity:
    try:
        state = _parse_state_identity_fields(raw)
    except (UnicodeDecodeError, ValueError, StatePersistenceError) as error:
        raise StatePersistenceError("Terraform state JSON is malformed") from error
    state_format = state.get("version")
    terraform_version = state.get("terraform_version")
    serial = state.get("serial")
    lineage = state.get("lineage")
    if (
        isinstance(state_format, bool)
        or not isinstance(state_format, int)
        or state_format < 1
        or not isinstance(terraform_version, str)
        or isinstance(serial, bool)
        or not isinstance(serial, int)
        or serial < 0
        or not isinstance(lineage, str)
    ):
        raise StatePersistenceError("Terraform state identity fields are invalid")
    try:
        lineage_uuid = uuid.UUID(lineage)
    except ValueError as error:
        raise StatePersistenceError("Terraform state lineage is invalid") from error
    if str(lineage_uuid) != lineage:
        raise StatePersistenceError("Terraform state lineage is not canonical")
    # Reuse the established identity/version validation without projecting values.
    return TerraformStateIdentity(
        TerraformStatePresence.PRESENT,
        state_format,
        terraform_version,
        serial,
        digest_bytes(lineage.encode("utf-8")),
        digest_bytes(raw),
    )


def _write_immutable_bytes(
    path: Path,
    raw: bytes,
    *,
    token_factory: Callable[[], str],
) -> None:
    if (
        os.name != "posix"
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.link not in os.supports_dir_fd
        or os.unlink not in os.supports_dir_fd
    ):
        raise StatePersistenceError(
            "secure immutable Terraform state backup creation is unavailable"
        )
    validate_state_directory(path.parent)
    token = token_factory()
    if not token or not token.isascii() or not token.isalnum():
        raise StatePersistenceError("temporary-file token is invalid")
    temporary_name = f".{path.name}.{token}.tmp"
    directory_descriptor: int | None = None
    descriptor: int | None = None
    created = False
    published = False
    try:
        directory_descriptor = os.open(
            path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        directory_stat = os.fstat(directory_descriptor)
        _require_named_identity(path.parent, directory_stat, directory=True)
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            _FILE_MODE,
            dir_fd=directory_descriptor,
        )
        created = True
        os.fchmod(descriptor, _FILE_MODE)
        _write_all(descriptor, raw)
        os.fsync(descriptor)
        temporary_stat = os.fstat(descriptor)
        _validate_open_owner_file(temporary_stat, "temporary Terraform state backup")
        named_temporary = os.stat(
            temporary_name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if stat.S_ISLNK(named_temporary.st_mode) or (
            named_temporary.st_dev,
            named_temporary.st_ino,
        ) != (temporary_stat.st_dev, temporary_stat.st_ino):
            raise UnsafePathError(
                "temporary Terraform state backup changed during creation"
            )
        try:
            os.stat(
                path.name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise StatePersistenceError(
                "Terraform state safeguard backup appeared concurrently"
            )
        os.link(
            temporary_name,
            path.name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        published = True
        os.unlink(temporary_name, dir_fd=directory_descriptor)
        created = False
        published_stat = os.fstat(descriptor)
        _validate_open_owner_file(published_stat, "Terraform state safeguard backup")
        named_backup = os.stat(
            path.name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if stat.S_ISLNK(named_backup.st_mode) or (
            named_backup.st_dev,
            named_backup.st_ino,
        ) != (published_stat.st_dev, published_stat.st_ino):
            raise UnsafePathError(
                "Terraform state safeguard backup changed during publication"
            )
        _require_named_identity(path.parent, directory_stat, directory=True)
        os.close(descriptor)
        descriptor = None
        os.fsync(directory_descriptor)
    except FileExistsError as error:
        raise StatePersistenceError(
            "Terraform state safeguard backup appeared concurrently"
        ) from error
    except OSError as error:
        if published:
            raise StatePersistenceError(
                "Terraform state backup publication is durability-ambiguous"
            ) from error
        raise StatePersistenceError("Terraform state backup write failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_descriptor is not None and created and not published:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=directory_descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def _read_owner_file(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    validate_state_file(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StatePersistenceError(f"cannot safely open {label}") from error
    try:
        before = os.fstat(descriptor)
        _validate_open_owner_file(before, label)
        _require_named_identity(path, before, directory=False)
        raw = _read_descriptor(descriptor, maximum_bytes=maximum_bytes, label=label)
        after = os.fstat(descriptor)
        if _stat_identity(before) != _stat_identity(after):
            raise UnsafePathError(f"{label} changed during access")
        _require_named_identity(path, after, directory=False)
        return raw
    finally:
        os.close(descriptor)


def _read_descriptor(descriptor: int, *, maximum_bytes: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        total += len(chunk)
        if total > maximum_bytes:
            raise StatePersistenceError(f"{label} exceeds the size limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _validate_open_owner_file(opened: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
        raise UnsafePathError(f"{label} must be a singly linked regular file")
    if os.name == "posix":
        getuid = getattr(os, "geteuid", None)
        if getuid is not None and opened.st_uid != getuid():
            raise UnsafePathError(f"{label} has an unexpected owner")
        if stat.S_IMODE(opened.st_mode) != _FILE_MODE:
            raise UnsafePathError(f"{label} permissions must be 0600")


def _require_named_identity(
    path: Path, opened: os.stat_result, *, directory: bool
) -> None:
    try:
        named = path.lstat()
    except OSError as error:
        raise UnsafePathError("managed state path changed during access") from error
    expected_type = (
        stat.S_ISDIR(named.st_mode) if directory else stat.S_ISREG(named.st_mode)
    )
    if (
        stat.S_ISLNK(named.st_mode)
        or not expected_type
        or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        raise UnsafePathError("managed state path changed during access")


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _write_all(descriptor: int, raw: bytes) -> None:
    remaining = memoryview(raw)
    while remaining:
        written = os.write(descriptor, remaining)
        if written == 0:
            raise StatePersistenceError("Terraform state backup write made no progress")
        remaining = remaining[written:]


def _validate_initialized_layout(paths: StatePaths) -> None:
    _require_canonical_paths(paths)
    for directory in paths.directory_paths:
        validate_state_directory(directory)
    validate_state_file(paths.cluster_metadata)
    validate_state_file(paths.terraform_tfvars)
    validate_state_file(paths.terraform_source_record)
    validate_state_file(paths.terraform_state, allow_missing=True)
    refuse_unexpected_terraform_state(paths, (paths.cluster_root,))


def _require_canonical_paths(paths: StatePaths) -> None:
    expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
    if (
        expected != paths
        or paths.terraform_plans.parent != paths.terraform
        or paths.terraform_backups.parent != paths.terraform
    ):
        raise UnsafePathError("Terraform state safeguard paths are not canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Terraform state safeguard requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_operation_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    allowed = {paths.operations / f"{operation_id}.json"}
    for entry in _directory_entries(paths.operations, "operation"):
        validate_state_file(entry)
        if str(operation_id) in entry.name and entry not in allowed:
            raise StateConflictError(
                "Terraform state safeguard operation history is ambiguous"
            )


def _refuse_ambiguous_plan_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    allowed = {
        paths.terraform_plans / f"{operation_id}.tfplan",
        paths.terraform_plans / f"{operation_id}.terraform-plan.json",
        terraform_apply_authorization_path(paths, operation_id),
        terraform_state_safeguard_path(paths, operation_id),
    }
    for entry in _directory_entries(paths.terraform_plans, "Terraform plan"):
        validate_state_file(entry)
        if str(operation_id) in entry.name and entry not in allowed:
            raise StateConflictError(
                "Terraform state safeguard plan history is ambiguous"
            )


def _refuse_ambiguous_backup_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    allowed = {terraform_state_backup_path(paths, operation_id)}
    for entry in _directory_entries(paths.terraform_backups, "Terraform backup"):
        validate_state_file(entry)
        if str(operation_id) in entry.name and entry not in allowed:
            raise StateConflictError(
                "Terraform state safeguard backup history is ambiguous"
            )


def _directory_entries(directory: Path, label: str) -> tuple[Path, ...]:
    try:
        return tuple(sorted(directory.iterdir(), key=lambda item: item.name))
    except OSError as error:
        raise StatePersistenceError(f"cannot safely list {label} history") from error


def _backend_digest(kind: str, identity: TerraformStateIdentity) -> str:
    return digest_bytes(
        serialize_json(
            {
                "backend_kind": kind,
                "state_identity_digest": _state_identity_digest(identity),
            }
        )
    )


def _state_identity_digest(identity: TerraformStateIdentity) -> str:
    return digest_bytes(serialize_json(identity.to_object()))


def _toolchain_digest(terraform_version: str, plan_format_version: str) -> str:
    return digest_bytes(
        serialize_json(
            {
                "plan_format_version": plan_format_version,
                "terraform_version": terraform_version,
            }
        )
    )


def _absent_proof_digest(record: TerraformStateSafeguard) -> str:
    return _absent_proof_digest_object(record.to_object())


def _absent_proof_digest_object(values: Mapping[str, object]) -> str:
    state = values["state_identity"]
    if not isinstance(state, dict):
        raise StatePersistenceError("Terraform absent-state proof identity is invalid")
    return digest_bytes(
        serialize_json(
            {
                "authorization_digest": values["authorization_digest"],
                "backend_digest": values["backend_digest"],
                "checkpoint_digest": values["checkpoint_digest"],
                "operation_id": values["operation_id"],
                "plan_change_class": values["plan_change_class"],
                "plan_drift_class": values["plan_drift_class"],
                "recovery_policy": values["recovery_policy"],
                "state_identity": state,
            }
        )
    )


def _safeguard_digest(record: TerraformStateSafeguard) -> str:
    return _safeguard_digest_object(record.to_object())


def _safeguard_digest_object(values: Mapping[str, object]) -> str:
    copied = dict(values)
    copied["safeguard_digest"] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(copied))


def _parse_state_identity_fields(raw: bytes) -> dict[str, object]:
    """Parse only selected top-level state scalars while validating JSON syntax."""

    text = raw.decode("utf-8", errors="strict")
    index = _skip_json_whitespace(text, 0)
    if index >= len(text) or text[index] != "{":
        raise StatePersistenceError("Terraform state must be a JSON object")
    index = _skip_json_whitespace(text, index + 1)
    selected: dict[str, object] = {}
    seen: set[str] = set()
    if index < len(text) and text[index] == "}":
        index = _skip_json_whitespace(text, index + 1)
        if index != len(text):
            raise StatePersistenceError("Terraform state has trailing JSON data")
        return selected
    while True:
        if index >= len(text) or text[index] != '"':
            raise StatePersistenceError("Terraform state object key is invalid")
        key_end = _scan_json_string(text, index)
        key = json.loads(text[index:key_end])
        if not isinstance(key, str):
            raise StatePersistenceError("Terraform state object key is invalid")
        if key in seen:
            raise StatePersistenceError(
                "Terraform state contains duplicate top-level fields"
            )
        seen.add(key)
        index = _skip_json_whitespace(text, key_end)
        if index >= len(text) or text[index] != ":":
            raise StatePersistenceError("Terraform state object entry is invalid")
        value_start = _skip_json_whitespace(text, index + 1)
        value_end = _scan_json_value(text, value_start, depth=1)
        if key in _STATE_IDENTITY_FIELDS:
            value = json.loads(
                text[value_start:value_end],
                parse_constant=_reject_state_constant,
            )
            if isinstance(value, (dict, list)):
                raise StatePersistenceError(
                    "Terraform state identity field must be scalar"
                )
            selected[key] = value
        index = _skip_json_whitespace(text, value_end)
        if index >= len(text):
            raise StatePersistenceError("Terraform state object is incomplete")
        if text[index] == "}":
            index = _skip_json_whitespace(text, index + 1)
            if index != len(text):
                raise StatePersistenceError("Terraform state has trailing JSON data")
            return selected
        if text[index] != ",":
            raise StatePersistenceError("Terraform state object entry is invalid")
        index = _skip_json_whitespace(text, index + 1)


def _scan_json_value(text: str, index: int, *, depth: int) -> int:
    if depth > 128 or index >= len(text):
        raise StatePersistenceError("Terraform state JSON nesting is invalid")
    character = text[index]
    if character == '"':
        return _scan_json_string(text, index)
    if character == "{":
        return _scan_json_object(text, index, depth=depth)
    if character == "[":
        return _scan_json_array(text, index, depth=depth)
    for literal in ("true", "false", "null"):
        if text.startswith(literal, index):
            return index + len(literal)
    match = _JSON_NUMBER.match(text, index)
    if match is not None:
        return match.end()
    raise StatePersistenceError("Terraform state JSON value is invalid")


def _scan_json_string(text: str, index: int) -> int:
    cursor = index + 1
    while cursor < len(text):
        character = text[cursor]
        if character == '"':
            return cursor + 1
        if ord(character) < 0x20:
            raise StatePersistenceError("Terraform state JSON string is invalid")
        if character == "\\":
            cursor += 1
            if cursor >= len(text) or text[cursor] not in '"\\/bfnrtu':
                raise StatePersistenceError("Terraform state JSON escape is invalid")
            if text[cursor] == "u":
                if cursor + 4 >= len(text) or any(
                    item not in "0123456789abcdefABCDEF"
                    for item in text[cursor + 1 : cursor + 5]
                ):
                    raise StatePersistenceError(
                        "Terraform state JSON Unicode escape is invalid"
                    )
                cursor += 4
        cursor += 1
    raise StatePersistenceError("Terraform state JSON string is incomplete")


def _scan_json_object(text: str, index: int, *, depth: int) -> int:
    cursor = _skip_json_whitespace(text, index + 1)
    if cursor < len(text) and text[cursor] == "}":
        return cursor + 1
    while True:
        if cursor >= len(text) or text[cursor] != '"':
            raise StatePersistenceError("Terraform state JSON object key is invalid")
        cursor = _skip_json_whitespace(text, _scan_json_string(text, cursor))
        if cursor >= len(text) or text[cursor] != ":":
            raise StatePersistenceError("Terraform state JSON object entry is invalid")
        cursor = _skip_json_whitespace(
            text,
            _scan_json_value(
                text,
                _skip_json_whitespace(text, cursor + 1),
                depth=depth + 1,
            ),
        )
        if cursor >= len(text):
            raise StatePersistenceError("Terraform state JSON object is incomplete")
        if text[cursor] == "}":
            return cursor + 1
        if text[cursor] != ",":
            raise StatePersistenceError("Terraform state JSON object entry is invalid")
        cursor = _skip_json_whitespace(text, cursor + 1)


def _scan_json_array(text: str, index: int, *, depth: int) -> int:
    cursor = _skip_json_whitespace(text, index + 1)
    if cursor < len(text) and text[cursor] == "]":
        return cursor + 1
    while True:
        cursor = _skip_json_whitespace(
            text,
            _scan_json_value(text, cursor, depth=depth + 1),
        )
        if cursor >= len(text):
            raise StatePersistenceError("Terraform state JSON array is incomplete")
        if text[cursor] == "]":
            return cursor + 1
        if text[cursor] != ",":
            raise StatePersistenceError("Terraform state JSON array entry is invalid")
        cursor = _skip_json_whitespace(text, cursor + 1)


def _skip_json_whitespace(text: str, index: int) -> int:
    while index < len(text) and text[index] in " \t\r\n":
        index += 1
    return index


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _optional_integer(value: Mapping[str, object], name: str) -> int | None:
    item = value[name]
    if item is None:
        return None
    return _integer(item, name)


def _optional_string(value: Mapping[str, object], name: str) -> str | None:
    item = value[name]
    if item is None:
        return None
    if not isinstance(item, str) or not item:
        raise StatePersistenceError(f"{name} must be a non-empty string or null")
    return item


def _reject_state_constant(value: str) -> Any:
    raise StatePersistenceError(f"invalid Terraform state JSON constant: {value}")


__all__ = [
    "TERRAFORM_STATE_BACKUP_FILENAME_SUFFIX",
    "TERRAFORM_STATE_SAFEGUARD_FILENAME_SUFFIX",
    "TERRAFORM_STATE_SAFEGUARD_REPORT_SCHEMA_VERSION",
    "TERRAFORM_STATE_SAFEGUARD_SCHEMA_VERSION",
    "StoredTerraformStateBackup",
    "StoredTerraformStateSafeguard",
    "TerraformStateBackupState",
    "TerraformStateBackupStore",
    "TerraformStateRecoveryPolicy",
    "TerraformStateSafeguard",
    "TerraformStateSafeguardReport",
    "TerraformStateSafeguardResult",
    "TerraformStateSafeguardStore",
    "safeguard_deploy_apply_state",
    "terraform_state_backup_path",
    "terraform_state_safeguard_path",
]
