"""Immutable authorization for one exact reviewed Terraform deploy plan."""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

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
from scylla_vms.terraform.plan import (
    TERRAFORM_PLAN_BACKEND_KIND,
    TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION,
    TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION,
    StoredTerraformPlanCheckpoint,
    TerraformPlanChangeClass,
    TerraformPlanCheckpoint,
    TerraformPlanCheckpointService,
    TerraformPlanCheckpointStore,
    TerraformPlanDriftClass,
    TerraformPlanReviewReport,
    TerraformPlanSummary,
    TerraformStateIdentity,
    TerraformStatePresence,
)

TERRAFORM_APPLY_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-apply-authorization/v1"
)
TERRAFORM_APPLY_AUTHORIZATION_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-apply-authorization-proof/v1"
)
TERRAFORM_APPLY_AUTHORIZATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-apply-authorization-report/v1"
)
TERRAFORM_APPLY_AUTHORIZATION_FILENAME_SUFFIX = ".terraform-apply-authorization.json"

_OPERATION = "deploy"
_PLAN_SUMMARY_CODE = "terraform-plan-reviewed"
_EXECUTION_INTENT = "not-started"
_APPLY_EXECUTION = "unavailable"
_STATE_BACKUP = "unavailable"
_DESTRUCTIVE_BOUNDARY = "not-crossed"


class TerraformApplyAuthorizationClass(StrEnum):
    """Effective class derived exclusively from the reviewed plan."""

    NOT_REQUIRED = "not-required"
    MUTATING = "mutating"
    DESTRUCTIVE = "destructive"


class TerraformApplyOrdinaryApproval(StrEnum):
    """PLAN-defined ordinary approval sources."""

    INTERACTIVE = "interactive"
    CLI_YES = "cli-yes"


class TerraformApplyDriftAcknowledgement(StrEnum):
    """Separate treatment for benign refresh drift in a reviewed plan."""

    NOT_REQUIRED = "not-required"
    INTERACTIVE_REVIEW = "interactive-review"


class TerraformApplyScopeProofState(StrEnum):
    """Whether exact destructive counts and digests were matched."""

    NOT_REQUIRED = "not-required"
    MATCHED = "matched"


class TerraformApplyAuthorizationState(StrEnum):
    """Authorization state without implying execution capability."""

    NOT_REQUIRED = "not-required"
    AUTHORIZED_PRE_EXECUTION = "authorized-pre-execution"


class TerraformApplyAuthorizationResult(StrEnum):
    """Whether an authorization companion was created, reused, or unnecessary."""

    CREATED = "created"
    REUSED = "reused"
    NOT_REQUIRED = "not-required"


@dataclass(frozen=True, slots=True)
class TerraformDestructiveScopeProof:
    """Address-free operator proof for the exact destructive plan scope."""

    destructive_count: int
    replacement_count: int
    deletion_count: int
    destructive_scope_digest: str
    replacement_scope_digest: str
    deletion_scope_digest: str

    def __post_init__(self) -> None:
        for value in (
            self.destructive_count,
            self.replacement_count,
            self.deletion_count,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise StateConflictError(
                    "Terraform destructive scope proof counts are invalid"
                )
        if (
            self.destructive_count < 1
            or self.destructive_count != self.replacement_count + self.deletion_count
        ):
            raise StateConflictError(
                "Terraform destructive scope proof counts conflict"
            )
        for label, digest_value in (
            ("Terraform destructive scope proof digest", self.destructive_scope_digest),
            ("Terraform replacement scope proof digest", self.replacement_scope_digest),
            ("Terraform deletion scope proof digest", self.deletion_scope_digest),
        ):
            validate_digest(digest_value, label)

    @classmethod
    def from_summary(
        cls, summary: TerraformPlanSummary
    ) -> TerraformDestructiveScopeProof:
        """Create the exact address-free proof displayed by plan review."""

        if not isinstance(summary, TerraformPlanSummary):
            raise StateConflictError("Terraform destructive scope summary is invalid")
        return cls(
            destructive_count=summary.resource_changes.destructive_count,
            replacement_count=summary.resource_changes.replace,
            deletion_count=summary.resource_changes.delete,
            destructive_scope_digest=summary.destructive_scope_digest,
            replacement_scope_digest=summary.replacement_scope_digest,
            deletion_scope_digest=summary.deletion_scope_digest,
        )


@dataclass(frozen=True, slots=True)
class TerraformApplyAuthorizationProof:
    """Already-normalized proof; no prompt text or caller classification is accepted."""

    ordinary_approval: TerraformApplyOrdinaryApproval | None = None
    allow_destructive: bool = False
    destructive_scope: TerraformDestructiveScopeProof | None = None
    drift_acknowledgement: TerraformApplyDriftAcknowledgement = (
        TerraformApplyDriftAcknowledgement.NOT_REQUIRED
    )

    def __post_init__(self) -> None:
        if self.ordinary_approval is not None and not isinstance(
            self.ordinary_approval, TerraformApplyOrdinaryApproval
        ):
            raise StateConflictError("Terraform ordinary approval proof is invalid")
        if not isinstance(self.allow_destructive, bool):
            raise StateConflictError(
                "Terraform destructive class acknowledgement is invalid"
            )
        if self.destructive_scope is not None and not isinstance(
            self.destructive_scope, TerraformDestructiveScopeProof
        ):
            raise StateConflictError("Terraform destructive scope proof is invalid")
        if not isinstance(
            self.drift_acknowledgement, TerraformApplyDriftAcknowledgement
        ):
            raise StateConflictError("Terraform drift acknowledgement is invalid")


@dataclass(frozen=True, slots=True)
class TerraformApplyProofDecision:
    """Persisted normalized proof states bound to the exact reviewed plan."""

    ordinary_approval: TerraformApplyOrdinaryApproval
    allow_destructive: bool
    destructive_scope: TerraformApplyScopeProofState
    drift_acknowledgement: TerraformApplyDriftAcknowledgement
    proof_digest: str
    schema_version: str = TERRAFORM_APPLY_AUTHORIZATION_PROOF_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != TERRAFORM_APPLY_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or not isinstance(self.ordinary_approval, TerraformApplyOrdinaryApproval)
            or not isinstance(self.allow_destructive, bool)
            or not isinstance(self.destructive_scope, TerraformApplyScopeProofState)
            or not isinstance(
                self.drift_acknowledgement,
                TerraformApplyDriftAcknowledgement,
            )
        ):
            raise StatePersistenceError(
                "Terraform apply authorization proof state is invalid"
            )
        validate_digest(self.proof_digest, "Terraform apply authorization proof digest")

    def to_object(self) -> dict[str, object]:
        return {
            "allow_destructive": self.allow_destructive,
            "destructive_scope": self.destructive_scope.value,
            "drift_acknowledgement": self.drift_acknowledgement.value,
            "ordinary_approval": self.ordinary_approval.value,
            "proof_digest": self.proof_digest,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> TerraformApplyProofDecision:
        require_exact_keys(
            value,
            {
                "allow_destructive",
                "destructive_scope",
                "drift_acknowledgement",
                "ordinary_approval",
                "proof_digest",
                "schema_version",
            },
            "Terraform apply authorization proof",
        )
        allow_destructive = value["allow_destructive"]
        if not isinstance(allow_destructive, bool):
            raise StatePersistenceError(
                "Terraform destructive class proof must be boolean"
            )
        try:
            ordinary = TerraformApplyOrdinaryApproval(
                require_string(value, "ordinary_approval")
            )
            scope = TerraformApplyScopeProofState(
                require_string(value, "destructive_scope")
            )
            drift = TerraformApplyDriftAcknowledgement(
                require_string(value, "drift_acknowledgement")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "Terraform apply authorization proof enum is invalid"
            ) from error
        return cls(
            ordinary_approval=ordinary,
            allow_destructive=allow_destructive,
            destructive_scope=scope,
            drift_acknowledgement=drift,
            proof_digest=require_string(value, "proof_digest"),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class TerraformApplyAuthorization:
    """Immutable exact-plan authorization companion; never execution authority."""

    generation: int
    created_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    operation_classification: OperationClassification
    authorization_class: TerraformApplyAuthorizationClass
    request_digest: str
    journal_schema_version: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    checkpoint_schema_version: str
    checkpoint_generation: int
    checkpoint_artifact_digest: str
    checkpoint_digest: str
    review_schema_version: str
    review_digest: str
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
    summary: TerraformPlanSummary
    proof: TerraformApplyProofDecision
    authorization_state: TerraformApplyAuthorizationState
    authorization_digest: str
    apply_required: bool = True
    execution_intent: str = _EXECUTION_INTENT
    apply_execution: str = _APPLY_EXECUTION
    state_backup: str = _STATE_BACKUP
    destructive_boundary: str = _DESTRUCTIVE_BOUNDARY
    schema_version: str = TERRAFORM_APPLY_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != TERRAFORM_APPLY_AUTHORIZATION_SCHEMA_VERSION:
            raise StatePersistenceError(
                "unsupported Terraform apply authorization schema"
            )
        if self.generation != 1:
            raise StatePersistenceError(
                "Terraform apply authorization generation must be one"
            )
        if not isinstance(self.cluster_uuid, uuid.UUID) or not isinstance(
            self.operation_id, uuid.UUID
        ):
            raise StatePersistenceError(
                "Terraform apply authorization identity must use UUIDs"
            )
        try:
            validate_cluster_name(self.cluster_name)
            operation = get_operation(self.operation)
        except (ConfigurationError, KeyError) as error:
            raise StatePersistenceError(
                "Terraform apply authorization identity is invalid"
            ) from error
        if (
            self.operation != _OPERATION
            or operation.classification is not self.operation_classification
            or self.operation_classification is not OperationClassification.MUTATING
            or not isinstance(
                self.authorization_class, TerraformApplyAuthorizationClass
            )
            or self.authorization_class is TerraformApplyAuthorizationClass.NOT_REQUIRED
        ):
            raise StatePersistenceError(
                "Terraform apply authorization class or operation conflicts"
            )
        parse_timestamp(self.created_at)
        for generation in (
            self.journal_generation,
            self.checkpoint_generation,
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
                    "Terraform apply authorization generation binding is invalid"
                )
        for label, value in (
            ("operation request digest", self.request_digest),
            ("operation journal digest", self.journal_digest),
            ("Terraform checkpoint artifact digest", self.checkpoint_artifact_digest),
            ("Terraform checkpoint digest", self.checkpoint_digest),
            ("Terraform review digest", self.review_digest),
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
            ("Terraform apply authorization digest", self.authorization_digest),
        ):
            validate_digest(value, label)
        if (
            self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.PLAN
            or self.checkpoint_schema_version
            != TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
            or self.checkpoint_generation != 1
            or self.review_schema_version != TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
            or self.backend_kind != TERRAFORM_PLAN_BACKEND_KIND
            or not self.source_version
            or not isinstance(self.state_identity, TerraformStateIdentity)
            or not isinstance(self.summary, TerraformPlanSummary)
            or not isinstance(self.proof, TerraformApplyProofDecision)
        ):
            raise StatePersistenceError(
                "Terraform apply authorization provenance binding is invalid"
            )
        if (
            self.terraform_version != self.summary.terraform_version
            or self.plan_format_version != self.summary.format_version
            or self.backend_digest
            != _backend_digest(self.backend_kind, self.state_identity)
            or self.state_identity_digest != _state_identity_digest(self.state_identity)
            or self.toolchain_digest
            != _toolchain_digest(self.terraform_version, self.plan_format_version)
        ):
            raise StatePersistenceError(
                "Terraform apply authorization derived binding conflicts"
            )
        expected_class = _authorization_class(self.summary)
        if (
            expected_class is TerraformApplyAuthorizationClass.NOT_REQUIRED
            or self.authorization_class is not expected_class
        ):
            raise StatePersistenceError(
                "Terraform apply authorization plan class conflicts"
            )
        if self.summary.drift_class is TerraformPlanDriftClass.CONFLICT:
            raise StatePersistenceError(
                "Terraform apply authorization cannot bind conflicting refresh drift"
            )
        if (
            self.state_identity.presence is TerraformStatePresence.ABSENT
            and self.summary.change_class is not TerraformPlanChangeClass.CREATE_ONLY
        ):
            raise StatePersistenceError(
                "absent Terraform state permits only an initial create-only plan"
            )
        _validate_proof_decision(
            self.authorization_class,
            self.summary,
            self.proof,
        )
        if self.proof.proof_digest != _proof_digest(self):
            raise StatePersistenceError(
                "Terraform apply authorization proof digest conflicts"
            )
        if (
            self.authorization_state
            is not TerraformApplyAuthorizationState.AUTHORIZED_PRE_EXECUTION
            or not self.apply_required
            or self.execution_intent != _EXECUTION_INTENT
            or self.apply_execution != _APPLY_EXECUTION
            or self.state_backup != _STATE_BACKUP
            or self.destructive_boundary != _DESTRUCTIVE_BOUNDARY
        ):
            raise StatePersistenceError(
                "Terraform apply authorization execution state conflicts"
            )
        if self.authorization_digest != _authorization_digest(self):
            raise StatePersistenceError(
                "Terraform apply authorization record digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "apply_execution": self.apply_execution,
            "apply_required": self.apply_required,
            "authorization_class": self.authorization_class.value,
            "authorization_digest": self.authorization_digest,
            "authorization_state": self.authorization_state.value,
            "backend_digest": self.backend_digest,
            "backend_kind": self.backend_kind,
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
            "journal_phase": self.journal_phase.value,
            "journal_schema_version": self.journal_schema_version,
            "journal_status": self.journal_status.value,
            "metadata_digest": self.metadata_digest,
            "metadata_generation": self.metadata_generation,
            "operation": self.operation,
            "operation_classification": self.operation_classification.value,
            "operation_id": str(self.operation_id),
            "plan_binary_digest": self.plan_binary_digest,
            "plan_format_version": self.plan_format_version,
            "plan_json_digest": self.plan_json_digest,
            "proof": self.proof.to_object(),
            "request_digest": self.request_digest,
            "review_digest": self.review_digest,
            "review_schema_version": self.review_schema_version,
            "schema_version": self.schema_version,
            "source_bundle_digest": self.source_bundle_digest,
            "source_digest": self.source_digest,
            "source_generation": self.source_generation,
            "source_version": self.source_version,
            "state_backup": self.state_backup,
            "state_identity": self.state_identity.to_object(),
            "state_identity_digest": self.state_identity_digest,
            "summary": self.summary.to_object(),
            "terraform_version": self.terraform_version,
            "tfvars_digest": self.tfvars_digest,
            "tfvars_generation": self.tfvars_generation,
            "toolchain_digest": self.toolchain_digest,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> TerraformApplyAuthorization:
        require_exact_keys(value, set(_AUTHORIZATION_KEYS), "Terraform authorization")
        state_value = value["state_identity"]
        summary_value = value["summary"]
        proof_value = value["proof"]
        if (
            not isinstance(state_value, dict)
            or not isinstance(summary_value, dict)
            or not isinstance(proof_value, dict)
        ):
            raise StatePersistenceError(
                "Terraform apply authorization nested binding is invalid"
            )
        try:
            operation_classification = OperationClassification(
                require_string(value, "operation_classification")
            )
            authorization_class = TerraformApplyAuthorizationClass(
                require_string(value, "authorization_class")
            )
            journal_status = JournalStatus(require_string(value, "journal_status"))
            journal_phase = OperationPhase(require_string(value, "journal_phase"))
            authorization_state = TerraformApplyAuthorizationState(
                require_string(value, "authorization_state")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "Terraform apply authorization enum is invalid"
            ) from error
        apply_required = value["apply_required"]
        if not isinstance(apply_required, bool):
            raise StatePersistenceError(
                "Terraform apply-required state must be boolean"
            )
        return cls(
            generation=_integer(value["generation"], "authorization generation"),
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
            authorization_class=authorization_class,
            request_digest=require_string(value, "request_digest"),
            journal_schema_version=require_string(value, "journal_schema_version"),
            journal_generation=_integer(
                value["journal_generation"], "journal generation"
            ),
            journal_digest=require_string(value, "journal_digest"),
            journal_status=journal_status,
            journal_phase=journal_phase,
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
            summary=TerraformPlanSummary.from_object(
                cast(dict[str, object], summary_value)
            ),
            proof=TerraformApplyProofDecision.from_object(
                cast(dict[str, object], proof_value)
            ),
            authorization_state=authorization_state,
            authorization_digest=require_string(value, "authorization_digest"),
            apply_required=apply_required,
            execution_intent=require_string(value, "execution_intent"),
            apply_execution=require_string(value, "apply_execution"),
            state_backup=require_string(value, "state_backup"),
            destructive_boundary=require_string(value, "destructive_boundary"),
            schema_version=require_string(value, "schema_version"),
        )


_AUTHORIZATION_KEYS = frozenset(
    {
        "apply_execution",
        "apply_required",
        "authorization_class",
        "authorization_digest",
        "authorization_state",
        "backend_digest",
        "backend_kind",
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
        "journal_phase",
        "journal_schema_version",
        "journal_status",
        "metadata_digest",
        "metadata_generation",
        "operation",
        "operation_classification",
        "operation_id",
        "plan_binary_digest",
        "plan_format_version",
        "plan_json_digest",
        "proof",
        "request_digest",
        "review_digest",
        "review_schema_version",
        "schema_version",
        "source_bundle_digest",
        "source_digest",
        "source_generation",
        "source_version",
        "state_backup",
        "state_identity",
        "state_identity_digest",
        "summary",
        "terraform_version",
        "tfvars_digest",
        "tfvars_generation",
        "toolchain_digest",
    }
)


@dataclass(frozen=True, slots=True)
class StoredTerraformApplyAuthorization:
    record: TerraformApplyAuthorization
    artifact_digest: str


class TerraformApplyAuthorizationStore:
    """Owner-only immutable authorization beside the exact reviewed saved plan."""

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
                "Terraform apply authorization operation ID must be a UUID"
            )
        self._paths = paths
        self._operation_id = operation_id
        self._path = terraform_apply_authorization_path(paths, operation_id)
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
        expected_operation: str = _OPERATION,
    ) -> StoredTerraformApplyAuthorization:
        value, artifact_digest = self._file.read()
        record = TerraformApplyAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or record.operation != expected_operation
        ):
            raise StatePersistenceError(
                "Terraform apply authorization identity conflicts"
            )
        return StoredTerraformApplyAuthorization(record, artifact_digest)

    def write_locked(
        self,
        record: TerraformApplyAuthorization,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredTerraformApplyAuthorization:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.terraform_plans)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Terraform apply authorization operation ID conflicts"
            )
        if self._path.exists():
            current = self.read(
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
                expected_operation=record.operation,
            )
            if (
                expected_digest is None
                or current.artifact_digest != expected_digest
                or current.record.generation != expected_generation
            ):
                raise StatePersistenceError(
                    "Terraform apply authorization changed concurrently"
                )
            if current.record == record:
                return current
            raise StatePersistenceError("Terraform apply authorization is immutable")
        if (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
        ):
            raise StatePersistenceError(
                "initial Terraform apply authorization requires generation one"
            )
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return StoredTerraformApplyAuthorization(record, artifact_digest)


@dataclass(frozen=True, slots=True)
class TerraformApplyAuthorizationReport:
    """Strict redacted result for exact-plan apply authorization."""

    operation_id: uuid.UUID
    result: TerraformApplyAuthorizationResult
    authorization_class: TerraformApplyAuthorizationClass
    authorization_state: TerraformApplyAuthorizationState
    apply_required: bool
    summary: TerraformPlanSummary
    journal_generation: int
    journal_digest: str
    checkpoint_artifact_digest: str
    checkpoint_digest: str
    review_digest: str
    proof_schema_version: str | None
    proof_digest: str | None
    ordinary_approval: TerraformApplyOrdinaryApproval | None
    allow_destructive: bool
    destructive_scope: TerraformApplyScopeProofState
    drift_acknowledgement: TerraformApplyDriftAcknowledgement
    authorization_artifact_digest: str | None
    authorization_digest: str | None
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    checkpoint_schema_version: str = TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
    review_schema_version: str = TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
    authorization_schema_version: str = TERRAFORM_APPLY_AUTHORIZATION_SCHEMA_VERSION
    execution_intent: str = _EXECUTION_INTENT
    apply_execution: str = _APPLY_EXECUTION
    state_backup: str = _STATE_BACKUP
    destructive_boundary: str = _DESTRUCTIVE_BOUNDARY
    schema_version: str = TERRAFORM_APPLY_AUTHORIZATION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != TERRAFORM_APPLY_AUTHORIZATION_REPORT_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.checkpoint_schema_version
            != TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
            or self.review_schema_version != TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
            or self.authorization_schema_version
            != TERRAFORM_APPLY_AUTHORIZATION_SCHEMA_VERSION
        ):
            raise StatePersistenceError(
                "unsupported Terraform apply authorization report schema"
            )
        if (
            not isinstance(self.operation_id, uuid.UUID)
            or not isinstance(self.result, TerraformApplyAuthorizationResult)
            or not isinstance(
                self.authorization_class, TerraformApplyAuthorizationClass
            )
            or not isinstance(
                self.authorization_state, TerraformApplyAuthorizationState
            )
            or not isinstance(self.apply_required, bool)
            or not isinstance(self.summary, TerraformPlanSummary)
            or isinstance(self.journal_generation, bool)
            or not isinstance(self.journal_generation, int)
            or self.journal_generation < 2
        ):
            raise StatePersistenceError(
                "Terraform apply authorization report state is invalid"
            )
        for label, value in (
            ("operation journal digest", self.journal_digest),
            ("Terraform checkpoint artifact digest", self.checkpoint_artifact_digest),
            ("Terraform checkpoint digest", self.checkpoint_digest),
            ("Terraform review digest", self.review_digest),
        ):
            validate_digest(value, label)
        if self.result is TerraformApplyAuthorizationResult.NOT_REQUIRED:
            if (
                self.authorization_class
                is not TerraformApplyAuthorizationClass.NOT_REQUIRED
                or self.authorization_state
                is not TerraformApplyAuthorizationState.NOT_REQUIRED
                or self.apply_required
                or self.proof_schema_version is not None
                or self.proof_digest is not None
                or self.ordinary_approval is not None
                or self.allow_destructive
                or self.destructive_scope
                is not TerraformApplyScopeProofState.NOT_REQUIRED
                or self.drift_acknowledgement
                is not TerraformApplyDriftAcknowledgement.NOT_REQUIRED
                or self.authorization_artifact_digest is not None
                or self.authorization_digest is not None
            ):
                raise StatePersistenceError(
                    "unnecessary Terraform apply authorization report conflicts"
                )
        else:
            if (
                self.authorization_class
                is TerraformApplyAuthorizationClass.NOT_REQUIRED
                or self.authorization_state
                is not TerraformApplyAuthorizationState.AUTHORIZED_PRE_EXECUTION
                or not self.apply_required
                or self.proof_schema_version
                != TERRAFORM_APPLY_AUTHORIZATION_PROOF_SCHEMA_VERSION
                or self.proof_digest is None
                or self.ordinary_approval is None
                or self.authorization_artifact_digest is None
                or self.authorization_digest is None
            ):
                raise StatePersistenceError(
                    "Terraform apply authorization report binding conflicts"
                )
            for label, value in (
                ("Terraform authorization proof digest", self.proof_digest),
                (
                    "Terraform authorization artifact digest",
                    self.authorization_artifact_digest,
                ),
                ("Terraform authorization digest", self.authorization_digest),
            ):
                validate_digest(value, label)
        if (
            self.execution_intent != _EXECUTION_INTENT
            or self.apply_execution != _APPLY_EXECUTION
            or self.state_backup != _STATE_BACKUP
            or self.destructive_boundary != _DESTRUCTIVE_BOUNDARY
        ):
            raise StatePersistenceError(
                "Terraform apply authorization report execution state conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "authorization": {
                "artifact_digest": self.authorization_artifact_digest,
                "class": self.authorization_class.value,
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
                "state_backup": self.state_backup,
            },
            "journal": {
                "digest": self.journal_digest,
                "generation": self.journal_generation,
                "phase": OperationPhase.PLAN.value,
                "schema_version": self.journal_schema_version,
                "status": JournalStatus.IN_PROGRESS.value,
                "updated": False,
            },
            "operation": {
                "classification": OperationClassification.MUTATING.value,
                "id": str(self.operation_id),
                "kind": _OPERATION,
            },
            "plan": {
                "change_class": self.summary.change_class.value,
                "counts": {
                    "output_changes": self.summary.output_changes.to_object(),
                    "resource_changes": self.summary.resource_changes.to_object(),
                    "resource_drift": self.summary.resource_drift.to_object(),
                },
                "drift_class": self.summary.drift_class.value,
                "scopes": {
                    "change": self.summary.change_scope_digest,
                    "deletion": self.summary.deletion_scope_digest,
                    "destructive": self.summary.destructive_scope_digest,
                    "drift": self.summary.drift_scope_digest,
                    "replacement": self.summary.replacement_scope_digest,
                },
            },
            "proof": {
                "allow_destructive": self.allow_destructive,
                "destructive_scope": self.destructive_scope.value,
                "digest": self.proof_digest,
                "drift_acknowledgement": self.drift_acknowledgement.value,
                "ordinary_approval": (
                    None
                    if self.ordinary_approval is None
                    else self.ordinary_approval.value
                ),
                "schema_version": self.proof_schema_version,
            },
            "provenance": {
                "checkpoint": {
                    "artifact_digest": self.checkpoint_artifact_digest,
                    "digest": self.checkpoint_digest,
                    "schema_version": self.checkpoint_schema_version,
                },
                "review": {
                    "digest": self.review_digest,
                    "schema_version": self.review_schema_version,
                },
            },
            "result": self.result.value,
            "schema_version": self.schema_version,
        }


def authorize_deploy_apply(
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proof: TerraformApplyAuthorizationProof,
) -> TerraformApplyAuthorizationReport:
    """Authorize only the exact canonical reviewed deploy plan without execution."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "Terraform apply authorization operation ID must be a UUID"
        )
    if not isinstance(proof, TerraformApplyAuthorizationProof):
        raise StateConflictError("Terraform apply authorization proof is invalid")
    paths = StatePaths.derive(state_root, cluster_name)
    _assert_operation_lock(lock, paths)
    _validate_initialized_layout(paths)
    _refuse_ambiguous_operation_artifacts(paths, operation_id)
    _refuse_ambiguous_plan_artifacts(paths, operation_id)

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
    review_digest = digest_bytes(serialize_json(review.to_object()))
    authorization_class = _authorization_class(checkpoint.record.summary)
    store = TerraformApplyAuthorizationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)

    if authorization_class is TerraformApplyAuthorizationClass.NOT_REQUIRED:
        _require_no_change_policy(checkpoint.record.summary, proof)
        if store.path.exists():
            raise StateConflictError(
                "no-change Terraform plan has a forbidden authorization record"
            )
        return _not_required_report(
            operation_id=operation_id,
            journal=journal,
            checkpoint=checkpoint,
            review=review,
            review_digest=review_digest,
        )

    proof_decision = _normalize_proof(checkpoint.record, authorization_class, proof)
    if store.path.exists():
        stored = store.read(
            expected_cluster_uuid=metadata.record.cluster_uuid,
            expected_cluster_name=metadata.record.cluster_name,
        )
        expected = _create_authorization(
            metadata=metadata,
            journal=journal,
            checkpoint=checkpoint,
            review_digest=review_digest,
            authorization_class=authorization_class,
            proof=proof_decision,
            created_at=stored.record.created_at,
        )
        if stored.record != expected:
            raise StateConflictError(
                "Terraform apply authorization changed; create a new plan and operation"
            )
        result = TerraformApplyAuthorizationResult.REUSED
    else:
        record = _create_authorization(
            metadata=metadata,
            journal=journal,
            checkpoint=checkpoint,
            review_digest=review_digest,
            authorization_class=authorization_class,
            proof=proof_decision,
            created_at=format_timestamp(datetime.now(UTC)),
        )
        stored = store.write_locked(
            record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        result = TerraformApplyAuthorizationResult.CREATED
    return _authorized_report(
        result=result,
        journal=journal,
        checkpoint=checkpoint,
        review=review,
        review_digest=review_digest,
        stored=stored,
    )


def terraform_apply_authorization_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the sole canonical path for an operation's apply authorization."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "Terraform apply authorization operation ID must be a UUID"
        )
    path = (
        paths.terraform_plans
        / f"{operation_id}{TERRAFORM_APPLY_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.terraform_plans or path.resolve(strict=False) != path:
        raise UnsafePathError("Terraform apply authorization path is not canonical")
    return path


def _create_authorization(
    *,
    metadata: StoredClusterMetadata,
    journal: StoredOperationRecord,
    checkpoint: StoredTerraformPlanCheckpoint,
    review_digest: str,
    authorization_class: TerraformApplyAuthorizationClass,
    proof: TerraformApplyProofDecision,
    created_at: str,
) -> TerraformApplyAuthorization:
    record = checkpoint.record
    values: dict[str, object] = {
        "apply_execution": _APPLY_EXECUTION,
        "apply_required": True,
        "authorization_class": authorization_class.value,
        "authorization_digest": "sha256:" + "0" * 64,
        "authorization_state": (
            TerraformApplyAuthorizationState.AUTHORIZED_PRE_EXECUTION.value
        ),
        "backend_digest": _backend_digest(record.backend_kind, record.state_identity),
        "backend_kind": record.backend_kind,
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
        "journal_phase": journal.record.phase.value,
        "journal_schema_version": journal.record.schema_version,
        "journal_status": journal.record.status.value,
        "metadata_digest": metadata.digest,
        "metadata_generation": metadata.record.generation,
        "operation": record.operation,
        "operation_classification": record.classification.value,
        "operation_id": str(record.operation_id),
        "plan_binary_digest": record.plan_binary_digest,
        "plan_format_version": record.summary.format_version,
        "plan_json_digest": record.plan_json_digest,
        "proof": proof.to_object(),
        "request_digest": record.request_digest,
        "review_digest": review_digest,
        "review_schema_version": TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION,
        "schema_version": TERRAFORM_APPLY_AUTHORIZATION_SCHEMA_VERSION,
        "source_bundle_digest": record.source_bundle_digest,
        "source_digest": record.source_digest,
        "source_generation": record.source_generation,
        "source_version": record.source_version,
        "state_backup": _STATE_BACKUP,
        "state_identity": record.state_identity.to_object(),
        "state_identity_digest": _state_identity_digest(record.state_identity),
        "summary": record.summary.to_object(),
        "terraform_version": record.summary.terraform_version,
        "tfvars_digest": record.tfvars_digest,
        "tfvars_generation": record.tfvars_generation,
        "toolchain_digest": _toolchain_digest(
            record.summary.terraform_version, record.summary.format_version
        ),
    }
    values["authorization_digest"] = _authorization_digest_object(values)
    return TerraformApplyAuthorization.from_object(values)


def _normalize_proof(
    checkpoint: TerraformPlanCheckpoint,
    authorization_class: TerraformApplyAuthorizationClass,
    proof: TerraformApplyAuthorizationProof,
) -> TerraformApplyProofDecision:
    summary = checkpoint.summary
    if proof.ordinary_approval is None:
        raise StateConflictError("ordinary Terraform apply approval is required")
    if summary.drift_class is TerraformPlanDriftClass.CONFLICT:
        raise StateConflictError(
            "conflicting Terraform refresh drift cannot be authorized"
        )
    if summary.drift_class is TerraformPlanDriftClass.REVIEW_REQUIRED:
        if (
            proof.drift_acknowledgement
            is not TerraformApplyDriftAcknowledgement.INTERACTIVE_REVIEW
        ):
            raise StateConflictError(
                "benign Terraform refresh drift requires separate interactive review"
            )
    elif (
        proof.drift_acknowledgement
        is not TerraformApplyDriftAcknowledgement.NOT_REQUIRED
    ):
        raise StateConflictError(
            "Terraform drift acknowledgement is over-broad for this plan"
        )
    if checkpoint.state_identity.presence is TerraformStatePresence.ABSENT and (
        summary.change_class is not TerraformPlanChangeClass.CREATE_ONLY
        or summary.drift_class is not TerraformPlanDriftClass.NONE
    ):
        raise StateConflictError(
            "absent Terraform state permits only a create-only drift-free plan"
        )

    if authorization_class is TerraformApplyAuthorizationClass.DESTRUCTIVE:
        if not proof.allow_destructive:
            raise StateConflictError(
                "destructive Terraform plan requires --allow-destructive"
            )
        if proof.destructive_scope is None:
            raise StateConflictError(
                "destructive Terraform plan requires exact scope proof"
            )
        if proof.destructive_scope != TerraformDestructiveScopeProof.from_summary(
            summary
        ):
            raise StateConflictError(
                "destructive Terraform scope proof does not match the reviewed plan"
            )
        scope_state = TerraformApplyScopeProofState.MATCHED
    else:
        if proof.allow_destructive or proof.destructive_scope is not None:
            raise StateConflictError(
                "destructive Terraform proof is over-broad for this plan"
            )
        scope_state = TerraformApplyScopeProofState.NOT_REQUIRED

    values: dict[str, object] = {
        "allow_destructive": proof.allow_destructive,
        "destructive_scope": scope_state.value,
        "drift_acknowledgement": proof.drift_acknowledgement.value,
        "ordinary_approval": proof.ordinary_approval.value,
        "proof_digest": "sha256:" + "0" * 64,
        "schema_version": TERRAFORM_APPLY_AUTHORIZATION_PROOF_SCHEMA_VERSION,
    }
    values["proof_digest"] = _proof_digest_from_values(checkpoint, values)
    return TerraformApplyProofDecision.from_object(values)


def _require_no_change_policy(
    summary: TerraformPlanSummary,
    proof: TerraformApplyAuthorizationProof,
) -> None:
    if summary.change_class is not TerraformPlanChangeClass.NO_CHANGES:
        raise StateConflictError("Terraform no-change authorization policy conflicts")
    if summary.drift_class is not TerraformPlanDriftClass.NONE:
        raise StateConflictError(
            "no-change Terraform plan with refresh drift requires new reconciliation"
        )
    if proof != TerraformApplyAuthorizationProof():
        raise StateConflictError(
            "no-change Terraform plan must not manufacture apply authorization"
        )


def _authorization_class(
    summary: TerraformPlanSummary,
) -> TerraformApplyAuthorizationClass:
    if summary.change_class is TerraformPlanChangeClass.NO_CHANGES:
        return TerraformApplyAuthorizationClass.NOT_REQUIRED
    if summary.change_class in {
        TerraformPlanChangeClass.CREATE_ONLY,
        TerraformPlanChangeClass.NON_DESTRUCTIVE,
    }:
        return TerraformApplyAuthorizationClass.MUTATING
    if summary.change_class is TerraformPlanChangeClass.DESTRUCTIVE:
        return TerraformApplyAuthorizationClass.DESTRUCTIVE
    raise StateConflictError("Terraform plan authorization class is unknown")


def _validate_proof_decision(
    authorization_class: TerraformApplyAuthorizationClass,
    summary: TerraformPlanSummary,
    proof: TerraformApplyProofDecision,
) -> None:
    if authorization_class is TerraformApplyAuthorizationClass.DESTRUCTIVE:
        if (
            not proof.allow_destructive
            or proof.destructive_scope is not TerraformApplyScopeProofState.MATCHED
        ):
            raise StatePersistenceError(
                "destructive Terraform authorization proof is incomplete"
            )
    elif (
        proof.allow_destructive
        or proof.destructive_scope is not TerraformApplyScopeProofState.NOT_REQUIRED
    ):
        raise StatePersistenceError(
            "mutating Terraform authorization has destructive proof"
        )
    if summary.drift_class is TerraformPlanDriftClass.REVIEW_REQUIRED:
        if (
            proof.drift_acknowledgement
            is not TerraformApplyDriftAcknowledgement.INTERACTIVE_REVIEW
        ):
            raise StatePersistenceError(
                "Terraform refresh drift acknowledgement is missing"
            )
    elif (
        proof.drift_acknowledgement
        is not TerraformApplyDriftAcknowledgement.NOT_REQUIRED
    ):
        raise StatePersistenceError(
            "Terraform refresh drift acknowledgement is over-broad"
        )


def _require_exact_composed_plan(
    metadata: StoredClusterMetadata,
    journal: StoredOperationRecord,
    checkpoint: StoredTerraformPlanCheckpoint,
) -> None:
    record = checkpoint.record
    operation = get_operation(_OPERATION)
    expected_event = CheckpointEvidence(
        phase=OperationPhase.PLAN,
        result=EvidenceResult.VALIDATED,
        digest=record.checkpoint_digest,
        summary_code=_PLAN_SUMMARY_CODE,
    )
    if (
        operation.classification is not OperationClassification.MUTATING
        or record.operation != _OPERATION
        or record.operation_id != journal.record.operation_id
        or record.classification is not operation.classification
        or record.cluster_uuid != metadata.record.cluster_uuid
        or record.cluster_name != metadata.record.cluster_name
        or record.provider != metadata.record.provider
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
            "Terraform apply authorization requires the exact composed PLAN checkpoint"
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
        raise StateConflictError(
            "Terraform apply authorization PLAN preimage conflicts"
        )


def _not_required_report(
    *,
    operation_id: uuid.UUID,
    journal: StoredOperationRecord,
    checkpoint: StoredTerraformPlanCheckpoint,
    review: TerraformPlanReviewReport,
    review_digest: str,
) -> TerraformApplyAuthorizationReport:
    return TerraformApplyAuthorizationReport(
        operation_id=operation_id,
        result=TerraformApplyAuthorizationResult.NOT_REQUIRED,
        authorization_class=TerraformApplyAuthorizationClass.NOT_REQUIRED,
        authorization_state=TerraformApplyAuthorizationState.NOT_REQUIRED,
        apply_required=False,
        summary=checkpoint.record.summary,
        journal_generation=journal.record.generation,
        journal_digest=journal.digest,
        checkpoint_artifact_digest=checkpoint.digest,
        checkpoint_digest=checkpoint.record.checkpoint_digest,
        review_digest=review_digest,
        proof_schema_version=None,
        proof_digest=None,
        ordinary_approval=None,
        allow_destructive=False,
        destructive_scope=TerraformApplyScopeProofState.NOT_REQUIRED,
        drift_acknowledgement=TerraformApplyDriftAcknowledgement.NOT_REQUIRED,
        authorization_artifact_digest=None,
        authorization_digest=None,
        review_schema_version=review.schema_version,
    )


def _authorized_report(
    *,
    result: TerraformApplyAuthorizationResult,
    journal: StoredOperationRecord,
    checkpoint: StoredTerraformPlanCheckpoint,
    review: TerraformPlanReviewReport,
    review_digest: str,
    stored: StoredTerraformApplyAuthorization,
) -> TerraformApplyAuthorizationReport:
    record = stored.record
    return TerraformApplyAuthorizationReport(
        operation_id=record.operation_id,
        result=result,
        authorization_class=record.authorization_class,
        authorization_state=record.authorization_state,
        apply_required=record.apply_required,
        summary=record.summary,
        journal_generation=journal.record.generation,
        journal_digest=journal.digest,
        checkpoint_artifact_digest=checkpoint.digest,
        checkpoint_digest=checkpoint.record.checkpoint_digest,
        review_digest=review_digest,
        proof_schema_version=record.proof.schema_version,
        proof_digest=record.proof.proof_digest,
        ordinary_approval=record.proof.ordinary_approval,
        allow_destructive=record.proof.allow_destructive,
        destructive_scope=record.proof.destructive_scope,
        drift_acknowledgement=record.proof.drift_acknowledgement,
        authorization_artifact_digest=stored.artifact_digest,
        authorization_digest=record.authorization_digest,
        review_schema_version=review.schema_version,
    )


def _authorization_digest(record: TerraformApplyAuthorization) -> str:
    return _authorization_digest_object(record.to_object())


def _authorization_digest_object(values: Mapping[str, object]) -> str:
    values = dict(values)
    values["authorization_digest"] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(values))


def _proof_digest(record: TerraformApplyAuthorization) -> str:
    return _proof_digest_from_values(record, record.proof.to_object())


def _proof_digest_from_values(
    binding: TerraformPlanCheckpoint | TerraformApplyAuthorization,
    proof: Mapping[str, object],
) -> str:
    proof_values = dict(proof)
    proof_values["proof_digest"] = "sha256:" + "0" * 64
    summary = binding.summary
    return digest_bytes(
        serialize_json(
            {
                "authorization_class": _authorization_class(summary).value,
                "checkpoint_digest": binding.checkpoint_digest,
                "cluster_uuid": str(binding.cluster_uuid),
                "operation": binding.operation,
                "operation_id": str(binding.operation_id),
                "plan_binary_digest": binding.plan_binary_digest,
                "plan_json_digest": binding.plan_json_digest,
                "proof": proof_values,
                "request_digest": binding.request_digest,
                "schema_version": TERRAFORM_APPLY_AUTHORIZATION_PROOF_SCHEMA_VERSION,
                "summary": {
                    "change_class": summary.change_class.value,
                    "deletion_count": summary.resource_changes.delete,
                    "deletion_scope_digest": summary.deletion_scope_digest,
                    "destructive_count": summary.resource_changes.destructive_count,
                    "destructive_scope_digest": summary.destructive_scope_digest,
                    "drift_class": summary.drift_class.value,
                    "drift_scope_digest": summary.drift_scope_digest,
                    "replacement_count": summary.resource_changes.replace,
                    "replacement_scope_digest": summary.replacement_scope_digest,
                },
            }
        )
    )


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


def _validate_initialized_layout(paths: StatePaths) -> None:
    _require_canonical_paths(paths)
    for directory in paths.directory_paths:
        validate_state_directory(directory)
    validate_state_file(paths.cluster_metadata)
    validate_state_file(paths.terraform_tfvars)
    validate_state_file(paths.terraform_source_record)
    refuse_unexpected_terraform_state(paths, (paths.cluster_root,))


def _require_canonical_paths(paths: StatePaths) -> None:
    expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
    if expected != paths or paths.terraform_plans.parent != paths.terraform:
        raise UnsafePathError("Terraform apply authorization paths are not canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Terraform apply authorization requires an acquired cluster lock"
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
                "Terraform apply authorization operation history is ambiguous"
            )


def _refuse_ambiguous_plan_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    allowed = {
        paths.terraform_plans / f"{operation_id}.tfplan",
        paths.terraform_plans / f"{operation_id}.terraform-plan.json",
        terraform_apply_authorization_path(paths, operation_id),
    }
    for entry in _directory_entries(paths.terraform_plans, "Terraform plan"):
        validate_state_file(entry)
        if str(operation_id) in entry.name and entry not in allowed:
            raise StateConflictError(
                "Terraform apply authorization plan history is ambiguous"
            )


def _directory_entries(directory: Path, label: str) -> tuple[Path, ...]:
    try:
        return tuple(sorted(directory.iterdir(), key=lambda item: item.name))
    except OSError as error:
        raise StatePersistenceError(f"cannot safely list {label} history") from error


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


__all__ = [
    "TERRAFORM_APPLY_AUTHORIZATION_FILENAME_SUFFIX",
    "TERRAFORM_APPLY_AUTHORIZATION_PROOF_SCHEMA_VERSION",
    "TERRAFORM_APPLY_AUTHORIZATION_REPORT_SCHEMA_VERSION",
    "TERRAFORM_APPLY_AUTHORIZATION_SCHEMA_VERSION",
    "StoredTerraformApplyAuthorization",
    "TerraformApplyAuthorization",
    "TerraformApplyAuthorizationClass",
    "TerraformApplyAuthorizationProof",
    "TerraformApplyAuthorizationReport",
    "TerraformApplyAuthorizationResult",
    "TerraformApplyAuthorizationState",
    "TerraformApplyAuthorizationStore",
    "TerraformApplyDriftAcknowledgement",
    "TerraformApplyOrdinaryApproval",
    "TerraformApplyProofDecision",
    "TerraformApplyScopeProofState",
    "TerraformDestructiveScopeProof",
    "authorize_deploy_apply",
    "terraform_apply_authorization_path",
]
