"""Durable intent-before-effect execution of one reviewed Terraform saved plan."""

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
    ToolExecutionError,
    ToolPrerequisiteError,
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
from scylla_vms.process import (
    ProcessOutputError,
    ProcessResult,
    ProcessSpec,
    ProcessTimeoutError,
    validate_executable,
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
    TerraformApplyAuthorizationClass,
    TerraformApplyAuthorizationState,
    TerraformApplyAuthorizationStore,
    terraform_apply_authorization_path,
)
from scylla_vms.terraform.commands import TerraformCommand, TerraformCommandBuilder
from scylla_vms.terraform.inputs import StoredTerraformInput, TerraformInputStore
from scylla_vms.terraform.operation_composition import (
    TERRAFORM_DEPLOY_PLAN_COMPOSITION_REPORT_SCHEMA_VERSION,
)
from scylla_vms.terraform.plan import (
    TERRAFORM_PLAN_BACKEND_KIND,
    TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION,
    TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION,
    StoredTerraformPlanCheckpoint,
    TerraformPlanChangeClass,
    TerraformPlanCheckpointStore,
    TerraformPlanDriftClass,
    TerraformStateIdentity,
    TerraformStatePresence,
    _digest_saved_plan,
    _review_report,
    capture_terraform_state_identity,
)
from scylla_vms.terraform.service import ProcessRunnerProtocol
from scylla_vms.terraform.source import (
    StoredTerraformSource,
    TerraformSourceStore,
    validate_staged_source,
)
from scylla_vms.terraform.state_safeguard import (
    TERRAFORM_STATE_SAFEGUARD_SCHEMA_VERSION,
    StoredTerraformStateSafeguard,
    TerraformStateBackupStore,
    TerraformStateSafeguard,
    TerraformStateSafeguardStore,
    safeguard_deploy_apply_state,
    terraform_state_backup_path,
    terraform_state_safeguard_path,
)
from scylla_vms.terraform.toolchain import (
    MAXIMUM_TERRAFORM_VERSION,
    MINIMUM_TERRAFORM_VERSION,
    TerraformToolchain,
    TerraformVersion,
)

TERRAFORM_APPLY_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-apply-execution/v1"
)
TERRAFORM_APPLY_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-apply-execution-report/v1"
)
TERRAFORM_APPLY_EXECUTION_FILENAME_SUFFIX = ".terraform-apply-execution.json"

_OPERATION = "deploy"
_PLAN_SUMMARY_CODE = "terraform-plan-reviewed"
_APPLY_INTENT_SUMMARY_CODE = "terraform-apply-intent"
_APPLY_VERIFY_BASELINE_ABSENT_SUMMARY_CODE = "terraform-output-baseline-absent"
_APPLY_VERIFY_BASELINE_PRESENT_SUMMARY_PREFIX = "terraform-output-baseline-present-"
_MAXIMUM_EXIT_CODE = 255


class TerraformApplyExecutionState(StrEnum):
    """Durable exact-plan apply states."""

    PREPARED = "prepared"
    STARTED = "started"
    PROCESS_SUCCEEDED_VERIFICATION_PENDING = "process-succeeded-verification-pending"
    PROCESS_FAILED_UNCERTAIN = "process-failed-uncertain"
    PROCESS_TIMED_OUT_UNCERTAIN = "process-timed-out-uncertain"
    PROCESS_INTERRUPTED_UNCERTAIN = "process-interrupted-uncertain"
    PROCESS_OUTPUT_INVALID_UNCERTAIN = "process-output-invalid-uncertain"
    PROCESS_ERROR_UNCERTAIN = "process-error-uncertain"
    PROCESS_MALFORMED_RESULT_UNCERTAIN = "process-malformed-result-uncertain"


_TERMINAL_STATES = frozenset(
    {
        TerraformApplyExecutionState.PROCESS_SUCCEEDED_VERIFICATION_PENDING,
        TerraformApplyExecutionState.PROCESS_FAILED_UNCERTAIN,
        TerraformApplyExecutionState.PROCESS_TIMED_OUT_UNCERTAIN,
        TerraformApplyExecutionState.PROCESS_INTERRUPTED_UNCERTAIN,
        TerraformApplyExecutionState.PROCESS_OUTPUT_INVALID_UNCERTAIN,
        TerraformApplyExecutionState.PROCESS_ERROR_UNCERTAIN,
        TerraformApplyExecutionState.PROCESS_MALFORMED_RESULT_UNCERTAIN,
    }
)


@dataclass(frozen=True, slots=True)
class TerraformApplyExecution:
    """Versioned state transition record for one exact saved-plan invocation."""

    generation: int
    prepared_at: str
    started_at: str | None
    finished_at: str | None
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    operation_classification: OperationClassification
    authorization_class: TerraformApplyAuthorizationClass
    request_digest: str
    plan_journal_schema_version: str
    plan_journal_generation: int
    plan_journal_digest: str
    intent_journal_generation: int | None
    intent_journal_digest: str | None
    checkpoint_schema_version: str
    checkpoint_generation: int
    checkpoint_artifact_digest: str
    checkpoint_digest: str
    review_schema_version: str
    review_digest: str
    composition_schema_version: str
    composition_digest: str
    authorization_schema_version: str
    authorization_generation: int
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_proof_digest: str
    safeguard_schema_version: str
    safeguard_generation: int
    safeguard_artifact_digest: str
    safeguard_digest: str
    backup_digest: str | None
    absent_proof_digest: str | None
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
    pre_apply_state_identity: TerraformStateIdentity
    pre_apply_state_identity_digest: str
    terraform_version: str
    plan_format_version: str
    toolchain_digest: str
    plan_binary_digest: str
    plan_json_digest: str
    plan_change_class: TerraformPlanChangeClass
    plan_drift_class: TerraformPlanDriftClass
    plan_summary_digest: str
    command_digest: str
    intent_digest: str
    execution_state: TerraformApplyExecutionState
    authorization_consumed: bool
    invocation_may_have_occurred: bool
    exit_code: int | None
    outcome_digest: str | None
    manual_recovery_required: bool
    verification_required: bool
    automatic_retry_allowed: bool
    record_digest: str
    schema_version: str = TERRAFORM_APPLY_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != TERRAFORM_APPLY_EXECUTION_SCHEMA_VERSION:
            raise StatePersistenceError("unsupported Terraform apply execution schema")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation not in {1, 2, 3}
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
        ):
            raise StatePersistenceError(
                "Terraform apply execution identity or generation is invalid"
            )
        try:
            validate_cluster_name(self.cluster_name)
            operation = get_operation(self.operation)
        except (ConfigurationError, KeyError) as error:
            raise StatePersistenceError(
                "Terraform apply execution operation identity is invalid"
            ) from error
        if (
            self.operation != _OPERATION
            or operation.classification is not self.operation_classification
            or self.operation_classification is not OperationClassification.MUTATING
            or not isinstance(
                self.authorization_class, TerraformApplyAuthorizationClass
            )
            or self.authorization_class is TerraformApplyAuthorizationClass.NOT_REQUIRED
            or not isinstance(self.execution_state, TerraformApplyExecutionState)
            or not isinstance(self.plan_change_class, TerraformPlanChangeClass)
            or not isinstance(self.plan_drift_class, TerraformPlanDriftClass)
            or not isinstance(self.pre_apply_state_identity, TerraformStateIdentity)
        ):
            raise StatePersistenceError(
                "Terraform apply execution classification is invalid"
            )
        prepared = parse_timestamp(self.prepared_at)
        started = _optional_timestamp(self.started_at)
        finished = _optional_timestamp(self.finished_at)
        if (
            (started is not None and started < prepared)
            or (finished is not None and started is None)
            or (finished is not None and started is not None and finished < started)
        ):
            raise StatePersistenceError(
                "Terraform apply execution timestamps are invalid"
            )
        for generation in (
            self.plan_journal_generation,
            self.checkpoint_generation,
            self.authorization_generation,
            self.safeguard_generation,
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
                    "Terraform apply execution generation binding is invalid"
                )
        if self.intent_journal_generation is not None and (
            isinstance(self.intent_journal_generation, bool)
            or not isinstance(self.intent_journal_generation, int)
            or self.intent_journal_generation < 1
        ):
            raise StatePersistenceError(
                "Terraform apply execution intent-journal generation is invalid"
            )
        for label, value in (
            ("operation request digest", self.request_digest),
            ("PLAN journal digest", self.plan_journal_digest),
            ("Terraform checkpoint artifact digest", self.checkpoint_artifact_digest),
            ("Terraform checkpoint digest", self.checkpoint_digest),
            ("Terraform review digest", self.review_digest),
            ("Terraform composition digest", self.composition_digest),
            (
                "Terraform authorization artifact digest",
                self.authorization_artifact_digest,
            ),
            ("Terraform authorization digest", self.authorization_digest),
            ("Terraform authorization proof digest", self.authorization_proof_digest),
            (
                "Terraform safeguard artifact digest",
                self.safeguard_artifact_digest,
            ),
            ("Terraform safeguard digest", self.safeguard_digest),
            ("cluster metadata digest", self.metadata_digest),
            ("desired specification digest", self.desired_spec_digest),
            ("Terraform tfvars digest", self.tfvars_digest),
            ("Terraform input digest", self.input_digest),
            ("Terraform source digest", self.source_digest),
            ("Terraform source bundle digest", self.source_bundle_digest),
            ("Terraform backend digest", self.backend_digest),
            (
                "Terraform pre-apply state identity digest",
                self.pre_apply_state_identity_digest,
            ),
            ("Terraform toolchain digest", self.toolchain_digest),
            ("Terraform saved plan digest", self.plan_binary_digest),
            ("Terraform plan JSON digest", self.plan_json_digest),
            ("Terraform plan summary digest", self.plan_summary_digest),
            ("Terraform apply command digest", self.command_digest),
            ("Terraform apply intent digest", self.intent_digest),
            ("Terraform apply execution record digest", self.record_digest),
        ):
            validate_digest(value, label)
        for label, optional_value in (
            ("Terraform intent journal digest", self.intent_journal_digest),
            ("Terraform state backup digest", self.backup_digest),
            ("Terraform absent-state proof digest", self.absent_proof_digest),
            ("Terraform apply outcome digest", self.outcome_digest),
        ):
            if optional_value is not None:
                validate_digest(optional_value, label)
        if (
            self.plan_journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.checkpoint_schema_version
            != TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
            or self.checkpoint_generation != 1
            or self.review_schema_version != TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
            or self.composition_schema_version
            != TERRAFORM_DEPLOY_PLAN_COMPOSITION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != TERRAFORM_APPLY_AUTHORIZATION_SCHEMA_VERSION
            or self.authorization_generation != 1
            or self.safeguard_schema_version != TERRAFORM_STATE_SAFEGUARD_SCHEMA_VERSION
            or self.safeguard_generation != 1
            or self.backend_kind != TERRAFORM_PLAN_BACKEND_KIND
            or not self.source_version
        ):
            raise StatePersistenceError(
                "Terraform apply execution provenance is invalid"
            )
        if (
            self.pre_apply_state_identity_digest
            != _state_identity_digest(self.pre_apply_state_identity)
            or self.backend_digest
            != _backend_digest(self.backend_kind, self.pre_apply_state_identity)
            or self.toolchain_digest
            != _toolchain_digest(self.terraform_version, self.plan_format_version)
        ):
            raise StatePersistenceError(
                "Terraform apply execution derived binding conflicts"
            )
        if (
            self.plan_change_class is TerraformPlanChangeClass.NO_CHANGES
            or self.plan_drift_class is TerraformPlanDriftClass.CONFLICT
            or (
                self.authorization_class is TerraformApplyAuthorizationClass.DESTRUCTIVE
                and self.plan_change_class is not TerraformPlanChangeClass.DESTRUCTIVE
            )
            or (
                self.authorization_class is TerraformApplyAuthorizationClass.MUTATING
                and self.plan_change_class
                not in {
                    TerraformPlanChangeClass.CREATE_ONLY,
                    TerraformPlanChangeClass.NON_DESTRUCTIVE,
                }
            )
        ):
            raise StatePersistenceError(
                "Terraform apply execution plan class conflicts"
            )
        if self.pre_apply_state_identity.presence is TerraformStatePresence.PRESENT:
            if (
                self.backup_digest is None
                or self.absent_proof_digest is not None
                or self.backup_digest != self.pre_apply_state_identity.state_digest
            ):
                raise StatePersistenceError(
                    "Terraform apply execution backup binding conflicts"
                )
        elif (
            self.backup_digest is not None
            or self.absent_proof_digest is None
            or self.plan_change_class is not TerraformPlanChangeClass.CREATE_ONLY
            or self.plan_drift_class is not TerraformPlanDriftClass.NONE
        ):
            raise StatePersistenceError(
                "Terraform apply execution absent-state binding conflicts"
            )
        self._validate_state_fields(started, finished)
        if self.intent_digest != _intent_digest(self):
            raise StatePersistenceError(
                "Terraform apply execution intent digest conflicts"
            )
        if self.record_digest != _record_digest(self):
            raise StatePersistenceError(
                "Terraform apply execution record digest conflicts"
            )

    def _validate_state_fields(
        self, started: datetime | None, finished: datetime | None
    ) -> None:
        if self.execution_state is TerraformApplyExecutionState.PREPARED:
            if (
                self.generation != 1
                or started is not None
                or finished is not None
                or self.intent_journal_generation is not None
                or self.intent_journal_digest is not None
                or self.authorization_consumed
                or self.invocation_may_have_occurred
                or self.exit_code is not None
                or self.outcome_digest is not None
                or self.manual_recovery_required
                or self.verification_required
                or self.automatic_retry_allowed
            ):
                raise StatePersistenceError(
                    "prepared Terraform apply execution state conflicts"
                )
            return
        if (
            self.intent_journal_generation != self.plan_journal_generation + 1
            or self.intent_journal_digest is None
            or started is None
            or not self.authorization_consumed
            or not self.invocation_may_have_occurred
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "started Terraform apply execution state conflicts"
            )
        if self.execution_state is TerraformApplyExecutionState.STARTED:
            if (
                self.generation != 2
                or finished is not None
                or self.exit_code is not None
                or self.outcome_digest is not None
                or not self.manual_recovery_required
                or not self.verification_required
            ):
                raise StatePersistenceError(
                    "started Terraform apply execution recovery state conflicts"
                )
            return
        if (
            self.execution_state not in _TERMINAL_STATES
            or self.generation != 3
            or finished is None
            or self.outcome_digest is None
            or not self.verification_required
        ):
            raise StatePersistenceError(
                "terminal Terraform apply execution state conflicts"
            )
        if (
            self.execution_state
            is TerraformApplyExecutionState.PROCESS_SUCCEEDED_VERIFICATION_PENDING
        ):
            if self.exit_code != 0 or self.manual_recovery_required:
                raise StatePersistenceError(
                    "successful Terraform apply process state conflicts"
                )
        elif (
            self.execution_state
            is TerraformApplyExecutionState.PROCESS_FAILED_UNCERTAIN
        ):
            if (
                self.exit_code is None
                or self.exit_code == 0
                or not _bounded_exit_code(self.exit_code)
                or not self.manual_recovery_required
            ):
                raise StatePersistenceError(
                    "failed Terraform apply process state conflicts"
                )
        elif self.exit_code is not None or not self.manual_recovery_required:
            raise StatePersistenceError(
                "uncertain Terraform apply process state conflicts"
            )
        if self.outcome_digest != _outcome_digest(self):
            raise StatePersistenceError(
                "Terraform apply execution outcome digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "absent_proof_digest": self.absent_proof_digest,
            "authorization_artifact_digest": self.authorization_artifact_digest,
            "authorization_class": self.authorization_class.value,
            "authorization_consumed": self.authorization_consumed,
            "authorization_digest": self.authorization_digest,
            "authorization_generation": self.authorization_generation,
            "authorization_proof_digest": self.authorization_proof_digest,
            "authorization_schema_version": self.authorization_schema_version,
            "automatic_retry_allowed": self.automatic_retry_allowed,
            "backend_digest": self.backend_digest,
            "backend_kind": self.backend_kind,
            "backup_digest": self.backup_digest,
            "checkpoint_artifact_digest": self.checkpoint_artifact_digest,
            "checkpoint_digest": self.checkpoint_digest,
            "checkpoint_generation": self.checkpoint_generation,
            "checkpoint_schema_version": self.checkpoint_schema_version,
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "command_digest": self.command_digest,
            "composition_digest": self.composition_digest,
            "composition_schema_version": self.composition_schema_version,
            "desired_spec_digest": self.desired_spec_digest,
            "execution_state": self.execution_state.value,
            "exit_code": self.exit_code,
            "finished_at": self.finished_at,
            "generation": self.generation,
            "input_digest": self.input_digest,
            "intent_digest": self.intent_digest,
            "intent_journal_digest": self.intent_journal_digest,
            "intent_journal_generation": self.intent_journal_generation,
            "invocation_may_have_occurred": self.invocation_may_have_occurred,
            "manual_recovery_required": self.manual_recovery_required,
            "metadata_digest": self.metadata_digest,
            "metadata_generation": self.metadata_generation,
            "operation": self.operation,
            "operation_classification": self.operation_classification.value,
            "operation_id": str(self.operation_id),
            "outcome_digest": self.outcome_digest,
            "plan_binary_digest": self.plan_binary_digest,
            "plan_change_class": self.plan_change_class.value,
            "plan_drift_class": self.plan_drift_class.value,
            "plan_format_version": self.plan_format_version,
            "plan_journal_digest": self.plan_journal_digest,
            "plan_journal_generation": self.plan_journal_generation,
            "plan_journal_schema_version": self.plan_journal_schema_version,
            "plan_json_digest": self.plan_json_digest,
            "plan_summary_digest": self.plan_summary_digest,
            "pre_apply_state_identity": self.pre_apply_state_identity.to_object(),
            "pre_apply_state_identity_digest": self.pre_apply_state_identity_digest,
            "prepared_at": self.prepared_at,
            "record_digest": self.record_digest,
            "request_digest": self.request_digest,
            "review_digest": self.review_digest,
            "review_schema_version": self.review_schema_version,
            "safeguard_artifact_digest": self.safeguard_artifact_digest,
            "safeguard_digest": self.safeguard_digest,
            "safeguard_generation": self.safeguard_generation,
            "safeguard_schema_version": self.safeguard_schema_version,
            "schema_version": self.schema_version,
            "source_bundle_digest": self.source_bundle_digest,
            "source_digest": self.source_digest,
            "source_generation": self.source_generation,
            "source_version": self.source_version,
            "started_at": self.started_at,
            "terraform_version": self.terraform_version,
            "tfvars_digest": self.tfvars_digest,
            "tfvars_generation": self.tfvars_generation,
            "toolchain_digest": self.toolchain_digest,
            "verification_required": self.verification_required,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> TerraformApplyExecution:
        require_exact_keys(value, set(_EXECUTION_KEYS), "Terraform apply execution")
        state_value = value["pre_apply_state_identity"]
        if not isinstance(state_value, dict):
            raise StatePersistenceError(
                "Terraform apply execution state identity must be an object"
            )
        try:
            classification = OperationClassification(
                require_string(value, "operation_classification")
            )
            authorization_class = TerraformApplyAuthorizationClass(
                require_string(value, "authorization_class")
            )
            change_class = TerraformPlanChangeClass(
                require_string(value, "plan_change_class")
            )
            drift_class = TerraformPlanDriftClass(
                require_string(value, "plan_drift_class")
            )
            execution_state = TerraformApplyExecutionState(
                require_string(value, "execution_state")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "Terraform apply execution enum is invalid"
            ) from error
        return cls(
            generation=_integer(value["generation"], "execution generation"),
            prepared_at=require_string(value, "prepared_at"),
            started_at=_optional_string(value, "started_at"),
            finished_at=_optional_string(value, "finished_at"),
            cluster_uuid=parse_uuid(
                require_string(value, "cluster_uuid"), "cluster UUID"
            ),
            cluster_name=require_string(value, "cluster_name"),
            operation_id=parse_uuid(
                require_string(value, "operation_id"), "operation ID"
            ),
            operation=require_string(value, "operation"),
            operation_classification=classification,
            authorization_class=authorization_class,
            request_digest=require_string(value, "request_digest"),
            plan_journal_schema_version=require_string(
                value, "plan_journal_schema_version"
            ),
            plan_journal_generation=_integer(
                value["plan_journal_generation"], "PLAN journal generation"
            ),
            plan_journal_digest=require_string(value, "plan_journal_digest"),
            intent_journal_generation=_optional_integer(
                value, "intent_journal_generation"
            ),
            intent_journal_digest=_optional_string(value, "intent_journal_digest"),
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
            composition_schema_version=require_string(
                value, "composition_schema_version"
            ),
            composition_digest=require_string(value, "composition_digest"),
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
            authorization_proof_digest=require_string(
                value, "authorization_proof_digest"
            ),
            safeguard_schema_version=require_string(value, "safeguard_schema_version"),
            safeguard_generation=_integer(
                value["safeguard_generation"], "safeguard generation"
            ),
            safeguard_artifact_digest=require_string(
                value, "safeguard_artifact_digest"
            ),
            safeguard_digest=require_string(value, "safeguard_digest"),
            backup_digest=_optional_string(value, "backup_digest"),
            absent_proof_digest=_optional_string(value, "absent_proof_digest"),
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
            pre_apply_state_identity=TerraformStateIdentity.from_object(
                cast(dict[str, object], state_value)
            ),
            pre_apply_state_identity_digest=require_string(
                value, "pre_apply_state_identity_digest"
            ),
            terraform_version=require_string(value, "terraform_version"),
            plan_format_version=require_string(value, "plan_format_version"),
            toolchain_digest=require_string(value, "toolchain_digest"),
            plan_binary_digest=require_string(value, "plan_binary_digest"),
            plan_json_digest=require_string(value, "plan_json_digest"),
            plan_change_class=change_class,
            plan_drift_class=drift_class,
            plan_summary_digest=require_string(value, "plan_summary_digest"),
            command_digest=require_string(value, "command_digest"),
            intent_digest=require_string(value, "intent_digest"),
            execution_state=execution_state,
            authorization_consumed=_boolean(value, "authorization_consumed"),
            invocation_may_have_occurred=_boolean(
                value, "invocation_may_have_occurred"
            ),
            exit_code=_optional_integer(value, "exit_code"),
            outcome_digest=_optional_string(value, "outcome_digest"),
            manual_recovery_required=_boolean(value, "manual_recovery_required"),
            verification_required=_boolean(value, "verification_required"),
            automatic_retry_allowed=_boolean(value, "automatic_retry_allowed"),
            record_digest=require_string(value, "record_digest"),
            schema_version=require_string(value, "schema_version"),
        )


_EXECUTION_KEYS = frozenset(
    {
        "absent_proof_digest",
        "authorization_artifact_digest",
        "authorization_class",
        "authorization_consumed",
        "authorization_digest",
        "authorization_generation",
        "authorization_proof_digest",
        "authorization_schema_version",
        "automatic_retry_allowed",
        "backend_digest",
        "backend_kind",
        "backup_digest",
        "checkpoint_artifact_digest",
        "checkpoint_digest",
        "checkpoint_generation",
        "checkpoint_schema_version",
        "cluster_name",
        "cluster_uuid",
        "command_digest",
        "composition_digest",
        "composition_schema_version",
        "desired_spec_digest",
        "execution_state",
        "exit_code",
        "finished_at",
        "generation",
        "input_digest",
        "intent_digest",
        "intent_journal_digest",
        "intent_journal_generation",
        "invocation_may_have_occurred",
        "manual_recovery_required",
        "metadata_digest",
        "metadata_generation",
        "operation",
        "operation_classification",
        "operation_id",
        "outcome_digest",
        "plan_binary_digest",
        "plan_change_class",
        "plan_drift_class",
        "plan_format_version",
        "plan_journal_digest",
        "plan_journal_generation",
        "plan_journal_schema_version",
        "plan_json_digest",
        "plan_summary_digest",
        "pre_apply_state_identity",
        "pre_apply_state_identity_digest",
        "prepared_at",
        "record_digest",
        "request_digest",
        "review_digest",
        "review_schema_version",
        "safeguard_artifact_digest",
        "safeguard_digest",
        "safeguard_generation",
        "safeguard_schema_version",
        "schema_version",
        "source_bundle_digest",
        "source_digest",
        "source_generation",
        "source_version",
        "started_at",
        "terraform_version",
        "tfvars_digest",
        "tfvars_generation",
        "toolchain_digest",
        "verification_required",
    }
)


@dataclass(frozen=True, slots=True)
class StoredTerraformApplyExecution:
    record: TerraformApplyExecution
    artifact_digest: str


class TerraformApplyExecutionStore:
    """Owner-only guarded transitions for one operation's apply execution."""

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
                "Terraform apply execution operation ID must be a UUID"
            )
        self._paths = paths
        self._operation_id = operation_id
        self._path = terraform_apply_execution_path(paths, operation_id)
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
    ) -> StoredTerraformApplyExecution:
        value, artifact_digest = self._file.read()
        record = TerraformApplyExecution.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or record.operation != _OPERATION
        ):
            raise StatePersistenceError("Terraform apply execution identity conflicts")
        return StoredTerraformApplyExecution(record, artifact_digest)

    def write_locked(
        self,
        record: TerraformApplyExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredTerraformApplyExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.terraform_plans)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Terraform apply execution operation ID conflicts"
            )
        if self._path.exists():
            current = self.read(
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if (
                expected_digest is None
                or current.artifact_digest != expected_digest
                or current.record.generation != expected_generation
            ):
                raise StatePersistenceError(
                    "Terraform apply execution changed concurrently"
                )
            _validate_execution_transition(current.record, record)
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
            or record.execution_state is not TerraformApplyExecutionState.PREPARED
        ):
            raise StatePersistenceError(
                "initial Terraform apply execution must be prepared generation one"
            )
        artifact_digest = self._file.write(
            record.to_object(), expected_digest=expected_digest
        )
        return StoredTerraformApplyExecution(record, artifact_digest)


@dataclass(frozen=True, slots=True)
class TerraformApplyExecutionReport:
    """Strict redacted execution projection."""

    operation_id: uuid.UUID
    authorization_class: TerraformApplyAuthorizationClass
    plan_change_class: TerraformPlanChangeClass
    plan_drift_class: TerraformPlanDriftClass
    execution_state: TerraformApplyExecutionState
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    checkpoint_artifact_digest: str
    checkpoint_digest: str
    review_digest: str
    composition_digest: str
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_proof_digest: str
    safeguard_artifact_digest: str
    safeguard_digest: str
    execution_artifact_digest: str
    execution_record_digest: str
    intent_digest: str
    command_digest: str
    exit_code: int | None
    runner_invoked: bool
    invocation_may_have_occurred: bool
    authorization_consumed: bool
    recovered_prepared_prefix: bool
    prestart_resume_allowed: bool
    automatic_retry_allowed: bool
    manual_recovery_required: bool
    verification_required: bool
    terminal_outcome_persisted: bool
    checkpoint_schema_version: str = TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
    review_schema_version: str = TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
    composition_schema_version: str = (
        TERRAFORM_DEPLOY_PLAN_COMPOSITION_REPORT_SCHEMA_VERSION
    )
    authorization_schema_version: str = TERRAFORM_APPLY_AUTHORIZATION_SCHEMA_VERSION
    safeguard_schema_version: str = TERRAFORM_STATE_SAFEGUARD_SCHEMA_VERSION
    execution_schema_version: str = TERRAFORM_APPLY_EXECUTION_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = TERRAFORM_APPLY_EXECUTION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != TERRAFORM_APPLY_EXECUTION_REPORT_SCHEMA_VERSION
            or self.checkpoint_schema_version
            != TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
            or self.review_schema_version != TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
            or self.composition_schema_version
            != TERRAFORM_DEPLOY_PLAN_COMPOSITION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != TERRAFORM_APPLY_AUTHORIZATION_SCHEMA_VERSION
            or self.safeguard_schema_version != TERRAFORM_STATE_SAFEGUARD_SCHEMA_VERSION
            or self.execution_schema_version != TERRAFORM_APPLY_EXECUTION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
        ):
            raise StatePersistenceError(
                "unsupported Terraform apply execution report schema"
            )
        if (
            not isinstance(self.operation_id, uuid.UUID)
            or not isinstance(
                self.authorization_class, TerraformApplyAuthorizationClass
            )
            or not isinstance(self.plan_change_class, TerraformPlanChangeClass)
            or not isinstance(self.plan_drift_class, TerraformPlanDriftClass)
            or not isinstance(self.execution_state, TerraformApplyExecutionState)
            or isinstance(self.journal_generation, bool)
            or not isinstance(self.journal_generation, int)
            or self.journal_generation < 3
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase
            not in {
                OperationPhase.EXECUTE,
                OperationPhase.VERIFY,
            }
            or (
                self.journal_phase is OperationPhase.VERIFY
                and self.execution_state
                is not TerraformApplyExecutionState.PROCESS_SUCCEEDED_VERIFICATION_PENDING
            )
        ):
            raise StatePersistenceError(
                "Terraform apply execution report state is invalid"
            )
        for label, value in (
            ("operation journal digest", self.journal_digest),
            ("Terraform checkpoint artifact digest", self.checkpoint_artifact_digest),
            ("Terraform checkpoint digest", self.checkpoint_digest),
            ("Terraform review digest", self.review_digest),
            ("Terraform composition digest", self.composition_digest),
            (
                "Terraform authorization artifact digest",
                self.authorization_artifact_digest,
            ),
            ("Terraform authorization digest", self.authorization_digest),
            ("Terraform authorization proof digest", self.authorization_proof_digest),
            (
                "Terraform safeguard artifact digest",
                self.safeguard_artifact_digest,
            ),
            ("Terraform safeguard digest", self.safeguard_digest),
            ("Terraform execution artifact digest", self.execution_artifact_digest),
            ("Terraform execution record digest", self.execution_record_digest),
            ("Terraform apply intent digest", self.intent_digest),
            ("Terraform apply command digest", self.command_digest),
        ):
            validate_digest(value, label)
        if self.exit_code is not None and not _bounded_exit_code(self.exit_code):
            raise StatePersistenceError(
                "Terraform apply execution report exit code is invalid"
            )
        if (
            not all(
                isinstance(value, bool)
                for value in (
                    self.runner_invoked,
                    self.invocation_may_have_occurred,
                    self.authorization_consumed,
                    self.recovered_prepared_prefix,
                    self.prestart_resume_allowed,
                    self.automatic_retry_allowed,
                    self.manual_recovery_required,
                    self.verification_required,
                    self.terminal_outcome_persisted,
                )
            )
            or self.automatic_retry_allowed
            or self.prestart_resume_allowed
            or not self.authorization_consumed
            or not self.invocation_may_have_occurred
        ):
            raise StatePersistenceError(
                "Terraform apply execution report safety state conflicts"
            )
        terminal = self.execution_state in _TERMINAL_STATES
        if self.terminal_outcome_persisted is not terminal:
            raise StatePersistenceError(
                "Terraform apply execution report terminal state conflicts"
            )
        if (
            self.execution_state
            is TerraformApplyExecutionState.PROCESS_SUCCEEDED_VERIFICATION_PENDING
        ):
            if (
                self.exit_code != 0
                or self.manual_recovery_required
                or not self.verification_required
            ):
                raise StatePersistenceError(
                    "Terraform apply success report state conflicts"
                )
        elif not self.manual_recovery_required or not self.verification_required:
            raise StatePersistenceError(
                "Terraform apply uncertain report state conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "authorization": {
                "artifact_digest": self.authorization_artifact_digest,
                "class": self.authorization_class.value,
                "consumed": self.authorization_consumed,
                "digest": self.authorization_digest,
                "proof_digest": self.authorization_proof_digest,
                "schema_version": self.authorization_schema_version,
            },
            "execution": {
                "artifact_digest": self.execution_artifact_digest,
                "command_digest": self.command_digest,
                "exit_code": self.exit_code,
                "intent_digest": self.intent_digest,
                "record_digest": self.execution_record_digest,
                "runner_invoked": self.runner_invoked,
                "invocation_may_have_occurred": self.invocation_may_have_occurred,
                "schema_version": self.execution_schema_version,
                "state": self.execution_state.value,
                "terminal_outcome_persisted": self.terminal_outcome_persisted,
            },
            "journal": {
                "digest": self.journal_digest,
                "generation": self.journal_generation,
                "phase": self.journal_phase.value,
                "schema_version": self.journal_schema_version,
                "status": self.journal_status.value,
            },
            "operation": {"id": str(self.operation_id), "kind": _OPERATION},
            "plan": {
                "change_class": self.plan_change_class.value,
                "drift_class": self.plan_drift_class.value,
            },
            "provenance": {
                "checkpoint": {
                    "artifact_digest": self.checkpoint_artifact_digest,
                    "digest": self.checkpoint_digest,
                    "schema_version": self.checkpoint_schema_version,
                },
                "composition": {
                    "digest": self.composition_digest,
                    "schema_version": self.composition_schema_version,
                },
                "review": {
                    "digest": self.review_digest,
                    "schema_version": self.review_schema_version,
                },
                "safeguard": {
                    "artifact_digest": self.safeguard_artifact_digest,
                    "digest": self.safeguard_digest,
                    "schema_version": self.safeguard_schema_version,
                },
            },
            "recovery": {
                "automatic_retry_allowed": self.automatic_retry_allowed,
                "manual_recovery_required": self.manual_recovery_required,
                "prestart_resume_allowed": self.prestart_resume_allowed,
                "recovered_prepared_prefix": self.recovered_prepared_prefix,
                "verification_required": self.verification_required,
            },
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    metadata: StoredClusterMetadata
    journal: StoredOperationRecord
    checkpoint: StoredTerraformPlanCheckpoint
    review_digest: str
    composition_digest: str
    authorization: StoredTerraformApplyAuthorization
    safeguard: StoredTerraformStateSafeguard
    tfvars: StoredTerraformInput
    source: StoredTerraformSource
    command: TerraformCommand
    command_digest: str


def execute_deploy_apply(
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    terraform_executable: Path,
    toolchain: TerraformToolchain,
) -> TerraformApplyExecutionReport:
    """Execute at most once the exact reviewed and safeguarded deploy plan."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "Terraform apply execution operation ID must be a UUID"
        )
    paths = StatePaths.derive(state_root, cluster_name)
    _assert_operation_lock(lock, paths)
    executable = validate_executable(terraform_executable)
    _validate_toolchain(toolchain)
    if not callable(getattr(runner, "run", None)):
        raise StatePersistenceError("Terraform apply execution runner is invalid")
    _validate_initialized_layout(paths)
    _refuse_ambiguous_artifacts(paths, operation_id)

    store = TerraformApplyExecutionStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    recovered_prepared = False
    if store.path.exists():
        metadata = ClusterMetadataStore(paths).read(
            expected_cluster_name=paths.cluster_root.name,
            expected_provider="oci",
        )
        stored = store.read(
            expected_cluster_uuid=metadata.record.cluster_uuid,
            expected_cluster_name=metadata.record.cluster_name,
        )
        require_pre_apply_state = (
            stored.record.execution_state is TerraformApplyExecutionState.PREPARED
        )
        context = _load_context(
            paths=paths,
            operation_id=operation_id,
            executable=executable,
            toolchain=toolchain,
            intent_digest=stored.record.intent_digest,
            require_pre_apply_state=require_pre_apply_state,
            allow_verification_journal=(
                stored.record.execution_state
                is TerraformApplyExecutionState.PROCESS_SUCCEEDED_VERIFICATION_PENDING
            ),
        )
        expected = _create_prepared_record(
            context, prepared_at=stored.record.prepared_at
        )
        _require_static_execution_binding(stored.record, expected)
        if stored.record.execution_state is not TerraformApplyExecutionState.PREPARED:
            return _execution_report(
                stored=stored,
                context=context,
                recovered_prepared_prefix=False,
                runner_invoked=False,
            )
        recovered_prepared = True
    else:
        checkpoint = _read_checkpoint_without_execution(paths, operation_id)
        if (
            checkpoint.record.summary.change_class
            is TerraformPlanChangeClass.NO_CHANGES
        ):
            raise StateConflictError(
                "Terraform apply execution requires an apply-required saved plan"
            )
        if not terraform_apply_authorization_path(paths, operation_id).exists():
            raise StateConflictError(
                "Terraform apply execution requires exact unconsumed authorization"
            )
        if not terraform_state_safeguard_path(paths, operation_id).exists():
            raise StateConflictError(
                "Terraform apply execution requires an exact state safeguard"
            )
        # Reuse the safeguard owner's complete canonical pre-apply validation.
        safeguard_deploy_apply_state(
            paths.state_root,
            paths.cluster_root.name,
            operation_id,
            lock,
        )
        context = _load_context(
            paths=paths,
            operation_id=operation_id,
            executable=executable,
            toolchain=toolchain,
            intent_digest=None,
            require_pre_apply_state=True,
        )
        prepared = _create_prepared_record(
            context, prepared_at=format_timestamp(datetime.now(UTC))
        )
        stored = store.write_locked(
            prepared,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )

    context = _ensure_apply_intent_journal(
        paths=paths,
        operation_id=operation_id,
        lock=lock,
        context=context,
        prepared=stored.record,
        executable=executable,
        toolchain=toolchain,
    )
    # Revalidate every pre-apply binding after the journal write and immediately
    # before consuming authorization in the durable started transition.
    context = _load_context(
        paths=paths,
        operation_id=operation_id,
        executable=executable,
        toolchain=toolchain,
        intent_digest=stored.record.intent_digest,
        require_pre_apply_state=True,
    )
    expected = _create_prepared_record(context, prepared_at=stored.record.prepared_at)
    _require_static_execution_binding(stored.record, expected)
    started = _transition_execution(
        stored.record,
        execution_state=TerraformApplyExecutionState.STARTED,
        intent_journal=context.journal,
        timestamp=format_timestamp(datetime.now(UTC)),
    )
    stored = store.write_locked(
        started,
        expected_generation=stored.record.generation,
        expected_digest=stored.artifact_digest,
        lock=lock,
    )

    terminal_state: TerraformApplyExecutionState
    exit_code: int | None = None
    try:
        result = runner.run(context.command.process)
    except ProcessTimeoutError:
        terminal_state = TerraformApplyExecutionState.PROCESS_TIMED_OUT_UNCERTAIN
    except ProcessOutputError:
        terminal_state = TerraformApplyExecutionState.PROCESS_OUTPUT_INVALID_UNCERTAIN
    except KeyboardInterrupt:
        terminal_state = TerraformApplyExecutionState.PROCESS_INTERRUPTED_UNCERTAIN
    except (ToolExecutionError, ToolPrerequisiteError):
        terminal_state = TerraformApplyExecutionState.PROCESS_ERROR_UNCERTAIN
    else:
        if not _valid_process_result(result, context.command.process):
            terminal_state = (
                TerraformApplyExecutionState.PROCESS_MALFORMED_RESULT_UNCERTAIN
            )
        else:
            exit_code = result.exit_code
            terminal_state = (
                TerraformApplyExecutionState.PROCESS_SUCCEEDED_VERIFICATION_PENDING
                if exit_code == 0
                else TerraformApplyExecutionState.PROCESS_FAILED_UNCERTAIN
            )

    terminal = _transition_execution(
        stored.record,
        execution_state=terminal_state,
        intent_journal=context.journal,
        timestamp=format_timestamp(datetime.now(UTC)),
        exit_code=exit_code,
    )
    stored = store.write_locked(
        terminal,
        expected_generation=stored.record.generation,
        expected_digest=stored.artifact_digest,
        lock=lock,
    )
    return _execution_report(
        stored=stored,
        context=context,
        recovered_prepared_prefix=recovered_prepared,
        runner_invoked=True,
    )


def terraform_apply_execution_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    """Return the sole canonical execution-companion path."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "Terraform apply execution operation ID must be a UUID"
        )
    path = (
        paths.terraform_plans
        / f"{operation_id}{TERRAFORM_APPLY_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.terraform_plans or path.resolve(strict=False) != path:
        raise UnsafePathError("Terraform apply execution path is not canonical")
    return path


def _read_checkpoint_without_execution(
    paths: StatePaths, operation_id: uuid.UUID
) -> StoredTerraformPlanCheckpoint:
    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name=paths.cluster_root.name,
        expected_provider="oci",
    )
    return TerraformPlanCheckpointStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_operation=_OPERATION,
    )


def _load_context(
    *,
    paths: StatePaths,
    operation_id: uuid.UUID,
    executable: Path,
    toolchain: TerraformToolchain,
    intent_digest: str | None,
    require_pre_apply_state: bool,
    allow_verification_journal: bool = False,
) -> _ExecutionContext:
    _validate_initialized_layout(paths)
    _refuse_ambiguous_artifacts(paths, operation_id)
    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name=paths.cluster_root.name,
        expected_provider="oci",
    )
    journal = OperationJournalStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )
    checkpoint = TerraformPlanCheckpointStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_operation=_OPERATION,
    )
    if checkpoint.record.summary.change_class is TerraformPlanChangeClass.NO_CHANGES:
        raise StateConflictError(
            "Terraform apply execution refuses a no-change saved plan"
        )
    if not checkpoint.record.summary.applyable:
        raise StateConflictError("Terraform saved plan is not applyable")
    if checkpoint.record.summary.drift_class is TerraformPlanDriftClass.CONFLICT:
        raise StateConflictError(
            "Terraform apply execution refuses conflicting refresh drift"
        )
    authorization_path = terraform_apply_authorization_path(paths, operation_id)
    safeguard_path = terraform_state_safeguard_path(paths, operation_id)
    if not authorization_path.exists():
        raise StateConflictError("Terraform apply authorization is missing")
    if not safeguard_path.exists():
        raise StateConflictError("Terraform state safeguard is missing")
    authorization = TerraformApplyAuthorizationStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )
    safeguard = TerraformStateSafeguardStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
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
    if not source.record.planning_ready or source.record.provider != "oci":
        raise StateConflictError("Terraform source is not apply-ready")
    validate_staged_source(paths, source)
    review = _review_report(checkpoint)
    review_digest = digest_bytes(serialize_json(review.to_object()))
    composition_digest = _composition_digest(
        checkpoint=checkpoint,
        review_digest=review_digest,
        authorization=authorization,
    )
    builder = TerraformCommandBuilder(
        executable,
        paths,
        source=source,
    )
    command = builder.apply_plan(operation_id)
    command_digest = _command_digest(command)
    _require_context_bindings(
        paths=paths,
        metadata=metadata,
        checkpoint=checkpoint,
        review_digest=review_digest,
        composition_digest=composition_digest,
        authorization=authorization,
        safeguard=safeguard,
        tfvars=tfvars,
        source=source,
        toolchain=toolchain,
        command=command,
        command_digest=command_digest,
        require_pre_apply_state=require_pre_apply_state,
    )
    _require_journal_state(
        journal=journal,
        checkpoint=checkpoint,
        authorization=authorization,
        intent_digest=intent_digest,
        allow_verification_journal=allow_verification_journal,
    )
    return _ExecutionContext(
        metadata=metadata,
        journal=journal,
        checkpoint=checkpoint,
        review_digest=review_digest,
        composition_digest=composition_digest,
        authorization=authorization,
        safeguard=safeguard,
        tfvars=tfvars,
        source=source,
        command=command,
        command_digest=command_digest,
    )


def _require_context_bindings(
    *,
    paths: StatePaths,
    metadata: StoredClusterMetadata,
    checkpoint: StoredTerraformPlanCheckpoint,
    review_digest: str,
    composition_digest: str,
    authorization: StoredTerraformApplyAuthorization,
    safeguard: StoredTerraformStateSafeguard,
    tfvars: StoredTerraformInput,
    source: StoredTerraformSource,
    toolchain: TerraformToolchain,
    command: TerraformCommand,
    command_digest: str,
    require_pre_apply_state: bool,
) -> None:
    plan = checkpoint.record
    auth = authorization.record
    safe = safeguard.record
    if (
        plan.operation != _OPERATION
        or plan.classification is not OperationClassification.MUTATING
        or plan.cluster_uuid != metadata.record.cluster_uuid
        or plan.cluster_name != metadata.record.cluster_name
        or plan.provider != metadata.record.provider
        or plan.request_digest != metadata.record.provenance.request_digest
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
        or plan.plan_binary_digest != _digest_saved_plan(cast(Path, command.plan_path))
        or plan.summary.terraform_version != str(toolchain.version)
        or auth.cluster_uuid != plan.cluster_uuid
        or auth.cluster_name != plan.cluster_name
        or auth.operation_id != plan.operation_id
        or auth.operation != plan.operation
        or auth.operation_classification is not plan.classification
        or auth.request_digest != plan.request_digest
        or auth.checkpoint_schema_version != plan.schema_version
        or auth.checkpoint_generation != plan.generation
        or auth.checkpoint_artifact_digest != checkpoint.digest
        or auth.checkpoint_digest != plan.checkpoint_digest
        or auth.review_schema_version != TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
        or auth.review_digest != review_digest
        or auth.metadata_generation != metadata.record.generation
        or auth.metadata_digest != metadata.digest
        or auth.desired_spec_digest != plan.desired_spec_digest
        or auth.tfvars_generation != plan.tfvars_generation
        or auth.tfvars_digest != plan.tfvars_digest
        or auth.input_digest != plan.input_digest
        or auth.source_generation != plan.source_generation
        or auth.source_digest != plan.source_digest
        or auth.source_version != plan.source_version
        or auth.source_bundle_digest != plan.source_bundle_digest
        or auth.backend_kind != plan.backend_kind
        or auth.state_identity != plan.state_identity
        or auth.terraform_version != plan.summary.terraform_version
        or auth.plan_format_version != plan.summary.format_version
        or auth.plan_binary_digest != plan.plan_binary_digest
        or auth.plan_json_digest != plan.plan_json_digest
        or auth.summary != plan.summary
        or auth.authorization_state
        is not TerraformApplyAuthorizationState.AUTHORIZED_PRE_EXECUTION
        or not auth.apply_required
        or auth.execution_intent != "not-started"
        or auth.apply_execution != "unavailable"
        or auth.state_backup != "unavailable"
        or auth.destructive_boundary != "not-crossed"
        or safe.cluster_uuid != plan.cluster_uuid
        or safe.cluster_name != plan.cluster_name
        or safe.operation_id != plan.operation_id
        or safe.operation != plan.operation
        or safe.operation_classification is not plan.classification
        or safe.request_digest != plan.request_digest
        or safe.journal_schema_version != auth.journal_schema_version
        or safe.journal_generation != auth.journal_generation
        or safe.journal_digest != auth.journal_digest
        or safe.checkpoint_schema_version != plan.schema_version
        or safe.checkpoint_generation != plan.generation
        or safe.checkpoint_artifact_digest != checkpoint.digest
        or safe.checkpoint_digest != plan.checkpoint_digest
        or safe.review_schema_version != auth.review_schema_version
        or safe.review_digest != review_digest
        or safe.authorization_schema_version != auth.schema_version
        or safe.authorization_generation != auth.generation
        or safe.authorization_artifact_digest != authorization.artifact_digest
        or safe.authorization_digest != auth.authorization_digest
        or safe.metadata_generation != metadata.record.generation
        or safe.metadata_digest != metadata.digest
        or safe.desired_spec_digest != plan.desired_spec_digest
        or safe.tfvars_generation != plan.tfvars_generation
        or safe.tfvars_digest != plan.tfvars_digest
        or safe.input_digest != plan.input_digest
        or safe.source_generation != plan.source_generation
        or safe.source_digest != plan.source_digest
        or safe.source_version != plan.source_version
        or safe.source_bundle_digest != plan.source_bundle_digest
        or safe.backend_kind != plan.backend_kind
        or safe.state_identity != plan.state_identity
        or safe.terraform_version != plan.summary.terraform_version
        or safe.plan_format_version != plan.summary.format_version
        or safe.plan_binary_digest != plan.plan_binary_digest
        or safe.plan_json_digest != plan.plan_json_digest
        or safe.plan_change_class is not plan.summary.change_class
        or safe.plan_drift_class is not plan.summary.drift_class
        or not safe.apply_required
        or safe.authorization_consumption != "unconsumed"
        or safe.execution_intent != "not-started"
        or safe.apply_execution != "unavailable"
        or safe.destructive_boundary != "not-crossed"
        or not composition_digest
        or command.plan_path is None
        or command.source_digest != source.record.bundle_digest
        or not command_digest
    ):
        raise StateConflictError(
            "Terraform apply execution binding is stale, consumed, or conflicting"
        )
    _require_safeguard_backup(paths, safe)
    if require_pre_apply_state:
        current_state = capture_terraform_state_identity(paths)
        if current_state != safe.state_identity:
            raise StateConflictError(
                "Terraform state changed before apply intent consumption"
            )


def _require_safeguard_backup(paths: StatePaths, safe: TerraformStateSafeguard) -> None:
    backup_path = terraform_state_backup_path(paths, safe.operation_id)
    validate_state_file(backup_path, allow_missing=True)
    if safe.state_identity.presence is TerraformStatePresence.PRESENT:
        if not backup_path.exists():
            raise StateConflictError(
                "Terraform apply execution safeguard backup is missing"
            )
        backup, _ = TerraformStateBackupStore(paths, safe.operation_id).read()
        if (
            backup.digest != safe.backup_digest
            or backup.size_bytes != safe.backup_size_bytes
        ):
            raise StateConflictError(
                "Terraform apply execution safeguard backup conflicts"
            )
    elif backup_path.exists():
        raise StateConflictError(
            "absent pre-apply state has a conflicting operation backup"
        )
    validate_state_file(paths.terraform_state_backup, allow_missing=True)
    if (
        safe.state_identity.presence is TerraformStatePresence.ABSENT
        and paths.terraform_state_backup.exists()
    ):
        raise StateConflictError(
            "absent pre-apply state has conflicting canonical backup metadata"
        )


def _require_journal_state(
    *,
    journal: StoredOperationRecord,
    checkpoint: StoredTerraformPlanCheckpoint,
    authorization: StoredTerraformApplyAuthorization,
    intent_digest: str | None,
    allow_verification_journal: bool = False,
) -> None:
    plan = checkpoint.record
    auth = authorization.record
    plan_event = CheckpointEvidence(
        phase=OperationPhase.PLAN,
        result=EvidenceResult.VALIDATED,
        digest=plan.checkpoint_digest,
        summary_code=_PLAN_SUMMARY_CODE,
    )
    record = journal.record
    identity_matches = (
        record.operation_id == plan.operation_id
        and record.operation == plan.operation
        and record.cluster_uuid == plan.cluster_uuid
        and record.cluster_name == plan.cluster_name
        and record.request_digest == plan.request_digest
        and record.status is JournalStatus.IN_PROGRESS
        and record.resume_revalidation_digest is None
    )
    if not identity_matches:
        raise StateConflictError("Terraform apply execution journal identity conflicts")
    if record.phase is OperationPhase.PLAN:
        if (
            record.generation != auth.journal_generation
            or journal.digest != auth.journal_digest
            or record.evidence != (plan_event,)
        ):
            raise StateConflictError(
                "Terraform apply execution PLAN journal binding conflicts"
            )
        return
    if record.phase is OperationPhase.EXECUTE and intent_digest is not None:
        intent_event = CheckpointEvidence(
            phase=OperationPhase.EXECUTE,
            result=EvidenceResult.VALIDATED,
            digest=intent_digest,
            summary_code=_APPLY_INTENT_SUMMARY_CODE,
        )
        if record.generation != auth.journal_generation + 1 or record.evidence != (
            plan_event,
            intent_event,
        ):
            raise StateConflictError(
                "Terraform apply execution intent journal binding conflicts"
            )
        return
    if (
        allow_verification_journal
        and record.phase is OperationPhase.VERIFY
        and intent_digest is not None
    ):
        intent_event = CheckpointEvidence(
            phase=OperationPhase.EXECUTE,
            result=EvidenceResult.VALIDATED,
            digest=intent_digest,
            summary_code=_APPLY_INTENT_SUMMARY_CODE,
        )
        verification_events = record.evidence[2:]
        if (
            record.generation != auth.journal_generation + 2
            or record.evidence[:2] != (plan_event, intent_event)
            or len(verification_events) != 1
            or verification_events[0].phase is not OperationPhase.VERIFY
            or verification_events[0].result is not EvidenceResult.VALIDATED
            or not _is_apply_verification_baseline_summary(
                verification_events[0].summary_code
            )
        ):
            raise StateConflictError(
                "Terraform post-apply verification journal binding conflicts"
            )
        return
    raise StateConflictError(
        "Terraform apply execution journal is advanced or conflicting"
    )


def _is_apply_verification_baseline_summary(summary_code: str) -> bool:
    if summary_code == _APPLY_VERIFY_BASELINE_ABSENT_SUMMARY_CODE:
        return True
    if not summary_code.startswith(_APPLY_VERIFY_BASELINE_PRESENT_SUMMARY_PREFIX):
        return False
    generation = summary_code.removeprefix(
        _APPLY_VERIFY_BASELINE_PRESENT_SUMMARY_PREFIX
    )
    return generation.isdigit() and not generation.startswith("0")


def _create_prepared_record(
    context: _ExecutionContext, *, prepared_at: str
) -> TerraformApplyExecution:
    plan = context.checkpoint.record
    auth = context.authorization.record
    safe = context.safeguard.record
    values: dict[str, object] = {
        "absent_proof_digest": safe.absent_proof_digest,
        "authorization_artifact_digest": context.authorization.artifact_digest,
        "authorization_class": auth.authorization_class.value,
        "authorization_consumed": False,
        "authorization_digest": auth.authorization_digest,
        "authorization_generation": auth.generation,
        "authorization_proof_digest": auth.proof.proof_digest,
        "authorization_schema_version": auth.schema_version,
        "automatic_retry_allowed": False,
        "backend_digest": safe.backend_digest,
        "backend_kind": safe.backend_kind,
        "backup_digest": safe.backup_digest,
        "checkpoint_artifact_digest": context.checkpoint.digest,
        "checkpoint_digest": plan.checkpoint_digest,
        "checkpoint_generation": plan.generation,
        "checkpoint_schema_version": plan.schema_version,
        "cluster_name": plan.cluster_name,
        "cluster_uuid": str(plan.cluster_uuid),
        "command_digest": context.command_digest,
        "composition_digest": context.composition_digest,
        "composition_schema_version": (
            TERRAFORM_DEPLOY_PLAN_COMPOSITION_REPORT_SCHEMA_VERSION
        ),
        "desired_spec_digest": plan.desired_spec_digest,
        "execution_state": TerraformApplyExecutionState.PREPARED.value,
        "exit_code": None,
        "finished_at": None,
        "generation": 1,
        "input_digest": plan.input_digest,
        "intent_digest": "sha256:" + "0" * 64,
        "intent_journal_digest": None,
        "intent_journal_generation": None,
        "invocation_may_have_occurred": False,
        "manual_recovery_required": False,
        "metadata_digest": context.metadata.digest,
        "metadata_generation": context.metadata.record.generation,
        "operation": plan.operation,
        "operation_classification": plan.classification.value,
        "operation_id": str(plan.operation_id),
        "outcome_digest": None,
        "plan_binary_digest": plan.plan_binary_digest,
        "plan_change_class": plan.summary.change_class.value,
        "plan_drift_class": plan.summary.drift_class.value,
        "plan_format_version": plan.summary.format_version,
        "plan_journal_digest": auth.journal_digest,
        "plan_journal_generation": auth.journal_generation,
        "plan_journal_schema_version": auth.journal_schema_version,
        "plan_json_digest": plan.plan_json_digest,
        "plan_summary_digest": digest_bytes(serialize_json(plan.summary.to_object())),
        "pre_apply_state_identity": safe.state_identity.to_object(),
        "pre_apply_state_identity_digest": safe.state_identity_digest,
        "prepared_at": prepared_at,
        "record_digest": "sha256:" + "0" * 64,
        "request_digest": plan.request_digest,
        "review_digest": context.review_digest,
        "review_schema_version": TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION,
        "safeguard_artifact_digest": context.safeguard.artifact_digest,
        "safeguard_digest": safe.safeguard_digest,
        "safeguard_generation": safe.generation,
        "safeguard_schema_version": safe.schema_version,
        "schema_version": TERRAFORM_APPLY_EXECUTION_SCHEMA_VERSION,
        "source_bundle_digest": plan.source_bundle_digest,
        "source_digest": plan.source_digest,
        "source_generation": plan.source_generation,
        "source_version": plan.source_version,
        "started_at": None,
        "terraform_version": plan.summary.terraform_version,
        "tfvars_digest": plan.tfvars_digest,
        "tfvars_generation": plan.tfvars_generation,
        "toolchain_digest": safe.toolchain_digest,
        "verification_required": False,
    }
    values["intent_digest"] = _intent_digest_object(values)
    values["record_digest"] = _record_digest_object(values)
    return TerraformApplyExecution.from_object(values)


def _ensure_apply_intent_journal(
    *,
    paths: StatePaths,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    context: _ExecutionContext,
    prepared: TerraformApplyExecution,
    executable: Path,
    toolchain: TerraformToolchain,
) -> _ExecutionContext:
    if context.journal.record.phase is OperationPhase.EXECUTE:
        return context
    intent_event = CheckpointEvidence(
        phase=OperationPhase.EXECUTE,
        result=EvidenceResult.VALIDATED,
        digest=prepared.intent_digest,
        summary_code=_APPLY_INTENT_SUMMARY_CODE,
    )
    candidate = context.journal.record.transition(
        status=JournalStatus.IN_PROGRESS,
        phase=OperationPhase.EXECUTE,
        evidence=(*context.journal.record.evidence, intent_event),
        clock=lambda: datetime.now(UTC),
    )
    OperationJournalStore(paths, operation_id).write(
        candidate,
        expected_generation=context.journal.record.generation,
        expected_digest=context.journal.digest,
    )
    return _load_context(
        paths=paths,
        operation_id=operation_id,
        executable=executable,
        toolchain=toolchain,
        intent_digest=prepared.intent_digest,
        require_pre_apply_state=True,
    )


def _transition_execution(
    previous: TerraformApplyExecution,
    *,
    execution_state: TerraformApplyExecutionState,
    intent_journal: StoredOperationRecord,
    timestamp: str,
    exit_code: int | None = None,
) -> TerraformApplyExecution:
    values = previous.to_object()
    if execution_state is TerraformApplyExecutionState.STARTED:
        values.update(
            {
                "authorization_consumed": True,
                "execution_state": execution_state.value,
                "generation": 2,
                "intent_journal_digest": intent_journal.digest,
                "intent_journal_generation": intent_journal.record.generation,
                "invocation_may_have_occurred": True,
                "manual_recovery_required": True,
                "started_at": timestamp,
                "verification_required": True,
            }
        )
    else:
        if execution_state not in _TERMINAL_STATES:
            raise StatePersistenceError(
                "Terraform apply execution terminal state is invalid"
            )
        values.update(
            {
                "execution_state": execution_state.value,
                "exit_code": exit_code,
                "finished_at": timestamp,
                "generation": 3,
                "manual_recovery_required": (
                    execution_state
                    is not TerraformApplyExecutionState.PROCESS_SUCCEEDED_VERIFICATION_PENDING
                ),
            }
        )
        values["outcome_digest"] = _outcome_digest_object(values)
    values["record_digest"] = _record_digest_object(values)
    return TerraformApplyExecution.from_object(values)


def _execution_report(
    *,
    stored: StoredTerraformApplyExecution,
    context: _ExecutionContext,
    recovered_prepared_prefix: bool,
    runner_invoked: bool,
) -> TerraformApplyExecutionReport:
    record = stored.record
    return TerraformApplyExecutionReport(
        operation_id=record.operation_id,
        authorization_class=record.authorization_class,
        plan_change_class=record.plan_change_class,
        plan_drift_class=record.plan_drift_class,
        execution_state=record.execution_state,
        journal_generation=context.journal.record.generation,
        journal_digest=context.journal.digest,
        journal_status=context.journal.record.status,
        journal_phase=context.journal.record.phase,
        checkpoint_artifact_digest=record.checkpoint_artifact_digest,
        checkpoint_digest=record.checkpoint_digest,
        review_digest=record.review_digest,
        composition_digest=record.composition_digest,
        authorization_artifact_digest=record.authorization_artifact_digest,
        authorization_digest=record.authorization_digest,
        authorization_proof_digest=record.authorization_proof_digest,
        safeguard_artifact_digest=record.safeguard_artifact_digest,
        safeguard_digest=record.safeguard_digest,
        execution_artifact_digest=stored.artifact_digest,
        execution_record_digest=record.record_digest,
        intent_digest=record.intent_digest,
        command_digest=record.command_digest,
        exit_code=record.exit_code,
        runner_invoked=runner_invoked,
        invocation_may_have_occurred=record.invocation_may_have_occurred,
        authorization_consumed=record.authorization_consumed,
        recovered_prepared_prefix=recovered_prepared_prefix,
        prestart_resume_allowed=False,
        automatic_retry_allowed=record.automatic_retry_allowed,
        manual_recovery_required=record.manual_recovery_required,
        verification_required=record.verification_required,
        terminal_outcome_persisted=record.execution_state in _TERMINAL_STATES,
    )


def _valid_process_result(result: object, spec: ProcessSpec) -> bool:
    return (
        isinstance(result, ProcessResult)
        and _bounded_exit_code(result.exit_code)
        and result.exit_code in spec.allowed_exit_codes
        and isinstance(result.stdout, str)
        and isinstance(result.stderr, str)
    )


def _validate_execution_transition(
    previous: TerraformApplyExecution, current: TerraformApplyExecution
) -> None:
    if current.generation != previous.generation + 1:
        raise StatePersistenceError(
            "Terraform apply execution generation must advance exactly once"
        )
    _require_static_execution_binding(current, previous)
    if (
        previous.execution_state is TerraformApplyExecutionState.PREPARED
        and current.execution_state is TerraformApplyExecutionState.STARTED
    ):
        return
    if (
        previous.execution_state is TerraformApplyExecutionState.STARTED
        and current.execution_state in _TERMINAL_STATES
    ):
        return
    raise StatePersistenceError("Terraform apply execution transition is invalid")


def _require_static_execution_binding(
    current: TerraformApplyExecution, expected: TerraformApplyExecution
) -> None:
    current_values = current.to_object()
    expected_values = expected.to_object()
    for name in _DYNAMIC_EXECUTION_FIELDS:
        current_values.pop(name)
        expected_values.pop(name)
    if current_values != expected_values:
        raise StateConflictError("Terraform apply execution immutable binding changed")


_DYNAMIC_EXECUTION_FIELDS = frozenset(
    {
        "authorization_consumed",
        "execution_state",
        "exit_code",
        "finished_at",
        "generation",
        "intent_journal_digest",
        "intent_journal_generation",
        "invocation_may_have_occurred",
        "manual_recovery_required",
        "outcome_digest",
        "record_digest",
        "started_at",
        "verification_required",
    }
)


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
        raise UnsafePathError("Terraform apply execution paths are not canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Terraform apply execution requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    operation_allowed = {paths.operations / f"{operation_id}.json"}
    _refuse_matching_unknown(
        paths.operations,
        operation_id,
        operation_allowed,
        "Terraform apply operation history",
    )
    plan_allowed = {
        paths.terraform_plans / f"{operation_id}.tfplan",
        paths.terraform_plans / f"{operation_id}.terraform-plan.json",
        terraform_apply_authorization_path(paths, operation_id),
        terraform_state_safeguard_path(paths, operation_id),
        terraform_apply_execution_path(paths, operation_id),
        paths.terraform_plans / f"{operation_id}.terraform-apply-verification.json",
        paths.terraform_plans / f"{operation_id}.terraform-apply-inventory.json",
        paths.terraform_plans / f"{operation_id}.terraform-apply-trust.json",
    }
    _refuse_matching_unknown(
        paths.terraform_plans,
        operation_id,
        plan_allowed,
        "Terraform apply plan history",
    )
    backup_allowed = {terraform_state_backup_path(paths, operation_id)}
    _refuse_matching_unknown(
        paths.terraform_backups,
        operation_id,
        backup_allowed,
        "Terraform apply backup history",
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


def _validate_toolchain(toolchain: TerraformToolchain) -> None:
    if not isinstance(toolchain, TerraformToolchain) or not isinstance(
        toolchain.version, TerraformVersion
    ):
        raise StatePersistenceError("Terraform apply toolchain is invalid")
    version = (
        toolchain.version.major,
        toolchain.version.minor,
        toolchain.version.patch,
    )
    if (
        any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0
            for item in version
        )
        or not MINIMUM_TERRAFORM_VERSION <= version < MAXIMUM_TERRAFORM_VERSION
    ):
        raise StatePersistenceError("Terraform apply toolchain is unsupported")


def _command_digest(command: TerraformCommand) -> str:
    process = command.process
    return digest_bytes(
        serialize_json(
            {
                "allowed_exit_codes": sorted(process.allowed_exit_codes),
                "argv": list(process.argv),
                "cwd": str(process.cwd),
                "environment": process.environment.for_subprocess(),
                "kind": command.kind.value,
                "max_output_bytes": process.max_output_bytes,
                "source_digest": command.source_digest,
                "timeout_seconds": process.timeout_seconds,
            }
        )
    )


def _composition_digest(
    *,
    checkpoint: StoredTerraformPlanCheckpoint,
    review_digest: str,
    authorization: StoredTerraformApplyAuthorization,
) -> str:
    return digest_bytes(
        serialize_json(
            {
                "checkpoint_artifact_digest": checkpoint.digest,
                "checkpoint_digest": checkpoint.record.checkpoint_digest,
                "journal_digest": authorization.record.journal_digest,
                "journal_generation": authorization.record.journal_generation,
                "review_digest": review_digest,
                "schema_version": (
                    TERRAFORM_DEPLOY_PLAN_COMPOSITION_REPORT_SCHEMA_VERSION
                ),
            }
        )
    )


def _intent_digest(record: TerraformApplyExecution) -> str:
    return _intent_digest_object(record.to_object())


def _intent_digest_object(values: Mapping[str, object]) -> str:
    return digest_bytes(
        serialize_json(
            {
                "authorization_artifact_digest": values[
                    "authorization_artifact_digest"
                ],
                "authorization_class": values["authorization_class"],
                "authorization_digest": values["authorization_digest"],
                "authorization_proof_digest": values["authorization_proof_digest"],
                "checkpoint_artifact_digest": values["checkpoint_artifact_digest"],
                "checkpoint_digest": values["checkpoint_digest"],
                "cluster_uuid": values["cluster_uuid"],
                "command_digest": values["command_digest"],
                "composition_digest": values["composition_digest"],
                "operation": values["operation"],
                "operation_id": values["operation_id"],
                "plan_binary_digest": values["plan_binary_digest"],
                "plan_change_class": values["plan_change_class"],
                "plan_drift_class": values["plan_drift_class"],
                "plan_journal_digest": values["plan_journal_digest"],
                "plan_journal_generation": values["plan_journal_generation"],
                "plan_json_digest": values["plan_json_digest"],
                "plan_summary_digest": values["plan_summary_digest"],
                "request_digest": values["request_digest"],
                "review_digest": values["review_digest"],
                "safeguard_artifact_digest": values["safeguard_artifact_digest"],
                "safeguard_digest": values["safeguard_digest"],
                "schema_version": TERRAFORM_APPLY_EXECUTION_SCHEMA_VERSION,
            }
        )
    )


def _record_digest(record: TerraformApplyExecution) -> str:
    return _record_digest_object(record.to_object())


def _record_digest_object(values: Mapping[str, object]) -> str:
    copied = dict(values)
    copied["record_digest"] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(copied))


def _outcome_digest(record: TerraformApplyExecution) -> str:
    return _outcome_digest_object(record.to_object())


def _outcome_digest_object(values: Mapping[str, object]) -> str:
    return digest_bytes(
        serialize_json(
            {
                "command_digest": values["command_digest"],
                "execution_state": values["execution_state"],
                "exit_code": values["exit_code"],
                "intent_digest": values["intent_digest"],
                "invocation_may_have_occurred": values["invocation_may_have_occurred"],
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


def _optional_timestamp(value: str | None) -> datetime | None:
    return None if value is None else parse_timestamp(value)


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


def _boolean(value: Mapping[str, object], name: str) -> bool:
    item = value[name]
    if not isinstance(item, bool):
        raise StatePersistenceError(f"{name} must be boolean")
    return item


def _bounded_exit_code(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and -_MAXIMUM_EXIT_CODE <= value <= _MAXIMUM_EXIT_CODE
    )


__all__ = [
    "TERRAFORM_APPLY_EXECUTION_FILENAME_SUFFIX",
    "TERRAFORM_APPLY_EXECUTION_REPORT_SCHEMA_VERSION",
    "TERRAFORM_APPLY_EXECUTION_SCHEMA_VERSION",
    "StoredTerraformApplyExecution",
    "TerraformApplyExecution",
    "TerraformApplyExecutionReport",
    "TerraformApplyExecutionState",
    "TerraformApplyExecutionStore",
    "execute_deploy_apply",
    "terraform_apply_execution_path",
]
