"""Lock-bound composition of a deploy Terraform plan into the common journal."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from scylla_vms.errors import StateConflictError, StateLockError, StatePersistenceError
from scylla_vms.journal import (
    JOURNAL_SCHEMA_VERSION,
    CheckpointEvidence,
    EvidenceResult,
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    OperationRecord,
    StoredOperationRecord,
    is_initial_plan_record,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification, get_operation
from scylla_vms.persistence import (
    ClusterMetadataStore,
    StoredClusterMetadata,
    digest_bytes,
    serialize_json,
    validate_digest,
)
from scylla_vms.state import (
    StatePaths,
    refuse_unexpected_terraform_state,
    validate_state_directory,
    validate_state_file,
)
from scylla_vms.terraform.plan import (
    TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION,
    TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION,
    TerraformPlanChangeClass,
    TerraformPlanCheckpoint,
    TerraformPlanCheckpointService,
    TerraformPlanCheckpointStore,
    TerraformPlanDriftClass,
    TerraformPlanReviewReport,
    TerraformPlanSummary,
)

TERRAFORM_DEPLOY_PLAN_COMPOSITION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-deploy-plan-composition-report/v1"
)

_OPERATION = "deploy"
_PLAN_SUMMARY_CODE = "terraform-plan-reviewed"
_APPLY_AUTHORIZATION = "not-collected"
_EXECUTION_INTENT = "not-started"
_APPLY_EXECUTION = "unavailable"
_DESTRUCTIVE_BOUNDARY = "not-crossed"


class DeployPlanCompositionState(StrEnum):
    """Whether this call appended or exactly reused the common PLAN event."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class TerraformDeployPlanCompositionReport:
    """Strict address-free projection of deploy PLAN journal composition."""

    operation_id: uuid.UUID
    operation_classification: OperationClassification
    state: DeployPlanCompositionState
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    checkpoint_artifact_digest: str
    checkpoint_digest: str
    review_digest: str
    summary: TerraformPlanSummary
    checkpoint_schema_version: str = TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
    review_schema_version: str = TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    apply_authorization: str = _APPLY_AUTHORIZATION
    execution_intent: str = _EXECUTION_INTENT
    apply_execution: str = _APPLY_EXECUTION
    destructive_boundary: str = _DESTRUCTIVE_BOUNDARY
    schema_version: str = TERRAFORM_DEPLOY_PLAN_COMPOSITION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != TERRAFORM_DEPLOY_PLAN_COMPOSITION_REPORT_SCHEMA_VERSION
            or self.checkpoint_schema_version
            != TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
            or self.review_schema_version != TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
        ):
            raise StatePersistenceError(
                "unsupported Terraform deploy plan composition schema"
            )
        if (
            not isinstance(self.operation_id, uuid.UUID)
            or self.operation_classification is not OperationClassification.MUTATING
            or not isinstance(self.state, DeployPlanCompositionState)
            or isinstance(self.journal_generation, bool)
            or not isinstance(self.journal_generation, int)
            or self.journal_generation < 2
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.PLAN
            or not isinstance(self.summary, TerraformPlanSummary)
        ):
            raise StatePersistenceError(
                "Terraform deploy plan composition report state conflicts"
            )
        for label, value in (
            ("operation journal digest", self.journal_digest),
            (
                "Terraform plan checkpoint artifact digest",
                self.checkpoint_artifact_digest,
            ),
            ("Terraform plan checkpoint digest", self.checkpoint_digest),
            ("Terraform plan review digest", self.review_digest),
        ):
            validate_digest(value, label)
        if (
            self.apply_authorization != _APPLY_AUTHORIZATION
            or self.execution_intent != _EXECUTION_INTENT
            or self.apply_execution != _APPLY_EXECUTION
            or self.destructive_boundary != _DESTRUCTIVE_BOUNDARY
        ):
            raise StatePersistenceError(
                "Terraform deploy plan composition execution state conflicts"
            )

    def to_object(self) -> dict[str, object]:
        replacements = self.summary.resource_changes.replace > 0
        deletions = self.summary.resource_changes.delete > 0
        drift = self.summary.drift_class is not TerraformPlanDriftClass.NONE
        destructive = self.summary.change_class is TerraformPlanChangeClass.DESTRUCTIVE
        return {
            "authorization": {
                "apply": self.apply_authorization,
                "plan_approved": False,
            },
            "execution": {
                "apply": self.apply_execution,
                "apply_command_available": False,
                "destructive_boundary": self.destructive_boundary,
                "intent": self.execution_intent,
            },
            "journal": {
                "digest": self.journal_digest,
                "event": {
                    "digest": self.checkpoint_digest,
                    "phase": OperationPhase.PLAN.value,
                    "result": EvidenceResult.VALIDATED.value,
                    "summary_code": _PLAN_SUMMARY_CODE,
                },
                "generation": self.journal_generation,
                "phase": self.journal_phase.value,
                "schema_version": self.journal_schema_version,
                "status": self.journal_status.value,
            },
            "operation": {
                "classification": self.operation_classification.value,
                "id": str(self.operation_id),
                "kind": _OPERATION,
            },
            "plan": {
                "applyable": self.summary.applyable,
                "change_class": self.summary.change_class.value,
                "complete": self.summary.complete,
                "counts": {
                    "output_changes": self.summary.output_changes.to_object(),
                    "resource_changes": self.summary.resource_changes.to_object(),
                    "resource_drift": self.summary.resource_drift.to_object(),
                },
                "drift_class": self.summary.drift_class.value,
                "has_deletions": deletions,
                "has_destructive_changes": destructive,
                "has_drift": drift,
                "has_replacements": replacements,
                "scopes": {
                    "change": self.summary.change_scope_digest,
                    "deletion": self.summary.deletion_scope_digest,
                    "destructive": self.summary.destructive_scope_digest,
                    "drift": self.summary.drift_scope_digest,
                    "replacement": self.summary.replacement_scope_digest,
                },
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
            "schema_version": self.schema_version,
            "state": self.state.value,
        }


def compose_deploy_plan_journal(
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> TerraformDeployPlanCompositionReport:
    """Append or exactly reuse one immutable Terraform checkpoint PLAN event."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError("Terraform deploy plan operation ID must be a UUID")
    paths = StatePaths.derive(state_root, cluster_name)
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Terraform deploy plan composition requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)
    _validate_initialized_layout(paths)
    _refuse_ambiguous_operation_artifacts(paths, operation_id)
    _refuse_ambiguous_plan_artifacts(paths, operation_id)

    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name=paths.cluster_root.name,
        expected_provider="oci",
    )
    journal_store = OperationJournalStore(paths, operation_id)
    journal = journal_store.read(
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
    _require_deploy_identity(checkpoint.record, journal, metadata)
    expected_event = _plan_checkpoint_evidence(checkpoint.record)

    if is_initial_plan_record(journal.record):
        _require_exact_preimage(checkpoint.record, journal)
        candidate = journal.record.transition(
            status=JournalStatus.IN_PROGRESS,
            phase=OperationPhase.PLAN,
            evidence=(expected_event,),
            clock=_utc_now,
        )
        journal = journal_store.write(
            candidate,
            expected_generation=journal.record.generation,
            expected_digest=journal.digest,
        )
        state = DeployPlanCompositionState.CREATED
    else:
        _require_exact_composed_journal(checkpoint.record, journal, expected_event)
        state = DeployPlanCompositionState.REUSED

    return _composition_report(
        operation_id=operation_id,
        state=state,
        journal=journal,
        checkpoint=checkpoint.record,
        review=review,
    )


def _validate_initialized_layout(paths: StatePaths) -> None:
    expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
    if expected != paths:
        raise StateConflictError(
            "Terraform deploy plan composition paths are not canonical"
        )
    for directory in paths.directory_paths:
        validate_state_directory(directory)
    validate_state_file(paths.cluster_metadata)
    validate_state_file(paths.terraform_tfvars)
    validate_state_file(paths.terraform_source_record)
    refuse_unexpected_terraform_state(paths, (paths.cluster_root,))


def _require_deploy_identity(
    checkpoint: TerraformPlanCheckpoint,
    journal: StoredOperationRecord,
    metadata: StoredClusterMetadata,
) -> None:
    operation = get_operation(_OPERATION)
    if (
        checkpoint.operation != _OPERATION
        or checkpoint.operation_id != journal.record.operation_id
        or checkpoint.classification is not operation.classification
        or checkpoint.classification is not OperationClassification.MUTATING
        or checkpoint.cluster_uuid != journal.record.cluster_uuid
        or checkpoint.cluster_name != journal.record.cluster_name
        or checkpoint.request_digest != journal.record.request_digest
        or checkpoint.cluster_uuid != metadata.record.cluster_uuid
        or checkpoint.cluster_name != metadata.record.cluster_name
        or checkpoint.provider != metadata.record.provider
        or checkpoint.request_digest != metadata.record.provenance.request_digest
        or checkpoint.metadata_digest != metadata.digest
        or checkpoint.journal_generation != 1
        or journal.record.resume_revalidation_digest is not None
    ):
        raise StateConflictError(
            "Terraform deploy plan checkpoint identity or preimage conflicts"
        )


def _require_exact_preimage(
    checkpoint: TerraformPlanCheckpoint,
    journal: StoredOperationRecord,
) -> None:
    if (
        journal.record.generation != checkpoint.journal_generation
        or journal.digest != checkpoint.journal_digest
        or journal.record.evidence
    ):
        raise StateConflictError(
            "Terraform deploy plan journal preimage does not match the checkpoint"
        )


def _require_exact_composed_journal(
    checkpoint: TerraformPlanCheckpoint,
    journal: StoredOperationRecord,
    expected_event: CheckpointEvidence,
) -> None:
    record = journal.record
    if (
        record.generation != checkpoint.journal_generation + 1
        or record.status is not JournalStatus.IN_PROGRESS
        or record.phase is not OperationPhase.PLAN
        or record.evidence != (expected_event,)
        or record.resume_revalidation_digest is not None
    ):
        raise StateConflictError(
            "Terraform deploy plan journal checkpoint history conflicts"
        )
    preimage = OperationRecord(
        generation=checkpoint.journal_generation,
        operation_id=record.operation_id,
        operation=record.operation,
        cluster_uuid=record.cluster_uuid,
        cluster_name=record.cluster_name,
        status=JournalStatus.IN_PROGRESS,
        phase=OperationPhase.PLAN,
        created_at=record.created_at,
        updated_at=record.created_at,
        request_digest=record.request_digest,
        resume_revalidation_digest=None,
        evidence=(),
    )
    if digest_bytes(serialize_json(preimage.to_object())) != checkpoint.journal_digest:
        raise StateConflictError(
            "Terraform deploy plan journal preimage digest conflicts"
        )


def _plan_checkpoint_evidence(
    checkpoint: TerraformPlanCheckpoint,
) -> CheckpointEvidence:
    return CheckpointEvidence(
        phase=OperationPhase.PLAN,
        result=EvidenceResult.VALIDATED,
        digest=checkpoint.checkpoint_digest,
        summary_code=_PLAN_SUMMARY_CODE,
    )


def _composition_report(
    *,
    operation_id: uuid.UUID,
    state: DeployPlanCompositionState,
    journal: StoredOperationRecord,
    checkpoint: TerraformPlanCheckpoint,
    review: TerraformPlanReviewReport,
) -> TerraformDeployPlanCompositionReport:
    review_digest = digest_bytes(serialize_json(review.to_object()))
    return TerraformDeployPlanCompositionReport(
        operation_id=operation_id,
        operation_classification=checkpoint.classification,
        state=state,
        journal_generation=journal.record.generation,
        journal_digest=journal.digest,
        journal_status=journal.record.status,
        journal_phase=journal.record.phase,
        checkpoint_artifact_digest=review.artifact_digest,
        checkpoint_digest=checkpoint.checkpoint_digest,
        review_digest=review_digest,
        summary=checkpoint.summary,
    )


def _refuse_ambiguous_operation_artifacts(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> None:
    expected = paths.operations / f"{operation_id}.json"
    for entry in _directory_entries(paths.operations, "operation"):
        validate_state_file(entry)
        if _filename_operation_id(entry.name) == operation_id and entry != expected:
            raise StateConflictError(
                "Terraform deploy plan operation history is ambiguous"
            )


def _refuse_ambiguous_plan_artifacts(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> None:
    allowed = {
        paths.terraform_plans / f"{operation_id}.tfplan",
        paths.terraform_plans / f"{operation_id}.terraform-plan.json",
    }
    for entry in _directory_entries(paths.terraform_plans, "Terraform plan"):
        validate_state_file(entry)
        if _filename_operation_id(entry.name) == operation_id and entry not in allowed:
            raise StateConflictError(
                "Terraform deploy plan checkpoint history is ambiguous"
            )


def _directory_entries(directory: Path, label: str) -> tuple[Path, ...]:
    try:
        return tuple(sorted(directory.iterdir(), key=lambda item: item.name))
    except OSError as error:
        raise StatePersistenceError(f"cannot safely list {label} history") from error


def _filename_operation_id(name: str) -> uuid.UUID | None:
    prefix = name.split(".", maxsplit=1)[0]
    try:
        return uuid.UUID(prefix)
    except ValueError:
        return None


def _utc_now() -> datetime:
    return datetime.now(UTC)


__all__ = [
    "TERRAFORM_DEPLOY_PLAN_COMPOSITION_REPORT_SCHEMA_VERSION",
    "DeployPlanCompositionState",
    "TerraformDeployPlanCompositionReport",
    "compose_deploy_plan_journal",
]
