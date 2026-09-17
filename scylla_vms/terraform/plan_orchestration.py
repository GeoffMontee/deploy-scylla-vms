"""Controlled lock-bound creation and composition of deploy Terraform plans."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    TerraformError,
    UnsafePathError,
)
from scylla_vms.journal import (
    JOURNAL_SCHEMA_VERSION,
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    is_initial_plan_record,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification, get_operation
from scylla_vms.persistence import (
    ClusterMetadataStore,
    digest_bytes,
    serialize_json,
    validate_digest,
)
from scylla_vms.process import validate_executable
from scylla_vms.state import (
    StatePaths,
    refuse_unexpected_terraform_state,
    validate_state_directory,
    validate_state_file,
)
from scylla_vms.terraform.commands import TerraformCommandBuilder
from scylla_vms.terraform.inputs import TerraformInputStore
from scylla_vms.terraform.operation_composition import (
    TERRAFORM_DEPLOY_PLAN_COMPOSITION_REPORT_SCHEMA_VERSION,
    DeployPlanCompositionState,
    TerraformDeployPlanCompositionReport,
    compose_deploy_plan_journal,
)
from scylla_vms.terraform.plan import (
    TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION,
    TERRAFORM_PLAN_FORMAT_VERSION,
    TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION,
    TerraformPlanChangeClass,
    TerraformPlanCheckpoint,
    TerraformPlanCheckpointService,
    TerraformPlanCheckpointStore,
    TerraformPlanDriftClass,
    TerraformPlanReviewReport,
    TerraformPlanSummary,
    TerraformStateIdentity,
    capture_terraform_state_identity,
    parse_terraform_plan_json,
)
from scylla_vms.terraform.service import ProcessRunnerProtocol, TerraformService
from scylla_vms.terraform.source import (
    StoredTerraformSource,
    TerraformSourceStore,
    validate_staged_source,
)
from scylla_vms.terraform.toolchain import (
    MAXIMUM_TERRAFORM_VERSION,
    MINIMUM_TERRAFORM_VERSION,
    TerraformToolchain,
    TerraformVersion,
)

TERRAFORM_DEPLOY_PLAN_ORCHESTRATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-deploy-plan-orchestration-report/v1"
)

_OPERATION = "deploy"
_MAXIMUM_PLAN_FILE_BYTES = 64 * 1024 * 1024
_FILE_MODE = 0o600
_APPLY_AUTHORIZATION = "not-collected"
_EXECUTION_INTENT = "not-started"
_APPLY_EXECUTION = "unavailable"
_DESTRUCTIVE_BOUNDARY = "not-crossed"


class TerraformPlanOrchestrationStageState(StrEnum):
    """Whether one orchestration stage was created or exactly reused."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class TerraformDeployPlanOrchestrationReport:
    """Strict redacted report for saved-plan creation through PLAN composition."""

    operation_id: uuid.UUID
    operation_classification: OperationClassification
    saved_plan_state: TerraformPlanOrchestrationStageState
    review_state: TerraformPlanOrchestrationStageState
    checkpoint_state: TerraformPlanOrchestrationStageState
    journal_state: DeployPlanCompositionState
    toolchain_version: str
    plan_binary_digest: str
    plan_json_digest: str
    checkpoint_artifact_digest: str
    checkpoint_digest: str
    review_digest: str
    journal_generation: int
    journal_digest: str
    summary: TerraformPlanSummary
    plan_subprocess_calls: int
    show_subprocess_calls: int
    plan_format_version: str = TERRAFORM_PLAN_FORMAT_VERSION
    checkpoint_schema_version: str = TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
    review_schema_version: str = TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    composition_schema_version: str = (
        TERRAFORM_DEPLOY_PLAN_COMPOSITION_REPORT_SCHEMA_VERSION
    )
    apply_authorization: str = _APPLY_AUTHORIZATION
    execution_intent: str = _EXECUTION_INTENT
    apply_execution: str = _APPLY_EXECUTION
    destructive_boundary: str = _DESTRUCTIVE_BOUNDARY
    automatic_replan_performed: bool = False
    automatic_retry_allowed: bool = False
    idempotent_reentry_allowed: bool = True
    manual_recovery_required: bool = False
    schema_version: str = TERRAFORM_DEPLOY_PLAN_ORCHESTRATION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != TERRAFORM_DEPLOY_PLAN_ORCHESTRATION_REPORT_SCHEMA_VERSION
            or self.plan_format_version != TERRAFORM_PLAN_FORMAT_VERSION
            or self.checkpoint_schema_version
            != TERRAFORM_PLAN_CHECKPOINT_SCHEMA_VERSION
            or self.review_schema_version != TERRAFORM_PLAN_REVIEW_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.composition_schema_version
            != TERRAFORM_DEPLOY_PLAN_COMPOSITION_REPORT_SCHEMA_VERSION
        ):
            raise StatePersistenceError(
                "unsupported Terraform deploy plan orchestration schema"
            )
        if (
            not isinstance(self.operation_id, uuid.UUID)
            or self.operation_classification is not OperationClassification.MUTATING
            or not isinstance(
                self.saved_plan_state, TerraformPlanOrchestrationStageState
            )
            or not isinstance(self.review_state, TerraformPlanOrchestrationStageState)
            or not isinstance(
                self.checkpoint_state, TerraformPlanOrchestrationStageState
            )
            or not isinstance(self.journal_state, DeployPlanCompositionState)
            or not isinstance(self.summary, TerraformPlanSummary)
            or self.toolchain_version != self.summary.terraform_version
            or self.plan_format_version != self.summary.format_version
            or isinstance(self.journal_generation, bool)
            or not isinstance(self.journal_generation, int)
            or self.journal_generation < 2
        ):
            raise StatePersistenceError(
                "Terraform deploy plan orchestration report state conflicts"
            )
        for count in (self.plan_subprocess_calls, self.show_subprocess_calls):
            if (
                isinstance(count, bool)
                or not isinstance(count, int)
                or count
                not in {
                    0,
                    1,
                }
            ):
                raise StatePersistenceError(
                    "Terraform deploy plan subprocess count is invalid"
                )
        if self.saved_plan_state is TerraformPlanOrchestrationStageState.CREATED:
            if self.plan_subprocess_calls != 1 or self.show_subprocess_calls != 1:
                raise StatePersistenceError(
                    "new Terraform saved plan requires one plan and show call"
                )
        elif self.plan_subprocess_calls != 0:
            raise StatePersistenceError(
                "reused Terraform saved plan cannot report a plan call"
            )
        if self.review_state is TerraformPlanOrchestrationStageState.CREATED:
            if self.show_subprocess_calls != 1:
                raise StatePersistenceError(
                    "new Terraform plan review requires one show call"
                )
        elif self.show_subprocess_calls != 0:
            raise StatePersistenceError(
                "reused Terraform plan review cannot report a show call"
            )
        for label, value in (
            ("Terraform saved plan digest", self.plan_binary_digest),
            ("Terraform plan JSON digest", self.plan_json_digest),
            (
                "Terraform plan checkpoint artifact digest",
                self.checkpoint_artifact_digest,
            ),
            ("Terraform plan checkpoint digest", self.checkpoint_digest),
            ("Terraform plan review digest", self.review_digest),
            ("operation journal digest", self.journal_digest),
        ):
            validate_digest(value, label)
        if (
            self.apply_authorization != _APPLY_AUTHORIZATION
            or self.execution_intent != _EXECUTION_INTENT
            or self.apply_execution != _APPLY_EXECUTION
            or self.destructive_boundary != _DESTRUCTIVE_BOUNDARY
            or self.automatic_replan_performed
            or self.automatic_retry_allowed
            or not self.idempotent_reentry_allowed
            or self.manual_recovery_required
        ):
            raise StatePersistenceError(
                "Terraform deploy plan orchestration safety state conflicts"
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
                "format_version": self.plan_format_version,
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
                "terraform_version": self.toolchain_version,
            },
            "provenance": {
                "checkpoint": {
                    "artifact_digest": self.checkpoint_artifact_digest,
                    "digest": self.checkpoint_digest,
                    "schema_version": self.checkpoint_schema_version,
                },
                "journal": {
                    "digest": self.journal_digest,
                    "generation": self.journal_generation,
                    "schema_version": self.journal_schema_version,
                },
                "plan": {
                    "binary_digest": self.plan_binary_digest,
                    "json_digest": self.plan_json_digest,
                },
                "review": {
                    "digest": self.review_digest,
                    "schema_version": self.review_schema_version,
                },
            },
            "recovery": {
                "automatic_replan_performed": self.automatic_replan_performed,
                "automatic_retry_allowed": self.automatic_retry_allowed,
                "idempotent_reentry_allowed": self.idempotent_reentry_allowed,
                "manual_recovery_required": self.manual_recovery_required,
            },
            "schema_version": self.schema_version,
            "stages": {
                "checkpoint": self.checkpoint_state.value,
                "journal": self.journal_state.value,
                "review": self.review_state.value,
                "saved_plan": self.saved_plan_state.value,
            },
            "subprocess_calls": {
                "plan": self.plan_subprocess_calls,
                "show": self.show_subprocess_calls,
            },
        }


@dataclass(frozen=True, slots=True)
class _Preflight:
    cluster_uuid: uuid.UUID
    metadata_generation: int
    metadata_digest: str
    desired_spec_digest: str
    journal_generation: int
    journal_digest: str
    journal_is_initial: bool
    request_digest: str
    tfvars_generation: int
    tfvars_digest: str
    input_digest: str
    source_generation: int
    source_digest: str
    source_version: str
    source_bundle_digest: str
    state_identity: TerraformStateIdentity
    source: StoredTerraformSource


def orchestrate_deploy_plan(
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    terraform_executable: Path,
    toolchain: TerraformToolchain,
) -> TerraformDeployPlanOrchestrationReport:
    """Create/recover one deploy saved plan, checkpoint it, and compose PLAN."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "Terraform deploy plan orchestration operation ID must be a UUID"
        )
    paths = StatePaths.derive(state_root, cluster_name)
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Terraform deploy plan orchestration requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)
    executable = validate_executable(terraform_executable)
    _validate_toolchain(toolchain)
    if not callable(getattr(runner, "run", None)):
        raise StatePersistenceError(
            "Terraform deploy plan orchestration runner is invalid"
        )
    _validate_initialized_layout(paths)
    _refuse_ambiguous_operation_artifacts(paths, operation_id)
    artifact_state = _plan_artifact_state(paths, operation_id)
    preflight = _load_preflight(paths, operation_id)

    final_plan = paths.terraform_plans / f"{operation_id}.tfplan"
    checkpoint_path = paths.terraform_plans / f"{operation_id}.terraform-plan.json"
    if artifact_state.staging_exists:
        raise StateConflictError(
            "incomplete Terraform plan staging artifact requires manual recovery"
        )

    plan_calls = 0
    show_calls = 0
    if artifact_state.checkpoint_exists:
        if not artifact_state.saved_plan_exists:
            raise StateConflictError(
                "Terraform plan checkpoint exists without its saved plan"
            )
        review = TerraformPlanCheckpointService(paths).revalidate_canonical_locked(
            operation_id=operation_id,
            operation=_OPERATION,
            lock=lock,
        )
        checkpoint = _read_checkpoint(paths, operation_id, preflight.cluster_uuid)
        _require_checkpoint_toolchain(checkpoint, toolchain)
        saved_plan_state = TerraformPlanOrchestrationStageState.REUSED
        review_state = TerraformPlanOrchestrationStageState.REUSED
        checkpoint_state = TerraformPlanOrchestrationStageState.REUSED
    else:
        if checkpoint_path.exists():
            raise StateConflictError("Terraform plan checkpoint state is ambiguous")
        _require_initial_preflight(preflight)
        builder = TerraformCommandBuilder(
            executable,
            paths,
            source=preflight.source,
        )
        service = TerraformService(builder, runner)
        if artifact_state.saved_plan_exists:
            _require_saved_plan_recovery_freshness(paths, operation_id, final_plan)
            plan_digest_before_show = _digest_saved_plan(final_plan)
            plan_json = service.show_plan(lock, operation_id)
            show_calls = 1
            saved_plan_state = TerraformPlanOrchestrationStageState.REUSED
        else:
            result = service.plan_staged(lock, operation_id)
            plan_calls = 1
            staged_plan = builder.staged_plan_path(operation_id, must_exist=True)
            if result.plan_path != staged_plan:
                raise StateConflictError(
                    "Terraform plan command returned an unexpected artifact"
                )
            plan_digest_before_show = _digest_saved_plan(staged_plan)
            plan_json = service.show_staged_plan(lock, operation_id)
            show_calls = 1
            saved_plan_state = TerraformPlanOrchestrationStageState.CREATED
        summary, _ = parse_terraform_plan_json(plan_json)
        if summary.terraform_version != str(toolchain.version):
            raise StateConflictError("Terraform saved-plan toolchain version conflicts")
        if plan_calls:
            has_changes = (
                summary.change_class is not TerraformPlanChangeClass.NO_CHANGES
            )
            if result.has_changes is not has_changes:
                raise TerraformError(
                    "Terraform detailed plan exit status conflicts with plan JSON"
                )
            if _digest_saved_plan(staged_plan) != plan_digest_before_show:
                raise StateConflictError("Terraform staged plan changed during review")
        elif _digest_saved_plan(final_plan) != plan_digest_before_show:
            raise StateConflictError("Terraform saved plan changed during review")
        _require_preflight_unchanged(paths, operation_id, preflight)
        if plan_calls:
            _promote_staged_plan(staged_plan, final_plan)
        review = TerraformPlanCheckpointService(paths).capture_locked(
            operation_id=operation_id,
            operation=_OPERATION,
            toolchain=toolchain,
            plan_json=plan_json,
            clock=_utc_now,
            lock=lock,
        )
        checkpoint = _read_checkpoint(paths, operation_id, preflight.cluster_uuid)
        review_state = TerraformPlanOrchestrationStageState.CREATED
        checkpoint_state = TerraformPlanOrchestrationStageState.CREATED

    composition = compose_deploy_plan_journal(
        paths.state_root,
        paths.cluster_root.name,
        operation_id,
        lock,
    )
    _require_composed_identity(checkpoint, review, composition, toolchain)
    return TerraformDeployPlanOrchestrationReport(
        operation_id=operation_id,
        operation_classification=checkpoint.classification,
        saved_plan_state=saved_plan_state,
        review_state=review_state,
        checkpoint_state=checkpoint_state,
        journal_state=composition.state,
        toolchain_version=str(toolchain.version),
        plan_binary_digest=checkpoint.plan_binary_digest,
        plan_json_digest=checkpoint.plan_json_digest,
        checkpoint_artifact_digest=composition.checkpoint_artifact_digest,
        checkpoint_digest=checkpoint.checkpoint_digest,
        review_digest=composition.review_digest,
        journal_generation=composition.journal_generation,
        journal_digest=composition.journal_digest,
        summary=checkpoint.summary,
        plan_subprocess_calls=plan_calls,
        show_subprocess_calls=show_calls,
    )


@dataclass(frozen=True, slots=True)
class _PlanArtifactState:
    saved_plan_exists: bool
    staging_exists: bool
    checkpoint_exists: bool


def _validate_initialized_layout(paths: StatePaths) -> None:
    expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
    if expected != paths:
        raise StateConflictError(
            "Terraform deploy plan orchestration paths are not canonical"
        )
    for directory in paths.directory_paths:
        validate_state_directory(directory)
    validate_state_file(paths.cluster_metadata)
    validate_state_file(paths.terraform_tfvars)
    validate_state_file(paths.terraform_source_record)
    refuse_unexpected_terraform_state(paths, (paths.cluster_root,))


def _refuse_ambiguous_operation_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    expected = paths.operations / f"{operation_id}.json"
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy operation history"
        ) from error
    for entry in entries:
        validate_state_file(entry)
        if str(operation_id) in entry.name and entry != expected:
            raise StateConflictError(
                "Terraform deploy plan operation history is ambiguous"
            )


def _plan_artifact_state(
    paths: StatePaths, operation_id: uuid.UUID
) -> _PlanArtifactState:
    saved_plan = paths.terraform_plans / f"{operation_id}.tfplan"
    staging = paths.terraform_plans / f"{operation_id}.tfplan.staging"
    checkpoint = paths.terraform_plans / f"{operation_id}.terraform-plan.json"
    allowed = {saved_plan, staging, checkpoint}
    try:
        entries = tuple(paths.terraform_plans.iterdir())
    except OSError as error:
        raise StatePersistenceError("cannot safely list Terraform plans") from error
    for entry in entries:
        validate_state_file(entry)
        if str(operation_id) in entry.name and entry not in allowed:
            raise StateConflictError("Terraform deploy plan history is ambiguous")
    return _PlanArtifactState(
        saved_plan.exists(),
        staging.exists(),
        checkpoint.exists(),
    )


def _load_preflight(paths: StatePaths, operation_id: uuid.UUID) -> _Preflight:
    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name=paths.cluster_root.name,
        expected_provider="oci",
    )
    journal = OperationJournalStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )
    operation = get_operation(_OPERATION)
    if (
        operation.classification is not OperationClassification.MUTATING
        or journal.record.operation != _OPERATION
        or journal.record.operation_id != operation_id
        or journal.record.cluster_uuid != metadata.record.cluster_uuid
        or journal.record.cluster_name != metadata.record.cluster_name
        or journal.record.request_digest != metadata.record.provenance.request_digest
        or journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.PLAN
        or journal.record.resume_revalidation_digest is not None
    ):
        raise StateConflictError(
            "Terraform deploy plan journal or cluster identity conflicts"
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
        raise StateConflictError(
            "Terraform source is not planning-ready for this cluster"
        )
    validate_staged_source(paths, source)
    return _Preflight(
        cluster_uuid=metadata.record.cluster_uuid,
        metadata_generation=metadata.record.generation,
        metadata_digest=metadata.digest,
        desired_spec_digest=metadata.record.desired_spec.digest(),
        journal_generation=journal.record.generation,
        journal_digest=journal.digest,
        journal_is_initial=is_initial_plan_record(journal.record),
        request_digest=journal.record.request_digest,
        tfvars_generation=tfvars.record.generation,
        tfvars_digest=tfvars.digest,
        input_digest=tfvars.record.input_digest,
        source_generation=source.record.generation,
        source_digest=source.digest,
        source_version=source.record.source_version,
        source_bundle_digest=source.record.bundle_digest,
        state_identity=capture_terraform_state_identity(paths),
        source=source,
    )


def _require_initial_preflight(preflight: _Preflight) -> None:
    if preflight.journal_generation != 1 or not preflight.journal_is_initial:
        raise StateConflictError(
            "Terraform plan creation requires the initial deploy PLAN journal"
        )


def _require_preflight_unchanged(
    paths: StatePaths, operation_id: uuid.UUID, expected: _Preflight
) -> None:
    current = _load_preflight(paths, operation_id)
    if current != expected or current.journal_generation != 1:
        raise StateConflictError(
            "Terraform deploy plan inputs changed during controlled review"
        )


def _read_checkpoint(
    paths: StatePaths, operation_id: uuid.UUID, cluster_uuid: uuid.UUID
) -> TerraformPlanCheckpoint:
    return (
        TerraformPlanCheckpointStore(paths, operation_id)
        .read(
            expected_cluster_uuid=cluster_uuid,
            expected_cluster_name=paths.cluster_root.name,
            expected_operation=_OPERATION,
        )
        .record
    )


def _require_saved_plan_recovery_freshness(
    paths: StatePaths, operation_id: uuid.UUID, saved_plan: Path
) -> None:
    """Refuse a saved-plan-only prefix if any bound input changed afterward."""

    plan_stat = saved_plan.lstat()
    bound_files = [
        paths.cluster_metadata,
        paths.terraform_tfvars,
        paths.terraform_source_record,
        paths.operations / f"{operation_id}.json",
    ]
    if paths.terraform_state.exists():
        bound_files.append(paths.terraform_state)
    bound_files.extend(
        entry for entry in paths.terraform_work.rglob("*") if entry.is_file()
    )
    for path in bound_files:
        validate_state_file(path)
        metadata = path.lstat()
        if (
            metadata.st_mtime_ns > plan_stat.st_mtime_ns
            or metadata.st_ctime_ns > plan_stat.st_ctime_ns
        ):
            raise StateConflictError(
                "Terraform saved-plan-only recovery inputs changed after planning"
            )


def _require_checkpoint_toolchain(
    checkpoint: TerraformPlanCheckpoint, toolchain: TerraformToolchain
) -> None:
    if checkpoint.summary.terraform_version != str(toolchain.version):
        raise StateConflictError(
            "Terraform plan checkpoint toolchain version conflicts"
        )


def _validate_toolchain(toolchain: TerraformToolchain) -> None:
    if not isinstance(toolchain, TerraformToolchain) or not isinstance(
        toolchain.version, TerraformVersion
    ):
        raise StatePersistenceError("Terraform plan toolchain is invalid")
    version: tuple[int, int, int] = (
        toolchain.version.major,
        toolchain.version.minor,
        toolchain.version.patch,
    )
    if any(
        isinstance(item, bool) or not isinstance(item, int) or item < 0
        for item in version
    ):
        raise StatePersistenceError("Terraform plan toolchain version is invalid")
    if not MINIMUM_TERRAFORM_VERSION <= version < MAXIMUM_TERRAFORM_VERSION:
        raise StatePersistenceError("Terraform plan toolchain version is unsupported")


def _digest_saved_plan(path: Path) -> str:
    validate_state_file(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely open Terraform saved plan"
        ) from error
    try:
        opened = os.fstat(descriptor)
        named = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            or stat.S_IMODE(opened.st_mode) != _FILE_MODE
            or opened.st_size < 1
            or opened.st_size > _MAXIMUM_PLAN_FILE_BYTES
        ):
            raise UnsafePathError(
                "Terraform saved plan must be a bounded owner-only singly linked file"
            )
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 65536):
            total += len(chunk)
            if total > _MAXIMUM_PLAN_FILE_BYTES:
                raise StatePersistenceError(
                    "Terraform saved plan exceeds the size limit"
                )
            digest.update(chunk)
        after = os.fstat(descriptor)
        named_after = path.lstat()
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or (named_after.st_dev, named_after.st_ino) != (
            after.st_dev,
            after.st_ino,
        ):
            raise UnsafePathError("Terraform saved plan changed during access")
        return "sha256:" + digest.hexdigest()
    finally:
        os.close(descriptor)


def _promote_staged_plan(staging: Path, final: Path) -> None:
    expected_digest = _digest_saved_plan(staging)
    validate_state_file(final, allow_missing=True)
    if final.exists():
        raise StateConflictError("Terraform saved plan appeared before promotion")
    try:
        os.link(staging, final, follow_symlinks=False)
        staging.unlink()
        _fsync_directory(final.parent)
    except FileExistsError as error:
        raise StateConflictError(
            "Terraform saved plan appeared before promotion"
        ) from error
    except OSError as error:
        raise StatePersistenceError("Terraform saved plan promotion failed") from error
    validate_state_file(final)
    if _digest_saved_plan(final) != expected_digest:
        raise StatePersistenceError("Terraform saved plan promotion changed its bytes")


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    except OSError as error:
        if error.errno not in {errno.EINVAL, errno.ENOTSUP}:
            raise
    finally:
        os.close(descriptor)


def _require_composed_identity(
    checkpoint: TerraformPlanCheckpoint,
    review: TerraformPlanReviewReport,
    composition: TerraformDeployPlanCompositionReport,
    toolchain: TerraformToolchain,
) -> None:
    review_digest = digest_bytes(serialize_json(review.to_object()))
    if (
        checkpoint.operation != _OPERATION
        or checkpoint.classification is not OperationClassification.MUTATING
        or checkpoint.summary.terraform_version != str(toolchain.version)
        or checkpoint.checkpoint_digest != composition.checkpoint_digest
        or checkpoint.summary != composition.summary
        or review_digest != composition.review_digest
    ):
        raise StateConflictError(
            "Terraform deploy plan orchestration composition conflicts"
        )


def _utc_now() -> datetime:
    return datetime.now(UTC)


__all__ = [
    "TERRAFORM_DEPLOY_PLAN_ORCHESTRATION_REPORT_SCHEMA_VERSION",
    "TerraformDeployPlanOrchestrationReport",
    "TerraformPlanOrchestrationStageState",
    "orchestrate_deploy_plan",
]
