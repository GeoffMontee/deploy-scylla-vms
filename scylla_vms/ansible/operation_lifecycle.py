"""Internal lifecycle composition for the modeled check-jump-hosts operation."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from scylla_vms.ansible.commands import AnsibleCommandBuilder
from scylla_vms.ansible.operation_authorization import OperationAuthorizationStore
from scylla_vms.ansible.operation_binding import (
    OperationPlanBindingStore,
    StoredOperationPlanBinding,
    normalized_operation_request_digest,
)
from scylla_vms.ansible.operation_context import (
    OPERATION_CONTEXT_UNMODELED,
    OperationContextStore,
)
from scylla_vms.ansible.operation_coordinator import (
    CanonicalAnsibleOperationContext,
    ControlledAnsibleExecutables,
    load_ansible_operation_coordination_context,
)
from scylla_vms.ansible.operation_evidence import OperationEvidenceStore
from scylla_vms.ansible.operation_execution import (
    ExecutionAttemptState,
    OperationExecutionStore,
)
from scylla_vms.ansible.operation_finalization import (
    CheckJumpHostsFinalizationReport,
    FinalizationCompanionState,
    OperationFinalizationStore,
    finalize_prepared_check_jump_hosts,
)
from scylla_vms.ansible.operation_orchestrator import (
    CheckJumpHostsFinalizationState,
    CheckJumpHostsOrchestrationReport,
    CheckJumpHostsOrchestrationState,
    orchestrate_prepared_check_jump_hosts,
)
from scylla_vms.ansible.operation_preparation import (
    AnsibleOperationPreparationReport,
    PreparationStageState,
    PreparationState,
    prepare_ansible_operation_checkpoints,
)
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.service import AnsibleService, ProcessRunnerProtocol
from scylla_vms.ansible.source import validate_ansible_config
from scylla_vms.ansible.trust import TrustStore
from scylla_vms.errors import StateConflictError, StateLockError, StatePersistenceError
from scylla_vms.inventory import InventoryStore
from scylla_vms.journal import (
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    StoredOperationRecord,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.models import OperationRequest
from scylla_vms.observed import ObservedStateStore
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import (
    ClusterMetadataStore,
    StoredClusterMetadata,
    validate_digest,
)
from scylla_vms.state import (
    StatePaths,
    refuse_unexpected_terraform_state,
    validate_state_directory,
    validate_state_file,
)

ANSIBLE_CHECK_JUMP_HOSTS_LIFECYCLE_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-check-jump-hosts-lifecycle-report/v1"
)

_OPERATION = "check-jump-hosts"
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")

_MISSING_JOURNAL = "operation-journal-missing"
_JOURNAL_NOT_RESUMABLE = "operation-journal-not-resumable"
_FINALIZATION_MISSING = "operation-finalization-missing"
_REQUEST_REQUIRED = "operation-request-required"
_REQUEST_UNEXPECTED = "operation-request-unexpected"
_WRONG_KIND = "operation-kind-conflict"
_WRONG_CLASS = "operation-classification-conflict"
_AUTHORIZATION_FORBIDDEN = "read-only-authorization-forbidden"
_SEMANTIC_EVIDENCE_MISSING = "semantic-evidence-missing"


class CheckJumpHostsLifecycleState(StrEnum):
    SUCCEEDED = "succeeded"
    BLOCKED = "blocked"
    EXECUTION_STOPPED = "execution-stopped"


class LifecyclePreparationState(StrEnum):
    NOT_REACHED = "not-reached"
    NOT_REQUIRED = "not-required"
    BLOCKED = "blocked"
    CREATED = "created"
    RESUMED = "resumed"
    REUSED = "reused"


class LifecycleExecutionState(StrEnum):
    NOT_REACHED = "not-reached"
    EXECUTED = "executed"
    RESUMED = "resumed"
    REUSED = "reused"
    STOPPED = "stopped"


class LifecycleEvidenceState(StrEnum):
    NOT_REACHED = "not-reached"
    POST_VERIFICATION_PENDING = "post-verification-pending"
    SEMANTIC_EVIDENCE_READY = "semantic-evidence-ready"


class LifecycleFinalizationState(StrEnum):
    NOT_REACHED = "not-reached"
    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class CheckJumpHostsLifecycleReport:
    """Strict redacted result of composing existing lifecycle components."""

    state: CheckJumpHostsLifecycleState
    blockers: tuple[str, ...]
    preparation_state: LifecyclePreparationState
    execution_stage_state: LifecycleExecutionState
    evidence_state: LifecycleEvidenceState
    finalization_state: LifecycleFinalizationState
    journal_status: JournalStatus | None
    journal_phase: OperationPhase | None
    execution_state: ExecutionAttemptState | None
    finalization_companion_state: FinalizationCompanionState | None
    planned_step_count: int
    succeeded_step_count: int
    coordinator_call_count: int
    preparation_call_count: int
    orchestration_call_count: int
    finalization_call_count: int
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    schemas: tuple[tuple[str, str | None], ...]
    digests: tuple[tuple[str, str | None], ...]
    schema_version: str = ANSIBLE_CHECK_JUMP_HOSTS_LIFECYCLE_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_CHECK_JUMP_HOSTS_LIFECYCLE_REPORT_SCHEMA_VERSION
            or not isinstance(self.state, CheckJumpHostsLifecycleState)
            or not isinstance(self.preparation_state, LifecyclePreparationState)
            or not isinstance(self.execution_stage_state, LifecycleExecutionState)
            or not isinstance(self.evidence_state, LifecycleEvidenceState)
            or not isinstance(self.finalization_state, LifecycleFinalizationState)
            or (
                self.journal_status is not None
                and not isinstance(self.journal_status, JournalStatus)
            )
            or (
                self.journal_phase is not None
                and not isinstance(self.journal_phase, OperationPhase)
            )
            or (
                self.execution_state is not None
                and not isinstance(self.execution_state, ExecutionAttemptState)
            )
            or (
                self.finalization_companion_state is not None
                and not isinstance(
                    self.finalization_companion_state, FinalizationCompanionState
                )
            )
            or not isinstance(self.manual_recovery_required, bool)
            or not isinstance(self.automatic_retry_allowed, bool)
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "check-jump-hosts lifecycle report state is invalid"
            )
        if self.blockers != tuple(sorted(set(self.blockers))) or not all(
            _BLOCKER.fullmatch(item) for item in self.blockers
        ):
            raise StatePersistenceError(
                "check-jump-hosts lifecycle blockers are invalid"
            )
        for value, label in (
            (self.planned_step_count, "planned step"),
            (self.succeeded_step_count, "succeeded step"),
            (self.coordinator_call_count, "coordinator call"),
            (self.preparation_call_count, "preparation call"),
            (self.orchestration_call_count, "orchestration call"),
            (self.finalization_call_count, "finalization call"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise StatePersistenceError(
                    f"check-jump-hosts lifecycle {label} count is invalid"
                )
        if (
            self.succeeded_step_count > self.planned_step_count
            or self.coordinator_call_count > self.planned_step_count
            or self.preparation_call_count not in {0, 1}
            or self.orchestration_call_count not in {0, 1}
            or self.finalization_call_count not in {0, 1}
        ):
            raise StatePersistenceError("check-jump-hosts lifecycle counts conflict")
        succeeded = self.state is CheckJumpHostsLifecycleState.SUCCEEDED
        stopped = self.state is CheckJumpHostsLifecycleState.EXECUTION_STOPPED
        if succeeded and (
            self.blockers
            or self.journal_status is not JournalStatus.SUCCEEDED
            or self.journal_phase is not OperationPhase.JOURNAL
            or self.execution_state is not ExecutionAttemptState.SUCCEEDED
            or self.evidence_state is not LifecycleEvidenceState.SEMANTIC_EVIDENCE_READY
            or self.finalization_state
            not in {
                LifecycleFinalizationState.CREATED,
                LifecycleFinalizationState.REUSED,
            }
            or self.finalization_companion_state is None
            or self.manual_recovery_required
            or self.planned_step_count < 1
            or self.succeeded_step_count != self.planned_step_count
        ):
            raise StatePersistenceError(
                "successful check-jump-hosts lifecycle report conflicts"
            )
        if stopped and (
            not self.blockers
            or not self.manual_recovery_required
            or self.execution_stage_state is not LifecycleExecutionState.STOPPED
            or self.finalization_state is not LifecycleFinalizationState.NOT_REACHED
        ):
            raise StatePersistenceError(
                "stopped check-jump-hosts lifecycle report conflicts"
            )
        if self.state is CheckJumpHostsLifecycleState.BLOCKED and (
            not self.blockers
            or self.finalization_state is not LifecycleFinalizationState.NOT_REACHED
        ):
            raise StatePersistenceError(
                "blocked check-jump-hosts lifecycle report conflicts"
            )
        for label, values in (("schema", self.schemas), ("digest", self.digests)):
            names = tuple(name for name, _ in values)
            if names != tuple(sorted(set(names))):
                raise StatePersistenceError(
                    f"check-jump-hosts lifecycle {label} names are invalid"
                )
        for _, digest in self.digests:
            if digest is not None:
                validate_digest(digest, "check-jump-hosts lifecycle digest")

    def to_object(self) -> dict[str, object]:
        return {
            "blockers": list(self.blockers),
            "counts": {
                "coordinator_calls": self.coordinator_call_count,
                "finalization_calls": self.finalization_call_count,
                "orchestration_calls": self.orchestration_call_count,
                "planned_steps": self.planned_step_count,
                "preparation_calls": self.preparation_call_count,
                "succeeded_steps": self.succeeded_step_count,
            },
            "digests": dict(self.digests),
            "execution": {
                "automatic_retry_allowed": self.automatic_retry_allowed,
                "manual_recovery_required": self.manual_recovery_required,
                "state": (
                    None if self.execution_state is None else self.execution_state.value
                ),
            },
            "journal": {
                "phase": (
                    None if self.journal_phase is None else self.journal_phase.value
                ),
                "status": (
                    None if self.journal_status is None else self.journal_status.value
                ),
            },
            "operation": {
                "classification": OperationClassification.READ_ONLY.value,
                "effective_classification": OperationClassification.READ_ONLY.value,
                "kind": _OPERATION,
            },
            "schema_version": self.schema_version,
            "schemas": dict(self.schemas),
            "stages": {
                "evidence": self.evidence_state.value,
                "execution": self.execution_stage_state.value,
                "finalization": {
                    "companion": (
                        None
                        if self.finalization_companion_state is None
                        else self.finalization_companion_state.value
                    ),
                    "state": self.finalization_state.value,
                },
                "preparation": self.preparation_state.value,
            },
            "state": self.state.value,
        }


@dataclass(frozen=True, slots=True)
class _LifecycleSnapshot:
    paths: StatePaths
    metadata: StoredClusterMetadata | None
    journal: StoredOperationRecord | None
    binding: StoredOperationPlanBinding | None
    context_exists: bool
    execution_exists: bool
    evidence_exists: bool
    finalization_exists: bool


def coordinate_check_jump_hosts_lifecycle(
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    request: OperationRequest | None,
    lock: ClusterLock,
    *,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
) -> CheckJumpHostsLifecycleReport:
    """Prepare, execute, semantically verify, and finalize one exact operation."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "check-jump-hosts lifecycle operation ID must be a UUID"
        )
    paths = StatePaths.derive(state_root, cluster_name)
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "check-jump-hosts lifecycle requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)
    request_blocker = _validate_optional_request(paths, request)
    if request_blocker is not None:
        return _blocked_report(
            blockers=request_blocker,
            preparation_state=LifecyclePreparationState.BLOCKED,
        )

    snapshot = _load_lifecycle_snapshot(paths, operation_id, lock)
    if snapshot.journal is None:
        return _blocked_report(
            blockers=(_MISSING_JOURNAL,),
            preparation_state=LifecyclePreparationState.BLOCKED,
        )
    journal = snapshot.journal
    if journal.record.operation != _OPERATION:
        return _blocked_from_snapshot(
            snapshot,
            blockers=(OPERATION_CONTEXT_UNMODELED, _WRONG_KIND),
            preparation_state=LifecyclePreparationState.BLOCKED,
        )
    if snapshot.binding is not None:
        bound = snapshot.binding.record
        if bound.operation != _OPERATION:
            return _blocked_from_snapshot(
                snapshot,
                blockers=(OPERATION_CONTEXT_UNMODELED, _WRONG_KIND),
                preparation_state=LifecyclePreparationState.BLOCKED,
            )
        if (
            bound.operation_classification is not OperationClassification.READ_ONLY
            or bound.effective_classification is not OperationClassification.READ_ONLY
        ):
            return _blocked_from_snapshot(
                snapshot,
                blockers=(_WRONG_CLASS,),
                preparation_state=LifecyclePreparationState.BLOCKED,
            )
    if OperationAuthorizationStore(paths, operation_id).path.exists():
        return _blocked_from_snapshot(
            snapshot,
            blockers=(_AUTHORIZATION_FORBIDDEN,),
            preparation_state=LifecyclePreparationState.BLOCKED,
        )

    reconstructable = snapshot.context_exists
    if reconstructable and request is not None:
        return _blocked_from_snapshot(
            snapshot,
            blockers=(_REQUEST_UNEXPECTED,),
            preparation_state=LifecyclePreparationState.BLOCKED,
        )
    if (
        journal.record.status is JournalStatus.SUCCEEDED
        and journal.record.phase is OperationPhase.JOURNAL
    ):
        if not snapshot.finalization_exists:
            return _blocked_from_snapshot(
                snapshot,
                blockers=(_FINALIZATION_MISSING,),
                preparation_state=LifecyclePreparationState.NOT_REQUIRED,
                manual_recovery_required=True,
            )
        return _run_finalization_only(snapshot, operation_id, lock)

    if (
        journal.record.status is JournalStatus.IN_PROGRESS
        and journal.record.phase is OperationPhase.VERIFY
    ):
        if not snapshot.finalization_exists:
            return _blocked_from_snapshot(
                snapshot,
                blockers=(_FINALIZATION_MISSING,),
                preparation_state=LifecyclePreparationState.NOT_REQUIRED,
                manual_recovery_required=True,
            )
        return _run_finalization_only(snapshot, operation_id, lock)

    if (
        journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.PLAN
    ):
        return _blocked_from_snapshot(
            snapshot,
            blockers=(_JOURNAL_NOT_RESUMABLE,),
            preparation_state=LifecyclePreparationState.NOT_REQUIRED,
            manual_recovery_required=True,
        )
    if snapshot.finalization_exists:
        return _run_finalization_only(snapshot, operation_id, lock)

    preparation_report: AnsibleOperationPreparationReport | None = None
    if not snapshot.execution_exists:
        if not reconstructable and request is None:
            return _blocked_from_snapshot(
                snapshot,
                blockers=(_REQUEST_REQUIRED,),
                preparation_state=LifecyclePreparationState.BLOCKED,
            )
        canonical: CanonicalAnsibleOperationContext | None = None
        selected_request = request
        if reconstructable:
            canonical = load_ansible_operation_coordination_context(
                paths,
                operation_id,
                lock,
            )
            selected_request = canonical.request
        if selected_request is None:
            raise StateConflictError(
                "check-jump-hosts lifecycle request reconstruction failed"
            )
        _require_request_matches_checkpoint(selected_request, snapshot)
        readiness = _establish_preparation_readiness(
            snapshot,
            lock,
            runner=runner,
            executables=executables,
            canonical=canonical,
        )
        preparation_report = prepare_ansible_operation_checkpoints(
            paths.state_root,
            paths.cluster_root.name,
            operation_id,
            _OPERATION,
            selected_request,
            readiness,
            lock,
        )
        if preparation_report.state is PreparationState.BLOCKED:
            return _blocked_from_preparation(snapshot, preparation_report)

    orchestration_report = orchestrate_prepared_check_jump_hosts(
        paths.state_root,
        paths.cluster_root.name,
        operation_id,
        lock,
        runner=runner,
        executables=executables,
    )
    preparation_state = _preparation_stage(preparation_report)
    execution_stage = _execution_stage(
        orchestration_report,
        resumed=snapshot.execution_exists,
    )
    if orchestration_report.state is CheckJumpHostsOrchestrationState.EXECUTION_STOPPED:
        return _stopped_report(
            snapshot,
            preparation_report,
            orchestration_report,
            preparation_state=preparation_state,
            blocker=f"execution-{orchestration_report.latest_outcome.value}",
        )
    if (
        orchestration_report.finalization_state
        is not CheckJumpHostsFinalizationState.SEMANTIC_EVIDENCE_READY
    ):
        return _stopped_report(
            snapshot,
            preparation_report,
            orchestration_report,
            preparation_state=preparation_state,
            blocker=_SEMANTIC_EVIDENCE_MISSING,
        )

    finalization_report = finalize_prepared_check_jump_hosts(
        paths.state_root,
        paths.cluster_root.name,
        operation_id,
        lock,
    )
    return _successful_report(
        preparation_report,
        orchestration_report,
        finalization_report,
        preparation_state=preparation_state,
        execution_stage=execution_stage,
        preparation_calls=1 if preparation_report is not None else 0,
        orchestration_calls=1,
        finalization_calls=1,
    )


def _validate_optional_request(
    paths: StatePaths,
    request: OperationRequest | None,
) -> tuple[str, ...] | None:
    if request is None:
        return None
    if not isinstance(request, OperationRequest):
        raise StateConflictError("check-jump-hosts lifecycle request is invalid")
    if (
        request.paths != paths
        or request.state_root != paths.state_root
        or request.cluster_name != paths.cluster_root.name
        or request.provider.name != "oci"
    ):
        raise StateConflictError(
            "check-jump-hosts lifecycle request identity conflicts"
        )
    if request.operation.name != _OPERATION:
        return (OPERATION_CONTEXT_UNMODELED, _WRONG_KIND)
    if (
        request.operation.classification is not OperationClassification.READ_ONLY
        or not request.operation.implemented
    ):
        return (_WRONG_CLASS,)
    return None


def _load_lifecycle_snapshot(
    paths: StatePaths,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> _LifecycleSnapshot:
    for directory in (
        paths.state_root,
        paths.clusters,
        paths.cluster_root,
        paths.terraform,
        paths.ansible,
        paths.operations,
        paths.logs,
    ):
        validate_state_directory(directory)
    refuse_unexpected_terraform_state(paths, (paths.cluster_root,))
    journal_path = paths.operations / f"{operation_id}.json"
    validate_state_file(journal_path, allow_missing=True)
    stores = (
        OperationPlanBindingStore(paths, operation_id),
        OperationContextStore(paths, operation_id),
        OperationAuthorizationStore(paths, operation_id),
        OperationExecutionStore(paths, operation_id),
        OperationEvidenceStore(paths, operation_id),
        OperationFinalizationStore(paths, operation_id),
    )
    for store in stores:
        validate_state_file(store.path, allow_missing=True)
    if not journal_path.exists():
        return _LifecycleSnapshot(paths, None, None, None, False, False, False, False)

    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name=paths.cluster_root.name
    )
    journal = OperationJournalStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )
    binding_store, context_store, _, execution_store, evidence_store, final_store = (
        stores
    )
    binding_exists = binding_store.path.exists()
    context_exists = context_store.path.exists()
    execution_exists = execution_store.path.exists()
    evidence_exists = evidence_store.path.exists()
    finalization_exists = final_store.path.exists()
    if (
        (context_exists and not binding_exists)
        or (execution_exists and not (binding_exists and context_exists))
        or (evidence_exists and not execution_exists)
        or (
            finalization_exists
            and not (
                binding_exists
                and context_exists
                and execution_exists
                and evidence_exists
            )
        )
    ):
        raise StateConflictError(
            "check-jump-hosts lifecycle companion topology is invalid"
        )
    binding = (
        binding_store.read_locked(
            lock,
            expected_cluster_uuid=metadata.record.cluster_uuid,
            expected_cluster_name=metadata.record.cluster_name,
        )
        if binding_exists
        else None
    )
    return _LifecycleSnapshot(
        paths,
        metadata,
        journal,
        binding,
        context_exists,
        execution_exists,
        evidence_exists,
        finalization_exists,
    )


def _require_request_matches_checkpoint(
    request: OperationRequest,
    snapshot: _LifecycleSnapshot,
) -> None:
    journal = snapshot.journal
    if journal is None:
        raise StateConflictError("check-jump-hosts lifecycle journal is missing")
    request_digest = normalized_operation_request_digest(request)
    if journal.record.request_digest != request_digest or (
        snapshot.binding is not None
        and snapshot.binding.record.request_digest != request_digest
    ):
        raise StateConflictError(
            "check-jump-hosts lifecycle request checkpoint drifted"
        )


def _establish_preparation_readiness(
    snapshot: _LifecycleSnapshot,
    lock: ClusterLock,
    *,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    canonical: CanonicalAnsibleOperationContext | None,
) -> ReadinessReport:
    paths = snapshot.paths
    metadata = snapshot.metadata
    if metadata is None:
        raise StateConflictError("check-jump-hosts lifecycle metadata is missing")
    if canonical is None:
        observed = ObservedStateStore(paths).read(
            expected_cluster_uuid=metadata.record.cluster_uuid,
            expected_cluster_name=metadata.record.cluster_name,
            expected_provider=metadata.record.provider,
        )
        inventory = InventoryStore(paths).read(
            expected_cluster_uuid=metadata.record.cluster_uuid,
            expected_cluster_name=metadata.record.cluster_name,
            expected_provider=metadata.record.provider,
        )
        trust = TrustStore(paths).read(
            expected_cluster_uuid=metadata.record.cluster_uuid,
            expected_cluster_name=metadata.record.cluster_name,
            expected_provider=metadata.record.provider,
        )
    else:
        observed = canonical.observed
        inventory = canonical.inventory
        trust = canonical.trust
    TrustStore(paths).validate_runtime(trust, inventory)
    validate_ansible_config(paths)
    service = AnsibleService(
        AnsibleCommandBuilder(executables.playbook, executables.inventory, paths),
        runner,
    )
    service.version(lock)
    return service.validate_inventory(lock, observed, inventory, trust)


def _run_finalization_only(
    snapshot: _LifecycleSnapshot,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> CheckJumpHostsLifecycleReport:
    report = finalize_prepared_check_jump_hosts(
        snapshot.paths.state_root,
        snapshot.paths.cluster_root.name,
        operation_id,
        lock,
    )
    return _successful_report(
        None,
        None,
        report,
        preparation_state=LifecyclePreparationState.NOT_REQUIRED,
        execution_stage=LifecycleExecutionState.REUSED,
        preparation_calls=0,
        orchestration_calls=0,
        finalization_calls=1,
    )


def _preparation_stage(
    report: AnsibleOperationPreparationReport | None,
) -> LifecyclePreparationState:
    if report is None:
        return LifecyclePreparationState.NOT_REQUIRED
    states = {report.binding.state, report.context.state}
    if states == {PreparationStageState.CREATED}:
        return LifecyclePreparationState.CREATED
    if states == {PreparationStageState.REUSED}:
        return LifecyclePreparationState.REUSED
    if states <= {PreparationStageState.CREATED, PreparationStageState.REUSED}:
        return LifecyclePreparationState.RESUMED
    raise StateConflictError("check-jump-hosts lifecycle preparation stage conflicts")


def _execution_stage(
    report: CheckJumpHostsOrchestrationReport,
    *,
    resumed: bool,
) -> LifecycleExecutionState:
    if report.coordinator_call_count == 0:
        return LifecycleExecutionState.REUSED
    return (
        LifecycleExecutionState.RESUMED if resumed else LifecycleExecutionState.EXECUTED
    )


def _successful_report(
    preparation: AnsibleOperationPreparationReport | None,
    orchestration: CheckJumpHostsOrchestrationReport | None,
    finalization: CheckJumpHostsFinalizationReport,
    *,
    preparation_state: LifecyclePreparationState,
    execution_stage: LifecycleExecutionState,
    preparation_calls: int,
    orchestration_calls: int,
    finalization_calls: int,
) -> CheckJumpHostsLifecycleReport:
    schemas = _merge_named(
        finalization.schemas,
        (
            (
                "finalization_report",
                finalization.schema_version,
            ),
            (
                "orchestration_report",
                None if orchestration is None else orchestration.schema_version,
            ),
            (
                "preparation_report",
                None if preparation is None else preparation.schema_version,
            ),
        ),
    )
    planned = 2 if orchestration is None else orchestration.planned_step_count
    coordinator_calls = (
        0 if orchestration is None else orchestration.coordinator_call_count
    )
    return CheckJumpHostsLifecycleReport(
        state=CheckJumpHostsLifecycleState.SUCCEEDED,
        blockers=(),
        preparation_state=preparation_state,
        execution_stage_state=execution_stage,
        evidence_state=LifecycleEvidenceState.SEMANTIC_EVIDENCE_READY,
        finalization_state=(
            LifecycleFinalizationState.CREATED
            if finalization.companion_state is FinalizationCompanionState.CREATED
            else LifecycleFinalizationState.REUSED
        ),
        journal_status=finalization.journal_status,
        journal_phase=finalization.journal_phase,
        execution_state=ExecutionAttemptState.SUCCEEDED,
        finalization_companion_state=finalization.companion_state,
        planned_step_count=planned,
        succeeded_step_count=planned,
        coordinator_call_count=coordinator_calls,
        preparation_call_count=preparation_calls,
        orchestration_call_count=orchestration_calls,
        finalization_call_count=finalization_calls,
        manual_recovery_required=False,
        automatic_retry_allowed=False,
        schemas=schemas,
        digests=finalization.digests,
    )


def _stopped_report(
    snapshot: _LifecycleSnapshot,
    preparation: AnsibleOperationPreparationReport | None,
    orchestration: CheckJumpHostsOrchestrationReport,
    *,
    preparation_state: LifecyclePreparationState,
    blocker: str,
) -> CheckJumpHostsLifecycleReport:
    journal = snapshot.journal
    if journal is None:
        raise StateConflictError("check-jump-hosts lifecycle journal is missing")
    evidence_state = (
        LifecycleEvidenceState.POST_VERIFICATION_PENDING
        if orchestration.finalization_state
        is CheckJumpHostsFinalizationState.POST_VERIFICATION_PENDING
        else LifecycleEvidenceState.NOT_REACHED
    )
    return CheckJumpHostsLifecycleReport(
        state=CheckJumpHostsLifecycleState.EXECUTION_STOPPED,
        blockers=(blocker,),
        preparation_state=preparation_state,
        execution_stage_state=LifecycleExecutionState.STOPPED,
        evidence_state=evidence_state,
        finalization_state=LifecycleFinalizationState.NOT_REACHED,
        journal_status=journal.record.status,
        journal_phase=journal.record.phase,
        execution_state=orchestration.latest_outcome,
        finalization_companion_state=None,
        planned_step_count=orchestration.planned_step_count,
        succeeded_step_count=orchestration.succeeded_step_count,
        coordinator_call_count=orchestration.coordinator_call_count,
        preparation_call_count=1 if preparation is not None else 0,
        orchestration_call_count=1,
        finalization_call_count=0,
        manual_recovery_required=True,
        automatic_retry_allowed=False,
        schemas=_merge_named(
            () if preparation is None else preparation.schemas,
            orchestration.schemas,
            (
                ("orchestration_report", orchestration.schema_version),
                (
                    "preparation_report",
                    None if preparation is None else preparation.schema_version,
                ),
            ),
        ),
        digests=_merge_named(
            () if preparation is None else preparation.digests,
            orchestration.digests,
        ),
    )


def _blocked_from_preparation(
    snapshot: _LifecycleSnapshot,
    preparation: AnsibleOperationPreparationReport,
) -> CheckJumpHostsLifecycleReport:
    journal = snapshot.journal
    if journal is None:
        raise StateConflictError("check-jump-hosts lifecycle journal is missing")
    return CheckJumpHostsLifecycleReport(
        state=CheckJumpHostsLifecycleState.BLOCKED,
        blockers=preparation.blockers,
        preparation_state=LifecyclePreparationState.BLOCKED,
        execution_stage_state=LifecycleExecutionState.NOT_REACHED,
        evidence_state=LifecycleEvidenceState.NOT_REACHED,
        finalization_state=LifecycleFinalizationState.NOT_REACHED,
        journal_status=journal.record.status,
        journal_phase=journal.record.phase,
        execution_state=None,
        finalization_companion_state=None,
        planned_step_count=0,
        succeeded_step_count=0,
        coordinator_call_count=0,
        preparation_call_count=1,
        orchestration_call_count=0,
        finalization_call_count=0,
        manual_recovery_required=False,
        automatic_retry_allowed=False,
        schemas=_merge_named(
            preparation.schemas,
            (("preparation_report", preparation.schema_version),),
        ),
        digests=preparation.digests,
    )


def _blocked_from_snapshot(
    snapshot: _LifecycleSnapshot,
    *,
    blockers: tuple[str, ...],
    preparation_state: LifecyclePreparationState,
    manual_recovery_required: bool = False,
) -> CheckJumpHostsLifecycleReport:
    journal = snapshot.journal
    return _blocked_report(
        blockers=blockers,
        preparation_state=preparation_state,
        journal_status=None if journal is None else journal.record.status,
        journal_phase=None if journal is None else journal.record.phase,
        journal_schema=None if journal is None else journal.record.schema_version,
        journal_digest=None if journal is None else journal.digest,
        manual_recovery_required=manual_recovery_required,
    )


def _blocked_report(
    *,
    blockers: tuple[str, ...],
    preparation_state: LifecyclePreparationState,
    journal_status: JournalStatus | None = None,
    journal_phase: OperationPhase | None = None,
    journal_schema: str | None = None,
    journal_digest: str | None = None,
    manual_recovery_required: bool = False,
) -> CheckJumpHostsLifecycleReport:
    return CheckJumpHostsLifecycleReport(
        state=CheckJumpHostsLifecycleState.BLOCKED,
        blockers=tuple(sorted(set(blockers))),
        preparation_state=preparation_state,
        execution_stage_state=LifecycleExecutionState.NOT_REACHED,
        evidence_state=LifecycleEvidenceState.NOT_REACHED,
        finalization_state=LifecycleFinalizationState.NOT_REACHED,
        journal_status=journal_status,
        journal_phase=journal_phase,
        execution_state=None,
        finalization_companion_state=None,
        planned_step_count=0,
        succeeded_step_count=0,
        coordinator_call_count=0,
        preparation_call_count=0,
        orchestration_call_count=0,
        finalization_call_count=0,
        manual_recovery_required=manual_recovery_required,
        automatic_retry_allowed=False,
        schemas=(("journal", journal_schema),) if journal_schema is not None else (),
        digests=(("journal", journal_digest),) if journal_digest is not None else (),
    )


def _merge_named(
    *groups: tuple[tuple[str, str | None], ...],
) -> tuple[tuple[str, str | None], ...]:
    merged: dict[str, str | None] = {}
    for group in groups:
        for name, value in group:
            previous = merged.get(name)
            if name in merged and previous is not None and value is not None:
                if previous != value:
                    raise StateConflictError(
                        "check-jump-hosts lifecycle report provenance conflicts"
                    )
            elif name not in merged or previous is None:
                merged[name] = value
    return tuple(sorted(merged.items()))
