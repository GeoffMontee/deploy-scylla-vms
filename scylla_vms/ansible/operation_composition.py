"""Internal one-call composition for the modeled check-jump-hosts operation."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from scylla_vms.ansible.operation_binding import (
    normalized_operation_request_digest,
)
from scylla_vms.ansible.operation_context import (
    CheckJumpHostsContext,
    OperationContextStore,
    validate_check_jump_hosts_operation_request,
)
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.operation_execution import ExecutionAttemptState
from scylla_vms.ansible.operation_finalization import FinalizationCompanionState
from scylla_vms.ansible.operation_initiation import (
    OperationInitiationReport,
    OperationInitiationState,
    initiate_check_jump_hosts_operation,
)
from scylla_vms.ansible.operation_lifecycle import (
    CheckJumpHostsLifecycleReport,
    CheckJumpHostsLifecycleState,
    LifecycleEvidenceState,
    LifecycleExecutionState,
    LifecycleFinalizationState,
    LifecyclePreparationState,
    coordinate_check_jump_hosts_lifecycle,
)
from scylla_vms.ansible.service import ProcessRunnerProtocol
from scylla_vms.errors import StateConflictError, StateLockError, StatePersistenceError
from scylla_vms.journal import (
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    StoredOperationRecord,
    is_initial_plan_record,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.models import OperationRequest
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import ClusterMetadataStore, validate_digest
from scylla_vms.state import StatePaths, validate_state_file

ANSIBLE_CHECK_JUMP_HOSTS_OPERATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-check-jump-hosts-operation-report/v1"
)

_OPERATION = "check-jump-hosts"
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")


class CheckJumpHostsOperationState(StrEnum):
    """Bounded final state of the one-call composition."""

    SUCCEEDED = "succeeded"
    BLOCKED = "blocked"
    EXECUTION_STOPPED = "execution-stopped"


class CheckJumpHostsInitiationStageState(StrEnum):
    """Whether this call created, reused, or observed journal ownership."""

    CREATED = "created"
    REUSED = "reused"
    NOT_REQUIRED = "not-required"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class CheckJumpHostsOperationReport:
    """Strict redacted top-level projection of initiation plus lifecycle."""

    state: CheckJumpHostsOperationState
    blockers: tuple[str, ...]
    initiation_state: CheckJumpHostsInitiationStageState
    lifecycle_state: CheckJumpHostsLifecycleState | None
    preparation_state: LifecyclePreparationState
    execution_stage_state: LifecycleExecutionState
    evidence_state: LifecycleEvidenceState
    finalization_state: LifecycleFinalizationState
    journal_status: JournalStatus | None
    journal_phase: OperationPhase | None
    execution_state: ExecutionAttemptState | None
    finalization_companion_state: FinalizationCompanionState | None
    target_count: int
    planned_step_count: int
    succeeded_step_count: int
    initiation_call_count: int
    lifecycle_call_count: int
    coordinator_call_count: int
    preparation_call_count: int
    orchestration_call_count: int
    finalization_call_count: int
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    schemas: tuple[tuple[str, str | None], ...]
    digests: tuple[tuple[str, str | None], ...]
    schema_version: str = ANSIBLE_CHECK_JUMP_HOSTS_OPERATION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_CHECK_JUMP_HOSTS_OPERATION_REPORT_SCHEMA_VERSION
            or not isinstance(self.state, CheckJumpHostsOperationState)
            or not isinstance(self.initiation_state, CheckJumpHostsInitiationStageState)
            or (
                self.lifecycle_state is not None
                and not isinstance(self.lifecycle_state, CheckJumpHostsLifecycleState)
            )
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
                "check-jump-hosts operation report state is invalid"
            )
        if self.blockers != tuple(sorted(set(self.blockers))) or not all(
            _BLOCKER.fullmatch(item) for item in self.blockers
        ):
            raise StatePersistenceError(
                "check-jump-hosts operation report blockers are invalid"
            )
        for value, label in (
            (self.target_count, "target"),
            (self.planned_step_count, "planned step"),
            (self.succeeded_step_count, "succeeded step"),
            (self.initiation_call_count, "initiation call"),
            (self.lifecycle_call_count, "lifecycle call"),
            (self.coordinator_call_count, "coordinator call"),
            (self.preparation_call_count, "preparation call"),
            (self.orchestration_call_count, "orchestration call"),
            (self.finalization_call_count, "finalization call"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise StatePersistenceError(
                    f"check-jump-hosts operation {label} count is invalid"
                )
        if (
            self.succeeded_step_count > self.planned_step_count
            or self.coordinator_call_count > self.planned_step_count
            or self.initiation_call_count not in {0, 1}
            or self.lifecycle_call_count not in {0, 1}
            or self.preparation_call_count not in {0, 1}
            or self.orchestration_call_count not in {0, 1}
            or self.finalization_call_count not in {0, 1}
        ):
            raise StatePersistenceError(
                "check-jump-hosts operation report counts conflict"
            )
        if self.state is CheckJumpHostsOperationState.SUCCEEDED and (
            self.blockers
            or self.lifecycle_state is not CheckJumpHostsLifecycleState.SUCCEEDED
            or self.journal_status is not JournalStatus.SUCCEEDED
            or self.journal_phase is not OperationPhase.JOURNAL
            or self.manual_recovery_required
        ):
            raise StatePersistenceError(
                "successful check-jump-hosts operation report conflicts"
            )
        if self.state is CheckJumpHostsOperationState.BLOCKED and not self.blockers:
            raise StatePersistenceError(
                "blocked check-jump-hosts operation report conflicts"
            )
        if self.state is CheckJumpHostsOperationState.EXECUTION_STOPPED and (
            not self.blockers
            or self.lifecycle_state
            is not CheckJumpHostsLifecycleState.EXECUTION_STOPPED
            or not self.manual_recovery_required
        ):
            raise StatePersistenceError(
                "stopped check-jump-hosts operation report conflicts"
            )
        if self.initiation_state is CheckJumpHostsInitiationStageState.BLOCKED and (
            self.lifecycle_state is not None
            or self.lifecycle_call_count != 0
            or self.preparation_state is not LifecyclePreparationState.NOT_REACHED
            or self.execution_stage_state is not LifecycleExecutionState.NOT_REACHED
            or self.evidence_state is not LifecycleEvidenceState.NOT_REACHED
            or self.finalization_state is not LifecycleFinalizationState.NOT_REACHED
        ):
            raise StatePersistenceError(
                "blocked check-jump-hosts initiation report conflicts"
            )
        for label, values in (("schema", self.schemas), ("digest", self.digests)):
            names = tuple(name for name, _ in values)
            if names != tuple(sorted(set(names))):
                raise StatePersistenceError(
                    f"check-jump-hosts operation {label} names are invalid"
                )
        for _, digest in self.digests:
            if digest is not None:
                validate_digest(digest, "check-jump-hosts operation digest")

    def to_object(self) -> dict[str, object]:
        return {
            "blockers": list(self.blockers),
            "counts": {
                "coordinator_calls": self.coordinator_call_count,
                "finalization_calls": self.finalization_call_count,
                "initiation_calls": self.initiation_call_count,
                "lifecycle_calls": self.lifecycle_call_count,
                "orchestration_calls": self.orchestration_call_count,
                "planned_steps": self.planned_step_count,
                "preparation_calls": self.preparation_call_count,
                "succeeded_steps": self.succeeded_step_count,
                "targets": self.target_count,
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
                "initiation": self.initiation_state.value,
                "lifecycle": (
                    None if self.lifecycle_state is None else self.lifecycle_state.value
                ),
                "preparation": self.preparation_state.value,
            },
            "state": self.state.value,
        }


def coordinate_check_jump_hosts_operation(
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    request: OperationRequest,
    lock: ClusterLock,
    *,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
) -> CheckJumpHostsOperationReport:
    """Initiate when needed, then drive the exact resumable lifecycle."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "check-jump-hosts operation composition ID must be a UUID"
        )
    paths = StatePaths.derive(state_root, cluster_name)
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "check-jump-hosts operation composition requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)
    request_context = _validate_request(paths, request)

    existing = _read_existing_journal(paths, operation_id)
    initiation: OperationInitiationReport | None = None
    if existing is None or is_initial_plan_record(existing.record):
        initiation = initiate_check_jump_hosts_operation(
            paths.state_root,
            paths.cluster_root.name,
            operation_id,
            _OPERATION,
            request,
            lock,
        )
        if initiation.state is OperationInitiationState.BLOCKED:
            return _blocked_from_initiation(initiation)
    else:
        _require_existing_request(existing, request)

    context_store = OperationContextStore(paths, operation_id)
    validate_state_file(context_store.path, allow_missing=True)
    lifecycle = coordinate_check_jump_hosts_lifecycle(
        paths.state_root,
        paths.cluster_root.name,
        operation_id,
        request if not context_store.path.exists() else None,
        lock,
        runner=runner,
        executables=executables,
    )
    return _from_lifecycle(
        lifecycle,
        initiation=initiation,
        target_count=len(request_context.jump_hosts),
    )


def _validate_request(
    paths: StatePaths,
    request: OperationRequest,
) -> CheckJumpHostsContext:
    if not isinstance(request, OperationRequest):
        raise StateConflictError(
            "check-jump-hosts operation composition request is invalid"
        )
    if (
        request.paths != paths
        or request.state_root != paths.state_root
        or request.cluster_name != paths.cluster_root.name
        or request.provider.name != "oci"
    ):
        raise StateConflictError(
            "check-jump-hosts operation composition request identity conflicts"
        )
    if (
        request.operation.name != _OPERATION
        or request.operation.classification is not OperationClassification.READ_ONLY
        or not request.operation.implemented
    ):
        raise StateConflictError(
            "check-jump-hosts operation composition request kind conflicts"
        )
    return validate_check_jump_hosts_operation_request(request)


def _read_existing_journal(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> StoredOperationRecord | None:
    journal_path = paths.operations / f"{operation_id}.json"
    validate_state_file(journal_path, allow_missing=True)
    if not journal_path.exists():
        return None
    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name=paths.cluster_root.name,
        expected_provider="oci",
    )
    return OperationJournalStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )


def _require_existing_request(
    journal: StoredOperationRecord,
    request: OperationRequest,
) -> None:
    if (
        journal.record.operation != _OPERATION
        or journal.record.request_digest != normalized_operation_request_digest(request)
    ):
        raise StateConflictError(
            "check-jump-hosts operation composition request checkpoint drifted"
        )


def _blocked_from_initiation(
    initiation: OperationInitiationReport,
) -> CheckJumpHostsOperationReport:
    return CheckJumpHostsOperationReport(
        state=CheckJumpHostsOperationState.BLOCKED,
        blockers=initiation.blockers,
        initiation_state=CheckJumpHostsInitiationStageState.BLOCKED,
        lifecycle_state=None,
        preparation_state=LifecyclePreparationState.NOT_REACHED,
        execution_stage_state=LifecycleExecutionState.NOT_REACHED,
        evidence_state=LifecycleEvidenceState.NOT_REACHED,
        finalization_state=LifecycleFinalizationState.NOT_REACHED,
        journal_status=initiation.journal_status,
        journal_phase=initiation.journal_phase,
        execution_state=None,
        finalization_companion_state=None,
        target_count=initiation.target_count,
        planned_step_count=0,
        succeeded_step_count=0,
        initiation_call_count=1,
        lifecycle_call_count=0,
        coordinator_call_count=0,
        preparation_call_count=0,
        orchestration_call_count=0,
        finalization_call_count=0,
        manual_recovery_required=False,
        automatic_retry_allowed=False,
        schemas=(("initiation_report", initiation.schema_version),),
        digests=tuple(
            (name, value)
            for name, value in (
                ("initiation_journal", initiation.journal_digest),
                ("request", initiation.request_digest),
            )
            if value is not None
        ),
    )


def _from_lifecycle(
    lifecycle: CheckJumpHostsLifecycleReport,
    *,
    initiation: OperationInitiationReport | None,
    target_count: int,
) -> CheckJumpHostsOperationReport:
    state = {
        CheckJumpHostsLifecycleState.SUCCEEDED: CheckJumpHostsOperationState.SUCCEEDED,
        CheckJumpHostsLifecycleState.BLOCKED: CheckJumpHostsOperationState.BLOCKED,
        CheckJumpHostsLifecycleState.EXECUTION_STOPPED: (
            CheckJumpHostsOperationState.EXECUTION_STOPPED
        ),
    }[lifecycle.state]
    if initiation is None:
        initiation_state = CheckJumpHostsInitiationStageState.NOT_REQUIRED
    elif initiation.state is OperationInitiationState.CREATED:
        initiation_state = CheckJumpHostsInitiationStageState.CREATED
    elif initiation.state is OperationInitiationState.REUSED:
        initiation_state = CheckJumpHostsInitiationStageState.REUSED
    else:
        raise StateConflictError(
            "check-jump-hosts operation initiation state conflicts"
        )
    schemas = _merge_named(
        lifecycle.schemas,
        (
            (
                "initiation_report",
                None if initiation is None else initiation.schema_version,
            ),
            ("lifecycle_report", lifecycle.schema_version),
        ),
    )
    initiation_digests = (
        ()
        if initiation is None
        else tuple(
            (name, value)
            for name, value in (
                ("initiation_journal", initiation.journal_digest),
                ("request", initiation.request_digest),
            )
            if value is not None
        )
    )
    return CheckJumpHostsOperationReport(
        state=state,
        blockers=lifecycle.blockers,
        initiation_state=initiation_state,
        lifecycle_state=lifecycle.state,
        preparation_state=lifecycle.preparation_state,
        execution_stage_state=lifecycle.execution_stage_state,
        evidence_state=lifecycle.evidence_state,
        finalization_state=lifecycle.finalization_state,
        journal_status=lifecycle.journal_status,
        journal_phase=lifecycle.journal_phase,
        execution_state=lifecycle.execution_state,
        finalization_companion_state=lifecycle.finalization_companion_state,
        target_count=target_count,
        planned_step_count=lifecycle.planned_step_count,
        succeeded_step_count=lifecycle.succeeded_step_count,
        initiation_call_count=0 if initiation is None else 1,
        lifecycle_call_count=1,
        coordinator_call_count=lifecycle.coordinator_call_count,
        preparation_call_count=lifecycle.preparation_call_count,
        orchestration_call_count=lifecycle.orchestration_call_count,
        finalization_call_count=lifecycle.finalization_call_count,
        manual_recovery_required=lifecycle.manual_recovery_required,
        automatic_retry_allowed=lifecycle.automatic_retry_allowed,
        schemas=schemas,
        digests=_merge_named(lifecycle.digests, initiation_digests),
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
                        "check-jump-hosts operation report provenance conflicts"
                    )
            elif name not in merged or previous is None:
                merged[name] = value
    return tuple(sorted(merged.items()))
