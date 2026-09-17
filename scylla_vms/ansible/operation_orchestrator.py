"""Internal deterministic orchestration for prepared check-jump-hosts work."""

import uuid
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from scylla_vms.ansible.commands import (
    ansible_command_intent_digest,
    validate_playbook_request_policy,
)
from scylla_vms.ansible.operation_binding import (
    ConfirmationState,
    ExecutionState,
    OperationResumeState,
)
from scylla_vms.ansible.operation_coordinator import (
    AnsibleOperationCoordinatorReport,
    CanonicalAnsibleOperationContext,
    ControlledAnsibleExecutables,
    coordinate_ansible_operation_step,
    load_ansible_operation_coordination_context,
)
from scylla_vms.ansible.operation_evidence import (
    OperationEvidenceEntry,
    OperationEvidenceStore,
    reconstruct_check_jump_hosts_semantic_facts,
)
from scylla_vms.ansible.operation_execution import (
    AuthorizationConsumption,
    ExecutionAttempt,
    ExecutionAttemptState,
    StoredOperationExecution,
)
from scylla_vms.ansible.orchestration import (
    AnsibleOperationPlan,
    AnsibleOperationPlanStatus,
    AnsibleOperationPlanStep,
    AnsibleOperationStepStatus,
)
from scylla_vms.ansible.registry import OPERATION_PLAYBOOKS
from scylla_vms.ansible.service import ProcessRunnerProtocol
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import digest_bytes, serialize_json, validate_digest
from scylla_vms.state import StatePaths

ANSIBLE_CHECK_JUMP_HOSTS_ORCHESTRATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-check-jump-hosts-orchestration-report/v1"
)
_OPERATION = "check-jump-hosts"
_EXPECTED_PLAYBOOKS = ("inventory-preflight", "connectivity-check")


class CheckJumpHostsOrchestrationState(StrEnum):
    """Bounded outcomes of driving the immutable executable step set."""

    STEPS_SUCCEEDED = "steps-succeeded"
    EXECUTION_STOPPED = "execution-stopped"


class CheckJumpHostsFinalizationState(StrEnum):
    """Truthful boundary before common-journal finalization."""

    POST_VERIFICATION_PENDING = "post-verification-pending"
    SEMANTIC_EVIDENCE_READY = "semantic-evidence-ready"
    NOT_REACHED = "not-reached"


@dataclass(frozen=True, slots=True)
class CheckJumpHostsOrchestrationReport:
    """Strict address-, path-, command-, value-, and identity-free projection."""

    state: CheckJumpHostsOrchestrationState
    finalization_state: CheckJumpHostsFinalizationState
    planned_step_count: int
    succeeded_step_count: int
    coordinator_call_count: int
    execution_generation: int
    latest_step_sequence: int
    latest_outcome: ExecutionAttemptState
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    schemas: tuple[tuple[str, str | None], ...]
    digests: tuple[tuple[str, str | None], ...]
    schema_version: str = ANSIBLE_CHECK_JUMP_HOSTS_ORCHESTRATION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_CHECK_JUMP_HOSTS_ORCHESTRATION_REPORT_SCHEMA_VERSION
        ):
            raise StatePersistenceError(
                "unsupported check-jump-hosts orchestration report schema"
            )
        for value, label in (
            (self.planned_step_count, "planned step count"),
            (self.execution_generation, "execution generation"),
            (self.latest_step_sequence, "latest step sequence"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise StatePersistenceError(
                    f"check-jump-hosts orchestration {label} is invalid"
                )
        if (
            isinstance(self.succeeded_step_count, bool)
            or not isinstance(self.succeeded_step_count, int)
            or not 0 <= self.succeeded_step_count <= self.planned_step_count
            or isinstance(self.coordinator_call_count, bool)
            or not isinstance(self.coordinator_call_count, int)
            or not 0 <= self.coordinator_call_count <= self.planned_step_count
            or not isinstance(self.state, CheckJumpHostsOrchestrationState)
            or not isinstance(self.finalization_state, CheckJumpHostsFinalizationState)
            or not isinstance(self.latest_outcome, ExecutionAttemptState)
            or not isinstance(self.manual_recovery_required, bool)
            or not isinstance(self.automatic_retry_allowed, bool)
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "check-jump-hosts orchestration report state is invalid"
            )
        succeeded = self.state is CheckJumpHostsOrchestrationState.STEPS_SUCCEEDED
        if succeeded != (
            self.finalization_state
            in {
                CheckJumpHostsFinalizationState.POST_VERIFICATION_PENDING,
                CheckJumpHostsFinalizationState.SEMANTIC_EVIDENCE_READY,
            }
        ) or succeeded != (
            self.succeeded_step_count == self.planned_step_count
            and self.latest_outcome is ExecutionAttemptState.SUCCEEDED
            and not self.manual_recovery_required
        ):
            raise StatePersistenceError(
                "check-jump-hosts orchestration finalization state conflicts"
            )
        if not succeeded and not self.manual_recovery_required:
            raise StatePersistenceError(
                "stopped check-jump-hosts orchestration must require recovery"
            )
        for label, entries in (("schema", self.schemas), ("digest", self.digests)):
            names = tuple(name for name, _ in entries)
            if names != tuple(sorted(set(names))):
                raise StatePersistenceError(
                    f"check-jump-hosts orchestration {label} names are invalid"
                )
        for _, digest_value in self.digests:
            if digest_value is not None:
                validate_digest(digest_value, "check-jump-hosts orchestration digest")

    def to_object(self) -> dict[str, object]:
        return {
            "execution": {
                "automatic_retry_allowed": self.automatic_retry_allowed,
                "generation": self.execution_generation,
                "latest_outcome": self.latest_outcome.value,
                "latest_step_sequence": self.latest_step_sequence,
                "manual_recovery_required": self.manual_recovery_required,
            },
            "finalization": {
                "common_journal": "unchanged-plan",
                "healthy_claimed": False,
                "public_report_reconstructable": (
                    self.finalization_state
                    is CheckJumpHostsFinalizationState.SEMANTIC_EVIDENCE_READY
                ),
                "state": self.finalization_state.value,
            },
            "operation": {
                "classification": OperationClassification.READ_ONLY.value,
                "effective_classification": OperationClassification.READ_ONLY.value,
                "kind": _OPERATION,
            },
            "schema_version": self.schema_version,
            "schemas": dict(self.schemas),
            "sequencing": {
                "coordinator_call_count": self.coordinator_call_count,
                "planned_step_count": self.planned_step_count,
                "succeeded_step_count": self.succeeded_step_count,
            },
            "state": self.state.value,
            "digests": dict(self.digests),
        }


@dataclass(frozen=True, slots=True)
class PreparedCheckJumpHostsStep:
    """One reconstructed immutable step used by execution and finalization."""

    sequence: int
    playbook: str
    classification: OperationClassification
    limit: tuple[str, ...]
    variables_digest: str
    command_digest: str
    playbook_source_digest: str
    result_schema_version: str


def orchestrate_prepared_check_jump_hosts(
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    *,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
) -> CheckJumpHostsOrchestrationReport:
    """Drive each exact prepared step once, stopping at every uncertain outcome."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "check-jump-hosts orchestration operation ID must be a UUID"
        )
    paths = StatePaths.derive(state_root, cluster_name)
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "check-jump-hosts orchestration requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)

    context, expected = _load_orchestration_checkpoint(paths, operation_id, lock)
    execution = validate_prepared_check_jump_hosts_execution(context, expected)
    if execution is not None:
        report = _terminal_report(
            execution,
            context,
            expected,
            coordinator_calls=0,
            lock=lock,
        )
        if report is not None:
            return report

    initial_attempt_count = 0 if execution is None else len(execution.record.attempts)
    maximum_calls = len(expected) - initial_attempt_count
    for coordinator_calls in range(1, maximum_calls + 1):
        coordinator_report: AnsibleOperationCoordinatorReport | None = None
        coordinator_error: AnsibleError | None = None
        try:
            coordinator_report = coordinate_ansible_operation_step(
                paths.state_root,
                paths.cluster_root.name,
                operation_id,
                lock,
                runner=runner,
                executables=executables,
            )
        except AnsibleError as error:
            coordinator_error = error

        current, current_expected = _load_orchestration_checkpoint(
            paths, operation_id, lock
        )
        _require_unchanged_checkpoint(context, expected, current, current_expected)
        execution = validate_prepared_check_jump_hosts_execution(
            current, current_expected
        )
        if execution is None:
            if coordinator_error is not None:
                raise coordinator_error
            raise StateConflictError(
                "check-jump-hosts coordinator did not persist execution intent"
            )
        if coordinator_report is not None:
            _validate_coordinator_report(coordinator_report, execution)
        terminal = _terminal_report(
            execution,
            current,
            current_expected,
            coordinator_calls=coordinator_calls,
            lock=lock,
        )
        if terminal is not None:
            return terminal
        if coordinator_error is not None:
            raise coordinator_error

    raise StateConflictError(
        "check-jump-hosts orchestration reached the immutable step-count bound"
    )


def _load_orchestration_checkpoint(
    paths: StatePaths,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> tuple[
    CanonicalAnsibleOperationContext,
    tuple[PreparedCheckJumpHostsStep, ...],
]:
    context = load_ansible_operation_coordination_context(
        paths,
        operation_id,
        lock,
        allow_terminal_execution=True,
    )
    bound = context.binding.record
    operation_context = context.operation_context.record
    if (
        bound.operation != _OPERATION
        or bound.operation_classification is not OperationClassification.READ_ONLY
        or bound.effective_classification is not OperationClassification.READ_ONLY
        or bound.plan_status is not AnsibleOperationPlanStatus.READY
        or bound.confirmation_state is not ConfirmationState.NOT_COLLECTED
        or bound.execution_state is not ExecutionState.NOT_STARTED
        or operation_context.operation != _OPERATION
        or operation_context.operation_classification
        is not OperationClassification.READ_ONLY
        or operation_context.effective_classification
        is not OperationClassification.READ_ONLY
        or context.request.operation.name != _OPERATION
        or context.request.operation.classification
        is not OperationClassification.READ_ONLY
        or not context.request.operation.implemented
    ):
        raise StateConflictError(
            "check-jump-hosts orchestration requires an exact read-only ready checkpoint"
        )
    return context, reconstruct_prepared_check_jump_hosts_steps(context)


def reconstruct_prepared_check_jump_hosts_steps(
    context: CanonicalAnsibleOperationContext,
) -> tuple[PreparedCheckJumpHostsStep, ...]:
    """Rebuild the exact catalog/source/command-bound two-step sequence."""

    mapped = OPERATION_PLAYBOOKS.get(_OPERATION)
    if (
        mapped is None
        or tuple(step.playbook for step in mapped) != _EXPECTED_PLAYBOOKS
        or any(step.condition != "always" for step in mapped)
        or context.active_conditions
        or len(context.intents) != len(mapped)
        or tuple(intent.sequence for intent in context.intents)
        != tuple(range(1, len(mapped) + 1))
    ):
        raise StateConflictError(
            "check-jump-hosts immutable operation step mapping drifted"
        )
    source = load_ansible_source_bundle()
    source_digests = {item.path: item.digest for item in source.files}
    expected: list[PreparedCheckJumpHostsStep] = []
    plan_steps: list[AnsibleOperationPlanStep] = []
    for sequence, (mapped_step, intent) in enumerate(
        zip(mapped, context.intents, strict=True),
        start=1,
    ):
        definition, _ = validate_playbook_request_policy(
            mapped_step.playbook,
            limit=intent.limit,
            tags=intent.tags,
            check=intent.check,
            diff=intent.diff,
            verbosity=intent.verbosity,
        )
        if (
            definition.classification is not OperationClassification.READ_ONLY
            or not intent.check
            or intent.health_gate_passed
        ):
            raise StateConflictError(
                "check-jump-hosts immutable operation step policy drifted"
            )
        validated_variables = definition.validate_variables(dict(intent.variables))
        variables_digest = digest_bytes(serialize_json(validated_variables))
        command_digest = ansible_command_intent_digest(
            definition,
            step_sequence=sequence,
            limit=intent.limit,
            variables_digest=variables_digest,
            tags=intent.tags,
            check=intent.check,
            diff=intent.diff,
            verbosity=intent.verbosity,
        )
        playbook_source_digest = source_digests.get(f"playbooks/{definition.filename}")
        if playbook_source_digest is None:
            raise StateConflictError(
                "check-jump-hosts playbook source binding is missing"
            )
        validate_digest(
            playbook_source_digest,
            "check-jump-hosts playbook source digest",
        )
        expected.append(
            PreparedCheckJumpHostsStep(
                sequence,
                definition.name,
                definition.classification,
                intent.limit,
                variables_digest,
                command_digest,
                playbook_source_digest,
                definition.execution_result_schema_version,
            )
        )
        plan_steps.append(
            AnsibleOperationPlanStep(
                sequence,
                definition.name,
                mapped_step.condition,
                definition.classification,
                AnsibleOperationStepStatus.READY,
                intent.limit,
                tuple(validated_variables),
                variables_digest,
                intent.check,
                (),
            )
        )
    plan = AnsibleOperationPlan(
        _OPERATION,
        OperationClassification.READ_ONLY,
        OperationClassification.READ_ONLY,
        True,
        (),
        AnsibleOperationPlanStatus.READY,
        (),
        tuple(plan_steps),
    )
    if (
        plan.plan_digest != context.binding.record.plan_digest
        or plan.plan_digest != context.operation_context.record.plan_digest
    ):
        raise StateConflictError(
            "check-jump-hosts reconstructed immutable plan digest drifted"
        )
    return tuple(expected)


def validate_prepared_check_jump_hosts_execution(
    context: CanonicalAnsibleOperationContext,
    expected: tuple[PreparedCheckJumpHostsStep, ...],
) -> StoredOperationExecution | None:
    """Validate exact ordered execution without authorizing another attempt."""

    stored = context.execution
    if stored is None:
        return None
    record = stored.record
    bound = context.binding.record
    if (
        record.cluster_uuid != bound.cluster_uuid
        or record.cluster_name != bound.cluster_name
        or record.operation_id != bound.operation_id
        or record.operation != _OPERATION
        or record.operation_classification is not OperationClassification.READ_ONLY
        or record.effective_classification is not OperationClassification.READ_ONLY
        or record.request_digest != bound.request_digest
        or record.plan_schema_version != bound.plan_schema_version
        or record.plan_digest != bound.plan_digest
        or record.binding_schema_version != bound.schema_version
        or record.binding_generation != bound.generation
        or record.binding_digest != context.binding.digest
        or record.authorization_consumption is not AuthorizationConsumption.NOT_REQUIRED
        or record.authorization_schema_version is not None
        or record.authorization_generation is not None
        or record.authorization_digest is not None
        or record.authorization_consumed_at is not None
        or record.catalog_digest != bound.catalog_digest
        or record.source_version != bound.source_version
        or record.source_digest != bound.source_digest
        or record.readiness_schema_version != bound.readiness_schema_version
        or record.readiness_digest != bound.readiness_digest
        or record.observation_generation != bound.observation_generation
        or record.observation_digest != bound.observation_digest
        or record.inventory_generation != bound.inventory_generation
        or record.inventory_digest != bound.inventory_digest
        or record.trust_generation != bound.trust_generation
        or record.trust_digest != bound.trust_digest
        or record.journal_schema_version != bound.journal_schema_version
        or record.journal_generation != bound.journal_generation
        or record.journal_digest != bound.journal_digest
        or record.journal_status is not JournalStatus.IN_PROGRESS
        or record.journal_phase is not OperationPhase.PLAN
        or record.checkpoint_revalidation_digest
        != _checkpoint_revalidation_digest(context)
        or record.executable_step_count != len(expected)
        or len(record.attempts) > len(expected)
    ):
        raise StateConflictError(
            "check-jump-hosts durable execution checkpoint drifted"
        )
    expected_generation = (
        len(record.attempts) * 2
        if record.state is not ExecutionAttemptState.STARTED
        else len(record.attempts) * 2 - 1
    )
    if record.generation != expected_generation:
        raise StateConflictError(
            "check-jump-hosts durable execution generation drifted"
        )
    for attempt, expected_step in zip(
        record.attempts,
        expected[: len(record.attempts)],
        strict=True,
    ):
        _validate_attempt(attempt, expected_step)
    return stored


def _validate_attempt(
    attempt: ExecutionAttempt, expected: PreparedCheckJumpHostsStep
) -> None:
    if (
        attempt.attempt_index != expected.sequence
        or attempt.step_sequence != expected.sequence
        or attempt.playbook != expected.playbook
        or attempt.classification is not expected.classification
        or attempt.limit != expected.limit
        or attempt.variables_digest != expected.variables_digest
        or attempt.command_digest != expected.command_digest
        or attempt.playbook_source_digest != expected.playbook_source_digest
        or attempt.result_schema_version != expected.result_schema_version
    ):
        raise StateConflictError(
            "check-jump-hosts durable execution step order or binding drifted"
        )


def _checkpoint_revalidation_digest(
    context: CanonicalAnsibleOperationContext,
) -> str:
    bound = context.binding.record
    return digest_bytes(
        serialize_json(
            {
                "authorization_digest": None,
                "authorization_schema_version": None,
                "binding_digest": context.binding.digest,
                "catalog_digest": bound.catalog_digest,
                "confirmation_state": ConfirmationState.NOT_REQUIRED.value,
                "journal_digest": bound.journal_digest,
                "plan_digest": bound.plan_digest,
                "readiness_digest": bound.readiness_digest,
                "request_digest": bound.request_digest,
                "resume_state": OperationResumeState.RESUMABLE_PRE_EXECUTION.value,
                "source_digest": bound.source_digest,
            }
        )
    )


def _validate_coordinator_report(
    report: AnsibleOperationCoordinatorReport,
    execution: StoredOperationExecution,
) -> None:
    attempt = execution.record.attempts[-1]
    if (
        report.execution_generation != execution.record.generation
        or report.execution_state is not execution.record.state
        or report.all_steps_completed is not execution.record.all_steps_completed
        or report.executable_step_count != execution.record.executable_step_count
        or report.attempt_index != attempt.attempt_index
        or report.step_sequence != attempt.step_sequence
        or report.attempt_state is not attempt.state
        or report.manual_recovery_required is not attempt.manual_recovery_required
        or report.automatic_retry_allowed is not attempt.automatic_retry_allowed
        or dict(report.digests).get("execution") != execution.digest
    ):
        raise StateConflictError(
            "check-jump-hosts coordinator report conflicts with durable execution"
        )


def _terminal_report(
    execution: StoredOperationExecution,
    context: CanonicalAnsibleOperationContext,
    expected: tuple[PreparedCheckJumpHostsStep, ...],
    *,
    coordinator_calls: int,
    lock: ClusterLock,
) -> CheckJumpHostsOrchestrationReport | None:
    record = execution.record
    attempt = record.attempts[-1]
    if (
        record.state is ExecutionAttemptState.SUCCEEDED
        and not record.all_steps_completed
    ):
        return None
    succeeded_count = sum(
        item.state is ExecutionAttemptState.SUCCEEDED for item in record.attempts
    )
    steps_succeeded = record.all_steps_completed
    finalization_state = CheckJumpHostsFinalizationState.NOT_REACHED
    evidence_schema: str | None = None
    evidence_digest: str | None = None
    inventory_projection_schema: str | None = None
    connectivity_projection_schema: str | None = None
    if steps_succeeded:
        evidence_store = OperationEvidenceStore(context.paths, record.operation_id)
        if evidence_store.path.exists():
            evidence = evidence_store.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
                expected_operation=_OPERATION,
            )
            facts = reconstruct_check_jump_hosts_semantic_facts(
                evidence,
                binding=context.binding,
                context=context.operation_context,
                intents=context.intents,
            )
            validate_check_jump_hosts_evidence_receipts(
                execution, evidence.record.entries
            )
            finalization_state = CheckJumpHostsFinalizationState.SEMANTIC_EVIDENCE_READY
            evidence_schema = evidence.record.schema_version
            evidence_digest = facts.evidence_digest
            inventory_projection_schema = facts.inventory_preflight.schema_version
            connectivity_projection_schema = facts.connectivity.schema_version
        else:
            finalization_state = (
                CheckJumpHostsFinalizationState.POST_VERIFICATION_PENDING
            )
    return CheckJumpHostsOrchestrationReport(
        state=(
            CheckJumpHostsOrchestrationState.STEPS_SUCCEEDED
            if steps_succeeded
            else CheckJumpHostsOrchestrationState.EXECUTION_STOPPED
        ),
        finalization_state=finalization_state,
        planned_step_count=len(expected),
        succeeded_step_count=succeeded_count,
        coordinator_call_count=coordinator_calls,
        execution_generation=record.generation,
        latest_step_sequence=attempt.step_sequence,
        latest_outcome=attempt.state,
        manual_recovery_required=attempt.manual_recovery_required,
        automatic_retry_allowed=attempt.automatic_retry_allowed,
        schemas=(
            ("binding", record.binding_schema_version),
            ("connectivity_projection", connectivity_projection_schema),
            ("context", context.operation_context.record.schema_version),
            (
                "context_values",
                context.operation_context.record.values.schema_version,
            ),
            ("evidence", evidence_schema),
            ("execution", record.schema_version),
            ("inventory_projection", inventory_projection_schema),
            ("journal", record.journal_schema_version),
            ("plan", record.plan_schema_version),
            ("result", attempt.result_schema_version),
        ),
        digests=(
            ("binding", record.binding_digest),
            ("catalog", record.catalog_digest),
            ("checkpoint_revalidation", record.checkpoint_revalidation_digest),
            ("context", context.operation_context.digest),
            ("evidence", evidence_digest),
            ("execution", execution.digest),
            ("inventory", record.inventory_digest),
            ("journal", record.journal_digest),
            ("observation", record.observation_digest),
            ("plan", record.plan_digest),
            ("readiness", record.readiness_digest),
            ("request", record.request_digest),
            ("result", attempt.result_digest),
            ("source", record.source_digest),
            ("trust", record.trust_digest),
        ),
    )


def validate_check_jump_hosts_evidence_receipts(
    execution: StoredOperationExecution,
    entries: tuple[OperationEvidenceEntry, ...],
) -> None:
    """Require each succeeded attempt to bind its exact semantic projection."""

    if len(execution.record.attempts) != len(entries):
        raise StateConflictError(
            "check-jump-hosts semantic evidence and execution counts conflict"
        )
    for attempt, raw_entry in zip(execution.record.attempts, entries, strict=True):
        entry = raw_entry
        receipt = {
            "command_digest": attempt.command_digest,
            "evidence_digest": entry.projection_digest,
            "exit_code": attempt.exit_code,
            "playbook": attempt.playbook,
            "schema_version": attempt.result_schema_version,
            "status": "succeeded",
            "step_sequence": attempt.step_sequence,
        }
        if (
            attempt.state is not ExecutionAttemptState.SUCCEEDED
            or attempt.exit_code != 0
            or attempt.result_digest != digest_bytes(serialize_json(receipt))
        ):
            raise StateConflictError(
                "check-jump-hosts durable evidence receipt binding conflicts"
            )


def _require_unchanged_checkpoint(
    previous: CanonicalAnsibleOperationContext,
    expected: tuple[PreparedCheckJumpHostsStep, ...],
    current: CanonicalAnsibleOperationContext,
    current_expected: tuple[PreparedCheckJumpHostsStep, ...],
) -> None:
    if (
        previous.metadata != current.metadata
        or previous.observed != current.observed
        or previous.inventory != current.inventory
        or previous.trust != current.trust
        or previous.binding != current.binding
        or previous.operation_context != current.operation_context
        or previous.request != current.request
        or previous.active_conditions != current.active_conditions
        or previous.intents != current.intents
        or expected != current_expected
    ):
        raise StateConflictError(
            "check-jump-hosts immutable orchestration checkpoint changed"
        )
