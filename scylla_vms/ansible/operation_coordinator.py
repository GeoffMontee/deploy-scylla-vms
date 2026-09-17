"""Internal canonical-state coordinator for one Ansible operation step."""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from scylla_vms.ansible.commands import AnsibleCommandBuilder
from scylla_vms.ansible.operation_authorization import OperationAuthorizationStore
from scylla_vms.ansible.operation_binding import (
    OperationPlanBindingStore,
    StoredOperationPlanBinding,
    normalized_operation_request_digest,
    readiness_binding_digest,
    validate_operation_plan_checkpoint_for_execution,
)
from scylla_vms.ansible.operation_context import (
    OPERATION_CONTEXT_UNMODELED,
    OperationContextStore,
    StoredOperationContext,
    reconstruct_operation_context,
)
from scylla_vms.ansible.operation_execution import (
    ExecutionAttempt,
    ExecutionAttemptState,
    OperationExecutionStore,
    StoredOperationExecution,
    handoff_operation_step,
)
from scylla_vms.ansible.operation_executor import (
    ControlledAnsibleExecutionContext,
    ControlledAnsibleOperationExecutor,
)
from scylla_vms.ansible.orchestration import (
    AnsibleStepIntent,
    ansible_operation_catalog_digest,
)
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.service import AnsibleService, ProcessRunnerProtocol
from scylla_vms.ansible.source import (
    load_ansible_source_bundle,
    validate_ansible_config,
)
from scylla_vms.ansible.trust import StoredTrustRecord, TrustStore
from scylla_vms.desired import resolve_existing_config
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    ToolExecutionError,
    ToolPrerequisiteError,
)
from scylla_vms.inventory import InventoryStore, StoredInventoryRecord
from scylla_vms.journal import OperationJournalStore
from scylla_vms.locking import ClusterLock
from scylla_vms.models import OperationRequest
from scylla_vms.observed import ObservedStateStore, StoredObservedState
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import ClusterMetadataStore, StoredClusterMetadata
from scylla_vms.process import validate_executable
from scylla_vms.reconciliation import (
    ReconciliationClass,
    reconcile_desired_observed,
)
from scylla_vms.state import (
    StatePaths,
    refuse_unexpected_terraform_state,
    validate_state_directory,
    validate_state_file,
)

ANSIBLE_OPERATION_COORDINATOR_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-operation-coordinator-report/v1"
)


@dataclass(frozen=True, slots=True)
class ControlledAnsibleExecutables:
    """Exact validated executable pair supplied by the controlled toolchain."""

    playbook: Path = field(repr=False)
    inventory: Path = field(repr=False)

    def __post_init__(self) -> None:
        playbook = validate_executable(self.playbook)
        inventory = validate_executable(self.inventory)
        if (
            playbook.name != "ansible-playbook"
            or inventory.name != "ansible-inventory"
            or playbook.parent != inventory.parent
        ):
            raise ToolPrerequisiteError(
                "controlled Ansible executables must be the exact sibling pair"
            )
        object.__setattr__(self, "playbook", playbook)
        object.__setattr__(self, "inventory", inventory)


@dataclass(frozen=True, slots=True)
class AnsibleOperationCoordinatorReport:
    """Strict path-, identity-, value-, command-, and output-free projection."""

    execution_generation: int
    execution_state: ExecutionAttemptState
    all_steps_completed: bool
    executable_step_count: int
    attempt_index: int
    step_sequence: int
    attempt_state: ExecutionAttemptState
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    schemas: tuple[tuple[str, str | None], ...]
    digests: tuple[tuple[str, str | None], ...]
    schema_version: str = ANSIBLE_OPERATION_COORDINATOR_REPORT_SCHEMA_VERSION

    def to_object(self) -> dict[str, object]:
        return {
            "attempt": {
                "automatic_retry_allowed": self.automatic_retry_allowed,
                "index": self.attempt_index,
                "manual_recovery_required": self.manual_recovery_required,
                "outcome": self.attempt_state.value,
                "step_sequence": self.step_sequence,
            },
            "digests": dict(self.digests),
            "operation": {
                "all_steps_completed": self.all_steps_completed,
                "executable_step_count": self.executable_step_count,
                "execution_generation": self.execution_generation,
                "state": self.execution_state.value,
            },
            "schema_version": self.schema_version,
            "schemas": dict(self.schemas),
        }


@dataclass(frozen=True, slots=True)
class CanonicalAnsibleOperationContext:
    """Canonical state reconstructed without accepting caller-owned plan inputs."""

    paths: StatePaths
    metadata: StoredClusterMetadata
    observed: StoredObservedState
    inventory: StoredInventoryRecord
    trust: StoredTrustRecord
    binding: StoredOperationPlanBinding
    operation_context: StoredOperationContext
    request: OperationRequest
    active_conditions: tuple[str, ...]
    intents: tuple[AnsibleStepIntent, ...]
    execution: StoredOperationExecution | None


def coordinate_ansible_operation_step(
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    *,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
) -> AnsibleOperationCoordinatorReport:
    """Load canonical context, preflight the toolchain, and hand off one step."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError("Ansible coordinator operation ID must be a UUID")
    paths = StatePaths.derive(state_root, cluster_name)
    if not isinstance(lock, ClusterLock):
        raise StateLockError("Ansible coordinator requires an acquired cluster lock")
    lock.assert_held_for(paths)

    context = load_ansible_operation_coordination_context(paths, operation_id, lock)
    builder = AnsibleCommandBuilder(
        executables.playbook,
        executables.inventory,
        paths,
    )
    service = AnsibleService(builder, runner)
    try:
        service.version(lock)
    except (AnsibleError, ToolExecutionError, ToolPrerequisiteError) as error:
        raise ToolPrerequisiteError(
            "controlled Ansible toolchain validation failed"
        ) from error
    try:
        readiness = service.validate_inventory(
            lock,
            context.observed,
            context.inventory,
            context.trust,
        )
    except (AnsibleError, ToolExecutionError, ToolPrerequisiteError) as error:
        raise AnsibleError("controlled Ansible inventory validation failed") from error
    _validate_readiness_binding(readiness, context.binding)
    plan = service.plan_operation(
        lock,
        context.metadata.record,
        context.inventory,
        context.request.operation.name,
        readiness=readiness,
        active_conditions=context.active_conditions,
        intents=context.intents,
    )
    # Repeat the complete immutable checkpoint immediately before the handoff.
    validate_operation_plan_checkpoint_for_execution(
        lock,
        context.metadata.record,
        context.request,
        operation_id,
        plan,
        readiness,
    )
    executor = ControlledAnsibleOperationExecutor(
        service,
        ControlledAnsibleExecutionContext(
            paths,
            lock,
            context.metadata,
            context.observed,
            context.inventory,
            context.trust,
            readiness,
            context.binding,
        ),
    )
    stored = handoff_operation_step(
        lock,
        context.metadata.record,
        context.request,
        operation_id,
        plan,
        readiness,
        context.intents,
        executor,
        clock=_utc_now,
    )
    return _coordinator_report(stored, context.operation_context)


def load_ansible_operation_coordination_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    *,
    allow_terminal_execution: bool = False,
) -> CanonicalAnsibleOperationContext:
    """Load and validate one prepared checkpoint without probing either tool."""

    for directory in (
        paths.state_root,
        paths.clusters,
        paths.cluster_root,
        paths.terraform,
        paths.ansible,
        paths.ansible_home,
        paths.ansible_local_tmp,
        paths.ansible_fact_cache,
        paths.ansible_control_path,
        paths.operations,
        paths.logs,
    ):
        validate_state_directory(directory)
    refuse_unexpected_terraform_state(paths, (paths.cluster_root,))
    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name=paths.cluster_root.name
    )
    binding = OperationPlanBindingStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )
    lock.assert_held_for_operation(paths, binding.record.operation)
    if binding.record.operation != "check-jump-hosts":
        raise StateConflictError(
            f"Ansible coordinator blocker: {OPERATION_CONTEXT_UNMODELED}"
        )
    operation_context = OperationContextStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_operation=binding.record.operation,
    )
    execution = _load_companions(
        paths,
        operation_id,
        metadata,
        binding,
        lock,
        allow_terminal_execution=allow_terminal_execution,
    )
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
    _validate_local_context(paths, metadata, observed, inventory, trust, binding)
    reconstructed = reconstruct_operation_context(
        paths,
        operation_context,
        binding,
        inventory,
    )
    request = reconstructed.request
    active_conditions = reconstructed.active_conditions
    intents = reconstructed.intents
    resolve_existing_config(request, metadata.record.desired_spec)
    if normalized_operation_request_digest(request) != binding.record.request_digest:
        raise StateConflictError("Ansible coordinator request binding drifted")
    return CanonicalAnsibleOperationContext(
        paths,
        metadata,
        observed,
        inventory,
        trust,
        binding,
        operation_context,
        request,
        active_conditions,
        intents,
        execution,
    )


def _load_companions(
    paths: StatePaths,
    operation_id: uuid.UUID,
    metadata: StoredClusterMetadata,
    binding: StoredOperationPlanBinding,
    lock: ClusterLock,
    *,
    allow_terminal_execution: bool,
) -> StoredOperationExecution | None:
    journal = OperationJournalStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )
    if (
        journal.record.operation != binding.record.operation
        or journal.record.generation != binding.record.journal_generation
        or journal.digest != binding.record.journal_digest
    ):
        raise StateConflictError("Ansible coordinator journal binding drifted")

    authorization_store = OperationAuthorizationStore(paths, operation_id)
    validate_state_file(authorization_store.path, allow_missing=True)
    authorization_exists = authorization_store.path.exists()
    if authorization_exists:
        authorization_store.read_locked(
            lock,
            expected_cluster_uuid=metadata.record.cluster_uuid,
            expected_cluster_name=metadata.record.cluster_name,
            expected_operation=binding.record.operation,
        )
    if (
        binding.record.operation_classification is OperationClassification.READ_ONLY
        and authorization_exists
    ):
        raise StateConflictError(
            "read-only operation has a forbidden authorization record"
        )
    if (
        binding.record.operation_classification is not OperationClassification.READ_ONLY
        and not authorization_exists
    ):
        raise StateConflictError("operation authorization checkpoint is missing")

    execution_store = OperationExecutionStore(paths, operation_id)
    validate_state_file(execution_store.path, allow_missing=True)
    if not execution_store.path.exists():
        return None
    execution = execution_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_operation=binding.record.operation,
    )
    if (
        not allow_terminal_execution
        and execution.record.state is not ExecutionAttemptState.SUCCEEDED
    ):
        raise StateConflictError(
            "started or uncertain execution requires manual recovery review"
        )
    if not allow_terminal_execution and execution.record.all_steps_completed:
        raise StateConflictError(
            "operation execution step set was already fully consumed"
        )
    return execution


def _validate_local_context(
    paths: StatePaths,
    metadata: StoredClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    trust: StoredTrustRecord,
    binding: StoredOperationPlanBinding,
) -> None:
    for path in (
        paths.cluster_metadata,
        paths.terraform_observed,
        paths.ansible_inventory,
        paths.ansible_trust,
        paths.known_hosts,
        paths.ansible_ssh_config,
        paths.ansible_config,
    ):
        validate_state_file(path)
    bound = binding.record
    if (
        inventory.record.source_manifest_generation != observed.record.generation
        or inventory.record.source_manifest_digest != observed.record.manifest_digest
        or observed.record.generation != bound.observation_generation
        or observed.record.manifest_digest != bound.observation_digest
        or inventory.record.generation != bound.inventory_generation
        or inventory.digest != bound.inventory_digest
        or trust.record.generation != bound.trust_generation
        or trust.digest != bound.trust_digest
    ):
        raise StateConflictError("Ansible coordinator canonical evidence drifted")
    reconciliation = reconcile_desired_observed(
        metadata.record.desired_spec,
        observed.record.manifest,
    )
    if reconciliation.status is not ReconciliationClass.MATCH:
        raise StateConflictError("Ansible coordinator desired state is not reconciled")
    if not trust.record.is_fresh_for(observed.record, inventory.record):
        raise StateConflictError("Ansible coordinator SSH trust is stale")
    TrustStore(paths).validate_runtime(trust, inventory)
    validate_ansible_config(paths)
    source = load_ansible_source_bundle()
    if (
        source.version != bound.source_version
        or source.digest != bound.source_digest
        or ansible_operation_catalog_digest() != bound.catalog_digest
    ):
        raise StateConflictError(
            "Ansible coordinator source or catalog binding drifted"
        )


def _validate_readiness_binding(
    readiness: ReadinessReport,
    binding: StoredOperationPlanBinding,
) -> None:
    bound = binding.record
    digest = readiness_binding_digest(readiness)
    if (
        readiness.schema_version != bound.readiness_schema_version
        or readiness.status is not bound.readiness_status
        or digest != bound.readiness_digest
        or readiness.observation_generation != bound.observation_generation
        or readiness.observation_digest != bound.observation_digest
        or readiness.inventory_generation != bound.inventory_generation
        or readiness.inventory_digest != bound.inventory_digest
        or readiness.trust_generation != bound.trust_generation
        or readiness.trust_digest != bound.trust_digest
    ):
        raise StateConflictError("Ansible coordinator readiness binding drifted")


def _coordinator_report(
    stored: StoredOperationExecution,
    operation_context: StoredOperationContext,
) -> AnsibleOperationCoordinatorReport:
    record = stored.record
    attempt: ExecutionAttempt = record.attempts[-1]
    return AnsibleOperationCoordinatorReport(
        execution_generation=record.generation,
        execution_state=record.state,
        all_steps_completed=record.all_steps_completed,
        executable_step_count=record.executable_step_count,
        attempt_index=attempt.attempt_index,
        step_sequence=attempt.step_sequence,
        attempt_state=attempt.state,
        manual_recovery_required=attempt.manual_recovery_required,
        automatic_retry_allowed=attempt.automatic_retry_allowed,
        schemas=(
            ("authorization", record.authorization_schema_version),
            ("binding", record.binding_schema_version),
            ("context", operation_context.record.schema_version),
            ("context_values", operation_context.record.values.schema_version),
            ("execution", record.schema_version),
            ("journal", record.journal_schema_version),
            ("plan", record.plan_schema_version),
            ("readiness", record.readiness_schema_version),
            ("result", attempt.result_schema_version),
        ),
        digests=(
            ("authorization", record.authorization_digest),
            ("binding", record.binding_digest),
            ("catalog", record.catalog_digest),
            ("checkpoint_revalidation", record.checkpoint_revalidation_digest),
            ("command", attempt.command_digest),
            ("context", operation_context.digest),
            ("context_intent", operation_context.record.intent_context_digest),
            ("execution", stored.digest),
            ("inventory", record.inventory_digest),
            ("journal", record.journal_digest),
            ("observation", record.observation_digest),
            ("plan", record.plan_digest),
            ("playbook_source", attempt.playbook_source_digest),
            ("readiness", record.readiness_digest),
            ("request", record.request_digest),
            ("result", attempt.result_digest),
            ("source", record.source_digest),
            ("trust", record.trust_digest),
            ("variables", attempt.variables_digest),
        ),
    )


def _utc_now() -> datetime:
    return datetime.now(UTC)
