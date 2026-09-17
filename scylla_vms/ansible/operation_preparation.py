"""Restartable lock-bound preparation of immutable Ansible operation checkpoints."""

import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from scylla_vms.ansible.commands import validate_playbook_request_policy
from scylla_vms.ansible.operation_authorization import (
    ConfirmationPolicy,
    InteractiveConfirmation,
    OperationAuthorizationStore,
    StoredOperationAuthorization,
    build_operation_authorization,
    confirmation_policy_for,
    validate_operation_authorization,
)
from scylla_vms.ansible.operation_binding import (
    OperationPlanBinding,
    OperationPlanBindingStore,
    StoredOperationPlanBinding,
    build_operation_plan_binding,
    normalized_operation_request_digest,
    readiness_binding_digest,
)
from scylla_vms.ansible.operation_context import (
    OPERATION_CONTEXT_FILENAME_SUFFIX,
    OPERATION_CONTEXT_UNMODELED,
    OperationContext,
    OperationContextStore,
    StoredOperationContext,
    build_operation_context,
    reconstruct_operation_context,
    resolve_operation_context_input,
)
from scylla_vms.ansible.operation_execution import (
    OPERATION_EXECUTION_FILENAME_SUFFIX,
    OperationExecutionStore,
)
from scylla_vms.ansible.orchestration import (
    AnsibleOperationPlan,
    AnsibleOperationPlanStatus,
    ansible_operation_catalog_digest,
    ansible_operation_plan_checkpoint_evidence,
    build_ansible_operation_plan,
)
from scylla_vms.ansible.readiness import (
    ReadinessReport,
    validate_current_readiness_report,
)
from scylla_vms.ansible.registry import PlaybookDefinition
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.ansible.trust import StoredTrustRecord, TrustStore
from scylla_vms.desired import resolve_existing_config
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.inventory import InventoryStore, StoredInventoryRecord
from scylla_vms.journal import (
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    StoredOperationRecord,
    is_initial_plan_record,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.models import OperationRequest
from scylla_vms.observed import ObservedStateStore, StoredObservedState
from scylla_vms.operations import (
    OperationClassification,
    OperationDefinition,
    get_operation,
)
from scylla_vms.persistence import (
    ClusterMetadataStore,
    StoredClusterMetadata,
    digest_bytes,
    parse_timestamp,
    serialize_json,
    validate_digest,
)
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

ANSIBLE_OPERATION_PREPARATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-operation-preparation-report/v1"
)
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")
_COMPANION_SUFFIXES = (
    ".ansible-deploy-context.json",
    ".ansible-deploy-plan.json",
    ".ansible-deploy-prerequisite-execution.json",
    ".ansible-deploy-prerequisite-evidence.json",
    ".ansible-deploy-effective-plan.json",
    ".ansible-deploy-pre-mutation-host-evidence-execution.json",
    ".ansible-deploy-pre-mutation-host-evidence.json",
    ".ansible-deploy-host-evidence-reconciliation.json",
    ".ansible-deploy-base-os-authorization.json",
    ".ansible-deploy-base-os-execution.json",
    ".ansible-deploy-base-os-evidence.json",
    ".ansible-deploy-base-os-reconciliation.json",
    ".ansible-deploy-reboot-plan.json",
    ".ansible-deploy-reboot-authorization.json",
    ".ansible-operation-authorization.json",
    OPERATION_CONTEXT_FILENAME_SUFFIX,
    ".ansible-operation-evidence.json",
    OPERATION_EXECUTION_FILENAME_SUFFIX,
    ".ansible-operation-finalization.json",
    ".ansible-operation-binding.json",
    ".json",
)


class PreparationStageState(StrEnum):
    CREATED = "created"
    REUSED = "reused"
    NOT_REQUIRED = "not-required"
    BLOCKED = "blocked"


class PreparationState(StrEnum):
    PREPARED = "prepared"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class PreparationStage:
    state: PreparationStageState
    schema_version: str | None
    digest: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.state, PreparationStageState):
            raise StatePersistenceError("operation preparation stage state is invalid")
        if (self.schema_version is None) != (self.digest is None):
            raise StatePersistenceError(
                "operation preparation stage provenance is incomplete"
            )
        if self.digest is not None:
            validate_digest(self.digest, "operation preparation stage digest")

    def to_object(self) -> dict[str, object]:
        return {
            "digest": self.digest,
            "schema_version": self.schema_version,
            "state": self.state.value,
        }


@dataclass(frozen=True, slots=True)
class AnsibleOperationPreparationReport:
    """Strict redacted projection of one pre-execution preparation attempt."""

    operation_id: uuid.UUID
    operation: str
    operation_classification: OperationClassification
    effective_classification: OperationClassification
    selected_stable_ids: tuple[str, ...]
    state: PreparationState
    blockers: tuple[str, ...]
    binding: PreparationStage
    context: PreparationStage
    authorization: PreparationStage
    resumable_pre_execution: bool
    schemas: tuple[tuple[str, str | None], ...]
    digests: tuple[tuple[str, str | None], ...]
    schema_version: str = ANSIBLE_OPERATION_PREPARATION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != ANSIBLE_OPERATION_PREPARATION_REPORT_SCHEMA_VERSION:
            raise StatePersistenceError(
                "unsupported Ansible operation preparation report schema"
            )
        if not isinstance(self.operation_id, uuid.UUID):
            raise StatePersistenceError("operation preparation ID must be a UUID")
        try:
            operation = get_operation(self.operation)
        except KeyError as error:
            raise StatePersistenceError(
                "operation preparation operation is invalid"
            ) from error
        if (
            operation.classification is not self.operation_classification
            or not isinstance(self.effective_classification, OperationClassification)
            or not isinstance(self.state, PreparationState)
            or not isinstance(self.resumable_pre_execution, bool)
        ):
            raise StatePersistenceError(
                "operation preparation classification or state conflicts"
            )
        if self.selected_stable_ids != tuple(
            sorted(set(self.selected_stable_ids))
        ) or not all(isinstance(value, str) for value in self.selected_stable_ids):
            raise StatePersistenceError(
                "operation preparation stable IDs are invalid or duplicated"
            )
        if self.blockers != tuple(sorted(set(self.blockers))) or not all(
            _BLOCKER.fullmatch(value) for value in self.blockers
        ):
            raise StatePersistenceError(
                "operation preparation blockers are invalid or duplicated"
            )
        if self.state is PreparationState.PREPARED and (
            self.blockers
            or not self.resumable_pre_execution
            or self.binding.state
            not in {PreparationStageState.CREATED, PreparationStageState.REUSED}
            or self.context.state
            not in {PreparationStageState.CREATED, PreparationStageState.REUSED}
            or self.authorization.state
            not in {
                PreparationStageState.CREATED,
                PreparationStageState.REUSED,
                PreparationStageState.NOT_REQUIRED,
            }
        ):
            raise StatePersistenceError("prepared operation report is inconsistent")
        for label, entries in (("schema", self.schemas), ("digest", self.digests)):
            names = tuple(name for name, _ in entries)
            if names != tuple(sorted(set(names))):
                raise StatePersistenceError(
                    f"operation preparation {label} names are invalid"
                )
        for _, value in self.digests:
            if value is not None:
                validate_digest(value, "operation preparation report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "blockers": list(self.blockers),
            "digests": dict(self.digests),
            "operation": {
                "classification": self.operation_classification.value,
                "effective_classification": self.effective_classification.value,
                "id": str(self.operation_id),
                "kind": self.operation,
                "selected_stable_ids": list(self.selected_stable_ids),
            },
            "resumable_pre_execution": self.resumable_pre_execution,
            "schema_version": self.schema_version,
            "schemas": dict(self.schemas),
            "stages": {
                "authorization": self.authorization.to_object(),
                "binding": self.binding.to_object(),
                "context": self.context.to_object(),
            },
            "state": self.state.value,
        }


@dataclass(frozen=True, slots=True)
class _OfflinePlanPolicy:
    paths: StatePaths

    def validate_playbook_request(
        self,
        name: str,
        *,
        limit: tuple[str, ...],
        tags: tuple[str, ...] = (),
        check: bool = False,
        diff: bool = False,
        verbosity: int = 0,
    ) -> tuple[PlaybookDefinition, str]:
        return validate_playbook_request_policy(
            name,
            limit=limit,
            tags=tags,
            check=check,
            diff=diff,
            verbosity=verbosity,
        )


@dataclass(frozen=True, slots=True)
class _CanonicalPreparationState:
    paths: StatePaths
    metadata: StoredClusterMetadata
    observed: StoredObservedState
    inventory: StoredInventoryRecord
    trust: StoredTrustRecord
    journal: StoredOperationRecord


def prepare_ansible_operation_checkpoints(
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    operation_kind: str,
    request: OperationRequest,
    readiness: ReadinessReport,
    lock: ClusterLock,
    *,
    authorization_proof: InteractiveConfirmation | None = None,
    clock: Callable[[], datetime] | None = None,
) -> AnsibleOperationPreparationReport:
    """Prepare binding, context, and authorization without execution or prompting."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError("operation preparation ID must be a UUID")
    paths = StatePaths.derive(state_root, cluster_name)
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "operation checkpoint preparation requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, operation_kind)
    operation = _validate_request_identity(paths, operation_kind, request)
    metadata, journal = _load_identity_and_history(
        paths, operation_id, operation_kind, request, lock
    )
    existing = _validate_partial_checkpoint_topology(
        paths, operation_id, operation, metadata, lock
    )
    if (
        operation.classification is OperationClassification.READ_ONLY
        and authorization_proof is not None
    ):
        raise StateConflictError(
            "read-only operations must not receive authorization proof"
        )
    if authorization_proof is not None and not isinstance(
        authorization_proof, InteractiveConfirmation
    ):
        raise StateConflictError("operation authorization proof is invalid")
    if operation_kind != "check-jump-hosts":
        return _blocked_unmodeled_report(
            operation_id,
            operation,
            journal,
            existing[0],
            existing[1],
            existing[2],
        )

    current = _load_current_state(paths, metadata, journal, request, readiness)
    context_input = resolve_operation_context_input(request, current.inventory)
    plan = build_ansible_operation_plan(
        lock,
        _OfflinePlanPolicy(paths),
        metadata.record,
        current.inventory,
        operation_kind,
        readiness=readiness,
        active_conditions=context_input.active_conditions,
        intents=context_input.intents,
    )
    now = clock or _utc_now
    if plan.status is AnsibleOperationPlanStatus.BLOCKED:
        _require_journal_plan(journal, plan)
        return _blocked_plan_report(
            operation_id,
            operation,
            plan,
            readiness,
            journal,
        )

    journal = _ensure_journal_plan_checkpoint(
        paths,
        operation_id,
        journal,
        plan,
        lock,
        clock=now,
    )
    binding_store = OperationPlanBindingStore(paths, operation_id)
    context_store = OperationContextStore(paths, operation_id)
    authorization_store = OperationAuthorizationStore(paths, operation_id)
    stored_binding = existing[0]
    binding_clock = (
        now
        if stored_binding is None
        else _timestamp_clock(stored_binding.record.created_at)
    )
    binding_record = build_operation_plan_binding(
        metadata.record,
        request,
        operation_id,
        plan,
        readiness,
        journal,
        clock=binding_clock,
    )
    binding_candidate = _validate_or_predict_binding(binding_record, stored_binding)
    stored_context = existing[1]
    context_clock = (
        now
        if stored_context is None
        else _timestamp_clock(stored_context.record.created_at)
    )
    context_record = build_operation_context(
        metadata.record,
        request,
        operation_id,
        plan,
        binding_candidate,
        clock=context_clock,
    )
    context_candidate = _validate_or_predict_context(context_record, stored_context)
    reconstruct_operation_context(
        paths,
        context_candidate,
        binding_candidate,
        current.inventory,
    )

    stored_authorization = existing[2]
    authorization_candidate = _prepare_authorization_candidate(
        metadata,
        request,
        journal,
        binding_candidate,
        stored_authorization,
        authorization_proof,
        now,
    )

    binding_stage, stored_binding = _persist_binding_stage(
        binding_store, binding_record, stored_binding, lock
    )
    _require_journal_unchanged(paths, operation_id, metadata, journal)
    _refuse_execution(paths, operation_id, metadata, operation_kind, lock)
    if stored_binding != binding_candidate:
        raise StateConflictError("operation preparation binding digest changed")

    context_stage, stored_context = _persist_context_stage(
        context_store, context_record, stored_context, lock
    )
    _require_journal_unchanged(paths, operation_id, metadata, journal)
    _refuse_execution(paths, operation_id, metadata, operation_kind, lock)
    if stored_context != context_candidate:
        raise StateConflictError("operation preparation context digest changed")

    authorization_stage, stored_authorization = _persist_authorization_stage(
        authorization_store,
        authorization_candidate,
        stored_authorization,
        lock,
        request,
        metadata,
    )
    _require_journal_unchanged(paths, operation_id, metadata, journal)
    _refuse_execution(paths, operation_id, metadata, operation_kind, lock)
    return _prepared_report(
        operation_id,
        operation,
        plan,
        readiness,
        journal,
        stored_binding,
        stored_context,
        stored_authorization,
        binding_stage,
        context_stage,
        authorization_stage,
    )


def _validate_request_identity(
    paths: StatePaths,
    operation_kind: str,
    request: OperationRequest,
) -> OperationDefinition:
    try:
        operation = get_operation(operation_kind)
    except KeyError as error:
        raise StateConflictError(
            "operation checkpoint preparation kind is not registered"
        ) from error
    if (
        request.paths != paths
        or request.state_root != paths.state_root
        or request.cluster_name != paths.cluster_root.name
        or request.operation != operation
        or request.provider.name != "oci"
    ):
        raise StateConflictError("operation checkpoint preparation identity conflicts")
    return operation


def _load_identity_and_history(
    paths: StatePaths,
    operation_id: uuid.UUID,
    operation_kind: str,
    request: OperationRequest,
    lock: ClusterLock,
) -> tuple[StoredClusterMetadata, StoredOperationRecord]:
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
    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name=request.cluster_name,
        expected_provider=request.provider.name,
    )
    lock.assert_held_for_operation(paths, operation_kind)
    journal_path = paths.operations / f"{operation_id}.json"
    validate_state_file(journal_path)
    journal = OperationJournalStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )
    request_digest = normalized_operation_request_digest(request)
    if (
        journal.record.operation != operation_kind
        or journal.record.request_digest != request_digest
        or journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.PLAN
        or journal.record.resume_revalidation_digest is not None
    ):
        raise StateConflictError(
            "operation checkpoint preparation requires unchanged IN_PROGRESS/PLAN history"
        )
    _refuse_ambiguous_duplicates(paths, operation_id)
    _refuse_execution(paths, operation_id, metadata, operation_kind, lock)
    return metadata, journal


def _validate_partial_checkpoint_topology(
    paths: StatePaths,
    operation_id: uuid.UUID,
    operation: OperationDefinition,
    metadata: StoredClusterMetadata,
    lock: ClusterLock,
) -> tuple[
    StoredOperationPlanBinding | None,
    StoredOperationContext | None,
    StoredOperationAuthorization | None,
]:
    binding_store = OperationPlanBindingStore(paths, operation_id)
    context_store = OperationContextStore(paths, operation_id)
    authorization_store = OperationAuthorizationStore(paths, operation_id)
    for path in (binding_store.path, context_store.path, authorization_store.path):
        validate_state_file(path, allow_missing=True)
    binding_exists = binding_store.path.exists()
    context_exists = context_store.path.exists()
    authorization_exists = authorization_store.path.exists()
    if (
        operation.classification is OperationClassification.READ_ONLY
        and authorization_exists
    ):
        raise StateConflictError(
            "read-only operation has a forbidden authorization record"
        )
    if context_exists and not binding_exists:
        raise StateConflictError(
            "operation checkpoint context exists without its binding"
        )
    if authorization_exists and not context_exists:
        raise StateConflictError(
            "operation checkpoint authorization exists without its context"
        )
    binding = (
        binding_store.read_locked(
            lock,
            expected_cluster_uuid=metadata.record.cluster_uuid,
            expected_cluster_name=metadata.record.cluster_name,
            expected_operation=operation.name,
        )
        if binding_exists
        else None
    )
    context = (
        context_store.read_locked(
            lock,
            expected_cluster_uuid=metadata.record.cluster_uuid,
            expected_cluster_name=metadata.record.cluster_name,
            expected_operation=operation.name,
        )
        if context_exists
        else None
    )
    authorization = (
        authorization_store.read_locked(
            lock,
            expected_cluster_uuid=metadata.record.cluster_uuid,
            expected_cluster_name=metadata.record.cluster_name,
            expected_operation=operation.name,
        )
        if authorization_exists
        else None
    )
    return binding, context, authorization


def _load_current_state(
    paths: StatePaths,
    metadata: StoredClusterMetadata,
    journal: StoredOperationRecord,
    request: OperationRequest,
    readiness: ReadinessReport,
) -> _CanonicalPreparationState:
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
    if (
        inventory.record.source_manifest_generation != observed.record.generation
        or inventory.record.source_manifest_digest != observed.record.manifest_digest
        or not trust.record.is_fresh_for(observed.record, inventory.record)
    ):
        raise StateConflictError(
            "operation checkpoint preparation canonical evidence drifted"
        )
    reconciliation = reconcile_desired_observed(
        metadata.record.desired_spec,
        observed.record.manifest,
    )
    if reconciliation.status is not ReconciliationClass.MATCH:
        raise StateConflictError(
            "operation checkpoint preparation desired state is not reconciled"
        )
    TrustStore(paths).validate_runtime(trust, inventory)
    resolve_existing_config(request, metadata.record.desired_spec)
    validate_current_readiness_report(readiness, observed, inventory, trust)
    readiness_binding_digest(readiness)
    source = load_ansible_source_bundle()
    validate_digest(source.digest, "Ansible source digest")
    ansible_operation_catalog_digest()
    return _CanonicalPreparationState(
        paths, metadata, observed, inventory, trust, journal
    )


def _validate_or_predict_binding(
    record: OperationPlanBinding,
    existing: StoredOperationPlanBinding | None,
) -> StoredOperationPlanBinding:
    if existing is not None:
        if existing.record != record:
            raise StateConflictError("operation checkpoint preparation binding drifted")
        return existing
    return StoredOperationPlanBinding(record, _record_digest(record.to_object()))


def _validate_or_predict_context(
    record: OperationContext,
    existing: StoredOperationContext | None,
) -> StoredOperationContext:
    if existing is not None:
        if existing.record != record:
            raise StateConflictError("operation checkpoint preparation context drifted")
        return existing
    return StoredOperationContext(record, _record_digest(record.to_object()))


def _prepare_authorization_candidate(
    metadata: StoredClusterMetadata,
    request: OperationRequest,
    journal: StoredOperationRecord,
    binding: StoredOperationPlanBinding,
    existing: StoredOperationAuthorization | None,
    proof: InteractiveConfirmation | None,
    clock: Callable[[], datetime],
) -> StoredOperationAuthorization | None:
    policy = confirmation_policy_for(request, binding.record)
    if policy is ConfirmationPolicy.NOT_REQUIRED:
        if existing is not None:
            raise StateConflictError(
                "read-only operation has a forbidden authorization record"
            )
        return None
    if existing is not None and proof is None:
        validate_operation_authorization(
            metadata.record,
            request,
            binding,
            journal,
            existing.record,
        )
        return existing
    if proof is None:
        raise StateConflictError("operation authorization proof is required")
    record = build_operation_authorization(
        metadata.record,
        request,
        binding,
        journal,
        interactive=proof,
        clock=(
            (lambda: parse_timestamp(existing.record.created_at))
            if existing is not None
            else clock
        ),
    )
    if existing is not None:
        if existing.record != record:
            raise StateConflictError(
                "operation checkpoint preparation authorization drifted"
            )
        return existing
    return StoredOperationAuthorization(record, _record_digest(record.to_object()))


def _persist_binding_stage(
    store: OperationPlanBindingStore,
    record: OperationPlanBinding,
    existing: StoredOperationPlanBinding | None,
    lock: ClusterLock,
) -> tuple[PreparationStage, StoredOperationPlanBinding]:
    if existing is not None:
        return (
            PreparationStage(
                PreparationStageState.REUSED,
                existing.record.schema_version,
                existing.digest,
            ),
            existing,
        )
    stored = store.write_locked(
        record,
        expected_generation=0,
        expected_digest=None,
        lock=lock,
    )
    return (
        PreparationStage(
            PreparationStageState.CREATED,
            stored.record.schema_version,
            stored.digest,
        ),
        stored,
    )


def _persist_context_stage(
    store: OperationContextStore,
    record: OperationContext,
    existing: StoredOperationContext | None,
    lock: ClusterLock,
) -> tuple[PreparationStage, StoredOperationContext]:
    if existing is not None:
        return (
            PreparationStage(
                PreparationStageState.REUSED,
                existing.record.schema_version,
                existing.digest,
            ),
            existing,
        )
    stored = store.write_locked(
        record,
        expected_generation=0,
        expected_digest=None,
        lock=lock,
    )
    return (
        PreparationStage(
            PreparationStageState.CREATED,
            stored.record.schema_version,
            stored.digest,
        ),
        stored,
    )


def _persist_authorization_stage(
    store: OperationAuthorizationStore,
    candidate: StoredOperationAuthorization | None,
    existing: StoredOperationAuthorization | None,
    lock: ClusterLock,
    request: OperationRequest,
    metadata: StoredClusterMetadata,
) -> tuple[PreparationStage, StoredOperationAuthorization | None]:
    if candidate is None:
        return (
            PreparationStage(PreparationStageState.NOT_REQUIRED, None, None),
            None,
        )
    if existing is not None:
        return (
            PreparationStage(
                PreparationStageState.REUSED,
                existing.record.schema_version,
                existing.digest,
            ),
            existing,
        )
    stored = store.write_locked(
        candidate.record,
        expected_generation=0,
        expected_digest=None,
        lock=lock,
        request=request,
        metadata=metadata.record,
    )
    return (
        PreparationStage(
            PreparationStageState.CREATED,
            stored.record.schema_version,
            stored.digest,
        ),
        stored,
    )


def _prepared_report(
    operation_id: uuid.UUID,
    operation: OperationDefinition,
    plan: AnsibleOperationPlan,
    readiness: ReadinessReport,
    journal: StoredOperationRecord,
    binding: StoredOperationPlanBinding,
    context: StoredOperationContext,
    authorization: StoredOperationAuthorization | None,
    binding_stage: PreparationStage,
    context_stage: PreparationStage,
    authorization_stage: PreparationStage,
) -> AnsibleOperationPreparationReport:
    source = load_ansible_source_bundle()
    return AnsibleOperationPreparationReport(
        operation_id=operation_id,
        operation=operation.name,
        operation_classification=operation.classification,
        effective_classification=plan.effective_classification,
        selected_stable_ids=binding.record.selected_stable_ids,
        state=PreparationState.PREPARED,
        blockers=(),
        binding=binding_stage,
        context=context_stage,
        authorization=authorization_stage,
        resumable_pre_execution=True,
        schemas=(
            (
                "authorization",
                None if authorization is None else authorization.record.schema_version,
            ),
            ("binding", binding.record.schema_version),
            ("context", context.record.schema_version),
            ("context_values", context.record.values.schema_version),
            ("journal", journal.record.schema_version),
            ("plan", plan.schema_version),
            ("readiness", readiness.schema_version),
        ),
        digests=(
            ("authorization", None if authorization is None else authorization.digest),
            ("binding", binding.digest),
            ("catalog", binding.record.catalog_digest),
            ("context", context.digest),
            ("context_intent", context.record.intent_context_digest),
            ("inventory", binding.record.inventory_digest),
            ("journal", journal.digest),
            ("observation", binding.record.observation_digest),
            ("plan", plan.plan_digest),
            ("readiness", binding.record.readiness_digest),
            ("request", binding.record.request_digest),
            ("source", source.digest),
            ("trust", binding.record.trust_digest),
        ),
    )


def _blocked_unmodeled_report(
    operation_id: uuid.UUID,
    operation: OperationDefinition,
    journal: StoredOperationRecord,
    binding: StoredOperationPlanBinding | None,
    context: StoredOperationContext | None,
    authorization: StoredOperationAuthorization | None,
) -> AnsibleOperationPreparationReport:
    blocked = PreparationStage(PreparationStageState.BLOCKED, None, None)
    return AnsibleOperationPreparationReport(
        operation_id=operation_id,
        operation=operation.name,
        operation_classification=operation.classification,
        effective_classification=operation.classification,
        selected_stable_ids=(
            () if binding is None else binding.record.selected_stable_ids
        ),
        state=PreparationState.BLOCKED,
        blockers=(OPERATION_CONTEXT_UNMODELED,),
        binding=blocked,
        context=blocked,
        authorization=blocked,
        resumable_pre_execution=False,
        schemas=(
            (
                "authorization",
                None if authorization is None else authorization.record.schema_version,
            ),
            ("binding", None if binding is None else binding.record.schema_version),
            ("context", None if context is None else context.record.schema_version),
            ("journal", journal.record.schema_version),
        ),
        digests=(
            ("authorization", None if authorization is None else authorization.digest),
            ("binding", None if binding is None else binding.digest),
            ("context", None if context is None else context.digest),
            ("journal", journal.digest),
            ("request", journal.record.request_digest),
        ),
    )


def _blocked_plan_report(
    operation_id: uuid.UUID,
    operation: OperationDefinition,
    plan: AnsibleOperationPlan,
    readiness: ReadinessReport,
    journal: StoredOperationRecord,
) -> AnsibleOperationPreparationReport:
    blocked = PreparationStage(PreparationStageState.BLOCKED, None, None)
    source = load_ansible_source_bundle()
    blockers = tuple(
        sorted(
            {
                "operation-plan-blocked",
                *plan.blockers,
                *(blocker for step in plan.steps for blocker in step.blockers),
            }
        )
    )
    return AnsibleOperationPreparationReport(
        operation_id=operation_id,
        operation=operation.name,
        operation_classification=operation.classification,
        effective_classification=plan.effective_classification,
        selected_stable_ids=_selected_stable_ids(plan),
        state=PreparationState.BLOCKED,
        blockers=blockers,
        binding=blocked,
        context=blocked,
        authorization=blocked,
        resumable_pre_execution=False,
        schemas=(
            ("authorization", None),
            ("binding", None),
            ("context", None),
            ("journal", journal.record.schema_version),
            ("plan", plan.schema_version),
            ("readiness", readiness.schema_version),
        ),
        digests=(
            ("authorization", None),
            ("binding", None),
            ("catalog", ansible_operation_catalog_digest()),
            ("context", None),
            ("journal", journal.digest),
            ("plan", plan.plan_digest),
            ("readiness", readiness_binding_digest(readiness)),
            ("request", journal.record.request_digest),
            ("source", source.digest),
        ),
    )


def _require_journal_plan(
    journal: StoredOperationRecord,
    plan: AnsibleOperationPlan,
) -> None:
    if is_initial_plan_record(journal.record):
        return
    if journal.record.evidence != (ansible_operation_plan_checkpoint_evidence(plan),):
        raise StateConflictError(
            "operation checkpoint preparation journal plan evidence drifted"
        )


def _ensure_journal_plan_checkpoint(
    paths: StatePaths,
    operation_id: uuid.UUID,
    journal: StoredOperationRecord,
    plan: AnsibleOperationPlan,
    lock: ClusterLock,
    *,
    clock: Callable[[], datetime],
) -> StoredOperationRecord:
    expected = ansible_operation_plan_checkpoint_evidence(plan)
    if journal.record.evidence == (expected,):
        return journal
    if not is_initial_plan_record(journal.record):
        raise StateConflictError("Ansible operation plan journal checkpoint conflicts")
    lock.assert_held_for_operation(paths, journal.record.operation)
    candidate = journal.record.transition(
        status=JournalStatus.IN_PROGRESS,
        phase=OperationPhase.PLAN,
        evidence=(expected,),
        clock=clock,
    )
    return OperationJournalStore(paths, operation_id).write(
        candidate,
        expected_generation=journal.record.generation,
        expected_digest=journal.digest,
    )


def _require_journal_unchanged(
    paths: StatePaths,
    operation_id: uuid.UUID,
    metadata: StoredClusterMetadata,
    expected: StoredOperationRecord,
) -> None:
    current = OperationJournalStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )
    if current != expected:
        raise StateConflictError(
            "operation checkpoint preparation journal changed during preparation"
        )


def _refuse_execution(
    paths: StatePaths,
    operation_id: uuid.UUID,
    metadata: StoredClusterMetadata,
    operation_kind: str,
    lock: ClusterLock,
) -> None:
    store = OperationExecutionStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    if not store.path.exists():
        return
    store.read_locked(
        lock,
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_operation=operation_kind,
    )
    raise StateConflictError(
        "operation checkpoint preparation refuses an existing execution record"
    )


def _refuse_ambiguous_duplicates(paths: StatePaths, operation_id: uuid.UUID) -> None:
    canonical = str(operation_id)
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list operation checkpoint records"
        ) from error
    for entry in entries:
        for suffix in _COMPANION_SUFFIXES:
            if not entry.name.endswith(suffix):
                continue
            prefix = entry.name[: -len(suffix)]
            try:
                parsed = uuid.UUID(prefix)
            except ValueError:
                break
            if parsed == operation_id and prefix != canonical:
                validate_state_file(entry)
                raise StateConflictError(
                    "operation checkpoint history contains an ambiguous duplicate"
                )
            break


def _selected_stable_ids(plan: AnsibleOperationPlan) -> tuple[str, ...]:
    return tuple(sorted({stable_id for step in plan.steps for stable_id in step.limit}))


def _record_digest(value: dict[str, object]) -> str:
    return digest_bytes(serialize_json(value))


def _timestamp_clock(value: str) -> Callable[[], datetime]:
    timestamp = parse_timestamp(value)
    return lambda: timestamp


def _utc_now() -> datetime:
    return datetime.now(UTC)
