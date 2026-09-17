"""Durable offline request/plan bindings and fail-closed resume validation."""

import ipaddress
import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast

from scylla_vms.ansible.orchestration import (
    ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION,
    AnsibleOperationPlan,
    AnsibleOperationPlanStatus,
    AnsibleOperationStepStatus,
    ansible_operation_catalog_digest,
    ansible_operation_plan_checkpoint_evidence,
)
from scylla_vms.ansible.readiness import (
    READINESS_SCHEMA_VERSION,
    EvidenceStatus,
    ReadinessReport,
    RouteReadiness,
    TrustReadiness,
)
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.contracts import fields_for_operation
from scylla_vms.errors import (
    ConfigurationError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import (
    JOURNAL_SCHEMA_VERSION,
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    OperationRecord,
    StoredOperationRecord,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.models import DeferredValue, OperationRequest
from scylla_vms.operations import OperationClassification, get_operation
from scylla_vms.persistence import (
    AtomicJsonFile,
    ClusterMetadata,
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
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)

ANSIBLE_OPERATION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-operation-binding/v1"
)
ANSIBLE_OPERATION_RESUME_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-operation-resume-validation/v2"
)
OPERATION_BINDING_FILENAME_SUFFIX = ".ansible-operation-binding.json"
_SOURCE_VERSION = re.compile(r"[a-z][a-z0-9-]{0,63}/v[1-9][0-9]{0,8}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CLASSIFICATION_RANK = {
    OperationClassification.READ_ONLY: 0,
    OperationClassification.MUTATING: 1,
    OperationClassification.SENSITIVE: 2,
    OperationClassification.DESTRUCTIVE: 3,
}


class HeldClusterLockProtocol(Protocol):
    def assert_held_for(self, paths: StatePaths) -> None:
        """Prove this lock protects the requested canonical state."""


class ConfirmationState(StrEnum):
    NOT_COLLECTED = "not-collected"
    NOT_REQUIRED = "not-required"
    AUTHORIZED = "authorized"


class ExecutionState(StrEnum):
    NOT_STARTED = "not-started"


class OperationResumeState(StrEnum):
    RESUMABLE_PRE_EXECUTION = "resumable-pre-execution"
    CONFIRMATION_STATE_AMBIGUOUS = "not-resumable-confirmation-state-ambiguous"
    EXECUTION_MAY_HAVE_STARTED = "not-resumable-execution-may-have-started"
    DESTRUCTIVE_BOUNDARY_RECORDED = "not-resumable-destructive-boundary-recorded"
    INTERRUPTED = "not-resumable-interrupted"
    FAILED = "not-resumable-failed"
    COMPLETED = "not-resumable-completed"
    AMBIGUOUS_HISTORY = "not-resumable-ambiguous-history"


@dataclass(frozen=True, slots=True)
class OperationPlanBinding:
    """One immutable operation request and offline Ansible-plan checkpoint."""

    generation: int
    created_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    operation_classification: OperationClassification
    effective_classification: OperationClassification
    selected_stable_ids: tuple[str, ...]
    request_digest: str
    plan_schema_version: str
    plan_digest: str
    plan_status: AnsibleOperationPlanStatus
    catalog_digest: str
    source_version: str
    source_digest: str
    readiness_schema_version: str
    readiness_digest: str
    readiness_status: EvidenceStatus
    observation_generation: int | None
    observation_digest: str | None
    inventory_generation: int
    inventory_digest: str
    trust_generation: int | None
    trust_digest: str | None
    journal_schema_version: str
    journal_generation: int
    journal_digest: str
    confirmation_state: ConfirmationState = ConfirmationState.NOT_COLLECTED
    execution_state: ExecutionState = ExecutionState.NOT_STARTED
    schema_version: str = ANSIBLE_OPERATION_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != ANSIBLE_OPERATION_BINDING_SCHEMA_VERSION:
            raise StatePersistenceError(
                "unsupported Ansible operation binding schema version"
            )
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation != 1
        ):
            raise StatePersistenceError(
                "Ansible operation binding generation must be one"
            )
        if not isinstance(self.cluster_uuid, uuid.UUID) or not isinstance(
            self.operation_id, uuid.UUID
        ):
            raise StatePersistenceError(
                "Ansible operation binding identities must be UUIDs"
            )
        try:
            validate_cluster_name(self.cluster_name)
            operation = get_operation(self.operation)
        except (ConfigurationError, KeyError) as error:
            raise StatePersistenceError(
                "Ansible operation binding identity is invalid"
            ) from error
        if (
            not isinstance(self.operation_classification, OperationClassification)
            or not isinstance(self.effective_classification, OperationClassification)
            or operation.classification is not self.operation_classification
            or _CLASSIFICATION_RANK[self.effective_classification]
            < _CLASSIFICATION_RANK[self.operation_classification]
        ):
            raise StatePersistenceError(
                "Ansible operation binding classification conflicts"
            )
        if not isinstance(self.created_at, str):
            raise StatePersistenceError(
                "Ansible operation binding timestamp must be a string"
            )
        parse_timestamp(self.created_at)
        _validate_stable_ids(self.selected_stable_ids)
        for label, value in (
            ("operation request digest", self.request_digest),
            ("Ansible operation plan digest", self.plan_digest),
            ("Ansible operation catalog digest", self.catalog_digest),
            ("Ansible source digest", self.source_digest),
            ("Ansible readiness digest", self.readiness_digest),
            ("inventory digest", self.inventory_digest),
            ("operation journal digest", self.journal_digest),
        ):
            validate_digest(value, label)
        if self.observation_digest is not None:
            validate_digest(self.observation_digest, "observation digest")
        if self.trust_digest is not None:
            validate_digest(self.trust_digest, "trust digest")
        if self.plan_schema_version != ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION:
            raise StatePersistenceError(
                "unsupported bound Ansible operation plan schema version"
            )
        if not isinstance(self.plan_status, AnsibleOperationPlanStatus):
            raise StatePersistenceError("Ansible operation plan status is invalid")
        if not _SOURCE_VERSION.fullmatch(self.source_version):
            raise StatePersistenceError("Ansible source version is invalid")
        if (
            self.readiness_schema_version != READINESS_SCHEMA_VERSION
            or self.readiness_status is not EvidenceStatus.FRESH
        ):
            raise StatePersistenceError(
                "Ansible operation binding requires fresh readiness evidence"
            )
        _validate_evidence_pair(
            self.observation_generation,
            self.observation_digest,
            "observation",
            required=True,
        )
        _validate_evidence_pair(
            self.inventory_generation,
            self.inventory_digest,
            "inventory",
            required=True,
        )
        _validate_evidence_pair(
            self.trust_generation,
            self.trust_digest,
            "trust",
            required=True,
        )
        if self.journal_schema_version != JOURNAL_SCHEMA_VERSION:
            raise StatePersistenceError(
                "unsupported bound operation journal schema version"
            )
        if (
            isinstance(self.journal_generation, bool)
            or not isinstance(self.journal_generation, int)
            or self.journal_generation < 1
        ):
            raise StatePersistenceError("bound operation journal generation is invalid")
        if self.confirmation_state is not ConfirmationState.NOT_COLLECTED:
            raise StatePersistenceError(
                "Ansible operation binding cannot claim confirmation"
            )
        if self.execution_state is not ExecutionState.NOT_STARTED:
            raise StatePersistenceError(
                "Ansible operation binding cannot claim execution"
            )

    def to_object(self) -> dict[str, object]:
        """Return the exact persistent schema without raw request or plan inputs."""

        return {
            "catalog_digest": self.catalog_digest,
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "confirmation_state": self.confirmation_state.value,
            "created_at": self.created_at,
            "effective_classification": self.effective_classification.value,
            "execution_state": self.execution_state.value,
            "generation": self.generation,
            "inventory_digest": self.inventory_digest,
            "inventory_generation": self.inventory_generation,
            "journal_digest": self.journal_digest,
            "journal_generation": self.journal_generation,
            "journal_schema_version": self.journal_schema_version,
            "observation_digest": self.observation_digest,
            "observation_generation": self.observation_generation,
            "operation": self.operation,
            "operation_classification": self.operation_classification.value,
            "operation_id": str(self.operation_id),
            "plan_digest": self.plan_digest,
            "plan_schema_version": self.plan_schema_version,
            "plan_status": self.plan_status.value,
            "readiness_digest": self.readiness_digest,
            "readiness_schema_version": self.readiness_schema_version,
            "readiness_status": self.readiness_status.value,
            "request_digest": self.request_digest,
            "schema_version": self.schema_version,
            "selected_stable_ids": list(self.selected_stable_ids),
            "source_digest": self.source_digest,
            "source_version": self.source_version,
            "trust_digest": self.trust_digest,
            "trust_generation": self.trust_generation,
        }

    def to_public_object(self) -> dict[str, object]:
        """Project only stable IDs, classifications, states, and digests."""

        return {
            "binding_generation": self.generation,
            "catalog_digest": self.catalog_digest,
            "confirmation_state": self.confirmation_state.value,
            "effective_classification": self.effective_classification.value,
            "execution_state": self.execution_state.value,
            "operation": self.operation,
            "operation_classification": self.operation_classification.value,
            "operation_id": str(self.operation_id),
            "plan": {
                "digest": self.plan_digest,
                "schema_version": self.plan_schema_version,
                "status": self.plan_status.value,
            },
            "readiness": {
                "digest": self.readiness_digest,
                "schema_version": self.readiness_schema_version,
                "status": self.readiness_status.value,
            },
            "request_digest": self.request_digest,
            "schema_version": self.schema_version,
            "selected_stable_ids": list(self.selected_stable_ids),
            "source": {
                "digest": self.source_digest,
                "version": self.source_version,
            },
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> "OperationPlanBinding":
        require_exact_keys(
            value,
            {
                "catalog_digest",
                "cluster_name",
                "cluster_uuid",
                "confirmation_state",
                "created_at",
                "effective_classification",
                "execution_state",
                "generation",
                "inventory_digest",
                "inventory_generation",
                "journal_digest",
                "journal_generation",
                "journal_schema_version",
                "observation_digest",
                "observation_generation",
                "operation",
                "operation_classification",
                "operation_id",
                "plan_digest",
                "plan_schema_version",
                "plan_status",
                "readiness_digest",
                "readiness_schema_version",
                "readiness_status",
                "request_digest",
                "schema_version",
                "selected_stable_ids",
                "source_digest",
                "source_version",
                "trust_digest",
                "trust_generation",
            },
            "Ansible operation binding",
        )
        if (
            require_string(value, "schema_version")
            != ANSIBLE_OPERATION_BINDING_SCHEMA_VERSION
        ):
            raise StatePersistenceError(
                "unsupported Ansible operation binding schema version"
            )
        stable_ids_value = value["selected_stable_ids"]
        if not isinstance(stable_ids_value, list) or not all(
            isinstance(item, str) for item in stable_ids_value
        ):
            raise StatePersistenceError(
                "Ansible operation binding stable IDs are invalid"
            )
        try:
            operation_classification = OperationClassification(
                require_string(value, "operation_classification")
            )
            effective_classification = OperationClassification(
                require_string(value, "effective_classification")
            )
            plan_status = AnsibleOperationPlanStatus(
                require_string(value, "plan_status")
            )
            readiness_status = EvidenceStatus(require_string(value, "readiness_status"))
            confirmation_state = ConfirmationState(
                require_string(value, "confirmation_state")
            )
            execution_state = ExecutionState(require_string(value, "execution_state"))
        except ValueError as error:
            raise StatePersistenceError(
                "Ansible operation binding enum is invalid"
            ) from error
        return cls(
            generation=_integer(value["generation"], "binding generation"),
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
            effective_classification=effective_classification,
            selected_stable_ids=tuple(cast(list[str], stable_ids_value)),
            request_digest=require_string(value, "request_digest"),
            plan_schema_version=require_string(value, "plan_schema_version"),
            plan_digest=require_string(value, "plan_digest"),
            plan_status=plan_status,
            catalog_digest=require_string(value, "catalog_digest"),
            source_version=require_string(value, "source_version"),
            source_digest=require_string(value, "source_digest"),
            readiness_schema_version=require_string(value, "readiness_schema_version"),
            readiness_digest=require_string(value, "readiness_digest"),
            readiness_status=readiness_status,
            observation_generation=_optional_integer(
                value["observation_generation"], "observation generation"
            ),
            observation_digest=_optional_string(
                value["observation_digest"], "observation digest"
            ),
            inventory_generation=_integer(
                value["inventory_generation"], "inventory generation"
            ),
            inventory_digest=require_string(value, "inventory_digest"),
            trust_generation=_optional_integer(
                value["trust_generation"], "trust generation"
            ),
            trust_digest=_optional_string(value["trust_digest"], "trust digest"),
            journal_schema_version=require_string(value, "journal_schema_version"),
            journal_generation=_integer(
                value["journal_generation"], "journal generation"
            ),
            journal_digest=require_string(value, "journal_digest"),
            confirmation_state=confirmation_state,
            execution_state=execution_state,
        )


@dataclass(frozen=True, slots=True)
class StoredOperationPlanBinding:
    record: OperationPlanBinding
    digest: str


@dataclass(frozen=True, slots=True)
class OperationResumeValidation:
    """Successful offline proof that only the pre-execution checkpoint may resume."""

    operation_id: uuid.UUID
    operation: str
    operation_classification: OperationClassification
    effective_classification: OperationClassification
    selected_stable_ids: tuple[str, ...]
    request_digest: str
    plan_digest: str
    plan_status: AnsibleOperationPlanStatus
    readiness_digest: str
    source_digest: str
    catalog_digest: str
    confirmation_state: ConfirmationState
    authorization_schema_version: str | None
    authorization_digest: str | None
    execution_state: ExecutionState
    resume_state: OperationResumeState
    revalidation_digest: str
    schema_version: str = ANSIBLE_OPERATION_RESUME_SCHEMA_VERSION

    def to_public_object(self) -> dict[str, object]:
        """Return a path-, address-, key-, provider-ID-, and value-free report."""

        return {
            "authorization": {
                "digest": self.authorization_digest,
                "schema_version": self.authorization_schema_version,
                "state": self.confirmation_state.value,
            },
            "catalog_digest": self.catalog_digest,
            "confirmation_state": self.confirmation_state.value,
            "effective_classification": self.effective_classification.value,
            "execution_state": self.execution_state.value,
            "operation": self.operation,
            "operation_classification": self.operation_classification.value,
            "operation_id": str(self.operation_id),
            "plan": {
                "digest": self.plan_digest,
                "status": self.plan_status.value,
            },
            "readiness_digest": self.readiness_digest,
            "request_digest": self.request_digest,
            "resume_state": self.resume_state.value,
            "revalidation_digest": self.revalidation_digest,
            "schema_version": self.schema_version,
            "selected_stable_ids": list(self.selected_stable_ids),
            "source_digest": self.source_digest,
        }


class OperationPlanBindingStore:
    """Persist one immutable binding beside its common operation journal."""

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
            raise StatePersistenceError("operation binding ID must be a UUID")
        self._paths = paths
        self._operation_id = operation_id
        self._path = operation_plan_binding_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read_locked(
        self,
        lock: HeldClusterLockProtocol,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
        expected_operation: str | None = None,
    ) -> StoredOperationPlanBinding:
        lock.assert_held_for(self._paths)
        value, digest = self._file.read()
        record = OperationPlanBinding.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or (
                expected_operation is not None
                and record.operation != expected_operation
            )
        ):
            raise StatePersistenceError("Ansible operation binding identity mismatch")
        return StoredOperationPlanBinding(record, digest)

    def write_locked(
        self,
        record: OperationPlanBinding,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredOperationPlanBinding:
        _assert_operation_lock(lock, self._paths, record.operation)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError("Ansible operation binding ID mismatch")
        journal = OperationJournalStore(self._paths, self._operation_id).read(
            expected_cluster_uuid=record.cluster_uuid,
            expected_cluster_name=record.cluster_name,
        )
        if (
            journal.record.operation != record.operation
            or journal.record.generation != record.journal_generation
            or journal.digest != record.journal_digest
        ):
            raise StateConflictError(
                "Ansible operation binding journal history is ambiguous"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
                expected_operation=record.operation,
            )
            if (
                current.record.generation != expected_generation
                or expected_digest is None
                or current.digest != expected_digest
            ):
                raise StatePersistenceError(
                    "Ansible operation binding changed concurrently"
                )
            if current.record == record:
                return current
            raise StatePersistenceError("Ansible operation binding is immutable")
        if (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
        ):
            raise StatePersistenceError(
                "initial Ansible operation binding write requires generation one"
            )
        digest = self._file.write(record.to_object(), expected_digest=None)
        return StoredOperationPlanBinding(record, digest)


def normalized_operation_request_digest(request: OperationRequest) -> str:
    """Digest exact normalized non-secret request semantics, never secret values."""

    _validate_request_shape(request)
    options = [
        {
            "name": option.name,
            "value": _normalize_request_value(option.value),
        }
        for option in sorted(request.options, key=lambda item: item.name)
        if option.name != "resume_operation"
    ]
    return digest_bytes(
        serialize_json(
            {
                "cluster_name": request.cluster_name,
                "operation": request.operation.name,
                "operation_classification": request.operation.classification.value,
                "options": options,
                "provider": request.provider.name,
                "schema_version": "deploy-scylla-vms.normalized-operation-request/v1",
            }
        )
    )


def readiness_binding_digest(readiness: ReadinessReport) -> str:
    """Digest only bounded readiness statuses/provenance, not keys or addresses."""

    _require_fresh_readiness(readiness)
    return digest_bytes(
        serialize_json(
            {
                "blockers": {
                    classification.value: list(blockers)
                    for classification, blockers in sorted(
                        readiness.blockers, key=lambda item: item[0].value
                    )
                },
                "host_count": readiness.host_count,
                "inventory": {
                    "digest": readiness.inventory_digest,
                    "generation": readiness.inventory_generation,
                },
                "machine_status": readiness.machine_status.value,
                "observation": {
                    "digest": readiness.observation_digest,
                    "generation": readiness.observation_generation,
                },
                "route": {
                    "direct_hosts": readiness.route.direct_hosts,
                    "findings": list(readiness.route.findings),
                    "jump_hosts": readiness.route.jump_hosts,
                    "proxied_hosts": readiness.route.proxied_hosts,
                    "status": readiness.route_status.value,
                },
                "schema_version": readiness.schema_version,
                "source_status": readiness.source_status.value,
                "status": readiness.status.value,
                "trust": {
                    "digest": readiness.trust_digest,
                    "generation": readiness.trust_generation,
                    "status": readiness.trust_status.value,
                    "trusted_host_count": readiness.trusted_host_count,
                },
            }
        )
    )


def build_operation_plan_binding(
    metadata: ClusterMetadata,
    request: OperationRequest,
    operation_id: uuid.UUID,
    plan: AnsibleOperationPlan,
    readiness: ReadinessReport,
    journal: StoredOperationRecord,
    *,
    clock: Callable[[], datetime],
) -> OperationPlanBinding:
    """Build a non-executing PLAN checkpoint bound to current local evidence."""

    _validate_current_identity(metadata, request, operation_id, plan)
    _require_fresh_readiness(readiness)
    request_digest = normalized_operation_request_digest(request)
    _validate_plan_journal(plan, journal, request_digest, operation_id)
    selected_stable_ids = _selected_stable_ids(plan)
    source = load_ansible_source_bundle()
    validate_digest(source.digest, "Ansible source digest")
    return OperationPlanBinding(
        generation=1,
        created_at=format_timestamp(clock()),
        cluster_uuid=metadata.cluster_uuid,
        cluster_name=metadata.cluster_name,
        operation_id=operation_id,
        operation=request.operation.name,
        operation_classification=request.operation.classification,
        effective_classification=plan.effective_classification,
        selected_stable_ids=selected_stable_ids,
        request_digest=request_digest,
        plan_schema_version=plan.schema_version,
        plan_digest=plan.plan_digest,
        plan_status=plan.status,
        catalog_digest=ansible_operation_catalog_digest(),
        source_version=source.version,
        source_digest=source.digest,
        readiness_schema_version=readiness.schema_version,
        readiness_digest=readiness_binding_digest(readiness),
        readiness_status=readiness.status,
        observation_generation=readiness.observation_generation,
        observation_digest=readiness.observation_digest,
        inventory_generation=cast(int, readiness.inventory_generation),
        inventory_digest=cast(str, readiness.inventory_digest),
        trust_generation=readiness.trust_generation,
        trust_digest=readiness.trust_digest,
        journal_schema_version=journal.record.schema_version,
        journal_generation=journal.record.generation,
        journal_digest=journal.digest,
    )


def classify_operation_resume_state(
    journal: OperationRecord,
    effective_classification: OperationClassification,
) -> OperationResumeState:
    """Conservatively classify history without authorizing any transition."""

    if journal.status is JournalStatus.INTERRUPTED:
        return OperationResumeState.INTERRUPTED
    if journal.status is JournalStatus.FAILED:
        return OperationResumeState.FAILED
    if journal.status is JournalStatus.SUCCEEDED:
        return OperationResumeState.COMPLETED
    if journal.status is not JournalStatus.IN_PROGRESS:
        return OperationResumeState.AMBIGUOUS_HISTORY
    if journal.phase is OperationPhase.PLAN:
        return OperationResumeState.RESUMABLE_PRE_EXECUTION
    if journal.phase is OperationPhase.CONFIRM:
        return OperationResumeState.CONFIRMATION_STATE_AMBIGUOUS
    if _phase_at_or_after(journal.phase, OperationPhase.EXECUTE):
        if effective_classification is OperationClassification.DESTRUCTIVE:
            return OperationResumeState.DESTRUCTIVE_BOUNDARY_RECORDED
        return OperationResumeState.EXECUTION_MAY_HAVE_STARTED
    return OperationResumeState.AMBIGUOUS_HISTORY


def validate_operation_plan_checkpoint_for_execution(
    lock: ClusterLock,
    metadata: ClusterMetadata,
    request: OperationRequest,
    operation_id: uuid.UUID,
    plan: AnsibleOperationPlan,
    readiness: ReadinessReport,
) -> OperationResumeValidation:
    """Recompute the exact immutable PLAN checkpoint for an execution handoff."""

    _assert_operation_lock(lock, request.paths, request.operation.name)
    _validate_current_identity(metadata, request, operation_id, plan)
    store = OperationPlanBindingStore(request.paths, operation_id)
    stored = store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
        expected_operation=request.operation.name,
    )
    journal_path = request.paths.operations / f"{operation_id}.json"
    validate_state_file(journal_path, allow_missing=True)
    if not journal_path.exists():
        raise StateConflictError(
            "Ansible operation resume journal history is missing or ambiguous"
        )
    journal = OperationJournalStore(request.paths, operation_id).read(
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    state = classify_operation_resume_state(
        journal.record, stored.record.effective_classification
    )
    if state is not OperationResumeState.RESUMABLE_PRE_EXECUTION:
        raise StateConflictError(f"Ansible operation resume state: {state.value}")
    if (
        journal.record.generation != stored.record.journal_generation
        or journal.digest != stored.record.journal_digest
    ):
        raise StateConflictError(
            "Ansible operation resume journal history is ambiguous"
        )
    request_digest = normalized_operation_request_digest(request)
    if request_digest != stored.record.request_digest:
        raise StateConflictError("Ansible operation resume request digest drifted")
    selected_stable_ids = _selected_stable_ids(plan)
    if selected_stable_ids != stored.record.selected_stable_ids:
        raise StateConflictError("Ansible operation resume target set drifted")
    if (
        plan.schema_version != stored.record.plan_schema_version
        or plan.plan_digest != stored.record.plan_digest
        or plan.status is not stored.record.plan_status
    ):
        raise StateConflictError("Ansible operation resume plan binding drifted")
    _validate_plan_journal(plan, journal, request_digest, operation_id)
    catalog_digest = ansible_operation_catalog_digest()
    if catalog_digest != stored.record.catalog_digest:
        raise StateConflictError("Ansible operation resume catalog binding drifted")
    source = load_ansible_source_bundle()
    if (
        source.version != stored.record.source_version
        or source.digest != stored.record.source_digest
    ):
        raise StateConflictError("Ansible operation resume source binding drifted")
    _require_fresh_readiness(readiness)
    readiness_digest = readiness_binding_digest(readiness)
    if (
        readiness.schema_version != stored.record.readiness_schema_version
        or readiness_digest != stored.record.readiness_digest
        or readiness.status is not stored.record.readiness_status
        or readiness.observation_generation != stored.record.observation_generation
        or readiness.observation_digest != stored.record.observation_digest
        or readiness.inventory_generation != stored.record.inventory_generation
        or readiness.inventory_digest != stored.record.inventory_digest
        or readiness.trust_generation != stored.record.trust_generation
        or readiness.trust_digest != stored.record.trust_digest
    ):
        raise StateConflictError(
            "Ansible operation resume readiness or evidence drifted"
        )
    from scylla_vms.ansible.operation_authorization import (
        validate_current_operation_authorization,
    )

    authorization = validate_current_operation_authorization(
        lock,
        metadata,
        request,
        stored,
        journal,
    )
    confirmation_state = (
        ConfirmationState.NOT_REQUIRED
        if authorization is None
        else ConfirmationState.AUTHORIZED
    )
    authorization_schema_version = (
        None if authorization is None else authorization.record.schema_version
    )
    authorization_digest = None if authorization is None else authorization.digest
    revalidation_digest = digest_bytes(
        serialize_json(
            {
                "authorization_digest": authorization_digest,
                "authorization_schema_version": authorization_schema_version,
                "confirmation_state": confirmation_state.value,
                "binding_digest": stored.digest,
                "catalog_digest": catalog_digest,
                "journal_digest": journal.digest,
                "plan_digest": plan.plan_digest,
                "readiness_digest": readiness_digest,
                "request_digest": request_digest,
                "resume_state": state.value,
                "source_digest": source.digest,
            }
        )
    )
    return OperationResumeValidation(
        operation_id,
        request.operation.name,
        request.operation.classification,
        plan.effective_classification,
        selected_stable_ids,
        request_digest,
        plan.plan_digest,
        plan.status,
        readiness_digest,
        source.digest,
        catalog_digest,
        confirmation_state,
        authorization_schema_version,
        authorization_digest,
        stored.record.execution_state,
        state,
        revalidation_digest,
    )


def validate_operation_plan_resume(
    lock: ClusterLock,
    metadata: ClusterMetadata,
    request: OperationRequest,
    operation_id: uuid.UUID,
    plan: AnsibleOperationPlan,
    readiness: ReadinessReport,
) -> OperationResumeValidation:
    """Permit resume only before any durable execution attempt exists."""

    validation = validate_operation_plan_checkpoint_for_execution(
        lock,
        metadata,
        request,
        operation_id,
        plan,
        readiness,
    )
    from scylla_vms.ansible.operation_execution import OperationExecutionStore

    store = OperationExecutionStore(request.paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    if store.path.exists():
        store.read_locked(
            lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
            expected_operation=request.operation.name,
        )
        raise StateConflictError(
            "Ansible operation resume state: "
            f"{OperationResumeState.EXECUTION_MAY_HAVE_STARTED.value}"
        )
    return validation


def operation_plan_binding_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError("operation binding ID must be a UUID")
    path = paths.operations / f"{operation_id}{OPERATION_BINDING_FILENAME_SUFFIX}"
    if path.parent != paths.operations:
        raise StatePersistenceError("Ansible operation binding path is not canonical")
    return path


def operation_plan_binding_id_from_filename(name: str) -> uuid.UUID | None:
    if not name.endswith(OPERATION_BINDING_FILENAME_SUFFIX):
        return None
    identifier_text = name[: -len(OPERATION_BINDING_FILENAME_SUFFIX)]
    try:
        identifier = uuid.UUID(identifier_text)
    except ValueError:
        return None
    return identifier if str(identifier) == identifier_text else None


def _validate_current_identity(
    metadata: ClusterMetadata,
    request: OperationRequest,
    operation_id: uuid.UUID,
    plan: AnsibleOperationPlan,
) -> None:
    _require_canonical_paths(request.paths)
    if (
        not isinstance(operation_id, uuid.UUID)
        or request.cluster_name != metadata.cluster_name
        or request.provider.name != metadata.provider
        or request.paths.cluster_root.name != metadata.cluster_name
        or request.operation.name != plan.operation
        or request.operation.classification is not plan.operation_classification
    ):
        raise StateConflictError("Ansible operation binding identity conflicts")
    operation = get_operation(request.operation.name)
    if operation != request.operation:
        raise StateConflictError("Ansible operation registry identity drifted")
    if plan.schema_version != ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION:
        raise StateConflictError("Ansible operation plan schema is unsupported")
    if not isinstance(plan.status, AnsibleOperationPlanStatus) or not isinstance(
        plan.effective_classification, OperationClassification
    ):
        raise StateConflictError("Ansible operation plan identity is invalid")


def _validate_plan_journal(
    plan: AnsibleOperationPlan,
    journal: StoredOperationRecord,
    request_digest: str,
    operation_id: uuid.UUID,
) -> None:
    expected_plan_evidence = ansible_operation_plan_checkpoint_evidence(plan)
    plan_evidence = tuple(
        evidence
        for evidence in journal.record.evidence
        if evidence.phase is OperationPhase.PLAN
    )
    if (
        journal.record.operation_id != operation_id
        or journal.record.operation != plan.operation
        or journal.record.request_digest != request_digest
        or journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.PLAN
        or plan_evidence != (expected_plan_evidence,)
    ):
        raise StateConflictError("Ansible operation plan journal checkpoint conflicts")


def _selected_stable_ids(plan: AnsibleOperationPlan) -> tuple[str, ...]:
    values = tuple(
        sorted(
            {
                stable_id
                for step in plan.steps
                if step.status is not AnsibleOperationStepStatus.SKIPPED
                for stable_id in step.limit
            }
        )
    )
    _validate_stable_ids(values)
    return values


def _require_fresh_readiness(readiness: ReadinessReport) -> None:
    if (
        readiness.schema_version != READINESS_SCHEMA_VERSION
        or readiness.status is not EvidenceStatus.FRESH
        or readiness.source_status is not EvidenceStatus.FRESH
        or readiness.machine_status is not EvidenceStatus.FRESH
        or readiness.trust_status is not TrustReadiness.COMPLETE
        or readiness.route_status is not RouteReadiness.VALID
    ):
        raise StateConflictError(
            "Ansible operation binding requires current fresh readiness"
        )
    _validate_evidence_pair(
        readiness.observation_generation,
        readiness.observation_digest,
        "observation",
        required=True,
    )
    _validate_evidence_pair(
        readiness.inventory_generation,
        readiness.inventory_digest,
        "inventory",
        required=True,
    )
    _validate_evidence_pair(
        readiness.trust_generation,
        readiness.trust_digest,
        "trust",
        required=True,
    )


def _validate_request_shape(request: OperationRequest) -> None:
    expected_names = {
        field.name for field in fields_for_operation(request.operation.name)
    }
    actual_names = [option.name for option in request.options]
    if (
        len(actual_names) != len(set(actual_names))
        or set(actual_names) != expected_names
        or request.paths.state_root != request.state_root
    ):
        raise StateConflictError("normalized operation request shape conflicts")


def _normalize_request_value(value: object) -> object:
    if isinstance(value, Path):
        return {"kind": "path", "value": str(value)}
    if isinstance(value, DeferredValue):
        return {"kind": "deferred", "value": value.value}
    if isinstance(value, tuple):
        return [_normalize_request_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise StateConflictError("normalized operation request value is invalid")


def _validate_stable_ids(values: tuple[str, ...]) -> None:
    if (
        not isinstance(values, tuple)
        or not values
        or values != tuple(sorted(set(values)))
        or not all(
            isinstance(value, str)
            and value.isascii()
            and _LOGICAL_ID.fullmatch(value) is not None
            and not _is_ip_address(value)
            for value in values
        )
    ):
        raise StatePersistenceError("Ansible operation binding stable IDs are invalid")


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _validate_evidence_pair(
    generation: int | None,
    digest: str | None,
    label: str,
    *,
    required: bool,
) -> None:
    if generation is None or digest is None:
        if required or generation is not None or digest is not None:
            raise StatePersistenceError(f"{label} evidence binding is incomplete")
        return
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 1
    ):
        raise StatePersistenceError(f"{label} evidence generation is invalid")
    validate_digest(digest, f"{label} evidence digest")


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    if value is None:
        return None
    return _integer(value, label)


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise StatePersistenceError(f"{label} must be null or a non-empty string")
    return value


def _require_canonical_paths(paths: StatePaths) -> None:
    expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
    if expected != paths or paths.operations.parent != paths.cluster_root:
        raise UnsafePathError("Ansible operation binding paths are not canonical")


def _assert_operation_lock(
    lock: ClusterLock, paths: StatePaths, operation: str
) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Ansible operation binding requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, operation)


def _phase_at_or_after(value: OperationPhase, threshold: OperationPhase) -> bool:
    phases = tuple(OperationPhase)
    return phases.index(value) >= phases.index(threshold)
