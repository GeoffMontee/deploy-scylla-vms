"""Immutable, digest-bound pre-execution operation authorization checkpoints."""

import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.operation_binding import (
    ANSIBLE_OPERATION_BINDING_SCHEMA_VERSION,
    ExecutionState,
    OperationPlanBinding,
    OperationPlanBindingStore,
    StoredOperationPlanBinding,
    normalized_operation_request_digest,
)
from scylla_vms.ansible.orchestration import (
    ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION,
    AnsibleOperationPlanStatus,
)
from scylla_vms.ansible.readiness import READINESS_SCHEMA_VERSION, EvidenceStatus
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

ANSIBLE_OPERATION_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-operation-authorization/v1"
)
OPERATION_AUTHORIZATION_FILENAME_SUFFIX = ".ansible-operation-authorization.json"
_PROOF_SCHEMA_VERSION = "deploy-scylla-vms.ansible-operation-authorization-proof/v1"
_SOURCE_VERSION = re.compile(r"[a-z][a-z0-9-]{0,63}/v[1-9][0-9]{0,8}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CLASSIFICATION_RANK = {
    OperationClassification.READ_ONLY: 0,
    OperationClassification.MUTATING: 1,
    OperationClassification.SENSITIVE: 2,
    OperationClassification.DESTRUCTIVE: 3,
}


class ConfirmationPolicy(StrEnum):
    """PLAN-compatible ordinary confirmation policy by public operation class."""

    NOT_REQUIRED = "not-required"
    MUTATING = "mutating-confirmation"
    SENSITIVE = "sensitive-confirmation"
    DESTRUCTIVE = "destructive-confirmation"


class AuthorizationState(StrEnum):
    """The only state this non-executing checkpoint may claim."""

    AUTHORIZED_PRE_EXECUTION = "authorized-pre-execution"


class AuthorizationProofKind(StrEnum):
    """Separated normalized proof classes; none retains an entered token."""

    ORDINARY_CONFIRMATION = "ordinary-confirmation"
    DESTRUCTIVE_CLASS = "destructive-class"
    EXACT_OPERATION_SCOPE = "exact-operation-scope"
    STORAGE_WIPE = "storage-wipe"
    MONITORING_RESTART = "monitoring-restart"


class AuthorizationProofSource(StrEnum):
    """Allowlisted proof source without terminal or operator identity data."""

    INTERACTIVE = "interactive"
    CLI_YES = "cli-yes"
    CLI_EXPLICIT = "cli-explicit"


_PROOF_ORDER = {kind: index for index, kind in enumerate(AuthorizationProofKind)}
_BASE_PROOF_KINDS = frozenset({AuthorizationProofKind.ORDINARY_CONFIRMATION})
_DESTRUCTIVE_PROOF_KINDS = frozenset(
    {
        AuthorizationProofKind.ORDINARY_CONFIRMATION,
        AuthorizationProofKind.DESTRUCTIVE_CLASS,
        AuthorizationProofKind.EXACT_OPERATION_SCOPE,
    }
)


@dataclass(frozen=True, slots=True)
class InteractiveConfirmation:
    """Normalized in-memory prompt outcomes; prompt text is never accepted."""

    ordinary_approved: bool = False
    exact_scope_approved: bool = False
    monitoring_restart_approved: bool = False

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, bool)
            for value in (
                self.ordinary_approved,
                self.exact_scope_approved,
                self.monitoring_restart_approved,
            )
        ):
            raise StateConflictError("interactive confirmation proof is invalid")


@dataclass(frozen=True, slots=True)
class AuthorizationProof:
    """One separately digest-bound normalized authorization fact."""

    kind: AuthorizationProofKind
    source: AuthorizationProofSource
    digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, AuthorizationProofKind) or not isinstance(
            self.source, AuthorizationProofSource
        ):
            raise StatePersistenceError("operation authorization proof enum is invalid")
        validate_digest(self.digest, "operation authorization proof digest")
        allowed_sources = {
            AuthorizationProofKind.ORDINARY_CONFIRMATION: {
                AuthorizationProofSource.INTERACTIVE,
                AuthorizationProofSource.CLI_YES,
            },
            AuthorizationProofKind.DESTRUCTIVE_CLASS: {
                AuthorizationProofSource.CLI_EXPLICIT
            },
            AuthorizationProofKind.EXACT_OPERATION_SCOPE: {
                AuthorizationProofSource.INTERACTIVE,
                AuthorizationProofSource.CLI_EXPLICIT,
            },
            AuthorizationProofKind.STORAGE_WIPE: {
                AuthorizationProofSource.CLI_EXPLICIT
            },
            AuthorizationProofKind.MONITORING_RESTART: {
                AuthorizationProofSource.INTERACTIVE,
                AuthorizationProofSource.CLI_EXPLICIT,
            },
        }
        if self.source not in allowed_sources[self.kind]:
            raise StatePersistenceError(
                "operation authorization proof source conflicts with its kind"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "digest": self.digest,
            "kind": self.kind.value,
            "source": self.source.value,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> "AuthorizationProof":
        require_exact_keys(
            value, {"digest", "kind", "source"}, "operation authorization proof"
        )
        try:
            kind = AuthorizationProofKind(require_string(value, "kind"))
            source = AuthorizationProofSource(require_string(value, "source"))
        except ValueError as error:
            raise StatePersistenceError(
                "operation authorization proof enum is invalid"
            ) from error
        return cls(kind, source, require_string(value, "digest"))


@dataclass(frozen=True, slots=True)
class OperationAuthorization:
    """One immutable confirmation checkpoint that cannot authorize execution."""

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
    operation_binding_schema_version: str
    operation_binding_generation: int
    operation_binding_digest: str
    catalog_digest: str
    source_version: str
    source_digest: str
    readiness_schema_version: str
    readiness_digest: str
    readiness_status: EvidenceStatus
    observation_generation: int
    observation_digest: str
    inventory_generation: int
    inventory_digest: str
    trust_generation: int
    trust_digest: str
    journal_schema_version: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    confirmation_policy: ConfirmationPolicy
    proofs: tuple[AuthorizationProof, ...]
    authorization_state: AuthorizationState = (
        AuthorizationState.AUTHORIZED_PRE_EXECUTION
    )
    execution_state: ExecutionState = ExecutionState.NOT_STARTED
    schema_version: str = ANSIBLE_OPERATION_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != ANSIBLE_OPERATION_AUTHORIZATION_SCHEMA_VERSION:
            raise StatePersistenceError(
                "unsupported Ansible operation authorization schema version"
            )
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation != 1
        ):
            raise StatePersistenceError(
                "Ansible operation authorization generation must be one"
            )
        if not isinstance(self.cluster_uuid, uuid.UUID) or not isinstance(
            self.operation_id, uuid.UUID
        ):
            raise StatePersistenceError(
                "Ansible operation authorization identities must be UUIDs"
            )
        try:
            validate_cluster_name(self.cluster_name)
            operation = get_operation(self.operation)
        except (ConfigurationError, KeyError) as error:
            raise StatePersistenceError(
                "Ansible operation authorization identity is invalid"
            ) from error
        if (
            operation.classification is not self.operation_classification
            or not isinstance(self.effective_classification, OperationClassification)
            or _CLASSIFICATION_RANK[self.effective_classification]
            < _CLASSIFICATION_RANK[self.operation_classification]
        ):
            raise StatePersistenceError(
                "Ansible operation authorization classification conflicts"
            )
        if not isinstance(self.created_at, str):
            raise StatePersistenceError(
                "Ansible operation authorization timestamp must be a string"
            )
        parse_timestamp(self.created_at)
        _validate_stable_ids(self.selected_stable_ids)
        for label, value in (
            ("operation request digest", self.request_digest),
            ("Ansible operation plan digest", self.plan_digest),
            ("Ansible operation binding digest", self.operation_binding_digest),
            ("Ansible operation catalog digest", self.catalog_digest),
            ("Ansible source digest", self.source_digest),
            ("Ansible readiness digest", self.readiness_digest),
            ("observation digest", self.observation_digest),
            ("inventory digest", self.inventory_digest),
            ("trust digest", self.trust_digest),
            ("operation journal digest", self.journal_digest),
        ):
            validate_digest(value, label)
        if (
            self.plan_schema_version != ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION
            or self.plan_status is not AnsibleOperationPlanStatus.READY
        ):
            raise StatePersistenceError(
                "Ansible operation authorization requires a ready plan"
            )
        if (
            self.operation_binding_schema_version
            != ANSIBLE_OPERATION_BINDING_SCHEMA_VERSION
            or self.operation_binding_generation != 1
        ):
            raise StatePersistenceError(
                "Ansible operation authorization binding is invalid"
            )
        if not _SOURCE_VERSION.fullmatch(self.source_version):
            raise StatePersistenceError("Ansible source version is invalid")
        if (
            self.readiness_schema_version != READINESS_SCHEMA_VERSION
            or self.readiness_status is not EvidenceStatus.FRESH
        ):
            raise StatePersistenceError(
                "Ansible operation authorization requires fresh readiness"
            )
        for generation, label in (
            (self.observation_generation, "observation"),
            (self.inventory_generation, "inventory"),
            (self.trust_generation, "trust"),
            (self.journal_generation, "operation journal"),
        ):
            _validate_generation(generation, label)
        if (
            self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.PLAN
        ):
            raise StatePersistenceError(
                "Ansible operation authorization journal checkpoint is invalid"
            )
        expected_policy = _classification_policy(self.operation_classification)
        if (
            not isinstance(self.confirmation_policy, ConfirmationPolicy)
            or self.confirmation_policy is ConfirmationPolicy.NOT_REQUIRED
            or self.confirmation_policy is not expected_policy
        ):
            raise StatePersistenceError(
                "Ansible operation authorization confirmation policy conflicts"
            )
        if (
            not isinstance(self.proofs, tuple)
            or not all(isinstance(item, AuthorizationProof) for item in self.proofs)
            or tuple(sorted(self.proofs, key=lambda item: _PROOF_ORDER[item.kind]))
            != self.proofs
            or len({item.kind for item in self.proofs}) != len(self.proofs)
        ):
            raise StatePersistenceError(
                "Ansible operation authorization proofs are invalid"
            )
        proof_kinds = {item.kind for item in self.proofs}
        required = (
            _DESTRUCTIVE_PROOF_KINDS
            if self.operation_classification is OperationClassification.DESTRUCTIVE
            else _BASE_PROOF_KINDS
        )
        if not required <= proof_kinds:
            raise StatePersistenceError(
                "Ansible operation authorization required proofs are missing"
            )
        if (
            self.authorization_state is not AuthorizationState.AUTHORIZED_PRE_EXECUTION
            or self.execution_state is not ExecutionState.NOT_STARTED
        ):
            raise StatePersistenceError(
                "Ansible operation authorization cannot claim execution"
            )

    def to_object(self) -> dict[str, object]:
        """Return the strict record without raw prompts, tokens, or request values."""

        return {
            "authorization_state": self.authorization_state.value,
            "catalog_digest": self.catalog_digest,
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "confirmation_policy": self.confirmation_policy.value,
            "created_at": self.created_at,
            "effective_classification": self.effective_classification.value,
            "execution_state": self.execution_state.value,
            "generation": self.generation,
            "inventory_digest": self.inventory_digest,
            "inventory_generation": self.inventory_generation,
            "journal_digest": self.journal_digest,
            "journal_generation": self.journal_generation,
            "journal_phase": self.journal_phase.value,
            "journal_schema_version": self.journal_schema_version,
            "journal_status": self.journal_status.value,
            "observation_digest": self.observation_digest,
            "observation_generation": self.observation_generation,
            "operation": self.operation,
            "operation_binding_digest": self.operation_binding_digest,
            "operation_binding_generation": self.operation_binding_generation,
            "operation_binding_schema_version": self.operation_binding_schema_version,
            "operation_classification": self.operation_classification.value,
            "operation_id": str(self.operation_id),
            "plan_digest": self.plan_digest,
            "plan_schema_version": self.plan_schema_version,
            "plan_status": self.plan_status.value,
            "proofs": [proof.to_object() for proof in self.proofs],
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
        """Return an explicit path-, prompt-, address-, key-, and value-free view."""

        return {
            "authorization_state": self.authorization_state.value,
            "binding_digest": self.operation_binding_digest,
            "catalog_digest": self.catalog_digest,
            "confirmation_policy": self.confirmation_policy.value,
            "effective_classification": self.effective_classification.value,
            "execution_state": self.execution_state.value,
            "generation": self.generation,
            "journal": {
                "digest": self.journal_digest,
                "generation": self.journal_generation,
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
            },
            "operation": self.operation,
            "operation_classification": self.operation_classification.value,
            "operation_id": str(self.operation_id),
            "plan_digest": self.plan_digest,
            "proofs": [proof.to_object() for proof in self.proofs],
            "readiness_digest": self.readiness_digest,
            "request_digest": self.request_digest,
            "schema_version": self.schema_version,
            "selected_stable_ids": list(self.selected_stable_ids),
            "source_digest": self.source_digest,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> "OperationAuthorization":
        require_exact_keys(
            value,
            {
                "authorization_state",
                "catalog_digest",
                "cluster_name",
                "cluster_uuid",
                "confirmation_policy",
                "created_at",
                "effective_classification",
                "execution_state",
                "generation",
                "inventory_digest",
                "inventory_generation",
                "journal_digest",
                "journal_generation",
                "journal_phase",
                "journal_schema_version",
                "journal_status",
                "observation_digest",
                "observation_generation",
                "operation",
                "operation_binding_digest",
                "operation_binding_generation",
                "operation_binding_schema_version",
                "operation_classification",
                "operation_id",
                "plan_digest",
                "plan_schema_version",
                "plan_status",
                "proofs",
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
            "Ansible operation authorization",
        )
        if (
            require_string(value, "schema_version")
            != ANSIBLE_OPERATION_AUTHORIZATION_SCHEMA_VERSION
        ):
            raise StatePersistenceError(
                "unsupported Ansible operation authorization schema version"
            )
        stable_ids = value["selected_stable_ids"]
        proofs_value = value["proofs"]
        if not isinstance(stable_ids, list) or not all(
            isinstance(item, str) for item in stable_ids
        ):
            raise StatePersistenceError(
                "Ansible operation authorization stable IDs are invalid"
            )
        if not isinstance(proofs_value, list) or not all(
            isinstance(item, dict) for item in proofs_value
        ):
            raise StatePersistenceError(
                "Ansible operation authorization proofs are invalid"
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
            journal_status = JournalStatus(require_string(value, "journal_status"))
            journal_phase = OperationPhase(require_string(value, "journal_phase"))
            confirmation_policy = ConfirmationPolicy(
                require_string(value, "confirmation_policy")
            )
            authorization_state = AuthorizationState(
                require_string(value, "authorization_state")
            )
            execution_state = ExecutionState(require_string(value, "execution_state"))
        except ValueError as error:
            raise StatePersistenceError(
                "Ansible operation authorization enum is invalid"
            ) from error
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
            effective_classification=effective_classification,
            selected_stable_ids=tuple(cast(list[str], stable_ids)),
            request_digest=require_string(value, "request_digest"),
            plan_schema_version=require_string(value, "plan_schema_version"),
            plan_digest=require_string(value, "plan_digest"),
            plan_status=plan_status,
            operation_binding_schema_version=require_string(
                value, "operation_binding_schema_version"
            ),
            operation_binding_generation=_integer(
                value["operation_binding_generation"], "operation binding generation"
            ),
            operation_binding_digest=require_string(value, "operation_binding_digest"),
            catalog_digest=require_string(value, "catalog_digest"),
            source_version=require_string(value, "source_version"),
            source_digest=require_string(value, "source_digest"),
            readiness_schema_version=require_string(value, "readiness_schema_version"),
            readiness_digest=require_string(value, "readiness_digest"),
            readiness_status=readiness_status,
            observation_generation=_integer(
                value["observation_generation"], "observation generation"
            ),
            observation_digest=require_string(value, "observation_digest"),
            inventory_generation=_integer(
                value["inventory_generation"], "inventory generation"
            ),
            inventory_digest=require_string(value, "inventory_digest"),
            trust_generation=_integer(value["trust_generation"], "trust generation"),
            trust_digest=require_string(value, "trust_digest"),
            journal_schema_version=require_string(value, "journal_schema_version"),
            journal_generation=_integer(
                value["journal_generation"], "journal generation"
            ),
            journal_digest=require_string(value, "journal_digest"),
            journal_status=journal_status,
            journal_phase=journal_phase,
            confirmation_policy=confirmation_policy,
            proofs=tuple(
                AuthorizationProof.from_object(cast(dict[str, object], item))
                for item in proofs_value
            ),
            authorization_state=authorization_state,
            execution_state=execution_state,
        )


@dataclass(frozen=True, slots=True)
class StoredOperationAuthorization:
    record: OperationAuthorization
    digest: str

    def to_public_object(self) -> dict[str, object]:
        value = self.record.to_public_object()
        value["authorization_digest"] = self.digest
        return value


class OperationAuthorizationStore:
    """Persist one immutable authorization beside its plan binding and journal."""

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
            raise StatePersistenceError("operation authorization ID must be a UUID")
        self._paths = paths
        self._operation_id = operation_id
        self._path = operation_authorization_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read_locked(
        self,
        lock: object,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
        expected_operation: str | None = None,
    ) -> StoredOperationAuthorization:
        _assert_read_lock(lock, self._paths)
        value, digest = self._file.read()
        record = OperationAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or (
                expected_operation is not None
                and record.operation != expected_operation
            )
        ):
            raise StatePersistenceError(
                "Ansible operation authorization identity mismatch"
            )
        return StoredOperationAuthorization(record, digest)

    def write_locked(
        self,
        record: OperationAuthorization,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
        request: OperationRequest,
        metadata: ClusterMetadata,
    ) -> StoredOperationAuthorization:
        _assert_operation_lock(lock, self._paths, record.operation)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError("Ansible operation authorization ID mismatch")
        binding = OperationPlanBindingStore(
            self._paths, self._operation_id
        ).read_locked(
            lock,
            expected_cluster_uuid=record.cluster_uuid,
            expected_cluster_name=record.cluster_name,
            expected_operation=record.operation,
        )
        journal = OperationJournalStore(self._paths, self._operation_id).read(
            expected_cluster_uuid=record.cluster_uuid,
            expected_cluster_name=record.cluster_name,
        )
        validate_operation_authorization(metadata, request, binding, journal, record)
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
                    "Ansible operation authorization changed concurrently"
                )
            if current.record == record:
                return current
            raise StatePersistenceError("Ansible operation authorization is immutable")
        if (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
        ):
            raise StatePersistenceError(
                "initial Ansible operation authorization write requires generation one"
            )
        digest = self._file.write(record.to_object(), expected_digest=None)
        return StoredOperationAuthorization(record, digest)


def confirmation_policy_for(
    request: OperationRequest, binding: OperationPlanBinding
) -> ConfirmationPolicy:
    """Return the static class policy after exact request/binding identity checks."""

    _validate_request_binding_identity(request, binding)
    return _classification_policy(request.operation.classification)


def build_operation_authorization(
    metadata: ClusterMetadata,
    request: OperationRequest,
    binding: StoredOperationPlanBinding,
    journal: StoredOperationRecord,
    *,
    interactive: InteractiveConfirmation,
    clock: Callable[[], datetime],
) -> OperationAuthorization:
    """Build an authorization-only checkpoint from an exact PLAN history."""

    _validate_checkpoint_inputs(metadata, request, binding, journal)
    policy = confirmation_policy_for(request, binding.record)
    if policy is ConfirmationPolicy.NOT_REQUIRED:
        raise StateConflictError(
            "read-only operations must not manufacture authorization"
        )
    if binding.record.plan_status is not AnsibleOperationPlanStatus.READY:
        raise StateConflictError(
            "operation authorization requires an unblocked ready plan"
        )
    if _boolean(request, "dry_run") or _boolean(request, "plan"):
        raise StateConflictError(
            "preview-only requests must not create operation authorization"
        )
    proofs = _build_authorization_proofs(request, binding, interactive)
    record = OperationAuthorization(
        generation=1,
        created_at=format_timestamp(clock()),
        cluster_uuid=metadata.cluster_uuid,
        cluster_name=metadata.cluster_name,
        operation_id=binding.record.operation_id,
        operation=binding.record.operation,
        operation_classification=binding.record.operation_classification,
        effective_classification=binding.record.effective_classification,
        selected_stable_ids=binding.record.selected_stable_ids,
        request_digest=binding.record.request_digest,
        plan_schema_version=binding.record.plan_schema_version,
        plan_digest=binding.record.plan_digest,
        plan_status=binding.record.plan_status,
        operation_binding_schema_version=binding.record.schema_version,
        operation_binding_generation=binding.record.generation,
        operation_binding_digest=binding.digest,
        catalog_digest=binding.record.catalog_digest,
        source_version=binding.record.source_version,
        source_digest=binding.record.source_digest,
        readiness_schema_version=binding.record.readiness_schema_version,
        readiness_digest=binding.record.readiness_digest,
        readiness_status=binding.record.readiness_status,
        observation_generation=cast(int, binding.record.observation_generation),
        observation_digest=cast(str, binding.record.observation_digest),
        inventory_generation=binding.record.inventory_generation,
        inventory_digest=binding.record.inventory_digest,
        trust_generation=cast(int, binding.record.trust_generation),
        trust_digest=cast(str, binding.record.trust_digest),
        journal_schema_version=journal.record.schema_version,
        journal_generation=journal.record.generation,
        journal_digest=journal.digest,
        journal_status=journal.record.status,
        journal_phase=journal.record.phase,
        confirmation_policy=policy,
        proofs=proofs,
    )
    validate_operation_authorization(metadata, request, binding, journal, record)
    return record


def checkpoint_operation_authorization(
    lock: ClusterLock,
    metadata: ClusterMetadata,
    request: OperationRequest,
    operation_id: uuid.UUID,
    *,
    interactive: InteractiveConfirmation,
    clock: Callable[[], datetime],
    expected_generation: int = 0,
    expected_digest: str | None = None,
    replace: Callable[[Path, Path], None] = os.replace,
    token_factory: Callable[[], str] | None = None,
) -> StoredOperationAuthorization:
    """Persist confirmation without changing the journal or invoking execution."""

    _assert_operation_lock(lock, request.paths, request.operation.name)
    binding = OperationPlanBindingStore(request.paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
        expected_operation=request.operation.name,
    )
    journal = OperationJournalStore(request.paths, operation_id).read(
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    record = build_operation_authorization(
        metadata,
        request,
        binding,
        journal,
        interactive=interactive,
        clock=clock,
    )
    return OperationAuthorizationStore(
        request.paths,
        operation_id,
        replace=replace,
        token_factory=token_factory,
    ).write_locked(
        record,
        expected_generation=expected_generation,
        expected_digest=expected_digest,
        lock=lock,
        request=request,
        metadata=metadata,
    )


def validate_current_operation_authorization(
    lock: ClusterLock,
    metadata: ClusterMetadata,
    request: OperationRequest,
    binding: StoredOperationPlanBinding,
    journal: StoredOperationRecord,
) -> StoredOperationAuthorization | None:
    """Require exact unchanged authorization only for confirmation-bearing classes."""

    _assert_operation_lock(lock, request.paths, request.operation.name)
    policy = confirmation_policy_for(request, binding.record)
    store = OperationAuthorizationStore(request.paths, binding.record.operation_id)
    validate_state_file(store.path, allow_missing=True)
    if policy is ConfirmationPolicy.NOT_REQUIRED:
        if store.path.exists():
            raise StateConflictError(
                "read-only operation has a forbidden authorization record"
            )
        return None
    if not store.path.exists():
        raise StateConflictError("operation authorization checkpoint is missing")
    stored = store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
        expected_operation=request.operation.name,
    )
    validate_operation_authorization(metadata, request, binding, journal, stored.record)
    return stored


def validate_operation_authorization(
    metadata: ClusterMetadata,
    request: OperationRequest,
    binding: StoredOperationPlanBinding,
    journal: StoredOperationRecord,
    authorization: OperationAuthorization,
) -> None:
    """Recompute the complete checkpoint and separated proof bindings."""

    _validate_checkpoint_inputs(metadata, request, binding, journal)
    bound = binding.record
    if (
        authorization.cluster_uuid != metadata.cluster_uuid
        or authorization.cluster_name != metadata.cluster_name
        or authorization.operation_id != bound.operation_id
        or authorization.operation != bound.operation
        or authorization.operation_classification is not bound.operation_classification
        or authorization.effective_classification is not bound.effective_classification
        or authorization.selected_stable_ids != bound.selected_stable_ids
        or authorization.request_digest != bound.request_digest
        or authorization.plan_schema_version != bound.plan_schema_version
        or authorization.plan_digest != bound.plan_digest
        or authorization.plan_status is not bound.plan_status
        or authorization.operation_binding_schema_version != bound.schema_version
        or authorization.operation_binding_generation != bound.generation
        or authorization.operation_binding_digest != binding.digest
        or authorization.catalog_digest != bound.catalog_digest
        or authorization.source_version != bound.source_version
        or authorization.source_digest != bound.source_digest
        or authorization.readiness_schema_version != bound.readiness_schema_version
        or authorization.readiness_digest != bound.readiness_digest
        or authorization.readiness_status is not bound.readiness_status
        or authorization.observation_generation != bound.observation_generation
        or authorization.observation_digest != bound.observation_digest
        or authorization.inventory_generation != bound.inventory_generation
        or authorization.inventory_digest != bound.inventory_digest
        or authorization.trust_generation != bound.trust_generation
        or authorization.trust_digest != bound.trust_digest
        or authorization.journal_schema_version != journal.record.schema_version
        or authorization.journal_generation != journal.record.generation
        or authorization.journal_digest != journal.digest
        or authorization.journal_status is not journal.record.status
        or authorization.journal_phase is not journal.record.phase
    ):
        raise StateConflictError(
            "operation authorization identity or provenance drifted"
        )
    if authorization.confirmation_policy is not confirmation_policy_for(request, bound):
        raise StateConflictError("operation authorization class policy drifted")
    expected = _recompute_authorization_proofs(request, binding, authorization.proofs)
    if authorization.proofs != expected:
        raise StateConflictError("operation authorization proof drifted")


def operation_authorization_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError("operation authorization ID must be a UUID")
    path = paths.operations / f"{operation_id}{OPERATION_AUTHORIZATION_FILENAME_SUFFIX}"
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "Ansible operation authorization path is not canonical"
        )
    return path


def operation_authorization_id_from_filename(name: str) -> uuid.UUID | None:
    if not name.endswith(OPERATION_AUTHORIZATION_FILENAME_SUFFIX):
        return None
    identifier_text = name[: -len(OPERATION_AUTHORIZATION_FILENAME_SUFFIX)]
    try:
        identifier = uuid.UUID(identifier_text)
    except ValueError:
        return None
    return identifier if str(identifier) == identifier_text else None


def _validate_checkpoint_inputs(
    metadata: ClusterMetadata,
    request: OperationRequest,
    binding: StoredOperationPlanBinding,
    journal: StoredOperationRecord,
) -> None:
    _require_canonical_paths(request.paths)
    validate_digest(binding.digest, "Ansible operation binding digest")
    _validate_request_binding_identity(request, binding.record)
    if (
        metadata.cluster_uuid != binding.record.cluster_uuid
        or metadata.cluster_name != binding.record.cluster_name
        or metadata.provider != request.provider.name
        or request.paths.cluster_root.name != metadata.cluster_name
    ):
        raise StateConflictError("operation authorization cluster identity conflicts")
    if (
        journal.record.operation_id != binding.record.operation_id
        or journal.record.operation != binding.record.operation
        or journal.record.cluster_uuid != binding.record.cluster_uuid
        or journal.record.cluster_name != binding.record.cluster_name
        or journal.record.request_digest != binding.record.request_digest
        or journal.record.schema_version != binding.record.journal_schema_version
        or journal.record.generation != binding.record.journal_generation
        or journal.digest != binding.record.journal_digest
        or journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.PLAN
    ):
        raise StateConflictError(
            "operation authorization requires the exact bound PLAN checkpoint"
        )
    if binding.record.plan_status is not AnsibleOperationPlanStatus.READY:
        raise StateConflictError(
            "operation authorization requires an unblocked ready plan"
        )


def _validate_request_binding_identity(
    request: OperationRequest, binding: OperationPlanBinding
) -> None:
    try:
        operation = get_operation(request.operation.name)
    except KeyError as error:
        raise StateConflictError(
            "operation authorization registry identity is invalid"
        ) from error
    if (
        operation != request.operation
        or binding.operation != request.operation.name
        or binding.operation_classification is not request.operation.classification
        or binding.request_digest != normalized_operation_request_digest(request)
    ):
        raise StateConflictError("operation authorization request binding drifted")


def _classification_policy(
    classification: OperationClassification,
) -> ConfirmationPolicy:
    policies = {
        OperationClassification.READ_ONLY: ConfirmationPolicy.NOT_REQUIRED,
        OperationClassification.MUTATING: ConfirmationPolicy.MUTATING,
        OperationClassification.SENSITIVE: ConfirmationPolicy.SENSITIVE,
        OperationClassification.DESTRUCTIVE: ConfirmationPolicy.DESTRUCTIVE,
    }
    try:
        return policies[classification]
    except KeyError as error:
        raise StateConflictError(
            "operation confirmation policy is undefined"
        ) from error


def _build_authorization_proofs(
    request: OperationRequest,
    binding: StoredOperationPlanBinding,
    interactive: InteractiveConfirmation,
) -> tuple[AuthorizationProof, ...]:
    sources: dict[AuthorizationProofKind, AuthorizationProofSource] = {}
    if _boolean(request, "yes"):
        sources[AuthorizationProofKind.ORDINARY_CONFIRMATION] = (
            AuthorizationProofSource.CLI_YES
        )
    elif not _boolean(request, "non_interactive") and interactive.ordinary_approved:
        sources[AuthorizationProofKind.ORDINARY_CONFIRMATION] = (
            AuthorizationProofSource.INTERACTIVE
        )
    else:
        raise StateConflictError("ordinary operation confirmation is required")

    require_exact_scope = _requires_exact_scope(request, binding.record)
    if require_exact_scope:
        if not _boolean(request, "allow_destructive"):
            raise StateConflictError("destructive class acknowledgement is required")
        sources[AuthorizationProofKind.DESTRUCTIVE_CLASS] = (
            AuthorizationProofSource.CLI_EXPLICIT
        )
        if _exact_scope_confirmation_present_and_valid(request, binding.record):
            sources[AuthorizationProofKind.EXACT_OPERATION_SCOPE] = (
                AuthorizationProofSource.CLI_EXPLICIT
            )
        elif (
            not _boolean(request, "non_interactive")
            and interactive.exact_scope_approved
        ):
            sources[AuthorizationProofKind.EXACT_OPERATION_SCOPE] = (
                AuthorizationProofSource.INTERACTIVE
            )
        else:
            raise StateConflictError(
                "exact destructive operation scope confirmation is required"
            )

    if _requires_storage_wipe(request):
        _validate_storage_wipe_confirmation(request)
        sources[AuthorizationProofKind.STORAGE_WIPE] = (
            AuthorizationProofSource.CLI_EXPLICIT
        )

    if _requires_monitoring_restart(request):
        if _boolean(request, "confirm_monitoring_restart"):
            sources[AuthorizationProofKind.MONITORING_RESTART] = (
                AuthorizationProofSource.CLI_EXPLICIT
            )
        elif (
            not _boolean(request, "non_interactive")
            and interactive.monitoring_restart_approved
        ):
            sources[AuthorizationProofKind.MONITORING_RESTART] = (
                AuthorizationProofSource.INTERACTIVE
            )
        else:
            raise StateConflictError("monitoring restart confirmation is required")
    return _proofs_from_sources(request, binding, sources)


def _recompute_authorization_proofs(
    request: OperationRequest,
    binding: StoredOperationPlanBinding,
    proofs: tuple[AuthorizationProof, ...],
) -> tuple[AuthorizationProof, ...]:
    sources = {proof.kind: proof.source for proof in proofs}
    ordinary_source = sources.get(AuthorizationProofKind.ORDINARY_CONFIRMATION)
    if _boolean(request, "yes"):
        expected_ordinary = AuthorizationProofSource.CLI_YES
    elif not _boolean(request, "non_interactive"):
        expected_ordinary = AuthorizationProofSource.INTERACTIVE
    else:
        raise StateConflictError("ordinary operation confirmation is missing")
    if ordinary_source is not expected_ordinary:
        raise StateConflictError("ordinary operation confirmation source drifted")

    required_kinds = set(_BASE_PROOF_KINDS)
    if _requires_exact_scope(request, binding.record):
        required_kinds.update(
            {
                AuthorizationProofKind.DESTRUCTIVE_CLASS,
                AuthorizationProofKind.EXACT_OPERATION_SCOPE,
            }
        )
        if not _boolean(request, "allow_destructive"):
            raise StateConflictError("destructive class acknowledgement drifted")
        if (
            sources.get(AuthorizationProofKind.DESTRUCTIVE_CLASS)
            is not AuthorizationProofSource.CLI_EXPLICIT
        ):
            raise StateConflictError("destructive class acknowledgement source drifted")
        scope_source = sources.get(AuthorizationProofKind.EXACT_OPERATION_SCOPE)
        cli_scope = _exact_scope_confirmation_present_and_valid(request, binding.record)
        expected_scope_source = (
            AuthorizationProofSource.CLI_EXPLICIT
            if cli_scope
            else AuthorizationProofSource.INTERACTIVE
        )
        if scope_source is not expected_scope_source or (
            expected_scope_source is AuthorizationProofSource.INTERACTIVE
            and _boolean(request, "non_interactive")
        ):
            raise StateConflictError(
                "exact destructive operation scope confirmation drifted"
            )

    if _requires_storage_wipe(request):
        _validate_storage_wipe_confirmation(request)
        required_kinds.add(AuthorizationProofKind.STORAGE_WIPE)
        if (
            sources.get(AuthorizationProofKind.STORAGE_WIPE)
            is not AuthorizationProofSource.CLI_EXPLICIT
        ):
            raise StateConflictError("storage wipe consent source drifted")

    if _requires_monitoring_restart(request):
        required_kinds.add(AuthorizationProofKind.MONITORING_RESTART)
        expected_restart_source = (
            AuthorizationProofSource.CLI_EXPLICIT
            if _boolean(request, "confirm_monitoring_restart")
            else AuthorizationProofSource.INTERACTIVE
        )
        if sources.get(
            AuthorizationProofKind.MONITORING_RESTART
        ) is not expected_restart_source or (
            expected_restart_source is AuthorizationProofSource.INTERACTIVE
            and _boolean(request, "non_interactive")
        ):
            raise StateConflictError("monitoring restart confirmation drifted")
    if set(sources) != required_kinds:
        raise StateConflictError(
            "operation authorization proof set is missing or over-broad"
        )
    return _proofs_from_sources(request, binding, sources)


def _proofs_from_sources(
    request: OperationRequest,
    binding: StoredOperationPlanBinding,
    sources: Mapping[AuthorizationProofKind, AuthorizationProofSource],
) -> tuple[AuthorizationProof, ...]:
    return tuple(
        AuthorizationProof(
            kind,
            sources[kind],
            _authorization_proof_digest(request, binding, kind, sources[kind]),
        )
        for kind in sorted(sources, key=_PROOF_ORDER.__getitem__)
    )


def _authorization_proof_digest(
    request: OperationRequest,
    binding: StoredOperationPlanBinding,
    kind: AuthorizationProofKind,
    source: AuthorizationProofSource,
) -> str:
    scope: dict[str, object] = {}
    if kind is AuthorizationProofKind.EXACT_OPERATION_SCOPE:
        scope = _exact_scope_payload(request, binding.record)
    elif kind is AuthorizationProofKind.STORAGE_WIPE:
        confirmations = _strings(request, "confirm_wipe_device")
        scope = {
            "confirmed_device_count": len(confirmations),
            "confirmed_device_set_digest": digest_bytes(
                serialize_json({"identifiers": list(sorted(confirmations))})
            ),
        }
    elif kind is AuthorizationProofKind.MONITORING_RESTART:
        scope = {"service_action": "restart"}
    return digest_bytes(
        serialize_json(
            {
                "binding_digest": binding.digest,
                "cluster_uuid": str(binding.record.cluster_uuid),
                "journal_digest": binding.record.journal_digest,
                "kind": kind.value,
                "operation": binding.record.operation,
                "operation_id": str(binding.record.operation_id),
                "plan_digest": binding.record.plan_digest,
                "request_digest": binding.record.request_digest,
                "schema_version": _PROOF_SCHEMA_VERSION,
                "scope": scope,
                "selected_stable_ids": list(binding.record.selected_stable_ids),
                "source": source.value,
            }
        )
    )


def _requires_exact_scope(
    request: OperationRequest, binding: OperationPlanBinding
) -> bool:
    if request.operation.classification is OperationClassification.DESTRUCTIVE:
        if request.operation.name not in {
            "replace-node",
            "destroy-node",
            "destroy",
            "scale-in",
        }:
            raise StateConflictError(
                "destructive operation has no PLAN-defined exact scope token"
            )
        return True
    if request.operation.name == "redeploy":
        return _string(request, "infrastructure") == "recreate-stateless"
    if request.operation.name == "upgrade-os":
        strategy = _string(request, "strategy")
        return strategy == "reprovision" or (
            strategy == "auto"
            and binding.effective_classification is OperationClassification.DESTRUCTIVE
        )
    return False


def _exact_scope_confirmation_present_and_valid(
    request: OperationRequest, binding: OperationPlanBinding
) -> bool:
    operation = request.operation.name
    actual: object
    expected: object
    if operation == "replace-node":
        actual = _optional_string(request, "confirm_replace_node")
        expected = _string(request, "node_id")
    elif operation == "destroy-node":
        actual = _optional_string(request, "confirm_destroy_node")
        expected = _string(request, "node_id")
    elif operation == "scale-in":
        actual = _optional_string(request, "confirm_scale_in")
        expected = request.cluster_name
    elif operation == "destroy":
        actual = _optional_string(request, "confirm_destroy_cluster")
        expected = f"{request.cluster_name}:{binding.cluster_uuid}"
    elif operation == "redeploy":
        actual = _optional_string(request, "confirm_recreate_host")
        expected = _string(request, "target_host")
    elif operation == "upgrade-os":
        actual = tuple(sorted(_strings(request, "confirm_reprovision_host")))
        expected = tuple(sorted(_exact_scope_stable_ids(request, binding)))
        if not actual:
            return False
    else:
        raise StateConflictError(
            "operation has no PLAN-defined exact scope confirmation"
        )
    if actual is None:
        return False
    if actual != expected:
        raise StateConflictError(
            "exact destructive operation scope confirmation conflicts"
        )
    return True


def _exact_scope_payload(
    request: OperationRequest, binding: OperationPlanBinding
) -> dict[str, object]:
    operation = request.operation.name
    if operation == "destroy":
        return {
            "scope": "cluster",
            "scope_digest": digest_bytes(
                serialize_json(
                    {
                        "cluster_name": request.cluster_name,
                        "cluster_uuid": str(binding.cluster_uuid),
                    }
                )
            ),
        }
    stable_ids = _exact_scope_stable_ids(request, binding)
    return {
        "scope": "stable-targets",
        "scope_digest": digest_bytes(serialize_json({"stable_ids": list(stable_ids)})),
        "target_count": len(stable_ids),
    }


def _exact_scope_stable_ids(
    request: OperationRequest, binding: OperationPlanBinding
) -> tuple[str, ...]:
    operation = request.operation.name
    values: tuple[str, ...]
    if operation in {"replace-node", "destroy-node"}:
        values = (_string(request, "node_id"),)
    elif operation == "scale-in":
        explicit = _strings(request, "remove_node")
        values = explicit or binding.selected_stable_ids
    elif operation == "redeploy":
        values = (_string(request, "target_host"),)
    elif operation == "upgrade-os":
        explicit = _strings(request, "target_host")
        values = explicit or binding.selected_stable_ids
    else:
        raise StateConflictError(
            "operation has no PLAN-defined stable target confirmation"
        )
    normalized = tuple(sorted(set(values)))
    _validate_stable_ids(normalized)
    if not set(normalized) <= set(binding.selected_stable_ids):
        raise StateConflictError(
            "exact destructive operation scope is outside the bound target set"
        )
    return normalized


def _requires_storage_wipe(request: OperationRequest) -> bool:
    if request.operation.name not in {"add-node", "replace-node"}:
        return False
    return _boolean(request, "wipe_storage")


def _validate_storage_wipe_confirmation(request: OperationRequest) -> None:
    confirmations = _strings(request, "confirm_wipe_device")
    if not confirmations:
        raise StateConflictError("storage wipe requires separate exact device consent")
    if confirmations != tuple(dict.fromkeys(confirmations)):
        raise StateConflictError("storage wipe device consent is duplicated")


def _requires_monitoring_restart(request: OperationRequest) -> bool:
    return (
        request.operation.name == "refresh-monitoring"
        and _string(request, "service_action") == "restart"
    )


def _boolean(request: OperationRequest, name: str) -> bool:
    try:
        value = request.option(name).value
    except KeyError:
        return False
    if not isinstance(value, bool):
        raise StateConflictError(
            f"operation authorization option is not boolean: {name}"
        )
    return value


def _string(request: OperationRequest, name: str) -> str:
    try:
        value = request.option(name).value
    except KeyError as error:
        raise StateConflictError(
            f"operation confirmation token is not defined by PLAN: {name}"
        ) from error
    if not isinstance(value, str):
        raise StateConflictError(
            f"operation authorization option is not a concrete string: {name}"
        )
    return value


def _optional_string(request: OperationRequest, name: str) -> str | None:
    try:
        value = request.option(name).value
    except KeyError as error:
        raise StateConflictError(
            f"operation confirmation token is not defined by PLAN: {name}"
        ) from error
    if value is None or isinstance(value, DeferredValue):
        return None
    if not isinstance(value, str):
        raise StateConflictError(
            f"operation authorization option is not a string: {name}"
        )
    return value


def _strings(request: OperationRequest, name: str) -> tuple[str, ...]:
    try:
        value = request.option(name).value
    except KeyError as error:
        raise StateConflictError(
            f"operation confirmation token is not defined by PLAN: {name}"
        ) from error
    if not isinstance(value, tuple) or not all(isinstance(item, str) for item in value):
        raise StateConflictError(
            f"operation authorization option is not a string list: {name}"
        )
    return cast(tuple[str, ...], value)


def _validate_stable_ids(values: tuple[str, ...]) -> None:
    if (
        not values
        or values != tuple(sorted(set(values)))
        or not all(
            value.isascii() and _LOGICAL_ID.fullmatch(value) is not None
            for value in values
        )
    ):
        raise StatePersistenceError(
            "Ansible operation authorization stable IDs are invalid"
        )


def _validate_generation(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} generation is invalid")


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _require_canonical_paths(paths: StatePaths) -> None:
    expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
    if expected != paths or paths.operations.parent != paths.cluster_root:
        raise UnsafePathError("Ansible operation authorization paths are not canonical")


def _assert_operation_lock(
    lock: ClusterLock, paths: StatePaths, operation: str
) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Ansible operation authorization requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, operation)


def _assert_read_lock(lock: object, paths: StatePaths) -> None:
    assertion = getattr(lock, "assert_held_for", None)
    if not callable(assertion):
        raise StateLockError(
            "Ansible operation authorization read requires an acquired cluster lock"
        )
    assertion(paths)
