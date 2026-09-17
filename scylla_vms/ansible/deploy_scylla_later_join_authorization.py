"""Sensitive authorization for the canonically selected later Scylla join.

This internal, subprocess-free owner derives the first unfinished sequence
``>=4`` exclusively from the immutable later-join safety reconciliation.  It
persists one immutable, unconsumed authorization without accepting
caller-selected target, sequence, execution, or runtime values.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from scylla_vms.ansible.deploy_plan import _digest_object, _require_operation_id
from scylla_vms.ansible.deploy_scylla_join_authorization import (
    DeployScyllaJoinApprovalMethod,
    DeployScyllaJoinNarrowApprovalMethod,
    _cluster_identity_digest,
    _dataclass_object,
    _digest_fields,
    _json_object,
    _json_value,
    _mapping,
    _nonnegative_integer,
    _parse_dataclass,
    _positive_integer,
)
from scylla_vms.ansible.deploy_scylla_join_safety import (
    DeployScyllaJoinSafetyProofStatus,
)
from scylla_vms.ansible.deploy_scylla_later_join_safety import (
    ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION,
    DeployScyllaLaterJoinSafetyContext,
    DeployScyllaLaterJoinSafetyContextStore,
    DeployScyllaLaterJoinSafetyEvidence,
    DeployScyllaLaterJoinSafetyEvidenceStore,
    DeployScyllaLaterJoinSafetyReconciliation,
    DeployScyllaLaterJoinSafetyReconciliationStore,
    DeployScyllaLaterJoinSafetyStepStatus,
    StoredDeployScyllaLaterJoinSafetyArtifact,
    _LaterJoinSafetyLoaded,
    _load_later_join_safety,
    deploy_scylla_later_join_safety_context_id_from_filename,
    deploy_scylla_later_join_safety_evidence_id_from_filename,
    deploy_scylla_later_join_safety_reconciliation_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_later_join_safety import (
    _build_context as _build_safety_context,
)
from scylla_vms.ansible.deploy_scylla_later_join_safety import (
    _build_evidence as _build_safety_evidence,
)
from scylla_vms.ansible.deploy_scylla_later_join_safety import (
    _build_reconciliation as _build_safety_reconciliation,
)
from scylla_vms.ansible.deploy_scylla_later_join_safety import (
    _validate_proofs as _validate_safety_proofs,
)
from scylla_vms.ansible.operation_authorization import (
    OPERATION_AUTHORIZATION_FILENAME_SUFFIX,
    ConfirmationPolicy,
)
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_bootstrap import ScyllaBootstrapMode
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.journal import JOURNAL_SCHEMA_VERSION, JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import (
    AtomicJsonFile,
    digest_bytes,
    format_timestamp,
    parse_timestamp,
    serialize_json,
    validate_digest,
)
from scylla_vms.state import (
    StatePaths,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)

ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-later-join-authorization-proof/v1"
)
ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-later-join-authorization/v1"
)
ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-later-join-authorization-report/v1"
)
DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_FILENAME_SUFFIX = "-authorization.json"
_LATER_JOIN_NAMESPACE_STEM = ".ansible-deploy-scylla-later-join-"
_LATER_JOIN_FILENAME_STEM = f"{_LATER_JOIN_NAMESPACE_STEM}sequence-"

_OPERATION = "deploy"
_PLAYBOOK = "scylla-bootstrap"
_STAGE = "later-join-authorization"
_SCOPE_KIND = "reconciled-first-unfinished-later-join-existing"
_MINIMUM_SEQUENCE = 4
_AUTHORIZED = "authorized-pre-execution"
_AUTHORIZATION_REQUIRED = "authorization-required"
_AUTHORIZATION_NOT_CREATED = "not-created"
_EXECUTION_UNAVAILABLE = "unavailable"
_FINALIZATION_NOT_STARTED = "not-started"
_PUBLIC_WORKFLOW_UNAVAILABLE = "unavailable"
_APPROVED = "approved"
_MATCHED = "matched"
_WAITING = "waiting"
_EXTERNAL_GATES = ("backup-policy", "capacity", "quorum", "replication")


class DeployScyllaLaterJoinAuthorizationArtifactState(StrEnum):
    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployScyllaLaterJoinAuthorizationScope:
    """Redacted exact scope derived from later-join safety."""

    sequence: int
    mode: ScyllaBootstrapMode
    classification: OperationClassification
    confirmation_policy: ConfirmationPolicy
    target_count: int
    target_digest: str
    bootstrap_plan_step_digest: str
    latest_health_step_digest: str
    safety_step_digest: str
    completed_prefix_count: int
    completed_prefix_digest: str
    order_digest: str
    survivor_count: int
    survivor_set_digest: str
    survivor_health_digest: str
    active_seed_count: int
    active_seed_set_digest: str
    topology_digest: str
    target_topology_digest: str
    schema_digest: str
    membership_digest: str
    host_mapping_digest: str
    streaming_gate_digest: str
    seed_policy_digest: str
    package_version_digest: str
    storage_evidence_digest: str
    configuration_evidence_digest: str
    target_capacity_evidence_digest: str
    backup_policy_evidence_digest: str
    capacity_policy_evidence_digest: str
    quorum_evidence_digest: str
    replication_evidence_digest: str
    playbook_source_digest: str
    safety_context_digest: str
    safety_evidence_digest: str
    safety_reconciliation_digest: str
    safety_proof_set_digest: str
    safety_gate_set_digest: str
    scope_digest: str

    def __post_init__(self) -> None:
        if (
            self.sequence < _MINIMUM_SEQUENCE
            or self.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or self.classification is not OperationClassification.SENSITIVE
            or self.confirmation_policy is not ConfirmationPolicy.SENSITIVE
            or self.target_count != 1
            or self.completed_prefix_count != self.sequence - 1
            or self.survivor_count != self.completed_prefix_count
            or self.active_seed_count != 1
            or self.order_digest
            != _digest_object(
                {
                    "completed_prefix_digest": self.completed_prefix_digest,
                    "sequence": self.sequence,
                    "target_plan_step_digest": self.bootstrap_plan_step_digest,
                }
            )
            or self.scope_digest != _scope_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla later-join authorization scope conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(value, "later-join authorization scope digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaLaterJoinAuthorizationScope:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={
                "sequence",
                "target_count",
                "completed_prefix_count",
                "survivor_count",
                "active_seed_count",
            },
            enum_fields={
                "mode": ScyllaBootstrapMode,
                "classification": OperationClassification,
                "confirmation_policy": ConfirmationPolicy,
            },
            label="later-join authorization scope",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaLaterJoinNarrowScopeProof:
    """Exact digest-only target/mode/sequence/scope acknowledgement."""

    sequence: int
    target_count: int
    target_digest: str
    mode: ScyllaBootstrapMode
    bootstrap_plan_step_digest: str
    safety_step_digest: str
    authorization_scope_digest: str

    def __post_init__(self) -> None:
        if (
            self.sequence < _MINIMUM_SEQUENCE
            or self.target_count != 1
            or self.mode is not ScyllaBootstrapMode.JOIN_EXISTING
        ):
            raise StateConflictError(
                "later-join narrow proof must bind one sequence >=4 "
                "join-existing target"
            )
        for value in _digest_fields(self):
            validate_digest(value, "later-join narrow proof digest")

    @classmethod
    def from_scope(
        cls, scope: DeployScyllaLaterJoinAuthorizationScope
    ) -> DeployScyllaLaterJoinNarrowScopeProof:
        if not isinstance(scope, DeployScyllaLaterJoinAuthorizationScope):
            raise StateConflictError("later-join authorization scope is malformed")
        return cls(
            sequence=scope.sequence,
            target_count=scope.target_count,
            target_digest=scope.target_digest,
            mode=scope.mode,
            bootstrap_plan_step_digest=scope.bootstrap_plan_step_digest,
            safety_step_digest=scope.safety_step_digest,
            authorization_scope_digest=scope.scope_digest,
        )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)


@dataclass(frozen=True, slots=True)
class DeployScyllaLaterJoinAuthorizationProof:
    """Already-normalized ordinary and narrow approval facts."""

    approval_method: DeployScyllaJoinApprovalMethod | None = None
    approved: bool = False
    narrow_approval_method: DeployScyllaJoinNarrowApprovalMethod | None = None
    narrow_approved: bool = False
    narrow_scope: DeployScyllaLaterJoinNarrowScopeProof | None = None
    allow_destructive: bool = False
    destructive_scope_provided: bool = False

    def __post_init__(self) -> None:
        if self.approval_method is not None and not isinstance(
            self.approval_method, DeployScyllaJoinApprovalMethod
        ):
            raise StateConflictError("later-join approval method is invalid")
        if self.narrow_approval_method is not None and not isinstance(
            self.narrow_approval_method, DeployScyllaJoinNarrowApprovalMethod
        ):
            raise StateConflictError("later-join narrow approval method is invalid")
        if self.narrow_scope is not None and not isinstance(
            self.narrow_scope, DeployScyllaLaterJoinNarrowScopeProof
        ):
            raise StateConflictError("later-join narrow proof is malformed")
        if not all(
            isinstance(item, bool)
            for item in (
                self.approved,
                self.narrow_approved,
                self.allow_destructive,
                self.destructive_scope_provided,
            )
        ):
            raise StateConflictError("later-join authorization proof is malformed")


@dataclass(frozen=True, slots=True)
class DeployScyllaLaterJoinProofDecision:
    """Persisted approval decision bound to the derived later-join scope."""

    approval_method: DeployScyllaJoinApprovalMethod
    approval_state: str
    narrow_approval_method: DeployScyllaJoinNarrowApprovalMethod
    narrow_approval_state: str
    sequence: int
    target_count: int
    target_digest: str
    mode: ScyllaBootstrapMode
    bootstrap_plan_step_digest: str
    safety_step_digest: str
    authorization_scope_digest: str
    allow_destructive: bool
    destructive_scope_provided: bool
    proof_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or self.approval_state != _APPROVED
            or self.narrow_approval_state != _MATCHED
            or self.sequence < _MINIMUM_SEQUENCE
            or self.target_count != 1
            or self.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or self.allow_destructive
            or self.destructive_scope_provided
        ):
            raise StatePersistenceError("later-join proof decision conflicts")
        for value in _digest_fields(self):
            validate_digest(value, "later-join proof decision digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaLaterJoinProofDecision:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={"sequence", "target_count"},
            boolean_fields={"allow_destructive", "destructive_scope_provided"},
            enum_fields={
                "approval_method": DeployScyllaJoinApprovalMethod,
                "narrow_approval_method": DeployScyllaJoinNarrowApprovalMethod,
                "mode": ScyllaBootstrapMode,
            },
            label="later-join authorization proof",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaLaterJoinAuthorization:
    """Immutable unconsumed authorization for one derived later join."""

    generation: int
    created_at: str
    cluster_uuid: uuid.UUID
    cluster_identity_digest: str
    operation_id: uuid.UUID
    operation: str
    stage: str
    scope_kind: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    bootstrap_context_artifact_digest: str
    bootstrap_context_record_digest: str
    bootstrap_plan_artifact_digest: str
    bootstrap_plan_digest: str
    latest_health_execution_artifact_digest: str
    latest_health_evidence_artifact_digest: str
    latest_health_evidence_digest: str
    latest_health_reconciliation_artifact_digest: str
    latest_health_reconciliation_digest: str
    safety_context_artifact_digest: str
    safety_context_digest: str
    safety_evidence_artifact_digest: str
    safety_evidence_digest: str
    safety_reconciliation_artifact_digest: str
    safety_reconciliation_digest: str
    completed_prefix_count: int
    completed_prefix_digest: str
    current_state_digest: str
    validated_chain_digest: str
    classification: OperationClassification
    confirmation_policy: ConfirmationPolicy
    scope: DeployScyllaLaterJoinAuthorizationScope
    authorization_scope_digest: str
    later_join_count: int
    later_join_digest: str
    non_authorized_scope_digest: str
    proof: DeployScyllaLaterJoinProofDecision
    authorization_state: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_digest: str
    safety_context_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
    )
    safety_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
    )
    safety_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION
    )
    proof_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_SCHEMA_VERSION
            or self.safety_context_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
            or self.safety_evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
            or self.safety_reconciliation_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.classification is not OperationClassification.SENSITIVE
            or self.confirmation_policy is not ConfirmationPolicy.SENSITIVE
            or self.authorization_state != _AUTHORIZED
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
            or not isinstance(self.scope, DeployScyllaLaterJoinAuthorizationScope)
            or not isinstance(self.proof, DeployScyllaLaterJoinProofDecision)
            or self.completed_prefix_count != self.scope.completed_prefix_count
            or self.completed_prefix_digest != self.scope.completed_prefix_digest
            or self.authorization_scope_digest != self.scope.scope_digest
            or self.proof.sequence != self.scope.sequence
            or self.proof.target_count != self.scope.target_count
            or self.proof.target_digest != self.scope.target_digest
            or self.proof.mode is not self.scope.mode
            or self.proof.bootstrap_plan_step_digest
            != self.scope.bootstrap_plan_step_digest
            or self.proof.safety_step_digest != self.scope.safety_step_digest
            or self.proof.authorization_scope_digest != self.authorization_scope_digest
            or self.proof.proof_digest != _proof_digest(self, self.proof.to_object())
            or self.authorization_digest != _authorization_digest(self)
        ):
            raise StatePersistenceError(
                "later-join authorization identity, scope, or state conflicts"
            )
        parse_timestamp(self.created_at)
        _positive_integer(self.journal_generation, "later-join authorization journal")
        _nonnegative_integer(self.later_join_count, "later join count")
        for value in _digest_fields(self):
            validate_digest(value, "later-join authorization digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, nested_fields={"scope", "proof"})

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaLaterJoinAuthorization:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={
                "generation",
                "journal_generation",
                "completed_prefix_count",
                "later_join_count",
            },
            uuid_fields={"cluster_uuid", "operation_id"},
            boolean_fields={"consumed"},
            enum_fields={
                "journal_status": JournalStatus,
                "journal_phase": OperationPhase,
                "classification": OperationClassification,
                "confirmation_policy": ConfirmationPolicy,
            },
            skip_fields={"scope", "proof"},
            label="later-join authorization",
        )
        parsed["scope"] = DeployScyllaLaterJoinAuthorizationScope.from_object(
            _mapping(value["scope"], "later-join authorization scope")
        )
        parsed["proof"] = DeployScyllaLaterJoinProofDecision.from_object(
            _mapping(value["proof"], "later-join authorization proof")
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaLaterJoinAuthorization:
    record: DeployScyllaLaterJoinAuthorization
    artifact_digest: str


class DeployScyllaLaterJoinAuthorizationStore:
    """Owner-only immutable generic later-join authorization store."""

    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        sequence: int,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        _require_canonical_paths(paths)
        self._paths = paths
        self._operation_id = _require_operation_id(operation_id)
        self._sequence = _require_later_sequence(sequence)
        self._path = deploy_scylla_later_join_authorization_path(
            paths, operation_id, sequence
        )
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaLaterJoinAuthorization:
        value, artifact_digest = self._file.read()
        record = DeployScyllaLaterJoinAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.scope.sequence != self._sequence
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_identity_digest
            != _cluster_identity_digest(expected_cluster_uuid, expected_cluster_name)
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError("later-join authorization identity conflicts")
        return StoredDeployScyllaLaterJoinAuthorization(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaLaterJoinAuthorization:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaLaterJoinAuthorization,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployScyllaLaterJoinAuthorization,
        DeployScyllaLaterJoinAuthorizationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError("later-join authorization operation conflicts")
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=self._paths.cluster_root.name,
            )
            if current.record != record:
                raise StateConflictError(
                    "later-join authorization is immutable; use a new operation"
                )
            return current, DeployScyllaLaterJoinAuthorizationArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaLaterJoinAuthorization(record, artifact_digest),
            DeployScyllaLaterJoinAuthorizationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaLaterJoinAuthorizationReport:
    """Strict redacted required/not-required projection."""

    operation_id: uuid.UUID
    required: bool
    state: str
    completed_prefix_count: int
    survivor_count: int
    active_seed_count: int
    later_join_count: int
    authorization_state: str
    execution_state: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    journal_digest: str
    artifact_state: DeployScyllaLaterJoinAuthorizationArtifactState | None = None
    authorization_artifact_digest: str | None = None
    authorization_digest: str | None = None
    classification: OperationClassification | None = None
    confirmation_policy: ConfirmationPolicy | None = None
    approval_method: DeployScyllaJoinApprovalMethod | None = None
    narrow_approval_method: DeployScyllaJoinNarrowApprovalMethod | None = None
    proof_digest: str | None = None
    sequence: int | None = None
    mode: ScyllaBootstrapMode | None = None
    target_count: int = 0
    target_digest: str | None = None
    authorization_scope_digest: str | None = None
    safety_context_digest: str | None = None
    safety_evidence_digest: str | None = None
    safety_reconciliation_digest: str | None = None
    safety_gate_set_digest: str | None = None
    validated_chain_digest: str | None = None
    later_join_digest: str | None = None
    consumed: bool = False
    public_workflow_state: str = _PUBLIC_WORKFLOW_UNAVAILABLE
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        required_values = (
            self.artifact_state,
            self.authorization_artifact_digest,
            self.authorization_digest,
            self.classification,
            self.confirmation_policy,
            self.approval_method,
            self.narrow_approval_method,
            self.proof_digest,
            self.sequence,
            self.mode,
            self.target_digest,
            self.authorization_scope_digest,
            self.safety_context_digest,
            self.safety_evidence_digest,
            self.safety_reconciliation_digest,
            self.safety_gate_set_digest,
            self.validated_chain_digest,
            self.later_join_digest,
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_REPORT_SCHEMA_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.consumed
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
            or (
                self.required
                and (
                    self.state != "required"
                    or any(value is None for value in required_values)
                    or self.classification is not OperationClassification.SENSITIVE
                    or self.confirmation_policy is not ConfirmationPolicy.SENSITIVE
                    or self.sequence is None
                    or self.sequence < _MINIMUM_SEQUENCE
                    or self.mode is not ScyllaBootstrapMode.JOIN_EXISTING
                    or self.target_count != 1
                    or self.completed_prefix_count != self.sequence - 1
                    or self.survivor_count != self.completed_prefix_count
                    or self.active_seed_count != 1
                    or self.authorization_state != _AUTHORIZED
                    or self.execution_state != _EXECUTION_UNAVAILABLE
                )
            )
            or (
                not self.required
                and (
                    self.state != "not-required"
                    or any(value is not None for value in required_values)
                    or self.target_count
                    or self.later_join_count
                    or self.authorization_state != "not-required"
                    or self.execution_state != "not-required"
                )
            )
        ):
            raise StatePersistenceError("later-join authorization report conflicts")
        validate_digest(self.journal_digest, "later-join report journal digest")
        for value in required_values:
            if isinstance(value, str) and value.startswith("sha256:"):
                validate_digest(value, "later-join authorization report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "authorization": (
                None
                if not self.required
                else {
                    "artifact_digest": self.authorization_artifact_digest,
                    "consumed": self.consumed,
                    "digest": self.authorization_digest,
                    "state": self.authorization_state,
                }
            ),
            "execution": {
                "available": False,
                "public_workflow_state": self.public_workflow_state,
                "state": self.execution_state,
            },
            "journal": {
                "digest": self.journal_digest,
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "operation": {
                "classification": (
                    None if self.classification is None else self.classification.value
                ),
                "confirmation_policy": (
                    None
                    if self.confirmation_policy is None
                    else self.confirmation_policy.value
                ),
                "id": str(self.operation_id),
                "kind": _OPERATION,
            },
            "proof": (
                None
                if not self.required
                else {
                    "digest": self.proof_digest,
                    "narrow_method": (
                        None
                        if self.narrow_approval_method is None
                        else self.narrow_approval_method.value
                    ),
                    "narrow_state": _MATCHED,
                    "ordinary_method": (
                        None
                        if self.approval_method is None
                        else self.approval_method.value
                    ),
                    "ordinary_state": _APPROVED,
                }
            ),
            "provenance": (
                None
                if not self.required
                else {
                    "safety_context_digest": self.safety_context_digest,
                    "safety_evidence_digest": self.safety_evidence_digest,
                    "safety_reconciliation_digest": (self.safety_reconciliation_digest),
                    "validated_chain_digest": self.validated_chain_digest,
                }
            ),
            "result": (
                self.state if self.artifact_state is None else self.artifact_state.value
            ),
            "schema_version": self.schema_version,
            "scope": {
                "active_seed_count": self.active_seed_count,
                "authorization_scope_digest": self.authorization_scope_digest,
                "completed_prefix_count": self.completed_prefix_count,
                "later_join_count": self.later_join_count,
                "later_join_digest": self.later_join_digest,
                "mode": None if self.mode is None else self.mode.value,
                "safety_gate_set_digest": self.safety_gate_set_digest,
                "sequence": self.sequence,
                "survivor_count": self.survivor_count,
                "target_count": self.target_count,
                "target_digest": self.target_digest,
            },
            "stage": _STAGE,
            "state": self.state,
        }


@dataclass(frozen=True, slots=True)
class _LaterJoinAuthorizationLoaded:
    chain: _LaterJoinSafetyLoaded
    safety_context: StoredDeployScyllaLaterJoinSafetyArtifact[
        DeployScyllaLaterJoinSafetyContext
    ]
    safety_evidence: StoredDeployScyllaLaterJoinSafetyArtifact[
        DeployScyllaLaterJoinSafetyEvidence
    ]
    safety_reconciliation: StoredDeployScyllaLaterJoinSafetyArtifact[
        DeployScyllaLaterJoinSafetyReconciliation
    ]


def authorize_deploy_scylla_later_join(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proof: DeployScyllaLaterJoinAuthorizationProof | None,
) -> DeployScyllaLaterJoinAuthorizationReport:
    """Authorize only the derived first unfinished later join."""

    if proof is not None and not isinstance(
        proof, DeployScyllaLaterJoinAuthorizationProof
    ):
        raise StateConflictError("later-join authorization proof is malformed")
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_authorization_artifacts(paths, operation_id)
    chain = _load_later_join_safety(paths, operation_id, lock=lock)
    _refuse_incompatible_or_later_artifacts(
        paths,
        operation_id,
        chain.target_sequence,
        completed_sequence=chain.completed_prefix_count,
    )
    if chain.target_sequence is None:
        if proof is not None:
            raise StateConflictError(
                "deploy Scylla later-join authorization is not required "
                "and accepts no proof"
            )
        _refuse_not_required_artifacts(
            paths,
            operation_id,
            completed_sequence=chain.completed_prefix_count,
        )
        return _not_required_report(chain)
    if proof is None:
        raise StateConflictError("later-join authorization proof is required")
    store = DeployScyllaLaterJoinAuthorizationStore(
        paths, operation_id, chain.target_sequence
    )
    validate_state_file(store.path, allow_missing=True)
    loaded = _load_later_join_authorization_context(
        paths, operation_id, lock=lock, chain=chain
    )
    scope = _derive_later_join_scope(loaded)
    decision = _normalize_proof(proof, loaded=loaded, scope=scope)
    if store.path.exists():
        stored = store.read_locked(
            lock,
            expected_cluster_uuid=chain.cluster_uuid,
            expected_cluster_name=chain.cluster_name,
        )
        expected = _build_authorization(
            loaded,
            scope=scope,
            proof=decision,
            created_at=stored.record.created_at,
        )
        if stored.record != expected:
            raise StateConflictError(
                "later-join authorization changed; re-plan with a new operation"
            )
        state = DeployScyllaLaterJoinAuthorizationArtifactState.REUSED
    else:
        record = _build_authorization(
            loaded,
            scope=scope,
            proof=decision,
            created_at=format_timestamp(datetime.now(UTC)),
        )
        try:
            stored, state = store.write_locked(record, lock=lock)
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "later-join authorization persistence failed"
            ) from error
    return _build_report(stored, state=state)


def deploy_scylla_later_join_authorization_path(
    paths: StatePaths, operation_id: uuid.UUID, sequence: int
) -> Path:
    _require_canonical_paths(paths)
    path = paths.operations / (
        f"{_require_operation_id(operation_id)}"
        f"{_LATER_JOIN_FILENAME_STEM}{_require_later_sequence(sequence)}"
        f"{DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError("later-join authorization path is not canonical")
    return path


def deploy_scylla_later_join_authorization_id_from_filename(
    name: str,
) -> tuple[uuid.UUID, int] | None:
    suffix = DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_FILENAME_SUFFIX
    if not name.endswith(suffix) or _LATER_JOIN_FILENAME_STEM not in name:
        return None
    prefix, sequence_value = name[: -len(suffix)].split(_LATER_JOIN_FILENAME_STEM, 1)
    try:
        operation_id = uuid.UUID(prefix)
        sequence = int(sequence_value)
    except ValueError:
        return None
    if (
        str(operation_id) != prefix
        or str(sequence) != sequence_value
        or sequence < _MINIMUM_SEQUENCE
    ):
        return None
    return operation_id, sequence


def _load_later_join_authorization_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
    chain: _LaterJoinSafetyLoaded | None = None,
    expected_sequence: int | None = None,
) -> _LaterJoinAuthorizationLoaded:
    current = (
        _load_later_join_safety(
            paths,
            operation_id,
            lock=lock,
            latest_completed_sequence=(
                None
                if expected_sequence is None
                else _require_later_sequence(expected_sequence) - 1
            ),
        )
        if chain is None
        else chain
    )
    if current.target_sequence is None:
        raise StateConflictError("later-join authorization is not required")
    sequence = current.target_sequence
    if expected_sequence is not None and sequence != expected_sequence:
        raise StateConflictError(
            "later-join authorization sequence does not match canonical history"
        )
    context_store = DeployScyllaLaterJoinSafetyContextStore(
        paths, operation_id, sequence
    )
    evidence_store = DeployScyllaLaterJoinSafetyEvidenceStore(
        paths, operation_id, sequence
    )
    reconciliation_store = DeployScyllaLaterJoinSafetyReconciliationStore(
        paths, operation_id, sequence
    )
    for path, label in (
        (context_store.path, "later-join safety context"),
        (evidence_store.path, "later-join safety evidence"),
        (reconciliation_store.path, "later-join safety reconciliation"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(f"later-join authorization requires exact {label}")
    context = context_store.read_locked(
        lock,
        expected_cluster_uuid=current.cluster_uuid,
        expected_cluster_name=current.cluster_name,
    )
    evidence = evidence_store.read_locked(
        lock,
        expected_cluster_uuid=current.cluster_uuid,
        expected_cluster_name=current.cluster_name,
    )
    reconciliation = reconciliation_store.read_locked(
        lock,
        expected_cluster_uuid=current.cluster_uuid,
        expected_cluster_name=current.cluster_name,
    )
    proofs = evidence.record.proofs
    _validate_safety_proofs(proofs, current)
    expected_context = _build_safety_context(
        current, proofs, created_at=context.record.created_at
    )
    if context.record != expected_context:
        raise StateConflictError(
            "later-join safety context drifted; use a new operation"
        )
    expected_evidence = _build_safety_evidence(
        current,
        context,
        proofs,
        created_at=evidence.record.created_at,
    )
    if evidence.record != expected_evidence:
        raise StateConflictError(
            "later-join safety evidence drifted; use a new operation"
        )
    expected_reconciliation = _build_safety_reconciliation(
        current,
        context,
        evidence,
        created_at=reconciliation.record.created_at,
    )
    if reconciliation.record != expected_reconciliation:
        raise StateConflictError(
            "later-join safety reconciliation drifted; use a new operation"
        )
    gates = evidence.record.gates
    target_sequence = current.target_sequence
    if (
        target_sequence is None
        or target_sequence < _MINIMUM_SEQUENCE
        or context.record.target_sequence != target_sequence
        or context.record.completed_prefix_count != current.completed_prefix_count
        or context.record.journal_generation != current.journal_generation
        or context.record.journal_digest != current.journal_digest
        or evidence.record.context_artifact_digest != context.artifact_digest
        or evidence.record.context_digest != context.record.context_digest
        or reconciliation.record.context_artifact_digest != context.artifact_digest
        or reconciliation.record.context_digest != context.record.context_digest
        or reconciliation.record.evidence_artifact_digest != evidence.artifact_digest
        or reconciliation.record.evidence_digest != evidence.record.evidence_digest
        or not evidence.record.ready_for_authorization
        or evidence.record.authorization_state != _AUTHORIZATION_REQUIRED
        or evidence.record.blockers
        or evidence.record.passed_count != evidence.record.gate_count
        or evidence.record.failed_count
        or evidence.record.unknown_count
        or evidence.record.not_applicable_count
        or any(
            gate.status is not DeployScyllaJoinSafetyProofStatus.PASSED
            for gate in gates
        )
        or reconciliation.record.authorization_required_count != 1
        or reconciliation.record.blocked_count
        or reconciliation.record.completed_prefix_count
        != current.completed_prefix_count
        or reconciliation.record.target_sequence != target_sequence
        or reconciliation.record.target_status != _AUTHORIZATION_REQUIRED
        or reconciliation.record.authorization_state != _AUTHORIZATION_NOT_CREATED
        or reconciliation.record.execution_state != _EXECUTION_UNAVAILABLE
        or reconciliation.record.journal_generation != current.journal_generation
        or reconciliation.record.journal_digest != current.journal_digest
    ):
        raise StateConflictError(
            "later join is not exactly reconciled for authorization"
        )
    return _LaterJoinAuthorizationLoaded(
        chain=current,
        safety_context=context,
        safety_evidence=evidence,
        safety_reconciliation=reconciliation,
    )


def _derive_later_join_scope(
    loaded: _LaterJoinAuthorizationLoaded,
) -> DeployScyllaLaterJoinAuthorizationScope:
    definition = get_playbook(_PLAYBOOK)
    chain = loaded.chain
    context = loaded.safety_context.record
    evidence = loaded.safety_evidence.record
    reconciliation = loaded.safety_reconciliation.record
    sequence = reconciliation.target_sequence
    if (
        definition.classification is not OperationClassification.SENSITIVE
        or definition.check_mode is not CheckMode.REFUSED
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.serial != 1
        or not definition.any_errors_fatal
        or not definition.source_available
        or sequence < _MINIMUM_SEQUENCE
        or sequence != chain.target_sequence
        or len(chain.plan_steps) != len(reconciliation.steps)
        or sequence > len(chain.plan_steps)
    ):
        raise StateConflictError("later-join catalog or reconciled scope conflicts")
    target = chain.plan_steps[sequence - 1]
    safety_target = reconciliation.steps[sequence - 1]
    later = reconciliation.steps[sequence:]
    gates = {gate.name: gate for gate in evidence.gates}
    if any(name not in gates for name in (*_EXTERNAL_GATES, "streaming")):
        raise StateConflictError("later-join safety gates conflict")
    if (
        target.sequence != sequence
        or target.mode is not ScyllaBootstrapMode.JOIN_EXISTING
        or safety_target.sequence != sequence
        or safety_target.mode is not target.mode
        or safety_target.target_digest != target.target_digest
        or safety_target.plan_step_digest != target.step_digest
        or safety_target.status
        is not DeployScyllaLaterJoinSafetyStepStatus.AUTHORIZATION_REQUIRED
        or safety_target.authorization_state != _AUTHORIZATION_REQUIRED
        or safety_target.blockers != ("join-authorization-not-collected",)
        or context.target_sequence != sequence
        or context.target_digest != target.target_digest
        or context.target_plan_step_digest != target.step_digest
        or context.target_topology_digest != target.topology_digest
        or context.target_storage_evidence_digest != target.storage_evidence_digest
        or context.target_configuration_evidence_digest
        != target.configuration_evidence_digest
        or context.target_capacity_evidence_digest != target.capacity_evidence_digest
        or context.target_package_version_digest != target.package_version_digest
        or context.playbook_source_digest != target.playbook_source_digest
        or context.completed_prefix_count != sequence - 1
        or context.completed_prefix_digest != chain.completed_prefix_digest
        or context.survivor_count != sequence - 1
        or context.survivor_set_digest != chain.survivor_set_digest
        or context.survivor_health_digest != chain.survivor_health_digest
        or context.active_seed_count != 1
        or context.active_seed_set_digest != chain.active_seed_set_digest
        or context.current_topology_digest != chain.current_topology_digest
        or context.current_schema_digest != chain.current_schema_digest
        or context.current_membership_digest != chain.current_membership_digest
        or context.current_host_mapping_digest != chain.current_host_mapping_digest
        or context.current_state_digest != chain.current_state_digest
        or context.validated_chain_digest != chain.validated_chain_digest
        or any(
            step.status is not DeployScyllaLaterJoinSafetyStepStatus.HEALTH_SUCCEEDED
            or step.authorization_state != "not-required"
            or step.blockers
            for step in reconciliation.steps[: sequence - 1]
        )
        or any(
            step.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or step.status is not DeployScyllaLaterJoinSafetyStepStatus.WAITING
            or step.authorization_state != _WAITING
            or step.blockers != ("preceding-join-not-completed",)
            for step in later
        )
        or any(
            gate.status is not DeployScyllaJoinSafetyProofStatus.PASSED
            for gate in gates.values()
        )
    ):
        raise StateConflictError(
            "only the exact reconciled first unfinished later join may be authorized"
        )
    order_digest = _digest_object(
        {
            "completed_prefix_digest": context.completed_prefix_digest,
            "sequence": sequence,
            "target_plan_step_digest": target.step_digest,
        }
    )
    values: dict[str, object] = {
        "sequence": sequence,
        "mode": target.mode,
        "classification": OperationClassification.SENSITIVE,
        "confirmation_policy": ConfirmationPolicy.SENSITIVE,
        "target_count": 1,
        "target_digest": target.target_digest,
        "bootstrap_plan_step_digest": target.step_digest,
        "latest_health_step_digest": safety_target.latest_health_step_digest,
        "safety_step_digest": safety_target.step_digest,
        "completed_prefix_count": context.completed_prefix_count,
        "completed_prefix_digest": context.completed_prefix_digest,
        "order_digest": order_digest,
        "survivor_count": context.survivor_count,
        "survivor_set_digest": context.survivor_set_digest,
        "survivor_health_digest": context.survivor_health_digest,
        "active_seed_count": context.active_seed_count,
        "active_seed_set_digest": context.active_seed_set_digest,
        "topology_digest": context.current_topology_digest,
        "target_topology_digest": target.topology_digest,
        "schema_digest": context.current_schema_digest,
        "membership_digest": context.current_membership_digest,
        "host_mapping_digest": context.current_host_mapping_digest,
        "streaming_gate_digest": gates["streaming"].gate_digest,
        "seed_policy_digest": target.seed_policy_digest,
        "package_version_digest": target.package_version_digest,
        "storage_evidence_digest": target.storage_evidence_digest,
        "configuration_evidence_digest": target.configuration_evidence_digest,
        "target_capacity_evidence_digest": target.capacity_evidence_digest,
        "backup_policy_evidence_digest": gates["backup-policy"].evidence_digest,
        "capacity_policy_evidence_digest": gates["capacity"].evidence_digest,
        "quorum_evidence_digest": gates["quorum"].evidence_digest,
        "replication_evidence_digest": gates["replication"].evidence_digest,
        "playbook_source_digest": target.playbook_source_digest,
        "safety_context_digest": context.context_digest,
        "safety_evidence_digest": evidence.evidence_digest,
        "safety_reconciliation_digest": reconciliation.reconciliation_digest,
        "safety_proof_set_digest": evidence.proof_set_digest,
        "safety_gate_set_digest": _digest_object(
            [gate.gate_digest for gate in evidence.gates]
        ),
        "scope_digest": "",
    }
    values["scope_digest"] = _scope_digest_from_values(values)
    return DeployScyllaLaterJoinAuthorizationScope(
        **values  # type: ignore[arg-type]
    )


def _normalize_proof(
    proof: DeployScyllaLaterJoinAuthorizationProof,
    *,
    loaded: _LaterJoinAuthorizationLoaded,
    scope: DeployScyllaLaterJoinAuthorizationScope,
) -> DeployScyllaLaterJoinProofDecision:
    if proof.approval_method is None:
        raise StateConflictError("ordinary later-join approval is required")
    if not proof.approved:
        raise StateConflictError("ordinary later-join approval was denied")
    if proof.allow_destructive or proof.destructive_scope_provided:
        raise StateConflictError(
            "destructive proof is inapplicable to sensitive later join"
        )
    if proof.narrow_approval_method is None or not proof.narrow_approved:
        raise StateConflictError(
            "exact later-join target/mode/sequence/scope approval is required; "
            "cli-yes alone is insufficient"
        )
    expected_scope = DeployScyllaLaterJoinNarrowScopeProof.from_scope(scope)
    if proof.narrow_scope != expected_scope:
        raise StateConflictError(
            "later-join target/mode/sequence/scope approval does not match "
            "the exact reconciled plan"
        )
    values: dict[str, object] = {
        "approval_method": proof.approval_method,
        "approval_state": _APPROVED,
        "narrow_approval_method": proof.narrow_approval_method,
        "narrow_approval_state": _MATCHED,
        "sequence": expected_scope.sequence,
        "target_count": expected_scope.target_count,
        "target_digest": expected_scope.target_digest,
        "mode": expected_scope.mode,
        "bootstrap_plan_step_digest": expected_scope.bootstrap_plan_step_digest,
        "safety_step_digest": expected_scope.safety_step_digest,
        "authorization_scope_digest": expected_scope.authorization_scope_digest,
        "allow_destructive": False,
        "destructive_scope_provided": False,
        "proof_digest": "",
    }
    values["proof_digest"] = _proof_digest_values(
        cluster_uuid=loaded.chain.cluster_uuid,
        operation_id=loaded.chain.operation_id,
        journal_digest=loaded.chain.journal_digest,
        safety_context_artifact_digest=loaded.safety_context.artifact_digest,
        safety_evidence_artifact_digest=loaded.safety_evidence.artifact_digest,
        safety_reconciliation_artifact_digest=(
            loaded.safety_reconciliation.artifact_digest
        ),
        scope_digest=scope.scope_digest,
        proof=values,
    )
    return DeployScyllaLaterJoinProofDecision(**values)  # type: ignore[arg-type]


def _build_authorization(
    loaded: _LaterJoinAuthorizationLoaded,
    *,
    scope: DeployScyllaLaterJoinAuthorizationScope,
    proof: DeployScyllaLaterJoinProofDecision,
    created_at: str,
) -> DeployScyllaLaterJoinAuthorization:
    chain = loaded.chain
    context = loaded.safety_context.record
    evidence = loaded.safety_evidence.record
    reconciliation = loaded.safety_reconciliation.record
    later = reconciliation.steps[scope.sequence :]
    later_values = [
        {
            "authorization_state": step.authorization_state,
            "mode": step.mode.value,
            "sequence": step.sequence,
            "status": step.status.value,
            "step_digest": step.step_digest,
            "target_digest": step.target_digest,
        }
        for step in later
    ]
    later_digest = _digest_object(later_values)
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": chain.cluster_uuid,
        "cluster_identity_digest": _cluster_identity_digest(
            chain.cluster_uuid, chain.cluster_name
        ),
        "operation_id": chain.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "scope_kind": _SCOPE_KIND,
        "request_digest": chain.request_digest,
        "journal_generation": chain.journal_generation,
        "journal_digest": chain.journal_digest,
        "journal_status": chain.journal_status,
        "journal_phase": chain.journal_phase,
        "bootstrap_context_artifact_digest": (
            chain.base_chain.bootstrap_context_artifact_digest
        ),
        "bootstrap_context_record_digest": (
            chain.base_chain.bootstrap_context_record_digest
        ),
        "bootstrap_plan_artifact_digest": (
            chain.base_chain.bootstrap_plan_artifact_digest
        ),
        "bootstrap_plan_digest": chain.base_chain.bootstrap_plan_digest,
        "latest_health_execution_artifact_digest": (
            chain.latest_health_execution.artifact_digest
        ),
        "latest_health_evidence_artifact_digest": (
            chain.latest_health_evidence.artifact_digest
        ),
        "latest_health_evidence_digest": (
            chain.latest_health_evidence.record.evidence_digest
        ),
        "latest_health_reconciliation_artifact_digest": (
            chain.latest_health_reconciliation.artifact_digest
        ),
        "latest_health_reconciliation_digest": (
            chain.latest_health_reconciliation.record.reconciliation_digest
        ),
        "safety_context_artifact_digest": loaded.safety_context.artifact_digest,
        "safety_context_digest": context.context_digest,
        "safety_evidence_artifact_digest": loaded.safety_evidence.artifact_digest,
        "safety_evidence_digest": evidence.evidence_digest,
        "safety_reconciliation_artifact_digest": (
            loaded.safety_reconciliation.artifact_digest
        ),
        "safety_reconciliation_digest": reconciliation.reconciliation_digest,
        "completed_prefix_count": chain.completed_prefix_count,
        "completed_prefix_digest": chain.completed_prefix_digest,
        "current_state_digest": chain.current_state_digest,
        "validated_chain_digest": chain.validated_chain_digest,
        "classification": OperationClassification.SENSITIVE,
        "confirmation_policy": ConfirmationPolicy.SENSITIVE,
        "scope": scope,
        "authorization_scope_digest": scope.scope_digest,
        "later_join_count": len(later),
        "later_join_digest": later_digest,
        "non_authorized_scope_digest": _digest_object(
            {
                "completed_prefix_count": chain.completed_prefix_count,
                "completed_prefix_digest": chain.completed_prefix_digest,
                "later_join_count": len(later),
                "later_join_digest": later_digest,
                "plan_step_count": len(chain.plan_steps),
            }
        ),
        "proof": proof,
        "authorization_state": _AUTHORIZED,
        "consumed": False,
        "execution_state": _EXECUTION_UNAVAILABLE,
        "finalization_state": _FINALIZATION_NOT_STARTED,
        "public_workflow_state": _PUBLIC_WORKFLOW_UNAVAILABLE,
        "authorization_digest": "",
    }
    values["authorization_digest"] = _authorization_digest_from_values(values)
    return DeployScyllaLaterJoinAuthorization(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployScyllaLaterJoinAuthorization,
    *,
    state: DeployScyllaLaterJoinAuthorizationArtifactState,
) -> DeployScyllaLaterJoinAuthorizationReport:
    record = stored.record
    scope = record.scope
    return DeployScyllaLaterJoinAuthorizationReport(
        operation_id=record.operation_id,
        required=True,
        state="required",
        completed_prefix_count=scope.completed_prefix_count,
        survivor_count=scope.survivor_count,
        active_seed_count=scope.active_seed_count,
        later_join_count=record.later_join_count,
        authorization_state=record.authorization_state,
        execution_state=record.execution_state,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        journal_digest=record.journal_digest,
        artifact_state=state,
        authorization_artifact_digest=stored.artifact_digest,
        authorization_digest=record.authorization_digest,
        classification=record.classification,
        confirmation_policy=record.confirmation_policy,
        approval_method=record.proof.approval_method,
        narrow_approval_method=record.proof.narrow_approval_method,
        proof_digest=record.proof.proof_digest,
        sequence=scope.sequence,
        mode=scope.mode,
        target_count=scope.target_count,
        target_digest=scope.target_digest,
        authorization_scope_digest=scope.scope_digest,
        safety_context_digest=scope.safety_context_digest,
        safety_evidence_digest=scope.safety_evidence_digest,
        safety_reconciliation_digest=scope.safety_reconciliation_digest,
        safety_gate_set_digest=scope.safety_gate_set_digest,
        validated_chain_digest=record.validated_chain_digest,
        later_join_digest=record.later_join_digest,
        consumed=record.consumed,
        public_workflow_state=record.public_workflow_state,
    )


def _not_required_report(
    chain: _LaterJoinSafetyLoaded,
) -> DeployScyllaLaterJoinAuthorizationReport:
    return DeployScyllaLaterJoinAuthorizationReport(
        operation_id=chain.operation_id,
        required=False,
        state="not-required",
        completed_prefix_count=chain.completed_prefix_count,
        survivor_count=len(chain.survivor_ids),
        active_seed_count=1,
        later_join_count=0,
        authorization_state="not-required",
        execution_state="not-required",
        journal_status=chain.journal_status,
        journal_phase=chain.journal_phase,
        journal_digest=chain.journal_digest,
    )


def _scope_digest(scope: DeployScyllaLaterJoinAuthorizationScope) -> str:
    return _scope_digest_from_values(scope.to_object())


def _scope_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    value["scope_digest"] = ""
    return _digest_object(value)


def _proof_digest(
    record: DeployScyllaLaterJoinAuthorization,
    proof: Mapping[str, object],
) -> str:
    return _proof_digest_values(
        cluster_uuid=record.cluster_uuid,
        operation_id=record.operation_id,
        journal_digest=record.journal_digest,
        safety_context_artifact_digest=record.safety_context_artifact_digest,
        safety_evidence_artifact_digest=record.safety_evidence_artifact_digest,
        safety_reconciliation_artifact_digest=(
            record.safety_reconciliation_artifact_digest
        ),
        scope_digest=record.authorization_scope_digest,
        proof=proof,
    )


def _proof_digest_values(
    *,
    cluster_uuid: uuid.UUID,
    operation_id: uuid.UUID,
    journal_digest: str,
    safety_context_artifact_digest: str,
    safety_evidence_artifact_digest: str,
    safety_reconciliation_artifact_digest: str,
    scope_digest: str,
    proof: Mapping[str, object],
) -> str:
    proof_value = _json_object(proof)
    proof_value.setdefault(
        "schema_version",
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION,
    )
    proof_value["proof_digest"] = ""
    return _digest_object(
        {
            "authorization_scope_digest": scope_digest,
            "cluster_uuid": str(cluster_uuid),
            "journal_digest": journal_digest,
            "operation": _OPERATION,
            "operation_id": str(operation_id),
            "proof": proof_value,
            "safety_context_artifact_digest": safety_context_artifact_digest,
            "safety_evidence_artifact_digest": safety_evidence_artifact_digest,
            "safety_reconciliation_artifact_digest": (
                safety_reconciliation_artifact_digest
            ),
            "stage": _STAGE,
        }
    )


def _authorization_digest(record: DeployScyllaLaterJoinAuthorization) -> str:
    return _authorization_digest_from_values(record.to_object())


def _authorization_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for name, field in DeployScyllaLaterJoinAuthorization.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["authorization_digest"] = ""
    return _digest_object(value)


def _refuse_not_required_artifacts(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    completed_sequence: int,
) -> None:
    parsers = (
        deploy_scylla_later_join_authorization_id_from_filename,
        deploy_scylla_later_join_safety_context_id_from_filename,
        deploy_scylla_later_join_safety_evidence_id_from_filename,
        deploy_scylla_later_join_safety_reconciliation_id_from_filename,
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list later-join authorization artifacts"
        ) from error
    for entry in entries:
        for parser in parsers:
            parsed = parser(entry.name)
            if (
                parsed is not None
                and parsed[0] == operation_id
                and parsed[1] > completed_sequence
            ):
                validate_state_file(entry)
                raise StateConflictError(
                    "later-join authorization artifacts conflict with completed plan"
                )


def _require_later_sequence(sequence: int) -> int:
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < _MINIMUM_SEQUENCE
    ):
        raise StatePersistenceError("later-join sequence is not canonical")
    return sequence


def _refuse_incompatible_or_later_artifacts(
    paths: StatePaths,
    operation_id: uuid.UUID,
    sequence: int | None,
    *,
    completed_sequence: int,
) -> None:
    generic = (
        paths.operations / f"{operation_id}{OPERATION_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    validate_state_file(generic, allow_missing=True)
    if generic.exists():
        raise StateConflictError(
            "generic Ansible authorization is incompatible with deploy VERIFY binding"
        )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list later-join authorization history"
        ) from error
    prefix = str(operation_id)
    for entry in entries:
        if entry.name.startswith(prefix) and _is_later_execution_history(entry.name):
            artifact_sequence = _later_artifact_sequence(entry.name)
            conflicts = artifact_sequence is None or (
                artifact_sequence > completed_sequence
                if sequence is None
                else artifact_sequence >= sequence
            )
            if conflicts:
                validate_state_file(entry)
                raise StateConflictError(
                    "later-join authorization refuses execution or later "
                    "membership history"
                )


def _later_artifact_sequence(name: str) -> int | None:
    marker = "-sequence-"
    if marker not in name:
        return None
    value = name.split(marker, 1)[1].split("-", 1)[0]
    try:
        sequence = int(value)
    except ValueError:
        return None
    return sequence if sequence >= _MINIMUM_SEQUENCE else None


def _is_later_execution_history(name: str) -> bool:
    return (
        _LATER_JOIN_FILENAME_STEM in name
        and "-safety-" not in name
        and (name.endswith("-execution.json") or name.endswith("-evidence.json"))
    ) or ".ansible-deploy-scylla-post-later-join-sequence-" in name


def _refuse_ambiguous_authorization_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list later-join authorization artifacts"
        ) from error
    for entry in entries:
        if not entry.name.endswith(
            DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_FILENAME_SUFFIX
        ):
            continue
        parsed = deploy_scylla_later_join_authorization_id_from_filename(entry.name)
        if (
            parsed is None
            and entry.name.startswith(str(operation_id))
            and _LATER_JOIN_NAMESPACE_STEM in entry.name
        ):
            validate_state_file(entry)
            raise StateConflictError("later-join authorization artifacts are ambiguous")


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError("later-join authorization paths are not canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "later-join authorization requires the matching held deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


__all__ = [
    "ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_SCHEMA_VERSION",
    "DEPLOY_SCYLLA_LATER_JOIN_AUTHORIZATION_FILENAME_SUFFIX",
    "DeployScyllaLaterJoinAuthorization",
    "DeployScyllaLaterJoinAuthorizationArtifactState",
    "DeployScyllaLaterJoinAuthorizationProof",
    "DeployScyllaLaterJoinAuthorizationReport",
    "DeployScyllaLaterJoinAuthorizationScope",
    "DeployScyllaLaterJoinAuthorizationStore",
    "DeployScyllaLaterJoinNarrowScopeProof",
    "DeployScyllaLaterJoinProofDecision",
    "StoredDeployScyllaLaterJoinAuthorization",
    "authorize_deploy_scylla_later_join",
    "deploy_scylla_later_join_authorization_id_from_filename",
    "deploy_scylla_later_join_authorization_path",
]
