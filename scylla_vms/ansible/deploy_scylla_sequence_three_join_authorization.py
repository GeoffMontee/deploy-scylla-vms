"""Sensitive authorization for only the reconciled sequence-three deploy join.

This internal, subprocess-free owner reloads and reproduces the complete
sequence-three safety chain, derives the one exact ``join-existing`` scope, and
persists an immutable unconsumed authorization.  It accepts no caller-selected
target or execution input and does not change the common journal.
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
from scylla_vms.ansible.deploy_scylla_sequence_three_join_safety import (
    _REQUIRED_GATES,
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_RECONCILIATION_SCHEMA_VERSION,
    DeployScyllaSequenceThreeSafetyContext,
    DeployScyllaSequenceThreeSafetyContextStore,
    DeployScyllaSequenceThreeSafetyEvidence,
    DeployScyllaSequenceThreeSafetyEvidenceStore,
    DeployScyllaSequenceThreeSafetyReconciliation,
    DeployScyllaSequenceThreeSafetyReconciliationStore,
    DeployScyllaSequenceThreeSafetyStepStatus,
    StoredDeployScyllaSequenceThreeSafetyArtifact,
    _load_sequence_three_safety,
    _SequenceThreeSafetyLoaded,
    _validate_proofs,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_safety import (
    _build_context as _build_safety_context,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_safety import (
    _build_evidence as _build_safety_evidence,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_safety import (
    _build_reconciliation as _build_safety_reconciliation,
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

ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-sequence-three-join-authorization-proof/v1"
)
ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-sequence-three-join-authorization/v1"
)
ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-sequence-three-join-"
    "authorization-report/v1"
)
DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-sequence-three-join-authorization.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "scylla-bootstrap"
_STAGE = "sequence-three-join-authorization"
_SCOPE_KIND = "reconciled-sequence-three-join-existing"
_TARGET_SEQUENCE = 3
_CURRENT_MEMBER_COUNT = 2
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


class DeployScyllaSequenceThreeJoinAuthorizationArtifactState(StrEnum):
    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployScyllaSequenceThreeJoinScope:
    """Redacted exact scope for the immediate sequence-three join."""

    sequence: int
    mode: ScyllaBootstrapMode
    classification: OperationClassification
    confirmation_policy: ConfirmationPolicy
    target_count: int
    target_digest: str
    bootstrap_plan_step_digest: str
    post_join_health_step_digest: str
    safety_step_digest: str
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
            self.sequence != _TARGET_SEQUENCE
            or self.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or self.classification is not OperationClassification.SENSITIVE
            or self.confirmation_policy is not ConfirmationPolicy.SENSITIVE
            or self.target_count != 1
            or self.survivor_count != _CURRENT_MEMBER_COUNT
            or self.active_seed_count != 1
            or self.scope_digest != _scope_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla sequence-three join authorization scope conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(
                value, "deploy Scylla sequence-three join authorization scope digest"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaSequenceThreeJoinScope:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={
                "sequence",
                "target_count",
                "survivor_count",
                "active_seed_count",
            },
            enum_fields={
                "mode": ScyllaBootstrapMode,
                "classification": OperationClassification,
                "confirmation_policy": ConfirmationPolicy,
            },
            label="sequence-three join authorization scope",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaSequenceThreeJoinNarrowScopeProof:
    """Exact digest-only sequence-three target/mode/scope acknowledgement."""

    sequence: int
    target_count: int
    target_digest: str
    mode: ScyllaBootstrapMode
    bootstrap_plan_step_digest: str
    safety_step_digest: str
    authorization_scope_digest: str

    def __post_init__(self) -> None:
        if (
            self.sequence != _TARGET_SEQUENCE
            or self.target_count != 1
            or self.mode is not ScyllaBootstrapMode.JOIN_EXISTING
        ):
            raise StateConflictError(
                "sequence-three narrow proof must bind one join-existing target"
            )
        for value in _digest_fields(self):
            validate_digest(value, "sequence-three join narrow proof digest")

    @classmethod
    def from_scope(
        cls, scope: DeployScyllaSequenceThreeJoinScope
    ) -> DeployScyllaSequenceThreeJoinNarrowScopeProof:
        if not isinstance(scope, DeployScyllaSequenceThreeJoinScope):
            raise StateConflictError("sequence-three join scope is malformed")
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
class DeployScyllaSequenceThreeJoinAuthorizationProof:
    """Already-normalized ordinary and exact narrow approval facts."""

    approval_method: DeployScyllaJoinApprovalMethod | None = None
    approved: bool = False
    narrow_approval_method: DeployScyllaJoinNarrowApprovalMethod | None = None
    narrow_approved: bool = False
    narrow_scope: DeployScyllaSequenceThreeJoinNarrowScopeProof | None = None
    allow_destructive: bool = False
    destructive_scope_provided: bool = False

    def __post_init__(self) -> None:
        if self.approval_method is not None and not isinstance(
            self.approval_method, DeployScyllaJoinApprovalMethod
        ):
            raise StateConflictError("sequence-three join approval method is invalid")
        if self.narrow_approval_method is not None and not isinstance(
            self.narrow_approval_method, DeployScyllaJoinNarrowApprovalMethod
        ):
            raise StateConflictError(
                "sequence-three join narrow approval method is invalid"
            )
        if self.narrow_scope is not None and not isinstance(
            self.narrow_scope, DeployScyllaSequenceThreeJoinNarrowScopeProof
        ):
            raise StateConflictError("sequence-three join narrow proof is malformed")
        if not all(
            isinstance(item, bool)
            for item in (
                self.approved,
                self.narrow_approved,
                self.allow_destructive,
                self.destructive_scope_provided,
            )
        ):
            raise StateConflictError(
                "sequence-three join authorization proof is malformed"
            )


@dataclass(frozen=True, slots=True)
class DeployScyllaSequenceThreeJoinProofDecision:
    """Persisted approval decision bound to the exact sequence-three scope."""

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
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or self.approval_state != _APPROVED
            or self.narrow_approval_state != _MATCHED
            or self.sequence != _TARGET_SEQUENCE
            or self.target_count != 1
            or self.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or self.allow_destructive
            or self.destructive_scope_provided
        ):
            raise StatePersistenceError("sequence-three join proof decision conflicts")
        for value in _digest_fields(self):
            validate_digest(value, "sequence-three join proof decision digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaSequenceThreeJoinProofDecision:
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
            label="sequence-three join authorization proof",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaSequenceThreeJoinAuthorization:
    """Immutable unconsumed authorization for only sequence three."""

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
    first_join_authorization_artifact_digest: str
    first_join_authorization_digest: str
    first_join_execution_artifact_digest: str
    first_join_execution_binding_digest: str
    first_join_evidence_artifact_digest: str
    first_join_evidence_digest: str
    post_join_health_execution_artifact_digest: str
    post_join_health_evidence_artifact_digest: str
    post_join_health_evidence_digest: str
    post_join_health_reconciliation_artifact_digest: str
    post_join_health_reconciliation_digest: str
    safety_context_artifact_digest: str
    safety_context_digest: str
    safety_evidence_artifact_digest: str
    safety_evidence_digest: str
    safety_reconciliation_artifact_digest: str
    safety_reconciliation_digest: str
    current_state_digest: str
    validated_chain_digest: str
    classification: OperationClassification
    confirmation_policy: ConfirmationPolicy
    scope: DeployScyllaSequenceThreeJoinScope
    authorization_scope_digest: str
    later_join_count: int
    later_join_digest: str
    non_authorized_scope_digest: str
    proof: DeployScyllaSequenceThreeJoinProofDecision
    authorization_state: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_digest: str
    safety_context_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_SCHEMA_VERSION
    )
    safety_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_EVIDENCE_SCHEMA_VERSION
    )
    safety_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_RECONCILIATION_SCHEMA_VERSION
    )
    proof_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_SCHEMA_VERSION
            or self.safety_context_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_SCHEMA_VERSION
            or self.safety_evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_EVIDENCE_SCHEMA_VERSION
            or self.safety_reconciliation_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_RECONCILIATION_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION
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
            or not isinstance(self.scope, DeployScyllaSequenceThreeJoinScope)
            or not isinstance(self.proof, DeployScyllaSequenceThreeJoinProofDecision)
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
                "sequence-three join authorization identity, scope, or state conflicts"
            )
        parse_timestamp(self.created_at)
        _positive_integer(
            self.journal_generation, "sequence-three join authorization journal"
        )
        _nonnegative_integer(self.later_join_count, "later join count")
        for value in _digest_fields(self):
            validate_digest(value, "sequence-three join authorization digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, nested_fields={"scope", "proof"})

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaSequenceThreeJoinAuthorization:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={"generation", "journal_generation", "later_join_count"},
            uuid_fields={"cluster_uuid", "operation_id"},
            boolean_fields={"consumed"},
            enum_fields={
                "journal_status": JournalStatus,
                "journal_phase": OperationPhase,
                "classification": OperationClassification,
                "confirmation_policy": ConfirmationPolicy,
            },
            skip_fields={"scope", "proof"},
            label="sequence-three join authorization",
        )
        parsed["scope"] = DeployScyllaSequenceThreeJoinScope.from_object(
            _mapping(value["scope"], "sequence-three join scope")
        )
        parsed["proof"] = DeployScyllaSequenceThreeJoinProofDecision.from_object(
            _mapping(value["proof"], "sequence-three join proof")
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaSequenceThreeJoinAuthorization:
    record: DeployScyllaSequenceThreeJoinAuthorization
    artifact_digest: str


class DeployScyllaSequenceThreeJoinAuthorizationStore:
    """Owner-only immutable sequence-three join authorization store."""

    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        _require_canonical_paths(paths)
        self._paths = paths
        self._operation_id = _require_operation_id(operation_id)
        self._path = deploy_scylla_sequence_three_join_authorization_path(
            paths, operation_id
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
    ) -> StoredDeployScyllaSequenceThreeJoinAuthorization:
        value, artifact_digest = self._file.read()
        record = DeployScyllaSequenceThreeJoinAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_identity_digest
            != _cluster_identity_digest(expected_cluster_uuid, expected_cluster_name)
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "sequence-three join authorization identity conflicts"
            )
        return StoredDeployScyllaSequenceThreeJoinAuthorization(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaSequenceThreeJoinAuthorization:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaSequenceThreeJoinAuthorization,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployScyllaSequenceThreeJoinAuthorization,
        DeployScyllaSequenceThreeJoinAuthorizationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "sequence-three join authorization operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=self._paths.cluster_root.name,
            )
            if current.record != record:
                raise StateConflictError(
                    "sequence-three join authorization is immutable; "
                    "use a new operation"
                )
            return (
                current,
                DeployScyllaSequenceThreeJoinAuthorizationArtifactState.REUSED,
            )
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaSequenceThreeJoinAuthorization(record, artifact_digest),
            DeployScyllaSequenceThreeJoinAuthorizationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaSequenceThreeJoinAuthorizationReport:
    """Strict redacted authorization projection."""

    operation_id: uuid.UUID
    artifact_state: DeployScyllaSequenceThreeJoinAuthorizationArtifactState
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_state: str
    classification: OperationClassification
    confirmation_policy: ConfirmationPolicy
    approval_method: DeployScyllaJoinApprovalMethod
    approval_state: str
    narrow_approval_method: DeployScyllaJoinNarrowApprovalMethod
    narrow_approval_state: str
    proof_digest: str
    sequence: int
    mode: ScyllaBootstrapMode
    target_count: int
    target_digest: str
    survivor_count: int
    survivor_set_digest: str
    active_seed_count: int
    active_seed_set_digest: str
    authorization_scope_digest: str
    safety_context_digest: str
    safety_evidence_digest: str
    safety_reconciliation_digest: str
    safety_gate_set_digest: str
    validated_chain_digest: str
    later_join_count: int
    later_join_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    journal_digest: str
    consumed: bool
    execution_state: str
    public_workflow_state: str
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_REPORT_SCHEMA_VERSION
            or self.authorization_state != _AUTHORIZED
            or self.classification is not OperationClassification.SENSITIVE
            or self.confirmation_policy is not ConfirmationPolicy.SENSITIVE
            or self.approval_state != _APPROVED
            or self.narrow_approval_state != _MATCHED
            or self.sequence != _TARGET_SEQUENCE
            or self.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or self.target_count != 1
            or self.survivor_count != _CURRENT_MEMBER_COUNT
            or self.active_seed_count != 1
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError(
                "sequence-three join authorization report conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(value, "sequence-three join authorization report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "authorization": {
                "artifact_digest": self.authorization_artifact_digest,
                "consumed": self.consumed,
                "digest": self.authorization_digest,
                "state": self.authorization_state,
            },
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
            "later_joins": {
                "count": self.later_join_count,
                "digest": self.later_join_digest,
                "state": _WAITING,
            },
            "operation": {
                "classification": self.classification.value,
                "confirmation_policy": self.confirmation_policy.value,
                "id": str(self.operation_id),
                "kind": _OPERATION,
            },
            "proof": {
                "digest": self.proof_digest,
                "narrow_method": self.narrow_approval_method.value,
                "narrow_state": self.narrow_approval_state,
                "ordinary_method": self.approval_method.value,
                "ordinary_state": self.approval_state,
            },
            "provenance": {
                "safety_context_digest": self.safety_context_digest,
                "safety_evidence_digest": self.safety_evidence_digest,
                "safety_reconciliation_digest": self.safety_reconciliation_digest,
                "validated_chain_digest": self.validated_chain_digest,
            },
            "result": self.artifact_state.value,
            "schema_version": self.schema_version,
            "scope": {
                "active_seed_count": self.active_seed_count,
                "active_seed_set_digest": self.active_seed_set_digest,
                "authorization_scope_digest": self.authorization_scope_digest,
                "mode": self.mode.value,
                "safety_gate_set_digest": self.safety_gate_set_digest,
                "sequence": self.sequence,
                "survivor_count": self.survivor_count,
                "survivor_set_digest": self.survivor_set_digest,
                "target_count": self.target_count,
                "target_digest": self.target_digest,
            },
            "stage": _STAGE,
        }


@dataclass(frozen=True, slots=True)
class _SequenceThreeJoinAuthorizationLoaded:
    chain: _SequenceThreeSafetyLoaded
    safety_context: StoredDeployScyllaSequenceThreeSafetyArtifact[
        DeployScyllaSequenceThreeSafetyContext
    ]
    safety_evidence: StoredDeployScyllaSequenceThreeSafetyArtifact[
        DeployScyllaSequenceThreeSafetyEvidence
    ]
    safety_reconciliation: StoredDeployScyllaSequenceThreeSafetyArtifact[
        DeployScyllaSequenceThreeSafetyReconciliation
    ]


def authorize_deploy_scylla_sequence_three_join(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proof: DeployScyllaSequenceThreeJoinAuthorizationProof,
) -> DeployScyllaSequenceThreeJoinAuthorizationReport:
    """Authorize only exact reconciled sequence three without execution."""

    if not isinstance(proof, DeployScyllaSequenceThreeJoinAuthorizationProof):
        raise StateConflictError("sequence-three join authorization proof is malformed")
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_authorization_artifacts(paths, operation_id)
    _refuse_incompatible_or_later_artifacts(paths, operation_id)
    loaded = _load_sequence_three_join_authorization_context(
        paths, operation_id, lock=lock
    )
    scope = _derive_sequence_three_join_scope(loaded)
    decision = _normalize_proof(proof, loaded=loaded, scope=scope)
    store = DeployScyllaSequenceThreeJoinAuthorizationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    if store.path.exists():
        stored = store.read_locked(
            lock,
            expected_cluster_uuid=loaded.chain.cluster_uuid,
            expected_cluster_name=loaded.chain.cluster_name,
        )
        expected = _build_authorization(
            loaded,
            scope=scope,
            proof=decision,
            created_at=stored.record.created_at,
        )
        if stored.record != expected:
            raise StateConflictError(
                "sequence-three join authorization changed; "
                "re-plan with a new operation"
            )
        state = DeployScyllaSequenceThreeJoinAuthorizationArtifactState.REUSED
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
                "sequence-three join authorization persistence failed"
            ) from error
    return _build_report(stored, state=state)


def deploy_scylla_sequence_three_join_authorization_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    path = paths.operations / (
        f"{_require_operation_id(operation_id)}"
        f"{DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "sequence-three join authorization path is not canonical"
        )
    return path


def deploy_scylla_sequence_three_join_authorization_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    suffix = DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_FILENAME_SUFFIX
    if not name.endswith(suffix):
        return None
    value = name[: -len(suffix)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _load_sequence_three_join_authorization_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
) -> _SequenceThreeJoinAuthorizationLoaded:
    chain = _load_sequence_three_safety(paths, operation_id, lock=lock)
    context_store = DeployScyllaSequenceThreeSafetyContextStore(paths, operation_id)
    evidence_store = DeployScyllaSequenceThreeSafetyEvidenceStore(paths, operation_id)
    reconciliation_store = DeployScyllaSequenceThreeSafetyReconciliationStore(
        paths, operation_id
    )
    for path, label in (
        (context_store.path, "sequence-three safety context"),
        (evidence_store.path, "sequence-three safety evidence"),
        (reconciliation_store.path, "sequence-three safety reconciliation"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"sequence-three join authorization requires exact {label}"
            )
    context = context_store.read_locked(
        lock,
        expected_cluster_uuid=chain.cluster_uuid,
        expected_cluster_name=chain.cluster_name,
    )
    evidence = evidence_store.read_locked(
        lock,
        expected_cluster_uuid=chain.cluster_uuid,
        expected_cluster_name=chain.cluster_name,
    )
    reconciliation = reconciliation_store.read_locked(
        lock,
        expected_cluster_uuid=chain.cluster_uuid,
        expected_cluster_name=chain.cluster_name,
    )
    proofs = evidence.record.proofs
    _validate_proofs(proofs, chain)
    expected_context = _build_safety_context(
        chain, proofs, created_at=context.record.created_at
    )
    if context.record != expected_context:
        raise StateConflictError(
            "sequence-three safety context drifted; use a new operation"
        )
    expected_evidence = _build_safety_evidence(
        chain,
        context,
        proofs,
        created_at=evidence.record.created_at,
    )
    if evidence.record != expected_evidence:
        raise StateConflictError(
            "sequence-three safety evidence drifted; use a new operation"
        )
    expected_reconciliation = _build_safety_reconciliation(
        chain,
        context,
        evidence,
        created_at=reconciliation.record.created_at,
    )
    if reconciliation.record != expected_reconciliation:
        raise StateConflictError(
            "sequence-three safety reconciliation drifted; use a new operation"
        )
    gates = evidence.record.gates
    if (
        context.record.journal_generation != chain.journal_generation
        or context.record.journal_digest != chain.journal_digest
        or evidence.record.context_artifact_digest != context.artifact_digest
        or evidence.record.context_digest != context.record.context_digest
        or reconciliation.record.context_artifact_digest != context.artifact_digest
        or reconciliation.record.context_digest != context.record.context_digest
        or reconciliation.record.evidence_artifact_digest != evidence.artifact_digest
        or reconciliation.record.evidence_digest != evidence.record.evidence_digest
        or tuple(gate.name for gate in gates) != _REQUIRED_GATES
        or not evidence.record.ready_for_authorization
        or evidence.record.authorization_state != _AUTHORIZATION_REQUIRED
        or evidence.record.blockers
        or evidence.record.gate_count != len(_REQUIRED_GATES)
        or evidence.record.passed_count != len(_REQUIRED_GATES)
        or evidence.record.failed_count
        or evidence.record.unknown_count
        or evidence.record.not_applicable_count
        or any(
            gate.status is not DeployScyllaJoinSafetyProofStatus.PASSED
            for gate in gates
        )
        or reconciliation.record.authorization_required_count != 1
        or reconciliation.record.blocked_count
        or reconciliation.record.target_sequence != _TARGET_SEQUENCE
        or reconciliation.record.target_status != _AUTHORIZATION_REQUIRED
        or reconciliation.record.authorization_state != _AUTHORIZATION_NOT_CREATED
        or reconciliation.record.execution_state != _EXECUTION_UNAVAILABLE
        or reconciliation.record.journal_generation != chain.journal_generation
        or reconciliation.record.journal_digest != chain.journal_digest
    ):
        raise StateConflictError(
            "sequence three is not exactly reconciled for authorization"
        )
    return _SequenceThreeJoinAuthorizationLoaded(
        chain=chain,
        safety_context=context,
        safety_evidence=evidence,
        safety_reconciliation=reconciliation,
    )


def _derive_sequence_three_join_scope(
    loaded: _SequenceThreeJoinAuthorizationLoaded,
) -> DeployScyllaSequenceThreeJoinScope:
    definition = get_playbook(_PLAYBOOK)
    chain = loaded.chain
    context = loaded.safety_context.record
    evidence = loaded.safety_evidence.record
    reconciliation = loaded.safety_reconciliation.record
    plan_steps = chain.plan_steps
    health_steps = chain.health_steps
    safety_steps = reconciliation.steps
    if (
        definition.classification is not OperationClassification.SENSITIVE
        or definition.check_mode is not CheckMode.REFUSED
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.serial != 1
        or not definition.any_errors_fatal
        or not definition.source_available
        or len(plan_steps) < _TARGET_SEQUENCE
        or len(health_steps) != len(plan_steps)
        or len(safety_steps) != len(plan_steps)
    ):
        raise StateConflictError(
            "sequence-three join catalog or reconciled scope conflicts"
        )
    target = plan_steps[_TARGET_SEQUENCE - 1]
    health_target = health_steps[_TARGET_SEQUENCE - 1]
    safety_target = safety_steps[_TARGET_SEQUENCE - 1]
    later = safety_steps[_TARGET_SEQUENCE:]
    gates = {gate.name: gate for gate in evidence.gates}
    if set(gates) != set(_REQUIRED_GATES):
        raise StateConflictError("sequence-three join safety gates conflict")
    if (
        target.sequence != _TARGET_SEQUENCE
        or target.mode is not ScyllaBootstrapMode.JOIN_EXISTING
        or health_target.sequence != target.sequence
        or health_target.mode is not target.mode
        or health_target.target_digest != target.target_digest
        or health_target.plan_step_digest != target.step_digest
        or safety_target.sequence != target.sequence
        or safety_target.mode is not target.mode
        or safety_target.target_digest != target.target_digest
        or safety_target.plan_step_digest != target.step_digest
        or safety_target.health_reconciliation_step_digest != health_target.step_digest
        or safety_target.status
        is not DeployScyllaSequenceThreeSafetyStepStatus.AUTHORIZATION_REQUIRED
        or safety_target.authorization_state != _AUTHORIZATION_REQUIRED
        or safety_target.blockers != ("join-authorization-not-collected",)
        or context.target_sequence != target.sequence
        or context.target_digest != target.target_digest
        or context.target_plan_step_digest != target.step_digest
        or context.target_topology_digest != target.topology_digest
        or context.target_storage_evidence_digest != target.storage_evidence_digest
        or context.target_configuration_evidence_digest
        != target.configuration_evidence_digest
        or context.target_capacity_evidence_digest != target.capacity_evidence_digest
        or context.target_package_version_digest != target.package_version_digest
        or context.playbook_source_digest != target.playbook_source_digest
        or context.survivor_count != _CURRENT_MEMBER_COUNT
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
            step.status
            is not DeployScyllaSequenceThreeSafetyStepStatus.HEALTH_SUCCEEDED
            or step.authorization_state != "not-required"
            or step.blockers
            for step in safety_steps[:_CURRENT_MEMBER_COUNT]
        )
        or any(
            step.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or step.status is not DeployScyllaSequenceThreeSafetyStepStatus.WAITING
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
            "only the exact reconciled sequence-three join may be authorized"
        )
    values: dict[str, object] = {
        "sequence": target.sequence,
        "mode": target.mode,
        "classification": OperationClassification.SENSITIVE,
        "confirmation_policy": ConfirmationPolicy.SENSITIVE,
        "target_count": 1,
        "target_digest": target.target_digest,
        "bootstrap_plan_step_digest": target.step_digest,
        "post_join_health_step_digest": health_target.step_digest,
        "safety_step_digest": safety_target.step_digest,
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
    return DeployScyllaSequenceThreeJoinScope(**values)  # type: ignore[arg-type]


def _normalize_proof(
    proof: DeployScyllaSequenceThreeJoinAuthorizationProof,
    *,
    loaded: _SequenceThreeJoinAuthorizationLoaded,
    scope: DeployScyllaSequenceThreeJoinScope,
) -> DeployScyllaSequenceThreeJoinProofDecision:
    if proof.approval_method is None:
        raise StateConflictError("ordinary sequence-three join approval is required")
    if not proof.approved:
        raise StateConflictError("ordinary sequence-three join approval was denied")
    if proof.allow_destructive or proof.destructive_scope_provided:
        raise StateConflictError(
            "destructive proof is inapplicable to sensitive sequence-three join"
        )
    if proof.narrow_approval_method is None or not proof.narrow_approved:
        raise StateConflictError(
            "exact sequence-three target/mode/scope approval is required; "
            "cli-yes alone is insufficient"
        )
    expected_scope = DeployScyllaSequenceThreeJoinNarrowScopeProof.from_scope(scope)
    if proof.narrow_scope != expected_scope:
        raise StateConflictError(
            "sequence-three target/mode/scope approval does not match "
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
    return DeployScyllaSequenceThreeJoinProofDecision(**values)  # type: ignore[arg-type]


def _build_authorization(
    loaded: _SequenceThreeJoinAuthorizationLoaded,
    *,
    scope: DeployScyllaSequenceThreeJoinScope,
    proof: DeployScyllaSequenceThreeJoinProofDecision,
    created_at: str,
) -> DeployScyllaSequenceThreeJoinAuthorization:
    chain = loaded.chain
    context = loaded.safety_context.record
    evidence = loaded.safety_evidence.record
    reconciliation = loaded.safety_reconciliation.record
    later = reconciliation.steps[_TARGET_SEQUENCE:]
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
        "bootstrap_context_artifact_digest": (chain.bootstrap_context_artifact_digest),
        "bootstrap_context_record_digest": chain.bootstrap_context_record_digest,
        "bootstrap_plan_artifact_digest": chain.bootstrap_plan_artifact_digest,
        "bootstrap_plan_digest": chain.bootstrap_plan_digest,
        "first_join_authorization_artifact_digest": (
            chain.first_join_authorization.artifact_digest
        ),
        "first_join_authorization_digest": (
            chain.first_join_authorization.record.authorization_digest
        ),
        "first_join_execution_artifact_digest": (
            chain.first_join_execution.artifact_digest
        ),
        "first_join_execution_binding_digest": (
            chain.first_join_execution.record.binding.binding_digest
        ),
        "first_join_evidence_artifact_digest": (
            chain.first_join_evidence.artifact_digest
        ),
        "first_join_evidence_digest": chain.first_join_evidence.record.evidence_digest,
        "post_join_health_execution_artifact_digest": (
            chain.post_join_health_execution.artifact_digest
        ),
        "post_join_health_evidence_artifact_digest": (
            chain.post_join_health_evidence.artifact_digest
        ),
        "post_join_health_evidence_digest": (
            chain.post_join_health_evidence.record.evidence_digest
        ),
        "post_join_health_reconciliation_artifact_digest": (
            chain.post_join_health_reconciliation.artifact_digest
        ),
        "post_join_health_reconciliation_digest": (
            chain.post_join_health_reconciliation.record.reconciliation_digest
        ),
        "safety_context_artifact_digest": loaded.safety_context.artifact_digest,
        "safety_context_digest": context.context_digest,
        "safety_evidence_artifact_digest": loaded.safety_evidence.artifact_digest,
        "safety_evidence_digest": evidence.evidence_digest,
        "safety_reconciliation_artifact_digest": (
            loaded.safety_reconciliation.artifact_digest
        ),
        "safety_reconciliation_digest": reconciliation.reconciliation_digest,
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
    return DeployScyllaSequenceThreeJoinAuthorization(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployScyllaSequenceThreeJoinAuthorization,
    *,
    state: DeployScyllaSequenceThreeJoinAuthorizationArtifactState,
) -> DeployScyllaSequenceThreeJoinAuthorizationReport:
    record = stored.record
    scope = record.scope
    return DeployScyllaSequenceThreeJoinAuthorizationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        authorization_artifact_digest=stored.artifact_digest,
        authorization_digest=record.authorization_digest,
        authorization_state=record.authorization_state,
        classification=record.classification,
        confirmation_policy=record.confirmation_policy,
        approval_method=record.proof.approval_method,
        approval_state=record.proof.approval_state,
        narrow_approval_method=record.proof.narrow_approval_method,
        narrow_approval_state=record.proof.narrow_approval_state,
        proof_digest=record.proof.proof_digest,
        sequence=scope.sequence,
        mode=scope.mode,
        target_count=scope.target_count,
        target_digest=scope.target_digest,
        survivor_count=scope.survivor_count,
        survivor_set_digest=scope.survivor_set_digest,
        active_seed_count=scope.active_seed_count,
        active_seed_set_digest=scope.active_seed_set_digest,
        authorization_scope_digest=scope.scope_digest,
        safety_context_digest=scope.safety_context_digest,
        safety_evidence_digest=scope.safety_evidence_digest,
        safety_reconciliation_digest=scope.safety_reconciliation_digest,
        safety_gate_set_digest=scope.safety_gate_set_digest,
        validated_chain_digest=record.validated_chain_digest,
        later_join_count=record.later_join_count,
        later_join_digest=record.later_join_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        journal_digest=record.journal_digest,
        consumed=record.consumed,
        execution_state=record.execution_state,
        public_workflow_state=record.public_workflow_state,
    )


def _scope_digest(scope: DeployScyllaSequenceThreeJoinScope) -> str:
    return _scope_digest_from_values(scope.to_object())


def _scope_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    value["scope_digest"] = ""
    return _digest_object(value)


def _proof_digest(
    record: DeployScyllaSequenceThreeJoinAuthorization,
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
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION,
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


def _authorization_digest(
    record: DeployScyllaSequenceThreeJoinAuthorization,
) -> str:
    return _authorization_digest_from_values(record.to_object())


def _authorization_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for (
        name,
        field,
    ) in DeployScyllaSequenceThreeJoinAuthorization.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["authorization_digest"] = ""
    return _digest_object(value)


def _refuse_incompatible_or_later_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    generic = (
        paths.operations / f"{operation_id}{OPERATION_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    validate_state_file(generic, allow_missing=True)
    if generic.exists():
        raise StateConflictError(
            "generic Ansible authorization is incompatible with deploy VERIFY binding"
        )
    forbidden_fragments = (
        ".ansible-deploy-scylla-sequence-three-join-execution",
        ".ansible-deploy-scylla-sequence-three-join-evidence",
        ".ansible-deploy-scylla-post-sequence-three-join",
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list sequence-three join authorization history"
        ) from error
    prefix = str(operation_id)
    for entry in entries:
        if entry.name.startswith(prefix) and any(
            fragment in entry.name for fragment in forbidden_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "sequence-three join authorization refuses execution "
                "or later membership history"
            )


def _refuse_ambiguous_authorization_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list sequence-three join authorization artifacts"
        ) from error
    canonical = str(operation_id)
    suffix = DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_FILENAME_SUFFIX
    for entry in entries:
        if not entry.name.endswith(suffix):
            continue
        prefix = entry.name[: -len(suffix)]
        try:
            parsed = uuid.UUID(prefix)
        except ValueError:
            parsed = None
        if prefix != canonical and (
            parsed is None or parsed == operation_id or canonical in prefix
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "sequence-three join authorization artifacts are ambiguous"
            )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "sequence-three join authorization paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "sequence-three join authorization requires the matching held deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


__all__ = [
    "ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_SCHEMA_VERSION",
    "DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_FILENAME_SUFFIX",
    "DeployScyllaSequenceThreeJoinAuthorization",
    "DeployScyllaSequenceThreeJoinAuthorizationArtifactState",
    "DeployScyllaSequenceThreeJoinAuthorizationProof",
    "DeployScyllaSequenceThreeJoinAuthorizationReport",
    "DeployScyllaSequenceThreeJoinAuthorizationStore",
    "DeployScyllaSequenceThreeJoinNarrowScopeProof",
    "DeployScyllaSequenceThreeJoinProofDecision",
    "DeployScyllaSequenceThreeJoinScope",
    "StoredDeployScyllaSequenceThreeJoinAuthorization",
    "authorize_deploy_scylla_sequence_three_join",
    "deploy_scylla_sequence_three_join_authorization_id_from_filename",
    "deploy_scylla_sequence_three_join_authorization_path",
]
