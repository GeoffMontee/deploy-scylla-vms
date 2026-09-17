"""Sensitive authorization for only the reconciled first deploy join.

This internal owner reloads the complete initial-seed, health-checkpoint, and
join-safety chain, derives the exact first ``join-existing`` scope from
canonical records, and persists one immutable unconsumed authorization.  It
accepts no caller target or mode, invokes no process, changes no journal, and
does not expose public workflow wiring.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.deploy_plan import _digest_object, _require_operation_id
from scylla_vms.ansible.deploy_scylla_bootstrap_plan import (
    ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_SCHEMA_VERSION,
    DeployScyllaBootstrapStepStatus,
)
from scylla_vms.ansible.deploy_scylla_health_checkpoint import (
    ANSIBLE_DEPLOY_SCYLLA_HEALTH_CHECKPOINT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_HEALTH_EXECUTION_SCHEMA_VERSION,
)
from scylla_vms.ansible.deploy_scylla_join_safety import (
    ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION,
    DeployScyllaJoinSafetyContextStore,
    DeployScyllaJoinSafetyEvidenceStore,
    DeployScyllaJoinSafetyProofStatus,
    DeployScyllaJoinSafetyReconciliationStore,
    DeployScyllaJoinSafetyStepStatus,
    StoredDeployScyllaJoinSafetyContext,
    StoredDeployScyllaJoinSafetyEvidence,
    StoredDeployScyllaJoinSafetyReconciliation,
    _build_context,
    _build_evidence,
    _build_reconciliation,
    _JoinSafetyLoaded,
    _load_join_safety,
    _validate_proof,
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

ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-authorization-proof/v1"
)
ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-authorization/v1"
)
ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-authorization-report/v1"
)
DEPLOY_SCYLLA_JOIN_AUTHORIZATION_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-join-authorization.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "scylla-bootstrap"
_STAGE = "post-first-join-safety-authorization"
_SCOPE_KIND = "first-reconciled-join-existing"
_AUTHORIZED = "authorized-pre-execution"
_EXECUTION_UNAVAILABLE = "unavailable"
_FINALIZATION_NOT_STARTED = "not-started"
_PUBLIC_WORKFLOW_UNAVAILABLE = "unavailable"
_APPROVED = "approved"
_MATCHED = "matched"
_AUTHORIZATION_REQUIRED = "authorization-required"
_AUTHORIZATION_NOT_CREATED = "not-created"
_WAITING = "waiting"
_REQUIRED_GATE_COUNT = 8


class DeployScyllaJoinApprovalMethod(StrEnum):
    """PLAN-permitted ordinary confirmation methods for sensitive work."""

    INTERACTIVE = "interactive"
    CLI_YES = "cli-yes"


class DeployScyllaJoinNarrowApprovalMethod(StrEnum):
    """Sources that can acknowledge the exact first-join scope."""

    INTERACTIVE = "interactive"
    CLI_EXPLICIT = "cli-explicit"


class DeployScyllaJoinAuthorizationArtifactState(StrEnum):
    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployScyllaJoinScope:
    """Redacted exact scope derived for only the first reconciled join."""

    sequence: int
    mode: ScyllaBootstrapMode
    classification: OperationClassification
    confirmation_policy: ConfirmationPolicy
    target_count: int
    target_digest: str
    bootstrap_plan_step_digest: str
    health_checkpoint_step_digest: str
    join_safety_step_digest: str
    survivor_count: int
    survivor_set_digest: str
    survivor_health_digest: str
    active_seed_count: int
    active_seed_set_digest: str
    topology_digest: str
    target_topology_digest: str
    schema_digest: str
    membership_digest: str
    seed_policy_digest: str
    package_version_digest: str
    storage_evidence_digest: str
    configuration_evidence_digest: str
    capacity_evidence_digest: str
    playbook_source_digest: str
    safety_context_digest: str
    safety_evidence_digest: str
    safety_reconciliation_digest: str
    safety_gate_set_digest: str
    scope_digest: str

    def __post_init__(self) -> None:
        if (
            self.sequence != 2
            or self.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or self.classification is not OperationClassification.SENSITIVE
            or self.confirmation_policy is not ConfirmationPolicy.SENSITIVE
            or self.target_count != 1
            or self.survivor_count != 1
            or self.active_seed_count != 1
            or self.active_seed_set_digest != self.survivor_set_digest
            or self.scope_digest != _scope_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla first-join authorization scope conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(value, "deploy Scylla first-join scope digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaJoinScope:
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
            label="first-join authorization scope",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaJoinNarrowScopeProof:
    """Exact target/mode/scope acknowledgement without caller selection."""

    target_count: int
    target_digest: str
    mode: ScyllaBootstrapMode
    bootstrap_plan_step_digest: str
    join_safety_step_digest: str
    authorization_scope_digest: str

    def __post_init__(self) -> None:
        if self.target_count != 1 or self.mode is not ScyllaBootstrapMode.JOIN_EXISTING:
            raise StateConflictError(
                "deploy Scylla join narrow proof must bind one join-existing target"
            )
        for value in _digest_fields(self):
            validate_digest(value, "deploy Scylla join narrow proof digest")

    @classmethod
    def from_scope(
        cls, scope: DeployScyllaJoinScope
    ) -> DeployScyllaJoinNarrowScopeProof:
        if not isinstance(scope, DeployScyllaJoinScope):
            raise StateConflictError("deploy Scylla join scope is malformed")
        return cls(
            target_count=scope.target_count,
            target_digest=scope.target_digest,
            mode=scope.mode,
            bootstrap_plan_step_digest=scope.bootstrap_plan_step_digest,
            join_safety_step_digest=scope.join_safety_step_digest,
            authorization_scope_digest=scope.scope_digest,
        )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)


@dataclass(frozen=True, slots=True)
class DeployScyllaJoinAuthorizationProof:
    """Already-normalized ordinary and exact narrow approval facts."""

    approval_method: DeployScyllaJoinApprovalMethod | None = None
    approved: bool = False
    narrow_approval_method: DeployScyllaJoinNarrowApprovalMethod | None = None
    narrow_approved: bool = False
    narrow_scope: DeployScyllaJoinNarrowScopeProof | None = None
    allow_destructive: bool = False
    destructive_scope_provided: bool = False

    def __post_init__(self) -> None:
        if self.approval_method is not None and not isinstance(
            self.approval_method, DeployScyllaJoinApprovalMethod
        ):
            raise StateConflictError("deploy Scylla join approval method is invalid")
        if self.narrow_approval_method is not None and not isinstance(
            self.narrow_approval_method, DeployScyllaJoinNarrowApprovalMethod
        ):
            raise StateConflictError(
                "deploy Scylla join narrow approval method is invalid"
            )
        if self.narrow_scope is not None and not isinstance(
            self.narrow_scope, DeployScyllaJoinNarrowScopeProof
        ):
            raise StateConflictError("deploy Scylla join narrow proof is malformed")
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
                "deploy Scylla join authorization proof is malformed"
            )


@dataclass(frozen=True, slots=True)
class DeployScyllaJoinProofDecision:
    """Persisted normalized approval decision bound to the exact join scope."""

    approval_method: DeployScyllaJoinApprovalMethod
    approval_state: str
    narrow_approval_method: DeployScyllaJoinNarrowApprovalMethod
    narrow_approval_state: str
    target_count: int
    target_digest: str
    mode: ScyllaBootstrapMode
    bootstrap_plan_step_digest: str
    join_safety_step_digest: str
    authorization_scope_digest: str
    allow_destructive: bool
    destructive_scope_provided: bool
    proof_digest: str
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or self.approval_state != _APPROVED
            or self.narrow_approval_state != _MATCHED
            or self.target_count != 1
            or self.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or self.allow_destructive
            or self.destructive_scope_provided
        ):
            raise StatePersistenceError(
                "deploy Scylla join authorization proof decision conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(value, "deploy Scylla join proof digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaJoinProofDecision:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={"target_count"},
            boolean_fields={"allow_destructive", "destructive_scope_provided"},
            enum_fields={
                "approval_method": DeployScyllaJoinApprovalMethod,
                "narrow_approval_method": DeployScyllaJoinNarrowApprovalMethod,
                "mode": ScyllaBootstrapMode,
            },
            label="first-join authorization proof",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaJoinAuthorization:
    """Immutable unconsumed authorization for only the first reconciled join."""

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
    bootstrap_execution_artifact_digest: str
    bootstrap_evidence_artifact_digest: str
    bootstrap_evidence_digest: str
    health_execution_artifact_digest: str
    health_evidence_artifact_digest: str
    health_evidence_digest: str
    health_checkpoint_artifact_digest: str
    health_checkpoint_digest: str
    safety_context_artifact_digest: str
    safety_context_digest: str
    safety_evidence_artifact_digest: str
    safety_evidence_digest: str
    safety_reconciliation_artifact_digest: str
    safety_reconciliation_digest: str
    post_configure_artifact_digest: str
    post_configure_record_digest: str
    terraform_verification_artifact_digest: str
    observation_artifact_digest: str
    inventory_artifact_digest: str
    trust_artifact_digest: str
    readiness_artifact_digest: str
    storage_evidence_artifact_digest: str
    install_evidence_artifact_digest: str
    configure_evidence_artifact_digest: str
    catalog_digest: str
    ansible_source_digest: str
    playbook_source_digest: str
    validated_chain_digest: str
    classification: OperationClassification
    confirmation_policy: ConfirmationPolicy
    scope: DeployScyllaJoinScope
    authorization_scope_digest: str
    later_join_count: int
    later_join_digest: str
    non_authorized_scope_digest: str
    proof: DeployScyllaJoinProofDecision
    authorization_state: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_digest: str
    bootstrap_context_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION
    )
    bootstrap_plan_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_SCHEMA_VERSION
    )
    health_execution_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_HEALTH_EXECUTION_SCHEMA_VERSION
    )
    health_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_SCHEMA_VERSION
    )
    health_checkpoint_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_HEALTH_CHECKPOINT_SCHEMA_VERSION
    )
    safety_context_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
    )
    safety_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
    )
    safety_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION
    )
    proof_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_SCHEMA_VERSION
            or self.bootstrap_context_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION
            or self.bootstrap_plan_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_SCHEMA_VERSION
            or self.health_execution_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_HEALTH_EXECUTION_SCHEMA_VERSION
            or self.health_evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_SCHEMA_VERSION
            or self.health_checkpoint_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_HEALTH_CHECKPOINT_SCHEMA_VERSION
            or self.safety_context_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
            or self.safety_evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
            or self.safety_reconciliation_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION
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
            or not isinstance(self.scope, DeployScyllaJoinScope)
            or not isinstance(self.proof, DeployScyllaJoinProofDecision)
            or self.authorization_scope_digest != self.scope.scope_digest
            or self.proof.target_count != self.scope.target_count
            or self.proof.target_digest != self.scope.target_digest
            or self.proof.mode is not self.scope.mode
            or self.proof.bootstrap_plan_step_digest
            != self.scope.bootstrap_plan_step_digest
            or self.proof.join_safety_step_digest != self.scope.join_safety_step_digest
            or self.proof.authorization_scope_digest != self.authorization_scope_digest
            or self.proof.proof_digest != _proof_digest(self, self.proof.to_object())
            or self.authorization_digest != _authorization_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla join authorization identity, scope, or state conflicts"
            )
        parse_timestamp(self.created_at)
        _positive_integer(self.journal_generation, "join authorization journal")
        _nonnegative_integer(self.later_join_count, "later join count")
        for value in _digest_fields(self):
            validate_digest(value, "deploy Scylla join authorization digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, nested_fields={"scope", "proof"})

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaJoinAuthorization:
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
            label="first-join authorization",
        )
        parsed["scope"] = DeployScyllaJoinScope.from_object(
            _mapping(value["scope"], "first-join scope")
        )
        parsed["proof"] = DeployScyllaJoinProofDecision.from_object(
            _mapping(value["proof"], "first-join proof")
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaJoinAuthorization:
    record: DeployScyllaJoinAuthorization
    artifact_digest: str


class DeployScyllaJoinAuthorizationStore:
    """Owner-only immutable first-join authorization store."""

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
        self._path = deploy_scylla_join_authorization_path(paths, operation_id)
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
    ) -> StoredDeployScyllaJoinAuthorization:
        value, artifact_digest = self._file.read()
        record = DeployScyllaJoinAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_identity_digest
            != _cluster_identity_digest(expected_cluster_uuid, expected_cluster_name)
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "deploy Scylla join authorization identity conflicts"
            )
        return StoredDeployScyllaJoinAuthorization(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaJoinAuthorization:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaJoinAuthorization,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployScyllaJoinAuthorization,
        DeployScyllaJoinAuthorizationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy Scylla join authorization operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=self._paths.cluster_root.name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy Scylla join authorization is immutable; use a new operation"
                )
            return current, DeployScyllaJoinAuthorizationArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaJoinAuthorization(record, artifact_digest),
            DeployScyllaJoinAuthorizationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaJoinAuthorizationReport:
    """Strict count/enum/digest-only first-join authorization projection."""

    operation_id: uuid.UUID
    artifact_state: DeployScyllaJoinAuthorizationArtifactState
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_state: str
    stage: str
    scope_kind: str
    classification: OperationClassification
    confirmation_policy: ConfirmationPolicy
    approval_method: DeployScyllaJoinApprovalMethod
    approval_state: str
    narrow_approval_method: DeployScyllaJoinNarrowApprovalMethod
    narrow_approval_state: str
    proof_digest: str
    target_count: int
    target_digest: str
    sequence: int
    mode: ScyllaBootstrapMode
    authorization_scope_digest: str
    survivor_count: int
    survivor_set_digest: str
    active_seed_count: int
    active_seed_set_digest: str
    topology_digest: str
    target_topology_digest: str
    schema_digest: str
    membership_digest: str
    seed_policy_digest: str
    package_version_digest: str
    storage_evidence_digest: str
    configuration_evidence_digest: str
    capacity_evidence_digest: str
    safety_context_digest: str
    safety_evidence_digest: str
    safety_reconciliation_digest: str
    safety_gate_set_digest: str
    later_join_count: int
    later_join_digest: str
    validated_chain_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    journal_digest: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_SCHEMA_VERSION
    )
    proof_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    safety_context_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
    )
    safety_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
    )
    safety_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or self.safety_context_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
            or self.safety_evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
            or self.safety_reconciliation_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION
            or self.authorization_state != _AUTHORIZED
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.classification is not OperationClassification.SENSITIVE
            or self.confirmation_policy is not ConfirmationPolicy.SENSITIVE
            or self.approval_state != _APPROVED
            or self.narrow_approval_state != _MATCHED
            or self.target_count != 1
            or self.sequence != 2
            or self.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or self.survivor_count != 1
            or self.active_seed_count != 1
            or self.active_seed_set_digest != self.survivor_set_digest
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError(
                "deploy Scylla join authorization report conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(value, "deploy Scylla join authorization report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "authorization": {
                "artifact_digest": self.authorization_artifact_digest,
                "consumed": self.consumed,
                "digest": self.authorization_digest,
                "schema_version": self.authorization_schema_version,
                "state": self.authorization_state,
            },
            "execution": {
                "available": False,
                "finalization_state": self.finalization_state,
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
                "schema_version": self.proof_schema_version,
            },
            "provenance": {
                "safety_context_digest": self.safety_context_digest,
                "safety_context_schema_version": self.safety_context_schema_version,
                "safety_evidence_digest": self.safety_evidence_digest,
                "safety_evidence_schema_version": self.safety_evidence_schema_version,
                "safety_reconciliation_digest": self.safety_reconciliation_digest,
                "safety_reconciliation_schema_version": (
                    self.safety_reconciliation_schema_version
                ),
                "validated_chain_digest": self.validated_chain_digest,
            },
            "result": self.artifact_state.value,
            "schema_version": self.schema_version,
            "scope": {
                "active_seed_count": self.active_seed_count,
                "active_seed_set_digest": self.active_seed_set_digest,
                "authorization_scope_digest": self.authorization_scope_digest,
                "capacity_evidence_digest": self.capacity_evidence_digest,
                "configuration_evidence_digest": (self.configuration_evidence_digest),
                "membership_digest": self.membership_digest,
                "mode": self.mode.value,
                "package_version_digest": self.package_version_digest,
                "safety_gate_set_digest": self.safety_gate_set_digest,
                "schema_digest": self.schema_digest,
                "seed_policy_digest": self.seed_policy_digest,
                "sequence": self.sequence,
                "storage_evidence_digest": self.storage_evidence_digest,
                "survivor_count": self.survivor_count,
                "survivor_set_digest": self.survivor_set_digest,
                "target_count": self.target_count,
                "target_digest": self.target_digest,
                "target_topology_digest": self.target_topology_digest,
                "topology_digest": self.topology_digest,
            },
            "stage": self.stage,
        }


@dataclass(frozen=True, slots=True)
class _JoinAuthorizationLoaded:
    chain: _JoinSafetyLoaded
    safety_context: StoredDeployScyllaJoinSafetyContext
    safety_evidence: StoredDeployScyllaJoinSafetyEvidence
    safety_reconciliation: StoredDeployScyllaJoinSafetyReconciliation


def authorize_deploy_scylla_join_existing(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proof: DeployScyllaJoinAuthorizationProof,
) -> DeployScyllaJoinAuthorizationReport:
    """Authorize only the canonical first reconciled join without execution."""

    if not isinstance(proof, DeployScyllaJoinAuthorizationProof):
        raise StateConflictError("deploy Scylla join authorization proof is malformed")
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_authorization_artifacts(paths, operation_id)
    _refuse_incompatible_or_later_artifacts(paths, operation_id)
    loaded = _load_join_authorization_context(paths, operation_id, lock=lock)
    scope = _derive_first_join_scope(loaded)
    decision = _normalize_proof(proof, loaded=loaded, scope=scope)
    store = DeployScyllaJoinAuthorizationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    identity = loaded.chain.health_evidence.record.binding
    if store.path.exists():
        stored = store.read_locked(
            lock,
            expected_cluster_uuid=identity.cluster_uuid,
            expected_cluster_name=identity.cluster_name,
        )
        expected = _build_authorization(
            loaded,
            scope=scope,
            proof=decision,
            created_at=stored.record.created_at,
        )
        if stored.record != expected:
            raise StateConflictError(
                "deploy Scylla join authorization changed; re-plan with a new operation"
            )
        state = DeployScyllaJoinAuthorizationArtifactState.REUSED
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
                "deploy Scylla join authorization persistence failed"
            ) from error
    return _build_report(stored, state=state)


def deploy_scylla_join_authorization_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the canonical first-join authorization path."""

    _require_canonical_paths(paths)
    path = paths.operations / (
        f"{_require_operation_id(operation_id)}"
        f"{DEPLOY_SCYLLA_JOIN_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Scylla join authorization path is not canonical"
        )
    return path


def deploy_scylla_join_authorization_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(DEPLOY_SCYLLA_JOIN_AUTHORIZATION_FILENAME_SUFFIX):
        return None
    value = name[: -len(DEPLOY_SCYLLA_JOIN_AUTHORIZATION_FILENAME_SUFFIX)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _load_join_authorization_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
) -> _JoinAuthorizationLoaded:
    chain = _load_join_safety(paths, operation_id, lock=lock)
    identity = chain.health_evidence.record.binding
    context_store = DeployScyllaJoinSafetyContextStore(paths, operation_id)
    evidence_store = DeployScyllaJoinSafetyEvidenceStore(paths, operation_id)
    reconciliation_store = DeployScyllaJoinSafetyReconciliationStore(
        paths, operation_id
    )
    for path, label in (
        (context_store.path, "join-safety context"),
        (evidence_store.path, "join-safety evidence"),
        (reconciliation_store.path, "join-safety reconciliation"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"deploy Scylla join authorization requires exact {label}"
            )
    context = context_store.read_locked(
        lock,
        expected_cluster_uuid=identity.cluster_uuid,
        expected_cluster_name=identity.cluster_name,
    )
    evidence = evidence_store.read_locked(
        lock,
        expected_cluster_uuid=identity.cluster_uuid,
        expected_cluster_name=identity.cluster_name,
    )
    reconciliation = reconciliation_store.read_locked(
        lock,
        expected_cluster_uuid=identity.cluster_uuid,
        expected_cluster_name=identity.cluster_name,
    )
    proof = evidence.record.proof
    _validate_proof(proof, chain)
    expected_context = _build_context(
        chain, proof=proof, created_at=context.record.created_at
    )
    if context.record != expected_context:
        raise StateConflictError(
            "deploy Scylla join-safety context drifted; use a new operation"
        )
    expected_evidence = _build_evidence(
        chain,
        context=context,
        proof=proof,
        created_at=evidence.record.created_at,
    )
    if evidence.record != expected_evidence:
        raise StateConflictError(
            "deploy Scylla join-safety evidence drifted; use a new operation"
        )
    expected_reconciliation = _build_reconciliation(
        chain,
        context=context,
        evidence=evidence,
        created_at=reconciliation.record.created_at,
    )
    if reconciliation.record != expected_reconciliation:
        raise StateConflictError(
            "deploy Scylla join-safety reconciliation drifted; use a new operation"
        )
    required_gates = tuple(gate for gate in evidence.record.gates if gate.required)
    policy_gates = tuple(gate for gate in evidence.record.gates if not gate.required)
    if (
        evidence.record.context_artifact_digest != context.artifact_digest
        or evidence.record.context_digest != context.record.context_digest
        or reconciliation.record.context_artifact_digest != context.artifact_digest
        or reconciliation.record.context_digest != context.record.context_digest
        or reconciliation.record.evidence_artifact_digest != evidence.artifact_digest
        or reconciliation.record.evidence_digest != evidence.record.evidence_digest
        or not evidence.record.ready_for_authorization
        or evidence.record.authorization_state != _AUTHORIZATION_REQUIRED
        or evidence.record.blockers
        or len(required_gates) != _REQUIRED_GATE_COUNT
        or evidence.record.required_passed_count != _REQUIRED_GATE_COUNT
        or evidence.record.failed_count
        or evidence.record.unknown_count
        or any(
            gate.status is not DeployScyllaJoinSafetyProofStatus.PASSED
            for gate in required_gates
        )
        or any(
            gate.status is not DeployScyllaJoinSafetyProofStatus.NOT_APPLICABLE
            for gate in policy_gates
        )
        or reconciliation.record.authorization_required_count != 1
        or reconciliation.record.blocked_count
        or reconciliation.record.first_join_sequence != 2
        or reconciliation.record.first_join_status != _AUTHORIZATION_REQUIRED
        or reconciliation.record.authorization_state != _AUTHORIZATION_NOT_CREATED
        or reconciliation.record.execution_state != _EXECUTION_UNAVAILABLE
        or reconciliation.record.journal_digest != context.record.journal_digest
        or reconciliation.record.journal_generation != context.record.journal_generation
    ):
        raise StateConflictError(
            "deploy Scylla first join is not exactly reconciled for authorization"
        )
    return _JoinAuthorizationLoaded(chain, context, evidence, reconciliation)


def _derive_first_join_scope(
    loaded: _JoinAuthorizationLoaded,
) -> DeployScyllaJoinScope:
    definition = get_playbook(_PLAYBOOK)
    chain = loaded.chain
    plan = chain.bootstrap_plan.record
    checkpoint = chain.health_checkpoint.record
    reconciliation = loaded.safety_reconciliation.record
    if (
        definition.classification is not OperationClassification.SENSITIVE
        or definition.check_mode is not CheckMode.REFUSED
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.serial != 1
        or not definition.any_errors_fatal
        or not definition.source_available
        or len(plan.steps) < 2
        or len(checkpoint.steps) != len(plan.steps)
        or len(reconciliation.steps) != len(plan.steps)
    ):
        raise StateConflictError(
            "deploy Scylla join catalog or reconciled scope conflicts"
        )
    initial = plan.steps[0]
    target = plan.steps[1]
    health_target = checkpoint.steps[1]
    safety_target = reconciliation.steps[1]
    later = reconciliation.steps[2:]
    health = chain.health_evidence.record
    safety_context = loaded.safety_context.record
    safety_evidence = loaded.safety_evidence.record
    if health.topology_digest is None or health.schema_digest is None:
        raise StateConflictError(
            "deploy Scylla join requires complete topology and schema evidence"
        )
    survivor_ids = tuple(node.stable_id for node in health.nodes)
    if (
        initial.sequence != 1
        or initial.mode is not ScyllaBootstrapMode.INITIAL_SEED
        or target.sequence != 2
        or target.mode is not ScyllaBootstrapMode.JOIN_EXISTING
        or target.status
        is not DeployScyllaBootstrapStepStatus.WAITING_FOR_HEALTH_CHECKPOINT
        or health_target.sequence != target.sequence
        or health_target.mode is not target.mode
        or health_target.target_digest != target.target_digest
        or health_target.original_step_digest != target.step_digest
        or safety_target.sequence != target.sequence
        or safety_target.mode is not target.mode
        or safety_target.target_digest != target.target_digest
        or safety_target.plan_step_digest != target.step_digest
        or safety_target.health_checkpoint_step_digest != health_target.step_digest
        or safety_target.status
        is not DeployScyllaJoinSafetyStepStatus.AUTHORIZATION_REQUIRED
        or safety_target.authorization_state != _AUTHORIZATION_REQUIRED
        or safety_target.blockers != ("join-authorization-not-collected",)
        or safety_context.target_sequence != target.sequence
        or safety_context.target_digest != target.target_digest
        or safety_context.target_plan_step_digest != target.step_digest
        or safety_context.target_topology_digest != target.topology_digest
        or safety_context.target_storage_evidence_digest
        != target.storage_evidence_digest
        or safety_context.target_configuration_evidence_digest
        != target.configuration_evidence_digest
        or safety_context.target_capacity_evidence_digest
        != target.capacity_evidence_digest
        or safety_context.playbook_source_digest != target.playbook_source_digest
        or safety_context.current_topology_digest != health.topology_digest
        or safety_context.current_schema_digest != health.schema_digest
        or safety_context.current_membership_digest != health.membership_digest
        or safety_context.survivor_count != 1
        or survivor_ids != tuple(dict.fromkeys(survivor_ids))
        or len(survivor_ids) != 1
        or health.nodes[0].stable_id_digest != initial.target_digest
        or safety_context.survivor_set_digest != _digest_object(list(survivor_ids))
        or safety_context.survivor_health_digest
        != _digest_object([node.evidence_digest for node in health.nodes])
        or any(
            step.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or step.status is not DeployScyllaJoinSafetyStepStatus.WAITING
            or step.authorization_state != _WAITING
            or step.blockers != ("preceding-join-not-completed",)
            for step in later
        )
    ):
        raise StateConflictError(
            "only the exact first reconciled join-existing target may be authorized"
        )
    values: dict[str, object] = {
        "sequence": target.sequence,
        "mode": target.mode,
        "classification": OperationClassification.SENSITIVE,
        "confirmation_policy": ConfirmationPolicy.SENSITIVE,
        "target_count": 1,
        "target_digest": target.target_digest,
        "bootstrap_plan_step_digest": target.step_digest,
        "health_checkpoint_step_digest": health_target.step_digest,
        "join_safety_step_digest": safety_target.step_digest,
        "survivor_count": safety_context.survivor_count,
        "survivor_set_digest": safety_context.survivor_set_digest,
        "survivor_health_digest": safety_context.survivor_health_digest,
        "active_seed_count": len(survivor_ids),
        "active_seed_set_digest": _digest_object(list(survivor_ids)),
        "topology_digest": health.topology_digest,
        "target_topology_digest": target.topology_digest,
        "schema_digest": health.schema_digest,
        "membership_digest": health.membership_digest,
        "seed_policy_digest": target.seed_policy_digest,
        "package_version_digest": target.package_version_digest,
        "storage_evidence_digest": target.storage_evidence_digest,
        "configuration_evidence_digest": target.configuration_evidence_digest,
        "capacity_evidence_digest": target.capacity_evidence_digest,
        "playbook_source_digest": target.playbook_source_digest,
        "safety_context_digest": safety_context.context_digest,
        "safety_evidence_digest": safety_evidence.evidence_digest,
        "safety_reconciliation_digest": reconciliation.reconciliation_digest,
        "safety_gate_set_digest": _digest_object(
            [gate.gate_digest for gate in safety_evidence.gates]
        ),
        "scope_digest": "",
    }
    values["scope_digest"] = _scope_digest_from_values(values)
    return DeployScyllaJoinScope(**values)  # type: ignore[arg-type]


def _normalize_proof(
    proof: DeployScyllaJoinAuthorizationProof,
    *,
    loaded: _JoinAuthorizationLoaded,
    scope: DeployScyllaJoinScope,
) -> DeployScyllaJoinProofDecision:
    if proof.approval_method is None:
        raise StateConflictError("ordinary deploy Scylla join approval is required")
    if not proof.approved:
        raise StateConflictError("ordinary deploy Scylla join approval was denied")
    if proof.allow_destructive or proof.destructive_scope_provided:
        raise StateConflictError(
            "destructive proof is inapplicable to sensitive join-existing bootstrap"
        )
    if proof.narrow_approval_method is None or not proof.narrow_approved:
        raise StateConflictError(
            "exact first join target/mode/scope approval is required; "
            "--yes alone is insufficient"
        )
    expected_scope = DeployScyllaJoinNarrowScopeProof.from_scope(scope)
    if proof.narrow_scope != expected_scope:
        raise StateConflictError(
            "first join target/mode/scope approval does not match "
            "the exact reconciled plan"
        )
    chain = loaded.chain
    values: dict[str, object] = {
        "approval_method": proof.approval_method,
        "approval_state": _APPROVED,
        "narrow_approval_method": proof.narrow_approval_method,
        "narrow_approval_state": _MATCHED,
        "target_count": expected_scope.target_count,
        "target_digest": expected_scope.target_digest,
        "mode": expected_scope.mode,
        "bootstrap_plan_step_digest": expected_scope.bootstrap_plan_step_digest,
        "join_safety_step_digest": expected_scope.join_safety_step_digest,
        "authorization_scope_digest": expected_scope.authorization_scope_digest,
        "allow_destructive": False,
        "destructive_scope_provided": False,
        "proof_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION
        ),
    }
    values["proof_digest"] = _proof_digest_values(
        cluster_uuid=chain.bootstrap_context.record.cluster_uuid,
        operation_id=chain.bootstrap_context.record.operation_id,
        journal_digest=chain.bootstrap_context.record.journal_digest,
        safety_context_artifact_digest=loaded.safety_context.artifact_digest,
        safety_evidence_artifact_digest=loaded.safety_evidence.artifact_digest,
        safety_reconciliation_artifact_digest=(
            loaded.safety_reconciliation.artifact_digest
        ),
        scope_digest=scope.scope_digest,
        proof=values,
    )
    return DeployScyllaJoinProofDecision(**values)  # type: ignore[arg-type]


def _build_authorization(
    loaded: _JoinAuthorizationLoaded,
    *,
    scope: DeployScyllaJoinScope,
    proof: DeployScyllaJoinProofDecision,
    created_at: str,
) -> DeployScyllaJoinAuthorization:
    chain = loaded.chain
    context = chain.bootstrap_context.record
    health = chain.health_evidence.record
    checkpoint = chain.health_checkpoint.record
    safety_context = loaded.safety_context.record
    safety_evidence = loaded.safety_evidence.record
    reconciliation = loaded.safety_reconciliation.record
    later = reconciliation.steps[2:]
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
    validated_chain = {
        "ansible_source_digest": context.ansible_source_digest,
        "bootstrap_context_artifact_digest": chain.bootstrap_context.artifact_digest,
        "bootstrap_context_record_digest": context.record_digest,
        "bootstrap_evidence_artifact_digest": chain.bootstrap_evidence.artifact_digest,
        "bootstrap_evidence_digest": (
            chain.bootstrap_evidence.record.entry.evidence_digest
        ),
        "bootstrap_execution_artifact_digest": (
            chain.bootstrap_execution.artifact_digest
        ),
        "bootstrap_plan_artifact_digest": chain.bootstrap_plan.artifact_digest,
        "bootstrap_plan_digest": chain.bootstrap_plan.record.plan_digest,
        "catalog_digest": context.catalog_digest,
        "configure_evidence_artifact_digest": (
            context.configure_evidence_artifact_digest
        ),
        "health_checkpoint_artifact_digest": chain.health_checkpoint.artifact_digest,
        "health_checkpoint_digest": checkpoint.checkpoint_digest,
        "health_evidence_artifact_digest": chain.health_evidence.artifact_digest,
        "health_evidence_digest": health.evidence_digest,
        "health_execution_artifact_digest": chain.health_execution.artifact_digest,
        "install_evidence_artifact_digest": (context.install_evidence_artifact_digest),
        "inventory_artifact_digest": context.inventory_artifact_digest,
        "journal_digest": context.journal_digest,
        "observation_artifact_digest": context.observation_artifact_digest,
        "post_configure_artifact_digest": context.post_configure_artifact_digest,
        "post_configure_record_digest": context.post_configure_record_digest,
        "readiness_artifact_digest": context.readiness_artifact_digest,
        "safety_context_artifact_digest": loaded.safety_context.artifact_digest,
        "safety_context_digest": safety_context.context_digest,
        "safety_evidence_artifact_digest": loaded.safety_evidence.artifact_digest,
        "safety_evidence_digest": safety_evidence.evidence_digest,
        "safety_reconciliation_artifact_digest": (
            loaded.safety_reconciliation.artifact_digest
        ),
        "safety_reconciliation_digest": reconciliation.reconciliation_digest,
        "storage_evidence_artifact_digest": context.storage_evidence_artifact_digest,
        "terraform_verification_artifact_digest": (
            context.terraform_verification_artifact_digest
        ),
        "trust_artifact_digest": context.trust_artifact_digest,
    }
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": context.cluster_uuid,
        "cluster_identity_digest": _cluster_identity_digest(
            context.cluster_uuid, context.cluster_name
        ),
        "operation_id": context.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "scope_kind": _SCOPE_KIND,
        "request_digest": context.request_digest,
        "journal_generation": context.journal_generation,
        "journal_digest": context.journal_digest,
        "journal_status": context.journal_status,
        "journal_phase": context.journal_phase,
        "bootstrap_context_artifact_digest": chain.bootstrap_context.artifact_digest,
        "bootstrap_context_record_digest": context.record_digest,
        "bootstrap_plan_artifact_digest": chain.bootstrap_plan.artifact_digest,
        "bootstrap_plan_digest": chain.bootstrap_plan.record.plan_digest,
        "bootstrap_execution_artifact_digest": (
            chain.bootstrap_execution.artifact_digest
        ),
        "bootstrap_evidence_artifact_digest": chain.bootstrap_evidence.artifact_digest,
        "bootstrap_evidence_digest": (
            chain.bootstrap_evidence.record.entry.evidence_digest
        ),
        "health_execution_artifact_digest": chain.health_execution.artifact_digest,
        "health_evidence_artifact_digest": chain.health_evidence.artifact_digest,
        "health_evidence_digest": health.evidence_digest,
        "health_checkpoint_artifact_digest": chain.health_checkpoint.artifact_digest,
        "health_checkpoint_digest": checkpoint.checkpoint_digest,
        "safety_context_artifact_digest": loaded.safety_context.artifact_digest,
        "safety_context_digest": safety_context.context_digest,
        "safety_evidence_artifact_digest": loaded.safety_evidence.artifact_digest,
        "safety_evidence_digest": safety_evidence.evidence_digest,
        "safety_reconciliation_artifact_digest": (
            loaded.safety_reconciliation.artifact_digest
        ),
        "safety_reconciliation_digest": reconciliation.reconciliation_digest,
        "post_configure_artifact_digest": context.post_configure_artifact_digest,
        "post_configure_record_digest": context.post_configure_record_digest,
        "terraform_verification_artifact_digest": (
            context.terraform_verification_artifact_digest
        ),
        "observation_artifact_digest": context.observation_artifact_digest,
        "inventory_artifact_digest": context.inventory_artifact_digest,
        "trust_artifact_digest": context.trust_artifact_digest,
        "readiness_artifact_digest": context.readiness_artifact_digest,
        "storage_evidence_artifact_digest": (context.storage_evidence_artifact_digest),
        "install_evidence_artifact_digest": (context.install_evidence_artifact_digest),
        "configure_evidence_artifact_digest": (
            context.configure_evidence_artifact_digest
        ),
        "catalog_digest": context.catalog_digest,
        "ansible_source_digest": context.ansible_source_digest,
        "playbook_source_digest": context.playbook_source_digest,
        "validated_chain_digest": _digest_object(validated_chain),
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
                "plan_target_count": chain.bootstrap_plan.record.target_count,
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
    return DeployScyllaJoinAuthorization(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployScyllaJoinAuthorization,
    *,
    state: DeployScyllaJoinAuthorizationArtifactState,
) -> DeployScyllaJoinAuthorizationReport:
    record = stored.record
    scope = record.scope
    return DeployScyllaJoinAuthorizationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        authorization_artifact_digest=stored.artifact_digest,
        authorization_digest=record.authorization_digest,
        authorization_state=record.authorization_state,
        stage=record.stage,
        scope_kind=record.scope_kind,
        classification=record.classification,
        confirmation_policy=record.confirmation_policy,
        approval_method=record.proof.approval_method,
        approval_state=record.proof.approval_state,
        narrow_approval_method=record.proof.narrow_approval_method,
        narrow_approval_state=record.proof.narrow_approval_state,
        proof_digest=record.proof.proof_digest,
        target_count=scope.target_count,
        target_digest=scope.target_digest,
        sequence=scope.sequence,
        mode=scope.mode,
        authorization_scope_digest=scope.scope_digest,
        survivor_count=scope.survivor_count,
        survivor_set_digest=scope.survivor_set_digest,
        active_seed_count=scope.active_seed_count,
        active_seed_set_digest=scope.active_seed_set_digest,
        topology_digest=scope.topology_digest,
        target_topology_digest=scope.target_topology_digest,
        schema_digest=scope.schema_digest,
        membership_digest=scope.membership_digest,
        seed_policy_digest=scope.seed_policy_digest,
        package_version_digest=scope.package_version_digest,
        storage_evidence_digest=scope.storage_evidence_digest,
        configuration_evidence_digest=scope.configuration_evidence_digest,
        capacity_evidence_digest=scope.capacity_evidence_digest,
        safety_context_digest=scope.safety_context_digest,
        safety_evidence_digest=scope.safety_evidence_digest,
        safety_reconciliation_digest=scope.safety_reconciliation_digest,
        safety_gate_set_digest=scope.safety_gate_set_digest,
        later_join_count=record.later_join_count,
        later_join_digest=record.later_join_digest,
        validated_chain_digest=record.validated_chain_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        journal_digest=record.journal_digest,
        consumed=record.consumed,
        execution_state=record.execution_state,
        finalization_state=record.finalization_state,
        public_workflow_state=record.public_workflow_state,
    )


def _scope_digest(scope: DeployScyllaJoinScope) -> str:
    return _scope_digest_from_values(scope.to_object())


def _scope_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    value["scope_digest"] = ""
    return _digest_object(value)


def _proof_digest(
    record: DeployScyllaJoinAuthorization,
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
            "schema_version": (
                ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION
            ),
            "stage": _STAGE,
        }
    )


def _authorization_digest(record: DeployScyllaJoinAuthorization) -> str:
    return _authorization_digest_from_values(record.to_object())


def _authorization_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for name, field in DeployScyllaJoinAuthorization.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["authorization_digest"] = ""
    return _digest_object(value)


def _cluster_identity_digest(cluster_uuid: uuid.UUID, cluster_name: str) -> str:
    validate_cluster_name(cluster_name)
    return _digest_object(
        {"cluster_name": cluster_name, "cluster_uuid": str(cluster_uuid)}
    )


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
        ".ansible-deploy-scylla-join-execution",
        ".ansible-deploy-scylla-join-evidence",
        ".ansible-deploy-post-scylla-join",
        ".ansible-scylla-remove",
        ".ansible-scylla-replace",
        ".ansible-scylla-repair",
        ".ansible-scylla-cleanup",
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Scylla join authorization history"
        ) from error
    prefix = str(operation_id)
    for entry in entries:
        if entry.name.startswith(prefix) and any(
            fragment in entry.name for fragment in forbidden_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy Scylla join authorization refuses execution "
                "or later membership history"
            )


def _refuse_ambiguous_authorization_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Scylla join authorization artifacts"
        ) from error
    canonical = str(operation_id)
    suffix = DEPLOY_SCYLLA_JOIN_AUTHORIZATION_FILENAME_SUFFIX
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
                "deploy Scylla join authorization artifacts are ambiguous"
            )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy Scylla join authorization paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy Scylla join authorization requires the matching held deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _digest_fields(value: object) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(value, name))
        for name in value.__dataclass_fields__  # type: ignore[attr-defined]
        if name.endswith("_digest") and isinstance(getattr(value, name), str)
    )


def _dataclass_object(
    value: object,
    *,
    nested_fields: set[str] | None = None,
) -> dict[str, object]:
    nested = nested_fields or set()
    result: dict[str, object] = {}
    for name in value.__dataclass_fields__:  # type: ignore[attr-defined]
        item = getattr(value, name)
        result[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(item, StrEnum)
            else item.to_object()
            if name in nested
            else item
        )
    return result


def _parse_dataclass(
    data_type: type[object],
    value: Mapping[str, object],
    *,
    integer_fields: set[str] | None = None,
    uuid_fields: set[str] | None = None,
    boolean_fields: set[str] | None = None,
    enum_fields: Mapping[str, type[StrEnum]] | None = None,
    skip_fields: set[str] | None = None,
    label: str,
) -> dict[str, object]:
    require_exact_keys(value, set(data_type.__dataclass_fields__), label)  # type: ignore[attr-defined]
    integers = integer_fields or set()
    uuids = uuid_fields or set()
    booleans = boolean_fields or set()
    enums = enum_fields or {}
    skipped = skip_fields or set()
    parsed: dict[str, object] = {}
    try:
        for name in data_type.__dataclass_fields__:  # type: ignore[attr-defined]
            if name in skipped:
                continue
            item = value[name]
            if name in integers:
                parsed[name] = _integer(item, name)
            elif name in uuids:
                parsed[name] = parse_uuid(require_string(value, name), name)
            elif name in booleans:
                parsed[name] = _boolean(item, name)
            elif name in enums:
                parsed[name] = enums[name](require_string(value, name))
            else:
                parsed[name] = require_string(value, name)
    except ValueError as error:
        raise StatePersistenceError(f"deploy Scylla {label} enum is invalid") from error
    return parsed


def _json_object(values: Mapping[str, object]) -> dict[str, object]:
    return {name: _json_value(item) for name, item in values.items()}


def _json_value(value: object) -> object:
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, Mapping):
        return {str(name): _json_value(item) for name, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if hasattr(value, "to_object"):
        return _json_value(value.to_object())
    return value


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise StatePersistenceError(f"deploy Scylla {label} is invalid")
    return cast(Mapping[str, object], value)


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"deploy Scylla {label} is invalid")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"deploy Scylla {label} is invalid")
    return value


def _positive_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"deploy Scylla {label} must be positive")


def _nonnegative_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StatePersistenceError(f"deploy Scylla {label} must be nonnegative")


__all__ = [
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_SCHEMA_VERSION",
    "DEPLOY_SCYLLA_JOIN_AUTHORIZATION_FILENAME_SUFFIX",
    "DeployScyllaJoinApprovalMethod",
    "DeployScyllaJoinAuthorization",
    "DeployScyllaJoinAuthorizationArtifactState",
    "DeployScyllaJoinAuthorizationProof",
    "DeployScyllaJoinAuthorizationReport",
    "DeployScyllaJoinAuthorizationStore",
    "DeployScyllaJoinNarrowApprovalMethod",
    "DeployScyllaJoinNarrowScopeProof",
    "DeployScyllaJoinProofDecision",
    "DeployScyllaJoinScope",
    "StoredDeployScyllaJoinAuthorization",
    "authorize_deploy_scylla_join_existing",
    "deploy_scylla_join_authorization_id_from_filename",
    "deploy_scylla_join_authorization_path",
]
