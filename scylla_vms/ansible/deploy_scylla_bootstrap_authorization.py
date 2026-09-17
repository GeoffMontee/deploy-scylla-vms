"""Immutable authorization for the exact deploy initial-seed bootstrap step.

This internal owner revalidates the complete post-configuration bootstrap
context and plan, derives the sole first membership-start scope from canonical
state, and persists an unconsumed, redacted authorization checkpoint.  It does
not accept caller targets or modes, authorize any join, invoke a process,
change the common journal, or expose public workflow wiring.
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
    DeployScyllaBootstrapContext,
    DeployScyllaBootstrapContextStore,
    DeployScyllaBootstrapNewClusterProof,
    DeployScyllaBootstrapPlan,
    DeployScyllaBootstrapPlanStep,
    DeployScyllaBootstrapPlanStore,
    DeployScyllaBootstrapProofState,
    DeployScyllaBootstrapStepStatus,
    StoredDeployScyllaBootstrapContext,
    StoredDeployScyllaBootstrapPlan,
    _build_context_record,
    _build_plan_record,
    _build_plan_steps,
    _load_planning_context,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import _loaded
from scylla_vms.ansible.deploy_scylla_configure_reconciliation import (
    _load_reconciliation_context,
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

ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-bootstrap-authorization-proof/v1"
)
ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-bootstrap-authorization/v1"
)
ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-bootstrap-authorization-report/v1"
)
DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-bootstrap-authorization.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "scylla-bootstrap"
_STAGE = "post-scylla-configure-bootstrap-initial-seed"
_SCOPE_KIND = "initial-seed-first-membership-start"
_EMPTY_CLUSTER_STATE = "proven-empty-new-cluster"
_INITIAL_HEALTH_CHECKPOINT = "not-required-before-initial-seed"
_JOIN_HEALTH_CHECKPOINT = "waiting-for-preceding-complete-health"
_INITIAL_AUTHORIZATION_BLOCKER = "bootstrap-authorization-not-collected"
_AUTHORIZED = "authorized-pre-execution"
_EXECUTION_UNAVAILABLE = "unavailable"
_FINALIZATION_NOT_STARTED = "not-started"
_PUBLIC_WORKFLOW_UNAVAILABLE = "unavailable"
_APPROVED = "approved"
_MATCHED = "matched"


class DeployScyllaBootstrapApprovalMethod(StrEnum):
    """PLAN-permitted ordinary confirmation methods for sensitive work."""

    INTERACTIVE = "interactive"
    CLI_YES = "cli-yes"


class DeployScyllaBootstrapNarrowApprovalMethod(StrEnum):
    """Sources that can acknowledge the exact irreversible first-start scope."""

    INTERACTIVE = "interactive"
    CLI_EXPLICIT = "cli-explicit"


class DeployScyllaBootstrapAuthorizationArtifactState(StrEnum):
    """Immutable authorization persistence result."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployScyllaBootstrapInitialSeedScope:
    """The sole redacted initial membership-start scope derived from the plan."""

    sequence: int
    mode: ScyllaBootstrapMode
    classification: OperationClassification
    confirmation_policy: ConfirmationPolicy
    target_count: int
    target_digest: str
    plan_step_digest: str
    order_digest: str
    topology_digest: str
    target_topology_digest: str
    seed_policy_digest: str
    package_version_digest: str
    storage_evidence_digest: str
    configuration_evidence_digest: str
    capacity_evidence_digest: str
    empty_cluster_proof_digest: str
    empty_cluster_state_digest: str
    prerequisite_digest: str
    playbook_source_digest: str
    scope_digest: str

    def __post_init__(self) -> None:
        if (
            self.sequence != 1
            or self.mode is not ScyllaBootstrapMode.INITIAL_SEED
            or self.classification is not OperationClassification.SENSITIVE
            or self.confirmation_policy is not ConfirmationPolicy.SENSITIVE
            or self.target_count != 1
            or self.scope_digest != _scope_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap initial-seed scope policy conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(value, "deploy Scylla bootstrap initial-seed scope digest")

    def to_object(self) -> dict[str, object]:
        return {
            name: value.value if isinstance(value, StrEnum) else value
            for name in self.__dataclass_fields__
            if (value := getattr(self, name)) is not None
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaBootstrapInitialSeedScope:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Scylla bootstrap initial-seed scope",
        )
        try:
            return cls(
                sequence=_integer(value["sequence"], "scope sequence"),
                mode=ScyllaBootstrapMode(require_string(value, "mode")),
                classification=OperationClassification(
                    require_string(value, "classification")
                ),
                confirmation_policy=ConfirmationPolicy(
                    require_string(value, "confirmation_policy")
                ),
                target_count=_integer(value["target_count"], "scope target count"),
                target_digest=require_string(value, "target_digest"),
                plan_step_digest=require_string(value, "plan_step_digest"),
                order_digest=require_string(value, "order_digest"),
                topology_digest=require_string(value, "topology_digest"),
                target_topology_digest=require_string(value, "target_topology_digest"),
                seed_policy_digest=require_string(value, "seed_policy_digest"),
                package_version_digest=require_string(value, "package_version_digest"),
                storage_evidence_digest=require_string(
                    value, "storage_evidence_digest"
                ),
                configuration_evidence_digest=require_string(
                    value, "configuration_evidence_digest"
                ),
                capacity_evidence_digest=require_string(
                    value, "capacity_evidence_digest"
                ),
                empty_cluster_proof_digest=require_string(
                    value, "empty_cluster_proof_digest"
                ),
                empty_cluster_state_digest=require_string(
                    value, "empty_cluster_state_digest"
                ),
                prerequisite_digest=require_string(value, "prerequisite_digest"),
                playbook_source_digest=require_string(value, "playbook_source_digest"),
                scope_digest=require_string(value, "scope_digest"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Scylla bootstrap initial-seed scope enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployScyllaBootstrapNarrowScopeProof:
    """Exact redacted scope acknowledgement; it cannot select a target or mode."""

    target_count: int
    target_digest: str
    plan_step_digest: str
    authorization_scope_digest: str

    def __post_init__(self) -> None:
        if self.target_count != 1:
            raise StateConflictError(
                "deploy Scylla bootstrap narrow scope must contain one target"
            )
        for value in (
            self.target_digest,
            self.plan_step_digest,
            self.authorization_scope_digest,
        ):
            validate_digest(value, "deploy Scylla bootstrap narrow scope digest")

    @classmethod
    def from_scope(
        cls, scope: DeployScyllaBootstrapInitialSeedScope
    ) -> DeployScyllaBootstrapNarrowScopeProof:
        if not isinstance(scope, DeployScyllaBootstrapInitialSeedScope):
            raise StateConflictError(
                "deploy Scylla bootstrap initial-seed scope is malformed"
            )
        return cls(
            target_count=scope.target_count,
            target_digest=scope.target_digest,
            plan_step_digest=scope.plan_step_digest,
            authorization_scope_digest=scope.scope_digest,
        )

    @classmethod
    def from_plan(
        cls,
        context: DeployScyllaBootstrapContext,
        plan: DeployScyllaBootstrapPlan,
    ) -> DeployScyllaBootstrapNarrowScopeProof:
        """Normalize an exact acknowledgement from immutable reviewed records."""

        return cls.from_scope(_derive_initial_seed_scope(context, plan))

    def to_object(self) -> dict[str, object]:
        return {
            "authorization_scope_digest": self.authorization_scope_digest,
            "plan_step_digest": self.plan_step_digest,
            "target_count": self.target_count,
            "target_digest": self.target_digest,
        }


@dataclass(frozen=True, slots=True)
class DeployScyllaBootstrapAuthorizationProof:
    """Already-normalized ordinary and narrow approval without free-form input."""

    approval_method: DeployScyllaBootstrapApprovalMethod | None = None
    approved: bool = False
    narrow_approval_method: DeployScyllaBootstrapNarrowApprovalMethod | None = None
    narrow_approved: bool = False
    narrow_scope: DeployScyllaBootstrapNarrowScopeProof | None = None
    allow_destructive: bool = False
    destructive_scope_provided: bool = False

    def __post_init__(self) -> None:
        if self.approval_method is not None and not isinstance(
            self.approval_method, DeployScyllaBootstrapApprovalMethod
        ):
            raise StateConflictError(
                "deploy Scylla bootstrap ordinary approval method is invalid"
            )
        if self.narrow_approval_method is not None and not isinstance(
            self.narrow_approval_method, DeployScyllaBootstrapNarrowApprovalMethod
        ):
            raise StateConflictError(
                "deploy Scylla bootstrap narrow approval method is invalid"
            )
        if self.narrow_scope is not None and not isinstance(
            self.narrow_scope, DeployScyllaBootstrapNarrowScopeProof
        ):
            raise StateConflictError(
                "deploy Scylla bootstrap narrow scope proof is malformed"
            )
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
                "deploy Scylla bootstrap authorization proof is malformed"
            )


@dataclass(frozen=True, slots=True)
class DeployScyllaBootstrapProofDecision:
    """Persisted proof decisions bound to the exact derived initial-seed scope."""

    approval_method: DeployScyllaBootstrapApprovalMethod
    approval_state: str
    narrow_approval_method: DeployScyllaBootstrapNarrowApprovalMethod
    narrow_approval_state: str
    target_count: int
    target_digest: str
    plan_step_digest: str
    authorization_scope_digest: str
    allow_destructive: bool
    destructive_scope_provided: bool
    proof_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or not isinstance(self.approval_method, DeployScyllaBootstrapApprovalMethod)
            or not isinstance(
                self.narrow_approval_method,
                DeployScyllaBootstrapNarrowApprovalMethod,
            )
            or self.approval_state != _APPROVED
            or self.narrow_approval_state != _MATCHED
            or self.target_count != 1
            or self.allow_destructive
            or self.destructive_scope_provided
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap authorization proof state conflicts"
            )
        for value in (
            self.target_digest,
            self.plan_step_digest,
            self.authorization_scope_digest,
            self.proof_digest,
        ):
            validate_digest(value, "deploy Scylla bootstrap proof digest")

    def to_object(self) -> dict[str, object]:
        return {
            "allow_destructive": self.allow_destructive,
            "approval_method": self.approval_method.value,
            "approval_state": self.approval_state,
            "authorization_scope_digest": self.authorization_scope_digest,
            "destructive_scope_provided": self.destructive_scope_provided,
            "narrow_approval_method": self.narrow_approval_method.value,
            "narrow_approval_state": self.narrow_approval_state,
            "plan_step_digest": self.plan_step_digest,
            "proof_digest": self.proof_digest,
            "schema_version": self.schema_version,
            "target_count": self.target_count,
            "target_digest": self.target_digest,
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaBootstrapProofDecision:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Scylla bootstrap authorization proof",
        )
        try:
            return cls(
                approval_method=DeployScyllaBootstrapApprovalMethod(
                    require_string(value, "approval_method")
                ),
                approval_state=require_string(value, "approval_state"),
                narrow_approval_method=DeployScyllaBootstrapNarrowApprovalMethod(
                    require_string(value, "narrow_approval_method")
                ),
                narrow_approval_state=require_string(value, "narrow_approval_state"),
                target_count=_integer(value["target_count"], "proof target count"),
                target_digest=require_string(value, "target_digest"),
                plan_step_digest=require_string(value, "plan_step_digest"),
                authorization_scope_digest=require_string(
                    value, "authorization_scope_digest"
                ),
                allow_destructive=_boolean(
                    value["allow_destructive"], "allow destructive"
                ),
                destructive_scope_provided=_boolean(
                    value["destructive_scope_provided"], "destructive scope"
                ),
                proof_digest=require_string(value, "proof_digest"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Scylla bootstrap authorization proof enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployScyllaBootstrapAuthorization:
    """Immutable unconsumed authorization for only the initial-seed start."""

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
    context_artifact_digest: str
    context_record_digest: str
    context_proof_digest: str
    plan_artifact_digest: str
    plan_digest: str
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
    scope: DeployScyllaBootstrapInitialSeedScope
    authorization_scope_digest: str
    join_waiting_count: int
    join_waiting_digest: str
    non_authorized_scope_digest: str
    proof: DeployScyllaBootstrapProofDecision
    authorization_state: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_digest: str
    context_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION
    plan_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_SCHEMA_VERSION
    proof_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_SCHEMA_VERSION
            or self.context_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION
            or self.plan_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_PROOF_SCHEMA_VERSION
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
            or not isinstance(self.scope, DeployScyllaBootstrapInitialSeedScope)
            or not isinstance(self.proof, DeployScyllaBootstrapProofDecision)
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap authorization identity or state conflicts"
            )
        parse_timestamp(self.created_at)
        _positive_integer(
            self.journal_generation,
            "deploy Scylla bootstrap authorization journal generation",
        )
        _nonnegative_integer(
            self.join_waiting_count,
            "deploy Scylla bootstrap authorization join count",
        )
        if (
            self.authorization_scope_digest != self.scope.scope_digest
            or self.proof.target_count != self.scope.target_count
            or self.proof.target_digest != self.scope.target_digest
            or self.proof.plan_step_digest != self.scope.plan_step_digest
            or self.proof.authorization_scope_digest != self.authorization_scope_digest
            or self.proof.proof_digest != _proof_digest(self, self.proof.to_object())
            or self.authorization_digest != _authorization_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap authorization scope or proof conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(value, "deploy Scylla bootstrap authorization digest")

    def to_object(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            result[name] = (
                str(value)
                if isinstance(value, uuid.UUID)
                else value.value
                if isinstance(value, StrEnum)
                else value.to_object()
                if name in {"scope", "proof"}
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaBootstrapAuthorization:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Scylla bootstrap authorization",
        )
        integer_fields = {"generation", "journal_generation", "join_waiting_count"}
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in integer_fields:
                    parsed[name] = _integer(item, name)
                elif name in {"cluster_uuid", "operation_id"}:
                    parsed[name] = parse_uuid(require_string(value, name), name)
                elif name == "journal_status":
                    parsed[name] = JournalStatus(require_string(value, name))
                elif name == "journal_phase":
                    parsed[name] = OperationPhase(require_string(value, name))
                elif name == "classification":
                    parsed[name] = OperationClassification(require_string(value, name))
                elif name == "confirmation_policy":
                    parsed[name] = ConfirmationPolicy(require_string(value, name))
                elif name == "scope":
                    parsed[name] = DeployScyllaBootstrapInitialSeedScope.from_object(
                        _mapping(item, "initial-seed scope")
                    )
                elif name == "proof":
                    parsed[name] = DeployScyllaBootstrapProofDecision.from_object(
                        _mapping(item, "authorization proof")
                    )
                elif name == "consumed":
                    parsed[name] = _boolean(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Scylla bootstrap authorization enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaBootstrapAuthorization:
    record: DeployScyllaBootstrapAuthorization
    artifact_digest: str


class DeployScyllaBootstrapAuthorizationStore:
    """Owner-only immutable authorization at the canonical operation path."""

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
        self._path = deploy_scylla_bootstrap_authorization_path(paths, operation_id)
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
    ) -> StoredDeployScyllaBootstrapAuthorization:
        value, artifact_digest = self._file.read()
        record = DeployScyllaBootstrapAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_identity_digest
            != _cluster_identity_digest(expected_cluster_uuid, expected_cluster_name)
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap authorization identity conflicts"
            )
        return StoredDeployScyllaBootstrapAuthorization(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaBootstrapAuthorization:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaBootstrapAuthorization,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployScyllaBootstrapAuthorization,
        DeployScyllaBootstrapAuthorizationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy Scylla bootstrap authorization operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=self._paths.cluster_root.name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy Scylla bootstrap authorization is immutable; "
                    "use a new operation"
                )
            return (
                current,
                DeployScyllaBootstrapAuthorizationArtifactState.REUSED,
            )
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaBootstrapAuthorization(record, artifact_digest),
            DeployScyllaBootstrapAuthorizationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaBootstrapAuthorizationReport:
    """Strict digest/count/enum-only authorization projection."""

    operation_id: uuid.UUID
    artifact_state: DeployScyllaBootstrapAuthorizationArtifactState
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_state: str
    stage: str
    scope_kind: str
    classification: OperationClassification
    confirmation_policy: ConfirmationPolicy
    approval_method: DeployScyllaBootstrapApprovalMethod
    approval_state: str
    narrow_approval_method: DeployScyllaBootstrapNarrowApprovalMethod
    narrow_approval_state: str
    proof_digest: str
    target_count: int
    target_digest: str
    mode: ScyllaBootstrapMode
    plan_step_digest: str
    authorization_scope_digest: str
    order_digest: str
    topology_digest: str
    seed_policy_digest: str
    package_version_digest: str
    storage_evidence_digest: str
    configuration_evidence_digest: str
    capacity_evidence_digest: str
    empty_cluster_proof_digest: str
    join_waiting_count: int
    join_waiting_digest: str
    context_artifact_digest: str
    plan_artifact_digest: str
    validated_chain_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    journal_digest: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_SCHEMA_VERSION
    )
    proof_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    context_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION
    plan_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or self.context_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION
            or self.plan_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_SCHEMA_VERSION
            or self.authorization_state != _AUTHORIZED
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.classification is not OperationClassification.SENSITIVE
            or self.confirmation_policy is not ConfirmationPolicy.SENSITIVE
            or self.approval_state != _APPROVED
            or self.narrow_approval_state != _MATCHED
            or self.target_count != 1
            or self.mode is not ScyllaBootstrapMode.INITIAL_SEED
            or self.join_waiting_count < 0
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap authorization report conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(
                value, "deploy Scylla bootstrap authorization report digest"
            )

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
            "joins": {
                "digest": self.join_waiting_digest,
                "waiting_count": self.join_waiting_count,
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
                "context_artifact_digest": self.context_artifact_digest,
                "context_schema_version": self.context_schema_version,
                "plan_artifact_digest": self.plan_artifact_digest,
                "plan_schema_version": self.plan_schema_version,
                "validated_chain_digest": self.validated_chain_digest,
            },
            "result": self.artifact_state.value,
            "schema_version": self.schema_version,
            "scope": {
                "authorization_scope_digest": self.authorization_scope_digest,
                "capacity_evidence_digest": self.capacity_evidence_digest,
                "configuration_evidence_digest": (self.configuration_evidence_digest),
                "empty_cluster_proof_digest": self.empty_cluster_proof_digest,
                "mode": self.mode.value,
                "order_digest": self.order_digest,
                "package_version_digest": self.package_version_digest,
                "plan_step_digest": self.plan_step_digest,
                "seed_policy_digest": self.seed_policy_digest,
                "storage_evidence_digest": self.storage_evidence_digest,
                "target_count": self.target_count,
                "target_digest": self.target_digest,
                "topology_digest": self.topology_digest,
            },
            "stage": self.stage,
        }


@dataclass(frozen=True, slots=True)
class _AuthorizationContext:
    context: StoredDeployScyllaBootstrapContext
    plan: StoredDeployScyllaBootstrapPlan


def authorize_deploy_scylla_bootstrap_initial_seed(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proof: DeployScyllaBootstrapAuthorizationProof,
) -> DeployScyllaBootstrapAuthorizationReport:
    """Authorize only the exact canonical initial-seed step without execution."""

    if not isinstance(proof, DeployScyllaBootstrapAuthorizationProof):
        raise StateConflictError(
            "deploy Scylla bootstrap authorization proof is malformed"
        )
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_authorization_artifacts(paths, operation_id)
    _refuse_incompatible_or_later_artifacts(paths, operation_id)
    loaded = _load_authorization_context(paths, operation_id, lock=lock)
    scope = _derive_initial_seed_scope(loaded.context.record, loaded.plan.record)
    decision = _normalize_proof(
        proof,
        context=loaded.context,
        plan=loaded.plan,
        scope=scope,
    )
    store = DeployScyllaBootstrapAuthorizationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    if store.path.exists():
        stored = store.read_locked(
            lock,
            expected_cluster_uuid=loaded.context.record.cluster_uuid,
            expected_cluster_name=loaded.context.record.cluster_name,
        )
        expected = _build_authorization(
            loaded,
            scope=scope,
            proof=decision,
            created_at=stored.record.created_at,
        )
        if stored.record != expected:
            raise StateConflictError(
                "deploy Scylla bootstrap authorization changed; "
                "re-plan with a new operation"
            )
        state = DeployScyllaBootstrapAuthorizationArtifactState.REUSED
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
                "deploy Scylla bootstrap authorization persistence failed"
            ) from error
    return _build_report(stored, state=state)


def deploy_scylla_bootstrap_authorization_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the canonical operation-bound initial-seed authorization path."""

    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Scylla bootstrap authorization path is not canonical"
        )
    return path


def deploy_scylla_bootstrap_authorization_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_FILENAME_SUFFIX):
        return None
    value = name[: -len(DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_FILENAME_SUFFIX)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _load_authorization_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
) -> _AuthorizationContext:
    # Load through post-configuration first so the stores can verify exact identity.
    chain = _load_reconciliation_context(paths, operation_id, lock=lock)
    metadata = _loaded(chain.authorization_context).planning.base.deploy.metadata.record
    context_store = DeployScyllaBootstrapContextStore(paths, operation_id)
    plan_store = DeployScyllaBootstrapPlanStore(paths, operation_id)
    for path, label in (
        (context_store.path, "bootstrap context"),
        (plan_store.path, "bootstrap plan"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"deploy Scylla bootstrap authorization requires exact {label}"
            )
    context = context_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    plan = plan_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    context_record = context.record
    if (
        not context_record.proof_collected
        or context_record.empty_cluster_state != _EMPTY_CLUSTER_STATE
        or context_record.blockers
        or any(
            state is not DeployScyllaBootstrapProofState.CONFIRMED
            for state in (
                context_record.proof_new_cluster_intent,
                context_record.proof_empty_cluster_review,
                context_record.proof_prior_membership_absence,
                context_record.proof_capacity_sufficiency,
            )
        )
    ):
        raise StateConflictError(
            "deploy Scylla bootstrap authorization requires complete exact "
            "empty-cluster proof"
        )
    reviewed_proof = DeployScyllaBootstrapNewClusterProof(
        new_cluster_intent=context_record.proof_new_cluster_intent,
        empty_cluster_review=context_record.proof_empty_cluster_review,
        prior_membership_absence=context_record.proof_prior_membership_absence,
        capacity_sufficiency=context_record.proof_capacity_sufficiency,
    )
    planning = _load_planning_context(
        paths, operation_id, lock=lock, proof=reviewed_proof
    )
    expected_context = _build_context_record(
        planning, created_at=context_record.created_at
    )
    if context_record != expected_context:
        raise StateConflictError(
            "deploy Scylla bootstrap authorization context drifted; use a new operation"
        )
    expected_steps = _build_plan_steps(context_record, planning.targets)
    expected_plan = _build_plan_record(
        context,
        steps=expected_steps,
        created_at=plan.record.created_at,
    )
    if plan.record != expected_plan:
        raise StateConflictError(
            "deploy Scylla bootstrap authorization plan drifted; use a new operation"
        )
    return _AuthorizationContext(context, plan)


def _derive_initial_seed_scope(
    context: DeployScyllaBootstrapContext,
    plan: DeployScyllaBootstrapPlan,
) -> DeployScyllaBootstrapInitialSeedScope:
    definition = get_playbook(_PLAYBOOK)
    if (
        definition.classification is not OperationClassification.SENSITIVE
        or definition.check_mode is not CheckMode.REFUSED
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.serial != 1
        or not definition.any_errors_fatal
        or not definition.source_available
    ):
        raise StateConflictError(
            "deploy Scylla bootstrap catalog classification or policy conflicts"
        )
    if (
        context.empty_cluster_state != _EMPTY_CLUSTER_STATE
        or context.blockers
        or not context.proof_collected
        or context.authorization_state != _EXECUTION_UNAVAILABLE
        or plan.context_record_digest != context.record_digest
        or plan.request_digest != context.request_digest
        or plan.journal_generation != context.journal_generation
        or plan.journal_digest != context.journal_digest
        or plan.target_count != context.target_count
        or plan.target_set_digest != context.target_set_digest
        or plan.order_digest != context.order_digest
        or plan.authorization_required_count != 1
        or plan.blocked_count
        or plan.waiting_health_count != plan.target_count - 1
    ):
        raise StateConflictError(
            "deploy Scylla bootstrap initial-seed authorization gates conflict"
        )
    initial, joins = _partition_authorizable_steps(plan.steps)
    if (
        initial.sequence != 1
        or initial.mode is not ScyllaBootstrapMode.INITIAL_SEED
        or initial.status is not DeployScyllaBootstrapStepStatus.AUTHORIZATION_REQUIRED
        or initial.health_checkpoint_state != _INITIAL_HEALTH_CHECKPOINT
        or initial.preceding_step_digest is not None
        or initial.blockers != (_INITIAL_AUTHORIZATION_BLOCKER,)
        or initial.playbook_source_digest != context.playbook_source_digest
        or len(joins) != plan.target_count - 1
    ):
        raise StateConflictError(
            "only the exact first initial-seed step may be authorized"
        )
    values: dict[str, object] = {
        "sequence": initial.sequence,
        "mode": initial.mode,
        "classification": OperationClassification.SENSITIVE,
        "confirmation_policy": ConfirmationPolicy.SENSITIVE,
        "target_count": 1,
        "target_digest": initial.target_digest,
        "plan_step_digest": initial.step_digest,
        "order_digest": plan.order_digest,
        "topology_digest": context.topology_digest,
        "target_topology_digest": initial.topology_digest,
        "seed_policy_digest": initial.seed_policy_digest,
        "package_version_digest": initial.package_version_digest,
        "storage_evidence_digest": initial.storage_evidence_digest,
        "configuration_evidence_digest": initial.configuration_evidence_digest,
        "capacity_evidence_digest": initial.capacity_evidence_digest,
        "empty_cluster_proof_digest": context.proof_digest,
        "empty_cluster_state_digest": _digest_object(context.empty_cluster_state),
        "prerequisite_digest": initial.prerequisite_digest,
        "playbook_source_digest": initial.playbook_source_digest,
        "scope_digest": "",
    }
    values["scope_digest"] = _scope_digest_from_values(values)
    return DeployScyllaBootstrapInitialSeedScope(**values)  # type: ignore[arg-type]


def _partition_authorizable_steps(
    steps: tuple[DeployScyllaBootstrapPlanStep, ...],
) -> tuple[
    DeployScyllaBootstrapPlanStep,
    tuple[DeployScyllaBootstrapPlanStep, ...],
]:
    if not steps:
        raise StateConflictError("deploy Scylla bootstrap plan has no initial seed")
    initial = steps[0]
    joins = steps[1:]
    preceding = initial.step_digest
    for expected_sequence, step in enumerate(joins, start=2):
        if (
            step.sequence != expected_sequence
            or step.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or step.status
            is not DeployScyllaBootstrapStepStatus.WAITING_FOR_HEALTH_CHECKPOINT
            or step.health_checkpoint_state != _JOIN_HEALTH_CHECKPOINT
            or step.preceding_step_digest != preceding
            or _INITIAL_AUTHORIZATION_BLOCKER not in step.blockers
        ):
            raise StateConflictError(
                "deploy Scylla bootstrap join scope is not waiting for health"
            )
        preceding = step.step_digest
    return initial, joins


def _normalize_proof(
    proof: DeployScyllaBootstrapAuthorizationProof,
    *,
    context: StoredDeployScyllaBootstrapContext,
    plan: StoredDeployScyllaBootstrapPlan,
    scope: DeployScyllaBootstrapInitialSeedScope,
) -> DeployScyllaBootstrapProofDecision:
    if proof.approval_method is None:
        raise StateConflictError(
            "ordinary deploy Scylla bootstrap approval is required"
        )
    if not proof.approved:
        raise StateConflictError("ordinary deploy Scylla bootstrap approval was denied")
    if proof.allow_destructive or proof.destructive_scope_provided:
        raise StateConflictError(
            "destructive proof is inapplicable to sensitive initial-seed bootstrap"
        )
    if proof.narrow_approval_method is None or not proof.narrow_approved:
        raise StateConflictError(
            "exact initial-seed scope approval is required; --yes alone is insufficient"
        )
    expected_scope = DeployScyllaBootstrapNarrowScopeProof.from_scope(scope)
    if proof.narrow_scope != expected_scope:
        raise StateConflictError(
            "initial-seed scope approval does not match the exact reviewed plan"
        )
    values: dict[str, object] = {
        "approval_method": proof.approval_method.value,
        "approval_state": _APPROVED,
        "narrow_approval_method": proof.narrow_approval_method.value,
        "narrow_approval_state": _MATCHED,
        "target_count": expected_scope.target_count,
        "target_digest": expected_scope.target_digest,
        "plan_step_digest": expected_scope.plan_step_digest,
        "authorization_scope_digest": expected_scope.authorization_scope_digest,
        "allow_destructive": False,
        "destructive_scope_provided": False,
        "proof_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_PROOF_SCHEMA_VERSION
        ),
    }
    values["proof_digest"] = _proof_digest_values(
        cluster_uuid=context.record.cluster_uuid,
        operation_id=context.record.operation_id,
        journal_digest=context.record.journal_digest,
        context_artifact_digest=context.artifact_digest,
        context_record_digest=context.record.record_digest,
        plan_artifact_digest=plan.artifact_digest,
        plan_digest=plan.record.plan_digest,
        scope_digest=scope.scope_digest,
        proof=values,
    )
    return DeployScyllaBootstrapProofDecision.from_object(values)


def _build_authorization(
    loaded: _AuthorizationContext,
    *,
    scope: DeployScyllaBootstrapInitialSeedScope,
    proof: DeployScyllaBootstrapProofDecision,
    created_at: str,
) -> DeployScyllaBootstrapAuthorization:
    context = loaded.context.record
    plan = loaded.plan.record
    _, joins = _partition_authorizable_steps(plan.steps)
    join_values = [
        {
            "blocker_digest": step.blocker_digest,
            "health_checkpoint_state": step.health_checkpoint_state,
            "mode": step.mode.value,
            "sequence": step.sequence,
            "status": step.status.value,
            "step_digest": step.step_digest,
        }
        for step in joins
    ]
    validated_chain = {
        "ansible_source_digest": context.ansible_source_digest,
        "catalog_digest": context.catalog_digest,
        "configure_evidence_artifact_digest": (
            context.configure_evidence_artifact_digest
        ),
        "context_artifact_digest": loaded.context.artifact_digest,
        "context_record_digest": context.record_digest,
        "install_evidence_artifact_digest": context.install_evidence_artifact_digest,
        "inventory_artifact_digest": context.inventory_artifact_digest,
        "journal_digest": context.journal_digest,
        "observation_artifact_digest": context.observation_artifact_digest,
        "plan_artifact_digest": loaded.plan.artifact_digest,
        "plan_digest": plan.plan_digest,
        "post_configure_artifact_digest": context.post_configure_artifact_digest,
        "post_configure_record_digest": context.post_configure_record_digest,
        "readiness_artifact_digest": context.readiness_artifact_digest,
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
        "context_artifact_digest": loaded.context.artifact_digest,
        "context_record_digest": context.record_digest,
        "context_proof_digest": context.proof_digest,
        "plan_artifact_digest": loaded.plan.artifact_digest,
        "plan_digest": plan.plan_digest,
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
        "install_evidence_artifact_digest": context.install_evidence_artifact_digest,
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
        "join_waiting_count": len(joins),
        "join_waiting_digest": _digest_object(join_values),
        "non_authorized_scope_digest": _digest_object(
            {
                "join_waiting_count": len(joins),
                "join_waiting_digest": _digest_object(join_values),
                "plan_target_count": plan.target_count,
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
    return DeployScyllaBootstrapAuthorization(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployScyllaBootstrapAuthorization,
    *,
    state: DeployScyllaBootstrapAuthorizationArtifactState,
) -> DeployScyllaBootstrapAuthorizationReport:
    record = stored.record
    scope = record.scope
    return DeployScyllaBootstrapAuthorizationReport(
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
        mode=scope.mode,
        plan_step_digest=scope.plan_step_digest,
        authorization_scope_digest=record.authorization_scope_digest,
        order_digest=scope.order_digest,
        topology_digest=scope.topology_digest,
        seed_policy_digest=scope.seed_policy_digest,
        package_version_digest=scope.package_version_digest,
        storage_evidence_digest=scope.storage_evidence_digest,
        configuration_evidence_digest=scope.configuration_evidence_digest,
        capacity_evidence_digest=scope.capacity_evidence_digest,
        empty_cluster_proof_digest=scope.empty_cluster_proof_digest,
        join_waiting_count=record.join_waiting_count,
        join_waiting_digest=record.join_waiting_digest,
        context_artifact_digest=record.context_artifact_digest,
        plan_artifact_digest=record.plan_artifact_digest,
        validated_chain_digest=record.validated_chain_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        journal_digest=record.journal_digest,
        consumed=record.consumed,
        execution_state=record.execution_state,
        finalization_state=record.finalization_state,
        public_workflow_state=record.public_workflow_state,
    )


def _scope_digest(scope: DeployScyllaBootstrapInitialSeedScope) -> str:
    return _scope_digest_from_values(scope.to_object())


def _scope_digest_from_values(values: Mapping[str, object]) -> str:
    projected = {
        name: item.value if isinstance(item, StrEnum) else item
        for name, item in values.items()
    }
    projected["scope_digest"] = ""
    return _digest_object(projected)


def _proof_digest(
    record: DeployScyllaBootstrapAuthorization,
    proof: Mapping[str, object],
) -> str:
    return _proof_digest_values(
        cluster_uuid=record.cluster_uuid,
        operation_id=record.operation_id,
        journal_digest=record.journal_digest,
        context_artifact_digest=record.context_artifact_digest,
        context_record_digest=record.context_record_digest,
        plan_artifact_digest=record.plan_artifact_digest,
        plan_digest=record.plan_digest,
        scope_digest=record.authorization_scope_digest,
        proof=proof,
    )


def _proof_digest_values(
    *,
    cluster_uuid: uuid.UUID,
    operation_id: uuid.UUID,
    journal_digest: str,
    context_artifact_digest: str,
    context_record_digest: str,
    plan_artifact_digest: str,
    plan_digest: str,
    scope_digest: str,
    proof: Mapping[str, object],
) -> str:
    proof_value = dict(proof)
    proof_value["proof_digest"] = ""
    return _digest_object(
        {
            "authorization_scope_digest": scope_digest,
            "cluster_uuid": str(cluster_uuid),
            "context_artifact_digest": context_artifact_digest,
            "context_record_digest": context_record_digest,
            "journal_digest": journal_digest,
            "operation": _OPERATION,
            "operation_id": str(operation_id),
            "plan_artifact_digest": plan_artifact_digest,
            "plan_digest": plan_digest,
            "proof": proof_value,
            "schema_version": (
                ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_PROOF_SCHEMA_VERSION
            ),
            "stage": _STAGE,
        }
    )


def _authorization_digest(record: DeployScyllaBootstrapAuthorization) -> str:
    return _authorization_digest_from_values(record.to_object())


def _authorization_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployScyllaBootstrapAuthorization.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(item, StrEnum)
            else item.to_object()
            if name == "scope"
            and isinstance(item, DeployScyllaBootstrapInitialSeedScope)
            else item.to_object()
            if name == "proof" and isinstance(item, DeployScyllaBootstrapProofDecision)
            else item
        )
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
        ".ansible-deploy-scylla-bootstrap-execution",
        ".ansible-deploy-scylla-bootstrap-evidence",
        ".ansible-deploy-post-scylla-bootstrap",
        ".ansible-deploy-scylla-health",
        ".ansible-scylla-bootstrap",
        ".ansible-scylla-health",
        ".ansible-scylla-remove",
        ".ansible-scylla-replace",
        ".ansible-scylla-repair",
        ".ansible-scylla-cleanup",
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Scylla bootstrap authorization history"
        ) from error
    prefix = str(operation_id)
    for entry in entries:
        if entry.name.startswith(prefix) and any(
            fragment in entry.name for fragment in forbidden_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy Scylla bootstrap authorization refuses execution "
                "or later membership history"
            )


def _refuse_ambiguous_authorization_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Scylla bootstrap authorization artifacts"
        ) from error
    canonical = str(operation_id)
    suffix = DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_FILENAME_SUFFIX
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
                "deploy Scylla bootstrap authorization artifacts are ambiguous"
            )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy Scylla bootstrap authorization paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy Scylla bootstrap authorization requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _digest_fields(value: object) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(value, name))
        for name in value.__dataclass_fields__  # type: ignore[attr-defined]
        if name.endswith("_digest") and isinstance(getattr(value, name), str)
    )


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _positive_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


def _nonnegative_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StatePersistenceError(f"{label} must be nonnegative")


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be a boolean")
    return value


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


__all__ = [
    "ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_PROOF_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_SCHEMA_VERSION",
    "DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_FILENAME_SUFFIX",
    "DeployScyllaBootstrapApprovalMethod",
    "DeployScyllaBootstrapAuthorization",
    "DeployScyllaBootstrapAuthorizationArtifactState",
    "DeployScyllaBootstrapAuthorizationProof",
    "DeployScyllaBootstrapAuthorizationReport",
    "DeployScyllaBootstrapAuthorizationStore",
    "DeployScyllaBootstrapInitialSeedScope",
    "DeployScyllaBootstrapNarrowApprovalMethod",
    "DeployScyllaBootstrapNarrowScopeProof",
    "DeployScyllaBootstrapProofDecision",
    "StoredDeployScyllaBootstrapAuthorization",
    "authorize_deploy_scylla_bootstrap_initial_seed",
    "deploy_scylla_bootstrap_authorization_id_from_filename",
    "deploy_scylla_bootstrap_authorization_path",
]
