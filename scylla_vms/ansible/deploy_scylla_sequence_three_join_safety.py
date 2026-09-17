"""Operation-specific safety ownership for deploy bootstrap sequence three.

This subprocess-free owner reloads the exact successful sequence-two join and
fresh complete-set post-join health chain, derives only the immediate
sequence-three ``join-existing`` target, and persists immutable redacted safety
context, evidence, and reconciliation records.  It never authorizes or
executes the join and never changes the common journal.
"""

from __future__ import annotations

import os
import uuid
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Generic, Protocol, TypeVar, cast

from scylla_vms.ansible.deploy_plan import _digest_object, _require_operation_id
from scylla_vms.ansible.deploy_scylla_bootstrap_plan import (
    DeployScyllaBootstrapPlanStep,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import _loaded
from scylla_vms.ansible.deploy_scylla_configure_reconciliation import (
    _load_reconciliation_context,
)
from scylla_vms.ansible.deploy_scylla_health_checkpoint import (
    DeployScyllaHealthExecutionState,
    DeployScyllaHealthStepStatus,
)
from scylla_vms.ansible.deploy_scylla_join_authorization import (
    DeployScyllaJoinAuthorizationStore,
    StoredDeployScyllaJoinAuthorization,
    _build_authorization,
    _derive_first_join_scope,
    _load_join_authorization_context,
)
from scylla_vms.ansible.deploy_scylla_join_execution import (
    DeployScyllaJoinEvidenceStore,
    DeployScyllaJoinExecutionState,
    DeployScyllaJoinExecutionStore,
    StoredDeployScyllaJoinEvidence,
    StoredDeployScyllaJoinExecution,
)
from scylla_vms.ansible.deploy_scylla_join_safety import (
    ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION,
    DeployScyllaJoinSafetyProof,
    DeployScyllaJoinSafetyProofStatus,
    _array,
    _dataclass_object,
    _digest_fields,
    _json_object,
    _mapping,
    _parse_dataclass,
)
from scylla_vms.ansible.deploy_scylla_post_join_health import (
    ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_SCHEMA_VERSION,
    DeployScyllaPostJoinHealthEvidenceStore,
    DeployScyllaPostJoinHealthExecutionStore,
    DeployScyllaPostJoinHealthReconciliationStore,
    DeployScyllaPostJoinHealthStep,
    StoredDeployScyllaPostJoinHealthEvidence,
    StoredDeployScyllaPostJoinHealthExecution,
    StoredDeployScyllaPostJoinHealthReconciliation,
)
from scylla_vms.ansible.scylla_bootstrap import (
    MutationBoundary,
    ScyllaBootstrapMode,
    ScyllaBootstrapStatus,
)
from scylla_vms.ansible.scylla_health import HealthCheckStatus
from scylla_vms.ansible.scylla_install import SCYLLA_PACKAGE_VERSION
from scylla_vms.desired import HostRole
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.journal import (
    JOURNAL_SCHEMA_VERSION,
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.persistence import (
    AtomicJsonFile,
    format_timestamp,
    parse_timestamp,
    validate_digest,
)
from scylla_vms.state import (
    StatePaths,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)

ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-sequence-three-join-safety-context/v1"
)
ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_GATE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-sequence-three-join-safety-gate/v1"
)
ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-sequence-three-join-safety-evidence/v1"
)
ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_STEP_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-sequence-three-join-safety-step/v1"
)
ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-sequence-three-join-safety-"
    "reconciliation/v1"
)
ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-sequence-three-join-safety-report/v1"
)

DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-sequence-three-join-safety-context.json"
)
DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-sequence-three-join-safety-evidence.json"
)
DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-sequence-three-join-safety-reconciliation.json"
)

_OPERATION = "deploy"
_STAGE = "pre-sequence-three-join-safety"
_TARGET_SEQUENCE = 3
_CURRENT_MEMBER_COUNT = 2
_EXTERNAL_GATES = ("backup-policy", "capacity", "quorum", "replication")
_HEALTH_GATES = (
    "completed-prior-membership",
    "cross-view-consistency",
    "membership",
    "schema",
    "seed-health",
    "service-api-cql",
    "streaming",
    "survivor-health",
    "target-absence",
    "topology",
)
_CURRENT_STATE_GATES = (
    "configuration-provenance",
    "no-competing-operation",
    "route-trust-readiness",
    "storage-provenance",
)
_REQUIRED_GATES = tuple(
    sorted((*_EXTERNAL_GATES, *_HEALTH_GATES, *_CURRENT_STATE_GATES))
)
_AUTHORIZATION_REQUIRED = "authorization-required"
_AUTHORIZATION_NOT_CREATED = "not-created"
_EXECUTION_UNAVAILABLE = "unavailable"
_PUBLIC_WORKFLOW_UNAVAILABLE = "unavailable"


class DeployScyllaSequenceThreeSafetyArtifactState(StrEnum):
    CREATED = "created"
    REUSED = "reused"


class DeployScyllaSequenceThreeSafetyGateSource(StrEnum):
    CURRENT_CANONICAL_STATE = "current-canonical-state"
    INDEPENDENT_POLICY_PROOF = "independent-policy-proof"
    POST_JOIN_HEALTH = "post-join-health"


class DeployScyllaSequenceThreeSafetyStepStatus(StrEnum):
    HEALTH_SUCCEEDED = "health-succeeded"
    AUTHORIZATION_REQUIRED = "authorization-required"
    BLOCKED = "blocked"
    WAITING = "waiting-for-preceding-complete-health"


@dataclass(frozen=True, slots=True)
class DeployScyllaSequenceThreeSafetyContext:
    generation: int
    created_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    stage: str
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
    current_state_digest: str
    validated_chain_digest: str
    target_sequence: int
    target_digest: str
    target_plan_step_digest: str
    target_topology_digest: str
    target_storage_evidence_digest: str
    target_configuration_evidence_digest: str
    target_capacity_evidence_digest: str
    target_package_version_digest: str
    playbook_source_digest: str
    survivor_count: int
    survivor_set_digest: str
    survivor_health_digest: str
    active_seed_count: int
    active_seed_set_digest: str
    current_topology_digest: str
    current_schema_digest: str
    current_membership_digest: str
    current_host_mapping_digest: str
    required_gates: tuple[str, ...]
    proof_set_digest: str
    policy_digest: str
    context_digest: str
    proof_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION
    post_join_health_execution_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_SCHEMA_VERSION
    )
    post_join_health_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EVIDENCE_SCHEMA_VERSION
    )
    post_join_health_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION
            or self.post_join_health_execution_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_SCHEMA_VERSION
            or self.post_join_health_evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EVIDENCE_SCHEMA_VERSION
            or self.post_join_health_reconciliation_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.target_sequence != _TARGET_SEQUENCE
            or self.survivor_count != _CURRENT_MEMBER_COUNT
            or self.active_seed_count != 1
            or self.required_gates != _REQUIRED_GATES
            or self.policy_digest
            != _digest_object(
                {
                    "current_member_count": _CURRENT_MEMBER_COUNT,
                    "required_gates": list(_REQUIRED_GATES),
                    "target_sequence": _TARGET_SEQUENCE,
                }
            )
            or self.context_digest != _context_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla sequence-three safety context conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "sequence-three safety context digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, tuple_fields={"required_gates"})

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaSequenceThreeSafetyContext:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={
                "generation",
                "journal_generation",
                "target_sequence",
                "survivor_count",
                "active_seed_count",
            },
            uuid_fields={"cluster_uuid", "operation_id"},
            tuple_fields={"required_gates"},
            enum_fields={
                "journal_status": JournalStatus,
                "journal_phase": OperationPhase,
            },
            label="sequence-three safety context",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaSequenceThreeSafetyGate:
    name: str
    required: bool
    status: DeployScyllaJoinSafetyProofStatus
    source: DeployScyllaSequenceThreeSafetyGateSource
    captured_at: str
    evidence_digest: str
    binding_digest: str
    gate_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_GATE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_GATE_SCHEMA_VERSION
            or self.name not in _REQUIRED_GATES
            or not self.required
            or self.gate_digest != _gate_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla sequence-three safety gate conflicts"
            )
        parse_timestamp(self.captured_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "sequence-three safety gate digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaSequenceThreeSafetyGate:
        parsed = _parse_dataclass(
            cls,
            value,
            boolean_fields={"required"},
            enum_fields={
                "status": DeployScyllaJoinSafetyProofStatus,
                "source": DeployScyllaSequenceThreeSafetyGateSource,
            },
            label="sequence-three safety gate",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaSequenceThreeSafetyEvidence:
    generation: int
    created_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    context_artifact_digest: str
    context_digest: str
    proofs: tuple[DeployScyllaJoinSafetyProof, ...]
    proof_count: int
    proof_set_digest: str
    gates: tuple[DeployScyllaSequenceThreeSafetyGate, ...]
    gate_count: int
    passed_count: int
    failed_count: int
    unknown_count: int
    not_applicable_count: int
    blockers: tuple[str, ...]
    blocker_digest: str
    ready_for_authorization: bool
    authorization_state: str
    execution_state: str
    public_workflow_state: str
    evidence_digest: str
    context_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_SCHEMA_VERSION
    )
    proof_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION
    gate_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_GATE_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_EVIDENCE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        counts = Counter(gate.status for gate in self.gates)
        ready = all(
            gate.status is DeployScyllaJoinSafetyProofStatus.PASSED
            for gate in self.gates
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_EVIDENCE_SCHEMA_VERSION
            or self.context_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION
            or self.gate_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_GATE_SCHEMA_VERSION
            or self.generation != 1
            or tuple(proof.gate for proof in self.proofs) != _EXTERNAL_GATES
            or self.proof_count != len(self.proofs)
            or self.proof_count != len(_EXTERNAL_GATES)
            or self.proof_set_digest
            != _digest_object([proof.proof_digest for proof in self.proofs])
            or tuple(gate.name for gate in self.gates) != _REQUIRED_GATES
            or self.gate_count != len(self.gates)
            or self.passed_count != counts[DeployScyllaJoinSafetyProofStatus.PASSED]
            or self.failed_count != counts[DeployScyllaJoinSafetyProofStatus.FAILED]
            or self.unknown_count != counts[DeployScyllaJoinSafetyProofStatus.UNKNOWN]
            or self.not_applicable_count
            != counts[DeployScyllaJoinSafetyProofStatus.NOT_APPLICABLE]
            or self.blockers != _gate_blockers(self.gates)
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.ready_for_authorization != ready
            or self.authorization_state
            != (_AUTHORIZATION_REQUIRED if ready else _AUTHORIZATION_NOT_CREATED)
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
            or self.evidence_digest != _evidence_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla sequence-three safety evidence conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "sequence-three safety evidence digest")

    def to_object(self) -> dict[str, object]:
        return {
            **_dataclass_object(
                self,
                tuple_fields={"blockers"},
                skip_fields={"proofs", "gates"},
            ),
            "proofs": [proof.to_object() for proof in self.proofs],
            "gates": [gate.to_object() for gate in self.gates],
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaSequenceThreeSafetyEvidence:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={
                "generation",
                "proof_count",
                "gate_count",
                "passed_count",
                "failed_count",
                "unknown_count",
                "not_applicable_count",
            },
            uuid_fields={"cluster_uuid", "operation_id"},
            boolean_fields={"ready_for_authorization"},
            tuple_fields={"blockers"},
            skip_fields={"proofs", "gates"},
            label="sequence-three safety evidence",
        )
        parsed["proofs"] = tuple(
            DeployScyllaJoinSafetyProof.from_object(
                _mapping(item, "sequence-three safety proof")
            )
            for item in _array(value["proofs"], "sequence-three safety proofs")
        )
        parsed["gates"] = tuple(
            DeployScyllaSequenceThreeSafetyGate.from_object(
                _mapping(item, "sequence-three safety gate")
            )
            for item in _array(value["gates"], "sequence-three safety gates")
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaSequenceThreeSafetyStep:
    sequence: int
    mode: ScyllaBootstrapMode
    target_digest: str
    plan_step_digest: str
    health_reconciliation_step_digest: str
    status: DeployScyllaSequenceThreeSafetyStepStatus
    authorization_state: str
    blockers: tuple[str, ...]
    blocker_digest: str
    step_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_STEP_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_STEP_SCHEMA_VERSION
            or self.sequence < 1
            or tuple(sorted(set(self.blockers))) != self.blockers
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.step_digest != _step_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla sequence-three safety step conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "sequence-three safety step digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, tuple_fields={"blockers"})

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaSequenceThreeSafetyStep:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={"sequence"},
            tuple_fields={"blockers"},
            enum_fields={
                "mode": ScyllaBootstrapMode,
                "status": DeployScyllaSequenceThreeSafetyStepStatus,
            },
            label="sequence-three safety step",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaSequenceThreeSafetyReconciliation:
    generation: int
    created_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    stage: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    context_artifact_digest: str
    context_digest: str
    evidence_artifact_digest: str
    evidence_digest: str
    post_join_health_reconciliation_artifact_digest: str
    post_join_health_reconciliation_digest: str
    steps: tuple[DeployScyllaSequenceThreeSafetyStep, ...]
    step_count: int
    health_succeeded_count: int
    authorization_required_count: int
    blocked_count: int
    waiting_count: int
    current_member_count: int
    target_sequence: int
    target_status: str
    target_blocker_digest: str
    later_join_count: int
    later_join_set_digest: str
    authorization_state: str
    execution_state: str
    public_workflow_state: str
    reconciliation_digest: str
    context_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_EVIDENCE_SCHEMA_VERSION
    )
    step_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_STEP_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        counts = Counter(step.status for step in self.steps)
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_RECONCILIATION_SCHEMA_VERSION
            or self.context_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_EVIDENCE_SCHEMA_VERSION
            or self.step_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_STEP_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.step_count != len(self.steps)
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, self.step_count + 1))
            or self.health_succeeded_count
            != counts[DeployScyllaSequenceThreeSafetyStepStatus.HEALTH_SUCCEEDED]
            or self.authorization_required_count
            != counts[DeployScyllaSequenceThreeSafetyStepStatus.AUTHORIZATION_REQUIRED]
            or self.blocked_count
            != counts[DeployScyllaSequenceThreeSafetyStepStatus.BLOCKED]
            or self.waiting_count
            != counts[DeployScyllaSequenceThreeSafetyStepStatus.WAITING]
            or self.current_member_count != _CURRENT_MEMBER_COUNT
            or self.health_succeeded_count != self.current_member_count
            or self.target_sequence != _TARGET_SEQUENCE
            or self.authorization_required_count + self.blocked_count != 1
            or self.later_join_count
            != max(0, self.step_count - self.current_member_count - 1)
            or self.authorization_state != _AUTHORIZATION_NOT_CREATED
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
            or self.reconciliation_digest != _reconciliation_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla sequence-three safety reconciliation conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "sequence-three safety reconciliation digest")

    def to_object(self) -> dict[str, object]:
        return {
            **_dataclass_object(self, skip_fields={"steps"}),
            "steps": [step.to_object() for step in self.steps],
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaSequenceThreeSafetyReconciliation:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={
                "generation",
                "journal_generation",
                "step_count",
                "health_succeeded_count",
                "authorization_required_count",
                "blocked_count",
                "waiting_count",
                "current_member_count",
                "target_sequence",
                "later_join_count",
            },
            uuid_fields={"cluster_uuid", "operation_id"},
            enum_fields={
                "journal_status": JournalStatus,
                "journal_phase": OperationPhase,
            },
            skip_fields={"steps"},
            label="sequence-three safety reconciliation",
        )
        parsed["steps"] = tuple(
            DeployScyllaSequenceThreeSafetyStep.from_object(
                _mapping(item, "sequence-three safety step")
            )
            for item in _array(value["steps"], "sequence-three safety steps")
        )
        return cls(**parsed)  # type: ignore[arg-type]


class _SafetyRecord(Protocol):
    @property
    def cluster_uuid(self) -> uuid.UUID: ...

    @property
    def cluster_name(self) -> str: ...

    @property
    def operation_id(self) -> uuid.UUID: ...

    def to_object(self) -> dict[str, object]: ...


_RecordT = TypeVar("_RecordT", bound=_SafetyRecord)


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaSequenceThreeSafetyArtifact(Generic[_RecordT]):
    record: _RecordT
    artifact_digest: str


class _ImmutableSafetyStore(Generic[_RecordT]):
    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        path: Path,
        parser: Callable[[Mapping[str, object]], _RecordT],
        label: str,
        replace_file: Callable[[Path, Path], None] = os.replace,
    ) -> None:
        _require_canonical_paths(paths)
        self._paths = paths
        self._operation_id = _require_operation_id(operation_id)
        self._path = path
        self._parser = parser
        self._label = label
        self._file = AtomicJsonFile(path, replace=replace_file)

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployScyllaSequenceThreeSafetyArtifact[_RecordT]:
        value, digest = self._file.read()
        record = self._parser(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                f"deploy Scylla {self._label} identity conflicts"
            )
        return StoredDeployScyllaSequenceThreeSafetyArtifact(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaSequenceThreeSafetyArtifact[_RecordT]:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self, record: _RecordT, *, lock: ClusterLock
    ) -> tuple[
        StoredDeployScyllaSequenceThreeSafetyArtifact[_RecordT],
        DeployScyllaSequenceThreeSafetyArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_file(self._path, allow_missing=True)
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    f"deploy Scylla {self._label} is immutable; use a new operation"
                )
            return current, DeployScyllaSequenceThreeSafetyArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaSequenceThreeSafetyArtifact(record, digest),
            DeployScyllaSequenceThreeSafetyArtifactState.CREATED,
        )


class DeployScyllaSequenceThreeSafetyContextStore(
    _ImmutableSafetyStore[DeployScyllaSequenceThreeSafetyContext]
):
    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
    ) -> None:
        super().__init__(
            paths,
            operation_id,
            path=deploy_scylla_sequence_three_safety_context_path(paths, operation_id),
            parser=DeployScyllaSequenceThreeSafetyContext.from_object,
            label="sequence-three safety context",
            replace_file=replace_file,
        )


class DeployScyllaSequenceThreeSafetyEvidenceStore(
    _ImmutableSafetyStore[DeployScyllaSequenceThreeSafetyEvidence]
):
    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
    ) -> None:
        super().__init__(
            paths,
            operation_id,
            path=deploy_scylla_sequence_three_safety_evidence_path(paths, operation_id),
            parser=DeployScyllaSequenceThreeSafetyEvidence.from_object,
            label="sequence-three safety evidence",
            replace_file=replace_file,
        )


class DeployScyllaSequenceThreeSafetyReconciliationStore(
    _ImmutableSafetyStore[DeployScyllaSequenceThreeSafetyReconciliation]
):
    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
    ) -> None:
        super().__init__(
            paths,
            operation_id,
            path=deploy_scylla_sequence_three_safety_reconciliation_path(
                paths, operation_id
            ),
            parser=DeployScyllaSequenceThreeSafetyReconciliation.from_object,
            label="sequence-three safety reconciliation",
            replace_file=replace_file,
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaSequenceThreeSafetyReport:
    operation_id: uuid.UUID
    stage: str
    context_state: DeployScyllaSequenceThreeSafetyArtifactState
    evidence_state: DeployScyllaSequenceThreeSafetyArtifactState
    reconciliation_state: DeployScyllaSequenceThreeSafetyArtifactState
    context_artifact_digest: str
    evidence_artifact_digest: str
    reconciliation_artifact_digest: str
    context_digest: str
    evidence_digest: str
    reconciliation_digest: str
    target_sequence: int
    target_status: str
    survivor_count: int
    active_seed_count: int
    proof_count: int
    passed_count: int
    failed_count: int
    unknown_count: int
    blocker_count: int
    later_join_count: int
    authorization_state: str
    execution_state: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    journal_updated: bool
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_REPORT_SCHEMA_VERSION
    )

    def to_object(self) -> dict[str, object]:
        return {
            "artifacts": {
                "context": {
                    "digest": self.context_artifact_digest,
                    "record_digest": self.context_digest,
                    "state": self.context_state.value,
                },
                "evidence": {
                    "digest": self.evidence_artifact_digest,
                    "record_digest": self.evidence_digest,
                    "state": self.evidence_state.value,
                },
                "reconciliation": {
                    "digest": self.reconciliation_artifact_digest,
                    "record_digest": self.reconciliation_digest,
                    "state": self.reconciliation_state.value,
                },
            },
            "gates": {
                "blocker_count": self.blocker_count,
                "failed_count": self.failed_count,
                "passed_count": self.passed_count,
                "proof_count": self.proof_count,
                "unknown_count": self.unknown_count,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": self.journal_updated,
            },
            "operation_id": str(self.operation_id),
            "scope": {
                "active_seed_count": self.active_seed_count,
                "later_join_count": self.later_join_count,
                "survivor_count": self.survivor_count,
                "target_sequence": self.target_sequence,
                "target_status": self.target_status,
            },
            "schema_version": self.schema_version,
            "stage": self.stage,
            "states": {
                "authorization": self.authorization_state,
                "execution": self.execution_state,
            },
        }


@dataclass(frozen=True, slots=True)
class _SequenceThreeSafetyLoaded:
    bootstrap_context_artifact_digest: str
    bootstrap_context_record_digest: str
    bootstrap_plan_artifact_digest: str
    bootstrap_plan_digest: str
    first_join_authorization: StoredDeployScyllaJoinAuthorization
    first_join_execution: StoredDeployScyllaJoinExecution
    first_join_evidence: StoredDeployScyllaJoinEvidence
    post_join_health_execution: StoredDeployScyllaPostJoinHealthExecution
    post_join_health_evidence: StoredDeployScyllaPostJoinHealthEvidence
    post_join_health_reconciliation: StoredDeployScyllaPostJoinHealthReconciliation
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    target_digest: str
    target_plan_step_digest: str
    target_topology_digest: str
    target_storage_evidence_digest: str
    target_configuration_evidence_digest: str
    target_capacity_evidence_digest: str
    target_package_version_digest: str
    playbook_source_digest: str
    survivor_ids: tuple[str, ...]
    survivor_set_digest: str
    survivor_health_digest: str
    active_seed_set_digest: str
    current_topology_digest: str
    current_schema_digest: str
    current_membership_digest: str
    current_host_mapping_digest: str
    current_state_digest: str
    validated_chain_digest: str
    canonical_gate_states: tuple[tuple[str, DeployScyllaJoinSafetyProofStatus], ...]
    plan_steps: tuple[DeployScyllaBootstrapPlanStep, ...]
    health_steps: tuple[DeployScyllaPostJoinHealthStep, ...]


def bind_deploy_scylla_sequence_three_join_safety(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proofs: tuple[DeployScyllaJoinSafetyProof, ...],
) -> DeployScyllaSequenceThreeSafetyReport:
    """Persist exact sequence-three safety without authorization or execution."""

    normalized = _normalize_proofs(proofs)
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_artifacts(paths, operation_id)
    loaded = _load_sequence_three_safety(paths, operation_id, lock=lock)
    _validate_proofs(normalized, loaded)

    context_store = DeployScyllaSequenceThreeSafetyContextStore(paths, operation_id)
    evidence_store = DeployScyllaSequenceThreeSafetyEvidenceStore(paths, operation_id)
    reconciliation_store = DeployScyllaSequenceThreeSafetyReconciliationStore(
        paths, operation_id
    )
    for path in (
        context_store.path,
        evidence_store.path,
        reconciliation_store.path,
    ):
        validate_state_file(path, allow_missing=True)
    if evidence_store.path.exists() and not context_store.path.exists():
        raise StateConflictError(
            "deploy Scylla sequence-three safety evidence exists without context"
        )
    if reconciliation_store.path.exists() and not evidence_store.path.exists():
        raise StateConflictError(
            "deploy Scylla sequence-three safety reconciliation exists without evidence"
        )

    existing_context = _read_optional(
        context_store,
        loaded,
        lock,
    )
    created_at = (
        existing_context.record.created_at
        if existing_context is not None
        else _timestamp()
    )
    context_record = _build_context(loaded, normalized, created_at=created_at)
    context, context_state = context_store.write_locked(context_record, lock=lock)

    existing_evidence = _read_optional(evidence_store, loaded, lock)
    evidence_record = _build_evidence(
        loaded,
        context,
        normalized,
        created_at=(
            existing_evidence.record.created_at
            if existing_evidence is not None
            else created_at
        ),
    )
    evidence, evidence_state = evidence_store.write_locked(evidence_record, lock=lock)

    existing_reconciliation = _read_optional(reconciliation_store, loaded, lock)
    reconciliation_record = _build_reconciliation(
        loaded,
        context,
        evidence,
        created_at=(
            existing_reconciliation.record.created_at
            if existing_reconciliation is not None
            else created_at
        ),
    )
    reconciliation, reconciliation_state = reconciliation_store.write_locked(
        reconciliation_record, lock=lock
    )
    return _report(
        context,
        evidence,
        reconciliation,
        context_state=context_state,
        evidence_state=evidence_state,
        reconciliation_state=reconciliation_state,
    )


def deploy_scylla_sequence_three_safety_context_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths,
        operation_id,
        DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_FILENAME_SUFFIX,
    )


def deploy_scylla_sequence_three_safety_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths,
        operation_id,
        DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_EVIDENCE_FILENAME_SUFFIX,
    )


def deploy_scylla_sequence_three_safety_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths,
        operation_id,
        DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_RECONCILIATION_FILENAME_SUFFIX,
    )


def deploy_scylla_sequence_three_safety_context_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_FILENAME_SUFFIX
    )


def deploy_scylla_sequence_three_safety_evidence_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_EVIDENCE_FILENAME_SUFFIX
    )


def deploy_scylla_sequence_three_safety_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_RECONCILIATION_FILENAME_SUFFIX
    )


def _load_sequence_three_safety(
    paths: StatePaths, operation_id: uuid.UUID, *, lock: ClusterLock
) -> _SequenceThreeSafetyLoaded:
    authorized = _load_join_authorization_context(paths, operation_id, lock=lock)
    configure = _load_reconciliation_context(paths, operation_id, lock=lock)
    current = _loaded(configure.authorization_context)
    planning = current.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    journal = deploy.journal
    bootstrap_context = authorized.chain.bootstrap_context
    bootstrap_plan = authorized.chain.bootstrap_plan
    plan = bootstrap_plan.record
    if len(plan.steps) < _TARGET_SEQUENCE:
        raise StateConflictError(
            "deploy Scylla sequence-three safety requires a sequence-three target"
        )

    scope = _derive_first_join_scope(authorized)
    authorization = DeployScyllaJoinAuthorizationStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_authorization = _build_authorization(
        authorized,
        scope=scope,
        proof=authorization.record.proof,
        created_at=authorization.record.created_at,
    )
    join_execution = DeployScyllaJoinExecutionStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    join_evidence = DeployScyllaJoinEvidenceStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    post_execution = DeployScyllaPostJoinHealthExecutionStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    post_evidence = DeployScyllaPostJoinHealthEvidenceStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    post_reconciliation = DeployScyllaPostJoinHealthReconciliationStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    joined = join_evidence.record
    execution = join_execution.record
    health_execution = post_execution.record
    health = post_evidence.record
    health_reconciliation = post_reconciliation.record
    binding = health.binding
    if (
        authorization.record != expected_authorization
        or authorization.record.consumed
        or execution.state is not DeployScyllaJoinExecutionState.SUCCEEDED
        or not execution.completed
        or execution.invocation_count != 1
        or not execution.ordinary_authorization_consumed
        or not execution.narrow_authorization_consumed
        or execution.manual_recovery_required
        or execution.automatic_retry_allowed
        or execution.binding.authorization_artifact_digest
        != authorization.artifact_digest
        or execution.binding.authorization_digest
        != authorization.record.authorization_digest
        or execution.evidence_digest != joined.evidence_digest
        or execution.result_digest != joined.result_digest
        or joined.binding != execution.binding
        or joined.sequence != 2
        or joined.mode is not ScyllaBootstrapMode.JOIN_EXISTING
        or joined.status is not ScyllaBootstrapStatus.BOOTSTRAPPED
        or joined.host_id_digest is None
        or joined.ring_membership_digest is None
        or not joined.service_active
        or not joined.cql_ready
        or not joined.nodetool_membership_verified
        or not joined.schema_agreement
        or not joined.streaming_complete
        or not joined.membership_may_have_changed
        or joined.mutation_boundary
        is not MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED
        or joined.recovery_required
        or joined.automatic_retry_allowed
        or health_execution.state is not DeployScyllaHealthExecutionState.SUCCEEDED
        or not health_execution.completed
        or health_execution.manual_recovery_required
        or health_execution.automatic_retry_allowed
        or health_execution.binding != binding
        or health_execution.evidence_digest != health.evidence_digest
        or health_execution.result_digest != health.result_digest
        or not health.strict_complete
        or health_reconciliation.health_execution_artifact_digest
        != post_execution.artifact_digest
        or health_reconciliation.health_evidence_artifact_digest
        != post_evidence.artifact_digest
        or health_reconciliation.health_evidence_digest != health.evidence_digest
        or health_reconciliation.reconciliation_digest
        != _post_join_reconciliation_digest(health_reconciliation)
    ):
        raise StateConflictError(
            "deploy Scylla sequence-three safety requires the exact successful "
            "sequence-two and post-join health chain"
        )

    inventory = deploy.inventory
    scylla_hosts = {
        host.logical_id: host
        for host in inventory.record.inventory.hosts
        if host.role is HostRole.SCYLLA
    }
    by_digest = {_digest_object(stable_id): stable_id for stable_id in scylla_hosts}
    try:
        desired_ids = tuple(by_digest[step.target_digest] for step in plan.steps)
    except KeyError as error:
        raise StateConflictError(
            "deploy Scylla sequence-three safety desired topology drifted"
        ) from error
    survivor_ids = desired_ids[:_CURRENT_MEMBER_COUNT]
    target_id = desired_ids[_TARGET_SEQUENCE - 1]
    target = plan.steps[_TARGET_SEQUENCE - 1]
    health_ids = tuple(node.stable_id for node in health.nodes)
    if (
        desired_ids != tuple(dict.fromkeys(desired_ids))
        or survivor_ids != tuple(sorted(survivor_ids))
        or health_ids != survivor_ids
        or target_id in survivor_ids
        or target.sequence != _TARGET_SEQUENCE
        or target.mode is not ScyllaBootstrapMode.JOIN_EXISTING
        or target.target_digest != _digest_object(target_id)
        or health.binding.current_member_count != _CURRENT_MEMBER_COUNT
        or health.binding.current_member_set_digest
        != _digest_object(list(survivor_ids))
        or health.binding.desired_member_count != len(desired_ids)
        or health.binding.desired_member_set_digest != _digest_object(list(desired_ids))
        or health.binding.future_member_count != len(desired_ids) - len(survivor_ids)
        or health.binding.future_member_set_digest
        != _digest_object(list(desired_ids[_CURRENT_MEMBER_COUNT:]))
        or health_reconciliation.current_member_count != _CURRENT_MEMBER_COUNT
        or health_reconciliation.current_member_set_digest
        != _digest_object(list(survivor_ids))
        or health_reconciliation.next_join_sequence != _TARGET_SEQUENCE
        or len(health_reconciliation.steps) != len(plan.steps)
    ):
        raise StateConflictError(
            "deploy Scylla sequence-three safety membership sequence conflicts"
        )
    for original, reconciled in zip(
        plan.steps, health_reconciliation.steps, strict=True
    ):
        expected_status = (
            DeployScyllaHealthStepStatus.HEALTH_SUCCEEDED
            if original.sequence <= _CURRENT_MEMBER_COUNT
            else DeployScyllaHealthStepStatus.BLOCKED
            if original.sequence == _TARGET_SEQUENCE
            else DeployScyllaHealthStepStatus.WAITING
        )
        if (
            reconciled.sequence != original.sequence
            or reconciled.mode is not original.mode
            or reconciled.target_digest != original.target_digest
            or reconciled.plan_step_digest != original.step_digest
            or reconciled.status is not expected_status
        ):
            raise StateConflictError(
                "deploy Scylla sequence-three safety requires contiguous "
                "post-join reconciliation"
            )

    storage_entries = {
        item.stable_id: item
        for item in configure.authorization_context.install.authorization_context.evidence.record.entries
    }
    install_entries = {
        item.stable_id: item
        for item in configure.authorization_context.install.evidence.record.entries
    }
    configuration_entries = {
        item.stable_id: item for item in configure.evidence.record.entries
    }
    if (
        target_id not in storage_entries
        or target_id not in install_entries
        or target_id not in configuration_entries
    ):
        raise StateConflictError(
            "deploy Scylla sequence-three target evidence is incomplete"
        )
    storage = storage_entries[target_id]
    install = install_entries[target_id]
    configuration = configuration_entries[target_id]
    target_host = scylla_hosts[target_id]
    target_capacity_digest = _digest_object(
        {
            "capacity_bytes": storage.capacity_bytes,
            "device_set_digest": storage.device_set_digest,
            "stable_id": target_id,
        }
    )
    if (
        not storage.readiness_for_scylla
        or storage.capacity_bytes < 1
        or storage.failed_check_count
        or storage.unknown_check_count
        or storage.blocker_count
        or not install.installed
        or install.package_version != SCYLLA_PACKAGE_VERSION
        or not configuration.configured
        or target.storage_evidence_digest != storage.evidence_digest
        or target.configuration_evidence_digest != configuration.evidence_digest
        or target.capacity_evidence_digest != target_capacity_digest
        or target.package_version_digest != _digest_object(SCYLLA_PACKAGE_VERSION)
        or target.topology_digest != configuration.topology_digest
        or target.datacenter_digest != _digest_object(target_host.scylla_datacenter)
        or target.rack_digest != _digest_object(target_host.scylla_rack)
    ):
        raise StateConflictError(
            "deploy Scylla sequence-three target provenance conflicts"
        )

    base = bootstrap_context.record
    trust = planning.base.trust
    if (
        journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
        or binding.cluster_uuid != metadata.cluster_uuid
        or binding.cluster_name != metadata.cluster_name
        or binding.operation_id != operation_id
        or binding.journal_generation != journal.record.generation
        or binding.journal_digest != journal.digest
        or binding.bootstrap_context_artifact_digest
        != bootstrap_context.artifact_digest
        or binding.bootstrap_context_record_digest != base.record_digest
        or binding.bootstrap_plan_artifact_digest != bootstrap_plan.artifact_digest
        or binding.bootstrap_plan_digest != plan.plan_digest
        or binding.join_authorization_artifact_digest != authorization.artifact_digest
        or binding.join_authorization_digest
        != authorization.record.authorization_digest
        or binding.join_execution_artifact_digest != join_execution.artifact_digest
        or binding.join_execution_binding_digest != execution.binding.binding_digest
        or binding.join_evidence_artifact_digest != join_evidence.artifact_digest
        or binding.join_evidence_digest != joined.evidence_digest
        or binding.post_configure_artifact_digest != base.post_configure_artifact_digest
        or binding.post_configure_record_digest != base.post_configure_record_digest
        or binding.terraform_verification_artifact_digest
        != base.terraform_verification_artifact_digest
        or binding.observation_generation != deploy.observation.record.generation
        or binding.observation_artifact_digest != deploy.observation.digest
        or binding.observation_manifest_digest
        != deploy.observation.record.manifest_digest
        or binding.inventory_generation != inventory.record.generation
        or binding.inventory_artifact_digest != inventory.digest
        or binding.inventory_digest != inventory.record.inventory_digest
        or binding.trust_generation != trust.record.generation
        or binding.trust_artifact_digest != trust.digest
        or binding.trust_entries_digest != trust.record.entries_digest
        or binding.readiness_artifact_digest != planning.readiness.artifact_digest
        or binding.readiness_record_digest != planning.readiness.record.record_digest
        or binding.storage_evidence_artifact_digest
        != base.storage_evidence_artifact_digest
        or binding.install_evidence_artifact_digest
        != base.install_evidence_artifact_digest
        or binding.configure_evidence_artifact_digest
        != base.configure_evidence_artifact_digest
        or binding.catalog_digest != current.catalog_digest
        or binding.source_version != current.source.version
        or binding.source_digest != current.source.digest
    ):
        raise StateConflictError(
            "deploy Scylla sequence-three safety current chain drifted"
        )

    check_states = dict(health.check_states)
    next_states = dict(health.next_join_gate_states)
    node_health = bool(health.nodes) and all(
        node.membership_state == "UN"
        and node.host_id_digest is not None
        and node.service_ready
        and node.api_ready
        and node.cql_ready
        and node.storage_ready
        and node.streaming_idle
        and node.blocker_count == 0
        for node in health.nodes
    )
    active_seed_id = desired_ids[0]
    no_competing_operation = _has_no_competing_operation(
        paths,
        operation_id,
        cluster_uuid=metadata.cluster_uuid,
        cluster_name=metadata.cluster_name,
    )
    canonical = {
        "completed-prior-membership": (
            _proof_status(next_states["completed-prior-membership"])
        ),
        "configuration-provenance": (
            _proof_status(next_states["configuration-provenance"])
        ),
        "cross-view-consistency": _proof_status(check_states["cross-view-consistency"]),
        "membership": _proof_status(check_states["membership"]),
        "no-competing-operation": (
            DeployScyllaJoinSafetyProofStatus.PASSED
            if no_competing_operation
            else DeployScyllaJoinSafetyProofStatus.FAILED
        ),
        "route-trust-readiness": DeployScyllaJoinSafetyProofStatus.PASSED,
        "schema": _proof_status(check_states["schema-agreement"]),
        "seed-health": (
            DeployScyllaJoinSafetyProofStatus.PASSED
            if node_health
            and health.nodes[0].stable_id == active_seed_id
            and next_states["seed-health"] is HealthCheckStatus.PASSED
            else DeployScyllaJoinSafetyProofStatus.FAILED
        ),
        "service-api-cql": _proof_status(next_states["service-api-cql"]),
        "storage-provenance": _proof_status(next_states["storage-provenance"]),
        "streaming": _proof_status(check_states["streaming"]),
        "survivor-health": (
            DeployScyllaJoinSafetyProofStatus.PASSED
            if node_health
            and next_states["survivor-health"] is HealthCheckStatus.PASSED
            else DeployScyllaJoinSafetyProofStatus.FAILED
        ),
        "target-absence": (
            DeployScyllaJoinSafetyProofStatus.PASSED
            if next_states["target-absence"] is HealthCheckStatus.PASSED
            and target_id not in health_ids
            else DeployScyllaJoinSafetyProofStatus.FAILED
        ),
        "topology": _proof_status(check_states["topology"]),
    }
    if set(canonical) != set((*_HEALTH_GATES, *_CURRENT_STATE_GATES)):
        raise StateConflictError(
            "deploy Scylla sequence-three canonical safety gates conflict"
        )

    current_state = {
        "catalog_digest": current.catalog_digest,
        "configure_evidence_artifact_digest": base.configure_evidence_artifact_digest,
        "install_evidence_artifact_digest": base.install_evidence_artifact_digest,
        "inventory_artifact_digest": inventory.digest,
        "observation_artifact_digest": deploy.observation.digest,
        "post_configure_artifact_digest": base.post_configure_artifact_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "source_digest": current.source.digest,
        "storage_evidence_artifact_digest": base.storage_evidence_artifact_digest,
        "terraform_verification_artifact_digest": (
            base.terraform_verification_artifact_digest
        ),
        "trust_artifact_digest": trust.digest,
    }
    validated_chain = {
        "bootstrap_context_artifact_digest": bootstrap_context.artifact_digest,
        "bootstrap_plan_artifact_digest": bootstrap_plan.artifact_digest,
        "first_join_authorization_artifact_digest": authorization.artifact_digest,
        "first_join_evidence_artifact_digest": join_evidence.artifact_digest,
        "first_join_execution_artifact_digest": join_execution.artifact_digest,
        "post_join_health_evidence_artifact_digest": post_evidence.artifact_digest,
        "post_join_health_execution_artifact_digest": post_execution.artifact_digest,
        "post_join_health_reconciliation_artifact_digest": (
            post_reconciliation.artifact_digest
        ),
        "current_state_digest": _digest_object(current_state),
        "journal_digest": journal.digest,
    }
    return _SequenceThreeSafetyLoaded(
        bootstrap_context_artifact_digest=bootstrap_context.artifact_digest,
        bootstrap_context_record_digest=base.record_digest,
        bootstrap_plan_artifact_digest=bootstrap_plan.artifact_digest,
        bootstrap_plan_digest=plan.plan_digest,
        first_join_authorization=authorization,
        first_join_execution=join_execution,
        first_join_evidence=join_evidence,
        post_join_health_execution=post_execution,
        post_join_health_evidence=post_evidence,
        post_join_health_reconciliation=post_reconciliation,
        cluster_uuid=metadata.cluster_uuid,
        cluster_name=metadata.cluster_name,
        operation_id=operation_id,
        request_digest=journal.record.request_digest,
        journal_generation=journal.record.generation,
        journal_digest=journal.digest,
        journal_status=journal.record.status,
        journal_phase=journal.record.phase,
        target_digest=target.target_digest,
        target_plan_step_digest=target.step_digest,
        target_topology_digest=target.topology_digest,
        target_storage_evidence_digest=target.storage_evidence_digest,
        target_configuration_evidence_digest=target.configuration_evidence_digest,
        target_capacity_evidence_digest=target.capacity_evidence_digest,
        target_package_version_digest=target.package_version_digest,
        playbook_source_digest=target.playbook_source_digest,
        survivor_ids=survivor_ids,
        survivor_set_digest=_digest_object(list(survivor_ids)),
        survivor_health_digest=_digest_object(
            [node.evidence_digest for node in health.nodes]
        ),
        active_seed_set_digest=_digest_object([active_seed_id]),
        current_topology_digest=cast(str, health.topology_digest),
        current_schema_digest=cast(str, health.schema_digest),
        current_membership_digest=health.membership_digest,
        current_host_mapping_digest=health.host_id_mapping_digest,
        current_state_digest=_digest_object(current_state),
        validated_chain_digest=_digest_object(validated_chain),
        canonical_gate_states=tuple(sorted(canonical.items())),
        plan_steps=plan.steps,
        health_steps=health_reconciliation.steps,
    )


def _normalize_proofs(
    proofs: tuple[DeployScyllaJoinSafetyProof, ...],
) -> tuple[DeployScyllaJoinSafetyProof, ...]:
    if not isinstance(proofs, tuple) or not all(
        isinstance(proof, DeployScyllaJoinSafetyProof) for proof in proofs
    ):
        raise StateConflictError(
            "deploy Scylla sequence-three safety proofs are malformed"
        )
    ordered = tuple(sorted(proofs, key=lambda proof: proof.gate))
    if tuple(proof.gate for proof in ordered) != _EXTERNAL_GATES:
        raise StateConflictError(
            "deploy Scylla sequence-three safety requires exact independent "
            "backup, capacity, quorum, and replication proofs"
        )
    return ordered


def _validate_proofs(
    proofs: tuple[DeployScyllaJoinSafetyProof, ...],
    loaded: _SequenceThreeSafetyLoaded,
) -> None:
    health = loaded.post_join_health_evidence.record
    for proof in proofs:
        if (
            proof.captured_at != health.created_at
            or proof.health_evidence_digest != health.evidence_digest
            or proof.target_digest != loaded.target_digest
            or proof.survivor_set_digest != loaded.survivor_set_digest
            or proof.topology_digest != loaded.current_topology_digest
            or proof.target_storage_evidence_digest
            != loaded.target_storage_evidence_digest
            or proof.target_configuration_evidence_digest
            != loaded.target_configuration_evidence_digest
            or proof.playbook_source_digest != loaded.playbook_source_digest
        ):
            raise StateConflictError(
                "deploy Scylla sequence-three safety proof is stale or "
                "binding-mismatched"
            )


def _build_context(
    loaded: _SequenceThreeSafetyLoaded,
    proofs: tuple[DeployScyllaJoinSafetyProof, ...],
    *,
    created_at: str,
) -> DeployScyllaSequenceThreeSafetyContext:
    proof_set_digest = _digest_object([proof.proof_digest for proof in proofs])
    policy_digest = _digest_object(
        {
            "current_member_count": _CURRENT_MEMBER_COUNT,
            "required_gates": list(_REQUIRED_GATES),
            "target_sequence": _TARGET_SEQUENCE,
        }
    )
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": loaded.cluster_uuid,
        "cluster_name": loaded.cluster_name,
        "operation_id": loaded.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "request_digest": loaded.request_digest,
        "journal_generation": loaded.journal_generation,
        "journal_digest": loaded.journal_digest,
        "journal_status": loaded.journal_status,
        "journal_phase": loaded.journal_phase,
        "bootstrap_context_artifact_digest": (loaded.bootstrap_context_artifact_digest),
        "bootstrap_context_record_digest": loaded.bootstrap_context_record_digest,
        "bootstrap_plan_artifact_digest": loaded.bootstrap_plan_artifact_digest,
        "bootstrap_plan_digest": loaded.bootstrap_plan_digest,
        "first_join_authorization_artifact_digest": (
            loaded.first_join_authorization.artifact_digest
        ),
        "first_join_authorization_digest": (
            loaded.first_join_authorization.record.authorization_digest
        ),
        "first_join_execution_artifact_digest": (
            loaded.first_join_execution.artifact_digest
        ),
        "first_join_execution_binding_digest": (
            loaded.first_join_execution.record.binding.binding_digest
        ),
        "first_join_evidence_artifact_digest": (
            loaded.first_join_evidence.artifact_digest
        ),
        "first_join_evidence_digest": (
            loaded.first_join_evidence.record.evidence_digest
        ),
        "post_join_health_execution_artifact_digest": (
            loaded.post_join_health_execution.artifact_digest
        ),
        "post_join_health_evidence_artifact_digest": (
            loaded.post_join_health_evidence.artifact_digest
        ),
        "post_join_health_evidence_digest": (
            loaded.post_join_health_evidence.record.evidence_digest
        ),
        "post_join_health_reconciliation_artifact_digest": (
            loaded.post_join_health_reconciliation.artifact_digest
        ),
        "post_join_health_reconciliation_digest": (
            loaded.post_join_health_reconciliation.record.reconciliation_digest
        ),
        "current_state_digest": loaded.current_state_digest,
        "validated_chain_digest": loaded.validated_chain_digest,
        "target_sequence": _TARGET_SEQUENCE,
        "target_digest": loaded.target_digest,
        "target_plan_step_digest": loaded.target_plan_step_digest,
        "target_topology_digest": loaded.target_topology_digest,
        "target_storage_evidence_digest": loaded.target_storage_evidence_digest,
        "target_configuration_evidence_digest": (
            loaded.target_configuration_evidence_digest
        ),
        "target_capacity_evidence_digest": loaded.target_capacity_evidence_digest,
        "target_package_version_digest": loaded.target_package_version_digest,
        "playbook_source_digest": loaded.playbook_source_digest,
        "survivor_count": len(loaded.survivor_ids),
        "survivor_set_digest": loaded.survivor_set_digest,
        "survivor_health_digest": loaded.survivor_health_digest,
        "active_seed_count": 1,
        "active_seed_set_digest": loaded.active_seed_set_digest,
        "current_topology_digest": loaded.current_topology_digest,
        "current_schema_digest": loaded.current_schema_digest,
        "current_membership_digest": loaded.current_membership_digest,
        "current_host_mapping_digest": loaded.current_host_mapping_digest,
        "required_gates": _REQUIRED_GATES,
        "proof_set_digest": proof_set_digest,
        "policy_digest": policy_digest,
        "context_digest": "",
    }
    values["context_digest"] = _context_digest_from_values(values)
    return DeployScyllaSequenceThreeSafetyContext(**values)  # type: ignore[arg-type]


def _build_evidence(
    loaded: _SequenceThreeSafetyLoaded,
    context: StoredDeployScyllaSequenceThreeSafetyArtifact[
        DeployScyllaSequenceThreeSafetyContext
    ],
    proofs: tuple[DeployScyllaJoinSafetyProof, ...],
    *,
    created_at: str,
) -> DeployScyllaSequenceThreeSafetyEvidence:
    canonical = dict(loaded.canonical_gate_states)
    proof_by_gate = {proof.gate: proof for proof in proofs}
    health = loaded.post_join_health_evidence.record
    gates: list[DeployScyllaSequenceThreeSafetyGate] = []
    for name in _REQUIRED_GATES:
        if name in proof_by_gate:
            proof = proof_by_gate[name]
            status = proof.status
            source = DeployScyllaSequenceThreeSafetyGateSource.INDEPENDENT_POLICY_PROOF
            evidence_digest = proof.evidence_digest
            binding_digest = proof.proof_digest
        else:
            status = canonical[name]
            if name in _CURRENT_STATE_GATES:
                source = (
                    DeployScyllaSequenceThreeSafetyGateSource.CURRENT_CANONICAL_STATE
                )
                evidence_digest = loaded.current_state_digest
                binding_digest = loaded.validated_chain_digest
            else:
                source = DeployScyllaSequenceThreeSafetyGateSource.POST_JOIN_HEALTH
                evidence_digest = health.evidence_digest
                binding_digest = _digest_object(
                    {
                        "current_member_set_digest": loaded.survivor_set_digest,
                        "health_evidence_digest": health.evidence_digest,
                        "target_digest": loaded.target_digest,
                    }
                )
        values: dict[str, object] = {
            "name": name,
            "required": True,
            "status": status,
            "source": source,
            "captured_at": health.created_at,
            "evidence_digest": evidence_digest,
            "binding_digest": binding_digest,
            "gate_digest": "",
        }
        values["gate_digest"] = _gate_digest_from_values(values)
        gates.append(DeployScyllaSequenceThreeSafetyGate(**values))  # type: ignore[arg-type]
    gate_tuple = tuple(gates)
    counts = Counter(gate.status for gate in gate_tuple)
    blockers = _gate_blockers(gate_tuple)
    ready = not blockers
    values = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": loaded.cluster_uuid,
        "cluster_name": loaded.cluster_name,
        "operation_id": loaded.operation_id,
        "context_artifact_digest": context.artifact_digest,
        "context_digest": context.record.context_digest,
        "proofs": proofs,
        "proof_count": len(proofs),
        "proof_set_digest": _digest_object([proof.proof_digest for proof in proofs]),
        "gates": gate_tuple,
        "gate_count": len(gate_tuple),
        "passed_count": counts[DeployScyllaJoinSafetyProofStatus.PASSED],
        "failed_count": counts[DeployScyllaJoinSafetyProofStatus.FAILED],
        "unknown_count": counts[DeployScyllaJoinSafetyProofStatus.UNKNOWN],
        "not_applicable_count": counts[
            DeployScyllaJoinSafetyProofStatus.NOT_APPLICABLE
        ],
        "blockers": blockers,
        "blocker_digest": _digest_object(list(blockers)),
        "ready_for_authorization": ready,
        "authorization_state": (
            _AUTHORIZATION_REQUIRED if ready else _AUTHORIZATION_NOT_CREATED
        ),
        "execution_state": _EXECUTION_UNAVAILABLE,
        "public_workflow_state": _PUBLIC_WORKFLOW_UNAVAILABLE,
        "evidence_digest": "",
    }
    values["evidence_digest"] = _evidence_digest_from_values(values)
    return DeployScyllaSequenceThreeSafetyEvidence(**values)  # type: ignore[arg-type]


def _build_reconciliation(
    loaded: _SequenceThreeSafetyLoaded,
    context: StoredDeployScyllaSequenceThreeSafetyArtifact[
        DeployScyllaSequenceThreeSafetyContext
    ],
    evidence: StoredDeployScyllaSequenceThreeSafetyArtifact[
        DeployScyllaSequenceThreeSafetyEvidence
    ],
    *,
    created_at: str,
) -> DeployScyllaSequenceThreeSafetyReconciliation:
    steps: list[DeployScyllaSequenceThreeSafetyStep] = []
    target_blockers: tuple[str, ...] = ()
    for original, health_step in zip(
        loaded.plan_steps, loaded.health_steps, strict=True
    ):
        sequence = original.sequence
        if sequence <= _CURRENT_MEMBER_COUNT:
            status = DeployScyllaSequenceThreeSafetyStepStatus.HEALTH_SUCCEEDED
            authorization_state = "not-required"
            blockers: tuple[str, ...] = ()
        elif sequence == _TARGET_SEQUENCE:
            if evidence.record.ready_for_authorization:
                status = (
                    DeployScyllaSequenceThreeSafetyStepStatus.AUTHORIZATION_REQUIRED
                )
                authorization_state = _AUTHORIZATION_REQUIRED
                blockers = ("join-authorization-not-collected",)
            else:
                status = DeployScyllaSequenceThreeSafetyStepStatus.BLOCKED
                authorization_state = _AUTHORIZATION_NOT_CREATED
                blockers = evidence.record.blockers
            target_blockers = blockers
        else:
            status = DeployScyllaSequenceThreeSafetyStepStatus.WAITING
            authorization_state = "waiting"
            blockers = ("preceding-join-not-completed",)
        values: dict[str, object] = {
            "sequence": sequence,
            "mode": original.mode,
            "target_digest": original.target_digest,
            "plan_step_digest": original.step_digest,
            "health_reconciliation_step_digest": health_step.step_digest,
            "status": status,
            "authorization_state": authorization_state,
            "blockers": blockers,
            "blocker_digest": _digest_object(list(blockers)),
            "step_digest": "",
        }
        values["step_digest"] = _step_digest_from_values(values)
        steps.append(DeployScyllaSequenceThreeSafetyStep(**values))  # type: ignore[arg-type]
    step_tuple = tuple(steps)
    counts = Counter(step.status for step in step_tuple)
    target = step_tuple[_TARGET_SEQUENCE - 1]
    later = step_tuple[_TARGET_SEQUENCE:]
    values = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": loaded.cluster_uuid,
        "cluster_name": loaded.cluster_name,
        "operation_id": loaded.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "request_digest": loaded.request_digest,
        "journal_generation": loaded.journal_generation,
        "journal_digest": loaded.journal_digest,
        "journal_status": loaded.journal_status,
        "journal_phase": loaded.journal_phase,
        "context_artifact_digest": context.artifact_digest,
        "context_digest": context.record.context_digest,
        "evidence_artifact_digest": evidence.artifact_digest,
        "evidence_digest": evidence.record.evidence_digest,
        "post_join_health_reconciliation_artifact_digest": (
            loaded.post_join_health_reconciliation.artifact_digest
        ),
        "post_join_health_reconciliation_digest": (
            loaded.post_join_health_reconciliation.record.reconciliation_digest
        ),
        "steps": step_tuple,
        "step_count": len(step_tuple),
        "health_succeeded_count": counts[
            DeployScyllaSequenceThreeSafetyStepStatus.HEALTH_SUCCEEDED
        ],
        "authorization_required_count": counts[
            DeployScyllaSequenceThreeSafetyStepStatus.AUTHORIZATION_REQUIRED
        ],
        "blocked_count": counts[DeployScyllaSequenceThreeSafetyStepStatus.BLOCKED],
        "waiting_count": counts[DeployScyllaSequenceThreeSafetyStepStatus.WAITING],
        "current_member_count": _CURRENT_MEMBER_COUNT,
        "target_sequence": _TARGET_SEQUENCE,
        "target_status": target.status.value,
        "target_blocker_digest": _digest_object(list(target_blockers)),
        "later_join_count": len(later),
        "later_join_set_digest": _digest_object([step.target_digest for step in later]),
        "authorization_state": _AUTHORIZATION_NOT_CREATED,
        "execution_state": _EXECUTION_UNAVAILABLE,
        "public_workflow_state": _PUBLIC_WORKFLOW_UNAVAILABLE,
        "reconciliation_digest": "",
    }
    values["reconciliation_digest"] = _reconciliation_digest_from_values(values)
    return DeployScyllaSequenceThreeSafetyReconciliation(**values)  # type: ignore[arg-type]


def _report(
    context: StoredDeployScyllaSequenceThreeSafetyArtifact[
        DeployScyllaSequenceThreeSafetyContext
    ],
    evidence: StoredDeployScyllaSequenceThreeSafetyArtifact[
        DeployScyllaSequenceThreeSafetyEvidence
    ],
    reconciliation: StoredDeployScyllaSequenceThreeSafetyArtifact[
        DeployScyllaSequenceThreeSafetyReconciliation
    ],
    *,
    context_state: DeployScyllaSequenceThreeSafetyArtifactState,
    evidence_state: DeployScyllaSequenceThreeSafetyArtifactState,
    reconciliation_state: DeployScyllaSequenceThreeSafetyArtifactState,
) -> DeployScyllaSequenceThreeSafetyReport:
    return DeployScyllaSequenceThreeSafetyReport(
        operation_id=context.record.operation_id,
        stage=_STAGE,
        context_state=context_state,
        evidence_state=evidence_state,
        reconciliation_state=reconciliation_state,
        context_artifact_digest=context.artifact_digest,
        evidence_artifact_digest=evidence.artifact_digest,
        reconciliation_artifact_digest=reconciliation.artifact_digest,
        context_digest=context.record.context_digest,
        evidence_digest=evidence.record.evidence_digest,
        reconciliation_digest=reconciliation.record.reconciliation_digest,
        target_sequence=reconciliation.record.target_sequence,
        target_status=reconciliation.record.target_status,
        survivor_count=context.record.survivor_count,
        active_seed_count=context.record.active_seed_count,
        proof_count=evidence.record.proof_count,
        passed_count=evidence.record.passed_count,
        failed_count=evidence.record.failed_count,
        unknown_count=evidence.record.unknown_count,
        blocker_count=len(evidence.record.blockers),
        later_join_count=reconciliation.record.later_join_count,
        authorization_state=reconciliation.record.authorization_state,
        execution_state=reconciliation.record.execution_state,
        journal_status=reconciliation.record.journal_status,
        journal_phase=reconciliation.record.journal_phase,
        journal_updated=False,
    )


def _read_optional(
    store: _ImmutableSafetyStore[_RecordT],
    loaded: _SequenceThreeSafetyLoaded,
    lock: ClusterLock,
) -> StoredDeployScyllaSequenceThreeSafetyArtifact[_RecordT] | None:
    return (
        store.read_locked(
            lock,
            expected_cluster_uuid=loaded.cluster_uuid,
            expected_cluster_name=loaded.cluster_name,
        )
        if store.path.exists()
        else None
    )


def _proof_status(status: HealthCheckStatus) -> DeployScyllaJoinSafetyProofStatus:
    return {
        HealthCheckStatus.PASSED: DeployScyllaJoinSafetyProofStatus.PASSED,
        HealthCheckStatus.FAILED: DeployScyllaJoinSafetyProofStatus.FAILED,
        HealthCheckStatus.UNKNOWN: DeployScyllaJoinSafetyProofStatus.UNKNOWN,
        HealthCheckStatus.NOT_PERFORMED: DeployScyllaJoinSafetyProofStatus.UNKNOWN,
    }[status]


def _gate_blockers(
    gates: tuple[DeployScyllaSequenceThreeSafetyGate, ...],
) -> tuple[str, ...]:
    suffixes = {
        DeployScyllaJoinSafetyProofStatus.FAILED: "failed",
        DeployScyllaJoinSafetyProofStatus.UNKNOWN: "unknown",
        DeployScyllaJoinSafetyProofStatus.NOT_APPLICABLE: "not-proven",
    }
    return tuple(
        sorted(
            f"{gate.name}-{suffixes[gate.status]}"
            for gate in gates
            if gate.status is not DeployScyllaJoinSafetyProofStatus.PASSED
        )
    )


def _context_digest(record: DeployScyllaSequenceThreeSafetyContext) -> str:
    return _context_digest_from_values(record.to_object())


def _context_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for (
        name,
        field,
    ) in DeployScyllaSequenceThreeSafetyContext.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["context_digest"] = ""
    return _digest_object(value)


def _gate_digest(record: DeployScyllaSequenceThreeSafetyGate) -> str:
    return _gate_digest_from_values(record.to_object())


def _gate_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    value.setdefault(
        "schema_version",
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_GATE_SCHEMA_VERSION,
    )
    value["gate_digest"] = ""
    return _digest_object(value)


def _evidence_digest(record: DeployScyllaSequenceThreeSafetyEvidence) -> str:
    return _evidence_digest_from_values(record.to_object())


def _evidence_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for (
        name,
        field,
    ) in DeployScyllaSequenceThreeSafetyEvidence.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["evidence_digest"] = ""
    return _digest_object(value)


def _step_digest(record: DeployScyllaSequenceThreeSafetyStep) -> str:
    return _step_digest_from_values(record.to_object())


def _step_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    value.setdefault(
        "schema_version",
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_STEP_SCHEMA_VERSION,
    )
    value["step_digest"] = ""
    return _digest_object(value)


def _reconciliation_digest(
    record: DeployScyllaSequenceThreeSafetyReconciliation,
) -> str:
    return _reconciliation_digest_from_values(record.to_object())


def _reconciliation_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for (
        name,
        field,
    ) in DeployScyllaSequenceThreeSafetyReconciliation.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["reconciliation_digest"] = ""
    return _digest_object(value)


def _post_join_reconciliation_digest(
    record: object,
) -> str:
    from scylla_vms.ansible.deploy_scylla_post_join_health import (
        _reconciliation_digest,
    )

    return _reconciliation_digest(record)  # type: ignore[arg-type]


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


def _artifact_path(paths: StatePaths, operation_id: uuid.UUID, suffix: str) -> Path:
    _require_canonical_paths(paths)
    path = paths.operations / f"{_require_operation_id(operation_id)}{suffix}"
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Scylla sequence-three safety path is not canonical"
        )
    return path


def _operation_id_from_filename(name: str, suffix: str) -> uuid.UUID | None:
    if not name.endswith(suffix):
        return None
    value = name[: -len(suffix)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_EVIDENCE_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_RECONCILIATION_FILENAME_SUFFIX,
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Scylla sequence-three safety artifacts"
        ) from error
    for entry in entries:
        for suffix in suffixes:
            if not entry.name.endswith(suffix):
                continue
            prefix = entry.name[: -len(suffix)]
            try:
                parsed = uuid.UUID(prefix)
            except ValueError:
                parsed = None
            if parsed == operation_id and prefix != canonical:
                validate_state_file(entry)
                raise StateConflictError(
                    "deploy Scylla sequence-three safety artifacts are ambiguous"
                )


def _has_no_competing_operation(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    cluster_uuid: uuid.UUID,
    cluster_name: str,
) -> bool:
    active = {
        JournalStatus.PENDING,
        JournalStatus.IN_PROGRESS,
        JournalStatus.INTERRUPTED,
    }
    try:
        entries = tuple(
            sorted(paths.operations.iterdir(), key=lambda entry: entry.name)
        )
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely inspect deploy Scylla operation history"
        ) from error
    competing = False
    for entry in entries:
        if not entry.name.endswith(".json"):
            continue
        prefix = entry.name[:-5]
        try:
            identifier = uuid.UUID(prefix)
        except ValueError:
            continue
        validate_state_file(entry)
        if str(identifier) != prefix:
            raise StateConflictError(
                "deploy Scylla operation history contains a noncanonical journal"
            )
        stored = OperationJournalStore(paths, identifier).read(
            expected_cluster_uuid=cluster_uuid,
            expected_cluster_name=cluster_name,
        )
        if identifier != operation_id and stored.record.status in active:
            competing = True
    return not competing


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy Scylla sequence-three safety requires the matching held deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy Scylla sequence-three safety paths are not canonical"
        )


def _timestamp() -> str:
    return format_timestamp(datetime.now(UTC))


__all__ = [
    "ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_GATE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_RECONCILIATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_STEP_SCHEMA_VERSION",
    "DeployScyllaSequenceThreeSafetyArtifactState",
    "DeployScyllaSequenceThreeSafetyContext",
    "DeployScyllaSequenceThreeSafetyContextStore",
    "DeployScyllaSequenceThreeSafetyEvidence",
    "DeployScyllaSequenceThreeSafetyEvidenceStore",
    "DeployScyllaSequenceThreeSafetyGate",
    "DeployScyllaSequenceThreeSafetyGateSource",
    "DeployScyllaSequenceThreeSafetyReconciliation",
    "DeployScyllaSequenceThreeSafetyReconciliationStore",
    "DeployScyllaSequenceThreeSafetyReport",
    "DeployScyllaSequenceThreeSafetyStep",
    "DeployScyllaSequenceThreeSafetyStepStatus",
    "bind_deploy_scylla_sequence_three_join_safety",
    "deploy_scylla_sequence_three_safety_context_id_from_filename",
    "deploy_scylla_sequence_three_safety_context_path",
    "deploy_scylla_sequence_three_safety_evidence_id_from_filename",
    "deploy_scylla_sequence_three_safety_evidence_path",
    "deploy_scylla_sequence_three_safety_reconciliation_id_from_filename",
    "deploy_scylla_sequence_three_safety_reconciliation_path",
]
