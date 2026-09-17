"""Generic safety ownership for the first unfinished deploy Scylla join.

This subprocess-free owner derives one sequence at a time from the immutable
bootstrap plan and the latest canonical complete-set health checkpoint.  It
never accepts caller-selected sequence or target data, authorizes or executes a
join, or changes the common operation journal.
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
from typing import Any, Generic, Protocol, TypeVar

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
from scylla_vms.ansible.deploy_scylla_post_sequence_three_join_health import (
    ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_RECONCILIATION_SCHEMA_VERSION,
    DeployScyllaPostSequenceThreeHealthEvidenceStore,
    DeployScyllaPostSequenceThreeHealthExecutionStore,
    DeployScyllaPostSequenceThreeHealthReconciliationStore,
    DeployScyllaPostSequenceThreeHealthStepStatus,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_authorization import (
    DeployScyllaSequenceThreeJoinAuthorizationStore,
    StoredDeployScyllaSequenceThreeJoinAuthorization,
    _derive_sequence_three_join_scope,
    _load_sequence_three_join_authorization_context,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_authorization import (
    _build_authorization as _build_sequence_three_authorization,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_execution import (
    DeployScyllaSequenceThreeJoinEvidenceStore,
    DeployScyllaSequenceThreeJoinExecutionState,
    DeployScyllaSequenceThreeJoinExecutionStore,
    StoredDeployScyllaSequenceThreeJoinEvidence,
    StoredDeployScyllaSequenceThreeJoinExecution,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_safety import (
    _has_no_competing_operation,
    _SequenceThreeSafetyLoaded,
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
from scylla_vms.journal import JOURNAL_SCHEMA_VERSION, JournalStatus, OperationPhase
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

ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-later-join-safety-context/v1"
)
ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_GATE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-later-join-safety-gate/v1"
)
ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-later-join-safety-evidence/v1"
)
ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_STEP_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-later-join-safety-step/v1"
)
ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-later-join-safety-reconciliation/v1"
)
ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-later-join-safety-report/v1"
)

DEPLOY_SCYLLA_LATER_JOIN_SAFETY_CONTEXT_FILENAME_SUFFIX = "-safety-context.json"
DEPLOY_SCYLLA_LATER_JOIN_SAFETY_EVIDENCE_FILENAME_SUFFIX = "-safety-evidence.json"
DEPLOY_SCYLLA_LATER_JOIN_SAFETY_RECONCILIATION_FILENAME_SUFFIX = (
    "-safety-reconciliation.json"
)
_LATER_JOIN_NAMESPACE_STEM = ".ansible-deploy-scylla-later-join-"
_LATER_JOIN_FILENAME_STEM = f"{_LATER_JOIN_NAMESPACE_STEM}sequence-"

_OPERATION = "deploy"
_STAGE = "pre-later-join-safety"
_MINIMUM_SEQUENCE = 4
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
_EXPECTED_POLICY_STATES = {
    "backup-policy": HealthCheckStatus.NOT_PERFORMED,
    "capacity": HealthCheckStatus.UNKNOWN,
    "quorum": HealthCheckStatus.UNKNOWN,
    "replication": HealthCheckStatus.NOT_PERFORMED,
}
_AUTHORIZATION_REQUIRED = "authorization-required"
_AUTHORIZATION_NOT_CREATED = "not-created"
_EXECUTION_UNAVAILABLE = "unavailable"
_PUBLIC_WORKFLOW_UNAVAILABLE = "unavailable"
_GENERIC_HEALTH_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-post-later-join-health-execution/v1"
)
_GENERIC_HEALTH_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-post-later-join-health-evidence/v1"
)
_GENERIC_HEALTH_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-post-later-join-health-reconciliation/v1"
)


class DeployScyllaLaterJoinSafetyArtifactState(StrEnum):
    CREATED = "created"
    REUSED = "reused"


class DeployScyllaLaterJoinSafetyGateSource(StrEnum):
    CURRENT_CANONICAL_STATE = "current-canonical-state"
    INDEPENDENT_POLICY_PROOF = "independent-policy-proof"
    LATEST_COMPLETE_SET_HEALTH = "latest-complete-set-health"


class DeployScyllaLaterJoinSafetyStepStatus(StrEnum):
    HEALTH_SUCCEEDED = "health-succeeded"
    AUTHORIZATION_REQUIRED = "authorization-required"
    BLOCKED = "blocked"
    WAITING = "waiting-for-preceding-complete-health"


@dataclass(frozen=True, slots=True)
class DeployScyllaLaterJoinSafetyContext:
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
    sequence_three_authorization_artifact_digest: str
    sequence_three_authorization_digest: str
    sequence_three_execution_artifact_digest: str
    sequence_three_execution_binding_digest: str
    sequence_three_evidence_artifact_digest: str
    sequence_three_evidence_digest: str
    latest_health_execution_artifact_digest: str
    latest_health_evidence_artifact_digest: str
    latest_health_evidence_digest: str
    latest_health_reconciliation_artifact_digest: str
    latest_health_reconciliation_digest: str
    completed_prefix_count: int
    completed_prefix_digest: str
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
    current_state_digest: str
    validated_chain_digest: str
    required_gates: tuple[str, ...]
    proof_set_digest: str
    policy_digest: str
    context_digest: str
    proof_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION
    latest_health_execution_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_SCHEMA_VERSION
    )
    latest_health_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EVIDENCE_SCHEMA_VERSION
    )
    latest_health_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_RECONCILIATION_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        health_schemas = (
            self.latest_health_execution_schema_version,
            self.latest_health_evidence_schema_version,
            self.latest_health_reconciliation_schema_version,
        )
        fixed_health_schemas = (
            ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_SCHEMA_VERSION,
            ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EVIDENCE_SCHEMA_VERSION,
            ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_RECONCILIATION_SCHEMA_VERSION,
        )
        generic_health_schemas = (
            _GENERIC_HEALTH_EXECUTION_SCHEMA_VERSION,
            _GENERIC_HEALTH_EVIDENCE_SCHEMA_VERSION,
            _GENERIC_HEALTH_RECONCILIATION_SCHEMA_VERSION,
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION
            or health_schemas not in {fixed_health_schemas, generic_health_schemas}
            or (self.target_sequence == _MINIMUM_SEQUENCE)
            != (health_schemas == fixed_health_schemas)
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.target_sequence < _MINIMUM_SEQUENCE
            or self.completed_prefix_count != self.target_sequence - 1
            or self.survivor_count != self.completed_prefix_count
            or self.active_seed_count != 1
            or self.required_gates != _REQUIRED_GATES
            or self.policy_digest
            != _digest_object(
                {
                    "completed_prefix_count": self.completed_prefix_count,
                    "derivation": "first-unfinished-bootstrap-plan-sequence",
                    "minimum_sequence": _MINIMUM_SEQUENCE,
                    "required_gates": list(_REQUIRED_GATES),
                    "target_sequence": self.target_sequence,
                }
            )
            or self.context_digest != _context_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla later-join safety context conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "later-join safety context digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, tuple_fields={"required_gates"})

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaLaterJoinSafetyContext:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={
                "generation",
                "journal_generation",
                "completed_prefix_count",
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
            label="later-join safety context",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaLaterJoinSafetyGate:
    name: str
    required: bool
    status: DeployScyllaJoinSafetyProofStatus
    source: DeployScyllaLaterJoinSafetyGateSource
    captured_at: str
    evidence_digest: str
    binding_digest: str
    gate_digest: str
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_GATE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_GATE_SCHEMA_VERSION
            or self.name not in _REQUIRED_GATES
            or not self.required
            or self.gate_digest != _gate_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla later-join safety gate conflicts"
            )
        parse_timestamp(self.captured_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "later-join safety gate digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaLaterJoinSafetyGate:
        parsed = _parse_dataclass(
            cls,
            value,
            boolean_fields={"required"},
            enum_fields={
                "status": DeployScyllaJoinSafetyProofStatus,
                "source": DeployScyllaLaterJoinSafetyGateSource,
            },
            label="later-join safety gate",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaLaterJoinSafetyEvidence:
    generation: int
    created_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    target_sequence: int
    context_artifact_digest: str
    context_digest: str
    proofs: tuple[DeployScyllaJoinSafetyProof, ...]
    proof_count: int
    proof_set_digest: str
    gates: tuple[DeployScyllaLaterJoinSafetyGate, ...]
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
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
    )
    proof_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION
    gate_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_GATE_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        counts = Counter(gate.status for gate in self.gates)
        ready = all(
            gate.status is DeployScyllaJoinSafetyProofStatus.PASSED
            for gate in self.gates
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
            or self.context_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION
            or self.gate_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_GATE_SCHEMA_VERSION
            or self.generation != 1
            or self.target_sequence < _MINIMUM_SEQUENCE
            or tuple(proof.gate for proof in self.proofs) != _EXTERNAL_GATES
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
                "deploy Scylla later-join safety evidence conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "later-join safety evidence digest")

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
    ) -> DeployScyllaLaterJoinSafetyEvidence:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={
                "generation",
                "target_sequence",
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
            label="later-join safety evidence",
        )
        parsed["proofs"] = tuple(
            DeployScyllaJoinSafetyProof.from_object(
                _mapping(item, "later-join safety proof")
            )
            for item in _array(value["proofs"], "later-join safety proofs")
        )
        parsed["gates"] = tuple(
            DeployScyllaLaterJoinSafetyGate.from_object(
                _mapping(item, "later-join safety gate")
            )
            for item in _array(value["gates"], "later-join safety gates")
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaLaterJoinSafetyStep:
    sequence: int
    mode: ScyllaBootstrapMode
    target_digest: str
    plan_step_digest: str
    latest_health_step_digest: str
    status: DeployScyllaLaterJoinSafetyStepStatus
    authorization_state: str
    blockers: tuple[str, ...]
    blocker_digest: str
    step_digest: str
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_STEP_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_STEP_SCHEMA_VERSION
            or self.sequence < 1
            or tuple(sorted(set(self.blockers))) != self.blockers
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.step_digest != _step_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla later-join safety step conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "later-join safety step digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, tuple_fields={"blockers"})

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaLaterJoinSafetyStep:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={"sequence"},
            tuple_fields={"blockers"},
            enum_fields={
                "mode": ScyllaBootstrapMode,
                "status": DeployScyllaLaterJoinSafetyStepStatus,
            },
            label="later-join safety step",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaLaterJoinSafetyReconciliation:
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
    latest_health_reconciliation_artifact_digest: str
    latest_health_reconciliation_digest: str
    steps: tuple[DeployScyllaLaterJoinSafetyStep, ...]
    step_count: int
    health_succeeded_count: int
    authorization_required_count: int
    blocked_count: int
    waiting_count: int
    completed_prefix_count: int
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
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
    )
    step_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_STEP_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        counts = Counter(step.status for step in self.steps)
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION
            or self.context_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
            or self.step_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_STEP_SCHEMA_VERSION
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
            != counts[DeployScyllaLaterJoinSafetyStepStatus.HEALTH_SUCCEEDED]
            or self.authorization_required_count
            != counts[DeployScyllaLaterJoinSafetyStepStatus.AUTHORIZATION_REQUIRED]
            or self.blocked_count
            != counts[DeployScyllaLaterJoinSafetyStepStatus.BLOCKED]
            or self.waiting_count
            != counts[DeployScyllaLaterJoinSafetyStepStatus.WAITING]
            or self.completed_prefix_count != self.target_sequence - 1
            or self.health_succeeded_count != self.completed_prefix_count
            or self.target_sequence < _MINIMUM_SEQUENCE
            or self.authorization_required_count + self.blocked_count != 1
            or self.later_join_count
            != max(0, self.step_count - self.completed_prefix_count - 1)
            or self.authorization_state != _AUTHORIZATION_NOT_CREATED
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
            or self.reconciliation_digest != _reconciliation_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla later-join safety reconciliation conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "later-join safety reconciliation digest")

    def to_object(self) -> dict[str, object]:
        return {
            **_dataclass_object(self, skip_fields={"steps"}),
            "steps": [step.to_object() for step in self.steps],
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaLaterJoinSafetyReconciliation:
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
                "completed_prefix_count",
                "target_sequence",
                "later_join_count",
            },
            uuid_fields={"cluster_uuid", "operation_id"},
            enum_fields={
                "journal_status": JournalStatus,
                "journal_phase": OperationPhase,
            },
            skip_fields={"steps"},
            label="later-join safety reconciliation",
        )
        parsed["steps"] = tuple(
            DeployScyllaLaterJoinSafetyStep.from_object(
                _mapping(item, "later-join safety step")
            )
            for item in _array(value["steps"], "later-join safety steps")
        )
        return cls(**parsed)  # type: ignore[arg-type]


class _SafetyRecord(Protocol):
    @property
    def cluster_uuid(self) -> uuid.UUID: ...

    @property
    def cluster_name(self) -> str: ...

    @property
    def operation_id(self) -> uuid.UUID: ...

    @property
    def target_sequence(self) -> int: ...

    def to_object(self) -> dict[str, object]: ...


_RecordT = TypeVar("_RecordT", bound=_SafetyRecord)


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaLaterJoinSafetyArtifact(Generic[_RecordT]):
    record: _RecordT
    artifact_digest: str


class _ImmutableSafetyStore(Generic[_RecordT]):
    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        sequence: int,
        *,
        path: Path,
        parser: Callable[[Mapping[str, object]], _RecordT],
        label: str,
        replace_file: Callable[[Path, Path], None] = os.replace,
    ) -> None:
        _require_canonical_paths(paths)
        self._paths = paths
        self._operation_id = _require_operation_id(operation_id)
        self._sequence = _require_later_sequence(sequence)
        self._path = path
        self._parser = parser
        self._label = label
        self._file = AtomicJsonFile(path, replace=replace_file)

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployScyllaLaterJoinSafetyArtifact[_RecordT]:
        value, digest = self._file.read()
        record = self._parser(value)
        if (
            record.operation_id != self._operation_id
            or record.target_sequence != self._sequence
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                f"deploy Scylla {self._label} identity conflicts"
            )
        return StoredDeployScyllaLaterJoinSafetyArtifact(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaLaterJoinSafetyArtifact[_RecordT]:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self, record: _RecordT, *, lock: ClusterLock
    ) -> tuple[
        StoredDeployScyllaLaterJoinSafetyArtifact[_RecordT],
        DeployScyllaLaterJoinSafetyArtifactState,
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
            return current, DeployScyllaLaterJoinSafetyArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaLaterJoinSafetyArtifact(record, digest),
            DeployScyllaLaterJoinSafetyArtifactState.CREATED,
        )


class DeployScyllaLaterJoinSafetyContextStore(
    _ImmutableSafetyStore[DeployScyllaLaterJoinSafetyContext]
):
    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        sequence: int,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
    ) -> None:
        super().__init__(
            paths,
            operation_id,
            sequence,
            path=deploy_scylla_later_join_safety_context_path(
                paths, operation_id, sequence
            ),
            parser=DeployScyllaLaterJoinSafetyContext.from_object,
            label="later-join safety context",
            replace_file=replace_file,
        )


class DeployScyllaLaterJoinSafetyEvidenceStore(
    _ImmutableSafetyStore[DeployScyllaLaterJoinSafetyEvidence]
):
    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        sequence: int,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
    ) -> None:
        super().__init__(
            paths,
            operation_id,
            sequence,
            path=deploy_scylla_later_join_safety_evidence_path(
                paths, operation_id, sequence
            ),
            parser=DeployScyllaLaterJoinSafetyEvidence.from_object,
            label="later-join safety evidence",
            replace_file=replace_file,
        )


class DeployScyllaLaterJoinSafetyReconciliationStore(
    _ImmutableSafetyStore[DeployScyllaLaterJoinSafetyReconciliation]
):
    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        sequence: int,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
    ) -> None:
        super().__init__(
            paths,
            operation_id,
            sequence,
            path=deploy_scylla_later_join_safety_reconciliation_path(
                paths, operation_id, sequence
            ),
            parser=DeployScyllaLaterJoinSafetyReconciliation.from_object,
            label="later-join safety reconciliation",
            replace_file=replace_file,
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaLaterJoinSafetyReport:
    operation_id: uuid.UUID
    required: bool
    state: str
    target_sequence: int | None
    target_status: str
    completed_prefix_count: int
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
    context_state: DeployScyllaLaterJoinSafetyArtifactState | None = None
    evidence_state: DeployScyllaLaterJoinSafetyArtifactState | None = None
    reconciliation_state: DeployScyllaLaterJoinSafetyArtifactState | None = None
    context_artifact_digest: str | None = None
    evidence_artifact_digest: str | None = None
    reconciliation_artifact_digest: str | None = None
    context_digest: str | None = None
    evidence_digest: str | None = None
    reconciliation_digest: str | None = None
    stage: str = _STAGE
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        artifacts = (
            self.context_state,
            self.evidence_state,
            self.reconciliation_state,
            self.context_artifact_digest,
            self.evidence_artifact_digest,
            self.reconciliation_artifact_digest,
            self.context_digest,
            self.evidence_digest,
            self.reconciliation_digest,
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_REPORT_SCHEMA_VERSION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.journal_updated
            or (
                self.required
                and (
                    self.state != "required"
                    or self.target_sequence is None
                    or self.target_sequence < _MINIMUM_SEQUENCE
                    or any(item is None for item in artifacts)
                )
            )
            or (
                not self.required
                and (
                    self.state != "not-required"
                    or self.target_sequence is not None
                    or any(item is not None for item in artifacts)
                    or any(
                        (
                            self.proof_count,
                            self.passed_count,
                            self.failed_count,
                            self.unknown_count,
                            self.blocker_count,
                            self.later_join_count,
                        )
                    )
                )
            )
        ):
            raise StatePersistenceError(
                "deploy Scylla later-join safety report conflicts"
            )
        for digest in (
            self.context_artifact_digest,
            self.evidence_artifact_digest,
            self.reconciliation_artifact_digest,
            self.context_digest,
            self.evidence_digest,
            self.reconciliation_digest,
        ):
            if digest is not None:
                validate_digest(digest, "later-join safety report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "artifacts": {
                "context": _artifact_report(
                    self.context_state,
                    self.context_artifact_digest,
                    self.context_digest,
                ),
                "evidence": _artifact_report(
                    self.evidence_state,
                    self.evidence_artifact_digest,
                    self.evidence_digest,
                ),
                "reconciliation": _artifact_report(
                    self.reconciliation_state,
                    self.reconciliation_artifact_digest,
                    self.reconciliation_digest,
                ),
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
                "completed_prefix_count": self.completed_prefix_count,
                "later_join_count": self.later_join_count,
                "survivor_count": self.survivor_count,
                "target_sequence": self.target_sequence,
                "target_status": self.target_status,
            },
            "schema_version": self.schema_version,
            "stage": self.stage,
            "state": self.state,
            "states": {
                "authorization": self.authorization_state,
                "execution": self.execution_state,
            },
        }


@dataclass(frozen=True, slots=True)
class _LaterJoinSafetyLoaded:
    base_chain: _SequenceThreeSafetyLoaded
    sequence_three_authorization: StoredDeployScyllaSequenceThreeJoinAuthorization
    sequence_three_execution: StoredDeployScyllaSequenceThreeJoinExecution
    sequence_three_evidence: StoredDeployScyllaSequenceThreeJoinEvidence
    latest_health_execution: Any
    latest_health_evidence: Any
    latest_health_reconciliation: Any
    latest_health_execution_schema_version: str
    latest_health_evidence_schema_version: str
    latest_health_reconciliation_schema_version: str
    completed_health_history_digest: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    completed_prefix_count: int
    completed_prefix_digest: str
    target_sequence: int | None
    target_digest: str | None
    target_plan_step_digest: str | None
    target_topology_digest: str | None
    target_storage_evidence_digest: str | None
    target_configuration_evidence_digest: str | None
    target_capacity_evidence_digest: str | None
    target_package_version_digest: str | None
    playbook_source_digest: str | None
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


def bind_deploy_scylla_later_join_safety(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proofs: tuple[DeployScyllaJoinSafetyProof, ...],
) -> DeployScyllaLaterJoinSafetyReport:
    """Persist safety for only the canonically derived first unfinished join."""

    if not isinstance(proofs, tuple) or not all(
        isinstance(proof, DeployScyllaJoinSafetyProof) for proof in proofs
    ):
        raise StateConflictError("deploy Scylla later-join safety proofs are malformed")
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_artifacts(paths, operation_id)
    loaded = _load_later_join_safety(paths, operation_id, lock=lock)

    if loaded.target_sequence is None:
        if proofs:
            raise StateConflictError(
                "deploy Scylla later-join safety is not required and accepts no proofs"
            )
        _refuse_completed_plan_artifacts(
            paths,
            operation_id,
            completed_sequence=loaded.completed_prefix_count,
        )
        return _not_required_report(loaded)

    sequence = loaded.target_sequence
    stores = (
        DeployScyllaLaterJoinSafetyContextStore(paths, operation_id, sequence),
        DeployScyllaLaterJoinSafetyEvidenceStore(paths, operation_id, sequence),
        DeployScyllaLaterJoinSafetyReconciliationStore(paths, operation_id, sequence),
    )
    for store in stores:
        validate_state_file(store.path, allow_missing=True)
    normalized = _normalize_proofs(proofs)
    _validate_proofs(normalized, loaded)
    context_store, evidence_store, reconciliation_store = stores
    if evidence_store.path.exists() and not context_store.path.exists():
        raise StateConflictError(
            "deploy Scylla later-join safety evidence exists without context"
        )
    if reconciliation_store.path.exists() and not evidence_store.path.exists():
        raise StateConflictError(
            "deploy Scylla later-join safety reconciliation exists without evidence"
        )
    existing_context = _read_optional(context_store, loaded, lock)
    created_at = (
        existing_context.record.created_at
        if existing_context is not None
        else _timestamp()
    )
    context, context_state = context_store.write_locked(
        _build_context(loaded, normalized, created_at=created_at), lock=lock
    )
    existing_evidence = _read_optional(evidence_store, loaded, lock)
    evidence, evidence_state = evidence_store.write_locked(
        _build_evidence(
            loaded,
            context,
            normalized,
            created_at=(
                existing_evidence.record.created_at
                if existing_evidence is not None
                else created_at
            ),
        ),
        lock=lock,
    )
    existing_reconciliation = _read_optional(reconciliation_store, loaded, lock)
    reconciliation, reconciliation_state = reconciliation_store.write_locked(
        _build_reconciliation(
            loaded,
            context,
            evidence,
            created_at=(
                existing_reconciliation.record.created_at
                if existing_reconciliation is not None
                else created_at
            ),
        ),
        lock=lock,
    )
    return _report(
        context,
        evidence,
        reconciliation,
        context_state=context_state,
        evidence_state=evidence_state,
        reconciliation_state=reconciliation_state,
    )


def deploy_scylla_later_join_safety_context_path(
    paths: StatePaths, operation_id: uuid.UUID, sequence: int
) -> Path:
    return _artifact_path(
        paths,
        operation_id,
        sequence,
        DEPLOY_SCYLLA_LATER_JOIN_SAFETY_CONTEXT_FILENAME_SUFFIX,
    )


def deploy_scylla_later_join_safety_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID, sequence: int
) -> Path:
    return _artifact_path(
        paths,
        operation_id,
        sequence,
        DEPLOY_SCYLLA_LATER_JOIN_SAFETY_EVIDENCE_FILENAME_SUFFIX,
    )


def deploy_scylla_later_join_safety_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID, sequence: int
) -> Path:
    return _artifact_path(
        paths,
        operation_id,
        sequence,
        DEPLOY_SCYLLA_LATER_JOIN_SAFETY_RECONCILIATION_FILENAME_SUFFIX,
    )


def deploy_scylla_later_join_safety_context_id_from_filename(
    name: str,
) -> tuple[uuid.UUID, int] | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_LATER_JOIN_SAFETY_CONTEXT_FILENAME_SUFFIX
    )


def deploy_scylla_later_join_safety_evidence_id_from_filename(
    name: str,
) -> tuple[uuid.UUID, int] | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_LATER_JOIN_SAFETY_EVIDENCE_FILENAME_SUFFIX
    )


def deploy_scylla_later_join_safety_reconciliation_id_from_filename(
    name: str,
) -> tuple[uuid.UUID, int] | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_LATER_JOIN_SAFETY_RECONCILIATION_FILENAME_SUFFIX
    )


def _load_later_join_safety(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
    latest_completed_sequence: int | None = None,
) -> _LaterJoinSafetyLoaded:
    authorized = _load_sequence_three_join_authorization_context(
        paths, operation_id, lock=lock
    )
    chain = authorized.chain
    configure = _load_reconciliation_context(paths, operation_id, lock=lock)
    current = _loaded(configure.authorization_context)
    planning = current.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    journal = deploy.journal
    inventory = deploy.inventory
    trust = planning.base.trust
    plan_steps = chain.plan_steps

    scope = _derive_sequence_three_join_scope(authorized)
    sequence_authorization = DeployScyllaSequenceThreeJoinAuthorizationStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_authorization = _build_sequence_three_authorization(
        authorized,
        scope=scope,
        proof=sequence_authorization.record.proof,
        created_at=sequence_authorization.record.created_at,
    )
    sequence_execution = DeployScyllaSequenceThreeJoinExecutionStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    sequence_evidence = DeployScyllaSequenceThreeJoinEvidenceStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    baseline_execution = DeployScyllaPostSequenceThreeHealthExecutionStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    baseline_evidence = DeployScyllaPostSequenceThreeHealthEvidenceStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    baseline_reconciliation = DeployScyllaPostSequenceThreeHealthReconciliationStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    if latest_completed_sequence is not None and latest_completed_sequence < 3:
        raise StateConflictError(
            "deploy Scylla later-join completed sequence is invalid"
        )
    from scylla_vms.ansible.deploy_scylla_post_later_join_health import (
        load_completed_later_join_health,
    )

    completed_health = (
        None
        if latest_completed_sequence == 3
        else load_completed_later_join_health(
            paths,
            operation_id,
            lock=lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
            maximum_sequence=(
                latest_completed_sequence
                if latest_completed_sequence is not None
                and latest_completed_sequence >= _MINIMUM_SEQUENCE
                else None
            ),
        )
    )
    if (
        latest_completed_sequence is not None
        and latest_completed_sequence >= 4
        and (
            completed_health is None
            or completed_health.sequence != latest_completed_sequence
        )
    ):
        raise StateConflictError(
            "deploy Scylla later-join latest health sequence conflicts"
        )
    latest_execution: Any
    latest_evidence: Any
    latest_reconciliation: Any
    if completed_health is None:
        latest_execution = baseline_execution
        latest_evidence = baseline_evidence
        latest_reconciliation = baseline_reconciliation
        completed_health_history_digest = _digest_object(
            {
                "evidence_artifact_digest": baseline_evidence.artifact_digest,
                "execution_artifact_digest": baseline_execution.artifact_digest,
                "reconciliation_artifact_digest": (
                    baseline_reconciliation.artifact_digest
                ),
                "sequence": 3,
            }
        )
    else:
        latest_execution = completed_health.execution
        latest_evidence = completed_health.evidence
        latest_reconciliation = completed_health.reconciliation
        completed_health_history_digest = completed_health.history_digest

    authorization = sequence_authorization.record
    execution = sequence_execution.record
    joined = sequence_evidence.record
    baseline_health_execution = baseline_execution.record
    baseline_health = baseline_evidence.record
    baseline_health_reconciliation = baseline_reconciliation.record
    health_execution = latest_execution.record
    health = latest_evidence.record
    health_reconciliation = latest_reconciliation.record
    binding = health.binding
    if (
        authorization != expected_authorization
        or authorization.consumed
        or execution.state is not DeployScyllaSequenceThreeJoinExecutionState.SUCCEEDED
        or not execution.completed
        or execution.invocation_count != 1
        or not execution.ordinary_authorization_consumed
        or not execution.narrow_authorization_consumed
        or execution.manual_recovery_required
        or execution.automatic_retry_allowed
        or execution.binding.authorization_artifact_digest
        != sequence_authorization.artifact_digest
        or execution.binding.authorization_digest != authorization.authorization_digest
        or execution.evidence_digest != joined.evidence_digest
        or execution.result_digest != joined.result_digest
        or joined.binding != execution.binding
        or joined.sequence != 3
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
        or baseline_health_execution.state
        is not DeployScyllaHealthExecutionState.SUCCEEDED
        or not baseline_health_execution.completed
        or baseline_health_execution.manual_recovery_required
        or baseline_health_execution.automatic_retry_allowed
        or baseline_health_execution.evidence_digest != baseline_health.evidence_digest
        or baseline_reconciliation.record.health_execution_artifact_digest
        != baseline_execution.artifact_digest
        or baseline_reconciliation.record.health_evidence_artifact_digest
        != baseline_evidence.artifact_digest
        or baseline_health_reconciliation.current_member_count != 3
        or health_execution.state.value
        != DeployScyllaHealthExecutionState.SUCCEEDED.value
        or not health_execution.completed
        or health_execution.manual_recovery_required
        or health_execution.automatic_retry_allowed
        or health_execution.binding != binding
        or health_execution.evidence_digest != health.evidence_digest
        or health_execution.result_digest != health.result_digest
        or not health.strict_complete
        or latest_reconciliation.record.health_execution_artifact_digest
        != latest_execution.artifact_digest
        or latest_reconciliation.record.health_evidence_artifact_digest
        != latest_evidence.artifact_digest
        or latest_reconciliation.record.health_evidence_digest != health.evidence_digest
    ):
        raise StateConflictError(
            "deploy Scylla later-join safety requires the exact successful "
            "sequence-three and latest complete-set health chain"
        )

    scylla_hosts = {
        host.logical_id: host
        for host in inventory.record.inventory.hosts
        if host.role is HostRole.SCYLLA
    }
    by_digest = {_digest_object(stable_id): stable_id for stable_id in scylla_hosts}
    try:
        desired_ids = tuple(by_digest[step.target_digest] for step in plan_steps)
    except KeyError as error:
        raise StateConflictError(
            "deploy Scylla later-join safety desired topology drifted"
        ) from error
    completed_count = health_reconciliation.current_member_count
    if completed_count < 3 or completed_count > len(plan_steps):
        raise StateConflictError(
            "deploy Scylla later-join safety completed prefix count conflicts"
        )
    survivor_ids = desired_ids[:completed_count]
    health_ids = tuple(node.stable_id for node in health.nodes)
    target_sequence = health_reconciliation.next_join_sequence
    target = None if target_sequence is None else plan_steps[target_sequence - 1]
    if (
        desired_ids != tuple(dict.fromkeys(desired_ids))
        or survivor_ids != tuple(sorted(survivor_ids))
        or health_ids != survivor_ids
        or binding.current_member_count != completed_count
        or binding.current_member_set_digest != _digest_object(list(survivor_ids))
        or binding.desired_member_count != len(desired_ids)
        or binding.desired_member_set_digest != _digest_object(list(desired_ids))
        or health_reconciliation.current_member_set_digest
        != _digest_object(list(survivor_ids))
        or health_reconciliation.health_succeeded_count != completed_count
        or len(health_reconciliation.steps) != len(plan_steps)
        or health_reconciliation.bootstrap_sequence_complete
        != (target_sequence is None)
        or health_reconciliation.next_step_required != (target_sequence is not None)
        or (
            target_sequence is not None
            and (
                target_sequence != completed_count + 1
                or target_sequence < _MINIMUM_SEQUENCE
                or target is None
                or target.sequence != target_sequence
                or target.mode is not ScyllaBootstrapMode.JOIN_EXISTING
                or target.target_digest
                != _digest_object(desired_ids[target_sequence - 1])
            )
        )
    ):
        raise StateConflictError(
            "deploy Scylla later-join safety membership sequence conflicts"
        )
    for original, reconciled in zip(
        plan_steps, health_reconciliation.steps, strict=True
    ):
        expected_status = (
            DeployScyllaPostSequenceThreeHealthStepStatus.HEALTH_SUCCEEDED.value
            if original.sequence <= completed_count
            else DeployScyllaPostSequenceThreeHealthStepStatus.WAITING_FOR_SAFETY.value
            if original.sequence == target_sequence
            else DeployScyllaPostSequenceThreeHealthStepStatus.WAITING_FOR_PRECEDING_HEALTH.value
        )
        if (
            reconciled.sequence != original.sequence
            or reconciled.mode is not original.mode
            or reconciled.target_digest != original.target_digest
            or reconciled.plan_step_digest != original.step_digest
            or reconciled.status.value != expected_status
        ):
            raise StateConflictError(
                "deploy Scylla later-join safety requires a contiguous completed prefix"
            )

    fixed_binding_conflict = completed_health is None and (
        binding.sequence_three_authorization_artifact_digest
        != sequence_authorization.artifact_digest
        or binding.sequence_three_authorization_digest
        != authorization.authorization_digest
        or binding.sequence_three_execution_artifact_digest
        != sequence_execution.artifact_digest
        or binding.sequence_three_execution_binding_digest
        != execution.binding.binding_digest
        or binding.sequence_three_evidence_artifact_digest
        != sequence_evidence.artifact_digest
        or binding.sequence_three_evidence_digest != joined.evidence_digest
    )
    generic_binding_conflict = completed_health is not None and (
        binding.completed_sequence != completed_count
        or binding.later_join_execution_artifact_digest
        != completed_health.reconciliation.record.later_join_execution_artifact_digest
        or binding.later_join_evidence_artifact_digest
        != completed_health.reconciliation.record.later_join_evidence_artifact_digest
        or binding.later_join_evidence_digest
        != completed_health.reconciliation.record.later_join_evidence_digest
    )
    if (
        journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
        or binding.cluster_uuid != metadata.cluster_uuid
        or binding.cluster_name != metadata.cluster_name
        or binding.operation_id != operation_id
        or binding.journal_generation != journal.record.generation
        or binding.journal_digest != journal.digest
        or binding.bootstrap_context_artifact_digest
        != chain.bootstrap_context_artifact_digest
        or binding.bootstrap_plan_artifact_digest
        != chain.bootstrap_plan_artifact_digest
        or binding.bootstrap_plan_digest != chain.bootstrap_plan_digest
        or fixed_binding_conflict
        or generic_binding_conflict
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
        or binding.catalog_digest != current.catalog_digest
        or binding.source_version != current.source.version
        or binding.source_digest != current.source.digest
    ):
        raise StateConflictError(
            "deploy Scylla later-join safety current canonical chain drifted"
        )

    check_states = dict(health.check_states)
    policy_states = dict(health.policy_states)
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
    if (
        policy_states != _EXPECTED_POLICY_STATES
        or any(
            check_states.get(name) is not HealthCheckStatus.PASSED
            for name in (
                "cross-view-consistency",
                "membership",
                "schema-agreement",
                "streaming",
                "topology",
            )
        )
        or not node_health
        or health.topology_digest is None
        or health.schema_digest is None
        or health.streaming_state != "complete"
    ):
        raise StateConflictError(
            "deploy Scylla later-join safety latest health is incomplete"
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
    target_id: str | None = None
    target_capacity_digest: str | None = None
    if target is not None:
        target_id = desired_ids[target.sequence - 1]
        if (
            target_id in survivor_ids
            or target_id not in storage_entries
            or target_id not in install_entries
            or target_id not in configuration_entries
        ):
            raise StateConflictError(
                "deploy Scylla later-join target evidence is incomplete"
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
                "deploy Scylla later-join target provenance conflicts"
            )

    no_competing_operation = _has_no_competing_operation(
        paths,
        operation_id,
        cluster_uuid=metadata.cluster_uuid,
        cluster_name=metadata.cluster_name,
    )
    canonical = {
        "completed-prior-membership": DeployScyllaJoinSafetyProofStatus.PASSED,
        "configuration-provenance": DeployScyllaJoinSafetyProofStatus.PASSED,
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
            if node_health and health.nodes[0].stable_id == desired_ids[0]
            else DeployScyllaJoinSafetyProofStatus.FAILED
        ),
        "service-api-cql": (
            DeployScyllaJoinSafetyProofStatus.PASSED
            if node_health
            else DeployScyllaJoinSafetyProofStatus.FAILED
        ),
        "storage-provenance": DeployScyllaJoinSafetyProofStatus.PASSED,
        "streaming": _proof_status(check_states["streaming"]),
        "survivor-health": (
            DeployScyllaJoinSafetyProofStatus.PASSED
            if node_health
            else DeployScyllaJoinSafetyProofStatus.FAILED
        ),
        "target-absence": (
            DeployScyllaJoinSafetyProofStatus.PASSED
            if target_id is None or target_id not in health_ids
            else DeployScyllaJoinSafetyProofStatus.FAILED
        ),
        "topology": _proof_status(check_states["topology"]),
    }
    if set(canonical) != set((*_HEALTH_GATES, *_CURRENT_STATE_GATES)):
        raise StateConflictError(
            "deploy Scylla later-join canonical safety gates conflict"
        )

    current_state = {
        "catalog_digest": current.catalog_digest,
        "configure_evidence_artifact_digest": (
            chain.post_join_health_evidence.record.binding.configure_evidence_artifact_digest
        ),
        "install_evidence_artifact_digest": (
            chain.post_join_health_evidence.record.binding.install_evidence_artifact_digest
        ),
        "inventory_artifact_digest": inventory.digest,
        "observation_artifact_digest": deploy.observation.digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "source_digest": current.source.digest,
        "storage_evidence_artifact_digest": (
            chain.post_join_health_evidence.record.binding.storage_evidence_artifact_digest
        ),
        "trust_artifact_digest": trust.digest,
    }
    completed_prefix = {
        "bootstrap_context_artifact_digest": chain.bootstrap_context_artifact_digest,
        "bootstrap_plan_artifact_digest": chain.bootstrap_plan_artifact_digest,
        "first_join_authorization_artifact_digest": (
            chain.first_join_authorization.artifact_digest
        ),
        "first_join_execution_artifact_digest": (
            chain.first_join_execution.artifact_digest
        ),
        "first_join_evidence_artifact_digest": chain.first_join_evidence.artifact_digest,
        "post_first_join_health_execution_artifact_digest": (
            chain.post_join_health_execution.artifact_digest
        ),
        "post_first_join_health_evidence_artifact_digest": (
            chain.post_join_health_evidence.artifact_digest
        ),
        "post_first_join_health_reconciliation_artifact_digest": (
            chain.post_join_health_reconciliation.artifact_digest
        ),
        "sequence_three_authorization_artifact_digest": (
            sequence_authorization.artifact_digest
        ),
        "sequence_three_execution_artifact_digest": sequence_execution.artifact_digest,
        "sequence_three_evidence_artifact_digest": sequence_evidence.artifact_digest,
        "latest_health_execution_artifact_digest": latest_execution.artifact_digest,
        "latest_health_evidence_artifact_digest": latest_evidence.artifact_digest,
        "latest_health_reconciliation_artifact_digest": (
            latest_reconciliation.artifact_digest
        ),
        "completed_health_history_digest": completed_health_history_digest,
    }
    validated_chain = {
        **completed_prefix,
        "completed_prefix_count": completed_count,
        "current_state_digest": _digest_object(current_state),
        "journal_digest": journal.digest,
        "target_sequence": target_sequence,
    }
    return _LaterJoinSafetyLoaded(
        base_chain=chain,
        sequence_three_authorization=sequence_authorization,
        sequence_three_execution=sequence_execution,
        sequence_three_evidence=sequence_evidence,
        latest_health_execution=latest_execution,
        latest_health_evidence=latest_evidence,
        latest_health_reconciliation=latest_reconciliation,
        latest_health_execution_schema_version=latest_execution.record.schema_version,
        latest_health_evidence_schema_version=latest_evidence.record.schema_version,
        latest_health_reconciliation_schema_version=(
            latest_reconciliation.record.schema_version
        ),
        completed_health_history_digest=completed_health_history_digest,
        cluster_uuid=metadata.cluster_uuid,
        cluster_name=metadata.cluster_name,
        operation_id=operation_id,
        request_digest=journal.record.request_digest,
        journal_generation=journal.record.generation,
        journal_digest=journal.digest,
        journal_status=journal.record.status,
        journal_phase=journal.record.phase,
        completed_prefix_count=completed_count,
        completed_prefix_digest=_digest_object(completed_prefix),
        target_sequence=target_sequence,
        target_digest=None if target is None else target.target_digest,
        target_plan_step_digest=None if target is None else target.step_digest,
        target_topology_digest=None if target is None else target.topology_digest,
        target_storage_evidence_digest=(
            None if target is None else target.storage_evidence_digest
        ),
        target_configuration_evidence_digest=(
            None if target is None else target.configuration_evidence_digest
        ),
        target_capacity_evidence_digest=target_capacity_digest,
        target_package_version_digest=(
            None if target is None else target.package_version_digest
        ),
        playbook_source_digest=(
            None if target is None else target.playbook_source_digest
        ),
        survivor_ids=survivor_ids,
        survivor_set_digest=_digest_object(list(survivor_ids)),
        survivor_health_digest=_digest_object(
            [node.evidence_digest for node in health.nodes]
        ),
        active_seed_set_digest=_digest_object([desired_ids[0]]),
        current_topology_digest=health.topology_digest,
        current_schema_digest=health.schema_digest,
        current_membership_digest=health.membership_digest,
        current_host_mapping_digest=health.host_id_mapping_digest,
        current_state_digest=_digest_object(current_state),
        validated_chain_digest=_digest_object(validated_chain),
        canonical_gate_states=tuple(sorted(canonical.items())),
        plan_steps=plan_steps,
    )


def _normalize_proofs(
    proofs: tuple[DeployScyllaJoinSafetyProof, ...],
) -> tuple[DeployScyllaJoinSafetyProof, ...]:
    ordered = tuple(sorted(proofs, key=lambda proof: proof.gate))
    if tuple(proof.gate for proof in ordered) != _EXTERNAL_GATES:
        raise StateConflictError(
            "deploy Scylla later-join safety requires exact independent "
            "backup, capacity, quorum, and replication proofs"
        )
    return ordered


def _validate_proofs(
    proofs: tuple[DeployScyllaJoinSafetyProof, ...],
    loaded: _LaterJoinSafetyLoaded,
) -> None:
    health = loaded.latest_health_evidence.record
    if (
        loaded.target_sequence is None
        or loaded.target_digest is None
        or loaded.target_storage_evidence_digest is None
        or loaded.target_configuration_evidence_digest is None
        or loaded.playbook_source_digest is None
    ):
        raise StateConflictError("deploy Scylla later-join safety is not required")
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
                "deploy Scylla later-join safety proof is stale or binding-mismatched"
            )


def _build_context(
    loaded: _LaterJoinSafetyLoaded,
    proofs: tuple[DeployScyllaJoinSafetyProof, ...],
    *,
    created_at: str,
) -> DeployScyllaLaterJoinSafetyContext:
    target_sequence = _required_target_sequence(loaded)
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
        "bootstrap_context_artifact_digest": (
            loaded.base_chain.bootstrap_context_artifact_digest
        ),
        "bootstrap_context_record_digest": (
            loaded.base_chain.bootstrap_context_record_digest
        ),
        "bootstrap_plan_artifact_digest": (
            loaded.base_chain.bootstrap_plan_artifact_digest
        ),
        "bootstrap_plan_digest": loaded.base_chain.bootstrap_plan_digest,
        "sequence_three_authorization_artifact_digest": (
            loaded.sequence_three_authorization.artifact_digest
        ),
        "sequence_three_authorization_digest": (
            loaded.sequence_three_authorization.record.authorization_digest
        ),
        "sequence_three_execution_artifact_digest": (
            loaded.sequence_three_execution.artifact_digest
        ),
        "sequence_three_execution_binding_digest": (
            loaded.sequence_three_execution.record.binding.binding_digest
        ),
        "sequence_three_evidence_artifact_digest": (
            loaded.sequence_three_evidence.artifact_digest
        ),
        "sequence_three_evidence_digest": (
            loaded.sequence_three_evidence.record.evidence_digest
        ),
        "latest_health_execution_artifact_digest": (
            loaded.latest_health_execution.artifact_digest
        ),
        "latest_health_evidence_artifact_digest": (
            loaded.latest_health_evidence.artifact_digest
        ),
        "latest_health_evidence_digest": (
            loaded.latest_health_evidence.record.evidence_digest
        ),
        "latest_health_reconciliation_artifact_digest": (
            loaded.latest_health_reconciliation.artifact_digest
        ),
        "latest_health_reconciliation_digest": (
            loaded.latest_health_reconciliation.record.reconciliation_digest
        ),
        "latest_health_execution_schema_version": (
            loaded.latest_health_execution_schema_version
        ),
        "latest_health_evidence_schema_version": (
            loaded.latest_health_evidence_schema_version
        ),
        "latest_health_reconciliation_schema_version": (
            loaded.latest_health_reconciliation_schema_version
        ),
        "completed_prefix_count": loaded.completed_prefix_count,
        "completed_prefix_digest": loaded.completed_prefix_digest,
        "target_sequence": target_sequence,
        "target_digest": _required_digest(loaded.target_digest),
        "target_plan_step_digest": _required_digest(loaded.target_plan_step_digest),
        "target_topology_digest": _required_digest(loaded.target_topology_digest),
        "target_storage_evidence_digest": _required_digest(
            loaded.target_storage_evidence_digest
        ),
        "target_configuration_evidence_digest": _required_digest(
            loaded.target_configuration_evidence_digest
        ),
        "target_capacity_evidence_digest": _required_digest(
            loaded.target_capacity_evidence_digest
        ),
        "target_package_version_digest": _required_digest(
            loaded.target_package_version_digest
        ),
        "playbook_source_digest": _required_digest(loaded.playbook_source_digest),
        "survivor_count": len(loaded.survivor_ids),
        "survivor_set_digest": loaded.survivor_set_digest,
        "survivor_health_digest": loaded.survivor_health_digest,
        "active_seed_count": 1,
        "active_seed_set_digest": loaded.active_seed_set_digest,
        "current_topology_digest": loaded.current_topology_digest,
        "current_schema_digest": loaded.current_schema_digest,
        "current_membership_digest": loaded.current_membership_digest,
        "current_host_mapping_digest": loaded.current_host_mapping_digest,
        "current_state_digest": loaded.current_state_digest,
        "validated_chain_digest": loaded.validated_chain_digest,
        "required_gates": _REQUIRED_GATES,
        "proof_set_digest": _digest_object([proof.proof_digest for proof in proofs]),
        "policy_digest": _digest_object(
            {
                "completed_prefix_count": loaded.completed_prefix_count,
                "derivation": "first-unfinished-bootstrap-plan-sequence",
                "minimum_sequence": _MINIMUM_SEQUENCE,
                "required_gates": list(_REQUIRED_GATES),
                "target_sequence": target_sequence,
            }
        ),
        "context_digest": "",
    }
    values["context_digest"] = _context_digest_from_values(values)
    return DeployScyllaLaterJoinSafetyContext(**values)  # type: ignore[arg-type]


def _build_evidence(
    loaded: _LaterJoinSafetyLoaded,
    context: StoredDeployScyllaLaterJoinSafetyArtifact[
        DeployScyllaLaterJoinSafetyContext
    ],
    proofs: tuple[DeployScyllaJoinSafetyProof, ...],
    *,
    created_at: str,
) -> DeployScyllaLaterJoinSafetyEvidence:
    canonical = dict(loaded.canonical_gate_states)
    proof_by_gate = {proof.gate: proof for proof in proofs}
    health = loaded.latest_health_evidence.record
    gates: list[DeployScyllaLaterJoinSafetyGate] = []
    for name in _REQUIRED_GATES:
        if name in proof_by_gate:
            proof = proof_by_gate[name]
            status = proof.status
            source = DeployScyllaLaterJoinSafetyGateSource.INDEPENDENT_POLICY_PROOF
            evidence_digest = proof.evidence_digest
            binding_digest = proof.proof_digest
        else:
            status = canonical[name]
            if name in _CURRENT_STATE_GATES:
                source = DeployScyllaLaterJoinSafetyGateSource.CURRENT_CANONICAL_STATE
                evidence_digest = loaded.current_state_digest
                binding_digest = loaded.validated_chain_digest
            else:
                source = (
                    DeployScyllaLaterJoinSafetyGateSource.LATEST_COMPLETE_SET_HEALTH
                )
                evidence_digest = health.evidence_digest
                binding_digest = _digest_object(
                    {
                        "completed_prefix_count": loaded.completed_prefix_count,
                        "current_member_set_digest": loaded.survivor_set_digest,
                        "health_evidence_digest": health.evidence_digest,
                        "target_digest": _required_digest(loaded.target_digest),
                        "target_sequence": _required_target_sequence(loaded),
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
        gates.append(DeployScyllaLaterJoinSafetyGate(**values))  # type: ignore[arg-type]
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
        "target_sequence": _required_target_sequence(loaded),
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
    return DeployScyllaLaterJoinSafetyEvidence(**values)  # type: ignore[arg-type]


def _build_reconciliation(
    loaded: _LaterJoinSafetyLoaded,
    context: StoredDeployScyllaLaterJoinSafetyArtifact[
        DeployScyllaLaterJoinSafetyContext
    ],
    evidence: StoredDeployScyllaLaterJoinSafetyArtifact[
        DeployScyllaLaterJoinSafetyEvidence
    ],
    *,
    created_at: str,
) -> DeployScyllaLaterJoinSafetyReconciliation:
    target_sequence = _required_target_sequence(loaded)
    health_steps = loaded.latest_health_reconciliation.record.steps
    steps: list[DeployScyllaLaterJoinSafetyStep] = []
    target_blockers: tuple[str, ...] = ()
    for original, health_step in zip(loaded.plan_steps, health_steps, strict=True):
        sequence = original.sequence
        if sequence <= loaded.completed_prefix_count:
            status = DeployScyllaLaterJoinSafetyStepStatus.HEALTH_SUCCEEDED
            authorization_state = "not-required"
            blockers: tuple[str, ...] = ()
        elif sequence == target_sequence:
            if evidence.record.ready_for_authorization:
                status = DeployScyllaLaterJoinSafetyStepStatus.AUTHORIZATION_REQUIRED
                authorization_state = _AUTHORIZATION_REQUIRED
                blockers = ("join-authorization-not-collected",)
            else:
                status = DeployScyllaLaterJoinSafetyStepStatus.BLOCKED
                authorization_state = _AUTHORIZATION_NOT_CREATED
                blockers = evidence.record.blockers
            target_blockers = blockers
        else:
            status = DeployScyllaLaterJoinSafetyStepStatus.WAITING
            authorization_state = "waiting"
            blockers = ("preceding-join-not-completed",)
        values: dict[str, object] = {
            "sequence": sequence,
            "mode": original.mode,
            "target_digest": original.target_digest,
            "plan_step_digest": original.step_digest,
            "latest_health_step_digest": health_step.step_digest,
            "status": status,
            "authorization_state": authorization_state,
            "blockers": blockers,
            "blocker_digest": _digest_object(list(blockers)),
            "step_digest": "",
        }
        values["step_digest"] = _step_digest_from_values(values)
        steps.append(DeployScyllaLaterJoinSafetyStep(**values))  # type: ignore[arg-type]
    step_tuple = tuple(steps)
    counts = Counter(step.status for step in step_tuple)
    target = step_tuple[target_sequence - 1]
    later = step_tuple[target_sequence:]
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
        "latest_health_reconciliation_artifact_digest": (
            loaded.latest_health_reconciliation.artifact_digest
        ),
        "latest_health_reconciliation_digest": (
            loaded.latest_health_reconciliation.record.reconciliation_digest
        ),
        "steps": step_tuple,
        "step_count": len(step_tuple),
        "health_succeeded_count": counts[
            DeployScyllaLaterJoinSafetyStepStatus.HEALTH_SUCCEEDED
        ],
        "authorization_required_count": counts[
            DeployScyllaLaterJoinSafetyStepStatus.AUTHORIZATION_REQUIRED
        ],
        "blocked_count": counts[DeployScyllaLaterJoinSafetyStepStatus.BLOCKED],
        "waiting_count": counts[DeployScyllaLaterJoinSafetyStepStatus.WAITING],
        "completed_prefix_count": loaded.completed_prefix_count,
        "target_sequence": target_sequence,
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
    return DeployScyllaLaterJoinSafetyReconciliation(
        **values  # type: ignore[arg-type]
    )


def _report(
    context: StoredDeployScyllaLaterJoinSafetyArtifact[
        DeployScyllaLaterJoinSafetyContext
    ],
    evidence: StoredDeployScyllaLaterJoinSafetyArtifact[
        DeployScyllaLaterJoinSafetyEvidence
    ],
    reconciliation: StoredDeployScyllaLaterJoinSafetyArtifact[
        DeployScyllaLaterJoinSafetyReconciliation
    ],
    *,
    context_state: DeployScyllaLaterJoinSafetyArtifactState,
    evidence_state: DeployScyllaLaterJoinSafetyArtifactState,
    reconciliation_state: DeployScyllaLaterJoinSafetyArtifactState,
) -> DeployScyllaLaterJoinSafetyReport:
    return DeployScyllaLaterJoinSafetyReport(
        operation_id=context.record.operation_id,
        required=True,
        state="required",
        target_sequence=reconciliation.record.target_sequence,
        target_status=reconciliation.record.target_status,
        completed_prefix_count=reconciliation.record.completed_prefix_count,
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
        context_state=context_state,
        evidence_state=evidence_state,
        reconciliation_state=reconciliation_state,
        context_artifact_digest=context.artifact_digest,
        evidence_artifact_digest=evidence.artifact_digest,
        reconciliation_artifact_digest=reconciliation.artifact_digest,
        context_digest=context.record.context_digest,
        evidence_digest=evidence.record.evidence_digest,
        reconciliation_digest=reconciliation.record.reconciliation_digest,
    )


def _not_required_report(
    loaded: _LaterJoinSafetyLoaded,
) -> DeployScyllaLaterJoinSafetyReport:
    return DeployScyllaLaterJoinSafetyReport(
        operation_id=loaded.operation_id,
        required=False,
        state="not-required",
        target_sequence=None,
        target_status="not-required",
        completed_prefix_count=loaded.completed_prefix_count,
        survivor_count=len(loaded.survivor_ids),
        active_seed_count=1,
        proof_count=0,
        passed_count=0,
        failed_count=0,
        unknown_count=0,
        blocker_count=0,
        later_join_count=0,
        authorization_state="not-required",
        execution_state="not-required",
        journal_status=loaded.journal_status,
        journal_phase=loaded.journal_phase,
        journal_updated=False,
    )


def _read_optional(
    store: _ImmutableSafetyStore[_RecordT],
    loaded: _LaterJoinSafetyLoaded,
    lock: ClusterLock,
) -> StoredDeployScyllaLaterJoinSafetyArtifact[_RecordT] | None:
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
    gates: tuple[DeployScyllaLaterJoinSafetyGate, ...],
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


def _context_digest(record: DeployScyllaLaterJoinSafetyContext) -> str:
    return _context_digest_from_values(record.to_object())


def _context_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for name, field in DeployScyllaLaterJoinSafetyContext.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["context_digest"] = ""
    return _digest_object(value)


def _gate_digest(record: DeployScyllaLaterJoinSafetyGate) -> str:
    return _gate_digest_from_values(record.to_object())


def _gate_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    value.setdefault(
        "schema_version",
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_GATE_SCHEMA_VERSION,
    )
    value["gate_digest"] = ""
    return _digest_object(value)


def _evidence_digest(record: DeployScyllaLaterJoinSafetyEvidence) -> str:
    return _evidence_digest_from_values(record.to_object())


def _evidence_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for name, field in DeployScyllaLaterJoinSafetyEvidence.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["evidence_digest"] = ""
    return _digest_object(value)


def _step_digest(record: DeployScyllaLaterJoinSafetyStep) -> str:
    return _step_digest_from_values(record.to_object())


def _step_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    value.setdefault(
        "schema_version",
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_STEP_SCHEMA_VERSION,
    )
    value["step_digest"] = ""
    return _digest_object(value)


def _reconciliation_digest(
    record: DeployScyllaLaterJoinSafetyReconciliation,
) -> str:
    return _reconciliation_digest_from_values(record.to_object())


def _reconciliation_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for (
        name,
        field,
    ) in DeployScyllaLaterJoinSafetyReconciliation.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["reconciliation_digest"] = ""
    return _digest_object(value)


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


def _required_target_sequence(loaded: _LaterJoinSafetyLoaded) -> int:
    if loaded.target_sequence is None:
        raise StateConflictError("deploy Scylla later-join safety is not required")
    return loaded.target_sequence


def _required_digest(value: str | None) -> str:
    if value is None:
        raise StateConflictError("deploy Scylla later-join safety binding is missing")
    return value


def _artifact_report(
    state: DeployScyllaLaterJoinSafetyArtifactState | None,
    artifact_digest: str | None,
    record_digest: str | None,
) -> dict[str, object] | None:
    if state is None:
        return None
    return {
        "digest": artifact_digest,
        "record_digest": record_digest,
        "state": state.value,
    }


def _artifact_path(
    paths: StatePaths, operation_id: uuid.UUID, sequence: int, suffix: str
) -> Path:
    _require_canonical_paths(paths)
    path = paths.operations / (
        f"{_require_operation_id(operation_id)}{_LATER_JOIN_FILENAME_STEM}"
        f"{_require_later_sequence(sequence)}{suffix}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Scylla later-join safety path is not canonical"
        )
    return path


def _operation_id_from_filename(name: str, suffix: str) -> tuple[uuid.UUID, int] | None:
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


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    suffixes = (
        DEPLOY_SCYLLA_LATER_JOIN_SAFETY_CONTEXT_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_LATER_JOIN_SAFETY_EVIDENCE_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_LATER_JOIN_SAFETY_RECONCILIATION_FILENAME_SUFFIX,
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Scylla later-join safety artifacts"
        ) from error
    for entry in entries:
        for suffix in suffixes:
            if not entry.name.endswith(suffix):
                continue
            parsed = _operation_id_from_filename(entry.name, suffix)
            if (
                parsed is None
                and entry.name.startswith(str(operation_id))
                and _LATER_JOIN_NAMESPACE_STEM in entry.name
            ):
                validate_state_file(entry)
                raise StateConflictError(
                    "deploy Scylla later-join safety artifacts are ambiguous"
                )


def _refuse_completed_plan_artifacts(
    paths: StatePaths, operation_id: uuid.UUID, *, completed_sequence: int
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Scylla later-join safety artifacts"
        ) from error
    parsers = (
        deploy_scylla_later_join_safety_context_id_from_filename,
        deploy_scylla_later_join_safety_evidence_id_from_filename,
        deploy_scylla_later_join_safety_reconciliation_id_from_filename,
    )
    for entry in entries:
        if any(
            parsed is not None
            and parsed[0] == operation_id
            and parsed[1] > completed_sequence
            for parser in parsers
            if (parsed := parser(entry.name)) is not None
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy Scylla later-join safety artifacts conflict with completed plan"
            )


def _require_later_sequence(sequence: int) -> int:
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < _MINIMUM_SEQUENCE
    ):
        raise StatePersistenceError(
            "deploy Scylla later-join sequence is not canonical"
        )
    return sequence


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy Scylla later-join safety requires the matching held deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy Scylla later-join safety paths are not canonical"
        )


def _timestamp() -> str:
    return format_timestamp(datetime.now(UTC))


__all__ = [
    "ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_GATE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_STEP_SCHEMA_VERSION",
    "DeployScyllaLaterJoinSafetyArtifactState",
    "DeployScyllaLaterJoinSafetyContext",
    "DeployScyllaLaterJoinSafetyContextStore",
    "DeployScyllaLaterJoinSafetyEvidence",
    "DeployScyllaLaterJoinSafetyEvidenceStore",
    "DeployScyllaLaterJoinSafetyGate",
    "DeployScyllaLaterJoinSafetyGateSource",
    "DeployScyllaLaterJoinSafetyReconciliation",
    "DeployScyllaLaterJoinSafetyReconciliationStore",
    "DeployScyllaLaterJoinSafetyReport",
    "DeployScyllaLaterJoinSafetyStep",
    "DeployScyllaLaterJoinSafetyStepStatus",
    "StoredDeployScyllaLaterJoinSafetyArtifact",
    "bind_deploy_scylla_later_join_safety",
    "deploy_scylla_later_join_safety_context_id_from_filename",
    "deploy_scylla_later_join_safety_context_path",
    "deploy_scylla_later_join_safety_evidence_id_from_filename",
    "deploy_scylla_later_join_safety_evidence_path",
    "deploy_scylla_later_join_safety_reconciliation_id_from_filename",
    "deploy_scylla_later_join_safety_reconciliation_path",
]
