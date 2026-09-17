"""Independent join-safety evidence before the first deploy join authorization.

This subprocess-free owner revalidates the complete initial-seed and health
checkpoint chain, derives the exact first waiting join and current survivor
set, and persists immutable redacted context, evidence, and reconciliation
records.  It never authorizes or executes a join and never changes the common
journal.
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
from typing import cast

from scylla_vms.ansible.deploy_plan import _digest_object, _require_operation_id
from scylla_vms.ansible.deploy_scylla_bootstrap_authorization import (
    _load_authorization_context,
)
from scylla_vms.ansible.deploy_scylla_bootstrap_execution import (
    DeployScyllaBootstrapEvidenceStore,
    DeployScyllaBootstrapExecutionState,
    DeployScyllaBootstrapExecutionStore,
    StoredDeployScyllaBootstrapEvidence,
    StoredDeployScyllaBootstrapExecution,
)
from scylla_vms.ansible.deploy_scylla_bootstrap_plan import (
    DeployScyllaBootstrapProofState,
    StoredDeployScyllaBootstrapContext,
    StoredDeployScyllaBootstrapPlan,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import _loaded
from scylla_vms.ansible.deploy_scylla_configure_reconciliation import (
    _load_reconciliation_context,
)
from scylla_vms.ansible.deploy_scylla_health_checkpoint import (
    ANSIBLE_DEPLOY_SCYLLA_HEALTH_CHECKPOINT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_HEALTH_EXECUTION_SCHEMA_VERSION,
    DeployScyllaHealthCheckpointStore,
    DeployScyllaHealthEvidenceStore,
    DeployScyllaHealthExecutionState,
    DeployScyllaHealthExecutionStore,
    StoredDeployScyllaHealthCheckpoint,
    StoredDeployScyllaHealthEvidence,
    StoredDeployScyllaHealthExecution,
    build_deploy_scylla_health_checkpoint,
)
from scylla_vms.ansible.scylla_bootstrap import (
    ScyllaBootstrapMode,
    ScyllaBootstrapStatus,
)
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
    parse_uuid,
    require_exact_keys,
    require_string,
    validate_digest,
)
from scylla_vms.state import (
    StatePaths,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)

ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-safety-proof/v1"
)
ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-safety-context/v1"
)
ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_GATE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-safety-gate/v1"
)
ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-safety-evidence/v1"
)
ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_STEP_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-safety-step/v1"
)
ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-safety-reconciliation/v1"
)
ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-safety-report/v1"
)

DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-join-safety-context.json"
)
DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-join-safety-evidence.json"
)
DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-join-safety-reconciliation.json"
)

_OPERATION = "deploy"
_STAGE = "pre-first-join-safety"
_REQUIRED_GATES = (
    "capacity",
    "completed-prior-membership",
    "schema",
    "seed-health",
    "streaming",
    "survivor-health",
    "target-absence",
    "topology",
)
_NOT_APPLICABLE_GATES = ("backup-policy", "quorum", "replication")
_ALL_GATES = tuple(sorted((*_REQUIRED_GATES, *_NOT_APPLICABLE_GATES)))
_CAPACITY_GATE = "capacity"
_AUTHORIZATION_REQUIRED = "authorization-required"
_AUTHORIZATION_NOT_CREATED = "not-created"
_EXECUTION_UNAVAILABLE = "unavailable"
_PUBLIC_WORKFLOW_UNAVAILABLE = "unavailable"


class DeployScyllaJoinSafetyProofStatus(StrEnum):
    """Closed status vocabulary for independent policy evidence."""

    PASSED = "passed"
    FAILED = "failed"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not-applicable"


class DeployScyllaJoinSafetyProofSource(StrEnum):
    """Reviewed source families accepted at the join-safety boundary."""

    INDEPENDENT_BACKUP_POLICY_REVIEW = "independent-backup-policy-review"
    INDEPENDENT_BOOTSTRAP_CAPACITY_REVIEW = "independent-bootstrap-capacity-review"
    INDEPENDENT_QUORUM_REVIEW = "independent-quorum-review"
    INDEPENDENT_REPLICATION_REVIEW = "independent-replication-review"


_PROOF_SOURCE_BY_GATE = {
    "backup-policy": DeployScyllaJoinSafetyProofSource.INDEPENDENT_BACKUP_POLICY_REVIEW,
    "capacity": (
        DeployScyllaJoinSafetyProofSource.INDEPENDENT_BOOTSTRAP_CAPACITY_REVIEW
    ),
    "quorum": DeployScyllaJoinSafetyProofSource.INDEPENDENT_QUORUM_REVIEW,
    "replication": DeployScyllaJoinSafetyProofSource.INDEPENDENT_REPLICATION_REVIEW,
}


class DeployScyllaJoinSafetyGateSource(StrEnum):
    """Closed source vocabulary for persisted gate decisions."""

    CANONICAL_HEALTH = "canonical-health"
    CANONICAL_STORAGE = "canonical-storage"
    INDEPENDENT_CAPACITY = "independent-capacity"
    INITIAL_DEPLOY_POLICY = "initial-deploy-policy"


class DeployScyllaJoinSafetyArtifactState(StrEnum):
    CREATED = "created"
    REUSED = "reused"


class DeployScyllaJoinSafetyStepStatus(StrEnum):
    HEALTH_SUCCEEDED = "health-succeeded"
    AUTHORIZATION_REQUIRED = "authorization-required"
    BLOCKED = "blocked"
    WAITING = "waiting-for-preceding-complete-health"


@dataclass(frozen=True, slots=True)
class DeployScyllaJoinSafetyProof:
    """Normalized independent safety proof with digest-only exact bindings."""

    gate: str
    status: DeployScyllaJoinSafetyProofStatus
    source: DeployScyllaJoinSafetyProofSource
    captured_at: str
    evidence_digest: str
    health_evidence_digest: str
    target_digest: str
    survivor_set_digest: str
    topology_digest: str
    target_storage_evidence_digest: str
    target_configuration_evidence_digest: str
    playbook_source_digest: str
    proof_digest: str
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION
            or self.gate not in _PROOF_SOURCE_BY_GATE
            or self.source is not _PROOF_SOURCE_BY_GATE[self.gate]
            or not isinstance(self.status, DeployScyllaJoinSafetyProofStatus)
            or not isinstance(self.source, DeployScyllaJoinSafetyProofSource)
            or self.proof_digest != _proof_digest(self)
        ):
            raise StateConflictError("deploy Scylla join-safety proof is malformed")
        parse_timestamp(self.captured_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy Scylla join-safety proof digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def create(
        cls,
        *,
        status: DeployScyllaJoinSafetyProofStatus,
        captured_at: str,
        evidence_digest: str,
        health_evidence_digest: str,
        target_digest: str,
        survivor_set_digest: str,
        topology_digest: str,
        target_storage_evidence_digest: str,
        target_configuration_evidence_digest: str,
        playbook_source_digest: str,
        gate: str = _CAPACITY_GATE,
    ) -> DeployScyllaJoinSafetyProof:
        try:
            source = _PROOF_SOURCE_BY_GATE[gate]
        except KeyError as error:
            raise StateConflictError(
                "deploy Scylla join-safety proof gate is unsupported"
            ) from error
        values: dict[str, object] = {
            "gate": gate,
            "status": status,
            "source": source,
            "captured_at": captured_at,
            "evidence_digest": evidence_digest,
            "health_evidence_digest": health_evidence_digest,
            "target_digest": target_digest,
            "survivor_set_digest": survivor_set_digest,
            "topology_digest": topology_digest,
            "target_storage_evidence_digest": target_storage_evidence_digest,
            "target_configuration_evidence_digest": (
                target_configuration_evidence_digest
            ),
            "playbook_source_digest": playbook_source_digest,
            "proof_digest": "",
            "schema_version": ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION,
        }
        values["proof_digest"] = _proof_digest_from_values(values)
        return cls(**values)  # type: ignore[arg-type]

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaJoinSafetyProof:
        require_exact_keys(value, set(cls.__dataclass_fields__), "join-safety proof")
        try:
            return cls(
                gate=require_string(value, "gate"),
                status=DeployScyllaJoinSafetyProofStatus(
                    require_string(value, "status")
                ),
                source=DeployScyllaJoinSafetyProofSource(
                    require_string(value, "source")
                ),
                captured_at=require_string(value, "captured_at"),
                evidence_digest=require_string(value, "evidence_digest"),
                health_evidence_digest=require_string(value, "health_evidence_digest"),
                target_digest=require_string(value, "target_digest"),
                survivor_set_digest=require_string(value, "survivor_set_digest"),
                topology_digest=require_string(value, "topology_digest"),
                target_storage_evidence_digest=require_string(
                    value, "target_storage_evidence_digest"
                ),
                target_configuration_evidence_digest=require_string(
                    value, "target_configuration_evidence_digest"
                ),
                playbook_source_digest=require_string(value, "playbook_source_digest"),
                proof_digest=require_string(value, "proof_digest"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Scylla join-safety proof enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployScyllaJoinSafetyContext:
    """Immutable digest-only scope and policy binding for the first join."""

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
    bootstrap_execution_artifact_digest: str
    bootstrap_evidence_artifact_digest: str
    bootstrap_evidence_digest: str
    health_execution_artifact_digest: str
    health_evidence_artifact_digest: str
    health_evidence_digest: str
    health_checkpoint_artifact_digest: str
    health_checkpoint_digest: str
    health_captured_at: str
    target_sequence: int
    target_digest: str
    target_plan_step_digest: str
    target_topology_digest: str
    target_storage_evidence_digest: str
    target_configuration_evidence_digest: str
    target_capacity_evidence_digest: str
    playbook_source_digest: str
    survivor_count: int
    survivor_set_digest: str
    survivor_health_digest: str
    current_topology_digest: str
    current_schema_digest: str
    current_membership_digest: str
    required_gates: tuple[str, ...]
    not_applicable_gates: tuple[str, ...]
    policy_digest: str
    proof_digest: str
    context_digest: str
    health_execution_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_HEALTH_EXECUTION_SCHEMA_VERSION
    )
    health_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_SCHEMA_VERSION
    )
    health_checkpoint_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_HEALTH_CHECKPOINT_SCHEMA_VERSION
    )
    proof_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
            or self.health_execution_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_HEALTH_EXECUTION_SCHEMA_VERSION
            or self.health_evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_SCHEMA_VERSION
            or self.health_checkpoint_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_HEALTH_CHECKPOINT_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.target_sequence != 2
            or self.survivor_count < 1
            or self.required_gates != _REQUIRED_GATES
            or self.not_applicable_gates != _NOT_APPLICABLE_GATES
            or self.policy_digest
            != _digest_object(
                {
                    "not_applicable": list(self.not_applicable_gates),
                    "required": list(self.required_gates),
                }
            )
            or self.context_digest != _context_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla join-safety context identity or policy conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        parse_timestamp(self.health_captured_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy Scylla join-safety context digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(
            self, tuple_fields={"required_gates", "not_applicable_gates"}
        )

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaJoinSafetyContext:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={
                "generation",
                "journal_generation",
                "target_sequence",
                "survivor_count",
            },
            uuid_fields={"cluster_uuid", "operation_id"},
            tuple_fields={"required_gates", "not_applicable_gates"},
            enum_fields={
                "journal_status": JournalStatus,
                "journal_phase": OperationPhase,
            },
            label="join-safety context",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaJoinSafetyGate:
    name: str
    required: bool
    status: DeployScyllaJoinSafetyProofStatus
    source: DeployScyllaJoinSafetyGateSource
    captured_at: str
    evidence_digest: str
    binding_digest: str
    gate_digest: str
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_GATE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_GATE_SCHEMA_VERSION
            or self.name not in _ALL_GATES
            or self.required != (self.name in _REQUIRED_GATES)
            or self.gate_digest != _gate_digest(self)
            or (
                not self.required
                and self.status is not DeployScyllaJoinSafetyProofStatus.NOT_APPLICABLE
            )
        ):
            raise StatePersistenceError("deploy Scylla join-safety gate conflicts")
        parse_timestamp(self.captured_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy Scylla join-safety gate digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaJoinSafetyGate:
        parsed = _parse_dataclass(
            cls,
            value,
            boolean_fields={"required"},
            enum_fields={
                "status": DeployScyllaJoinSafetyProofStatus,
                "source": DeployScyllaJoinSafetyGateSource,
            },
            label="join-safety gate",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaJoinSafetyEvidence:
    generation: int
    created_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    context_artifact_digest: str
    context_digest: str
    proof: DeployScyllaJoinSafetyProof
    proof_digest: str
    gates: tuple[DeployScyllaJoinSafetyGate, ...]
    gate_count: int
    required_passed_count: int
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
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
    )
    proof_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION
    gate_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_GATE_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        counts = Counter(gate.status for gate in self.gates)
        required_ready = all(
            gate.status is DeployScyllaJoinSafetyProofStatus.PASSED
            for gate in self.gates
            if gate.required
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
            or self.context_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION
            or self.gate_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_GATE_SCHEMA_VERSION
            or self.generation != 1
            or tuple(gate.name for gate in self.gates) != _ALL_GATES
            or self.gate_count != len(self.gates)
            or self.required_passed_count
            != sum(
                gate.required
                and gate.status is DeployScyllaJoinSafetyProofStatus.PASSED
                for gate in self.gates
            )
            or self.failed_count != counts[DeployScyllaJoinSafetyProofStatus.FAILED]
            or self.unknown_count != counts[DeployScyllaJoinSafetyProofStatus.UNKNOWN]
            or self.not_applicable_count
            != counts[DeployScyllaJoinSafetyProofStatus.NOT_APPLICABLE]
            or self.not_applicable_count != len(_NOT_APPLICABLE_GATES)
            or self.blockers != _gate_blockers(self.gates)
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.ready_for_authorization != required_ready
            or self.authorization_state
            != (
                _AUTHORIZATION_REQUIRED
                if required_ready
                else _AUTHORIZATION_NOT_CREATED
            )
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
            or self.proof_digest != self.proof.proof_digest
            or self.evidence_digest != _evidence_digest(self)
        ):
            raise StatePersistenceError("deploy Scylla join-safety evidence conflicts")
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy Scylla join-safety evidence digest")

    def to_object(self) -> dict[str, object]:
        return {
            **_dataclass_object(
                self,
                tuple_fields={"blockers"},
                skip_fields={"proof", "gates"},
            ),
            "proof": self.proof.to_object(),
            "gates": [gate.to_object() for gate in self.gates],
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaJoinSafetyEvidence:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={
                "generation",
                "gate_count",
                "required_passed_count",
                "failed_count",
                "unknown_count",
                "not_applicable_count",
            },
            uuid_fields={"cluster_uuid", "operation_id"},
            boolean_fields={"ready_for_authorization"},
            tuple_fields={"blockers"},
            skip_fields={"proof", "gates"},
            label="join-safety evidence",
        )
        parsed["proof"] = DeployScyllaJoinSafetyProof.from_object(
            _mapping(value["proof"], "join-safety proof")
        )
        parsed["gates"] = tuple(
            DeployScyllaJoinSafetyGate.from_object(_mapping(item, "join-safety gate"))
            for item in _array(value["gates"], "join-safety gates")
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaJoinSafetyStep:
    sequence: int
    mode: ScyllaBootstrapMode
    target_digest: str
    plan_step_digest: str
    health_checkpoint_step_digest: str
    status: DeployScyllaJoinSafetyStepStatus
    authorization_state: str
    blockers: tuple[str, ...]
    blocker_digest: str
    step_digest: str
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_STEP_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_STEP_SCHEMA_VERSION
            or self.sequence < 1
            or tuple(sorted(set(self.blockers))) != self.blockers
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.step_digest != _step_digest(self)
        ):
            raise StatePersistenceError("deploy Scylla join-safety step conflicts")
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy Scylla join-safety step digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, tuple_fields={"blockers"})

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaJoinSafetyStep:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={"sequence"},
            tuple_fields={"blockers"},
            enum_fields={
                "mode": ScyllaBootstrapMode,
                "status": DeployScyllaJoinSafetyStepStatus,
            },
            label="join-safety step",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaJoinSafetyReconciliation:
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
    health_checkpoint_artifact_digest: str
    health_checkpoint_digest: str
    steps: tuple[DeployScyllaJoinSafetyStep, ...]
    step_count: int
    health_succeeded_count: int
    authorization_required_count: int
    blocked_count: int
    waiting_count: int
    first_join_sequence: int
    first_join_status: str
    first_join_blocker_digest: str
    later_join_count: int
    later_join_set_digest: str
    authorization_state: str
    execution_state: str
    public_workflow_state: str
    reconciliation_digest: str
    context_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
    )
    step_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_STEP_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        statuses = Counter(step.status for step in self.steps)
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION
            or self.context_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
            or self.step_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_STEP_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.first_join_sequence != 2
            or self.step_count != len(self.steps)
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, self.step_count + 1))
            or self.health_succeeded_count
            != statuses[DeployScyllaJoinSafetyStepStatus.HEALTH_SUCCEEDED]
            or self.authorization_required_count
            != statuses[DeployScyllaJoinSafetyStepStatus.AUTHORIZATION_REQUIRED]
            or self.blocked_count != statuses[DeployScyllaJoinSafetyStepStatus.BLOCKED]
            or self.waiting_count != statuses[DeployScyllaJoinSafetyStepStatus.WAITING]
            or self.health_succeeded_count != 1
            or self.authorization_required_count + self.blocked_count != 1
            or self.later_join_count != max(0, self.step_count - 2)
            or self.authorization_state != _AUTHORIZATION_NOT_CREATED
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
            or self.reconciliation_digest != _reconciliation_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla join-safety reconciliation conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy Scylla join-safety reconciliation digest")

    def to_object(self) -> dict[str, object]:
        return {
            **_dataclass_object(self, skip_fields={"steps"}),
            "steps": [step.to_object() for step in self.steps],
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaJoinSafetyReconciliation:
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
                "first_join_sequence",
                "later_join_count",
            },
            uuid_fields={"cluster_uuid", "operation_id"},
            enum_fields={
                "journal_status": JournalStatus,
                "journal_phase": OperationPhase,
            },
            skip_fields={"steps"},
            label="join-safety reconciliation",
        )
        parsed["steps"] = tuple(
            DeployScyllaJoinSafetyStep.from_object(_mapping(item, "join-safety step"))
            for item in _array(value["steps"], "join-safety steps")
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaJoinSafetyContext:
    record: DeployScyllaJoinSafetyContext
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaJoinSafetyEvidence:
    record: DeployScyllaJoinSafetyEvidence
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaJoinSafetyReconciliation:
    record: DeployScyllaJoinSafetyReconciliation
    artifact_digest: str


class DeployScyllaJoinSafetyContextStore:
    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
    ) -> None:
        _require_canonical_paths(paths)
        self._paths = paths
        self._operation_id = _require_operation_id(operation_id)
        self._path = deploy_scylla_join_safety_context_path(paths, operation_id)
        self._file = AtomicJsonFile(self._path, replace=replace_file)

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployScyllaJoinSafetyContext:
        value, digest = self._file.read()
        record = DeployScyllaJoinSafetyContext.from_object(value)
        _require_identity(
            record.operation_id,
            record.cluster_uuid,
            record.cluster_name,
            operation_id=self._operation_id,
            cluster_uuid=expected_cluster_uuid,
            cluster_name=expected_cluster_name,
        )
        return StoredDeployScyllaJoinSafetyContext(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaJoinSafetyContext:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self, record: DeployScyllaJoinSafetyContext, *, lock: ClusterLock
    ) -> tuple[
        StoredDeployScyllaJoinSafetyContext, DeployScyllaJoinSafetyArtifactState
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy Scylla join-safety context is immutable; use a new operation"
                )
            return current, DeployScyllaJoinSafetyArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaJoinSafetyContext(record, digest),
            DeployScyllaJoinSafetyArtifactState.CREATED,
        )


class DeployScyllaJoinSafetyEvidenceStore:
    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
    ) -> None:
        _require_canonical_paths(paths)
        self._paths = paths
        self._operation_id = _require_operation_id(operation_id)
        self._path = deploy_scylla_join_safety_evidence_path(paths, operation_id)
        self._file = AtomicJsonFile(self._path, replace=replace_file)

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployScyllaJoinSafetyEvidence:
        value, digest = self._file.read()
        record = DeployScyllaJoinSafetyEvidence.from_object(value)
        _require_identity(
            record.operation_id,
            record.cluster_uuid,
            record.cluster_name,
            operation_id=self._operation_id,
            cluster_uuid=expected_cluster_uuid,
            cluster_name=expected_cluster_name,
        )
        return StoredDeployScyllaJoinSafetyEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaJoinSafetyEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self, record: DeployScyllaJoinSafetyEvidence, *, lock: ClusterLock
    ) -> tuple[
        StoredDeployScyllaJoinSafetyEvidence, DeployScyllaJoinSafetyArtifactState
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
                    "deploy Scylla join-safety evidence is immutable; use a new operation"
                )
            return current, DeployScyllaJoinSafetyArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaJoinSafetyEvidence(record, digest),
            DeployScyllaJoinSafetyArtifactState.CREATED,
        )


class DeployScyllaJoinSafetyReconciliationStore:
    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
    ) -> None:
        _require_canonical_paths(paths)
        self._paths = paths
        self._operation_id = _require_operation_id(operation_id)
        self._path = deploy_scylla_join_safety_reconciliation_path(paths, operation_id)
        self._file = AtomicJsonFile(self._path, replace=replace_file)

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployScyllaJoinSafetyReconciliation:
        value, digest = self._file.read()
        record = DeployScyllaJoinSafetyReconciliation.from_object(value)
        _require_identity(
            record.operation_id,
            record.cluster_uuid,
            record.cluster_name,
            operation_id=self._operation_id,
            cluster_uuid=expected_cluster_uuid,
            cluster_name=expected_cluster_name,
        )
        return StoredDeployScyllaJoinSafetyReconciliation(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaJoinSafetyReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self, record: DeployScyllaJoinSafetyReconciliation, *, lock: ClusterLock
    ) -> tuple[
        StoredDeployScyllaJoinSafetyReconciliation,
        DeployScyllaJoinSafetyArtifactState,
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
                    "deploy Scylla join-safety reconciliation is immutable; "
                    "use a new operation"
                )
            return current, DeployScyllaJoinSafetyArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaJoinSafetyReconciliation(record, digest),
            DeployScyllaJoinSafetyArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaJoinSafetyReport:
    operation_id: uuid.UUID
    stage: str
    context_state: DeployScyllaJoinSafetyArtifactState
    evidence_state: DeployScyllaJoinSafetyArtifactState
    reconciliation_state: DeployScyllaJoinSafetyArtifactState
    context_artifact_digest: str
    evidence_artifact_digest: str
    reconciliation_artifact_digest: str
    context_digest: str
    evidence_digest: str
    reconciliation_digest: str
    proof_status: DeployScyllaJoinSafetyProofStatus
    required_gate_count: int
    required_passed_count: int
    not_applicable_gate_count: int
    failed_count: int
    unknown_count: int
    first_join_sequence: int
    first_join_status: str
    later_join_count: int
    authorization_state: str
    execution_state: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    journal_updated: bool
    context_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
    )
    reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_REPORT_SCHEMA_VERSION

    def to_object(self) -> dict[str, object]:
        return {
            "artifacts": {
                "context": {
                    "digest": self.context_artifact_digest,
                    "record_digest": self.context_digest,
                    "schema_version": self.context_schema_version,
                    "state": self.context_state.value,
                },
                "evidence": {
                    "digest": self.evidence_artifact_digest,
                    "record_digest": self.evidence_digest,
                    "schema_version": self.evidence_schema_version,
                    "state": self.evidence_state.value,
                },
                "reconciliation": {
                    "digest": self.reconciliation_artifact_digest,
                    "record_digest": self.reconciliation_digest,
                    "schema_version": self.reconciliation_schema_version,
                    "state": self.reconciliation_state.value,
                },
            },
            "gates": {
                "failed_count": self.failed_count,
                "not_applicable_count": self.not_applicable_gate_count,
                "required_count": self.required_gate_count,
                "required_passed_count": self.required_passed_count,
                "unknown_count": self.unknown_count,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": self.journal_updated,
            },
            "next_join": {
                "later_join_count": self.later_join_count,
                "sequence": self.first_join_sequence,
                "status": self.first_join_status,
            },
            "operation_id": str(self.operation_id),
            "proof_status": self.proof_status.value,
            "schema_version": self.schema_version,
            "stage": self.stage,
            "states": {
                "authorization": self.authorization_state,
                "execution": self.execution_state,
            },
        }


@dataclass(frozen=True, slots=True)
class _JoinSafetyLoaded:
    bootstrap_context: StoredDeployScyllaBootstrapContext
    bootstrap_plan: StoredDeployScyllaBootstrapPlan
    bootstrap_execution: StoredDeployScyllaBootstrapExecution
    bootstrap_evidence: StoredDeployScyllaBootstrapEvidence
    health_execution: StoredDeployScyllaHealthExecution
    health_evidence: StoredDeployScyllaHealthEvidence
    health_checkpoint: StoredDeployScyllaHealthCheckpoint
    target_sequence: int
    target_digest: str
    target_plan_step_digest: str
    target_topology_digest: str
    target_storage_evidence_digest: str
    target_configuration_evidence_digest: str
    target_capacity_evidence_digest: str
    playbook_source_digest: str
    survivor_count: int
    survivor_set_digest: str
    survivor_health_digest: str
    current_topology_digest: str
    current_schema_digest: str
    current_membership_digest: str
    canonical_capacity_ready: bool


def bind_deploy_scylla_join_safety(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proofs: tuple[DeployScyllaJoinSafetyProof, ...],
) -> DeployScyllaJoinSafetyReport:
    """Persist exact first-join safety evidence without authorization or calls."""

    if (
        not isinstance(proofs, tuple)
        or len(proofs) != 1
        or not isinstance(proofs[0], DeployScyllaJoinSafetyProof)
    ):
        raise StateConflictError(
            "deploy Scylla join safety requires one normalized capacity proof"
        )
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_artifacts(paths, operation_id)
    loaded = _load_join_safety(paths, operation_id, lock=lock)
    proof = proofs[0]
    _validate_proof(proof, loaded)

    context_store = DeployScyllaJoinSafetyContextStore(paths, operation_id)
    evidence_store = DeployScyllaJoinSafetyEvidenceStore(paths, operation_id)
    reconciliation_store = DeployScyllaJoinSafetyReconciliationStore(
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
            "deploy Scylla join-safety evidence exists without context"
        )
    if reconciliation_store.path.exists() and not evidence_store.path.exists():
        raise StateConflictError(
            "deploy Scylla join-safety reconciliation exists without evidence"
        )

    existing_context = _read_context(context_store, loaded, lock)
    context_record = _build_context(
        loaded,
        proof=proof,
        created_at=(
            existing_context.record.created_at
            if existing_context is not None
            else _timestamp()
        ),
    )
    context, context_state = context_store.write_locked(context_record, lock=lock)

    existing_evidence = _read_safety_evidence(evidence_store, loaded, lock)
    evidence_record = _build_evidence(
        loaded,
        context=context,
        proof=proof,
        created_at=(
            existing_evidence.record.created_at
            if existing_evidence is not None
            else context.record.created_at
        ),
    )
    evidence, evidence_state = evidence_store.write_locked(evidence_record, lock=lock)

    existing_reconciliation = _read_reconciliation(reconciliation_store, loaded, lock)
    reconciliation_record = _build_reconciliation(
        loaded,
        context=context,
        evidence=evidence,
        created_at=(
            existing_reconciliation.record.created_at
            if existing_reconciliation is not None
            else evidence.record.created_at
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


def deploy_scylla_join_safety_context_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths, operation_id, DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_FILENAME_SUFFIX
    )


def deploy_scylla_join_safety_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths, operation_id, DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_FILENAME_SUFFIX
    )


def deploy_scylla_join_safety_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths,
        operation_id,
        DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_FILENAME_SUFFIX,
    )


def deploy_scylla_join_safety_context_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_FILENAME_SUFFIX
    )


def deploy_scylla_join_safety_evidence_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_FILENAME_SUFFIX
    )


def deploy_scylla_join_safety_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_FILENAME_SUFFIX
    )


def _load_join_safety(
    paths: StatePaths, operation_id: uuid.UUID, *, lock: ClusterLock
) -> _JoinSafetyLoaded:
    bootstrap = _load_authorization_context(paths, operation_id, lock=lock)
    chain = _load_reconciliation_context(paths, operation_id, lock=lock)
    loaded = _loaded(chain.authorization_context)
    metadata = loaded.planning.base.deploy.metadata.record
    context = bootstrap.context
    plan = bootstrap.plan
    if len(plan.record.steps) < 2:
        raise StateConflictError(
            "deploy Scylla join safety requires a waiting join target"
        )

    bootstrap_execution = DeployScyllaBootstrapExecutionStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    bootstrap_evidence = DeployScyllaBootstrapEvidenceStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    health_execution = DeployScyllaHealthExecutionStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    health_evidence = DeployScyllaHealthEvidenceStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    health_checkpoint = DeployScyllaHealthCheckpointStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    entry = bootstrap_evidence.record.entry
    health = health_evidence.record
    checkpoint = health_checkpoint.record
    expected_checkpoint = build_deploy_scylla_health_checkpoint(
        context=context,
        plan=plan,
        execution_artifact_digest=health_execution.artifact_digest,
        evidence_artifact_digest=health_evidence.artifact_digest,
        evidence=health,
        created_at=checkpoint.created_at,
    )
    if (
        bootstrap_execution.record.state
        is not DeployScyllaBootstrapExecutionState.SUCCEEDED
        or bootstrap_execution.record.binding != bootstrap_evidence.record.binding
        or entry.status is not ScyllaBootstrapStatus.BOOTSTRAPPED
        or entry.host_id_digest is None
        or entry.recovery_required
        or health_execution.record.state
        is not DeployScyllaHealthExecutionState.SUCCEEDED
        or health_execution.record.binding != health.binding
        or health_execution.record.evidence_digest != health.evidence_digest
        or not health.strict_complete
        or checkpoint != expected_checkpoint
        or checkpoint.next_join_sequence != 2
        or checkpoint.authorization_required_count != 0
        or checkpoint.blocked_count != 1
        or checkpoint.steps[0].status.value != "health-succeeded"
    ):
        raise StateConflictError(
            "deploy Scylla join safety requires the exact complete health checkpoint"
        )
    binding = health.binding
    if (
        binding.bootstrap_context_artifact_digest != context.artifact_digest
        or binding.bootstrap_context_record_digest != context.record.record_digest
        or binding.bootstrap_plan_artifact_digest != plan.artifact_digest
        or binding.bootstrap_plan_digest != plan.record.plan_digest
        or binding.bootstrap_execution_artifact_digest
        != bootstrap_execution.artifact_digest
        or binding.bootstrap_evidence_artifact_digest
        != bootstrap_evidence.artifact_digest
        or binding.bootstrap_evidence_digest != entry.evidence_digest
        or checkpoint.health_execution_artifact_digest
        != health_execution.artifact_digest
        or checkpoint.health_evidence_artifact_digest != health_evidence.artifact_digest
        or checkpoint.health_evidence_digest != health.evidence_digest
    ):
        raise StateConflictError(
            "deploy Scylla join-safety checkpoint provenance conflicts"
        )

    inventory = loaded.planning.base.deploy.inventory
    scylla_hosts = {
        host.logical_id: host
        for host in inventory.record.inventory.hosts
        if host.role is HostRole.SCYLLA
    }
    ids_by_digest = {_digest_object(stable_id): stable_id for stable_id in scylla_hosts}
    try:
        ordered_ids = tuple(
            ids_by_digest[step.target_digest] for step in plan.record.steps
        )
    except KeyError as error:
        raise StateConflictError(
            "deploy Scylla join-safety target topology drifted"
        ) from error
    survivor_ids = tuple(node.stable_id for node in health.nodes)
    if (
        ordered_ids != tuple(dict.fromkeys(ordered_ids))
        or survivor_ids != ordered_ids[:1]
        or binding.active_member_count != len(survivor_ids)
        or binding.active_member_set_digest != _digest_object(list(survivor_ids))
        or binding.future_member_count != len(ordered_ids) - len(survivor_ids)
    ):
        raise StateConflictError(
            "deploy Scylla join-safety survivor or target scope drifted"
        )

    target_step = plan.record.steps[1]
    target_id = ordered_ids[1]
    target_host = scylla_hosts[target_id]
    storage_entries = {
        item.stable_id: item
        for item in chain.authorization_context.install.authorization_context.evidence.record.entries
    }
    configure_entries = {item.stable_id: item for item in chain.evidence.record.entries}
    if target_id not in storage_entries or target_id not in configure_entries:
        raise StateConflictError(
            "deploy Scylla join-safety target evidence is incomplete"
        )
    storage = storage_entries[target_id]
    configure = configure_entries[target_id]
    target_capacity_digest = _digest_object(
        {
            "capacity_bytes": storage.capacity_bytes,
            "device_set_digest": storage.device_set_digest,
            "stable_id": target_id,
        }
    )
    if (
        target_step.mode is not ScyllaBootstrapMode.JOIN_EXISTING
        or target_step.sequence != 2
        or target_step.target_digest != _digest_object(target_id)
        or target_step.storage_evidence_digest != storage.evidence_digest
        or target_step.configuration_evidence_digest != configure.evidence_digest
        or target_step.capacity_evidence_digest != target_capacity_digest
        or target_step.topology_digest != configure.topology_digest
        or configure.datacenter_digest != _digest_object(target_host.scylla_datacenter)
        or configure.rack_digest != _digest_object(target_host.scylla_rack)
        or context.record.proof_capacity_sufficiency
        is not DeployScyllaBootstrapProofState.CONFIRMED
        or health.topology_digest is None
        or health.schema_digest is None
    ):
        raise StateConflictError(
            "deploy Scylla join-safety target, topology, or capacity binding conflicts"
        )
    canonical_capacity_ready = (
        storage.readiness_for_scylla
        and storage.capacity_bytes > 0
        and storage.failed_check_count == 0
        and storage.unknown_check_count == 0
        and storage.blocker_count == 0
        and all(node.storage_ready for node in health.nodes)
    )
    return _JoinSafetyLoaded(
        bootstrap_context=context,
        bootstrap_plan=plan,
        bootstrap_execution=bootstrap_execution,
        bootstrap_evidence=bootstrap_evidence,
        health_execution=health_execution,
        health_evidence=health_evidence,
        health_checkpoint=health_checkpoint,
        target_sequence=2,
        target_digest=target_step.target_digest,
        target_plan_step_digest=target_step.step_digest,
        target_topology_digest=target_step.topology_digest,
        target_storage_evidence_digest=target_step.storage_evidence_digest,
        target_configuration_evidence_digest=(
            target_step.configuration_evidence_digest
        ),
        target_capacity_evidence_digest=target_step.capacity_evidence_digest,
        playbook_source_digest=target_step.playbook_source_digest,
        survivor_count=len(survivor_ids),
        survivor_set_digest=_digest_object(list(survivor_ids)),
        survivor_health_digest=_digest_object(
            [node.evidence_digest for node in health.nodes]
        ),
        current_topology_digest=health.topology_digest,
        current_schema_digest=health.schema_digest,
        current_membership_digest=health.membership_digest,
        canonical_capacity_ready=canonical_capacity_ready,
    )


def _validate_proof(
    proof: DeployScyllaJoinSafetyProof, loaded: _JoinSafetyLoaded
) -> None:
    health = loaded.health_evidence.record
    if proof.status is DeployScyllaJoinSafetyProofStatus.NOT_APPLICABLE:
        raise StateConflictError(
            "capacity is required for initial-deploy join safety; "
            "not-applicable is not permitted"
        )
    if (
        proof.gate != _CAPACITY_GATE
        or proof.source
        is not DeployScyllaJoinSafetyProofSource.INDEPENDENT_BOOTSTRAP_CAPACITY_REVIEW
        or proof.captured_at != health.created_at
        or proof.health_evidence_digest != health.evidence_digest
        or proof.target_digest != loaded.target_digest
        or proof.survivor_set_digest != loaded.survivor_set_digest
        or proof.topology_digest != loaded.current_topology_digest
        or proof.target_storage_evidence_digest != loaded.target_storage_evidence_digest
        or proof.target_configuration_evidence_digest
        != loaded.target_configuration_evidence_digest
        or proof.playbook_source_digest != loaded.playbook_source_digest
    ):
        raise StateConflictError(
            "deploy Scylla join-safety proof is stale or binding-mismatched"
        )


def _build_context(
    loaded: _JoinSafetyLoaded,
    *,
    proof: DeployScyllaJoinSafetyProof,
    created_at: str,
) -> DeployScyllaJoinSafetyContext:
    bootstrap_context = loaded.bootstrap_context
    bootstrap_plan = loaded.bootstrap_plan
    bootstrap_execution = loaded.bootstrap_execution
    bootstrap_evidence = loaded.bootstrap_evidence
    context_record = bootstrap_context.record
    plan_record = bootstrap_plan.record
    checkpoint = loaded.health_checkpoint.record
    policy_digest = _digest_object(
        {
            "not_applicable": list(_NOT_APPLICABLE_GATES),
            "required": list(_REQUIRED_GATES),
        }
    )
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": context_record.cluster_uuid,
        "cluster_name": context_record.cluster_name,
        "operation_id": context_record.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "request_digest": context_record.request_digest,
        "journal_generation": context_record.journal_generation,
        "journal_digest": context_record.journal_digest,
        "journal_status": context_record.journal_status,
        "journal_phase": context_record.journal_phase,
        "bootstrap_context_artifact_digest": bootstrap_context.artifact_digest,
        "bootstrap_context_record_digest": context_record.record_digest,
        "bootstrap_plan_artifact_digest": bootstrap_plan.artifact_digest,
        "bootstrap_plan_digest": plan_record.plan_digest,
        "bootstrap_execution_artifact_digest": bootstrap_execution.artifact_digest,
        "bootstrap_evidence_artifact_digest": bootstrap_evidence.artifact_digest,
        "bootstrap_evidence_digest": bootstrap_evidence.record.entry.evidence_digest,
        "health_execution_artifact_digest": loaded.health_execution.artifact_digest,
        "health_evidence_artifact_digest": loaded.health_evidence.artifact_digest,
        "health_evidence_digest": loaded.health_evidence.record.evidence_digest,
        "health_checkpoint_artifact_digest": loaded.health_checkpoint.artifact_digest,
        "health_checkpoint_digest": checkpoint.checkpoint_digest,
        "health_captured_at": loaded.health_evidence.record.created_at,
        "target_sequence": loaded.target_sequence,
        "target_digest": loaded.target_digest,
        "target_plan_step_digest": loaded.target_plan_step_digest,
        "target_topology_digest": loaded.target_topology_digest,
        "target_storage_evidence_digest": loaded.target_storage_evidence_digest,
        "target_configuration_evidence_digest": (
            loaded.target_configuration_evidence_digest
        ),
        "target_capacity_evidence_digest": loaded.target_capacity_evidence_digest,
        "playbook_source_digest": loaded.playbook_source_digest,
        "survivor_count": loaded.survivor_count,
        "survivor_set_digest": loaded.survivor_set_digest,
        "survivor_health_digest": loaded.survivor_health_digest,
        "current_topology_digest": loaded.current_topology_digest,
        "current_schema_digest": loaded.current_schema_digest,
        "current_membership_digest": loaded.current_membership_digest,
        "required_gates": _REQUIRED_GATES,
        "not_applicable_gates": _NOT_APPLICABLE_GATES,
        "policy_digest": policy_digest,
        "proof_digest": proof.proof_digest,
        "context_digest": "",
    }
    values["context_digest"] = _context_digest_from_values(values)
    return DeployScyllaJoinSafetyContext(**values)  # type: ignore[arg-type]


def _build_evidence(
    loaded: _JoinSafetyLoaded,
    *,
    context: StoredDeployScyllaJoinSafetyContext,
    proof: DeployScyllaJoinSafetyProof,
    created_at: str,
) -> DeployScyllaJoinSafetyEvidence:
    health = loaded.health_evidence.record
    checks = dict(health.check_states)
    nodes_ready = bool(health.nodes) and all(
        node.membership_state == "UN"
        and node.service_ready
        and node.api_ready
        and node.cql_ready
        and node.storage_ready
        and node.streaming_idle
        and node.blocker_count == 0
        for node in health.nodes
    )
    health_binding = _digest_object(
        {
            "health_evidence_digest": health.evidence_digest,
            "survivor_set_digest": loaded.survivor_set_digest,
            "topology_digest": loaded.current_topology_digest,
        }
    )
    canonical_health = {
        "completed-prior-membership": (
            DeployScyllaJoinSafetyProofStatus.PASSED
            if loaded.health_checkpoint.record.steps[0].status.value
            == "health-succeeded"
            else DeployScyllaJoinSafetyProofStatus.FAILED
        ),
        "schema": (
            DeployScyllaJoinSafetyProofStatus.PASSED
            if health.schema_agreement and checks["schema-agreement"].value == "passed"
            else DeployScyllaJoinSafetyProofStatus.FAILED
        ),
        "seed-health": (
            DeployScyllaJoinSafetyProofStatus.PASSED
            if nodes_ready
            and health.nodes[0].stable_id_digest
            == loaded.bootstrap_plan.record.steps[0].target_digest
            else DeployScyllaJoinSafetyProofStatus.FAILED
        ),
        "streaming": (
            DeployScyllaJoinSafetyProofStatus.PASSED
            if health.streaming_state == "complete"
            and checks["streaming"].value == "passed"
            else DeployScyllaJoinSafetyProofStatus.FAILED
        ),
        "survivor-health": (
            DeployScyllaJoinSafetyProofStatus.PASSED
            if nodes_ready
            else DeployScyllaJoinSafetyProofStatus.FAILED
        ),
        "target-absence": (
            DeployScyllaJoinSafetyProofStatus.PASSED
            if checks["membership"].value == "passed"
            and checks["cross-view-consistency"].value == "passed"
            and loaded.target_digest
            not in {node.stable_id_digest for node in health.nodes}
            else DeployScyllaJoinSafetyProofStatus.FAILED
        ),
        "topology": (
            DeployScyllaJoinSafetyProofStatus.PASSED
            if checks["topology"].value == "passed"
            else DeployScyllaJoinSafetyProofStatus.FAILED
        ),
    }
    gates: list[DeployScyllaJoinSafetyGate] = []
    for name in _ALL_GATES:
        if name == _CAPACITY_GATE:
            status = (
                proof.status
                if loaded.canonical_capacity_ready
                else DeployScyllaJoinSafetyProofStatus.FAILED
            )
            source = DeployScyllaJoinSafetyGateSource.INDEPENDENT_CAPACITY
            evidence_digest = proof.evidence_digest
            binding_digest = _digest_object(
                {
                    "canonical_capacity_ready": loaded.canonical_capacity_ready,
                    "proof_digest": proof.proof_digest,
                    "target_capacity_evidence_digest": (
                        loaded.target_capacity_evidence_digest
                    ),
                }
            )
        elif name in _NOT_APPLICABLE_GATES:
            status = DeployScyllaJoinSafetyProofStatus.NOT_APPLICABLE
            source = DeployScyllaJoinSafetyGateSource.INITIAL_DEPLOY_POLICY
            evidence_digest = context.record.policy_digest
            binding_digest = _digest_object(
                {
                    "bootstrap_context_record_digest": (
                        context.record.bootstrap_context_record_digest
                    ),
                    "gate": name,
                    "policy_digest": context.record.policy_digest,
                    "stage": _STAGE,
                }
            )
        else:
            status = canonical_health[name]
            source = DeployScyllaJoinSafetyGateSource.CANONICAL_HEALTH
            evidence_digest = health.evidence_digest
            binding_digest = health_binding
        gate_values: dict[str, object] = {
            "name": name,
            "required": name in _REQUIRED_GATES,
            "status": status,
            "source": source,
            "captured_at": health.created_at,
            "evidence_digest": evidence_digest,
            "binding_digest": binding_digest,
            "gate_digest": "",
        }
        gate_values["gate_digest"] = _gate_digest_from_values(gate_values)
        gates.append(DeployScyllaJoinSafetyGate(**gate_values))  # type: ignore[arg-type]
    gate_tuple = tuple(gates)
    counts = Counter(gate.status for gate in gate_tuple)
    required_ready = all(
        gate.status is DeployScyllaJoinSafetyProofStatus.PASSED
        for gate in gate_tuple
        if gate.required
    )
    blockers = _gate_blockers(gate_tuple)
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": context.record.cluster_uuid,
        "cluster_name": context.record.cluster_name,
        "operation_id": context.record.operation_id,
        "context_artifact_digest": context.artifact_digest,
        "context_digest": context.record.context_digest,
        "proof": proof,
        "proof_digest": proof.proof_digest,
        "gates": gate_tuple,
        "gate_count": len(gate_tuple),
        "required_passed_count": sum(
            gate.required and gate.status is DeployScyllaJoinSafetyProofStatus.PASSED
            for gate in gate_tuple
        ),
        "failed_count": counts[DeployScyllaJoinSafetyProofStatus.FAILED],
        "unknown_count": counts[DeployScyllaJoinSafetyProofStatus.UNKNOWN],
        "not_applicable_count": counts[
            DeployScyllaJoinSafetyProofStatus.NOT_APPLICABLE
        ],
        "blockers": blockers,
        "blocker_digest": _digest_object(list(blockers)),
        "ready_for_authorization": required_ready,
        "authorization_state": (
            _AUTHORIZATION_REQUIRED if required_ready else _AUTHORIZATION_NOT_CREATED
        ),
        "execution_state": _EXECUTION_UNAVAILABLE,
        "public_workflow_state": _PUBLIC_WORKFLOW_UNAVAILABLE,
        "evidence_digest": "",
    }
    values["evidence_digest"] = _evidence_digest_from_values(values)
    return DeployScyllaJoinSafetyEvidence(**values)  # type: ignore[arg-type]


def _build_reconciliation(
    loaded: _JoinSafetyLoaded,
    *,
    context: StoredDeployScyllaJoinSafetyContext,
    evidence: StoredDeployScyllaJoinSafetyEvidence,
    created_at: str,
) -> DeployScyllaJoinSafetyReconciliation:
    plan = loaded.bootstrap_plan.record
    checkpoint = loaded.health_checkpoint.record
    if len(plan.steps) != len(checkpoint.steps):
        raise StateConflictError(
            "deploy Scylla join-safety plan/checkpoint length conflicts"
        )
    steps: list[DeployScyllaJoinSafetyStep] = []
    first_blockers: tuple[str, ...] = ()
    for original, prior in zip(plan.steps, checkpoint.steps, strict=True):
        if (
            original.sequence != prior.sequence
            or original.target_digest != prior.target_digest
            or original.step_digest != prior.original_step_digest
        ):
            raise StateConflictError(
                "deploy Scylla join-safety plan/checkpoint step conflicts"
            )
        if original.sequence == 1:
            status = DeployScyllaJoinSafetyStepStatus.HEALTH_SUCCEEDED
            authorization_state = "not-required"
            blockers: tuple[str, ...] = ()
        elif original.sequence == 2:
            if evidence.record.ready_for_authorization:
                status = DeployScyllaJoinSafetyStepStatus.AUTHORIZATION_REQUIRED
                authorization_state = _AUTHORIZATION_REQUIRED
                blockers = ("join-authorization-not-collected",)
            else:
                status = DeployScyllaJoinSafetyStepStatus.BLOCKED
                authorization_state = _AUTHORIZATION_NOT_CREATED
                blockers = evidence.record.blockers
            first_blockers = blockers
        else:
            status = DeployScyllaJoinSafetyStepStatus.WAITING
            authorization_state = "waiting"
            blockers = ("preceding-join-not-completed",)
        values: dict[str, object] = {
            "sequence": original.sequence,
            "mode": original.mode,
            "target_digest": original.target_digest,
            "plan_step_digest": original.step_digest,
            "health_checkpoint_step_digest": prior.step_digest,
            "status": status,
            "authorization_state": authorization_state,
            "blockers": blockers,
            "blocker_digest": _digest_object(list(blockers)),
            "step_digest": "",
        }
        values["step_digest"] = _step_digest_from_values(values)
        steps.append(DeployScyllaJoinSafetyStep(**values))  # type: ignore[arg-type]
    step_tuple = tuple(steps)
    counts = Counter(step.status for step in step_tuple)
    first = step_tuple[1]
    later = step_tuple[2:]
    values = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": context.record.cluster_uuid,
        "cluster_name": context.record.cluster_name,
        "operation_id": context.record.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "request_digest": context.record.request_digest,
        "journal_generation": context.record.journal_generation,
        "journal_digest": context.record.journal_digest,
        "journal_status": context.record.journal_status,
        "journal_phase": context.record.journal_phase,
        "context_artifact_digest": context.artifact_digest,
        "context_digest": context.record.context_digest,
        "evidence_artifact_digest": evidence.artifact_digest,
        "evidence_digest": evidence.record.evidence_digest,
        "health_checkpoint_artifact_digest": (loaded.health_checkpoint.artifact_digest),
        "health_checkpoint_digest": checkpoint.checkpoint_digest,
        "steps": step_tuple,
        "step_count": len(step_tuple),
        "health_succeeded_count": counts[
            DeployScyllaJoinSafetyStepStatus.HEALTH_SUCCEEDED
        ],
        "authorization_required_count": counts[
            DeployScyllaJoinSafetyStepStatus.AUTHORIZATION_REQUIRED
        ],
        "blocked_count": counts[DeployScyllaJoinSafetyStepStatus.BLOCKED],
        "waiting_count": counts[DeployScyllaJoinSafetyStepStatus.WAITING],
        "first_join_sequence": first.sequence,
        "first_join_status": first.status.value,
        "first_join_blocker_digest": _digest_object(list(first_blockers)),
        "later_join_count": len(later),
        "later_join_set_digest": _digest_object([step.target_digest for step in later]),
        "authorization_state": _AUTHORIZATION_NOT_CREATED,
        "execution_state": _EXECUTION_UNAVAILABLE,
        "public_workflow_state": _PUBLIC_WORKFLOW_UNAVAILABLE,
        "reconciliation_digest": "",
    }
    values["reconciliation_digest"] = _reconciliation_digest_from_values(values)
    return DeployScyllaJoinSafetyReconciliation(**values)  # type: ignore[arg-type]


def _report(
    context: StoredDeployScyllaJoinSafetyContext,
    evidence: StoredDeployScyllaJoinSafetyEvidence,
    reconciliation: StoredDeployScyllaJoinSafetyReconciliation,
    *,
    context_state: DeployScyllaJoinSafetyArtifactState,
    evidence_state: DeployScyllaJoinSafetyArtifactState,
    reconciliation_state: DeployScyllaJoinSafetyArtifactState,
) -> DeployScyllaJoinSafetyReport:
    return DeployScyllaJoinSafetyReport(
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
        proof_status=evidence.record.proof.status,
        required_gate_count=len(_REQUIRED_GATES),
        required_passed_count=evidence.record.required_passed_count,
        not_applicable_gate_count=evidence.record.not_applicable_count,
        failed_count=evidence.record.failed_count,
        unknown_count=evidence.record.unknown_count,
        first_join_sequence=reconciliation.record.first_join_sequence,
        first_join_status=reconciliation.record.first_join_status,
        later_join_count=reconciliation.record.later_join_count,
        authorization_state=reconciliation.record.authorization_state,
        execution_state=reconciliation.record.execution_state,
        journal_status=reconciliation.record.journal_status,
        journal_phase=reconciliation.record.journal_phase,
        journal_updated=False,
    )


def _read_context(
    store: DeployScyllaJoinSafetyContextStore,
    loaded: _JoinSafetyLoaded,
    lock: ClusterLock,
) -> StoredDeployScyllaJoinSafetyContext | None:
    return (
        store.read_locked(
            lock,
            expected_cluster_uuid=loaded.health_evidence.record.binding.cluster_uuid,
            expected_cluster_name=loaded.health_evidence.record.binding.cluster_name,
        )
        if store.path.exists()
        else None
    )


def _read_safety_evidence(
    store: DeployScyllaJoinSafetyEvidenceStore,
    loaded: _JoinSafetyLoaded,
    lock: ClusterLock,
) -> StoredDeployScyllaJoinSafetyEvidence | None:
    return (
        store.read_locked(
            lock,
            expected_cluster_uuid=loaded.health_evidence.record.binding.cluster_uuid,
            expected_cluster_name=loaded.health_evidence.record.binding.cluster_name,
        )
        if store.path.exists()
        else None
    )


def _read_reconciliation(
    store: DeployScyllaJoinSafetyReconciliationStore,
    loaded: _JoinSafetyLoaded,
    lock: ClusterLock,
) -> StoredDeployScyllaJoinSafetyReconciliation | None:
    return (
        store.read_locked(
            lock,
            expected_cluster_uuid=loaded.health_evidence.record.binding.cluster_uuid,
            expected_cluster_name=loaded.health_evidence.record.binding.cluster_name,
        )
        if store.path.exists()
        else None
    )


def _gate_blockers(
    gates: tuple[DeployScyllaJoinSafetyGate, ...],
) -> tuple[str, ...]:
    blockers: list[str] = []
    for gate in gates:
        if not gate.required or gate.status is DeployScyllaJoinSafetyProofStatus.PASSED:
            continue
        suffix = (
            "failed"
            if gate.status is DeployScyllaJoinSafetyProofStatus.FAILED
            else "unknown"
            if gate.status is DeployScyllaJoinSafetyProofStatus.UNKNOWN
            else "not-proven"
        )
        blockers.append(f"{gate.name}-{suffix}")
    return tuple(sorted(blockers))


def _proof_digest(record: DeployScyllaJoinSafetyProof) -> str:
    return _proof_digest_from_values(record.to_object())


def _proof_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    value["proof_digest"] = ""
    return _digest_object(value)


def _context_digest(record: DeployScyllaJoinSafetyContext) -> str:
    return _context_digest_from_values(record.to_object())


def _context_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    value.setdefault(
        "health_execution_schema_version",
        ANSIBLE_DEPLOY_SCYLLA_HEALTH_EXECUTION_SCHEMA_VERSION,
    )
    value.setdefault(
        "health_evidence_schema_version",
        ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_SCHEMA_VERSION,
    )
    value.setdefault(
        "health_checkpoint_schema_version",
        ANSIBLE_DEPLOY_SCYLLA_HEALTH_CHECKPOINT_SCHEMA_VERSION,
    )
    value.setdefault(
        "proof_schema_version",
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION,
    )
    value.setdefault("journal_schema_version", JOURNAL_SCHEMA_VERSION)
    value.setdefault(
        "schema_version", ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
    )
    value["context_digest"] = ""
    return _digest_object(value)


def _gate_digest(record: DeployScyllaJoinSafetyGate) -> str:
    return _gate_digest_from_values(record.to_object())


def _gate_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    value.setdefault(
        "schema_version", ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_GATE_SCHEMA_VERSION
    )
    value["gate_digest"] = ""
    return _digest_object(value)


def _evidence_digest(record: DeployScyllaJoinSafetyEvidence) -> str:
    return _evidence_digest_from_values(record.to_object())


def _evidence_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    value.setdefault(
        "context_schema_version",
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION,
    )
    value.setdefault(
        "proof_schema_version",
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION,
    )
    value.setdefault(
        "gate_schema_version",
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_GATE_SCHEMA_VERSION,
    )
    value.setdefault(
        "schema_version", ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
    )
    value["evidence_digest"] = ""
    return _digest_object(value)


def _step_digest(record: DeployScyllaJoinSafetyStep) -> str:
    return _step_digest_from_values(record.to_object())


def _step_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    value.setdefault(
        "schema_version", ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_STEP_SCHEMA_VERSION
    )
    value["step_digest"] = ""
    return _digest_object(value)


def _reconciliation_digest(record: DeployScyllaJoinSafetyReconciliation) -> str:
    return _reconciliation_digest_from_values(record.to_object())


def _reconciliation_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    value.setdefault(
        "context_schema_version",
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION,
    )
    value.setdefault(
        "evidence_schema_version",
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION,
    )
    value.setdefault(
        "step_schema_version",
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_STEP_SCHEMA_VERSION,
    )
    value.setdefault("journal_schema_version", JOURNAL_SCHEMA_VERSION)
    value.setdefault(
        "schema_version",
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION,
    )
    value["reconciliation_digest"] = ""
    return _digest_object(value)


def _artifact_path(paths: StatePaths, operation_id: uuid.UUID, suffix: str) -> Path:
    _require_canonical_paths(paths)
    path = paths.operations / f"{_require_operation_id(operation_id)}{suffix}"
    if path.parent != paths.operations:
        raise StatePersistenceError("deploy Scylla join-safety path is not canonical")
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
        DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_FILENAME_SUFFIX,
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Scylla join-safety artifacts"
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
                    "deploy Scylla join-safety artifacts are ambiguous"
                )


def _require_identity(
    record_operation_id: uuid.UUID,
    record_cluster_uuid: uuid.UUID,
    record_cluster_name: str,
    *,
    operation_id: uuid.UUID,
    cluster_uuid: uuid.UUID,
    cluster_name: str,
) -> None:
    if (
        record_operation_id != operation_id
        or record_cluster_uuid != cluster_uuid
        or record_cluster_name != cluster_name
    ):
        raise StatePersistenceError(
            "deploy Scylla join-safety artifact identity conflicts"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy Scylla join safety requires the matching held deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _require_canonical_paths(paths: StatePaths) -> None:
    if StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths:
        raise StatePersistenceError("deploy Scylla join-safety paths are not canonical")


def _timestamp() -> str:
    return format_timestamp(datetime.now(UTC))


def _digest_fields(value: object) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(value, name))
        for name in value.__dataclass_fields__  # type: ignore[attr-defined]
        if name.endswith("_digest") and isinstance(getattr(value, name), str)
    )


def _dataclass_object(
    value: object,
    *,
    tuple_fields: set[str] | None = None,
    skip_fields: set[str] | None = None,
) -> dict[str, object]:
    tuples = tuple_fields or set()
    skipped = skip_fields or set()
    result: dict[str, object] = {}
    for name in value.__dataclass_fields__:  # type: ignore[attr-defined]
        if name in skipped:
            continue
        item = getattr(value, name)
        result[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(item, StrEnum)
            else list(item)
            if name in tuples
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
    tuple_fields: set[str] | None = None,
    enum_fields: Mapping[str, type[StrEnum]] | None = None,
    skip_fields: set[str] | None = None,
    label: str,
) -> dict[str, object]:
    require_exact_keys(value, set(data_type.__dataclass_fields__), label)  # type: ignore[attr-defined]
    integers = integer_fields or set()
    uuids = uuid_fields or set()
    booleans = boolean_fields or set()
    tuples = tuple_fields or set()
    enums = enum_fields or {}
    skipped = skip_fields or set()
    result: dict[str, object] = {}
    try:
        for name in data_type.__dataclass_fields__:  # type: ignore[attr-defined]
            if name in skipped:
                continue
            item = value[name]
            if name in integers:
                result[name] = _integer(item, name)
            elif name in uuids:
                result[name] = parse_uuid(require_string(value, name), name)
            elif name in booleans:
                result[name] = _boolean(item, name)
            elif name in tuples:
                result[name] = _string_tuple(item, name)
            elif name in enums:
                result[name] = enums[name](require_string(value, name))
            else:
                result[name] = require_string(value, name)
    except ValueError as error:
        raise StatePersistenceError(f"deploy Scylla {label} enum is invalid") from error
    return result


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


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise StatePersistenceError(f"deploy Scylla {label} is invalid")
    return value


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise StatePersistenceError(f"deploy Scylla {label} is invalid")
    return tuple(value)


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"deploy Scylla {label} is invalid")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"deploy Scylla {label} is invalid")
    return value


__all__ = [
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_GATE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_PROOF_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_STEP_SCHEMA_VERSION",
    "DeployScyllaJoinSafetyArtifactState",
    "DeployScyllaJoinSafetyContext",
    "DeployScyllaJoinSafetyContextStore",
    "DeployScyllaJoinSafetyEvidence",
    "DeployScyllaJoinSafetyEvidenceStore",
    "DeployScyllaJoinSafetyGate",
    "DeployScyllaJoinSafetyGateSource",
    "DeployScyllaJoinSafetyProof",
    "DeployScyllaJoinSafetyProofSource",
    "DeployScyllaJoinSafetyProofStatus",
    "DeployScyllaJoinSafetyReconciliation",
    "DeployScyllaJoinSafetyReconciliationStore",
    "DeployScyllaJoinSafetyReport",
    "DeployScyllaJoinSafetyStep",
    "DeployScyllaJoinSafetyStepStatus",
    "bind_deploy_scylla_join_safety",
    "deploy_scylla_join_safety_context_id_from_filename",
    "deploy_scylla_join_safety_context_path",
    "deploy_scylla_join_safety_evidence_id_from_filename",
    "deploy_scylla_join_safety_evidence_path",
    "deploy_scylla_join_safety_reconciliation_id_from_filename",
    "deploy_scylla_join_safety_reconciliation_path",
]
