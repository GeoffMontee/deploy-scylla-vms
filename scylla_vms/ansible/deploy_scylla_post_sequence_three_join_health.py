"""Fresh complete-cluster health after deploy bootstrap sequence three.

This internal owner reloads the exact terminal-success sequence-three join
chain, runs only the reviewed read-only ``scylla-health`` source against the
complete current member prefix, and persists distinct redacted execution,
evidence, and reconciliation companions. It never treats bootstrap success as
cluster health, creates later safety or authorization, or changes the journal.
"""

from __future__ import annotations

import os
import uuid
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.commands import AnsibleCommandBuilder
from scylla_vms.ansible.deploy_plan import (
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_scylla_bootstrap_plan import (
    DeployScyllaBootstrapPlanStep,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import _loaded
from scylla_vms.ansible.deploy_scylla_configure_reconciliation import (
    _load_reconciliation_context,
)
from scylla_vms.ansible.deploy_scylla_health_checkpoint import (
    ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_NODE_SCHEMA_VERSION,
    DeployScyllaHealthArtifactState,
    DeployScyllaHealthEvidenceNode,
    DeployScyllaHealthExecutionState,
    _node_evidence_digest_from_values,
)
from scylla_vms.ansible.deploy_scylla_post_join_health import (
    ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_SCHEMA_VERSION,
    _array,
    _dataclass_object,
    _digest_fields,
    _digest_text,
    _failure_state,
    _json_object,
    _json_value,
    _mapping,
    _parse_dataclass,
    _positive_integer,
    _status_pairs,
    _timestamp,
    _validate_toolchain_version,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_authorization import (
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_SCHEMA_VERSION,
    _load_sequence_three_join_authorization_context,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_execution import (
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_SCHEMA_VERSION,
    DeployScyllaSequenceThreeJoinEvidenceStore,
    DeployScyllaSequenceThreeJoinExecutionState,
    DeployScyllaSequenceThreeJoinExecutionStore,
    StoredDeployScyllaSequenceThreeJoinEvidence,
    StoredDeployScyllaSequenceThreeJoinExecution,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_execution import (
    _ExecutionContext as _SequenceThreeExecutionContext,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_execution import (
    _load_execution_context as _load_sequence_three_execution_context,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_execution import (
    _validate_prefix as _validate_sequence_three_prefix,
)
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_bootstrap import (
    MutationBoundary,
    ScyllaBootstrapMode,
    ScyllaBootstrapStatus,
)
from scylla_vms.ansible.scylla_health import (
    SCYLLA_HEALTH_SCHEMA_VERSION,
    HealthCheckStatus,
    HealthReadiness,
    build_scylla_health_payload,
    parse_scylla_health_execution,
)
from scylla_vms.ansible.scylla_install import SCYLLA_PACKAGE_VERSION
from scylla_vms.ansible.service import (
    AnsibleExecutionResult,
    AnsibleResultError,
    AnsibleService,
    ProcessRunnerProtocol,
)
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION
from scylla_vms.ansible.toolchain import AnsibleToolchain
from scylla_vms.desired import HostRole
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.journal import JOURNAL_SCHEMA_VERSION, JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import (
    AtomicJsonFile,
    ClusterMetadata,
    parse_timestamp,
    validate_digest,
)
from scylla_vms.state import (
    StatePaths,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)
from scylla_vms.terraform.apply_readiness import (
    _executable_identity_digest,
    _toolchain_evidence_digest,
    _validate_toolchain_dependency,
)

ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-post-sequence-three-join-health-"
    "execution-binding/v1"
)
ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-post-sequence-three-join-health-"
    "execution/v1"
)
ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-post-sequence-three-join-health-"
    "evidence/v1"
)
ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_STEP_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-post-sequence-three-join-health-step/v1"
)
ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-post-sequence-three-join-health-"
    "reconciliation/v1"
)
ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-post-sequence-three-join-health-report/v1"
)

DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-post-sequence-three-join-health-execution.json"
)
DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-post-sequence-three-join-health-evidence.json"
)
DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-post-sequence-three-join-health-reconciliation.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "scylla-health"
_STAGE = "post-sequence-three-complete-current-set-health"
_TIMEOUT_SECONDS = 60
_CURRENT_MEMBER_COUNT = 3
_STRICT_CHECKS = (
    "cross-view-consistency",
    "membership",
    "schema-agreement",
    "streaming",
    "topology",
)
_POLICY_CHECKS = ("backup-policy", "capacity", "quorum", "replication")
_EXPECTED_POLICY_STATES = {
    "backup-policy": HealthCheckStatus.NOT_PERFORMED,
    "capacity": HealthCheckStatus.UNKNOWN,
    "quorum": HealthCheckStatus.UNKNOWN,
    "replication": HealthCheckStatus.NOT_PERFORMED,
}


class DeployScyllaPostSequenceThreeHealthStepStatus(StrEnum):
    HEALTH_SUCCEEDED = "health-succeeded"
    WAITING_FOR_SAFETY = "waiting-for-separate-safety-context"
    WAITING_FOR_PRECEDING_HEALTH = "waiting-for-preceding-complete-health"


@dataclass(frozen=True, slots=True)
class DeployScyllaPostSequenceThreeHealthExecutionBinding:
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    bootstrap_context_artifact_digest: str
    bootstrap_plan_artifact_digest: str
    bootstrap_plan_digest: str
    pre_sequence_three_health_execution_artifact_digest: str
    pre_sequence_three_health_evidence_artifact_digest: str
    pre_sequence_three_health_reconciliation_artifact_digest: str
    sequence_three_safety_context_artifact_digest: str
    sequence_three_safety_evidence_artifact_digest: str
    sequence_three_safety_reconciliation_artifact_digest: str
    sequence_three_authorization_artifact_digest: str
    sequence_three_authorization_digest: str
    sequence_three_execution_artifact_digest: str
    sequence_three_execution_binding_digest: str
    sequence_three_evidence_artifact_digest: str
    sequence_three_evidence_digest: str
    post_configure_artifact_digest: str
    terraform_verification_artifact_digest: str
    observation_generation: int
    observation_artifact_digest: str
    observation_manifest_digest: str
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    trust_generation: int
    trust_artifact_digest: str
    trust_entries_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    storage_evidence_artifact_digest: str
    install_evidence_artifact_digest: str
    configure_evidence_artifact_digest: str
    catalog_digest: str
    source_version: str
    source_digest: str
    playbook_source_digest: str
    toolchain_version: str
    executable_identity_digest: str
    toolchain_evidence_digest: str
    current_member_count: int
    current_member_set_digest: str
    desired_member_count: int
    desired_member_set_digest: str
    future_member_count: int
    future_member_set_digest: str
    current_topology_digest: str
    expected_host_mapping_digest: str
    storage_evidence_digest: str
    configuration_evidence_digest: str
    policy_digest: str
    variables_digest: str
    command_digest: str
    binding_digest: str
    sequence_three_execution_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_SCHEMA_VERSION
    )
    sequence_three_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EVIDENCE_SCHEMA_VERSION
    )
    sequence_three_authorization_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_SCHEMA_VERSION
    )
    pre_sequence_three_health_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_BINDING_SCHEMA_VERSION
            or self.sequence_three_execution_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_SCHEMA_VERSION
            or self.sequence_three_evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EVIDENCE_SCHEMA_VERSION
            or self.sequence_three_authorization_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_SCHEMA_VERSION
            or self.pre_sequence_three_health_reconciliation_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.current_member_count != _CURRENT_MEMBER_COUNT
            or self.desired_member_count < self.current_member_count
            or self.future_member_count
            != self.desired_member_count - self.current_member_count
            or self.binding_digest != _binding_digest(self)
        ):
            raise StatePersistenceError(
                "post-sequence-three Scylla health binding conflicts"
            )
        validate_cluster_name(self.cluster_name)
        for generation in (
            self.journal_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
        ):
            _positive_integer(generation, "post-sequence-three health generation")
        for digest in _digest_fields(self):
            validate_digest(digest, "post-sequence-three health binding digest")
        _validate_toolchain_version(self.toolchain_version)

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaPostSequenceThreeHealthExecutionBinding:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={
                "journal_generation",
                "observation_generation",
                "inventory_generation",
                "trust_generation",
                "current_member_count",
                "desired_member_count",
                "future_member_count",
            },
            uuid_fields={"cluster_uuid", "operation_id"},
            enum_fields={
                "journal_status": JournalStatus,
                "journal_phase": OperationPhase,
            },
            label="post-sequence-three health binding",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaPostSequenceThreeHealthExecution:
    generation: int
    created_at: str
    updated_at: str
    binding: DeployScyllaPostSequenceThreeHealthExecutionBinding
    state: DeployScyllaHealthExecutionState
    invocation_count: int
    completed: bool
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    exit_code: int | None
    result_digest: str | None
    evidence_digest: str | None
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        terminal = self.state in {
            DeployScyllaHealthExecutionState.SUCCEEDED,
            DeployScyllaHealthExecutionState.FAILED,
        }
        success = self.state is DeployScyllaHealthExecutionState.SUCCEEDED
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_SCHEMA_VERSION
            or self.generation not in {1, 2}
            or self.invocation_count != 1
            or self.completed != terminal
            or self.manual_recovery_required != (not success)
            or self.automatic_retry_allowed
            or (
                self.state is DeployScyllaHealthExecutionState.STARTED
                and (
                    self.generation != 1
                    or self.exit_code is not None
                    or self.result_digest is not None
                    or self.evidence_digest is not None
                )
            )
            or (
                self.state is not DeployScyllaHealthExecutionState.STARTED
                and self.generation != 2
            )
            or (
                terminal
                and (
                    self.exit_code is None
                    or self.result_digest is None
                    or self.evidence_digest is None
                )
            )
            or parse_timestamp(self.updated_at) < parse_timestamp(self.created_at)
        ):
            raise StatePersistenceError(
                "post-sequence-three Scylla health execution conflicts"
            )
        for digest in (self.result_digest, self.evidence_digest):
            if digest is not None:
                validate_digest(digest, "post-sequence-three health execution digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, nested_fields={"binding"})

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaPostSequenceThreeHealthExecution:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={"generation", "invocation_count"},
            boolean_fields={
                "completed",
                "manual_recovery_required",
                "automatic_retry_allowed",
            },
            enum_fields={"state": DeployScyllaHealthExecutionState},
            optional_string_fields={"result_digest", "evidence_digest"},
            optional_integer_fields={"exit_code"},
            skip_fields={"binding"},
            label="post-sequence-three health execution",
        )
        parsed["binding"] = (
            DeployScyllaPostSequenceThreeHealthExecutionBinding.from_object(
                _mapping(value["binding"], "post-sequence-three health binding")
            )
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaPostSequenceThreeHealthEvidence:
    generation: int
    created_at: str
    binding: DeployScyllaPostSequenceThreeHealthExecutionBinding
    health_status: HealthReadiness
    query_policy: str
    nodes: tuple[DeployScyllaHealthEvidenceNode, ...]
    host_id_mapping_digest: str
    membership_digest: str
    topology_digest: str | None
    schema_digest: str | None
    schema_agreement: bool
    streaming_state: str
    check_states: tuple[tuple[str, HealthCheckStatus], ...]
    policy_states: tuple[tuple[str, HealthCheckStatus], ...]
    blocker_count: int
    blocker_digest: str
    strict_complete: bool
    result_digest: str
    evidence_digest: str
    result_schema_version: str = SCYLLA_HEALTH_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EVIDENCE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EVIDENCE_SCHEMA_VERSION
            or self.result_schema_version != SCYLLA_HEALTH_SCHEMA_VERSION
            or self.generation != 1
            or self.query_policy != "all-nodes-cross-view"
            or tuple(node.stable_id for node in self.nodes)
            != tuple(sorted({node.stable_id for node in self.nodes}))
            or tuple(name for name, _ in self.check_states) != _STRICT_CHECKS
            or tuple(name for name, _ in self.policy_states) != _POLICY_CHECKS
            or self.blocker_count < 0
            or self.evidence_digest != _health_evidence_digest(self)
        ):
            raise StatePersistenceError(
                "post-sequence-three Scylla health evidence conflicts"
            )
        parse_timestamp(self.created_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "post-sequence-three health evidence digest")

    def to_object(self) -> dict[str, object]:
        return {
            **_dataclass_object(
                self,
                nested_fields={"binding"},
                skip_fields={"nodes", "check_states", "policy_states"},
            ),
            "nodes": [node.to_object() for node in self.nodes],
            "check_states": [
                [name, status.value] for name, status in self.check_states
            ],
            "policy_states": [
                [name, status.value] for name, status in self.policy_states
            ],
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaPostSequenceThreeHealthEvidence:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={"generation", "blocker_count"},
            boolean_fields={"schema_agreement", "strict_complete"},
            enum_fields={"health_status": HealthReadiness},
            optional_string_fields={"topology_digest", "schema_digest"},
            skip_fields={"binding", "nodes", "check_states", "policy_states"},
            label="post-sequence-three health evidence",
        )
        parsed["binding"] = (
            DeployScyllaPostSequenceThreeHealthExecutionBinding.from_object(
                _mapping(value["binding"], "post-sequence-three health binding")
            )
        )
        parsed["nodes"] = tuple(
            DeployScyllaHealthEvidenceNode.from_object(
                _mapping(item, "post-sequence-three health node")
            )
            for item in _array(value["nodes"], "post-sequence-three health nodes")
        )
        parsed["check_states"] = _status_pairs(value["check_states"], "check states")
        parsed["policy_states"] = _status_pairs(value["policy_states"], "policy states")
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaPostSequenceThreeHealthStep:
    sequence: int
    mode: ScyllaBootstrapMode
    target_digest: str
    plan_step_digest: str
    status: DeployScyllaPostSequenceThreeHealthStepStatus
    health_checkpoint_state: str
    safety_context_state: str
    blockers: tuple[str, ...]
    blocker_digest: str
    step_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_STEP_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_STEP_SCHEMA_VERSION
            or self.sequence < 1
            or tuple(sorted(set(self.blockers))) != self.blockers
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.step_digest != _step_digest(self)
        ):
            raise StatePersistenceError(
                "post-sequence-three Scylla health step conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "post-sequence-three health step digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, tuple_fields={"blockers"})

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaPostSequenceThreeHealthStep:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={"sequence"},
            tuple_fields={"blockers"},
            enum_fields={
                "mode": ScyllaBootstrapMode,
                "status": DeployScyllaPostSequenceThreeHealthStepStatus,
            },
            label="post-sequence-three health step",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaPostSequenceThreeHealthReconciliation:
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
    health_execution_artifact_digest: str
    health_evidence_artifact_digest: str
    health_evidence_digest: str
    sequence_three_execution_artifact_digest: str
    sequence_three_evidence_artifact_digest: str
    sequence_three_evidence_digest: str
    steps: tuple[DeployScyllaPostSequenceThreeHealthStep, ...]
    step_count: int
    health_succeeded_count: int
    waiting_for_safety_count: int
    waiting_for_preceding_health_count: int
    current_member_count: int
    current_member_set_digest: str
    bootstrap_sequence_complete: bool
    next_step_required: bool
    next_join_sequence: int | None
    next_join_status: str
    next_join_blocker_digest: str
    later_join_count: int
    later_join_set_digest: str
    reconciliation_digest: str
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        counts = Counter(step.status for step in self.steps)
        next_exists = self.step_count > _CURRENT_MEMBER_COUNT
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_RECONCILIATION_SCHEMA_VERSION
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
            != counts[DeployScyllaPostSequenceThreeHealthStepStatus.HEALTH_SUCCEEDED]
            or self.waiting_for_safety_count
            != counts[DeployScyllaPostSequenceThreeHealthStepStatus.WAITING_FOR_SAFETY]
            or self.waiting_for_preceding_health_count
            != counts[
                DeployScyllaPostSequenceThreeHealthStepStatus.WAITING_FOR_PRECEDING_HEALTH
            ]
            or self.health_succeeded_count != _CURRENT_MEMBER_COUNT
            or self.current_member_count != _CURRENT_MEMBER_COUNT
            or self.waiting_for_safety_count != int(next_exists)
            or self.bootstrap_sequence_complete != (not next_exists)
            or self.next_step_required != next_exists
            or self.next_join_sequence
            != (_CURRENT_MEMBER_COUNT + 1 if next_exists else None)
            or self.next_join_status
            != (
                DeployScyllaPostSequenceThreeHealthStepStatus.WAITING_FOR_SAFETY.value
                if next_exists
                else "not-required"
            )
            or self.later_join_count != max(0, self.step_count - 4)
            or self.reconciliation_digest != _reconciliation_digest(self)
        ):
            raise StatePersistenceError(
                "post-sequence-three Scylla health reconciliation conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "post-sequence-three reconciliation digest")

    def to_object(self) -> dict[str, object]:
        return {
            **_dataclass_object(self, skip_fields={"steps"}),
            "steps": [step.to_object() for step in self.steps],
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaPostSequenceThreeHealthReconciliation:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={
                "generation",
                "journal_generation",
                "step_count",
                "health_succeeded_count",
                "waiting_for_safety_count",
                "waiting_for_preceding_health_count",
                "current_member_count",
                "later_join_count",
            },
            uuid_fields={"cluster_uuid", "operation_id"},
            boolean_fields={"bootstrap_sequence_complete", "next_step_required"},
            enum_fields={
                "journal_status": JournalStatus,
                "journal_phase": OperationPhase,
            },
            optional_integer_fields={"next_join_sequence"},
            skip_fields={"steps"},
            label="post-sequence-three health reconciliation",
        )
        parsed["steps"] = tuple(
            DeployScyllaPostSequenceThreeHealthStep.from_object(
                _mapping(item, "post-sequence-three health step")
            )
            for item in _array(value["steps"], "post-sequence-three health steps")
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaPostSequenceThreeHealthExecution:
    record: DeployScyllaPostSequenceThreeHealthExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaPostSequenceThreeHealthEvidence:
    record: DeployScyllaPostSequenceThreeHealthEvidence
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaPostSequenceThreeHealthReconciliation:
    record: DeployScyllaPostSequenceThreeHealthReconciliation
    artifact_digest: str


class DeployScyllaPostSequenceThreeHealthExecutionStore:
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
        self._path = deploy_scylla_post_sequence_three_health_execution_path(
            paths, operation_id
        )
        self._file = AtomicJsonFile(self._path, replace=replace_file)

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployScyllaPostSequenceThreeHealthExecution:
        value, digest = self._file.read()
        record = DeployScyllaPostSequenceThreeHealthExecution.from_object(value)
        _require_identity(
            record.binding.operation_id,
            record.binding.cluster_uuid,
            record.binding.cluster_name,
            operation_id=self._operation_id,
            cluster_uuid=expected_cluster_uuid,
            cluster_name=expected_cluster_name,
        )
        return StoredDeployScyllaPostSequenceThreeHealthExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaPostSequenceThreeHealthExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaPostSequenceThreeHealthExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployScyllaPostSequenceThreeHealthExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if (
                current.record.generation != expected_generation
                or current.artifact_digest != expected_digest
                or record.generation != current.record.generation + 1
                or record.created_at != current.record.created_at
                or record.binding != current.record.binding
                or current.record.state is not DeployScyllaHealthExecutionState.STARTED
            ):
                raise StateConflictError(
                    "post-sequence-three health execution transition conflicts"
                )
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
            or record.state is not DeployScyllaHealthExecutionState.STARTED
        ):
            raise StateConflictError(
                "post-sequence-three health initial execution conflicts"
            )
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployScyllaPostSequenceThreeHealthExecution(record, digest)


class DeployScyllaPostSequenceThreeHealthEvidenceStore:
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
        self._path = deploy_scylla_post_sequence_three_health_evidence_path(
            paths, operation_id
        )
        self._file = AtomicJsonFile(self._path, replace=replace_file)

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployScyllaPostSequenceThreeHealthEvidence:
        value, digest = self._file.read()
        record = DeployScyllaPostSequenceThreeHealthEvidence.from_object(value)
        _require_identity(
            record.binding.operation_id,
            record.binding.cluster_uuid,
            record.binding.cluster_name,
            operation_id=self._operation_id,
            cluster_uuid=expected_cluster_uuid,
            cluster_name=expected_cluster_name,
        )
        return StoredDeployScyllaPostSequenceThreeHealthEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaPostSequenceThreeHealthEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaPostSequenceThreeHealthEvidence,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployScyllaPostSequenceThreeHealthEvidence,
        DeployScyllaHealthArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_file(self._path, allow_missing=True)
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "post-sequence-three health evidence is immutable"
                )
            return current, DeployScyllaHealthArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaPostSequenceThreeHealthEvidence(record, digest),
            DeployScyllaHealthArtifactState.CREATED,
        )


class DeployScyllaPostSequenceThreeHealthReconciliationStore:
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
        self._path = deploy_scylla_post_sequence_three_health_reconciliation_path(
            paths, operation_id
        )
        self._file = AtomicJsonFile(self._path, replace=replace_file)

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployScyllaPostSequenceThreeHealthReconciliation:
        value, digest = self._file.read()
        record = DeployScyllaPostSequenceThreeHealthReconciliation.from_object(value)
        _require_identity(
            record.operation_id,
            record.cluster_uuid,
            record.cluster_name,
            operation_id=self._operation_id,
            cluster_uuid=expected_cluster_uuid,
            cluster_name=expected_cluster_name,
        )
        return StoredDeployScyllaPostSequenceThreeHealthReconciliation(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaPostSequenceThreeHealthReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaPostSequenceThreeHealthReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployScyllaPostSequenceThreeHealthReconciliation,
        DeployScyllaHealthArtifactState,
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
                    "post-sequence-three health reconciliation is immutable"
                )
            return current, DeployScyllaHealthArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaPostSequenceThreeHealthReconciliation(record, digest),
            DeployScyllaHealthArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaPostSequenceThreeHealthReport:
    operation_id: uuid.UUID
    execution_state: DeployScyllaHealthExecutionState
    execution_artifact_state: DeployScyllaHealthArtifactState
    evidence_artifact_state: DeployScyllaHealthArtifactState
    reconciliation_artifact_state: DeployScyllaHealthArtifactState
    current_member_count: int
    desired_member_count: int
    future_member_count: int
    health_complete: bool
    host_identity_count: int
    up_normal_count: int
    service_ready_count: int
    api_ready_count: int
    cql_ready_count: int
    storage_ready_count: int
    schema_agreement: bool
    streaming_idle: bool
    policy_unknown_count: int
    policy_not_performed_count: int
    bootstrap_sequence_complete: bool
    next_step_required: bool
    next_join_sequence: int | None
    next_join_status: str
    next_join_blocker_count: int
    later_join_count: int
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    journal_status: JournalStatus
    journal_phase: OperationPhase
    execution_artifact_digest: str
    evidence_artifact_digest: str
    reconciliation_artifact_digest: str
    evidence_digest: str
    reconciliation_digest: str
    stage: str = _STAGE
    journal_updated: bool = False
    public_workflow_state: str = "unavailable"
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EVIDENCE_SCHEMA_VERSION
    )
    reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_REPORT_SCHEMA_VERSION
            or self.execution_state is not DeployScyllaHealthExecutionState.SUCCEEDED
            or self.current_member_count != _CURRENT_MEMBER_COUNT
            or not self.health_complete
            or self.policy_unknown_count
            != sum(
                status is HealthCheckStatus.UNKNOWN
                for status in _EXPECTED_POLICY_STATES.values()
            )
            or self.policy_not_performed_count
            != sum(
                status is HealthCheckStatus.NOT_PERFORMED
                for status in _EXPECTED_POLICY_STATES.values()
            )
            or self.bootstrap_sequence_complete == self.next_step_required
            or self.manual_recovery_required
            or self.automatic_retry_allowed
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.journal_updated
            or self.public_workflow_state != "unavailable"
        ):
            raise StatePersistenceError(
                "post-sequence-three Scylla health report conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "post-sequence-three health report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "artifacts": {
                "evidence": {
                    "digest": self.evidence_artifact_digest,
                    "record_digest": self.evidence_digest,
                    "schema_version": self.evidence_schema_version,
                    "state": self.evidence_artifact_state.value,
                },
                "execution": {
                    "digest": self.execution_artifact_digest,
                    "schema_version": self.execution_schema_version,
                    "state": self.execution_artifact_state.value,
                },
                "reconciliation": {
                    "digest": self.reconciliation_artifact_digest,
                    "record_digest": self.reconciliation_digest,
                    "schema_version": self.reconciliation_schema_version,
                    "state": self.reconciliation_artifact_state.value,
                },
            },
            "bootstrap_sequence": {
                "complete": self.bootstrap_sequence_complete,
                "next_step_required": self.next_step_required,
            },
            "health": {
                "api_ready_count": self.api_ready_count,
                "complete": self.health_complete,
                "cql_ready_count": self.cql_ready_count,
                "host_identity_count": self.host_identity_count,
                "policy_not_performed_count": self.policy_not_performed_count,
                "policy_unknown_count": self.policy_unknown_count,
                "schema_agreement": self.schema_agreement,
                "service_ready_count": self.service_ready_count,
                "storage_ready_count": self.storage_ready_count,
                "streaming_idle": self.streaming_idle,
                "up_normal_count": self.up_normal_count,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": self.journal_updated,
            },
            "membership": {
                "current_count": self.current_member_count,
                "desired_count": self.desired_member_count,
                "future_count": self.future_member_count,
            },
            "next_join": {
                "blocker_count": self.next_join_blocker_count,
                "later_join_count": self.later_join_count,
                "sequence": self.next_join_sequence,
                "status": self.next_join_status,
            },
            "operation": {
                "id": str(self.operation_id),
                "public_workflow_state": self.public_workflow_state,
            },
            "recovery": {
                "automatic_retry_allowed": self.automatic_retry_allowed,
                "manual_recovery_required": self.manual_recovery_required,
            },
            "schema_version": self.schema_version,
            "stage": self.stage,
        }


@dataclass(frozen=True, slots=True)
class _HealthContext:
    sequence_context: _SequenceThreeExecutionContext
    sequence_execution: StoredDeployScyllaSequenceThreeJoinExecution
    sequence_evidence: StoredDeployScyllaSequenceThreeJoinEvidence
    binding: DeployScyllaPostSequenceThreeHealthExecutionBinding
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport
    payload: dict[str, object]
    variables: tuple[tuple[str, object], ...]
    current_ids: tuple[str, ...]
    desired_ids: tuple[str, ...]
    future_ids: tuple[str, ...]
    plan_steps: tuple[DeployScyllaBootstrapPlanStep, ...]


def execute_deploy_scylla_post_sequence_three_join_health(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployScyllaPostSequenceThreeHealthReport:
    """Verify the exact three-member set and reconcile only plan completion."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _validate_toolchain_dependency(toolchain)
    executable_identity_digest = _executable_identity_digest(executables)
    toolchain_evidence_digest = _toolchain_evidence_digest(
        toolchain, executable_identity_digest
    )
    _refuse_ambiguous_artifacts(paths, operation_id)
    builder = AnsibleCommandBuilder(executables.playbook, executables.inventory, paths)
    context = _load_health_context(
        paths,
        operation_id,
        lock=lock,
        builder=builder,
        toolchain=toolchain,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    execution_store = DeployScyllaPostSequenceThreeHealthExecutionStore(
        paths, operation_id
    )
    evidence_store = DeployScyllaPostSequenceThreeHealthEvidenceStore(
        paths, operation_id
    )
    reconciliation_store = DeployScyllaPostSequenceThreeHealthReconciliationStore(
        paths, operation_id
    )
    for path in (
        execution_store.path,
        evidence_store.path,
        reconciliation_store.path,
    ):
        validate_state_file(path, allow_missing=True)
    execution = _read_execution(execution_store, context, lock)
    evidence = _read_evidence(evidence_store, context, lock)
    reconciliation = _read_reconciliation(reconciliation_store, context, lock)
    _validate_prefix(context, execution, evidence, reconciliation)
    if reconciliation is not None:
        return _report(
            execution=cast(
                StoredDeployScyllaPostSequenceThreeHealthExecution, execution
            ),
            evidence=cast(StoredDeployScyllaPostSequenceThreeHealthEvidence, evidence),
            reconciliation=reconciliation,
            execution_state=DeployScyllaHealthArtifactState.REUSED,
            evidence_state=DeployScyllaHealthArtifactState.REUSED,
            reconciliation_state=DeployScyllaHealthArtifactState.REUSED,
        )
    if execution is not None:
        if (
            execution.record.state is not DeployScyllaHealthExecutionState.SUCCEEDED
            or evidence is None
            or not evidence.record.strict_complete
        ):
            raise StateConflictError(
                "post-sequence-three Scylla health requires manual recovery "
                "and cannot retry"
            )
        record = _build_reconciliation(
            context, execution, evidence, created_at=_timestamp()
        )
        reconciliation, state = reconciliation_store.write_locked(record, lock=lock)
        return _report(
            execution=execution,
            evidence=evidence,
            reconciliation=reconciliation,
            execution_state=DeployScyllaHealthArtifactState.REUSED,
            evidence_state=DeployScyllaHealthArtifactState.REUSED,
            reconciliation_state=(
                DeployScyllaHealthArtifactState.RECOVERED
                if state is DeployScyllaHealthArtifactState.CREATED
                else state
            ),
        )

    service = AnsibleService(builder, runner)
    if service.version(lock) != toolchain:
        raise StateConflictError("post-sequence-three Scylla health toolchain drifted")
    before = _load_health_context(
        paths,
        operation_id,
        lock=lock,
        builder=builder,
        toolchain=toolchain,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    if before.binding != context.binding:
        raise StateConflictError(
            "post-sequence-three Scylla health state drifted before start"
        )
    execution = _persist_started(execution_store, before, lock=lock)
    try:
        result, command_digest = service.execute_operation_step(
            lock,
            before.metadata,
            before.inventory,
            _PLAYBOOK,
            step_sequence=1,
            limit=before.current_ids,
            variables=dict(before.variables),
            readiness=before.readiness,
            tags=(_PLAYBOOK,),
            check=True,
            diff=False,
            verbosity=0,
        )
        if command_digest != before.binding.command_digest:
            raise AnsibleResultError(
                "post-sequence-three health command result identity conflicts"
            )
    except KeyboardInterrupt:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployScyllaHealthExecutionState.INTERRUPTED,
            lock=lock,
        )
        raise AnsibleError(
            "post-sequence-three Scylla health was interrupted; "
            "manual recovery required"
        ) from None
    except (AnsibleError, StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            _failure_state(error),
            lock=lock,
        )
        raise AnsibleError(
            "post-sequence-three Scylla health execution is uncertain; "
            "manual recovery required"
        ) from error

    try:
        after = _load_health_context(
            paths,
            operation_id,
            lock=lock,
            builder=builder,
            toolchain=toolchain,
            executable_identity_digest=executable_identity_digest,
            toolchain_evidence_digest=toolchain_evidence_digest,
        )
        if after.binding != context.binding:
            raise StateConflictError(
                "post-sequence-three Scylla health state changed after invocation"
            )
        evidence_record = _semantic_evidence(before, result)
        evidence, evidence_state = evidence_store.write_locked(
            evidence_record, lock=lock
        )
    except (AnsibleError, StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployScyllaHealthExecutionState.MALFORMED_RESULT,
            lock=lock,
        )
        raise AnsibleError(
            "post-sequence-three Scylla health result is uncertain; "
            "manual recovery required"
        ) from error
    terminal_state = (
        DeployScyllaHealthExecutionState.SUCCEEDED
        if evidence.record.strict_complete
        else DeployScyllaHealthExecutionState.FAILED
    )
    execution = _persist_terminal(
        execution_store,
        execution,
        evidence=evidence,
        result=result,
        state=terminal_state,
        lock=lock,
    )
    if terminal_state is DeployScyllaHealthExecutionState.FAILED:
        raise AnsibleError(
            "post-sequence-three Scylla health preserved incomplete evidence; "
            "manual recovery required and automatic retry is forbidden"
        )
    reconciliation_record = _build_reconciliation(
        context, execution, evidence, created_at=_timestamp()
    )
    reconciliation, reconciliation_state = reconciliation_store.write_locked(
        reconciliation_record, lock=lock
    )
    return _report(
        execution=execution,
        evidence=evidence,
        reconciliation=reconciliation,
        execution_state=DeployScyllaHealthArtifactState.CREATED,
        evidence_state=evidence_state,
        reconciliation_state=reconciliation_state,
    )


def deploy_scylla_post_sequence_three_health_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths,
        operation_id,
        DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_FILENAME_SUFFIX,
    )


def deploy_scylla_post_sequence_three_health_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths,
        operation_id,
        DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EVIDENCE_FILENAME_SUFFIX,
    )


def deploy_scylla_post_sequence_three_health_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths,
        operation_id,
        DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_RECONCILIATION_FILENAME_SUFFIX,
    )


def deploy_scylla_post_sequence_three_health_execution_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_FILENAME_SUFFIX
    )


def deploy_scylla_post_sequence_three_health_evidence_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EVIDENCE_FILENAME_SUFFIX
    )


def deploy_scylla_post_sequence_three_health_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_RECONCILIATION_FILENAME_SUFFIX
    )


def _load_health_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
    builder: AnsibleCommandBuilder,
    toolchain: AnsibleToolchain,
    executable_identity_digest: str,
    toolchain_evidence_digest: str,
) -> _HealthContext:
    sequence_context = _load_sequence_three_execution_context(
        paths,
        operation_id,
        lock=lock,
        builder=builder,
        toolchain=toolchain,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    authorized = _load_sequence_three_join_authorization_context(
        paths, operation_id, lock=lock
    )
    configure = _load_reconciliation_context(paths, operation_id, lock=lock)
    current = _loaded(configure.authorization_context)
    planning = current.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    inventory = deploy.inventory
    journal = deploy.journal
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
    _validate_sequence_three_prefix(
        sequence_context, sequence_execution, sequence_evidence
    )
    executed = sequence_execution.record
    joined = sequence_evidence.record
    if (
        executed.state is not DeployScyllaSequenceThreeJoinExecutionState.SUCCEEDED
        or not executed.completed
        or executed.invocation_count != 1
        or not executed.ordinary_authorization_consumed
        or not executed.narrow_authorization_consumed
        or executed.manual_recovery_required
        or executed.automatic_retry_allowed
        or executed.evidence_digest != joined.evidence_digest
        or executed.result_digest != joined.result_digest
        or joined.status is not ScyllaBootstrapStatus.BOOTSTRAPPED
        or joined.sequence != _CURRENT_MEMBER_COUNT
        or joined.mode is not ScyllaBootstrapMode.JOIN_EXISTING
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
    ):
        raise StateConflictError(
            "post-sequence-three health requires exact terminal-success "
            "sequence-three execution and evidence"
        )
    if (
        journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
        or journal.digest != sequence_context.binding.journal_digest
        or journal.record.generation != sequence_context.binding.journal_generation
    ):
        raise StateConflictError(
            "post-sequence-three Scylla health journal checkpoint conflicts"
        )

    chain = authorized.chain
    plan_steps = chain.plan_steps
    if len(plan_steps) < _CURRENT_MEMBER_COUNT:
        raise StateConflictError(
            "post-sequence-three health requires sequence three in bootstrap plan"
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
            "post-sequence-three Scylla desired topology drifted"
        ) from error
    current_ids = desired_ids[:_CURRENT_MEMBER_COUNT]
    future_ids = desired_ids[_CURRENT_MEMBER_COUNT:]
    prior_health = chain.post_join_health_evidence.record
    prior_reconciliation = chain.post_join_health_reconciliation
    prior_execution = chain.post_join_health_execution
    prior_host_digests = tuple(node.host_id_digest for node in prior_health.nodes)
    expected_host_digests = (*prior_host_digests, joined.host_id_digest)
    if (
        desired_ids != tuple(dict.fromkeys(desired_ids))
        or current_ids != tuple(sorted(current_ids))
        or len(current_ids) != _CURRENT_MEMBER_COUNT
        or tuple(node.stable_id for node in prior_health.nodes) != current_ids[:2]
        or joined.stable_id != current_ids[2]
        or joined.binding.target_digest != plan_steps[2].target_digest
        or any(value is None for value in expected_host_digests)
        or len(set(expected_host_digests)) != _CURRENT_MEMBER_COUNT
        or prior_reconciliation.record.health_succeeded_count != 2
    ):
        raise StateConflictError(
            "post-sequence-three Scylla current membership prefix conflicts"
        )

    storage_entries = {
        item.stable_id: item
        for item in configure.authorization_context.install.authorization_context.evidence.record.entries
        if item.stable_id in current_ids
    }
    install_entries = {
        item.stable_id: item
        for item in configure.authorization_context.install.evidence.record.entries
        if item.stable_id in current_ids
    }
    configuration_entries = {
        item.stable_id: item
        for item in configure.evidence.record.entries
        if item.stable_id in current_ids
    }
    if (
        set(storage_entries) != set(current_ids)
        or set(install_entries) != set(current_ids)
        or set(configuration_entries) != set(current_ids)
        or any(
            not storage_entries[stable_id].readiness_for_scylla
            or storage_entries[stable_id].failed_check_count
            or storage_entries[stable_id].unknown_check_count
            or storage_entries[stable_id].blocker_count
            or not install_entries[stable_id].installed
            or install_entries[stable_id].package_version != SCYLLA_PACKAGE_VERSION
            or not configuration_entries[stable_id].configured
            for stable_id in current_ids
        )
    ):
        raise StateConflictError(
            "post-sequence-three Scylla storage, install, or configuration "
            "provenance conflicts"
        )
    for index, stable_id in enumerate(current_ids):
        step = plan_steps[index]
        configuration = configuration_entries[stable_id]
        host = scylla_hosts[stable_id]
        if (
            step.sequence != index + 1
            or step.target_digest != _digest_object(stable_id)
            or step.storage_evidence_digest
            != storage_entries[stable_id].evidence_digest
            or step.configuration_evidence_digest != configuration.evidence_digest
            or step.topology_digest != configuration.topology_digest
            or step.package_version_digest != _digest_object(SCYLLA_PACKAGE_VERSION)
            or step.datacenter_digest != _digest_object(host.scylla_datacenter)
            or step.rack_digest != _digest_object(host.scylla_rack)
        ):
            raise StateConflictError(
                "post-sequence-three Scylla plan provenance conflicts"
            )

    readiness = replace(
        sequence_context.readiness,
        observation_digest=deploy.observation.digest,
    )
    readiness.require_ready(OperationClassification.READ_ONLY)
    storage_bindings = {
        stable_id: (
            storage_entries[stable_id].readiness_for_scylla,
            storage_entries[stable_id].evidence_digest,
        )
        for stable_id in current_ids
    }
    payload = build_scylla_health_payload(
        metadata,
        deploy.observation,
        inventory,
        readiness,
        (),
        limit=current_ids,
        timeout_seconds=_TIMEOUT_SECONDS,
        active_stable_ids=current_ids,
        storage_bindings=storage_bindings,
    )
    variables = (("deploy_scylla_vms_scylla_health", payload),)
    definition, _, variables_digest, command_digest = builder.validate_operation_step(
        _PLAYBOOK,
        step_sequence=1,
        limit=current_ids,
        variables=dict(variables),
        tags=(_PLAYBOOK,),
        check=True,
        diff=False,
        verbosity=0,
    )
    catalog_definition = get_playbook(_PLAYBOOK)
    playbook_source_digest = _playbook_source_digest(current.source, _PLAYBOOK)
    if (
        definition != catalog_definition
        or definition.classification is not OperationClassification.READ_ONLY
        or definition.hosts != HostRole.SCYLLA.value
        or definition.serial != 5
        or definition.any_errors_fatal
        or definition.limit_policy is not LimitPolicy.EXPLICIT
        or definition.check_mode is not CheckMode.SUPPORTED
        or not definition.source_available
        or sequence_context.binding.catalog_digest != current.catalog_digest
        or sequence_context.binding.source_digest != current.source.digest
    ):
        raise StateConflictError(
            "post-sequence-three Scylla health catalog or source policy conflicts"
        )

    configure_base = current.planning.base
    trust = configure_base.trust
    expected_host_mapping_digest = _digest_object(
        [
            [
                _digest_object(current_ids[index]),
                expected_host_digests[index],
            ]
            for index in range(_CURRENT_MEMBER_COUNT)
        ]
    )
    storage_evidence_digest = _digest_object(
        [storage_entries[stable_id].evidence_digest for stable_id in current_ids]
    )
    configuration_evidence_digest = _digest_object(
        [configuration_entries[stable_id].evidence_digest for stable_id in current_ids]
    )
    policy_digest = _digest_object(
        {
            "current_member_count": _CURRENT_MEMBER_COUNT,
            "generic_policy_truth": {
                name: status.value for name, status in _EXPECTED_POLICY_STATES.items()
            },
            "ordered_serial_join": True,
            "query_policy": "all-nodes-cross-view",
        }
    )
    bootstrap_context = authorized.chain.bootstrap_context_artifact_digest
    bootstrap_plan_artifact = authorized.chain.bootstrap_plan_artifact_digest
    safety_context = authorized.safety_context
    safety_evidence = authorized.safety_evidence
    safety_reconciliation = authorized.safety_reconciliation
    authorization = sequence_context.authorization
    bootstrap_plan_digest = authorized.chain.bootstrap_plan_digest
    binding_values: dict[str, object] = {
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_name": metadata.cluster_name,
        "operation_id": operation_id,
        "operation": _OPERATION,
        "request_digest": journal.record.request_digest,
        "journal_generation": journal.record.generation,
        "journal_digest": journal.digest,
        "journal_status": journal.record.status,
        "journal_phase": journal.record.phase,
        "bootstrap_context_artifact_digest": bootstrap_context,
        "bootstrap_plan_artifact_digest": bootstrap_plan_artifact,
        "bootstrap_plan_digest": bootstrap_plan_digest,
        "pre_sequence_three_health_execution_artifact_digest": (
            prior_execution.artifact_digest
        ),
        "pre_sequence_three_health_evidence_artifact_digest": (
            chain.post_join_health_evidence.artifact_digest
        ),
        "pre_sequence_three_health_reconciliation_artifact_digest": (
            prior_reconciliation.artifact_digest
        ),
        "sequence_three_safety_context_artifact_digest": (
            safety_context.artifact_digest
        ),
        "sequence_three_safety_evidence_artifact_digest": (
            safety_evidence.artifact_digest
        ),
        "sequence_three_safety_reconciliation_artifact_digest": (
            safety_reconciliation.artifact_digest
        ),
        "sequence_three_authorization_artifact_digest": authorization.artifact_digest,
        "sequence_three_authorization_digest": (
            authorization.record.authorization_digest
        ),
        "sequence_three_execution_artifact_digest": sequence_execution.artifact_digest,
        "sequence_three_execution_binding_digest": executed.binding.binding_digest,
        "sequence_three_evidence_artifact_digest": sequence_evidence.artifact_digest,
        "sequence_three_evidence_digest": joined.evidence_digest,
        "post_configure_artifact_digest": (
            authorized.chain.post_join_health_evidence.record.binding.post_configure_artifact_digest
        ),
        "terraform_verification_artifact_digest": (
            authorized.chain.post_join_health_evidence.record.binding.terraform_verification_artifact_digest
        ),
        "observation_generation": deploy.observation.record.generation,
        "observation_artifact_digest": deploy.observation.digest,
        "observation_manifest_digest": deploy.observation.record.manifest_digest,
        "inventory_generation": inventory.record.generation,
        "inventory_artifact_digest": inventory.digest,
        "inventory_digest": inventory.record.inventory_digest,
        "trust_generation": trust.record.generation,
        "trust_artifact_digest": trust.digest,
        "trust_entries_digest": trust.record.entries_digest,
        "readiness_artifact_digest": current.planning.readiness.artifact_digest,
        "readiness_record_digest": current.planning.readiness.record.record_digest,
        "storage_evidence_artifact_digest": (
            authorized.chain.post_join_health_evidence.record.binding.storage_evidence_artifact_digest
        ),
        "install_evidence_artifact_digest": (
            authorized.chain.post_join_health_evidence.record.binding.install_evidence_artifact_digest
        ),
        "configure_evidence_artifact_digest": (
            authorized.chain.post_join_health_evidence.record.binding.configure_evidence_artifact_digest
        ),
        "catalog_digest": current.catalog_digest,
        "source_version": current.source.version,
        "source_digest": current.source.digest,
        "playbook_source_digest": playbook_source_digest,
        "toolchain_version": str(toolchain.core),
        "executable_identity_digest": executable_identity_digest,
        "toolchain_evidence_digest": toolchain_evidence_digest,
        "current_member_count": len(current_ids),
        "current_member_set_digest": _digest_object(list(current_ids)),
        "desired_member_count": len(desired_ids),
        "desired_member_set_digest": _digest_object(list(desired_ids)),
        "future_member_count": len(future_ids),
        "future_member_set_digest": _digest_object(list(future_ids)),
        "current_topology_digest": _digest_object(
            [
                {
                    "datacenter_digest": plan_steps[index].datacenter_digest,
                    "rack_digest": plan_steps[index].rack_digest,
                    "target_digest": plan_steps[index].target_digest,
                }
                for index in range(_CURRENT_MEMBER_COUNT)
            ]
        ),
        "expected_host_mapping_digest": expected_host_mapping_digest,
        "storage_evidence_digest": storage_evidence_digest,
        "configuration_evidence_digest": configuration_evidence_digest,
        "policy_digest": policy_digest,
        "variables_digest": variables_digest,
        "command_digest": command_digest,
        "binding_digest": "",
    }
    binding_values["binding_digest"] = _binding_digest_from_values(binding_values)
    return _HealthContext(
        sequence_context=sequence_context,
        sequence_execution=sequence_execution,
        sequence_evidence=sequence_evidence,
        binding=DeployScyllaPostSequenceThreeHealthExecutionBinding(
            **binding_values  # type: ignore[arg-type]
        ),
        metadata=metadata,
        inventory=inventory,
        readiness=readiness,
        payload=payload,
        variables=variables,
        current_ids=current_ids,
        desired_ids=desired_ids,
        future_ids=future_ids,
        plan_steps=plan_steps,
    )


def _semantic_evidence(
    context: _HealthContext, result: AnsibleExecutionResult
) -> DeployScyllaPostSequenceThreeHealthEvidence:
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.READ_ONLY
        or not result.check_mode
        or result.scylla_health is not None
    ):
        raise AnsibleResultError(
            "post-sequence-three Scylla health result identity conflicts"
        )
    parsed = parse_scylla_health_execution(
        result.stdout,
        expected_payload=context.payload,
        exit_code=result.exit_code,
    )
    checks = {item.name: item.status for item in parsed.checks}
    nodes: list[DeployScyllaHealthEvidenceNode] = []
    for item in parsed.nodes:
        node_values: dict[str, object] = {
            "stable_id": item.logical_id,
            "stable_id_digest": _digest_object(item.logical_id),
            "host_id_digest": (
                None if item.host_id is None else _digest_text(item.host_id)
            ),
            "membership_state": item.state,
            "datacenter_digest": _digest_object(item.datacenter),
            "rack_digest": _digest_object(item.rack),
            "version_digest": _digest_object(item.version),
            "service_ready": item.service_state == "active",
            "api_ready": item.api_reachable is True,
            "cql_ready": item.cql_reachable is True,
            "storage_ready": item.storage_ready,
            "streaming_idle": parsed.streaming_state == "complete",
            "blocker_count": len(item.blockers),
            "blocker_digest": _digest_object(list(item.blockers)),
            "evidence_digest": "",
            "schema_version": (
                ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_NODE_SCHEMA_VERSION
            ),
        }
        node_values["evidence_digest"] = _node_evidence_digest_from_values(node_values)
        nodes.append(
            DeployScyllaHealthEvidenceNode(**node_values)  # type: ignore[arg-type]
        )
    node_tuple = tuple(nodes)
    strict_states = tuple((name, checks[name]) for name in _STRICT_CHECKS)
    policy_states = tuple((name, checks[name]) for name in _POLICY_CHECKS)
    expected_host_mapping_digest = _digest_object(
        [[node.stable_id_digest, node.host_id_digest] for node in node_tuple]
    )
    node_health_complete = bool(node_tuple) and all(
        node.membership_state == "UN"
        and node.service_ready
        and node.api_ready
        and node.cql_ready
        and node.storage_ready
        and node.streaming_idle
        and node.version_digest == _digest_object(SCYLLA_PACKAGE_VERSION)
        and node.blocker_count == 0
        for node in node_tuple
    )
    strict_complete = (
        parsed.status is HealthReadiness.UNKNOWN
        and parsed.query_policy == "all-nodes-cross-view"
        and parsed.queried_nodes == context.current_ids
        and tuple(node.stable_id for node in node_tuple) == context.current_ids
        and len(node_tuple) == _CURRENT_MEMBER_COUNT
        and expected_host_mapping_digest == context.binding.expected_host_mapping_digest
        and node_health_complete
        and parsed.schema_agreement is True
        and parsed.schema_digest is not None
        and parsed.topology_digest is not None
        and parsed.streaming_state == "complete"
        and all(status is HealthCheckStatus.PASSED for _, status in strict_states)
        and dict(policy_states) == _EXPECTED_POLICY_STATES
        and not parsed.blockers
    )
    result_digest = _digest_object(
        {
            "blocker_digest": _digest_object(list(parsed.blockers)),
            "check_states": [[name, state.value] for name, state in strict_states],
            "host_id_mapping_digest": expected_host_mapping_digest,
            "policy_states": [[name, state.value] for name, state in policy_states],
            "query_policy": parsed.query_policy,
            "status": parsed.status.value,
        }
    )
    membership_digest = _digest_object(
        [
            [node.stable_id_digest, node.host_id_digest, node.membership_state]
            for node in node_tuple
        ]
    )
    evidence_values: dict[str, object] = {
        "generation": 1,
        "created_at": _timestamp(),
        "binding": context.binding,
        "health_status": parsed.status,
        "query_policy": parsed.query_policy,
        "nodes": node_tuple,
        "host_id_mapping_digest": expected_host_mapping_digest,
        "membership_digest": membership_digest,
        "topology_digest": parsed.topology_digest,
        "schema_digest": parsed.schema_digest,
        "schema_agreement": parsed.schema_agreement is True,
        "streaming_state": parsed.streaming_state,
        "check_states": strict_states,
        "policy_states": policy_states,
        "blocker_count": len(parsed.blockers),
        "blocker_digest": _digest_object(list(parsed.blockers)),
        "strict_complete": strict_complete,
        "result_digest": result_digest,
        "evidence_digest": "",
    }
    evidence_values["evidence_digest"] = _health_evidence_digest_from_values(
        evidence_values
    )
    return DeployScyllaPostSequenceThreeHealthEvidence(
        **evidence_values  # type: ignore[arg-type]
    )


def _build_reconciliation(
    context: _HealthContext,
    execution: StoredDeployScyllaPostSequenceThreeHealthExecution,
    evidence: StoredDeployScyllaPostSequenceThreeHealthEvidence,
    *,
    created_at: str,
) -> DeployScyllaPostSequenceThreeHealthReconciliation:
    if (
        execution.record.binding != context.binding
        or execution.record.state is not DeployScyllaHealthExecutionState.SUCCEEDED
        or execution.record.evidence_digest != evidence.record.evidence_digest
        or evidence.record.binding != context.binding
        or not evidence.record.strict_complete
    ):
        raise StateConflictError(
            "post-sequence-three Scylla health reconciliation prefix conflicts"
        )
    steps: list[DeployScyllaPostSequenceThreeHealthStep] = []
    next_join_sequence: int | None = None
    next_join_status = "not-required"
    next_join_blockers: tuple[str, ...] = ()
    for original in context.plan_steps:
        sequence = original.sequence
        if sequence <= _CURRENT_MEMBER_COUNT:
            status = DeployScyllaPostSequenceThreeHealthStepStatus.HEALTH_SUCCEEDED
            health_state = "complete-current-cluster-health"
            safety_state = "not-required"
            blockers: tuple[str, ...] = ()
        elif sequence == _CURRENT_MEMBER_COUNT + 1:
            status = DeployScyllaPostSequenceThreeHealthStepStatus.WAITING_FOR_SAFETY
            health_state = "complete-current-cluster-health"
            safety_state = "not-created"
            blockers = ("separate-safety-context-not-created",)
            next_join_sequence = sequence
            next_join_status = status.value
            next_join_blockers = blockers
        else:
            status = DeployScyllaPostSequenceThreeHealthStepStatus.WAITING_FOR_PRECEDING_HEALTH
            health_state = "waiting-for-preceding-complete-health"
            safety_state = "waiting"
            blockers = ("preceding-join-not-completed",)
        values: dict[str, object] = {
            "sequence": sequence,
            "mode": original.mode,
            "target_digest": original.target_digest,
            "plan_step_digest": original.step_digest,
            "status": status,
            "health_checkpoint_state": health_state,
            "safety_context_state": safety_state,
            "blockers": blockers,
            "blocker_digest": _digest_object(list(blockers)),
            "step_digest": "",
        }
        values["step_digest"] = _step_digest_from_values(values)
        steps.append(
            DeployScyllaPostSequenceThreeHealthStep(
                **values  # type: ignore[arg-type]
            )
        )
    step_tuple = tuple(steps)
    counts = Counter(step.status for step in step_tuple)
    later = step_tuple[_CURRENT_MEMBER_COUNT + 1 :]
    values = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": context.binding.cluster_uuid,
        "cluster_name": context.binding.cluster_name,
        "operation_id": context.binding.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "request_digest": context.binding.request_digest,
        "journal_generation": context.binding.journal_generation,
        "journal_digest": context.binding.journal_digest,
        "journal_status": context.binding.journal_status,
        "journal_phase": context.binding.journal_phase,
        "health_execution_artifact_digest": execution.artifact_digest,
        "health_evidence_artifact_digest": evidence.artifact_digest,
        "health_evidence_digest": evidence.record.evidence_digest,
        "sequence_three_execution_artifact_digest": (
            context.sequence_execution.artifact_digest
        ),
        "sequence_three_evidence_artifact_digest": (
            context.sequence_evidence.artifact_digest
        ),
        "sequence_three_evidence_digest": (
            context.sequence_evidence.record.evidence_digest
        ),
        "steps": step_tuple,
        "step_count": len(step_tuple),
        "health_succeeded_count": counts[
            DeployScyllaPostSequenceThreeHealthStepStatus.HEALTH_SUCCEEDED
        ],
        "waiting_for_safety_count": counts[
            DeployScyllaPostSequenceThreeHealthStepStatus.WAITING_FOR_SAFETY
        ],
        "waiting_for_preceding_health_count": counts[
            DeployScyllaPostSequenceThreeHealthStepStatus.WAITING_FOR_PRECEDING_HEALTH
        ],
        "current_member_count": len(context.current_ids),
        "current_member_set_digest": _digest_object(list(context.current_ids)),
        "bootstrap_sequence_complete": not context.future_ids,
        "next_step_required": bool(context.future_ids),
        "next_join_sequence": next_join_sequence,
        "next_join_status": next_join_status,
        "next_join_blocker_digest": _digest_object(list(next_join_blockers)),
        "later_join_count": len(later),
        "later_join_set_digest": _digest_object([step.target_digest for step in later]),
        "reconciliation_digest": "",
    }
    values["reconciliation_digest"] = _reconciliation_digest_from_values(values)
    return DeployScyllaPostSequenceThreeHealthReconciliation(
        **values  # type: ignore[arg-type]
    )


def _validate_prefix(
    context: _HealthContext,
    execution: StoredDeployScyllaPostSequenceThreeHealthExecution | None,
    evidence: StoredDeployScyllaPostSequenceThreeHealthEvidence | None,
    reconciliation: StoredDeployScyllaPostSequenceThreeHealthReconciliation | None,
) -> None:
    if execution is None:
        if evidence is not None or reconciliation is not None:
            raise StateConflictError(
                "post-sequence-three health artifacts exist without execution"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError(
            "post-sequence-three Scylla health execution binding drifted"
        )
    if evidence is not None and (
        evidence.record.binding != context.binding
        or execution.record.evidence_digest != evidence.record.evidence_digest
    ):
        raise StateConflictError(
            "post-sequence-three Scylla health evidence binding conflicts"
        )
    if reconciliation is not None:
        if evidence is None:
            raise StateConflictError(
                "post-sequence-three health reconciliation evidence is unavailable"
            )
        expected = _build_reconciliation(
            context,
            execution,
            evidence,
            created_at=reconciliation.record.created_at,
        )
        if reconciliation.record != expected:
            raise StateConflictError(
                "post-sequence-three Scylla health reconciliation drifted"
            )


def _persist_started(
    store: DeployScyllaPostSequenceThreeHealthExecutionStore,
    context: _HealthContext,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaPostSequenceThreeHealthExecution:
    now = _timestamp()
    return store.write_locked(
        DeployScyllaPostSequenceThreeHealthExecution(
            generation=1,
            created_at=now,
            updated_at=now,
            binding=context.binding,
            state=DeployScyllaHealthExecutionState.STARTED,
            invocation_count=1,
            completed=False,
            manual_recovery_required=True,
            automatic_retry_allowed=False,
            exit_code=None,
            result_digest=None,
            evidence_digest=None,
        ),
        expected_generation=0,
        expected_digest=None,
        lock=lock,
    )


def _persist_uncertain_or_raise(
    store: DeployScyllaPostSequenceThreeHealthExecutionStore,
    current: StoredDeployScyllaPostSequenceThreeHealthExecution,
    state: DeployScyllaHealthExecutionState,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaPostSequenceThreeHealthExecution:
    return store.write_locked(
        replace(
            current.record,
            generation=2,
            updated_at=_timestamp(),
            state=state,
            manual_recovery_required=True,
        ),
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _persist_terminal(
    store: DeployScyllaPostSequenceThreeHealthExecutionStore,
    current: StoredDeployScyllaPostSequenceThreeHealthExecution,
    *,
    evidence: StoredDeployScyllaPostSequenceThreeHealthEvidence,
    result: AnsibleExecutionResult,
    state: DeployScyllaHealthExecutionState,
    lock: ClusterLock,
) -> StoredDeployScyllaPostSequenceThreeHealthExecution:
    return store.write_locked(
        replace(
            current.record,
            generation=2,
            updated_at=_timestamp(),
            state=state,
            completed=True,
            manual_recovery_required=(
                state is not DeployScyllaHealthExecutionState.SUCCEEDED
            ),
            exit_code=result.exit_code,
            result_digest=evidence.record.result_digest,
            evidence_digest=evidence.record.evidence_digest,
        ),
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _report(
    *,
    execution: StoredDeployScyllaPostSequenceThreeHealthExecution,
    evidence: StoredDeployScyllaPostSequenceThreeHealthEvidence,
    reconciliation: StoredDeployScyllaPostSequenceThreeHealthReconciliation,
    execution_state: DeployScyllaHealthArtifactState,
    evidence_state: DeployScyllaHealthArtifactState,
    reconciliation_state: DeployScyllaHealthArtifactState,
) -> DeployScyllaPostSequenceThreeHealthReport:
    record = evidence.record
    next_step = (
        None
        if reconciliation.record.next_join_sequence is None
        else next(
            step
            for step in reconciliation.record.steps
            if step.sequence == reconciliation.record.next_join_sequence
        )
    )
    return DeployScyllaPostSequenceThreeHealthReport(
        operation_id=record.binding.operation_id,
        execution_state=execution.record.state,
        execution_artifact_state=execution_state,
        evidence_artifact_state=evidence_state,
        reconciliation_artifact_state=reconciliation_state,
        current_member_count=record.binding.current_member_count,
        desired_member_count=record.binding.desired_member_count,
        future_member_count=record.binding.future_member_count,
        health_complete=record.strict_complete,
        host_identity_count=sum(
            node.host_id_digest is not None for node in record.nodes
        ),
        up_normal_count=sum(node.membership_state == "UN" for node in record.nodes),
        service_ready_count=sum(node.service_ready for node in record.nodes),
        api_ready_count=sum(node.api_ready for node in record.nodes),
        cql_ready_count=sum(node.cql_ready for node in record.nodes),
        storage_ready_count=sum(node.storage_ready for node in record.nodes),
        schema_agreement=record.schema_agreement,
        streaming_idle=record.streaming_state == "complete",
        policy_unknown_count=sum(
            status is HealthCheckStatus.UNKNOWN for _, status in record.policy_states
        ),
        policy_not_performed_count=sum(
            status is HealthCheckStatus.NOT_PERFORMED
            for _, status in record.policy_states
        ),
        bootstrap_sequence_complete=reconciliation.record.bootstrap_sequence_complete,
        next_step_required=reconciliation.record.next_step_required,
        next_join_sequence=reconciliation.record.next_join_sequence,
        next_join_status=reconciliation.record.next_join_status,
        next_join_blocker_count=0 if next_step is None else len(next_step.blockers),
        later_join_count=reconciliation.record.later_join_count,
        manual_recovery_required=execution.record.manual_recovery_required,
        automatic_retry_allowed=False,
        journal_status=record.binding.journal_status,
        journal_phase=record.binding.journal_phase,
        execution_artifact_digest=execution.artifact_digest,
        evidence_artifact_digest=evidence.artifact_digest,
        reconciliation_artifact_digest=reconciliation.artifact_digest,
        evidence_digest=record.evidence_digest,
        reconciliation_digest=reconciliation.record.reconciliation_digest,
    )


def _read_execution(
    store: DeployScyllaPostSequenceThreeHealthExecutionStore,
    context: _HealthContext,
    lock: ClusterLock,
) -> StoredDeployScyllaPostSequenceThreeHealthExecution | None:
    return (
        store.read_locked(
            lock,
            expected_cluster_uuid=context.binding.cluster_uuid,
            expected_cluster_name=context.binding.cluster_name,
        )
        if store.path.exists()
        else None
    )


def _read_evidence(
    store: DeployScyllaPostSequenceThreeHealthEvidenceStore,
    context: _HealthContext,
    lock: ClusterLock,
) -> StoredDeployScyllaPostSequenceThreeHealthEvidence | None:
    return (
        store.read_locked(
            lock,
            expected_cluster_uuid=context.binding.cluster_uuid,
            expected_cluster_name=context.binding.cluster_name,
        )
        if store.path.exists()
        else None
    )


def _read_reconciliation(
    store: DeployScyllaPostSequenceThreeHealthReconciliationStore,
    context: _HealthContext,
    lock: ClusterLock,
) -> StoredDeployScyllaPostSequenceThreeHealthReconciliation | None:
    return (
        store.read_locked(
            lock,
            expected_cluster_uuid=context.binding.cluster_uuid,
            expected_cluster_name=context.binding.cluster_name,
        )
        if store.path.exists()
        else None
    )


def _binding_digest(
    record: DeployScyllaPostSequenceThreeHealthExecutionBinding,
) -> str:
    return _binding_digest_from_values(record.to_object())


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for (
        name,
        field,
    ) in (
        DeployScyllaPostSequenceThreeHealthExecutionBinding.__dataclass_fields__.items()
    ):
        value.setdefault(name, _json_value(field.default))
    value["binding_digest"] = ""
    return _digest_object(value)


def _health_evidence_digest(
    record: DeployScyllaPostSequenceThreeHealthEvidence,
) -> str:
    return _health_evidence_digest_from_values(record.to_object())


def _health_evidence_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for (
        name,
        field,
    ) in DeployScyllaPostSequenceThreeHealthEvidence.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["evidence_digest"] = ""
    return _digest_object(value)


def _step_digest(record: DeployScyllaPostSequenceThreeHealthStep) -> str:
    return _step_digest_from_values(record.to_object())


def _step_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    value.setdefault(
        "schema_version",
        ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_STEP_SCHEMA_VERSION,
    )
    value["step_digest"] = ""
    return _digest_object(value)


def _reconciliation_digest(
    record: DeployScyllaPostSequenceThreeHealthReconciliation,
) -> str:
    return _reconciliation_digest_from_values(record.to_object())


def _reconciliation_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for (
        name,
        field,
    ) in DeployScyllaPostSequenceThreeHealthReconciliation.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["reconciliation_digest"] = ""
    return _digest_object(value)


def _artifact_path(paths: StatePaths, operation_id: uuid.UUID, suffix: str) -> Path:
    _require_canonical_paths(paths)
    path = paths.operations / f"{_require_operation_id(operation_id)}{suffix}"
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "post-sequence-three Scylla health path is not canonical"
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
            "post-sequence-three Scylla health identity conflicts"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "post-sequence-three health requires the matching held deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "post-sequence-three Scylla health paths are not canonical"
        )


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EVIDENCE_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_RECONCILIATION_FILENAME_SUFFIX,
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list post-sequence-three health artifacts"
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
                    "post-sequence-three health artifacts are ambiguous"
                )


__all__ = [
    "ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_BINDING_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_RECONCILIATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_STEP_SCHEMA_VERSION",
    "DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_FILENAME_SUFFIX",
    "DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_RECONCILIATION_FILENAME_SUFFIX",
    "DeployScyllaPostSequenceThreeHealthEvidence",
    "DeployScyllaPostSequenceThreeHealthEvidenceStore",
    "DeployScyllaPostSequenceThreeHealthExecution",
    "DeployScyllaPostSequenceThreeHealthExecutionBinding",
    "DeployScyllaPostSequenceThreeHealthExecutionStore",
    "DeployScyllaPostSequenceThreeHealthReconciliation",
    "DeployScyllaPostSequenceThreeHealthReconciliationStore",
    "DeployScyllaPostSequenceThreeHealthReport",
    "DeployScyllaPostSequenceThreeHealthStep",
    "DeployScyllaPostSequenceThreeHealthStepStatus",
    "StoredDeployScyllaPostSequenceThreeHealthEvidence",
    "StoredDeployScyllaPostSequenceThreeHealthExecution",
    "StoredDeployScyllaPostSequenceThreeHealthReconciliation",
    "deploy_scylla_post_sequence_three_health_evidence_id_from_filename",
    "deploy_scylla_post_sequence_three_health_evidence_path",
    "deploy_scylla_post_sequence_three_health_execution_id_from_filename",
    "deploy_scylla_post_sequence_three_health_execution_path",
    "deploy_scylla_post_sequence_three_health_reconciliation_id_from_filename",
    "deploy_scylla_post_sequence_three_health_reconciliation_path",
    "execute_deploy_scylla_post_sequence_three_join_health",
]
