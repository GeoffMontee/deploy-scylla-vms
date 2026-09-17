"""Complete-set health after one canonically derived generic later join.

The owner derives the just-completed sequence from immutable sequence-keyed
later-join records, runs the existing read-only ``scylla-health`` source once,
and persists one immutable sequence-keyed checkpoint.  It never accepts a
caller-selected sequence and never creates the next safety stage.
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
from scylla_vms.ansible.deploy_scylla_later_join_authorization import (
    DeployScyllaLaterJoinAuthorizationStore,
    _load_later_join_authorization_context,
)
from scylla_vms.ansible.deploy_scylla_later_join_execution import (
    ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_EXECUTION_SCHEMA_VERSION,
    DeployScyllaLaterJoinEvidenceStore,
    DeployScyllaLaterJoinExecutionState,
    DeployScyllaLaterJoinExecutionStore,
    deploy_scylla_later_join_execution_id_from_filename,
)
from scylla_vms.ansible.deploy_scylla_later_join_execution import (
    _ExecutionContext as _LaterJoinExecutionContext,
)
from scylla_vms.ansible.deploy_scylla_later_join_execution import (
    _load_execution_context as _load_later_join_execution_context,
)
from scylla_vms.ansible.deploy_scylla_later_join_execution import (
    _validate_prefix as _validate_later_join_prefix,
)
from scylla_vms.ansible.deploy_scylla_later_join_safety import (
    DeployScyllaLaterJoinSafetyContextStore,
    DeployScyllaLaterJoinSafetyEvidenceStore,
    DeployScyllaLaterJoinSafetyReconciliationStore,
)
from scylla_vms.ansible.deploy_scylla_post_join_health import (
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
from scylla_vms.ansible.deploy_scylla_post_sequence_three_join_health import (
    DeployScyllaPostSequenceThreeHealthEvidenceStore,
    DeployScyllaPostSequenceThreeHealthExecutionStore,
    DeployScyllaPostSequenceThreeHealthReconciliationStore,
    StoredDeployScyllaPostSequenceThreeHealthEvidence,
    StoredDeployScyllaPostSequenceThreeHealthExecution,
    StoredDeployScyllaPostSequenceThreeHealthReconciliation,
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

ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-post-later-join-health-"
    "execution-binding/v1"
)
ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-post-later-join-health-execution/v1"
)
ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-post-later-join-health-evidence/v1"
)
ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_STEP_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-post-later-join-health-step/v1"
)
ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-post-later-join-health-reconciliation/v1"
)
ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-post-later-join-health-report/v1"
)

DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EXECUTION_FILENAME_SUFFIX = (
    "-health-execution.json"
)
DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EVIDENCE_FILENAME_SUFFIX = "-health-evidence.json"
DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_RECONCILIATION_FILENAME_SUFFIX = (
    "-health-reconciliation.json"
)
_FILENAME_STEM = ".ansible-deploy-scylla-post-later-join-sequence-"
_OPERATION = "deploy"
_PLAYBOOK = "scylla-health"
_STAGE = "post-later-join-complete-current-set-health"
_MINIMUM_SEQUENCE = 4
_TIMEOUT_SECONDS = 60
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


class DeployScyllaPostLaterJoinHealthStepStatus(StrEnum):
    HEALTH_SUCCEEDED = "health-succeeded"
    WAITING_FOR_SAFETY = "waiting-for-separate-safety-context"
    WAITING_FOR_PRECEDING_HEALTH = "waiting-for-preceding-complete-health"


@dataclass(frozen=True, slots=True)
class DeployScyllaPostLaterJoinHealthExecutionBinding:
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
    prior_health_execution_artifact_digest: str
    prior_health_evidence_artifact_digest: str
    prior_health_evidence_digest: str
    prior_health_reconciliation_artifact_digest: str
    prior_health_reconciliation_digest: str
    prior_health_schema_version: str
    later_safety_context_artifact_digest: str
    later_safety_context_digest: str
    later_safety_evidence_artifact_digest: str
    later_safety_evidence_digest: str
    later_safety_reconciliation_artifact_digest: str
    later_safety_reconciliation_digest: str
    later_authorization_artifact_digest: str
    later_authorization_digest: str
    later_join_execution_artifact_digest: str
    later_join_execution_binding_digest: str
    later_join_evidence_artifact_digest: str
    later_join_evidence_digest: str
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
    completed_sequence: int
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
    later_join_execution_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_EXECUTION_SCHEMA_VERSION
    )
    later_join_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_EVIDENCE_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EXECUTION_BINDING_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EXECUTION_BINDING_SCHEMA_VERSION
            or self.later_join_execution_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_EXECUTION_SCHEMA_VERSION
            or self.later_join_evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_EVIDENCE_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.completed_sequence < _MINIMUM_SEQUENCE
            or self.current_member_count != self.completed_sequence
            or self.desired_member_count < self.current_member_count
            or self.future_member_count
            != self.desired_member_count - self.current_member_count
            or self.binding_digest != _binding_digest(self)
        ):
            raise StatePersistenceError("post-later-join health binding conflicts")
        validate_cluster_name(self.cluster_name)
        for generation in (
            self.journal_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
        ):
            _positive_integer(generation, "post-later-join health generation")
        for digest in _digest_fields(self):
            validate_digest(digest, "post-later-join health binding digest")
        _validate_toolchain_version(self.toolchain_version)

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaPostLaterJoinHealthExecutionBinding:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={
                "journal_generation",
                "observation_generation",
                "inventory_generation",
                "trust_generation",
                "completed_sequence",
                "current_member_count",
                "desired_member_count",
                "future_member_count",
            },
            uuid_fields={"cluster_uuid", "operation_id"},
            enum_fields={
                "journal_status": JournalStatus,
                "journal_phase": OperationPhase,
            },
            label="post-later-join health binding",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaPostLaterJoinHealthExecution:
    generation: int
    created_at: str
    updated_at: str
    binding: DeployScyllaPostLaterJoinHealthExecutionBinding
    state: DeployScyllaHealthExecutionState
    invocation_count: int
    completed: bool
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    exit_code: int | None
    result_digest: str | None
    evidence_digest: str | None
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EXECUTION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        terminal = self.state in {
            DeployScyllaHealthExecutionState.SUCCEEDED,
            DeployScyllaHealthExecutionState.FAILED,
        }
        success = self.state is DeployScyllaHealthExecutionState.SUCCEEDED
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EXECUTION_SCHEMA_VERSION
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
            raise StatePersistenceError("post-later-join health execution conflicts")
        for digest in (self.result_digest, self.evidence_digest):
            if digest is not None:
                validate_digest(digest, "post-later-join health execution digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, nested_fields={"binding"})

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaPostLaterJoinHealthExecution:
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
            label="post-later-join health execution",
        )
        parsed["binding"] = DeployScyllaPostLaterJoinHealthExecutionBinding.from_object(
            _mapping(value["binding"], "post-later-join health binding")
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaPostLaterJoinHealthEvidence:
    generation: int
    created_at: str
    binding: DeployScyllaPostLaterJoinHealthExecutionBinding
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
        ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EVIDENCE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EVIDENCE_SCHEMA_VERSION
            or self.result_schema_version != SCYLLA_HEALTH_SCHEMA_VERSION
            or self.generation != 1
            or self.query_policy != "all-nodes-cross-view"
            or tuple(node.stable_id for node in self.nodes)
            != tuple(sorted({node.stable_id for node in self.nodes}))
            or len(self.nodes) != self.binding.current_member_count
            or tuple(name for name, _ in self.check_states) != _STRICT_CHECKS
            or tuple(name for name, _ in self.policy_states) != _POLICY_CHECKS
            or self.blocker_count < 0
            or self.evidence_digest != _health_evidence_digest(self)
        ):
            raise StatePersistenceError("post-later-join health evidence conflicts")
        parse_timestamp(self.created_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "post-later-join health evidence digest")

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
    ) -> DeployScyllaPostLaterJoinHealthEvidence:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={"generation", "blocker_count"},
            boolean_fields={"schema_agreement", "strict_complete"},
            enum_fields={"health_status": HealthReadiness},
            optional_string_fields={"topology_digest", "schema_digest"},
            skip_fields={"binding", "nodes", "check_states", "policy_states"},
            label="post-later-join health evidence",
        )
        parsed["binding"] = DeployScyllaPostLaterJoinHealthExecutionBinding.from_object(
            _mapping(value["binding"], "post-later-join health binding")
        )
        parsed["nodes"] = tuple(
            DeployScyllaHealthEvidenceNode.from_object(
                _mapping(item, "post-later-join health node")
            )
            for item in _array(value["nodes"], "post-later-join health nodes")
        )
        parsed["check_states"] = _status_pairs(value["check_states"], "check states")
        parsed["policy_states"] = _status_pairs(value["policy_states"], "policy states")
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaPostLaterJoinHealthStep:
    sequence: int
    mode: ScyllaBootstrapMode
    target_digest: str
    plan_step_digest: str
    status: DeployScyllaPostLaterJoinHealthStepStatus
    health_checkpoint_state: str
    safety_context_state: str
    blockers: tuple[str, ...]
    blocker_digest: str
    step_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_STEP_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_STEP_SCHEMA_VERSION
            or self.sequence < 1
            or tuple(sorted(set(self.blockers))) != self.blockers
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.step_digest != _step_digest(self)
        ):
            raise StatePersistenceError("post-later-join health step conflicts")
        for digest in _digest_fields(self):
            validate_digest(digest, "post-later-join health step digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, tuple_fields={"blockers"})

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaPostLaterJoinHealthStep:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={"sequence"},
            tuple_fields={"blockers"},
            enum_fields={
                "mode": ScyllaBootstrapMode,
                "status": DeployScyllaPostLaterJoinHealthStepStatus,
            },
            label="post-later-join health step",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaPostLaterJoinHealthReconciliation:
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
    completed_sequence: int
    health_execution_artifact_digest: str
    health_evidence_artifact_digest: str
    health_evidence_digest: str
    later_join_execution_artifact_digest: str
    later_join_evidence_artifact_digest: str
    later_join_evidence_digest: str
    steps: tuple[DeployScyllaPostLaterJoinHealthStep, ...]
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
        ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        counts = Counter(step.status for step in self.steps)
        next_exists = self.step_count > self.completed_sequence
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_RECONCILIATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.completed_sequence < _MINIMUM_SEQUENCE
            or self.step_count != len(self.steps)
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, self.step_count + 1))
            or self.health_succeeded_count
            != counts[DeployScyllaPostLaterJoinHealthStepStatus.HEALTH_SUCCEEDED]
            or self.waiting_for_safety_count
            != counts[DeployScyllaPostLaterJoinHealthStepStatus.WAITING_FOR_SAFETY]
            or self.waiting_for_preceding_health_count
            != counts[
                DeployScyllaPostLaterJoinHealthStepStatus.WAITING_FOR_PRECEDING_HEALTH
            ]
            or self.health_succeeded_count != self.completed_sequence
            or self.current_member_count != self.completed_sequence
            or self.waiting_for_safety_count != int(next_exists)
            or self.bootstrap_sequence_complete != (not next_exists)
            or self.next_step_required != next_exists
            or self.next_join_sequence
            != (self.completed_sequence + 1 if next_exists else None)
            or self.next_join_status
            != (
                DeployScyllaPostLaterJoinHealthStepStatus.WAITING_FOR_SAFETY.value
                if next_exists
                else "not-required"
            )
            or self.later_join_count
            != max(0, self.step_count - self.completed_sequence - 1)
            or self.reconciliation_digest != _reconciliation_digest(self)
        ):
            raise StatePersistenceError(
                "post-later-join health reconciliation conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "post-later-join reconciliation digest")

    def to_object(self) -> dict[str, object]:
        return {
            **_dataclass_object(self, skip_fields={"steps"}),
            "steps": [step.to_object() for step in self.steps],
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaPostLaterJoinHealthReconciliation:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={
                "generation",
                "journal_generation",
                "completed_sequence",
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
            label="post-later-join health reconciliation",
        )
        parsed["steps"] = tuple(
            DeployScyllaPostLaterJoinHealthStep.from_object(
                _mapping(item, "post-later-join health step")
            )
            for item in _array(value["steps"], "post-later-join health steps")
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaPostLaterJoinHealthExecution:
    record: DeployScyllaPostLaterJoinHealthExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaPostLaterJoinHealthEvidence:
    record: DeployScyllaPostLaterJoinHealthEvidence
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaPostLaterJoinHealthReconciliation:
    record: DeployScyllaPostLaterJoinHealthReconciliation
    artifact_digest: str


class DeployScyllaPostLaterJoinHealthExecutionStore:
    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        sequence: int,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
    ) -> None:
        _require_canonical_paths(paths)
        self._paths = paths
        self._operation_id = _require_operation_id(operation_id)
        self._sequence = _require_sequence(sequence)
        self._path = deploy_scylla_post_later_join_health_execution_path(
            paths, operation_id, sequence
        )
        self._file = AtomicJsonFile(self._path, replace=replace_file)

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployScyllaPostLaterJoinHealthExecution:
        value, digest = self._file.read()
        record = DeployScyllaPostLaterJoinHealthExecution.from_object(value)
        _require_identity(
            record.binding.operation_id,
            record.binding.cluster_uuid,
            record.binding.cluster_name,
            record.binding.completed_sequence,
            operation_id=self._operation_id,
            cluster_uuid=expected_cluster_uuid,
            cluster_name=expected_cluster_name,
            sequence=self._sequence,
        )
        return StoredDeployScyllaPostLaterJoinHealthExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaPostLaterJoinHealthExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaPostLaterJoinHealthExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployScyllaPostLaterJoinHealthExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.completed_sequence != self._sequence:
            raise StatePersistenceError(
                "post-later-join health execution sequence conflicts"
            )
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
                    "post-later-join health execution transition conflicts"
                )
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
            or record.state is not DeployScyllaHealthExecutionState.STARTED
        ):
            raise StateConflictError(
                "post-later-join health initial execution conflicts"
            )
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployScyllaPostLaterJoinHealthExecution(record, digest)


class DeployScyllaPostLaterJoinHealthEvidenceStore:
    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        sequence: int,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
    ) -> None:
        _require_canonical_paths(paths)
        self._paths = paths
        self._operation_id = _require_operation_id(operation_id)
        self._sequence = _require_sequence(sequence)
        self._path = deploy_scylla_post_later_join_health_evidence_path(
            paths, operation_id, sequence
        )
        self._file = AtomicJsonFile(self._path, replace=replace_file)

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployScyllaPostLaterJoinHealthEvidence:
        value, digest = self._file.read()
        record = DeployScyllaPostLaterJoinHealthEvidence.from_object(value)
        _require_identity(
            record.binding.operation_id,
            record.binding.cluster_uuid,
            record.binding.cluster_name,
            record.binding.completed_sequence,
            operation_id=self._operation_id,
            cluster_uuid=expected_cluster_uuid,
            cluster_name=expected_cluster_name,
            sequence=self._sequence,
        )
        return StoredDeployScyllaPostLaterJoinHealthEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaPostLaterJoinHealthEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaPostLaterJoinHealthEvidence,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployScyllaPostLaterJoinHealthEvidence,
        DeployScyllaHealthArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.completed_sequence != self._sequence:
            raise StatePersistenceError(
                "post-later-join health evidence sequence conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if current.record != record:
                raise StateConflictError("post-later-join health evidence is immutable")
            return current, DeployScyllaHealthArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaPostLaterJoinHealthEvidence(record, digest),
            DeployScyllaHealthArtifactState.CREATED,
        )


class DeployScyllaPostLaterJoinHealthReconciliationStore:
    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        sequence: int,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
    ) -> None:
        _require_canonical_paths(paths)
        self._paths = paths
        self._operation_id = _require_operation_id(operation_id)
        self._sequence = _require_sequence(sequence)
        self._path = deploy_scylla_post_later_join_health_reconciliation_path(
            paths, operation_id, sequence
        )
        self._file = AtomicJsonFile(self._path, replace=replace_file)

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployScyllaPostLaterJoinHealthReconciliation:
        value, digest = self._file.read()
        record = DeployScyllaPostLaterJoinHealthReconciliation.from_object(value)
        _require_identity(
            record.operation_id,
            record.cluster_uuid,
            record.cluster_name,
            record.completed_sequence,
            operation_id=self._operation_id,
            cluster_uuid=expected_cluster_uuid,
            cluster_name=expected_cluster_name,
            sequence=self._sequence,
        )
        return StoredDeployScyllaPostLaterJoinHealthReconciliation(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaPostLaterJoinHealthReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaPostLaterJoinHealthReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployScyllaPostLaterJoinHealthReconciliation,
        DeployScyllaHealthArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_file(self._path, allow_missing=True)
        if record.completed_sequence != self._sequence:
            raise StatePersistenceError(
                "post-later-join health reconciliation sequence conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "post-later-join health reconciliation is immutable"
                )
            return current, DeployScyllaHealthArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaPostLaterJoinHealthReconciliation(record, digest),
            DeployScyllaHealthArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaPostLaterJoinHealthReport:
    operation_id: uuid.UUID
    completed_sequence: int
    execution_state: DeployScyllaHealthExecutionState
    execution_artifact_state: DeployScyllaHealthArtifactState
    evidence_artifact_state: DeployScyllaHealthArtifactState
    reconciliation_artifact_state: DeployScyllaHealthArtifactState
    current_member_count: int
    desired_member_count: int
    future_member_count: int
    host_identity_count: int
    up_normal_count: int
    service_ready_count: int
    api_ready_count: int
    cql_ready_count: int
    storage_ready_count: int
    policy_unknown_count: int
    policy_not_performed_count: int
    bootstrap_sequence_complete: bool
    next_step_required: bool
    next_join_sequence: int | None
    next_join_status: str
    later_join_count: int
    execution_artifact_digest: str
    evidence_artifact_digest: str
    reconciliation_artifact_digest: str
    evidence_digest: str
    reconciliation_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    stage: str = _STAGE
    health_complete: bool = True
    schema_agreement: bool = True
    streaming_idle: bool = True
    manual_recovery_required: bool = False
    automatic_retry_allowed: bool = False
    journal_updated: bool = False
    public_workflow_state: str = "unavailable"
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_REPORT_SCHEMA_VERSION
            or self.stage != _STAGE
            or self.completed_sequence < _MINIMUM_SEQUENCE
            or self.current_member_count != self.completed_sequence
            or self.execution_state is not DeployScyllaHealthExecutionState.SUCCEEDED
            or not self.health_complete
            or not self.schema_agreement
            or not self.streaming_idle
            or self.policy_unknown_count != 2
            or self.policy_not_performed_count != 2
            or self.bootstrap_sequence_complete == self.next_step_required
            or self.manual_recovery_required
            or self.automatic_retry_allowed
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.journal_updated
            or self.public_workflow_state != "unavailable"
        ):
            raise StatePersistenceError("post-later-join health report conflicts")
        for digest in _digest_fields(self):
            validate_digest(digest, "post-later-join health report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "artifacts": {
                "execution": {
                    "digest": self.execution_artifact_digest,
                    "state": self.execution_artifact_state.value,
                },
                "evidence": {
                    "digest": self.evidence_artifact_digest,
                    "record_digest": self.evidence_digest,
                    "state": self.evidence_artifact_state.value,
                },
                "reconciliation": {
                    "digest": self.reconciliation_artifact_digest,
                    "record_digest": self.reconciliation_digest,
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
            "sequence": self.completed_sequence,
            "stage": self.stage,
        }


@dataclass(frozen=True, slots=True)
class _HealthContext:
    join_context: _LaterJoinExecutionContext
    binding: DeployScyllaPostLaterJoinHealthExecutionBinding
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport
    payload: dict[str, object]
    variables: tuple[tuple[str, object], ...]
    current_ids: tuple[str, ...]
    desired_ids: tuple[str, ...]
    future_ids: tuple[str, ...]
    plan_steps: tuple[DeployScyllaBootstrapPlanStep, ...]


@dataclass(frozen=True, slots=True)
class CompletedLaterJoinHealth:
    sequence: int
    execution: StoredDeployScyllaPostLaterJoinHealthExecution
    evidence: StoredDeployScyllaPostLaterJoinHealthEvidence
    reconciliation: StoredDeployScyllaPostLaterJoinHealthReconciliation
    history_digest: str


def execute_deploy_scylla_post_later_join_health(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployScyllaPostLaterJoinHealthReport:
    """Verify the exact current set after the canonically latest later join."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _validate_toolchain_dependency(toolchain)
    executable_identity_digest = _executable_identity_digest(executables)
    toolchain_evidence_digest = _toolchain_evidence_digest(
        toolchain, executable_identity_digest
    )
    sequence = _derive_completed_sequence(paths, operation_id)
    _refuse_ambiguous_artifacts(paths, operation_id)
    builder = AnsibleCommandBuilder(executables.playbook, executables.inventory, paths)
    context = _load_health_context(
        paths,
        operation_id,
        sequence=sequence,
        lock=lock,
        builder=builder,
        toolchain=toolchain,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    execution_store = DeployScyllaPostLaterJoinHealthExecutionStore(
        paths, operation_id, sequence
    )
    evidence_store = DeployScyllaPostLaterJoinHealthEvidenceStore(
        paths, operation_id, sequence
    )
    reconciliation_store = DeployScyllaPostLaterJoinHealthReconciliationStore(
        paths, operation_id, sequence
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
            execution=cast(StoredDeployScyllaPostLaterJoinHealthExecution, execution),
            evidence=cast(StoredDeployScyllaPostLaterJoinHealthEvidence, evidence),
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
                "post-later-join health requires manual recovery and cannot retry"
            )
        reconciliation, state = reconciliation_store.write_locked(
            _build_reconciliation(
                context, execution, evidence, created_at=_timestamp()
            ),
            lock=lock,
        )
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
        raise StateConflictError("post-later-join health toolchain drifted")
    before = _load_health_context(
        paths,
        operation_id,
        sequence=sequence,
        lock=lock,
        builder=builder,
        toolchain=toolchain,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    if before.binding != context.binding:
        raise StateConflictError("post-later-join health state drifted before start")
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
                "post-later-join health command result identity conflicts"
            )
    except KeyboardInterrupt:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployScyllaHealthExecutionState.INTERRUPTED,
            lock=lock,
        )
        raise AnsibleError(
            "post-later-join health was interrupted; manual recovery required"
        ) from None
    except (AnsibleError, StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store, execution, _failure_state(error), lock=lock
        )
        raise AnsibleError(
            "post-later-join health execution is uncertain; manual recovery required"
        ) from error

    try:
        after = _load_health_context(
            paths,
            operation_id,
            sequence=sequence,
            lock=lock,
            builder=builder,
            toolchain=toolchain,
            executable_identity_digest=executable_identity_digest,
            toolchain_evidence_digest=toolchain_evidence_digest,
        )
        if after.binding != context.binding:
            raise StateConflictError(
                "post-later-join health state changed after invocation"
            )
        evidence, evidence_state = evidence_store.write_locked(
            _semantic_evidence(before, result), lock=lock
        )
    except (AnsibleError, StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployScyllaHealthExecutionState.MALFORMED_RESULT,
            lock=lock,
        )
        raise AnsibleError(
            "post-later-join health result is uncertain; manual recovery required"
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
            "post-later-join health preserved incomplete evidence; "
            "manual recovery required and automatic retry is forbidden"
        )
    reconciliation, reconciliation_state = reconciliation_store.write_locked(
        _build_reconciliation(context, execution, evidence, created_at=_timestamp()),
        lock=lock,
    )
    return _report(
        execution=execution,
        evidence=evidence,
        reconciliation=reconciliation,
        execution_state=DeployScyllaHealthArtifactState.CREATED,
        evidence_state=evidence_state,
        reconciliation_state=reconciliation_state,
    )


def load_completed_later_join_health(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
    expected_cluster_uuid: uuid.UUID,
    expected_cluster_name: str,
    maximum_sequence: int | None = None,
) -> CompletedLaterJoinHealth | None:
    """Load and validate the exact contiguous generic health history."""

    _assert_operation_lock(lock, paths)
    sequences = _sequences_for(
        paths,
        operation_id,
        deploy_scylla_post_later_join_health_reconciliation_id_from_filename,
    )
    execution_sequences = _sequences_for(
        paths,
        operation_id,
        deploy_scylla_post_later_join_health_execution_id_from_filename,
    )
    evidence_sequences = _sequences_for(
        paths,
        operation_id,
        deploy_scylla_post_later_join_health_evidence_id_from_filename,
    )
    if maximum_sequence is not None:
        maximum_sequence = _require_sequence(maximum_sequence)
        sequences = tuple(item for item in sequences if item <= maximum_sequence)
        execution_sequences = tuple(
            item for item in execution_sequences if item <= maximum_sequence
        )
        evidence_sequences = tuple(
            item for item in evidence_sequences if item <= maximum_sequence
        )
        if not sequences or sequences[-1] != maximum_sequence:
            raise StateConflictError(
                "required post-later-join health checkpoint is unavailable"
            )
    if execution_sequences != sequences or evidence_sequences != sequences:
        raise StateConflictError(
            "post-later-join health history has an incomplete or ambiguous prefix"
        )
    if not sequences:
        return None
    expected = tuple(range(_MINIMUM_SEQUENCE, sequences[-1] + 1))
    if sequences != expected:
        raise StateConflictError(
            "post-later-join health history is not a contiguous immutable prefix"
        )

    prior_execution: (
        StoredDeployScyllaPostSequenceThreeHealthExecution
        | StoredDeployScyllaPostLaterJoinHealthExecution
    ) = DeployScyllaPostSequenceThreeHealthExecutionStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=expected_cluster_uuid,
        expected_cluster_name=expected_cluster_name,
    )
    prior_evidence: (
        StoredDeployScyllaPostSequenceThreeHealthEvidence
        | StoredDeployScyllaPostLaterJoinHealthEvidence
    ) = DeployScyllaPostSequenceThreeHealthEvidenceStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=expected_cluster_uuid,
        expected_cluster_name=expected_cluster_name,
    )
    prior_reconciliation: (
        StoredDeployScyllaPostSequenceThreeHealthReconciliation
        | StoredDeployScyllaPostLaterJoinHealthReconciliation
    ) = DeployScyllaPostSequenceThreeHealthReconciliationStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=expected_cluster_uuid,
        expected_cluster_name=expected_cluster_name,
    )
    prior_schema = prior_evidence.record.schema_version
    history: list[dict[str, object]] = []
    latest: CompletedLaterJoinHealth | None = None
    for sequence in sequences:
        execution = DeployScyllaPostLaterJoinHealthExecutionStore(
            paths, operation_id, sequence
        ).read_locked(
            lock,
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )
        evidence = DeployScyllaPostLaterJoinHealthEvidenceStore(
            paths, operation_id, sequence
        ).read_locked(
            lock,
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )
        reconciliation = DeployScyllaPostLaterJoinHealthReconciliationStore(
            paths, operation_id, sequence
        ).read_locked(
            lock,
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )
        join_execution = DeployScyllaLaterJoinExecutionStore(
            paths, operation_id, sequence
        ).read_locked(
            lock,
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )
        join_evidence = DeployScyllaLaterJoinEvidenceStore(
            paths, operation_id, sequence
        ).read_locked(
            lock,
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )
        safety_context = DeployScyllaLaterJoinSafetyContextStore(
            paths, operation_id, sequence
        ).read_locked(
            lock,
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )
        safety_evidence = DeployScyllaLaterJoinSafetyEvidenceStore(
            paths, operation_id, sequence
        ).read_locked(
            lock,
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )
        safety_reconciliation = DeployScyllaLaterJoinSafetyReconciliationStore(
            paths, operation_id, sequence
        ).read_locked(
            lock,
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )
        authorization = DeployScyllaLaterJoinAuthorizationStore(
            paths, operation_id, sequence
        ).read_locked(
            lock,
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )
        binding = execution.record.binding
        if (
            execution.record.state is not DeployScyllaHealthExecutionState.SUCCEEDED
            or not execution.record.completed
            or execution.record.manual_recovery_required
            or execution.record.automatic_retry_allowed
            or execution.record.evidence_digest != evidence.record.evidence_digest
            or execution.record.result_digest != evidence.record.result_digest
            or evidence.record.binding != binding
            or not evidence.record.strict_complete
            or reconciliation.record.completed_sequence != sequence
            or reconciliation.record.health_execution_artifact_digest
            != execution.artifact_digest
            or reconciliation.record.health_evidence_artifact_digest
            != evidence.artifact_digest
            or reconciliation.record.health_evidence_digest
            != evidence.record.evidence_digest
            or binding.completed_sequence != sequence
            or binding.prior_health_execution_artifact_digest
            != prior_execution.artifact_digest
            or binding.prior_health_evidence_artifact_digest
            != prior_evidence.artifact_digest
            or binding.prior_health_evidence_digest
            != prior_evidence.record.evidence_digest
            or binding.prior_health_reconciliation_artifact_digest
            != prior_reconciliation.artifact_digest
            or binding.prior_health_reconciliation_digest
            != prior_reconciliation.record.reconciliation_digest
            or binding.prior_health_schema_version != prior_schema
            or binding.later_safety_context_artifact_digest
            != safety_context.artifact_digest
            or binding.later_safety_evidence_artifact_digest
            != safety_evidence.artifact_digest
            or binding.later_safety_reconciliation_artifact_digest
            != safety_reconciliation.artifact_digest
            or binding.later_authorization_artifact_digest
            != authorization.artifact_digest
            or binding.later_join_execution_artifact_digest
            != join_execution.artifact_digest
            or binding.later_join_evidence_artifact_digest
            != join_evidence.artifact_digest
            or join_execution.record.state
            is not DeployScyllaLaterJoinExecutionState.SUCCEEDED
            or not join_execution.record.completed
            or join_execution.record.evidence_digest
            != join_evidence.record.evidence_digest
            or join_evidence.record.sequence != sequence
            or join_evidence.record.status is not ScyllaBootstrapStatus.BOOTSTRAPPED
            or join_evidence.record.mutation_boundary
            is not MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED
            or join_evidence.record.recovery_required
            or join_evidence.record.automatic_retry_allowed
        ):
            raise StateConflictError(
                "post-later-join health history provenance conflicts"
            )
        history.append(
            {
                "evidence_artifact_digest": evidence.artifact_digest,
                "evidence_digest": evidence.record.evidence_digest,
                "execution_artifact_digest": execution.artifact_digest,
                "reconciliation_artifact_digest": reconciliation.artifact_digest,
                "reconciliation_digest": reconciliation.record.reconciliation_digest,
                "sequence": sequence,
            }
        )
        latest = CompletedLaterJoinHealth(
            sequence=sequence,
            execution=execution,
            evidence=evidence,
            reconciliation=reconciliation,
            history_digest=_digest_object(history),
        )
        prior_execution = execution
        prior_evidence = evidence
        prior_reconciliation = reconciliation
        prior_schema = evidence.record.schema_version
    return latest


def deploy_scylla_post_later_join_health_execution_path(
    paths: StatePaths, operation_id: uuid.UUID, sequence: int
) -> Path:
    return _artifact_path(
        paths,
        operation_id,
        sequence,
        DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EXECUTION_FILENAME_SUFFIX,
    )


def deploy_scylla_post_later_join_health_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID, sequence: int
) -> Path:
    return _artifact_path(
        paths,
        operation_id,
        sequence,
        DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EVIDENCE_FILENAME_SUFFIX,
    )


def deploy_scylla_post_later_join_health_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID, sequence: int
) -> Path:
    return _artifact_path(
        paths,
        operation_id,
        sequence,
        DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_RECONCILIATION_FILENAME_SUFFIX,
    )


def deploy_scylla_post_later_join_health_execution_id_from_filename(
    name: str,
) -> tuple[uuid.UUID, int] | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EXECUTION_FILENAME_SUFFIX
    )


def deploy_scylla_post_later_join_health_evidence_id_from_filename(
    name: str,
) -> tuple[uuid.UUID, int] | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EVIDENCE_FILENAME_SUFFIX
    )


def deploy_scylla_post_later_join_health_reconciliation_id_from_filename(
    name: str,
) -> tuple[uuid.UUID, int] | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_RECONCILIATION_FILENAME_SUFFIX
    )


def _derive_completed_sequence(paths: StatePaths, operation_id: uuid.UUID) -> int:
    execution_sequences = _sequences_for(
        paths, operation_id, deploy_scylla_later_join_execution_id_from_filename
    )
    if not execution_sequences:
        raise StateConflictError(
            "post-later-join health requires a completed generic later join"
        )
    expected = tuple(range(_MINIMUM_SEQUENCE, execution_sequences[-1] + 1))
    if execution_sequences != expected:
        raise StateConflictError(
            "generic later-join execution history is not contiguous"
        )
    health_sequences = _sequences_for(
        paths,
        operation_id,
        deploy_scylla_post_later_join_health_reconciliation_id_from_filename,
    )
    allowed = expected[:-1]
    if health_sequences not in {allowed, expected}:
        raise StateConflictError(
            "post-later-join health history conflicts with completed joins"
        )
    return execution_sequences[-1]


def _load_health_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    sequence: int,
    lock: ClusterLock,
    builder: AnsibleCommandBuilder,
    toolchain: AnsibleToolchain,
    executable_identity_digest: str,
    toolchain_evidence_digest: str,
) -> _HealthContext:
    join_context = _load_later_join_execution_context(
        paths,
        operation_id,
        lock=lock,
        builder=builder,
        toolchain=toolchain,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
        expected_sequence=sequence,
    )
    authorized = _load_later_join_authorization_context(
        paths,
        operation_id,
        lock=lock,
        expected_sequence=sequence,
    )
    configure = _load_reconciliation_context(paths, operation_id, lock=lock)
    current = _loaded(configure.authorization_context)
    planning = current.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    inventory = deploy.inventory
    journal = deploy.journal
    join_execution = DeployScyllaLaterJoinExecutionStore(
        paths, operation_id, sequence
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    join_evidence = DeployScyllaLaterJoinEvidenceStore(
        paths, operation_id, sequence
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    _validate_later_join_prefix(join_context, join_execution, join_evidence)
    joined = join_evidence.record
    if (
        join_execution.record.state is not DeployScyllaLaterJoinExecutionState.SUCCEEDED
        or not join_execution.record.completed
        or join_execution.record.invocation_count != 1
        or not join_execution.record.ordinary_authorization_consumed
        or not join_execution.record.narrow_authorization_consumed
        or join_execution.record.manual_recovery_required
        or join_execution.record.automatic_retry_allowed
        or join_execution.record.evidence_digest != joined.evidence_digest
        or join_execution.record.result_digest != joined.result_digest
        or joined.sequence != sequence
        or joined.status is not ScyllaBootstrapStatus.BOOTSTRAPPED
        or joined.host_id_digest is None
        or joined.ring_membership_digest is None
        or not joined.service_active
        or not joined.cql_ready
        or not joined.nodetool_membership_verified
        or not joined.schema_agreement
        or not joined.streaming_complete
        or joined.mutation_boundary
        is not MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED
        or joined.recovery_required
        or joined.automatic_retry_allowed
        or journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
    ):
        raise StateConflictError(
            "post-later-join health requires exact terminal-success join evidence"
        )

    chain = authorized.chain
    plan_steps = chain.plan_steps
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
            "post-later-join health desired topology drifted"
        ) from error
    current_ids = desired_ids[:sequence]
    future_ids = desired_ids[sequence:]
    prior_health = chain.latest_health_evidence.record
    prior_reconciliation = chain.latest_health_reconciliation.record
    prior_host_digests = tuple(node.host_id_digest for node in prior_health.nodes)
    expected_host_digests = (*prior_host_digests, joined.host_id_digest)
    if (
        desired_ids != tuple(dict.fromkeys(desired_ids))
        or current_ids != tuple(sorted(current_ids))
        or len(current_ids) != sequence
        or tuple(node.stable_id for node in prior_health.nodes) != current_ids[:-1]
        or joined.stable_id != current_ids[-1]
        or joined.binding.target_digest != plan_steps[sequence - 1].target_digest
        or any(value is None for value in expected_host_digests)
        or len(set(expected_host_digests)) != sequence
        or prior_reconciliation.health_succeeded_count != sequence - 1
    ):
        raise StateConflictError(
            "post-later-join health current membership prefix conflicts"
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
            "post-later-join health storage, install, or configuration "
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
            raise StateConflictError("post-later-join health plan provenance conflicts")

    readiness = replace(
        join_context.readiness, observation_digest=deploy.observation.digest
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
    ):
        raise StateConflictError(
            "post-later-join health catalog or source policy conflicts"
        )

    prior_execution = chain.latest_health_execution
    prior_evidence = chain.latest_health_evidence
    prior_reconciliation = chain.latest_health_reconciliation
    safety_context = authorized.safety_context
    safety_evidence = authorized.safety_evidence
    safety_reconciliation = authorized.safety_reconciliation
    authorization = join_context.authorization
    trust = planning.base.trust
    expected_host_mapping_digest = _digest_object(
        [
            [_digest_object(current_ids[index]), expected_host_digests[index]]
            for index in range(sequence)
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
            "completed_sequence": sequence,
            "generic_policy_truth": {
                name: status.value for name, status in _EXPECTED_POLICY_STATES.items()
            },
            "ordered_serial_join": True,
            "query_policy": "all-nodes-cross-view",
        }
    )
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
        "bootstrap_context_artifact_digest": (
            chain.base_chain.bootstrap_context_artifact_digest
        ),
        "bootstrap_plan_artifact_digest": (
            chain.base_chain.bootstrap_plan_artifact_digest
        ),
        "bootstrap_plan_digest": chain.base_chain.bootstrap_plan_digest,
        "prior_health_execution_artifact_digest": prior_execution.artifact_digest,
        "prior_health_evidence_artifact_digest": prior_evidence.artifact_digest,
        "prior_health_evidence_digest": prior_evidence.record.evidence_digest,
        "prior_health_reconciliation_artifact_digest": (
            prior_reconciliation.artifact_digest
        ),
        "prior_health_reconciliation_digest": (
            prior_reconciliation.record.reconciliation_digest
        ),
        "prior_health_schema_version": prior_evidence.record.schema_version,
        "later_safety_context_artifact_digest": safety_context.artifact_digest,
        "later_safety_context_digest": safety_context.record.context_digest,
        "later_safety_evidence_artifact_digest": safety_evidence.artifact_digest,
        "later_safety_evidence_digest": safety_evidence.record.evidence_digest,
        "later_safety_reconciliation_artifact_digest": (
            safety_reconciliation.artifact_digest
        ),
        "later_safety_reconciliation_digest": (
            safety_reconciliation.record.reconciliation_digest
        ),
        "later_authorization_artifact_digest": authorization.artifact_digest,
        "later_authorization_digest": authorization.record.authorization_digest,
        "later_join_execution_artifact_digest": join_execution.artifact_digest,
        "later_join_execution_binding_digest": (
            join_execution.record.binding.binding_digest
        ),
        "later_join_evidence_artifact_digest": join_evidence.artifact_digest,
        "later_join_evidence_digest": joined.evidence_digest,
        "observation_generation": deploy.observation.record.generation,
        "observation_artifact_digest": deploy.observation.digest,
        "observation_manifest_digest": deploy.observation.record.manifest_digest,
        "inventory_generation": inventory.record.generation,
        "inventory_artifact_digest": inventory.digest,
        "inventory_digest": inventory.record.inventory_digest,
        "trust_generation": trust.record.generation,
        "trust_artifact_digest": trust.digest,
        "trust_entries_digest": trust.record.entries_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": planning.readiness.record.record_digest,
        "storage_evidence_artifact_digest": (
            chain.base_chain.post_join_health_evidence.record.binding.storage_evidence_artifact_digest
        ),
        "install_evidence_artifact_digest": (
            chain.base_chain.post_join_health_evidence.record.binding.install_evidence_artifact_digest
        ),
        "configure_evidence_artifact_digest": (
            chain.base_chain.post_join_health_evidence.record.binding.configure_evidence_artifact_digest
        ),
        "catalog_digest": current.catalog_digest,
        "source_version": current.source.version,
        "source_digest": current.source.digest,
        "playbook_source_digest": playbook_source_digest,
        "toolchain_version": str(toolchain.core),
        "executable_identity_digest": executable_identity_digest,
        "toolchain_evidence_digest": toolchain_evidence_digest,
        "completed_sequence": sequence,
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
                for index in range(sequence)
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
        join_context=join_context,
        binding=DeployScyllaPostLaterJoinHealthExecutionBinding(
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
) -> DeployScyllaPostLaterJoinHealthEvidence:
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.READ_ONLY
        or not result.check_mode
        or result.scylla_health is not None
    ):
        raise AnsibleResultError("post-later-join health result identity conflicts")
    parsed = parse_scylla_health_execution(
        result.stdout,
        expected_payload=context.payload,
        exit_code=result.exit_code,
    )
    checks = {item.name: item.status for item in parsed.checks}
    nodes: list[DeployScyllaHealthEvidenceNode] = []
    for item in parsed.nodes:
        values: dict[str, object] = {
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
        values["evidence_digest"] = _node_evidence_digest_from_values(values)
        nodes.append(
            DeployScyllaHealthEvidenceNode(**values)  # type: ignore[arg-type]
        )
    node_tuple = tuple(nodes)
    strict_states = tuple((name, checks[name]) for name in _STRICT_CHECKS)
    policy_states = tuple((name, checks[name]) for name in _POLICY_CHECKS)
    expected_host_mapping_digest = _digest_object(
        [[node.stable_id_digest, node.host_id_digest] for node in node_tuple]
    )
    complete = (
        parsed.status is HealthReadiness.UNKNOWN
        and parsed.query_policy == "all-nodes-cross-view"
        and parsed.queried_nodes == context.current_ids
        and tuple(node.stable_id for node in node_tuple) == context.current_ids
        and len(node_tuple) == context.binding.current_member_count
        and expected_host_mapping_digest == context.binding.expected_host_mapping_digest
        and all(
            node.membership_state == "UN"
            and node.host_id_digest is not None
            and node.service_ready
            and node.api_ready
            and node.cql_ready
            and node.storage_ready
            and node.streaming_idle
            and node.version_digest == _digest_object(SCYLLA_PACKAGE_VERSION)
            and node.blocker_count == 0
            for node in node_tuple
        )
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
    values = {
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
        "strict_complete": complete,
        "result_digest": result_digest,
        "evidence_digest": "",
    }
    values["evidence_digest"] = _health_evidence_digest_from_values(values)
    return DeployScyllaPostLaterJoinHealthEvidence(
        **values  # type: ignore[arg-type]
    )


def _build_reconciliation(
    context: _HealthContext,
    execution: StoredDeployScyllaPostLaterJoinHealthExecution,
    evidence: StoredDeployScyllaPostLaterJoinHealthEvidence,
    *,
    created_at: str,
) -> DeployScyllaPostLaterJoinHealthReconciliation:
    sequence = context.binding.completed_sequence
    if (
        execution.record.binding != context.binding
        or execution.record.state is not DeployScyllaHealthExecutionState.SUCCEEDED
        or execution.record.evidence_digest != evidence.record.evidence_digest
        or evidence.record.binding != context.binding
        or not evidence.record.strict_complete
    ):
        raise StateConflictError(
            "post-later-join health reconciliation prefix conflicts"
        )
    steps: list[DeployScyllaPostLaterJoinHealthStep] = []
    next_sequence: int | None = None
    next_status = "not-required"
    next_blockers: tuple[str, ...] = ()
    for original in context.plan_steps:
        if original.sequence <= sequence:
            status = DeployScyllaPostLaterJoinHealthStepStatus.HEALTH_SUCCEEDED
            health_state = "complete-current-cluster-health"
            safety_state = "not-required"
            blockers: tuple[str, ...] = ()
        elif original.sequence == sequence + 1:
            status = DeployScyllaPostLaterJoinHealthStepStatus.WAITING_FOR_SAFETY
            health_state = "complete-current-cluster-health"
            safety_state = "not-created"
            blockers = ("separate-safety-context-not-created",)
            next_sequence = original.sequence
            next_status = status.value
            next_blockers = blockers
        else:
            status = (
                DeployScyllaPostLaterJoinHealthStepStatus.WAITING_FOR_PRECEDING_HEALTH
            )
            health_state = "waiting-for-preceding-complete-health"
            safety_state = "waiting"
            blockers = ("preceding-join-not-completed",)
        values: dict[str, object] = {
            "sequence": original.sequence,
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
            DeployScyllaPostLaterJoinHealthStep(
                **values  # type: ignore[arg-type]
            )
        )
    step_tuple = tuple(steps)
    counts = Counter(step.status for step in step_tuple)
    later = step_tuple[sequence + 1 :]
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
        "completed_sequence": sequence,
        "health_execution_artifact_digest": execution.artifact_digest,
        "health_evidence_artifact_digest": evidence.artifact_digest,
        "health_evidence_digest": evidence.record.evidence_digest,
        "later_join_execution_artifact_digest": (
            context.binding.later_join_execution_artifact_digest
        ),
        "later_join_evidence_artifact_digest": (
            context.binding.later_join_evidence_artifact_digest
        ),
        "later_join_evidence_digest": (context.binding.later_join_evidence_digest),
        "steps": step_tuple,
        "step_count": len(step_tuple),
        "health_succeeded_count": counts[
            DeployScyllaPostLaterJoinHealthStepStatus.HEALTH_SUCCEEDED
        ],
        "waiting_for_safety_count": counts[
            DeployScyllaPostLaterJoinHealthStepStatus.WAITING_FOR_SAFETY
        ],
        "waiting_for_preceding_health_count": counts[
            DeployScyllaPostLaterJoinHealthStepStatus.WAITING_FOR_PRECEDING_HEALTH
        ],
        "current_member_count": len(context.current_ids),
        "current_member_set_digest": _digest_object(list(context.current_ids)),
        "bootstrap_sequence_complete": not context.future_ids,
        "next_step_required": bool(context.future_ids),
        "next_join_sequence": next_sequence,
        "next_join_status": next_status,
        "next_join_blocker_digest": _digest_object(list(next_blockers)),
        "later_join_count": len(later),
        "later_join_set_digest": _digest_object([step.target_digest for step in later]),
        "reconciliation_digest": "",
    }
    values["reconciliation_digest"] = _reconciliation_digest_from_values(values)
    return DeployScyllaPostLaterJoinHealthReconciliation(
        **values  # type: ignore[arg-type]
    )


def _validate_prefix(
    context: _HealthContext,
    execution: StoredDeployScyllaPostLaterJoinHealthExecution | None,
    evidence: StoredDeployScyllaPostLaterJoinHealthEvidence | None,
    reconciliation: StoredDeployScyllaPostLaterJoinHealthReconciliation | None,
) -> None:
    if execution is None:
        if evidence is not None or reconciliation is not None:
            raise StateConflictError(
                "post-later-join health artifacts exist without execution"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError("post-later-join health execution binding drifted")
    if evidence is not None and (
        evidence.record.binding != context.binding
        or execution.record.evidence_digest != evidence.record.evidence_digest
    ):
        raise StateConflictError("post-later-join health evidence binding conflicts")
    if reconciliation is not None:
        if evidence is None:
            raise StateConflictError(
                "post-later-join health reconciliation evidence is unavailable"
            )
        expected = _build_reconciliation(
            context,
            execution,
            evidence,
            created_at=reconciliation.record.created_at,
        )
        if reconciliation.record != expected:
            raise StateConflictError("post-later-join health reconciliation drifted")


def _persist_started(
    store: DeployScyllaPostLaterJoinHealthExecutionStore,
    context: _HealthContext,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaPostLaterJoinHealthExecution:
    now = _timestamp()
    return store.write_locked(
        DeployScyllaPostLaterJoinHealthExecution(
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
    store: DeployScyllaPostLaterJoinHealthExecutionStore,
    current: StoredDeployScyllaPostLaterJoinHealthExecution,
    state: DeployScyllaHealthExecutionState,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaPostLaterJoinHealthExecution:
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
    store: DeployScyllaPostLaterJoinHealthExecutionStore,
    current: StoredDeployScyllaPostLaterJoinHealthExecution,
    *,
    evidence: StoredDeployScyllaPostLaterJoinHealthEvidence,
    result: AnsibleExecutionResult,
    state: DeployScyllaHealthExecutionState,
    lock: ClusterLock,
) -> StoredDeployScyllaPostLaterJoinHealthExecution:
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
    execution: StoredDeployScyllaPostLaterJoinHealthExecution,
    evidence: StoredDeployScyllaPostLaterJoinHealthEvidence,
    reconciliation: StoredDeployScyllaPostLaterJoinHealthReconciliation,
    execution_state: DeployScyllaHealthArtifactState,
    evidence_state: DeployScyllaHealthArtifactState,
    reconciliation_state: DeployScyllaHealthArtifactState,
) -> DeployScyllaPostLaterJoinHealthReport:
    record = evidence.record
    return DeployScyllaPostLaterJoinHealthReport(
        operation_id=record.binding.operation_id,
        completed_sequence=record.binding.completed_sequence,
        execution_state=execution.record.state,
        execution_artifact_state=execution_state,
        evidence_artifact_state=evidence_state,
        reconciliation_artifact_state=reconciliation_state,
        current_member_count=record.binding.current_member_count,
        desired_member_count=record.binding.desired_member_count,
        future_member_count=record.binding.future_member_count,
        host_identity_count=sum(
            node.host_id_digest is not None for node in record.nodes
        ),
        up_normal_count=sum(node.membership_state == "UN" for node in record.nodes),
        service_ready_count=sum(node.service_ready for node in record.nodes),
        api_ready_count=sum(node.api_ready for node in record.nodes),
        cql_ready_count=sum(node.cql_ready for node in record.nodes),
        storage_ready_count=sum(node.storage_ready for node in record.nodes),
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
        later_join_count=reconciliation.record.later_join_count,
        execution_artifact_digest=execution.artifact_digest,
        evidence_artifact_digest=evidence.artifact_digest,
        reconciliation_artifact_digest=reconciliation.artifact_digest,
        evidence_digest=record.evidence_digest,
        reconciliation_digest=reconciliation.record.reconciliation_digest,
        journal_status=record.binding.journal_status,
        journal_phase=record.binding.journal_phase,
    )


def _read_execution(
    store: DeployScyllaPostLaterJoinHealthExecutionStore,
    context: _HealthContext,
    lock: ClusterLock,
) -> StoredDeployScyllaPostLaterJoinHealthExecution | None:
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
    store: DeployScyllaPostLaterJoinHealthEvidenceStore,
    context: _HealthContext,
    lock: ClusterLock,
) -> StoredDeployScyllaPostLaterJoinHealthEvidence | None:
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
    store: DeployScyllaPostLaterJoinHealthReconciliationStore,
    context: _HealthContext,
    lock: ClusterLock,
) -> StoredDeployScyllaPostLaterJoinHealthReconciliation | None:
    return (
        store.read_locked(
            lock,
            expected_cluster_uuid=context.binding.cluster_uuid,
            expected_cluster_name=context.binding.cluster_name,
        )
        if store.path.exists()
        else None
    )


def _binding_digest(record: DeployScyllaPostLaterJoinHealthExecutionBinding) -> str:
    return _binding_digest_from_values(record.to_object())


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for (
        name,
        field,
    ) in DeployScyllaPostLaterJoinHealthExecutionBinding.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["binding_digest"] = ""
    return _digest_object(value)


def _health_evidence_digest(
    record: DeployScyllaPostLaterJoinHealthEvidence,
) -> str:
    return _health_evidence_digest_from_values(record.to_object())


def _health_evidence_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for (
        name,
        field,
    ) in DeployScyllaPostLaterJoinHealthEvidence.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["evidence_digest"] = ""
    return _digest_object(value)


def _step_digest(record: DeployScyllaPostLaterJoinHealthStep) -> str:
    return _step_digest_from_values(record.to_object())


def _step_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    value.setdefault(
        "schema_version",
        ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_STEP_SCHEMA_VERSION,
    )
    value["step_digest"] = ""
    return _digest_object(value)


def _reconciliation_digest(
    record: DeployScyllaPostLaterJoinHealthReconciliation,
) -> str:
    return _reconciliation_digest_from_values(record.to_object())


def _reconciliation_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for (
        name,
        field,
    ) in DeployScyllaPostLaterJoinHealthReconciliation.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["reconciliation_digest"] = ""
    return _digest_object(value)


def _artifact_path(
    paths: StatePaths, operation_id: uuid.UUID, sequence: int, suffix: str
) -> Path:
    _require_canonical_paths(paths)
    path = paths.operations / (
        f"{_require_operation_id(operation_id)}{_FILENAME_STEM}"
        f"{_require_sequence(sequence)}{suffix}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError("post-later-join health path is not canonical")
    return path


def _operation_id_from_filename(name: str, suffix: str) -> tuple[uuid.UUID, int] | None:
    if not name.endswith(suffix) or _FILENAME_STEM not in name:
        return None
    prefix, sequence_value = name[: -len(suffix)].split(_FILENAME_STEM, 1)
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


def _sequences_for(
    paths: StatePaths,
    operation_id: uuid.UUID,
    parser: Callable[[str], tuple[uuid.UUID, int] | None],
) -> tuple[int, ...]:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list sequence-keyed later-join artifacts"
        ) from error
    sequences = []
    for entry in entries:
        parsed = parser(entry.name)
        if parsed is not None and parsed[0] == operation_id:
            validate_state_file(entry)
            sequences.append(parsed[1])
    if len(sequences) != len(set(sequences)):
        raise StateConflictError("duplicate sequence-keyed later-join artifacts")
    return tuple(sorted(sequences))


def _require_identity(
    record_operation_id: uuid.UUID,
    record_cluster_uuid: uuid.UUID,
    record_cluster_name: str,
    record_sequence: int,
    *,
    operation_id: uuid.UUID,
    cluster_uuid: uuid.UUID,
    cluster_name: str,
    sequence: int,
) -> None:
    if (
        record_operation_id != operation_id
        or record_cluster_uuid != cluster_uuid
        or record_cluster_name != cluster_name
        or record_sequence != sequence
    ):
        raise StatePersistenceError("post-later-join health identity conflicts")


def _require_sequence(sequence: int) -> int:
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < _MINIMUM_SEQUENCE
    ):
        raise StatePersistenceError("post-later-join health sequence is not canonical")
    return sequence


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "post-later-join health requires the matching held deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError("post-later-join health paths are not canonical")


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    suffixes = (
        DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EVIDENCE_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_RECONCILIATION_FILENAME_SUFFIX,
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list post-later-join health artifacts"
        ) from error
    for entry in entries:
        for suffix in suffixes:
            if not entry.name.endswith(suffix):
                continue
            parsed = _operation_id_from_filename(entry.name, suffix)
            if (
                parsed is None
                and entry.name.startswith(str(operation_id))
                and _FILENAME_STEM in entry.name
            ):
                validate_state_file(entry)
                raise StateConflictError(
                    "post-later-join health artifacts are ambiguous"
                )


__all__ = [
    "ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EXECUTION_BINDING_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_EXECUTION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_RECONCILIATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_POST_LATER_JOIN_HEALTH_STEP_SCHEMA_VERSION",
    "CompletedLaterJoinHealth",
    "DeployScyllaPostLaterJoinHealthEvidence",
    "DeployScyllaPostLaterJoinHealthEvidenceStore",
    "DeployScyllaPostLaterJoinHealthExecution",
    "DeployScyllaPostLaterJoinHealthExecutionBinding",
    "DeployScyllaPostLaterJoinHealthExecutionStore",
    "DeployScyllaPostLaterJoinHealthReconciliation",
    "DeployScyllaPostLaterJoinHealthReconciliationStore",
    "DeployScyllaPostLaterJoinHealthReport",
    "DeployScyllaPostLaterJoinHealthStep",
    "DeployScyllaPostLaterJoinHealthStepStatus",
    "StoredDeployScyllaPostLaterJoinHealthEvidence",
    "StoredDeployScyllaPostLaterJoinHealthExecution",
    "StoredDeployScyllaPostLaterJoinHealthReconciliation",
    "deploy_scylla_post_later_join_health_evidence_id_from_filename",
    "deploy_scylla_post_later_join_health_evidence_path",
    "deploy_scylla_post_later_join_health_execution_id_from_filename",
    "deploy_scylla_post_later_join_health_execution_path",
    "deploy_scylla_post_later_join_health_reconciliation_id_from_filename",
    "deploy_scylla_post_later_join_health_reconciliation_path",
    "execute_deploy_scylla_post_later_join_health",
    "load_completed_later_join_health",
]
