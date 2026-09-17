"""Fresh complete-cluster health after the first deploy join.

This internal owner revalidates the complete sequence-two join chain, executes
only the reviewed read-only ``scylla-health`` source against the exact current
member prefix, and persists immutable address-free health evidence plus an
ordered bootstrap reconciliation.  It never infers health from bootstrap
success, authorizes another join, or changes the common journal.
"""

from __future__ import annotations

import os
import uuid
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.commands import AnsibleCommandBuilder
from scylla_vms.ansible.deploy_plan import (
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
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
    DeployScyllaHealthStepStatus,
    _node_evidence_digest_from_values,
)
from scylla_vms.ansible.deploy_scylla_join_authorization import (
    _JoinAuthorizationLoaded,
    _load_join_authorization_context,
)
from scylla_vms.ansible.deploy_scylla_join_execution import (
    ANSIBLE_DEPLOY_SCYLLA_JOIN_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_SCHEMA_VERSION,
    DeployScyllaJoinEvidenceStore,
    DeployScyllaJoinExecutionState,
    DeployScyllaJoinExecutionStore,
    StoredDeployScyllaJoinEvidence,
    StoredDeployScyllaJoinExecution,
)
from scylla_vms.ansible.deploy_scylla_join_execution import (
    _ExecutionContext as _JoinExecutionContext,
)
from scylla_vms.ansible.deploy_scylla_join_execution import (
    _load_execution_context as _load_join_execution_context,
)
from scylla_vms.ansible.deploy_scylla_join_execution import (
    _validate_prefix as _validate_join_prefix,
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
from scylla_vms.ansible.toolchain import (
    AnsibleToolchain,
    AnsibleVersionError,
    parse_ansible_core_version,
)
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
    format_timestamp,
    parse_timestamp,
    parse_uuid,
    require_exact_keys,
    require_string,
    validate_digest,
)
from scylla_vms.process import ProcessOutputError, ProcessTimeoutError
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

ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-health-execution-binding/v1"
)
ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-health-execution/v1"
)
ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-health-evidence/v1"
)
ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_STEP_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-health-step/v1"
)
ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-health-reconciliation/v1"
)
ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-health-report/v1"
)

DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-join-health-execution.json"
)
DEPLOY_SCYLLA_JOIN_HEALTH_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-join-health-evidence.json"
)
DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-join-health-reconciliation.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "scylla-health"
_STAGE = "post-first-join-complete-cluster-health"
_TIMEOUT_SECONDS = 60
_CURRENT_MEMBER_COUNT = 2
_STRICT_CHECKS = (
    "cross-view-consistency",
    "membership",
    "schema-agreement",
    "streaming",
    "topology",
)
_POLICY_CHECKS = ("backup-policy", "capacity", "quorum", "replication")
_NEXT_JOIN_GATES = (
    "backup-policy",
    "capacity",
    "completed-prior-membership",
    "configuration-provenance",
    "cross-view-consistency",
    "membership",
    "quorum",
    "replication",
    "schema",
    "seed-health",
    "service-api-cql",
    "storage-provenance",
    "streaming",
    "survivor-health",
    "target-absence",
    "topology",
)


@dataclass(frozen=True, slots=True)
class DeployScyllaPostJoinHealthExecutionBinding:
    """Digest-only binding for the fresh post-sequence-two health call."""

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
    bootstrap_context_record_digest: str
    bootstrap_plan_artifact_digest: str
    bootstrap_plan_digest: str
    initial_execution_artifact_digest: str
    initial_evidence_artifact_digest: str
    initial_evidence_digest: str
    pre_join_health_execution_artifact_digest: str
    pre_join_health_evidence_artifact_digest: str
    pre_join_health_evidence_digest: str
    pre_join_health_checkpoint_artifact_digest: str
    pre_join_health_checkpoint_digest: str
    join_safety_context_artifact_digest: str
    join_safety_context_digest: str
    join_safety_evidence_artifact_digest: str
    join_safety_evidence_digest: str
    join_safety_reconciliation_artifact_digest: str
    join_safety_reconciliation_digest: str
    join_authorization_artifact_digest: str
    join_authorization_digest: str
    join_execution_artifact_digest: str
    join_execution_binding_digest: str
    join_evidence_artifact_digest: str
    join_evidence_digest: str
    post_configure_artifact_digest: str
    post_configure_record_digest: str
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
    join_execution_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_SCHEMA_VERSION
    )
    join_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_EVIDENCE_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_BINDING_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_BINDING_SCHEMA_VERSION
            or self.join_execution_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_SCHEMA_VERSION
            or self.join_evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_EVIDENCE_SCHEMA_VERSION
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
                "deploy Scylla post-join health binding conflicts"
            )
        validate_cluster_name(self.cluster_name)
        for generation in (
            self.journal_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
        ):
            _positive_integer(generation, "post-join health generation")
        for digest in _digest_fields(self):
            validate_digest(digest, "post-join health binding digest")
        _validate_toolchain_version(self.toolchain_version)

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaPostJoinHealthExecutionBinding:
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
            label="post-join health binding",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaPostJoinHealthExecution:
    generation: int
    created_at: str
    updated_at: str
    binding: DeployScyllaPostJoinHealthExecutionBinding
    state: DeployScyllaHealthExecutionState
    invocation_count: int
    completed: bool
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    exit_code: int | None
    result_digest: str | None
    evidence_digest: str | None
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        terminal = self.state in {
            DeployScyllaHealthExecutionState.SUCCEEDED,
            DeployScyllaHealthExecutionState.FAILED,
        }
        success = self.state is DeployScyllaHealthExecutionState.SUCCEEDED
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_SCHEMA_VERSION
            or self.generation not in {1, 2}
            or self.invocation_count != 1
            or self.completed != terminal
            or self.manual_recovery_required != (not success and self.generation == 2)
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
                "deploy Scylla post-join health execution conflicts"
            )
        for digest in (self.result_digest, self.evidence_digest):
            if digest is not None:
                validate_digest(digest, "post-join health execution digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, nested_fields={"binding"})

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaPostJoinHealthExecution:
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
            label="post-join health execution",
        )
        parsed["binding"] = DeployScyllaPostJoinHealthExecutionBinding.from_object(
            _mapping(value["binding"], "post-join health binding")
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaPostJoinHealthEvidence:
    generation: int
    created_at: str
    binding: DeployScyllaPostJoinHealthExecutionBinding
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
    next_join_gate_states: tuple[tuple[str, HealthCheckStatus], ...]
    blocker_count: int
    blocker_digest: str
    strict_complete: bool
    result_digest: str
    evidence_digest: str
    result_schema_version: str = SCYLLA_HEALTH_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EVIDENCE_SCHEMA_VERSION
            or self.result_schema_version != SCYLLA_HEALTH_SCHEMA_VERSION
            or self.generation != 1
            or self.query_policy != "all-nodes-cross-view"
            or tuple(node.stable_id for node in self.nodes)
            != tuple(sorted({node.stable_id for node in self.nodes}))
            or tuple(name for name, _ in self.check_states) != _STRICT_CHECKS
            or tuple(name for name, _ in self.policy_states) != _POLICY_CHECKS
            or tuple(name for name, _ in self.next_join_gate_states) != _NEXT_JOIN_GATES
            or self.blocker_count < 0
            or self.evidence_digest != _health_evidence_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla post-join health evidence conflicts"
            )
        parse_timestamp(self.created_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "post-join health evidence digest")

    def to_object(self) -> dict[str, object]:
        return {
            **_dataclass_object(
                self,
                nested_fields={"binding"},
                skip_fields={
                    "nodes",
                    "check_states",
                    "policy_states",
                    "next_join_gate_states",
                },
            ),
            "nodes": [node.to_object() for node in self.nodes],
            "check_states": [
                [name, status.value] for name, status in self.check_states
            ],
            "policy_states": [
                [name, status.value] for name, status in self.policy_states
            ],
            "next_join_gate_states": [
                [name, status.value] for name, status in self.next_join_gate_states
            ],
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaPostJoinHealthEvidence:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={"generation", "blocker_count"},
            boolean_fields={"schema_agreement", "strict_complete"},
            enum_fields={"health_status": HealthReadiness},
            optional_string_fields={"topology_digest", "schema_digest"},
            skip_fields={
                "binding",
                "nodes",
                "check_states",
                "policy_states",
                "next_join_gate_states",
            },
            label="post-join health evidence",
        )
        parsed["binding"] = DeployScyllaPostJoinHealthExecutionBinding.from_object(
            _mapping(value["binding"], "post-join health binding")
        )
        parsed["nodes"] = tuple(
            DeployScyllaHealthEvidenceNode.from_object(
                _mapping(item, "post-join health node")
            )
            for item in _array(value["nodes"], "post-join health nodes")
        )
        parsed["check_states"] = _status_pairs(value["check_states"], "check states")
        parsed["policy_states"] = _status_pairs(value["policy_states"], "policy states")
        parsed["next_join_gate_states"] = _status_pairs(
            value["next_join_gate_states"], "next join gate states"
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaPostJoinHealthStep:
    sequence: int
    mode: ScyllaBootstrapMode
    target_digest: str
    plan_step_digest: str
    status: DeployScyllaHealthStepStatus
    health_checkpoint_state: str
    authorization_state: str
    blockers: tuple[str, ...]
    blocker_digest: str
    step_digest: str
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_STEP_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_STEP_SCHEMA_VERSION
            or self.sequence < 1
            or tuple(sorted(set(self.blockers))) != self.blockers
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.step_digest != _step_digest(self)
        ):
            raise StatePersistenceError("deploy Scylla post-join health step conflicts")
        for digest in _digest_fields(self):
            validate_digest(digest, "post-join health step digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, tuple_fields={"blockers"})

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaPostJoinHealthStep:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={"sequence"},
            tuple_fields={"blockers"},
            enum_fields={
                "mode": ScyllaBootstrapMode,
                "status": DeployScyllaHealthStepStatus,
            },
            label="post-join health step",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaPostJoinHealthReconciliation:
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
    join_execution_artifact_digest: str
    join_evidence_artifact_digest: str
    join_evidence_digest: str
    steps: tuple[DeployScyllaPostJoinHealthStep, ...]
    step_count: int
    health_succeeded_count: int
    authorization_required_count: int
    blocked_count: int
    waiting_count: int
    current_member_count: int
    current_member_set_digest: str
    next_join_sequence: int | None
    next_join_status: str
    next_join_blocker_digest: str
    later_join_count: int
    later_join_set_digest: str
    reconciliation_digest: str
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        statuses = Counter(step.status for step in self.steps)
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_SCHEMA_VERSION
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
            != statuses[DeployScyllaHealthStepStatus.HEALTH_SUCCEEDED]
            or self.authorization_required_count
            != statuses[DeployScyllaHealthStepStatus.AUTHORIZATION_REQUIRED]
            or self.blocked_count != statuses[DeployScyllaHealthStepStatus.BLOCKED]
            or self.waiting_count != statuses[DeployScyllaHealthStepStatus.WAITING]
            or self.health_succeeded_count != self.current_member_count
            or self.current_member_count != _CURRENT_MEMBER_COUNT
            or self.authorization_required_count > 1
            or self.later_join_count
            != max(0, self.step_count - self.current_member_count - 1)
            or self.reconciliation_digest != _reconciliation_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla post-join health reconciliation conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "post-join health reconciliation digest")

    def to_object(self) -> dict[str, object]:
        return {
            **_dataclass_object(self, skip_fields={"steps"}),
            "steps": [step.to_object() for step in self.steps],
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaPostJoinHealthReconciliation:
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
                "later_join_count",
            },
            uuid_fields={"cluster_uuid", "operation_id"},
            enum_fields={
                "journal_status": JournalStatus,
                "journal_phase": OperationPhase,
            },
            optional_integer_fields={"next_join_sequence"},
            skip_fields={"steps"},
            label="post-join health reconciliation",
        )
        parsed["steps"] = tuple(
            DeployScyllaPostJoinHealthStep.from_object(
                _mapping(item, "post-join health step")
            )
            for item in _array(value["steps"], "post-join health steps")
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaPostJoinHealthExecution:
    record: DeployScyllaPostJoinHealthExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaPostJoinHealthEvidence:
    record: DeployScyllaPostJoinHealthEvidence
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaPostJoinHealthReconciliation:
    record: DeployScyllaPostJoinHealthReconciliation
    artifact_digest: str


class DeployScyllaPostJoinHealthExecutionStore:
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
        self._path = deploy_scylla_post_join_health_execution_path(paths, operation_id)
        self._file = AtomicJsonFile(self._path, replace=replace_file)

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaPostJoinHealthExecution:
        value, digest = self._file.read()
        record = DeployScyllaPostJoinHealthExecution.from_object(value)
        _require_identity(
            record.binding.operation_id,
            record.binding.cluster_uuid,
            record.binding.cluster_name,
            operation_id=self._operation_id,
            cluster_uuid=expected_cluster_uuid,
            cluster_name=expected_cluster_name,
        )
        return StoredDeployScyllaPostJoinHealthExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaPostJoinHealthExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaPostJoinHealthExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployScyllaPostJoinHealthExecution:
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
                    "deploy Scylla post-join health execution transition conflicts"
                )
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
            or record.state is not DeployScyllaHealthExecutionState.STARTED
        ):
            raise StateConflictError(
                "deploy Scylla post-join health initial execution conflicts"
            )
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployScyllaPostJoinHealthExecution(record, digest)


class DeployScyllaPostJoinHealthEvidenceStore:
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
        self._path = deploy_scylla_post_join_health_evidence_path(paths, operation_id)
        self._file = AtomicJsonFile(self._path, replace=replace_file)

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaPostJoinHealthEvidence:
        value, digest = self._file.read()
        record = DeployScyllaPostJoinHealthEvidence.from_object(value)
        _require_identity(
            record.binding.operation_id,
            record.binding.cluster_uuid,
            record.binding.cluster_name,
            operation_id=self._operation_id,
            cluster_uuid=expected_cluster_uuid,
            cluster_name=expected_cluster_name,
        )
        return StoredDeployScyllaPostJoinHealthEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaPostJoinHealthEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaPostJoinHealthEvidence,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployScyllaPostJoinHealthEvidence, DeployScyllaHealthArtifactState
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
                    "deploy Scylla post-join health evidence is immutable"
                )
            return current, DeployScyllaHealthArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaPostJoinHealthEvidence(record, digest),
            DeployScyllaHealthArtifactState.CREATED,
        )


class DeployScyllaPostJoinHealthReconciliationStore:
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
        self._path = deploy_scylla_post_join_health_reconciliation_path(
            paths, operation_id
        )
        self._file = AtomicJsonFile(self._path, replace=replace_file)

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaPostJoinHealthReconciliation:
        value, digest = self._file.read()
        record = DeployScyllaPostJoinHealthReconciliation.from_object(value)
        _require_identity(
            record.operation_id,
            record.cluster_uuid,
            record.cluster_name,
            operation_id=self._operation_id,
            cluster_uuid=expected_cluster_uuid,
            cluster_name=expected_cluster_name,
        )
        return StoredDeployScyllaPostJoinHealthReconciliation(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaPostJoinHealthReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaPostJoinHealthReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployScyllaPostJoinHealthReconciliation,
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
                    "deploy Scylla post-join health reconciliation is immutable"
                )
            return current, DeployScyllaHealthArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaPostJoinHealthReconciliation(record, digest),
            DeployScyllaHealthArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaPostJoinHealthReport:
    operation_id: uuid.UUID
    stage: str
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
    completed_prior_membership_count: int
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
    journal_updated: bool = False
    public_workflow_state: str = "unavailable"
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EVIDENCE_SCHEMA_VERSION
    )
    reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_REPORT_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EVIDENCE_SCHEMA_VERSION
            or self.reconciliation_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_SCHEMA_VERSION
            or self.execution_state is not DeployScyllaHealthExecutionState.SUCCEEDED
            or self.stage != _STAGE
            or self.current_member_count != _CURRENT_MEMBER_COUNT
            or self.completed_prior_membership_count != _CURRENT_MEMBER_COUNT
            or not self.health_complete
            or self.manual_recovery_required
            or self.automatic_retry_allowed
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.journal_updated
            or self.public_workflow_state != "unavailable"
        ):
            raise StatePersistenceError(
                "deploy Scylla post-join health report conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "post-join health report digest")

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
            "health": {
                "api_ready_count": self.api_ready_count,
                "complete": self.health_complete,
                "cql_ready_count": self.cql_ready_count,
                "host_identity_count": self.host_identity_count,
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
                "completed_prior_count": self.completed_prior_membership_count,
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
class _PostJoinHealthContext:
    authorized: _JoinAuthorizationLoaded
    join_context: _JoinExecutionContext
    join_execution: StoredDeployScyllaJoinExecution
    join_evidence: StoredDeployScyllaJoinEvidence
    binding: DeployScyllaPostJoinHealthExecutionBinding
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport
    payload: dict[str, object]
    variables: tuple[tuple[str, object], ...]
    current_ids: tuple[str, ...]
    desired_ids: tuple[str, ...]
    future_ids: tuple[str, ...]


def execute_deploy_scylla_post_join_health(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployScyllaPostJoinHealthReport:
    """Verify exact post-first-join health and reconcile only the next step."""

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
    execution_store = DeployScyllaPostJoinHealthExecutionStore(paths, operation_id)
    evidence_store = DeployScyllaPostJoinHealthEvidenceStore(paths, operation_id)
    reconciliation_store = DeployScyllaPostJoinHealthReconciliationStore(
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
            execution=cast(StoredDeployScyllaPostJoinHealthExecution, execution),
            evidence=cast(StoredDeployScyllaPostJoinHealthEvidence, evidence),
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
                "deploy Scylla post-join health execution requires manual "
                "recovery and cannot retry"
            )
        record = _build_reconciliation(
            context,
            execution,
            evidence,
            created_at=_timestamp(),
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
        raise StateConflictError("deploy Scylla post-join health toolchain drifted")
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
            "deploy Scylla post-join health state drifted before start"
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
                "deploy Scylla post-join health command result identity conflicts"
            )
    except KeyboardInterrupt:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployScyllaHealthExecutionState.INTERRUPTED,
            lock=lock,
        )
        raise AnsibleError(
            "deploy Scylla post-join health was interrupted; manual recovery required"
        ) from None
    except (AnsibleError, StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            _failure_state(error),
            lock=lock,
        )
        raise AnsibleError(
            "deploy Scylla post-join health execution is uncertain; "
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
                "deploy Scylla post-join health state changed after invocation"
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
            "deploy Scylla post-join health result is uncertain; "
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
            "deploy Scylla post-join health preserved incomplete evidence; "
            "manual recovery required and automatic retry is forbidden"
        )
    reconciliation_record = _build_reconciliation(
        context,
        execution,
        evidence,
        created_at=_timestamp(),
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


def deploy_scylla_post_join_health_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths, operation_id, DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_FILENAME_SUFFIX
    )


def deploy_scylla_post_join_health_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths, operation_id, DEPLOY_SCYLLA_JOIN_HEALTH_EVIDENCE_FILENAME_SUFFIX
    )


def deploy_scylla_post_join_health_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths, operation_id, DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_FILENAME_SUFFIX
    )


def deploy_scylla_post_join_health_execution_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_FILENAME_SUFFIX
    )


def deploy_scylla_post_join_health_evidence_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_JOIN_HEALTH_EVIDENCE_FILENAME_SUFFIX
    )


def deploy_scylla_post_join_health_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_FILENAME_SUFFIX
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
) -> _PostJoinHealthContext:
    join_context = _load_join_execution_context(
        paths,
        operation_id,
        lock=lock,
        builder=builder,
        toolchain=toolchain,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    authorized = _load_join_authorization_context(paths, operation_id, lock=lock)
    configure = _load_reconciliation_context(paths, operation_id, lock=lock)
    loaded = _loaded(configure.authorization_context)
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    inventory = deploy.inventory
    journal = deploy.journal
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
    _validate_join_prefix(join_context, join_execution, join_evidence)
    join_record = join_execution.record
    joined = join_evidence.record
    if (
        join_record.state is not DeployScyllaJoinExecutionState.SUCCEEDED
        or not join_record.completed
        or join_record.invocation_count != 1
        or not join_record.ordinary_authorization_consumed
        or not join_record.narrow_authorization_consumed
        or join_record.manual_recovery_required
        or join_record.automatic_retry_allowed
        or join_record.evidence_digest != joined.evidence_digest
        or join_record.result_digest != joined.result_digest
        or joined.status is not ScyllaBootstrapStatus.BOOTSTRAPPED
        or joined.sequence != 2
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
            "deploy Scylla post-join health requires exact terminal-success "
            "first-join execution and evidence"
        )
    if (
        join_context.authorization.artifact_digest
        != join_context.binding.authorization_artifact_digest
    ):
        raise StateConflictError(
            "deploy Scylla post-join health authorization provenance conflicts"
        )
    if (
        journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
        or journal.digest != join_context.binding.journal_digest
        or journal.record.generation != join_context.binding.journal_generation
    ):
        raise StateConflictError(
            "deploy Scylla post-join health journal checkpoint conflicts"
        )

    plan = authorized.chain.bootstrap_plan.record
    if len(plan.steps) < _CURRENT_MEMBER_COUNT:
        raise StateConflictError(
            "deploy Scylla post-join health requires sequence-two bootstrap"
        )
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
            "deploy Scylla post-join health desired topology drifted"
        ) from error
    current_ids = desired_ids[:_CURRENT_MEMBER_COUNT]
    future_ids = desired_ids[_CURRENT_MEMBER_COUNT:]
    initial_entry = authorized.chain.bootstrap_evidence.record.entry
    expected_host_digests = (initial_entry.host_id_digest, joined.host_id_digest)
    if (
        desired_ids != tuple(dict.fromkeys(desired_ids))
        or current_ids != tuple(sorted(current_ids))
        or len(current_ids) != _CURRENT_MEMBER_COUNT
        or joined.stable_id != current_ids[1]
        or joined.binding.target_digest != plan.steps[1].target_digest
        or initial_entry.stable_id != current_ids[0]
        or initial_entry.host_id_digest is None
        or len(set(expected_host_digests)) != _CURRENT_MEMBER_COUNT
    ):
        raise StateConflictError(
            "deploy Scylla post-join health current membership prefix conflicts"
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
            "deploy Scylla post-join health storage, install, or "
            "configuration provenance conflicts"
        )
    for index, stable_id in enumerate(current_ids):
        step = plan.steps[index]
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
                "deploy Scylla post-join health plan provenance conflicts"
            )

    readiness = replace(
        join_context.readiness,
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
    playbook_source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
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
            "deploy Scylla post-join health catalog or source policy conflicts"
        )
    base = authorized.chain.bootstrap_context.record
    pre_health = authorized.chain.health_evidence.record
    trust = planning.base.trust
    expected_host_mapping_digest = _digest_object(
        [
            [plan.steps[index].target_digest, expected_host_digests[index]]
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
            "next_join_gates": list(_NEXT_JOIN_GATES),
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
            authorized.chain.bootstrap_context.artifact_digest
        ),
        "bootstrap_context_record_digest": base.record_digest,
        "bootstrap_plan_artifact_digest": (
            authorized.chain.bootstrap_plan.artifact_digest
        ),
        "bootstrap_plan_digest": plan.plan_digest,
        "initial_execution_artifact_digest": (
            authorized.chain.bootstrap_execution.artifact_digest
        ),
        "initial_evidence_artifact_digest": (
            authorized.chain.bootstrap_evidence.artifact_digest
        ),
        "initial_evidence_digest": initial_entry.evidence_digest,
        "pre_join_health_execution_artifact_digest": (
            authorized.chain.health_execution.artifact_digest
        ),
        "pre_join_health_evidence_artifact_digest": (
            authorized.chain.health_evidence.artifact_digest
        ),
        "pre_join_health_evidence_digest": pre_health.evidence_digest,
        "pre_join_health_checkpoint_artifact_digest": (
            authorized.chain.health_checkpoint.artifact_digest
        ),
        "pre_join_health_checkpoint_digest": (
            authorized.chain.health_checkpoint.record.checkpoint_digest
        ),
        "join_safety_context_artifact_digest": (
            authorized.safety_context.artifact_digest
        ),
        "join_safety_context_digest": authorized.safety_context.record.context_digest,
        "join_safety_evidence_artifact_digest": (
            authorized.safety_evidence.artifact_digest
        ),
        "join_safety_evidence_digest": (
            authorized.safety_evidence.record.evidence_digest
        ),
        "join_safety_reconciliation_artifact_digest": (
            authorized.safety_reconciliation.artifact_digest
        ),
        "join_safety_reconciliation_digest": (
            authorized.safety_reconciliation.record.reconciliation_digest
        ),
        "join_authorization_artifact_digest": (
            join_context.authorization.artifact_digest
        ),
        "join_authorization_digest": (
            join_context.authorization.record.authorization_digest
        ),
        "join_execution_artifact_digest": join_execution.artifact_digest,
        "join_execution_binding_digest": join_record.binding.binding_digest,
        "join_evidence_artifact_digest": join_evidence.artifact_digest,
        "join_evidence_digest": joined.evidence_digest,
        "post_configure_artifact_digest": base.post_configure_artifact_digest,
        "post_configure_record_digest": base.post_configure_record_digest,
        "terraform_verification_artifact_digest": (
            base.terraform_verification_artifact_digest
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
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": planning.readiness.record.record_digest,
        "storage_evidence_artifact_digest": base.storage_evidence_artifact_digest,
        "install_evidence_artifact_digest": base.install_evidence_artifact_digest,
        "configure_evidence_artifact_digest": base.configure_evidence_artifact_digest,
        "catalog_digest": loaded.catalog_digest,
        "source_version": loaded.source.version,
        "source_digest": loaded.source.digest,
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
                    "datacenter_digest": plan.steps[index].datacenter_digest,
                    "rack_digest": plan.steps[index].rack_digest,
                    "target_digest": plan.steps[index].target_digest,
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
    return _PostJoinHealthContext(
        authorized=authorized,
        join_context=join_context,
        join_execution=join_execution,
        join_evidence=join_evidence,
        binding=DeployScyllaPostJoinHealthExecutionBinding(
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
    )


def _semantic_evidence(
    context: _PostJoinHealthContext,
    result: AnsibleExecutionResult,
) -> DeployScyllaPostJoinHealthEvidence:
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.READ_ONLY
        or not result.check_mode
        or result.scylla_health is not None
    ):
        raise AnsibleResultError(
            "deploy Scylla post-join health result identity conflicts"
        )
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
        nodes.append(DeployScyllaHealthEvidenceNode(**values))  # type: ignore[arg-type]
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
    target_absence = (
        HealthCheckStatus.PASSED
        if context.future_ids
        and checks["cross-view-consistency"] is HealthCheckStatus.PASSED
        and checks["membership"] is HealthCheckStatus.PASSED
        and not set(context.future_ids) & {node.stable_id for node in node_tuple}
        else HealthCheckStatus.NOT_PERFORMED
        if not context.future_ids
        else HealthCheckStatus.FAILED
    )
    policy = dict(policy_states)
    gate_values = {
        "backup-policy": policy["backup-policy"],
        "capacity": policy["capacity"],
        "completed-prior-membership": (
            HealthCheckStatus.PASSED
            if context.join_execution.record.state
            is DeployScyllaJoinExecutionState.SUCCEEDED
            and context.join_evidence.record.status
            is ScyllaBootstrapStatus.BOOTSTRAPPED
            else HealthCheckStatus.FAILED
        ),
        "configuration-provenance": HealthCheckStatus.PASSED,
        "cross-view-consistency": checks["cross-view-consistency"],
        "membership": checks["membership"],
        "quorum": policy["quorum"],
        "replication": policy["replication"],
        "schema": checks["schema-agreement"],
        "seed-health": (
            HealthCheckStatus.PASSED
            if node_health_complete
            and node_tuple[0].stable_id == context.current_ids[0]
            else HealthCheckStatus.FAILED
        ),
        "service-api-cql": (
            HealthCheckStatus.PASSED
            if node_health_complete
            else HealthCheckStatus.FAILED
        ),
        "storage-provenance": (
            HealthCheckStatus.PASSED
            if all(node.storage_ready for node in node_tuple)
            else HealthCheckStatus.FAILED
        ),
        "streaming": checks["streaming"],
        "survivor-health": (
            HealthCheckStatus.PASSED
            if node_health_complete
            else HealthCheckStatus.FAILED
        ),
        "target-absence": target_absence,
        "topology": checks["topology"],
    }
    next_join_gate_states = tuple(
        (name, gate_values[name]) for name in _NEXT_JOIN_GATES
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
        and dict(policy_states)
        == {
            "backup-policy": HealthCheckStatus.NOT_PERFORMED,
            "capacity": HealthCheckStatus.UNKNOWN,
            "quorum": HealthCheckStatus.UNKNOWN,
            "replication": HealthCheckStatus.NOT_PERFORMED,
        }
        and not parsed.blockers
    )
    result_digest = _digest_object(
        {
            "blocker_digest": _digest_object(list(parsed.blockers)),
            "check_states": [[name, state.value] for name, state in strict_states],
            "host_id_mapping_digest": expected_host_mapping_digest,
            "next_join_gate_states": [
                [name, state.value] for name, state in next_join_gate_states
            ],
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
        "next_join_gate_states": next_join_gate_states,
        "blocker_count": len(parsed.blockers),
        "blocker_digest": _digest_object(list(parsed.blockers)),
        "strict_complete": strict_complete,
        "result_digest": result_digest,
        "evidence_digest": "",
    }
    values["evidence_digest"] = _health_evidence_digest_from_values(values)
    return DeployScyllaPostJoinHealthEvidence(**values)  # type: ignore[arg-type]


def _build_reconciliation(
    context: _PostJoinHealthContext,
    execution: StoredDeployScyllaPostJoinHealthExecution,
    evidence: StoredDeployScyllaPostJoinHealthEvidence,
    *,
    created_at: str,
) -> DeployScyllaPostJoinHealthReconciliation:
    if (
        execution.record.binding != context.binding
        or execution.record.state is not DeployScyllaHealthExecutionState.SUCCEEDED
        or execution.record.evidence_digest != evidence.record.evidence_digest
        or evidence.record.binding != context.binding
        or not evidence.record.strict_complete
    ):
        raise StateConflictError(
            "deploy Scylla post-join health reconciliation prefix conflicts"
        )
    plan = context.authorized.chain.bootstrap_plan.record
    gate_blockers = tuple(
        sorted(
            f"{name}-{_status_blocker_suffix(status)}"
            for name, status in evidence.record.next_join_gate_states
            if status is not HealthCheckStatus.PASSED
        )
    )
    steps: list[DeployScyllaPostJoinHealthStep] = []
    next_join_sequence: int | None = None
    next_join_status = "not-required"
    next_join_blockers: tuple[str, ...] = ()
    for original in plan.steps:
        if original.sequence <= _CURRENT_MEMBER_COUNT:
            status = DeployScyllaHealthStepStatus.HEALTH_SUCCEEDED
            health_state = "complete-current-cluster-health"
            authorization_state = "not-required"
            blockers: tuple[str, ...] = ()
        elif original.sequence == _CURRENT_MEMBER_COUNT + 1:
            next_join_sequence = original.sequence
            health_state = "complete-current-cluster-health"
            if gate_blockers:
                status = DeployScyllaHealthStepStatus.BLOCKED
                authorization_state = "unavailable"
                blockers = gate_blockers
            else:
                status = DeployScyllaHealthStepStatus.AUTHORIZATION_REQUIRED
                authorization_state = "authorization-required"
                blockers = ("join-authorization-not-collected",)
            next_join_status = status.value
            next_join_blockers = blockers
        else:
            status = DeployScyllaHealthStepStatus.WAITING
            health_state = "waiting-for-preceding-complete-health"
            authorization_state = "waiting"
            blockers = ("preceding-join-not-completed",)
        values: dict[str, object] = {
            "sequence": original.sequence,
            "mode": original.mode,
            "target_digest": original.target_digest,
            "plan_step_digest": original.step_digest,
            "status": status,
            "health_checkpoint_state": health_state,
            "authorization_state": authorization_state,
            "blockers": blockers,
            "blocker_digest": _digest_object(list(blockers)),
            "step_digest": "",
        }
        values["step_digest"] = _step_digest_from_values(values)
        steps.append(DeployScyllaPostJoinHealthStep(**values))  # type: ignore[arg-type]
    step_tuple = tuple(steps)
    statuses = Counter(step.status for step in step_tuple)
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
        "join_execution_artifact_digest": (context.join_execution.artifact_digest),
        "join_evidence_artifact_digest": context.join_evidence.artifact_digest,
        "join_evidence_digest": context.join_evidence.record.evidence_digest,
        "steps": step_tuple,
        "step_count": len(step_tuple),
        "health_succeeded_count": statuses[
            DeployScyllaHealthStepStatus.HEALTH_SUCCEEDED
        ],
        "authorization_required_count": statuses[
            DeployScyllaHealthStepStatus.AUTHORIZATION_REQUIRED
        ],
        "blocked_count": statuses[DeployScyllaHealthStepStatus.BLOCKED],
        "waiting_count": statuses[DeployScyllaHealthStepStatus.WAITING],
        "current_member_count": len(context.current_ids),
        "current_member_set_digest": _digest_object(list(context.current_ids)),
        "next_join_sequence": next_join_sequence,
        "next_join_status": next_join_status,
        "next_join_blocker_digest": _digest_object(list(next_join_blockers)),
        "later_join_count": len(later),
        "later_join_set_digest": _digest_object([step.target_digest for step in later]),
        "reconciliation_digest": "",
    }
    values["reconciliation_digest"] = _reconciliation_digest_from_values(values)
    return DeployScyllaPostJoinHealthReconciliation(**values)  # type: ignore[arg-type]


def _validate_prefix(
    context: _PostJoinHealthContext,
    execution: StoredDeployScyllaPostJoinHealthExecution | None,
    evidence: StoredDeployScyllaPostJoinHealthEvidence | None,
    reconciliation: StoredDeployScyllaPostJoinHealthReconciliation | None,
) -> None:
    if execution is None:
        if evidence is not None or reconciliation is not None:
            raise StateConflictError(
                "deploy Scylla post-join health artifacts exist without execution"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError(
            "deploy Scylla post-join health execution binding drifted"
        )
    if evidence is not None and (
        evidence.record.binding != context.binding
        or execution.record.evidence_digest != evidence.record.evidence_digest
    ):
        raise StateConflictError(
            "deploy Scylla post-join health evidence binding conflicts"
        )
    if reconciliation is not None:
        if evidence is None:
            raise StateConflictError(
                "deploy Scylla post-join reconciliation evidence is unavailable"
            )
        expected = _build_reconciliation(
            context,
            execution,
            evidence,
            created_at=reconciliation.record.created_at,
        )
        if reconciliation.record != expected:
            raise StateConflictError(
                "deploy Scylla post-join health reconciliation drifted"
            )


def _persist_started(
    store: DeployScyllaPostJoinHealthExecutionStore,
    context: _PostJoinHealthContext,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaPostJoinHealthExecution:
    now = _timestamp()
    return store.write_locked(
        DeployScyllaPostJoinHealthExecution(
            generation=1,
            created_at=now,
            updated_at=now,
            binding=context.binding,
            state=DeployScyllaHealthExecutionState.STARTED,
            invocation_count=1,
            completed=False,
            manual_recovery_required=False,
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
    store: DeployScyllaPostJoinHealthExecutionStore,
    current: StoredDeployScyllaPostJoinHealthExecution,
    state: DeployScyllaHealthExecutionState,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaPostJoinHealthExecution:
    record = replace(
        current.record,
        generation=2,
        updated_at=_timestamp(),
        state=state,
        manual_recovery_required=True,
    )
    return store.write_locked(
        record,
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _persist_terminal(
    store: DeployScyllaPostJoinHealthExecutionStore,
    current: StoredDeployScyllaPostJoinHealthExecution,
    *,
    evidence: StoredDeployScyllaPostJoinHealthEvidence,
    result: AnsibleExecutionResult,
    state: DeployScyllaHealthExecutionState,
    lock: ClusterLock,
) -> StoredDeployScyllaPostJoinHealthExecution:
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
    execution: StoredDeployScyllaPostJoinHealthExecution,
    evidence: StoredDeployScyllaPostJoinHealthEvidence,
    reconciliation: StoredDeployScyllaPostJoinHealthReconciliation,
    execution_state: DeployScyllaHealthArtifactState,
    evidence_state: DeployScyllaHealthArtifactState,
    reconciliation_state: DeployScyllaHealthArtifactState,
) -> DeployScyllaPostJoinHealthReport:
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
    return DeployScyllaPostJoinHealthReport(
        operation_id=record.binding.operation_id,
        stage=_STAGE,
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
            status in {HealthCheckStatus.UNKNOWN, HealthCheckStatus.NOT_PERFORMED}
            for _, status in record.policy_states
        ),
        completed_prior_membership_count=(reconciliation.record.health_succeeded_count),
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
    store: DeployScyllaPostJoinHealthExecutionStore,
    context: _PostJoinHealthContext,
    lock: ClusterLock,
) -> StoredDeployScyllaPostJoinHealthExecution | None:
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
    store: DeployScyllaPostJoinHealthEvidenceStore,
    context: _PostJoinHealthContext,
    lock: ClusterLock,
) -> StoredDeployScyllaPostJoinHealthEvidence | None:
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
    store: DeployScyllaPostJoinHealthReconciliationStore,
    context: _PostJoinHealthContext,
    lock: ClusterLock,
) -> StoredDeployScyllaPostJoinHealthReconciliation | None:
    return (
        store.read_locked(
            lock,
            expected_cluster_uuid=context.binding.cluster_uuid,
            expected_cluster_name=context.binding.cluster_name,
        )
        if store.path.exists()
        else None
    )


def _binding_digest(record: DeployScyllaPostJoinHealthExecutionBinding) -> str:
    return _binding_digest_from_values(record.to_object())


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for (
        name,
        field,
    ) in DeployScyllaPostJoinHealthExecutionBinding.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["binding_digest"] = ""
    return _digest_object(value)


def _health_evidence_digest(record: DeployScyllaPostJoinHealthEvidence) -> str:
    return _health_evidence_digest_from_values(record.to_object())


def _health_evidence_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for name, field in DeployScyllaPostJoinHealthEvidence.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["evidence_digest"] = ""
    return _digest_object(value)


def _step_digest(record: DeployScyllaPostJoinHealthStep) -> str:
    return _step_digest_from_values(record.to_object())


def _step_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    value.setdefault(
        "schema_version", ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_STEP_SCHEMA_VERSION
    )
    value["step_digest"] = ""
    return _digest_object(value)


def _reconciliation_digest(
    record: DeployScyllaPostJoinHealthReconciliation,
) -> str:
    return _reconciliation_digest_from_values(record.to_object())


def _reconciliation_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for (
        name,
        field,
    ) in DeployScyllaPostJoinHealthReconciliation.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["reconciliation_digest"] = ""
    return _digest_object(value)


def _status_blocker_suffix(status: HealthCheckStatus) -> str:
    return {
        HealthCheckStatus.FAILED: "failed",
        HealthCheckStatus.UNKNOWN: "unknown",
        HealthCheckStatus.NOT_PERFORMED: "not-performed",
        HealthCheckStatus.PASSED: "passed",
    }[status]


def _artifact_path(paths: StatePaths, operation_id: uuid.UUID, suffix: str) -> Path:
    _require_canonical_paths(paths)
    path = paths.operations / f"{_require_operation_id(operation_id)}{suffix}"
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Scylla post-join health path is not canonical"
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


def _failure_state(error: BaseException) -> DeployScyllaHealthExecutionState:
    if isinstance(error, ProcessTimeoutError) or isinstance(
        error.__cause__, ProcessTimeoutError
    ):
        return DeployScyllaHealthExecutionState.TIMED_OUT
    if isinstance(error, ProcessOutputError) or isinstance(
        error.__cause__, ProcessOutputError
    ):
        return DeployScyllaHealthExecutionState.MALFORMED_RESULT
    if isinstance(error, AnsibleResultError):
        return DeployScyllaHealthExecutionState.MALFORMED_RESULT
    return DeployScyllaHealthExecutionState.UNREACHABLE


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
        raise StatePersistenceError("deploy Scylla post-join health identity conflicts")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy Scylla post-join health requires the matching held deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy Scylla post-join health paths are not canonical"
        )


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_JOIN_HEALTH_EVIDENCE_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_FILENAME_SUFFIX,
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Scylla post-join health artifacts"
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
                    "deploy Scylla post-join health artifacts are ambiguous"
                )


def _timestamp() -> str:
    return format_timestamp(datetime.now(UTC))


def _digest_text(value: str) -> str:
    from scylla_vms.persistence import digest_bytes

    return digest_bytes(value.encode("utf-8"))


def _validate_toolchain_version(value: str) -> None:
    try:
        parse_ansible_core_version(
            f"ansible-playbook [core {value}]\n",
            expected_executable="ansible-playbook",
        )
    except AnsibleVersionError as error:
        raise StatePersistenceError(
            "deploy Scylla post-join health toolchain version is invalid"
        ) from error


def _dataclass_object(
    value: object,
    *,
    nested_fields: set[str] | None = None,
    tuple_fields: set[str] | None = None,
    skip_fields: set[str] | None = None,
) -> dict[str, object]:
    nested = nested_fields or set()
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
            else item.to_object()
            if name in nested
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
    optional_string_fields: set[str] | None = None,
    optional_integer_fields: set[str] | None = None,
    skip_fields: set[str] | None = None,
    label: str,
) -> dict[str, object]:
    require_exact_keys(value, set(data_type.__dataclass_fields__), label)  # type: ignore[attr-defined]
    integers = integer_fields or set()
    uuids = uuid_fields or set()
    booleans = boolean_fields or set()
    tuples = tuple_fields or set()
    enums = enum_fields or {}
    optional_strings = optional_string_fields or set()
    optional_integers = optional_integer_fields or set()
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
            elif name in tuples:
                parsed[name] = _string_tuple(item, name)
            elif name in enums:
                parsed[name] = enums[name](require_string(value, name))
            elif name in optional_strings:
                parsed[name] = _optional_string(item, name)
            elif name in optional_integers:
                parsed[name] = _optional_integer(item, name)
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


def _digest_fields(value: object) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(value, name))
        for name in value.__dataclass_fields__  # type: ignore[attr-defined]
        if name.endswith("_digest") and isinstance(getattr(value, name), str)
    )


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


def _status_pairs(
    value: object, label: str
) -> tuple[tuple[str, HealthCheckStatus], ...]:
    if not isinstance(value, list):
        raise StatePersistenceError(f"deploy Scylla {label} is invalid")
    result: list[tuple[str, HealthCheckStatus]] = []
    try:
        for item in value:
            if (
                not isinstance(item, list)
                or len(item) != 2
                or not isinstance(item[0], str)
                or not isinstance(item[1], str)
            ):
                raise StatePersistenceError(f"deploy Scylla {label} is invalid")
            result.append((item[0], HealthCheckStatus(item[1])))
    except ValueError as error:
        raise StatePersistenceError(f"deploy Scylla {label} is invalid") from error
    return tuple(result)


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"deploy Scylla {label} is invalid")
    return value


def _positive_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"deploy Scylla {label} must be positive")


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"deploy Scylla {label} is invalid")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    return None if value is None else _integer(value, label)


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise StatePersistenceError(f"deploy Scylla {label} is invalid")
    return value


__all__ = [
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_BINDING_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_STEP_SCHEMA_VERSION",
    "DEPLOY_SCYLLA_JOIN_HEALTH_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_FILENAME_SUFFIX",
    "DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_FILENAME_SUFFIX",
    "DeployScyllaPostJoinHealthEvidence",
    "DeployScyllaPostJoinHealthEvidenceStore",
    "DeployScyllaPostJoinHealthExecution",
    "DeployScyllaPostJoinHealthExecutionBinding",
    "DeployScyllaPostJoinHealthExecutionStore",
    "DeployScyllaPostJoinHealthReconciliation",
    "DeployScyllaPostJoinHealthReconciliationStore",
    "DeployScyllaPostJoinHealthReport",
    "DeployScyllaPostJoinHealthStep",
    "StoredDeployScyllaPostJoinHealthEvidence",
    "StoredDeployScyllaPostJoinHealthExecution",
    "StoredDeployScyllaPostJoinHealthReconciliation",
    "deploy_scylla_post_join_health_evidence_id_from_filename",
    "deploy_scylla_post_join_health_evidence_path",
    "deploy_scylla_post_join_health_execution_id_from_filename",
    "deploy_scylla_post_join_health_execution_path",
    "deploy_scylla_post_join_health_reconciliation_id_from_filename",
    "deploy_scylla_post_join_health_reconciliation_path",
    "execute_deploy_scylla_post_join_health",
]
