"""Operation-bound current-cluster health after initial-seed bootstrap.

This internal owner derives the active member set from the exact succeeded
bootstrap prefix, runs only the reviewed read-only ``scylla-health`` source,
and writes immutable address-free evidence plus a bootstrap-plan checkpoint.
It never authorizes or executes a join and never changes the common journal.
"""

from __future__ import annotations

import os
import uuid
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
from scylla_vms.ansible.deploy_scylla_bootstrap_authorization import (
    _load_authorization_context,
)
from scylla_vms.ansible.deploy_scylla_bootstrap_execution import (
    DeployScyllaBootstrapEvidenceStore,
    DeployScyllaBootstrapExecutionState,
    DeployScyllaBootstrapExecutionStore,
)
from scylla_vms.ansible.deploy_scylla_bootstrap_execution import (
    _load_execution_context as _load_bootstrap_execution_context,
)
from scylla_vms.ansible.deploy_scylla_bootstrap_plan import (
    StoredDeployScyllaBootstrapContext,
    StoredDeployScyllaBootstrapPlan,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import _loaded
from scylla_vms.ansible.deploy_scylla_configure_reconciliation import (
    _load_reconciliation_context,
)
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, PlaybookDefinition
from scylla_vms.ansible.scylla_bootstrap import (
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
    digest_bytes,
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
    _reconstructed_readiness,
    _toolchain_evidence_digest,
    _validate_toolchain_dependency,
)

ANSIBLE_DEPLOY_SCYLLA_HEALTH_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-health-execution-binding/v1"
)
ANSIBLE_DEPLOY_SCYLLA_HEALTH_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-health-execution/v1"
)
ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_NODE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-health-evidence-node/v1"
)
ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-health-evidence/v1"
)
ANSIBLE_DEPLOY_SCYLLA_HEALTH_CHECKPOINT_STEP_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-health-checkpoint-step/v1"
)
ANSIBLE_DEPLOY_SCYLLA_HEALTH_CHECKPOINT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-health-checkpoint/v1"
)
ANSIBLE_DEPLOY_SCYLLA_HEALTH_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-health-report/v1"
)

DEPLOY_SCYLLA_HEALTH_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-health-execution.json"
)
DEPLOY_SCYLLA_HEALTH_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-health-evidence.json"
)
DEPLOY_SCYLLA_HEALTH_CHECKPOINT_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-health-checkpoint.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "scylla-health"
_STAGE = "post-initial-seed-current-cluster-health"
_TIMEOUT_SECONDS = 60
_REQUIRED_POLICY_CHECKS = ("backup-policy", "capacity", "quorum", "replication")
_JOIN_GATES = (
    "target-absence",
    "survivor-health",
    "seed-health",
    "topology",
    "schema",
    "capacity",
    "replication",
    "quorum",
    "backup-policy",
)
_STRICT_CHECKS = (
    "cross-view-consistency",
    "membership",
    "schema-agreement",
    "streaming",
    "topology",
)


class DeployScyllaHealthExecutionState(StrEnum):
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"


class DeployScyllaHealthArtifactState(StrEnum):
    CREATED = "created"
    REUSED = "reused"
    RECOVERED = "recovered"


class DeployScyllaHealthStepStatus(StrEnum):
    HEALTH_SUCCEEDED = "health-succeeded"
    AUTHORIZATION_REQUIRED = "authorization-required"
    BLOCKED = "blocked"
    WAITING = "waiting-for-preceding-complete-health"


@dataclass(frozen=True, slots=True)
class DeployScyllaHealthExecutionBinding:
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
    bootstrap_execution_artifact_digest: str
    bootstrap_execution_binding_digest: str
    bootstrap_evidence_artifact_digest: str
    bootstrap_evidence_digest: str
    post_configure_artifact_digest: str
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
    source_version: str
    source_digest: str
    playbook_source_digest: str
    catalog_digest: str
    toolchain_version: str
    executable_identity_digest: str
    toolchain_evidence_digest: str
    active_member_count: int
    active_member_set_digest: str
    desired_member_count: int
    desired_member_set_digest: str
    future_member_count: int
    future_member_set_digest: str
    desired_topology_digest: str
    bootstrap_host_id_digest: str
    storage_evidence_digest: str
    variables_digest: str
    command_digest: str
    binding_digest: str
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_HEALTH_EXECUTION_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_HEALTH_EXECUTION_BINDING_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.active_member_count < 1
            or self.desired_member_count < self.active_member_count
            or self.future_member_count
            != self.desired_member_count - self.active_member_count
            or self.binding_digest != _binding_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla health execution binding conflicts"
            )
        validate_cluster_name(self.cluster_name)
        for generation in (
            self.journal_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
        ):
            if generation < 1:
                raise StatePersistenceError(
                    "deploy Scylla health binding generation conflicts"
                )
        for digest in _digest_fields(self):
            if digest is None:
                raise StatePersistenceError(
                    "deploy Scylla health binding digest is unavailable"
                )
            validate_digest(digest, "deploy Scylla health binding digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaHealthExecutionBinding:
        require_exact_keys(value, set(cls.__dataclass_fields__), "health binding")
        integers = {
            "journal_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
            "active_member_count",
            "desired_member_count",
            "future_member_count",
        }
        enums: dict[str, type[StrEnum]] = {
            "journal_status": JournalStatus,
            "journal_phase": OperationPhase,
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in integers:
                    parsed[name] = _integer(item, name)
                elif name in {"cluster_uuid", "operation_id"}:
                    parsed[name] = parse_uuid(require_string(value, name), name)
                elif name in enums:
                    parsed[name] = enums[name](require_string(value, name))
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Scylla health binding enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaHealthExecution:
    generation: int
    created_at: str
    updated_at: str
    binding: DeployScyllaHealthExecutionBinding
    state: DeployScyllaHealthExecutionState
    invocation_count: int
    completed: bool
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    exit_code: int | None
    result_digest: str | None
    evidence_digest: str | None
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_HEALTH_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        terminal = self.state in {
            DeployScyllaHealthExecutionState.SUCCEEDED,
            DeployScyllaHealthExecutionState.FAILED,
        }
        success = self.state is DeployScyllaHealthExecutionState.SUCCEEDED
        if (
            self.schema_version != ANSIBLE_DEPLOY_SCYLLA_HEALTH_EXECUTION_SCHEMA_VERSION
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
            raise StatePersistenceError("deploy Scylla health execution conflicts")
        for value in (self.result_digest, self.evidence_digest):
            if value is not None:
                validate_digest(value, "deploy Scylla health execution digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaHealthExecution:
        require_exact_keys(value, set(cls.__dataclass_fields__), "health execution")
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                updated_at=require_string(value, "updated_at"),
                binding=DeployScyllaHealthExecutionBinding.from_object(
                    _mapping(value["binding"], "binding")
                ),
                state=DeployScyllaHealthExecutionState(require_string(value, "state")),
                invocation_count=_integer(
                    value["invocation_count"], "invocation count"
                ),
                completed=_boolean(value["completed"], "completed"),
                manual_recovery_required=_boolean(
                    value["manual_recovery_required"], "manual recovery"
                ),
                automatic_retry_allowed=_boolean(
                    value["automatic_retry_allowed"], "automatic retry"
                ),
                exit_code=_optional_integer(value["exit_code"], "exit code"),
                result_digest=_optional_string(value["result_digest"], "result digest"),
                evidence_digest=_optional_string(
                    value["evidence_digest"], "evidence digest"
                ),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Scylla health execution enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployScyllaHealthEvidenceNode:
    stable_id: str
    stable_id_digest: str
    host_id_digest: str | None
    membership_state: str
    datacenter_digest: str
    rack_digest: str
    version_digest: str
    service_ready: bool
    api_ready: bool
    cql_ready: bool
    storage_ready: bool
    streaming_idle: bool
    blocker_count: int
    blocker_digest: str
    evidence_digest: str
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_NODE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_NODE_SCHEMA_VERSION
            or not self.stable_id
            or self.membership_state
            not in {"UN", "DN", "UJ", "UL", "DJ", "DL", "NM", "unknown"}
            or self.blocker_count < 0
            or self.evidence_digest != _node_evidence_digest(self)
        ):
            raise StatePersistenceError("deploy Scylla health node evidence conflicts")
        for value in _digest_fields(self):
            if value is not None:
                validate_digest(value, "deploy Scylla health node digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaHealthEvidenceNode:
        require_exact_keys(value, set(cls.__dataclass_fields__), "health node")
        return cls(
            stable_id=require_string(value, "stable_id"),
            stable_id_digest=require_string(value, "stable_id_digest"),
            host_id_digest=_optional_string(value["host_id_digest"], "host ID digest"),
            membership_state=require_string(value, "membership_state"),
            datacenter_digest=require_string(value, "datacenter_digest"),
            rack_digest=require_string(value, "rack_digest"),
            version_digest=require_string(value, "version_digest"),
            service_ready=_boolean(value["service_ready"], "service readiness"),
            api_ready=_boolean(value["api_ready"], "API readiness"),
            cql_ready=_boolean(value["cql_ready"], "CQL readiness"),
            storage_ready=_boolean(value["storage_ready"], "storage readiness"),
            streaming_idle=_boolean(value["streaming_idle"], "streaming readiness"),
            blocker_count=_integer(value["blocker_count"], "blocker count"),
            blocker_digest=require_string(value, "blocker_digest"),
            evidence_digest=require_string(value, "evidence_digest"),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaHealthEvidence:
    generation: int
    created_at: str
    binding: DeployScyllaHealthExecutionBinding
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
    join_gate_states: tuple[tuple[str, HealthCheckStatus], ...]
    blocker_count: int
    blocker_digest: str
    strict_complete: bool
    result_digest: str
    evidence_digest: str
    result_schema_version: str = SCYLLA_HEALTH_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_SCHEMA_VERSION
            or self.result_schema_version != SCYLLA_HEALTH_SCHEMA_VERSION
            or self.generation != 1
            or self.query_policy != "all-nodes-cross-view"
            or tuple(node.stable_id for node in self.nodes)
            != tuple(sorted({node.stable_id for node in self.nodes}))
            or tuple(name for name, _ in self.check_states) != _STRICT_CHECKS
            or tuple(name for name, _ in self.policy_states) != _REQUIRED_POLICY_CHECKS
            or tuple(name for name, _ in self.join_gate_states) != _JOIN_GATES
            or self.blocker_count < 0
            or self.evidence_digest != _health_evidence_digest(self)
        ):
            raise StatePersistenceError("deploy Scylla health evidence conflicts")
        parse_timestamp(self.created_at)
        for value in _digest_fields(self):
            if value is not None:
                validate_digest(value, "deploy Scylla health evidence digest")

    def to_object(self) -> dict[str, object]:
        return {
            "binding": self.binding.to_object(),
            "blocker_count": self.blocker_count,
            "blocker_digest": self.blocker_digest,
            "check_states": [
                [name, status.value] for name, status in self.check_states
            ],
            "created_at": self.created_at,
            "evidence_digest": self.evidence_digest,
            "generation": self.generation,
            "health_status": self.health_status.value,
            "host_id_mapping_digest": self.host_id_mapping_digest,
            "join_gate_states": [
                [name, status.value] for name, status in self.join_gate_states
            ],
            "membership_digest": self.membership_digest,
            "nodes": [node.to_object() for node in self.nodes],
            "policy_states": [
                [name, status.value] for name, status in self.policy_states
            ],
            "query_policy": self.query_policy,
            "result_digest": self.result_digest,
            "result_schema_version": self.result_schema_version,
            "schema_agreement": self.schema_agreement,
            "schema_digest": self.schema_digest,
            "schema_version": self.schema_version,
            "streaming_state": self.streaming_state,
            "strict_complete": self.strict_complete,
            "topology_digest": self.topology_digest,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaHealthEvidence:
        require_exact_keys(value, set(cls.__dataclass_fields__), "health evidence")
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                binding=DeployScyllaHealthExecutionBinding.from_object(
                    _mapping(value["binding"], "binding")
                ),
                health_status=HealthReadiness(require_string(value, "health_status")),
                query_policy=require_string(value, "query_policy"),
                nodes=tuple(
                    DeployScyllaHealthEvidenceNode.from_object(
                        _mapping(item, "health node")
                    )
                    for item in _array(value["nodes"], "health nodes")
                ),
                host_id_mapping_digest=require_string(value, "host_id_mapping_digest"),
                membership_digest=require_string(value, "membership_digest"),
                topology_digest=_optional_string(
                    value["topology_digest"], "topology digest"
                ),
                schema_digest=_optional_string(value["schema_digest"], "schema digest"),
                schema_agreement=_boolean(
                    value["schema_agreement"], "schema agreement"
                ),
                streaming_state=require_string(value, "streaming_state"),
                check_states=_status_pairs(value["check_states"], "check states"),
                policy_states=_status_pairs(value["policy_states"], "policy states"),
                join_gate_states=_status_pairs(
                    value["join_gate_states"], "join gate states"
                ),
                blocker_count=_integer(value["blocker_count"], "blocker count"),
                blocker_digest=require_string(value, "blocker_digest"),
                strict_complete=_boolean(value["strict_complete"], "strict complete"),
                result_digest=require_string(value, "result_digest"),
                evidence_digest=require_string(value, "evidence_digest"),
                result_schema_version=require_string(value, "result_schema_version"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Scylla health evidence enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployScyllaHealthCheckpointStep:
    sequence: int
    mode: ScyllaBootstrapMode
    target_digest: str
    original_step_digest: str
    status: DeployScyllaHealthStepStatus
    health_checkpoint_state: str
    authorization_state: str
    blockers: tuple[str, ...]
    blocker_digest: str
    step_digest: str
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_HEALTH_CHECKPOINT_STEP_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_HEALTH_CHECKPOINT_STEP_SCHEMA_VERSION
            or self.sequence < 1
            or tuple(sorted(set(self.blockers))) != self.blockers
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.step_digest != _checkpoint_step_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla health checkpoint step conflicts"
            )
        for digest in _digest_fields(self):
            if digest is None:
                raise StatePersistenceError(
                    "deploy Scylla health checkpoint step digest is unavailable"
                )
            validate_digest(digest, "deploy Scylla health checkpoint step digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, tuple_fields={"blockers"})

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaHealthCheckpointStep:
        require_exact_keys(value, set(cls.__dataclass_fields__), "checkpoint step")
        try:
            return cls(
                sequence=_integer(value["sequence"], "sequence"),
                mode=ScyllaBootstrapMode(require_string(value, "mode")),
                target_digest=require_string(value, "target_digest"),
                original_step_digest=require_string(value, "original_step_digest"),
                status=DeployScyllaHealthStepStatus(require_string(value, "status")),
                health_checkpoint_state=require_string(
                    value, "health_checkpoint_state"
                ),
                authorization_state=require_string(value, "authorization_state"),
                blockers=_string_tuple(value["blockers"], "blockers"),
                blocker_digest=require_string(value, "blocker_digest"),
                step_digest=require_string(value, "step_digest"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Scylla health checkpoint step enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployScyllaHealthCheckpoint:
    generation: int
    created_at: str
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
    health_execution_artifact_digest: str
    health_evidence_artifact_digest: str
    health_evidence_digest: str
    active_member_count: int
    active_member_set_digest: str
    desired_member_count: int
    desired_member_set_digest: str
    future_member_count: int
    future_member_set_digest: str
    steps: tuple[DeployScyllaHealthCheckpointStep, ...]
    step_count: int
    health_succeeded_count: int
    authorization_required_count: int
    blocked_count: int
    waiting_count: int
    next_join_sequence: int | None
    next_join_status: str
    next_join_blocker_digest: str
    checkpoint_digest: str
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_HEALTH_CHECKPOINT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        statuses = tuple(step.status for step in self.steps)
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_HEALTH_CHECKPOINT_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.step_count != len(self.steps)
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, self.step_count + 1))
            or self.health_succeeded_count
            != statuses.count(DeployScyllaHealthStepStatus.HEALTH_SUCCEEDED)
            or self.authorization_required_count
            != statuses.count(DeployScyllaHealthStepStatus.AUTHORIZATION_REQUIRED)
            or self.blocked_count
            != statuses.count(DeployScyllaHealthStepStatus.BLOCKED)
            or self.waiting_count
            != statuses.count(DeployScyllaHealthStepStatus.WAITING)
            or self.health_succeeded_count != self.active_member_count
            or self.authorization_required_count > 1
            or self.checkpoint_digest != _checkpoint_digest(self)
        ):
            raise StatePersistenceError("deploy Scylla health checkpoint conflicts")
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for digest in _digest_fields(self):
            if digest is None:
                raise StatePersistenceError(
                    "deploy Scylla health checkpoint digest is unavailable"
                )
            validate_digest(digest, "deploy Scylla health checkpoint digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, step_fields={"steps"})

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaHealthCheckpoint:
        require_exact_keys(value, set(cls.__dataclass_fields__), "health checkpoint")
        integers = {
            "generation",
            "journal_generation",
            "active_member_count",
            "desired_member_count",
            "future_member_count",
            "step_count",
            "health_succeeded_count",
            "authorization_required_count",
            "blocked_count",
            "waiting_count",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in integers:
                    parsed[name] = _integer(item, name)
                elif name in {"cluster_uuid", "operation_id"}:
                    parsed[name] = parse_uuid(require_string(value, name), name)
                elif name == "journal_status":
                    parsed[name] = JournalStatus(require_string(value, name))
                elif name == "journal_phase":
                    parsed[name] = OperationPhase(require_string(value, name))
                elif name == "steps":
                    parsed[name] = tuple(
                        DeployScyllaHealthCheckpointStep.from_object(
                            _mapping(step, "checkpoint step")
                        )
                        for step in _array(item, "checkpoint steps")
                    )
                elif name == "next_join_sequence":
                    parsed[name] = _optional_integer(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Scylla health checkpoint enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaHealthExecution:
    record: DeployScyllaHealthExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaHealthEvidence:
    record: DeployScyllaHealthEvidence
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaHealthCheckpoint:
    record: DeployScyllaHealthCheckpoint
    artifact_digest: str


class DeployScyllaHealthExecutionStore:
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
        self._path = deploy_scylla_health_execution_path(paths, operation_id)
        self._file = AtomicJsonFile(self._path, replace=replace_file)

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaHealthExecution:
        value, digest = self._file.read()
        record = DeployScyllaHealthExecution.from_object(value)
        _require_identity(
            record.binding,
            operation_id=self._operation_id,
            cluster_uuid=expected_cluster_uuid,
            cluster_name=expected_cluster_name,
        )
        return StoredDeployScyllaHealthExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaHealthExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaHealthExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployScyllaHealthExecution:
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
                    "deploy Scylla health execution transition conflicts"
                )
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
            or record.state is not DeployScyllaHealthExecutionState.STARTED
        ):
            raise StateConflictError("deploy Scylla health initial execution conflicts")
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployScyllaHealthExecution(record, digest)


class DeployScyllaHealthEvidenceStore:
    def __init__(self, paths: StatePaths, operation_id: uuid.UUID) -> None:
        _require_canonical_paths(paths)
        self._paths = paths
        self._operation_id = _require_operation_id(operation_id)
        self._path = deploy_scylla_health_evidence_path(paths, operation_id)
        self._file = AtomicJsonFile(self._path)

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaHealthEvidence:
        value, digest = self._file.read()
        record = DeployScyllaHealthEvidence.from_object(value)
        _require_identity(
            record.binding,
            operation_id=self._operation_id,
            cluster_uuid=expected_cluster_uuid,
            cluster_name=expected_cluster_name,
        )
        return StoredDeployScyllaHealthEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaHealthEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self, record: DeployScyllaHealthEvidence, *, lock: ClusterLock
    ) -> tuple[StoredDeployScyllaHealthEvidence, DeployScyllaHealthArtifactState]:
        _assert_operation_lock(lock, self._paths)
        validate_state_file(self._path, allow_missing=True)
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if current.record != record:
                raise StateConflictError("deploy Scylla health evidence is immutable")
            return current, DeployScyllaHealthArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaHealthEvidence(record, digest),
            DeployScyllaHealthArtifactState.CREATED,
        )


class DeployScyllaHealthCheckpointStore:
    def __init__(self, paths: StatePaths, operation_id: uuid.UUID) -> None:
        _require_canonical_paths(paths)
        self._paths = paths
        self._operation_id = _require_operation_id(operation_id)
        self._path = deploy_scylla_health_checkpoint_path(paths, operation_id)
        self._file = AtomicJsonFile(self._path)

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaHealthCheckpoint:
        value, digest = self._file.read()
        record = DeployScyllaHealthCheckpoint.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy Scylla health checkpoint identity conflicts"
            )
        return StoredDeployScyllaHealthCheckpoint(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaHealthCheckpoint:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self, record: DeployScyllaHealthCheckpoint, *, lock: ClusterLock
    ) -> tuple[StoredDeployScyllaHealthCheckpoint, DeployScyllaHealthArtifactState]:
        _assert_operation_lock(lock, self._paths)
        validate_state_file(self._path, allow_missing=True)
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError("deploy Scylla health checkpoint is immutable")
            return current, DeployScyllaHealthArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaHealthCheckpoint(record, digest),
            DeployScyllaHealthArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaHealthReport:
    operation_id: uuid.UUID
    stage: str
    execution_state: DeployScyllaHealthExecutionState
    execution_artifact_state: DeployScyllaHealthArtifactState
    evidence_artifact_state: DeployScyllaHealthArtifactState
    checkpoint_artifact_state: DeployScyllaHealthArtifactState
    active_member_count: int
    desired_member_count: int
    future_member_count: int
    health_complete: bool
    host_identity_count: int
    up_normal_count: int
    service_ready_count: int
    api_ready_count: int
    cql_ready_count: int
    storage_ready_count: int
    version_ready_count: int
    schema_agreement: bool
    streaming_idle: bool
    policy_unknown_count: int
    next_join_status: str
    next_join_blocker_count: int
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    journal_status: JournalStatus
    journal_phase: OperationPhase
    journal_updated: bool
    execution_artifact_digest: str
    evidence_artifact_digest: str
    checkpoint_artifact_digest: str
    evidence_digest: str
    checkpoint_digest: str
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_HEALTH_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_SCHEMA_VERSION
    checkpoint_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_HEALTH_CHECKPOINT_SCHEMA_VERSION
    )
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_HEALTH_REPORT_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class _HealthContext:
    bootstrap_context: StoredDeployScyllaBootstrapContext
    bootstrap_plan: StoredDeployScyllaBootstrapPlan
    binding: DeployScyllaHealthExecutionBinding
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport
    payload: dict[str, object]
    variables: tuple[tuple[str, object], ...]
    active_ids: tuple[str, ...]
    desired_ids: tuple[str, ...]
    future_ids: tuple[str, ...]


def execute_deploy_scylla_health_checkpoint(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployScyllaHealthReport:
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
    execution_store = DeployScyllaHealthExecutionStore(paths, operation_id)
    evidence_store = DeployScyllaHealthEvidenceStore(paths, operation_id)
    checkpoint_store = DeployScyllaHealthCheckpointStore(paths, operation_id)
    for path in (
        execution_store.path,
        evidence_store.path,
        checkpoint_store.path,
    ):
        validate_state_file(path, allow_missing=True)
    execution = _read_execution(execution_store, context, lock)
    evidence = _read_evidence(evidence_store, context, lock)
    checkpoint = _read_checkpoint(checkpoint_store, context, lock)
    _validate_prefix(context, execution, evidence, checkpoint)
    if checkpoint is not None:
        return _report(
            execution=cast(StoredDeployScyllaHealthExecution, execution),
            evidence=cast(StoredDeployScyllaHealthEvidence, evidence),
            checkpoint=checkpoint,
            execution_state=DeployScyllaHealthArtifactState.REUSED,
            evidence_state=DeployScyllaHealthArtifactState.REUSED,
            checkpoint_state=DeployScyllaHealthArtifactState.REUSED,
        )
    if execution is not None:
        if (
            execution.record.state is not DeployScyllaHealthExecutionState.SUCCEEDED
            or evidence is None
            or not evidence.record.strict_complete
        ):
            raise StateConflictError(
                "deploy Scylla health execution requires manual recovery "
                "and cannot retry"
            )
        checkpoint_record = _build_checkpoint(
            context,
            execution,
            evidence,
            created_at=_timestamp(),
        )
        checkpoint, checkpoint_state = checkpoint_store.write_locked(
            checkpoint_record, lock=lock
        )
        return _report(
            execution=execution,
            evidence=evidence,
            checkpoint=checkpoint,
            execution_state=DeployScyllaHealthArtifactState.REUSED,
            evidence_state=DeployScyllaHealthArtifactState.REUSED,
            checkpoint_state=(
                DeployScyllaHealthArtifactState.RECOVERED
                if checkpoint_state is DeployScyllaHealthArtifactState.CREATED
                else checkpoint_state
            ),
        )

    service = AnsibleService(builder, runner)
    if service.version(lock) != toolchain:
        raise StateConflictError("deploy Scylla health toolchain drifted")
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
        raise StateConflictError("deploy Scylla health state drifted before start")
    execution = _persist_started(execution_store, before, lock=lock)
    try:
        result, command_digest = service.execute_operation_step(
            lock,
            before.metadata,
            before.inventory,
            _PLAYBOOK,
            step_sequence=1,
            limit=before.active_ids,
            variables=dict(before.variables),
            readiness=before.readiness,
            tags=(_PLAYBOOK,),
            check=True,
            diff=False,
            verbosity=0,
        )
        if command_digest != before.binding.command_digest:
            raise AnsibleResultError(
                "deploy Scylla health command result identity conflicts"
            )
    except KeyboardInterrupt:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployScyllaHealthExecutionState.INTERRUPTED,
            lock=lock,
        )
        raise AnsibleError(
            "deploy Scylla health was interrupted; manual recovery required"
        ) from None
    except (AnsibleError, StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            _failure_state(error),
            lock=lock,
        )
        raise AnsibleError(
            "deploy Scylla health execution is uncertain; manual recovery required"
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
                "deploy Scylla health state changed after invocation"
            )
        semantic = _semantic_evidence(before, result)
        evidence, evidence_state = evidence_store.write_locked(semantic, lock=lock)
    except (AnsibleError, StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployScyllaHealthExecutionState.MALFORMED_RESULT,
            lock=lock,
        )
        raise AnsibleError(
            "deploy Scylla health result is uncertain; manual recovery required"
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
            "deploy Scylla health preserved incomplete evidence; "
            "manual recovery required and automatic retry is forbidden"
        )
    checkpoint_record = _build_checkpoint(
        context,
        execution,
        evidence,
        created_at=_timestamp(),
    )
    checkpoint, checkpoint_state = checkpoint_store.write_locked(
        checkpoint_record, lock=lock
    )
    return _report(
        execution=execution,
        evidence=evidence,
        checkpoint=checkpoint,
        execution_state=DeployScyllaHealthArtifactState.CREATED,
        evidence_state=evidence_state,
        checkpoint_state=checkpoint_state,
    )


def deploy_scylla_health_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths, operation_id, DEPLOY_SCYLLA_HEALTH_EXECUTION_FILENAME_SUFFIX
    )


def deploy_scylla_health_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths, operation_id, DEPLOY_SCYLLA_HEALTH_EVIDENCE_FILENAME_SUFFIX
    )


def deploy_scylla_health_checkpoint_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths, operation_id, DEPLOY_SCYLLA_HEALTH_CHECKPOINT_FILENAME_SUFFIX
    )


def deploy_scylla_health_execution_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_HEALTH_EXECUTION_FILENAME_SUFFIX
    )


def deploy_scylla_health_evidence_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_HEALTH_EVIDENCE_FILENAME_SUFFIX
    )


def deploy_scylla_health_checkpoint_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_HEALTH_CHECKPOINT_FILENAME_SUFFIX
    )


def build_deploy_scylla_health_checkpoint(
    *,
    context: StoredDeployScyllaBootstrapContext,
    plan: StoredDeployScyllaBootstrapPlan,
    execution_artifact_digest: str,
    evidence_artifact_digest: str,
    evidence: DeployScyllaHealthEvidence,
    created_at: str,
) -> DeployScyllaHealthCheckpoint:
    """Reconcile strict current health without mutating the bootstrap plan."""
    if (
        not evidence.strict_complete
        or context.record.operation_id != plan.record.operation_id
        or context.record.record_digest != plan.record.context_record_digest
        or context.artifact_digest != plan.record.context_artifact_digest
    ):
        raise StateConflictError("deploy Scylla health checkpoint input conflicts")
    blockers = {
        f"{name}-not-proven"
        for name, state in evidence.join_gate_states
        if state is not HealthCheckStatus.PASSED
    }
    steps: list[DeployScyllaHealthCheckpointStep] = []
    next_join_sequence: int | None = None
    next_join_status = "not-required"
    next_join_blockers: tuple[str, ...] = ()
    for original in plan.record.steps:
        if original.sequence == 1:
            status = DeployScyllaHealthStepStatus.HEALTH_SUCCEEDED
            health_state = "complete-current-cluster-health"
            authorization_state = "not-required"
            step_blockers: tuple[str, ...] = ()
        elif original.sequence == 2:
            next_join_sequence = 2
            if blockers:
                status = DeployScyllaHealthStepStatus.BLOCKED
                health_state = "complete-current-cluster-health"
                authorization_state = "unavailable"
                step_blockers = tuple(sorted(blockers))
                next_join_status = status.value
            else:
                status = DeployScyllaHealthStepStatus.AUTHORIZATION_REQUIRED
                health_state = "complete-current-cluster-health"
                authorization_state = "authorization-required"
                step_blockers = ("join-authorization-not-collected",)
                next_join_status = status.value
            next_join_blockers = step_blockers
        else:
            status = DeployScyllaHealthStepStatus.WAITING
            health_state = "waiting-for-preceding-complete-health"
            authorization_state = "waiting"
            step_blockers = ("preceding-join-not-completed",)
        values: dict[str, object] = {
            "sequence": original.sequence,
            "mode": original.mode,
            "target_digest": original.target_digest,
            "original_step_digest": original.step_digest,
            "status": status,
            "health_checkpoint_state": health_state,
            "authorization_state": authorization_state,
            "blockers": step_blockers,
            "blocker_digest": _digest_object(list(step_blockers)),
            "step_digest": "",
            "schema_version": (
                ANSIBLE_DEPLOY_SCYLLA_HEALTH_CHECKPOINT_STEP_SCHEMA_VERSION
            ),
        }
        values["step_digest"] = _checkpoint_step_digest_from_values(values)
        steps.append(DeployScyllaHealthCheckpointStep(**values))  # type: ignore[arg-type]
    values = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": plan.record.cluster_uuid,
        "cluster_name": plan.record.cluster_name,
        "operation_id": plan.record.operation_id,
        "operation": _OPERATION,
        "request_digest": plan.record.request_digest,
        "journal_generation": plan.record.journal_generation,
        "journal_digest": plan.record.journal_digest,
        "journal_status": plan.record.journal_status,
        "journal_phase": plan.record.journal_phase,
        "bootstrap_context_artifact_digest": context.artifact_digest,
        "bootstrap_context_record_digest": context.record.record_digest,
        "bootstrap_plan_artifact_digest": plan.artifact_digest,
        "bootstrap_plan_digest": plan.record.plan_digest,
        "health_execution_artifact_digest": execution_artifact_digest,
        "health_evidence_artifact_digest": evidence_artifact_digest,
        "health_evidence_digest": evidence.evidence_digest,
        "active_member_count": evidence.binding.active_member_count,
        "active_member_set_digest": evidence.binding.active_member_set_digest,
        "desired_member_count": evidence.binding.desired_member_count,
        "desired_member_set_digest": evidence.binding.desired_member_set_digest,
        "future_member_count": evidence.binding.future_member_count,
        "future_member_set_digest": evidence.binding.future_member_set_digest,
        "steps": tuple(steps),
        "step_count": len(steps),
        "health_succeeded_count": 1,
        "authorization_required_count": sum(
            item.status is DeployScyllaHealthStepStatus.AUTHORIZATION_REQUIRED
            for item in steps
        ),
        "blocked_count": sum(
            item.status is DeployScyllaHealthStepStatus.BLOCKED for item in steps
        ),
        "waiting_count": sum(
            item.status is DeployScyllaHealthStepStatus.WAITING for item in steps
        ),
        "next_join_sequence": next_join_sequence,
        "next_join_status": next_join_status,
        "next_join_blocker_digest": _digest_object(list(next_join_blockers)),
        "checkpoint_digest": "",
        "journal_schema_version": JOURNAL_SCHEMA_VERSION,
        "schema_version": ANSIBLE_DEPLOY_SCYLLA_HEALTH_CHECKPOINT_SCHEMA_VERSION,
    }
    values["checkpoint_digest"] = _checkpoint_digest_from_values(values)
    return DeployScyllaHealthCheckpoint(**values)  # type: ignore[arg-type]


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
    bootstrap_execution_context = _load_bootstrap_execution_context(
        paths,
        operation_id,
        lock=lock,
        builder=builder,
        toolchain=toolchain,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    bootstrap = _load_authorization_context(paths, operation_id, lock=lock)
    configure = _load_reconciliation_context(paths, operation_id, lock=lock)
    loaded = _loaded(configure.authorization_context)
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    inventory = bootstrap_execution_context.inventory
    current_readiness = _reconstructed_readiness(planning.base)
    current_readiness.require_ready(OperationClassification.READ_ONLY)
    # Playbook payload contracts bind the complete observed artifact while the
    # generic readiness projection retains its source-manifest digest.
    readiness = replace(
        current_readiness,
        observation_digest=deploy.observation.digest,
    )
    execution = DeployScyllaBootstrapExecutionStore(paths, operation_id).read_locked(
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
    entry = bootstrap_evidence.record.entry
    if (
        execution.record.state is not DeployScyllaBootstrapExecutionState.SUCCEEDED
        or execution.record.binding != bootstrap_execution_context.binding
        or bootstrap_evidence.record.binding != bootstrap_execution_context.binding
        or execution.record.attempt.evidence_digest != entry.evidence_digest
        or entry.status is not ScyllaBootstrapStatus.BOOTSTRAPPED
        or entry.host_id_digest is None
        or not entry.service_active
        or not entry.cql_ready
        or not entry.nodetool_membership_verified
        or not entry.schema_agreement
        or not entry.streaming_complete
        or entry.recovery_required
    ):
        raise StateConflictError(
            "deploy Scylla health requires exact successful initial-seed evidence"
        )
    plan = bootstrap.plan.record
    hosts = {
        host.logical_id: host
        for host in inventory.record.inventory.hosts
        if host.role is HostRole.SCYLLA
    }
    by_digest = {_digest_object(stable_id): stable_id for stable_id in hosts}
    try:
        desired_ids = tuple(by_digest[step.target_digest] for step in plan.steps)
    except KeyError as error:
        raise StateConflictError(
            "deploy Scylla health desired topology no longer matches inventory"
        ) from error
    if len(desired_ids) != len(set(desired_ids)):
        raise StateConflictError("deploy Scylla health desired topology is ambiguous")
    active_ids = (entry.stable_id,)
    if active_ids != desired_ids[:1]:
        raise StateConflictError(
            "deploy Scylla health active bootstrap prefix conflicts"
        )
    future_ids = desired_ids[1:]
    storage_entries = {
        item.stable_id: item
        for item in configure.authorization_context.install.authorization_context.evidence.record.entries
        if item.stable_id in active_ids
    }
    if set(storage_entries) != set(active_ids):
        raise StateConflictError("deploy Scylla health storage evidence is incomplete")
    storage_bindings = {
        stable_id: (
            storage_entries[stable_id].readiness_for_scylla,
            storage_entries[stable_id].evidence_digest,
        )
        for stable_id in active_ids
    }
    provenance_conflicts = tuple(
        name
        for name, conflicts in (
            (
                "observation-generation",
                readiness.observation_generation
                != deploy.observation.record.generation,
            ),
            (
                "observation-digest",
                readiness.observation_digest != deploy.observation.digest,
            ),
            (
                "inventory-generation",
                readiness.inventory_generation != inventory.record.generation,
            ),
            ("inventory-digest", readiness.inventory_digest != inventory.digest),
            ("trust-generation", readiness.trust_generation is None),
            ("trust-digest", readiness.trust_digest is None),
        )
        if conflicts
    )
    if provenance_conflicts:
        raise StateConflictError(
            "deploy Scylla health readiness provenance conflicts: "
            + ", ".join(provenance_conflicts)
        )
    payload = build_scylla_health_payload(
        metadata,
        deploy.observation,
        inventory,
        readiness,
        (),
        limit=active_ids,
        timeout_seconds=_TIMEOUT_SECONDS,
        active_stable_ids=active_ids,
        storage_bindings=storage_bindings,
    )
    variables = (("deploy_scylla_vms_scylla_health", payload),)
    definition, _, variables_digest, command_digest = builder.validate_operation_step(
        _PLAYBOOK,
        step_sequence=1,
        limit=active_ids,
        variables=dict(variables),
        tags=(_PLAYBOOK,),
        check=True,
        diff=False,
        verbosity=0,
    )
    source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
    if (
        definition.classification is not OperationClassification.READ_ONLY
        or definition.hosts != HostRole.SCYLLA.value
        or definition.serial != 5
        or definition.any_errors_fatal
        or definition.limit_policy is not LimitPolicy.EXPLICIT
        or definition.check_mode is not CheckMode.SUPPORTED
        or not definition.source_available
    ):
        raise StateConflictError(
            "deploy Scylla health catalog or source policy conflicts"
        )
    journal = deploy.journal
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
        "bootstrap_context_artifact_digest": bootstrap.context.artifact_digest,
        "bootstrap_context_record_digest": bootstrap.context.record.record_digest,
        "bootstrap_plan_artifact_digest": bootstrap.plan.artifact_digest,
        "bootstrap_plan_digest": bootstrap.plan.record.plan_digest,
        "bootstrap_execution_artifact_digest": execution.artifact_digest,
        "bootstrap_execution_binding_digest": execution.record.binding.binding_digest,
        "bootstrap_evidence_artifact_digest": bootstrap_evidence.artifact_digest,
        "bootstrap_evidence_digest": entry.evidence_digest,
        "post_configure_artifact_digest": (
            bootstrap.context.record.post_configure_artifact_digest
        ),
        "observation_generation": deploy.observation.record.generation,
        "observation_artifact_digest": deploy.observation.digest,
        "observation_manifest_digest": deploy.observation.record.manifest_digest,
        "inventory_generation": inventory.record.generation,
        "inventory_artifact_digest": inventory.digest,
        "inventory_digest": inventory.record.inventory_digest,
        "trust_generation": planning.base.trust.record.generation,
        "trust_artifact_digest": planning.base.trust.digest,
        "trust_entries_digest": planning.base.trust.record.entries_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": planning.readiness.record.record_digest,
        "source_version": ANSIBLE_SOURCE_VERSION,
        "source_digest": loaded.source.digest,
        "playbook_source_digest": source_digest,
        "catalog_digest": loaded.catalog_digest,
        "toolchain_version": str(toolchain.core),
        "executable_identity_digest": executable_identity_digest,
        "toolchain_evidence_digest": toolchain_evidence_digest,
        "active_member_count": len(active_ids),
        "active_member_set_digest": _digest_object(list(active_ids)),
        "desired_member_count": len(desired_ids),
        "desired_member_set_digest": _digest_object(list(desired_ids)),
        "future_member_count": len(future_ids),
        "future_member_set_digest": _digest_object(list(future_ids)),
        "desired_topology_digest": _digest_object(
            [
                {
                    "datacenter_digest": step.datacenter_digest,
                    "mode": step.mode.value,
                    "rack_digest": step.rack_digest,
                    "target_digest": step.target_digest,
                }
                for step in plan.steps
            ]
        ),
        "bootstrap_host_id_digest": entry.host_id_digest,
        "storage_evidence_digest": _digest_object(
            [storage_entries[item].evidence_digest for item in active_ids]
        ),
        "variables_digest": variables_digest,
        "command_digest": command_digest,
        "binding_digest": "",
        "journal_schema_version": JOURNAL_SCHEMA_VERSION,
        "schema_version": (
            ANSIBLE_DEPLOY_SCYLLA_HEALTH_EXECUTION_BINDING_SCHEMA_VERSION
        ),
    }
    serialized_binding = {
        name: (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(item, StrEnum)
            else item
        )
        for name, item in binding_values.items()
    }
    binding_values["binding_digest"] = _binding_digest_from_values(serialized_binding)
    binding = DeployScyllaHealthExecutionBinding(**binding_values)  # type: ignore[arg-type]
    return _HealthContext(
        bootstrap_context=bootstrap.context,
        bootstrap_plan=bootstrap.plan,
        binding=binding,
        metadata=metadata,
        inventory=inventory,
        readiness=readiness,
        payload=payload,
        variables=variables,
        active_ids=active_ids,
        desired_ids=desired_ids,
        future_ids=future_ids,
    )


def _semantic_evidence(
    context: _HealthContext, result: AnsibleExecutionResult
) -> DeployScyllaHealthEvidence:
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.READ_ONLY
        or not result.check_mode
        or result.scylla_health is not None
    ):
        raise AnsibleResultError("deploy Scylla health result identity conflicts")
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
        nodes.append(DeployScyllaHealthEvidenceNode(**node_values))  # type: ignore[arg-type]
    strict_states = tuple((name, checks[name]) for name in _STRICT_CHECKS)
    policy_states = tuple((name, checks[name]) for name in _REQUIRED_POLICY_CHECKS)
    policy = dict(policy_states)
    host_digests = tuple(item.host_id_digest for item in nodes)
    node_health_complete = bool(nodes) and all(
        item.membership_state == "UN"
        and item.service_ready
        and item.api_ready
        and item.cql_ready
        and item.storage_ready
        and item.streaming_idle
        and item.version_digest == _digest_object(SCYLLA_PACKAGE_VERSION)
        and item.blocker_count == 0
        for item in nodes
    )
    join_gate_states = (
        (
            "target-absence",
            (
                HealthCheckStatus.PASSED
                if checks["cross-view-consistency"] is HealthCheckStatus.PASSED
                and checks["membership"] is HealthCheckStatus.PASSED
                else HealthCheckStatus.FAILED
            ),
        ),
        (
            "survivor-health",
            (
                HealthCheckStatus.PASSED
                if node_health_complete
                else HealthCheckStatus.FAILED
            ),
        ),
        (
            "seed-health",
            (
                HealthCheckStatus.PASSED
                if node_health_complete and nodes[0].stable_id == context.active_ids[0]
                else HealthCheckStatus.FAILED
            ),
        ),
        ("topology", checks["topology"]),
        ("schema", checks["schema-agreement"]),
        ("capacity", policy["capacity"]),
        ("replication", policy["replication"]),
        ("quorum", policy["quorum"]),
        ("backup-policy", policy["backup-policy"]),
    )
    strict_complete = (
        parsed.status is HealthReadiness.UNKNOWN
        and parsed.query_policy == "all-nodes-cross-view"
        and parsed.queried_nodes == context.active_ids
        and tuple(item.stable_id for item in nodes) == context.active_ids
        and len(nodes) == context.binding.active_member_count
        and all(item is not None for item in host_digests)
        and len(set(host_digests)) == len(host_digests)
        and nodes[0].host_id_digest == context.binding.bootstrap_host_id_digest
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
            "host_id_mapping_digest": _digest_object(
                [[item.stable_id_digest, item.host_id_digest] for item in nodes]
            ),
            "policy_states": [[name, state.value] for name, state in policy_states],
            "query_policy": parsed.query_policy,
            "status": parsed.status.value,
        }
    )
    membership_digest = _digest_object(
        [
            [item.stable_id_digest, item.host_id_digest, item.membership_state]
            for item in nodes
        ]
    )
    values: dict[str, object] = {
        "generation": 1,
        "created_at": _timestamp(),
        "binding": context.binding,
        "health_status": parsed.status,
        "query_policy": parsed.query_policy,
        "nodes": tuple(nodes),
        "host_id_mapping_digest": _digest_object(
            [[item.stable_id_digest, item.host_id_digest] for item in nodes]
        ),
        "membership_digest": membership_digest,
        "topology_digest": parsed.topology_digest,
        "schema_digest": parsed.schema_digest,
        "schema_agreement": parsed.schema_agreement is True,
        "streaming_state": parsed.streaming_state,
        "check_states": strict_states,
        "policy_states": policy_states,
        "join_gate_states": join_gate_states,
        "blocker_count": len(parsed.blockers),
        "blocker_digest": _digest_object(list(parsed.blockers)),
        "strict_complete": strict_complete,
        "result_digest": result_digest,
        "evidence_digest": "",
        "result_schema_version": SCYLLA_HEALTH_SCHEMA_VERSION,
        "schema_version": ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_SCHEMA_VERSION,
    }
    values["evidence_digest"] = _health_evidence_digest_from_values(values)
    return DeployScyllaHealthEvidence(**values)  # type: ignore[arg-type]


def _build_checkpoint(
    context: _HealthContext,
    execution: StoredDeployScyllaHealthExecution,
    evidence: StoredDeployScyllaHealthEvidence,
    *,
    created_at: str,
) -> DeployScyllaHealthCheckpoint:
    if (
        execution.record.binding != context.binding
        or execution.record.state is not DeployScyllaHealthExecutionState.SUCCEEDED
        or execution.record.evidence_digest != evidence.record.evidence_digest
        or evidence.record.binding != context.binding
    ):
        raise StateConflictError("deploy Scylla health checkpoint prefix conflicts")
    return build_deploy_scylla_health_checkpoint(
        context=context.bootstrap_context,
        plan=context.bootstrap_plan,
        execution_artifact_digest=execution.artifact_digest,
        evidence_artifact_digest=evidence.artifact_digest,
        evidence=evidence.record,
        created_at=created_at,
    )


def _validate_prefix(
    context: _HealthContext,
    execution: StoredDeployScyllaHealthExecution | None,
    evidence: StoredDeployScyllaHealthEvidence | None,
    checkpoint: StoredDeployScyllaHealthCheckpoint | None,
) -> None:
    if execution is None:
        if evidence is not None or checkpoint is not None:
            raise StateConflictError(
                "deploy Scylla health artifacts exist without execution intent"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError("deploy Scylla health execution binding drifted")
    if evidence is not None and (
        evidence.record.binding != context.binding
        or execution.record.evidence_digest != evidence.record.evidence_digest
    ):
        raise StateConflictError("deploy Scylla health evidence binding conflicts")
    if checkpoint is not None:
        if evidence is None:
            raise StateConflictError(
                "deploy Scylla health checkpoint evidence is unavailable"
            )
        expected = _build_checkpoint(
            context,
            execution,
            evidence,
            created_at=checkpoint.record.created_at,
        )
        if checkpoint.record != expected:
            raise StateConflictError("deploy Scylla health checkpoint drifted")


def _persist_started(
    store: DeployScyllaHealthExecutionStore,
    context: _HealthContext,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaHealthExecution:
    now = _timestamp()
    return store.write_locked(
        DeployScyllaHealthExecution(
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
    store: DeployScyllaHealthExecutionStore,
    current: StoredDeployScyllaHealthExecution,
    state: DeployScyllaHealthExecutionState,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaHealthExecution:
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
    store: DeployScyllaHealthExecutionStore,
    current: StoredDeployScyllaHealthExecution,
    *,
    evidence: StoredDeployScyllaHealthEvidence,
    result: AnsibleExecutionResult,
    state: DeployScyllaHealthExecutionState,
    lock: ClusterLock,
) -> StoredDeployScyllaHealthExecution:
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
    execution: StoredDeployScyllaHealthExecution,
    evidence: StoredDeployScyllaHealthEvidence,
    checkpoint: StoredDeployScyllaHealthCheckpoint,
    execution_state: DeployScyllaHealthArtifactState,
    evidence_state: DeployScyllaHealthArtifactState,
    checkpoint_state: DeployScyllaHealthArtifactState,
) -> DeployScyllaHealthReport:
    record = evidence.record
    policy_unknown = sum(
        state in {HealthCheckStatus.UNKNOWN, HealthCheckStatus.NOT_PERFORMED}
        for _, state in record.policy_states
    )
    return DeployScyllaHealthReport(
        operation_id=record.binding.operation_id,
        stage=_STAGE,
        execution_state=execution.record.state,
        execution_artifact_state=execution_state,
        evidence_artifact_state=evidence_state,
        checkpoint_artifact_state=checkpoint_state,
        active_member_count=record.binding.active_member_count,
        desired_member_count=record.binding.desired_member_count,
        future_member_count=record.binding.future_member_count,
        health_complete=record.strict_complete,
        host_identity_count=sum(
            item.host_id_digest is not None for item in record.nodes
        ),
        up_normal_count=sum(item.membership_state == "UN" for item in record.nodes),
        service_ready_count=sum(item.service_ready for item in record.nodes),
        api_ready_count=sum(item.api_ready for item in record.nodes),
        cql_ready_count=sum(item.cql_ready for item in record.nodes),
        storage_ready_count=sum(item.storage_ready for item in record.nodes),
        version_ready_count=sum(
            item.version_digest == _digest_object(SCYLLA_PACKAGE_VERSION)
            for item in record.nodes
        ),
        schema_agreement=record.schema_agreement,
        streaming_idle=record.streaming_state == "complete",
        policy_unknown_count=policy_unknown,
        next_join_status=checkpoint.record.next_join_status,
        next_join_blocker_count=(
            0
            if checkpoint.record.next_join_sequence is None
            else next(
                len(item.blockers)
                for item in checkpoint.record.steps
                if item.sequence == checkpoint.record.next_join_sequence
            )
        ),
        manual_recovery_required=execution.record.manual_recovery_required,
        automatic_retry_allowed=False,
        journal_status=record.binding.journal_status,
        journal_phase=record.binding.journal_phase,
        journal_updated=False,
        execution_artifact_digest=execution.artifact_digest,
        evidence_artifact_digest=evidence.artifact_digest,
        checkpoint_artifact_digest=checkpoint.artifact_digest,
        evidence_digest=record.evidence_digest,
        checkpoint_digest=checkpoint.record.checkpoint_digest,
    )


def _read_execution(
    store: DeployScyllaHealthExecutionStore,
    context: _HealthContext,
    lock: ClusterLock,
) -> StoredDeployScyllaHealthExecution | None:
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
    store: DeployScyllaHealthEvidenceStore,
    context: _HealthContext,
    lock: ClusterLock,
) -> StoredDeployScyllaHealthEvidence | None:
    return (
        store.read_locked(
            lock,
            expected_cluster_uuid=context.binding.cluster_uuid,
            expected_cluster_name=context.binding.cluster_name,
        )
        if store.path.exists()
        else None
    )


def _read_checkpoint(
    store: DeployScyllaHealthCheckpointStore,
    context: _HealthContext,
    lock: ClusterLock,
) -> StoredDeployScyllaHealthCheckpoint | None:
    return (
        store.read_locked(
            lock,
            expected_cluster_uuid=context.binding.cluster_uuid,
            expected_cluster_name=context.binding.cluster_name,
        )
        if store.path.exists()
        else None
    )


def _binding_digest(record: DeployScyllaHealthExecutionBinding) -> str:
    return _binding_digest_from_values(record.to_object())


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value = dict(values)
    value["binding_digest"] = ""
    return _digest_object(_json_value(value))


def _node_evidence_digest(record: DeployScyllaHealthEvidenceNode) -> str:
    return _node_evidence_digest_from_values(record.to_object())


def _node_evidence_digest_from_values(values: Mapping[str, object]) -> str:
    value = dict(values)
    value["evidence_digest"] = ""
    return _digest_object(_json_value(value))


def _health_evidence_digest(record: DeployScyllaHealthEvidence) -> str:
    return _health_evidence_digest_from_values(record.to_object())


def _health_evidence_digest_from_values(values: Mapping[str, object]) -> str:
    value = dict(values)
    value["evidence_digest"] = ""
    return _digest_object(_json_value(value))


def _checkpoint_step_digest(record: DeployScyllaHealthCheckpointStep) -> str:
    return _checkpoint_step_digest_from_values(record.to_object())


def _checkpoint_step_digest_from_values(values: Mapping[str, object]) -> str:
    value = dict(values)
    value["step_digest"] = ""
    return _digest_object(_json_value(value))


def _checkpoint_digest(record: DeployScyllaHealthCheckpoint) -> str:
    return _checkpoint_digest_from_values(record.to_object())


def _checkpoint_digest_from_values(values: Mapping[str, object]) -> str:
    value = dict(values)
    value["checkpoint_digest"] = ""
    return _digest_object(_json_value(value))


def _catalog_digest(definition: PlaybookDefinition) -> str:
    return _digest_object(
        {
            "check_mode": definition.check_mode.value,
            "classification": definition.classification.value,
            "limit_policy": definition.limit_policy.value,
            "name": definition.name,
            "serial": definition.serial,
            "source_available": definition.source_available,
        }
    )


def _digest_text(value: str) -> str:
    return digest_bytes(value.encode("utf-8"))


def _artifact_path(paths: StatePaths, operation_id: uuid.UUID, suffix: str) -> Path:
    _require_canonical_paths(paths)
    path = paths.operations / f"{_require_operation_id(operation_id)}{suffix}"
    if path.parent != paths.operations:
        raise StatePersistenceError("deploy Scylla health path is not canonical")
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
    if isinstance(error, ProcessTimeoutError):
        return DeployScyllaHealthExecutionState.TIMED_OUT
    if isinstance(error, ProcessOutputError):
        return DeployScyllaHealthExecutionState.MALFORMED_RESULT
    return DeployScyllaHealthExecutionState.UNREACHABLE


def _require_identity(
    binding: DeployScyllaHealthExecutionBinding,
    *,
    operation_id: uuid.UUID,
    cluster_uuid: uuid.UUID,
    cluster_name: str,
) -> None:
    if (
        binding.operation_id != operation_id
        or binding.cluster_uuid != cluster_uuid
        or binding.cluster_name != cluster_name
    ):
        raise StatePersistenceError("deploy Scylla health identity conflicts")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy Scylla health requires an acquired deploy operation lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _require_canonical_paths(paths: StatePaths) -> None:
    if StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths:
        raise StatePersistenceError("deploy Scylla health paths are not canonical")


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_SCYLLA_HEALTH_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_HEALTH_EVIDENCE_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_HEALTH_CHECKPOINT_FILENAME_SUFFIX,
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Scylla health artifacts"
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
                raise StateConflictError("deploy Scylla health artifacts are ambiguous")


def _timestamp() -> str:
    return format_timestamp(datetime.now(UTC))


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


def _dataclass_object(
    value: object,
    *,
    tuple_fields: set[str] | None = None,
    step_fields: set[str] | None = None,
) -> dict[str, object]:
    tuples = tuple_fields or set()
    steps = step_fields or set()
    result: dict[str, object] = {}
    for name in value.__dataclass_fields__:  # type: ignore[attr-defined]
        item = getattr(value, name)
        result[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(item, StrEnum)
            else [entry.to_object() for entry in item]
            if name in steps
            else list(item)
            if name in tuples
            else item.to_object()
            if hasattr(item, "to_object")
            else item
        )
    return result


def _digest_fields(value: object) -> tuple[str | None, ...]:
    return tuple(
        getattr(value, name)
        for name in value.__dataclass_fields__  # type: ignore[attr-defined]
        if name.endswith("_digest")
    )


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise StatePersistenceError(f"deploy Scylla health {label} is invalid")
    return value


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise StatePersistenceError(f"deploy Scylla health {label} is invalid")
    return value


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise StatePersistenceError(f"deploy Scylla health {label} is invalid")
    return tuple(value)


def _status_pairs(
    value: object, label: str
) -> tuple[tuple[str, HealthCheckStatus], ...]:
    if not isinstance(value, list):
        raise StatePersistenceError(f"deploy Scylla health {label} is invalid")
    try:
        return tuple(
            (
                require_string(_mapping({"name": item[0]}, label), "name"),
                HealthCheckStatus(item[1]),
            )
            for item in value
            if isinstance(item, list) and len(item) == 2 and isinstance(item[1], str)
        )
    except (IndexError, ValueError) as error:
        raise StatePersistenceError(
            f"deploy Scylla health {label} is invalid"
        ) from error


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"deploy Scylla health {label} is invalid")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    return None if value is None else _integer(value, label)


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"deploy Scylla health {label} is invalid")
    return value


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise StatePersistenceError(f"deploy Scylla health {label} is invalid")
    return value
