"""Immutable deploy-only Manager activation context and plan bridge.

The historical 21-position deploy mapping reaches ``manager-tasks`` without
modeling the prerequisite Manager backend, service, and registration work.
This subprocess-free owner preserves that mapping and persists a separate,
redacted context and ordered plan.  It does not authorize or execute any
boundary and does not choose a Manager task action.
"""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import Field, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from scylla_vms.ansible.deploy_monitoring_targets_reconciliation import (
    ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_SCHEMA_VERSION,
    DeployPostMonitoringTargetsReconciliationStore,
    StoredDeployPostMonitoringTargetsReconciliation,
)
from scylla_vms.ansible.deploy_monitoring_targets_reconciliation import (
    _build_record as _build_post_targets_record,
)
from scylla_vms.ansible.deploy_monitoring_targets_reconciliation import (
    _build_steps as _build_post_targets_steps,
)
from scylla_vms.ansible.deploy_monitoring_targets_reconciliation import (
    _load_context as _load_post_targets_context,
)
from scylla_vms.ansible.deploy_plan import (
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import _loaded
from scylla_vms.ansible.deploy_scylla_configure_reconciliation import _mapping_digest
from scylla_vms.ansible.manager_agent import (
    MANAGER_AGENT_SCHEMA_VERSION,
    ManagerAgentStatus,
)
from scylla_vms.ansible.manager_agent import (
    MANAGER_PACKAGE_VERSION as MANAGER_AGENT_PACKAGE_VERSION,
)
from scylla_vms.ansible.manager_agent import (
    MANAGER_RELEASE_LINE as MANAGER_AGENT_RELEASE_LINE,
)
from scylla_vms.ansible.manager_server import (
    MANAGER_PACKAGE_VERSION as MANAGER_SERVER_PACKAGE_VERSION,
)
from scylla_vms.ansible.manager_server import (
    MANAGER_RELEASE_LINE as MANAGER_SERVER_RELEASE_LINE,
)
from scylla_vms.ansible.manager_server import (
    MANAGER_SERVER_SCHEMA_VERSION,
    ManagerServerStatus,
)
from scylla_vms.ansible.manager_tasks import (
    EXPECTED_BLOCKERS as MANAGER_TASK_EXPECTED_BLOCKERS,
)
from scylla_vms.ansible.manager_tasks import (
    MANAGER_TASK_ACTIONS,
    MANAGER_TASK_KINDS,
    MANAGER_TASKS_SCHEMA_VERSION,
)
from scylla_vms.ansible.manager_tasks import (
    NOT_PERFORMED as MANAGER_TASK_NOT_PERFORMED,
)
from scylla_vms.ansible.registry import (
    OPERATION_PLAYBOOKS,
    PLAYBOOK_NAMES,
    get_playbook,
)
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION
from scylla_vms.desired import HostRole
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
from scylla_vms.terraform.apply_readiness import (
    TERRAFORM_APPLY_READINESS_SCHEMA_VERSION,
)

ANSIBLE_DEPLOY_MANAGER_ACTIVATION_CONTEXT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-activation-context/v1"
)
ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_STEP_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-activation-plan-step/v1"
)
ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-activation-plan/v1"
)
ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-activation-plan-report/v1"
)
DEPLOY_MANAGER_ACTIVATION_CONTEXT_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-activation-context.json"
)
DEPLOY_MANAGER_ACTIVATION_PLAN_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-activation-plan.json"
)

_OPERATION = "deploy"
_ORIGINAL_MAPPING_COUNT = 21
_MANAGER_TASKS_MAPPING = 19
_MANAGER_TASKS_PLAYBOOK = "manager-tasks"
_NOT_PERFORMED = "not-performed"
_UNAVAILABLE = "unavailable"
_ACTION_UNMODELED = "manager-tasks-action-unmodeled"
_NEXT_IMPLEMENTATION_CONTRACT = "manager-backend-configuration-owner"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")

_BOUNDARY_DEFINITIONS = (
    (
        "backend-configure",
        OperationClassification.MUTATING,
        HostRole.MANAGER.value,
        "source-unavailable",
    ),
    (
        "manager-start",
        OperationClassification.MUTATING,
        HostRole.MANAGER.value,
        "source-unavailable",
    ),
    (
        "cluster-registration-auth-token-handoff",
        OperationClassification.SENSITIVE,
        "manager-and-scylla",
        "source-unavailable",
    ),
    (
        _MANAGER_TASKS_PLAYBOOK,
        OperationClassification.SENSITIVE,
        HostRole.MANAGER.value,
        "source-available",
    ),
)

_BOUNDARY_BLOCKERS = (
    (
        "manager-backend-configuration-authorization-required",
        "manager-backend-configuration-evidence-required",
        "manager-backend-configuration-source-unavailable",
    ),
    (
        "manager-backend-configuration-not-performed",
        "manager-service-activation-authorization-required",
        "manager-service-activation-evidence-required",
        "manager-service-activation-source-unavailable",
    ),
    (
        "manager-agent-auth-token-not-performed",
        "manager-backend-not-performed",
        "manager-cluster-registration-authorization-required",
        "manager-cluster-registration-evidence-required",
        "manager-cluster-registration-source-unavailable",
        "manager-service-readiness-not-performed",
    ),
    (
        "manager-backend-not-performed",
        "manager-inactive",
        "manager-tasks-action-unmodeled",
        "manager-task-authorization-required",
        "manager-task-evidence-required",
        "manager-tasks-validation-only",
        "manager-unregistered",
        "ordered-manager-activation-boundary-not-reached",
    ),
)


class DeployManagerActivationArtifactState(StrEnum):
    """Immutable context/plan persistence result."""

    CREATED = "created"
    REUSED = "reused"


class DeployManagerActivationSourceState(StrEnum):
    """Whether one exact reviewed executable source exists."""

    AVAILABLE = "source-available"
    UNAVAILABLE = "source-unavailable"


class DeployManagerActivationBoundaryStatus(StrEnum):
    """Planning status; no boundary is execution-ready in this slice."""

    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class DeployManagerActivationContext:
    """Current value-free Manager installation and activation prerequisites."""

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
    post_targets_artifact_digest: str
    post_targets_record_digest: str
    post_targets_effective_plan_digest: str
    original_mapping_count: int
    original_mapping_digest: str
    original_mapping_unchanged: bool
    metadata_generation: int
    metadata_artifact_digest: str
    desired_spec_digest: str
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
    catalog_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    manager_target_id: str
    manager_target_digest: str
    manager_agent_target_ids: tuple[str, ...]
    manager_agent_target_count: int
    manager_agent_target_set_digest: str
    topology_digest: str
    identity_provenance_digest: str
    manager_server_evidence_artifact_digest: str
    manager_server_evidence_digest: str
    manager_server_provenance_digest: str
    manager_server_package_version_digest: str
    manager_server_source_digest: str
    manager_agent_evidence_artifact_digest: str
    manager_agent_evidence_set_digest: str
    manager_agent_provenance_set_digest: str
    manager_agent_package_version_digest: str
    manager_agent_source_digest: str
    manager_package_release_digest: str
    manager_package_provenance_digest: str
    manager_tasks_source_digest: str
    manager_tasks_contract_digest: str
    manager_tasks_action_state: str
    manager_tasks_action_digest: str
    manager_backend_state: str
    manager_service_state: str
    manager_registration_state: str
    manager_agent_token_state: str
    blocker_count: int
    blockers: tuple[str, ...]
    blocker_digest: str
    next_implementation_contract: str
    authorization_state: str
    execution_state: str
    public_workflow_state: str
    record_digest: str
    post_targets_schema_version: str = (
        ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_SCHEMA_VERSION
    )
    manager_server_schema_version: str = MANAGER_SERVER_SCHEMA_VERSION
    manager_agent_schema_version: str = MANAGER_AGENT_SCHEMA_VERSION
    manager_tasks_schema_version: str = MANAGER_TASKS_SCHEMA_VERSION
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_ACTIVATION_CONTEXT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_ACTIVATION_CONTEXT_SCHEMA_VERSION
            or self.post_targets_schema_version
            != ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_SCHEMA_VERSION
            or self.manager_server_schema_version != MANAGER_SERVER_SCHEMA_VERSION
            or self.manager_agent_schema_version != MANAGER_AGENT_SCHEMA_VERSION
            or self.manager_tasks_schema_version != MANAGER_TASKS_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.original_mapping_count != _ORIGINAL_MAPPING_COUNT
            or self.original_mapping_digest != _mapping_digest()
            or not self.original_mapping_unchanged
            or _LOGICAL_ID.fullmatch(self.manager_target_id) is None
            or self.manager_target_digest != _digest_object([self.manager_target_id])
            or not self.manager_agent_target_ids
            or self.manager_agent_target_ids
            != tuple(sorted(set(self.manager_agent_target_ids)))
            or any(
                _LOGICAL_ID.fullmatch(item) is None
                for item in self.manager_agent_target_ids
            )
            or self.manager_agent_target_count != len(self.manager_agent_target_ids)
            or self.manager_agent_target_set_digest
            != _digest_object(list(self.manager_agent_target_ids))
            or self.manager_tasks_action_state != _ACTION_UNMODELED
            or self.manager_backend_state != _NOT_PERFORMED
            or self.manager_service_state != _NOT_PERFORMED
            or self.manager_registration_state != _NOT_PERFORMED
            or self.manager_agent_token_state != _NOT_PERFORMED
            or self.blocker_count != len(self.blockers)
            or self.blockers != tuple(sorted(set(self.blockers)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blockers)
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.next_implementation_contract != _NEXT_IMPLEMENTATION_CONTRACT
            or self.authorization_state != _UNAVAILABLE
            or self.execution_state != _NOT_PERFORMED
            or self.public_workflow_state != _UNAVAILABLE
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.record_digest != _context_record_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Manager activation context identity or summary conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for value in (
            self.journal_generation,
            self.metadata_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
            self.manager_agent_target_count,
        ):
            _positive_integer(value, "deploy Manager activation context count")
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy Manager activation context digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(
            self, tuple_fields={"manager_agent_target_ids", "blockers"}
        )

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployManagerActivationContext:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager activation context",
        )
        integers = {
            "generation",
            "journal_generation",
            "original_mapping_count",
            "metadata_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
            "manager_agent_target_count",
            "blocker_count",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in integers:
                    parsed[name] = _integer(item, name)
                elif name == "original_mapping_unchanged":
                    parsed[name] = _boolean(item, name)
                elif name in {"cluster_uuid", "operation_id"}:
                    parsed[name] = parse_uuid(require_string(value, name), name)
                elif name == "journal_status":
                    parsed[name] = JournalStatus(require_string(value, name))
                elif name == "journal_phase":
                    parsed[name] = OperationPhase(require_string(value, name))
                elif name in {"manager_agent_target_ids", "blockers"}:
                    parsed[name] = _string_tuple(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Manager activation context enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployManagerActivationContext:
    record: DeployManagerActivationContext
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class DeployManagerActivationPlanStep:
    """One ordered, non-executable Manager activation boundary."""

    sequence: int
    boundary: str
    classification: OperationClassification
    target_role: str
    target_ids: tuple[str, ...]
    target_count: int
    target_set_digest: str
    source_state: DeployManagerActivationSourceState
    source_digest: str | None
    package_provenance_digest: str
    identity_provenance_digest: str
    topology_digest: str
    prerequisite_step_digest: str | None
    authorization_requirement: str
    evidence_requirement: str
    performance_state: str
    manager_tasks_action_state: str
    status: DeployManagerActivationBoundaryStatus
    blockers: tuple[str, ...]
    blocker_digest: str
    step_digest: str
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_STEP_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not 1 <= self.sequence <= len(_BOUNDARY_DEFINITIONS):
            raise StatePersistenceError(
                "deploy Manager activation plan sequence is invalid"
            )
        expected = _BOUNDARY_DEFINITIONS[self.sequence - 1]
        expected_source = DeployManagerActivationSourceState(expected[3])
        expected_blockers = tuple(sorted(_BOUNDARY_BLOCKERS[self.sequence - 1]))
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_STEP_SCHEMA_VERSION
            or self.boundary != expected[0]
            or self.classification is not expected[1]
            or self.target_role != expected[2]
            or self.target_ids != tuple(sorted(set(self.target_ids)))
            or not self.target_ids
            or any(_LOGICAL_ID.fullmatch(item) is None for item in self.target_ids)
            or self.target_count != len(self.target_ids)
            or self.target_set_digest != _digest_object(list(self.target_ids))
            or self.source_state is not expected_source
            or (
                self.source_digest is None
                if self.source_state is DeployManagerActivationSourceState.AVAILABLE
                else self.source_digest is not None
            )
            or (
                self.prerequisite_step_digest is not None
                if self.sequence == 1
                else self.prerequisite_step_digest is None
            )
            or self.authorization_requirement != "authorization-required"
            or self.evidence_requirement != "evidence-required"
            or self.performance_state != _NOT_PERFORMED
            or self.manager_tasks_action_state
            != (
                _ACTION_UNMODELED
                if self.boundary == _MANAGER_TASKS_PLAYBOOK
                else "not-applicable"
            )
            or self.status is not DeployManagerActivationBoundaryStatus.BLOCKED
            or self.blockers != expected_blockers
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.step_digest != _step_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Manager activation plan step identity conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy Manager activation plan step digest")
        if self.source_digest is not None:
            validate_digest(
                self.source_digest, "deploy Manager activation source digest"
            )
        if self.prerequisite_step_digest is not None:
            validate_digest(
                self.prerequisite_step_digest,
                "deploy Manager activation prerequisite digest",
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(
            self,
            tuple_fields={"target_ids", "blockers"},
            optional_fields={"source_digest", "prerequisite_step_digest"},
        )

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerActivationPlanStep:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager activation plan step",
        )
        source_digest = _optional_string(value["source_digest"], "source_digest")
        prerequisite = _optional_string(
            value["prerequisite_step_digest"], "prerequisite_step_digest"
        )
        try:
            return cls(
                sequence=_integer(value["sequence"], "sequence"),
                boundary=require_string(value, "boundary"),
                classification=OperationClassification(
                    require_string(value, "classification")
                ),
                target_role=require_string(value, "target_role"),
                target_ids=_string_tuple(value["target_ids"], "target_ids"),
                target_count=_integer(value["target_count"], "target_count"),
                target_set_digest=require_string(value, "target_set_digest"),
                source_state=DeployManagerActivationSourceState(
                    require_string(value, "source_state")
                ),
                source_digest=source_digest,
                package_provenance_digest=require_string(
                    value, "package_provenance_digest"
                ),
                identity_provenance_digest=require_string(
                    value, "identity_provenance_digest"
                ),
                topology_digest=require_string(value, "topology_digest"),
                prerequisite_step_digest=prerequisite,
                authorization_requirement=require_string(
                    value, "authorization_requirement"
                ),
                evidence_requirement=require_string(value, "evidence_requirement"),
                performance_state=require_string(value, "performance_state"),
                manager_tasks_action_state=require_string(
                    value, "manager_tasks_action_state"
                ),
                status=DeployManagerActivationBoundaryStatus(
                    require_string(value, "status")
                ),
                blockers=_string_tuple(value["blockers"], "blockers"),
                blocker_digest=require_string(value, "blocker_digest"),
                step_digest=require_string(value, "step_digest"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Manager activation plan step enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerActivationPlan:
    """Immutable ordered bridge outside the historical deploy mapping."""

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
    context_artifact_digest: str
    context_record_digest: str
    post_targets_artifact_digest: str
    post_targets_record_digest: str
    original_mapping_count: int
    original_mapping_digest: str
    original_mapping_unchanged: bool
    manager_target_id: str
    manager_target_digest: str
    manager_agent_target_ids: tuple[str, ...]
    manager_agent_target_count: int
    manager_agent_target_set_digest: str
    steps: tuple[DeployManagerActivationPlanStep, ...]
    step_count: int
    source_available_count: int
    source_unavailable_count: int
    authorization_required_count: int
    evidence_required_count: int
    not_performed_count: int
    blocked_count: int
    manager_tasks_action_state: str
    manager_tasks_blocker_digest: str
    next_implementation_contract: str
    plan_digest: str
    authorization_state: str
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    context_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_ACTIVATION_CONTEXT_SCHEMA_VERSION
    )
    post_targets_schema_version: str = (
        ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_SCHEMA_VERSION
            or self.context_schema_version
            != ANSIBLE_DEPLOY_MANAGER_ACTIVATION_CONTEXT_SCHEMA_VERSION
            or self.post_targets_schema_version
            != ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.original_mapping_count != _ORIGINAL_MAPPING_COUNT
            or self.original_mapping_digest != _mapping_digest()
            or not self.original_mapping_unchanged
            or self.manager_target_digest != _digest_object([self.manager_target_id])
            or self.manager_agent_target_count != len(self.manager_agent_target_ids)
            or self.manager_agent_target_ids
            != tuple(sorted(set(self.manager_agent_target_ids)))
            or self.manager_agent_target_set_digest
            != _digest_object(list(self.manager_agent_target_ids))
            or self.step_count != len(_BOUNDARY_DEFINITIONS)
            or self.step_count != len(self.steps)
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, len(_BOUNDARY_DEFINITIONS) + 1))
            or self.source_available_count != 1
            or self.source_unavailable_count != 3
            or self.authorization_required_count != self.step_count
            or self.evidence_required_count != self.step_count
            or self.not_performed_count != self.step_count
            or self.blocked_count != self.step_count
            or self.manager_tasks_action_state != _ACTION_UNMODELED
            or self.manager_tasks_blocker_digest != self.steps[-1].blocker_digest
            or self.next_implementation_contract != _NEXT_IMPLEMENTATION_CONTRACT
            or self.authorization_state != _UNAVAILABLE
            or self.execution_state != _NOT_PERFORMED
            or self.finalization_state != _NOT_PERFORMED
            or self.public_workflow_state != _UNAVAILABLE
            or self.plan_digest != _plan_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Manager activation plan identity or summary conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy Manager activation plan digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(
            self,
            tuple_fields={"manager_agent_target_ids"},
            step_fields={"steps"},
        )

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployManagerActivationPlan:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager activation plan",
        )
        integers = {
            "generation",
            "journal_generation",
            "original_mapping_count",
            "manager_agent_target_count",
            "step_count",
            "source_available_count",
            "source_unavailable_count",
            "authorization_required_count",
            "evidence_required_count",
            "not_performed_count",
            "blocked_count",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in integers:
                    parsed[name] = _integer(item, name)
                elif name == "original_mapping_unchanged":
                    parsed[name] = _boolean(item, name)
                elif name in {"cluster_uuid", "operation_id"}:
                    parsed[name] = parse_uuid(require_string(value, name), name)
                elif name == "journal_status":
                    parsed[name] = JournalStatus(require_string(value, name))
                elif name == "journal_phase":
                    parsed[name] = OperationPhase(require_string(value, name))
                elif name == "manager_agent_target_ids":
                    parsed[name] = _string_tuple(item, name)
                elif name == "steps":
                    parsed[name] = tuple(
                        DeployManagerActivationPlanStep.from_object(
                            _mapping(step, "Manager activation plan step")
                        )
                        for step in _array(item, "Manager activation plan steps")
                    )
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Manager activation plan enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployManagerActivationPlan:
    record: DeployManagerActivationPlan
    artifact_digest: str


class DeployManagerActivationContextStore:
    """Owner-only immutable Manager activation context store."""

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
        self._path = deploy_manager_activation_context_path(paths, operation_id)
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
    ) -> StoredDeployManagerActivationContext:
        value, digest = self._file.read()
        record = DeployManagerActivationContext.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy Manager activation context identity conflicts"
            )
        return StoredDeployManagerActivationContext(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerActivationContext:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerActivationContext,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerActivationContext, DeployManagerActivationArtifactState
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy Manager activation context operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy Manager activation context is immutable; "
                    "use a new operation"
                )
            return current, DeployManagerActivationArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerActivationContext(record, digest),
            DeployManagerActivationArtifactState.CREATED,
        )


class DeployManagerActivationPlanStore:
    """Owner-only immutable Manager activation plan store."""

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
        self._path = deploy_manager_activation_plan_path(paths, operation_id)
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
    ) -> StoredDeployManagerActivationPlan:
        value, digest = self._file.read()
        record = DeployManagerActivationPlan.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy Manager activation plan identity conflicts"
            )
        return StoredDeployManagerActivationPlan(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerActivationPlan:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerActivationPlan,
        *,
        lock: ClusterLock,
    ) -> tuple[StoredDeployManagerActivationPlan, DeployManagerActivationArtifactState]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy Manager activation plan operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy Manager activation plan is immutable; use a new operation"
                )
            return current, DeployManagerActivationArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerActivationPlan(record, digest),
            DeployManagerActivationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerActivationPlanReport:
    """Strict bounded Manager activation planning projection."""

    operation_id: uuid.UUID
    context_state: DeployManagerActivationArtifactState
    plan_state: DeployManagerActivationArtifactState
    context_artifact_digest: str
    context_record_digest: str
    plan_artifact_digest: str
    plan_digest: str
    manager_target_id: str
    manager_target_digest: str
    manager_agent_target_ids: tuple[str, ...]
    manager_agent_target_count: int
    manager_agent_target_set_digest: str
    step_count: int
    source_available_count: int
    source_unavailable_count: int
    authorization_required_count: int
    evidence_required_count: int
    not_performed_count: int
    blocked_count: int
    manager_tasks_action_state: str
    manager_tasks_blocker_digest: str
    next_implementation_contract: str
    original_mapping_unchanged: bool
    journal_status: JournalStatus
    journal_phase: OperationPhase
    authorization_state: str
    execution_state: str
    public_workflow_state: str
    context_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_ACTIVATION_CONTEXT_SCHEMA_VERSION
    )
    plan_schema_version: str = ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_REPORT_SCHEMA_VERSION
            or self.context_schema_version
            != ANSIBLE_DEPLOY_MANAGER_ACTIVATION_CONTEXT_SCHEMA_VERSION
            or self.plan_schema_version
            != ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_SCHEMA_VERSION
            or self.manager_agent_target_count != len(self.manager_agent_target_ids)
            or self.step_count != len(_BOUNDARY_DEFINITIONS)
            or self.source_available_count != 1
            or self.source_unavailable_count != 3
            or self.authorization_required_count != self.step_count
            or self.evidence_required_count != self.step_count
            or self.not_performed_count != self.step_count
            or self.blocked_count != self.step_count
            or self.manager_tasks_action_state != _ACTION_UNMODELED
            or self.next_implementation_contract != _NEXT_IMPLEMENTATION_CONTRACT
            or not self.original_mapping_unchanged
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.authorization_state != _UNAVAILABLE
            or self.execution_state != _NOT_PERFORMED
            or self.public_workflow_state != _UNAVAILABLE
        ):
            raise StatePersistenceError(
                "deploy Manager activation plan report conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy Manager activation report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "artifacts": {
                "context_digest": self.context_artifact_digest,
                "context_record_digest": self.context_record_digest,
                "context_state": self.context_state.value,
                "plan_digest": self.plan_artifact_digest,
                "plan_record_digest": self.plan_digest,
                "plan_state": self.plan_state.value,
            },
            "boundaries": {
                "authorization_required_count": self.authorization_required_count,
                "blocked_count": self.blocked_count,
                "evidence_required_count": self.evidence_required_count,
                "not_performed_count": self.not_performed_count,
                "source_available_count": self.source_available_count,
                "source_unavailable_count": self.source_unavailable_count,
                "step_count": self.step_count,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "manager_scope": {
                "agent_target_count": self.manager_agent_target_count,
                "agent_target_ids": list(self.manager_agent_target_ids),
                "agent_target_set_digest": self.manager_agent_target_set_digest,
                "server_target_digest": self.manager_target_digest,
                "server_target_id": self.manager_target_id,
            },
            "manager_tasks": {
                "action_state": self.manager_tasks_action_state,
                "blocker_digest": self.manager_tasks_blocker_digest,
            },
            "next_implementation_contract": self.next_implementation_contract,
            "operation_id": str(self.operation_id),
            "original_mapping_unchanged": self.original_mapping_unchanged,
            "schema_version": self.schema_version,
            "states": {
                "authorization": self.authorization_state,
                "execution": self.execution_state,
                "public_workflow": self.public_workflow_state,
            },
        }


@dataclass(frozen=True, slots=True)
class _PlanningContext:
    post_targets: StoredDeployPostMonitoringTargetsReconciliation
    manager_target_id: str
    manager_agent_target_ids: tuple[str, ...]
    values: Mapping[str, object]


def plan_deploy_manager_activation(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployManagerActivationPlanReport:
    """Persist or reuse the separate Manager activation context then plan."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _validate_contracts()
    _refuse_ambiguous_activation_artifacts(paths, operation_id)

    context_store = DeployManagerActivationContextStore(paths, operation_id)
    plan_store = DeployManagerActivationPlanStore(paths, operation_id)
    for path in (context_store.path, plan_store.path):
        validate_state_file(path, allow_missing=True)
    if plan_store.path.exists() and not context_store.path.exists():
        raise StateConflictError(
            "deploy Manager activation plan exists without its context"
        )

    loaded = _load_planning_context(paths, operation_id, lock=lock)
    cluster_uuid = loaded.post_targets.record.cluster_uuid
    canonical_cluster_name = loaded.post_targets.record.cluster_name
    existing_context = (
        context_store.read_locked(
            lock,
            expected_cluster_uuid=cluster_uuid,
            expected_cluster_name=canonical_cluster_name,
        )
        if context_store.path.exists()
        else None
    )
    existing_plan = (
        plan_store.read_locked(
            lock,
            expected_cluster_uuid=cluster_uuid,
            expected_cluster_name=canonical_cluster_name,
        )
        if plan_store.path.exists()
        else None
    )

    created_at = (
        existing_context.record.created_at
        if existing_context is not None
        else format_timestamp(datetime.now(UTC))
    )
    context_record = _build_context_record(loaded, created_at=created_at)
    expected_context_digest = digest_bytes(serialize_json(context_record.to_object()))
    context_for_plan = StoredDeployManagerActivationContext(
        context_record, expected_context_digest
    )
    steps = _build_plan_steps(context_record)
    plan_record = _build_plan_record(
        context_for_plan,
        steps=steps,
        created_at=(
            existing_plan.record.created_at if existing_plan is not None else created_at
        ),
    )

    stored_context, context_state = context_store.write_locked(
        context_record, lock=lock
    )
    if stored_context.artifact_digest != expected_context_digest:
        raise StateConflictError(
            "deploy Manager activation context bytes changed during persistence"
        )
    stored_plan, plan_state = plan_store.write_locked(plan_record, lock=lock)
    return _build_report(
        stored_context,
        stored_plan,
        context_state=context_state,
        plan_state=plan_state,
    )


def deploy_manager_activation_context_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MANAGER_ACTIVATION_CONTEXT_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Manager activation context path is not canonical"
        )
    return path


def deploy_manager_activation_plan_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MANAGER_ACTIVATION_PLAN_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Manager activation plan path is not canonical"
        )
    return path


def deploy_manager_activation_context_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(name, DEPLOY_MANAGER_ACTIVATION_CONTEXT_FILENAME_SUFFIX)


def deploy_manager_activation_plan_id_from_filename(name: str) -> uuid.UUID | None:
    return _id_from_filename(name, DEPLOY_MANAGER_ACTIVATION_PLAN_FILENAME_SUFFIX)


def _load_planning_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
) -> _PlanningContext:
    chain = _load_post_targets_context(paths, operation_id, lock=lock)
    authorization_context = chain.authorization_context
    agent_context = authorization_context.agent.authorization_context
    manager_agent_context = agent_context.manager.authorization_context
    loaded = _loaded(
        manager_agent_context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    deploy = loaded.planning.base.deploy
    post_store = DeployPostMonitoringTargetsReconciliationStore(paths, operation_id)
    validate_state_file(post_store.path, allow_missing=True)
    if not post_store.path.exists():
        raise StateConflictError(
            "deploy Manager activation requires post-monitoring-targets reconciliation"
        )
    post = post_store.read_locked(
        lock,
        expected_cluster_uuid=deploy.metadata.record.cluster_uuid,
        expected_cluster_name=deploy.metadata.record.cluster_name,
    )
    expected_post = _build_post_targets_record(
        chain,
        steps=_build_post_targets_steps(chain),
        created_at=post.record.created_at,
    )
    if post.record != expected_post:
        raise StateConflictError(
            "deploy Manager activation post-monitoring-targets reconciliation drifted"
        )

    manager_hosts = tuple(
        host
        for host in deploy.inventory.record.inventory.hosts
        if host.role is HostRole.MANAGER
    )
    scylla_hosts = tuple(
        host
        for host in deploy.inventory.record.inventory.hosts
        if host.role is HostRole.SCYLLA
    )
    if len(manager_hosts) != 1 or not scylla_hosts:
        raise StateConflictError(
            "deploy Manager activation requires one Manager and the complete Scylla set"
        )
    manager_target_id = manager_hosts[0].logical_id
    manager_agent_target_ids = tuple(sorted(host.logical_id for host in scylla_hosts))

    server_evidence = manager_agent_context.monitoring.monitoring.manager.evidence
    agent_evidence = agent_context.manager.evidence
    if len(server_evidence.record.entries) != 1:
        raise StateConflictError(
            "deploy Manager activation Manager-server evidence is ambiguous"
        )
    server = server_evidence.record.entries[0]
    agents = agent_evidence.record.entries
    if (
        server.stable_id != manager_target_id
        or server.status
        not in {ManagerServerStatus.INSTALLED, ManagerServerStatus.NO_CHANGE}
        or not server.installed
        or not server.service_masked
        or not server.service_inactive
        or server.service_started
        or server.backend_configured
        or server.configuration_performed
        or server.registration_performed
        or server.setup_performed
        or server.tasks_performed
        or server.manual_recovery_required
        or server.automatic_retry_allowed
        or server.package_version_digest
        != _digest_object(MANAGER_SERVER_PACKAGE_VERSION)
        or server.source_digest
        != _playbook_source_digest(loaded.source, "manager-server")
    ):
        raise StateConflictError(
            "deploy Manager activation requires exact install-only Manager-server "
            "evidence"
        )
    if tuple(entry.stable_id for entry in agents) != manager_agent_target_ids or any(
        entry.status not in {ManagerAgentStatus.INSTALLED, ManagerAgentStatus.NO_CHANGE}
        or not entry.installed
        or not entry.service_disabled
        or not entry.service_inactive
        or entry.configuration_performed
        or entry.auth_token_configured
        or entry.helper_slice_configured
        or entry.server_reachability != _NOT_PERFORMED
        or entry.service_started
        or entry.manual_recovery_required
        or entry.automatic_retry_allowed
        or entry.package_version_digest != _digest_object(MANAGER_AGENT_PACKAGE_VERSION)
        or entry.source_digest
        != _playbook_source_digest(loaded.source, "manager-agent")
        for entry in agents
    ):
        raise StateConflictError(
            "deploy Manager activation requires exact complete install-only "
            "Manager-agent evidence"
        )
    if (
        MANAGER_SERVER_RELEASE_LINE != MANAGER_AGENT_RELEASE_LINE
        or MANAGER_SERVER_PACKAGE_VERSION != MANAGER_AGENT_PACKAGE_VERSION
    ):
        raise StateConflictError(
            "deploy Manager activation package release provenance conflicts"
        )

    post_record = post.record
    topology_digest = _digest_object(
        [
            {
                "datacenter": host.scylla_datacenter,
                "rack": host.scylla_rack,
                "stable_id": host.logical_id,
            }
            for host in scylla_hosts
        ]
    )
    identity_provenance_digest = _digest_object(
        {
            "inventory_artifact_digest": deploy.inventory.digest,
            "manager_target_id": manager_target_id,
            "manager_agent_target_ids": list(manager_agent_target_ids),
            "trust_artifact_digest": loaded.planning.base.trust.digest,
        }
    )
    manager_server_source_digest = _playbook_source_digest(
        loaded.source, "manager-server"
    )
    manager_agent_source_digest = _playbook_source_digest(
        loaded.source, "manager-agent"
    )
    manager_tasks_source_digest = _playbook_source_digest(
        loaded.source, _MANAGER_TASKS_PLAYBOOK
    )
    server_package_digest = _digest_object(MANAGER_SERVER_PACKAGE_VERSION)
    agent_package_digest = _digest_object(MANAGER_AGENT_PACKAGE_VERSION)
    package_release_digest = _digest_object(MANAGER_SERVER_RELEASE_LINE)
    package_provenance_digest = _digest_object(
        {
            "agent_evidence": [entry.evidence_digest for entry in agents],
            "agent_package_version_digest": agent_package_digest,
            "agent_source_digest": manager_agent_source_digest,
            "release_digest": package_release_digest,
            "server_evidence_digest": server.evidence_digest,
            "server_package_version_digest": server_package_digest,
            "server_source_digest": manager_server_source_digest,
        }
    )
    manager_tasks_contract_digest = _digest_object(
        {
            "actions": list(MANAGER_TASK_ACTIONS),
            "expected_blockers": list(MANAGER_TASK_EXPECTED_BLOCKERS),
            "kinds": list(MANAGER_TASK_KINDS),
            "not_performed": list(MANAGER_TASK_NOT_PERFORMED),
            "schema_version": MANAGER_TASKS_SCHEMA_VERSION,
            "source_digest": manager_tasks_source_digest,
        }
    )
    action_digest = _digest_object(
        {
            "condition": "explicit-task-action",
            "state": _ACTION_UNMODELED,
        }
    )
    blockers = tuple(
        sorted({blocker for group in _BOUNDARY_BLOCKERS for blocker in group})
    )
    values: dict[str, object] = {
        "request_digest": post_record.request_digest,
        "journal_generation": post_record.journal_generation,
        "journal_digest": post_record.journal_digest,
        "journal_status": post_record.journal_status,
        "journal_phase": post_record.journal_phase,
        "original_mapping_count": post_record.original_mapping_count,
        "original_mapping_digest": post_record.original_mapping_digest,
        "original_mapping_unchanged": post_record.original_mapping_unchanged,
        "metadata_generation": post_record.metadata_generation,
        "metadata_artifact_digest": post_record.metadata_artifact_digest,
        "desired_spec_digest": post_record.desired_spec_digest,
        "observation_generation": post_record.observation_generation,
        "observation_artifact_digest": post_record.observation_artifact_digest,
        "observation_manifest_digest": post_record.observation_manifest_digest,
        "inventory_generation": post_record.inventory_generation,
        "inventory_artifact_digest": post_record.inventory_artifact_digest,
        "inventory_digest": post_record.inventory_digest,
        "trust_generation": post_record.trust_generation,
        "trust_artifact_digest": post_record.trust_artifact_digest,
        "trust_entries_digest": post_record.trust_entries_digest,
        "readiness_artifact_digest": post_record.readiness_artifact_digest,
        "readiness_record_digest": post_record.readiness_record_digest,
        "catalog_digest": post_record.catalog_digest,
        "ansible_source_version": post_record.ansible_source_version,
        "ansible_source_digest": post_record.ansible_source_digest,
        "manager_target_id": manager_target_id,
        "manager_target_digest": _digest_object([manager_target_id]),
        "manager_agent_target_ids": manager_agent_target_ids,
        "manager_agent_target_count": len(manager_agent_target_ids),
        "manager_agent_target_set_digest": _digest_object(
            list(manager_agent_target_ids)
        ),
        "topology_digest": topology_digest,
        "identity_provenance_digest": identity_provenance_digest,
        "manager_server_evidence_artifact_digest": server_evidence.artifact_digest,
        "manager_server_evidence_digest": server.evidence_digest,
        "manager_server_provenance_digest": server.provenance_digest,
        "manager_server_package_version_digest": server_package_digest,
        "manager_server_source_digest": manager_server_source_digest,
        "manager_agent_evidence_artifact_digest": agent_evidence.artifact_digest,
        "manager_agent_evidence_set_digest": _digest_object(
            [entry.evidence_digest for entry in agents]
        ),
        "manager_agent_provenance_set_digest": _digest_object(
            [entry.provenance_digest for entry in agents]
        ),
        "manager_agent_package_version_digest": agent_package_digest,
        "manager_agent_source_digest": manager_agent_source_digest,
        "manager_package_release_digest": package_release_digest,
        "manager_package_provenance_digest": package_provenance_digest,
        "manager_tasks_source_digest": manager_tasks_source_digest,
        "manager_tasks_contract_digest": manager_tasks_contract_digest,
        "manager_tasks_action_state": _ACTION_UNMODELED,
        "manager_tasks_action_digest": action_digest,
        "manager_backend_state": _NOT_PERFORMED,
        "manager_service_state": _NOT_PERFORMED,
        "manager_registration_state": _NOT_PERFORMED,
        "manager_agent_token_state": _NOT_PERFORMED,
        "blocker_count": len(blockers),
        "blockers": blockers,
        "blocker_digest": _digest_object(list(blockers)),
        "next_implementation_contract": _NEXT_IMPLEMENTATION_CONTRACT,
    }
    return _PlanningContext(
        post,
        manager_target_id,
        manager_agent_target_ids,
        values,
    )


def _build_context_record(
    context: _PlanningContext,
    *,
    created_at: str,
) -> DeployManagerActivationContext:
    post = context.post_targets
    record = post.record
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": record.cluster_uuid,
        "cluster_name": record.cluster_name,
        "operation_id": record.operation_id,
        "operation": record.operation,
        **context.values,
        "post_targets_artifact_digest": post.artifact_digest,
        "post_targets_record_digest": record.record_digest,
        "post_targets_effective_plan_digest": _digest_object(
            [step.to_object() for step in record.steps]
        ),
        "authorization_state": _UNAVAILABLE,
        "execution_state": _NOT_PERFORMED,
        "public_workflow_state": _UNAVAILABLE,
        "record_digest": "",
    }
    values["record_digest"] = _context_record_digest_from_values(values)
    return DeployManagerActivationContext(**values)  # type: ignore[arg-type]


def _build_plan_steps(
    context: DeployManagerActivationContext,
) -> tuple[DeployManagerActivationPlanStep, ...]:
    result: list[DeployManagerActivationPlanStep] = []
    combined_targets = tuple(
        sorted((context.manager_target_id, *context.manager_agent_target_ids))
    )
    for sequence, definition in enumerate(_BOUNDARY_DEFINITIONS, start=1):
        boundary, classification, target_role, source = definition
        target_ids = (
            combined_targets
            if target_role == "manager-and-scylla"
            else (context.manager_target_id,)
        )
        source_state = DeployManagerActivationSourceState(source)
        source_digest = (
            context.manager_tasks_source_digest
            if source_state is DeployManagerActivationSourceState.AVAILABLE
            else None
        )
        prerequisite = result[-1].step_digest if result else None
        blockers = tuple(sorted(_BOUNDARY_BLOCKERS[sequence - 1]))
        values: dict[str, object] = {
            "sequence": sequence,
            "boundary": boundary,
            "classification": classification,
            "target_role": target_role,
            "target_ids": target_ids,
            "target_count": len(target_ids),
            "target_set_digest": _digest_object(list(target_ids)),
            "source_state": source_state,
            "source_digest": source_digest,
            "package_provenance_digest": context.manager_package_provenance_digest,
            "identity_provenance_digest": context.identity_provenance_digest,
            "topology_digest": context.topology_digest,
            "prerequisite_step_digest": prerequisite,
            "authorization_requirement": "authorization-required",
            "evidence_requirement": "evidence-required",
            "performance_state": _NOT_PERFORMED,
            "manager_tasks_action_state": (
                _ACTION_UNMODELED
                if boundary == _MANAGER_TASKS_PLAYBOOK
                else "not-applicable"
            ),
            "status": DeployManagerActivationBoundaryStatus.BLOCKED,
            "blockers": blockers,
            "blocker_digest": _digest_object(list(blockers)),
            "step_digest": "",
        }
        values["step_digest"] = _step_digest_from_values(values)
        result.append(DeployManagerActivationPlanStep(**values))  # type: ignore[arg-type]
    return tuple(result)


def _build_plan_record(
    context: StoredDeployManagerActivationContext,
    *,
    steps: tuple[DeployManagerActivationPlanStep, ...],
    created_at: str,
) -> DeployManagerActivationPlan:
    record = context.record
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": record.cluster_uuid,
        "cluster_name": record.cluster_name,
        "operation_id": record.operation_id,
        "operation": record.operation,
        "request_digest": record.request_digest,
        "journal_generation": record.journal_generation,
        "journal_digest": record.journal_digest,
        "journal_status": record.journal_status,
        "journal_phase": record.journal_phase,
        "context_artifact_digest": context.artifact_digest,
        "context_record_digest": record.record_digest,
        "post_targets_artifact_digest": record.post_targets_artifact_digest,
        "post_targets_record_digest": record.post_targets_record_digest,
        "original_mapping_count": record.original_mapping_count,
        "original_mapping_digest": record.original_mapping_digest,
        "original_mapping_unchanged": record.original_mapping_unchanged,
        "manager_target_id": record.manager_target_id,
        "manager_target_digest": record.manager_target_digest,
        "manager_agent_target_ids": record.manager_agent_target_ids,
        "manager_agent_target_count": record.manager_agent_target_count,
        "manager_agent_target_set_digest": record.manager_agent_target_set_digest,
        "steps": steps,
        "step_count": len(steps),
        "source_available_count": sum(
            step.source_state is DeployManagerActivationSourceState.AVAILABLE
            for step in steps
        ),
        "source_unavailable_count": sum(
            step.source_state is DeployManagerActivationSourceState.UNAVAILABLE
            for step in steps
        ),
        "authorization_required_count": sum(
            step.authorization_requirement == "authorization-required" for step in steps
        ),
        "evidence_required_count": sum(
            step.evidence_requirement == "evidence-required" for step in steps
        ),
        "not_performed_count": sum(
            step.performance_state == _NOT_PERFORMED for step in steps
        ),
        "blocked_count": sum(
            step.status is DeployManagerActivationBoundaryStatus.BLOCKED
            for step in steps
        ),
        "manager_tasks_action_state": record.manager_tasks_action_state,
        "manager_tasks_blocker_digest": steps[-1].blocker_digest,
        "next_implementation_contract": record.next_implementation_contract,
        "plan_digest": "",
        "authorization_state": _UNAVAILABLE,
        "execution_state": _NOT_PERFORMED,
        "finalization_state": _NOT_PERFORMED,
        "public_workflow_state": _UNAVAILABLE,
    }
    values["plan_digest"] = _plan_digest_from_values(values)
    return DeployManagerActivationPlan(**values)  # type: ignore[arg-type]


def _build_report(
    context: StoredDeployManagerActivationContext,
    plan: StoredDeployManagerActivationPlan,
    *,
    context_state: DeployManagerActivationArtifactState,
    plan_state: DeployManagerActivationArtifactState,
) -> DeployManagerActivationPlanReport:
    record = plan.record
    return DeployManagerActivationPlanReport(
        operation_id=record.operation_id,
        context_state=context_state,
        plan_state=plan_state,
        context_artifact_digest=context.artifact_digest,
        context_record_digest=context.record.record_digest,
        plan_artifact_digest=plan.artifact_digest,
        plan_digest=record.plan_digest,
        manager_target_id=record.manager_target_id,
        manager_target_digest=record.manager_target_digest,
        manager_agent_target_ids=record.manager_agent_target_ids,
        manager_agent_target_count=record.manager_agent_target_count,
        manager_agent_target_set_digest=record.manager_agent_target_set_digest,
        step_count=record.step_count,
        source_available_count=record.source_available_count,
        source_unavailable_count=record.source_unavailable_count,
        authorization_required_count=record.authorization_required_count,
        evidence_required_count=record.evidence_required_count,
        not_performed_count=record.not_performed_count,
        blocked_count=record.blocked_count,
        manager_tasks_action_state=record.manager_tasks_action_state,
        manager_tasks_blocker_digest=record.manager_tasks_blocker_digest,
        next_implementation_contract=record.next_implementation_contract,
        original_mapping_unchanged=record.original_mapping_unchanged,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        authorization_state=record.authorization_state,
        execution_state=record.execution_state,
        public_workflow_state=record.public_workflow_state,
    )


def _validate_contracts() -> None:
    mapping = OPERATION_PLAYBOOKS[_OPERATION]
    manager_tasks = get_playbook(_MANAGER_TASKS_PLAYBOOK)
    unavailable_boundaries = {
        "backend-configure",
        "manager-start",
        "cluster-registration-auth-token-handoff",
    }
    if (
        len(mapping) != _ORIGINAL_MAPPING_COUNT
        or _mapping_digest()
        != _digest_object(
            [
                {
                    "condition": step.condition,
                    "mapping_sequence": index,
                    "playbook": step.playbook,
                }
                for index, step in enumerate(mapping, start=1)
            ]
        )
        or mapping[_MANAGER_TASKS_MAPPING - 1].playbook != _MANAGER_TASKS_PLAYBOOK
        or mapping[_MANAGER_TASKS_MAPPING - 1].condition != "explicit-task-action"
        or manager_tasks.classification is not OperationClassification.SENSITIVE
        or not manager_tasks.source_available
        or unavailable_boundaries.intersection(PLAYBOOK_NAMES)
        or tuple(MANAGER_TASK_ACTIONS) != ("inspect", "quiesce", "resume", "validate")
        or tuple(MANAGER_TASK_KINDS) != ("backup", "repair")
        or tuple(MANAGER_TASK_EXPECTED_BLOCKERS)
        != ("backend-unconfigured", "manager-inactive", "manager-unregistered")
        or not {
            "auth-token",
            "backend-configure",
            "cluster-registration",
            "manager-start",
        }.issubset(MANAGER_TASK_NOT_PERFORMED)
    ):
        raise StateConflictError(
            "deploy Manager activation source, mapping, or validation contract drifted"
        )


def _refuse_ambiguous_activation_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    exact_allowed = {
        f"{operation_id}{DEPLOY_MANAGER_ACTIVATION_CONTEXT_FILENAME_SUFFIX}",
        f"{operation_id}{DEPLOY_MANAGER_ACTIVATION_PLAN_FILENAME_SUFFIX}",
    }
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Manager activation operation history"
        ) from error
    operation_prefix = f"{operation_id}.ansible-deploy-manager-activation-"
    for entry in entries:
        if entry.name in exact_allowed:
            continue
        if (
            "manager-activation-context" in entry.name
            or "manager-activation-plan" in entry.name
            or entry.name.startswith(operation_prefix)
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy Manager activation refuses ambiguous or later activation "
                "artifacts"
            )


def _context_record_digest(record: DeployManagerActivationContext) -> str:
    value = record.to_object()
    value["record_digest"] = ""
    return _digest_object(value)


def _context_record_digest_from_values(values: Mapping[str, object]) -> str:
    value = _object_for_digest(
        DeployManagerActivationContext,
        values,
        tuple_fields={"manager_agent_target_ids", "blockers"},
    )
    value["record_digest"] = ""
    return _digest_object(value)


def _step_digest(step: DeployManagerActivationPlanStep) -> str:
    return _step_digest_from_values(step.to_object())


def _step_digest_from_values(values: Mapping[str, object]) -> str:
    value = _object_for_digest(
        DeployManagerActivationPlanStep,
        values,
        tuple_fields={"target_ids", "blockers"},
        optional_fields={"source_digest", "prerequisite_step_digest"},
    )
    value["step_digest"] = ""
    return _digest_object(value)


def _plan_digest(record: DeployManagerActivationPlan) -> str:
    value = record.to_object()
    value["plan_digest"] = ""
    return _digest_object(value)


def _plan_digest_from_values(values: Mapping[str, object]) -> str:
    value = _object_for_digest(
        DeployManagerActivationPlan,
        values,
        tuple_fields={"manager_agent_target_ids"},
        step_fields={"steps"},
    )
    value["plan_digest"] = ""
    return _digest_object(value)


def _dataclass_object(
    value: object,
    *,
    tuple_fields: set[str] | None = None,
    step_fields: set[str] | None = None,
    optional_fields: set[str] | None = None,
) -> dict[str, object]:
    return _object_for_digest(
        type(value),
        {
            name: getattr(value, name)
            for name in value.__dataclass_fields__  # type: ignore[attr-defined]
        },
        tuple_fields=tuple_fields,
        step_fields=step_fields,
        optional_fields=optional_fields,
    )


def _object_for_digest(
    data_type: type[Any],
    values: Mapping[str, object],
    *,
    tuple_fields: set[str] | None = None,
    step_fields: set[str] | None = None,
    optional_fields: set[str] | None = None,
) -> dict[str, object]:
    tuple_fields = tuple_fields or set()
    step_fields = step_fields or set()
    optional_fields = optional_fields or set()
    result: dict[str, object] = {}
    fields = cast(Mapping[str, Field[Any]], data_type.__dataclass_fields__)
    for name, field in fields.items():
        item = values.get(name, field.default)
        if name in tuple_fields:
            result[name] = list(cast(tuple[object, ...], item))
        elif name in step_fields:
            result[name] = [
                cast(DeployManagerActivationPlanStep, step).to_object()
                for step in cast(tuple[object, ...], item)
            ]
        elif name in optional_fields:
            result[name] = item
        elif isinstance(item, StrEnum):
            result[name] = item.value
        elif isinstance(item, uuid.UUID):
            result[name] = str(item)
        else:
            result[name] = item
    return result


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError("deploy Manager activation paths are not canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy Manager activation planning requires the matching held deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _id_from_filename(name: str, suffix: str) -> uuid.UUID | None:
    if not name.endswith(suffix):
        return None
    value = name[: -len(suffix)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


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


def _positive_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be a boolean")
    return value


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise StatePersistenceError(f"{label} must be a string or null")
    return value


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise StatePersistenceError(f"{label} must be an array")
    return value


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise StatePersistenceError(f"{label} must be a string array")
    return tuple(value)


__all__ = [
    "ANSIBLE_DEPLOY_MANAGER_ACTIVATION_CONTEXT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_STEP_SCHEMA_VERSION",
    "DEPLOY_MANAGER_ACTIVATION_CONTEXT_FILENAME_SUFFIX",
    "DEPLOY_MANAGER_ACTIVATION_PLAN_FILENAME_SUFFIX",
    "DeployManagerActivationArtifactState",
    "DeployManagerActivationBoundaryStatus",
    "DeployManagerActivationContext",
    "DeployManagerActivationContextStore",
    "DeployManagerActivationPlan",
    "DeployManagerActivationPlanReport",
    "DeployManagerActivationPlanStep",
    "DeployManagerActivationPlanStore",
    "DeployManagerActivationSourceState",
    "StoredDeployManagerActivationContext",
    "StoredDeployManagerActivationPlan",
    "deploy_manager_activation_context_id_from_filename",
    "deploy_manager_activation_context_path",
    "deploy_manager_activation_plan_id_from_filename",
    "deploy_manager_activation_plan_path",
    "plan_deploy_manager_activation",
]
