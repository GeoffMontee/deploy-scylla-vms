"""Immutable reconciliation after mapped deploy ``monitoring-targets`` execution.

This subprocess-free owner reloads the complete canonical deploy chain,
requires one exact terminal-success Scylla Monitoring 4.16.0 four-file target
result, and marks only historical mapping position 18 succeeded. Historical
mapping position 19 remains the exact unmodeled, validation-only
``manager-tasks`` gate. This owner never authorizes or executes later work and
never changes the common journal or any prior artifact.
"""

from __future__ import annotations

import os
import re
import uuid
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.base_os import (
    BaseOsEvidence,
    BaseOsHostEvidence,
    BaseOsStatus,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_monitoring_agent_reconciliation import (
    ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_SCHEMA_VERSION,
    DeployPostMonitoringAgentStep,
)
from scylla_vms.ansible.deploy_monitoring_targets_authorization import (
    ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCHEMA_VERSION,
    DeployMonitoringTargetsAuthorizationStore,
    StoredDeployMonitoringTargetsAuthorization,
    _AuthorizationContext,
    _build_authorization,
    _derive_authorization_scope,
    _load_authorization_context,
    _reconstruct_stack_evidence,
)
from scylla_vms.ansible.deploy_monitoring_targets_execution import (
    ANSIBLE_DEPLOY_MONITORING_TARGETS_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_SCHEMA_VERSION,
    DeployMonitoringTargetsEvidenceEntry,
    DeployMonitoringTargetsEvidenceStore,
    DeployMonitoringTargetsExecutionState,
    DeployMonitoringTargetsExecutionStore,
    StoredDeployMonitoringTargetsEvidence,
    StoredDeployMonitoringTargetsExecution,
)
from scylla_vms.ansible.deploy_plan import (
    DeployConditionState,
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import _loaded
from scylla_vms.ansible.deploy_scylla_configure_reconciliation import (
    _mapping_digest,
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
from scylla_vms.ansible.monitoring_stack import (
    STACK_VERSION,
    build_monitoring_stack_payload,
)
from scylla_vms.ansible.monitoring_targets import (
    SCRAPE_READINESS,
    TARGET_FILES,
    MonitoringTargetsStatus,
    build_monitoring_targets_payload,
)
from scylla_vms.ansible.registry import (
    OPERATION_PLAYBOOKS,
    CheckMode,
    LimitPolicy,
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
from scylla_vms.terraform.apply_readiness import (
    TERRAFORM_APPLY_READINESS_SCHEMA_VERSION,
    _reconstructed_readiness,
)

ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_STEP_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-monitoring-targets-step/v1"
)
ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-monitoring-targets-reconciliation/v1"
)
ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-monitoring-targets-reconciliation-report/v1"
)
DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-post-monitoring-targets-reconciliation.json"
)

_OPERATION = "deploy"
_STAGE = "post-monitoring-targets-reconciliation"
_TARGETS_PLAYBOOK = "monitoring-targets"
_TARGETS_MAPPING = 18
_MANAGER_TASKS_PLAYBOOK = "manager-tasks"
_MANAGER_TASKS_MAPPING = 19
_ORIGINAL_MAPPING_COUNT = 21
_NOT_STARTED = "not-started"
_UNAVAILABLE = "unavailable"
_TARGETS_EVIDENCE_STATE = "monitoring-targets-bound"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")
_STEP_DIGEST_EXCLUDED = {"step_digest", "schema_version"}
_MANAGER_TASK_BLOCKERS = (
    "cluster-health-not-performed",
    "deploy-authorization-not-collected",
    "deploy-condition-unmodeled",
    "manager-backend-not-performed",
    "manager-task-action-unmodeled",
    "manager-task-authorization-not-collected",
    "ordered-deploy-step-not-reached",
    "public-deploy-workflow-unavailable",
    "sensitive-deploy-execution-unavailable",
    "step-variable-evidence-not-performed",
)


class DeployPostMonitoringTargetsArtifactState(StrEnum):
    """Immutable reconciliation persistence result."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployPostMonitoringTargetsStep:
    """Full historical step identity plus one post-targets status."""

    sequence: int
    mapping_sequence: int
    playbook: str
    condition: str
    condition_state: DeployConditionState
    classification: OperationClassification
    target_role: str
    target_ids: tuple[str, ...]
    target_digest: str
    limit_policy: LimitPolicy
    serial: int | None
    check_mode: CheckMode
    variable_names: tuple[str, ...]
    variables_digest: str
    source_digest: str
    command_digest: str
    original_step_digest: str
    prior_step_digest: str
    status: DeployBaseOsReconciledStepStatus
    evidence_state: str
    evidence_digest: str | None
    blockers: tuple[str, ...]
    blocker_digest: str
    step_digest: str
    schema_version: str = ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_STEP_SCHEMA_VERSION

    def __post_init__(self) -> None:
        definition = get_playbook(self.playbook)
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_STEP_SCHEMA_VERSION
            or self.sequence < 1
            or self.mapping_sequence < 1
            or self.classification is not definition.classification
            or self.limit_policy is not definition.limit_policy
            or self.serial != definition.serial
            or self.check_mode is not definition.check_mode
            or self.target_role not in {"all", *(role.value for role in HostRole)}
            or self.target_ids != tuple(sorted(set(self.target_ids)))
            or any(_LOGICAL_ID.fullmatch(item) is None for item in self.target_ids)
            or self.variable_names != tuple(dict.fromkeys(self.variable_names))
            or set(self.variable_names)
            != {variable.name for variable in definition.variables}
            or self.blockers != tuple(sorted(set(self.blockers)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blockers)
            or self.target_digest != _digest_object(list(self.target_ids))
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.step_digest != _step_digest(self)
        ):
            raise StatePersistenceError(
                "post-monitoring-targets step identity conflicts"
            )
        for digest in (
            self.target_digest,
            self.variables_digest,
            self.source_digest,
            self.command_digest,
            self.original_step_digest,
            self.prior_step_digest,
            self.evidence_digest,
            self.blocker_digest,
            self.step_digest,
        ):
            if digest is not None:
                validate_digest(digest, "post-monitoring-targets step digest")
        self._validate_status()

    def _validate_status(self) -> None:
        if self.condition_state is DeployConditionState.INACTIVE:
            if (
                self.status is not DeployBaseOsReconciledStepStatus.NOT_PERFORMED
                or self.evidence_digest is not None
                or self.blockers
            ):
                raise StatePersistenceError(
                    "post-monitoring-targets inactive step state conflicts"
                )
            return
        if self.status is DeployBaseOsReconciledStepStatus.SUCCEEDED:
            if self.evidence_digest is None or self.blockers:
                raise StatePersistenceError(
                    "post-monitoring-targets succeeded step lacks exact evidence"
                )
            return
        if (
            self.status
            is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        ):
            if (
                self.classification is OperationClassification.READ_ONLY
                or self.evidence_digest is None
                or not self.target_ids
                or not self.blockers
            ):
                raise StatePersistenceError(
                    "post-monitoring-targets authorization-required step conflicts"
                )
            return
        if self.status is DeployBaseOsReconciledStepStatus.ELIGIBLE:
            if (
                self.classification is not OperationClassification.READ_ONLY
                or self.evidence_digest is None
                or not self.target_ids
                or self.blockers
            ):
                raise StatePersistenceError(
                    "post-monitoring-targets eligible step conflicts"
                )
            return
        if self.status is DeployBaseOsReconciledStepStatus.BLOCKED:
            if not self.blockers or self.evidence_digest is not None:
                raise StatePersistenceError(
                    "post-monitoring-targets blocked step conflicts"
                )
            return
        if self.evidence_digest is not None:
            raise StatePersistenceError(
                "post-monitoring-targets not-performed step has evidence"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "blocker_digest": self.blocker_digest,
            "blockers": list(self.blockers),
            "check_mode": self.check_mode.value,
            "classification": self.classification.value,
            "command_digest": self.command_digest,
            "condition": self.condition,
            "condition_state": self.condition_state.value,
            "evidence_digest": self.evidence_digest,
            "evidence_state": self.evidence_state,
            "limit_policy": self.limit_policy.value,
            "mapping_sequence": self.mapping_sequence,
            "original_step_digest": self.original_step_digest,
            "playbook": self.playbook,
            "prior_step_digest": self.prior_step_digest,
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "serial": self.serial,
            "source_digest": self.source_digest,
            "status": self.status.value,
            "step_digest": self.step_digest,
            "target_digest": self.target_digest,
            "target_ids": list(self.target_ids),
            "target_role": self.target_role,
            "variable_names": list(self.variable_names),
            "variables_digest": self.variables_digest,
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployPostMonitoringTargetsStep:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "post-monitoring-targets step",
        )
        evidence_digest = value["evidence_digest"]
        if evidence_digest is not None and not isinstance(evidence_digest, str):
            raise StatePersistenceError(
                "post-monitoring-targets evidence digest must be a string or null"
            )
        try:
            return cls(
                sequence=_integer(value["sequence"], "sequence"),
                mapping_sequence=_integer(
                    value["mapping_sequence"], "mapping sequence"
                ),
                playbook=require_string(value, "playbook"),
                condition=require_string(value, "condition"),
                condition_state=DeployConditionState(
                    require_string(value, "condition_state")
                ),
                classification=OperationClassification(
                    require_string(value, "classification")
                ),
                target_role=require_string(value, "target_role"),
                target_ids=_string_tuple(value["target_ids"], "target IDs"),
                target_digest=require_string(value, "target_digest"),
                limit_policy=LimitPolicy(require_string(value, "limit_policy")),
                serial=_optional_integer(value["serial"], "serial"),
                check_mode=CheckMode(require_string(value, "check_mode")),
                variable_names=_string_tuple(value["variable_names"], "variable names"),
                variables_digest=require_string(value, "variables_digest"),
                source_digest=require_string(value, "source_digest"),
                command_digest=require_string(value, "command_digest"),
                original_step_digest=require_string(value, "original_step_digest"),
                prior_step_digest=require_string(value, "prior_step_digest"),
                status=DeployBaseOsReconciledStepStatus(
                    require_string(value, "status")
                ),
                evidence_state=require_string(value, "evidence_state"),
                evidence_digest=evidence_digest,
                blockers=_string_tuple(value["blockers"], "blockers"),
                blocker_digest=require_string(value, "blocker_digest"),
                step_digest=require_string(value, "step_digest"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "post-monitoring-targets step enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployPostMonitoringTargetsReconciliation:
    """Bounded immutable checkpoint after exact four-file target generation."""

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
    post_monitoring_agent_artifact_digest: str
    post_monitoring_agent_record_digest: str
    post_monitoring_agent_effective_plan_digest: str
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_scope_digest: str
    authorization_proof_digest: str
    authorization_consumed: bool
    execution_artifact_digest: str
    execution_binding_digest: str
    execution_generation: int
    execution_state: DeployMonitoringTargetsExecutionState
    evidence_artifact_digest: str
    evidence_generation: int
    evidence_digest: str
    result_digest: str
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
    playbook_source_digest: str
    toolchain_version: str
    executable_identity_digest: str
    toolchain_evidence_digest: str
    stack_version_digest: str
    file_count: int
    file_set_digest: str
    file_content_set_digest: str
    manager_target_count: int
    scylla_target_count: int
    node_exporter_target_count: int
    manager_agent_target_count: int
    manager_identity_set_digest: str
    scylla_identity_set_digest: str
    target_intent_digest: str
    target_provenance_digest: str
    target_count: int
    target_set_digest: str
    generated_count: int
    changed_count: int
    no_change_count: int
    listen_policy: str
    scrape_readiness: str
    prohibited_action_count: int
    original_mapping_count: int
    original_mapping_digest: str
    original_mapping_unchanged: bool
    steps: tuple[DeployPostMonitoringTargetsStep, ...]
    step_count: int
    succeeded_count: int
    authorization_required_count: int
    eligible_count: int
    blocked_count: int
    not_performed_count: int
    next_mapping_sequence: int
    next_playbook: str
    next_condition_state: DeployConditionState
    next_classification: OperationClassification
    next_step_status: DeployBaseOsReconciledStepStatus
    next_target_count: int
    next_target_set_digest: str
    next_evidence_digest: str | None
    next_blocker_digest: str
    next_execution_state: str
    finalization_state: str
    public_workflow_state: str
    record_digest: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCHEMA_VERSION
    )
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_TARGETS_EVIDENCE_SCHEMA_VERSION
    )
    post_monitoring_agent_schema_version: str = (
        ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_MONITORING_TARGETS_EVIDENCE_SCHEMA_VERSION
            or self.post_monitoring_agent_schema_version
            != ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or not self.authorization_consumed
            or self.execution_state
            is not DeployMonitoringTargetsExecutionState.SUCCEEDED
            or self.stack_version_digest != _digest_object(STACK_VERSION)
            or self.file_count != len(TARGET_FILES)
            or self.target_count != 1
            or self.generated_count != 1
            or self.changed_count + self.no_change_count != 1
            or self.listen_policy != "not-started"
            or self.scrape_readiness != SCRAPE_READINESS
            or self.prohibited_action_count
            or self.original_mapping_count != _ORIGINAL_MAPPING_COUNT
            or self.original_mapping_digest != _mapping_digest()
            or not self.original_mapping_unchanged
            or self.next_mapping_sequence != _MANAGER_TASKS_MAPPING
            or self.next_playbook != _MANAGER_TASKS_PLAYBOOK
            or self.next_condition_state is not DeployConditionState.UNMODELED
            or self.next_classification is not OperationClassification.SENSITIVE
            or self.next_step_status is not DeployBaseOsReconciledStepStatus.BLOCKED
            or self.next_evidence_digest is not None
            or self.next_execution_state != _NOT_STARTED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
        ):
            raise StatePersistenceError(
                "post-monitoring-targets reconciliation identity conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for count in (
            self.journal_generation,
            self.execution_generation,
            self.evidence_generation,
            self.metadata_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
            self.file_count,
            self.manager_target_count,
            self.scylla_target_count,
            self.node_exporter_target_count,
            self.manager_agent_target_count,
            self.target_count,
            self.generated_count,
            self.changed_count,
            self.no_change_count,
            self.prohibited_action_count,
            self.step_count,
            self.succeeded_count,
            self.authorization_required_count,
            self.eligible_count,
            self.blocked_count,
            self.not_performed_count,
            self.next_mapping_sequence,
            self.next_target_count,
        ):
            _nonnegative_integer(count, "post-monitoring-targets count")
        if (
            self.journal_generation < 1
            or self.execution_generation < 1
            or self.evidence_generation != 1
            or self.metadata_generation < 1
            or self.observation_generation < 1
            or self.inventory_generation < 1
            or self.trust_generation < 1
            or self.manager_target_count != 1
            or self.scylla_target_count < 1
            or self.node_exporter_target_count != self.scylla_target_count
            or self.manager_agent_target_count != self.scylla_target_count
            or self.step_count != len(self.steps)
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, len(self.steps) + 1))
            or tuple(sorted({step.mapping_sequence for step in self.steps}))
            != tuple(range(1, _ORIGINAL_MAPPING_COUNT + 1))
        ):
            raise StatePersistenceError(
                "post-monitoring-targets reconciliation counts conflict"
            )
        mapping = OPERATION_PLAYBOOKS[_OPERATION]
        if len(mapping) != _ORIGINAL_MAPPING_COUNT or any(
            step.playbook != mapping[step.mapping_sequence - 1].playbook
            or step.condition != mapping[step.mapping_sequence - 1].condition
            for step in self.steps
        ):
            raise StatePersistenceError(
                "post-monitoring-targets immutable mapping conflicts"
            )
        targets = tuple(
            step for step in self.steps if step.mapping_sequence == _TARGETS_MAPPING
        )
        manager_tasks = tuple(
            step
            for step in self.steps
            if step.mapping_sequence == _MANAGER_TASKS_MAPPING
        )
        advanced = {
            DeployBaseOsReconciledStepStatus.SUCCEEDED,
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
        counts = Counter(step.status for step in self.steps)
        if (
            len(targets) != 1
            or targets[0].playbook != _TARGETS_PLAYBOOK
            or targets[0].status is not DeployBaseOsReconciledStepStatus.SUCCEEDED
            or targets[0].evidence_state != _TARGETS_EVIDENCE_STATE
            or targets[0].evidence_digest != self.evidence_digest
            or targets[0].target_digest != self.target_set_digest
            or len(manager_tasks) != 1
            or manager_tasks[0].condition != "explicit-task-action"
            or manager_tasks[0].condition_state is not DeployConditionState.UNMODELED
            or manager_tasks[0].status is not DeployBaseOsReconciledStepStatus.BLOCKED
            or manager_tasks[0].blockers != _MANAGER_TASK_BLOCKERS
            or manager_tasks[0].evidence_digest is not None
            or len(manager_tasks[0].target_ids) != self.next_target_count
            or manager_tasks[0].target_digest != self.next_target_set_digest
            or manager_tasks[0].blocker_digest != self.next_blocker_digest
            or any(
                step.mapping_sequence > _TARGETS_MAPPING and step.status in advanced
                for step in self.steps
            )
            or self.succeeded_count
            != counts[DeployBaseOsReconciledStepStatus.SUCCEEDED]
            or self.authorization_required_count
            != counts[
                DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            ]
            or self.eligible_count != counts[DeployBaseOsReconciledStepStatus.ELIGIBLE]
            or self.blocked_count != counts[DeployBaseOsReconciledStepStatus.BLOCKED]
            or self.not_performed_count
            != counts[DeployBaseOsReconciledStepStatus.NOT_PERFORMED]
            or self.record_digest != _record_digest(self)
        ):
            raise StatePersistenceError(
                "post-monitoring-targets reconciliation summary conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "post-monitoring-targets reconciliation digest")

    def to_object(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            result[name] = (
                str(value)
                if isinstance(value, uuid.UUID)
                else value.value
                if isinstance(value, StrEnum)
                else [step.to_object() for step in value]
                if name == "steps"
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployPostMonitoringTargetsReconciliation:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "post-monitoring-targets reconciliation",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "execution_generation",
            "evidence_generation",
            "metadata_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
            "file_count",
            "manager_target_count",
            "scylla_target_count",
            "node_exporter_target_count",
            "manager_agent_target_count",
            "target_count",
            "generated_count",
            "changed_count",
            "no_change_count",
            "prohibited_action_count",
            "original_mapping_count",
            "step_count",
            "succeeded_count",
            "authorization_required_count",
            "eligible_count",
            "blocked_count",
            "not_performed_count",
            "next_mapping_sequence",
            "next_target_count",
        }
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
                elif name == "execution_state":
                    parsed[name] = DeployMonitoringTargetsExecutionState(
                        require_string(value, name)
                    )
                elif name == "next_condition_state":
                    parsed[name] = DeployConditionState(require_string(value, name))
                elif name == "next_classification":
                    parsed[name] = OperationClassification(require_string(value, name))
                elif name == "next_step_status":
                    parsed[name] = DeployBaseOsReconciledStepStatus(
                        require_string(value, name)
                    )
                elif name in {
                    "authorization_consumed",
                    "original_mapping_unchanged",
                }:
                    parsed[name] = _boolean(item, name)
                elif name == "next_evidence_digest":
                    parsed[name] = _optional_string(item, name)
                elif name == "steps":
                    parsed[name] = tuple(
                        DeployPostMonitoringTargetsStep.from_object(
                            _mapping(step, "post-monitoring-targets step")
                        )
                        for step in _array(item, "steps")
                    )
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "post-monitoring-targets reconciliation enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployPostMonitoringTargetsReconciliation:
    record: DeployPostMonitoringTargetsReconciliation
    artifact_digest: str


class DeployPostMonitoringTargetsReconciliationStore:
    """Owner-only immutable reconciliation at the canonical operation path."""

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
        self._path = deploy_post_monitoring_targets_reconciliation_path(
            paths, operation_id
        )
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
    ) -> StoredDeployPostMonitoringTargetsReconciliation:
        value, artifact_digest = self._file.read()
        record = DeployPostMonitoringTargetsReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "post-monitoring-targets reconciliation identity conflicts"
            )
        return StoredDeployPostMonitoringTargetsReconciliation(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPostMonitoringTargetsReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployPostMonitoringTargetsReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployPostMonitoringTargetsReconciliation,
        DeployPostMonitoringTargetsArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "post-monitoring-targets reconciliation operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "post-monitoring-targets reconciliation is immutable; "
                    "use a new operation"
                )
            return current, DeployPostMonitoringTargetsArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployPostMonitoringTargetsReconciliation(record, digest),
            DeployPostMonitoringTargetsArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployPostMonitoringTargetsReconciliationReport:
    """Strict bounded post-monitoring-targets reconciliation projection."""

    operation_id: uuid.UUID
    artifact_state: DeployPostMonitoringTargetsArtifactState
    reconciliation_artifact_digest: str
    reconciliation_record_digest: str
    effective_plan_digest: str
    execution_artifact_digest: str
    evidence_artifact_digest: str
    evidence_digest: str
    target_intent_digest: str
    target_provenance_digest: str
    target_count: int
    target_set_digest: str
    generated_count: int
    changed_count: int
    no_change_count: int
    file_count: int
    file_set_digest: str
    file_content_set_digest: str
    prohibited_action_count: int
    authorization_consumed: bool
    execution_state: DeployMonitoringTargetsExecutionState
    original_mapping_unchanged: bool
    succeeded_count: int
    authorization_required_count: int
    eligible_count: int
    blocked_count: int
    not_performed_count: int
    next_mapping_sequence: int
    next_playbook: str
    next_condition_state: DeployConditionState
    next_classification: OperationClassification
    next_step_status: DeployBaseOsReconciledStepStatus
    next_target_count: int
    next_target_set_digest: str
    next_blocker_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    process_calls: int = 0
    authorization_created: bool = False
    execution_started: bool = False
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_REPORT_SCHEMA_VERSION
            or self.target_count != 1
            or self.generated_count != 1
            or self.changed_count + self.no_change_count != 1
            or self.file_count != len(TARGET_FILES)
            or self.prohibited_action_count
            or not self.authorization_consumed
            or self.execution_state
            is not DeployMonitoringTargetsExecutionState.SUCCEEDED
            or not self.original_mapping_unchanged
            or self.next_mapping_sequence != _MANAGER_TASKS_MAPPING
            or self.next_playbook != _MANAGER_TASKS_PLAYBOOK
            or self.next_condition_state is not DeployConditionState.UNMODELED
            or self.next_step_status is not DeployBaseOsReconciledStepStatus.BLOCKED
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.process_calls
            or self.authorization_created
            or self.execution_started
        ):
            raise StatePersistenceError(
                "post-monitoring-targets reconciliation report conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "post-monitoring-targets report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "artifact": {
                "digest": self.reconciliation_artifact_digest,
                "record_digest": self.reconciliation_record_digest,
                "state": self.artifact_state.value,
            },
            "counts": {
                "authorization_required": self.authorization_required_count,
                "blocked": self.blocked_count,
                "eligible": self.eligible_count,
                "not_performed": self.not_performed_count,
                "succeeded": self.succeeded_count,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "mapping": {
                "effective_plan_digest": self.effective_plan_digest,
                "original_unchanged": self.original_mapping_unchanged,
            },
            "monitoring_targets": {
                "authorization_consumed": self.authorization_consumed,
                "changed_count": self.changed_count,
                "evidence_artifact_digest": self.evidence_artifact_digest,
                "evidence_digest": self.evidence_digest,
                "execution_artifact_digest": self.execution_artifact_digest,
                "execution_state": self.execution_state.value,
                "file_content_set_digest": self.file_content_set_digest,
                "file_count": self.file_count,
                "file_set_digest": self.file_set_digest,
                "generated_count": self.generated_count,
                "no_change_count": self.no_change_count,
                "prohibited_action_count": self.prohibited_action_count,
                "target_count": self.target_count,
                "target_intent_digest": self.target_intent_digest,
                "target_provenance_digest": self.target_provenance_digest,
                "target_set_digest": self.target_set_digest,
            },
            "next_gate": {
                "blocker_digest": self.next_blocker_digest,
                "classification": self.next_classification.value,
                "condition_state": self.next_condition_state.value,
                "mapping_sequence": self.next_mapping_sequence,
                "playbook": self.next_playbook,
                "status": self.next_step_status.value,
                "target_count": self.next_target_count,
                "target_set_digest": self.next_target_set_digest,
            },
            "operation_id": str(self.operation_id),
            "schema_version": self.schema_version,
            "side_effects": {
                "authorization_created": self.authorization_created,
                "execution_started": self.execution_started,
                "process_calls": self.process_calls,
            },
        }


@dataclass(frozen=True, slots=True)
class _ReconciliationContext:
    authorization_context: _AuthorizationContext
    authorization: StoredDeployMonitoringTargetsAuthorization
    execution: StoredDeployMonitoringTargetsExecution
    evidence: StoredDeployMonitoringTargetsEvidence


def reconcile_deploy_monitoring_targets_result(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployPostMonitoringTargetsReconciliationReport:
    """Bind exact target-file success without advancing manager-tasks."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _validate_original_mapping()
    _refuse_ambiguous_or_later_artifacts(paths, operation_id)
    context = _load_context(paths, operation_id, lock=lock)
    steps = _build_steps(context)
    store = DeployPostMonitoringTargetsReconciliationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    existing = (
        store.read_locked(
            lock,
            expected_cluster_uuid=context.authorization.record.cluster_uuid,
            expected_cluster_name=paths.cluster_root.name,
        )
        if store.path.exists()
        else None
    )
    record = _build_record(
        context,
        steps=steps,
        created_at=None if existing is None else existing.record.created_at,
    )
    stored, state = store.write_locked(record, lock=lock)
    return _build_report(stored, state=state)


def deploy_post_monitoring_targets_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the canonical operation-bound post-monitoring-targets path."""

    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "post-monitoring-targets reconciliation path is not canonical"
        )
    return path


def deploy_post_monitoring_targets_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    suffix = DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_FILENAME_SUFFIX
    if not name.endswith(suffix):
        return None
    value = name[: -len(suffix)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _load_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
) -> _ReconciliationContext:
    authorization_context = _load_authorization_context(paths, operation_id, lock=lock)
    loaded = _loaded(
        authorization_context.agent.authorization_context.manager.authorization_context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    metadata = loaded.planning.base.deploy.metadata.record
    authorization_store = DeployMonitoringTargetsAuthorizationStore(paths, operation_id)
    execution_store = DeployMonitoringTargetsExecutionStore(paths, operation_id)
    evidence_store = DeployMonitoringTargetsEvidenceStore(paths, operation_id)
    for path, label in (
        (authorization_store.path, "authorization"),
        (execution_store.path, "execution"),
        (evidence_store.path, "evidence"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"post-monitoring-targets reconciliation requires complete {label}"
            )
    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    scope = _derive_authorization_scope(authorization_context)
    expected_authorization = _build_authorization(
        authorization_context,
        scope=scope,
        proof=authorization.record.proof,
        created_at=authorization.record.created_at,
    )
    if authorization.record != expected_authorization:
        raise StateConflictError(
            "post-monitoring-targets authorization or canonical scope drifted"
        )
    execution = execution_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    evidence = evidence_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    context = _ReconciliationContext(
        authorization_context, authorization, execution, evidence
    )
    _validate_complete_execution(context)
    return context


def _validate_complete_execution(context: _ReconciliationContext) -> None:
    authorization_context = context.authorization_context
    agent_context = authorization_context.agent.authorization_context
    manager_agent_context = agent_context.manager.authorization_context
    loaded = _loaded(
        manager_agent_context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    planning = loaded.planning
    deploy = planning.base.deploy
    authorization = context.authorization.record
    scope = authorization.scope
    execution = context.execution.record
    evidence = context.evidence.record
    binding = execution.binding
    attempt = execution.attempt
    entries = evidence.entries
    if (
        authorization.consumed
        or authorization.authorization_state != "authorized-pre-execution"
        or authorization.execution_state != _UNAVAILABLE
        or execution.state is not DeployMonitoringTargetsExecutionState.SUCCEEDED
        or not execution.completed
        or execution.manual_recovery_required
        or not execution.authorization_consumed
        or execution.invocation_count != 1
        or attempt.state is not DeployMonitoringTargetsExecutionState.SUCCEEDED
        or not attempt.authorization_consumed_at_start
        or not attempt.invocation_may_have_occurred
        or attempt.manual_recovery_required
        or attempt.automatic_retry_allowed
        or attempt.exit_code != 0
        or attempt.result_digest is None
        or attempt.evidence_digest is None
        or evidence.generation != 1
        or len(entries) != 1
        or evidence.binding != binding
    ):
        raise StateConflictError(
            "post-monitoring-targets reconciliation requires exact terminal success"
        )
    post_agent = authorization_context.post_agent
    stack_evidence = manager_agent_context.monitoring.evidence
    manager_server_evidence = (
        manager_agent_context.monitoring.monitoring.manager.evidence
    )
    manager_agent_evidence = agent_context.manager.evidence
    monitoring_agent_evidence = authorization_context.agent.evidence
    base_os = manager_agent_context.monitoring.monitoring.manager.manager.base_os
    trust = planning.base.trust
    readiness = planning.readiness
    expected_execution_scope_digest = _digest_object(
        {
            "authorization_scope_digest": authorization.authorization_scope_digest,
            "command_digest": scope.command_digest,
            "mapping_sequence": _TARGETS_MAPPING,
            "source_digest": scope.source_digest,
            "target_intent_digest": scope.target_intent_digest,
            "target_set_digest": scope.target_digest,
            "variables_digest": scope.variables_digest,
        }
    )
    if (
        binding.cluster_uuid != authorization.cluster_uuid
        or binding.cluster_name != deploy.metadata.record.cluster_name
        or binding.operation_id != authorization.operation_id
        or binding.operation != _OPERATION
        or binding.request_digest != authorization.request_digest
        or binding.journal_generation != deploy.journal.record.generation
        or binding.journal_digest != deploy.journal.digest
        or binding.journal_status is not JournalStatus.IN_PROGRESS
        or binding.journal_phase is not OperationPhase.VERIFY
        or binding.authorization_artifact_digest
        != context.authorization.artifact_digest
        or binding.authorization_digest != authorization.authorization_digest
        or binding.authorization_scope_digest
        != authorization.authorization_scope_digest
        or binding.authorization_proof_digest != authorization.proof.proof_digest
        or binding.post_monitoring_agent_artifact_digest != post_agent.artifact_digest
        or binding.post_monitoring_agent_record_digest
        != post_agent.record.record_digest
        or binding.post_monitoring_agent_effective_plan_digest
        != authorization.post_monitoring_agent_effective_plan_digest
        or binding.monitoring_stack_evidence_artifact_digest
        != stack_evidence.artifact_digest
        or binding.manager_server_evidence_artifact_digest
        != manager_server_evidence.artifact_digest
        or binding.manager_agent_evidence_artifact_digest
        != manager_agent_evidence.artifact_digest
        or binding.monitoring_agent_evidence_artifact_digest
        != monitoring_agent_evidence.artifact_digest
        or binding.base_os_artifact_digest != base_os.artifact_digest
        or binding.base_os_evidence_digest != scope.base_os_evidence_digest
        or binding.metadata_generation != deploy.metadata.record.generation
        or binding.metadata_artifact_digest != deploy.metadata.digest
        or binding.desired_spec_digest != deploy.metadata.record.desired_spec.digest()
        or binding.observation_generation != deploy.observation.record.generation
        or binding.observation_artifact_digest != deploy.observation.digest
        or binding.observation_manifest_digest
        != deploy.observation.record.manifest_digest
        or binding.inventory_generation != deploy.inventory.record.generation
        or binding.inventory_artifact_digest != deploy.inventory.digest
        or binding.inventory_digest != deploy.inventory.record.inventory_digest
        or binding.trust_generation != trust.record.generation
        or binding.trust_artifact_digest != trust.digest
        or binding.trust_entries_digest != trust.record.entries_digest
        or binding.readiness_artifact_digest != readiness.artifact_digest
        or binding.readiness_record_digest != readiness.record.record_digest
        or binding.catalog_digest != loaded.catalog_digest
        or binding.source_version != loaded.source.version
        or binding.source_digest != loaded.source.digest
        or binding.playbook_source_digest
        != _playbook_source_digest(loaded.source, _TARGETS_PLAYBOOK)
        or binding.toolchain_version != readiness.record.playbook_version
        or binding.toolchain_version != readiness.record.inventory_version
        or binding.executable_identity_digest
        != readiness.record.executable_identity_digest
        or binding.toolchain_evidence_digest
        != readiness.record.toolchain_evidence_digest
        or binding.target_stable_id != scope.target_stable_id
        or binding.target_set_digest != scope.target_digest
        or binding.target_intent_digest != scope.target_intent_digest
        or binding.variables_digest != scope.variables_digest
        or binding.command_digest != scope.command_digest
        or binding.execution_scope_digest != expected_execution_scope_digest
    ):
        raise StateConflictError(
            "post-monitoring-targets inventory, trust, readiness, source, "
            "catalog, authorization, prior-chain, or journal binding drifted"
        )
    _validate_entry(context, entries[0])


def _validate_entry(
    context: _ReconciliationContext,
    entry: DeployMonitoringTargetsEvidenceEntry,
) -> None:
    authorization = context.authorization.record
    scope = authorization.scope
    execution = context.execution.record
    binding = execution.binding
    attempt = execution.attempt
    expected_provenance = _expected_provenance_digest(context)
    prohibited = _prohibited_actions(entry)
    expected_result = _digest_object(
        {
            "changed": entry.changed,
            "file_content_set_digest": entry.file_content_set_digest,
            "file_count": entry.file_count,
            "file_set_digest": entry.file_set_digest,
            "listen_policy": entry.listen_policy,
            "logical_id": entry.stable_id,
            "manager_agent_target_count": entry.manager_agent_target_count,
            "manager_identity_set_digest": entry.manager_identity_set_digest,
            "manager_target_count": entry.manager_target_count,
            "node_exporter_target_count": entry.node_exporter_target_count,
            "prohibited_action_count": sum(prohibited),
            "provenance_digest": entry.provenance_digest,
            "schema_version": entry.result_schema_version,
            "scrape_readiness": entry.scrape_readiness,
            "scylla_identity_set_digest": entry.scylla_identity_set_digest,
            "scylla_target_count": entry.scylla_target_count,
            "status": entry.status.value,
        }
    )
    if (
        attempt.attempt_index != 1
        or attempt.mapping_sequence != _TARGETS_MAPPING
        or attempt.stable_id != scope.target_stable_id
        or attempt.target_digest != scope.target_digest
        or attempt.authorization_scope_digest
        != authorization.authorization_scope_digest
        or attempt.authorization_variables_digest != scope.variables_digest
        or attempt.authorization_command_digest != scope.command_digest
        or attempt.variables_digest != scope.variables_digest
        or attempt.command_digest != scope.command_digest
        or attempt.source_digest != scope.source_digest
        or attempt.stack_version_digest != _digest_object(STACK_VERSION)
        or attempt.target_intent_digest != scope.target_intent_digest
        or attempt.result_digest != entry.result_digest
        or attempt.evidence_digest != entry.evidence_digest
        or entry.attempt_index != 1
        or entry.mapping_sequence != _TARGETS_MAPPING
        or entry.stable_id != scope.target_stable_id
        or entry.image_architecture != scope.architecture.value
        or entry.status
        not in {MonitoringTargetsStatus.GENERATED, MonitoringTargetsStatus.NO_CHANGE}
        or not entry.generated
        or entry.changed != (entry.status is MonitoringTargetsStatus.GENERATED)
        or entry.stack_version_digest != _digest_object(STACK_VERSION)
        or entry.file_count != len(TARGET_FILES)
        or entry.file_count != scope.file_count
        or entry.file_set_digest != scope.file_set_digest
        or entry.file_content_set_digest != scope.file_content_set_digest
        or entry.manager_target_count != scope.manager_target_count
        or entry.scylla_target_count != scope.scylla_target_count
        or entry.node_exporter_target_count != scope.node_exporter_target_count
        or entry.manager_agent_target_count != scope.manager_agent_target_count
        or entry.manager_identity_set_digest != scope.manager_identity_set_digest
        or entry.scylla_identity_set_digest != scope.scylla_identity_set_digest
        or entry.listen_policy != scope.listen_policy.value
        or entry.listen_policy != "not-started"
        or entry.scrape_readiness != scope.scrape_readiness.value
        or entry.scrape_readiness != SCRAPE_READINESS
        or any(prohibited)
        or entry.provenance_digest != expected_provenance
        or entry.variables_digest != binding.variables_digest
        or entry.command_digest != binding.command_digest
        or entry.source_digest != binding.playbook_source_digest
        or entry.result_digest != expected_result
        or entry.manual_recovery_required
        or entry.automatic_retry_allowed
    ):
        raise StateConflictError(
            "post-monitoring-targets four-file intent, execution, provenance, "
            "or prohibited-action evidence conflicts"
        )


def _expected_provenance_digest(context: _ReconciliationContext) -> str:
    authorization_context = context.authorization_context
    agent_context = authorization_context.agent.authorization_context
    manager_agent_context = agent_context.manager.authorization_context
    loaded = _loaded(
        manager_agent_context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    planning = loaded.planning
    deploy = planning.base.deploy
    scope = context.authorization.record.scope
    base_os = manager_agent_context.monitoring.monitoring.manager.manager.base_os
    matches = tuple(
        (record, host)
        for record in base_os.record.entries
        for host in record.hosts
        if host.logical_id == scope.target_stable_id
    )
    if len(matches) != 1:
        raise StateConflictError(
            "post-monitoring-targets current base-os evidence is ambiguous"
        )
    _base_record, host = matches[0]
    image_filter = dict(deploy.metadata.record.desired_spec.image_filters).get(
        HostRole.MONITORING
    )
    if (
        image_filter is None
        or host.status not in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
        or not host.applied
        or host.reboot_required
    ):
        raise StateConflictError(
            "post-monitoring-targets current target prerequisites conflict"
        )
    current_base = BaseOsEvidence(
        host.status,
        (
            BaseOsHostEvidence(
                host.logical_id,
                host.status,
                host.changed,
                host.reboot_required,
                "canonical-deploy-evidence",
            ),
        ),
    )
    readiness = _reconstructed_readiness(planning.base)
    stack_entry = manager_agent_context.monitoring.evidence.record.entries[0]
    stack_payload = build_monitoring_stack_payload(
        deploy.metadata.record,
        deploy.observation,
        deploy.inventory,
        readiness,
        current_base,
        logical_id=scope.target_stable_id,
        image_filter=image_filter,
        architecture=host.image_architecture,
        stack_version=STACK_VERSION,
        cluster_spec_digest=deploy.metadata.record.desired_spec.digest(),
    )
    stack = _reconstruct_stack_evidence(stack_entry, stack_payload)
    target_readiness = replace(
        readiness,
        observation_digest=deploy.observation.digest,
    )
    payload = build_monitoring_targets_payload(
        deploy.metadata.record,
        deploy.observation,
        deploy.inventory,
        target_readiness,
        current_base,
        stack,
        logical_id=scope.target_stable_id,
        image_filter=image_filter,
        architecture=host.image_architecture,
        cluster_spec_digest=deploy.metadata.record.desired_spec.digest(),
    )
    provenance = payload.get("provenance")
    if not isinstance(provenance, Mapping):
        raise StateConflictError(
            "post-monitoring-targets current target provenance is malformed"
        )
    return _digest_object(dict(provenance))


def _build_steps(
    context: _ReconciliationContext,
) -> tuple[DeployPostMonitoringTargetsStep, ...]:
    prior_steps = context.authorization_context.post_agent.record.steps
    if tuple(sorted({step.mapping_sequence for step in prior_steps})) != tuple(
        range(1, _ORIGINAL_MAPPING_COUNT + 1)
    ):
        raise StateConflictError(
            "post-monitoring-targets prior mapping is incomplete or duplicated"
        )
    entry = context.evidence.record.entries[0]
    result: list[DeployPostMonitoringTargetsStep] = []
    targets_seen = 0
    manager_tasks_seen = 0
    advanced = {
        DeployBaseOsReconciledStepStatus.SUCCEEDED,
        DeployBaseOsReconciledStepStatus.ELIGIBLE,
        DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
    }
    for prior in prior_steps:
        _validate_prior_step(prior)
        status = prior.status
        evidence_state = prior.evidence_state
        evidence_digest = prior.evidence_digest
        blockers = prior.blockers
        if prior.mapping_sequence == _TARGETS_MAPPING:
            targets_seen += 1
            if (
                prior.status
                is not DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
                or prior.playbook != _TARGETS_PLAYBOOK
                or prior.condition_state is not DeployConditionState.ACTIVE
                or prior.target_ids != (entry.stable_id,)
                or prior.target_digest != context.authorization.record.target_set_digest
            ):
                raise StateConflictError(
                    "post-monitoring-targets executed mapping identity conflicts"
                )
            status = DeployBaseOsReconciledStepStatus.SUCCEEDED
            evidence_state = _TARGETS_EVIDENCE_STATE
            evidence_digest = entry.evidence_digest
            blockers = ()
        elif prior.mapping_sequence == _MANAGER_TASKS_MAPPING:
            manager_tasks_seen += 1
            _validate_manager_tasks_step(prior)
        elif prior.mapping_sequence > _TARGETS_MAPPING and prior.status in advanced:
            raise StateConflictError(
                "post-monitoring-targets later mapped gate already advanced"
            )
        result.append(
            _step_from_prior(
                prior,
                status=status,
                evidence_state=evidence_state,
                evidence_digest=evidence_digest,
                blockers=blockers,
            )
        )
    if targets_seen != 1 or manager_tasks_seen != 1:
        raise StateConflictError("post-monitoring-targets mapped scope is ambiguous")
    return tuple(result)


def _validate_prior_step(prior: DeployPostMonitoringAgentStep) -> None:
    mapping = OPERATION_PLAYBOOKS[_OPERATION]
    definition = mapping[prior.mapping_sequence - 1]
    if (
        prior.playbook != definition.playbook
        or prior.condition != definition.condition
        or prior.source_digest == ""
        or prior.command_digest == ""
        or prior.variables_digest == ""
    ):
        raise StateConflictError(
            "post-monitoring-targets historical step identity drifted"
        )


def _validate_manager_tasks_step(prior: DeployPostMonitoringAgentStep) -> None:
    definition = get_playbook(_MANAGER_TASKS_PLAYBOOK)
    if (
        prior.playbook != _MANAGER_TASKS_PLAYBOOK
        or prior.condition != "explicit-task-action"
        or prior.condition_state is not DeployConditionState.UNMODELED
        or prior.classification is not OperationClassification.SENSITIVE
        or prior.status is not DeployBaseOsReconciledStepStatus.BLOCKED
        or prior.evidence_digest is not None
        or prior.blockers != _MANAGER_TASK_BLOCKERS
        or definition.classification is not OperationClassification.SENSITIVE
        or definition.hosts != HostRole.MANAGER.value
        or definition.serial != 1
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.check_mode is not CheckMode.PREVIEW
        or not definition.any_errors_fatal
        or not definition.source_available
        or MANAGER_TASKS_SCHEMA_VERSION != "deploy-scylla-vms.ansible-manager-tasks/v1"
        or tuple(MANAGER_TASK_ACTIONS) != ("inspect", "quiesce", "resume", "validate")
        or tuple(MANAGER_TASK_KINDS) != ("backup", "repair")
        or tuple(MANAGER_TASK_NOT_PERFORMED)
        != (
            "auth-token",
            "backend-configure",
            "cluster-registration",
            "manager-start",
            "sctool-backup",
            "sctool-repair",
            "sctool-resume",
            "sctool-suspend",
            "sctool-tasks",
        )
        or tuple(MANAGER_TASK_EXPECTED_BLOCKERS)
        != (
            "backend-unconfigured",
            "manager-inactive",
            "manager-unregistered",
        )
    ):
        raise StateConflictError(
            "post-monitoring-targets manager-tasks blockers or "
            "validation-only contract conflicts"
        )


def _step_from_prior(
    prior: DeployPostMonitoringAgentStep,
    *,
    status: DeployBaseOsReconciledStepStatus,
    evidence_state: str,
    evidence_digest: str | None,
    blockers: tuple[str, ...],
) -> DeployPostMonitoringTargetsStep:
    values: dict[str, object] = {
        "sequence": prior.sequence,
        "mapping_sequence": prior.mapping_sequence,
        "playbook": prior.playbook,
        "condition": prior.condition,
        "condition_state": prior.condition_state,
        "classification": prior.classification,
        "target_role": prior.target_role,
        "target_ids": prior.target_ids,
        "target_digest": prior.target_digest,
        "limit_policy": prior.limit_policy,
        "serial": prior.serial,
        "check_mode": prior.check_mode,
        "variable_names": prior.variable_names,
        "variables_digest": prior.variables_digest,
        "source_digest": prior.source_digest,
        "command_digest": prior.command_digest,
        "original_step_digest": prior.original_step_digest,
        "prior_step_digest": _digest_object(prior.to_object()),
        "status": status,
        "evidence_state": evidence_state,
        "evidence_digest": evidence_digest,
        "blockers": tuple(sorted(blockers)),
        "blocker_digest": _digest_object(list(sorted(blockers))),
        "step_digest": "",
    }
    values["step_digest"] = _step_digest_from_values(values)
    return DeployPostMonitoringTargetsStep(**values)  # type: ignore[arg-type]


def _build_record(
    context: _ReconciliationContext,
    *,
    steps: tuple[DeployPostMonitoringTargetsStep, ...],
    created_at: str | None,
) -> DeployPostMonitoringTargetsReconciliation:
    authorization_context = context.authorization_context
    agent_context = authorization_context.agent.authorization_context
    manager_agent_context = agent_context.manager.authorization_context
    loaded = _loaded(
        manager_agent_context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    deploy = loaded.planning.base.deploy
    authorization = context.authorization.record
    execution = context.execution.record
    binding = execution.binding
    evidence = context.evidence.record
    entry = evidence.entries[0]
    scope = authorization.scope
    manager_tasks = tuple(
        step for step in steps if step.mapping_sequence == _MANAGER_TASKS_MAPPING
    )
    if len(manager_tasks) != 1:
        raise StateConflictError(
            "post-monitoring-targets manager-tasks mapping is ambiguous"
        )
    next_step = manager_tasks[0]
    counts = Counter(step.status for step in steps)
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at or format_timestamp(datetime.now(UTC)),
        "cluster_uuid": authorization.cluster_uuid,
        "cluster_name": deploy.metadata.record.cluster_name,
        "operation_id": authorization.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "request_digest": authorization.request_digest,
        "journal_generation": binding.journal_generation,
        "journal_digest": binding.journal_digest,
        "journal_status": binding.journal_status,
        "journal_phase": binding.journal_phase,
        "post_monitoring_agent_artifact_digest": (
            authorization_context.post_agent.artifact_digest
        ),
        "post_monitoring_agent_record_digest": (
            authorization_context.post_agent.record.record_digest
        ),
        "post_monitoring_agent_effective_plan_digest": (
            authorization.post_monitoring_agent_effective_plan_digest
        ),
        "authorization_artifact_digest": context.authorization.artifact_digest,
        "authorization_digest": authorization.authorization_digest,
        "authorization_scope_digest": authorization.authorization_scope_digest,
        "authorization_proof_digest": authorization.proof.proof_digest,
        "authorization_consumed": execution.authorization_consumed,
        "execution_artifact_digest": context.execution.artifact_digest,
        "execution_binding_digest": binding.binding_digest,
        "execution_generation": execution.generation,
        "execution_state": execution.state,
        "evidence_artifact_digest": context.evidence.artifact_digest,
        "evidence_generation": evidence.generation,
        "evidence_digest": entry.evidence_digest,
        "result_digest": entry.result_digest,
        "metadata_generation": binding.metadata_generation,
        "metadata_artifact_digest": binding.metadata_artifact_digest,
        "desired_spec_digest": binding.desired_spec_digest,
        "observation_generation": binding.observation_generation,
        "observation_artifact_digest": binding.observation_artifact_digest,
        "observation_manifest_digest": binding.observation_manifest_digest,
        "inventory_generation": binding.inventory_generation,
        "inventory_artifact_digest": binding.inventory_artifact_digest,
        "inventory_digest": binding.inventory_digest,
        "trust_generation": binding.trust_generation,
        "trust_artifact_digest": binding.trust_artifact_digest,
        "trust_entries_digest": binding.trust_entries_digest,
        "readiness_artifact_digest": binding.readiness_artifact_digest,
        "readiness_record_digest": binding.readiness_record_digest,
        "catalog_digest": binding.catalog_digest,
        "ansible_source_version": binding.source_version,
        "ansible_source_digest": binding.source_digest,
        "playbook_source_digest": binding.playbook_source_digest,
        "toolchain_version": binding.toolchain_version,
        "executable_identity_digest": binding.executable_identity_digest,
        "toolchain_evidence_digest": binding.toolchain_evidence_digest,
        "stack_version_digest": entry.stack_version_digest,
        "file_count": entry.file_count,
        "file_set_digest": entry.file_set_digest,
        "file_content_set_digest": entry.file_content_set_digest,
        "manager_target_count": entry.manager_target_count,
        "scylla_target_count": entry.scylla_target_count,
        "node_exporter_target_count": entry.node_exporter_target_count,
        "manager_agent_target_count": entry.manager_agent_target_count,
        "manager_identity_set_digest": entry.manager_identity_set_digest,
        "scylla_identity_set_digest": entry.scylla_identity_set_digest,
        "target_intent_digest": scope.target_intent_digest,
        "target_provenance_digest": entry.provenance_digest,
        "target_count": 1,
        "target_set_digest": binding.target_set_digest,
        "generated_count": int(entry.generated),
        "changed_count": int(entry.changed),
        "no_change_count": int(not entry.changed),
        "listen_policy": entry.listen_policy,
        "scrape_readiness": entry.scrape_readiness,
        "prohibited_action_count": sum(_prohibited_actions(entry)),
        "original_mapping_count": _ORIGINAL_MAPPING_COUNT,
        "original_mapping_digest": _mapping_digest(),
        "original_mapping_unchanged": True,
        "steps": steps,
        "step_count": len(steps),
        "succeeded_count": counts[DeployBaseOsReconciledStepStatus.SUCCEEDED],
        "authorization_required_count": counts[
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        ],
        "eligible_count": counts[DeployBaseOsReconciledStepStatus.ELIGIBLE],
        "blocked_count": counts[DeployBaseOsReconciledStepStatus.BLOCKED],
        "not_performed_count": counts[DeployBaseOsReconciledStepStatus.NOT_PERFORMED],
        "next_mapping_sequence": next_step.mapping_sequence,
        "next_playbook": next_step.playbook,
        "next_condition_state": next_step.condition_state,
        "next_classification": next_step.classification,
        "next_step_status": next_step.status,
        "next_target_count": len(next_step.target_ids),
        "next_target_set_digest": next_step.target_digest,
        "next_evidence_digest": next_step.evidence_digest,
        "next_blocker_digest": next_step.blocker_digest,
        "next_execution_state": _NOT_STARTED,
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(values)
    return DeployPostMonitoringTargetsReconciliation(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployPostMonitoringTargetsReconciliation,
    *,
    state: DeployPostMonitoringTargetsArtifactState,
) -> DeployPostMonitoringTargetsReconciliationReport:
    record = stored.record
    return DeployPostMonitoringTargetsReconciliationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        reconciliation_artifact_digest=stored.artifact_digest,
        reconciliation_record_digest=record.record_digest,
        effective_plan_digest=_digest_object(
            [step.to_object() for step in record.steps]
        ),
        execution_artifact_digest=record.execution_artifact_digest,
        evidence_artifact_digest=record.evidence_artifact_digest,
        evidence_digest=record.evidence_digest,
        target_intent_digest=record.target_intent_digest,
        target_provenance_digest=record.target_provenance_digest,
        target_count=record.target_count,
        target_set_digest=record.target_set_digest,
        generated_count=record.generated_count,
        changed_count=record.changed_count,
        no_change_count=record.no_change_count,
        file_count=record.file_count,
        file_set_digest=record.file_set_digest,
        file_content_set_digest=record.file_content_set_digest,
        prohibited_action_count=record.prohibited_action_count,
        authorization_consumed=record.authorization_consumed,
        execution_state=record.execution_state,
        original_mapping_unchanged=record.original_mapping_unchanged,
        succeeded_count=record.succeeded_count,
        authorization_required_count=record.authorization_required_count,
        eligible_count=record.eligible_count,
        blocked_count=record.blocked_count,
        not_performed_count=record.not_performed_count,
        next_mapping_sequence=record.next_mapping_sequence,
        next_playbook=record.next_playbook,
        next_condition_state=record.next_condition_state,
        next_classification=record.next_classification,
        next_step_status=record.next_step_status,
        next_target_count=record.next_target_count,
        next_target_set_digest=record.next_target_set_digest,
        next_blocker_digest=record.next_blocker_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
    )


def _validate_original_mapping() -> None:
    mapping = OPERATION_PLAYBOOKS[_OPERATION]
    if (
        len(mapping) != _ORIGINAL_MAPPING_COUNT
        or mapping[_TARGETS_MAPPING - 1].playbook != _TARGETS_PLAYBOOK
        or mapping[_MANAGER_TASKS_MAPPING - 1].playbook != _MANAGER_TASKS_PLAYBOOK
        or mapping[_MANAGER_TASKS_MAPPING - 1].condition != "explicit-task-action"
        or _mapping_digest()
        != _digest_object(
            [
                {
                    "condition": item.condition,
                    "mapping_sequence": index,
                    "playbook": item.playbook,
                }
                for index, item in enumerate(mapping, start=1)
            ]
        )
    ):
        raise StateConflictError(
            "post-monitoring-targets requires the immutable 21-position mapping"
        )


def _prohibited_actions(
    entry: DeployMonitoringTargetsEvidenceEntry,
) -> tuple[bool, ...]:
    return (
        entry.scrape_performed,
        entry.exporters_started,
        entry.stack_started,
        entry.containers_started,
        entry.compose_generated,
        entry.auth_configured,
        entry.public_bind,
        entry.manager_registration_performed,
        entry.scylla_started,
        entry.secrets_written,
    )


def _step_digest(step: DeployPostMonitoringTargetsStep) -> str:
    return _step_digest_from_values(step.to_object())


def _step_digest_from_values(values: Mapping[str, object]) -> str:
    return _digest_object(
        {
            name: _plain_value(value)
            for name, value in values.items()
            if name not in _STEP_DIGEST_EXCLUDED
        }
    )


def _record_digest(record: DeployPostMonitoringTargetsReconciliation) -> str:
    return _record_digest_from_object(record.to_object())


def _record_digest_from_values(values: Mapping[str, object]) -> str:
    result: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployPostMonitoringTargetsReconciliation.__dataclass_fields__.items():
        if name.endswith("schema_version"):
            continue
        value = values.get(name, field.default)
        result[name] = (
            [item.to_object() for item in value]
            if name == "steps" and isinstance(value, tuple)
            else value.value
            if isinstance(value, StrEnum)
            else str(value)
            if isinstance(value, uuid.UUID)
            else value
        )
    result["record_digest"] = ""
    return _digest_object(result)


def _record_digest_from_object(value: Mapping[str, object]) -> str:
    result = {
        name: item
        for name, item in value.items()
        if not name.endswith("schema_version")
    }
    result["record_digest"] = ""
    return _digest_object(result)


def _plain_value(value: object) -> object:
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, tuple):
        return list(value)
    return value


def _refuse_ambiguous_or_later_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    canonical = (
        f"{operation_id}{DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_FILENAME_SUFFIX}"
    )
    prefix = f"{operation_id}."
    later_fragments = (
        ".ansible-deploy-manager-tasks",
        ".ansible-deploy-post-manager-tasks",
        ".ansible-deploy-final-evidence",
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list post-monitoring-targets operation history"
        ) from error
    for entry in entries:
        if (
            entry.name.startswith(prefix)
            and "post-monitoring-targets-reconciliation" in entry.name
            and entry.name != canonical
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "post-monitoring-targets reconciliation artifacts are ambiguous"
            )
        if entry.name.startswith(prefix) and any(
            fragment in entry.name for fragment in later_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "post-monitoring-targets reconciliation refuses later-stage history"
            )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "post-monitoring-targets reconciliation paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "post-monitoring-targets reconciliation requires the matching "
            "held deploy lock"
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


def _nonnegative_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StatePersistenceError(f"{label} must be non-negative")


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be a boolean")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    if value is None:
        return None
    return _integer(value, label)


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
        raise StatePersistenceError(f"{label} must be an array of strings")
    return tuple(value)


__all__ = [
    "ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_STEP_SCHEMA_VERSION",
    "DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_FILENAME_SUFFIX",
    "DeployPostMonitoringTargetsArtifactState",
    "DeployPostMonitoringTargetsReconciliation",
    "DeployPostMonitoringTargetsReconciliationReport",
    "DeployPostMonitoringTargetsReconciliationStore",
    "DeployPostMonitoringTargetsStep",
    "StoredDeployPostMonitoringTargetsReconciliation",
    "deploy_post_monitoring_targets_reconciliation_id_from_filename",
    "deploy_post_monitoring_targets_reconciliation_path",
    "reconcile_deploy_monitoring_targets_result",
]
