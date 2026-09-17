"""Immutable reconciliation after mapped deploy ``monitoring-agent`` execution.

This subprocess-free owner reloads the canonical deploy chain, requires exact
ordered terminal success for the authorized Scylla scope, and advances at most
the immediate active historical mapping gate. It never configures monitoring,
authorizes work, invokes a process, or changes the common journal.
"""

from __future__ import annotations

import os
import re
import uuid
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
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
from scylla_vms.ansible.deploy_manager_agent_authorization import (
    _scylla_install_evidence,
)
from scylla_vms.ansible.deploy_manager_agent_reconciliation import (
    DeployPostManagerAgentStep,
)
from scylla_vms.ansible.deploy_monitoring_agent_authorization import (
    ANSIBLE_DEPLOY_MONITORING_AGENT_AUTHORIZATION_SCHEMA_VERSION,
    DeployMonitoringAgentAuthorizationScope,
    DeployMonitoringAgentAuthorizationStore,
    StoredDeployMonitoringAgentAuthorization,
    _AuthorizationContext,
    _build_authorization,
    _derive_authorization_scopes,
    _derive_package_provenance,
    _load_authorization_context,
)
from scylla_vms.ansible.deploy_monitoring_agent_execution import (
    ANSIBLE_DEPLOY_MONITORING_AGENT_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MONITORING_AGENT_EXECUTION_SCHEMA_VERSION,
    DeployMonitoringAgentEvidenceEntry,
    DeployMonitoringAgentEvidenceStore,
    DeployMonitoringAgentExecutionAttempt,
    DeployMonitoringAgentExecutionState,
    DeployMonitoringAgentExecutionStore,
    StoredDeployMonitoringAgentEvidence,
    StoredDeployMonitoringAgentExecution,
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
from scylla_vms.ansible.monitoring_agent import (
    LISTEN_POLICY,
    MONITORING_AGENT_PACKAGES,
    MONITORING_AGENT_SCHEMA_VERSION,
    MonitoringAgentStatus,
    build_monitoring_agent_payload,
)
from scylla_vms.ansible.registry import (
    OPERATION_PLAYBOOKS,
    CheckMode,
    LimitPolicy,
    get_playbook,
)
from scylla_vms.ansible.scylla_install import (
    SCYLLA_CHANNEL,
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_RELEASE_LINE,
    SCYLLA_REPOSITORY_DEFINITION_DIGEST,
    SCYLLA_SIGNING_KEY_DIGEST,
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

ANSIBLE_DEPLOY_POST_MONITORING_AGENT_STEP_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-monitoring-agent-step/v1"
)
ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-monitoring-agent-reconciliation/v1"
)
ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-monitoring-agent-reconciliation-report/v1"
)
DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-post-monitoring-agent-reconciliation.json"
)

_OPERATION = "deploy"
_STAGE = "post-monitoring-agent-reconciliation"
_AGENT_PLAYBOOK = "monitoring-agent"
_AGENT_MAPPING = 17
_ORIGINAL_MAPPING_COUNT = 21
_NOT_STARTED = "not-started"
_UNAVAILABLE = "unavailable"
_AGENT_EVIDENCE_STATE = "monitoring-agent-bound"
_NEXT_EVIDENCE_STATE = "next-gates-evaluated"
_AUTHORIZATION_BLOCKER = "deploy-authorization-not-collected"
_PUBLIC_WORKFLOW_BLOCKER = "public-deploy-workflow-unavailable"
_ORDER_BLOCKER = "ordered-deploy-step-not-reached"
_CLASS_BLOCKERS = {
    OperationClassification.MUTATING: "mutating-deploy-execution-unavailable",
    OperationClassification.SENSITIVE: "sensitive-deploy-execution-unavailable",
    OperationClassification.DESTRUCTIVE: "destructive-deploy-execution-unavailable",
}
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")
_STEP_DIGEST_EXCLUDED = {"step_digest", "schema_version"}


class DeployPostMonitoringAgentArtifactState(StrEnum):
    """Immutable reconciliation persistence result."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployPostMonitoringAgentStep:
    """Full historical step identity plus one post-exporter status."""

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
    schema_version: str = ANSIBLE_DEPLOY_POST_MONITORING_AGENT_STEP_SCHEMA_VERSION

    def __post_init__(self) -> None:
        definition = get_playbook(self.playbook)
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_MONITORING_AGENT_STEP_SCHEMA_VERSION
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
            raise StatePersistenceError("post-monitoring-agent step identity conflicts")
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
                validate_digest(digest, "post-monitoring-agent step digest")
        self._validate_status()

    def _validate_status(self) -> None:
        if self.condition_state is DeployConditionState.INACTIVE:
            if (
                self.status is not DeployBaseOsReconciledStepStatus.NOT_PERFORMED
                or self.evidence_digest is not None
                or self.blockers
            ):
                raise StatePersistenceError(
                    "post-monitoring-agent inactive step state conflicts"
                )
            return
        if self.status is DeployBaseOsReconciledStepStatus.SUCCEEDED:
            if self.evidence_digest is None or self.blockers:
                raise StatePersistenceError(
                    "post-monitoring-agent succeeded step lacks exact evidence"
                )
            return
        if (
            self.status
            is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        ):
            if (
                self.classification is OperationClassification.READ_ONLY
                or self.evidence_state != _NEXT_EVIDENCE_STATE
                or self.evidence_digest is None
                or not self.target_ids
                or _AUTHORIZATION_BLOCKER not in self.blockers
                or _CLASS_BLOCKERS[self.classification] not in self.blockers
                or _PUBLIC_WORKFLOW_BLOCKER not in self.blockers
            ):
                raise StatePersistenceError(
                    "post-monitoring-agent authorization-required step conflicts"
                )
            return
        if self.status is DeployBaseOsReconciledStepStatus.ELIGIBLE:
            if (
                self.classification is not OperationClassification.READ_ONLY
                or self.evidence_state != _NEXT_EVIDENCE_STATE
                or self.evidence_digest is None
                or not self.target_ids
                or self.blockers
            ):
                raise StatePersistenceError(
                    "post-monitoring-agent eligible step conflicts"
                )
            return
        if self.status is DeployBaseOsReconciledStepStatus.BLOCKED:
            if not self.blockers or self.evidence_digest is not None:
                raise StatePersistenceError(
                    "post-monitoring-agent blocked step conflicts"
                )
            return
        if self.evidence_digest is not None:
            raise StatePersistenceError(
                "post-monitoring-agent not-performed step has evidence"
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
    def from_object(cls, value: Mapping[str, object]) -> DeployPostMonitoringAgentStep:
        require_exact_keys(
            value, set(cls.__dataclass_fields__), "post-monitoring-agent step"
        )
        evidence_digest = value["evidence_digest"]
        if evidence_digest is not None and not isinstance(evidence_digest, str):
            raise StatePersistenceError(
                "post-monitoring-agent evidence digest must be a string or null"
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
                "post-monitoring-agent step enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployPostMonitoringAgentReconciliation:
    """Bounded immutable checkpoint after exact node-exporter installation."""

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
    post_manager_agent_artifact_digest: str
    post_manager_agent_record_digest: str
    post_manager_agent_effective_plan_digest: str
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_scope_digest: str
    authorization_proof_digest: str
    execution_artifact_digest: str
    execution_binding_digest: str
    execution_generation: int
    evidence_artifact_digest: str
    evidence_generation: int
    evidence_set_digest: str
    result_set_digest: str
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
    release_line: str
    channel: str
    package_version_digest: str
    package_count: int
    package_set_digest: str
    package_provenance_digest: str
    repository_definition_digest: str
    signing_key_artifact_digest: str
    signing_key_identity_digest: str
    target_count: int
    target_set_digest: str
    installed_count: int
    changed_count: int
    no_change_count: int
    service_safe_count: int
    listen_safe_count: int
    prohibited_action_count: int
    original_mapping_count: int
    original_mapping_digest: str
    original_mapping_unchanged: bool
    steps: tuple[DeployPostMonitoringAgentStep, ...]
    step_count: int
    succeeded_count: int
    authorization_required_count: int
    eligible_count: int
    blocked_count: int
    not_performed_count: int
    next_mapping_sequence: int
    next_playbook: str
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
        ANSIBLE_DEPLOY_MONITORING_AGENT_AUTHORIZATION_SCHEMA_VERSION
    )
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_AGENT_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_AGENT_EVIDENCE_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_MONITORING_AGENT_AUTHORIZATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_MONITORING_AGENT_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_MONITORING_AGENT_EVIDENCE_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.release_line != SCYLLA_RELEASE_LINE
            or self.channel != SCYLLA_CHANNEL
            or self.package_version_digest != _digest_object(SCYLLA_PACKAGE_VERSION)
            or self.package_count != len(MONITORING_AGENT_PACKAGES)
            or self.package_set_digest
            != _digest_object(list(MONITORING_AGENT_PACKAGES))
            or self.repository_definition_digest != SCYLLA_REPOSITORY_DEFINITION_DIGEST
            or self.signing_key_artifact_digest != SCYLLA_SIGNING_KEY_DIGEST
            or self.target_count < 1
            or self.installed_count != self.target_count
            or self.changed_count + self.no_change_count != self.target_count
            or self.service_safe_count != self.target_count
            or self.listen_safe_count != self.target_count
            or self.prohibited_action_count
            or self.original_mapping_count != _ORIGINAL_MAPPING_COUNT
            or self.original_mapping_digest != _mapping_digest()
            or not self.original_mapping_unchanged
            or self.next_execution_state != _NOT_STARTED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
        ):
            raise StatePersistenceError(
                "post-monitoring-agent reconciliation identity conflicts"
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
            self.package_count,
            self.target_count,
            self.installed_count,
            self.changed_count,
            self.no_change_count,
            self.service_safe_count,
            self.listen_safe_count,
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
            _nonnegative_integer(count, "post-monitoring-agent count")
        if (
            self.journal_generation < 1
            or self.execution_generation < 1
            or self.evidence_generation != self.target_count
            or self.metadata_generation < 1
            or self.observation_generation < 1
            or self.inventory_generation < 1
            or self.trust_generation < 1
            or self.step_count != len(self.steps)
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, len(self.steps) + 1))
            or tuple(sorted({step.mapping_sequence for step in self.steps}))
            != tuple(range(1, _ORIGINAL_MAPPING_COUNT + 1))
        ):
            raise StatePersistenceError(
                "post-monitoring-agent reconciliation counts conflict"
            )
        mapping = OPERATION_PLAYBOOKS[_OPERATION]
        if len(mapping) != _ORIGINAL_MAPPING_COUNT or any(
            step.playbook != mapping[step.mapping_sequence - 1].playbook
            or step.condition != mapping[step.mapping_sequence - 1].condition
            for step in self.steps
        ):
            raise StatePersistenceError(
                "post-monitoring-agent immutable mapping conflicts"
            )
        agents = tuple(
            step for step in self.steps if step.mapping_sequence == _AGENT_MAPPING
        )
        next_steps = tuple(
            step
            for step in self.steps
            if step.mapping_sequence == self.next_mapping_sequence
        )
        active_after_agent = tuple(
            step
            for step in self.steps
            if step.mapping_sequence > _AGENT_MAPPING
            and step.condition_state is DeployConditionState.ACTIVE
        )
        advanced_statuses = {
            DeployBaseOsReconciledStepStatus.SUCCEEDED,
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
        counts = Counter(step.status for step in self.steps)
        if (
            len(agents) != 1
            or agents[0].playbook != _AGENT_PLAYBOOK
            or agents[0].status is not DeployBaseOsReconciledStepStatus.SUCCEEDED
            or agents[0].evidence_state != _AGENT_EVIDENCE_STATE
            or agents[0].evidence_digest != self.evidence_set_digest
            or agents[0].target_digest != self.target_set_digest
            or len(next_steps) != 1
            or next_steps[0].playbook != self.next_playbook
            or next_steps[0].classification is not self.next_classification
            or next_steps[0].status is not self.next_step_status
            or len(next_steps[0].target_ids) != self.next_target_count
            or next_steps[0].target_digest != self.next_target_set_digest
            or next_steps[0].evidence_digest != self.next_evidence_digest
            or next_steps[0].blocker_digest != self.next_blocker_digest
            or not active_after_agent
            or self.next_mapping_sequence
            != min(step.mapping_sequence for step in active_after_agent)
            or any(
                step.condition_state is DeployConditionState.ACTIVE
                and step.mapping_sequence < _AGENT_MAPPING
                and step.status is not DeployBaseOsReconciledStepStatus.SUCCEEDED
                for step in self.steps
            )
            or any(
                step.mapping_sequence > _AGENT_MAPPING
                and step.mapping_sequence != self.next_mapping_sequence
                and step.status in advanced_statuses
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
                "post-monitoring-agent reconciliation summary conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "post-monitoring-agent reconciliation digest")

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
    ) -> DeployPostMonitoringAgentReconciliation:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "post-monitoring-agent reconciliation",
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
            "package_count",
            "target_count",
            "installed_count",
            "changed_count",
            "no_change_count",
            "service_safe_count",
            "listen_safe_count",
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
                elif name == "next_classification":
                    parsed[name] = OperationClassification(require_string(value, name))
                elif name == "next_step_status":
                    parsed[name] = DeployBaseOsReconciledStepStatus(
                        require_string(value, name)
                    )
                elif name == "original_mapping_unchanged":
                    parsed[name] = _boolean(item, name)
                elif name == "next_evidence_digest":
                    parsed[name] = _optional_string(item, name)
                elif name == "steps":
                    parsed[name] = tuple(
                        DeployPostMonitoringAgentStep.from_object(
                            _mapping(step, "post-monitoring-agent step")
                        )
                        for step in _array(item, "steps")
                    )
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "post-monitoring-agent reconciliation enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployPostMonitoringAgentReconciliation:
    record: DeployPostMonitoringAgentReconciliation
    artifact_digest: str


class DeployPostMonitoringAgentReconciliationStore:
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
        self._path = deploy_post_monitoring_agent_reconciliation_path(
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
    ) -> StoredDeployPostMonitoringAgentReconciliation:
        value, artifact_digest = self._file.read()
        record = DeployPostMonitoringAgentReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "post-monitoring-agent reconciliation identity conflicts"
            )
        return StoredDeployPostMonitoringAgentReconciliation(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPostMonitoringAgentReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployPostMonitoringAgentReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployPostMonitoringAgentReconciliation,
        DeployPostMonitoringAgentArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "post-monitoring-agent reconciliation operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "post-monitoring-agent reconciliation is immutable; "
                    "use a new operation"
                )
            return current, DeployPostMonitoringAgentArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployPostMonitoringAgentReconciliation(record, digest),
            DeployPostMonitoringAgentArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployPostMonitoringAgentReconciliationReport:
    """Strict bounded post-monitoring-agent reconciliation projection."""

    operation_id: uuid.UUID
    artifact_state: DeployPostMonitoringAgentArtifactState
    reconciliation_artifact_digest: str
    reconciliation_record_digest: str
    effective_plan_digest: str
    execution_artifact_digest: str
    evidence_artifact_digest: str
    evidence_set_digest: str
    package_provenance_digest: str
    target_count: int
    target_set_digest: str
    installed_count: int
    changed_count: int
    no_change_count: int
    service_safe_count: int
    listen_safe_count: int
    prohibited_action_count: int
    original_mapping_unchanged: bool
    succeeded_count: int
    authorization_required_count: int
    eligible_count: int
    blocked_count: int
    not_performed_count: int
    next_mapping_sequence: int
    next_playbook: str
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
        ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_REPORT_SCHEMA_VERSION
            or self.target_count < 1
            or self.installed_count != self.target_count
            or self.changed_count + self.no_change_count != self.target_count
            or self.service_safe_count != self.target_count
            or self.listen_safe_count != self.target_count
            or self.prohibited_action_count
            or not self.original_mapping_unchanged
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.process_calls
            or self.authorization_created
            or self.execution_started
        ):
            raise StatePersistenceError(
                "post-monitoring-agent reconciliation report conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "post-monitoring-agent report digest")

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
            "monitoring_agent": {
                "changed_count": self.changed_count,
                "evidence_artifact_digest": self.evidence_artifact_digest,
                "evidence_set_digest": self.evidence_set_digest,
                "execution_artifact_digest": self.execution_artifact_digest,
                "installed_count": self.installed_count,
                "listen_safe_count": self.listen_safe_count,
                "no_change_count": self.no_change_count,
                "package_provenance_digest": self.package_provenance_digest,
                "prohibited_action_count": self.prohibited_action_count,
                "service_safe_count": self.service_safe_count,
                "target_count": self.target_count,
                "target_set_digest": self.target_set_digest,
            },
            "next_gate": {
                "blocker_digest": self.next_blocker_digest,
                "classification": self.next_classification.value,
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
    authorization: StoredDeployMonitoringAgentAuthorization
    execution: StoredDeployMonitoringAgentExecution
    evidence: StoredDeployMonitoringAgentEvidence
    scopes: tuple[DeployMonitoringAgentAuthorizationScope, ...]


def reconcile_deploy_monitoring_agent_result(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployPostMonitoringAgentReconciliationReport:
    """Bind exact node-exporter success and evaluate the immediate mapped gate."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _validate_original_mapping()
    _refuse_ambiguous_or_later_artifacts(paths, operation_id)
    context = _load_context(paths, operation_id, lock=lock)
    steps = _build_steps(context)
    store = DeployPostMonitoringAgentReconciliationStore(paths, operation_id)
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


def deploy_post_monitoring_agent_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the canonical operation-bound post-monitoring-agent path."""

    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "post-monitoring-agent reconciliation path is not canonical"
        )
    return path


def deploy_post_monitoring_agent_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    suffix = DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_FILENAME_SUFFIX
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
    manager_context = authorization_context.manager.authorization_context
    loaded = _loaded(
        manager_context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    metadata = loaded.planning.base.deploy.metadata.record
    authorization_store = DeployMonitoringAgentAuthorizationStore(paths, operation_id)
    execution_store = DeployMonitoringAgentExecutionStore(paths, operation_id)
    evidence_store = DeployMonitoringAgentEvidenceStore(paths, operation_id)
    for path, label in (
        (authorization_store.path, "authorization"),
        (execution_store.path, "execution"),
        (evidence_store.path, "evidence"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"post-monitoring-agent reconciliation requires complete {label}"
            )
    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    package = _derive_package_provenance()
    scopes = _derive_authorization_scopes(authorization_context, package)
    expected_authorization = _build_authorization(
        authorization_context,
        scopes=scopes,
        package_provenance=package,
        proof=authorization.record.proof,
        created_at=authorization.record.created_at,
    )
    if authorization.record != expected_authorization:
        raise StateConflictError(
            "post-monitoring-agent authorization or canonical scope drifted"
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
        authorization_context,
        authorization,
        execution,
        evidence,
        scopes,
    )
    _validate_complete_execution(context)
    return context


def _validate_complete_execution(context: _ReconciliationContext) -> None:
    manager_context = context.authorization_context.manager.authorization_context
    loaded = _loaded(
        manager_context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    planning = loaded.planning
    deploy = planning.base.deploy
    authorization = context.authorization.record
    execution = context.execution.record
    evidence = context.evidence.record
    binding = execution.binding
    attempts = execution.attempts
    entries = evidence.entries
    scopes = context.scopes
    stable_ids = authorization.target_stable_ids
    if (
        authorization.consumed
        or authorization.authorization_state != "authorized-pre-execution"
        or authorization.execution_state != _UNAVAILABLE
        or execution.state is not DeployMonitoringAgentExecutionState.SUCCEEDED
        or not execution.all_scopes_completed
        or execution.manual_recovery_required
        or not execution.authorization_consumed
        or execution.invocation_count != len(scopes)
        or len(attempts) != len(scopes)
        or len(entries) != len(scopes)
        or evidence.generation != len(scopes)
        or evidence.binding != binding
        or stable_ids != tuple(scope.target_stable_id for scope in scopes)
        or tuple(attempt.stable_id for attempt in attempts) != stable_ids
        or tuple(entry.stable_id for entry in entries) != stable_ids
    ):
        raise StateConflictError(
            "post-monitoring-agent reconciliation requires exact terminal success"
        )
    expected_scope_values = [
        {
            "attempt_index": index,
            "authorization_command_digest": scope.command_digest,
            "authorization_scope_digest": _digest_object(scope.to_object()),
            "authorization_variables_digest": scope.variables_digest,
            "command_digest": scope.command_digest,
            "source_digest": scope.source_digest,
            "target_digest": scope.target_digest,
            "variables_digest": scope.variables_digest,
        }
        for index, scope in enumerate(scopes, start=1)
    ]
    post_manager = context.authorization_context.post_manager
    install = manager_context.install.evidence
    post_install = manager_context.post_install
    base_os = manager_context.monitoring.monitoring.manager.manager.base_os
    readiness = planning.readiness
    trust = planning.base.trust
    manager_evidence = context.authorization_context.manager.evidence.record
    package = authorization.package_provenance
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
        or binding.post_manager_agent_artifact_digest != post_manager.artifact_digest
        or binding.post_manager_agent_record_digest != post_manager.record.record_digest
        or binding.post_manager_agent_effective_plan_digest
        != _digest_object([step.to_object() for step in post_manager.record.steps])
        or binding.manager_agent_evidence_digest
        != _digest_object([entry.evidence_digest for entry in manager_evidence.entries])
        or binding.install_reconciliation_artifact_digest
        != post_install.artifact_digest
        or binding.install_reconciliation_record_digest
        != post_install.record.record_digest
        or binding.install_evidence_artifact_digest != install.artifact_digest
        or binding.install_evidence_digest
        != _digest_object([entry.evidence_digest for entry in install.record.entries])
        or binding.base_os_evidence_artifact_digest != base_os.artifact_digest
        or binding.base_os_evidence_digest != authorization.base_os_evidence_digest
        or binding.readiness_artifact_digest != readiness.artifact_digest
        or binding.readiness_record_digest != readiness.record.record_digest
        or binding.catalog_digest != loaded.catalog_digest
        or binding.source_version != loaded.source.version
        or binding.source_digest != loaded.source.digest
        or binding.playbook_source_digest
        != _playbook_source_digest(loaded.source, _AGENT_PLAYBOOK)
        or binding.toolchain_version != readiness.record.playbook_version
        or binding.toolchain_version != readiness.record.inventory_version
        or binding.executable_identity_digest
        != readiness.record.executable_identity_digest
        or binding.toolchain_evidence_digest
        != readiness.record.toolchain_evidence_digest
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
        or binding.package_provenance_digest != package.provenance_digest
        or binding.scope_count != len(scopes)
        or binding.stable_id_count != len(stable_ids)
        or binding.stable_id_set_digest != _digest_object(list(stable_ids))
        or binding.execution_scope_digest != _digest_object(expected_scope_values)
    ):
        raise StateConflictError(
            "post-monitoring-agent inventory, trust, readiness, source, catalog, "
            "authorization, prior-chain, or journal binding drifted"
        )
    for index, (scope, attempt, entry) in enumerate(
        zip(scopes, attempts, entries, strict=True), start=1
    ):
        _validate_scope_result(context, index, scope, attempt, entry)


def _validate_scope_result(
    context: _ReconciliationContext,
    index: int,
    scope: DeployMonitoringAgentAuthorizationScope,
    attempt: DeployMonitoringAgentExecutionAttempt,
    entry: DeployMonitoringAgentEvidenceEntry,
) -> None:
    package = context.authorization.record.package_provenance
    expected_provenance = _expected_provenance_digest(context, scope)
    expected_result = _digest_object(
        {
            "changed": entry.changed,
            "configuration_performed": entry.configuration_performed,
            "listen_policy": entry.listen_policy,
            "logical_id": entry.stable_id,
            "manager_registration_performed": entry.manager_registration_performed,
            "package_set_digest": _digest_object(
                {name: SCYLLA_PACKAGE_VERSION for name in MONITORING_AGENT_PACKAGES}
            ),
            "package_version_digest": _digest_object(SCYLLA_PACKAGE_VERSION),
            "process_exporter_installed": entry.process_exporter_installed,
            "provenance_digest": entry.provenance_digest,
            "repository_definition_digest": entry.repository_definition_digest,
            "schema_version": MONITORING_AGENT_SCHEMA_VERSION,
            "scylla_started": entry.scylla_started,
            "secrets_written": entry.secrets_written,
            "service_disabled": entry.service_disabled,
            "service_inactive": entry.service_inactive,
            "signing_key_artifact_digest": entry.signing_key_artifact_digest,
            "stack_installed": entry.stack_installed,
            "status": entry.status.value,
            "targets_generated": entry.targets_generated,
        }
    )
    prohibited = (
        entry.configuration_performed,
        entry.process_exporter_installed,
        entry.stack_installed,
        entry.targets_generated,
        entry.manager_registration_performed,
        entry.service_started,
        entry.scylla_started,
        entry.secrets_written,
    )
    if (
        attempt.attempt_index != index
        or attempt.step_sequence != scope.step_sequence
        or attempt.stable_id != scope.target_stable_id
        or attempt.target_digest != scope.target_digest
        or attempt.authorization_scope_digest != _digest_object(scope.to_object())
        or attempt.authorization_variables_digest != scope.variables_digest
        or attempt.authorization_command_digest != scope.command_digest
        or attempt.variables_digest != scope.variables_digest
        or attempt.command_digest != scope.command_digest
        or attempt.source_digest != scope.source_digest
        or attempt.package_version_digest != _digest_object(SCYLLA_PACKAGE_VERSION)
        or attempt.package_provenance_digest != package.provenance_digest
        or attempt.state is not DeployMonitoringAgentExecutionState.SUCCEEDED
        or attempt.started_at is None
        or attempt.completed_at is None
        or attempt.authorization_consumed_at_start != (index == 1)
        or not attempt.invocation_may_have_occurred
        or attempt.exit_code != 0
        or attempt.result_digest != entry.result_digest
        or attempt.evidence_digest != entry.evidence_digest
        or attempt.manual_recovery_required
        or attempt.automatic_retry_allowed
        or entry.attempt_index != index
        or entry.step_sequence != scope.step_sequence
        or entry.stable_id != scope.target_stable_id
        or entry.image_architecture != scope.architecture.value
        or entry.status
        not in {MonitoringAgentStatus.INSTALLED, MonitoringAgentStatus.NO_CHANGE}
        or not entry.installed
        or entry.changed != (entry.status is MonitoringAgentStatus.INSTALLED)
        or entry.package_version_digest != package.package_version_digest
        or entry.package_count != package.package_count
        or entry.package_set_digest != package.package_set_digest
        or entry.repository_definition_digest != package.repository_definition_digest
        or entry.signing_key_artifact_digest != package.signing_key_artifact_digest
        or entry.signing_key_identity_digest != package.signing_key_identity_digest
        or not entry.service_disabled
        or not entry.service_inactive
        or entry.listen_policy != LISTEN_POLICY
        or any(prohibited)
        or entry.provenance_digest != expected_provenance
        or entry.variables_digest != scope.variables_digest
        or entry.command_digest != scope.command_digest
        or entry.source_digest != scope.source_digest
        or entry.result_digest != expected_result
        or entry.manual_recovery_required
        or entry.automatic_retry_allowed
    ):
        raise StateConflictError(
            "post-monitoring-agent package, service, listen, execution, or "
            "prohibited-action evidence conflicts"
        )


def _expected_provenance_digest(
    context: _ReconciliationContext,
    scope: DeployMonitoringAgentAuthorizationScope,
) -> str:
    manager_context = context.authorization_context.manager.authorization_context
    loaded = _loaded(
        manager_context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    planning = loaded.planning
    deploy = planning.base.deploy
    base_os = manager_context.monitoring.monitoring.manager.manager.base_os
    base_matches = tuple(
        (record, host)
        for record in base_os.record.entries
        for host in record.hosts
        if host.logical_id == scope.target_stable_id
    )
    install_matches = tuple(
        entry
        for entry in manager_context.install.evidence.record.entries
        if entry.stable_id == scope.target_stable_id
    )
    if len(base_matches) != 1 or len(install_matches) != 1:
        raise StateConflictError(
            "post-monitoring-agent current prerequisite evidence is ambiguous"
        )
    _base_record, base_host = base_matches[0]
    install_entry = install_matches[0]
    image_filter = dict(deploy.metadata.record.desired_spec.image_filters).get(
        HostRole.SCYLLA
    )
    if image_filter is None:
        raise StateConflictError(
            "post-monitoring-agent current Scylla image policy is absent"
        )
    payload = build_monitoring_agent_payload(
        deploy.metadata.record,
        deploy.observation,
        deploy.inventory,
        _reconstructed_readiness(planning.base),
        BaseOsEvidence(
            base_host.status,
            (
                BaseOsHostEvidence(
                    base_host.logical_id,
                    base_host.status,
                    base_host.changed,
                    base_host.reboot_required,
                    "canonical-deploy-evidence",
                ),
            ),
        ),
        _scylla_install_evidence(
            install_entry,
            observation_digest=deploy.observation.digest,
            inventory_digest=deploy.inventory.digest,
        ),
        logical_id=scope.target_stable_id,
        image_filter=image_filter,
        architecture=base_host.image_architecture,
        package_version=SCYLLA_PACKAGE_VERSION,
        cluster_spec_digest=deploy.metadata.record.desired_spec.digest(),
    )
    provenance = payload.get("provenance")
    if not isinstance(provenance, Mapping):
        raise StateConflictError(
            "post-monitoring-agent current package provenance is malformed"
        )
    return _digest_object(dict(provenance))


def _build_steps(
    context: _ReconciliationContext,
) -> tuple[DeployPostMonitoringAgentStep, ...]:
    prior_steps = context.authorization_context.post_manager.record.steps
    if tuple(sorted({step.mapping_sequence for step in prior_steps})) != tuple(
        range(1, _ORIGINAL_MAPPING_COUNT + 1)
    ):
        raise StateConflictError("post-monitoring-agent prior mapping is incomplete")
    remaining = tuple(
        sorted(
            step.mapping_sequence
            for step in prior_steps
            if step.mapping_sequence > _AGENT_MAPPING
            and step.condition_state is DeployConditionState.ACTIVE
            and step.status is not DeployBaseOsReconciledStepStatus.SUCCEEDED
        )
    )
    if not remaining:
        raise StateConflictError(
            "post-monitoring-agent immediate next active mapping is unavailable"
        )
    next_mapping = remaining[0]
    evidence_set_digest = _digest_object(
        [entry.evidence_digest for entry in context.evidence.record.entries]
    )
    result: list[DeployPostMonitoringAgentStep] = []
    for prior in prior_steps:
        _validate_prior_step(prior)
        status = prior.status
        evidence_state = prior.evidence_state
        evidence_digest = prior.evidence_digest
        blockers = prior.blockers
        if prior.mapping_sequence == _AGENT_MAPPING:
            if (
                prior.status
                is not DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
                or prior.playbook != _AGENT_PLAYBOOK
                or prior.target_ids
                != tuple(entry.stable_id for entry in context.evidence.record.entries)
            ):
                raise StateConflictError(
                    "post-monitoring-agent executed mapping identity conflicts"
                )
            status = DeployBaseOsReconciledStepStatus.SUCCEEDED
            evidence_state = _AGENT_EVIDENCE_STATE
            evidence_digest = evidence_set_digest
            blockers = ()
        elif prior.mapping_sequence > _AGENT_MAPPING and prior.status is (
            DeployBaseOsReconciledStepStatus.SUCCEEDED
        ):
            raise StateConflictError(
                "post-monitoring-agent later mapped gate already succeeded"
            )
        elif prior.mapping_sequence == next_mapping and _next_gate_ready(
            prior, context
        ):
            evidence_digest = _next_gate_evidence_digest(prior, context)
            evidence_state = _NEXT_EVIDENCE_STATE
            if prior.classification is OperationClassification.READ_ONLY:
                status = DeployBaseOsReconciledStepStatus.ELIGIBLE
                blockers = ()
            else:
                status = DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
                blockers = tuple(
                    sorted(
                        {
                            _AUTHORIZATION_BLOCKER,
                            _CLASS_BLOCKERS[prior.classification],
                            _PUBLIC_WORKFLOW_BLOCKER,
                        }
                    )
                )
        elif prior.mapping_sequence > next_mapping and prior.condition_state is (
            DeployConditionState.ACTIVE
        ):
            if status in {
                DeployBaseOsReconciledStepStatus.ELIGIBLE,
                DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
            }:
                raise StateConflictError(
                    "post-monitoring-agent later mapped gate leapfrogged"
                )
            evidence_digest = None
            blockers = tuple(sorted({*blockers, _ORDER_BLOCKER}))
            status = (
                DeployBaseOsReconciledStepStatus.NOT_PERFORMED
                if prior.classification is OperationClassification.READ_ONLY
                else DeployBaseOsReconciledStepStatus.BLOCKED
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
    return tuple(result)


def _validate_prior_step(prior: DeployPostManagerAgentStep) -> None:
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
            "post-monitoring-agent historical step identity drifted"
        )


def _next_gate_ready(
    step: DeployPostManagerAgentStep,
    context: _ReconciliationContext,
) -> bool:
    manager_context = context.authorization_context.manager.authorization_context
    loaded = _loaded(
        manager_context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    deploy = loaded.planning.base.deploy
    definition = get_playbook(step.playbook)
    prior_steps = context.authorization_context.post_manager.record.steps
    if (
        step.condition_state is not DeployConditionState.ACTIVE
        or not step.target_ids
        or not definition.source_available
        or step.source_digest != _playbook_source_digest(loaded.source, step.playbook)
        or any(
            prior.condition_state is DeployConditionState.ACTIVE
            and prior.mapping_sequence < step.mapping_sequence
            and prior.mapping_sequence != _AGENT_MAPPING
            and prior.status is not DeployBaseOsReconciledStepStatus.SUCCEEDED
            for prior in prior_steps
        )
    ):
        return False
    inventory_roles = {
        host.logical_id: host.role.value
        for host in deploy.inventory.record.inventory.hosts
    }
    if any(
        stable_id not in inventory_roles
        or (
            step.target_role != "all" and inventory_roles[stable_id] != step.target_role
        )
        for stable_id in step.target_ids
    ):
        return False
    base_os = manager_context.monitoring.monitoring.manager.manager.base_os
    base_hosts = {
        host.logical_id: host
        for entry in base_os.record.entries
        for host in entry.hosts
    }
    selected = tuple(base_hosts.get(stable_id) for stable_id in step.target_ids)
    return all(
        host is not None
        and host.status in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
        and host.applied
        and not host.reboot_required
        and host.os_family == "Ubuntu"
        and host.os_version == "24.04"
        for host in selected
    )


def _next_gate_evidence_digest(
    step: DeployPostManagerAgentStep,
    context: _ReconciliationContext,
) -> str:
    manager_context = context.authorization_context.manager.authorization_context
    base_os = manager_context.monitoring.monitoring.manager.manager.base_os
    selected = tuple(
        (entry.evidence_digest, host.logical_id)
        for entry in base_os.record.entries
        for host in entry.hosts
        if host.logical_id in step.target_ids
    )
    predecessor_evidence = tuple(
        (prior.mapping_sequence, prior.playbook, prior.evidence_digest)
        for prior in context.authorization_context.post_manager.record.steps
        if prior.mapping_sequence < step.mapping_sequence
        and prior.mapping_sequence != _AGENT_MAPPING
        and prior.condition_state is DeployConditionState.ACTIVE
        and prior.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
    )
    return _digest_object(
        {
            "base_os_evidence": sorted(selected),
            "catalog_digest": context.execution.record.binding.catalog_digest,
            "monitoring_agent_evidence": [
                entry.evidence_digest for entry in context.evidence.record.entries
            ],
            "playbook": step.playbook,
            "predecessor_evidence": predecessor_evidence,
            "source_digest": step.source_digest,
            "target_digest": step.target_digest,
        }
    )


def _step_from_prior(
    prior: DeployPostManagerAgentStep,
    *,
    status: DeployBaseOsReconciledStepStatus,
    evidence_state: str,
    evidence_digest: str | None,
    blockers: tuple[str, ...],
) -> DeployPostMonitoringAgentStep:
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
    return DeployPostMonitoringAgentStep(**values)  # type: ignore[arg-type]


def _build_record(
    context: _ReconciliationContext,
    *,
    steps: tuple[DeployPostMonitoringAgentStep, ...],
    created_at: str | None,
) -> DeployPostMonitoringAgentReconciliation:
    manager_context = context.authorization_context.manager.authorization_context
    loaded = _loaded(
        manager_context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    deploy = loaded.planning.base.deploy
    authorization = context.authorization.record
    execution = context.execution.record
    binding = execution.binding
    evidence = context.evidence.record
    package = authorization.package_provenance
    entries = evidence.entries
    next_candidates = tuple(
        step
        for step in steps
        if step.mapping_sequence > _AGENT_MAPPING
        and step.condition_state is DeployConditionState.ACTIVE
    )
    if not next_candidates:
        raise StateConflictError(
            "post-monitoring-agent next mapped gate is unavailable"
        )
    next_step = min(next_candidates, key=lambda item: item.mapping_sequence)
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
        "post_manager_agent_artifact_digest": (
            context.authorization_context.post_manager.artifact_digest
        ),
        "post_manager_agent_record_digest": (
            context.authorization_context.post_manager.record.record_digest
        ),
        "post_manager_agent_effective_plan_digest": (
            binding.post_manager_agent_effective_plan_digest
        ),
        "authorization_artifact_digest": context.authorization.artifact_digest,
        "authorization_digest": authorization.authorization_digest,
        "authorization_scope_digest": authorization.authorization_scope_digest,
        "authorization_proof_digest": authorization.proof.proof_digest,
        "execution_artifact_digest": context.execution.artifact_digest,
        "execution_binding_digest": binding.binding_digest,
        "execution_generation": execution.generation,
        "evidence_artifact_digest": context.evidence.artifact_digest,
        "evidence_generation": evidence.generation,
        "evidence_set_digest": _digest_object(
            [entry.evidence_digest for entry in entries]
        ),
        "result_set_digest": _digest_object([entry.result_digest for entry in entries]),
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
        "release_line": package.release_line,
        "channel": package.channel,
        "package_version_digest": package.package_version_digest,
        "package_count": package.package_count,
        "package_set_digest": package.package_set_digest,
        "package_provenance_digest": package.provenance_digest,
        "repository_definition_digest": package.repository_definition_digest,
        "signing_key_artifact_digest": package.signing_key_artifact_digest,
        "signing_key_identity_digest": package.signing_key_identity_digest,
        "target_count": len(entries),
        "target_set_digest": binding.stable_id_set_digest,
        "installed_count": sum(entry.installed for entry in entries),
        "changed_count": sum(entry.changed for entry in entries),
        "no_change_count": sum(not entry.changed for entry in entries),
        "service_safe_count": sum(
            entry.service_disabled and entry.service_inactive for entry in entries
        ),
        "listen_safe_count": sum(
            entry.listen_policy == LISTEN_POLICY for entry in entries
        ),
        "prohibited_action_count": sum(
            entry.configuration_performed
            or entry.process_exporter_installed
            or entry.stack_installed
            or entry.targets_generated
            or entry.manager_registration_performed
            or entry.service_started
            or entry.scylla_started
            or entry.secrets_written
            for entry in entries
        ),
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
    return DeployPostMonitoringAgentReconciliation(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployPostMonitoringAgentReconciliation,
    *,
    state: DeployPostMonitoringAgentArtifactState,
) -> DeployPostMonitoringAgentReconciliationReport:
    record = stored.record
    return DeployPostMonitoringAgentReconciliationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        reconciliation_artifact_digest=stored.artifact_digest,
        reconciliation_record_digest=record.record_digest,
        effective_plan_digest=_digest_object(
            [step.to_object() for step in record.steps]
        ),
        execution_artifact_digest=record.execution_artifact_digest,
        evidence_artifact_digest=record.evidence_artifact_digest,
        evidence_set_digest=record.evidence_set_digest,
        package_provenance_digest=record.package_provenance_digest,
        target_count=record.target_count,
        target_set_digest=record.target_set_digest,
        installed_count=record.installed_count,
        changed_count=record.changed_count,
        no_change_count=record.no_change_count,
        service_safe_count=record.service_safe_count,
        listen_safe_count=record.listen_safe_count,
        prohibited_action_count=record.prohibited_action_count,
        original_mapping_unchanged=record.original_mapping_unchanged,
        succeeded_count=record.succeeded_count,
        authorization_required_count=record.authorization_required_count,
        eligible_count=record.eligible_count,
        blocked_count=record.blocked_count,
        not_performed_count=record.not_performed_count,
        next_mapping_sequence=record.next_mapping_sequence,
        next_playbook=record.next_playbook,
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
        or mapping[_AGENT_MAPPING - 1].playbook != _AGENT_PLAYBOOK
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
            "post-monitoring-agent requires the immutable 21-position mapping"
        )


def _step_digest(step: DeployPostMonitoringAgentStep) -> str:
    return _step_digest_from_values(step.to_object())


def _step_digest_from_values(values: Mapping[str, object]) -> str:
    return _digest_object(
        {
            name: _plain_value(value)
            for name, value in values.items()
            if name not in _STEP_DIGEST_EXCLUDED
        }
    )


def _record_digest(record: DeployPostMonitoringAgentReconciliation) -> str:
    return _record_digest_from_object(record.to_object())


def _record_digest_from_values(values: Mapping[str, object]) -> str:
    result: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployPostMonitoringAgentReconciliation.__dataclass_fields__.items():
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
        f"{operation_id}{DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_FILENAME_SUFFIX}"
    )
    prefix = f"{operation_id}."
    later_fragments = (
        ".ansible-deploy-monitoring-targets",
        ".ansible-deploy-post-monitoring-targets",
        ".ansible-deploy-manager-tasks",
        ".ansible-deploy-post-manager-tasks",
        ".ansible-deploy-final-evidence",
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list post-monitoring-agent operation history"
        ) from error
    for entry in entries:
        if (
            entry.name.startswith(prefix)
            and "post-monitoring-agent-reconciliation" in entry.name
            and entry.name != canonical
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "post-monitoring-agent reconciliation artifacts are ambiguous"
            )
        if entry.name.startswith(prefix) and any(
            fragment in entry.name for fragment in later_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "post-monitoring-agent reconciliation refuses later-stage history"
            )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "post-monitoring-agent reconciliation paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "post-monitoring-agent reconciliation requires the matching held deploy lock"
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
    "ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_POST_MONITORING_AGENT_STEP_SCHEMA_VERSION",
    "DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_FILENAME_SUFFIX",
    "DeployPostMonitoringAgentArtifactState",
    "DeployPostMonitoringAgentReconciliation",
    "DeployPostMonitoringAgentReconciliationReport",
    "DeployPostMonitoringAgentReconciliationStore",
    "DeployPostMonitoringAgentStep",
    "StoredDeployPostMonitoringAgentReconciliation",
    "deploy_post_monitoring_agent_reconciliation_id_from_filename",
    "deploy_post_monitoring_agent_reconciliation_path",
    "reconcile_deploy_monitoring_agent_result",
]
