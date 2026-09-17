"""Immutable deploy-plan reconciliation for pre-mutation host evidence.

This owner consumes the distinct role-batched host-evidence checkpoint.  It
does not rewrite any earlier plan, authorize a mutation, invoke a runner, or
advance the common journal.
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

from scylla_vms.ansible.commands import ansible_command_intent_digest
from scylla_vms.ansible.deploy_host_evidence import (
    ANSIBLE_DEPLOY_PRE_MUTATION_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_PRE_MUTATION_EXECUTION_SCHEMA_VERSION,
    DeployPreMutationEvidenceStore,
    DeployPreMutationExecutionStore,
    PreMutationEvidenceStatus,
    PreMutationHostEvidence,
    StoredDeployPreMutationEvidence,
    StoredDeployPreMutationExecution,
    _entry_evidence_digest,
    _host_evidence_complete,
)
from scylla_vms.ansible.deploy_plan import (
    ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION,
    DeployAnsiblePlanStep,
    DeployConditionState,
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_reconciliation import (
    ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION,
    DeployEffectivePlanStep,
    DeployEffectivePlanStore,
    StoredDeployEffectivePlan,
    _build_effective_plan,
    _build_effective_steps,
    _load_reconciliation_context,
    _ReconciliationContext,
)
from scylla_vms.ansible.operation_execution import ExecutionAttemptState
from scylla_vms.ansible.registry import (
    OPERATION_PLAYBOOKS,
    CheckMode,
    LimitPolicy,
    get_playbook,
)
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION
from scylla_vms.desired import HostRole
from scylla_vms.errors import StateConflictError, StatePersistenceError
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

ANSIBLE_DEPLOY_HOST_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-host-evidence-reconciliation/v1"
)
ANSIBLE_DEPLOY_HOST_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-host-evidence-reconciliation-report/v1"
)
DEPLOY_HOST_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-host-evidence-reconciliation.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "evidence-collect"
_CHECKPOINT_KIND = "pre-mutation-host-evidence"
_EVIDENCE_TIMEOUT_SECONDS = 10
_NOT_COLLECTED = "not-collected"
_BLOCKED = "blocked"
_NOT_STARTED = "not-started"
_UNAVAILABLE = "unavailable"
_PUBLIC_WORKFLOW_BLOCKER = "public-deploy-workflow-unavailable"
_AUTHORIZATION_BLOCKER = "deploy-authorization-not-collected"
_MUTATION_BLOCKER = "mutating-deploy-execution-unavailable"
_RECONCILED_BASE_OS_MAPPING = 3
_FINAL_EVIDENCE_MAPPING = len(OPERATION_PLAYBOOKS[_OPERATION])
_ROLE_ORDER = (
    HostRole.JUMP_HOST,
    HostRole.SCYLLA,
    HostRole.MANAGER,
    HostRole.MONITORING,
)
_ROLE_SERVICES = {
    HostRole.JUMP_HOST: (),
    HostRole.SCYLLA: ("scylla-server.service",),
    HostRole.MANAGER: ("scylla-manager.service",),
    HostRole.MONITORING: ("grafana-server.service", "prometheus.service"),
}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SUPPORTED_OS_VERSION = re.compile(r"24\.04(?:\.[0-9]+)?\Z")
_SAFE_SERVICE_STATES = frozenset({"inactive", "stopped"})
_FAILED_SERVICE_STATES = frozenset({"active", "running"})
_RECONCILED_ORIGINAL_BLOCKERS = frozenset(
    {"host-evidence-not-performed", "base-os-evidence-not-performed"}
)


class DeployHostReconciliationArtifactState(StrEnum):
    """Immutable reconciliation companion persistence state."""

    CREATED = "created"
    REUSED = "reused"


class DeployHostReconciledStepStatus(StrEnum):
    """Truthful post-host-evidence state of one immutable mapped step."""

    SUCCEEDED = "succeeded"
    EVIDENCE_READY_AUTHORIZATION_REQUIRED = "evidence-ready-authorization-required"
    BLOCKED = "blocked"
    NOT_PERFORMED = "not-performed"


class DeployHostReconciledEvidenceState(StrEnum):
    """Evidence relationship for one reconciled step."""

    PREREQUISITE_BOUND = "prerequisite-bound"
    HOST_GATES_EVALUATED = "host-gates-evaluated"
    NOT_PERFORMED = "not-performed"
    NOT_REQUIRED = "not-required"


class HostEvidenceGateState(StrEnum):
    """Bounded evaluation state for one host gate."""

    PASSED = "passed"
    FAILED = "failed"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not-applicable"


@dataclass(frozen=True, slots=True)
class HostEvidenceGateCount:
    """Address-free aggregate for one evaluated host gate."""

    gate: str
    passed_count: int
    failed_count: int
    unknown_count: int
    not_applicable_count: int
    total_count: int
    outcome_digest: str

    def __post_init__(self) -> None:
        if not _BLOCKER.fullmatch(self.gate):
            raise StatePersistenceError("host-evidence gate name is invalid")
        for value in (
            self.passed_count,
            self.failed_count,
            self.unknown_count,
            self.not_applicable_count,
            self.total_count,
        ):
            _nonnegative_integer(value, "host-evidence gate count")
        if (
            self.total_count < 1
            or self.total_count
            != self.passed_count
            + self.failed_count
            + self.unknown_count
            + self.not_applicable_count
        ):
            raise StatePersistenceError("host-evidence gate counts conflict")
        validate_digest(self.outcome_digest, "host-evidence gate outcome digest")

    def to_object(self) -> dict[str, object]:
        return {
            "failed_count": self.failed_count,
            "gate": self.gate,
            "not_applicable_count": self.not_applicable_count,
            "outcome_digest": self.outcome_digest,
            "passed_count": self.passed_count,
            "total_count": self.total_count,
            "unknown_count": self.unknown_count,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> HostEvidenceGateCount:
        require_exact_keys(
            value,
            {
                "failed_count",
                "gate",
                "not_applicable_count",
                "outcome_digest",
                "passed_count",
                "total_count",
                "unknown_count",
            },
            "host-evidence gate count",
        )
        return cls(
            gate=require_string(value, "gate"),
            passed_count=_integer(value["passed_count"], "passed count"),
            failed_count=_integer(value["failed_count"], "failed count"),
            unknown_count=_integer(value["unknown_count"], "unknown count"),
            not_applicable_count=_integer(
                value["not_applicable_count"], "not-applicable count"
            ),
            total_count=_integer(value["total_count"], "total count"),
            outcome_digest=require_string(value, "outcome_digest"),
        )


@dataclass(frozen=True, slots=True)
class DeployHostReconciledStep:
    """Original step identity with its post-host-evidence status."""

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
    prior_effective_step_digest: str
    status: DeployHostReconciledStepStatus
    evidence_state: DeployHostReconciledEvidenceState
    evidence_digest: str | None
    blockers: tuple[str, ...]

    def __post_init__(self) -> None:
        definition = get_playbook(self.playbook)
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 1
            or isinstance(self.mapping_sequence, bool)
            or not isinstance(self.mapping_sequence, int)
            or self.mapping_sequence < 1
            or not isinstance(self.condition_state, DeployConditionState)
            or not isinstance(self.classification, OperationClassification)
            or not isinstance(self.limit_policy, LimitPolicy)
            or not isinstance(self.check_mode, CheckMode)
            or not isinstance(self.status, DeployHostReconciledStepStatus)
            or not isinstance(self.evidence_state, DeployHostReconciledEvidenceState)
            or self.classification is not definition.classification
            or self.limit_policy is not definition.limit_policy
            or self.serial != definition.serial
            or self.check_mode is not definition.check_mode
            or self.target_role not in {"all", *(role.value for role in _ROLE_ORDER)}
        ):
            raise StatePersistenceError("host-reconciled deploy step policy is invalid")
        if (
            self.target_ids != tuple(sorted(set(self.target_ids)))
            or any(not _LOGICAL_ID.fullmatch(item) for item in self.target_ids)
            or self.variable_names != tuple(dict.fromkeys(self.variable_names))
            or set(self.variable_names)
            != {variable.name for variable in definition.variables}
            or self.blockers != tuple(sorted(set(self.blockers)))
            or any(not _BLOCKER.fullmatch(item) for item in self.blockers)
        ):
            raise StatePersistenceError(
                "host-reconciled deploy step projection is invalid"
            )
        for digest_value in (
            self.target_digest,
            self.variables_digest,
            self.source_digest,
            self.command_digest,
            self.original_step_digest,
            self.prior_effective_step_digest,
        ):
            validate_digest(digest_value, "host-reconciled deploy step digest")
        if self.target_digest != _digest_object(list(self.target_ids)):
            raise StatePersistenceError("host-reconciled target digest conflicts")
        if self.evidence_digest is not None:
            validate_digest(self.evidence_digest, "host-reconciled evidence digest")
        if self.status is DeployHostReconciledStepStatus.SUCCEEDED:
            if (
                self.sequence not in {1, 2}
                or self.playbook not in {"inventory-preflight", "connectivity-check"}
                or self.evidence_state
                is not DeployHostReconciledEvidenceState.PREREQUISITE_BOUND
                or self.evidence_digest is None
                or self.blockers
            ):
                raise StatePersistenceError("host-reconciled succeeded step is invalid")
        elif (
            self.status
            is DeployHostReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        ):
            if (
                self.mapping_sequence != _RECONCILED_BASE_OS_MAPPING
                or self.playbook != "base-os"
                or self.condition_state is not DeployConditionState.ACTIVE
                or self.classification is not OperationClassification.MUTATING
                or self.evidence_state
                is not DeployHostReconciledEvidenceState.HOST_GATES_EVALUATED
                or self.evidence_digest is None
                or _AUTHORIZATION_BLOCKER not in self.blockers
                or _MUTATION_BLOCKER not in self.blockers
                or _PUBLIC_WORKFLOW_BLOCKER not in self.blockers
                or not self.target_ids
            ):
                raise StatePersistenceError(
                    "host-reconciled authorization-required step is invalid"
                )
        elif self.status is DeployHostReconciledStepStatus.BLOCKED:
            if not self.blockers:
                raise StatePersistenceError("host-reconciled blocked step is invalid")
        elif self.evidence_digest is not None:
            raise StatePersistenceError(
                "host-reconciled not-performed step has evidence"
            )
        if self.condition_state is DeployConditionState.INACTIVE and (
            self.status is not DeployHostReconciledStepStatus.NOT_PERFORMED
            or self.evidence_state is not DeployHostReconciledEvidenceState.NOT_REQUIRED
            or self.blockers
        ):
            raise StatePersistenceError("host-reconciled inactive step is invalid")
        if self.mapping_sequence == _FINAL_EVIDENCE_MAPPING and (
            self.playbook != _PLAYBOOK
            or self.status is not DeployHostReconciledStepStatus.NOT_PERFORMED
            or self.evidence_state
            is not DeployHostReconciledEvidenceState.NOT_PERFORMED
            or self.evidence_digest is not None
        ):
            raise StatePersistenceError(
                "mapped final host evidence must remain not performed"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "blockers": list(self.blockers),
            "check_mode": self.check_mode.value,
            "classification": self.classification.value,
            "command_digest": self.command_digest,
            "condition": self.condition,
            "condition_state": self.condition_state.value,
            "evidence_digest": self.evidence_digest,
            "evidence_state": self.evidence_state.value,
            "limit_policy": self.limit_policy.value,
            "mapping_sequence": self.mapping_sequence,
            "original_step_digest": self.original_step_digest,
            "playbook": self.playbook,
            "prior_effective_step_digest": self.prior_effective_step_digest,
            "sequence": self.sequence,
            "serial": self.serial,
            "source_digest": self.source_digest,
            "status": self.status.value,
            "target_digest": self.target_digest,
            "target_ids": list(self.target_ids),
            "target_role": self.target_role,
            "variable_names": list(self.variable_names),
            "variables_digest": self.variables_digest,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployHostReconciledStep:
        require_exact_keys(
            value,
            {
                "blockers",
                "check_mode",
                "classification",
                "command_digest",
                "condition",
                "condition_state",
                "evidence_digest",
                "evidence_state",
                "limit_policy",
                "mapping_sequence",
                "original_step_digest",
                "playbook",
                "prior_effective_step_digest",
                "sequence",
                "serial",
                "source_digest",
                "status",
                "target_digest",
                "target_ids",
                "target_role",
                "variable_names",
                "variables_digest",
            },
            "host-reconciled deploy step",
        )
        evidence_digest = value["evidence_digest"]
        if evidence_digest is not None and not isinstance(evidence_digest, str):
            raise StatePersistenceError(
                "host-reconciled evidence digest must be a string or null"
            )
        try:
            return cls(
                sequence=_integer(value["sequence"], "step sequence"),
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
                prior_effective_step_digest=require_string(
                    value, "prior_effective_step_digest"
                ),
                status=DeployHostReconciledStepStatus(require_string(value, "status")),
                evidence_state=DeployHostReconciledEvidenceState(
                    require_string(value, "evidence_state")
                ),
                evidence_digest=evidence_digest,
                blockers=_string_tuple(value["blockers"], "blockers"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "host-reconciled deploy step enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployHostEvidenceReconciliation:
    """Immutable effective plan after bounded host-evidence reconciliation."""

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
    original_plan_artifact_digest: str
    original_plan_record_digest: str
    prior_effective_plan_artifact_digest: str
    prior_effective_plan_record_digest: str
    prior_effective_plan_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    prerequisite_execution_artifact_digest: str
    prerequisite_evidence_artifact_digest: str
    pre_mutation_execution_artifact_digest: str
    pre_mutation_evidence_artifact_digest: str
    pre_mutation_binding_digest: str
    pre_mutation_checkpoint_digest: str
    pre_mutation_evidence_digest: str
    checkpoint_kind: str
    catalog_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    host_count: int
    host_set_digest: str
    host_gate_counts: tuple[HostEvidenceGateCount, ...]
    host_gate_digest: str
    steps: tuple[DeployHostReconciledStep, ...]
    mapping_count: int
    step_count: int
    succeeded_count: int
    authorization_required_count: int
    blocked_count: int
    not_performed_count: int
    blocker_set: tuple[str, ...]
    blocker_digest: str
    effective_plan_digest: str
    authorization_state: str
    mutating_execution_state: str
    finalization_state: str
    public_workflow_state: str
    record_digest: str
    context_schema_version: str = ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
    original_plan_schema_version: str = ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION
    prior_effective_plan_schema_version: str = (
        ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    pre_mutation_execution_schema_version: str = (
        ANSIBLE_DEPLOY_PRE_MUTATION_EXECUTION_SCHEMA_VERSION
    )
    pre_mutation_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_PRE_MUTATION_EVIDENCE_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_HOST_RECONCILIATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version != ANSIBLE_DEPLOY_HOST_RECONCILIATION_SCHEMA_VERSION
            or self.context_schema_version != ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
            or self.original_plan_schema_version != ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION
            or self.prior_effective_plan_schema_version
            != ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.pre_mutation_execution_schema_version
            != ANSIBLE_DEPLOY_PRE_MUTATION_EXECUTION_SCHEMA_VERSION
            or self.pre_mutation_evidence_schema_version
            != ANSIBLE_DEPLOY_PRE_MUTATION_EVIDENCE_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.checkpoint_kind != _CHECKPOINT_KIND
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.authorization_state != _NOT_COLLECTED
            or self.mutating_execution_state != _BLOCKED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
        ):
            raise StatePersistenceError(
                "host-evidence reconciliation identity is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for value in (
            self.journal_generation,
            self.host_count,
            self.mapping_count,
            self.step_count,
            self.succeeded_count,
            self.authorization_required_count,
            self.blocked_count,
            self.not_performed_count,
        ):
            _nonnegative_integer(value, "host-evidence reconciliation count")
        if (
            self.journal_generation < 1
            or self.host_count < 1
            or self.mapping_count != len(OPERATION_PLAYBOOKS[_OPERATION])
            or self.step_count != len(self.steps)
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, len(self.steps) + 1))
            or tuple(item.gate for item in self.host_gate_counts)
            != tuple(sorted(item.gate for item in self.host_gate_counts))
        ):
            raise StatePersistenceError(
                "host-evidence reconciliation sequence is invalid"
            )
        expected_mapping = OPERATION_PLAYBOOKS[_OPERATION]
        if {step.mapping_sequence for step in self.steps} != set(
            range(1, len(expected_mapping) + 1)
        ) or any(
            step.playbook != expected_mapping[step.mapping_sequence - 1].playbook
            or step.condition != expected_mapping[step.mapping_sequence - 1].condition
            for step in self.steps
        ):
            raise StatePersistenceError(
                "host-evidence reconciliation mapping conflicts"
            )
        status_counts = Counter(step.status for step in self.steps)
        blocker_set = tuple(
            sorted(
                {
                    *(blocker for step in self.steps for blocker in step.blockers),
                    *(
                        blocker
                        for blocker in self.blocker_set
                        if blocker.startswith("host-")
                        or blocker.startswith("unsupported-")
                        or blocker
                        in {
                            "capacity-evidence-unavailable",
                            "device-evidence-unavailable",
                            "mount-evidence-unavailable",
                            "reboot-required",
                            "reboot-requirement-not-collected",
                            "service-state-active",
                            "service-state-unavailable",
                            "system-identity-unavailable",
                        }
                    ),
                }
            )
        )
        if (
            self.succeeded_count
            != status_counts[DeployHostReconciledStepStatus.SUCCEEDED]
            or self.authorization_required_count
            != status_counts[
                DeployHostReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            ]
            or self.blocked_count
            != status_counts[DeployHostReconciledStepStatus.BLOCKED]
            or self.not_performed_count
            != status_counts[DeployHostReconciledStepStatus.NOT_PERFORMED]
            or self.succeeded_count
            + self.authorization_required_count
            + self.blocked_count
            + self.not_performed_count
            != self.step_count
            or self.succeeded_count != 2
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or blocker_set != self.blocker_set
            or any(not _BLOCKER.fullmatch(item) for item in self.blocker_set)
            or self.blocker_digest != _digest_object(list(self.blocker_set))
            or self.host_gate_digest
            != _digest_object([item.to_object() for item in self.host_gate_counts])
            or any(
                item.total_count != self.host_count for item in self.host_gate_counts
            )
            or self.effective_plan_digest
            != _digest_object([step.to_object() for step in self.steps])
        ):
            raise StatePersistenceError(
                "host-evidence reconciliation summary conflicts"
            )
        for digest_value in (
            self.request_digest,
            self.journal_digest,
            self.context_artifact_digest,
            self.context_record_digest,
            self.original_plan_artifact_digest,
            self.original_plan_record_digest,
            self.prior_effective_plan_artifact_digest,
            self.prior_effective_plan_record_digest,
            self.prior_effective_plan_digest,
            self.readiness_artifact_digest,
            self.readiness_record_digest,
            self.prerequisite_execution_artifact_digest,
            self.prerequisite_evidence_artifact_digest,
            self.pre_mutation_execution_artifact_digest,
            self.pre_mutation_evidence_artifact_digest,
            self.pre_mutation_binding_digest,
            self.pre_mutation_checkpoint_digest,
            self.pre_mutation_evidence_digest,
            self.catalog_digest,
            self.ansible_source_digest,
            self.host_set_digest,
            self.host_gate_digest,
            self.blocker_digest,
            self.effective_plan_digest,
            self.record_digest,
        ):
            validate_digest(digest_value, "host-evidence reconciliation digest")
        if self.record_digest != _record_digest(self):
            raise StatePersistenceError(
                "host-evidence reconciliation record digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            result[name] = (
                str(value)
                if isinstance(value, uuid.UUID)
                else value.value
                if isinstance(value, (JournalStatus, OperationPhase))
                else [step.to_object() for step in value]
                if name == "steps"
                else [item.to_object() for item in value]
                if name == "host_gate_counts"
                else list(value)
                if name == "blocker_set"
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployHostEvidenceReconciliation:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "host-evidence reconciliation",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "host_count",
            "mapping_count",
            "step_count",
            "succeeded_count",
            "authorization_required_count",
            "blocked_count",
            "not_performed_count",
        }
        parsed: dict[str, object] = {}
        for name in cls.__dataclass_fields__:
            item = value[name]
            if name in integer_fields:
                parsed[name] = _integer(item, name)
            elif name in {"cluster_uuid", "operation_id"}:
                parsed[name] = parse_uuid(require_string(value, name), name)
            elif name == "journal_status":
                try:
                    parsed[name] = JournalStatus(require_string(value, name))
                except ValueError as error:
                    raise StatePersistenceError(
                        "host-evidence reconciliation status is invalid"
                    ) from error
            elif name == "journal_phase":
                try:
                    parsed[name] = OperationPhase(require_string(value, name))
                except ValueError as error:
                    raise StatePersistenceError(
                        "host-evidence reconciliation phase is invalid"
                    ) from error
            elif name == "steps":
                parsed[name] = tuple(
                    DeployHostReconciledStep.from_object(
                        _mapping(step, "host-reconciled step")
                    )
                    for step in _array(item, "host-reconciled steps")
                )
            elif name == "host_gate_counts":
                parsed[name] = tuple(
                    HostEvidenceGateCount.from_object(
                        _mapping(gate, "host-evidence gate")
                    )
                    for gate in _array(item, "host-evidence gates")
                )
            elif name == "blocker_set":
                parsed[name] = _string_tuple(item, name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployHostEvidenceReconciliation:
    record: DeployHostEvidenceReconciliation
    artifact_digest: str


class DeployHostEvidenceReconciliationStore:
    """Owner-only immutable post-host-evidence effective plan."""

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
        self._path = deploy_host_evidence_reconciliation_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path,
            replace=replace_file,
            token_factory=token_factory,
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployHostEvidenceReconciliation:
        value, artifact_digest = self._file.read()
        record = DeployHostEvidenceReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or artifact_digest != _artifact_digest(record.to_object())
        ):
            raise StatePersistenceError(
                "host-evidence reconciliation identity conflicts"
            )
        return StoredDeployHostEvidenceReconciliation(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployHostEvidenceReconciliation:
        lock.assert_held_for_operation(self._paths, _OPERATION)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployHostEvidenceReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployHostEvidenceReconciliation,
        DeployHostReconciliationArtifactState,
    ]:
        lock.assert_held_for_operation(self._paths, _OPERATION)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "host-evidence reconciliation operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError("host-evidence reconciliation is immutable")
            return current, DeployHostReconciliationArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployHostEvidenceReconciliation(record, artifact_digest),
            DeployHostReconciliationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class AuthorizationRequiredStepCount:
    """Redacted grouping for evidence-ready authorization boundaries."""

    playbook: str
    role: str
    step_count: int
    stable_id_count: int

    def __post_init__(self) -> None:
        if get_playbook(
            self.playbook
        ).classification is OperationClassification.READ_ONLY or self.role not in {
            role.value for role in _ROLE_ORDER
        }:
            raise StatePersistenceError(
                "authorization-required step summary is invalid"
            )
        _positive_integer(self.step_count, "authorization-required step count")
        _positive_integer(
            self.stable_id_count, "authorization-required stable-ID count"
        )

    def to_object(self) -> dict[str, object]:
        return {
            "playbook": self.playbook,
            "role": self.role,
            "stable_id_count": self.stable_id_count,
            "step_count": self.step_count,
        }


@dataclass(frozen=True, slots=True)
class DeployHostEvidenceReconciliationReport:
    """Strict address-free reconciliation projection."""

    operation_id: uuid.UUID
    artifact_state: DeployHostReconciliationArtifactState
    reconciliation_artifact_digest: str
    reconciliation_record_digest: str
    effective_plan_digest: str
    prior_effective_plan_artifact_digest: str
    prior_effective_plan_digest: str
    pre_mutation_execution_artifact_digest: str
    pre_mutation_evidence_artifact_digest: str
    pre_mutation_checkpoint_digest: str
    pre_mutation_evidence_digest: str
    host_count: int
    host_set_digest: str
    host_gate_counts: tuple[HostEvidenceGateCount, ...]
    host_gate_digest: str
    total_count: int
    succeeded_count: int
    authorization_required_count: int
    blocked_count: int
    not_performed_count: int
    next_authorization_required: tuple[AuthorizationRequiredStepCount, ...]
    blocker_set: tuple[str, ...]
    blocker_digest: str
    mapped_final_evidence_state: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    authorization_state: str
    mutating_execution_state: str
    finalization_state: str
    public_workflow_state: str
    schema_version: str = ANSIBLE_DEPLOY_HOST_RECONCILIATION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_HOST_RECONCILIATION_REPORT_SCHEMA_VERSION
            or not isinstance(self.operation_id, uuid.UUID)
            or not isinstance(
                self.artifact_state, DeployHostReconciliationArtifactState
            )
            or self.mapped_final_evidence_state != "not-performed"
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.authorization_state != _NOT_COLLECTED
            or self.mutating_execution_state != _BLOCKED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
        ):
            raise StatePersistenceError(
                "host-evidence reconciliation report is invalid"
            )
        for value in (
            self.host_count,
            self.total_count,
            self.succeeded_count,
            self.authorization_required_count,
            self.blocked_count,
            self.not_performed_count,
        ):
            _nonnegative_integer(value, "host-evidence reconciliation report count")
        if (
            self.host_count < 1
            or self.total_count < 1
            or self.succeeded_count != 2
            or self.total_count
            != self.succeeded_count
            + self.authorization_required_count
            + self.blocked_count
            + self.not_performed_count
            or sum(item.step_count for item in self.next_authorization_required)
            != self.authorization_required_count
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(not _BLOCKER.fullmatch(item) for item in self.blocker_set)
            or tuple(item.gate for item in self.host_gate_counts)
            != tuple(sorted(item.gate for item in self.host_gate_counts))
            or any(
                item.total_count != self.host_count for item in self.host_gate_counts
            )
        ):
            raise StatePersistenceError(
                "host-evidence reconciliation report summary conflicts"
            )
        for digest_value in (
            self.reconciliation_artifact_digest,
            self.reconciliation_record_digest,
            self.effective_plan_digest,
            self.prior_effective_plan_artifact_digest,
            self.prior_effective_plan_digest,
            self.pre_mutation_execution_artifact_digest,
            self.pre_mutation_evidence_artifact_digest,
            self.pre_mutation_checkpoint_digest,
            self.pre_mutation_evidence_digest,
            self.host_set_digest,
            self.host_gate_digest,
            self.blocker_digest,
        ):
            validate_digest(digest_value, "host-evidence reconciliation report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "artifact_state": self.artifact_state.value,
            "authorization_required_count": self.authorization_required_count,
            "authorization_state": self.authorization_state,
            "blocked_count": self.blocked_count,
            "blocker_digest": self.blocker_digest,
            "blocker_set": list(self.blocker_set),
            "effective_plan_digest": self.effective_plan_digest,
            "finalization_state": self.finalization_state,
            "host_count": self.host_count,
            "host_gate_counts": [item.to_object() for item in self.host_gate_counts],
            "host_gate_digest": self.host_gate_digest,
            "host_set_digest": self.host_set_digest,
            "journal_phase": self.journal_phase.value,
            "journal_status": self.journal_status.value,
            "mapped_final_evidence_state": self.mapped_final_evidence_state,
            "mutating_execution_state": self.mutating_execution_state,
            "next_authorization_required": [
                item.to_object() for item in self.next_authorization_required
            ],
            "not_performed_count": self.not_performed_count,
            "operation_id": str(self.operation_id),
            "pre_mutation_checkpoint_digest": self.pre_mutation_checkpoint_digest,
            "pre_mutation_evidence_artifact_digest": (
                self.pre_mutation_evidence_artifact_digest
            ),
            "pre_mutation_evidence_digest": self.pre_mutation_evidence_digest,
            "pre_mutation_execution_artifact_digest": (
                self.pre_mutation_execution_artifact_digest
            ),
            "prior_effective_plan_artifact_digest": (
                self.prior_effective_plan_artifact_digest
            ),
            "prior_effective_plan_digest": self.prior_effective_plan_digest,
            "public_workflow_state": self.public_workflow_state,
            "reconciliation_artifact_digest": self.reconciliation_artifact_digest,
            "reconciliation_record_digest": self.reconciliation_record_digest,
            "schema_version": self.schema_version,
            "succeeded_count": self.succeeded_count,
            "total_count": self.total_count,
        }


@dataclass(frozen=True, slots=True)
class _HostGateEvaluation:
    logical_id: str
    role: HostRole
    states: tuple[tuple[str, HostEvidenceGateState], ...]
    blockers: tuple[str, ...]
    evidence_digest: str


@dataclass(frozen=True, slots=True)
class _HostReconciliationContext:
    loaded: _ReconciliationContext
    prior_effective: StoredDeployEffectivePlan
    execution: StoredDeployPreMutationExecution
    evidence: StoredDeployPreMutationEvidence
    host_evaluations: tuple[_HostGateEvaluation, ...]
    gate_counts: tuple[HostEvidenceGateCount, ...]
    host_gate_digest: str
    pre_mutation_evidence_digest: str


def reconcile_deploy_pre_mutation_host_evidence(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployHostEvidenceReconciliationReport:
    """Persist a new immutable effective view of exact host evidence."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    lock.assert_held_for_operation(paths, _OPERATION)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_reconciliation_artifacts(paths, operation_id)

    context = _load_host_reconciliation_context(paths, operation_id, lock=lock)
    metadata = context.loaded.planning.base.deploy.metadata.record
    store = DeployHostEvidenceReconciliationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    existing = (
        store.read_locked(
            lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
        )
        if store.path.exists()
        else None
    )
    created_at = (
        existing.record.created_at
        if existing is not None
        else format_timestamp(datetime.now(UTC))
    )
    steps = _build_reconciled_steps(context)
    record = _build_reconciliation_record(
        context,
        steps=steps,
        created_at=created_at,
    )
    if existing is not None and existing.record != record:
        raise StateConflictError("host-evidence reconciliation is immutable")
    try:
        stored, state = store.write_locked(record, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "host-evidence reconciliation persistence failed"
        ) from error
    return _build_report(stored, state=state, context=context)


def deploy_host_evidence_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = (
        paths.operations / f"{operation_id}{DEPLOY_HOST_RECONCILIATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "host-evidence reconciliation path is not canonical"
        )
    return path


def deploy_host_evidence_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(DEPLOY_HOST_RECONCILIATION_FILENAME_SUFFIX):
        return None
    value = name[: -len(DEPLOY_HOST_RECONCILIATION_FILENAME_SUFFIX)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _load_host_reconciliation_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
) -> _HostReconciliationContext:
    loaded = _load_reconciliation_context(paths, operation_id, lock=lock)
    planning = loaded.planning
    journal = planning.base.deploy.journal
    if (
        journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
    ):
        raise StateConflictError(
            "host-evidence reconciliation requires the unchanged VERIFY journal"
        )
    metadata = planning.base.deploy.metadata.record
    effective_store = DeployEffectivePlanStore(paths, operation_id)
    execution_store = DeployPreMutationExecutionStore(paths, operation_id)
    evidence_store = DeployPreMutationEvidenceStore(paths, operation_id)
    for path in (effective_store.path, execution_store.path, evidence_store.path):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                "host-evidence reconciliation requires complete evidence"
            )
    prior_effective = effective_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_effective = _build_effective_plan(
        loaded,
        effective_steps=_build_effective_steps(
            loaded.plan.record.steps,
            loaded.evidence,
        ),
        created_at=prior_effective.record.created_at,
    )
    if prior_effective.record != expected_effective:
        raise StateConflictError(
            "host-evidence reconciliation prior effective plan drifted"
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
    _validate_complete_checkpoint(
        loaded,
        prior_effective,
        execution,
        evidence,
    )
    evaluations = tuple(
        _evaluate_host(host, evidence_digest=entry.evidence_digest)
        for entry in evidence.record.entries
        for host in entry.hosts
    )
    if tuple(item.logical_id for item in evaluations) != tuple(
        sorted(item.logical_id for item in evaluations)
    ):
        # Role-batch order differs from global stable-ID order by design. The
        # persisted aggregate is canonicalized below, while each role batch was
        # validated separately in checkpoint order.
        evaluations = tuple(sorted(evaluations, key=lambda item: item.logical_id))
    host_ids = tuple(item.logical_id for item in evaluations)
    if host_ids != tuple(sorted(set(host_ids))):
        raise StateConflictError(
            "host-evidence reconciliation host membership conflicts"
        )
    gate_counts = _build_gate_counts(evaluations)
    host_gate_digest = _digest_object([item.to_object() for item in gate_counts])
    pre_mutation_evidence_digest = _digest_object(
        [entry.evidence_digest for entry in evidence.record.entries]
    )
    return _HostReconciliationContext(
        loaded,
        prior_effective,
        execution,
        evidence,
        evaluations,
        gate_counts,
        host_gate_digest,
        pre_mutation_evidence_digest,
    )


def _validate_complete_checkpoint(
    loaded: _ReconciliationContext,
    prior_effective: StoredDeployEffectivePlan,
    execution: StoredDeployPreMutationExecution,
    evidence: StoredDeployPreMutationEvidence,
) -> None:
    binding = execution.record.binding
    planning = loaded.planning
    deploy = planning.base.deploy
    trust = planning.base.trust
    readiness = planning.readiness.record
    journal = deploy.journal
    metadata = deploy.metadata.record
    if (
        evidence.record.binding != binding
        or binding.cluster_uuid != metadata.cluster_uuid
        or binding.cluster_name != metadata.cluster_name
        or binding.operation_id != journal.record.operation_id
        or binding.operation != _OPERATION
        or binding.request_digest != journal.record.request_digest
        or binding.journal_generation != journal.record.generation
        or binding.journal_digest != journal.digest
        or binding.journal_status is not journal.record.status
        or binding.journal_phase is not journal.record.phase
        or binding.context_artifact_digest != loaded.context.artifact_digest
        or binding.context_record_digest != loaded.context.record.record_digest
        or binding.original_plan_artifact_digest != loaded.plan.artifact_digest
        or binding.original_plan_record_digest != loaded.plan.record.record_digest
        or binding.effective_plan_artifact_digest != prior_effective.artifact_digest
        or binding.effective_plan_record_digest != prior_effective.record.record_digest
        or binding.effective_plan_digest != prior_effective.record.effective_plan_digest
        or binding.prerequisite_execution_artifact_digest
        != loaded.execution.artifact_digest
        or binding.prerequisite_evidence_artifact_digest
        != loaded.evidence.artifact_digest
        or binding.prerequisite_evidence_digest
        != _digest_object(
            [entry.evidence_digest for entry in loaded.evidence.record.entries]
        )
        or binding.readiness_artifact_digest != planning.readiness.artifact_digest
        or binding.readiness_record_digest != readiness.record_digest
        or binding.catalog_digest != loaded.catalog_digest
        or binding.source_version != loaded.source.version
        or binding.source_digest != loaded.source.digest
        or binding.toolchain_version != readiness.playbook_version
        or binding.toolchain_version != readiness.inventory_version
        or binding.executable_identity_digest != readiness.executable_identity_digest
        or binding.toolchain_evidence_digest != readiness.toolchain_evidence_digest
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
        or binding.checkpoint_kind != _CHECKPOINT_KIND
    ):
        raise StateConflictError(
            "host-evidence reconciliation checkpoint provenance drifted"
        )
    inventory_hosts = deploy.inventory.record.inventory.hosts
    expected_batches = tuple(
        (
            role,
            tuple(
                sorted(host.logical_id for host in inventory_hosts if host.role is role)
            ),
        )
        for role in _ROLE_ORDER
        if any(host.role is role for host in inventory_hosts)
    )
    all_host_ids = tuple(sorted(host.logical_id for host in inventory_hosts))
    source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
    variables_digest = digest_bytes(
        serialize_json(
            {"deploy_scylla_vms_evidence_timeout_seconds": (_EVIDENCE_TIMEOUT_SECONDS)}
        )
    )
    definition = get_playbook(_PLAYBOOK)
    batch_values: list[dict[str, object]] = []
    if (
        binding.host_count != len(all_host_ids)
        or binding.host_set_digest != _digest_object(list(all_host_ids))
        or binding.batch_count != len(expected_batches)
        or len(execution.record.attempts) != len(expected_batches)
        or len(evidence.record.entries) != len(expected_batches)
        or not execution.record.all_batches_completed
        or execution.record.state is not ExecutionAttemptState.SUCCEEDED
        or execution.record.generation < len(expected_batches) * 2
        or evidence.record.generation != len(expected_batches)
    ):
        raise StateConflictError(
            "host-evidence reconciliation checkpoint is incomplete"
        )
    for sequence, ((role, target_ids), attempt, entry) in enumerate(
        zip(
            expected_batches,
            execution.record.attempts,
            evidence.record.entries,
            strict=True,
        ),
        start=1,
    ):
        target_digest = _digest_object(list(target_ids))
        command_digest = ansible_command_intent_digest(
            definition,
            step_sequence=sequence,
            limit=target_ids,
            variables_digest=variables_digest,
            tags=(),
            check=True,
            diff=False,
            verbosity=0,
        )
        batch_values.append(
            {
                "command_digest": command_digest,
                "role": role.value,
                "sequence": sequence,
                "source_digest": source_digest,
                "target_digest": target_digest,
                "variables_digest": variables_digest,
            }
        )
        if (
            attempt.attempt_index != sequence
            or attempt.step_sequence != sequence
            or attempt.playbook != _PLAYBOOK
            or attempt.classification is not OperationClassification.READ_ONLY
            or attempt.limit != target_ids
            or attempt.variables_digest != variables_digest
            or attempt.command_digest != command_digest
            or attempt.playbook_source_digest != source_digest
            or attempt.result_schema_version
            != definition.execution_result_schema_version
            or attempt.state is not ExecutionAttemptState.SUCCEEDED
            or attempt.manual_recovery_required
            or attempt.result_digest is None
            or entry.sequence != sequence
            or entry.role is not role
            or entry.playbook != _PLAYBOOK
            or entry.variables_digest != variables_digest
            or entry.command_digest != command_digest
            or entry.source_digest != source_digest
            or entry.result_digest != attempt.result_digest
            or entry.target_count != len(target_ids)
            or entry.target_set_digest != target_digest
            or entry.status is not PreMutationEvidenceStatus.SUCCEEDED
            or tuple(host.logical_id for host in entry.hosts) != target_ids
            or any(host.role is not role for host in entry.hosts)
            or entry.evidence_digest != _entry_evidence_digest(entry)
            or any(not _host_evidence_complete(host) for host in entry.hosts)
        ):
            raise StateConflictError(
                "host-evidence reconciliation execution or evidence conflicts"
            )
    batch_plan_digest = _digest_object(batch_values)
    checkpoint_digest = _digest_object(
        {
            "batch_plan_digest": batch_plan_digest,
            "checkpoint_kind": _CHECKPOINT_KIND,
            "effective_plan_digest": prior_effective.record.effective_plan_digest,
            "host_evidence_schema_version": (
                evidence.record.entries[0].host_evidence_schema_version
            ),
            "playbook": _PLAYBOOK,
            "schema_version": binding.schema_version,
        }
    )
    if (
        binding.batch_plan_digest != batch_plan_digest
        or binding.checkpoint_digest != checkpoint_digest
    ):
        raise StateConflictError("host-evidence reconciliation batch mapping drifted")


def _evaluate_host(
    host: PreMutationHostEvidence,
    *,
    evidence_digest: str,
) -> _HostGateEvaluation:
    blockers = set(host.blockers)
    states: dict[str, HostEvidenceGateState] = {}
    if host.os_family is None or host.os_version is None or host.architecture is None:
        states["platform"] = HostEvidenceGateState.UNKNOWN
        blockers.add("system-identity-unavailable")
    elif (
        host.os_family.casefold() != "ubuntu"
        or _SUPPORTED_OS_VERSION.fullmatch(host.os_version) is None
        or host.architecture not in {"x86_64", "aarch64"}
    ):
        states["platform"] = HostEvidenceGateState.FAILED
        if host.os_family.casefold() != "ubuntu":
            blockers.add("unsupported-os-family")
        if _SUPPORTED_OS_VERSION.fullmatch(host.os_version) is None:
            blockers.add("unsupported-os-version")
        if host.architecture not in {"x86_64", "aarch64"}:
            blockers.add("unsupported-architecture")
    else:
        states["platform"] = HostEvidenceGateState.PASSED

    if host.reboot_required == "required":
        states["reboot-requirement"] = HostEvidenceGateState.FAILED
        blockers.add("reboot-required")
    elif host.reboot_required == "not-required":
        states["reboot-requirement"] = HostEvidenceGateState.PASSED
    else:
        states["reboot-requirement"] = HostEvidenceGateState.UNKNOWN
        blockers.add("reboot-requirement-not-collected")

    if host.cpu_count is None or host.cpu_count < 1 or host.memory_mib is None:
        states["capacity-evidence"] = HostEvidenceGateState.UNKNOWN
        blockers.add("capacity-evidence-unavailable")
    elif host.memory_mib < 1:
        states["capacity-evidence"] = HostEvidenceGateState.FAILED
        blockers.add("capacity-evidence-unavailable")
    else:
        states["capacity-evidence"] = HostEvidenceGateState.PASSED

    if host.filesystem_status != "available" or host.mount_count < 1:
        states["mount-evidence"] = HostEvidenceGateState.UNKNOWN
        blockers.add("mount-evidence-unavailable")
    else:
        states["mount-evidence"] = HostEvidenceGateState.PASSED

    if host.role is not HostRole.SCYLLA:
        states["device-evidence"] = HostEvidenceGateState.NOT_APPLICABLE
    elif host.block_device_status != "available" or host.block_device_count < 1:
        states["device-evidence"] = HostEvidenceGateState.UNKNOWN
        blockers.add("device-evidence-unavailable")
    else:
        states["device-evidence"] = HostEvidenceGateState.PASSED

    service_statuses = tuple(service.status for service in host.services)
    if not _ROLE_SERVICES[host.role]:
        states["service-state"] = HostEvidenceGateState.NOT_APPLICABLE
    elif any(status in _FAILED_SERVICE_STATES for status in service_statuses):
        states["service-state"] = HostEvidenceGateState.FAILED
        blockers.add("service-state-active")
    elif any(status not in _SAFE_SERVICE_STATES for status in service_statuses):
        states["service-state"] = HostEvidenceGateState.UNKNOWN
        blockers.add("service-state-unavailable")
    else:
        states["service-state"] = HostEvidenceGateState.PASSED

    return _HostGateEvaluation(
        host.logical_id,
        host.role,
        tuple(sorted(states.items())),
        tuple(sorted(blockers)),
        _digest_object(
            {
                "entry_evidence_digest": evidence_digest,
                "logical_id": host.logical_id,
                "role": host.role.value,
                "states": [
                    {"gate": gate, "state": state.value}
                    for gate, state in sorted(states.items())
                ],
            }
        ),
    )


def _build_gate_counts(
    evaluations: tuple[_HostGateEvaluation, ...],
) -> tuple[HostEvidenceGateCount, ...]:
    gate_names = tuple(
        sorted(
            {gate for evaluation in evaluations for gate, _state in evaluation.states}
        )
    )
    result: list[HostEvidenceGateCount] = []
    for gate in gate_names:
        outcomes = tuple(
            (
                evaluation.logical_id,
                dict(evaluation.states)[gate],
                evaluation.evidence_digest,
            )
            for evaluation in evaluations
        )
        counts = Counter(state for _logical_id, state, _digest in outcomes)
        result.append(
            HostEvidenceGateCount(
                gate,
                counts[HostEvidenceGateState.PASSED],
                counts[HostEvidenceGateState.FAILED],
                counts[HostEvidenceGateState.UNKNOWN],
                counts[HostEvidenceGateState.NOT_APPLICABLE],
                len(evaluations),
                _digest_object(
                    [
                        {
                            "evidence_digest": evidence_digest,
                            "logical_id": logical_id,
                            "state": state.value,
                        }
                        for logical_id, state, evidence_digest in outcomes
                    ]
                ),
            )
        )
    return tuple(result)


def _build_reconciled_steps(
    context: _HostReconciliationContext,
) -> tuple[DeployHostReconciledStep, ...]:
    original_by_sequence = {
        step.sequence: step for step in context.loaded.plan.record.steps
    }
    evaluation_by_host = {
        evaluation.logical_id: evaluation for evaluation in context.host_evaluations
    }
    result: list[DeployHostReconciledStep] = []
    for prior in context.prior_effective.record.steps:
        original = original_by_sequence.get(prior.sequence)
        if original is None:
            raise StateConflictError(
                "host-evidence reconciliation original step is unavailable"
            )
        if prior.sequence in {1, 2}:
            status = DeployHostReconciledStepStatus.SUCCEEDED
            evidence_state = DeployHostReconciledEvidenceState.PREREQUISITE_BOUND
            evidence_digest = prior.evidence_digest
            blockers: tuple[str, ...] = ()
        elif prior.condition_state is DeployConditionState.INACTIVE:
            status = DeployHostReconciledStepStatus.NOT_PERFORMED
            evidence_state = DeployHostReconciledEvidenceState.NOT_REQUIRED
            evidence_digest = None
            blockers = ()
        elif (
            prior.mapping_sequence == _RECONCILED_BASE_OS_MAPPING
            and prior.playbook == "base-os"
        ):
            target_evaluations = tuple(
                evaluation_by_host[target] for target in prior.target_ids
            )
            gate_blockers = tuple(
                sorted(
                    {
                        blocker
                        for evaluation in target_evaluations
                        for blocker in evaluation.blockers
                    }
                )
            )
            blockers = tuple(
                sorted(
                    {
                        *(
                            blocker
                            for blocker in prior.blockers
                            if blocker not in _RECONCILED_ORIGINAL_BLOCKERS
                        ),
                        *gate_blockers,
                        _AUTHORIZATION_BLOCKER,
                        _MUTATION_BLOCKER,
                        _PUBLIC_WORKFLOW_BLOCKER,
                    }
                )
            )
            status = (
                DeployHostReconciledStepStatus.BLOCKED
                if gate_blockers
                else (
                    DeployHostReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
                )
            )
            evidence_state = DeployHostReconciledEvidenceState.HOST_GATES_EVALUATED
            evidence_digest = _digest_object(
                [
                    {
                        "evidence_digest": evaluation.evidence_digest,
                        "logical_id": evaluation.logical_id,
                        "states": [
                            {"gate": gate, "state": state.value}
                            for gate, state in evaluation.states
                        ],
                    }
                    for evaluation in target_evaluations
                ]
            )
        elif prior.classification is OperationClassification.READ_ONLY:
            status = DeployHostReconciledStepStatus.NOT_PERFORMED
            evidence_state = DeployHostReconciledEvidenceState.NOT_PERFORMED
            evidence_digest = None
            blockers = prior.blockers
        else:
            status = DeployHostReconciledStepStatus.BLOCKED
            evidence_state = DeployHostReconciledEvidenceState.NOT_PERFORMED
            evidence_digest = None
            blockers = prior.blockers
        result.append(
            _reconciled_step(
                original,
                prior,
                status=status,
                evidence_state=evidence_state,
                evidence_digest=evidence_digest,
                blockers=blockers,
            )
        )
    return tuple(result)


def _reconciled_step(
    original: DeployAnsiblePlanStep,
    prior: DeployEffectivePlanStep,
    *,
    status: DeployHostReconciledStepStatus,
    evidence_state: DeployHostReconciledEvidenceState,
    evidence_digest: str | None,
    blockers: tuple[str, ...],
) -> DeployHostReconciledStep:
    if (
        prior.sequence != original.sequence
        or prior.mapping_sequence != original.mapping_sequence
        or prior.playbook != original.playbook
        or prior.condition != original.condition
        or prior.condition_state is not original.condition_state
        or prior.classification is not original.classification
        or prior.target_role != original.target_role
        or prior.target_ids != original.target_ids
        or prior.target_digest != original.target_digest
        or prior.limit_policy is not original.limit_policy
        or prior.serial != original.serial
        or prior.check_mode is not original.check_mode
        or prior.variable_names != original.variable_names
        or prior.variables_digest != original.variables_digest
        or prior.source_digest != original.source_digest
        or prior.command_digest != original.command_digest
        or prior.original_step_digest != _digest_object(original.to_object())
    ):
        raise StateConflictError("host-evidence reconciliation step identity drifted")
    return DeployHostReconciledStep(
        sequence=original.sequence,
        mapping_sequence=original.mapping_sequence,
        playbook=original.playbook,
        condition=original.condition,
        condition_state=original.condition_state,
        classification=original.classification,
        target_role=original.target_role,
        target_ids=original.target_ids,
        target_digest=original.target_digest,
        limit_policy=original.limit_policy,
        serial=original.serial,
        check_mode=original.check_mode,
        variable_names=original.variable_names,
        variables_digest=original.variables_digest,
        source_digest=original.source_digest,
        command_digest=original.command_digest,
        original_step_digest=prior.original_step_digest,
        prior_effective_step_digest=_digest_object(prior.to_object()),
        status=status,
        evidence_state=evidence_state,
        evidence_digest=evidence_digest,
        blockers=blockers,
    )


def _build_reconciliation_record(
    context: _HostReconciliationContext,
    *,
    steps: tuple[DeployHostReconciledStep, ...],
    created_at: str,
) -> DeployHostEvidenceReconciliation:
    loaded = context.loaded
    planning = loaded.planning
    metadata = planning.base.deploy.metadata.record
    journal = planning.base.deploy.journal
    status_counts = Counter(step.status for step in steps)
    host_blockers = {
        blocker
        for evaluation in context.host_evaluations
        for blocker in evaluation.blockers
    }
    blocker_set = tuple(
        sorted(
            {
                *host_blockers,
                *(blocker for step in steps for blocker in step.blockers),
            }
        )
    )
    host_ids = tuple(item.logical_id for item in context.host_evaluations)
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_name": metadata.cluster_name,
        "operation_id": journal.record.operation_id,
        "operation": _OPERATION,
        "request_digest": journal.record.request_digest,
        "journal_generation": journal.record.generation,
        "journal_digest": journal.digest,
        "journal_status": journal.record.status,
        "journal_phase": journal.record.phase,
        "context_artifact_digest": loaded.context.artifact_digest,
        "context_record_digest": loaded.context.record.record_digest,
        "original_plan_artifact_digest": loaded.plan.artifact_digest,
        "original_plan_record_digest": loaded.plan.record.record_digest,
        "prior_effective_plan_artifact_digest": context.prior_effective.artifact_digest,
        "prior_effective_plan_record_digest": (
            context.prior_effective.record.record_digest
        ),
        "prior_effective_plan_digest": (
            context.prior_effective.record.effective_plan_digest
        ),
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": planning.readiness.record.record_digest,
        "prerequisite_execution_artifact_digest": loaded.execution.artifact_digest,
        "prerequisite_evidence_artifact_digest": loaded.evidence.artifact_digest,
        "pre_mutation_execution_artifact_digest": context.execution.artifact_digest,
        "pre_mutation_evidence_artifact_digest": context.evidence.artifact_digest,
        "pre_mutation_binding_digest": context.execution.record.binding.binding_digest,
        "pre_mutation_checkpoint_digest": (
            context.execution.record.binding.checkpoint_digest
        ),
        "pre_mutation_evidence_digest": context.pre_mutation_evidence_digest,
        "checkpoint_kind": _CHECKPOINT_KIND,
        "catalog_digest": loaded.catalog_digest,
        "ansible_source_version": loaded.source.version,
        "ansible_source_digest": loaded.source.digest,
        "host_count": len(host_ids),
        "host_set_digest": _digest_object(list(host_ids)),
        "host_gate_counts": context.gate_counts,
        "host_gate_digest": context.host_gate_digest,
        "steps": steps,
        "mapping_count": len(OPERATION_PLAYBOOKS[_OPERATION]),
        "step_count": len(steps),
        "succeeded_count": status_counts[DeployHostReconciledStepStatus.SUCCEEDED],
        "authorization_required_count": status_counts[
            DeployHostReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        ],
        "blocked_count": status_counts[DeployHostReconciledStepStatus.BLOCKED],
        "not_performed_count": status_counts[
            DeployHostReconciledStepStatus.NOT_PERFORMED
        ],
        "blocker_set": blocker_set,
        "blocker_digest": _digest_object(list(blocker_set)),
        "effective_plan_digest": _digest_object([step.to_object() for step in steps]),
        "authorization_state": _NOT_COLLECTED,
        "mutating_execution_state": _BLOCKED,
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(values)
    return DeployHostEvidenceReconciliation(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployHostEvidenceReconciliation,
    *,
    state: DeployHostReconciliationArtifactState,
    context: _HostReconciliationContext,
) -> DeployHostEvidenceReconciliationReport:
    record = stored.record
    host_roles = {
        host.logical_id: host.role.value
        for host in context.loaded.planning.base.deploy.inventory.record.inventory.hosts
    }
    grouped_steps: dict[tuple[str, str], list[DeployHostReconciledStep]] = {}
    for step in record.steps:
        if (
            step.status
            is not DeployHostReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        ):
            continue
        roles = {host_roles[target] for target in step.target_ids}
        if len(roles) != 1:
            raise StatePersistenceError("authorization-required step role is ambiguous")
        key = (step.playbook, next(iter(roles)))
        grouped_steps.setdefault(key, []).append(step)
    next_authorization_required = tuple(
        AuthorizationRequiredStepCount(
            playbook,
            role,
            len(steps),
            len({target for step in steps for target in step.target_ids}),
        )
        for (playbook, role), steps in sorted(grouped_steps.items())
    )
    return DeployHostEvidenceReconciliationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        reconciliation_artifact_digest=stored.artifact_digest,
        reconciliation_record_digest=record.record_digest,
        effective_plan_digest=record.effective_plan_digest,
        prior_effective_plan_artifact_digest=(
            record.prior_effective_plan_artifact_digest
        ),
        prior_effective_plan_digest=record.prior_effective_plan_digest,
        pre_mutation_execution_artifact_digest=(
            record.pre_mutation_execution_artifact_digest
        ),
        pre_mutation_evidence_artifact_digest=(
            record.pre_mutation_evidence_artifact_digest
        ),
        pre_mutation_checkpoint_digest=record.pre_mutation_checkpoint_digest,
        pre_mutation_evidence_digest=record.pre_mutation_evidence_digest,
        host_count=record.host_count,
        host_set_digest=record.host_set_digest,
        host_gate_counts=record.host_gate_counts,
        host_gate_digest=record.host_gate_digest,
        total_count=record.step_count,
        succeeded_count=record.succeeded_count,
        authorization_required_count=record.authorization_required_count,
        blocked_count=record.blocked_count,
        not_performed_count=record.not_performed_count,
        next_authorization_required=next_authorization_required,
        blocker_set=record.blocker_set,
        blocker_digest=record.blocker_digest,
        mapped_final_evidence_state="not-performed",
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        authorization_state=record.authorization_state,
        mutating_execution_state=record.mutating_execution_state,
        finalization_state=record.finalization_state,
        public_workflow_state=record.public_workflow_state,
    )


def _record_digest(record: DeployHostEvidenceReconciliation) -> str:
    value = record.to_object()
    value["record_digest"] = ""
    return _digest_object(value)


def _record_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployHostEvidenceReconciliation.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(item, (JournalStatus, OperationPhase))
            else [step.to_object() for step in item]
            if name == "steps" and isinstance(item, tuple)
            else [gate.to_object() for gate in item]
            if name == "host_gate_counts" and isinstance(item, tuple)
            else list(item)
            if name == "blocker_set" and isinstance(item, tuple)
            else item
        )
    value["record_digest"] = ""
    return _digest_object(value)


def _artifact_digest(value: Mapping[str, object]) -> str:
    return digest_bytes(serialize_json(value))


def _require_canonical_paths(paths: StatePaths) -> None:
    if StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths:
        raise StatePersistenceError(
            "host-evidence reconciliation paths are not canonical"
        )


def _refuse_ambiguous_reconciliation_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list host-evidence reconciliation artifacts"
        ) from error
    canonical = str(operation_id)
    for entry in entries:
        if not entry.name.endswith(DEPLOY_HOST_RECONCILIATION_FILENAME_SUFFIX):
            continue
        prefix = entry.name[: -len(DEPLOY_HOST_RECONCILIATION_FILENAME_SUFFIX)]
        try:
            parsed = uuid.UUID(prefix)
        except ValueError:
            continue
        if parsed == operation_id and prefix != canonical:
            validate_state_file(entry)
            raise StateConflictError(
                "host-evidence reconciliation artifacts are ambiguous"
            )


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    if value is None:
        return None
    return _integer(value, label)


def _nonnegative_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StatePersistenceError(f"{label} must be nonnegative")


def _positive_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise StatePersistenceError(f"{label} must be a string array")
    return tuple(value)


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise StatePersistenceError(f"{label} must be an array")
    return value


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(Mapping[str, object], value)
