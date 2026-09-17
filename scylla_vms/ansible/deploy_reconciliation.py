"""Immutable deploy-plan reconciliation after read-only prerequisite evidence.

This owner consumes the exact completed inventory-preflight and initial
connectivity evidence.  It never rewrites the original deploy context or plan,
never invokes a runner, and never makes a mutating step executable.
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

from scylla_vms.ansible.deploy_plan import (
    ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION,
    DeployAnsibleContextStore,
    DeployAnsiblePlanStep,
    DeployAnsiblePlanStore,
    DeployConditionState,
    DeployIntentContext,
    StoredDeployAnsibleContext,
    StoredDeployAnsiblePlan,
    _assert_operation_lock,
    _build_context,
    _build_plan,
    _build_steps,
    _DeployPlanningContext,
    _digest_object,
    _load_deploy_planning_context,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_prerequisites import (
    ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_PREREQUISITE_EXECUTION_SCHEMA_VERSION,
    DeployPrerequisiteEvidenceStatus,
    DeployPrerequisiteEvidenceStore,
    DeployPrerequisiteExecutionStore,
    StoredDeployPrerequisiteEvidence,
    StoredDeployPrerequisiteExecution,
    _RuntimeContext,
    _validate_prefix,
)
from scylla_vms.ansible.operation_execution import ExecutionAttemptState
from scylla_vms.ansible.orchestration import ansible_operation_catalog_digest
from scylla_vms.ansible.registry import (
    OPERATION_PLAYBOOKS,
    CheckMode,
    LimitPolicy,
    get_playbook,
)
from scylla_vms.ansible.source import (
    ANSIBLE_SOURCE_VERSION,
    AnsibleSourceBundle,
    load_ansible_source_bundle,
)
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

ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-effective-plan/v1"
)
ANSIBLE_DEPLOY_EFFECTIVE_PLAN_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-effective-plan-report/v1"
)
DEPLOY_EFFECTIVE_PLAN_FILENAME_SUFFIX = ".ansible-deploy-effective-plan.json"

_OPERATION = "deploy"
_NOT_COLLECTED = "not-collected"
_BLOCKED = "blocked"
_NOT_STARTED = "not-started"
_UNAVAILABLE = "unavailable"
_REQUIRED_PLAYBOOKS = ("inventory-preflight", "connectivity-check")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ROLE_ORDER = ("jump-host", "scylla", "manager", "monitoring")
_CLASS_BLOCKERS = {
    OperationClassification.MUTATING: "mutating-deploy-execution-unavailable",
    OperationClassification.SENSITIVE: "sensitive-deploy-execution-unavailable",
    OperationClassification.DESTRUCTIVE: "destructive-deploy-execution-unavailable",
}


class DeployEffectivePlanArtifactState(StrEnum):
    """Immutable companion persistence state."""

    CREATED = "created"
    REUSED = "reused"


class DeployEffectiveStepStatus(StrEnum):
    """Truthful effective state of one immutable original plan step."""

    SUCCEEDED = "succeeded"
    ELIGIBLE = "eligible"
    BLOCKED = "blocked"
    NOT_PERFORMED = "not-performed"


class DeployEffectiveEvidenceState(StrEnum):
    """Whether an effective step is bound to exact semantic evidence."""

    BOUND = "bound"
    NOT_PERFORMED = "not-performed"
    NOT_REQUIRED = "not-required"


@dataclass(frozen=True, slots=True)
class DeployEffectivePlanStep:
    """Original step identity plus its evidence-reconciled status."""

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
    status: DeployEffectiveStepStatus
    evidence_state: DeployEffectiveEvidenceState
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
            or not isinstance(self.status, DeployEffectiveStepStatus)
            or not isinstance(self.evidence_state, DeployEffectiveEvidenceState)
            or self.classification is not definition.classification
            or self.limit_policy is not definition.limit_policy
            or self.serial != definition.serial
            or self.check_mode is not definition.check_mode
            or self.target_role not in {"all", *_ROLE_ORDER}
        ):
            raise StatePersistenceError("effective deploy step policy is invalid")
        if (
            self.target_ids != tuple(sorted(set(self.target_ids)))
            or any(not _LOGICAL_ID.fullmatch(item) for item in self.target_ids)
            or self.variable_names != tuple(dict.fromkeys(self.variable_names))
            or set(self.variable_names)
            != {variable.name for variable in definition.variables}
            or self.blockers != tuple(sorted(set(self.blockers)))
            or any(not _BLOCKER.fullmatch(blocker) for blocker in self.blockers)
        ):
            raise StatePersistenceError("effective deploy step projection is invalid")
        if self.target_ids:
            from scylla_vms.ansible.commands import validate_playbook_request_policy

            validate_playbook_request_policy(
                definition.name,
                limit=self.target_ids,
            )
        for value in (
            self.target_digest,
            self.variables_digest,
            self.source_digest,
            self.command_digest,
            self.original_step_digest,
        ):
            validate_digest(value, "effective deploy step digest")
        if self.target_digest != _digest_object(list(self.target_ids)):
            raise StatePersistenceError("effective deploy target digest conflicts")
        if self.evidence_digest is not None:
            validate_digest(self.evidence_digest, "effective deploy evidence digest")
        if self.status is DeployEffectiveStepStatus.SUCCEEDED:
            if (
                self.sequence not in {1, 2}
                or self.playbook != _REQUIRED_PLAYBOOKS[self.sequence - 1]
                or self.evidence_state is not DeployEffectiveEvidenceState.BOUND
                or self.evidence_digest is None
                or self.blockers
            ):
                raise StatePersistenceError(
                    "effective deploy succeeded step is not evidence-bound"
                )
        elif self.status is DeployEffectiveStepStatus.ELIGIBLE:
            if (
                self.classification is not OperationClassification.READ_ONLY
                or self.evidence_state is not DeployEffectiveEvidenceState.NOT_PERFORMED
                or self.evidence_digest is not None
                or self.blockers
                or not self.target_ids
            ):
                raise StatePersistenceError("effective deploy eligible step is invalid")
        elif self.status is DeployEffectiveStepStatus.BLOCKED:
            if not self.blockers or self.evidence_digest is not None:
                raise StatePersistenceError("effective deploy blocked step is invalid")
        elif self.evidence_digest is not None:
            raise StatePersistenceError(
                "effective deploy not-performed step has evidence"
            )
        if self.condition_state is DeployConditionState.INACTIVE and (
            self.status is not DeployEffectiveStepStatus.NOT_PERFORMED
            or self.evidence_state is not DeployEffectiveEvidenceState.NOT_REQUIRED
            or self.blockers
        ):
            raise StatePersistenceError("effective inactive deploy step is invalid")
        if (
            self.classification is not OperationClassification.READ_ONLY
            and self.condition_state is not DeployConditionState.INACTIVE
            and (
                self.status is not DeployEffectiveStepStatus.BLOCKED
                or _CLASS_BLOCKERS[self.classification] not in self.blockers
            )
        ):
            raise StatePersistenceError("effective mutating deploy step is not blocked")

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
    def from_object(cls, value: Mapping[str, object]) -> DeployEffectivePlanStep:
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
            "effective deploy step",
        )
        evidence_digest = value["evidence_digest"]
        if evidence_digest is not None and not isinstance(evidence_digest, str):
            raise StatePersistenceError(
                "effective deploy evidence digest must be a string or null"
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
                status=DeployEffectiveStepStatus(require_string(value, "status")),
                evidence_state=DeployEffectiveEvidenceState(
                    require_string(value, "evidence_state")
                ),
                evidence_digest=evidence_digest,
                blockers=_string_tuple(value["blockers"], "blockers"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "effective deploy step enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployEffectivePlan:
    """Immutable evidence-bound effective view of the original deploy plan."""

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
    readiness_artifact_digest: str
    readiness_record_digest: str
    prerequisite_execution_artifact_digest: str
    prerequisite_evidence_artifact_digest: str
    prerequisite_evidence_digest: str
    catalog_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    steps: tuple[DeployEffectivePlanStep, ...]
    mapping_count: int
    step_count: int
    succeeded_count: int
    eligible_count: int
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
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    prerequisite_execution_schema_version: str = (
        ANSIBLE_DEPLOY_PREREQUISITE_EXECUTION_SCHEMA_VERSION
    )
    prerequisite_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version != ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION
            or self.context_schema_version != ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
            or self.original_plan_schema_version != ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.prerequisite_execution_schema_version
            != ANSIBLE_DEPLOY_PREREQUISITE_EXECUTION_SCHEMA_VERSION
            or self.prerequisite_evidence_schema_version
            != ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.authorization_state != _NOT_COLLECTED
            or self.mutating_execution_state != _BLOCKED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
        ):
            raise StatePersistenceError("effective deploy plan identity is invalid")
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for count in (
            self.journal_generation,
            self.mapping_count,
            self.step_count,
            self.succeeded_count,
            self.eligible_count,
            self.blocked_count,
            self.not_performed_count,
        ):
            _nonnegative_integer(count, "effective deploy plan count")
        if (
            self.journal_generation < 1
            or self.mapping_count != len(OPERATION_PLAYBOOKS[_OPERATION])
            or self.step_count != len(self.steps)
            or not self.steps
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, len(self.steps) + 1))
        ):
            raise StatePersistenceError("effective deploy plan sequence is invalid")
        expected_mapping = OPERATION_PLAYBOOKS[_OPERATION]
        if {step.mapping_sequence for step in self.steps} != set(
            range(1, len(expected_mapping) + 1)
        ) or any(
            step.playbook != expected_mapping[step.mapping_sequence - 1].playbook
            or step.condition != expected_mapping[step.mapping_sequence - 1].condition
            for step in self.steps
        ):
            raise StatePersistenceError("effective deploy plan mapping conflicts")
        status_counts = Counter(step.status for step in self.steps)
        blocker_set = tuple(
            sorted({blocker for step in self.steps for blocker in step.blockers})
        )
        if (
            self.succeeded_count != status_counts[DeployEffectiveStepStatus.SUCCEEDED]
            or self.eligible_count != status_counts[DeployEffectiveStepStatus.ELIGIBLE]
            or self.eligible_count != 0
            or self.blocked_count != status_counts[DeployEffectiveStepStatus.BLOCKED]
            or self.not_performed_count
            != status_counts[DeployEffectiveStepStatus.NOT_PERFORMED]
            or self.succeeded_count
            + self.eligible_count
            + self.blocked_count
            + self.not_performed_count
            != self.step_count
            or self.succeeded_count != 2
            or self.blocker_set != blocker_set
            or self.blocker_digest != _digest_object(list(blocker_set))
            or self.effective_plan_digest
            != _digest_object([step.to_object() for step in self.steps])
        ):
            raise StatePersistenceError("effective deploy plan summary conflicts")
        for value in (
            self.request_digest,
            self.journal_digest,
            self.context_artifact_digest,
            self.context_record_digest,
            self.original_plan_artifact_digest,
            self.original_plan_record_digest,
            self.readiness_artifact_digest,
            self.readiness_record_digest,
            self.prerequisite_execution_artifact_digest,
            self.prerequisite_evidence_artifact_digest,
            self.prerequisite_evidence_digest,
            self.catalog_digest,
            self.ansible_source_digest,
            self.blocker_digest,
            self.effective_plan_digest,
            self.record_digest,
        ):
            validate_digest(value, "effective deploy plan digest")
        if self.record_digest != _record_digest(self):
            raise StatePersistenceError("effective deploy plan record digest conflicts")

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
                else list(value)
                if name == "blocker_set"
                else value
            )
        return result

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployEffectivePlan:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "effective deploy plan",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "mapping_count",
            "step_count",
            "succeeded_count",
            "eligible_count",
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
                        "effective deploy journal status is invalid"
                    ) from error
            elif name == "journal_phase":
                try:
                    parsed[name] = OperationPhase(require_string(value, name))
                except ValueError as error:
                    raise StatePersistenceError(
                        "effective deploy journal phase is invalid"
                    ) from error
            elif name == "steps":
                if not isinstance(item, list) or not all(
                    isinstance(step, Mapping) for step in item
                ):
                    raise StatePersistenceError(
                        "effective deploy plan steps are invalid"
                    )
                parsed[name] = tuple(
                    DeployEffectivePlanStep.from_object(step) for step in item
                )
            elif name == "blocker_set":
                parsed[name] = _string_tuple(item, name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployEffectivePlan:
    record: DeployEffectivePlan
    artifact_digest: str


class DeployEffectivePlanStore:
    """Owner-only immutable evidence-reconciled deploy-plan companion."""

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
        self._path = deploy_effective_plan_path(paths, operation_id)
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
    ) -> StoredDeployEffectivePlan:
        value, artifact_digest = self._file.read()
        record = DeployEffectivePlan.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or artifact_digest != _artifact_digest(record.to_object())
        ):
            raise StatePersistenceError("effective deploy plan identity conflicts")
        return StoredDeployEffectivePlan(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployEffectivePlan:
        _assert_operation_lock(lock, self._paths, self._operation_id)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployEffectivePlan,
        *,
        lock: ClusterLock,
    ) -> tuple[StoredDeployEffectivePlan, DeployEffectivePlanArtifactState]:
        _assert_operation_lock(lock, self._paths, self._operation_id)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError("effective deploy operation ID conflicts")
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError("effective deploy plan is immutable")
            return current, DeployEffectivePlanArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployEffectivePlan(record, artifact_digest),
            DeployEffectivePlanArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployEffectivePlanReport:
    """Strict redacted projection of evidence reconciliation."""

    operation_id: uuid.UUID
    artifact_state: DeployEffectivePlanArtifactState
    effective_plan_schema_version: str
    effective_plan_artifact_digest: str
    effective_plan_record_digest: str
    effective_plan_digest: str
    context_schema_version: str
    context_artifact_digest: str
    context_record_digest: str
    original_plan_schema_version: str
    original_plan_artifact_digest: str
    original_plan_record_digest: str
    prerequisite_execution_schema_version: str
    prerequisite_execution_artifact_digest: str
    prerequisite_evidence_schema_version: str
    prerequisite_evidence_artifact_digest: str
    prerequisite_evidence_digest: str
    readiness_schema_version: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    catalog_digest: str
    ansible_source_digest: str
    total_count: int
    succeeded_count: int
    eligible_count: int
    blocked_count: int
    not_performed_count: int
    next_eligible_steps: tuple[tuple[str, int], ...]
    blocker_set: tuple[str, ...]
    blocker_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    journal_generation: int
    journal_digest: str
    authorization_state: str
    mutating_execution_state: str
    finalization_state: str
    public_workflow_state: str
    schema_version: str = ANSIBLE_DEPLOY_EFFECTIVE_PLAN_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_EFFECTIVE_PLAN_REPORT_SCHEMA_VERSION
            or self.effective_plan_schema_version
            != ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION
            or self.context_schema_version != ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
            or self.original_plan_schema_version != ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION
            or self.prerequisite_execution_schema_version
            != ANSIBLE_DEPLOY_PREREQUISITE_EXECUTION_SCHEMA_VERSION
            or self.prerequisite_evidence_schema_version
            != ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.authorization_state != _NOT_COLLECTED
            or self.mutating_execution_state != _BLOCKED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
            or not isinstance(self.operation_id, uuid.UUID)
            or not isinstance(self.artifact_state, DeployEffectivePlanArtifactState)
        ):
            raise StatePersistenceError("effective deploy report identity is invalid")
        for count in (
            self.total_count,
            self.succeeded_count,
            self.eligible_count,
            self.blocked_count,
            self.not_performed_count,
            self.journal_generation,
        ):
            _nonnegative_integer(count, "effective deploy report count")
        if (
            self.total_count < 1
            or self.succeeded_count != 2
            or self.total_count
            != self.succeeded_count
            + self.eligible_count
            + self.blocked_count
            + self.not_performed_count
            or self.eligible_count != 0
            or self.journal_generation < 1
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(not _BLOCKER.fullmatch(item) for item in self.blocker_set)
            or len(self.next_eligible_steps) != self.eligible_count
        ):
            raise StatePersistenceError("effective deploy report summary is invalid")
        for playbook, target_count in self.next_eligible_steps:
            if (
                get_playbook(playbook).classification
                is not OperationClassification.READ_ONLY
                or isinstance(target_count, bool)
                or not isinstance(target_count, int)
                or target_count < 1
            ):
                raise StatePersistenceError(
                    "effective deploy eligible-step summary is invalid"
                )
        for value in (
            self.effective_plan_artifact_digest,
            self.effective_plan_record_digest,
            self.effective_plan_digest,
            self.context_artifact_digest,
            self.context_record_digest,
            self.original_plan_artifact_digest,
            self.original_plan_record_digest,
            self.prerequisite_execution_artifact_digest,
            self.prerequisite_evidence_artifact_digest,
            self.prerequisite_evidence_digest,
            self.readiness_artifact_digest,
            self.readiness_record_digest,
            self.catalog_digest,
            self.ansible_source_digest,
            self.blocker_digest,
            self.journal_digest,
        ):
            validate_digest(value, "effective deploy report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "ansible_source_digest": self.ansible_source_digest,
            "artifact_state": self.artifact_state.value,
            "authorization_state": self.authorization_state,
            "blocked_count": self.blocked_count,
            "blocker_digest": self.blocker_digest,
            "blocker_set": list(self.blocker_set),
            "catalog_digest": self.catalog_digest,
            "context_artifact_digest": self.context_artifact_digest,
            "context_record_digest": self.context_record_digest,
            "context_schema_version": self.context_schema_version,
            "effective_plan_artifact_digest": self.effective_plan_artifact_digest,
            "effective_plan_digest": self.effective_plan_digest,
            "effective_plan_record_digest": self.effective_plan_record_digest,
            "effective_plan_schema_version": self.effective_plan_schema_version,
            "eligible_count": self.eligible_count,
            "finalization_state": self.finalization_state,
            "journal_digest": self.journal_digest,
            "journal_generation": self.journal_generation,
            "journal_phase": self.journal_phase.value,
            "journal_status": self.journal_status.value,
            "mutating_execution_state": self.mutating_execution_state,
            "next_eligible_steps": [
                {"playbook": playbook, "stable_id_count": target_count}
                for playbook, target_count in self.next_eligible_steps
            ],
            "not_performed_count": self.not_performed_count,
            "operation_id": str(self.operation_id),
            "original_plan_artifact_digest": self.original_plan_artifact_digest,
            "original_plan_record_digest": self.original_plan_record_digest,
            "original_plan_schema_version": self.original_plan_schema_version,
            "prerequisite_evidence_artifact_digest": (
                self.prerequisite_evidence_artifact_digest
            ),
            "prerequisite_evidence_digest": self.prerequisite_evidence_digest,
            "prerequisite_evidence_schema_version": (
                self.prerequisite_evidence_schema_version
            ),
            "prerequisite_execution_artifact_digest": (
                self.prerequisite_execution_artifact_digest
            ),
            "prerequisite_execution_schema_version": (
                self.prerequisite_execution_schema_version
            ),
            "public_workflow_state": self.public_workflow_state,
            "readiness_artifact_digest": self.readiness_artifact_digest,
            "readiness_record_digest": self.readiness_record_digest,
            "readiness_schema_version": self.readiness_schema_version,
            "schema_version": self.schema_version,
            "succeeded_count": self.succeeded_count,
            "total_count": self.total_count,
        }


@dataclass(frozen=True, slots=True)
class _ReconciliationContext:
    planning: _DeployPlanningContext
    source: AnsibleSourceBundle
    catalog_digest: str
    context: StoredDeployAnsibleContext
    plan: StoredDeployAnsiblePlan
    execution: StoredDeployPrerequisiteExecution
    evidence: StoredDeployPrerequisiteEvidence


def reconcile_deploy_ansible_plan(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployEffectivePlanReport:
    """Persist an immutable effective plan after exact prerequisite success."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths, operation_id)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_effective_plan_artifacts(paths, operation_id)

    loaded = _load_reconciliation_context(paths, operation_id, lock=lock)
    metadata = loaded.planning.base.deploy.metadata.record
    store = DeployEffectivePlanStore(paths, operation_id)
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
    effective_steps = _build_effective_steps(loaded.plan.record.steps, loaded.evidence)
    record = _build_effective_plan(
        loaded,
        effective_steps=effective_steps,
        created_at=created_at,
    )
    if existing is not None and existing.record != record:
        raise StateConflictError("effective deploy plan is immutable")
    try:
        stored, state = store.write_locked(record, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "effective deploy plan persistence failed"
        ) from error
    return _build_report(stored, state=state)


def deploy_effective_plan_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / f"{operation_id}{DEPLOY_EFFECTIVE_PLAN_FILENAME_SUFFIX}"
    if path.parent != paths.operations:
        raise StatePersistenceError("effective deploy plan path is not canonical")
    return path


def deploy_effective_plan_id_from_filename(name: str) -> uuid.UUID | None:
    if not name.endswith(DEPLOY_EFFECTIVE_PLAN_FILENAME_SUFFIX):
        return None
    value = name[: -len(DEPLOY_EFFECTIVE_PLAN_FILENAME_SUFFIX)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _load_reconciliation_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
) -> _ReconciliationContext:
    planning = _load_deploy_planning_context(paths, operation_id)
    journal = planning.base.deploy.journal
    if (
        journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
    ):
        raise StateConflictError(
            "deploy plan reconciliation requires the unchanged VERIFY journal"
        )
    source = load_ansible_source_bundle()
    catalog_digest = ansible_operation_catalog_digest()
    metadata = planning.base.deploy.metadata.record
    context_store = DeployAnsibleContextStore(paths, operation_id)
    plan_store = DeployAnsiblePlanStore(paths, operation_id)
    execution_store = DeployPrerequisiteExecutionStore(paths, operation_id)
    evidence_store = DeployPrerequisiteEvidenceStore(paths, operation_id)
    for path in (
        context_store.path,
        plan_store.path,
        execution_store.path,
        evidence_store.path,
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                "deploy plan reconciliation requires completed prerequisites"
            )
    context = context_store.read(
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    plan = plan_store.read(
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_context = _build_context(
        planning,
        source_bundle=source,
        catalog_digest=catalog_digest,
        intent=DeployIntentContext(),
        created_at=context.record.created_at,
    )
    expected_steps = _build_steps(planning, source_bundle=source)
    expected_plan = _build_plan(
        context_record=expected_context,
        context_artifact_digest=context.artifact_digest,
        steps=expected_steps,
        source_bundle=source,
        catalog_digest=catalog_digest,
        created_at=context.record.created_at,
    )
    if context.record != expected_context:
        raise StateConflictError(
            "deploy plan reconciliation context requires explicit re-plan"
        )
    if plan.record != expected_plan:
        raise StateConflictError(
            "deploy plan reconciliation mapping requires explicit re-plan"
        )

    matches = tuple(
        tuple(
            step
            for step in plan.record.steps
            if step.mapping_sequence == mapping_sequence
        )
        for mapping_sequence in (1, 2)
    )
    if any(len(group) != 1 for group in matches):
        raise StateConflictError(
            "deploy plan reconciliation prerequisite mapping conflicts"
        )
    prerequisite_steps = (matches[0][0], matches[1][0])
    host_ids = tuple(
        sorted(
            host.logical_id
            for host in planning.base.deploy.inventory.record.inventory.hosts
        )
    )
    runtime = _RuntimeContext(
        planning,
        context,
        plan,
        prerequisite_steps,
        source,
        catalog_digest,
        host_ids,
        _digest_object(list(host_ids)),
        planning.readiness.record.executable_identity_digest,
        planning.readiness.record.toolchain_evidence_digest,
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
    _validate_prefix(runtime, execution, evidence)
    if (
        not execution.record.all_steps_completed
        or execution.record.state is not ExecutionAttemptState.SUCCEEDED
        or len(execution.record.attempts) != 2
        or any(
            attempt.state is not ExecutionAttemptState.SUCCEEDED
            or attempt.manual_recovery_required
            for attempt in execution.record.attempts
        )
        or len(evidence.record.entries) != 2
        or any(
            entry.status is not DeployPrerequisiteEvidenceStatus.PASSED
            for entry in evidence.record.entries
        )
    ):
        raise StateConflictError(
            "deploy plan reconciliation requires exact succeeded prerequisites"
        )
    return _ReconciliationContext(
        planning,
        source,
        catalog_digest,
        context,
        plan,
        execution,
        evidence,
    )


def _build_effective_steps(
    original_steps: tuple[DeployAnsiblePlanStep, ...],
    evidence: StoredDeployPrerequisiteEvidence,
) -> tuple[DeployEffectivePlanStep, ...]:
    evidence_by_sequence = {entry.sequence: entry for entry in evidence.record.entries}
    result: list[DeployEffectivePlanStep] = []
    for step in original_steps:
        evidence_entry = evidence_by_sequence.get(step.sequence)
        if step.sequence in {1, 2}:
            if (
                evidence_entry is None
                or evidence_entry.playbook != step.playbook
                or evidence_entry.mapping_sequence != step.mapping_sequence
                or evidence_entry.plan_command_digest != step.command_digest
                or evidence_entry.variables_digest != step.variables_digest
                or evidence_entry.source_digest != step.source_digest
                or evidence_entry.target_set_digest != step.target_digest
            ):
                raise StateConflictError(
                    "deploy plan reconciliation evidence conflicts with the plan"
                )
            status = DeployEffectiveStepStatus.SUCCEEDED
            evidence_state = DeployEffectiveEvidenceState.BOUND
            evidence_digest = evidence_entry.evidence_digest
            blockers: tuple[str, ...] = ()
        elif step.condition_state is DeployConditionState.INACTIVE:
            status = DeployEffectiveStepStatus.NOT_PERFORMED
            evidence_state = DeployEffectiveEvidenceState.NOT_REQUIRED
            evidence_digest = None
            blockers = ()
        elif step.classification is OperationClassification.READ_ONLY:
            # The next active positions in the immutable deploy mapping are
            # mutating. Later read-only checks cannot be promoted out of order;
            # their remote facts truthfully remain not performed.
            status = DeployEffectiveStepStatus.NOT_PERFORMED
            evidence_state = DeployEffectiveEvidenceState.NOT_PERFORMED
            evidence_digest = None
            blockers = step.blockers
        else:
            status = DeployEffectiveStepStatus.BLOCKED
            evidence_state = DeployEffectiveEvidenceState.NOT_PERFORMED
            evidence_digest = None
            blockers = tuple(
                sorted(
                    {
                        *step.blockers,
                        _CLASS_BLOCKERS[step.classification],
                        "deploy-authorization-not-collected",
                    }
                )
            )
        result.append(
            DeployEffectivePlanStep(
                sequence=step.sequence,
                mapping_sequence=step.mapping_sequence,
                playbook=step.playbook,
                condition=step.condition,
                condition_state=step.condition_state,
                classification=step.classification,
                target_role=step.target_role,
                target_ids=step.target_ids,
                target_digest=step.target_digest,
                limit_policy=step.limit_policy,
                serial=step.serial,
                check_mode=step.check_mode,
                variable_names=step.variable_names,
                variables_digest=step.variables_digest,
                source_digest=step.source_digest,
                command_digest=step.command_digest,
                original_step_digest=_digest_object(step.to_object()),
                status=status,
                evidence_state=evidence_state,
                evidence_digest=evidence_digest,
                blockers=blockers,
            )
        )
    return tuple(result)


def _build_effective_plan(
    loaded: _ReconciliationContext,
    *,
    effective_steps: tuple[DeployEffectivePlanStep, ...],
    created_at: str,
) -> DeployEffectivePlan:
    planning = loaded.planning
    metadata = planning.base.deploy.metadata.record
    journal = planning.base.deploy.journal
    context = loaded.context
    plan = loaded.plan
    status_counts = Counter(step.status for step in effective_steps)
    blocker_set = tuple(
        sorted({blocker for step in effective_steps for blocker in step.blockers})
    )
    prerequisite_evidence_digest = _digest_object(
        [entry.evidence_digest for entry in loaded.evidence.record.entries]
    )
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
        "context_artifact_digest": context.artifact_digest,
        "context_record_digest": context.record.record_digest,
        "original_plan_artifact_digest": plan.artifact_digest,
        "original_plan_record_digest": plan.record.record_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": planning.readiness.record.record_digest,
        "prerequisite_execution_artifact_digest": loaded.execution.artifact_digest,
        "prerequisite_evidence_artifact_digest": loaded.evidence.artifact_digest,
        "prerequisite_evidence_digest": prerequisite_evidence_digest,
        "catalog_digest": loaded.catalog_digest,
        "ansible_source_version": loaded.source.version,
        "ansible_source_digest": loaded.source.digest,
        "steps": effective_steps,
        "mapping_count": len(OPERATION_PLAYBOOKS[_OPERATION]),
        "step_count": len(effective_steps),
        "succeeded_count": status_counts[DeployEffectiveStepStatus.SUCCEEDED],
        "eligible_count": status_counts[DeployEffectiveStepStatus.ELIGIBLE],
        "blocked_count": status_counts[DeployEffectiveStepStatus.BLOCKED],
        "not_performed_count": status_counts[DeployEffectiveStepStatus.NOT_PERFORMED],
        "blocker_set": blocker_set,
        "blocker_digest": _digest_object(list(blocker_set)),
        "effective_plan_digest": _digest_object(
            [step.to_object() for step in effective_steps]
        ),
        "authorization_state": _NOT_COLLECTED,
        "mutating_execution_state": _BLOCKED,
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(values)
    return DeployEffectivePlan(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployEffectivePlan,
    *,
    state: DeployEffectivePlanArtifactState,
) -> DeployEffectivePlanReport:
    record = stored.record
    next_eligible = tuple(
        (step.playbook, len(step.target_ids))
        for step in record.steps
        if step.status is DeployEffectiveStepStatus.ELIGIBLE
    )
    return DeployEffectivePlanReport(
        operation_id=record.operation_id,
        artifact_state=state,
        effective_plan_schema_version=record.schema_version,
        effective_plan_artifact_digest=stored.artifact_digest,
        effective_plan_record_digest=record.record_digest,
        effective_plan_digest=record.effective_plan_digest,
        context_schema_version=record.context_schema_version,
        context_artifact_digest=record.context_artifact_digest,
        context_record_digest=record.context_record_digest,
        original_plan_schema_version=record.original_plan_schema_version,
        original_plan_artifact_digest=record.original_plan_artifact_digest,
        original_plan_record_digest=record.original_plan_record_digest,
        prerequisite_execution_schema_version=(
            record.prerequisite_execution_schema_version
        ),
        prerequisite_execution_artifact_digest=(
            record.prerequisite_execution_artifact_digest
        ),
        prerequisite_evidence_schema_version=(
            record.prerequisite_evidence_schema_version
        ),
        prerequisite_evidence_artifact_digest=(
            record.prerequisite_evidence_artifact_digest
        ),
        prerequisite_evidence_digest=record.prerequisite_evidence_digest,
        readiness_schema_version=record.readiness_schema_version,
        readiness_artifact_digest=record.readiness_artifact_digest,
        readiness_record_digest=record.readiness_record_digest,
        catalog_digest=record.catalog_digest,
        ansible_source_digest=record.ansible_source_digest,
        total_count=record.step_count,
        succeeded_count=record.succeeded_count,
        eligible_count=record.eligible_count,
        blocked_count=record.blocked_count,
        not_performed_count=record.not_performed_count,
        next_eligible_steps=next_eligible,
        blocker_set=record.blocker_set,
        blocker_digest=record.blocker_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        journal_generation=record.journal_generation,
        journal_digest=record.journal_digest,
        authorization_state=record.authorization_state,
        mutating_execution_state=record.mutating_execution_state,
        finalization_state=record.finalization_state,
        public_workflow_state=record.public_workflow_state,
    )


def _record_digest(record: DeployEffectivePlan) -> str:
    value = record.to_object()
    value["record_digest"] = ""
    return _digest_object(value)


def _record_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployEffectivePlan.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(item, (JournalStatus, OperationPhase))
            else [step.to_object() for step in item]
            if name == "steps" and isinstance(item, tuple)
            else list(item)
            if name == "blocker_set" and isinstance(item, tuple)
            else item
        )
    value["record_digest"] = ""
    return _digest_object(value)


def _artifact_digest(value: Mapping[str, object]) -> str:
    return digest_bytes(serialize_json(value))


def _refuse_ambiguous_effective_plan_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list effective deploy artifacts"
        ) from error
    canonical = str(operation_id)
    for entry in entries:
        if not entry.name.endswith(DEPLOY_EFFECTIVE_PLAN_FILENAME_SUFFIX):
            continue
        prefix = entry.name[: -len(DEPLOY_EFFECTIVE_PLAN_FILENAME_SUFFIX)]
        try:
            parsed = uuid.UUID(prefix)
        except ValueError:
            continue
        if parsed == operation_id and prefix != canonical:
            validate_state_file(entry)
            raise StateConflictError("effective deploy plan artifacts are ambiguous")


def _require_canonical_paths(paths: StatePaths) -> None:
    if StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths:
        raise StatePersistenceError("effective deploy paths are not canonical")


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _nonnegative_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StatePersistenceError(f"{label} must be nonnegative")


def _optional_integer(value: object, label: str) -> int | None:
    if value is None:
        return None
    return _integer(value, label)


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise StatePersistenceError(f"{label} must be a string array")
    return tuple(value)
