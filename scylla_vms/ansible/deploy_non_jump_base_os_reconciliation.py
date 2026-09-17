"""Immutable reconciliation after non-jump ``base-os`` execution.

This internal owner accepts only canonical operation identity and a held deploy
lock.  It proves exact terminal execution and semantic evidence, records reboot
requirements without handling them, and advances at most the immediate
evidence-ready mapping in a new immutable companion.
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
    BASE_OS_EVIDENCE_SCHEMA_VERSION,
    BaseOsEvidence,
    BaseOsHostEvidence,
    BaseOsStatus,
    base_os_variables,
)
from scylla_vms.ansible.commands import ansible_command_intent_digest
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStep,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_final_routes import (
    ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION,
    StoredDeployPostFinalRoutesReconciliation,
)
from scylla_vms.ansible.deploy_host_evidence import PreMutationHostEvidence
from scylla_vms.ansible.deploy_host_reconciliation import _HostReconciliationContext
from scylla_vms.ansible.deploy_non_jump_base_os_authorization import (
    ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_SCHEMA_VERSION,
    DeployNonJumpBaseOsAuthorizationScope,
    DeployNonJumpBaseOsAuthorizationStore,
    StoredDeployNonJumpBaseOsAuthorization,
    _AuthorizationContext,
    _build_authorization,
    _derive_authorization_scopes,
    _load_authorization_context,
)
from scylla_vms.ansible.deploy_non_jump_base_os_execution import (
    ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EXECUTION_SCHEMA_VERSION,
    DeployNonJumpBaseOsEvidenceEntry,
    DeployNonJumpBaseOsEvidenceStore,
    DeployNonJumpBaseOsExecutionState,
    DeployNonJumpBaseOsExecutionStore,
    DeployNonJumpBaseOsHostEvidence,
    StoredDeployNonJumpBaseOsEvidence,
    StoredDeployNonJumpBaseOsExecution,
    _base_os_result_digest,
    _entry_evidence_digest,
)
from scylla_vms.ansible.deploy_plan import (
    DeployConditionState,
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.registry import OPERATION_PLAYBOOKS, get_playbook
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION
from scylla_vms.desired import HostRole, ImageVersionMatch
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

ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-non-jump-base-os-reconciliation/v1"
)
ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-non-jump-base-os-reconciliation-report/v1"
)
DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-post-non-jump-base-os-reconciliation.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "base-os"
_CONDITION = "non-jump-managed-hosts"
_MAPPING_SEQUENCE = 6
_FINAL_EVIDENCE_MAPPING = len(OPERATION_PLAYBOOKS[_OPERATION])
_NOT_PERFORMED = "not-performed"
_NOT_STARTED = "not-started"
_UNAVAILABLE = "unavailable"
_AUTHORIZATION_CONSUMED = "consumed-by-execution"
_ORDER_BLOCKER = "ordered-deploy-step-not-reached"
_AUTHORIZATION_BLOCKER = "deploy-authorization-not-collected"
_PUBLIC_WORKFLOW_BLOCKER = "public-deploy-workflow-unavailable"
_REBOOT_BLOCKER = "reboot-required"
_REBOOT_HANDLING_BLOCKER = "reboot-handling-not-performed"
_CLASS_BLOCKERS = {
    OperationClassification.MUTATING: "mutating-deploy-execution-unavailable",
    OperationClassification.SENSITIVE: "sensitive-deploy-execution-unavailable",
    OperationClassification.DESTRUCTIVE: "destructive-deploy-execution-unavailable",
}
_SUCCESS_STATUSES = frozenset(
    {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED, BaseOsStatus.REBOOT_REQUIRED}
)
_SAFE_GUEST_ARCHITECTURES = {"x86_64": "amd64", "aarch64": "aarch64"}
_CANONICAL_COMMON_VARIABLES = frozenset(
    {
        "deploy_scylla_vms_checkpoint_id",
        "deploy_scylla_vms_cluster_uuid",
        "deploy_scylla_vms_inventory_digest",
        "deploy_scylla_vms_os_family",
        "deploy_scylla_vms_os_major",
        "deploy_scylla_vms_scylla_version",
    }
)
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")


class DeployPostNonJumpBaseOsArtifactState(StrEnum):
    """Immutable reconciliation persistence state."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployPostNonJumpBaseOsReconciliation:
    """Immutable effective view after exact non-jump base-OS execution."""

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
    post_final_routes_reconciliation_artifact_digest: str
    post_final_routes_reconciliation_record_digest: str
    post_final_routes_effective_plan_digest: str
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_scope_digest: str
    execution_artifact_digest: str
    execution_binding_digest: str
    evidence_artifact_digest: str
    evidence_digest: str
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
    base_os_scope_count: int
    base_os_host_count: int
    base_os_host_set_digest: str
    changed_count: int
    already_current_count: int
    reboot_required_count: int
    reboot_required: bool
    reboot_handling_status: str
    steps: tuple[DeployBaseOsReconciledStep, ...]
    mapping_count: int
    step_count: int
    succeeded_count: int
    authorization_required_count: int
    eligible_count: int
    blocked_count: int
    not_performed_count: int
    blocker_set: tuple[str, ...]
    blocker_digest: str
    effective_plan_digest: str
    authorization_state: str
    execution_state: str
    next_execution_state: str
    final_evidence_state: str
    finalization_state: str
    public_workflow_state: str
    record_digest: str
    post_final_routes_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION
    )
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
    )
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EVIDENCE_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_SCHEMA_VERSION
            or self.post_final_routes_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EVIDENCE_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.reboot_handling_status != _NOT_PERFORMED
            or self.authorization_state != _AUTHORIZATION_CONSUMED
            or self.execution_state != DeployNonJumpBaseOsExecutionState.SUCCEEDED.value
            or self.next_execution_state != _NOT_STARTED
            or self.final_evidence_state != _NOT_PERFORMED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
        ):
            raise StatePersistenceError(
                "post-non-jump-base-os reconciliation identity is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for value in (
            self.journal_generation,
            self.inventory_generation,
            self.trust_generation,
            self.base_os_scope_count,
            self.base_os_host_count,
            self.changed_count,
            self.already_current_count,
            self.reboot_required_count,
            self.mapping_count,
            self.step_count,
            self.succeeded_count,
            self.authorization_required_count,
            self.eligible_count,
            self.blocked_count,
            self.not_performed_count,
        ):
            _nonnegative_integer(value, "post-non-jump-base-os reconciliation count")
        if (
            self.journal_generation < 1
            or self.inventory_generation < 1
            or self.trust_generation < 1
            or self.base_os_scope_count < 1
            or self.base_os_host_count < 1
            or self.changed_count + self.already_current_count
            != self.base_os_host_count
            or self.reboot_required_count > self.changed_count
            or self.reboot_required != (self.reboot_required_count > 0)
            or self.mapping_count != len(OPERATION_PLAYBOOKS[_OPERATION])
            or self.step_count != len(self.steps)
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, len(self.steps) + 1))
        ):
            raise StatePersistenceError(
                "post-non-jump-base-os reconciliation counts conflict"
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
                "post-non-jump-base-os reconciliation mapping conflicts"
            )
        counts = Counter(step.status for step in self.steps)
        non_jump_successes = tuple(
            step
            for step in self.steps
            if step.mapping_sequence == _MAPPING_SEQUENCE
            and step.playbook == _PLAYBOOK
            and step.condition == _CONDITION
            and step.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
            and step.evidence_state
            is DeployBaseOsReconciledEvidenceState.NON_JUMP_BASE_OS_BOUND
        )
        blockers = tuple(
            sorted({blocker for step in self.steps for blocker in step.blockers})
        )
        if self.reboot_required:
            blockers = tuple(
                sorted({*blockers, _REBOOT_BLOCKER, _REBOOT_HANDLING_BLOCKER})
            )
        if (
            len(non_jump_successes) != self.base_os_scope_count
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
            or sum(counts.values()) != self.step_count
            or self.blocker_set != blockers
            or self.blocker_digest != _digest_object(list(blockers))
            or self.effective_plan_digest
            != _digest_object([step.to_object() for step in self.steps])
        ):
            raise StatePersistenceError(
                "post-non-jump-base-os reconciliation summary conflicts"
            )
        for digest_value in _record_digests(self):
            validate_digest(digest_value, "post-non-jump-base-os reconciliation digest")
        if self.record_digest != _record_digest(self):
            raise StatePersistenceError(
                "post-non-jump-base-os reconciliation record digest conflicts"
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
                else list(value)
                if name == "blocker_set"
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployPostNonJumpBaseOsReconciliation:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "post-non-jump-base-os reconciliation",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "inventory_generation",
            "trust_generation",
            "base_os_scope_count",
            "base_os_host_count",
            "changed_count",
            "already_current_count",
            "reboot_required_count",
            "mapping_count",
            "step_count",
            "succeeded_count",
            "authorization_required_count",
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
                parsed[name] = _enum(
                    JournalStatus, require_string(value, name), "journal status"
                )
            elif name == "journal_phase":
                parsed[name] = _enum(
                    OperationPhase, require_string(value, name), "journal phase"
                )
            elif name == "reboot_required":
                parsed[name] = _boolean(item, name)
            elif name == "steps":
                parsed[name] = tuple(
                    DeployBaseOsReconciledStep.from_object(
                        _mapping(step, "post-non-jump-base-os reconciled step")
                    )
                    for step in _array(item, "post-non-jump-base-os reconciled steps")
                )
            elif name == "blocker_set":
                parsed[name] = _string_tuple(item, name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployPostNonJumpBaseOsReconciliation:
    record: DeployPostNonJumpBaseOsReconciliation
    artifact_digest: str


class DeployPostNonJumpBaseOsReconciliationStore:
    """Owner-only immutable post-non-jump-base-OS companion."""

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
        self._path = deploy_post_non_jump_base_os_reconciliation_path(
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
    ) -> StoredDeployPostNonJumpBaseOsReconciliation:
        value, artifact_digest = self._file.read()
        record = DeployPostNonJumpBaseOsReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "post-non-jump-base-os reconciliation identity conflicts"
            )
        return StoredDeployPostNonJumpBaseOsReconciliation(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPostNonJumpBaseOsReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployPostNonJumpBaseOsReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployPostNonJumpBaseOsReconciliation,
        DeployPostNonJumpBaseOsArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "post-non-jump-base-os reconciliation operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "post-non-jump-base-os reconciliation is immutable"
                )
            return current, DeployPostNonJumpBaseOsArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployPostNonJumpBaseOsReconciliation(record, artifact_digest),
            DeployPostNonJumpBaseOsArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployPostNonJumpBaseOsNextStepSummary:
    """Address-free grouping for the immediate derived gate."""

    playbook: str
    target_role: str
    classification: OperationClassification
    status: DeployBaseOsReconciledStepStatus
    instance_count: int
    target_count: int
    target_set_digest: str
    instance_digest: str

    def __post_init__(self) -> None:
        if (
            get_playbook(self.playbook).classification is not self.classification
            or self.status
            not in {
                DeployBaseOsReconciledStepStatus.ELIGIBLE,
                DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
            }
            or self.instance_count < 1
            or self.target_count < 1
        ):
            raise StatePersistenceError(
                "post-non-jump-base-os next-step summary is invalid"
            )
        validate_digest(self.target_set_digest, "next target set digest")
        validate_digest(self.instance_digest, "next step instance digest")

    def to_object(self) -> dict[str, object]:
        return {
            "classification": self.classification.value,
            "instance_count": self.instance_count,
            "instance_digest": self.instance_digest,
            "playbook": self.playbook,
            "status": self.status.value,
            "target_count": self.target_count,
            "target_role": self.target_role,
            "target_set_digest": self.target_set_digest,
        }


@dataclass(frozen=True, slots=True)
class DeployPostNonJumpBaseOsReconciliationReport:
    """Strict redacted projection of non-jump base-OS reconciliation."""

    operation_id: uuid.UUID
    artifact_state: DeployPostNonJumpBaseOsArtifactState
    reconciliation_artifact_digest: str
    reconciliation_record_digest: str
    effective_plan_digest: str
    prior_reconciliation_artifact_digest: str
    authorization_artifact_digest: str
    execution_artifact_digest: str
    evidence_artifact_digest: str
    evidence_digest: str
    base_os_scope_count: int
    base_os_host_count: int
    base_os_host_set_digest: str
    changed_count: int
    already_current_count: int
    reboot_required_count: int
    reboot_required: bool
    reboot_handling_status: str
    succeeded_count: int
    authorization_required_count: int
    eligible_count: int
    blocked_count: int
    not_performed_count: int
    next_steps: tuple[DeployPostNonJumpBaseOsNextStepSummary, ...]
    next_step_count: int
    next_target_count: int
    next_target_set_digest: str
    blocker_set: tuple[str, ...]
    blocker_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    authorization_state: str
    execution_state: str
    next_execution_state: str
    final_evidence_state: str
    finalization_state: str
    public_workflow_state: str
    reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_SCHEMA_VERSION
    )
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
    )
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EVIDENCE_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_REPORT_SCHEMA_VERSION
            or self.reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EVIDENCE_SCHEMA_VERSION
            or self.reboot_handling_status != _NOT_PERFORMED
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.authorization_state != _AUTHORIZATION_CONSUMED
            or self.execution_state != DeployNonJumpBaseOsExecutionState.SUCCEEDED.value
            or self.next_execution_state != _NOT_STARTED
            or self.final_evidence_state != _NOT_PERFORMED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
            or self.next_step_count
            != sum(item.instance_count for item in self.next_steps)
            or self.reboot_required != (self.reboot_required_count > 0)
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blocker_set)
            or self.blocker_digest != _digest_object(list(self.blocker_set))
        ):
            raise StatePersistenceError(
                "post-non-jump-base-os reconciliation report is invalid"
            )
        for value in (
            self.reconciliation_artifact_digest,
            self.reconciliation_record_digest,
            self.effective_plan_digest,
            self.prior_reconciliation_artifact_digest,
            self.authorization_artifact_digest,
            self.execution_artifact_digest,
            self.evidence_artifact_digest,
            self.evidence_digest,
            self.base_os_host_set_digest,
            self.next_target_set_digest,
            self.blocker_digest,
        ):
            validate_digest(value, "post-non-jump-base-os report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "artifact_state": self.artifact_state.value,
            "base_os": {
                "already_current_count": self.already_current_count,
                "changed_count": self.changed_count,
                "host_count": self.base_os_host_count,
                "host_set_digest": self.base_os_host_set_digest,
                "scope_count": self.base_os_scope_count,
            },
            "blockers": {
                "digest": self.blocker_digest,
                "values": list(self.blocker_set),
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "next": {
                "execution_state": self.next_execution_state,
                "step_count": self.next_step_count,
                "steps": [item.to_object() for item in self.next_steps],
                "target_count": self.next_target_count,
                "target_set_digest": self.next_target_set_digest,
            },
            "operation_id": str(self.operation_id),
            "provenance": {
                "authorization_artifact_digest": self.authorization_artifact_digest,
                "evidence_artifact_digest": self.evidence_artifact_digest,
                "evidence_digest": self.evidence_digest,
                "execution_artifact_digest": self.execution_artifact_digest,
                "prior_reconciliation_artifact_digest": (
                    self.prior_reconciliation_artifact_digest
                ),
                "reconciliation_artifact_digest": self.reconciliation_artifact_digest,
                "reconciliation_record_digest": self.reconciliation_record_digest,
            },
            "reboot": {
                "handling_status": self.reboot_handling_status,
                "performed": False,
                "required": self.reboot_required,
                "required_count": self.reboot_required_count,
            },
            "schema_version": self.schema_version,
            "schemas": {
                "authorization": self.authorization_schema_version,
                "evidence": self.evidence_schema_version,
                "execution": self.execution_schema_version,
                "reconciliation": self.reconciliation_schema_version,
            },
            "states": {
                "authorization": self.authorization_state,
                "execution": self.execution_state,
                "final_evidence": self.final_evidence_state,
                "finalization": self.finalization_state,
                "public_workflow": self.public_workflow_state,
            },
            "steps": {
                "authorization_required_count": self.authorization_required_count,
                "blocked_count": self.blocked_count,
                "effective_plan_digest": self.effective_plan_digest,
                "eligible_count": self.eligible_count,
                "not_performed_count": self.not_performed_count,
                "succeeded_count": self.succeeded_count,
            },
        }


@dataclass(frozen=True, slots=True)
class _ReconciliationContext:
    authorization_context: _AuthorizationContext
    prior: StoredDeployPostFinalRoutesReconciliation
    authorization: StoredDeployNonJumpBaseOsAuthorization
    execution: StoredDeployNonJumpBaseOsExecution
    evidence: StoredDeployNonJumpBaseOsEvidence
    entries_by_sequence: Mapping[int, DeployNonJumpBaseOsEvidenceEntry]
    evidence_digest: str
    stable_ids: tuple[str, ...]
    hosts_by_id: Mapping[str, DeployNonJumpBaseOsHostEvidence]
    changed_count: int
    already_current_count: int
    reboot_required_count: int


def reconcile_deploy_non_jump_base_os_result(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployPostNonJumpBaseOsReconciliationReport:
    """Persist exact non-jump base-OS success and only its immediate next gate."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_artifacts(paths, operation_id)
    context = _load_context(paths, operation_id, lock=lock)
    metadata = context.authorization_context.final_routes.post.post.base.host.loaded.planning.base.deploy.metadata.record
    store = DeployPostNonJumpBaseOsReconciliationStore(paths, operation_id)
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
    steps = _build_steps(context)
    record = _build_record(context, steps=steps, created_at=created_at)
    if existing is not None and existing.record != record:
        raise StateConflictError(
            "post-non-jump-base-os reconciliation is immutable; use a new operation"
        )
    try:
        stored, state = store.write_locked(record, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "post-non-jump-base-os reconciliation persistence failed"
        ) from error
    return _build_report(stored, state=state)


def deploy_post_non_jump_base_os_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the sole canonical post-non-jump-base-OS companion path."""

    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "post-non-jump-base-os reconciliation path is not canonical"
        )
    return path


def deploy_post_non_jump_base_os_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    suffix = DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_FILENAME_SUFFIX
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
    host_context = authorization_context.final_routes.post.post.base.host
    planning = host_context.loaded.planning
    metadata = planning.base.deploy.metadata.record
    journal = planning.base.deploy.journal
    if (
        journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
    ):
        raise StateConflictError(
            "post-non-jump-base-os reconciliation requires unchanged VERIFY journal"
        )
    authorization_store = DeployNonJumpBaseOsAuthorizationStore(paths, operation_id)
    execution_store = DeployNonJumpBaseOsExecutionStore(paths, operation_id)
    evidence_store = DeployNonJumpBaseOsEvidenceStore(paths, operation_id)
    for path, label in (
        (authorization_store.path, "authorization"),
        (execution_store.path, "execution"),
        (evidence_store.path, "evidence"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                "post-non-jump-base-os reconciliation requires complete "
                f"non-jump base-os {label}"
            )
    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    scopes, roles = _derive_authorization_scopes(authorization_context)
    expected_authorization = _build_authorization(
        authorization_context,
        scopes=scopes,
        roles=roles,
        proof=authorization.record.proof,
        created_at=authorization.record.created_at,
    )
    if authorization.record != expected_authorization:
        raise StateConflictError(
            "post-non-jump-base-os reconciliation authorization drifted"
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
    (
        entries_by_sequence,
        evidence_digest,
        stable_ids,
        hosts_by_id,
        changed_count,
        already_current_count,
        reboot_required_count,
    ) = _validate_complete_execution(
        authorization_context,
        authorization,
        execution,
        evidence,
    )
    return _ReconciliationContext(
        authorization_context,
        authorization_context.reconciliation,
        authorization,
        execution,
        evidence,
        entries_by_sequence,
        evidence_digest,
        stable_ids,
        hosts_by_id,
        changed_count,
        already_current_count,
        reboot_required_count,
    )


def _validate_complete_execution(
    authorization_context: _AuthorizationContext,
    authorization: StoredDeployNonJumpBaseOsAuthorization,
    execution: StoredDeployNonJumpBaseOsExecution,
    evidence: StoredDeployNonJumpBaseOsEvidence,
) -> tuple[
    Mapping[int, DeployNonJumpBaseOsEvidenceEntry],
    str,
    tuple[str, ...],
    Mapping[str, DeployNonJumpBaseOsHostEvidence],
    int,
    int,
    int,
]:
    host_context = authorization_context.final_routes.post.post.base.host
    planning = host_context.loaded.planning
    deploy = planning.base.deploy
    trust = planning.base.trust
    readiness = planning.readiness
    journal = deploy.journal
    prior = authorization_context.reconciliation
    binding = execution.record.binding
    scopes = authorization.record.scopes
    stable_ids = tuple(sorted({item for scope in scopes for item in scope.target_ids}))
    if (
        not scopes
        or authorization.record.consumed
        or evidence.record.binding != binding
        or binding.cluster_uuid != deploy.metadata.record.cluster_uuid
        or binding.cluster_name != deploy.metadata.record.cluster_name
        or binding.operation_id != journal.record.operation_id
        or binding.operation != _OPERATION
        or binding.request_digest != journal.record.request_digest
        or binding.journal_generation != journal.record.generation
        or binding.journal_digest != journal.digest
        or binding.journal_status is not journal.record.status
        or binding.journal_phase is not journal.record.phase
        or binding.authorization_artifact_digest != authorization.artifact_digest
        or binding.authorization_digest != authorization.record.authorization_digest
        or binding.authorization_scope_digest
        != authorization.record.authorization_scope_digest
        or binding.authorization_proof_digest != authorization.record.proof.proof_digest
        or binding.final_routes_reconciliation_artifact_digest != prior.artifact_digest
        or binding.final_routes_reconciliation_record_digest
        != prior.record.record_digest
        or binding.final_routes_reconciled_plan_digest
        != prior.record.effective_plan_digest
        or binding.readiness_artifact_digest != readiness.artifact_digest
        or binding.readiness_record_digest != readiness.record.record_digest
        or binding.catalog_digest != host_context.loaded.catalog_digest
        or binding.source_version != host_context.loaded.source.version
        or binding.source_digest != host_context.loaded.source.digest
        or binding.toolchain_version != readiness.record.playbook_version
        or binding.toolchain_version != readiness.record.inventory_version
        or binding.executable_identity_digest
        != readiness.record.executable_identity_digest
        or binding.toolchain_evidence_digest
        != readiness.record.toolchain_evidence_digest
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
        or binding.scope_count != len(scopes)
        or binding.stable_id_count != len(stable_ids)
        or binding.stable_id_set_digest != _digest_object(list(stable_ids))
        or execution.record.state is not DeployNonJumpBaseOsExecutionState.SUCCEEDED
        or not execution.record.authorization_consumed
        or not execution.record.all_scopes_completed
        or execution.record.invocation_count != len(scopes)
        or len(execution.record.attempts) != len(scopes)
        or evidence.record.generation != len(scopes)
        or len(evidence.record.entries) != len(scopes)
    ):
        raise StateConflictError(
            "post-non-jump-base-os execution provenance is incomplete, "
            "uncertain, or stale"
        )
    inventory_hosts = {
        host.logical_id: host for host in deploy.inventory.record.inventory.hosts
    }
    pre_mutation_hosts = _pre_mutation_hosts(host_context)
    desired_filters = dict(deploy.metadata.record.desired_spec.image_filters)
    source_digest = _playbook_source_digest(host_context.loaded.source, _PLAYBOOK)
    definition = get_playbook(_PLAYBOOK)
    entries_by_sequence: dict[int, DeployNonJumpBaseOsEvidenceEntry] = {}
    hosts_by_id: dict[str, DeployNonJumpBaseOsHostEvidence] = {}
    all_hosts: list[DeployNonJumpBaseOsHostEvidence] = []
    scope_values: list[dict[str, object]] = []
    for index, (scope, attempt, entry) in enumerate(
        zip(
            scopes,
            execution.record.attempts,
            evidence.record.entries,
            strict=True,
        ),
        start=1,
    ):
        _validate_scope_identity(scope)
        image_architectures: set[str] = set()
        expected_hosts: list[tuple[PreMutationHostEvidence, str]] = []
        selected_filter = None
        for target in scope.target_ids:
            inventory_host = inventory_hosts.get(target)
            pre_mutation = pre_mutation_hosts.get(target)
            if inventory_host is None or pre_mutation is None:
                raise StateConflictError(
                    "post-non-jump-base-os target evidence is unavailable"
                )
            image_filter = desired_filters.get(inventory_host.role)
            if (
                inventory_host.role is HostRole.JUMP_HOST
                or pre_mutation.role is not inventory_host.role
                or pre_mutation.os_family != "Ubuntu"
                or pre_mutation.os_version is None
                or not pre_mutation.os_version.startswith("24.04")
                or pre_mutation.architecture not in _SAFE_GUEST_ARCHITECTURES
                or image_filter is None
                or image_filter.operating_system != "Ubuntu"
                or image_filter.operating_system_version != "24.04"
                or image_filter.version_match is not ImageVersionMatch.EXACT
                or (
                    scope.target_role != "all"
                    and inventory_host.role.value != scope.target_role
                )
            ):
                raise StateConflictError(
                    "post-non-jump-base-os target provenance drifted"
                )
            if selected_filter is not None and image_filter != selected_filter:
                raise StateConflictError(
                    "post-non-jump-base-os scope mixes image filters"
                )
            selected_filter = image_filter
            assert pre_mutation.architecture is not None
            image_architecture = _SAFE_GUEST_ARCHITECTURES[pre_mutation.architecture]
            image_architectures.add(image_architecture)
            expected_hosts.append((pre_mutation, image_architecture))
        if selected_filter is None or len(image_architectures) != 1:
            raise StateConflictError("post-non-jump-base-os scope mixes architectures")
        variables = base_os_variables(selected_filter, next(iter(image_architectures)))
        variables_digest = digest_bytes(serialize_json(variables))
        command_digest = ansible_command_intent_digest(
            definition,
            step_sequence=scope.sequence,
            limit=scope.target_ids,
            variables_digest=variables_digest,
            tags=(),
            check=False,
            diff=False,
            verbosity=0,
        )
        scope_digest = _digest_object(scope.to_object())
        if (
            attempt.attempt_index != index
            or attempt.step_sequence != scope.sequence
            or attempt.target_ids != scope.target_ids
            or attempt.target_digest != scope.target_digest
            or attempt.authorization_scope_digest != scope_digest
            or attempt.authorization_variables_digest != scope.variables_digest
            or attempt.authorization_command_digest != scope.command_digest
            or attempt.variables_digest != variables_digest
            or attempt.command_digest != command_digest
            or attempt.source_digest != source_digest
            or attempt.result_schema_version != BASE_OS_EVIDENCE_SCHEMA_VERSION
            or attempt.state is not DeployNonJumpBaseOsExecutionState.SUCCEEDED
            or not attempt.authorization_consumed
            or not attempt.invocation_may_have_occurred
            or attempt.exit_code != 0
            or attempt.result_digest is None
            or attempt.evidence_digest is None
            or attempt.manual_recovery_required
            or attempt.automatic_retry_allowed
            or entry.attempt_index != index
            or entry.step_sequence != scope.sequence
            or entry.target_count != len(scope.target_ids)
            or entry.target_set_digest != scope.target_digest
            or entry.variables_digest != variables_digest
            or entry.command_digest != command_digest
            or entry.source_digest != source_digest
            or entry.result_schema_version != BASE_OS_EVIDENCE_SCHEMA_VERSION
            or entry.result_digest != attempt.result_digest
            or entry.evidence_digest != attempt.evidence_digest
            or entry.evidence_digest != _entry_evidence_digest(entry)
            or tuple(host.logical_id for host in entry.hosts) != scope.target_ids
        ):
            raise StateConflictError(
                "post-non-jump-base-os execution or evidence conflicts"
            )
        for persisted, (pre_mutation, image_architecture) in zip(
            entry.hosts, expected_hosts, strict=True
        ):
            _validate_successful_host(
                persisted,
                pre_mutation,
                image_architecture=image_architecture,
            )
            if persisted.logical_id in hosts_by_id:
                raise StateConflictError(
                    "post-non-jump-base-os semantic evidence is duplicated"
                )
            hosts_by_id[persisted.logical_id] = persisted
        expected_status = _aggregate_status(entry.hosts)
        result_evidence = BaseOsEvidence(
            expected_status,
            tuple(_reconstruct_result_host(host) for host in entry.hosts),
        )
        if (
            entry.status is not expected_status
            or entry.result_digest != _base_os_result_digest(result_evidence)
            or scope.sequence in entries_by_sequence
        ):
            raise StateConflictError(
                "post-non-jump-base-os semantic evidence conflicts"
            )
        entries_by_sequence[scope.sequence] = entry
        all_hosts.extend(entry.hosts)
        scope_values.append(
            {
                "attempt_index": index,
                "authorization_command_digest": scope.command_digest,
                "authorization_scope_digest": scope_digest,
                "authorization_variables_digest": scope.variables_digest,
                "command_digest": command_digest,
                "source_digest": source_digest,
                "step_sequence": scope.sequence,
                "target_digest": scope.target_digest,
                "variables_digest": variables_digest,
            }
        )
    if (
        binding.execution_scope_digest != _digest_object(scope_values)
        or tuple(host.logical_id for host in all_hosts) != stable_ids
        or set(hosts_by_id) != set(stable_ids)
    ):
        raise StateConflictError("post-non-jump-base-os execution scope digest drifted")
    return (
        entries_by_sequence,
        _digest_object([entry.evidence_digest for entry in evidence.record.entries]),
        stable_ids,
        hosts_by_id,
        sum(host.changed for host in all_hosts),
        sum(host.status is BaseOsStatus.NO_CHANGE for host in all_hosts),
        sum(host.reboot_required for host in all_hosts),
    )


def _validate_scope_identity(scope: DeployNonJumpBaseOsAuthorizationScope) -> None:
    if (
        scope.mapping_sequence != _MAPPING_SEQUENCE
        or scope.playbook != _PLAYBOOK
        or scope.condition != _CONDITION
        or scope.classification is not OperationClassification.MUTATING
        or scope.target_role != "all"
        or not scope.target_ids
    ):
        raise StateConflictError("post-non-jump-base-os authorization scope conflicts")


def _pre_mutation_hosts(
    host_context: _HostReconciliationContext,
) -> Mapping[str, PreMutationHostEvidence]:
    result: dict[str, PreMutationHostEvidence] = {}
    for entry in host_context.evidence.record.entries:
        for host in entry.hosts:
            if host.logical_id in result:
                raise StateConflictError(
                    "post-non-jump-base-os pre-mutation evidence is duplicated"
                )
            result[host.logical_id] = host
    return result


def _validate_successful_host(
    host: DeployNonJumpBaseOsHostEvidence,
    pre_mutation: PreMutationHostEvidence,
    *,
    image_architecture: str,
) -> None:
    if (
        host.logical_id != pre_mutation.logical_id
        or host.os_family != "Ubuntu"
        or host.os_version != "24.04"
        or host.image_architecture != image_architecture
        or host.guest_architecture != pre_mutation.architecture
        or host.status not in _SUCCESS_STATUSES
        or not host.applied
        or host.prerequisite_policy_status != "satisfied"
        or host.timesync_service_status != "enabled-active"
    ):
        raise StateConflictError(
            "post-non-jump-base-os host success evidence conflicts"
        )


def _aggregate_status(
    hosts: tuple[DeployNonJumpBaseOsHostEvidence, ...],
) -> BaseOsStatus:
    if any(host.reboot_required for host in hosts):
        return BaseOsStatus.REBOOT_REQUIRED
    if any(host.changed for host in hosts):
        return BaseOsStatus.CHANGED
    return BaseOsStatus.NO_CHANGE


def _reconstruct_result_host(
    host: DeployNonJumpBaseOsHostEvidence,
) -> BaseOsHostEvidence:
    reason = {
        BaseOsStatus.NO_CHANGE: "already-current",
        BaseOsStatus.CHANGED: "applied",
        BaseOsStatus.REBOOT_REQUIRED: "reboot-required",
    }.get(host.status)
    if reason is None:
        raise StateConflictError("post-non-jump-base-os host result is not successful")
    return BaseOsHostEvidence(
        host.logical_id,
        host.status,
        host.changed,
        host.reboot_required,
        reason,
    )


def _build_steps(
    context: _ReconciliationContext,
) -> tuple[DeployBaseOsReconciledStep, ...]:
    prior_steps = context.prior.record.steps
    executed = context.entries_by_sequence
    if not executed:
        raise StateConflictError(
            "post-non-jump-base-os reconciliation has no completed scope"
        )
    remaining_mappings = tuple(
        sorted(
            {
                step.mapping_sequence
                for step in prior_steps
                if step.sequence not in executed
                and step.mapping_sequence > _MAPPING_SEQUENCE
                and step.mapping_sequence != _FINAL_EVIDENCE_MAPPING
                and step.condition_state is DeployConditionState.ACTIVE
                and step.status is not DeployBaseOsReconciledStepStatus.SUCCEEDED
            }
        )
    )
    next_mapping = remaining_mappings[0] if remaining_mappings else None
    reboot_required = context.reboot_required_count > 0
    result: list[DeployBaseOsReconciledStep] = []
    for prior in prior_steps:
        prior_digest = _digest_object(prior.to_object())
        if prior.sequence in executed:
            entry = executed[prior.sequence]
            if (
                prior.mapping_sequence != _MAPPING_SEQUENCE
                or prior.playbook != _PLAYBOOK
                or prior.condition != _CONDITION
                or prior.status
                is not DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
                or prior.target_ids != tuple(host.logical_id for host in entry.hosts)
            ):
                raise StateConflictError(
                    "post-non-jump-base-os executed step identity drifted"
                )
            result.append(
                replace(
                    prior,
                    prior_reconciled_step_digest=prior_digest,
                    status=DeployBaseOsReconciledStepStatus.SUCCEEDED,
                    evidence_state=(
                        DeployBaseOsReconciledEvidenceState.NON_JUMP_BASE_OS_BOUND
                    ),
                    evidence_digest=entry.evidence_digest,
                    blockers=(),
                )
            )
            continue
        if (
            prior.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
            or prior.condition_state is DeployConditionState.INACTIVE
        ):
            result.append(replace(prior, prior_reconciled_step_digest=prior_digest))
            continue
        if prior.mapping_sequence == _FINAL_EVIDENCE_MAPPING:
            result.append(
                replace(
                    prior,
                    prior_reconciled_step_digest=prior_digest,
                    status=DeployBaseOsReconciledStepStatus.NOT_PERFORMED,
                    evidence_state=DeployBaseOsReconciledEvidenceState.NOT_PERFORMED,
                    evidence_digest=None,
                    blockers=tuple(sorted({*prior.blockers, _ORDER_BLOCKER})),
                )
            )
            continue
        if reboot_required:
            result.append(
                replace(
                    prior,
                    prior_reconciled_step_digest=prior_digest,
                    status=DeployBaseOsReconciledStepStatus.BLOCKED,
                    evidence_state=DeployBaseOsReconciledEvidenceState.NOT_PERFORMED,
                    evidence_digest=None,
                    blockers=tuple(
                        sorted(
                            {
                                *prior.blockers,
                                _ORDER_BLOCKER,
                                _REBOOT_BLOCKER,
                                _REBOOT_HANDLING_BLOCKER,
                            }
                        )
                    ),
                )
            )
            continue
        if prior.mapping_sequence == next_mapping and _next_gate_ready(prior, context):
            status = (
                DeployBaseOsReconciledStepStatus.ELIGIBLE
                if prior.classification is OperationClassification.READ_ONLY
                else DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            )
            blockers = (
                ()
                if prior.classification is OperationClassification.READ_ONLY
                else tuple(
                    sorted(
                        {
                            _AUTHORIZATION_BLOCKER,
                            _CLASS_BLOCKERS[prior.classification],
                            _PUBLIC_WORKFLOW_BLOCKER,
                        }
                    )
                )
            )
            result.append(
                replace(
                    prior,
                    prior_reconciled_step_digest=prior_digest,
                    status=status,
                    evidence_state=(
                        DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED
                    ),
                    evidence_digest=_next_gate_digest(prior, context),
                    blockers=blockers,
                )
            )
            continue
        result.append(
            replace(
                prior,
                prior_reconciled_step_digest=prior_digest,
                status=(
                    DeployBaseOsReconciledStepStatus.NOT_PERFORMED
                    if prior.classification is OperationClassification.READ_ONLY
                    else DeployBaseOsReconciledStepStatus.BLOCKED
                ),
                evidence_state=DeployBaseOsReconciledEvidenceState.NOT_PERFORMED,
                evidence_digest=None,
                blockers=tuple(sorted({*prior.blockers, _ORDER_BLOCKER})),
            )
        )
    return tuple(result)


def _next_gate_ready(
    step: DeployBaseOsReconciledStep,
    context: _ReconciliationContext,
) -> bool:
    definition = get_playbook(step.playbook)
    planning = (
        context.authorization_context.final_routes.post.post.base.host.loaded.planning
    )
    inventory_hosts = {
        host.logical_id: host
        for host in planning.base.deploy.inventory.record.inventory.hosts
    }
    selected = tuple(inventory_hosts.get(target) for target in step.target_ids)
    if (
        not definition.source_available
        or not step.target_ids
        or any(host is None for host in selected)
        or not set(step.target_ids).issubset(context.stable_ids)
        or not set(step.variable_names) <= _CANONICAL_COMMON_VARIABLES
    ):
        return False
    for target, inventory_host in zip(step.target_ids, selected, strict=True):
        assert inventory_host is not None
        result = context.hosts_by_id.get(target)
        if (
            result is None
            or result.reboot_required
            or result.status not in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
            or not result.applied
            or result.prerequisite_policy_status != "satisfied"
            or result.timesync_service_status != "enabled-active"
            or (
                step.target_role != "all"
                and inventory_host.role.value != step.target_role
            )
        ):
            return False
    return True


def _next_gate_digest(
    step: DeployBaseOsReconciledStep,
    context: _ReconciliationContext,
) -> str:
    planning = (
        context.authorization_context.final_routes.post.post.base.host.loaded.planning
    )
    return _digest_object(
        {
            "ansible_source_digest": (
                context.authorization_context.final_routes.post.post.base.host.loaded.source.digest
            ),
            "catalog_digest": (
                context.authorization_context.final_routes.post.post.base.host.loaded.catalog_digest
            ),
            "evidence_artifact_digest": context.evidence.artifact_digest,
            "evidence_digest": context.evidence_digest,
            "inventory_artifact_digest": planning.base.deploy.inventory.digest,
            "inventory_digest": (
                planning.base.deploy.inventory.record.inventory_digest
            ),
            "playbook": step.playbook,
            "readiness_record_digest": planning.readiness.record.record_digest,
            "sequence": step.sequence,
            "target_digest": step.target_digest,
            "trust_artifact_digest": planning.base.trust.digest,
            "trust_entries_digest": planning.base.trust.record.entries_digest,
        }
    )


def _build_record(
    context: _ReconciliationContext,
    *,
    steps: tuple[DeployBaseOsReconciledStep, ...],
    created_at: str,
) -> DeployPostNonJumpBaseOsReconciliation:
    host_context = context.authorization_context.final_routes.post.post.base.host
    planning = host_context.loaded.planning
    deploy = planning.base.deploy
    journal = deploy.journal
    metadata = deploy.metadata.record
    counts = Counter(step.status for step in steps)
    blockers = {blocker for step in steps for blocker in step.blockers}
    if context.reboot_required_count:
        blockers.update({_REBOOT_BLOCKER, _REBOOT_HANDLING_BLOCKER})
    blocker_values = tuple(sorted(blockers))
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
        "post_final_routes_reconciliation_artifact_digest": context.prior.artifact_digest,
        "post_final_routes_reconciliation_record_digest": (
            context.prior.record.record_digest
        ),
        "post_final_routes_effective_plan_digest": (
            context.prior.record.effective_plan_digest
        ),
        "authorization_artifact_digest": context.authorization.artifact_digest,
        "authorization_digest": context.authorization.record.authorization_digest,
        "authorization_scope_digest": (
            context.authorization.record.authorization_scope_digest
        ),
        "execution_artifact_digest": context.execution.artifact_digest,
        "execution_binding_digest": context.execution.record.binding.binding_digest,
        "evidence_artifact_digest": context.evidence.artifact_digest,
        "evidence_digest": context.evidence_digest,
        "inventory_generation": deploy.inventory.record.generation,
        "inventory_artifact_digest": deploy.inventory.digest,
        "inventory_digest": deploy.inventory.record.inventory_digest,
        "trust_generation": planning.base.trust.record.generation,
        "trust_artifact_digest": planning.base.trust.digest,
        "trust_entries_digest": planning.base.trust.record.entries_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": planning.readiness.record.record_digest,
        "catalog_digest": host_context.loaded.catalog_digest,
        "ansible_source_version": host_context.loaded.source.version,
        "ansible_source_digest": host_context.loaded.source.digest,
        "base_os_scope_count": len(context.authorization.record.scopes),
        "base_os_host_count": len(context.stable_ids),
        "base_os_host_set_digest": _digest_object(list(context.stable_ids)),
        "changed_count": context.changed_count,
        "already_current_count": context.already_current_count,
        "reboot_required_count": context.reboot_required_count,
        "reboot_required": context.reboot_required_count > 0,
        "reboot_handling_status": _NOT_PERFORMED,
        "steps": steps,
        "mapping_count": len(OPERATION_PLAYBOOKS[_OPERATION]),
        "step_count": len(steps),
        "succeeded_count": counts[DeployBaseOsReconciledStepStatus.SUCCEEDED],
        "authorization_required_count": counts[
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        ],
        "eligible_count": counts[DeployBaseOsReconciledStepStatus.ELIGIBLE],
        "blocked_count": counts[DeployBaseOsReconciledStepStatus.BLOCKED],
        "not_performed_count": counts[DeployBaseOsReconciledStepStatus.NOT_PERFORMED],
        "blocker_set": blocker_values,
        "blocker_digest": _digest_object(list(blocker_values)),
        "effective_plan_digest": _digest_object([step.to_object() for step in steps]),
        "authorization_state": _AUTHORIZATION_CONSUMED,
        "execution_state": DeployNonJumpBaseOsExecutionState.SUCCEEDED.value,
        "next_execution_state": _NOT_STARTED,
        "final_evidence_state": _NOT_PERFORMED,
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(values)
    return DeployPostNonJumpBaseOsReconciliation(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployPostNonJumpBaseOsReconciliation,
    *,
    state: DeployPostNonJumpBaseOsArtifactState,
) -> DeployPostNonJumpBaseOsReconciliationReport:
    record = stored.record
    selected = tuple(
        step
        for step in record.steps
        if step.status
        in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
    )
    grouped: dict[
        tuple[
            str,
            str,
            OperationClassification,
            DeployBaseOsReconciledStepStatus,
        ],
        list[DeployBaseOsReconciledStep],
    ] = {}
    for step in selected:
        grouped.setdefault(
            (step.playbook, step.target_role, step.classification, step.status), []
        ).append(step)
    summaries: list[DeployPostNonJumpBaseOsNextStepSummary] = []
    for (playbook, role, classification, status), steps in sorted(
        grouped.items(),
        key=lambda item: (
            item[0][0],
            item[0][1],
            item[0][2].value,
            item[0][3].value,
        ),
    ):
        targets = tuple(
            sorted({target for step in steps for target in step.target_ids})
        )
        summaries.append(
            DeployPostNonJumpBaseOsNextStepSummary(
                playbook,
                role,
                classification,
                status,
                len(steps),
                len(targets),
                _digest_object(list(targets)),
                _digest_object(
                    [
                        {
                            "evidence_digest": step.evidence_digest,
                            "sequence": step.sequence,
                            "target_digest": step.target_digest,
                        }
                        for step in steps
                    ]
                ),
            )
        )
    targets = tuple(sorted({target for step in selected for target in step.target_ids}))
    return DeployPostNonJumpBaseOsReconciliationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        reconciliation_artifact_digest=stored.artifact_digest,
        reconciliation_record_digest=record.record_digest,
        effective_plan_digest=record.effective_plan_digest,
        prior_reconciliation_artifact_digest=(
            record.post_final_routes_reconciliation_artifact_digest
        ),
        authorization_artifact_digest=record.authorization_artifact_digest,
        execution_artifact_digest=record.execution_artifact_digest,
        evidence_artifact_digest=record.evidence_artifact_digest,
        evidence_digest=record.evidence_digest,
        base_os_scope_count=record.base_os_scope_count,
        base_os_host_count=record.base_os_host_count,
        base_os_host_set_digest=record.base_os_host_set_digest,
        changed_count=record.changed_count,
        already_current_count=record.already_current_count,
        reboot_required_count=record.reboot_required_count,
        reboot_required=record.reboot_required,
        reboot_handling_status=record.reboot_handling_status,
        succeeded_count=record.succeeded_count,
        authorization_required_count=record.authorization_required_count,
        eligible_count=record.eligible_count,
        blocked_count=record.blocked_count,
        not_performed_count=record.not_performed_count,
        next_steps=tuple(summaries),
        next_step_count=len(selected),
        next_target_count=len(targets),
        next_target_set_digest=_digest_object(list(targets)),
        blocker_set=record.blocker_set,
        blocker_digest=record.blocker_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        authorization_state=record.authorization_state,
        execution_state=record.execution_state,
        next_execution_state=record.next_execution_state,
        final_evidence_state=record.final_evidence_state,
        finalization_state=record.finalization_state,
        public_workflow_state=record.public_workflow_state,
    )


def _record_digests(
    record: DeployPostNonJumpBaseOsReconciliation,
) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(record, name))
        for name in record.__dataclass_fields__
        if name.endswith("_digest")
    )


def _record_digest(record: DeployPostNonJumpBaseOsReconciliation) -> str:
    value = record.to_object()
    value["record_digest"] = ""
    return _digest_object(value)


def _record_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployPostNonJumpBaseOsReconciliation.__dataclass_fields__.items():
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


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "post-non-jump-base-os reconciliation paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "post-non-jump-base-os reconciliation requires acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list post-non-jump-base-os reconciliation artifacts"
        ) from error
    suffix = DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_FILENAME_SUFFIX
    canonical = str(operation_id)
    for entry in entries:
        if not entry.name.endswith(suffix):
            continue
        prefix = entry.name[: -len(suffix)]
        try:
            parsed = uuid.UUID(prefix)
        except ValueError:
            parsed = None
        if prefix != canonical and (
            parsed is None or parsed == operation_id or canonical in prefix
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "post-non-jump-base-os reconciliation artifacts are ambiguous"
            )


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _nonnegative_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StatePersistenceError(f"{label} must be nonnegative")


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be a boolean")
    return value


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


def _enum(enum_type: type[StrEnum], value: str, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except ValueError as error:
        raise StatePersistenceError(
            f"post-non-jump-base-os reconciliation {label} is invalid"
        ) from error


__all__ = [
    "ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_SCHEMA_VERSION",
    "DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_FILENAME_SUFFIX",
    "DeployPostNonJumpBaseOsArtifactState",
    "DeployPostNonJumpBaseOsNextStepSummary",
    "DeployPostNonJumpBaseOsReconciliation",
    "DeployPostNonJumpBaseOsReconciliationReport",
    "DeployPostNonJumpBaseOsReconciliationStore",
    "StoredDeployPostNonJumpBaseOsReconciliation",
    "deploy_post_non_jump_base_os_reconciliation_id_from_filename",
    "deploy_post_non_jump_base_os_reconciliation_path",
    "reconcile_deploy_non_jump_base_os_result",
]
