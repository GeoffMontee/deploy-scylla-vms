"""Immutable deploy-plan reconciliation after non-jump reboot handling.

This internal owner accepts only canonical operation identity and the matching
already-held deploy lock. It proves either that the distinct non-jump reboot
scope was not required or that its exact ordered execution completed with
strict semantic evidence, then persists one new effective-plan companion.
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

from scylla_vms.ansible.base_os import BaseOsStatus
from scylla_vms.ansible.commands import (
    ansible_command_intent_digest,
    validate_playbook_request_policy,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStep,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_non_jump_base_os_reconciliation import (
    ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_SCHEMA_VERSION,
    DeployPostNonJumpBaseOsNextStepSummary,
    DeployPostNonJumpBaseOsReconciliationStore,
    StoredDeployPostNonJumpBaseOsReconciliation,
    _ReconciliationContext,
)
from scylla_vms.ansible.deploy_non_jump_base_os_reconciliation import (
    _build_record as _build_non_jump_reconciliation,
)
from scylla_vms.ansible.deploy_non_jump_base_os_reconciliation import (
    _build_steps as _build_non_jump_steps,
)
from scylla_vms.ansible.deploy_non_jump_base_os_reconciliation import (
    _load_context as _load_non_jump_context,
)
from scylla_vms.ansible.deploy_non_jump_reboot_authorization import (
    ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_NON_JUMP_REBOOT_PLAN_SCHEMA_VERSION,
    DeployNonJumpRebootAuthorizationStore,
    DeployNonJumpRebootPlanStore,
    DeployNonJumpRebootPlanTarget,
    StoredDeployNonJumpRebootAuthorization,
    StoredDeployNonJumpRebootPlan,
    _build_authorization,
    _build_plan,
    _build_targets,
    _derive_candidates,
    deploy_non_jump_reboot_authorization_path,
    deploy_non_jump_reboot_plan_path,
)
from scylla_vms.ansible.deploy_non_jump_reboot_execution import (
    ANSIBLE_DEPLOY_NON_JUMP_REBOOT_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_NON_JUMP_REBOOT_EXECUTION_SCHEMA_VERSION,
    DeployNonJumpRebootEvidenceEntry,
    DeployNonJumpRebootEvidenceStore,
    DeployNonJumpRebootExecutionAttempt,
    DeployNonJumpRebootExecutionBinding,
    DeployNonJumpRebootExecutionState,
    DeployNonJumpRebootExecutionStore,
    StoredDeployNonJumpRebootEvidence,
    StoredDeployNonJumpRebootExecution,
    _binding_digest_from_values,
    deploy_non_jump_reboot_evidence_path,
    deploy_non_jump_reboot_execution_path,
)
from scylla_vms.ansible.deploy_plan import (
    DeployConditionState,
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_reboot import (
    DEPLOY_REBOOT_RESULT_SCHEMA_VERSION,
    DeployRebootResult,
    DeployRebootResultStatus,
    deploy_reboot_variables,
)
from scylla_vms.ansible.operation_binding import readiness_binding_digest
from scylla_vms.ansible.registry import OPERATION_PLAYBOOKS, get_playbook
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION
from scylla_vms.ansible.trust import TrustStore
from scylla_vms.errors import (
    AnsibleError,
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
    _reconstructed_readiness,
)

ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-non-jump-reboot-reconciliation/v1"
)
ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-non-jump-reboot-reconciliation-report/v1"
)
DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-post-non-jump-reboot-reconciliation.json"
)

_OPERATION = "deploy"
_REBOOT_PLAYBOOK = "deploy-reboot"
_FINAL_EVIDENCE_MAPPING = len(OPERATION_PLAYBOOKS[_OPERATION])
_NOT_REQUIRED = "not-required"
_SUCCEEDED = "succeeded"
_REBOOT_EVIDENCE_BOUND = "non-jump-reboot-evidence-bound"
_NOT_STARTED = "not-started"
_NOT_PERFORMED = "not-performed"
_UNAVAILABLE = "unavailable"
_ORDER_BLOCKER = "ordered-deploy-step-not-reached"
_AUTHORIZATION_BLOCKER = "deploy-authorization-not-collected"
_PUBLIC_WORKFLOW_BLOCKER = "public-deploy-workflow-unavailable"
_CLASS_BLOCKERS = {
    OperationClassification.MUTATING: "mutating-deploy-execution-unavailable",
    OperationClassification.SENSITIVE: "sensitive-deploy-execution-unavailable",
    OperationClassification.DESTRUCTIVE: "destructive-deploy-execution-unavailable",
}
_REBOOT_BLOCKERS = frozenset({"reboot-required", "reboot-handling-not-performed"})
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


class DeployPostNonJumpRebootBranch(StrEnum):
    """Truthful non-jump reboot branch."""

    NO_REBOOT_REQUIRED = "no-reboot-required"
    REBOOT_REQUIRED = "reboot-required"


class DeployPostNonJumpRebootArtifactState(StrEnum):
    """Persistence outcome for the immutable companion."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployPostNonJumpRebootReconciliation:
    """Immutable effective deploy view after non-jump reboot handling."""

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
    prior_reconciliation_artifact_digest: str
    prior_reconciliation_record_digest: str
    prior_effective_plan_digest: str
    reboot_plan_artifact_digest: str | None
    reboot_plan_record_digest: str | None
    reboot_authorization_artifact_digest: str | None
    reboot_authorization_digest: str | None
    reboot_execution_artifact_digest: str | None
    reboot_execution_binding_digest: str | None
    reboot_evidence_artifact_digest: str | None
    reboot_evidence_digest: str | None
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
    branch: DeployPostNonJumpRebootBranch
    reboot_handling_status: str
    reboot_evidence_state: str
    reboot_authorization_consumed: bool
    reboot_execution_state: str
    reboot_target_count: int
    reboot_succeeded_count: int
    reboot_target_set_digest: str | None
    reboot_target_order_digest: str | None
    reconnect_count: int
    boot_changed_count: int
    identity_verified_count: int
    trust_revalidated_count: int
    machine_evidence_verified_count: int
    service_safety_count: int
    reboot_clear_count: int
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
    next_execution_state: str
    final_evidence_state: str
    finalization_state: str
    public_workflow_state: str
    record_digest: str
    prior_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_SCHEMA_VERSION
    )
    reboot_plan_schema_version: str = ANSIBLE_DEPLOY_NON_JUMP_REBOOT_PLAN_SCHEMA_VERSION
    reboot_authorization_schema_version: str = (
        ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_SCHEMA_VERSION
    )
    reboot_execution_schema_version: str = (
        ANSIBLE_DEPLOY_NON_JUMP_REBOOT_EXECUTION_SCHEMA_VERSION
    )
    reboot_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_NON_JUMP_REBOOT_EVIDENCE_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_SCHEMA_VERSION
            or self.prior_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_SCHEMA_VERSION
            or self.reboot_plan_schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_REBOOT_PLAN_SCHEMA_VERSION
            or self.reboot_authorization_schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_SCHEMA_VERSION
            or self.reboot_execution_schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_REBOOT_EXECUTION_SCHEMA_VERSION
            or self.reboot_evidence_schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_REBOOT_EVIDENCE_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.next_execution_state != _NOT_STARTED
            or self.final_evidence_state != _NOT_PERFORMED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
            or not isinstance(self.branch, DeployPostNonJumpRebootBranch)
        ):
            raise StatePersistenceError(
                "post-non-jump-reboot reconciliation identity is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for value in (
            self.journal_generation,
            self.inventory_generation,
            self.trust_generation,
            self.reboot_target_count,
            self.reboot_succeeded_count,
            self.reconnect_count,
            self.boot_changed_count,
            self.identity_verified_count,
            self.trust_revalidated_count,
            self.machine_evidence_verified_count,
            self.service_safety_count,
            self.reboot_clear_count,
            self.mapping_count,
            self.step_count,
            self.succeeded_count,
            self.authorization_required_count,
            self.eligible_count,
            self.blocked_count,
            self.not_performed_count,
        ):
            _nonnegative_integer(value, "post-non-jump-reboot count")
        if (
            self.journal_generation < 1
            or self.inventory_generation < 1
            or self.trust_generation < 1
            or self.mapping_count != len(OPERATION_PLAYBOOKS[_OPERATION])
            or self.step_count != len(self.steps)
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, len(self.steps) + 1))
        ):
            raise StatePersistenceError(
                "post-non-jump-reboot reconciliation counts conflict"
            )
        expected_mapping = OPERATION_PLAYBOOKS[_OPERATION]
        if {step.mapping_sequence for step in self.steps} != set(
            range(1, len(expected_mapping) + 1)
        ) or any(
            step.playbook != expected_mapping[step.mapping_sequence - 1].playbook
            or step.condition != expected_mapping[step.mapping_sequence - 1].condition
            for step in self.steps
        ):
            raise StatePersistenceError("post-non-jump-reboot deploy mapping conflicts")
        counts = Counter(step.status for step in self.steps)
        blockers = tuple(
            sorted({blocker for step in self.steps for blocker in step.blockers})
        )
        if (
            self.succeeded_count != counts[DeployBaseOsReconciledStepStatus.SUCCEEDED]
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
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blocker_set)
            or self.blocker_digest != _digest_object(list(self.blocker_set))
            or self.effective_plan_digest
            != _digest_object([step.to_object() for step in self.steps])
        ):
            raise StatePersistenceError(
                "post-non-jump-reboot reconciliation summary conflicts"
            )
        self._validate_branch()
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if name.endswith("_digest") and value is not None:
                validate_digest(value, "post-non-jump-reboot reconciliation digest")
        if self.record_digest != _record_digest(self):
            raise StatePersistenceError(
                "post-non-jump-reboot reconciliation record digest conflicts"
            )

    def _validate_branch(self) -> None:
        optional = (
            self.reboot_plan_artifact_digest,
            self.reboot_plan_record_digest,
            self.reboot_authorization_artifact_digest,
            self.reboot_authorization_digest,
            self.reboot_execution_artifact_digest,
            self.reboot_execution_binding_digest,
            self.reboot_evidence_artifact_digest,
            self.reboot_evidence_digest,
            self.reboot_target_set_digest,
            self.reboot_target_order_digest,
        )
        gates = (
            self.reconnect_count,
            self.boot_changed_count,
            self.identity_verified_count,
            self.trust_revalidated_count,
            self.machine_evidence_verified_count,
            self.service_safety_count,
            self.reboot_clear_count,
        )
        if self.branch is DeployPostNonJumpRebootBranch.NO_REBOOT_REQUIRED:
            if (
                self.reboot_handling_status != _NOT_REQUIRED
                or self.reboot_evidence_state != _NOT_REQUIRED
                or self.reboot_execution_state != _NOT_REQUIRED
                or self.reboot_authorization_consumed
                or self.reboot_target_count
                or self.reboot_succeeded_count
                or any(gates)
                or any(value is not None for value in optional)
                or any(blocker in self.blocker_set for blocker in _REBOOT_BLOCKERS)
            ):
                raise StatePersistenceError(
                    "post-non-jump-reboot not-required branch conflicts"
                )
            return
        if (
            self.reboot_handling_status != _SUCCEEDED
            or self.reboot_evidence_state != _REBOOT_EVIDENCE_BOUND
            or self.reboot_execution_state
            != DeployNonJumpRebootExecutionState.SUCCEEDED.value
            or not self.reboot_authorization_consumed
            or self.reboot_target_count < 1
            or self.reboot_succeeded_count != self.reboot_target_count
            or any(count != self.reboot_target_count for count in gates)
            or any(value is None for value in optional)
            or any(blocker in self.blocker_set for blocker in _REBOOT_BLOCKERS)
        ):
            raise StatePersistenceError(
                "post-non-jump-reboot completed branch conflicts"
            )

    def to_object(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            result[name] = (
                str(value)
                if isinstance(value, uuid.UUID)
                else value.value
                if isinstance(value, (JournalStatus, OperationPhase, StrEnum))
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
    ) -> DeployPostNonJumpRebootReconciliation:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "post-non-jump-reboot reconciliation",
        )
        integers = {
            "generation",
            "journal_generation",
            "inventory_generation",
            "trust_generation",
            "reboot_target_count",
            "reboot_succeeded_count",
            "reconnect_count",
            "boot_changed_count",
            "identity_verified_count",
            "trust_revalidated_count",
            "machine_evidence_verified_count",
            "service_safety_count",
            "reboot_clear_count",
            "mapping_count",
            "step_count",
            "succeeded_count",
            "authorization_required_count",
            "eligible_count",
            "blocked_count",
            "not_performed_count",
        }
        optional = {
            "reboot_plan_artifact_digest",
            "reboot_plan_record_digest",
            "reboot_authorization_artifact_digest",
            "reboot_authorization_digest",
            "reboot_execution_artifact_digest",
            "reboot_execution_binding_digest",
            "reboot_evidence_artifact_digest",
            "reboot_evidence_digest",
            "reboot_target_set_digest",
            "reboot_target_order_digest",
        }
        parsed: dict[str, object] = {}
        for name in cls.__dataclass_fields__:
            item = value[name]
            if name in integers:
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
            elif name == "branch":
                parsed[name] = _enum(
                    DeployPostNonJumpRebootBranch,
                    require_string(value, name),
                    "post-non-jump-reboot branch",
                )
            elif name == "reboot_authorization_consumed":
                parsed[name] = _boolean(item, name)
            elif name == "steps":
                parsed[name] = tuple(
                    DeployBaseOsReconciledStep.from_object(
                        _mapping(step, "post-non-jump-reboot reconciled step")
                    )
                    for step in _array(item, "post-non-jump-reboot reconciled steps")
                )
            elif name == "blocker_set":
                parsed[name] = _string_tuple(item, name)
            elif name in optional:
                parsed[name] = _optional_string(item, name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployPostNonJumpRebootReconciliation:
    record: DeployPostNonJumpRebootReconciliation
    artifact_digest: str


class DeployPostNonJumpRebootReconciliationStore:
    """Owner-only immutable post-non-jump-reboot companion."""

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
        self._path = deploy_post_non_jump_reboot_reconciliation_path(
            paths, operation_id
        )
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployPostNonJumpRebootReconciliation:
        value, artifact_digest = self._file.read()
        record = DeployPostNonJumpRebootReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "post-non-jump-reboot reconciliation identity conflicts"
            )
        return StoredDeployPostNonJumpRebootReconciliation(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPostNonJumpRebootReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployPostNonJumpRebootReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployPostNonJumpRebootReconciliation,
        DeployPostNonJumpRebootArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "post-non-jump-reboot reconciliation operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "post-non-jump-reboot reconciliation is immutable"
                )
            return current, DeployPostNonJumpRebootArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployPostNonJumpRebootReconciliation(record, artifact_digest),
            DeployPostNonJumpRebootArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployPostNonJumpRebootReconciliationReport:
    """Strict address-free post-non-jump-reboot projection."""

    operation_id: uuid.UUID
    artifact_state: DeployPostNonJumpRebootArtifactState
    reconciliation_artifact_digest: str
    reconciliation_record_digest: str
    effective_plan_digest: str
    branch: DeployPostNonJumpRebootBranch
    reboot_handling_status: str
    reboot_evidence_state: str
    reboot_target_count: int
    reboot_succeeded_count: int
    reboot_target_set_digest: str | None
    reboot_target_order_digest: str | None
    reconnect_count: int
    boot_changed_count: int
    identity_verified_count: int
    trust_revalidated_count: int
    machine_evidence_verified_count: int
    service_safety_count: int
    reboot_clear_count: int
    next_steps: tuple[DeployPostNonJumpBaseOsNextStepSummary, ...]
    next_step_count: int
    next_target_count: int
    next_target_set_digest: str
    blocker_set: tuple[str, ...]
    blocker_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    next_execution_state: str
    finalization_state: str
    public_workflow_state: str
    reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_REPORT_SCHEMA_VERSION
            or self.reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_SCHEMA_VERSION
            or not isinstance(self.operation_id, uuid.UUID)
            or not isinstance(self.branch, DeployPostNonJumpRebootBranch)
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.next_execution_state != _NOT_STARTED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
            or self.next_step_count
            != sum(item.instance_count for item in self.next_steps)
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blocker_set)
            or self.blocker_digest != _digest_object(list(self.blocker_set))
        ):
            raise StatePersistenceError(
                "post-non-jump-reboot reconciliation report is invalid"
            )
        for count_value in (
            self.reboot_target_count,
            self.reboot_succeeded_count,
            self.reconnect_count,
            self.boot_changed_count,
            self.identity_verified_count,
            self.trust_revalidated_count,
            self.machine_evidence_verified_count,
            self.service_safety_count,
            self.reboot_clear_count,
            self.next_step_count,
            self.next_target_count,
        ):
            _nonnegative_integer(count_value, "post-non-jump-reboot report count")
        for digest_value in (
            self.reconciliation_artifact_digest,
            self.reconciliation_record_digest,
            self.effective_plan_digest,
            self.next_target_set_digest,
            self.blocker_digest,
        ):
            validate_digest(digest_value, "post-non-jump-reboot report digest")
        for optional_digest in (
            self.reboot_target_set_digest,
            self.reboot_target_order_digest,
        ):
            if optional_digest is not None:
                validate_digest(
                    optional_digest, "post-non-jump-reboot report optional digest"
                )
        gates = (
            self.reconnect_count,
            self.boot_changed_count,
            self.identity_verified_count,
            self.trust_revalidated_count,
            self.machine_evidence_verified_count,
            self.service_safety_count,
            self.reboot_clear_count,
        )
        if self.branch is DeployPostNonJumpRebootBranch.NO_REBOOT_REQUIRED:
            if (
                self.reboot_handling_status != _NOT_REQUIRED
                or self.reboot_evidence_state != _NOT_REQUIRED
                or self.reboot_target_count
                or self.reboot_succeeded_count
                or any(gates)
                or self.reboot_target_set_digest is not None
                or self.reboot_target_order_digest is not None
            ):
                raise StatePersistenceError(
                    "post-non-jump-reboot not-required report conflicts"
                )
        elif (
            self.reboot_handling_status != _SUCCEEDED
            or self.reboot_evidence_state != _REBOOT_EVIDENCE_BOUND
            or self.reboot_target_count < 1
            or self.reboot_succeeded_count != self.reboot_target_count
            or any(count != self.reboot_target_count for count in gates)
            or self.reboot_target_set_digest is None
            or self.reboot_target_order_digest is None
        ):
            raise StatePersistenceError(
                "post-non-jump-reboot completed report conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "artifact_state": self.artifact_state.value,
            "blockers": {
                "digest": self.blocker_digest,
                "values": list(self.blocker_set),
            },
            "branch": self.branch.value,
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
                "effective_plan_digest": self.effective_plan_digest,
                "reconciliation_artifact_digest": self.reconciliation_artifact_digest,
                "reconciliation_record_digest": self.reconciliation_record_digest,
            },
            "reboot": {
                "boot_changed_count": self.boot_changed_count,
                "evidence_state": self.reboot_evidence_state,
                "handling_status": self.reboot_handling_status,
                "identity_verified_count": self.identity_verified_count,
                "machine_evidence_verified_count": (
                    self.machine_evidence_verified_count
                ),
                "reboot_clear_count": self.reboot_clear_count,
                "reconnect_count": self.reconnect_count,
                "service_safety_count": self.service_safety_count,
                "succeeded_count": self.reboot_succeeded_count,
                "target_count": self.reboot_target_count,
                "target_order_digest": self.reboot_target_order_digest,
                "target_set_digest": self.reboot_target_set_digest,
                "trust_revalidated_count": self.trust_revalidated_count,
            },
            "schema_version": self.schema_version,
            "schemas": {"reconciliation": self.reconciliation_schema_version},
            "states": {
                "finalization": self.finalization_state,
                "public_workflow": self.public_workflow_state,
            },
        }


@dataclass(frozen=True, slots=True)
class _RebootScope:
    target: DeployNonJumpRebootPlanTarget
    variables_digest: str
    command_digest: str
    source_digest: str
    request_digest: str
    target_plan_digest: str


@dataclass(frozen=True, slots=True)
class _PostNonJumpRebootContext:
    chain: _ReconciliationContext
    prior: StoredDeployPostNonJumpBaseOsReconciliation
    branch: DeployPostNonJumpRebootBranch
    plan: StoredDeployNonJumpRebootPlan | None
    authorization: StoredDeployNonJumpRebootAuthorization | None
    execution: StoredDeployNonJumpRebootExecution | None
    evidence: StoredDeployNonJumpRebootEvidence | None
    reboot_entries: tuple[DeployNonJumpRebootEvidenceEntry, ...]
    reboot_evidence_digest: str | None


def reconcile_deploy_post_non_jump_reboot_plan(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployPostNonJumpRebootReconciliationReport:
    """Persist the exact effective plan after distinct non-jump reboot handling."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_artifacts(paths, operation_id)
    context = _load_context(paths, operation_id, lock=lock)
    planning = context.chain.authorization_context.final_routes.post.post.base.host.loaded.planning
    metadata = planning.base.deploy.metadata.record
    store = DeployPostNonJumpRebootReconciliationStore(paths, operation_id)
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
            "post-non-jump-reboot reconciliation is immutable; use a new operation"
        )
    try:
        stored, state = store.write_locked(record, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "post-non-jump-reboot reconciliation persistence failed"
        ) from error
    return _build_report(stored, state=state)


def deploy_post_non_jump_reboot_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the sole canonical post-non-jump-reboot companion path."""

    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "post-non-jump-reboot reconciliation path is not canonical"
        )
    return path


def deploy_post_non_jump_reboot_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    suffix = DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_FILENAME_SUFFIX
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
) -> _PostNonJumpRebootContext:
    chain = _load_non_jump_context(paths, operation_id, lock=lock)
    planning = (
        chain.authorization_context.final_routes.post.post.base.host.loaded.planning
    )
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    journal = deploy.journal
    if (
        journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
    ):
        raise StateConflictError(
            "post-non-jump-reboot reconciliation requires unchanged VERIFY journal"
        )
    prior_store = DeployPostNonJumpBaseOsReconciliationStore(paths, operation_id)
    validate_state_file(prior_store.path, allow_missing=True)
    if not prior_store.path.exists():
        raise StateConflictError(
            "post-non-jump-reboot reconciliation requires non-jump base reconciliation"
        )
    prior = prior_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_prior = _build_non_jump_reconciliation(
        chain,
        steps=_build_non_jump_steps(chain),
        created_at=prior.record.created_at,
    )
    if prior.record != expected_prior:
        raise StateConflictError(
            "post-non-jump-reboot prior reconciliation changed or drifted"
        )
    _validate_current_runtime(paths, chain)
    candidates = _derive_candidates(chain, prior)
    reboot_paths = (
        deploy_non_jump_reboot_plan_path(paths, operation_id),
        deploy_non_jump_reboot_authorization_path(paths, operation_id),
        deploy_non_jump_reboot_execution_path(paths, operation_id),
        deploy_non_jump_reboot_evidence_path(paths, operation_id),
    )
    for path in reboot_paths:
        validate_state_file(path, allow_missing=True)
    if not candidates:
        if prior.record.reboot_required or prior.record.reboot_required_count:
            raise StateConflictError(
                "post-non-jump-reboot no-reboot evidence conflicts"
            )
        if any(path.exists() for path in reboot_paths):
            raise StateConflictError(
                "post-non-jump-reboot artifacts conflict with not-required branch"
            )
        return _PostNonJumpRebootContext(
            chain,
            prior,
            DeployPostNonJumpRebootBranch.NO_REBOOT_REQUIRED,
            None,
            None,
            None,
            None,
            (),
            None,
        )
    if not all(path.exists() for path in reboot_paths):
        raise StateConflictError(
            "post-non-jump-reboot reconciliation requires complete reboot chain"
        )
    return _load_required_reboot_context(
        paths, operation_id, chain=chain, prior=prior, lock=lock
    )


def _validate_current_runtime(paths: StatePaths, chain: _ReconciliationContext) -> None:
    planning = (
        chain.authorization_context.final_routes.post.post.base.host.loaded.planning
    )
    readiness_record = planning.readiness.record
    readiness = _reconstructed_readiness(planning.base)
    if (
        readiness_binding_digest(readiness) != readiness_record.readiness_digest
        or readiness_record.playbook_version != readiness_record.inventory_version
        or readiness_record.remote_playbook_status != _NOT_PERFORMED
    ):
        raise StateConflictError(
            "post-non-jump-reboot inventory, trust, or readiness evidence is stale"
        )
    readiness.require_ready(OperationClassification.MUTATING)
    TrustStore(paths).validate_runtime(
        planning.base.trust, planning.base.deploy.inventory
    )


def _load_required_reboot_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    chain: _ReconciliationContext,
    prior: StoredDeployPostNonJumpBaseOsReconciliation,
    lock: ClusterLock,
) -> _PostNonJumpRebootContext:
    host_context = chain.authorization_context.final_routes.post.post.base.host
    planning = host_context.loaded.planning
    metadata = planning.base.deploy.metadata.record
    plan = DeployNonJumpRebootPlanStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    candidates = _derive_candidates(chain, prior)
    targets, blockers = _build_targets(chain, candidates)
    expected_plan = _build_plan(
        chain,
        prior,
        targets=targets,
        blockers=blockers,
        created_at=plan.record.created_at,
    )
    if (
        plan.record != expected_plan
        or blockers
        or plan.record.blocker_set
        or plan.record.target_count != prior.record.reboot_required_count
    ):
        raise StateConflictError(
            "post-non-jump-reboot plan is blocked, stale, reordered, or mismatched"
        )
    authorization = DeployNonJumpRebootAuthorizationStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_authorization = _build_authorization(
        plan,
        proof=authorization.record.proof,
        created_at=authorization.record.created_at,
    )
    if (
        authorization.record != expected_authorization
        or authorization.record.consumed
        or authorization.record.authorization_state != "authorized-pre-execution"
    ):
        raise StateConflictError(
            "post-non-jump-reboot authorization is stale or mismatched"
        )
    scopes, binding = _rebuild_execution_binding(chain, prior, plan, authorization)
    execution = DeployNonJumpRebootExecutionStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    evidence = DeployNonJumpRebootEvidenceStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    entries = _validate_complete_reboot(
        scopes, binding, execution=execution, evidence=evidence
    )
    if (
        binding.catalog_digest != host_context.loaded.catalog_digest
        or binding.source_version != host_context.loaded.source.version
        or binding.source_digest != host_context.loaded.source.digest
    ):
        raise StateConflictError("post-non-jump-reboot source or catalog drifted")
    return _PostNonJumpRebootContext(
        chain,
        prior,
        DeployPostNonJumpRebootBranch.REBOOT_REQUIRED,
        plan,
        authorization,
        execution,
        evidence,
        entries,
        _digest_object([entry.evidence_digest for entry in entries]),
    )


def _rebuild_execution_binding(
    chain: _ReconciliationContext,
    prior: StoredDeployPostNonJumpBaseOsReconciliation,
    plan: StoredDeployNonJumpRebootPlan,
    authorization: StoredDeployNonJumpRebootAuthorization,
) -> tuple[tuple[_RebootScope, ...], DeployNonJumpRebootExecutionBinding]:
    host_context = chain.authorization_context.final_routes.post.post.base.host
    loaded = host_context.loaded
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    journal = deploy.journal
    readiness = planning.readiness.record
    source_digest = _playbook_source_digest(loaded.source, _REBOOT_PLAYBOOK)
    definition = get_playbook(_REBOOT_PLAYBOOK)
    inventory_hosts = {
        host.logical_id: host for host in deploy.inventory.record.inventory.hosts
    }
    scopes: list[_RebootScope] = []
    try:
        for target in plan.record.targets:
            host = chain.hosts_by_id.get(target.stable_id)
            inventory_host = inventory_hosts.get(target.stable_id)
            entry = chain.entries_by_sequence.get(target.base_os_step_sequence)
            if (
                host is None
                or entry is None
                or target.base_os_target_index > len(entry.hosts)
                or entry.hosts[target.base_os_target_index - 1] != host
                or entry.attempt_index != target.base_os_attempt_index
                or entry.evidence_digest != target.base_os_evidence_digest
                or entry.result_digest != target.base_os_result_digest
                or inventory_host is None
                or inventory_host.role is not target.role
                or not host.reboot_required
                or host.status is not BaseOsStatus.REBOOT_REQUIRED
                or not host.applied
                or host.os_family != "Ubuntu"
                or host.os_version != "24.04"
                or host.guest_architecture not in {"x86_64", "aarch64"}
                or host.prerequisite_policy_status != "satisfied"
                or host.timesync_service_status != "enabled-active"
            ):
                raise StateConflictError(
                    "post-non-jump-reboot target identity or base evidence drifted"
                )
            target_plan_digest = _digest_object(target.to_object())
            request_digest = _digest_object(
                {
                    "authorization_digest": authorization.record.authorization_digest,
                    "base_os_evidence_digest": target.base_os_evidence_digest,
                    "base_os_result_digest": target.base_os_result_digest,
                    "final_routes_evidence_digest": (
                        target.final_routes_evidence_digest
                    ),
                    "operation_id": str(plan.record.operation_id),
                    "plan_record_digest": plan.record.record_digest,
                    "route_relationship_digest": target.route_relationship_digest,
                    "source_digest": source_digest,
                    "target_plan_digest": target_plan_digest,
                    "trust_identity_digest": target.trust_identity_digest,
                }
            )
            variables = deploy_reboot_variables(
                operation_id=str(plan.record.operation_id),
                logical_id=target.stable_id,
                role=target.role,
                architecture=host.guest_architecture,
                request_digest=request_digest,
            )
            validate_playbook_request_policy(
                _REBOOT_PLAYBOOK,
                limit=(target.stable_id,),
                tags=(_REBOOT_PLAYBOOK,),
                check=False,
                diff=False,
                verbosity=0,
            )
            validated = definition.validate_variables(variables)
            variables_digest = digest_bytes(serialize_json(validated))
            command_digest = ansible_command_intent_digest(
                definition,
                step_sequence=target.sequence,
                limit=(target.stable_id,),
                variables_digest=variables_digest,
                tags=(_REBOOT_PLAYBOOK,),
                check=False,
                diff=False,
                verbosity=0,
            )
            scopes.append(
                _RebootScope(
                    target,
                    variables_digest,
                    command_digest,
                    source_digest,
                    request_digest,
                    target_plan_digest,
                )
            )
    except AnsibleError as error:
        raise StateConflictError(
            "post-non-jump-reboot command intent or variables drifted"
        ) from error
    execution_scope_digest = _digest_object(
        [
            {
                "command_digest": scope.command_digest,
                "request_digest": scope.request_digest,
                "sequence": scope.target.sequence,
                "source_digest": scope.source_digest,
                "target_plan_digest": scope.target_plan_digest,
                "variables_digest": scope.variables_digest,
            }
            for scope in scopes
        ]
    )
    record = plan.record
    values: dict[str, object] = {
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_name": metadata.cluster_name,
        "operation_id": plan.record.operation_id,
        "operation": _OPERATION,
        "stage": plan.record.stage,
        "scope_kind": plan.record.scope_kind,
        "request_digest": journal.record.request_digest,
        "journal_generation": journal.record.generation,
        "journal_digest": journal.digest,
        "journal_status": journal.record.status,
        "journal_phase": journal.record.phase,
        "plan_artifact_digest": plan.artifact_digest,
        "plan_record_digest": record.record_digest,
        "authorization_artifact_digest": authorization.artifact_digest,
        "authorization_digest": authorization.record.authorization_digest,
        "authorization_proof_digest": authorization.record.proof.proof_digest,
        "post_non_jump_reconciliation_artifact_digest": prior.artifact_digest,
        "post_non_jump_reconciliation_record_digest": prior.record.record_digest,
        "non_jump_base_os_authorization_artifact_digest": (
            record.non_jump_base_os_authorization_artifact_digest
        ),
        "non_jump_base_os_execution_artifact_digest": (
            record.non_jump_base_os_execution_artifact_digest
        ),
        "non_jump_base_os_execution_binding_digest": (
            record.non_jump_base_os_execution_binding_digest
        ),
        "non_jump_base_os_evidence_artifact_digest": (
            record.non_jump_base_os_evidence_artifact_digest
        ),
        "non_jump_base_os_evidence_digest": record.non_jump_base_os_evidence_digest,
        "final_routes_execution_artifact_digest": (
            record.final_routes_execution_artifact_digest
        ),
        "final_routes_evidence_artifact_digest": (
            record.final_routes_evidence_artifact_digest
        ),
        "final_routes_evidence_digest": record.final_routes_evidence_digest,
        "final_routes_reconciliation_artifact_digest": (
            record.final_routes_reconciliation_artifact_digest
        ),
        "final_routes_reconciliation_record_digest": (
            record.final_routes_reconciliation_record_digest
        ),
        "inventory_generation": deploy.inventory.record.generation,
        "inventory_artifact_digest": deploy.inventory.digest,
        "inventory_digest": deploy.inventory.record.inventory_digest,
        "trust_generation": planning.base.trust.record.generation,
        "trust_artifact_digest": planning.base.trust.digest,
        "trust_entries_digest": planning.base.trust.record.entries_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": readiness.record_digest,
        "catalog_digest": loaded.catalog_digest,
        "source_version": loaded.source.version,
        "source_digest": loaded.source.digest,
        "playbook_source_digest": source_digest,
        "toolchain_version": readiness.playbook_version,
        "executable_identity_digest": readiness.executable_identity_digest,
        "toolchain_evidence_digest": readiness.toolchain_evidence_digest,
        "target_count": record.target_count,
        "target_set_digest": record.target_set_digest,
        "target_order_digest": record.target_order_digest,
        "role_counts_digest": record.role_counts_digest,
        "route_relationship_digest": record.route_relationship_digest,
        "execution_scope_digest": execution_scope_digest,
        "binding_digest": "",
    }
    values["binding_digest"] = _binding_digest_from_values(values)
    return (
        tuple(scopes),
        DeployNonJumpRebootExecutionBinding(**values),  # type: ignore[arg-type]
    )


def _validate_complete_reboot(
    scopes: tuple[_RebootScope, ...],
    binding: DeployNonJumpRebootExecutionBinding,
    *,
    execution: StoredDeployNonJumpRebootExecution,
    evidence: StoredDeployNonJumpRebootEvidence,
) -> tuple[DeployNonJumpRebootEvidenceEntry, ...]:
    attempts = execution.record.attempts
    entries = evidence.record.entries
    if (
        not scopes
        or execution.record.binding != binding
        or evidence.record.binding != binding
        or execution.record.state is not DeployNonJumpRebootExecutionState.SUCCEEDED
        or not execution.record.authorization_consumed
        or not execution.record.all_targets_completed
        or execution.record.invocation_count != len(scopes)
        or execution.record.completed_target_count != len(scopes)
        or len(attempts) != len(scopes)
        or len(entries) != len(scopes)
        or execution.record.generation != len(scopes) * 3
        or evidence.record.generation != len(scopes)
    ):
        raise StateConflictError(
            "post-non-jump-reboot execution is partial, uncertain, or mismatched"
        )
    for index, (scope, attempt, entry) in enumerate(
        zip(scopes, attempts, entries, strict=True), start=1
    ):
        _validate_completed_target(index, scope, attempt, entry)
    return entries


def _validate_completed_target(
    index: int,
    scope: _RebootScope,
    attempt: DeployNonJumpRebootExecutionAttempt,
    entry: DeployNonJumpRebootEvidenceEntry,
) -> None:
    target = scope.target
    try:
        result = DeployRebootResult(
            logical_id=entry.stable_id,
            role=entry.role,
            status=entry.status,
            os_family=entry.os_family,
            os_version=entry.os_version,
            architecture=entry.architecture,
            services_safe_before=entry.services_safe_before,
            reboot_performed=entry.reboot_performed,
            reconnected=entry.reconnected,
            boot_changed=entry.boot_changed,
            identity_verified=entry.identity_verified,
            trust_revalidated=entry.trust_revalidated,
            machine_evidence_verified=entry.machine_evidence_verified,
            services_safe_after=entry.services_safe_after,
            reboot_required_clear=entry.reboot_required_clear,
            elapsed_seconds=entry.elapsed_seconds,
            request_digest=entry.request_digest,
        )
    except AnsibleError as error:
        raise StateConflictError(
            "post-non-jump-reboot semantic gates are incomplete"
        ) from error
    result_digest = _digest_object(result.to_object())
    if (
        target.sequence != index
        or attempt.sequence != index
        or entry.sequence != index
        or attempt.stable_id != target.stable_id
        or entry.stable_id != target.stable_id
        or attempt.role is not target.role
        or entry.role is not target.role
        or attempt.target_plan_digest != scope.target_plan_digest
        or entry.target_plan_digest != scope.target_plan_digest
        or attempt.variables_digest != scope.variables_digest
        or entry.variables_digest != scope.variables_digest
        or attempt.command_digest != scope.command_digest
        or entry.command_digest != scope.command_digest
        or attempt.source_digest != scope.source_digest
        or entry.source_digest != scope.source_digest
        or attempt.request_digest != scope.request_digest
        or entry.request_digest != scope.request_digest
        or attempt.state is not DeployNonJumpRebootExecutionState.SUCCEEDED
        or not attempt.authorization_consumed
        or not attempt.invocation_may_have_occurred
        or attempt.exit_code != 0
        or attempt.manual_recovery_required
        or attempt.automatic_retry_allowed
        or attempt.result_digest != result_digest
        or entry.result_digest != result_digest
        or attempt.evidence_digest != entry.evidence_digest
        or entry.status is not DeployRebootResultStatus.SUCCEEDED
        or entry.result_schema_version != DEPLOY_REBOOT_RESULT_SCHEMA_VERSION
        or not all(
            (
                entry.services_safe_before,
                entry.reboot_performed,
                entry.reconnected,
                entry.boot_changed,
                entry.identity_verified,
                entry.trust_revalidated,
                entry.machine_evidence_verified,
                entry.services_safe_after,
                entry.reboot_required_clear,
            )
        )
    ):
        raise StateConflictError(
            "post-non-jump-reboot target order, result, or evidence conflicts"
        )


def _build_steps(
    context: _PostNonJumpRebootContext,
) -> tuple[DeployBaseOsReconciledStep, ...]:
    prior_steps = context.prior.record.steps
    if context.branch is DeployPostNonJumpRebootBranch.NO_REBOOT_REQUIRED:
        return prior_steps
    base_mappings = {
        step.mapping_sequence
        for step in prior_steps
        if step.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
        and step.evidence_state
        is DeployBaseOsReconciledEvidenceState.NON_JUMP_BASE_OS_BOUND
    }
    if len(base_mappings) != 1:
        raise StateConflictError(
            "post-non-jump-reboot completed base mapping is ambiguous"
        )
    base_mapping = next(iter(base_mappings))
    remaining = tuple(
        sorted(
            {
                step.mapping_sequence
                for step in prior_steps
                if step.mapping_sequence > base_mapping
                and step.mapping_sequence != _FINAL_EVIDENCE_MAPPING
                and step.condition_state is DeployConditionState.ACTIVE
                and step.status is not DeployBaseOsReconciledStepStatus.SUCCEEDED
            }
        )
    )
    next_mapping = remaining[0] if remaining else None
    result: list[DeployBaseOsReconciledStep] = []
    for prior in prior_steps:
        prior_digest = _digest_object(prior.to_object())
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
                    blockers=tuple(
                        sorted(
                            {
                                *(
                                    blocker
                                    for blocker in prior.blockers
                                    if blocker not in _REBOOT_BLOCKERS
                                ),
                                _ORDER_BLOCKER,
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
                blockers=tuple(
                    sorted(
                        {
                            *(
                                blocker
                                for blocker in prior.blockers
                                if blocker not in _REBOOT_BLOCKERS
                            ),
                            _ORDER_BLOCKER,
                        }
                    )
                ),
            )
        )
    return tuple(result)


def _next_gate_ready(
    step: DeployBaseOsReconciledStep,
    context: _PostNonJumpRebootContext,
) -> bool:
    definition = get_playbook(step.playbook)
    planning = context.chain.authorization_context.final_routes.post.post.base.host.loaded.planning
    inventory_hosts = {
        host.logical_id: host
        for host in planning.base.deploy.inventory.record.inventory.hosts
    }
    selected = tuple(inventory_hosts.get(target) for target in step.target_ids)
    rebooted = {entry.stable_id for entry in context.reboot_entries}
    if (
        not definition.source_available
        or definition.classification is not step.classification
        or not step.target_ids
        or any(host is None for host in selected)
        or not set(step.target_ids).issubset(context.chain.stable_ids)
        or not set(step.variable_names) <= _CANONICAL_COMMON_VARIABLES
        or context.reboot_evidence_digest is None
    ):
        return False
    for target, inventory_host in zip(step.target_ids, selected, strict=True):
        assert inventory_host is not None
        base_result = context.chain.hosts_by_id.get(target)
        if (
            base_result is None
            or base_result.status
            not in {
                BaseOsStatus.NO_CHANGE,
                BaseOsStatus.CHANGED,
                BaseOsStatus.REBOOT_REQUIRED,
            }
            or not base_result.applied
            or base_result.prerequisite_policy_status != "satisfied"
            or base_result.timesync_service_status != "enabled-active"
            or (base_result.reboot_required and target not in rebooted)
            or (
                step.target_role != "all"
                and inventory_host.role.value != step.target_role
            )
        ):
            return False
    return True


def _next_gate_digest(
    step: DeployBaseOsReconciledStep,
    context: _PostNonJumpRebootContext,
) -> str:
    planning = context.chain.authorization_context.final_routes.post.post.base.host.loaded.planning
    return _digest_object(
        {
            "ansible_source_digest": (
                context.chain.authorization_context.final_routes.post.post.base.host.loaded.source.digest
            ),
            "catalog_digest": (
                context.chain.authorization_context.final_routes.post.post.base.host.loaded.catalog_digest
            ),
            "inventory_artifact_digest": planning.base.deploy.inventory.digest,
            "inventory_digest": planning.base.deploy.inventory.record.inventory_digest,
            "playbook": step.playbook,
            "prior_reconciliation_record_digest": context.prior.record.record_digest,
            "readiness_record_digest": planning.readiness.record.record_digest,
            "reboot_evidence_digest": context.reboot_evidence_digest,
            "sequence": step.sequence,
            "target_digest": step.target_digest,
            "trust_artifact_digest": planning.base.trust.digest,
            "trust_entries_digest": planning.base.trust.record.entries_digest,
        }
    )


def _build_record(
    context: _PostNonJumpRebootContext,
    *,
    steps: tuple[DeployBaseOsReconciledStep, ...],
    created_at: str,
) -> DeployPostNonJumpRebootReconciliation:
    planning = context.chain.authorization_context.final_routes.post.post.base.host.loaded.planning
    host_context = context.chain.authorization_context.final_routes.post.post.base.host
    deploy = planning.base.deploy
    journal = deploy.journal
    metadata = deploy.metadata.record
    counts = Counter(step.status for step in steps)
    blockers = tuple(sorted({blocker for step in steps for blocker in step.blockers}))
    plan = context.plan
    authorization = context.authorization
    execution = context.execution
    evidence = context.evidence
    target_count = len(context.reboot_entries)
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
        "prior_reconciliation_artifact_digest": context.prior.artifact_digest,
        "prior_reconciliation_record_digest": context.prior.record.record_digest,
        "prior_effective_plan_digest": context.prior.record.effective_plan_digest,
        "reboot_plan_artifact_digest": (
            plan.artifact_digest if plan is not None else None
        ),
        "reboot_plan_record_digest": (
            plan.record.record_digest if plan is not None else None
        ),
        "reboot_authorization_artifact_digest": (
            authorization.artifact_digest if authorization is not None else None
        ),
        "reboot_authorization_digest": (
            authorization.record.authorization_digest
            if authorization is not None
            else None
        ),
        "reboot_execution_artifact_digest": (
            execution.artifact_digest if execution is not None else None
        ),
        "reboot_execution_binding_digest": (
            execution.record.binding.binding_digest if execution is not None else None
        ),
        "reboot_evidence_artifact_digest": (
            evidence.artifact_digest if evidence is not None else None
        ),
        "reboot_evidence_digest": context.reboot_evidence_digest,
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
        "branch": context.branch,
        "reboot_handling_status": (
            _NOT_REQUIRED
            if context.branch is DeployPostNonJumpRebootBranch.NO_REBOOT_REQUIRED
            else _SUCCEEDED
        ),
        "reboot_evidence_state": (
            _NOT_REQUIRED
            if context.branch is DeployPostNonJumpRebootBranch.NO_REBOOT_REQUIRED
            else _REBOOT_EVIDENCE_BOUND
        ),
        "reboot_authorization_consumed": (
            execution.record.authorization_consumed if execution is not None else False
        ),
        "reboot_execution_state": (
            execution.record.state.value if execution is not None else _NOT_REQUIRED
        ),
        "reboot_target_count": target_count,
        "reboot_succeeded_count": target_count,
        "reboot_target_set_digest": (
            plan.record.target_set_digest if plan is not None else None
        ),
        "reboot_target_order_digest": (
            plan.record.target_order_digest if plan is not None else None
        ),
        "reconnect_count": sum(entry.reconnected for entry in context.reboot_entries),
        "boot_changed_count": sum(
            entry.boot_changed for entry in context.reboot_entries
        ),
        "identity_verified_count": sum(
            entry.identity_verified for entry in context.reboot_entries
        ),
        "trust_revalidated_count": sum(
            entry.trust_revalidated for entry in context.reboot_entries
        ),
        "machine_evidence_verified_count": sum(
            entry.machine_evidence_verified for entry in context.reboot_entries
        ),
        "service_safety_count": sum(
            entry.services_safe_before and entry.services_safe_after
            for entry in context.reboot_entries
        ),
        "reboot_clear_count": sum(
            entry.reboot_required_clear for entry in context.reboot_entries
        ),
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
        "blocker_set": blockers,
        "blocker_digest": _digest_object(list(blockers)),
        "effective_plan_digest": _digest_object([step.to_object() for step in steps]),
        "next_execution_state": _NOT_STARTED,
        "final_evidence_state": _NOT_PERFORMED,
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(values)
    return DeployPostNonJumpRebootReconciliation(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployPostNonJumpRebootReconciliation,
    *,
    state: DeployPostNonJumpRebootArtifactState,
) -> DeployPostNonJumpRebootReconciliationReport:
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
    summaries = _next_summaries(selected)
    target_ids = tuple(
        sorted({target for step in selected for target in step.target_ids})
    )
    return DeployPostNonJumpRebootReconciliationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        reconciliation_artifact_digest=stored.artifact_digest,
        reconciliation_record_digest=record.record_digest,
        effective_plan_digest=record.effective_plan_digest,
        branch=record.branch,
        reboot_handling_status=record.reboot_handling_status,
        reboot_evidence_state=record.reboot_evidence_state,
        reboot_target_count=record.reboot_target_count,
        reboot_succeeded_count=record.reboot_succeeded_count,
        reboot_target_set_digest=record.reboot_target_set_digest,
        reboot_target_order_digest=record.reboot_target_order_digest,
        reconnect_count=record.reconnect_count,
        boot_changed_count=record.boot_changed_count,
        identity_verified_count=record.identity_verified_count,
        trust_revalidated_count=record.trust_revalidated_count,
        machine_evidence_verified_count=record.machine_evidence_verified_count,
        service_safety_count=record.service_safety_count,
        reboot_clear_count=record.reboot_clear_count,
        next_steps=summaries,
        next_step_count=len(selected),
        next_target_count=len(target_ids),
        next_target_set_digest=_digest_object(list(target_ids)),
        blocker_set=record.blocker_set,
        blocker_digest=record.blocker_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        next_execution_state=record.next_execution_state,
        finalization_state=record.finalization_state,
        public_workflow_state=record.public_workflow_state,
    )


def _next_summaries(
    steps: tuple[DeployBaseOsReconciledStep, ...],
) -> tuple[DeployPostNonJumpBaseOsNextStepSummary, ...]:
    grouped: dict[
        tuple[
            str,
            str,
            OperationClassification,
            DeployBaseOsReconciledStepStatus,
        ],
        list[DeployBaseOsReconciledStep],
    ] = {}
    for step in steps:
        grouped.setdefault(
            (step.playbook, step.target_role, step.classification, step.status), []
        ).append(step)
    result: list[DeployPostNonJumpBaseOsNextStepSummary] = []
    for (playbook, role, classification, status), selected in sorted(
        grouped.items(),
        key=lambda item: (
            item[0][0],
            item[0][1],
            item[0][2].value,
            item[0][3].value,
        ),
    ):
        targets = tuple(
            sorted({target for step in selected for target in step.target_ids})
        )
        result.append(
            DeployPostNonJumpBaseOsNextStepSummary(
                playbook,
                role,
                classification,
                status,
                len(selected),
                len(targets),
                _digest_object(list(targets)),
                _digest_object(
                    [
                        {
                            "evidence_digest": step.evidence_digest,
                            "sequence": step.sequence,
                            "target_digest": step.target_digest,
                        }
                        for step in selected
                    ]
                ),
            )
        )
    return tuple(result)


def _record_digest(record: DeployPostNonJumpRebootReconciliation) -> str:
    value = record.to_object()
    value["record_digest"] = ""
    return _digest_object(value)


def _record_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployPostNonJumpRebootReconciliation.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(item, (JournalStatus, OperationPhase, StrEnum))
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
            "post-non-jump-reboot reconciliation paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "post-non-jump-reboot reconciliation requires acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list post-non-jump-reboot reconciliation artifacts"
        ) from error
    suffix = DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_FILENAME_SUFFIX
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
                "post-non-jump-reboot reconciliation artifacts are ambiguous"
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


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise StatePersistenceError(f"{label} must be a string or null")
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
        raise StatePersistenceError(f"{label} is invalid") from error


__all__ = [
    "ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_SCHEMA_VERSION",
    "DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_FILENAME_SUFFIX",
    "DeployPostNonJumpRebootArtifactState",
    "DeployPostNonJumpRebootBranch",
    "DeployPostNonJumpRebootReconciliation",
    "DeployPostNonJumpRebootReconciliationReport",
    "DeployPostNonJumpRebootReconciliationStore",
    "StoredDeployPostNonJumpRebootReconciliation",
    "deploy_post_non_jump_reboot_reconciliation_id_from_filename",
    "deploy_post_non_jump_reboot_reconciliation_path",
    "reconcile_deploy_post_non_jump_reboot_plan",
]
