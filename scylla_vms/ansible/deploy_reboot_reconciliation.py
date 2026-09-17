"""Immutable deploy-plan reconciliation after reboot handling.

This internal owner accepts only canonical operation identity and the matching
already-held deploy lock.  It proves either that reboot handling was not needed
or that the exact authorized serial reboot scope completed with strict semantic
evidence, then persists a new effective-plan companion without authorizing or
executing a later deploy step.
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

from scylla_vms.ansible.commands import (
    ansible_command_intent_digest,
    validate_playbook_request_policy,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION,
    DeployBaseOsNextStepSummary,
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStep,
    DeployBaseOsReconciledStepStatus,
    DeployBaseOsReconciliationStore,
    StoredDeployBaseOsReconciliation,
    _BaseOsReconciliationContext,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    _build_record as _build_base_os_reconciliation,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    _build_steps as _build_base_os_steps,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    _load_context as _load_base_os_context,
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
from scylla_vms.ansible.deploy_reboot_authorization import (
    ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_REBOOT_PLAN_SCHEMA_VERSION,
    DeployRebootAuthorizationStore,
    DeployRebootPlanStore,
    DeployRebootPlanTarget,
    StoredDeployRebootAuthorization,
    StoredDeployRebootPlan,
    _build_authorization,
    _build_plan,
    _build_targets,
    _derive_candidates,
    deploy_reboot_authorization_path,
    deploy_reboot_plan_path,
)
from scylla_vms.ansible.deploy_reboot_execution import (
    ANSIBLE_DEPLOY_REBOOT_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_REBOOT_EXECUTION_SCHEMA_VERSION,
    DeployRebootEvidenceEntry,
    DeployRebootEvidenceStore,
    DeployRebootExecutionAttempt,
    DeployRebootExecutionBinding,
    DeployRebootExecutionState,
    DeployRebootExecutionStore,
    StoredDeployRebootEvidence,
    StoredDeployRebootExecution,
    deploy_reboot_evidence_path,
    deploy_reboot_execution_path,
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

ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-reboot-reconciliation/v1"
)
ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-reboot-reconciliation-report/v1"
)
DEPLOY_POST_REBOOT_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-post-reboot-reconciliation.json"
)

_OPERATION = "deploy"
_REBOOT_PLAYBOOK = "deploy-reboot"
_BASE_OS_MAPPING = 3
_JUMP_CONFIGURE_MAPPING = 4
_FINAL_EVIDENCE_MAPPING = len(OPERATION_PLAYBOOKS[_OPERATION])
_NOT_REQUIRED = "not-required"
_SUCCEEDED = "succeeded"
_REBOOT_EVIDENCE_BOUND = "reboot-evidence-bound"
_NOT_STARTED = "not-started"
_NOT_PERFORMED = "not-performed"
_UNAVAILABLE = "unavailable"
_CONSUMED_BY_EXECUTION = "consumed-by-execution"
_PUBLIC_WORKFLOW_BLOCKER = "public-deploy-workflow-unavailable"
_AUTHORIZATION_BLOCKER = "deploy-authorization-not-collected"
_ORDER_BLOCKER = "ordered-deploy-step-not-reached"
_CLASS_BLOCKERS = {
    OperationClassification.MUTATING: "mutating-deploy-execution-unavailable",
    OperationClassification.SENSITIVE: "sensitive-deploy-execution-unavailable",
    OperationClassification.DESTRUCTIVE: "destructive-deploy-execution-unavailable",
}
_CLEARED_REBOOT_BLOCKERS = frozenset(
    {"reboot-required", "reboot-handling-not-performed"}
)
_CLEARED_NEXT_GATE_BLOCKERS = frozenset(
    {
        *_CLEARED_REBOOT_BLOCKERS,
        "base-os-evidence-not-performed",
        _ORDER_BLOCKER,
    }
)
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")


class DeployPostRebootBranch(StrEnum):
    """Truthful base-OS reboot branch."""

    NO_REBOOT_REQUIRED = "no-reboot-required"
    REBOOT_REQUIRED = "reboot-required"


class DeployPostRebootArtifactState(StrEnum):
    """Immutable companion persistence state."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployPostRebootReconciliation:
    """Immutable effective deploy view after reboot handling."""

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
    base_os_reconciliation_artifact_digest: str
    base_os_reconciliation_record_digest: str
    base_os_effective_plan_digest: str
    base_os_execution_artifact_digest: str
    base_os_evidence_artifact_digest: str
    base_os_evidence_digest: str
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    trust_generation: int
    trust_artifact_digest: str
    trust_entries_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    connectivity_execution_artifact_digest: str
    connectivity_evidence_artifact_digest: str
    connectivity_evidence_digest: str
    catalog_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    branch: DeployPostRebootBranch
    reboot_handling_status: str
    reboot_evidence_state: str
    reboot_plan_artifact_digest: str | None
    reboot_plan_record_digest: str | None
    reboot_authorization_artifact_digest: str | None
    reboot_authorization_digest: str | None
    reboot_execution_artifact_digest: str | None
    reboot_execution_binding_digest: str | None
    reboot_evidence_artifact_digest: str | None
    reboot_evidence_digest: str | None
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
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    base_os_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION
    )
    reboot_plan_schema_version: str = ANSIBLE_DEPLOY_REBOOT_PLAN_SCHEMA_VERSION
    reboot_authorization_schema_version: str = (
        ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_SCHEMA_VERSION
    )
    reboot_execution_schema_version: str = (
        ANSIBLE_DEPLOY_REBOOT_EXECUTION_SCHEMA_VERSION
    )
    reboot_evidence_schema_version: str = ANSIBLE_DEPLOY_REBOOT_EVIDENCE_SCHEMA_VERSION
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.base_os_reconciliation_schema_version
            != ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION
            or self.reboot_plan_schema_version
            != ANSIBLE_DEPLOY_REBOOT_PLAN_SCHEMA_VERSION
            or self.reboot_authorization_schema_version
            != ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_SCHEMA_VERSION
            or self.reboot_execution_schema_version
            != ANSIBLE_DEPLOY_REBOOT_EXECUTION_SCHEMA_VERSION
            or self.reboot_evidence_schema_version
            != ANSIBLE_DEPLOY_REBOOT_EVIDENCE_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
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
            or not isinstance(self.branch, DeployPostRebootBranch)
        ):
            raise StatePersistenceError(
                "post-reboot reconciliation identity or state is invalid"
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
            _nonnegative_integer(value, "post-reboot reconciliation count")
        if (
            self.journal_generation < 1
            or self.inventory_generation < 1
            or self.trust_generation < 1
            or self.mapping_count != len(OPERATION_PLAYBOOKS[_OPERATION])
            or self.step_count != len(self.steps)
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, len(self.steps) + 1))
        ):
            raise StatePersistenceError("post-reboot reconciliation counts conflict")
        expected_mapping = OPERATION_PLAYBOOKS[_OPERATION]
        if {step.mapping_sequence for step in self.steps} != set(
            range(1, len(expected_mapping) + 1)
        ) or any(
            step.playbook != expected_mapping[step.mapping_sequence - 1].playbook
            or step.condition != expected_mapping[step.mapping_sequence - 1].condition
            for step in self.steps
        ):
            raise StatePersistenceError("post-reboot deploy mapping conflicts")
        status_counts = Counter(step.status for step in self.steps)
        blocker_set = tuple(
            sorted({blocker for step in self.steps for blocker in step.blockers})
        )
        if (
            self.succeeded_count
            != status_counts[DeployBaseOsReconciledStepStatus.SUCCEEDED]
            or self.authorization_required_count
            != status_counts[
                DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            ]
            or self.eligible_count
            != status_counts[DeployBaseOsReconciledStepStatus.ELIGIBLE]
            or self.blocked_count
            != status_counts[DeployBaseOsReconciledStepStatus.BLOCKED]
            or self.not_performed_count
            != status_counts[DeployBaseOsReconciledStepStatus.NOT_PERFORMED]
            or self.succeeded_count
            + self.authorization_required_count
            + self.eligible_count
            + self.blocked_count
            + self.not_performed_count
            != self.step_count
            or self.blocker_set != blocker_set
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blocker_set)
            or self.blocker_digest != _digest_object(list(self.blocker_set))
            or self.effective_plan_digest
            != _digest_object([step.to_object() for step in self.steps])
        ):
            raise StatePersistenceError("post-reboot reconciliation summary conflicts")
        self._validate_reboot_branch()
        for digest_value in _required_digests(self):
            validate_digest(digest_value, "post-reboot reconciliation digest")
        for optional_digest in _optional_digests(self):
            if optional_digest is not None:
                validate_digest(optional_digest, "post-reboot optional digest")
        if self.record_digest != _record_digest(self):
            raise StatePersistenceError(
                "post-reboot reconciliation record digest conflicts"
            )

    def _validate_reboot_branch(self) -> None:
        optional_values = _optional_digests(self)
        gate_counts = (
            self.reconnect_count,
            self.boot_changed_count,
            self.identity_verified_count,
            self.trust_revalidated_count,
            self.machine_evidence_verified_count,
            self.service_safety_count,
            self.reboot_clear_count,
        )
        if self.branch is DeployPostRebootBranch.NO_REBOOT_REQUIRED:
            if (
                self.reboot_handling_status != _NOT_REQUIRED
                or self.reboot_evidence_state != _NOT_REQUIRED
                or self.reboot_execution_state != _NOT_REQUIRED
                or self.reboot_authorization_consumed
                or self.reboot_target_count
                or self.reboot_succeeded_count
                or any(gate_counts)
                or any(value is not None for value in optional_values)
            ):
                raise StatePersistenceError("post-reboot not-required branch conflicts")
            return
        if (
            self.reboot_handling_status != _SUCCEEDED
            or self.reboot_evidence_state != _REBOOT_EVIDENCE_BOUND
            or self.reboot_execution_state != DeployRebootExecutionState.SUCCEEDED.value
            or not self.reboot_authorization_consumed
            or self.reboot_target_count < 1
            or self.reboot_succeeded_count != self.reboot_target_count
            or any(count != self.reboot_target_count for count in gate_counts)
            or any(value is None for value in optional_values)
            or any(blocker in self.blocker_set for blocker in _CLEARED_REBOOT_BLOCKERS)
        ):
            raise StatePersistenceError("post-reboot completed branch conflicts")

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
    def from_object(cls, value: Mapping[str, object]) -> DeployPostRebootReconciliation:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "post-reboot reconciliation",
        )
        integer_fields = {
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
        optional_fields = {
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
            elif name == "branch":
                parsed[name] = _enum(
                    DeployPostRebootBranch,
                    require_string(value, name),
                    "post-reboot branch",
                )
            elif name == "reboot_authorization_consumed":
                parsed[name] = _boolean(item, name)
            elif name == "steps":
                parsed[name] = tuple(
                    DeployBaseOsReconciledStep.from_object(
                        _mapping(step, "post-reboot reconciled step")
                    )
                    for step in _array(item, "post-reboot reconciled steps")
                )
            elif name == "blocker_set":
                parsed[name] = _string_tuple(item, name)
            elif name in optional_fields:
                parsed[name] = _optional_string(item, name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployPostRebootReconciliation:
    record: DeployPostRebootReconciliation
    artifact_digest: str


class DeployPostRebootReconciliationStore:
    """Owner-only immutable post-reboot effective-plan companion."""

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
        self._path = deploy_post_reboot_reconciliation_path(paths, operation_id)
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
    ) -> StoredDeployPostRebootReconciliation:
        value, artifact_digest = self._file.read()
        record = DeployPostRebootReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError("post-reboot reconciliation identity conflicts")
        return StoredDeployPostRebootReconciliation(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPostRebootReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployPostRebootReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployPostRebootReconciliation,
        DeployPostRebootArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "post-reboot reconciliation operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "post-reboot reconciliation is immutable; use a new operation"
                )
            return current, DeployPostRebootArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployPostRebootReconciliation(record, artifact_digest),
            DeployPostRebootArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployPostRebootReconciliationReport:
    """Strict address-free projection of post-reboot reconciliation."""

    operation_id: uuid.UUID
    artifact_state: DeployPostRebootArtifactState
    reconciliation_artifact_digest: str
    reconciliation_record_digest: str
    effective_plan_digest: str
    branch: DeployPostRebootBranch
    reboot_handling_status: str
    reboot_evidence_state: str
    reboot_target_count: int
    reboot_succeeded_count: int
    reboot_target_set_digest: str | None
    reboot_target_order_digest: str | None
    reconnect_count: int
    reboot_clear_count: int
    next_authorization_required: tuple[DeployBaseOsNextStepSummary, ...]
    next_authorization_required_count: int
    next_authorization_target_count: int
    next_authorization_target_set_digest: str
    blocker_set: tuple[str, ...]
    blocker_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    next_execution_state: str
    finalization_state: str
    public_workflow_state: str
    reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_REPORT_SCHEMA_VERSION
            or self.reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION
            or not isinstance(self.operation_id, uuid.UUID)
            or not isinstance(self.branch, DeployPostRebootBranch)
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.next_execution_state != _NOT_STARTED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
        ):
            raise StatePersistenceError(
                "post-reboot reconciliation report identity is invalid"
            )
        for value in (
            self.reboot_target_count,
            self.reboot_succeeded_count,
            self.reconnect_count,
            self.reboot_clear_count,
            self.next_authorization_required_count,
            self.next_authorization_target_count,
        ):
            _nonnegative_integer(value, "post-reboot report count")
        next_count = sum(
            item.instance_count for item in self.next_authorization_required
        )
        next_ids = sum(
            item.stable_id_count for item in self.next_authorization_required
        )
        if (
            next_count != self.next_authorization_required_count
            or next_ids != self.next_authorization_target_count
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blocker_set)
            or self.blocker_digest != _digest_object(list(self.blocker_set))
        ):
            raise StatePersistenceError(
                "post-reboot reconciliation report summary conflicts"
            )
        for digest_value in (
            self.reconciliation_artifact_digest,
            self.reconciliation_record_digest,
            self.effective_plan_digest,
            self.next_authorization_target_set_digest,
            self.blocker_digest,
        ):
            validate_digest(digest_value, "post-reboot report digest")
        for optional_digest in (
            self.reboot_target_set_digest,
            self.reboot_target_order_digest,
        ):
            if optional_digest is not None:
                validate_digest(optional_digest, "post-reboot report optional digest")
        if self.branch is DeployPostRebootBranch.NO_REBOOT_REQUIRED:
            if (
                self.reboot_handling_status != _NOT_REQUIRED
                or self.reboot_evidence_state != _NOT_REQUIRED
                or self.reboot_target_count
                or self.reboot_succeeded_count
                or self.reconnect_count
                or self.reboot_clear_count
                or self.reboot_target_set_digest is not None
                or self.reboot_target_order_digest is not None
            ):
                raise StatePersistenceError(
                    "post-reboot report not-required branch conflicts"
                )
        elif (
            self.reboot_handling_status != _SUCCEEDED
            or self.reboot_evidence_state != _REBOOT_EVIDENCE_BOUND
            or self.reboot_target_count < 1
            or self.reboot_succeeded_count != self.reboot_target_count
            or self.reconnect_count != self.reboot_target_count
            or self.reboot_clear_count != self.reboot_target_count
            or self.reboot_target_set_digest is None
            or self.reboot_target_order_digest is None
        ):
            raise StatePersistenceError("post-reboot report completed branch conflicts")

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
                "authorization_required": [
                    item.to_object() for item in self.next_authorization_required
                ],
                "authorization_required_count": (
                    self.next_authorization_required_count
                ),
                "execution_state": self.next_execution_state,
                "target_count": self.next_authorization_target_count,
                "target_set_digest": self.next_authorization_target_set_digest,
            },
            "operation_id": str(self.operation_id),
            "provenance": {
                "effective_plan_digest": self.effective_plan_digest,
                "reconciliation_artifact_digest": (self.reconciliation_artifact_digest),
                "reconciliation_record_digest": self.reconciliation_record_digest,
            },
            "reboot": {
                "evidence_state": self.reboot_evidence_state,
                "handling_status": self.reboot_handling_status,
                "reboot_clear_count": self.reboot_clear_count,
                "reconnect_count": self.reconnect_count,
                "succeeded_count": self.reboot_succeeded_count,
                "target_count": self.reboot_target_count,
                "target_order_digest": self.reboot_target_order_digest,
                "target_set_digest": self.reboot_target_set_digest,
            },
            "schema_version": self.schema_version,
            "schemas": {
                "reconciliation": self.reconciliation_schema_version,
            },
            "states": {
                "finalization": self.finalization_state,
                "public_workflow": self.public_workflow_state,
            },
        }


@dataclass(frozen=True, slots=True)
class _RebootScope:
    target: DeployRebootPlanTarget
    variables_digest: str
    command_digest: str
    source_digest: str
    request_digest: str
    target_plan_digest: str


@dataclass(frozen=True, slots=True)
class _PostRebootContext:
    base: _BaseOsReconciliationContext
    base_reconciliation: StoredDeployBaseOsReconciliation
    branch: DeployPostRebootBranch
    plan: StoredDeployRebootPlan | None
    authorization: StoredDeployRebootAuthorization | None
    execution: StoredDeployRebootExecution | None
    evidence: StoredDeployRebootEvidence | None
    reboot_evidence_digest: str | None
    reboot_target_count: int
    reconnect_count: int
    boot_changed_count: int
    identity_verified_count: int
    trust_revalidated_count: int
    machine_evidence_verified_count: int
    service_safety_count: int
    reboot_clear_count: int


def reconcile_deploy_post_reboot_plan(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployPostRebootReconciliationReport:
    """Persist the exact immutable effective plan after reboot handling."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_artifacts(paths, operation_id)
    context = _load_context(paths, operation_id, lock=lock)
    metadata = context.base.host.loaded.planning.base.deploy.metadata.record
    store = DeployPostRebootReconciliationStore(paths, operation_id)
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
            "post-reboot reconciliation is immutable; use a new operation"
        )
    try:
        stored, state = store.write_locked(record, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "post-reboot reconciliation persistence failed"
        ) from error
    return _build_report(stored, state=state)


def deploy_post_reboot_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the sole canonical post-reboot reconciliation path."""

    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_POST_REBOOT_RECONCILIATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError("post-reboot reconciliation path is not canonical")
    return path


def deploy_post_reboot_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(DEPLOY_POST_REBOOT_RECONCILIATION_FILENAME_SUFFIX):
        return None
    value = name[: -len(DEPLOY_POST_REBOOT_RECONCILIATION_FILENAME_SUFFIX)]
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
) -> _PostRebootContext:
    base = _load_base_os_context(paths, operation_id, lock=lock)
    planning = base.host.loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    journal = deploy.journal
    if (
        journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
    ):
        raise StateConflictError(
            "post-reboot reconciliation requires the unchanged VERIFY journal"
        )
    base_store = DeployBaseOsReconciliationStore(paths, operation_id)
    validate_state_file(base_store.path, allow_missing=True)
    if not base_store.path.exists():
        raise StateConflictError(
            "post-reboot reconciliation requires base-os reconciliation"
        )
    base_reconciliation = base_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_base = _build_base_os_reconciliation(
        base,
        steps=_build_base_os_steps(base),
        created_at=base_reconciliation.record.created_at,
    )
    if base_reconciliation.record != expected_base:
        raise StateConflictError("post-reboot base-os result changed or drifted")
    _validate_current_runtime(paths, base)

    reboot_paths = (
        deploy_reboot_plan_path(paths, operation_id),
        deploy_reboot_authorization_path(paths, operation_id),
        deploy_reboot_execution_path(paths, operation_id),
        deploy_reboot_evidence_path(paths, operation_id),
    )
    for path in reboot_paths:
        validate_state_file(path, allow_missing=True)
    if not base_reconciliation.record.reboot_required:
        if any(path.exists() for path in reboot_paths):
            raise StateConflictError(
                "post-reboot artifacts conflict with no-reboot-required branch"
            )
        return _PostRebootContext(
            base=base,
            base_reconciliation=base_reconciliation,
            branch=DeployPostRebootBranch.NO_REBOOT_REQUIRED,
            plan=None,
            authorization=None,
            execution=None,
            evidence=None,
            reboot_evidence_digest=None,
            reboot_target_count=0,
            reconnect_count=0,
            boot_changed_count=0,
            identity_verified_count=0,
            trust_revalidated_count=0,
            machine_evidence_verified_count=0,
            service_safety_count=0,
            reboot_clear_count=0,
        )
    if not all(path.exists() for path in reboot_paths):
        raise StateConflictError(
            "post-reboot reconciliation requires the complete reboot chain"
        )
    return _load_required_reboot_context(
        paths,
        operation_id,
        base=base,
        base_reconciliation=base_reconciliation,
        lock=lock,
    )


def _validate_current_runtime(
    paths: StatePaths,
    base: _BaseOsReconciliationContext,
) -> None:
    planning = base.host.loaded.planning
    deploy = planning.base.deploy
    readiness_record = planning.readiness.record
    readiness = _reconstructed_readiness(planning.base)
    if (
        readiness_binding_digest(readiness) != readiness_record.readiness_digest
        or readiness_record.playbook_version != readiness_record.inventory_version
        or readiness_record.remote_playbook_status != _NOT_PERFORMED
    ):
        raise StateConflictError(
            "post-reboot inventory, trust, or readiness evidence is stale"
        )
    readiness.require_ready(OperationClassification.MUTATING)
    TrustStore(paths).validate_runtime(planning.base.trust, deploy.inventory)


def _load_required_reboot_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    base: _BaseOsReconciliationContext,
    base_reconciliation: StoredDeployBaseOsReconciliation,
    lock: ClusterLock,
) -> _PostRebootContext:
    planning = base.host.loaded.planning
    loaded = base.host.loaded
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    plan = DeployRebootPlanStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    candidates = _derive_candidates(base, base_reconciliation)
    targets, blockers = _build_targets(base, candidates)
    expected_plan = _build_plan(
        base,
        base_reconciliation,
        targets=targets,
        blockers=blockers,
        created_at=plan.record.created_at,
    )
    if (
        plan.record != expected_plan
        or blockers
        or plan.record.blocker_set
        or plan.record.target_count != base_reconciliation.record.reboot_required_count
    ):
        raise StateConflictError(
            "post-reboot plan is blocked, stale, reordered, or mismatched"
        )
    authorization = DeployRebootAuthorizationStore(paths, operation_id).read_locked(
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
            "post-reboot authorization is stale, changed, or mismatched"
        )
    execution = DeployRebootExecutionStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    evidence = DeployRebootEvidenceStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    scopes, binding = _rebuild_execution_binding(
        base,
        base_reconciliation,
        plan,
        authorization,
    )
    entries = _validate_complete_reboot(
        scopes,
        binding,
        execution,
        evidence,
    )
    evidence_digest = _digest_object([entry.evidence_digest for entry in entries])
    if (
        binding.catalog_digest != loaded.catalog_digest
        or binding.source_version != loaded.source.version
        or binding.source_digest != loaded.source.digest
    ):
        raise StateConflictError("post-reboot source or catalog drifted")
    return _PostRebootContext(
        base=base,
        base_reconciliation=base_reconciliation,
        branch=DeployPostRebootBranch.REBOOT_REQUIRED,
        plan=plan,
        authorization=authorization,
        execution=execution,
        evidence=evidence,
        reboot_evidence_digest=evidence_digest,
        reboot_target_count=len(entries),
        reconnect_count=sum(entry.reconnected for entry in entries),
        boot_changed_count=sum(entry.boot_changed for entry in entries),
        identity_verified_count=sum(entry.identity_verified for entry in entries),
        trust_revalidated_count=sum(entry.trust_revalidated for entry in entries),
        machine_evidence_verified_count=sum(
            entry.machine_evidence_verified for entry in entries
        ),
        service_safety_count=sum(
            entry.services_safe_before and entry.services_safe_after
            for entry in entries
        ),
        reboot_clear_count=sum(entry.reboot_required_clear for entry in entries),
    )


def _rebuild_execution_binding(
    base: _BaseOsReconciliationContext,
    reconciliation: StoredDeployBaseOsReconciliation,
    plan: StoredDeployRebootPlan,
    authorization: StoredDeployRebootAuthorization,
) -> tuple[tuple[_RebootScope, ...], DeployRebootExecutionBinding]:
    planning = base.host.loaded.planning
    loaded = base.host.loaded
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    journal = deploy.journal
    readiness = planning.readiness.record
    source_digest = _playbook_source_digest(loaded.source, _REBOOT_PLAYBOOK)
    definition = get_playbook(_REBOOT_PLAYBOOK)
    base_os_hosts = {
        host.logical_id: host
        for entry in base.evidence.record.entries
        for host in entry.hosts
    }
    inventory_hosts = {
        host.logical_id: host for host in deploy.inventory.record.inventory.hosts
    }
    scopes: list[_RebootScope] = []
    try:
        for target in plan.record.targets:
            host = base_os_hosts.get(target.stable_id)
            inventory_host = inventory_hosts.get(target.stable_id)
            if (
                host is None
                or inventory_host is None
                or inventory_host.role is not target.role
                or not host.reboot_required
                or host.status.value != "reboot-required"
                or host.os_family != "Ubuntu"
                or host.os_version != "24.04"
                or host.guest_architecture not in {"x86_64", "aarch64"}
            ):
                raise StateConflictError(
                    "post-reboot target base-os identity or result drifted"
                )
            target_plan_digest = _digest_object(target.to_object())
            request_digest = _digest_object(
                {
                    "authorization_digest": authorization.record.authorization_digest,
                    "base_os_evidence_digest": target.base_os_evidence_digest,
                    "base_os_result_digest": target.base_os_result_digest,
                    "operation_id": str(plan.record.operation_id),
                    "plan_record_digest": plan.record.record_digest,
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
            "post-reboot command intent or variables drifted"
        ) from error
    scope_digest = _digest_object(
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
    binding_values: dict[str, object] = {
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_name": metadata.cluster_name,
        "operation_id": plan.record.operation_id,
        "operation": _OPERATION,
        "request_digest": journal.record.request_digest,
        "journal_generation": journal.record.generation,
        "journal_digest": journal.digest,
        "journal_status": journal.record.status,
        "journal_phase": journal.record.phase,
        "reboot_plan_artifact_digest": plan.artifact_digest,
        "reboot_plan_record_digest": plan.record.record_digest,
        "reboot_authorization_artifact_digest": authorization.artifact_digest,
        "reboot_authorization_digest": authorization.record.authorization_digest,
        "reboot_authorization_proof_digest": authorization.record.proof.proof_digest,
        "base_os_reconciliation_artifact_digest": reconciliation.artifact_digest,
        "base_os_reconciliation_record_digest": reconciliation.record.record_digest,
        "base_os_execution_artifact_digest": base.execution.artifact_digest,
        "base_os_evidence_artifact_digest": base.evidence.artifact_digest,
        "connectivity_execution_artifact_digest": loaded.execution.artifact_digest,
        "connectivity_evidence_artifact_digest": loaded.evidence.artifact_digest,
        "connectivity_evidence_digest": plan.record.connectivity_evidence_digest,
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
        "target_count": plan.record.target_count,
        "target_set_digest": plan.record.target_set_digest,
        "target_order_digest": plan.record.target_order_digest,
        "role_batch_digest": plan.record.role_batch_digest,
        "execution_scope_digest": scope_digest,
        "binding_digest": "",
    }
    binding_values["binding_digest"] = _binding_digest_from_values(binding_values)
    return tuple(scopes), DeployRebootExecutionBinding(**binding_values)  # type: ignore[arg-type]


def _validate_complete_reboot(
    scopes: tuple[_RebootScope, ...],
    binding: DeployRebootExecutionBinding,
    execution: StoredDeployRebootExecution,
    evidence: StoredDeployRebootEvidence,
) -> tuple[DeployRebootEvidenceEntry, ...]:
    attempts = execution.record.attempts
    entries = evidence.record.entries
    if (
        not scopes
        or execution.record.binding != binding
        or evidence.record.binding != binding
        or execution.record.state is not DeployRebootExecutionState.SUCCEEDED
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
            "post-reboot execution is missing, partial, uncertain, or mismatched"
        )
    for index, (scope, attempt, entry) in enumerate(
        zip(scopes, attempts, entries, strict=True),
        start=1,
    ):
        _validate_completed_target(index, scope, attempt, entry)
    return entries


def _validate_completed_target(
    index: int,
    scope: _RebootScope,
    attempt: DeployRebootExecutionAttempt,
    entry: DeployRebootEvidenceEntry,
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
            "post-reboot semantic gates are incomplete or unsafe"
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
        or attempt.state is not DeployRebootExecutionState.SUCCEEDED
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
            "post-reboot target order, identity, result, or evidence conflicts"
        )


def _build_steps(
    context: _PostRebootContext,
) -> tuple[DeployBaseOsReconciledStep, ...]:
    prior_steps = context.base_reconciliation.record.steps
    if context.branch is DeployPostRebootBranch.NO_REBOOT_REQUIRED:
        return prior_steps
    remaining_mappings = tuple(
        sorted(
            {
                step.mapping_sequence
                for step in prior_steps
                if step.status is not DeployBaseOsReconciledStepStatus.SUCCEEDED
                and step.condition_state is DeployConditionState.ACTIVE
                and step.mapping_sequence > _BASE_OS_MAPPING
                and step.mapping_sequence != _FINAL_EVIDENCE_MAPPING
            }
        )
    )
    next_mapping = remaining_mappings[0] if remaining_mappings else None
    result: list[DeployBaseOsReconciledStep] = []
    for prior in prior_steps:
        prior_digest = _digest_object(prior.to_object())
        if prior.status is DeployBaseOsReconciledStepStatus.SUCCEEDED:
            result.append(replace(prior, prior_reconciled_step_digest=prior_digest))
            continue
        if prior.condition_state is DeployConditionState.INACTIVE:
            result.append(replace(prior, prior_reconciled_step_digest=prior_digest))
            continue
        if prior.mapping_sequence == _FINAL_EVIDENCE_MAPPING:
            result.append(
                replace(
                    prior,
                    prior_reconciled_step_digest=prior_digest,
                    blockers=tuple(
                        sorted(
                            {
                                *(
                                    blocker
                                    for blocker in prior.blockers
                                    if blocker not in _CLEARED_REBOOT_BLOCKERS
                                ),
                                _ORDER_BLOCKER,
                            }
                        )
                    ),
                )
            )
            continue
        if prior.mapping_sequence == next_mapping and _next_gate_ready(prior, context):
            blockers = tuple(
                sorted(
                    {
                        *(
                            blocker
                            for blocker in prior.blockers
                            if blocker not in _CLEARED_NEXT_GATE_BLOCKERS
                        ),
                        _AUTHORIZATION_BLOCKER,
                        _CLASS_BLOCKERS[prior.classification],
                        _PUBLIC_WORKFLOW_BLOCKER,
                    }
                )
            )
            result.append(
                replace(
                    prior,
                    prior_reconciled_step_digest=prior_digest,
                    status=(
                        DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
                    ),
                    evidence_state=(
                        DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED
                    ),
                    evidence_digest=_next_gate_digest(prior, context),
                    blockers=blockers,
                )
            )
            continue
        blockers = tuple(
            sorted(
                {
                    *(
                        blocker
                        for blocker in prior.blockers
                        if blocker not in _CLEARED_REBOOT_BLOCKERS
                    ),
                    _ORDER_BLOCKER,
                }
            )
        )
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
                blockers=blockers,
            )
        )
    return tuple(result)


def _next_gate_ready(
    step: DeployBaseOsReconciledStep,
    context: _PostRebootContext,
) -> bool:
    # Post-reboot evidence supersedes only reboot/reconnect identity facts.
    # Current canonical inventory, trust, routes, and readiness were separately
    # revalidated; no pre-reboot capacity/storage/package/health fact advances.
    return (
        step.mapping_sequence == _JUMP_CONFIGURE_MAPPING
        and step.playbook == "jump-host-configure"
        and step.classification is OperationClassification.MUTATING
        and step.condition_state is DeployConditionState.ACTIVE
        and bool(step.target_ids)
        and set(step.target_ids).issubset(context.base.stable_ids)
        and context.reboot_evidence_digest is not None
    )


def _next_gate_digest(
    step: DeployBaseOsReconciledStep,
    context: _PostRebootContext,
) -> str:
    planning = context.base.host.loaded.planning
    deploy = planning.base.deploy
    return _digest_object(
        {
            "base_os_evidence_digest": context.base.base_os_evidence_digest,
            "inventory_artifact_digest": deploy.inventory.digest,
            "inventory_digest": deploy.inventory.record.inventory_digest,
            "playbook": step.playbook,
            "readiness_record_digest": planning.readiness.record.record_digest,
            "reboot_evidence_digest": context.reboot_evidence_digest,
            "sequence": step.sequence,
            "target_digest": step.target_digest,
            "trust_artifact_digest": planning.base.trust.digest,
            "trust_entries_digest": planning.base.trust.record.entries_digest,
        }
    )


def _build_record(
    context: _PostRebootContext,
    *,
    steps: tuple[DeployBaseOsReconciledStep, ...],
    created_at: str,
) -> DeployPostRebootReconciliation:
    base = context.base
    loaded = base.host.loaded
    planning = loaded.planning
    deploy = planning.base.deploy
    journal = deploy.journal
    metadata = deploy.metadata.record
    counts = Counter(step.status for step in steps)
    blockers = tuple(sorted({blocker for step in steps for blocker in step.blockers}))
    plan = context.plan
    authorization = context.authorization
    execution = context.execution
    evidence = context.evidence
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
        "base_os_reconciliation_artifact_digest": (
            context.base_reconciliation.artifact_digest
        ),
        "base_os_reconciliation_record_digest": (
            context.base_reconciliation.record.record_digest
        ),
        "base_os_effective_plan_digest": (
            context.base_reconciliation.record.effective_plan_digest
        ),
        "base_os_execution_artifact_digest": base.execution.artifact_digest,
        "base_os_evidence_artifact_digest": base.evidence.artifact_digest,
        "base_os_evidence_digest": base.base_os_evidence_digest,
        "inventory_generation": deploy.inventory.record.generation,
        "inventory_artifact_digest": deploy.inventory.digest,
        "inventory_digest": deploy.inventory.record.inventory_digest,
        "trust_generation": planning.base.trust.record.generation,
        "trust_artifact_digest": planning.base.trust.digest,
        "trust_entries_digest": planning.base.trust.record.entries_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": planning.readiness.record.record_digest,
        "connectivity_execution_artifact_digest": loaded.execution.artifact_digest,
        "connectivity_evidence_artifact_digest": loaded.evidence.artifact_digest,
        "connectivity_evidence_digest": loaded.evidence.record.entries[
            1
        ].evidence_digest,
        "catalog_digest": loaded.catalog_digest,
        "ansible_source_version": loaded.source.version,
        "ansible_source_digest": loaded.source.digest,
        "branch": context.branch,
        "reboot_handling_status": (
            _NOT_REQUIRED
            if context.branch is DeployPostRebootBranch.NO_REBOOT_REQUIRED
            else _SUCCEEDED
        ),
        "reboot_evidence_state": (
            _NOT_REQUIRED
            if context.branch is DeployPostRebootBranch.NO_REBOOT_REQUIRED
            else _REBOOT_EVIDENCE_BOUND
        ),
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
        "reboot_authorization_consumed": (
            execution.record.authorization_consumed if execution is not None else False
        ),
        "reboot_execution_state": (
            execution.record.state.value if execution is not None else _NOT_REQUIRED
        ),
        "reboot_target_count": context.reboot_target_count,
        "reboot_succeeded_count": context.reboot_target_count,
        "reboot_target_set_digest": (
            plan.record.target_set_digest if plan is not None else None
        ),
        "reboot_target_order_digest": (
            plan.record.target_order_digest if plan is not None else None
        ),
        "reconnect_count": context.reconnect_count,
        "boot_changed_count": context.boot_changed_count,
        "identity_verified_count": context.identity_verified_count,
        "trust_revalidated_count": context.trust_revalidated_count,
        "machine_evidence_verified_count": (context.machine_evidence_verified_count),
        "service_safety_count": context.service_safety_count,
        "reboot_clear_count": context.reboot_clear_count,
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
    return DeployPostRebootReconciliation(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployPostRebootReconciliation,
    *,
    state: DeployPostRebootArtifactState,
) -> DeployPostRebootReconciliationReport:
    record = stored.record
    next_steps = tuple(
        step
        for step in record.steps
        if step.status
        is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
    )
    summaries = _next_summaries(next_steps)
    next_ids = tuple(
        sorted({target for step in next_steps for target in step.target_ids})
    )
    return DeployPostRebootReconciliationReport(
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
        reboot_clear_count=record.reboot_clear_count,
        next_authorization_required=summaries,
        next_authorization_required_count=len(next_steps),
        next_authorization_target_count=len(next_ids),
        next_authorization_target_set_digest=_digest_object(list(next_ids)),
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
) -> tuple[DeployBaseOsNextStepSummary, ...]:
    grouped: dict[
        tuple[str, OperationClassification], list[DeployBaseOsReconciledStep]
    ] = {}
    for step in steps:
        grouped.setdefault((step.playbook, step.classification), []).append(step)
    result: list[DeployBaseOsNextStepSummary] = []
    for (playbook, classification), selected in sorted(
        grouped.items(), key=lambda item: (item[0][0], item[0][1].value)
    ):
        stable_ids = tuple(
            sorted({target for step in selected for target in step.target_ids})
        )
        result.append(
            DeployBaseOsNextStepSummary(
                playbook,
                classification,
                len(selected),
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
                len(stable_ids),
                _digest_object(list(stable_ids)),
            )
        )
    return tuple(result)


def _required_digests(
    record: DeployPostRebootReconciliation,
) -> tuple[str, ...]:
    return (
        record.request_digest,
        record.journal_digest,
        record.base_os_reconciliation_artifact_digest,
        record.base_os_reconciliation_record_digest,
        record.base_os_effective_plan_digest,
        record.base_os_execution_artifact_digest,
        record.base_os_evidence_artifact_digest,
        record.base_os_evidence_digest,
        record.inventory_artifact_digest,
        record.inventory_digest,
        record.trust_artifact_digest,
        record.trust_entries_digest,
        record.readiness_artifact_digest,
        record.readiness_record_digest,
        record.connectivity_execution_artifact_digest,
        record.connectivity_evidence_artifact_digest,
        record.connectivity_evidence_digest,
        record.catalog_digest,
        record.ansible_source_digest,
        record.blocker_digest,
        record.effective_plan_digest,
        record.record_digest,
    )


def _optional_digests(
    record: DeployPostRebootReconciliation,
) -> tuple[str | None, ...]:
    return (
        record.reboot_plan_artifact_digest,
        record.reboot_plan_record_digest,
        record.reboot_authorization_artifact_digest,
        record.reboot_authorization_digest,
        record.reboot_execution_artifact_digest,
        record.reboot_execution_binding_digest,
        record.reboot_evidence_artifact_digest,
        record.reboot_evidence_digest,
        record.reboot_target_set_digest,
        record.reboot_target_order_digest,
    )


def _record_digest(record: DeployPostRebootReconciliation) -> str:
    value = record.to_object()
    value["record_digest"] = ""
    return _digest_object(value)


def _record_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployPostRebootReconciliation.__dataclass_fields__.items():
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


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployRebootExecutionBinding.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(item, (JournalStatus, OperationPhase))
            else item
        )
    value["binding_digest"] = ""
    return _digest_object(value)


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "post-reboot reconciliation paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "post-reboot reconciliation requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list post-reboot reconciliation artifacts"
        ) from error
    canonical = str(operation_id)
    for entry in entries:
        if not entry.name.endswith(DEPLOY_POST_REBOOT_RECONCILIATION_FILENAME_SUFFIX):
            continue
        prefix = entry.name[: -len(DEPLOY_POST_REBOOT_RECONCILIATION_FILENAME_SUFFIX)]
        try:
            parsed = uuid.UUID(prefix)
        except ValueError:
            parsed = None
        if prefix != canonical and (
            parsed is None or parsed == operation_id or canonical in prefix
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "post-reboot reconciliation artifacts are ambiguous"
            )


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _nonnegative_integer(value: int, label: str) -> None:
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
    "ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION",
    "DEPLOY_POST_REBOOT_RECONCILIATION_FILENAME_SUFFIX",
    "DeployPostRebootArtifactState",
    "DeployPostRebootBranch",
    "DeployPostRebootReconciliation",
    "DeployPostRebootReconciliationReport",
    "DeployPostRebootReconciliationStore",
    "StoredDeployPostRebootReconciliation",
    "deploy_post_reboot_reconciliation_id_from_filename",
    "deploy_post_reboot_reconciliation_path",
    "reconcile_deploy_post_reboot_plan",
]
