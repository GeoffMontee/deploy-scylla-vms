"""Immutable deploy-plan reconciliation after successful ``base-os`` execution.

This internal owner consumes only canonical, operation-bound state.  It proves
the exact authorized base-OS scope completed with strict semantic evidence,
records reboot requirements without handling them, and never invokes a runner,
creates authorization, or advances the common journal.
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
    BASE_OS_EVIDENCE_SCHEMA_VERSION,
    BaseOsEvidence,
    BaseOsHostEvidence,
    BaseOsStatus,
    base_os_variables,
)
from scylla_vms.ansible.commands import ansible_command_intent_digest
from scylla_vms.ansible.deploy_authorization import (
    ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_SCHEMA_VERSION,
    DeployBaseOsAuthorizationScope,
    DeployBaseOsAuthorizationStore,
    StoredDeployBaseOsAuthorization,
    _build_authorization,
    _derive_authorization_scopes,
)
from scylla_vms.ansible.deploy_base_os_execution import (
    ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_BASE_OS_EXECUTION_SCHEMA_VERSION,
    DeployBaseOsEvidenceEntry,
    DeployBaseOsEvidenceStore,
    DeployBaseOsExecutionState,
    DeployBaseOsExecutionStore,
    DeployBaseOsHostEvidence,
    StoredDeployBaseOsEvidence,
    StoredDeployBaseOsExecution,
    _base_os_result_digest,
    _entry_evidence_digest,
)
from scylla_vms.ansible.deploy_host_evidence import PreMutationHostEvidence
from scylla_vms.ansible.deploy_host_reconciliation import (
    ANSIBLE_DEPLOY_HOST_RECONCILIATION_SCHEMA_VERSION,
    DeployHostEvidenceReconciliationStore,
    DeployHostReconciledStep,
    StoredDeployHostEvidenceReconciliation,
    _build_reconciled_steps,
    _build_reconciliation_record,
    _HostReconciliationContext,
    _load_host_reconciliation_context,
)
from scylla_vms.ansible.deploy_plan import (
    ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION,
    DeployConditionState,
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_reconciliation import (
    ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION,
)
from scylla_vms.ansible.registry import (
    OPERATION_PLAYBOOKS,
    CheckMode,
    LimitPolicy,
    get_playbook,
)
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION
from scylla_vms.desired import HostRole, ImageVersionMatch
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

ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-base-os-reconciliation/v1"
)
ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-base-os-reconciliation-report/v1"
)
DEPLOY_BASE_OS_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-base-os-reconciliation.json"
)

_OPERATION = "deploy"
_BASE_OS = "base-os"
_JUMP_CONFIGURE = "jump-host-configure"
_BASE_OS_MAPPING = 3
_JUMP_CONFIGURE_MAPPING = 4
_FINAL_EVIDENCE_MAPPING = len(OPERATION_PLAYBOOKS[_OPERATION])
_NOT_PERFORMED = "not-performed"
_NOT_STARTED = "not-started"
_UNAVAILABLE = "unavailable"
_AUTHORIZATION_CONSUMED = "consumed-by-execution"
_PUBLIC_WORKFLOW_BLOCKER = "public-deploy-workflow-unavailable"
_AUTHORIZATION_BLOCKER = "deploy-authorization-not-collected"
_ORDER_BLOCKER = "ordered-deploy-step-not-reached"
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
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")


class DeployBaseOsReconciliationArtifactState(StrEnum):
    """Immutable reconciliation persistence state."""

    CREATED = "created"
    REUSED = "reused"


class DeployBaseOsReconciledStepStatus(StrEnum):
    """Truthful status after exact base-OS semantic reconciliation."""

    SUCCEEDED = "succeeded"
    EVIDENCE_READY_AUTHORIZATION_REQUIRED = "evidence-ready-authorization-required"
    ELIGIBLE = "eligible"
    BLOCKED = "blocked"
    NOT_PERFORMED = "not-performed"


class DeployBaseOsReconciledEvidenceState(StrEnum):
    """Evidence relationship for one post-base-OS effective step."""

    PREREQUISITE_BOUND = "prerequisite-bound"
    BASE_OS_BOUND = "base-os-bound"
    NON_JUMP_BASE_OS_BOUND = "non-jump-base-os-bound"
    JUMP_HOST_CONFIGURE_BOUND = "jump-host-configure-bound"
    FINAL_ROUTES_CONNECTIVITY_BOUND = "final-routes-connectivity-bound"
    STORAGE_DISCOVERY_BOUND = "storage-discovery-bound"
    STORAGE_PREFLIGHT_BOUND = "storage-preflight-bound"
    STORAGE_PREPARE_BOUND = "storage-prepare-bound"
    STORAGE_POSTCHECK_BOUND = "storage-postcheck-bound"
    SCYLLA_INSTALL_BOUND = "scylla-install-bound"
    SCYLLA_CONFIGURE_BOUND = "scylla-configure-bound"
    NEXT_GATES_EVALUATED = "next-gates-evaluated"
    NOT_PERFORMED = "not-performed"
    NOT_REQUIRED = "not-required"


@dataclass(frozen=True, slots=True)
class DeployBaseOsReconciledStep:
    """Original immutable step identity plus post-base-OS status."""

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
    prior_reconciled_step_digest: str
    status: DeployBaseOsReconciledStepStatus
    evidence_state: DeployBaseOsReconciledEvidenceState
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
            or not isinstance(self.status, DeployBaseOsReconciledStepStatus)
            or not isinstance(self.evidence_state, DeployBaseOsReconciledEvidenceState)
            or self.classification is not definition.classification
            or self.limit_policy is not definition.limit_policy
            or self.serial != definition.serial
            or self.check_mode is not definition.check_mode
            or self.target_role not in {"all", *(role.value for role in HostRole)}
        ):
            raise StatePersistenceError(
                "post-base-os reconciled deploy step policy is invalid"
            )
        if (
            self.target_ids != tuple(sorted(set(self.target_ids)))
            or any(_LOGICAL_ID.fullmatch(item) is None for item in self.target_ids)
            or self.variable_names != tuple(dict.fromkeys(self.variable_names))
            or set(self.variable_names)
            != {variable.name for variable in definition.variables}
            or self.blockers != tuple(sorted(set(self.blockers)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blockers)
        ):
            raise StatePersistenceError(
                "post-base-os reconciled step projection is invalid"
            )
        for value in (
            self.target_digest,
            self.variables_digest,
            self.source_digest,
            self.command_digest,
            self.original_step_digest,
            self.prior_reconciled_step_digest,
        ):
            validate_digest(value, "post-base-os reconciled step digest")
        if self.target_digest != _digest_object(list(self.target_ids)):
            raise StatePersistenceError(
                "post-base-os reconciled target digest conflicts"
            )
        if self.evidence_digest is not None:
            validate_digest(
                self.evidence_digest, "post-base-os reconciled evidence digest"
            )
        self._validate_status()
        if self.condition_state is DeployConditionState.INACTIVE and (
            self.status is not DeployBaseOsReconciledStepStatus.NOT_PERFORMED
            or self.evidence_state
            is not DeployBaseOsReconciledEvidenceState.NOT_REQUIRED
            or self.evidence_digest is not None
            or self.blockers
        ):
            raise StatePersistenceError("post-base-os inactive deploy step is invalid")
        if self.mapping_sequence == _FINAL_EVIDENCE_MAPPING and (
            self.playbook != "evidence-collect"
            or self.status is not DeployBaseOsReconciledStepStatus.NOT_PERFORMED
            or self.evidence_state
            is not DeployBaseOsReconciledEvidenceState.NOT_PERFORMED
            or self.evidence_digest is not None
        ):
            raise StatePersistenceError(
                "post-base-os final host evidence must remain not performed"
            )

    def _validate_status(self) -> None:
        if self.status is DeployBaseOsReconciledStepStatus.SUCCEEDED:
            prerequisite = (
                self.sequence in {1, 2}
                and self.playbook in {"inventory-preflight", "connectivity-check"}
                and self.evidence_state
                is DeployBaseOsReconciledEvidenceState.PREREQUISITE_BOUND
            )
            base_os = (
                self.mapping_sequence == _BASE_OS_MAPPING
                and self.playbook == _BASE_OS
                and self.evidence_state
                is DeployBaseOsReconciledEvidenceState.BASE_OS_BOUND
            )
            non_jump_base_os = (
                self.mapping_sequence == 6
                and self.playbook == _BASE_OS
                and self.condition == "non-jump-managed-hosts"
                and self.evidence_state
                is DeployBaseOsReconciledEvidenceState.NON_JUMP_BASE_OS_BOUND
            )
            jump_host_configure = (
                self.mapping_sequence == _JUMP_CONFIGURE_MAPPING
                and self.playbook == _JUMP_CONFIGURE
                and self.evidence_state
                is DeployBaseOsReconciledEvidenceState.JUMP_HOST_CONFIGURE_BOUND
            )
            final_routes_connectivity = (
                self.mapping_sequence == _JUMP_CONFIGURE_MAPPING + 1
                and self.playbook == "connectivity-check"
                and self.condition == "final-routes"
                and self.evidence_state
                is DeployBaseOsReconciledEvidenceState.FINAL_ROUTES_CONNECTIVITY_BOUND
            )
            storage_discovery = (
                self.mapping_sequence == 7
                and self.playbook == "storage-discover"
                and self.evidence_state
                is DeployBaseOsReconciledEvidenceState.STORAGE_DISCOVERY_BOUND
            )
            storage_preflight = (
                self.mapping_sequence == 8
                and self.playbook == "storage-preflight"
                and self.evidence_state
                is DeployBaseOsReconciledEvidenceState.STORAGE_PREFLIGHT_BOUND
            )
            storage_prepare = (
                self.mapping_sequence == 9
                and self.playbook == "storage-prepare"
                and self.evidence_state
                is DeployBaseOsReconciledEvidenceState.STORAGE_PREPARE_BOUND
            )
            storage_postcheck = (
                self.mapping_sequence == 10
                and self.playbook == "storage-postcheck"
                and self.evidence_state
                is DeployBaseOsReconciledEvidenceState.STORAGE_POSTCHECK_BOUND
            )
            scylla_install = (
                self.mapping_sequence == 11
                and self.playbook == "scylla-install"
                and self.evidence_state
                is DeployBaseOsReconciledEvidenceState.SCYLLA_INSTALL_BOUND
            )
            scylla_configure = (
                self.mapping_sequence == 12
                and self.playbook == "scylla-configure"
                and self.evidence_state
                is DeployBaseOsReconciledEvidenceState.SCYLLA_CONFIGURE_BOUND
            )
            if (
                not (
                    prerequisite
                    or base_os
                    or non_jump_base_os
                    or jump_host_configure
                    or final_routes_connectivity
                    or storage_discovery
                    or storage_preflight
                    or storage_prepare
                    or storage_postcheck
                    or scylla_install
                    or scylla_configure
                )
                or self.evidence_digest is None
                or self.blockers
            ):
                raise StatePersistenceError(
                    "post-base-os succeeded step is not evidence-bound"
                )
            return
        if (
            self.status
            is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        ):
            if (
                self.classification is OperationClassification.READ_ONLY
                or self.evidence_state
                is not DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED
                or self.evidence_digest is None
                or not self.target_ids
                or _AUTHORIZATION_BLOCKER not in self.blockers
                or _CLASS_BLOCKERS[self.classification] not in self.blockers
                or _PUBLIC_WORKFLOW_BLOCKER not in self.blockers
            ):
                raise StatePersistenceError(
                    "post-base-os authorization-required step is invalid"
                )
            return
        if self.status is DeployBaseOsReconciledStepStatus.ELIGIBLE:
            if (
                self.classification is not OperationClassification.READ_ONLY
                or self.evidence_state
                is not DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED
                or self.evidence_digest is None
                or not self.target_ids
                or self.blockers
            ):
                raise StatePersistenceError("post-base-os eligible step is invalid")
            return
        if self.status is DeployBaseOsReconciledStepStatus.BLOCKED:
            if not self.blockers or self.evidence_digest is not None:
                raise StatePersistenceError("post-base-os blocked step is invalid")
            return
        if self.evidence_digest is not None:
            raise StatePersistenceError("post-base-os not-performed step has evidence")

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
            "prior_reconciled_step_digest": self.prior_reconciled_step_digest,
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
    def from_object(cls, value: Mapping[str, object]) -> DeployBaseOsReconciledStep:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "post-base-os reconciled deploy step",
        )
        evidence_digest = value["evidence_digest"]
        if evidence_digest is not None and not isinstance(evidence_digest, str):
            raise StatePersistenceError(
                "post-base-os evidence digest must be a string or null"
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
                prior_reconciled_step_digest=require_string(
                    value, "prior_reconciled_step_digest"
                ),
                status=DeployBaseOsReconciledStepStatus(
                    require_string(value, "status")
                ),
                evidence_state=DeployBaseOsReconciledEvidenceState(
                    require_string(value, "evidence_state")
                ),
                evidence_digest=evidence_digest,
                blockers=_string_tuple(value["blockers"], "blockers"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "post-base-os reconciled step enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployBaseOsReconciliation:
    """Immutable effective view after exact base-OS execution."""

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
    prior_effective_plan_digest: str
    host_reconciliation_artifact_digest: str
    host_reconciliation_record_digest: str
    host_reconciled_plan_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    base_os_authorization_artifact_digest: str
    base_os_authorization_digest: str
    base_os_authorization_scope_digest: str
    base_os_execution_artifact_digest: str
    base_os_evidence_artifact_digest: str
    base_os_execution_binding_digest: str
    base_os_evidence_digest: str
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
    context_schema_version: str = ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
    original_plan_schema_version: str = ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION
    prior_effective_plan_schema_version: str = (
        ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION
    )
    host_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_HOST_RECONCILIATION_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    base_os_authorization_schema_version: str = (
        ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
    )
    base_os_execution_schema_version: str = (
        ANSIBLE_DEPLOY_BASE_OS_EXECUTION_SCHEMA_VERSION
    )
    base_os_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION
            or self.context_schema_version != ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
            or self.original_plan_schema_version != ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION
            or self.prior_effective_plan_schema_version
            != ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION
            or self.host_reconciliation_schema_version
            != ANSIBLE_DEPLOY_HOST_RECONCILIATION_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.base_os_authorization_schema_version
            != ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
            or self.base_os_execution_schema_version
            != ANSIBLE_DEPLOY_BASE_OS_EXECUTION_SCHEMA_VERSION
            or self.base_os_evidence_schema_version
            != ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.reboot_handling_status != _NOT_PERFORMED
            or self.authorization_state != _AUTHORIZATION_CONSUMED
            or self.execution_state != DeployBaseOsExecutionState.SUCCEEDED.value
            or self.next_execution_state != _NOT_STARTED
            or self.final_evidence_state != _NOT_PERFORMED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
        ):
            raise StatePersistenceError(
                "post-base-os reconciliation identity is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for value in (
            self.journal_generation,
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
            _nonnegative_integer(value, "post-base-os reconciliation count")
        if (
            self.journal_generation < 1
            or self.base_os_scope_count < 1
            or self.base_os_host_count < 1
            or self.changed_count > self.base_os_host_count
            or self.already_current_count > self.base_os_host_count
            or self.reboot_required_count > self.base_os_host_count
            or self.reboot_required != (self.reboot_required_count > 0)
            or self.mapping_count != len(OPERATION_PLAYBOOKS[_OPERATION])
            or self.step_count != len(self.steps)
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, len(self.steps) + 1))
        ):
            raise StatePersistenceError("post-base-os reconciliation counts conflict")
        expected_mapping = OPERATION_PLAYBOOKS[_OPERATION]
        if {step.mapping_sequence for step in self.steps} != set(
            range(1, len(expected_mapping) + 1)
        ) or any(
            step.playbook != expected_mapping[step.mapping_sequence - 1].playbook
            or step.condition != expected_mapping[step.mapping_sequence - 1].condition
            for step in self.steps
        ):
            raise StatePersistenceError("post-base-os reconciliation mapping conflicts")
        status_counts = Counter(step.status for step in self.steps)
        blocker_set = tuple(
            sorted({blocker for step in self.steps for blocker in step.blockers})
        )
        if self.reboot_required:
            blocker_set = tuple(
                sorted({*blocker_set, _REBOOT_BLOCKER, _REBOOT_HANDLING_BLOCKER})
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
            or self.succeeded_count != 2 + self.base_os_scope_count
            or self.blocker_set != blocker_set
            or self.blocker_digest != _digest_object(list(blocker_set))
            or self.effective_plan_digest
            != _digest_object([step.to_object() for step in self.steps])
        ):
            raise StatePersistenceError("post-base-os reconciliation summary conflicts")
        for digest_value in _record_digests(self):
            validate_digest(digest_value, "post-base-os reconciliation digest")
        if self.record_digest != _record_digest(self):
            raise StatePersistenceError(
                "post-base-os reconciliation record digest conflicts"
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
    def from_object(cls, value: Mapping[str, object]) -> DeployBaseOsReconciliation:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "post-base-os reconciliation",
        )
        integer_fields = {
            "generation",
            "journal_generation",
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
                    JournalStatus,
                    require_string(value, name),
                    "post-base-os journal status",
                )
            elif name == "journal_phase":
                parsed[name] = _enum(
                    OperationPhase,
                    require_string(value, name),
                    "post-base-os journal phase",
                )
            elif name in {"reboot_required"}:
                parsed[name] = _boolean(item, name)
            elif name == "steps":
                parsed[name] = tuple(
                    DeployBaseOsReconciledStep.from_object(
                        _mapping(step, "post-base-os reconciled step")
                    )
                    for step in _array(item, "post-base-os reconciled steps")
                )
            elif name == "blocker_set":
                parsed[name] = _string_tuple(item, name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployBaseOsReconciliation:
    record: DeployBaseOsReconciliation
    artifact_digest: str


class DeployBaseOsReconciliationStore:
    """Owner-only immutable post-base-OS effective plan."""

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
        self._path = deploy_base_os_reconciliation_path(paths, operation_id)
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
    ) -> StoredDeployBaseOsReconciliation:
        value, artifact_digest = self._file.read()
        record = DeployBaseOsReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or artifact_digest != _artifact_digest(record.to_object())
        ):
            raise StatePersistenceError(
                "post-base-os reconciliation identity conflicts"
            )
        return StoredDeployBaseOsReconciliation(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployBaseOsReconciliation:
        lock.assert_held_for_operation(self._paths, _OPERATION)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployBaseOsReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployBaseOsReconciliation,
        DeployBaseOsReconciliationArtifactState,
    ]:
        lock.assert_held_for_operation(self._paths, _OPERATION)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "post-base-os reconciliation operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError("post-base-os reconciliation is immutable")
            return current, DeployBaseOsReconciliationArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployBaseOsReconciliation(record, artifact_digest),
            DeployBaseOsReconciliationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployBaseOsNextStepSummary:
    """Address-free report grouping for the exact next mapping."""

    playbook: str
    classification: OperationClassification
    instance_count: int
    instance_digest: str
    stable_id_count: int
    stable_id_set_digest: str

    def __post_init__(self) -> None:
        if (
            get_playbook(self.playbook).classification is not self.classification
            or self.instance_count < 1
            or self.stable_id_count < 1
        ):
            raise StatePersistenceError("post-base-os next-step summary is invalid")
        validate_digest(self.instance_digest, "next-step instance digest")
        validate_digest(self.stable_id_set_digest, "next-step stable-ID digest")

    def to_object(self) -> dict[str, object]:
        return {
            "classification": self.classification.value,
            "instance_count": self.instance_count,
            "instance_digest": self.instance_digest,
            "playbook": self.playbook,
            "stable_id_count": self.stable_id_count,
            "stable_id_set_digest": self.stable_id_set_digest,
        }


@dataclass(frozen=True, slots=True)
class DeployBaseOsReconciliationReport:
    """Strict redacted projection of post-base-OS reconciliation."""

    operation_id: uuid.UUID
    artifact_state: DeployBaseOsReconciliationArtifactState
    reconciliation_artifact_digest: str
    reconciliation_record_digest: str
    effective_plan_digest: str
    prior_reconciliation_artifact_digest: str
    base_os_authorization_artifact_digest: str
    base_os_execution_artifact_digest: str
    base_os_evidence_artifact_digest: str
    base_os_evidence_digest: str
    base_os_scope_count: int
    base_os_host_count: int
    base_os_host_set_digest: str
    changed_count: int
    already_current_count: int
    reboot_required_count: int
    reboot_required: bool
    reboot_handling_status: str
    total_count: int
    succeeded_count: int
    authorization_required_count: int
    eligible_count: int
    blocked_count: int
    not_performed_count: int
    next_authorization_required: tuple[DeployBaseOsNextStepSummary, ...]
    next_eligible: tuple[DeployBaseOsNextStepSummary, ...]
    blocker_set: tuple[str, ...]
    blocker_digest: str
    final_evidence_state: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    authorization_state: str
    execution_state: str
    next_execution_state: str
    finalization_state: str
    public_workflow_state: str
    reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION
    )
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
    )
    execution_schema_version: str = ANSIBLE_DEPLOY_BASE_OS_EXECUTION_SCHEMA_VERSION
    evidence_schema_version: str = ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_REPORT_SCHEMA_VERSION
            or self.reconciliation_schema_version
            != ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_BASE_OS_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_SCHEMA_VERSION
            or self.reboot_handling_status != _NOT_PERFORMED
            or self.final_evidence_state != _NOT_PERFORMED
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.authorization_state != _AUTHORIZATION_CONSUMED
            or self.execution_state != DeployBaseOsExecutionState.SUCCEEDED.value
            or self.next_execution_state != _NOT_STARTED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
        ):
            raise StatePersistenceError("post-base-os reconciliation report is invalid")
        for value in (
            self.base_os_scope_count,
            self.base_os_host_count,
            self.changed_count,
            self.already_current_count,
            self.reboot_required_count,
            self.total_count,
            self.succeeded_count,
            self.authorization_required_count,
            self.eligible_count,
            self.blocked_count,
            self.not_performed_count,
        ):
            _nonnegative_integer(value, "post-base-os report count")
        if (
            self.base_os_scope_count < 1
            or self.base_os_host_count < 1
            or self.reboot_required != (self.reboot_required_count > 0)
            or self.total_count
            != self.succeeded_count
            + self.authorization_required_count
            + self.eligible_count
            + self.blocked_count
            + self.not_performed_count
            or sum(item.instance_count for item in self.next_authorization_required)
            != self.authorization_required_count
            or sum(item.instance_count for item in self.next_eligible)
            != self.eligible_count
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blocker_set)
        ):
            raise StatePersistenceError(
                "post-base-os reconciliation report summary conflicts"
            )
        for digest_value in (
            self.reconciliation_artifact_digest,
            self.reconciliation_record_digest,
            self.effective_plan_digest,
            self.prior_reconciliation_artifact_digest,
            self.base_os_authorization_artifact_digest,
            self.base_os_execution_artifact_digest,
            self.base_os_evidence_artifact_digest,
            self.base_os_evidence_digest,
            self.base_os_host_set_digest,
            self.blocker_digest,
        ):
            validate_digest(digest_value, "post-base-os report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "artifact_state": self.artifact_state.value,
            "base_os": {
                "already_current_count": self.already_current_count,
                "authorization_artifact_digest": (
                    self.base_os_authorization_artifact_digest
                ),
                "changed_count": self.changed_count,
                "evidence_artifact_digest": self.base_os_evidence_artifact_digest,
                "evidence_digest": self.base_os_evidence_digest,
                "evidence_schema_version": self.evidence_schema_version,
                "execution_artifact_digest": self.base_os_execution_artifact_digest,
                "execution_schema_version": self.execution_schema_version,
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
                "authorization_required": [
                    item.to_object() for item in self.next_authorization_required
                ],
                "eligible": [item.to_object() for item in self.next_eligible],
                "execution_state": self.next_execution_state,
            },
            "operation_id": str(self.operation_id),
            "provenance": {
                "prior_reconciliation_artifact_digest": (
                    self.prior_reconciliation_artifact_digest
                ),
                "reconciliation_artifact_digest": (self.reconciliation_artifact_digest),
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
                "total_count": self.total_count,
            },
        }


@dataclass(frozen=True, slots=True)
class _BaseOsReconciliationContext:
    host: _HostReconciliationContext
    prior: StoredDeployHostEvidenceReconciliation
    authorization: StoredDeployBaseOsAuthorization
    execution: StoredDeployBaseOsExecution
    evidence: StoredDeployBaseOsEvidence
    entries_by_sequence: Mapping[int, DeployBaseOsEvidenceEntry]
    base_os_evidence_digest: str
    stable_ids: tuple[str, ...]
    changed_count: int
    already_current_count: int
    reboot_required_count: int


def reconcile_deploy_base_os_result(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployBaseOsReconciliationReport:
    """Persist the immutable post-base-OS effective plan."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    lock.assert_held_for_operation(paths, _OPERATION)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_reconciliation_artifacts(paths, operation_id)
    context = _load_context(paths, operation_id, lock=lock)
    metadata = context.host.loaded.planning.base.deploy.metadata.record
    store = DeployBaseOsReconciliationStore(paths, operation_id)
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
        raise StateConflictError("post-base-os reconciliation is immutable")
    try:
        stored, state = store.write_locked(record, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "post-base-os reconciliation persistence failed"
        ) from error
    return _build_report(stored, state=state)


def deploy_base_os_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the sole canonical post-base-OS reconciliation path."""

    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_BASE_OS_RECONCILIATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError("post-base-os reconciliation path is not canonical")
    return path


def deploy_base_os_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(DEPLOY_BASE_OS_RECONCILIATION_FILENAME_SUFFIX):
        return None
    value = name[: -len(DEPLOY_BASE_OS_RECONCILIATION_FILENAME_SUFFIX)]
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
) -> _BaseOsReconciliationContext:
    host = _load_host_reconciliation_context(paths, operation_id, lock=lock)
    planning = host.loaded.planning
    journal = planning.base.deploy.journal
    metadata = planning.base.deploy.metadata.record
    if (
        journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
    ):
        raise StateConflictError(
            "post-base-os reconciliation requires the unchanged VERIFY journal"
        )
    prior_store = DeployHostEvidenceReconciliationStore(paths, operation_id)
    authorization_store = DeployBaseOsAuthorizationStore(paths, operation_id)
    execution_store = DeployBaseOsExecutionStore(paths, operation_id)
    evidence_store = DeployBaseOsEvidenceStore(paths, operation_id)
    for path in (
        prior_store.path,
        authorization_store.path,
        execution_store.path,
        evidence_store.path,
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                "post-base-os reconciliation requires the complete base-os chain"
            )
    prior = prior_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_prior = _build_reconciliation_record(
        host,
        steps=_build_reconciled_steps(host),
        created_at=prior.record.created_at,
    )
    if prior.record != expected_prior:
        raise StateConflictError(
            "post-base-os reconciliation prior reconciliation drifted"
        )
    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    scopes = _derive_authorization_scopes(prior)
    expected_authorization = _build_authorization(
        prior,
        scopes=scopes,
        proof=authorization.record.proof,
        created_at=authorization.record.created_at,
    )
    if authorization.record != expected_authorization:
        raise StateConflictError("post-base-os reconciliation authorization drifted")
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
        base_os_evidence_digest,
        stable_ids,
        changed_count,
        already_current_count,
        reboot_required_count,
    ) = _validate_complete_base_os(
        host,
        prior,
        authorization,
        execution,
        evidence,
    )
    return _BaseOsReconciliationContext(
        host,
        prior,
        authorization,
        execution,
        evidence,
        entries_by_sequence,
        base_os_evidence_digest,
        stable_ids,
        changed_count,
        already_current_count,
        reboot_required_count,
    )


def _validate_complete_base_os(
    host: _HostReconciliationContext,
    prior: StoredDeployHostEvidenceReconciliation,
    authorization: StoredDeployBaseOsAuthorization,
    execution: StoredDeployBaseOsExecution,
    evidence: StoredDeployBaseOsEvidence,
) -> tuple[
    Mapping[int, DeployBaseOsEvidenceEntry],
    str,
    tuple[str, ...],
    int,
    int,
    int,
]:
    planning = host.loaded.planning
    deploy = planning.base.deploy
    trust = planning.base.trust
    journal = deploy.journal
    readiness = planning.readiness
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
        or binding.host_reconciliation_artifact_digest != prior.artifact_digest
        or binding.host_reconciliation_record_digest != prior.record.record_digest
        or binding.host_reconciled_plan_digest != prior.record.effective_plan_digest
        or binding.readiness_artifact_digest != readiness.artifact_digest
        or binding.readiness_record_digest != readiness.record.record_digest
        or binding.catalog_digest != host.loaded.catalog_digest
        or binding.source_version != host.loaded.source.version
        or binding.source_digest != host.loaded.source.digest
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
        or execution.record.state is not DeployBaseOsExecutionState.SUCCEEDED
        or not execution.record.authorization_consumed
        or not execution.record.all_scopes_completed
        or execution.record.invocation_count != len(scopes)
        or len(execution.record.attempts) != len(scopes)
        or evidence.record.generation != len(scopes)
        or len(evidence.record.entries) != len(scopes)
    ):
        raise StateConflictError(
            "post-base-os reconciliation execution provenance is incomplete or stale"
        )
    inventory_hosts = {
        item.logical_id: item for item in deploy.inventory.record.inventory.hosts
    }
    pre_mutation_hosts = _pre_mutation_hosts(host)
    desired_filters = dict(deploy.metadata.record.desired_spec.image_filters)
    source_digest = _playbook_source_digest(host.loaded.source, _BASE_OS)
    definition = get_playbook(_BASE_OS)
    scope_values: list[dict[str, object]] = []
    entries_by_sequence: dict[int, DeployBaseOsEvidenceEntry] = {}
    all_hosts: list[DeployBaseOsHostEvidence] = []
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
                    "post-base-os reconciliation target evidence is unavailable"
                )
            image_filter = desired_filters.get(inventory_host.role)
            if (
                pre_mutation.role is not inventory_host.role
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
                    "post-base-os reconciliation target provenance drifted"
                )
            if selected_filter is not None and image_filter != selected_filter:
                raise StateConflictError(
                    "post-base-os reconciliation scope mixes image filters"
                )
            selected_filter = image_filter
            assert pre_mutation.architecture is not None
            image_architecture = _SAFE_GUEST_ARCHITECTURES[pre_mutation.architecture]
            image_architectures.add(image_architecture)
            expected_hosts.append((pre_mutation, image_architecture))
        if selected_filter is None or len(image_architectures) != 1:
            raise StateConflictError(
                "post-base-os reconciliation scope mixes architectures"
            )
        variables = base_os_variables(
            selected_filter,
            next(iter(image_architectures)),
        )
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
            or attempt.state is not DeployBaseOsExecutionState.SUCCEEDED
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
            or tuple(item.logical_id for item in entry.hosts) != scope.target_ids
        ):
            raise StateConflictError(
                "post-base-os reconciliation execution or evidence conflicts"
            )
        for persisted, (pre_mutation, image_architecture) in zip(
            entry.hosts,
            expected_hosts,
            strict=True,
        ):
            _validate_successful_host(
                persisted,
                pre_mutation,
                image_architecture=image_architecture,
            )
        expected_status = _aggregate_status(entry.hosts)
        result_evidence = BaseOsEvidence(
            expected_status,
            tuple(_reconstruct_result_host(item) for item in entry.hosts),
        )
        if (
            entry.status is not expected_status
            or entry.result_digest != _base_os_result_digest(result_evidence)
            or scope.sequence in entries_by_sequence
        ):
            raise StateConflictError(
                "post-base-os reconciliation semantic evidence conflicts"
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
        or tuple(item.logical_id for item in all_hosts) != stable_ids
    ):
        raise StateConflictError(
            "post-base-os reconciliation execution scope digest drifted"
        )
    return (
        entries_by_sequence,
        _digest_object([entry.evidence_digest for entry in evidence.record.entries]),
        stable_ids,
        sum(item.changed for item in all_hosts),
        sum(item.status is BaseOsStatus.NO_CHANGE for item in all_hosts),
        sum(item.reboot_required for item in all_hosts),
    )


def _validate_scope_identity(scope: DeployBaseOsAuthorizationScope) -> None:
    if (
        scope.mapping_sequence != _BASE_OS_MAPPING
        or scope.playbook != _BASE_OS
        or scope.classification is not OperationClassification.MUTATING
        or not scope.target_ids
    ):
        raise StateConflictError(
            "post-base-os reconciliation authorization scope conflicts"
        )


def _pre_mutation_hosts(
    context: _HostReconciliationContext,
) -> Mapping[str, PreMutationHostEvidence]:
    result: dict[str, PreMutationHostEvidence] = {}
    for entry in context.evidence.record.entries:
        for host in entry.hosts:
            if host.logical_id in result:
                raise StateConflictError(
                    "post-base-os reconciliation pre-mutation evidence is duplicated"
                )
            result[host.logical_id] = host
    return result


def _validate_successful_host(
    host: DeployBaseOsHostEvidence,
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
            "post-base-os reconciliation host success evidence conflicts"
        )


def _aggregate_status(
    hosts: tuple[DeployBaseOsHostEvidence, ...],
) -> BaseOsStatus:
    if any(item.reboot_required for item in hosts):
        return BaseOsStatus.REBOOT_REQUIRED
    if any(item.changed for item in hosts):
        return BaseOsStatus.CHANGED
    return BaseOsStatus.NO_CHANGE


def _reconstruct_result_host(host: DeployBaseOsHostEvidence) -> BaseOsHostEvidence:
    reason = {
        BaseOsStatus.NO_CHANGE: "already-current",
        BaseOsStatus.CHANGED: "applied",
        BaseOsStatus.REBOOT_REQUIRED: "reboot-required",
    }.get(host.status)
    if reason is None:
        raise StateConflictError(
            "post-base-os reconciliation host result is not successful"
        )
    return BaseOsHostEvidence(
        host.logical_id,
        host.status,
        host.changed,
        host.reboot_required,
        reason,
    )


def _build_steps(
    context: _BaseOsReconciliationContext,
) -> tuple[DeployBaseOsReconciledStep, ...]:
    executed = context.entries_by_sequence
    prior_steps = context.prior.record.steps
    executed_sequences = tuple(sorted(executed))
    if not executed_sequences:
        raise StateConflictError(
            "post-base-os reconciliation has no completed base-os scope"
        )
    remaining_active_mappings = tuple(
        sorted(
            {
                step.mapping_sequence
                for step in prior_steps
                if step.sequence not in executed
                and step.condition_state is DeployConditionState.ACTIVE
                and step.mapping_sequence > _BASE_OS_MAPPING
            }
        )
    )
    next_mapping = remaining_active_mappings[0] if remaining_active_mappings else None
    reboot_required = context.reboot_required_count > 0
    result: list[DeployBaseOsReconciledStep] = []
    for prior in prior_steps:
        if prior.sequence in {1, 2}:
            status = DeployBaseOsReconciledStepStatus.SUCCEEDED
            evidence_state = DeployBaseOsReconciledEvidenceState.PREREQUISITE_BOUND
            evidence_digest = prior.evidence_digest
            blockers: tuple[str, ...] = ()
        elif prior.sequence in executed:
            entry = executed[prior.sequence]
            if (
                prior.mapping_sequence != _BASE_OS_MAPPING
                or prior.playbook != _BASE_OS
                or prior.target_ids != tuple(item.logical_id for item in entry.hosts)
            ):
                raise StateConflictError(
                    "post-base-os reconciliation executed step identity drifted"
                )
            status = DeployBaseOsReconciledStepStatus.SUCCEEDED
            evidence_state = DeployBaseOsReconciledEvidenceState.BASE_OS_BOUND
            evidence_digest = entry.evidence_digest
            blockers = ()
        elif prior.condition_state is DeployConditionState.INACTIVE:
            status = DeployBaseOsReconciledStepStatus.NOT_PERFORMED
            evidence_state = DeployBaseOsReconciledEvidenceState.NOT_REQUIRED
            evidence_digest = None
            blockers = ()
        elif prior.mapping_sequence == _FINAL_EVIDENCE_MAPPING:
            status = DeployBaseOsReconciledStepStatus.NOT_PERFORMED
            evidence_state = DeployBaseOsReconciledEvidenceState.NOT_PERFORMED
            evidence_digest = None
            blockers = tuple(sorted({*prior.blockers, _ORDER_BLOCKER}))
        elif reboot_required:
            status = DeployBaseOsReconciledStepStatus.BLOCKED
            evidence_state = DeployBaseOsReconciledEvidenceState.NOT_PERFORMED
            evidence_digest = None
            blockers = tuple(
                sorted(
                    {
                        *prior.blockers,
                        _ORDER_BLOCKER,
                        _REBOOT_BLOCKER,
                        _REBOOT_HANDLING_BLOCKER,
                    }
                )
            )
        elif prior.mapping_sequence == next_mapping and _next_gate_ready(
            prior, context
        ):
            evidence_digest = _next_gate_digest(prior, context)
            evidence_state = DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED
            if prior.classification is OperationClassification.READ_ONLY:
                status = DeployBaseOsReconciledStepStatus.ELIGIBLE
                blockers = ()
            else:
                status = DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
                blockers = tuple(
                    sorted(
                        {
                            *(
                                blocker
                                for blocker in prior.blockers
                                if blocker != "base-os-evidence-not-performed"
                            ),
                            _AUTHORIZATION_BLOCKER,
                            _CLASS_BLOCKERS[prior.classification],
                            _PUBLIC_WORKFLOW_BLOCKER,
                        }
                    )
                )
        elif prior.classification is OperationClassification.READ_ONLY:
            status = DeployBaseOsReconciledStepStatus.NOT_PERFORMED
            evidence_state = DeployBaseOsReconciledEvidenceState.NOT_PERFORMED
            evidence_digest = None
            blockers = tuple(sorted({*prior.blockers, _ORDER_BLOCKER}))
        else:
            status = DeployBaseOsReconciledStepStatus.BLOCKED
            evidence_state = DeployBaseOsReconciledEvidenceState.NOT_PERFORMED
            evidence_digest = None
            blockers = tuple(sorted({*prior.blockers, _ORDER_BLOCKER}))
        result.append(
            _reconciled_step(
                prior,
                status=status,
                evidence_state=evidence_state,
                evidence_digest=evidence_digest,
                blockers=blockers,
            )
        )
    return tuple(result)


def _next_gate_ready(
    step: DeployHostReconciledStep,
    context: _BaseOsReconciliationContext,
) -> bool:
    # This slice can supersede only the exact base-OS prerequisite.  Current
    # trust/routes/readiness are independently revalidated by the canonical
    # loader; no pre-mutation capacity, storage, package, or health fact is
    # promoted across the mutation boundary.
    return (
        step.mapping_sequence == _JUMP_CONFIGURE_MAPPING
        and step.playbook == _JUMP_CONFIGURE
        and step.condition_state is DeployConditionState.ACTIVE
        and bool(step.target_ids)
        and set(step.target_ids).issubset(context.stable_ids)
    )


def _next_gate_digest(
    step: DeployHostReconciledStep,
    context: _BaseOsReconciliationContext,
) -> str:
    planning = context.host.loaded.planning
    return _digest_object(
        {
            "base_os_evidence_digest": context.base_os_evidence_digest,
            "playbook": step.playbook,
            "readiness_record_digest": planning.readiness.record.record_digest,
            "sequence": step.sequence,
            "target_digest": step.target_digest,
            "trust_artifact_digest": planning.base.trust.digest,
            "trust_entries_digest": planning.base.trust.record.entries_digest,
        }
    )


def _reconciled_step(
    prior: DeployHostReconciledStep,
    *,
    status: DeployBaseOsReconciledStepStatus,
    evidence_state: DeployBaseOsReconciledEvidenceState,
    evidence_digest: str | None,
    blockers: tuple[str, ...],
) -> DeployBaseOsReconciledStep:
    return DeployBaseOsReconciledStep(
        sequence=prior.sequence,
        mapping_sequence=prior.mapping_sequence,
        playbook=prior.playbook,
        condition=prior.condition,
        condition_state=prior.condition_state,
        classification=prior.classification,
        target_role=prior.target_role,
        target_ids=prior.target_ids,
        target_digest=prior.target_digest,
        limit_policy=prior.limit_policy,
        serial=prior.serial,
        check_mode=prior.check_mode,
        variable_names=prior.variable_names,
        variables_digest=prior.variables_digest,
        source_digest=prior.source_digest,
        command_digest=prior.command_digest,
        original_step_digest=prior.original_step_digest,
        prior_reconciled_step_digest=_digest_object(prior.to_object()),
        status=status,
        evidence_state=evidence_state,
        evidence_digest=evidence_digest,
        blockers=blockers,
    )


def _build_record(
    context: _BaseOsReconciliationContext,
    *,
    steps: tuple[DeployBaseOsReconciledStep, ...],
    created_at: str,
) -> DeployBaseOsReconciliation:
    host = context.host
    loaded = host.loaded
    planning = loaded.planning
    deploy = planning.base.deploy
    journal = deploy.journal
    metadata = deploy.metadata.record
    status_counts = Counter(step.status for step in steps)
    blocker_set = {blocker for step in steps for blocker in step.blockers}
    if context.reboot_required_count:
        blocker_set.update({_REBOOT_BLOCKER, _REBOOT_HANDLING_BLOCKER})
    blocker_values = tuple(sorted(blocker_set))
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
        "prior_effective_plan_artifact_digest": (host.prior_effective.artifact_digest),
        "prior_effective_plan_digest": (
            host.prior_effective.record.effective_plan_digest
        ),
        "host_reconciliation_artifact_digest": context.prior.artifact_digest,
        "host_reconciliation_record_digest": context.prior.record.record_digest,
        "host_reconciled_plan_digest": (context.prior.record.effective_plan_digest),
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": planning.readiness.record.record_digest,
        "base_os_authorization_artifact_digest": (
            context.authorization.artifact_digest
        ),
        "base_os_authorization_digest": (
            context.authorization.record.authorization_digest
        ),
        "base_os_authorization_scope_digest": (
            context.authorization.record.authorization_scope_digest
        ),
        "base_os_execution_artifact_digest": context.execution.artifact_digest,
        "base_os_evidence_artifact_digest": context.evidence.artifact_digest,
        "base_os_execution_binding_digest": (
            context.execution.record.binding.binding_digest
        ),
        "base_os_evidence_digest": context.base_os_evidence_digest,
        "catalog_digest": loaded.catalog_digest,
        "ansible_source_version": loaded.source.version,
        "ansible_source_digest": loaded.source.digest,
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
        "succeeded_count": status_counts[DeployBaseOsReconciledStepStatus.SUCCEEDED],
        "authorization_required_count": status_counts[
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        ],
        "eligible_count": status_counts[DeployBaseOsReconciledStepStatus.ELIGIBLE],
        "blocked_count": status_counts[DeployBaseOsReconciledStepStatus.BLOCKED],
        "not_performed_count": status_counts[
            DeployBaseOsReconciledStepStatus.NOT_PERFORMED
        ],
        "blocker_set": blocker_values,
        "blocker_digest": _digest_object(list(blocker_values)),
        "effective_plan_digest": _digest_object([step.to_object() for step in steps]),
        "authorization_state": _AUTHORIZATION_CONSUMED,
        "execution_state": DeployBaseOsExecutionState.SUCCEEDED.value,
        "next_execution_state": _NOT_STARTED,
        "final_evidence_state": _NOT_PERFORMED,
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(values)
    return DeployBaseOsReconciliation(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployBaseOsReconciliation,
    *,
    state: DeployBaseOsReconciliationArtifactState,
) -> DeployBaseOsReconciliationReport:
    record = stored.record
    return DeployBaseOsReconciliationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        reconciliation_artifact_digest=stored.artifact_digest,
        reconciliation_record_digest=record.record_digest,
        effective_plan_digest=record.effective_plan_digest,
        prior_reconciliation_artifact_digest=(
            record.host_reconciliation_artifact_digest
        ),
        base_os_authorization_artifact_digest=(
            record.base_os_authorization_artifact_digest
        ),
        base_os_execution_artifact_digest=(record.base_os_execution_artifact_digest),
        base_os_evidence_artifact_digest=(record.base_os_evidence_artifact_digest),
        base_os_evidence_digest=record.base_os_evidence_digest,
        base_os_scope_count=record.base_os_scope_count,
        base_os_host_count=record.base_os_host_count,
        base_os_host_set_digest=record.base_os_host_set_digest,
        changed_count=record.changed_count,
        already_current_count=record.already_current_count,
        reboot_required_count=record.reboot_required_count,
        reboot_required=record.reboot_required,
        reboot_handling_status=record.reboot_handling_status,
        total_count=record.step_count,
        succeeded_count=record.succeeded_count,
        authorization_required_count=record.authorization_required_count,
        eligible_count=record.eligible_count,
        blocked_count=record.blocked_count,
        not_performed_count=record.not_performed_count,
        next_authorization_required=_next_summaries(
            record.steps,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        ),
        next_eligible=_next_summaries(
            record.steps,
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
        ),
        blocker_set=record.blocker_set,
        blocker_digest=record.blocker_digest,
        final_evidence_state=record.final_evidence_state,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        authorization_state=record.authorization_state,
        execution_state=record.execution_state,
        next_execution_state=record.next_execution_state,
        finalization_state=record.finalization_state,
        public_workflow_state=record.public_workflow_state,
    )


def _next_summaries(
    steps: tuple[DeployBaseOsReconciledStep, ...],
    status: DeployBaseOsReconciledStepStatus,
) -> tuple[DeployBaseOsNextStepSummary, ...]:
    grouped: dict[
        tuple[str, OperationClassification], list[DeployBaseOsReconciledStep]
    ] = {}
    for step in steps:
        if step.status is status:
            grouped.setdefault((step.playbook, step.classification), []).append(step)
    result: list[DeployBaseOsNextStepSummary] = []
    for (playbook, classification), selected in sorted(
        grouped.items(),
        key=lambda item: (item[0][0], item[0][1].value),
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


def _record_digests(record: DeployBaseOsReconciliation) -> tuple[str, ...]:
    return (
        record.request_digest,
        record.journal_digest,
        record.context_artifact_digest,
        record.context_record_digest,
        record.original_plan_artifact_digest,
        record.original_plan_record_digest,
        record.prior_effective_plan_artifact_digest,
        record.prior_effective_plan_digest,
        record.host_reconciliation_artifact_digest,
        record.host_reconciliation_record_digest,
        record.host_reconciled_plan_digest,
        record.readiness_artifact_digest,
        record.readiness_record_digest,
        record.base_os_authorization_artifact_digest,
        record.base_os_authorization_digest,
        record.base_os_authorization_scope_digest,
        record.base_os_execution_artifact_digest,
        record.base_os_evidence_artifact_digest,
        record.base_os_execution_binding_digest,
        record.base_os_evidence_digest,
        record.catalog_digest,
        record.ansible_source_digest,
        record.base_os_host_set_digest,
        record.blocker_digest,
        record.effective_plan_digest,
        record.record_digest,
    )


def _record_digest(record: DeployBaseOsReconciliation) -> str:
    value = record.to_object()
    value["record_digest"] = ""
    return _digest_object(value)


def _record_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployBaseOsReconciliation.__dataclass_fields__.items():
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


def _require_canonical_paths(paths: StatePaths) -> None:
    if StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths:
        raise StatePersistenceError(
            "post-base-os reconciliation paths are not canonical"
        )


def _refuse_ambiguous_reconciliation_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list post-base-os reconciliation artifacts"
        ) from error
    canonical = str(operation_id)
    for entry in entries:
        if not entry.name.endswith(DEPLOY_BASE_OS_RECONCILIATION_FILENAME_SUFFIX):
            continue
        prefix = entry.name[: -len(DEPLOY_BASE_OS_RECONCILIATION_FILENAME_SUFFIX)]
        try:
            parsed = uuid.UUID(prefix)
        except ValueError:
            continue
        if parsed == operation_id and prefix != canonical:
            validate_state_file(entry)
            raise StateConflictError(
                "post-base-os reconciliation artifacts are ambiguous"
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


def _enum(
    enum_type: type[StrEnum],
    value: str,
    label: str,
) -> StrEnum:
    try:
        return enum_type(value)
    except ValueError as error:
        raise StatePersistenceError(f"{label} is invalid") from error


__all__ = [
    "ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION",
    "DEPLOY_BASE_OS_RECONCILIATION_FILENAME_SUFFIX",
    "DeployBaseOsNextStepSummary",
    "DeployBaseOsReconciledEvidenceState",
    "DeployBaseOsReconciledStep",
    "DeployBaseOsReconciledStepStatus",
    "DeployBaseOsReconciliation",
    "DeployBaseOsReconciliationArtifactState",
    "DeployBaseOsReconciliationReport",
    "DeployBaseOsReconciliationStore",
    "StoredDeployBaseOsReconciliation",
    "deploy_base_os_reconciliation_id_from_filename",
    "deploy_base_os_reconciliation_path",
    "reconcile_deploy_base_os_result",
]
