"""Immutable reconciliation after Manager-local backend package installation.

This subprocess-free owner reloads the complete canonical package-install
chain, requires one exact terminal-success result, and evaluates only the
immediate next boundary from the immutable backend installation plan.
"""

from __future__ import annotations

import os
import re
import uuid
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, is_dataclass
from datetime import UTC, datetime
from enum import Enum, StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.deploy_manager_backend_installation_plan import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_STEP_SCHEMA_VERSION,
    DeployManagerBackendInstallationPlanStatus,
    DeployManagerBackendInstallationPlanStep,
    DeployManagerBackendInstallationSourceState,
    StoredDeployManagerBackendInstallationContext,
    StoredDeployManagerBackendInstallationPlan,
    _build_plan_record,
    _build_plan_steps,
)
from scylla_vms.ansible.deploy_manager_backend_local_install_authorization import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCHEMA_VERSION,
    DeployManagerBackendLocalInstallAuthorizationStore,
    StoredDeployManagerBackendLocalInstallAuthorization,
    _AuthorizationContext,
    _build_authorization,
    _build_payload,
    _derive_authorization_scope,
    _derive_package_provenance,
    _load_authorization_context,
)
from scylla_vms.ansible.deploy_manager_backend_local_install_execution import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_SCHEMA_VERSION,
    DeployManagerBackendLocalInstallEvidenceEntry,
    DeployManagerBackendLocalInstallEvidenceStore,
    DeployManagerBackendLocalInstallExecutionState,
    DeployManagerBackendLocalInstallExecutionStore,
    StoredDeployManagerBackendLocalInstallEvidence,
    StoredDeployManagerBackendLocalInstallExecution,
)
from scylla_vms.ansible.deploy_manager_backend_preflight_execution import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION,
)
from scylla_vms.ansible.deploy_manager_backend_preflight_reconciliation import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION,
)
from scylla_vms.ansible.deploy_plan import _digest_object, _require_operation_id
from scylla_vms.ansible.manager_backend_local_install import (
    MANAGER_BACKEND_LOCAL_INSTALL_FORBIDDEN_ACTIONS,
    ManagerBackendLocalInstallStatus,
)
from scylla_vms.ansible.scylla_install import (
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_PACKAGES,
    SCYLLA_RELEASE_LINE,
    SCYLLA_REPOSITORY_DEFINITION_DIGEST,
    SCYLLA_SIGNING_KEY_DIGEST,
)
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION
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

ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_STEP_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-manager-backend-local-install-step/v1"
)
ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-manager-backend-local-install-"
    "reconciliation/v1"
)
ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-manager-backend-local-install-"
    "reconciliation-report/v1"
)

DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-post-manager-backend-local-install-reconciliation.json"
)

_OPERATION = "deploy"
_STAGE = "post-manager-backend-local-package-install-reconciliation"
_PACKAGE_EVIDENCE_STATE = "package-install-evidence-bound"
_NEXT_EVIDENCE_STATE = "current-evidence-evaluated"
_NOT_PERFORMED = "not-performed"
_NOT_STARTED = "not-started"
_UNAVAILABLE = "unavailable"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")
_AUTHORIZATION_BLOCKER = "deploy-authorization-not-collected"
_PUBLIC_WORKFLOW_BLOCKER = "public-deploy-workflow-unavailable"
_CLASS_BLOCKERS = {
    OperationClassification.MUTATING: "mutating-deploy-execution-unavailable",
    OperationClassification.SENSITIVE: "sensitive-deploy-execution-unavailable",
    OperationClassification.DESTRUCTIVE: "destructive-deploy-execution-unavailable",
}
_REQUIRED_UNRESOLVED_BLOCKERS = frozenset(
    {
        "manager-backend-capacity-policy-unknown",
        "manager-backend-file-policy-unapproved",
        "manager-backend-keyspace-rf-schema-policy-unapproved",
        "manager-backend-recovery-semantics-unapproved",
        "manager-backend-scyllamgr-setup-unapproved",
        "manager-backend-tuning-suitability-unknown",
    }
)


class DeployPostManagerBackendLocalInstallArtifactState(StrEnum):
    """Immutable reconciliation persistence result."""

    CREATED = "created"
    REUSED = "reused"


class DeployPostManagerBackendLocalInstallStepStatus(StrEnum):
    """Closed post-package boundary state."""

    SUCCEEDED = "succeeded"
    ELIGIBLE = "eligible"
    EVIDENCE_READY_AUTHORIZATION_REQUIRED = "evidence-ready-authorization-required"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class DeployPostManagerBackendLocalInstallStep:
    """One original installation boundary plus its reconciled state."""

    sequence: int
    boundary: str
    classification: OperationClassification
    target_ids: tuple[str, ...]
    target_count: int
    target_set_digest: str
    package_reference_digest: str
    storage_decision_digest: str
    prerequisite_gate_set_digest: str
    source_state: DeployManagerBackendInstallationSourceState
    source_digest: str | None
    source_contract_state: str
    authorization_requirement: str
    performance_state: str
    original_status: DeployManagerBackendInstallationPlanStatus
    original_blockers: tuple[str, ...]
    original_blocker_digest: str
    original_step_digest: str
    status: DeployPostManagerBackendLocalInstallStepStatus
    evidence_state: str
    evidence_digest: str | None
    blockers: tuple[str, ...]
    blocker_digest: str
    step_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_STEP_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_STEP_SCHEMA_VERSION
            or self.sequence < 1
            or not self.boundary
            or self.target_ids != tuple(sorted(set(self.target_ids)))
            or any(_LOGICAL_ID.fullmatch(item) is None for item in self.target_ids)
            or self.target_count != len(self.target_ids)
            or self.target_set_digest != _digest_object(list(self.target_ids))
            or self.performance_state != _NOT_PERFORMED
            or self.original_blockers != tuple(sorted(set(self.original_blockers)))
            or self.original_blocker_digest
            != _digest_object(list(self.original_blockers))
            or self.blockers != tuple(sorted(set(self.blockers)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blockers)
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.step_digest != _record_digest(self, "step_digest")
        ):
            raise StatePersistenceError(
                "post-Manager-backend package reconciliation step conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "post-Manager-backend package step digest")
        self._validate_status()

    def _validate_status(self) -> None:
        if self.status is DeployPostManagerBackendLocalInstallStepStatus.SUCCEEDED:
            valid = (
                self.evidence_state == _PACKAGE_EVIDENCE_STATE
                and self.evidence_digest is not None
                and not self.blockers
            )
        elif self.status is DeployPostManagerBackendLocalInstallStepStatus.ELIGIBLE:
            valid = (
                self.classification is OperationClassification.READ_ONLY
                and self.evidence_state == _NEXT_EVIDENCE_STATE
                and self.evidence_digest is not None
                and self.source_state
                is DeployManagerBackendInstallationSourceState.AVAILABLE
                and not self.blockers
            )
        elif (
            self.status
            is DeployPostManagerBackendLocalInstallStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        ):
            valid = (
                self.classification is not OperationClassification.READ_ONLY
                and self.evidence_state == _NEXT_EVIDENCE_STATE
                and self.evidence_digest is not None
                and self.source_state
                is DeployManagerBackendInstallationSourceState.AVAILABLE
                and _AUTHORIZATION_BLOCKER in self.blockers
                and _PUBLIC_WORKFLOW_BLOCKER in self.blockers
                and _CLASS_BLOCKERS[self.classification] in self.blockers
            )
        else:
            valid = (
                self.evidence_state == _NOT_PERFORMED
                and self.evidence_digest is None
                and bool(self.blockers)
            )
        if not valid:
            raise StatePersistenceError(
                "post-Manager-backend package step status conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls,
        value: Mapping[str, object],
    ) -> DeployPostManagerBackendLocalInstallStep:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "post-Manager-backend package reconciliation step",
        )
        source_digest = _optional_string(value["source_digest"], "source digest")
        evidence_digest = _optional_string(value["evidence_digest"], "evidence digest")
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in {"sequence", "target_count"}:
                    parsed[name] = _integer(item, name)
                elif name == "classification":
                    parsed[name] = OperationClassification(require_string(value, name))
                elif name == "source_state":
                    parsed[name] = DeployManagerBackendInstallationSourceState(
                        require_string(value, name)
                    )
                elif name == "original_status":
                    parsed[name] = DeployManagerBackendInstallationPlanStatus(
                        require_string(value, name)
                    )
                elif name == "status":
                    parsed[name] = DeployPostManagerBackendLocalInstallStepStatus(
                        require_string(value, name)
                    )
                elif name in {"target_ids", "original_blockers", "blockers"}:
                    parsed[name] = _string_tuple(item, name)
                elif name == "source_digest":
                    parsed[name] = source_digest
                elif name == "evidence_digest":
                    parsed[name] = evidence_digest
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "post-Manager-backend package step enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployPostManagerBackendLocalInstallReconciliation:
    """Bounded immutable checkpoint after exact package-only success."""

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
    backend_context_artifact_digest: str
    backend_context_record_digest: str
    backend_plan_artifact_digest: str
    backend_plan_digest: str
    preflight_execution_artifact_digest: str
    preflight_evidence_artifact_digest: str
    preflight_reconciliation_artifact_digest: str
    preflight_reconciliation_record_digest: str
    installation_context_artifact_digest: str
    installation_context_record_digest: str
    installation_plan_artifact_digest: str
    installation_plan_digest: str
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_scope_digest: str
    authorization_proof_digest: str
    execution_artifact_digest: str
    execution_binding_digest: str
    execution_generation: int
    evidence_artifact_digest: str
    evidence_digest: str
    result_digest: str
    base_os_evidence_artifact_digest: str
    base_os_evidence_digest: str
    manager_server_evidence_artifact_digest: str
    manager_server_evidence_digest: str
    manager_server_provenance_digest: str
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
    target_stable_id: str
    target_count: int
    target_set_digest: str
    operating_system: str
    operating_system_version: str
    architecture: str
    release_line: str
    package_version_digest: str
    package_count: int
    package_set_digest: str
    package_provenance_digest: str
    repository_definition_digest: str
    signing_key_artifact_digest: str
    signing_key_identity_digest: str
    storage_decision_digest: str
    installed_count: int
    changed_count: int
    no_change_count: int
    service_safe_count: int
    prohibited_action_count: int
    authorization_consumed: bool
    original_plan_step_count: int
    original_plan_step_set_digest: str
    original_plan_unchanged: bool
    original_mapping_count: int
    original_mapping_digest: str
    original_mapping_unchanged: bool
    steps: tuple[DeployPostManagerBackendLocalInstallStep, ...]
    step_count: int
    succeeded_count: int
    eligible_count: int
    authorization_required_count: int
    blocked_count: int
    effective_plan_digest: str
    unresolved_blockers: tuple[str, ...]
    unresolved_blocker_count: int
    unresolved_blocker_digest: str
    next_sequence: int
    next_boundary: str
    next_classification: OperationClassification
    next_source_state: DeployManagerBackendInstallationSourceState
    next_status: DeployPostManagerBackendLocalInstallStepStatus
    next_target_count: int
    next_target_set_digest: str
    next_blockers: tuple[str, ...]
    next_blocker_count: int
    next_blocker_digest: str
    next_implementation_contract: str
    next_execution_state: str
    finalization_state: str
    public_workflow_state: str
    record_digest: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCHEMA_VERSION
    )
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_SCHEMA_VERSION
    )
    installation_context_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_SCHEMA_VERSION
    )
    installation_plan_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_SCHEMA_VERSION
    )
    preflight_execution_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION
    )
    preflight_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    )
    preflight_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_SCHEMA_VERSION
            or self.installation_context_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_SCHEMA_VERSION
            or self.installation_plan_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_SCHEMA_VERSION
            or self.preflight_execution_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION
            or self.preflight_evidence_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
            or self.preflight_reconciliation_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
            or self.target_count != 1
            or self.target_set_digest != _digest_object([self.target_stable_id])
            or self.operating_system != "Ubuntu"
            or self.operating_system_version != "24.04"
            or self.architecture not in {"amd64", "aarch64"}
            or self.release_line != SCYLLA_RELEASE_LINE
            or self.package_version_digest != _digest_object(SCYLLA_PACKAGE_VERSION)
            or self.package_count != len(SCYLLA_PACKAGES)
            or self.package_set_digest != _digest_object(list(SCYLLA_PACKAGES))
            or self.repository_definition_digest != SCYLLA_REPOSITORY_DEFINITION_DIGEST
            or self.signing_key_artifact_digest != SCYLLA_SIGNING_KEY_DIGEST
            or self.installed_count != 1
            or self.changed_count + self.no_change_count != 1
            or self.service_safe_count != 1
            or self.prohibited_action_count != 0
            or not self.authorization_consumed
            or not self.original_plan_unchanged
            or not self.original_mapping_unchanged
            or self.next_execution_state != _NOT_STARTED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
            or self.unresolved_blockers != tuple(sorted(set(self.unresolved_blockers)))
            or not _REQUIRED_UNRESOLVED_BLOCKERS.issubset(self.unresolved_blockers)
            or self.unresolved_blocker_count != len(self.unresolved_blockers)
            or self.unresolved_blocker_digest
            != _digest_object(list(self.unresolved_blockers))
            or self.next_blockers != tuple(sorted(set(self.next_blockers)))
            or self.next_blocker_count != len(self.next_blockers)
            or self.next_blocker_digest != _digest_object(list(self.next_blockers))
            or self.record_digest != _record_digest(self, "record_digest")
        ):
            raise StatePersistenceError(
                "post-Manager-backend package reconciliation identity conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for count in (
            self.journal_generation,
            self.execution_generation,
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
            self.prohibited_action_count,
            self.original_plan_step_count,
            self.original_mapping_count,
            self.step_count,
            self.succeeded_count,
            self.eligible_count,
            self.authorization_required_count,
            self.blocked_count,
            self.unresolved_blocker_count,
            self.next_sequence,
            self.next_target_count,
            self.next_blocker_count,
        ):
            _nonnegative_integer(count, "post-Manager-backend package count")
        if (
            min(
                self.journal_generation,
                self.execution_generation,
                self.metadata_generation,
                self.observation_generation,
                self.inventory_generation,
                self.trust_generation,
                self.original_plan_step_count,
                self.original_mapping_count,
                self.step_count,
                self.next_sequence,
            )
            < 1
            or self.step_count != len(self.steps)
            or self.original_plan_step_count != len(self.steps)
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, len(self.steps) + 1))
            or self.original_plan_step_set_digest
            != _digest_object([_original_step_projection(step) for step in self.steps])
            or self.effective_plan_digest
            != _digest_object([step.to_object() for step in self.steps])
        ):
            raise StatePersistenceError(
                "post-Manager-backend package reconciliation counts conflict"
            )
        counts = Counter(step.status for step in self.steps)
        next_steps = tuple(
            step for step in self.steps if step.sequence == self.next_sequence
        )
        succeeded = tuple(
            step
            for step in self.steps
            if step.status is DeployPostManagerBackendLocalInstallStepStatus.SUCCEEDED
        )
        if (
            len(succeeded) != 1
            or succeeded[0].evidence_digest != self.evidence_digest
            or succeeded[0].target_set_digest != self.target_set_digest
            or len(next_steps) != 1
            or self.next_sequence != succeeded[0].sequence + 1
            or next_steps[0].boundary != self.next_boundary
            or next_steps[0].classification is not self.next_classification
            or next_steps[0].source_state is not self.next_source_state
            or next_steps[0].status is not self.next_status
            or next_steps[0].target_count != self.next_target_count
            or next_steps[0].target_set_digest != self.next_target_set_digest
            or next_steps[0].blockers != self.next_blockers
            or next_steps[0].blocker_digest != self.next_blocker_digest
            or self.next_implementation_contract
            != f"manager-backend-{self.next_boundary}-contract"
            or self.succeeded_count
            != counts[DeployPostManagerBackendLocalInstallStepStatus.SUCCEEDED]
            or self.eligible_count
            != counts[DeployPostManagerBackendLocalInstallStepStatus.ELIGIBLE]
            or self.authorization_required_count
            != counts[
                DeployPostManagerBackendLocalInstallStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            ]
            or self.blocked_count
            != counts[DeployPostManagerBackendLocalInstallStepStatus.BLOCKED]
            or self.succeeded_count != 1
            or self.eligible_count + self.authorization_required_count > 1
            or any(
                step.sequence > self.next_sequence
                and step.status
                in {
                    DeployPostManagerBackendLocalInstallStepStatus.ELIGIBLE,
                    DeployPostManagerBackendLocalInstallStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
                    DeployPostManagerBackendLocalInstallStepStatus.SUCCEEDED,
                }
                for step in self.steps
            )
        ):
            raise StatePersistenceError(
                "post-Manager-backend package reconciliation summary conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(
                digest,
                "post-Manager-backend package reconciliation digest",
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls,
        value: Mapping[str, object],
    ) -> DeployPostManagerBackendLocalInstallReconciliation:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "post-Manager-backend package reconciliation",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "execution_generation",
            "metadata_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
            "target_count",
            "package_count",
            "installed_count",
            "changed_count",
            "no_change_count",
            "service_safe_count",
            "prohibited_action_count",
            "original_plan_step_count",
            "original_mapping_count",
            "step_count",
            "succeeded_count",
            "eligible_count",
            "authorization_required_count",
            "blocked_count",
            "unresolved_blocker_count",
            "next_sequence",
            "next_target_count",
            "next_blocker_count",
        }
        boolean_fields = {
            "authorization_consumed",
            "original_plan_unchanged",
            "original_mapping_unchanged",
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
                elif name == "next_source_state":
                    parsed[name] = DeployManagerBackendInstallationSourceState(
                        require_string(value, name)
                    )
                elif name == "next_status":
                    parsed[name] = DeployPostManagerBackendLocalInstallStepStatus(
                        require_string(value, name)
                    )
                elif name in boolean_fields:
                    parsed[name] = _boolean(item, name)
                elif name in {"unresolved_blockers", "next_blockers"}:
                    parsed[name] = _string_tuple(item, name)
                elif name == "steps":
                    parsed[name] = tuple(
                        DeployPostManagerBackendLocalInstallStep.from_object(
                            _mapping(step, "post-package step")
                        )
                        for step in _array(item, "post-package steps")
                    )
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "post-Manager-backend package reconciliation enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployPostManagerBackendLocalInstallReconciliation:
    record: DeployPostManagerBackendLocalInstallReconciliation
    artifact_digest: str


class DeployPostManagerBackendLocalInstallReconciliationStore:
    """Owner-only immutable post-package reconciliation."""

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
        self._path = deploy_post_manager_backend_local_install_reconciliation_path(
            paths,
            operation_id,
        )
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
    ) -> StoredDeployPostManagerBackendLocalInstallReconciliation:
        value, artifact_digest = self._file.read()
        record = DeployPostManagerBackendLocalInstallReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "post-Manager-backend package reconciliation identity conflicts"
            )
        return StoredDeployPostManagerBackendLocalInstallReconciliation(
            record,
            artifact_digest,
        )

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPostManagerBackendLocalInstallReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployPostManagerBackendLocalInstallReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployPostManagerBackendLocalInstallReconciliation,
        DeployPostManagerBackendLocalInstallArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "post-Manager-backend package reconciliation operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "post-Manager-backend package reconciliation is immutable; "
                    "use a new operation"
                )
            return (
                current,
                DeployPostManagerBackendLocalInstallArtifactState.REUSED,
            )
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployPostManagerBackendLocalInstallReconciliation(record, digest),
            DeployPostManagerBackendLocalInstallArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployPostManagerBackendLocalInstallReconciliationReport:
    """Strict bounded projection of post-package reconciliation."""

    operation_id: uuid.UUID
    artifact_state: DeployPostManagerBackendLocalInstallArtifactState
    reconciliation_artifact_digest: str
    reconciliation_record_digest: str
    effective_plan_digest: str
    installation_plan_digest: str
    execution_artifact_digest: str
    evidence_artifact_digest: str
    evidence_digest: str
    package_provenance_digest: str
    target_stable_id: str
    target_count: int
    target_set_digest: str
    installed_count: int
    changed_count: int
    no_change_count: int
    service_safe_count: int
    prohibited_action_count: int
    authorization_consumed: bool
    original_plan_unchanged: bool
    original_mapping_unchanged: bool
    step_count: int
    succeeded_count: int
    eligible_count: int
    authorization_required_count: int
    blocked_count: int
    unresolved_blocker_count: int
    unresolved_blocker_digest: str
    next_sequence: int
    next_boundary: str
    next_classification: OperationClassification
    next_source_state: DeployManagerBackendInstallationSourceState
    next_status: DeployPostManagerBackendLocalInstallStepStatus
    next_target_count: int
    next_target_set_digest: str
    next_blocker_count: int
    next_blocker_digest: str
    next_implementation_contract: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    process_calls: int = 0
    authorization_created: bool = False
    execution_started: bool = False
    schema_version: str = ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_REPORT_SCHEMA_VERSION
            or self.target_count != 1
            or self.installed_count != 1
            or self.changed_count + self.no_change_count != 1
            or self.service_safe_count != 1
            or self.prohibited_action_count
            or not self.authorization_consumed
            or not self.original_plan_unchanged
            or not self.original_mapping_unchanged
            or self.succeeded_count != 1
            or self.eligible_count + self.authorization_required_count > 1
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.process_calls
            or self.authorization_created
            or self.execution_started
        ):
            raise StatePersistenceError(
                "post-Manager-backend package reconciliation report conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(
                digest,
                "post-Manager-backend package report digest",
            )

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
                "steps": self.step_count,
                "succeeded": self.succeeded_count,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "next_boundary": {
                "blocker_count": self.next_blocker_count,
                "blocker_digest": self.next_blocker_digest,
                "boundary": self.next_boundary,
                "classification": self.next_classification.value,
                "contract": self.next_implementation_contract,
                "sequence": self.next_sequence,
                "source_state": self.next_source_state.value,
                "status": self.next_status.value,
                "target_count": self.next_target_count,
                "target_set_digest": self.next_target_set_digest,
            },
            "operation_id": str(self.operation_id),
            "package_install": {
                "authorization_consumed": self.authorization_consumed,
                "changed_count": self.changed_count,
                "evidence_artifact_digest": self.evidence_artifact_digest,
                "evidence_digest": self.evidence_digest,
                "execution_artifact_digest": self.execution_artifact_digest,
                "installed_count": self.installed_count,
                "no_change_count": self.no_change_count,
                "package_provenance_digest": self.package_provenance_digest,
                "prohibited_action_count": self.prohibited_action_count,
                "service_safe_count": self.service_safe_count,
                "target_count": self.target_count,
                "target_set_digest": self.target_set_digest,
                "target_stable_id": self.target_stable_id,
            },
            "plan": {
                "effective_plan_digest": self.effective_plan_digest,
                "installation_plan_digest": self.installation_plan_digest,
                "original_mapping_unchanged": self.original_mapping_unchanged,
                "original_plan_unchanged": self.original_plan_unchanged,
            },
            "schema_version": self.schema_version,
            "side_effects": {
                "authorization_created": self.authorization_created,
                "execution_started": self.execution_started,
                "process_calls": self.process_calls,
            },
            "unresolved_blockers": {
                "count": self.unresolved_blocker_count,
                "digest": self.unresolved_blocker_digest,
            },
        }


@dataclass(frozen=True, slots=True)
class _ReconciliationContext:
    authorization_context: _AuthorizationContext
    installation_context: StoredDeployManagerBackendInstallationContext
    installation_plan: StoredDeployManagerBackendInstallationPlan
    authorization: StoredDeployManagerBackendLocalInstallAuthorization
    execution: StoredDeployManagerBackendLocalInstallExecution
    evidence: StoredDeployManagerBackendLocalInstallEvidence


_StoredRecord = (
    DeployPostManagerBackendLocalInstallStep
    | DeployPostManagerBackendLocalInstallReconciliation
    | DeployPostManagerBackendLocalInstallReconciliationReport
)


def reconcile_deploy_manager_backend_local_install_result(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployPostManagerBackendLocalInstallReconciliationReport:
    """Bind exact package success and evaluate only the next planned boundary."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_or_later_artifacts(paths, operation_id)
    context = _load_context(paths, operation_id, lock=lock)
    steps = _build_steps(context)
    store = DeployPostManagerBackendLocalInstallReconciliationStore(
        paths,
        operation_id,
    )
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


def deploy_post_manager_backend_local_install_reconciliation_path(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> Path:
    """Return the canonical operation-bound reconciliation path."""

    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}"
        f"{DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "post-Manager-backend package reconciliation path is not canonical"
        )
    return path


def deploy_post_manager_backend_local_install_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    suffix = DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_FILENAME_SUFFIX
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
    authorization_context = _load_authorization_context(
        paths,
        operation_id,
        lock=lock,
    )
    planning = authorization_context.planning
    current = planning.execution_context
    metadata = current.metadata
    installation_context = authorization_context.installation_context
    installation_plan = authorization_context.installation_plan
    _validate_recomputed_installation_plan(installation_context, installation_plan)

    authorization_store = DeployManagerBackendLocalInstallAuthorizationStore(
        paths,
        operation_id,
    )
    execution_store = DeployManagerBackendLocalInstallExecutionStore(
        paths,
        operation_id,
    )
    evidence_store = DeployManagerBackendLocalInstallEvidenceStore(
        paths,
        operation_id,
    )
    for path, label in (
        (authorization_store.path, "authorization"),
        (execution_store.path, "execution"),
        (evidence_store.path, "evidence"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"post-Manager-backend package reconciliation requires complete {label}"
            )

    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    payload = _build_payload(authorization_context)
    package = _derive_package_provenance(authorization_context, payload)
    scope = _derive_authorization_scope(authorization_context, payload, package)
    expected_authorization = _build_authorization(
        authorization_context,
        scope=scope,
        package_provenance=package,
        proof=authorization.record.proof,
        created_at=authorization.record.created_at,
    )
    if authorization.record != expected_authorization:
        raise StateConflictError(
            "post-Manager-backend package authorization or scope drifted"
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
        installation_context,
        installation_plan,
        authorization,
        execution,
        evidence,
    )
    _validate_complete_package_result(context, payload)
    return context


def _validate_recomputed_installation_plan(
    context: StoredDeployManagerBackendInstallationContext,
    plan: StoredDeployManagerBackendInstallationPlan,
) -> None:
    steps = _build_plan_steps(context.record)
    expected = _build_plan_record(
        context,
        steps=steps,
        created_at=plan.record.created_at,
    )
    if (
        plan.record != expected
        or plan.record.context_artifact_digest != context.artifact_digest
        or plan.record.context_record_digest != context.record.record_digest
    ):
        raise StateConflictError(
            "post-Manager-backend package installation plan drifted"
        )


def _validate_complete_package_result(
    context: _ReconciliationContext,
    payload: Mapping[str, object],
) -> None:
    planning = context.authorization_context.planning
    current = planning.execution_context
    preflight_binding = current.binding
    authorization = context.authorization.record
    scope = authorization.scope
    package = authorization.package_provenance
    execution = context.execution.record
    binding = execution.binding
    attempt = execution.attempt
    evidence = context.evidence.record
    if (
        authorization.consumed
        or authorization.authorization_state != "authorized-pre-execution"
        or authorization.execution_state != _UNAVAILABLE
        or execution.state
        is not DeployManagerBackendLocalInstallExecutionState.SUCCEEDED
        or not execution.completed
        or execution.generation != 3
        or not execution.authorization_consumed
        or execution.invocation_count != 1
        or execution.manual_recovery_required
        or attempt.state is not DeployManagerBackendLocalInstallExecutionState.SUCCEEDED
        or not attempt.authorization_consumed_at_start
        or not attempt.invocation_may_have_occurred
        or attempt.manual_recovery_required
        or attempt.automatic_retry_allowed
        or attempt.exit_code != 0
        or attempt.result_digest is None
        or attempt.evidence_digest is None
        or evidence.generation != 1
        or len(evidence.entries) != 1
        or evidence.binding != binding
    ):
        raise StateConflictError(
            "post-Manager-backend package reconciliation requires exact "
            "terminal success and consumed execution authorization"
        )
    if (
        binding.authorization_artifact_digest != context.authorization.artifact_digest
        or binding.authorization_digest != authorization.authorization_digest
        or binding.authorization_scope_digest
        != authorization.authorization_scope_digest
        or binding.authorization_proof_digest != authorization.proof.proof_digest
        or binding.backend_context_artifact_digest
        != authorization.backend_context_artifact_digest
        or binding.backend_context_record_digest
        != authorization.backend_context_record_digest
        or binding.backend_plan_artifact_digest
        != authorization.backend_plan_artifact_digest
        or binding.backend_plan_digest != authorization.backend_plan_digest
        or binding.preflight_execution_artifact_digest
        != authorization.preflight_execution_artifact_digest
        or binding.preflight_execution_binding_digest
        != authorization.preflight_execution_binding_digest
        or binding.preflight_evidence_artifact_digest
        != authorization.preflight_evidence_artifact_digest
        or binding.preflight_evidence_digest != authorization.preflight_evidence_digest
        or binding.preflight_reconciliation_artifact_digest
        != authorization.preflight_reconciliation_artifact_digest
        or binding.preflight_reconciliation_record_digest
        != authorization.preflight_reconciliation_record_digest
        or binding.installation_context_artifact_digest
        != context.installation_context.artifact_digest
        or binding.installation_context_record_digest
        != context.installation_context.record.record_digest
        or binding.installation_plan_artifact_digest
        != context.installation_plan.artifact_digest
        or binding.installation_plan_digest
        != context.installation_plan.record.plan_digest
        or binding.base_os_evidence_artifact_digest
        != authorization.base_os_evidence_artifact_digest
        or binding.base_os_evidence_digest != authorization.base_os_evidence_digest
        or binding.manager_server_evidence_artifact_digest
        != authorization.manager_server_evidence_artifact_digest
        or binding.manager_server_evidence_digest
        != authorization.manager_server_evidence_digest
        or binding.manager_server_provenance_digest
        != authorization.manager_server_provenance_digest
        or binding.metadata_generation != authorization.metadata_generation
        or binding.metadata_artifact_digest != authorization.metadata_artifact_digest
        or binding.desired_spec_digest != authorization.desired_spec_digest
        or binding.observation_generation != authorization.observation_generation
        or binding.observation_artifact_digest
        != authorization.observation_artifact_digest
        or binding.observation_manifest_digest
        != authorization.observation_manifest_digest
        or binding.inventory_generation != authorization.inventory_generation
        or binding.inventory_artifact_digest != authorization.inventory_artifact_digest
        or binding.inventory_digest != authorization.inventory_digest
        or binding.trust_generation != authorization.trust_generation
        or binding.trust_artifact_digest != authorization.trust_artifact_digest
        or binding.trust_entries_digest != authorization.trust_entries_digest
        or binding.readiness_artifact_digest != authorization.readiness_artifact_digest
        or binding.readiness_record_digest != authorization.readiness_record_digest
        or binding.catalog_digest != authorization.catalog_digest
        or binding.source_version != ANSIBLE_SOURCE_VERSION
        or binding.source_digest != authorization.ansible_source_digest
        or binding.playbook_source_digest != scope.playbook_source_digest
        or binding.target_stable_id != scope.target_stable_id
        or binding.target_set_digest != scope.target_digest
        or binding.architecture != scope.architecture.value
        or binding.package_version_digest != package.package_version_digest
        or binding.package_set_digest != package.package_set_digest
        or binding.package_provenance_digest != package.provenance_digest
        or binding.repository_definition_digest != package.repository_definition_digest
        or binding.signing_key_artifact_digest != package.signing_key_artifact_digest
        or binding.signing_key_identity_digest != package.signing_key_identity_digest
        or binding.storage_decision_digest != scope.storage_decision_digest
        or binding.variables_digest != scope.variables_digest
        or binding.command_digest != scope.command_digest
        or binding.command_policy_digest != scope.command_policy_digest
        or binding.journal_generation != authorization.journal_generation
        or binding.journal_digest != authorization.journal_digest
        or binding.journal_status is not JournalStatus.IN_PROGRESS
        or binding.journal_phase is not OperationPhase.VERIFY
        or binding.toolchain_version != preflight_binding.toolchain_version
        or binding.executable_identity_digest
        != preflight_binding.executable_identity_digest
        or binding.toolchain_evidence_digest
        != preflight_binding.toolchain_evidence_digest
    ):
        raise StateConflictError(
            "post-Manager-backend package execution or canonical chain drifted"
        )
    expected_execution_scope_digest = _digest_object(
        {
            "authorization_scope_digest": authorization.authorization_scope_digest,
            "command_digest": scope.command_digest,
            "package_provenance_digest": package.provenance_digest,
            "source_digest": scope.playbook_source_digest,
            "storage_decision_digest": scope.storage_decision_digest,
            "target_set_digest": scope.target_digest,
            "variables_digest": scope.variables_digest,
        }
    )
    if binding.execution_scope_digest != expected_execution_scope_digest:
        raise StateConflictError(
            "post-Manager-backend package execution scope digest drifted"
        )
    if (
        attempt.step_sequence != scope.step_sequence
        or attempt.boundary != scope.boundary
        or attempt.stable_id != scope.target_stable_id
        or attempt.target_digest != scope.target_digest
        or attempt.authorization_scope_digest
        != authorization.authorization_scope_digest
        or attempt.authorization_variables_digest != scope.variables_digest
        or attempt.authorization_command_digest != scope.command_digest
        or attempt.variables_digest != binding.variables_digest
        or attempt.command_digest != binding.command_digest
        or attempt.source_digest != binding.playbook_source_digest
        or attempt.package_provenance_digest != package.provenance_digest
        or attempt.storage_decision_digest != scope.storage_decision_digest
    ):
        raise StateConflictError("post-Manager-backend package attempt scope conflicts")
    entry = evidence.entries[0]
    _validate_evidence_entry(context, entry, payload)
    if (
        attempt.result_digest != entry.result_digest
        or attempt.evidence_digest != entry.evidence_digest
    ):
        raise StateConflictError(
            "post-Manager-backend package execution/evidence digests conflict"
        )


def _validate_evidence_entry(
    context: _ReconciliationContext,
    entry: DeployManagerBackendLocalInstallEvidenceEntry,
    payload: Mapping[str, object],
) -> None:
    authorization = context.authorization.record
    scope = authorization.scope
    package = authorization.package_provenance
    provenance = _mapping(payload.get("provenance"), "package provenance")
    prohibited_digest = _digest_object(
        {name: False for name in MANAGER_BACKEND_LOCAL_INSTALL_FORBIDDEN_ACTIONS}
    )
    expected_result = _digest_object(
        {
            "changed": entry.changed,
            "command_policy_digest": entry.command_policy_digest,
            "logical_id": entry.stable_id,
            "package_set_digest": entry.package_set_digest,
            "prohibited_actions_digest": prohibited_digest,
            "provenance_digest": _digest_object(dict(provenance)),
            "repository_definition_digest": entry.repository_definition_digest,
            "schema_version": entry.result_schema_version,
            "service_inactive": entry.service_inactive,
            "service_masked": entry.service_masked,
            "signing_key_artifact_digest": entry.signing_key_artifact_digest,
            "source_digest": entry.source_digest,
            "status": entry.status.value,
        }
    )
    if (
        entry.stable_id != scope.target_stable_id
        or entry.role != "manager"
        or entry.operating_system != "Ubuntu"
        or entry.operating_system_version != "24.04"
        or entry.architecture != scope.architecture.value
        or entry.status
        not in {
            ManagerBackendLocalInstallStatus.INSTALLED,
            ManagerBackendLocalInstallStatus.NO_CHANGE,
        }
        or not entry.installed
        or entry.changed != (entry.status is ManagerBackendLocalInstallStatus.INSTALLED)
        or entry.release_line != SCYLLA_RELEASE_LINE
        or entry.package_version_digest != package.package_version_digest
        or entry.package_count != package.package_count
        or entry.package_set_digest != package.package_set_digest
        or entry.repository_definition_digest != package.repository_definition_digest
        or entry.signing_key_artifact_digest != package.signing_key_artifact_digest
        or entry.signing_key_identity_digest != package.signing_key_identity_digest
        or entry.source_digest != scope.source_digest
        or entry.command_policy_digest != scope.command_policy_digest
        or entry.provenance_digest != _digest_object(dict(provenance))
        or entry.storage_decision_digest != scope.storage_decision_digest
        or entry.variables_digest != scope.variables_digest
        or entry.command_digest != scope.command_digest
        or not entry.service_masked
        or not entry.service_inactive
        or entry.prohibited_action_count
        or entry.prohibited_actions_digest != prohibited_digest
        or entry.result_digest != expected_result
        or entry.manual_recovery_required
        or entry.automatic_retry_allowed
    ):
        raise StateConflictError(
            "post-Manager-backend package semantic evidence conflicts"
        )


def _build_steps(
    context: _ReconciliationContext,
) -> tuple[DeployPostManagerBackendLocalInstallStep, ...]:
    planned = context.installation_plan.record
    scope = context.authorization.record.scope
    entry = context.evidence.record.entries[0]
    matches = tuple(
        step
        for step in planned.steps
        if step.sequence == scope.step_sequence
        and step.boundary == scope.boundary
        and step.step_digest == scope.plan_step_digest
    )
    if len(matches) != 1:
        raise StateConflictError(
            "post-Manager-backend package completed boundary is ambiguous"
        )
    completed = matches[0]
    remaining = tuple(
        step for step in planned.steps if step.sequence > completed.sequence
    )
    if not remaining:
        raise StateConflictError(
            "post-Manager-backend package immediate next boundary is unavailable"
        )
    next_planned = min(remaining, key=lambda item: item.sequence)
    result: list[DeployPostManagerBackendLocalInstallStep] = []
    for planned_step in planned.steps:
        status = DeployPostManagerBackendLocalInstallStepStatus.BLOCKED
        evidence_state = _NOT_PERFORMED
        evidence_digest: str | None = None
        blockers = planned_step.blockers
        if planned_step.sequence == completed.sequence:
            status = DeployPostManagerBackendLocalInstallStepStatus.SUCCEEDED
            evidence_state = _PACKAGE_EVIDENCE_STATE
            evidence_digest = entry.evidence_digest
            blockers = ()
        elif planned_step.sequence == next_planned.sequence:
            status, evidence_state, evidence_digest, blockers = _evaluate_next_boundary(
                context, planned_step
            )
        result.append(
            _step_from_planned(
                planned_step,
                status=status,
                evidence_state=evidence_state,
                evidence_digest=evidence_digest,
                blockers=blockers,
            )
        )
    return tuple(result)


def _evaluate_next_boundary(
    context: _ReconciliationContext,
    step: DeployManagerBackendInstallationPlanStep,
) -> tuple[
    DeployPostManagerBackendLocalInstallStepStatus,
    str,
    str | None,
    tuple[str, ...],
]:
    unresolved = tuple(
        sorted(
            blocker
            for blocker in step.blockers
            if blocker
            not in {
                _AUTHORIZATION_BLOCKER,
                _PUBLIC_WORKFLOW_BLOCKER,
                *_CLASS_BLOCKERS.values(),
            }
        )
    )
    if (
        step.source_state is DeployManagerBackendInstallationSourceState.UNAVAILABLE
        or unresolved
    ):
        return (
            DeployPostManagerBackendLocalInstallStepStatus.BLOCKED,
            _NOT_PERFORMED,
            None,
            step.blockers,
        )
    evidence_digest = _digest_object(
        {
            "installation_plan_digest": context.installation_plan.record.plan_digest,
            "next_boundary": step.boundary,
            "next_step_digest": step.step_digest,
            "package_evidence_digest": context.evidence.record.entries[
                0
            ].evidence_digest,
            "storage_decision_digest": step.storage_decision_digest,
        }
    )
    if step.classification is OperationClassification.READ_ONLY:
        return (
            DeployPostManagerBackendLocalInstallStepStatus.ELIGIBLE,
            _NEXT_EVIDENCE_STATE,
            evidence_digest,
            (),
        )
    blockers = tuple(
        sorted(
            {
                _AUTHORIZATION_BLOCKER,
                _CLASS_BLOCKERS[step.classification],
                _PUBLIC_WORKFLOW_BLOCKER,
            }
        )
    )
    return (
        DeployPostManagerBackendLocalInstallStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        _NEXT_EVIDENCE_STATE,
        evidence_digest,
        blockers,
    )


def _step_from_planned(
    step: DeployManagerBackendInstallationPlanStep,
    *,
    status: DeployPostManagerBackendLocalInstallStepStatus,
    evidence_state: str,
    evidence_digest: str | None,
    blockers: tuple[str, ...],
) -> DeployPostManagerBackendLocalInstallStep:
    values: dict[str, object] = {
        "sequence": step.sequence,
        "boundary": step.boundary,
        "classification": step.classification,
        "target_ids": step.target_ids,
        "target_count": step.target_count,
        "target_set_digest": step.target_set_digest,
        "package_reference_digest": step.package_reference_digest,
        "storage_decision_digest": step.storage_decision_digest,
        "prerequisite_gate_set_digest": step.prerequisite_gate_set_digest,
        "source_state": step.source_state,
        "source_digest": step.source_digest,
        "source_contract_state": step.source_contract_state,
        "authorization_requirement": step.authorization_requirement,
        "performance_state": step.performance_state,
        "original_status": step.status,
        "original_blockers": step.blockers,
        "original_blocker_digest": step.blocker_digest,
        "original_step_digest": step.step_digest,
        "status": status,
        "evidence_state": evidence_state,
        "evidence_digest": evidence_digest,
        "blockers": tuple(sorted(blockers)),
        "blocker_digest": _digest_object(list(sorted(blockers))),
        "step_digest": "",
    }
    values["step_digest"] = _record_digest_from_values(values, "step_digest")
    return DeployPostManagerBackendLocalInstallStep(**values)  # type: ignore[arg-type]


def _build_record(
    context: _ReconciliationContext,
    *,
    steps: tuple[DeployPostManagerBackendLocalInstallStep, ...],
    created_at: str | None,
) -> DeployPostManagerBackendLocalInstallReconciliation:
    authorization = context.authorization.record
    execution = context.execution.record
    binding = execution.binding
    package = authorization.package_provenance
    entry = context.evidence.record.entries[0]
    plan = context.installation_plan.record
    completed = next(
        (
            step
            for step in steps
            if step.status is DeployPostManagerBackendLocalInstallStepStatus.SUCCEEDED
        ),
        None,
    )
    if completed is None:
        raise StateConflictError(
            "post-Manager-backend package completed boundary is unavailable"
        )
    next_steps = tuple(step for step in steps if step.sequence > completed.sequence)
    if not next_steps:
        raise StateConflictError(
            "post-Manager-backend package next boundary is unavailable"
        )
    next_step = min(next_steps, key=lambda item: item.sequence)
    counts = Counter(step.status for step in steps)
    unresolved = tuple(
        sorted(
            {
                blocker
                for step in steps
                if step.sequence > completed.sequence
                for blocker in step.blockers
            }
        )
    )
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at or format_timestamp(datetime.now(UTC)),
        "cluster_uuid": authorization.cluster_uuid,
        "cluster_name": binding.cluster_name,
        "operation_id": authorization.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "request_digest": authorization.request_digest,
        "journal_generation": binding.journal_generation,
        "journal_digest": binding.journal_digest,
        "journal_status": binding.journal_status,
        "journal_phase": binding.journal_phase,
        "backend_context_artifact_digest": binding.backend_context_artifact_digest,
        "backend_context_record_digest": binding.backend_context_record_digest,
        "backend_plan_artifact_digest": binding.backend_plan_artifact_digest,
        "backend_plan_digest": binding.backend_plan_digest,
        "preflight_execution_artifact_digest": (
            binding.preflight_execution_artifact_digest
        ),
        "preflight_evidence_artifact_digest": (
            binding.preflight_evidence_artifact_digest
        ),
        "preflight_reconciliation_artifact_digest": (
            binding.preflight_reconciliation_artifact_digest
        ),
        "preflight_reconciliation_record_digest": (
            binding.preflight_reconciliation_record_digest
        ),
        "installation_context_artifact_digest": (
            context.installation_context.artifact_digest
        ),
        "installation_context_record_digest": (
            context.installation_context.record.record_digest
        ),
        "installation_plan_artifact_digest": context.installation_plan.artifact_digest,
        "installation_plan_digest": plan.plan_digest,
        "authorization_artifact_digest": context.authorization.artifact_digest,
        "authorization_digest": authorization.authorization_digest,
        "authorization_scope_digest": authorization.authorization_scope_digest,
        "authorization_proof_digest": authorization.proof.proof_digest,
        "execution_artifact_digest": context.execution.artifact_digest,
        "execution_binding_digest": binding.binding_digest,
        "execution_generation": execution.generation,
        "evidence_artifact_digest": context.evidence.artifact_digest,
        "evidence_digest": entry.evidence_digest,
        "result_digest": entry.result_digest,
        "base_os_evidence_artifact_digest": (binding.base_os_evidence_artifact_digest),
        "base_os_evidence_digest": binding.base_os_evidence_digest,
        "manager_server_evidence_artifact_digest": (
            binding.manager_server_evidence_artifact_digest
        ),
        "manager_server_evidence_digest": binding.manager_server_evidence_digest,
        "manager_server_provenance_digest": binding.manager_server_provenance_digest,
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
        "target_stable_id": binding.target_stable_id,
        "target_count": 1,
        "target_set_digest": binding.target_set_digest,
        "operating_system": entry.operating_system,
        "operating_system_version": entry.operating_system_version,
        "architecture": entry.architecture,
        "release_line": package.release_line,
        "package_version_digest": package.package_version_digest,
        "package_count": package.package_count,
        "package_set_digest": package.package_set_digest,
        "package_provenance_digest": package.provenance_digest,
        "repository_definition_digest": package.repository_definition_digest,
        "signing_key_artifact_digest": package.signing_key_artifact_digest,
        "signing_key_identity_digest": package.signing_key_identity_digest,
        "storage_decision_digest": binding.storage_decision_digest,
        "installed_count": int(entry.installed),
        "changed_count": int(entry.changed),
        "no_change_count": int(not entry.changed),
        "service_safe_count": int(entry.service_masked and entry.service_inactive),
        "prohibited_action_count": entry.prohibited_action_count,
        "authorization_consumed": execution.authorization_consumed,
        "original_plan_step_count": plan.step_count,
        "original_plan_step_set_digest": _digest_object(
            [step.to_object() for step in plan.steps]
        ),
        "original_plan_unchanged": True,
        "original_mapping_count": plan.original_mapping_count,
        "original_mapping_digest": plan.original_mapping_digest,
        "original_mapping_unchanged": plan.original_mapping_unchanged,
        "steps": steps,
        "step_count": len(steps),
        "succeeded_count": counts[
            DeployPostManagerBackendLocalInstallStepStatus.SUCCEEDED
        ],
        "eligible_count": counts[
            DeployPostManagerBackendLocalInstallStepStatus.ELIGIBLE
        ],
        "authorization_required_count": counts[
            DeployPostManagerBackendLocalInstallStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        ],
        "blocked_count": counts[DeployPostManagerBackendLocalInstallStepStatus.BLOCKED],
        "effective_plan_digest": _digest_object([step.to_object() for step in steps]),
        "unresolved_blockers": unresolved,
        "unresolved_blocker_count": len(unresolved),
        "unresolved_blocker_digest": _digest_object(list(unresolved)),
        "next_sequence": next_step.sequence,
        "next_boundary": next_step.boundary,
        "next_classification": next_step.classification,
        "next_source_state": next_step.source_state,
        "next_status": next_step.status,
        "next_target_count": next_step.target_count,
        "next_target_set_digest": next_step.target_set_digest,
        "next_blockers": next_step.blockers,
        "next_blocker_count": len(next_step.blockers),
        "next_blocker_digest": next_step.blocker_digest,
        "next_implementation_contract": (
            f"manager-backend-{next_step.boundary}-contract"
        ),
        "next_execution_state": _NOT_STARTED,
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(values, "record_digest")
    return DeployPostManagerBackendLocalInstallReconciliation(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployPostManagerBackendLocalInstallReconciliation,
    *,
    state: DeployPostManagerBackendLocalInstallArtifactState,
) -> DeployPostManagerBackendLocalInstallReconciliationReport:
    record = stored.record
    return DeployPostManagerBackendLocalInstallReconciliationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        reconciliation_artifact_digest=stored.artifact_digest,
        reconciliation_record_digest=record.record_digest,
        effective_plan_digest=record.effective_plan_digest,
        installation_plan_digest=record.installation_plan_digest,
        execution_artifact_digest=record.execution_artifact_digest,
        evidence_artifact_digest=record.evidence_artifact_digest,
        evidence_digest=record.evidence_digest,
        package_provenance_digest=record.package_provenance_digest,
        target_stable_id=record.target_stable_id,
        target_count=record.target_count,
        target_set_digest=record.target_set_digest,
        installed_count=record.installed_count,
        changed_count=record.changed_count,
        no_change_count=record.no_change_count,
        service_safe_count=record.service_safe_count,
        prohibited_action_count=record.prohibited_action_count,
        authorization_consumed=record.authorization_consumed,
        original_plan_unchanged=record.original_plan_unchanged,
        original_mapping_unchanged=record.original_mapping_unchanged,
        step_count=record.step_count,
        succeeded_count=record.succeeded_count,
        eligible_count=record.eligible_count,
        authorization_required_count=record.authorization_required_count,
        blocked_count=record.blocked_count,
        unresolved_blocker_count=record.unresolved_blocker_count,
        unresolved_blocker_digest=record.unresolved_blocker_digest,
        next_sequence=record.next_sequence,
        next_boundary=record.next_boundary,
        next_classification=record.next_classification,
        next_source_state=record.next_source_state,
        next_status=record.next_status,
        next_target_count=record.next_target_count,
        next_target_set_digest=record.next_target_set_digest,
        next_blocker_count=record.next_blocker_count,
        next_blocker_digest=record.next_blocker_digest,
        next_implementation_contract=record.next_implementation_contract,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
    )


def _original_step_projection(
    step: DeployPostManagerBackendLocalInstallStep,
) -> dict[str, object]:
    return {
        "authorization_requirement": step.authorization_requirement,
        "blocker_digest": step.original_blocker_digest,
        "blockers": list(step.original_blockers),
        "boundary": step.boundary,
        "classification": step.classification.value,
        "package_reference_digest": step.package_reference_digest,
        "performance_state": step.performance_state,
        "prerequisite_gate_set_digest": step.prerequisite_gate_set_digest,
        "schema_version": (
            ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_STEP_SCHEMA_VERSION
        ),
        "sequence": step.sequence,
        "source_contract_state": step.source_contract_state,
        "source_digest": step.source_digest,
        "source_state": step.source_state.value,
        "status": step.original_status.value,
        "step_digest": step.original_step_digest,
        "storage_decision_digest": step.storage_decision_digest,
        "target_count": step.target_count,
        "target_ids": list(step.target_ids),
        "target_set_digest": step.target_set_digest,
    }


def _record_digest(value: _StoredRecord, digest_field: str) -> str:
    return _record_digest_from_values(
        cast(Mapping[str, object], asdict(value)),
        digest_field,
    )


def _record_digest_from_values(
    values: Mapping[str, object],
    digest_field: str,
) -> str:
    copied = {
        name: item
        for name, item in values.items()
        if name != "schema_version" and not name.endswith("_schema_version")
    }
    copied[digest_field] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(cast(Mapping[str, object], _jsonable(copied))))


def _dataclass_object(value: _StoredRecord) -> dict[str, object]:
    return cast(dict[str, object], _jsonable(asdict(value)))


def _jsonable(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, uuid.UUID):
        return str(value)
    if is_dataclass(value):
        return _dataclass_object(cast(_StoredRecord, value))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest_fields(value: _StoredRecord) -> tuple[str, ...]:
    return tuple(
        cast(str, item)
        for name, item in asdict(value).items()
        if name.endswith("_digest") and item is not None
    )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "post-Manager-backend package reconciliation paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "post-Manager-backend package reconciliation requires the matching "
            "held deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_or_later_artifacts(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> None:
    canonical = (
        f"{operation_id}"
        f"{DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_FILENAME_SUFFIX}"
    )
    prefix = f"{operation_id}."
    later_fragments = (
        ".ansible-deploy-manager-backend-storage",
        ".ansible-deploy-manager-backend-file-configuration",
        ".ansible-deploy-manager-backend-schema",
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list post-Manager-backend package history"
        ) from error
    for entry in entries:
        if (
            entry.name.startswith(prefix)
            and "post-manager-backend-local-install-reconciliation" in entry.name
            and entry.name != canonical
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "post-Manager-backend package reconciliation artifacts are ambiguous"
            )
        if entry.name.startswith(prefix) and any(
            fragment in entry.name for fragment in later_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "post-Manager-backend package reconciliation refuses later history"
            )


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise StatePersistenceError(f"{label} must be an array")
    return value


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise StatePersistenceError(f"{label} must be an array of strings")
    return tuple(value)


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


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise StatePersistenceError(f"{label} must be a string or null")
    return value


__all__ = [
    "ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_STEP_SCHEMA_VERSION",
    "DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_FILENAME_SUFFIX",
    "DeployPostManagerBackendLocalInstallArtifactState",
    "DeployPostManagerBackendLocalInstallReconciliation",
    "DeployPostManagerBackendLocalInstallReconciliationReport",
    "DeployPostManagerBackendLocalInstallReconciliationStore",
    "DeployPostManagerBackendLocalInstallStep",
    "DeployPostManagerBackendLocalInstallStepStatus",
    "StoredDeployPostManagerBackendLocalInstallReconciliation",
    "deploy_post_manager_backend_local_install_reconciliation_id_from_filename",
    "deploy_post_manager_backend_local_install_reconciliation_path",
    "reconcile_deploy_manager_backend_local_install_result",
]
