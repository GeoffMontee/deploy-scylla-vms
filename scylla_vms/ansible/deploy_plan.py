"""Deploy-only Ansible context and deterministic blocked-plan binding.

This module deliberately does not reuse the generic Ansible PLAN checkpoint:
deploy has already crossed Terraform execution and remains in VERIFY.  These
companions therefore bind the verified post-apply chain without changing the
common journal or authorizing any playbook execution.
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

from scylla_vms.ansible.commands import (
    ansible_command_intent_digest,
    validate_playbook_request_policy,
)
from scylla_vms.ansible.operation_authorization import (
    OPERATION_AUTHORIZATION_FILENAME_SUFFIX,
)
from scylla_vms.ansible.operation_binding import OPERATION_BINDING_FILENAME_SUFFIX
from scylla_vms.ansible.operation_context import OPERATION_CONTEXT_FILENAME_SUFFIX
from scylla_vms.ansible.operation_evidence import OPERATION_EVIDENCE_FILENAME_SUFFIX
from scylla_vms.ansible.operation_execution import OPERATION_EXECUTION_FILENAME_SUFFIX
from scylla_vms.ansible.operation_finalization import (
    OPERATION_FINALIZATION_FILENAME_SUFFIX,
)
from scylla_vms.ansible.orchestration import ansible_operation_catalog_digest
from scylla_vms.ansible.registry import (
    OPERATION_PLAYBOOKS,
    CheckMode,
    LimitPolicy,
    PlaybookDefinition,
    get_playbook,
)
from scylla_vms.ansible.source import (
    ANSIBLE_SOURCE_VERSION,
    AnsibleSourceBundle,
    load_ansible_source_bundle,
    validate_ansible_config,
)
from scylla_vms.errors import StateConflictError, StatePersistenceError
from scylla_vms.journal import JournalStatus, OperationPhase
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
    StoredTerraformApplyReadiness,
    TerraformApplyReadinessStore,
    _load_readiness_context,
    _ReadinessContext,
)

ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION = "deploy-scylla-vms.ansible-deploy-context/v1"
ANSIBLE_DEPLOY_INTENT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-context.intent/v1"
)
ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION = "deploy-scylla-vms.ansible-deploy-plan/v1"
ANSIBLE_DEPLOY_PLAN_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-plan-report/v1"
)
DEPLOY_CONTEXT_FILENAME_SUFFIX = ".ansible-deploy-context.json"
DEPLOY_PLAN_FILENAME_SUFFIX = ".ansible-deploy-plan.json"

_OPERATION = "deploy"
_NOT_PERFORMED = "not-performed"
_NOT_COLLECTED = "not-collected"
_UNMODELED = "unmodeled"
_NOT_STARTED = "not-started"
_DEPLOY_CONNECT_TIMEOUT_SECONDS = 10.0
_DEPLOY_PROBE_TIMEOUT_SECONDS = 10
_PUBLIC_WORKFLOW_BLOCKER = "public-deploy-workflow-unavailable"
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ROLE_ORDER = ("jump-host", "scylla", "manager", "monitoring")
_GENERIC_COMPANION_SUFFIXES = (
    OPERATION_AUTHORIZATION_FILENAME_SUFFIX,
    OPERATION_BINDING_FILENAME_SUFFIX,
    OPERATION_CONTEXT_FILENAME_SUFFIX,
    OPERATION_EVIDENCE_FILENAME_SUFFIX,
    OPERATION_EXECUTION_FILENAME_SUFFIX,
    OPERATION_FINALIZATION_FILENAME_SUFFIX,
)
_DEPLOY_ADVANCED_COMPANION_SUFFIXES = (
    ".ansible-deploy-prerequisite-execution.json",
    ".ansible-deploy-prerequisite-evidence.json",
    ".ansible-deploy-effective-plan.json",
    ".ansible-deploy-pre-mutation-host-evidence-execution.json",
    ".ansible-deploy-pre-mutation-host-evidence.json",
    ".ansible-deploy-host-evidence-reconciliation.json",
    ".ansible-deploy-base-os-authorization.json",
    ".ansible-deploy-base-os-execution.json",
    ".ansible-deploy-base-os-evidence.json",
    ".ansible-deploy-base-os-reconciliation.json",
    ".ansible-deploy-reboot-plan.json",
    ".ansible-deploy-reboot-authorization.json",
    ".ansible-deploy-non-jump-base-os-authorization.json",
    ".ansible-deploy-non-jump-base-os-execution.json",
    ".ansible-deploy-non-jump-base-os-evidence.json",
    ".ansible-deploy-post-non-jump-base-os-reconciliation.json",
    ".ansible-deploy-non-jump-reboot-plan.json",
    ".ansible-deploy-non-jump-reboot-authorization.json",
    ".ansible-deploy-non-jump-reboot-execution.json",
    ".ansible-deploy-non-jump-reboot-evidence.json",
    ".ansible-deploy-post-non-jump-reboot-reconciliation.json",
    ".ansible-deploy-storage-discovery-execution.json",
    ".ansible-deploy-storage-discovery-evidence.json",
    ".ansible-deploy-post-storage-discovery-reconciliation.json",
)

_BASE_STEP_BLOCKERS: dict[str, tuple[str, ...]] = {
    "connectivity-check": ("remote-connectivity-not-performed",),
    "evidence-collect": ("host-evidence-not-performed",),
    "base-os": ("host-evidence-not-performed", "base-os-evidence-not-performed"),
    "storage-discover": (
        "base-os-evidence-not-performed",
        "storage-discovery-not-performed",
    ),
    "storage-preflight": (
        "storage-discovery-not-performed",
        "storage-preflight-not-performed",
    ),
    "storage-prepare": (
        "storage-preflight-not-performed",
        "storage-wipe-consent-not-collected",
    ),
    "storage-postcheck": (
        "storage-prepare-not-performed",
        "storage-postcheck-not-performed",
    ),
    "scylla-install": (
        "storage-postcheck-not-performed",
        "scylla-package-version-unmodeled",
    ),
    "scylla-configure": (
        "scylla-install-not-performed",
        "scylla-configuration-intent-unmodeled",
    ),
    "scylla-bootstrap": (
        "scylla-configuration-not-performed",
        "bootstrap-mode-unmodeled",
        "empty-cluster-proof-not-performed",
        "bootstrap-authorization-not-collected",
    ),
    "scylla-health": (
        "bootstrap-not-performed",
        "empty-cluster-proof-not-performed",
        "cluster-health-not-performed",
        "quorum-evidence-not-performed",
        "backup-policy-evidence-not-performed",
        "capacity-evidence-not-performed",
    ),
    "jump-host-configure": (
        "base-os-evidence-not-performed",
        "jump-host-authorization-not-collected",
    ),
    "manager-agent": (
        "scylla-install-not-performed",
        "manager-package-version-unmodeled",
    ),
    "manager-server": (
        "base-os-evidence-not-performed",
        "manager-package-version-unmodeled",
        "manager-backend-not-performed",
    ),
    "monitoring-agent": (
        "scylla-install-not-performed",
        "monitoring-agent-version-unmodeled",
    ),
    "monitoring-stack": (
        "base-os-evidence-not-performed",
        "monitoring-stack-version-unmodeled",
        "monitoring-startup-not-performed",
    ),
    "monitoring-targets": (
        "monitoring-stack-not-performed",
        "monitoring-targets-not-performed",
    ),
    "manager-tasks": (
        "manager-task-action-unmodeled",
        "manager-backend-not-performed",
        "manager-task-authorization-not-collected",
        "cluster-health-not-performed",
    ),
}


class DeployArtifactState(StrEnum):
    """Immutable companion persistence state."""

    CREATED = "created"
    REUSED = "reused"


class DeployConditionState(StrEnum):
    """Truthful resolution of one documented deploy condition."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    UNMODELED = "unmodeled"


class DeployStepStatus(StrEnum):
    """Whether a step can execute in this planning slice."""

    EXECUTABLE = "executable"
    BLOCKED = "blocked"
    NOT_PERFORMED = "not-performed"


@dataclass(frozen=True, slots=True)
class _DeployPlanningContext:
    base: _ReadinessContext
    readiness: StoredTerraformApplyReadiness


@dataclass(frozen=True, slots=True)
class DeployIntentContext:
    """Explicit allowlist for deploy intent not derivable from current state."""

    connection_policy: str = _UNMODELED
    host_evidence_policy: str = _UNMODELED
    storage_wipe_consent: str = _NOT_COLLECTED
    bootstrap_mode: str = _UNMODELED
    empty_cluster_proof: str = _NOT_PERFORMED
    scylla_package_version: str = _UNMODELED
    manager_package_version: str = _UNMODELED
    manager_task_action: str = _UNMODELED
    manager_backend: str = _NOT_PERFORMED
    monitoring_startup: str = _NOT_PERFORMED
    schema_version: str = ANSIBLE_DEPLOY_INTENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        expected = {
            "connection_policy": _UNMODELED,
            "host_evidence_policy": _UNMODELED,
            "storage_wipe_consent": _NOT_COLLECTED,
            "bootstrap_mode": _UNMODELED,
            "empty_cluster_proof": _NOT_PERFORMED,
            "scylla_package_version": _UNMODELED,
            "manager_package_version": _UNMODELED,
            "manager_task_action": _UNMODELED,
            "manager_backend": _NOT_PERFORMED,
            "monitoring_startup": _NOT_PERFORMED,
            "schema_version": ANSIBLE_DEPLOY_INTENT_SCHEMA_VERSION,
        }
        if any(getattr(self, name) != value for name, value in expected.items()):
            raise StatePersistenceError("deploy intent context is not safely modeled")

    def to_object(self) -> dict[str, object]:
        return {
            name: getattr(self, name)
            for name in DeployIntentContext.__dataclass_fields__
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployIntentContext:
        require_exact_keys(
            value,
            set(DeployIntentContext.__dataclass_fields__),
            "deploy intent context",
        )
        return cls(
            **{
                name: require_string(value, name)
                for name in DeployIntentContext.__dataclass_fields__
            }
        )


@dataclass(frozen=True, slots=True)
class DeployAnsibleContext:
    """Immutable binding from the verified apply chain to safe deploy intent."""

    generation: int
    created_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    verification_artifact_digest: str
    verification_record_digest: str
    apply_inventory_artifact_digest: str
    apply_inventory_record_digest: str
    apply_trust_artifact_digest: str
    apply_trust_record_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    metadata_generation: int
    metadata_digest: str
    desired_spec_digest: str
    source_generation: int
    source_artifact_digest: str
    source_version: str
    source_bundle_digest: str
    observation_generation: int
    observation_artifact_digest: str
    observation_manifest_digest: str
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    trust_generation: int
    trust_artifact_digest: str
    trust_entries_digest: str
    readiness_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    catalog_digest: str
    intent: DeployIntentContext
    intent_digest: str
    record_digest: str
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version != ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.operation != _OPERATION
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
            or not isinstance(self.intent, DeployIntentContext)
        ):
            raise StatePersistenceError("deploy Ansible context identity is invalid")
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for generation in (
            self.journal_generation,
            self.metadata_generation,
            self.source_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
        ):
            if isinstance(generation, bool) or not isinstance(generation, int):
                raise StatePersistenceError("deploy context generation is invalid")
            if generation < 1:
                raise StatePersistenceError("deploy context generation is invalid")
        for name in (
            "request_digest",
            "journal_digest",
            "verification_artifact_digest",
            "verification_record_digest",
            "apply_inventory_artifact_digest",
            "apply_inventory_record_digest",
            "apply_trust_artifact_digest",
            "apply_trust_record_digest",
            "readiness_artifact_digest",
            "readiness_record_digest",
            "metadata_digest",
            "desired_spec_digest",
            "source_artifact_digest",
            "source_bundle_digest",
            "observation_artifact_digest",
            "observation_manifest_digest",
            "inventory_artifact_digest",
            "inventory_digest",
            "trust_artifact_digest",
            "trust_entries_digest",
            "readiness_digest",
            "ansible_source_digest",
            "catalog_digest",
            "intent_digest",
            "record_digest",
        ):
            validate_digest(getattr(self, name), f"deploy context {name}")
        if self.ansible_source_version != ANSIBLE_SOURCE_VERSION:
            raise StatePersistenceError(
                "deploy context Ansible source version conflicts"
            )
        if self.intent_digest != _digest_object(self.intent.to_object()):
            raise StatePersistenceError("deploy context intent digest conflicts")
        if self.record_digest != _context_record_digest(self):
            raise StatePersistenceError("deploy context record digest conflicts")

    def to_object(self) -> dict[str, object]:
        return {
            name: (
                str(value)
                if isinstance(value, uuid.UUID)
                else value.to_object()
                if isinstance(value, DeployIntentContext)
                else value
            )
            for name, value in (
                (field_name, getattr(self, field_name))
                for field_name in DeployAnsibleContext.__dataclass_fields__
            )
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployAnsibleContext:
        require_exact_keys(
            value,
            set(DeployAnsibleContext.__dataclass_fields__),
            "deploy Ansible context",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "metadata_generation",
            "source_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
        }
        parsed: dict[str, object] = {}
        for name in DeployAnsibleContext.__dataclass_fields__:
            item = value[name]
            if name in integer_fields:
                parsed[name] = _integer(item, name)
            elif name in {"cluster_uuid", "operation_id"}:
                parsed[name] = parse_uuid(require_string(value, name), name)
            elif name == "intent":
                if not isinstance(item, Mapping):
                    raise StatePersistenceError(
                        "deploy intent context must be an object"
                    )
                parsed[name] = DeployIntentContext.from_object(item)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployAnsiblePlanStep:
    """Address-free deploy step intent and its truthful prerequisite state."""

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
    status: DeployStepStatus
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
            or not isinstance(self.status, DeployStepStatus)
            or self.classification is not definition.classification
            or self.limit_policy is not definition.limit_policy
            or self.check_mode is not definition.check_mode
            or self.serial != definition.serial
            or self.target_role not in {"all", *_ROLE_ORDER}
        ):
            raise StatePersistenceError("deploy plan step policy is invalid")
        if (
            self.target_ids != tuple(sorted(set(self.target_ids)))
            or any(not _LOGICAL_ID.fullmatch(item) for item in self.target_ids)
            or self.variable_names != tuple(dict.fromkeys(self.variable_names))
            or set(self.variable_names)
            != {variable.name for variable in definition.variables}
            or self.blockers != tuple(sorted(set(self.blockers)))
            or any(not _BLOCKER.fullmatch(blocker) for blocker in self.blockers)
        ):
            raise StatePersistenceError("deploy plan step projection is invalid")
        if self.target_ids:
            validate_playbook_request_policy(
                definition.name,
                limit=self.target_ids,
            )
        if self.status is DeployStepStatus.EXECUTABLE and (
            self.blockers or not self.target_ids
        ):
            raise StatePersistenceError("executable deploy step remains blocked")
        if self.status is DeployStepStatus.BLOCKED and not self.blockers:
            raise StatePersistenceError("blocked deploy step has no blockers")
        if self.condition_state is DeployConditionState.INACTIVE and (
            self.status is not DeployStepStatus.NOT_PERFORMED or self.blockers
        ):
            raise StatePersistenceError("inactive deploy step state is invalid")
        for name in (
            "target_digest",
            "variables_digest",
            "source_digest",
            "command_digest",
        ):
            validate_digest(getattr(self, name), f"deploy plan step {name}")
        if self.target_digest != _digest_object(list(self.target_ids)):
            raise StatePersistenceError("deploy plan step target digest conflicts")

    def to_object(self) -> dict[str, object]:
        return {
            "blockers": list(self.blockers),
            "check_mode": self.check_mode.value,
            "classification": self.classification.value,
            "command_digest": self.command_digest,
            "condition": self.condition,
            "condition_state": self.condition_state.value,
            "limit_policy": self.limit_policy.value,
            "mapping_sequence": self.mapping_sequence,
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
    def from_object(cls, value: Mapping[str, object]) -> DeployAnsiblePlanStep:
        require_exact_keys(
            value,
            {
                "blockers",
                "check_mode",
                "classification",
                "command_digest",
                "condition",
                "condition_state",
                "limit_policy",
                "mapping_sequence",
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
            "deploy Ansible plan step",
        )
        try:
            return cls(
                sequence=_integer(value["sequence"], "sequence"),
                mapping_sequence=_integer(
                    value["mapping_sequence"], "mapping_sequence"
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
                status=DeployStepStatus(require_string(value, "status")),
                blockers=_string_tuple(value["blockers"], "blockers"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Ansible plan step enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployAnsiblePlan:
    """Immutable address-free deterministic deploy Ansible plan binding."""

    generation: int
    created_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    context_artifact_digest: str
    context_record_digest: str
    intent_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    catalog_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    steps: tuple[DeployAnsiblePlanStep, ...]
    blocker_set: tuple[str, ...]
    blocker_digest: str
    step_count: int
    target_count: int
    executable_count: int
    blocked_count: int
    not_performed_count: int
    authorization_state: str
    execution_state: str
    finalization_state: str
    record_digest: str
    context_schema_version: str = ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version != ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION
            or self.context_schema_version != ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
            or self.operation != _OPERATION
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.authorization_state != _NOT_COLLECTED
            or self.execution_state != _NOT_STARTED
            or self.finalization_state != _NOT_STARTED
        ):
            raise StatePersistenceError("deploy Ansible plan identity is invalid")
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        if not self.steps:
            raise StatePersistenceError("deploy Ansible plan must contain steps")
        if tuple(step.sequence for step in self.steps) != tuple(
            range(1, len(self.steps) + 1)
        ):
            raise StatePersistenceError("deploy Ansible plan sequence is invalid")
        expected_mapping = OPERATION_PLAYBOOKS[_OPERATION]
        if {step.mapping_sequence for step in self.steps} != set(
            range(1, len(expected_mapping) + 1)
        ) or any(
            step.playbook != expected_mapping[step.mapping_sequence - 1].playbook
            or step.condition != expected_mapping[step.mapping_sequence - 1].condition
            for step in self.steps
        ):
            raise StatePersistenceError("deploy Ansible plan mapping conflicts")
        blocker_set = tuple(
            sorted({blocker for step in self.steps for blocker in step.blockers})
        )
        targets = {target for step in self.steps for target in step.target_ids}
        status_counts = Counter(step.status for step in self.steps)
        if (
            self.blocker_set != blocker_set
            or self.blocker_digest != _digest_object(list(blocker_set))
            or self.step_count != len(self.steps)
            or self.target_count != len(targets)
            or self.executable_count != status_counts[DeployStepStatus.EXECUTABLE]
            or self.blocked_count != status_counts[DeployStepStatus.BLOCKED]
            or self.not_performed_count != status_counts[DeployStepStatus.NOT_PERFORMED]
            or self.executable_count + self.blocked_count + self.not_performed_count
            != self.step_count
        ):
            raise StatePersistenceError("deploy Ansible plan summary conflicts")
        for name in (
            "request_digest",
            "journal_digest",
            "context_artifact_digest",
            "context_record_digest",
            "intent_digest",
            "readiness_artifact_digest",
            "readiness_record_digest",
            "catalog_digest",
            "ansible_source_digest",
            "blocker_digest",
            "record_digest",
        ):
            validate_digest(getattr(self, name), f"deploy plan {name}")
        if self.record_digest != _plan_record_digest(self):
            raise StatePersistenceError("deploy Ansible plan record digest conflicts")

    def to_object(self) -> dict[str, object]:
        return {
            name: (
                str(value)
                if isinstance(value, uuid.UUID)
                else [step.to_object() for step in value]
                if name == "steps"
                else list(value)
                if name == "blocker_set"
                else value
            )
            for name, value in (
                (field_name, getattr(self, field_name))
                for field_name in DeployAnsiblePlan.__dataclass_fields__
            )
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployAnsiblePlan:
        require_exact_keys(
            value,
            set(DeployAnsiblePlan.__dataclass_fields__),
            "deploy Ansible plan",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "step_count",
            "target_count",
            "executable_count",
            "blocked_count",
            "not_performed_count",
        }
        parsed: dict[str, object] = {}
        for name in DeployAnsiblePlan.__dataclass_fields__:
            item = value[name]
            if name in integer_fields:
                parsed[name] = _integer(item, name)
            elif name in {"cluster_uuid", "operation_id"}:
                parsed[name] = parse_uuid(require_string(value, name), name)
            elif name == "steps":
                if not isinstance(item, list):
                    raise StatePersistenceError("deploy plan steps must be an array")
                if not all(isinstance(step, Mapping) for step in item):
                    raise StatePersistenceError("deploy plan step must be an object")
                parsed[name] = tuple(
                    DeployAnsiblePlanStep.from_object(step) for step in item
                )
            elif name == "blocker_set":
                parsed[name] = _string_tuple(item, name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployAnsibleContext:
    record: DeployAnsibleContext
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployAnsiblePlan:
    record: DeployAnsiblePlan
    artifact_digest: str


class DeployAnsibleContextStore:
    """Owner-only immutable deploy context companion."""

    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        _require_canonical_paths(paths)
        self._paths = paths
        self._operation_id = _require_operation_id(operation_id)
        self._path = deploy_ansible_context_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployAnsibleContext:
        value, artifact_digest = self._file.read()
        record = DeployAnsibleContext.from_object(value)
        if artifact_digest != _artifact_digest(record.to_object()):
            raise StatePersistenceError(
                "deploy context artifact serialization conflicts"
            )
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError("deploy context identity conflicts")
        return StoredDeployAnsibleContext(record, artifact_digest)

    def write_locked(
        self,
        record: DeployAnsibleContext,
        *,
        lock: ClusterLock,
    ) -> tuple[StoredDeployAnsibleContext, DeployArtifactState]:
        _assert_operation_lock(lock, self._paths, self._operation_id)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError("deploy context operation ID conflicts")
        if self._path.exists():
            current = self.read(
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError("deploy Ansible context is immutable")
            return current, DeployArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployAnsibleContext(record, artifact_digest),
            DeployArtifactState.CREATED,
        )


class DeployAnsiblePlanStore:
    """Owner-only immutable deploy plan companion."""

    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        _require_canonical_paths(paths)
        self._paths = paths
        self._operation_id = _require_operation_id(operation_id)
        self._path = deploy_ansible_plan_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployAnsiblePlan:
        value, artifact_digest = self._file.read()
        record = DeployAnsiblePlan.from_object(value)
        if artifact_digest != _artifact_digest(record.to_object()):
            raise StatePersistenceError("deploy plan artifact serialization conflicts")
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError("deploy plan identity conflicts")
        return StoredDeployAnsiblePlan(record, artifact_digest)

    def write_locked(
        self,
        record: DeployAnsiblePlan,
        *,
        lock: ClusterLock,
    ) -> tuple[StoredDeployAnsiblePlan, DeployArtifactState]:
        _assert_operation_lock(lock, self._paths, self._operation_id)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError("deploy plan operation ID conflicts")
        if self._path.exists():
            current = self.read(
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError("deploy Ansible plan is immutable")
            return current, DeployArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployAnsiblePlan(record, artifact_digest),
            DeployArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployAnsiblePlanReport:
    """Strict address-free report for deploy context and plan binding."""

    operation_id: uuid.UUID
    context_state: DeployArtifactState
    plan_state: DeployArtifactState
    context_artifact_digest: str
    context_record_digest: str
    plan_artifact_digest: str
    plan_record_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    catalog_digest: str
    ansible_source_digest: str
    blocker_digest: str
    step_count: int
    target_count: int
    executable_count: int
    blocked_count: int
    not_performed_count: int
    playbook_counts: tuple[tuple[str, int], ...]
    role_target_counts: tuple[tuple[str, int], ...]
    blocker_set: tuple[str, ...]
    journal_status: JournalStatus
    journal_phase: OperationPhase
    journal_generation: int
    journal_digest: str
    authorization_state: str
    execution_state: str
    finalization_state: str
    context_schema_version: str = ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
    plan_schema_version: str = ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_PLAN_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_PLAN_REPORT_SCHEMA_VERSION
            or self.context_schema_version != ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
            or self.plan_schema_version != ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION
            or not isinstance(self.operation_id, uuid.UUID)
            or not isinstance(self.context_state, DeployArtifactState)
            or not isinstance(self.plan_state, DeployArtifactState)
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.authorization_state != _NOT_COLLECTED
            or self.execution_state != _NOT_STARTED
            or self.finalization_state != _NOT_STARTED
        ):
            raise StatePersistenceError("deploy Ansible plan report is invalid")
        for count in (
            self.step_count,
            self.target_count,
            self.executable_count,
            self.blocked_count,
            self.not_performed_count,
            self.journal_generation,
        ):
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise StatePersistenceError("deploy plan report count is invalid")
        if (
            self.step_count < 1
            or self.journal_generation < 1
            or self.executable_count + self.blocked_count + self.not_performed_count
            != self.step_count
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(not _BLOCKER.fullmatch(item) for item in self.blocker_set)
        ):
            raise StatePersistenceError("deploy plan report summary is invalid")
        for name in (
            "context_artifact_digest",
            "context_record_digest",
            "plan_artifact_digest",
            "plan_record_digest",
            "readiness_artifact_digest",
            "readiness_record_digest",
            "catalog_digest",
            "ansible_source_digest",
            "blocker_digest",
            "journal_digest",
        ):
            validate_digest(getattr(self, name), f"deploy plan report {name}")
        _validate_counts(self.playbook_counts, "playbook")
        _validate_counts(self.role_target_counts, "role")

    def to_object(self) -> dict[str, object]:
        return {
            "ansible_source_digest": self.ansible_source_digest,
            "authorization_state": self.authorization_state,
            "blocked_count": self.blocked_count,
            "blocker_digest": self.blocker_digest,
            "blocker_set": list(self.blocker_set),
            "catalog_digest": self.catalog_digest,
            "context_artifact_digest": self.context_artifact_digest,
            "context_record_digest": self.context_record_digest,
            "context_schema_version": self.context_schema_version,
            "context_state": self.context_state.value,
            "executable_count": self.executable_count,
            "execution_state": self.execution_state,
            "finalization_state": self.finalization_state,
            "journal_digest": self.journal_digest,
            "journal_generation": self.journal_generation,
            "journal_phase": self.journal_phase.value,
            "journal_status": self.journal_status.value,
            "not_performed_count": self.not_performed_count,
            "operation_id": str(self.operation_id),
            "plan_artifact_digest": self.plan_artifact_digest,
            "plan_record_digest": self.plan_record_digest,
            "plan_schema_version": self.plan_schema_version,
            "plan_state": self.plan_state.value,
            "playbook_counts": [
                {"playbook": name, "step_count": count}
                for name, count in self.playbook_counts
            ],
            "readiness_artifact_digest": self.readiness_artifact_digest,
            "readiness_record_digest": self.readiness_record_digest,
            "role_target_counts": [
                {"role": name, "target_count": count}
                for name, count in self.role_target_counts
            ],
            "schema_version": self.schema_version,
            "step_count": self.step_count,
            "target_count": self.target_count,
        }


def _load_deploy_planning_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> _DeployPlanningContext:
    base = _load_readiness_context(paths, operation_id)
    store = TerraformApplyReadinessStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    if not store.path.exists():
        raise StateConflictError(
            "deploy Ansible planning requires current local readiness"
        )
    stored = store.read(
        expected_cluster_uuid=base.deploy.metadata.record.cluster_uuid,
        expected_cluster_name=base.deploy.metadata.record.cluster_name,
    )
    record = stored.record
    deploy = base.deploy
    if (
        stored.artifact_digest != _artifact_digest(record.to_object())
        or record.operation_id != operation_id
        or record.request_digest != deploy.journal.record.request_digest
        or record.journal_generation != deploy.journal.record.generation
        or record.journal_digest != deploy.journal.digest
        or record.verification_artifact_digest != deploy.verification.artifact_digest
        or record.verification_record_digest != deploy.verification.record.record_digest
        or record.apply_inventory_artifact_digest
        != deploy.apply_inventory.artifact_digest
        or record.apply_inventory_record_digest
        != deploy.apply_inventory.record.record_digest
        or record.apply_trust_artifact_digest != base.apply_trust.artifact_digest
        or record.apply_trust_record_digest != base.apply_trust.record.record_digest
        or record.metadata_generation != deploy.metadata.record.generation
        or record.metadata_digest != deploy.metadata.digest
        or record.desired_spec_digest != deploy.metadata.record.desired_spec.digest()
        or record.source_generation != deploy.source.record.generation
        or record.source_artifact_digest != deploy.source.digest
        or record.source_version != deploy.source.record.source_version
        or record.source_bundle_digest != deploy.source.record.bundle_digest
        or record.observation_generation != deploy.observation.record.generation
        or record.observation_artifact_digest != deploy.observation.digest
        or record.observation_manifest_digest
        != deploy.observation.record.manifest_digest
        or record.inventory_generation != deploy.inventory.record.generation
        or record.inventory_artifact_digest != deploy.inventory.digest
        or record.inventory_digest != deploy.inventory.record.inventory_digest
        or record.trust_generation != base.trust.record.generation
        or record.trust_artifact_digest != base.trust.digest
        or record.trust_entries_digest != base.trust.record.entries_digest
        or record.ansible_source_version != base.ansible_source.version
        or record.ansible_source_digest != base.ansible_source.digest
        or record.config_digest != validate_ansible_config(paths)
    ):
        raise StateConflictError(
            "deploy Ansible readiness chain is stale or conflicting"
        )
    return _DeployPlanningContext(base, stored)


def bind_deploy_ansible_plan(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployAnsiblePlanReport:
    """Bind deploy Ansible intent and a deterministic plan without processes."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths, operation_id)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_operation_artifacts(paths, operation_id)
    _refuse_generic_operation_companions(paths, operation_id)
    _refuse_advanced_deploy_companions(paths, operation_id)

    # This loader revalidates the complete apply verification, generated
    # inventory, complete trust, rendered derivatives, and local readiness chain.
    context = _load_deploy_planning_context(paths, operation_id)
    if (
        context.base.deploy.journal.record.status is not JournalStatus.IN_PROGRESS
        or context.base.deploy.journal.record.phase is not OperationPhase.VERIFY
    ):
        raise StateConflictError("deploy Ansible planning requires VERIFY phase")
    readiness = context.readiness.record
    if (
        readiness.remote_connectivity_status != _NOT_PERFORMED
        or readiness.remote_health_status != _NOT_PERFORMED
        or readiness.remote_playbook_status != _NOT_PERFORMED
    ):
        raise StateConflictError("deploy readiness remote status conflicts")

    source_bundle = load_ansible_source_bundle()
    catalog_digest = ansible_operation_catalog_digest()
    context_store = DeployAnsibleContextStore(paths, operation_id)
    plan_store = DeployAnsiblePlanStore(paths, operation_id)
    validate_state_file(context_store.path, allow_missing=True)
    validate_state_file(plan_store.path, allow_missing=True)
    existing_context = (
        context_store.read(
            expected_cluster_uuid=context.base.deploy.metadata.record.cluster_uuid,
            expected_cluster_name=context.base.deploy.metadata.record.cluster_name,
        )
        if context_store.path.exists()
        else None
    )
    created_at = (
        existing_context.record.created_at
        if existing_context is not None
        else _timestamp(_utc_now())
    )
    intent = DeployIntentContext()
    context_record = _build_context(
        context,
        source_bundle=source_bundle,
        catalog_digest=catalog_digest,
        intent=intent,
        created_at=created_at,
    )
    steps = _build_steps(
        context,
        source_bundle=source_bundle,
    )

    # Validate both records fully in memory before the acyclic context -> plan
    # persistence order.  A context-only prefix is safe to resume.
    context_artifact_digest = (
        existing_context.artifact_digest
        if existing_context is not None and existing_context.record == context_record
        else _artifact_digest(context_record.to_object())
    )
    if existing_context is not None and existing_context.record != context_record:
        raise StateConflictError("deploy Ansible context is immutable")
    plan_record = _build_plan(
        context_record=context_record,
        context_artifact_digest=context_artifact_digest,
        steps=steps,
        source_bundle=source_bundle,
        catalog_digest=catalog_digest,
        created_at=created_at,
    )
    existing_plan = (
        plan_store.read(
            expected_cluster_uuid=context.base.deploy.metadata.record.cluster_uuid,
            expected_cluster_name=context.base.deploy.metadata.record.cluster_name,
        )
        if plan_store.path.exists()
        else None
    )
    if existing_plan is not None and existing_context is None:
        raise StateConflictError("deploy plan exists without its context")
    if existing_plan is not None and existing_plan.record != plan_record:
        raise StateConflictError("deploy Ansible plan is immutable")

    stored_context, context_state = context_store.write_locked(
        context_record, lock=lock
    )
    if stored_context.artifact_digest != context_artifact_digest:
        raise StateConflictError("deploy context persistence digest conflicts")
    stored_plan, plan_state = plan_store.write_locked(plan_record, lock=lock)
    return _build_report(
        context,
        stored_context=stored_context,
        context_state=context_state,
        stored_plan=stored_plan,
        plan_state=plan_state,
    )


def deploy_ansible_context_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / f"{operation_id}{DEPLOY_CONTEXT_FILENAME_SUFFIX}"
    if path.parent != paths.operations:
        raise StatePersistenceError("deploy Ansible context path is not canonical")
    return path


def deploy_ansible_plan_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / f"{operation_id}{DEPLOY_PLAN_FILENAME_SUFFIX}"
    if path.parent != paths.operations:
        raise StatePersistenceError("deploy Ansible plan path is not canonical")
    return path


def deploy_ansible_context_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(name, DEPLOY_CONTEXT_FILENAME_SUFFIX)


def deploy_ansible_plan_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(name, DEPLOY_PLAN_FILENAME_SUFFIX)


def _build_context(
    context: _DeployPlanningContext,
    *,
    source_bundle: AnsibleSourceBundle,
    catalog_digest: str,
    intent: DeployIntentContext,
    created_at: str,
) -> DeployAnsibleContext:
    metadata = context.base.deploy.metadata.record
    readiness = context.readiness.record
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_name": metadata.cluster_name,
        "operation_id": readiness.operation_id,
        "operation": _OPERATION,
        "request_digest": readiness.request_digest,
        "journal_generation": readiness.journal_generation,
        "journal_digest": readiness.journal_digest,
        "verification_artifact_digest": readiness.verification_artifact_digest,
        "verification_record_digest": readiness.verification_record_digest,
        "apply_inventory_artifact_digest": readiness.apply_inventory_artifact_digest,
        "apply_inventory_record_digest": readiness.apply_inventory_record_digest,
        "apply_trust_artifact_digest": readiness.apply_trust_artifact_digest,
        "apply_trust_record_digest": readiness.apply_trust_record_digest,
        "readiness_artifact_digest": context.readiness.artifact_digest,
        "readiness_record_digest": readiness.record_digest,
        "metadata_generation": readiness.metadata_generation,
        "metadata_digest": readiness.metadata_digest,
        "desired_spec_digest": readiness.desired_spec_digest,
        "source_generation": readiness.source_generation,
        "source_artifact_digest": readiness.source_artifact_digest,
        "source_version": readiness.source_version,
        "source_bundle_digest": readiness.source_bundle_digest,
        "observation_generation": readiness.observation_generation,
        "observation_artifact_digest": readiness.observation_artifact_digest,
        "observation_manifest_digest": readiness.observation_manifest_digest,
        "inventory_generation": readiness.inventory_generation,
        "inventory_artifact_digest": readiness.inventory_artifact_digest,
        "inventory_digest": readiness.inventory_digest,
        "trust_generation": readiness.trust_generation,
        "trust_artifact_digest": readiness.trust_artifact_digest,
        "trust_entries_digest": readiness.trust_entries_digest,
        "readiness_digest": readiness.readiness_digest,
        "ansible_source_version": source_bundle.version,
        "ansible_source_digest": source_bundle.digest,
        "catalog_digest": catalog_digest,
        "intent": intent,
        "intent_digest": _digest_object(intent.to_object()),
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(DeployAnsibleContext, values)
    return DeployAnsibleContext(**values)  # type: ignore[arg-type]


def _build_steps(
    context: _DeployPlanningContext,
    *,
    source_bundle: AnsibleSourceBundle,
) -> tuple[DeployAnsiblePlanStep, ...]:
    hosts = tuple(
        sorted(
            context.base.deploy.inventory.record.inventory.hosts,
            key=lambda host: host.logical_id,
        )
    )
    role_targets = {
        role: tuple(host.logical_id for host in hosts if host.role.value == role)
        for role in _ROLE_ORDER
    }
    all_targets = tuple(host.logical_id for host in hosts)
    non_jump_targets = tuple(
        host.logical_id for host in hosts if host.role.value != "jump-host"
    )
    jump_exists = bool(role_targets["jump-host"])
    steps: list[DeployAnsiblePlanStep] = []
    sequence = 1
    for mapping_sequence, mapped_step in enumerate(
        OPERATION_PLAYBOOKS[_OPERATION],
        start=1,
    ):
        playbook_name = mapped_step.playbook
        condition = mapped_step.condition
        definition = get_playbook(playbook_name)
        condition_state = _condition_state(condition, jump_exists=jump_exists)
        targets, target_role = _targets_for_step(
            playbook_name,
            condition,
            condition_state=condition_state,
            all_targets=all_targets,
            non_jump_targets=non_jump_targets,
            role_targets=role_targets,
            jump_exists=jump_exists,
        )
        target_sets = _expand_target_sets(
            definition,
            targets,
            condition_state=condition_state,
        )
        for target_ids in target_sets:
            variable_names = tuple(variable.name for variable in definition.variables)
            variable_values = _safe_variable_values(
                context,
                definition=definition,
                target_ids=target_ids,
            )
            blockers = _step_blockers(
                playbook_name,
                condition_state=condition_state,
                target_ids=target_ids,
                variable_names=variable_names,
                variable_values=variable_values,
            )
            status = (
                DeployStepStatus.NOT_PERFORMED
                if condition_state is DeployConditionState.INACTIVE
                else DeployStepStatus.BLOCKED
                if blockers
                else DeployStepStatus.EXECUTABLE
            )
            # Keep the PLAN command identity byte-for-byte compatible with the
            # anchored runtime builder. The playbook is already bound by the
            # command-intent digest and must not be mixed into this digest.
            variables_digest = digest_bytes(serialize_json(variable_values))
            source_digest = _playbook_source_digest(source_bundle, playbook_name)
            command_digest = ansible_command_intent_digest(
                definition,
                step_sequence=sequence,
                limit=target_ids,
                variables_digest=variables_digest,
                tags=(),
                check=False,
                diff=False,
                verbosity=0,
            )
            steps.append(
                DeployAnsiblePlanStep(
                    sequence=sequence,
                    mapping_sequence=mapping_sequence,
                    playbook=playbook_name,
                    condition=condition,
                    condition_state=condition_state,
                    classification=definition.classification,
                    target_role=target_role,
                    target_ids=target_ids,
                    target_digest=_digest_object(list(target_ids)),
                    limit_policy=definition.limit_policy,
                    serial=definition.serial,
                    check_mode=definition.check_mode,
                    variable_names=variable_names,
                    variables_digest=variables_digest,
                    source_digest=source_digest,
                    command_digest=command_digest,
                    status=status,
                    blockers=blockers,
                )
            )
            sequence += 1
    return tuple(steps)


def _build_plan(
    *,
    context_record: DeployAnsibleContext,
    context_artifact_digest: str,
    steps: tuple[DeployAnsiblePlanStep, ...],
    source_bundle: AnsibleSourceBundle,
    catalog_digest: str,
    created_at: str,
) -> DeployAnsiblePlan:
    blocker_set = tuple(
        sorted({blocker for step in steps for blocker in step.blockers})
    )
    status_counts = Counter(step.status for step in steps)
    targets = {target for step in steps for target in step.target_ids}
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": context_record.cluster_uuid,
        "cluster_name": context_record.cluster_name,
        "operation_id": context_record.operation_id,
        "operation": _OPERATION,
        "request_digest": context_record.request_digest,
        "journal_generation": context_record.journal_generation,
        "journal_digest": context_record.journal_digest,
        "context_artifact_digest": context_artifact_digest,
        "context_record_digest": context_record.record_digest,
        "intent_digest": context_record.intent_digest,
        "readiness_artifact_digest": context_record.readiness_artifact_digest,
        "readiness_record_digest": context_record.readiness_record_digest,
        "catalog_digest": catalog_digest,
        "ansible_source_version": source_bundle.version,
        "ansible_source_digest": source_bundle.digest,
        "steps": steps,
        "blocker_set": blocker_set,
        "blocker_digest": _digest_object(list(blocker_set)),
        "step_count": len(steps),
        "target_count": len(targets),
        "executable_count": status_counts[DeployStepStatus.EXECUTABLE],
        "blocked_count": status_counts[DeployStepStatus.BLOCKED],
        "not_performed_count": status_counts[DeployStepStatus.NOT_PERFORMED],
        "authorization_state": _NOT_COLLECTED,
        "execution_state": _NOT_STARTED,
        "finalization_state": _NOT_STARTED,
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(DeployAnsiblePlan, values)
    return DeployAnsiblePlan(**values)  # type: ignore[arg-type]


def _build_report(
    context: _DeployPlanningContext,
    *,
    stored_context: StoredDeployAnsibleContext,
    context_state: DeployArtifactState,
    stored_plan: StoredDeployAnsiblePlan,
    plan_state: DeployArtifactState,
) -> DeployAnsiblePlanReport:
    plan = stored_plan.record
    playbook_counts = tuple(
        sorted(Counter(step.playbook for step in plan.steps).items())
    )
    role_targets: dict[str, set[str]] = {role: set() for role in _ROLE_ORDER}
    host_roles = {
        host.logical_id: host.role.value
        for host in context.base.deploy.inventory.record.inventory.hosts
    }
    for step in plan.steps:
        for target in step.target_ids:
            role_targets[host_roles[target]].add(target)
    return DeployAnsiblePlanReport(
        operation_id=plan.operation_id,
        context_state=context_state,
        plan_state=plan_state,
        context_artifact_digest=stored_context.artifact_digest,
        context_record_digest=stored_context.record.record_digest,
        plan_artifact_digest=stored_plan.artifact_digest,
        plan_record_digest=plan.record_digest,
        readiness_artifact_digest=plan.readiness_artifact_digest,
        readiness_record_digest=plan.readiness_record_digest,
        catalog_digest=plan.catalog_digest,
        ansible_source_digest=plan.ansible_source_digest,
        blocker_digest=plan.blocker_digest,
        step_count=plan.step_count,
        target_count=plan.target_count,
        executable_count=plan.executable_count,
        blocked_count=plan.blocked_count,
        not_performed_count=plan.not_performed_count,
        playbook_counts=playbook_counts,
        role_target_counts=tuple(
            sorted((role, len(role_targets[role])) for role in _ROLE_ORDER)
        ),
        blocker_set=plan.blocker_set,
        journal_status=context.base.deploy.journal.record.status,
        journal_phase=context.base.deploy.journal.record.phase,
        journal_generation=context.base.deploy.journal.record.generation,
        journal_digest=context.base.deploy.journal.digest,
        authorization_state=plan.authorization_state,
        execution_state=plan.execution_state,
        finalization_state=plan.finalization_state,
    )


def _safe_variable_values(
    context: _DeployPlanningContext,
    *,
    definition: PlaybookDefinition,
    target_ids: tuple[str, ...],
) -> dict[str, object]:
    readiness = context.readiness.record
    hosts = {
        host.logical_id: host
        for host in context.base.deploy.inventory.record.inventory.hosts
    }
    image_filters = dict(context.base.deploy.metadata.record.desired_spec.image_filters)
    selected_filters = tuple(
        image_filters[hosts[target_id].role]
        for target_id in target_ids
        if target_id in hosts and hosts[target_id].role in image_filters
    )
    operating_systems = {
        image_filter.operating_system for image_filter in selected_filters
    }
    operating_system_versions = {
        image_filter.operating_system_version for image_filter in selected_filters
    }
    os_family = next(iter(operating_systems)) if len(operating_systems) == 1 else None
    os_version = (
        next(iter(operating_system_versions))
        if len(operating_system_versions) == 1
        else None
    )
    common = {
        "deploy_scylla_vms_cluster_uuid": str(
            context.base.deploy.metadata.record.cluster_uuid
        ),
        "deploy_scylla_vms_inventory_digest": readiness.inventory_digest,
        "deploy_scylla_vms_checkpoint_id": str(readiness.operation_id),
    }
    if os_family is not None:
        common["deploy_scylla_vms_os_family"] = os_family
        common["deploy_scylla_vms_image_operating_system"] = os_family
    if os_version is not None:
        common["deploy_scylla_vms_os_major"] = os_version.split(".", 1)[0]
        common["deploy_scylla_vms_image_operating_system_version"] = os_version
    if definition.name == "inventory-preflight":
        # Inventory provenance and operation targets are injected only by the
        # controlled service from current canonical state.
        return {}
    if definition.name == "connectivity-check":
        # The initial and final route checks are SSH-only unless a later
        # reviewed plan schema explicitly models destination probes.
        return {
            "deploy_scylla_vms_connect_timeout_seconds": (
                _DEPLOY_CONNECT_TIMEOUT_SECONDS
            ),
            "deploy_scylla_vms_destination_probes": [],
            "deploy_scylla_vms_probe_timeout_seconds": (_DEPLOY_PROBE_TIMEOUT_SECONDS),
        }
    values: dict[str, object] = {}
    for name in (variable.name for variable in definition.variables):
        if name in common:
            values[name] = common[name]
        else:
            values[name] = {
                "state": _NOT_PERFORMED,
                "intent": _UNMODELED,
                "target_digest": _digest_object(list(target_ids)),
            }
    return values


def _step_blockers(
    playbook: str,
    *,
    condition_state: DeployConditionState,
    target_ids: tuple[str, ...],
    variable_names: tuple[str, ...],
    variable_values: Mapping[str, object],
) -> tuple[str, ...]:
    if condition_state is DeployConditionState.INACTIVE:
        return ()
    blockers = {_PUBLIC_WORKFLOW_BLOCKER}
    blockers.update(_BASE_STEP_BLOCKERS.get(playbook, ()))
    if condition_state is DeployConditionState.UNMODELED:
        blockers.add("deploy-condition-unmodeled")
    if not target_ids:
        blockers.add("deploy-targets-unavailable")
    if any(
        name not in variable_values or isinstance(variable_values[name], Mapping)
        for name in variable_names
        if name
        not in {
            "deploy_scylla_vms_cluster_uuid",
            "deploy_scylla_vms_inventory_digest",
            "deploy_scylla_vms_checkpoint_id",
        }
    ):
        blockers.add("step-variable-evidence-not-performed")
    return tuple(sorted(blockers))


def _targets_for_step(
    playbook: str,
    condition: str,
    *,
    condition_state: DeployConditionState,
    all_targets: tuple[str, ...],
    non_jump_targets: tuple[str, ...],
    role_targets: Mapping[str, tuple[str, ...]],
    jump_exists: bool,
) -> tuple[tuple[str, ...], str]:
    definition = get_playbook(playbook)
    if condition_state is DeployConditionState.INACTIVE:
        return (), _target_role(definition)
    if playbook == "inventory-preflight" or (
        playbook == "connectivity-check" and condition == "final-routes"
    ):
        return all_targets, "all"
    if playbook == "connectivity-check":
        # The first deploy connectivity gate proves SSH reachability for the
        # complete immutable host set, including routed private hosts.
        return all_targets, "all"
    if playbook == "evidence-collect":
        return all_targets, "all"
    if playbook == "base-os" and condition == "jump-hosts-exist":
        return role_targets["jump-host"], "jump-host"
    if playbook == "base-os" and condition == "non-jump-managed-hosts":
        return non_jump_targets, "all"
    return role_targets[_target_role(definition)], _target_role(definition)


def _target_role(definition: PlaybookDefinition) -> str:
    if definition.target_groups == ("all",):
        return "all"
    if len(definition.target_groups) != 1:
        raise StatePersistenceError("deploy playbook target role is ambiguous")
    role = {
        "jump_hosts": "jump-host",
        "scylla": "scylla",
        "manager": "manager",
        "monitoring": "monitoring",
    }.get(definition.target_groups[0], "")
    if role not in _ROLE_ORDER:
        raise StatePersistenceError("deploy playbook target role is invalid")
    return role


def _expand_target_sets(
    definition: PlaybookDefinition,
    targets: tuple[str, ...],
    *,
    condition_state: DeployConditionState,
) -> tuple[tuple[str, ...], ...]:
    if condition_state is DeployConditionState.INACTIVE or not targets:
        return ((),)
    if definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST:
        return tuple((target,) for target in targets)
    return (targets,)


def _condition_state(condition: str, *, jump_exists: bool) -> DeployConditionState:
    if condition == "always":
        return DeployConditionState.ACTIVE
    if condition == "jump-hosts-exist":
        return (
            DeployConditionState.ACTIVE
            if jump_exists
            else DeployConditionState.INACTIVE
        )
    if condition in {"final-routes", "non-jump-managed-hosts"}:
        return DeployConditionState.ACTIVE
    if condition == "explicit-task-action":
        return DeployConditionState.UNMODELED
    raise StatePersistenceError("deploy playbook condition is unsupported")


def _refuse_generic_operation_companions(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    for suffix in _GENERIC_COMPANION_SUFFIXES:
        path = paths.operations / f"{operation_id}{suffix}"
        validate_state_file(path, allow_missing=True)
        if path.exists():
            raise StateConflictError(
                "deploy Ansible planning refuses generic operation companions"
            )


def _refuse_advanced_deploy_companions(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    for suffix in _DEPLOY_ADVANCED_COMPANION_SUFFIXES:
        path = paths.operations / f"{operation_id}{suffix}"
        validate_state_file(path, allow_missing=True)
        if path.exists():
            raise StateConflictError(
                "deploy Ansible planning refuses advanced execution companions"
            )


def _refuse_ambiguous_operation_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    suffixes = (
        DEPLOY_CONTEXT_FILENAME_SUFFIX,
        DEPLOY_PLAN_FILENAME_SUFFIX,
        *_GENERIC_COMPANION_SUFFIXES,
        *_DEPLOY_ADVANCED_COMPANION_SUFFIXES,
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Ansible operation artifacts"
        ) from error
    canonical = str(operation_id)
    for entry in entries:
        for suffix in suffixes:
            if not entry.name.endswith(suffix):
                continue
            prefix = entry.name[: -len(suffix)]
            try:
                parsed = uuid.UUID(prefix)
            except ValueError:
                break
            if parsed == operation_id and prefix != canonical:
                validate_state_file(entry)
                raise StateConflictError(
                    "deploy Ansible operation artifacts are ambiguous"
                )
            break


def _context_record_digest(record: DeployAnsibleContext) -> str:
    value = record.to_object()
    value["record_digest"] = ""
    return _digest_object(value)


def _plan_record_digest(record: DeployAnsiblePlan) -> str:
    value = record.to_object()
    value["record_digest"] = ""
    return _digest_object(value)


def _record_digest_from_values(
    record_type: type[DeployAnsibleContext] | type[DeployAnsiblePlan],
    values: Mapping[str, object],
) -> str:
    value: dict[str, object] = {}
    for name in record_type.__dataclass_fields__:
        item = values.get(name, record_type.__dataclass_fields__[name].default)
        value[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.to_object()
            if isinstance(item, DeployIntentContext)
            else [step.to_object() for step in item]
            if name == "steps" and isinstance(item, tuple)
            else list(item)
            if name == "blocker_set" and isinstance(item, tuple)
            else item
        )
    value["record_digest"] = ""
    return _digest_object(value)


def _playbook_source_digest(
    source_bundle: AnsibleSourceBundle, playbook_name: str
) -> str:
    expected_path = f"playbooks/{get_playbook(playbook_name).filename}"
    matches = tuple(
        source_file.digest
        for source_file in source_bundle.files
        if source_file.path == expected_path
    )
    if len(matches) != 1:
        raise StatePersistenceError("deploy playbook source binding is incomplete")
    validate_digest(matches[0], "deploy playbook source digest")
    return matches[0]


def _digest_object(value: object) -> str:
    return digest_bytes(serialize_json({"value": value}))


def _artifact_digest(value: Mapping[str, object]) -> str:
    return digest_bytes(serialize_json(value))


def _assert_operation_lock(
    lock: ClusterLock, paths: StatePaths, operation_id: uuid.UUID
) -> None:
    del operation_id
    lock.assert_held_for_operation(paths, _OPERATION)


def _require_canonical_paths(paths: StatePaths) -> None:
    expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
    if expected != paths:
        raise StatePersistenceError("deploy Ansible paths are not canonical")


def _require_operation_id(operation_id: uuid.UUID) -> uuid.UUID:
    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError("deploy Ansible operation ID must be a UUID")
    return operation_id


def _operation_id_from_filename(name: str, suffix: str) -> uuid.UUID | None:
    if not name.endswith(suffix):
        return None
    value = name[: -len(suffix)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    if str(operation_id) != value:
        return None
    return operation_id


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"deploy Ansible {label} must be an integer")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    if value is None:
        return None
    return _integer(value, label)


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise StatePersistenceError(f"deploy Ansible {label} must be a string array")
    return tuple(value)


def _validate_counts(values: tuple[tuple[str, int], ...], label: str) -> None:
    if values != tuple(sorted(values)) or len(values) != len(
        {name for name, _ in values}
    ):
        raise StatePersistenceError(f"deploy plan report {label} counts are invalid")
    for name, count in values:
        if (
            not _LOGICAL_ID.fullmatch(name)
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
        ):
            raise StatePersistenceError(f"deploy plan report {label} count is invalid")


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise StatePersistenceError("deploy Ansible planning clock must return UTC")
    return format_timestamp(value)


def _utc_now() -> datetime:
    return datetime.now(UTC)
