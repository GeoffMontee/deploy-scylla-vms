"""Deploy-specific read-only storage preflight and immutable reconciliation.

This internal owner derives the sole eligible Scylla scope from the complete
storage-discovery reconciliation chain. It records started intent before the
controlled call, projects exact disposition evidence without device paths, and
derives only the immediate storage-preparation authorization scope.
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
    AnsibleCommandBuilder,
    ansible_command_intent_digest,
    validate_playbook_request_policy,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStep,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_non_jump_base_os_reconciliation import (
    DeployPostNonJumpBaseOsNextStepSummary,
)
from scylla_vms.ansible.deploy_plan import (
    DeployConditionState,
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_storage_discovery import (
    ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION,
    DeployPostStorageDiscoveryReconciliationStore,
    DeployStorageDiscoveryEvidenceStore,
    DeployStorageDiscoveryExecutionState,
    DeployStorageDiscoveryExecutionStore,
    StoredDeployPostStorageDiscoveryReconciliation,
    StoredDeployStorageDiscoveryEvidence,
    StoredDeployStorageDiscoveryExecution,
    _load_storage_discovery_context,
    _StorageDiscoveryContext,
)
from scylla_vms.ansible.deploy_storage_discovery import (
    _build_reconciled_steps as _build_post_storage_discovery_steps,
)
from scylla_vms.ansible.deploy_storage_discovery import (
    _build_reconciliation_record as _build_post_storage_discovery_record,
)
from scylla_vms.ansible.deploy_storage_discovery import (
    _validate_execution_prefix as _validate_storage_discovery_prefix,
)
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.registry import (
    OPERATION_PLAYBOOKS,
    CheckMode,
    LimitPolicy,
    get_playbook,
)
from scylla_vms.ansible.service import (
    AnsibleExecutionResult,
    AnsibleResultError,
    AnsibleService,
    ProcessRunnerProtocol,
)
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION
from scylla_vms.ansible.storage_preflight import (
    STORAGE_PREFLIGHT_SCHEMA_VERSION,
    SelectedStorageDevice,
    StorageHostPreflight,
    StorageOwnershipStatus,
    StoragePreflightResult,
    parse_storage_preflight_execution,
)
from scylla_vms.ansible.toolchain import AnsibleToolchain
from scylla_vms.desired import HostRole
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.journal import JOURNAL_SCHEMA_VERSION, JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import (
    AtomicJsonFile,
    ClusterMetadata,
    digest_bytes,
    format_timestamp,
    parse_timestamp,
    parse_uuid,
    require_exact_keys,
    require_string,
    serialize_json,
    validate_digest,
)
from scylla_vms.process import ProcessOutputError, ProcessTimeoutError
from scylla_vms.state import (
    StatePaths,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)
from scylla_vms.terraform.apply_readiness import (
    TERRAFORM_APPLY_READINESS_SCHEMA_VERSION,
    _executable_identity_digest,
    _toolchain_evidence_digest,
    _validate_toolchain_dependency,
)

ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-preflight-execution-binding/v1"
)
ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-preflight-execution/v1"
)
ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-preflight-evidence/v1"
)
ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-preflight-execution-report/v1"
)
ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-storage-preflight-reconciliation/v1"
)
ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-storage-preflight-reconciliation-report/v1"
)

DEPLOY_STORAGE_PREFLIGHT_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-storage-preflight-execution.json"
)
DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-storage-preflight-evidence.json"
)
DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-post-storage-preflight-reconciliation.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "storage-preflight"
_NEXT_PLAYBOOK = "storage-prepare"
_MAPPING_SEQUENCE = 8
_FINAL_EVIDENCE_MAPPING = len(OPERATION_PLAYBOOKS[_OPERATION])
_NOT_STARTED = "not-started"
_UNAVAILABLE = "unavailable"
_ORDER_BLOCKER = "ordered-deploy-step-not-reached"
_AUTHORIZATION_BLOCKER = "deploy-authorization-not-collected"
_PUBLIC_WORKFLOW_BLOCKER = "public-deploy-workflow-unavailable"
_CLASS_BLOCKERS = {
    OperationClassification.MUTATING: "mutating-deploy-execution-unavailable",
    OperationClassification.SENSITIVE: "sensitive-deploy-execution-unavailable",
    OperationClassification.DESTRUCTIVE: "destructive-deploy-execution-unavailable",
}
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BLOCKER = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,127}\Z")


class DeployStoragePreflightExecutionState(StrEnum):
    """Durable state of the sole storage-preflight invocation."""

    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"


class DeployStoragePreflightArtifactState(StrEnum):
    """Persistence outcome returned by the internal owners."""

    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployStoragePreflightExecutionBinding:
    """Address-free full-chain and exact-command binding."""

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
    discovery_execution_artifact_digest: str
    discovery_execution_binding_digest: str
    discovery_evidence_artifact_digest: str
    discovery_evidence_digest: str
    full_chain_digest: str
    observation_generation: int
    observation_artifact_digest: str
    observation_manifest_digest: str
    desired_storage_policy_digest: str
    storage_manifest_digest: str
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    trust_generation: int
    trust_artifact_digest: str
    trust_entries_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    catalog_digest: str
    source_version: str
    source_digest: str
    playbook_source_digest: str
    toolchain_version: str
    executable_identity_digest: str
    toolchain_evidence_digest: str
    step_sequence: int
    step_digest: str
    target_count: int
    target_set_digest: str
    runtime_variables_digest: str
    variables_digest: str
    command_digest: str
    binding_digest: str
    prior_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_BINDING_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_BINDING_SCHEMA_VERSION
            or self.prior_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
        ):
            raise StatePersistenceError(
                "deploy storage-preflight execution binding is invalid"
            )
        validate_cluster_name(self.cluster_name)
        for value in (
            self.journal_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
            self.step_sequence,
            self.target_count,
        ):
            _positive_integer(value, "storage-preflight binding count")
        for digest_value in _binding_digests(self):
            validate_digest(digest_value, "storage-preflight binding digest")
        if self.binding_digest != _binding_digest(self):
            raise StatePersistenceError(
                "deploy storage-preflight binding digest conflicts"
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
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployStoragePreflightExecutionBinding:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy storage-preflight execution binding",
        )
        integers = {
            "journal_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
            "step_sequence",
            "target_count",
        }
        parsed: dict[str, object] = {}
        for name in cls.__dataclass_fields__:
            if name in {"cluster_uuid", "operation_id"}:
                parsed[name] = parse_uuid(require_string(value, name), name)
            elif name in integers:
                parsed[name] = _integer(value[name], name)
            elif name == "journal_status":
                parsed[name] = _enum(
                    JournalStatus, require_string(value, name), "journal status"
                )
            elif name == "journal_phase":
                parsed[name] = _enum(
                    OperationPhase, require_string(value, name), "journal phase"
                )
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployStoragePreflightExecution:
    """Generation-guarded at-most-once read-only execution."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployStoragePreflightExecutionBinding
    state: DeployStoragePreflightExecutionState
    invocation_count: int
    invocation_may_have_occurred: bool
    completed: bool
    exit_code: int | None
    result_digest: str | None
    evidence_digest: str | None
    manual_recovery_required: bool
    automatic_retry_allowed: bool = False
    schema_version: str = ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION
            or self.generation not in {1, 2}
            or self.invocation_count != 1
            or not self.invocation_may_have_occurred
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy storage-preflight execution summary is invalid"
            )
        created = parse_timestamp(self.created_at)
        updated = parse_timestamp(self.updated_at)
        if updated < created:
            raise StatePersistenceError(
                "deploy storage-preflight execution timestamps conflict"
            )
        if self.state is DeployStoragePreflightExecutionState.STARTED:
            valid = (
                self.generation == 1
                and not self.completed
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.manual_recovery_required
            )
        elif self.state in {
            DeployStoragePreflightExecutionState.SUCCEEDED,
            DeployStoragePreflightExecutionState.FAILED,
            DeployStoragePreflightExecutionState.UNREACHABLE,
        }:
            valid = (
                self.generation == 2
                and self.completed
                and self.exit_code is not None
                and self.result_digest is not None
                and self.evidence_digest is not None
                and self.manual_recovery_required
                == (self.state is not DeployStoragePreflightExecutionState.SUCCEEDED)
            )
        else:
            valid = (
                self.generation == 2
                and not self.completed
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.manual_recovery_required
            )
        if not valid:
            raise StatePersistenceError(
                "deploy storage-preflight execution state conflicts"
            )
        for value in (self.result_digest, self.evidence_digest):
            if value is not None:
                validate_digest(value, "storage-preflight execution outcome digest")

    def to_object(self) -> dict[str, object]:
        return {
            "automatic_retry_allowed": self.automatic_retry_allowed,
            "binding": self.binding.to_object(),
            "completed": self.completed,
            "created_at": self.created_at,
            "evidence_digest": self.evidence_digest,
            "exit_code": self.exit_code,
            "generation": self.generation,
            "invocation_count": self.invocation_count,
            "invocation_may_have_occurred": self.invocation_may_have_occurred,
            "manual_recovery_required": self.manual_recovery_required,
            "result_digest": self.result_digest,
            "schema_version": self.schema_version,
            "state": self.state.value,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployStoragePreflightExecution:
        require_exact_keys(
            value, set(cls.__dataclass_fields__), "deploy storage-preflight execution"
        )
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                updated_at=require_string(value, "updated_at"),
                binding=DeployStoragePreflightExecutionBinding.from_object(
                    _mapping(value["binding"], "execution binding")
                ),
                state=DeployStoragePreflightExecutionState(
                    require_string(value, "state")
                ),
                invocation_count=_integer(
                    value["invocation_count"], "invocation count"
                ),
                invocation_may_have_occurred=_boolean(
                    value["invocation_may_have_occurred"],
                    "invocation may have occurred",
                ),
                completed=_boolean(value["completed"], "completed"),
                exit_code=_optional_integer(value["exit_code"], "exit code"),
                result_digest=_optional_string(value["result_digest"], "result digest"),
                evidence_digest=_optional_string(
                    value["evidence_digest"], "evidence digest"
                ),
                manual_recovery_required=_boolean(
                    value["manual_recovery_required"], "manual recovery required"
                ),
                automatic_retry_allowed=_boolean(
                    value["automatic_retry_allowed"], "automatic retry allowed"
                ),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy storage-preflight execution enum is invalid"
            ) from error


class DeployStoragePreflightAction(StrEnum):
    """Immediate deploy action proven by one exact preflight result."""

    BLOCKED = "blocked"
    OWNED_NOOP = "owned-noop"
    PREPARE_REQUIRED = "prepare-required"


@dataclass(frozen=True, slots=True)
class DeployStoragePreflightHostEvidence:
    """Address- and device-path-free exact-host semantic preflight evidence."""

    stable_id: str
    disposition: StorageOwnershipStatus
    action: DeployStoragePreflightAction
    backend: str
    layout: str
    capacity_bytes: int
    device_count: int
    device_set_digest: str
    desired_policy_digest: str
    manifest_digest: str
    discovery_digest: str
    preparation_intent_digest: str
    wipe_required: bool
    blocker_set: tuple[str, ...]
    blocker_digest: str
    status_digest: str

    def __post_init__(self) -> None:
        if (
            _LOGICAL_ID.fullmatch(self.stable_id) is None
            or not isinstance(self.disposition, StorageOwnershipStatus)
            or not isinstance(self.action, DeployStoragePreflightAction)
            or self.backend not in {"block-volume", "local-nvme"}
            or self.layout not in {"single", "raid0"}
            or isinstance(self.capacity_bytes, bool)
            or not isinstance(self.capacity_bytes, int)
            or self.capacity_bytes < 0
            or isinstance(self.device_count, bool)
            or not isinstance(self.device_count, int)
            or self.device_count < 0
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blocker_set)
            or self.wipe_required
            != (self.disposition is StorageOwnershipStatus.WIPE_REVIEW_REQUIRED)
            or (self.action is DeployStoragePreflightAction.BLOCKED)
            != (self.disposition is StorageOwnershipStatus.BLOCKED)
            or (self.action is DeployStoragePreflightAction.OWNED_NOOP)
            != (self.disposition is StorageOwnershipStatus.OWNED_NOOP)
            or (self.action is DeployStoragePreflightAction.PREPARE_REQUIRED)
            != (
                self.disposition
                in {
                    StorageOwnershipStatus.CLEAN_NEW,
                    StorageOwnershipStatus.WIPE_REVIEW_REQUIRED,
                }
            )
            or bool(self.blocker_set)
            != (self.disposition is StorageOwnershipStatus.BLOCKED)
        ):
            raise StatePersistenceError(
                "deploy storage-preflight host evidence conflicts"
            )
        for value in (
            self.device_set_digest,
            self.desired_policy_digest,
            self.manifest_digest,
            self.discovery_digest,
            self.preparation_intent_digest,
            self.blocker_digest,
            self.status_digest,
        ):
            validate_digest(value, "storage-preflight host digest")
        if self.blocker_digest != _digest_object(list(self.blocker_set)):
            raise StatePersistenceError(
                "deploy storage-preflight blocker digest conflicts"
            )
        if self.status_digest != _host_status_digest(self):
            raise StatePersistenceError(
                "deploy storage-preflight status digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "action": self.action.value,
            "backend": self.backend,
            "blocker_digest": self.blocker_digest,
            "blocker_set": list(self.blocker_set),
            "capacity_bytes": self.capacity_bytes,
            "desired_policy_digest": self.desired_policy_digest,
            "device_count": self.device_count,
            "device_set_digest": self.device_set_digest,
            "discovery_digest": self.discovery_digest,
            "disposition": self.disposition.value,
            "layout": self.layout,
            "manifest_digest": self.manifest_digest,
            "preparation_intent_digest": self.preparation_intent_digest,
            "stable_id": self.stable_id,
            "status_digest": self.status_digest,
            "wipe_required": self.wipe_required,
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployStoragePreflightHostEvidence:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy storage-preflight host evidence",
        )
        try:
            return cls(
                stable_id=require_string(value, "stable_id"),
                disposition=StorageOwnershipStatus(
                    require_string(value, "disposition")
                ),
                action=DeployStoragePreflightAction(require_string(value, "action")),
                backend=require_string(value, "backend"),
                layout=require_string(value, "layout"),
                capacity_bytes=_integer(value["capacity_bytes"], "capacity bytes"),
                device_count=_integer(value["device_count"], "device count"),
                device_set_digest=require_string(value, "device_set_digest"),
                desired_policy_digest=require_string(value, "desired_policy_digest"),
                manifest_digest=require_string(value, "manifest_digest"),
                discovery_digest=require_string(value, "discovery_digest"),
                preparation_intent_digest=require_string(
                    value, "preparation_intent_digest"
                ),
                wipe_required=_boolean(value["wipe_required"], "wipe required"),
                blocker_set=_string_tuple(value["blocker_set"], "blocker set"),
                blocker_digest=require_string(value, "blocker_digest"),
                status_digest=require_string(value, "status_digest"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy storage-preflight host enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployStoragePreflightEvidence:
    """Immutable bounded semantic evidence for the exact Scylla scope."""

    generation: int
    created_at: str
    binding: DeployStoragePreflightExecutionBinding
    hosts: tuple[DeployStoragePreflightHostEvidence, ...]
    blocked_host_count: int
    owned_noop_host_count: int
    prepare_required_host_count: int
    wipe_required_host_count: int
    device_count: int
    device_set_digest: str
    desired_policy_digest: str
    manifest_digest: str
    discovery_evidence_digest: str
    status_digest: str
    result_digest: str
    evidence_digest: str
    result_schema_version: str = STORAGE_PREFLIGHT_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
            or self.result_schema_version != STORAGE_PREFLIGHT_SCHEMA_VERSION
            or self.generation != 1
            or len(self.hosts) != self.binding.target_count
            or tuple(item.stable_id for item in self.hosts)
            != tuple(sorted({item.stable_id for item in self.hosts}))
            or self.blocked_host_count
            != sum(
                item.action is DeployStoragePreflightAction.BLOCKED
                for item in self.hosts
            )
            or self.owned_noop_host_count
            != sum(
                item.action is DeployStoragePreflightAction.OWNED_NOOP
                for item in self.hosts
            )
            or self.prepare_required_host_count
            != sum(
                item.action is DeployStoragePreflightAction.PREPARE_REQUIRED
                for item in self.hosts
            )
            or self.wipe_required_host_count
            != sum(item.wipe_required for item in self.hosts)
            or self.device_count != sum(item.device_count for item in self.hosts)
            or self.blocked_host_count
            + self.owned_noop_host_count
            + self.prepare_required_host_count
            != len(self.hosts)
            or any(
                item.desired_policy_digest != self.desired_policy_digest
                or item.manifest_digest != self.manifest_digest
                or item.discovery_digest != self.discovery_evidence_digest
                for item in self.hosts
            )
        ):
            raise StatePersistenceError(
                "deploy storage-preflight evidence summary conflicts"
            )
        parse_timestamp(self.created_at)
        for value in (
            self.device_set_digest,
            self.desired_policy_digest,
            self.manifest_digest,
            self.discovery_evidence_digest,
            self.status_digest,
            self.result_digest,
            self.evidence_digest,
        ):
            validate_digest(value, "storage-preflight evidence digest")
        expected_device_set = _digest_object(
            [
                {
                    "device_set_digest": host.device_set_digest,
                    "stable_id": host.stable_id,
                }
                for host in self.hosts
            ]
        )
        expected_status = _digest_object(
            [
                {"stable_id": host.stable_id, "status_digest": host.status_digest}
                for host in self.hosts
            ]
        )
        if (
            self.device_set_digest != expected_device_set
            or self.status_digest != expected_status
            or self.result_digest != _result_digest(self.hosts)
            or self.evidence_digest
            != _semantic_evidence_digest(
                self.binding,
                self.result_digest,
                self.device_set_digest,
                self.status_digest,
            )
        ):
            raise StatePersistenceError(
                "deploy storage-preflight evidence digest conflicts"
            )

    @property
    def successful(self) -> bool:
        return len(self.hosts) == self.binding.target_count

    def to_object(self) -> dict[str, object]:
        return {
            "binding": self.binding.to_object(),
            "blocked_host_count": self.blocked_host_count,
            "created_at": self.created_at,
            "desired_policy_digest": self.desired_policy_digest,
            "device_count": self.device_count,
            "device_set_digest": self.device_set_digest,
            "discovery_evidence_digest": self.discovery_evidence_digest,
            "evidence_digest": self.evidence_digest,
            "generation": self.generation,
            "hosts": [item.to_object() for item in self.hosts],
            "manifest_digest": self.manifest_digest,
            "owned_noop_host_count": self.owned_noop_host_count,
            "prepare_required_host_count": self.prepare_required_host_count,
            "result_digest": self.result_digest,
            "result_schema_version": self.result_schema_version,
            "schema_version": self.schema_version,
            "status_digest": self.status_digest,
            "wipe_required_host_count": self.wipe_required_host_count,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployStoragePreflightEvidence:
        require_exact_keys(
            value, set(cls.__dataclass_fields__), "deploy storage-preflight evidence"
        )
        return cls(
            generation=_integer(value["generation"], "generation"),
            created_at=require_string(value, "created_at"),
            binding=DeployStoragePreflightExecutionBinding.from_object(
                _mapping(value["binding"], "evidence binding")
            ),
            hosts=tuple(
                DeployStoragePreflightHostEvidence.from_object(
                    _mapping(item, "host evidence")
                )
                for item in _array(value["hosts"], "host evidence")
            ),
            blocked_host_count=_integer(
                value["blocked_host_count"], "blocked host count"
            ),
            owned_noop_host_count=_integer(
                value["owned_noop_host_count"], "owned noop host count"
            ),
            prepare_required_host_count=_integer(
                value["prepare_required_host_count"], "prepare required host count"
            ),
            wipe_required_host_count=_integer(
                value["wipe_required_host_count"], "wipe required host count"
            ),
            device_count=_integer(value["device_count"], "device count"),
            device_set_digest=require_string(value, "device_set_digest"),
            desired_policy_digest=require_string(value, "desired_policy_digest"),
            manifest_digest=require_string(value, "manifest_digest"),
            discovery_evidence_digest=require_string(
                value, "discovery_evidence_digest"
            ),
            status_digest=require_string(value, "status_digest"),
            result_digest=require_string(value, "result_digest"),
            evidence_digest=require_string(value, "evidence_digest"),
            result_schema_version=require_string(value, "result_schema_version"),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredDeployStoragePreflightExecution:
    record: DeployStoragePreflightExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployStoragePreflightEvidence:
    record: DeployStoragePreflightEvidence
    artifact_digest: str


class DeployStoragePreflightExecutionStore:
    """Generation-guarded owner-only execution store."""

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
        self._path = deploy_storage_preflight_execution_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployStoragePreflightExecution:
        value, digest = self._file.read()
        record = DeployStoragePreflightExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy storage-preflight execution identity conflicts"
            )
        return StoredDeployStoragePreflightExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployStoragePreflightExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployStoragePreflightExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployStoragePreflightExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy storage-preflight execution operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if (
                current.record.generation != expected_generation
                or current.artifact_digest != expected_digest
                or current.record.state
                is not DeployStoragePreflightExecutionState.STARTED
                or record.generation != 2
                or record.created_at != current.record.created_at
                or record.binding != current.record.binding
            ):
                raise StateConflictError(
                    "deploy storage-preflight execution transition conflicts"
                )
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
            or record.state is not DeployStoragePreflightExecutionState.STARTED
        ):
            raise StateConflictError(
                "deploy storage-preflight initial execution conflicts"
            )
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployStoragePreflightExecution(record, digest)


class DeployStoragePreflightEvidenceStore:
    """Immutable owner-only semantic evidence store."""

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
        self._path = deploy_storage_preflight_evidence_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployStoragePreflightEvidence:
        value, digest = self._file.read()
        record = DeployStoragePreflightEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy storage-preflight evidence identity conflicts"
            )
        return StoredDeployStoragePreflightEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployStoragePreflightEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployStoragePreflightEvidence,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployStoragePreflightEvidence, DeployStoragePreflightArtifactState
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy storage-preflight evidence operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy storage-preflight evidence is immutable"
                )
            return current, DeployStoragePreflightArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployStoragePreflightEvidence(record, digest),
            DeployStoragePreflightArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployStoragePreflightExecutionReport:
    """Strict redacted execution projection."""

    operation_id: uuid.UUID
    execution_artifact_state: DeployStoragePreflightArtifactState
    evidence_artifact_state: DeployStoragePreflightArtifactState
    execution_state: DeployStoragePreflightExecutionState
    execution_artifact_digest: str
    evidence_artifact_digest: str
    binding_digest: str
    invocation_count: int
    target_count: int
    target_set_digest: str
    validated_host_count: int
    blocked_host_count: int
    owned_noop_host_count: int
    prepare_required_host_count: int
    wipe_required_host_count: int
    device_count: int
    device_set_digest: str
    status_digest: str
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    journal_status: JournalStatus
    journal_phase: OperationPhase
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_REPORT_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
            or self.execution_state
            is not DeployStoragePreflightExecutionState.SUCCEEDED
            or self.invocation_count != 1
            or self.target_count < 1
            or self.validated_host_count != self.target_count
            or self.blocked_host_count
            + self.owned_noop_host_count
            + self.prepare_required_host_count
            != self.target_count
            or self.wipe_required_host_count > self.prepare_required_host_count
            or self.device_count < 0
            or self.manual_recovery_required
            or self.automatic_retry_allowed
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError(
                "deploy storage-preflight execution report is invalid"
            )
        for value in (
            self.execution_artifact_digest,
            self.evidence_artifact_digest,
            self.binding_digest,
            self.target_set_digest,
            self.device_set_digest,
            self.status_digest,
        ):
            validate_digest(value, "storage-preflight report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "artifacts": {
                "evidence_digest": self.evidence_artifact_digest,
                "evidence_state": self.evidence_artifact_state.value,
                "execution_digest": self.execution_artifact_digest,
                "execution_state": self.execution_artifact_state.value,
            },
            "execution": {
                "automatic_retry_allowed": self.automatic_retry_allowed,
                "binding_digest": self.binding_digest,
                "invocation_count": self.invocation_count,
                "manual_recovery_required": self.manual_recovery_required,
                "state": self.execution_state.value,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "operation_id": str(self.operation_id),
            "result": {
                "blocked_host_count": self.blocked_host_count,
                "device_count": self.device_count,
                "device_set_digest": self.device_set_digest,
                "owned_noop_host_count": self.owned_noop_host_count,
                "prepare_required_host_count": self.prepare_required_host_count,
                "status_digest": self.status_digest,
                "validated_host_count": self.validated_host_count,
                "wipe_required_host_count": self.wipe_required_host_count,
            },
            "schema_version": self.schema_version,
            "schemas": {
                "evidence": self.evidence_schema_version,
                "execution": self.execution_schema_version,
            },
            "scope": {
                "target_count": self.target_count,
                "target_set_digest": self.target_set_digest,
            },
        }


@dataclass(frozen=True, slots=True)
class _StoragePreflightScope:
    step: DeployBaseOsReconciledStep
    targets: tuple[str, ...]
    variables: Mapping[str, object]
    variables_digest: str
    command_digest: str
    source_digest: str


@dataclass(frozen=True, slots=True)
class _StoragePreflightContext:
    discovery: _StorageDiscoveryContext
    discovery_execution: StoredDeployStorageDiscoveryExecution
    discovery_evidence: StoredDeployStorageDiscoveryEvidence
    reconciliation: StoredDeployPostStorageDiscoveryReconciliation
    scope: _StoragePreflightScope
    binding: DeployStoragePreflightExecutionBinding
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport
    preflight: StoragePreflightResult


def execute_deploy_storage_preflight(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployStoragePreflightExecutionReport:
    """Execute exactly one canonical storage-preflight scope."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _validate_toolchain_dependency(toolchain)
    executable_identity_digest = _executable_identity_digest(executables)
    toolchain_evidence_digest = _toolchain_evidence_digest(
        toolchain, executable_identity_digest
    )
    _refuse_ambiguous_artifacts(paths, operation_id)
    context = _load_storage_preflight_context(
        paths,
        operation_id,
        lock=lock,
        toolchain_version=str(toolchain.core),
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    execution_store = DeployStoragePreflightExecutionStore(paths, operation_id)
    evidence_store = DeployStoragePreflightEvidenceStore(paths, operation_id)
    for path in (execution_store.path, evidence_store.path):
        validate_state_file(path, allow_missing=True)
    execution = (
        execution_store.read_locked(
            lock,
            expected_cluster_uuid=context.metadata.cluster_uuid,
            expected_cluster_name=context.metadata.cluster_name,
        )
        if execution_store.path.exists()
        else None
    )
    evidence = (
        evidence_store.read_locked(
            lock,
            expected_cluster_uuid=context.metadata.cluster_uuid,
            expected_cluster_name=context.metadata.cluster_name,
        )
        if evidence_store.path.exists()
        else None
    )
    _validate_execution_prefix(context, execution, evidence)
    if execution is not None:
        if (
            execution.record.state is DeployStoragePreflightExecutionState.SUCCEEDED
            and evidence is not None
            and evidence.record.successful
        ):
            return _build_execution_report(
                execution,
                evidence,
                execution_state=DeployStoragePreflightArtifactState.REUSED,
                evidence_state=DeployStoragePreflightArtifactState.REUSED,
            )
        raise StateConflictError(
            "deploy storage-preflight execution requires manual recovery and cannot retry"
        )

    builder = AnsibleCommandBuilder(executables.playbook, executables.inventory, paths)
    definition, validated, variables_digest, command_digest = (
        builder.validate_operation_step(
            _PLAYBOOK,
            step_sequence=context.scope.step.sequence,
            limit=context.scope.targets,
            variables=dict(context.scope.variables),
            tags=(),
            check=True,
            diff=False,
            verbosity=0,
        )
    )
    if (
        definition.name != _PLAYBOOK
        or definition.hosts != HostRole.SCYLLA.value
        or definition.serial != 5
        or definition.limit_policy is not LimitPolicy.EXPLICIT
        or variables_digest != context.scope.variables_digest
        or command_digest != context.scope.command_digest
    ):
        raise StateConflictError("deploy storage-preflight command identity conflicts")
    service = AnsibleService(builder, runner)
    discovered = service.version(lock)
    if discovered != toolchain:
        raise StateConflictError("deploy storage-preflight Ansible toolchain drifted")
    before = _load_storage_preflight_context(
        paths,
        operation_id,
        lock=lock,
        toolchain_version=str(toolchain.core),
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    if before.binding != context.binding:
        raise StateConflictError(
            "deploy storage-preflight state drifted before invocation"
        )
    now = _timestamp()
    started = DeployStoragePreflightExecution(
        generation=1,
        created_at=now,
        updated_at=now,
        binding=context.binding,
        state=DeployStoragePreflightExecutionState.STARTED,
        invocation_count=1,
        invocation_may_have_occurred=True,
        completed=False,
        exit_code=None,
        result_digest=None,
        evidence_digest=None,
        manual_recovery_required=True,
    )
    try:
        execution = execution_store.write_locked(
            started, expected_generation=0, expected_digest=None, lock=lock
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy storage-preflight started intent persistence failed before invocation"
        ) from error
    try:
        result, observed_command_digest = service.execute_operation_step(
            lock,
            context.metadata,
            context.inventory,
            _PLAYBOOK,
            step_sequence=context.scope.step.sequence,
            limit=context.scope.targets,
            variables=validated,
            readiness=context.readiness,
            tags=(),
            check=True,
            diff=False,
            verbosity=0,
        )
        if observed_command_digest != context.scope.command_digest:
            raise AnsibleResultError(
                "deploy storage-preflight command result identity conflicts"
            )
    except KeyboardInterrupt:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployStoragePreflightExecutionState.INTERRUPTED,
            lock=lock,
        )
        raise AnsibleError(
            "deploy storage-preflight execution was interrupted; "
            "manual recovery required"
        ) from None
    except AnsibleError as error:
        _persist_uncertain_or_raise(
            execution_store, execution, _failure_state(error), lock=lock
        )
        raise AnsibleError(
            "deploy storage-preflight execution is uncertain; manual recovery required"
        ) from error

    try:
        after = _load_storage_preflight_context(
            paths,
            operation_id,
            lock=lock,
            toolchain_version=str(toolchain.core),
            executable_identity_digest=executable_identity_digest,
            toolchain_evidence_digest=toolchain_evidence_digest,
        )
    except (StateConflictError, StatePersistenceError) as error:
        raise StateConflictError(
            "deploy storage-preflight state changed after invocation; "
            "manual recovery required"
        ) from error
    if after.binding != context.binding:
        raise StateConflictError(
            "deploy storage-preflight state changed after invocation; "
            "manual recovery required"
        )
    try:
        evidence_record = _build_semantic_evidence(context, result)
    except (AnsibleError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployStoragePreflightExecutionState.MALFORMED_RESULT,
            lock=lock,
        )
        raise AnsibleError(
            "deploy storage-preflight result is malformed; manual recovery required"
        ) from error
    try:
        evidence, evidence_state = evidence_store.write_locked(
            evidence_record, lock=lock
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy storage-preflight evidence persistence failed; "
            "manual recovery required"
        ) from error
    terminal_state = _terminal_state(evidence_record, result.exit_code)
    terminal = replace(
        execution.record,
        generation=2,
        updated_at=_timestamp(),
        state=terminal_state,
        completed=terminal_state
        in {
            DeployStoragePreflightExecutionState.SUCCEEDED,
            DeployStoragePreflightExecutionState.FAILED,
            DeployStoragePreflightExecutionState.UNREACHABLE,
        },
        exit_code=result.exit_code,
        result_digest=evidence_record.result_digest,
        evidence_digest=evidence_record.evidence_digest,
        manual_recovery_required=(
            terminal_state is not DeployStoragePreflightExecutionState.SUCCEEDED
        ),
    )
    try:
        execution = execution_store.write_locked(
            terminal,
            expected_generation=execution.record.generation,
            expected_digest=execution.artifact_digest,
            lock=lock,
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy storage-preflight terminal persistence failed; "
            "manual recovery required"
        ) from error
    if terminal_state is not DeployStoragePreflightExecutionState.SUCCEEDED:
        raise AnsibleError(
            "deploy storage-preflight execution failed; manual recovery required"
        )
    return _build_execution_report(
        execution,
        evidence,
        execution_state=DeployStoragePreflightArtifactState.UPDATED,
        evidence_state=evidence_state,
    )


def deploy_storage_preflight_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_STORAGE_PREFLIGHT_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy storage-preflight execution path is not canonical"
        )
    return path


def deploy_storage_preflight_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy storage-preflight evidence path is not canonical"
        )
    return path


def deploy_storage_preflight_execution_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(name, DEPLOY_STORAGE_PREFLIGHT_EXECUTION_FILENAME_SUFFIX)


def deploy_storage_preflight_evidence_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(name, DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_FILENAME_SUFFIX)


def _load_storage_preflight_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
    toolchain_version: str,
    executable_identity_digest: str,
    toolchain_evidence_digest: str,
) -> _StoragePreflightContext:
    discovery = _load_storage_discovery_context(
        paths,
        operation_id,
        lock=lock,
        toolchain_version=toolchain_version,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    planning = discovery.post.chain.authorization_context.final_routes.post.post.base.host.loaded.planning
    loaded = discovery.post.chain.authorization_context.final_routes.post.post.base.host.loaded
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    discovery_execution_store = DeployStorageDiscoveryExecutionStore(
        paths, operation_id
    )
    discovery_evidence_store = DeployStorageDiscoveryEvidenceStore(paths, operation_id)
    for store, label in (
        (discovery_execution_store, "storage-discovery execution"),
        (discovery_evidence_store, "storage-discovery evidence"),
    ):
        validate_state_file(store.path, allow_missing=True)
        if not store.path.exists():
            raise StateConflictError(
                f"deploy storage-preflight requires complete {label}"
            )
    discovery_execution = discovery_execution_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    discovery_evidence = discovery_evidence_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    _validate_storage_discovery_prefix(
        discovery, discovery_execution, discovery_evidence
    )
    if (
        discovery_execution.record.state
        is not DeployStorageDiscoveryExecutionState.SUCCEEDED
        or not discovery_evidence.record.successful
    ):
        raise StateConflictError(
            "deploy storage-preflight requires certain storage-discovery success"
        )
    reconciliation_store = DeployPostStorageDiscoveryReconciliationStore(
        paths, operation_id
    )
    validate_state_file(reconciliation_store.path, allow_missing=True)
    if not reconciliation_store.path.exists():
        raise StateConflictError(
            "deploy storage-preflight requires post-storage-discovery reconciliation"
        )
    reconciliation = reconciliation_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_steps = _build_post_storage_discovery_steps(discovery, discovery_evidence)
    expected = _build_post_storage_discovery_record(
        discovery,
        discovery_execution,
        discovery_evidence,
        steps=expected_steps,
        created_at=reconciliation.record.created_at,
    )
    if reconciliation.record != expected:
        raise StateConflictError(
            "deploy storage-preflight prior reconciliation drifted"
        )
    preflight = _preflight_from_discovery_evidence(discovery_evidence)
    desired_policy = next(
        (
            policy
            for policy in metadata.desired_spec.storage
            if policy.role is HostRole.SCYLLA
        ),
        None,
    )
    if desired_policy is None:
        raise StateConflictError(
            "deploy storage-preflight desired Scylla storage policy is unavailable"
        )
    desired_policy_digest = _digest_object(desired_policy.to_object())
    storage_manifest_digest = _digest_object(
        deploy.observation.record.manifest.to_persistence_object()
    )
    scope = _derive_scope(discovery, reconciliation, preflight)
    journal = deploy.journal
    readiness_record = planning.readiness.record
    values: dict[str, object] = {
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_name": metadata.cluster_name,
        "operation_id": operation_id,
        "operation": _OPERATION,
        "request_digest": journal.record.request_digest,
        "journal_generation": journal.record.generation,
        "journal_digest": journal.digest,
        "journal_status": journal.record.status,
        "journal_phase": journal.record.phase,
        "prior_reconciliation_artifact_digest": reconciliation.artifact_digest,
        "prior_reconciliation_record_digest": reconciliation.record.record_digest,
        "prior_effective_plan_digest": reconciliation.record.effective_plan_digest,
        "discovery_execution_artifact_digest": (discovery_execution.artifact_digest),
        "discovery_execution_binding_digest": (
            discovery_execution.record.binding.binding_digest
        ),
        "discovery_evidence_artifact_digest": discovery_evidence.artifact_digest,
        "discovery_evidence_digest": discovery_evidence.record.evidence_digest,
        "full_chain_digest": _digest_object(
            {
                "catalog_digest": loaded.catalog_digest,
                "discovery_evidence_artifact_digest": (
                    discovery_evidence.artifact_digest
                ),
                "discovery_execution_artifact_digest": (
                    discovery_execution.artifact_digest
                ),
                "prior_artifact_digest": reconciliation.artifact_digest,
                "prior_record_digest": reconciliation.record.record_digest,
                "source_digest": loaded.source.digest,
            }
        ),
        "observation_generation": deploy.observation.record.generation,
        "observation_artifact_digest": deploy.observation.digest,
        "observation_manifest_digest": deploy.observation.record.manifest_digest,
        "desired_storage_policy_digest": desired_policy_digest,
        "storage_manifest_digest": storage_manifest_digest,
        "inventory_generation": deploy.inventory.record.generation,
        "inventory_artifact_digest": deploy.inventory.digest,
        "inventory_digest": deploy.inventory.record.inventory_digest,
        "trust_generation": planning.base.trust.record.generation,
        "trust_artifact_digest": planning.base.trust.digest,
        "trust_entries_digest": planning.base.trust.record.entries_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": readiness_record.record_digest,
        "catalog_digest": loaded.catalog_digest,
        "source_version": loaded.source.version,
        "source_digest": loaded.source.digest,
        "playbook_source_digest": scope.source_digest,
        "toolchain_version": toolchain_version,
        "executable_identity_digest": executable_identity_digest,
        "toolchain_evidence_digest": toolchain_evidence_digest,
        "step_sequence": scope.step.sequence,
        "step_digest": _digest_object(scope.step.to_object()),
        "target_count": len(scope.targets),
        "target_set_digest": _digest_object(list(scope.targets)),
        "runtime_variables_digest": _digest_object(scope.variables),
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "binding_digest": "",
    }
    values["binding_digest"] = _binding_digest_from_values(values)
    binding = DeployStoragePreflightExecutionBinding(**values)  # type: ignore[arg-type]
    return _StoragePreflightContext(
        discovery,
        discovery_execution,
        discovery_evidence,
        reconciliation,
        scope,
        binding,
        metadata,
        deploy.inventory,
        discovery.readiness,
        preflight,
    )


def _preflight_from_discovery_evidence(
    evidence: StoredDeployStorageDiscoveryEvidence,
) -> StoragePreflightResult:
    hosts: list[StorageHostPreflight] = []
    for item in evidence.record.hosts:
        devices = tuple(
            SelectedStorageDevice(
                device.identity,
                device.capacity_bytes,
                device.identity,
            )
            for device in item.preflight_devices
        )
        host = StorageHostPreflight(
            logical_id=item.stable_id,
            backend=item.preflight_backend,
            layout=item.preflight_layout,
            capacity_bytes=item.preflight_capacity_bytes,
            ownership_status=item.preflight_ownership_status,
            blockers=item.preflight_blockers,
            wipe_required=item.preflight_wipe_required,
            preparation_intent_digest=item.preparation_intent_digest,
            devices=devices,
        )
        if _digest_object(host.to_object()) != item.preflight_result_digest:
            raise StateConflictError(
                "deploy storage-preflight discovery projection drifted"
            )
        hosts.append(host)
    result = StoragePreflightResult(tuple(hosts))
    if tuple(host.logical_id for host in result.hosts) != tuple(
        sorted({host.logical_id for host in result.hosts})
    ):
        raise StateConflictError(
            "deploy storage-preflight discovery membership conflicts"
        )
    return result


def _derive_scope(
    discovery: _StorageDiscoveryContext,
    reconciliation: StoredDeployPostStorageDiscoveryReconciliation,
    preflight: StoragePreflightResult,
) -> _StoragePreflightScope:
    loaded = discovery.post.chain.authorization_context.final_routes.post.post.base.host.loaded
    inventory_hosts = loaded.planning.base.deploy.inventory.record.inventory.hosts
    scylla_ids = tuple(
        sorted(
            host.logical_id for host in inventory_hosts if host.role is HostRole.SCYLLA
        )
    )
    selected = tuple(
        step
        for step in reconciliation.record.steps
        if step.mapping_sequence == _MAPPING_SEQUENCE
    )
    definition = get_playbook(_PLAYBOOK)
    variables: dict[str, object] = {
        "deploy_scylla_vms_storage_preflight": {
            host.logical_id: host.to_object() for host in preflight.hosts
        }
    }
    if (
        len(selected) != 1
        or not scylla_ids
        or tuple(host.logical_id for host in preflight.hosts) != scylla_ids
        or selected[0].playbook != _PLAYBOOK
        or selected[0].condition_state is not DeployConditionState.ACTIVE
        or selected[0].classification is not OperationClassification.READ_ONLY
        or selected[0].status is not DeployBaseOsReconciledStepStatus.ELIGIBLE
        or selected[0].evidence_state
        is not DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED
        or selected[0].target_role != HostRole.SCYLLA.value
        or selected[0].target_ids != scylla_ids
        or selected[0].target_digest != _digest_object(list(scylla_ids))
        or selected[0].source_digest
        != _playbook_source_digest(loaded.source, _PLAYBOOK)
        or definition.classification is not OperationClassification.READ_ONLY
        or definition.hosts != HostRole.SCYLLA.value
        or definition.serial != 5
        or definition.limit_policy is not LimitPolicy.EXPLICIT
        or definition.check_mode is not CheckMode.SUPPORTED
        or not definition.source_available
    ):
        raise StateConflictError(
            "deploy storage-preflight eligible scope identity conflicts"
        )
    validate_playbook_request_policy(
        _PLAYBOOK,
        limit=scylla_ids,
        tags=(),
        check=True,
        diff=False,
        verbosity=0,
    )
    validated = definition.validate_variables(variables)
    variables_digest = digest_bytes(serialize_json(validated))
    command_digest = ansible_command_intent_digest(
        definition,
        step_sequence=selected[0].sequence,
        limit=scylla_ids,
        variables_digest=variables_digest,
        tags=(),
        check=True,
        diff=False,
        verbosity=0,
    )
    return _StoragePreflightScope(
        selected[0],
        scylla_ids,
        validated,
        variables_digest,
        command_digest,
        _playbook_source_digest(loaded.source, _PLAYBOOK),
    )


def _validate_execution_prefix(
    context: _StoragePreflightContext,
    execution: StoredDeployStoragePreflightExecution | None,
    evidence: StoredDeployStoragePreflightEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "deploy storage-preflight evidence exists without intent"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError(
            "deploy storage-preflight execution provenance is stale"
        )
    if evidence is not None:
        if (
            evidence.record.binding != context.binding
            or execution.record.result_digest != evidence.record.result_digest
            or execution.record.evidence_digest != evidence.record.evidence_digest
        ):
            raise StateConflictError(
                "deploy storage-preflight semantic evidence conflicts"
            )
    elif execution.record.state in {
        DeployStoragePreflightExecutionState.SUCCEEDED,
        DeployStoragePreflightExecutionState.FAILED,
        DeployStoragePreflightExecutionState.UNREACHABLE,
    }:
        raise StateConflictError(
            "deploy storage-preflight terminal evidence is missing"
        )


def _build_semantic_evidence(
    context: _StoragePreflightContext,
    result: AnsibleExecutionResult,
) -> DeployStoragePreflightEvidence:
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.READ_ONLY
        or not result.check_mode
        or result.storage_preflight is not None
    ):
        raise AnsibleResultError("deploy storage-preflight result identity conflicts")
    parsed = parse_storage_preflight_execution(
        result.stdout,
        context.preflight,
        result.exit_code,
    )
    if parsed != context.preflight:
        raise AnsibleResultError("deploy storage-preflight result conflicts")
    hosts: list[DeployStoragePreflightHostEvidence] = []
    for item in parsed.hosts:
        device_set_digest = _digest_object([device.identity for device in item.devices])
        action = (
            DeployStoragePreflightAction.BLOCKED
            if item.ownership_status is StorageOwnershipStatus.BLOCKED
            else DeployStoragePreflightAction.OWNED_NOOP
            if item.ownership_status is StorageOwnershipStatus.OWNED_NOOP
            else DeployStoragePreflightAction.PREPARE_REQUIRED
        )
        values: dict[str, object] = {
            "stable_id": item.logical_id,
            "disposition": item.ownership_status,
            "action": action,
            "backend": item.backend,
            "layout": item.layout,
            "capacity_bytes": item.capacity_bytes,
            "device_count": len(item.devices),
            "device_set_digest": device_set_digest,
            "desired_policy_digest": (context.binding.desired_storage_policy_digest),
            "manifest_digest": context.binding.storage_manifest_digest,
            "discovery_digest": context.binding.discovery_evidence_digest,
            "preparation_intent_digest": item.preparation_intent_digest,
            "wipe_required": item.wipe_required,
            "blocker_set": item.blockers,
            "blocker_digest": _digest_object(list(item.blockers)),
            "status_digest": "",
        }
        values["status_digest"] = _host_status_digest_from_values(values)
        hosts.append(DeployStoragePreflightHostEvidence(**values))  # type: ignore[arg-type]
    projected = tuple(hosts)
    result_digest = _result_digest(projected)
    device_set_digest = _digest_object(
        [
            {
                "device_set_digest": host.device_set_digest,
                "stable_id": host.stable_id,
            }
            for host in projected
        ]
    )
    status_digest = _digest_object(
        [
            {"stable_id": host.stable_id, "status_digest": host.status_digest}
            for host in projected
        ]
    )
    return DeployStoragePreflightEvidence(
        generation=1,
        created_at=_timestamp(),
        binding=context.binding,
        hosts=projected,
        blocked_host_count=sum(
            host.action is DeployStoragePreflightAction.BLOCKED for host in projected
        ),
        owned_noop_host_count=sum(
            host.action is DeployStoragePreflightAction.OWNED_NOOP for host in projected
        ),
        prepare_required_host_count=sum(
            host.action is DeployStoragePreflightAction.PREPARE_REQUIRED
            for host in projected
        ),
        wipe_required_host_count=sum(host.wipe_required for host in projected),
        device_count=sum(host.device_count for host in projected),
        device_set_digest=device_set_digest,
        desired_policy_digest=context.binding.desired_storage_policy_digest,
        manifest_digest=context.binding.storage_manifest_digest,
        discovery_evidence_digest=context.binding.discovery_evidence_digest,
        status_digest=status_digest,
        result_digest=result_digest,
        evidence_digest=_semantic_evidence_digest(
            context.binding,
            result_digest,
            device_set_digest,
            status_digest,
        ),
    )


def _terminal_state(
    evidence: DeployStoragePreflightEvidence, exit_code: int
) -> DeployStoragePreflightExecutionState:
    if exit_code == 0 and evidence.successful:
        return DeployStoragePreflightExecutionState.SUCCEEDED
    return DeployStoragePreflightExecutionState.FAILED


def _persist_uncertain_or_raise(
    store: DeployStoragePreflightExecutionStore,
    current: StoredDeployStoragePreflightExecution,
    state: DeployStoragePreflightExecutionState,
    *,
    lock: ClusterLock,
) -> None:
    try:
        record = replace(
            current.record,
            generation=2,
            updated_at=_timestamp(),
            state=state,
            manual_recovery_required=True,
        )
        store.write_locked(
            record,
            expected_generation=current.record.generation,
            expected_digest=current.artifact_digest,
            lock=lock,
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy storage-preflight uncertain outcome persistence failed; "
            "manual recovery required"
        ) from error


def _build_execution_report(
    execution: StoredDeployStoragePreflightExecution,
    evidence: StoredDeployStoragePreflightEvidence,
    *,
    execution_state: DeployStoragePreflightArtifactState,
    evidence_state: DeployStoragePreflightArtifactState,
) -> DeployStoragePreflightExecutionReport:
    if (
        execution.record.state is not DeployStoragePreflightExecutionState.SUCCEEDED
        or not evidence.record.successful
        or execution.record.result_digest != evidence.record.result_digest
        or execution.record.evidence_digest != evidence.record.evidence_digest
    ):
        raise StateConflictError(
            "deploy storage-preflight success evidence is incomplete"
        )
    return DeployStoragePreflightExecutionReport(
        operation_id=execution.record.binding.operation_id,
        execution_artifact_state=execution_state,
        evidence_artifact_state=evidence_state,
        execution_state=execution.record.state,
        execution_artifact_digest=execution.artifact_digest,
        evidence_artifact_digest=evidence.artifact_digest,
        binding_digest=execution.record.binding.binding_digest,
        invocation_count=execution.record.invocation_count,
        target_count=execution.record.binding.target_count,
        target_set_digest=execution.record.binding.target_set_digest,
        validated_host_count=len(evidence.record.hosts),
        blocked_host_count=evidence.record.blocked_host_count,
        owned_noop_host_count=evidence.record.owned_noop_host_count,
        prepare_required_host_count=evidence.record.prepare_required_host_count,
        wipe_required_host_count=evidence.record.wipe_required_host_count,
        device_count=evidence.record.device_count,
        device_set_digest=evidence.record.device_set_digest,
        status_digest=evidence.record.status_digest,
        manual_recovery_required=execution.record.manual_recovery_required,
        automatic_retry_allowed=execution.record.automatic_retry_allowed,
        journal_status=execution.record.binding.journal_status,
        journal_phase=execution.record.binding.journal_phase,
    )


@dataclass(frozen=True, slots=True)
class DeployStoragePreparationScope:
    """Exact non-authorizing host/device scope that requires preparation."""

    stable_id: str
    disposition: StorageOwnershipStatus
    device_count: int
    device_set_digest: str
    preparation_intent_digest: str
    wipe_required: bool
    scope_digest: str

    def __post_init__(self) -> None:
        if (
            _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.disposition
            not in {
                StorageOwnershipStatus.CLEAN_NEW,
                StorageOwnershipStatus.WIPE_REVIEW_REQUIRED,
            }
            or self.device_count < 1
            or self.wipe_required
            != (self.disposition is StorageOwnershipStatus.WIPE_REVIEW_REQUIRED)
        ):
            raise StatePersistenceError("deploy storage preparation scope is invalid")
        for value in (
            self.device_set_digest,
            self.preparation_intent_digest,
            self.scope_digest,
        ):
            validate_digest(value, "storage preparation scope digest")
        if self.scope_digest != _preparation_scope_digest(self):
            raise StatePersistenceError(
                "deploy storage preparation scope digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "device_count": self.device_count,
            "device_set_digest": self.device_set_digest,
            "disposition": self.disposition.value,
            "preparation_intent_digest": self.preparation_intent_digest,
            "scope_digest": self.scope_digest,
            "stable_id": self.stable_id,
            "wipe_required": self.wipe_required,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployStoragePreparationScope:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy storage preparation scope",
        )
        try:
            return cls(
                stable_id=require_string(value, "stable_id"),
                disposition=StorageOwnershipStatus(
                    require_string(value, "disposition")
                ),
                device_count=_integer(value["device_count"], "device count"),
                device_set_digest=require_string(value, "device_set_digest"),
                preparation_intent_digest=require_string(
                    value, "preparation_intent_digest"
                ),
                wipe_required=_boolean(value["wipe_required"], "wipe required"),
                scope_digest=require_string(value, "scope_digest"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy storage preparation disposition is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployPostStoragePreflightReconciliation:
    """Immutable effective plan after exact storage preflight."""

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
    execution_artifact_digest: str
    execution_binding_digest: str
    evidence_artifact_digest: str
    evidence_digest: str
    target_count: int
    target_set_digest: str
    device_count: int
    device_set_digest: str
    status_digest: str
    blocked_host_count: int
    owned_noop_host_count: int
    prepare_required_host_count: int
    wipe_required_host_count: int
    preparation_scopes: tuple[DeployStoragePreparationScope, ...]
    preparation_target_set_digest: str
    preparation_scope_digest: str
    wipe_target_set_digest: str
    wipe_scope_digest: str
    steps: tuple[DeployBaseOsReconciledStep, ...]
    step_count: int
    succeeded_count: int
    authorization_required_count: int
    eligible_count: int
    blocked_count: int
    not_performed_count: int
    blocker_set: tuple[str, ...]
    blocker_digest: str
    effective_plan_digest: str
    finalization_state: str
    public_workflow_state: str
    record_digest: str
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    prior_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION
    )
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.prior_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
        ):
            raise StatePersistenceError(
                "post-storage-preflight reconciliation identity is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        counts = Counter(step.status for step in self.steps)
        blockers = tuple(
            sorted({blocker for step in self.steps for blocker in step.blockers})
        )
        if (
            self.journal_generation < 1
            or self.target_count < 1
            or self.device_count < 0
            or len(self.preparation_scopes) != self.prepare_required_host_count
            or sum(item.wipe_required for item in self.preparation_scopes)
            != self.wipe_required_host_count
            or self.blocked_host_count
            + self.owned_noop_host_count
            + self.prepare_required_host_count
            != self.target_count
            or self.wipe_required_host_count > self.prepare_required_host_count
            or len(self.preparation_scopes) != self.prepare_required_host_count
            or tuple(item.stable_id for item in self.preparation_scopes)
            != tuple(sorted({item.stable_id for item in self.preparation_scopes}))
            or self.wipe_required_host_count
            != sum(item.wipe_required for item in self.preparation_scopes)
            or self.preparation_target_set_digest
            != _digest_object([item.stable_id for item in self.preparation_scopes])
            or self.preparation_scope_digest
            != _digest_object([item.to_object() for item in self.preparation_scopes])
            or self.wipe_target_set_digest
            != _digest_object(
                [
                    item.stable_id
                    for item in self.preparation_scopes
                    if item.wipe_required
                ]
            )
            or self.wipe_scope_digest
            != _digest_object(
                [
                    item.to_object()
                    for item in self.preparation_scopes
                    if item.wipe_required
                ]
            )
            or self.step_count != len(self.steps)
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
            or blockers != self.blocker_set
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blocker_set)
            or self.blocker_digest != _digest_object(list(self.blocker_set))
            or self.effective_plan_digest
            != _digest_object([step.to_object() for step in self.steps])
        ):
            raise StatePersistenceError(
                "post-storage-preflight reconciliation summary conflicts"
            )
        for value in _reconciliation_digests(self):
            validate_digest(value, "post-storage-preflight reconciliation digest")
        if self.record_digest != _reconciliation_record_digest(self):
            raise StatePersistenceError(
                "post-storage-preflight reconciliation record digest conflicts"
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
                if name == "preparation_scopes"
                else list(value)
                if name == "blocker_set"
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployPostStoragePreflightReconciliation:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "post-storage-preflight reconciliation",
        )
        integers = {
            "generation",
            "journal_generation",
            "target_count",
            "device_count",
            "blocked_host_count",
            "owned_noop_host_count",
            "prepare_required_host_count",
            "wipe_required_host_count",
            "step_count",
            "succeeded_count",
            "authorization_required_count",
            "eligible_count",
            "blocked_count",
            "not_performed_count",
        }
        parsed: dict[str, object] = {}
        for name in cls.__dataclass_fields__:
            if name in integers:
                parsed[name] = _integer(value[name], name)
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
            elif name == "steps":
                parsed[name] = tuple(
                    DeployBaseOsReconciledStep.from_object(
                        _mapping(item, "reconciled step")
                    )
                    for item in _array(value[name], "reconciled steps")
                )
            elif name == "preparation_scopes":
                parsed[name] = tuple(
                    DeployStoragePreparationScope.from_object(
                        _mapping(item, "preparation scope")
                    )
                    for item in _array(value[name], "preparation scopes")
                )
            elif name == "blocker_set":
                parsed[name] = _string_tuple(value[name], name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployPostStoragePreflightReconciliation:
    record: DeployPostStoragePreflightReconciliation
    artifact_digest: str


class DeployPostStoragePreflightReconciliationStore:
    """Immutable owner-only post-storage-preflight store."""

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
        self._path = deploy_post_storage_preflight_reconciliation_path(
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
    ) -> StoredDeployPostStoragePreflightReconciliation:
        value, digest = self._file.read()
        record = DeployPostStoragePreflightReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "post-storage-preflight reconciliation identity conflicts"
            )
        return StoredDeployPostStoragePreflightReconciliation(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPostStoragePreflightReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployPostStoragePreflightReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployPostStoragePreflightReconciliation,
        DeployStoragePreflightArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "post-storage-preflight reconciliation operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "post-storage-preflight reconciliation is immutable"
                )
            return current, DeployStoragePreflightArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployPostStoragePreflightReconciliation(record, digest),
            DeployStoragePreflightArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployPostStoragePreflightReconciliationReport:
    """Strict redacted immediate-next-gate projection."""

    operation_id: uuid.UUID
    artifact_state: DeployStoragePreflightArtifactState
    reconciliation_artifact_digest: str
    reconciliation_record_digest: str
    effective_plan_digest: str
    target_count: int
    target_set_digest: str
    device_count: int
    device_set_digest: str
    status_digest: str
    blocked_host_count: int
    owned_noop_host_count: int
    prepare_required_host_count: int
    wipe_required_host_count: int
    preparation_scopes: tuple[DeployStoragePreparationScope, ...]
    preparation_target_set_digest: str
    preparation_scope_digest: str
    wipe_target_set_digest: str
    wipe_scope_digest: str
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
    finalization_state: str
    public_workflow_state: str
    reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_REPORT_SCHEMA_VERSION
            or self.reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
            or self.target_count < 1
            or self.device_count < 0
            or len(self.preparation_scopes) != self.prepare_required_host_count
            or sum(item.wipe_required for item in self.preparation_scopes)
            != self.wipe_required_host_count
            or self.next_step_count
            != sum(item.instance_count for item in self.next_steps)
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or self.blocker_digest != _digest_object(list(self.blocker_set))
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
        ):
            raise StatePersistenceError(
                "post-storage-preflight reconciliation report is invalid"
            )
        for value in (
            self.reconciliation_artifact_digest,
            self.reconciliation_record_digest,
            self.effective_plan_digest,
            self.target_set_digest,
            self.device_set_digest,
            self.status_digest,
            self.preparation_target_set_digest,
            self.preparation_scope_digest,
            self.wipe_target_set_digest,
            self.wipe_scope_digest,
            self.next_target_set_digest,
            self.blocker_digest,
        ):
            validate_digest(value, "post-storage-preflight report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "artifact_state": self.artifact_state.value,
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
            "schema_version": self.schema_version,
            "schemas": {"reconciliation": self.reconciliation_schema_version},
            "states": {
                "finalization": self.finalization_state,
                "public_workflow": self.public_workflow_state,
            },
            "steps": {
                "authorization_required_count": self.authorization_required_count,
                "blocked_count": self.blocked_count,
                "eligible_count": self.eligible_count,
                "not_performed_count": self.not_performed_count,
                "succeeded_count": self.succeeded_count,
            },
            "storage_preflight": {
                "blocked_host_count": self.blocked_host_count,
                "device_count": self.device_count,
                "device_set_digest": self.device_set_digest,
                "owned_noop_host_count": self.owned_noop_host_count,
                "prepare_required_host_count": self.prepare_required_host_count,
                "status": "succeeded",
                "status_digest": self.status_digest,
                "target_count": self.target_count,
                "target_set_digest": self.target_set_digest,
                "wipe_required_host_count": self.wipe_required_host_count,
            },
            "storage_prepare_scope": {
                "scope_digest": self.preparation_scope_digest,
                "scopes": [item.to_object() for item in self.preparation_scopes],
                "target_count": len(self.preparation_scopes),
                "target_set_digest": self.preparation_target_set_digest,
                "wipe_scope_digest": self.wipe_scope_digest,
                "wipe_target_count": self.wipe_required_host_count,
                "wipe_target_set_digest": self.wipe_target_set_digest,
            },
        }


def reconcile_deploy_storage_preflight(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployPostStoragePreflightReconciliationReport:
    """Persist preflight success and derive only immediate preparation scope."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _refuse_ambiguous_artifacts(paths, operation_id)
    execution_store = DeployStoragePreflightExecutionStore(paths, operation_id)
    evidence_store = DeployStoragePreflightEvidenceStore(paths, operation_id)
    for path, label in (
        (execution_store.path, "execution"),
        (evidence_store.path, "evidence"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"post-storage-preflight reconciliation requires complete {label}"
            )
    raw_execution = execution_store.read(
        expected_cluster_uuid=_read_binding_identity(execution_store.path)[0],
        expected_cluster_name=_read_binding_identity(execution_store.path)[1],
    )
    context = _load_storage_preflight_context(
        paths,
        operation_id,
        lock=lock,
        toolchain_version=raw_execution.record.binding.toolchain_version,
        executable_identity_digest=(
            raw_execution.record.binding.executable_identity_digest
        ),
        toolchain_evidence_digest=(
            raw_execution.record.binding.toolchain_evidence_digest
        ),
    )
    execution = execution_store.read_locked(
        lock,
        expected_cluster_uuid=context.metadata.cluster_uuid,
        expected_cluster_name=context.metadata.cluster_name,
    )
    evidence = evidence_store.read_locked(
        lock,
        expected_cluster_uuid=context.metadata.cluster_uuid,
        expected_cluster_name=context.metadata.cluster_name,
    )
    _validate_execution_prefix(context, execution, evidence)
    if (
        execution.record.state is not DeployStoragePreflightExecutionState.SUCCEEDED
        or not evidence.record.successful
    ):
        raise StateConflictError(
            "post-storage-preflight reconciliation requires certain successful execution"
        )
    steps = _build_reconciled_steps(context, evidence)
    store = DeployPostStoragePreflightReconciliationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    existing = (
        store.read_locked(
            lock,
            expected_cluster_uuid=context.metadata.cluster_uuid,
            expected_cluster_name=context.metadata.cluster_name,
        )
        if store.path.exists()
        else None
    )
    created_at = existing.record.created_at if existing is not None else _timestamp()
    record = _build_reconciliation_record(
        context,
        execution,
        evidence,
        steps=steps,
        created_at=created_at,
    )
    if existing is not None and existing.record != record:
        raise StateConflictError(
            "post-storage-preflight reconciliation is immutable; use a new operation"
        )
    try:
        stored, state = store.write_locked(record, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "post-storage-preflight reconciliation persistence failed"
        ) from error
    return _build_reconciliation_report(stored, state=state)


def deploy_post_storage_preflight_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "post-storage-preflight reconciliation path is not canonical"
        )
    return path


def deploy_post_storage_preflight_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(
        name, DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_FILENAME_SUFFIX
    )


def _read_binding_identity(path: Path) -> tuple[uuid.UUID, str]:
    value, _digest = AtomicJsonFile(path).read()
    binding = _mapping(value.get("binding"), "execution binding")
    return (
        parse_uuid(require_string(binding, "cluster_uuid"), "cluster uuid"),
        require_string(binding, "cluster_name"),
    )


def _build_reconciled_steps(
    context: _StoragePreflightContext,
    evidence: StoredDeployStoragePreflightEvidence,
) -> tuple[DeployBaseOsReconciledStep, ...]:
    prior_steps = context.reconciliation.record.steps
    hosts = {host.stable_id: host for host in evidence.record.hosts}
    result: list[DeployBaseOsReconciledStep] = []
    for prior in prior_steps:
        prior_digest = _digest_object(prior.to_object())
        if prior.mapping_sequence == _MAPPING_SEQUENCE:
            if (
                prior.playbook != _PLAYBOOK
                or prior.status is not DeployBaseOsReconciledStepStatus.ELIGIBLE
                or prior.sequence != context.scope.step.sequence
                or prior.target_ids != context.scope.targets
            ):
                raise StateConflictError(
                    "post-storage-preflight executed step identity drifted"
                )
            result.append(
                replace(
                    prior,
                    prior_reconciled_step_digest=prior_digest,
                    status=DeployBaseOsReconciledStepStatus.SUCCEEDED,
                    evidence_state=(
                        DeployBaseOsReconciledEvidenceState.STORAGE_PREFLIGHT_BOUND
                    ),
                    evidence_digest=evidence.record.evidence_digest,
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
        if prior.mapping_sequence == _MAPPING_SEQUENCE + 1:
            if (
                prior.playbook != _NEXT_PLAYBOOK
                or prior.classification is not OperationClassification.DESTRUCTIVE
                or prior.target_role != HostRole.SCYLLA.value
                or len(prior.target_ids) != 1
            ):
                raise StateConflictError(
                    "post-storage-preflight preparation step identity drifted"
                )
            host = hosts.get(prior.target_ids[0])
            if host is None:
                raise StateConflictError(
                    "post-storage-preflight preparation target is unavailable"
                )
            if host.action is DeployStoragePreflightAction.PREPARE_REQUIRED:
                blockers = {
                    _AUTHORIZATION_BLOCKER,
                    _CLASS_BLOCKERS[prior.classification],
                    _PUBLIC_WORKFLOW_BLOCKER,
                }
                if host.wipe_required:
                    blockers.add("storage-wipe-consent-not-collected")
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
                        evidence_digest=_storage_prepare_gate_digest(
                            prior, context, evidence, host
                        ),
                        blockers=tuple(sorted(blockers)),
                    )
                )
                continue
            if host.action is DeployStoragePreflightAction.OWNED_NOOP:
                result.append(
                    replace(
                        prior,
                        prior_reconciled_step_digest=prior_digest,
                        status=DeployBaseOsReconciledStepStatus.NOT_PERFORMED,
                        evidence_state=DeployBaseOsReconciledEvidenceState.NOT_REQUIRED,
                        evidence_digest=None,
                        blockers=(),
                    )
                )
                continue
            result.append(
                replace(
                    prior,
                    prior_reconciled_step_digest=prior_digest,
                    status=DeployBaseOsReconciledStepStatus.BLOCKED,
                    evidence_state=DeployBaseOsReconciledEvidenceState.NOT_PERFORMED,
                    evidence_digest=None,
                    blockers=("storage-preflight-blocked",),
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


def _storage_prepare_gate_digest(
    step: DeployBaseOsReconciledStep,
    context: _StoragePreflightContext,
    evidence: StoredDeployStoragePreflightEvidence,
    host: DeployStoragePreflightHostEvidence,
) -> str:
    return _digest_object(
        {
            "device_set_digest": host.device_set_digest,
            "disposition": host.disposition.value,
            "evidence_artifact_digest": evidence.artifact_digest,
            "evidence_digest": evidence.record.evidence_digest,
            "preparation_intent_digest": host.preparation_intent_digest,
            "prior_reconciliation_artifact_digest": (
                context.reconciliation.artifact_digest
            ),
            "sequence": step.sequence,
            "stable_id": host.stable_id,
            "target_digest": step.target_digest,
            "wipe_required": host.wipe_required,
        }
    )


def _preparation_scopes(
    evidence: StoredDeployStoragePreflightEvidence,
) -> tuple[DeployStoragePreparationScope, ...]:
    scopes: list[DeployStoragePreparationScope] = []
    for host in evidence.record.hosts:
        if host.action is not DeployStoragePreflightAction.PREPARE_REQUIRED:
            continue
        values: dict[str, object] = {
            "stable_id": host.stable_id,
            "disposition": host.disposition,
            "device_count": host.device_count,
            "device_set_digest": host.device_set_digest,
            "preparation_intent_digest": host.preparation_intent_digest,
            "wipe_required": host.wipe_required,
            "scope_digest": "",
        }
        values["scope_digest"] = _preparation_scope_digest_from_values(values)
        scopes.append(DeployStoragePreparationScope(**values))  # type: ignore[arg-type]
    return tuple(scopes)


def _build_reconciliation_record(
    context: _StoragePreflightContext,
    execution: StoredDeployStoragePreflightExecution,
    evidence: StoredDeployStoragePreflightEvidence,
    *,
    steps: tuple[DeployBaseOsReconciledStep, ...],
    created_at: str,
) -> DeployPostStoragePreflightReconciliation:
    binding = execution.record.binding
    counts = Counter(step.status for step in steps)
    blockers = tuple(sorted({item for step in steps for item in step.blockers}))
    scopes = _preparation_scopes(evidence)
    wipe_scopes = tuple(item for item in scopes if item.wipe_required)
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": binding.cluster_uuid,
        "cluster_name": binding.cluster_name,
        "operation_id": binding.operation_id,
        "operation": binding.operation,
        "request_digest": binding.request_digest,
        "journal_generation": binding.journal_generation,
        "journal_digest": binding.journal_digest,
        "journal_status": binding.journal_status,
        "journal_phase": binding.journal_phase,
        "prior_reconciliation_artifact_digest": (
            binding.prior_reconciliation_artifact_digest
        ),
        "prior_reconciliation_record_digest": (
            binding.prior_reconciliation_record_digest
        ),
        "prior_effective_plan_digest": binding.prior_effective_plan_digest,
        "execution_artifact_digest": execution.artifact_digest,
        "execution_binding_digest": binding.binding_digest,
        "evidence_artifact_digest": evidence.artifact_digest,
        "evidence_digest": evidence.record.evidence_digest,
        "target_count": binding.target_count,
        "target_set_digest": binding.target_set_digest,
        "device_count": evidence.record.device_count,
        "device_set_digest": evidence.record.device_set_digest,
        "status_digest": evidence.record.status_digest,
        "blocked_host_count": evidence.record.blocked_host_count,
        "owned_noop_host_count": evidence.record.owned_noop_host_count,
        "prepare_required_host_count": evidence.record.prepare_required_host_count,
        "wipe_required_host_count": evidence.record.wipe_required_host_count,
        "preparation_scopes": scopes,
        "preparation_target_set_digest": _digest_object(
            [item.stable_id for item in scopes]
        ),
        "preparation_scope_digest": _digest_object(
            [item.to_object() for item in scopes]
        ),
        "wipe_target_set_digest": _digest_object(
            [item.stable_id for item in wipe_scopes]
        ),
        "wipe_scope_digest": _digest_object([item.to_object() for item in wipe_scopes]),
        "steps": steps,
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
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "record_digest": "",
    }
    values["record_digest"] = _reconciliation_record_digest_from_values(values)
    return DeployPostStoragePreflightReconciliation(**values)  # type: ignore[arg-type]


def _build_reconciliation_report(
    stored: StoredDeployPostStoragePreflightReconciliation,
    *,
    state: DeployStoragePreflightArtifactState,
) -> DeployPostStoragePreflightReconciliationReport:
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
        targets = tuple(sorted({item for step in steps for item in step.target_ids}))
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
    return DeployPostStoragePreflightReconciliationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        reconciliation_artifact_digest=stored.artifact_digest,
        reconciliation_record_digest=record.record_digest,
        effective_plan_digest=record.effective_plan_digest,
        target_count=record.target_count,
        target_set_digest=record.target_set_digest,
        device_count=record.device_count,
        device_set_digest=record.device_set_digest,
        status_digest=record.status_digest,
        blocked_host_count=record.blocked_host_count,
        owned_noop_host_count=record.owned_noop_host_count,
        prepare_required_host_count=record.prepare_required_host_count,
        wipe_required_host_count=record.wipe_required_host_count,
        preparation_scopes=record.preparation_scopes,
        preparation_target_set_digest=record.preparation_target_set_digest,
        preparation_scope_digest=record.preparation_scope_digest,
        wipe_target_set_digest=record.wipe_target_set_digest,
        wipe_scope_digest=record.wipe_scope_digest,
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
        finalization_state=record.finalization_state,
        public_workflow_state=record.public_workflow_state,
    )


def _result_digest(
    hosts: tuple[DeployStoragePreflightHostEvidence, ...],
) -> str:
    return _digest_object(
        {
            "hosts": [host.to_object() for host in hosts],
            "schema_version": STORAGE_PREFLIGHT_SCHEMA_VERSION,
        }
    )


def _semantic_evidence_digest(
    binding: DeployStoragePreflightExecutionBinding,
    result_digest: str,
    device_set_digest: str,
    status_digest: str,
) -> str:
    return _digest_object(
        {
            "command_digest": binding.command_digest,
            "device_set_digest": device_set_digest,
            "playbook_source_digest": binding.playbook_source_digest,
            "result_digest": result_digest,
            "runtime_variables_digest": binding.runtime_variables_digest,
            "status_digest": status_digest,
            "step_digest": binding.step_digest,
            "target_set_digest": binding.target_set_digest,
        }
    )


def _host_status_digest(host: DeployStoragePreflightHostEvidence) -> str:
    return _host_status_digest_from_values(host.to_object())


def _host_status_digest_from_values(values: Mapping[str, object]) -> str:
    return _digest_object(
        {
            "action": _enum_value(values["action"]),
            "backend": values["backend"],
            "blocker_digest": values["blocker_digest"],
            "capacity_bytes": values["capacity_bytes"],
            "desired_policy_digest": values["desired_policy_digest"],
            "device_count": values["device_count"],
            "device_set_digest": values["device_set_digest"],
            "discovery_digest": values["discovery_digest"],
            "disposition": _enum_value(values["disposition"]),
            "layout": values["layout"],
            "manifest_digest": values["manifest_digest"],
            "preparation_intent_digest": values["preparation_intent_digest"],
            "stable_id": values["stable_id"],
            "wipe_required": values["wipe_required"],
        }
    )


def _preparation_scope_digest(scope: DeployStoragePreparationScope) -> str:
    value = scope.to_object()
    value["scope_digest"] = ""
    return _digest_object(value)


def _preparation_scope_digest_from_values(values: Mapping[str, object]) -> str:
    return _digest_object(
        {
            "device_count": values["device_count"],
            "device_set_digest": values["device_set_digest"],
            "disposition": _enum_value(values["disposition"]),
            "preparation_intent_digest": values["preparation_intent_digest"],
            "scope_digest": "",
            "stable_id": values["stable_id"],
            "wipe_required": values["wipe_required"],
        }
    )


def _enum_value(value: object) -> object:
    return value.value if isinstance(value, StrEnum) else value


def _failure_state(error: AnsibleError) -> DeployStoragePreflightExecutionState:
    if isinstance(error, AnsibleResultError):
        return DeployStoragePreflightExecutionState.MALFORMED_RESULT
    cause = error.__cause__
    if isinstance(cause, ProcessTimeoutError):
        return DeployStoragePreflightExecutionState.TIMED_OUT
    if isinstance(cause, ProcessOutputError):
        return DeployStoragePreflightExecutionState.MALFORMED_RESULT
    return DeployStoragePreflightExecutionState.FAILED


def _binding_digests(
    binding: DeployStoragePreflightExecutionBinding,
) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(binding, name))
        for name in binding.__dataclass_fields__
        if name.endswith("_digest")
    )


def _binding_digest(binding: DeployStoragePreflightExecutionBinding) -> str:
    value = binding.to_object()
    value["binding_digest"] = ""
    return _digest_object(value)


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployStoragePreflightExecutionBinding.__dataclass_fields__.items():
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


def _reconciliation_digests(
    record: DeployPostStoragePreflightReconciliation,
) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(record, name))
        for name in record.__dataclass_fields__
        if name.endswith("_digest")
    )


def _reconciliation_record_digest(
    record: DeployPostStoragePreflightReconciliation,
) -> str:
    value = record.to_object()
    value["record_digest"] = ""
    return _digest_object(value)


def _reconciliation_record_digest_from_values(
    values: Mapping[str, object],
) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployPostStoragePreflightReconciliation.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(item, (JournalStatus, OperationPhase))
            else [step.to_object() for step in item]
            if name == "steps" and isinstance(item, tuple)
            else [scope.to_object() for scope in item]
            if name == "preparation_scopes" and isinstance(item, tuple)
            else list(item)
            if name == "blocker_set" and isinstance(item, tuple)
            else item
        )
    value["record_digest"] = ""
    return _digest_object(value)


def _timestamp() -> str:
    return format_timestamp(datetime.now(UTC))


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError("deploy storage-preflight paths are not canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy storage-preflight requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy storage-preflight artifacts"
        ) from error
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_STORAGE_PREFLIGHT_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_FILENAME_SUFFIX,
        DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_FILENAME_SUFFIX,
    )
    for entry in entries:
        suffix = next(
            (candidate for candidate in suffixes if entry.name.endswith(candidate)),
            None,
        )
        if suffix is None:
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
            raise StateConflictError("deploy storage-preflight artifacts are ambiguous")


def _id_from_filename(name: str, suffix: str) -> uuid.UUID | None:
    if not name.endswith(suffix):
        return None
    value = name[: -len(suffix)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _positive_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


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
    "ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION",
    "DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_FILENAME_SUFFIX",
    "DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_STORAGE_PREFLIGHT_EXECUTION_FILENAME_SUFFIX",
    "DeployPostStoragePreflightReconciliation",
    "DeployPostStoragePreflightReconciliationReport",
    "DeployPostStoragePreflightReconciliationStore",
    "DeployStoragePreflightAction",
    "DeployStoragePreflightArtifactState",
    "DeployStoragePreflightEvidence",
    "DeployStoragePreflightEvidenceStore",
    "DeployStoragePreflightExecution",
    "DeployStoragePreflightExecutionReport",
    "DeployStoragePreflightExecutionState",
    "DeployStoragePreflightExecutionStore",
    "DeployStoragePreflightHostEvidence",
    "DeployStoragePreparationScope",
    "StoredDeployPostStoragePreflightReconciliation",
    "StoredDeployStoragePreflightEvidence",
    "StoredDeployStoragePreflightExecution",
    "deploy_post_storage_preflight_reconciliation_id_from_filename",
    "deploy_post_storage_preflight_reconciliation_path",
    "deploy_storage_preflight_evidence_id_from_filename",
    "deploy_storage_preflight_evidence_path",
    "deploy_storage_preflight_execution_id_from_filename",
    "deploy_storage_preflight_execution_path",
    "execute_deploy_storage_preflight",
    "reconcile_deploy_storage_preflight",
]
