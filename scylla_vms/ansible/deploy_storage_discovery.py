"""Deploy-specific read-only storage discovery and immutable reconciliation.

This internal owner derives the sole eligible Scylla scope from the complete
post-non-jump-reboot chain.  It records started intent before the controlled
call, projects strict storage results without device paths or identifiers, and
advances only the immediate storage-preflight gate after certain success.
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
from scylla_vms.ansible.deploy_non_jump_reboot_reconciliation import (
    ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_SCHEMA_VERSION,
    DeployPostNonJumpRebootReconciliationStore,
    StoredDeployPostNonJumpRebootReconciliation,
    _PostNonJumpRebootContext,
)
from scylla_vms.ansible.deploy_non_jump_reboot_reconciliation import (
    _build_record as _build_post_non_jump_reboot_record,
)
from scylla_vms.ansible.deploy_non_jump_reboot_reconciliation import (
    _build_steps as _build_post_non_jump_reboot_steps,
)
from scylla_vms.ansible.deploy_non_jump_reboot_reconciliation import (
    _load_context as _load_post_non_jump_reboot_context,
)
from scylla_vms.ansible.deploy_plan import (
    DeployConditionState,
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.operation_binding import readiness_binding_digest
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
from scylla_vms.ansible.storage import (
    STORAGE_DISCOVERY_SCHEMA_VERSION,
    StorageDeviceEvidence,
    StorageHostEvidence,
)
from scylla_vms.ansible.storage_preflight import (
    STORAGE_PREFLIGHT_SCHEMA_VERSION,
    StorageHostPreflight,
    StorageOwnershipStatus,
    reconcile_storage_preflight,
)
from scylla_vms.ansible.toolchain import AnsibleToolchain
from scylla_vms.ansible.trust import TrustStore
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
    _reconstructed_readiness,
    _toolchain_evidence_digest,
    _validate_toolchain_dependency,
)

ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-discovery-execution-binding/v1"
)
ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-discovery-execution/v1"
)
ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-discovery-evidence/v2"
)
ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-discovery-execution-report/v1"
)
ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-storage-discovery-reconciliation/v1"
)
ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-storage-discovery-reconciliation-report/v1"
)

DEPLOY_STORAGE_DISCOVERY_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-storage-discovery-execution.json"
)
DEPLOY_STORAGE_DISCOVERY_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-storage-discovery-evidence.json"
)
DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-post-storage-discovery-reconciliation.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "storage-discover"
_NEXT_PLAYBOOK = "storage-preflight"
_MAPPING_SEQUENCE = 7
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
_PUBLIC_DEVICE_ID = re.compile(r"device-sha256:[0-9a-f]{64}\Z")


class DeployStorageDiscoveryExecutionState(StrEnum):
    """Durable state of the sole storage-discovery invocation."""

    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"


class DeployStorageDiscoveryHostStatus(StrEnum):
    """Bounded semantic result for one selected host."""

    DISCOVERED = "discovered"
    FAILED = "failed"
    UNREACHABLE = "unreachable"


class DeployStorageDiscoveryArtifactState(StrEnum):
    """Persistence outcome returned by the internal owners."""

    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployStorageDiscoveryExecutionBinding:
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
    full_chain_digest: str
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
        ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_BINDING_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_BINDING_SCHEMA_VERSION
            or self.prior_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_SCHEMA_VERSION
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
                "deploy storage-discovery execution binding is invalid"
            )
        validate_cluster_name(self.cluster_name)
        for value in (
            self.journal_generation,
            self.inventory_generation,
            self.trust_generation,
            self.step_sequence,
            self.target_count,
        ):
            _positive_integer(value, "storage-discovery binding count")
        for digest_value in _binding_digests(self):
            validate_digest(digest_value, "storage-discovery binding digest")
        if self.binding_digest != _binding_digest(self):
            raise StatePersistenceError(
                "deploy storage-discovery binding digest conflicts"
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
    ) -> DeployStorageDiscoveryExecutionBinding:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy storage-discovery execution binding",
        )
        integers = {
            "journal_generation",
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
class DeployStorageDiscoveryExecution:
    """Generation-guarded at-most-once read-only execution."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployStorageDiscoveryExecutionBinding
    state: DeployStorageDiscoveryExecutionState
    invocation_count: int
    invocation_may_have_occurred: bool
    completed: bool
    exit_code: int | None
    result_digest: str | None
    evidence_digest: str | None
    manual_recovery_required: bool
    automatic_retry_allowed: bool = False
    schema_version: str = ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION
            or self.generation not in {1, 2}
            or self.invocation_count != 1
            or not self.invocation_may_have_occurred
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy storage-discovery execution summary is invalid"
            )
        created = parse_timestamp(self.created_at)
        updated = parse_timestamp(self.updated_at)
        if updated < created:
            raise StatePersistenceError(
                "deploy storage-discovery execution timestamps conflict"
            )
        if self.state is DeployStorageDiscoveryExecutionState.STARTED:
            valid = (
                self.generation == 1
                and not self.completed
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.manual_recovery_required
            )
        elif self.state in {
            DeployStorageDiscoveryExecutionState.SUCCEEDED,
            DeployStorageDiscoveryExecutionState.FAILED,
            DeployStorageDiscoveryExecutionState.UNREACHABLE,
        }:
            valid = (
                self.generation == 2
                and self.completed
                and self.exit_code is not None
                and self.result_digest is not None
                and self.evidence_digest is not None
                and self.manual_recovery_required
                == (self.state is not DeployStorageDiscoveryExecutionState.SUCCEEDED)
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
                "deploy storage-discovery execution state conflicts"
            )
        for value in (self.result_digest, self.evidence_digest):
            if value is not None:
                validate_digest(value, "storage-discovery execution outcome digest")

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
    ) -> DeployStorageDiscoveryExecution:
        require_exact_keys(
            value, set(cls.__dataclass_fields__), "deploy storage-discovery execution"
        )
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                updated_at=require_string(value, "updated_at"),
                binding=DeployStorageDiscoveryExecutionBinding.from_object(
                    _mapping(value["binding"], "execution binding")
                ),
                state=DeployStorageDiscoveryExecutionState(
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
                "deploy storage-discovery execution enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployStorageDiscoveryDeviceEvidence:
    """Hashed, address-free projection of one discovered block device."""

    identity_digest: str
    kind: str
    size_bytes: int
    root_ancestor: bool
    boot_ancestor: bool
    filesystem_present: bool
    mount_count: int
    parent_count: int
    holder_count: int
    signature_count: int
    signature_digest: str
    ownership_marker: str
    ownership_digest: str | None
    topology_digest: str

    def __post_init__(self) -> None:
        if (
            self.kind not in {"crypt", "disk", "lvm", "mpath", "part", "raid"}
            or self.ownership_marker not in {"absent", "present", "unavailable"}
            or self.size_bytes < 1
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in (
                    self.mount_count,
                    self.parent_count,
                    self.holder_count,
                    self.signature_count,
                )
            )
            or (self.ownership_marker == "present")
            != (self.ownership_digest is not None)
        ):
            raise StatePersistenceError(
                "deploy storage-discovery device evidence is invalid"
            )
        for value in (
            self.identity_digest,
            self.signature_digest,
            self.topology_digest,
        ):
            validate_digest(value, "storage-discovery device digest")
        if self.ownership_digest is not None:
            validate_digest(self.ownership_digest, "storage ownership digest")

    def to_object(self) -> dict[str, object]:
        return {
            "boot_ancestor": self.boot_ancestor,
            "filesystem_present": self.filesystem_present,
            "holder_count": self.holder_count,
            "identity_digest": self.identity_digest,
            "kind": self.kind,
            "mount_count": self.mount_count,
            "ownership_digest": self.ownership_digest,
            "ownership_marker": self.ownership_marker,
            "parent_count": self.parent_count,
            "root_ancestor": self.root_ancestor,
            "signature_count": self.signature_count,
            "signature_digest": self.signature_digest,
            "size_bytes": self.size_bytes,
            "topology_digest": self.topology_digest,
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployStorageDiscoveryDeviceEvidence:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy storage-discovery device evidence",
        )
        return cls(
            identity_digest=require_string(value, "identity_digest"),
            kind=require_string(value, "kind"),
            size_bytes=_integer(value["size_bytes"], "size bytes"),
            root_ancestor=_boolean(value["root_ancestor"], "root ancestor"),
            boot_ancestor=_boolean(value["boot_ancestor"], "boot ancestor"),
            filesystem_present=_boolean(
                value["filesystem_present"], "filesystem present"
            ),
            mount_count=_integer(value["mount_count"], "mount count"),
            parent_count=_integer(value["parent_count"], "parent count"),
            holder_count=_integer(value["holder_count"], "holder count"),
            signature_count=_integer(value["signature_count"], "signature count"),
            signature_digest=require_string(value, "signature_digest"),
            ownership_marker=require_string(value, "ownership_marker"),
            ownership_digest=_optional_string(
                value["ownership_digest"], "ownership digest"
            ),
            topology_digest=require_string(value, "topology_digest"),
        )


@dataclass(frozen=True, slots=True)
class DeployStorageDiscoveryPreflightDevice:
    """Redacted selected-device projection retained for the next read-only gate."""

    identity: str
    capacity_bytes: int

    def __post_init__(self) -> None:
        if (
            _PUBLIC_DEVICE_ID.fullmatch(self.identity) is None
            or isinstance(self.capacity_bytes, bool)
            or not isinstance(self.capacity_bytes, int)
            or self.capacity_bytes < 1
        ):
            raise StatePersistenceError(
                "deploy storage-discovery preflight device is invalid"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "capacity_bytes": self.capacity_bytes,
            "identity": self.identity,
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployStorageDiscoveryPreflightDevice:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy storage-discovery preflight device",
        )
        return cls(
            identity=require_string(value, "identity"),
            capacity_bytes=_integer(value["capacity_bytes"], "capacity bytes"),
        )


@dataclass(frozen=True, slots=True)
class DeployStorageDiscoveryHostEvidence:
    """Exact-host semantic projection with no device or provider identity."""

    stable_id: str
    status: DeployStorageDiscoveryHostStatus
    host_manifest_digest: str
    storage_generation: int
    storage_policy_digest: str
    device_count: int
    device_set_digest: str
    tools_available_count: int
    tools_unavailable_count: int
    tools_digest: str
    root_ancestor_count: int
    boot_ancestor_count: int
    mounted_device_count: int
    signed_device_count: int
    owned_device_count: int
    devices: tuple[DeployStorageDiscoveryDeviceEvidence, ...]
    preflight_backend: str
    preflight_layout: str
    preflight_capacity_bytes: int
    preflight_ownership_status: StorageOwnershipStatus
    preflight_blockers: tuple[str, ...]
    preflight_wipe_required: bool
    preparation_intent_digest: str
    preflight_devices: tuple[DeployStorageDiscoveryPreflightDevice, ...]
    preflight_device_set_digest: str
    preflight_result_digest: str

    def __post_init__(self) -> None:
        if (
            _LOGICAL_ID.fullmatch(self.stable_id) is None
            or not isinstance(self.status, DeployStorageDiscoveryHostStatus)
            or self.storage_generation < 1
            or self.device_count != len(self.devices)
            or self.tools_available_count < 0
            or self.tools_unavailable_count < 0
            or self.root_ancestor_count
            != sum(item.root_ancestor for item in self.devices)
            or self.boot_ancestor_count
            != sum(item.boot_ancestor for item in self.devices)
            or self.mounted_device_count
            != sum(item.mount_count > 0 for item in self.devices)
            or self.signed_device_count
            != sum(item.signature_count > 0 for item in self.devices)
            or self.owned_device_count
            != sum(item.ownership_marker == "present" for item in self.devices)
            or tuple(item.identity_digest for item in self.devices)
            != tuple(sorted({item.identity_digest for item in self.devices}))
            or self.preflight_backend not in {"block-volume", "local-nvme"}
            or self.preflight_layout not in {"single", "raid0"}
            or self.preflight_capacity_bytes < 0
            or not isinstance(self.preflight_ownership_status, StorageOwnershipStatus)
            or self.preflight_blockers != tuple(sorted(set(self.preflight_blockers)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.preflight_blockers)
            or self.preflight_wipe_required
            != (
                self.preflight_ownership_status
                is StorageOwnershipStatus.WIPE_REVIEW_REQUIRED
            )
            or (self.preflight_ownership_status is StorageOwnershipStatus.BLOCKED)
            != bool(self.preflight_blockers)
            or tuple(item.identity for item in self.preflight_devices)
            != tuple(sorted({item.identity for item in self.preflight_devices}))
        ):
            raise StatePersistenceError(
                "deploy storage-discovery host evidence conflicts"
            )
        if self.status is not DeployStorageDiscoveryHostStatus.DISCOVERED and (
            self.devices
            or self.device_count
            or self.tools_available_count
            or self.tools_unavailable_count
            or self.root_ancestor_count
            or self.boot_ancestor_count
            or self.mounted_device_count
            or self.signed_device_count
            or self.owned_device_count
            or self.preflight_capacity_bytes
            or self.preflight_wipe_required
            or self.preflight_devices
        ):
            raise StatePersistenceError(
                "failed storage-discovery host retained device evidence"
            )
        for value in (
            self.host_manifest_digest,
            self.storage_policy_digest,
            self.device_set_digest,
            self.tools_digest,
            self.preparation_intent_digest,
            self.preflight_device_set_digest,
            self.preflight_result_digest,
        ):
            validate_digest(value, "storage-discovery host digest")
        if self.device_set_digest != _digest_object(
            [item.identity_digest for item in self.devices]
        ):
            raise StatePersistenceError(
                "deploy storage-discovery device set digest conflicts"
            )
        expected_preflight_set = _digest_object(
            [item.identity for item in self.preflight_devices]
        )
        if self.preflight_device_set_digest != expected_preflight_set:
            raise StatePersistenceError(
                "deploy storage-discovery preflight device set digest conflicts"
            )
        projection = {
            "backend": self.preflight_backend,
            "blockers": list(self.preflight_blockers),
            "capacity_bytes": self.preflight_capacity_bytes,
            "devices": [item.to_object() for item in self.preflight_devices],
            "layout": self.preflight_layout,
            "logical_id": self.stable_id,
            "ownership_status": self.preflight_ownership_status.value,
            "preparation_intent_digest": self.preparation_intent_digest,
            "ready": not self.preflight_blockers and not self.preflight_wipe_required,
            "schema_version": STORAGE_PREFLIGHT_SCHEMA_VERSION,
            "wipe_required": self.preflight_wipe_required,
        }
        if self.preflight_result_digest != _digest_object(projection):
            raise StatePersistenceError(
                "deploy storage-discovery preflight result digest conflicts"
            )

    @property
    def successful(self) -> bool:
        return self.status is DeployStorageDiscoveryHostStatus.DISCOVERED

    def to_object(self) -> dict[str, object]:
        return {
            "boot_ancestor_count": self.boot_ancestor_count,
            "device_count": self.device_count,
            "device_set_digest": self.device_set_digest,
            "devices": [item.to_object() for item in self.devices],
            "host_manifest_digest": self.host_manifest_digest,
            "mounted_device_count": self.mounted_device_count,
            "owned_device_count": self.owned_device_count,
            "root_ancestor_count": self.root_ancestor_count,
            "signed_device_count": self.signed_device_count,
            "stable_id": self.stable_id,
            "status": self.status.value,
            "storage_generation": self.storage_generation,
            "storage_policy_digest": self.storage_policy_digest,
            "tools_available_count": self.tools_available_count,
            "tools_digest": self.tools_digest,
            "tools_unavailable_count": self.tools_unavailable_count,
            "preflight_backend": self.preflight_backend,
            "preflight_blockers": list(self.preflight_blockers),
            "preflight_capacity_bytes": self.preflight_capacity_bytes,
            "preflight_device_set_digest": self.preflight_device_set_digest,
            "preflight_devices": [item.to_object() for item in self.preflight_devices],
            "preflight_layout": self.preflight_layout,
            "preflight_ownership_status": self.preflight_ownership_status.value,
            "preflight_result_digest": self.preflight_result_digest,
            "preflight_wipe_required": self.preflight_wipe_required,
            "preparation_intent_digest": self.preparation_intent_digest,
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployStorageDiscoveryHostEvidence:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy storage-discovery host evidence",
        )
        try:
            return cls(
                stable_id=require_string(value, "stable_id"),
                status=DeployStorageDiscoveryHostStatus(
                    require_string(value, "status")
                ),
                host_manifest_digest=require_string(value, "host_manifest_digest"),
                storage_generation=_integer(
                    value["storage_generation"], "storage generation"
                ),
                storage_policy_digest=require_string(value, "storage_policy_digest"),
                device_count=_integer(value["device_count"], "device count"),
                device_set_digest=require_string(value, "device_set_digest"),
                tools_available_count=_integer(
                    value["tools_available_count"], "tools available count"
                ),
                tools_unavailable_count=_integer(
                    value["tools_unavailable_count"], "tools unavailable count"
                ),
                tools_digest=require_string(value, "tools_digest"),
                root_ancestor_count=_integer(
                    value["root_ancestor_count"], "root ancestor count"
                ),
                boot_ancestor_count=_integer(
                    value["boot_ancestor_count"], "boot ancestor count"
                ),
                mounted_device_count=_integer(
                    value["mounted_device_count"], "mounted device count"
                ),
                signed_device_count=_integer(
                    value["signed_device_count"], "signed device count"
                ),
                owned_device_count=_integer(
                    value["owned_device_count"], "owned device count"
                ),
                devices=tuple(
                    DeployStorageDiscoveryDeviceEvidence.from_object(
                        _mapping(item, "device evidence")
                    )
                    for item in _array(value["devices"], "device evidence")
                ),
                preflight_backend=require_string(value, "preflight_backend"),
                preflight_layout=require_string(value, "preflight_layout"),
                preflight_capacity_bytes=_integer(
                    value["preflight_capacity_bytes"], "preflight capacity bytes"
                ),
                preflight_ownership_status=StorageOwnershipStatus(
                    require_string(value, "preflight_ownership_status")
                ),
                preflight_blockers=_string_tuple(
                    value["preflight_blockers"], "preflight blockers"
                ),
                preflight_wipe_required=_boolean(
                    value["preflight_wipe_required"], "preflight wipe required"
                ),
                preparation_intent_digest=require_string(
                    value, "preparation_intent_digest"
                ),
                preflight_devices=tuple(
                    DeployStorageDiscoveryPreflightDevice.from_object(
                        _mapping(item, "preflight device")
                    )
                    for item in _array(value["preflight_devices"], "preflight devices")
                ),
                preflight_device_set_digest=require_string(
                    value, "preflight_device_set_digest"
                ),
                preflight_result_digest=require_string(
                    value, "preflight_result_digest"
                ),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy storage-discovery host status is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployStorageDiscoveryEvidence:
    """Immutable bounded semantic evidence for the exact Scylla scope."""

    generation: int
    created_at: str
    binding: DeployStorageDiscoveryExecutionBinding
    hosts: tuple[DeployStorageDiscoveryHostEvidence, ...]
    discovered_host_count: int
    failed_host_count: int
    unreachable_host_count: int
    device_count: int
    device_set_digest: str
    result_digest: str
    evidence_digest: str
    result_schema_version: str = STORAGE_DISCOVERY_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION
            or self.result_schema_version != STORAGE_DISCOVERY_SCHEMA_VERSION
            or self.generation != 1
            or len(self.hosts) != self.binding.target_count
            or tuple(item.stable_id for item in self.hosts)
            != tuple(sorted({item.stable_id for item in self.hosts}))
            or self.discovered_host_count != sum(item.successful for item in self.hosts)
            or self.failed_host_count
            != sum(
                item.status is DeployStorageDiscoveryHostStatus.FAILED
                for item in self.hosts
            )
            or self.unreachable_host_count
            != sum(
                item.status is DeployStorageDiscoveryHostStatus.UNREACHABLE
                for item in self.hosts
            )
            or self.device_count != sum(item.device_count for item in self.hosts)
            or self.discovered_host_count
            + self.failed_host_count
            + self.unreachable_host_count
            != len(self.hosts)
        ):
            raise StatePersistenceError(
                "deploy storage-discovery evidence summary conflicts"
            )
        parse_timestamp(self.created_at)
        for value in (
            self.device_set_digest,
            self.result_digest,
            self.evidence_digest,
        ):
            validate_digest(value, "storage-discovery evidence digest")
        expected_device_set = _digest_object(
            [
                {
                    "device_set_digest": host.device_set_digest,
                    "stable_id": host.stable_id,
                }
                for host in self.hosts
            ]
        )
        if (
            self.device_set_digest != expected_device_set
            or self.result_digest != _result_digest(self.hosts)
            or self.evidence_digest
            != _semantic_evidence_digest(
                self.binding, self.result_digest, self.device_set_digest
            )
        ):
            raise StatePersistenceError(
                "deploy storage-discovery evidence digest conflicts"
            )

    @property
    def successful(self) -> bool:
        return (
            self.discovered_host_count == len(self.hosts)
            and self.failed_host_count == 0
            and self.unreachable_host_count == 0
        )

    def to_object(self) -> dict[str, object]:
        return {
            "binding": self.binding.to_object(),
            "created_at": self.created_at,
            "device_count": self.device_count,
            "device_set_digest": self.device_set_digest,
            "discovered_host_count": self.discovered_host_count,
            "evidence_digest": self.evidence_digest,
            "failed_host_count": self.failed_host_count,
            "generation": self.generation,
            "hosts": [item.to_object() for item in self.hosts],
            "result_digest": self.result_digest,
            "result_schema_version": self.result_schema_version,
            "schema_version": self.schema_version,
            "unreachable_host_count": self.unreachable_host_count,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployStorageDiscoveryEvidence:
        require_exact_keys(
            value, set(cls.__dataclass_fields__), "deploy storage-discovery evidence"
        )
        return cls(
            generation=_integer(value["generation"], "generation"),
            created_at=require_string(value, "created_at"),
            binding=DeployStorageDiscoveryExecutionBinding.from_object(
                _mapping(value["binding"], "evidence binding")
            ),
            hosts=tuple(
                DeployStorageDiscoveryHostEvidence.from_object(
                    _mapping(item, "host evidence")
                )
                for item in _array(value["hosts"], "host evidence")
            ),
            discovered_host_count=_integer(
                value["discovered_host_count"], "discovered host count"
            ),
            failed_host_count=_integer(value["failed_host_count"], "failed host count"),
            unreachable_host_count=_integer(
                value["unreachable_host_count"], "unreachable host count"
            ),
            device_count=_integer(value["device_count"], "device count"),
            device_set_digest=require_string(value, "device_set_digest"),
            result_digest=require_string(value, "result_digest"),
            evidence_digest=require_string(value, "evidence_digest"),
            result_schema_version=require_string(value, "result_schema_version"),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredDeployStorageDiscoveryExecution:
    record: DeployStorageDiscoveryExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployStorageDiscoveryEvidence:
    record: DeployStorageDiscoveryEvidence
    artifact_digest: str


class DeployStorageDiscoveryExecutionStore:
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
        self._path = deploy_storage_discovery_execution_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployStorageDiscoveryExecution:
        value, digest = self._file.read()
        record = DeployStorageDiscoveryExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy storage-discovery execution identity conflicts"
            )
        return StoredDeployStorageDiscoveryExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployStorageDiscoveryExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployStorageDiscoveryExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployStorageDiscoveryExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy storage-discovery execution operation conflicts"
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
                is not DeployStorageDiscoveryExecutionState.STARTED
                or record.generation != 2
                or record.created_at != current.record.created_at
                or record.binding != current.record.binding
            ):
                raise StateConflictError(
                    "deploy storage-discovery execution transition conflicts"
                )
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
            or record.state is not DeployStorageDiscoveryExecutionState.STARTED
        ):
            raise StateConflictError(
                "deploy storage-discovery initial execution conflicts"
            )
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployStorageDiscoveryExecution(record, digest)


class DeployStorageDiscoveryEvidenceStore:
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
        self._path = deploy_storage_discovery_evidence_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployStorageDiscoveryEvidence:
        value, digest = self._file.read()
        record = DeployStorageDiscoveryEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy storage-discovery evidence identity conflicts"
            )
        return StoredDeployStorageDiscoveryEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployStorageDiscoveryEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployStorageDiscoveryEvidence,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployStorageDiscoveryEvidence, DeployStorageDiscoveryArtifactState
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy storage-discovery evidence operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy storage-discovery evidence is immutable"
                )
            return current, DeployStorageDiscoveryArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployStorageDiscoveryEvidence(record, digest),
            DeployStorageDiscoveryArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployStorageDiscoveryExecutionReport:
    """Strict redacted execution projection."""

    operation_id: uuid.UUID
    execution_artifact_state: DeployStorageDiscoveryArtifactState
    evidence_artifact_state: DeployStorageDiscoveryArtifactState
    execution_state: DeployStorageDiscoveryExecutionState
    execution_artifact_digest: str
    evidence_artifact_digest: str
    binding_digest: str
    invocation_count: int
    target_count: int
    target_set_digest: str
    discovered_host_count: int
    device_count: int
    device_set_digest: str
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    journal_status: JournalStatus
    journal_phase: OperationPhase
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_REPORT_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION
            or self.execution_state
            is not DeployStorageDiscoveryExecutionState.SUCCEEDED
            or self.invocation_count != 1
            or self.target_count < 1
            or self.discovered_host_count != self.target_count
            or self.device_count < 0
            or self.manual_recovery_required
            or self.automatic_retry_allowed
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError(
                "deploy storage-discovery execution report is invalid"
            )
        for value in (
            self.execution_artifact_digest,
            self.evidence_artifact_digest,
            self.binding_digest,
            self.target_set_digest,
            self.device_set_digest,
        ):
            validate_digest(value, "storage-discovery report digest")

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
                "device_count": self.device_count,
                "device_set_digest": self.device_set_digest,
                "discovered_host_count": self.discovered_host_count,
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
class _StorageDiscoveryScope:
    step: DeployBaseOsReconciledStep
    targets: tuple[str, ...]
    variables: Mapping[str, object]
    variables_digest: str
    command_digest: str
    source_digest: str


@dataclass(frozen=True, slots=True)
class _StorageDiscoveryContext:
    post: _PostNonJumpRebootContext
    reconciliation: StoredDeployPostNonJumpRebootReconciliation
    scope: _StorageDiscoveryScope
    binding: DeployStorageDiscoveryExecutionBinding
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport


def execute_deploy_storage_discovery(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployStorageDiscoveryExecutionReport:
    """Execute exactly one canonical storage-discovery scope."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _validate_toolchain_dependency(toolchain)
    executable_identity_digest = _executable_identity_digest(executables)
    toolchain_evidence_digest = _toolchain_evidence_digest(
        toolchain, executable_identity_digest
    )
    _refuse_ambiguous_artifacts(paths, operation_id)
    context = _load_storage_discovery_context(
        paths,
        operation_id,
        lock=lock,
        toolchain_version=str(toolchain.core),
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    execution_store = DeployStorageDiscoveryExecutionStore(paths, operation_id)
    evidence_store = DeployStorageDiscoveryEvidenceStore(paths, operation_id)
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
            execution.record.state is DeployStorageDiscoveryExecutionState.SUCCEEDED
            and evidence is not None
            and evidence.record.successful
        ):
            return _build_execution_report(
                execution,
                evidence,
                execution_state=DeployStorageDiscoveryArtifactState.REUSED,
                evidence_state=DeployStorageDiscoveryArtifactState.REUSED,
            )
        raise StateConflictError(
            "deploy storage-discovery execution requires manual recovery and cannot retry"
        )

    builder = AnsibleCommandBuilder(executables.playbook, executables.inventory, paths)
    definition, validated, variables_digest, command_digest = (
        builder.validate_operation_step(
            _PLAYBOOK,
            step_sequence=context.scope.step.sequence,
            limit=context.scope.targets,
            variables=dict(context.scope.variables),
            tags=(),
            check=False,
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
        raise StateConflictError("deploy storage-discovery command identity conflicts")
    service = AnsibleService(builder, runner)
    discovered = service.version(lock)
    if discovered != toolchain:
        raise StateConflictError("deploy storage-discovery Ansible toolchain drifted")
    before = _load_storage_discovery_context(
        paths,
        operation_id,
        lock=lock,
        toolchain_version=str(toolchain.core),
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    if before.binding != context.binding:
        raise StateConflictError(
            "deploy storage-discovery state drifted before invocation"
        )
    now = _timestamp()
    started = DeployStorageDiscoveryExecution(
        generation=1,
        created_at=now,
        updated_at=now,
        binding=context.binding,
        state=DeployStorageDiscoveryExecutionState.STARTED,
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
            "deploy storage-discovery started intent persistence failed before invocation"
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
            check=False,
            diff=False,
            verbosity=0,
        )
        if observed_command_digest != context.scope.command_digest:
            raise AnsibleResultError(
                "deploy storage-discovery command result identity conflicts"
            )
    except KeyboardInterrupt:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployStorageDiscoveryExecutionState.INTERRUPTED,
            lock=lock,
        )
        raise AnsibleError(
            "deploy storage-discovery execution was interrupted; "
            "manual recovery required"
        ) from None
    except AnsibleError as error:
        _persist_uncertain_or_raise(
            execution_store, execution, _failure_state(error), lock=lock
        )
        raise AnsibleError(
            "deploy storage-discovery execution is uncertain; manual recovery required"
        ) from error

    try:
        after = _load_storage_discovery_context(
            paths,
            operation_id,
            lock=lock,
            toolchain_version=str(toolchain.core),
            executable_identity_digest=executable_identity_digest,
            toolchain_evidence_digest=toolchain_evidence_digest,
        )
    except (StateConflictError, StatePersistenceError) as error:
        raise StateConflictError(
            "deploy storage-discovery state changed after invocation; "
            "manual recovery required"
        ) from error
    if after.binding != context.binding:
        raise StateConflictError(
            "deploy storage-discovery state changed after invocation; "
            "manual recovery required"
        )
    try:
        evidence_record = _build_semantic_evidence(context, result)
    except (AnsibleError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployStorageDiscoveryExecutionState.MALFORMED_RESULT,
            lock=lock,
        )
        raise AnsibleError(
            "deploy storage-discovery result is malformed; manual recovery required"
        ) from error
    try:
        evidence, evidence_state = evidence_store.write_locked(
            evidence_record, lock=lock
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy storage-discovery evidence persistence failed; "
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
            DeployStorageDiscoveryExecutionState.SUCCEEDED,
            DeployStorageDiscoveryExecutionState.FAILED,
            DeployStorageDiscoveryExecutionState.UNREACHABLE,
        },
        exit_code=result.exit_code,
        result_digest=evidence_record.result_digest,
        evidence_digest=evidence_record.evidence_digest,
        manual_recovery_required=(
            terminal_state is not DeployStorageDiscoveryExecutionState.SUCCEEDED
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
            "deploy storage-discovery terminal persistence failed; "
            "manual recovery required"
        ) from error
    if terminal_state is not DeployStorageDiscoveryExecutionState.SUCCEEDED:
        raise AnsibleError(
            "deploy storage-discovery execution failed; manual recovery required"
        )
    return _build_execution_report(
        execution,
        evidence,
        execution_state=DeployStorageDiscoveryArtifactState.UPDATED,
        evidence_state=evidence_state,
    )


def deploy_storage_discovery_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_STORAGE_DISCOVERY_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy storage-discovery execution path is not canonical"
        )
    return path


def deploy_storage_discovery_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_STORAGE_DISCOVERY_EVIDENCE_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy storage-discovery evidence path is not canonical"
        )
    return path


def deploy_storage_discovery_execution_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(name, DEPLOY_STORAGE_DISCOVERY_EXECUTION_FILENAME_SUFFIX)


def deploy_storage_discovery_evidence_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(name, DEPLOY_STORAGE_DISCOVERY_EVIDENCE_FILENAME_SUFFIX)


def _load_storage_discovery_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
    toolchain_version: str,
    executable_identity_digest: str,
    toolchain_evidence_digest: str,
) -> _StorageDiscoveryContext:
    post = _load_post_non_jump_reboot_context(paths, operation_id, lock=lock)
    planning = post.chain.authorization_context.final_routes.post.post.base.host.loaded.planning
    loaded = post.chain.authorization_context.final_routes.post.post.base.host.loaded
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    readiness_record = planning.readiness.record
    if (
        readiness_record.playbook_version != toolchain_version
        or readiness_record.inventory_version != toolchain_version
        or readiness_record.executable_identity_digest != executable_identity_digest
        or readiness_record.toolchain_evidence_digest != toolchain_evidence_digest
        or readiness_record.remote_playbook_status != "not-performed"
    ):
        raise StateConflictError(
            "deploy storage-discovery readiness or toolchain binding conflicts"
        )
    readiness = _reconstructed_readiness(planning.base)
    if readiness_binding_digest(readiness) != readiness_record.readiness_digest:
        raise StateConflictError("deploy storage-discovery readiness is stale")
    readiness.require_ready(OperationClassification.READ_ONLY)
    TrustStore(paths).validate_runtime(planning.base.trust, deploy.inventory)
    store = DeployPostNonJumpRebootReconciliationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    if not store.path.exists():
        raise StateConflictError(
            "deploy storage-discovery requires post-non-jump-reboot reconciliation"
        )
    reconciliation = store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected = _build_post_non_jump_reboot_record(
        post,
        steps=_build_post_non_jump_reboot_steps(post),
        created_at=reconciliation.record.created_at,
    )
    if reconciliation.record != expected:
        raise StateConflictError(
            "deploy storage-discovery prior reconciliation drifted"
        )
    scope = _derive_scope(post, reconciliation)
    journal = deploy.journal
    runtime_variables = {
        "deploy_scylla_vms_cluster_uuid": str(deploy.inventory.record.cluster_uuid),
        "deploy_scylla_vms_host_manifest_digest": (
            deploy.inventory.record.source_manifest_digest
        ),
        "deploy_scylla_vms_inventory_file_digest": deploy.inventory.digest,
        "deploy_scylla_vms_inventory_generation": (deploy.inventory.record.generation),
        "deploy_scylla_vms_observation_digest": (
            deploy.inventory.record.source_manifest_digest
        ),
        "deploy_scylla_vms_observation_generation": (
            deploy.inventory.record.source_manifest_generation
        ),
    }
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
        "full_chain_digest": _digest_object(
            {
                "prior_artifact_digest": reconciliation.artifact_digest,
                "prior_record_digest": reconciliation.record.record_digest,
                "prior_effective_plan_digest": (
                    reconciliation.record.effective_plan_digest
                ),
                "catalog_digest": loaded.catalog_digest,
                "source_digest": loaded.source.digest,
            }
        ),
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
        "runtime_variables_digest": _digest_object(runtime_variables),
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "binding_digest": "",
    }
    values["binding_digest"] = _binding_digest_from_values(values)
    binding = DeployStorageDiscoveryExecutionBinding(**values)  # type: ignore[arg-type]
    return _StorageDiscoveryContext(
        post,
        reconciliation,
        scope,
        binding,
        metadata,
        deploy.inventory,
        readiness,
    )


def _derive_scope(
    post: _PostNonJumpRebootContext,
    reconciliation: StoredDeployPostNonJumpRebootReconciliation,
) -> _StorageDiscoveryScope:
    authorization_context = post.chain.authorization_context
    host_context = authorization_context.final_routes.post.post.base.host
    loaded = host_context.loaded
    planning = loaded.planning
    inventory_hosts = planning.base.deploy.inventory.record.inventory.hosts
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
    variables: dict[str, object] = {}
    if (
        len(selected) != 1
        or not scylla_ids
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
            "deploy storage-discovery eligible scope identity conflicts"
        )
    validate_playbook_request_policy(
        _PLAYBOOK,
        limit=scylla_ids,
        tags=(),
        check=False,
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
        check=False,
        diff=False,
        verbosity=0,
    )
    return _StorageDiscoveryScope(
        selected[0],
        scylla_ids,
        validated,
        variables_digest,
        command_digest,
        _playbook_source_digest(loaded.source, _PLAYBOOK),
    )


def _validate_execution_prefix(
    context: _StorageDiscoveryContext,
    execution: StoredDeployStorageDiscoveryExecution | None,
    evidence: StoredDeployStorageDiscoveryEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "deploy storage-discovery evidence exists without intent"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError(
            "deploy storage-discovery execution provenance is stale"
        )
    if evidence is not None:
        if (
            evidence.record.binding != context.binding
            or execution.record.result_digest != evidence.record.result_digest
            or execution.record.evidence_digest != evidence.record.evidence_digest
        ):
            raise StateConflictError(
                "deploy storage-discovery semantic evidence conflicts"
            )
    elif execution.record.state in {
        DeployStorageDiscoveryExecutionState.SUCCEEDED,
        DeployStorageDiscoveryExecutionState.FAILED,
        DeployStorageDiscoveryExecutionState.UNREACHABLE,
    }:
        raise StateConflictError(
            "deploy storage-discovery terminal evidence is missing"
        )


def _build_semantic_evidence(
    context: _StorageDiscoveryContext,
    result: AnsibleExecutionResult,
) -> DeployStorageDiscoveryEvidence:
    parsed = result.storage_discovery
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.READ_ONLY
        or result.check_mode
        or result.stdout
        or result.stderr
        or parsed is None
    ):
        raise AnsibleResultError("deploy storage-discovery result identity conflicts")
    successful = {host.logical_id: host for host in parsed.hosts}
    unavailable = set(parsed.unavailable_hosts)
    if set(successful) | unavailable != set(context.scope.targets):
        raise AnsibleResultError("deploy storage-discovery result membership conflicts")
    deploy = context.post.chain.authorization_context.final_routes.post.post.base.host.loaded.planning.base.deploy
    preflight = (
        reconcile_storage_preflight(
            context.metadata,
            deploy.observation,
            context.inventory,
            parsed,
            context.scope.targets,
        )
        if not unavailable
        else None
    )
    preflight_by_host = (
        {host.logical_id: host for host in preflight.hosts}
        if preflight is not None
        else {}
    )
    inventory_hosts = {
        host.logical_id: host for host in context.inventory.record.inventory.hosts
    }
    manifest_hosts = {
        host.logical_id: host for host in deploy.observation.record.manifest.hosts
    }
    hosts: list[DeployStorageDiscoveryHostEvidence] = []
    failed_status = (
        DeployStorageDiscoveryHostStatus.UNREACHABLE
        if result.exit_code == 4
        else DeployStorageDiscoveryHostStatus.FAILED
    )
    for stable_id in context.scope.targets:
        parsed_host = successful.get(stable_id)
        inventory_host = inventory_hosts.get(stable_id)
        if inventory_host is None or inventory_host.role is not HostRole.SCYLLA:
            raise AnsibleResultError(
                "deploy storage-discovery inventory membership conflicts"
            )
        if parsed_host is None:
            manifest_host = manifest_hosts.get(stable_id)
            if manifest_host is None or manifest_host.storage.layout is None:
                raise AnsibleResultError(
                    "deploy storage-discovery manifest membership conflicts"
                )
            blockers = ("storage-discovery-unavailable",)
            intent_digest = _digest_object(
                {
                    "host_manifest_digest": (
                        context.inventory.record.source_manifest_digest
                    ),
                    "stable_id": stable_id,
                    "state": "storage-discovery-unavailable",
                    "storage_policy_digest": inventory_host.storage_policy_digest,
                }
            )
            preflight_projection = {
                "backend": manifest_host.storage.selected_backend.value,
                "blockers": list(blockers),
                "capacity_bytes": 0,
                "devices": [],
                "layout": manifest_host.storage.layout,
                "logical_id": stable_id,
                "ownership_status": StorageOwnershipStatus.BLOCKED.value,
                "preparation_intent_digest": intent_digest,
                "ready": False,
                "schema_version": STORAGE_PREFLIGHT_SCHEMA_VERSION,
                "wipe_required": False,
            }
            hosts.append(
                DeployStorageDiscoveryHostEvidence(
                    stable_id=stable_id,
                    status=failed_status,
                    host_manifest_digest=context.inventory.record.source_manifest_digest,
                    storage_generation=inventory_host.storage_generation,
                    storage_policy_digest=inventory_host.storage_policy_digest,
                    device_count=0,
                    device_set_digest=_digest_object([]),
                    tools_available_count=0,
                    tools_unavailable_count=0,
                    tools_digest=_digest_object([]),
                    root_ancestor_count=0,
                    boot_ancestor_count=0,
                    mounted_device_count=0,
                    signed_device_count=0,
                    owned_device_count=0,
                    devices=(),
                    preflight_backend=manifest_host.storage.selected_backend.value,
                    preflight_layout=manifest_host.storage.layout,
                    preflight_capacity_bytes=0,
                    preflight_ownership_status=StorageOwnershipStatus.BLOCKED,
                    preflight_blockers=blockers,
                    preflight_wipe_required=False,
                    preparation_intent_digest=intent_digest,
                    preflight_devices=(),
                    preflight_device_set_digest=_digest_object([]),
                    preflight_result_digest=_digest_object(preflight_projection),
                )
            )
            continue
        preflight_host = preflight_by_host.get(stable_id)
        if preflight_host is None:
            raise AnsibleResultError(
                "deploy storage-discovery preflight projection is incomplete"
            )
        hosts.append(_project_host(parsed_host, preflight_host))
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
    return DeployStorageDiscoveryEvidence(
        generation=1,
        created_at=_timestamp(),
        binding=context.binding,
        hosts=projected,
        discovered_host_count=sum(host.successful for host in projected),
        failed_host_count=sum(
            host.status is DeployStorageDiscoveryHostStatus.FAILED for host in projected
        ),
        unreachable_host_count=sum(
            host.status is DeployStorageDiscoveryHostStatus.UNREACHABLE
            for host in projected
        ),
        device_count=sum(host.device_count for host in projected),
        device_set_digest=device_set_digest,
        result_digest=result_digest,
        evidence_digest=_semantic_evidence_digest(
            context.binding, result_digest, device_set_digest
        ),
    )


def _project_host(
    host: StorageHostEvidence,
    preflight: StorageHostPreflight,
) -> DeployStorageDiscoveryHostEvidence:
    devices = tuple(
        sorted(
            (_project_device(item) for item in host.devices),
            key=lambda item: item.identity_digest,
        )
    )
    tools = tuple(host.tools)
    preflight_devices = tuple(
        DeployStorageDiscoveryPreflightDevice(item.identity, item.capacity_bytes)
        for item in preflight.devices
    )
    return DeployStorageDiscoveryHostEvidence(
        stable_id=host.logical_id,
        status=DeployStorageDiscoveryHostStatus.DISCOVERED,
        host_manifest_digest=host.host_manifest_digest,
        storage_generation=host.storage_generation,
        storage_policy_digest=host.storage_policy_digest,
        device_count=len(devices),
        device_set_digest=_digest_object([item.identity_digest for item in devices]),
        tools_available_count=sum(status == "available" for _name, status in tools),
        tools_unavailable_count=sum(status == "unavailable" for _name, status in tools),
        tools_digest=_digest_object(
            [{"name": name, "status": status} for name, status in tools]
        ),
        root_ancestor_count=sum(item.root_ancestor for item in devices),
        boot_ancestor_count=sum(item.boot_ancestor for item in devices),
        mounted_device_count=sum(item.mount_count > 0 for item in devices),
        signed_device_count=sum(item.signature_count > 0 for item in devices),
        owned_device_count=sum(item.ownership_marker == "present" for item in devices),
        devices=devices,
        preflight_backend=preflight.backend,
        preflight_layout=preflight.layout,
        preflight_capacity_bytes=preflight.capacity_bytes,
        preflight_ownership_status=preflight.ownership_status,
        preflight_blockers=preflight.blockers,
        preflight_wipe_required=preflight.wipe_required,
        preparation_intent_digest=preflight.preparation_intent_digest,
        preflight_devices=preflight_devices,
        preflight_device_set_digest=_digest_object(
            [item.identity for item in preflight_devices]
        ),
        preflight_result_digest=_digest_object(preflight.to_object()),
    )


def _project_device(
    device: StorageDeviceEvidence,
) -> DeployStorageDiscoveryDeviceEvidence:
    identity_digest = _digest_object({"stable_device_id": device.stable_id})
    ownership_digest = (
        _digest_object(
            {
                "backend": device.ownership.backend,
                "cluster_uuid": device.ownership.cluster_uuid,
                "layout": device.ownership.layout,
                "logical_id": device.ownership.logical_id,
                "policy_digest": device.ownership.policy_digest,
                "preparation_intent_digest": (
                    device.ownership.preparation_intent_digest
                ),
                "stable_device_ids": list(device.ownership.stable_device_ids),
                "storage_generation": device.ownership.storage_generation,
            }
        )
        if device.ownership is not None
        else None
    )
    return DeployStorageDiscoveryDeviceEvidence(
        identity_digest=identity_digest,
        kind=device.kind,
        size_bytes=device.size_bytes,
        root_ancestor=device.root_ancestor,
        boot_ancestor=device.boot_ancestor,
        filesystem_present=device.filesystem is not None,
        mount_count=len(device.mount_points),
        parent_count=len(device.parents),
        holder_count=len(device.holders),
        signature_count=len(device.signatures),
        signature_digest=_digest_object(
            [
                {"kind": signature.kind, "value": signature.value}
                for signature in device.signatures
            ]
        ),
        ownership_marker=device.ownership_marker,
        ownership_digest=ownership_digest,
        topology_digest=_digest_object(
            {
                "holders": list(device.holders),
                "mounts": list(device.mount_points),
                "parents": list(device.parents),
            }
        ),
    )


def _terminal_state(
    evidence: DeployStorageDiscoveryEvidence, exit_code: int
) -> DeployStorageDiscoveryExecutionState:
    if exit_code == 0 and evidence.successful:
        return DeployStorageDiscoveryExecutionState.SUCCEEDED
    if exit_code == 4 or evidence.unreachable_host_count:
        return DeployStorageDiscoveryExecutionState.UNREACHABLE
    return DeployStorageDiscoveryExecutionState.FAILED


def _persist_uncertain_or_raise(
    store: DeployStorageDiscoveryExecutionStore,
    current: StoredDeployStorageDiscoveryExecution,
    state: DeployStorageDiscoveryExecutionState,
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
            "deploy storage-discovery uncertain outcome persistence failed; "
            "manual recovery required"
        ) from error


def _build_execution_report(
    execution: StoredDeployStorageDiscoveryExecution,
    evidence: StoredDeployStorageDiscoveryEvidence,
    *,
    execution_state: DeployStorageDiscoveryArtifactState,
    evidence_state: DeployStorageDiscoveryArtifactState,
) -> DeployStorageDiscoveryExecutionReport:
    if (
        execution.record.state is not DeployStorageDiscoveryExecutionState.SUCCEEDED
        or not evidence.record.successful
        or execution.record.result_digest != evidence.record.result_digest
        or execution.record.evidence_digest != evidence.record.evidence_digest
    ):
        raise StateConflictError(
            "deploy storage-discovery success evidence is incomplete"
        )
    return DeployStorageDiscoveryExecutionReport(
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
        discovered_host_count=evidence.record.discovered_host_count,
        device_count=evidence.record.device_count,
        device_set_digest=evidence.record.device_set_digest,
        manual_recovery_required=execution.record.manual_recovery_required,
        automatic_retry_allowed=execution.record.automatic_retry_allowed,
        journal_status=execution.record.binding.journal_status,
        journal_phase=execution.record.binding.journal_phase,
    )


@dataclass(frozen=True, slots=True)
class DeployPostStorageDiscoveryReconciliation:
    """Immutable effective plan after exact storage discovery."""

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
        ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_SCHEMA_VERSION
    )
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.prior_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
        ):
            raise StatePersistenceError(
                "post-storage-discovery reconciliation identity is invalid"
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
                "post-storage-discovery reconciliation summary conflicts"
            )
        for value in _reconciliation_digests(self):
            validate_digest(value, "post-storage-discovery reconciliation digest")
        if self.record_digest != _reconciliation_record_digest(self):
            raise StatePersistenceError(
                "post-storage-discovery reconciliation record digest conflicts"
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
    ) -> DeployPostStorageDiscoveryReconciliation:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "post-storage-discovery reconciliation",
        )
        integers = {
            "generation",
            "journal_generation",
            "target_count",
            "device_count",
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
            elif name == "blocker_set":
                parsed[name] = _string_tuple(value[name], name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployPostStorageDiscoveryReconciliation:
    record: DeployPostStorageDiscoveryReconciliation
    artifact_digest: str


class DeployPostStorageDiscoveryReconciliationStore:
    """Immutable owner-only post-storage-discovery store."""

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
        self._path = deploy_post_storage_discovery_reconciliation_path(
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
    ) -> StoredDeployPostStorageDiscoveryReconciliation:
        value, digest = self._file.read()
        record = DeployPostStorageDiscoveryReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "post-storage-discovery reconciliation identity conflicts"
            )
        return StoredDeployPostStorageDiscoveryReconciliation(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPostStorageDiscoveryReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployPostStorageDiscoveryReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployPostStorageDiscoveryReconciliation,
        DeployStorageDiscoveryArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "post-storage-discovery reconciliation operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "post-storage-discovery reconciliation is immutable"
                )
            return current, DeployStorageDiscoveryArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployPostStorageDiscoveryReconciliation(record, digest),
            DeployStorageDiscoveryArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployPostStorageDiscoveryReconciliationReport:
    """Strict redacted immediate-next-gate projection."""

    operation_id: uuid.UUID
    artifact_state: DeployStorageDiscoveryArtifactState
    reconciliation_artifact_digest: str
    reconciliation_record_digest: str
    effective_plan_digest: str
    target_count: int
    target_set_digest: str
    device_count: int
    device_set_digest: str
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
        ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_REPORT_SCHEMA_VERSION
            or self.reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION
            or self.target_count < 1
            or self.device_count < 0
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
                "post-storage-discovery reconciliation report is invalid"
            )
        for value in (
            self.reconciliation_artifact_digest,
            self.reconciliation_record_digest,
            self.effective_plan_digest,
            self.target_set_digest,
            self.device_set_digest,
            self.next_target_set_digest,
            self.blocker_digest,
        ):
            validate_digest(value, "post-storage-discovery report digest")

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
            "storage_discovery": {
                "device_count": self.device_count,
                "device_set_digest": self.device_set_digest,
                "status": "succeeded",
                "target_count": self.target_count,
                "target_set_digest": self.target_set_digest,
            },
        }


def reconcile_deploy_storage_discovery(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployPostStorageDiscoveryReconciliationReport:
    """Persist storage success and advance only immediate storage-preflight."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _refuse_ambiguous_artifacts(paths, operation_id)
    execution_store = DeployStorageDiscoveryExecutionStore(paths, operation_id)
    evidence_store = DeployStorageDiscoveryEvidenceStore(paths, operation_id)
    for path, label in (
        (execution_store.path, "execution"),
        (evidence_store.path, "evidence"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"post-storage-discovery reconciliation requires complete {label}"
            )
    raw_execution = execution_store.read(
        expected_cluster_uuid=_read_binding_identity(execution_store.path)[0],
        expected_cluster_name=_read_binding_identity(execution_store.path)[1],
    )
    context = _load_storage_discovery_context(
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
        execution.record.state is not DeployStorageDiscoveryExecutionState.SUCCEEDED
        or not evidence.record.successful
    ):
        raise StateConflictError(
            "post-storage-discovery reconciliation requires certain successful execution"
        )
    steps = _build_reconciled_steps(context, evidence)
    store = DeployPostStorageDiscoveryReconciliationStore(paths, operation_id)
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
            "post-storage-discovery reconciliation is immutable; use a new operation"
        )
    try:
        stored, state = store.write_locked(record, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "post-storage-discovery reconciliation persistence failed"
        ) from error
    return _build_reconciliation_report(stored, state=state)


def deploy_post_storage_discovery_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "post-storage-discovery reconciliation path is not canonical"
        )
    return path


def deploy_post_storage_discovery_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(
        name, DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_FILENAME_SUFFIX
    )


def _read_binding_identity(path: Path) -> tuple[uuid.UUID, str]:
    value, _digest = AtomicJsonFile(path).read()
    binding = _mapping(value.get("binding"), "execution binding")
    return (
        parse_uuid(require_string(binding, "cluster_uuid"), "cluster uuid"),
        require_string(binding, "cluster_name"),
    )


def _build_reconciled_steps(
    context: _StorageDiscoveryContext,
    evidence: StoredDeployStorageDiscoveryEvidence,
) -> tuple[DeployBaseOsReconciledStep, ...]:
    prior_steps = context.reconciliation.record.steps
    remaining_mappings = tuple(
        sorted(
            {
                step.mapping_sequence
                for step in prior_steps
                if step.mapping_sequence > _MAPPING_SEQUENCE
                and step.mapping_sequence != _FINAL_EVIDENCE_MAPPING
                and step.condition_state is DeployConditionState.ACTIVE
                and step.status is not DeployBaseOsReconciledStepStatus.SUCCEEDED
            }
        )
    )
    next_mapping = remaining_mappings[0] if remaining_mappings else None
    result: list[DeployBaseOsReconciledStep] = []
    for prior in prior_steps:
        prior_digest = _digest_object(prior.to_object())
        if prior.mapping_sequence == _MAPPING_SEQUENCE:
            if (
                prior.playbook != _PLAYBOOK
                or prior.status is not DeployBaseOsReconciledStepStatus.ELIGIBLE
                or prior.sequence != context.scope.step.sequence
            ):
                raise StateConflictError(
                    "post-storage-discovery executed step identity drifted"
                )
            result.append(
                replace(
                    prior,
                    prior_reconciled_step_digest=prior_digest,
                    status=DeployBaseOsReconciledStepStatus.SUCCEEDED,
                    evidence_state=(
                        DeployBaseOsReconciledEvidenceState.STORAGE_DISCOVERY_BOUND
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
        if prior.mapping_sequence == next_mapping and _next_gate_ready(
            prior, context, evidence
        ):
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
                    evidence_digest=_next_gate_digest(prior, context, evidence),
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
    context: _StorageDiscoveryContext,
    evidence: StoredDeployStorageDiscoveryEvidence,
) -> bool:
    definition = get_playbook(step.playbook)
    return (
        step.playbook == _NEXT_PLAYBOOK
        and step.target_role == HostRole.SCYLLA.value
        and step.target_ids == context.scope.targets
        and step.target_digest == context.binding.target_set_digest
        and step.classification is OperationClassification.READ_ONLY
        and definition.classification is OperationClassification.READ_ONLY
        and definition.source_available
        and definition.serial == 5
        and definition.check_mode is CheckMode.SUPPORTED
        and evidence.record.successful
        and evidence.record.discovered_host_count == context.binding.target_count
    )


def _next_gate_digest(
    step: DeployBaseOsReconciledStep,
    context: _StorageDiscoveryContext,
    evidence: StoredDeployStorageDiscoveryEvidence,
) -> str:
    return _digest_object(
        {
            "evidence_artifact_digest": evidence.artifact_digest,
            "evidence_digest": evidence.record.evidence_digest,
            "inventory_artifact_digest": context.binding.inventory_artifact_digest,
            "playbook": step.playbook,
            "prior_reconciliation_artifact_digest": (
                context.reconciliation.artifact_digest
            ),
            "readiness_record_digest": context.binding.readiness_record_digest,
            "sequence": step.sequence,
            "target_digest": step.target_digest,
            "trust_artifact_digest": context.binding.trust_artifact_digest,
        }
    )


def _build_reconciliation_record(
    context: _StorageDiscoveryContext,
    execution: StoredDeployStorageDiscoveryExecution,
    evidence: StoredDeployStorageDiscoveryEvidence,
    *,
    steps: tuple[DeployBaseOsReconciledStep, ...],
    created_at: str,
) -> DeployPostStorageDiscoveryReconciliation:
    binding = execution.record.binding
    counts = Counter(step.status for step in steps)
    blockers = tuple(sorted({item for step in steps for item in step.blockers}))
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
    return DeployPostStorageDiscoveryReconciliation(**values)  # type: ignore[arg-type]


def _build_reconciliation_report(
    stored: StoredDeployPostStorageDiscoveryReconciliation,
    *,
    state: DeployStorageDiscoveryArtifactState,
) -> DeployPostStorageDiscoveryReconciliationReport:
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
    return DeployPostStorageDiscoveryReconciliationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        reconciliation_artifact_digest=stored.artifact_digest,
        reconciliation_record_digest=record.record_digest,
        effective_plan_digest=record.effective_plan_digest,
        target_count=record.target_count,
        target_set_digest=record.target_set_digest,
        device_count=record.device_count,
        device_set_digest=record.device_set_digest,
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
    hosts: tuple[DeployStorageDiscoveryHostEvidence, ...],
) -> str:
    return _digest_object(
        {
            "hosts": [host.to_object() for host in hosts],
            "schema_version": STORAGE_DISCOVERY_SCHEMA_VERSION,
        }
    )


def _semantic_evidence_digest(
    binding: DeployStorageDiscoveryExecutionBinding,
    result_digest: str,
    device_set_digest: str,
) -> str:
    return _digest_object(
        {
            "command_digest": binding.command_digest,
            "device_set_digest": device_set_digest,
            "playbook_source_digest": binding.playbook_source_digest,
            "result_digest": result_digest,
            "runtime_variables_digest": binding.runtime_variables_digest,
            "step_digest": binding.step_digest,
            "target_set_digest": binding.target_set_digest,
        }
    )


def _failure_state(error: AnsibleError) -> DeployStorageDiscoveryExecutionState:
    if isinstance(error, AnsibleResultError):
        return DeployStorageDiscoveryExecutionState.MALFORMED_RESULT
    cause = error.__cause__
    if isinstance(cause, ProcessTimeoutError):
        return DeployStorageDiscoveryExecutionState.TIMED_OUT
    if isinstance(cause, ProcessOutputError):
        return DeployStorageDiscoveryExecutionState.MALFORMED_RESULT
    return DeployStorageDiscoveryExecutionState.FAILED


def _binding_digests(
    binding: DeployStorageDiscoveryExecutionBinding,
) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(binding, name))
        for name in binding.__dataclass_fields__
        if name.endswith("_digest")
    )


def _binding_digest(binding: DeployStorageDiscoveryExecutionBinding) -> str:
    value = binding.to_object()
    value["binding_digest"] = ""
    return _digest_object(value)


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployStorageDiscoveryExecutionBinding.__dataclass_fields__.items():
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
    record: DeployPostStorageDiscoveryReconciliation,
) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(record, name))
        for name in record.__dataclass_fields__
        if name.endswith("_digest")
    )


def _reconciliation_record_digest(
    record: DeployPostStorageDiscoveryReconciliation,
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
    ) in DeployPostStorageDiscoveryReconciliation.__dataclass_fields__.items():
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


def _timestamp() -> str:
    return format_timestamp(datetime.now(UTC))


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError("deploy storage-discovery paths are not canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy storage-discovery requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy storage-discovery artifacts"
        ) from error
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_STORAGE_DISCOVERY_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_STORAGE_DISCOVERY_EVIDENCE_FILENAME_SUFFIX,
        DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_FILENAME_SUFFIX,
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
            raise StateConflictError("deploy storage-discovery artifacts are ambiguous")


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
    "ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION",
    "DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_FILENAME_SUFFIX",
    "DEPLOY_STORAGE_DISCOVERY_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_STORAGE_DISCOVERY_EXECUTION_FILENAME_SUFFIX",
    "DeployPostStorageDiscoveryReconciliation",
    "DeployPostStorageDiscoveryReconciliationReport",
    "DeployPostStorageDiscoveryReconciliationStore",
    "DeployStorageDiscoveryArtifactState",
    "DeployStorageDiscoveryEvidence",
    "DeployStorageDiscoveryEvidenceStore",
    "DeployStorageDiscoveryExecution",
    "DeployStorageDiscoveryExecutionReport",
    "DeployStorageDiscoveryExecutionState",
    "DeployStorageDiscoveryExecutionStore",
    "StoredDeployPostStorageDiscoveryReconciliation",
    "StoredDeployStorageDiscoveryEvidence",
    "StoredDeployStorageDiscoveryExecution",
    "deploy_post_storage_discovery_reconciliation_id_from_filename",
    "deploy_post_storage_discovery_reconciliation_path",
    "deploy_storage_discovery_evidence_id_from_filename",
    "deploy_storage_discovery_evidence_path",
    "deploy_storage_discovery_execution_id_from_filename",
    "deploy_storage_discovery_execution_path",
    "execute_deploy_storage_discovery",
    "reconcile_deploy_storage_discovery",
]
