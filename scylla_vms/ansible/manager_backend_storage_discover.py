"""Strict Manager-only read-only discovery for one dedicated backend volume."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from scylla_vms.ansible.deploy_manager_backend_storage_allocation_plan import (
    DeployManagerBackendStorageAllocationPlanStatus,
    DeployManagerBackendStorageAllocationState,
    DeployManagerBackendStorageGuestIdentityState,
    StoredDeployManagerBackendStorageAllocationContext,
    StoredDeployManagerBackendStorageAllocationPlan,
    _derive_allocation_decision,
)
from scylla_vms.ansible.deploy_plan import _playbook_source_digest
from scylla_vms.ansible.orchestration import ansible_operation_catalog_digest
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.registry import get_playbook
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.desired import HostRole, StorageBackend
from scylla_vms.errors import AnsibleError, StateConflictError, StatePersistenceError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata, validate_digest
from scylla_vms.terraform.inputs import StoredTerraformInput
from scylla_vms.terraform.outputs import StorageDeviceKind

MANAGER_BACKEND_STORAGE_DISCOVERY_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-manager-backend-storage-discovery/v1"
)
MANAGER_BACKEND_STORAGE_DISCOVERY_NOT_PERFORMED = (
    "cql-access",
    "filesystem-creation",
    "fstab-write",
    "manager-configuration",
    "mount",
    "partition",
    "raid-creation",
    "service-mutation",
    "service-start",
    "storage-configuration",
    "storage-write",
    "wipe",
)

_PLAYBOOK = "manager-backend-storage-discover"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MARKER = re.compile(
    r"DSV_MANAGER_BACKEND_STORAGE_DISCOVERY_B64="
    r"(?P<data>[A-Za-z0-9+/]+={0,2})"
)
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+"
    r"unreachable=(?P<unreachable>\d+)\s+failed=(?P<failed>\d+)\s+"
    r"skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_BLOCKERS = frozenset(
    {
        "ambiguous-device-match",
        "device-held",
        "device-mounted",
        "device-not-found",
        "device-type-mismatch",
        "discovery-failed",
        "manifest-conflict",
        "ownership-conflict",
        "root-or-boot-device",
        "signature-present",
        "size-mismatch",
    }
)


class ManagerBackendStorageDiscoveryStatus(StrEnum):
    DISCOVERED = "discovered"
    BLOCKED = "blocked"
    FAILED = "failed"


class ManagerBackendStorageSignatureStatus(StrEnum):
    ABSENT = "absent"
    PRESENT = "present"
    UNKNOWN = "unknown"


class ManagerBackendStorageOwnershipStatus(StrEnum):
    UNOWNED = "unowned"
    MANAGER_OWNED = "manager-owned"
    FOREIGN = "foreign"
    UNKNOWN = "unknown"


class ManagerBackendStorageMountStatus(StrEnum):
    UNMOUNTED = "unmounted"
    MOUNTED = "mounted"
    UNKNOWN = "unknown"


class ManagerBackendStorageRootStatus(StrEnum):
    EXCLUDED = "excluded"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ManagerBackendStorageDiscoveryEvidence:
    """Bounded address-free evidence; this does not prove capacity adequacy."""

    logical_id: str
    role: str
    status: ManagerBackendStorageDiscoveryStatus
    backend_type: str
    device_type: str
    device_count: int
    total_size_gib: int
    signature_status: ManagerBackendStorageSignatureStatus
    ownership_status: ManagerBackendStorageOwnershipStatus
    mount_status: ManagerBackendStorageMountStatus
    root_status: ManagerBackendStorageRootStatus
    device_set_digest: str
    topology_digest: str
    manifest_digest: str
    provenance: tuple[tuple[str, str], ...]
    not_performed: tuple[str, ...]
    blockers: tuple[str, ...]
    capacity_policy_state: str
    capacity_evaluation_state: str
    schema_version: str = MANAGER_BACKEND_STORAGE_DISCOVERY_SCHEMA_VERSION


def build_manager_backend_storage_discovery_payload(
    metadata: ClusterMetadata,
    terraform_input: StoredTerraformInput,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    context: StoredDeployManagerBackendStorageAllocationContext,
    plan: StoredDeployManagerBackendStorageAllocationPlan,
    *,
    logical_id: str,
) -> dict[str, object]:
    """Rebuild one exact Manager-volume discovery request from canonical state."""

    if _LOGICAL_ID.fullmatch(logical_id) is None:
        raise StateConflictError("Manager backend storage discovery target is invalid")
    context_record = context.record
    plan_record = plan.record
    source = load_ansible_source_bundle()
    definition = get_playbook(_PLAYBOOK)
    current_allocation = _derive_allocation_decision(
        metadata.desired_spec,
        terraform_input,
        observed,
        inventory,
        logical_id,
    )
    manager_hosts = tuple(
        host
        for host in observed.record.manifest.hosts
        if host.logical_id == logical_id and host.role is HostRole.MANAGER
    )
    inventory_hosts = tuple(
        host
        for host in inventory.record.inventory.hosts
        if host.logical_id == logical_id and host.role is HostRole.MANAGER
    )
    if len(manager_hosts) != 1 or len(inventory_hosts) != 1:
        raise StateConflictError(
            "Manager backend storage discovery requires one exact Manager target"
        )
    host = manager_hosts[0]
    inventory_host = inventory_hosts[0]
    storage = host.storage
    if len(storage.devices) != 1:
        raise StateConflictError(
            "Manager backend storage discovery manifest is ambiguous"
        )
    device = storage.devices[0]
    guest_identities = {
        "expected_by_id": device.expected_by_id,
        "expected_serial": device.expected_serial,
        "expected_wwn": device.expected_wwn,
    }
    if (
        context_record.manager_target_id != logical_id
        or plan_record.manager_target_id != logical_id
        or plan_record.discovery_target_ids != (logical_id,)
        or plan_record.status
        is not DeployManagerBackendStorageAllocationPlanStatus.ELIGIBLE
        or plan_record.allocation_state
        is not DeployManagerBackendStorageAllocationState.EXACT
        or plan_record.guest_identity_state
        is not DeployManagerBackendStorageGuestIdentityState.AVAILABLE
        or current_allocation != context_record.allocation
        or current_allocation.provider_allocation_identity_digest
        != plan_record.provider_allocation_identity_digest
        or current_allocation.guest_identity_set_digest
        != plan_record.guest_identity_set_digest
        or not any(value is not None for value in guest_identities.values())
        or metadata.cluster_uuid != context_record.cluster_uuid
        or metadata.cluster_name != context_record.cluster_name
        or metadata.generation != context_record.metadata_generation
        or metadata.desired_spec.digest() != context_record.desired_spec_digest
        or terraform_input.record.generation
        != context_record.terraform_input_generation
        or terraform_input.digest != context_record.terraform_input_artifact_digest
        or terraform_input.record.input_digest != context_record.terraform_input_digest
        or observed.record.generation != context_record.observation_generation
        or observed.digest != context_record.observation_artifact_digest
        or observed.record.manifest_digest != context_record.observation_manifest_digest
        or inventory.record.generation != context_record.inventory_generation
        or inventory.digest != context_record.inventory_artifact_digest
        or inventory.record.inventory_digest != context_record.inventory_digest
        or readiness.observation_generation != observed.record.generation
        or readiness.observation_digest != observed.record.manifest_digest
        or readiness.inventory_generation != inventory.record.generation
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_generation != context_record.trust_generation
        or readiness.trust_digest != context_record.trust_artifact_digest
        or source.version != context_record.ansible_source_version
        or source.digest != context_record.ansible_source_digest
        or ansible_operation_catalog_digest() != context_record.catalog_digest
        or plan_record.context_artifact_digest != context.artifact_digest
        or plan_record.context_record_digest != context_record.record_digest
        or plan_record.source_digest != _playbook_source_digest(source, _PLAYBOOK)
        or not definition.source_available
        or host.provider_id != inventory_host.provider_id
        or inventory_host.selected_storage_backend != StorageBackend.BLOCK_VOLUME.value
        or inventory_host.storage_device_count != 1
        or inventory_host.storage_raw_gib != current_allocation.size_gib
        or inventory_host.storage_generation != storage.storage_generation
        or inventory_host.storage_policy_digest != storage.policy_digest
        or device.kind is not StorageDeviceKind.BLOCK_VOLUME
        or device.ephemeral
    ):
        raise StateConflictError(
            "Manager backend storage discovery canonical provenance conflicts"
        )

    provenance = {
        "allocation_context_artifact_digest": context.artifact_digest,
        "allocation_context_record_digest": context_record.record_digest,
        "allocation_decision_digest": current_allocation.decision_digest,
        "allocation_plan_artifact_digest": plan.artifact_digest,
        "allocation_plan_digest": plan_record.plan_digest,
        "ansible_source_digest": source.digest,
        "catalog_digest": context_record.catalog_digest,
        "inventory_digest": inventory.digest,
        "observation_digest": observed.digest,
        "playbook_source_digest": plan_record.source_digest,
        "terraform_input_digest": terraform_input.digest,
        "trust_digest": readiness.trust_digest,
    }
    return {
        "backend_type": StorageBackend.BLOCK_VOLUME.value,
        "capacity_evaluation_state": "not-evaluated",
        "capacity_policy_state": "unknown",
        "expected_device_count": 1,
        "expected_size_gib": current_allocation.size_gib,
        "guest_identity_set_digest": current_allocation.guest_identity_set_digest,
        "guest_identities": guest_identities,
        "logical_id": logical_id,
        "manifest_digest": current_allocation.observed_manifest_digest,
        "not_performed": list(MANAGER_BACKEND_STORAGE_DISCOVERY_NOT_PERFORMED),
        "provenance": provenance,
        "role": "manager",
        "schema_version": MANAGER_BACKEND_STORAGE_DISCOVERY_SCHEMA_VERSION,
        "storage_generation": current_allocation.storage_generation,
        "storage_policy_digest": storage.policy_digest,
    }


def parse_manager_backend_storage_discovery_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> ManagerBackendStorageDiscoveryEvidence:
    """Parse one strict normalized marker and one exact recap row."""

    if len(stdout.encode("utf-8")) > 256 * 1024:
        raise AnsibleError(
            "Ansible Manager backend storage discovery output is too large"
        )
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_MANAGER_BACKEND_STORAGE_DISCOVERY_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError(
                "Ansible Manager backend storage discovery marker is malformed"
            )
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"), object_pairs_hook=_strict_object
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible Manager backend storage discovery marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError(
                "Ansible Manager backend storage discovery evidence is invalid"
            )
        values.append(value)

    _before, separator, after = stdout.partition("PLAY RECAP")
    if not separator:
        raise AnsibleError(
            "Ansible Manager backend storage discovery omitted PLAY RECAP"
        )
    rows: dict[str, tuple[int, int, int]] = {}
    for line in after.splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError(
                "Ansible Manager backend storage discovery recap is malformed"
            )
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    logical_id = _text(expected_payload["logical_id"])
    if set(rows) != {logical_id}:
        raise AnsibleError(
            "Ansible Manager backend storage discovery recap membership conflicts"
        )
    changed, unreachable, failed = rows[logical_id]
    recap_failed = bool(unreachable or failed)
    if changed:
        raise AnsibleError(
            "Ansible Manager backend storage discovery reported a mutation"
        )
    if not values:
        if not recap_failed or exit_code == 0:
            raise AnsibleError(
                "Ansible Manager backend storage discovery evidence is incomplete"
            )
        return _failed_evidence(expected_payload)
    if len(values) != 1:
        raise AnsibleError(
            "Ansible Manager backend storage discovery evidence is duplicated"
        )
    evidence = _parse_result(values[0], expected_payload)
    result_failed = evidence.status is ManagerBackendStorageDiscoveryStatus.FAILED
    if recap_failed != result_failed or (exit_code == 0) == result_failed:
        raise AnsibleError(
            "Ansible Manager backend storage discovery exit status conflicts"
        )
    return evidence


def _parse_result(
    value: dict[str, object],
    expected: dict[str, object],
) -> ManagerBackendStorageDiscoveryEvidence:
    fields = {
        "backend_type",
        "blockers",
        "capacity_evaluation_state",
        "capacity_policy_state",
        "device_count",
        "device_set_digest",
        "device_type",
        "logical_id",
        "manifest_digest",
        "mount_status",
        "not_performed",
        "ownership_status",
        "provenance",
        "role",
        "root_status",
        "schema_version",
        "signature_status",
        "status",
        "topology_digest",
        "total_size_gib",
    }
    if (
        set(value) != fields
        or value.get("schema_version")
        != MANAGER_BACKEND_STORAGE_DISCOVERY_SCHEMA_VERSION
    ):
        raise AnsibleError(
            "Ansible Manager backend storage discovery schema is invalid"
        )
    if (
        value["logical_id"] != expected["logical_id"]
        or value["role"] != "manager"
        or value["backend_type"] != StorageBackend.BLOCK_VOLUME.value
        or value["manifest_digest"] != expected["manifest_digest"]
        or value["capacity_policy_state"] != "unknown"
        or value["capacity_evaluation_state"] != "not-evaluated"
        or value["not_performed"] != expected["not_performed"]
        or value["provenance"] != expected["provenance"]
    ):
        raise AnsibleError(
            "Ansible Manager backend storage discovery evidence conflicts"
        )
    try:
        status = ManagerBackendStorageDiscoveryStatus(_text(value["status"]))
        signature = ManagerBackendStorageSignatureStatus(
            _text(value["signature_status"])
        )
        ownership = ManagerBackendStorageOwnershipStatus(
            _text(value["ownership_status"])
        )
        mount = ManagerBackendStorageMountStatus(_text(value["mount_status"]))
        root = ManagerBackendStorageRootStatus(_text(value["root_status"]))
    except ValueError as error:
        raise AnsibleError(
            "Ansible Manager backend storage discovery enum is invalid"
        ) from error
    device_count = _bounded_integer(value["device_count"], 0, 16, "device count")
    total_size = _bounded_integer(
        value["total_size_gib"], 0, 1024 * 1024, "storage size"
    )
    device_type = _choice(value["device_type"], {"disk", "unknown"}, "device type")
    blockers = _sorted_choices(value["blockers"], _BLOCKERS, "storage blockers")
    provenance = _digest_mapping(value["provenance"], "storage provenance")
    not_performed = _sorted_strings(value["not_performed"], "not performed")
    device_set_digest = _digest(value["device_set_digest"])
    topology_digest = _digest(value["topology_digest"])
    manifest_digest = _digest(value["manifest_digest"])
    if (
        tuple(provenance)
        != tuple(sorted(cast(dict[str, str], expected["provenance"]).items()))
        or not_performed != tuple(cast(list[str], expected["not_performed"]))
        or manifest_digest != expected["manifest_digest"]
    ):
        raise AnsibleError(
            "Ansible Manager backend storage discovery provenance conflicts"
        )
    if status is ManagerBackendStorageDiscoveryStatus.DISCOVERED:
        valid = (
            not blockers
            and device_count == 1
            and total_size == expected["expected_size_gib"]
            and device_type == "disk"
            and signature is ManagerBackendStorageSignatureStatus.ABSENT
            and ownership
            in {
                ManagerBackendStorageOwnershipStatus.UNOWNED,
                ManagerBackendStorageOwnershipStatus.MANAGER_OWNED,
            }
            and mount is ManagerBackendStorageMountStatus.UNMOUNTED
            and root is ManagerBackendStorageRootStatus.EXCLUDED
        )
    elif status is ManagerBackendStorageDiscoveryStatus.FAILED:
        valid = blockers == ("discovery-failed",) and device_count == 0
    else:
        valid = bool(blockers)
    if not valid:
        raise AnsibleError("Ansible Manager backend storage discovery status conflicts")
    return ManagerBackendStorageDiscoveryEvidence(
        logical_id=_text(value["logical_id"]),
        role="manager",
        status=status,
        backend_type=StorageBackend.BLOCK_VOLUME.value,
        device_type=device_type,
        device_count=device_count,
        total_size_gib=total_size,
        signature_status=signature,
        ownership_status=ownership,
        mount_status=mount,
        root_status=root,
        device_set_digest=device_set_digest,
        topology_digest=topology_digest,
        manifest_digest=manifest_digest,
        provenance=provenance,
        not_performed=not_performed,
        blockers=blockers,
        capacity_policy_state="unknown",
        capacity_evaluation_state="not-evaluated",
    )


def _failed_evidence(
    expected: dict[str, object],
) -> ManagerBackendStorageDiscoveryEvidence:
    return ManagerBackendStorageDiscoveryEvidence(
        logical_id=_text(expected["logical_id"]),
        role="manager",
        status=ManagerBackendStorageDiscoveryStatus.FAILED,
        backend_type=StorageBackend.BLOCK_VOLUME.value,
        device_type="unknown",
        device_count=0,
        total_size_gib=0,
        signature_status=ManagerBackendStorageSignatureStatus.UNKNOWN,
        ownership_status=ManagerBackendStorageOwnershipStatus.UNKNOWN,
        mount_status=ManagerBackendStorageMountStatus.UNKNOWN,
        root_status=ManagerBackendStorageRootStatus.UNKNOWN,
        device_set_digest=_object_digest([]),
        topology_digest=_object_digest({"state": "unavailable"}),
        manifest_digest=_digest(expected["manifest_digest"]),
        provenance=tuple(sorted(cast(dict[str, str], expected["provenance"]).items())),
        not_performed=tuple(cast(list[str], expected["not_performed"])),
        blockers=("discovery-failed",),
        capacity_policy_state="unknown",
        capacity_evaluation_state="not-evaluated",
    )


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str):
        raise AnsibleError("Ansible Manager backend storage digest is invalid")
    try:
        validate_digest(value, "Manager backend storage digest")
    except StatePersistenceError as error:
        raise AnsibleError(
            "Ansible Manager backend storage digest is invalid"
        ) from error
    return value


def _digest_mapping(
    value: object,
    label: str,
) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    ):
        raise AnsibleError(f"Ansible Manager backend {label} is invalid")
    result = tuple(sorted(cast(dict[str, str], value).items()))
    if not result:
        raise AnsibleError(f"Ansible Manager backend {label} is empty")
    for _key, item in result:
        _digest(item)
    return result


def _sorted_choices(
    value: object,
    choices: frozenset[str],
    label: str,
) -> tuple[str, ...]:
    values = _sorted_strings(value, label)
    if any(item not in choices for item in values):
        raise AnsibleError(f"Ansible Manager backend {label} is invalid")
    return values


def _sorted_strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise AnsibleError(f"Ansible Manager backend {label} is invalid")
    result = tuple(cast(list[str], value))
    if result != tuple(sorted(set(result))):
        raise AnsibleError(f"Ansible Manager backend {label} is not canonical")
    return result


def _bounded_integer(value: object, minimum: int, maximum: int, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise AnsibleError(f"Ansible Manager backend {label} is invalid")
    return value


def _choice(value: object, choices: set[str], label: str) -> str:
    text = _text(value)
    if text not in choices:
        raise AnsibleError(f"Ansible Manager backend {label} is invalid")
    return text


def _text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise AnsibleError("Ansible Manager backend storage text is invalid")
    return value


def _object_digest(value: object) -> str:
    data = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(data).hexdigest()}"
