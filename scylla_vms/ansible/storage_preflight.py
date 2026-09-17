"""Deterministic, read-only storage-manifest reconciliation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from scylla_vms.ansible.storage import (
    StorageDeviceEvidence,
    StorageDiscoveryEvidence,
    StorageHostEvidence,
)
from scylla_vms.desired import HostRole, StorageBackend, StoragePolicy
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata
from scylla_vms.terraform.outputs import (
    StorageDevice,
    StorageDeviceKind,
    StorageManifest,
    TerraformHost,
)

STORAGE_PREFLIGHT_SCHEMA_VERSION = "deploy-scylla-vms.ansible-storage-preflight/v1"
_GIB = 1024**3
_REQUIRED_TOOLS = frozenset(
    {"blkid", "by-id", "findmnt", "lsblk", "lvm", "md", "wipefs"}
)
_MARKER = re.compile(
    r'DSV_STORAGE_PREFLIGHT_B64=(?P<data>[A-Za-z0-9+/]+={0,2})"(?:\})?\s*$'
)


class StorageOwnershipStatus(StrEnum):
    CLEAN_NEW = "clean-new"
    OWNED_NOOP = "owned-noop"
    WIPE_REVIEW_REQUIRED = "wipe-review-required"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class SelectedStorageDevice:
    identity: str
    capacity_bytes: int
    stable_id: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class StorageHostPreflight:
    logical_id: str
    backend: str
    layout: str
    capacity_bytes: int
    ownership_status: StorageOwnershipStatus
    blockers: tuple[str, ...]
    wipe_required: bool
    preparation_intent_digest: str
    devices: tuple[SelectedStorageDevice, ...]
    schema_version: str = STORAGE_PREFLIGHT_SCHEMA_VERSION

    @property
    def ready(self) -> bool:
        return not self.blockers and not self.wipe_required

    def to_object(self) -> dict[str, object]:
        return {
            "backend": self.backend,
            "blockers": list(self.blockers),
            "capacity_bytes": self.capacity_bytes,
            "devices": [
                {"capacity_bytes": item.capacity_bytes, "identity": item.identity}
                for item in self.devices
            ],
            "layout": self.layout,
            "logical_id": self.logical_id,
            "ownership_status": self.ownership_status.value,
            "preparation_intent_digest": self.preparation_intent_digest,
            "ready": self.ready,
            "schema_version": self.schema_version,
            "wipe_required": self.wipe_required,
        }


@dataclass(frozen=True, slots=True)
class StoragePreflightResult:
    hosts: tuple[StorageHostPreflight, ...]
    schema_version: str = STORAGE_PREFLIGHT_SCHEMA_VERSION

    def to_object(self) -> dict[str, object]:
        return {
            "hosts": [host.to_object() for host in self.hosts],
            "schema_version": self.schema_version,
        }


def parse_storage_preflight_execution(
    stdout: str,
    expected: StoragePreflightResult,
    exit_code: int,
) -> StoragePreflightResult:
    """Validate that Ansible returned only the exact controller projection."""

    expected_objects = {host.logical_id: host.to_object() for host in expected.hosts}
    parse_storage_preflight_projection(stdout, expected_objects, exit_code)
    return expected


def parse_storage_preflight_projection(
    stdout: str,
    expected_objects: Mapping[str, object],
    exit_code: int,
) -> dict[str, object]:
    """Validate the exact public controller projection used by an operation step."""

    if not expected_objects or not all(
        isinstance(key, str) and isinstance(value, dict)
        for key, value in expected_objects.items()
    ):
        raise AnsibleError("Ansible storage preflight expectation is malformed")
    if len(stdout.encode("utf-8")) > 2 * 1024 * 1024:
        raise AnsibleError(
            "Ansible storage preflight output exceeds the evidence limit"
        )
    markers: dict[str, object] = {}
    for line in stdout.splitlines():
        if "DSV_STORAGE_PREFLIGHT_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible storage preflight marker is malformed")
        try:
            raw = base64.b64decode(match.group("data"), validate=True)
            if len(raw) > 256 * 1024:
                raise AnsibleError("Ansible storage preflight marker is oversized")
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_strict_preflight_object,
                parse_constant=_reject_preflight_constant,
            )
        except (binascii.Error, RecursionError, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible storage preflight marker is malformed"
            ) from error
        if not isinstance(value, dict) or not isinstance(value.get("logical_id"), str):
            raise AnsibleError("Ansible storage preflight result is malformed")
        logical_id = value["logical_id"]
        if logical_id in markers:
            raise AnsibleError("Ansible storage preflight result is duplicated")
        markers[logical_id] = value
    if markers != expected_objects:
        raise AnsibleError("Ansible storage preflight result conflicts")
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible storage preflight output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    pattern = re.compile(
        r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
        r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
        r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
    )
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = pattern.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible storage preflight recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    if (
        set(rows) != set(expected_objects)
        or any(
            changed or unreachable or failed
            for changed, unreachable, failed in rows.values()
        )
        or exit_code != 0
    ):
        raise AnsibleError("Ansible storage preflight execution is incomplete")
    return dict(expected_objects)


def _strict_preflight_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AnsibleError("Ansible storage preflight contains duplicate fields")
        result[key] = value
    return result


def _reject_preflight_constant(value: str) -> None:
    raise AnsibleError(f"invalid storage preflight constant: {value}")


def reconcile_storage_preflight(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    discovery: StorageDiscoveryEvidence,
    expected_hosts: tuple[str, ...],
) -> StoragePreflightResult:
    """Reconcile exact persisted policy, Terraform manifest, and guest evidence."""

    expected = tuple(sorted(expected_hosts))
    if not expected or expected != tuple(sorted(set(expected))):
        raise AnsibleError("storage preflight host membership is invalid")
    if discovery.unavailable_hosts:
        raise AnsibleError("storage preflight discovery is incomplete")
    if (
        observed.record.cluster_uuid != metadata.cluster_uuid
        or observed.record.cluster_name != metadata.cluster_name
        or observed.record.provider != metadata.provider
        or observed.record.generation != inventory.record.source_manifest_generation
        or observed.record.manifest_digest != inventory.record.source_manifest_digest
    ):
        raise StateConflictError("storage preflight persisted provenance conflicts")

    manifest_hosts = {host.logical_id: host for host in observed.record.manifest.hosts}
    discovery_hosts = {host.logical_id: host for host in discovery.hosts}
    inventory_hosts = {
        host.logical_id: host for host in inventory.record.inventory.hosts
    }
    if set(expected) != set(discovery_hosts):
        raise AnsibleError("storage preflight discovery membership conflicts")
    policies = {policy.role: policy for policy in metadata.desired_spec.storage}
    results: list[StorageHostPreflight] = []
    for logical_id in expected:
        manifest_host = manifest_hosts.get(logical_id)
        inventory_host = inventory_hosts.get(logical_id)
        if (
            manifest_host is None
            or inventory_host is None
            or manifest_host.role is not HostRole.SCYLLA
            or inventory_host.role is not HostRole.SCYLLA
        ):
            raise StateConflictError("storage preflight requires exact Scylla host IDs")
        if (
            inventory_host.selected_storage_backend
            != manifest_host.storage.selected_backend.value
            or inventory_host.storage_device_count
            != manifest_host.storage.expected_device_count
            or inventory_host.storage_raw_gib != manifest_host.storage.raw_total_gib
            or inventory_host.storage_usable_gib
            != manifest_host.storage.usable_total_gib
            or inventory_host.storage_generation
            != manifest_host.storage.storage_generation
            or inventory_host.storage_policy_digest
            != manifest_host.storage.policy_digest
        ):
            raise StateConflictError("storage preflight inventory manifest conflicts")
        policy = policies.get(HostRole.SCYLLA)
        if policy is None:
            raise StateConflictError("persisted Scylla storage policy is unavailable")
        _validate_policy(policy, manifest_host.storage)
        results.append(
            _reconcile_host(
                metadata,
                observed,
                inventory,
                manifest_host,
                discovery_hosts[logical_id],
            )
        )
    return StoragePreflightResult(tuple(results))


def _validate_policy(policy: StoragePolicy, manifest: StorageManifest) -> None:
    if (
        policy.requested_backend is not manifest.requested_backend
        or policy.layout is None
        or policy.layout.value != manifest.layout
    ):
        raise StateConflictError("storage preflight policy and backend conflict")
    if manifest.selected_backend is StorageBackend.BLOCK_VOLUME:
        block = policy.block_volume
        if (
            block is None
            or block.count != manifest.expected_device_count
            or any(device.size_gib != block.size_gib for device in manifest.devices)
        ):
            raise StateConflictError("storage preflight block-volume policy conflicts")
    elif manifest.selected_backend is StorageBackend.LOCAL_NVME:
        if (
            policy.local_min_device_count is None
            or policy.local_min_total_gib is None
            or manifest.expected_device_count < policy.local_min_device_count
            or manifest.raw_total_gib < policy.local_min_total_gib
        ):
            raise StateConflictError("storage preflight local-NVMe policy conflicts")
    else:
        raise StateConflictError("storage preflight backend is unsupported")


def _reconcile_host(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    manifest_host: TerraformHost,
    evidence: StorageHostEvidence,
) -> StorageHostPreflight:
    manifest = manifest_host.storage
    blockers: set[str] = set()
    tools = dict(evidence.tools)
    required_tools = set(_REQUIRED_TOOLS)
    if manifest.selected_backend is StorageBackend.LOCAL_NVME:
        required_tools.add("nvme")
    if any(tools.get(name) != "available" for name in required_tools):
        blockers.add("required-discovery-evidence-unavailable")
    if (
        evidence.host_manifest_digest != observed.record.manifest_digest
        or evidence.storage_policy_digest != manifest.policy_digest
        or evidence.storage_generation != manifest.storage_generation
        or evidence.provider_id != manifest_host.provider_id
    ):
        blockers.add("manifest-or-policy-provenance-conflict")

    selected = (
        _map_block_devices(manifest, evidence.devices, blockers)
        if manifest.selected_backend is StorageBackend.BLOCK_VOLUME
        else _map_local_devices(manifest, evidence.devices, blockers)
    )
    if len(selected) != manifest.expected_device_count:
        blockers.add("device-count-conflict")
    capacity = sum(device.size_bytes for device in selected)
    if capacity < manifest.usable_total_gib * _GIB:
        blockers.add("device-capacity-conflict")
    for device in selected:
        if device.root_ancestor or device.boot_ancestor:
            blockers.add("root-or-boot-device-conflict")
        if device.ownership_marker == "unavailable":
            blockers.add("ownership-evidence-unavailable")
        if device.ownership_marker != "present" and (
            device.mount_points or device.holders
        ):
            blockers.add("mounted-or-active-storage-conflict")

    intent = _intent_digest(
        metadata,
        observed,
        inventory,
        manifest_host,
        evidence,
        selected,
    )
    ownership = _ownership_status(
        metadata,
        manifest_host,
        selected,
        intent,
        blockers,
    )
    public_devices = tuple(
        SelectedStorageDevice(
            "device-sha256:"
            + hashlib.sha256(device.stable_id.encode("utf-8")).hexdigest(),
            device.size_bytes,
            device.stable_id,
        )
        for device in sorted(selected, key=lambda item: item.stable_id)
    )
    if blockers:
        ownership = StorageOwnershipStatus.BLOCKED
    wipe_required = ownership is StorageOwnershipStatus.WIPE_REVIEW_REQUIRED
    return StorageHostPreflight(
        evidence.logical_id,
        manifest.selected_backend.value,
        manifest.layout or "",
        capacity,
        ownership,
        tuple(sorted(blockers)),
        wipe_required,
        intent,
        public_devices,
    )


def _map_block_devices(
    manifest: StorageManifest,
    devices: tuple[StorageDeviceEvidence, ...],
    blockers: set[str],
) -> tuple[StorageDeviceEvidence, ...]:
    selected: list[StorageDeviceEvidence] = []
    used: set[str] = set()
    for expected in manifest.devices:
        matches = [
            candidate
            for candidate in devices
            if _matches_block_identity(expected, candidate)
        ]
        if len(matches) != 1 or matches[0].stable_id in used:
            blockers.add("block-device-identity-ambiguous")
            continue
        candidate = matches[0]
        used.add(candidate.stable_id)
        if candidate.size_bytes != expected.size_gib * _GIB:
            blockers.add("block-device-size-conflict")
        selected.append(candidate)
    identifiable = {
        device.stable_id
        for device in devices
        if any(
            _matches_block_identity(expected, device) for expected in manifest.devices
        )
    }
    if identifiable != used:
        blockers.add("unexpected-or-duplicate-block-device")
    if any(
        device.provider_attachment_ids and device.stable_id not in used
        for device in devices
    ):
        blockers.add("unexpected-or-duplicate-block-device")
    return tuple(selected)


def _matches_block_identity(
    expected: StorageDevice, candidate: StorageDeviceEvidence
) -> bool:
    if expected.kind is not StorageDeviceKind.BLOCK_VOLUME or candidate.kind != "disk":
        return False
    by_id = set(candidate.by_id)
    identities = {
        *candidate.provider_attachment_ids,
        *(value for value in (candidate.serial, candidate.wwn) if value is not None),
        *(item.rsplit("/", 1)[-1] for item in candidate.by_id),
    }
    required = (
        expected.provider_volume_id,
        expected.provider_attachment_id,
    )
    if any(value is None or value not in identities for value in required):
        return False
    checks = (
        expected.expected_by_id is None or expected.expected_by_id in by_id,
        expected.expected_serial is None
        or expected.expected_serial == candidate.serial,
        expected.expected_wwn is None or expected.expected_wwn == candidate.wwn,
    )
    return all(checks)


def _map_local_devices(
    manifest: StorageManifest,
    devices: tuple[StorageDeviceEvidence, ...],
    blockers: set[str],
) -> tuple[StorageDeviceEvidence, ...]:
    candidates = tuple(
        device
        for device in devices
        if device.kind == "disk"
        and device.transport == "nvme"
        and device.nvme is not None
        and device.nvme.model is not None
        and device.nvme.namespace_id is not None
        and device.nvme.serial is not None
        and device.nvme.capabilities
        and device.by_id
        and not device.stable_id.startswith(("serial:", "wwn:"))
    )
    if len(candidates) != manifest.expected_device_count:
        blockers.add("local-NVMe-device-set-conflict")
    if any(device.size_bytes <= 0 for device in candidates):
        blockers.add("local-NVMe-capacity-unknown")
    return tuple(sorted(candidates, key=lambda item: item.stable_id))


def _ownership_status(
    metadata: ClusterMetadata,
    host: TerraformHost,
    selected: tuple[StorageDeviceEvidence, ...],
    intent: str,
    blockers: set[str],
) -> StorageOwnershipStatus:
    expected_ids = tuple(sorted(device.stable_id for device in selected))
    markers = [device.ownership for device in selected if device.ownership is not None]
    present = [device for device in selected if device.ownership_marker == "present"]
    if present:
        if len(present) != len(selected) or len(markers) != len(selected):
            blockers.add("partial-or-ambiguous-ownership-marker")
            return StorageOwnershipStatus.BLOCKED
        for marker in markers:
            if (
                marker.cluster_uuid != str(metadata.cluster_uuid)
                or marker.logical_id != host.logical_id
                or marker.provider_id != host.provider_id
                or marker.backend != host.storage.selected_backend.value
                or marker.layout != host.storage.layout
                or marker.storage_generation != host.storage.storage_generation
                or marker.policy_digest != host.storage.policy_digest
                or marker.preparation_intent_digest != intent
                or marker.stable_device_ids != expected_ids
            ):
                blockers.add("foreign-or-stale-ownership-marker")
        return (
            StorageOwnershipStatus.BLOCKED
            if blockers
            else StorageOwnershipStatus.OWNED_NOOP
        )
    unsafe = any(
        device.filesystem is not None
        or device.mount_points
        or device.holders
        or device.parents
        or device.signatures
        for device in selected
    )
    return (
        StorageOwnershipStatus.WIPE_REVIEW_REQUIRED
        if unsafe
        else StorageOwnershipStatus.CLEAN_NEW
    )


def _intent_digest(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    host: TerraformHost,
    discovery: StorageHostEvidence,
    selected: tuple[StorageDeviceEvidence, ...],
) -> str:
    value = {
        "backend": host.storage.selected_backend.value,
        "cluster_uuid": str(metadata.cluster_uuid),
        "devices": [
            {"size_bytes": device.size_bytes, "stable_id": device.stable_id}
            for device in sorted(selected, key=lambda item: item.stable_id)
        ],
        "discovery": {
            "host_manifest_digest": discovery.host_manifest_digest,
            "inventory_digest": discovery.inventory_digest,
            "inventory_generation": discovery.inventory_generation,
            "observation_digest": discovery.observation_digest,
            "observation_generation": discovery.observation_generation,
        },
        "inventory_digest": inventory.digest,
        "layout": host.storage.layout,
        "logical_id": host.logical_id,
        "observation_digest": observed.digest,
        "policy_digest": host.storage.policy_digest,
        "provider_id": host.provider_id,
        "storage_generation": host.storage.storage_generation,
    }
    data = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()
