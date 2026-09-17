"""Strict read-only verification of prepared Scylla storage."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from scylla_vms.ansible.storage import StorageDiscoveryEvidence, StorageHostEvidence
from scylla_vms.ansible.storage_preflight import (
    StorageOwnershipStatus,
    StoragePreflightResult,
    reconcile_storage_preflight,
)
from scylla_vms.ansible.storage_prepare import (
    StoragePrepareEvidence,
    StoragePrepareStatus,
    storage_device_set_digest,
)
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata

STORAGE_POSTCHECK_SCHEMA_VERSION = "deploy-scylla-vms.ansible-storage-postcheck/v1"
DEPLOY_STORAGE_POSTCHECK_SELECTION_MODE = "public-device-identity-digest"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MARKER = re.compile(
    r'DSV_STORAGE_POSTCHECK_B64=(?P<data>[A-Za-z0-9+/]+={0,2})"(?:\})?\s*$'
)
_CHECK_NAMES = frozenset(
    {
        "capacity",
        "device-membership",
        "filesystem",
        "fstab",
        "holders",
        "marker",
        "mount",
        "permissions",
        "provenance",
        "raid",
        "signatures",
        "tools",
    }
)
_BLOCKERS = frozenset(
    {
        "capacity-conflict",
        "device-identity-conflict",
        "device-membership-conflict",
        "filesystem-conflict",
        "fstab-conflict",
        "holder-conflict",
        "marker-conflict",
        "mount-conflict",
        "permission-conflict",
        "provenance-conflict",
        "raid-conflict",
        "signature-conflict",
        "tool-evidence-unavailable",
        "verification-incomplete",
    }
)


class StorageCheckStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class StoragePostcheckCheck:
    name: str
    status: StorageCheckStatus


@dataclass(frozen=True, slots=True)
class StoragePostcheckEvidence:
    logical_id: str
    backend: str
    layout: str
    readiness_for_scylla: bool
    checks: tuple[StoragePostcheckCheck, ...]
    blockers: tuple[str, ...]
    devices: tuple[tuple[str, int], ...]
    provenance: tuple[tuple[str, str], ...]
    schema_version: str = STORAGE_POSTCHECK_SCHEMA_VERSION


def build_storage_postcheck_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    discovery: StorageDiscoveryEvidence,
    preflight: StoragePreflightResult,
    preparation: StoragePrepareEvidence,
    *,
    limit: tuple[str, ...],
) -> dict[str, object]:
    """Reconcile all prior evidence and build one private read-only expectation."""

    if len(limit) != 1:
        raise StateConflictError("storage postcheck requires one exact target")
    expected = reconcile_storage_preflight(
        metadata, observed, inventory, discovery, limit
    )
    if expected != preflight or len(preflight.hosts) != 1:
        raise StateConflictError("storage postcheck preflight is stale or mismatched")
    host = preflight.hosts[0]
    if (
        host.logical_id != limit[0]
        or host.ownership_status is StorageOwnershipStatus.BLOCKED
        or host.blockers
        or preparation.logical_id != host.logical_id
        or preparation.backend != host.backend
        or preparation.layout != host.layout
        or preparation.status
        not in {StoragePrepareStatus.CHANGED, StoragePrepareStatus.NOOP}
    ):
        raise StateConflictError("storage postcheck preparation result conflicts")
    stable_ids = tuple(device.stable_id for device in host.devices)
    device_set_digest = storage_device_set_digest(stable_ids)
    if preparation.device_set_digest != device_set_digest:
        raise StateConflictError("storage postcheck device set conflicts")
    manifest_host = next(
        (
            item
            for item in observed.record.manifest.hosts
            if item.logical_id == host.logical_id
        ),
        None,
    )
    discovery_host = next(
        (item for item in discovery.hosts if item.logical_id == host.logical_id), None
    )
    if manifest_host is None or discovery_host is None:
        raise StateConflictError("storage postcheck target provenance is unavailable")
    by_id = {item.stable_id: item for item in discovery_host.devices}
    devices = []
    for selected in host.devices:
        device = by_id.get(selected.stable_id)
        if device is None:
            raise StateConflictError("storage postcheck device mapping is incomplete")
        devices.append(
            {
                "by_id": list(device.by_id),
                "identity": selected.identity,
                "path": device.path,
                "size_bytes": device.size_bytes,
                "stable_id": device.stable_id,
            }
        )
    manifest = manifest_host.storage
    return {
        "backend": host.backend,
        "capacity_bytes": host.capacity_bytes,
        "cluster_uuid": str(metadata.cluster_uuid),
        "devices": devices,
        "discovery_digest": _discovery_digest(discovery_host),
        "expected_filesystem_uuid_digest": preparation.filesystem_uuid_digest,
        "expected_marker_digest": preparation.marker_digest,
        "filesystem": manifest.filesystem_type,
        "inventory_digest": inventory.digest,
        "inventory_generation": inventory.record.generation,
        "layout": host.layout,
        "logical_id": host.logical_id,
        "mount_options": list(manifest.mount_options),
        "mount_point": manifest.mount_point,
        "observation_digest": observed.digest,
        "observation_generation": observed.record.generation,
        "policy_digest": manifest.policy_digest,
        "preparation_intent_digest": host.preparation_intent_digest,
        "prepare_device_set_digest": preparation.device_set_digest,
        "provider_id": manifest_host.provider_id,
        "schema_version": STORAGE_POSTCHECK_SCHEMA_VERSION,
        "storage_generation": manifest.storage_generation,
    }


def build_deploy_storage_postcheck_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    preflight: StoragePreflightResult,
    preparation: StoragePrepareEvidence,
    *,
    discovery_evidence_digest: str,
    preflight_evidence_digest: str,
    preparation_evidence_digest: str,
    limit: tuple[str, ...],
) -> dict[str, object]:
    """Build a path-free deploy postcheck payload for one exact current target."""

    if len(limit) != 1 or len(preflight.hosts) != 1:
        raise StateConflictError("deploy storage postcheck requires one exact target")
    host = preflight.hosts[0]
    if (
        host.logical_id != limit[0]
        or host.ownership_status is StorageOwnershipStatus.BLOCKED
        or host.blockers
        or not host.devices
        or preparation.logical_id != host.logical_id
        or preparation.backend != host.backend
        or preparation.layout != host.layout
        or preparation.status
        not in {StoragePrepareStatus.CHANGED, StoragePrepareStatus.NOOP}
    ):
        raise StateConflictError("deploy storage postcheck preparation conflicts")
    identities = tuple(device.identity for device in host.devices)
    device_set_digest = _deploy_device_set_digest(identities)
    if preparation.device_set_digest != device_set_digest:
        raise StateConflictError("deploy storage postcheck device set conflicts")
    for value in (
        discovery_evidence_digest,
        preflight_evidence_digest,
        preparation_evidence_digest,
    ):
        if _DIGEST.fullmatch(value) is None:
            raise StateConflictError(
                "deploy storage postcheck provenance digest is invalid"
            )
    manifest_host = next(
        (
            item
            for item in observed.record.manifest.hosts
            if item.logical_id == host.logical_id
        ),
        None,
    )
    inventory_host = next(
        (
            item
            for item in inventory.record.inventory.hosts
            if item.logical_id == host.logical_id
        ),
        None,
    )
    if (
        manifest_host is None
        or inventory_host is None
        or inventory_host.provider_id != manifest_host.provider_id
        or inventory_host.storage_generation != manifest_host.storage.storage_generation
        or inventory_host.storage_policy_digest != manifest_host.storage.policy_digest
    ):
        raise StateConflictError(
            "deploy storage postcheck manifest target is unavailable"
        )
    manifest = manifest_host.storage
    if (
        manifest.mount_point != "/var/lib/scylla"
        or manifest.filesystem_type != "xfs"
        or manifest.layout not in {"single", "raid0"}
        or manifest.layout != host.layout
        or manifest.selected_backend.value != host.backend
        or manifest.expected_device_count != len(host.devices)
    ):
        raise StateConflictError("deploy storage postcheck policy is unsupported")
    return {
        "backend": host.backend,
        "capacity_bytes": host.capacity_bytes,
        "cluster_uuid": str(metadata.cluster_uuid),
        "devices": [
            {
                "capacity_bytes": device.capacity_bytes,
                "identity": device.identity,
            }
            for device in host.devices
        ],
        "discovery_digest": discovery_evidence_digest,
        "expected_filesystem_uuid_digest": preparation.filesystem_uuid_digest,
        "expected_marker_digest": preparation.marker_digest,
        "filesystem": manifest.filesystem_type,
        "inventory_digest": inventory.digest,
        "inventory_generation": inventory.record.generation,
        "layout": host.layout,
        "logical_id": host.logical_id,
        "mount_options": list(manifest.mount_options),
        "mount_point": manifest.mount_point,
        "observation_digest": observed.digest,
        "observation_generation": observed.record.generation,
        "policy_digest": manifest.policy_digest,
        "preflight_evidence_digest": preflight_evidence_digest,
        "preparation_evidence_digest": preparation_evidence_digest,
        "preparation_intent_digest": host.preparation_intent_digest,
        "prepare_device_set_digest": device_set_digest,
        "provider_id": manifest_host.provider_id,
        "schema_version": STORAGE_POSTCHECK_SCHEMA_VERSION,
        "selection_mode": DEPLOY_STORAGE_POSTCHECK_SELECTION_MODE,
        "storage_generation": manifest.storage_generation,
    }


def parse_storage_postcheck_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> StoragePostcheckEvidence:
    """Parse one bounded, redacted postcheck result."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError(
            "Ansible storage postcheck output exceeds the evidence limit"
        )
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_STORAGE_POSTCHECK_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible storage postcheck marker is malformed")
        try:
            raw = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible storage postcheck marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible storage postcheck result is malformed")
        values.append(value)
    if len(values) != 1:
        raise AnsibleError("Ansible storage postcheck evidence is incomplete")
    value = values[0]
    if (
        set(value)
        != {
            "backend",
            "blockers",
            "checks",
            "devices",
            "layout",
            "logical_id",
            "provenance",
            "readiness_for_scylla",
            "schema_version",
        }
        or value["schema_version"] != STORAGE_POSTCHECK_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible storage postcheck result is malformed")
    logical_id = _text(value["logical_id"])
    backend = _text(value["backend"])
    layout = _text(value["layout"])
    if (
        logical_id != expected_payload["logical_id"]
        or backend != expected_payload["backend"]
        or layout != expected_payload["layout"]
    ):
        raise AnsibleError("Ansible storage postcheck result conflicts")
    checks_value = value["checks"]
    if not isinstance(checks_value, list):
        raise AnsibleError("Ansible storage postcheck checks are invalid")
    checks: list[StoragePostcheckCheck] = []
    for item in checks_value:
        if not isinstance(item, dict) or set(item) != {"name", "status"}:
            raise AnsibleError("Ansible storage postcheck checks are invalid")
        name = _text(item["name"])
        try:
            status = StorageCheckStatus(_text(item["status"]))
        except ValueError as error:
            raise AnsibleError("Ansible storage postcheck status is invalid") from error
        if name not in _CHECK_NAMES:
            raise AnsibleError("Ansible storage postcheck check is unknown")
        checks.append(StoragePostcheckCheck(name, status))
    ordered_checks = tuple(sorted(checks, key=lambda item: item.name))
    if tuple(checks) != ordered_checks or len({item.name for item in checks}) != len(
        checks
    ):
        raise AnsibleError("Ansible storage postcheck checks are not uniquely sorted")
    blockers = _sorted_strings(value["blockers"])
    if not set(blockers) <= _BLOCKERS:
        raise AnsibleError("Ansible storage postcheck blocker is unknown")
    devices_value = value["devices"]
    if not isinstance(devices_value, list):
        raise AnsibleError("Ansible storage postcheck devices are invalid")
    devices: list[tuple[str, int]] = []
    for item in devices_value:
        if (
            not isinstance(item, dict)
            or set(item) != {"capacity_bytes", "identity"}
            or not isinstance(item["capacity_bytes"], int)
            or isinstance(item["capacity_bytes"], bool)
            or item["capacity_bytes"] <= 0
        ):
            raise AnsibleError("Ansible storage postcheck devices are invalid")
        identity = _text(item["identity"])
        if re.fullmatch(r"device-sha256:[0-9a-f]{64}", identity) is None:
            raise AnsibleError("Ansible storage postcheck device identity is invalid")
        devices.append((identity, item["capacity_bytes"]))
    if devices != sorted(set(devices)):
        raise AnsibleError("Ansible storage postcheck devices are not uniquely sorted")
    payload_devices = cast(list[dict[str, object]], expected_payload["devices"])
    capacity_key = (
        "capacity_bytes"
        if expected_payload.get("selection_mode")
        == DEPLOY_STORAGE_POSTCHECK_SELECTION_MODE
        else "size_bytes"
    )
    expected_devices = sorted(
        (
            _text(item["identity"]),
            cast(int, item[capacity_key]),
        )
        for item in payload_devices
    )
    if devices != expected_devices:
        raise AnsibleError("Ansible storage postcheck device evidence conflicts")
    provenance_value = value["provenance"]
    if not isinstance(provenance_value, dict) or not provenance_value:
        raise AnsibleError("Ansible storage postcheck provenance is invalid")
    required_provenance = {
        "device_set_digest": expected_payload["prepare_device_set_digest"],
        "discovery_digest": expected_payload["discovery_digest"],
        "inventory_digest": expected_payload["inventory_digest"],
        "observation_digest": expected_payload["observation_digest"],
        "policy_digest": expected_payload["policy_digest"],
        "preparation_intent_digest": expected_payload["preparation_intent_digest"],
    }
    if (
        expected_payload.get("selection_mode")
        == DEPLOY_STORAGE_POSTCHECK_SELECTION_MODE
    ):
        required_provenance.update(
            {
                "preflight_evidence_digest": (
                    expected_payload["preflight_evidence_digest"]
                ),
                "preparation_evidence_digest": (
                    expected_payload["preparation_evidence_digest"]
                ),
            }
        )
    if not set(required_provenance) <= set(provenance_value):
        raise AnsibleError("Ansible storage postcheck provenance is incomplete")
    provenance = tuple(
        sorted((_text(key), _digest(item)) for key, item in provenance_value.items())
    )
    if any(provenance_value[key] != item for key, item in required_provenance.items()):
        raise AnsibleError("Ansible storage postcheck provenance conflicts")
    if set(provenance_value) - {
        *required_provenance,
        "filesystem_uuid_digest",
        "marker_digest",
    }:
        raise AnsibleError("Ansible storage postcheck provenance is invalid")
    if {item.name for item in checks} != _CHECK_NAMES:
        raise AnsibleError("Ansible storage postcheck checks are incomplete")
    readiness = value["readiness_for_scylla"]
    if not isinstance(readiness, bool):
        raise AnsibleError("Ansible storage postcheck readiness is invalid")
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible storage postcheck output omitted PLAY RECAP")
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
            raise AnsibleError("Ansible storage postcheck recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    if set(rows) != {logical_id} or rows[logical_id][0] != 0:
        raise AnsibleError("Ansible storage postcheck recap conflicts")
    failed = bool(blockers) or any(
        item.status is not StorageCheckStatus.PASSED for item in checks
    )
    recap_failed = bool(rows[logical_id][1] or rows[logical_id][2])
    if readiness == failed or recap_failed != failed or (exit_code == 0) == failed:
        raise AnsibleError("Ansible storage postcheck exit status conflicts")
    return StoragePostcheckEvidence(
        logical_id,
        backend,
        layout,
        readiness,
        ordered_checks,
        blockers,
        tuple(devices),
        provenance,
    )


def _discovery_digest(host: StorageHostEvidence) -> str:
    devices = host.devices
    value = {
        "devices": [
            {
                "by_id": list(item.by_id),
                "path": item.path,
                "size_bytes": item.size_bytes,
                "stable_id": item.stable_id,
            }
            for item in devices
        ],
        "logical_id": host.logical_id,
        "provider_id": host.provider_id,
    }
    data = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _deploy_device_set_digest(identities: tuple[str, ...]) -> str:
    if (
        not identities
        or identities != tuple(sorted(set(identities)))
        or any(
            re.fullmatch(r"device-sha256:[0-9a-f]{64}", item) is None
            for item in identities
        )
    ):
        raise StateConflictError(
            "deploy storage postcheck device identities are invalid"
        )
    data = (
        json.dumps(
            {"value": list(identities)},
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AnsibleError("Ansible storage postcheck contains duplicate fields")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise AnsibleError(f"invalid storage postcheck constant: {value}")


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024 or "\0" in value:
        raise AnsibleError("Ansible storage postcheck value is invalid")
    return value


def _digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible storage postcheck digest is invalid")
    return text


def _sorted_strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible storage postcheck values are invalid")
    values = tuple(_text(item) for item in value)
    if values != tuple(sorted(set(values))):
        raise AnsibleError("Ansible storage postcheck values are not uniquely sorted")
    return values
