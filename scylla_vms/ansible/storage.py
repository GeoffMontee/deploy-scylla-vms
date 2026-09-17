"""Strict, sensitive, read-only storage-discovery evidence."""

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from typing import cast

from scylla_vms.errors import AnsibleError
from scylla_vms.inventory import StoredInventoryRecord

STORAGE_DISCOVERY_SCHEMA_VERSION = "deploy-scylla-vms.ansible-storage-discovery/v1"
MAXIMUM_STORAGE_OUTPUT_BYTES = 2 * 1024 * 1024
MAXIMUM_STORAGE_HOST_BYTES = 256 * 1024
MAXIMUM_STORAGE_DEVICES = 256
MAXIMUM_STORAGE_DEPTH = 16
_MARKER = re.compile(
    r'DSV_STORAGE_DISCOVERY_B64=(?P<data>[A-Za-z0-9+/]+={0,2})"(?:\})?\s*$'
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DEVICE_PATH = re.compile(r"/dev/[A-Za-z0-9][A-Za-z0-9._/+:-]{0,255}\Z")
_STABLE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+/-]{0,511}\Z")
_SECRET = re.compile(
    r"(?i)(?:password|passphrase|private[_ -]?key|credential|secret|token)"
)
_KINDS = frozenset({"crypt", "disk", "lvm", "mpath", "part", "raid"})
_TOOL_STATUS = frozenset({"available", "unavailable"})
_SIGNATURE_TYPES = frozenset({"filesystem", "partition-table", "raid", "lvm"})


@dataclass(frozen=True, slots=True)
class StorageSignature:
    kind: str
    value: str


@dataclass(frozen=True, slots=True)
class NvmeEvidence:
    model: str | None
    namespace_id: int | None
    capabilities: tuple[str, ...]
    serial: str | None = field(repr=False)


@dataclass(frozen=True, slots=True)
class StorageOwnershipEvidence:
    schema_version: str
    cluster_uuid: str
    logical_id: str
    backend: str
    layout: str
    storage_generation: int
    policy_digest: str
    preparation_intent_digest: str
    stable_device_ids: tuple[str, ...] = field(repr=False)
    provider_id: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class StorageDeviceEvidence:
    stable_id: str
    path: str
    kind: str
    size_bytes: int
    transport: str | None
    filesystem: str | None
    mount_points: tuple[str, ...]
    parents: tuple[str, ...]
    holders: tuple[str, ...]
    root_ancestor: bool
    boot_ancestor: bool
    signatures: tuple[StorageSignature, ...]
    ownership_marker: str
    ownership: StorageOwnershipEvidence | None
    by_id: tuple[str, ...]
    provider_attachment_ids: tuple[str, ...] = field(repr=False)
    serial: str | None = field(repr=False)
    wwn: str | None = field(repr=False)
    nvme: NvmeEvidence | None = field(repr=False)


@dataclass(frozen=True, slots=True)
class StorageHostEvidence:
    cluster_uuid: str
    observation_generation: int
    observation_digest: str
    inventory_generation: int
    inventory_digest: str
    logical_id: str
    host_manifest_digest: str
    storage_generation: int
    storage_policy_digest: str
    tools: tuple[tuple[str, str], ...]
    mounts: tuple[str, ...]
    devices: tuple[StorageDeviceEvidence, ...]
    provider_id: str = field(repr=False)
    schema_version: str = STORAGE_DISCOVERY_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class StorageDiscoveryEvidence:
    hosts: tuple[StorageHostEvidence, ...]
    unavailable_hosts: tuple[str, ...]


def parse_storage_discovery_evidence(
    stdout: str,
    inventory: StoredInventoryRecord,
    expected_hosts: tuple[str, ...],
    exit_code: int,
) -> StorageDiscoveryEvidence:
    """Parse normalized discovery markers and bind them to exact inventory state."""

    if len(stdout.encode("utf-8")) > MAXIMUM_STORAGE_OUTPUT_BYTES:
        raise AnsibleError(
            "Ansible storage discovery output exceeds the evidence limit"
        )
    expected = tuple(sorted(expected_hosts))
    if not expected or expected != tuple(sorted(set(expected))):
        raise AnsibleError("Ansible storage discovery host membership is invalid")
    inventory_hosts = {
        host.logical_id: host for host in inventory.record.inventory.hosts
    }
    if any(
        logical_id not in inventory_hosts
        or inventory_hosts[logical_id].role.value != "scylla"
        for logical_id in expected
    ):
        raise AnsibleError("Ansible storage discovery requires exact Scylla host IDs")

    markers: dict[str, StorageHostEvidence] = {}
    for line in stdout.splitlines():
        if "DSV_STORAGE_DISCOVERY_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible storage discovery evidence marker is malformed")
        marker = _decode_marker(match.group("data"))
        if marker.logical_id in markers:
            raise AnsibleError("Ansible storage discovery evidence is duplicated")
        markers[marker.logical_id] = marker
    if set(markers) - set(expected):
        raise AnsibleError("Ansible storage discovery evidence membership conflicts")

    unavailable = _parse_recap(stdout, expected)
    if set(markers) & set(unavailable):
        raise AnsibleError("Ansible storage discovery failure evidence conflicts")
    if set(markers) | set(unavailable) != set(expected):
        raise AnsibleError("Ansible storage discovery evidence is incomplete")
    if (exit_code == 0) != (not unavailable):
        raise AnsibleError(
            "Ansible storage discovery exit status conflicts with evidence"
        )

    record = inventory.record
    for logical_id, evidence in markers.items():
        host = inventory_hosts[logical_id]
        if (
            evidence.cluster_uuid != str(record.cluster_uuid)
            or evidence.observation_generation != record.source_manifest_generation
            or evidence.observation_digest != record.source_manifest_digest
            or evidence.inventory_generation != record.generation
            or evidence.inventory_digest != inventory.digest
            or evidence.provider_id != host.provider_id
            or evidence.storage_generation != host.storage_generation
            or evidence.storage_policy_digest != host.storage_policy_digest
        ):
            raise AnsibleError(
                "Ansible storage discovery host or manifest identity conflicts"
            )
    return StorageDiscoveryEvidence(
        tuple(markers[name] for name in sorted(markers)), tuple(sorted(unavailable))
    )


def _decode_marker(encoded: str) -> StorageHostEvidence:
    try:
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) > MAXIMUM_STORAGE_HOST_BYTES:
            raise AnsibleError("Ansible storage discovery host evidence is oversized")
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
        _check_tree(value, 0)
        _reject_secrets(value)
        item = _object(
            value,
            {
                "cluster_uuid",
                "devices",
                "host_manifest_digest",
                "inventory_digest",
                "inventory_generation",
                "logical_id",
                "mounts",
                "observation_digest",
                "observation_generation",
                "provider_id",
                "schema_version",
                "storage_generation",
                "storage_policy_digest",
                "tools",
            },
        )
        if item["schema_version"] != STORAGE_DISCOVERY_SCHEMA_VERSION:
            raise AnsibleError("Ansible storage discovery schema is invalid")
        tools_object = _object(
            item["tools"],
            {"blkid", "by-id", "findmnt", "lsblk", "lvm", "md", "nvme", "wipefs"},
        )
        tools = tuple(
            sorted(
                (_text(name), _choice(status, _TOOL_STATUS))
                for name, status in tools_object.items()
            )
        )
        devices = tuple(_device(device) for device in _array(item["devices"]))
        if (
            len(devices) > MAXIMUM_STORAGE_DEVICES
            or tuple(device.stable_id for device in devices)
            != tuple(sorted({device.stable_id for device in devices}))
            or len({device.path for device in devices}) != len(devices)
        ):
            raise AnsibleError(
                "Ansible storage discovery devices are not uniquely sorted"
            )
        _validate_topology(devices)
        return StorageHostEvidence(
            _text(item["cluster_uuid"]),
            _positive_int(item["observation_generation"]),
            _digest(item["observation_digest"]),
            _positive_int(item["inventory_generation"]),
            _digest(item["inventory_digest"]),
            _matched_text(item["logical_id"], _LOGICAL_ID),
            _digest(item["host_manifest_digest"]),
            _positive_int(item["storage_generation"]),
            _digest(item["storage_policy_digest"]),
            tools,
            _sorted_paths(item["mounts"], mounts=True),
            devices,
            _text(item["provider_id"]),
        )
    except (
        UnicodeDecodeError,
        binascii.Error,
        json.JSONDecodeError,
        TypeError,
    ) as error:
        raise AnsibleError(
            "Ansible storage discovery evidence marker is malformed"
        ) from error


def _device(value: object) -> StorageDeviceEvidence:
    item = _object(
        value,
        {
            "boot_ancestor",
            "by_id",
            "filesystem",
            "holders",
            "kind",
            "mount_points",
            "nvme",
            "ownership_marker",
            "ownership",
            "parents",
            "path",
            "provider_attachment_ids",
            "root_ancestor",
            "serial",
            "signatures",
            "size_bytes",
            "stable_id",
            "transport",
            "wwn",
        },
    )
    stable_id = _matched_text(item["stable_id"], _STABLE_ID)
    if stable_id.startswith("/dev/") or re.fullmatch(
        r"(?:sd|vd|xvd|nvme)\w+", stable_id
    ):
        raise AnsibleError("Ansible storage discovery stable device ID is invalid")
    signatures = tuple(
        StorageSignature(
            _choice(signature["kind"], _SIGNATURE_TYPES), _text(signature["value"])
        )
        for signature in (
            _object(entry, {"kind", "value"}) for entry in _array(item["signatures"])
        )
    )
    if signatures != tuple(
        sorted(set(signatures), key=lambda value: (value.kind, value.value))
    ):
        raise AnsibleError(
            "Ansible storage discovery signatures are not uniquely sorted"
        )
    nvme_value = item["nvme"]
    nvme = None
    if nvme_value is not None:
        nvme_item = _object(
            nvme_value, {"capabilities", "model", "namespace_id", "serial"}
        )
        namespace = nvme_item["namespace_id"]
        nvme = NvmeEvidence(
            _optional_text(nvme_item["model"]),
            None if namespace is None else _positive_int(namespace),
            _sorted_text(nvme_item["capabilities"]),
            _optional_text(nvme_item["serial"]),
        )
    ownership_value = item["ownership"]
    ownership = None
    if ownership_value is not None:
        ownership_item = _object(
            ownership_value,
            {
                "backend",
                "cluster_uuid",
                "layout",
                "logical_id",
                "policy_digest",
                "preparation_intent_digest",
                "provider_id",
                "schema_version",
                "stable_device_ids",
                "storage_generation",
            },
        )
        ownership = StorageOwnershipEvidence(
            _choice(
                ownership_item["schema_version"],
                frozenset({"deploy-scylla-vms.prepared-storage/v1"}),
            ),
            _text(ownership_item["cluster_uuid"]),
            _matched_text(ownership_item["logical_id"], _LOGICAL_ID),
            _choice(
                ownership_item["backend"],
                frozenset({"block-volume", "local-nvme"}),
            ),
            _choice(ownership_item["layout"], frozenset({"single", "raid0"})),
            _positive_int(ownership_item["storage_generation"]),
            _digest(ownership_item["policy_digest"]),
            _digest(ownership_item["preparation_intent_digest"]),
            _sorted_text(ownership_item["stable_device_ids"]),
            _text(ownership_item["provider_id"]),
        )
    marker = _choice(
        item["ownership_marker"], frozenset({"absent", "present", "unavailable"})
    )
    if (marker == "present") != (ownership is not None):
        raise AnsibleError("Ansible storage discovery ownership marker is inconsistent")
    path = _matched_text(item["path"], _DEVICE_PATH)
    return StorageDeviceEvidence(
        stable_id,
        path,
        _choice(item["kind"], _KINDS),
        _positive_int(item["size_bytes"]),
        _optional_text(item["transport"]),
        _optional_text(item["filesystem"]),
        _sorted_paths(item["mount_points"], mounts=True),
        _sorted_text(item["parents"]),
        _sorted_text(item["holders"]),
        _boolean(item["root_ancestor"]),
        _boolean(item["boot_ancestor"]),
        signatures,
        marker,
        ownership,
        _sorted_paths(item["by_id"], mounts=False),
        _sorted_text(item["provider_attachment_ids"]),
        _optional_text(item["serial"]),
        _optional_text(item["wwn"]),
        nvme,
    )


def _validate_topology(devices: tuple[StorageDeviceEvidence, ...]) -> None:
    ids = {device.stable_id for device in devices}
    graph: dict[str, tuple[str, ...]] = {}
    for device in devices:
        related = (*device.parents, *device.holders)
        if any(item not in ids or item == device.stable_id for item in related):
            raise AnsibleError("Ansible storage discovery topology is invalid")
        graph[device.stable_id] = device.parents
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(device_id: str) -> None:
        if device_id in visiting:
            raise AnsibleError("Ansible storage discovery topology contains a cycle")
        if device_id in visited:
            return
        visiting.add(device_id)
        for related in graph[device_id]:
            visit(related)
        visiting.remove(device_id)
        visited.add(device_id)

    for device_id in sorted(graph):
        visit(device_id)


def _parse_recap(stdout: str, expected: tuple[str, ...]) -> tuple[str, ...]:
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible storage discovery output omitted PLAY RECAP")
    pattern = re.compile(
        r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
        r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
        r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
    )
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = pattern.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible storage discovery recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    if tuple(sorted(rows)) != expected or any(row[0] for row in rows.values()):
        raise AnsibleError("Ansible storage discovery recap conflicts")
    return tuple(sorted(host for host, row in rows.items() if row[1] or row[2]))


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AnsibleError("Ansible storage discovery contains duplicate fields")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise AnsibleError(f"invalid storage evidence constant: {value}")


def _check_tree(value: object, depth: int) -> None:
    if depth > MAXIMUM_STORAGE_DEPTH:
        raise AnsibleError("Ansible storage discovery exceeds the depth limit")
    if isinstance(value, dict):
        for item in value.values():
            _check_tree(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_tree(item, depth + 1)
    elif value is not None and not isinstance(value, (str, int, bool)):
        raise AnsibleError("Ansible storage discovery contains an invalid value")


def _reject_secrets(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _SECRET.search(key):
                raise AnsibleError(
                    "Ansible storage discovery contains secret-like data"
                )
            _reject_secrets(item)
    elif isinstance(value, list):
        for item in value:
            _reject_secrets(item)
    elif isinstance(value, str) and _SECRET.search(value):
        raise AnsibleError("Ansible storage discovery contains secret-like data")


def _object(value: object, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AnsibleError("Ansible storage discovery schema is invalid")
    return cast(dict[str, object], value)


def _array(value: object) -> list[object]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible storage discovery schema is invalid")
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024 or "\0" in value:
        raise AnsibleError("Ansible storage discovery schema is invalid")
    return value


def _matched_text(value: object, pattern: re.Pattern[str]) -> str:
    text = _text(value)
    if pattern.fullmatch(text) is None:
        raise AnsibleError("Ansible storage discovery schema is invalid")
    return text


def _optional_text(value: object) -> str | None:
    return None if value is None else _text(value)


def _choice(value: object, choices: frozenset[str]) -> str:
    text = _text(value)
    if text not in choices:
        raise AnsibleError("Ansible storage discovery schema is invalid")
    return text


def _positive_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 2**63:
        raise AnsibleError("Ansible storage discovery schema is invalid")
    return value


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError("Ansible storage discovery schema is invalid")
    return value


def _digest(value: object) -> str:
    return _matched_text(value, _DIGEST)


def _sorted_text(value: object) -> tuple[str, ...]:
    items = tuple(_text(item) for item in _array(value))
    if items != tuple(sorted(set(items))):
        raise AnsibleError("Ansible storage discovery values are not uniquely sorted")
    return items


def _sorted_paths(value: object, *, mounts: bool) -> tuple[str, ...]:
    items = _sorted_text(value)
    if any(
        not item.startswith("/")
        or ".." in item.split("/")
        or (not mounts and not item.startswith("/dev/disk/by-id/"))
        for item in items
    ):
        raise AnsibleError("Ansible storage discovery path is invalid")
    return items
