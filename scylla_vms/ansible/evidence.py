"""Strict diagnostic evidence parsing and optional protected persistence."""

import base64
import binascii
import json
import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, cast

from scylla_vms.ansible.service import (
    HostConnectivityStatus,
    parse_connectivity_evidence,
)
from scylla_vms.ansible.trust import StoredTrustRecord
from scylla_vms.desired import HostRole
from scylla_vms.errors import AnsibleError, ConfigurationError, StatePersistenceError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import (
    AtomicJsonFile,
    ClusterMetadata,
    format_timestamp,
    parse_timestamp,
    parse_uuid,
    require_exact_keys,
    require_string,
    validate_digest,
)
from scylla_vms.state import (
    StatePaths,
    validate_cluster_name,
    validate_state_file,
)

if TYPE_CHECKING:
    from scylla_vms.locking import ClusterLock

EVIDENCE_SCHEMA_VERSION = "deploy-scylla-vms.diagnostics-evidence/v1"
HOST_EVIDENCE_SCHEMA_VERSION = "deploy-scylla-vms.ansible-host-evidence/v1"
_MAX_OUTPUT_BYTES = 1024 * 1024
_MAX_HOST_BYTES = 64 * 1024
_MAX_HOSTS = 256
_MARKER = re.compile(r'DSV_EVIDENCE_B64=(?P<data>[A-Za-z0-9+/]+={0,2})"(?:\})?\s*$')
_SAFE_TEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ,:._+()-]{0,255}\Z")
_SECRET_TEXT = re.compile(r"(?i)(?:credential|password|private[-_ ]?key|secret|token)")
_DEVICE_NAME = re.compile(r"[a-zA-Z][a-zA-Z0-9._-]{0,63}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DEVICE_SIZE = re.compile(r"[0-9]+(?:\.[0-9]+)?\s+[KMGTPE]?B\Z")
_MOUNTS = frozenset(
    {
        "/",
        "/var/lib/grafana",
        "/var/lib/prometheus",
        "/var/lib/scylla",
        "/var/lib/scylla-manager",
    }
)
_SERVICES = {
    HostRole.JUMP_HOST: frozenset(),
    HostRole.MANAGER: frozenset({"scylla-manager.service"}),
    HostRole.MONITORING: frozenset({"grafana-server.service", "prometheus.service"}),
    HostRole.SCYLLA: frozenset({"scylla-server.service"}),
}
_ERRORS = frozenset(
    {
        "host-failed",
        "host-unreachable",
        "service-facts-unavailable",
        "system-facts-unavailable",
    }
)


class EvidenceStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class FilesystemEvidence:
    mount: str
    total_bytes: int
    available_bytes: int
    used_percent: float | None

    def to_object(self) -> dict[str, object]:
        return {
            "available_bytes": self.available_bytes,
            "mount": self.mount,
            "total_bytes": self.total_bytes,
            "used_percent": self.used_percent,
        }


@dataclass(frozen=True, slots=True)
class BlockDeviceEvidence:
    name: str
    size: str | None
    rotational: bool | None

    def to_object(self) -> dict[str, object]:
        return {
            "name": self.name,
            "rotational": self.rotational,
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class ServiceEvidence:
    name: str
    status: str

    def to_object(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status}


@dataclass(frozen=True, slots=True)
class HostEvidence:
    logical_id: str
    role: HostRole
    status: EvidenceStatus
    system: Mapping[str, object]
    filesystem_status: str
    filesystems: tuple[FilesystemEvidence, ...]
    block_device_status: str
    block_devices: tuple[BlockDeviceEvidence, ...]
    services: tuple[ServiceEvidence, ...]
    service_version_status: str
    service_version: str | None
    scylla_health: str
    errors: tuple[str, ...]

    def to_object(self) -> dict[str, object]:
        return {
            "block_devices": {
                "items": [item.to_object() for item in self.block_devices],
                "status": self.block_device_status,
            },
            "errors": list(self.errors),
            "filesystems": {
                "items": [item.to_object() for item in self.filesystems],
                "status": self.filesystem_status,
            },
            "logical_id": self.logical_id,
            "role": self.role.value,
            "schema_version": HOST_EVIDENCE_SCHEMA_VERSION,
            "scylla_health": {"status": self.scylla_health},
            "service_version": {
                "status": self.service_version_status,
                "value": self.service_version,
            },
            "services": [item.to_object() for item in self.services],
            "status": self.status.value,
            "system": dict(self.system),
        }


@dataclass(frozen=True, slots=True)
class CollectedEvidence:
    status: EvidenceStatus
    hosts: tuple[HostEvidence, ...]


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    generation: int
    cluster_uuid: uuid.UUID
    cluster_name: str
    provider: str
    captured_at: str
    observation_generation: int
    observation_digest: str
    observation_file_digest: str
    inventory_generation: int
    inventory_digest: str
    inventory_file_digest: str
    trust_generation: int
    trust_digest: str
    status: EvidenceStatus
    target_ids: tuple[str, ...]
    hosts: tuple[HostEvidence, ...]
    schema_version: str = EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != EVIDENCE_SCHEMA_VERSION
            or self.generation < 1
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.provider, str)
            or not self.provider
            or self.observation_generation < 1
            or self.inventory_generation < 1
            or self.trust_generation < 1
            or not self.target_ids
            or len(self.target_ids) > _MAX_HOSTS
            or self.target_ids != tuple(sorted(set(self.target_ids)))
            or tuple(host.logical_id for host in self.hosts) != self.target_ids
        ):
            raise StatePersistenceError("diagnostic evidence record is invalid")
        try:
            validate_cluster_name(self.cluster_name)
        except ConfigurationError as error:
            raise StatePersistenceError(
                "diagnostic evidence cluster name is invalid"
            ) from error
        for value in (
            self.observation_digest,
            self.observation_file_digest,
            self.inventory_digest,
            self.inventory_file_digest,
            self.trust_digest,
        ):
            validate_digest(value, "diagnostic evidence digest")
        parse_timestamp(self.captured_at)
        if (
            tuple(_host_from_object(host.to_object()) for host in self.hosts)
            != self.hosts
        ):
            raise StatePersistenceError("diagnostic host evidence conflicts")
        expected_status = (
            EvidenceStatus.COMPLETE
            if all(host.status is EvidenceStatus.COMPLETE for host in self.hosts)
            else EvidenceStatus.UNAVAILABLE
            if all(host.status is EvidenceStatus.UNAVAILABLE for host in self.hosts)
            else EvidenceStatus.PARTIAL
        )
        if self.status is not expected_status:
            raise StatePersistenceError("diagnostic evidence status conflicts")

    @classmethod
    def create(
        cls,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        trust: StoredTrustRecord,
        collected: CollectedEvidence,
        *,
        generation: int,
        clock: Callable[[], datetime],
    ) -> "EvidenceRecord":
        identities = {
            (
                metadata.cluster_uuid,
                metadata.cluster_name,
                metadata.provider,
            ),
            (
                observed.record.cluster_uuid,
                observed.record.cluster_name,
                observed.record.provider,
            ),
            (
                inventory.record.cluster_uuid,
                inventory.record.cluster_name,
                inventory.record.provider,
            ),
            (
                trust.record.cluster_uuid,
                trust.record.cluster_name,
                trust.record.provider,
            ),
        }
        if len(identities) != 1:
            raise StatePersistenceError("diagnostic evidence identities conflict")
        if not trust.record.is_fresh_for(observed.record, inventory.record):
            raise StatePersistenceError("diagnostic evidence trust is stale")
        hosts = tuple(sorted(collected.hosts, key=lambda item: item.logical_id))
        inventory_roles = {
            host.logical_id: host.role for host in inventory.record.inventory.hosts
        }
        if any(inventory_roles.get(host.logical_id) is not host.role for host in hosts):
            raise StatePersistenceError("diagnostic evidence targets conflict")
        return cls(
            generation,
            metadata.cluster_uuid,
            metadata.cluster_name,
            metadata.provider,
            format_timestamp(clock()),
            observed.record.generation,
            observed.record.manifest_digest,
            observed.digest,
            inventory.record.generation,
            inventory.record.inventory_digest,
            inventory.digest,
            trust.record.generation,
            trust.digest,
            collected.status,
            tuple(host.logical_id for host in hosts),
            hosts,
        )

    def to_object(self) -> dict[str, object]:
        return {
            "captured_at": self.captured_at,
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "generation": self.generation,
            "hosts": [host.to_object() for host in self.hosts],
            "inventory_digest": self.inventory_digest,
            "inventory_file_digest": self.inventory_file_digest,
            "inventory_generation": self.inventory_generation,
            "observation_digest": self.observation_digest,
            "observation_file_digest": self.observation_file_digest,
            "observation_generation": self.observation_generation,
            "provider": self.provider,
            "schema_version": self.schema_version,
            "status": self.status.value,
            "target_ids": list(self.target_ids),
            "trust_digest": self.trust_digest,
            "trust_generation": self.trust_generation,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> "EvidenceRecord":
        require_exact_keys(
            value,
            {
                "captured_at",
                "cluster_name",
                "cluster_uuid",
                "generation",
                "hosts",
                "inventory_digest",
                "inventory_file_digest",
                "inventory_generation",
                "observation_digest",
                "observation_file_digest",
                "observation_generation",
                "provider",
                "schema_version",
                "status",
                "target_ids",
                "trust_digest",
                "trust_generation",
            },
            "diagnostic evidence",
        )
        hosts_value = value["hosts"]
        targets_value = value["target_ids"]
        hosts_array = _array(hosts_value, "diagnostic evidence hosts", _MAX_HOSTS)
        targets_array = _array(
            targets_value, "diagnostic evidence target IDs", _MAX_HOSTS
        )
        return cls(
            _positive_int(value["generation"], "evidence generation"),
            parse_uuid(require_string(value, "cluster_uuid"), "evidence cluster UUID"),
            require_string(value, "cluster_name"),
            require_string(value, "provider"),
            require_string(value, "captured_at"),
            _positive_int(
                value["observation_generation"], "evidence observation generation"
            ),
            require_string(value, "observation_digest"),
            require_string(value, "observation_file_digest"),
            _positive_int(
                value["inventory_generation"], "evidence inventory generation"
            ),
            require_string(value, "inventory_digest"),
            require_string(value, "inventory_file_digest"),
            _positive_int(value["trust_generation"], "evidence trust generation"),
            require_string(value, "trust_digest"),
            _status(value["status"], "evidence status"),
            tuple(_strings(targets_array, "evidence target IDs")),
            tuple(_host_from_object(item) for item in hosts_array),
            require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredEvidenceRecord:
    record: EvidenceRecord
    digest: str


class EvidenceStore:
    def __init__(
        self,
        paths: StatePaths,
        *,
        replace: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self._paths = paths
        self._file = AtomicJsonFile(
            paths.diagnostics_evidence,
            replace=replace,
            token_factory=token_factory,
        )

    def read(self) -> StoredEvidenceRecord:
        value, digest = self._file.read()
        return StoredEvidenceRecord(EvidenceRecord.from_object(value), digest)

    def write_locked(
        self,
        record: EvidenceRecord,
        observed: StoredObservedState,
        inventory: StoredInventoryRecord,
        trust: StoredTrustRecord,
        *,
        approved: bool,
        expected_generation: int,
        expected_digest: str | None,
        lock: "ClusterLock",
    ) -> StoredEvidenceRecord:
        if not approved:
            raise StatePersistenceError(
                "diagnostic evidence persistence requires explicit approval"
            )
        lock.assert_held_for(self._paths)
        if (
            record.cluster_uuid != observed.record.cluster_uuid
            or record.cluster_name != observed.record.cluster_name
            or record.provider != observed.record.provider
            or record.observation_generation != observed.record.generation
            or record.observation_digest != observed.record.manifest_digest
            or record.observation_file_digest != observed.digest
            or record.inventory_generation != inventory.record.generation
            or record.inventory_digest != inventory.record.inventory_digest
            or record.inventory_file_digest != inventory.digest
            or record.trust_generation != trust.record.generation
            or record.trust_digest != trust.digest
            or not trust.record.is_fresh_for(observed.record, inventory.record)
        ):
            raise StatePersistenceError("diagnostic evidence source bindings are stale")
        validate_state_file(self._paths.diagnostics_evidence, allow_missing=True)
        exists = self._paths.diagnostics_evidence.exists()
        if exists:
            current = self.read()
            if (
                expected_digest != current.digest
                or expected_generation != current.record.generation
                or record.generation != current.record.generation + 1
            ):
                raise StatePersistenceError("diagnostic evidence changed concurrently")
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
        ):
            raise StatePersistenceError("initial diagnostic evidence guard failed")
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredEvidenceRecord(record, digest)


def parse_collected_evidence(
    stdout: str,
    inventory: StoredInventoryRecord,
    expected_hosts: tuple[str, ...],
    exit_code: int,
) -> CollectedEvidence:
    if len(stdout.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise AnsibleError("Ansible evidence output exceeds the evidence limit")
    if len(expected_hosts) > _MAX_HOSTS:
        raise AnsibleError("Ansible evidence target count exceeds the limit")
    connectivity = parse_connectivity_evidence(stdout, expected_hosts, exit_code)
    inventory_hosts = {
        host.logical_id: host for host in inventory.record.inventory.hosts
    }
    parsed: dict[str, HostEvidence] = {}
    for line in stdout.splitlines():
        if "DSV_EVIDENCE_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible host evidence marker is malformed")
        try:
            encoded = base64.b64decode(match.group("data"), validate=True)
        except (binascii.Error, ValueError) as error:
            raise AnsibleError("Ansible host evidence encoding is invalid") from error
        if len(encoded) > _MAX_HOST_BYTES:
            raise AnsibleError("Ansible host evidence exceeds the host limit")
        try:
            value = json.loads(
                encoded.decode("utf-8"),
                object_pairs_hook=_strict_json_object,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise AnsibleError("Ansible host evidence JSON is invalid") from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible host evidence must be an object")
        parsed_host = _host_from_ansible_object(cast(dict[str, object], value))
        if parsed_host.logical_id in parsed:
            raise AnsibleError("Ansible host evidence is duplicated")
        parsed[parsed_host.logical_id] = parsed_host
    host_statuses = {item.logical_id: item.status for item in connectivity.hosts}
    extra = set(parsed) - set(expected_hosts)
    if extra:
        raise AnsibleError("Ansible host evidence membership conflicts")
    hosts: list[HostEvidence] = []
    for logical_id in sorted(expected_hosts):
        expected = inventory_hosts.get(logical_id)
        if expected is None:
            raise AnsibleError("Ansible host evidence target is unknown")
        host = parsed.get(logical_id)
        if host is None:
            connection = host_statuses[logical_id]
            if connection is HostConnectivityStatus.REACHABLE:
                raise AnsibleError("Ansible host evidence is incomplete")
            error_code = (
                "host-unreachable"
                if connection is HostConnectivityStatus.UNREACHABLE
                else "host-failed"
            )
            host = _unavailable_host(logical_id, expected.role, error_code)
        if host.role is not expected.role:
            raise AnsibleError("Ansible host evidence role conflicts")
        hosts.append(host)
    if all(host.status is EvidenceStatus.COMPLETE for host in hosts):
        status = EvidenceStatus.COMPLETE
    elif all(host.status is EvidenceStatus.UNAVAILABLE for host in hosts):
        status = EvidenceStatus.UNAVAILABLE
    else:
        status = EvidenceStatus.PARTIAL
    return CollectedEvidence(status, tuple(hosts))


def _host_from_ansible_object(value: Mapping[str, object]) -> HostEvidence:
    try:
        return _host_from_object(value)
    except StatePersistenceError as error:
        raise AnsibleError("Ansible host evidence schema is invalid") from error


def _host_from_object(value: object) -> HostEvidence:
    if not isinstance(value, dict):
        raise StatePersistenceError("diagnostic host evidence must be an object")
    data = cast(dict[str, object], value)
    require_exact_keys(
        data,
        {
            "block_devices",
            "errors",
            "filesystems",
            "logical_id",
            "role",
            "schema_version",
            "scylla_health",
            "service_version",
            "services",
            "status",
            "system",
        },
        "diagnostic host evidence",
    )
    if require_string(data, "schema_version") != HOST_EVIDENCE_SCHEMA_VERSION:
        raise StatePersistenceError("diagnostic host evidence schema is unsupported")
    try:
        role = HostRole(require_string(data, "role"))
    except ValueError as error:
        raise StatePersistenceError("diagnostic host role is invalid") from error
    system = _system(data["system"])
    filesystem_status, filesystems = _filesystems(data["filesystems"])
    block_device_status, block_devices = _block_devices(data["block_devices"])
    services = _services(data["services"], role)
    version = _object(data["service_version"], "service version")
    require_exact_keys(version, {"status", "value"}, "service version")
    version_status = require_string(version, "status")
    version_value = version["value"]
    if (
        version_status not in {"available", "not-performed", "unavailable"}
        or ((role is HostRole.JUMP_HOST) != (version_status == "not-performed"))
        or (version_status == "available") != (version_value is not None)
        or (
            version_value is not None
            and (
                not isinstance(version_value, str)
                or _SAFE_TEXT.fullmatch(version_value) is None
                or _SECRET_TEXT.search(version_value) is not None
            )
        )
    ):
        raise StatePersistenceError("diagnostic service version is invalid")
    health = _object(data["scylla_health"], "Scylla health")
    require_exact_keys(health, {"status"}, "Scylla health")
    health_status = require_string(health, "status")
    allowed_health = (
        {"failed", "passed", "unavailable"}
        if role is HostRole.SCYLLA
        else {"not-performed"}
    )
    if health_status not in allowed_health:
        raise StatePersistenceError("diagnostic Scylla health is invalid")
    errors = tuple(_strings(data["errors"], "diagnostic errors"))
    if errors != tuple(sorted(set(errors))) or not set(errors) <= _ERRORS:
        raise StatePersistenceError("diagnostic errors are invalid")
    logical_id = require_string(data, "logical_id")
    if _LOGICAL_ID.fullmatch(logical_id) is None:
        raise StatePersistenceError("diagnostic logical host ID is invalid")
    return HostEvidence(
        logical_id,
        role,
        _status(data["status"], "host evidence status"),
        system,
        filesystem_status,
        filesystems,
        block_device_status,
        block_devices,
        services,
        version_status,
        version_value,
        health_status,
        errors,
    )


def _system(value: object) -> dict[str, object]:
    data = _object(value, "diagnostic system")
    keys = {
        "architecture",
        "cpu_count",
        "current_time",
        "kernel",
        "memory_mib",
        "os_name",
        "os_version",
        "uptime_seconds",
    }
    require_exact_keys(data, keys, "diagnostic system")
    normalized = dict(data)
    for name in ("cpu_count", "memory_mib", "uptime_seconds"):
        item = data[name]
        if isinstance(item, str) and item.isascii() and item.isdigit():
            item = int(item)
        if item is not None and (
            isinstance(item, bool) or not isinstance(item, int) or item < 0
        ):
            raise StatePersistenceError("diagnostic system number is invalid")
        normalized[name] = item
    for name in ("architecture", "kernel", "os_name", "os_version"):
        item = data[name]
        if item is not None and (
            not isinstance(item, str) or _SAFE_TEXT.fullmatch(item) is None
        ):
            raise StatePersistenceError("diagnostic system text is invalid")
    current = data["current_time"]
    if current is not None:
        if not isinstance(current, str):
            raise StatePersistenceError("diagnostic system time is invalid")
        parse_timestamp(current)
    return {name: normalized[name] for name in sorted(keys)}


def _filesystems(
    value: object,
) -> tuple[str, tuple[FilesystemEvidence, ...]]:
    envelope = _object(value, "diagnostic filesystems")
    require_exact_keys(envelope, {"items", "status"}, "diagnostic filesystems")
    status = require_string(envelope, "status")
    values = _array(envelope["items"], "diagnostic filesystems", 16)
    result: list[FilesystemEvidence] = []
    for item in values:
        data = _object(item, "diagnostic filesystem")
        require_exact_keys(
            data,
            {"available_bytes", "mount", "total_bytes", "used_percent"},
            "diagnostic filesystem",
        )
        mount = require_string(data, "mount")
        total = _nonnegative_int(data["total_bytes"], "filesystem total")
        available = _nonnegative_int(data["available_bytes"], "filesystem available")
        used = data["used_percent"]
        if (
            mount not in _MOUNTS
            or available > total
            or (
                used is not None
                and (
                    isinstance(used, bool)
                    or not isinstance(used, (int, float))
                    or not 0 <= float(used) <= 100
                )
            )
        ):
            raise StatePersistenceError("diagnostic filesystem is invalid")
        result.append(
            FilesystemEvidence(
                mount, total, available, None if used is None else float(used)
            )
        )
    if tuple(item.mount for item in result) != tuple(
        sorted(set(item.mount for item in result))
    ):
        raise StatePersistenceError("diagnostic filesystems are not ordered")
    if status not in {"available", "unavailable"} or (
        (status == "available") != bool(result)
    ):
        raise StatePersistenceError("diagnostic filesystem status is invalid")
    return status, tuple(result)


def _block_devices(
    value: object,
) -> tuple[str, tuple[BlockDeviceEvidence, ...]]:
    envelope = _object(value, "diagnostic block devices")
    require_exact_keys(envelope, {"items", "status"}, "diagnostic block devices")
    status = require_string(envelope, "status")
    values = _array(envelope["items"], "diagnostic block devices", 64)
    result: list[BlockDeviceEvidence] = []
    for item in values:
        data = _object(item, "diagnostic block device")
        require_exact_keys(
            data, {"name", "rotational", "size"}, "diagnostic block device"
        )
        name = require_string(data, "name")
        size = data["size"]
        rotational = data["rotational"]
        if (
            _DEVICE_NAME.fullmatch(name) is None
            or (
                size is not None
                and (not isinstance(size, str) or _DEVICE_SIZE.fullmatch(size) is None)
            )
            or (
                rotational is not None
                and not isinstance(rotational, bool)
                and not (
                    isinstance(rotational, int)
                    and not isinstance(rotational, bool)
                    and rotational in {0, 1}
                )
                and rotational not in {"0", "1"}
            )
        ):
            raise StatePersistenceError("diagnostic block device is invalid")
        normalized = (
            None if rotational is None else str(rotational).lower() in {"1", "true"}
        )
        result.append(BlockDeviceEvidence(name, size, normalized))
    if tuple(item.name for item in result) != tuple(
        sorted(set(item.name for item in result))
    ):
        raise StatePersistenceError("diagnostic block devices are not ordered")
    if status not in {"available", "unavailable"} or (
        (status == "available") != bool(result)
    ):
        raise StatePersistenceError("diagnostic block-device status is invalid")
    return status, tuple(result)


def _services(value: object, role: HostRole) -> tuple[ServiceEvidence, ...]:
    values = _array(value, "diagnostic services", 8)
    result: list[ServiceEvidence] = []
    for item in values:
        data = _object(item, "diagnostic service")
        require_exact_keys(data, {"name", "status"}, "diagnostic service")
        name = require_string(data, "name")
        status = require_string(data, "status")
        if name not in _SERVICES[role] or status not in {
            "active",
            "inactive",
            "running",
            "stopped",
            "unknown",
            "unavailable",
        }:
            raise StatePersistenceError("diagnostic service is invalid")
        result.append(ServiceEvidence(name, status))
    if tuple(item.name for item in result) != tuple(sorted(_SERVICES[role])):
        raise StatePersistenceError("diagnostic services are not ordered")
    return tuple(result)


def _unavailable_host(logical_id: str, role: HostRole, error: str) -> HostEvidence:
    return HostEvidence(
        logical_id,
        role,
        EvidenceStatus.UNAVAILABLE,
        {
            name: None
            for name in (
                "architecture",
                "cpu_count",
                "current_time",
                "kernel",
                "memory_mib",
                "os_name",
                "os_version",
                "uptime_seconds",
            )
        },
        "unavailable",
        (),
        "unavailable",
        (),
        (),
        ("not-performed" if role is HostRole.JUMP_HOST else "unavailable"),
        None,
        "unavailable" if role is HostRole.SCYLLA else "not-performed",
        (error,),
    )


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _array(value: object, label: str, maximum: int) -> list[object]:
    if not isinstance(value, list) or len(value) > maximum:
        raise StatePersistenceError(f"{label} must be a bounded array")
    return cast(list[object], value)


def _strings(value: object, label: str) -> list[str]:
    values = _array(value, label, 256)
    if not all(isinstance(item, str) for item in values):
        raise StatePersistenceError(f"{label} must contain strings")
    return cast(list[str], values)


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StatePersistenceError(f"{label} must be nonnegative")
    return value


def _status(value: object, label: str) -> EvidenceStatus:
    if not isinstance(value, str):
        raise StatePersistenceError(f"{label} is invalid")
    try:
        return EvidenceStatus(value)
    except (TypeError, ValueError) as error:
        raise StatePersistenceError(f"{label} is invalid") from error


def _strict_json_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number: {value}")
