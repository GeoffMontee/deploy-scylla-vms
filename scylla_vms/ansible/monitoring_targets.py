"""Strict Scylla Monitoring 4.16.0 inventory target-file evidence."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from scylla_vms.ansible.base_os import BaseOsEvidence, BaseOsStatus
from scylla_vms.ansible.monitoring_stack import (
    ARTIFACT_DIGEST,
    INSTALL_ROOT,
    LISTEN_POLICY,
    SOURCE_COMMIT,
    STACK_RELEASE_LINE,
    STACK_SERVICE_UNIT,
    STACK_VERSION,
    MonitoringStackEvidence,
    MonitoringStackStatus,
)
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.desired import HostRole, ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import InventoryHost, StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata

MONITORING_TARGETS_SCHEMA_VERSION = "deploy-scylla-vms.ansible-monitoring-targets/v1"
TARGET_DIRECTORY = f"{INSTALL_ROOT}/prometheus"
SCRAPE_READINESS = "not-performed"
MANAGER_METRICS_PORT = 5090
SCRAPE_PORTS = {
    "manager": MANAGER_METRICS_PORT,
    "manager_agent": 5090,
    "node_exporter": 9100,
    "scylla": 9180,
}
TARGET_FILES = (
    "scylla_servers.yml",
    "node_exporter_servers.yml",
    "scylla_manager_agents.yml",
    "scylla_manager_servers.yml",
)
_RFC1918 = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_LABEL = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MARKER = re.compile(r"DSV_MONITORING_TARGETS_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_BLOCKERS = frozenset(
    {
        "containers-started",
        "execution-failed",
        "file-mismatch",
        "service-active",
        "service-enabled",
    }
)
_LISTEN = frozenset({"not-started"})
_SCRAPE = frozenset({"not-performed"})
_NOT_PERFORMED_FALSE = (
    "auth_configured",
    "compose_generated",
    "containers_started",
    "exporters_started",
    "manager_registration_performed",
    "public_bind",
    "scrape_performed",
    "scylla_started",
    "secrets_written",
    "stack_started",
)


class MonitoringTargetsStatus(StrEnum):
    GENERATED = "generated"
    NO_CHANGE = "no-change"
    NOT_PREDICTED = "not-predicted"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class MonitoringTargetsEvidence:
    logical_id: str
    status: MonitoringTargetsStatus
    stack_version: str
    install_root: str
    files: tuple[tuple[str, str], ...]
    target_counts: tuple[tuple[str, int], ...]
    identities: tuple[tuple[str, tuple[str, ...]], ...]
    documented_scrape_ports: tuple[tuple[str, int], ...]
    listen_policy: str
    scrape_readiness: str
    scrape_performed: bool
    exporters_started: bool
    stack_started: bool
    containers_started: bool
    auth_configured: bool
    public_bind: bool
    manager_registration_performed: bool
    scylla_started: bool
    secrets_written: bool
    compose_generated: bool
    provenance: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]
    schema_version: str = MONITORING_TARGETS_SCHEMA_VERSION


def build_monitoring_targets_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    base_os: BaseOsEvidence,
    stack: MonitoringStackEvidence,
    *,
    logical_id: str,
    image_filter: ImageFilter,
    architecture: str,
    cluster_spec_digest: str,
) -> dict[str, object]:
    """Build official 4.16.0 target files after current stack prerequisites."""

    if image_filter != ImageFilter(
        "Ubuntu", "24.04", ImageVersionMatch.EXACT
    ) or architecture not in {"amd64", "aarch64"}:
        raise StateConflictError(
            "Monitoring target generation requires exact Ubuntu 24.04 evidence"
        )
    if (
        len(base_os.hosts) != 1
        or base_os.hosts[0].logical_id != logical_id
        or base_os.hosts[0].status not in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
        or base_os.hosts[0].reboot_required
    ):
        raise StateConflictError(
            "Monitoring target generation requires successful current base-os"
        )
    record = inventory.record
    if (
        metadata.cluster_uuid != record.cluster_uuid
        or metadata.cluster_name != record.cluster_name
        or observed.record.cluster_uuid != record.cluster_uuid
        or readiness.observation_generation != observed.record.generation
        or readiness.observation_digest != observed.digest
        or readiness.inventory_generation != record.generation
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_generation is None
        or readiness.trust_digest is None
    ):
        raise StateConflictError("Monitoring target input provenance conflicts")
    hosts = record.inventory.hosts
    monitoring_ids = {
        host.logical_id for host in hosts if host.role is HostRole.MONITORING
    }
    if logical_id not in monitoring_ids:
        raise StateConflictError(
            "Monitoring target generation target is not a monitoring stable ID"
        )
    _require_current_stack(stack, logical_id, observed, inventory)
    cluster = _label(metadata.cluster_name, "cluster")
    scylla_hosts = tuple(
        sorted(
            (host for host in hosts if host.role is HostRole.SCYLLA),
            key=lambda host: host.logical_id,
        )
    )
    manager_hosts = tuple(host for host in hosts if host.role is HostRole.MANAGER)
    if not scylla_hosts:
        raise StateConflictError("Monitoring target generation requires Scylla hosts")
    if len(manager_hosts) != 1:
        raise StateConflictError(
            "Monitoring target generation requires exactly one Manager host"
        )
    grouped = _scylla_groups(scylla_hosts)
    scylla_yaml = _render_scylla_servers(cluster, grouped)
    manager_yaml = _render_manager_servers(
        _rfc1918_ipv4(manager_hosts[0].private_address)
    )
    files = (
        _file("scylla_servers.yml", scylla_yaml),
        _file("node_exporter_servers.yml", scylla_yaml),
        _file("scylla_manager_agents.yml", scylla_yaml),
        _file("scylla_manager_servers.yml", manager_yaml),
    )
    scylla_identities = tuple(
        sorted(_identity_digest(host.logical_id) for host in scylla_hosts)
    )
    manager_identities = (_identity_digest(manager_hosts[0].logical_id),)
    identities = {
        "manager": list(manager_identities),
        "manager_agent": list(scylla_identities),
        "node_exporter": list(scylla_identities),
        "scylla": list(scylla_identities),
    }
    target_counts = {
        "manager": 1,
        "manager_agent": len(scylla_hosts),
        "node_exporter": len(scylla_hosts),
        "scylla": len(scylla_hosts),
    }
    provenance = {
        "agent_target_digest": _object_digest(
            {
                "manager_agent": list(scylla_identities),
                "node_exporter": list(scylla_identities),
            }
        ),
        "base_os_digest": _object_digest(_base_os_object(base_os)),
        "cluster_spec_digest": _require_digest(cluster_spec_digest),
        "inventory_digest": inventory.digest,
        "monitoring_stack_digest": _object_digest(_stack_object(stack)),
        "observation_digest": observed.digest,
        "trust_digest": readiness.trust_digest,
    }
    return {
        "architecture": architecture,
        "auth_configured": False,
        "cluster_uuid": str(metadata.cluster_uuid),
        "compose_generated": False,
        "containers_started": False,
        "documented_scrape_ports": dict(SCRAPE_PORTS),
        "exporters_started": False,
        "file_digests": {item["path"]: item["digest"] for item in files},
        "files": [dict(item) for item in files],
        "identities": identities,
        "image_operating_system": "Ubuntu",
        "image_operating_system_version": "24.04",
        "install_root": INSTALL_ROOT,
        "listen_policy": LISTEN_POLICY,
        "logical_id": logical_id,
        "manager_registration_performed": False,
        "provenance": provenance,
        "public_bind": False,
        "release_line": STACK_RELEASE_LINE,
        "schema_version": MONITORING_TARGETS_SCHEMA_VERSION,
        "scrape_performed": False,
        "scrape_readiness": SCRAPE_READINESS,
        "scylla_started": False,
        "secrets_written": False,
        "service_unit": STACK_SERVICE_UNIT,
        "source_commit": SOURCE_COMMIT,
        "stack_started": False,
        "stack_version": STACK_VERSION,
        "target_counts": target_counts,
        "target_directory": TARGET_DIRECTORY,
    }


def parse_monitoring_targets_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> MonitoringTargetsEvidence:
    """Parse only the bounded normalized result and recap."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError(
            "Ansible monitoring targets output exceeds the evidence limit"
        )
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_MONITORING_TARGETS_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible monitoring targets marker is malformed")
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"), object_pairs_hook=_strict_object
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible monitoring targets marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible monitoring targets evidence is malformed")
        values.append(value)
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible monitoring targets output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible monitoring targets recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    logical_id = _text(expected_payload["logical_id"])
    if set(rows) != {logical_id}:
        raise AnsibleError("Ansible monitoring targets recap membership conflicts")
    recap_failed = bool(rows[logical_id][1] or rows[logical_id][2])
    if not values:
        if not recap_failed or exit_code == 0:
            raise AnsibleError("Ansible monitoring targets evidence is incomplete")
        return _failed_evidence(expected_payload)
    if len(values) != 1:
        raise AnsibleError("Ansible monitoring targets evidence is duplicated")
    evidence = _parse_result(values[0], expected_payload)
    failed = evidence.status is MonitoringTargetsStatus.FAILED
    if recap_failed != failed or (exit_code == 0) == failed:
        raise AnsibleError("Ansible monitoring targets exit status conflicts")
    changed = evidence.status is MonitoringTargetsStatus.GENERATED
    if bool(rows[logical_id][0]) != changed:
        raise AnsibleError("Ansible monitoring targets changed status conflicts")
    return evidence


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> MonitoringTargetsEvidence:
    expected_fields = {
        "auth_configured",
        "blockers",
        "compose_generated",
        "containers_started",
        "documented_scrape_ports",
        "exporters_started",
        "files",
        "identities",
        "install_root",
        "listen_policy",
        "logical_id",
        "manager_registration_performed",
        "provenance",
        "public_bind",
        "schema_version",
        "scrape_performed",
        "scrape_readiness",
        "scylla_started",
        "secrets_written",
        "stack_started",
        "stack_version",
        "status",
        "target_counts",
    }
    if (
        set(value) != expected_fields
        or value["schema_version"] != MONITORING_TARGETS_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible monitoring targets evidence schema is invalid")
    logical_id = _text(value["logical_id"])
    stack_version = _text(value["stack_version"])
    install_root = _text(value["install_root"])
    listen_policy = _text(value["listen_policy"])
    scrape_readiness = _text(value["scrape_readiness"])
    if (
        logical_id != expected["logical_id"]
        or stack_version != expected["stack_version"]
        or install_root != expected["install_root"]
        or listen_policy != expected["listen_policy"]
        or listen_policy not in _LISTEN
        or scrape_readiness != expected["scrape_readiness"]
        or scrape_readiness not in _SCRAPE
    ):
        raise AnsibleError("Ansible monitoring targets evidence conflicts")
    try:
        status = MonitoringTargetsStatus(_text(value["status"]))
    except ValueError as error:
        raise AnsibleError("Ansible monitoring targets status is invalid") from error
    files = _parse_files(value["files"], expected, status)
    target_counts = _parse_counts(value["target_counts"], expected)
    identities = _parse_identities(value["identities"], expected)
    ports_value = value["documented_scrape_ports"]
    if not isinstance(ports_value, dict):
        raise AnsibleError("Ansible monitoring targets ports are invalid")
    documented_ports = tuple(
        sorted((_text(name), _require_port(port)) for name, port in ports_value.items())
    )
    blockers = _sorted_strings(value["blockers"])
    if not set(blockers) <= _BLOCKERS:
        raise AnsibleError("Ansible monitoring targets blocker is unknown")
    provenance_value = value["provenance"]
    expected_provenance = cast(dict[str, object], expected["provenance"])
    if (
        not isinstance(provenance_value, dict)
        or provenance_value != expected_provenance
    ):
        raise AnsibleError("Ansible monitoring targets provenance conflicts")
    provenance = tuple(
        sorted(
            (_text(name), _require_digest(item))
            for name, item in provenance_value.items()
        )
    )
    flags = {name: _require_bool(value[name]) for name in _NOT_PERFORMED_FALSE}
    expected_ports = tuple(
        sorted(cast(dict[str, int], expected["documented_scrape_ports"]).items())
    )
    deferred = any(flags.values())
    success = status in {
        MonitoringTargetsStatus.GENERATED,
        MonitoringTargetsStatus.NO_CHANGE,
    }
    if success and (
        not files
        or documented_ports != expected_ports
        or listen_policy != LISTEN_POLICY
        or scrape_readiness != SCRAPE_READINESS
        or deferred
        or blockers
    ):
        raise AnsibleError("Ansible monitoring targets success evidence conflicts")
    if status is MonitoringTargetsStatus.NOT_PREDICTED and (
        files
        or documented_ports != expected_ports
        or listen_policy != LISTEN_POLICY
        or scrape_readiness != SCRAPE_READINESS
        or deferred
        or blockers
    ):
        raise AnsibleError("Ansible monitoring targets check evidence conflicts")
    if status is MonitoringTargetsStatus.FAILED and (
        files
        or documented_ports != expected_ports
        or listen_policy != LISTEN_POLICY
        or scrape_readiness != SCRAPE_READINESS
        or deferred
        or not blockers
    ):
        raise AnsibleError("Ansible monitoring targets failure evidence conflicts")
    _reject_addresses(value)
    return MonitoringTargetsEvidence(
        logical_id,
        status,
        stack_version,
        install_root,
        files,
        target_counts,
        identities,
        documented_ports,
        listen_policy,
        scrape_readiness,
        flags["scrape_performed"],
        flags["exporters_started"],
        flags["stack_started"],
        flags["containers_started"],
        flags["auth_configured"],
        flags["public_bind"],
        flags["manager_registration_performed"],
        flags["scylla_started"],
        flags["secrets_written"],
        flags["compose_generated"],
        provenance,
        blockers,
    )


def _failed_evidence(expected: dict[str, object]) -> MonitoringTargetsEvidence:
    provenance = cast(dict[str, object], expected["provenance"])
    counts = tuple(sorted(cast(dict[str, int], expected["target_counts"]).items()))
    identities = tuple(
        sorted(
            (role, tuple(items))
            for role, items in cast(
                dict[str, list[str]], expected["identities"]
            ).items()
        )
    )
    ports = tuple(
        sorted(cast(dict[str, int], expected["documented_scrape_ports"]).items())
    )
    return MonitoringTargetsEvidence(
        _text(expected["logical_id"]),
        MonitoringTargetsStatus.FAILED,
        _text(expected["stack_version"]),
        _text(expected["install_root"]),
        (),
        counts,
        identities,
        ports,
        LISTEN_POLICY,
        SCRAPE_READINESS,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        tuple(sorted((_text(k), _require_digest(v)) for k, v in provenance.items())),
        ("execution-failed",),
    )


def _require_current_stack(
    stack: MonitoringStackEvidence,
    logical_id: str,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
) -> None:
    provenance = dict(stack.provenance)
    if (
        stack.logical_id != logical_id
        or stack.status
        not in {MonitoringStackStatus.INSTALLED, MonitoringStackStatus.NO_CHANGE}
        or stack.requested_version != STACK_VERSION
        or stack.installed_version != STACK_VERSION
        or stack.artifact_digest != ARTIFACT_DIGEST
        or stack.source_commit != SOURCE_COMMIT
        or stack.listen_policy != LISTEN_POLICY
        or stack.containers_started
        or stack.public_bind
        or stack.auth_configured
        or stack.compose_generated
        or stack.secrets_written
        or stack.scylla_started
        or stack.manager_registration_performed
        or provenance.get("inventory_digest") != inventory.digest
        or provenance.get("observation_digest") != observed.digest
    ):
        raise StateConflictError(
            "Monitoring target generation requires successful current monitoring-stack"
        )


def _scylla_groups(
    hosts: tuple[InventoryHost, ...],
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    grouped: dict[str, list[str]] = {}
    seen: set[str] = set()
    for host in hosts:
        datacenter = host.scylla_datacenter
        if datacenter is None:
            raise StateConflictError(
                "Monitoring Scylla targets require a datacenter label"
            )
        label = _label(datacenter, "datacenter")
        address = _rfc1918_ipv4(host.private_address)
        if address in seen:
            raise StateConflictError("Monitoring Scylla scrape addresses collide")
        seen.add(address)
        grouped.setdefault(label, []).append(address)
    return tuple(
        (datacenter, tuple(sorted(addresses)))
        for datacenter, addresses in sorted(grouped.items())
    )


def _render_scylla_servers(
    cluster: str, groups: tuple[tuple[str, tuple[str, ...]], ...]
) -> str:
    lines = ["# List Scylla end points", ""]
    for datacenter, addresses in groups:
        lines.append("- targets:")
        for address in addresses:
            lines.append(f"  - {address}")
        lines.append("  labels:")
        lines.append(f"    cluster: {cluster}")
        lines.append(f"    dc: {datacenter}")
    return "\n".join(lines) + "\n"


def _render_manager_servers(address: str) -> str:
    return (
        "# List Scylla Manager end points\n"
        "\n"
        "- targets:\n"
        f"  - {address}:{MANAGER_METRICS_PORT}\n"
    )


def _file(name: str, content: str) -> dict[str, str]:
    if name not in TARGET_FILES:
        raise AnsibleError("Monitoring target file name is not official")
    return {
        "content": content,
        "digest": _text_digest(content),
        "name": name,
        "path": f"{TARGET_DIRECTORY}/{name}",
    }


def _parse_files(
    value: object,
    expected: dict[str, object],
    status: MonitoringTargetsStatus,
) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict):
        raise AnsibleError("Ansible monitoring targets files are invalid")
    files = tuple(
        sorted((_text(path), _require_digest(digest)) for path, digest in value.items())
    )
    expected_files = tuple(
        sorted(
            (_text(item["path"]), _text(item["digest"]))
            for item in cast(list[dict[str, str]], expected["files"])
        )
    )
    if status in {
        MonitoringTargetsStatus.GENERATED,
        MonitoringTargetsStatus.NO_CHANGE,
    }:
        if files != expected_files:
            raise AnsibleError("Ansible monitoring targets file evidence conflicts")
    elif files:
        raise AnsibleError("Ansible monitoring targets file evidence conflicts")
    return files


def _parse_counts(
    value: object, expected: dict[str, object]
) -> tuple[tuple[str, int], ...]:
    if not isinstance(value, dict):
        raise AnsibleError("Ansible monitoring targets counts are invalid")
    counts = tuple(
        sorted((_text(role), _require_count(count)) for role, count in value.items())
    )
    expected_counts = tuple(
        sorted(cast(dict[str, int], expected["target_counts"]).items())
    )
    if counts != expected_counts:
        raise AnsibleError("Ansible monitoring targets count evidence conflicts")
    return counts


def _parse_identities(
    value: object, expected: dict[str, object]
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if not isinstance(value, dict):
        raise AnsibleError("Ansible monitoring targets identities are invalid")
    identities = tuple(
        sorted((_text(role), _sorted_digests(items)) for role, items in value.items())
    )
    expected_identities = tuple(
        sorted(
            (role, tuple(items))
            for role, items in cast(
                dict[str, list[str]], expected["identities"]
            ).items()
        )
    )
    if identities != expected_identities:
        raise AnsibleError("Ansible monitoring targets identity evidence conflicts")
    return identities


def _reject_addresses(value: dict[str, object]) -> None:
    encoded = json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True)
    if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", encoded) is not None:
        raise AnsibleError("Ansible monitoring targets evidence contains an address")
    if "content" in encoded:
        raise AnsibleError("Ansible monitoring targets evidence contains file content")


def _stack_object(value: MonitoringStackEvidence) -> dict[str, object]:
    return {
        "artifact_digest": value.artifact_digest,
        "containers_started": value.containers_started,
        "installed_version": value.installed_version,
        "listen_policy": value.listen_policy,
        "logical_id": value.logical_id,
        "provenance": dict(value.provenance),
        "public_bind": value.public_bind,
        "requested_version": value.requested_version,
        "schema_version": value.schema_version,
        "source_commit": value.source_commit,
        "status": value.status.value,
        "targets_generated": value.targets_generated,
    }


def _base_os_object(value: BaseOsEvidence) -> dict[str, object]:
    return {
        "hosts": [
            {
                "changed": host.changed,
                "logical_id": host.logical_id,
                "reason": host.reason,
                "reboot_required": host.reboot_required,
                "status": host.status.value,
            }
            for host in value.hosts
        ],
        "status": value.status.value,
    }


def _rfc1918_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise StateConflictError("Monitoring scrape address is invalid") from error
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or str(address) != value
        or not any(address in network for network in _RFC1918)
    ):
        raise StateConflictError("Monitoring scrape targets require RFC 1918 IPv4")
    return value


def _label(value: str, name: str) -> str:
    if _LABEL.fullmatch(value) is None or "--" in value or value.endswith("-"):
        raise StateConflictError(f"Monitoring target {name} label is invalid")
    return value


def _identity_digest(logical_id: str) -> str:
    return _text_digest(logical_id)


def _object_digest(value: object) -> str:
    data = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _text_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AnsibleError(
                "Ansible monitoring targets evidence has duplicate fields"
            )
        value[key] = item
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible monitoring targets value is invalid")
    return value


def _require_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError("Ansible monitoring targets boolean is invalid")
    return value


def _require_port(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise AnsibleError("Ansible monitoring targets port is invalid")
    return value


def _require_count(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise AnsibleError("Ansible monitoring targets count is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible monitoring targets digest is invalid")
    return text


def _sorted_strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible monitoring targets blockers are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError(
            "Ansible monitoring targets blockers are not uniquely sorted"
        )
    return items


def _sorted_digests(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible monitoring targets identities are invalid")
    items = tuple(_require_digest(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError(
            "Ansible monitoring targets identities are not uniquely sorted"
        )
    return items
