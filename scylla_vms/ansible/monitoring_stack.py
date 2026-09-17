"""Strict Scylla Monitoring 4.16.0 install-only stack evidence."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from scylla_vms.ansible.base_os import BaseOsEvidence, BaseOsStatus
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.desired import ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata

MONITORING_STACK_SCHEMA_VERSION = "deploy-scylla-vms.ansible-monitoring-stack/v1"
STACK_RELEASE_LINE = "4.16"
STACK_VERSION = "4.16.0"
STACK_CHANNEL = "stable"
STACK_SERVICE_UNIT = "docker.service"
LISTEN_POLICY = "not-started"
INSTALL_ROOT = "/opt/scylla-monitoring/4.16.0"
CACHE_PATH = "/var/cache/deploy-scylla-vms/scylla-monitoring-4.16.0.tar.gz"
SOURCE_COMMIT = "fac61b89b229a69d2af2d88b7e09a6316c3924e4"
ARTIFACT_URI = "https://github.com/scylladb/scylla-monitoring/archive/4.16.0.tar.gz"
ARTIFACT_DIGEST = (
    "sha256:3f016d90d3591fd01e7173a3c392b43a21316851a6290b6910dbc41be62fe7fc"
)
STACK_ARTIFACTS = {
    "alertmanager": "v0.34.0",
    "grafana": "13.2.0",
    "loki": "3.7.7",
    "prometheus": "v3.14.0",
    "promtail": "3.6.11",
    "stack": STACK_VERSION,
}
DOCUMENTED_PORTS = {
    "alertmanager": 9093,
    "grafana": 3000,
    "prometheus": 9090,
}
_STACK_VERSION = re.compile(r"4\.16\.0\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MARKER = re.compile(r"DSV_MONITORING_STACK_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_BLOCKERS = frozenset(
    {
        "artifact-mismatch",
        "containers-started",
        "execution-failed",
        "service-active",
        "service-enabled",
    }
)
_LISTEN = frozenset({"localhost", "not-started", "private"})
_NOT_PERFORMED_FALSE = (
    "auth_configured",
    "compose_generated",
    "containers_started",
    "manager_registration_performed",
    "public_bind",
    "scylla_started",
    "secrets_written",
    "targets_generated",
)


class MonitoringStackStatus(StrEnum):
    INSTALLED = "installed"
    NO_CHANGE = "no-change"
    NOT_PREDICTED = "not-predicted"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class MonitoringStackEvidence:
    logical_id: str
    status: MonitoringStackStatus
    requested_release: str
    requested_version: str
    installed_version: str | None
    artifacts: tuple[tuple[str, str], ...]
    artifact_digest: str
    source_commit: str
    service_enabled: bool | None
    service_inactive: bool | None
    containers_started: bool
    listen_policy: str
    documented_ports: tuple[tuple[str, int], ...]
    targets_generated: bool
    auth_configured: bool
    public_bind: bool
    manager_registration_performed: bool
    scylla_started: bool
    secrets_written: bool
    compose_generated: bool
    provenance: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]
    schema_version: str = MONITORING_STACK_SCHEMA_VERSION


def build_monitoring_stack_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    base_os: BaseOsEvidence,
    *,
    logical_id: str,
    image_filter: ImageFilter,
    architecture: str,
    stack_version: str,
    cluster_spec_digest: str,
) -> dict[str, object]:
    """Build one exact Monitoring-stack install intent after local prerequisites."""

    if image_filter != ImageFilter(
        "Ubuntu", "24.04", ImageVersionMatch.EXACT
    ) or architecture not in {"amd64", "aarch64"}:
        raise StateConflictError(
            "Monitoring stack install requires exact Ubuntu 24.04 evidence"
        )
    if _STACK_VERSION.fullmatch(stack_version) is None:
        raise AnsibleError(
            "Monitoring stack version must be the exact 4.16.0 release archive"
        )
    if (
        len(base_os.hosts) != 1
        or base_os.hosts[0].logical_id != logical_id
        or base_os.hosts[0].status not in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
        or base_os.hosts[0].reboot_required
    ):
        raise StateConflictError(
            "Monitoring stack install requires successful current base-os"
        )
    record = inventory.record
    if (
        metadata.cluster_uuid != record.cluster_uuid
        or metadata.cluster_name != record.cluster_name
        or observed.record.cluster_uuid != record.cluster_uuid
        or readiness.observation_generation != observed.record.generation
        or readiness.observation_digest != observed.record.manifest_digest
        or readiness.inventory_generation != record.generation
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_generation is None
        or readiness.trust_digest is None
    ):
        raise StateConflictError("Monitoring stack input provenance conflicts")
    host_ids = {
        host.logical_id
        for host in record.inventory.hosts
        if host.role.value == "monitoring"
    }
    if logical_id not in host_ids:
        raise StateConflictError(
            "Monitoring stack target is not a monitoring stable ID"
        )
    provenance = {
        "base_os_digest": _object_digest(_base_os_object(base_os)),
        "cluster_spec_digest": _require_digest(cluster_spec_digest),
        "inventory_digest": inventory.digest,
        "observation_digest": observed.digest,
        "trust_digest": readiness.trust_digest,
    }
    return {
        "architecture": architecture,
        "artifact": {
            "digest": ARTIFACT_DIGEST,
            "uri": ARTIFACT_URI,
        },
        "artifacts": dict(STACK_ARTIFACTS),
        "auth_configured": False,
        "cache_path": CACHE_PATH,
        "channel": STACK_CHANNEL,
        "cluster_uuid": str(metadata.cluster_uuid),
        "compose_generated": False,
        "containers_started": False,
        "documented_ports": dict(DOCUMENTED_PORTS),
        "image_operating_system": "Ubuntu",
        "image_operating_system_version": "24.04",
        "install_root": INSTALL_ROOT,
        "listen_policy": LISTEN_POLICY,
        "logical_id": logical_id,
        "manager_registration_performed": False,
        "provenance": provenance,
        "public_bind": False,
        "release_line": STACK_RELEASE_LINE,
        "schema_version": MONITORING_STACK_SCHEMA_VERSION,
        "scylla_started": False,
        "secrets_written": False,
        "service_unit": STACK_SERVICE_UNIT,
        "source_commit": SOURCE_COMMIT,
        "stack_version": stack_version,
        "targets_generated": False,
    }


def parse_monitoring_stack_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> MonitoringStackEvidence:
    """Parse only the bounded normalized result and recap."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError("Ansible monitoring stack output exceeds the evidence limit")
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_MONITORING_STACK_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible monitoring stack marker is malformed")
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"), object_pairs_hook=_strict_object
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible monitoring stack marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible monitoring stack evidence is malformed")
        values.append(value)
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible monitoring stack output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible monitoring stack recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    logical_id = _text(expected_payload["logical_id"])
    if set(rows) != {logical_id}:
        raise AnsibleError("Ansible monitoring stack recap membership conflicts")
    recap_failed = bool(rows[logical_id][1] or rows[logical_id][2])
    if not values:
        if not recap_failed or exit_code == 0:
            raise AnsibleError("Ansible monitoring stack evidence is incomplete")
        return _failed_evidence(expected_payload)
    if len(values) != 1:
        raise AnsibleError("Ansible monitoring stack evidence is duplicated")
    evidence = _parse_result(values[0], expected_payload)
    failed = evidence.status is MonitoringStackStatus.FAILED
    if recap_failed != failed or (exit_code == 0) == failed:
        raise AnsibleError("Ansible monitoring stack exit status conflicts")
    changed = evidence.status is MonitoringStackStatus.INSTALLED
    if bool(rows[logical_id][0]) != changed:
        raise AnsibleError("Ansible monitoring stack changed status conflicts")
    return evidence


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> MonitoringStackEvidence:
    expected_fields = {
        "artifact_digest",
        "artifacts",
        "auth_configured",
        "blockers",
        "compose_generated",
        "containers_started",
        "documented_ports",
        "installed_version",
        "listen_policy",
        "logical_id",
        "manager_registration_performed",
        "provenance",
        "public_bind",
        "requested_release",
        "requested_version",
        "schema_version",
        "scylla_started",
        "secrets_written",
        "service_enabled",
        "service_inactive",
        "source_commit",
        "status",
        "targets_generated",
    }
    if (
        set(value) != expected_fields
        or value["schema_version"] != MONITORING_STACK_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible monitoring stack evidence schema is invalid")
    logical_id = _text(value["logical_id"])
    requested_release = _text(value["requested_release"])
    requested_version = _text(value["requested_version"])
    listen_policy = _text(value["listen_policy"])
    source_commit = _text(value["source_commit"])
    if (
        logical_id != expected["logical_id"]
        or requested_release != expected["release_line"]
        or requested_version != expected["stack_version"]
        or listen_policy != expected["listen_policy"]
        or listen_policy not in _LISTEN
        or source_commit != expected["source_commit"]
    ):
        raise AnsibleError("Ansible monitoring stack evidence conflicts")
    try:
        status = MonitoringStackStatus(_text(value["status"]))
    except ValueError as error:
        raise AnsibleError("Ansible monitoring stack status is invalid") from error
    artifacts_value = value["artifacts"]
    if not isinstance(artifacts_value, dict):
        raise AnsibleError("Ansible monitoring stack artifacts are invalid")
    artifacts = tuple(
        sorted(
            (_text(name), _text(version)) for name, version in artifacts_value.items()
        )
    )
    ports_value = value["documented_ports"]
    if not isinstance(ports_value, dict):
        raise AnsibleError("Ansible monitoring stack ports are invalid")
    documented_ports = tuple(
        sorted((_text(name), _require_port(port)) for name, port in ports_value.items())
    )
    blockers = _sorted_strings(value["blockers"])
    if not set(blockers) <= _BLOCKERS:
        raise AnsibleError("Ansible monitoring stack blocker is unknown")
    provenance_value = value["provenance"]
    expected_provenance = cast(dict[str, object], expected["provenance"])
    if (
        not isinstance(provenance_value, dict)
        or provenance_value != expected_provenance
    ):
        raise AnsibleError("Ansible monitoring stack provenance conflicts")
    provenance = tuple(
        sorted(
            (_text(name), _require_digest(item))
            for name, item in provenance_value.items()
        )
    )
    installed_version = _optional_text(value["installed_version"])
    service_enabled = _optional_bool(value["service_enabled"])
    service_inactive = _optional_bool(value["service_inactive"])
    flags = {name: _require_bool(value[name]) for name in _NOT_PERFORMED_FALSE}
    artifact = cast(dict[str, object], expected["artifact"])
    artifact_digest = _require_digest(value["artifact_digest"])
    if artifact_digest != artifact["digest"]:
        raise AnsibleError("Ansible monitoring stack artifact provenance conflicts")
    expected_artifacts = tuple(
        sorted(cast(dict[str, str], expected["artifacts"]).items())
    )
    expected_ports = tuple(
        sorted(cast(dict[str, int], expected["documented_ports"]).items())
    )
    deferred = any(flags.values())
    success = status in {
        MonitoringStackStatus.INSTALLED,
        MonitoringStackStatus.NO_CHANGE,
    }
    if success and (
        installed_version != requested_version
        or artifacts != expected_artifacts
        or documented_ports != expected_ports
        or service_enabled is not False
        or service_inactive is not True
        or listen_policy != LISTEN_POLICY
        or deferred
        or blockers
    ):
        raise AnsibleError("Ansible monitoring stack success evidence conflicts")
    if status is MonitoringStackStatus.NOT_PREDICTED and (
        installed_version is not None
        or artifacts
        or documented_ports != expected_ports
        or service_enabled is not None
        or service_inactive is not None
        or listen_policy != LISTEN_POLICY
        or deferred
        or blockers
    ):
        raise AnsibleError("Ansible monitoring stack check evidence conflicts")
    if status is MonitoringStackStatus.FAILED and (
        installed_version is not None
        or artifacts
        or documented_ports != expected_ports
        or service_enabled is not None
        or service_inactive is not None
        or listen_policy != LISTEN_POLICY
        or deferred
        or not blockers
    ):
        raise AnsibleError("Ansible monitoring stack failure evidence conflicts")
    return MonitoringStackEvidence(
        logical_id,
        status,
        requested_release,
        requested_version,
        installed_version,
        artifacts,
        artifact_digest,
        source_commit,
        service_enabled,
        service_inactive,
        flags["containers_started"],
        listen_policy,
        documented_ports,
        flags["targets_generated"],
        flags["auth_configured"],
        flags["public_bind"],
        flags["manager_registration_performed"],
        flags["scylla_started"],
        flags["secrets_written"],
        flags["compose_generated"],
        provenance,
        blockers,
    )


def _failed_evidence(expected: dict[str, object]) -> MonitoringStackEvidence:
    artifact = cast(dict[str, object], expected["artifact"])
    provenance = cast(dict[str, object], expected["provenance"])
    ports = tuple(sorted(cast(dict[str, int], expected["documented_ports"]).items()))
    return MonitoringStackEvidence(
        _text(expected["logical_id"]),
        MonitoringStackStatus.FAILED,
        _text(expected["release_line"]),
        _text(expected["stack_version"]),
        None,
        (),
        _require_digest(artifact["digest"]),
        _text(expected["source_commit"]),
        None,
        None,
        False,
        LISTEN_POLICY,
        ports,
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


def _object_digest(value: object) -> str:
    data = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AnsibleError("Ansible monitoring stack evidence has duplicate fields")
        value[key] = item
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible monitoring stack value is invalid")
    return value


def _optional_text(value: object) -> str | None:
    return None if value is None else _text(value)


def _optional_bool(value: object) -> bool | None:
    if value is not None and not isinstance(value, bool):
        raise AnsibleError("Ansible monitoring stack boolean is invalid")
    return value


def _require_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError("Ansible monitoring stack boolean is invalid")
    return value


def _require_port(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise AnsibleError("Ansible monitoring stack port is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible monitoring stack digest is invalid")
    return text


def _sorted_strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible monitoring stack blockers are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError("Ansible monitoring stack blockers are not uniquely sorted")
    return items
