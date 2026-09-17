"""Strict ScyllaDB 2026.2 node-exporter install-only monitoring-agent evidence."""

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
from scylla_vms.ansible.scylla_install import (
    SCYLLA_CHANNEL,
    SCYLLA_PACKAGES,
    SCYLLA_RELEASE_LINE,
    SCYLLA_REPOSITORY_DEFINITION_DIGEST,
    SCYLLA_REPOSITORY_URI,
    SCYLLA_SIGNING_KEY_DIGEST,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
    SCYLLA_SIGNING_KEY_RESOURCE,
    ScyllaInstallEvidence,
    ScyllaInstallStatus,
    load_scylla_signing_key,
    validate_scylla_signing_key,
)
from scylla_vms.desired import ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata

MONITORING_AGENT_SCHEMA_VERSION = "deploy-scylla-vms.ansible-monitoring-agent/v1"
MONITORING_AGENT_PACKAGES = ("scylla-node-exporter",)
MONITORING_AGENT_SERVICE = "scylla-node-exporter"
NODE_EXPORTER_PORT = 9100
LISTEN_POLICY = "not-started"
_PACKAGE_VERSION = re.compile(
    r"2026\.2\.(?:0|[1-9][0-9]*)-0\.[0-9]{8}\.[0-9a-f]{12}-1\Z"
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MARKER = re.compile(r"DSV_MONITORING_AGENT_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_BLOCKERS = frozenset(
    {
        "execution-failed",
        "installed-package-mismatch",
        "service-active",
        "service-enabled",
    }
)
_LISTEN = frozenset({"localhost", "not-started", "private"})
_NOT_PERFORMED_FALSE = (
    "configuration_performed",
    "manager_registration_performed",
    "process_exporter_installed",
    "scylla_started",
    "secrets_written",
    "stack_installed",
    "targets_generated",
)


class MonitoringAgentStatus(StrEnum):
    INSTALLED = "installed"
    NO_CHANGE = "no-change"
    NOT_PREDICTED = "not-predicted"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class MonitoringAgentEvidence:
    logical_id: str
    status: MonitoringAgentStatus
    requested_release: str
    requested_version: str
    installed_version: str | None
    packages: tuple[tuple[str, str], ...]
    repository_digest: str
    signing_key_fingerprint: str
    signing_key_digest: str
    service_enabled: bool | None
    service_inactive: bool | None
    listen_policy: str
    configuration_performed: bool
    process_exporter_installed: bool
    stack_installed: bool
    targets_generated: bool
    manager_registration_performed: bool
    scylla_started: bool
    secrets_written: bool
    provenance: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]
    schema_version: str = MONITORING_AGENT_SCHEMA_VERSION


def build_monitoring_agent_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    base_os: BaseOsEvidence,
    install: ScyllaInstallEvidence,
    *,
    logical_id: str,
    image_filter: ImageFilter,
    architecture: str,
    package_version: str,
    cluster_spec_digest: str,
) -> dict[str, object]:
    """Build one exact node-exporter install intent after local prerequisites reconcile."""

    validate_scylla_signing_key(load_scylla_signing_key())
    if image_filter != ImageFilter(
        "Ubuntu", "24.04", ImageVersionMatch.EXACT
    ) or architecture not in {"amd64", "aarch64"}:
        raise StateConflictError(
            "Monitoring agent install requires exact Ubuntu 24.04 evidence"
        )
    if _PACKAGE_VERSION.fullmatch(package_version) is None:
        raise AnsibleError(
            "Monitoring agent package version must be an exact 2026.2 release package version"
        )
    record = inventory.record
    host_roles = {host.logical_id: host.role.value for host in record.inventory.hosts}
    if host_roles.get(logical_id) != "scylla":
        raise StateConflictError("Monitoring agent target is not a Scylla stable ID")
    if (
        len(base_os.hosts) != 1
        or base_os.hosts[0].logical_id != logical_id
        or base_os.hosts[0].status not in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
        or base_os.hosts[0].reboot_required
    ):
        raise StateConflictError(
            "Monitoring agent install requires successful current base-os"
        )
    install_provenance = dict(install.provenance)
    if (
        install.logical_id != logical_id
        or install.status
        not in {ScyllaInstallStatus.INSTALLED, ScyllaInstallStatus.NO_CHANGE}
        or install.installed_version != package_version
        or install.requested_version != package_version
        or ("scylla-node-exporter", package_version) not in install.packages
        or install_provenance.get("inventory_digest") != inventory.digest
        or install_provenance.get("observation_digest") != observed.digest
    ):
        raise StateConflictError(
            "Monitoring agent install requires successful current Scylla install"
        )
    if "scylla-node-exporter" not in SCYLLA_PACKAGES:
        raise StateConflictError(
            "Monitoring agent requires the official Scylla node-exporter package"
        )
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
        raise StateConflictError("Monitoring agent input provenance conflicts")
    provenance = {
        "base_os_digest": _object_digest(_base_os_object(base_os)),
        "cluster_spec_digest": _require_digest(cluster_spec_digest),
        "inventory_digest": inventory.digest,
        "observation_digest": observed.digest,
        "scylla_install_digest": _object_digest(_install_object(install)),
        "trust_digest": readiness.trust_digest,
    }
    return {
        "architecture": architecture,
        "channel": SCYLLA_CHANNEL,
        "cluster_uuid": str(metadata.cluster_uuid),
        "configuration_performed": False,
        "documented_metrics_port": NODE_EXPORTER_PORT,
        "image_operating_system": "Ubuntu",
        "image_operating_system_version": "24.04",
        "listen_policy": LISTEN_POLICY,
        "logical_id": logical_id,
        "manager_registration_performed": False,
        "package_version": package_version,
        "packages": list(MONITORING_AGENT_PACKAGES),
        "process_exporter_installed": False,
        "provenance": provenance,
        "release_line": SCYLLA_RELEASE_LINE,
        "repository": {
            "definition_digest": SCYLLA_REPOSITORY_DEFINITION_DIGEST,
            "uri": SCYLLA_REPOSITORY_URI,
        },
        "schema_version": MONITORING_AGENT_SCHEMA_VERSION,
        "scylla_started": False,
        "secrets_written": False,
        "service_unit": MONITORING_AGENT_SERVICE,
        "signing_key": {
            "artifact_digest": SCYLLA_SIGNING_KEY_DIGEST,
            "fingerprint": SCYLLA_SIGNING_KEY_FINGERPRINT,
            "resource": SCYLLA_SIGNING_KEY_RESOURCE,
        },
        "stack_installed": False,
        "targets_generated": False,
    }


def parse_monitoring_agent_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> MonitoringAgentEvidence:
    """Parse only the bounded normalized result and recap."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError("Ansible monitoring agent output exceeds the evidence limit")
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_MONITORING_AGENT_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible monitoring agent marker is malformed")
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"), object_pairs_hook=_strict_object
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible monitoring agent marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible monitoring agent evidence is malformed")
        values.append(value)
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible monitoring agent output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible monitoring agent recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    logical_id = _text(expected_payload["logical_id"])
    if set(rows) != {logical_id}:
        raise AnsibleError("Ansible monitoring agent recap membership conflicts")
    recap_failed = bool(rows[logical_id][1] or rows[logical_id][2])
    if not values:
        if not recap_failed or exit_code == 0:
            raise AnsibleError("Ansible monitoring agent evidence is incomplete")
        return _failed_evidence(expected_payload)
    if len(values) != 1:
        raise AnsibleError("Ansible monitoring agent evidence is duplicated")
    evidence = _parse_result(values[0], expected_payload)
    failed = evidence.status is MonitoringAgentStatus.FAILED
    if recap_failed != failed or (exit_code == 0) == failed:
        raise AnsibleError("Ansible monitoring agent exit status conflicts")
    changed = evidence.status is MonitoringAgentStatus.INSTALLED
    if bool(rows[logical_id][0]) != changed:
        raise AnsibleError("Ansible monitoring agent changed status conflicts")
    return evidence


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> MonitoringAgentEvidence:
    expected_fields = {
        "blockers",
        "configuration_performed",
        "installed_version",
        "listen_policy",
        "logical_id",
        "manager_registration_performed",
        "packages",
        "process_exporter_installed",
        "provenance",
        "repository_digest",
        "requested_release",
        "requested_version",
        "schema_version",
        "scylla_started",
        "secrets_written",
        "service_enabled",
        "service_inactive",
        "signing_key_digest",
        "signing_key_fingerprint",
        "stack_installed",
        "status",
        "targets_generated",
    }
    if (
        set(value) != expected_fields
        or value["schema_version"] != MONITORING_AGENT_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible monitoring agent evidence schema is invalid")
    logical_id = _text(value["logical_id"])
    requested_release = _text(value["requested_release"])
    requested_version = _text(value["requested_version"])
    listen_policy = _text(value["listen_policy"])
    if (
        logical_id != expected["logical_id"]
        or requested_release != expected["release_line"]
        or requested_version != expected["package_version"]
        or listen_policy != expected["listen_policy"]
        or listen_policy not in _LISTEN
    ):
        raise AnsibleError("Ansible monitoring agent evidence conflicts")
    try:
        status = MonitoringAgentStatus(_text(value["status"]))
    except ValueError as error:
        raise AnsibleError("Ansible monitoring agent status is invalid") from error
    packages_value = value["packages"]
    if not isinstance(packages_value, dict):
        raise AnsibleError("Ansible monitoring agent packages are invalid")
    packages = tuple(
        sorted(
            (_text(name), _text(version)) for name, version in packages_value.items()
        )
    )
    blockers = _sorted_strings(value["blockers"])
    if not set(blockers) <= _BLOCKERS:
        raise AnsibleError("Ansible monitoring agent blocker is unknown")
    provenance_value = value["provenance"]
    expected_provenance = cast(dict[str, object], expected["provenance"])
    if (
        not isinstance(provenance_value, dict)
        or provenance_value != expected_provenance
    ):
        raise AnsibleError("Ansible monitoring agent provenance conflicts")
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
    repository = cast(dict[str, object], expected["repository"])
    signing_key = cast(dict[str, object], expected["signing_key"])
    repository_digest = _require_digest(value["repository_digest"])
    key_digest = _require_digest(value["signing_key_digest"])
    key_fingerprint = _text(value["signing_key_fingerprint"])
    if (
        repository_digest != repository["definition_digest"]
        or key_digest != signing_key["artifact_digest"]
        or key_fingerprint != signing_key["fingerprint"]
    ):
        raise AnsibleError("Ansible monitoring agent repository provenance conflicts")
    success = status in {
        MonitoringAgentStatus.INSTALLED,
        MonitoringAgentStatus.NO_CHANGE,
    }
    expected_packages = tuple(
        (name, requested_version) for name in cast(list[str], expected["packages"])
    )
    if success and (
        installed_version != requested_version
        or packages != expected_packages
        or service_enabled is not False
        or service_inactive is not True
        or listen_policy != LISTEN_POLICY
        or any(flags.values())
        or blockers
    ):
        raise AnsibleError("Ansible monitoring agent success evidence conflicts")
    if status is MonitoringAgentStatus.NOT_PREDICTED and (
        installed_version is not None
        or packages
        or service_enabled is not None
        or service_inactive is not None
        or listen_policy != LISTEN_POLICY
        or any(flags.values())
        or blockers
    ):
        raise AnsibleError("Ansible monitoring agent check evidence conflicts")
    if status is MonitoringAgentStatus.FAILED and (
        installed_version is not None
        or packages
        or service_enabled is not None
        or service_inactive is not None
        or listen_policy != LISTEN_POLICY
        or any(flags.values())
        or not blockers
    ):
        raise AnsibleError("Ansible monitoring agent failure evidence conflicts")
    return MonitoringAgentEvidence(
        logical_id,
        status,
        requested_release,
        requested_version,
        installed_version,
        packages,
        repository_digest,
        key_fingerprint,
        key_digest,
        service_enabled,
        service_inactive,
        listen_policy,
        flags["configuration_performed"],
        flags["process_exporter_installed"],
        flags["stack_installed"],
        flags["targets_generated"],
        flags["manager_registration_performed"],
        flags["scylla_started"],
        flags["secrets_written"],
        provenance,
        blockers,
    )


def _failed_evidence(expected: dict[str, object]) -> MonitoringAgentEvidence:
    repository = cast(dict[str, object], expected["repository"])
    signing_key = cast(dict[str, object], expected["signing_key"])
    provenance = cast(dict[str, object], expected["provenance"])
    return MonitoringAgentEvidence(
        _text(expected["logical_id"]),
        MonitoringAgentStatus.FAILED,
        _text(expected["release_line"]),
        _text(expected["package_version"]),
        None,
        (),
        _require_digest(repository["definition_digest"]),
        _text(signing_key["fingerprint"]),
        _require_digest(signing_key["artifact_digest"]),
        None,
        None,
        LISTEN_POLICY,
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


def _install_object(value: ScyllaInstallEvidence) -> dict[str, object]:
    return {
        "blockers": list(value.blockers),
        "installed_edition": value.installed_edition,
        "installed_version": value.installed_version,
        "logical_id": value.logical_id,
        "packages": dict(value.packages),
        "provenance": dict(value.provenance),
        "repository_digest": value.repository_digest,
        "requested_edition": value.requested_edition,
        "requested_version": value.requested_version,
        "service_inactive": value.service_inactive,
        "service_masked": value.service_masked,
        "signing_key_digest": value.signing_key_digest,
        "signing_key_fingerprint": value.signing_key_fingerprint,
        "status": value.status.value,
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


def _object_digest(value: object) -> str:
    data = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AnsibleError("Ansible monitoring agent evidence has duplicate fields")
        value[key] = item
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible monitoring agent value is invalid")
    return value


def _optional_text(value: object) -> str | None:
    return None if value is None else _text(value)


def _optional_bool(value: object) -> bool | None:
    if value is not None and not isinstance(value, bool):
        raise AnsibleError("Ansible monitoring agent boolean is invalid")
    return value


def _require_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError("Ansible monitoring agent boolean is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible monitoring agent digest is invalid")
    return text


def _sorted_strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible monitoring agent blockers are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError("Ansible monitoring agent blockers are not uniquely sorted")
    return items
