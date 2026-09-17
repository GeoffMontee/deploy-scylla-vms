"""Fail-closed Manager 3.12 task validation without live sctool or startup."""

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
from scylla_vms.ansible.manager_server import (
    MANAGER_RELEASE_LINE,
    MANAGER_SERVICE_UNIT,
    ManagerServerEvidence,
    ManagerServerStatus,
)
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.desired import ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata

MANAGER_TASKS_SCHEMA_VERSION = "deploy-scylla-vms.ansible-manager-tasks/v1"
MANAGER_TASK_ACTIONS = ("inspect", "quiesce", "resume", "validate")
MANAGER_TASK_KINDS = ("backup", "repair")
NOT_PERFORMED = (
    "auth-token",
    "backend-configure",
    "cluster-registration",
    "manager-start",
    "sctool-backup",
    "sctool-repair",
    "sctool-resume",
    "sctool-suspend",
    "sctool-tasks",
)
EXPECTED_BLOCKERS = (
    "backend-unconfigured",
    "manager-inactive",
    "manager-unregistered",
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MARKER = re.compile(r"DSV_MANAGER_TASKS_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_BLOCKERS = frozenset(
    {
        *EXPECTED_BLOCKERS,
        "execution-failed",
        "service-active",
        "service-unmasked",
    }
)
_FALSE_FLAGS = (
    "applied",
    "auth_token_used",
    "backend_configured",
    "backup_task_created",
    "inspect_performed",
    "quiesce_performed",
    "registration_performed",
    "repair_task_created",
    "resume_performed",
    "scylla_started",
    "sctool_invoked",
    "secrets_written",
    "service_started",
    "setup_performed",
    "validate_performed",
)


class ManagerTasksStatus(StrEnum):
    NOT_PERFORMED = "not-performed"
    NOT_PREDICTED = "not-predicted"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ManagerTasksEvidence:
    logical_id: str
    status: ManagerTasksStatus
    action: str
    requested_kinds: tuple[str, ...]
    applied: bool
    service_unit: str
    service_masked: bool | None
    service_inactive: bool | None
    service_started: bool
    backend_configured: bool
    registration_performed: bool
    setup_performed: bool
    sctool_invoked: bool
    auth_token_used: bool
    inspect_performed: bool
    quiesce_performed: bool
    resume_performed: bool
    validate_performed: bool
    backup_task_created: bool
    repair_task_created: bool
    secrets_written: bool
    scylla_started: bool
    not_performed: tuple[str, ...]
    provenance: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]
    schema_version: str = MANAGER_TASKS_SCHEMA_VERSION


def build_manager_tasks_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    base_os: BaseOsEvidence,
    manager_server: ManagerServerEvidence,
    *,
    logical_id: str,
    image_filter: ImageFilter,
    architecture: str,
    cluster_spec_digest: str,
    action: str = "inspect",
) -> dict[str, object]:
    """Build one fail-closed Manager task intent after local prerequisites."""

    if action not in MANAGER_TASK_ACTIONS:
        raise AnsibleError(
            "Manager task action must be inspect, quiesce, resume, or validate"
        )
    if image_filter != ImageFilter(
        "Ubuntu", "24.04", ImageVersionMatch.EXACT
    ) or architecture not in {"amd64", "aarch64"}:
        raise StateConflictError(
            "Manager task validation requires exact Ubuntu 24.04 evidence"
        )
    if (
        len(base_os.hosts) != 1
        or base_os.hosts[0].logical_id != logical_id
        or base_os.hosts[0].status not in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
        or base_os.hosts[0].reboot_required
    ):
        raise StateConflictError(
            "Manager task validation requires successful current base-os"
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
        raise StateConflictError("Manager task input provenance conflicts")
    host_ids = {
        host.logical_id
        for host in record.inventory.hosts
        if host.role.value == "manager"
    }
    if logical_id not in host_ids:
        raise StateConflictError("Manager task target is not a manager stable ID")
    _require_current_manager_server(manager_server, logical_id, observed, inventory)
    provenance = {
        "base_os_digest": _object_digest(_base_os_object(base_os)),
        "cluster_spec_digest": _require_digest(cluster_spec_digest),
        "inventory_digest": inventory.digest,
        "manager_server_digest": _object_digest(_server_object(manager_server)),
        "observation_digest": observed.digest,
        "trust_digest": readiness.trust_digest,
    }
    return {
        "action": action,
        "applied": False,
        "architecture": architecture,
        "auth_token_used": False,
        "backend_configured": False,
        "backup_task_created": False,
        "cluster_uuid": str(metadata.cluster_uuid),
        "expected_blockers": list(EXPECTED_BLOCKERS),
        "image_operating_system": "Ubuntu",
        "image_operating_system_version": "24.04",
        "inspect_performed": False,
        "logical_id": logical_id,
        "not_performed": list(NOT_PERFORMED),
        "provenance": provenance,
        "quiesce_performed": False,
        "registration_performed": False,
        "repair_task_created": False,
        "requested_kinds": list(MANAGER_TASK_KINDS),
        "requested_release": MANAGER_RELEASE_LINE,
        "resume_performed": False,
        "schema_version": MANAGER_TASKS_SCHEMA_VERSION,
        "scylla_started": False,
        "sctool_invoked": False,
        "secrets_written": False,
        "service_started": False,
        "service_unit": MANAGER_SERVICE_UNIT,
        "setup_performed": False,
        "validate_performed": False,
    }


def parse_manager_tasks_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> ManagerTasksEvidence:
    """Parse only the bounded normalized result and recap."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError("Ansible Manager tasks output exceeds the evidence limit")
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_MANAGER_TASKS_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible Manager tasks marker is malformed")
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"), object_pairs_hook=_strict_object
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError("Ansible Manager tasks marker is malformed") from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible Manager tasks evidence is malformed")
        values.append(value)
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible Manager tasks output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible Manager tasks recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    logical_id = _text(expected_payload["logical_id"])
    if set(rows) != {logical_id}:
        raise AnsibleError("Ansible Manager tasks recap membership conflicts")
    recap_failed = bool(rows[logical_id][1] or rows[logical_id][2])
    if not values:
        if not recap_failed or exit_code == 0:
            raise AnsibleError("Ansible Manager tasks evidence is incomplete")
        return _failed_evidence(expected_payload)
    if len(values) != 1:
        raise AnsibleError("Ansible Manager tasks evidence is duplicated")
    evidence = _parse_result(values[0], expected_payload)
    failed = evidence.status is ManagerTasksStatus.FAILED
    if recap_failed != failed or (exit_code == 0) == failed:
        raise AnsibleError("Ansible Manager tasks exit status conflicts")
    if rows[logical_id][0]:
        raise AnsibleError("Ansible Manager tasks changed status conflicts")
    return evidence


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> ManagerTasksEvidence:
    expected_fields = {
        "action",
        "applied",
        "auth_token_used",
        "backend_configured",
        "backup_task_created",
        "blockers",
        "inspect_performed",
        "logical_id",
        "not_performed",
        "provenance",
        "quiesce_performed",
        "registration_performed",
        "repair_task_created",
        "requested_kinds",
        "resume_performed",
        "schema_version",
        "scylla_started",
        "sctool_invoked",
        "secrets_written",
        "service_inactive",
        "service_masked",
        "service_started",
        "setup_performed",
        "status",
        "validate_performed",
    }
    if (
        set(value) != expected_fields
        or value["schema_version"] != MANAGER_TASKS_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible Manager tasks evidence schema is invalid")
    logical_id = _text(value["logical_id"])
    action = _text(value["action"])
    if logical_id != expected["logical_id"] or action != expected["action"]:
        raise AnsibleError("Ansible Manager tasks evidence conflicts")
    try:
        status = ManagerTasksStatus(_text(value["status"]))
    except ValueError as error:
        raise AnsibleError("Ansible Manager tasks status is invalid") from error
    requested_kinds = _sorted_strings(value["requested_kinds"], name="kinds")
    if requested_kinds != MANAGER_TASK_KINDS:
        raise AnsibleError("Ansible Manager tasks requested kinds are invalid")
    not_performed = _sorted_strings(value["not_performed"], name="not-performed")
    if not_performed != NOT_PERFORMED:
        raise AnsibleError("Ansible Manager tasks not-performed set is invalid")
    blockers = _sorted_strings(value["blockers"], name="blockers")
    if not set(blockers) <= _BLOCKERS:
        raise AnsibleError("Ansible Manager tasks blocker is unknown")
    provenance_value = value["provenance"]
    expected_provenance = cast(dict[str, object], expected["provenance"])
    if (
        not isinstance(provenance_value, dict)
        or provenance_value != expected_provenance
    ):
        raise AnsibleError("Ansible Manager tasks provenance conflicts")
    provenance = tuple(
        sorted(
            (_text(name), _require_digest(item))
            for name, item in provenance_value.items()
        )
    )
    flags = {name: _require_bool(value[name]) for name in _FALSE_FLAGS}
    if any(flags.values()):
        raise AnsibleError("Ansible Manager tasks claimed a forbidden mutation")
    service_masked = _optional_bool(value["service_masked"])
    service_inactive = _optional_bool(value["service_inactive"])
    if status is ManagerTasksStatus.NOT_PERFORMED and (
        service_masked is not True
        or service_inactive is not True
        or blockers != EXPECTED_BLOCKERS
    ):
        raise AnsibleError("Ansible Manager tasks success evidence conflicts")
    if status is ManagerTasksStatus.NOT_PREDICTED and (
        service_masked is not None or service_inactive is not None or blockers
    ):
        raise AnsibleError("Ansible Manager tasks check evidence conflicts")
    if status is ManagerTasksStatus.FAILED and (
        not blockers or set(blockers) <= set(EXPECTED_BLOCKERS)
    ):
        raise AnsibleError("Ansible Manager tasks failure evidence conflicts")
    _reject_secrets(value)
    return ManagerTasksEvidence(
        logical_id,
        status,
        action,
        requested_kinds,
        flags["applied"],
        MANAGER_SERVICE_UNIT,
        service_masked,
        service_inactive,
        flags["service_started"],
        flags["backend_configured"],
        flags["registration_performed"],
        flags["setup_performed"],
        flags["sctool_invoked"],
        flags["auth_token_used"],
        flags["inspect_performed"],
        flags["quiesce_performed"],
        flags["resume_performed"],
        flags["validate_performed"],
        flags["backup_task_created"],
        flags["repair_task_created"],
        flags["secrets_written"],
        flags["scylla_started"],
        not_performed,
        provenance,
        blockers,
    )


def _failed_evidence(expected: dict[str, object]) -> ManagerTasksEvidence:
    provenance = cast(dict[str, object], expected["provenance"])
    return ManagerTasksEvidence(
        _text(expected["logical_id"]),
        ManagerTasksStatus.FAILED,
        _text(expected["action"]),
        MANAGER_TASK_KINDS,
        False,
        MANAGER_SERVICE_UNIT,
        None,
        None,
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
        False,
        False,
        False,
        False,
        NOT_PERFORMED,
        tuple(sorted((_text(k), _require_digest(v)) for k, v in provenance.items())),
        ("execution-failed",),
    )


def _require_current_manager_server(
    server: ManagerServerEvidence,
    logical_id: str,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
) -> None:
    provenance = dict(server.provenance)
    if (
        server.logical_id != logical_id
        or server.status
        not in {ManagerServerStatus.INSTALLED, ManagerServerStatus.NO_CHANGE}
        or server.requested_release != MANAGER_RELEASE_LINE
        or server.service_masked is not True
        or server.service_inactive is not True
        or server.service_started
        or server.backend_configured
        or server.registration_performed
        or server.setup_performed
        or provenance.get("inventory_digest") != inventory.digest
        or provenance.get("observation_digest") != observed.digest
    ):
        raise StateConflictError(
            "Manager task validation requires successful current manager-server"
        )


def _server_object(value: ManagerServerEvidence) -> dict[str, object]:
    return {
        "backend_configured": value.backend_configured,
        "installed_version": value.installed_version,
        "logical_id": value.logical_id,
        "packages": list(value.packages),
        "provenance": dict(value.provenance),
        "registration_performed": value.registration_performed,
        "requested_release": value.requested_release,
        "requested_version": value.requested_version,
        "schema_version": value.schema_version,
        "service_inactive": value.service_inactive,
        "service_masked": value.service_masked,
        "service_started": value.service_started,
        "setup_performed": value.setup_performed,
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
            raise AnsibleError("Ansible Manager tasks evidence has duplicate fields")
        value[key] = item
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible Manager tasks value is invalid")
    return value


def _optional_bool(value: object) -> bool | None:
    if value is not None and not isinstance(value, bool):
        raise AnsibleError("Ansible Manager tasks boolean is invalid")
    return value


def _require_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError("Ansible Manager tasks boolean is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible Manager tasks digest is invalid")
    return text


def _sorted_strings(value: object, *, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError(f"Ansible Manager tasks {name} are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError(f"Ansible Manager tasks {name} are not uniquely sorted")
    return items


def _reject_secrets(value: dict[str, object]) -> None:
    encoded = json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True)
    if re.search(
        r"(?i)(?:-----BEGIN [^-]*PRIVATE KEY-----|"
        r"(?:password|passphrase|secret|token)\s*[:=])",
        encoded,
    ):
        raise AnsibleError("Ansible Manager tasks evidence contains a secret")
