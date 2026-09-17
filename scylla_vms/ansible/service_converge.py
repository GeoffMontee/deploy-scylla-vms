"""Fail-closed role-aware systemd reconcile without unreviewed starts."""

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
from scylla_vms.ansible.jump_host_configure import (
    JumpHostConfigureEvidence,
    JumpHostConfigureStatus,
)
from scylla_vms.ansible.manager_agent import ManagerAgentEvidence, ManagerAgentStatus
from scylla_vms.ansible.manager_server import (
    ManagerServerEvidence,
    ManagerServerStatus,
)
from scylla_vms.ansible.monitoring_agent import (
    MonitoringAgentEvidence,
    MonitoringAgentStatus,
)
from scylla_vms.ansible.monitoring_stack import (
    MonitoringStackEvidence,
    MonitoringStackStatus,
)
from scylla_vms.ansible.monitoring_targets import (
    MonitoringTargetsEvidence,
    MonitoringTargetsStatus,
)
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.scylla_install import ScyllaInstallEvidence, ScyllaInstallStatus
from scylla_vms.desired import HostRole, ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata

SERVICE_CONVERGE_SCHEMA_VERSION = "deploy-scylla-vms.ansible-service-converge/v1"
TIMESYNC_UNIT = "systemd-timesyncd.service"
SERVICE_SCOPES = (
    "base",
    "jump-host",
    "manager-agent",
    "manager-server",
    "monitoring-agent",
    "monitoring-stack",
    "monitoring-targets",
    "scylla",
)
RESTART_POLICIES = ("always", "if-required", "never")
NOT_PERFORMED = (
    "container-start",
    "docker-start",
    "exporter-start",
    "manager-agent-start",
    "manager-start",
    "scylla-start",
    "ssh-restart",
    "stack-start",
)
SCOPE_ROLES = {
    "jump-host": HostRole.JUMP_HOST,
    "manager-agent": HostRole.SCYLLA,
    "manager-server": HostRole.MANAGER,
    "monitoring-agent": HostRole.SCYLLA,
    "monitoring-stack": HostRole.MONITORING,
    "monitoring-targets": HostRole.MONITORING,
    "scylla": HostRole.SCYLLA,
}
SCOPE_UNITS: dict[str, tuple[tuple[str, str, str, bool], ...]] = {
    "base": ((TIMESYNC_UNIT, "enabled", "active", True),),
    "jump-host": ((TIMESYNC_UNIT, "enabled", "active", True),),
    "manager-agent": (("scylla-manager-agent.service", "disabled", "inactive", False),),
    "manager-server": (("scylla-manager.service", "masked", "inactive", False),),
    "monitoring-agent": (
        ("scylla-node-exporter.service", "disabled", "inactive", False),
    ),
    "monitoring-stack": (),
    "monitoring-targets": (),
    "scylla": (("scylla-server.service", "masked", "inactive", False),),
}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MARKER = re.compile(r"DSV_SERVICE_CONVERGE_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_UNIT = re.compile(r"[a-z][a-z0-9._-]{0,62}\.service\Z")
_BLOCKERS = frozenset(
    {
        "execution-failed",
        "service-active",
        "service-enabled",
        "service-masked",
        "service-unmasked",
        "start-not-performed",
        "unit-not-found",
    }
)
_UNIT_NOT_PERFORMED = ("restart", "start", "unmask")


class ServiceConvergeStatus(StrEnum):
    CONVERGED = "converged"
    NO_CHANGE = "no-change"
    NOT_PREDICTED = "not-predicted"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ServiceConvergeUnitEvidence:
    unit: str
    desired_enabled: str
    desired_active: str
    observed_enabled: str | None
    observed_active: str | None
    start_allowed: bool
    applied: bool
    started: bool
    restarted: bool
    not_performed: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ServiceConvergeEvidence:
    logical_id: str
    status: ServiceConvergeStatus
    service_scope: str
    restart_policy: str
    applied: bool
    started: bool
    restarted: bool
    units: tuple[ServiceConvergeUnitEvidence, ...]
    not_performed: tuple[str, ...]
    provenance: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]
    schema_version: str = SERVICE_CONVERGE_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class ServiceConvergePrerequisites:
    jump_host_configure: JumpHostConfigureEvidence | None = None
    scylla_install: ScyllaInstallEvidence | None = None
    manager_agent: ManagerAgentEvidence | None = None
    manager_server: ManagerServerEvidence | None = None
    monitoring_agent: MonitoringAgentEvidence | None = None
    monitoring_stack: MonitoringStackEvidence | None = None
    monitoring_targets: MonitoringTargetsEvidence | None = None


def scope_units(service_scope: str) -> tuple[dict[str, object], ...]:
    """Return the exact PLAN-owned unit allowlist for one service scope."""

    if service_scope not in SERVICE_SCOPES:
        raise AnsibleError("service-converge scope is not allowlisted")
    return tuple(
        {
            "desired_active": active,
            "desired_enabled": enabled,
            "not_performed": [] if start_allowed else list(_UNIT_NOT_PERFORMED),
            "start_allowed": start_allowed,
            "unit": unit,
        }
        for unit, enabled, active, start_allowed in SCOPE_UNITS[service_scope]
    )


def build_service_converge_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    base_os: BaseOsEvidence,
    prerequisites: ServiceConvergePrerequisites,
    *,
    logical_id: str,
    image_filter: ImageFilter,
    architecture: str,
    cluster_spec_digest: str,
    service_scope: str,
    restart_policy: str = "if-required",
) -> dict[str, object]:
    """Build one fail-closed unit-reconcile intent after current prerequisites."""

    if service_scope not in SERVICE_SCOPES:
        raise AnsibleError("service-converge scope is not allowlisted")
    if restart_policy not in RESTART_POLICIES:
        raise AnsibleError("service-converge restart policy is not allowlisted")
    if image_filter != ImageFilter(
        "Ubuntu", "24.04", ImageVersionMatch.EXACT
    ) or architecture not in {"amd64", "aarch64"}:
        raise StateConflictError(
            "service-converge requires exact Ubuntu 24.04 evidence"
        )
    if (
        len(base_os.hosts) != 1
        or base_os.hosts[0].logical_id != logical_id
        or base_os.hosts[0].status not in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
        or base_os.hosts[0].reboot_required
    ):
        raise StateConflictError("service-converge requires successful current base-os")
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
        raise StateConflictError("service-converge input provenance conflicts")
    hosts = {host.logical_id: host for host in record.inventory.hosts}
    host = hosts.get(logical_id)
    if host is None:
        raise StateConflictError("service-converge target is not a current stable ID")
    required_role = SCOPE_ROLES.get(service_scope)
    if required_role is not None and host.role is not required_role:
        raise StateConflictError(
            f"service-converge {service_scope} target is not a {required_role.value} "
            "stable ID"
        )
    provenance = {
        "base_os_digest": _object_digest(_base_os_object(base_os)),
        "cluster_spec_digest": _require_digest(cluster_spec_digest),
        "inventory_digest": inventory.digest,
        "observation_digest": observed.digest,
        "trust_digest": readiness.trust_digest,
    }
    provenance.update(
        _role_evidence_digests(
            service_scope,
            prerequisites,
            logical_id,
            observed,
            inventory,
        )
    )
    return {
        "applied": False,
        "architecture": architecture,
        "expected_role": host.role.value,
        "image_operating_system": "Ubuntu",
        "image_operating_system_version": "24.04",
        "logical_id": logical_id,
        "not_performed": list(NOT_PERFORMED),
        "provenance": provenance,
        "restart_policy": restart_policy,
        "schema_version": SERVICE_CONVERGE_SCHEMA_VERSION,
        "service_scope": service_scope,
        "started": False,
        "units": [dict(item) for item in scope_units(service_scope)],
    }


def parse_service_converge_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> ServiceConvergeEvidence:
    """Parse only the bounded normalized result and recap."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError("Ansible service-converge output exceeds the evidence limit")
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_SERVICE_CONVERGE_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible service-converge marker is malformed")
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"), object_pairs_hook=_strict_object
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible service-converge marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible service-converge evidence is malformed")
        values.append(value)
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible service-converge output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible service-converge recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    logical_id = _text(expected_payload["logical_id"])
    if set(rows) != {logical_id}:
        raise AnsibleError("Ansible service-converge recap membership conflicts")
    recap_failed = bool(rows[logical_id][1] or rows[logical_id][2])
    if not values:
        if not recap_failed or exit_code == 0:
            raise AnsibleError("Ansible service-converge evidence is incomplete")
        return _failed_evidence(expected_payload)
    if len(values) != 1:
        raise AnsibleError("Ansible service-converge evidence is duplicated")
    evidence = _parse_result(values[0], expected_payload)
    failed = evidence.status is ServiceConvergeStatus.FAILED
    if recap_failed != failed or (exit_code == 0) == failed:
        raise AnsibleError("Ansible service-converge exit status conflicts")
    changed = bool(rows[logical_id][0])
    if changed != (evidence.status is ServiceConvergeStatus.CONVERGED):
        raise AnsibleError("Ansible service-converge changed status conflicts")
    return evidence


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> ServiceConvergeEvidence:
    expected_fields = {
        "applied",
        "blockers",
        "logical_id",
        "not_performed",
        "provenance",
        "restart_policy",
        "restarted",
        "schema_version",
        "service_scope",
        "started",
        "status",
        "units",
    }
    if (
        set(value) != expected_fields
        or value["schema_version"] != SERVICE_CONVERGE_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible service-converge evidence schema is invalid")
    logical_id = _text(value["logical_id"])
    service_scope = _text(value["service_scope"])
    restart_policy = _text(value["restart_policy"])
    if (
        logical_id != expected["logical_id"]
        or service_scope != expected["service_scope"]
        or restart_policy != expected["restart_policy"]
    ):
        raise AnsibleError("Ansible service-converge evidence conflicts")
    try:
        status = ServiceConvergeStatus(_text(value["status"]))
    except ValueError as error:
        raise AnsibleError("Ansible service-converge status is invalid") from error
    not_performed = _sorted_strings(value["not_performed"], name="not-performed")
    if not_performed != NOT_PERFORMED:
        raise AnsibleError("Ansible service-converge not-performed set is invalid")
    blockers = _sorted_strings(value["blockers"], name="blockers")
    if not set(blockers) <= _BLOCKERS:
        raise AnsibleError("Ansible service-converge blocker is unknown")
    provenance_value = value["provenance"]
    expected_provenance = cast(dict[str, object], expected["provenance"])
    if (
        not isinstance(provenance_value, dict)
        or provenance_value != expected_provenance
    ):
        raise AnsibleError("Ansible service-converge provenance conflicts")
    provenance = tuple(
        sorted(
            (_text(name), _require_digest(item))
            for name, item in provenance_value.items()
        )
    )
    applied = _require_bool(value["applied"])
    started = _require_bool(value["started"])
    restarted = _require_bool(value["restarted"])
    units = _parse_units(value["units"], expected)
    unit_applied = any(unit.applied for unit in units)
    unit_started = any(unit.started for unit in units)
    unit_restarted = any(unit.restarted for unit in units)
    if (
        applied != unit_applied
        or started != unit_started
        or restarted != unit_restarted
    ):
        raise AnsibleError("Ansible service-converge unit mutation flags conflict")
    if any(
        unit.started or unit.restarted or (unit.applied and not unit.start_allowed)
        for unit in units
        if not unit.start_allowed
    ):
        raise AnsibleError("Ansible service-converge claimed a forbidden start")
    if any(
        unit.started or unit.restarted for unit in units if unit.unit != TIMESYNC_UNIT
    ):
        raise AnsibleError("Ansible service-converge claimed an unreviewed start")
    if status is ServiceConvergeStatus.NO_CHANGE and (
        applied or started or restarted or blockers
    ):
        raise AnsibleError("Ansible service-converge no-change evidence conflicts")
    if status is ServiceConvergeStatus.CONVERGED and (
        not applied or blockers or not any(unit.start_allowed for unit in units)
    ):
        raise AnsibleError("Ansible service-converge converge evidence conflicts")
    if status is ServiceConvergeStatus.NOT_PREDICTED and (
        applied
        or started
        or restarted
        or blockers
        or any(
            unit.observed_enabled is not None or unit.observed_active is not None
            for unit in units
        )
    ):
        raise AnsibleError("Ansible service-converge check evidence conflicts")
    if status is ServiceConvergeStatus.FAILED and not blockers:
        raise AnsibleError("Ansible service-converge failure evidence conflicts")
    if status in {ServiceConvergeStatus.NO_CHANGE, ServiceConvergeStatus.CONVERGED}:
        for unit in units:
            if (
                unit.observed_enabled != unit.desired_enabled
                or unit.observed_active != unit.desired_active
            ):
                raise AnsibleError(
                    "Ansible service-converge success evidence conflicts"
                )
    _reject_secrets(value)
    return ServiceConvergeEvidence(
        logical_id,
        status,
        service_scope,
        restart_policy,
        applied,
        started,
        restarted,
        units,
        not_performed,
        provenance,
        blockers,
    )


def _parse_units(
    value: object, expected: dict[str, object]
) -> tuple[ServiceConvergeUnitEvidence, ...]:
    expected_units = cast(list[object], expected["units"])
    if not isinstance(value, list) or len(value) != len(expected_units):
        raise AnsibleError("Ansible service-converge units are invalid")
    units: list[ServiceConvergeUnitEvidence] = []
    seen: set[str] = set()
    for item, expected_item in zip(value, expected_units, strict=True):
        if not isinstance(item, dict) or not isinstance(expected_item, dict):
            raise AnsibleError("Ansible service-converge unit is invalid")
        fields = {
            "applied",
            "desired_active",
            "desired_enabled",
            "not_performed",
            "observed_active",
            "observed_enabled",
            "restarted",
            "start_allowed",
            "started",
            "unit",
        }
        if set(item) != fields:
            raise AnsibleError("Ansible service-converge unit schema is invalid")
        unit = _text(item["unit"])
        if _UNIT.fullmatch(unit) is None or unit in seen:
            raise AnsibleError("Ansible service-converge unit identity is invalid")
        seen.add(unit)
        start_allowed = _require_bool(item["start_allowed"])
        desired_enabled = _text(item["desired_enabled"])
        desired_active = _text(item["desired_active"])
        if (
            unit != expected_item["unit"]
            or desired_enabled != expected_item["desired_enabled"]
            or desired_active != expected_item["desired_active"]
            or start_allowed != expected_item["start_allowed"]
        ):
            raise AnsibleError("Ansible service-converge unit allowlist conflicts")
        if start_allowed is not (unit == TIMESYNC_UNIT):
            raise AnsibleError("Ansible service-converge start allowlist conflicts")
        not_performed = _sorted_strings(
            item["not_performed"], name="unit-not-performed"
        )
        if start_allowed:
            if not_performed:
                raise AnsibleError(
                    "Ansible service-converge start-allowed not-performed is invalid"
                )
        elif not_performed != _UNIT_NOT_PERFORMED:
            raise AnsibleError(
                "Ansible service-converge forbidden not-performed set is invalid"
            )
        units.append(
            ServiceConvergeUnitEvidence(
                unit,
                desired_enabled,
                desired_active,
                _optional_text(item["observed_enabled"]),
                _optional_text(item["observed_active"]),
                start_allowed,
                _require_bool(item["applied"]),
                _require_bool(item["started"]),
                _require_bool(item["restarted"]),
                not_performed,
            )
        )
    expected_names = [
        _text(cast(dict[str, object], item)["unit"]) for item in expected_units
    ]
    if [unit.unit for unit in units] != expected_names:
        raise AnsibleError("Ansible service-converge unit order conflicts")
    return tuple(units)


def _failed_evidence(expected: dict[str, object]) -> ServiceConvergeEvidence:
    provenance = cast(dict[str, object], expected["provenance"])
    units = tuple(
        ServiceConvergeUnitEvidence(
            _text(item["unit"]),
            _text(item["desired_enabled"]),
            _text(item["desired_active"]),
            None,
            None,
            _require_bool(item["start_allowed"]),
            False,
            False,
            False,
            () if item["start_allowed"] else _UNIT_NOT_PERFORMED,
        )
        for item in cast(list[dict[str, object]], expected["units"])
    )
    return ServiceConvergeEvidence(
        _text(expected["logical_id"]),
        ServiceConvergeStatus.FAILED,
        _text(expected["service_scope"]),
        _text(expected["restart_policy"]),
        False,
        False,
        False,
        units,
        NOT_PERFORMED,
        tuple(sorted((_text(k), _require_digest(v)) for k, v in provenance.items())),
        ("execution-failed",),
    )


def _role_evidence_digests(
    service_scope: str,
    prerequisites: ServiceConvergePrerequisites,
    logical_id: str,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
) -> dict[str, str]:
    if service_scope == "base":
        return {}
    if service_scope == "jump-host":
        jump = prerequisites.jump_host_configure
        if jump is None:
            raise StateConflictError(
                "service-converge jump-host requires current jump-host-configure"
            )
        _require_current_jump(jump, logical_id, observed, inventory)
        return {"jump_host_configure_digest": _object_digest(_jump_object(jump))}
    if service_scope == "scylla":
        install = prerequisites.scylla_install
        if install is None:
            raise StateConflictError(
                "service-converge scylla requires current scylla-install"
            )
        _require_current_scylla_install(install, logical_id, observed, inventory)
        return {
            "scylla_install_digest": _object_digest(_scylla_install_object(install))
        }
    if service_scope == "manager-agent":
        agent = prerequisites.manager_agent
        if agent is None:
            raise StateConflictError(
                "service-converge manager-agent requires current manager-agent"
            )
        _require_current_manager_agent(agent, logical_id, observed, inventory)
        return {"manager_agent_digest": _object_digest(_manager_agent_object(agent))}
    if service_scope == "manager-server":
        server = prerequisites.manager_server
        if server is None:
            raise StateConflictError(
                "service-converge manager-server requires current manager-server"
            )
        _require_current_manager_server(server, logical_id, observed, inventory)
        return {"manager_server_digest": _object_digest(_manager_server_object(server))}
    if service_scope == "monitoring-agent":
        exporter = prerequisites.monitoring_agent
        if exporter is None:
            raise StateConflictError(
                "service-converge monitoring-agent requires current monitoring-agent"
            )
        _require_current_monitoring_agent(exporter, logical_id, observed, inventory)
        return {
            "monitoring_agent_digest": _object_digest(
                _monitoring_agent_object(exporter)
            )
        }
    if service_scope == "monitoring-stack":
        stack = prerequisites.monitoring_stack
        if stack is None:
            raise StateConflictError(
                "service-converge monitoring-stack requires current monitoring-stack"
            )
        _require_current_monitoring_stack(stack, logical_id, observed, inventory)
        return {
            "monitoring_stack_digest": _object_digest(_monitoring_stack_object(stack))
        }
    targets = prerequisites.monitoring_targets
    if targets is None:
        raise StateConflictError(
            "service-converge monitoring-targets requires current monitoring-targets"
        )
    _require_current_monitoring_targets(targets, logical_id, observed, inventory)
    return {
        "monitoring_targets_digest": _object_digest(_monitoring_targets_object(targets))
    }


def _require_current_jump(
    evidence: JumpHostConfigureEvidence,
    logical_id: str,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
) -> None:
    provenance = dict(evidence.provenance_digests)
    if (
        evidence.logical_id != logical_id
        or evidence.status
        not in {JumpHostConfigureStatus.CHANGED, JumpHostConfigureStatus.NOOP}
        or provenance.get("inventory_digest") != inventory.digest
        or provenance.get("observation_digest") != observed.digest
    ):
        raise StateConflictError(
            "service-converge requires successful current jump-host-configure"
        )


def _require_current_scylla_install(
    evidence: ScyllaInstallEvidence,
    logical_id: str,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
) -> None:
    provenance = dict(evidence.provenance)
    if (
        evidence.logical_id != logical_id
        or evidence.status
        not in {ScyllaInstallStatus.INSTALLED, ScyllaInstallStatus.NO_CHANGE}
        or evidence.service_masked is not True
        or evidence.service_inactive is not True
        or provenance.get("inventory_digest") != inventory.digest
        or provenance.get("observation_digest") != observed.digest
    ):
        raise StateConflictError(
            "service-converge requires successful current scylla-install"
        )


def _require_current_manager_agent(
    evidence: ManagerAgentEvidence,
    logical_id: str,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
) -> None:
    provenance = dict(evidence.provenance)
    if (
        evidence.logical_id != logical_id
        or evidence.status
        not in {ManagerAgentStatus.INSTALLED, ManagerAgentStatus.NO_CHANGE}
        or evidence.service_enabled is True
        or evidence.service_inactive is not True
        or provenance.get("inventory_digest") != inventory.digest
        or provenance.get("observation_digest") != observed.digest
    ):
        raise StateConflictError(
            "service-converge requires successful current manager-agent"
        )


def _require_current_manager_server(
    evidence: ManagerServerEvidence,
    logical_id: str,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
) -> None:
    provenance = dict(evidence.provenance)
    if (
        evidence.logical_id != logical_id
        or evidence.status
        not in {ManagerServerStatus.INSTALLED, ManagerServerStatus.NO_CHANGE}
        or evidence.service_masked is not True
        or evidence.service_inactive is not True
        or evidence.service_started
        or provenance.get("inventory_digest") != inventory.digest
        or provenance.get("observation_digest") != observed.digest
    ):
        raise StateConflictError(
            "service-converge requires successful current manager-server"
        )


def _require_current_monitoring_agent(
    evidence: MonitoringAgentEvidence,
    logical_id: str,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
) -> None:
    provenance = dict(evidence.provenance)
    if (
        evidence.logical_id != logical_id
        or evidence.status
        not in {MonitoringAgentStatus.INSTALLED, MonitoringAgentStatus.NO_CHANGE}
        or evidence.service_enabled is True
        or evidence.service_inactive is not True
        or evidence.scylla_started
        or provenance.get("inventory_digest") != inventory.digest
        or provenance.get("observation_digest") != observed.digest
    ):
        raise StateConflictError(
            "service-converge requires successful current monitoring-agent"
        )


def _require_current_monitoring_stack(
    evidence: MonitoringStackEvidence,
    logical_id: str,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
) -> None:
    provenance = dict(evidence.provenance)
    if (
        evidence.logical_id != logical_id
        or evidence.status
        not in {MonitoringStackStatus.INSTALLED, MonitoringStackStatus.NO_CHANGE}
        or evidence.containers_started
        or evidence.service_enabled is True
        or evidence.scylla_started
        or provenance.get("inventory_digest") != inventory.digest
        or provenance.get("observation_digest") != observed.digest
    ):
        raise StateConflictError(
            "service-converge requires successful current monitoring-stack"
        )


def _require_current_monitoring_targets(
    evidence: MonitoringTargetsEvidence,
    logical_id: str,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
) -> None:
    provenance = dict(evidence.provenance)
    if (
        evidence.logical_id != logical_id
        or evidence.status
        not in {MonitoringTargetsStatus.GENERATED, MonitoringTargetsStatus.NO_CHANGE}
        or evidence.stack_started
        or evidence.exporters_started
        or evidence.containers_started
        or evidence.scylla_started
        or provenance.get("inventory_digest") != inventory.digest
        or provenance.get("observation_digest") != observed.digest
    ):
        raise StateConflictError(
            "service-converge requires successful current monitoring-targets"
        )


def _jump_object(value: JumpHostConfigureEvidence) -> dict[str, object]:
    return {
        "config_digest": value.config_digest,
        "logical_id": value.logical_id,
        "provenance_digests": dict(value.provenance_digests),
        "schema_version": value.schema_version,
        "status": value.status.value,
    }


def _scylla_install_object(value: ScyllaInstallEvidence) -> dict[str, object]:
    return {
        "logical_id": value.logical_id,
        "packages": list(value.packages),
        "provenance": dict(value.provenance),
        "schema_version": value.schema_version,
        "service_inactive": value.service_inactive,
        "service_masked": value.service_masked,
        "status": value.status.value,
    }


def _manager_agent_object(value: ManagerAgentEvidence) -> dict[str, object]:
    return {
        "logical_id": value.logical_id,
        "packages": list(value.packages),
        "provenance": dict(value.provenance),
        "schema_version": value.schema_version,
        "service_enabled": value.service_enabled,
        "service_inactive": value.service_inactive,
        "status": value.status.value,
    }


def _manager_server_object(value: ManagerServerEvidence) -> dict[str, object]:
    return {
        "logical_id": value.logical_id,
        "packages": list(value.packages),
        "provenance": dict(value.provenance),
        "schema_version": value.schema_version,
        "service_inactive": value.service_inactive,
        "service_masked": value.service_masked,
        "service_started": value.service_started,
        "status": value.status.value,
    }


def _monitoring_agent_object(value: MonitoringAgentEvidence) -> dict[str, object]:
    return {
        "logical_id": value.logical_id,
        "packages": list(value.packages),
        "provenance": dict(value.provenance),
        "schema_version": value.schema_version,
        "service_enabled": value.service_enabled,
        "service_inactive": value.service_inactive,
        "status": value.status.value,
    }


def _monitoring_stack_object(value: MonitoringStackEvidence) -> dict[str, object]:
    return {
        "containers_started": value.containers_started,
        "logical_id": value.logical_id,
        "provenance": dict(value.provenance),
        "schema_version": value.schema_version,
        "service_enabled": value.service_enabled,
        "status": value.status.value,
    }


def _monitoring_targets_object(value: MonitoringTargetsEvidence) -> dict[str, object]:
    return {
        "containers_started": value.containers_started,
        "exporters_started": value.exporters_started,
        "logical_id": value.logical_id,
        "provenance": dict(value.provenance),
        "schema_version": value.schema_version,
        "stack_started": value.stack_started,
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
            raise AnsibleError("Ansible service-converge evidence has duplicate fields")
        value[key] = item
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible service-converge value is invalid")
    return value


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    return _text(value)


def _require_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError("Ansible service-converge boolean is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible service-converge digest is invalid")
    return text


def _sorted_strings(value: object, *, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError(f"Ansible service-converge {name} are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError(f"Ansible service-converge {name} are not uniquely sorted")
    return items


def _reject_secrets(value: dict[str, object]) -> None:
    encoded = json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True)
    if re.search(
        r"(?i)(?:-----BEGIN [^-]*PRIVATE KEY-----|"
        r"(?:password|passphrase|secret|token)\s*[:=])",
        encoded,
    ):
        raise AnsibleError("Ansible service-converge evidence contains a secret")
