"""Fail-closed full-cluster Scylla shutdown validation without unreviewed mutation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from scylla_vms.ansible.manager_tasks import (
    EXPECTED_BLOCKERS as MANAGER_TASK_BLOCKERS,
)
from scylla_vms.ansible.manager_tasks import ManagerTasksEvidence, ManagerTasksStatus
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.scylla_health import HealthReadiness, ScyllaHealthEvidence
from scylla_vms.ansible.scylla_remove_live import scylla_health_evidence_digest
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata

SCYLLA_CLUSTER_SHUTDOWN_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-scylla-cluster-shutdown/v1"
)
MANAGER_APPLICABILITY = "not-applicable"
MUTATION_BOUNDARY = "not-started"
NOT_PERFORMED = (
    "decommission",
    "drain",
    "manager-quiesce",
    "removenode",
    "start",
    "storage-wipe",
    "systemd-mask",
    "systemd-stop",
    "terraform",
    "vm-destroy",
)
EXPECTED_BLOCKERS = (
    "manager-tasks-not-applicable",
    "official-command-order-unreviewed",
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MARKER = re.compile(r"DSV_SCYLLA_CLUSTER_SHUTDOWN_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_BLOCKERS = frozenset(
    {
        *EXPECTED_BLOCKERS,
        "authorization-invalid",
        "execution-failed",
        "execution-interrupted",
        "health-not-ready",
        "host-failed",
        "host-unreachable",
        "identity-changed",
        "manager-quiesce-unproven",
        "service-inspect-failed",
    }
)
_FALSE_FLAGS = (
    "applied",
    "decommission_performed",
    "drain_performed",
    "manager_quiesce_performed",
    "mask_performed",
    "removenode_performed",
    "start_performed",
    "stop_performed",
    "storage_wiped",
    "terraform_ran",
    "vm_destroyed",
)
_NODE_STATES = ("not-performed", "not-predicted", "unknown")
_SERVICE_ENABLED = frozenset({"disabled", "enabled", "masked", "not-found"})
_SERVICE_ACTIVE = frozenset({"active", "failed", "inactive", "unknown"})


class ScyllaClusterShutdownStatus(StrEnum):
    NOT_PERFORMED = "not-performed"
    NOT_PREDICTED = "not-predicted"
    FAILED = "failed"


class NodeShutdownState(StrEnum):
    NOT_PERFORMED = "not-performed"
    NOT_PREDICTED = "not-predicted"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ScyllaClusterShutdownAuthorization:
    """Narrow destructive approval bound to one exact cluster/health snapshot."""

    operation_id: str
    cluster_uuid: str
    authorization_digest: str
    health_digest: str
    topology_digest: str
    observation_digest: str
    inventory_digest: str
    trust_digest: str
    manager_tasks_digest: str
    confirmed_cluster: str
    manager_applicability: str
    allow_manager_not_applicable: bool
    allow_destructive: bool
    reviewed: bool
    no_competing_operation: bool


@dataclass(frozen=True, slots=True)
class ScyllaClusterShutdownNodeEvidence:
    logical_id: str
    host_id_digest: str
    drain_state: NodeShutdownState
    stop_state: NodeShutdownState
    mask_state: NodeShutdownState
    observed_enabled: str | None
    observed_active: str | None


@dataclass(frozen=True, slots=True)
class ScyllaClusterShutdownEvidence:
    status: ScyllaClusterShutdownStatus
    nodes: tuple[ScyllaClusterShutdownNodeEvidence, ...]
    applied: bool
    drain_performed: bool
    stop_performed: bool
    mask_performed: bool
    manager_quiesce_performed: bool
    decommission_performed: bool
    removenode_performed: bool
    start_performed: bool
    terraform_ran: bool
    vm_destroyed: bool
    storage_wiped: bool
    mutation_boundary: str
    recovery_required: bool
    not_performed: tuple[str, ...]
    provenance: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]
    schema_version: str = SCYLLA_CLUSTER_SHUTDOWN_SCHEMA_VERSION


def build_scylla_cluster_shutdown_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    health: ScyllaHealthEvidence,
    manager_tasks: ManagerTasksEvidence,
    authorization: ScyllaClusterShutdownAuthorization,
    *,
    limit: tuple[str, ...],
) -> dict[str, object]:
    """Build one fail-closed full-cluster shutdown validation request."""

    scylla_hosts = tuple(
        host for host in inventory.record.inventory.hosts if host.role.value == "scylla"
    )
    expected_ids = tuple(host.logical_id for host in scylla_hosts)
    if not expected_ids or limit != expected_ids or limit != tuple(sorted(set(limit))):
        raise StateConflictError(
            "Scylla cluster shutdown requires the exact complete Scylla set"
        )
    if (
        metadata.cluster_uuid != inventory.record.cluster_uuid
        or metadata.cluster_name != inventory.record.cluster_name
        or metadata.provider != inventory.record.provider
        or observed.record.cluster_uuid != inventory.record.cluster_uuid
        or observed.record.cluster_name != inventory.record.cluster_name
        or observed.record.generation != inventory.record.source_manifest_generation
        or readiness.observation_generation != observed.record.generation
        or readiness.observation_digest != observed.digest
        or readiness.inventory_generation != inventory.record.generation
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_generation is None
        or readiness.trust_digest is None
    ):
        raise StateConflictError("Scylla cluster shutdown provenance conflicts")
    health_digest = _require_current_health(health, expected_ids)
    manager_digest = _require_manager_not_applicable(manager_tasks)
    _validate_authorization(
        metadata,
        observed,
        inventory,
        readiness,
        health,
        health_digest,
        manager_digest,
        authorization,
    )
    hosts = []
    for host in scylla_hosts:
        node = next(item for item in health.nodes if item.logical_id == host.logical_id)
        if host.scylla_datacenter is None or host.scylla_rack is None:
            raise StateConflictError("Scylla cluster shutdown topology is incomplete")
        hosts.append(
            {
                "datacenter": host.scylla_datacenter,
                "host_id": node.host_id,
                "logical_id": host.logical_id,
                "provider_id_digest": node.provider_id_digest,
                "rack": host.scylla_rack,
            }
        )
    provenance = {
        "authorization_digest": authorization.authorization_digest,
        "health_digest": health_digest,
        "inventory_digest": inventory.digest,
        "manager_tasks_digest": manager_digest,
        "observation_digest": observed.digest,
        "topology_digest": health.topology_digest,
        "trust_digest": readiness.trust_digest,
    }
    return {
        "applied": False,
        "authorization": {
            "allow_destructive": True,
            "allow_manager_not_applicable": True,
            "authorization_digest": authorization.authorization_digest,
            "confirmed_cluster": authorization.confirmed_cluster,
            "manager_applicability": MANAGER_APPLICABILITY,
            "no_competing_operation": True,
            "operation_id": authorization.operation_id,
            "reviewed": True,
        },
        "cluster_uuid": str(metadata.cluster_uuid),
        "decommission_performed": False,
        "drain_performed": False,
        "expected_blockers": list(EXPECTED_BLOCKERS),
        "health_digest": health_digest,
        "hosts": hosts,
        "inventory_digest": inventory.digest,
        "manager_quiesce_performed": False,
        "mask_performed": False,
        "mutation_boundary": MUTATION_BOUNDARY,
        "not_performed": list(NOT_PERFORMED),
        "observation_digest": observed.digest,
        "provenance": provenance,
        "removenode_performed": False,
        "schema_version": SCYLLA_CLUSTER_SHUTDOWN_SCHEMA_VERSION,
        "start_performed": False,
        "stop_performed": False,
        "storage_wiped": False,
        "terraform_ran": False,
        "topology_digest": health.topology_digest,
        "trust_digest": readiness.trust_digest,
        "vm_destroyed": False,
    }


def parse_scylla_cluster_shutdown_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> ScyllaClusterShutdownEvidence:
    """Parse only the bounded normalized cluster-shutdown result and recap."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError(
            "Ansible Scylla cluster-shutdown output exceeds the evidence limit"
        )
    expected_ids = tuple(
        _text(cast(dict[str, object], item)["logical_id"])
        for item in cast(list[object], expected_payload["hosts"])
    )
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_SCYLLA_CLUSTER_SHUTDOWN_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible Scylla cluster-shutdown marker is malformed")
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"), object_pairs_hook=_strict_object
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible Scylla cluster-shutdown marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible Scylla cluster-shutdown evidence is malformed")
        values.append(value)
    recap = _parse_recap(stdout)
    if set(recap) != set(expected_ids):
        raise AnsibleError("Ansible Scylla cluster-shutdown recap membership conflicts")
    recap_failed = any(
        unreachable or failed for _, unreachable, failed in recap.values()
    )
    if not values:
        if not recap_failed or exit_code == 0:
            raise AnsibleError("Ansible Scylla cluster-shutdown evidence is incomplete")
        return _failed_evidence(expected_payload)
    if {item for item, recap_row in recap.items() if recap_row[0]}:
        raise AnsibleError("Ansible Scylla cluster-shutdown changed status conflicts")
    nodes: list[ScyllaClusterShutdownNodeEvidence] = []
    status: ScyllaClusterShutdownStatus | None = None
    blockers: tuple[str, ...] | None = None
    for value in values:
        evidence = _parse_host_result(value, expected_payload)
        if status is None:
            status = evidence.status
            blockers = evidence.blockers
        elif evidence.status != status or evidence.blockers != blockers:
            raise AnsibleError(
                "Ansible Scylla cluster-shutdown host evidence conflicts"
            )
        nodes.extend(evidence.nodes)
    if status is None or blockers is None:
        raise AnsibleError("Ansible Scylla cluster-shutdown evidence is incomplete")
    nodes.sort(key=lambda item: item.logical_id)
    logical_ids = tuple(node.logical_id for node in nodes)
    if logical_ids != expected_ids or len(nodes) != len(expected_ids):
        raise AnsibleError("Ansible Scylla cluster-shutdown node membership conflicts")
    failed = status is ScyllaClusterShutdownStatus.FAILED
    predicted = status is ScyllaClusterShutdownStatus.NOT_PREDICTED
    if predicted and (exit_code == 0 or not recap_failed):
        raise AnsibleError("Ansible Scylla cluster-shutdown check refusal conflicts")
    if not predicted and (recap_failed != failed or (exit_code == 0) == failed):
        raise AnsibleError("Ansible Scylla cluster-shutdown exit status conflicts")
    return ScyllaClusterShutdownEvidence(
        status,
        tuple(nodes),
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
        MUTATION_BOUNDARY,
        False,
        NOT_PERFORMED,
        _provenance(expected_payload),
        blockers,
    )


def _require_current_health(
    health: ScyllaHealthEvidence, expected_ids: tuple[str, ...]
) -> str:
    if (
        health.status is HealthReadiness.BLOCKED
        or health.blockers
        or health.query_policy != "all-nodes-cross-view"
        or health.queried_nodes != expected_ids
        or tuple(item.logical_id for item in health.nodes) != expected_ids
        or any(item.state != "UN" or item.host_id is None for item in health.nodes)
        or health.schema_agreement is not True
        or health.schema_digest is None
        or health.topology_digest is None
        or health.streaming_state != "complete"
    ):
        raise StateConflictError(
            "Scylla cluster shutdown requires current full-cluster health"
        )
    digest = scylla_health_evidence_digest(health)
    _require_digest(digest)
    _require_digest(health.topology_digest)
    return digest


def _require_manager_not_applicable(manager_tasks: ManagerTasksEvidence) -> str:
    if (
        manager_tasks.status is not ManagerTasksStatus.NOT_PERFORMED
        or manager_tasks.applied
        or manager_tasks.quiesce_performed
        or manager_tasks.sctool_invoked
        or manager_tasks.service_started
        or manager_tasks.registration_performed
        or manager_tasks.backend_configured
        or manager_tasks.blockers != MANAGER_TASK_BLOCKERS
    ):
        raise StateConflictError(
            "Scylla cluster shutdown requires Manager tasks not-performed evidence"
        )
    digest = _object_digest(
        {
            "action": manager_tasks.action,
            "applied": manager_tasks.applied,
            "blockers": list(manager_tasks.blockers),
            "logical_id": manager_tasks.logical_id,
            "quiesce_performed": manager_tasks.quiesce_performed,
            "registration_performed": manager_tasks.registration_performed,
            "service_started": manager_tasks.service_started,
            "sctool_invoked": manager_tasks.sctool_invoked,
            "status": manager_tasks.status.value,
        }
    )
    return digest


def _validate_authorization(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    health: ScyllaHealthEvidence,
    health_digest: str,
    manager_digest: str,
    value: ScyllaClusterShutdownAuthorization,
) -> None:
    try:
        valid_ids = (
            str(uuid.UUID(value.operation_id)) == value.operation_id
            and str(uuid.UUID(value.cluster_uuid)) == value.cluster_uuid
        )
    except ValueError:
        valid_ids = False
    confirmed = f"{metadata.cluster_name}:{metadata.cluster_uuid}"
    if (
        not valid_ids
        or value.cluster_uuid != str(metadata.cluster_uuid)
        or value.observation_digest != observed.digest
        or value.inventory_digest != inventory.digest
        or value.trust_digest != readiness.trust_digest
        or value.health_digest != health_digest
        or value.topology_digest != health.topology_digest
        or value.manager_tasks_digest != manager_digest
        or value.confirmed_cluster != confirmed
        or value.manager_applicability != MANAGER_APPLICABILITY
        or not value.allow_manager_not_applicable
        or not value.allow_destructive
        or not value.reviewed
        or not value.no_competing_operation
    ):
        raise StateConflictError(
            "cluster-shutdown authorization does not bind the exact execution"
        )
    for digest in (
        value.authorization_digest,
        value.health_digest,
        value.topology_digest,
        value.observation_digest,
        value.inventory_digest,
        value.trust_digest,
        value.manager_tasks_digest,
    ):
        _require_digest(digest)


def _parse_host_result(
    value: dict[str, object], expected: dict[str, object]
) -> ScyllaClusterShutdownEvidence:
    fields = {
        "applied",
        "blockers",
        "decommission_performed",
        "drain_performed",
        "manager_quiesce_performed",
        "mask_performed",
        "mutation_boundary",
        "nodes",
        "not_performed",
        "provenance",
        "recovery_required",
        "removenode_performed",
        "schema_version",
        "start_performed",
        "status",
        "stop_performed",
        "storage_wiped",
        "terraform_ran",
        "vm_destroyed",
    }
    if (
        set(value) != fields
        or value["schema_version"] != SCYLLA_CLUSTER_SHUTDOWN_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible Scylla cluster-shutdown evidence schema is invalid")
    try:
        status = ScyllaClusterShutdownStatus(_text(value["status"]))
    except ValueError as error:
        raise AnsibleError(
            "Ansible Scylla cluster-shutdown status is invalid"
        ) from error
    not_performed = _sorted_strings(value["not_performed"], name="not-performed")
    if not_performed != NOT_PERFORMED:
        raise AnsibleError(
            "Ansible Scylla cluster-shutdown not-performed set is invalid"
        )
    blockers = _sorted_strings(value["blockers"], name="blockers")
    if not set(blockers) <= _BLOCKERS:
        raise AnsibleError("Ansible Scylla cluster-shutdown blocker is unknown")
    provenance_value = value["provenance"]
    expected_provenance = cast(dict[str, object], expected["provenance"])
    if (
        not isinstance(provenance_value, dict)
        or provenance_value != expected_provenance
    ):
        raise AnsibleError("Ansible Scylla cluster-shutdown provenance conflicts")
    flags = {name: _require_bool(value[name]) for name in _FALSE_FLAGS}
    if any(flags.values()):
        raise AnsibleError(
            "Ansible Scylla cluster-shutdown claimed a forbidden mutation"
        )
    if value["mutation_boundary"] != MUTATION_BOUNDARY or value["recovery_required"]:
        raise AnsibleError(
            "Ansible Scylla cluster-shutdown mutation boundary conflicts"
        )
    nodes = _parse_nodes(value["nodes"], expected, status)
    if status is ScyllaClusterShutdownStatus.NOT_PERFORMED and (
        blockers != EXPECTED_BLOCKERS
        or any(
            node.drain_state is not NodeShutdownState.NOT_PERFORMED
            or node.stop_state is not NodeShutdownState.NOT_PERFORMED
            or node.mask_state is not NodeShutdownState.NOT_PERFORMED
            or node.observed_enabled is None
            or node.observed_active is None
            for node in nodes
        )
    ):
        raise AnsibleError("Ansible Scylla cluster-shutdown success evidence conflicts")
    if status is ScyllaClusterShutdownStatus.NOT_PREDICTED and (
        blockers
        or any(
            node.drain_state is not NodeShutdownState.NOT_PREDICTED
            or node.stop_state is not NodeShutdownState.NOT_PREDICTED
            or node.mask_state is not NodeShutdownState.NOT_PREDICTED
            or node.observed_enabled is not None
            or node.observed_active is not None
            for node in nodes
        )
    ):
        raise AnsibleError("Ansible Scylla cluster-shutdown check evidence conflicts")
    if status is ScyllaClusterShutdownStatus.FAILED and (
        not blockers or set(blockers) <= set(EXPECTED_BLOCKERS)
    ):
        raise AnsibleError("Ansible Scylla cluster-shutdown failure evidence conflicts")
    _reject_secrets(value)
    return ScyllaClusterShutdownEvidence(
        status,
        nodes,
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
        MUTATION_BOUNDARY,
        False,
        NOT_PERFORMED,
        _provenance(expected),
        blockers,
    )


def _parse_nodes(
    value: object,
    expected: dict[str, object],
    status: ScyllaClusterShutdownStatus,
) -> tuple[ScyllaClusterShutdownNodeEvidence, ...]:
    if not isinstance(value, list) or not value:
        raise AnsibleError("Ansible Scylla cluster-shutdown nodes are invalid")
    hosts = {
        _text(cast(dict[str, object], item)["logical_id"]): _digest_text(
            _text(cast(dict[str, object], item)["host_id"])
        )
        for item in cast(list[object], expected["hosts"])
    }
    nodes: list[ScyllaClusterShutdownNodeEvidence] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "drain_state",
            "host_id_digest",
            "logical_id",
            "mask_state",
            "observed_active",
            "observed_enabled",
            "stop_state",
        }:
            raise AnsibleError("Ansible Scylla cluster-shutdown node schema is invalid")
        logical_id = _text(item["logical_id"])
        if (
            _LOGICAL_ID.fullmatch(logical_id) is None
            or logical_id in seen
            or logical_id not in hosts
        ):
            raise AnsibleError(
                "Ansible Scylla cluster-shutdown node identity conflicts"
            )
        seen.add(logical_id)
        try:
            drain = NodeShutdownState(_text(item["drain_state"]))
            stop = NodeShutdownState(_text(item["stop_state"]))
            mask = NodeShutdownState(_text(item["mask_state"]))
        except ValueError as error:
            raise AnsibleError(
                "Ansible Scylla cluster-shutdown node state is invalid"
            ) from error
        if {drain.value, stop.value, mask.value} - set(_NODE_STATES):
            raise AnsibleError("Ansible Scylla cluster-shutdown node state is invalid")
        enabled = _optional_service(item["observed_enabled"], _SERVICE_ENABLED)
        active = _optional_service(item["observed_active"], _SERVICE_ACTIVE)
        host_digest = _require_digest(item["host_id_digest"])
        if host_digest != hosts[logical_id]:
            raise AnsibleError(
                "Ansible Scylla cluster-shutdown Host ID digest conflicts"
            )
        nodes.append(
            ScyllaClusterShutdownNodeEvidence(
                logical_id,
                host_digest,
                drain,
                stop,
                mask,
                enabled,
                active,
            )
        )
    return tuple(sorted(nodes, key=lambda item: item.logical_id))


def _failed_evidence(expected: dict[str, object]) -> ScyllaClusterShutdownEvidence:
    hosts = cast(list[object], expected["hosts"])
    nodes = tuple(
        ScyllaClusterShutdownNodeEvidence(
            _text(cast(dict[str, object], item)["logical_id"]),
            _digest_text(_text(cast(dict[str, object], item)["host_id"])),
            NodeShutdownState.UNKNOWN,
            NodeShutdownState.UNKNOWN,
            NodeShutdownState.UNKNOWN,
            None,
            None,
        )
        for item in hosts
    )
    return ScyllaClusterShutdownEvidence(
        ScyllaClusterShutdownStatus.FAILED,
        nodes,
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
        MUTATION_BOUNDARY,
        False,
        NOT_PERFORMED,
        _provenance(expected),
        ("execution-failed",),
    )


def _parse_recap(stdout: str) -> dict[str, tuple[int, int, int]]:
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible Scylla cluster-shutdown output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible Scylla cluster-shutdown recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    return rows


def _provenance(expected: dict[str, object]) -> tuple[tuple[str, str], ...]:
    provenance = cast(dict[str, object], expected["provenance"])
    return tuple(
        sorted(
            (_text(name), _require_digest(item)) for name, item in provenance.items()
        )
    )


def _object_digest(value: object) -> str:
    data = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _digest_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AnsibleError(
                "Ansible Scylla cluster-shutdown evidence has duplicate fields"
            )
        value[key] = item
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible Scylla cluster-shutdown value is invalid")
    return value


def _require_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError("Ansible Scylla cluster-shutdown boolean is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible Scylla cluster-shutdown digest is invalid")
    return text


def _optional_service(value: object, allowed: frozenset[str]) -> str | None:
    if value is None:
        return None
    text = _text(value)
    if text not in allowed:
        raise AnsibleError("Ansible Scylla cluster-shutdown service state is invalid")
    return text


def _sorted_strings(value: object, *, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError(f"Ansible Scylla cluster-shutdown {name} are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError(
            f"Ansible Scylla cluster-shutdown {name} are not uniquely sorted"
        )
    return items


def _reject_secrets(value: dict[str, object]) -> None:
    encoded = json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True)
    if re.search(
        r"(?i)(?:-----BEGIN [^-]*PRIVATE KEY-----|"
        r"(?:password|passphrase|secret|token)\s*[:=])",
        encoded,
    ):
        raise AnsibleError("Ansible Scylla cluster-shutdown evidence contains a secret")
