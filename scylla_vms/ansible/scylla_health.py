"""Strict read-only ScyllaDB topology and health evidence contracts."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.scylla_install import SCYLLA_PACKAGE_VERSION
from scylla_vms.ansible.storage_postcheck import StoragePostcheckEvidence
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata, parse_timestamp

SCYLLA_HEALTH_SCHEMA_VERSION = "deploy-scylla-vms.ansible-scylla-health/v1"
SCYLLA_HEALTH_VIEW_SCHEMA_VERSION = "deploy-scylla-vms.ansible-scylla-health-view/v1"

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MARKER = re.compile(r"DSV_SCYLLA_HEALTH_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_NODE_STATES = frozenset({"UN", "UJ", "UL", "UM", "DN", "DJ", "DL", "DM"})
_COMMANDS = (
    ("/usr/bin/nodetool", "info"),
    ("/usr/bin/nodetool", "status"),
    ("/usr/bin/nodetool", "describecluster"),
    ("/usr/bin/nodetool", "netstats"),
    ("/usr/bin/nodetool", "version"),
    ("/usr/bin/systemctl", "is-active", "scylla-server.service"),
)
_BLOCKERS = frozenset(
    {
        "api-unreachable",
        "backup-policy-not-performed",
        "capacity-not-proven",
        "cql-unreachable",
        "duplicate-host-id",
        "extra-ring-member",
        "host-failed",
        "host-unreachable",
        "identity-conflict",
        "inconsistent-ring-view",
        "missing-ring-member",
        "node-not-up-normal",
        "node-not-queried",
        "quorum-not-proven",
        "replication-not-performed",
        "schema-disagreement",
        "service-inactive",
        "storage-not-ready",
        "streaming-active",
        "topology-conflict",
        "version-conflict",
        "view-command-failed",
    }
)


class HealthCheckStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    UNKNOWN = "unknown"
    NOT_PERFORMED = "not-performed"


class HealthReadiness(StrEnum):
    READY = "ready"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class HealthCheck:
    name: str
    status: HealthCheckStatus


@dataclass(frozen=True, slots=True)
class ScyllaNodeHealth:
    logical_id: str
    host_id: str | None
    provider_id_digest: str
    state: str
    datacenter: str
    rack: str
    version: str
    service_state: str
    cql_reachable: bool | None
    api_reachable: bool | None
    storage_ready: bool
    storage_usable_gib: int
    checks: tuple[HealthCheck, ...]
    blockers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OperationHealthGate:
    operation_class: str
    readiness: HealthReadiness
    blockers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ScyllaHealthEvidence:
    status: HealthReadiness
    query_policy: str
    queried_nodes: tuple[str, ...]
    captured_at_start: str
    captured_at_end: str
    nodes: tuple[ScyllaNodeHealth, ...]
    checks: tuple[HealthCheck, ...]
    schema_digest: str | None
    schema_agreement: bool | None
    topology_digest: str | None
    streaming_state: str
    operation_gates: tuple[OperationHealthGate, ...]
    provenance: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]
    schema_version: str = SCYLLA_HEALTH_SCHEMA_VERSION


def build_scylla_health_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    storage: tuple[StoragePostcheckEvidence, ...],
    *,
    limit: tuple[str, ...],
    timeout_seconds: int,
    known_host_ids: dict[str, str] | None = None,
    active_stable_ids: tuple[str, ...] | None = None,
    expected_version: str = SCYLLA_PACKAGE_VERSION,
    storage_bindings: Mapping[str, tuple[bool, str]] | None = None,
) -> dict[str, object]:
    """Build a full-view or known-identity coordinator health request."""

    if not 1 <= timeout_seconds <= 60:
        raise StateConflictError("Scylla health command timeout is invalid")
    scylla_hosts = tuple(
        host for host in inventory.record.inventory.hosts if host.role.value == "scylla"
    )
    desired_ids = tuple(host.logical_id for host in scylla_hosts)
    expected_ids = desired_ids if active_stable_ids is None else active_stable_ids
    if (
        not desired_ids
        or expected_ids != tuple(sorted(set(expected_ids)))
        or not set(expected_ids) <= set(desired_ids)
        or limit != tuple(sorted(set(limit)))
        or expected_version != SCYLLA_PACKAGE_VERSION
    ):
        raise StateConflictError("Scylla health targets are invalid")
    if limit == expected_ids:
        query_policy = "all-nodes-cross-view"
        normalized_known: dict[str, str] = {}
    elif len(limit) == 1 and known_host_ids is not None:
        query_policy = "coordinator-known-identities"
        normalized_known = _validate_known_host_ids(known_host_ids, expected_ids)
    else:
        raise StateConflictError(
            "Scylla health requires all nodes or one coordinator with exact Host IDs"
        )
    if (
        metadata.cluster_uuid != inventory.record.cluster_uuid
        or metadata.cluster_name != inventory.record.cluster_name
        or metadata.provider != inventory.record.provider
        or observed.record.cluster_uuid != inventory.record.cluster_uuid
        or observed.record.cluster_name != inventory.record.cluster_name
        or observed.record.generation != inventory.record.source_manifest_generation
        or observed.record.manifest_digest != inventory.record.source_manifest_digest
        or readiness.observation_generation != observed.record.generation
        or readiness.observation_digest != observed.digest
        or readiness.inventory_generation != inventory.record.generation
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_generation is None
        or readiness.trust_digest is None
    ):
        raise StateConflictError("Scylla health input provenance conflicts")
    storage_by_id = {item.logical_id: item for item in storage}
    if storage_bindings is None:
        if set(storage_by_id) != set(expected_ids) or len(storage_by_id) != len(
            storage
        ):
            raise StateConflictError(
                "Scylla health storage evidence membership conflicts"
            )
        normalized_storage = {
            logical_id: (
                item.readiness_for_scylla,
                _object_digest(_storage_object(item)),
            )
            for logical_id, item in storage_by_id.items()
        }
    else:
        if storage or set(storage_bindings) != set(expected_ids):
            raise StateConflictError(
                "Scylla health storage evidence membership conflicts"
            )
        normalized_storage = {}
        for logical_id, binding in storage_bindings.items():
            if (
                not isinstance(binding, tuple)
                or len(binding) != 2
                or not isinstance(binding[0], bool)
                or not isinstance(binding[1], str)
                or _DIGEST.fullmatch(binding[1]) is None
            ):
                raise StateConflictError("Scylla health storage binding is invalid")
            normalized_storage[logical_id] = binding
    hosts: list[dict[str, object]] = []
    for host in scylla_hosts:
        if host.logical_id not in expected_ids:
            continue
        storage_ready, storage_digest = normalized_storage[host.logical_id]
        if host.scylla_datacenter is None or host.scylla_rack is None:
            raise StateConflictError("Scylla health topology is incomplete")
        hosts.append(
            {
                "datacenter": host.scylla_datacenter,
                "host_id": normalized_known.get(host.logical_id),
                "logical_id": host.logical_id,
                "private_address": host.private_address,
                "provider_id_digest": _digest_text(host.provider_id),
                "rack": host.scylla_rack,
                "storage_digest": storage_digest,
                "storage_ready": storage_ready,
                "storage_usable_gib": host.storage_usable_gib,
                "version": expected_version,
            }
        )
    return {
        "cluster_uuid": str(metadata.cluster_uuid),
        "expected_hosts": hosts,
        "provenance": {
            "inventory_digest": inventory.digest,
            "inventory_generation": str(inventory.record.generation),
            "observation_captured_at": getattr(
                observed.record, "captured_at", inventory.record.captured_at
            ),
            "observation_digest": observed.digest,
            "observation_generation": str(observed.record.generation),
            "trust_digest": readiness.trust_digest,
            "trust_generation": str(readiness.trust_generation),
        },
        "queried_nodes": list(limit),
        "query_policy": query_policy,
        "schema_version": SCYLLA_HEALTH_SCHEMA_VERSION,
        "timeout_seconds": timeout_seconds,
    }


def parse_scylla_health_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> ScyllaHealthEvidence:
    """Parse normalized node views and reconcile exact cluster identity."""

    if len(stdout.encode("utf-8")) > 1024 * 1024:
        raise AnsibleError("Ansible Scylla health output exceeds the evidence limit")
    if (
        set(expected_payload)
        != {
            "cluster_uuid",
            "expected_hosts",
            "provenance",
            "queried_nodes",
            "query_policy",
            "schema_version",
            "timeout_seconds",
        }
        or expected_payload.get("schema_version") != SCYLLA_HEALTH_SCHEMA_VERSION
    ):
        raise AnsibleError("Scylla health request schema is invalid")
    expected_hosts = _expected_hosts(expected_payload)
    queried = _sorted_texts(expected_payload.get("queried_nodes"), "queried nodes")
    recap = _parse_recap(stdout)
    if set(recap) != set(queried):
        raise AnsibleError("Ansible Scylla health recap membership conflicts")
    views: dict[str, dict[str, object]] = {}
    for line in stdout.splitlines():
        if "DSV_SCYLLA_HEALTH_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible Scylla health marker is malformed")
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError("Ansible Scylla health marker is malformed") from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible Scylla health view is malformed")
        logical_id = _text(value.get("logical_id"))
        if logical_id in views or logical_id not in queried:
            raise AnsibleError("Ansible Scylla health view membership conflicts")
        views[logical_id] = _validate_view(value)
    for logical_id, (changed, unreachable, failed) in recap.items():
        if changed:
            raise AnsibleError(
                f"Ansible Scylla health unexpectedly changed host: {logical_id}"
            )
        if logical_id in views and unreachable:
            raise AnsibleError("Ansible Scylla health view conflicts with recap")
        if (
            logical_id in views
            and failed
            and not cast(list[str], views[logical_id]["errors"])
        ):
            raise AnsibleError("Ansible Scylla health failure lacks bounded evidence")
        if logical_id not in views and not (unreachable or failed):
            raise AnsibleError("Ansible Scylla health evidence is incomplete")
    failed_recap = any(
        unreachable or failed for _, unreachable, failed in recap.values()
    )
    if (exit_code == 0) == failed_recap:
        raise AnsibleError("Ansible Scylla health exit status conflicts")
    return _reconcile(expected_payload, expected_hosts, queried, views, recap)


def _reconcile(
    payload: dict[str, object],
    expected_hosts: dict[str, dict[str, object]],
    queried: tuple[str, ...],
    views: dict[str, dict[str, object]],
    recap: dict[str, tuple[int, int, int]],
) -> ScyllaHealthEvidence:
    blockers: set[str] = set()
    local_host_ids: dict[str, str] = {}
    timestamps: list[str] = []
    for logical_id, local_view in views.items():
        timestamps.append(_text(local_view["captured_at"]))
        local_host_ids[logical_id] = _uuid_text(local_view["local_host_id"])
    for logical_id, expected in expected_hosts.items():
        known = expected["host_id"]
        if known is not None:
            known_id = _uuid_text(known)
            previous = local_host_ids.setdefault(logical_id, known_id)
            if previous != known_id:
                blockers.add("identity-conflict")
    if len(set(local_host_ids.values())) != len(local_host_ids):
        blockers.add("duplicate-host-id")
    expected_host_ids = set(local_host_ids.values())
    canonical_ring: tuple[tuple[str, str, str, str], ...] | None = None
    schema_sets: list[tuple[str, ...]] = []
    streaming_complete = True
    for queried_view in views.values():
        ring = tuple(
            (
                _uuid_text(cast(dict[str, object], row)["host_id"]),
                _text(cast(dict[str, object], row)["state"]),
                _text(cast(dict[str, object], row)["datacenter"]),
                _text(cast(dict[str, object], row)["rack"]),
            )
            for row in cast(list[object], queried_view["ring"])
        )
        if {row[0] for row in ring} - expected_host_ids:
            blockers.add("extra-ring-member")
        if expected_host_ids - {row[0] for row in ring}:
            blockers.add("missing-ring-member")
        if canonical_ring is None:
            canonical_ring = ring
        elif canonical_ring != ring:
            blockers.add("inconsistent-ring-view")
        schemas = tuple(cast(list[str], queried_view["schema_versions"]))
        schema_sets.append(schemas)
        if (
            _text(queried_view["mode"]) != "NORMAL"
            or cast(int, queried_view["sending_streams"]) != 0
            or cast(int, queried_view["receiving_streams"]) != 0
        ):
            streaming_complete = False
            blockers.add("streaming-active")
    schema_agreement: bool | None
    schema_digest: str | None
    if not schema_sets:
        schema_agreement = None
        schema_digest = None
    else:
        schema_agreement = (
            all(item == schema_sets[0] for item in schema_sets)
            and len(schema_sets[0]) == 1
        )
        schema_digest = _object_digest(list(schema_sets[0]))
        if not schema_agreement:
            blockers.add("schema-disagreement")
    ring_by_host_id = {
        host_id: (state, dc, rack)
        for host_id, state, dc, rack in (canonical_ring or ())
    }
    nodes: list[ScyllaNodeHealth] = []
    for logical_id, expected in sorted(expected_hosts.items()):
        node_blockers: set[str] = set()
        host_id = local_host_ids.get(logical_id)
        state = "unknown"
        dc = _text(expected["datacenter"])
        rack = _text(expected["rack"])
        version = "unknown"
        if host_id is not None and host_id in ring_by_host_id:
            state, ring_dc, ring_rack = ring_by_host_id[host_id]
            if state != "UN":
                node_blockers.add("node-not-up-normal")
            if ring_dc != dc or ring_rack != rack:
                node_blockers.add("topology-conflict")
        else:
            node_blockers.add("missing-ring-member")
        node_view = views.get(logical_id)
        service_state = "unknown"
        cql: bool | None = None
        api: bool | None = None
        if node_view is None and logical_id not in queried:
            node_blockers.add("node-not-queried")
        elif node_view is None:
            _, unreachable, _ = recap.get(logical_id, (0, 0, 1))
            node_blockers.add("host-unreachable" if unreachable else "host-failed")
        else:
            service_state = _text(node_view["service_state"])
            cql = cast(bool, node_view["cql_reachable"])
            api = cast(bool, node_view["api_reachable"])
            version = _text(node_view["version"])
            if service_state != "active":
                node_blockers.add("service-inactive")
            if not cql:
                node_blockers.add("cql-unreachable")
            if not api:
                node_blockers.add("api-unreachable")
            if version != _text(expected["version"]):
                node_blockers.add("version-conflict")
            if cast(list[str], node_view["errors"]):
                node_blockers.add("view-command-failed")
            if "identity" in cast(list[str], node_view["errors"]):
                node_blockers.add("identity-conflict")
        storage_ready = cast(bool, expected["storage_ready"])
        if not storage_ready:
            node_blockers.add("storage-not-ready")
        blockers.update(node_blockers)
        node_checks = (
            HealthCheck(
                "api-reachability",
                _boolean_status(api),
            ),
            HealthCheck("cql-reachability", _boolean_status(cql)),
            HealthCheck(
                "service-active",
                HealthCheckStatus.UNKNOWN
                if service_state == "unknown"
                else HealthCheckStatus.PASSED
                if service_state == "active"
                else HealthCheckStatus.FAILED,
            ),
            HealthCheck(
                "storage-readiness",
                HealthCheckStatus.PASSED if storage_ready else HealthCheckStatus.FAILED,
            ),
            HealthCheck(
                "topology",
                HealthCheckStatus.FAILED
                if {"missing-ring-member", "topology-conflict"} & node_blockers
                else HealthCheckStatus.PASSED,
            ),
            HealthCheck(
                "version",
                HealthCheckStatus.UNKNOWN
                if version == "unknown"
                else HealthCheckStatus.PASSED
                if version == expected["version"]
                else HealthCheckStatus.FAILED,
            ),
            HealthCheck(
                "up-normal",
                HealthCheckStatus.UNKNOWN
                if state == "unknown"
                else HealthCheckStatus.PASSED
                if state == "UN"
                else HealthCheckStatus.FAILED,
            ),
        )
        nodes.append(
            ScyllaNodeHealth(
                logical_id,
                host_id,
                _require_digest(expected["provider_id_digest"]),
                state,
                dc,
                rack,
                version,
                service_state,
                cql,
                api,
                storage_ready,
                _nonnegative_int(expected["storage_usable_gib"]),
                node_checks,
                tuple(sorted(node_blockers)),
            )
        )
    checks: tuple[HealthCheck, ...] = (
        HealthCheck(
            "backup-policy",
            HealthCheckStatus.NOT_PERFORMED,
        ),
        HealthCheck("capacity", HealthCheckStatus.UNKNOWN),
        HealthCheck(
            "cross-view-consistency",
            _failed_if("inconsistent-ring-view", blockers),
        ),
        HealthCheck(
            "membership",
            _failed_if(
                "extra-ring-member",
                blockers,
                secondary="missing-ring-member",
            ),
        ),
        HealthCheck("quorum", HealthCheckStatus.UNKNOWN),
        HealthCheck("replication", HealthCheckStatus.NOT_PERFORMED),
        HealthCheck(
            "schema-agreement",
            HealthCheckStatus.UNKNOWN
            if schema_agreement is None
            else HealthCheckStatus.PASSED
            if schema_agreement
            else HealthCheckStatus.FAILED,
        ),
        HealthCheck(
            "streaming",
            HealthCheckStatus.PASSED
            if views and streaming_complete
            else HealthCheckStatus.FAILED,
        ),
        HealthCheck(
            "topology",
            _failed_if("topology-conflict", blockers),
        ),
    )
    strong_unknown = {
        "backup-policy-not-performed",
        "capacity-not-proven",
        "quorum-not-proven",
        "replication-not-performed",
    }
    mutating_blockers = tuple(sorted(blockers | strong_unknown))
    gates = (
        OperationHealthGate(
            "read-only",
            HealthReadiness.READY if not blockers else HealthReadiness.BLOCKED,
            tuple(sorted(blockers)),
        ),
        OperationHealthGate(
            "mutating",
            HealthReadiness.BLOCKED,
            mutating_blockers,
        ),
        OperationHealthGate(
            "sensitive",
            HealthReadiness.BLOCKED,
            mutating_blockers,
        ),
        OperationHealthGate(
            "destructive",
            HealthReadiness.BLOCKED,
            mutating_blockers,
        ),
    )
    topology_digest = (
        _object_digest(
            [
                [node.logical_id, node.host_id, node.datacenter, node.rack]
                for node in nodes
            ]
        )
        if all(node.host_id is not None for node in nodes)
        else None
    )
    status = HealthReadiness.UNKNOWN if not blockers else HealthReadiness.BLOCKED
    provenance = _provenance(payload)
    start = (
        min(timestamps)
        if timestamps
        else _text(
            cast(dict[str, object], payload["provenance"]).get(
                "observation_captured_at"
            )
        )
    )
    end = max(timestamps) if timestamps else start
    return ScyllaHealthEvidence(
        status,
        _text(payload.get("query_policy")),
        queried,
        start,
        end,
        tuple(nodes),
        checks,
        schema_digest,
        schema_agreement,
        topology_digest,
        "complete" if views and streaming_complete else "active-or-unknown",
        gates,
        provenance,
        tuple(sorted(blockers)),
    )


def _expected_hosts(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    raw = payload.get("expected_hosts")
    if not isinstance(raw, list) or not raw or len(raw) > 256:
        raise AnsibleError("Scylla health expected hosts are invalid")
    result: dict[str, dict[str, object]] = {}
    fields = {
        "datacenter",
        "host_id",
        "logical_id",
        "private_address",
        "provider_id_digest",
        "rack",
        "storage_digest",
        "storage_ready",
        "storage_usable_gib",
        "version",
    }
    for item in raw:
        if not isinstance(item, dict) or set(item) != fields:
            raise AnsibleError("Scylla health expected host schema is invalid")
        logical_id = _text(item["logical_id"])
        if _LOGICAL_ID.fullmatch(logical_id) is None or logical_id in result:
            raise AnsibleError("Scylla health expected host identity is invalid")
        if not isinstance(item["storage_ready"], bool):
            raise AnsibleError("Scylla health storage readiness is invalid")
        _require_digest(item["provider_id_digest"])
        _require_digest(item["storage_digest"])
        try:
            private_address = ipaddress.ip_address(_text(item["private_address"]))
        except ValueError as error:
            raise AnsibleError("Scylla health private address is invalid") from error
        if (
            not isinstance(private_address, ipaddress.IPv4Address)
            or not private_address.is_private
        ):
            raise AnsibleError("Scylla health private address is invalid")
        _nonnegative_int(item["storage_usable_gib"])
        _text(item["version"])
        if item["host_id"] is not None:
            _uuid_text(item["host_id"])
        result[logical_id] = cast(dict[str, object], item)
    if tuple(result) != tuple(sorted(result)):
        raise AnsibleError("Scylla health expected hosts are not sorted")
    return result


def _validate_view(value: dict[str, object]) -> dict[str, object]:
    fields = {
        "api_reachable",
        "captured_at",
        "commands",
        "cql_reachable",
        "datacenter",
        "errors",
        "local_host_id",
        "logical_id",
        "mode",
        "rack",
        "receiving_streams",
        "ring",
        "schema_version",
        "schema_versions",
        "sending_streams",
        "service_state",
        "version",
    }
    if (
        set(value) != fields
        or value["schema_version"] != SCYLLA_HEALTH_VIEW_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible Scylla health view schema is invalid")
    if _LOGICAL_ID.fullmatch(_text(value["logical_id"])) is None:
        raise AnsibleError("Ansible Scylla health logical ID is invalid")
    _uuid_text(value["local_host_id"])
    parse_timestamp(_text(value["captured_at"]))
    for name in ("api_reachable", "cql_reachable"):
        if not isinstance(value[name], bool):
            raise AnsibleError("Ansible Scylla health reachability is invalid")
    if value["commands"] != [list(item) for item in _COMMANDS]:
        raise AnsibleError("Ansible Scylla health command evidence conflicts")
    _text(value["version"])
    errors = _sorted_texts(value["errors"], "view errors")
    if any(
        item
        not in {
            "describecluster",
            "identity",
            "info",
            "netstats",
            "status",
            "systemctl",
            "version",
        }
        for item in errors
    ):
        raise AnsibleError("Ansible Scylla health error is invalid")
    ring = value["ring"]
    if not isinstance(ring, list) or len(ring) > 256:
        raise AnsibleError("Ansible Scylla health ring is invalid")
    parsed_ring: list[dict[str, object]] = []
    for item in ring:
        if not isinstance(item, dict) or set(item) != {
            "datacenter",
            "host_id",
            "rack",
            "state",
        }:
            raise AnsibleError("Ansible Scylla health ring row is invalid")
        host_id = _uuid_text(item["host_id"])
        state = _text(item["state"])
        if state not in _NODE_STATES:
            raise AnsibleError("Ansible Scylla health node state is invalid")
        parsed_ring.append(
            {
                "datacenter": _text(item["datacenter"]),
                "host_id": host_id,
                "rack": _text(item["rack"]),
                "state": state,
            }
        )
    if parsed_ring != sorted(parsed_ring, key=lambda item: cast(str, item["host_id"])):
        raise AnsibleError("Ansible Scylla health ring rows are not sorted")
    schemas = _sorted_uuid_texts(value["schema_versions"])
    value["ring"] = parsed_ring
    value["schema_versions"] = list(schemas)
    value["errors"] = list(errors)
    _nonnegative_int(value["sending_streams"])
    _nonnegative_int(value["receiving_streams"])
    return value


def _parse_recap(stdout: str) -> dict[str, tuple[int, int, int]]:
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible Scylla health output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible Scylla health recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    return rows


def _validate_known_host_ids(
    value: dict[str, str], expected_ids: tuple[str, ...]
) -> dict[str, str]:
    if set(value) != set(expected_ids):
        raise StateConflictError("known Scylla Host IDs are incomplete")
    normalized = {key: _uuid_text(item) for key, item in value.items()}
    if len(set(normalized.values())) != len(normalized):
        raise StateConflictError("known Scylla Host IDs are duplicated")
    return normalized


def _provenance(payload: dict[str, object]) -> tuple[tuple[str, str], ...]:
    raw = payload.get("provenance")
    if not isinstance(raw, dict) or set(raw) != {
        "inventory_digest",
        "inventory_generation",
        "observation_captured_at",
        "observation_digest",
        "observation_generation",
        "trust_digest",
        "trust_generation",
    }:
        raise AnsibleError("Scylla health provenance is invalid")
    result = tuple(sorted((_text(key), _text(value)) for key, value in raw.items()))
    for key, value in result:
        if key.endswith("_digest"):
            _require_digest(value)
        elif key == "observation_captured_at":
            parse_timestamp(value)
        elif not value.isdigit() or int(value) < 1:
            raise AnsibleError("Scylla health provenance generation is invalid")
    return result


def _storage_object(value: StoragePostcheckEvidence) -> object:
    return {
        "backend": value.backend,
        "blockers": list(value.blockers),
        "checks": [(item.name, item.status.value) for item in value.checks],
        "devices": list(value.devices),
        "layout": value.layout,
        "logical_id": value.logical_id,
        "provenance": dict(value.provenance),
        "readiness_for_scylla": value.readiness_for_scylla,
    }


def _object_digest(value: object) -> str:
    encoded = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _digest_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _boolean_status(value: bool | None) -> HealthCheckStatus:
    if value is None:
        return HealthCheckStatus.UNKNOWN
    return HealthCheckStatus.PASSED if value else HealthCheckStatus.FAILED


def _failed_if(
    blocker: str, blockers: set[str], *, secondary: str | None = None
) -> HealthCheckStatus:
    return (
        HealthCheckStatus.FAILED
        if blocker in blockers or (secondary is not None and secondary in blockers)
        else HealthCheckStatus.PASSED
    )


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AnsibleError("Ansible Scylla health evidence has duplicate fields")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise AnsibleError(f"invalid Scylla health constant: {value}")


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible Scylla health value is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible Scylla health digest is invalid")
    return text


def _uuid_text(value: object) -> str:
    text = _text(value).lower()
    try:
        parsed = uuid.UUID(text)
    except ValueError as error:
        raise AnsibleError("Ansible Scylla Host ID is invalid") from error
    if str(parsed) != text:
        raise AnsibleError("Ansible Scylla Host ID is not canonical")
    return text


def _sorted_uuid_texts(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible Scylla schema versions are invalid")
    items = tuple(_uuid_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError("Ansible Scylla schema versions are not uniquely sorted")
    return items


def _sorted_texts(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError(f"Scylla health {label} are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError(f"Scylla health {label} are not uniquely sorted")
    return items


def _nonnegative_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AnsibleError("Ansible Scylla health integer is invalid")
    return value
