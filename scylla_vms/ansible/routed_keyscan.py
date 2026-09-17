"""Fail-closed private-host SSH key candidate collection through trusted jumps."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, cast

from scylla_vms.ansible.readiness import (
    EvidenceStatus,
    ReadinessReport,
    RouteReadiness,
    TrustReadiness,
    validate_current_readiness_report,
)
from scylla_vms.ansible.trust import (
    APPROVED_HOST_KEY_ALGORITHMS,
    HostEndpoint,
    HostKeyCandidate,
    StoredTrustRecord,
    TrustCaptureSource,
    TrustStore,
    validate_host_public_key,
)
from scylla_vms.desired import HostRole
from scylla_vms.errors import AnsibleError, StateConflictError, StatePersistenceError
from scylla_vms.inventory import InventoryHost, StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import (
    ClusterMetadata,
    digest_bytes,
    format_timestamp,
    parse_timestamp,
    serialize_json,
    validate_digest,
)

if TYPE_CHECKING:
    from scylla_vms.ansible.service import AnsibleService, HeldClusterLockProtocol


ROUTED_KEYSCAN_REQUEST_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-routed-keyscan-request/v1"
)
ROUTED_KEYSCAN_RESULT_SCHEMA_VERSION = "deploy-scylla-vms.ansible-routed-keyscan/v1"
ROUTED_KEYSCAN_COLLECTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ssh-key-candidate-collection/v1"
)
ROUTED_KEYSCAN_EXECUTABLE = "/usr/bin/ssh-keyscan"
ROUTED_KEYSCAN_PORT = 22
ROUTED_KEYSCAN_MAXIMUM_TARGETS = 64
ROUTED_KEYSCAN_MAXIMUM_OUTPUT_BYTES = 32 * 1024
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MARKER = re.compile(r"DSV_ROUTED_KEYSCAN_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_IPV4_TEXT = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
_EXECUTION_BLOCKERS = frozenset(
    {
        "execution-failed",
        "invalid-output",
        "output-limit-exceeded",
        "scan-timeout",
        "target-unreachable",
    }
)


class RoutedKeyscanExecutionStatus(StrEnum):
    COLLECTED = "collected"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    UNREACHABLE = "unreachable"


class RoutedCandidateStatus(StrEnum):
    COLLECTED = "collected"
    BLOCKED = "blocked"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    UNREACHABLE = "unreachable"


@dataclass(frozen=True, slots=True)
class RoutedKeyscanKey:
    algorithm: str
    public_key: str
    fingerprint: str

    def __post_init__(self) -> None:
        try:
            fingerprint = validate_host_public_key(self.algorithm, self.public_key)
        except (StateConflictError, StatePersistenceError) as error:
            raise AnsibleError("routed SSH keyscan key is invalid") from error
        if fingerprint != self.fingerprint:
            raise AnsibleError("routed SSH keyscan fingerprint conflicts")


@dataclass(frozen=True, slots=True)
class RoutedKeyscanTargetEvidence:
    logical_id: str
    route_digest: str
    status: RoutedKeyscanExecutionStatus
    keys: tuple[RoutedKeyscanKey, ...]
    blocker: str | None


@dataclass(frozen=True, slots=True)
class RoutedKeyscanExecutionEvidence:
    jump_host_id: str
    request_digest: str
    status: str
    targets: tuple[RoutedKeyscanTargetEvidence, ...]
    schema_version: str = ROUTED_KEYSCAN_RESULT_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class RoutedCandidateTarget:
    logical_id: str
    provider_id: str
    jump_host_id: str
    route_digest: str
    status: RoutedCandidateStatus
    candidates: tuple[HostKeyCandidate, ...]
    blockers: tuple[str, ...]

    def to_public_object(self) -> dict[str, object]:
        return {
            "blockers": list(self.blockers),
            "candidates": [
                {
                    "algorithm": candidate.algorithm,
                    "fingerprint": candidate.fingerprint,
                }
                for candidate in self.candidates
            ],
            "jump_host_id": self.jump_host_id,
            "logical_id": self.logical_id,
            "route_digest": self.route_digest,
            "status": self.status.value,
        }


@dataclass(frozen=True, slots=True)
class RoutedHostKeyCandidateCollection:
    captured_at: str
    status: str
    observation_generation: int
    observation_digest: str
    inventory_generation: int
    inventory_digest: str
    trust_generation: int
    trust_digest: str
    readiness_schema_version: str
    readiness_digest: str
    timeout_seconds: int
    jump_host_ids: tuple[str, ...]
    targets: tuple[RoutedCandidateTarget, ...]
    schema_version: str = ROUTED_KEYSCAN_COLLECTION_SCHEMA_VERSION

    def to_public_object(self) -> dict[str, object]:
        """Return an address-, provider-, path-, and public-key-free projection."""

        return {
            "captured_at": self.captured_at,
            "jumps": {"stable_ids": list(self.jump_host_ids)},
            "provenance": {
                "inventory": {
                    "digest": self.inventory_digest,
                    "generation": self.inventory_generation,
                },
                "observation": {
                    "digest": self.observation_digest,
                    "generation": self.observation_generation,
                },
                "readiness": {
                    "digest": self.readiness_digest,
                    "schema_version": self.readiness_schema_version,
                },
                "trust": {
                    "digest": self.trust_digest,
                    "generation": self.trust_generation,
                },
            },
            "schema_version": self.schema_version,
            "selection": {
                "count": len(self.targets),
                "stable_ids": [target.logical_id for target in self.targets],
            },
            "status": self.status,
            "targets": [target.to_public_object() for target in self.targets],
            "timeout_policy": {
                "approved_key_types": list(APPROVED_HOST_KEY_ALGORITHMS),
                "maximum_output_bytes_per_target": (
                    ROUTED_KEYSCAN_MAXIMUM_OUTPUT_BYTES
                ),
                "port": ROUTED_KEYSCAN_PORT,
                "seconds_per_target": self.timeout_seconds,
            },
        }


def collect_routed_host_key_candidates(
    service: AnsibleService,
    lock: HeldClusterLockProtocol,
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    trust: StoredTrustRecord,
    readiness: ReadinessReport,
    *,
    target_logical_ids: tuple[str, ...],
    captured_at: datetime,
    timeout_seconds: int = 10,
    verbosity: int = 0,
) -> RoutedHostKeyCandidateCollection:
    """Collect untrusted candidates in memory without changing canonical state."""

    lock.assert_held_for(service.command_builder.paths)
    _validate_collection_inputs(
        metadata,
        observed,
        inventory,
        trust,
        readiness,
        target_logical_ids=target_logical_ids,
        timeout_seconds=timeout_seconds,
    )
    TrustStore(service.command_builder.paths).validate_runtime(trust, inventory)
    selected = _select_targets(inventory, trust, target_logical_ids)
    captured = format_timestamp(captured_at)
    by_jump: dict[str, list[InventoryHost]] = {}
    for host in selected:
        if host.jump_host_id is None:
            raise StateConflictError("routed SSH keyscan target has no jump route")
        by_jump.setdefault(host.jump_host_id, []).append(host)

    execution_by_target: dict[str, RoutedKeyscanTargetEvidence] = {}
    for jump_host_id in sorted(by_jump):
        targets = tuple(sorted(by_jump[jump_host_id], key=lambda item: item.logical_id))
        payload = build_routed_keyscan_request(
            inventory,
            trust,
            readiness,
            jump_host_id=jump_host_id,
            targets=targets,
            collection_time=captured,
            timeout_seconds=timeout_seconds,
        )
        executed = service.execute(
            lock,
            metadata,
            inventory,
            "routed-keyscan",
            limit=(jump_host_id,),
            variables={"deploy_scylla_vms_routed_keyscan": payload},
            readiness=readiness,
            tags=("routed-keyscan",),
            check=True,
            verbosity=verbosity,
        )
        evidence = executed.routed_keyscan
        if evidence is None:
            raise AnsibleError("routed SSH keyscan evidence is unavailable")
        for target in evidence.targets:
            if target.logical_id in execution_by_target:
                raise AnsibleError("routed SSH keyscan evidence is duplicated")
            execution_by_target[target.logical_id] = target
        validate_current_readiness_report(readiness, observed, inventory, trust)
        TrustStore(service.command_builder.paths).validate_runtime(trust, inventory)

    trusted = {entry.logical_id: entry for entry in trust.record.entries}
    candidate_targets: list[RoutedCandidateTarget] = []
    for host in selected:
        target_evidence = execution_by_target.get(host.logical_id)
        if target_evidence is None:
            raise AnsibleError("routed SSH keyscan evidence is incomplete")
        candidates = tuple(
            HostKeyCandidate(
                host.logical_id,
                host.provider_id,
                HostEndpoint(host.private_address, ROUTED_KEYSCAN_PORT),
                host.jump_host_id,
                key.algorithm,
                key.public_key,
                key.fingerprint,
                captured,
                TrustCaptureSource.ROUTED_JUMP_KEYSCAN,
            )
            for key in target_evidence.keys
        )
        existing = trusted.get(host.logical_id)
        blockers: tuple[str, ...]
        if existing is not None:
            exact = any(
                candidate.algorithm == existing.algorithm
                and candidate.fingerprint == existing.fingerprint
                and candidate.public_key == existing.public_key
                for candidate in candidates
            )
            status = RoutedCandidateStatus.BLOCKED
            if target_evidence.status is not RoutedKeyscanExecutionStatus.COLLECTED:
                blockers = (
                    "existing-trust-requires-replacement-workflow",
                    cast(str, target_evidence.blocker),
                )
            else:
                changed_same_algorithm = any(
                    candidate.algorithm == existing.algorithm
                    and (
                        candidate.fingerprint != existing.fingerprint
                        or candidate.public_key != existing.public_key
                    )
                    for candidate in candidates
                )
                blockers = (
                    ("changed-key-replacement-required",)
                    if changed_same_algorithm or not exact
                    else ("existing-trust-requires-replacement-workflow",)
                )
        else:
            status = RoutedCandidateStatus(target_evidence.status.value)
            blockers = (
                (target_evidence.blocker,)
                if target_evidence.blocker is not None
                else ()
            )
        if host.jump_host_id is None:
            raise StateConflictError("routed SSH keyscan target route disappeared")
        candidate_targets.append(
            RoutedCandidateTarget(
                host.logical_id,
                host.provider_id,
                host.jump_host_id,
                target_evidence.route_digest,
                status,
                candidates,
                blockers,
            )
        )

    ordered = tuple(candidate_targets)
    collection_status = _collection_status(ordered)
    return RoutedHostKeyCandidateCollection(
        captured,
        collection_status,
        observed.record.generation,
        observed.record.manifest_digest,
        inventory.record.generation,
        inventory.digest,
        trust.record.generation,
        trust.digest,
        readiness.schema_version,
        _readiness_digest(readiness),
        timeout_seconds,
        tuple(sorted(by_jump)),
        ordered,
    )


def build_routed_keyscan_request(
    inventory: StoredInventoryRecord,
    trust: StoredTrustRecord,
    readiness: ReadinessReport,
    *,
    jump_host_id: str,
    targets: tuple[InventoryHost, ...],
    collection_time: str,
    timeout_seconds: int,
) -> dict[str, object]:
    """Build the sole address-bearing, ephemeral module request from inventory."""

    hosts = {host.logical_id: host for host in inventory.record.inventory.hosts}
    jump = hosts.get(jump_host_id)
    trusted = {entry.logical_id: entry for entry in trust.record.entries}
    if (
        jump is None
        or jump.role is not HostRole.JUMP_HOST
        or jump.jump_host_id is not None
        or jump_host_id not in trusted
    ):
        raise StateConflictError("routed SSH keyscan jump trust is unavailable")
    target_values = [
        {
            "address": host.private_address,
            "logical_id": host.logical_id,
            "port": ROUTED_KEYSCAN_PORT,
            "route_digest": routed_keyscan_route_digest(jump, host),
        }
        for host in targets
    ]
    payload: dict[str, object] = {
        "collection_time": collection_time,
        "jump_host_id": jump_host_id,
        "provenance": {
            "inventory_digest": inventory.digest,
            "inventory_generation": inventory.record.generation,
            "observation_digest": inventory.record.source_manifest_digest,
            "observation_generation": inventory.record.source_manifest_generation,
            "readiness_digest": _readiness_digest(readiness),
            "readiness_schema_version": readiness.schema_version,
            "trust_digest": trust.digest,
            "trust_generation": trust.record.generation,
        },
        "schema_version": ROUTED_KEYSCAN_REQUEST_SCHEMA_VERSION,
        "targets": target_values,
        "timeout_policy": {
            "approved_key_types": list(APPROVED_HOST_KEY_ALGORITHMS),
            "executable": ROUTED_KEYSCAN_EXECUTABLE,
            "maximum_output_bytes_per_target": ROUTED_KEYSCAN_MAXIMUM_OUTPUT_BYTES,
            "port": ROUTED_KEYSCAN_PORT,
            "seconds_per_target": timeout_seconds,
        },
    }
    payload["request_digest"] = digest_bytes(serialize_json(payload))
    return payload


def routed_keyscan_route_digest(jump: InventoryHost, target: InventoryHost) -> str:
    """Bind protected route identities without exposing them in projections."""

    return digest_bytes(
        serialize_json(
            {
                "jump": {
                    "address": jump.ansible_host,
                    "logical_id": jump.logical_id,
                    "provider_id": jump.provider_id,
                },
                "port": ROUTED_KEYSCAN_PORT,
                "schema_version": "deploy-scylla-vms.ssh-route-identity/v1",
                "target": {
                    "address": target.private_address,
                    "logical_id": target.logical_id,
                    "provider_id": target.provider_id,
                },
            }
        )
    )


def parse_routed_keyscan_execution(
    stdout: str,
    expected_payload: dict[str, object],
    expected_jump_id: str,
    exit_code: int,
) -> RoutedKeyscanExecutionEvidence:
    """Parse one address-free marker and exact successful jump-host recap."""

    data = stdout.encode("utf-8")
    if len(data) > 512 * 1024:
        raise AnsibleError("routed SSH keyscan output exceeds the evidence limit")
    for candidate in _IPV4_TEXT.findall(stdout):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.is_private:
            raise AnsibleError("routed SSH keyscan output exposed a private address")
    markers: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_ROUTED_KEYSCAN_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("routed SSH keyscan marker is malformed")
        try:
            raw = base64.b64decode(match.group("data"), validate=True)
            if len(raw) > 256 * 1024:
                raise AnsibleError("routed SSH keyscan marker is oversized")
            value = json.loads(
                raw.decode("utf-8", errors="strict"),
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (binascii.Error, RecursionError, UnicodeError, ValueError) as error:
            raise AnsibleError("routed SSH keyscan marker is malformed") from error
        if not isinstance(value, dict):
            raise AnsibleError("routed SSH keyscan result is malformed")
        markers.append(cast(dict[str, object], value))
    if exit_code != 0 or len(markers) != 1:
        raise AnsibleError("routed SSH keyscan execution did not complete safely")
    evidence = _parse_result(markers[0], expected_payload, expected_jump_id)
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("routed SSH keyscan output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines()[1:]:
        if not line.strip():
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("routed SSH keyscan recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    if rows != {expected_jump_id: (0, 0, 0)}:
        raise AnsibleError("routed SSH keyscan jump execution is incomplete")
    return evidence


def validate_routed_keyscan_request(value: object) -> bool:
    """Validate the exact ephemeral registry variable shape."""

    if not isinstance(value, dict) or set(value) != {
        "collection_time",
        "jump_host_id",
        "provenance",
        "request_digest",
        "schema_version",
        "targets",
        "timeout_policy",
    }:
        return False
    if (
        value.get("schema_version") != ROUTED_KEYSCAN_REQUEST_SCHEMA_VERSION
        or not isinstance(value.get("collection_time"), str)
        or not isinstance(value.get("jump_host_id"), str)
        or not _LOGICAL_ID.fullmatch(cast(str, value["jump_host_id"]))
        or not isinstance(value.get("request_digest"), str)
    ):
        return False
    try:
        parse_timestamp(cast(str, value["collection_time"]))
        validate_digest(cast(str, value["request_digest"]), "routed keyscan request")
    except (StatePersistenceError, TypeError):
        return False
    payload_without_digest = {
        key: item for key, item in value.items() if key != "request_digest"
    }
    if value["request_digest"] != digest_bytes(serialize_json(payload_without_digest)):
        return False
    provenance = value.get("provenance")
    if not isinstance(provenance, dict) or set(provenance) != {
        "inventory_digest",
        "inventory_generation",
        "observation_digest",
        "observation_generation",
        "readiness_digest",
        "readiness_schema_version",
        "trust_digest",
        "trust_generation",
    }:
        return False
    if not all(
        isinstance(provenance[name], int)
        and not isinstance(provenance[name], bool)
        and cast(int, provenance[name]) >= 1
        for name in (
            "inventory_generation",
            "observation_generation",
            "trust_generation",
        )
    ):
        return False
    try:
        for name in (
            "inventory_digest",
            "observation_digest",
            "readiness_digest",
            "trust_digest",
        ):
            validate_digest(cast(str, provenance[name]), f"routed keyscan {name}")
    except (StatePersistenceError, TypeError):
        return False
    if provenance["readiness_schema_version"] != (
        "deploy-scylla-vms.ansible-readiness/v1"
    ):
        return False
    policy = value.get("timeout_policy")
    if not isinstance(policy, dict) or policy != {
        "approved_key_types": list(APPROVED_HOST_KEY_ALGORITHMS),
        "executable": ROUTED_KEYSCAN_EXECUTABLE,
        "maximum_output_bytes_per_target": ROUTED_KEYSCAN_MAXIMUM_OUTPUT_BYTES,
        "port": ROUTED_KEYSCAN_PORT,
        "seconds_per_target": policy.get("seconds_per_target"),
    }:
        return False
    seconds = policy.get("seconds_per_target")
    if (
        isinstance(seconds, bool)
        or not isinstance(seconds, int)
        or not 1 <= seconds <= 60
    ):
        return False
    targets = value.get("targets")
    if (
        not isinstance(targets, list)
        or not 1 <= len(targets) <= ROUTED_KEYSCAN_MAXIMUM_TARGETS
    ):
        return False
    normalized: list[tuple[str, str, int, str]] = []
    for item in targets:
        if not isinstance(item, dict) or set(item) != {
            "address",
            "logical_id",
            "port",
            "route_digest",
        }:
            return False
        logical_id = item.get("logical_id")
        address = item.get("address")
        if (
            not isinstance(logical_id, str)
            or not _LOGICAL_ID.fullmatch(logical_id)
            or not isinstance(address, str)
            or item.get("port") != ROUTED_KEYSCAN_PORT
            or not isinstance(item.get("route_digest"), str)
        ):
            return False
        try:
            parsed = ipaddress.ip_address(address)
            validate_digest(cast(str, item["route_digest"]), "routed keyscan route")
        except (TypeError, ValueError):
            return False
        if not isinstance(parsed, ipaddress.IPv4Address) or not _is_rfc1918(address):
            return False
        normalized.append(
            (
                logical_id,
                address,
                ROUTED_KEYSCAN_PORT,
                cast(str, item["route_digest"]),
            )
        )
    return normalized == sorted(set(normalized))


def _validate_collection_inputs(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    trust: StoredTrustRecord,
    readiness: ReadinessReport,
    *,
    target_logical_ids: tuple[str, ...],
    timeout_seconds: int,
) -> None:
    if (
        metadata.cluster_uuid != inventory.record.cluster_uuid
        or metadata.cluster_uuid != observed.record.cluster_uuid
        or metadata.cluster_name != observed.record.cluster_name
        or metadata.cluster_name != inventory.record.cluster_name
        or metadata.provider != observed.record.provider
        or metadata.provider != inventory.record.provider
    ):
        raise StateConflictError("routed SSH keyscan cluster identity conflicts")
    if not trust.record.is_fresh_for(observed.record, inventory.record):
        raise StateConflictError("routed SSH keyscan trust is stale")
    validate_current_readiness_report(readiness, observed, inventory, trust)
    if (
        readiness.source_status is not EvidenceStatus.FRESH
        or readiness.machine_status is not EvidenceStatus.FRESH
        or readiness.route_status is not RouteReadiness.VALID
        or readiness.trust_status
        not in {TrustReadiness.INCOMPLETE, TrustReadiness.COMPLETE}
    ):
        raise StateConflictError("routed SSH keyscan readiness is unsatisfied")
    if (
        not target_logical_ids
        or len(target_logical_ids) > ROUTED_KEYSCAN_MAXIMUM_TARGETS
        or len(target_logical_ids) != len(set(target_logical_ids))
        or not all(
            isinstance(item, str) and _LOGICAL_ID.fullmatch(item)
            for item in target_logical_ids
        )
    ):
        raise StateConflictError(
            "routed SSH keyscan requires bounded unique stable-ID targets"
        )
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 1 <= timeout_seconds <= 60
    ):
        raise StateConflictError("routed SSH keyscan timeout policy is invalid")


def _select_targets(
    inventory: StoredInventoryRecord,
    trust: StoredTrustRecord,
    selected_ids: tuple[str, ...],
) -> tuple[InventoryHost, ...]:
    hosts = {host.logical_id: host for host in inventory.record.inventory.hosts}
    trusted = {entry.logical_id: entry for entry in trust.record.entries}
    selected: list[InventoryHost] = []
    for logical_id in sorted(selected_ids):
        host = hosts.get(logical_id)
        jump = (
            hosts.get(host.jump_host_id)
            if host is not None and host.jump_host_id is not None
            else None
        )
        jump_trust = trusted.get(jump.logical_id) if jump is not None else None
        if (
            host is None
            or host.role is HostRole.JUMP_HOST
            or host.route_mode != "proxy-jump"
            or host.jump_host_id is None
            or host.ansible_host != host.private_address
            or not _is_rfc1918(host.private_address)
            or jump is None
            or jump.role is not HostRole.JUMP_HOST
            or jump.jump_host_id is not None
            or jump_trust is None
            or jump_trust.provider_id != jump.provider_id
            or jump_trust.endpoint.address != jump.ansible_host
            or jump_trust.endpoint.port != ROUTED_KEYSCAN_PORT
            or jump_trust.jump_host_id is not None
        ):
            raise StateConflictError(
                "routed SSH keyscan target or trusted jump route is invalid"
            )
        selected.append(host)
    return tuple(selected)


def _parse_result(
    value: dict[str, object],
    expected_payload: dict[str, object],
    expected_jump_id: str,
) -> RoutedKeyscanExecutionEvidence:
    if set(value) != {
        "jump_host_id",
        "request_digest",
        "schema_version",
        "status",
        "targets",
    }:
        raise AnsibleError("routed SSH keyscan result fields conflict")
    if (
        value["schema_version"] != ROUTED_KEYSCAN_RESULT_SCHEMA_VERSION
        or value["jump_host_id"] != expected_jump_id
        or value["request_digest"] != expected_payload.get("request_digest")
        or value["status"] not in {"failure", "partial-failure", "success"}
    ):
        raise AnsibleError("routed SSH keyscan result provenance conflicts")
    expected_targets_value = expected_payload.get("targets")
    if not isinstance(expected_targets_value, list):
        raise AnsibleError("routed SSH keyscan expected targets are invalid")
    expected_targets = {
        cast(str, item["logical_id"]): cast(dict[str, object], item)
        for item in expected_targets_value
        if isinstance(item, dict) and isinstance(item.get("logical_id"), str)
    }
    target_values = value["targets"]
    if not isinstance(target_values, list):
        raise AnsibleError("routed SSH keyscan targets are malformed")
    targets: list[RoutedKeyscanTargetEvidence] = []
    for item_value in target_values:
        if not isinstance(item_value, dict) or set(item_value) != {
            "blocker",
            "keys",
            "logical_id",
            "route_digest",
            "status",
        }:
            raise AnsibleError("routed SSH keyscan target result is malformed")
        item = cast(dict[str, object], item_value)
        logical_id = item["logical_id"]
        if not isinstance(logical_id, str):
            raise AnsibleError("routed SSH keyscan target provenance conflicts")
        expected = expected_targets.get(logical_id)
        if (
            expected is None
            or item["route_digest"] != expected["route_digest"]
            or item["status"]
            not in {status.value for status in RoutedKeyscanExecutionStatus}
            or (
                item["blocker"] is not None
                and item["blocker"] not in _EXECUTION_BLOCKERS
            )
        ):
            raise AnsibleError("routed SSH keyscan target provenance conflicts")
        status = RoutedKeyscanExecutionStatus(item["status"])
        key_values = item["keys"]
        if not isinstance(key_values, list):
            raise AnsibleError("routed SSH keyscan keys are malformed")
        keys: list[RoutedKeyscanKey] = []
        for key_value in key_values:
            if not isinstance(key_value, dict) or set(key_value) != {
                "algorithm",
                "fingerprint",
                "public_key",
            }:
                raise AnsibleError("routed SSH keyscan key is malformed")
            key = cast(dict[str, object], key_value)
            if not all(
                isinstance(key[name], str)
                for name in ("algorithm", "fingerprint", "public_key")
            ):
                raise AnsibleError("routed SSH keyscan key is malformed")
            keys.append(
                RoutedKeyscanKey(
                    cast(str, key["algorithm"]),
                    cast(str, key["public_key"]),
                    cast(str, key["fingerprint"]),
                )
            )
        identities = [(key.algorithm, key.fingerprint) for key in keys]
        algorithms = [key.algorithm for key in keys]
        if identities != sorted(identities) or len(algorithms) != len(set(algorithms)):
            raise AnsibleError("routed SSH keyscan keys are duplicated or unordered")
        if (status is RoutedKeyscanExecutionStatus.COLLECTED) != (
            bool(keys) and item["blocker"] is None
        ):
            raise AnsibleError("routed SSH keyscan target status conflicts")
        if status is not RoutedKeyscanExecutionStatus.COLLECTED and (
            keys or item["blocker"] is None
        ):
            raise AnsibleError("routed SSH keyscan failure evidence conflicts")
        targets.append(
            RoutedKeyscanTargetEvidence(
                logical_id,
                cast(str, item["route_digest"]),
                status,
                tuple(keys),
                item["blocker"],
            )
        )
    if [target.logical_id for target in targets] != sorted(expected_targets) or len(
        targets
    ) != len(expected_targets):
        raise AnsibleError("routed SSH keyscan target membership conflicts")
    collected = sum(
        target.status is RoutedKeyscanExecutionStatus.COLLECTED for target in targets
    )
    expected_status = (
        "success"
        if collected == len(targets)
        else "partial-failure"
        if collected
        else "failure"
    )
    if value["status"] != expected_status:
        raise AnsibleError("routed SSH keyscan aggregate status conflicts")
    return RoutedKeyscanExecutionEvidence(
        expected_jump_id,
        cast(str, value["request_digest"]),
        expected_status,
        tuple(targets),
    )


def _collection_status(targets: tuple[RoutedCandidateTarget, ...]) -> str:
    collected = sum(
        target.status is RoutedCandidateStatus.COLLECTED for target in targets
    )
    blocked = sum(target.status is RoutedCandidateStatus.BLOCKED for target in targets)
    if collected == len(targets):
        return "collected"
    if blocked == len(targets):
        return "blocked"
    if collected or blocked:
        return "partial"
    return "failed"


def _readiness_digest(readiness: ReadinessReport) -> str:
    return digest_bytes(serialize_json(readiness.to_public_object()))


def _is_rfc1918(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return isinstance(address, ipaddress.IPv4Address) and any(
        address in network
        for network in (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
    )


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"unsupported JSON constant: {value}")
