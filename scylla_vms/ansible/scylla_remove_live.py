"""Strict live-node decommission authorization and result contracts."""

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

from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.scylla_health import (
    HealthReadiness,
    ScyllaHealthEvidence,
)
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import InventoryHost, StoredInventoryRecord
from scylla_vms.journal import CheckpointEvidence, EvidenceResult, OperationPhase
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata, parse_timestamp

SCYLLA_REMOVE_LIVE_SCHEMA_VERSION = "deploy-scylla-vms.ansible-scylla-remove-live/v1"
SCYLLA_REMOVE_LIVE_SAFETY_SCHEMA_VERSION = (
    "deploy-scylla-vms.scylla-remove-live-safety/v1"
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MARKER = re.compile(r"DSV_SCYLLA_REMOVE_LIVE_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_BLOCKERS = frozenset(
    {
        "command-failed",
        "execution-interrupted",
        "identity-changed",
        "postcondition-disagreement",
        "postcondition-timeout",
        "recovery-required",
    }
)


class SafetyCheckStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    UNKNOWN = "unknown"
    NOT_PERFORMED = "not-performed"


class ScyllaRemoveLiveStatus(StrEnum):
    REMOVED = "removed"
    FAILED = "failed"
    NOT_PREDICTED = "not-predicted"


class DecommissionCommandBoundary(StrEnum):
    NOT_STARTED = "not-started"
    STARTED = "started"
    COMPLETED = "completed"


class MembershipMutationBoundary(StrEnum):
    UNCHANGED = "unchanged"
    MAY_HAVE_CHANGED = "may-have-changed"
    TARGET_ABSENT = "target-absent"


@dataclass(frozen=True, slots=True)
class ScyllaRemovalSafetyEvidence:
    """Independent authenticated-CQL/Manager/capacity safety evidence."""

    captured_at: str
    health_digest: str
    surviving_stable_ids: tuple[str, ...]
    intended_post_topology_digest: str
    replication: SafetyCheckStatus
    quorum: SafetyCheckStatus
    capacity: SafetyCheckStatus
    backup_policy: SafetyCheckStatus
    schema_version: str = SCYLLA_REMOVE_LIVE_SAFETY_SCHEMA_VERSION

    def validate(self) -> None:
        if self.schema_version != SCYLLA_REMOVE_LIVE_SAFETY_SCHEMA_VERSION:
            raise StateConflictError("Scylla removal safety schema is unsupported")
        parse_timestamp(self.captured_at)
        _require_digest(self.health_digest)
        _require_digest(self.intended_post_topology_digest)
        if (
            self.surviving_stable_ids != tuple(sorted(set(self.surviving_stable_ids)))
            or not self.surviving_stable_ids
            or any(
                _LOGICAL_ID.fullmatch(item) is None
                for item in self.surviving_stable_ids
            )
            or any(
                item is not SafetyCheckStatus.PASSED
                for item in (
                    self.replication,
                    self.quorum,
                    self.capacity,
                    self.backup_policy,
                )
            )
        ):
            raise StateConflictError(
                "live removal requires passed replication, quorum, capacity, and "
                "backup-policy evidence"
            )


@dataclass(frozen=True, slots=True)
class ScyllaRemoveLiveAuthorization:
    """Narrow destructive approval bound to one exact ring transition."""

    operation_id: str
    cluster_uuid: str
    target_logical_id: str
    target_host_id: str
    target_provider_id: str
    target_datacenter: str
    target_rack: str
    desired_removal_intent_digest: str
    authorization_digest: str
    health_generation: int
    health_digest: str
    intended_post_topology_digest: str
    confirmed_target: str
    allow_destructive: bool
    reviewed: bool
    prior_command_started: bool = False


@dataclass(frozen=True, slots=True)
class ScyllaRemoveLiveEvidence:
    status: ScyllaRemoveLiveStatus
    target_logical_id: str
    target_host_id_digest: str
    pre_health_digest: str
    post_health_digest: str | None
    decommission_command: tuple[str, ...]
    command_boundary: DecommissionCommandBoundary
    membership_boundary: MembershipMutationBoundary
    postconditions: tuple[tuple[str, SafetyCheckStatus], ...]
    recovery_required: bool
    blockers: tuple[str, ...]
    schema_version: str = SCYLLA_REMOVE_LIVE_SCHEMA_VERSION


def build_scylla_remove_live_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    health: ScyllaHealthEvidence,
    safety: ScyllaRemovalSafetyEvidence,
    authorization: ScyllaRemoveLiveAuthorization,
    *,
    config_digest: str,
    storage_digest: str,
    decommission_timeout_seconds: int,
) -> dict[str, object]:
    """Build one exact decommission request after every safety gate passes."""

    if not 60 <= decommission_timeout_seconds <= 86_400:
        raise StateConflictError("Scylla decommission timeout is invalid")
    safety.validate()
    health_digest = scylla_health_evidence_digest(health)
    scylla_hosts = tuple(
        host for host in inventory.record.inventory.hosts if host.role.value == "scylla"
    )
    expected_ids = tuple(host.logical_id for host in scylla_hosts)
    target = next(
        (
            host
            for host in scylla_hosts
            if host.logical_id == authorization.target_logical_id
        ),
        None,
    )
    target_health = next(
        (
            node
            for node in health.nodes
            if node.logical_id == authorization.target_logical_id
        ),
        None,
    )
    survivors = tuple(
        logical_id
        for logical_id in expected_ids
        if logical_id != authorization.target_logical_id
    )
    if target is None or target_health is None or not survivors:
        raise StateConflictError("live removal requires one target and surviving nodes")
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
        raise StateConflictError("Scylla live-removal provenance conflicts")
    read_gate = next(
        (
            gate
            for gate in health.operation_gates
            if gate.operation_class == "read-only"
        ),
        None,
    )
    if (
        health.query_policy != "all-nodes-cross-view"
        or health.queried_nodes != expected_ids
        or health.status is HealthReadiness.BLOCKED
        or read_gate is None
        or read_gate.readiness is not HealthReadiness.READY
        or health.blockers
        or health.schema_agreement is not True
        or health.streaming_state != "complete"
        or safety.captured_at != health.captured_at_end
        or any(node.state != "UN" for node in health.nodes)
        or target_health.host_id is None
    ):
        raise StateConflictError(
            "live removal requires fresh healthy full-cluster Up Normal evidence"
        )
    expected_post_topology = [
        {
            "datacenter": node.datacenter,
            "host_id": node.host_id,
            "rack": node.rack,
            "state": "UN",
        }
        for node in health.nodes
        if node.logical_id in survivors
    ]
    if (
        any(item["host_id"] is None for item in expected_post_topology)
        or _object_digest(expected_post_topology)
        != safety.intended_post_topology_digest
    ):
        raise StateConflictError(
            "independent safety evidence conflicts with intended post-removal topology"
        )
    _validate_authorization(
        metadata,
        target,
        target_health.host_id,
        health_digest,
        safety,
        authorization,
        survivors,
    )
    coordinator = survivors[0]
    return {
        "authorization": {
            "authorization_digest": authorization.authorization_digest,
            "desired_removal_intent_digest": (
                authorization.desired_removal_intent_digest
            ),
            "health_generation": authorization.health_generation,
            "reviewed": authorization.reviewed,
        },
        "cluster_uuid": str(metadata.cluster_uuid),
        "coordinator_stable_id": coordinator,
        "decommission_timeout_seconds": decommission_timeout_seconds,
        "expected_post_topology": expected_post_topology,
        "expected_survivor_host_ids": sorted(
            node.host_id
            for node in health.nodes
            if node.logical_id in survivors and node.host_id is not None
        ),
        "intended_post_topology_digest": safety.intended_post_topology_digest,
        "operation_id": authorization.operation_id,
        "pre_health_digest": health_digest,
        "prerequisite_digests": {
            "config_digest": _require_digest(config_digest),
            "inventory_digest": inventory.digest,
            "observation_digest": observed.digest,
            "safety_evidence_digest": _object_digest(_safety_object(safety)),
            "storage_digest": _require_digest(storage_digest),
            "trust_digest": _require_digest(readiness.trust_digest),
        },
        "schema_version": SCYLLA_REMOVE_LIVE_SCHEMA_VERSION,
        "surviving_stable_ids": list(survivors),
        "target": {
            "datacenter": target.scylla_datacenter,
            "host_id": target_health.host_id,
            "logical_id": target.logical_id,
            "provider_id_digest": _digest_text(target.provider_id),
            "rack": target.scylla_rack,
        },
    }


def _validate_authorization(
    metadata: ClusterMetadata,
    target: InventoryHost,
    target_host_id: str,
    health_digest: str,
    safety: ScyllaRemovalSafetyEvidence,
    authorization: ScyllaRemoveLiveAuthorization,
    survivors: tuple[str, ...],
) -> None:
    logical_id = target.logical_id
    provider_id = target.provider_id
    datacenter = target.scylla_datacenter
    rack = target.scylla_rack
    try:
        operation_id = str(uuid.UUID(authorization.operation_id))
        cluster_uuid = str(uuid.UUID(authorization.cluster_uuid))
        host_id = str(uuid.UUID(authorization.target_host_id))
    except ValueError as error:
        raise StateConflictError(
            "Scylla removal authorization identity is invalid"
        ) from error
    if (
        operation_id != authorization.operation_id
        or cluster_uuid != authorization.cluster_uuid
        or host_id != authorization.target_host_id
        or authorization.cluster_uuid != str(metadata.cluster_uuid)
        or authorization.target_logical_id != logical_id
        or authorization.target_host_id != target_host_id
        or authorization.target_provider_id != provider_id
        or authorization.target_datacenter != datacenter
        or authorization.target_rack != rack
        or authorization.confirmed_target != logical_id
        or not authorization.allow_destructive
        or not authorization.reviewed
        or authorization.prior_command_started
        or authorization.health_generation < 1
        or authorization.health_digest != health_digest
        or safety.health_digest != health_digest
        or safety.surviving_stable_ids != survivors
        or authorization.intended_post_topology_digest
        != safety.intended_post_topology_digest
    ):
        raise StateConflictError(
            "Scylla live-removal authorization does not match the exact target "
            "and intended post-removal topology"
        )
    for digest in (
        authorization.desired_removal_intent_digest,
        authorization.authorization_digest,
        authorization.health_digest,
        authorization.intended_post_topology_digest,
    ):
        _require_digest(digest)


def parse_scylla_remove_live_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> ScyllaRemoveLiveEvidence:
    """Parse only the strict address-free decommission projection."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError("Ansible Scylla live-removal output exceeds the limit")
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_SCYLLA_REMOVE_LIVE_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible Scylla live-removal marker is malformed")
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible Scylla live-removal marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible Scylla live-removal evidence is malformed")
        values.append(value)
    target = cast(dict[str, object], expected_payload.get("target"))
    logical_id = _text(target.get("logical_id"))
    recap = _parse_recap(stdout)
    if set(recap) != {logical_id} or len(values) != 1:
        raise AnsibleError("Ansible Scylla live-removal evidence is incomplete")
    evidence = _parse_result(values[0], expected_payload)
    changed, unreachable, failed = recap[logical_id]
    result_failed = evidence.status is not ScyllaRemoveLiveStatus.REMOVED
    if bool(unreachable or failed) != result_failed or (exit_code == 0) != (
        not result_failed
    ):
        raise AnsibleError("Ansible Scylla live-removal exit status conflicts")
    if bool(changed) != (
        evidence.command_boundary is not DecommissionCommandBoundary.NOT_STARTED
    ):
        raise AnsibleError("Ansible Scylla decommission mutation status conflicts")
    return evidence


def scylla_remove_live_checkpoint_evidence(
    evidence: ScyllaRemoveLiveEvidence,
) -> CheckpointEvidence:
    """Project command-start/completion truth into the append-only journal."""

    if evidence.status is ScyllaRemoveLiveStatus.NOT_PREDICTED:
        raise StateConflictError("check-mode refusal is not removal execution evidence")
    completed = evidence.status is ScyllaRemoveLiveStatus.REMOVED
    summary = (
        "scylla-live-removal-complete"
        if completed
        else "scylla-decommission-started-recovery-required"
        if evidence.command_boundary is not DecommissionCommandBoundary.NOT_STARTED
        else "scylla-live-removal-refused"
    )
    return CheckpointEvidence(
        OperationPhase.EXECUTE,
        EvidenceResult.COMPLETED if completed else EvidenceResult.FAILED,
        _object_digest(_result_object(evidence)),
        summary,
    )


def scylla_remove_live_interrupted_evidence(
    expected_payload: dict[str, object],
) -> ScyllaRemoveLiveEvidence:
    """Conservatively journal an invocation interrupted without a result marker."""

    target = expected_payload.get("target")
    if (
        not isinstance(target, dict)
        or expected_payload.get("schema_version") != SCYLLA_REMOVE_LIVE_SCHEMA_VERSION
    ):
        raise StateConflictError("Scylla removal interruption payload is invalid")
    logical_id = _text(target.get("logical_id"))
    host_id = _text(target.get("host_id"))
    pre_health_digest = _require_digest(expected_payload.get("pre_health_digest"))
    return ScyllaRemoveLiveEvidence(
        ScyllaRemoveLiveStatus.FAILED,
        logical_id,
        _digest_text(host_id),
        pre_health_digest,
        None,
        ("/usr/bin/nodetool", "decommission"),
        DecommissionCommandBoundary.STARTED,
        MembershipMutationBoundary.MAY_HAVE_CHANGED,
        tuple(
            (name, SafetyCheckStatus.UNKNOWN)
            for name in (
                "expected-topology",
                "no-streaming",
                "schema-agreement",
                "survivors-up-normal",
                "target-absent",
            )
        ),
        True,
        ("execution-interrupted",),
    )


def scylla_health_evidence_digest(health: ScyllaHealthEvidence) -> str:
    return _object_digest(
        {
            "blockers": list(health.blockers),
            "captured_at_end": health.captured_at_end,
            "captured_at_start": health.captured_at_start,
            "checks": [(item.name, item.status.value) for item in health.checks],
            "nodes": [
                {
                    "blockers": list(node.blockers),
                    "datacenter": node.datacenter,
                    "host_id": node.host_id,
                    "logical_id": node.logical_id,
                    "provider_id_digest": node.provider_id_digest,
                    "rack": node.rack,
                    "state": node.state,
                }
                for node in health.nodes
            ],
            "provenance": dict(health.provenance),
            "queried_nodes": list(health.queried_nodes),
            "schema_agreement": health.schema_agreement,
            "schema_digest": health.schema_digest,
            "streaming_state": health.streaming_state,
            "topology_digest": health.topology_digest,
        }
    )


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> ScyllaRemoveLiveEvidence:
    fields = {
        "blockers",
        "command_boundary",
        "decommission_command",
        "membership_boundary",
        "post_health_digest",
        "postconditions",
        "pre_health_digest",
        "recovery_required",
        "schema_version",
        "status",
        "target_host_id_digest",
        "target_logical_id",
    }
    if (
        set(value) != fields
        or value["schema_version"] != SCYLLA_REMOVE_LIVE_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible Scylla live-removal result schema is invalid")
    try:
        status = ScyllaRemoveLiveStatus(_text(value["status"]))
        command_boundary = DecommissionCommandBoundary(_text(value["command_boundary"]))
        membership_boundary = MembershipMutationBoundary(
            _text(value["membership_boundary"])
        )
    except ValueError as error:
        raise AnsibleError("Ansible Scylla live-removal enum is invalid") from error
    target = cast(dict[str, object], expected["target"])
    logical_id = _text(value["target_logical_id"])
    target_digest = _require_digest(value["target_host_id_digest"])
    pre_digest = _require_digest(value["pre_health_digest"])
    post_digest = _optional_digest(value["post_health_digest"])
    command = _sorted_command(value["decommission_command"])
    postconditions = _postconditions(value["postconditions"])
    blockers = _sorted_strings(value["blockers"])
    recovery = value["recovery_required"]
    if (
        logical_id != target["logical_id"]
        or target_digest != _digest_text(_text(target["host_id"]))
        or pre_digest != expected["pre_health_digest"]
        or command != ("/usr/bin/nodetool", "decommission")
        or not isinstance(recovery, bool)
        or not set(blockers) <= _BLOCKERS
    ):
        raise AnsibleError("Ansible Scylla live-removal result conflicts")
    passed = all(item is SafetyCheckStatus.PASSED for _, item in postconditions)
    if status is ScyllaRemoveLiveStatus.REMOVED and (
        command_boundary is not DecommissionCommandBoundary.COMPLETED
        or membership_boundary is not MembershipMutationBoundary.TARGET_ABSENT
        or post_digest is None
        or not passed
        or recovery
        or blockers
    ):
        raise AnsibleError("Ansible Scylla live-removal success evidence conflicts")
    if status is ScyllaRemoveLiveStatus.NOT_PREDICTED and (
        command_boundary is not DecommissionCommandBoundary.NOT_STARTED
        or membership_boundary is not MembershipMutationBoundary.UNCHANGED
        or post_digest is not None
        or recovery
        or blockers
    ):
        raise AnsibleError("Ansible Scylla live-removal check refusal conflicts")
    if status is ScyllaRemoveLiveStatus.FAILED and (not recovery or not blockers):
        raise AnsibleError("Ansible Scylla live-removal failure evidence conflicts")
    return ScyllaRemoveLiveEvidence(
        status,
        logical_id,
        target_digest,
        pre_digest,
        post_digest,
        command,
        command_boundary,
        membership_boundary,
        postconditions,
        recovery,
        blockers,
    )


def _postconditions(value: object) -> tuple[tuple[str, SafetyCheckStatus], ...]:
    names = (
        "expected-topology",
        "no-streaming",
        "schema-agreement",
        "survivors-up-normal",
        "target-absent",
    )
    if not isinstance(value, dict) or tuple(sorted(value)) != names:
        raise AnsibleError("Scylla live-removal postconditions are invalid")
    try:
        return tuple((name, SafetyCheckStatus(_text(value[name]))) for name in names)
    except ValueError as error:
        raise AnsibleError(
            "Scylla live-removal postcondition status is invalid"
        ) from error


def _parse_recap(stdout: str) -> dict[str, tuple[int, int, int]]:
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible Scylla live-removal output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible Scylla live-removal recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    return rows


def _safety_object(value: ScyllaRemovalSafetyEvidence) -> object:
    return {
        "backup_policy": value.backup_policy.value,
        "capacity": value.capacity.value,
        "captured_at": value.captured_at,
        "health_digest": value.health_digest,
        "intended_post_topology_digest": value.intended_post_topology_digest,
        "quorum": value.quorum.value,
        "replication": value.replication.value,
        "schema_version": value.schema_version,
        "surviving_stable_ids": list(value.surviving_stable_ids),
    }


def _result_object(value: ScyllaRemoveLiveEvidence) -> object:
    return {
        "blockers": list(value.blockers),
        "command_boundary": value.command_boundary.value,
        "membership_boundary": value.membership_boundary.value,
        "post_health_digest": value.post_health_digest,
        "pre_health_digest": value.pre_health_digest,
        "recovery_required": value.recovery_required,
        "status": value.status.value,
        "target_host_id_digest": value.target_host_id_digest,
        "target_logical_id": value.target_logical_id,
    }


def _object_digest(value: object) -> str:
    data = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _digest_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AnsibleError(
                "Ansible Scylla live-removal evidence has duplicate fields"
            )
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise AnsibleError(f"invalid Scylla live-removal constant: {value}")


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible Scylla live-removal value is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible Scylla live-removal digest is invalid")
    return text


def _optional_digest(value: object) -> str | None:
    return None if value is None else _require_digest(value)


def _sorted_strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible Scylla live-removal blockers are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError("Ansible Scylla live-removal blockers are not sorted")
    return items


def _sorted_command(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible Scylla decommission command is invalid")
    return tuple(_text(item) for item in value)
