"""Strict dead-node removal authorization and result contracts."""

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
from scylla_vms.ansible.scylla_health import HealthReadiness, ScyllaHealthEvidence
from scylla_vms.ansible.scylla_remove_live import (
    SafetyCheckStatus,
    ScyllaRemovalSafetyEvidence,
    scylla_health_evidence_digest,
)
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.journal import CheckpointEvidence, EvidenceResult, OperationPhase
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata, parse_timestamp

SCYLLA_REMOVE_DEAD_SCHEMA_VERSION = "deploy-scylla-vms.ansible-scylla-remove-dead/v1"
SCYLLA_REMOVE_DEAD_TARGET_SCHEMA_VERSION = (
    "deploy-scylla-vms.scylla-remove-dead-target/v1"
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MARKER = re.compile(r"DSV_SCYLLA_REMOVE_DEAD_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_BLOCKERS = frozenset(
    {
        "already-running",
        "command-failed",
        "execution-interrupted",
        "postcondition-disagreement",
        "postcondition-timeout",
        "recovery-required",
        "revalidation-failed",
    }
)


class ReachabilityStatus(StrEnum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    AMBIGUOUS = "ambiguous"
    NOT_PERFORMED = "not-performed"


class ScyllaRemoveDeadStatus(StrEnum):
    REMOVED = "removed"
    FAILED = "failed"
    NOT_PREDICTED = "not-predicted"


class RemoveNodeCommandBoundary(StrEnum):
    NOT_STARTED = "not-started"
    STARTED = "started"
    COMPLETED = "completed"


class RingMutationBoundary(StrEnum):
    UNCHANGED = "unchanged"
    MAY_HAVE_CHANGED = "may-have-changed"
    TARGET_ABSENT = "target-absent"


@dataclass(frozen=True, slots=True)
class SurvivorRingView:
    stable_id: str
    coordinator_host_id: str
    target_host_id: str
    target_state: str
    ring_digest: str
    schema_agreed: bool
    streaming_complete: bool

    def validate(self) -> None:
        if (
            _LOGICAL_ID.fullmatch(self.stable_id) is None
            or str(uuid.UUID(self.coordinator_host_id)) != self.coordinator_host_id
            or str(uuid.UUID(self.target_host_id)) != self.target_host_id
            or self.target_state != "DN"
            or not self.schema_agreed
            or not self.streaming_complete
        ):
            raise StateConflictError("dead-node survivor ring view is unsafe")
        _require_digest(self.ring_digest)


@dataclass(frozen=True, slots=True)
class DeadTargetEvidence:
    """Independent reachability, provider identity, and survivor ring evidence."""

    captured_at: str
    target_stable_id: str
    target_host_id: str
    target_provider_id: str
    provider_identity_unchanged: bool
    ssh_reachability: ReachabilityStatus
    service_reachability: ReachabilityStatus
    provider_lifecycle_reachability: ReachabilityStatus
    survivor_views: tuple[SurvivorRingView, ...]
    active_membership_operation: str | None = None
    schema_version: str = SCYLLA_REMOVE_DEAD_TARGET_SCHEMA_VERSION

    def validate(self, required_survivors: tuple[str, ...]) -> None:
        if self.schema_version != SCYLLA_REMOVE_DEAD_TARGET_SCHEMA_VERSION:
            raise StateConflictError("dead-target evidence schema is unsupported")
        parse_timestamp(self.captured_at)
        if (
            _LOGICAL_ID.fullmatch(self.target_stable_id) is None
            or str(uuid.UUID(self.target_host_id)) != self.target_host_id
            or not self.target_provider_id
            or not self.provider_identity_unchanged
            or self.active_membership_operation is not None
            or any(
                value is not ReachabilityStatus.UNREACHABLE
                for value in (
                    self.ssh_reachability,
                    self.service_reachability,
                    self.provider_lifecycle_reachability,
                )
            )
            or tuple(view.stable_id for view in self.survivor_views)
            != required_survivors
        ):
            raise StateConflictError(
                "dead target must be independently unreachable with unchanged identity"
            )
        if not self.survivor_views:
            raise StateConflictError("dead removal requires survivor ring views")
        for view in self.survivor_views:
            view.validate()
        if (
            any(
                view.target_host_id != self.target_host_id
                for view in self.survivor_views
            )
            or len({view.ring_digest for view in self.survivor_views}) != 1
        ):
            raise StateConflictError(
                "survivor ring views disagree about the dead target"
            )


@dataclass(frozen=True, slots=True)
class ScyllaRemoveDeadAuthorization:
    operation_id: str
    cluster_uuid: str
    target_stable_id: str
    target_host_id: str
    target_provider_id: str
    coordinator_stable_id: str
    health_digest: str
    observation_digest: str
    inventory_digest: str
    trust_digest: str
    intended_post_topology_digest: str
    authorization_digest: str
    confirmed_target: str
    allow_destructive: bool
    reviewed: bool
    prior_command_started: bool = False


@dataclass(frozen=True, slots=True)
class ScyllaRemoveDeadEvidence:
    status: ScyllaRemoveDeadStatus
    target_stable_id: str
    coordinator_stable_id: str
    target_host_id_digest: str
    coordinator_host_id_digest: str
    pre_evidence_digest: str
    post_evidence_digest: str | None
    removal_command: tuple[str, ...]
    status_command: tuple[str, ...]
    command_boundary: RemoveNodeCommandBoundary
    mutation_boundary: RingMutationBoundary
    removal_status: str
    postconditions: tuple[tuple[str, SafetyCheckStatus], ...]
    recovery_required: bool
    blockers: tuple[str, ...]
    schema_version: str = SCYLLA_REMOVE_DEAD_SCHEMA_VERSION


def build_scylla_remove_dead_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    survivor_health: ScyllaHealthEvidence,
    dead_target: DeadTargetEvidence,
    safety: ScyllaRemovalSafetyEvidence,
    authorization: ScyllaRemoveDeadAuthorization,
    *,
    timeout_seconds: int,
) -> dict[str, object]:
    """Build one exact removenode request after all local gates pass."""

    if not 60 <= timeout_seconds <= 86_400:
        raise StateConflictError("Scylla dead-removal timeout is invalid")
    hosts = {
        host.logical_id: host
        for host in inventory.record.inventory.hosts
        if host.role.value == "scylla"
    }
    target = hosts.get(authorization.target_stable_id)
    coordinator = hosts.get(authorization.coordinator_stable_id)
    survivors = tuple(sorted(set(hosts) - {authorization.target_stable_id}))
    required_quorum = tuple(
        sorted(view.stable_id for view in dead_target.survivor_views)
    )
    health_digest = scylla_health_evidence_digest(survivor_health)
    if target is None or coordinator is None or coordinator.logical_id not in survivors:
        raise StateConflictError(
            "dead removal requires an inventory target and coordinator"
        )
    if (
        metadata.cluster_uuid != inventory.record.cluster_uuid
        or observed.record.cluster_uuid != inventory.record.cluster_uuid
        or observed.record.generation != inventory.record.source_manifest_generation
        or observed.record.manifest_digest != inventory.record.source_manifest_digest
        or readiness.observation_digest != observed.digest
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_digest is None
    ):
        raise StateConflictError("Scylla dead-removal provenance conflicts")
    if (
        survivor_health.status is HealthReadiness.BLOCKED
        or survivor_health.blockers
        or survivor_health.queried_nodes != survivors
        or tuple(node.logical_id for node in survivor_health.nodes) != survivors
        or any(
            node.state != "UN" or node.host_id is None for node in survivor_health.nodes
        )
        or survivor_health.schema_agreement is not True
        or survivor_health.streaming_state != "complete"
        or dead_target.captured_at != survivor_health.captured_at_end
    ):
        raise StateConflictError(
            "dead removal requires fresh healthy survivor evidence"
        )
    dead_target.validate(required_quorum)
    if (
        not set(required_quorum) <= set(survivors)
        or coordinator.logical_id not in required_quorum
        or len(required_quorum) < (len(survivors) // 2 + 1)
        or len({view.coordinator_host_id for view in dead_target.survivor_views})
        != len(required_quorum)
        or dead_target.target_stable_id != target.logical_id
        or dead_target.target_host_id != authorization.target_host_id
        or dead_target.target_provider_id != target.provider_id
        or authorization.coordinator_stable_id != coordinator.logical_id
        or authorization.target_stable_id == authorization.coordinator_stable_id
    ):
        raise StateConflictError(
            "dead-target logical, Host, or provider identity conflicts"
        )
    safety.validate()
    expected_post_topology = [
        {
            "datacenter": node.datacenter,
            "host_id": node.host_id,
            "rack": node.rack,
            "state": "UN",
        }
        for node in survivor_health.nodes
    ]
    if (
        safety.health_digest != health_digest
        or safety.surviving_stable_ids != survivors
        or _object_digest(expected_post_topology)
        != safety.intended_post_topology_digest
    ):
        raise StateConflictError("dead-removal safety evidence conflicts")
    _validate_authorization(
        metadata,
        observed,
        inventory,
        readiness,
        target.provider_id,
        health_digest,
        safety,
        authorization,
    )
    coordinator_health = next(
        node
        for node in survivor_health.nodes
        if node.logical_id == coordinator.logical_id
    )
    pre_digest = _object_digest(
        {
            "dead_target": _dead_target_object(dead_target),
            "health_digest": health_digest,
            "safety": {
                "topology": safety.intended_post_topology_digest,
                "survivors": list(safety.surviving_stable_ids),
            },
        }
    )
    return {
        "authorization": {
            "authorization_digest": authorization.authorization_digest,
            "reviewed": authorization.reviewed,
        },
        "cluster_uuid": str(metadata.cluster_uuid),
        "coordinator": {
            "host_id": coordinator_health.host_id,
            "stable_id": coordinator.logical_id,
        },
        "expected_post_topology": expected_post_topology,
        "intended_post_topology_digest": safety.intended_post_topology_digest,
        "operation_id": authorization.operation_id,
        "pre_evidence_digest": pre_digest,
        "required_survivor_quorum": list(required_quorum),
        "schema_version": SCYLLA_REMOVE_DEAD_SCHEMA_VERSION,
        "target": {
            "host_id": dead_target.target_host_id,
            "provider_id_digest": _digest_text(target.provider_id),
            "stable_id": target.logical_id,
        },
        "timeout_seconds": timeout_seconds,
    }


def _validate_authorization(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    provider_id: str,
    health_digest: str,
    safety: ScyllaRemovalSafetyEvidence,
    authorization: ScyllaRemoveDeadAuthorization,
) -> None:
    try:
        valid_ids = (
            str(uuid.UUID(authorization.operation_id)) == authorization.operation_id
            and str(uuid.UUID(authorization.cluster_uuid)) == authorization.cluster_uuid
            and str(uuid.UUID(authorization.target_host_id))
            == authorization.target_host_id
        )
    except ValueError:
        valid_ids = False
    if (
        not valid_ids
        or authorization.cluster_uuid != str(metadata.cluster_uuid)
        or authorization.target_provider_id != provider_id
        or authorization.confirmed_target != authorization.target_stable_id
        or authorization.health_digest != health_digest
        or authorization.observation_digest != observed.digest
        or authorization.inventory_digest != inventory.digest
        or authorization.trust_digest != readiness.trust_digest
        or authorization.intended_post_topology_digest
        != safety.intended_post_topology_digest
        or not authorization.allow_destructive
        or not authorization.reviewed
        or authorization.prior_command_started
    ):
        raise StateConflictError(
            "dead-removal authorization does not bind the exact transition"
        )
    for value in (
        authorization.health_digest,
        authorization.observation_digest,
        authorization.inventory_digest,
        authorization.trust_digest,
        authorization.intended_post_topology_digest,
        authorization.authorization_digest,
    ):
        _require_digest(value)


def parse_scylla_remove_dead_execution(
    stdout: str, *, expected_payload: dict[str, object], exit_code: int
) -> ScyllaRemoveDeadEvidence:
    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError("Ansible dead-removal output exceeds the limit")
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_SCYLLA_REMOVE_DEAD_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible dead-removal marker is malformed")
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError("Ansible dead-removal marker is malformed") from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible dead-removal evidence is malformed")
        values.append(value)
    coordinator = cast(dict[str, object], expected_payload.get("coordinator"))
    stable_id = _text(coordinator.get("stable_id"))
    recap = _parse_recap(stdout)
    if set(recap) != {stable_id} or len(values) != 1:
        raise AnsibleError("Ansible dead-removal evidence is incomplete")
    evidence = _parse_result(values[0], expected_payload)
    changed, unreachable, failed = recap[stable_id]
    result_failed = evidence.status is not ScyllaRemoveDeadStatus.REMOVED
    if bool(unreachable or failed) != result_failed or (exit_code == 0) != (
        not result_failed
    ):
        raise AnsibleError("Ansible dead-removal exit status conflicts")
    if bool(changed) != (
        evidence.command_boundary is not RemoveNodeCommandBoundary.NOT_STARTED
    ):
        raise AnsibleError("Ansible dead-removal mutation status conflicts")
    return evidence


def scylla_remove_dead_interrupted_evidence(
    payload: dict[str, object],
) -> ScyllaRemoveDeadEvidence:
    target = cast(dict[str, object], payload["target"])
    coordinator = cast(dict[str, object], payload["coordinator"])
    host_id = _text(target["host_id"])
    coordinator_host_id = _text(coordinator["host_id"])
    return ScyllaRemoveDeadEvidence(
        ScyllaRemoveDeadStatus.FAILED,
        _text(target["stable_id"]),
        _text(coordinator["stable_id"]),
        _digest_text(host_id),
        _digest_text(coordinator_host_id),
        _require_digest(payload["pre_evidence_digest"]),
        None,
        ("/usr/bin/nodetool", "removenode", host_id),
        ("/usr/bin/nodetool", "removenode", "status"),
        RemoveNodeCommandBoundary.STARTED,
        RingMutationBoundary.MAY_HAVE_CHANGED,
        "unknown",
        tuple((name, SafetyCheckStatus.UNKNOWN) for name in _POSTCONDITIONS),
        True,
        ("execution-interrupted",),
    )


def scylla_remove_dead_checkpoint_evidence(
    evidence: ScyllaRemoveDeadEvidence,
) -> CheckpointEvidence:
    if evidence.status is ScyllaRemoveDeadStatus.NOT_PREDICTED:
        raise StateConflictError("check refusal is not removal execution evidence")
    completed = evidence.status is ScyllaRemoveDeadStatus.REMOVED
    summary = (
        "scylla-dead-removal-complete"
        if completed
        else "scylla-removenode-started-recovery-required"
        if evidence.command_boundary is not RemoveNodeCommandBoundary.NOT_STARTED
        else "scylla-dead-removal-refused"
    )
    return CheckpointEvidence(
        OperationPhase.EXECUTE,
        EvidenceResult.COMPLETED if completed else EvidenceResult.FAILED,
        _object_digest(_result_object(evidence)),
        summary,
    )


_POSTCONDITIONS = (
    "expected-topology",
    "no-streaming",
    "removal-finished",
    "schema-agreement",
    "survivors-up-normal",
    "target-absent",
)


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> ScyllaRemoveDeadEvidence:
    fields = {
        "blockers",
        "command_boundary",
        "coordinator_host_id_digest",
        "coordinator_stable_id",
        "mutation_boundary",
        "post_evidence_digest",
        "postconditions",
        "pre_evidence_digest",
        "recovery_required",
        "removal_command",
        "removal_status",
        "schema_version",
        "status",
        "status_command",
        "target_host_id_digest",
        "target_stable_id",
    }
    if (
        set(value) != fields
        or value["schema_version"] != SCYLLA_REMOVE_DEAD_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible dead-removal result schema is invalid")
    target = cast(dict[str, object], expected["target"])
    coordinator = cast(dict[str, object], expected["coordinator"])
    try:
        status = ScyllaRemoveDeadStatus(_text(value["status"]))
        command_boundary = RemoveNodeCommandBoundary(_text(value["command_boundary"]))
        mutation_boundary = RingMutationBoundary(_text(value["mutation_boundary"]))
    except ValueError as error:
        raise AnsibleError("Ansible dead-removal enum is invalid") from error
    host_id = _text(target["host_id"])
    evidence = ScyllaRemoveDeadEvidence(
        status,
        _text(value["target_stable_id"]),
        _text(value["coordinator_stable_id"]),
        _require_digest(value["target_host_id_digest"]),
        _require_digest(value["coordinator_host_id_digest"]),
        _require_digest(value["pre_evidence_digest"]),
        _optional_digest(value["post_evidence_digest"]),
        _command(value["removal_command"]),
        _command(value["status_command"]),
        command_boundary,
        mutation_boundary,
        _text(value["removal_status"]),
        _postconditions(value["postconditions"]),
        _boolean(value["recovery_required"]),
        _sorted_strings(value["blockers"]),
    )
    if (
        evidence.target_stable_id != target["stable_id"]
        or evidence.coordinator_stable_id != coordinator["stable_id"]
        or evidence.target_host_id_digest != _digest_text(host_id)
        or evidence.coordinator_host_id_digest
        != _digest_text(_text(coordinator["host_id"]))
        or evidence.pre_evidence_digest != expected["pre_evidence_digest"]
        or evidence.removal_command != ("/usr/bin/nodetool", "removenode", host_id)
        or evidence.status_command != ("/usr/bin/nodetool", "removenode", "status")
        or not set(evidence.blockers) <= _BLOCKERS
    ):
        raise AnsibleError("Ansible dead-removal result conflicts")
    passed = all(
        item is SafetyCheckStatus.PASSED for _, item in evidence.postconditions
    )
    if status is ScyllaRemoveDeadStatus.REMOVED and (
        command_boundary is not RemoveNodeCommandBoundary.COMPLETED
        or mutation_boundary is not RingMutationBoundary.TARGET_ABSENT
        or evidence.removal_status != "complete"
        or evidence.post_evidence_digest is None
        or not passed
        or evidence.recovery_required
        or evidence.blockers
    ):
        raise AnsibleError("Ansible dead-removal success evidence conflicts")
    if status is ScyllaRemoveDeadStatus.NOT_PREDICTED and (
        command_boundary is not RemoveNodeCommandBoundary.NOT_STARTED
        or mutation_boundary is not RingMutationBoundary.UNCHANGED
        or evidence.removal_status != "not-performed"
        or evidence.post_evidence_digest is not None
        or any(
            item is not SafetyCheckStatus.NOT_PERFORMED
            for _, item in evidence.postconditions
        )
        or evidence.recovery_required
        or evidence.blockers
    ):
        raise AnsibleError("Ansible dead-removal check refusal conflicts")
    if status is ScyllaRemoveDeadStatus.FAILED and (
        not evidence.recovery_required or not evidence.blockers
    ):
        raise AnsibleError("Ansible dead-removal failure evidence conflicts")
    return evidence


def _dead_target_object(value: DeadTargetEvidence) -> object:
    return {
        "captured_at": value.captured_at,
        "provider_identity_unchanged": value.provider_identity_unchanged,
        "provider_id_digest": _digest_text(value.target_provider_id),
        "reachability": [
            value.ssh_reachability.value,
            value.service_reachability.value,
            value.provider_lifecycle_reachability.value,
        ],
        "survivor_views": [
            {
                "ring_digest": item.ring_digest,
                "stable_id": item.stable_id,
                "target_host_id": item.target_host_id,
            }
            for item in value.survivor_views
        ],
        "target_host_id": value.target_host_id,
        "target_stable_id": value.target_stable_id,
    }


def _result_object(value: ScyllaRemoveDeadEvidence) -> object:
    return {
        "blockers": list(value.blockers),
        "command_boundary": value.command_boundary.value,
        "coordinator_stable_id": value.coordinator_stable_id,
        "mutation_boundary": value.mutation_boundary.value,
        "post_evidence_digest": value.post_evidence_digest,
        "pre_evidence_digest": value.pre_evidence_digest,
        "recovery_required": value.recovery_required,
        "removal_status": value.removal_status,
        "status": value.status.value,
        "target_stable_id": value.target_stable_id,
    }


def _postconditions(value: object) -> tuple[tuple[str, SafetyCheckStatus], ...]:
    if not isinstance(value, dict) or tuple(sorted(value)) != _POSTCONDITIONS:
        raise AnsibleError("Scylla dead-removal postconditions are invalid")
    try:
        return tuple(
            (name, SafetyCheckStatus(_text(value[name]))) for name in _POSTCONDITIONS
        )
    except ValueError as error:
        raise AnsibleError("dead-removal postcondition status is invalid") from error


def _parse_recap(stdout: str) -> dict[str, tuple[int, int, int]]:
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible dead-removal output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible dead-removal recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    return rows


def _object_digest(value: object) -> str:
    encoded = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _digest_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AnsibleError("dead-removal evidence has duplicate fields")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise AnsibleError(f"invalid dead-removal constant: {value}")


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible dead-removal value is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible dead-removal digest is invalid")
    return text


def _optional_digest(value: object) -> str | None:
    return None if value is None else _require_digest(value)


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError("Ansible dead-removal boolean is invalid")
    return value


def _command(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible dead-removal command is invalid")
    return tuple(_text(item) for item in value)


def _sorted_strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible dead-removal blockers are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError("Ansible dead-removal blockers are not sorted")
    return items
