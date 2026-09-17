"""Strict post-expansion ScyllaDB 2026.2 cleanup contracts."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from enum import StrEnum

from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.scylla_health import HealthReadiness, ScyllaHealthEvidence
from scylla_vms.ansible.scylla_remove_live import scylla_health_evidence_digest
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.journal import CheckpointEvidence, EvidenceResult, OperationPhase
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata, parse_timestamp

SCYLLA_CLEANUP_SCHEMA_VERSION = "deploy-scylla-vms.ansible-scylla-cleanup/v1"

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PACKAGE_VERSION = re.compile(
    r"2026\.2\.(?:0|[1-9][0-9]*)-0\.[0-9]{8}\.[0-9a-f]{12}-1\Z"
)
_MARKER = re.compile(r"DSV_SCYLLA_CLEANUP_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_BLOCKERS = frozenset(
    {
        "cleanup-timeout",
        "command-failed",
        "execution-interrupted",
        "pending-work",
        "post-health-failed",
        "revalidation-failed",
    }
)


class CleanupOperation(StrEnum):
    ADD_NODE = "add-node"
    SCALE_OUT = "scale-out"


class ScyllaCleanupStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    NOT_PREDICTED = "not-predicted"


class CleanupMutationBoundary(StrEnum):
    NOT_STARTED = "not-started"
    COMMAND_STARTED = "command-started"
    COMMAND_COMPLETED = "command-completed"
    POSTCHECKS_PASSED = "postchecks-passed"


@dataclass(frozen=True, slots=True)
class CleanupTopologyChangeEvidence:
    operation: CleanupOperation
    operation_id: str
    status: str
    pre_existing_ids: tuple[str, ...]
    joined_ids: tuple[str, ...]
    post_topology_digest: str
    bootstrap_results_digest: str
    repair_required: bool
    repair_completed: bool
    repair_result_digest: str | None
    recovery_required: bool = False


@dataclass(frozen=True, slots=True)
class ScyllaCleanupAuthorization:
    operation_id: str
    cluster_uuid: str
    stable_id: str
    host_id: str
    observation_digest: str
    inventory_digest: str
    trust_digest: str
    config_digest: str
    storage_digest: str
    health_digest: str
    health_captured_at: str
    topology_change_digest: str
    repair_result_digest: str | None
    disk_headroom_digest: str
    authorization_digest: str
    confirmed_target: str
    disk_headroom_passed: bool
    no_competing_operation: bool
    reviewed: bool
    prior_cleanup_started: bool = False


@dataclass(frozen=True, slots=True)
class ScyllaCleanupEvidence:
    status: ScyllaCleanupStatus
    stable_id: str
    host_id_digest: str
    topology_change_digest: str
    repair_result_digest: str | None
    pre_health_digest: str
    post_health_digest: str | None
    command_evidence: str
    pending_work_evidence: str
    mutation_boundary: CleanupMutationBoundary
    recovery_required: bool
    blockers: tuple[str, ...]
    schema_version: str = SCYLLA_CLEANUP_SCHEMA_VERSION


def build_scylla_cleanup_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    health: ScyllaHealthEvidence,
    topology_change: CleanupTopologyChangeEvidence,
    authorization: ScyllaCleanupAuthorization,
    *,
    package_version: str,
    timeout_seconds: int,
) -> dict[str, object]:
    """Build one authorized post-expansion cleanup request."""

    if (
        _PACKAGE_VERSION.fullmatch(package_version) is None
        or not 300 <= timeout_seconds <= 86_400
    ):
        raise StateConflictError("Scylla cleanup version or timeout is invalid")
    hosts = tuple(
        host for host in inventory.record.inventory.hosts if host.role.value == "scylla"
    )
    target = next(
        (host for host in hosts if host.logical_id == authorization.stable_id), None
    )
    if target is None or target.scylla_datacenter is None or target.scylla_rack is None:
        raise StateConflictError(
            "Scylla cleanup target is not an exact Scylla stable ID"
        )
    if (
        metadata.cluster_uuid != inventory.record.cluster_uuid
        or observed.record.cluster_uuid != inventory.record.cluster_uuid
        or observed.record.generation != inventory.record.source_manifest_generation
        or readiness.observation_digest != observed.digest
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_digest is None
    ):
        raise StateConflictError("Scylla cleanup provenance conflicts")
    parse_timestamp(health.captured_at_start)
    parse_timestamp(health.captured_at_end)
    expected_ids = tuple(host.logical_id for host in hosts)
    health_digest = scylla_health_evidence_digest(health)
    node = next(
        (item for item in health.nodes if item.logical_id == target.logical_id), None
    )
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
        or node is None
        or node.host_id != authorization.host_id
        or node.datacenter != target.scylla_datacenter
        or node.rack != target.scylla_rack
    ):
        raise StateConflictError("Scylla cleanup requires fresh full-cluster health")
    topology_digest = _topology_change_digest(topology_change)
    _validate_topology_change(topology_change, expected_ids, target.logical_id, health)
    _validate_authorization(
        metadata,
        observed,
        inventory,
        readiness,
        health_digest,
        health.captured_at_end,
        topology_digest,
        topology_change,
        authorization,
    )
    return {
        "authorization": {
            "authorization_digest": authorization.authorization_digest,
            "reviewed": authorization.reviewed,
        },
        "cleanup_command": ["/usr/bin/nodetool", "cleanup"],
        "cluster_uuid": str(metadata.cluster_uuid),
        "config_digest": authorization.config_digest,
        "expected_ring": [
            {
                "datacenter": item.datacenter,
                "host_id": item.host_id,
                "rack": item.rack,
                "state": "UN",
            }
            for item in health.nodes
        ],
        "health_digest": health_digest,
        "host_id": authorization.host_id,
        "inventory_digest": inventory.digest,
        "observation_digest": observed.digest,
        "repair_result_digest": topology_change.repair_result_digest,
        "schema_version": SCYLLA_CLEANUP_SCHEMA_VERSION,
        "server_version": package_version.split("-0.", 1)[0],
        "stable_id": target.logical_id,
        "storage_digest": authorization.storage_digest,
        "timeout_seconds": timeout_seconds,
        "topology_change_digest": topology_digest,
        "topology_digest": health.topology_digest,
        "trust_digest": readiness.trust_digest,
    }


def _validate_topology_change(
    value: CleanupTopologyChangeEvidence,
    expected_ids: tuple[str, ...],
    target: str,
    health: ScyllaHealthEvidence,
) -> None:
    try:
        valid_operation_id = str(uuid.UUID(value.operation_id)) == value.operation_id
    except ValueError:
        valid_operation_id = False
    eligible = (*value.pre_existing_ids, *value.joined_ids[:-1])
    if (
        not valid_operation_id
        or value.status != "completed"
        or value.recovery_required
        or not value.pre_existing_ids
        or not value.joined_ids
        or len(set((*value.pre_existing_ids, *value.joined_ids))) != len(expected_ids)
        or tuple(sorted((*value.pre_existing_ids, *value.joined_ids))) != expected_ids
        or target not in eligible
        or value.post_topology_digest != health.topology_digest
        or value.repair_required != (value.repair_result_digest is not None)
        or value.repair_required != value.repair_completed
    ):
        raise StateConflictError("Scylla cleanup topology-change evidence is invalid")
    _require_digest(value.post_topology_digest)
    _require_digest(value.bootstrap_results_digest)
    if value.repair_result_digest is not None:
        _require_digest(value.repair_result_digest)


def _validate_authorization(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    health_digest: str,
    captured_at: str,
    topology_digest: str,
    topology: CleanupTopologyChangeEvidence,
    value: ScyllaCleanupAuthorization,
) -> None:
    parse_timestamp(value.health_captured_at)
    try:
        valid_ids = (
            str(uuid.UUID(value.operation_id)) == value.operation_id
            and str(uuid.UUID(value.cluster_uuid)) == value.cluster_uuid
            and str(uuid.UUID(value.host_id)) == value.host_id
        )
    except ValueError:
        valid_ids = False
    if (
        not valid_ids
        or value.operation_id != topology.operation_id
        or value.cluster_uuid != str(metadata.cluster_uuid)
        or value.observation_digest != observed.digest
        or value.inventory_digest != inventory.digest
        or value.trust_digest != readiness.trust_digest
        or value.health_digest != health_digest
        or value.health_captured_at != captured_at
        or value.topology_change_digest != topology_digest
        or value.repair_result_digest != topology.repair_result_digest
        or value.confirmed_target != value.stable_id
        or not value.disk_headroom_passed
        or not value.no_competing_operation
        or not value.reviewed
        or value.prior_cleanup_started
    ):
        raise StateConflictError("cleanup authorization does not bind exact execution")
    for digest in (
        value.observation_digest,
        value.inventory_digest,
        value.trust_digest,
        value.config_digest,
        value.storage_digest,
        value.health_digest,
        value.topology_change_digest,
        value.disk_headroom_digest,
        value.authorization_digest,
    ):
        _require_digest(digest)


def parse_scylla_cleanup_execution(
    stdout: str, *, expected_payload: dict[str, object], exit_code: int
) -> ScyllaCleanupEvidence:
    if len(stdout.encode()) > 512 * 1024:
        raise AnsibleError("Ansible cleanup output exceeds evidence limit")
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_SCYLLA_CLEANUP_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible cleanup marker is malformed")
        try:
            item = json.loads(
                base64.b64decode(match.group("data"), validate=True).decode(),
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError("Ansible cleanup marker is malformed") from error
        if not isinstance(item, dict):
            raise AnsibleError("Ansible cleanup evidence is malformed")
        values.append(item)
    stable_id = _text(expected_payload["stable_id"])
    recap = _parse_recap(stdout)
    if len(values) != 1 or set(recap) != {stable_id}:
        raise AnsibleError("Ansible cleanup evidence is incomplete")
    evidence = _parse_result(values[0], expected_payload)
    changed, unreachable, failed = recap[stable_id]
    if evidence.status is ScyllaCleanupStatus.NOT_PREDICTED:
        if not bool(unreachable or failed) or exit_code == 0 or changed:
            raise AnsibleError("Ansible cleanup check refusal conflicts")
        return evidence
    expected_failed = evidence.status is ScyllaCleanupStatus.FAILED
    expected_changed = (
        evidence.mutation_boundary is not CleanupMutationBoundary.NOT_STARTED
    )
    if (
        bool(unreachable or failed) != expected_failed
        or (exit_code == 0) == expected_failed
        or bool(changed) != expected_changed
    ):
        raise AnsibleError("Ansible cleanup recap conflicts")
    return evidence


def scylla_cleanup_interrupted_evidence(
    payload: dict[str, object],
) -> ScyllaCleanupEvidence:
    return ScyllaCleanupEvidence(
        ScyllaCleanupStatus.FAILED,
        _text(payload["stable_id"]),
        _digest_text(_text(payload["host_id"])),
        _require_digest(payload["topology_change_digest"]),
        _optional_digest(payload["repair_result_digest"]),
        _require_digest(payload["health_digest"]),
        None,
        "unknown",
        "not-proven",
        CleanupMutationBoundary.COMMAND_STARTED,
        True,
        ("execution-interrupted",),
    )


def scylla_cleanup_checkpoint_evidence(
    evidence: ScyllaCleanupEvidence,
) -> CheckpointEvidence:
    if evidence.status is ScyllaCleanupStatus.NOT_PREDICTED:
        raise StateConflictError("check refusal is not cleanup execution evidence")
    completed = evidence.status is ScyllaCleanupStatus.COMPLETED
    summary = (
        "scylla-cleanup-complete"
        if completed
        else "scylla-cleanup-recovery-required"
        if evidence.mutation_boundary is not CleanupMutationBoundary.NOT_STARTED
        else "scylla-cleanup-refused"
    )
    return CheckpointEvidence(
        OperationPhase.EXECUTE,
        EvidenceResult.COMPLETED if completed else EvidenceResult.FAILED,
        _object_digest(
            {
                "blockers": list(evidence.blockers),
                "boundary": evidence.mutation_boundary.value,
                "stable_id": evidence.stable_id,
                "status": evidence.status.value,
            }
        ),
        summary,
    )


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> ScyllaCleanupEvidence:
    fields = {
        "blockers",
        "command_evidence",
        "host_id_digest",
        "mutation_boundary",
        "pending_work_evidence",
        "post_health_digest",
        "pre_health_digest",
        "recovery_required",
        "repair_result_digest",
        "schema_version",
        "stable_id",
        "status",
        "topology_change_digest",
    }
    if set(value) != fields or value["schema_version"] != SCYLLA_CLEANUP_SCHEMA_VERSION:
        raise AnsibleError("Ansible cleanup result schema is invalid")
    try:
        evidence = ScyllaCleanupEvidence(
            ScyllaCleanupStatus(_text(value["status"])),
            _text(value["stable_id"]),
            _require_digest(value["host_id_digest"]),
            _require_digest(value["topology_change_digest"]),
            _optional_digest(value["repair_result_digest"]),
            _require_digest(value["pre_health_digest"]),
            _optional_digest(value["post_health_digest"]),
            _text(value["command_evidence"]),
            _text(value["pending_work_evidence"]),
            CleanupMutationBoundary(_text(value["mutation_boundary"])),
            _boolean(value["recovery_required"]),
            _sorted_strings(value["blockers"]),
        )
    except ValueError as error:
        raise AnsibleError("Ansible cleanup enum is invalid") from error
    if (
        evidence.stable_id != expected["stable_id"]
        or evidence.host_id_digest != _digest_text(_text(expected["host_id"]))
        or evidence.topology_change_digest != expected["topology_change_digest"]
        or evidence.repair_result_digest != expected["repair_result_digest"]
        or evidence.pre_health_digest != expected["health_digest"]
        or not set(evidence.blockers) <= _BLOCKERS
    ):
        raise AnsibleError("Ansible cleanup result conflicts")
    if evidence.status is ScyllaCleanupStatus.COMPLETED and (
        evidence.mutation_boundary is not CleanupMutationBoundary.POSTCHECKS_PASSED
        or evidence.post_health_digest is None
        or evidence.command_evidence != "exit-zero"
        or evidence.pending_work_evidence != "none"
        or evidence.recovery_required
        or evidence.blockers
    ):
        raise AnsibleError("Ansible cleanup completion evidence conflicts")
    if evidence.status is ScyllaCleanupStatus.FAILED and (
        not evidence.recovery_required or not evidence.blockers
    ):
        raise AnsibleError("Ansible cleanup failure evidence conflicts")
    if evidence.status is ScyllaCleanupStatus.NOT_PREDICTED and (
        evidence.mutation_boundary is not CleanupMutationBoundary.NOT_STARTED
        or evidence.post_health_digest is not None
        or evidence.command_evidence != "not-run"
        or evidence.pending_work_evidence != "not-predicted"
        or evidence.recovery_required
        or evidence.blockers
    ):
        raise AnsibleError("Ansible cleanup check refusal conflicts")
    return evidence


def _topology_change_digest(value: CleanupTopologyChangeEvidence) -> str:
    return _object_digest(
        {
            "bootstrap_results_digest": value.bootstrap_results_digest,
            "joined_ids": list(value.joined_ids),
            "operation": value.operation.value,
            "operation_id": value.operation_id,
            "post_topology_digest": value.post_topology_digest,
            "pre_existing_ids": list(value.pre_existing_ids),
            "repair_result_digest": value.repair_result_digest,
            "status": value.status,
        }
    )


def _parse_recap(stdout: str) -> dict[str, tuple[int, int, int]]:
    _, marker, body = stdout.partition("PLAY RECAP")
    if not marker:
        raise AnsibleError("Ansible cleanup output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in body.splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible cleanup recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    return rows


def _object_digest(value: object) -> str:
    encoded = json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True)
    return "sha256:" + hashlib.sha256(encoded.encode()).hexdigest()


def _digest_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AnsibleError("cleanup evidence has duplicate fields")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise AnsibleError(f"invalid cleanup constant: {value}")


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible cleanup value is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible cleanup digest is invalid")
    return text


def _optional_digest(value: object) -> str | None:
    return None if value is None else _require_digest(value)


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError("Ansible cleanup boolean is invalid")
    return value


def _sorted_strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible cleanup blockers are invalid")
    values = tuple(_text(item) for item in value)
    if values != tuple(sorted(set(values))):
        raise AnsibleError("Ansible cleanup blockers are not sorted")
    return values
