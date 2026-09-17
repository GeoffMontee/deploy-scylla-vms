"""Strict direct ScyllaDB 2026.2 repair contracts."""

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
from scylla_vms.ansible.scylla_bootstrap import (
    ScyllaBootstrapEvidence,
    ScyllaBootstrapMode,
    ScyllaBootstrapStatus,
)
from scylla_vms.ansible.scylla_health import HealthReadiness, ScyllaHealthEvidence
from scylla_vms.ansible.scylla_remove_live import scylla_health_evidence_digest
from scylla_vms.ansible.scylla_replace_dead import (
    RepairBasedNodeOperationsEvidence,
    ScyllaReplaceDeadEvidence,
    ScyllaReplaceDeadStatus,
)
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.journal import CheckpointEvidence, EvidenceResult, OperationPhase
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata, parse_timestamp

SCYLLA_REPAIR_SCHEMA_VERSION = "deploy-scylla-vms.ansible-scylla-repair/v1"

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PACKAGE_VERSION = re.compile(
    r"2026\.2\.(?:0|[1-9][0-9]*)-0\.[0-9]{8}\.[0-9a-f]{12}-1\Z"
)
_MARKER = re.compile(r"DSV_SCYLLA_REPAIR_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_BLOCKERS = frozenset(
    {
        "command-failed",
        "execution-interrupted",
        "pending-work",
        "post-health-failed",
        "repair-timeout",
        "revalidation-failed",
    }
)


class ScyllaRepairReason(StrEnum):
    POST_REPLACEMENT = "post-replacement"
    POST_BOOTSTRAP = "post-bootstrap"


class ScyllaRepairStatus(StrEnum):
    COMPLETED = "completed"
    RBNO_SKIPPED = "rbno-skipped"
    FAILED = "failed"
    NOT_PREDICTED = "not-predicted"


class RepairMutationBoundary(StrEnum):
    NOT_STARTED = "not-started"
    COMMAND_STARTED = "command-started"
    COMMAND_COMPLETED = "command-completed"
    POSTCHECKS_PASSED = "postchecks-passed"


@dataclass(frozen=True, slots=True)
class ScyllaRepairAuthorization:
    operation_id: str
    cluster_uuid: str
    stable_id: str
    host_id: str
    reason: ScyllaRepairReason
    observation_digest: str
    inventory_digest: str
    trust_digest: str
    config_digest: str
    storage_digest: str
    health_digest: str
    health_captured_at: str
    source_result_digest: str
    capacity_digest: str
    quorum_digest: str
    authorization_digest: str
    confirmed_target: str
    capacity_passed: bool
    quorum_passed: bool
    no_competing_operation: bool
    reviewed: bool
    prior_repair_started: bool = False


@dataclass(frozen=True, slots=True)
class ScyllaRepairEvidence:
    reason: ScyllaRepairReason
    status: ScyllaRepairStatus
    stable_id: str
    host_id_digest: str
    pre_health_digest: str
    post_health_digest: str | None
    source_result_digest: str
    command_evidence: str
    completion_evidence: str
    completion_cryptographically_proven: bool
    explicit_review_required: bool
    rbno_skip: bool
    mutation_boundary: RepairMutationBoundary
    recovery_required: bool
    blockers: tuple[str, ...]
    schema_version: str = SCYLLA_REPAIR_SCHEMA_VERSION


def build_scylla_repair_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    health: ScyllaHealthEvidence,
    source_result: ScyllaReplaceDeadEvidence | ScyllaBootstrapEvidence,
    rbno: RepairBasedNodeOperationsEvidence,
    authorization: ScyllaRepairAuthorization,
    *,
    package_version: str,
    timeout_seconds: int,
) -> dict[str, object]:
    """Build one authorized full direct repair request."""

    if (
        _PACKAGE_VERSION.fullmatch(package_version) is None
        or not 300 <= timeout_seconds <= 86_400
    ):
        raise StateConflictError("Scylla repair version or timeout is invalid")
    hosts = tuple(
        host for host in inventory.record.inventory.hosts if host.role.value == "scylla"
    )
    target = next(
        (host for host in hosts if host.logical_id == authorization.stable_id), None
    )
    if target is None or target.scylla_datacenter is None or target.scylla_rack is None:
        raise StateConflictError(
            "Scylla repair target is not an exact Scylla stable ID"
        )
    if (
        metadata.cluster_uuid != inventory.record.cluster_uuid
        or observed.record.cluster_uuid != inventory.record.cluster_uuid
        or observed.record.generation != inventory.record.source_manifest_generation
        or readiness.observation_digest != observed.digest
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_digest is None
    ):
        raise StateConflictError("Scylla repair provenance conflicts")
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
        raise StateConflictError("Scylla repair requires fresh full-cluster health")
    source_digest = _source_result_digest(source_result)
    skip = _validate_source_result(source_result, rbno, authorization)
    _validate_authorization(
        metadata,
        observed,
        inventory,
        readiness,
        health_digest,
        health.captured_at_end,
        source_digest,
        authorization,
    )
    return {
        "authorization": {
            "authorization_digest": authorization.authorization_digest,
            "reviewed": authorization.reviewed,
        },
        "cluster_uuid": str(metadata.cluster_uuid),
        "config_digest": authorization.config_digest,
        "datacenter": target.scylla_datacenter,
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
        "package_version": package_version,
        "rack": target.scylla_rack,
        "reason": authorization.reason.value,
        "repair_command": ["/usr/bin/nodetool", "repair"],
        "rbno_skip": skip,
        "server_version": package_version.split("-0.", 1)[0],
        "schema_version": SCYLLA_REPAIR_SCHEMA_VERSION,
        "source_result_digest": source_digest,
        "stable_id": target.logical_id,
        "storage_digest": authorization.storage_digest,
        "timeout_seconds": timeout_seconds,
        "topology_digest": health.topology_digest,
        "trust_digest": readiness.trust_digest,
    }


def _validate_source_result(
    source: ScyllaReplaceDeadEvidence | ScyllaBootstrapEvidence,
    rbno: RepairBasedNodeOperationsEvidence,
    authorization: ScyllaRepairAuthorization,
) -> bool:
    rbno.validate()
    if authorization.reason is ScyllaRepairReason.POST_REPLACEMENT:
        if (
            not isinstance(source, ScyllaReplaceDeadEvidence)
            or source.status is not ScyllaReplaceDeadStatus.REPLACED
            or source.stable_id != authorization.stable_id
            or source.recovery_required
        ):
            raise StateConflictError("post-replacement repair source result is invalid")
        skip = rbno.enabled and rbno.replacement_complete and not source.repair_required
        if not skip and not source.repair_required:
            raise StateConflictError("replacement repair requirement conflicts")
        return skip
    if (
        not isinstance(source, ScyllaBootstrapEvidence)
        or source.status is not ScyllaBootstrapStatus.BOOTSTRAPPED
        or source.mode is not ScyllaBootstrapMode.JOIN_EXISTING
        or source.target_logical_id != authorization.stable_id
        or source.recovery_required
        or rbno.enabled
        or rbno.replacement_complete
    ):
        raise StateConflictError("post-bootstrap repair source result is invalid")
    return False


def _validate_authorization(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    health_digest: str,
    health_captured_at: str,
    source_digest: str,
    value: ScyllaRepairAuthorization,
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
        or value.cluster_uuid != str(metadata.cluster_uuid)
        or value.observation_digest != observed.digest
        or value.inventory_digest != inventory.digest
        or value.trust_digest != readiness.trust_digest
        or value.health_digest != health_digest
        or value.health_captured_at != health_captured_at
        or value.source_result_digest != source_digest
        or value.confirmed_target != value.stable_id
        or not value.capacity_passed
        or not value.quorum_passed
        or not value.no_competing_operation
        or not value.reviewed
        or value.prior_repair_started
    ):
        raise StateConflictError(
            "repair authorization does not bind the exact execution"
        )
    for digest in (
        value.observation_digest,
        value.inventory_digest,
        value.trust_digest,
        value.config_digest,
        value.storage_digest,
        value.health_digest,
        value.source_result_digest,
        value.capacity_digest,
        value.quorum_digest,
        value.authorization_digest,
    ):
        _require_digest(digest)


def parse_scylla_repair_execution(
    stdout: str, *, expected_payload: dict[str, object], exit_code: int
) -> ScyllaRepairEvidence:
    if len(stdout.encode()) > 512 * 1024:
        raise AnsibleError("Ansible repair output exceeds the evidence limit")
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_SCYLLA_REPAIR_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible repair marker is malformed")
        try:
            item = json.loads(
                base64.b64decode(match.group("data"), validate=True).decode(),
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError("Ansible repair marker is malformed") from error
        if not isinstance(item, dict):
            raise AnsibleError("Ansible repair evidence is malformed")
        values.append(item)
    stable_id = _text(expected_payload["stable_id"])
    recap = _parse_recap(stdout)
    if len(values) != 1 or set(recap) != {stable_id}:
        raise AnsibleError("Ansible repair evidence is incomplete")
    evidence = _parse_result(values[0], expected_payload)
    changed, unreachable, failed = recap[stable_id]
    if evidence.status is ScyllaRepairStatus.NOT_PREDICTED:
        if not bool(unreachable or failed) or exit_code == 0 or changed:
            raise AnsibleError("Ansible repair check refusal conflicts")
        return evidence
    expected_failed = evidence.status is ScyllaRepairStatus.FAILED
    expected_changed = evidence.mutation_boundary not in {
        RepairMutationBoundary.NOT_STARTED,
    }
    if (
        bool(unreachable or failed) != expected_failed
        or (exit_code == 0) == expected_failed
        or bool(changed) != expected_changed
    ):
        raise AnsibleError("Ansible repair recap conflicts")
    return evidence


def scylla_repair_interrupted_evidence(
    payload: dict[str, object],
) -> ScyllaRepairEvidence:
    return ScyllaRepairEvidence(
        ScyllaRepairReason(_text(payload["reason"])),
        ScyllaRepairStatus.FAILED,
        _text(payload["stable_id"]),
        _digest_text(_text(payload["host_id"])),
        _require_digest(payload["health_digest"]),
        None,
        _require_digest(payload["source_result_digest"]),
        "unknown",
        "not-proven",
        False,
        True,
        False,
        RepairMutationBoundary.COMMAND_STARTED,
        True,
        ("execution-interrupted",),
    )


def scylla_repair_checkpoint_evidence(
    evidence: ScyllaRepairEvidence,
) -> CheckpointEvidence:
    if evidence.status is ScyllaRepairStatus.NOT_PREDICTED:
        raise StateConflictError("check refusal is not repair execution evidence")
    completed = evidence.status in {
        ScyllaRepairStatus.COMPLETED,
        ScyllaRepairStatus.RBNO_SKIPPED,
    }
    summary = (
        "scylla-repair-rbno-skipped"
        if evidence.status is ScyllaRepairStatus.RBNO_SKIPPED
        else "scylla-repair-complete-review-required"
        if completed
        else "scylla-repair-recovery-required"
        if evidence.mutation_boundary is not RepairMutationBoundary.NOT_STARTED
        else "scylla-repair-refused"
    )
    return CheckpointEvidence(
        OperationPhase.EXECUTE,
        EvidenceResult.COMPLETED if completed else EvidenceResult.FAILED,
        _object_digest(_result_object(evidence)),
        summary,
    )


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> ScyllaRepairEvidence:
    fields = {
        "blockers",
        "command_evidence",
        "completion_cryptographically_proven",
        "completion_evidence",
        "explicit_review_required",
        "host_id_digest",
        "mutation_boundary",
        "post_health_digest",
        "pre_health_digest",
        "reason",
        "rbno_skip",
        "recovery_required",
        "schema_version",
        "source_result_digest",
        "stable_id",
        "status",
    }
    if set(value) != fields or value["schema_version"] != SCYLLA_REPAIR_SCHEMA_VERSION:
        raise AnsibleError("Ansible repair result schema is invalid")
    try:
        evidence = ScyllaRepairEvidence(
            ScyllaRepairReason(_text(value["reason"])),
            ScyllaRepairStatus(_text(value["status"])),
            _text(value["stable_id"]),
            _require_digest(value["host_id_digest"]),
            _require_digest(value["pre_health_digest"]),
            _optional_digest(value["post_health_digest"]),
            _require_digest(value["source_result_digest"]),
            _text(value["command_evidence"]),
            _text(value["completion_evidence"]),
            _boolean(value["completion_cryptographically_proven"]),
            _boolean(value["explicit_review_required"]),
            _boolean(value["rbno_skip"]),
            RepairMutationBoundary(_text(value["mutation_boundary"])),
            _boolean(value["recovery_required"]),
            _sorted_strings(value["blockers"]),
        )
    except ValueError as error:
        raise AnsibleError("Ansible repair enum is invalid") from error
    if (
        evidence.reason.value != expected["reason"]
        or evidence.stable_id != expected["stable_id"]
        or evidence.host_id_digest != _digest_text(_text(expected["host_id"]))
        or evidence.pre_health_digest != expected["health_digest"]
        or evidence.source_result_digest != expected["source_result_digest"]
        or evidence.rbno_skip is not expected["rbno_skip"]
        or not set(evidence.blockers) <= _BLOCKERS
    ):
        raise AnsibleError("Ansible repair result conflicts")
    if evidence.status is ScyllaRepairStatus.COMPLETED and (
        evidence.mutation_boundary is not RepairMutationBoundary.POSTCHECKS_PASSED
        or evidence.post_health_digest is None
        or evidence.command_evidence != "exit-zero"
        or evidence.completion_evidence != "command-and-postchecks"
        or evidence.completion_cryptographically_proven
        or not evidence.explicit_review_required
        or evidence.recovery_required
        or evidence.blockers
    ):
        raise AnsibleError("Ansible repair completion evidence conflicts")
    if evidence.status is ScyllaRepairStatus.RBNO_SKIPPED and (
        not evidence.rbno_skip
        or evidence.mutation_boundary is not RepairMutationBoundary.NOT_STARTED
        or evidence.post_health_digest != evidence.pre_health_digest
        or evidence.command_evidence != "not-run"
        or evidence.completion_evidence != "rbno-enabled-complete"
        or not evidence.completion_cryptographically_proven
        or evidence.explicit_review_required
        or evidence.recovery_required
        or evidence.blockers
    ):
        raise AnsibleError("Ansible repair RBNO evidence conflicts")
    if evidence.status is ScyllaRepairStatus.FAILED and (
        not evidence.recovery_required or not evidence.blockers
    ):
        raise AnsibleError("Ansible repair failure evidence conflicts")
    if evidence.status is ScyllaRepairStatus.NOT_PREDICTED and (
        evidence.mutation_boundary is not RepairMutationBoundary.NOT_STARTED
        or evidence.post_health_digest is not None
        or evidence.command_evidence != "not-run"
        or evidence.recovery_required
        or evidence.blockers
    ):
        raise AnsibleError("Ansible repair check refusal conflicts")
    return evidence


def _source_result_digest(value: object) -> str:
    if isinstance(value, ScyllaReplaceDeadEvidence):
        projected = {
            "kind": "replacement",
            "post": value.post_evidence_digest,
            "repair_required": value.repair_required,
            "stable_id": value.stable_id,
            "status": value.status.value,
        }
    elif isinstance(value, ScyllaBootstrapEvidence):
        projected = {
            "kind": "bootstrap",
            "membership": value.ring_membership_digest,
            "mode": value.mode.value,
            "stable_id": value.target_logical_id,
            "status": value.status.value,
        }
    else:
        raise StateConflictError("repair source result type is unsupported")
    return _object_digest(projected)


def _result_object(value: ScyllaRepairEvidence) -> object:
    return {
        "blockers": list(value.blockers),
        "boundary": value.mutation_boundary.value,
        "reason": value.reason.value,
        "recovery": value.recovery_required,
        "stable_id": value.stable_id,
        "status": value.status.value,
    }


def _parse_recap(stdout: str) -> dict[str, tuple[int, int, int]]:
    _, marker, body = stdout.partition("PLAY RECAP")
    if not marker:
        raise AnsibleError("Ansible repair output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in body.splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible repair recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    return rows


def _object_digest(value: object) -> str:
    data = json.dumps(
        value, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _digest_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AnsibleError("repair evidence has duplicate fields")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise AnsibleError(f"invalid repair constant: {value}")


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible repair value is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible repair digest is invalid")
    return text


def _optional_digest(value: object) -> str | None:
    return None if value is None else _require_digest(value)


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError("Ansible repair boolean is invalid")
    return value


def _sorted_strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible repair blockers are invalid")
    values = tuple(_text(item) for item in value)
    if values != tuple(sorted(set(values))):
        raise AnsibleError("Ansible repair blockers are not sorted")
    return values
