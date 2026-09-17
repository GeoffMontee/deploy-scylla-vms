"""Strict ScyllaDB 2026.2 dead-node replacement contracts."""

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
from scylla_vms.ansible.scylla_configure import (
    ScyllaConfigureEvidence,
    ScyllaConfigureStatus,
)
from scylla_vms.ansible.scylla_health import HealthReadiness, ScyllaHealthEvidence
from scylla_vms.ansible.scylla_install import (
    ScyllaInstallEvidence,
    ScyllaInstallStatus,
)
from scylla_vms.ansible.scylla_remove_dead import (
    ReachabilityStatus,
    SurvivorRingView,
)
from scylla_vms.ansible.scylla_remove_live import (
    SafetyCheckStatus,
    ScyllaRemovalSafetyEvidence,
    scylla_health_evidence_digest,
)
from scylla_vms.ansible.storage_postcheck import StoragePostcheckEvidence
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.journal import CheckpointEvidence, EvidenceResult, OperationPhase
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata, parse_timestamp

SCYLLA_REPLACE_DEAD_SCHEMA_VERSION = "deploy-scylla-vms.ansible-scylla-replace-dead/v1"
SCYLLA_REPLACE_DEAD_TARGET_SCHEMA_VERSION = (
    "deploy-scylla-vms.scylla-replace-dead-target/v1"
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_PACKAGE_VERSION = re.compile(
    r"2026\.2\.(?:0|[1-9][0-9]*)-0\.[0-9]{8}\.[0-9a-f]{12}-1\Z"
)
_MARKER = re.compile(r"DSV_SCYLLA_REPLACE_DEAD_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_BLOCKERS = frozenset(
    {
        "execution-interrupted",
        "key-write-failed",
        "postcondition-disagreement",
        "replacement-timeout",
        "revalidation-failed",
        "service-start-failed",
    }
)
_POSTCONDITIONS = (
    "expected-topology",
    "new-host-id",
    "no-streaming",
    "old-host-id-absent",
    "replacement-up-normal",
    "schema-agreement",
)


class ScyllaReplaceDeadStatus(StrEnum):
    REPLACED = "replaced"
    FAILED = "failed"
    NOT_PREDICTED = "not-predicted"


class ReplacementMutationBoundary(StrEnum):
    NOT_STARTED = "not-started"
    KEY_WRITTEN = "key-written"
    SERVICE_STARTED = "service-started"
    MEMBERSHIP_MAY_HAVE_CHANGED = "membership-may-have-changed"
    MEMBERSHIP_PROVEN = "membership-proven"


@dataclass(frozen=True, slots=True)
class ReplacementTargetEvidence:
    captured_at: str
    stable_id: str
    old_host_id: str
    old_provider_id: str
    new_provider_id: str
    ssh_reachability: ReachabilityStatus
    service_reachability: ReachabilityStatus
    provider_lifecycle_reachability: ReachabilityStatus
    survivor_views: tuple[SurvivorRingView, ...]
    mapping_reviewed: bool
    replacement_absent_from_ring: bool
    active_topology_operation: str | None = None
    removenode_status: str = "not-started"
    schema_version: str = SCYLLA_REPLACE_DEAD_TARGET_SCHEMA_VERSION

    def validate(self, survivors: tuple[str, ...]) -> None:
        parse_timestamp(self.captured_at)
        if (
            self.schema_version != SCYLLA_REPLACE_DEAD_TARGET_SCHEMA_VERSION
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or str(uuid.UUID(self.old_host_id)) != self.old_host_id
            or not self.old_provider_id
            or not self.new_provider_id
            or self.old_provider_id == self.new_provider_id
            or not self.mapping_reviewed
            or not self.replacement_absent_from_ring
            or self.active_topology_operation is not None
            or self.removenode_status != "not-started"
            or any(
                value is not ReachabilityStatus.UNREACHABLE
                for value in (
                    self.ssh_reachability,
                    self.service_reachability,
                    self.provider_lifecycle_reachability,
                )
            )
            or tuple(view.stable_id for view in self.survivor_views) != survivors
            or not self.survivor_views
        ):
            raise StateConflictError("dead replacement target evidence is unsafe")
        for view in self.survivor_views:
            view.validate()
        if (
            any(view.target_host_id != self.old_host_id for view in self.survivor_views)
            or len({view.ring_digest for view in self.survivor_views}) != 1
        ):
            raise StateConflictError("survivors disagree about the dead Host ID")


@dataclass(frozen=True, slots=True)
class RepairBasedNodeOperationsEvidence:
    enabled: bool
    replacement_complete: bool
    evidence_digest: str

    def validate(self) -> None:
        _require_digest(self.evidence_digest)
        if self.replacement_complete and not self.enabled:
            raise StateConflictError("RBNO completion requires RBNO to be enabled")


@dataclass(frozen=True, slots=True)
class ScyllaReplaceDeadAuthorization:
    operation_id: str
    cluster_uuid: str
    stable_id: str
    old_host_id: str
    old_provider_id: str
    new_provider_id: str
    observation_digest: str
    inventory_digest: str
    trust_digest: str
    storage_digest: str
    config_digest: str
    health_digest: str
    topology_digest: str
    intended_post_state_digest: str
    authorization_digest: str
    config_file_digests: tuple[tuple[str, str], ...]
    confirmed_target: str
    allow_destructive: bool
    reviewed: bool
    prior_key_written: bool = False
    prior_service_started: bool = False


@dataclass(frozen=True, slots=True)
class ScyllaReplaceDeadEvidence:
    status: ScyllaReplaceDeadStatus
    stable_id: str
    old_provider_id_digest: str
    new_provider_id_digest: str
    old_host_id_digest: str
    new_host_id_digest: str | None
    pre_evidence_digest: str
    post_evidence_digest: str | None
    config_digest: str
    storage_digest: str
    topology_digest: str
    intended_post_state_digest: str
    mutation_boundary: ReplacementMutationBoundary
    streaming_status: str
    ring_status: str
    replacement_key_retained: bool
    repair_required: bool
    rbno_status: str
    postconditions: tuple[tuple[str, SafetyCheckStatus], ...]
    recovery_required: bool
    blockers: tuple[str, ...]
    schema_version: str = SCYLLA_REPLACE_DEAD_SCHEMA_VERSION


def build_scylla_replace_dead_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    survivor_health: ScyllaHealthEvidence,
    target: ReplacementTargetEvidence,
    safety: ScyllaRemovalSafetyEvidence,
    storage: StoragePostcheckEvidence,
    install: ScyllaInstallEvidence,
    configure: ScyllaConfigureEvidence,
    rbno: RepairBasedNodeOperationsEvidence,
    authorization: ScyllaReplaceDeadAuthorization,
    *,
    package_version: str,
    timeout_seconds: int,
) -> dict[str, object]:
    """Build an exact one-target 2026.2 replacement request."""

    if (
        _PACKAGE_VERSION.fullmatch(package_version) is None
        or not 60 <= timeout_seconds <= 86_400
    ):
        raise StateConflictError("Scylla replacement version or timeout is invalid")
    scylla_hosts = {
        host.logical_id: host
        for host in inventory.record.inventory.hosts
        if host.role.value == "scylla"
    }
    replacement = scylla_hosts.get(authorization.stable_id)
    survivors = tuple(sorted(set(scylla_hosts) - {authorization.stable_id}))
    if replacement is None or not survivors:
        raise StateConflictError("dead replacement requires target and survivors")
    if (
        metadata.cluster_uuid != inventory.record.cluster_uuid
        or observed.record.cluster_uuid != inventory.record.cluster_uuid
        or readiness.observation_digest != observed.digest
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_digest is None
        or observed.record.generation != inventory.record.source_manifest_generation
    ):
        raise StateConflictError("Scylla replacement provenance conflicts")
    health_digest = scylla_health_evidence_digest(survivor_health)
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
    ):
        raise StateConflictError("replacement requires healthy survivor evidence")
    target.validate(survivors)
    if (
        target.captured_at != survivor_health.captured_at_end
        or target.stable_id != replacement.logical_id
        or target.new_provider_id != replacement.provider_id
        or len(target.survivor_views) < (len(survivors) // 2 + 1)
        or not set(view.stable_id for view in target.survivor_views) <= set(survivors)
    ):
        raise StateConflictError("dead replacement identity or quorum conflicts")
    safety.validate()
    if (
        safety.health_digest != health_digest
        or safety.surviving_stable_ids != survivors
        or safety.intended_post_topology_digest
        != authorization.intended_post_state_digest
        or any(
            value is not SafetyCheckStatus.PASSED
            for value in (
                safety.replication,
                safety.quorum,
                safety.capacity,
                safety.backup_policy,
            )
        )
    ):
        raise StateConflictError("replacement safety evidence is incomplete")
    if (
        storage.logical_id != replacement.logical_id
        or not storage.readiness_for_scylla
        or storage.blockers
        or install.logical_id != replacement.logical_id
        or install.status
        not in {ScyllaInstallStatus.INSTALLED, ScyllaInstallStatus.NO_CHANGE}
        or install.installed_version != package_version
        or not install.service_masked
        or not install.service_inactive
        or configure.logical_id != replacement.logical_id
        or configure.status
        not in {ScyllaConfigureStatus.CHANGED, ScyllaConfigureStatus.NOOP}
        or configure.installed_version != package_version
        or not configure.service_masked
        or not configure.service_inactive
    ):
        raise StateConflictError(
            "replacement requires exact empty storage, package, and configuration"
        )
    rbno.validate()
    storage_digest = _object_digest(_storage_object(storage))
    _validate_authorization(
        metadata,
        observed,
        inventory,
        readiness,
        target,
        health_digest,
        storage_digest,
        configure,
        authorization,
    )
    expected_survivors = [
        {
            "datacenter": node.datacenter,
            "host_id": node.host_id,
            "rack": node.rack,
            "state": "UN",
        }
        for node in survivor_health.nodes
    ]
    pre_digest = _object_digest(
        {
            "health": health_digest,
            "old_host_id": target.old_host_id,
            "old_provider_id": target.old_provider_id,
            "new_provider_id": target.new_provider_id,
            "storage": storage_digest,
            "config": configure.config_digest,
            "topology": authorization.topology_digest,
        }
    )
    return {
        "authorization": {
            "authorization_digest": authorization.authorization_digest,
            "reviewed": authorization.reviewed,
        },
        "cluster_uuid": str(metadata.cluster_uuid),
        "config_digest": configure.config_digest,
        "config_file_digests": dict(authorization.config_file_digests),
        "datacenter": replacement.scylla_datacenter,
        "expected_survivors": expected_survivors,
        "intended_post_state_digest": authorization.intended_post_state_digest,
        "new_provider_id_digest": _digest_text(target.new_provider_id),
        "old_host_id": target.old_host_id,
        "old_provider_id_digest": _digest_text(target.old_provider_id),
        "operation_id": authorization.operation_id,
        "package_version": package_version,
        "pre_evidence_digest": pre_digest,
        "rack": replacement.scylla_rack,
        "rbno": {
            "complete": rbno.replacement_complete,
            "digest": rbno.evidence_digest,
            "enabled": rbno.enabled,
        },
        "release_line": "2026.2",
        "repair_required": not (rbno.enabled and rbno.replacement_complete),
        "required_survivor_quorum": [view.stable_id for view in target.survivor_views],
        "schema_version": SCYLLA_REPLACE_DEAD_SCHEMA_VERSION,
        "stable_id": replacement.logical_id,
        "storage_digest": storage_digest,
        "timeout_seconds": timeout_seconds,
        "topology_digest": authorization.topology_digest,
    }


def _validate_authorization(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    target: ReplacementTargetEvidence,
    health_digest: str,
    storage_digest: str,
    configure: ScyllaConfigureEvidence,
    value: ScyllaReplaceDeadAuthorization,
) -> None:
    try:
        valid_uuids = (
            str(uuid.UUID(value.operation_id)) == value.operation_id
            and str(uuid.UUID(value.cluster_uuid)) == value.cluster_uuid
            and str(uuid.UUID(value.old_host_id)) == value.old_host_id
        )
    except ValueError:
        valid_uuids = False
    if (
        not valid_uuids
        or value.cluster_uuid != str(metadata.cluster_uuid)
        or value.stable_id != target.stable_id
        or value.old_host_id != target.old_host_id
        or value.old_provider_id != target.old_provider_id
        or value.new_provider_id != target.new_provider_id
        or value.observation_digest != observed.digest
        or value.inventory_digest != inventory.digest
        or value.trust_digest != readiness.trust_digest
        or value.storage_digest != storage_digest
        or value.config_digest != configure.config_digest
        or tuple(name for name, _ in value.config_file_digests)
        != ("cassandra-rackdc.properties", "scylla.yaml")
        or any(_require_digest(item) != item for _, item in value.config_file_digests)
        or _object_digest(dict(value.config_file_digests)) != configure.config_digest
        or value.health_digest != health_digest
        or value.confirmed_target != value.stable_id
        or not value.allow_destructive
        or not value.reviewed
        or value.prior_key_written
        or value.prior_service_started
    ):
        raise StateConflictError(
            "replacement authorization does not bind the exact transition"
        )
    for digest in (
        value.observation_digest,
        value.inventory_digest,
        value.trust_digest,
        value.storage_digest,
        value.config_digest,
        value.health_digest,
        value.topology_digest,
        value.intended_post_state_digest,
        value.authorization_digest,
    ):
        _require_digest(digest)


def parse_scylla_replace_dead_execution(
    stdout: str, *, expected_payload: dict[str, object], exit_code: int
) -> ScyllaReplaceDeadEvidence:
    """Parse only strict address-free replacement evidence."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError("Ansible replacement output exceeds the limit")
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_SCYLLA_REPLACE_DEAD_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible replacement marker is malformed")
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            item = json.loads(
                decoded.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError("Ansible replacement marker is malformed") from error
        if not isinstance(item, dict):
            raise AnsibleError("Ansible replacement evidence is malformed")
        values.append(item)
    stable_id = _text(expected_payload["stable_id"])
    recap = _parse_recap(stdout)
    if set(recap) != {stable_id} or len(values) != 1:
        raise AnsibleError("Ansible replacement evidence is incomplete")
    evidence = _parse_result(values[0], expected_payload)
    changed, unreachable, failed = recap[stable_id]
    result_failed = evidence.status is not ScyllaReplaceDeadStatus.REPLACED
    if bool(unreachable or failed) != result_failed or (exit_code == 0) != (
        not result_failed
    ):
        raise AnsibleError("Ansible replacement exit status conflicts")
    if bool(changed) != (
        evidence.mutation_boundary is not ReplacementMutationBoundary.NOT_STARTED
    ):
        raise AnsibleError("Ansible replacement mutation status conflicts")
    return evidence


def scylla_replace_dead_interrupted_evidence(
    payload: dict[str, object],
) -> ScyllaReplaceDeadEvidence:
    return ScyllaReplaceDeadEvidence(
        ScyllaReplaceDeadStatus.FAILED,
        _text(payload["stable_id"]),
        _require_digest(payload["old_provider_id_digest"]),
        _require_digest(payload["new_provider_id_digest"]),
        _digest_text(_text(payload["old_host_id"])),
        None,
        _require_digest(payload["pre_evidence_digest"]),
        None,
        _require_digest(payload["config_digest"]),
        _require_digest(payload["storage_digest"]),
        _require_digest(payload["topology_digest"]),
        _require_digest(payload["intended_post_state_digest"]),
        ReplacementMutationBoundary.MEMBERSHIP_MAY_HAVE_CHANGED,
        "unknown",
        "unknown",
        True,
        _boolean(payload["repair_required"]),
        _rbno_status(payload),
        tuple((name, SafetyCheckStatus.UNKNOWN) for name in _POSTCONDITIONS),
        True,
        ("execution-interrupted",),
    )


def scylla_replace_dead_checkpoint_evidence(
    evidence: ScyllaReplaceDeadEvidence,
) -> CheckpointEvidence:
    if evidence.status is ScyllaReplaceDeadStatus.NOT_PREDICTED:
        raise StateConflictError("check refusal is not replacement execution evidence")
    completed = evidence.status is ScyllaReplaceDeadStatus.REPLACED
    summary = (
        "scylla-replacement-membership-proven"
        if completed and not evidence.repair_required
        else "scylla-replacement-repair-required"
        if completed
        else "scylla-replacement-recovery-required"
        if evidence.mutation_boundary is not ReplacementMutationBoundary.NOT_STARTED
        else "scylla-replacement-refused"
    )
    return CheckpointEvidence(
        OperationPhase.EXECUTE,
        EvidenceResult.COMPLETED if completed else EvidenceResult.FAILED,
        _object_digest(_result_object(evidence)),
        summary,
    )


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> ScyllaReplaceDeadEvidence:
    fields = {
        "blockers",
        "config_digest",
        "intended_post_state_digest",
        "mutation_boundary",
        "new_host_id_digest",
        "new_provider_id_digest",
        "old_host_id_digest",
        "old_provider_id_digest",
        "post_evidence_digest",
        "postconditions",
        "pre_evidence_digest",
        "rbno_status",
        "recovery_required",
        "repair_required",
        "replacement_key_retained",
        "ring_status",
        "schema_version",
        "stable_id",
        "status",
        "storage_digest",
        "streaming_status",
        "topology_digest",
    }
    if (
        set(value) != fields
        or value["schema_version"] != SCYLLA_REPLACE_DEAD_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible replacement result schema is invalid")
    try:
        status = ScyllaReplaceDeadStatus(_text(value["status"]))
        boundary = ReplacementMutationBoundary(_text(value["mutation_boundary"]))
    except ValueError as error:
        raise AnsibleError("Ansible replacement enum is invalid") from error
    evidence = ScyllaReplaceDeadEvidence(
        status,
        _text(value["stable_id"]),
        _require_digest(value["old_provider_id_digest"]),
        _require_digest(value["new_provider_id_digest"]),
        _require_digest(value["old_host_id_digest"]),
        _optional_digest(value["new_host_id_digest"]),
        _require_digest(value["pre_evidence_digest"]),
        _optional_digest(value["post_evidence_digest"]),
        _require_digest(value["config_digest"]),
        _require_digest(value["storage_digest"]),
        _require_digest(value["topology_digest"]),
        _require_digest(value["intended_post_state_digest"]),
        boundary,
        _text(value["streaming_status"]),
        _text(value["ring_status"]),
        _boolean(value["replacement_key_retained"]),
        _boolean(value["repair_required"]),
        _text(value["rbno_status"]),
        _postconditions(value["postconditions"]),
        _boolean(value["recovery_required"]),
        _sorted_strings(value["blockers"]),
    )
    if (
        evidence.stable_id != expected["stable_id"]
        or evidence.old_provider_id_digest != expected["old_provider_id_digest"]
        or evidence.new_provider_id_digest != expected["new_provider_id_digest"]
        or evidence.old_host_id_digest != _digest_text(_text(expected["old_host_id"]))
        or evidence.pre_evidence_digest != expected["pre_evidence_digest"]
        or evidence.config_digest != expected["config_digest"]
        or evidence.storage_digest != expected["storage_digest"]
        or evidence.topology_digest != expected["topology_digest"]
        or evidence.intended_post_state_digest != expected["intended_post_state_digest"]
        or evidence.repair_required is not expected["repair_required"]
        or evidence.rbno_status != _rbno_status(expected)
        or not set(evidence.blockers) <= _BLOCKERS
    ):
        raise AnsibleError("Ansible replacement result conflicts")
    passed = all(
        item is SafetyCheckStatus.PASSED for _, item in evidence.postconditions
    )
    if status is ScyllaReplaceDeadStatus.REPLACED and (
        boundary is not ReplacementMutationBoundary.MEMBERSHIP_PROVEN
        or evidence.new_host_id_digest is None
        or evidence.new_host_id_digest == evidence.old_host_id_digest
        or evidence.post_evidence_digest is None
        or evidence.streaming_status != "complete"
        or evidence.ring_status != "UN"
        or not evidence.replacement_key_retained
        or not passed
        or evidence.recovery_required
        or evidence.blockers
    ):
        raise AnsibleError("Ansible replacement success evidence conflicts")
    if status is ScyllaReplaceDeadStatus.FAILED and (
        not evidence.recovery_required or not evidence.blockers
    ):
        raise AnsibleError("Ansible replacement failure evidence conflicts")
    if status is ScyllaReplaceDeadStatus.NOT_PREDICTED and (
        boundary is not ReplacementMutationBoundary.NOT_STARTED
        or evidence.new_host_id_digest is not None
        or evidence.post_evidence_digest is not None
        or evidence.streaming_status != "not-checked"
        or evidence.ring_status != "not-checked"
        or evidence.replacement_key_retained
        or evidence.recovery_required
        or evidence.blockers
        or any(
            item is not SafetyCheckStatus.NOT_PERFORMED
            for _, item in evidence.postconditions
        )
    ):
        raise AnsibleError("Ansible replacement check refusal conflicts")
    return evidence


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


def _rbno_status(payload: dict[str, object]) -> str:
    rbno = cast(dict[str, object], payload["rbno"])
    return (
        "enabled-complete"
        if rbno.get("enabled") is True and rbno.get("complete") is True
        else "repair-required"
    )


def _result_object(value: ScyllaReplaceDeadEvidence) -> object:
    return {
        "blockers": list(value.blockers),
        "mutation_boundary": value.mutation_boundary.value,
        "post_evidence_digest": value.post_evidence_digest,
        "pre_evidence_digest": value.pre_evidence_digest,
        "recovery_required": value.recovery_required,
        "repair_required": value.repair_required,
        "stable_id": value.stable_id,
        "status": value.status.value,
    }


def _postconditions(value: object) -> tuple[tuple[str, SafetyCheckStatus], ...]:
    if not isinstance(value, dict) or tuple(sorted(value)) != _POSTCONDITIONS:
        raise AnsibleError("Scylla replacement postconditions are invalid")
    try:
        return tuple(
            (name, SafetyCheckStatus(_text(value[name]))) for name in _POSTCONDITIONS
        )
    except ValueError as error:
        raise AnsibleError(
            "Scylla replacement postcondition status is invalid"
        ) from error


def _parse_recap(stdout: str) -> dict[str, tuple[int, int, int]]:
    _, marker, body = stdout.partition("PLAY RECAP")
    if not marker:
        raise AnsibleError("Ansible replacement output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in body.splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible replacement recap is malformed")
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
            raise AnsibleError("replacement evidence has duplicate fields")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise AnsibleError(f"invalid replacement constant: {value}")


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible replacement value is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible replacement digest is invalid")
    return text


def _optional_digest(value: object) -> str | None:
    return None if value is None else _require_digest(value)


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError("Ansible replacement boolean is invalid")
    return value


def _sorted_strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible replacement blockers are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError("Ansible replacement blockers are not sorted")
    return items
