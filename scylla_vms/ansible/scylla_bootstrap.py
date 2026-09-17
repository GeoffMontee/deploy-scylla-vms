"""Strict first-start and join-existing ScyllaDB bootstrap contracts."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.scylla_configure import (
    ScyllaConfigureEvidence,
    ScyllaConfigureStatus,
    ScyllaSeedPolicy,
)
from scylla_vms.ansible.scylla_install import (
    SCYLLA_RELEASE_LINE,
    ScyllaInstallEvidence,
    ScyllaInstallStatus,
)
from scylla_vms.ansible.storage_postcheck import StoragePostcheckEvidence
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.journal import (
    CheckpointEvidence,
    EvidenceResult,
    OperationPhase,
)
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata

SCYLLA_BOOTSTRAP_SCHEMA_VERSION = "deploy-scylla-vms.ansible-scylla-bootstrap/v1"

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_PACKAGE_VERSION = re.compile(
    r"2026\.2\.(?:0|[1-9][0-9]*)-0\.[0-9]{8}\.[0-9a-f]{12}-1\Z"
)
_MARKER = re.compile(r"DSV_SCYLLA_BOOTSTRAP_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_BLOCKERS = frozenset(
    {
        "execution-failed",
        "join-incomplete",
        "readiness-timeout",
        "ring-membership-conflict",
        "schema-disagreement",
        "streaming-incomplete",
    }
)


class ScyllaBootstrapMode(StrEnum):
    INITIAL_SEED = "initial-seed"
    JOIN_EXISTING = "join-existing"


class ScyllaBootstrapStatus(StrEnum):
    BOOTSTRAPPED = "bootstrapped"
    NOT_PREDICTED = "not-predicted"
    FAILED = "failed"


class MutationBoundary(StrEnum):
    NOT_REACHED = "not-reached"
    SERVICE_UNMASKED_STARTED = "service-unmasked-started"
    RING_MEMBERSHIP_MAY_HAVE_CHANGED = "ring-membership-may-have-changed"


@dataclass(frozen=True, slots=True)
class ScyllaBootstrapAuthorization:
    """Explicit reviewed topology evidence and mutation authorization."""

    operation_id: str
    mode: ScyllaBootstrapMode
    target_logical_id: str
    intent_digest: str
    authorization_digest: str
    reviewed: bool
    target_present_in_ring: bool
    existing_member_count: int
    live_cluster_state_absent: bool
    healthy_member_ids: tuple[str, ...]
    healthy_seed_ids: tuple[str, ...]
    capacity_check_passed: bool
    topology_check_passed: bool
    schema_agreement: bool
    config_file_digests: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class ScyllaBootstrapEvidence:
    mode: ScyllaBootstrapMode
    status: ScyllaBootstrapStatus
    target_logical_id: str
    service_state: str
    ring_membership_digest: str | None
    host_id_digest: str | None
    datacenter: str
    rack: str
    streaming_state: str
    prerequisite_digests: tuple[tuple[str, str], ...]
    mutation_boundary: MutationBoundary
    recovery_required: bool
    blockers: tuple[str, ...]
    schema_version: str = SCYLLA_BOOTSTRAP_SCHEMA_VERSION


def build_scylla_bootstrap_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    storage: StoragePostcheckEvidence,
    install: ScyllaInstallEvidence,
    configure: ScyllaConfigureEvidence,
    seed_policy: ScyllaSeedPolicy,
    authorization: ScyllaBootstrapAuthorization,
    *,
    package_version: str,
    bootstrap_timeout_seconds: int,
    cluster_spec_digest: str,
) -> dict[str, object]:
    """Build one explicit first-start or add/scale join intent."""

    logical_id = authorization.target_logical_id
    if (
        _LOGICAL_ID.fullmatch(logical_id) is None
        or _PACKAGE_VERSION.fullmatch(package_version) is None
        or not 1 <= bootstrap_timeout_seconds <= 86_400
    ):
        raise StateConflictError(
            "Scylla bootstrap target, version, or timeout is invalid"
        )
    host = next(
        (
            item
            for item in inventory.record.inventory.hosts
            if item.logical_id == logical_id and item.role.value == "scylla"
        ),
        None,
    )
    if host is None:
        raise StateConflictError("Scylla bootstrap target is not a Scylla stable ID")
    if (
        metadata.cluster_uuid != inventory.record.cluster_uuid
        or metadata.cluster_name != inventory.record.cluster_name
        or metadata.provider != inventory.record.provider
        or observed.record.cluster_uuid != inventory.record.cluster_uuid
        or observed.record.cluster_name != inventory.record.cluster_name
        or readiness.observation_generation != observed.record.generation
        or readiness.observation_digest != observed.digest
        or readiness.inventory_generation != inventory.record.generation
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_generation is None
        or readiness.trust_digest is None
    ):
        raise StateConflictError("Scylla bootstrap input provenance conflicts")
    if (
        storage.logical_id != logical_id
        or not storage.readiness_for_scylla
        or install.logical_id != logical_id
        or install.status
        not in {ScyllaInstallStatus.INSTALLED, ScyllaInstallStatus.NO_CHANGE}
        or install.installed_version != package_version
        or install.service_masked is not True
        or install.service_inactive is not True
        or configure.logical_id != logical_id
        or configure.status
        not in {ScyllaConfigureStatus.CHANGED, ScyllaConfigureStatus.NOOP}
        or configure.installed_version != package_version
        or configure.service_masked is not True
        or configure.service_inactive is not True
        or configure.seed_digest != seed_policy.digest
        or _object_digest(dict(authorization.config_file_digests))
        != configure.config_digest
    ):
        raise StateConflictError(
            "Scylla bootstrap requires current storage, install, and configure evidence"
        )
    _validate_authorization(
        authorization,
        seed_policy,
        {
            item.logical_id
            for item in inventory.record.inventory.hosts
            if item.role.value == "scylla"
        },
    )
    prerequisite_digests = {
        "authorization_digest": _require_digest(authorization.authorization_digest),
        "cluster_spec_digest": _require_digest(cluster_spec_digest),
        "config_digest": _require_digest(configure.config_digest),
        "install_digest": _object_digest(_install_object(install)),
        "inventory_digest": inventory.digest,
        "observation_digest": observed.digest,
        "seed_digest": _require_digest(configure.seed_digest),
        "storage_digest": _object_digest(_storage_object(storage)),
        "topology_digest": _require_digest(configure.topology_digest),
        "trust_digest": _require_digest(readiness.trust_digest),
    }
    return {
        "authorization": {
            "authorization_digest": authorization.authorization_digest,
            "capacity_check_passed": authorization.capacity_check_passed,
            "existing_member_count": authorization.existing_member_count,
            "healthy_member_ids": list(authorization.healthy_member_ids),
            "healthy_seed_ids": list(authorization.healthy_seed_ids),
            "intent_digest": authorization.intent_digest,
            "live_cluster_state_absent": authorization.live_cluster_state_absent,
            "reviewed": authorization.reviewed,
            "schema_agreement": authorization.schema_agreement,
            "target_present_in_ring": authorization.target_present_in_ring,
            "topology_check_passed": authorization.topology_check_passed,
        },
        "bootstrap_timeout_seconds": bootstrap_timeout_seconds,
        "cluster_uuid": str(metadata.cluster_uuid),
        "datacenter": host.scylla_datacenter,
        "logical_id": logical_id,
        "mode": authorization.mode.value,
        "operation_id": authorization.operation_id,
        "package_version": package_version,
        "config_file_digests": dict(authorization.config_file_digests),
        "prerequisite_digests": prerequisite_digests,
        "rack": host.scylla_rack,
        "release_line": SCYLLA_RELEASE_LINE,
        "schema_version": SCYLLA_BOOTSTRAP_SCHEMA_VERSION,
        "seed_stable_ids": list(seed_policy.stable_ids),
    }


def parse_scylla_bootstrap_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> ScyllaBootstrapEvidence:
    """Parse only strict address-free bootstrap evidence."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError("Ansible Scylla bootstrap output exceeds the evidence limit")
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_SCYLLA_BOOTSTRAP_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible Scylla bootstrap marker is malformed")
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible Scylla bootstrap marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible Scylla bootstrap evidence is malformed")
        values.append(value)
    logical_id = _text(expected_payload["logical_id"])
    rows = _parse_recap(stdout)
    if set(rows) != {logical_id}:
        raise AnsibleError("Ansible Scylla bootstrap recap membership conflicts")
    recap_failed = bool(rows[logical_id][1] or rows[logical_id][2])
    if len(values) != 1:
        raise AnsibleError(
            "Ansible Scylla bootstrap evidence is incomplete or duplicated"
        )
    evidence = _parse_result(values[0], expected_payload)
    if evidence.status is ScyllaBootstrapStatus.NOT_PREDICTED:
        if not recap_failed or exit_code == 0 or rows[logical_id][0]:
            raise AnsibleError("Ansible Scylla bootstrap check refusal conflicts")
        return evidence
    failed = evidence.status is ScyllaBootstrapStatus.FAILED
    if recap_failed != failed or (exit_code == 0) == failed:
        raise AnsibleError("Ansible Scylla bootstrap exit status conflicts")
    if bool(rows[logical_id][0]) != (
        evidence.mutation_boundary is not MutationBoundary.NOT_REACHED
    ):
        raise AnsibleError("Ansible Scylla bootstrap mutation status conflicts")
    return evidence


def bootstrap_checkpoint_evidence(
    evidence: ScyllaBootstrapEvidence,
) -> CheckpointEvidence:
    """Project the mutation boundary into bounded operation-journal evidence."""

    if evidence.status is ScyllaBootstrapStatus.NOT_PREDICTED:
        raise StateConflictError(
            "check-mode refusal is not bootstrap execution evidence"
        )
    if evidence.status is ScyllaBootstrapStatus.BOOTSTRAPPED:
        result = EvidenceResult.COMPLETED
        summary = "scylla-bootstrap-complete"
    else:
        result = EvidenceResult.FAILED
        summary = (
            "scylla-membership-may-have-changed"
            if evidence.mutation_boundary
            is MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED
            else "scylla-start-failed-before-membership"
        )
    digest = _object_digest(
        {
            "blockers": list(evidence.blockers),
            "host_id_digest": evidence.host_id_digest,
            "mode": evidence.mode.value,
            "mutation_boundary": evidence.mutation_boundary.value,
            "prerequisite_digests": dict(evidence.prerequisite_digests),
            "recovery_required": evidence.recovery_required,
            "ring_membership_digest": evidence.ring_membership_digest,
            "status": evidence.status.value,
            "target_logical_id": evidence.target_logical_id,
        }
    )
    return CheckpointEvidence(OperationPhase.EXECUTE, result, digest, summary)


def _validate_authorization(
    value: ScyllaBootstrapAuthorization,
    seeds: ScyllaSeedPolicy,
    inventory_ids: set[str],
) -> None:
    if (
        not value.operation_id
        or len(value.operation_id) > 128
        or not value.reviewed
        or value.target_present_in_ring
        or value.healthy_member_ids != tuple(sorted(set(value.healthy_member_ids)))
        or value.healthy_seed_ids != tuple(sorted(set(value.healthy_seed_ids)))
        or not set(value.healthy_seed_ids) <= set(value.healthy_member_ids)
        or not set(value.healthy_member_ids) <= inventory_ids
        or value.target_logical_id in value.healthy_member_ids
        or _require_digest(value.intent_digest) != value.intent_digest
        or _require_digest(value.authorization_digest) != value.authorization_digest
        or tuple(name for name, _ in value.config_file_digests)
        != ("cassandra-rackdc.properties", "scylla.yaml")
        or any(_require_digest(item) != item for _, item in value.config_file_digests)
    ):
        raise StateConflictError("Scylla bootstrap authorization is invalid")
    if value.mode is ScyllaBootstrapMode.INITIAL_SEED:
        if (
            value.existing_member_count != 0
            or not value.live_cluster_state_absent
            or value.healthy_member_ids
            or value.healthy_seed_ids
            or seeds.stable_ids != (value.target_logical_id,)
        ):
            raise StateConflictError(
                "initial-seed requires reviewed empty-cluster evidence and exact seed"
            )
    elif (
        value.existing_member_count < 1
        or value.live_cluster_state_absent
        or not value.healthy_member_ids
        or not value.healthy_seed_ids
        or not value.capacity_check_passed
        or not value.topology_check_passed
        or not value.schema_agreement
        or value.target_logical_id in seeds.stable_ids
        or not set(seeds.stable_ids) <= set(value.healthy_seed_ids)
    ):
        raise StateConflictError(
            "join-existing requires healthy members, capacity, topology, and add intent"
        )


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> ScyllaBootstrapEvidence:
    fields = {
        "blockers",
        "datacenter",
        "host_id_digest",
        "mode",
        "mutation_boundary",
        "prerequisite_digests",
        "rack",
        "recovery_required",
        "ring_membership_digest",
        "schema_version",
        "service_state",
        "status",
        "streaming_state",
        "target_logical_id",
    }
    if (
        set(value) != fields
        or value["schema_version"] != SCYLLA_BOOTSTRAP_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible Scylla bootstrap evidence schema is invalid")
    try:
        mode = ScyllaBootstrapMode(_text(value["mode"]))
        status = ScyllaBootstrapStatus(_text(value["status"]))
        boundary = MutationBoundary(_text(value["mutation_boundary"]))
    except ValueError as error:
        raise AnsibleError("Ansible Scylla bootstrap enum is invalid") from error
    logical_id = _text(value["target_logical_id"])
    datacenter = _text(value["datacenter"])
    rack = _text(value["rack"])
    service_state = _text(value["service_state"])
    streaming_state = _text(value["streaming_state"])
    ring_digest = _optional_digest(value["ring_membership_digest"])
    host_id_digest = _optional_digest(value["host_id_digest"])
    blockers = _sorted_strings(value["blockers"])
    recovery_required = value["recovery_required"]
    expected_digests = cast(dict[str, object], expected["prerequisite_digests"])
    actual_digests = value["prerequisite_digests"]
    if (
        mode.value != expected["mode"]
        or logical_id != expected["logical_id"]
        or datacenter != expected["datacenter"]
        or rack != expected["rack"]
        or not isinstance(actual_digests, dict)
        or actual_digests != expected_digests
        or not isinstance(recovery_required, bool)
        or not set(blockers) <= _BLOCKERS
    ):
        raise AnsibleError("Ansible Scylla bootstrap evidence conflicts")
    prerequisite_digests = tuple(
        sorted(
            (_text(name), _require_digest(item))
            for name, item in actual_digests.items()
        )
    )
    if status is ScyllaBootstrapStatus.BOOTSTRAPPED and (
        service_state != "active"
        or streaming_state != "complete"
        or ring_digest is None
        or host_id_digest is None
        or boundary is not MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED
        or recovery_required
        or blockers
    ):
        raise AnsibleError("Ansible Scylla bootstrap success evidence conflicts")
    if status is ScyllaBootstrapStatus.NOT_PREDICTED and (
        service_state != "not-checked"
        or streaming_state != "not-checked"
        or ring_digest is not None
        or host_id_digest is not None
        or boundary is not MutationBoundary.NOT_REACHED
        or recovery_required
        or blockers
    ):
        raise AnsibleError("Ansible Scylla bootstrap check evidence conflicts")
    if status is ScyllaBootstrapStatus.FAILED and (
        boundary is MutationBoundary.NOT_REACHED
        or not recovery_required
        or not blockers
    ):
        raise AnsibleError("Ansible Scylla bootstrap failure evidence conflicts")
    return ScyllaBootstrapEvidence(
        mode,
        status,
        logical_id,
        service_state,
        ring_digest,
        host_id_digest,
        datacenter,
        rack,
        streaming_state,
        prerequisite_digests,
        boundary,
        recovery_required,
        blockers,
    )


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


def _install_object(value: ScyllaInstallEvidence) -> object:
    return {
        "blockers": list(value.blockers),
        "installed_edition": value.installed_edition,
        "installed_version": value.installed_version,
        "logical_id": value.logical_id,
        "packages": dict(value.packages),
        "provenance": dict(value.provenance),
        "repository_digest": value.repository_digest,
        "requested_edition": value.requested_edition,
        "requested_version": value.requested_version,
        "service_inactive": value.service_inactive,
        "service_masked": value.service_masked,
        "status": value.status.value,
    }


def _object_digest(value: object) -> str:
    data = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _parse_recap(stdout: str) -> dict[str, tuple[int, int, int]]:
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible Scylla bootstrap output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible Scylla bootstrap recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    return rows


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AnsibleError("Ansible Scylla bootstrap evidence has duplicate fields")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise AnsibleError(f"invalid Scylla bootstrap constant: {value}")


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible Scylla bootstrap value is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible Scylla bootstrap digest is invalid")
    return text


def _optional_digest(value: object) -> str | None:
    return None if value is None else _require_digest(value)


def _sorted_strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible Scylla bootstrap blockers are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError("Ansible Scylla bootstrap blockers are not uniquely sorted")
    return items
