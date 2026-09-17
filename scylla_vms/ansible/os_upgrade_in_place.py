"""Fail-closed in-place OS-upgrade validation without host mutation."""

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

from scylla_vms.ansible.base_os import BaseOsEvidence
from scylla_vms.ansible.os_upgrade_preflight import (
    HOST_GATE_NAMES,
    OS_UPGRADE_PREFLIGHT_SCHEMA_VERSION,
    GateStatus,
    OsUpgradePreflightEvidence,
    OsUpgradePreflightIntent,
    OsUpgradePreflightPrerequisites,
    OsUpgradePreflightStatus,
    TransitionClassification,
    build_os_upgrade_preflight_payload,
)
from scylla_vms.ansible.os_upgrade_preflight import (
    NOT_PERFORMED as PREFLIGHT_NOT_PERFORMED,
)
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.desired import HostRole, ImageFilter
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata

OS_UPGRADE_IN_PLACE_SCHEMA_VERSION = "deploy-scylla-vms.ansible-os-upgrade-in-place/v1"
CURRENT_OPERATING_SYSTEM = "Ubuntu"
CURRENT_OPERATING_SYSTEM_VERSION = "24.04"
SUPPORTED_ARCHITECTURES = ("aarch64", "amd64")
MUTATION_BOUNDARY = "not-started"
ACTION_NOT_PERFORMED = "not-performed"
NOT_PERFORMED = (
    "apt-full-upgrade",
    "apt-update",
    "apt-upgrade",
    "automatic-retry",
    "configuration-write",
    "do-release-upgrade",
    "kernel-modification",
    "nodetool-drain",
    "package-mutation",
    "package-source-modification",
    "reboot",
    "service-start",
    "service-stop",
    "service-unmask",
    "storage-mutation",
    "terraform",
    "vm-replacement",
)
_ACTION_FIELDS = (
    "configuration_action",
    "kernel_action",
    "package_action",
    "reboot_action",
    "service_action",
    "source_action",
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MARKER = re.compile(r"DSV_OS_UPGRADE_IN_PLACE_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_FAILURE_BLOCKERS = frozenset(
    {
        "execution-failed",
        "host-unreachable",
    }
)
_ELIGIBLE_PREFLIGHT_BLOCKERS = (
    "kernel-policy-undefined",
    "package-currency-not-performed",
    "repository-inspection-not-performed",
    "target-transition-unsupported",
)


class OsUpgradeInPlaceStatus(StrEnum):
    BLOCKED = "blocked"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class OsUpgradeInPlaceAuthorization:
    """Narrow sensitive approval bound to one exact blocked upgrade request."""

    operation_id: str
    cluster_uuid: str
    logical_id: str
    role: HostRole
    current_operating_system: str
    current_operating_system_version: str
    target_operating_system: str
    target_operating_system_version: str
    architecture: str
    preflight_digest: str
    observation_digest: str
    inventory_digest: str
    trust_digest: str
    allow_sensitive: bool
    reviewed: bool
    no_competing_operation: bool
    authorization_digest: str


@dataclass(frozen=True, slots=True)
class OsUpgradeInPlaceEvidence:
    logical_id: str
    role: HostRole
    status: OsUpgradeInPlaceStatus
    transition_classification: str
    current_operating_system: str
    current_operating_system_version: str
    target_operating_system: str
    target_operating_system_version: str
    architecture: str
    applied: bool
    package_action: str
    source_action: str
    service_action: str
    reboot_action: str
    kernel_action: str
    configuration_action: str
    automatic_retry: bool
    mutation_boundary: str
    recovery_required: bool
    not_performed: tuple[str, ...]
    provenance: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]
    schema_version: str = OS_UPGRADE_IN_PLACE_SCHEMA_VERSION


def os_upgrade_preflight_evidence_digest(
    evidence: OsUpgradePreflightEvidence,
) -> str:
    """Bind the strict preflight projection without raw Ansible output."""

    return _object_digest(_preflight_object(evidence))


def build_os_upgrade_in_place_authorization(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    preflight: OsUpgradePreflightEvidence,
    *,
    operation_id: str,
    allow_sensitive: bool = True,
    reviewed: bool = True,
    no_competing_operation: bool = True,
) -> OsUpgradeInPlaceAuthorization:
    """Build exact authorization for validation of one in-place request."""

    if not _valid_uuid(operation_id):
        raise AnsibleError("OS-upgrade in-place operation ID is invalid")
    if (
        metadata.cluster_uuid != inventory.record.cluster_uuid
        or metadata.cluster_name != inventory.record.cluster_name
        or metadata.provider != inventory.record.provider
        or observed.record.cluster_uuid != inventory.record.cluster_uuid
        or readiness.observation_generation != observed.record.generation
        or readiness.observation_digest != observed.digest
        or readiness.inventory_generation != inventory.record.generation
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_generation is None
        or readiness.trust_digest is None
    ):
        raise StateConflictError(
            "OS-upgrade in-place authorization provenance conflicts"
        )
    if not allow_sensitive or not reviewed or not no_competing_operation:
        raise StateConflictError(
            "OS-upgrade in-place authorization requires explicit reviewed approval"
        )
    preflight_digest = os_upgrade_preflight_evidence_digest(preflight)
    values = {
        "allow_sensitive": allow_sensitive,
        "architecture": preflight.architecture,
        "cluster_uuid": str(metadata.cluster_uuid),
        "current_operating_system": preflight.current_operating_system,
        "current_operating_system_version": preflight.current_operating_system_version,
        "inventory_digest": inventory.digest,
        "logical_id": preflight.logical_id,
        "no_competing_operation": no_competing_operation,
        "observation_digest": observed.digest,
        "operation_id": operation_id,
        "preflight_digest": preflight_digest,
        "reviewed": reviewed,
        "role": preflight.role.value,
        "target_operating_system": preflight.target_operating_system,
        "target_operating_system_version": preflight.target_operating_system_version,
        "trust_digest": readiness.trust_digest,
    }
    return OsUpgradeInPlaceAuthorization(
        operation_id,
        str(metadata.cluster_uuid),
        preflight.logical_id,
        preflight.role,
        preflight.current_operating_system,
        preflight.current_operating_system_version,
        preflight.target_operating_system,
        preflight.target_operating_system_version,
        preflight.architecture,
        preflight_digest,
        observed.digest,
        inventory.digest,
        readiness.trust_digest,
        allow_sensitive,
        reviewed,
        no_competing_operation,
        _object_digest(values),
    )


def build_os_upgrade_in_place_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    base_os: BaseOsEvidence,
    prerequisites: OsUpgradePreflightPrerequisites,
    intent: OsUpgradePreflightIntent,
    preflight: OsUpgradePreflightEvidence,
    authorization: OsUpgradeInPlaceAuthorization,
    *,
    limit: tuple[str, ...],
    image_filter: ImageFilter,
    architecture: str,
) -> dict[str, object]:
    """Build a strict request that can only emit blocked, not-performed evidence."""

    if len(limit) != 1 or limit[0] != intent.logical_id:
        raise StateConflictError("OS-upgrade in-place requires one exact stable ID")
    if architecture not in SUPPORTED_ARCHITECTURES:
        raise StateConflictError("OS-upgrade in-place architecture is unsupported")
    if preflight.architecture != architecture:
        raise StateConflictError("OS-upgrade in-place architecture evidence mismatches")
    if (
        intent.target_operating_system != CURRENT_OPERATING_SYSTEM
        or preflight.target_operating_system != CURRENT_OPERATING_SYSTEM
    ):
        raise StateConflictError("OS-upgrade in-place target OS is unsupported")
    if (
        intent.target_operating_system_version == CURRENT_OPERATING_SYSTEM_VERSION
        or preflight.target_operating_system_version == CURRENT_OPERATING_SYSTEM_VERSION
    ):
        raise StateConflictError(
            "OS-upgrade in-place same-version request is not an upgrade"
        )
    expected_preflight = build_os_upgrade_preflight_payload(
        metadata,
        observed,
        inventory,
        readiness,
        base_os,
        prerequisites,
        intent,
        limit=limit,
        image_filter=image_filter,
        architecture=architecture,
    )
    _require_current_eligible_preflight(preflight, expected_preflight)
    _validate_authorization(
        metadata,
        observed,
        inventory,
        readiness,
        preflight,
        authorization,
    )
    expected_blockers = ["target-transition-unapproved"]
    if preflight.role is HostRole.SCYLLA:
        expected_blockers.append("shutdown-sequence-unreviewed")
    blockers = tuple(sorted(expected_blockers))
    provenance = dict(preflight.provenance)
    provenance.update(
        {
            "authorization_digest": authorization.authorization_digest,
            "preflight_digest": authorization.preflight_digest,
        }
    )
    return {
        "applied": False,
        "architecture": architecture,
        "authorization": {
            "allow_sensitive": True,
            "authorization_digest": authorization.authorization_digest,
            "no_competing_operation": True,
            "operation_id": authorization.operation_id,
            "reviewed": True,
        },
        "automatic_retry": False,
        "cluster_uuid": str(metadata.cluster_uuid),
        "configuration_action": ACTION_NOT_PERFORMED,
        "current_operating_system": CURRENT_OPERATING_SYSTEM,
        "current_operating_system_version": CURRENT_OPERATING_SYSTEM_VERSION,
        "expected_blockers": list(blockers),
        "guest_architecture": "x86_64" if architecture == "amd64" else "aarch64",
        "kernel_action": ACTION_NOT_PERFORMED,
        "logical_id": preflight.logical_id,
        "mutation_boundary": MUTATION_BOUNDARY,
        "not_performed": list(NOT_PERFORMED),
        "package_action": ACTION_NOT_PERFORMED,
        "preflight_digest": authorization.preflight_digest,
        "provenance": provenance,
        "reboot_action": ACTION_NOT_PERFORMED,
        "recovery_required": False,
        "role": preflight.role.value,
        "schema_version": OS_UPGRADE_IN_PLACE_SCHEMA_VERSION,
        "service_action": ACTION_NOT_PERFORMED,
        "source_action": ACTION_NOT_PERFORMED,
        "target_operating_system": preflight.target_operating_system,
        "target_operating_system_version": preflight.target_operating_system_version,
        "transition_classification": "unapproved",
    }


def parse_os_upgrade_in_place_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> OsUpgradeInPlaceEvidence:
    """Parse only bounded blocked/failure evidence and the exact host recap."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError("Ansible OS-upgrade in-place output exceeds evidence limit")
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_OS_UPGRADE_IN_PLACE_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible OS-upgrade in-place marker is malformed")
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"), object_pairs_hook=_strict_object
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible OS-upgrade in-place marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible OS-upgrade in-place evidence is malformed")
        values.append(value)
    recap = _parse_recap(stdout)
    logical_id = _text(expected_payload["logical_id"])
    if set(recap) != {logical_id}:
        raise AnsibleError("Ansible OS-upgrade in-place recap membership conflicts")
    changed, unreachable, failed = recap[logical_id]
    if changed:
        raise AnsibleError("Ansible OS-upgrade in-place reported a mutation")
    recap_failed = bool(unreachable or failed)
    if not values:
        if not recap_failed or exit_code == 0:
            raise AnsibleError("Ansible OS-upgrade in-place evidence is incomplete")
        return _failed_evidence(expected_payload, unreachable=bool(unreachable))
    if len(values) != 1:
        raise AnsibleError("Ansible OS-upgrade in-place evidence is duplicated")
    evidence = _parse_result(values[0], expected_payload)
    result_failed = evidence.status is OsUpgradeInPlaceStatus.FAILED
    if recap_failed != result_failed or (exit_code == 0) == result_failed:
        raise AnsibleError("Ansible OS-upgrade in-place exit status conflicts")
    return evidence


def _require_current_eligible_preflight(
    preflight: OsUpgradePreflightEvidence,
    expected: dict[str, object],
) -> None:
    expected_provenance = cast(dict[str, object], expected["provenance"])
    expected_gates = {
        _text(cast(dict[str, object], item)["name"]): GateStatus(
            _text(cast(dict[str, object], item)["status"])
        )
        for item in cast(list[object], expected["controller_gates"])
    }
    actual_gates = {item.name: item.status for item in preflight.gates}
    for name in HOST_GATE_NAMES:
        expected_gates[name] = GateStatus.PASSED
    if (
        preflight.schema_version != OS_UPGRADE_PREFLIGHT_SCHEMA_VERSION
        or preflight.status is not OsUpgradePreflightStatus.BLOCKED
        or preflight.transition_classification
        is not TransitionClassification.UNSUPPORTED
        or preflight.requested_strategy not in {"auto", "in-place"}
        or preflight.selected_path != "not-performed"
        or preflight.current_operating_system != expected["current_operating_system"]
        or preflight.current_operating_system_version
        != expected["current_operating_system_version"]
        or preflight.target_operating_system != expected["target_operating_system"]
        or preflight.target_operating_system_version
        != expected["target_operating_system_version"]
        or preflight.logical_id != expected["logical_id"]
        or preflight.role.value != expected["role"]
        or preflight.architecture != expected["architecture"]
        or not preflight.rolling_eligible
        or actual_gates != expected_gates
        or preflight.not_performed != PREFLIGHT_NOT_PERFORMED
        or preflight.provenance
        != tuple(
            sorted(
                (_text(name), _require_digest(value))
                for name, value in expected_provenance.items()
            )
        )
        or preflight.blockers
        != tuple(
            _sorted_strings(
                expected["controller_blockers"], name="preflight-controller-blockers"
            )
        )
        or preflight.blockers != _ELIGIBLE_PREFLIGHT_BLOCKERS
    ):
        raise StateConflictError(
            "OS-upgrade in-place requires current explicitly eligible preflight evidence"
        )


def _validate_authorization(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    preflight: OsUpgradePreflightEvidence,
    authorization: OsUpgradeInPlaceAuthorization,
) -> None:
    values = {
        "allow_sensitive": authorization.allow_sensitive,
        "architecture": authorization.architecture,
        "cluster_uuid": authorization.cluster_uuid,
        "current_operating_system": authorization.current_operating_system,
        "current_operating_system_version": (
            authorization.current_operating_system_version
        ),
        "inventory_digest": authorization.inventory_digest,
        "logical_id": authorization.logical_id,
        "no_competing_operation": authorization.no_competing_operation,
        "observation_digest": authorization.observation_digest,
        "operation_id": authorization.operation_id,
        "preflight_digest": authorization.preflight_digest,
        "reviewed": authorization.reviewed,
        "role": authorization.role.value,
        "target_operating_system": authorization.target_operating_system,
        "target_operating_system_version": authorization.target_operating_system_version,
        "trust_digest": authorization.trust_digest,
    }
    if (
        not _valid_uuid(authorization.operation_id)
        or authorization.cluster_uuid != str(metadata.cluster_uuid)
        or authorization.logical_id != preflight.logical_id
        or authorization.role is not preflight.role
        or authorization.current_operating_system != preflight.current_operating_system
        or authorization.current_operating_system_version
        != preflight.current_operating_system_version
        or authorization.target_operating_system != preflight.target_operating_system
        or authorization.target_operating_system_version
        != preflight.target_operating_system_version
        or authorization.architecture != preflight.architecture
        or authorization.preflight_digest
        != os_upgrade_preflight_evidence_digest(preflight)
        or authorization.observation_digest != observed.digest
        or authorization.inventory_digest != inventory.digest
        or authorization.trust_digest != readiness.trust_digest
        or not authorization.allow_sensitive
        or not authorization.reviewed
        or not authorization.no_competing_operation
        or authorization.authorization_digest != _object_digest(values)
    ):
        raise StateConflictError(
            "OS-upgrade in-place authorization does not bind the exact request"
        )
    for digest in (
        authorization.authorization_digest,
        authorization.preflight_digest,
        authorization.observation_digest,
        authorization.inventory_digest,
        authorization.trust_digest,
    ):
        _require_digest(digest)


def _parse_result(
    value: dict[str, object],
    expected: dict[str, object],
) -> OsUpgradeInPlaceEvidence:
    fields = {
        "applied",
        "architecture",
        "automatic_retry",
        "blockers",
        "configuration_action",
        "current_operating_system",
        "current_operating_system_version",
        "kernel_action",
        "logical_id",
        "mutation_boundary",
        "not_performed",
        "package_action",
        "provenance",
        "reboot_action",
        "recovery_required",
        "role",
        "schema_version",
        "service_action",
        "source_action",
        "status",
        "target_operating_system",
        "target_operating_system_version",
        "transition_classification",
    }
    if (
        set(value) != fields
        or value["schema_version"] != OS_UPGRADE_IN_PLACE_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible OS-upgrade in-place evidence schema is invalid")
    for name in (
        "architecture",
        "current_operating_system",
        "current_operating_system_version",
        "logical_id",
        "role",
        "target_operating_system",
        "target_operating_system_version",
        "transition_classification",
    ):
        if value[name] != expected[name]:
            raise AnsibleError("Ansible OS-upgrade in-place evidence conflicts")
    try:
        status = OsUpgradeInPlaceStatus(_text(value["status"]))
        role = HostRole(_text(value["role"]))
    except ValueError as error:
        raise AnsibleError("Ansible OS-upgrade in-place status is invalid") from error
    if _require_bool(value["applied"]) or _require_bool(value["automatic_retry"]):
        raise AnsibleError("Ansible OS-upgrade in-place claimed a forbidden mutation")
    for name in _ACTION_FIELDS:
        if value[name] != ACTION_NOT_PERFORMED:
            raise AnsibleError("Ansible OS-upgrade in-place claimed a forbidden action")
    if value["mutation_boundary"] != MUTATION_BOUNDARY or _require_bool(
        value["recovery_required"]
    ):
        raise AnsibleError("Ansible OS-upgrade in-place mutation boundary conflicts")
    not_performed = _sorted_strings(value["not_performed"], name="not-performed")
    if not_performed != NOT_PERFORMED:
        raise AnsibleError("Ansible OS-upgrade in-place not-performed set is invalid")
    blockers = _sorted_strings(value["blockers"], name="blockers")
    expected_blockers = tuple(
        _sorted_strings(expected["expected_blockers"], name="expected-blockers")
    )
    if status is OsUpgradeInPlaceStatus.BLOCKED and blockers != expected_blockers:
        raise AnsibleError("Ansible OS-upgrade in-place blocked evidence conflicts")
    if status is OsUpgradeInPlaceStatus.FAILED and (
        len(blockers) != 1 or blockers[0] not in _FAILURE_BLOCKERS
    ):
        raise AnsibleError("Ansible OS-upgrade in-place failure evidence conflicts")
    provenance_value = value["provenance"]
    if (
        not isinstance(provenance_value, dict)
        or provenance_value != expected["provenance"]
    ):
        raise AnsibleError("Ansible OS-upgrade in-place provenance conflicts")
    provenance = tuple(
        sorted(
            (_text(name), _require_digest(item))
            for name, item in provenance_value.items()
        )
    )
    _reject_secrets(value)
    return OsUpgradeInPlaceEvidence(
        _text(value["logical_id"]),
        role,
        status,
        "unapproved",
        _text(value["current_operating_system"]),
        _text(value["current_operating_system_version"]),
        _text(value["target_operating_system"]),
        _text(value["target_operating_system_version"]),
        _text(value["architecture"]),
        False,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        False,
        MUTATION_BOUNDARY,
        False,
        not_performed,
        provenance,
        blockers,
    )


def _failed_evidence(
    expected: dict[str, object],
    *,
    unreachable: bool,
) -> OsUpgradeInPlaceEvidence:
    return OsUpgradeInPlaceEvidence(
        _text(expected["logical_id"]),
        HostRole(_text(expected["role"])),
        OsUpgradeInPlaceStatus.FAILED,
        "unapproved",
        _text(expected["current_operating_system"]),
        _text(expected["current_operating_system_version"]),
        _text(expected["target_operating_system"]),
        _text(expected["target_operating_system_version"]),
        _text(expected["architecture"]),
        False,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        False,
        MUTATION_BOUNDARY,
        False,
        NOT_PERFORMED,
        _provenance(expected),
        ("host-unreachable" if unreachable else "execution-failed",),
    )


def _preflight_object(evidence: OsUpgradePreflightEvidence) -> dict[str, object]:
    return {
        "architecture": evidence.architecture,
        "blockers": list(evidence.blockers),
        "current_operating_system": evidence.current_operating_system,
        "current_operating_system_version": evidence.current_operating_system_version,
        "gates": [
            {"name": gate.name, "status": gate.status.value} for gate in evidence.gates
        ],
        "logical_id": evidence.logical_id,
        "not_performed": list(evidence.not_performed),
        "provenance": dict(evidence.provenance),
        "requested_strategy": evidence.requested_strategy,
        "role": evidence.role.value,
        "rolling_eligible": evidence.rolling_eligible,
        "schema_version": evidence.schema_version,
        "selected_path": evidence.selected_path,
        "status": evidence.status.value,
        "target_operating_system": evidence.target_operating_system,
        "target_operating_system_version": evidence.target_operating_system_version,
        "transition_classification": evidence.transition_classification.value,
    }


def _parse_recap(stdout: str) -> dict[str, tuple[int, int, int]]:
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible OS-upgrade in-place output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible OS-upgrade in-place recap is malformed")
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


def _valid_uuid(value: str) -> bool:
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _object_digest(value: object) -> str:
    data = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AnsibleError(
                "Ansible OS-upgrade in-place evidence has duplicate fields"
            )
        value[key] = item
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible OS-upgrade in-place value is invalid")
    return value


def _require_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError("Ansible OS-upgrade in-place boolean is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible OS-upgrade in-place digest is invalid")
    return text


def _sorted_strings(value: object, *, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError(f"Ansible OS-upgrade in-place {name} are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError(
            f"Ansible OS-upgrade in-place {name} are not uniquely sorted"
        )
    return items


def _reject_secrets(value: dict[str, object]) -> None:
    encoded = json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True)
    if re.search(
        r"(?i)(?:-----BEGIN [^-]*PRIVATE KEY-----|"
        r"(?:password|passphrase|secret|token)\s*[:=])",
        encoded,
    ):
        raise AnsibleError("Ansible OS-upgrade in-place evidence contains a secret")
