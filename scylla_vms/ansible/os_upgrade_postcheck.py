"""Strict read-only postcheck for an OS upgrade or immutable reprovision."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import cast

from scylla_vms.ansible.base_os import BaseOsEvidence, BaseOsStatus
from scylla_vms.ansible.os_reprovision_prepare import (
    ACTION_NOT_PERFORMED as REPROVISION_ACTION_NOT_PERFORMED,
)
from scylla_vms.ansible.os_reprovision_prepare import (
    MUTATION_BOUNDARY as REPROVISION_MUTATION_BOUNDARY,
)
from scylla_vms.ansible.os_reprovision_prepare import (
    OS_REPROVISION_PREPARE_SCHEMA_VERSION,
    OsReprovisionPrepareAuthorization,
    OsReprovisionPrepareEvidence,
    OsReprovisionPrepareStatus,
)
from scylla_vms.ansible.os_upgrade_in_place import (
    ACTION_NOT_PERFORMED as IN_PLACE_ACTION_NOT_PERFORMED,
)
from scylla_vms.ansible.os_upgrade_in_place import (
    MUTATION_BOUNDARY as IN_PLACE_MUTATION_BOUNDARY,
)
from scylla_vms.ansible.os_upgrade_in_place import (
    OS_UPGRADE_IN_PLACE_SCHEMA_VERSION,
    OsUpgradeInPlaceAuthorization,
    OsUpgradeInPlaceEvidence,
    OsUpgradeInPlaceStatus,
)
from scylla_vms.ansible.os_upgrade_preflight import (
    GATE_NAMES as PREFLIGHT_GATE_NAMES,
)
from scylla_vms.ansible.os_upgrade_preflight import (
    GateStatus,
    OsUpgradePreflightPrerequisites,
    _role_gates,
    _validate_role_safety,
)
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.scylla_install import SCYLLA_RELEASE_LINE
from scylla_vms.desired import HostRole, ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata

OS_UPGRADE_POSTCHECK_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-os-upgrade-postcheck/v1"
)
CURRENT_OPERATING_SYSTEM = "Ubuntu"
CURRENT_OPERATING_SYSTEM_VERSION = "24.04"
SUPPORTED_ARCHITECTURES = ("aarch64", "amd64")
SOURCE_MODES = ("in-place", "reprovision")
SOURCE_UPGRADE_NOT_PERFORMED = "source-upgrade-not-performed"
NOT_PERFORMED = (
    "apt-mutation",
    "automatic-remediation",
    "configuration-write",
    "package-mutation",
    "provider-call",
    "reboot",
    "service-change",
    "storage-write",
    "terraform",
    "trust-replacement",
)
GATE_NAMES = (
    "architecture",
    "base-os",
    "broken-packages",
    "health",
    "kernel",
    "operating-system",
    "package-state",
    "provider-identity",
    "reboot-required",
    "role-configuration",
    "role-package",
    "route",
    "service-policy",
    "source-upgrade",
    "stable-identity",
    "storage",
    "transition",
)
HOST_GATE_NAMES = frozenset(
    {
        "architecture",
        "broken-packages",
        "kernel",
        "operating-system",
        "package-state",
        "reboot-required",
        "service-policy",
    }
)
VERIFICATION_NAMES = (
    "architecture",
    "broken-packages",
    "kernel",
    "operating-system",
    "package-state",
    "reboot-required",
    "service-policy",
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_OS_NAME = re.compile(r"[A-Za-z][A-Za-z0-9 ._-]{0,63}\Z")
_OS_VERSION = re.compile(r"[0-9][A-Za-z0-9._-]{0,31}\Z")
_PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}\Z")
_MARKER = re.compile(r"DSV_OS_UPGRADE_POSTCHECK_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_FAILURE_BLOCKERS = frozenset({"execution-failed", "host-unreachable"})
_BLOCKERS = frozenset(
    {
        "architecture-mismatch",
        "broken-packages",
        "current-os-mismatch",
        "execution-failed",
        "host-unreachable",
        "jump-health-not-performed",
        "kernel-mismatch",
        "kernel-policy-undefined",
        "manager-backend-unconfigured",
        "manager-health-not-performed",
        "manager-service-not-started",
        "monitoring-health-not-performed",
        "monitoring-stack-not-started",
        "package-inspection-failed",
        "package-state-mismatch",
        "provider-identity-not-changed",
        "reboot-required",
        "role-availability-failed",
        "role-availability-unknown",
        "route-failed",
        "route-unknown",
        "same-version-not-upgrade",
        "service-inspection-failed",
        "service-policy-mismatch",
        "service-policy-unknown",
        SOURCE_UPGRADE_NOT_PERFORMED,
        "source-operation-failed",
        "target-transition-unapproved",
        "target-transition-unsupported",
    }
)
_IN_PLACE_ACTION_FIELDS = (
    "configuration_action",
    "kernel_action",
    "package_action",
    "reboot_action",
    "service_action",
    "source_action",
)
_REPROVISION_ACTION_FIELDS = (
    "configuration_action",
    "desired_state_action",
    "membership_action",
    "package_action",
    "provider_action",
    "reboot_action",
    "registration_action",
    "restore_action",
    "service_action",
    "storage_action",
    "terraform_action",
    "trust_action",
    "vm_action",
)


class OsUpgradePostcheckStatus(StrEnum):
    VERIFIED = "verified"
    BLOCKED = "blocked"
    FAILED = "failed"


class TransitionComparison(StrEnum):
    MATCHED = "matched"
    MISMATCHED = "mismatched"


class TransitionClassification(StrEnum):
    APPROVED = "approved"
    SAME_VERSION = "same-version"
    UNAPPROVED = "unapproved"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class OsUpgradePostcheckGateEvidence:
    name: str
    status: GateStatus


@dataclass(frozen=True, slots=True)
class OsUpgradePostcheckEvidence:
    logical_id: str
    role: HostRole
    status: OsUpgradePostcheckStatus
    source_mode: str
    source_schema_version: str
    source_status: str
    source_result_digest: str
    source_upgrade_performed: bool
    transition_classification: TransitionClassification
    transition_comparison: TransitionComparison
    previous_operating_system: str
    previous_operating_system_version: str
    previous_architecture: str
    target_operating_system: str
    target_operating_system_version: str
    target_architecture: str
    current_operating_system: str
    current_operating_system_version: str
    current_architecture: str
    current_provider_id_digest: str
    current_kernel_release_digest: str | None
    current_package_state_digest: str | None
    current_service_state_digest: str | None
    observation_generation: int
    inventory_generation: int
    trust_generation: int
    gates: tuple[OsUpgradePostcheckGateEvidence, ...]
    verification_performed: tuple[str, ...]
    verification_not_performed: tuple[str, ...]
    mutation_performed: bool
    remediation_performed: bool
    automatic_remediation: bool
    not_performed: tuple[str, ...]
    provenance: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]
    schema_version: str = OS_UPGRADE_POSTCHECK_SCHEMA_VERSION


SourceResult = OsUpgradeInPlaceEvidence | OsReprovisionPrepareEvidence
SourceAuthorization = OsUpgradeInPlaceAuthorization | OsReprovisionPrepareAuthorization


def os_upgrade_source_result_digest(source_result: SourceResult) -> str:
    """Bind one strict source-operation projection without raw output."""

    if not isinstance(
        source_result, (OsUpgradeInPlaceEvidence, OsReprovisionPrepareEvidence)
    ):
        raise StateConflictError("OS-upgrade postcheck source result type is invalid")
    return _object_digest(asdict(source_result))


def build_os_upgrade_postcheck_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    base_os: BaseOsEvidence,
    prerequisites: OsUpgradePreflightPrerequisites,
    source_result: SourceResult,
    source_authorization: SourceAuthorization,
    *,
    operation_id: str,
    limit: tuple[str, ...],
    image_filter: ImageFilter,
    architecture: str,
    expected_kernel_release_digest: str | None = None,
) -> dict[str, object]:
    """Build a read-only postcheck that rejects current validation-only sources."""

    _require_state_provenance(metadata, observed, inventory, readiness)
    if not _valid_uuid(operation_id):
        raise AnsibleError("OS-upgrade postcheck operation ID is invalid")
    if (
        len(limit) != 1
        or limit != tuple(sorted(set(limit)))
        or _LOGICAL_ID.fullmatch(limit[0]) is None
    ):
        raise StateConflictError("OS-upgrade postcheck requires one exact stable ID")
    if (
        image_filter
        != ImageFilter(
            CURRENT_OPERATING_SYSTEM,
            CURRENT_OPERATING_SYSTEM_VERSION,
            ImageVersionMatch.EXACT,
        )
        or architecture not in SUPPORTED_ARCHITECTURES
    ):
        raise StateConflictError(
            "OS-upgrade postcheck requires exact current Ubuntu 24.04 evidence"
        )
    if expected_kernel_release_digest is not None:
        _require_digest(expected_kernel_release_digest)

    host = next(
        (
            item
            for item in inventory.record.inventory.hosts
            if item.logical_id == limit[0]
        ),
        None,
    )
    if host is None:
        raise StateConflictError(
            "OS-upgrade postcheck target is not a current stable ID"
        )
    source = _source_details(
        source_result,
        source_authorization,
        operation_id=operation_id,
        logical_id=host.logical_id,
        role=host.role,
        observed=observed,
        inventory=inventory,
        readiness=readiness,
    )

    base_host = next(
        (item for item in base_os.hosts if item.logical_id == host.logical_id), None
    )
    if (
        len(base_os.hosts) != 1
        or base_host is None
        or base_os.status
        not in {
            BaseOsStatus.CHANGED,
            BaseOsStatus.NO_CHANGE,
        }
        or base_host.status
        not in {
            BaseOsStatus.CHANGED,
            BaseOsStatus.NO_CHANGE,
        }
        or base_host.reboot_required
    ):
        raise StateConflictError(
            "OS-upgrade postcheck requires current successful base-os evidence"
        )

    preflight_gates = {name: GateStatus.NOT_PERFORMED for name in PREFLIGHT_GATE_NAMES}
    role_blockers: set[str] = set()
    _validate_role_safety(prerequisites.role_safety)
    if (
        prerequisites.role_safety.logical_id != host.logical_id
        or prerequisites.role_safety.role is not host.role
    ):
        raise StateConflictError("OS-upgrade postcheck role evidence target conflicts")
    role_provenance, _ = _role_gates(
        host.role,
        host.logical_id,
        observed,
        inventory,
        prerequisites,
        preflight_gates,
        role_blockers,
    )

    gates = {name: GateStatus.NOT_PERFORMED for name in GATE_NAMES}
    gates.update(
        {
            "base-os": GateStatus.PASSED,
            "health": preflight_gates["health"],
            "provider-identity": cast(GateStatus, source["provider_identity_status"]),
            "role-configuration": preflight_gates["role-configuration"],
            "role-package": preflight_gates["role-package"],
            "route": prerequisites.role_safety.route,
            "service-policy": preflight_gates["service"],
            "source-upgrade": GateStatus.FAILED,
            "stable-identity": GateStatus.PASSED,
            "storage": preflight_gates["storage"],
            "transition": GateStatus.FAILED,
        }
    )
    blockers = set(role_blockers)
    blockers.add(SOURCE_UPGRADE_NOT_PERFORMED)
    if source["source_status"] == "failed":
        blockers.add("source-operation-failed")
    if source["provider_identity_status"] is GateStatus.FAILED:
        blockers.add("provider-identity-not-changed")
    _add_status_blocker(
        blockers,
        prerequisites.role_safety.route,
        failed="route-failed",
        unknown="route-unknown",
    )
    _add_status_blocker(
        blockers,
        prerequisites.role_safety.availability,
        failed="role-availability-failed",
        unknown="role-availability-unknown",
    )

    transition = classify_postcheck_transition(
        str(source["previous_operating_system"]),
        str(source["previous_operating_system_version"]),
        str(source["previous_architecture"]),
        str(source["target_operating_system"]),
        str(source["target_operating_system_version"]),
        str(source["target_architecture"]),
    )
    blockers.add(
        {
            TransitionClassification.SAME_VERSION: "same-version-not-upgrade",
            TransitionClassification.UNSUPPORTED: "target-transition-unsupported",
            TransitionClassification.UNAPPROVED: "target-transition-unapproved",
            TransitionClassification.APPROVED: "target-transition-unapproved",
        }[transition]
    )
    if expected_kernel_release_digest is None:
        gates["kernel"] = GateStatus.UNKNOWN
        blockers.add("kernel-policy-undefined")

    expected_packages = _expected_packages(host.role, prerequisites)
    expected_services = _expected_services(host.role)
    if gates["service-policy"] in {
        GateStatus.NOT_PERFORMED,
        GateStatus.UNKNOWN,
    }:
        gates["service-policy"] = GateStatus.UNKNOWN
        blockers.add("service-policy-unknown")
    if host.role is HostRole.MANAGER:
        blockers.add("manager-health-not-performed")
    elif host.role is HostRole.JUMP_HOST:
        blockers.add("jump-health-not-performed")

    source_digest = cast(str, source["source_result_digest"])
    authorization_digest = cast(str, source["source_authorization_digest"])
    provenance: dict[str, str] = {
        "base_os_digest": _object_digest(_base_os_object(base_os)),
        "inventory_digest": inventory.digest,
        "observation_digest": observed.digest,
        "role_safety_digest": prerequisites.role_safety.digest,
        "source_authorization_digest": authorization_digest,
        "source_result_digest": source_digest,
        "trust_digest": _require_digest(readiness.trust_digest),
        **role_provenance,
    }
    current_provider_id_digest = _digest_text(host.provider_id)
    return {
        "architecture": architecture,
        "cluster_uuid": str(metadata.cluster_uuid),
        "controller_blockers": sorted(blockers),
        "controller_gates": [
            {"name": name, "status": gates[name].value} for name in GATE_NAMES
        ],
        "current_operating_system": image_filter.operating_system,
        "current_operating_system_version": image_filter.operating_system_version,
        "current_provider_id_digest": current_provider_id_digest,
        "expected_kernel_release_digest": expected_kernel_release_digest,
        "expected_packages": expected_packages,
        "expected_services": expected_services,
        "guest_architecture": "x86_64" if architecture == "amd64" else "aarch64",
        "inventory_generation": inventory.record.generation,
        "logical_id": host.logical_id,
        "not_performed": list(NOT_PERFORMED),
        "observation_generation": observed.record.generation,
        "operation_id": operation_id,
        "previous_architecture": source["previous_architecture"],
        "previous_operating_system": source["previous_operating_system"],
        "previous_operating_system_version": source[
            "previous_operating_system_version"
        ],
        "provenance": provenance,
        "role": host.role.value,
        "schema_version": OS_UPGRADE_POSTCHECK_SCHEMA_VERSION,
        "source_mode": source["source_mode"],
        "source_result_digest": source_digest,
        "source_schema_version": source["source_schema_version"],
        "source_status": source["source_status"],
        "source_upgrade_performed": False,
        "target_architecture": source["target_architecture"],
        "target_operating_system": source["target_operating_system"],
        "target_operating_system_version": source["target_operating_system_version"],
        "transition_classification": transition.value,
        "trust_generation": readiness.trust_generation,
        "verification_names": list(VERIFICATION_NAMES),
    }


def classify_postcheck_transition(
    previous_operating_system: str,
    previous_operating_system_version: str,
    previous_architecture: str,
    target_operating_system: str,
    target_operating_system_version: str,
    target_architecture: str,
) -> TransitionClassification:
    """Classify without inventing a target transition not approved by PLAN."""

    _validate_os(previous_operating_system, previous_operating_system_version)
    _validate_os(target_operating_system, target_operating_system_version)
    if (
        previous_architecture not in SUPPORTED_ARCHITECTURES
        or target_architecture not in SUPPORTED_ARCHITECTURES
        or target_operating_system != CURRENT_OPERATING_SYSTEM
    ):
        return TransitionClassification.UNSUPPORTED
    if (
        previous_operating_system == target_operating_system
        and previous_operating_system_version == target_operating_system_version
        and previous_architecture == target_architecture
    ):
        return TransitionClassification.SAME_VERSION
    return TransitionClassification.UNAPPROVED


def parse_os_upgrade_postcheck_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> OsUpgradePostcheckEvidence:
    """Parse only bounded normalized postcheck evidence and one exact recap."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError("Ansible OS-upgrade postcheck output exceeds evidence limit")
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_OS_UPGRADE_POSTCHECK_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible OS-upgrade postcheck marker is malformed")
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"), object_pairs_hook=_strict_object
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible OS-upgrade postcheck marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible OS-upgrade postcheck evidence is malformed")
        values.append(value)
    recap = _parse_recap(stdout)
    logical_id = _text(expected_payload["logical_id"])
    if set(recap) != {logical_id}:
        raise AnsibleError("Ansible OS-upgrade postcheck recap membership conflicts")
    changed, unreachable, failed = recap[logical_id]
    if changed:
        raise AnsibleError("Ansible OS-upgrade postcheck reported a mutation")
    recap_failed = bool(unreachable or failed)
    if not values:
        if not recap_failed or exit_code == 0:
            raise AnsibleError("Ansible OS-upgrade postcheck evidence is incomplete")
        return _failed_evidence(expected_payload, unreachable=bool(unreachable))
    if len(values) != 1:
        raise AnsibleError("Ansible OS-upgrade postcheck evidence is duplicated")
    evidence = _parse_result(values[0], expected_payload)
    result_failed = evidence.status is OsUpgradePostcheckStatus.FAILED
    if recap_failed != result_failed or (exit_code == 0) == result_failed:
        raise AnsibleError("Ansible OS-upgrade postcheck exit status conflicts")
    return evidence


def _source_details(
    source_result: SourceResult,
    source_authorization: SourceAuthorization,
    *,
    operation_id: str,
    logical_id: str,
    role: HostRole,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
) -> dict[str, object]:
    if not isinstance(
        source_result, (OsUpgradeInPlaceEvidence, OsReprovisionPrepareEvidence)
    ):
        raise StateConflictError("OS-upgrade postcheck source result type is invalid")
    provenance = dict(source_result.provenance)
    source_digest = os_upgrade_source_result_digest(source_result)
    if isinstance(source_result, OsUpgradeInPlaceEvidence):
        if not isinstance(source_authorization, OsUpgradeInPlaceAuthorization):
            raise StateConflictError(
                "OS-upgrade postcheck source mode and authorization conflict"
            )
        _validate_in_place_source(source_result)
        authorization_digest = source_authorization.authorization_digest
        valid_authorization = (
            source_authorization.operation_id == operation_id
            and source_authorization.logical_id == logical_id
            and source_authorization.role is role
            and source_authorization.current_operating_system
            == source_result.current_operating_system
            and source_authorization.current_operating_system_version
            == source_result.current_operating_system_version
            and source_authorization.target_operating_system
            == source_result.target_operating_system
            and source_authorization.target_operating_system_version
            == source_result.target_operating_system_version
            and source_authorization.architecture == source_result.architecture
            and source_authorization.observation_digest == observed.digest
            and source_authorization.inventory_digest == inventory.digest
            and source_authorization.trust_digest == readiness.trust_digest
            and provenance.get("authorization_digest") == authorization_digest
            and provenance.get("preflight_digest")
            == source_authorization.preflight_digest
            and source_authorization.allow_sensitive
            and source_authorization.reviewed
            and source_authorization.no_competing_operation
            and _authorization_digest(source_authorization)
            == source_authorization.authorization_digest
        )
        details: dict[str, object] = {
            "previous_architecture": source_result.architecture,
            "previous_operating_system": source_result.current_operating_system,
            "previous_operating_system_version": (
                source_result.current_operating_system_version
            ),
            "provider_identity_status": GateStatus.PASSED,
            "source_mode": "in-place",
            "source_schema_version": source_result.schema_version,
            "source_status": source_result.status.value,
            "target_architecture": source_result.architecture,
            "target_operating_system": source_result.target_operating_system,
            "target_operating_system_version": (
                source_result.target_operating_system_version
            ),
        }
    elif isinstance(source_result, OsReprovisionPrepareEvidence):
        if not isinstance(source_authorization, OsReprovisionPrepareAuthorization):
            raise StateConflictError(
                "OS-upgrade postcheck source mode and authorization conflict"
            )
        _validate_reprovision_source(source_result)
        authorization_digest = source_authorization.authorization_digest
        valid_authorization = (
            source_authorization.operation_id == operation_id
            and source_authorization.logical_id == logical_id
            and source_authorization.role is role
            and source_authorization.current_operating_system
            == source_result.current_operating_system
            and source_authorization.current_operating_system_version
            == source_result.current_operating_system_version
            and source_authorization.current_architecture
            == source_result.current_architecture
            and source_authorization.target_operating_system
            == source_result.target_operating_system
            and source_authorization.target_operating_system_version
            == source_result.target_operating_system_version
            and source_authorization.target_architecture
            == source_result.target_architecture
            and source_authorization.provider_id_digest
            == source_result.current_provider_id_digest
            and source_authorization.observation_digest == observed.digest
            and source_authorization.inventory_digest == inventory.digest
            and source_authorization.trust_digest == readiness.trust_digest
            and provenance.get("authorization_digest") == authorization_digest
            and provenance.get("preflight_digest")
            == source_authorization.preflight_digest
            and source_authorization.allow_destructive
            and source_authorization.reviewed
            and source_authorization.no_competing_operation
            and source_authorization.stable_identity_preserved
            and _authorization_digest(source_authorization)
            == source_authorization.authorization_digest
        )
        details = {
            "previous_architecture": source_result.current_architecture,
            "previous_operating_system": source_result.current_operating_system,
            "previous_operating_system_version": (
                source_result.current_operating_system_version
            ),
            "provider_identity_status": GateStatus.FAILED,
            "source_mode": "reprovision",
            "source_schema_version": source_result.schema_version,
            "source_status": source_result.status.value,
            "target_architecture": source_result.target_architecture,
            "target_operating_system": source_result.target_operating_system,
            "target_operating_system_version": (
                source_result.target_operating_system_version
            ),
        }
    else:
        raise StateConflictError("OS-upgrade postcheck source result type is invalid")
    if (
        source_result.logical_id != logical_id
        or source_result.role is not role
        or provenance.get("observation_digest") != observed.digest
        or provenance.get("inventory_digest") != inventory.digest
        or provenance.get("trust_digest") != readiness.trust_digest
        or not valid_authorization
        or not _valid_uuid(source_authorization.operation_id)
    ):
        raise StateConflictError(
            "OS-upgrade postcheck source operation evidence conflicts"
        )
    _require_digest(authorization_digest)
    details.update(
        {
            "source_authorization_digest": authorization_digest,
            "source_result_digest": source_digest,
        }
    )
    return details


def _validate_in_place_source(source: OsUpgradeInPlaceEvidence) -> None:
    if (
        source.schema_version != OS_UPGRADE_IN_PLACE_SCHEMA_VERSION
        or source.status
        not in {
            OsUpgradeInPlaceStatus.BLOCKED,
            OsUpgradeInPlaceStatus.FAILED,
        }
        or source.transition_classification != "unapproved"
        or source.applied
        or source.automatic_retry
        or source.mutation_boundary != IN_PLACE_MUTATION_BOUNDARY
        or source.recovery_required
        or any(
            getattr(source, name) != IN_PLACE_ACTION_NOT_PERFORMED
            for name in _IN_PLACE_ACTION_FIELDS
        )
    ):
        raise StateConflictError(
            "OS-upgrade postcheck in-place source evidence conflicts"
        )


def _validate_reprovision_source(source: OsReprovisionPrepareEvidence) -> None:
    if (
        source.schema_version != OS_REPROVISION_PREPARE_SCHEMA_VERSION
        or source.status
        not in {
            OsReprovisionPrepareStatus.BLOCKED,
            OsReprovisionPrepareStatus.FAILED,
        }
        or source.transition_classification != "unapproved"
        or source.reprovision_classification != "validation-only"
        or source.applied
        or source.automatic_retry
        or source.replacement_provider_id_state != "not-created"
        or source.mutation_boundary != REPROVISION_MUTATION_BOUNDARY
        or source.recovery_required
        or any(
            getattr(source, name) != REPROVISION_ACTION_NOT_PERFORMED
            for name in _REPROVISION_ACTION_FIELDS
        )
    ):
        raise StateConflictError(
            "OS-upgrade postcheck reprovision source evidence conflicts"
        )


def _expected_packages(
    role: HostRole,
    prerequisites: OsUpgradePreflightPrerequisites,
) -> list[dict[str, str]]:
    packages: tuple[tuple[str, str], ...]
    if role is HostRole.SCYLLA:
        packages = (
            prerequisites.scylla_install.packages
            if prerequisites.scylla_install is not None
            else ()
        )
    elif role is HostRole.MANAGER:
        packages = (
            prerequisites.manager_server.packages
            if prerequisites.manager_server is not None
            else ()
        )
    else:
        packages = ()
    normalized = [
        {"name": _require_package(name), "version": _text(version)}
        for name, version in packages
    ]
    if normalized != sorted(normalized, key=lambda item: item["name"]) or len(
        {item["name"] for item in normalized}
    ) != len(normalized):
        raise StateConflictError("OS-upgrade postcheck package evidence conflicts")
    if role is HostRole.SCYLLA and any(
        not item["version"].startswith(f"{SCYLLA_RELEASE_LINE}.") for item in normalized
    ):
        raise StateConflictError(
            "OS-upgrade postcheck Scylla package evidence conflicts"
        )
    return normalized


def _expected_services(role: HostRole) -> list[dict[str, str | None]]:
    values: list[dict[str, str | None]] = [
        {
            "active": "active",
            "enabled": "enabled",
            "unit": "systemd-timesyncd.service",
        }
    ]
    if role is HostRole.SCYLLA:
        values.append(
            {
                "active": "active",
                "enabled": None,
                "unit": "scylla-server.service",
            }
        )
    elif role is HostRole.MANAGER:
        values.append(
            {
                "active": "inactive",
                "enabled": "masked",
                "unit": "scylla-manager.service",
            }
        )
    elif role is HostRole.JUMP_HOST:
        values.append(
            {
                "active": "active",
                "enabled": None,
                "unit": "ssh.service",
            }
        )
    return sorted(values, key=lambda item: cast(str, item["unit"]))


def _parse_result(
    value: dict[str, object],
    expected: dict[str, object],
) -> OsUpgradePostcheckEvidence:
    fields = {
        "automatic_remediation",
        "blockers",
        "current_architecture",
        "current_kernel_release_digest",
        "current_operating_system",
        "current_operating_system_version",
        "current_package_state_digest",
        "current_provider_id_digest",
        "current_service_state_digest",
        "gates",
        "inventory_generation",
        "logical_id",
        "mutation_performed",
        "not_performed",
        "observation_generation",
        "previous_architecture",
        "previous_operating_system",
        "previous_operating_system_version",
        "provenance",
        "remediation_performed",
        "role",
        "schema_version",
        "source_mode",
        "source_result_digest",
        "source_schema_version",
        "source_status",
        "source_upgrade_performed",
        "status",
        "target_architecture",
        "target_operating_system",
        "target_operating_system_version",
        "transition_classification",
        "transition_comparison",
        "trust_generation",
        "verification_not_performed",
        "verification_performed",
    }
    if (
        set(value) != fields
        or value["schema_version"] != OS_UPGRADE_POSTCHECK_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible OS-upgrade postcheck evidence schema is invalid")
    for name in (
        "current_provider_id_digest",
        "inventory_generation",
        "logical_id",
        "observation_generation",
        "previous_architecture",
        "previous_operating_system",
        "previous_operating_system_version",
        "role",
        "source_mode",
        "source_result_digest",
        "source_schema_version",
        "source_status",
        "target_architecture",
        "target_operating_system",
        "target_operating_system_version",
        "transition_classification",
        "trust_generation",
    ):
        if value[name] != expected[name]:
            raise AnsibleError("Ansible OS-upgrade postcheck evidence conflicts")
    try:
        status = OsUpgradePostcheckStatus(_text(value["status"]))
        role = HostRole(_text(value["role"]))
        transition = TransitionClassification(_text(value["transition_classification"]))
        comparison = TransitionComparison(_text(value["transition_comparison"]))
    except ValueError as error:
        raise AnsibleError("Ansible OS-upgrade postcheck status is invalid") from error
    if any(
        _require_bool(value[name])
        for name in (
            "automatic_remediation",
            "mutation_performed",
            "remediation_performed",
            "source_upgrade_performed",
        )
    ):
        raise AnsibleError("Ansible OS-upgrade postcheck claimed a forbidden mutation")
    current_os = _text(value["current_operating_system"])
    current_version = _text(value["current_operating_system_version"])
    current_architecture = _text(value["current_architecture"])
    if (current_os, current_version) != ("unknown", "unknown"):
        _validate_os(current_os, current_version)
    if current_architecture not in {*SUPPORTED_ARCHITECTURES, "unknown"}:
        raise AnsibleError("Ansible OS-upgrade postcheck architecture is invalid")
    matches = (
        current_os == expected["target_operating_system"]
        and current_version == expected["target_operating_system_version"]
        and current_architecture == expected["target_architecture"]
    )
    if comparison is not (
        TransitionComparison.MATCHED if matches else TransitionComparison.MISMATCHED
    ):
        raise AnsibleError(
            "Ansible OS-upgrade postcheck transition comparison conflicts"
        )
    gates = _parse_gates(value["gates"], expected, status)
    blockers = _sorted_strings(value["blockers"], name="blockers")
    if not set(blockers) <= _BLOCKERS:
        raise AnsibleError("Ansible OS-upgrade postcheck blockers are invalid")
    expected_controller = set(
        _sorted_strings(expected["controller_blockers"], name="controller-blockers")
    )
    if status is OsUpgradePostcheckStatus.BLOCKED:
        if not expected_controller <= set(blockers):
            raise AnsibleError(
                "Ansible OS-upgrade postcheck controller blockers were omitted"
            )
        _validate_host_gate_blockers(gates, blockers)
    elif status is OsUpgradePostcheckStatus.FAILED:
        if len(blockers) != 1 or blockers[0] not in _FAILURE_BLOCKERS:
            raise AnsibleError(
                "Ansible OS-upgrade postcheck failure evidence conflicts"
            )
    else:
        raise AnsibleError(
            "Ansible OS-upgrade postcheck cannot verify an unperformed source upgrade"
        )
    performed = _sorted_strings(
        value["verification_performed"], name="verification-performed"
    )
    not_verified = _sorted_strings(
        value["verification_not_performed"], name="verification-not-performed"
    )
    if (
        set(performed) & set(not_verified)
        or tuple(sorted((*performed, *not_verified))) != VERIFICATION_NAMES
        or (status is OsUpgradePostcheckStatus.FAILED and performed)
    ):
        raise AnsibleError(
            "Ansible OS-upgrade postcheck verification coverage conflicts"
        )
    not_performed = _sorted_strings(value["not_performed"], name="not-performed")
    if not_performed != NOT_PERFORMED:
        raise AnsibleError("Ansible OS-upgrade postcheck not-performed set is invalid")
    provenance_value = value["provenance"]
    if (
        not isinstance(provenance_value, dict)
        or provenance_value != expected["provenance"]
    ):
        raise AnsibleError("Ansible OS-upgrade postcheck provenance conflicts")
    provenance = tuple(
        sorted(
            (_text(name), _require_digest(item))
            for name, item in provenance_value.items()
        )
    )
    kernel_digest = _optional_digest(value["current_kernel_release_digest"])
    package_digest = _optional_digest(value["current_package_state_digest"])
    service_digest = _optional_digest(value["current_service_state_digest"])
    _reject_secrets(value)
    return OsUpgradePostcheckEvidence(
        _text(value["logical_id"]),
        role,
        status,
        _text(value["source_mode"]),
        _text(value["source_schema_version"]),
        _text(value["source_status"]),
        _require_digest(value["source_result_digest"]),
        False,
        transition,
        comparison,
        _text(value["previous_operating_system"]),
        _text(value["previous_operating_system_version"]),
        _text(value["previous_architecture"]),
        _text(value["target_operating_system"]),
        _text(value["target_operating_system_version"]),
        _text(value["target_architecture"]),
        current_os,
        current_version,
        current_architecture,
        _require_digest(value["current_provider_id_digest"]),
        kernel_digest,
        package_digest,
        service_digest,
        _positive_int(value["observation_generation"]),
        _positive_int(value["inventory_generation"]),
        _positive_int(value["trust_generation"]),
        gates,
        performed,
        not_verified,
        False,
        False,
        False,
        not_performed,
        provenance,
        blockers,
    )


def _parse_gates(
    value: object,
    expected: dict[str, object],
    status: OsUpgradePostcheckStatus,
) -> tuple[OsUpgradePostcheckGateEvidence, ...]:
    if not isinstance(value, list) or len(value) != len(GATE_NAMES):
        raise AnsibleError("Ansible OS-upgrade postcheck gates are incomplete")
    expected_values = {
        _text(cast(dict[str, object], item)["name"]): _text(
            cast(dict[str, object], item)["status"]
        )
        for item in cast(list[object], expected["controller_gates"])
    }
    gates: list[OsUpgradePostcheckGateEvidence] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"name", "status"}:
            raise AnsibleError("Ansible OS-upgrade postcheck gate schema is invalid")
        name = _text(item["name"])
        try:
            gate_status = GateStatus(_text(item["status"]))
        except ValueError as error:
            raise AnsibleError(
                "Ansible OS-upgrade postcheck gate status is invalid"
            ) from error
        if name not in GATE_NAMES or name in {gate.name for gate in gates}:
            raise AnsibleError("Ansible OS-upgrade postcheck gate name is invalid")
        if (
            status is OsUpgradePostcheckStatus.BLOCKED
            and name not in HOST_GATE_NAMES
            and gate_status.value != expected_values[name]
        ):
            raise AnsibleError("Ansible OS-upgrade postcheck controller gate conflicts")
        if (
            status is OsUpgradePostcheckStatus.FAILED
            and gate_status is not GateStatus.UNKNOWN
        ):
            raise AnsibleError("Ansible OS-upgrade postcheck failure gates conflict")
        gates.append(OsUpgradePostcheckGateEvidence(name, gate_status))
    if tuple(gate.name for gate in gates) != GATE_NAMES:
        raise AnsibleError("Ansible OS-upgrade postcheck gates are not ordered")
    return tuple(gates)


def _validate_host_gate_blockers(
    gates: tuple[OsUpgradePostcheckGateEvidence, ...],
    blockers: tuple[str, ...],
) -> None:
    statuses = {gate.name: gate.status for gate in gates}
    rules: dict[str, dict[GateStatus, str | None]] = {
        "architecture": {
            GateStatus.FAILED: "architecture-mismatch",
            GateStatus.PASSED: None,
        },
        "broken-packages": {
            GateStatus.FAILED: "broken-packages",
            GateStatus.PASSED: None,
        },
        "kernel": {
            GateStatus.FAILED: "kernel-mismatch",
            GateStatus.PASSED: None,
            GateStatus.UNKNOWN: "kernel-policy-undefined",
        },
        "operating-system": {
            GateStatus.FAILED: "current-os-mismatch",
            GateStatus.PASSED: None,
        },
        "package-state": {
            GateStatus.FAILED: "package-state-mismatch",
            GateStatus.PASSED: None,
            GateStatus.UNKNOWN: "package-inspection-failed",
        },
        "reboot-required": {
            GateStatus.FAILED: "reboot-required",
            GateStatus.PASSED: None,
        },
        "service-policy": {
            GateStatus.FAILED: "service-policy-mismatch",
            GateStatus.PASSED: None,
            GateStatus.UNKNOWN: "service-policy-unknown",
        },
    }
    blocker_set = set(blockers)
    all_host_blockers = {
        blocker
        for allowed in rules.values()
        for blocker in allowed.values()
        if blocker is not None
    }
    expected: set[str] = set()
    for name, allowed in rules.items():
        status = statuses[name]
        if status is GateStatus.NOT_PERFORMED:
            continue
        if status not in allowed:
            raise AnsibleError(
                "Ansible OS-upgrade postcheck host gate status is invalid"
            )
        blocker = allowed[status]
        if blocker is not None:
            expected.add(blocker)
    if blocker_set & all_host_blockers != expected:
        raise AnsibleError("Ansible OS-upgrade postcheck host gate blockers conflict")


def _failed_evidence(
    expected: dict[str, object],
    *,
    unreachable: bool,
) -> OsUpgradePostcheckEvidence:
    provenance = cast(dict[str, object], expected["provenance"])
    current_os = _text(expected["current_operating_system"])
    current_version = _text(expected["current_operating_system_version"])
    current_architecture = _text(expected["architecture"])
    matches = (
        current_os == expected["target_operating_system"]
        and current_version == expected["target_operating_system_version"]
        and current_architecture == expected["target_architecture"]
    )
    return OsUpgradePostcheckEvidence(
        _text(expected["logical_id"]),
        HostRole(_text(expected["role"])),
        OsUpgradePostcheckStatus.FAILED,
        _text(expected["source_mode"]),
        _text(expected["source_schema_version"]),
        _text(expected["source_status"]),
        _require_digest(expected["source_result_digest"]),
        False,
        TransitionClassification(_text(expected["transition_classification"])),
        TransitionComparison.MATCHED if matches else TransitionComparison.MISMATCHED,
        _text(expected["previous_operating_system"]),
        _text(expected["previous_operating_system_version"]),
        _text(expected["previous_architecture"]),
        _text(expected["target_operating_system"]),
        _text(expected["target_operating_system_version"]),
        _text(expected["target_architecture"]),
        current_os,
        current_version,
        current_architecture,
        _require_digest(expected["current_provider_id_digest"]),
        None,
        None,
        None,
        _positive_int(expected["observation_generation"]),
        _positive_int(expected["inventory_generation"]),
        _positive_int(expected["trust_generation"]),
        tuple(
            OsUpgradePostcheckGateEvidence(name, GateStatus.UNKNOWN)
            for name in GATE_NAMES
        ),
        (),
        VERIFICATION_NAMES,
        False,
        False,
        False,
        NOT_PERFORMED,
        tuple(
            sorted(
                (_text(name), _require_digest(item))
                for name, item in provenance.items()
            )
        ),
        ("host-unreachable" if unreachable else "execution-failed",),
    )


def _require_state_provenance(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
) -> None:
    record = inventory.record
    if (
        metadata.cluster_uuid != record.cluster_uuid
        or metadata.cluster_name != record.cluster_name
        or metadata.provider != record.provider
        or observed.record.cluster_uuid != record.cluster_uuid
        or observed.record.cluster_name != record.cluster_name
        or observed.record.generation != record.source_manifest_generation
        or observed.record.manifest_digest != record.source_manifest_digest
        or readiness.observation_generation != observed.record.generation
        or readiness.observation_digest != observed.digest
        or readiness.inventory_generation != record.generation
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_generation is None
        or readiness.trust_digest is None
    ):
        raise StateConflictError("OS-upgrade postcheck state provenance conflicts")


def _add_status_blocker(
    blockers: set[str],
    status: GateStatus,
    *,
    failed: str,
    unknown: str,
) -> None:
    if status is GateStatus.FAILED:
        blockers.add(failed)
    elif status in {GateStatus.UNKNOWN, GateStatus.NOT_PERFORMED}:
        blockers.add(unknown)


def _base_os_object(value: BaseOsEvidence) -> dict[str, object]:
    return {
        "hosts": [
            {
                "changed": host.changed,
                "logical_id": host.logical_id,
                "reason": host.reason,
                "reboot_required": host.reboot_required,
                "status": host.status.value,
            }
            for host in value.hosts
        ],
        "status": value.status.value,
    }


def _parse_recap(stdout: str) -> dict[str, tuple[int, int, int]]:
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible OS-upgrade postcheck output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible OS-upgrade postcheck recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    return rows


def _validate_os(operating_system: str, version: str) -> None:
    if (
        _OS_NAME.fullmatch(operating_system) is None
        or _OS_VERSION.fullmatch(version) is None
    ):
        raise AnsibleError("OS-upgrade postcheck OS evidence is invalid")


def _require_package(value: str) -> str:
    if _PACKAGE.fullmatch(value) is None:
        raise StateConflictError("OS-upgrade postcheck package name is invalid")
    return value


def _object_digest(value: object) -> str:
    data = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _authorization_digest(value: SourceAuthorization) -> str:
    fields = asdict(value)
    fields.pop("authorization_digest")
    return _object_digest(fields)


def _digest_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AnsibleError(
                "Ansible OS-upgrade postcheck evidence has duplicate fields"
            )
        value[key] = item
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible OS-upgrade postcheck value is invalid")
    return value


def _require_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError("Ansible OS-upgrade postcheck boolean is invalid")
    return value


def _positive_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise AnsibleError("Ansible OS-upgrade postcheck generation is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible OS-upgrade postcheck digest is invalid")
    return text


def _optional_digest(value: object) -> str | None:
    return None if value is None else _require_digest(value)


def _sorted_strings(value: object, *, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError(f"Ansible OS-upgrade postcheck {name} are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError(
            f"Ansible OS-upgrade postcheck {name} are not uniquely sorted"
        )
    return items


def _valid_uuid(value: object) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _reject_secrets(value: dict[str, object]) -> None:
    encoded = json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True)
    if re.search(
        r"(?i)(?:-----BEGIN [^-]*PRIVATE KEY-----|"
        r"(?:password|passphrase|secret|token)\s*[:=])",
        encoded,
    ):
        raise AnsibleError("Ansible OS-upgrade postcheck evidence contains a secret")
