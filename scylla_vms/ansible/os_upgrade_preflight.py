"""Strict read-only OS-upgrade preflight for the Ubuntu 24.04 baseline."""

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

from scylla_vms.ansible.base_os import BaseOsEvidence, BaseOsStatus
from scylla_vms.ansible.jump_host_configure import (
    JumpHostConfigureEvidence,
    JumpHostConfigureStatus,
)
from scylla_vms.ansible.manager_server import (
    ManagerServerEvidence,
    ManagerServerStatus,
)
from scylla_vms.ansible.monitoring_stack import (
    MonitoringStackEvidence,
    MonitoringStackStatus,
)
from scylla_vms.ansible.monitoring_targets import (
    MonitoringTargetsEvidence,
    MonitoringTargetsStatus,
)
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.scylla_configure import (
    ScyllaConfigureEvidence,
    ScyllaConfigureStatus,
)
from scylla_vms.ansible.scylla_health import ScyllaHealthEvidence
from scylla_vms.ansible.scylla_install import (
    SCYLLA_RELEASE_LINE,
    ScyllaInstallEvidence,
    ScyllaInstallStatus,
)
from scylla_vms.ansible.scylla_remove_live import scylla_health_evidence_digest
from scylla_vms.ansible.storage_postcheck import StoragePostcheckEvidence
from scylla_vms.desired import HostRole, ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata

OS_UPGRADE_PREFLIGHT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-os-upgrade-preflight/v1"
)
SUPPORTED_CURRENT_OS = "Ubuntu"
SUPPORTED_CURRENT_OS_VERSION = "24.04"
SUPPORTED_ARCHITECTURES = ("aarch64", "amd64")
STRATEGIES = ("auto", "in-place", "reprovision")
NOT_PERFORMED = (
    "apt-dist-upgrade",
    "apt-update",
    "desired-state-change",
    "do-release-upgrade",
    "nodetool-drain",
    "oci-discovery",
    "package-mutation",
    "reboot",
    "service-start",
    "service-stop",
    "terraform",
    "vm-replacement",
)
GATE_NAMES = (
    "architecture",
    "backup-policy",
    "base-os",
    "boot-space",
    "broken-packages",
    "capacity",
    "current-os",
    "health",
    "kernel-family",
    "kernel-policy",
    "package-channel",
    "package-currency",
    "package-locks",
    "provider-image",
    "quorum",
    "reboot-required",
    "replication",
    "repository-state",
    "role-availability",
    "role-configuration",
    "role-package",
    "root-space",
    "route",
    "service",
    "storage",
    "topology-work",
    "transition",
)
HOST_GATE_NAMES = frozenset(
    {
        "boot-space",
        "broken-packages",
        "kernel-family",
        "package-locks",
        "reboot-required",
        "root-space",
    }
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_OS_NAME = re.compile(r"[A-Za-z][A-Za-z0-9 ._-]{0,63}\Z")
_OS_VERSION = re.compile(r"[0-9][A-Za-z0-9._-]{0,31}\Z")
_MARKER = re.compile(r"DSV_OS_UPGRADE_PREFLIGHT_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_BLOCKERS = frozenset(
    {
        "architecture-mismatch",
        "backup-policy-failed",
        "backup-policy-unknown",
        "base-os-reboot-required",
        "boot-space-insufficient",
        "boot-space-unknown",
        "broken-packages",
        "capacity-failed",
        "capacity-unknown",
        "execution-failed",
        "health-failed",
        "health-unknown",
        "host-unreachable",
        "kernel-family-unsupported",
        "kernel-policy-undefined",
        "manager-backend-unconfigured",
        "manager-health-not-performed",
        "manager-service-not-started",
        "monitoring-health-not-performed",
        "monitoring-stack-not-started",
        "package-channel-unavailable",
        "package-currency-not-performed",
        "package-lock-evidence-unknown",
        "package-manager-lock-held",
        "provider-image-mismatch",
        "provider-image-not-performed",
        "quorum-failed",
        "quorum-unknown",
        "reboot-required",
        "replication-failed",
        "replication-unknown",
        "repository-inspection-not-performed",
        "role-availability-failed",
        "role-availability-unknown",
        "root-space-insufficient",
        "root-space-unknown",
        "route-failed",
        "route-unknown",
        "target-transition-undefined",
        "target-transition-unsupported",
        "topology-work-active",
    }
)


class GateStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    UNKNOWN = "unknown"
    NOT_PERFORMED = "not-performed"


class TransitionClassification(StrEnum):
    UNDEFINED = "undefined"
    UNSUPPORTED = "unsupported"


class OsUpgradePreflightStatus(StrEnum):
    BLOCKED = "blocked"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class OsUpgradeProviderImageFacts:
    operating_system: str
    operating_system_version: str
    architecture: str
    image_id_digest: str
    source_digest: str
    available: bool
    replacement_plan_reviewed: bool
    digest: str


@dataclass(frozen=True, slots=True)
class OsUpgradeRoleSafetyEvidence:
    logical_id: str
    role: HostRole
    route: GateStatus
    availability: GateStatus
    digest: str


@dataclass(frozen=True, slots=True)
class ScyllaRollingSafetyEvidence:
    logical_id: str
    health_digest: str
    topology_digest: str
    replication: GateStatus
    quorum: GateStatus
    capacity: GateStatus
    backup_policy: GateStatus
    no_active_topology_work: bool
    shutdown_not_started: bool
    drain_not_started: bool
    digest: str


@dataclass(frozen=True, slots=True)
class OsUpgradePreflightIntent:
    operation_id: str
    cluster_uuid: str
    logical_id: str
    strategy: str
    target_operating_system: str
    target_operating_system_version: str
    package_policy_digest: str | None
    provider_image: OsUpgradeProviderImageFacts | None
    minimum_root_free_bytes: int
    minimum_boot_free_bytes: int
    space_policy_digest: str
    max_unavailable: int
    no_competing_operation: bool
    digest: str


@dataclass(frozen=True, slots=True)
class OsUpgradePreflightPrerequisites:
    role_safety: OsUpgradeRoleSafetyEvidence
    scylla_install: ScyllaInstallEvidence | None = None
    scylla_configure: ScyllaConfigureEvidence | None = None
    storage_postcheck: StoragePostcheckEvidence | None = None
    scylla_health: ScyllaHealthEvidence | None = None
    scylla_rolling: ScyllaRollingSafetyEvidence | None = None
    jump_host_configure: JumpHostConfigureEvidence | None = None
    manager_server: ManagerServerEvidence | None = None
    monitoring_stack: MonitoringStackEvidence | None = None
    monitoring_targets: MonitoringTargetsEvidence | None = None


@dataclass(frozen=True, slots=True)
class OsUpgradeGateEvidence:
    name: str
    status: GateStatus


@dataclass(frozen=True, slots=True)
class OsUpgradePreflightEvidence:
    logical_id: str
    role: HostRole
    status: OsUpgradePreflightStatus
    transition_classification: TransitionClassification
    requested_strategy: str
    selected_path: str
    current_operating_system: str
    current_operating_system_version: str
    target_operating_system: str
    target_operating_system_version: str
    architecture: str
    rolling_eligible: bool
    gates: tuple[OsUpgradeGateEvidence, ...]
    not_performed: tuple[str, ...]
    provenance: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]
    schema_version: str = OS_UPGRADE_PREFLIGHT_SCHEMA_VERSION


def os_upgrade_space_policy_digest(
    minimum_root_free_bytes: int, minimum_boot_free_bytes: int
) -> str:
    """Bind exact caller-reviewed free-space thresholds."""

    if (
        isinstance(minimum_root_free_bytes, bool)
        or isinstance(minimum_boot_free_bytes, bool)
        or not 1 <= minimum_root_free_bytes <= 2**63 - 1
        or not 1 <= minimum_boot_free_bytes <= 2**63 - 1
    ):
        raise StateConflictError("OS-upgrade preflight space policy is invalid")
    return _object_digest(
        {
            "minimum_boot_free_bytes": minimum_boot_free_bytes,
            "minimum_root_free_bytes": minimum_root_free_bytes,
        }
    )


def build_provider_image_facts(
    *,
    operating_system: str,
    operating_system_version: str,
    architecture: str,
    image_id_digest: str,
    source_digest: str,
    available: bool,
    replacement_plan_reviewed: bool,
) -> OsUpgradeProviderImageFacts:
    """Build digest-bound offline provider image facts without OCI access."""

    _validate_os_target(operating_system, operating_system_version)
    if architecture not in SUPPORTED_ARCHITECTURES:
        raise AnsibleError("OS-upgrade provider image architecture is invalid")
    values = {
        "architecture": architecture,
        "available": available,
        "image_id_digest": _require_digest(image_id_digest),
        "operating_system": operating_system,
        "operating_system_version": operating_system_version,
        "replacement_plan_reviewed": replacement_plan_reviewed,
        "source_digest": _require_digest(source_digest),
    }
    return OsUpgradeProviderImageFacts(
        operating_system,
        operating_system_version,
        architecture,
        image_id_digest,
        source_digest,
        available,
        replacement_plan_reviewed,
        _object_digest(values),
    )


def build_role_safety_evidence(
    logical_id: str,
    role: HostRole,
    *,
    route: GateStatus,
    availability: GateStatus,
) -> OsUpgradeRoleSafetyEvidence:
    """Build exact target route/availability evidence for rolling selection."""

    _require_logical_id(logical_id)
    values = {
        "availability": availability.value,
        "logical_id": logical_id,
        "role": role.value,
        "route": route.value,
    }
    return OsUpgradeRoleSafetyEvidence(
        logical_id, role, route, availability, _object_digest(values)
    )


def build_scylla_rolling_safety_evidence(
    logical_id: str,
    health: ScyllaHealthEvidence,
    *,
    replication: GateStatus,
    quorum: GateStatus,
    capacity: GateStatus,
    backup_policy: GateStatus,
    no_active_topology_work: bool,
    shutdown_not_started: bool,
    drain_not_started: bool,
) -> ScyllaRollingSafetyEvidence:
    """Bind independent rolling gates to one exact complete health snapshot."""

    _require_logical_id(logical_id)
    health_digest = scylla_health_evidence_digest(health)
    topology_digest = _require_digest(health.topology_digest)
    values = {
        "backup_policy": backup_policy.value,
        "capacity": capacity.value,
        "drain_not_started": drain_not_started,
        "health_digest": health_digest,
        "logical_id": logical_id,
        "no_active_topology_work": no_active_topology_work,
        "quorum": quorum.value,
        "replication": replication.value,
        "shutdown_not_started": shutdown_not_started,
        "topology_digest": topology_digest,
    }
    return ScyllaRollingSafetyEvidence(
        logical_id,
        health_digest,
        topology_digest,
        replication,
        quorum,
        capacity,
        backup_policy,
        no_active_topology_work,
        shutdown_not_started,
        drain_not_started,
        _object_digest(values),
    )


def build_os_upgrade_preflight_intent(
    metadata: ClusterMetadata,
    *,
    operation_id: str,
    logical_id: str,
    strategy: str,
    target_operating_system: str,
    target_operating_system_version: str,
    package_policy_digest: str | None,
    provider_image: OsUpgradeProviderImageFacts | None,
    minimum_root_free_bytes: int,
    minimum_boot_free_bytes: int,
    space_policy_digest: str,
    max_unavailable: int = 1,
    no_competing_operation: bool = True,
) -> OsUpgradePreflightIntent:
    """Build narrow read-only intent for one serial preflight target."""

    try:
        valid_operation = str(uuid.UUID(operation_id)) == operation_id
    except ValueError:
        valid_operation = False
    _require_logical_id(logical_id)
    _validate_os_target(target_operating_system, target_operating_system_version)
    if not valid_operation or strategy not in STRATEGIES:
        raise AnsibleError("OS-upgrade preflight operation intent is invalid")
    if (
        isinstance(minimum_root_free_bytes, bool)
        or isinstance(minimum_boot_free_bytes, bool)
        or not 1 <= minimum_root_free_bytes <= 2**63 - 1
        or not 1 <= minimum_boot_free_bytes <= 2**63 - 1
        or max_unavailable != 1
        or not no_competing_operation
    ):
        raise StateConflictError("OS-upgrade preflight safety policy is invalid")
    if strategy in {"auto", "in-place"}:
        if package_policy_digest is None:
            raise StateConflictError(
                "OS-upgrade preflight requires reviewed package policy evidence"
            )
        _require_digest(package_policy_digest)
    elif package_policy_digest is not None:
        raise StateConflictError(
            "reprovision-only OS preflight forbids package policy input"
        )
    if strategy == "reprovision" and provider_image is None:
        raise StateConflictError(
            "reprovision OS preflight requires offline provider image facts"
        )
    if strategy == "in-place" and provider_image is not None:
        raise StateConflictError("in-place OS preflight forbids provider image facts")
    provider_digest = None
    if provider_image is not None:
        _validate_provider_image_facts(provider_image)
        provider_digest = provider_image.digest
    expected_space_digest = os_upgrade_space_policy_digest(
        minimum_root_free_bytes, minimum_boot_free_bytes
    )
    if space_policy_digest != expected_space_digest:
        raise StateConflictError("OS-upgrade preflight space policy digest conflicts")
    values = {
        "cluster_uuid": str(metadata.cluster_uuid),
        "logical_id": logical_id,
        "max_unavailable": max_unavailable,
        "minimum_boot_free_bytes": minimum_boot_free_bytes,
        "minimum_root_free_bytes": minimum_root_free_bytes,
        "no_competing_operation": no_competing_operation,
        "operation_id": operation_id,
        "package_policy_digest": package_policy_digest,
        "provider_image_digest": provider_digest,
        "space_policy_digest": expected_space_digest,
        "strategy": strategy,
        "target_operating_system": target_operating_system,
        "target_operating_system_version": target_operating_system_version,
    }
    return OsUpgradePreflightIntent(
        operation_id,
        str(metadata.cluster_uuid),
        logical_id,
        strategy,
        target_operating_system,
        target_operating_system_version,
        package_policy_digest,
        provider_image,
        minimum_root_free_bytes,
        minimum_boot_free_bytes,
        expected_space_digest,
        max_unavailable,
        no_competing_operation,
        _object_digest(values),
    )


def build_os_upgrade_preflight_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    base_os: BaseOsEvidence,
    prerequisites: OsUpgradePreflightPrerequisites,
    intent: OsUpgradePreflightIntent,
    *,
    limit: tuple[str, ...],
    image_filter: ImageFilter,
    architecture: str,
) -> dict[str, object]:
    """Build one strict preflight that cannot authorize an undefined transition."""

    if len(limit) != 1 or limit[0] != intent.logical_id:
        raise StateConflictError("OS-upgrade preflight requires one exact target")
    if (
        image_filter
        != ImageFilter(
            SUPPORTED_CURRENT_OS,
            SUPPORTED_CURRENT_OS_VERSION,
            ImageVersionMatch.EXACT,
        )
        or architecture not in SUPPORTED_ARCHITECTURES
    ):
        raise StateConflictError(
            "OS-upgrade preflight refuses unsupported current OS evidence"
        )
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
        raise StateConflictError("OS-upgrade preflight input provenance conflicts")
    host = next(
        (item for item in record.inventory.hosts if item.logical_id == limit[0]), None
    )
    if host is None:
        raise StateConflictError(
            "OS-upgrade preflight target is not a current stable ID"
        )
    _validate_intent(metadata, intent)
    if (
        prerequisites.role_safety.logical_id != host.logical_id
        or prerequisites.role_safety.role is not host.role
    ):
        raise StateConflictError("OS-upgrade preflight role safety target conflicts")
    _validate_role_safety(prerequisites.role_safety)
    base_host = next(
        (item for item in base_os.hosts if item.logical_id == host.logical_id), None
    )
    if (
        len(base_os.hosts) != 1
        or base_host is None
        or base_os.status
        in {
            BaseOsStatus.FAILURE,
            BaseOsStatus.UNSUPPORTED,
        }
        or base_host.status
        in {
            BaseOsStatus.FAILURE,
            BaseOsStatus.UNSUPPORTED,
        }
    ):
        raise StateConflictError(
            "OS-upgrade preflight requires current successful base-os evidence"
        )

    gates = {name: GateStatus.NOT_PERFORMED for name in GATE_NAMES}
    blockers: set[str] = {
        "kernel-policy-undefined",
        "package-currency-not-performed",
        "repository-inspection-not-performed",
    }
    gates.update(
        {
            "architecture": GateStatus.PASSED,
            "base-os": (
                GateStatus.FAILED if base_host.reboot_required else GateStatus.PASSED
            ),
            "current-os": GateStatus.PASSED,
            "kernel-policy": GateStatus.UNKNOWN,
            "package-channel": (
                GateStatus.PASSED
                if intent.package_policy_digest is not None
                else GateStatus.NOT_PERFORMED
            ),
            "package-currency": GateStatus.UNKNOWN,
            "repository-state": GateStatus.UNKNOWN,
            "role-availability": prerequisites.role_safety.availability,
            "route": prerequisites.role_safety.route,
        }
    )
    if base_host.reboot_required:
        blockers.add("base-os-reboot-required")
    _add_status_blocker(
        blockers,
        prerequisites.role_safety.availability,
        failed="role-availability-failed",
        unknown="role-availability-unknown",
    )
    _add_status_blocker(
        blockers,
        prerequisites.role_safety.route,
        failed="route-failed",
        unknown="route-unknown",
    )
    if intent.package_policy_digest is None and intent.strategy != "reprovision":
        blockers.add("package-channel-unavailable")
    provider_status = _provider_gate(intent, architecture)
    gates["provider-image"] = provider_status
    if provider_status is GateStatus.FAILED:
        blockers.add("provider-image-mismatch")
    elif intent.strategy == "reprovision" and provider_status is not GateStatus.PASSED:
        blockers.add("provider-image-not-performed")

    transition = classify_transition(
        intent.target_operating_system, intent.target_operating_system_version
    )
    if transition is TransitionClassification.UNDEFINED:
        gates["transition"] = GateStatus.UNKNOWN
        blockers.add("target-transition-undefined")
    else:
        gates["transition"] = GateStatus.FAILED
        blockers.add("target-transition-unsupported")

    role_provenance, rolling_eligible = _role_gates(
        host.role,
        host.logical_id,
        observed,
        inventory,
        prerequisites,
        gates,
        blockers,
    )
    provenance = {
        "base_os_digest": _object_digest(_base_os_object(base_os)),
        "intent_digest": intent.digest,
        "inventory_digest": inventory.digest,
        "observation_digest": observed.digest,
        "role_safety_digest": prerequisites.role_safety.digest,
        "space_policy_digest": intent.space_policy_digest,
        "trust_digest": readiness.trust_digest,
        **role_provenance,
    }
    return {
        "architecture": architecture,
        "cluster_uuid": str(metadata.cluster_uuid),
        "controller_blockers": sorted(blockers),
        "controller_gates": [
            {"name": name, "status": gates[name].value} for name in GATE_NAMES
        ],
        "current_operating_system": SUPPORTED_CURRENT_OS,
        "current_operating_system_version": SUPPORTED_CURRENT_OS_VERSION,
        "guest_architecture": "x86_64" if architecture == "amd64" else "aarch64",
        "intent": {
            "digest": intent.digest,
            "max_unavailable": 1,
            "no_competing_operation": True,
            "operation_id": intent.operation_id,
        },
        "logical_id": host.logical_id,
        "minimum_boot_free_bytes": intent.minimum_boot_free_bytes,
        "minimum_root_free_bytes": intent.minimum_root_free_bytes,
        "not_performed": list(NOT_PERFORMED),
        "provenance": provenance,
        "requested_strategy": intent.strategy,
        "role": host.role.value,
        "rolling_eligible": rolling_eligible,
        "schema_version": OS_UPGRADE_PREFLIGHT_SCHEMA_VERSION,
        "selected_path": "not-performed",
        "target_operating_system": intent.target_operating_system,
        "target_operating_system_version": intent.target_operating_system_version,
        "transition_classification": transition.value,
    }


def classify_transition(
    target_operating_system: str, target_operating_system_version: str
) -> TransitionClassification:
    """Classify against the deliberately empty approved target transition matrix."""

    _validate_os_target(target_operating_system, target_operating_system_version)
    if (
        target_operating_system == SUPPORTED_CURRENT_OS
        and target_operating_system_version == SUPPORTED_CURRENT_OS_VERSION
    ):
        return TransitionClassification.UNDEFINED
    return TransitionClassification.UNSUPPORTED


def parse_os_upgrade_preflight_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> OsUpgradePreflightEvidence:
    """Parse only bounded normalized per-host preflight evidence and recap."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError("Ansible OS-upgrade preflight output exceeds evidence limit")
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_OS_UPGRADE_PREFLIGHT_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible OS-upgrade preflight marker is malformed")
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"), object_pairs_hook=_strict_object
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible OS-upgrade preflight marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible OS-upgrade preflight evidence is malformed")
        values.append(value)
    recap = _parse_recap(stdout)
    logical_id = _text(expected_payload["logical_id"])
    if set(recap) != {logical_id}:
        raise AnsibleError("Ansible OS-upgrade preflight recap membership conflicts")
    changed, unreachable, failed = recap[logical_id]
    recap_failed = bool(unreachable or failed)
    if changed:
        raise AnsibleError("Ansible OS-upgrade preflight reported a mutation")
    if not values:
        if not recap_failed or exit_code == 0:
            raise AnsibleError("Ansible OS-upgrade preflight evidence is incomplete")
        return _failed_evidence(expected_payload, unreachable=bool(unreachable))
    if len(values) != 1:
        raise AnsibleError("Ansible OS-upgrade preflight evidence is duplicated")
    evidence = _parse_result(values[0], expected_payload)
    result_failed = evidence.status is OsUpgradePreflightStatus.FAILED
    if recap_failed != result_failed or (exit_code == 0) == result_failed:
        raise AnsibleError("Ansible OS-upgrade preflight exit status conflicts")
    return evidence


def _role_gates(
    role: HostRole,
    logical_id: str,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    prerequisites: OsUpgradePreflightPrerequisites,
    gates: dict[str, GateStatus],
    blockers: set[str],
) -> tuple[dict[str, str], bool]:
    provenance: dict[str, str] = {}
    if role is HostRole.SCYLLA:
        install = prerequisites.scylla_install
        configure = prerequisites.scylla_configure
        storage = prerequisites.storage_postcheck
        health = prerequisites.scylla_health
        rolling = prerequisites.scylla_rolling
        if any(item is None for item in (install, configure, storage, health, rolling)):
            raise StateConflictError(
                "OS-upgrade Scylla preflight evidence is incomplete"
            )
        assert install is not None
        assert configure is not None
        assert storage is not None
        assert health is not None
        assert rolling is not None
        _require_current_scylla(
            logical_id, observed, inventory, install, configure, storage, health
        )
        _validate_scylla_rolling(rolling, logical_id, health)
        gates.update(
            {
                "backup-policy": rolling.backup_policy,
                "capacity": rolling.capacity,
                "health": GateStatus.PASSED,
                "quorum": rolling.quorum,
                "replication": rolling.replication,
                "role-configuration": GateStatus.PASSED,
                "role-package": GateStatus.PASSED,
                "service": GateStatus.PASSED,
                "storage": GateStatus.PASSED,
                "topology-work": (
                    GateStatus.PASSED
                    if (
                        rolling.no_active_topology_work
                        and rolling.shutdown_not_started
                        and rolling.drain_not_started
                    )
                    else GateStatus.FAILED
                ),
            }
        )
        for status, failed_name, unknown_name in (
            (rolling.backup_policy, "backup-policy-failed", "backup-policy-unknown"),
            (rolling.capacity, "capacity-failed", "capacity-unknown"),
            (rolling.quorum, "quorum-failed", "quorum-unknown"),
            (rolling.replication, "replication-failed", "replication-unknown"),
        ):
            _add_status_blocker(
                blockers, status, failed=failed_name, unknown=unknown_name
            )
        if gates["topology-work"] is GateStatus.FAILED:
            blockers.add("topology-work-active")
        provenance.update(
            {
                "scylla_configure_digest": _object_digest(
                    _scylla_configure_object(configure)
                ),
                "scylla_health_digest": rolling.health_digest,
                "scylla_install_digest": _object_digest(
                    _scylla_install_object(install)
                ),
                "scylla_rolling_digest": rolling.digest,
                "storage_postcheck_digest": _object_digest(_storage_object(storage)),
                "topology_digest": rolling.topology_digest,
            }
        )
        rolling_ready = (
            all(
                status is GateStatus.PASSED
                for status in (
                    rolling.backup_policy,
                    rolling.capacity,
                    rolling.quorum,
                    rolling.replication,
                )
            )
            and gates["topology-work"] is GateStatus.PASSED
        )
    elif role is HostRole.MANAGER:
        server = prerequisites.manager_server
        if server is None:
            raise StateConflictError(
                "OS-upgrade Manager preflight evidence is incomplete"
            )
        _require_current_manager(logical_id, observed, inventory, server)
        gates.update(
            {
                "health": GateStatus.NOT_PERFORMED,
                "role-configuration": GateStatus.UNKNOWN,
                "role-package": GateStatus.PASSED,
                "service": GateStatus.UNKNOWN,
                "storage": GateStatus.NOT_PERFORMED,
                "topology-work": GateStatus.NOT_PERFORMED,
            }
        )
        blockers.update(
            {
                "manager-backend-unconfigured",
                "manager-health-not-performed",
                "manager-service-not-started",
            }
        )
        provenance["manager_server_digest"] = _object_digest(
            _manager_server_object(server)
        )
        rolling_ready = False
    elif role is HostRole.MONITORING:
        stack = prerequisites.monitoring_stack
        targets = prerequisites.monitoring_targets
        if stack is None or targets is None:
            raise StateConflictError(
                "OS-upgrade monitoring preflight evidence is incomplete"
            )
        _require_current_monitoring(logical_id, observed, inventory, stack, targets)
        gates.update(
            {
                "health": GateStatus.NOT_PERFORMED,
                "role-configuration": GateStatus.PASSED,
                "role-package": GateStatus.PASSED,
                "service": GateStatus.UNKNOWN,
                "storage": GateStatus.NOT_PERFORMED,
                "topology-work": GateStatus.NOT_PERFORMED,
            }
        )
        blockers.update(
            {"monitoring-health-not-performed", "monitoring-stack-not-started"}
        )
        provenance.update(
            {
                "monitoring_stack_digest": _object_digest(
                    _monitoring_stack_object(stack)
                ),
                "monitoring_targets_digest": _object_digest(
                    _monitoring_targets_object(targets)
                ),
            }
        )
        rolling_ready = False
    else:
        jump = prerequisites.jump_host_configure
        if jump is None:
            raise StateConflictError(
                "OS-upgrade jump-host preflight evidence is incomplete"
            )
        _require_current_jump(logical_id, observed, inventory, jump)
        gates.update(
            {
                "health": GateStatus.NOT_PERFORMED,
                "role-configuration": GateStatus.PASSED,
                "role-package": GateStatus.PASSED,
                "service": GateStatus.PASSED,
                "storage": GateStatus.NOT_PERFORMED,
                "topology-work": GateStatus.NOT_PERFORMED,
            }
        )
        provenance["jump_host_configure_digest"] = _object_digest(_jump_object(jump))
        rolling_ready = True
    rolling_ready = (
        rolling_ready
        and prerequisites.role_safety.route is GateStatus.PASSED
        and prerequisites.role_safety.availability is GateStatus.PASSED
    )
    return provenance, rolling_ready


def _require_current_scylla(
    logical_id: str,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    install: ScyllaInstallEvidence,
    configure: ScyllaConfigureEvidence,
    storage: StoragePostcheckEvidence,
    health: ScyllaHealthEvidence,
) -> None:
    install_provenance = dict(install.provenance)
    config_provenance = dict(configure.prerequisite_digests)
    storage_provenance = dict(storage.provenance)
    expected_ids = tuple(
        host.logical_id
        for host in inventory.record.inventory.hosts
        if host.role is HostRole.SCYLLA
    )
    health_provenance = dict(health.provenance)
    target_health = next(
        (node for node in health.nodes if node.logical_id == logical_id), None
    )
    if (
        install.logical_id != logical_id
        or install.status
        not in {ScyllaInstallStatus.INSTALLED, ScyllaInstallStatus.NO_CHANGE}
        or not install.requested_version.startswith(f"{SCYLLA_RELEASE_LINE}.")
        or install.installed_version != install.requested_version
        or install_provenance.get("inventory_digest") != inventory.digest
        or install_provenance.get("observation_digest") != observed.digest
        or configure.logical_id != logical_id
        or configure.status
        not in {ScyllaConfigureStatus.CHANGED, ScyllaConfigureStatus.NOOP}
        or configure.installed_version != install.installed_version
        or config_provenance.get("inventory_digest") != inventory.digest
        or config_provenance.get("observation_digest") != observed.digest
        or storage.logical_id != logical_id
        or not storage.readiness_for_scylla
        or storage.blockers
        or storage_provenance.get("inventory_digest") != inventory.digest
        or storage_provenance.get("observation_digest") != observed.digest
        or health.query_policy != "all-nodes-cross-view"
        or health.queried_nodes != expected_ids
        or tuple(node.logical_id for node in health.nodes) != expected_ids
        or target_health is None
        or health.schema_agreement is not True
        or health.schema_digest is None
        or health.topology_digest is None
        or health.streaming_state != "complete"
        or health_provenance.get("inventory_digest") != inventory.digest
        or health_provenance.get("observation_digest") != observed.digest
        or any(
            node.state != "UN"
            or node.host_id is None
            or node.service_state != "active"
            or node.cql_reachable is not True
            or node.api_reachable is not True
            or not node.storage_ready
            for node in health.nodes
        )
    ):
        raise StateConflictError(
            "OS-upgrade preflight requires current complete Scylla evidence"
        )


def _require_current_manager(
    logical_id: str,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    server: ManagerServerEvidence,
) -> None:
    provenance = dict(server.provenance)
    if (
        server.logical_id != logical_id
        or server.status
        not in {ManagerServerStatus.INSTALLED, ManagerServerStatus.NO_CHANGE}
        or server.installed_version != server.requested_version
        or server.service_masked is not True
        or server.service_inactive is not True
        or server.service_started
        or server.backend_configured
        or server.registration_performed
        or provenance.get("inventory_digest") != inventory.digest
        or provenance.get("observation_digest") != observed.digest
    ):
        raise StateConflictError(
            "OS-upgrade preflight requires current Manager package evidence"
        )


def _require_current_monitoring(
    logical_id: str,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    stack: MonitoringStackEvidence,
    targets: MonitoringTargetsEvidence,
) -> None:
    stack_provenance = dict(stack.provenance)
    target_provenance = dict(targets.provenance)
    if (
        stack.logical_id != logical_id
        or stack.status
        not in {MonitoringStackStatus.INSTALLED, MonitoringStackStatus.NO_CHANGE}
        or stack.installed_version != stack.requested_version
        or stack.containers_started
        or stack_provenance.get("inventory_digest") != inventory.digest
        or stack_provenance.get("observation_digest") != observed.digest
        or targets.logical_id != logical_id
        or targets.status
        not in {MonitoringTargetsStatus.GENERATED, MonitoringTargetsStatus.NO_CHANGE}
        or targets.stack_started
        or targets.containers_started
        or target_provenance.get("inventory_digest") != inventory.digest
        or target_provenance.get("observation_digest") != observed.digest
    ):
        raise StateConflictError(
            "OS-upgrade preflight requires current monitoring evidence"
        )


def _require_current_jump(
    logical_id: str,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    jump: JumpHostConfigureEvidence,
) -> None:
    provenance = dict(jump.provenance_digests)
    if (
        jump.logical_id != logical_id
        or jump.status
        not in {JumpHostConfigureStatus.CHANGED, JumpHostConfigureStatus.NOOP}
        or not jump.validation_performed
        or jump.validation_passed is not True
        or provenance.get("inventory_digest") != inventory.digest
        or provenance.get("observation_digest") != observed.digest
    ):
        raise StateConflictError(
            "OS-upgrade preflight requires current jump-host configuration evidence"
        )


def _validate_scylla_rolling(
    value: ScyllaRollingSafetyEvidence,
    logical_id: str,
    health: ScyllaHealthEvidence,
) -> None:
    values = {
        "backup_policy": value.backup_policy.value,
        "capacity": value.capacity.value,
        "drain_not_started": value.drain_not_started,
        "health_digest": value.health_digest,
        "logical_id": value.logical_id,
        "no_active_topology_work": value.no_active_topology_work,
        "quorum": value.quorum.value,
        "replication": value.replication.value,
        "shutdown_not_started": value.shutdown_not_started,
        "topology_digest": value.topology_digest,
    }
    if (
        value.logical_id != logical_id
        or value.health_digest != scylla_health_evidence_digest(health)
        or value.topology_digest != health.topology_digest
        or value.digest != _object_digest(values)
    ):
        raise StateConflictError("OS-upgrade Scylla rolling evidence conflicts")


def _provider_gate(intent: OsUpgradePreflightIntent, architecture: str) -> GateStatus:
    image = intent.provider_image
    if image is None:
        return GateStatus.NOT_PERFORMED
    if (
        image.operating_system != intent.target_operating_system
        or image.operating_system_version != intent.target_operating_system_version
        or image.architecture != architecture
        or not image.available
        or not image.replacement_plan_reviewed
    ):
        return GateStatus.FAILED
    return GateStatus.PASSED


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> OsUpgradePreflightEvidence:
    fields = {
        "architecture",
        "blockers",
        "current_operating_system",
        "current_operating_system_version",
        "gates",
        "logical_id",
        "not_performed",
        "provenance",
        "requested_strategy",
        "role",
        "rolling_eligible",
        "schema_version",
        "selected_path",
        "status",
        "target_operating_system",
        "target_operating_system_version",
        "transition_classification",
    }
    if (
        set(value) != fields
        or value["schema_version"] != OS_UPGRADE_PREFLIGHT_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible OS-upgrade preflight evidence schema is invalid")
    for name in (
        "architecture",
        "current_operating_system",
        "current_operating_system_version",
        "logical_id",
        "requested_strategy",
        "role",
        "selected_path",
        "target_operating_system",
        "target_operating_system_version",
        "transition_classification",
    ):
        if value[name] != expected[name]:
            raise AnsibleError("Ansible OS-upgrade preflight evidence conflicts")
    try:
        status = OsUpgradePreflightStatus(_text(value["status"]))
        role = HostRole(_text(value["role"]))
        transition = TransitionClassification(_text(value["transition_classification"]))
    except ValueError as error:
        raise AnsibleError("Ansible OS-upgrade preflight status is invalid") from error
    if value["selected_path"] != "not-performed":
        raise AnsibleError("Ansible OS-upgrade preflight selected an unavailable path")
    blockers = _sorted_strings(value["blockers"], name="blockers")
    if not blockers or not set(blockers) <= _BLOCKERS:
        raise AnsibleError("Ansible OS-upgrade preflight blockers are invalid")
    expected_controller = set(
        _sorted_strings(expected["controller_blockers"], name="controller-blockers")
    )
    if status is OsUpgradePreflightStatus.BLOCKED and not expected_controller <= set(
        blockers
    ):
        raise AnsibleError(
            "Ansible OS-upgrade preflight controller blockers were omitted"
        )
    if status is OsUpgradePreflightStatus.FAILED and not (
        {"execution-failed", "host-unreachable"} & set(blockers)
    ):
        raise AnsibleError("Ansible OS-upgrade preflight failure evidence conflicts")
    not_performed = _sorted_strings(value["not_performed"], name="not-performed")
    if not_performed != NOT_PERFORMED:
        raise AnsibleError("Ansible OS-upgrade preflight not-performed set is invalid")
    provenance_value = value["provenance"]
    if (
        not isinstance(provenance_value, dict)
        or provenance_value != expected["provenance"]
    ):
        raise AnsibleError("Ansible OS-upgrade preflight provenance conflicts")
    provenance = tuple(
        sorted(
            (_text(name), _require_digest(item))
            for name, item in provenance_value.items()
        )
    )
    gates = _parse_gates(value["gates"], expected, status)
    if status is OsUpgradePreflightStatus.BLOCKED:
        _validate_host_gate_blockers(gates, blockers)
    rolling_eligible = _require_bool(value["rolling_eligible"])
    if (
        status is OsUpgradePreflightStatus.BLOCKED
        and rolling_eligible is not _require_bool(expected["rolling_eligible"])
    ) or (status is OsUpgradePreflightStatus.FAILED and rolling_eligible):
        raise AnsibleError("Ansible OS-upgrade preflight rolling eligibility conflicts")
    if status is OsUpgradePreflightStatus.BLOCKED and transition not in {
        TransitionClassification.UNDEFINED,
        TransitionClassification.UNSUPPORTED,
    }:
        raise AnsibleError("Ansible OS-upgrade transition classification is invalid")
    _reject_secrets(value)
    return OsUpgradePreflightEvidence(
        _text(value["logical_id"]),
        role,
        status,
        transition,
        _text(value["requested_strategy"]),
        "not-performed",
        _text(value["current_operating_system"]),
        _text(value["current_operating_system_version"]),
        _text(value["target_operating_system"]),
        _text(value["target_operating_system_version"]),
        _text(value["architecture"]),
        rolling_eligible,
        gates,
        not_performed,
        provenance,
        blockers,
    )


def _parse_gates(
    value: object,
    expected: dict[str, object],
    status: OsUpgradePreflightStatus,
) -> tuple[OsUpgradeGateEvidence, ...]:
    if not isinstance(value, list) or len(value) != len(GATE_NAMES):
        raise AnsibleError("Ansible OS-upgrade preflight gates are incomplete")
    expected_values = {
        _text(cast(dict[str, object], item)["name"]): _text(
            cast(dict[str, object], item)["status"]
        )
        for item in cast(list[object], expected["controller_gates"])
    }
    gates: list[OsUpgradeGateEvidence] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"name", "status"}:
            raise AnsibleError("Ansible OS-upgrade preflight gate schema is invalid")
        name = _text(item["name"])
        try:
            gate_status = GateStatus(_text(item["status"]))
        except ValueError as error:
            raise AnsibleError(
                "Ansible OS-upgrade preflight gate status is invalid"
            ) from error
        if name not in GATE_NAMES or name in {gate.name for gate in gates}:
            raise AnsibleError("Ansible OS-upgrade preflight gate name is invalid")
        if (
            status is OsUpgradePreflightStatus.BLOCKED
            and name not in HOST_GATE_NAMES
            and gate_status.value != expected_values[name]
        ):
            raise AnsibleError("Ansible OS-upgrade preflight controller gate conflicts")
        gates.append(OsUpgradeGateEvidence(name, gate_status))
    if tuple(gate.name for gate in gates) != GATE_NAMES:
        raise AnsibleError("Ansible OS-upgrade preflight gates are not ordered")
    return tuple(gates)


def _validate_host_gate_blockers(
    gates: tuple[OsUpgradeGateEvidence, ...], blockers: tuple[str, ...]
) -> None:
    statuses = {gate.name: gate.status for gate in gates}
    blocker_set = set(blockers)
    rules: dict[str, dict[GateStatus, str | None]] = {
        "architecture": {
            GateStatus.FAILED: "architecture-mismatch",
            GateStatus.PASSED: None,
        },
        "boot-space": {
            GateStatus.FAILED: "boot-space-insufficient",
            GateStatus.PASSED: None,
        },
        "broken-packages": {
            GateStatus.FAILED: "broken-packages",
            GateStatus.PASSED: None,
        },
        "kernel-family": {
            GateStatus.FAILED: "kernel-family-unsupported",
            GateStatus.PASSED: None,
        },
        "package-locks": {
            GateStatus.FAILED: "package-manager-lock-held",
            GateStatus.UNKNOWN: "package-lock-evidence-unknown",
            GateStatus.PASSED: None,
        },
        "reboot-required": {
            GateStatus.FAILED: "reboot-required",
            GateStatus.PASSED: None,
        },
        "root-space": {
            GateStatus.FAILED: "root-space-insufficient",
            GateStatus.PASSED: None,
        },
    }
    all_host_blockers = {
        blocker for values in rules.values() for blocker in values.values() if blocker
    }
    expected_host_blockers: set[str] = set()
    for name, allowed in rules.items():
        status = statuses[name]
        if status not in allowed:
            raise AnsibleError(
                "Ansible OS-upgrade preflight host gate status is invalid"
            )
        blocker = allowed[status]
        if blocker is not None:
            expected_host_blockers.add(blocker)
    if blocker_set & all_host_blockers != expected_host_blockers:
        raise AnsibleError("Ansible OS-upgrade preflight host gate blockers conflict")


def _failed_evidence(
    expected: dict[str, object], *, unreachable: bool
) -> OsUpgradePreflightEvidence:
    gates = tuple(
        OsUpgradeGateEvidence(name, GateStatus.UNKNOWN) for name in GATE_NAMES
    )
    provenance = cast(dict[str, object], expected["provenance"])
    return OsUpgradePreflightEvidence(
        _text(expected["logical_id"]),
        HostRole(_text(expected["role"])),
        OsUpgradePreflightStatus.FAILED,
        TransitionClassification(_text(expected["transition_classification"])),
        _text(expected["requested_strategy"]),
        "not-performed",
        _text(expected["current_operating_system"]),
        _text(expected["current_operating_system_version"]),
        _text(expected["target_operating_system"]),
        _text(expected["target_operating_system_version"]),
        _text(expected["architecture"]),
        False,
        gates,
        NOT_PERFORMED,
        tuple(
            sorted(
                (_text(name), _require_digest(item))
                for name, item in provenance.items()
            )
        ),
        ("host-unreachable" if unreachable else "execution-failed",),
    )


def _validate_intent(
    metadata: ClusterMetadata, intent: OsUpgradePreflightIntent
) -> None:
    try:
        valid_operation = str(uuid.UUID(intent.operation_id)) == intent.operation_id
    except ValueError:
        valid_operation = False
    _require_logical_id(intent.logical_id)
    _validate_os_target(
        intent.target_operating_system, intent.target_operating_system_version
    )
    expected_space_digest = os_upgrade_space_policy_digest(
        intent.minimum_root_free_bytes, intent.minimum_boot_free_bytes
    )
    if intent.package_policy_digest is not None:
        _require_digest(intent.package_policy_digest)
    provider_digest = None
    if intent.provider_image is not None:
        _validate_provider_image_facts(intent.provider_image)
        provider_digest = intent.provider_image.digest
    valid_strategy_inputs = (
        (intent.strategy == "auto" and intent.package_policy_digest is not None)
        or (
            intent.strategy == "in-place"
            and intent.package_policy_digest is not None
            and intent.provider_image is None
        )
        or (
            intent.strategy == "reprovision"
            and intent.package_policy_digest is None
            and intent.provider_image is not None
        )
    )
    values = {
        "cluster_uuid": intent.cluster_uuid,
        "logical_id": intent.logical_id,
        "max_unavailable": intent.max_unavailable,
        "minimum_boot_free_bytes": intent.minimum_boot_free_bytes,
        "minimum_root_free_bytes": intent.minimum_root_free_bytes,
        "no_competing_operation": intent.no_competing_operation,
        "operation_id": intent.operation_id,
        "package_policy_digest": intent.package_policy_digest,
        "provider_image_digest": provider_digest,
        "space_policy_digest": intent.space_policy_digest,
        "strategy": intent.strategy,
        "target_operating_system": intent.target_operating_system,
        "target_operating_system_version": intent.target_operating_system_version,
    }
    if (
        not valid_operation
        or intent.cluster_uuid != str(metadata.cluster_uuid)
        or intent.strategy not in STRATEGIES
        or not valid_strategy_inputs
        or intent.max_unavailable != 1
        or not intent.no_competing_operation
        or intent.space_policy_digest != expected_space_digest
        or intent.digest != _object_digest(values)
    ):
        raise StateConflictError("OS-upgrade preflight intent binding conflicts")


def _validate_provider_image_facts(value: OsUpgradeProviderImageFacts) -> None:
    values = {
        "architecture": value.architecture,
        "available": value.available,
        "image_id_digest": _require_digest(value.image_id_digest),
        "operating_system": value.operating_system,
        "operating_system_version": value.operating_system_version,
        "replacement_plan_reviewed": value.replacement_plan_reviewed,
        "source_digest": _require_digest(value.source_digest),
    }
    _validate_os_target(value.operating_system, value.operating_system_version)
    if (
        value.architecture not in SUPPORTED_ARCHITECTURES
        or value.digest != _object_digest(values)
    ):
        raise StateConflictError("OS-upgrade provider image facts conflict")


def _validate_role_safety(value: OsUpgradeRoleSafetyEvidence) -> None:
    values = {
        "availability": value.availability.value,
        "logical_id": value.logical_id,
        "role": value.role.value,
        "route": value.route.value,
    }
    if value.digest != _object_digest(values):
        raise StateConflictError("OS-upgrade role safety evidence conflicts")


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


def _parse_recap(stdout: str) -> dict[str, tuple[int, int, int]]:
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible OS-upgrade preflight output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible OS-upgrade preflight recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    return rows


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


def _scylla_install_object(value: ScyllaInstallEvidence) -> dict[str, object]:
    return {
        "installed_version": value.installed_version,
        "logical_id": value.logical_id,
        "packages": list(value.packages),
        "provenance": dict(value.provenance),
        "requested_version": value.requested_version,
        "schema_version": value.schema_version,
        "status": value.status.value,
    }


def _scylla_configure_object(value: ScyllaConfigureEvidence) -> dict[str, object]:
    return {
        "bootstrap_performed": value.bootstrap_performed,
        "config_digest": value.config_digest,
        "configuration_file_digests": dict(value.configuration_file_digests),
        "files_mode_0644": value.files_mode_0644,
        "files_root_owned": value.files_root_owned,
        "firewall_operation_performed": value.firewall_operation_performed,
        "installed_version": value.installed_version,
        "logical_id": value.logical_id,
        "manager_operation_performed": value.manager_operation_performed,
        "package_install_performed": value.package_install_performed,
        "prerequisite_digests": dict(value.prerequisite_digests),
        "schema_version": value.schema_version,
        "service_started": value.service_started,
        "ssh_operation_performed": value.ssh_operation_performed,
        "status": value.status.value,
        "storage_mutation_performed": value.storage_mutation_performed,
        "topology_digest": value.topology_digest,
        "tuning_performed": value.tuning_performed,
    }


def _storage_object(value: StoragePostcheckEvidence) -> dict[str, object]:
    return {
        "backend": value.backend,
        "blockers": list(value.blockers),
        "logical_id": value.logical_id,
        "provenance": dict(value.provenance),
        "readiness_for_scylla": value.readiness_for_scylla,
        "schema_version": value.schema_version,
    }


def _manager_server_object(value: ManagerServerEvidence) -> dict[str, object]:
    return {
        "backend_configured": value.backend_configured,
        "installed_version": value.installed_version,
        "logical_id": value.logical_id,
        "packages": list(value.packages),
        "provenance": dict(value.provenance),
        "schema_version": value.schema_version,
        "service_inactive": value.service_inactive,
        "service_masked": value.service_masked,
        "status": value.status.value,
    }


def _monitoring_stack_object(value: MonitoringStackEvidence) -> dict[str, object]:
    return {
        "containers_started": value.containers_started,
        "installed_version": value.installed_version,
        "logical_id": value.logical_id,
        "provenance": dict(value.provenance),
        "schema_version": value.schema_version,
        "status": value.status.value,
    }


def _monitoring_targets_object(
    value: MonitoringTargetsEvidence,
) -> dict[str, object]:
    return {
        "containers_started": value.containers_started,
        "logical_id": value.logical_id,
        "provenance": dict(value.provenance),
        "schema_version": value.schema_version,
        "stack_started": value.stack_started,
        "status": value.status.value,
    }


def _jump_object(value: JumpHostConfigureEvidence) -> dict[str, object]:
    return {
        "config_digest": value.config_digest,
        "logical_id": value.logical_id,
        "provenance": dict(value.provenance_digests),
        "schema_version": value.schema_version,
        "status": value.status.value,
        "validation_passed": value.validation_passed,
        "validation_performed": value.validation_performed,
    }


def _validate_os_target(operating_system: str, version: str) -> None:
    if (
        not isinstance(operating_system, str)
        or _OS_NAME.fullmatch(operating_system) is None
        or not isinstance(version, str)
        or _OS_VERSION.fullmatch(version) is None
    ):
        raise AnsibleError("OS-upgrade target OS evidence is invalid")


def _require_logical_id(value: str) -> str:
    if _LOGICAL_ID.fullmatch(value) is None:
        raise AnsibleError("OS-upgrade stable logical ID is invalid")
    return value


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
                "Ansible OS-upgrade preflight evidence has duplicate fields"
            )
        value[key] = item
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible OS-upgrade preflight value is invalid")
    return value


def _require_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError("Ansible OS-upgrade preflight boolean is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible OS-upgrade preflight digest is invalid")
    return text


def _sorted_strings(value: object, *, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError(f"Ansible OS-upgrade preflight {name} are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError(
            f"Ansible OS-upgrade preflight {name} are not uniquely sorted"
        )
    return items


def _reject_secrets(value: dict[str, object]) -> None:
    encoded = json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True)
    if re.search(
        r"(?i)(?:-----BEGIN [^-]*PRIVATE KEY-----|"
        r"(?:password|passphrase|secret|token)\s*[:=])",
        encoded,
    ):
        raise AnsibleError("Ansible OS-upgrade preflight evidence contains a secret")
