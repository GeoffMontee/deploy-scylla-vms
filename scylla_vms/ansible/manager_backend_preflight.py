"""Strict read-only evidence for later Manager local-backend planning."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum, StrEnum
from typing import cast

from scylla_vms.ansible.base_os import BaseOsEvidence, BaseOsStatus
from scylla_vms.ansible.deploy_manager_backend_configuration_plan import (
    DeployManagerBackendConfigurationDecisionState,
    DeployManagerBackendConfigurationGateState,
    DeployManagerBackendConfigurationPlanStatus,
    DeployManagerBackendMode,
    StoredDeployManagerBackendConfigurationContext,
    StoredDeployManagerBackendConfigurationPlan,
)
from scylla_vms.ansible.manager_server import (
    MANAGER_PACKAGE_VERSION,
    MANAGER_PACKAGES,
    ManagerServerEvidence,
    ManagerServerStatus,
)
from scylla_vms.ansible.orchestration import ansible_operation_catalog_digest
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.desired import ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata

MANAGER_BACKEND_PREFLIGHT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-manager-backend-preflight/v1"
)
MANAGER_BACKEND_MODE = "local-one-node"
MANAGER_BACKEND_SCYLLA_RELEASE = "2026.2"
MANAGER_BACKEND_CQL_PORT = 9042
MANAGER_BACKEND_LOCAL_PACKAGES = ("scylla", "scylla-server")
MANAGER_BACKEND_MANAGER_SERVICE = "scylla-manager.service"
MANAGER_BACKEND_SCYLLA_SERVICE = "scylla-server.service"
MANAGER_BACKEND_NOT_PERFORMED = (
    "cloud-metadata-access",
    "configuration-read",
    "configuration-write",
    "cql-connection",
    "environment-collection",
    "network-connection",
    "package-installation",
    "package-repository-query",
    "process-command-collection",
    "schema-creation",
    "schema-query",
    "scyllamgr-setup",
    "service-mutation",
    "service-start",
)
MANAGER_BACKEND_UNRESOLVED_BLOCKERS = (
    "manager-backend-capacity-policy-unknown",
    "manager-backend-configuration-source-unavailable",
    "manager-backend-package-availability-unknown",
    "manager-backend-recovery-semantics-unapproved",
    "manager-backend-schema-bootstrap-unapproved",
    "manager-backend-setup-behavior-unapproved",
    "manager-backend-storage-suitability-unknown",
    "manager-backend-tuning-suitability-unknown",
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MARKER = re.compile(
    r"DSV_MANAGER_BACKEND_PREFLIGHT_B64=(?P<data>[A-Za-z0-9+/]+={0,2})"
)
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_OBSERVED_BLOCKERS = frozenset(
    {
        "approved-mount-unavailable",
        "architecture-mismatch",
        "capacity-evidence-unavailable",
        "execution-failed",
        "local-scylla-package-present",
        "local-scylla-service-state-unsafe",
        "loopback-unavailable",
        "manager-package-mismatch",
        "manager-service-state-unsafe",
        "operating-system-mismatch",
        "reboot-required",
    }
)
_BLOCKERS = frozenset(MANAGER_BACKEND_UNRESOLVED_BLOCKERS) | _OBSERVED_BLOCKERS


class ManagerBackendPreflightStatus(StrEnum):
    """Whether bounded host evidence can inform a later installation plan."""

    EVIDENCE_READY = "evidence-ready"
    BLOCKED = "blocked"
    FAILED = "failed"


class ManagerBackendPackageStatus(StrEnum):
    """Bounded local package-database state."""

    INSTALLED = "installed"
    NOT_INSTALLED = "not-installed"
    PARTIAL = "partial"
    MISMATCH = "mismatch"
    UNKNOWN = "unknown"


class ManagerBackendServiceStatus(StrEnum):
    """Bounded state for one fixed service unit."""

    ABSENT = "absent"
    MASKED_INACTIVE = "masked-inactive"
    DISABLED_INACTIVE = "disabled-inactive"
    ENABLED_INACTIVE = "enabled-inactive"
    ACTIVE = "active"
    UNKNOWN = "unknown"


class ManagerBackendLoopbackStatus(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ManagerBackendCapacityEvidence:
    cpu_count: int | None
    memory_bytes: int | None
    root_total_bytes: int | None
    root_free_bytes: int | None
    approved_mount_count: int | None
    available_mount_count: int | None


@dataclass(frozen=True, slots=True)
class ManagerBackendPreflightEvidence:
    """Strict address-free result; this is not backend readiness."""

    logical_id: str
    role: str
    status: ManagerBackendPreflightStatus
    backend_mode: str
    scylla_release: str
    operating_system: str
    operating_system_version: str
    architecture: str
    capacity: ManagerBackendCapacityEvidence
    manager_package_status: ManagerBackendPackageStatus
    local_scylla_package_status: ManagerBackendPackageStatus
    package_availability_status: str
    manager_service_status: ManagerBackendServiceStatus
    local_scylla_service_status: ManagerBackendServiceStatus
    reboot_required: bool | None
    loopback_policy_status: ManagerBackendLoopbackStatus
    configuration_status: str
    schema_status: str
    operational_readiness: str
    not_performed: tuple[str, ...]
    provenance: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]
    schema_version: str = MANAGER_BACKEND_PREFLIGHT_SCHEMA_VERSION


def build_manager_backend_preflight_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    base_os: BaseOsEvidence,
    manager_server: ManagerServerEvidence,
    backend_context: StoredDeployManagerBackendConfigurationContext,
    backend_plan: StoredDeployManagerBackendConfigurationPlan,
    *,
    logical_id: str,
    image_filter: ImageFilter,
    architecture: str,
) -> dict[str, object]:
    """Build one exact, read-only Manager local-backend preflight request."""

    if _LOGICAL_ID.fullmatch(logical_id) is None:
        raise StateConflictError("Manager backend preflight target is invalid")
    if image_filter != ImageFilter(
        "Ubuntu", "24.04", ImageVersionMatch.EXACT
    ) or architecture not in {"amd64", "aarch64"}:
        raise StateConflictError(
            "Manager backend preflight requires exact Ubuntu 24.04 evidence"
        )
    if (
        len(base_os.hosts) != 1
        or base_os.hosts[0].logical_id != logical_id
        or base_os.hosts[0].status not in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
        or base_os.hosts[0].reboot_required
    ):
        raise StateConflictError(
            "Manager backend preflight requires successful current base-os"
        )
    if (
        manager_server.logical_id != logical_id
        or manager_server.status
        not in {ManagerServerStatus.INSTALLED, ManagerServerStatus.NO_CHANGE}
        or manager_server.requested_version != MANAGER_PACKAGE_VERSION
        or manager_server.installed_version != MANAGER_PACKAGE_VERSION
        or not manager_server.service_masked
        or not manager_server.service_inactive
        or manager_server.service_started
        or manager_server.backend_configured
        or manager_server.configuration_performed
        or manager_server.registration_performed
        or manager_server.setup_performed
        or manager_server.tasks_performed
        or manager_server.blockers
    ):
        raise StateConflictError(
            "Manager backend preflight requires current install-only Manager evidence"
        )

    record = inventory.record
    context = backend_context.record
    plan = backend_plan.record
    manager_ids = tuple(
        sorted(
            host.logical_id
            for host in record.inventory.hosts
            if host.role.value == "manager"
        )
    )
    if manager_ids != (logical_id,):
        raise StateConflictError(
            "Manager backend preflight requires the exact single manager target"
        )
    if (
        metadata.cluster_uuid != record.cluster_uuid
        or metadata.cluster_name != record.cluster_name
        or observed.record.cluster_uuid != record.cluster_uuid
        or readiness.observation_generation != observed.record.generation
        or readiness.observation_digest != observed.record.manifest_digest
        or readiness.inventory_generation != record.generation
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_generation is None
        or readiness.trust_digest is None
    ):
        raise StateConflictError("Manager backend preflight input provenance conflicts")

    manager_server_provenance = {
        "base_os_digest": _manager_server_base_os_digest(base_os),
        "cluster_spec_digest": context.desired_spec_digest,
        "inventory_digest": inventory.digest,
        "observation_digest": observed.digest,
        "trust_digest": readiness.trust_digest,
    }
    if manager_server.provenance != tuple(sorted(manager_server_provenance.items())):
        raise StateConflictError(
            "Manager backend preflight Manager-server evidence provenance conflicts"
        )

    source = load_ansible_source_bundle()
    if (
        context.ansible_source_version != source.version
        or context.ansible_source_digest != source.digest
        or context.catalog_digest != ansible_operation_catalog_digest()
    ):
        raise StateConflictError(
            "Manager backend preflight source provenance conflicts"
        )

    backend_mode_gates = tuple(
        gate for gate in context.gates if gate.name == "backend-mode"
    )
    policy = context.intent.backend_policy
    if (
        context.cluster_uuid != metadata.cluster_uuid
        or context.cluster_name != metadata.cluster_name
        or context.manager_target_id != logical_id
        or context.observation_generation != observed.record.generation
        or context.observation_manifest_digest != observed.record.manifest_digest
        or context.inventory_generation != record.generation
        or context.inventory_artifact_digest != inventory.digest
        or context.trust_generation != readiness.trust_generation
        or context.trust_artifact_digest != readiness.trust_digest
        or context.manager_service_masked is not True
        or context.manager_service_inactive is not True
    ):
        raise StateConflictError(
            "Manager backend preflight context provenance conflicts"
        )
    if (
        context.intent.backend_mode
        is not DeployManagerBackendConfigurationDecisionState.APPROVED
        or context.intent.backend_mode_value
        is not DeployManagerBackendMode.LOCAL_ONE_NODE
        or policy.backend_mode is not DeployManagerBackendMode.LOCAL_ONE_NODE
        or policy.target_role != "manager"
        or policy.managed_data_cluster_backend != "forbidden"
        or policy.cql_network_ingress != "forbidden"
        or policy.contact_scope != "loopback-only"
        or policy.cql_port != MANAGER_BACKEND_CQL_PORT
        or policy.scylla_release != MANAGER_BACKEND_SCYLLA_RELEASE
        or policy.backend_credentials != "not-required"
        or policy.backend_tls != "not-required"
        or len(backend_mode_gates) != 1
        or backend_mode_gates[0].state
        is not DeployManagerBackendConfigurationGateState.PASSED
        or backend_mode_gates[0].evidence_digest != policy.policy_digest
        or backend_mode_gates[0].blocker is not None
    ):
        raise StateConflictError(
            "Manager backend preflight requires the selected local-one-node policy"
        )
    if (
        plan.cluster_uuid != metadata.cluster_uuid
        or plan.cluster_name != metadata.cluster_name
        or plan.operation_id != context.operation_id
        or plan.context_artifact_digest != backend_context.artifact_digest
        or plan.context_record_digest != context.record_digest
        or plan.manager_target_id != logical_id
        or context.status is not DeployManagerBackendConfigurationPlanStatus.BLOCKED
        or plan.passed_gate_count != context.passed_gate_count
        or plan.unknown_gate_count != context.unknown_gate_count
        or plan.blocked_gate_count != context.blocked_gate_count
        or plan.blocker_digest != context.blocker_digest
    ):
        raise StateConflictError(
            "Manager backend preflight context and plan provenance conflicts"
        )

    provenance = {
        "ansible_source_digest": context.ansible_source_digest,
        "backend_context_artifact_digest": backend_context.artifact_digest,
        "backend_context_record_digest": context.record_digest,
        "backend_plan_artifact_digest": backend_plan.artifact_digest,
        "backend_plan_digest": plan.plan_digest,
        "backend_policy_digest": policy.policy_digest,
        "base_os_digest": _object_digest(base_os),
        "desired_spec_digest": context.desired_spec_digest,
        "inventory_digest": inventory.digest,
        "manager_server_digest": _object_digest(manager_server),
        "manager_server_evidence_digest": context.manager_server_evidence_digest,
        "observation_digest": observed.digest,
        "trust_digest": readiness.trust_digest,
    }
    return {
        "architecture": architecture,
        "backend_policy": policy.to_object(),
        "cluster_uuid": str(metadata.cluster_uuid),
        "expected_manager_package_version": MANAGER_PACKAGE_VERSION,
        "guest_architecture": "x86_64" if architecture == "amd64" else "aarch64",
        "local_scylla_packages": list(MANAGER_BACKEND_LOCAL_PACKAGES),
        "local_scylla_service": MANAGER_BACKEND_SCYLLA_SERVICE,
        "logical_id": logical_id,
        "manager_packages": list(MANAGER_PACKAGES),
        "manager_service": MANAGER_BACKEND_MANAGER_SERVICE,
        "not_performed": list(MANAGER_BACKEND_NOT_PERFORMED),
        "operating_system": "Ubuntu",
        "operating_system_version": "24.04",
        "provenance": provenance,
        "role": "manager",
        "schema_version": MANAGER_BACKEND_PREFLIGHT_SCHEMA_VERSION,
        "unresolved_blockers": list(MANAGER_BACKEND_UNRESOLVED_BLOCKERS),
    }


def parse_manager_backend_preflight_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> ManagerBackendPreflightEvidence:
    """Parse only one strict normalized marker and one exact recap row."""

    if len(stdout.encode("utf-8")) > 256 * 1024:
        raise AnsibleError("Ansible Manager backend preflight output is too large")
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_MANAGER_BACKEND_PREFLIGHT_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible Manager backend preflight marker is malformed")
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"), object_pairs_hook=_strict_object
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible Manager backend preflight marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible Manager backend preflight evidence is invalid")
        values.append(value)

    before_recap, separator, after_recap = stdout.partition("PLAY RECAP")
    del before_recap
    if not separator:
        raise AnsibleError("Ansible Manager backend preflight omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in after_recap.splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible Manager backend preflight recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    logical_id = _text(expected_payload["logical_id"])
    if set(rows) != {logical_id}:
        raise AnsibleError(
            "Ansible Manager backend preflight recap membership conflicts"
        )
    changed, unreachable, failed = rows[logical_id]
    recap_failed = bool(unreachable or failed)
    if changed:
        raise AnsibleError("Ansible Manager backend preflight reported a mutation")
    if not values:
        if not recap_failed or exit_code == 0:
            raise AnsibleError(
                "Ansible Manager backend preflight evidence is incomplete"
            )
        return _failed_evidence(expected_payload)
    if len(values) != 1:
        raise AnsibleError("Ansible Manager backend preflight evidence is duplicated")

    evidence = _parse_result(values[0], expected_payload)
    result_failed = evidence.status is ManagerBackendPreflightStatus.FAILED
    if recap_failed != result_failed or (exit_code == 0) == result_failed:
        raise AnsibleError("Ansible Manager backend preflight exit status conflicts")
    return evidence


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> ManagerBackendPreflightEvidence:
    expected_fields = {
        "architecture",
        "backend_mode",
        "blockers",
        "capacity",
        "configuration_status",
        "local_scylla_package_status",
        "local_scylla_service_status",
        "logical_id",
        "loopback_policy_status",
        "manager_package_status",
        "manager_service_status",
        "not_performed",
        "operating_system",
        "operating_system_version",
        "operational_readiness",
        "package_availability_status",
        "provenance",
        "reboot_required",
        "role",
        "schema_status",
        "schema_version",
        "scylla_release",
        "status",
    }
    if (
        set(value) != expected_fields
        or value["schema_version"] != MANAGER_BACKEND_PREFLIGHT_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible Manager backend preflight schema is invalid")
    if (
        value["logical_id"] != expected["logical_id"]
        or value["role"] != "manager"
        or value["backend_mode"] != MANAGER_BACKEND_MODE
        or value["scylla_release"] != MANAGER_BACKEND_SCYLLA_RELEASE
        or value["operating_system"] != expected["operating_system"]
        or value["operating_system_version"] != expected["operating_system_version"]
        or value["architecture"] != expected["architecture"]
        or value["package_availability_status"] != "not-performed"
        or value["configuration_status"] != "not-inspected"
        or value["schema_status"] != "not-inspected"
        or value["operational_readiness"] != "not-performed"
    ):
        raise AnsibleError("Ansible Manager backend preflight evidence conflicts")

    try:
        status = ManagerBackendPreflightStatus(_text(value["status"]))
        manager_package = ManagerBackendPackageStatus(
            _text(value["manager_package_status"])
        )
        scylla_package = ManagerBackendPackageStatus(
            _text(value["local_scylla_package_status"])
        )
        manager_service = ManagerBackendServiceStatus(
            _text(value["manager_service_status"])
        )
        scylla_service = ManagerBackendServiceStatus(
            _text(value["local_scylla_service_status"])
        )
        loopback = ManagerBackendLoopbackStatus(_text(value["loopback_policy_status"]))
    except ValueError as error:
        raise AnsibleError(
            "Ansible Manager backend preflight enum is invalid"
        ) from error

    capacity = _parse_capacity(
        value["capacity"], failed=status is ManagerBackendPreflightStatus.FAILED
    )
    reboot_required = value["reboot_required"]
    if reboot_required is not None and not isinstance(reboot_required, bool):
        raise AnsibleError(
            "Ansible Manager backend preflight reboot evidence is invalid"
        )
    blockers = _sorted_strings(value["blockers"], "blockers")
    if not set(blockers) <= _BLOCKERS:
        raise AnsibleError("Ansible Manager backend preflight blocker is unknown")
    unresolved = set(MANAGER_BACKEND_UNRESOLVED_BLOCKERS)
    if not unresolved <= set(blockers):
        raise AnsibleError(
            "Ansible Manager backend preflight omitted unresolved design blockers"
        )
    not_performed = _sorted_strings(value["not_performed"], "not_performed")
    if not_performed != MANAGER_BACKEND_NOT_PERFORMED:
        raise AnsibleError(
            "Ansible Manager backend preflight performed a forbidden action"
        )
    provenance = _digest_mapping(value["provenance"])
    if provenance != _digest_mapping(expected["provenance"]):
        raise AnsibleError("Ansible Manager backend preflight provenance conflicts")

    host_ready = (
        manager_package is ManagerBackendPackageStatus.INSTALLED
        and scylla_package is ManagerBackendPackageStatus.NOT_INSTALLED
        and manager_service is ManagerBackendServiceStatus.MASKED_INACTIVE
        and scylla_service is ManagerBackendServiceStatus.ABSENT
        and reboot_required is False
        and loopback is ManagerBackendLoopbackStatus.AVAILABLE
        and all(item is not None for item in asdict(capacity).values())
        and capacity.approved_mount_count == capacity.available_mount_count == 1
    )
    observed_blockers = set(blockers) - unresolved
    if status is ManagerBackendPreflightStatus.EVIDENCE_READY:
        if not host_ready or observed_blockers:
            raise AnsibleError("Ansible Manager backend preflight readiness conflicts")
    elif status is ManagerBackendPreflightStatus.BLOCKED:
        if host_ready or not observed_blockers:
            raise AnsibleError("Ansible Manager backend preflight blockers conflict")
    elif (
        "execution-failed" not in observed_blockers
        or any(item is not None for item in asdict(capacity).values())
        or reboot_required is not None
    ):
        raise AnsibleError("Ansible Manager backend preflight failure conflicts")

    return ManagerBackendPreflightEvidence(
        logical_id=_text(value["logical_id"]),
        role="manager",
        status=status,
        backend_mode=MANAGER_BACKEND_MODE,
        scylla_release=MANAGER_BACKEND_SCYLLA_RELEASE,
        operating_system=_text(value["operating_system"]),
        operating_system_version=_text(value["operating_system_version"]),
        architecture=_text(value["architecture"]),
        capacity=capacity,
        manager_package_status=manager_package,
        local_scylla_package_status=scylla_package,
        package_availability_status="not-performed",
        manager_service_status=manager_service,
        local_scylla_service_status=scylla_service,
        reboot_required=reboot_required,
        loopback_policy_status=loopback,
        configuration_status="not-inspected",
        schema_status="not-inspected",
        operational_readiness="not-performed",
        not_performed=not_performed,
        provenance=provenance,
        blockers=blockers,
    )


def _failed_evidence(
    expected: dict[str, object],
) -> ManagerBackendPreflightEvidence:
    blockers = tuple(sorted((*MANAGER_BACKEND_UNRESOLVED_BLOCKERS, "execution-failed")))
    return ManagerBackendPreflightEvidence(
        logical_id=_text(expected["logical_id"]),
        role="manager",
        status=ManagerBackendPreflightStatus.FAILED,
        backend_mode=MANAGER_BACKEND_MODE,
        scylla_release=MANAGER_BACKEND_SCYLLA_RELEASE,
        operating_system=_text(expected["operating_system"]),
        operating_system_version=_text(expected["operating_system_version"]),
        architecture=_text(expected["architecture"]),
        capacity=ManagerBackendCapacityEvidence(None, None, None, None, None, None),
        manager_package_status=ManagerBackendPackageStatus.UNKNOWN,
        local_scylla_package_status=ManagerBackendPackageStatus.UNKNOWN,
        package_availability_status="not-performed",
        manager_service_status=ManagerBackendServiceStatus.UNKNOWN,
        local_scylla_service_status=ManagerBackendServiceStatus.UNKNOWN,
        reboot_required=None,
        loopback_policy_status=ManagerBackendLoopbackStatus.UNKNOWN,
        configuration_status="not-inspected",
        schema_status="not-inspected",
        operational_readiness="not-performed",
        not_performed=MANAGER_BACKEND_NOT_PERFORMED,
        provenance=_digest_mapping(expected["provenance"]),
        blockers=blockers,
    )


def _parse_capacity(value: object, *, failed: bool) -> ManagerBackendCapacityEvidence:
    if not isinstance(value, dict) or set(value) != {
        "approved_mount_count",
        "available_mount_count",
        "cpu_count",
        "memory_bytes",
        "root_free_bytes",
        "root_total_bytes",
    }:
        raise AnsibleError("Ansible Manager backend preflight capacity is invalid")
    parsed: dict[str, int | None] = {}
    limits = {
        "approved_mount_count": 32,
        "available_mount_count": 32,
        "cpu_count": 4096,
        "memory_bytes": 2**63 - 1,
        "root_free_bytes": 2**63 - 1,
        "root_total_bytes": 2**63 - 1,
    }
    for name, limit in limits.items():
        item = value[name]
        if item is None and failed:
            parsed[name] = None
        elif (
            not isinstance(item, int)
            or isinstance(item, bool)
            or not 0 <= item <= limit
            or (name in {"cpu_count", "memory_bytes", "root_total_bytes"} and item == 0)
        ):
            raise AnsibleError("Ansible Manager backend preflight capacity is invalid")
        else:
            parsed[name] = item
    if not failed and cast(int, parsed["root_free_bytes"]) > cast(
        int, parsed["root_total_bytes"]
    ):
        raise AnsibleError("Ansible Manager backend preflight capacity conflicts")
    return ManagerBackendCapacityEvidence(
        cpu_count=parsed["cpu_count"],
        memory_bytes=parsed["memory_bytes"],
        root_total_bytes=parsed["root_total_bytes"],
        root_free_bytes=parsed["root_free_bytes"],
        approved_mount_count=parsed["approved_mount_count"],
        available_mount_count=parsed["available_mount_count"],
    )


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise AnsibleError("Ansible Manager backend preflight text is invalid")
    return value


def _sorted_strings(value: object, name: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or len(value) > 64
        or any(not isinstance(item, str) or not item for item in value)
        or value != sorted(set(value))
    ):
        raise AnsibleError(f"Ansible Manager backend preflight {name} is invalid")
    return tuple(cast(list[str], value))


def _digest_mapping(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict) or len(value) > 32:
        raise AnsibleError("Ansible Manager backend preflight provenance is invalid")
    result: list[tuple[str, str]] = []
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not isinstance(item, str)
            or _DIGEST.fullmatch(item) is None
        ):
            raise AnsibleError(
                "Ansible Manager backend preflight provenance is invalid"
            )
        result.append((key, item))
    ordered = tuple(sorted(result))
    if tuple(key for key, _ in ordered) != tuple(sorted(value)):
        raise AnsibleError("Ansible Manager backend preflight provenance is invalid")
    return ordered


def _object_digest(value: object) -> str:
    encoded = json.dumps(
        _canonical(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _manager_server_base_os_digest(value: BaseOsEvidence) -> str:
    return _object_digest(
        {
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
    )


def _canonical(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return _canonical(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    return value
