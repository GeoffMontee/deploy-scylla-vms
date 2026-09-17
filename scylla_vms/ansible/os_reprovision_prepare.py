"""Fail-closed immutable OS-reprovision preparation without mutation."""

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
from scylla_vms.ansible.os_upgrade_in_place import (
    os_upgrade_preflight_evidence_digest,
)
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

OS_REPROVISION_PREPARE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-os-reprovision-prepare/v1"
)
CURRENT_OPERATING_SYSTEM = "Ubuntu"
CURRENT_OPERATING_SYSTEM_VERSION = "24.04"
SUPPORTED_ARCHITECTURES = ("aarch64", "amd64")
MUTATION_BOUNDARY = "not-started"
ACTION_NOT_PERFORMED = "not-performed"
PROVIDER_IDENTITY_POLICY = "must-change-after-replacement"
REPLACEMENT_PROVIDER_ID_STATE = "not-created"
REPROVISION_CLASSIFICATION = "validation-only"
NOT_PERFORMED = (
    "automatic-retry",
    "configuration-write",
    "decommission",
    "desired-state-change",
    "host-retrust",
    "manager-reregistration",
    "membership-mutation",
    "monitoring-target-refresh",
    "nodetool-drain",
    "oci-discovery",
    "package-mutation",
    "provider-identity-assignment",
    "reboot",
    "removenode",
    "restore",
    "service-start",
    "service-stop",
    "storage-delete",
    "storage-detach",
    "storage-mutation",
    "storage-wipe",
    "terraform-apply",
    "terraform-destroy",
    "terraform-plan",
    "vm-destroy",
    "vm-replacement",
)
_ACTION_FIELDS = (
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
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MARKER = re.compile(r"DSV_OS_REPROVISION_PREPARE_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_FAILURE_BLOCKERS = frozenset({"execution-failed", "host-unreachable"})
_SCYLLA_LIFECYCLE_PATHS = frozenset(
    {
        "remove-dead-completed",
        "remove-live-completed",
        "replace-node-delegation-required",
    }
)
_STATELESS_LIFECYCLE_PATH = "stateless-replacement-reviewed"
_ROLE_CLASSIFICATIONS = {
    HostRole.JUMP_HOST: "jump-route-host",
    HostRole.MANAGER: "manager-control-plane-host",
    HostRole.MONITORING: "monitoring-stateful-host",
    HostRole.SCYLLA: "scylla-stateful-member",
}


class OsReprovisionPrepareStatus(StrEnum):
    BLOCKED = "blocked"
    FAILED = "failed"


class ReprovisionReadiness(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    UNKNOWN = "unknown"
    NOT_PERFORMED = "not-performed"


class ReprovisionStorageDisposition(StrEnum):
    RETAIN = "retain"
    DELETE = "delete"
    EPHEMERAL = "ephemeral"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class OsReprovisionCurrentProviderFacts:
    """Caller-supplied current provider/image facts, projected only as digests."""

    logical_id: str
    role: HostRole
    provider: str
    current_operating_system: str
    current_operating_system_version: str
    architecture: str
    provider_id_digest: str
    image_id_digest: str
    source_digest: str
    digest: str


@dataclass(frozen=True, slots=True)
class OsReprovisionRoleSafetyEvidence:
    """Independent role/lifecycle facts; unknown values never authorize readiness."""

    logical_id: str
    role: HostRole
    role_classification: str
    topology_digest: str
    storage_disposition: ReprovisionStorageDisposition
    lifecycle_path: str
    lifecycle_evidence_digest: str
    membership_readiness: ReprovisionReadiness
    service_readiness: ReprovisionReadiness
    replacement_availability: ReprovisionReadiness
    route_redundancy: ReprovisionReadiness
    restore_readiness: ReprovisionReadiness
    reregistration_readiness: ReprovisionReadiness
    retrust_readiness: ReprovisionReadiness
    stable_identity_preserved: bool
    provider_identity_policy: str
    digest: str


@dataclass(frozen=True, slots=True)
class OsReprovisionPrepareAuthorization:
    """Narrow destructive-scope approval that authorizes validation only."""

    operation_id: str
    cluster_uuid: str
    logical_id: str
    role: HostRole
    current_operating_system: str
    current_operating_system_version: str
    target_operating_system: str
    target_operating_system_version: str
    current_architecture: str
    target_architecture: str
    storage_disposition: ReprovisionStorageDisposition
    topology_digest: str
    provider_id_digest: str
    preflight_digest: str
    current_provider_facts_digest: str
    target_image_facts_digest: str
    role_safety_digest: str
    observation_digest: str
    inventory_digest: str
    trust_digest: str
    confirmed_target: str
    allow_destructive: bool
    reviewed: bool
    no_competing_operation: bool
    stable_identity_preserved: bool
    provider_identity_policy: str
    authorization_digest: str


@dataclass(frozen=True, slots=True)
class OsReprovisionPrepareEvidence:
    logical_id: str
    role: HostRole
    role_classification: str
    status: OsReprovisionPrepareStatus
    transition_classification: str
    reprovision_classification: str
    current_operating_system: str
    current_operating_system_version: str
    current_architecture: str
    target_operating_system: str
    target_operating_system_version: str
    target_architecture: str
    stable_identity_preserved: bool
    provider_identity_policy: str
    replacement_provider_id_state: str
    current_provider_id_digest: str
    current_image_facts_digest: str
    target_image_facts_digest: str
    current_image_id_digest: str
    target_image_id_digest: str
    provider_source_digests: tuple[tuple[str, str], ...]
    storage_disposition: ReprovisionStorageDisposition
    membership_readiness: ReprovisionReadiness
    service_readiness: ReprovisionReadiness
    lifecycle_path: str
    applied: bool
    automatic_retry: bool
    configuration_action: str
    desired_state_action: str
    membership_action: str
    package_action: str
    provider_action: str
    reboot_action: str
    registration_action: str
    restore_action: str
    service_action: str
    storage_action: str
    terraform_action: str
    trust_action: str
    vm_action: str
    mutation_boundary: str
    recovery_required: bool
    not_performed: tuple[str, ...]
    provenance: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]
    schema_version: str = OS_REPROVISION_PREPARE_SCHEMA_VERSION


def build_os_reprovision_current_provider_facts(
    inventory: StoredInventoryRecord,
    *,
    logical_id: str,
    current_operating_system: str,
    current_operating_system_version: str,
    architecture: str,
    image_id_digest: str,
    source_digest: str,
) -> OsReprovisionCurrentProviderFacts:
    """Bind offline current image facts to the exact observed provider identity."""

    host = next(
        (
            item
            for item in inventory.record.inventory.hosts
            if item.logical_id == logical_id
        ),
        None,
    )
    if host is None:
        raise StateConflictError(
            "OS-reprovision current provider facts target is unavailable"
        )
    if architecture not in SUPPORTED_ARCHITECTURES:
        raise AnsibleError("OS-reprovision current provider architecture is invalid")
    if (
        current_operating_system != CURRENT_OPERATING_SYSTEM
        or current_operating_system_version != CURRENT_OPERATING_SYSTEM_VERSION
    ):
        raise StateConflictError(
            "OS-reprovision current provider facts require Ubuntu 24.04"
        )
    provider_id_digest = _digest_text(host.provider_id)
    values = {
        "architecture": architecture,
        "current_operating_system": current_operating_system,
        "current_operating_system_version": current_operating_system_version,
        "image_id_digest": _require_digest(image_id_digest),
        "logical_id": logical_id,
        "provider": inventory.record.provider,
        "provider_id_digest": provider_id_digest,
        "role": host.role.value,
        "source_digest": _require_digest(source_digest),
    }
    return OsReprovisionCurrentProviderFacts(
        logical_id,
        host.role,
        inventory.record.provider,
        current_operating_system,
        current_operating_system_version,
        architecture,
        provider_id_digest,
        image_id_digest,
        source_digest,
        _object_digest(values),
    )


def build_os_reprovision_role_safety_evidence(
    logical_id: str,
    role: HostRole,
    *,
    topology_digest: str,
    storage_disposition: ReprovisionStorageDisposition,
    lifecycle_path: str,
    lifecycle_evidence_digest: str,
    membership_readiness: ReprovisionReadiness,
    service_readiness: ReprovisionReadiness,
    replacement_availability: ReprovisionReadiness,
    route_redundancy: ReprovisionReadiness,
    restore_readiness: ReprovisionReadiness,
    reregistration_readiness: ReprovisionReadiness,
    retrust_readiness: ReprovisionReadiness,
) -> OsReprovisionRoleSafetyEvidence:
    """Build exact caller-validated role safety without contacting a provider."""

    _require_logical_id(logical_id)
    _require_digest(topology_digest)
    _require_digest(lifecycle_evidence_digest)
    if role is HostRole.JUMP_HOST:
        if storage_disposition is not ReprovisionStorageDisposition.NONE:
            raise StateConflictError("jump-host reprovision storage must be none")
    elif storage_disposition is ReprovisionStorageDisposition.NONE:
        raise StateConflictError("role reprovision storage disposition is required")
    if role is HostRole.SCYLLA:
        if lifecycle_path not in _SCYLLA_LIFECYCLE_PATHS:
            raise StateConflictError(
                "Scylla reprovision lifecycle path is not independently reviewed"
            )
        if (
            lifecycle_path in {"remove-dead-completed", "remove-live-completed"}
            and membership_readiness is not ReprovisionReadiness.PASSED
        ) or (
            lifecycle_path == "replace-node-delegation-required"
            and membership_readiness is ReprovisionReadiness.PASSED
        ):
            raise StateConflictError(
                "Scylla reprovision lifecycle and membership evidence conflict"
            )
    elif lifecycle_path != _STATELESS_LIFECYCLE_PATH:
        raise StateConflictError("stateless role reprovision lifecycle path is invalid")
    if (
        role is not HostRole.SCYLLA
        and membership_readiness is not ReprovisionReadiness.NOT_PERFORMED
    ):
        raise StateConflictError(
            "non-Scylla reprovision membership evidence is not applicable"
        )
    if retrust_readiness is ReprovisionReadiness.PASSED:
        raise StateConflictError(
            "replacement host retrust cannot pass before provider replacement"
        )
    if role is HostRole.MANAGER:
        valid_role_readiness = (
            restore_readiness is not ReprovisionReadiness.PASSED
            and reregistration_readiness is not ReprovisionReadiness.PASSED
            and service_readiness is not ReprovisionReadiness.PASSED
        )
    elif role is HostRole.MONITORING:
        valid_role_readiness = (
            restore_readiness is not ReprovisionReadiness.PASSED
            and reregistration_readiness is ReprovisionReadiness.NOT_PERFORMED
            and service_readiness is not ReprovisionReadiness.PASSED
        )
    else:
        valid_role_readiness = (
            restore_readiness is ReprovisionReadiness.NOT_PERFORMED
            and reregistration_readiness is ReprovisionReadiness.NOT_PERFORMED
        )
    if not valid_role_readiness:
        raise StateConflictError(
            "OS-reprovision role restore or service readiness conflicts"
        )
    role_classification = _ROLE_CLASSIFICATIONS[role]
    values = {
        "lifecycle_evidence_digest": lifecycle_evidence_digest,
        "lifecycle_path": lifecycle_path,
        "logical_id": logical_id,
        "membership_readiness": membership_readiness.value,
        "provider_identity_policy": PROVIDER_IDENTITY_POLICY,
        "replacement_availability": replacement_availability.value,
        "reregistration_readiness": reregistration_readiness.value,
        "restore_readiness": restore_readiness.value,
        "retrust_readiness": retrust_readiness.value,
        "role": role.value,
        "role_classification": role_classification,
        "route_redundancy": route_redundancy.value,
        "service_readiness": service_readiness.value,
        "stable_identity_preserved": True,
        "storage_disposition": storage_disposition.value,
        "topology_digest": topology_digest,
    }
    return OsReprovisionRoleSafetyEvidence(
        logical_id,
        role,
        role_classification,
        topology_digest,
        storage_disposition,
        lifecycle_path,
        lifecycle_evidence_digest,
        membership_readiness,
        service_readiness,
        replacement_availability,
        route_redundancy,
        restore_readiness,
        reregistration_readiness,
        retrust_readiness,
        True,
        PROVIDER_IDENTITY_POLICY,
        _object_digest(values),
    )


def build_os_reprovision_prepare_authorization(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    preflight: OsUpgradePreflightEvidence,
    current_provider: OsReprovisionCurrentProviderFacts,
    role_safety: OsReprovisionRoleSafetyEvidence,
    intent: OsUpgradePreflightIntent,
    *,
    operation_id: str,
    confirmed_target: str,
    allow_destructive: bool = True,
    reviewed: bool = True,
    no_competing_operation: bool = True,
) -> OsReprovisionPrepareAuthorization:
    """Authorize exact blocked preparation, never Terraform or host mutation."""

    _require_state_provenance(metadata, observed, inventory, readiness)
    if not _valid_uuid(operation_id) or operation_id != intent.operation_id:
        raise AnsibleError("OS-reprovision preparation operation ID is invalid")
    if (
        confirmed_target != preflight.logical_id
        or not allow_destructive
        or not reviewed
        or not no_competing_operation
    ):
        raise StateConflictError(
            "OS-reprovision preparation requires exact reviewed destructive scope"
        )
    image = intent.provider_image
    if image is None:
        raise StateConflictError(
            "OS-reprovision preparation requires target provider image facts"
        )
    _validate_current_provider_facts(current_provider, inventory)
    _validate_role_safety(role_safety)
    if (
        current_provider.logical_id != preflight.logical_id
        or current_provider.role is not preflight.role
        or role_safety.logical_id != preflight.logical_id
        or role_safety.role is not preflight.role
    ):
        raise StateConflictError(
            "OS-reprovision preparation authorization target conflicts"
        )
    preflight_digest = os_upgrade_preflight_evidence_digest(preflight)
    values = {
        "allow_destructive": allow_destructive,
        "cluster_uuid": str(metadata.cluster_uuid),
        "confirmed_target": confirmed_target,
        "current_architecture": current_provider.architecture,
        "current_operating_system": current_provider.current_operating_system,
        "current_operating_system_version": (
            current_provider.current_operating_system_version
        ),
        "current_provider_facts_digest": current_provider.digest,
        "inventory_digest": inventory.digest,
        "logical_id": preflight.logical_id,
        "no_competing_operation": no_competing_operation,
        "observation_digest": observed.digest,
        "operation_id": operation_id,
        "preflight_digest": preflight_digest,
        "provider_id_digest": current_provider.provider_id_digest,
        "provider_identity_policy": PROVIDER_IDENTITY_POLICY,
        "reviewed": reviewed,
        "role": preflight.role.value,
        "role_safety_digest": role_safety.digest,
        "stable_identity_preserved": True,
        "storage_disposition": role_safety.storage_disposition.value,
        "target_architecture": image.architecture,
        "target_image_facts_digest": image.digest,
        "target_operating_system": image.operating_system,
        "target_operating_system_version": image.operating_system_version,
        "topology_digest": role_safety.topology_digest,
        "trust_digest": readiness.trust_digest,
    }
    return OsReprovisionPrepareAuthorization(
        operation_id,
        str(metadata.cluster_uuid),
        preflight.logical_id,
        preflight.role,
        current_provider.current_operating_system,
        current_provider.current_operating_system_version,
        image.operating_system,
        image.operating_system_version,
        current_provider.architecture,
        image.architecture,
        role_safety.storage_disposition,
        role_safety.topology_digest,
        current_provider.provider_id_digest,
        preflight_digest,
        current_provider.digest,
        image.digest,
        role_safety.digest,
        observed.digest,
        inventory.digest,
        _require_digest(readiness.trust_digest),
        confirmed_target,
        allow_destructive,
        reviewed,
        no_competing_operation,
        True,
        PROVIDER_IDENTITY_POLICY,
        _object_digest(values),
    )


def build_os_reprovision_prepare_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    base_os: BaseOsEvidence,
    prerequisites: OsUpgradePreflightPrerequisites,
    intent: OsUpgradePreflightIntent,
    preflight: OsUpgradePreflightEvidence,
    current_provider: OsReprovisionCurrentProviderFacts,
    role_safety: OsReprovisionRoleSafetyEvidence,
    authorization: OsReprovisionPrepareAuthorization,
    *,
    limit: tuple[str, ...],
    image_filter: ImageFilter,
    architecture: str,
) -> dict[str, object]:
    """Build strict blocked immutable-replacement preparation evidence."""

    if len(limit) != 1 or limit[0] != intent.logical_id:
        raise StateConflictError(
            "OS-reprovision preparation requires one exact stable ID"
        )
    if architecture not in SUPPORTED_ARCHITECTURES:
        raise StateConflictError(
            "OS-reprovision preparation architecture is unsupported"
        )
    if intent.strategy != "reprovision" or intent.package_policy_digest is not None:
        raise StateConflictError(
            "OS-reprovision preparation requires reprovision-only image intent"
        )
    if intent.provider_image is None:
        raise StateConflictError(
            "OS-reprovision preparation requires target provider image facts"
        )
    image = intent.provider_image
    if not isinstance(current_provider, OsReprovisionCurrentProviderFacts):
        raise StateConflictError(
            "OS-reprovision preparation requires current provider image facts"
        )
    if not isinstance(role_safety, OsReprovisionRoleSafetyEvidence):
        raise StateConflictError(
            "OS-reprovision preparation requires role lifecycle evidence"
        )
    if (
        intent.target_operating_system != CURRENT_OPERATING_SYSTEM
        or image.operating_system != CURRENT_OPERATING_SYSTEM
    ):
        raise StateConflictError(
            "OS-reprovision target operating system is unsupported"
        )
    if (
        intent.target_operating_system_version == CURRENT_OPERATING_SYSTEM_VERSION
        or image.operating_system_version == CURRENT_OPERATING_SYSTEM_VERSION
    ):
        raise StateConflictError(
            "OS-reprovision same-version request is not an OS upgrade"
        )
    if (
        image.operating_system != intent.target_operating_system
        or image.operating_system_version != intent.target_operating_system_version
        or image.architecture != architecture
        or not image.available
        or not image.replacement_plan_reviewed
    ):
        raise StateConflictError(
            "OS-reprovision target provider image facts are ineligible"
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
    _require_current_reprovision_preflight(preflight, expected_preflight)
    _validate_current_provider_facts(current_provider, inventory)
    _validate_role_safety(role_safety)
    if (
        current_provider.logical_id != preflight.logical_id
        or current_provider.role is not preflight.role
        or current_provider.architecture != architecture
        or role_safety.logical_id != preflight.logical_id
        or role_safety.role is not preflight.role
        or (
            preflight.role is HostRole.SCYLLA
            and dict(preflight.provenance).get("topology_digest")
            != role_safety.topology_digest
        )
    ):
        raise StateConflictError(
            "OS-reprovision preparation role or provider identity conflicts"
        )
    _validate_authorization(
        metadata,
        observed,
        inventory,
        readiness,
        preflight,
        current_provider,
        role_safety,
        intent,
        authorization,
    )
    blockers = _expected_blockers(role_safety)
    provenance = dict(preflight.provenance)
    provenance.update(
        {
            "authorization_digest": authorization.authorization_digest,
            "current_provider_facts_digest": current_provider.digest,
            "lifecycle_evidence_digest": role_safety.lifecycle_evidence_digest,
            "preflight_digest": authorization.preflight_digest,
            "role_safety_digest": role_safety.digest,
            "target_image_facts_digest": image.digest,
            "topology_digest": role_safety.topology_digest,
        }
    )
    return {
        "applied": False,
        "automatic_retry": False,
        "authorization": {
            "allow_destructive": True,
            "authorization_digest": authorization.authorization_digest,
            "confirmed_target": authorization.confirmed_target,
            "no_competing_operation": True,
            "operation_id": authorization.operation_id,
            "reviewed": True,
        },
        "blockers": list(blockers),
        "configuration_action": ACTION_NOT_PERFORMED,
        "current_architecture": current_provider.architecture,
        "current_image_facts_digest": current_provider.digest,
        "current_image_id_digest": current_provider.image_id_digest,
        "current_operating_system": current_provider.current_operating_system,
        "current_operating_system_version": (
            current_provider.current_operating_system_version
        ),
        "current_provider_id_digest": current_provider.provider_id_digest,
        "desired_state_action": ACTION_NOT_PERFORMED,
        "guest_architecture": (
            "x86_64" if current_provider.architecture == "amd64" else "aarch64"
        ),
        "lifecycle_path": role_safety.lifecycle_path,
        "logical_id": preflight.logical_id,
        "membership_action": ACTION_NOT_PERFORMED,
        "membership_readiness": role_safety.membership_readiness.value,
        "mutation_boundary": MUTATION_BOUNDARY,
        "not_performed": list(NOT_PERFORMED),
        "package_action": ACTION_NOT_PERFORMED,
        "provider_action": ACTION_NOT_PERFORMED,
        "provider_identity_policy": PROVIDER_IDENTITY_POLICY,
        "provider_source_digests": {
            "current": current_provider.source_digest,
            "target": image.source_digest,
        },
        "provenance": provenance,
        "reboot_action": ACTION_NOT_PERFORMED,
        "recovery_required": False,
        "registration_action": ACTION_NOT_PERFORMED,
        "replacement_provider_id_state": REPLACEMENT_PROVIDER_ID_STATE,
        "reprovision_classification": REPROVISION_CLASSIFICATION,
        "restore_action": ACTION_NOT_PERFORMED,
        "role": preflight.role.value,
        "role_classification": role_safety.role_classification,
        "schema_version": OS_REPROVISION_PREPARE_SCHEMA_VERSION,
        "service_action": ACTION_NOT_PERFORMED,
        "service_readiness": role_safety.service_readiness.value,
        "stable_identity_preserved": True,
        "storage_action": ACTION_NOT_PERFORMED,
        "storage_disposition": role_safety.storage_disposition.value,
        "target_architecture": image.architecture,
        "target_image_facts_digest": image.digest,
        "target_image_id_digest": image.image_id_digest,
        "target_operating_system": image.operating_system,
        "target_operating_system_version": image.operating_system_version,
        "terraform_action": ACTION_NOT_PERFORMED,
        "transition_classification": "unapproved",
        "trust_action": ACTION_NOT_PERFORMED,
        "vm_action": ACTION_NOT_PERFORMED,
    }


def parse_os_reprovision_prepare_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> OsReprovisionPrepareEvidence:
    """Parse only bounded blocked/failure evidence and exact host recap."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError(
            "Ansible OS-reprovision preparation output exceeds evidence limit"
        )
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_OS_REPROVISION_PREPARE_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible OS-reprovision preparation marker is malformed")
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"), object_pairs_hook=_strict_object
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible OS-reprovision preparation marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError(
                "Ansible OS-reprovision preparation evidence is malformed"
            )
        values.append(value)
    recap = _parse_recap(stdout)
    logical_id = _text(expected_payload["logical_id"])
    if set(recap) != {logical_id}:
        raise AnsibleError(
            "Ansible OS-reprovision preparation recap membership conflicts"
        )
    changed, unreachable, failed = recap[logical_id]
    if changed:
        raise AnsibleError("Ansible OS-reprovision preparation reported a mutation")
    recap_failed = bool(unreachable or failed)
    if not values:
        if not recap_failed or exit_code == 0:
            raise AnsibleError(
                "Ansible OS-reprovision preparation evidence is incomplete"
            )
        return _failed_evidence(expected_payload, unreachable=bool(unreachable))
    if len(values) != 1:
        raise AnsibleError("Ansible OS-reprovision preparation evidence is duplicated")
    evidence = _parse_result(values[0], expected_payload)
    result_failed = evidence.status is OsReprovisionPrepareStatus.FAILED
    if recap_failed != result_failed or (exit_code == 0) == result_failed:
        raise AnsibleError("Ansible OS-reprovision preparation exit status conflicts")
    return evidence


def _require_current_reprovision_preflight(
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
    expected_blockers = tuple(
        _sorted_strings(
            expected["controller_blockers"], name="preflight-controller-blockers"
        )
    )
    expected_rolling = _require_bool(expected["rolling_eligible"])
    if (
        preflight.schema_version != OS_UPGRADE_PREFLIGHT_SCHEMA_VERSION
        or preflight.status is not OsUpgradePreflightStatus.BLOCKED
        or preflight.transition_classification
        is not TransitionClassification.UNSUPPORTED
        or preflight.requested_strategy != "reprovision"
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
        or preflight.rolling_eligible is not expected_rolling
        or actual_gates != expected_gates
        or preflight.not_performed != PREFLIGHT_NOT_PERFORMED
        or preflight.provenance
        != tuple(
            sorted(
                (_text(name), _require_digest(value))
                for name, value in expected_provenance.items()
            )
        )
        or preflight.blockers != expected_blockers
        or (
            preflight.role in {HostRole.JUMP_HOST, HostRole.SCYLLA}
            and not preflight.rolling_eligible
        )
    ):
        raise StateConflictError(
            "OS-reprovision preparation requires current eligible preflight evidence"
        )


def _validate_current_provider_facts(
    value: OsReprovisionCurrentProviderFacts,
    inventory: StoredInventoryRecord,
) -> None:
    host = next(
        (
            item
            for item in inventory.record.inventory.hosts
            if item.logical_id == value.logical_id
        ),
        None,
    )
    values = {
        "architecture": value.architecture,
        "current_operating_system": value.current_operating_system,
        "current_operating_system_version": value.current_operating_system_version,
        "image_id_digest": _require_digest(value.image_id_digest),
        "logical_id": value.logical_id,
        "provider": value.provider,
        "provider_id_digest": _require_digest(value.provider_id_digest),
        "role": value.role.value,
        "source_digest": _require_digest(value.source_digest),
    }
    if (
        host is None
        or value.role is not host.role
        or value.provider != inventory.record.provider
        or value.current_operating_system != CURRENT_OPERATING_SYSTEM
        or value.current_operating_system_version != CURRENT_OPERATING_SYSTEM_VERSION
        or value.architecture not in SUPPORTED_ARCHITECTURES
        or value.provider_id_digest != _digest_text(host.provider_id)
        or value.digest != _object_digest(values)
    ):
        raise StateConflictError(
            "OS-reprovision current provider facts conflict with inventory"
        )


def _validate_role_safety(value: OsReprovisionRoleSafetyEvidence) -> None:
    _require_logical_id(value.logical_id)
    values = {
        "lifecycle_evidence_digest": _require_digest(value.lifecycle_evidence_digest),
        "lifecycle_path": value.lifecycle_path,
        "logical_id": value.logical_id,
        "membership_readiness": value.membership_readiness.value,
        "provider_identity_policy": value.provider_identity_policy,
        "replacement_availability": value.replacement_availability.value,
        "reregistration_readiness": value.reregistration_readiness.value,
        "restore_readiness": value.restore_readiness.value,
        "retrust_readiness": value.retrust_readiness.value,
        "role": value.role.value,
        "role_classification": value.role_classification,
        "route_redundancy": value.route_redundancy.value,
        "service_readiness": value.service_readiness.value,
        "stable_identity_preserved": value.stable_identity_preserved,
        "storage_disposition": value.storage_disposition.value,
        "topology_digest": _require_digest(value.topology_digest),
    }
    valid_storage = (
        value.storage_disposition is ReprovisionStorageDisposition.NONE
        if value.role is HostRole.JUMP_HOST
        else value.storage_disposition is not ReprovisionStorageDisposition.NONE
    )
    valid_lifecycle = (
        value.lifecycle_path in _SCYLLA_LIFECYCLE_PATHS
        if value.role is HostRole.SCYLLA
        else value.lifecycle_path == _STATELESS_LIFECYCLE_PATH
    )
    valid_membership = (
        (
            value.membership_readiness is ReprovisionReadiness.PASSED
            if value.lifecycle_path
            in {"remove-dead-completed", "remove-live-completed"}
            else value.membership_readiness is not ReprovisionReadiness.PASSED
        )
        if value.role is HostRole.SCYLLA
        else value.membership_readiness is ReprovisionReadiness.NOT_PERFORMED
    )
    if value.role is HostRole.MANAGER:
        valid_role_readiness = (
            value.restore_readiness is not ReprovisionReadiness.PASSED
            and value.reregistration_readiness is not ReprovisionReadiness.PASSED
            and value.service_readiness is not ReprovisionReadiness.PASSED
        )
    elif value.role is HostRole.MONITORING:
        valid_role_readiness = (
            value.restore_readiness is not ReprovisionReadiness.PASSED
            and value.reregistration_readiness is ReprovisionReadiness.NOT_PERFORMED
            and value.service_readiness is not ReprovisionReadiness.PASSED
        )
    else:
        valid_role_readiness = (
            value.restore_readiness is ReprovisionReadiness.NOT_PERFORMED
            and value.reregistration_readiness is ReprovisionReadiness.NOT_PERFORMED
        )
    if (
        value.role_classification != _ROLE_CLASSIFICATIONS[value.role]
        or not valid_storage
        or not valid_lifecycle
        or not valid_membership
        or not valid_role_readiness
        or value.retrust_readiness is ReprovisionReadiness.PASSED
        or not value.stable_identity_preserved
        or value.provider_identity_policy != PROVIDER_IDENTITY_POLICY
        or value.digest != _object_digest(values)
    ):
        raise StateConflictError("OS-reprovision role safety evidence conflicts")


def _validate_authorization(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    preflight: OsUpgradePreflightEvidence,
    current_provider: OsReprovisionCurrentProviderFacts,
    role_safety: OsReprovisionRoleSafetyEvidence,
    intent: OsUpgradePreflightIntent,
    authorization: OsReprovisionPrepareAuthorization,
) -> None:
    image = intent.provider_image
    if image is None:
        raise StateConflictError(
            "OS-reprovision preparation target image facts are unavailable"
        )
    values = {
        "allow_destructive": authorization.allow_destructive,
        "cluster_uuid": authorization.cluster_uuid,
        "confirmed_target": authorization.confirmed_target,
        "current_architecture": authorization.current_architecture,
        "current_operating_system": authorization.current_operating_system,
        "current_operating_system_version": (
            authorization.current_operating_system_version
        ),
        "current_provider_facts_digest": (authorization.current_provider_facts_digest),
        "inventory_digest": authorization.inventory_digest,
        "logical_id": authorization.logical_id,
        "no_competing_operation": authorization.no_competing_operation,
        "observation_digest": authorization.observation_digest,
        "operation_id": authorization.operation_id,
        "preflight_digest": authorization.preflight_digest,
        "provider_id_digest": authorization.provider_id_digest,
        "provider_identity_policy": authorization.provider_identity_policy,
        "reviewed": authorization.reviewed,
        "role": authorization.role.value,
        "role_safety_digest": authorization.role_safety_digest,
        "stable_identity_preserved": authorization.stable_identity_preserved,
        "storage_disposition": authorization.storage_disposition.value,
        "target_architecture": authorization.target_architecture,
        "target_image_facts_digest": authorization.target_image_facts_digest,
        "target_operating_system": authorization.target_operating_system,
        "target_operating_system_version": (
            authorization.target_operating_system_version
        ),
        "topology_digest": authorization.topology_digest,
        "trust_digest": authorization.trust_digest,
    }
    if (
        not _valid_uuid(authorization.operation_id)
        or authorization.operation_id != intent.operation_id
        or authorization.cluster_uuid != str(metadata.cluster_uuid)
        or authorization.logical_id != preflight.logical_id
        or authorization.confirmed_target != preflight.logical_id
        or authorization.role is not preflight.role
        or authorization.current_operating_system
        != current_provider.current_operating_system
        or authorization.current_operating_system_version
        != current_provider.current_operating_system_version
        or authorization.current_architecture != current_provider.architecture
        or authorization.target_operating_system != image.operating_system
        or authorization.target_operating_system_version
        != image.operating_system_version
        or authorization.target_architecture != image.architecture
        or authorization.storage_disposition is not role_safety.storage_disposition
        or authorization.topology_digest != role_safety.topology_digest
        or authorization.provider_id_digest != current_provider.provider_id_digest
        or authorization.preflight_digest
        != os_upgrade_preflight_evidence_digest(preflight)
        or authorization.current_provider_facts_digest != current_provider.digest
        or authorization.target_image_facts_digest != image.digest
        or authorization.role_safety_digest != role_safety.digest
        or authorization.observation_digest != observed.digest
        or authorization.inventory_digest != inventory.digest
        or authorization.trust_digest != readiness.trust_digest
        or not authorization.allow_destructive
        or not authorization.reviewed
        or not authorization.no_competing_operation
        or not authorization.stable_identity_preserved
        or authorization.provider_identity_policy != PROVIDER_IDENTITY_POLICY
        or authorization.authorization_digest != _object_digest(values)
    ):
        raise StateConflictError(
            "OS-reprovision preparation authorization does not bind exact intent"
        )
    for digest in (
        authorization.authorization_digest,
        authorization.preflight_digest,
        authorization.current_provider_facts_digest,
        authorization.target_image_facts_digest,
        authorization.role_safety_digest,
        authorization.observation_digest,
        authorization.inventory_digest,
        authorization.trust_digest,
    ):
        _require_digest(digest)


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
        raise StateConflictError(
            "OS-reprovision preparation state provenance conflicts"
        )


def _expected_blockers(
    safety: OsReprovisionRoleSafetyEvidence,
) -> tuple[str, ...]:
    blockers = {
        "host-retrust-required",
        "provider-identity-revalidation-required",
        "target-transition-unapproved",
        "terraform-replacement-orchestration-unimplemented",
    }
    if safety.replacement_availability is not ReprovisionReadiness.PASSED:
        blockers.add("replacement-availability-unproven")
    if safety.route_redundancy is not ReprovisionReadiness.PASSED:
        blockers.add("route-redundancy-unproven")
    if safety.storage_disposition is not ReprovisionStorageDisposition.NONE:
        blockers.add("storage-disposition-not-executed")
    if safety.role is HostRole.SCYLLA:
        blockers.add("scylla-reprovision-requires-replace-node")
        if (
            safety.membership_readiness is not ReprovisionReadiness.PASSED
            or safety.lifecycle_path == "replace-node-delegation-required"
        ):
            blockers.add("scylla-membership-handling-unproven")
        if safety.service_readiness is not ReprovisionReadiness.PASSED:
            blockers.add("scylla-service-readiness-unproven")
    elif safety.role is HostRole.MANAGER:
        blockers.update(
            {
                "manager-reregistration-unimplemented",
                "manager-restore-unimplemented",
                "manager-service-readiness-unimplemented",
            }
        )
    elif safety.role is HostRole.MONITORING:
        blockers.update(
            {
                "monitoring-restore-unimplemented",
                "monitoring-service-readiness-unimplemented",
                "monitoring-target-refresh-unimplemented",
            }
        )
    else:
        blockers.add("jump-route-revalidation-required")
    return tuple(sorted(blockers))


def _parse_result(
    value: dict[str, object],
    expected: dict[str, object],
) -> OsReprovisionPrepareEvidence:
    fields = {
        "applied",
        "automatic_retry",
        "blockers",
        "configuration_action",
        "current_architecture",
        "current_image_facts_digest",
        "current_image_id_digest",
        "current_operating_system",
        "current_operating_system_version",
        "current_provider_id_digest",
        "desired_state_action",
        "lifecycle_path",
        "logical_id",
        "membership_action",
        "membership_readiness",
        "mutation_boundary",
        "not_performed",
        "package_action",
        "provider_action",
        "provider_identity_policy",
        "provider_source_digests",
        "provenance",
        "reboot_action",
        "recovery_required",
        "registration_action",
        "replacement_provider_id_state",
        "reprovision_classification",
        "restore_action",
        "role",
        "role_classification",
        "schema_version",
        "service_action",
        "service_readiness",
        "stable_identity_preserved",
        "status",
        "storage_action",
        "storage_disposition",
        "target_architecture",
        "target_image_facts_digest",
        "target_image_id_digest",
        "target_operating_system",
        "target_operating_system_version",
        "terraform_action",
        "transition_classification",
        "trust_action",
        "vm_action",
    }
    if (
        set(value) != fields
        or value["schema_version"] != OS_REPROVISION_PREPARE_SCHEMA_VERSION
    ):
        raise AnsibleError(
            "Ansible OS-reprovision preparation evidence schema is invalid"
        )
    for name in (
        "current_architecture",
        "current_image_facts_digest",
        "current_image_id_digest",
        "current_operating_system",
        "current_operating_system_version",
        "current_provider_id_digest",
        "lifecycle_path",
        "logical_id",
        "membership_readiness",
        "provider_identity_policy",
        "replacement_provider_id_state",
        "reprovision_classification",
        "role",
        "role_classification",
        "service_readiness",
        "storage_disposition",
        "target_architecture",
        "target_image_facts_digest",
        "target_image_id_digest",
        "target_operating_system",
        "target_operating_system_version",
        "transition_classification",
    ):
        if value[name] != expected[name]:
            raise AnsibleError("Ansible OS-reprovision preparation evidence conflicts")
    try:
        status = OsReprovisionPrepareStatus(_text(value["status"]))
        role = HostRole(_text(value["role"]))
        disposition = ReprovisionStorageDisposition(_text(value["storage_disposition"]))
        membership = ReprovisionReadiness(_text(value["membership_readiness"]))
        service = ReprovisionReadiness(_text(value["service_readiness"]))
    except ValueError as error:
        raise AnsibleError(
            "Ansible OS-reprovision preparation status is invalid"
        ) from error
    if _require_bool(value["applied"]) or _require_bool(value["automatic_retry"]):
        raise AnsibleError(
            "Ansible OS-reprovision preparation claimed a forbidden mutation"
        )
    if not _require_bool(value["stable_identity_preserved"]):
        raise AnsibleError(
            "Ansible OS-reprovision preparation stable identity conflicts"
        )
    for name in _ACTION_FIELDS:
        if value[name] != ACTION_NOT_PERFORMED:
            raise AnsibleError(
                "Ansible OS-reprovision preparation claimed a forbidden action"
            )
    if value["mutation_boundary"] != MUTATION_BOUNDARY or _require_bool(
        value["recovery_required"]
    ):
        raise AnsibleError(
            "Ansible OS-reprovision preparation mutation boundary conflicts"
        )
    not_performed = _sorted_strings(value["not_performed"], name="not-performed")
    if not_performed != NOT_PERFORMED:
        raise AnsibleError(
            "Ansible OS-reprovision preparation not-performed set is invalid"
        )
    blockers = _sorted_strings(value["blockers"], name="blockers")
    expected_blockers = tuple(
        _sorted_strings(expected["blockers"], name="expected-blockers")
    )
    if status is OsReprovisionPrepareStatus.BLOCKED and blockers != expected_blockers:
        raise AnsibleError(
            "Ansible OS-reprovision preparation blocked evidence conflicts"
        )
    if status is OsReprovisionPrepareStatus.FAILED and (
        len(blockers) != 1 or blockers[0] not in _FAILURE_BLOCKERS
    ):
        raise AnsibleError(
            "Ansible OS-reprovision preparation failure evidence conflicts"
        )
    provenance_value = value["provenance"]
    source_value = value["provider_source_digests"]
    if (
        not isinstance(provenance_value, dict)
        or provenance_value != expected["provenance"]
        or not isinstance(source_value, dict)
        or source_value != expected["provider_source_digests"]
    ):
        raise AnsibleError("Ansible OS-reprovision preparation provenance conflicts")
    provenance = tuple(
        sorted(
            (_text(name), _require_digest(item))
            for name, item in provenance_value.items()
        )
    )
    provider_sources = tuple(
        sorted(
            (_text(name), _require_digest(item)) for name, item in source_value.items()
        )
    )
    _reject_secrets(value)
    return OsReprovisionPrepareEvidence(
        _text(value["logical_id"]),
        role,
        _text(value["role_classification"]),
        status,
        "unapproved",
        REPROVISION_CLASSIFICATION,
        _text(value["current_operating_system"]),
        _text(value["current_operating_system_version"]),
        _text(value["current_architecture"]),
        _text(value["target_operating_system"]),
        _text(value["target_operating_system_version"]),
        _text(value["target_architecture"]),
        True,
        PROVIDER_IDENTITY_POLICY,
        REPLACEMENT_PROVIDER_ID_STATE,
        _require_digest(value["current_provider_id_digest"]),
        _require_digest(value["current_image_facts_digest"]),
        _require_digest(value["target_image_facts_digest"]),
        _require_digest(value["current_image_id_digest"]),
        _require_digest(value["target_image_id_digest"]),
        provider_sources,
        disposition,
        membership,
        service,
        _text(value["lifecycle_path"]),
        False,
        False,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
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
) -> OsReprovisionPrepareEvidence:
    source_value = cast(dict[str, object], expected["provider_source_digests"])
    return OsReprovisionPrepareEvidence(
        _text(expected["logical_id"]),
        HostRole(_text(expected["role"])),
        _text(expected["role_classification"]),
        OsReprovisionPrepareStatus.FAILED,
        "unapproved",
        REPROVISION_CLASSIFICATION,
        _text(expected["current_operating_system"]),
        _text(expected["current_operating_system_version"]),
        _text(expected["current_architecture"]),
        _text(expected["target_operating_system"]),
        _text(expected["target_operating_system_version"]),
        _text(expected["target_architecture"]),
        True,
        PROVIDER_IDENTITY_POLICY,
        REPLACEMENT_PROVIDER_ID_STATE,
        _require_digest(expected["current_provider_id_digest"]),
        _require_digest(expected["current_image_facts_digest"]),
        _require_digest(expected["target_image_facts_digest"]),
        _require_digest(expected["current_image_id_digest"]),
        _require_digest(expected["target_image_id_digest"]),
        tuple(
            sorted(
                (_text(name), _require_digest(item))
                for name, item in source_value.items()
            )
        ),
        ReprovisionStorageDisposition(_text(expected["storage_disposition"])),
        ReprovisionReadiness(_text(expected["membership_readiness"])),
        ReprovisionReadiness(_text(expected["service_readiness"])),
        _text(expected["lifecycle_path"]),
        False,
        False,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        ACTION_NOT_PERFORMED,
        MUTATION_BOUNDARY,
        False,
        NOT_PERFORMED,
        _provenance(expected),
        ("host-unreachable" if unreachable else "execution-failed",),
    )


def _parse_recap(stdout: str) -> dict[str, tuple[int, int, int]]:
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError(
            "Ansible OS-reprovision preparation output omitted PLAY RECAP"
        )
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible OS-reprovision preparation recap is malformed")
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


def _digest_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AnsibleError(
                "Ansible OS-reprovision preparation evidence has duplicate fields"
            )
        value[key] = item
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible OS-reprovision preparation value is invalid")
    return value


def _require_logical_id(value: str) -> str:
    if _LOGICAL_ID.fullmatch(value) is None:
        raise AnsibleError("OS-reprovision stable logical ID is invalid")
    return value


def _require_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError("Ansible OS-reprovision preparation boolean is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible OS-reprovision preparation digest is invalid")
    return text


def _sorted_strings(value: object, *, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError(f"Ansible OS-reprovision preparation {name} are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError(
            f"Ansible OS-reprovision preparation {name} are not uniquely sorted"
        )
    return items


def _reject_secrets(value: dict[str, object]) -> None:
    encoded = json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True)
    if re.search(
        r"(?i)(?:-----BEGIN [^-]*PRIVATE KEY-----|"
        r"(?:password|passphrase|secret|token)\s*[:=])",
        encoded,
    ):
        raise AnsibleError(
            "Ansible OS-reprovision preparation evidence contains a secret"
        )
