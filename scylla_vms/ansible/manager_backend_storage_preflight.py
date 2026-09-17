"""Strict read-only preflight for Manager-local dedicated backend storage."""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from scylla_vms.ansible.deploy_manager_backend_storage_discovery_reconciliation import (
    DeployManagerBackendStorageDiscoveryBoundaryStatus,
    StoredDeployManagerBackendStorageDiscoveryReconciliation,
)
from scylla_vms.ansible.deploy_manager_backend_storage_preflight_plan import (
    DeployManagerBackendStoragePreflightPlanStatus,
    DeployManagerBackendStoragePreflightSourceState,
    StoredDeployManagerBackendStoragePreflightContext,
    StoredDeployManagerBackendStoragePreflightPlan,
)
from scylla_vms.ansible.deploy_plan import _playbook_source_digest
from scylla_vms.ansible.orchestration import ansible_operation_catalog_digest
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.registry import get_playbook
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.desired import HostRole, StorageBackend, StorageLayout
from scylla_vms.errors import AnsibleError, StateConflictError, StatePersistenceError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata, validate_digest
from scylla_vms.terraform.inputs import StoredTerraformInput
from scylla_vms.terraform.outputs import StorageDeviceKind

MANAGER_BACKEND_STORAGE_PREFLIGHT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-manager-backend-storage-preflight/v1"
)
MANAGER_BACKEND_STORAGE_PREFLIGHT_NOT_PERFORMED = (
    "cql-access",
    "filesystem-creation",
    "fstab-write",
    "manager-configuration",
    "mount",
    "partition",
    "raid-creation",
    "service-mutation",
    "service-start",
    "setup",
    "storage-write",
    "tuning",
    "wipe",
)

_PLAYBOOK = "manager-backend-storage-preflight"
_MOUNT_BOUNDARY = "fixed-scylla-data-root"
_FILESYSTEM = "xfs"
_ROLE_MARKER = "manager-local-one-node-backend"
_ACTIONS = frozenset(
    {
        "create-xfs",
        "mount-scylla-data-root",
        "write-fstab",
        "write-manager-one-node-marker",
    }
)
_BLOCKERS = frozenset(
    {
        "ambiguous-device-match",
        "device-busy",
        "device-not-found",
        "device-size-conflict",
        "device-topology-conflict",
        "device-type-conflict",
        "foreign-ownership",
        "foreign-signature",
        "fstab-conflict",
        "identity-conflict",
        "manifest-conflict",
        "mount-conflict",
        "owned-layout-conflict",
        "preflight-failed",
        "root-or-boot-device",
        "signature-evidence-unavailable",
    }
)
_MARKER = re.compile(
    r"DSV_MANAGER_BACKEND_STORAGE_PREFLIGHT_B64="
    r"(?P<data>[A-Za-z0-9+/]+={0,2})"
)
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+"
    r"unreachable=(?P<unreachable>\d+)\s+failed=(?P<failed>\d+)\s+"
    r"skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)


class ManagerBackendStoragePreflightDisposition(StrEnum):
    OWNED_NOOP = "owned-noop"
    PREPARE_REQUIRED = "prepare-required"
    BLOCKED = "blocked"


class ManagerBackendStoragePreflightSignatureState(StrEnum):
    ABSENT = "absent"
    PRESENT = "present"
    UNKNOWN = "unknown"


class ManagerBackendStoragePreflightOwnershipState(StrEnum):
    UNOWNED = "unowned"
    MANAGER_OWNED = "manager-owned"
    FOREIGN = "foreign"
    UNKNOWN = "unknown"


class ManagerBackendStoragePreflightMountState(StrEnum):
    UNMOUNTED = "unmounted"
    EXPECTED = "expected-mounted"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


class ManagerBackendStoragePreflightFstabState(StrEnum):
    ABSENT = "absent"
    EXPECTED = "expected"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


class ManagerBackendStoragePreflightRoleMarkerState(StrEnum):
    ABSENT = "absent"
    EXPECTED = "expected"
    FOREIGN = "foreign"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ManagerBackendStoragePreflightEvidence:
    stable_id: str
    role: str
    backend: str
    layout: str
    filesystem: str
    mount_boundary: str
    capacity_policy_state: str
    capacity_sufficiency_state: str
    disposition: ManagerBackendStoragePreflightDisposition
    actions: tuple[str, ...]
    wipe_required: bool
    device_count: int
    requested_size_gib: int
    observed_size_gib: int
    device_size_gib: int
    signature_state: ManagerBackendStoragePreflightSignatureState
    ownership_state: ManagerBackendStoragePreflightOwnershipState
    mount_state: ManagerBackendStoragePreflightMountState
    fstab_state: ManagerBackendStoragePreflightFstabState
    role_marker_state: ManagerBackendStoragePreflightRoleMarkerState
    partition_present: bool
    raid_present: bool
    device_set_digest: str
    preparation_intent_digest: str
    blocker_digest: str
    provenance_digest: str
    blockers: tuple[str, ...]
    not_performed: tuple[str, ...]
    schema_version: str = MANAGER_BACKEND_STORAGE_PREFLIGHT_SCHEMA_VERSION


def build_manager_backend_storage_preflight_payload(
    metadata: ClusterMetadata,
    terraform_input: StoredTerraformInput,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    discovery: StoredDeployManagerBackendStorageDiscoveryReconciliation,
    context: StoredDeployManagerBackendStoragePreflightContext,
    plan: StoredDeployManagerBackendStoragePreflightPlan,
) -> dict[str, object]:
    """Derive the sole strict source payload from canonical immutable state."""

    context_record = context.record
    plan_record = plan.record
    policy = context_record.storage_policy
    target = context_record.manager_target_id
    source = load_ansible_source_bundle()
    definition = get_playbook(_PLAYBOOK)
    desired = tuple(
        item for item in metadata.desired_spec.storage if item.role is HostRole.MANAGER
    )
    observed_hosts = tuple(
        item
        for item in observed.record.manifest.hosts
        if item.logical_id == target and item.role is HostRole.MANAGER
    )
    inventory_hosts = tuple(
        item
        for item in inventory.record.inventory.hosts
        if item.logical_id == target and item.role is HostRole.MANAGER
    )
    if len(desired) != 1 or len(observed_hosts) != 1 or len(inventory_hosts) != 1:
        raise StateConflictError(
            "Manager backend storage preflight requires one exact Manager target"
        )
    desired_policy = desired[0]
    host = observed_hosts[0]
    inventory_host = inventory_hosts[0]
    storage = host.storage
    if (
        desired_policy.block_volume is None
        or len(storage.devices) != 1
        or storage.expected_device_count != 1
    ):
        raise StateConflictError(
            "Manager backend storage preflight manifest is ambiguous"
        )
    device = storage.devices[0]
    guest_identities = {
        "expected_by_id": device.expected_by_id,
        "expected_serial": device.expected_serial,
        "expected_wwn": device.expected_wwn,
    }
    discovery_record = discovery.record
    if (
        plan_record.status
        is not DeployManagerBackendStoragePreflightPlanStatus.ELIGIBLE
        or plan_record.source_state
        is not DeployManagerBackendStoragePreflightSourceState.AVAILABLE
        or plan_record.manager_target_id != target
        or plan_record.context_artifact_digest != context.artifact_digest
        or plan_record.context_record_digest != context_record.record_digest
        or plan_record.storage_policy_digest != policy.policy_digest
        or plan_record.preparation_intent_digest != policy.preparation_intent_digest
        or plan_record.device_set_digest != policy.device_set_digest
        or discovery.artifact_digest
        != context_record.discovery_reconciliation_artifact_digest
        or discovery_record.record_digest
        != context_record.discovery_reconciliation_record_digest
        or discovery_record.discovery_boundary_status
        is not DeployManagerBackendStorageDiscoveryBoundaryStatus.SUCCEEDED
        or discovery_record.target_stable_id != target
        or discovery_record.device_count != 1
        or discovery_record.device_set_digest != policy.device_set_digest
        or metadata.cluster_uuid != context_record.cluster_uuid
        or metadata.cluster_name != context_record.cluster_name
        or metadata.generation != context_record.metadata_generation
        or metadata.desired_spec.digest() != context_record.desired_spec_digest
        or terraform_input.record.generation
        != context_record.terraform_input_generation
        or terraform_input.digest != context_record.terraform_input_artifact_digest
        or terraform_input.record.input_digest != context_record.terraform_input_digest
        or observed.record.generation != context_record.observation_generation
        or observed.digest != context_record.observation_artifact_digest
        or observed.record.manifest_digest != context_record.observation_manifest_digest
        or inventory.record.generation != context_record.inventory_generation
        or inventory.digest != context_record.inventory_artifact_digest
        or inventory.record.inventory_digest != context_record.inventory_digest
        or readiness.observation_generation != observed.record.generation
        or readiness.observation_digest != observed.record.manifest_digest
        or readiness.inventory_generation != inventory.record.generation
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_generation != context_record.trust_generation
        or readiness.trust_digest != context_record.trust_artifact_digest
        or source.version != context_record.ansible_source_version
        or source.digest != context_record.ansible_source_digest
        or ansible_operation_catalog_digest() != context_record.catalog_digest
        or plan_record.source_digest != _playbook_source_digest(source, _PLAYBOOK)
        or not definition.source_available
        or desired_policy.requested_backend is not StorageBackend.BLOCK_VOLUME
        or desired_policy.layout is not StorageLayout.SINGLE
        or desired_policy.block_volume.count != 1
        or desired_policy.block_volume.size_gib != policy.requested_size_gib
        or storage.requested_backend is not StorageBackend.BLOCK_VOLUME
        or storage.selected_backend is not StorageBackend.BLOCK_VOLUME
        or storage.layout != StorageLayout.SINGLE.value
        or storage.devices[0].size_gib != policy.observed_size_gib
        or inventory_host.provider_id != host.provider_id
        or inventory_host.selected_storage_backend != StorageBackend.BLOCK_VOLUME.value
        or inventory_host.storage_device_count != 1
        or inventory_host.storage_raw_gib != policy.observed_size_gib
        or device.kind is not StorageDeviceKind.BLOCK_VOLUME
        or device.ephemeral
        or not any(value is not None for value in guest_identities.values())
    ):
        raise StateConflictError(
            "Manager backend storage preflight canonical provenance conflicts"
        )

    provenance = {
        "ansible_source_digest": source.digest,
        "catalog_digest": context_record.catalog_digest,
        "discovery_evidence_digest": discovery_record.evidence_digest,
        "discovery_reconciliation_digest": discovery_record.record_digest,
        "inventory_digest": inventory.digest,
        "observation_digest": observed.digest,
        "playbook_source_digest": plan_record.source_digest,
        "preflight_context_digest": context_record.record_digest,
        "preflight_plan_digest": plan_record.plan_digest,
        "storage_policy_digest": policy.policy_digest,
        "terraform_input_digest": terraform_input.digest,
        "trust_digest": readiness.trust_digest,
    }
    return {
        "backend": StorageBackend.BLOCK_VOLUME.value,
        "capacity_policy_state": policy.size_policy_state,
        "capacity_sufficiency_state": policy.capacity_sufficiency_state,
        "discovery_device_set_digest": policy.device_set_digest,
        "expected_device_count": 1,
        "filesystem": policy.filesystem,
        "guest_identities": guest_identities,
        "layout": policy.layout,
        "manifest_digest": policy.observed_manifest_digest,
        "mount_boundary": policy.mount_boundary,
        "not_performed": list(MANAGER_BACKEND_STORAGE_PREFLIGHT_NOT_PERFORMED),
        "observed_size_gib": policy.observed_size_gib,
        "preparation_actions": list(policy.preparation_actions),
        "preparation_intent_digest": policy.preparation_intent_digest,
        "provenance": provenance,
        "provenance_digest": _object_digest(provenance),
        "requested_size_gib": policy.requested_size_gib,
        "role": "manager",
        "role_marker": _ROLE_MARKER,
        "schema_version": MANAGER_BACKEND_STORAGE_PREFLIGHT_SCHEMA_VERSION,
        "stable_id": target,
        "storage_generation": storage.storage_generation,
        "storage_policy_digest": storage.policy_digest,
    }


def parse_manager_backend_storage_preflight_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> ManagerBackendStoragePreflightEvidence:
    """Parse exactly one strict redacted marker and one exact recap row."""

    if len(stdout.encode("utf-8")) > 256 * 1024:
        raise AnsibleError(
            "Ansible Manager backend storage preflight output is too large"
        )
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_MANAGER_BACKEND_STORAGE_PREFLIGHT_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError(
                "Ansible Manager backend storage preflight marker is malformed"
            )
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"), object_pairs_hook=_strict_object
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible Manager backend storage preflight marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError(
                "Ansible Manager backend storage preflight evidence is invalid"
            )
        values.append(value)
    _before, separator, after = stdout.partition("PLAY RECAP")
    if not separator:
        raise AnsibleError(
            "Ansible Manager backend storage preflight omitted PLAY RECAP"
        )
    rows: dict[str, tuple[int, int, int]] = {}
    for line in after.splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError(
                "Ansible Manager backend storage preflight recap is malformed"
            )
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    stable_id = _text(expected_payload["stable_id"])
    if set(rows) != {stable_id} or len(values) != 1:
        raise AnsibleError(
            "Ansible Manager backend storage preflight membership conflicts"
        )
    changed, unreachable, failed = rows[stable_id]
    if changed:
        raise AnsibleError(
            "Ansible Manager backend storage preflight reported a mutation"
        )
    evidence = _parse_result(values[0], expected_payload)
    process_failed = bool(unreachable or failed or exit_code)
    semantic_failed = (
        evidence.disposition is ManagerBackendStoragePreflightDisposition.BLOCKED
        and evidence.blockers == ("preflight-failed",)
    )
    if process_failed != semantic_failed:
        raise AnsibleError(
            "Ansible Manager backend storage preflight exit status conflicts"
        )
    return evidence


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> ManagerBackendStoragePreflightEvidence:
    fields = {
        "actions",
        "backend",
        "blocker_digest",
        "blockers",
        "capacity_policy_state",
        "capacity_sufficiency_state",
        "device_count",
        "device_set_digest",
        "device_size_gib",
        "disposition",
        "filesystem",
        "fstab_state",
        "layout",
        "mount_boundary",
        "mount_state",
        "not_performed",
        "observed_size_gib",
        "ownership_state",
        "partition_present",
        "preparation_intent_digest",
        "provenance_digest",
        "raid_present",
        "requested_size_gib",
        "role",
        "role_marker_state",
        "schema_version",
        "signature_state",
        "stable_id",
        "wipe_required",
    }
    if (
        set(value) != fields
        or value.get("schema_version")
        != MANAGER_BACKEND_STORAGE_PREFLIGHT_SCHEMA_VERSION
    ):
        raise AnsibleError(
            "Ansible Manager backend storage preflight schema is invalid"
        )
    if (
        value["stable_id"] != expected["stable_id"]
        or value["role"] != "manager"
        or value["backend"] != StorageBackend.BLOCK_VOLUME.value
        or value["layout"] != StorageLayout.SINGLE.value
        or value["filesystem"] != _FILESYSTEM
        or value["mount_boundary"] != _MOUNT_BOUNDARY
        or value["capacity_policy_state"] != expected["capacity_policy_state"]
        or value["capacity_sufficiency_state"] != expected["capacity_sufficiency_state"]
        or value["requested_size_gib"] != expected["requested_size_gib"]
        or value["observed_size_gib"] != expected["observed_size_gib"]
        or value["preparation_intent_digest"] != expected["preparation_intent_digest"]
        or value["not_performed"] != expected["not_performed"]
    ):
        raise AnsibleError(
            "Ansible Manager backend storage preflight evidence conflicts"
        )
    try:
        disposition = ManagerBackendStoragePreflightDisposition(
            _text(value["disposition"])
        )
        signature = ManagerBackendStoragePreflightSignatureState(
            _text(value["signature_state"])
        )
        ownership = ManagerBackendStoragePreflightOwnershipState(
            _text(value["ownership_state"])
        )
        mount = ManagerBackendStoragePreflightMountState(_text(value["mount_state"]))
        fstab = ManagerBackendStoragePreflightFstabState(_text(value["fstab_state"]))
        marker = ManagerBackendStoragePreflightRoleMarkerState(
            _text(value["role_marker_state"])
        )
    except ValueError as error:
        raise AnsibleError(
            "Ansible Manager backend storage preflight enum is invalid"
        ) from error
    actions = _sorted_choices(value["actions"], _ACTIONS, "preflight actions")
    blockers = _sorted_choices(value["blockers"], _BLOCKERS, "preflight blockers")
    device_count = _bounded_integer(value["device_count"], 0, 1, "device count")
    device_size = _bounded_integer(
        value["device_size_gib"], 0, 1024 * 1024, "device size"
    )
    wipe_required = _boolean(value["wipe_required"], "wipe requirement")
    partition_present = _boolean(value["partition_present"], "partition state")
    raid_present = _boolean(value["raid_present"], "RAID state")
    device_set_digest = _digest(value["device_set_digest"])
    preparation_intent_digest = _digest(value["preparation_intent_digest"])
    blocker_digest = _digest(value["blocker_digest"])
    provenance_digest = _digest(value["provenance_digest"])
    not_performed = _sorted_strings(value["not_performed"], "not performed")
    if (
        blocker_digest != _object_digest(list(blockers))
        or provenance_digest != _object_digest(expected["provenance"])
        or not_performed != tuple(cast(list[str], expected["not_performed"]))
    ):
        raise AnsibleError("Ansible Manager backend storage preflight digest conflicts")
    expected_actions = tuple(cast(list[str], expected["preparation_actions"]))
    if disposition is ManagerBackendStoragePreflightDisposition.OWNED_NOOP:
        valid = (
            not blockers
            and not actions
            and not wipe_required
            and device_count == 1
            and device_size == expected["observed_size_gib"]
            and device_set_digest == expected["discovery_device_set_digest"]
            and signature is ManagerBackendStoragePreflightSignatureState.PRESENT
            and ownership is ManagerBackendStoragePreflightOwnershipState.MANAGER_OWNED
            and mount is ManagerBackendStoragePreflightMountState.EXPECTED
            and fstab is ManagerBackendStoragePreflightFstabState.EXPECTED
            and marker is ManagerBackendStoragePreflightRoleMarkerState.EXPECTED
            and not partition_present
            and not raid_present
        )
    elif disposition is ManagerBackendStoragePreflightDisposition.PREPARE_REQUIRED:
        valid = (
            not blockers
            and device_count == 1
            and device_size == expected["observed_size_gib"]
            and device_set_digest == expected["discovery_device_set_digest"]
            and ownership is ManagerBackendStoragePreflightOwnershipState.UNOWNED
            and mount is ManagerBackendStoragePreflightMountState.UNMOUNTED
            and fstab is ManagerBackendStoragePreflightFstabState.ABSENT
            and marker is ManagerBackendStoragePreflightRoleMarkerState.ABSENT
            and not partition_present
            and not raid_present
            and actions == expected_actions
            and not wipe_required
            and signature is ManagerBackendStoragePreflightSignatureState.ABSENT
        )
    else:
        foreign_signature = "foreign-signature" in blockers
        valid = (
            bool(blockers)
            and not actions
            and wipe_required is foreign_signature
            and (
                not foreign_signature
                or (
                    signature is ManagerBackendStoragePreflightSignatureState.PRESENT
                    and ownership
                    is ManagerBackendStoragePreflightOwnershipState.UNOWNED
                )
            )
        )
    if not valid:
        raise AnsibleError(
            "Ansible Manager backend storage preflight disposition conflicts"
        )
    return ManagerBackendStoragePreflightEvidence(
        stable_id=_text(value["stable_id"]),
        role="manager",
        backend=StorageBackend.BLOCK_VOLUME.value,
        layout=StorageLayout.SINGLE.value,
        filesystem=_FILESYSTEM,
        mount_boundary=_MOUNT_BOUNDARY,
        capacity_policy_state=_text(value["capacity_policy_state"]),
        capacity_sufficiency_state=_text(value["capacity_sufficiency_state"]),
        disposition=disposition,
        actions=actions,
        wipe_required=wipe_required,
        device_count=device_count,
        requested_size_gib=_bounded_integer(
            value["requested_size_gib"], 1, 1024 * 1024, "requested size"
        ),
        observed_size_gib=_bounded_integer(
            value["observed_size_gib"], 1, 1024 * 1024, "observed size"
        ),
        device_size_gib=device_size,
        signature_state=signature,
        ownership_state=ownership,
        mount_state=mount,
        fstab_state=fstab,
        role_marker_state=marker,
        partition_present=partition_present,
        raid_present=raid_present,
        device_set_digest=device_set_digest,
        preparation_intent_digest=preparation_intent_digest,
        blocker_digest=blocker_digest,
        provenance_digest=provenance_digest,
        blockers=blockers,
        not_performed=not_performed,
    )


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _digest(value: object) -> str:
    if not isinstance(value, str):
        raise AnsibleError(
            "Ansible Manager backend storage preflight digest is invalid"
        )
    try:
        validate_digest(value, "Manager backend storage preflight digest")
    except StatePersistenceError as error:
        raise AnsibleError(
            "Ansible Manager backend storage preflight digest is invalid"
        ) from error
    return value


def _sorted_choices(
    value: object, choices: frozenset[str], label: str
) -> tuple[str, ...]:
    values = _sorted_strings(value, label)
    if any(item not in choices for item in values):
        raise AnsibleError(f"Ansible Manager backend storage {label} is invalid")
    return values


def _sorted_strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise AnsibleError(f"Ansible Manager backend storage {label} is invalid")
    result = tuple(cast(list[str], value))
    if result != tuple(sorted(set(result))):
        raise AnsibleError(f"Ansible Manager backend storage {label} is not canonical")
    return result


def _bounded_integer(value: object, minimum: int, maximum: int, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise AnsibleError(f"Ansible Manager backend storage {label} is invalid")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError(f"Ansible Manager backend storage {label} is invalid")
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise AnsibleError("Ansible Manager backend storage preflight text is invalid")
    return value


def _object_digest(value: object) -> str:
    import hashlib

    data = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


__all__ = [
    "MANAGER_BACKEND_STORAGE_PREFLIGHT_NOT_PERFORMED",
    "MANAGER_BACKEND_STORAGE_PREFLIGHT_SCHEMA_VERSION",
    "ManagerBackendStoragePreflightDisposition",
    "ManagerBackendStoragePreflightEvidence",
    "ManagerBackendStoragePreflightFstabState",
    "ManagerBackendStoragePreflightMountState",
    "ManagerBackendStoragePreflightOwnershipState",
    "ManagerBackendStoragePreflightRoleMarkerState",
    "ManagerBackendStoragePreflightSignatureState",
    "build_manager_backend_storage_preflight_payload",
    "parse_manager_backend_storage_preflight_execution",
]
