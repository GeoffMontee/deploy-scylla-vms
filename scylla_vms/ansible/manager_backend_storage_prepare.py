"""Strict Manager-local dedicated-storage preparation source contract."""

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

from scylla_vms.ansible.deploy_manager_backend_local_install_reconciliation import (
    StoredDeployPostManagerBackendLocalInstallReconciliation,
)
from scylla_vms.ansible.deploy_manager_backend_storage_preflight_execution import (
    DeployManagerBackendStoragePreflightExecutionState,
    StoredDeployManagerBackendStoragePreflightEvidence,
    StoredDeployManagerBackendStoragePreflightExecution,
)
from scylla_vms.ansible.deploy_manager_backend_storage_preflight_reconciliation import (
    DeployManagerBackendStoragePreflightBoundaryStatus,
    DeployManagerBackendStoragePreflightNextStatus,
    DeployManagerBackendStoragePreparationScopeState,
    StoredDeployManagerBackendStoragePreflightReconciliation,
)
from scylla_vms.ansible.deploy_plan import _playbook_source_digest
from scylla_vms.ansible.manager_backend_storage_preflight import (
    ManagerBackendStoragePreflightDisposition,
)
from scylla_vms.ansible.orchestration import ansible_operation_catalog_digest
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.desired import HostRole, StorageBackend, StorageLayout
from scylla_vms.errors import AnsibleError, StateConflictError, StatePersistenceError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import ClusterMetadata, validate_digest
from scylla_vms.terraform.inputs import StoredTerraformInput
from scylla_vms.terraform.outputs import StorageDeviceKind

MANAGER_BACKEND_STORAGE_PREPARE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-manager-backend-storage-prepare/v1"
)
MANAGER_BACKEND_STORAGE_PREPARE_NOT_PERFORMED = (
    "cql-access",
    "lvm-creation",
    "manager-configuration",
    "manager-registration",
    "manager-tasks",
    "package-changes",
    "partition",
    "raid-creation",
    "scylla-configuration",
    "schema-or-keyspace",
    "service-enable",
    "service-start",
    "setup",
    "tuning",
)

_PLAYBOOK = "manager-backend-storage-prepare"
_FILESYSTEM = "xfs"
_MOUNT_BOUNDARY = "fixed-scylla-data-root"
_CAPACITY_POLICY_BINDING = "operator-selected-allocation-conformance"
_CAPACITY_SUFFICIENCY = "not-proven"
_ACTION = "prepare-required"
_ACTIONS = (
    "create-xfs",
    "mount-scylla-data-root",
    "write-fstab",
    "write-manager-one-node-marker",
)
_VERIFICATION_FIELDS = (
    "fstab",
    "marker",
    "mount",
    "ownership",
    "xfs",
)
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MARKER = re.compile(
    r"DSV_MANAGER_BACKEND_STORAGE_PREPARE_B64="
    r"(?P<data>[A-Za-z0-9+/]+={0,2})"
)
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+"
    r"unreachable=(?P<unreachable>\d+)\s+failed=(?P<failed>\d+)\s+"
    r"skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)


class ManagerBackendStoragePrepareStatus(StrEnum):
    CHANGED = "changed"
    FAILED = "failed"


class ManagerBackendStorageMutationBoundary(StrEnum):
    NOT_CROSSED = "not-crossed"
    CROSSED = "crossed"
    COMPLETED = "completed"


class ManagerBackendStorageVerificationStatus(StrEnum):
    VERIFIED = "verified"
    NOT_VERIFIED = "not-verified"


@dataclass(frozen=True, slots=True)
class ManagerBackendStoragePreparationAuthorization:
    """Typed proof for one operation/node/scope; wipe consent stays separate."""

    operation_id: uuid.UUID
    stable_id: str
    preparation_scope_digest: str
    device_set_digest: str
    preparation_intent_digest: str
    preparation_approved: bool
    wipe_approved: bool
    wipe_scope_digest: str | None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.operation_id, uuid.UUID)
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or not isinstance(self.preparation_approved, bool)
            or not isinstance(self.wipe_approved, bool)
            or (self.wipe_approved != (self.wipe_scope_digest is not None))
        ):
            raise AnsibleError(
                "Manager backend storage preparation authorization is invalid"
            )
        for value in (
            self.preparation_scope_digest,
            self.device_set_digest,
            self.preparation_intent_digest,
        ):
            _digest(value)
        if self.wipe_scope_digest is not None:
            _digest(self.wipe_scope_digest)


@dataclass(frozen=True, slots=True)
class ManagerBackendStoragePrepareEvidence:
    stable_id: str
    role: str
    backend: str
    layout: str
    disposition: str
    status: ManagerBackendStoragePrepareStatus
    action_count: int
    device_count: int
    requested_size_gib: int
    observed_size_gib: int
    discovered_size_gib: int
    capacity_policy_binding: str
    capacity_sufficiency_state: str
    device_set_digest: str
    preparation_intent_digest: str
    provenance_digest: str
    wipe_applied: bool
    mutation_boundary: ManagerBackendStorageMutationBoundary
    first_irreversible_step: str | None
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    xfs_status: ManagerBackendStorageVerificationStatus
    fstab_status: ManagerBackendStorageVerificationStatus
    mount_status: ManagerBackendStorageVerificationStatus
    marker_status: ManagerBackendStorageVerificationStatus
    ownership_status: ManagerBackendStorageVerificationStatus
    not_performed: tuple[str, ...]
    schema_version: str = MANAGER_BACKEND_STORAGE_PREPARE_SCHEMA_VERSION


def build_manager_backend_storage_prepare_payload(
    metadata: ClusterMetadata,
    terraform_input: StoredTerraformInput,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    package_reconciliation: StoredDeployPostManagerBackendLocalInstallReconciliation,
    preflight_execution: StoredDeployManagerBackendStoragePreflightExecution,
    preflight_evidence: StoredDeployManagerBackendStoragePreflightEvidence,
    preflight_reconciliation: StoredDeployManagerBackendStoragePreflightReconciliation,
    authorization: ManagerBackendStoragePreparationAuthorization,
    *,
    limit: tuple[str, ...],
    check: bool,
) -> dict[str, object]:
    """Revalidate the exact immutable prepare-required scope before runtime."""

    source = load_ansible_source_bundle()
    definition = get_playbook(_PLAYBOOK)
    package = package_reconciliation.record
    execution = preflight_execution.record
    binding = execution.binding
    evidence = preflight_evidence.record
    preflight = preflight_reconciliation.record
    if (
        check
        or limit != (authorization.stable_id,)
        or authorization.operation_id != preflight.operation_id
        or authorization.stable_id != preflight.target_stable_id
        or not authorization.preparation_approved
        or preflight.preflight_boundary_status
        is not DeployManagerBackendStoragePreflightBoundaryStatus.SUCCEEDED
        or preflight.disposition
        is not ManagerBackendStoragePreflightDisposition.PREPARE_REQUIRED
        or preflight.preparation_scope_state
        is not DeployManagerBackendStoragePreparationScopeState.DERIVED
        or len(preflight.preparation_scopes) != 1
        or preflight.preparation_target_count != 1
        or preflight.next_status
        is not DeployManagerBackendStoragePreflightNextStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        or preflight.storage_preparation_source_state != "source-available"
        or execution.state
        is not DeployManagerBackendStoragePreflightExecutionState.SUCCEEDED
        or not execution.completed
        or execution.exit_code != 0
        or execution.manual_recovery_required
        or execution.automatic_retry_allowed
        or execution.result_digest != evidence.result_digest
        or execution.evidence_digest != evidence.evidence_digest
        or evidence.disposition
        is not ManagerBackendStoragePreflightDisposition.PREPARE_REQUIRED
        or evidence.actions != _ACTIONS
        or evidence.wipe_required
        or evidence.blocker_count
        or evidence.device_count != 1
    ):
        raise StateConflictError(
            "Manager backend storage preparation requires one exact authorized "
            "prepare-required scope"
        )
    scope = preflight.preparation_scopes[0]
    if (
        scope.stable_id != authorization.stable_id
        or scope.scope_digest != authorization.preparation_scope_digest
        or scope.device_set_digest != authorization.device_set_digest
        or scope.preparation_intent_digest != authorization.preparation_intent_digest
    ):
        raise StateConflictError(
            "Manager backend storage preparation authorization scope conflicts"
        )
    if (
        preflight.wipe_required != authorization.wipe_approved
        or (
            authorization.wipe_approved
            and authorization.wipe_scope_digest != preflight.wipe_scope_digest
        )
        or (
            not authorization.wipe_approved
            and authorization.wipe_scope_digest is not None
        )
    ):
        raise StateConflictError(
            "Manager backend storage wipe requires separate exact scope consent"
        )

    desired = tuple(
        item for item in metadata.desired_spec.storage if item.role is HostRole.MANAGER
    )
    observed_hosts = tuple(
        item
        for item in observed.record.manifest.hosts
        if item.logical_id == authorization.stable_id and item.role is HostRole.MANAGER
    )
    inventory_hosts = tuple(
        item
        for item in inventory.record.inventory.hosts
        if item.logical_id == authorization.stable_id and item.role is HostRole.MANAGER
    )
    if len(desired) != 1 or len(observed_hosts) != 1 or len(inventory_hosts) != 1:
        raise StateConflictError(
            "Manager backend storage preparation target identity is ambiguous"
        )
    desired_policy = desired[0]
    host = observed_hosts[0]
    inventory_host = inventory_hosts[0]
    storage = host.storage
    if (
        desired_policy.requested_backend is not StorageBackend.BLOCK_VOLUME
        or desired_policy.layout is not StorageLayout.SINGLE
        or desired_policy.block_volume is None
        or desired_policy.block_volume.count != 1
        or storage.requested_backend is not StorageBackend.BLOCK_VOLUME
        or storage.selected_backend is not StorageBackend.BLOCK_VOLUME
        or storage.layout != StorageLayout.SINGLE.value
        or storage.expected_device_count != 1
        or len(storage.devices) != 1
        or storage.devices[0].kind is not StorageDeviceKind.BLOCK_VOLUME
        or storage.devices[0].ephemeral
        or inventory_host.provider_id != host.provider_id
        or inventory_host.selected_storage_backend != StorageBackend.BLOCK_VOLUME.value
        or inventory_host.storage_device_count != 1
    ):
        raise StateConflictError(
            "Manager backend storage preparation dedicated-volume policy conflicts"
        )
    device = storage.devices[0]
    identities = {
        "expected_by_id": device.expected_by_id,
        "expected_serial": device.expected_serial,
        "expected_wwn": device.expected_wwn,
    }
    requested_size = desired_policy.block_volume.size_gib
    observed_size = device.size_gib
    discovered_size = evidence.device_size_gib
    if (
        requested_size != observed_size
        or requested_size != discovered_size
        or requested_size != evidence.requested_size_gib
        or observed_size != evidence.observed_size_gib
        or inventory_host.storage_raw_gib != requested_size
        or not any(value is not None for value in identities.values())
        or preflight.device_set_digest != authorization.device_set_digest
        or preflight.preparation_intent_digest
        != authorization.preparation_intent_digest
    ):
        raise StateConflictError(
            "Manager backend storage allocation conformance is not proven"
        )

    if (
        package.operation_id != authorization.operation_id
        or package.cluster_uuid != metadata.cluster_uuid
        or package.cluster_name != metadata.cluster_name
        or package.target_stable_id != authorization.stable_id
        or package.installed_count != 1
        or package.service_safe_count != 1
        or package.prohibited_action_count != 0
        or not package.authorization_consumed
        or package.ansible_source_digest != source.digest
        or metadata.generation != package.metadata_generation
        or metadata.desired_spec.digest() != package.desired_spec_digest
        or observed.record.generation != package.observation_generation
        or observed.digest != package.observation_artifact_digest
        or observed.record.manifest_digest != package.observation_manifest_digest
        or inventory.record.generation != package.inventory_generation
        or inventory.digest != package.inventory_artifact_digest
        or inventory.record.inventory_digest != package.inventory_digest
        or readiness.observation_generation != observed.record.generation
        or readiness.observation_digest != observed.record.manifest_digest
        or readiness.inventory_generation != inventory.record.generation
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_generation != package.trust_generation
        or readiness.trust_digest != package.trust_artifact_digest
        or binding.package_reconciliation_artifact_digest
        != package_reconciliation.artifact_digest
        or binding.package_reconciliation_record_digest != package.record_digest
        or binding.terraform_input_generation != terraform_input.record.generation
        or binding.terraform_input_artifact_digest != terraform_input.digest
        or binding.terraform_input_digest != terraform_input.record.input_digest
        or binding.observation_generation != observed.record.generation
        or binding.observation_artifact_digest != observed.digest
        or binding.observation_manifest_digest != observed.record.manifest_digest
        or binding.inventory_generation != inventory.record.generation
        or binding.inventory_artifact_digest != inventory.digest
        or binding.inventory_digest != inventory.record.inventory_digest
        or binding.readiness_artifact_digest != package.readiness_artifact_digest
        or binding.readiness_record_digest != package.readiness_record_digest
        or binding.preparation_intent_digest != evidence.preparation_intent_digest
        or binding.discovery_device_set_digest != evidence.device_set_digest
        or preflight.source_digest != source.digest
        or binding.source_digest != source.digest
        or binding.catalog_digest != ansible_operation_catalog_digest()
        or definition.target_groups != ("manager",)
        or definition.classification is not OperationClassification.DESTRUCTIVE
        or definition.check_mode is not CheckMode.REFUSED
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.serial != 1
        or not definition.any_errors_fatal
        or not definition.source_available
    ):
        raise StateConflictError(
            "Manager backend storage preparation canonical provenance conflicts"
        )
    source_digest = _playbook_source_digest(source, _PLAYBOOK)
    if source_digest != binding.playbook_source_digest:
        raise StateConflictError(
            "Manager backend storage preparation playbook provenance conflicts"
        )
    provenance = {
        "ansible_source_digest": source.digest,
        "catalog_digest": binding.catalog_digest,
        "desired_policy_digest": preflight.desired_policy_digest,
        "device_set_digest": preflight.device_set_digest,
        "inventory_digest": inventory.digest,
        "manifest_digest": preflight.manifest_digest,
        "observation_digest": observed.digest,
        "package_reconciliation_digest": package.record_digest,
        "playbook_source_digest": source_digest,
        "preflight_evidence_digest": evidence.evidence_digest,
        "preflight_execution_binding_digest": binding.binding_digest,
        "preflight_reconciliation_digest": preflight.record_digest,
        "preparation_intent_digest": preflight.preparation_intent_digest,
        "terraform_input_digest": terraform_input.digest,
        "trust_digest": readiness.trust_digest,
    }
    return {
        "action": _ACTION,
        "authorization": {
            "device_set_digest": authorization.device_set_digest,
            "operation_id": str(authorization.operation_id),
            "preparation_approved": True,
            "preparation_intent_digest": authorization.preparation_intent_digest,
            "preparation_scope_digest": authorization.preparation_scope_digest,
            "wipe_approved": authorization.wipe_approved,
            "wipe_scope_digest": authorization.wipe_scope_digest,
        },
        "backend": StorageBackend.BLOCK_VOLUME.value,
        "capacity_policy_binding": _CAPACITY_POLICY_BINDING,
        "capacity_sufficiency_state": _CAPACITY_SUFFICIENCY,
        "check_mode_requested": False,
        "cluster_uuid": str(metadata.cluster_uuid),
        "device_count": 1,
        "discovered_size_gib": discovered_size,
        "disposition": preflight.disposition.value,
        "filesystem": _FILESYSTEM,
        "guest_identities": identities,
        "layout": StorageLayout.SINGLE.value,
        "mount_boundary": _MOUNT_BOUNDARY,
        "not_performed": list(MANAGER_BACKEND_STORAGE_PREPARE_NOT_PERFORMED),
        "observed_size_gib": observed_size,
        "provenance": provenance,
        "provenance_digest": _object_digest(provenance),
        "requested_size_gib": requested_size,
        "role": "manager",
        "schema_version": MANAGER_BACKEND_STORAGE_PREPARE_SCHEMA_VERSION,
        "stable_id": authorization.stable_id,
        "storage_generation": storage.storage_generation,
        "storage_policy_digest": storage.policy_digest,
    }


def parse_manager_backend_storage_prepare_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> ManagerBackendStoragePrepareEvidence:
    """Parse one strict redacted preparation result and exact recap row."""

    if len(stdout.encode("utf-8")) > 256 * 1024:
        raise AnsibleError(
            "Ansible Manager backend storage preparation output is too large"
        )
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_MANAGER_BACKEND_STORAGE_PREPARE_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError(
                "Ansible Manager backend storage preparation marker is malformed"
            )
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"), object_pairs_hook=_strict_object
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible Manager backend storage preparation marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError(
                "Ansible Manager backend storage preparation evidence is invalid"
            )
        values.append(value)
    _before, separator, after = stdout.partition("PLAY RECAP")
    if not separator:
        raise AnsibleError(
            "Ansible Manager backend storage preparation omitted PLAY RECAP"
        )
    rows: dict[str, tuple[int, int, int]] = {}
    for line in after.splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError(
                "Ansible Manager backend storage preparation recap is malformed"
            )
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    stable_id = _text(expected_payload["stable_id"])
    if set(rows) != {stable_id} or len(values) != 1:
        raise AnsibleError(
            "Ansible Manager backend storage preparation membership conflicts"
        )
    evidence = _parse_result(values[0], expected_payload)
    changed, unreachable, failed = rows[stable_id]
    process_failed = bool(unreachable or failed or exit_code)
    semantic_failed = evidence.status is ManagerBackendStoragePrepareStatus.FAILED
    if (
        process_failed != semantic_failed
        or (
            not semantic_failed
            and not (
                changed > 0
                and evidence.status is ManagerBackendStoragePrepareStatus.CHANGED
            )
        )
        or (
            semantic_failed
            and (changed > 0)
            != (
                evidence.mutation_boundary
                is ManagerBackendStorageMutationBoundary.CROSSED
            )
        )
    ):
        raise AnsibleError(
            "Ansible Manager backend storage preparation exit status conflicts"
        )
    return evidence


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> ManagerBackendStoragePrepareEvidence:
    fields = {
        "action_count",
        "automatic_retry_allowed",
        "backend",
        "capacity_policy_binding",
        "capacity_sufficiency_state",
        "device_count",
        "device_set_digest",
        "discovered_size_gib",
        "disposition",
        "first_irreversible_step",
        "fstab_status",
        "layout",
        "manual_recovery_required",
        "marker_status",
        "mount_status",
        "mutation_boundary",
        "not_performed",
        "observed_size_gib",
        "ownership_status",
        "preparation_intent_digest",
        "provenance_digest",
        "requested_size_gib",
        "role",
        "schema_version",
        "stable_id",
        "status",
        "wipe_applied",
        "xfs_status",
    }
    if (
        set(value) != fields
        or value.get("schema_version") != MANAGER_BACKEND_STORAGE_PREPARE_SCHEMA_VERSION
    ):
        raise AnsibleError(
            "Ansible Manager backend storage preparation schema is invalid"
        )
    authorization = cast(dict[str, object], expected["authorization"])
    if (
        value["stable_id"] != expected["stable_id"]
        or value["role"] != "manager"
        or value["backend"] != StorageBackend.BLOCK_VOLUME.value
        or value["layout"] != StorageLayout.SINGLE.value
        or value["disposition"] != _ACTION
        or value["capacity_policy_binding"] != _CAPACITY_POLICY_BINDING
        or value["capacity_sufficiency_state"] != _CAPACITY_SUFFICIENCY
        or value["requested_size_gib"] != expected["requested_size_gib"]
        or value["observed_size_gib"] != expected["observed_size_gib"]
        or value["discovered_size_gib"] != expected["discovered_size_gib"]
        or value["device_set_digest"] != authorization["device_set_digest"]
        or value["preparation_intent_digest"]
        != authorization["preparation_intent_digest"]
        or value["provenance_digest"] != expected["provenance_digest"]
        or value["not_performed"] != expected["not_performed"]
    ):
        raise AnsibleError(
            "Ansible Manager backend storage preparation evidence conflicts"
        )
    try:
        status = ManagerBackendStoragePrepareStatus(_text(value["status"]))
        boundary = ManagerBackendStorageMutationBoundary(
            _text(value["mutation_boundary"])
        )
        verification = {
            name: ManagerBackendStorageVerificationStatus(
                _text(value[f"{name}_status"])
            )
            for name in _VERIFICATION_FIELDS
        }
    except ValueError as error:
        raise AnsibleError(
            "Ansible Manager backend storage preparation enum is invalid"
        ) from error
    action_count = _bounded_integer(value["action_count"], 0, len(_ACTIONS))
    device_count = _bounded_integer(value["device_count"], 0, 1)
    wipe_applied = _boolean(value["wipe_applied"])
    manual_recovery = _boolean(value["manual_recovery_required"])
    automatic_retry = _boolean(value["automatic_retry_allowed"])
    first_step = _optional_choice(
        value["first_irreversible_step"], {"signatures-wiped", "xfs-created"}
    )
    success = status is ManagerBackendStoragePrepareStatus.CHANGED
    wipe_authorized = cast(bool, authorization["wipe_approved"])
    if success:
        valid = (
            action_count == len(_ACTIONS)
            and device_count == 1
            and boundary is ManagerBackendStorageMutationBoundary.COMPLETED
            and first_step == ("signatures-wiped" if wipe_authorized else "xfs-created")
            and wipe_applied is wipe_authorized
            and not manual_recovery
            and not automatic_retry
            and all(
                item is ManagerBackendStorageVerificationStatus.VERIFIED
                for item in verification.values()
            )
        )
    else:
        valid = (
            action_count <= len(_ACTIONS)
            and boundary
            in {
                ManagerBackendStorageMutationBoundary.NOT_CROSSED,
                ManagerBackendStorageMutationBoundary.CROSSED,
            }
            and manual_recovery
            is (boundary is ManagerBackendStorageMutationBoundary.CROSSED)
            and not automatic_retry
            and (
                first_step is None
                if boundary is ManagerBackendStorageMutationBoundary.NOT_CROSSED
                else first_step is not None
            )
        )
    if not valid:
        raise AnsibleError(
            "Ansible Manager backend storage preparation result conflicts"
        )
    return ManagerBackendStoragePrepareEvidence(
        stable_id=_text(value["stable_id"]),
        role="manager",
        backend=StorageBackend.BLOCK_VOLUME.value,
        layout=StorageLayout.SINGLE.value,
        disposition=_ACTION,
        status=status,
        action_count=action_count,
        device_count=device_count,
        requested_size_gib=_bounded_integer(
            value["requested_size_gib"], 1, 1024 * 1024
        ),
        observed_size_gib=_bounded_integer(value["observed_size_gib"], 1, 1024 * 1024),
        discovered_size_gib=_bounded_integer(
            value["discovered_size_gib"], 1, 1024 * 1024
        ),
        capacity_policy_binding=_CAPACITY_POLICY_BINDING,
        capacity_sufficiency_state=_CAPACITY_SUFFICIENCY,
        device_set_digest=_digest(value["device_set_digest"]),
        preparation_intent_digest=_digest(value["preparation_intent_digest"]),
        provenance_digest=_digest(value["provenance_digest"]),
        wipe_applied=wipe_applied,
        mutation_boundary=boundary,
        first_irreversible_step=first_step,
        manual_recovery_required=manual_recovery,
        automatic_retry_allowed=automatic_retry,
        xfs_status=verification["xfs"],
        fstab_status=verification["fstab"],
        mount_status=verification["mount"],
        marker_status=verification["marker"],
        ownership_status=verification["ownership"],
        not_performed=tuple(cast(list[str], value["not_performed"])),
    )


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024 or "\0" in value:
        raise AnsibleError(
            "Ansible Manager backend storage preparation text is invalid"
        )
    return value


def _digest(value: object) -> str:
    text = _text(value)
    try:
        validate_digest(text, "Manager backend storage preparation digest")
    except StatePersistenceError as error:
        raise AnsibleError(
            "Ansible Manager backend storage preparation digest is invalid"
        ) from error
    return text


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError(
            "Ansible Manager backend storage preparation boolean is invalid"
        )
    return value


def _bounded_integer(value: object, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise AnsibleError(
            "Ansible Manager backend storage preparation count is invalid"
        )
    return value


def _optional_choice(value: object, choices: set[str]) -> str | None:
    if value is None:
        return None
    text = _text(value)
    if text not in choices:
        raise AnsibleError(
            "Ansible Manager backend storage irreversible step is invalid"
        )
    return text


def _object_digest(value: object) -> str:
    data = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


__all__ = [
    "MANAGER_BACKEND_STORAGE_PREPARE_NOT_PERFORMED",
    "MANAGER_BACKEND_STORAGE_PREPARE_SCHEMA_VERSION",
    "ManagerBackendStorageMutationBoundary",
    "ManagerBackendStoragePreparationAuthorization",
    "ManagerBackendStoragePrepareEvidence",
    "ManagerBackendStoragePrepareStatus",
    "ManagerBackendStorageVerificationStatus",
    "build_manager_backend_storage_prepare_payload",
    "parse_manager_backend_storage_prepare_execution",
]
