"""Fail-closed storage preparation authorization and result evidence."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from enum import StrEnum

from scylla_vms.ansible.storage import StorageDiscoveryEvidence
from scylla_vms.ansible.storage_preflight import (
    StorageOwnershipStatus,
    StoragePreflightResult,
    reconcile_storage_preflight,
)
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata, digest_bytes, serialize_json

STORAGE_PREPARE_SCHEMA_VERSION = "deploy-scylla-vms.ansible-storage-prepare/v1"
STORAGE_OWNER_SCHEMA_VERSION = "deploy-scylla-vms.prepared-storage/v1"
CANONICAL_SCYLLA_MOUNT = "/var/lib/scylla"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MARKER = re.compile(
    r'DSV_STORAGE_PREPARE_B64=(?P<data>[A-Za-z0-9+/]+={0,2})"(?:\})?\s*$'
)
_RESULT_KEYS = {
    "backend",
    "completed_steps",
    "device_set_digest",
    "filesystem_uuid_digest",
    "irreversible_step_status",
    "layout",
    "logical_id",
    "marker_digest",
    "post_action_verification",
    "schema_version",
    "status",
}
_DEPLOY_RESULT_KEYS = _RESULT_KEYS | {
    "action",
    "completed",
    "disposition",
    "first_irreversible_step",
    "immediate_device_revalidation",
    "mutation_boundary",
    "preparation_intent_digest",
    "provenance_digest",
    "wipe_applied",
}
_DEPLOY_ACTION = "prepare-required"
_DEPLOY_DISPOSITIONS = frozenset(
    {
        StorageOwnershipStatus.CLEAN_NEW.value,
        StorageOwnershipStatus.WIPE_REVIEW_REQUIRED.value,
    }
)
_MUTATION_BOUNDARIES = frozenset({"not-crossed", "crossed", "completed"})
_IRREVERSIBLE_STEPS = frozenset({"signatures-wiped", "raid0-created", "xfs-formatted"})


class StoragePrepareStatus(StrEnum):
    CHANGED = "changed"
    NOOP = "noop"
    NOT_PREDICTED = "not-predicted"
    FAILED = "failed"


class IrreversibleStepStatus(StrEnum):
    NOT_STARTED = "not-started"
    STARTED = "started"
    COMPLETED = "completed"


@dataclass(frozen=True, slots=True)
class StoragePreparationAuthorization:
    """Narrow approval bound to one operation, node, intent, and device set."""

    operation_id: uuid.UUID
    logical_id: str
    preparation_intent_digest: str
    device_set_digest: str
    preparation_approved: bool
    wipe_acknowledged: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.operation_id, uuid.UUID):
            raise AnsibleError("storage preparation operation ID is invalid")
        if (
            not self.logical_id
            or _DIGEST.fullmatch(self.preparation_intent_digest) is None
            or _DIGEST.fullmatch(self.device_set_digest) is None
            or not isinstance(self.preparation_approved, bool)
            or not isinstance(self.wipe_acknowledged, bool)
        ):
            raise AnsibleError("storage preparation authorization is invalid")


@dataclass(frozen=True, slots=True)
class StoragePrepareEvidence:
    logical_id: str
    status: StoragePrepareStatus
    backend: str
    layout: str
    device_set_digest: str
    filesystem_uuid_digest: str | None
    marker_digest: str | None
    irreversible_step_status: IrreversibleStepStatus
    completed_steps: tuple[str, ...]
    post_action_verification: tuple[tuple[str, bool], ...]
    action: str | None = None
    disposition: str | None = None
    immediate_device_revalidation: bool | None = None
    preparation_intent_digest: str | None = None
    provenance_digest: str | None = None
    wipe_applied: bool | None = None
    mutation_boundary: str | None = None
    first_irreversible_step: str | None = None
    completed: bool | None = None
    schema_version: str = STORAGE_PREPARE_SCHEMA_VERSION


def storage_device_set_digest(stable_ids: tuple[str, ...]) -> str:
    """Digest the exact sorted protected device identities."""

    if not stable_ids or stable_ids != tuple(sorted(set(stable_ids))):
        raise AnsibleError("storage preparation device identities are invalid")
    data = json.dumps(
        list(stable_ids),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_storage_prepare_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    discovery: StorageDiscoveryEvidence,
    preflight: StoragePreflightResult,
    authorization: StoragePreparationAuthorization,
    *,
    limit: tuple[str, ...],
    check: bool,
) -> dict[str, object]:
    """Revalidate preflight and build one private owner-only runtime payload."""

    if len(limit) != 1 or limit[0] != authorization.logical_id:
        raise StateConflictError(
            "storage preparation requires one exact authorized target"
        )
    expected = reconcile_storage_preflight(
        metadata, observed, inventory, discovery, limit
    )
    if expected != preflight or len(preflight.hosts) != 1:
        raise StateConflictError("storage preparation preflight is stale or mismatched")
    host = preflight.hosts[0]
    if host.ownership_status is StorageOwnershipStatus.BLOCKED or host.blockers:
        raise StateConflictError("blocked storage preparation is never executable")
    stable_ids = tuple(device.stable_id for device in host.devices)
    device_digest = storage_device_set_digest(stable_ids)
    if (
        authorization.preparation_intent_digest != host.preparation_intent_digest
        or authorization.device_set_digest != device_digest
        or not authorization.preparation_approved
    ):
        raise StateConflictError(
            "storage preparation authorization does not match intent"
        )
    if (
        host.ownership_status is StorageOwnershipStatus.WIPE_REVIEW_REQUIRED
        and not authorization.wipe_acknowledged
    ):
        raise StateConflictError(
            "storage wipe requires a separately bound explicit acknowledgement"
        )
    if (
        host.ownership_status is not StorageOwnershipStatus.WIPE_REVIEW_REQUIRED
        and authorization.wipe_acknowledged
    ):
        raise StateConflictError("storage wipe acknowledgement is not applicable")

    discovery_host = discovery.hosts[0]
    by_stable_id = {device.stable_id: device for device in discovery_host.devices}
    selected = [by_stable_id.get(stable_id) for stable_id in stable_ids]
    if any(device is None for device in selected):
        raise StateConflictError("storage preparation device mapping is incomplete")
    manifest_host = next(
        (
            item
            for item in observed.record.manifest.hosts
            if item.logical_id == host.logical_id
        ),
        None,
    )
    if manifest_host is None:
        raise StateConflictError("storage preparation manifest target is unavailable")
    manifest = manifest_host.storage
    if (
        manifest.mount_point != CANONICAL_SCYLLA_MOUNT
        or manifest.filesystem_type != "xfs"
        or manifest.layout not in {"single", "raid0"}
    ):
        raise StateConflictError("storage preparation policy is unsupported")

    devices = []
    for device in selected:
        assert device is not None
        devices.append(
            {
                "by_id": list(device.by_id),
                "filesystem": device.filesystem,
                "holders": list(device.holders),
                "mount_points": list(device.mount_points),
                "path": device.path,
                "root_ancestor": device.root_ancestor,
                "signatures": [
                    {"kind": item.kind, "value": item.value}
                    for item in device.signatures
                ],
                "size_bytes": device.size_bytes,
                "stable_id": device.stable_id,
            }
        )
    return {
        "authorization": {
            "device_set_digest": device_digest,
            "logical_id": authorization.logical_id,
            "operation_id": str(authorization.operation_id),
            "preparation_approved": authorization.preparation_approved,
            "preparation_intent_digest": authorization.preparation_intent_digest,
            "wipe_acknowledged": authorization.wipe_acknowledged,
        },
        "backend": host.backend,
        "check_mode_requested": check,
        "classification": host.ownership_status.value,
        "cluster_uuid": str(metadata.cluster_uuid),
        "devices": devices,
        "discovery_digest": _discovery_digest(discovery_host),
        "filesystem": "xfs",
        "host_manifest_digest": discovery_host.host_manifest_digest,
        "inventory_digest": inventory.digest,
        "inventory_generation": inventory.record.generation,
        "layout": host.layout,
        "logical_id": host.logical_id,
        "mount_options": list(manifest.mount_options),
        "mount_point": CANONICAL_SCYLLA_MOUNT,
        "observation_digest": observed.digest,
        "observation_generation": observed.record.generation,
        "policy_digest": manifest.policy_digest,
        "provider_id": manifest_host.provider_id,
        "schema_version": STORAGE_PREPARE_SCHEMA_VERSION,
        "storage_generation": manifest.storage_generation,
    }


def build_deploy_storage_prepare_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    preflight: StoragePreflightResult,
    authorization: StoragePreparationAuthorization,
    *,
    discovery_digest: str,
    preflight_evidence_digest: str,
    limit: tuple[str, ...],
    check: bool,
) -> dict[str, object]:
    """Build a deploy payload that never persists or accepts guest device paths.

    The packaged module resolves each public device-identity digest to exactly
    one current guest device and repeats the destructive safety checks
    immediately before the first write.
    """

    if len(limit) != 1 or limit[0] != authorization.logical_id:
        raise StateConflictError(
            "deploy storage preparation requires one exact authorized target"
        )
    if len(preflight.hosts) != 1 or preflight.hosts[0].logical_id != limit[0]:
        raise StateConflictError(
            "deploy storage preparation preflight scope is stale or mismatched"
        )
    host = preflight.hosts[0]
    if (
        host.ownership_status
        not in {
            StorageOwnershipStatus.CLEAN_NEW,
            StorageOwnershipStatus.WIPE_REVIEW_REQUIRED,
        }
        or host.blockers
        or not host.devices
    ):
        raise StateConflictError(
            "only exact prepare-required storage may enter deploy execution"
        )
    identities = tuple(device.identity for device in host.devices)
    device_digest = _deploy_storage_device_set_digest(identities)
    wipe_required = host.ownership_status is StorageOwnershipStatus.WIPE_REVIEW_REQUIRED
    if (
        authorization.preparation_intent_digest != host.preparation_intent_digest
        or authorization.device_set_digest != device_digest
        or not authorization.preparation_approved
        or authorization.wipe_acknowledged is not wipe_required
    ):
        raise StateConflictError(
            "deploy storage preparation authorization does not match intent"
        )
    if not _DIGEST.fullmatch(discovery_digest) or not _DIGEST.fullmatch(
        preflight_evidence_digest
    ):
        raise StateConflictError(
            "deploy storage preparation provenance digest is invalid"
        )
    manifest_host = next(
        (
            item
            for item in observed.record.manifest.hosts
            if item.logical_id == host.logical_id
        ),
        None,
    )
    inventory_host = next(
        (
            item
            for item in inventory.record.inventory.hosts
            if item.logical_id == host.logical_id
        ),
        None,
    )
    if (
        manifest_host is None
        or inventory_host is None
        or inventory_host.provider_id != manifest_host.provider_id
        or inventory_host.storage_generation != manifest_host.storage.storage_generation
        or inventory_host.storage_policy_digest != manifest_host.storage.policy_digest
    ):
        raise StateConflictError(
            "deploy storage preparation manifest target is unavailable"
        )
    manifest = manifest_host.storage
    if (
        manifest.mount_point != CANONICAL_SCYLLA_MOUNT
        or manifest.filesystem_type != "xfs"
        or manifest.layout not in {"single", "raid0"}
        or manifest.layout != host.layout
        or manifest.selected_backend.value != host.backend
        or manifest.expected_device_count != len(host.devices)
    ):
        raise StateConflictError("deploy storage preparation policy is unsupported")
    provenance = _deploy_provenance_digest(
        cluster_uuid=str(metadata.cluster_uuid),
        operation_id=str(authorization.operation_id),
        logical_id=host.logical_id,
        observation_digest=observed.digest,
        observation_generation=observed.record.generation,
        inventory_digest=inventory.digest,
        inventory_generation=inventory.record.generation,
        discovery_digest=discovery_digest,
        preflight_evidence_digest=preflight_evidence_digest,
        policy_digest=manifest.policy_digest,
        storage_generation=manifest.storage_generation,
        preparation_intent_digest=host.preparation_intent_digest,
        device_set_digest=device_digest,
    )
    return {
        "action": _DEPLOY_ACTION,
        "authorization": {
            "device_set_digest": device_digest,
            "logical_id": authorization.logical_id,
            "operation_id": str(authorization.operation_id),
            "preparation_approved": authorization.preparation_approved,
            "preparation_intent_digest": authorization.preparation_intent_digest,
            "wipe_acknowledged": authorization.wipe_acknowledged,
        },
        "backend": host.backend,
        "check_mode_requested": check,
        "classification": host.ownership_status.value,
        "cluster_uuid": str(metadata.cluster_uuid),
        "devices": [
            {
                "capacity_bytes": device.capacity_bytes,
                "identity": device.identity,
            }
            for device in host.devices
        ],
        "discovery_digest": discovery_digest,
        "filesystem": "xfs",
        "host_manifest_digest": observed.record.manifest_digest,
        "inventory_digest": inventory.digest,
        "inventory_generation": inventory.record.generation,
        "layout": host.layout,
        "logical_id": host.logical_id,
        "mount_options": list(manifest.mount_options),
        "mount_point": CANONICAL_SCYLLA_MOUNT,
        "observation_digest": observed.digest,
        "observation_generation": observed.record.generation,
        "policy_digest": manifest.policy_digest,
        "preflight_evidence_digest": preflight_evidence_digest,
        "provenance_digest": provenance,
        "provider_id": manifest_host.provider_id,
        "schema_version": STORAGE_PREPARE_SCHEMA_VERSION,
        "selection_mode": "public-device-identity-digest",
        "storage_generation": manifest.storage_generation,
    }


def parse_storage_prepare_execution(
    stdout: str,
    *,
    expected_logical_id: str,
    expected_backend: str,
    expected_layout: str,
    expected_device_set_digest: str,
    exit_code: int,
    require_deploy_proof: bool = False,
    expected_action: str | None = None,
    expected_disposition: str | None = None,
    expected_preparation_intent_digest: str | None = None,
    expected_provenance_digest: str | None = None,
) -> StoragePrepareEvidence:
    """Parse one bounded allowlisted preparation result and recap."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError(
            "Ansible storage preparation output exceeds the evidence limit"
        )
    markers: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_STORAGE_PREPARE_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible storage preparation marker is malformed")
        try:
            raw = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible storage preparation marker is malformed"
            ) from error
        expected_keys = _DEPLOY_RESULT_KEYS if require_deploy_proof else _RESULT_KEYS
        if not isinstance(value, dict) or set(value) != expected_keys:
            raise AnsibleError("Ansible storage preparation result is malformed")
        markers.append(value)
    if len(markers) != 1:
        raise AnsibleError("Ansible storage preparation evidence is incomplete")
    value = markers[0]
    try:
        status = StoragePrepareStatus(_text(value["status"]))
        irreversible = IrreversibleStepStatus(_text(value["irreversible_step_status"]))
    except ValueError as error:
        raise AnsibleError("Ansible storage preparation status is invalid") from error
    completed = _string_tuple(value["completed_steps"])
    verification_object = value["post_action_verification"]
    if not isinstance(verification_object, dict) or any(
        not isinstance(key, str) or not isinstance(item, bool)
        for key, item in verification_object.items()
    ):
        raise AnsibleError("Ansible storage preparation verification is invalid")
    verification = tuple(sorted(verification_object.items()))
    deploy_values: dict[str, object] = {}
    if require_deploy_proof:
        deploy_values = {
            "action": _text(value["action"]),
            "disposition": _text(value["disposition"]),
            "immediate_device_revalidation": _boolean(
                value["immediate_device_revalidation"]
            ),
            "preparation_intent_digest": _digest(value["preparation_intent_digest"]),
            "provenance_digest": _digest(value["provenance_digest"]),
            "wipe_applied": _boolean(value["wipe_applied"]),
            "mutation_boundary": _text(value["mutation_boundary"]),
            "first_irreversible_step": _optional_irreversible_step(
                value["first_irreversible_step"]
            ),
            "completed": _boolean(value["completed"]),
        }
    evidence = StoragePrepareEvidence(
        logical_id=_text(value["logical_id"]),
        status=status,
        backend=_text(value["backend"]),
        layout=_text(value["layout"]),
        device_set_digest=_digest(value["device_set_digest"]),
        filesystem_uuid_digest=_optional_digest(value["filesystem_uuid_digest"]),
        marker_digest=_optional_digest(value["marker_digest"]),
        irreversible_step_status=irreversible,
        completed_steps=completed,
        post_action_verification=verification,
        **deploy_values,  # type: ignore[arg-type]
    )
    if (
        evidence.logical_id != expected_logical_id
        or evidence.backend != expected_backend
        or evidence.layout != expected_layout
        or evidence.device_set_digest != expected_device_set_digest
    ):
        raise AnsibleError("Ansible storage preparation evidence conflicts")
    failed = status is StoragePrepareStatus.FAILED
    if (exit_code == 0) == failed:
        raise AnsibleError("Ansible storage preparation exit status conflicts")
    if not failed and not verification:
        raise AnsibleError("Ansible storage preparation verification is incomplete")
    if require_deploy_proof:
        _validate_deploy_result(
            evidence,
            expected_action=expected_action,
            expected_disposition=expected_disposition,
            expected_preparation_intent_digest=(expected_preparation_intent_digest),
            expected_provenance_digest=expected_provenance_digest,
        )
    return evidence


def _validate_deploy_result(
    evidence: StoragePrepareEvidence,
    *,
    expected_action: str | None,
    expected_disposition: str | None,
    expected_preparation_intent_digest: str | None,
    expected_provenance_digest: str | None,
) -> None:
    if (
        expected_action != _DEPLOY_ACTION
        or expected_disposition not in _DEPLOY_DISPOSITIONS
        or expected_preparation_intent_digest is None
        or expected_provenance_digest is None
        or evidence.action != expected_action
        or evidence.disposition != expected_disposition
        or evidence.preparation_intent_digest != expected_preparation_intent_digest
        or evidence.provenance_digest != expected_provenance_digest
        or evidence.mutation_boundary not in _MUTATION_BOUNDARIES
    ):
        raise AnsibleError("Ansible deploy storage preparation provenance conflicts")
    expected_boundary = {
        IrreversibleStepStatus.NOT_STARTED: "not-crossed",
        IrreversibleStepStatus.STARTED: "crossed",
        IrreversibleStepStatus.COMPLETED: "completed",
    }[evidence.irreversible_step_status]
    if (
        evidence.mutation_boundary != expected_boundary
        or (
            evidence.status is StoragePrepareStatus.CHANGED
            and evidence.first_irreversible_step is not None
            and evidence.first_irreversible_step not in evidence.completed_steps
        )
        or (
            evidence.irreversible_step_status is IrreversibleStepStatus.NOT_STARTED
            and evidence.first_irreversible_step is not None
        )
        or (
            evidence.irreversible_step_status is not IrreversibleStepStatus.NOT_STARTED
            and evidence.first_irreversible_step is None
        )
    ):
        raise AnsibleError("Ansible deploy storage mutation boundary conflicts")
    succeeded = evidence.status is StoragePrepareStatus.CHANGED
    if (
        evidence.completed is not succeeded
        or (
            succeeded
            and (
                evidence.immediate_device_revalidation is not True
                or evidence.irreversible_step_status
                is not IrreversibleStepStatus.COMPLETED
                or evidence.filesystem_uuid_digest is None
                or evidence.marker_digest is None
                or not all(value for _, value in evidence.post_action_verification)
            )
        )
        or (
            expected_disposition == StorageOwnershipStatus.WIPE_REVIEW_REQUIRED.value
            and succeeded
            and not evidence.wipe_applied
        )
        or (
            expected_disposition == StorageOwnershipStatus.CLEAN_NEW.value
            and evidence.wipe_applied
        )
    ):
        raise AnsibleError("Ansible deploy storage completion evidence conflicts")


def _deploy_provenance_digest(
    *,
    cluster_uuid: str,
    operation_id: str,
    logical_id: str,
    observation_digest: str,
    observation_generation: int,
    inventory_digest: str,
    inventory_generation: int,
    discovery_digest: str,
    preflight_evidence_digest: str,
    policy_digest: str,
    storage_generation: int,
    preparation_intent_digest: str,
    device_set_digest: str,
) -> str:
    value = {
        "cluster_uuid": cluster_uuid,
        "device_set_digest": device_set_digest,
        "discovery_digest": discovery_digest,
        "inventory_digest": inventory_digest,
        "inventory_generation": inventory_generation,
        "logical_id": logical_id,
        "observation_digest": observation_digest,
        "observation_generation": observation_generation,
        "operation_id": operation_id,
        "policy_digest": policy_digest,
        "preflight_evidence_digest": preflight_evidence_digest,
        "preparation_intent_digest": preparation_intent_digest,
        "schema_version": "deploy-scylla-vms.storage-prepare-provenance/v1",
        "storage_generation": storage_generation,
    }
    data = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _deploy_storage_device_set_digest(identities: tuple[str, ...]) -> str:
    if not identities or identities != tuple(sorted(set(identities))):
        raise AnsibleError("deploy storage device identities are invalid")
    return digest_bytes(serialize_json({"value": list(identities)}))


def _discovery_digest(host: object) -> str:
    data = json.dumps(
        {
            "devices": [
                {
                    "by_id": list(device.by_id),
                    "filesystem": device.filesystem,
                    "holders": list(device.holders),
                    "mount_points": list(device.mount_points),
                    "path": device.path,
                    "root_ancestor": device.root_ancestor,
                    "signatures": [
                        {"kind": item.kind, "value": item.value}
                        for item in device.signatures
                    ],
                    "size_bytes": device.size_bytes,
                    "stable_id": device.stable_id,
                }
                for device in host.devices  # type: ignore[attr-defined]
            ],
            "logical_id": host.logical_id,  # type: ignore[attr-defined]
            "provider_id": host.provider_id,  # type: ignore[attr-defined]
        },
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AnsibleError("Ansible storage preparation contains duplicate fields")
        result[key] = value
    return result


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024 or "\0" in value:
        raise AnsibleError("Ansible storage preparation value is invalid")
    return value


def _digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible storage preparation digest is invalid")
    return text


def _optional_digest(value: object) -> str | None:
    return None if value is None else _digest(value)


def _optional_irreversible_step(value: object) -> str | None:
    if value is None:
        return None
    step = _text(value)
    if step not in _IRREVERSIBLE_STEPS:
        raise AnsibleError("Ansible storage preparation irreversible step is invalid")
    return step


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError("Ansible storage preparation boolean is invalid")
    return value


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible storage preparation steps are invalid")
    result = tuple(_text(item) for item in value)
    if len(result) > 32 or len(set(result)) != len(result):
        raise AnsibleError("Ansible storage preparation steps are invalid")
    return result
