"""Fail-closed retirement of previously prepared Scylla guest storage."""

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
from scylla_vms.ansible.storage import StorageDiscoveryEvidence, StorageHostEvidence
from scylla_vms.ansible.storage_postcheck import StoragePostcheckEvidence
from scylla_vms.ansible.storage_preflight import (
    StorageOwnershipStatus,
    StoragePreflightResult,
    reconcile_storage_preflight,
)
from scylla_vms.ansible.storage_prepare import (
    CANONICAL_SCYLLA_MOUNT,
    StoragePrepareEvidence,
    StoragePrepareStatus,
    storage_device_set_digest,
)
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata

STORAGE_RETIRE_SCHEMA_VERSION = "deploy-scylla-vms.ansible-storage-retire/v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DEVICE_IDENTITY = re.compile(r"device-sha256:[0-9a-f]{64}\Z")
_MARKER = re.compile(
    r'DSV_STORAGE_RETIRE_B64=(?P<data>[A-Za-z0-9+/]+={0,2})"(?:\})?\s*$'
)
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_RESULT_KEYS = {
    "backend",
    "blockers",
    "completed_steps",
    "device_set_digest",
    "devices",
    "disposition",
    "first_irreversible_step",
    "irreversible_step_status",
    "layout",
    "logical_id",
    "manual_recovery_required",
    "not_performed",
    "post_action_verification",
    "provenance",
    "schema_version",
    "status",
    "wipe_performed",
}
_STATUSES = frozenset({"changed", "noop", "not-predicted", "failed"})
_DISPOSITIONS = frozenset({"delete", "ephemeral", "retain"})
_IRREVERSIBLE = frozenset({"not-started", "started", "completed"})
_FIRST_STEPS = frozenset({"none", "unmount", "raid-stop", "wipe"})
_NOT_PERFORMED = (
    "raid-teardown",
    "scylla-start",
    "scylla-stop",
    "terraform-apply",
    "terraform-destroy",
    "vm-destroy",
    "volume-delete",
    "volume-detach",
    "wipe",
)
_BLOCKERS = frozenset(
    {
        "active-data-claimed",
        "blocked-storage",
        "check-mode-refused",
        "classification-not-owned",
        "device-identity-conflict",
        "execution-failed",
        "membership-not-absent",
        "service-active",
        "still-member",
        "wipe-consent-missing",
        "wipe-consent-not-applicable",
    }
)
_VERIFICATION_KEYS = frozenset(
    {
        "devices_unmounted",
        "fstab_removed",
        "infrastructure_destroyed",
        "membership_absent",
        "raid_deactivated",
        "scylla_started",
        "scylla_stopped",
        "service_inactive",
        "terraform_performed",
        "wipe_verified",
        "writes_performed",
    }
)


class StorageVolumeDisposition(StrEnum):
    DELETE = "delete"
    EPHEMERAL = "ephemeral"
    RETAIN = "retain"


class StorageRetireStatus(StrEnum):
    CHANGED = "changed"
    NOOP = "noop"
    NOT_PREDICTED = "not-predicted"
    FAILED = "failed"


class IrreversibleStepStatus(StrEnum):
    NOT_STARTED = "not-started"
    STARTED = "started"
    COMPLETED = "completed"


class FirstIrreversibleStep(StrEnum):
    NONE = "none"
    UNMOUNT = "unmount"
    RAID_STOP = "raid-stop"
    WIPE = "wipe"


@dataclass(frozen=True, slots=True)
class StorageRetirementAuthorization:
    """Narrow approval bound to one operation, node, disposition, and device set."""

    operation_id: uuid.UUID
    logical_id: str
    device_set_digest: str
    disposition: StorageVolumeDisposition
    retirement_approved: bool
    membership_absent: bool
    wipe_acknowledged: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.operation_id, uuid.UUID):
            raise AnsibleError("storage retirement operation ID is invalid")
        if (
            not self.logical_id
            or _DIGEST.fullmatch(self.device_set_digest) is None
            or not isinstance(self.retirement_approved, bool)
            or not isinstance(self.membership_absent, bool)
            or not isinstance(self.wipe_acknowledged, bool)
        ):
            raise AnsibleError("storage retirement authorization is invalid")


@dataclass(frozen=True, slots=True)
class StorageRetireEvidence:
    logical_id: str
    status: StorageRetireStatus
    disposition: StorageVolumeDisposition
    backend: str
    layout: str
    device_set_digest: str
    devices: tuple[tuple[str, int], ...]
    irreversible_step_status: IrreversibleStepStatus
    first_irreversible_step: FirstIrreversibleStep
    completed_steps: tuple[str, ...]
    manual_recovery_required: bool
    wipe_performed: bool
    not_performed: tuple[str, ...]
    provenance: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]
    post_action_verification: tuple[tuple[str, bool], ...]
    schema_version: str = STORAGE_RETIRE_SCHEMA_VERSION


def wipe_required_for_disposition(disposition: StorageVolumeDisposition) -> bool:
    """Guest wipe is reviewed only for Block Volume delete, never retain/ephemeral."""

    return disposition is StorageVolumeDisposition.DELETE


def build_storage_retire_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    discovery: StorageDiscoveryEvidence,
    preflight: StoragePreflightResult,
    preparation: StoragePrepareEvidence,
    postcheck: StoragePostcheckEvidence,
    authorization: StorageRetirementAuthorization,
    readiness: ReadinessReport,
    *,
    limit: tuple[str, ...],
    check: bool,
) -> dict[str, object]:
    """Revalidate owned prepared storage and build one owner-only retire payload."""

    if len(limit) != 1 or limit[0] != authorization.logical_id:
        raise StateConflictError(
            "storage retirement requires one exact authorized target"
        )
    inventory_host = next(
        (
            item
            for item in inventory.record.inventory.hosts
            if item.logical_id == authorization.logical_id
        ),
        None,
    )
    if inventory_host is None or inventory_host.role.value != "scylla":
        raise StateConflictError("storage retirement target is not a Scylla stable ID")
    expected = reconcile_storage_preflight(
        metadata, observed, inventory, discovery, limit
    )
    if expected != preflight or len(preflight.hosts) != 1:
        raise StateConflictError("storage retirement preflight is stale or mismatched")
    host = preflight.hosts[0]
    if host.logical_id != authorization.logical_id:
        raise StateConflictError("storage retirement target is mismatched")
    if host.ownership_status is StorageOwnershipStatus.BLOCKED or host.blockers:
        raise StateConflictError("blocked storage retirement is never executable")
    if host.ownership_status is not StorageOwnershipStatus.OWNED_NOOP:
        raise StateConflictError(
            "storage retirement requires previously prepared owned storage"
        )
    if not authorization.retirement_approved:
        raise StateConflictError("storage retirement is not approved")
    if not authorization.membership_absent:
        raise StateConflictError(
            "storage retirement requires proven cluster membership absence"
        )
    if (
        readiness.observation_generation != observed.record.generation
        or readiness.observation_digest != observed.digest
        or readiness.inventory_generation != inventory.record.generation
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_generation is None
        or readiness.trust_digest is None
    ):
        raise StateConflictError("storage retirement readiness provenance conflicts")
    stable_ids = tuple(device.stable_id for device in host.devices)
    device_digest = storage_device_set_digest(stable_ids)
    if authorization.device_set_digest != device_digest:
        raise StateConflictError(
            "storage retirement authorization does not match the device set"
        )
    wipe_required = wipe_required_for_disposition(authorization.disposition)
    if wipe_required and not authorization.wipe_acknowledged:
        raise StateConflictError(
            "storage wipe requires a separately bound explicit acknowledgement"
        )
    if not wipe_required and authorization.wipe_acknowledged:
        raise StateConflictError("storage wipe acknowledgement is not applicable")
    if (
        preparation.logical_id != host.logical_id
        or preparation.backend != host.backend
        or preparation.layout != host.layout
        or preparation.device_set_digest != device_digest
        or preparation.status
        not in {StoragePrepareStatus.CHANGED, StoragePrepareStatus.NOOP}
    ):
        raise StateConflictError("storage retirement preparation result conflicts")
    if (
        postcheck.logical_id != host.logical_id
        or postcheck.backend != host.backend
        or postcheck.layout != host.layout
        or not postcheck.readiness_for_scylla
    ):
        raise StateConflictError("storage retirement postcheck is not current")
    expected_devices = tuple(
        sorted((item.identity, item.capacity_bytes) for item in host.devices)
    )
    if postcheck.devices != expected_devices:
        raise StateConflictError("storage retirement device set conflicts")
    discovery_host = next(
        (item for item in discovery.hosts if item.logical_id == host.logical_id),
        None,
    )
    manifest_host = next(
        (
            item
            for item in observed.record.manifest.hosts
            if item.logical_id == host.logical_id
        ),
        None,
    )
    if discovery_host is None or manifest_host is None:
        raise StateConflictError("storage retirement target provenance is unavailable")
    manifest = manifest_host.storage
    if (
        manifest.mount_point != CANONICAL_SCYLLA_MOUNT
        or manifest.filesystem_type != "xfs"
        or manifest.layout not in {"single", "raid0"}
    ):
        raise StateConflictError("storage retirement policy is unsupported")
    by_stable_id = {device.stable_id: device for device in discovery_host.devices}
    devices = []
    for selected in host.devices:
        device = by_stable_id.get(selected.stable_id)
        if device is None:
            raise StateConflictError("storage retirement device mapping is incomplete")
        devices.append(
            {
                "by_id": list(device.by_id),
                "filesystem": device.filesystem,
                "holders": list(device.holders),
                "identity": selected.identity,
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
    not_performed = list(_NOT_PERFORMED)
    if wipe_required:
        not_performed.remove("wipe")
        if host.layout == "raid0":
            not_performed.remove("raid-teardown")
    elif host.layout != "raid0":
        not_performed.remove("raid-teardown")
    return {
        "authorization": {
            "device_set_digest": device_digest,
            "disposition": authorization.disposition.value,
            "logical_id": authorization.logical_id,
            "membership_absent": authorization.membership_absent,
            "operation_id": str(authorization.operation_id),
            "retirement_approved": authorization.retirement_approved,
            "wipe_acknowledged": authorization.wipe_acknowledged,
        },
        "backend": host.backend,
        "check_mode_requested": check,
        "classification": host.ownership_status.value,
        "cluster_uuid": str(metadata.cluster_uuid),
        "devices": devices,
        "discovery_digest": _discovery_digest(discovery_host),
        "expected_filesystem_uuid_digest": preparation.filesystem_uuid_digest,
        "expected_marker_digest": preparation.marker_digest,
        "filesystem": "xfs",
        "inventory_digest": inventory.digest,
        "inventory_generation": inventory.record.generation,
        "layout": host.layout,
        "logical_id": host.logical_id,
        "mount_point": CANONICAL_SCYLLA_MOUNT,
        "not_performed": not_performed,
        "observation_digest": observed.digest,
        "observation_generation": observed.record.generation,
        "policy_digest": manifest.policy_digest,
        "postcheck_device_set_digest": device_digest,
        "preparation_intent_digest": host.preparation_intent_digest,
        "provider_id": manifest_host.provider_id,
        "schema_version": STORAGE_RETIRE_SCHEMA_VERSION,
        "storage_generation": manifest.storage_generation,
        "trust_digest": readiness.trust_digest,
        "wipe_required": wipe_required,
    }


def parse_storage_retire_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> StorageRetireEvidence:
    """Parse one bounded allowlisted retirement result and recap."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError(
            "Ansible storage retirement output exceeds the evidence limit"
        )
    markers: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_STORAGE_RETIRE_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible storage retirement marker is malformed")
        try:
            raw = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible storage retirement marker is malformed"
            ) from error
        if not isinstance(value, dict) or set(value) != _RESULT_KEYS:
            raise AnsibleError("Ansible storage retirement result is malformed")
        markers.append(value)
    if len(markers) != 1:
        raise AnsibleError("Ansible storage retirement evidence is incomplete")
    value = markers[0]
    if value["schema_version"] != STORAGE_RETIRE_SCHEMA_VERSION:
        raise AnsibleError("Ansible storage retirement schema is invalid")
    try:
        status = StorageRetireStatus(_text(value["status"]))
        disposition = StorageVolumeDisposition(_text(value["disposition"]))
        irreversible = IrreversibleStepStatus(_text(value["irreversible_step_status"]))
        first_step = FirstIrreversibleStep(_text(value["first_irreversible_step"]))
    except ValueError as error:
        raise AnsibleError("Ansible storage retirement status is invalid") from error
    if (
        status.value not in _STATUSES
        or disposition.value not in _DISPOSITIONS
        or irreversible.value not in _IRREVERSIBLE
        or first_step.value not in _FIRST_STEPS
    ):
        raise AnsibleError("Ansible storage retirement status is invalid")
    logical_id = _text(value["logical_id"])
    backend = _text(value["backend"])
    layout = _text(value["layout"])
    device_set_digest = _digest(value["device_set_digest"])
    authorization = expected_payload["authorization"]
    if not isinstance(authorization, dict):
        raise AnsibleError("Ansible storage retirement authorization is invalid")
    if (
        logical_id != expected_payload["logical_id"]
        or backend != expected_payload["backend"]
        or layout != expected_payload["layout"]
        or device_set_digest != expected_payload["postcheck_device_set_digest"]
        or disposition.value != authorization["disposition"]
    ):
        raise AnsibleError("Ansible storage retirement evidence conflicts")
    devices = _devices(value["devices"], expected_payload)
    completed = _string_tuple(value["completed_steps"])
    not_performed = _sorted_known(value["not_performed"], frozenset(_NOT_PERFORMED))
    expected_not_performed = tuple(cast(list[str], expected_payload["not_performed"]))
    if not_performed != expected_not_performed:
        raise AnsibleError("Ansible storage retirement not-performed set conflicts")
    blockers = _sorted_known(value["blockers"], _BLOCKERS)
    provenance = _provenance(value["provenance"], expected_payload)
    verification = _verification(value["post_action_verification"])
    wipe_performed = value["wipe_performed"]
    manual_recovery = value["manual_recovery_required"]
    if not isinstance(wipe_performed, bool) or not isinstance(manual_recovery, bool):
        raise AnsibleError("Ansible storage retirement flags are invalid")
    if wipe_performed and not expected_payload["wipe_required"]:
        raise AnsibleError("Ansible storage retirement wipe evidence conflicts")
    expected_recovery = (
        irreversible is not IrreversibleStepStatus.NOT_STARTED
        and status is StorageRetireStatus.FAILED
    )
    if manual_recovery != expected_recovery:
        raise AnsibleError("Ansible storage retirement recovery evidence conflicts")
    recap = _parse_recap(stdout, logical_id)
    failed = status is StorageRetireStatus.FAILED
    if (exit_code == 0) == failed or recap[1] != failed:
        raise AnsibleError("Ansible storage retirement exit status conflicts")
    if not failed and status is StorageRetireStatus.CHANGED and recap[0] == 0:
        raise AnsibleError("Ansible storage retirement recap conflicts")
    if not failed and not verification:
        raise AnsibleError("Ansible storage retirement verification is incomplete")
    return StorageRetireEvidence(
        logical_id,
        status,
        disposition,
        backend,
        layout,
        device_set_digest,
        devices,
        irreversible,
        first_step,
        completed,
        manual_recovery,
        wipe_performed,
        not_performed,
        provenance,
        blockers,
        verification,
    )


def _discovery_digest(host: StorageHostEvidence) -> str:
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
                for device in host.devices
            ],
            "logical_id": host.logical_id,
            "provider_id": host.provider_id,
        },
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _devices(
    value: object, expected_payload: dict[str, object]
) -> tuple[tuple[str, int], ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible storage retirement devices are invalid")
    devices: list[tuple[str, int]] = []
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"capacity_bytes", "identity"}
            or not isinstance(item["capacity_bytes"], int)
            or isinstance(item["capacity_bytes"], bool)
            or item["capacity_bytes"] <= 0
        ):
            raise AnsibleError("Ansible storage retirement devices are invalid")
        identity = _text(item["identity"])
        if _DEVICE_IDENTITY.fullmatch(identity) is None:
            raise AnsibleError("Ansible storage retirement device identity is invalid")
        devices.append((identity, item["capacity_bytes"]))
    if devices != sorted(set(devices)):
        raise AnsibleError("Ansible storage retirement devices are not uniquely sorted")
    payload_devices = cast(list[dict[str, object]], expected_payload["devices"])
    expected = sorted(
        (_text(item["identity"]), cast(int, item["size_bytes"]))
        for item in payload_devices
    )
    if devices != expected:
        raise AnsibleError("Ansible storage retirement device evidence conflicts")
    return tuple(devices)


def _provenance(
    value: object, expected_payload: dict[str, object]
) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict) or not value:
        raise AnsibleError("Ansible storage retirement provenance is invalid")
    required = {
        "device_set_digest": expected_payload["postcheck_device_set_digest"],
        "discovery_digest": expected_payload["discovery_digest"],
        "inventory_digest": expected_payload["inventory_digest"],
        "observation_digest": expected_payload["observation_digest"],
        "policy_digest": expected_payload["policy_digest"],
        "preparation_intent_digest": expected_payload["preparation_intent_digest"],
        "trust_digest": expected_payload["trust_digest"],
    }
    if not set(required) <= set(value):
        raise AnsibleError("Ansible storage retirement provenance is incomplete")
    provenance = tuple(
        sorted((_text(key), _digest(item)) for key, item in value.items())
    )
    if any(value[key] != item for key, item in required.items()):
        raise AnsibleError("Ansible storage retirement provenance conflicts")
    extra = set(value) - {
        *required,
        "filesystem_uuid_digest",
        "marker_digest",
    }
    if extra:
        raise AnsibleError("Ansible storage retirement provenance is invalid")
    return provenance


def _verification(value: object) -> tuple[tuple[str, bool], ...]:
    if not isinstance(value, dict) or any(
        key not in _VERIFICATION_KEYS or not isinstance(item, bool)
        for key, item in value.items()
    ):
        raise AnsibleError("Ansible storage retirement verification is invalid")
    return tuple(sorted(value.items()))


def _parse_recap(stdout: str, logical_id: str) -> tuple[int, bool]:
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible storage retirement output omitted PLAY RECAP")
    rows: dict[str, tuple[int, bool]] = {}
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible storage retirement recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            bool(int(match.group("unreachable")) or int(match.group("failed"))),
        )
    if set(rows) != {logical_id}:
        raise AnsibleError("Ansible storage retirement recap conflicts")
    return rows[logical_id]


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AnsibleError("Ansible storage retirement contains duplicate fields")
        result[key] = value
    return result


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024 or "\0" in value:
        raise AnsibleError("Ansible storage retirement value is invalid")
    return value


def _digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible storage retirement digest is invalid")
    return text


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible storage retirement steps are invalid")
    result = tuple(_text(item) for item in value)
    if len(result) > 32 or len(set(result)) != len(result):
        raise AnsibleError("Ansible storage retirement steps are invalid")
    return result


def _sorted_known(value: object, allowed: frozenset[str]) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible storage retirement values are invalid")
    values = tuple(_text(item) for item in value)
    if values != tuple(sorted(set(values))) or not set(values) <= allowed:
        raise AnsibleError("Ansible storage retirement values are invalid")
    return values
