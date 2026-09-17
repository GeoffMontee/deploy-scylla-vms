#!/usr/bin/python
"""Retire one exact pre-authorized prepared Scylla device set."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-untyped]

SCHEMA = "deploy-scylla-vms.ansible-storage-retire/v1"
MOUNT_POINT = "/var/lib/scylla"
MD_DEVICE = "/dev/md/scylla-data"
MARKER_NAME = ".deploy-scylla-vms-storage.json"
COMMAND_TIMEOUT = 30
COMMANDS = {
    "blkid": "/usr/sbin/blkid",
    "findmnt": "/usr/bin/findmnt",
    "lsblk": "/usr/bin/lsblk",
    "mdadm": "/usr/sbin/mdadm",
    "systemctl": "/usr/bin/systemctl",
    "umount": "/usr/bin/umount",
    "wipefs": "/usr/sbin/wipefs",
}


class RetirementError(Exception):
    pass


def _run(argv: list[str], *, allowed: tuple[int, ...] = (0,)) -> str:
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=COMMAND_TIMEOUT,
            shell=False,
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise RetirementError("fixed storage command execution failed") from error
    if result.returncode not in allowed or len(result.stdout.encode("utf-8")) > 262144:
        raise RetirementError("fixed storage command returned invalid evidence")
    return result.stdout


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _result(
    intent: dict[str, Any],
    *,
    status: str,
    completed: list[str],
    irreversible: str,
    first_step: str,
    wipe_performed: bool,
    manual_recovery: bool,
    blockers: list[str],
    verification: dict[str, bool] | None = None,
) -> dict[str, object]:
    devices = sorted(
        (
            {
                "capacity_bytes": item["size_bytes"],
                "identity": item["identity"],
            }
            for item in intent["devices"]
        ),
        key=lambda item: item["identity"],
    )
    provenance = {
        "device_set_digest": intent["authorization"]["device_set_digest"],
        "discovery_digest": intent["discovery_digest"],
        "inventory_digest": intent["inventory_digest"],
        "observation_digest": intent["observation_digest"],
        "policy_digest": intent["policy_digest"],
        "preparation_intent_digest": intent["preparation_intent_digest"],
        "trust_digest": intent["trust_digest"],
    }
    if intent.get("expected_filesystem_uuid_digest"):
        provenance["filesystem_uuid_digest"] = intent["expected_filesystem_uuid_digest"]
    if intent.get("expected_marker_digest"):
        provenance["marker_digest"] = intent["expected_marker_digest"]
    return {
        "backend": intent["backend"],
        "blockers": sorted(set(blockers)),
        "completed_steps": completed,
        "device_set_digest": intent["authorization"]["device_set_digest"],
        "devices": devices,
        "disposition": intent["authorization"]["disposition"],
        "first_irreversible_step": first_step,
        "irreversible_step_status": irreversible,
        "layout": intent["layout"],
        "logical_id": intent["logical_id"],
        "manual_recovery_required": manual_recovery,
        "not_performed": list(intent["not_performed"]),
        "post_action_verification": verification or {},
        "provenance": provenance,
        "schema_version": SCHEMA,
        "status": status,
        "wipe_performed": wipe_performed,
    }


def _validate_intent(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RetirementError("storage retirement intent is not an object")
    required = {
        "authorization",
        "backend",
        "check_mode_requested",
        "classification",
        "cluster_uuid",
        "devices",
        "discovery_digest",
        "expected_filesystem_uuid_digest",
        "expected_marker_digest",
        "filesystem",
        "inventory_digest",
        "inventory_generation",
        "layout",
        "logical_id",
        "mount_point",
        "not_performed",
        "observation_digest",
        "observation_generation",
        "policy_digest",
        "postcheck_device_set_digest",
        "preparation_intent_digest",
        "provider_id",
        "schema_version",
        "storage_generation",
        "trust_digest",
        "wipe_required",
    }
    if set(value) != required:
        raise RetirementError("storage retirement intent fields are invalid")
    authorization = value["authorization"]
    if not isinstance(authorization, dict) or set(authorization) != {
        "device_set_digest",
        "disposition",
        "logical_id",
        "membership_absent",
        "operation_id",
        "retirement_approved",
        "wipe_acknowledged",
    }:
        raise RetirementError("storage retirement authorization fields are invalid")
    if (
        value["schema_version"] != SCHEMA
        or value["logical_id"] != authorization["logical_id"]
        or value["backend"] not in {"block-volume", "local-nvme"}
        or value["layout"] not in {"single", "raid0"}
        or value["filesystem"] != "xfs"
        or value["mount_point"] != MOUNT_POINT
        or value["classification"] != "owned-noop"
        or authorization["retirement_approved"] is not True
        or authorization["disposition"] not in {"delete", "ephemeral", "retain"}
        or not isinstance(value["devices"], list)
        or not value["devices"]
        or not isinstance(value["not_performed"], list)
        or not isinstance(value["wipe_required"], bool)
    ):
        raise RetirementError("storage retirement policy or authorization is invalid")
    if authorization["membership_absent"] is not True:
        raise RetirementError("storage retirement membership is not proven absent")
    wipe = value["wipe_required"] is True
    if authorization["disposition"] == "delete" and not wipe:
        raise RetirementError("storage retirement delete disposition requires wipe")
    if authorization["disposition"] != "delete" and wipe:
        raise RetirementError("storage retirement wipe is not applicable")
    if authorization["wipe_acknowledged"] is not wipe:
        raise RetirementError("storage wipe acknowledgement does not match disposition")
    devices = value["devices"]
    stable_ids: list[str] = []
    for item in devices:
        if not isinstance(item, dict) or not isinstance(item.get("stable_id"), str):
            raise RetirementError("storage retirement device identity is invalid")
        stable_ids.append(item["stable_id"])
    if (
        stable_ids != sorted(set(stable_ids))
        or _digest(_canonical_json(stable_ids)) != authorization["device_set_digest"]
        or authorization["device_set_digest"] != value["postcheck_device_set_digest"]
        or (value["layout"] == "single") != (len(devices) == 1)
    ):
        raise RetirementError("storage retirement exact device set is invalid")
    return value


def _lsblk() -> dict[str, dict[str, Any]]:
    raw = _run(
        [
            COMMANDS["lsblk"],
            "--json",
            "--bytes",
            "--output",
            "NAME,KNAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS,PKNAME,SERIAL,WWN",
        ]
    )
    try:
        root = json.loads(raw)
    except ValueError as error:
        raise RetirementError(
            "immediate block topology evidence is malformed"
        ) from error
    found: dict[str, dict[str, Any]] = {}

    def walk(items: object, parents: tuple[str, ...] = ()) -> None:
        if not isinstance(items, list):
            raise RetirementError("immediate block topology evidence is malformed")
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise RetirementError("immediate block topology evidence is malformed")
            normalized = dict(item)
            normalized["_parents"] = parents
            path = normalized["path"]
            if path in found:
                raise RetirementError("immediate block topology evidence is duplicated")
            found[path] = normalized
            walk(item.get("children", []), (*parents, path))

    if not isinstance(root, dict):
        raise RetirementError("immediate block topology evidence is malformed")
    walk(root.get("blockdevices"))
    return found


def _mount_active() -> bool:
    raw = _run(
        [COMMANDS["findmnt"], "--json", "--target", MOUNT_POINT],
        allowed=(0, 1),
    )
    return MOUNT_POINT in raw


def _service_active() -> bool:
    raw = _run(
        [COMMANDS["systemctl"], "is-active", "scylla-server"],
        allowed=(0, 3, 4),
    )
    return raw.strip() == "active"


def _immediate_revalidate(intent: dict[str, Any]) -> list[str]:
    topology = _lsblk()
    paths: list[str] = []
    selected_paths = {item["path"] for item in intent["devices"]}
    for expected in intent["devices"]:
        if set(expected) != {
            "by_id",
            "filesystem",
            "holders",
            "identity",
            "mount_points",
            "path",
            "root_ancestor",
            "signatures",
            "size_bytes",
            "stable_id",
        }:
            raise RetirementError("storage device intent fields are invalid")
        path = expected["path"]
        if (
            not isinstance(path, str)
            or not path.startswith("/dev/")
            or os.path.islink(path)
            or os.path.realpath(path) != path
        ):
            raise RetirementError("selected storage path is not an exact real device")
        current = topology.get(path)
        if (
            current is None
            or current.get("type") != "disk"
            or current.get("size") != expected["size_bytes"]
        ):
            raise RetirementError("immediate block evidence differs from discovery")
        boot_mounts = set(current.get("mountpoints") or []) & {
            "/",
            "/boot",
            "/boot/efi",
        }
        if expected["root_ancestor"] or boot_mounts:
            raise RetirementError("selected storage intersects boot or system storage")
        by_ids = expected["by_id"]
        if not isinstance(by_ids, list) or not by_ids:
            raise RetirementError("stable by-id evidence is unavailable")
        for by_id in by_ids:
            if (
                not isinstance(by_id, str)
                or not by_id.startswith("/dev/disk/by-id/")
                or os.path.realpath(by_id) != path
            ):
                raise RetirementError("stable by-id ownership changed")
        paths.append(path)
    if set(paths) != selected_paths or len(paths) != len(selected_paths):
        raise RetirementError("storage device set contains extra or missing paths")
    return paths


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temporary)


def _remove_fstab_entry() -> bool:
    fstab = Path("/etc/fstab")
    current = fstab.read_text(encoding="utf-8")
    kept: list[str] = []
    removed = False
    for line in current.splitlines(keepends=True):
        stripped = line.split("#", 1)[0]
        fields = stripped.split()
        if len(fields) >= 2 and fields[1] == MOUNT_POINT:
            if removed:
                raise RetirementError(
                    "canonical Scylla mount has duplicate fstab entries"
                )
            removed = True
            continue
        kept.append(line)
    if not removed:
        return False
    _atomic_write(fstab, "".join(kept).encode("utf-8"), 0o644)
    return True


def _raid_present() -> bool:
    return Path(MD_DEVICE).exists()


def _retire(intent: dict[str, Any]) -> tuple[bool, dict[str, object]]:
    completed = ["authorization-validated"]
    irreversible = "not-started"
    first_step = "none"
    wipe_performed = False
    blockers: list[str] = []
    try:
        if intent["classification"] != "owned-noop":
            blockers.append("classification-not-owned")
            raise RetirementError("owned-noop storage is required")
        if intent["authorization"]["membership_absent"] is not True:
            blockers.append("membership-not-absent")
            blockers.append("still-member")
            raise RetirementError("target is still a cluster member")
        if _service_active():
            blockers.extend(["service-active", "still-member", "active-data-claimed"])
            raise RetirementError("Scylla service is still active")
        completed.append("service-inactive-validated")
        paths = _immediate_revalidate(intent)
        completed.append("immediate-rediscovery-validated")
        mounted = _mount_active()
        if not mounted:
            blockers.append("device-identity-conflict")
            raise RetirementError("prepared mount evidence is missing or drifted")
        if intent["check_mode_requested"]:
            return False, _result(
                intent,
                status="not-predicted",
                completed=completed,
                irreversible=irreversible,
                first_step=first_step,
                wipe_performed=False,
                manual_recovery=False,
                blockers=["check-mode-refused"],
                verification={"writes_performed": False},
            )
        marker_path = Path(MOUNT_POINT, MARKER_NAME)
        if not marker_path.is_file():
            raise RetirementError("owned storage marker is unavailable")
        marker_digest = _digest(marker_path.read_bytes())
        expected_marker = intent["expected_marker_digest"]
        if expected_marker is not None and marker_digest != expected_marker:
            raise RetirementError("owned storage marker digest changed")
        completed.append("ownership-verified")
        first_step = "unmount"
        irreversible = "started"
        _run([COMMANDS["umount"], MOUNT_POINT])
        completed.append("unmounted")
        _remove_fstab_entry()
        completed.append("fstab-removed")
        raid_deactivated = intent["layout"] != "raid0"
        if intent["layout"] == "raid0":
            if not _raid_present():
                raise RetirementError("authorized RAID device is missing")
            first_step = first_step or "raid-stop"
            _run([COMMANDS["mdadm"], "--stop", MD_DEVICE])
            completed.append("raid-deactivated")
            raid_deactivated = True
        if intent["wipe_required"]:
            if first_step == "none":
                first_step = "wipe"
            for path in paths:
                _run([COMMANDS["wipefs"], "--all", "--force", path])
            wipe_performed = True
            completed.append("signatures-wiped")
        irreversible = "completed"
        if _mount_active():
            raise RetirementError("post-action mount verification failed")
        return True, _result(
            intent,
            status="changed",
            completed=completed,
            irreversible=irreversible,
            first_step=first_step,
            wipe_performed=wipe_performed,
            manual_recovery=False,
            blockers=[],
            verification={
                "devices_unmounted": True,
                "fstab_removed": True,
                "infrastructure_destroyed": False,
                "membership_absent": True,
                "raid_deactivated": raid_deactivated,
                "scylla_started": False,
                "scylla_stopped": False,
                "service_inactive": True,
                "terraform_performed": False,
                "wipe_verified": wipe_performed,
                "writes_performed": True,
            },
        )
    except (OSError, RetirementError, UnicodeError, ValueError):
        status = "failed"
        if intent["check_mode_requested"] and "check-mode-refused" in blockers:
            status = "not-predicted"
        return False, _result(
            intent,
            status=status,
            completed=completed,
            irreversible=irreversible,
            first_step=first_step,
            wipe_performed=wipe_performed,
            manual_recovery=irreversible != "not-started",
            blockers=blockers or ["execution-failed"],
            verification={
                "infrastructure_destroyed": False,
                "scylla_started": False,
                "scylla_stopped": False,
                "terraform_performed": False,
                "writes_performed": irreversible != "not-started",
            }
            if status == "failed"
            else {"writes_performed": False},
        )


def main() -> None:
    module = AnsibleModule(
        argument_spec={"intent": {"type": "dict", "required": True}},
        supports_check_mode=True,
    )
    try:
        intent = _validate_intent(module.params["intent"])
        if module.check_mode:
            intent = dict(intent)
            intent["check_mode_requested"] = True
        changed, result = _retire(intent)
    except RetirementError as error:
        message = str(error)
        blockers = ["execution-failed"]
        if "member" in message:
            blockers = ["membership-not-absent", "still-member"]
        elif "wipe acknowledgement" in message:
            blockers = ["wipe-consent-missing"]
        module.exit_json(
            changed=False,
            storage_retire_result={
                "backend": "unknown",
                "blockers": blockers,
                "completed_steps": [],
                "device_set_digest": "sha256:" + "0" * 64,
                "devices": [],
                "disposition": "retain",
                "first_irreversible_step": "none",
                "irreversible_step_status": "not-started",
                "layout": "unknown",
                "logical_id": "unknown",
                "manual_recovery_required": False,
                "not_performed": [
                    "raid-teardown",
                    "scylla-start",
                    "scylla-stop",
                    "terraform-apply",
                    "terraform-destroy",
                    "vm-destroy",
                    "volume-delete",
                    "volume-detach",
                    "wipe",
                ],
                "post_action_verification": {"manual_recovery_required": False},
                "provenance": {},
                "schema_version": SCHEMA,
                "status": "failed",
                "wipe_performed": False,
            },
        )
    module.exit_json(changed=changed, storage_retire_result=result)


if __name__ == "__main__":
    main()
