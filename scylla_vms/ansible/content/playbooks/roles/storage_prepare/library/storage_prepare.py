#!/usr/bin/python
"""Prepare an exact pre-authorized Scylla device set without discovery selection."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-untyped]

SCHEMA = "deploy-scylla-vms.ansible-storage-prepare/v1"
OWNER_SCHEMA = "deploy-scylla-vms.prepared-storage/v1"
MOUNT_POINT = "/var/lib/scylla"
MD_DEVICE = "/dev/md/scylla-data"
COMMAND_TIMEOUT = 30
DEPLOY_SELECTION_MODE = "public-device-identity-digest"
DEPLOY_ACTION = "prepare-required"
COMMANDS = {
    "blkid": "/usr/sbin/blkid",
    "findmnt": "/usr/bin/findmnt",
    "lsblk": "/usr/bin/lsblk",
    "mdadm": "/usr/sbin/mdadm",
    "mkfs_xfs": "/usr/sbin/mkfs.xfs",
    "mount": "/usr/bin/mount",
    "wipefs": "/usr/sbin/wipefs",
}


class PreparationError(Exception):
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
        raise PreparationError("fixed storage command execution failed") from error
    if result.returncode not in allowed or len(result.stdout.encode("utf-8")) > 262144:
        raise PreparationError("fixed storage command returned invalid evidence")
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
    filesystem_uuid: str | None = None,
    marker_digest: str | None = None,
    verification: dict[str, bool] | None = None,
    immediate_revalidated: bool = False,
    first_irreversible_step: str | None = None,
    wipe_applied: bool = False,
) -> dict[str, object]:
    result: dict[str, object] = {
        "backend": intent["backend"],
        "completed_steps": completed,
        "device_set_digest": intent["authorization"]["device_set_digest"],
        "filesystem_uuid_digest": (
            None
            if filesystem_uuid is None
            else _digest(filesystem_uuid.encode("utf-8"))
        ),
        "irreversible_step_status": irreversible,
        "layout": intent["layout"],
        "logical_id": intent["logical_id"],
        "marker_digest": marker_digest,
        "post_action_verification": verification or {},
        "schema_version": SCHEMA,
        "status": status,
    }
    if intent.get("selection_mode") == DEPLOY_SELECTION_MODE:
        result.update(
            {
                "action": intent["action"],
                "completed": status == "changed" and irreversible == "completed",
                "disposition": intent["classification"],
                "first_irreversible_step": first_irreversible_step,
                "immediate_device_revalidation": immediate_revalidated,
                "mutation_boundary": (
                    "not-crossed"
                    if irreversible == "not-started"
                    else "completed"
                    if irreversible == "completed"
                    else "crossed"
                ),
                "preparation_intent_digest": intent["authorization"][
                    "preparation_intent_digest"
                ],
                "provenance_digest": intent["provenance_digest"],
                "wipe_applied": wipe_applied,
            }
        )
    return result


def _validate_intent(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PreparationError("storage preparation intent is not an object")
    required = {
        "authorization",
        "backend",
        "check_mode_requested",
        "classification",
        "cluster_uuid",
        "devices",
        "discovery_digest",
        "filesystem",
        "host_manifest_digest",
        "inventory_digest",
        "inventory_generation",
        "layout",
        "logical_id",
        "mount_options",
        "mount_point",
        "observation_digest",
        "observation_generation",
        "policy_digest",
        "provider_id",
        "schema_version",
        "storage_generation",
    }
    deploy_mode = value.get("selection_mode") == DEPLOY_SELECTION_MODE
    if deploy_mode:
        required.update(
            {
                "action",
                "preflight_evidence_digest",
                "provenance_digest",
                "selection_mode",
            }
        )
    if set(value) != required:
        raise PreparationError("storage preparation intent fields are invalid")
    authorization = value["authorization"]
    if not isinstance(authorization, dict) or set(authorization) != {
        "device_set_digest",
        "logical_id",
        "operation_id",
        "preparation_approved",
        "preparation_intent_digest",
        "wipe_acknowledged",
    }:
        raise PreparationError("storage preparation authorization fields are invalid")
    if (
        value["schema_version"] != SCHEMA
        or value["logical_id"] != authorization["logical_id"]
        or value["backend"] not in {"block-volume", "local-nvme"}
        or value["layout"] not in {"single", "raid0"}
        or value["filesystem"] != "xfs"
        or value["mount_point"] != MOUNT_POINT
        or value["classification"]
        not in (
            {"clean-new", "wipe-review-required"}
            if deploy_mode
            else {"clean-new", "owned-noop", "wipe-review-required"}
        )
        or authorization["preparation_approved"] is not True
        or not isinstance(value["devices"], list)
        or not value["devices"]
    ):
        raise PreparationError("storage preparation policy or authorization is invalid")
    wipe = value["classification"] == "wipe-review-required"
    if authorization["wipe_acknowledged"] is not wipe:
        raise PreparationError(
            "storage wipe acknowledgement does not match classification"
        )
    devices = value["devices"]
    identities: list[str] = []
    if deploy_mode:
        if value["action"] != DEPLOY_ACTION:
            raise PreparationError("storage preparation action is invalid")
        for item in devices:
            if (
                not isinstance(item, dict)
                or set(item) != {"capacity_bytes", "identity"}
                or not isinstance(item.get("capacity_bytes"), int)
                or isinstance(item.get("capacity_bytes"), bool)
                or item["capacity_bytes"] <= 0
                or not isinstance(item.get("identity"), str)
                or re.fullmatch(r"device-sha256:[0-9a-f]{64}", item["identity"]) is None
            ):
                raise PreparationError(
                    "storage preparation public device identity is invalid"
                )
            identities.append(item["identity"])
        expected_provenance = _deploy_provenance_digest(value)
        if (
            not _is_digest(value["preflight_evidence_digest"])
            or value["provenance_digest"] != expected_provenance
        ):
            raise PreparationError("storage preparation deploy provenance is invalid")
    else:
        for item in devices:
            if not isinstance(item, dict) or not isinstance(item.get("stable_id"), str):
                raise PreparationError("storage preparation device identity is invalid")
            identities.append(item["stable_id"])
    if (
        identities != sorted(set(identities))
        or (
            _digest(
                _canonical_json({"value": identities}) + b"\n"
                if deploy_mode
                else _canonical_json(identities)
            )
            != authorization["device_set_digest"]
        )
        or (value["layout"] == "single") != (len(devices) == 1)
    ):
        raise PreparationError("storage preparation exact device set is invalid")
    return value


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    )


def _deploy_provenance_digest(intent: dict[str, Any]) -> str:
    value = {
        "cluster_uuid": intent["cluster_uuid"],
        "device_set_digest": intent["authorization"]["device_set_digest"],
        "discovery_digest": intent["discovery_digest"],
        "inventory_digest": intent["inventory_digest"],
        "inventory_generation": intent["inventory_generation"],
        "logical_id": intent["logical_id"],
        "observation_digest": intent["observation_digest"],
        "observation_generation": intent["observation_generation"],
        "operation_id": intent["authorization"]["operation_id"],
        "policy_digest": intent["policy_digest"],
        "preflight_evidence_digest": intent["preflight_evidence_digest"],
        "preparation_intent_digest": intent["authorization"][
            "preparation_intent_digest"
        ],
        "schema_version": "deploy-scylla-vms.storage-prepare-provenance/v1",
        "storage_generation": intent["storage_generation"],
    }
    return _digest(_canonical_json(value))


def _lsblk() -> dict[str, dict[str, Any]]:
    raw = _run(
        [
            COMMANDS["lsblk"],
            "--json",
            "--bytes",
            "--output",
            "NAME,KNAME,PATH,TYPE,SIZE,TRAN,FSTYPE,MOUNTPOINTS,PKNAME,SERIAL,WWN",
        ]
    )
    try:
        root = json.loads(raw)
    except ValueError as error:
        raise PreparationError(
            "immediate block topology evidence is malformed"
        ) from error
    found: dict[str, dict[str, Any]] = {}

    def walk(items: object, parents: tuple[str, ...] = ()) -> None:
        if not isinstance(items, list):
            raise PreparationError("immediate block topology evidence is malformed")
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise PreparationError("immediate block topology evidence is malformed")
            normalized = dict(item)
            normalized["_parents"] = parents
            path = normalized["path"]
            if path in found:
                raise PreparationError(
                    "immediate block topology evidence is duplicated"
                )
            found[path] = normalized
            walk(item.get("children", []), (*parents, path))

    if not isinstance(root, dict):
        raise PreparationError("immediate block topology evidence is malformed")
    walk(root.get("blockdevices"))
    return found


def _by_id_links() -> dict[str, list[str]]:
    root = Path("/dev/disk/by-id")
    result: dict[str, list[str]] = {}
    try:
        entries = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError:
        return result
    for entry in entries[:1024]:
        try:
            if not entry.is_symlink():
                continue
            target = str(entry.resolve(strict=True))
        except OSError:
            continue
        result.setdefault(target, []).append(str(entry))
    return result


def _stable_id(row: dict[str, Any], links: list[str]) -> str | None:
    if links:
        return f"by-id:{Path(links[0]).name}"
    wwn = row.get("wwn")
    if isinstance(wwn, str) and wwn:
        return f"wwn:{wwn}"
    serial = row.get("serial")
    if isinstance(serial, str) and serial:
        return f"serial:{serial}"
    return None


def _public_device_identity(stable_id: str) -> str:
    return "device-sha256:" + hashlib.sha256(stable_id.encode("utf-8")).hexdigest()


def _signatures(path: str) -> list[dict[str, str]]:
    raw = _run(
        [COMMANDS["wipefs"], "--json", "--noheadings", path],
        allowed=(0, 1),
    )
    signatures: set[tuple[str, str]] = set()
    try:
        value = json.loads(raw) if raw.strip() else {"signatures": []}
    except ValueError as error:
        raise PreparationError("immediate signature evidence is malformed") from error
    for item in value.get("signatures", []):
        signature_type = item.get("type")
        usage = item.get("usage")
        if not isinstance(signature_type, str) or not signature_type:
            raise PreparationError("immediate signature evidence is malformed")
        kind = (
            "filesystem"
            if usage == "filesystem"
            else "partition-table"
            if usage == "partition table"
            else "raid"
            if isinstance(usage, str) and "raid" in usage
            else "lvm"
            if "lvm" in signature_type.lower()
            else "partition-table"
            if signature_type.lower() in {"dos", "gpt"}
            else "filesystem"
        )
        signatures.add((kind, signature_type))
    blkid = _run(
        [COMMANDS["blkid"], "--probe", "--output", "export", path],
        allowed=(0, 2),
    )
    for line in blkid.splitlines()[:64]:
        key, separator, signature = line.partition("=")
        if not separator or not signature:
            continue
        if key == "TYPE":
            signatures.add(("filesystem", signature))
        elif key == "PTTYPE":
            signatures.add(("partition-table", signature))
    return [{"kind": kind, "value": value} for kind, value in sorted(signatures)]


def _immediate_revalidate(intent: dict[str, Any]) -> list[str]:
    if intent.get("selection_mode") == DEPLOY_SELECTION_MODE:
        return _immediate_revalidate_deploy(intent)
    topology = _lsblk()
    paths: list[str] = []
    selected_paths = {item["path"] for item in intent["devices"]}
    for expected in intent["devices"]:
        if set(expected) != {
            "by_id",
            "filesystem",
            "holders",
            "mount_points",
            "path",
            "root_ancestor",
            "signatures",
            "size_bytes",
            "stable_id",
        }:
            raise PreparationError("storage device intent fields are invalid")
        path = expected["path"]
        if (
            not isinstance(path, str)
            or not path.startswith("/dev/")
            or os.path.islink(path)
            or os.path.realpath(path) != path
        ):
            raise PreparationError("selected storage path is not an exact real device")
        current = topology.get(path)
        current_mounts = (
            sorted(
                item
                for item in (current.get("mountpoints") or [])
                if isinstance(item, str)
            )
            if current is not None
            else []
        )
        if (
            current is None
            or current.get("type") != "disk"
            or current.get("size") != expected["size_bytes"]
            or current.get("fstype") != expected["filesystem"]
            or current_mounts != expected["mount_points"]
        ):
            raise PreparationError("immediate block evidence differs from preflight")
        kname = current.get("kname")
        if not isinstance(kname, str) or "/" in kname:
            raise PreparationError("immediate block kernel identity is invalid")
        holders = Path("/sys/class/block", kname, "holders")
        try:
            current_holders = sorted(item.name for item in holders.iterdir())
        except OSError as error:
            raise PreparationError(
                "immediate holder evidence is unavailable"
            ) from error
        if current_holders != expected["holders"]:
            raise PreparationError("immediate holder evidence differs from preflight")
        if _signatures(path) != expected["signatures"]:
            raise PreparationError(
                "immediate signature evidence differs from preflight"
            )
        descendants = [
            item for item in topology.values() if path in item.get("_parents", ())
        ]
        if any(
            set(item.get("mountpoints") or []) & {"/", "/boot", "/boot/efi"}
            or item.get("type") in {"crypt", "lvm", "raid", "md"}
            for item in (current, *descendants)
        ):
            raise PreparationError("selected storage intersects boot or active storage")
        by_ids = expected["by_id"]
        if not isinstance(by_ids, list) or not by_ids:
            raise PreparationError("stable by-id evidence is unavailable")
        for by_id in by_ids:
            if (
                not isinstance(by_id, str)
                or not by_id.startswith("/dev/disk/by-id/")
                or os.path.realpath(by_id) != path
            ):
                raise PreparationError("stable by-id ownership changed")
        paths.append(path)
    if set(paths) != selected_paths or len(paths) != len(selected_paths):
        raise PreparationError("storage device set contains extra or missing paths")
    return paths


def _immediate_revalidate_deploy(intent: dict[str, Any]) -> list[str]:
    topology = _lsblk()
    links = _by_id_links()
    matches: dict[str, tuple[str, str]] = {}
    for path, row in topology.items():
        if row.get("type") != "disk":
            continue
        stable_id = _stable_id(row, links.get(path, []))
        if stable_id is None:
            continue
        identity = _public_device_identity(stable_id)
        if identity in matches:
            raise PreparationError("immediate public device identity is ambiguous")
        matches[identity] = (path, stable_id)

    paths: list[str] = []
    stable_ids: list[str] = []
    for expected in intent["devices"]:
        identity = expected["identity"]
        selected = matches.get(identity)
        if selected is None:
            raise PreparationError("immediate public device identity is unavailable")
        path, stable_id = selected
        current = topology[path]
        current_mounts = sorted(
            item for item in (current.get("mountpoints") or []) if isinstance(item, str)
        )
        descendants = [
            item for item in topology.values() if path in item.get("_parents", ())
        ]
        if (
            current.get("size") != expected["capacity_bytes"]
            or current_mounts
            or (
                current.get("fstype") is not None
                and intent["classification"] == "clean-new"
            )
            or any(
                set(item.get("mountpoints") or []) & {"/", "/boot", "/boot/efi"}
                or item.get("type") in {"crypt", "lvm", "raid", "md"}
                for item in (current, *descendants)
            )
        ):
            raise PreparationError(
                "immediate block evidence differs from authorized preflight"
            )
        kname = current.get("kname")
        if not isinstance(kname, str) or "/" in kname:
            raise PreparationError("immediate block kernel identity is invalid")
        holders = Path("/sys/class/block", kname, "holders")
        try:
            if any(holders.iterdir()):
                raise PreparationError("selected storage has active holders")
        except OSError as error:
            raise PreparationError(
                "immediate holder evidence is unavailable"
            ) from error
        signatures = _signatures(path)
        if intent["classification"] == "clean-new" and signatures:
            raise PreparationError(
                "clean-new storage acquired signatures after preflight"
            )
        if (
            not path.startswith("/dev/")
            or os.path.islink(path)
            or os.path.realpath(path) != path
        ):
            raise PreparationError("selected storage path is not an exact real device")
        paths.append(path)
        stable_ids.append(stable_id)
    if len(paths) != len(set(paths)) or len(paths) != len(intent["devices"]):
        raise PreparationError("storage device set contains extra or missing paths")
    intent["_resolved_stable_device_ids"] = sorted(stable_ids)
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


def _prepare(intent: dict[str, Any]) -> tuple[bool, dict[str, object]]:
    completed = ["authorization-validated"]
    irreversible = "not-started"
    filesystem_uuid: str | None = None
    marker_digest: str | None = None
    immediate_revalidated = False
    first_irreversible_step: str | None = None
    wipe_applied = False
    try:
        paths = _immediate_revalidate(intent)
        immediate_revalidated = True
        completed.append("immediate-rediscovery-validated")
        if intent["check_mode_requested"]:
            return False, _result(
                intent,
                status="not-predicted",
                completed=completed,
                irreversible=irreversible,
                verification={"writes_performed": False},
                immediate_revalidated=immediate_revalidated,
                first_irreversible_step=first_irreversible_step,
                wipe_applied=wipe_applied,
            )
        if intent["classification"] == "owned-noop":
            marker_path = Path(MOUNT_POINT, ".deploy-scylla-vms-storage.json")
            if not marker_path.is_file():
                raise PreparationError("owned storage marker is unavailable")
            marker_digest = _digest(marker_path.read_bytes())
            return False, _result(
                intent,
                status="noop",
                completed=[*completed, "owned-state-verified"],
                irreversible=irreversible,
                marker_digest=marker_digest,
                verification={"marker_present": True, "writes_performed": False},
                immediate_revalidated=immediate_revalidated,
                first_irreversible_step=first_irreversible_step,
                wipe_applied=wipe_applied,
            )

        if intent["classification"] == "wipe-review-required":
            irreversible = "started"
            first_irreversible_step = "signatures-wiped"
            for path in paths:
                _run([COMMANDS["wipefs"], "--all", "--force", path])
                wipe_applied = True
            completed.append("signatures-wiped")

        target = paths[0]
        if intent["layout"] == "raid0":
            irreversible = "started"
            if first_irreversible_step is None:
                first_irreversible_step = "raid0-created"
            _run(
                [
                    COMMANDS["mdadm"],
                    "--create",
                    MD_DEVICE,
                    "--run",
                    "--level=0",
                    f"--raid-devices={len(paths)}",
                    *paths,
                ]
            )
            completed.append("raid0-created")
            target = MD_DEVICE

        irreversible = "started"
        if first_irreversible_step is None:
            first_irreversible_step = "xfs-formatted"
        _run([COMMANDS["mkfs_xfs"], "-f", "-L", "scylla-data", target])
        completed.append("xfs-formatted")
        filesystem_uuid = _run(
            [COMMANDS["blkid"], "-s", "UUID", "-o", "value", target]
        ).strip()
        if not filesystem_uuid or len(filesystem_uuid) > 128:
            raise PreparationError("filesystem UUID verification failed")

        mount_path = Path(MOUNT_POINT)
        mount_path.mkdir(mode=0o750, parents=True, exist_ok=True)
        os.chown(mount_path, 0, 0)
        os.chmod(mount_path, 0o750)
        source = f"UUID={filesystem_uuid}"
        options = ",".join(intent["mount_options"])
        fstab = Path("/etc/fstab")
        line = f"{source} {MOUNT_POINT} xfs {options} 0 0\n"
        current_fstab = fstab.read_text(encoding="utf-8")
        if MOUNT_POINT in current_fstab:
            raise PreparationError("canonical Scylla mount already has an fstab entry")
        _atomic_write(fstab, (current_fstab + line).encode("utf-8"), 0o644)
        completed.append("fstab-written")
        _run([COMMANDS["mount"], MOUNT_POINT])
        completed.append("mounted")

        owner = {
            "backend": intent["backend"],
            "cluster_uuid": intent["cluster_uuid"],
            "layout": intent["layout"],
            "logical_id": intent["logical_id"],
            "policy_digest": intent["policy_digest"],
            "preparation_intent_digest": intent["authorization"][
                "preparation_intent_digest"
            ],
            "provider_id": intent["provider_id"],
            "schema_version": OWNER_SCHEMA,
            "stable_device_ids": (
                intent["_resolved_stable_device_ids"]
                if intent.get("selection_mode") == DEPLOY_SELECTION_MODE
                else [item["stable_id"] for item in intent["devices"]]
            ),
            "storage_generation": intent["storage_generation"],
        }
        marker_data = _canonical_json(owner) + b"\n"
        marker_path = Path(MOUNT_POINT, ".deploy-scylla-vms-storage.json")
        _atomic_write(marker_path, marker_data, 0o600)
        marker_digest = _digest(marker_data)
        completed.append("owner-marker-written")
        irreversible = "completed"
        mounted = MOUNT_POINT in _run(
            [COMMANDS["findmnt"], "--json", "--target", MOUNT_POINT]
        )
        if not mounted:
            raise PreparationError("post-action mount verification failed")
        return True, _result(
            intent,
            status="changed",
            completed=completed,
            irreversible=irreversible,
            filesystem_uuid=filesystem_uuid,
            marker_digest=marker_digest,
            verification={
                "filesystem_uuid_verified": True,
                "fstab_uuid_verified": True,
                "marker_verified": True,
                "mount_verified": True,
            },
            immediate_revalidated=immediate_revalidated,
            first_irreversible_step=first_irreversible_step,
            wipe_applied=wipe_applied,
        )
    except (OSError, PreparationError, UnicodeError, ValueError):
        return bool(irreversible != "not-started"), _result(
            intent,
            status="failed",
            completed=completed,
            irreversible=irreversible,
            filesystem_uuid=filesystem_uuid,
            marker_digest=marker_digest,
            verification={"manual_recovery_required": irreversible != "not-started"},
            immediate_revalidated=immediate_revalidated,
            first_irreversible_step=first_irreversible_step,
            wipe_applied=wipe_applied,
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
        changed, result = _prepare(intent)
    except PreparationError:
        module.fail_json(
            changed=False,
            msg="storage preparation validation failed",
            storage_prepare_result={
                "backend": "unknown",
                "completed_steps": [],
                "device_set_digest": "sha256:" + "0" * 64,
                "filesystem_uuid_digest": None,
                "irreversible_step_status": "not-started",
                "layout": "unknown",
                "logical_id": "unknown",
                "marker_digest": None,
                "post_action_verification": {"manual_recovery_required": False},
                "schema_version": SCHEMA,
                "status": "failed",
            },
        )
    if result["status"] == "failed":
        module.fail_json(
            changed=changed,
            msg="storage preparation failed",
            storage_prepare_result=result,
        )
    module.exit_json(changed=changed, storage_prepare_result=result)


if __name__ == "__main__":
    main()
