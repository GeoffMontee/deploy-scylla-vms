#!/usr/bin/python
"""Read-only exact verification of prepared Scylla storage."""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-untyped]

SCHEMA = "deploy-scylla-vms.ansible-storage-postcheck/v1"
OWNER_SCHEMA = "deploy-scylla-vms.prepared-storage/v1"
DEPLOY_SELECTION_MODE = "public-device-identity-digest"
MOUNT_POINT = "/var/lib/scylla"
MARKER_PATH = Path(MOUNT_POINT, ".deploy-scylla-vms-storage.json")
MD_DEVICE = "/dev/md/scylla-data"
COMMAND_TIMEOUT = 30
COMMANDS = {
    "findmnt": "/usr/bin/findmnt",
    "lsblk": "/usr/bin/lsblk",
    "mdadm": "/usr/sbin/mdadm",
}
CHECKS = (
    "capacity",
    "device-membership",
    "filesystem",
    "fstab",
    "holders",
    "marker",
    "mount",
    "permissions",
    "provenance",
    "raid",
    "signatures",
    "tools",
)


class PostcheckError(Exception):
    pass


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


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
        raise PostcheckError("fixed read-only storage command failed") from error
    if result.returncode not in allowed or len(result.stdout.encode("utf-8")) > 262144:
        raise PostcheckError(
            "fixed read-only storage command returned invalid evidence"
        )
    return result.stdout


def _validate_expected(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PostcheckError("storage postcheck expectation fields are invalid")
    required = {
        "backend",
        "capacity_bytes",
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
        "mount_options",
        "mount_point",
        "observation_digest",
        "observation_generation",
        "policy_digest",
        "preparation_intent_digest",
        "prepare_device_set_digest",
        "provider_id",
        "schema_version",
        "storage_generation",
    }
    deploy_mode = value.get("selection_mode") == DEPLOY_SELECTION_MODE
    if deploy_mode:
        required.update(
            {
                "preflight_evidence_digest",
                "preparation_evidence_digest",
                "selection_mode",
            }
        )
    if set(value) != required:
        raise PostcheckError("storage postcheck expectation fields are invalid")
    if (
        value["schema_version"] != SCHEMA
        or value["backend"] not in {"block-volume", "local-nvme"}
        or value["layout"] not in {"single", "raid0"}
        or value["filesystem"] != "xfs"
        or value["mount_point"] != MOUNT_POINT
        or not isinstance(value["devices"], list)
        or not value["devices"]
        or not isinstance(value["mount_options"], list)
        or value["mount_options"] != sorted(set(value["mount_options"]))
    ):
        raise PostcheckError("storage postcheck policy is invalid")
    stable_ids: list[str] = []
    for item in value["devices"]:
        if deploy_mode:
            if (
                not isinstance(item, dict)
                or set(item) != {"capacity_bytes", "identity"}
                or not isinstance(item.get("capacity_bytes"), int)
                or isinstance(item.get("capacity_bytes"), bool)
                or item["capacity_bytes"] <= 0
                or not isinstance(item.get("identity"), str)
                or re.fullmatch(r"device-sha256:[0-9a-f]{64}", item["identity"]) is None
            ):
                raise PostcheckError(
                    "storage postcheck public device identity is invalid"
                )
            stable_ids.append(item["identity"])
        else:
            if not isinstance(item, dict) or set(item) != {
                "by_id",
                "identity",
                "path",
                "size_bytes",
                "stable_id",
            }:
                raise PostcheckError("storage postcheck device expectation is invalid")
            if (
                not isinstance(item["path"], str)
                or not item["path"].startswith("/dev/")
                or not isinstance(item["stable_id"], str)
                or not isinstance(item["by_id"], list)
                or not item["by_id"]
                or not isinstance(item["size_bytes"], int)
                or item["size_bytes"] <= 0
            ):
                raise PostcheckError("storage postcheck device expectation is invalid")
            stable_ids.append(item["stable_id"])
    if stable_ids != sorted(set(stable_ids)):
        raise PostcheckError("storage postcheck device membership is invalid")
    if deploy_mode:
        for name in (
            "preflight_evidence_digest",
            "preparation_evidence_digest",
            "prepare_device_set_digest",
        ):
            if not _is_digest(value[name]):
                raise PostcheckError("storage postcheck deploy provenance is invalid")
        if (
            _digest(_canonical_json({"value": stable_ids}) + b"\n")
            != value["prepare_device_set_digest"]
        ):
            raise PostcheckError("storage postcheck exact device set is invalid")
    return value


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    )


def _lsblk() -> dict[str, dict[str, Any]]:
    raw = _run(
        [
            COMMANDS["lsblk"],
            "--json",
            "--bytes",
            "--output",
            "KNAME,PATH,TYPE,SIZE,FSTYPE,UUID,MOUNTPOINTS,PKNAME,SERIAL,WWN",
        ]
    )
    try:
        root = json.loads(raw)
    except ValueError as error:
        raise PostcheckError("block topology evidence is malformed") from error
    found: dict[str, dict[str, Any]] = {}

    def walk(items: object, parents: tuple[str, ...] = ()) -> None:
        if not isinstance(items, list):
            raise PostcheckError("block topology evidence is malformed")
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise PostcheckError("block topology evidence is malformed")
            normalized = dict(item)
            normalized["_parents"] = parents
            path = normalized["path"]
            if path in found:
                raise PostcheckError("block topology evidence is duplicated")
            found[path] = normalized
            walk(item.get("children", []), (*parents, path))

    if not isinstance(root, dict):
        raise PostcheckError("block topology evidence is malformed")
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


def _resolve_deploy_expected(expected: dict[str, Any]) -> dict[str, Any]:
    if expected.get("selection_mode") != DEPLOY_SELECTION_MODE:
        return expected
    topology = _lsblk()
    links = _by_id_links()
    matches: dict[str, tuple[str, str, list[str]]] = {}
    for path, row in topology.items():
        if row.get("type") != "disk":
            continue
        by_id = links.get(path, [])
        stable_id = _stable_id(row, by_id)
        if stable_id is None:
            continue
        identity = _public_device_identity(stable_id)
        if identity in matches:
            raise PostcheckError("storage postcheck public identity is ambiguous")
        matches[identity] = (path, stable_id, by_id)
    resolved: list[dict[str, object]] = []
    for item in expected["devices"]:
        identity = item["identity"]
        selected = matches.get(identity)
        if selected is None:
            raise PostcheckError("storage postcheck public identity is unavailable")
        path, stable_id, by_id = selected
        row = topology[path]
        if row.get("size") != item["capacity_bytes"]:
            raise PostcheckError("storage postcheck public capacity conflicts")
        resolved.append(
            {
                "by_id": by_id,
                "identity": identity,
                "path": path,
                "size_bytes": item["capacity_bytes"],
                "stable_id": stable_id,
            }
        )
    if len({item["path"] for item in resolved}) != len(resolved):
        raise PostcheckError("storage postcheck public device set conflicts")
    result = dict(expected)
    result["devices"] = sorted(resolved, key=lambda item: str(item["stable_id"]))
    return result


def _mount() -> dict[str, Any]:
    raw = _run(
        [
            COMMANDS["findmnt"],
            "--json",
            "--target",
            MOUNT_POINT,
            "--output",
            "SOURCE,TARGET,FSTYPE,OPTIONS,UUID",
        ]
    )
    try:
        value = json.loads(raw)
        filesystems = value["filesystems"]
    except (KeyError, TypeError, ValueError) as error:
        raise PostcheckError("mount evidence is malformed") from error
    if not isinstance(filesystems, list) or len(filesystems) != 1:
        raise PostcheckError("mount evidence is ambiguous")
    mount = filesystems[0]
    if not isinstance(mount, dict):
        raise PostcheckError("mount evidence is malformed")
    return mount


def _fstab(uuid_value: str, options: list[str]) -> bool:
    try:
        lines = Path("/etc/fstab").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise PostcheckError("fstab evidence is unavailable") from error
    matches: list[list[str]] = []
    for line in lines:
        content = line.partition("#")[0].strip()
        if not content:
            continue
        fields = content.split()
        if len(fields) >= 2 and fields[1] == MOUNT_POINT:
            matches.append(fields)
    return (
        len(matches) == 1
        and len(matches[0]) == 6
        and matches[0][0] == f"UUID={uuid_value}"
        and matches[0][2] == "xfs"
        and matches[0][3].split(",") == options
        and matches[0][4:] == ["0", "0"]
    )


def _raid_members() -> tuple[bool, set[str]]:
    raw = _run(
        [COMMANDS["mdadm"], "--detail", "--export", MD_DEVICE],
        allowed=(0, 1, 2),
    )
    values: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if separator and key and key not in values:
            values[key] = value
    state = values.get("MD_STATE", "").lower()
    level = values.get("MD_LEVEL", "").lower()
    degraded = values.get("MD_DEGRADED", "0")
    members = {
        value
        for key, value in values.items()
        if key.startswith("MD_DEVICE_") and value.startswith("/dev/")
    }
    return state in {"active", "clean"} and level in {
        "raid0",
        "0",
    } and degraded == "0", members


def _verify(expected: dict[str, Any]) -> dict[str, object]:
    status = {name: "unknown" for name in CHECKS}
    blockers: set[str] = set()
    provenance = {
        "device_set_digest": expected["prepare_device_set_digest"],
        "discovery_digest": expected["discovery_digest"],
        "inventory_digest": expected["inventory_digest"],
        "observation_digest": expected["observation_digest"],
        "policy_digest": expected["policy_digest"],
        "preparation_intent_digest": expected["preparation_intent_digest"],
    }
    if expected.get("selection_mode") == DEPLOY_SELECTION_MODE:
        provenance.update(
            {
                "preflight_evidence_digest": expected["preflight_evidence_digest"],
                "preparation_evidence_digest": (
                    expected["preparation_evidence_digest"]
                ),
            }
        )
    public_devices = sorted(
        [
            {
                "capacity_bytes": item["size_bytes"],
                "identity": item["identity"],
            }
            for item in expected["devices"]
        ],
        key=lambda item: item["identity"],
    )
    try:
        missing_tools = [
            name for name, path in COMMANDS.items() if not Path(path).is_file()
        ]
        status["tools"] = "failed" if missing_tools else "passed"
        if missing_tools:
            blockers.add("tool-evidence-unavailable")
            raise PostcheckError("required read-only storage tools are unavailable")

        topology = _lsblk()
        expected_paths = {item["path"] for item in expected["devices"]}
        selected = [topology.get(path) for path in sorted(expected_paths)]
        membership_ok = all(item is not None for item in selected)
        identity_ok = True
        for device in expected["devices"]:
            if (
                os.path.islink(device["path"])
                or os.path.realpath(device["path"]) != device["path"]
                or any(
                    os.path.realpath(path) != device["path"] for path in device["by_id"]
                )
            ):
                identity_ok = False
        status["device-membership"] = "passed" if membership_ok else "failed"
        if not membership_ok:
            blockers.add("device-membership-conflict")
        if not identity_ok:
            status["device-membership"] = "failed"
            blockers.add("device-identity-conflict")

        capacity_ok = membership_ok and all(
            item is not None and item.get("size") == expected_device["size_bytes"]
            for item, expected_device in zip(
                selected,
                sorted(expected["devices"], key=lambda value: value["path"]),
                strict=True,
            )
        )
        capacity_ok = (
            capacity_ok
            and sum(item["size_bytes"] for item in expected["devices"])
            >= expected["capacity_bytes"]
        )
        status["capacity"] = "passed" if capacity_ok else "failed"
        if not capacity_ok:
            blockers.add("capacity-conflict")

        target_path = (
            sorted(expected_paths)[0] if expected["layout"] == "single" else MD_DEVICE
        )
        target = topology.get(target_path)
        filesystem_ok = (
            target is not None
            and target.get("fstype") == "xfs"
            and isinstance(target.get("uuid"), str)
            and bool(target["uuid"])
        )
        status["filesystem"] = "passed" if filesystem_ok else "failed"
        if not filesystem_ok:
            blockers.add("filesystem-conflict")
            raise PostcheckError("filesystem evidence is unavailable")
        assert target is not None
        filesystem_uuid = target["uuid"]
        filesystem_uuid_digest = _digest(filesystem_uuid.encode("utf-8"))
        provenance["filesystem_uuid_digest"] = filesystem_uuid_digest
        if (
            expected["expected_filesystem_uuid_digest"] is not None
            and filesystem_uuid_digest != expected["expected_filesystem_uuid_digest"]
        ):
            status["filesystem"] = "failed"
            blockers.add("filesystem-conflict")

        raid_ok = True
        related_paths: set[str] = set()
        if expected["layout"] == "raid0":
            raid_ok, related_paths = _raid_members()
            raid_ok = raid_ok and related_paths == expected_paths
        status["raid"] = "passed" if raid_ok else "failed"
        if not raid_ok:
            blockers.add("raid-conflict")

        holders_ok = membership_ok and all(
            target_path
            in {
                path
                for path, value in topology.items()
                if device_path in value.get("_parents", ())
            }
            if expected["layout"] == "raid0"
            else not {
                path
                for path, value in topology.items()
                if device_path in value.get("_parents", ())
            }
            for device_path in expected_paths
        )
        status["holders"] = "passed" if holders_ok else "failed"
        if not holders_ok:
            blockers.add("holder-conflict")

        mount_membership_ok = all(
            sorted(
                item
                for item in (topology[path].get("mountpoints") or [])
                if isinstance(item, str)
            )
            == ([MOUNT_POINT] if expected["layout"] == "single" else [])
            for path in expected_paths
        )
        if not mount_membership_ok:
            status["device-membership"] = "failed"
            blockers.add("device-membership-conflict")

        signatures_ok = target.get("fstype") == "xfs" and (
            expected["layout"] == "single"
            or all(
                topology[path].get("fstype") in {"linux_raid_member", None}
                for path in expected_paths
            )
        )
        status["signatures"] = "passed" if signatures_ok else "failed"
        if not signatures_ok:
            blockers.add("signature-conflict")

        mount = _mount()
        options = sorted(set(str(mount.get("options", "")).split(",")))
        mount_ok = (
            mount.get("target") == MOUNT_POINT
            and mount.get("fstype") == "xfs"
            and mount.get("uuid") == filesystem_uuid
            and set(expected["mount_options"]) <= set(options)
            and os.path.realpath(str(mount.get("source", ""))) == target_path
        )
        status["mount"] = "passed" if mount_ok else "failed"
        if not mount_ok:
            blockers.add("mount-conflict")

        fstab_ok = _fstab(filesystem_uuid, expected["mount_options"])
        status["fstab"] = "passed" if fstab_ok else "failed"
        if not fstab_ok:
            blockers.add("fstab-conflict")

        info = os.stat(MOUNT_POINT, follow_symlinks=False)
        permission_ok = (
            stat.S_ISDIR(info.st_mode)
            and pwd.getpwuid(info.st_uid).pw_name == "root"
            and grp.getgrgid(info.st_gid).gr_name == "root"
            and stat.S_IMODE(info.st_mode) == 0o750
        )
        status["permissions"] = "passed" if permission_ok else "failed"
        if not permission_ok:
            blockers.add("permission-conflict")

        marker_data = MARKER_PATH.read_bytes()
        if len(marker_data) > 65536:
            raise PostcheckError("ownership marker is oversized")
        marker = json.loads(marker_data.decode("utf-8"))
        expected_marker = {
            "backend": expected["backend"],
            "cluster_uuid": expected["cluster_uuid"],
            "layout": expected["layout"],
            "logical_id": expected["logical_id"],
            "policy_digest": expected["policy_digest"],
            "preparation_intent_digest": expected["preparation_intent_digest"],
            "provider_id": expected["provider_id"],
            "schema_version": OWNER_SCHEMA,
            "stable_device_ids": [item["stable_id"] for item in expected["devices"]],
            "storage_generation": expected["storage_generation"],
        }
        marker_digest = _digest(marker_data)
        provenance["marker_digest"] = marker_digest
        marker_info = os.stat(MARKER_PATH, follow_symlinks=False)
        marker_ok = (
            marker == expected_marker
            and marker_data == _canonical_json(expected_marker) + b"\n"
            and stat.S_ISREG(marker_info.st_mode)
            and stat.S_IMODE(marker_info.st_mode) == 0o600
            and marker_info.st_nlink == 1
            and (
                expected["expected_marker_digest"] is None
                or marker_digest == expected["expected_marker_digest"]
            )
        )
        status["marker"] = "passed" if marker_ok else "failed"
        if not marker_ok:
            blockers.add("marker-conflict")
        status["provenance"] = "passed" if marker_ok else "failed"
        if not marker_ok:
            blockers.add("provenance-conflict")
    except (KeyError, OSError, PostcheckError, TypeError, UnicodeError, ValueError):
        blockers.add("verification-incomplete")

    readiness = not blockers and all(value == "passed" for value in status.values())
    return {
        "backend": expected["backend"],
        "blockers": sorted(blockers),
        "checks": [{"name": name, "status": status[name]} for name in sorted(status)],
        "devices": public_devices,
        "layout": expected["layout"],
        "logical_id": expected["logical_id"],
        "provenance": dict(sorted(provenance.items())),
        "readiness_for_scylla": readiness,
        "schema_version": SCHEMA,
    }


def main() -> None:
    module = AnsibleModule(
        argument_spec={"expected": {"type": "dict", "required": True}},
        supports_check_mode=True,
    )
    try:
        expected = _validate_expected(module.params["expected"])
        expected = _resolve_deploy_expected(expected)
        result = _verify(expected)
    except PostcheckError:
        result = {
            "backend": "unknown",
            "blockers": ["verification-incomplete"],
            "checks": [{"name": name, "status": "unknown"} for name in CHECKS],
            "devices": [],
            "layout": "unknown",
            "logical_id": "unknown",
            "provenance": {"failure_digest": _digest(b"postcheck-invalid-input")},
            "readiness_for_scylla": False,
            "schema_version": SCHEMA,
        }
    module.exit_json(changed=False, storage_postcheck_result=result)


if __name__ == "__main__":
    main()
