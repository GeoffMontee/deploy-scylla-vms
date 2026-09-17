#!/usr/bin/python
"""Read-only bounded storage discovery for deploy-scylla-vms."""

from __future__ import annotations

import json
import os
import re
import subprocess
from contextlib import suppress
from pathlib import Path
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-untyped]

MAX_OUTPUT = 1024 * 1024
COMMAND_TIMEOUT = 15
MARKER_MAX_BYTES = 16 * 1024
MARKER_FIELDS = {
    "backend",
    "cluster_uuid",
    "layout",
    "logical_id",
    "policy_digest",
    "preparation_intent_digest",
    "provider_id",
    "schema_version",
    "stable_device_ids",
    "storage_generation",
}


def _run(argv: list[str]) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=COMMAND_TIMEOUT,
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return 127, ""
    if len(completed.stdout.encode("utf-8")) > MAX_OUTPUT:
        return 126, ""
    return completed.returncode, completed.stdout


def _tool(path: str) -> str:
    return (
        "available"
        if os.path.isfile(path) and os.access(path, os.X_OK)
        else "unavailable"
    )


def _by_id_links() -> dict[str, list[str]]:
    root = Path("/dev/disk/by-id")
    result: dict[str, list[str]] = {}
    try:
        entries = sorted(root.iterdir(), key=lambda value: value.name)
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


def _provider_links() -> dict[str, list[str]]:
    root = Path("/dev/oracleoci")
    result: dict[str, list[str]] = {}
    try:
        entries = sorted(root.iterdir(), key=lambda value: value.name)
    except OSError:
        return result
    for entry in entries[:256]:
        try:
            if not entry.is_symlink():
                continue
            target = str(entry.resolve(strict=True))
        except OSError:
            continue
        result.setdefault(target, []).append(f"oracleoci:{entry.name}")
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


def _source_names(target: str) -> set[str]:
    rc, output = _run(
        ["/usr/bin/findmnt", "--json", "--output", "SOURCE", "--target", target]
    )
    if rc != 0:
        return set()
    try:
        filesystems = json.loads(output).get("filesystems", [])
        return {
            Path(item["source"]).name
            for item in filesystems
            if isinstance(item, dict)
            and isinstance(item.get("source"), str)
            and item["source"].startswith("/dev/")
        }
    except (ValueError, TypeError, KeyError):
        return set()


def _ancestry(names: set[str], parents: dict[str, str | None]) -> set[str]:
    result = set(names)
    pending = list(names)
    while pending:
        parent = parents.get(pending.pop())
        if parent and parent not in result:
            result.add(parent)
            pending.append(parent)
    return result


def _signatures(path: str) -> list[dict[str, str]]:
    rc, output = _run(["/usr/sbin/wipefs", "--json", "--noheadings", path])
    found: set[tuple[str, str]] = set()
    if rc == 0:
        try:
            for item in json.loads(output).get("signatures", []):
                signature = str(item.get("type", "")).strip()
                usage = str(item.get("usage", "")).strip().lower()
                if not signature:
                    continue
                kind = (
                    "filesystem"
                    if usage == "filesystem"
                    else "partition-table"
                    if usage == "partition table"
                    else "raid"
                    if "raid" in usage
                    else "lvm"
                    if "lvm" in signature.lower()
                    else "filesystem"
                )
                found.add((kind, signature))
        except (ValueError, TypeError, AttributeError):
            pass
    rc, output = _run(["/usr/sbin/blkid", "--probe", "--output", "export", path])
    if rc == 0:
        for line in output.splitlines()[:64]:
            key, separator, value = line.partition("=")
            if not separator or not value:
                continue
            if key == "TYPE":
                found.add(("filesystem", value))
            elif key == "PTTYPE":
                found.add(("partition-table", value))
    return [{"kind": kind, "value": value} for kind, value in sorted(found)]


def _nvme(path: str, row: dict[str, Any]) -> dict[str, Any] | None:
    if row.get("tran") != "nvme":
        return None
    match = re.fullmatch(r"(/dev/nvme[0-9]+)n([0-9]+)(?:p[0-9]+)?", path)
    if match is None:
        return None
    controller = match.group(1)
    namespace_path = f"{controller}n{match.group(2)}"
    rc_ctrl, ctrl = _run(
        ["/usr/sbin/nvme", "id-ctrl", "--output-format=json", controller]
    )
    rc_ns, namespace = _run(
        ["/usr/sbin/nvme", "id-ns", "--output-format=json", namespace_path]
    )
    ctrl_value: dict[str, Any] = {}
    namespace_value: dict[str, Any] = {}
    try:
        if rc_ctrl == 0:
            ctrl_value = json.loads(ctrl)
        if rc_ns == 0:
            namespace_value = json.loads(namespace)
    except (ValueError, TypeError):
        return None
    capabilities = []
    if ctrl_value.get("vwc") not in (None, 0):
        capabilities.append("volatile-write-cache")
    if namespace_value.get("nsfeat") not in (None, 0):
        capabilities.append("namespace-features")
    return {
        "capabilities": sorted(capabilities),
        "model": ctrl_value.get("mn")
        if isinstance(ctrl_value.get("mn"), str)
        else None,
        "namespace_id": namespace_value.get("nsid")
        if isinstance(namespace_value.get("nsid"), int) and namespace_value["nsid"] > 0
        else None,
        "serial": ctrl_value.get("sn")
        if isinstance(ctrl_value.get("sn"), str)
        else None,
    }


def _ownership_marker(mounts: list[str], marker_name: str) -> tuple[str, Any]:
    found: list[dict[str, Any]] = []
    unavailable = False
    for mount in mounts:
        marker = Path(mount) / marker_name
        try:
            if not marker.is_file() or marker.is_symlink():
                continue
            data = marker.read_bytes()
            if not data or len(data) > MARKER_MAX_BYTES:
                unavailable = True
                continue
            value = json.loads(data.decode("utf-8", errors="strict"))
            if (
                not isinstance(value, dict)
                or set(value) != MARKER_FIELDS
                or value.get("schema_version")
                != "deploy-scylla-vms.prepared-storage/v1"
            ):
                unavailable = True
                continue
            found.append(value)
        except (OSError, UnicodeError, ValueError):
            unavailable = True
    if len(found) == 1:
        return "present", found[0]
    if found or unavailable:
        return "unavailable", None
    return "absent", None


def _discover(marker_name: str) -> dict[str, Any]:
    tools = {
        "blkid": _tool("/usr/sbin/blkid"),
        "by-id": "available" if Path("/dev/disk/by-id").is_dir() else "unavailable",
        "findmnt": _tool("/usr/bin/findmnt"),
        "lsblk": _tool("/usr/bin/lsblk"),
        "lvm": _tool("/usr/sbin/lvs"),
        "md": _tool("/usr/sbin/mdadm"),
        "nvme": _tool("/usr/sbin/nvme"),
        "wipefs": _tool("/usr/sbin/wipefs"),
    }
    if tools["lsblk"] != "available":
        return {"devices": [], "mounts": [], "tools": tools}
    rc, output = _run(
        [
            "/usr/bin/lsblk",
            "--json",
            "--bytes",
            "--paths",
            "--list",
            "--output",
            "NAME,TYPE,SIZE,TRAN,FSTYPE,MOUNTPOINTS,PKNAME,SERIAL,WWN",
        ]
    )
    if rc != 0:
        tools["lsblk"] = "unavailable"
        return {"devices": [], "mounts": [], "tools": tools}
    try:
        rows = json.loads(output).get("blockdevices", [])
    except (ValueError, TypeError):
        tools["lsblk"] = "unavailable"
        return {"devices": [], "mounts": [], "tools": tools}
    links = _by_id_links()
    provider_links = _provider_links()
    stable: dict[str, str] = {}
    parents: dict[str, str | None] = {}
    bounded_rows = [row for row in rows[:512] if isinstance(row, dict)]
    for row in bounded_rows:
        path = row.get("name")
        if not isinstance(path, str) or not path.startswith("/dev/"):
            continue
        identifier = _stable_id(row, links.get(path, []))
        if identifier is not None:
            stable[Path(path).name] = identifier
        parent = row.get("pkname")
        parents[Path(path).name] = (
            Path(parent).name if isinstance(parent, str) and parent else None
        )
    root = _ancestry(_source_names("/"), parents)
    boot = _ancestry(_source_names("/boot") | _source_names("/boot/efi"), parents)
    devices: list[dict[str, Any]] = []
    mounts: set[str] = set()
    for row in bounded_rows:
        path = row.get("name")
        if not isinstance(path, str) or not path.startswith("/dev/"):
            continue
        name = Path(path).name
        identifier = stable.get(name)
        size = row.get("size")
        kind = row.get("type")
        if (
            identifier is None
            or not isinstance(size, int)
            or size <= 0
            or kind not in {"crypt", "disk", "lvm", "mpath", "part", "raid"}
        ):
            continue
        row_mounts = sorted(
            {
                mount
                for mount in (row.get("mountpoints") or [])
                if isinstance(mount, str) and mount.startswith("/")
            }
        )
        mounts.update(row_mounts)
        parent = parents.get(name)
        holder_names: list[str] = []
        with suppress(OSError):
            holder_names = sorted(
                item.name
                for item in (Path("/sys/class/block") / name / "holders").iterdir()
            )
        marker, ownership = _ownership_marker(row_mounts, marker_name)
        devices.append(
            {
                "boot_ancestor": name in boot,
                "by_id": sorted(links.get(path, [])),
                "filesystem": row.get("fstype")
                if isinstance(row.get("fstype"), str)
                else None,
                "holders": sorted(
                    stable[item] for item in holder_names if item in stable
                ),
                "kind": kind,
                "mount_points": row_mounts,
                "nvme": _nvme(path, row) if tools["nvme"] == "available" else None,
                "ownership_marker": marker,
                "ownership": ownership,
                "parents": [stable[parent]] if parent in stable else [],
                "path": path,
                "provider_attachment_ids": sorted(provider_links.get(path, [])),
                "root_ancestor": name in root,
                "serial": row.get("serial")
                if isinstance(row.get("serial"), str)
                else None,
                "signatures": _signatures(path)
                if tools["wipefs"] == "available"
                else [],
                "size_bytes": size,
                "stable_id": identifier,
                "transport": row.get("tran")
                if isinstance(row.get("tran"), str)
                else None,
                "wwn": row.get("wwn") if isinstance(row.get("wwn"), str) else None,
            }
        )
    devices.sort(key=lambda item: item["stable_id"])
    return {"devices": devices[:256], "mounts": sorted(mounts), "tools": tools}


def main() -> None:
    module = AnsibleModule(
        argument_spec={"ownership_marker_name": {"type": "str", "required": True}},
        supports_check_mode=True,
    )
    marker_name = module.params["ownership_marker_name"]
    if marker_name != ".deploy-scylla-vms-storage.json":
        module.fail_json(msg="unsupported ownership marker")
    module.exit_json(changed=False, **_discover(marker_name))


if __name__ == "__main__":
    main()
