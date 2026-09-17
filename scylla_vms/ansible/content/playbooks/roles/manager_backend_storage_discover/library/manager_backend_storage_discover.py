#!/usr/bin/python
"""Read-only discovery for one exact Manager-local backend Block Volume."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from contextlib import suppress
from pathlib import Path
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-untyped]

SCHEMA = "deploy-scylla-vms.ansible-manager-backend-storage-discovery/v1"
MAX_OUTPUT = 1024 * 1024
COMMAND_TIMEOUT = 15
MARKER_MAX_BYTES = 16 * 1024
OWNERSHIP_MARKER = ".deploy-scylla-vms-storage.json"
NOT_PERFORMED = (
    "cql-access",
    "filesystem-creation",
    "fstab-write",
    "manager-configuration",
    "mount",
    "partition",
    "raid-creation",
    "service-mutation",
    "service-start",
    "storage-configuration",
    "storage-write",
    "wipe",
)
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


class DiscoveryError(Exception):
    pass


def _digest(value: Any) -> str:
    data = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


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
            shell=False,
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return 127, ""
    if (
        len(completed.stdout.encode("utf-8")) > MAX_OUTPUT
        or len(completed.stderr.encode("utf-8")) > MAX_OUTPUT
    ):
        return 126, ""
    return completed.returncode, completed.stdout


def _tool(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK)


def _by_id_links() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    try:
        entries = sorted(
            Path("/dev/disk/by-id").iterdir(),
            key=lambda value: value.name,
        )
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


def _source_names(target: str) -> set[str]:
    code, output = _run(
        ["/usr/bin/findmnt", "--json", "--output", "SOURCE", "--target", target]
    )
    if code != 0:
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


def _signatures(path: str) -> tuple[str, tuple[str, ...]]:
    if not _tool("/usr/sbin/wipefs") or not _tool("/usr/sbin/blkid"):
        return "unknown", ()
    found: set[str] = set()
    code, output = _run(["/usr/sbin/wipefs", "--json", "--noheadings", path])
    if code not in {0, 1}:
        return "unknown", ()
    if code == 0:
        try:
            for item in json.loads(output).get("signatures", []):
                if not isinstance(item, dict):
                    return "unknown", ()
                signature = item.get("type")
                usage = item.get("usage")
                if isinstance(signature, str) and signature:
                    found.add(
                        _digest(
                            {
                                "type": signature,
                                "usage": usage if isinstance(usage, str) else "unknown",
                            }
                        )
                    )
        except (ValueError, TypeError):
            return "unknown", ()
    code, output = _run(["/usr/sbin/blkid", "--probe", "--output", "export", path])
    if code not in {0, 2}:
        return "unknown", ()
    if code == 0:
        for line in output.splitlines()[:64]:
            key, separator, value = line.partition("=")
            if separator and value and key in {"TYPE", "PTTYPE"}:
                found.add(_digest({"kind": key, "value": value}))
    return ("present" if found else "absent"), tuple(sorted(found))


def _ownership(mounts: tuple[str, ...], payload: dict[str, Any]) -> str:
    markers: list[dict[str, Any]] = []
    unreadable = False
    for mount in mounts:
        marker = Path(mount) / OWNERSHIP_MARKER
        try:
            if not marker.exists():
                continue
            if not marker.is_file() or marker.is_symlink():
                unreadable = True
                continue
            data = marker.read_bytes()
            if not data or len(data) > MARKER_MAX_BYTES:
                unreadable = True
                continue
            value = json.loads(data.decode("utf-8", errors="strict"))
            if not isinstance(value, dict) or set(value) != MARKER_FIELDS:
                unreadable = True
                continue
            markers.append(value)
        except (OSError, UnicodeError, ValueError):
            unreadable = True
    if len(markers) > 1 or (markers and unreadable):
        return "foreign"
    if not markers:
        return "unknown" if unreadable else "unowned"
    marker_value = markers[0]
    if (
        marker_value.get("schema_version") == "deploy-scylla-vms.prepared-storage/v1"
        and marker_value.get("logical_id") == payload["logical_id"]
        and marker_value.get("backend") == "block-volume"
        and marker_value.get("layout") == "single"
        and marker_value.get("storage_generation") == payload["storage_generation"]
        and marker_value.get("policy_digest") == payload["storage_policy_digest"]
    ):
        return "manager-owned"
    return "foreign"


def _discover() -> dict[str, Any]:
    if not _tool("/usr/bin/lsblk") or not _tool("/usr/bin/findmnt"):
        raise DiscoveryError("required read-only storage tools are unavailable")
    code, output = _run(
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
    if code != 0:
        raise DiscoveryError("bounded block-device inspection failed")
    try:
        rows = json.loads(output).get("blockdevices", [])
    except (ValueError, TypeError) as error:
        raise DiscoveryError("bounded block-device evidence is malformed") from error
    if not isinstance(rows, list) or len(rows) > 512:
        raise DiscoveryError("bounded block-device evidence is invalid")
    links = _by_id_links()
    parents: dict[str, str | None] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise DiscoveryError("bounded block-device row is invalid")
        path = row.get("name")
        if not isinstance(path, str) or not path.startswith("/dev/"):
            continue
        parent = row.get("pkname")
        parents[Path(path).name] = (
            Path(parent).name if isinstance(parent, str) and parent else None
        )
    root = _ancestry(_source_names("/"), parents)
    boot = _ancestry(_source_names("/boot") | _source_names("/boot/efi"), parents)
    devices: list[dict[str, Any]] = []
    for row in rows:
        path = row.get("name")
        size = row.get("size")
        kind = row.get("type")
        if (
            not isinstance(path, str)
            or not path.startswith("/dev/")
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
            or not isinstance(kind, str)
        ):
            continue
        name = Path(path).name
        mounts = tuple(
            sorted(
                {
                    item
                    for item in (row.get("mountpoints") or [])
                    if isinstance(item, str) and item.startswith("/")
                }
            )
        )
        holder_names: list[str] = []
        with suppress(OSError):
            holder_names = sorted(
                item.name
                for item in (Path("/sys/class/block") / name / "holders").iterdir()
            )
        devices.append(
            {
                "boot_ancestor": name in boot,
                "by_id": tuple(sorted(links.get(path, []))),
                "holders": tuple(holder_names),
                "kind": kind,
                "mounts": mounts,
                "parent": parents.get(name),
                "path": path,
                "root_ancestor": name in root,
                "serial": row.get("serial")
                if isinstance(row.get("serial"), str)
                else None,
                "size_bytes": size,
                "transport": row.get("tran")
                if isinstance(row.get("tran"), str)
                else None,
                "wwn": row.get("wwn") if isinstance(row.get("wwn"), str) else None,
            }
        )
    return {"devices": devices}


def _matches(device: dict[str, Any], identities: dict[str, Any]) -> bool:
    checks = []
    expected_by_id = identities.get("expected_by_id")
    expected_serial = identities.get("expected_serial")
    expected_wwn = identities.get("expected_wwn")
    if expected_by_id is not None:
        checks.append(expected_by_id in device["by_id"])
    if expected_serial is not None:
        checks.append(expected_serial == device["serial"])
    if expected_wwn is not None:
        checks.append(expected_wwn == device["wwn"])
    return bool(checks) and all(checks)


def _evaluate(payload: dict[str, Any], discovery: dict[str, Any]) -> dict[str, Any]:
    _validate_payload(payload)
    devices = discovery.get("devices")
    if not isinstance(devices, list):
        raise DiscoveryError("bounded discovery evidence is invalid")
    matches = [
        item
        for item in devices
        if isinstance(item, dict) and _matches(item, payload["guest_identities"])
    ]
    blockers: set[str] = set()
    if not matches:
        blockers.add("device-not-found")
    elif len(matches) > 1:
        blockers.add("ambiguous-device-match")
    if len(matches) != 1:
        return _result_without_match(payload, blockers)

    device = matches[0]
    size_bytes = device["size_bytes"]
    size_gib = size_bytes // (1024**3)
    if size_bytes % (1024**3) or size_gib != payload["expected_size_gib"]:
        blockers.add("size-mismatch")
    device_type = device["kind"] if device["kind"] == "disk" else "unknown"
    if device_type != "disk":
        blockers.add("device-type-mismatch")
    root_status = (
        "conflict" if device["root_ancestor"] or device["boot_ancestor"] else "excluded"
    )
    if root_status == "conflict":
        blockers.add("root-or-boot-device")
    mount_status = "mounted" if device["mounts"] else "unmounted"
    if mount_status == "mounted":
        blockers.add("device-mounted")
    if device["holders"]:
        blockers.add("device-held")
    signature_status, signature_digests = _signatures(device["path"])
    if signature_status == "present":
        blockers.add("signature-present")
    elif signature_status == "unknown":
        blockers.add("manifest-conflict")
    ownership_status = _ownership(device["mounts"], payload)
    if ownership_status in {"foreign", "unknown"}:
        blockers.add("ownership-conflict")

    stable_projection = {
        "by_id": tuple(_digest(value) for value in device["by_id"]),
        "serial": _digest(device["serial"]) if device["serial"] else None,
        "wwn": _digest(device["wwn"]) if device["wwn"] else None,
    }
    topology = {
        "holders": tuple(_digest(value) for value in device["holders"]),
        "parent": _digest(device["parent"]) if device["parent"] else None,
        "signature_digests": signature_digests,
        "transport": device["transport"] or "unknown",
        "type": device["kind"],
    }
    return {
        "backend_type": "block-volume",
        "blockers": sorted(blockers),
        "capacity_evaluation_state": "not-evaluated",
        "capacity_policy_state": "unknown",
        "device_count": 1,
        "device_set_digest": _digest([stable_projection]),
        "device_type": device_type,
        "logical_id": payload["logical_id"],
        "manifest_digest": payload["manifest_digest"],
        "mount_status": mount_status,
        "not_performed": list(NOT_PERFORMED),
        "ownership_status": ownership_status,
        "provenance": payload["provenance"],
        "role": "manager",
        "root_status": root_status,
        "schema_version": SCHEMA,
        "signature_status": signature_status,
        "status": "blocked" if blockers else "discovered",
        "topology_digest": _digest(topology),
        "total_size_gib": size_gib,
    }


def _result_without_match(
    payload: dict[str, Any], blockers: set[str]
) -> dict[str, Any]:
    return {
        "backend_type": "block-volume",
        "blockers": sorted(blockers),
        "capacity_evaluation_state": "not-evaluated",
        "capacity_policy_state": "unknown",
        "device_count": 0,
        "device_set_digest": _digest([]),
        "device_type": "unknown",
        "logical_id": payload["logical_id"],
        "manifest_digest": payload["manifest_digest"],
        "mount_status": "unknown",
        "not_performed": list(NOT_PERFORMED),
        "ownership_status": "unknown",
        "provenance": payload["provenance"],
        "role": "manager",
        "root_status": "unknown",
        "schema_version": SCHEMA,
        "signature_status": "unknown",
        "status": "blocked",
        "topology_digest": _digest({"state": "unmatched"}),
        "total_size_gib": 0,
    }


def _validate_payload(payload: dict[str, Any]) -> None:
    fields = {
        "backend_type",
        "capacity_evaluation_state",
        "capacity_policy_state",
        "expected_device_count",
        "expected_size_gib",
        "guest_identities",
        "guest_identity_set_digest",
        "logical_id",
        "manifest_digest",
        "not_performed",
        "provenance",
        "role",
        "schema_version",
        "storage_generation",
        "storage_policy_digest",
    }
    identities = payload.get("guest_identities")
    provenance = payload.get("provenance")
    if (
        set(payload) != fields
        or payload.get("schema_version") != SCHEMA
        or payload.get("role") != "manager"
        or payload.get("backend_type") != "block-volume"
        or payload.get("expected_device_count") != 1
        or not isinstance(payload.get("expected_size_gib"), int)
        or isinstance(payload.get("expected_size_gib"), bool)
        or not 1 <= payload["expected_size_gib"] <= 1024 * 1024
        or not isinstance(payload.get("storage_generation"), int)
        or isinstance(payload.get("storage_generation"), bool)
        or payload["storage_generation"] < 1
        or payload.get("capacity_policy_state") != "unknown"
        or payload.get("capacity_evaluation_state") != "not-evaluated"
        or payload.get("not_performed") != list(NOT_PERFORMED)
        or not isinstance(identities, dict)
        or set(identities) != {"expected_by_id", "expected_serial", "expected_wwn"}
        or not any(value is not None for value in identities.values())
        or any(
            value is not None
            and (
                not isinstance(value, str)
                or not value
                or len(value) > 4096
                or "\0" in value
            )
            for value in identities.values()
        )
        or not isinstance(provenance, dict)
        or not provenance
        or not all(
            isinstance(key, str)
            and isinstance(value, str)
            and value.startswith("sha256:")
            and len(value) == 71
            for key, value in provenance.items()
        )
        or not isinstance(payload.get("logical_id"), str)
        or not payload["logical_id"]
        or any(
            not isinstance(payload.get(name), str)
            or not payload[name].startswith("sha256:")
            or len(payload[name]) != 71
            for name in (
                "guest_identity_set_digest",
                "manifest_digest",
                "storage_policy_digest",
            )
        )
    ):
        raise DiscoveryError("Manager backend storage discovery payload is invalid")


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={"payload": {"type": "dict", "required": True}},
        supports_check_mode=True,
    )
    payload = module.params["payload"]
    if not isinstance(payload, dict):
        module.fail_json(
            msg="Manager backend storage discovery input is invalid",
            blocker="discovery-failed",
        )
    try:
        result = _evaluate(payload, _discover())
    except DiscoveryError:
        module.fail_json(
            msg="Manager backend storage discovery could not establish bounded evidence",
            blocker="discovery-failed",
        )
    module.exit_json(changed=False, result=result)


if __name__ == "__main__":
    run_module()
