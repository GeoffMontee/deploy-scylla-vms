#!/usr/bin/python
"""Read-only preflight for one Manager-local backend Block Volume."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from contextlib import suppress
from pathlib import Path
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-untyped]

SCHEMA = "deploy-scylla-vms.ansible-manager-backend-storage-preflight/v1"
MOUNT_ROOT = "/var/lib/scylla"
MARKER_PATH = Path(MOUNT_ROOT) / ".deploy-scylla-vms-manager-backend-storage.json"
MARKER_SCHEMA = "deploy-scylla-vms.manager-backend-storage-marker/v1"
FSTAB_PATH = Path("/etc/fstab")
MAX_OUTPUT = 1024 * 1024
MAX_FILE = 64 * 1024
COMMAND_TIMEOUT = 15
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
    "setup",
    "storage-write",
    "tuning",
    "wipe",
)


class PreflightError(Exception):
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
        entries = sorted(Path("/dev/disk/by-id").iterdir(), key=lambda item: item.name)
    except OSError:
        return result
    for entry in entries[:1024]:
        try:
            if entry.is_symlink():
                result.setdefault(str(entry.resolve(strict=True)), []).append(
                    str(entry)
                )
        except OSError:
            continue
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


def _signature_state(path: str) -> str:
    if not _tool("/usr/sbin/wipefs") or not _tool("/usr/sbin/blkid"):
        return "unknown"
    wipe_code, wipe_output = _run(["/usr/sbin/wipefs", "--json", "--noheadings", path])
    if wipe_code not in {0, 1}:
        return "unknown"
    signatures = False
    if wipe_code == 0:
        try:
            values = json.loads(wipe_output).get("signatures", [])
            if not isinstance(values, list):
                return "unknown"
            signatures = bool(values)
        except (TypeError, ValueError):
            return "unknown"
    blkid_code, blkid_output = _run(
        ["/usr/sbin/blkid", "--probe", "--output", "export", path]
    )
    if blkid_code not in {0, 2}:
        return "unknown"
    if blkid_code == 0 and any(
        line.startswith(("TYPE=", "PTTYPE=")) for line in blkid_output.splitlines()[:64]
    ):
        signatures = True
    return "present" if signatures else "absent"


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        if path.is_symlink():
            return {}
        if not path.exists():
            return None
        if not path.is_file():
            return {}
        data = path.read_bytes()
        if not data or len(data) > MAX_FILE:
            return {}
        value = json.loads(data.decode("utf-8", errors="strict"))
        return value if isinstance(value, dict) else {}
    except (OSError, UnicodeError, ValueError):
        return {}


def _fstab_entries() -> tuple[tuple[str, str, str, tuple[str, ...]], ...] | None:
    try:
        if not FSTAB_PATH.is_file() or FSTAB_PATH.is_symlink():
            return None
        data = FSTAB_PATH.read_bytes()
        if len(data) > MAX_FILE:
            return None
        text = data.decode("utf-8", errors="strict")
    except (OSError, UnicodeError):
        return None
    entries: list[tuple[str, str, str, tuple[str, ...]]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) < 4:
            return None
        entries.append((fields[0], fields[1], fields[2], tuple(fields[3].split(","))))
    return tuple(entries)


def _inspect() -> dict[str, Any]:
    if not _tool("/usr/bin/lsblk") or not _tool("/usr/bin/findmnt"):
        raise PreflightError("required read-only storage tools are unavailable")
    code, output = _run(
        [
            "/usr/bin/lsblk",
            "--json",
            "--bytes",
            "--paths",
            "--list",
            "--output",
            "NAME,TYPE,SIZE,FSTYPE,UUID,MOUNTPOINTS,PKNAME,SERIAL,WWN,TRAN",
        ]
    )
    if code != 0:
        raise PreflightError("bounded block-device inspection failed")
    try:
        rows = json.loads(output).get("blockdevices", [])
    except (TypeError, ValueError) as error:
        raise PreflightError("bounded block-device evidence is malformed") from error
    if not isinstance(rows, list) or len(rows) > 512:
        raise PreflightError("bounded block-device evidence is invalid")
    links = _by_id_links()
    parents: dict[str, str | None] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise PreflightError("bounded block-device row is invalid")
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
        if not isinstance(row, dict):
            continue
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
        holders: tuple[str, ...] = ()
        with suppress(OSError):
            holders = tuple(
                sorted(
                    item.name
                    for item in (Path("/sys/class/block") / name / "holders").iterdir()
                )
            )
        children = tuple(
            sorted(child for child, parent in parents.items() if parent == name)
        )
        devices.append(
            {
                "boot_ancestor": name in boot,
                "by_id": tuple(sorted(links.get(path, []))),
                "children": children,
                "filesystem": (
                    row.get("fstype") if isinstance(row.get("fstype"), str) else None
                ),
                "filesystem_uuid": (
                    row.get("uuid") if isinstance(row.get("uuid"), str) else None
                ),
                "holders": holders,
                "kind": kind,
                "mounts": mounts,
                "path": path,
                "root_ancestor": name in root,
                "serial": (
                    row.get("serial") if isinstance(row.get("serial"), str) else None
                ),
                "size_bytes": size,
                "transport": (
                    row.get("tran") if isinstance(row.get("tran"), str) else None
                ),
                "wwn": row.get("wwn") if isinstance(row.get("wwn"), str) else None,
            }
        )
    return {
        "devices": devices,
        "fstab": _fstab_entries(),
        "marker": _read_json(MARKER_PATH),
    }


def _matches(device: dict[str, Any], identities: dict[str, Any]) -> bool:
    checks: list[bool] = []
    if identities.get("expected_by_id") is not None:
        checks.append(identities["expected_by_id"] in device["by_id"])
    if identities.get("expected_serial") is not None:
        checks.append(identities["expected_serial"] == device["serial"])
    if identities.get("expected_wwn") is not None:
        checks.append(identities["expected_wwn"] == device["wwn"])
    return bool(checks) and all(checks)


def _device_set_digest(device: dict[str, Any]) -> str:
    projection = {
        "by_id": tuple(_digest(value) for value in device["by_id"]),
        "serial": _digest(device["serial"]) if device["serial"] else None,
        "wwn": _digest(device["wwn"]) if device["wwn"] else None,
    }
    return _digest([projection])


def _expected_marker(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "backend": "block-volume",
        "device_set_digest": payload["discovery_device_set_digest"],
        "filesystem": "xfs",
        "layout": "single",
        "mount_boundary": "fixed-scylla-data-root",
        "preparation_intent_digest": payload["preparation_intent_digest"],
        "role_marker": payload["role_marker"],
        "schema_version": MARKER_SCHEMA,
        "size_gib": payload["observed_size_gib"],
        "stable_id": payload["stable_id"],
        "storage_generation": payload["storage_generation"],
        "storage_policy_digest": payload["storage_policy_digest"],
    }


def _evaluate(payload: dict[str, Any], facts: dict[str, Any]) -> dict[str, Any]:
    _validate_payload(payload)
    devices = facts.get("devices")
    if not isinstance(devices, list):
        raise PreflightError("bounded preflight device evidence is invalid")
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
        return _result(
            payload,
            disposition="blocked",
            actions=(),
            wipe_required=False,
            device_count=0,
            device_size_gib=0,
            signature_state="unknown",
            ownership_state="unknown",
            mount_state="unknown",
            fstab_state="unknown",
            marker_state="unknown",
            partition_present=False,
            raid_present=False,
            device_set_digest=_digest([]),
            blockers=blockers,
        )
    device = matches[0]
    size_bytes = device["size_bytes"]
    size_gib = size_bytes // (1024**3)
    if size_bytes % (1024**3) or size_gib != payload["observed_size_gib"]:
        blockers.add("device-size-conflict")
    if device["kind"] != "disk" or device["transport"] == "nvme":
        blockers.add("device-type-conflict")
    if device["root_ancestor"] or device["boot_ancestor"] or device["children"]:
        blockers.add(
            "root-or-boot-device"
            if device["root_ancestor"] or device["boot_ancestor"]
            else "device-topology-conflict"
        )
    raid_present = bool(device["holders"])
    if raid_present:
        blockers.add("device-busy")
    partition_present = bool(device["children"])
    device_set_digest = _device_set_digest(device)
    if device_set_digest != payload["discovery_device_set_digest"]:
        blockers.add("identity-conflict")
    signature = _signature_state(device["path"])
    if signature == "unknown":
        blockers.add("signature-evidence-unavailable")

    mounts = tuple(device["mounts"])
    if not mounts:
        mount_state = "unmounted"
    elif mounts == (MOUNT_ROOT,):
        mount_state = "expected-mounted"
    else:
        mount_state = "conflict"
        blockers.add("mount-conflict")

    fstab = facts.get("fstab")
    if fstab is None:
        fstab_state = "unknown"
        blockers.add("fstab-conflict")
    else:
        entries = [item for item in fstab if item[1] == MOUNT_ROOT]
        if not entries:
            fstab_state = "absent"
        elif (
            len(entries) == 1
            and device["filesystem_uuid"] is not None
            and entries[0][0] == f"UUID={device['filesystem_uuid']}"
            and entries[0][2] == "xfs"
            and {"defaults", "nofail"}.issubset(set(entries[0][3]))
        ):
            fstab_state = "expected"
        else:
            fstab_state = "conflict"
            blockers.add("fstab-conflict")

    marker = facts.get("marker")
    if marker is None:
        marker_state = "absent"
        ownership_state = "unowned"
    elif marker == _expected_marker(payload):
        marker_state = "expected"
        ownership_state = "manager-owned"
    else:
        marker_state = "foreign"
        ownership_state = "foreign"
        blockers.add("foreign-ownership")

    if ownership_state == "manager-owned":
        if not (
            signature == "present"
            and device.get("filesystem") == "xfs"
            and mount_state == "expected-mounted"
            and fstab_state == "expected"
            and not partition_present
            and not raid_present
        ):
            blockers.add("owned-layout-conflict")
        disposition = "owned-noop" if not blockers else "blocked"
        actions: tuple[str, ...] = ()
        wipe_required = False
    elif ownership_state == "unowned" and signature == "present":
        disposition = "blocked"
        actions = ()
        wipe_required = True
        blockers.add("foreign-signature")
    elif blockers:
        disposition = "blocked"
        actions = ()
        wipe_required = False
    elif mount_state != "unmounted" or fstab_state != "absent":
        disposition = "blocked"
        actions = ()
        wipe_required = False
        blockers.add(
            "mount-conflict" if mount_state != "unmounted" else "fstab-conflict"
        )
    else:
        disposition = "prepare-required"
        wipe_required = False
        actions = tuple(payload["preparation_actions"])
    return _result(
        payload,
        disposition=disposition,
        actions=actions,
        wipe_required=wipe_required,
        device_count=1,
        device_size_gib=size_gib,
        signature_state=signature,
        ownership_state=ownership_state,
        mount_state=mount_state,
        fstab_state=fstab_state,
        marker_state=marker_state,
        partition_present=partition_present,
        raid_present=raid_present,
        device_set_digest=device_set_digest,
        blockers=blockers,
    )


def _result(
    payload: dict[str, Any],
    *,
    disposition: str,
    actions: tuple[str, ...],
    wipe_required: bool,
    device_count: int,
    device_size_gib: int,
    signature_state: str,
    ownership_state: str,
    mount_state: str,
    fstab_state: str,
    marker_state: str,
    partition_present: bool,
    raid_present: bool,
    device_set_digest: str,
    blockers: set[str],
) -> dict[str, Any]:
    sorted_blockers = sorted(blockers)
    return {
        "actions": list(actions),
        "backend": "block-volume",
        "blocker_digest": _digest(sorted_blockers),
        "blockers": sorted_blockers,
        "capacity_policy_state": payload["capacity_policy_state"],
        "capacity_sufficiency_state": payload["capacity_sufficiency_state"],
        "device_count": device_count,
        "device_set_digest": device_set_digest,
        "device_size_gib": device_size_gib,
        "disposition": disposition,
        "filesystem": "xfs",
        "fstab_state": fstab_state,
        "layout": "single",
        "mount_boundary": "fixed-scylla-data-root",
        "mount_state": mount_state,
        "not_performed": list(NOT_PERFORMED),
        "observed_size_gib": payload["observed_size_gib"],
        "ownership_state": ownership_state,
        "partition_present": partition_present,
        "preparation_intent_digest": payload["preparation_intent_digest"],
        "provenance_digest": _digest(payload["provenance"]),
        "raid_present": raid_present,
        "requested_size_gib": payload["requested_size_gib"],
        "role": "manager",
        "role_marker_state": marker_state,
        "schema_version": SCHEMA,
        "signature_state": signature_state,
        "stable_id": payload["stable_id"],
        "wipe_required": wipe_required,
    }


def _validate_payload(payload: dict[str, Any]) -> None:
    fields = {
        "backend",
        "capacity_policy_state",
        "capacity_sufficiency_state",
        "discovery_device_set_digest",
        "expected_device_count",
        "filesystem",
        "guest_identities",
        "layout",
        "manifest_digest",
        "mount_boundary",
        "not_performed",
        "observed_size_gib",
        "preparation_actions",
        "preparation_intent_digest",
        "provenance",
        "provenance_digest",
        "requested_size_gib",
        "role",
        "role_marker",
        "schema_version",
        "stable_id",
        "storage_generation",
        "storage_policy_digest",
    }
    identities = payload.get("guest_identities")
    provenance = payload.get("provenance")
    digests = (
        "discovery_device_set_digest",
        "manifest_digest",
        "preparation_intent_digest",
        "provenance_digest",
        "storage_policy_digest",
    )
    if (
        set(payload) != fields
        or payload.get("schema_version") != SCHEMA
        or payload.get("role") != "manager"
        or payload.get("backend") != "block-volume"
        or payload.get("layout") != "single"
        or payload.get("filesystem") != "xfs"
        or payload.get("mount_boundary") != "fixed-scylla-data-root"
        or payload.get("role_marker") != "manager-local-one-node-backend"
        or payload.get("capacity_policy_state")
        != "operator-selected-allocation-conformance"
        or payload.get("capacity_sufficiency_state") != "not-proven"
        or payload.get("expected_device_count") != 1
        or payload.get("preparation_actions")
        != [
            "create-xfs",
            "mount-scylla-data-root",
            "write-fstab",
            "write-manager-one-node-marker",
        ]
        or payload.get("not_performed") != list(NOT_PERFORMED)
        or not isinstance(payload.get("requested_size_gib"), int)
        or isinstance(payload.get("requested_size_gib"), bool)
        or not isinstance(payload.get("observed_size_gib"), int)
        or isinstance(payload.get("observed_size_gib"), bool)
        or payload["requested_size_gib"] != payload["observed_size_gib"]
        or not 1 <= payload["requested_size_gib"] <= 1024 * 1024
        or not isinstance(payload.get("storage_generation"), int)
        or isinstance(payload.get("storage_generation"), bool)
        or payload["storage_generation"] < 1
        or not isinstance(payload.get("stable_id"), str)
        or not payload["stable_id"]
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
        or any(
            not isinstance(payload.get(name), str)
            or not payload[name].startswith("sha256:")
            or len(payload[name]) != 71
            for name in digests
        )
        or not isinstance(provenance, dict)
        or not provenance
        or payload["provenance_digest"] != _digest(provenance)
        or not all(
            isinstance(key, str)
            and isinstance(value, str)
            and value.startswith("sha256:")
            and len(value) == 71
            for key, value in provenance.items()
        )
    ):
        raise PreflightError("Manager backend storage preflight payload is invalid")


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={"payload": {"type": "dict", "required": True}},
        supports_check_mode=True,
    )
    payload = module.params["payload"]
    if not isinstance(payload, dict):
        module.fail_json(msg="Manager backend storage preflight input is invalid")
    try:
        result = _evaluate(payload, _inspect())
    except PreflightError:
        module.fail_json(
            msg="Manager backend storage preflight could not establish bounded evidence"
        )
    module.exit_json(changed=False, result=result)


if __name__ == "__main__":
    run_module()
