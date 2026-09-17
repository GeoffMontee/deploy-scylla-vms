#!/usr/bin/python
"""Prepare one exact Manager-local backend Block Volume."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-untyped]

SCHEMA = "deploy-scylla-vms.ansible-manager-backend-storage-prepare/v1"
MARKER_SCHEMA = "deploy-scylla-vms.manager-backend-storage-marker/v1"
MOUNT_ROOT = Path("/var/lib/scylla")
MARKER_PATH = MOUNT_ROOT / ".deploy-scylla-vms-manager-backend-storage.json"
FSTAB_PATH = Path("/etc/fstab")
COMMAND_TIMEOUT = 30
MAX_OUTPUT = 1024 * 1024
MAX_FILE = 64 * 1024
NOT_PERFORMED = (
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


class PreparationError(Exception):
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


def _run(argv: list[str], *, allowed: tuple[int, ...] = (0,)) -> str:
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
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise PreparationError("fixed storage command execution failed") from error
    if (
        completed.returncode not in allowed
        or len(completed.stdout.encode("utf-8")) > MAX_OUTPUT
        or len(completed.stderr.encode("utf-8")) > MAX_OUTPUT
    ):
        raise PreparationError("fixed storage command returned invalid evidence")
    return completed.stdout


def _tool(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK)


def _is_block_device(path: str) -> bool:
    try:
        return stat.S_ISBLK(os.stat(path, follow_symlinks=False).st_mode)
    except OSError:
        return False


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
    output = _run(
        ["/usr/bin/findmnt", "--json", "--output", "SOURCE", "--target", target],
        allowed=(0, 1),
    )
    if not output.strip():
        return set()
    try:
        values = json.loads(output).get("filesystems", [])
        return {
            Path(item["source"]).name
            for item in values
            if isinstance(item, dict)
            and isinstance(item.get("source"), str)
            and item["source"].startswith("/dev/")
        }
    except (KeyError, TypeError, ValueError) as error:
        raise PreparationError("mount ancestry evidence is malformed") from error


def _ancestry(names: set[str], parents: dict[str, str | None]) -> set[str]:
    result = set(names)
    pending = list(names)
    while pending:
        parent = parents.get(pending.pop())
        if parent and parent not in result:
            result.add(parent)
            pending.append(parent)
    return result


def _signatures(path: str) -> tuple[tuple[str, str], ...]:
    wipe_output = _run(
        ["/usr/sbin/wipefs", "--json", "--noheadings", path],
        allowed=(0, 1),
    )
    signatures: set[tuple[str, str]] = set()
    try:
        values = json.loads(wipe_output).get("signatures", []) if wipe_output else []
    except (AttributeError, TypeError, ValueError) as error:
        raise PreparationError("signature evidence is malformed") from error
    if not isinstance(values, list):
        raise PreparationError("signature evidence is malformed")
    for item in values:
        if not isinstance(item, dict):
            raise PreparationError("signature evidence is malformed")
        kind = item.get("type")
        usage = item.get("usage")
        if not isinstance(kind, str) or not kind:
            raise PreparationError("signature evidence is malformed")
        signatures.add((str(usage or "unknown"), kind))
    blkid = _run(
        ["/usr/sbin/blkid", "--probe", "--output", "export", path],
        allowed=(0, 2),
    )
    for line in blkid.splitlines()[:64]:
        key, separator, value = line.partition("=")
        if separator and value and key in {"TYPE", "PTTYPE"}:
            signatures.add((key.lower(), value))
    return tuple(sorted(signatures))


def _fstab_entries() -> tuple[tuple[str, str, str, tuple[str, ...]], ...]:
    try:
        if FSTAB_PATH.is_symlink() or not FSTAB_PATH.is_file():
            raise PreparationError("fstab is unavailable or unsafe")
        data = FSTAB_PATH.read_bytes()
        if len(data) > MAX_FILE:
            raise PreparationError("fstab exceeds the bounded input limit")
        text = data.decode("utf-8", errors="strict")
    except (OSError, UnicodeError) as error:
        raise PreparationError("fstab cannot be read safely") from error
    entries: list[tuple[str, str, str, tuple[str, ...]]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) < 4:
            raise PreparationError("fstab contains an invalid record")
        entries.append((fields[0], fields[1], fields[2], tuple(fields[3].split(","))))
    return tuple(entries)


def _inspect() -> dict[str, Any]:
    for tool in (
        "/usr/bin/findmnt",
        "/usr/bin/lsblk",
        "/usr/bin/mount",
        "/usr/sbin/blkid",
        "/usr/sbin/mkfs.xfs",
        "/usr/sbin/wipefs",
    ):
        if not _tool(tool):
            raise PreparationError("required fixed storage tool is unavailable")
    output = _run(
        [
            "/usr/bin/lsblk",
            "--json",
            "--bytes",
            "--paths",
            "--list",
            "--output",
            "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,PKNAME,SERIAL,WWN,TRAN",
        ]
    )
    try:
        rows = json.loads(output).get("blockdevices", [])
    except (AttributeError, TypeError, ValueError) as error:
        raise PreparationError("block-device evidence is malformed") from error
    if not isinstance(rows, list) or len(rows) > 512:
        raise PreparationError("block-device evidence is invalid")
    parents: dict[str, str | None] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise PreparationError("block-device row is invalid")
        path = row.get("name")
        if isinstance(path, str) and path.startswith("/dev/"):
            parent = row.get("pkname")
            parents[Path(path).name] = (
                Path(parent).name if isinstance(parent, str) and parent else None
            )
    root = _ancestry(_source_names("/"), parents)
    boot = _ancestry(_source_names("/boot") | _source_names("/boot/efi"), parents)
    links = _by_id_links()
    devices: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        path = row.get("name")
        size = row.get("size")
        if (
            not isinstance(path, str)
            or not path.startswith("/dev/")
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
        ):
            continue
        name = Path(path).name
        holders: tuple[str, ...] = ()
        try:
            holders = tuple(
                sorted(
                    item.name
                    for item in (Path("/sys/class/block") / name / "holders").iterdir()
                )
            )
        except OSError as error:
            raise PreparationError("holder evidence is unavailable") from error
        devices.append(
            {
                "boot_ancestor": name in boot,
                "by_id": tuple(sorted(links.get(path, []))),
                "children": tuple(
                    sorted(child for child, parent in parents.items() if parent == name)
                ),
                "filesystem": (
                    row.get("fstype") if isinstance(row.get("fstype"), str) else None
                ),
                "holders": holders,
                "kind": row.get("type"),
                "mounts": tuple(
                    sorted(
                        item
                        for item in (row.get("mountpoints") or [])
                        if isinstance(item, str)
                    )
                ),
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
    return {"devices": devices, "fstab": _fstab_entries()}


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
    return _digest(
        [
            {
                "by_id": tuple(_digest(value) for value in device["by_id"]),
                "serial": _digest(device["serial"]) if device["serial"] else None,
                "wwn": _digest(device["wwn"]) if device["wwn"] else None,
            }
        ]
    )


def _validate_payload(payload: dict[str, Any]) -> None:
    fields = {
        "action",
        "authorization",
        "backend",
        "capacity_policy_binding",
        "capacity_sufficiency_state",
        "check_mode_requested",
        "cluster_uuid",
        "device_count",
        "discovered_size_gib",
        "disposition",
        "filesystem",
        "guest_identities",
        "layout",
        "mount_boundary",
        "not_performed",
        "observed_size_gib",
        "provenance",
        "provenance_digest",
        "requested_size_gib",
        "role",
        "schema_version",
        "stable_id",
        "storage_generation",
        "storage_policy_digest",
    }
    authorization = payload.get("authorization")
    identities = payload.get("guest_identities")
    provenance = payload.get("provenance")
    sizes = (
        payload.get("requested_size_gib"),
        payload.get("observed_size_gib"),
        payload.get("discovered_size_gib"),
    )
    if (
        set(payload) != fields
        or payload.get("schema_version") != SCHEMA
        or payload.get("action") != "prepare-required"
        or payload.get("disposition") != "prepare-required"
        or payload.get("role") != "manager"
        or payload.get("backend") != "block-volume"
        or payload.get("layout") != "single"
        or payload.get("filesystem") != "xfs"
        or payload.get("mount_boundary") != "fixed-scylla-data-root"
        or payload.get("capacity_policy_binding")
        != "operator-selected-allocation-conformance"
        or payload.get("capacity_sufficiency_state") != "not-proven"
        or payload.get("check_mode_requested") is not False
        or payload.get("device_count") != 1
        or payload.get("not_performed") != list(NOT_PERFORMED)
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in sizes
        )
        or len(set(sizes)) != 1
        or not isinstance(authorization, dict)
        or set(authorization)
        != {
            "device_set_digest",
            "operation_id",
            "preparation_approved",
            "preparation_intent_digest",
            "preparation_scope_digest",
            "wipe_approved",
            "wipe_scope_digest",
        }
        or authorization.get("preparation_approved") is not True
        or not isinstance(authorization.get("wipe_approved"), bool)
        or (
            authorization["wipe_approved"]
            != (authorization.get("wipe_scope_digest") is not None)
        )
        or not isinstance(identities, dict)
        or set(identities) != {"expected_by_id", "expected_serial", "expected_wwn"}
        or not any(value is not None for value in identities.values())
        or not isinstance(provenance, dict)
        or not provenance
        or payload.get("provenance_digest") != _digest(provenance)
    ):
        raise PreparationError("Manager backend storage preparation payload is invalid")
    for value in (
        authorization["device_set_digest"],
        authorization["preparation_intent_digest"],
        authorization["preparation_scope_digest"],
        payload["provenance_digest"],
        payload["storage_policy_digest"],
    ):
        if (
            not isinstance(value, str)
            or len(value) != 71
            or not value.startswith("sha256:")
        ):
            raise PreparationError(
                "Manager backend storage preparation digest is invalid"
            )


def _revalidate(payload: dict[str, Any], facts: dict[str, Any]) -> dict[str, Any]:
    _validate_payload(payload)
    devices = facts.get("devices")
    fstab = facts.get("fstab")
    if not isinstance(devices, list) or not isinstance(fstab, tuple):
        raise PreparationError("immediate storage evidence is invalid")
    matches = [
        item
        for item in devices
        if isinstance(item, dict) and _matches(item, payload["guest_identities"])
    ]
    if len(matches) != 1:
        raise PreparationError("exact Manager backend device identity is ambiguous")
    device = matches[0]
    path = device.get("path")
    expected_bytes = payload["observed_size_gib"] * 1024**3
    if (
        not isinstance(path, str)
        or not path.startswith("/dev/")
        or os.path.islink(path)
        or os.path.realpath(path) != path
        or not _is_block_device(path)
        or device.get("kind") != "disk"
        or device.get("transport") == "nvme"
        or device.get("size_bytes") != expected_bytes
        or device.get("root_ancestor")
        or device.get("boot_ancestor")
        or device.get("children")
        or device.get("holders")
        or device.get("mounts")
        or device.get("filesystem") is not None
        or any(entry[1] == str(MOUNT_ROOT) for entry in fstab)
        or MARKER_PATH.exists()
        or _device_set_digest(device) != payload["authorization"]["device_set_digest"]
    ):
        raise PreparationError(
            "immediate Manager backend device evidence conflicts with authorization"
        )
    signatures = _signatures(path)
    wipe_approved = payload["authorization"]["wipe_approved"]
    if bool(signatures) != wipe_approved:
        raise PreparationError(
            "immediate signature evidence conflicts with separate wipe consent"
        )
    return {"path": path, "signatures": signatures}


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


def _write_fstab(filesystem_uuid: str) -> None:
    data = FSTAB_PATH.read_bytes()
    if len(data) > MAX_FILE:
        raise PreparationError("fstab exceeds the bounded input limit")
    text = data.decode("utf-8", errors="strict")
    if any(
        line.split()[1] == str(MOUNT_ROOT)
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#") and len(line.split()) >= 2
    ):
        raise PreparationError("Manager backend mount already exists in fstab")
    prefix = "" if not text or text.endswith("\n") else "\n"
    line = f"UUID={filesystem_uuid} {MOUNT_ROOT} xfs defaults,nofail 0 0\n"
    _atomic_write(FSTAB_PATH, (text + prefix + line).encode("utf-8"), 0o644)


def _write_marker(payload: dict[str, Any]) -> None:
    marker = {
        "backend": "block-volume",
        "device_set_digest": payload["authorization"]["device_set_digest"],
        "filesystem": "xfs",
        "layout": "single",
        "mount_boundary": "fixed-scylla-data-root",
        "preparation_intent_digest": payload["authorization"][
            "preparation_intent_digest"
        ],
        "role_marker": "manager-local-one-node-backend",
        "schema_version": MARKER_SCHEMA,
        "size_gib": payload["observed_size_gib"],
        "stable_id": payload["stable_id"],
        "storage_generation": payload["storage_generation"],
        "storage_policy_digest": payload["storage_policy_digest"],
    }
    _atomic_write(
        MARKER_PATH,
        json.dumps(
            marker,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n",
        0o600,
    )
    os.chown(MARKER_PATH, 0, 0)
    os.chmod(MARKER_PATH, 0o600)


def _mount_is_xfs(output: str) -> bool:
    try:
        rows = json.loads(output).get("filesystems", [])
    except (AttributeError, TypeError, ValueError) as error:
        raise PreparationError("post-action mount evidence is malformed") from error
    return (
        isinstance(rows, list)
        and len(rows) == 1
        and isinstance(rows[0], dict)
        and rows[0].get("fstype") == "xfs"
        and rows[0].get("target") == str(MOUNT_ROOT)
    )


def _result(
    payload: dict[str, Any],
    *,
    status: str,
    action_count: int,
    boundary: str,
    first_step: str | None,
    wipe_applied: bool,
    verified: bool,
) -> dict[str, Any]:
    verification = "verified" if verified else "not-verified"
    return {
        "action_count": action_count,
        "automatic_retry_allowed": False,
        "backend": "block-volume",
        "capacity_policy_binding": "operator-selected-allocation-conformance",
        "capacity_sufficiency_state": "not-proven",
        "device_count": 1,
        "device_set_digest": payload["authorization"]["device_set_digest"],
        "discovered_size_gib": payload["discovered_size_gib"],
        "disposition": "prepare-required",
        "first_irreversible_step": first_step,
        "fstab_status": verification,
        "layout": "single",
        "manual_recovery_required": boundary == "crossed",
        "marker_status": verification,
        "mount_status": verification,
        "mutation_boundary": boundary,
        "not_performed": list(NOT_PERFORMED),
        "observed_size_gib": payload["observed_size_gib"],
        "ownership_status": verification,
        "preparation_intent_digest": payload["authorization"][
            "preparation_intent_digest"
        ],
        "provenance_digest": payload["provenance_digest"],
        "requested_size_gib": payload["requested_size_gib"],
        "role": "manager",
        "schema_version": SCHEMA,
        "stable_id": payload["stable_id"],
        "status": status,
        "wipe_applied": wipe_applied,
        "xfs_status": verification,
    }


def _prepare(
    payload: dict[str, Any], facts: dict[str, Any]
) -> tuple[bool, dict[str, Any]]:
    boundary = "not-crossed"
    first_step: str | None = None
    wipe_applied = False
    actions = 0
    try:
        current = _revalidate(payload, facts)
        path = current["path"]
        if payload["authorization"]["wipe_approved"]:
            first_step = "signatures-wiped"
            boundary = "crossed"
            _run(["/usr/sbin/wipefs", "--all", "--force", path])
            wipe_applied = True
        if first_step is None:
            first_step = "xfs-created"
            boundary = "crossed"
        _run(["/usr/sbin/mkfs.xfs", "-f", "-L", "scylla-data", path])
        actions += 1
        filesystem_uuid = _run(
            ["/usr/sbin/blkid", "-s", "UUID", "-o", "value", path]
        ).strip()
        if not filesystem_uuid or len(filesystem_uuid) > 128:
            raise PreparationError("filesystem UUID verification failed")
        MOUNT_ROOT.mkdir(mode=0o750, parents=True, exist_ok=True)
        os.chown(MOUNT_ROOT, 0, 0)
        os.chmod(MOUNT_ROOT, 0o750)
        _write_fstab(filesystem_uuid)
        actions += 1
        _run(["/usr/bin/mount", str(MOUNT_ROOT)])
        os.chown(MOUNT_ROOT, 0, 0)
        os.chmod(MOUNT_ROOT, 0o750)
        actions += 1
        _write_marker(payload)
        actions += 1
        findmnt = _run(
            [
                "/usr/bin/findmnt",
                "--json",
                "--output",
                "SOURCE,FSTYPE,TARGET",
                "--target",
                str(MOUNT_ROOT),
            ]
        )
        if (
            filesystem_uuid
            not in FSTAB_PATH.read_text(encoding="utf-8", errors="strict")
            or not _mount_is_xfs(findmnt)
            or not MARKER_PATH.is_file()
            or MARKER_PATH.is_symlink()
            or (MARKER_PATH.stat().st_uid, MARKER_PATH.stat().st_gid) != (0, 0)
            or MARKER_PATH.stat().st_mode & 0o777 != 0o600
            or (MOUNT_ROOT.stat().st_uid, MOUNT_ROOT.stat().st_gid) != (0, 0)
            or MOUNT_ROOT.stat().st_mode & 0o777 != 0o750
        ):
            raise PreparationError("post-action storage verification failed")
        boundary = "completed"
        return True, _result(
            payload,
            status="changed",
            action_count=actions,
            boundary=boundary,
            first_step=first_step,
            wipe_applied=wipe_applied,
            verified=True,
        )
    except (OSError, PreparationError, UnicodeError, ValueError):
        return boundary == "crossed", _result(
            payload,
            status="failed",
            action_count=actions,
            boundary=boundary,
            first_step=first_step,
            wipe_applied=wipe_applied,
            verified=False,
        )


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={"payload": {"type": "dict", "required": True}},
        supports_check_mode=False,
    )
    payload = module.params["payload"]
    if not isinstance(payload, dict):
        module.fail_json(msg="Manager backend storage preparation input is invalid")
    try:
        _validate_payload(payload)
        changed, result = _prepare(payload, _inspect())
    except PreparationError:
        module.fail_json(
            changed=False,
            msg="Manager backend storage preparation validation failed",
        )
    if result["status"] == "failed":
        module.fail_json(
            changed=changed,
            msg="Manager backend storage preparation failed",
            result=result,
        )
    module.exit_json(changed=changed, result=result)


if __name__ == "__main__":
    run_module()
