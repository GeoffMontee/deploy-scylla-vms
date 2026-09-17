#!/usr/bin/python
"""Collect bounded read-only Ubuntu package, lock, reboot, kernel, and space gates."""

from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-untyped]

SCHEMA = "deploy-scylla-vms.ansible-os-upgrade-preflight/v1"
DPKG = "/usr/bin/dpkg"
REBOOT_REQUIRED = Path("/run/reboot-required")
LOCK_PATHS = (
    Path("/var/lib/dpkg/lock"),
    Path("/var/lib/dpkg/lock-frontend"),
    Path("/var/lib/apt/lists/lock"),
    Path("/var/cache/apt/archives/lock"),
)
PROC_LOCKS = Path("/proc/locks")
GATE_NAMES = (
    "architecture",
    "backup-policy",
    "base-os",
    "boot-space",
    "broken-packages",
    "capacity",
    "current-os",
    "health",
    "kernel-family",
    "kernel-policy",
    "package-channel",
    "package-currency",
    "package-locks",
    "provider-image",
    "quorum",
    "reboot-required",
    "replication",
    "repository-state",
    "role-availability",
    "role-configuration",
    "role-package",
    "root-space",
    "route",
    "service",
    "storage",
    "topology-work",
    "transition",
)


class PreflightError(Exception):
    def __init__(self, blocker: str) -> None:
        super().__init__(blocker)
        self.blocker = blocker


def _run_dpkg_audit(timeout: int) -> bool:
    try:
        result = subprocess.run(
            [DPKG, "--audit"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=timeout,
            shell=False,
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise PreflightError("execution-failed") from error
    if (
        len(result.stdout.encode("utf-8")) > 64 * 1024
        or len(result.stderr.encode("utf-8")) > 64 * 1024
    ):
        raise PreflightError("execution-failed")
    return (
        result.returncode == 0
        and not result.stdout.strip()
        and not result.stderr.strip()
    )


def _lock_status() -> str:
    """Observe fixed package lock inodes in /proc/locks without opening lock files."""

    try:
        lock_ids = {
            (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
            for path in LOCK_PATHS
            if (info := path.stat()).st_ino > 0
        }
        content = PROC_LOCKS.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        return "unknown"
    if not lock_ids or len(content.encode("utf-8")) > 512 * 1024:
        return "unknown"
    for line in content.splitlines():
        fields = line.split()
        if len(fields) < 6:
            continue
        identity = fields[5].split(":")
        if len(identity) != 3:
            continue
        try:
            candidate = (int(identity[0], 16), int(identity[1], 16), int(identity[2]))
        except ValueError:
            continue
        if candidate in lock_ids:
            return "held"
    return "clear"


def _free_bytes(path: str) -> int:
    try:
        value = os.statvfs(path)
    except OSError as error:
        raise PreflightError(
            "boot-space-unknown" if path == "/boot" else "root-space-unknown"
        ) from error
    return value.f_bavail * value.f_frsize


def _reboot_required() -> bool:
    try:
        REBOOT_REQUIRED.stat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise PreflightError("execution-failed") from error
    return True


def _validate_payload(payload: dict[str, Any]) -> None:
    required = {
        "architecture",
        "cluster_uuid",
        "controller_blockers",
        "controller_gates",
        "current_operating_system",
        "current_operating_system_version",
        "guest_architecture",
        "intent",
        "logical_id",
        "minimum_boot_free_bytes",
        "minimum_root_free_bytes",
        "not_performed",
        "provenance",
        "requested_strategy",
        "role",
        "rolling_eligible",
        "schema_version",
        "selected_path",
        "target_operating_system",
        "target_operating_system_version",
        "transition_classification",
    }
    gates = payload.get("controller_gates")
    if (
        set(payload) != required
        or payload.get("schema_version") != SCHEMA
        or payload.get("selected_path") != "not-performed"
        or payload.get("requested_strategy") not in {"auto", "in-place", "reprovision"}
        or payload.get("role") not in {"jump-host", "manager", "monitoring", "scylla"}
        or payload.get("transition_classification") not in {"undefined", "unsupported"}
        or not isinstance(payload.get("minimum_boot_free_bytes"), int)
        or not isinstance(payload.get("minimum_root_free_bytes"), int)
        or not isinstance(payload.get("controller_blockers"), list)
        or not isinstance(payload.get("not_performed"), list)
        or not isinstance(payload.get("provenance"), dict)
        or not isinstance(gates, list)
        or [item.get("name") for item in gates if isinstance(item, dict)]
        != list(GATE_NAMES)
    ):
        raise PreflightError("execution-failed")


def _inspect(payload: dict[str, Any], timeout: int) -> dict[str, Any]:
    _validate_payload(payload)
    gates = {item["name"]: item["status"] for item in payload["controller_gates"]}
    blockers = set(payload["controller_blockers"])

    guest_architecture = payload["guest_architecture"]
    if platform.machine() == guest_architecture:
        gates["architecture"] = "passed"
    else:
        gates["architecture"] = "failed"
        blockers.add("architecture-mismatch")

    if platform.system() == "Linux" and bool(platform.release()):
        gates["kernel-family"] = "passed"
    else:
        gates["kernel-family"] = "failed"
        blockers.add("kernel-family-unsupported")

    if _reboot_required():
        gates["reboot-required"] = "failed"
        blockers.add("reboot-required")
    else:
        gates["reboot-required"] = "passed"

    if _run_dpkg_audit(timeout):
        gates["broken-packages"] = "passed"
    else:
        gates["broken-packages"] = "failed"
        blockers.add("broken-packages")

    lock_status = _lock_status()
    if lock_status == "clear":
        gates["package-locks"] = "passed"
    elif lock_status == "held":
        gates["package-locks"] = "failed"
        blockers.add("package-manager-lock-held")
    else:
        gates["package-locks"] = "unknown"
        blockers.add("package-lock-evidence-unknown")

    root_free = _free_bytes("/")
    if root_free >= payload["minimum_root_free_bytes"]:
        gates["root-space"] = "passed"
    else:
        gates["root-space"] = "failed"
        blockers.add("root-space-insufficient")

    boot_free = _free_bytes("/boot")
    if boot_free >= payload["minimum_boot_free_bytes"]:
        gates["boot-space"] = "passed"
    else:
        gates["boot-space"] = "failed"
        blockers.add("boot-space-insufficient")

    return {
        "architecture": payload["architecture"],
        "blockers": sorted(blockers),
        "current_operating_system": payload["current_operating_system"],
        "current_operating_system_version": payload["current_operating_system_version"],
        "gates": [{"name": name, "status": gates[name]} for name in GATE_NAMES],
        "logical_id": payload["logical_id"],
        "not_performed": payload["not_performed"],
        "provenance": payload["provenance"],
        "requested_strategy": payload["requested_strategy"],
        "role": payload["role"],
        "rolling_eligible": payload["rolling_eligible"],
        "schema_version": SCHEMA,
        "selected_path": "not-performed",
        "status": "blocked",
        "target_operating_system": payload["target_operating_system"],
        "target_operating_system_version": payload["target_operating_system_version"],
        "transition_classification": payload["transition_classification"],
    }


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "payload": {"type": "dict", "required": True},
            "timeout_seconds": {"type": "int", "required": True},
        },
        supports_check_mode=True,
    )
    payload = module.params["payload"]
    timeout = module.params["timeout_seconds"]
    if (
        not isinstance(payload, dict)
        or not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or not 1 <= timeout <= 60
    ):
        module.fail_json(
            msg="OS-upgrade preflight input is invalid",
            blocker="execution-failed",
        )
    try:
        result = _inspect(payload, timeout)
    except PreflightError as error:
        module.fail_json(
            msg="OS-upgrade preflight could not establish bounded evidence",
            blocker=error.blocker,
        )
    module.exit_json(changed=False, result=result)


if __name__ == "__main__":
    run_module()
