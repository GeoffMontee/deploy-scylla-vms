#!/usr/bin/python
"""Inspect scylla-server and refuse unreviewed drain, stop, or mask mutation."""

from __future__ import annotations

import subprocess
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-untyped]

SCHEMA = "deploy-scylla-vms.ansible-scylla-cluster-shutdown/v1"
SYSTEMCTL = "/usr/bin/systemctl"
UNIT = "scylla-server.service"
ALLOWED_ACTIONS = {"inspect"}
REFUSED_ACTIONS = {"drain", "mask", "shutdown", "stop"}


class ShutdownError(Exception):
    def __init__(self, blocker: str) -> None:
        super().__init__(blocker)
        self.blocker = blocker


def _run(argv: list[str], timeout: int) -> str:
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=timeout,
            shell=False,
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
    except subprocess.TimeoutExpired as error:
        raise ShutdownError("execution-interrupted") from error
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise ShutdownError("execution-failed") from error
    if (
        result.returncode not in {0, 1, 3, 4}
        or len(result.stdout.encode("utf-8")) > 4096
    ):
        raise ShutdownError("service-inspect-failed")
    return result.stdout.strip() or "unknown"


def _inspect(timeout: int) -> dict[str, str]:
    enabled = _run([SYSTEMCTL, "is-enabled", UNIT], timeout)
    active = _run([SYSTEMCTL, "is-active", UNIT], timeout)
    if enabled not in {"disabled", "enabled", "masked", "not-found"}:
        raise ShutdownError("service-inspect-failed")
    if active not in {"active", "failed", "inactive", "unknown"}:
        active = "unknown"
    return {"active": active, "enabled": enabled, "unit": UNIT}


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "action": {"type": "str", "required": True},
            "timeout_seconds": {"type": "int", "required": True},
        },
        supports_check_mode=False,
    )
    action = module.params["action"]
    timeout = module.params["timeout_seconds"]
    if action in REFUSED_ACTIONS:
        module.fail_json(
            msg="scylla-cluster-shutdown refused an unreviewed mutation",
            blocker="official-command-order-unreviewed",
        )
    if (
        action not in ALLOWED_ACTIONS
        or not isinstance(timeout, int)
        or not (1 <= timeout <= 60)
    ):
        module.fail_json(msg="scylla-cluster-shutdown intent is invalid")
    try:
        inspection = _inspect(timeout)
    except ShutdownError as error:
        module.fail_json(
            msg="scylla-cluster-shutdown refused an unreviewed mutation",
            blocker=error.blocker,
        )
    result: dict[str, Any] = {
        "changed": False,
        "inspection": inspection,
        "schema_version": SCHEMA,
    }
    module.exit_json(**result)


if __name__ == "__main__":
    run_module()
