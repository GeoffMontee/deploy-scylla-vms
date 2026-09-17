#!/usr/bin/python
"""Read then converge only PLAN-owned systemd units without unreviewed starts."""

from __future__ import annotations

import subprocess
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-untyped]

SCHEMA = "deploy-scylla-vms.ansible-service-converge/v1"
TIMESYNC_UNIT = "systemd-timesyncd.service"
SYSTEMCTL = "/usr/bin/systemctl"
COMMAND_TIMEOUT = 15
UNIT_NOT_PERFORMED = ["restart", "start", "unmask"]
SCOPES = {
    "base",
    "jump-host",
    "manager-agent",
    "manager-server",
    "monitoring-agent",
    "monitoring-stack",
    "monitoring-targets",
    "scylla",
}
POLICIES = {"always", "if-required", "never"}
SCOPE_UNITS = {
    "base": ((TIMESYNC_UNIT, "enabled", "active", True),),
    "jump-host": ((TIMESYNC_UNIT, "enabled", "active", True),),
    "manager-agent": (("scylla-manager-agent.service", "disabled", "inactive", False),),
    "manager-server": (("scylla-manager.service", "masked", "inactive", False),),
    "monitoring-agent": (
        ("scylla-node-exporter.service", "disabled", "inactive", False),
    ),
    "monitoring-stack": (),
    "monitoring-targets": (),
    "scylla": (("scylla-server.service", "masked", "inactive", False),),
}


class ConvergeError(Exception):
    def __init__(self, blocker: str) -> None:
        super().__init__(blocker)
        self.blocker = blocker


def _run(argv: list[str], *, allowed: tuple[int, ...] = (0, 1, 3, 4)) -> str:
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
        raise ConvergeError("execution-failed") from error
    if result.returncode not in allowed or len(result.stdout.encode("utf-8")) > 4096:
        raise ConvergeError("execution-failed")
    return result.stdout.strip()


def _inspect(unit: str) -> tuple[str, str]:
    enabled = _run([SYSTEMCTL, "is-enabled", unit])
    active = _run([SYSTEMCTL, "is-active", unit])
    if not enabled:
        enabled = "not-found"
    if not active:
        active = "unknown"
    return enabled, active


def _match(
    desired_enabled: str, desired_active: str, enabled: str, active: str
) -> str | None:
    if enabled == "not-found":
        return "unit-not-found"
    if desired_enabled == "masked" and enabled != "masked":
        return "service-unmasked"
    if desired_enabled == "disabled" and enabled == "enabled":
        return "service-enabled"
    if desired_enabled == "enabled" and enabled == "masked":
        return "service-masked"
    if desired_enabled == "enabled" and enabled != "enabled":
        return "unit-not-found" if enabled == "not-found" else "service-masked"
    if desired_active == "inactive" and active == "active":
        return "service-active"
    if desired_active == "active" and active != "active":
        return "start-not-performed"
    if enabled != desired_enabled or active != desired_active:
        return "start-not-performed"
    return None


def _converge_timesyncd(
    policy: str, enabled: str, active: str
) -> tuple[bool, bool, bool]:
    started = False
    restarted = False
    if enabled == "masked":
        raise ConvergeError("service-masked")
    if enabled != "enabled" or active != "active":
        _run([SYSTEMCTL, "enable", "--now", TIMESYNC_UNIT], allowed=(0,))
        started = active != "active"
    if policy == "always":
        _run([SYSTEMCTL, "restart", TIMESYNC_UNIT], allowed=(0,))
        restarted = True
    after_enabled, after_active = _inspect(TIMESYNC_UNIT)
    if after_enabled != "enabled" or after_active != "active":
        raise ConvergeError("start-not-performed")
    return started or restarted, started, restarted


def _expected_units(scope: str) -> tuple[tuple[str, str, str, bool], ...]:
    try:
        return SCOPE_UNITS[scope]
    except KeyError as error:
        raise ConvergeError("execution-failed") from error


def _normalize_units(intent: dict[str, Any]) -> list[dict[str, Any]]:
    scope = intent.get("service_scope")
    if scope not in SCOPES:
        raise ConvergeError("execution-failed")
    expected = _expected_units(scope)
    raw_units = intent.get("units")
    if not isinstance(raw_units, list) or len(raw_units) != len(expected):
        raise ConvergeError("execution-failed")
    units: list[dict[str, Any]] = []
    for item, (unit, enabled, active, start_allowed) in zip(
        raw_units, expected, strict=True
    ):
        if (
            not isinstance(item, dict)
            or item.get("unit") != unit
            or item.get("desired_enabled") != enabled
            or item.get("desired_active") != active
            or item.get("start_allowed") is not start_allowed
            or start_allowed is not (unit == TIMESYNC_UNIT)
        ):
            raise ConvergeError("execution-failed")
        units.append(
            {
                "desired_active": active,
                "desired_enabled": enabled,
                "start_allowed": start_allowed,
                "unit": unit,
            }
        )
    return units


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={"intent": {"type": "dict", "required": True}},
        supports_check_mode=False,
    )
    intent = module.params["intent"]
    if (
        not isinstance(intent, dict)
        or intent.get("schema_version") != SCHEMA
        or intent.get("applied") is not False
        or intent.get("started") is not False
        or intent.get("restart_policy") not in POLICIES
        or not isinstance(intent.get("not_performed"), list)
        or not isinstance(intent.get("provenance"), dict)
    ):
        module.fail_json(msg="service-converge intent is invalid")
    try:
        units = _normalize_units(intent)
        results: list[dict[str, object]] = []
        applied = False
        started = False
        restarted = False
        for item in units:
            unit = str(item["unit"])
            enabled, active = _inspect(unit)
            unit_applied = False
            unit_started = False
            unit_restarted = False
            if item["start_allowed"]:
                if unit != TIMESYNC_UNIT:
                    raise ConvergeError("start-not-performed")
                unit_applied, unit_started, unit_restarted = _converge_timesyncd(
                    str(intent["restart_policy"]), enabled, active
                )
                enabled, active = _inspect(unit)
            else:
                blocker = _match(
                    str(item["desired_enabled"]),
                    str(item["desired_active"]),
                    enabled,
                    active,
                )
                if blocker is not None:
                    raise ConvergeError(blocker)
            applied = applied or unit_applied
            started = started or unit_started
            restarted = restarted or unit_restarted
            results.append(
                {
                    "applied": unit_applied,
                    "desired_active": item["desired_active"],
                    "desired_enabled": item["desired_enabled"],
                    "not_performed": []
                    if item["start_allowed"]
                    else UNIT_NOT_PERFORMED,
                    "observed_active": active,
                    "observed_enabled": enabled,
                    "restarted": unit_restarted,
                    "start_allowed": item["start_allowed"],
                    "started": unit_started,
                    "unit": unit,
                }
            )
    except ConvergeError as error:
        module.fail_json(
            msg="service-converge refused an unreviewed mutation",
            blocker=error.blocker,
        )
    result = {
        "applied": applied,
        "blockers": [],
        "logical_id": intent["logical_id"],
        "not_performed": intent["not_performed"],
        "provenance": intent["provenance"],
        "restart_policy": intent["restart_policy"],
        "restarted": restarted,
        "schema_version": SCHEMA,
        "service_scope": intent["service_scope"],
        "started": started,
        "status": "converged" if applied else "no-change",
        "units": results,
    }
    module.exit_json(changed=applied, result=result)


if __name__ == "__main__":
    run_module()
