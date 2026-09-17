#!/usr/bin/python
"""Collect a bounded normalized Scylla health view without returning raw output."""

from __future__ import annotations

import re
import socket
import subprocess
from datetime import UTC, datetime
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-untyped]

_COMMANDS = {
    "describecluster": ["/usr/bin/nodetool", "describecluster"],
    "info": ["/usr/bin/nodetool", "info"],
    "netstats": ["/usr/bin/nodetool", "netstats"],
    "status": ["/usr/bin/nodetool", "status"],
    "systemctl": ["/usr/bin/systemctl", "is-active", "scylla-server.service"],
    "version": ["/usr/bin/nodetool", "version"],
}
_COMMAND_EXPORT = [
    ["/usr/bin/nodetool", "info"],
    ["/usr/bin/nodetool", "status"],
    ["/usr/bin/nodetool", "describecluster"],
    ["/usr/bin/nodetool", "netstats"],
    ["/usr/bin/nodetool", "version"],
    ["/usr/bin/systemctl", "is-active", "scylla-server.service"],
]
_HOST_ID = re.compile(r"(?im)^ID\s*:\s*([0-9a-f]{8}-[0-9a-f-]{27})\s*$")
_DC = re.compile(r"^Datacenter:\s*(\S.*?)\s*$")
_ROW = re.compile(
    r"^(?P<state>[UD][NLJM])\s+(?P<address>\S+)\s+.*\s+"
    r"(?P<host_id>[0-9a-f]{8}-[0-9a-f-]{27})\s+(?P<rack>\S+)\s*$"
)
_SCHEMA = re.compile(r"(?m)^\s*([0-9a-f]{8}-[0-9a-f-]{27})\s*:\s*\[")
_VERSION = re.compile(r"(?m)^ReleaseVersion:\s*(\S+)\s*$")
_MAX_OUTPUT = 256 * 1024


def _run(argv: list[str], timeout: int) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            shell=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""
    output = completed.stdout
    if len(output) > _MAX_OUTPUT:
        return 1, ""
    try:
        text = output.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return 1, ""
    return completed.returncode, text


def _port_open(port: int, timeout: int) -> bool:
    try:
        with socket.create_connection(
            ("127.0.0.1", port), timeout=min(float(timeout), 5.0)
        ):
            return True
    except OSError:
        return False


def _ring(text: str) -> list[dict[str, str]]:
    datacenter = ""
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        dc_match = _DC.fullmatch(line.strip())
        if dc_match is not None:
            datacenter = dc_match.group(1)
            continue
        row_match = _ROW.fullmatch(line.strip())
        if row_match is not None and datacenter:
            rows.append(
                {
                    "address": row_match.group("address"),
                    "datacenter": datacenter,
                    "host_id": row_match.group("host_id").lower(),
                    "rack": row_match.group("rack"),
                    "state": row_match.group("state"),
                }
            )
    return sorted(rows, key=lambda item: item["host_id"])


def main() -> None:
    module = AnsibleModule(
        argument_spec={
            "logical_id": {"type": "str", "required": True},
            "datacenter": {"type": "str", "required": True},
            "rack": {"type": "str", "required": True},
            "expected_hosts": {"type": "list", "elements": "dict", "required": True},
            "timeout_seconds": {"type": "int", "required": True},
        },
        supports_check_mode=True,
    )
    logical_id = module.params["logical_id"]
    datacenter = module.params["datacenter"]
    rack = module.params["rack"]
    expected_hosts = module.params["expected_hosts"]
    timeout = module.params["timeout_seconds"]
    if (
        not isinstance(logical_id, str)
        or not isinstance(datacenter, str)
        or not isinstance(rack, str)
        or not isinstance(timeout, int)
        or not isinstance(expected_hosts, list)
        or isinstance(timeout, bool)
        or not 1 <= timeout <= 60
    ):
        module.fail_json(msg="Scylla health arguments are invalid", changed=False)
    outputs: dict[str, str] = {}
    errors: list[str] = []
    for name in (
        "info",
        "status",
        "describecluster",
        "netstats",
        "version",
        "systemctl",
    ):
        rc, output = _run(_COMMANDS[name], timeout)
        outputs[name] = output
        if rc != 0:
            errors.append(name)
    host_match = _HOST_ID.search(outputs["info"])
    if host_match is None and "info" not in errors:
        errors.append("info")
    raw_ring = _ring(outputs["status"])
    if not raw_ring and "status" not in errors:
        errors.append("status")
    expected_addresses = {
        item.get("private_address") for item in expected_hosts if isinstance(item, dict)
    }
    ring_addresses = {item["address"] for item in raw_ring}
    if (
        len(expected_addresses) != len(expected_hosts)
        or ring_addresses != expected_addresses
    ):
        errors.append("identity")
    ring = [
        {
            "datacenter": item["datacenter"],
            "host_id": item["host_id"],
            "rack": item["rack"],
            "state": item["state"],
        }
        for item in raw_ring
    ]
    schema_versions = sorted(set(_SCHEMA.findall(outputs["describecluster"])))
    if not schema_versions and "describecluster" not in errors:
        errors.append("describecluster")
    mode_match = re.search(r"(?m)^Mode:\s*(\S+)\s*$", outputs["netstats"])
    mode = mode_match.group(1) if mode_match is not None else "UNKNOWN"
    no_sending = "Not sending any streams." in outputs["netstats"]
    no_receiving = "Not receiving any streams." in outputs["netstats"]
    if (mode_match is None or not no_sending or not no_receiving) and (
        "netstats" not in errors
    ):
        errors.append("netstats")
    version_match = _VERSION.search(outputs["version"])
    version = version_match.group(1) if version_match is not None else "unknown"
    if version_match is None and "version" not in errors:
        errors.append("version")
    service_state = outputs["systemctl"].strip()
    if service_state not in {
        "active",
        "inactive",
        "failed",
        "activating",
        "deactivating",
    }:
        service_state = "unknown"
        if "systemctl" not in errors:
            errors.append("systemctl")
    result: dict[str, Any] = {
        "api_reachable": _port_open(10000, timeout),
        "captured_at": datetime.now(UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "commands": _COMMAND_EXPORT,
        "cql_reachable": _port_open(9042, timeout),
        "datacenter": datacenter,
        "errors": sorted(set(errors)),
        "local_host_id": (
            host_match.group(1).lower()
            if host_match is not None
            else "00000000-0000-0000-0000-000000000000"
        ),
        "logical_id": logical_id,
        "mode": mode,
        "rack": rack,
        "receiving_streams": 0 if no_receiving else 1,
        "ring": ring,
        "schema_version": "deploy-scylla-vms.ansible-scylla-health-view/v1",
        "schema_versions": schema_versions,
        "sending_streams": 0 if no_sending else 1,
        "service_state": service_state,
        "version": version,
    }
    module.exit_json(changed=False, scylla_health=result)


if __name__ == "__main__":
    main()
