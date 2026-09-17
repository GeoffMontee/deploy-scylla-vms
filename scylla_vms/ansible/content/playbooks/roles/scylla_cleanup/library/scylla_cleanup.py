#!/usr/bin/python
"""Run one fixed cleanup and return only bounded normalized evidence."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-untyped]

_COMMANDS = {
    "cleanup": ["/usr/bin/nodetool", "cleanup"],
    "compactionstats": ["/usr/bin/nodetool", "compactionstats"],
    "describecluster": ["/usr/bin/nodetool", "describecluster"],
    "info": ["/usr/bin/nodetool", "info"],
    "netstats": ["/usr/bin/nodetool", "netstats"],
    "status": ["/usr/bin/nodetool", "status"],
    "version": ["/usr/bin/nodetool", "version"],
}
_HOST_ID = re.compile(r"(?im)^ID\s*:\s*([0-9a-f]{8}-[0-9a-f-]{27})\s*$")
_DC = re.compile(r"^Datacenter:\s*(\S.*?)\s*$")
_ROW = re.compile(
    r"^(?P<state>[UD][NLJM])\s+\S+\s+.*\s+"
    r"(?P<host_id>[0-9a-f]{8}-[0-9a-f-]{27})\s+(?P<rack>\S+)\s*$"
)
_SCHEMA = re.compile(r"(?m)^\s*([0-9a-f]{8}-[0-9a-f-]{27})\s*:\s*\[")
_MAX_OUTPUT = 256 * 1024


def _run(argv: list[str], timeout: int) -> tuple[int, str, bool]:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            shell=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return 1, "", True
    except OSError:
        return 1, "", False
    if len(completed.stdout) > _MAX_OUTPUT:
        return 1, "", False
    try:
        output = completed.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return 1, "", False
    return completed.returncode, output, False


def _ring(text: str) -> list[dict[str, str]]:
    datacenter = ""
    result: list[dict[str, str]] = []
    for line in text.splitlines():
        dc = _DC.fullmatch(line.strip())
        if dc is not None:
            datacenter = dc.group(1)
            continue
        row = _ROW.fullmatch(line.strip())
        if row is not None and datacenter:
            result.append(
                {
                    "datacenter": datacenter,
                    "host_id": row.group("host_id").lower(),
                    "rack": row.group("rack"),
                    "state": row.group("state"),
                }
            )
    return sorted(result, key=lambda item: item["host_id"])


def _inspect_once(
    expected_ring: list[dict[str, str]],
    host_id: str,
    server_version: str,
    timeout: int,
) -> dict[str, Any]:
    outputs: dict[str, str] = {}
    command_ok = True
    for name in (
        "info",
        "status",
        "describecluster",
        "netstats",
        "compactionstats",
        "version",
    ):
        rc, output, timed_out = _run(_COMMANDS[name], min(timeout, 60))
        outputs[name] = output
        command_ok = command_ok and rc == 0 and not timed_out
    local = _HOST_ID.search(outputs["info"])
    ring = _ring(outputs["status"])
    schemas = sorted(set(_SCHEMA.findall(outputs["describecluster"])))
    streaming_complete = (
        "Mode: NORMAL" in outputs["netstats"]
        and "Not sending any streams." in outputs["netstats"]
        and "Not receiving any streams." in outputs["netstats"]
    )
    no_pending_compactions = (
        re.search(r"(?im)^pending tasks:\s*0\s*$", outputs["compactionstats"])
        is not None
    )
    no_cleanup_work = not re.search(
        r"(?i)cleanup.*(?:pending|active|running)",
        outputs["compactionstats"],
    )
    version_matches = outputs["version"].strip() == f"ReleaseVersion: {server_version}"
    health_ok = (
        command_ok
        and local is not None
        and local.group(1).lower() == host_id
        and ring == sorted(expected_ring, key=lambda item: item["host_id"])
        and all(item["state"] == "UN" for item in ring)
        and len(schemas) == 1
        and streaming_complete
        and version_matches
    )
    digest = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                {
                    "command_ok": command_ok,
                    "health_ok": health_ok,
                    "host_id": host_id,
                    "no_cleanup_work": no_cleanup_work,
                    "no_pending_compactions": no_pending_compactions,
                    "ring": ring,
                    "schema_count": len(schemas),
                    "streaming_complete": streaming_complete,
                    "version_matches": version_matches,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()
    )
    return {
        "command_ok": command_ok,
        "health_digest": digest,
        "health_ok": health_ok,
        "host_id_matches": local is not None and local.group(1).lower() == host_id,
        "pending_work": not (no_pending_compactions and no_cleanup_work),
        "schema_agreed": len(schemas) == 1,
        "streaming_complete": streaming_complete,
        "version_matches": version_matches,
    }


def _inspect(
    expected_ring: list[dict[str, str]],
    host_id: str,
    server_version: str,
    timeout: int,
    poll: bool,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        result = _inspect_once(expected_ring, host_id, server_version, timeout)
        if not poll or (
            result["command_ok"] and result["health_ok"] and not result["pending_work"]
        ):
            return result
        if time.monotonic() >= deadline:
            result["poll_timed_out"] = True
            return result
        time.sleep(min(10, max(0, deadline - time.monotonic())))


def main() -> None:
    module = AnsibleModule(
        argument_spec={
            "action": {
                "type": "str",
                "required": True,
                "choices": ["inspect", "cleanup", "poll"],
            },
            "expected_ring": {"type": "list", "elements": "dict", "required": True},
            "host_id": {"type": "str", "required": True},
            "server_version": {"type": "str", "required": True},
            "timeout_seconds": {"type": "int", "required": True},
        },
        supports_check_mode=False,
    )
    action = module.params["action"]
    expected_ring = module.params["expected_ring"]
    host_id = module.params["host_id"]
    timeout = module.params["timeout_seconds"]
    server_version = module.params["server_version"]
    if (
        not isinstance(expected_ring, list)
        or not isinstance(host_id, str)
        or not isinstance(timeout, int)
        or not isinstance(server_version, str)
        or isinstance(timeout, bool)
        or not 1 <= timeout <= 86_400
    ):
        module.fail_json(msg="Scylla cleanup arguments are invalid", changed=False)
    if action in {"inspect", "poll"}:
        module.exit_json(
            changed=False,
            inspection=_inspect(
                expected_ring,
                host_id,
                server_version,
                timeout,
                action == "poll",
            ),
        )
    rc, _, timed_out = _run(["/usr/bin/nodetool", "cleanup"], timeout)
    module.exit_json(
        changed=True,
        cleanup={
            "command": ["/usr/bin/nodetool", "cleanup"],
            "exit_zero": rc == 0 and not timed_out,
            "timed_out": timed_out,
        },
    )


if __name__ == "__main__":
    main()
