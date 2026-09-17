#!/usr/bin/python
"""Run one bounded removenode phase without retaining raw nodetool output."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-untyped]

_HOST_ID = re.compile(r"(?im)^ID\s*:\s*([0-9a-f]{8}-[0-9a-f-]{27})\s*$")
_DC = re.compile(r"^Datacenter:\s*(\S.*?)\s*$")
_ROW = re.compile(
    r"^(?P<state>[UD][NLJM])\s+\S+\s+.*\s+"
    r"(?P<host_id>[0-9a-f]{8}-[0-9a-f-]{27})\s+(?P<rack>\S+)\s*$"
)
_SCHEMA = re.compile(r"(?m)^\s*([0-9a-f]{8}-[0-9a-f-]{27})\s*:\s*\[")
_MAX_OUTPUT = 256 * 1024


def _run(argv: list[str], timeout: int) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            check=False,
            shell=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""
    if len(completed.stdout) > _MAX_OUTPUT:
        return 1, ""
    try:
        return completed.returncode, completed.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return 1, ""


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
                    "datacenter": datacenter,
                    "host_id": row_match.group("host_id").lower(),
                    "rack": row_match.group("rack"),
                    "state": row_match.group("state"),
                }
            )
    return sorted(rows, key=lambda item: item["host_id"])


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _inspect(target_host_id: str, timeout: int) -> dict[str, object]:
    info_rc, info = _run(["/usr/bin/nodetool", "info"], timeout)
    status_rc, status = _run(["/usr/bin/nodetool", "status"], timeout)
    schema_rc, schema = _run(["/usr/bin/nodetool", "describecluster"], timeout)
    netstats_rc, netstats = _run(["/usr/bin/nodetool", "netstats"], timeout)
    host_match = _HOST_ID.search(info)
    ring = _ring(status)
    schemas = sorted(set(_SCHEMA.findall(schema)))
    return {
        "command_ok": all(
            value == 0 for value in (info_rc, status_rc, schema_rc, netstats_rc)
        ),
        "host_id": host_match.group(1).lower() if host_match is not None else None,
        "ring": ring,
        "ring_digest": _digest(ring),
        "schema_agreed": len(schemas) == 1,
        "streaming_complete": (
            netstats_rc == 0
            and "Mode: NORMAL" in netstats
            and "Not sending any streams." in netstats
            and "Not receiving any streams." in netstats
        ),
        "target_present_dead": sum(
            item["host_id"] == target_host_id and item["state"] == "DN" for item in ring
        )
        == 1,
    }


def _postcheck(
    expected_topology: list[dict[str, str]],
    target_host_id: str,
    intended_digest: str,
    timeout: int,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    last: dict[str, object] = {}
    removal_status = "unknown"
    while time.monotonic() < deadline:
        remaining = min(30, max(1, int(deadline - time.monotonic())))
        status_rc, status_text = _run(
            ["/usr/bin/nodetool", "removenode", "status"], remaining
        )
        removal_status = (
            "complete"
            if status_rc == 0 and "No token removals in process." in status_text
            else "running"
            if status_rc == 0
            else "unknown"
        )
        last = _inspect(target_host_id, remaining)
        ring = last.get("ring")
        if (
            removal_status == "complete"
            and last.get("command_ok") is True
            and isinstance(ring, list)
            and not any(item.get("host_id") == target_host_id for item in ring)
            and ring == expected_topology
            and _digest(ring) == intended_digest
            and last.get("schema_agreed") is True
            and last.get("streaming_complete") is True
        ):
            return {
                "complete": True,
                "post_evidence_digest": _digest(
                    {
                        "removal_status": removal_status,
                        "ring": ring,
                        "schema_agreed": True,
                        "streaming_complete": True,
                    }
                ),
                "postconditions": {
                    "expected-topology": "passed",
                    "no-streaming": "passed",
                    "removal-finished": "passed",
                    "schema-agreement": "passed",
                    "survivors-up-normal": "passed",
                    "target-absent": "passed",
                },
                "removal_status": removal_status,
            }
        time.sleep(min(5.0, max(0.0, deadline - time.monotonic())))
    ring = last.get("ring")
    return {
        "complete": False,
        "post_evidence_digest": None,
        "postconditions": {
            "expected-topology": (
                "failed"
                if isinstance(ring, list) and ring != expected_topology
                else "unknown"
            ),
            "no-streaming": (
                "passed" if last.get("streaming_complete") is True else "unknown"
            ),
            "removal-finished": (
                "passed" if removal_status == "complete" else "unknown"
            ),
            "schema-agreement": (
                "passed" if last.get("schema_agreed") is True else "unknown"
            ),
            "survivors-up-normal": (
                "passed"
                if isinstance(ring, list)
                and ring
                and all(item.get("state") == "UN" for item in ring)
                else "unknown"
            ),
            "target-absent": (
                "passed"
                if isinstance(ring, list)
                and not any(item.get("host_id") == target_host_id for item in ring)
                else "unknown"
            ),
        },
        "removal_status": removal_status,
    }


def main() -> None:
    module = AnsibleModule(
        argument_spec={
            "action": {
                "type": "str",
                "required": True,
                "choices": ["inspect", "removenode", "postcheck"],
            },
            "expected_post_topology": {
                "type": "list",
                "elements": "dict",
                "default": [],
            },
            "intended_post_topology_digest": {"type": "str", "default": ""},
            "target_host_id": {"type": "str", "required": True},
            "timeout_seconds": {"type": "int", "required": True},
        },
        supports_check_mode=False,
    )
    action = module.params["action"]
    target_host_id = module.params["target_host_id"]
    timeout = module.params["timeout_seconds"]
    topology = module.params["expected_post_topology"]
    intended_digest = module.params["intended_post_topology_digest"]
    if (
        not isinstance(target_host_id, str)
        or _HOST_ID.fullmatch("ID: " + target_host_id) is None
        or isinstance(timeout, bool)
        or not isinstance(timeout, int)
        or not 1 <= timeout <= 86_400
    ):
        module.fail_json(msg="Scylla dead-removal arguments are invalid", changed=False)
    if action == "inspect":
        module.exit_json(
            changed=False, inspection=_inspect(target_host_id, min(timeout, 60))
        )
    if action == "removenode":
        status_rc, status = _run(["/usr/bin/nodetool", "removenode", "status"], 60)
        if status_rc != 0 or "No token removals in process." not in status:
            module.fail_json(
                msg="A removal is already running or its status is ambiguous",
                changed=False,
                already_running=True,
            )
        rc, _ = _run(["/usr/bin/nodetool", "removenode", target_host_id], timeout)
        if rc != 0:
            module.fail_json(
                msg="Scylla removenode failed; recovery review is required",
                changed=True,
                command_started=True,
                command_completed=False,
            )
        module.exit_json(changed=True, command_started=True, command_completed=True)
    if (
        not isinstance(topology, list)
        or not isinstance(intended_digest, str)
        or _digest(topology) != intended_digest
    ):
        module.fail_json(msg="Scylla post-removal topology is invalid", changed=False)
    result: dict[str, Any] = _postcheck(
        topology, target_host_id, intended_digest, timeout
    )
    module.exit_json(changed=False, postcheck=result)


if __name__ == "__main__":
    main()
