#!/usr/bin/python
"""Run one bounded 2026.2 replacement phase without retaining raw output."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-untyped]

_HOST_ID = re.compile(r"(?im)^ID\s*:\s*([0-9a-f]{8}-[0-9a-f-]{27})\s*$")
_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_DC = re.compile(r"^Datacenter:\s*(\S.*?)\s*$")
_ROW = re.compile(
    r"^(?P<state>[UD][NLJM])\s+\S+\s+.*\s+"
    r"(?P<host_id>[0-9a-f]{8}-[0-9a-f-]{27})\s+(?P<rack>\S+)\s*$"
)
_SCHEMA = re.compile(r"(?m)^\s*([0-9a-f]{8}-[0-9a-f-]{27})\s*:\s*\[")
_REPLACEMENT_KEY = re.compile(r"(?m)^\s*replace_node_first_boot\s*:")
_OBSOLETE_KEY = re.compile(r"(?m)^\s*replace_address(?:_first_boot)?\s*:")
_CONFIG = Path("/etc/scylla/scylla.yaml")
_DATA = Path("/var/lib/scylla/data")
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


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _file_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


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


def _inspect_survivor(old_host_id: str, timeout: int) -> dict[str, object]:
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
        "old_host_present_dead": sum(
            row["host_id"] == old_host_id and row["state"] == "DN" for row in ring
        )
        == 1,
        "ring_digest": _digest(ring),
        "schema_agreed": len(schemas) == 1,
        "streaming_complete": (
            netstats_rc == 0
            and "Mode: NORMAL" in netstats
            and "Not sending any streams." in netstats
            and "Not receiving any streams." in netstats
        ),
    }


def _target_inspection(
    config_digest: str, package_version: str, timeout: int
) -> dict[str, object]:
    try:
        config = _CONFIG.read_bytes()
        stat_result = _CONFIG.stat()
        storage_empty = _DATA.is_dir() and not any(_DATA.iterdir())
    except OSError:
        config = b""
        stat_result = None
        storage_empty = False
    package_rc, installed = _run(
        ["/usr/bin/dpkg-query", "-W", "-f=${Version}", "scylla"], timeout
    )
    service_rc, service = _run(
        [
            "/usr/bin/systemctl",
            "show",
            "scylla-server",
            "--property=ActiveState,LoadState",
            "--value",
        ],
        timeout,
    )
    text = config.decode("utf-8", errors="replace")
    return {
        "command_ok": package_rc == 0 and service_rc == 0 and stat_result is not None,
        "config_matches": _file_digest(config) == config_digest,
        "obsolete_key_present": _OBSOLETE_KEY.search(text) is not None,
        "package_matches": installed.strip() == package_version,
        "replacement_key_present": _REPLACEMENT_KEY.search(text) is not None,
        "service_inactive": "inactive" in service,
        "service_masked": "masked" in service,
        "storage_empty": storage_empty,
    }


def _write_key(old_host_id: str, config_digest: str) -> None:
    data = _CONFIG.read_bytes()
    text = data.decode("utf-8", errors="strict")
    if (
        _file_digest(data) != config_digest
        or _REPLACEMENT_KEY.search(text) is not None
        or _OBSOLETE_KEY.search(text) is not None
    ):
        raise ValueError("replacement configuration changed before key write")
    updated = text
    if updated and not updated.endswith("\n"):
        updated += "\n"
    updated += f"replace_node_first_boot: {old_host_id}\n"
    stat_result = _CONFIG.stat()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".scylla.yaml.replace.", dir=str(_CONFIG.parent)
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, stat_result.st_mode & 0o777)
        os.fchown(descriptor, stat_result.st_uid, stat_result.st_gid)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(updated.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, _CONFIG)
        directory = os.open(_CONFIG.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _postcheck(
    expected_survivors: list[dict[str, str]],
    old_host_id: str,
    datacenter: str,
    rack: str,
    intended_post_state_digest: str,
    timeout: int,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    last: dict[str, object] = {}
    survivor_ids = {item["host_id"] for item in expected_survivors}
    while time.monotonic() < deadline:
        remaining = min(30, max(1, int(deadline - time.monotonic())))
        gossip_rc, gossip = _run(["/usr/bin/nodetool", "gossipinfo"], remaining)
        status_rc, status = _run(["/usr/bin/nodetool", "status"], remaining)
        schema_rc, schema = _run(["/usr/bin/nodetool", "describecluster"], remaining)
        netstats_rc, netstats = _run(["/usr/bin/nodetool", "netstats"], remaining)
        ring = _ring(status)
        candidates = [
            item
            for item in ring
            if item["host_id"] not in survivor_ids
            and item["host_id"] != old_host_id
            and item["datacenter"] == datacenter
            and item["rack"] == rack
        ]
        gossip_ids = {item.lower() for item in _UUID.findall(gossip.lower())}
        schemas = sorted(set(_SCHEMA.findall(schema)))
        streaming_complete = (
            netstats_rc == 0
            and "Mode: NORMAL" in netstats
            and "Not sending any streams." in netstats
            and "Not receiving any streams." in netstats
        )
        complete = (
            all(value == 0 for value in (gossip_rc, status_rc, schema_rc, netstats_rc))
            and len(candidates) == 1
            and candidates[0]["state"] == "UN"
            and candidates[0]["host_id"] in gossip_ids
            and old_host_id not in gossip_ids
            and not any(item["host_id"] == old_host_id for item in ring)
            and sorted(
                (item for item in ring if item["host_id"] in survivor_ids),
                key=lambda item: item["host_id"],
            )
            == sorted(expected_survivors, key=lambda item: item["host_id"])
            and all(item["state"] == "UN" for item in ring)
            and len(schemas) == 1
            and streaming_complete
        )
        last = {
            "candidates": candidates,
            "complete": complete,
            "gossip_old_absent": old_host_id not in gossip_ids,
            "ring": ring,
            "schema_agreed": len(schemas) == 1,
            "streaming_complete": streaming_complete,
        }
        if complete:
            new_host_id = candidates[0]["host_id"]
            return {
                "complete": True,
                "new_host_id_digest": _file_digest(new_host_id.encode()),
                "post_evidence_digest": _digest(
                    {
                        "intended_post_state_digest": intended_post_state_digest,
                        "new_host_id": new_host_id,
                        "ring": ring,
                        "schema_agreed": True,
                        "streaming_complete": True,
                    }
                ),
                "postconditions": {
                    "expected-topology": "passed",
                    "new-host-id": "passed",
                    "no-streaming": "passed",
                    "old-host-id-absent": "passed",
                    "replacement-up-normal": "passed",
                    "schema-agreement": "passed",
                },
            }
        time.sleep(min(5.0, max(0.0, deadline - time.monotonic())))
    last_candidates = last.get("candidates")
    return {
        "complete": False,
        "new_host_id_digest": None,
        "post_evidence_digest": None,
        "postconditions": {
            "expected-topology": (
                "failed" if isinstance(last.get("ring"), list) else "unknown"
            ),
            "new-host-id": (
                "passed"
                if isinstance(last_candidates, list) and len(last_candidates) == 1
                else "unknown"
            ),
            "no-streaming": (
                "passed" if last.get("streaming_complete") is True else "unknown"
            ),
            "old-host-id-absent": (
                "passed" if last.get("gossip_old_absent") is True else "unknown"
            ),
            "replacement-up-normal": "unknown",
            "schema-agreement": (
                "passed" if last.get("schema_agreed") is True else "unknown"
            ),
        },
    }


def main() -> None:
    module = AnsibleModule(
        argument_spec={
            "action": {
                "type": "str",
                "required": True,
                "choices": [
                    "inspect-survivor",
                    "inspect-target",
                    "write-key",
                    "postcheck",
                ],
            },
            "config_digest": {"type": "str", "default": ""},
            "datacenter": {"type": "str", "default": ""},
            "expected_survivors": {
                "type": "list",
                "elements": "dict",
                "default": [],
            },
            "intended_post_state_digest": {"type": "str", "default": ""},
            "old_host_id": {"type": "str", "required": True},
            "package_version": {"type": "str", "default": ""},
            "rack": {"type": "str", "default": ""},
            "timeout_seconds": {"type": "int", "required": True},
        },
        supports_check_mode=False,
    )
    action = module.params["action"]
    old_host_id = module.params["old_host_id"]
    timeout = module.params["timeout_seconds"]
    if (
        not isinstance(old_host_id, str)
        or _UUID.fullmatch(old_host_id) is None
        or isinstance(timeout, bool)
        or not isinstance(timeout, int)
        or not 1 <= timeout <= 86_400
    ):
        module.fail_json(msg="Scylla replacement arguments are invalid", changed=False)
    if action == "inspect-survivor":
        module.exit_json(
            changed=False,
            inspection=_inspect_survivor(old_host_id, min(timeout, 60)),
        )
    if action == "inspect-target":
        module.exit_json(
            changed=False,
            inspection=_target_inspection(
                module.params["config_digest"],
                module.params["package_version"],
                min(timeout, 60),
            ),
        )
    if action == "write-key":
        try:
            _write_key(old_host_id, module.params["config_digest"])
        except (OSError, UnicodeError, ValueError):
            module.fail_json(
                msg="Atomic replacement key write failed; recovery review is required",
                changed=False,
            )
        module.exit_json(changed=True, key_written=True, key_retained=True)
    survivors = module.params["expected_survivors"]
    if not isinstance(survivors, list):
        module.fail_json(msg="Expected survivor topology is invalid", changed=False)
    result: dict[str, Any] = _postcheck(
        survivors,
        old_host_id,
        module.params["datacenter"],
        module.params["rack"],
        module.params["intended_post_state_digest"],
        timeout,
    )
    module.exit_json(changed=False, postcheck=result)


if __name__ == "__main__":
    main()
