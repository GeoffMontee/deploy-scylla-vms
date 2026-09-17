#!/usr/bin/python
"""Collect bounded SSH host-key candidates from one already trusted jump."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import selectors
import stat
import subprocess
import time
from datetime import datetime
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-untyped]

REQUEST_SCHEMA = "deploy-scylla-vms.ansible-routed-keyscan-request/v1"
RESULT_SCHEMA = "deploy-scylla-vms.ansible-routed-keyscan/v1"
EXECUTABLE = "/usr/bin/ssh-keyscan"
PORT = 22
MAXIMUM_TARGETS = 64
MAXIMUM_OUTPUT_BYTES = 32 * 1024
APPROVED_ALGORITHMS = ("ecdsa-sha2-nistp256", "ssh-ed25519")
KEYSCAN_TYPES = "ecdsa,ed25519"
LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
KEY_BLOB = re.compile(r"[A-Za-z0-9+/]+={0,2}\Z")
TIMESTAMP = re.compile(
    r"(?:[0-9]{4})-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z"
)


class ScanError(Exception):
    def __init__(self, blocker: str) -> None:
        super().__init__(blocker)
        self.blocker = blocker


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _is_rfc1918(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return isinstance(address, ipaddress.IPv4Address) and any(
        address in network
        for network in (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
    )


def _is_timestamp(value: object) -> bool:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        return False
    try:
        return (
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            == value
        )
    except ValueError:
        return False


def _validate_request(request: dict[str, Any]) -> None:
    if set(request) != {
        "collection_time",
        "jump_host_id",
        "provenance",
        "request_digest",
        "schema_version",
        "targets",
        "timeout_policy",
    }:
        raise ScanError("execution-failed")
    if (
        request.get("schema_version") != REQUEST_SCHEMA
        or not _is_timestamp(request.get("collection_time"))
        or not isinstance(request.get("jump_host_id"), str)
        or LOGICAL_ID.fullmatch(request["jump_host_id"]) is None
        or not isinstance(request.get("request_digest"), str)
        or DIGEST.fullmatch(request["request_digest"]) is None
    ):
        raise ScanError("execution-failed")
    unsigned = {key: value for key, value in request.items() if key != "request_digest"}
    if request["request_digest"] != _canonical_digest(unsigned):
        raise ScanError("execution-failed")
    provenance = request.get("provenance")
    if not isinstance(provenance, dict) or set(provenance) != {
        "inventory_digest",
        "inventory_generation",
        "observation_digest",
        "observation_generation",
        "readiness_digest",
        "readiness_schema_version",
        "trust_digest",
        "trust_generation",
    }:
        raise ScanError("execution-failed")
    if not all(
        isinstance(provenance.get(name), int)
        and not isinstance(provenance[name], bool)
        and provenance[name] >= 1
        for name in (
            "inventory_generation",
            "observation_generation",
            "trust_generation",
        )
    ) or not all(
        isinstance(provenance.get(name), str)
        and DIGEST.fullmatch(provenance[name]) is not None
        for name in (
            "inventory_digest",
            "observation_digest",
            "readiness_digest",
            "trust_digest",
        )
    ):
        raise ScanError("execution-failed")
    if (
        provenance.get("readiness_schema_version")
        != "deploy-scylla-vms.ansible-readiness/v1"
    ):
        raise ScanError("execution-failed")
    policy = request.get("timeout_policy")
    if not isinstance(policy, dict) or set(policy) != {
        "approved_key_types",
        "executable",
        "maximum_output_bytes_per_target",
        "port",
        "seconds_per_target",
    }:
        raise ScanError("execution-failed")
    timeout = policy.get("seconds_per_target")
    if (
        policy.get("approved_key_types") != list(APPROVED_ALGORITHMS)
        or policy.get("executable") != EXECUTABLE
        or policy.get("maximum_output_bytes_per_target") != MAXIMUM_OUTPUT_BYTES
        or policy.get("port") != PORT
        or isinstance(timeout, bool)
        or not isinstance(timeout, int)
        or not 1 <= timeout <= 60
    ):
        raise ScanError("execution-failed")
    targets = request.get("targets")
    if not isinstance(targets, list) or not 1 <= len(targets) <= MAXIMUM_TARGETS:
        raise ScanError("execution-failed")
    normalized: list[tuple[str, str, int, str]] = []
    for item in targets:
        if not isinstance(item, dict) or set(item) != {
            "address",
            "logical_id",
            "port",
            "route_digest",
        }:
            raise ScanError("execution-failed")
        logical_id = item.get("logical_id")
        address = item.get("address")
        route_digest = item.get("route_digest")
        if (
            not isinstance(logical_id, str)
            or LOGICAL_ID.fullmatch(logical_id) is None
            or not isinstance(address, str)
            or not _is_rfc1918(address)
            or item.get("port") != PORT
            or not isinstance(route_digest, str)
            or DIGEST.fullmatch(route_digest) is None
        ):
            raise ScanError("execution-failed")
        normalized.append((logical_id, address, PORT, route_digest))
    if normalized != sorted(set(normalized)):
        raise ScanError("execution-failed")


def _validate_executable() -> None:
    try:
        information = os.lstat(EXECUTABLE)
    except OSError as error:
        raise ScanError("execution-failed") from error
    if (
        stat.S_ISLNK(information.st_mode)
        or not stat.S_ISREG(information.st_mode)
        or os.path.realpath(EXECUTABLE) != EXECUTABLE
        or information.st_uid != 0
        or information.st_mode & 0o022
        or not os.access(EXECUTABLE, os.X_OK)
    ):
        raise ScanError("execution-failed")


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=1)


def _run_bounded(address: str, timeout: int) -> tuple[int, bytes, bytes]:
    try:
        process = subprocess.Popen(
            [
                EXECUTABLE,
                "-T",
                str(timeout),
                "-p",
                str(PORT),
                "-t",
                KEYSCAN_TYPES,
                address,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
    except OSError as error:
        raise ScanError("execution-failed") from error
    if process.stdout is None or process.stderr is None:
        _terminate(process)
        raise ScanError("execution-failed")
    selector = selectors.DefaultSelector()
    streams = {
        process.stdout.fileno(): bytearray(),
        process.stderr.fileno(): bytearray(),
    }
    for descriptor in streams:
        selector.register(descriptor, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    total = 0
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate(process)
                raise ScanError("scan-timeout")
            events = selector.select(remaining)
            if not events:
                _terminate(process)
                raise ScanError("scan-timeout")
            for key, _ in events:
                descriptor = key.fd
                chunk = os.read(descriptor, 8192)
                if not chunk:
                    selector.unregister(descriptor)
                    continue
                total += len(chunk)
                if total > MAXIMUM_OUTPUT_BYTES:
                    _terminate(process)
                    raise ScanError("output-limit-exceeded")
                streams[descriptor].extend(chunk)
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as error:
        _terminate(process)
        raise ScanError("scan-timeout") from error
    except OSError as error:
        _terminate(process)
        raise ScanError("execution-failed") from error
    finally:
        selector.close()
    return (
        process.returncode,
        bytes(streams[process.stdout.fileno()]),
        bytes(streams[process.stderr.fileno()]),
    )


def _ssh_string(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(data):
        raise ScanError("invalid-output")
    size = int.from_bytes(data[offset : offset + 4], "big")
    start = offset + 4
    end = start + size
    if size < 1 or end > len(data):
        raise ScanError("invalid-output")
    return data[start:end], end


def _validate_key(algorithm: str, public_key: str) -> str:
    if (
        algorithm not in APPROVED_ALGORITHMS
        or not isinstance(public_key, str)
        or len(public_key) > 32 * 1024
        or KEY_BLOB.fullmatch(public_key) is None
    ):
        raise ScanError("invalid-output")
    try:
        key = base64.b64decode(public_key, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ScanError("invalid-output") from error
    if not key or len(key) > 16 * 1024:
        raise ScanError("invalid-output")
    embedded, offset = _ssh_string(key, 0)
    if embedded != algorithm.encode("ascii"):
        raise ScanError("invalid-output")
    if algorithm == "ssh-ed25519":
        point, offset = _ssh_string(key, offset)
        if len(point) != 32:
            raise ScanError("invalid-output")
    else:
        curve, offset = _ssh_string(key, offset)
        point, offset = _ssh_string(key, offset)
        if curve != b"nistp256" or len(point) != 65 or point[:1] != b"\x04":
            raise ScanError("invalid-output")
    if offset != len(key):
        raise ScanError("invalid-output")
    fingerprint = base64.b64encode(hashlib.sha256(key).digest()).decode("ascii")
    return "SHA256:" + fingerprint.rstrip("=")


def _validate_stderr(stderr: str, address: str) -> None:
    banner = re.compile(rf"# {re.escape(address)}(?::{PORT})? SSH-[ -~]{{1,255}}\Z")
    if any(not banner.fullmatch(line) for line in stderr.splitlines() if line):
        raise ScanError("invalid-output")


def _parse_output(stdout: bytes, stderr: bytes, address: str) -> list[dict[str, str]]:
    try:
        stdout_text = stdout.decode("utf-8", errors="strict")
        stderr_text = stderr.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ScanError("invalid-output") from error
    _validate_stderr(stderr_text, address)
    keys: list[dict[str, str]] = []
    for line in stdout_text.splitlines():
        fields = line.split()
        if len(fields) != 3 or fields[0] != address:
            raise ScanError("invalid-output")
        algorithm, public_key = fields[1:]
        keys.append(
            {
                "algorithm": algorithm,
                "fingerprint": _validate_key(algorithm, public_key),
                "public_key": public_key,
            }
        )
    algorithms = [item["algorithm"] for item in keys]
    if not keys or len(algorithms) != len(set(algorithms)):
        raise ScanError("invalid-output")
    keys.sort(key=lambda item: (item["algorithm"], item["fingerprint"]))
    return keys


def _scan_target(item: dict[str, Any], timeout: int) -> dict[str, object]:
    try:
        return_code, stdout, stderr = _run_bounded(item["address"], timeout)
        if return_code != 0:
            raise ScanError("target-unreachable")
        keys = _parse_output(stdout, stderr, item["address"])
    except ScanError as error:
        status = (
            "timed-out"
            if error.blocker == "scan-timeout"
            else ("unreachable" if error.blocker == "target-unreachable" else "failed")
        )
        return {
            "blocker": error.blocker,
            "keys": [],
            "logical_id": item["logical_id"],
            "route_digest": item["route_digest"],
            "status": status,
        }
    return {
        "blocker": None,
        "keys": keys,
        "logical_id": item["logical_id"],
        "route_digest": item["route_digest"],
        "status": "collected",
    }


def run_module() -> None:
    module = AnsibleModule(
        argument_spec={
            "request": {
                "type": "dict",
                "required": True,
                "no_log": True,
            },
        },
        supports_check_mode=True,
    )
    request = module.params["request"]
    if not isinstance(request, dict):
        module.fail_json(
            msg="Routed SSH keyscan request is invalid",
            blocker="execution-failed",
        )
    try:
        _validate_request(request)
        _validate_executable()
        timeout = request["timeout_policy"]["seconds_per_target"]
        targets = [_scan_target(item, timeout) for item in request["targets"]]
    except ScanError as error:
        module.fail_json(
            msg="Routed SSH keyscan could not establish bounded candidate evidence",
            blocker=error.blocker,
        )
    collected = sum(item["status"] == "collected" for item in targets)
    status = (
        "success"
        if collected == len(targets)
        else "partial-failure"
        if collected
        else "failure"
    )
    module.exit_json(
        changed=False,
        result={
            "jump_host_id": request["jump_host_id"],
            "request_digest": request["request_digest"],
            "schema_version": RESULT_SCHEMA,
            "status": status,
            "targets": targets,
        },
    )


if __name__ == "__main__":
    run_module()
