#!/usr/bin/python
"""Collect bounded read-only evidence for Manager local-backend planning."""

from __future__ import annotations

import os
import platform
import socket
import subprocess
from pathlib import Path
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-untyped]

SCHEMA = "deploy-scylla-vms.ansible-manager-backend-preflight/v1"
DPKG_QUERY = "/usr/bin/dpkg-query"
SYSTEMCTL = "/usr/bin/systemctl"
REBOOT_REQUIRED = Path("/run/reboot-required")
EXPECTED_MANAGER_VERSION = "3.12.1~0.20260911.6f499af46"
MANAGER_PACKAGES = ("scylla-manager-client", "scylla-manager-server")
LOCAL_SCYLLA_PACKAGES = ("scylla", "scylla-server")
UNRESOLVED_BLOCKERS = (
    "manager-backend-capacity-policy-unknown",
    "manager-backend-configuration-source-unavailable",
    "manager-backend-package-availability-unknown",
    "manager-backend-recovery-semantics-unapproved",
    "manager-backend-schema-bootstrap-unapproved",
    "manager-backend-setup-behavior-unapproved",
    "manager-backend-storage-suitability-unknown",
    "manager-backend-tuning-suitability-unknown",
)
NOT_PERFORMED = (
    "cloud-metadata-access",
    "configuration-read",
    "configuration-write",
    "cql-connection",
    "environment-collection",
    "network-connection",
    "package-installation",
    "package-repository-query",
    "process-command-collection",
    "schema-creation",
    "schema-query",
    "scyllamgr-setup",
    "service-mutation",
    "service-start",
)


class PreflightError(Exception):
    pass


def _run(argv: list[str], timeout: int) -> tuple[int, str, str]:
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
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise PreflightError("bounded inspection failed") from error
    if (
        len(result.stdout.encode("utf-8")) > 64 * 1024
        or len(result.stderr.encode("utf-8")) > 64 * 1024
    ):
        raise PreflightError("bounded inspection output is too large")
    return result.returncode, result.stdout, result.stderr


def _package_state(
    packages: list[str], *, expected_version: str | None, timeout: int
) -> str:
    states: list[tuple[str, str | None]] = []
    for package in packages:
        code, stdout, _ = _run(
            [
                DPKG_QUERY,
                "-W",
                "-f=${db:Status-Abbrev}\\t${Version}\\n",
                package,
            ],
            timeout,
        )
        if code == 1 and not stdout.strip():
            states.append(("absent", None))
            continue
        fields = stdout.strip().split("\t")
        if code != 0 or len(fields) != 2:
            return "unknown"
        status, version = fields
        if status == "ii " and version:
            states.append(("installed", version))
        else:
            states.append(("partial", version or None))

    if all(state == "absent" for state, _ in states):
        return "not-installed"
    if any(state == "partial" for state, _ in states):
        return "partial"
    if any(state == "absent" for state, _ in states):
        return "partial"
    if expected_version is not None and any(
        version != expected_version for _, version in states
    ):
        return "mismatch"
    return "installed"


def _service_state(unit: str, timeout: int) -> str:
    try:
        code, stdout, _ = _run(
            [
                SYSTEMCTL,
                "show",
                "--no-pager",
                "--property=ActiveState",
                "--property=LoadState",
                "--property=UnitFileState",
                unit,
            ],
            timeout,
        )
    except PreflightError:
        return "unknown"
    values: dict[str, str] = {}
    for line in stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            return "unknown"
        values[key] = value
    if set(values) != {"ActiveState", "LoadState", "UnitFileState"}:
        return "unknown"
    if values["LoadState"] == "not-found":
        return "absent"
    if code != 0 or values["LoadState"] != "loaded":
        return "unknown"
    if values["ActiveState"] == "active":
        return "active"
    if values["ActiveState"] not in {"inactive", "failed"}:
        return "unknown"
    unit_file_state = values["UnitFileState"]
    if unit_file_state == "masked":
        return "masked-inactive"
    if unit_file_state in {"disabled", "static", "indirect"}:
        return "disabled-inactive"
    if unit_file_state in {"enabled", "enabled-runtime"}:
        return "enabled-inactive"
    return "unknown"


def _capacity() -> dict[str, int]:
    cpu_count = os.cpu_count()
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        page_count = os.sysconf("SC_PHYS_PAGES")
        root = os.statvfs("/")
    except (OSError, ValueError) as error:
        raise PreflightError("capacity inspection failed") from error
    if (
        not isinstance(cpu_count, int)
        or not 1 <= cpu_count <= 4096
        or not isinstance(page_size, int)
        or not isinstance(page_count, int)
        or page_size <= 0
        or page_count <= 0
    ):
        raise PreflightError("capacity inspection is invalid")
    memory_bytes = page_size * page_count
    root_total_bytes = root.f_blocks * root.f_frsize
    root_free_bytes = root.f_bavail * root.f_frsize
    if (
        not 1 <= memory_bytes <= 2**63 - 1
        or not 1 <= root_total_bytes <= 2**63 - 1
        or not 0 <= root_free_bytes <= root_total_bytes
    ):
        raise PreflightError("capacity inspection is outside bounds")
    return {
        "approved_mount_count": 1,
        "available_mount_count": 1,
        "cpu_count": cpu_count,
        "memory_bytes": memory_bytes,
        "root_free_bytes": root_free_bytes,
        "root_total_bytes": root_total_bytes,
    }


def _operating_system() -> tuple[str, str]:
    try:
        release = platform.freedesktop_os_release()
    except (OSError, ValueError):
        return "unknown", "unknown"
    return release.get("NAME", "unknown"), release.get("VERSION_ID", "unknown")


def _reboot_required() -> bool:
    try:
        REBOOT_REQUIRED.stat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise PreflightError("reboot inspection failed") from error
    return True


def _loopback_status() -> str:
    try:
        names = {name for _, name in socket.if_nameindex()}
    except OSError:
        return "unknown"
    return "available" if "lo" in names else "unavailable"


def _validate_payload(payload: dict[str, Any]) -> None:
    required = {
        "architecture",
        "backend_policy",
        "cluster_uuid",
        "expected_manager_package_version",
        "guest_architecture",
        "local_scylla_packages",
        "local_scylla_service",
        "logical_id",
        "manager_packages",
        "manager_service",
        "not_performed",
        "operating_system",
        "operating_system_version",
        "provenance",
        "role",
        "schema_version",
        "unresolved_blockers",
    }
    policy = payload.get("backend_policy")
    policy_fields = {
        "backend_credentials",
        "backend_mode",
        "backend_tls",
        "configuration_write",
        "contact_scope",
        "cql_network_ingress",
        "cql_port",
        "local_scylla_service_start",
        "managed_data_cluster_backend",
        "manager_agent_token_policy",
        "manager_service_start",
        "manager_service_state",
        "package_installation",
        "policy_digest",
        "schema_creation",
        "schema_version",
        "scylla_release",
        "setup_execution",
        "target_role",
    }
    if (
        set(payload) != required
        or payload.get("schema_version") != SCHEMA
        or payload.get("role") != "manager"
        or payload.get("operating_system") != "Ubuntu"
        or payload.get("operating_system_version") != "24.04"
        or payload.get("architecture") not in {"amd64", "aarch64"}
        or payload.get("guest_architecture") not in {"x86_64", "aarch64"}
        or payload.get("expected_manager_package_version") != EXPECTED_MANAGER_VERSION
        or payload.get("manager_packages") != list(MANAGER_PACKAGES)
        or payload.get("local_scylla_packages") != list(LOCAL_SCYLLA_PACKAGES)
        or payload.get("manager_service") != "scylla-manager.service"
        or payload.get("local_scylla_service") != "scylla-server.service"
        or payload.get("not_performed") != list(NOT_PERFORMED)
        or payload.get("unresolved_blockers") != list(UNRESOLVED_BLOCKERS)
        or not isinstance(payload.get("manager_packages"), list)
        or not isinstance(payload.get("local_scylla_packages"), list)
        or not isinstance(payload.get("provenance"), dict)
        or not isinstance(policy, dict)
        or set(policy) != policy_fields
        or policy.get("schema_version")
        != "deploy-scylla-vms.manager-backend-local-one-node-policy/v1"
        or policy.get("backend_mode") != "local-one-node"
        or policy.get("target_role") != "manager"
        or policy.get("managed_data_cluster_backend") != "forbidden"
        or policy.get("cql_network_ingress") != "forbidden"
        or policy.get("contact_scope") != "loopback-only"
        or policy.get("cql_port") != 9042
        or policy.get("scylla_release") != "2026.2"
        or policy.get("backend_credentials") != "not-required"
        or policy.get("backend_tls") != "not-required"
        or policy.get("manager_service_state") != "masked-inactive"
        or policy.get("manager_agent_token_policy") != "environment-only-required"
        or any(
            policy.get(name) != "not-performed"
            for name in (
                "configuration_write",
                "local_scylla_service_start",
                "manager_service_start",
                "package_installation",
                "schema_creation",
                "setup_execution",
            )
        )
    ):
        raise PreflightError("payload is invalid")


def _inspect(payload: dict[str, Any], timeout: int) -> dict[str, Any]:
    _validate_payload(payload)
    blockers = set(payload["unresolved_blockers"])
    operating_system, operating_system_version = _operating_system()
    if (
        operating_system != payload["operating_system"]
        or operating_system_version != payload["operating_system_version"]
    ):
        blockers.add("operating-system-mismatch")

    if platform.machine() != payload["guest_architecture"]:
        blockers.add("architecture-mismatch")

    capacity = _capacity()

    manager_package_status = _package_state(
        payload["manager_packages"],
        expected_version=payload["expected_manager_package_version"],
        timeout=timeout,
    )
    if manager_package_status != "installed":
        blockers.add("manager-package-mismatch")

    local_scylla_package_status = _package_state(
        payload["local_scylla_packages"],
        expected_version=None,
        timeout=timeout,
    )
    if local_scylla_package_status != "not-installed":
        blockers.add("local-scylla-package-present")

    manager_service_status = _service_state(payload["manager_service"], timeout)
    if manager_service_status != "masked-inactive":
        blockers.add("manager-service-state-unsafe")

    local_scylla_service_status = _service_state(
        payload["local_scylla_service"], timeout
    )
    if local_scylla_service_status != "absent":
        blockers.add("local-scylla-service-state-unsafe")

    reboot_required = _reboot_required()
    if reboot_required:
        blockers.add("reboot-required")

    loopback_status = _loopback_status()
    if loopback_status != "available":
        blockers.add("loopback-unavailable")

    status = "evidence-ready" if blockers == set(UNRESOLVED_BLOCKERS) else "blocked"
    return {
        "architecture": payload["architecture"],
        "backend_mode": "local-one-node",
        "blockers": sorted(blockers),
        "capacity": capacity,
        "configuration_status": "not-inspected",
        "local_scylla_package_status": local_scylla_package_status,
        "local_scylla_service_status": local_scylla_service_status,
        "logical_id": payload["logical_id"],
        "loopback_policy_status": loopback_status,
        "manager_package_status": manager_package_status,
        "manager_service_status": manager_service_status,
        "not_performed": payload["not_performed"],
        "operating_system": payload["operating_system"],
        "operating_system_version": payload["operating_system_version"],
        "operational_readiness": "not-performed",
        "package_availability_status": "not-performed",
        "provenance": payload["provenance"],
        "reboot_required": reboot_required,
        "role": "manager",
        "schema_status": "not-inspected",
        "schema_version": SCHEMA,
        "scylla_release": "2026.2",
        "status": status,
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
            msg="Manager backend preflight input is invalid",
            blocker="execution-failed",
        )
    try:
        result = _inspect(payload, timeout)
    except PreflightError:
        module.fail_json(
            msg="Manager backend preflight could not establish bounded evidence",
            blocker="execution-failed",
        )
    module.exit_json(changed=False, result=result)


if __name__ == "__main__":
    run_module()
