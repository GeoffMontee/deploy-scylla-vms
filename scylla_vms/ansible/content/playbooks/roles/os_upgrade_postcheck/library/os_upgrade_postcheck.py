#!/usr/bin/python
"""Collect bounded read-only OS-upgrade postcheck evidence."""

from __future__ import annotations

import hashlib
import json
import platform
import re
import subprocess
from pathlib import Path
from typing import Any

from ansible.module_utils.basic import AnsibleModule  # type: ignore[import-untyped]

SCHEMA = "deploy-scylla-vms.ansible-os-upgrade-postcheck/v1"
DPKG = "/usr/bin/dpkg"
DPKG_QUERY = "/usr/bin/dpkg-query"
SYSTEMCTL = "/usr/bin/systemctl"
OS_RELEASE = Path("/etc/os-release")
REBOOT_REQUIRED = Path("/run/reboot-required")
GATE_NAMES = (
    "architecture",
    "base-os",
    "broken-packages",
    "health",
    "kernel",
    "operating-system",
    "package-state",
    "provider-identity",
    "reboot-required",
    "role-configuration",
    "role-package",
    "route",
    "service-policy",
    "source-upgrade",
    "stable-identity",
    "storage",
    "transition",
)
VERIFICATION_NAMES = (
    "architecture",
    "broken-packages",
    "kernel",
    "operating-system",
    "package-state",
    "reboot-required",
    "service-policy",
)
ALLOWED_PACKAGES = frozenset(
    {
        "scylla",
        "scylla-conf",
        "scylla-cqlsh",
        "scylla-kernel-conf",
        "scylla-manager-client",
        "scylla-manager-server",
        "scylla-node-exporter",
        "scylla-python3",
        "scylla-server",
    }
)
ALLOWED_SERVICES = frozenset(
    {
        "scylla-manager.service",
        "scylla-server.service",
        "ssh.service",
        "systemd-timesyncd.service",
    }
)
ALLOWED_ENABLED = frozenset(
    {
        "alias",
        "disabled",
        "enabled",
        "enabled-runtime",
        "generated",
        "indirect",
        "linked",
        "linked-runtime",
        "masked",
        "masked-runtime",
        "static",
        "transient",
    }
)
ALLOWED_ACTIVE = frozenset({"active", "inactive"})
MAX_OUTPUT_BYTES = 64 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PACKAGE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,255}\Z")


class PostcheckError(Exception):
    def __init__(self, blocker: str) -> None:
        super().__init__(blocker)
        self.blocker = blocker


def _run(argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
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
        raise PostcheckError("execution-failed") from error
    if (
        len(result.stdout.encode("utf-8")) > MAX_OUTPUT_BYTES
        or len(result.stderr.encode("utf-8")) > MAX_OUTPUT_BYTES
    ):
        raise PostcheckError("execution-failed")
    return result


def _read_os_release() -> tuple[str, str]:
    try:
        content = OS_RELEASE.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as error:
        raise PostcheckError("execution-failed") from error
    if not content or len(content.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise PostcheckError("execution-failed")
    values: dict[str, str] = {}
    for line in content.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw = line.split("=", 1)
        if key in values or key not in {"ID", "VERSION_ID"}:
            continue
        value = raw.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    if values.get("ID") != "ubuntu" or not values.get("VERSION_ID"):
        return ("unknown", "unknown")
    return ("Ubuntu", values["VERSION_ID"])


def _architecture() -> str:
    value = platform.machine()
    if value == "x86_64":
        return "amd64"
    if value == "aarch64":
        return "aarch64"
    return "unknown"


def _reboot_required() -> bool:
    try:
        REBOOT_REQUIRED.stat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise PostcheckError("execution-failed") from error
    return True


def _broken_packages(timeout: int) -> bool:
    result = _run([DPKG, "--audit"], timeout)
    return (
        result.returncode != 0
        or bool(result.stdout.strip())
        or bool(result.stderr.strip())
    )


def _package_state(expected: list[dict[str, str]], timeout: int) -> tuple[bool, str]:
    observed: list[dict[str, str]] = []
    matched = True
    for item in expected:
        result = _run(
            [
                DPKG_QUERY,
                "--show",
                "--showformat=${db:Status-Abbrev}\\t${Version}\\n",
                item["name"],
            ],
            timeout,
        )
        fields = [field.strip() for field in result.stdout.strip().split("\t")]
        if (
            result.returncode != 0
            or result.stderr.strip()
            or len(fields) != 2
            or fields[0] != "ii"
            or _PACKAGE_VERSION.fullmatch(fields[1]) is None
        ):
            matched = False
            observed.append({"name": item["name"], "status": "mismatch"})
            continue
        version_digest = _digest_text(fields[1])
        observed.append(
            {
                "name": item["name"],
                "status": "matched" if fields[1] == item["version"] else "mismatch",
                "version_digest": version_digest,
            }
        )
        if fields[1] != item["version"]:
            matched = False
    return matched, _object_digest(observed)


def _service_state(
    expected: list[dict[str, str | None]], timeout: int
) -> tuple[bool, str]:
    observed: list[dict[str, str]] = []
    matched = True
    for item in expected:
        unit = item["unit"]
        if not isinstance(unit, str):
            raise PostcheckError("service-inspection-failed")
        enabled_result = _run([SYSTEMCTL, "is-enabled", unit], timeout)
        active_result = _run([SYSTEMCTL, "is-active", unit], timeout)
        enabled = enabled_result.stdout.strip()
        active = active_result.stdout.strip()
        if (
            enabled_result.stderr.strip()
            or active_result.stderr.strip()
            or enabled not in ALLOWED_ENABLED
            or active not in ALLOWED_ACTIVE
        ):
            raise PostcheckError("service-inspection-failed")
        expected_enabled = item["enabled"]
        expected_active = item["active"]
        item_matches = (
            expected_enabled is None or enabled == expected_enabled
        ) and active == expected_active
        observed.append(
            {
                "active": active,
                "enabled": enabled,
                "unit": unit,
            }
        )
        if not item_matches:
            matched = False
    return matched, _object_digest(observed)


def _validate_payload(payload: dict[str, Any]) -> None:
    required = {
        "architecture",
        "cluster_uuid",
        "controller_blockers",
        "controller_gates",
        "current_operating_system",
        "current_operating_system_version",
        "current_provider_id_digest",
        "expected_kernel_release_digest",
        "expected_packages",
        "expected_services",
        "guest_architecture",
        "inventory_generation",
        "logical_id",
        "not_performed",
        "observation_generation",
        "operation_id",
        "previous_architecture",
        "previous_operating_system",
        "previous_operating_system_version",
        "provenance",
        "role",
        "schema_version",
        "source_mode",
        "source_result_digest",
        "source_schema_version",
        "source_status",
        "source_upgrade_performed",
        "target_architecture",
        "target_operating_system",
        "target_operating_system_version",
        "transition_classification",
        "trust_generation",
        "verification_names",
    }
    gates = payload.get("controller_gates")
    packages = payload.get("expected_packages")
    services = payload.get("expected_services")
    if (
        set(payload) != required
        or payload.get("schema_version") != SCHEMA
        or payload.get("source_mode") not in {"in-place", "reprovision"}
        or payload.get("source_upgrade_performed") is not False
        or payload.get("role") not in {"jump-host", "manager", "monitoring", "scylla"}
        or payload.get("transition_classification")
        not in {"same-version", "unapproved", "unsupported"}
        or payload.get("verification_names") != list(VERIFICATION_NAMES)
        or not isinstance(payload.get("controller_blockers"), list)
        or not isinstance(payload.get("not_performed"), list)
        or not isinstance(payload.get("provenance"), dict)
        or not isinstance(gates, list)
        or not isinstance(packages, list)
        or not isinstance(services, list)
    ):
        raise PostcheckError("execution-failed")
    if (
        len(gates) != len(GATE_NAMES)
        or any(
            not isinstance(item, dict)
            or set(item) != {"name", "status"}
            or item.get("status")
            not in {"failed", "not-performed", "passed", "unknown"}
            for item in gates
        )
        or [item["name"] for item in gates] != list(GATE_NAMES)
    ):
        raise PostcheckError("execution-failed")
    kernel_digest = payload.get("expected_kernel_release_digest")
    if kernel_digest is not None and (
        not isinstance(kernel_digest, str) or _DIGEST.fullmatch(kernel_digest) is None
    ):
        raise PostcheckError("execution-failed")
    package_names: list[str] = []
    for item in packages:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "version"}
            or item.get("name") not in ALLOWED_PACKAGES
            or not isinstance(item.get("version"), str)
            or _PACKAGE_VERSION.fullmatch(item["version"]) is None
        ):
            raise PostcheckError("execution-failed")
        package_names.append(item["name"])
    if package_names != sorted(set(package_names)):
        raise PostcheckError("execution-failed")
    service_names: list[str] = []
    for item in services:
        if (
            not isinstance(item, dict)
            or set(item) != {"active", "enabled", "unit"}
            or item.get("unit") not in ALLOWED_SERVICES
            or item.get("active") not in ALLOWED_ACTIVE
            or item.get("enabled") not in {*ALLOWED_ENABLED, None}
        ):
            raise PostcheckError("execution-failed")
        service_names.append(item["unit"])
    if service_names != sorted(set(service_names)):
        raise PostcheckError("execution-failed")


def _inspect(payload: dict[str, Any], timeout: int) -> dict[str, Any]:
    _validate_payload(payload)
    gates = {item["name"]: item["status"] for item in payload["controller_gates"]}
    blockers = set(payload["controller_blockers"])
    performed: set[str] = set()

    current_os, current_version = _read_os_release()
    performed.add("operating-system")
    os_matches = (
        current_os == payload["target_operating_system"]
        and current_version == payload["target_operating_system_version"]
    )
    if os_matches:
        gates["operating-system"] = "passed"
        blockers.discard("current-os-mismatch")
    else:
        gates["operating-system"] = "failed"
        blockers.add("current-os-mismatch")

    current_architecture = _architecture()
    performed.add("architecture")
    architecture_matches = current_architecture == payload["target_architecture"]
    if architecture_matches:
        gates["architecture"] = "passed"
        blockers.discard("architecture-mismatch")
    else:
        gates["architecture"] = "failed"
        blockers.add("architecture-mismatch")

    kernel_digest = _digest_text(platform.release())
    expected_kernel = payload["expected_kernel_release_digest"]
    if expected_kernel is None:
        gates["kernel"] = "unknown"
        blockers.add("kernel-policy-undefined")
    else:
        performed.add("kernel")
        if kernel_digest == expected_kernel:
            gates["kernel"] = "passed"
            blockers.discard("kernel-mismatch")
        else:
            gates["kernel"] = "failed"
            blockers.add("kernel-mismatch")

    performed.add("reboot-required")
    if _reboot_required():
        gates["reboot-required"] = "failed"
        blockers.add("reboot-required")
    else:
        gates["reboot-required"] = "passed"
        blockers.discard("reboot-required")

    performed.add("broken-packages")
    if _broken_packages(timeout):
        gates["broken-packages"] = "failed"
        blockers.add("broken-packages")
    else:
        gates["broken-packages"] = "passed"
        blockers.discard("broken-packages")

    try:
        packages_match, package_digest = _package_state(
            payload["expected_packages"], timeout
        )
    except PostcheckError:
        gates["package-state"] = "unknown"
        blockers.add("package-inspection-failed")
        package_digest = None
    else:
        performed.add("package-state")
        if packages_match:
            gates["package-state"] = "passed"
            blockers.discard("package-state-mismatch")
        else:
            gates["package-state"] = "failed"
            blockers.add("package-state-mismatch")

    if gates["service-policy"] == "unknown":
        service_digest = None
        blockers.add("service-policy-unknown")
    else:
        try:
            services_match, service_digest = _service_state(
                payload["expected_services"], timeout
            )
        except PostcheckError:
            gates["service-policy"] = "unknown"
            blockers.add("service-policy-unknown")
            blockers.add("service-inspection-failed")
            service_digest = None
        else:
            performed.add("service-policy")
            if services_match:
                gates["service-policy"] = "passed"
                blockers.discard("service-policy-mismatch")
            else:
                gates["service-policy"] = "failed"
                blockers.add("service-policy-mismatch")

    transition_matches = os_matches and architecture_matches
    return {
        "automatic_remediation": False,
        "blockers": sorted(blockers),
        "current_architecture": current_architecture,
        "current_kernel_release_digest": kernel_digest,
        "current_operating_system": current_os,
        "current_operating_system_version": current_version,
        "current_package_state_digest": package_digest,
        "current_provider_id_digest": payload["current_provider_id_digest"],
        "current_service_state_digest": service_digest,
        "gates": [{"name": name, "status": gates[name]} for name in GATE_NAMES],
        "inventory_generation": payload["inventory_generation"],
        "logical_id": payload["logical_id"],
        "mutation_performed": False,
        "not_performed": payload["not_performed"],
        "observation_generation": payload["observation_generation"],
        "previous_architecture": payload["previous_architecture"],
        "previous_operating_system": payload["previous_operating_system"],
        "previous_operating_system_version": payload[
            "previous_operating_system_version"
        ],
        "provenance": payload["provenance"],
        "remediation_performed": False,
        "role": payload["role"],
        "schema_version": SCHEMA,
        "source_mode": payload["source_mode"],
        "source_result_digest": payload["source_result_digest"],
        "source_schema_version": payload["source_schema_version"],
        "source_status": payload["source_status"],
        "source_upgrade_performed": False,
        "status": "blocked",
        "target_architecture": payload["target_architecture"],
        "target_operating_system": payload["target_operating_system"],
        "target_operating_system_version": payload["target_operating_system_version"],
        "transition_classification": payload["transition_classification"],
        "transition_comparison": "matched" if transition_matches else "mismatched",
        "trust_generation": payload["trust_generation"],
        "verification_not_performed": sorted(set(VERIFICATION_NAMES) - performed),
        "verification_performed": sorted(performed),
    }


def _object_digest(value: object) -> str:
    data = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _digest_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


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
            msg="OS-upgrade postcheck input is invalid",
            blocker="execution-failed",
        )
    try:
        result = _inspect(payload, timeout)
    except PostcheckError as error:
        module.fail_json(
            msg="OS-upgrade postcheck could not establish bounded evidence",
            blocker=error.blocker,
        )
    module.exit_json(changed=False, result=result)


if __name__ == "__main__":
    run_module()
