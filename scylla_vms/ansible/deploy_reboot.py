"""Strict address-free result evidence for the deploy reboot support source."""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from scylla_vms.desired import HostRole
from scylla_vms.errors import AnsibleError

DEPLOY_REBOOT_RESULT_SCHEMA_VERSION = "deploy-scylla-vms.ansible-deploy-reboot/v1"
DEPLOY_REBOOT_REQUEST_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-reboot-request/v1"
)
MAXIMUM_DEPLOY_REBOOT_OUTPUT_BYTES = 1024 * 1024
MINIMUM_REBOOT_TIMEOUT_SECONDS = 60
MAXIMUM_REBOOT_TIMEOUT_SECONDS = 1800
MINIMUM_CONNECT_TIMEOUT_SECONDS = 5
MAXIMUM_CONNECT_TIMEOUT_SECONDS = 60
MAXIMUM_POST_REBOOT_DELAY_SECONDS = 60

_MARKER = re.compile(r"DSV_DEPLOY_REBOOT_B64=(?P<value>[A-Za-z0-9+/]+={0,2})")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RECAP_LINE = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=(?P<ok>[0-9]+)\s+changed=(?P<changed>[0-9]+)\s+"
    r"unreachable=(?P<unreachable>[0-9]+)\s+failed=(?P<failed>[0-9]+)\s+"
    r"skipped=(?P<skipped>[0-9]+)\s+rescued=(?P<rescued>[0-9]+)\s+"
    r"ignored=(?P<ignored>[0-9]+)\s*$"
)
_GUEST_ARCHITECTURES = frozenset({"x86_64", "aarch64"})


class DeployRebootResultStatus(StrEnum):
    """Bounded semantic outcomes from one exact serial target."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNREACHABLE = "unreachable"


@dataclass(frozen=True, slots=True)
class DeployRebootResult:
    """One strict result without boot IDs, endpoints, keys, or raw output."""

    logical_id: str
    role: HostRole
    status: DeployRebootResultStatus
    os_family: str
    os_version: str
    architecture: str
    services_safe_before: bool
    reboot_performed: bool
    reconnected: bool
    boot_changed: bool
    identity_verified: bool
    trust_revalidated: bool
    machine_evidence_verified: bool
    services_safe_after: bool
    reboot_required_clear: bool
    elapsed_seconds: int
    request_digest: str
    schema_version: str = DEPLOY_REBOOT_RESULT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != DEPLOY_REBOOT_RESULT_SCHEMA_VERSION
            or _LOGICAL_ID.fullmatch(self.logical_id) is None
            or not isinstance(self.role, HostRole)
            or not isinstance(self.status, DeployRebootResultStatus)
            or self.os_family != "Ubuntu"
            or self.os_version != "24.04"
            or self.architecture not in _GUEST_ARCHITECTURES
            or isinstance(self.elapsed_seconds, bool)
            or not isinstance(self.elapsed_seconds, int)
            or not 0 <= self.elapsed_seconds <= MAXIMUM_REBOOT_TIMEOUT_SECONDS
            or _DIGEST.fullmatch(self.request_digest) is None
        ):
            raise AnsibleError("deploy reboot result schema is invalid")
        gates = (
            self.services_safe_before,
            self.reboot_performed,
            self.reconnected,
            self.boot_changed,
            self.identity_verified,
            self.trust_revalidated,
            self.machine_evidence_verified,
            self.services_safe_after,
            self.reboot_required_clear,
        )
        if not all(isinstance(value, bool) for value in gates):
            raise AnsibleError("deploy reboot result gates are invalid")
        if self.status is DeployRebootResultStatus.SUCCEEDED:
            if not all(gates):
                raise AnsibleError("deploy reboot success gates are incomplete")
        elif any(gates) or self.elapsed_seconds != 0:
            raise AnsibleError("deploy reboot failure evidence makes unsafe claims")

    def to_object(self) -> dict[str, object]:
        return {
            "architecture": self.architecture,
            "boot_changed": self.boot_changed,
            "elapsed_seconds": self.elapsed_seconds,
            "identity_verified": self.identity_verified,
            "logical_id": self.logical_id,
            "machine_evidence_verified": self.machine_evidence_verified,
            "os_family": self.os_family,
            "os_version": self.os_version,
            "reboot_performed": self.reboot_performed,
            "reboot_required_clear": self.reboot_required_clear,
            "reconnected": self.reconnected,
            "request_digest": self.request_digest,
            "role": self.role.value,
            "schema_version": self.schema_version,
            "services_safe_after": self.services_safe_after,
            "services_safe_before": self.services_safe_before,
            "status": self.status.value,
            "trust_revalidated": self.trust_revalidated,
        }


def deploy_reboot_variables(
    *,
    operation_id: str,
    logical_id: str,
    role: HostRole,
    architecture: str,
    request_digest: str,
    reboot_timeout_seconds: int = 900,
    connect_timeout_seconds: int = 15,
    post_reboot_delay_seconds: int = 5,
) -> dict[str, object]:
    """Build the sole typed payload accepted by the support playbook."""

    if (
        not isinstance(operation_id, str)
        or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            operation_id,
        )
        or _LOGICAL_ID.fullmatch(logical_id) is None
        or not isinstance(role, HostRole)
        or architecture not in _GUEST_ARCHITECTURES
        or _DIGEST.fullmatch(request_digest) is None
        or isinstance(reboot_timeout_seconds, bool)
        or not MINIMUM_REBOOT_TIMEOUT_SECONDS
        <= reboot_timeout_seconds
        <= MAXIMUM_REBOOT_TIMEOUT_SECONDS
        or isinstance(connect_timeout_seconds, bool)
        or not MINIMUM_CONNECT_TIMEOUT_SECONDS
        <= connect_timeout_seconds
        <= MAXIMUM_CONNECT_TIMEOUT_SECONDS
        or isinstance(post_reboot_delay_seconds, bool)
        or not 0 <= post_reboot_delay_seconds <= MAXIMUM_POST_REBOOT_DELAY_SECONDS
    ):
        raise AnsibleError("deploy reboot request values are invalid")
    return {
        "deploy_scylla_vms_deploy_reboot": {
            "architecture": architecture,
            "connect_timeout_seconds": connect_timeout_seconds,
            "logical_id": logical_id,
            "operation_id": operation_id,
            "os_family": "Ubuntu",
            "os_version": "24.04",
            "post_reboot_delay_seconds": post_reboot_delay_seconds,
            "reboot_timeout_seconds": reboot_timeout_seconds,
            "request_digest": request_digest,
            "role": role.value,
            "schema_version": DEPLOY_REBOOT_REQUEST_SCHEMA_VERSION,
        }
    }


def parse_deploy_reboot_result(
    stdout: str,
    expected_payload: dict[str, object],
    exit_code: int,
) -> DeployRebootResult:
    """Parse one exact marker and recap, with conservative failure fallback."""

    if len(stdout.encode("utf-8")) > MAXIMUM_DEPLOY_REBOOT_OUTPUT_BYTES:
        raise AnsibleError("deploy reboot output exceeds the evidence limit")
    expected = _validate_payload(expected_payload)
    markers: list[DeployRebootResult] = []
    for line in stdout.splitlines():
        if "DSV_DEPLOY_REBOOT_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("deploy reboot result marker is malformed")
        markers.append(_decode_marker(match.group("value")))
    if len(markers) > 1:
        raise AnsibleError("deploy reboot result marker is duplicated")

    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("deploy reboot output omitted PLAY RECAP")
    recaps: dict[str, tuple[int, int]] = {}
    for line in recap[2].splitlines()[1:]:
        if not line.strip():
            continue
        match = _RECAP_LINE.fullmatch(line.strip())
        if match is None:
            raise AnsibleError("deploy reboot recap is malformed")
        host = match.group("host")
        if host in recaps:
            raise AnsibleError("deploy reboot recap is duplicated")
        recaps[host] = (
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    logical_id = cast(str, expected["logical_id"])
    if tuple(recaps) != (logical_id,):
        raise AnsibleError("deploy reboot recap membership conflicts")
    unreachable, failed = recaps[logical_id]
    marker = markers[0] if markers else None
    if marker is not None:
        _validate_expected_result(marker, expected)
    if exit_code == 0:
        if unreachable or failed or marker is None:
            raise AnsibleError("deploy reboot success evidence is incomplete")
        if marker.status is not DeployRebootResultStatus.SUCCEEDED:
            raise AnsibleError("deploy reboot exit status conflicts with evidence")
        return marker
    if exit_code not in {2, 4}:
        raise AnsibleError("deploy reboot exit status is unsupported")
    expected_status = (
        DeployRebootResultStatus.UNREACHABLE
        if exit_code == 4 or unreachable
        else DeployRebootResultStatus.FAILED
    )
    if marker is not None:
        if marker.status is not expected_status:
            raise AnsibleError("deploy reboot failure evidence conflicts")
        return marker
    if not (unreachable or failed):
        raise AnsibleError("deploy reboot failure recap is incomplete")
    return _failure_result(expected, expected_status)


def _validate_payload(value: dict[str, object]) -> dict[str, object]:
    required = {
        "architecture",
        "connect_timeout_seconds",
        "logical_id",
        "operation_id",
        "os_family",
        "os_version",
        "post_reboot_delay_seconds",
        "reboot_timeout_seconds",
        "request_digest",
        "role",
        "schema_version",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise AnsibleError("deploy reboot request schema is invalid")
    try:
        role = HostRole(cast(str, value["role"]))
    except (TypeError, ValueError) as error:
        raise AnsibleError("deploy reboot request role is invalid") from error
    rebuilt = deploy_reboot_variables(
        operation_id=cast(str, value["operation_id"]),
        logical_id=cast(str, value["logical_id"]),
        role=role,
        architecture=cast(str, value["architecture"]),
        request_digest=cast(str, value["request_digest"]),
        reboot_timeout_seconds=cast(int, value["reboot_timeout_seconds"]),
        connect_timeout_seconds=cast(int, value["connect_timeout_seconds"]),
        post_reboot_delay_seconds=cast(int, value["post_reboot_delay_seconds"]),
    )["deploy_scylla_vms_deploy_reboot"]
    if value != rebuilt:
        raise AnsibleError("deploy reboot request values conflict")
    return value


def _decode_marker(encoded: str) -> DeployRebootResult:
    try:
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) > 16 * 1024:
            raise AnsibleError("deploy reboot result marker is oversized")
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (
        AnsibleError,
        binascii.Error,
        json.JSONDecodeError,
        UnicodeDecodeError,
        ValueError,
    ) as error:
        raise AnsibleError("deploy reboot result marker is malformed") from error
    if not isinstance(value, dict) or set(value) != {
        "architecture",
        "boot_changed",
        "elapsed_seconds",
        "identity_verified",
        "logical_id",
        "machine_evidence_verified",
        "os_family",
        "os_version",
        "reboot_performed",
        "reboot_required_clear",
        "reconnected",
        "request_digest",
        "role",
        "schema_version",
        "services_safe_after",
        "services_safe_before",
        "status",
        "trust_revalidated",
    }:
        raise AnsibleError("deploy reboot result schema is invalid")
    item = cast(dict[str, object], value)
    try:
        return DeployRebootResult(
            logical_id=_string(item, "logical_id"),
            role=HostRole(_string(item, "role")),
            status=DeployRebootResultStatus(_string(item, "status")),
            os_family=_string(item, "os_family"),
            os_version=_string(item, "os_version"),
            architecture=_string(item, "architecture"),
            services_safe_before=_boolean(item, "services_safe_before"),
            reboot_performed=_boolean(item, "reboot_performed"),
            reconnected=_boolean(item, "reconnected"),
            boot_changed=_boolean(item, "boot_changed"),
            identity_verified=_boolean(item, "identity_verified"),
            trust_revalidated=_boolean(item, "trust_revalidated"),
            machine_evidence_verified=_boolean(item, "machine_evidence_verified"),
            services_safe_after=_boolean(item, "services_safe_after"),
            reboot_required_clear=_boolean(item, "reboot_required_clear"),
            elapsed_seconds=_integer(item, "elapsed_seconds"),
            request_digest=_string(item, "request_digest"),
            schema_version=_string(item, "schema_version"),
        )
    except ValueError as error:
        raise AnsibleError("deploy reboot result enum is invalid") from error


def _validate_expected_result(
    result: DeployRebootResult, expected: dict[str, object]
) -> None:
    if (
        result.logical_id != expected["logical_id"]
        or result.role.value != expected["role"]
        or result.os_family != expected["os_family"]
        or result.os_version != expected["os_version"]
        or result.architecture != expected["architecture"]
        or result.request_digest != expected["request_digest"]
        or result.elapsed_seconds > cast(int, expected["reboot_timeout_seconds"])
    ):
        raise AnsibleError("deploy reboot result identity conflicts")


def _failure_result(
    expected: dict[str, object],
    status: DeployRebootResultStatus,
) -> DeployRebootResult:
    return DeployRebootResult(
        logical_id=cast(str, expected["logical_id"]),
        role=HostRole(cast(str, expected["role"])),
        status=status,
        os_family=cast(str, expected["os_family"]),
        os_version=cast(str, expected["os_version"]),
        architecture=cast(str, expected["architecture"]),
        services_safe_before=False,
        reboot_performed=False,
        reconnected=False,
        boot_changed=False,
        identity_verified=False,
        trust_revalidated=False,
        machine_evidence_verified=False,
        services_safe_after=False,
        reboot_required_clear=False,
        elapsed_seconds=0,
        request_digest=cast(str, expected["request_digest"]),
    )


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AnsibleError("deploy reboot result contains duplicate keys")
        value[key] = item
    return value


def _reject_constant(value: str) -> object:
    raise ValueError(f"invalid constant: {value}")


def _string(value: dict[str, object], name: str) -> str:
    item = value[name]
    if not isinstance(item, str):
        raise AnsibleError("deploy reboot result string is invalid")
    return item


def _boolean(value: dict[str, object], name: str) -> bool:
    item = value[name]
    if not isinstance(item, bool):
        raise AnsibleError("deploy reboot result boolean is invalid")
    return item


def _integer(value: dict[str, object], name: str) -> int:
    item = value[name]
    if isinstance(item, bool) or not isinstance(item, int):
        raise AnsibleError("deploy reboot result integer is invalid")
    return item


__all__ = [
    "DEPLOY_REBOOT_REQUEST_SCHEMA_VERSION",
    "DEPLOY_REBOOT_RESULT_SCHEMA_VERSION",
    "DeployRebootResult",
    "DeployRebootResultStatus",
    "deploy_reboot_variables",
    "parse_deploy_reboot_result",
]
