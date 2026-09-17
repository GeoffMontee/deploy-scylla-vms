"""Strict, redacted result evidence for the production base-OS playbook."""

import base64
import binascii
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from scylla_vms.desired import ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError

BASE_OS_EVIDENCE_SCHEMA_VERSION = "deploy-scylla-vms.ansible-base-os/v1"
MAXIMUM_BASE_OS_OUTPUT_BYTES = 1024 * 1024
SUPPORTED_BASE_OS_MATRIX = (
    ("Ubuntu", "24.04", "amd64", "Ubuntu", "24.04", "x86_64"),
    ("Ubuntu", "24.04", "aarch64", "Ubuntu", "24.04", "aarch64"),
)

_MARKER = re.compile(r"DSV_BASE_OS_B64=(?P<value>[A-Za-z0-9+/]+={0,2})")
_RECAP_LINE = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=(?P<ok>[0-9]+)\s+changed=(?P<changed>[0-9]+)\s+"
    r"unreachable=(?P<unreachable>[0-9]+)\s+failed=(?P<failed>[0-9]+)\s+"
    r"skipped=(?P<skipped>[0-9]+)\s+rescued=(?P<rescued>[0-9]+)\s+"
    r"ignored=(?P<ignored>[0-9]+)\s*$"
)


class BaseOsStatus(StrEnum):
    NO_CHANGE = "no-change"
    CHANGED = "changed"
    REBOOT_REQUIRED = "reboot-required"
    UNSUPPORTED = "unsupported"
    FAILURE = "failure"


@dataclass(frozen=True, slots=True)
class BaseOsHostEvidence:
    logical_id: str
    status: BaseOsStatus
    changed: bool
    reboot_required: bool
    reason: str


@dataclass(frozen=True, slots=True)
class BaseOsEvidence:
    status: BaseOsStatus
    hosts: tuple[BaseOsHostEvidence, ...]


def base_os_variables(
    image_filter: ImageFilter,
    architecture: str,
) -> dict[str, object]:
    """Project exact configured image evidence for the closed guest matrix."""

    configured = (
        image_filter.operating_system,
        image_filter.operating_system_version,
        architecture,
    )
    if image_filter.version_match is not ImageVersionMatch.EXACT or not any(
        configured == row[:3] for row in SUPPORTED_BASE_OS_MATRIX
    ):
        raise AnsibleError("configured image evidence is unsupported for base-os")
    return {
        "deploy_scylla_vms_image_architecture": architecture,
        "deploy_scylla_vms_image_operating_system": image_filter.operating_system,
        "deploy_scylla_vms_image_operating_system_version": (
            image_filter.operating_system_version
        ),
    }


def parse_base_os_evidence(
    stdout: str,
    expected_hosts: tuple[str, ...],
    exit_code: int,
) -> BaseOsEvidence:
    """Parse only the allowlisted marker and recap; retain no module output."""

    if len(stdout.encode("utf-8")) > MAXIMUM_BASE_OS_OUTPUT_BYTES:
        raise AnsibleError("Ansible base-os output exceeds the evidence limit")
    expected = tuple(sorted(expected_hosts))
    if not expected or expected != tuple(sorted(set(expected))):
        raise AnsibleError("Ansible base-os expected host membership is invalid")

    markers: dict[str, BaseOsHostEvidence] = {}
    for line in stdout.splitlines():
        if "DSV_BASE_OS_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible base-os evidence marker is malformed")
        evidence = _decode_marker(match.group("value"))
        if evidence.logical_id in markers:
            raise AnsibleError("Ansible base-os evidence is duplicated")
        markers[evidence.logical_id] = evidence

    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible base-os output omitted PLAY RECAP")
    recaps: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines()[1:]:
        if not line.strip():
            continue
        match = _RECAP_LINE.fullmatch(line.strip())
        if match is None:
            raise AnsibleError("Ansible base-os recap is malformed")
        host = match.group("host")
        if host in recaps:
            raise AnsibleError("Ansible base-os recap is duplicated")
        recaps[host] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    if tuple(sorted(recaps)) != expected or set(markers) - set(expected):
        raise AnsibleError("Ansible base-os evidence membership conflicts")

    hosts: list[BaseOsHostEvidence] = []
    for logical_id in expected:
        changed_count, unreachable, failed = recaps[logical_id]
        marker = markers.get(logical_id)
        if unreachable or failed:
            if marker is not None and marker.status not in {
                BaseOsStatus.UNSUPPORTED,
                BaseOsStatus.FAILURE,
            }:
                raise AnsibleError("Ansible base-os failure evidence conflicts")
            hosts.append(
                marker
                or BaseOsHostEvidence(
                    logical_id,
                    BaseOsStatus.FAILURE,
                    False,
                    False,
                    "execution-failed",
                )
            )
            continue
        if marker is None:
            raise AnsibleError("Ansible base-os evidence is incomplete")
        if marker.status in {BaseOsStatus.UNSUPPORTED, BaseOsStatus.FAILURE}:
            raise AnsibleError("Ansible base-os success evidence conflicts")
        if marker.changed != (changed_count > 0):
            raise AnsibleError("Ansible base-os changed evidence conflicts")
        hosts.append(marker)

    failures = [
        host
        for host in hosts
        if host.status in {BaseOsStatus.UNSUPPORTED, BaseOsStatus.FAILURE}
    ]
    if (exit_code == 0) != (not failures):
        raise AnsibleError("Ansible base-os exit status conflicts with evidence")
    overall = (
        BaseOsStatus.FAILURE
        if any(host.status is BaseOsStatus.FAILURE for host in hosts)
        else BaseOsStatus.UNSUPPORTED
        if failures
        else BaseOsStatus.REBOOT_REQUIRED
        if any(host.reboot_required for host in hosts)
        else BaseOsStatus.CHANGED
        if any(host.changed for host in hosts)
        else BaseOsStatus.NO_CHANGE
    )
    return BaseOsEvidence(overall, tuple(hosts))


def _decode_marker(encoded: str) -> BaseOsHostEvidence:
    try:
        raw = base64.b64decode(encoded, validate=True)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (
        binascii.Error,
        UnicodeDecodeError,
        json.JSONDecodeError,
        AnsibleError,
    ) as error:
        raise AnsibleError("Ansible base-os evidence marker is malformed") from error
    if not isinstance(value, dict) or set(value) != {
        "changed",
        "logical_id",
        "reason",
        "reboot_required",
        "schema_version",
        "status",
    }:
        raise AnsibleError("Ansible base-os evidence schema is invalid")
    item = cast(dict[str, object], value)
    logical_id = item["logical_id"]
    reason = item["reason"]
    changed = item["changed"]
    reboot_required = item["reboot_required"]
    if (
        item["schema_version"] != BASE_OS_EVIDENCE_SCHEMA_VERSION
        or not isinstance(logical_id, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", logical_id)
        or not isinstance(reason, str)
        or reason
        not in {
            "applied",
            "already-current",
            "execution-failed",
            "image-evidence-unsupported",
            "guest-facts-mismatch",
            "reboot-required",
        }
        or not isinstance(changed, bool)
        or not isinstance(reboot_required, bool)
        or not isinstance(item["status"], str)
    ):
        raise AnsibleError("Ansible base-os evidence schema is invalid")
    try:
        status = BaseOsStatus(item["status"])
    except ValueError as error:
        raise AnsibleError("Ansible base-os evidence schema is invalid") from error
    if (
        (status is BaseOsStatus.NO_CHANGE and (changed or reboot_required))
        or (status is BaseOsStatus.CHANGED and (not changed or reboot_required))
        or (status is BaseOsStatus.REBOOT_REQUIRED and not reboot_required)
        or (
            status in {BaseOsStatus.UNSUPPORTED, BaseOsStatus.FAILURE}
            and (changed or reboot_required)
        )
    ):
        raise AnsibleError("Ansible base-os evidence values conflict")
    return BaseOsHostEvidence(logical_id, status, changed, reboot_required, reason)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AnsibleError("Ansible base-os evidence contains duplicate keys")
        value[key] = item
    return value
