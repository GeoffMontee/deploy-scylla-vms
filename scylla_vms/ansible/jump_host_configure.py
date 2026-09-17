"""Strict jump-host SSH hardening intent and redacted result evidence."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from scylla_vms.ansible.base_os import BaseOsEvidence, BaseOsStatus
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.trust import StoredTrustRecord
from scylla_vms.desired import HostRole
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import InventoryHost, StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata

JUMP_HOST_CONFIGURE_SCHEMA_VERSION = "deploy-scylla-vms.ansible-jump-host-configure/v1"
JUMP_HOST_SSHD_DROP_IN = "/etc/ssh/sshd_config.d/00-deploy-scylla-vms.conf"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MARKER = re.compile(r"DSV_JUMP_HOST_CONFIGURE_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_BLOCKERS = frozenset(
    {
        "execution-failed",
        "host-key-mismatch",
        "reload-failed",
        "sshd-validation-failed",
    }
)


class JumpHostConfigureStatus(StrEnum):
    CHANGED = "changed"
    NOOP = "noop"
    NOT_PREDICTED = "not-predicted"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class JumpHostConfigurationAuthorization:
    operation_id: str
    target_logical_id: str
    observation_digest: str
    inventory_digest: str
    trust_digest: str
    base_os_digest: str
    allowed_route_digest: str
    config_digest: str
    authorization_digest: str


@dataclass(frozen=True, slots=True)
class JumpHostConfigureEvidence:
    logical_id: str
    status: JumpHostConfigureStatus
    config_digest: str
    allowed_route_digest: str
    host_key_digest: str
    provenance_digests: tuple[tuple[str, str], ...]
    validation_performed: bool
    validation_passed: bool | None
    reload_performed: bool
    reload_passed: bool | None
    blockers: tuple[str, ...]
    schema_version: str = JUMP_HOST_CONFIGURE_SCHEMA_VERSION


def authorize_jump_host_configuration(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    trust: StoredTrustRecord,
    readiness: ReadinessReport,
    base_os: BaseOsEvidence,
    *,
    operation_id: str,
    target_logical_id: str,
) -> JumpHostConfigurationAuthorization:
    """Create narrow authorization bound to the complete derived SSH policy."""

    derived = _derive_intent(
        metadata, observed, inventory, trust, readiness, base_os, target_logical_id
    )
    if _OPERATION_ID.fullmatch(operation_id) is None:
        raise StateConflictError("jump-host configuration operation ID is invalid")
    values = {
        "operation_id": operation_id,
        "target_logical_id": target_logical_id,
        "observation_digest": observed.digest,
        "inventory_digest": inventory.digest,
        "trust_digest": trust.digest,
        "base_os_digest": derived["base_os_digest"],
        "allowed_route_digest": derived["allowed_route_digest"],
        "config_digest": derived["config_digest"],
    }
    return JumpHostConfigurationAuthorization(
        operation_id,
        target_logical_id,
        observed.digest,
        inventory.digest,
        trust.digest,
        _text(derived["base_os_digest"]),
        _text(derived["allowed_route_digest"]),
        _text(derived["config_digest"]),
        _object_digest(values),
    )


def build_jump_host_configure_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    trust: StoredTrustRecord,
    readiness: ReadinessReport,
    base_os: BaseOsEvidence,
    authorization: JumpHostConfigurationAuthorization,
) -> dict[str, object]:
    """Build the exact address-sensitive runtime payload for one jump host."""

    derived = _derive_intent(
        metadata,
        observed,
        inventory,
        trust,
        readiness,
        base_os,
        authorization.target_logical_id,
    )
    expected_authorization = {
        "operation_id": authorization.operation_id,
        "target_logical_id": authorization.target_logical_id,
        "observation_digest": observed.digest,
        "inventory_digest": inventory.digest,
        "trust_digest": trust.digest,
        "base_os_digest": derived["base_os_digest"],
        "allowed_route_digest": derived["allowed_route_digest"],
        "config_digest": derived["config_digest"],
    }
    if (
        _OPERATION_ID.fullmatch(authorization.operation_id) is None
        or authorization.observation_digest != observed.digest
        or authorization.inventory_digest != inventory.digest
        or authorization.trust_digest != trust.digest
        or authorization.base_os_digest != derived["base_os_digest"]
        or authorization.allowed_route_digest != derived["allowed_route_digest"]
        or authorization.config_digest != derived["config_digest"]
        or authorization.authorization_digest != _object_digest(expected_authorization)
    ):
        raise StateConflictError("jump-host configuration authorization conflicts")
    return {
        "allowed_route_digest": derived["allowed_route_digest"],
        "allowed_routes": derived["allowed_routes"],
        "authorization_digest": authorization.authorization_digest,
        "cluster_uuid": str(metadata.cluster_uuid),
        "config": derived["config"],
        "config_digest": derived["config_digest"],
        "expected_private_address": derived["private_address"],
        "expected_public_address": derived["public_address"],
        "host_key": derived["host_key"],
        "host_key_digest": derived["host_key_digest"],
        "logical_id": authorization.target_logical_id,
        "network_intent": "operator-ssh-to-jump-and-jump-ssh-to-assigned-private-hosts",
        "operation_id": authorization.operation_id,
        "provenance": {
            "base_os_digest": derived["base_os_digest"],
            "inventory_digest": inventory.digest,
            "observation_digest": observed.digest,
            "trust_digest": trust.digest,
        },
        "schema_version": JUMP_HOST_CONFIGURE_SCHEMA_VERSION,
        "sshd_drop_in": JUMP_HOST_SSHD_DROP_IN,
    }


def parse_jump_host_configure_execution(
    stdout: str, *, expected_payload: dict[str, object], exit_code: int
) -> JumpHostConfigureEvidence:
    """Parse one strict marker and recap, retaining no raw configuration."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError("Ansible jump-host output exceeds the evidence limit")
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_JUMP_HOST_CONFIGURE_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible jump-host evidence marker is malformed")
        try:
            raw = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible jump-host evidence marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible jump-host evidence is malformed")
        values.append(value)
    logical_id = _text(expected_payload["logical_id"])
    rows = _parse_recap(stdout)
    if set(rows) != {logical_id}:
        raise AnsibleError("Ansible jump-host recap membership conflicts")
    recap_failed = bool(rows[logical_id][1] or rows[logical_id][2])
    if not values:
        if not recap_failed or exit_code == 0:
            raise AnsibleError("Ansible jump-host evidence is incomplete")
        return _failed_evidence(expected_payload)
    if len(values) != 1:
        raise AnsibleError("Ansible jump-host evidence is duplicated")
    evidence = _parse_result(values[0], expected_payload)
    failed = evidence.status is JumpHostConfigureStatus.FAILED
    if recap_failed != failed or ((exit_code == 0) == failed):
        raise AnsibleError("Ansible jump-host exit status conflicts")
    if bool(rows[logical_id][0]) != (
        evidence.status is JumpHostConfigureStatus.CHANGED
    ):
        raise AnsibleError("Ansible jump-host changed status conflicts")
    return evidence


def _derive_intent(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    trust: StoredTrustRecord,
    readiness: ReadinessReport,
    base_os: BaseOsEvidence,
    target_logical_id: str,
) -> dict[str, object]:
    record = inventory.record
    hosts = {host.logical_id: host for host in record.inventory.hosts}
    host = hosts.get(target_logical_id)
    if (
        host is None
        or host.role is not HostRole.JUMP_HOST
        or host.route_mode != "direct"
        or host.jump_host_id is not None
    ):
        raise StateConflictError(
            "jump-host configuration target is not an exact jump ID"
        )
    if (
        metadata.cluster_uuid != record.cluster_uuid
        or metadata.cluster_name != record.cluster_name
        or metadata.provider != record.provider
        or observed.record.cluster_uuid != record.cluster_uuid
        or observed.record.cluster_name != record.cluster_name
        or observed.record.provider != record.provider
        or record.source_manifest_generation != observed.record.generation
        or record.source_manifest_digest != observed.record.manifest_digest
        or readiness.observation_generation != observed.record.generation
        or readiness.inventory_generation != record.generation
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_generation != trust.record.generation
        or readiness.trust_digest != trust.digest
        or not trust.record.is_fresh_for(observed.record, record)
    ):
        raise StateConflictError("jump-host configuration provenance is stale")
    base_host = (
        base_os.hosts[0]
        if len(base_os.hosts) == 1 and base_os.hosts[0].logical_id == target_logical_id
        else None
    )
    if (
        base_host is None
        or base_host.status not in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
        or base_host.reboot_required
    ):
        raise StateConflictError(
            "jump-host configuration requires current Ubuntu base-os evidence"
        )
    entry = next(
        (item for item in trust.record.entries if item.logical_id == target_logical_id),
        None,
    )
    if (
        entry is None
        or entry.provider_id != host.provider_id
        or entry.endpoint.address != host.ansible_host
        or entry.endpoint.port != 22
        or entry.jump_host_id is not None
    ):
        raise StateConflictError("jump-host host-key identity conflicts")
    private = _private_ipv4(host.private_address)
    public = _canonical_address(host.public_address)
    if host.public_address is not None and host.ansible_host != host.public_address:
        raise StateConflictError("jump-host public route intent conflicts")
    routes = tuple(
        sorted(
            f"{_private_ipv4(item.private_address)}:22"
            for item in hosts.values()
            if item.role is not HostRole.JUMP_HOST
            and item.jump_host_id == target_logical_id
            and item.route_mode == "proxy-jump"
        )
    )
    assigned = {
        item.logical_id
        for item in hosts.values()
        if item.role is not HostRole.JUMP_HOST
        and item.jump_host_id == target_logical_id
    }
    represented = {
        item.logical_id
        for item in hosts.values()
        if item.role is not HostRole.JUMP_HOST
        and item.jump_host_id == target_logical_id
        and item.route_mode == "proxy-jump"
    }
    if assigned != represented or len(routes) != len(set(routes)):
        raise StateConflictError("jump-host PermitOpen routes cannot be represented")
    config = _render_sshd_config(host, routes)
    base_os_digest = _object_digest(
        {
            "changed": base_host.changed,
            "logical_id": base_host.logical_id,
            "reason": base_host.reason,
            "reboot_required": base_host.reboot_required,
            "status": base_host.status.value,
        }
    )
    host_key = {
        "algorithm": entry.algorithm,
        "fingerprint": entry.fingerprint,
    }
    return {
        "allowed_route_digest": _object_digest({"permit_open": list(routes)}),
        "allowed_routes": list(routes),
        "base_os_digest": base_os_digest,
        "config": config,
        "config_digest": _text_digest(config),
        "host_key": host_key,
        "host_key_digest": _object_digest(host_key),
        "private_address": private,
        "public_address": public,
    }


def _render_sshd_config(host: InventoryHost, routes: tuple[str, ...]) -> str:
    permit_open = " ".join(routes) if routes else "none"
    return (
        "# Managed by deploy-scylla-vms; local edits are overwritten.\n"
        "PasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\n"
        "ChallengeResponseAuthentication no\n"
        "PermitRootLogin no\n"
        "PubkeyAuthentication yes\n"
        "AuthenticationMethods publickey\n"
        "AllowAgentForwarding no\n"
        "X11Forwarding no\n"
        "PermitTunnel no\n"
        "AllowStreamLocalForwarding no\n"
        "AllowTcpForwarding local\n"
        "GatewayPorts no\n"
        "PermitListen none\n"
        f"PermitOpen {permit_open}\n"
        f"AllowUsers {host.ansible_user}\n"
        "LogLevel VERBOSE\n"
    )


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> JumpHostConfigureEvidence:
    fields = {
        "allowed_route_digest",
        "blockers",
        "config_digest",
        "host_key_digest",
        "logical_id",
        "provenance_digests",
        "reload_passed",
        "reload_performed",
        "schema_version",
        "status",
        "validation_passed",
        "validation_performed",
    }
    if (
        set(value) != fields
        or value["schema_version"] != JUMP_HOST_CONFIGURE_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible jump-host evidence schema is invalid")
    if value["logical_id"] != expected["logical_id"]:
        raise AnsibleError("Ansible jump-host evidence identity conflicts")
    try:
        status = JumpHostConfigureStatus(_text(value["status"]))
    except ValueError as error:
        raise AnsibleError("Ansible jump-host status is invalid") from error
    config_digest = _require_digest(value["config_digest"])
    route_digest = _require_digest(value["allowed_route_digest"])
    host_key_digest = _require_digest(value["host_key_digest"])
    provenance_value = value["provenance_digests"]
    if (
        config_digest != expected["config_digest"]
        or route_digest != expected["allowed_route_digest"]
        or host_key_digest != expected["host_key_digest"]
        or provenance_value != expected["provenance"]
        or not isinstance(provenance_value, dict)
    ):
        raise AnsibleError("Ansible jump-host evidence digests conflict")
    provenance = tuple(
        sorted(
            (_text(key), _require_digest(item))
            for key, item in provenance_value.items()
        )
    )
    blockers = _sorted_strings(value["blockers"])
    validation_performed = _bool(value["validation_performed"])
    validation_passed = _optional_bool(value["validation_passed"])
    reload_performed = _bool(value["reload_performed"])
    reload_passed = _optional_bool(value["reload_passed"])
    success = status in {JumpHostConfigureStatus.CHANGED, JumpHostConfigureStatus.NOOP}
    if (
        not set(blockers) <= _BLOCKERS
        or (
            success
            and (
                blockers
                or not validation_performed
                or validation_passed is not True
                or reload_performed != (status is JumpHostConfigureStatus.CHANGED)
                or reload_passed
                != (True if status is JumpHostConfigureStatus.CHANGED else None)
            )
        )
        or (
            status is JumpHostConfigureStatus.NOT_PREDICTED
            and (
                blockers
                or validation_performed
                or validation_passed is not None
                or reload_performed
                or reload_passed is not None
            )
        )
        or (status is JumpHostConfigureStatus.FAILED and not blockers)
    ):
        raise AnsibleError("Ansible jump-host evidence values conflict")
    return JumpHostConfigureEvidence(
        _text(value["logical_id"]),
        status,
        config_digest,
        route_digest,
        host_key_digest,
        provenance,
        validation_performed,
        validation_passed,
        reload_performed,
        reload_passed,
        blockers,
    )


def _failed_evidence(expected: dict[str, object]) -> JumpHostConfigureEvidence:
    provenance = cast(dict[str, object], expected["provenance"])
    return JumpHostConfigureEvidence(
        _text(expected["logical_id"]),
        JumpHostConfigureStatus.FAILED,
        _require_digest(expected["config_digest"]),
        _require_digest(expected["allowed_route_digest"]),
        _require_digest(expected["host_key_digest"]),
        tuple(sorted((_text(k), _require_digest(v)) for k, v in provenance.items())),
        False,
        None,
        False,
        None,
        ("execution-failed",),
    )


def _parse_recap(stdout: str) -> dict[str, tuple[int, int, int]]:
    partition = stdout.partition("PLAY RECAP")
    if not partition[1]:
        raise AnsibleError("Ansible jump-host output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in partition[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible jump-host recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    return rows


def _canonical_address(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise StateConflictError("jump-host public address is invalid") from error
    if str(address) != value:
        raise StateConflictError("jump-host public address is not canonical")
    return value


def _private_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise StateConflictError(
            "jump-host private route address is invalid"
        ) from error
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_private:
        raise StateConflictError("jump-host private route must be RFC 1918 IPv4")
    return str(address)


def _object_digest(value: object) -> str:
    data = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _text_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AnsibleError("Ansible jump-host evidence has duplicate fields")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise AnsibleError(f"invalid jump-host evidence constant: {value}")


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible jump-host value is invalid")
    return value


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible jump-host digest is invalid")
    return text


def _bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError("Ansible jump-host boolean is invalid")
    return value


def _optional_bool(value: object) -> bool | None:
    if value is not None and not isinstance(value, bool):
        raise AnsibleError("Ansible jump-host optional boolean is invalid")
    return value


def _sorted_strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible jump-host blockers are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError("Ansible jump-host blockers are not uniquely sorted")
    return items
