"""Strict ScyllaDB 2026.2 configuration intent and result evidence."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from scylla_vms.ansible.base_os import BaseOsEvidence, BaseOsStatus
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.scylla_install import (
    SCYLLA_RELEASE_LINE,
    ScyllaInstallEvidence,
    ScyllaInstallStatus,
)
from scylla_vms.ansible.storage_postcheck import StoragePostcheckEvidence
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import InventoryHost, StoredInventoryRecord
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import ClusterMetadata

SCYLLA_CONFIGURE_SCHEMA_VERSION = "deploy-scylla-vms.ansible-scylla-configure/v1"
SCYLLA_CONFIGURE_MAX_SEEDS = 3
SCYLLA_CONFIGURE_DIRECTORIES = (
    "/var/lib/scylla/data",
    "/var/lib/scylla/commitlog",
    "/var/lib/scylla/hints",
    "/var/lib/scylla/view_hints",
)
SCYLLA_CONFIGURE_KEYS = (
    "api_address",
    "broadcast_address",
    "broadcast_rpc_address",
    "cluster_name",
    "commitlog_directory",
    "data_file_directories",
    "endpoint_snitch",
    "hints_directory",
    "listen_address",
    "prometheus_address",
    "rpc_address",
    "seed_provider",
    "view_hints_directory",
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TOPOLOGY_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}\Z")
_PACKAGE_VERSION = re.compile(
    r"2026\.2\.(?:0|[1-9][0-9]*)-0\.[0-9]{8}\.[0-9a-f]{12}-1\Z"
)
_MARKER = re.compile(r"DSV_SCYLLA_CONFIGURE_B64=(?P<data>[A-Za-z0-9+/]+={0,2})")
_RECAP = re.compile(
    r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})\s*:\s*"
    r"ok=\d+\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)\s+"
    r"failed=(?P<failed>\d+)\s+skipped=\d+\s+rescued=\d+\s+ignored=\d+\s*$"
)
_BLOCKERS = frozenset(
    {
        "configuration-conflict",
        "execution-failed",
        "installed-package-mismatch",
        "service-active",
        "service-unmasked",
        "static-validation-failed",
    }
)


class SeedSelectionMode(StrEnum):
    INITIAL = "initial"
    ADD = "add"
    REPLACE = "replace"
    CONVERGE = "converge"


class ScyllaConfigureStatus(StrEnum):
    CHANGED = "changed"
    NOOP = "noop"
    NOT_PREDICTED = "not-predicted"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ScyllaSeedPolicy:
    mode: SeedSelectionMode
    stable_ids: tuple[str, ...]
    digest: str


@dataclass(frozen=True, slots=True)
class ScyllaConfigureEvidence:
    logical_id: str
    status: ScyllaConfigureStatus
    config_digest: str
    topology_digest: str
    seed_digest: str
    configuration_file_digests: tuple[tuple[str, str], ...]
    files_root_owned: bool | None
    files_mode_0644: bool | None
    installed_version: str | None
    service_masked: bool | None
    service_inactive: bool | None
    runtime_validation_performed: bool
    package_install_performed: bool
    storage_mutation_performed: bool
    tuning_performed: bool
    firewall_operation_performed: bool
    ssh_operation_performed: bool
    manager_operation_performed: bool
    service_started: bool
    bootstrap_performed: bool
    prerequisite_digests: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]
    schema_version: str = SCYLLA_CONFIGURE_SCHEMA_VERSION


def select_scylla_seeds(
    inventory: StoredInventoryRecord,
    *,
    mode: SeedSelectionMode,
    target_logical_id: str,
    healthy_surviving_ids: tuple[str, ...] = (),
    persisted_seed_ids: tuple[str, ...] = (),
) -> ScyllaSeedPolicy:
    """Select a deterministic bounded stable-ID seed policy."""

    hosts = _scylla_hosts(inventory)
    by_id = {host.logical_id: host for host in hosts}
    if target_logical_id not in by_id:
        raise StateConflictError("Scylla configure target is not a Scylla stable ID")
    _ordered_unique_ids(healthy_surviving_ids, "healthy seed candidates")
    _ordered_unique_ids(persisted_seed_ids, "persisted seed policy")
    if not set(healthy_surviving_ids) <= set(by_id) or not set(
        persisted_seed_ids
    ) <= set(by_id):
        raise StateConflictError("Scylla seed policy contains an unknown stable ID")

    selected: tuple[str, ...]
    if mode is SeedSelectionMode.INITIAL:
        if healthy_surviving_ids or persisted_seed_ids:
            raise StateConflictError(
                "initial Scylla seed selection accepts no prior state"
            )
        selected = (hosts[0].logical_id,)
    else:
        if not healthy_surviving_ids:
            raise StateConflictError(
                "Scylla add/replace/converge requires healthy surviving seed members"
            )
        candidates = tuple(
            logical_id
            for logical_id in healthy_surviving_ids
            if logical_id != target_logical_id
        )
        if not candidates:
            raise StateConflictError(
                "joining or replacement node cannot be the sole Scylla seed"
            )
        desired_count = min(
            SCYLLA_CONFIGURE_MAX_SEEDS,
            max(1, (len(hosts) + 2) // 3),
            len(candidates),
        )
        retained = tuple(
            logical_id for logical_id in persisted_seed_ids if logical_id in candidates
        )
        selected_list = list(retained[:desired_count])
        used_racks = {by_id[item].scylla_rack for item in selected_list}
        for logical_id in candidates:
            if len(selected_list) >= desired_count:
                break
            rack = by_id[logical_id].scylla_rack
            if logical_id not in selected_list and rack not in used_racks:
                selected_list.append(logical_id)
                used_racks.add(rack)
        for logical_id in candidates:
            if len(selected_list) >= desired_count:
                break
            if logical_id not in selected_list:
                selected_list.append(logical_id)
        selected = tuple(selected_list)
    digest = _object_digest({"mode": mode.value, "stable_ids": list(selected)})
    return ScyllaSeedPolicy(mode, selected, digest)


def build_scylla_configure_payload(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
    base_os: BaseOsEvidence,
    storage: StoragePostcheckEvidence,
    install: ScyllaInstallEvidence,
    seed_policy: ScyllaSeedPolicy,
    *,
    logical_id: str,
    package_version: str,
    architecture: str,
    cluster_spec_digest: str,
    prior_configuration: ScyllaConfigureEvidence | None = None,
) -> dict[str, object]:
    """Build one exact wrapper-owned configuration intent."""

    if (
        architecture not in {"amd64", "aarch64"}
        or _PACKAGE_VERSION.fullmatch(package_version) is None
    ):
        raise StateConflictError(
            "Scylla configure requires supported architecture and exact 2026.2 version"
        )
    hosts = _scylla_hosts(inventory)
    by_id = {host.logical_id: host for host in hosts}
    host = by_id.get(logical_id)
    if host is None:
        raise StateConflictError("Scylla configure target is not a Scylla stable ID")
    _validate_current_provenance(metadata, observed, inventory, readiness)
    _validate_prerequisites(
        base_os,
        storage,
        install,
        logical_id=logical_id,
        package_version=package_version,
    )
    _validate_seed_policy(seed_policy, hosts, logical_id)

    cluster_name = _normalized_label(metadata.cluster_name, "cluster name")
    datacenter = _normalized_label(host.scylla_datacenter, "Scylla datacenter")
    rack = _normalized_label(host.scylla_rack, "Scylla rack")
    private_addresses = {
        item.logical_id: _private_ipv4(item.private_address) for item in hosts
    }
    if len(set(private_addresses.values())) != len(private_addresses):
        raise StateConflictError("Scylla private addresses are duplicated")
    seed_addresses = [private_addresses[item] for item in seed_policy.stable_ids]
    address = private_addresses[logical_id]
    directories = {
        "data_file_directories": [SCYLLA_CONFIGURE_DIRECTORIES[0]],
        "commitlog_directory": SCYLLA_CONFIGURE_DIRECTORIES[1],
        "hints_directory": SCYLLA_CONFIGURE_DIRECTORIES[2],
        "view_hints_directory": SCYLLA_CONFIGURE_DIRECTORIES[3],
    }
    config: dict[str, object] = {
        "api_address": address,
        "broadcast_address": address,
        "broadcast_rpc_address": address,
        "cluster_name": cluster_name,
        **directories,
        "endpoint_snitch": "GossipingPropertyFileSnitch",
        "listen_address": address,
        "prometheus_address": address,
        "rpc_address": address,
        "seed_provider": [
            {
                "class_name": "org.apache.cassandra.locator.SimpleSeedProvider",
                "parameters": [{"seeds": ",".join(seed_addresses)}],
            }
        ],
    }
    if tuple(sorted(config)) != SCYLLA_CONFIGURE_KEYS:
        raise AssertionError("internal Scylla configuration allowlist conflict")
    topology: dict[str, str] = {
        "cluster_name": cluster_name,
        "datacenter": datacenter,
        "rack": rack,
    }
    file_contents = _render_configuration_files(config, topology)
    file_digests = {
        name: "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()
        for name, content in file_contents.items()
    }
    config_digest = _object_digest(file_digests)
    topology_digest = _object_digest(topology)
    if prior_configuration is not None and (
        prior_configuration.logical_id != logical_id
        or prior_configuration.status
        not in {ScyllaConfigureStatus.CHANGED, ScyllaConfigureStatus.NOOP}
        or prior_configuration.topology_digest != topology_digest
    ):
        raise StateConflictError(
            "Scylla cluster name or datacenter/rack relabel drift is refused"
        )
    provenance = {
        "base_os_digest": _object_digest(_base_os_object(base_os)),
        "cluster_spec_digest": _require_digest(cluster_spec_digest),
        "inventory_digest": inventory.digest,
        "observation_digest": observed.digest,
        "scylla_install_digest": _object_digest(_install_object(install)),
        "storage_postcheck_digest": _object_digest(_storage_object(storage)),
        "trust_digest": _require_digest(readiness.trust_digest),
    }
    install_provenance = dict(install.provenance)
    expected_install_provenance = {
        "base_os_digest": provenance["base_os_digest"],
        "cluster_spec_digest": provenance["cluster_spec_digest"],
        "inventory_digest": provenance["inventory_digest"],
        "observation_digest": provenance["observation_digest"],
        "storage_postcheck_digest": provenance["storage_postcheck_digest"],
        "trust_digest": provenance["trust_digest"],
    }
    storage_provenance = dict(storage.provenance)
    if (
        install_provenance != expected_install_provenance
        or storage_provenance.get("inventory_digest") != inventory.digest
        or storage_provenance.get("observation_digest") != observed.digest
    ):
        raise StateConflictError("Scylla configure prerequisite digests conflict")
    return {
        "architecture": architecture,
        "cluster_uuid": str(metadata.cluster_uuid),
        "config": config,
        "config_digest": config_digest,
        "configuration_state": "existing" if prior_configuration else "initial",
        "file_digests": file_digests,
        "logical_id": logical_id,
        "package_version": package_version,
        "provenance": provenance,
        "release_line": SCYLLA_RELEASE_LINE,
        "runtime_validation_performed": False,
        "schema_version": SCYLLA_CONFIGURE_SCHEMA_VERSION,
        "seed_digest": seed_policy.digest,
        "seed_stable_ids": list(seed_policy.stable_ids),
        "topology": topology,
        "topology_digest": topology_digest,
        "previous_config_digest": (
            prior_configuration.config_digest
            if prior_configuration is not None
            else None
        ),
    }


def parse_scylla_configure_execution(
    stdout: str,
    *,
    expected_payload: dict[str, object],
    exit_code: int,
) -> ScyllaConfigureEvidence:
    """Parse only the bounded normalized configure result and recap."""

    if len(stdout.encode("utf-8")) > 512 * 1024:
        raise AnsibleError("Ansible Scylla configure output exceeds the evidence limit")
    values: list[dict[str, object]] = []
    for line in stdout.splitlines():
        if "DSV_SCYLLA_CONFIGURE_B64=" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            raise AnsibleError("Ansible Scylla configure marker is malformed")
        try:
            decoded = base64.b64decode(match.group("data"), validate=True)
            value = json.loads(
                decoded.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (binascii.Error, UnicodeError, ValueError) as error:
            raise AnsibleError(
                "Ansible Scylla configure marker is malformed"
            ) from error
        if not isinstance(value, dict):
            raise AnsibleError("Ansible Scylla configure evidence is malformed")
        values.append(value)
    logical_id = _text(expected_payload["logical_id"])
    rows = _parse_recap(stdout)
    if set(rows) != {logical_id}:
        raise AnsibleError("Ansible Scylla configure recap membership conflicts")
    recap_failed = bool(rows[logical_id][1] or rows[logical_id][2])
    if not values:
        if not recap_failed or exit_code == 0:
            raise AnsibleError("Ansible Scylla configure evidence is incomplete")
        return _failed_evidence(expected_payload)
    if len(values) != 1:
        raise AnsibleError("Ansible Scylla configure evidence is duplicated")
    evidence = _parse_result(values[0], expected_payload)
    failed = evidence.status is ScyllaConfigureStatus.FAILED
    if recap_failed != failed or (exit_code == 0) == failed:
        raise AnsibleError("Ansible Scylla configure exit status conflicts")
    changed = evidence.status is ScyllaConfigureStatus.CHANGED
    if bool(rows[logical_id][0]) != changed:
        raise AnsibleError("Ansible Scylla configure changed status conflicts")
    return evidence


def _parse_result(
    value: dict[str, object], expected: dict[str, object]
) -> ScyllaConfigureEvidence:
    fields = {
        "blockers",
        "bootstrap_performed",
        "config_digest",
        "configuration_file_digests",
        "files_mode_0644",
        "files_root_owned",
        "firewall_operation_performed",
        "installed_version",
        "logical_id",
        "manager_operation_performed",
        "package_install_performed",
        "prerequisite_digests",
        "runtime_validation_performed",
        "schema_version",
        "seed_digest",
        "service_inactive",
        "service_masked",
        "service_started",
        "ssh_operation_performed",
        "status",
        "storage_mutation_performed",
        "topology_digest",
        "tuning_performed",
    }
    if (
        set(value) != fields
        or value["schema_version"] != SCYLLA_CONFIGURE_SCHEMA_VERSION
    ):
        raise AnsibleError("Ansible Scylla configure evidence schema is invalid")
    logical_id = _text(value["logical_id"])
    if logical_id != expected["logical_id"]:
        raise AnsibleError("Ansible Scylla configure evidence conflicts")
    try:
        status = ScyllaConfigureStatus(_text(value["status"]))
    except ValueError as error:
        raise AnsibleError("Ansible Scylla configure status is invalid") from error
    config_digest = _require_digest(value["config_digest"])
    topology_digest = _require_digest(value["topology_digest"])
    seed_digest = _require_digest(value["seed_digest"])
    if (
        config_digest != expected["config_digest"]
        or topology_digest != expected["topology_digest"]
        or seed_digest != expected["seed_digest"]
    ):
        raise AnsibleError("Ansible Scylla configure digests conflict")
    provenance_value = value["prerequisite_digests"]
    expected_provenance = cast(dict[str, object], expected["provenance"])
    if (
        not isinstance(provenance_value, dict)
        or provenance_value != expected_provenance
    ):
        raise AnsibleError("Ansible Scylla configure provenance conflicts")
    provenance = tuple(
        sorted(
            (_text(name), _require_digest(item))
            for name, item in provenance_value.items()
        )
    )
    blockers = _sorted_strings(value["blockers"])
    if not set(blockers) <= _BLOCKERS:
        raise AnsibleError("Ansible Scylla configure blocker is unknown")
    installed = _optional_text(value["installed_version"])
    masked = _optional_bool(value["service_masked"])
    inactive = _optional_bool(value["service_inactive"])
    files_root_owned = _optional_bool(value["files_root_owned"])
    files_mode_0644 = _optional_bool(value["files_mode_0644"])
    file_digests = _digest_mapping(
        value["configuration_file_digests"], "configuration file digests"
    )
    runtime_validation = value["runtime_validation_performed"]
    if runtime_validation is not False:
        raise AnsibleError("Scylla runtime validation must be reported not performed")
    prohibited = tuple(
        _required_bool(value[name], name)
        for name in (
            "package_install_performed",
            "storage_mutation_performed",
            "tuning_performed",
            "firewall_operation_performed",
            "ssh_operation_performed",
            "manager_operation_performed",
            "service_started",
            "bootstrap_performed",
        )
    )
    if any(prohibited):
        raise AnsibleError("Ansible Scylla configure reported a prohibited action")
    success = status in {ScyllaConfigureStatus.CHANGED, ScyllaConfigureStatus.NOOP}
    expected_files = cast(dict[str, object], expected["file_digests"])
    if success and (
        installed != expected["package_version"]
        or masked is not True
        or inactive is not True
        or files_root_owned is not True
        or files_mode_0644 is not True
        or dict(file_digests) != expected_files
        or set(dict(file_digests)) != {"cassandra-rackdc.properties", "scylla.yaml"}
        or blockers
    ):
        raise AnsibleError("Ansible Scylla configure success evidence conflicts")
    if status is ScyllaConfigureStatus.NOT_PREDICTED and (
        installed is not None
        or masked is not None
        or inactive is not None
        or files_root_owned is not None
        or files_mode_0644 is not None
        or file_digests
        or blockers
    ):
        raise AnsibleError("Ansible Scylla configure check evidence conflicts")
    if status is ScyllaConfigureStatus.FAILED and (
        installed is not None
        or masked is not None
        or inactive is not None
        or files_root_owned is not None
        or files_mode_0644 is not None
        or file_digests
        or not blockers
    ):
        raise AnsibleError("Ansible Scylla configure failure evidence conflicts")
    return ScyllaConfigureEvidence(
        logical_id=logical_id,
        status=status,
        config_digest=config_digest,
        topology_digest=topology_digest,
        seed_digest=seed_digest,
        configuration_file_digests=file_digests,
        files_root_owned=files_root_owned,
        files_mode_0644=files_mode_0644,
        installed_version=installed,
        service_masked=masked,
        service_inactive=inactive,
        runtime_validation_performed=False,
        package_install_performed=prohibited[0],
        storage_mutation_performed=prohibited[1],
        tuning_performed=prohibited[2],
        firewall_operation_performed=prohibited[3],
        ssh_operation_performed=prohibited[4],
        manager_operation_performed=prohibited[5],
        service_started=prohibited[6],
        bootstrap_performed=prohibited[7],
        prerequisite_digests=provenance,
        blockers=blockers,
    )


def _validate_current_provenance(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    readiness: ReadinessReport,
) -> None:
    record = inventory.record
    if (
        metadata.cluster_uuid != record.cluster_uuid
        or metadata.cluster_name != record.cluster_name
        or metadata.provider != record.provider
        or observed.record.cluster_uuid != record.cluster_uuid
        or observed.record.cluster_name != record.cluster_name
        or readiness.observation_generation != observed.record.generation
        or readiness.observation_digest != observed.digest
        or readiness.inventory_generation != record.generation
        or readiness.inventory_digest != inventory.digest
        or readiness.trust_generation is None
        or readiness.trust_digest is None
    ):
        raise StateConflictError("Scylla configure input provenance conflicts")


def _validate_prerequisites(
    base_os: BaseOsEvidence,
    storage: StoragePostcheckEvidence,
    install: ScyllaInstallEvidence,
    *,
    logical_id: str,
    package_version: str,
) -> None:
    if (
        len(base_os.hosts) != 1
        or base_os.hosts[0].logical_id != logical_id
        or base_os.hosts[0].status not in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
        or base_os.hosts[0].reboot_required
        or storage.logical_id != logical_id
        or not storage.readiness_for_scylla
        or install.logical_id != logical_id
        or install.status
        not in {ScyllaInstallStatus.INSTALLED, ScyllaInstallStatus.NO_CHANGE}
        or install.requested_version != package_version
        or install.requested_edition != "enterprise"
        or install.installed_edition != "enterprise"
        or install.installed_version != package_version
        or install.service_masked is not True
        or install.service_inactive is not True
    ):
        raise StateConflictError(
            "Scylla configure requires current base-os, storage, and install evidence"
        )


def _validate_seed_policy(
    policy: ScyllaSeedPolicy,
    hosts: tuple[InventoryHost, ...],
    target_logical_id: str,
) -> None:
    host_ids = {host.logical_id for host in hosts}
    if (
        not policy.stable_ids
        or len(policy.stable_ids) > SCYLLA_CONFIGURE_MAX_SEEDS
        or len(set(policy.stable_ids)) != len(policy.stable_ids)
        or not all(_LOGICAL_ID.fullmatch(value) for value in policy.stable_ids)
        or not set(policy.stable_ids) <= host_ids
        or policy.digest
        != _object_digest(
            {"mode": policy.mode.value, "stable_ids": list(policy.stable_ids)}
        )
    ):
        raise StateConflictError("Scylla seed policy is invalid")
    if (
        len(hosts) > 1
        and policy.mode is not SeedSelectionMode.INITIAL
        and policy.stable_ids == (target_logical_id,)
    ):
        raise StateConflictError("multi-node Scylla seed policy cannot be self-only")


def _scylla_hosts(inventory: StoredInventoryRecord) -> tuple[InventoryHost, ...]:
    hosts = tuple(
        host for host in inventory.record.inventory.hosts if host.role.value == "scylla"
    )
    if not hosts:
        raise StateConflictError("Scylla inventory membership is empty")
    return hosts


def _private_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise StateConflictError("Scylla private address is invalid") from error
    networks = tuple(
        ipaddress.ip_network(item)
        for item in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    )
    if not isinstance(address, ipaddress.IPv4Address) or not any(
        address in network for network in networks
    ):
        raise StateConflictError("Scylla address must be private RFC 1918 IPv4")
    return str(address)


def _normalized_label(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or unicodedata.normalize("NFKC", value) != value
        or _TOPOLOGY_LABEL.fullmatch(value) is None
    ):
        raise StateConflictError(f"{label} is not strictly normalized")
    return value


def _ordered_unique_ids(values: tuple[str, ...], label: str) -> None:
    if values != tuple(sorted(set(values))) or not all(
        _LOGICAL_ID.fullmatch(value) for value in values
    ):
        raise StateConflictError(f"{label} is not uniquely sorted")


def _failed_evidence(expected: dict[str, object]) -> ScyllaConfigureEvidence:
    provenance = cast(dict[str, object], expected["provenance"])
    return ScyllaConfigureEvidence(
        _text(expected["logical_id"]),
        ScyllaConfigureStatus.FAILED,
        _require_digest(expected["config_digest"]),
        _require_digest(expected["topology_digest"]),
        _require_digest(expected["seed_digest"]),
        (),
        None,
        None,
        None,
        None,
        None,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        tuple(
            sorted(
                (_text(name), _require_digest(value))
                for name, value in provenance.items()
            )
        ),
        ("execution-failed",),
    )


def _parse_recap(stdout: str) -> dict[str, tuple[int, int, int]]:
    recap = stdout.partition("PLAY RECAP")
    if not recap[1]:
        raise AnsibleError("Ansible Scylla configure output omitted PLAY RECAP")
    rows: dict[str, tuple[int, int, int]] = {}
    for line in recap[2].splitlines():
        if not line.strip() or set(line.strip()) == {"*"}:
            continue
        match = _RECAP.fullmatch(line.strip())
        if match is None or match.group("host") in rows:
            raise AnsibleError("Ansible Scylla configure recap is malformed")
        rows[match.group("host")] = (
            int(match.group("changed")),
            int(match.group("unreachable")),
            int(match.group("failed")),
        )
    return rows


def _base_os_object(value: BaseOsEvidence) -> object:
    return {
        "hosts": [
            {
                "changed": host.changed,
                "logical_id": host.logical_id,
                "reason": host.reason,
                "reboot_required": host.reboot_required,
                "status": host.status.value,
            }
            for host in value.hosts
        ],
        "status": value.status.value,
    }


def _storage_object(value: StoragePostcheckEvidence) -> object:
    return {
        "backend": value.backend,
        "blockers": list(value.blockers),
        "checks": [(item.name, item.status.value) for item in value.checks],
        "devices": list(value.devices),
        "layout": value.layout,
        "logical_id": value.logical_id,
        "provenance": dict(value.provenance),
        "readiness_for_scylla": value.readiness_for_scylla,
    }


def _install_object(value: ScyllaInstallEvidence) -> object:
    return {
        "blockers": list(value.blockers),
        "installed_edition": value.installed_edition,
        "installed_version": value.installed_version,
        "logical_id": value.logical_id,
        "packages": dict(value.packages),
        "provenance": dict(value.provenance),
        "repository_digest": value.repository_digest,
        "requested_edition": value.requested_edition,
        "requested_version": value.requested_version,
        "service_inactive": value.service_inactive,
        "service_masked": value.service_masked,
        "signing_key_digest": value.signing_key_digest,
        "signing_key_fingerprint": value.signing_key_fingerprint,
        "status": value.status.value,
    }


def _object_digest(value: object) -> str:
    data = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _render_configuration_files(
    config: dict[str, object], topology: dict[str, str]
) -> dict[str, str]:
    seed_provider = cast(list[dict[str, object]], config["seed_provider"])
    parameters = cast(list[dict[str, str]], seed_provider[0]["parameters"])
    data_directories = cast(list[str], config["data_file_directories"])

    def quote(value: object) -> str:
        return json.dumps(value, ensure_ascii=True)

    scylla_yaml = (
        f"cluster_name: {quote(config['cluster_name'])}\n"
        f"listen_address: {config['listen_address']}\n"
        f"broadcast_address: {config['broadcast_address']}\n"
        f"rpc_address: {config['rpc_address']}\n"
        f"broadcast_rpc_address: {config['broadcast_rpc_address']}\n"
        "seed_provider:\n"
        "  - class_name: org.apache.cassandra.locator.SimpleSeedProvider\n"
        "    parameters:\n"
        f"      - seeds: {quote(parameters[0]['seeds'])}\n"
        "data_file_directories:\n"
        f"  - {data_directories[0]}\n"
        f"commitlog_directory: {config['commitlog_directory']}\n"
        f"hints_directory: {config['hints_directory']}\n"
        f"view_hints_directory: {config['view_hints_directory']}\n"
        f"api_address: {config['api_address']}\n"
        f"prometheus_address: {config['prometheus_address']}\n"
        "endpoint_snitch: GossipingPropertyFileSnitch\n"
    )
    rackdc = (
        f"dc={topology['datacenter']}\nrack={topology['rack']}\nprefer_local=true\n"
    )
    return {
        "cassandra-rackdc.properties": rackdc,
        "scylla.yaml": scylla_yaml,
    }


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AnsibleError("Ansible Scylla configure evidence has duplicate fields")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise AnsibleError(f"invalid Scylla configure constant: {value}")


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value:
        raise AnsibleError("Ansible Scylla configure value is invalid")
    return value


def _optional_text(value: object) -> str | None:
    return None if value is None else _text(value)


def _optional_bool(value: object) -> bool | None:
    if value is not None and not isinstance(value, bool):
        raise AnsibleError("Ansible Scylla configure boolean is invalid")
    return value


def _required_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise AnsibleError(f"Ansible Scylla configure {label} is invalid")
    return value


def _digest_mapping(value: object, label: str) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and key for key in value
    ):
        raise AnsibleError(f"Ansible Scylla configure {label} is invalid")
    return tuple(
        sorted((_text(key), _require_digest(item)) for key, item in value.items())
    )


def _require_digest(value: object) -> str:
    text = _text(value)
    if _DIGEST.fullmatch(text) is None:
        raise AnsibleError("Ansible Scylla configure digest is invalid")
    return text


def _sorted_strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AnsibleError("Ansible Scylla configure blockers are invalid")
    items = tuple(_text(item) for item in value)
    if items != tuple(sorted(set(items))):
        raise AnsibleError("Ansible Scylla configure blockers are not uniquely sorted")
    return items
