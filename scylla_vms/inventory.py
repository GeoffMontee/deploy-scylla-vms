"""Deterministic Ansible inventory projection and protected persistence."""

import ipaddress
import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, cast

from scylla_vms.desired import ClusterSpec, HostRole
from scylla_vms.errors import (
    ConfigurationError,
    StateConflictError,
    StatePersistenceError,
)
from scylla_vms.observed import StoredObservedState
from scylla_vms.persistence import (
    AtomicJsonFile,
    ClusterMetadata,
    digest_bytes,
    format_timestamp,
    parse_timestamp,
    parse_uuid,
    require_exact_keys,
    require_string,
    serialize_json,
    validate_digest,
)
from scylla_vms.providers import get_provider
from scylla_vms.reconciliation import (
    ReconciliationClass,
    ReconciliationReport,
    reconcile_desired_observed,
)
from scylla_vms.state import StatePaths, validate_cluster_name, validate_state_file
from scylla_vms.terraform.outputs import TerraformHost, TerraformHostManifest

if TYPE_CHECKING:
    from scylla_vms.locking import ClusterLock

INVENTORY_SCHEMA_VERSION = "deploy-scylla-vms.inventory/v1"
ANSIBLE_INVENTORY_SCHEMA_VERSION = "deploy-scylla-vms.ansible-inventory/v1"
_GROUP_COMPONENT = re.compile(r"[^a-z0-9_]")
_GROUP_NAME = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_PROVIDER_ID = re.compile(r"ocid1\.instance\.[A-Za-z0-9._:+/-]+\Z")
_SSH_USER = re.compile(r"[a-z_][a-z0-9_-]{0,63}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SECRET_KEY = re.compile(
    r"(?i)(?:password|passphrase|secret|token|private[_-]?key|credential)"
)
_SECRET_VALUE = re.compile(
    r"(?i)(?:-----BEGIN [^-]*PRIVATE KEY-----|"
    r"(?:password|passphrase|secret|token)\s*[:=])"
)
_BASE_GROUPS = ("jump_hosts", "manager", "monitoring", "scylla")
_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


class HostTrustStatus(StrEnum):
    UNAVAILABLE = "unavailable"
    VERIFIED = "verified"
    CONFLICT = "conflict"


@dataclass(frozen=True, slots=True)
class InventoryHost:
    logical_id: str
    role: HostRole
    zone: str
    provider_id: str
    private_address: str
    public_address: str | None
    ansible_host: str
    ansible_user: str
    shape: str
    scylla_datacenter: str | None
    scylla_rack: str | None
    route_mode: str
    jump_host_id: str | None
    selected_storage_backend: str
    storage_device_count: int
    storage_raw_gib: int
    storage_usable_gib: int
    storage_ephemeral: bool
    storage_generation: int
    storage_policy_digest: str

    def __post_init__(self) -> None:
        if not _LOGICAL_ID.fullmatch(self.logical_id):
            raise StatePersistenceError("inventory logical host ID is invalid")
        if not isinstance(self.role, HostRole):
            raise StatePersistenceError("inventory host role is invalid")
        if not self.zone.isascii() or not self.zone or len(self.zone) > 255:
            raise StatePersistenceError("inventory host zone is invalid")
        if not _PROVIDER_ID.fullmatch(self.provider_id):
            raise StatePersistenceError("inventory provider ID is invalid")
        _address(self.private_address)
        if self.public_address is not None:
            _address(self.public_address)
        expected_ansible_host = (
            self.public_address
            if self.role is HostRole.JUMP_HOST and self.public_address is not None
            else self.private_address
        )
        if self.ansible_host != expected_ansible_host:
            raise StatePersistenceError("inventory connection address conflicts")
        if not _SSH_USER.fullmatch(self.ansible_user):
            raise StatePersistenceError("inventory SSH user is invalid")
        if not self.shape or not self.shape.isascii():
            raise StatePersistenceError("inventory shape is invalid")
        if self.role is HostRole.SCYLLA:
            if self.scylla_datacenter is None or self.scylla_rack is None:
                raise StatePersistenceError("inventory Scylla topology is incomplete")
        elif self.scylla_datacenter is not None or self.scylla_rack is not None:
            raise StatePersistenceError("inventory non-Scylla topology must be null")
        if self.route_mode not in {"direct", "proxy-jump"} or (
            (self.route_mode == "proxy-jump") != (self.jump_host_id is not None)
        ):
            raise StatePersistenceError("inventory route metadata is invalid")
        if self.role is HostRole.JUMP_HOST and self.jump_host_id is not None:
            raise StatePersistenceError("inventory jump host route is invalid")
        if (
            any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in (
                    self.storage_device_count,
                    self.storage_raw_gib,
                    self.storage_usable_gib,
                    self.storage_generation,
                )
            )
            or self.storage_generation < 1
        ):
            raise StatePersistenceError("inventory storage metadata is invalid")
        if self.selected_storage_backend not in {
            "local-nvme",
            "block-volume",
            "boot-only",
        }:
            raise StatePersistenceError("inventory storage backend is invalid")
        if not isinstance(self.storage_ephemeral, bool) or not _DIGEST.fullmatch(
            self.storage_policy_digest
        ):
            raise StatePersistenceError("inventory storage metadata is invalid")

    def to_hostvars(self) -> dict[str, object]:
        return {
            "ansible_host": self.ansible_host,
            "ansible_user": self.ansible_user,
            "deploy_scylla_vms_jump_host_id": self.jump_host_id,
            "deploy_scylla_vms_logical_id": self.logical_id,
            "deploy_scylla_vms_private_address": self.private_address,
            "deploy_scylla_vms_provider_id": self.provider_id,
            "deploy_scylla_vms_public_address": self.public_address,
            "deploy_scylla_vms_role": self.role.value,
            "deploy_scylla_vms_route_mode": self.route_mode,
            "deploy_scylla_vms_scylla_datacenter": self.scylla_datacenter,
            "deploy_scylla_vms_scylla_rack": self.scylla_rack,
            "deploy_scylla_vms_shape": self.shape,
            "deploy_scylla_vms_storage": {
                "device_count": self.storage_device_count,
                "ephemeral": self.storage_ephemeral,
                "generation": self.storage_generation,
                "policy_digest": self.storage_policy_digest,
                "raw_gib": self.storage_raw_gib,
                "selected_backend": self.selected_storage_backend,
                "usable_gib": self.storage_usable_gib,
            },
            "deploy_scylla_vms_zone": self.zone,
        }


@dataclass(frozen=True, slots=True)
class InventoryGroup:
    name: str
    hosts: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not _GROUP_NAME.fullmatch(self.name)
            or self.hosts != tuple(sorted(set(self.hosts)))
            or not all(_LOGICAL_ID.fullmatch(host) for host in self.hosts)
        ):
            raise StatePersistenceError("inventory group is invalid")


@dataclass(frozen=True, slots=True)
class InventoryModel:
    hosts: tuple[InventoryHost, ...]
    groups: tuple[InventoryGroup, ...]
    host_trust_status: HostTrustStatus
    schema_version: str = ANSIBLE_INVENTORY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != ANSIBLE_INVENTORY_SCHEMA_VERSION:
            raise StatePersistenceError("Ansible inventory schema is unsupported")
        host_ids = tuple(host.logical_id for host in self.hosts)
        group_names = tuple(group.name for group in self.groups)
        if (
            host_ids != tuple(sorted(set(host_ids)))
            or group_names != tuple(sorted(set(group_names)))
            or not isinstance(self.host_trust_status, HostTrustStatus)
            or any(
                host not in host_ids for group in self.groups for host in group.hosts
            )
        ):
            raise StatePersistenceError("Ansible inventory ordering is invalid")
        by_id = {host.logical_id: host for host in self.hosts}
        for host in self.hosts:
            if host.jump_host_id is not None:
                jump = by_id.get(host.jump_host_id)
                if jump is None or jump.role is not HostRole.JUMP_HOST:
                    raise StatePersistenceError("inventory jump route is invalid")
        try:
            expected_groups = _groups_for_hosts(self.hosts)
        except StateConflictError as error:
            raise StatePersistenceError(
                "inventory group derivation conflicts"
            ) from error
        if self.groups != expected_groups:
            raise StatePersistenceError("inventory groups conflict with host metadata")

    def to_object(self) -> dict[str, object]:
        value: dict[str, object] = {
            "_meta": {
                "hostvars": {host.logical_id: host.to_hostvars() for host in self.hosts}
            },
            "all": {
                "children": [group.name for group in self.groups],
                "vars": {
                    "deploy_scylla_vms_host_key_checking_required": True,
                    "deploy_scylla_vms_host_trust_status": self.host_trust_status.value,
                    "deploy_scylla_vms_inventory_schema": self.schema_version,
                },
            },
        }
        value.update(
            {group.name: {"hosts": list(group.hosts)} for group in self.groups}
        )
        return value


def build_inventory(
    spec: ClusterSpec,
    manifest: TerraformHostManifest,
    *,
    host_trust_status: HostTrustStatus = HostTrustStatus.UNAVAILABLE,
) -> InventoryModel:
    """Build a stable inventory without raw SSH arguments or invented host trust."""

    reconciliation = reconcile_desired_observed(spec, manifest)
    if reconciliation.status is not ReconciliationClass.MATCH:
        raise StateConflictError(
            "inventory generation requires matching desired and observed state"
        )
    hosts = tuple(_inventory_host(host, spec) for host in manifest.hosts)
    _validate_inventory_network_policy(hosts)
    groups = _groups_for_hosts(hosts)
    return InventoryModel(hosts, groups, host_trust_status)


def _inventory_host(host: TerraformHost, spec: ClusterSpec) -> InventoryHost:
    ansible_host = (
        host.public_address
        if host.role is HostRole.JUMP_HOST and host.public_address is not None
        else host.private_address
    )
    route_mode = "proxy-jump" if host.jump_host_id is not None else "direct"
    return InventoryHost(
        host.logical_id,
        host.role,
        host.zone,
        host.provider_id,
        host.private_address,
        host.public_address,
        ansible_host,
        spec.network.ssh_user,
        host.shape,
        host.scylla_datacenter,
        host.scylla_rack,
        route_mode,
        host.jump_host_id,
        host.storage.selected_backend.value,
        host.storage.expected_device_count,
        host.storage.raw_total_gib,
        host.storage.usable_total_gib,
        bool(host.storage.devices)
        and all(device.ephemeral for device in host.storage.devices),
        host.storage.storage_generation,
        host.storage.policy_digest,
    )


def _validate_inventory_network_policy(hosts: tuple[InventoryHost, ...]) -> None:
    for host in hosts:
        private_address = ipaddress.ip_address(host.private_address)
        if not isinstance(private_address, ipaddress.IPv4Address) or not any(
            private_address in network for network in _RFC1918_NETWORKS
        ):
            raise StatePersistenceError(
                "inventory private address must use RFC 1918 IPv4"
            )
        if host.public_address is not None and host.role is not HostRole.JUMP_HOST:
            raise StatePersistenceError(
                "inventory public address is restricted to jump hosts"
            )


def _role_group(role: HostRole) -> str:
    return {
        HostRole.SCYLLA: "scylla",
        HostRole.MANAGER: "manager",
        HostRole.MONITORING: "monitoring",
        HostRole.JUMP_HOST: "jump_hosts",
    }[role]


def _derived_group(prefix: str, value: str, sources: dict[str, str]) -> str:
    component = _GROUP_COMPONENT.sub("_", value.lower()).strip("_")
    component = re.sub(r"_+", "_", component)
    if not component:
        raise StateConflictError("inventory group label is empty after normalization")
    group = f"{prefix}_{component}"
    source = f"{prefix}:{value}"
    existing = sources.setdefault(group, source)
    if existing != source or group in _BASE_GROUPS or group in {"all", "_meta"}:
        raise StateConflictError("inventory group normalization collision")
    return group


def _groups_for_hosts(hosts: tuple[InventoryHost, ...]) -> tuple[InventoryGroup, ...]:
    group_sources: dict[str, str] = {}
    members: dict[str, list[str]] = {name: [] for name in _BASE_GROUPS}
    for host in hosts:
        members[_role_group(host.role)].append(host.logical_id)
        zone_group = _derived_group("zone", host.zone, group_sources)
        members.setdefault(zone_group, []).append(host.logical_id)
        if host.role is HostRole.SCYLLA:
            if host.scylla_datacenter is None or host.scylla_rack is None:
                raise StateConflictError("Scylla inventory topology is incomplete")
            dc_group = _derived_group(
                "scylla_dc", host.scylla_datacenter, group_sources
            )
            rack_group = _derived_group("scylla_rack", host.scylla_rack, group_sources)
            members.setdefault(dc_group, []).append(host.logical_id)
            members.setdefault(rack_group, []).append(host.logical_id)
    return tuple(
        InventoryGroup(name, tuple(sorted(members[name]))) for name in sorted(members)
    )


@dataclass(frozen=True, slots=True)
class InventoryRecord:
    generation: int
    cluster_uuid: uuid.UUID
    cluster_name: str
    provider: str
    captured_at: str
    source_manifest_generation: int
    source_manifest_digest: str
    inventory_digest: str
    inventory: InventoryModel
    schema_version: str = INVENTORY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != INVENTORY_SCHEMA_VERSION:
            raise StatePersistenceError("unsupported inventory record schema")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 1
            or isinstance(self.source_manifest_generation, bool)
            or not isinstance(self.source_manifest_generation, int)
            or self.source_manifest_generation < 1
        ):
            raise StatePersistenceError("inventory generations must be positive")
        if not isinstance(self.cluster_uuid, uuid.UUID):
            raise StatePersistenceError("inventory cluster UUID is invalid")
        try:
            validate_cluster_name(self.cluster_name)
            get_provider(self.provider)
        except (ConfigurationError, KeyError) as error:
            raise StatePersistenceError(
                "inventory cluster identity is invalid"
            ) from error
        parse_timestamp(self.captured_at)
        validate_digest(self.source_manifest_digest, "source manifest digest")
        validate_digest(self.inventory_digest, "inventory digest")
        if self.inventory_digest != _inventory_digest(self.inventory):
            raise StatePersistenceError("inventory digest does not match")

    def to_object(self) -> dict[str, object]:
        """Serialize canonical static JSON/YAML accepted by Ansible."""

        machine = self.to_machine_object()
        all_group = cast(dict[str, object], machine["all"])
        variables = cast(dict[str, object], all_group["vars"])
        hostvars = cast(
            dict[str, object],
            cast(dict[str, object], machine["_meta"])["hostvars"],
        )
        groups: dict[str, object] = {
            group.name: {"hosts": {logical_id: {} for logical_id in group.hosts}}
            for group in self.inventory.groups
        }
        return {
            "all": {
                "children": groups,
                "hosts": hostvars,
                "vars": variables,
            }
        }

    def to_machine_object(self) -> dict[str, object]:
        """Return the exact normalized ``ansible-inventory --list`` shape."""

        value = self.inventory.to_object()
        all_group = cast(dict[str, object], value["all"])
        variables = cast(dict[str, object], all_group["vars"])
        variables["deploy_scylla_vms_record"] = {
            "captured_at": self.captured_at,
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "generation": self.generation,
            "inventory_digest": self.inventory_digest,
            "provider": self.provider,
            "schema_version": self.schema_version,
            "source_manifest_digest": self.source_manifest_digest,
            "source_manifest_generation": self.source_manifest_generation,
        }
        return value


@dataclass(frozen=True, slots=True)
class StoredInventoryRecord:
    record: InventoryRecord
    digest: str


class InventoryStore:
    """Strict atomic inventory record at the canonical Ansible path."""

    def __init__(
        self,
        paths: StatePaths,
        *,
        replace: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self._paths = paths
        self._file = AtomicJsonFile(
            paths.ansible_inventory,
            replace=replace,
            token_factory=token_factory,
        )

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
        expected_provider: str,
    ) -> StoredInventoryRecord:
        value, digest = self._file.read()
        record = _inventory_record_from_object(value)
        if (
            record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or record.provider != expected_provider
        ):
            raise StatePersistenceError("persisted inventory identity conflicts")
        return StoredInventoryRecord(record, digest)

    def write_locked(
        self,
        record: InventoryRecord,
        *,
        expected_generation: int,
        expected_digest: str | None,
        approved: bool,
        lock: "ClusterLock",
    ) -> StoredInventoryRecord:
        lock.assert_held_for(self._paths)
        if not approved:
            raise StateConflictError("inventory replacement requires explicit approval")
        validate_state_file(self._paths.ansible_inventory, allow_missing=True)
        exists = self._paths.ansible_inventory.exists()
        if not exists:
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial inventory write requires generation one"
                )
        else:
            current = self.read(
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
                expected_provider=record.provider,
            )
            if (
                expected_digest is None
                or current.digest != expected_digest
                or current.record.generation != expected_generation
            ):
                raise StatePersistenceError("inventory changed concurrently")
            if record.generation != current.record.generation + 1:
                raise StatePersistenceError(
                    "inventory generation must increase by exactly one"
                )
            if record.source_manifest_generation < (
                current.record.source_manifest_generation
            ) or (
                record.source_manifest_generation
                == current.record.source_manifest_generation
                and record.source_manifest_digest
                != current.record.source_manifest_digest
            ):
                raise StatePersistenceError(
                    "inventory source manifest generation regressed or conflicted"
                )
            if parse_timestamp(record.captured_at) < parse_timestamp(
                current.record.captured_at
            ):
                raise StatePersistenceError("inventory timestamp regressed")
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredInventoryRecord(record, digest)


@dataclass(frozen=True, slots=True)
class InventoryChange:
    change_class: str
    logical_id: str | None
    field: str


@dataclass(frozen=True, slots=True)
class InventoryRefreshResult:
    reconciliation: ReconciliationReport
    candidate: InventoryRecord | None
    changes: tuple[InventoryChange, ...]
    fresh: bool
    conflict_free: bool
    host_trust_ready: bool


class InventoryRefreshService:
    """Prepare and explicitly persist local inventory refreshes without Ansible."""

    def __init__(self, paths: StatePaths, store: InventoryStore | None = None) -> None:
        self._store = store or InventoryStore(paths)

    def prepare(
        self,
        metadata: ClusterMetadata,
        observed: StoredObservedState,
        current: StoredInventoryRecord | None,
        *,
        clock: Callable[[], datetime],
    ) -> InventoryRefreshResult:
        return prepare_inventory_refresh(metadata, observed, current, clock=clock)

    def write(
        self,
        result: InventoryRefreshResult,
        current: StoredInventoryRecord | None,
        *,
        approved: bool,
        lock: "ClusterLock",
    ) -> StoredInventoryRecord:
        if result.candidate is None or not result.conflict_free:
            raise StateConflictError(
                "conflicting inventory candidate cannot be written"
            )
        return self._store.write_locked(
            result.candidate,
            expected_generation=0 if current is None else current.record.generation,
            expected_digest=None if current is None else current.digest,
            approved=approved,
            lock=lock,
        )


def prepare_inventory_refresh(
    metadata: ClusterMetadata,
    observed: StoredObservedState,
    current: StoredInventoryRecord | None,
    *,
    clock: Callable[[], datetime],
) -> InventoryRefreshResult:
    reconciliation = reconcile_desired_observed(
        metadata.desired_spec, observed.record.manifest
    )
    if reconciliation.status is not ReconciliationClass.MATCH:
        return InventoryRefreshResult(reconciliation, None, (), False, False, False)
    model = build_inventory(metadata.desired_spec, observed.record.manifest)
    generation = 1 if current is None else current.record.generation + 1
    candidate = InventoryRecord(
        generation,
        metadata.cluster_uuid,
        metadata.cluster_name,
        metadata.provider,
        format_timestamp(clock()),
        observed.record.generation,
        observed.record.manifest_digest,
        _inventory_digest(model),
        model,
    )
    changes = _inventory_changes(current.record.inventory if current else None, model)
    fresh = (
        current is not None
        and current.record.source_manifest_generation == observed.record.generation
        and current.record.source_manifest_digest == observed.record.manifest_digest
        and current.record.inventory_digest == candidate.inventory_digest
    )
    return InventoryRefreshResult(
        reconciliation,
        candidate,
        changes,
        fresh,
        True,
        model.host_trust_status is HostTrustStatus.VERIFIED,
    )


def _inventory_record_from_object(value: Mapping[str, object]) -> InventoryRecord:
    if set(value) != {"all"}:
        raise StatePersistenceError("inventory record fields do not match the schema")
    all_group = _mapping(value["all"], "all inventory group")
    require_exact_keys(all_group, {"children", "hosts", "vars"}, "all inventory group")
    variables = _mapping(all_group["vars"], "all inventory variables")
    record = _mapping(variables.get("deploy_scylla_vms_record"), "inventory record")
    require_exact_keys(
        record,
        {
            "captured_at",
            "cluster_name",
            "cluster_uuid",
            "generation",
            "inventory_digest",
            "provider",
            "schema_version",
            "source_manifest_digest",
            "source_manifest_generation",
        },
        "inventory record",
    )
    generation = _integer(record, "generation")
    source_generation = _integer(record, "source_manifest_generation")
    model_variables = dict(variables)
    del model_variables["deploy_scylla_vms_record"]
    static_hosts = _mapping(all_group["hosts"], "inventory hosts")
    static_children = _mapping(all_group["children"], "inventory child groups")
    model_value: dict[str, object] = {
        "_meta": {"hostvars": static_hosts},
        "all": {
            "children": sorted(static_children),
            "vars": model_variables,
        },
    }
    for name in sorted(static_children):
        group = _mapping(static_children[name], "inventory child group")
        require_exact_keys(group, {"hosts"}, "inventory child group")
        group_hosts = _mapping(group["hosts"], "inventory child group hosts")
        if any(hostvars != {} for hostvars in group_hosts.values()):
            raise StatePersistenceError(
                "inventory child membership must not define host variables"
            )
        model_value[name] = {"hosts": sorted(group_hosts)}
    inventory = _inventory_model_from_object(model_value)
    result = InventoryRecord(
        generation,
        parse_uuid(require_string(record, "cluster_uuid"), "inventory cluster UUID"),
        require_string(record, "cluster_name"),
        require_string(record, "provider"),
        require_string(record, "captured_at"),
        source_generation,
        require_string(record, "source_manifest_digest"),
        require_string(record, "inventory_digest"),
        inventory,
        require_string(record, "schema_version"),
    )
    if result.to_object() != value:
        raise StatePersistenceError("inventory record is not canonical")
    return result


def _inventory_model_from_object(value: Mapping[str, object]) -> InventoryModel:
    _reject_secret_material(value)
    if "_meta" not in value or "all" not in value:
        raise StatePersistenceError("Ansible inventory fields are invalid")
    meta = _mapping(value["_meta"], "inventory metadata")
    require_exact_keys(meta, {"hostvars"}, "inventory metadata")
    hostvars = _mapping(meta["hostvars"], "inventory hostvars")
    hosts = tuple(
        _inventory_host_from_object(
            logical_id, _mapping(hostvars[logical_id], "hostvars")
        )
        for logical_id in sorted(hostvars)
    )
    all_group = _mapping(value["all"], "all inventory group")
    require_exact_keys(all_group, {"children", "vars"}, "all inventory group")
    variables = _mapping(all_group["vars"], "all inventory variables")
    require_exact_keys(
        variables,
        {
            "deploy_scylla_vms_host_key_checking_required",
            "deploy_scylla_vms_host_trust_status",
            "deploy_scylla_vms_inventory_schema",
        },
        "all inventory variables",
    )
    if variables["deploy_scylla_vms_host_key_checking_required"] is not True:
        raise StatePersistenceError("inventory must require host-key checking")
    try:
        trust = HostTrustStatus(
            require_string(variables, "deploy_scylla_vms_host_trust_status")
        )
    except ValueError as error:
        raise StatePersistenceError("inventory host trust status is invalid") from error
    if (
        require_string(variables, "deploy_scylla_vms_inventory_schema")
        != ANSIBLE_INVENTORY_SCHEMA_VERSION
    ):
        raise StatePersistenceError("Ansible inventory schema is unsupported")
    groups: list[InventoryGroup] = []
    for name in sorted(set(value) - {"_meta", "all"}):
        group = _mapping(value[name], "inventory group")
        require_exact_keys(group, {"hosts"}, "inventory group")
        group_hosts = _string_array(group["hosts"], "inventory group hosts")
        if any(logical_id not in hostvars for logical_id in group_hosts):
            raise StatePersistenceError("inventory group contains an unknown host")
        groups.append(InventoryGroup(name, group_hosts))
    children = _string_array(all_group["children"], "inventory child groups")
    if children != tuple(group.name for group in groups):
        raise StatePersistenceError("inventory child groups conflict")
    model = InventoryModel(hosts, tuple(groups), trust)
    if model.groups != _groups_for_hosts(model.hosts):
        raise StatePersistenceError("inventory groups conflict with host metadata")
    if model.to_object() != value:
        raise StatePersistenceError("inventory is not canonical")
    return model


def _inventory_host_from_object(
    logical_id: str, value: Mapping[str, object]
) -> InventoryHost:
    expected = {
        "ansible_host",
        "ansible_user",
        "deploy_scylla_vms_jump_host_id",
        "deploy_scylla_vms_logical_id",
        "deploy_scylla_vms_private_address",
        "deploy_scylla_vms_provider_id",
        "deploy_scylla_vms_public_address",
        "deploy_scylla_vms_role",
        "deploy_scylla_vms_route_mode",
        "deploy_scylla_vms_scylla_datacenter",
        "deploy_scylla_vms_scylla_rack",
        "deploy_scylla_vms_shape",
        "deploy_scylla_vms_storage",
        "deploy_scylla_vms_zone",
    }
    require_exact_keys(value, expected, "inventory hostvars")
    if require_string(value, "deploy_scylla_vms_logical_id") != logical_id:
        raise StatePersistenceError("inventory logical host identity conflicts")
    try:
        role = HostRole(require_string(value, "deploy_scylla_vms_role"))
    except ValueError as error:
        raise StatePersistenceError("inventory host role is invalid") from error
    storage = _mapping(value["deploy_scylla_vms_storage"], "inventory storage")
    require_exact_keys(
        storage,
        {
            "device_count",
            "ephemeral",
            "generation",
            "policy_digest",
            "raw_gib",
            "selected_backend",
            "usable_gib",
        },
        "inventory storage",
    )
    private_address = _address(
        require_string(value, "deploy_scylla_vms_private_address")
    )
    public_address = _optional_string(value["deploy_scylla_vms_public_address"])
    if public_address is not None:
        _address(public_address)
    host = InventoryHost(
        logical_id,
        role,
        require_string(value, "deploy_scylla_vms_zone"),
        require_string(value, "deploy_scylla_vms_provider_id"),
        private_address,
        public_address,
        _address(require_string(value, "ansible_host")),
        require_string(value, "ansible_user"),
        require_string(value, "deploy_scylla_vms_shape"),
        _optional_string(value["deploy_scylla_vms_scylla_datacenter"]),
        _optional_string(value["deploy_scylla_vms_scylla_rack"]),
        require_string(value, "deploy_scylla_vms_route_mode"),
        _optional_string(value["deploy_scylla_vms_jump_host_id"]),
        require_string(storage, "selected_backend"),
        _integer(storage, "device_count"),
        _integer(storage, "raw_gib"),
        _integer(storage, "usable_gib"),
        _boolean(storage, "ephemeral"),
        _integer(storage, "generation"),
        require_string(storage, "policy_digest"),
    )
    if host.to_hostvars() != value:
        raise StatePersistenceError("inventory hostvars are not canonical")
    return host


def _inventory_changes(
    current: InventoryModel | None, candidate: InventoryModel
) -> tuple[InventoryChange, ...]:
    if current is None:
        return tuple(
            InventoryChange("addition", host.logical_id, "membership")
            for host in candidate.hosts
        )
    before = {host.logical_id: host for host in current.hosts}
    after = {host.logical_id: host for host in candidate.hosts}
    changes: list[InventoryChange] = []
    for logical_id in sorted(set(after) - set(before)):
        changes.append(InventoryChange("addition", logical_id, "membership"))
    for logical_id in sorted(set(before) - set(after)):
        changes.append(InventoryChange("removal", logical_id, "membership"))
    fields = (
        ("identity", ("role", "provider_id")),
        ("address", ("private_address", "public_address", "ansible_host")),
        ("topology", ("zone", "scylla_datacenter", "scylla_rack")),
        ("routing", ("route_mode", "jump_host_id")),
        (
            "storage",
            (
                "selected_storage_backend",
                "storage_device_count",
                "storage_raw_gib",
                "storage_usable_gib",
                "storage_ephemeral",
                "storage_generation",
                "storage_policy_digest",
            ),
        ),
    )
    for logical_id in sorted(set(before) & set(after)):
        for change_class, names in fields:
            if any(
                getattr(before[logical_id], name) != getattr(after[logical_id], name)
                for name in names
            ):
                changes.append(InventoryChange(change_class, logical_id, change_class))
    return tuple(changes)


def _inventory_digest(inventory: InventoryModel) -> str:
    return digest_bytes(serialize_json(inventory.to_object()))


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _integer(value: Mapping[str, object], key: str) -> int:
    item = value[key]
    if isinstance(item, bool) or not isinstance(item, int) or item < 0:
        raise StatePersistenceError(f"inventory integer is invalid: {key}")
    return item


def _boolean(value: Mapping[str, object], key: str) -> bool:
    item = value[key]
    if not isinstance(item, bool):
        raise StatePersistenceError(f"inventory boolean is invalid: {key}")
    return item


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise StatePersistenceError("inventory optional string is invalid")
    return value


def _string_array(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise StatePersistenceError(f"{label} must be a string array")
    items = cast(tuple[str, ...], tuple(value))
    if items != tuple(sorted(set(items))):
        raise StatePersistenceError(f"{label} must be unique and sorted")
    return items


def _address(value: str) -> str:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as error:
        raise StatePersistenceError("inventory address is invalid") from error
    if str(parsed) != value:
        raise StatePersistenceError("inventory address is not canonical")
    return value


def _reject_secret_material(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _SECRET_KEY.search(str(key)):
                raise StatePersistenceError("inventory contains a secret-like field")
            _reject_secret_material(item)
    elif isinstance(value, list):
        for item in value:
            _reject_secret_material(item)
    elif isinstance(value, str) and _SECRET_VALUE.search(value):
        raise StatePersistenceError("inventory contains secret-like material")
