"""Immutable desired-cluster specification, compilation, and change intent."""

import hashlib
import ipaddress
import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TypeVar, cast

from scylla_vms.contracts import DESIRED_CONFIG_FIELD_NAMES
from scylla_vms.errors import ConfigurationError, StateConflictError
from scylla_vms.models import DeferredValue, OperationRequest, ValueSource
from scylla_vms.operations import OperationClassification
from scylla_vms.state import validate_cluster_name

CLUSTER_SPEC_SCHEMA_VERSION = "deploy-scylla-vms.desired/v2"
TOPOLOGY_NORMALIZATION_VERSION = "oci-ascii-slug/v1"
_TOPOLOGY_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_SHAPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SECRET_KEY = re.compile(
    r"(?:^|[_-])(?:password|passphrase|secret|token|credential|private[_-]?key)"
    r"(?:$|[_-])",
    re.IGNORECASE,
)
_EnumT = TypeVar("_EnumT", bound=StrEnum)


class HostRole(StrEnum):
    SCYLLA = "scylla"
    MANAGER = "manager"
    MONITORING = "monitoring"
    JUMP_HOST = "jump-host"


class NetworkMode(StrEnum):
    CREATE = "create"
    EXISTING = "existing"


class StorageBackend(StrEnum):
    AUTO = "auto"
    LOCAL_NVME = "local-nvme"
    BLOCK_VOLUME = "block-volume"
    BOOT_ONLY = "boot-only"


class StorageLayout(StrEnum):
    SINGLE = "single"
    RAID0 = "raid0"


class AttachmentType(StrEnum):
    ISCSI = "iscsi"
    PARAVIRTUALIZED = "paravirtualized"


class VolumeRetention(StrEnum):
    RETAIN = "retain"
    DELETE = "delete"


class ChangeDisposition(StrEnum):
    IDENTITY_ASSERTION = "identity-assertion"
    PROPOSED_CHANGE = "proposed-change"


class ImageVersionMatch(StrEnum):
    EXACT = "exact"
    PREFIX = "prefix"


@dataclass(frozen=True, slots=True)
class ImageFilter:
    operating_system: str
    operating_system_version: str
    version_match: ImageVersionMatch

    def __post_init__(self) -> None:
        _require_nonempty_ascii(
            self.operating_system, "image operating system", maximum=255
        )
        _require_nonempty_ascii(
            self.operating_system_version,
            "image operating-system version",
            maximum=255,
        )
        if not isinstance(self.version_match, ImageVersionMatch):
            raise ConfigurationError("image version-match policy is invalid")

    def to_object(self) -> dict[str, object]:
        return {
            "operating_system": self.operating_system,
            "operating_system_version": self.operating_system_version,
            "version_match": self.version_match.value,
        }

    @classmethod
    def from_object(cls, value: object) -> "ImageFilter":
        item = _object(
            value,
            {"operating_system", "operating_system_version", "version_match"},
            "image filter",
        )
        return cls(
            _string(item, "operating_system"),
            _string(item, "operating_system_version"),
            _enum(
                ImageVersionMatch,
                item["version_match"],
                "image version-match policy",
            ),
        )


@dataclass(frozen=True, slots=True)
class TopologyLabel:
    value: str
    source: str

    def __post_init__(self) -> None:
        _require_topology_name(self.value, "topology label")
        if self.source not in {"explicit", TOPOLOGY_NORMALIZATION_VERSION}:
            raise ConfigurationError("topology label source is invalid")

    def to_object(self) -> dict[str, object]:
        return {"source": self.source, "value": self.value}

    @classmethod
    def from_object(cls, value: object) -> "TopologyLabel":
        item = _object(value, {"source", "value"}, "topology label")
        return cls(_string(item, "value"), _string(item, "source"))


@dataclass(frozen=True, slots=True)
class ZoneSpec:
    zone_id: str
    scylla_nodes: int
    scylla_rack: TopologyLabel
    logical_node_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_nonempty_ascii(self.zone_id, "zone ID", maximum=255)
        _nonnegative_integer(self.scylla_nodes, "Scylla node count")
        if not isinstance(self.scylla_rack, TopologyLabel):
            raise ConfigurationError("zone rack must be a topology label")
        if len(self.logical_node_ids) != self.scylla_nodes:
            raise ConfigurationError("zone logical node IDs must match its node count")
        _require_unique(self.logical_node_ids, "logical node IDs")
        for logical_id in self.logical_node_ids:
            _require_logical_id(logical_id)

    def to_object(self) -> dict[str, object]:
        return {
            "logical_node_ids": list(self.logical_node_ids),
            "scylla_nodes": self.scylla_nodes,
            "scylla_rack": self.scylla_rack.to_object(),
            "zone_id": self.zone_id,
        }

    @classmethod
    def from_object(cls, value: object) -> "ZoneSpec":
        item = _object(
            value,
            {"logical_node_ids", "scylla_nodes", "scylla_rack", "zone_id"},
            "zone",
        )
        return cls(
            _string(item, "zone_id"),
            _integer(item, "scylla_nodes"),
            TopologyLabel.from_object(item["scylla_rack"]),
            _string_tuple(item, "logical_node_ids"),
        )


@dataclass(frozen=True, slots=True)
class ServiceSpec:
    role: HostRole
    count: int
    zones: tuple[str, ...]
    instance_type: str | None
    logical_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.role is HostRole.SCYLLA:
            raise ConfigurationError("Scylla placement is represented by zones")
        _nonnegative_integer(self.count, "service count")
        if self.role in {HostRole.MANAGER, HostRole.MONITORING} and self.count != 1:
            raise ConfigurationError(
                "Manager and monitoring counts must be exactly one"
            )
        if len(self.zones) != self.count:
            raise ConfigurationError("service placement zones must match its count")
        for zone in self.zones:
            _require_nonempty_ascii(zone, "service zone", maximum=255)
        if self.count:
            if self.instance_type is None or not _SHAPE.fullmatch(self.instance_type):
                raise ConfigurationError(
                    "deployed service requires a valid instance type"
                )
        elif self.instance_type is not None:
            raise ConfigurationError(
                "zero-count service must not declare an instance type"
            )
        if len(self.logical_ids) != self.count:
            raise ConfigurationError("service logical IDs must match its count")
        _require_unique(self.logical_ids, "service logical IDs")
        for logical_id in self.logical_ids:
            _require_logical_id(logical_id)

    def to_object(self) -> dict[str, object]:
        return {
            "count": self.count,
            "instance_type": self.instance_type,
            "logical_ids": list(self.logical_ids),
            "role": self.role.value,
            "zones": list(self.zones),
        }

    @classmethod
    def from_object(cls, value: object) -> "ServiceSpec":
        item = _object(
            value, {"count", "instance_type", "logical_ids", "role", "zones"}, "service"
        )
        return cls(
            _enum(HostRole, item["role"], "service role"),
            _integer(item, "count"),
            _string_tuple(item, "zones"),
            _optional_string(item, "instance_type"),
            _string_tuple(item, "logical_ids"),
        )


@dataclass(frozen=True, slots=True)
class BlockVolumePolicy:
    count: int
    size_gib: int
    vpus_per_gb: int
    attachment_type: AttachmentType
    retention: VolumeRetention
    key_id: str | None
    in_transit_encryption: bool
    chap_enabled: bool = False

    def __post_init__(self) -> None:
        _positive_integer(self.count, "block-volume count")
        _positive_integer(self.size_gib, "block-volume size")
        _nonnegative_integer(self.vpus_per_gb, "block-volume VPUs")
        if not isinstance(self.attachment_type, AttachmentType) or not isinstance(
            self.retention, VolumeRetention
        ):
            raise ConfigurationError("block-volume enum is invalid")
        if self.key_id is not None:
            _require_ocid(self.key_id, "block-volume key ID")
        if not isinstance(self.in_transit_encryption, bool):
            raise ConfigurationError("in-transit encryption must be a boolean")
        if self.chap_enabled:
            raise ConfigurationError("CHAP is not supported")

    def to_object(self) -> dict[str, object]:
        return {
            "attachment_type": self.attachment_type.value,
            "chap_enabled": self.chap_enabled,
            "count": self.count,
            "in_transit_encryption": self.in_transit_encryption,
            "key_id": self.key_id,
            "retention": self.retention.value,
            "size_gib": self.size_gib,
            "vpus_per_gb": self.vpus_per_gb,
        }

    @classmethod
    def from_object(cls, value: object) -> "BlockVolumePolicy":
        item = _object(
            value,
            {
                "attachment_type",
                "chap_enabled",
                "count",
                "in_transit_encryption",
                "key_id",
                "retention",
                "size_gib",
                "vpus_per_gb",
            },
            "block-volume policy",
        )
        return cls(
            _integer(item, "count"),
            _integer(item, "size_gib"),
            _integer(item, "vpus_per_gb"),
            _enum(AttachmentType, item["attachment_type"], "attachment type"),
            _enum(VolumeRetention, item["retention"], "volume retention"),
            _optional_string(item, "key_id"),
            _boolean(item, "in_transit_encryption"),
            _boolean(item, "chap_enabled"),
        )


@dataclass(frozen=True, slots=True)
class StoragePolicy:
    role: HostRole
    requested_backend: StorageBackend
    layout: StorageLayout | None
    local_min_device_count: int | None
    local_min_total_gib: int | None
    block_volume: BlockVolumePolicy | None

    def __post_init__(self) -> None:
        if not isinstance(self.role, HostRole) or not isinstance(
            self.requested_backend, StorageBackend
        ):
            raise ConfigurationError("storage role or backend is invalid")
        if self.layout is not None and not isinstance(self.layout, StorageLayout):
            raise ConfigurationError("storage layout is invalid")
        local = (
            self.local_min_device_count is not None
            and self.local_min_total_gib is not None
        )
        if (self.local_min_device_count is None) != (self.local_min_total_gib is None):
            raise ConfigurationError("local storage minimums are required together")
        if local:
            _positive_integer(
                cast(int, self.local_min_device_count), "local device count"
            )
            _positive_integer(cast(int, self.local_min_total_gib), "local total GiB")
        if self.role is HostRole.SCYLLA:
            if self.requested_backend is StorageBackend.AUTO and not (
                local and self.block_volume is not None
            ):
                raise ConfigurationError(
                    "Scylla auto storage requires local minimums and block fallback"
                )
            if self.requested_backend is StorageBackend.LOCAL_NVME and not (
                local and self.block_volume is None
            ):
                raise ConfigurationError(
                    "Scylla local NVMe requires only local minimums"
                )
            if self.requested_backend is StorageBackend.BLOCK_VOLUME and not (
                not local and self.block_volume is not None
            ):
                raise ConfigurationError(
                    "Scylla block storage requires only block-volume settings"
                )
            if self.requested_backend is StorageBackend.BOOT_ONLY:
                raise ConfigurationError("Scylla cannot use boot-only storage")
        elif self.role in {HostRole.MANAGER, HostRole.MONITORING}:
            if (
                self.requested_backend is not StorageBackend.BLOCK_VOLUME
                or local
                or self.block_volume is None
                or self.block_volume.count != 1
            ):
                raise ConfigurationError(
                    "Manager and monitoring require one explicit block volume"
                )
        elif (
            self.requested_backend is not StorageBackend.BOOT_ONLY
            or local
            or self.block_volume is not None
            or self.layout is not None
        ):
            raise ConfigurationError("jump hosts support only boot-only storage")
        device_counts = [
            count
            for count in (
                self.local_min_device_count,
                self.block_volume.count if self.block_volume is not None else None,
            )
            if count is not None
        ]
        if device_counts:
            if len({count > 1 for count in device_counts}) > 1:
                raise ConfigurationError(
                    "storage layout cannot satisfy local and fallback device counts"
                )
            expected = (
                StorageLayout.RAID0 if max(device_counts) > 1 else StorageLayout.SINGLE
            )
            if self.layout is not expected:
                raise ConfigurationError("storage layout does not match device count")

    def to_object(self) -> dict[str, object]:
        return {
            "block_volume": (
                self.block_volume.to_object() if self.block_volume is not None else None
            ),
            "layout": self.layout.value if self.layout is not None else None,
            "local_min_device_count": self.local_min_device_count,
            "local_min_total_gib": self.local_min_total_gib,
            "requested_backend": self.requested_backend.value,
            "role": self.role.value,
        }

    @classmethod
    def from_object(cls, value: object) -> "StoragePolicy":
        item = _object(
            value,
            {
                "block_volume",
                "layout",
                "local_min_device_count",
                "local_min_total_gib",
                "requested_backend",
                "role",
            },
            "storage policy",
        )
        block_value = item["block_volume"]
        layout = item["layout"]
        return cls(
            _enum(HostRole, item["role"], "storage role"),
            _enum(StorageBackend, item["requested_backend"], "storage backend"),
            None if layout is None else _enum(StorageLayout, layout, "storage layout"),
            _optional_integer(item, "local_min_device_count"),
            _optional_integer(item, "local_min_total_gib"),
            None if block_value is None else BlockVolumePolicy.from_object(block_value),
        )


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    mode: NetworkMode
    vcn_id: str | None
    subnets: tuple[tuple[HostRole, str], ...]
    operator_cidrs: tuple[str, ...]
    ssh_user: str
    ssh_public_key_path: Path = field(repr=False)
    public_endpoints: bool = False
    vcn_cidr: str | None = None
    private_subnet_cidrs: tuple[tuple[str, str], ...] = ()
    public_subnet_cidrs: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.mode, NetworkMode):
            raise ConfigurationError("network mode is invalid")
        if not self.ssh_user.strip() or any(
            character.isspace() for character in self.ssh_user
        ):
            raise ConfigurationError("SSH user is invalid")
        if not self.ssh_public_key_path.is_absolute():
            raise ConfigurationError("SSH public-key path must be absolute")
        if not isinstance(self.public_endpoints, bool):
            raise ConfigurationError("public jump-host policy must be a boolean")
        roles = tuple(role for role, _ in self.subnets)
        _require_unique(tuple(role.value for role in roles), "subnet roles")
        for role, subnet_id in self.subnets:
            if not isinstance(role, HostRole):
                raise ConfigurationError("subnet role is invalid")
            _require_ocid(subnet_id, "subnet ID")
        _require_unique(self.operator_cidrs, "operator CIDRs")
        for value in self.operator_cidrs:
            _require_canonical_cidr(value)
            if ipaddress.ip_network(value, strict=True).prefixlen == 0:
                raise ConfigurationError("operator ingress cannot allow all addresses")
        if self.mode is NetworkMode.CREATE:
            if self.vcn_id is not None or self.subnets:
                raise ConfigurationError("created network forbids existing selectors")
            if self.vcn_cidr is None:
                raise ConfigurationError(
                    "created network requires an explicit VCN CIDR"
                )
            _validate_managed_cidrs(
                self.vcn_cidr,
                self.private_subnet_cidrs,
                self.public_subnet_cidrs,
            )
        elif self.vcn_id is None:
            raise ConfigurationError("existing network requires a VCN ID")
        else:
            _require_ocid(self.vcn_id, "VCN ID")
            if (
                self.vcn_cidr is not None
                or self.private_subnet_cidrs
                or self.public_subnet_cidrs
            ):
                raise ConfigurationError(
                    "existing network forbids managed network CIDRs"
                )

    def to_object(self) -> dict[str, object]:
        return {
            "mode": self.mode.value,
            "operator_cidrs": list(self.operator_cidrs),
            "private_subnet_cidrs": dict(self.private_subnet_cidrs),
            "public_endpoints": self.public_endpoints,
            "public_subnet_cidrs": dict(self.public_subnet_cidrs),
            "ssh_public_key_path": str(self.ssh_public_key_path),
            "ssh_user": self.ssh_user,
            "subnets": {role.value: value for role, value in self.subnets},
            "vcn_cidr": self.vcn_cidr,
            "vcn_id": self.vcn_id,
        }

    @classmethod
    def from_object(cls, value: object) -> "NetworkPolicy":
        item = _object(
            value,
            {
                "mode",
                "operator_cidrs",
                "private_subnet_cidrs",
                "public_endpoints",
                "public_subnet_cidrs",
                "ssh_public_key_path",
                "ssh_user",
                "subnets",
                "vcn_cidr",
                "vcn_id",
            },
            "network policy",
        )
        subnets = _object_any(item["subnets"], "subnets")
        return cls(
            _enum(NetworkMode, item["mode"], "network mode"),
            _optional_string(item, "vcn_id"),
            tuple(
                (
                    _enum(HostRole, role, "subnet role"),
                    _value_string(subnets[role], "subnet ID"),
                )
                for role in sorted(subnets)
            ),
            _string_tuple(item, "operator_cidrs"),
            _string(item, "ssh_user"),
            Path(_string(item, "ssh_public_key_path")),
            _boolean(item, "public_endpoints"),
            _optional_string(item, "vcn_cidr"),
            _string_map_tuple(item["private_subnet_cidrs"], "private subnet CIDRs"),
            _string_map_tuple(item["public_subnet_cidrs"], "public subnet CIDRs"),
        )


@dataclass(frozen=True, slots=True)
class ClusterSpec:
    cluster_uuid: uuid.UUID
    cluster_name: str
    provider: str
    oci_region: str
    oci_compartment_id: str
    scylla_datacenter: TopologyLabel
    scylla_instance_type: str
    zones: tuple[ZoneSpec, ...]
    services: tuple[ServiceSpec, ...]
    network: NetworkPolicy
    storage: tuple[StoragePolicy, ...]
    provenance: tuple[tuple[str, ValueSource], ...]
    image_filters: tuple[tuple[HostRole, ImageFilter], ...]
    schema_version: str = CLUSTER_SPEC_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != CLUSTER_SPEC_SCHEMA_VERSION:
            raise ConfigurationError("unsupported desired-cluster schema version")
        if not isinstance(self.cluster_uuid, uuid.UUID):
            raise ConfigurationError("cluster UUID must be a UUID")
        validate_cluster_name(self.cluster_name)
        if self.provider != "oci":
            raise ConfigurationError("desired cluster provider must be oci")
        _require_nonempty_ascii(self.oci_region, "OCI region", maximum=255)
        _require_ocid(self.oci_compartment_id, "OCI compartment ID")
        if not isinstance(self.scylla_datacenter, TopologyLabel):
            raise ConfigurationError("Scylla datacenter must be a topology label")
        if not _SHAPE.fullmatch(self.scylla_instance_type):
            raise ConfigurationError("Scylla instance type is invalid")
        zone_ids = tuple(zone.zone_id for zone in self.zones)
        if not zone_ids or zone_ids != tuple(sorted(zone_ids)):
            raise ConfigurationError("zones must use deterministic sorted order")
        _require_unique(zone_ids, "zones")
        if sum(zone.scylla_nodes for zone in self.zones) < 1:
            raise ConfigurationError(
                "desired cluster requires at least one Scylla node"
            )
        racks = tuple(zone.scylla_rack.value for zone in self.zones)
        _require_unique(racks, "Scylla racks")
        service_roles = tuple(service.role for service in self.services)
        if service_roles != (
            HostRole.MANAGER,
            HostRole.MONITORING,
            HostRole.JUMP_HOST,
        ):
            raise ConfigurationError("service roles or order do not match the schema")
        required_image_roles = {
            HostRole.SCYLLA,
            HostRole.MANAGER,
            HostRole.MONITORING,
        }
        if self.services[2].count:
            required_image_roles.add(HostRole.JUMP_HOST)
        if (
            {role for role, _ in self.image_filters} != required_image_roles
            or tuple(role.value for role, _ in self.image_filters)
            != tuple(sorted(role.value for role in required_image_roles))
            or any(
                not isinstance(image_filter, ImageFilter)
                for _, image_filter in self.image_filters
            )
        ):
            raise ConfigurationError(
                "desired image filters must cover every deployed role"
            )
        if any(
            zone not in set(zone_ids)
            for service in self.services
            for zone in service.zones
        ):
            raise ConfigurationError("service placement names an unknown zone")
        if self.network.mode is NetworkMode.EXISTING:
            required_subnets = {
                HostRole.SCYLLA,
                HostRole.MANAGER,
                HostRole.MONITORING,
            }
            if self.services[2].count:
                required_subnets.add(HostRole.JUMP_HOST)
            if {role for role, _ in self.network.subnets} != required_subnets:
                raise ConfigurationError(
                    "existing network must map every deployed role exactly once"
                )
        else:
            expected_private_zones = set(zone_ids)
            if {zone for zone, _ in self.network.private_subnet_cidrs} != (
                expected_private_zones
            ):
                raise ConfigurationError(
                    "managed private subnets must map every zone exactly once"
                )
            jump_zones = set(self.services[2].zones)
            expected_public_zones = (
                jump_zones if self.network.public_endpoints else set()
            )
            if {zone for zone, _ in self.network.public_subnet_cidrs} != (
                expected_public_zones
            ):
                raise ConfigurationError(
                    "managed public subnets must map public jump-host zones exactly"
                )
            if self.network.public_endpoints and not jump_zones:
                raise ConfigurationError(
                    "public jump-host networking requires jump hosts"
                )
        all_ids = tuple(
            logical_id for zone in self.zones for logical_id in zone.logical_node_ids
        ) + tuple(
            logical_id
            for service in self.services
            for logical_id in service.logical_ids
        )
        _require_unique(all_ids, "cluster logical IDs")
        storage_roles = tuple(policy.role for policy in self.storage)
        if storage_roles != tuple(HostRole):
            raise ConfigurationError(
                "storage policies or order do not match the schema"
            )
        provenance_names = tuple(name for name, _ in self.provenance)
        if provenance_names != tuple(sorted(provenance_names)):
            raise ConfigurationError("provenance must use deterministic sorted order")
        _require_unique(provenance_names, "provenance fields")
        if not all(
            name in DESIRED_CONFIG_FIELD_NAMES and isinstance(source, ValueSource)
            for name, source in self.provenance
        ):
            raise ConfigurationError("desired-cluster provenance is invalid")

    def to_object(self) -> dict[str, object]:
        value: dict[str, object] = {
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "network": self.network.to_object(),
            "image_filters": {
                role.value: image_filter.to_object()
                for role, image_filter in self.image_filters
            },
            "oci_compartment_id": self.oci_compartment_id,
            "oci_region": self.oci_region,
            "provenance": {name: source.value for name, source in self.provenance},
            "provider": self.provider,
            "schema_version": self.schema_version,
            "scylla_datacenter": self.scylla_datacenter.to_object(),
            "scylla_instance_type": self.scylla_instance_type,
            "services": [service.to_object() for service in self.services],
            "storage": [policy.to_object() for policy in self.storage],
            "zones": [zone.to_object() for zone in self.zones],
        }
        _reject_secret_keys(value)
        return value

    def digest(self) -> str:
        return (
            "sha256:" + hashlib.sha256(_canonical_bytes(self.to_object())).hexdigest()
        )

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> "ClusterSpec":
        item = _object(
            value,
            {
                "cluster_name",
                "cluster_uuid",
                "network",
                "image_filters",
                "oci_compartment_id",
                "oci_region",
                "provenance",
                "provider",
                "schema_version",
                "scylla_datacenter",
                "scylla_instance_type",
                "services",
                "storage",
                "zones",
            },
            "desired cluster",
        )
        if _string(item, "schema_version") != CLUSTER_SPEC_SCHEMA_VERSION:
            raise ConfigurationError("unsupported desired-cluster schema version")
        provenance = _object_any(item["provenance"], "provenance")
        image_filters = _object_any(item["image_filters"], "image filters")
        return cls(
            _uuid(_string(item, "cluster_uuid"), "cluster UUID"),
            _string(item, "cluster_name"),
            _string(item, "provider"),
            _string(item, "oci_region"),
            _string(item, "oci_compartment_id"),
            TopologyLabel.from_object(item["scylla_datacenter"]),
            _string(item, "scylla_instance_type"),
            tuple(ZoneSpec.from_object(zone) for zone in _array(item, "zones")),
            tuple(
                ServiceSpec.from_object(service) for service in _array(item, "services")
            ),
            NetworkPolicy.from_object(item["network"]),
            tuple(
                StoragePolicy.from_object(policy) for policy in _array(item, "storage")
            ),
            tuple(
                (
                    name,
                    _enum(ValueSource, provenance[name], "provenance source"),
                )
                for name in sorted(provenance)
            ),
            tuple(
                (
                    _enum(HostRole, role, "image-filter role"),
                    ImageFilter.from_object(image_filters[role]),
                )
                for role in sorted(image_filters)
            ),
        )

    def option_value(self, name: str) -> object:
        return _flatten_spec(self)[name]


@dataclass(frozen=True, slots=True)
class ProposedChange:
    field: str
    baseline: object
    requested: object
    source: ValueSource
    disposition: ChangeDisposition


@dataclass(frozen=True, slots=True)
class ExistingConfigResolution:
    baseline: ClusterSpec
    changes: tuple[ProposedChange, ...]


def compile_new_cluster_spec(
    request: OperationRequest,
    *,
    cluster_uuid: uuid.UUID,
    canonical_zone_ids: Mapping[str, str],
    derived_ssh_user: str | None = None,
) -> ClusterSpec:
    """Compile a complete deploy request after provider zone canonicalization."""

    if request.operation.name != "deploy":
        raise ConfigurationError("only deploy can compile a new desired cluster")
    aliases = _request_strings(request, "zone")
    if set(canonical_zone_ids) != set(aliases):
        raise ConfigurationError(
            "canonical zone identities must exactly cover configured zones"
        )
    canonical = tuple(sorted(canonical_zone_ids.values()))
    _require_unique(canonical, "canonical zone identities")
    counts = _request_map(request, "nodes_per_zone")
    rack_inputs = _request_map(request, "scylla_rack")
    generated_slugs = {
        alias: _provider_slug(canonical_zone_ids[alias], maximum=58)
        for alias in aliases
    }
    _require_unique(tuple(generated_slugs.values()), "normalized zone keys")
    zones: list[ZoneSpec] = []
    for alias in aliases:
        rack_input = rack_inputs.get(alias)
        rack = (
            TopologyLabel(cast(str, rack_input), "explicit")
            if rack_input is not None
            else TopologyLabel(
                "rack-" + generated_slugs[alias], TOPOLOGY_NORMALIZATION_VERSION
            )
        )
        count = cast(int, counts[alias])
        logical_ids = tuple(
            f"scylla-{generated_slugs[alias]}-{ordinal}"
            for ordinal in range(1, count + 1)
        )
        zones.append(ZoneSpec(canonical_zone_ids[alias], count, rack, logical_ids))
    zones.sort(key=lambda zone: zone.zone_id)
    if sum(zone.scylla_nodes for zone in zones) < 1:
        raise ConfigurationError("deploy requires at least one Scylla node")

    region = _request_string(request, "oci_region")
    datacenter_input = _request_optional_string(request, "scylla_datacenter")
    datacenter = (
        TopologyLabel(datacenter_input, "explicit")
        if datacenter_input is not None
        else TopologyLabel(
            "oci-" + _provider_slug(region, maximum=59),
            TOPOLOGY_NORMALIZATION_VERSION,
        )
    )
    sorted_zone_ids = tuple(zone.zone_id for zone in zones)
    manager_zone = _resolved_service_zone(
        request, "manager_zone", canonical_zone_ids, sorted_zone_ids[0]
    )
    monitoring_default = (
        sorted_zone_ids[1] if len(sorted_zone_ids) > 1 else sorted_zone_ids[0]
    )
    monitoring_zone = _resolved_service_zone(
        request, "monitoring_zone", canonical_zone_ids, monitoring_default
    )
    jump_count = _request_integer(request, "jump_host_count")
    services = (
        ServiceSpec(
            HostRole.MANAGER,
            _request_integer(request, "manager_count"),
            (manager_zone,),
            _request_string(request, "manager_instance_type"),
            ("manager-1",),
        ),
        ServiceSpec(
            HostRole.MONITORING,
            _request_integer(request, "monitoring_count"),
            (monitoring_zone,),
            _request_string(request, "monitoring_instance_type"),
            ("monitoring-1",),
        ),
        ServiceSpec(
            HostRole.JUMP_HOST,
            jump_count,
            tuple(
                sorted_zone_ids[index % len(sorted_zone_ids)]
                for index in range(jump_count)
            ),
            _request_optional_string(request, "jump_host_instance_type"),
            tuple(f"jump-host-{ordinal}" for ordinal in range(1, jump_count + 1)),
        ),
    )
    ssh_user = _request_optional_string(request, "ssh_user") or derived_ssh_user
    if ssh_user is None:
        raise ConfigurationError(
            "provider-derived SSH user is required to compile desired state"
        )
    subnets = tuple(
        (
            HostRole(role),
            cast(str, subnet_id),
        )
        for role, subnet_id in sorted(_request_map(request, "oci_subnet").items())
    )
    network = NetworkPolicy(
        NetworkMode(_request_string(request, "network_mode")),
        _request_optional_string(request, "oci_vcn_id"),
        subnets,
        tuple(sorted(_request_strings(request, "operator_cidr"))),
        ssh_user,
        _request_path(request, "ssh_public_key_path"),
        _request_boolean(request, "oci_public_jump_hosts"),
        _request_optional_string(request, "oci_vcn_cidr"),
        tuple(
            sorted(
                (
                    canonical_zone_ids[alias],
                    cast(str, cidr),
                )
                for alias, cidr in _request_map(
                    request, "oci_private_subnet_cidr"
                ).items()
            )
        ),
        tuple(
            sorted(
                (
                    canonical_zone_ids[alias],
                    cast(str, cidr),
                )
                for alias, cidr in _request_map(
                    request, "oci_public_subnet_cidr"
                ).items()
            )
        ),
    )
    storage = (
        _compile_scylla_storage(request),
        _compile_service_storage(request, HostRole.MANAGER),
        _compile_service_storage(request, HostRole.MONITORING),
        StoragePolicy(
            HostRole.JUMP_HOST,
            StorageBackend.BOOT_ONLY,
            None,
            None,
            None,
            None,
        ),
    )
    provenance = tuple(
        sorted(
            (
                option.name,
                option.source,
            )
            for option in request.options
            if option.name in DESIRED_CONFIG_FIELD_NAMES
            and option.source is not ValueSource.UNSET
        )
    )
    return ClusterSpec(
        cluster_uuid,
        request.cluster_name,
        request.provider.name,
        region,
        _request_string(request, "oci_compartment_id"),
        datacenter,
        _request_string(request, "scylla_instance_type"),
        tuple(zones),
        services,
        network,
        storage,
        provenance,
        tuple(
            (
                role,
                ImageFilter(
                    _request_string(
                        request,
                        f"{role.value.replace('-', '_')}_image_operating_system",
                    ),
                    _request_string(
                        request,
                        f"{role.value.replace('-', '_')}_image_operating_system_version",
                    ),
                    ImageVersionMatch(
                        _request_string(
                            request,
                            f"{role.value.replace('-', '_')}_image_version_match",
                        )
                    ),
                ),
            )
            for role in sorted(
                (
                    HostRole.SCYLLA,
                    HostRole.MANAGER,
                    HostRole.MONITORING,
                    *((HostRole.JUMP_HOST,) if jump_count else ()),
                ),
                key=lambda item: item.value,
            )
        ),
    )


def resolve_existing_config(
    request: OperationRequest, baseline: ClusterSpec
) -> ExistingConfigResolution:
    """Compare explicit request sources with persisted desired state without applying."""

    if request.cluster_name != baseline.cluster_name:
        raise StateConflictError(
            "requested cluster name conflicts with persisted identity"
        )
    if request.provider.name != baseline.provider:
        raise StateConflictError("requested provider conflicts with persisted identity")
    flattened = _flatten_spec(baseline)
    changes: list[ProposedChange] = []
    identity_fields = {
        "cloud_provider",
        "cluster_name",
        "oci_region",
        "oci_compartment_id",
    }
    for option in request.options:
        if (
            option.name not in flattened
            or option.source
            not in {ValueSource.CLI, ValueSource.ENVIRONMENT, ValueSource.CONFIG}
            or isinstance(option.value, DeferredValue)
        ):
            continue
        requested = _comparable(option.value)
        persisted = _comparable(flattened[option.name])
        if requested == persisted:
            continue
        disposition = (
            ChangeDisposition.IDENTITY_ASSERTION
            if option.name in identity_fields
            else ChangeDisposition.PROPOSED_CHANGE
        )
        if request.operation.classification is OperationClassification.READ_ONLY:
            raise StateConflictError(
                f"read-only request conflicts with persisted field: {option.name}"
            )
        changes.append(
            ProposedChange(
                option.name,
                persisted,
                requested,
                option.source,
                disposition,
            )
        )
    return ExistingConfigResolution(
        baseline, tuple(sorted(changes, key=lambda change: change.field))
    )


def _compile_scylla_storage(request: OperationRequest) -> StoragePolicy:
    backend = StorageBackend(_request_string(request, "scylla_storage_backend"))
    layout = StorageLayout(_request_string(request, "scylla_storage_layout"))
    local_count = _request_optional_integer(request, "scylla_storage_min_device_count")
    local_total = _request_optional_integer(request, "scylla_storage_min_total_gib")
    block = (
        None
        if backend is StorageBackend.LOCAL_NVME
        else _block_policy(request, "scylla_block_volume")
    )
    return StoragePolicy(
        HostRole.SCYLLA, backend, layout, local_count, local_total, block
    )


def _compile_service_storage(
    request: OperationRequest, role: HostRole
) -> StoragePolicy:
    prefix = role.value
    block = BlockVolumePolicy(
        1,
        _request_integer(request, f"{prefix}_data_volume_size_gib"),
        _request_integer(request, f"{prefix}_data_volume_vpus_per_gb"),
        AttachmentType(
            _request_string(request, f"{prefix}_data_volume_attachment_type")
        ),
        VolumeRetention(_request_string(request, f"{prefix}_data_volume_retention")),
        _request_optional_string(request, f"{prefix}_data_volume_key_id"),
        _request_string(request, f"{prefix}_data_volume_in_transit_encryption")
        == "enabled",
    )
    return StoragePolicy(
        role, StorageBackend.BLOCK_VOLUME, StorageLayout.SINGLE, None, None, block
    )


def _block_policy(request: OperationRequest, prefix: str) -> BlockVolumePolicy:
    return BlockVolumePolicy(
        _request_integer(request, f"{prefix}_count"),
        _request_integer(request, f"{prefix}_size_gib"),
        _request_integer(request, f"{prefix}_vpus_per_gb"),
        AttachmentType(_request_string(request, f"{prefix}_attachment_type")),
        VolumeRetention(_request_string(request, f"{prefix}_retention")),
        _request_optional_string(request, f"{prefix}_key_id"),
        _request_string(request, f"{prefix}_in_transit_encryption") == "enabled",
        _request_string(request, "scylla_block_volume_chap") == "enabled",
    )


def _resolved_service_zone(
    request: OperationRequest,
    name: str,
    canonical_zone_ids: Mapping[str, str],
    default: str,
) -> str:
    configured = _request_optional_string(request, name)
    return canonical_zone_ids[configured] if configured is not None else default


def _flatten_spec(spec: ClusterSpec) -> dict[str, object]:
    services = {service.role: service for service in spec.services}
    storage = {policy.role: policy for policy in spec.storage}
    scylla = storage[HostRole.SCYLLA]
    result: dict[str, object] = {
        "cloud_provider": spec.provider,
        "cluster_name": spec.cluster_name,
        "oci_region": spec.oci_region,
        "oci_compartment_id": spec.oci_compartment_id,
        "network_mode": spec.network.mode.value,
        "oci_vcn_id": spec.network.vcn_id,
        "oci_vcn_cidr": spec.network.vcn_cidr,
        "oci_private_subnet_cidr": spec.network.private_subnet_cidrs,
        "oci_public_subnet_cidr": spec.network.public_subnet_cidrs,
        "oci_public_jump_hosts": spec.network.public_endpoints,
        "oci_subnet": tuple(
            (role.value, value) for role, value in spec.network.subnets
        ),
        "operator_cidr": spec.network.operator_cidrs,
        "ssh_user": spec.network.ssh_user,
        "ssh_public_key_path": spec.network.ssh_public_key_path,
        "scylla_datacenter": spec.scylla_datacenter.value,
        "jump_host_count": services[HostRole.JUMP_HOST].count,
        "scylla_instance_type": spec.scylla_instance_type,
        "manager_instance_type": services[HostRole.MANAGER].instance_type,
        "monitoring_instance_type": services[HostRole.MONITORING].instance_type,
        "jump_host_instance_type": services[HostRole.JUMP_HOST].instance_type,
        "manager_count": services[HostRole.MANAGER].count,
        "monitoring_count": services[HostRole.MONITORING].count,
        "manager_zone": services[HostRole.MANAGER].zones[0],
        "monitoring_zone": services[HostRole.MONITORING].zones[0],
        "scylla_storage_backend": scylla.requested_backend.value,
        "scylla_storage_min_device_count": scylla.local_min_device_count,
        "scylla_storage_min_total_gib": scylla.local_min_total_gib,
        "scylla_storage_layout": (
            scylla.layout.value if scylla.layout is not None else None
        ),
        "scylla_block_volume_chap": "disabled",
    }
    for role, image_filter in spec.image_filters:
        prefix = role.value.replace("-", "_")
        result[f"{prefix}_image_operating_system"] = image_filter.operating_system
        result[f"{prefix}_image_operating_system_version"] = (
            image_filter.operating_system_version
        )
        result[f"{prefix}_image_version_match"] = image_filter.version_match.value
    _flatten_block(result, "scylla_block_volume", scylla.block_volume)
    for role in (HostRole.MANAGER, HostRole.MONITORING):
        _flatten_block(
            result,
            f"{role.value}_data_volume",
            storage[role].block_volume,
            service=True,
        )
    return result


def _flatten_block(
    result: dict[str, object],
    prefix: str,
    block: BlockVolumePolicy | None,
    *,
    service: bool = False,
) -> None:
    if not service:
        result[f"{prefix}_count"] = block.count if block is not None else None
    result[f"{prefix}_size_gib"] = block.size_gib if block is not None else None
    result[f"{prefix}_vpus_per_gb"] = block.vpus_per_gb if block is not None else None
    result[f"{prefix}_attachment_type"] = (
        block.attachment_type.value if block is not None else None
    )
    result[f"{prefix}_retention"] = block.retention.value if block is not None else None
    result[f"{prefix}_key_id"] = block.key_id if block is not None else None
    result[f"{prefix}_in_transit_encryption"] = (
        "enabled" if block is not None and block.in_transit_encryption else "disabled"
    )


def _request_option(request: OperationRequest, name: str) -> object:
    return request.option(name).value


def _request_string(request: OperationRequest, name: str) -> str:
    value = _request_option(request, name)
    if not isinstance(value, str):
        raise ConfigurationError(f"required desired setting is missing: {name}")
    return value


def _request_optional_string(request: OperationRequest, name: str) -> str | None:
    value = _request_option(request, name)
    if value is None or isinstance(value, DeferredValue):
        return None
    if not isinstance(value, str):
        raise ConfigurationError(f"desired setting must be a string: {name}")
    return value


def _request_integer(request: OperationRequest, name: str) -> int:
    value = _request_option(request, name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"required desired integer is missing: {name}")
    return value


def _request_boolean(request: OperationRequest, name: str) -> bool:
    value = _request_option(request, name)
    if not isinstance(value, bool):
        raise ConfigurationError(f"required desired boolean is missing: {name}")
    return value


def _request_optional_integer(request: OperationRequest, name: str) -> int | None:
    value = _request_option(request, name)
    if value is None or isinstance(value, DeferredValue):
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"desired setting must be an integer: {name}")
    return value


def _request_strings(request: OperationRequest, name: str) -> tuple[str, ...]:
    value = _request_option(request, name)
    if not isinstance(value, tuple) or not all(isinstance(item, str) for item in value):
        raise ConfigurationError(f"desired setting must be a string list: {name}")
    return cast(tuple[str, ...], value)


def _request_map(request: OperationRequest, name: str) -> dict[str, object]:
    value = _request_option(request, name)
    if not isinstance(value, tuple):
        raise ConfigurationError(f"desired setting must be a mapping: {name}")
    result: dict[str, object] = {}
    for item in value:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], str)
        ):
            raise ConfigurationError(f"desired mapping is invalid: {name}")
        result[item[0]] = item[1]
    return result


def _request_path(request: OperationRequest, name: str) -> Path:
    value = _request_option(request, name)
    if not isinstance(value, Path):
        raise ConfigurationError(f"required desired path is missing: {name}")
    return value


def _provider_slug(value: str, *, maximum: int) -> str:
    if not value.isascii():
        raise ConfigurationError("provider identity cannot be normalized to ASCII")
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    slug = slug[:maximum].rstrip("-")
    if not slug:
        raise ConfigurationError("provider identity normalizes to an empty key")
    return slug


def _require_topology_name(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or not _TOPOLOGY_NAME.fullmatch(value)
        or "--" in value
        or value.endswith("-")
    ):
        raise ConfigurationError(f"{label} has invalid normalized syntax")


def _require_logical_id(value: str) -> None:
    if not value.isascii() or not _LOGICAL_ID.fullmatch(value):
        raise ConfigurationError("stable logical ID syntax is invalid")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return
    raise ConfigurationError("stable logical ID must not be an IP address")


def _require_ocid(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.startswith("ocid1.")
        or any(character.isspace() for character in value)
        or len(value) > 255
    ):
        raise ConfigurationError(f"{label} must use OCID-like syntax")


def _require_canonical_cidr(value: str) -> None:
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise ConfigurationError("operator CIDR is invalid") from error
    if value.lower() != str(network):
        raise ConfigurationError("operator CIDR must use canonical spelling")


def _validate_managed_cidrs(
    vcn_cidr: str,
    private_subnets: tuple[tuple[str, str], ...],
    public_subnets: tuple[tuple[str, str], ...],
) -> None:
    vcn = _managed_network(vcn_cidr, "managed VCN CIDR")
    if not 16 <= vcn.prefixlen <= 30:
        raise ConfigurationError("managed VCN CIDR prefix must be between /16 and /30")
    _require_unique(
        tuple(key for key, _ in private_subnets), "managed private subnet zones"
    )
    _require_unique(
        tuple(key for key, _ in public_subnets), "managed public subnet zones"
    )
    networks: list[ipaddress.IPv4Network] = []
    for zone, value in (*private_subnets, *public_subnets):
        _require_nonempty_ascii(zone, "managed subnet zone", maximum=255)
        subnet = _managed_network(value, "managed subnet CIDR")
        if not subnet.subnet_of(vcn):
            raise ConfigurationError("managed subnet CIDR must be inside the VCN CIDR")
        if any(subnet.overlaps(existing) for existing in networks):
            raise ConfigurationError("managed subnet CIDRs must not overlap")
        networks.append(subnet)


def _managed_network(value: str, label: str) -> ipaddress.IPv4Network:
    _require_canonical_cidr(value)
    network = ipaddress.ip_network(value, strict=True)
    if not isinstance(network, ipaddress.IPv4Network):
        raise ConfigurationError(f"{label} must be IPv4")
    private_ranges = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    if not any(network.subnet_of(private) for private in private_ranges):
        raise ConfigurationError(f"{label} must use RFC 1918 private address space")
    if not 16 <= network.prefixlen <= 30:
        raise ConfigurationError(f"{label} prefix must be between /16 and /30")
    return network


def _string_map_tuple(value: object, label: str) -> tuple[tuple[str, str], ...]:
    item = _object_any(value, label)
    return tuple((key, _value_string(item[key], label)) for key in sorted(item))


def _require_nonempty_ascii(value: str, label: str, *, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ConfigurationError(f"{label} is invalid")


def _positive_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConfigurationError(f"{label} must be a positive integer")


def _nonnegative_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConfigurationError(f"{label} must be a non-negative integer")


def _require_unique(values: tuple[object, ...], label: str) -> None:
    if len(values) != len(set(values)):
        raise ConfigurationError(f"{label} must be unique")


def _canonical_bytes(value: Mapping[str, object]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _reject_secret_keys(value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if _SECRET_KEY.search(str(key)) and key != "ssh_public_key_path":
                raise ConfigurationError(
                    "secret-like field is forbidden in desired state"
                )
            _reject_secret_keys(child)
    elif isinstance(value, list):
        for child in value:
            _reject_secret_keys(child)


def _object(value: object, expected: set[str], label: str) -> dict[str, object]:
    item = _object_any(value, label)
    if set(item) != expected:
        raise ConfigurationError(f"{label} fields do not match the schema")
    return item


def _object_any(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ConfigurationError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _array(value: Mapping[str, object], key: str) -> list[object]:
    item = value[key]
    if not isinstance(item, list):
        raise ConfigurationError(f"{key} must be an array")
    return cast(list[object], item)


def _string(value: Mapping[str, object], key: str) -> str:
    return _value_string(value[key], key)


def _value_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigurationError(f"{label} must be a non-empty string")
    return value


def _optional_string(value: Mapping[str, object], key: str) -> str | None:
    item = value[key]
    if item is None:
        return None
    return _value_string(item, key)


def _integer(value: Mapping[str, object], key: str) -> int:
    item = value[key]
    if isinstance(item, bool) or not isinstance(item, int):
        raise ConfigurationError(f"{key} must be an integer")
    return item


def _optional_integer(value: Mapping[str, object], key: str) -> int | None:
    item = value[key]
    if item is None:
        return None
    if isinstance(item, bool) or not isinstance(item, int):
        raise ConfigurationError(f"{key} must be null or an integer")
    return item


def _boolean(value: Mapping[str, object], key: str) -> bool:
    item = value[key]
    if not isinstance(item, bool):
        raise ConfigurationError(f"{key} must be a boolean")
    return item


def _string_tuple(value: Mapping[str, object], key: str) -> tuple[str, ...]:
    items = _array(value, key)
    if not all(isinstance(item, str) for item in items):
        raise ConfigurationError(f"{key} must contain only strings")
    return cast(tuple[str, ...], tuple(items))


def _enum(enum_type: type[_EnumT], value: object, label: str) -> _EnumT:
    if not isinstance(value, str):
        raise ConfigurationError(f"{label} must be a string")
    try:
        return enum_type(value)
    except ValueError as error:
        raise ConfigurationError(f"{label} is invalid") from error


def _uuid(value: str, label: str) -> uuid.UUID:
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise ConfigurationError(f"{label} is invalid") from error
    if str(parsed) != value:
        raise ConfigurationError(f"{label} must use canonical spelling")
    return parsed


def _comparable(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, tuple):
        return tuple(_comparable(item) for item in value)
    return value
