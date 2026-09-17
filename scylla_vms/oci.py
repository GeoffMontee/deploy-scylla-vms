"""Offline OCI adapter and strict deterministic Terraform input model."""

import hashlib
import ipaddress
import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from scylla_vms.desired import (
    BlockVolumePolicy,
    ClusterSpec,
    HostRole,
    ImageFilter,
    ImageVersionMatch,
    ProposedChange,
    StorageBackend,
    StoragePolicy,
)
from scylla_vms.errors import ConfigurationError, StateConflictError
from scylla_vms.providers import ProviderCapabilities, ProviderTerraformInput
from scylla_vms.ssh_public import validate_public_ssh_key_text
from scylla_vms.state import validate_cluster_name

OCI_TERRAFORM_INPUT_SCHEMA_VERSION = "deploy-scylla-vms.terraform-input.oci/v2"
OCI_INPUT_SELECTION_ALGORITHM = "oci-shape-capabilities/v1"
_OCID = re.compile(r"ocid1\.[a-z0-9-]+\.[A-Za-z0-9.-]*\.[A-Za-z0-9._:+/-]+\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SECRET_KEY = re.compile(
    r"(?i)(?:password|passphrase|secret|token|credential|private[_-]?key)"
)
_SECRET_VALUE = re.compile(
    r"(?i)(?:-----BEGIN [^-]*PRIVATE KEY-----|"
    r"(?:password|passphrase|secret|token)\s*[:=])"
)


@dataclass(frozen=True, slots=True)
class OciShapeCapability:
    """Provider-derived shape facts; construction does not prove availability."""

    shape: str
    architecture: str
    zones: tuple[str, ...]
    local_nvme_device_count: int
    local_nvme_total_gib: int

    def __post_init__(self) -> None:
        if not self.shape or not self.shape.isascii():
            raise ConfigurationError("OCI shape capability name is invalid")
        if self.architecture not in {"amd64", "aarch64"}:
            raise ConfigurationError("OCI shape architecture is unsupported")
        if not self.zones or self.zones != tuple(sorted(set(self.zones))):
            raise ConfigurationError("OCI shape capability zones must be sorted")
        if any(not zone or not zone.isascii() for zone in self.zones):
            raise ConfigurationError("OCI shape capability zone is invalid")
        for value in (self.local_nvme_device_count, self.local_nvme_total_gib):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ConfigurationError("OCI local-NVMe capability is invalid")
        if (self.local_nvme_device_count == 0) != (self.local_nvme_total_gib == 0):
            raise ConfigurationError("OCI local-NVMe capability is inconsistent")


@dataclass(frozen=True, slots=True)
class OciCapabilities:
    """Validated facts supplied by a future provider discovery boundary."""

    region: str
    zones: tuple[str, ...]
    shapes: tuple[OciShapeCapability, ...]
    images: tuple["OciImageCandidate", ...]
    pinned_images: tuple[tuple[str, "OciSelectedImage"], ...] = ()
    provider: str = "oci"

    def __post_init__(self) -> None:
        if self.provider != "oci" or not self.region or not self.region.isascii():
            raise ConfigurationError("OCI capability identity is invalid")
        if not self.zones or self.zones != tuple(sorted(set(self.zones))):
            raise ConfigurationError("OCI capability zones must be sorted")
        shape_names = tuple(shape.shape for shape in self.shapes)
        if shape_names != tuple(sorted(set(shape_names))):
            raise ConfigurationError("OCI shape capabilities must be sorted")
        if any(not set(shape.zones) <= set(self.zones) for shape in self.shapes):
            raise ConfigurationError("OCI shape capability names an unknown zone")
        image_ids = tuple(image.image_id for image in self.images)
        if image_ids != tuple(sorted(set(image_ids))):
            raise ConfigurationError("OCI image candidates must be uniquely sorted")
        if self.pinned_images != tuple(
            sorted(self.pinned_images, key=lambda item: item[0])
        ) or len({logical_id for logical_id, _ in self.pinned_images}) != len(
            self.pinned_images
        ):
            raise ConfigurationError("OCI pinned image evidence is invalid")


@dataclass(frozen=True, slots=True)
class OciImageCandidate:
    image_id: str
    display_name: str
    time_created: str
    operating_system: str
    operating_system_version: str
    architecture: str
    compatible_shapes: tuple[str, ...]
    state: str

    def __post_init__(self) -> None:
        _require_ocid(self.image_id, "OCI image ID", kind="image")
        if (
            not self.display_name
            or not self.display_name.isascii()
            or self.architecture not in {"amd64", "aarch64"}
            or self.compatible_shapes != tuple(sorted(set(self.compatible_shapes)))
            or self.state not in {"AVAILABLE", "DISABLED", "DELETED"}
        ):
            raise ConfigurationError("OCI image candidate is invalid")
        _parse_oci_time(self.time_created)


@dataclass(frozen=True, slots=True)
class OciSelectedImage:
    image_id: str
    display_name: str
    time_created: str
    operating_system: str
    operating_system_version: str
    architecture: str

    def __post_init__(self) -> None:
        _require_ocid(self.image_id, "OCI selected image ID", kind="image")
        if (
            not self.display_name
            or not self.display_name.isascii()
            or self.architecture not in {"amd64", "aarch64"}
        ):
            raise ConfigurationError("OCI selected image evidence is invalid")
        _parse_oci_time(self.time_created)

    def to_object(self) -> dict[str, object]:
        return {
            "architecture": self.architecture,
            "display_name": self.display_name,
            "image_id": self.image_id,
            "operating_system": self.operating_system,
            "operating_system_version": self.operating_system_version,
            "time_created": self.time_created,
        }


@dataclass(frozen=True, slots=True)
class OciStorageInput:
    requested_backend: StorageBackend
    selected_backend: StorageBackend
    selection_algorithm: str
    policy_digest: str
    layout: str | None
    local_min_device_count: int | None
    local_min_total_gib: int | None
    provider_local_device_count: int | None
    provider_local_total_gib: int | None
    block_volume: BlockVolumePolicy | None

    def __post_init__(self) -> None:
        if self.layout not in {None, "single", "raid0"} or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in (
                self.local_min_device_count,
                self.local_min_total_gib,
                self.provider_local_device_count,
                self.provider_local_total_gib,
            )
            if value is not None
        ):
            raise ConfigurationError("OCI storage capacity input is invalid")
        if (
            not isinstance(self.requested_backend, StorageBackend)
            or not isinstance(self.selected_backend, StorageBackend)
            or self.selected_backend is StorageBackend.AUTO
            or self.selection_algorithm != OCI_INPUT_SELECTION_ALGORITHM
            or not _DIGEST.fullmatch(self.policy_digest)
        ):
            raise ConfigurationError("OCI storage input is invalid")
        if (
            self.requested_backend is not StorageBackend.AUTO
            and self.requested_backend is not self.selected_backend
        ):
            raise ConfigurationError("OCI selected storage backend conflicts")
        if self.selected_backend is StorageBackend.LOCAL_NVME and (
            self.local_min_device_count is None or self.local_min_total_gib is None
        ):
            raise ConfigurationError("OCI local-NVMe input lacks capability minimums")
        if self.selected_backend is StorageBackend.LOCAL_NVME:
            minimum_count = cast(int, self.local_min_device_count)
            minimum_total = cast(int, self.local_min_total_gib)
            if (
                self.provider_local_device_count is None
                or self.provider_local_total_gib is None
                or self.provider_local_device_count < minimum_count
                or self.provider_local_total_gib < minimum_total
            ):
                raise ConfigurationError("OCI local-NVMe capability facts conflict")
        elif (
            self.provider_local_device_count is not None
            or self.provider_local_total_gib is not None
        ):
            raise ConfigurationError("OCI non-local storage has local capability facts")
        if self.selected_backend is StorageBackend.BLOCK_VOLUME and (
            self.block_volume is None
        ):
            raise ConfigurationError("OCI block-volume input lacks volume policy")
        if self.requested_backend is StorageBackend.LOCAL_NVME and (
            self.block_volume is not None
        ):
            raise ConfigurationError("OCI local-NVMe input contains block fallback")
        if self.requested_backend is StorageBackend.BLOCK_VOLUME and (
            self.local_min_device_count is not None
            or self.local_min_total_gib is not None
        ):
            raise ConfigurationError("OCI block-volume input contains local minimums")
        if self.requested_backend is StorageBackend.AUTO and (
            self.local_min_device_count is None
            or self.local_min_total_gib is None
            or self.block_volume is None
        ):
            raise ConfigurationError("OCI auto storage input is incomplete")
        if self.selected_backend is StorageBackend.BOOT_ONLY and any(
            value is not None
            for value in (
                self.layout,
                self.local_min_device_count,
                self.local_min_total_gib,
                self.block_volume,
            )
        ):
            raise ConfigurationError("OCI boot-only storage input is not empty")

    def to_object(self) -> dict[str, object]:
        return {
            "block_volume": (
                self.block_volume.to_object() if self.block_volume is not None else None
            ),
            "layout": self.layout,
            "local_min_device_count": self.local_min_device_count,
            "local_min_total_gib": self.local_min_total_gib,
            "policy_digest": self.policy_digest,
            "provider_local_device_count": self.provider_local_device_count,
            "provider_local_total_gib": self.provider_local_total_gib,
            "requested_backend": self.requested_backend.value,
            "selected_backend": self.selected_backend.value,
            "selection_algorithm": self.selection_algorithm,
        }


@dataclass(frozen=True, slots=True)
class OciHostInput:
    logical_id: str
    role: HostRole
    zone: str
    shape: str
    image_id: str
    image_name: str
    image_time_created: str
    subnet_id: str | None
    subnet_key: str | None
    assign_public_ip: bool
    scylla_datacenter: str | None
    scylla_rack: str | None
    storage: OciStorageInput
    freeform_tags: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if (
            not _LOGICAL_ID.fullmatch(self.logical_id)
            or not isinstance(self.role, HostRole)
            or not self.zone
            or not self.zone.isascii()
            or not self.shape
            or not self.shape.isascii()
        ):
            raise ConfigurationError("OCI host input identity is invalid")
        _require_ocid(self.image_id, "OCI host image ID", kind="image")
        if not self.image_name or not self.image_name.isascii():
            raise ConfigurationError("OCI host image name is invalid")
        _parse_oci_time(self.image_time_created)
        if self.subnet_id is not None:
            _require_ocid(self.subnet_id, "OCI subnet ID", kind="subnet")
        if self.subnet_key is not None and (
            not self.subnet_key.isascii() or ":" not in self.subnet_key
        ):
            raise ConfigurationError("OCI managed subnet key is invalid")
        if (self.subnet_id is None) == (self.subnet_key is None):
            raise ConfigurationError(
                "OCI host must select exactly one existing or managed subnet"
            )
        if not isinstance(self.assign_public_ip, bool) or (
            self.assign_public_ip and self.role is not HostRole.JUMP_HOST
        ):
            raise ConfigurationError("OCI host public-IP policy is invalid")
        if self.role is HostRole.SCYLLA:
            if self.scylla_datacenter is None or self.scylla_rack is None:
                raise ConfigurationError("OCI Scylla topology is incomplete")
        elif self.scylla_datacenter is not None or self.scylla_rack is not None:
            raise ConfigurationError("OCI non-Scylla topology must be null")
        if self.freeform_tags != tuple(sorted(set(self.freeform_tags))):
            raise ConfigurationError("OCI freeform tags must be uniquely sorted")
        if self.role is HostRole.JUMP_HOST:
            if self.storage.selected_backend is not StorageBackend.BOOT_ONLY:
                raise ConfigurationError("OCI jump host storage must be boot-only")
        elif self.role is HostRole.SCYLLA:
            if self.storage.selected_backend is StorageBackend.BOOT_ONLY:
                raise ConfigurationError("OCI Scylla storage cannot be boot-only")
        elif self.storage.selected_backend is not StorageBackend.BLOCK_VOLUME:
            raise ConfigurationError("OCI service storage must be block-volume")

    def to_object(self) -> dict[str, object]:
        return {
            "assign_public_ip": self.assign_public_ip,
            "freeform_tags": dict(self.freeform_tags),
            "image_id": self.image_id,
            "image_name": self.image_name,
            "image_time_created": self.image_time_created,
            "logical_id": self.logical_id,
            "role": self.role.value,
            "scylla_datacenter": self.scylla_datacenter,
            "scylla_rack": self.scylla_rack,
            "shape": self.shape,
            "storage": self.storage.to_object(),
            "subnet_id": self.subnet_id,
            "subnet_key": self.subnet_key,
            "zone": self.zone,
        }


@dataclass(frozen=True, slots=True)
class OciNetworkInput:
    mode: str
    vcn_id: str | None
    subnet_ids: tuple[tuple[str, str], ...]
    vcn_cidr: str | None
    private_subnet_cidrs: tuple[tuple[str, str], ...]
    public_subnet_cidrs: tuple[tuple[str, str], ...]
    operator_cidrs: tuple[str, ...]
    allow_public_jump_hosts: bool

    def __post_init__(self) -> None:
        if self.mode not in {"create", "existing"} or not isinstance(
            self.allow_public_jump_hosts, bool
        ):
            raise ConfigurationError("OCI network input is invalid")
        if self.subnet_ids != tuple(sorted(set(self.subnet_ids))):
            raise ConfigurationError("OCI subnet inputs must be uniquely sorted")
        if self.private_subnet_cidrs != tuple(
            sorted(set(self.private_subnet_cidrs))
        ) or self.public_subnet_cidrs != tuple(sorted(set(self.public_subnet_cidrs))):
            raise ConfigurationError("OCI managed subnet CIDRs must be uniquely sorted")
        for role, subnet_id in self.subnet_ids:
            try:
                HostRole(role)
            except ValueError as error:
                raise ConfigurationError("OCI subnet role is invalid") from error
            _require_ocid(subnet_id, "OCI subnet ID", kind="subnet")
        if self.mode == "create":
            if self.vcn_id is not None or self.subnet_ids:
                raise ConfigurationError("managed OCI network forbids selectors")
            if self.vcn_cidr is None or not self.private_subnet_cidrs:
                raise ConfigurationError("managed OCI network CIDRs are incomplete")
            vcn = _managed_network(self.vcn_cidr, "OCI VCN CIDR")
            networks: list[ipaddress.IPv4Network] = []
            for _, value in (*self.private_subnet_cidrs, *self.public_subnet_cidrs):
                subnet = _managed_network(value, "OCI subnet CIDR")
                if not subnet.subnet_of(vcn):
                    raise ConfigurationError("OCI subnet CIDR is outside the VCN")
                if any(subnet.overlaps(existing) for existing in networks):
                    raise ConfigurationError("OCI subnet CIDRs overlap")
                networks.append(subnet)
        elif self.vcn_id is None:
            raise ConfigurationError("existing OCI network requires VCN identity")
        else:
            _require_ocid(self.vcn_id, "OCI VCN ID", kind="vcn")
            if (
                self.vcn_cidr is not None
                or self.private_subnet_cidrs
                or self.public_subnet_cidrs
            ):
                raise ConfigurationError("existing OCI network forbids managed CIDRs")
        if self.operator_cidrs != tuple(sorted(set(self.operator_cidrs))):
            raise ConfigurationError("OCI operator CIDRs must be uniquely sorted")
        for cidr in self.operator_cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=True)
            except ValueError as error:
                raise ConfigurationError("OCI operator CIDR is invalid") from error
            if str(network) != cidr:
                raise ConfigurationError("OCI operator CIDR is not canonical")
            if network.prefixlen == 0:
                raise ConfigurationError("OCI operator ingress cannot allow all")
        if self.allow_public_jump_hosts:
            if not self.operator_cidrs or (
                self.mode == "create" and not self.public_subnet_cidrs
            ):
                raise ConfigurationError("public OCI jump-host policy is incomplete")
        elif self.public_subnet_cidrs:
            raise ConfigurationError("public OCI subnet requires public jump hosts")

    def to_object(self) -> dict[str, object]:
        return {
            "allow_public_jump_hosts": self.allow_public_jump_hosts,
            "mode": self.mode,
            "operator_cidrs": list(self.operator_cidrs),
            "private_subnet_cidrs": dict(self.private_subnet_cidrs),
            "public_subnet_cidrs": dict(self.public_subnet_cidrs),
            "subnet_ids": dict(self.subnet_ids),
            "vcn_cidr": self.vcn_cidr,
            "vcn_id": self.vcn_id,
        }


@dataclass(frozen=True, slots=True)
class OciTerraformInput:
    cluster_uuid: uuid.UUID
    cluster_name: str
    provider: str
    region: str
    compartment_id: str
    image_filters: tuple[tuple[HostRole, ImageFilter], ...]
    public_ssh_key: str
    network: OciNetworkInput
    hosts: tuple[OciHostInput, ...]
    schema_version: str = OCI_TERRAFORM_INPUT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != OCI_TERRAFORM_INPUT_SCHEMA_VERSION:
            raise ConfigurationError("unsupported OCI Terraform input schema")
        if self.provider != "oci" or not isinstance(self.cluster_uuid, uuid.UUID):
            raise ConfigurationError("OCI Terraform input identity is invalid")
        validate_cluster_name(self.cluster_name)
        if not self.region or not self.region.isascii():
            raise ConfigurationError("OCI Terraform region is invalid")
        _require_ocid(self.compartment_id, "OCI compartment ID", kind="compartment")
        if self.image_filters != tuple(
            sorted(self.image_filters, key=lambda item: item[0].value)
        ) or any(
            not isinstance(role, HostRole) or not isinstance(image_filter, ImageFilter)
            for role, image_filter in self.image_filters
        ):
            raise ConfigurationError("OCI Terraform image filters are invalid")
        validate_public_ssh_key_text(self.public_ssh_key)
        logical_ids = tuple(host.logical_id for host in self.hosts)
        if not logical_ids or logical_ids != tuple(sorted(set(logical_ids))):
            raise ConfigurationError("OCI Terraform hosts must be uniquely sorted")
        if {role for role, _ in self.image_filters} != {
            host.role for host in self.hosts
        }:
            raise ConfigurationError("OCI Terraform image filters do not cover hosts")
        subnet_map = dict(self.network.subnet_ids)
        active_roles = {host.role.value for host in self.hosts}
        if self.network.mode == "existing":
            if set(subnet_map) != active_roles or any(
                host.subnet_id != subnet_map[host.role.value] for host in self.hosts
            ):
                raise ConfigurationError("OCI host subnet selection conflicts")
        elif any(host.subnet_id is not None for host in self.hosts):
            raise ConfigurationError("managed OCI hosts cannot select existing subnets")
        if any(
            host.role is HostRole.JUMP_HOST
            and host.assign_public_ip != self.network.allow_public_jump_hosts
            for host in self.hosts
        ):
            raise ConfigurationError("OCI public jump-host policy conflicts")
        if any(host.role is HostRole.JUMP_HOST for host in self.hosts) and not (
            self.network.operator_cidrs
        ):
            raise ConfigurationError("OCI jump hosts require operator CIDRs")
        for host in self.hosts:
            if host.storage.policy_digest != _storage_policy_digest(
                host.role, host.storage
            ):
                raise ConfigurationError("OCI storage policy digest conflicts")
            expected_tags = {
                "deploy-scylla-vms.cluster-name": self.cluster_name,
                "deploy-scylla-vms.cluster-uuid": str(self.cluster_uuid),
                "deploy-scylla-vms.logical-id": host.logical_id,
                "deploy-scylla-vms.managed-by": "deploy-scylla-vms",
                "deploy-scylla-vms.role": host.role.value,
                "deploy-scylla-vms.zone": host.zone,
            }
            if host.scylla_datacenter is not None:
                expected_tags["deploy-scylla-vms.scylla-datacenter"] = (
                    host.scylla_datacenter
                )
            if host.scylla_rack is not None:
                expected_tags["deploy-scylla-vms.scylla-rack"] = host.scylla_rack
            if dict(host.freeform_tags) != expected_tags:
                raise ConfigurationError("OCI host ownership tags conflict")
        value = self.to_object()
        _reject_secret_material(value)

    def to_object(self) -> dict[str, object]:
        return {
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "compartment_id": self.compartment_id,
            "hosts": [host.to_object() for host in self.hosts],
            "image_filters": {
                role.value: image_filter.to_object()
                for role, image_filter in self.image_filters
            },
            "network": self.network.to_object(),
            "provider": self.provider,
            "public_ssh_key": self.public_ssh_key,
            "region": self.region,
            "schema_version": self.schema_version,
        }

    def digest(self) -> str:
        encoded = json.dumps(
            self.to_object(),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    @classmethod
    def from_object(cls, value: object) -> "OciTerraformInput":
        _reject_secret_material(value)
        item = _object(
            value,
            {
                "cluster_name",
                "cluster_uuid",
                "compartment_id",
                "hosts",
                "image_filters",
                "network",
                "provider",
                "public_ssh_key",
                "region",
                "schema_version",
            },
            "OCI Terraform input",
        )
        network = _parse_network(item["network"])
        hosts_value = item["hosts"]
        if not isinstance(hosts_value, list):
            raise ConfigurationError("OCI Terraform hosts must be an array")
        try:
            cluster_uuid = uuid.UUID(_string(item, "cluster_uuid"))
        except ValueError as error:
            raise ConfigurationError("OCI Terraform cluster UUID is invalid") from error
        image_filters = _string_object_map(item["image_filters"], "image filters")
        result = cls(
            cluster_uuid,
            _string(item, "cluster_name"),
            _string(item, "provider"),
            _string(item, "region"),
            _string(item, "compartment_id"),
            tuple(
                (
                    HostRole(role),
                    ImageFilter.from_object(image_filters[role]),
                )
                for role in sorted(image_filters)
            ),
            _string(item, "public_ssh_key"),
            network,
            tuple(_parse_host(host) for host in hosts_value),
            _string(item, "schema_version"),
        )
        if result.to_object() != value:
            raise ConfigurationError("OCI Terraform input is not canonical")
        return result


@dataclass(frozen=True, slots=True)
class OciAdapter:
    name: str = "oci"

    def build_terraform_input(
        self,
        spec: ClusterSpec,
        capabilities: ProviderCapabilities,
        *,
        public_ssh_key: str,
        change_intent: tuple[ProposedChange, ...] = (),
    ) -> ProviderTerraformInput:
        if spec.provider != self.name:
            raise ConfigurationError("OCI adapter requires an OCI cluster")
        if not isinstance(capabilities, OciCapabilities):
            raise ConfigurationError("OCI adapter requires OCI capabilities")
        if change_intent:
            raise StateConflictError(
                "Terraform input changes require an implemented operation workflow"
            )
        if capabilities.region != spec.oci_region:
            raise ConfigurationError(
                "OCI capability region conflicts with desired state"
            )
        desired_zones = {zone.zone_id for zone in spec.zones}
        if not desired_zones <= set(capabilities.zones):
            raise ConfigurationError("desired OCI zone is not in supplied capabilities")
        validate_public_ssh_key_text(public_ssh_key)
        shape_map = {shape.shape: shape for shape in capabilities.shapes}
        required_shapes = {
            spec.scylla_instance_type,
            *(
                cast(str, service.instance_type)
                for service in spec.services
                if service.count
            ),
        }
        if not required_shapes <= set(shape_map):
            raise ConfigurationError("OCI shape capability is unavailable")
        image_filters = dict(spec.image_filters)
        selected_images = {
            (role, shape): _select_image(
                image_filters[role], capability, capabilities.images
            )
            for role, shape in {
                (HostRole.SCYLLA, spec.scylla_instance_type),
                *(
                    (service.role, cast(str, service.instance_type))
                    for service in spec.services
                    if service.count
                ),
            }
            for capability in (shape_map[shape],)
        }
        pinned_images = dict(capabilities.pinned_images)
        desired_ids = {
            *(
                logical_id
                for zone in spec.zones
                for logical_id in zone.logical_node_ids
            ),
            *(
                logical_id
                for service in spec.services
                for logical_id in service.logical_ids
            ),
        }
        if not set(pinned_images) <= desired_ids:
            raise ConfigurationError("OCI pinned image names an unknown logical host")
        policies = {policy.role: policy for policy in spec.storage}
        subnets = {role: value for role, value in spec.network.subnets}
        hosts: list[OciHostInput] = []
        for zone in spec.zones:
            for logical_id in zone.logical_node_ids:
                hosts.append(
                    _host_input(
                        spec,
                        capabilities,
                        shape_map,
                        selected_images,
                        pinned_images,
                        policies[HostRole.SCYLLA],
                        subnets,
                        logical_id,
                        HostRole.SCYLLA,
                        zone.zone_id,
                        spec.scylla_instance_type,
                        spec.scylla_datacenter.value,
                        zone.scylla_rack.value,
                    )
                )
        for service in spec.services:
            for logical_id, service_zone in zip(
                service.logical_ids, service.zones, strict=True
            ):
                if service.instance_type is None:
                    raise ConfigurationError(
                        "deployed OCI service shape is unavailable"
                    )
                hosts.append(
                    _host_input(
                        spec,
                        capabilities,
                        shape_map,
                        selected_images,
                        pinned_images,
                        policies[service.role],
                        subnets,
                        logical_id,
                        service.role,
                        service_zone,
                        service.instance_type,
                        None,
                        None,
                    )
                )
        if any(host.role is HostRole.JUMP_HOST for host in hosts) and not (
            spec.network.operator_cidrs
        ):
            raise ConfigurationError(
                "OCI jump hosts require explicit operator ingress CIDRs"
            )
        network = OciNetworkInput(
            spec.network.mode.value,
            spec.network.vcn_id,
            tuple(
                sorted((role.value, subnet_id) for role, subnet_id in subnets.items())
            ),
            spec.network.vcn_cidr,
            spec.network.private_subnet_cidrs,
            spec.network.public_subnet_cidrs,
            spec.network.operator_cidrs,
            spec.network.public_endpoints,
        )
        return OciTerraformInput(
            spec.cluster_uuid,
            spec.cluster_name,
            "oci",
            spec.oci_region,
            spec.oci_compartment_id,
            spec.image_filters,
            public_ssh_key,
            network,
            tuple(sorted(hosts, key=lambda host: host.logical_id)),
        )


OCI_ADAPTER = OciAdapter()


def _select_image(
    image_filter: ImageFilter,
    shape: OciShapeCapability,
    candidates: tuple[OciImageCandidate, ...],
) -> OciSelectedImage:
    matches = [
        candidate
        for candidate in candidates
        if candidate.state == "AVAILABLE"
        and candidate.operating_system == image_filter.operating_system
        and _version_matches(
            candidate.operating_system_version,
            image_filter.operating_system_version,
            image_filter.version_match,
        )
        and candidate.architecture == shape.architecture
        and shape.shape in candidate.compatible_shapes
    ]
    if not matches:
        raise ConfigurationError(
            f"no AVAILABLE OCI image matches the explicit filter for shape {shape.shape}"
        )
    newest = max(_parse_oci_time(candidate.time_created) for candidate in matches)
    selected = [
        candidate
        for candidate in matches
        if _parse_oci_time(candidate.time_created) == newest
    ]
    if len(selected) != 1:
        raise ConfigurationError(
            f"OCI image selection is ambiguous for shape {shape.shape}"
        )
    image = selected[0]
    return OciSelectedImage(
        image.image_id,
        image.display_name,
        image.time_created,
        image.operating_system,
        image.operating_system_version,
        image.architecture,
    )


def _version_matches(candidate: str, requested: str, policy: ImageVersionMatch) -> bool:
    if policy is ImageVersionMatch.EXACT:
        return candidate == requested
    return candidate.startswith(requested)


def _parse_oci_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ConfigurationError("OCI image creation time is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ConfigurationError("OCI image creation time must be UTC")
    return parsed.astimezone(UTC)


def _host_input(
    spec: ClusterSpec,
    capabilities: OciCapabilities,
    shape_map: dict[str, OciShapeCapability],
    selected_images: dict[tuple[HostRole, str], OciSelectedImage],
    pinned_images: dict[str, OciSelectedImage],
    policy: StoragePolicy,
    subnets: dict[HostRole, str],
    logical_id: str,
    role: HostRole,
    zone: str,
    shape: str,
    datacenter: str | None,
    rack: str | None,
) -> OciHostInput:
    capability = shape_map.get(shape)
    if capability is None or zone not in capability.zones:
        raise ConfigurationError("OCI shape capability is unavailable in desired zone")
    storage = _storage_input(policy, capability)
    image = pinned_images.get(logical_id, selected_images[(role, shape)])
    desired_filter = dict(spec.image_filters)[role]
    if (
        image.architecture != capability.architecture
        or image.operating_system != desired_filter.operating_system
        or not _version_matches(
            image.operating_system_version,
            desired_filter.operating_system_version,
            desired_filter.version_match,
        )
    ):
        raise ConfigurationError("OCI pinned image conflicts with desired host policy")
    tags = {
        "deploy-scylla-vms.cluster-name": spec.cluster_name,
        "deploy-scylla-vms.cluster-uuid": str(spec.cluster_uuid),
        "deploy-scylla-vms.logical-id": logical_id,
        "deploy-scylla-vms.managed-by": "deploy-scylla-vms",
        "deploy-scylla-vms.role": role.value,
        "deploy-scylla-vms.zone": zone,
    }
    if datacenter is not None:
        tags["deploy-scylla-vms.scylla-datacenter"] = datacenter
    if rack is not None:
        tags["deploy-scylla-vms.scylla-rack"] = rack
    return OciHostInput(
        logical_id,
        role,
        zone,
        shape,
        image.image_id,
        image.display_name,
        image.time_created,
        subnets.get(role),
        (
            None
            if spec.network.mode.value == "existing"
            else (
                f"public:{zone}"
                if role is HostRole.JUMP_HOST and spec.network.public_endpoints
                else f"private:{zone}"
            )
        ),
        role is HostRole.JUMP_HOST and spec.network.public_endpoints,
        datacenter,
        rack,
        storage,
        tuple(sorted(tags.items())),
    )


def _storage_input(
    policy: StoragePolicy, capability: OciShapeCapability
) -> OciStorageInput:
    selected = policy.requested_backend
    if policy.requested_backend in {StorageBackend.AUTO, StorageBackend.LOCAL_NVME}:
        minimum_count = policy.local_min_device_count or 0
        minimum_total = policy.local_min_total_gib or 0
        capable = (
            capability.local_nvme_device_count >= minimum_count
            and capability.local_nvme_total_gib >= minimum_total
        )
        if policy.requested_backend is StorageBackend.LOCAL_NVME and not capable:
            raise ConfigurationError(
                "OCI shape local-NVMe capability does not satisfy desired policy"
            )
        selected = StorageBackend.LOCAL_NVME if capable else StorageBackend.BLOCK_VOLUME
    policy_object = policy.to_object()
    policy_digest = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                policy_object,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
    )
    return OciStorageInput(
        policy.requested_backend,
        selected,
        OCI_INPUT_SELECTION_ALGORITHM,
        policy_digest,
        policy.layout.value if policy.layout is not None else None,
        policy.local_min_device_count,
        policy.local_min_total_gib,
        (
            capability.local_nvme_device_count
            if selected is StorageBackend.LOCAL_NVME
            else None
        ),
        (
            capability.local_nvme_total_gib
            if selected is StorageBackend.LOCAL_NVME
            else None
        ),
        policy.block_volume,
    )


def _storage_policy_digest(role: HostRole, storage: OciStorageInput) -> str:
    value = {
        "block_volume": (
            storage.block_volume.to_object()
            if storage.block_volume is not None
            else None
        ),
        "layout": storage.layout,
        "local_min_device_count": storage.local_min_device_count,
        "local_min_total_gib": storage.local_min_total_gib,
        "requested_backend": storage.requested_backend.value,
        "role": role.value,
    }
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
    )


def _parse_network(value: object) -> OciNetworkInput:
    item = _object(
        value,
        {
            "allow_public_jump_hosts",
            "mode",
            "operator_cidrs",
            "private_subnet_cidrs",
            "public_subnet_cidrs",
            "subnet_ids",
            "vcn_cidr",
            "vcn_id",
        },
        "OCI network input",
    )
    subnet_value = item["subnet_ids"]
    if not isinstance(subnet_value, dict) or not all(
        isinstance(key, str) and isinstance(entry, str)
        for key, entry in subnet_value.items()
    ):
        raise ConfigurationError("OCI subnet inputs must be a string map")
    cidrs = item["operator_cidrs"]
    if not isinstance(cidrs, list) or not all(isinstance(cidr, str) for cidr in cidrs):
        raise ConfigurationError("OCI operator CIDRs must be a string array")
    private_cidrs = _string_map(item["private_subnet_cidrs"], "private subnet CIDRs")
    public_cidrs = _string_map(item["public_subnet_cidrs"], "public subnet CIDRs")
    return OciNetworkInput(
        _string(item, "mode"),
        _optional_string(item["vcn_id"]),
        tuple(sorted(cast(dict[str, str], subnet_value).items())),
        _optional_string(item["vcn_cidr"]),
        tuple(sorted(private_cidrs.items())),
        tuple(sorted(public_cidrs.items())),
        tuple(cast(list[str], cidrs)),
        _boolean(item, "allow_public_jump_hosts"),
    )


def _parse_host(value: object) -> OciHostInput:
    item = _object(
        value,
        {
            "assign_public_ip",
            "freeform_tags",
            "image_id",
            "image_name",
            "image_time_created",
            "logical_id",
            "role",
            "scylla_datacenter",
            "scylla_rack",
            "shape",
            "storage",
            "subnet_id",
            "subnet_key",
            "zone",
        },
        "OCI host input",
    )
    try:
        role = HostRole(_string(item, "role"))
    except ValueError as error:
        raise ConfigurationError("OCI host role is invalid") from error
    tags_value = item["freeform_tags"]
    if not isinstance(tags_value, dict) or not all(
        isinstance(key, str) and isinstance(entry, str)
        for key, entry in tags_value.items()
    ):
        raise ConfigurationError("OCI freeform tags must be a string map")
    return OciHostInput(
        _string(item, "logical_id"),
        role,
        _string(item, "zone"),
        _string(item, "shape"),
        _string(item, "image_id"),
        _string(item, "image_name"),
        _string(item, "image_time_created"),
        _optional_string(item["subnet_id"]),
        _optional_string(item["subnet_key"]),
        _boolean(item, "assign_public_ip"),
        _optional_string(item["scylla_datacenter"]),
        _optional_string(item["scylla_rack"]),
        _parse_storage(item["storage"]),
        tuple(sorted(cast(dict[str, str], tags_value).items())),
    )


def _parse_storage(value: object) -> OciStorageInput:
    item = _object(
        value,
        {
            "block_volume",
            "layout",
            "local_min_device_count",
            "local_min_total_gib",
            "policy_digest",
            "provider_local_device_count",
            "provider_local_total_gib",
            "requested_backend",
            "selected_backend",
            "selection_algorithm",
        },
        "OCI storage input",
    )
    try:
        requested = StorageBackend(_string(item, "requested_backend"))
        selected = StorageBackend(_string(item, "selected_backend"))
    except ValueError as error:
        raise ConfigurationError("OCI storage backend is invalid") from error
    block = item["block_volume"]
    return OciStorageInput(
        requested,
        selected,
        _string(item, "selection_algorithm"),
        _string(item, "policy_digest"),
        _optional_string(item["layout"]),
        _optional_int(item["local_min_device_count"]),
        _optional_int(item["local_min_total_gib"]),
        _optional_int(item["provider_local_device_count"]),
        _optional_int(item["provider_local_total_gib"]),
        None if block is None else BlockVolumePolicy.from_object(block),
    )


def _object(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ConfigurationError(f"{label} fields do not match the schema")
    return cast(dict[str, object], value)


def _string(value: dict[str, object], key: str) -> str:
    item = value[key]
    if not isinstance(item, str) or not item:
        raise ConfigurationError(f"OCI Terraform input string is invalid: {key}")
    return item


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ConfigurationError("OCI Terraform optional string is invalid")
    return value


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConfigurationError("OCI Terraform optional integer is invalid")
    return value


def _string_map(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    ):
        raise ConfigurationError(f"OCI {label} must be a string map")
    return cast(dict[str, str], value)


def _string_object_map(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ConfigurationError(f"OCI {label} must be an object map")
    return cast(dict[str, object], value)


def _boolean(value: dict[str, object], key: str) -> bool:
    item = value[key]
    if not isinstance(item, bool):
        raise ConfigurationError(f"OCI Terraform boolean is invalid: {key}")
    return item


def _require_ocid(value: str, label: str, *, kind: str) -> None:
    if not _OCID.fullmatch(value) or not value.startswith(f"ocid1.{kind}."):
        raise ConfigurationError(f"{label} is invalid")


def _managed_network(value: str, label: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise ConfigurationError(f"{label} is invalid") from error
    private_ranges = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    if (
        not isinstance(network, ipaddress.IPv4Network)
        or not any(network.subnet_of(item) for item in private_ranges)
        or not 16 <= network.prefixlen <= 30
        or str(network) != value
    ):
        raise ConfigurationError(f"{label} must be canonical RFC 1918 IPv4")
    return network


def _reject_secret_material(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _SECRET_KEY.search(str(key)):
                raise ConfigurationError("Terraform input contains a secret-like field")
            _reject_secret_material(item)
    elif isinstance(value, list):
        for item in value:
            _reject_secret_material(item)
    elif isinstance(value, str) and _SECRET_VALUE.search(value):
        raise ConfigurationError("Terraform input contains secret-like material")
