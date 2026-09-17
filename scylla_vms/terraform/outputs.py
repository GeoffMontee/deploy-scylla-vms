"""Strict immutable Terraform output, host, and storage manifest schemas."""

import ipaddress
import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any

from scylla_vms.desired import ClusterSpec, HostRole, StorageBackend
from scylla_vms.errors import TerraformError

TERRAFORM_OUTPUT_SCHEMA_VERSION = "deploy-scylla-vms.terraform-output/v1"
TERRAFORM_IMAGE_SELECTION_OUTPUT_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-output-partial/v2"
)
TERRAFORM_IMAGE_SELECTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-image-selection/v1"
)
TERRAFORM_NETWORK_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.terraform-network-evidence/v1"
)
HOST_MANIFEST_SCHEMA_VERSION = "deploy-scylla-vms.host-manifest/v1"
STORAGE_MANIFEST_SCHEMA_VERSION = "deploy-scylla-vms.storage-manifest/v1"
MAXIMUM_TERRAFORM_OUTPUT_BYTES = 4 * 1024 * 1024
MAXIMUM_JSON_DEPTH = 32
MAXIMUM_HOSTS = 4096
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_SHAPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")
_OCID = re.compile(r"ocid1\.[a-z0-9-]+\.[A-Za-z0-9.-]*\.[A-Za-z0-9._:+/-]+\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SECRET_KEY = re.compile(
    r"(?i)(?:password|passphrase|secret|token|private[_-]?key|credential)"
)
_SECRET_VALUE = re.compile(
    r"(?i)(?:-----BEGIN [^-]*PRIVATE KEY-----|"
    r"(?:password|passphrase|secret|token)\s*[:=])"
)


class TerraformContractError(TerraformError):
    """Terraform output failed a strict machine-readable contract."""


class StorageSelectionStatus(StrEnum):
    PROVISIONAL = "provisional"
    FINAL = "final"


class StorageDeviceKind(StrEnum):
    LOCAL_NVME = "local-nvme"
    BLOCK_VOLUME = "block-volume"


@dataclass(frozen=True, slots=True)
class StorageDevice:
    kind: StorageDeviceKind
    provider_volume_id: str | None
    provider_attachment_id: str | None
    local_device_id: str | None
    requested_path: str | None
    expected_serial: str | None
    expected_wwn: str | None
    expected_by_id: str | None
    size_gib: int
    ephemeral: bool
    attachment_type: str | None
    iqn: str | None
    portal: str | None
    multipath_id: str | None
    in_transit_encryption: bool
    at_rest_encryption: str
    customer_key_id: str | None
    vpus_per_gb: int | None
    retention: str | None


@dataclass(frozen=True, slots=True)
class StorageManifest:
    requested_backend: StorageBackend
    selected_backend: StorageBackend
    selection_algorithm: str
    selection_status: StorageSelectionStatus
    policy_digest: str
    storage_generation: int
    expected_device_count: int
    raw_total_gib: int
    usable_total_gib: int
    layout: str | None
    raid_device: str | None
    filesystem_type: str | None
    filesystem_label: str | None
    mount_strategy: str | None
    mount_point: str | None
    mount_options: tuple[str, ...]
    role_allocations: tuple[str, ...]
    devices: tuple[StorageDevice, ...]
    schema_version: str = STORAGE_MANIFEST_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class TerraformHost:
    logical_id: str
    role: HostRole
    zone: str
    provider_id: str
    private_address: str
    public_address: str | None
    jump_host_id: str | None
    scylla_datacenter: str | None
    scylla_rack: str | None
    shape: str
    storage: StorageManifest


@dataclass(frozen=True, slots=True)
class TerraformHostManifest:
    cluster_uuid: uuid.UUID
    hosts: tuple[TerraformHost, ...]
    schema_version: str = HOST_MANIFEST_SCHEMA_VERSION

    def to_object(self, *, include_addresses: bool = False) -> dict[str, object]:
        """Return a deterministic allowlist projection; addresses are opt-in."""

        return {
            "cluster_uuid": str(self.cluster_uuid),
            "hosts": [
                _host_object(host, include_addresses=include_addresses)
                for host in self.hosts
            ],
            "schema_version": self.schema_version,
        }

    def to_persistence_object(self) -> dict[str, object]:
        """Return the complete strict manifest for protected local persistence."""

        return {
            "cluster_uuid": str(self.cluster_uuid),
            "hosts": [_host_persistence_object(host) for host in self.hosts],
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True, slots=True)
class TerraformImageEvidence:
    logical_id: str
    role: HostRole
    shape: str
    image_id: str
    image_name: str
    image_time_created: str
    operating_system: str
    operating_system_version: str
    version_match: str


@dataclass(frozen=True, slots=True)
class TerraformImageSelection:
    cluster_uuid: uuid.UUID
    cluster_name: str
    provider: str
    images: tuple[TerraformImageEvidence, ...]
    schema_version: str = TERRAFORM_IMAGE_SELECTION_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class TerraformNetworkOwnership:
    vcn: bool
    gateways: bool
    route_tables: bool
    subnets: bool


@dataclass(frozen=True, slots=True)
class TerraformNetworkSubnet:
    zone: str
    role: str
    access: str
    subnet_id: str
    owned: bool


@dataclass(frozen=True, slots=True)
class TerraformNetworkEvidence:
    cluster_uuid: uuid.UUID
    cluster_name: str
    provider: str
    mode: str
    vcn_id: str
    external_routing_validated: bool
    ownership: TerraformNetworkOwnership
    subnets: tuple[TerraformNetworkSubnet, ...]
    network_security_groups: tuple[tuple[str, str], ...]
    schema_version: str = TERRAFORM_NETWORK_EVIDENCE_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class TerraformOutputBundle:
    """Complete strict output evidence retained only in memory."""

    manifest: TerraformHostManifest
    image_selection: TerraformImageSelection
    network: TerraformNetworkEvidence
    schema_version: str = TERRAFORM_OUTPUT_SCHEMA_VERSION


def terraform_image_selection_type_descriptor() -> list[object]:
    """Return the exact Terraform JSON type for partial image-selection output."""

    image_filter = _terraform_object_type(
        {
            "operating_system": "string",
            "operating_system_version": "string",
            "version_match": "string",
        }
    )
    image = _terraform_object_type(
        {
            "filter": image_filter,
            "image_id": "string",
            "image_name": "string",
            "image_time_created": "string",
            "logical_id": "string",
            "role": "string",
            "shape": "string",
        }
    )
    return _terraform_object_type(
        {
            "cluster_name": "string",
            "cluster_uuid": "string",
            "images": ["list", image],
            "provider": "string",
            "schema_version": "string",
        }
    )


def terraform_network_evidence_type_descriptor() -> list[object]:
    """Return the exact Terraform JSON type for partial network evidence."""

    ownership = _terraform_object_type(
        {
            "gateways": "bool",
            "route_tables": "bool",
            "subnets": "bool",
            "vcn": "bool",
        }
    )
    subnet = _terraform_object_type(
        {
            "access": "string",
            "owned": "bool",
            "role": "string",
            "subnet_id": "string",
            "zone": "string",
        }
    )
    network_security_group = _terraform_object_type(
        {
            "id": "string",
            "role": "string",
        }
    )
    return _terraform_object_type(
        {
            "cluster_name": "string",
            "cluster_uuid": "string",
            "external_routing_validated": "bool",
            "mode": "string",
            "network_security_groups": ["list", network_security_group],
            "ownership": ownership,
            "provider": "string",
            "schema_version": "string",
            "subnets": ["list", subnet],
            "vcn_id": "string",
        }
    )


def parse_terraform_image_selection_outputs(
    data: str | bytes, *, expected_cluster_uuid: uuid.UUID
) -> TerraformImageSelection:
    """Parse image evidence from the strict non-planning-ready OCI outputs."""

    return _parse_terraform_partial_outputs(
        data, expected_cluster_uuid=expected_cluster_uuid
    )[0]


def parse_terraform_network_outputs(
    data: str | bytes, *, expected_cluster_uuid: uuid.UUID
) -> TerraformNetworkEvidence:
    """Parse network evidence from the strict non-planning-ready OCI outputs."""

    return _parse_terraform_partial_outputs(
        data, expected_cluster_uuid=expected_cluster_uuid
    )[1]


def _parse_terraform_partial_outputs(
    data: str | bytes, *, expected_cluster_uuid: uuid.UUID
) -> tuple[TerraformImageSelection, TerraformNetworkEvidence]:
    root = _load_bounded_json(data)
    envelope = _object(
        root,
        {"schema_version", "image_selection", "network_evidence"},
        "output envelope",
    )
    schema_output = _object(
        envelope["schema_version"],
        {"sensitive", "type", "value"},
        "schema_version output",
    )
    if (
        schema_output["sensitive"] is not False
        or schema_output["type"] != "string"
        or schema_output["value"] != TERRAFORM_IMAGE_SELECTION_OUTPUT_SCHEMA_VERSION
    ):
        raise TerraformContractError("unsupported Terraform image output schema")
    image_selection = _parse_image_selection_output(
        envelope, expected_cluster_uuid=expected_cluster_uuid
    )
    network_evidence = _parse_network_evidence_output(
        envelope, expected_cluster_uuid=expected_cluster_uuid
    )
    if (
        image_selection.cluster_name != network_evidence.cluster_name
        or image_selection.provider != network_evidence.provider
    ):
        raise TerraformContractError("Terraform partial output identities conflict")
    return image_selection, network_evidence


def _parse_image_selection_output(
    envelope: dict[str, object], *, expected_cluster_uuid: uuid.UUID
) -> TerraformImageSelection:
    output = _object(
        envelope["image_selection"],
        {"sensitive", "type", "value"},
        "image_selection output",
    )
    if (
        output["sensitive"] is not False
        or output["type"] != terraform_image_selection_type_descriptor()
    ):
        raise TerraformContractError("image selection output contract is invalid")
    value = _object(
        output["value"],
        {"cluster_name", "cluster_uuid", "images", "provider", "schema_version"},
        "image selection",
    )
    if value["schema_version"] != TERRAFORM_IMAGE_SELECTION_SCHEMA_VERSION:
        raise TerraformContractError("unsupported Terraform image selection schema")
    cluster_uuid = _uuid(value["cluster_uuid"], "cluster UUID")
    if cluster_uuid != expected_cluster_uuid:
        raise TerraformContractError("Terraform image output identity conflicts")
    cluster_name = _string(value["cluster_name"], "cluster name", _NAME)
    if "--" in cluster_name or cluster_name.endswith("-"):
        raise TerraformContractError("Terraform image output cluster name is invalid")
    if value["provider"] != "oci":
        raise TerraformContractError("Terraform image output provider is invalid")
    images = tuple(
        _parse_image_evidence(item) for item in _array(value["images"], "images")
    )
    logical_ids = tuple(image.logical_id for image in images)
    if (
        not images
        or len(images) > MAXIMUM_HOSTS
        or logical_ids != tuple(sorted(set(logical_ids)))
    ):
        raise TerraformContractError("Terraform image evidence is not uniquely sorted")
    return TerraformImageSelection(cluster_uuid, cluster_name, "oci", images)


def _parse_network_evidence_output(
    envelope: dict[str, object], *, expected_cluster_uuid: uuid.UUID
) -> TerraformNetworkEvidence:
    output = _object(
        envelope["network_evidence"],
        {"sensitive", "type", "value"},
        "network_evidence output",
    )
    if (
        output["sensitive"] is not False
        or output["type"] != terraform_network_evidence_type_descriptor()
    ):
        raise TerraformContractError("network evidence output contract is invalid")
    value = _object(
        output["value"],
        {
            "cluster_name",
            "cluster_uuid",
            "external_routing_validated",
            "mode",
            "network_security_groups",
            "ownership",
            "provider",
            "schema_version",
            "subnets",
            "vcn_id",
        },
        "network evidence",
    )
    if value["schema_version"] != TERRAFORM_NETWORK_EVIDENCE_SCHEMA_VERSION:
        raise TerraformContractError("unsupported Terraform network evidence schema")
    cluster_uuid = _uuid(value["cluster_uuid"], "cluster UUID")
    if cluster_uuid != expected_cluster_uuid:
        raise TerraformContractError("Terraform network output identity conflicts")
    cluster_name = _string(value["cluster_name"], "cluster name", _NAME)
    if "--" in cluster_name or cluster_name.endswith("-"):
        raise TerraformContractError("Terraform network output cluster name is invalid")
    if value["provider"] != "oci":
        raise TerraformContractError("Terraform network output provider is invalid")
    mode = _choice(value["mode"], "network mode", {"create", "existing"})
    vcn_id = _oci_resource_id(value["vcn_id"], "VCN ID", "vcn")
    ownership_value = _object(
        value["ownership"],
        {"gateways", "route_tables", "subnets", "vcn"},
        "network ownership",
    )
    ownership = TerraformNetworkOwnership(
        _boolean(ownership_value["vcn"], "VCN ownership"),
        _boolean(ownership_value["gateways"], "gateway ownership"),
        _boolean(ownership_value["route_tables"], "route-table ownership"),
        _boolean(ownership_value["subnets"], "subnet ownership"),
    )
    expected_owned = mode == "create"
    if any(
        item != expected_owned
        for item in (
            ownership.vcn,
            ownership.gateways,
            ownership.route_tables,
            ownership.subnets,
        )
    ):
        raise TerraformContractError("network ownership conflicts with network mode")
    external_routing_validated = _boolean(
        value["external_routing_validated"], "external routing validation"
    )
    if external_routing_validated:
        raise TerraformContractError(
            "partial Terraform output cannot claim external routing validation"
        )
    subnets = tuple(
        _parse_network_subnet(item) for item in _array(value["subnets"], "subnets")
    )
    subnet_keys = tuple((item.zone, item.role) for item in subnets)
    if (
        not subnets
        or len(subnets) > MAXIMUM_HOSTS
        or subnet_keys != tuple(sorted(set(subnet_keys)))
        or any(subnet.owned != expected_owned for subnet in subnets)
    ):
        raise TerraformContractError("Terraform network subnets are not canonical")
    groups = tuple(
        _parse_network_security_group(item)
        for item in _array(value["network_security_groups"], "network security groups")
    )
    roles = tuple(role for role, _ in groups)
    if not groups or roles != tuple(sorted(set(roles))):
        raise TerraformContractError("Terraform network security groups are invalid")
    return TerraformNetworkEvidence(
        cluster_uuid,
        cluster_name,
        "oci",
        mode,
        vcn_id,
        external_routing_validated,
        ownership,
        subnets,
        groups,
    )


def _parse_network_subnet(value: object) -> TerraformNetworkSubnet:
    item = _object(
        value,
        {"access", "owned", "role", "subnet_id", "zone"},
        "network subnet",
    )
    role = _choice(
        item["role"],
        "network subnet role",
        {"private", "scylla", "manager", "monitoring", "jump-host"},
    )
    access = _choice(item["access"], "network subnet access", {"private", "public"})
    if access == "public" and role != "jump-host":
        raise TerraformContractError("only jump-host subnets may be public")
    return TerraformNetworkSubnet(
        _string(item["zone"], "network subnet zone", _LOGICAL_ID),
        role,
        access,
        _oci_resource_id(item["subnet_id"], "subnet ID", "subnet"),
        _boolean(item["owned"], "subnet ownership"),
    )


def _parse_network_security_group(value: object) -> tuple[str, str]:
    item = _object(value, {"id", "role"}, "network security group")
    role = _choice(
        item["role"],
        "network security group role",
        {"scylla", "manager", "monitoring", "jump-host"},
    )
    return role, _oci_resource_id(
        item["id"], "network security group ID", "networksecuritygroup"
    )


def _parse_image_evidence(value: object) -> TerraformImageEvidence:
    item = _object(
        value,
        {
            "filter",
            "image_id",
            "image_name",
            "image_time_created",
            "logical_id",
            "role",
            "shape",
        },
        "image evidence",
    )
    image_filter = _object(
        item["filter"],
        {"operating_system", "operating_system_version", "version_match"},
        "image filter",
    )
    try:
        role = HostRole(_string(item["role"], "host role"))
    except ValueError as error:
        raise TerraformContractError("image evidence role is invalid") from error
    image_id = _string(item["image_id"], "image ID", _OCID)
    if not image_id.startswith("ocid1.image."):
        raise TerraformContractError("image evidence ID must identify an OCI image")
    created = _bounded_ascii(item["image_time_created"], "image creation time", 64)
    try:
        parsed = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError as error:
        raise TerraformContractError("image creation time is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise TerraformContractError("image creation time must be UTC")
    version_match = _choice(
        image_filter["version_match"], "image version match", {"exact", "prefix"}
    )
    return TerraformImageEvidence(
        _string(item["logical_id"], "logical host ID", _LOGICAL_ID),
        role,
        _string(item["shape"], "shape", _SHAPE),
        image_id,
        _bounded_ascii(item["image_name"], "image name", 255),
        created,
        _bounded_ascii(image_filter["operating_system"], "image operating system", 255),
        _bounded_ascii(
            image_filter["operating_system_version"],
            "image operating system version",
            255,
        ),
        version_match,
    )


def terraform_host_manifest_type_descriptor() -> list[object]:
    """Return the exact Terraform JSON type descriptor for the v1 manifest."""

    device = _terraform_object_type(
        {
            "at_rest_encryption": "string",
            "attachment_type": "string",
            "customer_key_id": "string",
            "ephemeral": "bool",
            "expected_by_id": "string",
            "expected_serial": "string",
            "expected_wwn": "string",
            "in_transit_encryption": "bool",
            "iqn": "string",
            "kind": "string",
            "local_device_id": "string",
            "multipath_id": "string",
            "portal": "string",
            "provider_attachment_id": "string",
            "provider_volume_id": "string",
            "requested_path": "string",
            "retention": "string",
            "size_gib": "number",
            "vpus_per_gb": "number",
        }
    )
    storage = _terraform_object_type(
        {
            "devices": ["list", device],
            "expected_device_count": "number",
            "filesystem_label": "string",
            "filesystem_type": "string",
            "layout": "string",
            "mount_options": ["list", "string"],
            "mount_point": "string",
            "mount_strategy": "string",
            "policy_digest": "string",
            "raid_device": "string",
            "raw_total_gib": "number",
            "requested_backend": "string",
            "role_allocations": ["list", "string"],
            "schema_version": "string",
            "selected_backend": "string",
            "selection_algorithm": "string",
            "selection_status": "string",
            "storage_generation": "number",
            "usable_total_gib": "number",
        }
    )
    host = _terraform_object_type(
        {
            "jump_host_id": "string",
            "logical_id": "string",
            "private_address": "string",
            "provider_id": "string",
            "public_address": "string",
            "role": "string",
            "scylla_datacenter": "string",
            "scylla_rack": "string",
            "shape": "string",
            "storage": storage,
            "zone": "string",
        }
    )
    return _terraform_object_type(
        {
            "cluster_uuid": "string",
            "hosts": ["list", host],
            "schema_version": "string",
        }
    )


def parse_terraform_outputs(
    data: str | bytes,
    *,
    expected_cluster_uuid: uuid.UUID,
    expected_spec: ClusterSpec | None = None,
) -> TerraformHostManifest:
    """Parse the exact Terraform output envelope and host manifest."""

    return parse_terraform_output_bundle(
        data,
        expected_cluster_uuid=expected_cluster_uuid,
        expected_spec=expected_spec,
    ).manifest


def parse_terraform_output_bundle(
    data: str | bytes,
    *,
    expected_cluster_uuid: uuid.UUID,
    expected_spec: ClusterSpec | None = None,
) -> TerraformOutputBundle:
    """Parse all strict output evidence without persisting raw Terraform output."""

    root = _load_bounded_json(data)
    envelope = _object(
        root,
        {
            "host_manifest",
            "image_selection",
            "network_evidence",
            "schema_version",
        },
        "output envelope",
    )
    schema_output = _object(
        envelope["schema_version"],
        {"sensitive", "type", "value"},
        "schema_version output",
    )
    if (
        schema_output["sensitive"] is not False
        or schema_output["type"] != "string"
        or schema_output["value"] != TERRAFORM_OUTPUT_SCHEMA_VERSION
    ):
        raise TerraformContractError("unsupported Terraform output schema version")
    output = _object(
        envelope["host_manifest"],
        {"sensitive", "type", "value"},
        "host_manifest output",
    )
    if output["sensitive"] is not False:
        raise TerraformContractError("host manifest output must not be sensitive")
    if output["type"] != terraform_host_manifest_type_descriptor():
        raise TerraformContractError("host manifest Terraform type is invalid")
    manifest = parse_host_manifest_object(
        output["value"], expected_cluster_uuid=expected_cluster_uuid
    )
    partial_envelope = {
        "image_selection": envelope["image_selection"],
        "network_evidence": envelope["network_evidence"],
        "schema_version": {
            "sensitive": False,
            "type": "string",
            "value": TERRAFORM_IMAGE_SELECTION_OUTPUT_SCHEMA_VERSION,
        },
    }
    images, network = _parse_terraform_partial_outputs(
        json.dumps(partial_envelope), expected_cluster_uuid=expected_cluster_uuid
    )
    if {host.logical_id for host in manifest.hosts} != {
        image.logical_id for image in images.images
    }:
        raise TerraformContractError(
            "Terraform image evidence membership conflicts with host manifest"
        )
    if any(
        host.role.value not in dict(network.network_security_groups)
        for host in manifest.hosts
    ):
        raise TerraformContractError(
            "Terraform network evidence does not cover host roles"
        )
    if expected_spec is not None:
        if expected_spec.cluster_uuid != expected_cluster_uuid:
            raise TerraformContractError("expected desired cluster identity conflicts")
        _validate_against_spec(manifest.hosts, expected_spec)
    return TerraformOutputBundle(manifest, images, network)


def parse_host_manifest_object(
    value: object, *, expected_cluster_uuid: uuid.UUID
) -> TerraformHostManifest:
    """Parse a complete host manifest object without a Terraform output wrapper."""

    _check_tree(value, depth=0)
    _reject_secret_material(value)
    manifest_value = _object(
        value, {"schema_version", "cluster_uuid", "hosts"}, "host manifest"
    )
    if manifest_value["schema_version"] != HOST_MANIFEST_SCHEMA_VERSION:
        raise TerraformContractError("unsupported host manifest schema version")
    cluster_uuid = _uuid(manifest_value["cluster_uuid"], "cluster UUID")
    if cluster_uuid != expected_cluster_uuid:
        raise TerraformContractError("Terraform output cluster identity conflicts")
    host_values = _array(manifest_value["hosts"], "hosts")
    if not host_values or len(host_values) > MAXIMUM_HOSTS:
        raise TerraformContractError("Terraform host count is invalid")
    hosts = tuple(_parse_host(value) for value in host_values)
    if tuple(host.logical_id for host in hosts) != tuple(
        sorted(host.logical_id for host in hosts)
    ):
        raise TerraformContractError(
            "Terraform hosts are not deterministically ordered"
        )
    _validate_hosts(hosts)
    return TerraformHostManifest(cluster_uuid, hosts)


def _parse_host(value: object) -> TerraformHost:
    item = _object(
        value,
        {
            "jump_host_id",
            "logical_id",
            "private_address",
            "provider_id",
            "public_address",
            "role",
            "scylla_datacenter",
            "scylla_rack",
            "shape",
            "storage",
            "zone",
        },
        "host",
    )
    logical_id = _string(item["logical_id"], "logical host ID", _LOGICAL_ID)
    try:
        role = HostRole(_string(item["role"], "host role"))
    except ValueError as error:
        raise TerraformContractError("host role is invalid") from error
    zone = _bounded_ascii(item["zone"], "host zone", 255)
    provider_id = _string(item["provider_id"], "provider ID", _OCID)
    if not provider_id.startswith("ocid1.instance."):
        raise TerraformContractError("host provider ID must identify an OCI instance")
    private_address = _address(item["private_address"], "private address")
    public_address = _optional_address(item["public_address"], "public address")
    jump_host_id = _optional_string(item["jump_host_id"], "jump host ID", _LOGICAL_ID)
    datacenter = _optional_string(item["scylla_datacenter"], "Scylla datacenter", _NAME)
    rack = _optional_string(item["scylla_rack"], "Scylla rack", _NAME)
    shape = _string(item["shape"], "host shape", _SHAPE)
    if role is HostRole.SCYLLA:
        if datacenter is None or rack is None:
            raise TerraformContractError("Scylla host topology is incomplete")
    elif datacenter is not None or rack is not None:
        raise TerraformContractError("non-Scylla host topology must be null")
    storage = _parse_storage(item["storage"])
    _validate_role_storage(role, storage)
    return TerraformHost(
        logical_id,
        role,
        zone,
        provider_id,
        private_address,
        public_address,
        jump_host_id,
        datacenter,
        rack,
        shape,
        storage,
    )


def _parse_storage(value: object) -> StorageManifest:
    item = _object(
        value,
        {
            "devices",
            "expected_device_count",
            "filesystem_label",
            "filesystem_type",
            "layout",
            "mount_options",
            "mount_point",
            "mount_strategy",
            "policy_digest",
            "raid_device",
            "raw_total_gib",
            "requested_backend",
            "role_allocations",
            "schema_version",
            "selected_backend",
            "selection_algorithm",
            "selection_status",
            "storage_generation",
            "usable_total_gib",
        },
        "storage manifest",
    )
    if item["schema_version"] != STORAGE_MANIFEST_SCHEMA_VERSION:
        raise TerraformContractError("unsupported storage manifest schema version")
    requested = _backend(item["requested_backend"], "requested storage backend")
    selected = _backend(item["selected_backend"], "selected storage backend")
    if selected is StorageBackend.AUTO:
        raise TerraformContractError("selected storage backend cannot be auto")
    if requested is not StorageBackend.AUTO and requested is not selected:
        raise TerraformContractError("requested and selected storage backends conflict")
    try:
        status = StorageSelectionStatus(
            _string(item["selection_status"], "storage selection status")
        )
    except ValueError as error:
        raise TerraformContractError("storage selection status is invalid") from error
    algorithm = _bounded_ascii(
        item["selection_algorithm"], "storage selection algorithm", 128
    )
    policy_digest = _string(item["policy_digest"], "storage policy digest", _DIGEST)
    generation = _positive_int(item["storage_generation"], "storage generation")
    expected_count = _nonnegative_int(
        item["expected_device_count"], "expected device count"
    )
    raw_total = _nonnegative_int(item["raw_total_gib"], "raw storage total")
    usable_total = _nonnegative_int(item["usable_total_gib"], "usable storage total")
    devices = tuple(
        _parse_device(value) for value in _array(item["devices"], "devices")
    )
    if expected_count != len(devices):
        raise TerraformContractError("expected storage device count conflicts")
    block_devices = tuple(
        device for device in devices if device.kind is StorageDeviceKind.BLOCK_VOLUME
    )
    block_device_keys = tuple(
        device.provider_volume_id
        for device in block_devices
        if device.provider_volume_id is not None
    )
    local_devices = tuple(
        device for device in devices if device.kind is StorageDeviceKind.LOCAL_NVME
    )
    local_device_keys = tuple(
        device.local_device_id
        for device in local_devices
        if device.local_device_id is not None
    )
    if (
        len(block_device_keys) != len(block_devices)
        or block_device_keys != tuple(sorted(set(block_device_keys)))
        or (
            local_device_keys
            and (
                len(local_device_keys) != len(local_devices)
                or local_device_keys != tuple(sorted(set(local_device_keys)))
            )
        )
    ):
        raise TerraformContractError(
            "storage devices are not uniquely and deterministically ordered"
        )
    if raw_total != sum(device.size_gib for device in devices):
        raise TerraformContractError("raw storage total conflicts")
    if usable_total > raw_total:
        raise TerraformContractError("usable storage total exceeds raw total")
    layout = _optional_choice(item["layout"], "storage layout", {"single", "raid0"})
    raid_device = _optional_absolute_path(item["raid_device"], "RAID device")
    filesystem = _optional_choice(item["filesystem_type"], "filesystem type", {"xfs"})
    filesystem_label = _optional_bounded_ascii(
        item["filesystem_label"], "filesystem label", 64
    )
    mount_strategy = _optional_choice(
        item["mount_strategy"], "mount strategy", {"filesystem-uuid", "by-id"}
    )
    mount_point = _optional_absolute_path(item["mount_point"], "mount point")
    mount_options = _unique_strings(item["mount_options"], "mount options")
    role_allocations = _unique_strings(item["role_allocations"], "role allocations")
    allowed_allocations = {"data", "commitlog", "cache", "logs"}
    if not set(role_allocations) <= allowed_allocations:
        raise TerraformContractError("storage role allocation is invalid")
    manifest = StorageManifest(
        requested,
        selected,
        algorithm,
        status,
        policy_digest,
        generation,
        expected_count,
        raw_total,
        usable_total,
        layout,
        raid_device,
        filesystem,
        filesystem_label,
        mount_strategy,
        mount_point,
        mount_options,
        role_allocations,
        devices,
    )
    _validate_storage_combinations(manifest)
    return manifest


def _parse_device(value: object) -> StorageDevice:
    item = _object(
        value,
        {
            "at_rest_encryption",
            "attachment_type",
            "customer_key_id",
            "ephemeral",
            "expected_by_id",
            "expected_serial",
            "expected_wwn",
            "in_transit_encryption",
            "iqn",
            "kind",
            "local_device_id",
            "multipath_id",
            "portal",
            "provider_attachment_id",
            "provider_volume_id",
            "requested_path",
            "retention",
            "size_gib",
            "vpus_per_gb",
        },
        "storage device",
    )
    try:
        kind = StorageDeviceKind(_string(item["kind"], "storage device kind"))
    except ValueError as error:
        raise TerraformContractError("storage device kind is invalid") from error
    device = StorageDevice(
        kind,
        _optional_ocid(item["provider_volume_id"], "volume ID"),
        _optional_ocid(item["provider_attachment_id"], "attachment ID"),
        _optional_bounded_ascii(item["local_device_id"], "local device ID", 255),
        _optional_absolute_path(item["requested_path"], "requested device path"),
        _optional_bounded_ascii(item["expected_serial"], "expected serial", 255),
        _optional_bounded_ascii(item["expected_wwn"], "expected WWN", 255),
        _optional_absolute_path(item["expected_by_id"], "expected by-id path"),
        _positive_int(item["size_gib"], "device size"),
        _boolean(item["ephemeral"], "device ephemeral"),
        _optional_choice(
            item["attachment_type"],
            "attachment type",
            {"iscsi", "paravirtualized"},
        ),
        _optional_bounded_ascii(item["iqn"], "IQN", 255),
        _optional_bounded_ascii(item["portal"], "portal", 255),
        _optional_bounded_ascii(item["multipath_id"], "multipath ID", 255),
        _boolean(item["in_transit_encryption"], "in-transit encryption"),
        _choice(
            item["at_rest_encryption"],
            "at-rest encryption",
            {"provider-managed", "customer-managed"},
        ),
        _optional_ocid(item["customer_key_id"], "customer key ID"),
        _optional_nonnegative_int(item["vpus_per_gb"], "VPUs per GiB"),
        _optional_choice(item["retention"], "retention", {"retain", "delete"}),
    )
    _validate_device(device)
    return device


def _validate_device(device: StorageDevice) -> None:
    if device.at_rest_encryption == "customer-managed":
        if device.customer_key_id is None:
            raise TerraformContractError("customer-managed storage requires a key ID")
    elif device.customer_key_id is not None:
        raise TerraformContractError("provider-managed storage forbids a key ID")
    if device.kind is StorageDeviceKind.LOCAL_NVME:
        if not device.ephemeral:
            raise TerraformContractError("local NVMe ephemerality is invalid")
        if any(
            value is not None
            for value in (
                device.provider_volume_id,
                device.provider_attachment_id,
                device.attachment_type,
                device.iqn,
                device.portal,
                device.multipath_id,
                device.vpus_per_gb,
                device.retention,
            )
        ):
            raise TerraformContractError("local NVMe contains block-volume metadata")
    else:
        if (
            device.provider_volume_id is None
            or device.provider_attachment_id is None
            or device.attachment_type is None
            or device.vpus_per_gb is None
            or device.retention is None
            or device.ephemeral
            or device.local_device_id is not None
        ):
            raise TerraformContractError("block-volume device metadata is incomplete")


def _validate_storage_combinations(manifest: StorageManifest) -> None:
    if manifest.selected_backend is StorageBackend.BOOT_ONLY:
        if (
            manifest.devices
            or manifest.expected_device_count
            or manifest.raw_total_gib
            or manifest.usable_total_gib
            or any(
                value is not None
                for value in (
                    manifest.layout,
                    manifest.raid_device,
                    manifest.filesystem_type,
                    manifest.filesystem_label,
                    manifest.mount_strategy,
                    manifest.mount_point,
                )
            )
            or manifest.mount_options
            or manifest.role_allocations
        ):
            raise TerraformContractError("boot-only storage must have no data layout")
        return
    expected_kind = (
        StorageDeviceKind.LOCAL_NVME
        if manifest.selected_backend is StorageBackend.LOCAL_NVME
        else StorageDeviceKind.BLOCK_VOLUME
    )
    if not manifest.devices or any(
        device.kind is not expected_kind for device in manifest.devices
    ):
        raise TerraformContractError("storage devices conflict with selected backend")
    expected_layout = "single" if len(manifest.devices) == 1 else "raid0"
    if (
        manifest.layout != expected_layout
        or manifest.filesystem_type != "xfs"
        or manifest.mount_strategy is None
        or manifest.mount_point is None
        or not manifest.role_allocations
    ):
        raise TerraformContractError("storage filesystem/layout metadata is incomplete")
    if (
        expected_layout == "raid0"
        and manifest.raid_device is None
        and manifest.selection_status is StorageSelectionStatus.FINAL
    ):
        raise TerraformContractError("RAID0 storage requires an intended RAID device")
    if expected_layout == "single" and manifest.raid_device is not None:
        raise TerraformContractError("single-device storage forbids a RAID device")


def _validate_role_storage(role: HostRole, storage: StorageManifest) -> None:
    if role is HostRole.JUMP_HOST:
        if storage.selected_backend is not StorageBackend.BOOT_ONLY:
            raise TerraformContractError("jump hosts require boot-only storage")
    elif role is HostRole.SCYLLA:
        if storage.selected_backend is StorageBackend.BOOT_ONLY:
            raise TerraformContractError("Scylla hosts require data storage")
    elif storage.selected_backend is not StorageBackend.BLOCK_VOLUME:
        raise TerraformContractError(
            "Manager and monitoring require block-volume storage"
        )


def _validate_hosts(hosts: tuple[TerraformHost, ...]) -> None:
    _unique((host.logical_id for host in hosts), "logical host IDs")
    _unique((host.provider_id for host in hosts), "provider instance IDs")
    all_addresses = [
        address
        for host in hosts
        for address in (host.private_address, host.public_address)
        if address is not None
    ]
    _unique(iter(all_addresses), "host addresses")
    for attribute, label in (
        ("provider_volume_id", "provider volume IDs"),
        ("provider_attachment_id", "provider attachment IDs"),
        ("expected_serial", "expected device serials"),
        ("expected_wwn", "expected device WWNs"),
        ("expected_by_id", "expected device by-id paths"),
    ):
        values = (
            value
            for host in hosts
            for device in host.storage.devices
            if (value := getattr(device, attribute)) is not None
        )
        _unique(values, label)
    by_id = {host.logical_id: host for host in hosts}
    for host in hosts:
        if host.public_address is not None and host.role is not HostRole.JUMP_HOST:
            raise TerraformContractError("only jump hosts may have public addresses")
        if host.jump_host_id is not None:
            jump = by_id.get(host.jump_host_id)
            if (
                jump is None
                or jump.role is not HostRole.JUMP_HOST
                or jump.logical_id == host.logical_id
            ):
                raise TerraformContractError("host jump routing reference is invalid")
        if host.role is HostRole.JUMP_HOST and host.jump_host_id is not None:
            raise TerraformContractError("jump host cannot route through a jump host")


def _validate_against_spec(hosts: tuple[TerraformHost, ...], spec: ClusterSpec) -> None:
    expected: dict[str, tuple[HostRole, str, str, str | None, str | None]] = {}
    for zone_spec in spec.zones:
        for logical_id in zone_spec.logical_node_ids:
            expected[logical_id] = (
                HostRole.SCYLLA,
                zone_spec.zone_id,
                spec.scylla_instance_type,
                spec.scylla_datacenter.value,
                zone_spec.scylla_rack.value,
            )
    for service in spec.services:
        for logical_id, service_zone in zip(
            service.logical_ids, service.zones, strict=True
        ):
            if service.instance_type is None:
                raise TerraformContractError("desired service shape is unavailable")
            expected[logical_id] = (
                service.role,
                service_zone,
                service.instance_type,
                None,
                None,
            )
    if set(expected) != {host.logical_id for host in hosts}:
        raise TerraformContractError(
            "Terraform host membership conflicts with desired state"
        )
    policies = {policy.role: policy for policy in spec.storage}
    for host in hosts:
        role, expected_zone, shape, datacenter, rack = expected[host.logical_id]
        if (
            host.role is not role
            or host.zone != expected_zone
            or host.shape != shape
            or host.scylla_datacenter != datacenter
            or host.scylla_rack != rack
            or host.storage.requested_backend is not policies[role].requested_backend
        ):
            raise TerraformContractError(
                "Terraform host facts conflict with desired state"
            )


def _load_bounded_json(data: str | bytes) -> object:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > MAXIMUM_TERRAFORM_OUTPUT_BYTES:
        raise TerraformContractError("Terraform output exceeds the size limit")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise TerraformContractError("Terraform output is malformed JSON") from error
    _check_tree(value, depth=0)
    _reject_secret_material(value)
    return value


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TerraformContractError("Terraform output has duplicate JSON keys")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise TerraformContractError(f"invalid JSON constant: {value}")


def _check_tree(value: object, *, depth: int) -> None:
    if depth > MAXIMUM_JSON_DEPTH:
        raise TerraformContractError("Terraform output exceeds the depth limit")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TerraformContractError("Terraform output key is invalid")
            _check_tree(item, depth=depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_tree(item, depth=depth + 1)
    elif value is not None and not isinstance(value, (str, int, float, bool)):
        raise TerraformContractError("Terraform output contains an invalid JSON value")


def _reject_secret_material(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _SECRET_KEY.search(key):
                raise TerraformContractError(
                    "Terraform output contains a secret-like field"
                )
            _reject_secret_material(item)
    elif isinstance(value, list):
        for item in value:
            _reject_secret_material(item)
    elif isinstance(value, str) and _SECRET_VALUE.search(value):
        raise TerraformContractError("Terraform output contains secret-like material")


def _host_object(host: TerraformHost, *, include_addresses: bool) -> dict[str, object]:
    result: dict[str, object] = {
        "jump_host_id": host.jump_host_id,
        "logical_id": host.logical_id,
        "provider_id": host.provider_id,
        "role": host.role.value,
        "scylla_datacenter": host.scylla_datacenter,
        "scylla_rack": host.scylla_rack,
        "shape": host.shape,
        "storage": {
            "expected_device_count": host.storage.expected_device_count,
            "requested_backend": host.storage.requested_backend.value,
            "schema_version": host.storage.schema_version,
            "selected_backend": host.storage.selected_backend.value,
            "selection_status": host.storage.selection_status.value,
            "storage_generation": host.storage.storage_generation,
        },
        "zone": host.zone,
    }
    if include_addresses:
        result["private_address"] = host.private_address
        result["public_address"] = host.public_address
    return result


def _host_persistence_object(host: TerraformHost) -> dict[str, object]:
    return {
        "jump_host_id": host.jump_host_id,
        "logical_id": host.logical_id,
        "private_address": host.private_address,
        "provider_id": host.provider_id,
        "public_address": host.public_address,
        "role": host.role.value,
        "scylla_datacenter": host.scylla_datacenter,
        "scylla_rack": host.scylla_rack,
        "shape": host.shape,
        "storage": _storage_persistence_object(host.storage),
        "zone": host.zone,
    }


def _storage_persistence_object(storage: StorageManifest) -> dict[str, object]:
    return {
        "devices": [_device_persistence_object(device) for device in storage.devices],
        "expected_device_count": storage.expected_device_count,
        "filesystem_label": storage.filesystem_label,
        "filesystem_type": storage.filesystem_type,
        "layout": storage.layout,
        "mount_options": list(storage.mount_options),
        "mount_point": storage.mount_point,
        "mount_strategy": storage.mount_strategy,
        "policy_digest": storage.policy_digest,
        "raid_device": storage.raid_device,
        "raw_total_gib": storage.raw_total_gib,
        "requested_backend": storage.requested_backend.value,
        "role_allocations": list(storage.role_allocations),
        "schema_version": storage.schema_version,
        "selected_backend": storage.selected_backend.value,
        "selection_algorithm": storage.selection_algorithm,
        "selection_status": storage.selection_status.value,
        "storage_generation": storage.storage_generation,
        "usable_total_gib": storage.usable_total_gib,
    }


def _device_persistence_object(device: StorageDevice) -> dict[str, object]:
    return {
        "at_rest_encryption": device.at_rest_encryption,
        "attachment_type": device.attachment_type,
        "customer_key_id": device.customer_key_id,
        "ephemeral": device.ephemeral,
        "expected_by_id": device.expected_by_id,
        "expected_serial": device.expected_serial,
        "expected_wwn": device.expected_wwn,
        "in_transit_encryption": device.in_transit_encryption,
        "iqn": device.iqn,
        "kind": device.kind.value,
        "local_device_id": device.local_device_id,
        "multipath_id": device.multipath_id,
        "portal": device.portal,
        "provider_attachment_id": device.provider_attachment_id,
        "provider_volume_id": device.provider_volume_id,
        "requested_path": device.requested_path,
        "retention": device.retention,
        "size_gib": device.size_gib,
        "vpus_per_gb": device.vpus_per_gb,
    }


def _terraform_object_type(fields: dict[str, object]) -> list[object]:
    return ["object", {name: fields[name] for name in sorted(fields)}]


def _object(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise TerraformContractError(f"{label} fields are invalid")
    return value


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise TerraformContractError(f"{label} must be an array")
    return value


def _string(value: object, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if (
        not isinstance(value, str)
        or not value
        or (pattern is not None and pattern.fullmatch(value) is None)
    ):
        raise TerraformContractError(f"{label} is invalid")
    return value


def _oci_resource_id(value: object, label: str, kind: str) -> str:
    resource_id = _string(value, label, _OCID)
    if not resource_id.startswith(f"ocid1.{kind}."):
        raise TerraformContractError(f"{label} identifies the wrong OCI resource")
    return resource_id


def _bounded_ascii(value: object, label: str, maximum: int) -> str:
    result = _string(value, label)
    if (
        not result.isascii()
        or len(result) > maximum
        or any(ord(char) < 32 for char in result)
    ):
        raise TerraformContractError(f"{label} is invalid")
    return result


def _optional_string(
    value: object, label: str, pattern: re.Pattern[str] | None = None
) -> str | None:
    return None if value is None else _string(value, label, pattern)


def _optional_bounded_ascii(value: object, label: str, maximum: int) -> str | None:
    return None if value is None else _bounded_ascii(value, label, maximum)


def _choice(value: object, label: str, choices: set[str]) -> str:
    result = _string(value, label)
    if result not in choices:
        raise TerraformContractError(f"{label} is invalid")
    return result


def _optional_choice(value: object, label: str, choices: set[str]) -> str | None:
    return None if value is None else _choice(value, label, choices)


def _backend(value: object, label: str) -> StorageBackend:
    try:
        return StorageBackend(_string(value, label))
    except ValueError as error:
        raise TerraformContractError(f"{label} is invalid") from error


def _uuid(value: object, label: str) -> uuid.UUID:
    text = _string(value, label)
    try:
        result = uuid.UUID(text)
    except ValueError as error:
        raise TerraformContractError(f"{label} is invalid") from error
    if str(result) != text:
        raise TerraformContractError(f"{label} is not canonical")
    return result


def _address(value: object, label: str) -> str:
    text = _string(value, label)
    try:
        result = ipaddress.ip_address(text)
    except ValueError as error:
        raise TerraformContractError(f"{label} is invalid") from error
    if str(result) != text:
        raise TerraformContractError(f"{label} is not canonical")
    return text


def _optional_address(value: object, label: str) -> str | None:
    return None if value is None else _address(value, label)


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise TerraformContractError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TerraformContractError(f"{label} must be a nonnegative integer")
    return value


def _optional_nonnegative_int(value: object, label: str) -> int | None:
    return None if value is None else _nonnegative_int(value, label)


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise TerraformContractError(f"{label} must be a boolean")
    return value


def _optional_ocid(value: object, label: str) -> str | None:
    return None if value is None else _string(value, label, _OCID)


def _optional_absolute_path(value: object, label: str) -> str | None:
    if value is None:
        return None
    text = _bounded_ascii(value, label, 4096)
    path = PurePosixPath(text)
    if not path.is_absolute() or ".." in path.parts or str(path) != text:
        raise TerraformContractError(f"{label} is not canonical and absolute")
    return text


def _unique_strings(value: object, label: str) -> tuple[str, ...]:
    values = tuple(_bounded_ascii(item, label, 255) for item in _array(value, label))
    _unique(iter(values), label)
    if values != tuple(sorted(values)):
        raise TerraformContractError(f"{label} are not deterministically ordered")
    return values


def _unique(values: Any, label: str) -> None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            raise TerraformContractError(f"{label} contain duplicates")
        seen.add(value)
