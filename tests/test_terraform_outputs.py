import copy
import json
import uuid
from dataclasses import FrozenInstanceError

import pytest

from scylla_vms.desired import HostRole, StorageBackend
from scylla_vms.terraform.outputs import (
    HOST_MANIFEST_SCHEMA_VERSION,
    MAXIMUM_TERRAFORM_OUTPUT_BYTES,
    STORAGE_MANIFEST_SCHEMA_VERSION,
    TERRAFORM_IMAGE_SELECTION_SCHEMA_VERSION,
    TERRAFORM_NETWORK_EVIDENCE_SCHEMA_VERSION,
    TERRAFORM_OUTPUT_SCHEMA_VERSION,
    TerraformContractError,
    parse_terraform_outputs,
    terraform_host_manifest_type_descriptor,
    terraform_image_selection_type_descriptor,
    terraform_network_evidence_type_descriptor,
)

CLUSTER_UUID = uuid.UUID("11111111-1111-4111-8111-111111111111")


def _device(kind: str, suffix: str) -> dict[str, object]:
    local = kind == "local-nvme"
    return {
        "at_rest_encryption": "provider-managed",
        "attachment_type": None if local else "paravirtualized",
        "customer_key_id": None,
        "ephemeral": local,
        "expected_by_id": None if local else f"/dev/disk/by-id/fake-{suffix}",
        "expected_serial": f"FAKE-{suffix.upper()}",
        "expected_wwn": None,
        "in_transit_encryption": not local,
        "iqn": None,
        "kind": kind,
        "local_device_id": f"local-slot-{suffix}" if local else None,
        "multipath_id": None,
        "portal": None,
        "provider_attachment_id": (
            None if local else f"ocid1.volumeattachment.oc1.iad.fake{suffix}"
        ),
        "provider_volume_id": (None if local else f"ocid1.volume.oc1.iad.fake{suffix}"),
        "requested_path": None if local else f"/dev/oracleoci/oraclevd{suffix}",
        "retention": None if local else "retain",
        "size_gib": 500,
        "vpus_per_gb": None if local else 10,
    }


def _storage(
    selected: str,
    suffix: str,
    *,
    requested: str | None = None,
    count: int = 1,
) -> dict[str, object]:
    if selected == "boot-only":
        return {
            "devices": [],
            "expected_device_count": 0,
            "filesystem_label": None,
            "filesystem_type": None,
            "layout": None,
            "mount_options": [],
            "mount_point": None,
            "mount_strategy": None,
            "policy_digest": "sha256:" + "a" * 64,
            "raid_device": None,
            "raw_total_gib": 0,
            "requested_backend": "boot-only",
            "role_allocations": [],
            "schema_version": STORAGE_MANIFEST_SCHEMA_VERSION,
            "selected_backend": "boot-only",
            "selection_algorithm": "boot-only/v1",
            "selection_status": "final",
            "storage_generation": 1,
            "usable_total_gib": 0,
        }
    devices = [_device(selected, f"{suffix}{index}") for index in range(1, count + 1)]
    return {
        "devices": devices,
        "expected_device_count": count,
        "filesystem_label": f"data-{suffix}",
        "filesystem_type": "xfs",
        "layout": "single" if count == 1 else "raid0",
        "mount_options": ["noatime"],
        "mount_point": (
            "/var/lib/scylla"
            if suffix.startswith("scylla-")
            else f"/var/lib/fake-{suffix}"
        ),
        "mount_strategy": "by-id" if selected == "block-volume" else "filesystem-uuid",
        "policy_digest": "sha256:" + "b" * 64,
        "raid_device": None if count == 1 else f"/dev/md/fake-{suffix}",
        "raw_total_gib": 500 * count,
        "requested_backend": requested or selected,
        "role_allocations": ["data"],
        "schema_version": STORAGE_MANIFEST_SCHEMA_VERSION,
        "selected_backend": selected,
        "selection_algorithm": "oci-storage-selection/v1",
        "selection_status": "final",
        "storage_generation": 2,
        "usable_total_gib": 500 * count,
    }


def _host(
    logical_id: str,
    role: str,
    zone: str,
    address: str,
    storage: dict[str, object],
    *,
    jump_host_id: str | None = "jump-host-1",
) -> dict[str, object]:
    scylla = role == "scylla"
    return {
        "jump_host_id": jump_host_id,
        "logical_id": logical_id,
        "private_address": address,
        "provider_id": f"ocid1.instance.oc1.iad.fake{logical_id.replace('-', '')}",
        "public_address": "203.0.113.10" if role == "jump-host" else None,
        "role": role,
        "scylla_datacenter": "example-dc" if scylla else None,
        "scylla_rack": f"rack-{zone[-1].lower()}" if scylla else None,
        "shape": "VM.Standard.E5.Flex",
        "storage": storage,
        "zone": zone,
    }


def _output() -> dict[str, object]:
    hosts = [
        _host(
            "jump-host-1",
            "jump-host",
            "AD-1",
            "10.0.0.10",
            _storage("boot-only", "jump"),
            jump_host_id=None,
        ),
        _host(
            "manager-1",
            "manager",
            "AD-1",
            "10.0.1.10",
            _storage("block-volume", "manager"),
        ),
        _host(
            "monitoring-1",
            "monitoring",
            "AD-2",
            "10.0.2.10",
            _storage("block-volume", "monitoring"),
        ),
        _host(
            "scylla-ad-1-1",
            "scylla",
            "AD-1",
            "10.0.3.10",
            _storage("local-nvme", "scyllaa", requested="auto", count=2),
        ),
        _host(
            "scylla-ad-2-1",
            "scylla",
            "AD-2",
            "10.0.4.10",
            _storage("block-volume", "scyllab", count=2),
        ),
    ]
    return {
        "host_manifest": {
            "sensitive": False,
            "type": terraform_host_manifest_type_descriptor(),
            "value": {
                "cluster_uuid": str(CLUSTER_UUID),
                "hosts": hosts,
                "schema_version": HOST_MANIFEST_SCHEMA_VERSION,
            },
        },
        "image_selection": {
            "sensitive": False,
            "type": terraform_image_selection_type_descriptor(),
            "value": {
                "cluster_name": "example",
                "cluster_uuid": str(CLUSTER_UUID),
                "images": [
                    {
                        "filter": {
                            "operating_system": "Ubuntu",
                            "operating_system_version": "24.04",
                            "version_match": "exact",
                        },
                        "image_id": f"ocid1.image.oc1.iad.fake{host['logical_id'].replace('-', '')}",
                        "image_name": "Canonical-Ubuntu-24.04-fake",
                        "image_time_created": "2026-09-01T00:00:00Z",
                        "logical_id": host["logical_id"],
                        "role": host["role"],
                        "shape": host["shape"],
                    }
                    for host in hosts
                ],
                "provider": "oci",
                "schema_version": TERRAFORM_IMAGE_SELECTION_SCHEMA_VERSION,
            },
        },
        "network_evidence": {
            "sensitive": False,
            "type": terraform_network_evidence_type_descriptor(),
            "value": {
                "cluster_name": "example",
                "cluster_uuid": str(CLUSTER_UUID),
                "external_routing_validated": False,
                "mode": "create",
                "network_security_groups": [
                    {
                        "id": f"ocid1.networksecuritygroup.oc1.iad.fake{role.replace('-', '')}",
                        "role": role,
                    }
                    for role in ["jump-host", "manager", "monitoring", "scylla"]
                ],
                "ownership": {
                    "gateways": True,
                    "route_tables": True,
                    "subnets": True,
                    "vcn": True,
                },
                "provider": "oci",
                "schema_version": TERRAFORM_NETWORK_EVIDENCE_SCHEMA_VERSION,
                "subnets": [
                    {
                        "access": "private",
                        "owned": True,
                        "role": "private",
                        "subnet_id": "ocid1.subnet.oc1.iad.fakead1",
                        "zone": "AD-1",
                    },
                    {
                        "access": "private",
                        "owned": True,
                        "role": "private",
                        "subnet_id": "ocid1.subnet.oc1.iad.fakead2",
                        "zone": "AD-2",
                    },
                ],
                "vcn_id": "ocid1.vcn.oc1.iad.fakevcn",
            },
        },
        "schema_version": {
            "sensitive": False,
            "type": "string",
            "value": TERRAFORM_OUTPUT_SCHEMA_VERSION,
        },
    }


def test_valid_multi_role_multi_zone_storage_manifest_is_immutable_and_sorted() -> None:
    manifest = parse_terraform_outputs(
        json.dumps(_output()), expected_cluster_uuid=CLUSTER_UUID
    )
    assert [host.logical_id for host in manifest.hosts] == [
        "jump-host-1",
        "manager-1",
        "monitoring-1",
        "scylla-ad-1-1",
        "scylla-ad-2-1",
    ]
    assert manifest.hosts[3].storage.requested_backend is StorageBackend.AUTO
    assert manifest.hosts[3].storage.selected_backend is StorageBackend.LOCAL_NVME
    assert manifest.hosts[4].storage.selected_backend is StorageBackend.BLOCK_VOLUME
    assert manifest.hosts[0].role is HostRole.JUMP_HOST
    with pytest.raises(FrozenInstanceError):
        manifest.hosts[0].zone = "changed"  # type: ignore[misc]


def test_address_projection_is_explicitly_opt_in() -> None:
    manifest = parse_terraform_outputs(
        json.dumps(_output()), expected_cluster_uuid=CLUSTER_UUID
    )
    default_host = manifest.to_object()["hosts"][0]  # type: ignore[index]
    disclosed_host = manifest.to_object(include_addresses=True)["hosts"][0]  # type: ignore[index]
    assert "private_address" not in default_host
    assert disclosed_host["private_address"] == "10.0.0.10"


def test_provisional_storage_does_not_require_guessed_guest_device_paths() -> None:
    value = _output()
    local_storage = value["host_manifest"]["value"]["hosts"][3]["storage"]
    for device in local_storage["devices"]:
        device["local_device_id"] = None
        device["requested_path"] = None
        device["expected_serial"] = None

    storage = value["host_manifest"]["value"]["hosts"][4]["storage"]
    storage["selection_status"] = "provisional"
    storage["raid_device"] = None
    for device in storage["devices"]:
        device["requested_path"] = None
        device["expected_by_id"] = None

    manifest = parse_terraform_outputs(
        json.dumps(value), expected_cluster_uuid=CLUSTER_UUID
    )
    assert manifest.hosts[4].storage.raid_device is None
    assert all(
        device.requested_path is None for device in manifest.hosts[4].storage.devices
    )
    assert all(
        device.local_device_id is None for device in manifest.hosts[3].storage.devices
    )


def test_wrong_cluster_identity_is_rejected() -> None:
    with pytest.raises(TerraformContractError, match="identity"):
        parse_terraform_outputs(
            json.dumps(_output()),
            expected_cluster_uuid=uuid.UUID("33333333-3333-4333-8333-333333333333"),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"unexpected": True}), "fields"),
        (
            lambda value: value["host_manifest"]["value"]["hosts"][1].update(
                {"logical_id": "jump-host-1"}
            ),
            "ordered|duplicates",
        ),
        (
            lambda value: value["host_manifest"]["value"]["hosts"][1].update(
                {
                    "provider_id": value["host_manifest"]["value"]["hosts"][0][
                        "provider_id"
                    ]
                }
            ),
            "provider instance IDs",
        ),
        (
            lambda value: value["host_manifest"]["value"]["hosts"][1].update(
                {"scylla_rack": "rack-a"}
            ),
            "non-Scylla",
        ),
        (
            lambda value: value["host_manifest"]["value"]["hosts"][3]["storage"].update(
                {"selected_backend": "boot-only"}
            ),
            "requested and selected|Scylla|boot-only",
        ),
        (
            lambda value: value["host_manifest"]["value"]["hosts"][1].update(
                {"private_address": "010.0.0.1"}
            ),
            "address",
        ),
        (
            lambda value: value["host_manifest"]["value"]["hosts"][1].update(
                {"jump_host_id": "missing-jump"}
            ),
            "routing",
        ),
        (
            lambda value: value["host_manifest"]["value"]["hosts"][1].update(
                {"api_token": "obviously-fake"}
            ),
            "fields|secret-like",
        ),
    ],
)
def test_invalid_schema_identity_topology_storage_and_address_combinations_fail(
    mutation: object, message: str
) -> None:
    value = copy.deepcopy(_output())
    mutation(value)  # type: ignore[operator]
    with pytest.raises(TerraformContractError, match=message):
        parse_terraform_outputs(json.dumps(value), expected_cluster_uuid=CLUSTER_UUID)


def test_duplicate_json_keys_and_secret_material_are_rejected() -> None:
    payload = json.dumps(_output())
    duplicate = payload.replace(
        '"sensitive": false', '"sensitive": false, "sensitive": false', 1
    )
    with pytest.raises(TerraformContractError, match="duplicate"):
        parse_terraform_outputs(duplicate, expected_cluster_uuid=CLUSTER_UUID)
    value = _output()
    value["host_manifest"]["value"]["hosts"][1]["shape"] = (
        "password=obviously-fake-secret"
    )
    with pytest.raises(TerraformContractError, match="secret-like"):
        parse_terraform_outputs(json.dumps(value), expected_cluster_uuid=CLUSTER_UUID)


def test_duplicate_provider_storage_identity_is_rejected() -> None:
    value = _output()
    devices = value["host_manifest"]["value"]["hosts"][3]["storage"]["devices"]
    devices[1]["provider_volume_id"] = devices[0]["provider_volume_id"]
    devices[1]["local_device_id"] = devices[0]["local_device_id"]
    with pytest.raises(TerraformContractError, match="uniquely"):
        parse_terraform_outputs(json.dumps(value), expected_cluster_uuid=CLUSTER_UUID)


def test_oversized_and_excessively_deep_json_are_rejected() -> None:
    oversized = b" " * (MAXIMUM_TERRAFORM_OUTPUT_BYTES + 1)
    with pytest.raises(TerraformContractError, match="size"):
        parse_terraform_outputs(oversized, expected_cluster_uuid=CLUSTER_UUID)
    deep: object = None
    for _ in range(40):
        deep = [deep]
    with pytest.raises(TerraformContractError, match="depth"):
        parse_terraform_outputs(json.dumps(deep), expected_cluster_uuid=CLUSTER_UUID)
