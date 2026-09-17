import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from scylla_vms.cli import parse_operation_request
from scylla_vms.desired import (
    AttachmentType,
    BlockVolumePolicy,
    ClusterSpec,
    HostRole,
    ImageFilter,
    ImageVersionMatch,
    NetworkMode,
    NetworkPolicy,
    StorageBackend,
    StorageLayout,
    StoragePolicy,
    VolumeRetention,
    compile_new_cluster_spec,
    resolve_existing_config,
)
from scylla_vms.errors import ConfigurationError, StateConflictError
from scylla_vms.models import ValueSource

_CLUSTER_UUID = uuid.UUID("11111111-1111-4111-8111-111111111111")


def _config_text(public_key: Path, *, counts: str = '"AD-2" = 1, "AD-1" = 1') -> str:
    return f"""
schema_version = "deploy-scylla-vms.config/v2"

[cluster]
cluster_name = "example"
cloud_provider = "oci"
oci_region = "us-phoenix-1"
oci_compartment_id = "ocid1.compartment.oc1..fixture"
scylla_image_operating_system = "Ubuntu"
scylla_image_operating_system_version = "24.04"
manager_image_operating_system = "Ubuntu"
manager_image_operating_system_version = "24.04"
monitoring_image_operating_system = "Ubuntu"
monitoring_image_operating_system_version = "24.04"
zone = ["AD-2", "AD-1"]
nodes_per_zone = {{ {counts} }}
scylla_rack = {{ "AD-1" = "rack-explicit" }}
jump_host_count = 0
scylla_instance_type = "VM.Standard.E5.Flex"
manager_instance_type = "VM.Standard.E5.Flex"
monitoring_instance_type = "VM.Standard.E5.Flex"
network_mode = "create"
oci_vcn_cidr = "10.0.0.0/16"
oci_private_subnet_cidr = {{ "AD-1" = "10.0.1.0/24", "AD-2" = "10.0.2.0/24" }}
ssh_user = "opc"
ssh_public_key_path = "{public_key}"
scylla_storage_backend = "block-volume"
scylla_block_volume_count = 1
scylla_block_volume_size_gib = 100
scylla_block_volume_vpus_per_gb = 10
scylla_block_volume_attachment_type = "paravirtualized"
scylla_block_volume_retention = "delete"
manager_data_volume_size_gib = 50
manager_data_volume_vpus_per_gb = 10
manager_data_volume_attachment_type = "paravirtualized"
monitoring_data_volume_size_gib = 75
monitoring_data_volume_vpus_per_gb = 10
monitoring_data_volume_attachment_type = "paravirtualized"
"""


def _deploy_request(tmp_path: Path, *, counts: str = '"AD-2" = 1, "AD-1" = 1'):
    public_key = tmp_path / "id.pub"
    public_key.write_text("ssh-ed25519 AAAAfixture", encoding="utf-8")
    config = tmp_path / "cluster.toml"
    config.write_text(_config_text(public_key, counts=counts), encoding="utf-8")
    config.chmod(0o600)
    return parse_operation_request(
        [
            "--state-dir",
            str(tmp_path / "state"),
            "--config",
            str(config),
            "deploy",
            "--dry-run",
            "--oci-auth-mode",
            "instance-principal",
        ],
        environ={},
    )


def _spec(tmp_path: Path) -> ClusterSpec:
    return compile_new_cluster_spec(
        _deploy_request(tmp_path),
        cluster_uuid=_CLUSTER_UUID,
        canonical_zone_ids={
            "AD-1": "kIdk:PHX-AD-1",
            "AD-2": "kIdk:PHX-AD-2",
        },
    )


def test_complete_spec_compilation_is_normalized_deterministic_and_secret_free(
    tmp_path: Path,
) -> None:
    spec = _spec(tmp_path)

    assert tuple(zone.zone_id for zone in spec.zones) == (
        "kIdk:PHX-AD-1",
        "kIdk:PHX-AD-2",
    )
    assert spec.zones[0].scylla_rack.value == "rack-explicit"
    assert spec.zones[0].scylla_rack.source == "explicit"
    assert spec.zones[1].scylla_rack.value == "rack-kidk-phx-ad-2"
    assert spec.scylla_datacenter.value == "oci-us-phoenix-1"
    assert spec.zones[0].logical_node_ids == ("scylla-kidk-phx-ad-1-1",)
    assert spec.services[0].zones == ("kIdk:PHX-AD-1",)
    assert spec.services[1].zones == ("kIdk:PHX-AD-2",)
    assert tuple(policy.role for policy in spec.storage) == tuple(HostRole)
    assert spec.storage[0].requested_backend is StorageBackend.BLOCK_VOLUME
    assert spec.storage[3].requested_backend is StorageBackend.BOOT_ONLY
    assert spec.network.public_endpoints is False
    assert "PRIVATE KEY" not in str(spec.to_object())
    assert str(tmp_path / "id.pub") not in repr(spec)

    restored = ClusterSpec.from_object(spec.to_object())
    assert restored == spec
    assert restored.digest() == spec.digest()


def test_persisted_oracle_image_intent_is_readable_but_not_migrated(
    tmp_path: Path,
) -> None:
    supported = _spec(tmp_path)
    legacy = replace(
        supported,
        image_filters=tuple(
            (
                role,
                ImageFilter("Oracle Linux", "9.4", ImageVersionMatch.EXACT),
            )
            for role, _ in supported.image_filters
        ),
    )
    restored = ClusterSpec.from_object(legacy.to_object())
    assert restored == legacy
    resolution = resolve_existing_config(_deploy_request(tmp_path), restored)
    changed_fields = {change.field for change in resolution.changes}
    assert {
        "scylla_image_operating_system",
        "scylla_image_operating_system_version",
        "manager_image_operating_system",
        "manager_image_operating_system_version",
        "monitoring_image_operating_system",
        "monitoring_image_operating_system_version",
    } <= changed_fields
    assert resolution.baseline == legacy


def test_spec_round_trip_rejects_unknown_missing_and_wrong_native_types(
    tmp_path: Path,
) -> None:
    value = _spec(tmp_path).to_object()
    network = value["network"]
    assert isinstance(network, dict)
    network["password"] = "fixture"
    with pytest.raises(ConfigurationError, match="fields do not match"):
        ClusterSpec.from_object(value)

    value = _spec(tmp_path).to_object()
    value.pop("zones")
    with pytest.raises(ConfigurationError, match="fields do not match"):
        ClusterSpec.from_object(value)

    value = _spec(tmp_path).to_object()
    zones = value["zones"]
    assert isinstance(zones, list)
    assert isinstance(zones[0], dict)
    zones[0]["scylla_nodes"] = True
    with pytest.raises(ConfigurationError, match="integer"):
        ClusterSpec.from_object(value)

    old = _spec(tmp_path).to_object()
    old["schema_version"] = "deploy-scylla-vms.desired/v1"
    with pytest.raises(ConfigurationError, match="unsupported"):
        ClusterSpec.from_object(old)


def test_provider_zone_facts_are_required_and_normalization_collisions_refuse(
    tmp_path: Path,
) -> None:
    request = _deploy_request(tmp_path)
    with pytest.raises(ConfigurationError, match="exactly cover"):
        compile_new_cluster_spec(
            request,
            cluster_uuid=_CLUSTER_UUID,
            canonical_zone_ids={"AD-1": "canonical-1"},
        )
    with pytest.raises(ConfigurationError, match="normalized zone keys"):
        compile_new_cluster_spec(
            request,
            cluster_uuid=_CLUSTER_UUID,
            canonical_zone_ids={"AD-1": "canonical_a", "AD-2": "canonical-a"},
        )


def test_jump_hosts_receive_stable_round_robin_zone_placement(tmp_path: Path) -> None:
    request = _deploy_request(tmp_path)
    options = tuple(
        replace(option, value=3, source=ValueSource.CONFIG)
        if option.name == "jump_host_count"
        else replace(
            option,
            value="VM.Standard.E5.Flex",
            source=ValueSource.CONFIG,
        )
        if option.name == "jump_host_instance_type"
        else replace(
            option,
            value=("Ubuntu" if option.name.endswith("operating_system") else "24.04"),
            source=ValueSource.CONFIG,
        )
        if option.name
        in {
            "jump_host_image_operating_system",
            "jump_host_image_operating_system_version",
        }
        else option
        for option in request.options
    )
    request = replace(request, options=options)
    spec = compile_new_cluster_spec(
        request,
        cluster_uuid=_CLUSTER_UUID,
        canonical_zone_ids={"AD-1": "AD-1", "AD-2": "AD-2"},
    )
    jump_hosts = spec.services[2]
    assert jump_hosts.logical_ids == ("jump-host-1", "jump-host-2", "jump-host-3")
    assert jump_hosts.zones == ("AD-1", "AD-2", "AD-1")


def test_public_jump_subnets_must_match_assigned_zones(tmp_path: Path) -> None:
    public_key = tmp_path / "public.pub"
    public_key.write_text("ssh-ed25519 AAAAfixture", encoding="utf-8")
    text = _config_text(public_key).replace(
        "jump_host_count = 0",
        """jump_host_count = 1
jump_host_instance_type = "VM.Standard.E5.Flex"
jump_host_image_operating_system = "Ubuntu"
jump_host_image_operating_system_version = "24.04"
oci_public_jump_hosts = true
oci_public_subnet_cidr = { "AD-1" = "10.0.10.0/24" }
operator_cidr = ["198.51.100.0/24"]""",
    )
    config = tmp_path / "public.toml"
    config.write_text(text, encoding="utf-8")
    config.chmod(0o600)
    request = parse_operation_request(
        [
            "--state-dir",
            str(tmp_path / "state"),
            "--config",
            str(config),
            "deploy",
            "--dry-run",
            "--oci-auth-mode",
            "instance-principal",
        ],
        environ={},
    )
    spec = compile_new_cluster_spec(
        request,
        cluster_uuid=_CLUSTER_UUID,
        canonical_zone_ids={"AD-1": "AD-1", "AD-2": "AD-2"},
    )
    assert spec.network.public_subnet_cidrs == (("AD-1", "10.0.10.0/24"),)

    wrong = replace(
        request,
        options=tuple(
            replace(option, value=(("AD-2", "10.0.10.0/24"),))
            if option.name == "oci_public_subnet_cidr"
            else option
            for option in request.options
        ),
    )
    with pytest.raises(ConfigurationError, match="public subnets"):
        compile_new_cluster_spec(
            wrong,
            cluster_uuid=_CLUSTER_UUID,
            canonical_zone_ids={"AD-1": "AD-1", "AD-2": "AD-2"},
        )


def test_zero_scylla_cluster_is_refused_at_complete_spec_boundary(
    tmp_path: Path,
) -> None:
    request = _deploy_request(tmp_path, counts='"AD-2" = 0, "AD-1" = 0')
    with pytest.raises(ConfigurationError, match="at least one Scylla"):
        compile_new_cluster_spec(
            request,
            cluster_uuid=_CLUSTER_UUID,
            canonical_zone_ids={"AD-1": "AD-1", "AD-2": "AD-2"},
        )


def test_storage_and_network_role_restrictions_are_enforced(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    block = BlockVolumePolicy(
        1,
        10,
        10,
        AttachmentType.PARAVIRTUALIZED,
        VolumeRetention.RETAIN,
        None,
        False,
    )
    with pytest.raises(ConfigurationError, match="Manager and monitoring"):
        StoragePolicy(
            HostRole.MANAGER,
            StorageBackend.LOCAL_NVME,
            StorageLayout.SINGLE,
            1,
            10,
            None,
        )
    with pytest.raises(ConfigurationError, match="requires a VCN"):
        NetworkPolicy(
            NetworkMode.EXISTING,
            None,
            (),
            (),
            "opc",
            spec.network.ssh_public_key_path,
        )
    with pytest.raises(ConfigurationError, match="one explicit block"):
        StoragePolicy(
            HostRole.MONITORING,
            StorageBackend.BLOCK_VOLUME,
            StorageLayout.SINGLE,
            None,
            None,
            replace(block, count=2),
        )
    with pytest.raises(ConfigurationError, match="cannot satisfy"):
        StoragePolicy(
            HostRole.SCYLLA,
            StorageBackend.AUTO,
            StorageLayout.RAID0,
            2,
            100,
            block,
        )


def test_existing_baseline_yields_proposed_changes_but_read_only_refuses(
    tmp_path: Path,
) -> None:
    baseline = _spec(tmp_path)
    request = parse_operation_request(
        [
            "--cluster-name",
            "example",
            "--state-dir",
            str(tmp_path / "state"),
            "add-node",
            "--dry-run",
            "--oci-auth-mode",
            "instance-principal",
            "--scylla-instance-type",
            "VM.Standard.E6.Flex",
            "--node-id",
            "scylla-new-1",
            "--zone",
            "kIdk:PHX-AD-1",
        ],
        environ={},
    )
    resolution = resolve_existing_config(request, baseline)
    assert len(resolution.changes) == 1
    assert resolution.changes[0].field == "scylla_instance_type"
    assert resolution.changes[0].source is ValueSource.CLI
    assert baseline.scylla_instance_type == "VM.Standard.E5.Flex"

    show = parse_operation_request(
        [
            "--cluster-name",
            "example",
            "--state-dir",
            str(tmp_path / "state"),
            "show",
        ],
        environ={"DEPLOY_SCYLLA_VMS_OCI_REGION": "us-ashburn-1"},
    )
    with pytest.raises(StateConflictError, match="read-only request conflicts"):
        resolve_existing_config(show, baseline)
