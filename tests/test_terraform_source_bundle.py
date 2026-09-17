import importlib.resources
import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

from scylla_vms.locking import ClusterLock
from scylla_vms.oci import OciTerraformInput
from scylla_vms.state import StatePaths, initialize_state_layout
from scylla_vms.terraform.commands import TerraformCommandBuilder
from scylla_vms.terraform.outputs import (
    TERRAFORM_IMAGE_SELECTION_OUTPUT_SCHEMA_VERSION,
    TERRAFORM_IMAGE_SELECTION_SCHEMA_VERSION,
    TERRAFORM_NETWORK_EVIDENCE_SCHEMA_VERSION,
    parse_terraform_image_selection_outputs,
    parse_terraform_network_outputs,
    terraform_image_selection_type_descriptor,
    terraform_network_evidence_type_descriptor,
)
from scylla_vms.terraform.source import (
    PRODUCTION_OCI_SOURCE_VERSION,
    TerraformSourceStager,
    load_production_oci_source_bundle,
    validate_staged_source,
)

CLUSTER_UUID = uuid.UUID("22222222-2222-4222-8222-222222222222")


def _source_text() -> tuple[set[str], str]:
    bundle = load_production_oci_source_bundle()
    return (
        {source.path for source in bundle.files},
        "\n".join(source.content.decode("utf-8") for source in bundle.files),
    )


def test_packaged_oci_source_has_exact_version_lock_and_deterministic_hashes() -> None:
    first = load_production_oci_source_bundle()
    second = load_production_oci_source_bundle()

    assert first == second
    assert first.version == PRODUCTION_OCI_SOURCE_VERSION == "oci-root/v3"
    assert first.planning_ready
    assert {source.path for source in first.files} == {
        ".terraform.lock.hcl",
        "compute.tf",
        "images.tf",
        "network.tf",
        "outputs.tf",
        "security.tf",
        "storage.tf",
        "variables.tf",
        "versions.tf",
    }
    lock = next(
        source.content.decode("utf-8")
        for source in first.files
        if source.path == ".terraform.lock.hcl"
    )
    assert 'version     = "9.1.0"' in lock
    assert 'constraints = "~> 9.1.0"' in lock
    assert "h1:" in lock and lock.count("zh:") >= 2


def test_packaged_oci_source_uses_one_stable_physical_root() -> None:
    bundles = importlib.resources.files("scylla_vms.terraform").joinpath("bundles")
    active = bundles.joinpath("oci_root")

    assert active.is_dir()
    assert {entry.name for entry in active.iterdir() if entry.is_file()} == {
        ".terraform.lock.hcl",
        "compute.tf",
        "images.tf",
        "network.tf",
        "outputs.tf",
        "security.tf",
        "storage.tf",
        "variables.tf",
        "versions.tf",
    }
    assert not any(
        entry.is_dir() and re.fullmatch(r"oci_root_v[0-9]+", entry.name)
        for entry in bundles.iterdir()
    )


def test_terraform_variables_cover_exact_v2_provider_input_shape() -> None:
    _, text = _source_text()
    input_fields = set(OciTerraformInput.__dataclass_fields__) - {"schema_version"}
    for field in input_fields | {"schema_version"}:
        assert re.search(rf"\b{re.escape(field)}\b", text)

    for field in {
        "allow_public_jump_hosts",
        "assign_public_ip",
        "block_volume",
        "freeform_tags",
        "image_filters",
        "image_time_created",
        "local_min_device_count",
        "operator_cidrs",
        "policy_digest",
        "private_subnet_cidrs",
        "public_ssh_key",
        "public_subnet_cidrs",
        "selected_backend",
        "subnet_ids",
    }:
        assert re.search(rf"\b{field}\b", text)
    assert "deploy-scylla-vms.terraform-input.oci/v2" in text
    assert "deploy-scylla-vms.tfvars/v1" in text


def test_image_lookup_is_shape_filtered_deterministic_and_refuses_ambiguity() -> None:
    _, text = _source_text()
    assert 'data "oci_core_images" "role_shape"' in text
    assert "for_each = local.image_queries" in text
    assert 'state      = "AVAILABLE"' in text
    assert 'sort_by    = "TIMECREATED"' in text
    assert 'sort_order = "DESC"' in text
    assert "startswith(image.operating_system_version" in text
    assert "length(local.compatible_images[key]) > 0" in text
    assert "length(local.newest_images[key]) == 1" in text
    assert "Each role and shape must resolve to exactly one newest" in text


def test_partial_outputs_include_reviewable_image_and_network_evidence() -> None:
    _, text = _source_text()
    for field in {
        "filter",
        "image_id",
        "image_name",
        "image_time_created",
        "operating_system",
        "operating_system_version",
        "role",
        "shape",
        "version_match",
    }:
        assert re.search(rf"\b{field}\b", text)
    assert 'output "network_evidence"' in text
    assert "deploy-scylla-vms.terraform-network-evidence/v1" in text


def test_partial_image_output_matches_strict_python_contract() -> None:
    value = {
        "cluster_name": "example",
        "cluster_uuid": str(CLUSTER_UUID),
        "images": [
            {
                "filter": {
                    "operating_system": "Ubuntu",
                    "operating_system_version": "24.04",
                    "version_match": "exact",
                },
                "image_id": "ocid1.image.oc1.iad.fakeimage",
                "image_name": "Canonical-Ubuntu-24.04-2026.09.01-0",
                "image_time_created": "2026-09-01T00:00:00Z",
                "logical_id": "scylla-ad-1-1",
                "role": "scylla",
                "shape": "VM.Standard.E5.Flex",
            }
        ],
        "provider": "oci",
        "schema_version": TERRAFORM_IMAGE_SELECTION_SCHEMA_VERSION,
    }
    outputs = {
        "image_selection": {
            "sensitive": False,
            "type": terraform_image_selection_type_descriptor(),
            "value": value,
        },
        "schema_version": {
            "sensitive": False,
            "type": "string",
            "value": TERRAFORM_IMAGE_SELECTION_OUTPUT_SCHEMA_VERSION,
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
                        "id": "ocid1.networksecuritygroup.oc1.iad.fakensg",
                        "role": "scylla",
                    }
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
                        "subnet_id": "ocid1.subnet.oc1.iad.fakesubnet",
                        "zone": "AD-1",
                    }
                ],
                "vcn_id": "ocid1.vcn.oc1.iad.fakevcn",
            },
        },
    }

    parsed = parse_terraform_image_selection_outputs(
        json.dumps(outputs), expected_cluster_uuid=CLUSTER_UUID
    )
    assert parsed.cluster_name == "example"
    assert parsed.images[0].logical_id == "scylla-ad-1-1"
    assert parsed.images[0].image_id == "ocid1.image.oc1.iad.fakeimage"
    network = parse_terraform_network_outputs(
        json.dumps(outputs), expected_cluster_uuid=CLUSTER_UUID
    )
    assert network.mode == "create"
    assert network.subnets[0].zone == "AD-1"
    assert network.network_security_groups[0][0] == "scylla"


def test_managed_and_existing_network_branches_preserve_ownership() -> None:
    paths, text = _source_text()

    assert "network.tf" in paths
    assert 'resource "oci_core_vcn" "managed"' in text
    assert 'resource "oci_core_subnet" "private"' in text
    assert 'resource "oci_core_subnet" "public_jump"' in text
    assert 'resource "oci_core_nat_gateway" "private"' in text
    assert 'resource "oci_core_internet_gateway" "jump"' in text
    assert 'resource "oci_core_route_table" "private"' in text
    assert 'resource "oci_core_route_table" "public"' in text
    assert "for_each = local.managed_private_subnets" in text
    assert "for_each = local.managed_public_subnets" in text
    assert "security_list_ids          = []" in text
    assert "prohibit_public_ip_on_vnic = true" in text
    assert "oci_core_service_gateway" not in text
    assert "external_routing_validated = false" in text
    assert "Existing mode must not declare managed network ownership." in text


def test_network_security_rules_are_role_scoped_and_have_no_public_ingress() -> None:
    bundle = load_production_oci_source_bundle()
    security = next(
        source.content.decode("utf-8")
        for source in bundle.files
        if source.path == "security.tf"
    )

    assert 'resource "oci_core_network_security_group" "role"' in security
    assert "for_each = local.active_roles" in security
    assert 'source_type               = "NETWORK_SECURITY_GROUP"' in security
    assert (
        'resource "oci_core_network_security_group_security_rule" "operator_to_jump_ssh"'
        in security
    )
    assert 'oci_core_network_security_group.role["jump-host"].id' in security
    assert (
        'resource "oci_core_network_security_group_security_rule" "jump_to_private_ssh"'
        in security
    )
    for port in {22, 7000, 7001, 9042, 9100, 9180, 10001}:
        assert re.search(rf"\b{port}\b", security)
    ingress_blocks = [
        block
        for block in security.split(
            'resource "oci_core_network_security_group_security_rule"'
        )
        if 'direction                 = "INGRESS"' in block
    ]
    assert ingress_blocks
    assert all(
        "0.0.0.0/0" not in block and "::/0" not in block for block in ingress_blocks
    )
    assert "operator_cidrs" not in next(
        block for block in ingress_blocks if '"jump_to_private_ssh"' in block
    )


def test_source_contains_no_authentication_or_private_material() -> None:
    _, text = _source_text()
    lowered = text.lower()
    for forbidden in {
        "api_key",
        "auth_type",
        "fingerprint",
        "private_key",
        "security_token",
        "tenancy_ocid",
        "user_ocid",
    }:
        assert forbidden not in lowered
    assert "-----begin" not in lowered


def test_compute_storage_and_final_output_graph_is_complete() -> None:
    paths, text = _source_text()

    assert {"compute.tf", "storage.tf"} <= paths
    assert 'resource "oci_core_instance" "host"' in text
    assert "for_each = local.hosts_by_id" in text
    assert "ssh_authorized_keys" in text
    assert "assign_public_ip" in text
    assert 'resource "oci_core_volume" "retained"' in text
    assert "prevent_destroy = true" in text
    assert 'resource "oci_core_volume" "deleted"' in text
    assert 'resource "oci_core_volume_attachment" "data"' in text
    assert "is_pv_encryption_in_transit_enabled" in text
    assert 'output "host_manifest"' in text
    assert "deploy-scylla-vms.terraform-output/v1" in text
    assert "deploy-scylla-vms.host-manifest/v1" in text
    assert "deploy-scylla-vms.storage-manifest/v1" in text
    assert "/dev/nvme" not in text
    assert "capability-slot" not in text


def test_production_bundle_stages_with_hash_binding_and_allows_plan(
    tmp_path: Path,
) -> None:
    paths = StatePaths.derive(tmp_path / "state", "example")
    initialize_state_layout(paths)
    bundle = load_production_oci_source_bundle()

    with ClusterLock(paths, "deploy", 0) as lock:
        stored = TerraformSourceStager(
            paths, token_factory=lambda: "production"
        ).stage_locked(
            bundle,
            cluster_uuid=CLUSTER_UUID,
            cluster_name="example",
            clock=lambda: datetime(2026, 9, 17, tzinfo=UTC),
            lock=lock,
        )
    assert validate_staged_source(paths, stored) == stored.record
    assert stored.record.bundle_digest == bundle.digest
    assert stored.record.planning_ready

    executable = tmp_path / "terraform"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    command = TerraformCommandBuilder(executable, paths, source=stored).plan(
        uuid.uuid4()
    )
    assert command.source_digest == stored.record.bundle_digest
    assert command.plan_path is not None
