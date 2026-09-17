from collections.abc import Callable
from pathlib import Path

import pytest

from scylla_vms.cli import parse_operation_request
from scylla_vms.errors import ConfigurationError
from scylla_vms.models import DeferredValue, ValueSource


def _deploy_arguments(tmp_path: Path) -> list[str]:
    return [
        "--cluster-name",
        "example",
        "--state-dir",
        str(tmp_path / "state"),
        "deploy",
        "--dry-run",
        "--oci-auth-mode",
        "instance-principal",
        "--zone",
        "AD-1",
        "--zone",
        "AD-2",
        "--nodes-per-zone",
        "AD-1=2",
        "--nodes-per-zone",
        "AD-2=1",
        "--oci-vcn-cidr",
        "10.0.0.0/16",
        "--oci-private-subnet-cidr",
        "AD-1=10.0.1.0/24",
        "--oci-private-subnet-cidr",
        "AD-2=10.0.2.0/24",
    ]


def _deploy_environment(tmp_path: Path) -> dict[str, str]:
    public_key = tmp_path / "id_fixture.pub"
    public_key.write_text("ssh-ed25519 AAAAfixture", encoding="utf-8")
    return {
        "DEPLOY_SCYLLA_VMS_OCI_REGION": "us-ashburn-1",
        "DEPLOY_SCYLLA_VMS_OCI_COMPARTMENT_ID": "ocid1.compartment.oc1..fixture",
        "DEPLOY_SCYLLA_VMS_SCYLLA_IMAGE_OPERATING_SYSTEM": "Ubuntu",
        "DEPLOY_SCYLLA_VMS_SCYLLA_IMAGE_OPERATING_SYSTEM_VERSION": "24.04",
        "DEPLOY_SCYLLA_VMS_MANAGER_IMAGE_OPERATING_SYSTEM": "Ubuntu",
        "DEPLOY_SCYLLA_VMS_MANAGER_IMAGE_OPERATING_SYSTEM_VERSION": "24.04",
        "DEPLOY_SCYLLA_VMS_MONITORING_IMAGE_OPERATING_SYSTEM": "Ubuntu",
        "DEPLOY_SCYLLA_VMS_MONITORING_IMAGE_OPERATING_SYSTEM_VERSION": "24.04",
        "DEPLOY_SCYLLA_VMS_SCYLLA_INSTANCE_TYPE": "VM.Standard.E5.Flex",
        "DEPLOY_SCYLLA_VMS_MANAGER_INSTANCE_TYPE": "VM.Standard.E5.Flex",
        "DEPLOY_SCYLLA_VMS_MONITORING_INSTANCE_TYPE": "VM.Standard.E5.Flex",
        "DEPLOY_SCYLLA_VMS_SSH_PUBLIC_KEY_PATH": str(public_key),
        "DEPLOY_SCYLLA_VMS_SCYLLA_STORAGE_BACKEND": "block-volume",
        "DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_COUNT": "1",
        "DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_SIZE_GIB": "100",
        "DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_VPUS_PER_GB": "10",
        "DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_ATTACHMENT_TYPE": "paravirtualized",
        "DEPLOY_SCYLLA_VMS_SCYLLA_BLOCK_VOLUME_RETENTION": "delete",
        "DEPLOY_SCYLLA_VMS_MANAGER_DATA_VOLUME_SIZE_GIB": "50",
        "DEPLOY_SCYLLA_VMS_MANAGER_DATA_VOLUME_VPUS_PER_GB": "10",
        "DEPLOY_SCYLLA_VMS_MANAGER_DATA_VOLUME_ATTACHMENT_TYPE": "paravirtualized",
        "DEPLOY_SCYLLA_VMS_MONITORING_DATA_VOLUME_SIZE_GIB": "50",
        "DEPLOY_SCYLLA_VMS_MONITORING_DATA_VOLUME_VPUS_PER_GB": "10",
        "DEPLOY_SCYLLA_VMS_MONITORING_DATA_VOLUME_ATTACHMENT_TYPE": "paravirtualized",
    }


def _without_option(arguments: list[str], flag: str) -> list[str]:
    result = list(arguments)
    while flag in result:
        index = result.index(flag)
        del result[index : index + 2]
    return result


def _replace_option_value(
    arguments: list[str], flag: str, old: str, new: str
) -> list[str]:
    result = list(arguments)
    for index, value in enumerate(result):
        if value == flag and result[index + 1] == old:
            result[index + 1] = new
            return result
    raise AssertionError(f"missing fixture option: {flag} {old}")


def test_deploy_resolves_typed_environment_and_derived_values(
    tmp_path: Path,
) -> None:
    request = parse_operation_request(
        _deploy_arguments(tmp_path),
        environ=_deploy_environment(tmp_path),
    )

    assert request.option("oci_region").value == "us-ashburn-1"
    assert request.option("oci_region").source is ValueSource.ENVIRONMENT
    assert request.option("nodes_per_zone").value == (("AD-1", 2), ("AD-2", 1))
    assert request.option("scylla_block_volume_count").value == 1
    assert request.option("scylla_storage_layout").value == "single"
    assert request.option("scylla_datacenter").value is DeferredValue.DERIVED
    assert request.option("manager_zone").value is DeferredValue.DERIVED
    assert not (tmp_path / "state").exists()


def test_new_desired_state_requires_exact_ubuntu_2404_images(
    tmp_path: Path,
) -> None:
    environment = _deploy_environment(tmp_path)
    for name, value in (
        ("DEPLOY_SCYLLA_VMS_SCYLLA_IMAGE_OPERATING_SYSTEM", "Oracle Linux"),
        ("DEPLOY_SCYLLA_VMS_MANAGER_IMAGE_OPERATING_SYSTEM_VERSION", "22.04"),
        ("DEPLOY_SCYLLA_VMS_MONITORING_IMAGE_VERSION_MATCH", "prefix"),
    ):
        invalid = dict(environment)
        invalid[name] = value
        with pytest.raises(ConfigurationError, match=r"exact Ubuntu 24\.04"):
            parse_operation_request(_deploy_arguments(tmp_path), environ=invalid)


def test_cli_deploy_value_overrides_environment(tmp_path: Path) -> None:
    request = parse_operation_request(
        [
            *_deploy_arguments(tmp_path),
            "--manager-data-volume-size-gib",
            "75",
        ],
        environ=_deploy_environment(tmp_path),
    )

    assert request.option("manager_data_volume_size_gib").value == 75
    assert request.option("manager_data_volume_size_gib").source is ValueSource.CLI


def test_deploy_zone_mappings_reject_missing_duplicate_and_unknown_keys(
    tmp_path: Path,
) -> None:
    environment = _deploy_environment(tmp_path)
    arguments = _deploy_arguments(tmp_path)
    with pytest.raises(ConfigurationError, match="every declared"):
        incomplete = list(arguments)
        index = incomplete.index("AD-2=1")
        del incomplete[index - 1 : index + 1]
        parse_operation_request(
            incomplete,
            environ=environment,
        )
    with pytest.raises(ConfigurationError, match="values must be unique"):
        parse_operation_request(
            [*arguments, "--zone", "AD-1"],
            environ=environment,
        )
    with pytest.raises(ConfigurationError, match="unknown zone"):
        parse_operation_request(
            [*arguments, "--scylla-rack", "AD-3=rack-c"],
            environ=environment,
        )


def test_existing_network_requires_complete_role_subnet_map(
    tmp_path: Path,
) -> None:
    environment = _deploy_environment(tmp_path)
    environment.update(
        {
            "DEPLOY_SCYLLA_VMS_NETWORK_MODE": "existing",
            "DEPLOY_SCYLLA_VMS_OCI_VCN_ID": "ocid1.vcn.oc1..fixture",
        }
    )
    with pytest.raises(ConfigurationError, match="every deployed role"):
        parse_operation_request(
            [
                *_without_option(
                    _without_option(
                        _deploy_arguments(tmp_path), "--oci-private-subnet-cidr"
                    ),
                    "--oci-vcn-cidr",
                ),
                "--oci-subnet",
                "scylla=ocid1.subnet.oc1..scylla",
            ],
            environ=environment,
        )

    request = parse_operation_request(
        [
            *_without_option(
                _without_option(
                    _deploy_arguments(tmp_path), "--oci-private-subnet-cidr"
                ),
                "--oci-vcn-cidr",
            ),
            "--oci-subnet",
            "scylla=ocid1.subnet.oc1..scylla",
            "--oci-subnet",
            "manager=ocid1.subnet.oc1..manager",
            "--oci-subnet",
            "monitoring=ocid1.subnet.oc1..monitoring",
        ],
        environ=environment,
    )
    assert request.option("network_mode").value == "existing"


@pytest.mark.parametrize(
    ("arguments", "message"),
    (
        (
            lambda values: _without_option(values, "--oci-private-subnet-cidr"),
            "every zone",
        ),
        (
            lambda values: _replace_option_value(
                values,
                "--oci-private-subnet-cidr",
                "AD-2=10.0.2.0/24",
                "AD-2=10.0.1.0/24",
            ),
            "overlap",
        ),
        (
            lambda values: _replace_option_value(
                values,
                "--oci-private-subnet-cidr",
                "AD-2=10.0.2.0/24",
                "AD-2=10.1.2.0/24",
            ),
            "inside",
        ),
        (
            lambda values: _replace_option_value(
                values,
                "--oci-vcn-cidr",
                "10.0.0.0/16",
                "203.0.113.0/24",
            ),
            "RFC 1918",
        ),
    ),
)
def test_managed_network_requires_complete_private_nonoverlapping_cidrs(
    tmp_path: Path,
    arguments: Callable[[list[str]], list[str]],
    message: str,
) -> None:
    with pytest.raises(ConfigurationError, match=message):
        parse_operation_request(
            arguments(_deploy_arguments(tmp_path)),
            environ=_deploy_environment(tmp_path),
        )


def test_storage_backend_required_together_and_forbidden_rules(
    tmp_path: Path,
) -> None:
    environment = _deploy_environment(tmp_path)
    environment["DEPLOY_SCYLLA_VMS_SCYLLA_STORAGE_BACKEND"] = "local-nvme"
    with pytest.raises(ConfigurationError, match="required"):
        parse_operation_request(_deploy_arguments(tmp_path), environ=environment)

    environment.update(
        {
            "DEPLOY_SCYLLA_VMS_SCYLLA_STORAGE_MIN_DEVICE_COUNT": "2",
            "DEPLOY_SCYLLA_VMS_SCYLLA_STORAGE_MIN_TOTAL_GIB": "500",
            "DEPLOY_SCYLLA_VMS_SCYLLA_STORAGE_LAYOUT": "raid0",
        }
    )
    with pytest.raises(ConfigurationError, match="selected storage backend forbids"):
        parse_operation_request(_deploy_arguments(tmp_path), environ=environment)


def test_chap_enablement_is_explicitly_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="not supported"):
        parse_operation_request(
            [
                *_deploy_arguments(tmp_path),
                "--scylla-block-volume-chap",
                "enabled",
            ],
            environ=_deploy_environment(tmp_path),
        )
