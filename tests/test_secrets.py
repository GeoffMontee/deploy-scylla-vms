from pathlib import Path

import pytest

from scylla_vms.cli import parse_operation_request
from scylla_vms.errors import ConfigurationError
from scylla_vms.secrets import SecretInputs, SecretValue


def _check_request(tmp_path: Path, auth_mode: str) -> list[str]:
    return [
        "--cluster-name",
        "example",
        "--state-dir",
        str(tmp_path / "state"),
        "check-jump-hosts",
        "--oci-auth-mode",
        auth_mode,
    ]


def test_secret_value_string_and_repr_are_redacted() -> None:
    value = SecretValue("obviously-fake-secret")
    assert str(value) == "[REDACTED]"
    assert "obviously-fake-secret" not in repr(value)


def test_api_key_mode_requires_exact_environment_only_inputs(
    tmp_path: Path,
) -> None:
    with pytest.raises(ConfigurationError) as raised:
        parse_operation_request(
            _check_request(tmp_path, "api-key"),
            environ={"OCI_PRIVATE_KEY": "obviously-fake-private-key"},
        )

    diagnostic = str(raised.value)
    assert "OCI_TENANCY_OCID" in diagnostic
    assert "obviously-fake-private-key" not in diagnostic


def test_api_key_secrets_are_typed_without_value_exposure(tmp_path: Path) -> None:
    environment = {
        "OCI_TENANCY_OCID": "ocid1.tenancy.oc1..fixture",
        "OCI_USER_OCID": "ocid1.user.oc1..fixture",
        "OCI_FINGERPRINT": "00:11:22:33",
        "OCI_PRIVATE_KEY": "obviously-fake-private-key",
    }
    request = parse_operation_request(
        _check_request(tmp_path, "api-key"),
        environ=environment,
    )

    assert request.secrets.names == tuple(sorted(environment))
    representation = repr(request)
    for value in environment.values():
        assert value not in representation


def test_instance_principal_rejects_inapplicable_oci_secrets(
    tmp_path: Path,
) -> None:
    with pytest.raises(ConfigurationError, match="forbids protected input"):
        parse_operation_request(
            _check_request(tmp_path, "instance-principal"),
            environ={"OCI_PRIVATE_KEY": "obviously-fake-private-key"},
        )


def test_resource_principal_region_mismatch_names_no_secret(
    tmp_path: Path,
) -> None:
    environment = {
        "OCI_RESOURCE_PRINCIPAL_VERSION": "2.2",
        "OCI_RESOURCE_PRINCIPAL_RPST": "obviously-fake-rpst",
        "OCI_RESOURCE_PRINCIPAL_PRIVATE_PEM": "obviously-fake-pem",
        "OCI_RESOURCE_PRINCIPAL_REGION": "us-phoenix-1",
    }
    with pytest.raises(ConfigurationError, match="does not match") as raised:
        parse_operation_request(
            [
                "--cluster-name",
                "example",
                "--state-dir",
                str(tmp_path / "state"),
                "check-jump-hosts",
                "--oci-auth-mode",
                "resource-principal",
                "--oci-region",
                "us-ashburn-1",
            ],
            environ=environment,
        )

    diagnostic = str(raised.value)
    assert "us-phoenix-1" not in diagnostic
    assert "obviously-fake-rpst" not in diagnostic


def test_empty_secret_and_conflicting_ssh_sources_are_rejected() -> None:
    with pytest.raises(ConfigurationError, match="must not be empty"):
        SecretInputs.from_environment({"OCI_PRIVATE_KEY": ""})
    with pytest.raises(ConfigurationError, match="mutually exclusive"):
        SecretInputs.from_environment(
            {
                "DEPLOY_SCYLLA_VMS_SSH_PRIVATE_KEY": "obviously-fake-key",
                "SSH_AUTH_SOCK": "/tmp/obviously-fake-agent",
            }
        )


@pytest.mark.parametrize(
    ("environment", "message"),
    [
        (
            {"DEPLOY_SCYLLA_VMS_SSH_PRIVATE_KEY_PASSPHRASE": "fixture"},
            "requires DEPLOY_SCYLLA_VMS_SSH_PRIVATE_KEY",
        ),
        (
            {"OCI_PRIVATE_KEY_PASSWORD": "fixture"},
            "requires OCI_PRIVATE_KEY",
        ),
        (
            {"DEPLOY_SCYLLA_VMS_SCYLLA_REPOSITORY_USERNAME": "fixture"},
            "required together",
        ),
        (
            {"SSH_AUTH_SOCK": "relative/socket"},
            "absolute path",
        ),
    ],
)
def test_secret_required_together_and_path_rules(
    environment: dict[str, str], message: str
) -> None:
    with pytest.raises(ConfigurationError, match=message):
        SecretInputs.from_environment(environment)
