from pathlib import Path

import pytest

from scylla_vms.config import ValueSource, resolve_common_config
from scylla_vms.errors import ConfigurationError


def test_cli_values_override_environment(tmp_path: Path) -> None:
    cli_root = tmp_path / "cli-state"
    env_root = tmp_path / "env-state"
    config = resolve_common_config(
        cli_provider="OCI",
        cli_cluster_name="cli-cluster",
        cli_state_dir=str(cli_root),
        environ={
            "DEPLOY_SCYLLA_VMS_CLOUD_PROVIDER": "oci",
            "DEPLOY_SCYLLA_VMS_CLUSTER_NAME": "env-cluster",
            "DEPLOY_SCYLLA_VMS_STATE_DIR": str(env_root),
        },
    )

    assert config.provider.name == "oci"
    assert config.cluster_name == "cli-cluster"
    assert config.state_root == cli_root
    assert config.provider_source is ValueSource.CLI
    assert config.cluster_name_source is ValueSource.CLI
    assert config.state_root_source is ValueSource.CLI


def test_environment_values_override_defaults(tmp_path: Path) -> None:
    env_root = tmp_path / "env-state"
    config = resolve_common_config(
        cli_provider=None,
        cli_cluster_name=None,
        cli_state_dir=None,
        environ={
            "DEPLOY_SCYLLA_VMS_CLOUD_PROVIDER": " OCI ",
            "DEPLOY_SCYLLA_VMS_CLUSTER_NAME": " env-cluster ",
            "DEPLOY_SCYLLA_VMS_STATE_DIR": f" {env_root} ",
        },
        default_state_root=lambda: tmp_path / "default-state",
    )

    assert config.cluster_name == "env-cluster"
    assert config.state_root == env_root
    assert config.provider_source is ValueSource.ENVIRONMENT
    assert config.cluster_name_source is ValueSource.ENVIRONMENT
    assert config.state_root_source is ValueSource.ENVIRONMENT


def test_provider_and_state_defaults(tmp_path: Path) -> None:
    default_root = tmp_path / "default-state"
    config = resolve_common_config(
        cli_provider=None,
        cli_cluster_name="example",
        cli_state_dir=None,
        environ={},
        default_state_root=lambda: default_root,
    )

    assert config.provider.name == "oci"
    assert config.state_root == default_root
    assert config.provider_source is ValueSource.DEFAULT
    assert config.state_root_source is ValueSource.DEFAULT


def test_unsupported_environment_provider_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="unsupported cloud provider: aws"):
        resolve_common_config(
            cli_provider=None,
            cli_cluster_name="example",
            cli_state_dir=str(tmp_path / "state"),
            environ={"DEPLOY_SCYLLA_VMS_CLOUD_PROVIDER": "aws"},
        )


def test_empty_implemented_environment_value_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="must not be empty"):
        resolve_common_config(
            cli_provider=None,
            cli_cluster_name=None,
            cli_state_dir=str(tmp_path / "state"),
            environ={"DEPLOY_SCYLLA_VMS_CLUSTER_NAME": "  "},
        )


def test_unknown_application_environment_reports_name_not_value(
    tmp_path: Path,
) -> None:
    secret = "definitely-not-a-real-secret"
    with pytest.raises(ConfigurationError) as raised:
        resolve_common_config(
            cli_provider=None,
            cli_cluster_name="example",
            cli_state_dir=str(tmp_path / "state"),
            environ={"DEPLOY_SCYLLA_VMS_UNKNOWN_TOKEN": secret},
        )

    assert "DEPLOY_SCYLLA_VMS_UNKNOWN_TOKEN" in str(raised.value)
    assert secret not in str(raised.value)


def test_resolution_does_not_create_state(tmp_path: Path) -> None:
    root = tmp_path / "absent-state"
    assert not root.exists()

    config = resolve_common_config(
        cli_provider=None,
        cli_cluster_name="example",
        cli_state_dir=str(root),
        environ={},
    )

    assert config.paths.cluster_root == root / "clusters" / "example"
    assert not root.exists()
