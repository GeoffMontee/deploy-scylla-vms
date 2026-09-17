import os
from pathlib import Path

import pytest

from scylla_vms.cli import parse_operation_request
from scylla_vms.config_file import CONFIG_SCHEMA_VERSION, load_config
from scylla_vms.errors import ConfigurationError, UnsafePathError
from scylla_vms.models import ValueSource


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)


def _document(cluster: str = "") -> str:
    return f'schema_version = "{CONFIG_SCHEMA_VERSION}"\n[cluster]\n{cluster}'


def test_absent_config_is_distinct_from_explicit_missing_and_empty(
    tmp_path: Path,
) -> None:
    assert load_config(None).values == {}
    with pytest.raises(ConfigurationError, match="does not exist"):
        load_config(tmp_path / "missing.toml")

    empty = tmp_path / "empty.toml"
    _write(empty, "")
    with pytest.raises(ConfigurationError, match="must not be empty"):
        load_config(empty)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("not = [valid", "invalid TOML"),
        (
            'schema_version = "deploy-scylla-vms.config/v999"\n[cluster]\n',
            "unsupported",
        ),
        (
            'schema_version = "deploy-scylla-vms.config/v1"\n[cluster]\n',
            "unsupported",
        ),
        (
            _document('unknown = "value"\n'),
            "unknown non-secret",
        ),
        (
            _document('api_token = "fixture"\n'),
            "secret-like keys",
        ),
        (
            _document('ssh_user = "-----BEGIN PRIVATE KEY-----"\n'),
            "private key material",
        ),
        (
            _document('ssh_user = "${USER}"\n'),
            "interpolation",
        ),
        (
            f'schema_version = "{CONFIG_SCHEMA_VERSION}"\n'
            'include = "other.toml"\n[cluster]\n',
            "only schema_version",
        ),
        (
            f'schema_version = "{CONFIG_SCHEMA_VERSION}"\n'
            f'schema_version = "{CONFIG_SCHEMA_VERSION}"\n[cluster]\n',
            "invalid TOML",
        ),
    ],
)
def test_config_rejects_invalid_version_unknown_duplicate_and_secret_content(
    tmp_path: Path, content: str, message: str
) -> None:
    path = tmp_path / "config.toml"
    _write(path, content)
    with pytest.raises(ConfigurationError, match=message):
        load_config(path)


def test_config_refuses_directory_symlink_hardlink_and_unsafe_permissions(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(UnsafePathError, match="regular file"):
        load_config(directory)

    target = tmp_path / "target.toml"
    _write(target, _document())
    symlink = tmp_path / "symlink.toml"
    symlink.symlink_to(target)
    with pytest.raises(UnsafePathError, match="symbolic link"):
        load_config(symlink)

    hardlink = tmp_path / "hardlink.toml"
    os.link(target, hardlink)
    with pytest.raises(UnsafePathError, match="hard links"):
        load_config(target)
    hardlink.unlink()

    if os.name == "posix":
        target.chmod(0o622)
        with pytest.raises(UnsafePathError, match="writable by group"):
            load_config(target)


def test_config_refuses_noncanonical_path_alias(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    config = tmp_path / "config.toml"
    _write(config, _document())
    alias = nested / ".." / "config.toml"
    with pytest.raises(UnsafePathError, match="not canonical"):
        load_config(alias)


def test_native_config_types_and_cli_environment_precedence_are_strict(
    tmp_path: Path,
) -> None:
    config = tmp_path / "config.toml"
    _write(
        config,
        _document(
            'cluster_name = "config-name"\n'
            'oci_region = "us-phoenix-1"\n'
            "jump_host_count = 0\n"
        ),
    )
    request = parse_operation_request(
        [
            "--cluster-name",
            "cli-name",
            "--state-dir",
            str(tmp_path / "state"),
            "--config",
            str(config),
            "show",
        ],
        environ={"DEPLOY_SCYLLA_VMS_OCI_REGION": "us-ashburn-1"},
    )
    assert request.cluster_name == "cli-name"
    assert request.option("cluster_name").source is ValueSource.CLI
    assert request.option("oci_region").value == "us-ashburn-1"
    assert request.option("oci_region").source is ValueSource.ENVIRONMENT
    assert not (tmp_path / "state").exists()

    _write(config, _document('jump_host_count = "0"\n'))
    with pytest.raises(ConfigurationError, match="must be an integer"):
        parse_operation_request(
            [
                "--cluster-name",
                "example",
                "--state-dir",
                str(tmp_path / "state"),
                "--config",
                str(config),
                "deploy",
            ],
            environ={},
        )


def test_config_mapping_uses_deterministic_key_order(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    _write(
        config,
        _document(
            'cluster_name = "example"\n'
            'zone = ["AD-2", "AD-1"]\n'
            'nodes_per_zone = { "AD-2" = 2, "AD-1" = 1 }\n'
        ),
    )
    loaded = load_config(config)
    assert loaded.values["nodes_per_zone"] == {"AD-2": 2, "AD-1": 1}

    _write(
        config,
        _document(
            'cluster_name = "example"\nnodes_per_zone = { "AD-1" = 1, " AD-1 " = 2 }\n'
        ),
    )
    with pytest.raises(ConfigurationError, match="duplicate normalized key"):
        parse_operation_request(
            [
                "--state-dir",
                str(tmp_path / "state"),
                "--config",
                str(config),
                "deploy",
            ],
            environ={},
        )
