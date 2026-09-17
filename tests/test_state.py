from pathlib import Path

import pytest

from scylla_vms.errors import ConfigurationError, UnsafePathError
from scylla_vms.state import StatePaths, validate_cluster_name


@pytest.mark.parametrize(
    "name",
    [
        "",
        ".",
        "..",
        "../cluster",
        "a/b",
        r"a\b",
        "/absolute",
        "Upper",
        "éxample",
        "a--b",
        "a-",
        "1cluster",
        "a" * 64,
        "clusters",
    ],
)
def test_invalid_cluster_names_are_rejected(name: str) -> None:
    with pytest.raises(ConfigurationError):
        validate_cluster_name(name)


@pytest.mark.parametrize("name", ["a", "example", "cluster-1", "a1", "a" * 63])
def test_valid_cluster_names_are_unchanged(name: str) -> None:
    assert validate_cluster_name(name) == name


def test_canonical_state_layout(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    paths = StatePaths.derive(state_root, "example")
    cluster = state_root / "clusters" / "example"

    assert paths.cluster_root == cluster
    assert paths.cluster_metadata == cluster / "cluster.json"
    assert paths.storage == cluster / "storage"
    assert paths.terraform_work == cluster / "terraform" / "work"
    assert paths.terraform_data == cluster / "terraform" / ".terraform"
    assert paths.terraform_backups == cluster / "terraform" / "backups"
    assert paths.terraform_state == cluster / "terraform" / "terraform.tfstate"
    assert paths.terraform_plans == cluster / "terraform" / "plans"
    assert paths.ansible_inventory == cluster / "ansible" / "inventory.yml"
    assert paths.known_hosts == cluster / "ansible" / "known_hosts"
    assert paths.operations == cluster / "operations"
    assert paths.logs == cluster / "logs"
    assert paths.lock == cluster / "lock"
    assert not state_root.exists()


def test_existing_clusters_symlink_escape_is_rejected(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    outside = tmp_path / "outside"
    state_root.mkdir(mode=0o700)
    outside.mkdir(mode=0o700)
    (state_root / "clusters").symlink_to(outside, target_is_directory=True)

    with pytest.raises(UnsafePathError, match="symbolic link"):
        StatePaths.derive(state_root, "example")


def test_existing_cluster_symlink_escape_is_rejected(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    clusters = state_root / "clusters"
    outside = tmp_path / "outside"
    state_root.mkdir(mode=0o700)
    clusters.mkdir(mode=0o700)
    outside.mkdir(mode=0o700)
    (clusters / "example").symlink_to(outside, target_is_directory=True)

    with pytest.raises(UnsafePathError, match="symbolic link"):
        StatePaths.derive(state_root, "example")


def test_insecure_existing_state_root_is_rejected(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o755)

    with pytest.raises(UnsafePathError, match="permissions must be 0700"):
        StatePaths.derive(state_root, "example")


def test_relative_state_root_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="must be absolute"):
        StatePaths.derive("relative/state", "example")
