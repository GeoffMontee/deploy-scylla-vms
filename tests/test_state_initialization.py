import os
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from scylla_vms.errors import StateConflictError, UnsafePathError
from scylla_vms.state import (
    StatePaths,
    find_unexpected_terraform_state,
    initialize_state_layout,
    refuse_unexpected_terraform_state,
)


def test_explicit_initialization_is_exact_idempotent_and_owner_only(
    tmp_path: Path,
) -> None:
    paths = StatePaths.derive(tmp_path / "state", "example")
    previous_umask = os.umask(0)
    try:
        initialize_state_layout(paths)
        initialize_state_layout(paths)
    finally:
        os.umask(previous_umask)

    for directory in paths.directory_paths:
        assert directory.is_dir()
        if os.name == "posix":
            assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert all(not path.exists() for path in paths.file_paths)


def test_initialization_requires_existing_parent(tmp_path: Path) -> None:
    paths = StatePaths.derive(tmp_path / "missing" / "state", "example")

    with pytest.raises(UnsafePathError, match="parent"):
        initialize_state_layout(paths)


def test_initialization_rejects_noncanonical_model(tmp_path: Path) -> None:
    paths = StatePaths.derive(tmp_path / "state", "example")
    tampered = replace(paths, logs=tmp_path / "outside")

    with pytest.raises(UnsafePathError, match="canonical"):
        initialize_state_layout(tampered)


def test_wrong_types_and_insecure_existing_components_are_rejected(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    clusters = root / "clusters"
    clusters.write_text("not a directory", encoding="utf-8")
    clusters.chmod(0o600)

    with pytest.raises(UnsafePathError, match="wrong type"):
        StatePaths.derive(root, "example")

    clusters.unlink()
    clusters.mkdir(mode=0o755)
    with pytest.raises(UnsafePathError, match="permissions"):
        StatePaths.derive(root, "example")


def test_intermediate_managed_symlink_and_path_alias_are_rejected(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    paths = StatePaths.derive(root, "example")
    initialize_state_layout(paths)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    paths.terraform_work.rmdir()
    paths.terraform_data.rmdir()
    paths.terraform_plugin_cache.rmdir()
    paths.terraform_backups.rmdir()
    paths.terraform_plans.rmdir()
    paths.terraform.rmdir()
    paths.terraform.symlink_to(outside, target_is_directory=True)

    with pytest.raises(UnsafePathError, match=r"symbolic link|resolves unexpectedly"):
        StatePaths.derive(root, "example")

    alias = tmp_path / "unused" / ".." / "alias"
    with pytest.raises(UnsafePathError, match="non-canonical"):
        StatePaths.derive(alias, "example")


@pytest.mark.skipif(os.name != "posix", reason="FIFO type is POSIX-specific")
def test_special_file_at_managed_file_path_is_rejected(tmp_path: Path) -> None:
    paths = StatePaths.derive(tmp_path / "state", "example")
    initialize_state_layout(paths)
    os.mkfifo(paths.lock, 0o600)

    with pytest.raises(UnsafePathError, match="wrong type"):
        StatePaths.derive(paths.state_root, "example")


def test_unexpected_terraform_state_is_reported_without_reading_it(
    tmp_path: Path,
) -> None:
    paths = StatePaths.derive(tmp_path / "canonical", "example")
    initialize_state_layout(paths)
    checkout = tmp_path / "checkout"
    backend = checkout / ".terraform"
    backend.mkdir(parents=True)
    state = checkout / "terraform.tfstate"
    state.write_text("not-json-and-not-read", encoding="utf-8")
    metadata = backend / "terraform.tfstate"
    metadata.write_text("backend", encoding="utf-8")

    assert find_unexpected_terraform_state(paths, (checkout,)) == (
        metadata,
        state,
    )
    with pytest.raises(StateConflictError, match="unexpected Terraform state"):
        refuse_unexpected_terraform_state(paths, (checkout,))


def test_unexpected_state_detection_refuses_symlinked_metadata_parent(
    tmp_path: Path,
) -> None:
    paths = StatePaths.derive(tmp_path / "canonical", "example")
    initialize_state_layout(paths)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "terraform.tfstate").write_text("state", encoding="utf-8")
    (checkout / ".terraform").symlink_to(outside, target_is_directory=True)

    with pytest.raises(UnsafePathError, match="symbolic link"):
        find_unexpected_terraform_state(paths, (checkout,))


def test_canonical_terraform_metadata_is_not_reported_as_unexpected(
    tmp_path: Path,
) -> None:
    paths = StatePaths.derive(tmp_path / "state", "example")
    initialize_state_layout(paths)
    paths.terraform_state.write_text("state", encoding="utf-8")
    paths.terraform_state.chmod(0o600)
    backend = paths.terraform_data / "terraform.tfstate"
    backend.write_text("metadata", encoding="utf-8")
    backend.chmod(0o600)

    assert find_unexpected_terraform_state(paths, (paths.terraform,)) == ()
