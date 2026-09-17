"""Canonical state paths, explicit initialization, and conflict detection."""

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from scylla_vms.errors import (
    ConfigurationError,
    StateConflictError,
    UnsafePathError,
)

_CLUSTER_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
RESERVED_CLUSTER_NAMES = frozenset(
    {"ansible", "clusters", "logs", "operations", "storage", "terraform"}
)


def validate_cluster_name(value: str) -> str:
    """Validate and return a canonical, unchanged cluster path component."""

    if not value:
        raise ConfigurationError("cluster name must not be empty")
    if not _CLUSTER_NAME.fullmatch(value):
        raise ConfigurationError("cluster name must match [a-z][a-z0-9-]{0,62}")
    if "--" in value or value.endswith("-"):
        raise ConfigurationError(
            "cluster name must not contain consecutive or trailing hyphens"
        )
    if value in RESERVED_CLUSTER_NAMES:
        raise ConfigurationError(f"cluster name is reserved: {value}")
    return value


def resolve_state_root(value: str | Path) -> Path:
    """Resolve a canonical root without creating or following symlink aliases."""

    raw = str(value)
    if not raw or raw.isspace():
        raise ConfigurationError("state directory must not be empty")
    raw = raw.strip()
    path = Path(raw)
    if raw.startswith("~"):
        try:
            path = path.expanduser()
        except RuntimeError as error:
            raise ConfigurationError("state directory has an unknown user") from error
    if not path.is_absolute():
        raise ConfigurationError(
            "state directory must be absolute or start with a resolvable '~'"
        )
    if path == Path(path.anchor):
        raise UnsafePathError("state directory must not be the filesystem root")
    _reject_existing_symlink_components(path)
    canonical = path.resolve(strict=False)
    if canonical != path:
        raise UnsafePathError("state directory contains a non-canonical path alias")
    validate_state_directory(canonical, allow_missing=True)
    return canonical


@dataclass(frozen=True, slots=True)
class StatePaths:
    """Canonical paths for one cluster; derivation never creates them."""

    state_root: Path
    clusters: Path
    cluster_root: Path
    cluster_metadata: Path
    storage: Path
    terraform: Path
    terraform_work: Path
    terraform_data: Path
    terraform_plugin_cache: Path
    terraform_backups: Path
    terraform_state: Path
    terraform_state_backup: Path
    terraform_observed: Path
    terraform_tfvars: Path
    terraform_source_record: Path
    terraform_plans: Path
    ansible: Path
    ansible_inventory: Path
    ansible_trust: Path
    ansible_config: Path
    ansible_ssh_config: Path
    ansible_home: Path
    ansible_local_tmp: Path
    ansible_fact_cache: Path
    ansible_control_path: Path
    ansible_log: Path
    known_hosts: Path
    operations: Path
    logs: Path
    diagnostics_evidence: Path
    lock: Path

    @classmethod
    def derive(cls, state_root: str | Path, cluster_name: str) -> "StatePaths":
        """Validate and derive the complete documented layout without writes."""

        root = resolve_state_root(state_root)
        name = validate_cluster_name(cluster_name)
        clusters = root / "clusters"
        cluster_root = clusters / name
        paths = cls(
            state_root=root,
            clusters=clusters,
            cluster_root=cluster_root,
            cluster_metadata=cluster_root / "cluster.json",
            storage=cluster_root / "storage",
            terraform=cluster_root / "terraform",
            terraform_work=cluster_root / "terraform" / "work",
            terraform_data=cluster_root / "terraform" / ".terraform",
            terraform_plugin_cache=cluster_root / "terraform" / "plugin-cache",
            terraform_backups=cluster_root / "terraform" / "backups",
            terraform_state=cluster_root / "terraform" / "terraform.tfstate",
            terraform_state_backup=cluster_root
            / "terraform"
            / "terraform.tfstate.backup",
            terraform_observed=cluster_root / "terraform" / "observed.json",
            terraform_tfvars=cluster_root
            / "terraform"
            / "work"
            / "cluster.auto.tfvars.json",
            terraform_source_record=cluster_root / "terraform" / "source.json",
            terraform_plans=cluster_root / "terraform" / "plans",
            ansible=cluster_root / "ansible",
            ansible_inventory=cluster_root / "ansible" / "inventory.yml",
            ansible_trust=cluster_root / "ansible" / "trust.json",
            ansible_config=cluster_root / "ansible" / "ansible.cfg",
            ansible_ssh_config=cluster_root / "ansible" / "ssh_config",
            ansible_home=cluster_root / "ansible" / "home",
            ansible_local_tmp=cluster_root / "ansible" / "tmp",
            ansible_fact_cache=cluster_root / "ansible" / "fact-cache",
            ansible_control_path=cluster_root / "ansible" / "control",
            ansible_log=cluster_root / "logs" / "ansible.log",
            known_hosts=cluster_root / "ansible" / "known_hosts",
            operations=cluster_root / "operations",
            logs=cluster_root / "logs",
            diagnostics_evidence=cluster_root / "logs" / "evidence.json",
            lock=cluster_root / "lock",
        )
        if cluster_root.parent != clusters:
            raise UnsafePathError(
                "cluster root must be a direct child of the clusters directory"
            )
        for directory in paths.directory_paths:
            validate_state_directory(directory, allow_missing=True)
            _validate_containment(directory, root, cluster_root)
        for file_path in paths.file_paths:
            validate_state_file(file_path, allow_missing=True)
            _validate_containment(file_path, root, cluster_root)
        return paths

    @property
    def directory_paths(self) -> tuple[Path, ...]:
        """Return directories created by explicit initialization in parent order."""

        return (
            self.state_root,
            self.clusters,
            self.cluster_root,
            self.storage,
            self.terraform,
            self.terraform_work,
            self.terraform_data,
            self.terraform_plugin_cache,
            self.terraform_backups,
            self.terraform_plans,
            self.ansible,
            self.ansible_home,
            self.ansible_local_tmp,
            self.ansible_fact_cache,
            self.ansible_control_path,
            self.operations,
            self.logs,
        )

    @property
    def file_paths(self) -> tuple[Path, ...]:
        """Return approved file locations without creating them."""

        return (
            self.cluster_metadata,
            self.terraform_state,
            self.terraform_state_backup,
            self.terraform_observed,
            self.terraform_tfvars,
            self.terraform_source_record,
            self.ansible_inventory,
            self.ansible_trust,
            self.ansible_config,
            self.ansible_ssh_config,
            self.ansible_log,
            self.known_hosts,
            self.diagnostics_evidence,
            self.lock,
        )

    @property
    def managed_paths(self) -> tuple[Path, ...]:
        """Return every cluster-relative managed path."""

        return tuple(
            path
            for path in (*self.directory_paths, *self.file_paths)
            if path != self.state_root and path != self.clusters
        )


def initialize_state_layout(paths: StatePaths) -> None:
    """Explicitly create the canonical directory layout with owner-only modes."""

    expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
    if expected != paths:
        raise UnsafePathError("state path model does not match the canonical layout")
    parent = paths.state_root.parent
    _validate_parent_directory(parent)
    if _supports_secure_dir_fd():
        _initialize_posix(paths, parent)
    else:
        _initialize_portable(paths)
    # Re-derive after creation so every component is validated independently.
    if StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths:
        raise UnsafePathError("initialized state layout changed unexpectedly")


def validate_state_directory(path: Path, *, allow_missing: bool = False) -> None:
    """Validate an existing managed directory without following symlinks."""

    path_stat = _lstat(path, allow_missing=allow_missing)
    if path_stat is None:
        return
    if stat.S_ISLNK(path_stat.st_mode):
        raise UnsafePathError(f"managed state path is a symbolic link: {path}")
    if not stat.S_ISDIR(path_stat.st_mode):
        raise UnsafePathError(f"managed state directory has the wrong type: {path}")
    _validate_owner_and_mode(path, path_stat, _DIRECTORY_MODE)


def validate_state_file(path: Path, *, allow_missing: bool = False) -> None:
    """Validate an existing owner-only regular state file."""

    path_stat = _lstat(path, allow_missing=allow_missing)
    if path_stat is None:
        return
    if stat.S_ISLNK(path_stat.st_mode):
        raise UnsafePathError(f"managed state path is a symbolic link: {path}")
    if not stat.S_ISREG(path_stat.st_mode):
        raise UnsafePathError(f"managed state file has the wrong type: {path}")
    if path_stat.st_nlink != 1:
        raise UnsafePathError(f"managed state file has unexpected hard links: {path}")
    _validate_owner_and_mode(path, path_stat, _FILE_MODE)


def find_unexpected_terraform_state(
    paths: StatePaths, candidate_roots: tuple[Path, ...]
) -> tuple[Path, ...]:
    """Return exact unexpected local state/backend metadata paths, without reading."""

    canonical_allowed = {
        paths.terraform_state,
        paths.terraform_data / "terraform.tfstate",
        paths.terraform_data / "environment",
    }
    found: set[Path] = set()
    for root in candidate_roots:
        if not root.is_absolute():
            raise ConfigurationError(
                "unexpected-state candidate roots must be absolute"
            )
        _reject_existing_symlink_components(root)
        candidate_root = root.resolve(strict=False)
        for candidate in (
            candidate_root / "terraform.tfstate",
            candidate_root / ".terraform" / "terraform.tfstate",
            candidate_root / ".terraform" / "environment",
            candidate_root / "terraform" / "terraform.tfstate",
            candidate_root / "terraform" / ".terraform" / "terraform.tfstate",
            candidate_root / "terraform" / ".terraform" / "environment",
        ):
            if candidate in canonical_allowed:
                continue
            _reject_existing_symlink_components(candidate)
            path_stat = _lstat(candidate, allow_missing=True)
            if path_stat is not None:
                if stat.S_ISLNK(path_stat.st_mode):
                    raise UnsafePathError(
                        f"unexpected state candidate is a symbolic link: {candidate}"
                    )
                found.add(candidate)
    return tuple(sorted(found))


def refuse_unexpected_terraform_state(
    paths: StatePaths, candidate_roots: tuple[Path, ...]
) -> None:
    """Refuse a second or ambiguous Terraform state/backend location."""

    conflicts = find_unexpected_terraform_state(paths, candidate_roots)
    if conflicts:
        locations = ", ".join(str(path) for path in conflicts)
        raise StateConflictError(f"unexpected Terraform state metadata: {locations}")


def _validate_containment(path: Path, root: Path, cluster_root: Path) -> None:
    if not path.is_absolute() or not path.is_relative_to(root):
        raise UnsafePathError("derived state path escapes the state root")
    if path not in {root, root / "clusters"} and not path.is_relative_to(cluster_root):
        raise UnsafePathError("derived state path escapes the cluster root")
    if path.resolve(strict=False) != path:
        raise UnsafePathError(f"managed state path resolves unexpectedly: {path}")


def _reject_existing_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        path_stat = _lstat(current, allow_missing=True)
        if path_stat is None:
            break
        if stat.S_ISLNK(path_stat.st_mode):
            raise UnsafePathError(f"state path component is a symbolic link: {current}")


def _lstat(path: Path, *, allow_missing: bool) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        if allow_missing:
            return None
        raise UnsafePathError(f"required state path does not exist: {path}") from None
    except OSError as error:
        raise UnsafePathError(f"cannot inspect managed state path: {path}") from error


def _validate_owner_and_mode(
    path: Path, path_stat: os.stat_result, required_mode: int
) -> None:
    if os.name != "posix":
        return
    getuid = getattr(os, "geteuid", None)
    if getuid is not None and path_stat.st_uid != getuid():
        raise UnsafePathError(f"state path is not owned by the current user: {path}")
    if stat.S_IMODE(path_stat.st_mode) != required_mode:
        raise UnsafePathError(
            f"state path permissions must be {required_mode:04o}: {path}"
        )


def _validate_parent_directory(path: Path) -> None:
    path_stat = _lstat(path, allow_missing=True)
    if path_stat is None:
        raise UnsafePathError("state root parent directory does not exist")
    if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISDIR(path_stat.st_mode):
        raise UnsafePathError("state root parent must be a non-symlink directory")


def _supports_secure_dir_fd() -> bool:
    return (
        os.name == "posix"
        and hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and os.mkdir in os.supports_dir_fd
        and os.open in os.supports_dir_fd
    )


def _initialize_posix(paths: StatePaths, parent: Path) -> None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors: dict[Path, int] = {}
    try:
        descriptors[parent] = os.open(parent, flags)
        _require_open_directory_path(parent, descriptors[parent])
        for directory in paths.directory_paths:
            parent_fd = descriptors[directory.parent]
            created = False
            try:
                os.mkdir(directory.name, _DIRECTORY_MODE, dir_fd=parent_fd)
                created = True
            except FileExistsError:
                pass
            try:
                descriptor = os.open(directory.name, flags, dir_fd=parent_fd)
            except OSError as error:
                raise UnsafePathError(
                    f"cannot safely open state directory: {directory}"
                ) from error
            descriptors[directory] = descriptor
            if created:
                os.fchmod(descriptor, _DIRECTORY_MODE)
            _validate_open_directory(directory, descriptor)
            _require_open_directory_path(directory, descriptor)
        for directory, descriptor in descriptors.items():
            _require_open_directory_path(directory, descriptor)
    finally:
        for descriptor in reversed(tuple(descriptors.values())):
            os.close(descriptor)


def _initialize_portable(paths: StatePaths) -> None:
    for directory in paths.directory_paths:
        created = False
        try:
            directory.mkdir(mode=_DIRECTORY_MODE)
            created = True
        except FileExistsError:
            pass
        if created:
            directory.chmod(_DIRECTORY_MODE)
        validate_state_directory(directory)


def _validate_open_directory(path: Path, descriptor: int) -> None:
    path_stat = os.fstat(descriptor)
    if not stat.S_ISDIR(path_stat.st_mode):
        raise UnsafePathError(f"managed state directory has the wrong type: {path}")
    _validate_owner_and_mode(path, path_stat, _DIRECTORY_MODE)


def _require_open_directory_path(path: Path, descriptor: int) -> None:
    try:
        named_stat = path.lstat()
    except OSError as error:
        raise UnsafePathError(
            "state directory changed during initialization"
        ) from error
    opened_stat = os.fstat(descriptor)
    if stat.S_ISLNK(named_stat.st_mode) or (
        named_stat.st_dev,
        named_stat.st_ino,
    ) != (opened_stat.st_dev, opened_stat.st_ino):
        raise UnsafePathError("state directory changed during initialization")
