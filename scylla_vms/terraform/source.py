"""Approved Terraform source bundles and tamper-safe canonical staging."""

import hashlib
import importlib.resources
import json
import os
import re
import shutil
import stat
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, cast

from scylla_vms.errors import ConfigurationError, StatePersistenceError, UnsafePathError
from scylla_vms.persistence import (
    AtomicJsonFile,
    format_timestamp,
    parse_timestamp,
    parse_uuid,
    require_exact_keys,
    require_string,
    validate_digest,
)
from scylla_vms.state import (
    StatePaths,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)

if TYPE_CHECKING:
    from scylla_vms.locking import ClusterLock

TERRAFORM_SOURCE_RECORD_SCHEMA_VERSION = "deploy-scylla-vms.terraform-source/v1"
PRODUCTION_OCI_SOURCE_VERSION = "oci-root/v3"
_PRODUCTION_OCI_SOURCE_HASHES = {
    ".terraform.lock.hcl": "sha256:c4e3414520192ae8a2ba638654c9d7caf6a6f17e972971e2d37203d3656c0f40",
    "compute.tf": "sha256:563f532257c70e888394ba198f5c2a28fadcc2b125b2fbe9c8d99f2c783fe6e0",
    "images.tf": "sha256:d18f96e44d9843e3513f230af1956b79117b88c330018c03c7df1229f93de3d9",
    "network.tf": "sha256:1feb1f98382ebf5a2c8771788585679502380caa23a2a4bd0ff1f457f6b425f3",
    "outputs.tf": "sha256:91b3b22fd1bc528ddffad4fe3273d13f78c4037b3a4e97f764076cbf4360b19c",
    "security.tf": "sha256:fb336ed421f9c6d9acee028f377cbfb18d6fe9fd480069347977a75bdceaff56",
    "storage.tf": "sha256:b5205ceaeb735a3aa48ee93ed524afed8e6c5ea767d73817215048c04c3a9d9f",
    "variables.tf": "sha256:b1616f808f8584b9834c7bcaac092485d680229d69c5a016b1958854295e62c8",
    "versions.tf": "sha256:76a8751271c8f49bfeafeb3cd8ed8d53f932d99f6fba2e8afa2dd92f82e7b92f",
}
_SOURCE_VERSION = re.compile(r"oci-root/v([1-9][0-9]*)\Z")
_FILE_MODE = 0o600
_DIRECTORY_MODE = 0o700
_TFVARS_NAME = "cluster.auto.tfvars.json"
_MAXIMUM_SOURCE_FILE_BYTES = 1024 * 1024
_MAXIMUM_SOURCE_BUNDLE_BYTES = 4 * 1024 * 1024
_SECRET_SOURCE = re.compile(
    rb"(?i)(?:private[_-]?key|password|passphrase|secret|token)"
)


@dataclass(frozen=True, slots=True)
class ApprovedSourceFile:
    path: str
    content: bytes
    digest: str

    def __post_init__(self) -> None:
        pure = PurePosixPath(self.path)
        is_lock_file = self.path == ".terraform.lock.hcl"
        if (
            not self.path
            or pure.is_absolute()
            or ".." in pure.parts
            or "." in pure.parts
            or (
                not is_lock_file
                and any(not part or part.startswith(".") for part in pure.parts)
            )
            or not (
                self.path.endswith(".tf")
                or self.path.endswith(".tf.json")
                or is_lock_file
            )
        ):
            raise StatePersistenceError("approved Terraform source path is invalid")
        if (
            not isinstance(self.content, bytes)
            or not self.content
            or len(self.content) > _MAXIMUM_SOURCE_FILE_BYTES
        ):
            raise StatePersistenceError("approved Terraform source content is empty")
        if b"\x00" in self.content:
            raise StatePersistenceError("approved Terraform source contains NUL")
        if _SECRET_SOURCE.search(self.content):
            raise StatePersistenceError(
                "approved Terraform source contains secret-like material"
            )
        try:
            self.content.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise StatePersistenceError(
                "approved Terraform source is not UTF-8"
            ) from error
        validate_digest(self.digest, "approved Terraform source digest")
        if self.digest != _digest(self.content):
            raise StatePersistenceError("approved Terraform source digest conflicts")


@dataclass(frozen=True, slots=True)
class ApprovedSourceBundle:
    """Immutable reviewed bytes and their deterministic source manifest."""

    version: str
    files: tuple[ApprovedSourceFile, ...]
    planning_ready: bool
    digest: str

    def __post_init__(self) -> None:
        if _version_number(self.version) < 1:
            raise StatePersistenceError("approved Terraform source version is invalid")
        paths = tuple(file.path for file in self.files)
        if (
            not paths
            or paths != tuple(sorted(set(paths)))
            or not any(path.endswith((".tf", ".tf.json")) for path in paths)
            or sum(len(file.content) for file in self.files)
            > _MAXIMUM_SOURCE_BUNDLE_BYTES
            or not isinstance(self.planning_ready, bool)
        ):
            raise StatePersistenceError("approved Terraform source files are invalid")
        validate_digest(self.digest, "approved Terraform source bundle digest")
        if self.digest != _bundle_digest(self.version, self.files, self.planning_ready):
            raise StatePersistenceError(
                "approved Terraform source bundle digest conflicts"
            )

    @classmethod
    def build(
        cls,
        *,
        version: str,
        files: Mapping[str, bytes],
        planning_ready: bool,
    ) -> "ApprovedSourceBundle":
        source_files = tuple(
            ApprovedSourceFile(path, files[path], _digest(files[path]))
            for path in sorted(files)
        )
        return cls(
            version,
            source_files,
            planning_ready,
            _bundle_digest(version, source_files, planning_ready),
        )


def load_production_oci_source_bundle() -> ApprovedSourceBundle:
    """Load the active OCI root and verify its logical immutable bundle identity."""

    root = importlib.resources.files("scylla_vms.terraform").joinpath(
        "bundles", "oci_root"
    )
    files: dict[str, bytes] = {}
    for name, expected_digest in _PRODUCTION_OCI_SOURCE_HASHES.items():
        resource = root.joinpath(name)
        if not resource.is_file():
            raise StatePersistenceError(
                f"packaged Terraform source file is unavailable: {name}"
            )
        content = resource.read_bytes()
        if _digest(content) != expected_digest:
            raise StatePersistenceError(
                f"packaged Terraform source hash conflicts: {name}"
            )
        files[name] = content
    unexpected = tuple(
        sorted(
            entry.name
            for entry in root.iterdir()
            if entry.is_file() and entry.name not in _PRODUCTION_OCI_SOURCE_HASHES
        )
    )
    if unexpected:
        raise StatePersistenceError(
            "packaged Terraform source contains unexpected files"
        )
    return ApprovedSourceBundle.build(
        version=PRODUCTION_OCI_SOURCE_VERSION,
        files=files,
        planning_ready=True,
    )


@dataclass(frozen=True, slots=True)
class TerraformSourceRecord:
    generation: int
    cluster_uuid: uuid.UUID
    cluster_name: str
    provider: str
    staged_at: str
    source_version: str
    bundle_digest: str
    planning_ready: bool
    file_hashes: tuple[tuple[str, str], ...]
    schema_version: str = TERRAFORM_SOURCE_RECORD_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != TERRAFORM_SOURCE_RECORD_SCHEMA_VERSION:
            raise StatePersistenceError("unsupported Terraform source record schema")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 1
        ):
            raise StatePersistenceError("Terraform source generation must be positive")
        if not isinstance(self.cluster_uuid, uuid.UUID) or self.provider != "oci":
            raise StatePersistenceError("Terraform source identity is invalid")
        try:
            validate_cluster_name(self.cluster_name)
        except ConfigurationError as error:
            raise StatePersistenceError(
                "Terraform source cluster name is invalid"
            ) from error
        parse_timestamp(self.staged_at)
        _version_number(self.source_version)
        validate_digest(self.bundle_digest, "Terraform source bundle digest")
        if not isinstance(self.planning_ready, bool):
            raise StatePersistenceError("Terraform planning readiness is invalid")
        paths = tuple(path for path, _ in self.file_hashes)
        if not paths or paths != tuple(sorted(set(paths))):
            raise StatePersistenceError("Terraform source file hashes are invalid")
        for path, digest in self.file_hashes:
            ApprovedSourceFile(path, b"x", _digest(b"x"))
            validate_digest(digest, "Terraform source file digest")
        if self.bundle_digest != _source_manifest_digest(
            self.source_version, self.file_hashes, self.planning_ready
        ):
            raise StatePersistenceError("Terraform source record digest conflicts")

    def to_object(self) -> dict[str, object]:
        return {
            "bundle_digest": self.bundle_digest,
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "file_hashes": dict(self.file_hashes),
            "generation": self.generation,
            "planning_ready": self.planning_ready,
            "provider": self.provider,
            "schema_version": self.schema_version,
            "source_version": self.source_version,
            "staged_at": self.staged_at,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> "TerraformSourceRecord":
        require_exact_keys(
            value,
            {
                "bundle_digest",
                "cluster_name",
                "cluster_uuid",
                "file_hashes",
                "generation",
                "planning_ready",
                "provider",
                "schema_version",
                "source_version",
                "staged_at",
            },
            "Terraform source record",
        )
        generation = value["generation"]
        planning_ready = value["planning_ready"]
        hashes = value["file_hashes"]
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise StatePersistenceError(
                "Terraform source generation must be an integer"
            )
        if not isinstance(planning_ready, bool):
            raise StatePersistenceError("Terraform planning readiness must be boolean")
        if not isinstance(hashes, dict) or not all(
            isinstance(path, str) and isinstance(digest, str)
            for path, digest in hashes.items()
        ):
            raise StatePersistenceError("Terraform source hashes must be a string map")
        return cls(
            generation,
            parse_uuid(
                require_string(value, "cluster_uuid"), "Terraform source cluster UUID"
            ),
            require_string(value, "cluster_name"),
            require_string(value, "provider"),
            require_string(value, "staged_at"),
            require_string(value, "source_version"),
            require_string(value, "bundle_digest"),
            planning_ready,
            tuple(sorted(cast(dict[str, str], hashes).items())),
            require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredTerraformSource:
    record: TerraformSourceRecord
    digest: str


class TerraformSourceStore:
    def __init__(
        self,
        paths: StatePaths,
        *,
        replace: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self._paths = paths
        self._file = AtomicJsonFile(
            paths.terraform_source_record,
            replace=replace,
            token_factory=token_factory,
        )

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredTerraformSource:
        value, digest = self._file.read()
        record = TerraformSourceRecord.from_object(value)
        if (
            record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError("persisted Terraform source identity conflicts")
        return StoredTerraformSource(record, digest)

    def _write(
        self,
        record: TerraformSourceRecord,
        *,
        expected_generation: int,
        expected_digest: str | None,
    ) -> StoredTerraformSource:
        validate_state_file(self._paths.terraform_source_record, allow_missing=True)
        exists = self._paths.terraform_source_record.exists()
        if not exists:
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial Terraform source write requires generation one"
                )
        else:
            current = self.read(
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if (
                expected_digest is None
                or current.digest != expected_digest
                or current.record.generation != expected_generation
            ):
                raise StatePersistenceError("Terraform source changed concurrently")
            if record.generation != current.record.generation + 1:
                raise StatePersistenceError(
                    "Terraform source generation must increase by exactly one"
                )
            if parse_timestamp(record.staged_at) < parse_timestamp(
                current.record.staged_at
            ):
                raise StatePersistenceError("Terraform source timestamp regressed")
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredTerraformSource(record, digest)


class TerraformSourceStager:
    """Stage one complete source tree and record, rolling back on failure."""

    def __init__(
        self,
        paths: StatePaths,
        *,
        store: TerraformSourceStore | None = None,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self._paths = paths
        self._store = store or TerraformSourceStore(paths)
        self._token_factory = token_factory or (lambda: uuid.uuid4().hex)

    def stage_locked(
        self,
        bundle: ApprovedSourceBundle,
        *,
        cluster_uuid: uuid.UUID,
        cluster_name: str,
        clock: Callable[[], datetime],
        lock: "ClusterLock",
    ) -> StoredTerraformSource:
        lock.assert_held_for(self._paths)
        validate_state_directory(self._paths.terraform)
        validate_state_directory(self._paths.terraform_work)
        validate_state_file(self._paths.terraform_source_record, allow_missing=True)
        _refuse_incomplete_staging(self._paths.terraform)
        if self._paths.terraform_tfvars.exists():
            from scylla_vms.terraform.inputs import TerraformInputStore

            TerraformInputStore(self._paths).read(
                expected_cluster_uuid=cluster_uuid,
                expected_cluster_name=cluster_name,
                expected_provider="oci",
            )
        current = self._read_current(cluster_uuid, cluster_name)
        if current is not None:
            _validate_work_tree(self._paths, current.record)
            if (
                current.record.source_version == bundle.version
                and current.record.bundle_digest == bundle.digest
                and current.record.planning_ready == bundle.planning_ready
            ):
                return current
            if _version_number(bundle.version) < _version_number(
                current.record.source_version
            ):
                raise StatePersistenceError(
                    "Terraform source version downgrade refused"
                )
        else:
            _validate_empty_initial_work(self._paths)
        _refuse_active_terraform_data(self._paths)
        token = self._token_factory()
        if not token or not token.isascii() or not token.isalnum():
            raise StatePersistenceError("Terraform staging token is invalid")
        candidate = self._paths.terraform / f".work-stage-{token}"
        backup = self._paths.terraform / f".work-backup-{token}"
        if candidate.exists() or backup.exists():
            raise StatePersistenceError("Terraform staging path already exists")
        record = TerraformSourceRecord(
            1 if current is None else current.record.generation + 1,
            cluster_uuid,
            cluster_name,
            "oci",
            format_timestamp(clock()),
            bundle.version,
            bundle.digest,
            bundle.planning_ready,
            tuple((file.path, file.digest) for file in bundle.files),
        )
        swapped = False
        try:
            _write_candidate(candidate, bundle, self._paths.terraform_tfvars)
            os.rename(self._paths.terraform_work, backup)
            try:
                os.rename(candidate, self._paths.terraform_work)
                swapped = True
            except OSError:
                os.rename(backup, self._paths.terraform_work)
                raise
            stored = self._store._write(
                record,
                expected_generation=0 if current is None else current.record.generation,
                expected_digest=None if current is None else current.digest,
            )
            swapped = False
            with suppress(OSError):
                shutil.rmtree(backup)
            return stored
        except OSError as error:
            raise StatePersistenceError("Terraform source staging failed") from error
        finally:
            if swapped:
                failed = self._paths.terraform / f".work-failed-{token}"
                with suppress(OSError):
                    os.rename(self._paths.terraform_work, failed)
                    os.rename(backup, self._paths.terraform_work)
                    shutil.rmtree(failed)
            for path in (candidate, backup):
                if path.exists():
                    with suppress(OSError):
                        shutil.rmtree(path)

    def _read_current(
        self, cluster_uuid: uuid.UUID, cluster_name: str
    ) -> StoredTerraformSource | None:
        if not self._paths.terraform_source_record.exists():
            return None
        return self._store.read(
            expected_cluster_uuid=cluster_uuid,
            expected_cluster_name=cluster_name,
        )


def validate_staged_source(
    paths: StatePaths, stored: StoredTerraformSource
) -> TerraformSourceRecord:
    """Revalidate a stored record against exact canonical work-tree bytes."""

    if (
        stored.record.cluster_name != paths.cluster_root.name
        or stored.record.provider != "oci"
    ):
        raise StatePersistenceError("staged Terraform source identity conflicts")
    _validate_work_tree(paths, stored.record)
    return stored.record


def _write_candidate(
    candidate: Path, bundle: ApprovedSourceBundle, tfvars_path: Path
) -> None:
    candidate.mkdir(mode=_DIRECTORY_MODE)
    for source in bundle.files:
        target = candidate.joinpath(*PurePosixPath(source.path).parts)
        target.parent.mkdir(mode=_DIRECTORY_MODE, parents=True, exist_ok=True)
        _write_file(target, source.content)
    if tfvars_path.exists():
        validate_state_file(tfvars_path)
        _write_file(candidate / _TFVARS_NAME, _read_secure_file(tfvars_path))
    _validate_candidate(candidate, bundle)


def _write_file(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        _FILE_MODE,
    )
    try:
        os.fchmod(descriptor, _FILE_MODE)
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written == 0:
                raise StatePersistenceError("Terraform source write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_candidate(candidate: Path, bundle: ApprovedSourceBundle) -> None:
    actual = _tree_files(candidate)
    expected = {source.path: source.digest for source in bundle.files}
    if (candidate / _TFVARS_NAME).exists():
        expected[_TFVARS_NAME] = _digest(_read_secure_file(candidate / _TFVARS_NAME))
    if actual != expected:
        raise StatePersistenceError("staged Terraform source hashes conflict")


def _validate_work_tree(paths: StatePaths, record: TerraformSourceRecord) -> None:
    actual = _tree_files(paths.terraform_work)
    expected = dict(record.file_hashes)
    if paths.terraform_tfvars.exists():
        validate_state_file(paths.terraform_tfvars)
        expected[_TFVARS_NAME] = _digest(_read_secure_file(paths.terraform_tfvars))
    if actual != expected:
        raise StatePersistenceError(
            "staged Terraform source is tampered or contains unexpected files"
        )


def _validate_empty_initial_work(paths: StatePaths) -> None:
    actual = _tree_files(paths.terraform_work)
    allowed = {_TFVARS_NAME} if paths.terraform_tfvars.exists() else set()
    if set(actual) != allowed:
        raise StatePersistenceError(
            "initial Terraform work directory contains unexpected files"
        )


def _tree_files(root: Path) -> dict[str, str]:
    validate_state_directory(root)
    result: dict[str, str] = {}
    total = 0
    for entry in sorted(root.rglob("*")):
        relative = entry.relative_to(root).as_posix()
        metadata = entry.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise UnsafePathError("Terraform source tree contains a symbolic link")
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_IMODE(metadata.st_mode) != _DIRECTORY_MODE:
                raise UnsafePathError(
                    "Terraform source directory permissions must be 0700"
                )
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != _FILE_MODE
        ):
            raise UnsafePathError(
                "Terraform source must contain owner-only singly linked files"
            )
        content = _read_secure_file(entry)
        total += len(content)
        if total > _MAXIMUM_SOURCE_BUNDLE_BYTES + _MAXIMUM_SOURCE_FILE_BYTES:
            raise StatePersistenceError("Terraform source tree exceeds the size limit")
        result[relative] = _digest(content)
    return result


def _read_secure_file(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        named = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            or stat.S_IMODE(opened.st_mode) != _FILE_MODE
        ):
            raise UnsafePathError("Terraform staged source changed during access")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 65536):
            total += len(chunk)
            if total > _MAXIMUM_SOURCE_FILE_BYTES:
                raise StatePersistenceError(
                    "Terraform staged file exceeds the size limit"
                )
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _refuse_active_terraform_data(paths: StatePaths) -> None:
    validate_state_file(paths.terraform_state, allow_missing=True)
    if paths.terraform_state.exists():
        raise StatePersistenceError("Terraform source change refused with active state")
    for directory in (paths.terraform_data, paths.terraform_plugin_cache):
        validate_state_directory(directory)
        if any(directory.iterdir()):
            raise StatePersistenceError(
                "Terraform source change refused with active backend/provider data"
            )


def _refuse_incomplete_staging(terraform: Path) -> None:
    for entry in terraform.iterdir():
        if entry.name.startswith((".work-stage-", ".work-backup-", ".work-failed-")):
            raise StatePersistenceError(
                "incomplete Terraform source staging artifact requires recovery"
            )


def _version_number(value: str) -> int:
    match = _SOURCE_VERSION.fullmatch(value)
    if match is None:
        raise StatePersistenceError("Terraform source version is invalid")
    return int(match.group(1))


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _bundle_digest(
    version: str, files: tuple[ApprovedSourceFile, ...], planning_ready: bool
) -> str:
    return _source_manifest_digest(
        version,
        tuple((file.path, file.digest) for file in files),
        planning_ready,
    )


def _source_manifest_digest(
    version: str, file_hashes: tuple[tuple[str, str], ...], planning_ready: bool
) -> str:
    encoded = json.dumps(
        {
            "files": dict(file_hashes),
            "planning_ready": planning_ready,
            "version": version,
        },
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _digest(encoded)
