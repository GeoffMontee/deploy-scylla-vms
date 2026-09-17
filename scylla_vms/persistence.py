"""Strict versioned metadata and durable owner-only JSON persistence."""

import errno
import hashlib
import json
import os
import re
import stat
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, cast

from scylla_vms.desired import ClusterSpec
from scylla_vms.errors import (
    ConfigurationError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.providers import get_provider
from scylla_vms.state import (
    StatePaths,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)

if TYPE_CHECKING:
    from scylla_vms.locking import ClusterLock

CLUSTER_SCHEMA_VERSION = "deploy-scylla-vms.cluster/v2"
_FILE_MODE = 0o600
_MAX_JSON_BYTES = 1024 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class MetadataSource(StrEnum):
    """Allowed source for creation of a persisted cluster identity."""

    INITIAL_REQUEST = "initial-request"


@dataclass(frozen=True, slots=True)
class RecordProvenance:
    """Non-secret provenance binding a record to a sanitized request digest."""

    source: MetadataSource
    request_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.source, MetadataSource):
            raise StatePersistenceError("invalid cluster metadata provenance source")
        validate_digest(self.request_digest, "request digest")


@dataclass(frozen=True, slots=True)
class ClusterMetadata:
    """Durable identity and complete desired-cluster specification envelope."""

    generation: int
    cluster_uuid: uuid.UUID
    cluster_name: str
    provider: str
    created_at: str
    updated_at: str
    provenance: RecordProvenance
    desired_spec: ClusterSpec
    schema_version: str = CLUSTER_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != CLUSTER_SCHEMA_VERSION:
            raise StatePersistenceError("unsupported cluster metadata schema version")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 1
        ):
            raise StatePersistenceError("cluster metadata generation must be positive")
        if not isinstance(self.cluster_uuid, uuid.UUID):
            raise StatePersistenceError("cluster UUID must be a UUID")
        try:
            validate_cluster_name(self.cluster_name)
        except ConfigurationError as error:
            raise StatePersistenceError("persisted cluster name is invalid") from error
        if not isinstance(self.provider, str):
            raise StatePersistenceError("persisted provider must be a string")
        if not isinstance(self.provenance, RecordProvenance):
            raise StatePersistenceError("cluster metadata provenance is invalid")
        if not isinstance(self.desired_spec, ClusterSpec):
            raise StatePersistenceError("persisted desired cluster is invalid")
        if (
            self.desired_spec.cluster_uuid != self.cluster_uuid
            or self.desired_spec.cluster_name != self.cluster_name
            or self.desired_spec.provider != self.provider
        ):
            raise StatePersistenceError(
                "persisted desired cluster identity does not match its envelope"
            )
        try:
            get_provider(self.provider)
        except KeyError as error:
            raise StatePersistenceError("unsupported persisted provider") from error
        if not isinstance(self.created_at, str) or not isinstance(self.updated_at, str):
            raise StatePersistenceError("persisted timestamps must be strings")
        created = parse_timestamp(self.created_at)
        updated = parse_timestamp(self.updated_at)
        if updated < created:
            raise StatePersistenceError("cluster metadata timestamp regressed")

    @classmethod
    def create(
        cls,
        *,
        cluster_uuid: uuid.UUID,
        cluster_name: str,
        provider: str,
        request_digest: str,
        desired_spec: ClusterSpec,
        clock: Callable[[], datetime],
    ) -> "ClusterMetadata":
        """Create generation one using an injected UTC clock."""

        timestamp = format_timestamp(clock())
        return cls(
            generation=1,
            cluster_uuid=cluster_uuid,
            cluster_name=cluster_name,
            provider=provider,
            created_at=timestamp,
            updated_at=timestamp,
            provenance=RecordProvenance(MetadataSource.INITIAL_REQUEST, request_digest),
            desired_spec=desired_spec,
        )

    def next_generation(
        self,
        *,
        clock: Callable[[], datetime],
        desired_spec: ClusterSpec | None = None,
    ) -> "ClusterMetadata":
        """Return the next identity-preserving generation."""

        return ClusterMetadata(
            generation=self.generation + 1,
            cluster_uuid=self.cluster_uuid,
            cluster_name=self.cluster_name,
            provider=self.provider,
            created_at=self.created_at,
            updated_at=format_timestamp(clock()),
            provenance=self.provenance,
            desired_spec=desired_spec or self.desired_spec,
        )

    def to_object(self) -> dict[str, object]:
        """Return the strict deterministic JSON object."""

        return {
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "created_at": self.created_at,
            "desired_spec": self.desired_spec.to_object(),
            "generation": self.generation,
            "provenance": {
                "request_digest": self.provenance.request_digest,
                "source": self.provenance.source.value,
            },
            "provider": self.provider,
            "schema_version": self.schema_version,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> "ClusterMetadata":
        """Parse an exact schema, rejecting missing and unknown fields."""

        require_exact_keys(
            value,
            {
                "cluster_name",
                "cluster_uuid",
                "created_at",
                "desired_spec",
                "generation",
                "provenance",
                "provider",
                "schema_version",
                "updated_at",
            },
            "cluster metadata",
        )
        schema_version = require_string(value, "schema_version")
        if schema_version != CLUSTER_SCHEMA_VERSION:
            raise StatePersistenceError("unsupported cluster metadata schema version")
        generation = value["generation"]
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise StatePersistenceError(
                "cluster metadata generation must be an integer"
            )
        cluster_uuid = parse_uuid(require_string(value, "cluster_uuid"), "cluster UUID")
        provenance_value = value["provenance"]
        if not isinstance(provenance_value, dict):
            raise StatePersistenceError("cluster metadata provenance must be an object")
        provenance = cast(dict[str, object], provenance_value)
        require_exact_keys(
            provenance, {"request_digest", "source"}, "cluster metadata provenance"
        )
        try:
            source = MetadataSource(require_string(provenance, "source"))
        except ValueError as error:
            raise StatePersistenceError(
                "unsupported cluster metadata provenance source"
            ) from error
        desired_value = value["desired_spec"]
        if not isinstance(desired_value, dict):
            raise StatePersistenceError("persisted desired cluster must be an object")
        try:
            desired_spec = ClusterSpec.from_object(
                cast(dict[str, object], desired_value)
            )
        except ConfigurationError as error:
            raise StatePersistenceError(
                "persisted desired cluster is invalid"
            ) from error
        return cls(
            generation=generation,
            cluster_uuid=cluster_uuid,
            cluster_name=require_string(value, "cluster_name"),
            provider=require_string(value, "provider"),
            created_at=require_string(value, "created_at"),
            updated_at=require_string(value, "updated_at"),
            provenance=RecordProvenance(
                source, require_string(provenance, "request_digest")
            ),
            desired_spec=desired_spec,
            schema_version=schema_version,
        )


@dataclass(frozen=True, slots=True)
class StoredClusterMetadata:
    """A validated record and the digest required for a safe next write."""

    record: ClusterMetadata
    digest: str


class ClusterMetadataStore:
    """Read and atomically update one canonical cluster metadata file."""

    def __init__(
        self,
        paths: StatePaths,
        *,
        replace: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self._paths = paths
        self._file = AtomicJsonFile(
            paths.cluster_metadata,
            replace=replace,
            token_factory=token_factory,
        )

    def read(
        self,
        *,
        expected_cluster_name: str,
        expected_cluster_uuid: uuid.UUID | None = None,
        expected_provider: str | None = None,
    ) -> StoredClusterMetadata:
        """Read and identity-check canonical cluster metadata."""

        value, digest = self._file.read()
        record = ClusterMetadata.from_object(value)
        if record.cluster_name != expected_cluster_name:
            raise StatePersistenceError("persisted cluster name does not match request")
        if (
            expected_cluster_uuid is not None
            and record.cluster_uuid != expected_cluster_uuid
        ):
            raise StatePersistenceError("persisted cluster UUID does not match request")
        if expected_provider is not None and record.provider != expected_provider:
            raise StatePersistenceError("persisted provider does not match request")
        return StoredClusterMetadata(record, digest)

    def write(
        self,
        record: ClusterMetadata,
        *,
        expected_generation: int,
        expected_digest: str | None,
    ) -> StoredClusterMetadata:
        """Create or update one generation with explicit lost-update guards."""

        validate_state_directory(self._paths.cluster_root)
        validate_state_file(self._paths.cluster_metadata, allow_missing=True)
        exists = self._paths.cluster_metadata.exists()
        if not exists:
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial cluster metadata write requires generation one"
                )
        else:
            current_value, current_digest = self._file.read()
            current = ClusterMetadata.from_object(current_value)
            if expected_digest is None:
                raise StatePersistenceError(
                    "metadata update requires the expected prior digest"
                )
            if (
                current.generation != expected_generation
                or current_digest != expected_digest
            ):
                raise StatePersistenceError("cluster metadata changed concurrently")
            if record.generation != current.generation + 1:
                raise StatePersistenceError(
                    "cluster metadata generation must increase by exactly one"
                )
            if (
                record.cluster_uuid != current.cluster_uuid
                or record.cluster_name != current.cluster_name
                or record.provider != current.provider
                or record.created_at != current.created_at
            ):
                raise StatePersistenceError(
                    "cluster metadata identity fields are immutable"
                )
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredClusterMetadata(record, digest)

    def write_locked(
        self,
        record: ClusterMetadata,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: "ClusterLock",
    ) -> StoredClusterMetadata:
        """Write only after proving the matching cluster lock is already held."""

        from scylla_vms.locking import ClusterLock

        if not isinstance(lock, ClusterLock):
            raise StatePersistenceError(
                "cluster metadata write requires an acquired cluster lock"
            )
        lock.assert_held_for(self._paths)
        return self.write(
            record,
            expected_generation=expected_generation,
            expected_digest=expected_digest,
        )


class AtomicJsonFile:
    """Owner-only deterministic JSON with fsync and same-directory replace."""

    def __init__(
        self,
        path: Path,
        *,
        replace: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self._path = path
        self._replace = replace
        self._token_factory = token_factory or (lambda: uuid.uuid4().hex)

    def read(self) -> tuple[dict[str, object], str]:
        """Safely read one strict JSON object and return its byte digest."""

        validate_state_directory(self._path.parent)
        encoded = _read_bytes(self._path)
        try:
            decoded = encoded.decode("utf-8")
        except UnicodeDecodeError as error:
            raise StatePersistenceError("persisted state is not valid UTF-8") from error
        try:
            value = json.loads(decoded, object_pairs_hook=_strict_object)
        except json.JSONDecodeError as error:
            raise StatePersistenceError(
                "persisted state contains invalid JSON"
            ) from error
        if not isinstance(value, dict):
            raise StatePersistenceError("persisted state must contain a JSON object")
        return cast(dict[str, object], value), digest_bytes(encoded)

    def write(self, value: Mapping[str, object], *, expected_digest: str | None) -> str:
        """Durably replace JSON if the existing byte digest still matches."""

        validate_state_directory(self._path.parent)
        validate_state_file(self._path, allow_missing=True)
        _check_expected_digest(self._path, expected_digest)
        encoded = serialize_json(value)
        token = self._token_factory()
        if not token or not token.isascii() or not token.isalnum():
            raise StatePersistenceError("temporary-file token is invalid")
        temporary = self._path.with_name(f".{self._path.name}.{token}.tmp")
        descriptor: int | None = None
        created = False
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(temporary, flags, _FILE_MODE)
            created = True
            if os.name == "posix":
                os.fchmod(descriptor, _FILE_MODE)
            _write_all(descriptor, encoded)
            os.fsync(descriptor)
            validate_state_file(temporary)
            _require_same_inode(temporary, os.fstat(descriptor))
            _check_expected_digest(self._path, expected_digest)
            if expected_digest is None and os.name == "posix":
                try:
                    os.link(temporary, self._path, follow_symlinks=False)
                except FileExistsError as error:
                    raise StatePersistenceError(
                        "persisted state appeared before initial creation"
                    ) from error
                temporary.unlink()
                created = False
            else:
                self._replace(temporary, self._path)
                created = False
            validate_state_file(self._path)
            _require_same_inode(self._path, os.fstat(descriptor))
            os.close(descriptor)
            descriptor = None
            _fsync_directory(self._path.parent)
        except FileExistsError as error:
            raise StatePersistenceError(
                "secure temporary state file already exists"
            ) from error
        except OSError as error:
            raise StatePersistenceError("atomic state write failed") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if created:
                with suppress(FileNotFoundError):
                    temporary.unlink()
        return digest_bytes(encoded)


def serialize_json(value: Mapping[str, object]) -> bytes:
    """Serialize deterministic UTF-8 JSON with one trailing newline."""

    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise StatePersistenceError("state object is not serializable JSON") from error
    return (text + "\n").encode("utf-8")


def digest_bytes(value: bytes) -> str:
    """Return the canonical digest spelling used by persistence guards."""

    return "sha256:" + hashlib.sha256(value).hexdigest()


def validate_digest(value: str, label: str) -> str:
    """Validate a canonical SHA-256 digest."""

    if not _DIGEST.fullmatch(value):
        raise StatePersistenceError(f"{label} must be a canonical SHA-256 digest")
    return value


def format_timestamp(value: datetime) -> str:
    """Format an injected UTC timestamp in the strict persisted representation."""

    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise StatePersistenceError("persisted clocks must return UTC-aware timestamps")
    return (
        value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def parse_timestamp(value: str) -> datetime:
    """Parse only canonical second-resolution UTC timestamps."""

    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise StatePersistenceError(
            "persisted timestamp must be canonical UTC"
        ) from error
    if format_timestamp(parsed) != value:
        raise StatePersistenceError("persisted timestamp must be canonical UTC")
    return parsed


def parse_uuid(value: str, label: str) -> uuid.UUID:
    """Parse a canonical lowercase UUID string."""

    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise StatePersistenceError(f"{label} must be a canonical UUID") from error
    if str(parsed) != value:
        raise StatePersistenceError(f"{label} must be a canonical UUID")
    return parsed


def require_exact_keys(
    value: Mapping[str, object], expected: set[str], label: str
) -> None:
    """Reject both missing and unknown schema fields."""

    actual = set(value)
    if actual != expected:
        raise StatePersistenceError(f"{label} fields do not match the schema")


def require_string(value: Mapping[str, object], key: str) -> str:
    """Return one required string field."""

    item = value[key]
    if not isinstance(item, str) or not item:
        raise StatePersistenceError(
            f"persisted field must be a non-empty string: {key}"
        )
    return item


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise StatePersistenceError(f"persisted JSON has a duplicate field: {key}")
        result[key] = value
    return result


def _read_bytes(path: Path) -> bytes:
    validate_state_file(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise StatePersistenceError("cannot safely open persisted state") from error
    try:
        path_stat = os.fstat(descriptor)
        if not stat.S_ISREG(path_stat.st_mode) or path_stat.st_nlink != 1:
            raise UnsafePathError(
                "persisted state must be a singly linked regular file"
            )
        if os.name == "posix":
            getuid = getattr(os, "geteuid", None)
            if getuid is not None and path_stat.st_uid != getuid():
                raise UnsafePathError("persisted state has an unexpected owner")
            if stat.S_IMODE(path_stat.st_mode) != _FILE_MODE:
                raise UnsafePathError("persisted state permissions must be 0600")
        _require_same_inode(path, path_stat)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_JSON_BYTES:
                raise StatePersistenceError("persisted state exceeds the size limit")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _check_expected_digest(path: Path, expected_digest: str | None) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        if expected_digest is not None:
            raise StatePersistenceError(
                "persisted state disappeared before replacement"
            ) from None
        return
    if expected_digest is None:
        raise StatePersistenceError("persisted state appeared before replacement")
    validate_digest(expected_digest, "expected digest")
    actual = digest_bytes(_read_bytes(path))
    if actual != expected_digest:
        raise StatePersistenceError("persisted state changed before replacement")


def _write_all(descriptor: int, encoded: bytes) -> None:
    remaining = memoryview(encoded)
    while remaining:
        written = os.write(descriptor, remaining)
        if written == 0:
            raise StatePersistenceError("state write made no progress")
        remaining = remaining[written:]


def _require_same_inode(path: Path, opened_stat: os.stat_result) -> None:
    try:
        named_stat = path.lstat()
    except OSError as error:
        raise UnsafePathError("managed state file changed during access") from error
    if (named_stat.st_dev, named_stat.st_ino) != (
        opened_stat.st_dev,
        opened_stat.st_ino,
    ):
        raise UnsafePathError("managed state file changed during access")


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    except OSError as error:
        if error.errno not in {errno.EINVAL, errno.ENOTSUP}:
            raise
    finally:
        os.close(descriptor)
