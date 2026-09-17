"""POSIX application-level cluster locking with bounded acquisition."""

import fcntl
import json
import os
import socket
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType

from scylla_vms.errors import StateLockError, UnsafePathError
from scylla_vms.operations import get_operation
from scylla_vms.state import StatePaths, validate_state_directory, validate_state_file

LOCK_SCHEMA_VERSION = "deploy-scylla-vms.lock/v1"
_LOCK_MODE = 0o600


@dataclass(frozen=True, slots=True)
class LockOwner:
    """Validated, non-secret diagnostic metadata for a held lock."""

    pid: int
    hostname: str
    operation: str
    acquired_at: str


class ClusterLock:
    """Exclusive cluster lock; it complements, not replaces, backend locking."""

    def __init__(
        self,
        paths: StatePaths,
        operation: str,
        timeout_seconds: float,
        *,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
        hostname: Callable[[], str] = socket.gethostname,
    ) -> None:
        try:
            get_operation(operation)
        except KeyError as error:
            raise StateLockError("cluster lock operation is not registered") from error
        if timeout_seconds < 0:
            raise StateLockError("lock timeout must not be negative")
        self._paths = paths
        self._operation = operation
        self._timeout = timeout_seconds
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic
        self._sleeper = sleeper
        self._hostname = hostname
        self._directory_descriptor: int | None = None
        self._descriptor: int | None = None

    def acquire(self) -> "ClusterLock":
        """Acquire the cluster lock or raise a stable bounded conflict."""

        if self._descriptor is not None:
            raise StateLockError("cluster lock is already acquired by this object")
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise StateLockError("cluster locking requires POSIX flock and O_NOFOLLOW")
        validate_state_directory(self._paths.cluster_root)
        started = self._monotonic()
        directory_descriptor = _open_cluster_directory(self._paths.cluster_root)
        try:
            _acquire_exclusive(
                directory_descriptor,
                timeout=self._timeout,
                started=started,
                monotonic=self._monotonic,
                sleeper=self._sleeper,
            )
            validate_state_file(self._paths.lock, allow_missing=True)
            descriptor = _open_lock_file(self._paths.lock)
            try:
                _acquire_exclusive(
                    descriptor,
                    timeout=self._timeout,
                    started=started,
                    monotonic=self._monotonic,
                    sleeper=self._sleeper,
                    owner_descriptor=descriptor,
                )
            except StateLockError:
                os.close(descriptor)
                raise
        except (StateLockError, UnsafePathError):
            fcntl.flock(directory_descriptor, fcntl.LOCK_UN)
            os.close(directory_descriptor)
            raise

        try:
            owner = LockOwner(
                pid=os.getpid(),
                hostname=_safe_hostname(self._hostname()),
                operation=self._operation,
                acquired_at=_format_timestamp(self._clock()),
            )
            _write_owner(descriptor, owner)
        except (OSError, StateLockError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
            fcntl.flock(directory_descriptor, fcntl.LOCK_UN)
            os.close(directory_descriptor)
            raise
        self._directory_descriptor = directory_descriptor
        self._descriptor = descriptor
        return self

    def release(self) -> None:
        """Clear diagnostics, unlock, and close the owned descriptor."""

        descriptor = self._descriptor
        directory_descriptor = self._directory_descriptor
        if descriptor is None or directory_descriptor is None:
            return
        self._descriptor = None
        self._directory_descriptor = None
        try:
            os.ftruncate(descriptor, 0)
            os.fsync(descriptor)
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
                try:
                    fcntl.flock(directory_descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(directory_descriptor)

    def assert_held_for(self, paths: StatePaths) -> None:
        """Refuse a persistence call not protected by this exact acquired lock."""

        if (
            self._descriptor is None
            or self._directory_descriptor is None
            or paths != self._paths
        ):
            raise StateLockError(
                "cluster persistence requires the matching acquired cluster lock"
            )

    def assert_held_for_operation(self, paths: StatePaths, operation: str) -> None:
        """Also prove the acquired lock names the operation being persisted."""

        self.assert_held_for(paths)
        if operation != self._operation:
            raise StateLockError(
                "cluster persistence requires a lock for the matching operation"
            )

    def __enter__(self) -> "ClusterLock":
        return self.acquire()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()


class ClusterReadLock:
    """Exclusive read lock that never creates or changes a filesystem entry."""

    def __init__(
        self,
        paths: StatePaths,
        timeout_seconds: float,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if timeout_seconds < 0:
            raise StateLockError("lock timeout must not be negative")
        self._paths = paths
        self._timeout = timeout_seconds
        self._monotonic = monotonic
        self._sleeper = sleeper
        self._directory_descriptor: int | None = None
        self._lock_descriptor: int | None = None

    def acquire(self) -> "ClusterReadLock":
        """Acquire compatible locks without creating or rewriting the lock file."""

        if self._directory_descriptor is not None:
            raise StateLockError("cluster read lock is already acquired")
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise StateLockError("cluster locking requires POSIX flock and O_NOFOLLOW")
        validate_state_directory(self._paths.cluster_root)
        started = self._monotonic()
        directory_descriptor = _open_cluster_directory(self._paths.cluster_root)
        lock_descriptor: int | None = None
        try:
            _acquire_exclusive(
                directory_descriptor,
                timeout=self._timeout,
                started=started,
                monotonic=self._monotonic,
                sleeper=self._sleeper,
            )
            validate_state_file(self._paths.lock, allow_missing=True)
            if self._paths.lock.exists():
                lock_descriptor = _open_existing_lock_file(self._paths.lock)
                _acquire_exclusive(
                    lock_descriptor,
                    timeout=self._timeout,
                    started=started,
                    monotonic=self._monotonic,
                    sleeper=self._sleeper,
                    owner_descriptor=lock_descriptor,
                )
        except (StateLockError, UnsafePathError):
            if lock_descriptor is not None:
                os.close(lock_descriptor)
            fcntl.flock(directory_descriptor, fcntl.LOCK_UN)
            os.close(directory_descriptor)
            raise
        self._directory_descriptor = directory_descriptor
        self._lock_descriptor = lock_descriptor
        return self

    def assert_held_for(self, paths: StatePaths) -> None:
        """Prove local state is protected by this exact acquired read lock."""

        if self._directory_descriptor is None or paths != self._paths:
            raise StateLockError(
                "state read requires the matching acquired cluster lock"
            )

    def release(self) -> None:
        """Release descriptors without modifying lock diagnostics."""

        directory_descriptor = self._directory_descriptor
        if directory_descriptor is None:
            return
        lock_descriptor = self._lock_descriptor
        self._directory_descriptor = None
        self._lock_descriptor = None
        if lock_descriptor is not None:
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            finally:
                os.close(lock_descriptor)
        try:
            fcntl.flock(directory_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(directory_descriptor)

    def __enter__(self) -> "ClusterReadLock":
        return self.acquire()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()


def _open_cluster_directory(path: Path) -> int:
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise UnsafePathError("cannot safely open the cluster directory") from error
    try:
        opened = os.fstat(descriptor)
        named = path.lstat()
        if not stat.S_ISDIR(opened.st_mode) or stat.S_ISLNK(named.st_mode):
            raise UnsafePathError("cluster lock path must be a directory")
        if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
            raise UnsafePathError("cluster directory changed while it was opened")
        validate_state_directory(path)
        return descriptor
    except UnsafePathError:
        os.close(descriptor)
        raise
    except OSError as error:
        os.close(descriptor)
        raise UnsafePathError("cannot validate the open cluster directory") from error


def _open_lock_file(path: Path) -> int:
    flags = os.O_RDWR | os.O_NOFOLLOW
    created = False
    try:
        try:
            descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, _LOCK_MODE)
            created = True
        except FileExistsError:
            descriptor = os.open(path, flags)
    except OSError as error:
        raise UnsafePathError("cannot safely open the cluster lock") from error
    try:
        path_stat = os.fstat(descriptor)
        if not stat.S_ISREG(path_stat.st_mode) or path_stat.st_nlink != 1:
            raise UnsafePathError("cluster lock must be a singly linked regular file")
        if created:
            os.fchmod(descriptor, _LOCK_MODE)
        validate_state_file(path)
        named_stat = path.lstat()
        if (named_stat.st_dev, named_stat.st_ino) != (
            path_stat.st_dev,
            path_stat.st_ino,
        ):
            raise UnsafePathError("cluster lock changed while it was opened")
        return descriptor
    except UnsafePathError:
        os.close(descriptor)
        raise
    except OSError as error:
        os.close(descriptor)
        raise UnsafePathError("cannot validate the open cluster lock") from error


def _open_existing_lock_file(path: Path) -> int:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise UnsafePathError("cannot safely open the cluster lock") from error
    try:
        path_stat = os.fstat(descriptor)
        named_stat = path.lstat()
        if (
            not stat.S_ISREG(path_stat.st_mode)
            or path_stat.st_nlink != 1
            or (named_stat.st_dev, named_stat.st_ino)
            != (path_stat.st_dev, path_stat.st_ino)
        ):
            raise UnsafePathError("cluster lock must be a singly linked regular file")
        validate_state_file(path)
        return descriptor
    except UnsafePathError:
        os.close(descriptor)
        raise
    except OSError as error:
        os.close(descriptor)
        raise UnsafePathError("cannot validate the open cluster lock") from error


def _acquire_exclusive(
    descriptor: int,
    *,
    timeout: float,
    started: float,
    monotonic: Callable[[], float],
    sleeper: Callable[[float], None],
    owner_descriptor: int | None = None,
) -> None:
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            elapsed = monotonic() - started
            if elapsed >= timeout:
                owner = (
                    _read_owner(owner_descriptor)
                    if owner_descriptor is not None
                    else None
                )
                raise StateLockError(_conflict_message(owner)) from None
            sleeper(min(0.05, max(0.0, timeout - elapsed)))


def _write_owner(descriptor: int, owner: LockOwner) -> None:
    payload = {
        "acquired_at": owner.acquired_at,
        "hostname": owner.hostname,
        "operation": owner.operation,
        "pid": owner.pid,
        "schema_version": LOCK_SCHEMA_VERSION,
    }
    encoded = (
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.ftruncate(descriptor, 0)
    remaining = memoryview(encoded)
    while remaining:
        written = os.write(descriptor, remaining)
        if written == 0:
            raise StateLockError("cluster lock metadata write made no progress")
        remaining = remaining[written:]
    os.fsync(descriptor)


def _read_owner(descriptor: int) -> LockOwner | None:
    try:
        raw = os.pread(descriptor, 4096, 0)
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or set(value) != {
            "acquired_at",
            "hostname",
            "operation",
            "pid",
            "schema_version",
        }:
            return None
        if value["schema_version"] != LOCK_SCHEMA_VERSION:
            return None
        pid = value["pid"]
        hostname = value["hostname"]
        operation = value["operation"]
        acquired_at = value["acquired_at"]
        if (
            not isinstance(pid, int)
            or pid <= 0
            or not isinstance(hostname, str)
            or not isinstance(operation, str)
            or not isinstance(acquired_at, str)
        ):
            return None
        get_operation(operation)
        return LockOwner(pid, hostname, operation, acquired_at)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError):
        return None


def _conflict_message(owner: LockOwner | None) -> str:
    if owner is None:
        return (
            "cluster lock is held; owner metadata is unavailable and it was not broken"
        )
    state = "live or unverified"
    if owner.hostname == _safe_hostname(socket.gethostname()):
        try:
            os.kill(owner.pid, 0)
        except ProcessLookupError:
            state = "potentially stale"
        except PermissionError:
            state = "unverified"
        else:
            state = "live"
    return (
        f"cluster lock is held by pid {owner.pid} on {owner.hostname} "
        f"for {owner.operation} ({state}); it was not broken"
    )


def _safe_hostname(value: str) -> str:
    safe = "".join(
        character
        for character in value
        if character.isascii() and (character.isalnum() or character in ".-")
    )
    return safe[:255] or "unknown"


def _format_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise StateLockError("lock clock must return a UTC-aware timestamp")
    return (
        value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )
