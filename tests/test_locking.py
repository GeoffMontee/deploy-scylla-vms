import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scylla_vms.errors import StateLockError, UnsafePathError
from scylla_vms.locking import LOCK_SCHEMA_VERSION, ClusterLock, ClusterReadLock
from scylla_vms.state import StatePaths, initialize_state_layout


def _initialized_paths(tmp_path: Path) -> StatePaths:
    paths = StatePaths.derive(tmp_path / "state", "example")
    initialize_state_layout(paths)
    return paths


def test_lock_context_writes_only_bounded_metadata_and_releases(tmp_path: Path) -> None:
    paths = _initialized_paths(tmp_path)

    def clock() -> datetime:
        return datetime(2026, 9, 17, 12, 0, tzinfo=UTC)

    with ClusterLock(
        paths,
        "show",
        0,
        clock=clock,
        hostname=lambda: "test-host",
    ):
        metadata = json.loads(paths.lock.read_text(encoding="utf-8"))
        assert metadata == {
            "acquired_at": "2026-09-17T12:00:00Z",
            "hostname": "test-host",
            "operation": "show",
            "pid": os.getpid(),
            "schema_version": LOCK_SCHEMA_VERSION,
        }
        assert "secret" not in paths.lock.read_text(encoding="utf-8").lower()

    assert paths.lock.read_bytes() == b""
    with ClusterLock(paths, "show", 0):
        pass


def test_read_lock_creates_nothing_and_preserves_existing_diagnostics(
    tmp_path: Path,
) -> None:
    paths = _initialized_paths(tmp_path)
    assert not paths.lock.exists()

    with ClusterReadLock(paths, 0) as lock:
        lock.assert_held_for(paths)
        assert not paths.lock.exists()

    paths.lock.write_text("existing diagnostics\n", encoding="utf-8")
    paths.lock.chmod(0o600)
    before = paths.lock.read_bytes()
    with ClusterReadLock(paths, 0):
        assert paths.lock.read_bytes() == before
    assert paths.lock.read_bytes() == before


def test_lock_contention_times_out_without_breaking_owner(tmp_path: Path) -> None:
    paths = _initialized_paths(tmp_path)
    first = ClusterLock(paths, "deploy", 0).acquire()
    try:
        with pytest.raises(
            StateLockError, match=r"held by pid|metadata is unavailable"
        ):
            ClusterLock(paths, "show", 0).acquire()
        assert paths.lock.read_text(encoding="utf-8")
    finally:
        first.release()


@pytest.mark.skipif(os.name != "posix", reason="cluster lock uses POSIX flock")
def test_lock_contention_is_process_scoped(tmp_path: Path) -> None:
    paths = _initialized_paths(tmp_path)
    ready = tmp_path / "ready"
    script = """
import sys
import time
from pathlib import Path
from scylla_vms.locking import ClusterLock
from scylla_vms.state import StatePaths

paths = StatePaths.derive(Path(sys.argv[1]), "example")
with ClusterLock(paths, "deploy", 0):
    Path(sys.argv[2]).write_text("ready", encoding="utf-8")
    time.sleep(1.0)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(paths.state_root), str(ready)],
        cwd=Path(__file__).parents[1],
    )
    try:
        deadline = time.monotonic() + 5
        while (
            not ready.exists()
            and process.poll() is None
            and time.monotonic() < deadline
        ):
            time.sleep(0.02)
        assert ready.exists(), "lock-holder subprocess did not start"
        with pytest.raises(StateLockError, match="it was not broken"):
            ClusterLock(paths, "show", 0.05).acquire()
    finally:
        process.wait(timeout=5)
    assert process.returncode == 0


def test_lock_refuses_symlinks_and_hard_links(tmp_path: Path) -> None:
    paths = _initialized_paths(tmp_path)
    outside = tmp_path / "outside"
    outside.write_text("", encoding="utf-8")
    outside.chmod(0o600)
    paths.lock.symlink_to(outside)
    with pytest.raises(UnsafePathError, match="symbolic link"):
        ClusterLock(paths, "show", 0).acquire()

    paths.lock.unlink()
    os.link(outside, paths.lock)
    with pytest.raises(UnsafePathError, match="hard links"):
        ClusterLock(paths, "show", 0).acquire()
