import os
import stat
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scylla_vms.desired import (
    AttachmentType,
    BlockVolumePolicy,
    ClusterSpec,
    HostRole,
    ImageFilter,
    ImageVersionMatch,
    NetworkMode,
    NetworkPolicy,
    ServiceSpec,
    StorageBackend,
    StorageLayout,
    StoragePolicy,
    TopologyLabel,
    VolumeRetention,
    ZoneSpec,
)
from scylla_vms.errors import StateLockError, StatePersistenceError, UnsafePathError
from scylla_vms.locking import ClusterLock
from scylla_vms.models import ValueSource
from scylla_vms.persistence import (
    CLUSTER_SCHEMA_VERSION,
    AtomicJsonFile,
    ClusterMetadata,
    ClusterMetadataStore,
    digest_bytes,
    serialize_json,
)
from scylla_vms.state import StatePaths, initialize_state_layout

_CLUSTER_UUID = uuid.UUID("11111111-1111-4111-8111-111111111111")
_REQUEST_DIGEST = digest_bytes(b"sanitized request")


def _clock_at(hour: int) -> datetime:
    return datetime(2026, 9, 17, hour, 0, tzinfo=UTC)


def _store(tmp_path: Path) -> tuple[StatePaths, ClusterMetadataStore]:
    paths = StatePaths.derive(tmp_path / "state", "example")
    initialize_state_layout(paths)
    return paths, ClusterMetadataStore(paths, token_factory=lambda: "fixedtoken")


def _metadata() -> ClusterMetadata:
    return ClusterMetadata.create(
        cluster_uuid=_CLUSTER_UUID,
        cluster_name="example",
        provider="oci",
        request_digest=_REQUEST_DIGEST,
        desired_spec=_spec(),
        clock=lambda: _clock_at(10),
    )


def _block(size: int) -> BlockVolumePolicy:
    return BlockVolumePolicy(
        1,
        size,
        10,
        AttachmentType.PARAVIRTUALIZED,
        VolumeRetention.RETAIN,
        None,
        False,
    )


def _spec() -> ClusterSpec:
    return ClusterSpec(
        _CLUSTER_UUID,
        "example",
        "oci",
        "us-ashburn-1",
        "ocid1.compartment.oc1..fixture",
        TopologyLabel("oci-us-ashburn-1", "oci-ascii-slug/v1"),
        "VM.Standard.E5.Flex",
        (
            ZoneSpec(
                "AD-1",
                1,
                TopologyLabel("rack-ad-1", "explicit"),
                ("scylla-ad-1-1",),
            ),
        ),
        (
            ServiceSpec(
                HostRole.MANAGER,
                1,
                ("AD-1",),
                "VM.Standard.E5.Flex",
                ("manager-1",),
            ),
            ServiceSpec(
                HostRole.MONITORING,
                1,
                ("AD-1",),
                "VM.Standard.E5.Flex",
                ("monitoring-1",),
            ),
            ServiceSpec(HostRole.JUMP_HOST, 0, (), None, ()),
        ),
        NetworkPolicy(
            NetworkMode.CREATE,
            None,
            (),
            (),
            "opc",
            Path("/fixture/id.pub"),
            False,
            "10.0.0.0/16",
            (("AD-1", "10.0.1.0/24"),),
            (),
        ),
        (
            StoragePolicy(
                HostRole.SCYLLA,
                StorageBackend.BLOCK_VOLUME,
                StorageLayout.SINGLE,
                None,
                None,
                _block(100),
            ),
            StoragePolicy(
                HostRole.MANAGER,
                StorageBackend.BLOCK_VOLUME,
                StorageLayout.SINGLE,
                None,
                None,
                _block(50),
            ),
            StoragePolicy(
                HostRole.MONITORING,
                StorageBackend.BLOCK_VOLUME,
                StorageLayout.SINGLE,
                None,
                None,
                _block(50),
            ),
            StoragePolicy(
                HostRole.JUMP_HOST,
                StorageBackend.BOOT_ONLY,
                None,
                None,
                None,
                None,
            ),
        ),
        (("cluster_name", ValueSource.CLI),),
        tuple(
            (role, ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT))
            for role in (HostRole.MANAGER, HostRole.MONITORING, HostRole.SCYLLA)
        ),
    )


def _write_raw(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    path.chmod(0o600)


def test_cluster_metadata_round_trip_is_deterministic_and_owner_only(
    tmp_path: Path,
) -> None:
    paths, store = _store(tmp_path)
    record = _metadata()

    stored = store.write(record, expected_generation=0, expected_digest=None)

    assert paths.cluster_metadata.read_bytes() == serialize_json(record.to_object())
    assert store.read(expected_cluster_name="example") == stored
    if os.name == "posix":
        assert stat.S_IMODE(paths.cluster_metadata.stat().st_mode) == 0o600

    updated = record.next_generation(clock=lambda: _clock_at(11))
    next_stored = store.write(
        updated,
        expected_generation=stored.record.generation,
        expected_digest=stored.digest,
    )
    assert next_stored.record.generation == 2
    assert (
        store.read(expected_cluster_name="example", expected_cluster_uuid=_CLUSTER_UUID)
        == next_stored
    )


def test_metadata_updates_reject_lost_updates_generation_and_identity_changes(
    tmp_path: Path,
) -> None:
    _, store = _store(tmp_path)
    initial = store.write(_metadata(), expected_generation=0, expected_digest=None)
    updated = initial.record.next_generation(clock=lambda: _clock_at(11))

    with pytest.raises(StatePersistenceError, match="changed concurrently"):
        store.write(
            updated, expected_generation=1, expected_digest=digest_bytes(b"old")
        )
    with pytest.raises(StatePersistenceError, match="increase by exactly one"):
        store.write(
            initial.record,
            expected_generation=1,
            expected_digest=initial.digest,
        )

    changed_uuid = uuid.UUID("22222222-2222-4222-8222-222222222222")
    changed_identity = ClusterMetadata(
        generation=2,
        cluster_uuid=changed_uuid,
        cluster_name="example",
        provider="oci",
        created_at=initial.record.created_at,
        updated_at="2026-09-17T11:00:00Z",
        provenance=initial.record.provenance,
        desired_spec=replace(initial.record.desired_spec, cluster_uuid=changed_uuid),
    )
    with pytest.raises(StatePersistenceError, match="identity fields are immutable"):
        store.write(
            changed_identity,
            expected_generation=1,
            expected_digest=initial.digest,
        )


def test_atomic_replace_failure_preserves_old_bytes_and_cleans_temp(
    tmp_path: Path,
) -> None:
    paths, store = _store(tmp_path)
    initial = store.write(_metadata(), expected_generation=0, expected_digest=None)
    old_bytes = paths.cluster_metadata.read_bytes()

    def fail_replace(source: Path, destination: Path) -> None:
        raise OSError("injected replacement failure")

    failing_store = ClusterMetadataStore(
        paths, replace=fail_replace, token_factory=lambda: "failuretoken"
    )
    with pytest.raises(StatePersistenceError, match="atomic state write failed"):
        failing_store.write(
            initial.record.next_generation(clock=lambda: _clock_at(11)),
            expected_generation=1,
            expected_digest=initial.digest,
        )

    assert paths.cluster_metadata.read_bytes() == old_bytes
    assert not (paths.cluster_root / ".cluster.json.failuretoken.tmp").exists()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(schema_version="deploy-scylla-vms.cluster/v999"),
        lambda value: value.update(cluster_uuid="NOT-A-UUID"),
        lambda value: value.update(updated_at="2026-09-17 10:00:00"),
        lambda value: value.update(generation=0),
        lambda value: value.update(password="must-not-persist"),
        lambda value: value.pop("provider"),
    ],
)
def test_strict_metadata_schema_rejects_invalid_values(
    tmp_path: Path, mutation: object
) -> None:
    paths, store = _store(tmp_path)
    value = _metadata().to_object()
    assert callable(mutation)
    mutation(value)
    _write_raw(paths.cluster_metadata, serialize_json(value))

    with pytest.raises(StatePersistenceError):
        store.read(expected_cluster_name="example")


@pytest.mark.parametrize(
    "encoded",
    [
        b'{"schema_version":',
        b"\xff",
        b"[]\n",
        b'{"schema_version":"a","schema_version":"b"}\n',
    ],
)
def test_corrupt_truncated_non_utf8_and_duplicate_json_are_rejected(
    tmp_path: Path, encoded: bytes
) -> None:
    paths, store = _store(tmp_path)
    _write_raw(paths.cluster_metadata, encoded)

    with pytest.raises(StatePersistenceError):
        store.read(expected_cluster_name="example")


def test_read_rejects_identity_mismatch_permissions_symlink_and_hardlink(
    tmp_path: Path,
) -> None:
    paths, store = _store(tmp_path)
    store.write(_metadata(), expected_generation=0, expected_digest=None)

    with pytest.raises(StatePersistenceError, match="name does not match"):
        store.read(expected_cluster_name="another")

    paths.cluster_metadata.chmod(0o644)
    with pytest.raises(UnsafePathError, match="permissions"):
        store.read(expected_cluster_name="example")
    paths.cluster_metadata.chmod(0o600)

    hardlink = tmp_path / "metadata-link"
    os.link(paths.cluster_metadata, hardlink)
    with pytest.raises(UnsafePathError, match="hard links"):
        store.read(expected_cluster_name="example")
    hardlink.unlink()

    outside = tmp_path / "outside.json"
    paths.cluster_metadata.replace(outside)
    paths.cluster_metadata.symlink_to(outside)
    with pytest.raises(UnsafePathError, match="symbolic link"):
        store.read(expected_cluster_name="example")


def test_atomic_writer_rejects_preexisting_temporary_file(tmp_path: Path) -> None:
    paths, _ = _store(tmp_path)
    temporary = paths.cluster_root / ".cluster.json.collision.tmp"
    temporary.write_text("attacker", encoding="utf-8")
    writer = AtomicJsonFile(paths.cluster_metadata, token_factory=lambda: "collision")

    with pytest.raises(StatePersistenceError, match="temporary"):
        writer.write({"schema_version": CLUSTER_SCHEMA_VERSION}, expected_digest=None)
    assert temporary.read_text(encoding="utf-8") == "attacker"
    assert not paths.cluster_metadata.exists()


def test_timestamp_generation_rejects_clock_regression() -> None:
    record = _metadata()

    with pytest.raises(StatePersistenceError, match="timestamp regressed"):
        record.next_generation(clock=lambda: _clock_at(10) - timedelta(seconds=1))


def test_explicit_locked_metadata_api_requires_matching_acquired_lock(
    tmp_path: Path,
) -> None:
    paths, store = _store(tmp_path)
    lock = ClusterLock(paths, "deploy", 0)
    with pytest.raises(StateLockError, match="matching acquired cluster lock"):
        store.write_locked(
            _metadata(),
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )

    with lock:
        stored = store.write_locked(
            _metadata(),
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    assert stored.record.desired_spec == _spec()


def test_persisted_desired_spec_identity_and_provider_are_checked(
    tmp_path: Path,
) -> None:
    _, store = _store(tmp_path)
    stored = store.write(_metadata(), expected_generation=0, expected_digest=None)
    with pytest.raises(StatePersistenceError, match="provider does not match"):
        store.read(expected_cluster_name="example", expected_provider="future-provider")

    value = stored.record.to_object()
    desired = value["desired_spec"]
    assert isinstance(desired, dict)
    desired["cluster_name"] = "other"
    with pytest.raises(StatePersistenceError, match="identity"):
        ClusterMetadata.from_object(value)
