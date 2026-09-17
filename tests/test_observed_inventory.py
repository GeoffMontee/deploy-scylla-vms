import json
import os
import uuid
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path

import pytest

from scylla_vms.cli import main
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
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.inventory import (
    HostTrustStatus,
    InventoryRefreshService,
    InventoryStore,
    build_inventory,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.models import ValueSource
from scylla_vms.observed import ObservedStateRecord, ObservedStateStore
from scylla_vms.persistence import (
    ClusterMetadata,
    ClusterMetadataStore,
    digest_bytes,
)
from scylla_vms.reconciliation import (
    ReconciliationClass,
    reconcile_desired_observed,
)
from scylla_vms.state import StatePaths, initialize_state_layout
from scylla_vms.terraform.outputs import (
    StorageDevice,
    StorageDeviceKind,
    StorageManifest,
    StorageSelectionStatus,
    TerraformHost,
    TerraformHostManifest,
)

CLUSTER_UUID = uuid.UUID("11111111-1111-4111-8111-111111111111")
CAPTURED = datetime(2026, 9, 17, 16, 0, tzinfo=UTC)


def _block(count: int, size: int) -> BlockVolumePolicy:
    return BlockVolumePolicy(
        count,
        size,
        10,
        AttachmentType.PARAVIRTUALIZED,
        VolumeRetention.RETAIN,
        None,
        True,
    )


def _spec() -> ClusterSpec:
    return ClusterSpec(
        CLUSTER_UUID,
        "example",
        "oci",
        "us-ashburn-1",
        "ocid1.compartment.oc1..fake",
        TopologyLabel("example-dc", "explicit"),
        "VM.Standard.E5.Flex",
        (
            ZoneSpec(
                "AD-1",
                1,
                TopologyLabel("rack-a", "explicit"),
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
            ServiceSpec(
                HostRole.JUMP_HOST,
                1,
                ("AD-1",),
                "VM.Standard.E5.Flex",
                ("jump-host-1",),
            ),
        ),
        NetworkPolicy(
            NetworkMode.EXISTING,
            "ocid1.vcn.oc1..fake",
            (
                (HostRole.JUMP_HOST, "ocid1.subnet.oc1..jump"),
                (HostRole.MANAGER, "ocid1.subnet.oc1..manager"),
                (HostRole.MONITORING, "ocid1.subnet.oc1..monitoring"),
                (HostRole.SCYLLA, "ocid1.subnet.oc1..scylla"),
            ),
            ("198.51.100.0/24",),
            "opc",
            Path("/tmp/fake-bootstrap.pub"),
        ),
        (
            StoragePolicy(
                HostRole.SCYLLA,
                StorageBackend.BLOCK_VOLUME,
                StorageLayout.SINGLE,
                None,
                None,
                _block(1, 500),
            ),
            StoragePolicy(
                HostRole.MANAGER,
                StorageBackend.BLOCK_VOLUME,
                StorageLayout.SINGLE,
                None,
                None,
                _block(1, 100),
            ),
            StoragePolicy(
                HostRole.MONITORING,
                StorageBackend.BLOCK_VOLUME,
                StorageLayout.SINGLE,
                None,
                None,
                _block(1, 200),
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
            for role in (
                HostRole.JUMP_HOST,
                HostRole.MANAGER,
                HostRole.MONITORING,
                HostRole.SCYLLA,
            )
        ),
    )


def _storage(logical_id: str, size: int) -> StorageManifest:
    if size == 0:
        return StorageManifest(
            StorageBackend.BOOT_ONLY,
            StorageBackend.BOOT_ONLY,
            "boot-only/v1",
            StorageSelectionStatus.FINAL,
            "sha256:" + "a" * 64,
            1,
            0,
            0,
            0,
            None,
            None,
            None,
            None,
            None,
            None,
            (),
            (),
            (),
        )
    suffix = logical_id.replace("-", "")
    device = StorageDevice(
        StorageDeviceKind.BLOCK_VOLUME,
        f"ocid1.volume.oc1.iad.fake{suffix}",
        f"ocid1.volumeattachment.oc1.iad.fake{suffix}",
        None,
        f"/dev/oracleoci/{suffix}",
        f"FAKE-{suffix}",
        None,
        f"/dev/disk/by-id/fake-{suffix}",
        size,
        False,
        "paravirtualized",
        None,
        None,
        None,
        True,
        "provider-managed",
        None,
        10,
        "retain",
    )
    return StorageManifest(
        StorageBackend.BLOCK_VOLUME,
        StorageBackend.BLOCK_VOLUME,
        "oci-storage/v1",
        StorageSelectionStatus.FINAL,
        "sha256:" + "b" * 64,
        1,
        1,
        size,
        size,
        "single",
        None,
        "xfs",
        f"data-{suffix}",
        "by-id",
        f"/var/lib/{suffix}",
        ("noatime",),
        ("data",),
        (device,),
    )


def _manifest() -> TerraformHostManifest:
    values = (
        ("jump-host-1", HostRole.JUMP_HOST, "10.0.0.10", 0, None, None, None),
        ("manager-1", HostRole.MANAGER, "10.0.1.10", 100, None, None, "jump-host-1"),
        (
            "monitoring-1",
            HostRole.MONITORING,
            "10.0.2.10",
            200,
            None,
            None,
            "jump-host-1",
        ),
        (
            "scylla-ad-1-1",
            HostRole.SCYLLA,
            "10.0.3.10",
            500,
            "example-dc",
            "rack-a",
            "jump-host-1",
        ),
    )
    hosts = []
    for logical_id, role, address, size, dc, rack, jump in values:
        hosts.append(
            TerraformHost(
                logical_id,
                role,
                "AD-1",
                f"ocid1.instance.oc1.iad.fake{logical_id.replace('-', '')}",
                address,
                "203.0.113.10" if role is HostRole.JUMP_HOST else None,
                jump,
                dc,
                rack,
                "VM.Standard.E5.Flex",
                _storage(logical_id, size),
            )
        )
    return TerraformHostManifest(CLUSTER_UUID, tuple(hosts))


def _state(
    tmp_path: Path,
) -> tuple[StatePaths, ClusterMetadata, ObservedStateRecord]:
    paths = StatePaths.derive(tmp_path / "state", "example")
    initialize_state_layout(paths)
    spec = _spec()
    metadata = ClusterMetadata.create(
        cluster_uuid=CLUSTER_UUID,
        cluster_name="example",
        provider="oci",
        request_digest="sha256:" + "c" * 64,
        desired_spec=spec,
        clock=lambda: CAPTURED,
    )
    observed = ObservedStateRecord.create(
        cluster_uuid=CLUSTER_UUID,
        cluster_name="example",
        provider="oci",
        manifest=_manifest(),
        clock=lambda: CAPTURED,
    )
    return paths, metadata, observed


def test_observed_record_round_trip_generation_and_lock_guards(tmp_path: Path) -> None:
    paths, _, record = _state(tmp_path)
    store = ObservedStateStore(paths)
    lock = ClusterLock(paths, "deploy", 0)
    with pytest.raises(StateLockError):
        store.write_locked(
            record, expected_generation=0, expected_digest=None, lock=lock
        )
    with lock:
        stored = store.write_locked(
            record, expected_generation=0, expected_digest=None, lock=lock
        )
    assert paths.terraform_observed.stat().st_mode & 0o777 == 0o600
    assert (
        store.read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
            expected_provider="oci",
        )
        == stored
    )
    next_record = record.next_generation(
        manifest=record.manifest, clock=lambda: CAPTURED + timedelta(seconds=1)
    )
    with ClusterLock(paths, "deploy", 0) as next_lock:
        updated = store.write_locked(
            next_record,
            expected_generation=1,
            expected_digest=stored.digest,
            lock=next_lock,
        )
    assert updated.record.generation == 2


def test_invalid_observed_update_preserves_previous_record(tmp_path: Path) -> None:
    paths, _, record = _state(tmp_path)
    store = ObservedStateStore(paths)
    with ClusterLock(paths, "deploy", 0) as lock:
        stored = store.write_locked(
            record, expected_generation=0, expected_digest=None, lock=lock
        )
    before = paths.terraform_observed.read_bytes()
    failing = ObservedStateStore(
        paths,
        replace=lambda _source, _target: (_ for _ in ()).throw(OSError("fake")),
    )
    next_record = record.next_generation(
        manifest=record.manifest, clock=lambda: CAPTURED + timedelta(seconds=1)
    )
    with (
        ClusterLock(paths, "deploy", 0) as lock,
        pytest.raises(StatePersistenceError, match="atomic"),
    ):
        failing.write_locked(
            next_record,
            expected_generation=1,
            expected_digest=stored.digest,
            lock=lock,
        )
    assert paths.terraform_observed.read_bytes() == before


@pytest.mark.parametrize("field", ["schema_version", "manifest_digest", "provider"])
def test_corrupt_observed_envelope_is_rejected(tmp_path: Path, field: str) -> None:
    paths, _, record = _state(tmp_path)
    value = record.to_object()
    value[field] = "invalid"
    paths.terraform_observed.write_text(json.dumps(value), encoding="utf-8")
    paths.terraform_observed.chmod(0o600)
    with pytest.raises(StatePersistenceError):
        ObservedStateStore(paths).read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
            expected_provider="oci",
        )


def test_observed_store_rejects_unsafe_and_oversized_files(tmp_path: Path) -> None:
    paths, _, _ = _state(tmp_path)
    paths.terraform_observed.write_bytes(b"{" + b" " * (1024 * 1024 + 1))
    paths.terraform_observed.chmod(0o600)
    with pytest.raises(StatePersistenceError, match="size"):
        ObservedStateStore(paths).read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
            expected_provider="oci",
        )
    paths.terraform_observed.unlink()
    outside = tmp_path / "outside"
    outside.write_text("{}", encoding="utf-8")
    paths.terraform_observed.symlink_to(outside)
    with pytest.raises(UnsafePathError, match="symbolic link"):
        ObservedStateStore(paths).read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
            expected_provider="oci",
        )
    paths.terraform_observed.unlink()
    outside.chmod(0o600)
    os.link(outside, paths.terraform_observed)
    with pytest.raises(UnsafePathError, match=r"hard links|singly linked"):
        ObservedStateStore(paths).read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
            expected_provider="oci",
        )


def test_reconciliation_classifies_match_unknown_intent_and_sensitive_drift() -> None:
    spec = _spec()
    manifest = _manifest()
    report = reconcile_desired_observed(spec, manifest)
    assert report.status is ReconciliationClass.MATCH
    assert report.sensitive_ready

    missing = replace(manifest, hosts=manifest.hosts[:-1])
    report = reconcile_desired_observed(spec, missing)
    assert report.status is ReconciliationClass.UNKNOWN
    intended = reconcile_desired_observed(
        spec, missing, intended_additions=frozenset({"scylla-ad-1-1"})
    )
    assert intended.status is ReconciliationClass.INTENDED_CHANGE

    wrong_zone = replace(
        manifest,
        hosts=(
            *manifest.hosts[:-1],
            replace(manifest.hosts[-1], zone="AD-2"),
        ),
    )
    report = reconcile_desired_observed(spec, wrong_zone)
    assert report.status is ReconciliationClass.SENSITIVE_CONFLICT
    assert any(finding.code == "zone-conflict" for finding in report.findings)


def test_reconciliation_detects_shape_provider_address_and_storage_changes() -> None:
    spec = _spec()
    baseline = _manifest()
    changed_host = replace(
        baseline.hosts[-1],
        provider_id="ocid1.instance.oc1.iad.replacement",
        private_address="10.0.3.11",
        storage=replace(baseline.hosts[-1].storage, storage_generation=2),
    )
    changed = replace(baseline, hosts=(*baseline.hosts[:-1], changed_host))
    report = reconcile_desired_observed(spec, changed, baseline=baseline)
    assert report.status is ReconciliationClass.SENSITIVE_CONFLICT
    assert {finding.field for finding in report.findings} >= {
        "provider_id",
        "private_address",
        "storage",
    }
    shape = replace(
        baseline,
        hosts=(
            *baseline.hosts[:-1],
            replace(baseline.hosts[-1], shape="VM.Standard.E6.Flex"),
        ),
    )
    assert reconcile_desired_observed(spec, shape).status is ReconciliationClass.DRIFT


def test_inventory_projection_has_stable_groups_routes_and_no_ssh_bypass() -> None:
    first = build_inventory(_spec(), _manifest())
    second = build_inventory(_spec(), _manifest())
    assert first == second
    value = first.to_object()
    groups = set(value) - {"_meta", "all"}
    assert list(value)[2:] == sorted(groups)
    assert {
        "jump_hosts",
        "manager",
        "monitoring",
        "scylla",
        "scylla_dc_example_dc",
        "scylla_rack_rack_a",
        "zone_ad_1",
    } <= groups
    hostvars = value["_meta"]["hostvars"]
    assert hostvars["scylla-ad-1-1"]["deploy_scylla_vms_route_mode"] == "proxy-jump"
    assert "ansible_ssh_common_args" not in json.dumps(value)
    assert "host_key_checking_required" in json.dumps(value)
    assert first.host_trust_status is HostTrustStatus.UNAVAILABLE
    with pytest.raises(FrozenInstanceError):
        first.groups[0].name = "changed"  # type: ignore[misc]


def test_inventory_enforces_private_public_and_ssh_connection_policy() -> None:
    spec = _spec()
    manifest = _manifest()
    inventory = build_inventory(spec, manifest)
    private_host = next(
        host for host in inventory.hosts if host.role is HostRole.SCYLLA
    )
    manifest_host = next(
        host for host in manifest.hosts if host.role is HostRole.SCYLLA
    )
    with pytest.raises(StatePersistenceError, match="RFC 1918"):
        build_inventory(
            spec,
            replace(
                manifest,
                hosts=tuple(
                    replace(host, private_address="198.51.100.10")
                    if host == manifest_host
                    else host
                    for host in manifest.hosts
                ),
            ),
        )
    with pytest.raises(StatePersistenceError, match="restricted to jump hosts"):
        build_inventory(
            spec,
            replace(
                manifest,
                hosts=tuple(
                    replace(host, public_address="198.51.100.11")
                    if host == manifest_host
                    else host
                    for host in manifest.hosts
                ),
            ),
        )
    with pytest.raises(StatePersistenceError, match="SSH user"):
        replace(private_host, ansible_user="root user")
    assert all(host.ansible_user == spec.network.ssh_user for host in inventory.hosts)


def test_inventory_rejects_sanitized_group_collisions() -> None:
    spec = _spec()
    second_zone = ZoneSpec(
        "AD_1",
        1,
        TopologyLabel("rack-b", "explicit"),
        ("scylla-ad-2-1",),
    )
    spec = replace(spec, zones=(*spec.zones, second_zone))
    original = _manifest()
    second_host = replace(
        original.hosts[-1],
        logical_id="scylla-ad-2-1",
        zone="AD_1",
        provider_id="ocid1.instance.oc1.iad.fakescyllaad21",
        private_address="10.0.3.11",
        scylla_rack="rack-b",
        storage=_storage("scylla-ad-2-1", 500),
    )
    manifest = replace(original, hosts=(*original.hosts, second_host))
    with pytest.raises(
        (StateConflictError, StatePersistenceError), match=r"normalization|derivation"
    ):
        build_inventory(spec, manifest)


@pytest.mark.parametrize("jump_count", [0, 2])
def test_inventory_supports_zero_and_multiple_stable_jump_routes(
    jump_count: int,
) -> None:
    spec = _spec()
    manifest = _manifest()
    if jump_count == 0:
        jump_service = ServiceSpec(HostRole.JUMP_HOST, 0, (), None, ())
        network = replace(
            spec.network,
            subnets=tuple(
                item
                for item in spec.network.subnets
                if item[0] is not HostRole.JUMP_HOST
            ),
        )
        spec = replace(
            spec,
            services=(*spec.services[:2], jump_service),
            network=network,
            image_filters=tuple(
                item for item in spec.image_filters if item[0] is not HostRole.JUMP_HOST
            ),
        )
        manifest = replace(
            manifest,
            hosts=tuple(
                replace(host, jump_host_id=None)
                for host in manifest.hosts
                if host.role is not HostRole.JUMP_HOST
            ),
        )
    else:
        jump_service = ServiceSpec(
            HostRole.JUMP_HOST,
            2,
            ("AD-1", "AD-1"),
            "VM.Standard.E5.Flex",
            ("jump-host-1", "jump-host-2"),
        )
        spec = replace(spec, services=(*spec.services[:2], jump_service))
        second_jump = replace(
            manifest.hosts[0],
            logical_id="jump-host-2",
            provider_id="ocid1.instance.oc1.iad.fakejumphost2",
            private_address="10.0.0.11",
            public_address="203.0.113.11",
        )
        manifest = replace(
            manifest, hosts=(manifest.hosts[0], second_jump, *manifest.hosts[1:])
        )
    inventory = build_inventory(spec, manifest)
    jump_group = next(group for group in inventory.groups if group.name == "jump_hosts")
    assert jump_group.hosts == tuple(
        f"jump-host-{index}" for index in range(1, jump_count + 1)
    )
    if jump_count == 0:
        assert all(host.route_mode == "direct" for host in inventory.hosts)
    else:
        assert (
            next(
                host for host in inventory.hosts if host.logical_id == "scylla-ad-1-1"
            ).jump_host_id
            == "jump-host-1"
        )


def test_inventory_refresh_requires_approval_and_tracks_manifest_freshness(
    tmp_path: Path,
) -> None:
    paths, metadata, observed_record = _state(tmp_path)
    with ClusterLock(paths, "deploy", 0) as lock:
        ClusterMetadataStore(paths).write_locked(
            metadata,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        observed = ObservedStateStore(paths).write_locked(
            observed_record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    service = InventoryRefreshService(paths)
    prepared = service.prepare(metadata, observed, None, clock=lambda: CAPTURED)
    assert not prepared.fresh
    assert prepared.conflict_free
    assert not prepared.host_trust_ready
    assert len(prepared.changes) == 4
    with ClusterLock(paths, "deploy", 0) as lock:
        with pytest.raises(StateConflictError, match="approval"):
            service.write(prepared, None, approved=False, lock=lock)
        stored = service.write(prepared, None, approved=True, lock=lock)
    assert paths.ansible_inventory.stat().st_mode & 0o777 == 0o600
    reread = InventoryStore(paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    assert reread == stored
    fresh = service.prepare(
        metadata, observed, stored, clock=lambda: CAPTURED + timedelta(seconds=1)
    )
    assert fresh.fresh
    assert fresh.changes == ()
    newer = replace(
        observed,
        record=observed.record.next_generation(
            manifest=observed.record.manifest,
            clock=lambda: CAPTURED + timedelta(seconds=2),
        ),
    )
    stale = service.prepare(
        metadata, newer, stored, clock=lambda: CAPTURED + timedelta(seconds=3)
    )
    assert not stale.fresh


def test_inventory_invalid_update_preserves_prior_and_secret_fields_fail(
    tmp_path: Path,
) -> None:
    paths, metadata, observed_record = _state(tmp_path)
    with ClusterLock(paths, "deploy", 0) as lock:
        observed = ObservedStateStore(paths).write_locked(
            observed_record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        prepared = InventoryRefreshService(paths).prepare(
            metadata, observed, None, clock=lambda: CAPTURED
        )
        assert prepared.candidate is not None
        stored = InventoryStore(paths).write_locked(
            prepared.candidate,
            expected_generation=0,
            expected_digest=None,
            approved=True,
            lock=lock,
        )
    before = paths.ansible_inventory.read_bytes()
    next_record = replace(
        stored.record,
        generation=2,
        captured_at="2026-09-17T16:00:01Z",
    )
    failing = InventoryStore(
        paths,
        replace=lambda _source, _target: (_ for _ in ()).throw(OSError("fake")),
    )
    with (
        ClusterLock(paths, "deploy", 0) as lock,
        pytest.raises(StatePersistenceError, match="atomic"),
    ):
        failing.write_locked(
            next_record,
            expected_generation=1,
            expected_digest=stored.digest,
            approved=True,
            lock=lock,
        )
    assert paths.ansible_inventory.read_bytes() == before

    value = stored.record.to_object()
    hostvars = value["all"]["hosts"]
    hostvars["manager-1"]["password"] = "obviously-fake"
    paths.ansible_inventory.write_text(json.dumps(value), encoding="utf-8")
    paths.ansible_inventory.chmod(0o600)
    with pytest.raises(StatePersistenceError, match=r"secret-like|schema"):
        InventoryStore(paths).read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
            expected_provider="oci",
        )


def test_inventory_bytes_and_digest_are_deterministic() -> None:
    inventory = build_inventory(_spec(), _manifest())
    encoded = json.dumps(
        inventory.to_object(), sort_keys=True, separators=(",", ":")
    ).encode()
    assert digest_bytes(encoded) == digest_bytes(encoded)
    assert b"password" not in encoded.lower()
    assert b"private_key" not in encoded.lower()
    assert b"token" not in encoded.lower()


def _show(paths: StatePaths, *arguments: str) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    result = main(
        [
            "--cluster-name",
            "example",
            "--state-dir",
            str(paths.state_root),
            "--json",
            "show",
            *arguments,
        ],
        environ={},
        stdout=stdout,
        stderr=stderr,
        clock=lambda: CAPTURED + timedelta(minutes=1),
    )
    return result, stdout.getvalue(), stderr.getvalue()


def test_show_consumes_local_observation_and_inventory_without_writes(
    tmp_path: Path,
) -> None:
    paths, metadata, observed_record = _state(tmp_path)
    service = InventoryRefreshService(paths)
    with ClusterLock(paths, "deploy", 0) as lock:
        ClusterMetadataStore(paths).write_locked(
            metadata,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        observed = ObservedStateStore(paths).write_locked(
            observed_record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        prepared = service.prepare(metadata, observed, None, clock=lambda: CAPTURED)
        service.write(prepared, None, approved=True, lock=lock)
    before = {
        path.relative_to(paths.state_root): path.read_bytes()
        for path in paths.state_root.rglob("*")
        if path.is_file()
    }

    result, stdout, stderr = _show(paths, "--fail-on", "drift")

    assert result == 0
    assert stderr == ""
    report = json.loads(stdout)
    assert report["sources"]["terraform"]["status"] == "fresh"
    assert report["sources"]["inventory"]["status"] == "fresh"
    assert report["sources"]["provider"]["status"] == "not-performed"
    assert report["sections"]["drift"]["status"] == "match"
    assert report["sections"]["hosts"]["addresses"]["status"] == "redacted"
    assert report["sections"]["hosts"]["observed_items"][0]["provider_id"].startswith(
        "ocid1.instance."
    )
    assert "10.0.3.10" not in stdout
    after = {
        path.relative_to(paths.state_root): path.read_bytes()
        for path in paths.state_root.rglob("*")
        if path.is_file()
    }
    assert after == before

    result, stdout, stderr = _show(paths, "--include-addresses")
    assert result == 0
    assert stderr == ""
    addresses = json.loads(stdout)["sections"]["hosts"]["addresses"]
    assert addresses["status"] == "available"
    assert any(item["private"] == "10.0.3.10" for item in addresses["items"])
