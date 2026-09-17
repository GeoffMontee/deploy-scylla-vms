import base64
import json
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from test_ansible import (
    DIGEST,
    FakeRunner,
    _builder,
    _inventory,
    _metadata,
    _paths,
    _readiness,
)

from scylla_vms.ansible.service import AnsibleService
from scylla_vms.ansible.storage import (
    STORAGE_DISCOVERY_SCHEMA_VERSION,
    StorageDiscoveryEvidence,
    parse_storage_discovery_evidence,
)
from scylla_vms.ansible.storage_postcheck import (
    STORAGE_POSTCHECK_SCHEMA_VERSION,
    StorageCheckStatus,
    build_storage_postcheck_payload,
    parse_storage_postcheck_execution,
)
from scylla_vms.ansible.storage_preflight import (
    StorageOwnershipStatus,
    StoragePreflightResult,
    parse_storage_preflight_execution,
    reconcile_storage_preflight,
)
from scylla_vms.ansible.storage_prepare import (
    STORAGE_PREPARE_SCHEMA_VERSION,
    IrreversibleStepStatus,
    StoragePreparationAuthorization,
    StoragePrepareStatus,
    build_storage_prepare_payload,
    parse_storage_prepare_execution,
    storage_device_set_digest,
)
from scylla_vms.desired import (
    AttachmentType,
    BlockVolumePolicy,
    HostRole,
    StorageBackend,
    StorageLayout,
    StoragePolicy,
    VolumeRetention,
)
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import (
    InventoryGroup,
    InventoryModel,
    StoredInventoryRecord,
    _inventory_digest,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import ObservedStateRecord, StoredObservedState
from scylla_vms.persistence import ClusterMetadata
from scylla_vms.process import ProcessResult, ProcessTimeoutError
from scylla_vms.terraform.outputs import (
    StorageDevice,
    StorageDeviceKind,
    StorageManifest,
    StorageSelectionStatus,
    TerraformHost,
    TerraformHostManifest,
)


def _scylla_inventory() -> StoredInventoryRecord:
    stored = _inventory()
    old = stored.record.inventory.hosts[0]
    host = replace(
        old,
        logical_id="scylla-ad-1-1",
        role=HostRole.SCYLLA,
        provider_id="ocid1.instance.oc1.iad.fakescylla",
        private_address="10.0.0.20",
        public_address=None,
        ansible_host="10.0.0.20",
        scylla_datacenter="dc1",
        scylla_rack="rack1",
        selected_storage_backend="block-volume",
        storage_device_count=1,
        storage_raw_gib=500,
        storage_usable_gib=500,
    )
    groups = (
        InventoryGroup("jump_hosts", ()),
        InventoryGroup("manager", ()),
        InventoryGroup("monitoring", ()),
        InventoryGroup("scylla", (host.logical_id,)),
        InventoryGroup("scylla_dc_dc1", (host.logical_id,)),
        InventoryGroup("scylla_rack_rack1", (host.logical_id,)),
        InventoryGroup("zone_ad_1", (host.logical_id,)),
    )
    model = InventoryModel((host,), groups, stored.record.inventory.host_trust_status)
    record = replace(
        stored.record, inventory=model, inventory_digest=_inventory_digest(model)
    )
    return StoredInventoryRecord(record, DIGEST)


def _device(
    stable_id: str = "by-id:wwn-fake-data",
    *,
    path: str = "/dev/sdb",
) -> dict[str, object]:
    return {
        "boot_ancestor": False,
        "by_id": [f"/dev/disk/by-id/{stable_id.removeprefix('by-id:')}"],
        "filesystem": None,
        "holders": [],
        "kind": "disk",
        "mount_points": [],
        "nvme": None,
        "ownership": None,
        "ownership_marker": "absent",
        "parents": [],
        "path": path,
        "provider_attachment_ids": [
            "ocid1.volume.oc1.iad.fake",
            "ocid1.volumeattachment.oc1.iad.fake",
        ],
        "root_ancestor": False,
        "serial": "sensitive-fake-serial",
        "signatures": [],
        "size_bytes": 536870912000,
        "stable_id": stable_id,
        "transport": "scsi",
        "wwn": "sensitive-fake-wwn",
    }


def _host() -> dict[str, object]:
    inventory = _scylla_inventory()
    host = inventory.record.inventory.hosts[0]
    return {
        "cluster_uuid": str(inventory.record.cluster_uuid),
        "devices": [_device()],
        "host_manifest_digest": DIGEST,
        "inventory_digest": inventory.digest,
        "inventory_generation": inventory.record.generation,
        "logical_id": host.logical_id,
        "mounts": ["/"],
        "observation_digest": inventory.record.source_manifest_digest,
        "observation_generation": inventory.record.source_manifest_generation,
        "provider_id": host.provider_id,
        "schema_version": STORAGE_DISCOVERY_SCHEMA_VERSION,
        "storage_generation": host.storage_generation,
        "storage_policy_digest": host.storage_policy_digest,
        "tools": {
            "blkid": "available",
            "by-id": "available",
            "findmnt": "available",
            "lsblk": "available",
            "lvm": "unavailable",
            "md": "unavailable",
            "nvme": "unavailable",
            "wipefs": "available",
        },
    }


def _stdout(host: dict[str, object] | None, *, failed: int = 0) -> str:
    marker = ""
    if host is not None:
        encoded = base64.b64encode(
            json.dumps(host, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        marker = (
            f'ok: [scylla-ad-1-1] => {{"msg": "DSV_STORAGE_DISCOVERY_B64={encoded}"}}\n'
        )
    return (
        marker
        + "PLAY RECAP *****\n"
        + f"scylla-ad-1-1 : ok=3 changed=0 unreachable=0 failed={failed} "
        "skipped=0 rescued=0 ignored=0\n"
    )


def _preflight_stdout(result: StoragePreflightResult) -> str:
    host = result.hosts[0]
    encoded = base64.b64encode(
        json.dumps(host.to_object(), sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    return (
        f"ok: [{host.logical_id}] => "
        f'{{"msg": "DSV_STORAGE_PREFLIGHT_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"{host.logical_id} : ok=3 changed=0 unreachable=0 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )


def _prepare_stdout(result: dict[str, object], *, failed: int = 0) -> str:
    encoded = base64.b64encode(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    return (
        'ok: [scylla-ad-1-1] => {"msg": '
        f'"DSV_STORAGE_PREPARE_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"scylla-ad-1-1 : ok=4 changed={0 if failed else 1} "
        f"unreachable=0 failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


def _postcheck_stdout(result: dict[str, object], *, failed: int = 0) -> str:
    encoded = base64.b64encode(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    return (
        'ok: [scylla-ad-1-1] => {"msg": '
        f'"DSV_STORAGE_POSTCHECK_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"scylla-ad-1-1 : ok=5 changed=0 unreachable=0 failed={failed} "
        "skipped=0 rescued=0 ignored=0\n"
    )


def _clean_preflight() -> tuple[
    ClusterMetadata,
    StoredObservedState,
    StoredInventoryRecord,
    StorageDiscoveryEvidence,
    StoragePreflightResult,
]:
    metadata, observed, inventory, _ = _preflight_context()
    value = _host()
    value["tools"]["lvm"] = "available"  # type: ignore[index]
    value["tools"]["md"] = "available"  # type: ignore[index]
    discovery = parse_storage_discovery_evidence(
        _stdout(value), inventory, ("scylla-ad-1-1",), 0
    )
    preflight = reconcile_storage_preflight(
        metadata, observed, inventory, discovery, ("scylla-ad-1-1",)
    )
    return metadata, observed, inventory, discovery, preflight


def _preflight_context() -> tuple[
    ClusterMetadata,
    StoredObservedState,
    StoredInventoryRecord,
    TerraformHost,
]:
    inventory = _scylla_inventory()
    inventory_host = inventory.record.inventory.hosts[0]
    device = StorageDevice(
        StorageDeviceKind.BLOCK_VOLUME,
        "ocid1.volume.oc1.iad.fake",
        "ocid1.volumeattachment.oc1.iad.fake",
        None,
        "/dev/oracleoci/oraclevdb",
        "sensitive-fake-serial",
        "sensitive-fake-wwn",
        "/dev/disk/by-id/wwn-fake-data",
        500,
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
    storage = StorageManifest(
        StorageBackend.BLOCK_VOLUME,
        StorageBackend.BLOCK_VOLUME,
        "oci-storage-selection/v1",
        StorageSelectionStatus.FINAL,
        inventory_host.storage_policy_digest,
        inventory_host.storage_generation,
        1,
        500,
        500,
        "single",
        None,
        "xfs",
        "scylla-data",
        "by-id",
        "/var/lib/scylla",
        ("noatime",),
        ("data",),
        (device,),
    )
    host = TerraformHost(
        inventory_host.logical_id,
        HostRole.SCYLLA,
        inventory_host.zone,
        inventory_host.provider_id,
        inventory_host.private_address,
        None,
        inventory_host.jump_host_id,
        inventory_host.scylla_datacenter,
        inventory_host.scylla_rack,
        inventory_host.shape,
        storage,
    )
    manifest = TerraformHostManifest(inventory.record.cluster_uuid, (host,))
    observed_record = cast(
        ObservedStateRecord,
        SimpleNamespace(
            cluster_uuid=inventory.record.cluster_uuid,
            cluster_name=inventory.record.cluster_name,
            provider=inventory.record.provider,
            generation=inventory.record.source_manifest_generation,
            manifest_digest=inventory.record.source_manifest_digest,
            manifest=manifest,
        ),
    )
    observed = StoredObservedState(observed_record, DIGEST)
    block = BlockVolumePolicy(
        1,
        500,
        10,
        AttachmentType.PARAVIRTUALIZED,
        VolumeRetention.RETAIN,
        None,
        True,
    )
    policy = StoragePolicy(
        HostRole.SCYLLA,
        StorageBackend.BLOCK_VOLUME,
        StorageLayout.SINGLE,
        None,
        None,
        block,
    )
    metadata = cast(
        ClusterMetadata,
        SimpleNamespace(
            cluster_uuid=inventory.record.cluster_uuid,
            cluster_name=inventory.record.cluster_name,
            provider=inventory.record.provider,
            desired_spec=SimpleNamespace(storage=(policy,)),
        ),
    )
    return metadata, observed, inventory, host


def _local_preflight_context() -> tuple[
    ClusterMetadata,
    StoredObservedState,
    StoredInventoryRecord,
]:
    metadata, observed, inventory, old_host = _preflight_context()
    old_inventory_host = inventory.record.inventory.hosts[0]
    inventory_host = replace(
        old_inventory_host,
        selected_storage_backend="local-nvme",
        storage_ephemeral=True,
    )
    model = replace(inventory.record.inventory, hosts=(inventory_host,))
    inventory = StoredInventoryRecord(
        replace(
            inventory.record,
            inventory=model,
            inventory_digest=_inventory_digest(model),
        ),
        DIGEST,
    )
    device = StorageDevice(
        StorageDeviceKind.LOCAL_NVME,
        None,
        None,
        "local-slot-1",
        None,
        None,
        None,
        None,
        500,
        True,
        None,
        None,
        None,
        None,
        False,
        "provider-managed",
        None,
        None,
        None,
    )
    storage = replace(
        old_host.storage,
        requested_backend=StorageBackend.LOCAL_NVME,
        selected_backend=StorageBackend.LOCAL_NVME,
        mount_strategy="filesystem-uuid",
        devices=(device,),
    )
    host = replace(old_host, storage=storage)
    manifest = TerraformHostManifest(inventory.record.cluster_uuid, (host,))
    observed = StoredObservedState(
        cast(
            ObservedStateRecord,
            SimpleNamespace(
                cluster_uuid=inventory.record.cluster_uuid,
                cluster_name=inventory.record.cluster_name,
                provider=inventory.record.provider,
                generation=inventory.record.source_manifest_generation,
                manifest_digest=inventory.record.source_manifest_digest,
                manifest=manifest,
            ),
        ),
        DIGEST,
    )
    policy = StoragePolicy(
        HostRole.SCYLLA,
        StorageBackend.LOCAL_NVME,
        StorageLayout.SINGLE,
        1,
        500,
        None,
    )
    metadata = cast(
        ClusterMetadata,
        SimpleNamespace(
            cluster_uuid=inventory.record.cluster_uuid,
            cluster_name=inventory.record.cluster_name,
            provider=inventory.record.provider,
            desired_spec=SimpleNamespace(storage=(policy,)),
        ),
    )
    return metadata, observed, inventory


def test_parses_bound_storage_discovery_and_keeps_identifiers_internal() -> None:
    result = parse_storage_discovery_evidence(
        _stdout(_host()), _scylla_inventory(), ("scylla-ad-1-1",), 0
    )
    device = result.hosts[0].devices[0]
    assert device.size_bytes == 536870912000
    assert device.provider_attachment_ids
    assert "sensitive-fake-serial" not in repr(result)
    assert result.hosts[0].tools[-1] == ("wipefs", "available")


def test_storage_preflight_clean_block_volume_is_deterministic_and_redacted() -> None:
    metadata, observed, inventory, _ = _preflight_context()
    value = _host()
    value["tools"]["lvm"] = "available"  # type: ignore[index]
    value["tools"]["md"] = "available"  # type: ignore[index]
    discovery = parse_storage_discovery_evidence(
        _stdout(value), inventory, ("scylla-ad-1-1",), 0
    )
    first = reconcile_storage_preflight(
        metadata, observed, inventory, discovery, ("scylla-ad-1-1",)
    )
    second = reconcile_storage_preflight(
        metadata, observed, inventory, discovery, ("scylla-ad-1-1",)
    )
    host = first.hosts[0]
    assert first == second
    assert host.ownership_status is StorageOwnershipStatus.CLEAN_NEW
    assert host.ready and not host.wipe_required
    assert host.capacity_bytes == 500 * 1024**3
    assert host.devices[0].identity.startswith("device-sha256:")
    assert "sensitive-fake" not in json.dumps(first.to_object(), sort_keys=True)


def test_storage_preflight_selects_local_nvme_by_stable_evidence_not_path_order() -> (
    None
):
    metadata, observed, inventory = _local_preflight_context()
    value = _host()
    device = value["devices"][0]  # type: ignore[index]
    device.update(
        {
            "by_id": ["/dev/disk/by-id/nvme-fake-local"],
            "nvme": {
                "capabilities": ["namespace-features"],
                "model": "Fake Local NVMe",
                "namespace_id": 1,
                "serial": "sensitive-local-serial",
            },
            "path": "/dev/nvme9n1",
            "provider_attachment_ids": [],
            "serial": "sensitive-local-serial",
            "stable_id": "by-id:nvme-fake-local",
            "transport": "nvme",
            "wwn": None,
        }
    )
    value["tools"]["lvm"] = "available"  # type: ignore[index]
    value["tools"]["md"] = "available"  # type: ignore[index]
    value["tools"]["nvme"] = "available"  # type: ignore[index]
    discovery = parse_storage_discovery_evidence(
        _stdout(value), inventory, ("scylla-ad-1-1",), 0
    )
    result = reconcile_storage_preflight(
        metadata, observed, inventory, discovery, ("scylla-ad-1-1",)
    )
    assert result.hosts[0].ownership_status is StorageOwnershipStatus.CLEAN_NEW
    assert result.hosts[0].ready
    assert "/dev/nvme9n1" not in json.dumps(result.to_object())


@pytest.mark.parametrize(
    ("change", "blocker"),
    [
        ({"root_ancestor": True}, "root-or-boot-device-conflict"),
        ({"holders": ["by-id:holder"]}, "storage discovery topology"),
        ({"provider_attachment_ids": []}, "block-device-identity-ambiguous"),
        ({"size_bytes": 500 * 1024**3 - 1}, "block-device-size-conflict"),
    ],
)
def test_storage_preflight_refuses_unsafe_or_ambiguous_block_devices(
    change: dict[str, object], blocker: str
) -> None:
    metadata, observed, inventory, _ = _preflight_context()
    value = _host()
    value["tools"]["lvm"] = "available"  # type: ignore[index]
    value["tools"]["md"] = "available"  # type: ignore[index]
    value["devices"][0].update(change)  # type: ignore[index]
    if blocker == "storage discovery topology":
        with pytest.raises(AnsibleError, match="topology"):
            parse_storage_discovery_evidence(
                _stdout(value), inventory, ("scylla-ad-1-1",), 0
            )
        return
    discovery = parse_storage_discovery_evidence(
        _stdout(value), inventory, ("scylla-ad-1-1",), 0
    )
    result = reconcile_storage_preflight(
        metadata, observed, inventory, discovery, ("scylla-ad-1-1",)
    )
    assert blocker in result.hosts[0].blockers


def test_storage_preflight_distinguishes_wipe_review_and_exact_owned_noop() -> None:
    metadata, observed, inventory, host_manifest = _preflight_context()
    value = _host()
    value["devices"][0]["signatures"] = [  # type: ignore[index]
        {"kind": "filesystem", "value": "xfs"}
    ]
    blocked_discovery = parse_storage_discovery_evidence(
        _stdout(value), inventory, ("scylla-ad-1-1",), 0
    )
    blocked = reconcile_storage_preflight(
        metadata, observed, inventory, blocked_discovery, ("scylla-ad-1-1",)
    )
    assert blocked.hosts[0].ownership_status is StorageOwnershipStatus.BLOCKED
    assert not blocked.hosts[0].wipe_required

    value["tools"]["lvm"] = "available"  # type: ignore[index]
    value["tools"]["md"] = "available"  # type: ignore[index]
    discovery = parse_storage_discovery_evidence(
        _stdout(value), inventory, ("scylla-ad-1-1",), 0
    )
    wipe = reconcile_storage_preflight(
        metadata, observed, inventory, discovery, ("scylla-ad-1-1",)
    )
    assert wipe.hosts[0].ownership_status is StorageOwnershipStatus.WIPE_REVIEW_REQUIRED
    assert wipe.hosts[0].wipe_required and not wipe.hosts[0].ready

    value["devices"][0]["ownership_marker"] = "present"  # type: ignore[index]
    value["devices"][0]["ownership"] = {  # type: ignore[index]
        "backend": "block-volume",
        "cluster_uuid": str(inventory.record.cluster_uuid),
        "layout": "single",
        "logical_id": "scylla-ad-1-1",
        "policy_digest": host_manifest.storage.policy_digest,
        "preparation_intent_digest": wipe.hosts[0].preparation_intent_digest,
        "provider_id": host_manifest.provider_id,
        "schema_version": "deploy-scylla-vms.prepared-storage/v1",
        "stable_device_ids": ["by-id:wwn-fake-data"],
        "storage_generation": host_manifest.storage.storage_generation,
    }
    owned_discovery = parse_storage_discovery_evidence(
        _stdout(value), inventory, ("scylla-ad-1-1",), 0
    )
    owned = reconcile_storage_preflight(
        metadata, observed, inventory, owned_discovery, ("scylla-ad-1-1",)
    )
    assert owned.hosts[0].ownership_status is StorageOwnershipStatus.OWNED_NOOP
    assert owned.hosts[0].ready

    value["devices"][0]["ownership"]["provider_id"] = "wrong-provider"  # type: ignore[index]
    stale_discovery = parse_storage_discovery_evidence(
        _stdout(value), inventory, ("scylla-ad-1-1",), 0
    )
    stale = reconcile_storage_preflight(
        metadata, observed, inventory, stale_discovery, ("scylla-ad-1-1",)
    )
    assert "foreign-or-stale-ownership-marker" in stale.hosts[0].blockers


def test_service_executes_preflight_with_exact_return_only_projection(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    metadata, observed, inventory, _ = _preflight_context()
    value = _host()
    value["tools"]["lvm"] = "available"  # type: ignore[index]
    value["tools"]["md"] = "available"  # type: ignore[index]
    discovery = parse_storage_discovery_evidence(
        _stdout(value), inventory, ("scylla-ad-1-1",), 0
    )
    expected = reconcile_storage_preflight(
        metadata, observed, inventory, discovery, ("scylla-ad-1-1",)
    )
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(0, _preflight_stdout(expected), ""),
        ]
    )
    service = AnsibleService(_builder(tmp_path, paths), runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute_storage_preflight(
            lock,
            metadata,
            observed,
            inventory,
            discovery,
            limit=("scylla-ad-1-1",),
            readiness=_readiness(inventory),
        )
    assert result.storage_preflight == expected
    assert result.stdout == result.stderr == ""
    assert runner.runtime_payloads[-1]["deploy_scylla_vms_storage_preflight"] == {
        "scylla-ad-1-1": expected.hosts[0].to_object()
    }
    assert "--check" in runner.specs[-1].argv
    assert not paths.diagnostics_evidence.exists()


def test_storage_preflight_execution_rejects_partial_malformed_and_oversized() -> None:
    metadata, observed, inventory, _ = _preflight_context()
    value = _host()
    value["tools"]["lvm"] = "available"  # type: ignore[index]
    value["tools"]["md"] = "available"  # type: ignore[index]
    discovery = parse_storage_discovery_evidence(
        _stdout(value), inventory, ("scylla-ad-1-1",), 0
    )
    expected = reconcile_storage_preflight(
        metadata, observed, inventory, discovery, ("scylla-ad-1-1",)
    )
    with pytest.raises(AnsibleError, match="incomplete"):
        parse_storage_preflight_execution(_preflight_stdout(expected), expected, 2)
    with pytest.raises(AnsibleError, match="marker"):
        parse_storage_preflight_execution(
            'ok: [scylla-ad-1-1] => {"msg": '
            '"DSV_STORAGE_PREFLIGHT_B64=not-base64"}\nPLAY RECAP *****\n',
            expected,
            2,
        )
    with pytest.raises(AnsibleError, match="exceeds"):
        parse_storage_preflight_execution("x" * (2 * 1024 * 1024 + 1), expected, 2)


def test_storage_prepare_payload_binds_exact_approval_and_private_devices() -> None:
    metadata, observed, inventory, discovery, preflight = _clean_preflight()
    host = preflight.hosts[0]
    device_digest = storage_device_set_digest(
        tuple(device.stable_id for device in host.devices)
    )
    authorization = StoragePreparationAuthorization(
        uuid.UUID("22222222-2222-4222-8222-222222222222"),
        host.logical_id,
        host.preparation_intent_digest,
        device_digest,
        True,
    )
    payload = build_storage_prepare_payload(
        metadata,
        observed,
        inventory,
        discovery,
        preflight,
        authorization,
        limit=(host.logical_id,),
        check=False,
    )
    assert payload["mount_point"] == "/var/lib/scylla"
    assert payload["filesystem"] == "xfs"
    assert payload["classification"] == "clean-new"
    assert payload["devices"] == [
        {
            "by_id": ["/dev/disk/by-id/wwn-fake-data"],
            "filesystem": None,
            "holders": [],
            "mount_points": [],
            "path": "/dev/sdb",
            "root_ancestor": False,
            "signatures": [],
            "size_bytes": 500 * 1024**3,
            "stable_id": "by-id:wwn-fake-data",
        }
    ]
    assert "sensitive-fake-serial" not in json.dumps(payload)

    for changed in (
        replace(authorization, logical_id="other"),
        replace(authorization, preparation_intent_digest="sha256:" + "b" * 64),
        replace(authorization, device_set_digest="sha256:" + "c" * 64),
        replace(authorization, preparation_approved=False),
        replace(authorization, wipe_acknowledged=True),
    ):
        with pytest.raises((AnsibleError, StateConflictError)):
            build_storage_prepare_payload(
                metadata,
                observed,
                inventory,
                discovery,
                preflight,
                changed,
                limit=(host.logical_id,),
                check=False,
            )


def test_storage_prepare_requires_extra_wipe_consent_and_refuses_blocked() -> None:
    metadata, observed, inventory, _, _ = _clean_preflight()
    value = _host()
    value["tools"]["lvm"] = "available"  # type: ignore[index]
    value["tools"]["md"] = "available"  # type: ignore[index]
    value["devices"][0]["signatures"] = [  # type: ignore[index]
        {"kind": "filesystem", "value": "xfs"}
    ]
    discovery = parse_storage_discovery_evidence(
        _stdout(value), inventory, ("scylla-ad-1-1",), 0
    )
    preflight = reconcile_storage_preflight(
        metadata, observed, inventory, discovery, ("scylla-ad-1-1",)
    )
    host = preflight.hosts[0]
    authorization = StoragePreparationAuthorization(
        uuid.UUID("22222222-2222-4222-8222-222222222222"),
        host.logical_id,
        host.preparation_intent_digest,
        storage_device_set_digest(tuple(item.stable_id for item in host.devices)),
        True,
    )
    with pytest.raises(StateConflictError, match="separately bound"):
        build_storage_prepare_payload(
            metadata,
            observed,
            inventory,
            discovery,
            preflight,
            authorization,
            limit=(host.logical_id,),
            check=False,
        )
    payload = build_storage_prepare_payload(
        metadata,
        observed,
        inventory,
        discovery,
        preflight,
        replace(authorization, wipe_acknowledged=True),
        limit=(host.logical_id,),
        check=False,
    )
    assert payload["classification"] == "wipe-review-required"

    blocked_value = _host()
    blocked_value["tools"]["lvm"] = "available"  # type: ignore[index]
    blocked_value["tools"]["md"] = "available"  # type: ignore[index]
    blocked_value["devices"][0]["root_ancestor"] = True  # type: ignore[index]
    blocked = parse_storage_discovery_evidence(
        _stdout(blocked_value), inventory, ("scylla-ad-1-1",), 0
    )
    blocked_preflight = reconcile_storage_preflight(
        metadata, observed, inventory, blocked, ("scylla-ad-1-1",)
    )
    with pytest.raises(StateConflictError, match="never executable"):
        build_storage_prepare_payload(
            metadata,
            observed,
            inventory,
            blocked,
            blocked_preflight,
            authorization,
            limit=(host.logical_id,),
            check=False,
        )


@pytest.mark.parametrize(
    ("status", "exit_code", "irreversible"),
    [
        ("changed", 0, "completed"),
        ("noop", 0, "not-started"),
        ("not-predicted", 0, "not-started"),
        ("failed", 2, "started"),
    ],
)
def test_storage_prepare_result_parser_is_strict_and_redacted(
    status: str, exit_code: int, irreversible: str
) -> None:
    device_digest = "sha256:" + "d" * 64
    result: dict[str, object] = {
        "backend": "block-volume",
        "completed_steps": ["authorization-validated"],
        "device_set_digest": device_digest,
        "filesystem_uuid_digest": None,
        "irreversible_step_status": irreversible,
        "layout": "single",
        "logical_id": "scylla-ad-1-1",
        "marker_digest": None,
        "post_action_verification": {"manual_recovery_required": status == "failed"},
        "schema_version": STORAGE_PREPARE_SCHEMA_VERSION,
        "status": status,
    }
    evidence = parse_storage_prepare_execution(
        _prepare_stdout(result, failed=1 if status == "failed" else 0),
        expected_logical_id="scylla-ad-1-1",
        expected_backend="block-volume",
        expected_layout="single",
        expected_device_set_digest=device_digest,
        exit_code=exit_code,
    )
    assert evidence.status is StoragePrepareStatus(status)
    assert evidence.irreversible_step_status is IrreversibleStepStatus(irreversible)
    assert "ocid1" not in repr(evidence)
    malformed = dict(result)
    malformed["provider_id"] = "must-not-be-public"
    with pytest.raises(AnsibleError, match="malformed"):
        parse_storage_prepare_execution(
            _prepare_stdout(malformed),
            expected_logical_id="scylla-ad-1-1",
            expected_backend="block-volume",
            expected_layout="single",
            expected_device_set_digest=device_digest,
            exit_code=0,
        )


def test_packaged_storage_prepare_has_irreversible_order_and_no_dynamic_selection() -> (
    None
):
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content/playbooks"
    playbook = (root / "storage-prepare.yml").read_text(encoding="utf-8")
    tasks = (root / "roles/storage_prepare/tasks/main.yml").read_text(encoding="utf-8")
    module = (root / "roles/storage_prepare/library/storage_prepare.py").read_text(
        encoding="utf-8"
    )
    assert "gather_facts: true" in playbook
    assert "serial: 1" in playbook
    assert "any_errors_fatal: true" in playbook
    assert "not ansible_check_mode" in playbook
    assert "ansible.builtin.shell" not in playbook + tasks
    assert ".glob(" not in module
    assert "/dev/nvme*" not in module
    assert "shell=False" in module
    assert "authorization-validated" in module
    assert module.index("_immediate_revalidate(intent)") < module.index(
        'COMMANDS["wipefs"], "--all"'
    )
    assert module.index('_run([COMMANDS["mount"], MOUNT_POINT])') < module.index(
        "_atomic_write(marker_path"
    )
    assert '"--create"' in module and '"--level=0"' in module
    assert '"/var/lib/scylla"' in module


def test_service_executes_one_authorized_storage_prepare_and_cleans_vars(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    metadata, observed, inventory, discovery, preflight = _clean_preflight()
    host = preflight.hosts[0]
    device_digest = storage_device_set_digest(
        tuple(item.stable_id for item in host.devices)
    )
    authorization = StoragePreparationAuthorization(
        uuid.UUID("22222222-2222-4222-8222-222222222222"),
        host.logical_id,
        host.preparation_intent_digest,
        device_digest,
        True,
    )
    prepared = {
        "backend": host.backend,
        "completed_steps": [
            "authorization-validated",
            "immediate-rediscovery-validated",
            "xfs-formatted",
            "fstab-written",
            "mounted",
            "owner-marker-written",
        ],
        "device_set_digest": device_digest,
        "filesystem_uuid_digest": "sha256:" + "e" * 64,
        "irreversible_step_status": "completed",
        "layout": host.layout,
        "logical_id": host.logical_id,
        "marker_digest": "sha256:" + "f" * 64,
        "post_action_verification": {
            "filesystem_uuid_verified": True,
            "fstab_uuid_verified": True,
            "marker_verified": True,
            "mount_verified": True,
        },
        "schema_version": STORAGE_PREPARE_SCHEMA_VERSION,
        "status": "changed",
    }
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(0, _prepare_stdout(prepared), ""),
        ]
    )
    service = AnsibleService(_builder(tmp_path, paths), runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute_storage_prepare(
            lock,
            metadata,
            observed,
            inventory,
            discovery,
            preflight,
            authorization,
            limit=(host.logical_id,),
            readiness=_readiness(inventory),
        )
    assert result.storage_prepare is not None
    assert result.storage_prepare.status is StoragePrepareStatus.CHANGED
    assert result.stdout == result.stderr == ""
    assert runner.runtime_modes[-1] == 0o600
    assert "--check" not in runner.specs[-1].argv
    assert "/dev/sdb" in runner.specs[-1].sensitive_values
    assert "ocid1.instance.oc1.iad.fakescylla" in runner.specs[-1].sensitive_values
    assert not tuple(paths.ansible_local_tmp.iterdir())


def test_storage_prepare_timeout_is_redacted_and_cleans_runtime_file(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    metadata, observed, inventory, discovery, preflight = _clean_preflight()
    host = preflight.hosts[0]
    authorization = StoragePreparationAuthorization(
        uuid.UUID("22222222-2222-4222-8222-222222222222"),
        host.logical_id,
        host.preparation_intent_digest,
        storage_device_set_digest(tuple(item.stable_id for item in host.devices)),
        True,
    )
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
        ]
    )
    service = AnsibleService(_builder(tmp_path, paths), runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        runner.error = ProcessTimeoutError(
            "simulated /dev/sdb ocid1.instance.oc1.iad.fakescylla timeout"
        )
        with pytest.raises(AnsibleError, match="storage-prepare command failed"):
            service.execute_storage_prepare(
                lock,
                metadata,
                observed,
                inventory,
                discovery,
                preflight,
                authorization,
                limit=(host.logical_id,),
                readiness=_readiness(inventory),
            )
    assert "/dev/sdb" in runner.specs[-1].sensitive_values
    assert not tuple(paths.ansible_local_tmp.iterdir())


def test_parses_nvme_root_ancestry_holders_signatures_and_missing_tools() -> None:
    value = _host()
    root = _device("by-id:wwn-fake-root", path="/dev/nvme0n1")
    root.update(
        {
            "boot_ancestor": True,
            "holders": ["by-id:wwn-fake-root-part"],
            "nvme": {
                "capabilities": ["namespace-features"],
                "model": "Fake NVMe",
                "namespace_id": 1,
                "serial": "sensitive-nvme-serial",
            },
            "root_ancestor": True,
            "transport": "nvme",
        }
    )
    partition = _device("by-id:wwn-fake-root-part", path="/dev/nvme0n1p1")
    partition.update(
        {
            "filesystem": "xfs",
            "kind": "part",
            "mount_points": ["/"],
            "parents": ["by-id:wwn-fake-root"],
            "root_ancestor": True,
            "signatures": [{"kind": "filesystem", "value": "xfs"}],
            "size_bytes": 107374182400,
        }
    )
    value["devices"] = sorted([root, partition], key=lambda item: item["stable_id"])
    value["tools"]["wipefs"] = "unavailable"  # type: ignore[index]
    result = parse_storage_discovery_evidence(
        _stdout(value), _scylla_inventory(), ("scylla-ad-1-1",), 0
    )
    assert result.hosts[0].devices[1].root_ancestor
    assert ("wipefs", "unavailable") in result.hosts[0].tools


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value.update({"unexpected": True}),
        lambda value: value.update({"provider_id": "wrong"}),
        lambda value: value["devices"].append(value["devices"][0].copy()),
        lambda value: value["devices"][0].update({"path": "sdb"}),
        lambda value: value["devices"][0].update({"size_bytes": 0}),
        lambda value: value["devices"][0].update({"password": "bad"}),
    ],
)
def test_rejects_malformed_duplicate_mismatch_and_secret_like_data(
    mutator: object,
) -> None:
    value = _host()
    mutator(value)  # type: ignore[operator]
    with pytest.raises(AnsibleError):
        parse_storage_discovery_evidence(
            _stdout(value), _scylla_inventory(), ("scylla-ad-1-1",), 0
        )


def test_rejects_cyclic_topology_and_accepts_partial_failure() -> None:
    value = _host()
    second = _device("by-id:wwn-fake-two", path="/dev/sdc")
    value["devices"][0]["parents"] = [second["stable_id"]]  # type: ignore[index]
    second["parents"] = [value["devices"][0]["stable_id"]]  # type: ignore[index]
    value["devices"] = sorted(
        [value["devices"][0], second], key=lambda item: item["stable_id"]
    )  # type: ignore[index]
    with pytest.raises(AnsibleError, match="cycle"):
        parse_storage_discovery_evidence(
            _stdout(value), _scylla_inventory(), ("scylla-ad-1-1",), 0
        )
    partial = parse_storage_discovery_evidence(
        _stdout(None, failed=1), _scylla_inventory(), ("scylla-ad-1-1",), 2
    )
    assert partial.unavailable_hosts == ("scylla-ad-1-1",)


def test_service_uses_exact_scylla_limit_provenance_and_never_persists(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    inventory = _scylla_inventory()
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(0, _stdout(_host()), ""),
        ]
    )
    service = AnsibleService(_builder(tmp_path, paths), runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute(
            lock,
            _metadata(),
            inventory,
            "storage-discover",
            limit=("scylla-ad-1-1",),
            variables={},
            readiness=_readiness(inventory),
            check=True,
        )
    assert result.storage_discovery is not None
    assert result.stdout == result.stderr == ""
    assert runner.runtime_payloads[-1] == {
        "deploy_scylla_vms_cluster_uuid": str(inventory.record.cluster_uuid),
        "deploy_scylla_vms_host_manifest_digest": DIGEST,
        "deploy_scylla_vms_inventory_file_digest": DIGEST,
        "deploy_scylla_vms_inventory_generation": 1,
        "deploy_scylla_vms_observation_digest": DIGEST,
        "deploy_scylla_vms_observation_generation": 1,
    }
    assert runner.specs[-1].argv[runner.specs[-1].argv.index("--limit") + 1] == (
        "scylla-ad-1-1"
    )
    assert not paths.diagnostics_evidence.exists()


def test_packaged_module_has_only_read_only_argv_discovery() -> None:
    module = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles/storage_discover/library"
        / "storage_discover.py"
    ).read_text(encoding="utf-8")
    assert "subprocess.run(" in module
    assert "shell=True" not in module
    assert "/dev/nvme*" not in module
    assert ".glob(" not in module
    for forbidden in (
        '"/usr/bin/mount"',
        '"/usr/bin/umount"',
        '"/usr/sbin/mdadm", "--assemble"',
        '"/usr/sbin/mkfs',
        '"/usr/sbin/pvcreate"',
        '"/usr/sbin/vgchange"',
        '"/usr/sbin/wipefs", "--all"',
    ):
        assert forbidden not in module


def _postcheck_context() -> tuple[
    ClusterMetadata,
    StoredObservedState,
    StoredInventoryRecord,
    StorageDiscoveryEvidence,
    StoragePreflightResult,
    object,
    dict[str, object],
]:
    metadata, observed, inventory, discovery, preflight = _clean_preflight()
    host = preflight.hosts[0]
    device_digest = storage_device_set_digest(
        tuple(item.stable_id for item in host.devices)
    )
    preparation = parse_storage_prepare_execution(
        _prepare_stdout(
            {
                "backend": host.backend,
                "completed_steps": ["authorization-validated"],
                "device_set_digest": device_digest,
                "filesystem_uuid_digest": "sha256:" + "e" * 64,
                "irreversible_step_status": "completed",
                "layout": host.layout,
                "logical_id": host.logical_id,
                "marker_digest": "sha256:" + "f" * 64,
                "post_action_verification": {"mount_verified": True},
                "schema_version": STORAGE_PREPARE_SCHEMA_VERSION,
                "status": "changed",
            }
        ),
        expected_logical_id=host.logical_id,
        expected_backend=host.backend,
        expected_layout=host.layout,
        expected_device_set_digest=device_digest,
        exit_code=0,
    )
    payload = build_storage_postcheck_payload(
        metadata,
        observed,
        inventory,
        discovery,
        preflight,
        preparation,
        limit=(host.logical_id,),
    )
    return (
        metadata,
        observed,
        inventory,
        discovery,
        preflight,
        preparation,
        payload,
    )


def _postcheck_result(
    payload: dict[str, object], *, passed: bool = True
) -> dict[str, object]:
    check_names = (
        "capacity",
        "device-membership",
        "filesystem",
        "fstab",
        "holders",
        "marker",
        "mount",
        "permissions",
        "provenance",
        "raid",
        "signatures",
        "tools",
    )
    devices = cast(list[dict[str, object]], payload["devices"])
    provenance = {
        "device_set_digest": payload["prepare_device_set_digest"],
        "discovery_digest": payload["discovery_digest"],
        "filesystem_uuid_digest": "sha256:" + "e" * 64,
        "inventory_digest": payload["inventory_digest"],
        "marker_digest": "sha256:" + "f" * 64,
        "observation_digest": payload["observation_digest"],
        "policy_digest": payload["policy_digest"],
        "preparation_intent_digest": payload["preparation_intent_digest"],
    }
    return {
        "backend": payload["backend"],
        "blockers": [] if passed else ["mount-conflict"],
        "checks": [
            {
                "name": name,
                "status": "passed" if passed or name != "mount" else "failed",
            }
            for name in check_names
        ],
        "devices": [
            {
                "capacity_bytes": item["size_bytes"],
                "identity": item["identity"],
            }
            for item in devices
        ],
        "layout": payload["layout"],
        "logical_id": payload["logical_id"],
        "provenance": provenance,
        "readiness_for_scylla": passed,
        "schema_version": STORAGE_POSTCHECK_SCHEMA_VERSION,
    }


def test_storage_postcheck_payload_and_result_are_exact_deterministic_and_redacted() -> (
    None
):
    *_, payload = _postcheck_context()
    first = parse_storage_postcheck_execution(
        _postcheck_stdout(_postcheck_result(payload)),
        expected_payload=payload,
        exit_code=0,
    )
    second = parse_storage_postcheck_execution(
        _postcheck_stdout(_postcheck_result(payload)),
        expected_payload=payload,
        exit_code=0,
    )
    assert first == second
    assert first.readiness_for_scylla
    assert all(item.status is StorageCheckStatus.PASSED for item in first.checks)
    public = json.dumps(_postcheck_result(payload), sort_keys=True)
    assert "/dev/" not in public
    assert "ocid1." not in public
    assert "sensitive-fake" not in public


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"logical_id": "other"}, "conflicts"),
        ({"schema_version": "wrong"}, "malformed"),
        ({"readiness_for_scylla": False}, "exit status"),
        ({"blockers": ["not-allowlisted"]}, "unknown"),
    ],
)
def test_storage_postcheck_rejects_mismatch_malformed_and_status_conflicts(
    change: dict[str, object], message: str
) -> None:
    *_, payload = _postcheck_context()
    result = _postcheck_result(payload)
    result.update(change)
    with pytest.raises(AnsibleError, match=message):
        parse_storage_postcheck_execution(
            _postcheck_stdout(result),
            expected_payload=payload,
            exit_code=0,
        )
    with pytest.raises(AnsibleError, match="exceeds"):
        parse_storage_postcheck_execution(
            "x" * (512 * 1024 + 1),
            expected_payload=payload,
            exit_code=2,
        )


def test_storage_postcheck_reports_failure_and_accepts_raid0_shape() -> None:
    *_, payload = _postcheck_context()
    payload = dict(payload)
    payload["layout"] = "raid0"
    failed = _postcheck_result(payload, passed=False)
    evidence = parse_storage_postcheck_execution(
        _postcheck_stdout(failed, failed=1),
        expected_payload=payload,
        exit_code=2,
    )
    assert not evidence.readiness_for_scylla
    assert evidence.blockers == ("mount-conflict",)


def test_packaged_storage_postcheck_is_read_only_single_target_and_check_safe() -> None:
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content/playbooks"
    playbook = (root / "storage-postcheck.yml").read_text(encoding="utf-8")
    tasks = (root / "roles/storage_postcheck/tasks/main.yml").read_text(
        encoding="utf-8"
    )
    module = (root / "roles/storage_postcheck/library/storage_postcheck.py").read_text(
        encoding="utf-8"
    )
    assert "gather_facts: true" in playbook
    assert "become: true" in playbook
    assert "serial: 1" in playbook
    assert "any_errors_fatal: true" in playbook
    assert "check_mode: true" in playbook + tasks
    assert "ansible.builtin.shell" not in playbook + tasks
    assert "shell=False" in module
    assert ".glob(" not in module
    for forbidden in (
        "open('/dev/",
        'open("/dev/',
        '"--assemble"',
        '"--create"',
        '"--zero-superblock"',
        '"mkfs',
        '"/usr/bin/mount"',
        '"/usr/bin/umount"',
        '"wipefs"',
        "os.chown(",
        "os.chmod(",
        "write_bytes(",
        "write_text(",
    ):
        assert forbidden not in module


def test_service_executes_guarded_storage_postcheck_and_cleans_runtime_file(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    (
        metadata,
        observed,
        inventory,
        discovery,
        preflight,
        preparation,
        payload,
    ) = _postcheck_context()
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(0, _postcheck_stdout(_postcheck_result(payload)), ""),
        ]
    )
    service = AnsibleService(_builder(tmp_path, paths), runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute_storage_postcheck(
            lock,
            metadata,
            observed,
            inventory,
            discovery,
            preflight,
            preparation,  # type: ignore[arg-type]
            limit=("scylla-ad-1-1",),
            readiness=_readiness(inventory),
        )
    assert result.storage_postcheck is not None
    assert result.storage_postcheck.readiness_for_scylla
    assert result.stdout == result.stderr == ""
    assert "--check" in runner.specs[-1].argv
    assert runner.runtime_payloads[-1]["deploy_scylla_vms_storage_postcheck"] == payload
    assert "/dev/sdb" in runner.specs[-1].sensitive_values
    assert not tuple(paths.ansible_local_tmp.iterdir())


@pytest.mark.real_device
def test_storage_postcheck_against_real_prepared_devices_requires_explicit_harness() -> (
    None
):
    pytest.fail("real-device storage postcheck requires a separately approved harness")
