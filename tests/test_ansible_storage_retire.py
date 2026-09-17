import base64
import json
import os
import shutil
import subprocess
import uuid
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible import (
    DIGEST,
    FakeRunner,
    _builder,
    _paths,
    _readiness,
)
from test_ansible_storage import (
    _device,
    _host,
    _preflight_context,
    _stdout,
)

from scylla_vms.ansible.registry import (
    PLAYBOOKS,
    CheckMode,
    LimitPolicy,
    get_playbook,
)
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.ansible.storage import parse_storage_discovery_evidence
from scylla_vms.ansible.storage_postcheck import (
    StorageCheckStatus,
    StoragePostcheckCheck,
    StoragePostcheckEvidence,
)
from scylla_vms.ansible.storage_preflight import (
    StorageOwnershipStatus,
    reconcile_storage_preflight,
)
from scylla_vms.ansible.storage_prepare import (
    IrreversibleStepStatus as PrepareIrreversible,
)
from scylla_vms.ansible.storage_prepare import (
    StoragePrepareEvidence,
    StoragePrepareStatus,
    storage_device_set_digest,
)
from scylla_vms.ansible.storage_retire import (
    STORAGE_RETIRE_SCHEMA_VERSION,
    FirstIrreversibleStep,
    IrreversibleStepStatus,
    StorageRetirementAuthorization,
    StorageRetireStatus,
    StorageVolumeDisposition,
    build_storage_retire_payload,
    parse_storage_retire_execution,
)
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.process import ProcessResult, ProcessTimeoutError

_CHECK_NAMES = (
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


def _owned_context() -> tuple[object, ...]:
    metadata, observed, inventory, host_manifest = _preflight_context()
    value = _host()
    value["tools"]["lvm"] = "available"  # type: ignore[index]
    value["tools"]["md"] = "available"  # type: ignore[index]
    device = value["devices"][0]  # type: ignore[index]
    device.update(
        {
            "filesystem": "xfs",
            "mount_points": ["/var/lib/scylla"],
            "ownership_marker": "present",
            "signatures": [{"kind": "filesystem", "value": "xfs"}],
        }
    )
    unsigned = dict(value)
    unsigned["devices"] = [_device()]
    unsigned["devices"][0]["signatures"] = [{"kind": "filesystem", "value": "xfs"}]
    unsigned["tools"] = value["tools"]
    wipe_discovery = parse_storage_discovery_evidence(
        _stdout(unsigned), inventory, ("scylla-ad-1-1",), 0
    )
    wipe = reconcile_storage_preflight(
        metadata, observed, inventory, wipe_discovery, ("scylla-ad-1-1",)
    )
    device["ownership"] = {
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
    discovery = parse_storage_discovery_evidence(
        _stdout(value), inventory, ("scylla-ad-1-1",), 0
    )
    preflight = reconcile_storage_preflight(
        metadata, observed, inventory, discovery, ("scylla-ad-1-1",)
    )
    host = preflight.hosts[0]
    assert host.ownership_status is StorageOwnershipStatus.OWNED_NOOP
    device_digest = storage_device_set_digest(
        tuple(item.stable_id for item in host.devices)
    )
    preparation = StoragePrepareEvidence(
        host.logical_id,
        StoragePrepareStatus.CHANGED,
        host.backend,
        host.layout,
        device_digest,
        "sha256:" + "e" * 64,
        "sha256:" + "f" * 64,
        PrepareIrreversible.COMPLETED,
        ("authorization-validated", "mounted"),
        (("mount_verified", True),),
    )
    postcheck = StoragePostcheckEvidence(
        host.logical_id,
        host.backend,
        host.layout,
        True,
        tuple(
            StoragePostcheckCheck(name, StorageCheckStatus.PASSED)
            for name in _CHECK_NAMES
        ),
        (),
        tuple(sorted((item.identity, item.capacity_bytes) for item in host.devices)),
        (
            ("device_set_digest", device_digest),
            ("discovery_digest", DIGEST),
            ("inventory_digest", inventory.digest),
            ("observation_digest", observed.digest),
            ("policy_digest", host_manifest.storage.policy_digest),
            ("preparation_intent_digest", host.preparation_intent_digest),
        ),
    )
    return (
        metadata,
        observed,
        inventory,
        discovery,
        preflight,
        preparation,
        postcheck,
        host_manifest,
    )


def _authorization(
    *,
    logical_id: str,
    device_digest: str,
    disposition: StorageVolumeDisposition = StorageVolumeDisposition.RETAIN,
    approved: bool = True,
    membership_absent: bool = True,
    wipe_acknowledged: bool = False,
) -> StorageRetirementAuthorization:
    return StorageRetirementAuthorization(
        uuid.UUID("33333333-3333-4333-8333-333333333333"),
        logical_id,
        device_digest,
        disposition,
        approved,
        membership_absent,
        wipe_acknowledged,
    )


def _retire_stdout(
    result: dict[str, object], *, failed: int = 0, changed: int = 1
) -> str:
    encoded = base64.b64encode(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    return (
        'ok: [scylla-ad-1-1] => {"msg": '
        f'"DSV_STORAGE_RETIRE_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"scylla-ad-1-1 : ok=4 changed={changed} "
        f"unreachable=0 failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


def _success_result(
    payload: dict[str, object], *, wipe: bool = False
) -> dict[str, object]:
    devices = cast(list[dict[str, object]], payload["devices"])
    provenance = {
        "device_set_digest": payload["postcheck_device_set_digest"],
        "discovery_digest": payload["discovery_digest"],
        "filesystem_uuid_digest": payload["expected_filesystem_uuid_digest"],
        "inventory_digest": payload["inventory_digest"],
        "marker_digest": payload["expected_marker_digest"],
        "observation_digest": payload["observation_digest"],
        "policy_digest": payload["policy_digest"],
        "preparation_intent_digest": payload["preparation_intent_digest"],
        "trust_digest": payload["trust_digest"],
    }
    return {
        "backend": payload["backend"],
        "blockers": [],
        "completed_steps": [
            "authorization-validated",
            "service-inactive-validated",
            "immediate-rediscovery-validated",
            "ownership-verified",
            "unmounted",
            "fstab-removed",
        ],
        "device_set_digest": payload["postcheck_device_set_digest"],
        "devices": sorted(
            (
                {
                    "capacity_bytes": item["size_bytes"],
                    "identity": item["identity"],
                }
                for item in devices
            ),
            key=lambda item: item["identity"],
        ),
        "disposition": payload["authorization"]["disposition"],
        "first_irreversible_step": "unmount",
        "irreversible_step_status": "completed",
        "layout": payload["layout"],
        "logical_id": payload["logical_id"],
        "manual_recovery_required": False,
        "not_performed": list(payload["not_performed"]),
        "post_action_verification": {
            "devices_unmounted": True,
            "fstab_removed": True,
            "infrastructure_destroyed": False,
            "membership_absent": True,
            "raid_deactivated": True,
            "scylla_started": False,
            "scylla_stopped": False,
            "service_inactive": True,
            "terraform_performed": False,
            "wipe_verified": wipe,
            "writes_performed": True,
        },
        "provenance": provenance,
        "schema_version": STORAGE_RETIRE_SCHEMA_VERSION,
        "status": "changed",
        "wipe_performed": wipe,
    }


def _payload(
    disposition: StorageVolumeDisposition = StorageVolumeDisposition.RETAIN,
    *,
    wipe_acknowledged: bool | None = None,
    membership_absent: bool = True,
    check: bool = False,
) -> tuple[object, ...]:
    (
        metadata,
        observed,
        inventory,
        discovery,
        preflight,
        preparation,
        postcheck,
        _,
    ) = _owned_context()
    host = preflight.hosts[0]
    device_digest = storage_device_set_digest(
        tuple(item.stable_id for item in host.devices)
    )
    if wipe_acknowledged is None:
        wipe_acknowledged = disposition is StorageVolumeDisposition.DELETE
    payload = build_storage_retire_payload(
        metadata,
        observed,
        inventory,
        discovery,
        preflight,
        preparation,
        postcheck,
        _authorization(
            logical_id=host.logical_id,
            device_digest=device_digest,
            disposition=disposition,
            membership_absent=membership_absent,
            wipe_acknowledged=wipe_acknowledged,
        ),
        _readiness(inventory),
        limit=(host.logical_id,),
        check=check,
    )
    return (
        metadata,
        observed,
        inventory,
        discovery,
        preflight,
        preparation,
        postcheck,
        payload,
    )


def test_storage_retire_registry_source_and_package_parity() -> None:
    definition = get_playbook("storage-retire")
    assert definition.source_available
    assert definition.hosts == "scylla"
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert definition.check_mode is CheckMode.REFUSED
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.classification is OperationClassification.DESTRUCTIVE
    assert definition.tags == ("storage", "retire")
    assert callable(AnsibleService.execute_storage_retire)
    assert {book.name for book in PLAYBOOKS if book.source_available} >= {
        "storage-retire"
    }
    bundle_paths = {item.path for item in load_ansible_source_bundle().files}
    assert {
        "playbooks/storage-retire.yml",
        "playbooks/roles/storage_retire/library/storage_retire.py",
        "playbooks/roles/storage_retire/tasks/main.yml",
    } <= bundle_paths
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content/playbooks"
    playbook = (root / "storage-retire.yml").read_text(encoding="utf-8")
    tasks = (root / "roles/storage_retire/tasks/main.yml").read_text(encoding="utf-8")
    module = (root / "roles/storage_retire/library/storage_retire.py").read_text(
        encoding="utf-8"
    )
    assert "gather_facts: true" in playbook
    assert "serial: 1" in playbook
    assert "any_errors_fatal: true" in playbook
    assert "hosts: scylla" in playbook
    assert "not ansible_check_mode" in playbook
    assert "ansible.builtin.shell" not in playbook + tasks
    assert ".glob(" not in module
    assert "/dev/nvme*" not in module
    assert "shell=False" in module
    assert "authorization-validated" in module
    assert module.index("_immediate_revalidate(intent)") < module.index(
        'COMMANDS["umount"]'
    )
    assert '"--stop"' in module
    assert 'COMMANDS["wipefs"], "--all"' in module
    assert '"/var/lib/scylla"' in module
    assert "terraform" in module.lower()
    assert "scylla-server" in module


def test_storage_retire_builds_retain_payload_without_wipe() -> None:
    *_, payload = _payload()
    assert payload["schema_version"] == STORAGE_RETIRE_SCHEMA_VERSION
    assert payload["classification"] == "owned-noop"
    assert payload["wipe_required"] is False
    assert payload["authorization"]["wipe_acknowledged"] is False
    assert payload["authorization"]["membership_absent"] is True
    assert "wipe" in payload["not_performed"]
    assert payload["devices"][0]["path"] == "/dev/sdb"
    public = json.dumps(
        {
            "devices": [
                {"identity": item["identity"], "capacity_bytes": item["size_bytes"]}
                for item in payload["devices"]
            ]
        }
    )
    assert "/dev/" not in public
    assert "ocid1" not in public


def test_storage_retire_refuses_non_scylla_and_multi_target() -> None:
    (
        metadata,
        observed,
        inventory,
        discovery,
        preflight,
        preparation,
        postcheck,
        _,
    ) = _owned_context()
    host = preflight.hosts[0]
    device_digest = storage_device_set_digest(
        tuple(item.stable_id for item in host.devices)
    )
    authorization = _authorization(
        logical_id=host.logical_id, device_digest=device_digest
    )
    with pytest.raises(StateConflictError, match="one exact authorized target"):
        build_storage_retire_payload(
            metadata,
            observed,
            inventory,
            discovery,
            preflight,
            preparation,
            postcheck,
            authorization,
            _readiness(inventory),
            limit=(host.logical_id, "scylla-ad-1-2"),
            check=False,
        )
    with pytest.raises(StateConflictError, match="not a Scylla stable ID"):
        build_storage_retire_payload(
            metadata,
            observed,
            inventory,
            discovery,
            preflight,
            preparation,
            postcheck,
            _authorization(logical_id="jump-host-1", device_digest=device_digest),
            _readiness(inventory),
            limit=("jump-host-1",),
            check=False,
        )


def test_storage_retire_refuses_stale_missing_and_unprepared_evidence() -> None:
    (
        metadata,
        observed,
        inventory,
        discovery,
        preflight,
        preparation,
        postcheck,
        _,
    ) = _owned_context()
    host = preflight.hosts[0]
    device_digest = storage_device_set_digest(
        tuple(item.stable_id for item in host.devices)
    )
    authorization = _authorization(
        logical_id=host.logical_id, device_digest=device_digest
    )
    stale_readiness = replace(
        _readiness(inventory), inventory_digest="sha256:" + "b" * 64
    )
    with pytest.raises(StateConflictError, match="readiness provenance"):
        build_storage_retire_payload(
            metadata,
            observed,
            inventory,
            discovery,
            preflight,
            preparation,
            postcheck,
            authorization,
            stale_readiness,
            limit=(host.logical_id,),
            check=False,
        )
    from test_ansible_storage import _clean_preflight

    clean = _clean_preflight()
    with pytest.raises(StateConflictError, match="previously prepared"):
        build_storage_retire_payload(
            clean[0],
            clean[1],
            clean[2],
            clean[3],
            clean[4],
            preparation,
            postcheck,
            _authorization(
                logical_id=clean[4].hosts[0].logical_id,
                device_digest=storage_device_set_digest(
                    tuple(item.stable_id for item in clean[4].hosts[0].devices)
                ),
            ),
            _readiness(clean[2]),
            limit=(clean[4].hosts[0].logical_id,),
            check=False,
        )
    unreadiness = StoragePostcheckEvidence(
        postcheck.logical_id,
        postcheck.backend,
        postcheck.layout,
        False,
        postcheck.checks,
        ("mount-conflict",),
        postcheck.devices,
        postcheck.provenance,
    )
    with pytest.raises(StateConflictError, match="postcheck is not current"):
        build_storage_retire_payload(
            metadata,
            observed,
            inventory,
            discovery,
            preflight,
            preparation,
            unreadiness,
            authorization,
            _readiness(inventory),
            limit=(host.logical_id,),
            check=False,
        )


def test_storage_retire_refuses_still_member_and_wipe_consent_mismatch() -> None:
    (
        metadata,
        observed,
        inventory,
        discovery,
        preflight,
        preparation,
        postcheck,
        _,
    ) = _owned_context()
    host = preflight.hosts[0]
    device_digest = storage_device_set_digest(
        tuple(item.stable_id for item in host.devices)
    )
    with pytest.raises(StateConflictError, match="membership absence"):
        build_storage_retire_payload(
            metadata,
            observed,
            inventory,
            discovery,
            preflight,
            preparation,
            postcheck,
            _authorization(
                logical_id=host.logical_id,
                device_digest=device_digest,
                membership_absent=False,
            ),
            _readiness(inventory),
            limit=(host.logical_id,),
            check=False,
        )
    with pytest.raises(StateConflictError, match="wipe requires"):
        build_storage_retire_payload(
            metadata,
            observed,
            inventory,
            discovery,
            preflight,
            preparation,
            postcheck,
            _authorization(
                logical_id=host.logical_id,
                device_digest=device_digest,
                disposition=StorageVolumeDisposition.DELETE,
                wipe_acknowledged=False,
            ),
            _readiness(inventory),
            limit=(host.logical_id,),
            check=False,
        )
    with pytest.raises(StateConflictError, match="not applicable"):
        build_storage_retire_payload(
            metadata,
            observed,
            inventory,
            discovery,
            preflight,
            preparation,
            postcheck,
            _authorization(
                logical_id=host.logical_id,
                device_digest=device_digest,
                wipe_acknowledged=True,
            ),
            _readiness(inventory),
            limit=(host.logical_id,),
            check=False,
        )


def test_storage_retire_refuses_device_identity_mismatch() -> None:
    (
        metadata,
        observed,
        inventory,
        discovery,
        preflight,
        preparation,
        postcheck,
        _,
    ) = _owned_context()
    host = preflight.hosts[0]
    with pytest.raises(StateConflictError, match="device set"):
        build_storage_retire_payload(
            metadata,
            observed,
            inventory,
            discovery,
            preflight,
            preparation,
            postcheck,
            _authorization(
                logical_id=host.logical_id,
                device_digest="sha256:" + "d" * 64,
            ),
            _readiness(inventory),
            limit=(host.logical_id,),
            check=False,
        )


def test_parses_success_failure_check_mode_and_redacts_public_fields() -> None:
    *_, payload = _payload()
    evidence = parse_storage_retire_execution(
        _retire_stdout(_success_result(payload)),
        expected_payload=payload,
        exit_code=0,
    )
    assert evidence.status is StorageRetireStatus.CHANGED
    assert evidence.first_irreversible_step is FirstIrreversibleStep.UNMOUNT
    assert evidence.irreversible_step_status is IrreversibleStepStatus.COMPLETED
    assert evidence.wipe_performed is False
    assert "wipe" in evidence.not_performed
    assert "ocid1" not in repr(evidence)
    assert "/dev/sdb" not in repr(evidence)
    failed = _success_result(payload)
    failed["status"] = "failed"
    failed["irreversible_step_status"] = "started"
    failed["manual_recovery_required"] = True
    failed["blockers"] = ["execution-failed"]
    failed["post_action_verification"] = {
        "infrastructure_destroyed": False,
        "scylla_started": False,
        "scylla_stopped": False,
        "terraform_performed": False,
        "writes_performed": True,
    }
    parsed_failed = parse_storage_retire_execution(
        _retire_stdout(failed, failed=1, changed=0),
        expected_payload=payload,
        exit_code=2,
    )
    assert parsed_failed.status is StorageRetireStatus.FAILED
    assert parsed_failed.manual_recovery_required
    predicted = _success_result(payload)
    predicted.update(
        {
            "status": "not-predicted",
            "first_irreversible_step": "none",
            "irreversible_step_status": "not-started",
            "wipe_performed": False,
            "completed_steps": ["authorization-validated"],
            "blockers": ["check-mode-refused"],
            "post_action_verification": {"writes_performed": False},
        }
    )
    parsed_check = parse_storage_retire_execution(
        _retire_stdout(predicted, changed=0),
        expected_payload=payload,
        exit_code=0,
    )
    assert parsed_check.status is StorageRetireStatus.NOT_PREDICTED
    service_active = dict(failed)
    service_active["blockers"] = [
        "active-data-claimed",
        "service-active",
        "still-member",
    ]
    service_active["irreversible_step_status"] = "not-started"
    service_active["manual_recovery_required"] = False
    service_active["post_action_verification"] = {
        "infrastructure_destroyed": False,
        "scylla_started": False,
        "scylla_stopped": False,
        "terraform_performed": False,
        "writes_performed": False,
    }
    parsed_active = parse_storage_retire_execution(
        _retire_stdout(service_active, failed=1, changed=0),
        expected_payload=payload,
        exit_code=2,
    )
    assert "service-active" in parsed_active.blockers
    assert "still-member" in parsed_active.blockers
    malformed = _success_result(payload)
    malformed["provider_id"] = "must-not-be-public"
    with pytest.raises(AnsibleError, match="malformed"):
        parse_storage_retire_execution(
            _retire_stdout(malformed),
            expected_payload=payload,
            exit_code=0,
        )


def test_service_executes_authorized_storage_retire_and_cleans_vars(
    tmp_path: Path,
) -> None:
    (
        metadata,
        observed,
        inventory,
        discovery,
        preflight,
        preparation,
        postcheck,
        payload,
    ) = _payload()
    host = preflight.hosts[0]
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(0, _retire_stdout(_success_result(payload)), ""),
        ]
    )
    paths = _paths(tmp_path)
    service = AnsibleService(_builder(tmp_path, paths), runner)
    device_digest = storage_device_set_digest(
        tuple(item.stable_id for item in host.devices)
    )
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute_storage_retire(
            lock,
            metadata,
            observed,
            inventory,
            discovery,
            preflight,
            preparation,
            postcheck,
            _authorization(logical_id=host.logical_id, device_digest=device_digest),
            limit=(host.logical_id,),
            readiness=_readiness(inventory),
        )
    assert result.storage_retire is not None
    assert result.storage_retire.status is StorageRetireStatus.CHANGED
    assert result.stdout == result.stderr == ""
    assert runner.runtime_modes[-1] == 0o600
    assert "--check" not in runner.specs[-1].argv
    assert "/dev/sdb" in runner.specs[-1].sensitive_values
    assert "ocid1.instance.oc1.iad.fakescylla" in runner.specs[-1].sensitive_values
    assert not tuple(paths.ansible_local_tmp.iterdir())


def test_storage_retire_timeout_is_redacted_and_cleans_runtime_file(
    tmp_path: Path,
) -> None:
    (
        metadata,
        observed,
        inventory,
        discovery,
        preflight,
        preparation,
        postcheck,
        _,
    ) = _owned_context()
    host = preflight.hosts[0]
    paths = _paths(tmp_path)
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
        with pytest.raises(AnsibleError, match="storage-retire command failed"):
            service.execute_storage_retire(
                lock,
                metadata,
                observed,
                inventory,
                discovery,
                preflight,
                preparation,
                postcheck,
                _authorization(
                    logical_id=host.logical_id,
                    device_digest=storage_device_set_digest(
                        tuple(item.stable_id for item in host.devices)
                    ),
                ),
                limit=(host.logical_id,),
                readiness=_readiness(inventory),
            )
    assert "/dev/sdb" in runner.specs[-1].sensitive_values
    assert not tuple(paths.ansible_local_tmp.iterdir())


def test_builder_refuses_storage_retire_check_mode(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    builder = _builder(tmp_path, paths)
    runtime = paths.ansible_local_tmp / "extra-vars-test.json"
    runtime.write_text("{}\n", encoding="utf-8")
    runtime.chmod(0o600)
    with pytest.raises(AnsibleError, match="check mode is refused"):
        builder.playbook(
            "storage-retire",
            limit=("scylla-ad-1-1",),
            extra_vars_path=runtime,
            check=True,
        )


def test_delete_disposition_requires_wipe_and_omits_wipe_from_not_performed() -> None:
    *_, payload = _payload(StorageVolumeDisposition.DELETE)
    assert payload["wipe_required"] is True
    assert payload["authorization"]["wipe_acknowledged"] is True
    assert "wipe" not in payload["not_performed"]
    evidence = parse_storage_retire_execution(
        _retire_stdout(_success_result(payload, wipe=True)),
        expected_payload=payload,
        exit_code=0,
    )
    assert evidence.wipe_performed is True
    assert evidence.disposition is StorageVolumeDisposition.DELETE


def test_storage_retire_playbook_syntax_check_is_local_and_write_free(
    tmp_path: Path,
) -> None:
    executable = shutil.which("ansible-playbook")
    if executable is None:
        pytest.skip("Ansible development executable is unavailable")
    playbook = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/storage-retire.yml"
    )
    local_tmp = tmp_path / "ansible-tmp"
    local_tmp.mkdir()
    result = subprocess.run(
        [
            executable,
            "--syntax-check",
            "-i",
            "localhost,",
            str(playbook),
        ],
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="strict",
        timeout=30,
        env={
            **os.environ,
            "ANSIBLE_LOCAL_TEMP": str(local_tmp),
            "HOME": str(tmp_path),
        },
    )
    assert result.returncode == 0, result.stderr
    assert "playbook: " in result.stdout
    assert not tuple(local_tmp.iterdir())
