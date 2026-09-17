import base64
import importlib.util
import inspect
import json
import uuid
from pathlib import Path
from typing import Any, cast

import pytest

from scylla_vms.ansible.manager_backend_storage_prepare import (
    MANAGER_BACKEND_STORAGE_PREPARE_NOT_PERFORMED,
    MANAGER_BACKEND_STORAGE_PREPARE_SCHEMA_VERSION,
    ManagerBackendStorageMutationBoundary,
    ManagerBackendStoragePreparationAuthorization,
    ManagerBackendStoragePrepareStatus,
    build_manager_backend_storage_prepare_payload,
    parse_manager_backend_storage_prepare_execution,
)
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.errors import AnsibleError
from scylla_vms.operations import OperationClassification

_DIGEST = "sha256:" + "a" * 64
_OTHER_DIGEST = "sha256:" + "b" * 64
_FIXTURE = (
    Path(__file__).parent
    / "fixtures/ansible/manager-backend-storage-prepare-result.json"
)


def _remote_module() -> Any:
    path = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles"
        / "manager_backend_storage_prepare/library"
        / "manager_backend_storage_prepare.py"
    )
    spec = importlib.util.spec_from_file_location(
        "manager_backend_storage_prepare_remote",
        path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _candidate() -> dict[str, object]:
    return {
        "boot_ancestor": False,
        "by_id": ("/dev/disk/by-id/obviously-fake-manager-volume",),
        "children": (),
        "filesystem": None,
        "holders": (),
        "kind": "disk",
        "mounts": (),
        "path": "/dev/sdz",
        "root_ancestor": False,
        "serial": "obviously-fake-manager-serial",
        "size_bytes": 256 * 1024**3,
        "transport": "virtio",
        "wwn": None,
    }


def _payload(module: Any, *, wipe: bool = False) -> dict[str, object]:
    device = _candidate()
    provenance = {
        "ansible_source_digest": _DIGEST,
        "catalog_digest": _DIGEST,
        "desired_policy_digest": _DIGEST,
        "device_set_digest": module._device_set_digest(device),
        "inventory_digest": _DIGEST,
        "manifest_digest": _DIGEST,
        "observation_digest": _DIGEST,
        "package_reconciliation_digest": _DIGEST,
        "playbook_source_digest": _DIGEST,
        "preflight_evidence_digest": _DIGEST,
        "preflight_execution_binding_digest": _DIGEST,
        "preflight_reconciliation_digest": _DIGEST,
        "preparation_intent_digest": _DIGEST,
        "terraform_input_digest": _DIGEST,
        "trust_digest": _DIGEST,
    }
    return {
        "action": "prepare-required",
        "authorization": {
            "device_set_digest": module._device_set_digest(device),
            "operation_id": "12345678-1234-5678-9234-567812345678",
            "preparation_approved": True,
            "preparation_intent_digest": _DIGEST,
            "preparation_scope_digest": _DIGEST,
            "wipe_approved": wipe,
            "wipe_scope_digest": _OTHER_DIGEST if wipe else None,
        },
        "backend": "block-volume",
        "capacity_policy_binding": "operator-selected-allocation-conformance",
        "capacity_sufficiency_state": "not-proven",
        "check_mode_requested": False,
        "cluster_uuid": "12345678-1234-5678-9234-567812345678",
        "device_count": 1,
        "discovered_size_gib": 256,
        "disposition": "prepare-required",
        "filesystem": "xfs",
        "guest_identities": {
            "expected_by_id": "/dev/disk/by-id/obviously-fake-manager-volume",
            "expected_serial": "obviously-fake-manager-serial",
            "expected_wwn": None,
        },
        "layout": "single",
        "mount_boundary": "fixed-scylla-data-root",
        "not_performed": list(MANAGER_BACKEND_STORAGE_PREPARE_NOT_PERFORMED),
        "observed_size_gib": 256,
        "provenance": provenance,
        "provenance_digest": module._digest(provenance),
        "requested_size_gib": 256,
        "role": "manager",
        "schema_version": MANAGER_BACKEND_STORAGE_PREPARE_SCHEMA_VERSION,
        "stable_id": "manager-1",
        "storage_generation": 1,
        "storage_policy_digest": _DIGEST,
    }


def _stdout(
    result: dict[str, object],
    *,
    changed: int = 1,
    failed: int = 0,
) -> str:
    encoded = base64.b64encode(
        json.dumps(
            result,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).decode("ascii")
    return (
        f"DSV_MANAGER_BACKEND_STORAGE_PREPARE_B64={encoded}\n"
        "PLAY RECAP *****\n"
        f"manager-1 : ok=5 changed={changed} unreachable=0 failed={failed} "
        "skipped=0 rescued=0 ignored=0\n"
    )


def test_source_registry_payload_and_service_are_narrow() -> None:
    definition = get_playbook("manager-backend-storage-prepare")
    assert definition.source_available
    assert definition.classification is OperationClassification.DESTRUCTIVE
    assert definition.target_groups == ("manager",)
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.check_mode is CheckMode.REFUSED
    assert definition.serial == 1
    assert definition.any_errors_fatal

    signature = inspect.signature(build_manager_backend_storage_prepare_payload)
    assert tuple(signature.parameters) == (
        "metadata",
        "terraform_input",
        "observed",
        "inventory",
        "readiness",
        "package_reconciliation",
        "preflight_execution",
        "preflight_evidence",
        "preflight_reconciliation",
        "authorization",
        "limit",
        "check",
    )
    for forbidden in (
        "device",
        "path",
        "command",
        "variable",
        "result",
        "free_text",
    ):
        assert forbidden not in signature.parameters
    assert hasattr(AnsibleService, "execute_manager_backend_storage_prepare")


def test_authorization_keeps_wipe_consent_separate_and_digest_bound() -> None:
    operation_id = uuid.UUID("12345678-1234-5678-9234-567812345678")
    ManagerBackendStoragePreparationAuthorization(
        operation_id=operation_id,
        stable_id="manager-1",
        preparation_scope_digest=_DIGEST,
        device_set_digest=_DIGEST,
        preparation_intent_digest=_DIGEST,
        preparation_approved=True,
        wipe_approved=False,
        wipe_scope_digest=None,
    )
    with pytest.raises(AnsibleError, match="authorization"):
        ManagerBackendStoragePreparationAuthorization(
            operation_id=operation_id,
            stable_id="manager-1",
            preparation_scope_digest=_DIGEST,
            device_set_digest=_DIGEST,
            preparation_intent_digest=_DIGEST,
            preparation_approved=True,
            wipe_approved=False,
            wipe_scope_digest=_OTHER_DIGEST,
        )


def test_remote_revalidation_accepts_only_blank_exact_block_volume(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _remote_module()
    payload = _payload(module)
    monkeypatch.setattr(module, "_is_block_device", lambda _path: True)
    monkeypatch.setattr(module, "MARKER_PATH", tmp_path / "marker")
    monkeypatch.setattr(module, "_signatures", lambda _path: ())

    current = module._revalidate(
        payload,
        {"devices": [_candidate()], "fstab": ()},
    )
    assert current["path"] == "/dev/sdz"
    assert current["signatures"] == ()


@pytest.mark.parametrize(
    "change",
    (
        {"root_ancestor": True},
        {"boot_ancestor": True},
        {"transport": "nvme"},
        {"kind": "part"},
        {"holders": ("dm-0",)},
        {"children": ("sdz1",)},
        {"mounts": ("/srv/foreign",)},
        {"filesystem": "xfs"},
        {"size_bytes": 255 * 1024**3},
    ),
)
def test_remote_revalidation_refuses_unsafe_device_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    change: dict[str, object],
) -> None:
    module = _remote_module()
    payload = _payload(module)
    device = _candidate()
    device.update(change)
    monkeypatch.setattr(module, "_is_block_device", lambda _path: True)
    monkeypatch.setattr(module, "MARKER_PATH", tmp_path / "marker")
    monkeypatch.setattr(module, "_signatures", lambda _path: ())
    with pytest.raises(module.PreparationError, match="conflicts"):
        module._revalidate(payload, {"devices": [device], "fstab": ()})


def test_remote_refuses_ambiguity_foreign_ownership_and_provenance_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _remote_module()
    payload = _payload(module)
    duplicate = dict(_candidate())
    duplicate["path"] = "/dev/sdy"
    monkeypatch.setattr(module, "_is_block_device", lambda _path: True)
    monkeypatch.setattr(module, "_signatures", lambda _path: ())
    marker = tmp_path / "marker"
    monkeypatch.setattr(module, "MARKER_PATH", marker)
    with pytest.raises(module.PreparationError, match="ambiguous"):
        module._revalidate(
            payload,
            {"devices": [_candidate(), duplicate], "fstab": ()},
        )

    marker.write_text("foreign", encoding="utf-8")
    with pytest.raises(module.PreparationError, match="conflicts"):
        module._revalidate(payload, {"devices": [_candidate()], "fstab": ()})

    drifted = dict(payload)
    drifted["provenance_digest"] = _OTHER_DIGEST
    with pytest.raises(module.PreparationError, match="payload"):
        module._validate_payload(drifted)


def test_remote_wipe_requires_separate_consent_and_never_wipes_blank(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _remote_module()
    monkeypatch.setattr(module, "_is_block_device", lambda _path: True)
    monkeypatch.setattr(module, "MARKER_PATH", tmp_path / "marker")
    facts = {"devices": [_candidate()], "fstab": ()}

    monkeypatch.setattr(module, "_signatures", lambda _path: (("filesystem", "xfs"),))
    with pytest.raises(module.PreparationError, match="wipe consent"):
        module._revalidate(_payload(module), facts)
    assert module._revalidate(_payload(module, wipe=True), facts)["signatures"]

    monkeypatch.setattr(module, "_signatures", lambda _path: ())
    with pytest.raises(module.PreparationError, match="wipe consent"):
        module._revalidate(_payload(module, wipe=True), facts)
    assert module._revalidate(_payload(module), facts)["signatures"] == ()


def test_parser_accepts_redacted_success_and_rejects_check_or_raw_fields() -> None:
    module = _remote_module()
    payload = _payload(module)
    fixture = cast(
        dict[str, object],
        json.loads(_FIXTURE.read_text(encoding="utf-8")),
    )
    authorization = cast(dict[str, object], payload["authorization"])
    fixture["device_set_digest"] = authorization["device_set_digest"]
    fixture["preparation_intent_digest"] = authorization["preparation_intent_digest"]
    fixture["provenance_digest"] = payload["provenance_digest"]
    evidence = parse_manager_backend_storage_prepare_execution(
        _stdout(fixture),
        expected_payload=payload,
        exit_code=0,
    )
    assert evidence.status is ManagerBackendStoragePrepareStatus.CHANGED
    assert evidence.mutation_boundary is ManagerBackendStorageMutationBoundary.COMPLETED
    assert evidence.capacity_sufficiency_state == "not-proven"
    assert not evidence.wipe_applied

    public = json.dumps(
        {field: getattr(evidence, field) for field in evidence.__dataclass_fields__},
        default=str,
        sort_keys=True,
    )
    for protected in (
        "/dev/",
        "obviously-fake-manager-serial",
        "UUID=",
        "ocid1.",
        "10.0.",
        "command",
        "variable",
        "output",
        "environment",
        "credential",
        "secret",
    ):
        assert protected not in public

    raw = dict(fixture)
    raw["device_path"] = "/dev/sdz"
    with pytest.raises(AnsibleError, match="schema"):
        parse_manager_backend_storage_prepare_execution(
            _stdout(raw),
            expected_payload=payload,
            exit_code=0,
        )

    check_payload = dict(payload)
    check_payload["check_mode_requested"] = True
    with pytest.raises(module.PreparationError, match="payload"):
        module._validate_payload(check_payload)


def test_parser_preserves_failed_mutation_boundary_for_manual_recovery() -> None:
    module = _remote_module()
    payload = _payload(module)
    authorization = cast(dict[str, object], payload["authorization"])
    failed = cast(
        dict[str, object],
        json.loads(_FIXTURE.read_text(encoding="utf-8")),
    )
    failed.update(
        {
            "action_count": 1,
            "device_set_digest": authorization["device_set_digest"],
            "first_irreversible_step": "xfs-created",
            "fstab_status": "not-verified",
            "manual_recovery_required": True,
            "marker_status": "not-verified",
            "mount_status": "not-verified",
            "mutation_boundary": "crossed",
            "ownership_status": "not-verified",
            "preparation_intent_digest": authorization["preparation_intent_digest"],
            "provenance_digest": payload["provenance_digest"],
            "status": "failed",
            "xfs_status": "not-verified",
        }
    )
    evidence = parse_manager_backend_storage_prepare_execution(
        _stdout(failed, changed=1, failed=1),
        expected_payload=payload,
        exit_code=2,
    )
    assert evidence.status is ManagerBackendStoragePrepareStatus.FAILED
    assert evidence.manual_recovery_required
    assert evidence.mutation_boundary is ManagerBackendStorageMutationBoundary.CROSSED


def test_remote_source_revalidates_before_first_write() -> None:
    source = inspect.getsource(_remote_module()._prepare)
    revalidate = source.index("_revalidate(payload, facts)")
    wipe = source.index('"/usr/sbin/wipefs"')
    filesystem = source.index('"/usr/sbin/mkfs.xfs"')
    assert revalidate < wipe < filesystem
