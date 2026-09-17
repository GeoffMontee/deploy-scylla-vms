import base64
import importlib.util
import inspect
import json
from pathlib import Path
from typing import Any, cast

import pytest

from scylla_vms.ansible.manager_backend_storage_preflight import (
    MANAGER_BACKEND_STORAGE_PREFLIGHT_NOT_PERFORMED,
    MANAGER_BACKEND_STORAGE_PREFLIGHT_SCHEMA_VERSION,
    ManagerBackendStoragePreflightDisposition,
    build_manager_backend_storage_preflight_payload,
    parse_manager_backend_storage_preflight_execution,
)
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.errors import AnsibleError
from scylla_vms.operations import OperationClassification

_DIGEST = "sha256:" + "a" * 64
_FIXTURE = (
    Path(__file__).parent
    / "fixtures/ansible/manager-backend-storage-preflight-result.json"
)


def _remote_module() -> Any:
    path = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles"
        / "manager_backend_storage_preflight/library"
        / "manager_backend_storage_preflight.py"
    )
    spec = importlib.util.spec_from_file_location(
        "manager_backend_storage_preflight_remote",
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
        "filesystem_uuid": None,
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


def _payload(module: Any) -> dict[str, object]:
    device = _candidate()
    provenance = {
        "ansible_source_digest": _DIGEST,
        "catalog_digest": _DIGEST,
        "discovery_evidence_digest": _DIGEST,
        "discovery_reconciliation_digest": _DIGEST,
        "inventory_digest": _DIGEST,
        "observation_digest": _DIGEST,
        "playbook_source_digest": _DIGEST,
        "preflight_context_digest": _DIGEST,
        "preflight_plan_digest": _DIGEST,
        "storage_policy_digest": _DIGEST,
        "terraform_input_digest": _DIGEST,
        "trust_digest": _DIGEST,
    }
    return {
        "backend": "block-volume",
        "capacity_policy_state": "operator-selected-allocation-conformance",
        "capacity_sufficiency_state": "not-proven",
        "discovery_device_set_digest": module._device_set_digest(device),
        "expected_device_count": 1,
        "filesystem": "xfs",
        "guest_identities": {
            "expected_by_id": "/dev/disk/by-id/obviously-fake-manager-volume",
            "expected_serial": "obviously-fake-manager-serial",
            "expected_wwn": None,
        },
        "layout": "single",
        "manifest_digest": _DIGEST,
        "mount_boundary": "fixed-scylla-data-root",
        "not_performed": list(MANAGER_BACKEND_STORAGE_PREFLIGHT_NOT_PERFORMED),
        "observed_size_gib": 256,
        "preparation_actions": [
            "create-xfs",
            "mount-scylla-data-root",
            "write-fstab",
            "write-manager-one-node-marker",
        ],
        "preparation_intent_digest": _DIGEST,
        "provenance": provenance,
        "provenance_digest": module._digest(provenance),
        "requested_size_gib": 256,
        "role": "manager",
        "role_marker": "manager-local-one-node-backend",
        "schema_version": MANAGER_BACKEND_STORAGE_PREFLIGHT_SCHEMA_VERSION,
        "stable_id": "manager-1",
        "storage_generation": 1,
        "storage_policy_digest": _DIGEST,
    }


def _stdout(result: dict[str, object], *, changed: int = 0) -> str:
    encoded = base64.b64encode(
        json.dumps(
            result,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).decode("ascii")
    return (
        f"DSV_MANAGER_BACKEND_STORAGE_PREFLIGHT_B64={encoded}\n"
        "PLAY RECAP *****\n"
        f"manager-1 : ok=3 changed={changed} unreachable=0 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )


def test_source_policy_payload_builder_and_service_are_narrow() -> None:
    definition = get_playbook("manager-backend-storage-preflight")
    assert definition.source_available
    assert definition.classification is OperationClassification.READ_ONLY
    assert definition.target_groups == ("manager",)
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.check_mode is CheckMode.SUPPORTED
    assert definition.serial == 1
    assert definition.any_errors_fatal

    signature = inspect.signature(build_manager_backend_storage_preflight_payload)
    assert tuple(signature.parameters) == (
        "metadata",
        "terraform_input",
        "observed",
        "inventory",
        "readiness",
        "discovery",
        "context",
        "plan",
    )
    for forbidden in (
        "device",
        "path",
        "action",
        "layout",
        "capacity",
        "command",
        "variable",
        "free_text",
    ):
        assert forbidden not in signature.parameters
    assert hasattr(AnsibleService, "execute_manager_backend_storage_preflight")


def test_remote_blank_signature_and_owned_layout_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _remote_module()
    payload = _payload(module)
    device = _candidate()
    facts = {"devices": [device], "fstab": (), "marker": None}
    monkeypatch.setattr(module, "_signature_state", lambda _path: "absent")

    prepare = module._evaluate(payload, facts)
    assert prepare["disposition"] == "prepare-required"
    assert prepare["wipe_required"] is False
    assert prepare["actions"] == payload["preparation_actions"]
    assert prepare["capacity_sufficiency_state"] == "not-proven"

    monkeypatch.setattr(module, "_signature_state", lambda _path: "present")
    wipe = module._evaluate(payload, facts)
    assert wipe["disposition"] == "blocked"
    assert wipe["wipe_required"] is True
    assert wipe["actions"] == []
    assert wipe["blockers"] == ["foreign-signature"]

    busy_device = dict(device)
    busy_device["holders"] = ("dm-0",)
    blocked_wipe = module._evaluate(
        payload,
        {"devices": [busy_device], "fstab": (), "marker": None},
    )
    assert blocked_wipe["disposition"] == "blocked"
    assert blocked_wipe["wipe_required"] is True
    assert blocked_wipe["actions"] == []
    assert blocked_wipe["blockers"] == ["device-busy", "foreign-signature"]

    owned_device = dict(device)
    owned_device.update(
        {
            "filesystem": "xfs",
            "filesystem_uuid": "obviously-fake-filesystem-uuid",
            "mounts": ("/var/lib/scylla",),
        }
    )
    owned = module._evaluate(
        payload,
        {
            "devices": [owned_device],
            "fstab": (
                (
                    "UUID=obviously-fake-filesystem-uuid",
                    "/var/lib/scylla",
                    "xfs",
                    ("defaults", "nofail"),
                ),
            ),
            "marker": module._expected_marker(payload),
        },
    )
    assert owned["disposition"] == "owned-noop"
    assert owned["actions"] == []
    assert owned["wipe_required"] is False


def test_remote_marker_reader_distinguishes_absence_from_invalid(
    tmp_path: Path,
) -> None:
    module = _remote_module()
    marker = tmp_path / "marker.json"
    assert module._read_json(marker) is None

    marker.write_text("{malformed", encoding="utf-8")
    assert module._read_json(marker) == {}

    marker.unlink()
    marker.symlink_to(tmp_path / "missing-target")
    assert module._read_json(marker) == {}


@pytest.mark.parametrize(
    ("device_change", "facts_change", "expected_blocker"),
    (
        ({"root_ancestor": True}, {}, "root-or-boot-device"),
        ({"holders": ("dm-0",)}, {}, "device-busy"),
        ({"children": ("sdz1",)}, {}, "device-topology-conflict"),
        ({"size_bytes": 255 * 1024**3}, {}, "device-size-conflict"),
        ({"transport": "nvme"}, {}, "device-type-conflict"),
        ({"mounts": ("/srv/foreign",)}, {}, "mount-conflict"),
        ({}, {"marker": {"schema_version": "foreign"}}, "foreign-ownership"),
        (
            {},
            {
                "fstab": (
                    (
                        "/dev/disk/by-id/wrong-volume",
                        "/var/lib/scylla",
                        "xfs",
                        ("defaults", "nofail"),
                    ),
                )
            },
            "fstab-conflict",
        ),
    ),
)
def test_remote_contract_blocks_unsafe_or_conflicting_devices(
    monkeypatch: pytest.MonkeyPatch,
    device_change: dict[str, object],
    facts_change: dict[str, object],
    expected_blocker: str,
) -> None:
    module = _remote_module()
    payload = _payload(module)
    device = _candidate()
    device.update(device_change)
    facts = {"devices": [device], "fstab": (), "marker": None}
    facts.update(facts_change)
    monkeypatch.setattr(module, "_signature_state", lambda _path: "absent")
    result = module._evaluate(payload, facts)
    assert result["disposition"] == "blocked"
    assert result["actions"] == []
    assert expected_blocker in result["blockers"]


def test_remote_contract_refuses_ambiguity_and_provenance_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _remote_module()
    payload = _payload(module)
    device = _candidate()
    duplicate = dict(device)
    duplicate["path"] = "/dev/sdy"
    monkeypatch.setattr(module, "_signature_state", lambda _path: "absent")
    ambiguous = module._evaluate(
        payload,
        {"devices": [device, duplicate], "fstab": (), "marker": None},
    )
    assert ambiguous["disposition"] == "blocked"
    assert ambiguous["blockers"] == ["ambiguous-device-match"]

    drifted = dict(payload)
    drifted["provenance_digest"] = "sha256:" + "b" * 64
    with pytest.raises(module.PreflightError, match="payload"):
        module._evaluate(
            drifted,
            {"devices": [device], "fstab": (), "marker": None},
        )


def test_parser_accepts_redacted_result_and_rejects_mutation_or_raw_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _remote_module()
    payload = _payload(module)
    monkeypatch.setattr(module, "_signature_state", lambda _path: "absent")
    result = module._evaluate(
        payload,
        {"devices": [_candidate()], "fstab": (), "marker": None},
    )
    fixture = cast(
        dict[str, object],
        json.loads(_FIXTURE.read_text(encoding="utf-8")),
    )
    assert set(fixture) == set(result)
    evidence = parse_manager_backend_storage_preflight_execution(
        _stdout(result),
        expected_payload=payload,
        exit_code=0,
    )
    assert (
        evidence.disposition
        is ManagerBackendStoragePreflightDisposition.PREPARE_REQUIRED
    )
    assert evidence.capacity_sufficiency_state == "not-proven"
    assert evidence.wipe_required is False

    public = json.dumps(
        {field: getattr(evidence, field) for field in evidence.__dataclass_fields__},
        default=str,
        sort_keys=True,
    )
    for protected in (
        "/dev/",
        "obviously-fake-manager-serial",
        "ocid1.",
        "10.0.",
        "command",
        "environment",
        "credential",
        "secret",
    ):
        assert protected not in public

    raw = dict(result)
    raw["device_path"] = "/dev/sdz"
    with pytest.raises(AnsibleError, match="schema"):
        parse_manager_backend_storage_preflight_execution(
            _stdout(raw),
            expected_payload=payload,
            exit_code=0,
        )
    with pytest.raises(AnsibleError, match="mutation"):
        parse_manager_backend_storage_preflight_execution(
            _stdout(result, changed=1),
            expected_payload=payload,
            exit_code=0,
        )
    wrong_identity = dict(result)
    wrong_identity["device_set_digest"] = _DIGEST
    with pytest.raises(AnsibleError, match="disposition"):
        parse_manager_backend_storage_preflight_execution(
            _stdout(wrong_identity),
            expected_payload=payload,
            exit_code=0,
        )

    monkeypatch.setattr(module, "_signature_state", lambda _path: "present")
    foreign_signature = module._evaluate(
        payload,
        {"devices": [_candidate()], "fstab": (), "marker": None},
    )
    foreign_signature["wipe_required"] = False
    with pytest.raises(AnsibleError, match="disposition"):
        parse_manager_backend_storage_preflight_execution(
            _stdout(foreign_signature),
            expected_payload=payload,
            exit_code=0,
        )
