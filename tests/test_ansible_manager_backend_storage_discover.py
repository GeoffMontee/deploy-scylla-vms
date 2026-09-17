import base64
import importlib.util
import inspect
import json
from pathlib import Path
from typing import Any, cast

import pytest
from test_ansible import FakeRunner, _builder
from test_ansible_deploy_manager_backend_storage_allocation_plan import (
    _call as _plan_storage,
)
from test_ansible_deploy_manager_backend_storage_allocation_plan import (
    _records as _storage_records,
)
from test_ansible_manager_backend_preflight import _readiness
from test_provider_source import CLUSTER_UUID

from scylla_vms.ansible.manager_backend_storage_discover import (
    MANAGER_BACKEND_STORAGE_DISCOVERY_NOT_PERFORMED,
    MANAGER_BACKEND_STORAGE_DISCOVERY_SCHEMA_VERSION,
    ManagerBackendStorageDiscoveryStatus,
    ManagerBackendStorageMountStatus,
    ManagerBackendStorageOwnershipStatus,
    ManagerBackendStorageRootStatus,
    ManagerBackendStorageSignatureStatus,
    build_manager_backend_storage_discovery_payload,
    parse_manager_backend_storage_discovery_execution,
)
from scylla_vms.ansible.registry import (
    CheckMode,
    LimitPolicy,
    get_playbook,
)
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import InventoryStore
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import ObservedStateStore
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import ClusterMetadataStore
from scylla_vms.process import ProcessResult
from scylla_vms.terraform.inputs import TerraformInputStore

pytest_plugins = ("test_ansible_deploy_manager_backend_storage_allocation_plan",)

_FIXTURE = (
    Path(__file__).parent
    / "fixtures/ansible/manager-backend-storage-discover-result.json"
)
_DIGEST = "sha256:" + "a" * 64


def _payload() -> dict[str, object]:
    result = cast(
        dict[str, object],
        json.loads(_FIXTURE.read_text(encoding="utf-8")),
    )
    return {
        "backend_type": "block-volume",
        "capacity_evaluation_state": "not-evaluated",
        "capacity_policy_state": "unknown",
        "expected_device_count": 1,
        "expected_size_gib": 256,
        "guest_identity_set_digest": _DIGEST,
        "guest_identities": {
            "expected_by_id": "/dev/disk/by-id/obviously-fake-manager-volume",
            "expected_serial": "obviously-fake-serial",
            "expected_wwn": None,
        },
        "logical_id": "manager-1",
        "manifest_digest": result["manifest_digest"],
        "not_performed": list(MANAGER_BACKEND_STORAGE_DISCOVERY_NOT_PERFORMED),
        "provenance": result["provenance"],
        "role": "manager",
        "schema_version": MANAGER_BACKEND_STORAGE_DISCOVERY_SCHEMA_VERSION,
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
        f"DSV_MANAGER_BACKEND_STORAGE_DISCOVERY_B64={encoded}\n"
        "PLAY RECAP *****\n"
        f"manager-1 : ok=3 changed={changed} unreachable=0 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )


def _remote_module() -> Any:
    path = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles"
        / "manager_backend_storage_discover/library"
        / "manager_backend_storage_discover.py"
    )
    spec = importlib.util.spec_from_file_location(
        "manager_backend_storage_discover_remote",
        path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_parser_accepts_strict_redacted_success_and_refuses_ambiguity() -> None:
    payload = _payload()
    result = cast(
        dict[str, object],
        json.loads(_FIXTURE.read_text(encoding="utf-8")),
    )
    evidence = parse_manager_backend_storage_discovery_execution(
        _stdout(result),
        expected_payload=payload,
        exit_code=0,
    )
    assert evidence.status is ManagerBackendStorageDiscoveryStatus.DISCOVERED
    assert evidence.signature_status is ManagerBackendStorageSignatureStatus.ABSENT
    assert evidence.ownership_status is ManagerBackendStorageOwnershipStatus.UNOWNED
    assert evidence.mount_status is ManagerBackendStorageMountStatus.UNMOUNTED
    assert evidence.root_status is ManagerBackendStorageRootStatus.EXCLUDED
    assert evidence.device_count == 1
    assert evidence.total_size_gib == 256
    assert evidence.capacity_policy_state == "unknown"
    assert evidence.capacity_evaluation_state == "not-evaluated"

    with pytest.raises(AnsibleError, match="duplicated"):
        parse_manager_backend_storage_discovery_execution(
            _stdout(result).replace(
                "PLAY RECAP",
                _stdout(result).splitlines()[0] + "\nPLAY RECAP",
                1,
            ),
            expected_payload=payload,
            exit_code=0,
        )
    changed = dict(result)
    changed["raw_path"] = "/dev/sdz"
    with pytest.raises(AnsibleError, match="schema"):
        parse_manager_backend_storage_discovery_execution(
            _stdout(changed),
            expected_payload=payload,
            exit_code=0,
        )
    with pytest.raises(AnsibleError, match="mutation"):
        parse_manager_backend_storage_discovery_execution(
            _stdout(result, changed=1),
            expected_payload=payload,
            exit_code=0,
        )


def test_parser_failure_is_bounded_and_result_never_contains_raw_identifiers() -> None:
    payload = _payload()
    output = (
        "PLAY RECAP *****\n"
        "manager-1 : ok=0 changed=0 unreachable=1 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    evidence = parse_manager_backend_storage_discovery_execution(
        output,
        expected_payload=payload,
        exit_code=4,
    )
    assert evidence.status is ManagerBackendStorageDiscoveryStatus.FAILED
    assert evidence.blockers == ("discovery-failed",)
    public = json.dumps(
        evidence.__dict__
        if hasattr(evidence, "__dict__")
        else {
            field: getattr(evidence, field) for field in evidence.__dataclass_fields__
        },
        default=str,
        sort_keys=True,
    )
    for protected in (
        "/dev/",
        "obviously-fake-serial",
        "ocid1.",
        "10.0.",
        "command",
        "environment",
        "credential",
    ):
        assert protected not in public


def test_remote_contract_matches_exact_device_and_redacts_raw_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _remote_module()
    payload = _payload()
    candidate = {
        "boot_ancestor": False,
        "by_id": ("/dev/disk/by-id/obviously-fake-manager-volume",),
        "holders": (),
        "kind": "disk",
        "mounts": (),
        "parent": None,
        "path": "/dev/sdz",
        "root_ancestor": False,
        "serial": "obviously-fake-serial",
        "size_bytes": 256 * 1024**3,
        "transport": "virtio",
        "wwn": None,
    }
    monkeypatch.setattr(module, "_signatures", lambda _path: ("absent", ()))
    monkeypatch.setattr(module, "_ownership", lambda _mounts, _payload: "unowned")
    result = module._evaluate(payload, {"devices": [candidate]})
    assert result["status"] == "discovered"
    assert result["device_count"] == 1
    assert result["total_size_gib"] == 256
    serialized = json.dumps(result, sort_keys=True)
    for protected in (
        "/dev/",
        "obviously-fake-serial",
        "virtio",
        "provider_id",
        "command",
        "environment",
    ):
        assert protected not in serialized

    duplicate = dict(candidate)
    duplicate["path"] = "/dev/sdy"
    ambiguous = module._evaluate(payload, {"devices": [candidate, duplicate]})
    assert ambiguous["status"] == "blocked"
    assert ambiguous["device_count"] == 0
    assert ambiguous["blockers"] == ["ambiguous-device-match"]


@pytest.mark.parametrize(
    ("change", "expected_blocker"),
    (
        ({"root_ancestor": True}, "root-or-boot-device"),
        ({"mounts": ("/srv/backend",)}, "device-mounted"),
        ({"holders": ("dm-0",)}, "device-held"),
        ({"size_bytes": 255 * 1024**3}, "size-mismatch"),
        ({"kind": "part"}, "device-type-mismatch"),
    ),
)
def test_remote_contract_refuses_root_mount_size_and_type(
    monkeypatch: pytest.MonkeyPatch,
    change: dict[str, object],
    expected_blocker: str,
) -> None:
    module = _remote_module()
    payload = _payload()
    candidate = {
        "boot_ancestor": False,
        "by_id": ("/dev/disk/by-id/obviously-fake-manager-volume",),
        "holders": (),
        "kind": "disk",
        "mounts": (),
        "parent": None,
        "path": "/dev/sdz",
        "root_ancestor": False,
        "serial": "obviously-fake-serial",
        "size_bytes": 256 * 1024**3,
        "transport": "virtio",
        "wwn": None,
        **change,
    }
    monkeypatch.setattr(module, "_signatures", lambda _path: ("absent", ()))
    monkeypatch.setattr(module, "_ownership", lambda _mounts, _payload: "unowned")
    result = module._evaluate(payload, {"devices": [candidate]})
    assert result["status"] == "blocked"
    assert expected_blocker in result["blockers"]


def test_payload_builder_service_registry_check_mode_and_provenance(
    ready_storage_plan,
) -> None:
    prepared, _runner = ready_storage_plan
    _plan_storage(prepared)
    context, plan = _storage_records(prepared)
    metadata = ClusterMetadataStore(prepared.paths).read(
        expected_cluster_name="example",
        expected_cluster_uuid=CLUSTER_UUID,
        expected_provider="oci",
    )
    terraform_input = TerraformInputStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    observed = ObservedStateStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    inventory = InventoryStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    readiness = _readiness(inventory, context)
    payload = build_manager_backend_storage_discovery_payload(
        metadata.record,
        terraform_input,
        observed,
        inventory,
        readiness,
        context,
        plan,
        logical_id="manager-1",
    )
    assert payload["capacity_policy_state"] == "unknown"
    assert payload["capacity_evaluation_state"] == "not-evaluated"
    assert payload["expected_device_count"] == 1
    assert payload["expected_size_gib"] == context.record.allocation.size_gib
    assert cast(dict[str, object], payload["guest_identities"])["expected_by_id"]
    assert set(cast(dict[str, str], payload["provenance"])) == {
        "allocation_context_artifact_digest",
        "allocation_context_record_digest",
        "allocation_decision_digest",
        "allocation_plan_artifact_digest",
        "allocation_plan_digest",
        "ansible_source_digest",
        "catalog_digest",
        "inventory_digest",
        "observation_digest",
        "playbook_source_digest",
        "terraform_input_digest",
        "trust_digest",
    }

    fixture = cast(
        dict[str, object],
        json.loads(_FIXTURE.read_text(encoding="utf-8")),
    )
    fixture["manifest_digest"] = payload["manifest_digest"]
    fixture["provenance"] = payload["provenance"]
    fixture["total_size_gib"] = payload["expected_size_gib"]
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(0, _stdout(fixture), "obviously-fake-secret"),
        ]
    )
    service = AnsibleService(
        _builder(prepared.paths.state_root, prepared.paths), runner
    )
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        service.version(lock)
        execution = service.execute_manager_backend_storage_discovery(
            lock,
            metadata.record,
            terraform_input,
            observed,
            inventory,
            context,
            plan,
            limit=("manager-1",),
            readiness=readiness,
            check=True,
        )
    assert execution.check_mode
    assert execution.stdout == execution.stderr == ""
    assert execution.manager_backend_storage_discovery is not None
    assert (
        execution.manager_backend_storage_discovery.status
        is ManagerBackendStorageDiscoveryStatus.DISCOVERED
    )

    definition = get_playbook("manager-backend-storage-discover")
    assert definition.source_available
    assert definition.hosts == "manager"
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert definition.check_mode is CheckMode.SUPPORTED
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.classification is OperationClassification.READ_ONLY
    assert definition.pre_health_gate
    expected_paths = {
        "playbooks/manager-backend-storage-discover.yml",
        (
            "playbooks/roles/manager_backend_storage_discover/files/"
            "manager-backend-storage-discover.provenance.yml"
        ),
        (
            "playbooks/roles/manager_backend_storage_discover/library/"
            "manager_backend_storage_discover.py"
        ),
        "playbooks/roles/manager_backend_storage_discover/tasks/main.yml",
    }
    assert expected_paths <= {item.path for item in load_ansible_source_bundle().files}


def test_payload_refuses_context_plan_or_target_drift(ready_storage_plan) -> None:
    prepared, _runner = ready_storage_plan
    _plan_storage(prepared)
    context, plan = _storage_records(prepared)
    metadata = ClusterMetadataStore(prepared.paths).read(
        expected_cluster_name="example",
        expected_cluster_uuid=CLUSTER_UUID,
        expected_provider="oci",
    )
    terraform_input = TerraformInputStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    observed = ObservedStateStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    inventory = InventoryStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    readiness = _readiness(inventory, context)
    with pytest.raises(StateConflictError):
        build_manager_backend_storage_discovery_payload(
            metadata.record,
            terraform_input,
            observed,
            inventory,
            readiness,
            context,
            plan,
            logical_id="scylla-1",
        )

    assert tuple(
        inspect.signature(build_manager_backend_storage_discovery_payload).parameters
    ) == (
        "metadata",
        "terraform_input",
        "observed",
        "inventory",
        "readiness",
        "context",
        "plan",
        "logical_id",
    )
