import inspect
import json
from pathlib import Path
from typing import cast

import pytest
from test_ansible import FakeRunner, _builder
from test_ansible_deploy_manager_backend_storage_discovery_execution import (
    ManagerBackendStorageDiscoveryRunner,
)
from test_ansible_deploy_manager_backend_storage_discovery_execution import (
    _call as _execute_discovery,
)
from test_ansible_deploy_manager_backend_storage_discovery_reconciliation import (
    _call as _reconcile_discovery,
)
from test_ansible_manager_backend_preflight import _readiness
from test_ansible_manager_backend_storage_preflight import _stdout
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_manager_backend_storage_discovery_reconciliation import (
    DeployManagerBackendStorageDiscoveryReconciliationStore,
)
from scylla_vms.ansible.deploy_manager_backend_storage_preflight_plan import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_PLAN_SCHEMA_VERSION,
    DeployManagerBackendStoragePreflightArtifactState,
    DeployManagerBackendStoragePreflightContextStore,
    DeployManagerBackendStoragePreflightPlanStatus,
    DeployManagerBackendStoragePreflightPlanStore,
    DeployManagerBackendStoragePreflightSourceState,
    deploy_manager_backend_storage_preflight_context_path,
    deploy_manager_backend_storage_preflight_plan_path,
    plan_deploy_manager_backend_storage_preflight,
)
from scylla_vms.ansible.manager_backend_storage_preflight import (
    ManagerBackendStoragePreflightDisposition,
    build_manager_backend_storage_preflight_payload,
)
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.errors import StatePersistenceError
from scylla_vms.inventory import InventoryStore
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import ObservedStateStore
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import ClusterMetadataStore
from scylla_vms.process import ProcessResult
from scylla_vms.terraform.inputs import TerraformInputStore

pytest_plugins = (
    "test_ansible_deploy_manager_backend_storage_discovery_reconciliation",
)


@pytest.fixture
def ready_preflight_plan(ready_discovery):
    prepared, executables, toolchain = ready_discovery
    runner = ManagerBackendStorageDiscoveryRunner()
    _execute_discovery(prepared, runner, executables, toolchain)
    _reconcile_discovery(prepared)
    return prepared, runner


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return plan_deploy_manager_backend_storage_preflight(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _records(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = DeployManagerBackendStoragePreflightContextStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        plan = DeployManagerBackendStoragePreflightPlanStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    return context, plan


def test_planner_persists_exact_read_only_policy_and_reuses_without_effects(
    ready_preflight_plan,
) -> None:
    signature = inspect.signature(plan_deploy_manager_backend_storage_preflight)
    assert tuple(signature.parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    for forbidden in (
        "device",
        "path",
        "action",
        "layout",
        "capacity",
        "command",
        "variable",
        "target",
        "authorization",
        "runner",
        "free_text",
    ):
        assert forbidden not in signature.parameters

    prepared, runner = ready_preflight_plan
    process_count = len(runner.specs or ())
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_bytes = journal_path.read_bytes()
    context_path = deploy_manager_backend_storage_preflight_context_path(
        prepared.paths, OPERATION_ID
    )
    plan_path = deploy_manager_backend_storage_preflight_plan_path(
        prepared.paths, OPERATION_ID
    )

    report = _call(prepared)
    context_bytes = context_path.read_bytes()
    plan_bytes = plan_path.read_bytes()
    context_mtime = context_path.stat().st_mtime_ns
    plan_mtime = plan_path.stat().st_mtime_ns
    reused = _call(prepared)
    context, plan = _records(prepared)

    assert (
        context.record.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_CONTEXT_SCHEMA_VERSION
    )
    assert (
        plan.record.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_PLAN_SCHEMA_VERSION
    )
    assert (
        report.context_state
        is DeployManagerBackendStoragePreflightArtifactState.CREATED
    )
    assert (
        report.plan_state is DeployManagerBackendStoragePreflightArtifactState.CREATED
    )
    assert (
        reused.context_state is DeployManagerBackendStoragePreflightArtifactState.REUSED
    )
    assert reused.plan_state is DeployManagerBackendStoragePreflightArtifactState.REUSED
    assert context_path.read_bytes() == context_bytes
    assert plan_path.read_bytes() == plan_bytes
    assert context_path.stat().st_mtime_ns == context_mtime
    assert plan_path.stat().st_mtime_ns == plan_mtime
    assert context_path.stat().st_mode & 0o777 == 0o600
    assert plan_path.stat().st_mode & 0o777 == 0o600
    assert journal_path.read_bytes() == journal_bytes
    assert len(runner.specs or ()) == process_count

    policy = context.record.storage_policy
    assert policy.backend == "block-volume"
    assert policy.layout == "single"
    assert policy.expected_device_count == 1
    assert policy.filesystem == "xfs"
    assert policy.mount_boundary == "fixed-scylla-data-root"
    assert policy.fstab_policy == "required"
    assert policy.partition_policy == "forbidden"
    assert policy.raid_policy == "forbidden"
    assert policy.root_fallback_policy == "forbidden"
    assert policy.local_nvme_policy == "forbidden"
    assert policy.role_marker == "manager-local-one-node-backend"
    assert (
        policy.requested_size_gib
        == policy.observed_size_gib
        == policy.discovered_size_gib
    )
    assert policy.size_policy_state == "operator-selected-allocation-conformance"
    assert policy.capacity_sufficiency_state == "not-proven"
    assert policy.wipe_authorization_policy == "separate-explicit-proof-if-required"
    assert not policy.blockers

    assert plan.record.status is DeployManagerBackendStoragePreflightPlanStatus.ELIGIBLE
    assert (
        plan.record.source_state
        is DeployManagerBackendStoragePreflightSourceState.AVAILABLE
    )
    assert plan.record.classification is OperationClassification.READ_ONLY
    assert plan.record.authorization_state == "not-required-read-only"
    assert plan.record.execution_state == "not-started"
    assert plan.record.evidence_state == "not-performed"
    assert plan.record.mutation_state == "not-performed"
    assert plan.record.journal_status is JournalStatus.IN_PROGRESS
    assert plan.record.journal_phase is OperationPhase.VERIFY
    assert report.capacity_sufficiency_state == "not-proven"
    assert report.process_calls == 0
    assert not report.authorization_created
    assert not report.execution_started
    assert not report.mutation_performed
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0

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
    discovery = DeployManagerBackendStorageDiscoveryReconciliationStore(
        prepared.paths, OPERATION_ID
    ).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    readiness = _readiness(inventory, context)
    payload = build_manager_backend_storage_preflight_payload(
        metadata.record,
        terraform_input,
        observed,
        inventory,
        readiness,
        discovery,
        context,
        plan,
    )
    assert payload["stable_id"] == plan.record.manager_target_id
    assert payload["capacity_sufficiency_state"] == "not-proven"
    assert set(cast(dict[str, str], payload["provenance"])) == {
        "ansible_source_digest",
        "catalog_digest",
        "discovery_evidence_digest",
        "discovery_reconciliation_digest",
        "inventory_digest",
        "observation_digest",
        "playbook_source_digest",
        "preflight_context_digest",
        "preflight_plan_digest",
        "storage_policy_digest",
        "terraform_input_digest",
        "trust_digest",
    }

    fixture_path = (
        Path(__file__).parent
        / "fixtures/ansible/manager-backend-storage-preflight-result.json"
    )
    result = cast(
        dict[str, object],
        json.loads(fixture_path.read_text(encoding="utf-8")),
    )
    result.update(
        {
            "device_set_digest": payload["discovery_device_set_digest"],
            "device_size_gib": payload["observed_size_gib"],
            "observed_size_gib": payload["observed_size_gib"],
            "preparation_intent_digest": payload["preparation_intent_digest"],
            "provenance_digest": payload["provenance_digest"],
            "requested_size_gib": payload["requested_size_gib"],
            "stable_id": payload["stable_id"],
        }
    )
    service_runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(0, _stdout(result), "obviously-fake-secret"),
        ]
    )
    service = AnsibleService(
        _builder(prepared.paths.state_root, prepared.paths),
        service_runner,
    )
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        service.version(lock)
        executed = service.execute_manager_backend_storage_preflight(
            lock,
            metadata.record,
            terraform_input,
            observed,
            inventory,
            discovery,
            context,
            plan,
            limit=(plan.record.manager_target_id,),
            readiness=readiness,
            check=True,
        )
    assert executed.check_mode
    assert executed.stdout == executed.stderr == ""
    assert executed.manager_backend_storage_preflight is not None
    assert (
        executed.manager_backend_storage_preflight.disposition
        is ManagerBackendStoragePreflightDisposition.PREPARE_REQUIRED
    )


def test_context_only_prefix_recovers_and_tamper_fails_show(
    ready_preflight_plan,
) -> None:
    prepared, _runner = ready_preflight_plan
    _call(prepared)
    plan_path = deploy_manager_backend_storage_preflight_plan_path(
        prepared.paths, OPERATION_ID
    )
    plan_path.unlink()
    recovered = _call(prepared)
    assert (
        recovered.context_state
        is DeployManagerBackendStoragePreflightArtifactState.REUSED
    )
    assert (
        recovered.plan_state
        is DeployManagerBackendStoragePreflightArtifactState.CREATED
    )

    value = json.loads(plan_path.read_text(encoding="utf-8"))
    value["capacity_sufficiency_state"] = "passed"
    plan_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    plan_path.chmod(0o600)
    with pytest.raises(StatePersistenceError):
        _records(prepared)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
