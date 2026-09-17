import inspect
import json

import pytest
from test_ansible_deploy_manager_backend_storage_discovery_execution import (
    ManagerBackendStorageDiscoveryRunner,
)
from test_ansible_deploy_manager_backend_storage_discovery_execution import (
    _call as _execute,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_manager_backend_storage_discovery_execution import (
    DeployManagerBackendStorageDiscoveryArtifactState,
    deploy_manager_backend_storage_discovery_evidence_path,
)
from scylla_vms.ansible.deploy_manager_backend_storage_discovery_reconciliation import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION,
    DeployManagerBackendStorageDiscoveryBoundaryStatus,
    DeployManagerBackendStorageDiscoveryNextStatus,
    DeployManagerBackendStorageDiscoveryReconciliationStore,
    deploy_manager_backend_storage_discovery_reconciliation_path,
    reconcile_deploy_manager_backend_storage_discovery,
)
from scylla_vms.ansible.manager_backend_storage_discover import (
    ManagerBackendStorageDiscoveryStatus,
)
from scylla_vms.errors import StateConflictError, StatePersistenceError
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock

pytest_plugins = ("test_ansible_deploy_manager_backend_storage_discovery_execution",)


def _complete(
    ready_discovery,
    *,
    mode: str = "discovered",
):
    prepared, executables, toolchain = ready_discovery
    runner = ManagerBackendStorageDiscoveryRunner(mode=mode)
    _execute(prepared, runner, executables, toolchain)
    return prepared, runner


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_manager_backend_storage_discovery(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployManagerBackendStorageDiscoveryReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


def test_reconciliation_marks_only_discovery_success_and_preserves_unknowns(
    ready_discovery,
) -> None:
    signature = inspect.signature(reconcile_deploy_manager_backend_storage_discovery)
    assert tuple(signature.parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    for forbidden in (
        "target",
        "device",
        "manifest",
        "capacity",
        "evidence",
        "command",
        "variable",
        "result",
        "runner",
        "executable",
        "toolchain",
    ):
        assert forbidden not in signature.parameters

    prepared, runner = _complete(ready_discovery)
    process_count = len(runner.specs or [])
    path = deploy_manager_backend_storage_discovery_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_bytes = journal_path.read_bytes()
    prior_paths = tuple(
        item
        for item in prepared.paths.operations.iterdir()
        if item.is_file() and item != path
    )
    prior_bytes = {item: item.read_bytes() for item in prior_paths}

    report = _call(prepared)
    record = _record(prepared).record
    assert (
        report.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    assert (
        record.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION
    )
    assert (
        report.artifact_state
        is DeployManagerBackendStorageDiscoveryArtifactState.CREATED
    )
    assert record.semantic_status is ManagerBackendStorageDiscoveryStatus.DISCOVERED
    assert (
        record.discovery_boundary_status
        is DeployManagerBackendStorageDiscoveryBoundaryStatus.SUCCEEDED
    )
    assert record.journal_status is JournalStatus.IN_PROGRESS
    assert record.journal_phase is OperationPhase.VERIFY
    assert record.capacity_policy_state == "unknown"
    assert record.capacity_adequacy_state == "unknown"
    assert record.storage_preflight_source_state == "unavailable"
    assert record.storage_preflight_execution_state == "not-started"
    assert record.storage_preparation_source_state == "unavailable"
    assert record.storage_preparation_authorization_state == "unavailable"
    assert record.storage_preparation_execution_state == "not-started"
    assert record.wipe_safety_state == "not-evaluated"
    assert record.owned_noop_state == "not-inferred"
    assert record.next_boundary == "capacity-and-storage-preflight-planning"
    assert record.next_status is DeployManagerBackendStorageDiscoveryNextStatus.BLOCKED
    assert {
        "manager-backend-capacity-policy-unknown",
        "manager-backend-storage-preflight-source-unavailable",
        "manager-backend-storage-preparation-source-unavailable",
    }.issubset(record.blockers)
    assert path.stat().st_mode & 0o777 == 0o600
    assert journal_path.read_bytes() == journal_bytes
    assert {item: item.read_bytes() for item in prior_paths} == prior_bytes
    assert len(runner.specs or []) == process_count

    encoded = path.read_text(encoding="utf-8")
    for protected in (
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "/dev/",
        "serial",
        "--extra-vars",
        "deploy_scylla_vms_manager_backend_storage_discover",
        "credential",
        "secret",
    ):
        assert protected not in encoded.lower()

    artifact_bytes = path.read_bytes()
    artifact_mtime = path.stat().st_mtime_ns
    reused = _call(prepared)
    assert (
        reused.artifact_state
        is DeployManagerBackendStorageDiscoveryArtifactState.REUSED
    )
    assert path.read_bytes() == artifact_bytes
    assert path.stat().st_mtime_ns == artifact_mtime
    assert len(runner.specs or []) == process_count
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


def test_blocked_discovery_remains_blocked_without_wipe_or_noop_inference(
    ready_discovery,
) -> None:
    prepared, _runner = _complete(ready_discovery, mode="blocked")
    report = _call(prepared)
    record = _record(prepared).record
    assert report.semantic_status is ManagerBackendStorageDiscoveryStatus.BLOCKED
    assert (
        report.discovery_boundary_status
        is DeployManagerBackendStorageDiscoveryBoundaryStatus.BLOCKED
    )
    assert record.discovery_boundary_status.value == "blocked"
    assert "ambiguous-device-match" in record.blockers
    assert record.wipe_safety_state == "not-evaluated"
    assert record.owned_noop_state == "not-inferred"
    assert record.storage_preparation_authorization_state == "unavailable"


def test_reconciliation_refuses_missing_tampered_and_conflicting_prefixes(
    ready_discovery,
) -> None:
    prepared, _executables, _toolchain = ready_discovery
    with pytest.raises(StateConflictError, match="requires complete execution"):
        _call(prepared)


def test_reconciliation_and_show_refuse_tampered_evidence(
    ready_discovery,
) -> None:
    prepared, _runner = _complete(ready_discovery)
    evidence_path = deploy_manager_backend_storage_discovery_evidence_path(
        prepared.paths, OPERATION_ID
    )
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["device_count"] = 16
    evidence_path.write_text(json.dumps(evidence) + "\n", encoding="utf-8")
    evidence_path.chmod(0o600)
    with pytest.raises(StatePersistenceError):
        _call(prepared)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0


def test_reconciliation_refuses_conflicting_immutable_record(
    ready_discovery,
) -> None:
    prepared, _runner = _complete(ready_discovery)
    _call(prepared)
    path = deploy_manager_backend_storage_discovery_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    value = json.loads(path.read_text(encoding="utf-8"))
    value["owned_noop_state"] = "owned-noop"
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(StatePersistenceError):
        _call(prepared)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
