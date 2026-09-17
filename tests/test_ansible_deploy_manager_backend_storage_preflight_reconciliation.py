import inspect
import json

import pytest
from test_ansible_deploy_manager_backend_storage_preflight_execution import (
    ManagerBackendStoragePreflightRunner,
)
from test_ansible_deploy_manager_backend_storage_preflight_execution import (
    _call as _execute_preflight,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_manager_backend_storage_preflight_reconciliation import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION,
    DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_FILENAME_SUFFIX,
    DeployManagerBackendStoragePreflightNextStatus,
    DeployManagerBackendStoragePreflightReconciliationStore,
    DeployManagerBackendStoragePreparationScopeState,
    deploy_manager_backend_storage_preflight_reconciliation_path,
    reconcile_deploy_manager_backend_storage_preflight,
)
from scylla_vms.ansible.manager_backend_storage_preflight import (
    ManagerBackendStoragePreflightDisposition,
)
from scylla_vms.errors import StateConflictError, StateLockError, StatePersistenceError
from scylla_vms.locking import ClusterLock

pytest_plugins = ("test_ansible_deploy_manager_backend_storage_preflight_execution",)


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_manager_backend_storage_preflight(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployManagerBackendStoragePreflightReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


def test_prepare_required_scope_reconciliation_reuse_show_and_redaction(
    ready_preflight_execution,
) -> None:
    signature = inspect.signature(reconcile_deploy_manager_backend_storage_preflight)
    assert tuple(signature.parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    for forbidden in (
        "target",
        "device",
        "path",
        "action",
        "layout",
        "capacity",
        "evidence",
        "command",
        "variable",
        "result",
        "retry",
        "runner",
        "authorization",
    ):
        assert forbidden not in signature.parameters

    prepared, executables, toolchain = ready_preflight_execution
    _execute_preflight(
        prepared,
        ManagerBackendStoragePreflightRunner(),
        executables,
        toolchain,
    )
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_bytes = journal_path.read_bytes()
    path = deploy_manager_backend_storage_preflight_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    report = _call(prepared)
    stored = _record(prepared)
    record = stored.record
    assert (
        report.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    assert (
        record.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
    )
    assert (
        record.disposition is ManagerBackendStoragePreflightDisposition.PREPARE_REQUIRED
    )
    assert (
        record.preparation_scope_state
        is DeployManagerBackendStoragePreparationScopeState.DERIVED
    )
    assert len(record.preparation_scopes) == 1
    scope = record.preparation_scopes[0]
    assert scope.stable_id == record.target_stable_id
    assert scope.disposition is record.disposition
    assert scope.device_set_digest == record.device_set_digest
    assert scope.preparation_intent_digest == record.preparation_intent_digest
    assert record.preparation_target_count == 1
    assert not record.wipe_required
    assert record.wipe_target_count == 0
    assert record.capacity_sufficiency_state == "not-proven"
    assert (
        record.next_status
        is DeployManagerBackendStoragePreflightNextStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
    )
    assert set(record.blockers) == {
        "manager-backend-storage-prepare-authorization-unavailable",
        "public-deploy-workflow-unavailable",
    }
    assert record.storage_preparation_source_state == "source-available"
    assert record.storage_preparation_authorization_state == "unavailable"
    assert record.mutation_state == "not-performed"
    assert path.stat().st_mode & 0o777 == 0o600
    assert journal_path.read_bytes() == journal_bytes
    encoded = path.read_text()
    for protected in (
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "/dev/",
        "serial",
        "command",
        "variable",
        "environment",
        "credential",
        "password",
    ):
        assert protected not in encoded.lower()

    record_bytes = path.read_bytes()
    record_mtime = path.stat().st_mtime_ns
    reused = _call(prepared)
    assert reused.artifact_state.value == "reused"
    assert path.read_bytes() == record_bytes
    assert path.stat().st_mtime_ns == record_mtime
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


@pytest.mark.parametrize(
    (
        "mode",
        "disposition",
        "scope_state",
        "next_status",
        "wipe_count",
    ),
    (
        (
            "owned-noop",
            ManagerBackendStoragePreflightDisposition.OWNED_NOOP,
            DeployManagerBackendStoragePreparationScopeState.NOT_REQUIRED,
            DeployManagerBackendStoragePreflightNextStatus.NOT_REQUIRED,
            0,
        ),
        (
            "blocked",
            ManagerBackendStoragePreflightDisposition.BLOCKED,
            DeployManagerBackendStoragePreparationScopeState.BLOCKED,
            DeployManagerBackendStoragePreflightNextStatus.BLOCKED,
            0,
        ),
        (
            "blocked-wipe",
            ManagerBackendStoragePreflightDisposition.BLOCKED,
            DeployManagerBackendStoragePreparationScopeState.BLOCKED,
            DeployManagerBackendStoragePreflightNextStatus.BLOCKED,
            1,
        ),
    ),
)
def test_disposition_and_wipe_scopes_remain_distinct(
    ready_preflight_execution,
    mode: str,
    disposition: ManagerBackendStoragePreflightDisposition,
    scope_state: DeployManagerBackendStoragePreparationScopeState,
    next_status: DeployManagerBackendStoragePreflightNextStatus,
    wipe_count: int,
) -> None:
    prepared, executables, toolchain = ready_preflight_execution
    _execute_preflight(
        prepared,
        ManagerBackendStoragePreflightRunner(mode=mode),
        executables,
        toolchain,
    )
    report = _call(prepared)
    record = _record(prepared).record
    assert report.disposition is disposition
    assert record.preparation_scope_state is scope_state
    assert record.next_status is next_status
    assert record.preparation_scopes == ()
    assert record.preparation_target_count == 0
    assert record.wipe_target_count == wipe_count
    assert len(record.wipe_target_ids) == wipe_count
    assert record.capacity_sufficiency_state == "not-proven"
    if disposition is ManagerBackendStoragePreflightDisposition.OWNED_NOOP:
        assert not record.blockers
        assert record.owned_noop_state == "not-required"
    else:
        assert "manager-backend-storage-preflight-blocked" in record.blockers
    if wipe_count:
        assert "manager-backend-storage-wipe-review-required" in record.blockers


def test_refuses_wrong_lock_ambiguity_incomplete_execution_and_tamper(
    ready_preflight_execution,
) -> None:
    prepared, executables, toolchain = ready_preflight_execution
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        reconcile_deploy_manager_backend_storage_preflight(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
        )

    with pytest.raises(StateConflictError, match="requires complete execution"):
        _call(prepared)

    _execute_preflight(
        prepared,
        ManagerBackendStoragePreflightRunner(),
        executables,
        toolchain,
    )
    ambiguous = prepared.paths.operations / (
        f"{str(OPERATION_ID).upper()}"
        f"{DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_RECONCILIATION_FILENAME_SUFFIX}"
    )
    ambiguous.write_text("{}\n", encoding="utf-8")
    ambiguous.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _call(prepared)
    ambiguous.unlink()

    _call(prepared)
    path = deploy_manager_backend_storage_preflight_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    document = json.loads(path.read_text(encoding="utf-8"))
    document["capacity_sufficiency_state"] = "passed"
    path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(StatePersistenceError):
        _call(prepared)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0


def test_upstream_drift_refuses_reconciliation_without_rewrite(
    ready_preflight_execution,
) -> None:
    prepared, executables, toolchain = ready_preflight_execution
    _execute_preflight(
        prepared,
        ManagerBackendStoragePreflightRunner(),
        executables,
        toolchain,
    )
    inventory_path = prepared.paths.ansible_inventory
    inventory_path.write_text("{}\n", encoding="utf-8")
    inventory_path.chmod(0o600)
    path = deploy_manager_backend_storage_preflight_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    with pytest.raises(StatePersistenceError):
        _call(prepared)
    assert not path.exists()
