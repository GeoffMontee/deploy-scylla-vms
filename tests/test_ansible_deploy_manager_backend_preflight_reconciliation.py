import inspect
import json
from pathlib import Path

import pytest
from test_ansible_deploy_manager_backend_preflight_execution import (
    ManagerBackendPreflightRunner,
    _prepared,
)
from test_ansible_deploy_manager_backend_preflight_execution import (
    _call as _execute,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_manager_backend_preflight_execution import (
    DeployManagerBackendPreflightArtifactState,
    deploy_manager_backend_preflight_evidence_path,
)
from scylla_vms.ansible.deploy_manager_backend_preflight_reconciliation import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION,
    DeployManagerBackendPreflightInstallationPlanningState,
    DeployManagerBackendPreflightReconciliationGateState,
    DeployManagerBackendPreflightReconciliationStore,
    deploy_manager_backend_preflight_reconciliation_path,
    reconcile_deploy_manager_backend_preflight,
)
from scylla_vms.ansible.manager_backend_preflight import (
    MANAGER_BACKEND_UNRESOLVED_BLOCKERS,
    ManagerBackendPreflightStatus,
)
from scylla_vms.errors import StateConflictError, StatePersistenceError
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock


def _complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    mode: str = "evidence-ready",
):
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = ManagerBackendPreflightRunner(mode=mode)
    _execute(prepared, runner, executables, toolchain)
    return prepared, runner


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_manager_backend_preflight(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployManagerBackendPreflightReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


def test_reconciliation_binds_success_preserves_unknowns_and_reuses_exactly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signature = inspect.signature(reconcile_deploy_manager_backend_preflight)
    assert tuple(signature.parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    for forbidden in (
        "target",
        "evidence",
        "capacity",
        "package",
        "service",
        "config",
        "command",
        "variable",
        "path",
        "result",
        "runner",
        "executable",
        "toolchain",
    ):
        assert forbidden not in signature.parameters

    prepared, runner = _complete(tmp_path, monkeypatch)
    process_count = len(runner.specs or [])
    path = deploy_manager_backend_preflight_reconciliation_path(
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
    stored = _record(prepared)
    record = stored.record
    assert report.schema_version == (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    assert record.schema_version == (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
    )
    assert report.artifact_state is DeployManagerBackendPreflightArtifactState.CREATED
    assert report.semantic_status is ManagerBackendPreflightStatus.EVIDENCE_READY
    assert (
        report.installation_planning_state
        is DeployManagerBackendPreflightInstallationPlanningState.EVIDENCE_READY
    )
    assert record.journal_status is JournalStatus.IN_PROGRESS
    assert record.journal_phase is OperationPhase.VERIFY
    assert record.backend_operational_readiness == "not-performed"
    assert record.mutation_authorization_state == "unavailable"
    assert record.mutation_execution_state == "not-started"
    assert record.public_workflow_state == "unavailable"
    assert record.next_implementation_contract == (
        "manager-backend-local-installation-plan-contract"
    )
    assert set(MANAGER_BACKEND_UNRESOLVED_BLOCKERS).issubset(record.blockers)
    by_name = {gate.name: gate for gate in record.gates}
    assert (
        by_name["host-preflight-evidence"].state
        is DeployManagerBackendPreflightReconciliationGateState.PASSED
    )
    for name in (
        "package-availability",
        "storage-suitability",
        "tuning-suitability",
        "capacity-policy",
    ):
        assert (
            by_name[name].state
            is DeployManagerBackendPreflightReconciliationGateState.UNKNOWN
        )
    for name in (
        "setup-behavior",
        "schema-keyspace-policy",
        "recovery-semantics",
        "backend-configuration-source",
    ):
        assert (
            by_name[name].state
            is DeployManagerBackendPreflightReconciliationGateState.BLOCKED
        )
    assert (
        by_name["backend-operational-readiness"].state
        is DeployManagerBackendPreflightReconciliationGateState.NOT_PERFORMED
    )
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
        "--extra-vars",
        "deploy_scylla_vms_manager_backend_preflight",
        "password",
        "credential",
    ):
        assert protected not in encoded

    artifact_bytes = path.read_bytes()
    artifact_mtime = path.stat().st_mtime_ns
    reused = _call(prepared)
    assert reused.artifact_state is DeployManagerBackendPreflightArtifactState.REUSED
    assert path.read_bytes() == artifact_bytes
    assert path.stat().st_mtime_ns == artifact_mtime
    assert len(runner.specs or []) == process_count
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


def test_blocked_semantic_evidence_remains_blocked_without_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _complete(tmp_path, monkeypatch, mode="blocked")
    report = _call(prepared)
    record = _record(prepared).record
    assert report.semantic_status is ManagerBackendPreflightStatus.BLOCKED
    assert (
        report.installation_planning_state
        is DeployManagerBackendPreflightInstallationPlanningState.BLOCKED
    )
    assert record.host_observed_blockers == ("local-scylla-package-present",)
    assert "local-scylla-package-present" in record.blockers
    host_gate = next(
        gate for gate in record.gates if gate.name == "host-preflight-evidence"
    )
    assert (
        host_gate.state is DeployManagerBackendPreflightReconciliationGateState.BLOCKED
    )
    assert host_gate.blockers == ("local-scylla-package-present",)
    assert record.mutation_authorization_state == "unavailable"


def test_reconciliation_refuses_missing_tampered_or_conflicting_prefixes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_root = tmp_path / "missing"
    missing_root.mkdir()
    prepared, _executables, _toolchain = _prepared(missing_root, monkeypatch)
    with pytest.raises(StateConflictError, match="requires complete execution"):
        _call(prepared)

    monkeypatch.undo()
    tamper_root = tmp_path / "tamper"
    tamper_root.mkdir()
    prepared, _runner = _complete(tamper_root, monkeypatch)
    evidence_path = deploy_manager_backend_preflight_evidence_path(
        prepared.paths, OPERATION_ID
    )
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["cpu_count"] = 4096
    evidence_path.write_text(json.dumps(evidence) + "\n", encoding="utf-8")
    evidence_path.chmod(0o600)
    with pytest.raises(StatePersistenceError):
        _call(prepared)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0

    monkeypatch.undo()
    conflict_root = tmp_path / "conflict"
    conflict_root.mkdir()
    prepared, _runner = _complete(conflict_root, monkeypatch)
    _call(prepared)
    path = deploy_manager_backend_preflight_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    value = json.loads(path.read_text(encoding="utf-8"))
    value["backend_operational_readiness"] = "ready"
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(StatePersistenceError):
        _call(prepared)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
