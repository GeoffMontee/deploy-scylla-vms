import inspect
import json
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_monitoring_agent_execution import (
    MonitoringAgentRunner,
    _prepared,
    _prepared_multi,
)
from test_ansible_deploy_monitoring_agent_execution import _call as _execute_agent
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_monitoring_agent_reconciliation as reconciliation_module
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_monitoring_agent_reconciliation import (
    ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_SCHEMA_VERSION,
    DeployPostMonitoringAgentArtifactState,
    DeployPostMonitoringAgentReconciliationStore,
    deploy_post_monitoring_agent_reconciliation_id_from_filename,
    deploy_post_monitoring_agent_reconciliation_path,
    reconcile_deploy_monitoring_agent_result,
)
from scylla_vms.ansible.scylla_install import (
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_REPOSITORY_URI,
)
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification

_PRIVATE_PATH = "/private/operator/post-monitoring-agent.json"
_SECRET = "obviously-fake-post-monitoring-agent-secret"


def _complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str = "no-change",
):
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = MonitoringAgentRunner(mode=mode)
    _execute_agent(prepared, runner, executables, toolchain)
    return prepared, runner


def _complete_multi(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    prepared, executables, toolchain = _prepared_multi(tmp_path, monkeypatch)
    runner = MonitoringAgentRunner()
    _execute_agent(prepared, runner, executables, toolchain)
    return prepared, runner


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_monitoring_agent_result(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployPostMonitoringAgentReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


@pytest.mark.parametrize(
    ("mode", "changed_count"),
    (("installed", 1), ("no-change", 0)),
)
def test_success_reuse_mapping_next_gate_redaction_and_show(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    changed_count: int,
) -> None:
    signature = inspect.signature(reconcile_deploy_monitoring_agent_result)
    assert tuple(signature.parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    for forbidden in (
        "result",
        "status",
        "step",
        "target",
        "path",
        "runner",
        "command",
        "variable",
    ):
        assert forbidden not in signature.parameters

    prepared, runner = _complete(tmp_path, monkeypatch, mode)
    assert runner.specs is not None
    process_count = len(runner.specs)
    path = deploy_post_monitoring_agent_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    prior_paths = tuple(
        item
        for item in prepared.paths.operations.iterdir()
        if item != path and item.is_file()
    )
    prior_bytes = {item: item.read_bytes() for item in prior_paths}
    show_before = _run_show(prepared.paths, "--fail-on", "none")

    report = _call(prepared)
    first_bytes = path.read_bytes()
    reused = _call(prepared)
    stored = _record(prepared)

    assert report.schema_version == (
        ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    assert stored.record.schema_version == (
        ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_SCHEMA_VERSION
    )
    assert report.artifact_state is DeployPostMonitoringAgentArtifactState.CREATED
    assert reused.artifact_state is DeployPostMonitoringAgentArtifactState.REUSED
    assert path.read_bytes() == first_bytes
    assert path.stat().st_mode & 0o777 == 0o600
    assert len(runner.specs) == process_count
    assert _run_show(prepared.paths, "--fail-on", "none") == show_before
    assert journal_path.read_bytes() == prior_bytes[journal_path]
    assert {item: item.read_bytes() for item in prior_paths} == prior_bytes
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert report.target_count == report.installed_count == 1
    assert report.changed_count == changed_count
    assert report.no_change_count == 1 - changed_count
    assert report.service_safe_count == 1
    assert report.listen_safe_count == 1
    assert report.prohibited_action_count == 0
    assert report.process_calls == 0
    assert not report.authorization_created
    assert not report.execution_started

    record = stored.record
    assert record.original_mapping_count == 21
    assert record.original_mapping_unchanged
    assert tuple(step.mapping_sequence for step in record.steps) == tuple(range(1, 22))
    agent = next(step for step in record.steps if step.mapping_sequence == 17)
    next_step = next(step for step in record.steps if step.mapping_sequence == 18)
    assert agent.playbook == "monitoring-agent"
    assert agent.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
    assert agent.evidence_state == "monitoring-agent-bound"
    assert agent.evidence_digest == record.evidence_set_digest
    assert not agent.blockers
    assert report.next_mapping_sequence == next_step.mapping_sequence == 18
    assert report.next_playbook == next_step.playbook == "monitoring-targets"
    assert (
        report.next_classification
        is next_step.classification
        is OperationClassification.MUTATING
    )
    assert (
        report.next_step_status
        is next_step.status
        is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
    )
    assert next_step.evidence_state == "next-gates-evaluated"
    assert set(next_step.blockers) == {
        "deploy-authorization-not-collected",
        "mutating-deploy-execution-unavailable",
        "public-deploy-workflow-unavailable",
    }
    advanced = tuple(
        step
        for step in record.steps
        if step.mapping_sequence > 17
        and step.status
        in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
    )
    assert tuple(step.mapping_sequence for step in advanced) == (18,)

    public = first_bytes.decode() + json.dumps(report.to_object(), sort_keys=True)
    for protected in (
        _PRIVATE_PATH,
        _SECRET,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        SCYLLA_PACKAGE_VERSION,
        SCYLLA_REPOSITORY_URI,
        '"9100"',
        "ansible-playbook",
        "--limit",
        '"variables"',
        '"commands"',
        "password",
        "PLAY RECAP",
    ):
        assert protected not in public
    assert (
        deploy_post_monitoring_agent_reconciliation_id_from_filename(path.name)
        == OPERATION_ID
    )
    assert (
        deploy_post_monitoring_agent_reconciliation_id_from_filename(
            f"uppercase-{path.name}"
        )
        is None
    )

    document = cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))
    document["record_digest"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0


def test_multi_target_complete_order_and_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _complete_multi(tmp_path, monkeypatch)
    report = _call(prepared)
    stored = _record(prepared)

    assert runner.payloads is not None
    ordered = tuple(cast(str, payload["logical_id"]) for payload in runner.payloads)
    assert ordered == tuple(sorted(ordered))
    assert report.target_count == report.installed_count == len(ordered) == 2
    assert report.changed_count == 0
    assert report.no_change_count == 2
    assert report.service_safe_count == 2
    assert report.listen_safe_count == 2
    assert stored.record.target_set_digest == report.target_set_digest
    agent = next(step for step in stored.record.steps if step.mapping_sequence == 17)
    assert agent.target_ids == ordered
    assert stored.record.evidence_generation == 2


def test_refuses_missing_failed_uncertain_tamper_drift_and_later_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "missing"
    missing.mkdir()
    prepared, _executables, _toolchain = _prepared(missing, monkeypatch)
    with pytest.raises(StateConflictError, match="complete execution"):
        _call(prepared)
    monkeypatch.undo()

    failed = tmp_path / "failed"
    failed.mkdir()
    prepared, executables, toolchain = _prepared(failed, monkeypatch)
    with pytest.raises(AnsibleError):
        _execute_agent(
            prepared,
            MonitoringAgentRunner(mode="failed"),
            executables,
            toolchain,
        )
    with pytest.raises(StateConflictError, match="complete evidence"):
        _call(prepared)
    monkeypatch.undo()

    complete = tmp_path / "complete"
    complete.mkdir()
    prepared, _runner = _complete(complete, monkeypatch)
    evidence_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-monitoring-agent-evidence.json"
    )
    original_evidence = evidence_path.read_bytes()
    document = cast(dict[str, object], json.loads(original_evidence.decode("utf-8")))
    entries = cast(list[dict[str, object]], document["entries"])
    entries[0]["targets_generated"] = True
    evidence_path.write_text(
        json.dumps(document, sort_keys=True) + "\n", encoding="utf-8"
    )
    evidence_path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    evidence_path.write_bytes(original_evidence)
    evidence_path.chmod(0o600)

    original_source_digest = reconciliation_module._playbook_source_digest
    monkeypatch.setattr(
        reconciliation_module,
        "_playbook_source_digest",
        lambda *_args: "sha256:" + "a" * 64,
    )
    with pytest.raises(StateConflictError, match="source"):
        _call(prepared)
    monkeypatch.setattr(
        reconciliation_module,
        "_playbook_source_digest",
        original_source_digest,
    )

    inventory_path = prepared.paths.ansible_inventory
    original_inventory = inventory_path.read_bytes()
    inventory_path.write_bytes(original_inventory + b" ")
    inventory_path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    inventory_path.write_bytes(original_inventory)
    inventory_path.chmod(0o600)

    later = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-monitoring-targets-authorization.json"
    )
    later.write_text("{}\n", encoding="utf-8")
    later.chmod(0o600)
    with pytest.raises(StateConflictError, match="later-stage history"):
        _call(prepared)
    later.unlink()

    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        reconcile_deploy_monitoring_agent_result(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
        )

    _call(prepared)
    path = deploy_post_monitoring_agent_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    document = cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))
    document["changed_count"] = 7
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(StatePersistenceError):
        _call(prepared)
