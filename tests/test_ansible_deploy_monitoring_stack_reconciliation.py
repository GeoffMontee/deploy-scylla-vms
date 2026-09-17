import inspect
import json
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_monitoring_stack_execution import (
    MonitoringStackRunner,
    _prepared,
)
from test_ansible_deploy_monitoring_stack_execution import (
    _call as _execute_monitoring,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_monitoring_stack_reconciliation as reconciliation_module
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_monitoring_stack_execution import (
    DeployMonitoringStackExecutionState,
    DeployMonitoringStackExecutionStore,
)
from scylla_vms.ansible.deploy_monitoring_stack_reconciliation import (
    ANSIBLE_DEPLOY_POST_MONITORING_STACK_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_POST_MONITORING_STACK_RECONCILIATION_SCHEMA_VERSION,
    DeployPostMonitoringStackArtifactState,
    DeployPostMonitoringStackReconciliationStore,
    deploy_post_monitoring_stack_reconciliation_id_from_filename,
    deploy_post_monitoring_stack_reconciliation_path,
    reconcile_deploy_monitoring_stack_result,
)
from scylla_vms.ansible.monitoring_stack import (
    ARTIFACT_URI,
    CACHE_PATH,
    INSTALL_ROOT,
    SOURCE_COMMIT,
    STACK_VERSION,
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

_PRIVATE_PATH = "/private/operator/post-monitoring-stack.json"
_SECRET = "obviously-fake-post-monitoring-stack-secret"


def _complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str = "no-change",
):
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = MonitoringStackRunner(mode=mode)
    _execute_monitoring(prepared, runner, executables, toolchain)
    return prepared, runner


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_monitoring_stack_result(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployPostMonitoringStackReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


@pytest.mark.parametrize(
    ("mode", "changed_count", "no_change_count"),
    (("installed", 1, 0), ("no-change", 0, 1)),
)
def test_strict_success_reuse_mapping_next_gate_redaction_and_show(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    changed_count: int,
    no_change_count: int,
) -> None:
    signature = inspect.signature(reconcile_deploy_monitoring_stack_result)
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
    path = deploy_post_monitoring_stack_reconciliation_path(
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
        ANSIBLE_DEPLOY_POST_MONITORING_STACK_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    assert stored.record.schema_version == (
        ANSIBLE_DEPLOY_POST_MONITORING_STACK_RECONCILIATION_SCHEMA_VERSION
    )
    assert report.artifact_state is DeployPostMonitoringStackArtifactState.CREATED
    assert reused.artifact_state is DeployPostMonitoringStackArtifactState.REUSED
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
    assert report.no_change_count == no_change_count
    assert report.service_safe_count == 1
    assert report.listen_policy == "not-started"
    assert report.prohibited_action_count == 0
    assert report.process_calls == 0
    assert not report.authorization_created
    assert not report.execution_started

    record = stored.record
    assert record.original_mapping_count == 21
    assert record.original_mapping_unchanged
    assert tuple(step.mapping_sequence for step in record.steps) == tuple(range(1, 22))
    monitoring = next(step for step in record.steps if step.mapping_sequence == 15)
    next_step = next(step for step in record.steps if step.mapping_sequence == 16)
    assert monitoring.playbook == "monitoring-stack"
    assert monitoring.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
    assert monitoring.evidence_state == "monitoring-stack-bound"
    assert monitoring.evidence_digest == record.evidence_digest
    assert not monitoring.blockers
    assert report.next_mapping_sequence == next_step.mapping_sequence == 16
    assert report.next_playbook == next_step.playbook == "manager-agent"
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
        if step.mapping_sequence > 15
        and step.status
        in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
    )
    assert tuple(step.mapping_sequence for step in advanced) == (16,)

    public = first_bytes.decode() + json.dumps(report.to_object(), sort_keys=True)
    for protected in (
        _PRIVATE_PATH,
        _SECRET,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        ARTIFACT_URI,
        CACHE_PATH,
        INSTALL_ROOT,
        SOURCE_COMMIT,
        STACK_VERSION,
        "ansible-playbook",
        "--limit",
        '"variables"',
        '"commands"',
        "grafana_admin",
        "password",
        "PLAY RECAP",
    ):
        assert protected not in public
    assert (
        deploy_post_monitoring_stack_reconciliation_id_from_filename(path.name)
        == OPERATION_ID
    )
    assert (
        deploy_post_monitoring_stack_reconciliation_id_from_filename(
            f"uppercase-{path.name}"
        )
        is None
    )

    document = cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))
    document["record_digest"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0


def test_refuses_missing_prepared_failed_and_uncertain_prefixes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "missing"
    missing.mkdir()
    prepared, executables, toolchain = _prepared(missing, monkeypatch)
    with pytest.raises(StateConflictError, match="complete execution"):
        _call(prepared)
    monkeypatch.undo()

    prepared_root = tmp_path / "prepared"
    prepared_root.mkdir()
    prepared, executables, toolchain = _prepared(prepared_root, monkeypatch)
    original_write = DeployMonitoringStackExecutionStore.write_locked

    def refuse_start(self, record, **kwargs):
        if record.state is DeployMonitoringStackExecutionState.STARTED:
            raise StatePersistenceError("simulated refusal before invocation")
        return original_write(self, record, **kwargs)

    monkeypatch.setattr(
        DeployMonitoringStackExecutionStore, "write_locked", refuse_start
    )
    with pytest.raises(StatePersistenceError, match="before invocation"):
        _execute_monitoring(
            prepared,
            MonitoringStackRunner(),
            executables,
            toolchain,
        )
    with pytest.raises(StateConflictError, match="complete evidence"):
        _call(prepared)
    monkeypatch.undo()

    for mode in ("timeout", "failed"):
        root = tmp_path / mode
        root.mkdir()
        prepared, executables, toolchain = _prepared(root, monkeypatch)
        with pytest.raises(AnsibleError):
            _execute_monitoring(
                prepared,
                MonitoringStackRunner(mode=mode),
                executables,
                toolchain,
            )
        with pytest.raises(StateConflictError, match="complete evidence"):
            _call(prepared)
        monkeypatch.undo()


def test_refuses_evidence_tamper_source_drift_and_conflicting_reentry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _complete(tmp_path, monkeypatch)
    evidence_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-monitoring-stack-evidence.json"
    )
    original_evidence = evidence_path.read_bytes()
    for mode in ("prohibited-action", "wrong-target", "duplicate"):
        document = cast(
            dict[str, object], json.loads(original_evidence.decode("utf-8"))
        )
        entries = cast(list[dict[str, object]], document["entries"])
        if mode == "prohibited-action":
            entries[0]["auth_configured"] = True
        elif mode == "wrong-target":
            entries[0]["stable_id"] = "monitoring-wrong"
        else:
            entries.append(dict(entries[0]))
        evidence_path.write_text(
            json.dumps(document, sort_keys=True) + "\n", encoding="utf-8"
        )
        evidence_path.chmod(0o600)
        with pytest.raises((StateConflictError, StatePersistenceError)):
            _call(prepared)

    evidence_path.write_bytes(original_evidence)
    evidence_path.chmod(0o600)
    later = (
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-manager-agent-authorization.json"
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
        reconcile_deploy_monitoring_stack_result(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
        )

    monkeypatch.setattr(
        reconciliation_module,
        "_playbook_source_digest",
        lambda *_args: "sha256:" + "a" * 64,
    )
    with pytest.raises(StateConflictError, match="source"):
        _call(prepared)
    monkeypatch.undo()

    _call(prepared)
    path = deploy_post_monitoring_stack_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    document = cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))
    document["changed_count"] = 7
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(StatePersistenceError):
        _call(prepared)
