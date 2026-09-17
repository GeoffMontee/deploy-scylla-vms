import inspect
import json
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_manager_server_execution import (
    ManagerServerRunner,
    _prepared,
)
from test_ansible_deploy_manager_server_execution import (
    _call as _execute_manager,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_manager_server_reconciliation as reconciliation_module
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_manager_server_execution import (
    DeployManagerServerExecutionState,
    DeployManagerServerExecutionStore,
)
from scylla_vms.ansible.deploy_manager_server_reconciliation import (
    ANSIBLE_DEPLOY_POST_MANAGER_SERVER_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_POST_MANAGER_SERVER_RECONCILIATION_SCHEMA_VERSION,
    DeployPostManagerServerArtifactState,
    DeployPostManagerServerReconciliationStore,
    deploy_post_manager_server_reconciliation_id_from_filename,
    deploy_post_manager_server_reconciliation_path,
    reconcile_deploy_manager_server_result,
)
from scylla_vms.ansible.manager_server import (
    MANAGER_PACKAGE_VERSION,
    MANAGER_REPOSITORY_URI,
)
from scylla_vms.ansible.scylla_install import SCYLLA_SIGNING_KEY_FINGERPRINT
from scylla_vms.errors import AnsibleError, StateConflictError, StatePersistenceError
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification

_PRIVATE_PATH = "/private/operator/post-manager-server.json"
_SECRET = "obviously-fake-post-manager-server-secret"


def _complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str = "no-change",
):
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = ManagerServerRunner(mode=mode)
    _execute_manager(prepared, runner, executables, toolchain)
    return prepared, runner


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_manager_server_result(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployPostManagerServerReconciliationStore(
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
    assert tuple(
        inspect.signature(reconcile_deploy_manager_server_result).parameters
    ) == ("state_root", "cluster_name", "operation_id", "lock")
    prepared, runner = _complete(tmp_path, monkeypatch, mode)
    assert runner.specs is not None
    process_count = len(runner.specs)
    path = deploy_post_manager_server_reconciliation_path(prepared.paths, OPERATION_ID)
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
        ANSIBLE_DEPLOY_POST_MANAGER_SERVER_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    assert stored.record.schema_version == (
        ANSIBLE_DEPLOY_POST_MANAGER_SERVER_RECONCILIATION_SCHEMA_VERSION
    )
    assert report.artifact_state is DeployPostManagerServerArtifactState.CREATED
    assert reused.artifact_state is DeployPostManagerServerArtifactState.REUSED
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
    assert report.prohibited_action_count == 0
    assert report.process_calls == 0
    assert not report.authorization_created
    assert not report.execution_started

    record = stored.record
    assert record.original_mapping_count == 21
    assert record.original_mapping_unchanged
    assert tuple(step.mapping_sequence for step in record.steps) == tuple(range(1, 22))
    manager = next(step for step in record.steps if step.mapping_sequence == 14)
    next_step = next(step for step in record.steps if step.mapping_sequence == 15)
    assert manager.playbook == "manager-server"
    assert manager.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
    assert manager.evidence_state == "manager-server-bound"
    assert manager.evidence_digest == record.evidence_digest
    assert not manager.blockers
    assert report.next_mapping_sequence == next_step.mapping_sequence == 15
    assert report.next_playbook == next_step.playbook == "monitoring-stack"
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
        if step.mapping_sequence > 14
        and step.status
        in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
    )
    assert tuple(step.mapping_sequence for step in advanced) == (15,)

    public = first_bytes.decode() + json.dumps(report.to_object(), sort_keys=True)
    for protected in (
        _PRIVATE_PATH,
        _SECRET,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        MANAGER_REPOSITORY_URI,
        SCYLLA_SIGNING_KEY_FINGERPRINT,
        MANAGER_PACKAGE_VERSION,
        "BEGIN PGP",
        "ansible-playbook",
        "--limit",
        '"variables"',
        '"commands"',
    ):
        assert protected not in public
    assert (
        deploy_post_manager_server_reconciliation_id_from_filename(path.name)
        == OPERATION_ID
    )
    assert (
        deploy_post_manager_server_reconciliation_id_from_filename(
            f"uppercase-{path.name}"
        )
        is None
    )

    document = cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))
    document["record_digest"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0


def test_refuses_missing_prepared_started_failed_and_uncertain_prefixes(
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
    original_write = DeployManagerServerExecutionStore.write_locked

    def refuse_start(self, record, **kwargs):
        if record.state is DeployManagerServerExecutionState.STARTED:
            raise StatePersistenceError("simulated refusal before invocation")
        return original_write(self, record, **kwargs)

    monkeypatch.setattr(DeployManagerServerExecutionStore, "write_locked", refuse_start)
    with pytest.raises(StatePersistenceError, match="before invocation"):
        _execute_manager(
            prepared,
            ManagerServerRunner(),
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
            _execute_manager(
                prepared,
                ManagerServerRunner(mode=mode),
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
        f"{OPERATION_ID}.ansible-deploy-manager-server-evidence.json"
    )
    original_evidence = evidence_path.read_bytes()
    document = cast(
        dict[str, object], json.loads(evidence_path.read_text(encoding="utf-8"))
    )
    entries = cast(list[dict[str, object]], document["entries"])
    entries[0]["backend_configured"] = True
    evidence_path.write_text(
        json.dumps(document, sort_keys=True) + "\n", encoding="utf-8"
    )
    evidence_path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)

    evidence_path.write_bytes(original_evidence)
    evidence_path.chmod(0o600)
    monkeypatch.setattr(
        reconciliation_module,
        "_playbook_source_digest",
        lambda *_args: "sha256:" + "a" * 64,
    )
    with pytest.raises(StateConflictError, match="source"):
        _call(prepared)
    monkeypatch.undo()

    _call(prepared)
    path = deploy_post_manager_server_reconciliation_path(prepared.paths, OPERATION_ID)
    document = cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))
    document["changed_count"] = 7
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(StatePersistenceError):
        _call(prepared)
