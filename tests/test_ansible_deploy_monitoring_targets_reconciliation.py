import inspect
import json
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_monitoring_targets_execution import (
    MonitoringTargetsRunner,
    _prepared,
)
from test_ansible_deploy_monitoring_targets_execution import (
    _call as _execute_targets,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_monitoring_targets_reconciliation as reconciliation_module
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_monitoring_targets_execution import (
    DeployMonitoringTargetsEvidenceStore,
    DeployMonitoringTargetsExecutionState,
    DeployMonitoringTargetsExecutionStore,
    deploy_monitoring_targets_evidence_path,
    deploy_monitoring_targets_execution_path,
)
from scylla_vms.ansible.deploy_monitoring_targets_reconciliation import (
    ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_SCHEMA_VERSION,
    DeployPostMonitoringTargetsArtifactState,
    DeployPostMonitoringTargetsReconciliationStore,
    deploy_post_monitoring_targets_reconciliation_id_from_filename,
    deploy_post_monitoring_targets_reconciliation_path,
    reconcile_deploy_monitoring_targets_result,
)
from scylla_vms.ansible.deploy_plan import DeployConditionState
from scylla_vms.ansible.manager_tasks import (
    EXPECTED_BLOCKERS as MANAGER_TASK_EXPECTED_BLOCKERS,
)
from scylla_vms.ansible.manager_tasks import (
    MANAGER_TASK_ACTIONS,
    MANAGER_TASK_KINDS,
)
from scylla_vms.ansible.manager_tasks import (
    NOT_PERFORMED as MANAGER_TASK_NOT_PERFORMED,
)
from scylla_vms.ansible.monitoring_stack import STACK_VERSION
from scylla_vms.ansible.monitoring_targets import INSTALL_ROOT, TARGET_FILES
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import serialize_json

_PRIVATE_PATH = "/private/operator/monitoring-targets-runtime.json"
_SECRET = "obviously-fake-monitoring-targets-execution-secret"
_MANAGER_TASK_BLOCKERS = (
    "cluster-health-not-performed",
    "deploy-authorization-not-collected",
    "deploy-condition-unmodeled",
    "manager-backend-not-performed",
    "manager-task-action-unmodeled",
    "manager-task-authorization-not-collected",
    "ordered-deploy-step-not-reached",
    "public-deploy-workflow-unavailable",
    "sensitive-deploy-execution-unavailable",
    "step-variable-evidence-not-performed",
)


def _complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str = "no-change",
):
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = MonitoringTargetsRunner(mode=mode)
    _execute_targets(prepared, runner, executables, toolchain)
    return prepared, runner


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_monitoring_targets_result(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployPostMonitoringTargetsReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


def _write_document(path: Path, value: dict[str, object]) -> None:
    path.write_bytes(serialize_json(value))
    path.chmod(0o600)


@pytest.mark.parametrize(
    ("mode", "changed_count", "no_change_count"),
    (("generated", 1, 0), ("no-change", 0, 1)),
)
def test_success_reuse_mapping_manager_tasks_and_redaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    changed_count: int,
    no_change_count: int,
) -> None:
    signature = inspect.signature(reconcile_deploy_monitoring_targets_result)
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
    path = deploy_post_monitoring_targets_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    post_agent_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-post-monitoring-agent-reconciliation.json"
    )
    prior_document = cast(
        dict[str, object], json.loads(post_agent_path.read_text(encoding="utf-8"))
    )
    prior_steps = cast(list[dict[str, object]], prior_document["steps"])
    prior_by_mapping = {
        cast(int, step["mapping_sequence"]): step for step in prior_steps
    }
    assert prior_by_mapping[19]["playbook"] == "manager-tasks"
    assert prior_by_mapping[19]["condition"] == "explicit-task-action"
    assert prior_by_mapping[19]["condition_state"] == "unmodeled"
    assert prior_by_mapping[19]["classification"] == "sensitive"
    assert prior_by_mapping[19]["status"] == "blocked"
    assert prior_by_mapping[19]["evidence_digest"] is None
    assert prior_by_mapping[19]["blockers"] == list(_MANAGER_TASK_BLOCKERS)
    prior_paths = tuple(
        item
        for item in prepared.paths.operations.iterdir()
        if item != path and item.is_file()
    )
    prior_bytes = {item: item.read_bytes() for item in prior_paths}
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"

    report = _call(prepared)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0
    first_bytes = path.read_bytes()
    first_mtime = path.stat().st_mtime_ns
    reused = _call(prepared)
    stored = _record(prepared)

    assert report.schema_version == (
        ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    assert stored.record.schema_version == (
        ANSIBLE_DEPLOY_POST_MONITORING_TARGETS_RECONCILIATION_SCHEMA_VERSION
    )
    assert report.artifact_state is DeployPostMonitoringTargetsArtifactState.CREATED
    assert reused.artifact_state is DeployPostMonitoringTargetsArtifactState.REUSED
    assert path.read_bytes() == first_bytes
    assert path.stat().st_mtime_ns == first_mtime
    assert path.stat().st_mode & 0o777 == 0o600
    assert len(runner.specs) == process_count
    assert journal_path.read_bytes() == prior_bytes[journal_path]
    assert {item: item.read_bytes() for item in prior_paths} == prior_bytes

    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert report.target_count == report.generated_count == 1
    assert report.changed_count == changed_count
    assert report.no_change_count == no_change_count
    assert report.file_count == len(TARGET_FILES) == 4
    assert report.prohibited_action_count == 0
    assert report.authorization_consumed
    assert report.execution_state is DeployMonitoringTargetsExecutionState.SUCCEEDED
    assert report.process_calls == 0
    assert not report.authorization_created
    assert not report.execution_started

    record = stored.record
    assert record.original_mapping_count == 21
    assert record.original_mapping_unchanged
    assert tuple(step.mapping_sequence for step in record.steps) == tuple(range(1, 22))
    assert tuple(
        (
            step.mapping_sequence,
            step.playbook,
            step.condition,
            step.original_step_digest,
        )
        for step in record.steps
    ) == tuple(
        (
            cast(int, prior["mapping_sequence"]),
            cast(str, prior["playbook"]),
            cast(str, prior["condition"]),
            cast(str, prior["original_step_digest"]),
        )
        for prior in prior_steps
    )
    for step in record.steps:
        prior = prior_by_mapping[step.mapping_sequence]
        if step.mapping_sequence != 18:
            assert (
                step.status.value,
                step.evidence_state,
                step.evidence_digest,
                list(step.blockers),
            ) == (
                prior["status"],
                prior["evidence_state"],
                prior["evidence_digest"],
                prior["blockers"],
            )

    targets = tuple(step for step in record.steps if step.mapping_sequence == 18)
    assert len(targets) == 1
    targets_step = targets[0]
    assert prior_by_mapping[18]["status"] == (
        DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED.value
    )
    assert targets_step.playbook == "monitoring-targets"
    assert targets_step.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
    assert targets_step.evidence_state == "monitoring-targets-bound"
    assert targets_step.evidence_digest == record.evidence_digest
    assert not targets_step.blockers

    manager_tasks = next(step for step in record.steps if step.mapping_sequence == 19)
    assert report.next_mapping_sequence == manager_tasks.mapping_sequence == 19
    assert report.next_playbook == manager_tasks.playbook == "manager-tasks"
    assert (
        report.next_condition_state
        is manager_tasks.condition_state
        is DeployConditionState.UNMODELED
    )
    assert (
        report.next_classification
        is manager_tasks.classification
        is OperationClassification.SENSITIVE
    )
    assert (
        report.next_step_status
        is manager_tasks.status
        is DeployBaseOsReconciledStepStatus.BLOCKED
    )
    assert manager_tasks.blockers == _MANAGER_TASK_BLOCKERS
    assert manager_tasks.evidence_digest is None
    assert record.next_execution_state == "not-started"
    assert tuple(MANAGER_TASK_ACTIONS) == ("inspect", "quiesce", "resume", "validate")
    assert tuple(MANAGER_TASK_KINDS) == ("backup", "repair")
    assert tuple(MANAGER_TASK_EXPECTED_BLOCKERS) == (
        "backend-unconfigured",
        "manager-inactive",
        "manager-unregistered",
    )
    assert tuple(MANAGER_TASK_NOT_PERFORMED) == (
        "auth-token",
        "backend-configure",
        "cluster-registration",
        "manager-start",
        "sctool-backup",
        "sctool-repair",
        "sctool-resume",
        "sctool-suspend",
        "sctool-tasks",
    )
    assert not any(
        step.mapping_sequence > 18
        and step.status
        in {
            DeployBaseOsReconciledStepStatus.SUCCEEDED,
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
        for step in record.steps
    )

    public = first_bytes.decode() + json.dumps(report.to_object(), sort_keys=True)
    for protected in (
        _PRIVATE_PATH,
        _SECRET,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        INSTALL_ROOT,
        STACK_VERSION,
        *TARGET_FILES,
        '"labels"',
        '"ports"',
        '"5090"',
        '"9100"',
        '"9180"',
        "ansible-playbook",
        "--limit",
        '"variables"',
        '"commands"',
        "DSV_MONITORING_TARGETS_B64",
        "password",
        "PLAY RECAP",
    ):
        assert protected not in public
    assert (
        deploy_post_monitoring_targets_reconciliation_id_from_filename(path.name)
        == OPERATION_ID
    )
    assert (
        deploy_post_monitoring_targets_reconciliation_id_from_filename(
            f"uppercase-{path.name}"
        )
        is None
    )


@pytest.mark.parametrize(
    ("case", "expected_state", "manual_recovery"),
    (
        ("missing", None, None),
        ("prepared", DeployMonitoringTargetsExecutionState.PREPARED, False),
        ("started", DeployMonitoringTargetsExecutionState.STARTED, True),
        ("failed", DeployMonitoringTargetsExecutionState.FAILED, True),
        ("uncertain", DeployMonitoringTargetsExecutionState.TIMED_OUT, True),
    ),
)
def test_refuses_incomplete_failed_and_uncertain_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    expected_state: DeployMonitoringTargetsExecutionState | None,
    manual_recovery: bool | None,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    original_execution_write = DeployMonitoringTargetsExecutionStore.write_locked
    original_evidence_write = DeployMonitoringTargetsEvidenceStore.write_locked

    if case == "prepared":

        def fail_started(self, record, **kwargs):
            if record.state is DeployMonitoringTargetsExecutionState.STARTED:
                raise StatePersistenceError("simulated pre-start refusal")
            return original_execution_write(self, record, **kwargs)

        monkeypatch.setattr(
            DeployMonitoringTargetsExecutionStore,
            "write_locked",
            fail_started,
        )
        with pytest.raises(StatePersistenceError, match="before invocation"):
            _execute_targets(
                prepared,
                MonitoringTargetsRunner(),
                executables,
                toolchain,
            )
    elif case == "started":

        def fail_evidence(self, record, **kwargs):
            raise StatePersistenceError("simulated evidence persistence failure")

        monkeypatch.setattr(
            DeployMonitoringTargetsEvidenceStore,
            "write_locked",
            fail_evidence,
        )
        with pytest.raises(StatePersistenceError, match="evidence persistence failed"):
            _execute_targets(
                prepared,
                MonitoringTargetsRunner(),
                executables,
                toolchain,
            )
    elif case in {"failed", "uncertain"}:
        mode = "failed" if case == "failed" else "timeout"
        with pytest.raises(AnsibleError):
            _execute_targets(
                prepared,
                MonitoringTargetsRunner(mode=mode),
                executables,
                toolchain,
            )

    monkeypatch.setattr(
        DeployMonitoringTargetsExecutionStore,
        "write_locked",
        original_execution_write,
    )
    monkeypatch.setattr(
        DeployMonitoringTargetsEvidenceStore,
        "write_locked",
        original_evidence_write,
    )
    execution_path = deploy_monitoring_targets_execution_path(
        prepared.paths, OPERATION_ID
    )
    if expected_state is None:
        assert not execution_path.exists()
    else:
        stored = DeployMonitoringTargetsExecutionStore(
            prepared.paths, OPERATION_ID
        ).read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        assert stored.record.state is expected_state
        assert stored.record.manual_recovery_required is manual_recovery

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not deploy_post_monitoring_targets_reconciliation_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_refuses_missing_extra_duplicate_and_wrong_target_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _complete(tmp_path, monkeypatch)
    evidence_path = deploy_monitoring_targets_evidence_path(
        prepared.paths, OPERATION_ID
    )
    original = evidence_path.read_bytes()
    reconciliation_path = deploy_post_monitoring_targets_reconciliation_path(
        prepared.paths, OPERATION_ID
    )

    for case in ("missing", "extra", "duplicate", "wrong-target"):
        if case == "missing":
            evidence_path.unlink()
        else:
            document = cast(dict[str, object], json.loads(original))
            entries = cast(list[dict[str, object]], document["entries"])
            if case == "extra":
                extra = dict(entries[0])
                extra["stable_id"] = "monitoring-extra"
                entries.append(extra)
            elif case == "duplicate":
                entries.append(dict(entries[0]))
            else:
                entries[0]["stable_id"] = "monitoring-wrong"
            _write_document(evidence_path, document)
        with pytest.raises((StateConflictError, StatePersistenceError)):
            _call(prepared)
        assert not reconciliation_path.exists()
        evidence_path.write_bytes(original)
        evidence_path.chmod(0o600)


def test_refuses_bound_authorization_evidence_source_catalog_inventory_and_journal_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _complete(tmp_path, monkeypatch)
    paths = prepared.paths
    reconciliation_path = deploy_post_monitoring_targets_reconciliation_path(
        paths, OPERATION_ID
    )
    authorization_path = paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-monitoring-targets-authorization.json"
    )
    evidence_path = deploy_monitoring_targets_evidence_path(paths, OPERATION_ID)
    execution_path = deploy_monitoring_targets_execution_path(paths, OPERATION_ID)
    inventory_path = paths.ansible_inventory
    journal_path = paths.operations / f"{OPERATION_ID}.json"

    file_cases = (
        ("authorization", authorization_path),
        ("evidence", evidence_path),
        ("catalog", execution_path),
        ("inventory", inventory_path),
        ("journal", journal_path),
    )
    for case, path in file_cases:
        original = path.read_bytes()
        if case == "inventory":
            path.write_bytes(original + b" ")
            path.chmod(0o600)
        else:
            document = cast(dict[str, object], json.loads(original))
            if case == "authorization":
                document["authorization_digest"] = "sha256:" + "a" * 64
            elif case == "evidence":
                entries = cast(list[dict[str, object]], document["entries"])
                entries[0]["public_bind"] = True
            elif case == "catalog":
                binding = cast(dict[str, object], document["binding"])
                binding["catalog_digest"] = "sha256:" + "b" * 64
            else:
                document["request_digest"] = "sha256:" + "c" * 64
            _write_document(path, document)
        with pytest.raises((StateConflictError, StatePersistenceError)):
            _call(prepared)
        assert not reconciliation_path.exists()
        path.write_bytes(original)
        path.chmod(0o600)

    original_source_digest = reconciliation_module._playbook_source_digest
    monkeypatch.setattr(
        reconciliation_module,
        "_playbook_source_digest",
        lambda *_args: "sha256:" + "d" * 64,
    )
    with pytest.raises(StateConflictError, match="source"):
        _call(prepared)
    assert not reconciliation_path.exists()
    monkeypatch.setattr(
        reconciliation_module,
        "_playbook_source_digest",
        original_source_digest,
    )


def test_wrong_lock_and_reconciliation_parser_store_conflict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _complete(tmp_path, monkeypatch)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        reconcile_deploy_monitoring_targets_result(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
        )

    _call(prepared)
    path = deploy_post_monitoring_targets_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    document = cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))
    document["changed_count"] = 7
    _write_document(path, document)
    with pytest.raises(StatePersistenceError):
        _call(prepared)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
