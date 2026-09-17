import inspect
import json
from pathlib import Path

import pytest
from test_ansible_deploy_monitoring_targets_reconciliation import (
    _call as _reconcile_targets,
)
from test_ansible_deploy_monitoring_targets_reconciliation import (
    _complete as _complete_targets,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_manager_activation_plan as activation_module
from scylla_vms.ansible.deploy_manager_activation_plan import (
    ANSIBLE_DEPLOY_MANAGER_ACTIVATION_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_SCHEMA_VERSION,
    DeployManagerActivationArtifactState,
    DeployManagerActivationBoundaryStatus,
    DeployManagerActivationContextStore,
    DeployManagerActivationPlanStore,
    DeployManagerActivationSourceState,
    deploy_manager_activation_context_id_from_filename,
    deploy_manager_activation_context_path,
    deploy_manager_activation_plan_id_from_filename,
    deploy_manager_activation_plan_path,
    plan_deploy_manager_activation,
)
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import serialize_json

_PRIVATE_PATH = "/private/operator/manager-activation.json"
_SECRET = "obviously-fake-manager-activation-secret"


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, runner = _complete_targets(tmp_path, monkeypatch)
    _reconcile_targets(prepared)
    return prepared, runner


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return plan_deploy_manager_activation(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _records(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = DeployManagerActivationContextStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        plan = DeployManagerActivationPlanStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    return context, plan


def _write_document(path: Path, value: dict[str, object]) -> None:
    path.write_bytes(serialize_json(value))
    path.chmod(0o600)


def test_activation_bridge_is_immutable_ordered_redacted_and_mapping_preserving(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signature = inspect.signature(plan_deploy_manager_activation)
    assert tuple(signature.parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    for forbidden in (
        "action",
        "backend",
        "registration",
        "task",
        "target",
        "command",
        "variable",
        "path",
        "text",
    ):
        assert forbidden not in signature.parameters

    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    context_path = deploy_manager_activation_context_path(prepared.paths, OPERATION_ID)
    plan_path = deploy_manager_activation_plan_path(prepared.paths, OPERATION_ID)
    prior_paths = tuple(
        path
        for path in prepared.paths.operations.iterdir()
        if path not in {context_path, plan_path} and path.is_file()
    )
    prior_bytes = {path: path.read_bytes() for path in prior_paths}

    report = _call(prepared)
    context_bytes = context_path.read_bytes()
    plan_bytes = plan_path.read_bytes()
    context_mtime = context_path.stat().st_mtime_ns
    plan_mtime = plan_path.stat().st_mtime_ns
    reused = _call(prepared)
    context, plan = _records(prepared)

    assert report.schema_version == (
        ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_REPORT_SCHEMA_VERSION
    )
    assert (
        context.record.schema_version
        == ANSIBLE_DEPLOY_MANAGER_ACTIVATION_CONTEXT_SCHEMA_VERSION
    )
    assert (
        plan.record.schema_version
        == ANSIBLE_DEPLOY_MANAGER_ACTIVATION_PLAN_SCHEMA_VERSION
    )
    assert report.context_state is DeployManagerActivationArtifactState.CREATED
    assert report.plan_state is DeployManagerActivationArtifactState.CREATED
    assert reused.context_state is DeployManagerActivationArtifactState.REUSED
    assert reused.plan_state is DeployManagerActivationArtifactState.REUSED
    assert context_path.read_bytes() == context_bytes
    assert plan_path.read_bytes() == plan_bytes
    assert context_path.stat().st_mtime_ns == context_mtime
    assert plan_path.stat().st_mtime_ns == plan_mtime
    assert context_path.stat().st_mode & 0o777 == 0o600
    assert plan_path.stat().st_mode & 0o777 == 0o600
    assert {path: path.read_bytes() for path in prior_paths} == prior_bytes
    assert len(runner.specs) == process_count
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0

    record = context.record
    planned = plan.record
    assert record.original_mapping_count == planned.original_mapping_count == 21
    assert record.original_mapping_unchanged
    assert planned.original_mapping_unchanged
    assert record.journal_status is planned.journal_status is JournalStatus.IN_PROGRESS
    assert record.journal_phase is planned.journal_phase is OperationPhase.VERIFY
    assert report.manager_target_id == record.manager_target_id
    assert report.manager_agent_target_ids == record.manager_agent_target_ids
    assert report.manager_agent_target_count == len(report.manager_agent_target_ids)
    assert report.step_count == 4
    assert report.source_available_count == 1
    assert report.source_unavailable_count == 3
    assert report.authorization_required_count == 4
    assert report.evidence_required_count == 4
    assert report.not_performed_count == 4
    assert report.blocked_count == 4
    assert report.next_implementation_contract == (
        "manager-backend-configuration-owner"
    )
    assert record.manager_backend_state == "not-performed"
    assert record.manager_service_state == "not-performed"
    assert record.manager_registration_state == "not-performed"
    assert record.manager_agent_token_state == "not-performed"
    assert record.manager_tasks_action_state == "manager-tasks-action-unmodeled"

    steps = planned.steps
    assert tuple(step.boundary for step in steps) == (
        "backend-configure",
        "manager-start",
        "cluster-registration-auth-token-handoff",
        "manager-tasks",
    )
    assert tuple(step.classification for step in steps) == (
        OperationClassification.MUTATING,
        OperationClassification.MUTATING,
        OperationClassification.SENSITIVE,
        OperationClassification.SENSITIVE,
    )
    assert tuple(step.source_state for step in steps) == (
        DeployManagerActivationSourceState.UNAVAILABLE,
        DeployManagerActivationSourceState.UNAVAILABLE,
        DeployManagerActivationSourceState.UNAVAILABLE,
        DeployManagerActivationSourceState.AVAILABLE,
    )
    assert all(
        step.status is DeployManagerActivationBoundaryStatus.BLOCKED
        and step.authorization_requirement == "authorization-required"
        and step.evidence_requirement == "evidence-required"
        and step.performance_state == "not-performed"
        for step in steps
    )
    assert steps[0].prerequisite_step_digest is None
    assert tuple(step.prerequisite_step_digest for step in steps[1:]) == tuple(
        step.step_digest for step in steps[:-1]
    )
    assert steps[2].target_ids == tuple(
        sorted((record.manager_target_id, *record.manager_agent_target_ids))
    )
    assert steps[3].manager_tasks_action_state == ("manager-tasks-action-unmodeled")
    assert {
        "manager-backend-not-performed",
        "manager-inactive",
        "manager-unregistered",
        "manager-tasks-action-unmodeled",
        "manager-tasks-validation-only",
    } <= set(steps[3].blockers)

    public = (
        context_bytes.decode()
        + plan_bytes.decode()
        + json.dumps(report.to_object(), sort_keys=True)
    )
    for protected in (
        _PRIVATE_PATH,
        _SECRET,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "auth_token",
        "scylla-manager.yaml",
        "ansible-playbook",
        "--limit",
        '"provider_id"',
        '"command"',
        '"variables"',
        '"inspect"',
        '"quiesce"',
        '"resume"',
        '"validate"',
    ):
        assert protected not in public
    assert (
        deploy_manager_activation_context_id_from_filename(context_path.name)
        == OPERATION_ID
    )
    assert (
        deploy_manager_activation_plan_id_from_filename(plan_path.name) == OPERATION_ID
    )


def test_missing_reconciliation_wrong_lock_and_plan_without_context_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _complete_targets(tmp_path, monkeypatch)
    with pytest.raises(StateConflictError, match="post-monitoring-targets"):
        _call(prepared)
    assert not deploy_manager_activation_context_path(
        prepared.paths, OPERATION_ID
    ).exists()

    _reconcile_targets(prepared)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        plan_deploy_manager_activation(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
        )

    plan_path = deploy_manager_activation_plan_path(prepared.paths, OPERATION_ID)
    plan_path.write_text("{}\n", encoding="utf-8")
    plan_path.chmod(0o600)
    with pytest.raises(StateConflictError, match="without its context"):
        _call(prepared)


def test_records_build_before_write_and_context_only_prefix_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    context_path = deploy_manager_activation_context_path(prepared.paths, OPERATION_ID)
    plan_path = deploy_manager_activation_plan_path(prepared.paths, OPERATION_ID)

    original_builder = activation_module._build_plan_record

    def fail_build(*args, **kwargs):
        del args, kwargs
        raise StateConflictError("injected in-memory plan failure")

    monkeypatch.setattr(activation_module, "_build_plan_record", fail_build)
    with pytest.raises(StateConflictError, match="in-memory"):
        _call(prepared)
    assert not context_path.exists()
    assert not plan_path.exists()
    monkeypatch.setattr(activation_module, "_build_plan_record", original_builder)

    original_write = DeployManagerActivationPlanStore.write_locked

    def fail_write(*args, **kwargs):
        del args, kwargs
        raise StatePersistenceError("injected plan persistence failure")

    monkeypatch.setattr(DeployManagerActivationPlanStore, "write_locked", fail_write)
    with pytest.raises(StatePersistenceError, match="injected"):
        _call(prepared)
    assert context_path.exists()
    context_bytes = context_path.read_bytes()
    assert not plan_path.exists()

    monkeypatch.setattr(
        DeployManagerActivationPlanStore, "write_locked", original_write
    )
    report = _call(prepared)
    assert report.context_state is DeployManagerActivationArtifactState.REUSED
    assert report.plan_state is DeployManagerActivationArtifactState.CREATED
    assert context_path.read_bytes() == context_bytes
    assert len(runner.specs) == process_count


def test_tamper_drift_and_ambiguous_activation_history_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    conflict = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-manager-activation-execution.json"
    )
    conflict.write_text("{}\n", encoding="utf-8")
    conflict.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous or later"):
        _call(prepared)
    assert not deploy_manager_activation_context_path(
        prepared.paths, OPERATION_ID
    ).exists()
    conflict.unlink()

    trust_path = prepared.paths.ansible_trust
    trust_bytes = trust_path.read_bytes()
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    trust["generation"] += 1
    _write_document(trust_path, trust)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not deploy_manager_activation_context_path(
        prepared.paths, OPERATION_ID
    ).exists()

    trust_path.write_bytes(trust_bytes)
    trust_path.chmod(0o600)
    _call(prepared)
    plan_path = deploy_manager_activation_plan_path(prepared.paths, OPERATION_ID)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["source_available_count"] = 2
    _write_document(plan_path, plan)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
    with pytest.raises(StatePersistenceError):
        _records(prepared)
