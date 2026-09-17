import inspect
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from test_provider_source import CLUSTER_UUID
from test_terraform_apply_readiness import (
    _call as _readiness_call,
)
from test_terraform_apply_readiness import (
    _prepared as _readiness_prepared,
)
from test_terraform_apply_readiness import (
    _runner as _readiness_runner,
)
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_plan as deploy_plan_module
from scylla_vms.ansible.deploy_plan import (
    ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_PLAN_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION,
    DeployAnsibleContextStore,
    DeployAnsiblePlanStore,
    DeployArtifactState,
    DeployConditionState,
    DeployStepStatus,
    bind_deploy_ansible_plan,
    deploy_ansible_context_path,
    deploy_ansible_plan_path,
)
from scylla_vms.ansible.registry import OPERATION_PLAYBOOKS, LimitPolicy, get_playbook
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.persistence import serialize_json


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, inventory, executables, toolchain = _readiness_prepared(
        tmp_path, monkeypatch
    )
    runner = _readiness_runner(inventory)
    _readiness_call(prepared, runner, executables, toolchain)
    assert runner.specs is not None
    assert len(runner.specs) == 3
    return prepared


def _bind(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return bind_deploy_ansible_plan(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _records(prepared):
    context = DeployAnsibleContextStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    plan = DeployAnsiblePlanStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    return context, plan


def test_api_is_narrow_blocked_redacted_and_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(inspect.signature(bind_deploy_ansible_plan).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    prepared = _prepared(tmp_path, monkeypatch)

    created = _bind(prepared)
    reused = _bind(prepared)
    context, plan = _records(prepared)

    assert created.schema_version == ANSIBLE_DEPLOY_PLAN_REPORT_SCHEMA_VERSION
    assert created.context_state is DeployArtifactState.CREATED
    assert created.plan_state is DeployArtifactState.CREATED
    assert reused.context_state is DeployArtifactState.REUSED
    assert reused.plan_state is DeployArtifactState.REUSED
    assert reused.plan_record_digest == created.plan_record_digest
    assert context.record.schema_version == ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
    assert plan.record.schema_version == ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION
    assert (
        deploy_ansible_context_path(prepared.paths, OPERATION_ID).stat().st_mode & 0o777
        == 0o600
    )
    assert (
        deploy_ansible_plan_path(prepared.paths, OPERATION_ID).stat().st_mode & 0o777
        == 0o600
    )
    assert plan.record.executable_count == 0
    assert plan.record.blocked_count > 0
    assert plan.record.not_performed_count >= 0
    assert "public-deploy-workflow-unavailable" in plan.record.blocker_set
    assert "remote-connectivity-not-performed" in plan.record.blocker_set
    assert "host-evidence-not-performed" in plan.record.blocker_set
    assert "storage-wipe-consent-not-collected" in plan.record.blocker_set
    assert "manager-backend-not-performed" in plan.record.blocker_set
    assert "monitoring-startup-not-performed" in plan.record.blocker_set
    assert plan.record.authorization_state == "not-collected"
    assert plan.record.execution_state == "not-started"
    assert plan.record.finalization_state == "not-started"
    assert created.journal_status is JournalStatus.IN_PROGRESS
    assert created.journal_phase is OperationPhase.VERIFY
    assert created.to_object() == reused.to_object() | {
        "context_state": "created",
        "plan_state": "created",
    }
    projected = json.dumps(created.to_object(), sort_keys=True)
    assert "10." not in projected
    assert "ocid1." not in projected
    assert "ssh-" not in projected
    assert "fingerprint" not in projected
    assert "password" not in projected
    assert "token" not in projected
    assert "command" not in projected
    assert "environment" not in projected
    assert "path" not in projected


def test_exact_mapping_conditions_limits_and_stable_role_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    _bind(prepared)
    _context, stored = _records(prepared)
    plan = stored.record

    expected = OPERATION_PLAYBOOKS["deploy"]
    assert {step.mapping_sequence for step in plan.steps} == set(
        range(1, len(expected) + 1)
    )
    for mapping_sequence, mapped in enumerate(expected, start=1):
        expanded = [
            step for step in plan.steps if step.mapping_sequence == mapping_sequence
        ]
        assert expanded
        assert {step.playbook for step in expanded} == {mapped.playbook}
        assert {step.condition for step in expanded} == {mapped.condition}
        definition = get_playbook(mapped.playbook)
        assert {step.limit_policy for step in expanded} == {definition.limit_policy}
        assert {step.serial for step in expanded} == {definition.serial}
        assert {step.check_mode for step in expanded} == {definition.check_mode}
        if definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST:
            assert all(len(step.target_ids) <= 1 for step in expanded)
        assert all(
            step.target_ids == tuple(sorted(set(step.target_ids))) for step in expanded
        )

    role_counts = dict(_bind(prepared).role_target_counts)
    assert role_counts == {
        "jump-host": 1,
        "manager": 1,
        "monitoring": 1,
        "scylla": 1,
    }
    explicit_manager = [step for step in plan.steps if step.playbook == "manager-tasks"]
    assert len(explicit_manager) == 1
    assert explicit_manager[0].condition_state is DeployConditionState.UNMODELED
    assert explicit_manager[0].status is DeployStepStatus.BLOCKED
    assert "manager-task-action-unmodeled" in explicit_manager[0].blockers


def test_context_is_strict_allowlisted_and_contains_no_runtime_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    _bind(prepared)
    context, plan = _records(prepared)

    assert context.record.intent.to_object() == {
        "bootstrap_mode": "unmodeled",
        "connection_policy": "unmodeled",
        "empty_cluster_proof": "not-performed",
        "host_evidence_policy": "unmodeled",
        "manager_backend": "not-performed",
        "manager_package_version": "unmodeled",
        "manager_task_action": "unmodeled",
        "monitoring_startup": "not-performed",
        "schema_version": ("deploy-scylla-vms.ansible-deploy-context.intent/v1"),
        "scylla_package_version": "unmodeled",
        "storage_wipe_consent": "not-collected",
    }
    context_text = context.record.to_object()
    assert "variables" not in context_text
    assert "paths" not in context_text
    assert "environment" not in context_text
    assert "commands" not in context_text
    assert all(
        step.status is not DeployStepStatus.EXECUTABLE for step in plan.record.steps
    )
    assert all(step.variables_digest for step in plan.record.steps)
    assert all(step.command_digest for step in plan.record.steps)
    assert all(step.source_digest for step in plan.record.steps)


def test_missing_readiness_and_wrong_lock_fail_before_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _readiness_prepared(
        tmp_path, monkeypatch
    )
    with (
        ClusterLock(prepared.paths, "deploy", 0) as lock,
        pytest.raises(StateConflictError, match="current local readiness"),
    ):
        bind_deploy_ansible_plan(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )
    assert not deploy_ansible_context_path(prepared.paths, OPERATION_ID).exists()
    assert not deploy_ansible_plan_path(prepared.paths, OPERATION_ID).exists()

    _readiness_call(
        prepared,
        _readiness_runner(inventory),
        executables,
        toolchain,
    )
    with (
        ClusterLock(prepared.paths, "show", 0) as lock,
        pytest.raises(StateLockError, match="matching operation"),
    ):
        bind_deploy_ansible_plan(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def test_context_only_prefix_recovers_and_conflicts_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    first = _bind(prepared)
    plan_path = deploy_ansible_plan_path(prepared.paths, OPERATION_ID)
    plan_path.unlink()

    recovered = _bind(prepared)
    assert recovered.context_state is DeployArtifactState.REUSED
    assert recovered.plan_state is DeployArtifactState.CREATED
    assert recovered.plan_record_digest == first.plan_record_digest

    context_path = deploy_ansible_context_path(prepared.paths, OPERATION_ID)
    value = json.loads(context_path.read_text(encoding="utf-8"))
    value["catalog_digest"] = "sha256:" + "1" * 64
    context_path.write_bytes(serialize_json(value))
    context_path.chmod(0o600)
    with pytest.raises(StatePersistenceError, match="record digest conflicts"):
        _bind(prepared)


def test_unsafe_plan_path_is_rejected_without_processes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    target = prepared.paths.operations / "outside.json"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    plan_path = deploy_ansible_plan_path(prepared.paths, OPERATION_ID)
    os.symlink(target, plan_path)

    with pytest.raises(UnsafePathError):
        _bind(prepared)
    assert not deploy_ansible_context_path(prepared.paths, OPERATION_ID).exists()


def test_ambiguous_operation_artifact_is_refused_before_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    duplicate = prepared.paths.operations / (
        f"{{{OPERATION_ID}}}.ansible-deploy-context.json"
    )
    duplicate.write_text("{}\n", encoding="utf-8")
    duplicate.chmod(0o600)

    with pytest.raises(StateConflictError, match="ambiguous"):
        _bind(prepared)
    assert not deploy_ansible_context_path(prepared.paths, OPERATION_ID).exists()
    assert not deploy_ansible_plan_path(prepared.paths, OPERATION_ID).exists()


@pytest.mark.parametrize(
    "path_name",
    (
        "cluster_metadata",
        "terraform_source_record",
        "terraform_observed",
        "ansible_inventory",
        "ansible_trust",
        "readiness",
    ),
)
def test_current_chain_artifact_drift_is_refused_before_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    path_name: str,
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    if path_name == "readiness":
        path = deploy_plan_module.TerraformApplyReadinessStore(
            prepared.paths, OPERATION_ID
        ).path
    else:
        path = getattr(prepared.paths, path_name)
    path.write_bytes(path.read_bytes() + b" ")
    path.chmod(0o600)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _bind(prepared)
    assert not deploy_ansible_context_path(prepared.paths, OPERATION_ID).exists()
    assert not deploy_ansible_plan_path(prepared.paths, OPERATION_ID).exists()


@pytest.mark.parametrize("binding", ("catalog", "ansible-source"))
def test_existing_companions_refuse_catalog_or_source_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    binding: str,
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    _bind(prepared)
    _context, original_plan = _records(prepared)
    if binding == "catalog":
        monkeypatch.setattr(
            deploy_plan_module,
            "ansible_operation_catalog_digest",
            lambda: "sha256:" + "1" * 64,
        )
    else:
        current = deploy_plan_module.load_ansible_source_bundle()
        monkeypatch.setattr(
            deploy_plan_module,
            "load_ansible_source_bundle",
            lambda: replace(current, digest="sha256:" + "2" * 64),
        )

    with pytest.raises(StateConflictError, match="context is immutable"):
        _bind(prepared)
    _context, current_plan = _records(prepared)
    assert current_plan == original_plan
