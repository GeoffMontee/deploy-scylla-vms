import inspect
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from test_ansible_deploy_prerequisites import (
    PrerequisiteRunner,
)
from test_ansible_deploy_prerequisites import (
    _call as _prerequisite_call,
)
from test_ansible_deploy_prerequisites import (
    _prepared as _prerequisite_prepared,
)
from test_provider_source import CLUSTER_UUID
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_plan as deploy_plan_module
import scylla_vms.ansible.deploy_reconciliation as reconciliation_module
from scylla_vms.ansible.deploy_plan import (
    DeployAnsibleContextStore,
    DeployAnsiblePlanStore,
)
from scylla_vms.ansible.deploy_prerequisites import (
    DeployPrerequisiteEvidenceStore,
    DeployPrerequisiteExecutionStore,
    deploy_prerequisite_evidence_path,
)
from scylla_vms.ansible.deploy_reconciliation import (
    ANSIBLE_DEPLOY_EFFECTIVE_PLAN_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION,
    DeployEffectiveEvidenceState,
    DeployEffectivePlan,
    DeployEffectivePlanArtifactState,
    DeployEffectivePlanStore,
    DeployEffectiveStepStatus,
    deploy_effective_plan_path,
    reconcile_deploy_ansible_plan,
)
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import serialize_json

_PRIVATE_PATH = "/private/operator/reconciliation.json"
_SECRET = "obviously-fake-reconciliation-secret"


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, inventory, executables, toolchain = _prerequisite_prepared(
        tmp_path, monkeypatch
    )
    runner = PrerequisiteRunner(inventory)
    _prerequisite_call(prepared, runner, executables, toolchain)
    return prepared, runner


def _reconcile(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_ansible_plan(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployEffectivePlanStore(prepared.paths, OPERATION_ID).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


def test_successful_reconciliation_is_narrow_redacted_immutable_and_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(inspect.signature(reconcile_deploy_ansible_plan).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    prepared, runner = _prepared(tmp_path, monkeypatch)
    original_paths = (
        DeployAnsibleContextStore(prepared.paths, OPERATION_ID).path,
        DeployAnsiblePlanStore(prepared.paths, OPERATION_ID).path,
        DeployPrerequisiteExecutionStore(prepared.paths, OPERATION_ID).path,
        DeployPrerequisiteEvidenceStore(prepared.paths, OPERATION_ID).path,
        prepared.paths.operations / f"{OPERATION_ID}.json",
    )
    original_bytes = tuple(path.read_bytes() for path in original_paths)
    process_count = len(runner.specs or ())

    created = _reconcile(prepared)
    companion_path = deploy_effective_plan_path(prepared.paths, OPERATION_ID)
    companion_bytes = companion_path.read_bytes()
    companion_mtime = companion_path.stat().st_mtime_ns
    reused = _reconcile(prepared)
    stored = _record(prepared)
    assert (
        DeployEffectivePlanStore(prepared.paths, OPERATION_ID).read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        == stored
    )
    assert (
        DeployPrerequisiteExecutionStore(prepared.paths, OPERATION_ID)
        .read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        .record.all_steps_completed
    )
    assert (
        len(
            DeployPrerequisiteEvidenceStore(prepared.paths, OPERATION_ID)
            .read(
                expected_cluster_uuid=CLUSTER_UUID,
                expected_cluster_name="example",
            )
            .record.entries
        )
        == 2
    )

    assert created.schema_version == (
        ANSIBLE_DEPLOY_EFFECTIVE_PLAN_REPORT_SCHEMA_VERSION
    )
    assert created.artifact_state is DeployEffectivePlanArtifactState.CREATED
    assert reused.artifact_state is DeployEffectivePlanArtifactState.REUSED
    assert reused.to_object() == created.to_object() | {"artifact_state": "reused"}
    assert stored.record.schema_version == ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION
    assert companion_path.stat().st_mode & 0o777 == 0o600
    assert companion_path.read_bytes() == companion_bytes
    assert companion_path.stat().st_mtime_ns == companion_mtime
    assert tuple(path.read_bytes() for path in original_paths) == original_bytes
    assert len(runner.specs or ()) == process_count
    assert created.journal_status is JournalStatus.IN_PROGRESS
    assert created.journal_phase is OperationPhase.VERIFY
    assert created.succeeded_count == 2
    assert created.eligible_count == 0
    assert created.next_eligible_steps == ()
    assert created.total_count == (
        created.succeeded_count
        + created.eligible_count
        + created.blocked_count
        + created.not_performed_count
    )

    original = DeployAnsiblePlanStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    assert len(stored.record.steps) == len(original.record.steps)
    for effective, source in zip(
        stored.record.steps, original.record.steps, strict=True
    ):
        assert (
            effective.sequence,
            effective.mapping_sequence,
            effective.playbook,
            effective.condition,
            effective.condition_state,
            effective.classification,
            effective.target_role,
            effective.target_ids,
            effective.target_digest,
            effective.limit_policy,
            effective.serial,
            effective.check_mode,
            effective.variable_names,
            effective.variables_digest,
            effective.source_digest,
            effective.command_digest,
        ) == (
            source.sequence,
            source.mapping_sequence,
            source.playbook,
            source.condition,
            source.condition_state,
            source.classification,
            source.target_role,
            source.target_ids,
            source.target_digest,
            source.limit_policy,
            source.serial,
            source.check_mode,
            source.variable_names,
            source.variables_digest,
            source.source_digest,
            source.command_digest,
        )

    first, second = stored.record.steps[:2]
    assert (first.playbook, second.playbook) == (
        "inventory-preflight",
        "connectivity-check",
    )
    assert first.status is DeployEffectiveStepStatus.SUCCEEDED
    assert second.status is DeployEffectiveStepStatus.SUCCEEDED
    assert first.evidence_state is DeployEffectiveEvidenceState.BOUND
    assert second.evidence_state is DeployEffectiveEvidenceState.BOUND
    assert first.evidence_digest is not None
    assert second.evidence_digest is not None
    assert all(
        step.status is DeployEffectiveStepStatus.BLOCKED
        for step in stored.record.steps
        if step.sequence > 2
        and step.condition_state.value != "inactive"
        and step.classification is not OperationClassification.READ_ONLY
    )
    assert all(
        step.status is not DeployEffectiveStepStatus.ELIGIBLE
        for step in stored.record.steps
        if step.sequence > 2
    )
    assert any(
        step.playbook == "evidence-collect"
        and step.status is DeployEffectiveStepStatus.NOT_PERFORMED
        and "host-evidence-not-performed" in step.blockers
        for step in stored.record.steps
    )
    assert "deploy-authorization-not-collected" in stored.record.blocker_set
    assert "mutating-deploy-execution-unavailable" in stored.record.blocker_set
    assert "sensitive-deploy-execution-unavailable" in stored.record.blocker_set
    assert stored.record.authorization_state == "not-collected"
    assert stored.record.mutating_execution_state == "blocked"
    assert stored.record.finalization_state == "not-started"
    assert stored.record.public_workflow_state == "unavailable"

    projected = json.dumps(created.to_object(), sort_keys=True)
    persisted = companion_path.read_text(encoding="utf-8")
    for forbidden in (
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "ssh-ed25519",
        "fingerprint",
        "PLAY RECAP",
        "DSV_INVENTORY_PREFLIGHT",
        "command_digest",
        "variables_digest",
        "target_ids",
        "environment",
        _PRIVATE_PATH,
        _SECRET,
    ):
        assert forbidden not in projected
    for forbidden in (
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "ssh-ed25519",
        "fingerprint",
        "PLAY RECAP",
        "DSV_INVENTORY_PREFLIGHT",
        "environment",
        _PRIVATE_PATH,
        _SECRET,
    ):
        assert forbidden not in persisted


@pytest.mark.parametrize(
    "mode",
    ("missing", "failed", "uncertain"),
)
def test_incomplete_failed_and_uncertain_prerequisites_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    prepared, inventory, executables, toolchain = _prerequisite_prepared(
        tmp_path, monkeypatch
    )
    runner = PrerequisiteRunner(
        inventory,
        mode=(
            "preflight-failed"
            if mode == "failed"
            else "preflight-timeout"
            if mode == "uncertain"
            else "success"
        ),
    )
    if mode != "missing":
        with pytest.raises(AnsibleError):
            _prerequisite_call(prepared, runner, executables, toolchain)

    with (
        ClusterLock(prepared.paths, "deploy", 0) as lock,
        pytest.raises(StateConflictError, match=r"completed prerequisites|succeeded"),
    ):
        reconcile_deploy_ansible_plan(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )
    assert not deploy_effective_plan_path(prepared.paths, OPERATION_ID).exists()


@pytest.mark.parametrize(
    "drift",
    (
        "context",
        "plan",
        "evidence",
        "readiness",
        "journal",
        "catalog",
        "source",
    ),
)
def test_provenance_drift_is_refused_before_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    if drift == "context":
        _tamper_digest(
            DeployAnsibleContextStore(prepared.paths, OPERATION_ID).path,
            "record_digest",
        )
    elif drift == "plan":
        _tamper_digest(
            DeployAnsiblePlanStore(prepared.paths, OPERATION_ID).path,
            "record_digest",
        )
    elif drift == "evidence":
        value = json.loads(
            deploy_prerequisite_evidence_path(prepared.paths, OPERATION_ID).read_text(
                encoding="utf-8"
            )
        )
        value["entries"] = list(reversed(value["entries"]))
        _write_json(
            deploy_prerequisite_evidence_path(prepared.paths, OPERATION_ID),
            value,
        )
    elif drift == "readiness":
        _tamper_digest(
            prepared.paths.terraform_plans
            / f"{OPERATION_ID}.terraform-apply-readiness.json",
            "record_digest",
        )
    elif drift == "journal":
        _tamper_digest(
            prepared.paths.operations / f"{OPERATION_ID}.json",
            "request_digest",
        )
    elif drift == "catalog":
        monkeypatch.setattr(
            reconciliation_module,
            "ansible_operation_catalog_digest",
            lambda: "sha256:" + "b" * 64,
        )
    else:
        source = load_ansible_source_bundle()
        monkeypatch.setattr(
            reconciliation_module,
            "load_ansible_source_bundle",
            lambda: replace(source, digest="sha256:" + "c" * 64),
        )

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _reconcile(prepared)
    assert not deploy_effective_plan_path(prepared.paths, OPERATION_ID).exists()


@pytest.mark.parametrize("mapping_change", ("reordered", "extra"))
def test_mapping_reorder_or_extra_requires_explicit_replan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mapping_change: str,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    current = deploy_plan_module.OPERATION_PLAYBOOKS
    deploy = current["deploy"]
    changed = (
        (deploy[1], deploy[0], *deploy[2:])
        if mapping_change == "reordered"
        else (*deploy, deploy[-1])
    )
    replacement = dict(current)
    replacement["deploy"] = tuple(changed)
    monkeypatch.setattr(deploy_plan_module, "OPERATION_PLAYBOOKS", replacement)
    monkeypatch.setattr(reconciliation_module, "OPERATION_PLAYBOOKS", replacement)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _reconcile(prepared)
    assert not deploy_effective_plan_path(prepared.paths, OPERATION_ID).exists()


def test_write_failure_preserves_original_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    original_plan = DeployAnsiblePlanStore(
        prepared.paths, OPERATION_ID
    ).path.read_bytes()
    original_evidence = DeployPrerequisiteEvidenceStore(
        prepared.paths, OPERATION_ID
    ).path.read_bytes()

    def fail_write(self, record, *, lock):
        del self, record, lock
        raise StatePersistenceError(f"simulated {_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(DeployEffectivePlanStore, "write_locked", fail_write)
    with pytest.raises(StatePersistenceError) as caught:
        _reconcile(prepared)
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    assert not deploy_effective_plan_path(prepared.paths, OPERATION_ID).exists()
    assert (
        DeployAnsiblePlanStore(prepared.paths, OPERATION_ID).path.read_bytes()
        == original_plan
    )
    assert (
        DeployPrerequisiteEvidenceStore(prepared.paths, OPERATION_ID).path.read_bytes()
        == original_evidence
    )


def test_lock_symlink_permissions_and_ambiguous_path_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    with (
        ClusterLock(prepared.paths, "show", 0) as lock,
        pytest.raises(StateLockError),
    ):
        reconcile_deploy_ansible_plan(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )

    path = deploy_effective_plan_path(prepared.paths, OPERATION_ID)
    target = prepared.paths.operations / "outside-effective-plan.json"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _reconcile(prepared)
    path.unlink()
    target.unlink()

    plan_path = DeployAnsiblePlanStore(prepared.paths, OPERATION_ID).path
    plan_path.chmod(0o644)
    with pytest.raises(UnsafePathError):
        _reconcile(prepared)
    plan_path.chmod(0o600)

    ambiguous = prepared.paths.operations / (
        f"{{{OPERATION_ID}}}.ansible-deploy-effective-plan.json"
    )
    ambiguous.write_text("{}\n", encoding="utf-8")
    ambiguous.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _reconcile(prepared)
    assert not path.exists()


def test_effective_record_refuses_status_and_summary_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    _reconcile(prepared)
    value = _record(prepared).record.to_object()
    steps = value["steps"]
    assert isinstance(steps, list)
    first = steps[0]
    assert isinstance(first, dict)
    first["status"] = "eligible"
    with pytest.raises(StatePersistenceError):
        DeployEffectivePlan.from_object(value)


def _tamper_digest(path: Path, field: str) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    value[field] = "sha256:" + "d" * 64
    _write_json(path, value)


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(serialize_json(value))
    os.chmod(path, 0o600)
