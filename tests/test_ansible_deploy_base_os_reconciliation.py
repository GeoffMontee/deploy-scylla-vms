import inspect
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from test_ansible_deploy_base_os_execution import (
    BaseOsRunner,
)
from test_ansible_deploy_base_os_execution import (
    _call as _execute_base_os,
)
from test_ansible_deploy_base_os_execution import (
    _prepared as _base_os_prepared,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_reconciliation as reconciliation_module
from scylla_vms.ansible.deploy_base_os_execution import (
    DeployBaseOsEvidenceStore,
    DeployBaseOsExecutionState,
    DeployBaseOsExecutionStore,
    deploy_base_os_evidence_path,
    deploy_base_os_execution_path,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION,
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStepStatus,
    DeployBaseOsReconciliationArtifactState,
    DeployBaseOsReconciliationStore,
    deploy_base_os_reconciliation_path,
    reconcile_deploy_base_os_result,
)
from scylla_vms.ansible.deploy_host_reconciliation import (
    DeployHostEvidenceReconciliationStore,
    deploy_host_evidence_reconciliation_path,
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
from scylla_vms.persistence import serialize_json

_PRIVATE_PATH = "/private/operator/post-base-os.json"
_SECRET = "obviously-fake-post-base-os-secret"


def _prepared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    mode: str = "no-change",
):
    prepared, inventory, executables, toolchain = _base_os_prepared(
        tmp_path, monkeypatch
    )
    runner = BaseOsRunner(inventory, mode=mode)
    _execute_base_os(prepared, runner, executables, toolchain)
    return prepared, inventory, runner


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_base_os_result(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployBaseOsReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


@pytest.mark.parametrize(
    ("mode", "changed_count", "already_current_count"),
    (("no-change", 0, 1), ("changed", 1, 0)),
)
def test_successful_no_change_and_changed_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    changed_count: int,
    already_current_count: int,
) -> None:
    assert tuple(inspect.signature(reconcile_deploy_base_os_result).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    prepared, _inventory, runner = _prepared(
        tmp_path,
        monkeypatch,
        mode=mode,
    )
    source_paths = (
        prepared.paths.operations / f"{OPERATION_ID}.json",
        deploy_host_evidence_reconciliation_path(prepared.paths, OPERATION_ID),
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-base-os-authorization.json",
        deploy_base_os_execution_path(prepared.paths, OPERATION_ID),
        deploy_base_os_evidence_path(prepared.paths, OPERATION_ID),
    )
    source_bytes = tuple(path.read_bytes() for path in source_paths)
    process_count = len(runner.specs or ())
    show_before = _run_show(prepared.paths)

    report = _call(prepared)
    stored = _record(prepared)

    assert report.schema_version == (
        ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    assert stored.record.schema_version == (
        ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION
    )
    assert report.artifact_state is DeployBaseOsReconciliationArtifactState.CREATED
    assert report.changed_count == changed_count
    assert report.already_current_count == already_current_count
    assert report.base_os_host_count == 1
    assert report.base_os_scope_count == 1
    assert not report.reboot_required
    assert report.reboot_required_count == 0
    assert report.reboot_handling_status == "not-performed"
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert report.succeeded_count == 3
    assert report.authorization_required_count == 1
    assert report.eligible_count == 0
    assert tuple(
        (item.playbook, item.classification.value, item.instance_count)
        for item in report.next_authorization_required
    ) == (("jump-host-configure", "mutating", 1),)
    assert report.next_eligible == ()
    assert report.execution_state == "succeeded"
    assert report.authorization_state == "consumed-by-execution"
    assert report.next_execution_state == "not-started"
    assert report.final_evidence_state == "not-performed"
    assert report.finalization_state == "not-started"
    assert report.public_workflow_state == "unavailable"
    assert len(runner.specs or ()) == process_count
    assert tuple(path.read_bytes() for path in source_paths) == source_bytes
    assert _run_show(prepared.paths) == show_before


def test_exact_step_success_next_gate_and_no_leapfrog(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch, mode="changed")
    _call(prepared)
    record = _record(prepared).record
    prior = DeployHostEvidenceReconciliationStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )

    assert len(record.steps) == len(prior.record.steps)
    for step, previous in zip(record.steps, prior.record.steps, strict=True):
        assert (
            step.sequence,
            step.mapping_sequence,
            step.playbook,
            step.condition,
            step.condition_state,
            step.classification,
            step.target_role,
            step.target_ids,
            step.target_digest,
            step.limit_policy,
            step.serial,
            step.check_mode,
            step.variable_names,
            step.variables_digest,
            step.source_digest,
            step.command_digest,
            step.original_step_digest,
        ) == (
            previous.sequence,
            previous.mapping_sequence,
            previous.playbook,
            previous.condition,
            previous.condition_state,
            previous.classification,
            previous.target_role,
            previous.target_ids,
            previous.target_digest,
            previous.limit_policy,
            previous.serial,
            previous.check_mode,
            previous.variable_names,
            previous.variables_digest,
            previous.source_digest,
            previous.command_digest,
            previous.original_step_digest,
        )

    succeeded = tuple(
        step
        for step in record.steps
        if step.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
    )
    assert tuple(step.playbook for step in succeeded[:2]) == (
        "inventory-preflight",
        "connectivity-check",
    )
    assert all(
        step.evidence_state is DeployBaseOsReconciledEvidenceState.PREREQUISITE_BOUND
        for step in succeeded[:2]
    )
    assert len(succeeded[2:]) == 1
    assert succeeded[2].playbook == "base-os"
    assert succeeded[2].mapping_sequence == 3
    assert (
        succeeded[2].evidence_state is DeployBaseOsReconciledEvidenceState.BASE_OS_BOUND
    )

    next_required = tuple(
        step
        for step in record.steps
        if step.status
        is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
    )
    assert len(next_required) == 1
    assert next_required[0].mapping_sequence == 4
    assert next_required[0].playbook == "jump-host-configure"
    assert (
        next_required[0].evidence_state
        is DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED
    )
    assert next_required[0].evidence_digest is not None
    assert "deploy-authorization-not-collected" in next_required[0].blockers
    assert "mutating-deploy-execution-unavailable" in next_required[0].blockers
    assert "public-deploy-workflow-unavailable" in next_required[0].blockers

    assert all(
        step.status
        not in {
            DeployBaseOsReconciledStepStatus.SUCCEEDED,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
        }
        for step in record.steps
        if step.mapping_sequence > 4
    )
    later_base_os = tuple(
        step
        for step in record.steps
        if step.mapping_sequence == 6 and step.playbook == "base-os"
    )
    assert later_base_os
    assert all(
        step.status is DeployBaseOsReconciledStepStatus.BLOCKED
        and "base-os-evidence-not-performed" in step.blockers
        and "ordered-deploy-step-not-reached" in step.blockers
        for step in later_base_os
    )
    final = tuple(step for step in record.steps if step.mapping_sequence == 21)
    assert len(final) == 1
    assert final[0].playbook == "evidence-collect"
    assert final[0].status is DeployBaseOsReconciledStepStatus.NOT_PERFORMED
    assert final[0].evidence_state is DeployBaseOsReconciledEvidenceState.NOT_PERFORMED
    assert final[0].evidence_digest is None


@pytest.mark.parametrize("reboot_case", ("one", "all"))
def test_reboot_required_blocks_every_later_active_step_without_reboot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reboot_case: str,
) -> None:
    # The fixture has one exact authorized jump-host target, so one and all are
    # the same complete scope while exercising both required policy cases.
    prepared, _inventory, runner = _prepared(
        tmp_path,
        monkeypatch,
        mode="reboot",
    )
    process_count = len(runner.specs or ())
    report = _call(prepared)
    record = _record(prepared).record

    assert reboot_case in {"one", "all"}
    assert report.reboot_required
    assert report.reboot_required_count == report.base_os_host_count == 1
    assert report.reboot_handling_status == "not-performed"
    assert report.authorization_required_count == 0
    assert report.eligible_count == 0
    assert report.next_authorization_required == ()
    assert report.next_eligible == ()
    assert "reboot-required" in report.blocker_set
    assert "reboot-handling-not-performed" in report.blocker_set
    assert len(runner.specs or ()) == process_count

    base_os = tuple(
        step
        for step in record.steps
        if step.mapping_sequence == 3 and step.playbook == "base-os"
    )
    assert base_os
    assert all(
        step.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
        and step.evidence_state is DeployBaseOsReconciledEvidenceState.BASE_OS_BOUND
        for step in base_os
    )
    later_active = tuple(
        step
        for step in record.steps
        if step.mapping_sequence > 3
        and step.mapping_sequence != 21
        and step.condition_state.value != "inactive"
    )
    assert later_active
    assert all(
        step.status is DeployBaseOsReconciledStepStatus.BLOCKED
        and "reboot-required" in step.blockers
        and "reboot-handling-not-performed" in step.blockers
        for step in later_active
    )
    final = next(step for step in record.steps if step.mapping_sequence == 21)
    assert final.status is DeployBaseOsReconciledStepStatus.NOT_PERFORMED


@pytest.mark.parametrize("mode", ("missing", "extra", "wrong-host", "mixed"))
def test_incomplete_extra_wrong_host_and_mixed_evidence_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch)
    path = deploy_base_os_evidence_path(prepared.paths, OPERATION_ID)
    value = json.loads(path.read_text(encoding="utf-8"))
    entries = value["entries"]
    assert isinstance(entries, list)
    if mode == "missing":
        entries.clear()
        value["generation"] = 1
    elif mode == "extra":
        entries.append(dict(entries[0]))
        value["generation"] = len(entries)
    else:
        host = entries[0]["hosts"][0]
        if mode == "wrong-host":
            host["logical_id"] = "wrong-host"
        else:
            host["status"] = "changed"
            host["changed"] = True
    path.write_bytes(serialize_json(value))
    os.chmod(path, 0o600)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not deploy_base_os_reconciliation_path(prepared.paths, OPERATION_ID).exists()


@pytest.mark.parametrize(
    ("execution_mode", "expected_state"),
    (
        ("prepared", DeployBaseOsExecutionState.PREPARED),
        ("started", DeployBaseOsExecutionState.STARTED),
        ("failed", DeployBaseOsExecutionState.FAILED),
        ("uncertain", DeployBaseOsExecutionState.TIMED_OUT),
    ),
)
def test_nonterminal_failed_and_uncertain_execution_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    execution_mode: str,
    expected_state: DeployBaseOsExecutionState,
) -> None:
    prepared, inventory, executables, toolchain = _base_os_prepared(
        tmp_path, monkeypatch
    )
    original_execution_write = DeployBaseOsExecutionStore.write_locked
    original_evidence_write = DeployBaseOsEvidenceStore.append_locked

    if execution_mode == "prepared":

        def fail_started(self, record, **kwargs):
            if record.state is DeployBaseOsExecutionState.STARTED:
                raise StatePersistenceError("simulated pre-start refusal")
            return original_execution_write(self, record, **kwargs)

        monkeypatch.setattr(
            DeployBaseOsExecutionStore,
            "write_locked",
            fail_started,
        )
        with pytest.raises(StatePersistenceError):
            _execute_base_os(
                prepared,
                BaseOsRunner(inventory),
                executables,
                toolchain,
            )
    elif execution_mode == "started":

        def fail_evidence(self, record, **kwargs):
            raise StatePersistenceError("simulated post-start refusal")

        monkeypatch.setattr(
            DeployBaseOsEvidenceStore,
            "append_locked",
            fail_evidence,
        )
        with pytest.raises(StatePersistenceError):
            _execute_base_os(
                prepared,
                BaseOsRunner(inventory),
                executables,
                toolchain,
            )
    elif execution_mode == "failed":
        with pytest.raises(AnsibleError):
            _execute_base_os(
                prepared,
                BaseOsRunner(inventory, mode="nonzero"),
                executables,
                toolchain,
            )
    else:
        with pytest.raises(AnsibleError):
            _execute_base_os(
                prepared,
                BaseOsRunner(inventory, mode="timeout"),
                executables,
                toolchain,
            )
    monkeypatch.setattr(
        DeployBaseOsExecutionStore,
        "write_locked",
        original_execution_write,
    )
    monkeypatch.setattr(
        DeployBaseOsEvidenceStore,
        "append_locked",
        original_evidence_write,
    )
    execution = DeployBaseOsExecutionStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    assert execution.record.state is expected_state

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not deploy_base_os_reconciliation_path(prepared.paths, OPERATION_ID).exists()


@pytest.mark.parametrize(
    "drift",
    (
        "authorization",
        "execution",
        "evidence",
        "reconciliation",
        "source",
        "catalog",
        "readiness",
        "journal",
    ),
)
def test_bound_chain_drift_refused_before_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch)
    paths = prepared.paths
    if drift == "authorization":
        _tamper_digest(
            paths.operations
            / f"{OPERATION_ID}.ansible-deploy-base-os-authorization.json",
            "authorization_digest",
        )
    elif drift == "execution":
        path = deploy_base_os_execution_path(paths, OPERATION_ID)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["binding"]["catalog_digest"] = "sha256:" + "a" * 64
        path.write_bytes(serialize_json(value))
        os.chmod(path, 0o600)
    elif drift == "evidence":
        _tamper_digest(
            deploy_base_os_evidence_path(paths, OPERATION_ID),
            "binding",
            nested="source_digest",
        )
    elif drift == "reconciliation":
        _tamper_digest(
            deploy_host_evidence_reconciliation_path(paths, OPERATION_ID),
            "record_digest",
        )
    elif drift == "source":
        source = load_ansible_source_bundle()
        monkeypatch.setattr(
            reconciliation_module,
            "load_ansible_source_bundle",
            lambda: replace(source, digest="sha256:" + "b" * 64),
        )
    elif drift == "catalog":
        monkeypatch.setattr(
            reconciliation_module,
            "ansible_operation_catalog_digest",
            lambda: "sha256:" + "c" * 64,
        )
    elif drift == "readiness":
        _tamper_digest(
            paths.terraform_plans / f"{OPERATION_ID}.terraform-apply-readiness.json",
            "record_digest",
        )
    else:
        _tamper_digest(
            paths.operations / f"{OPERATION_ID}.json",
            "request_digest",
        )
    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _call(prepared)
    assert not deploy_base_os_reconciliation_path(paths, OPERATION_ID).exists()


def test_exact_reuse_write_failure_and_redaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch)
    original = DeployBaseOsReconciliationStore.write_locked

    def fail_write(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(
        DeployBaseOsReconciliationStore,
        "write_locked",
        fail_write,
    )
    with pytest.raises(StatePersistenceError) as caught:
        _call(prepared)
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    path = deploy_base_os_reconciliation_path(prepared.paths, OPERATION_ID)
    assert not path.exists()

    monkeypatch.setattr(
        DeployBaseOsReconciliationStore,
        "write_locked",
        original,
    )
    created = _call(prepared)
    first_bytes = path.read_bytes()
    first_mtime = path.stat().st_mtime_ns
    process_count = len(runner.specs or ())
    reused = _call(prepared)
    assert reused.artifact_state is DeployBaseOsReconciliationArtifactState.REUSED
    assert reused.to_object() == created.to_object() | {"artifact_state": "reused"}
    assert path.read_bytes() == first_bytes
    assert path.stat().st_mtime_ns == first_mtime
    assert path.stat().st_mode & 0o777 == 0o600
    assert len(runner.specs or ()) == process_count

    projected = json.dumps(created.to_object(), sort_keys=True)
    persisted = path.read_text(encoding="utf-8")
    for forbidden in (
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "ssh-ed25519",
        "fingerprint",
        "ProxyJump",
        "PLAY RECAP",
        "DSV_BASE_OS_B64",
        "--limit",
        "ansible-playbook",
        "environment",
        _PRIVATE_PATH,
        _SECRET,
    ):
        assert forbidden not in projected
        assert forbidden not in persisted
    assert "deploy_scylla_vms_" not in projected


def test_lock_path_symlink_permissions_and_ambiguity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        reconcile_deploy_base_os_result(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
        )

    path = deploy_base_os_reconciliation_path(prepared.paths, OPERATION_ID)
    target = prepared.paths.operations / "fake-post-base-os-target.json"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _call(prepared)
    path.unlink()
    target.unlink()

    execution_path = deploy_base_os_execution_path(prepared.paths, OPERATION_ID)
    execution_path.chmod(0o644)
    with pytest.raises(UnsafePathError):
        _call(prepared)
    execution_path.chmod(0o600)

    ambiguous = prepared.paths.operations / (
        f"{{{OPERATION_ID}}}.ansible-deploy-base-os-reconciliation.json"
    )
    ambiguous.write_text("{}\n", encoding="utf-8")
    ambiguous.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _call(prepared)


def _tamper_digest(path: Path, field: str, *, nested: str | None = None) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    if nested is None:
        value[field] = "sha256:" + "d" * 64
    else:
        value[field][nested] = "sha256:" + "d" * 64
    path.write_bytes(serialize_json(value))
    os.chmod(path, 0o600)
