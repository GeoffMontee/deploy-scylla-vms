import inspect
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from test_ansible_deploy_non_jump_base_os_execution import (
    BaseOsRunner,
)
from test_ansible_deploy_non_jump_base_os_execution import (
    _call as _execute_base_os,
)
from test_ansible_deploy_non_jump_base_os_execution import (
    _prepared as _base_os_prepared,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_reconciliation as reconciliation_module
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_non_jump_base_os_execution import (
    DeployNonJumpBaseOsEvidenceStore,
    DeployNonJumpBaseOsExecutionState,
    DeployNonJumpBaseOsExecutionStore,
    deploy_non_jump_base_os_evidence_path,
    deploy_non_jump_base_os_execution_path,
)
from scylla_vms.ansible.deploy_non_jump_base_os_reconciliation import (
    ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_SCHEMA_VERSION,
    DeployPostNonJumpBaseOsArtifactState,
    DeployPostNonJumpBaseOsReconciliationStore,
    deploy_post_non_jump_base_os_reconciliation_path,
    reconcile_deploy_non_jump_base_os_result,
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

_PRIVATE_PATH = "/private/operator/post-non-jump-base-os.json"
_SECRET = "obviously-fake-post-non-jump-base-os-secret"


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
        return reconcile_deploy_non_jump_base_os_result(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployPostNonJumpBaseOsReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


@pytest.mark.parametrize(
    ("mode", "changed_count", "already_current_count"),
    (("no-change", 0, 3), ("changed", 3, 0)),
)
def test_no_change_and_changed_advance_only_storage_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    changed_count: int,
    already_current_count: int,
) -> None:
    assert tuple(
        inspect.signature(reconcile_deploy_non_jump_base_os_result).parameters
    ) == ("state_root", "cluster_name", "operation_id", "lock")
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch, mode=mode)
    immutable_paths = (
        prepared.paths.operations / f"{OPERATION_ID}.json",
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-post-final-routes-reconciliation.json",
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-non-jump-base-os-authorization.json",
        deploy_non_jump_base_os_execution_path(prepared.paths, OPERATION_ID),
        deploy_non_jump_base_os_evidence_path(prepared.paths, OPERATION_ID),
    )
    immutable = tuple(path.read_bytes() for path in immutable_paths)
    process_count = len(runner.specs or ())
    show_before = _run_show(prepared.paths)

    report = _call(prepared)
    stored = _record(prepared)

    assert report.schema_version == (
        ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    assert stored.record.schema_version == (
        ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_SCHEMA_VERSION
    )
    assert report.artifact_state is DeployPostNonJumpBaseOsArtifactState.CREATED
    assert report.base_os_scope_count == 1
    assert report.base_os_host_count == 3
    assert report.changed_count == changed_count
    assert report.already_current_count == already_current_count
    assert not report.reboot_required
    assert report.reboot_required_count == 0
    assert report.reboot_handling_status == "not-performed"
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert report.authorization_state == "consumed-by-execution"
    assert report.execution_state == "succeeded"
    assert report.next_execution_state == "not-started"
    assert report.eligible_count == 1
    assert report.authorization_required_count == 0
    assert tuple(
        (
            item.playbook,
            item.target_role,
            item.classification.value,
            item.status.value,
            item.instance_count,
            item.target_count,
        )
        for item in report.next_steps
    ) == (("storage-discover", "scylla", "read-only", "eligible", 1, 1),)
    assert len(runner.specs or ()) == process_count
    assert tuple(path.read_bytes() for path in immutable_paths) == immutable
    assert _run_show(prepared.paths) == show_before

    executed = tuple(
        step
        for step in stored.record.steps
        if step.mapping_sequence == 6
        and step.playbook == "base-os"
        and step.condition == "non-jump-managed-hosts"
    )
    assert len(executed) == 1
    assert executed[0].status is DeployBaseOsReconciledStepStatus.SUCCEEDED
    assert (
        executed[0].evidence_state
        is DeployBaseOsReconciledEvidenceState.NON_JUMP_BASE_OS_BOUND
    )
    immediate = tuple(
        step
        for step in stored.record.steps
        if step.status is DeployBaseOsReconciledStepStatus.ELIGIBLE
    )
    assert len(immediate) == 1
    assert immediate[0].mapping_sequence == 7
    assert immediate[0].playbook == "storage-discover"
    assert immediate[0].target_role == "scylla"
    assert immediate[0].target_ids == ("scylla-ad-1-1",)
    assert all(
        step.status
        not in {
            DeployBaseOsReconciledStepStatus.SUCCEEDED,
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
        for step in stored.record.steps
        if step.mapping_sequence > 7
    )


@pytest.mark.parametrize(
    ("mode", "reboot_count"),
    (("mixed-reboot", 1), ("reboot", 3)),
)
def test_mixed_and_all_reboot_block_every_later_gate_without_reusing_old_reboots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    reboot_count: int,
) -> None:
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch, mode=mode)
    # The earlier jump-host reboot chain is real and complete in this fixture.
    # It must not satisfy a new reboot requirement from the non-jump scope.
    assert (
        prepared.paths.operations / f"{OPERATION_ID}.ansible-deploy-reboot-plan.json"
    ).exists()
    assert (
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-reboot-evidence.json"
    ).exists()
    process_count = len(runner.specs or ())

    report = _call(prepared)
    record = _record(prepared).record

    assert report.reboot_required
    assert report.reboot_required_count == reboot_count
    assert report.reboot_handling_status == "not-performed"
    assert report.next_steps == ()
    assert report.eligible_count == 0
    assert report.authorization_required_count == 0
    assert "reboot-required" in report.blocker_set
    assert "reboot-handling-not-performed" in report.blocker_set
    assert len(runner.specs or ()) == process_count
    assert all("reboot_artifact" not in name for name in record.__dataclass_fields__)
    later = tuple(
        step
        for step in record.steps
        if step.mapping_sequence > 6
        and step.mapping_sequence != 21
        and step.condition_state.value != "inactive"
    )
    assert later
    assert all(
        step.status is DeployBaseOsReconciledStepStatus.BLOCKED
        and "reboot-required" in step.blockers
        and "reboot-handling-not-performed" in step.blockers
        for step in later
    )
    final = next(step for step in record.steps if step.mapping_sequence == 21)
    assert final.status is DeployBaseOsReconciledStepStatus.NOT_PERFORMED


@pytest.mark.parametrize(
    "mode",
    ("missing", "extra", "duplicate", "wrong-host", "wrong-scope"),
)
def test_malformed_incomplete_duplicate_and_wrong_scope_evidence_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch)
    if mode == "wrong-scope":
        path = deploy_non_jump_base_os_execution_path(prepared.paths, OPERATION_ID)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["binding"]["stable_id_set_digest"] = "sha256:" + "a" * 64
    else:
        path = deploy_non_jump_base_os_evidence_path(prepared.paths, OPERATION_ID)
        value = json.loads(path.read_text(encoding="utf-8"))
        entries = value["entries"]
        assert isinstance(entries, list)
        if mode == "missing":
            entries.clear()
            value["generation"] = 0
        elif mode in {"extra", "duplicate"}:
            entries.append(dict(entries[0]))
            value["generation"] = len(entries)
        else:
            entries[0]["hosts"][0]["logical_id"] = "wrong-host"
    path.write_bytes(serialize_json(value))
    os.chmod(path, 0o600)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not deploy_post_non_jump_base_os_reconciliation_path(
        prepared.paths, OPERATION_ID
    ).exists()


@pytest.mark.parametrize(
    ("execution_mode", "expected_state"),
    (
        ("prepared", DeployNonJumpBaseOsExecutionState.PREPARED),
        ("started", DeployNonJumpBaseOsExecutionState.STARTED),
        ("failed", DeployNonJumpBaseOsExecutionState.FAILED),
        ("uncertain", DeployNonJumpBaseOsExecutionState.TIMED_OUT),
    ),
)
def test_nonterminal_failed_and_uncertain_execution_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    execution_mode: str,
    expected_state: DeployNonJumpBaseOsExecutionState,
) -> None:
    prepared, inventory, executables, toolchain = _base_os_prepared(
        tmp_path, monkeypatch
    )
    original_execution_write = DeployNonJumpBaseOsExecutionStore.write_locked
    original_evidence_write = DeployNonJumpBaseOsEvidenceStore.append_locked

    if execution_mode == "prepared":

        def fail_started(self, record, **kwargs):
            if record.state is DeployNonJumpBaseOsExecutionState.STARTED:
                raise StatePersistenceError("simulated pre-start refusal")
            return original_execution_write(self, record, **kwargs)

        monkeypatch.setattr(
            DeployNonJumpBaseOsExecutionStore, "write_locked", fail_started
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
            DeployNonJumpBaseOsEvidenceStore, "append_locked", fail_evidence
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
        DeployNonJumpBaseOsExecutionStore,
        "write_locked",
        original_execution_write,
    )
    monkeypatch.setattr(
        DeployNonJumpBaseOsEvidenceStore,
        "append_locked",
        original_evidence_write,
    )
    execution = DeployNonJumpBaseOsExecutionStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    assert execution.record.state is expected_state

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not deploy_post_non_jump_base_os_reconciliation_path(
        prepared.paths, OPERATION_ID
    ).exists()


@pytest.mark.parametrize(
    "drift",
    (
        "authorization",
        "execution",
        "evidence",
        "prior-reconciliation",
        "inventory",
        "readiness",
        "source",
        "catalog",
        "journal",
    ),
)
def test_full_chain_drift_refused_before_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch)
    paths = prepared.paths
    if drift == "authorization":
        _tamper_digest(
            paths.operations
            / f"{OPERATION_ID}.ansible-deploy-non-jump-base-os-authorization.json",
            "authorization_digest",
        )
    elif drift == "execution":
        path = deploy_non_jump_base_os_execution_path(paths, OPERATION_ID)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["binding"]["catalog_digest"] = "sha256:" + "a" * 64
        path.write_bytes(serialize_json(value))
        os.chmod(path, 0o600)
    elif drift == "evidence":
        path = deploy_non_jump_base_os_evidence_path(paths, OPERATION_ID)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["binding"]["source_digest"] = "sha256:" + "b" * 64
        path.write_bytes(serialize_json(value))
        os.chmod(path, 0o600)
    elif drift == "prior-reconciliation":
        _tamper_digest(
            paths.operations
            / f"{OPERATION_ID}.ansible-deploy-post-final-routes-reconciliation.json",
            "record_digest",
        )
    elif drift == "inventory":
        path = paths.ansible_inventory
        value = json.loads(path.read_text(encoding="utf-8"))
        value["unexpected"] = _SECRET
        path.write_bytes(serialize_json(value))
        os.chmod(path, 0o600)
    elif drift == "readiness":
        _tamper_digest(
            paths.terraform_plans / f"{OPERATION_ID}.terraform-apply-readiness.json",
            "record_digest",
        )
    elif drift == "source":
        source = load_ansible_source_bundle()
        monkeypatch.setattr(
            reconciliation_module,
            "load_ansible_source_bundle",
            lambda: replace(source, digest="sha256:" + "c" * 64),
        )
    elif drift == "catalog":
        monkeypatch.setattr(
            reconciliation_module,
            "ansible_operation_catalog_digest",
            lambda: "sha256:" + "d" * 64,
        )
    else:
        _tamper_digest(
            paths.operations / f"{OPERATION_ID}.json",
            "request_digest",
        )
    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _call(prepared)
    assert not deploy_post_non_jump_base_os_reconciliation_path(
        paths, OPERATION_ID
    ).exists()


def test_exact_reuse_write_failure_permissions_redaction_and_zero_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch)
    original = DeployPostNonJumpBaseOsReconciliationStore.write_locked

    def fail_write(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(
        DeployPostNonJumpBaseOsReconciliationStore,
        "write_locked",
        fail_write,
    )
    with pytest.raises(StatePersistenceError) as caught:
        _call(prepared)
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    path = deploy_post_non_jump_base_os_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    assert not path.exists()

    monkeypatch.setattr(
        DeployPostNonJumpBaseOsReconciliationStore,
        "write_locked",
        original,
    )
    created = _call(prepared)
    first_bytes = path.read_bytes()
    first_mtime = path.stat().st_mtime_ns
    process_count = len(runner.specs or ())
    reused = _call(prepared)
    assert reused.artifact_state is DeployPostNonJumpBaseOsArtifactState.REUSED
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
        reconcile_deploy_non_jump_base_os_result(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
        )

    path = deploy_post_non_jump_base_os_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    target = prepared.paths.operations / "fake-post-non-jump-target.json"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _call(prepared)
    path.unlink()
    target.unlink()

    execution_path = deploy_non_jump_base_os_execution_path(
        prepared.paths, OPERATION_ID
    )
    execution_path.chmod(0o644)
    with pytest.raises(UnsafePathError):
        _call(prepared)
    execution_path.chmod(0o600)

    ambiguous = prepared.paths.operations / (
        f"{{{OPERATION_ID}}}.ansible-deploy-post-non-jump-base-os-reconciliation.json"
    )
    ambiguous.write_text("{}\n", encoding="utf-8")
    ambiguous.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _call(prepared)


def _tamper_digest(path: Path, field: str) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    value[field] = "sha256:" + "e" * 64
    path.write_bytes(serialize_json(value))
    os.chmod(path, 0o600)
