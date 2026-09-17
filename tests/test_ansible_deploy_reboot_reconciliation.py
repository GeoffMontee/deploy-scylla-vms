import inspect
import json
import os
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_reboot_execution import (
    RebootRunner,
)
from test_ansible_deploy_reboot_execution import (
    _call as _execute_reboots,
)
from test_ansible_deploy_reboot_execution import (
    _prepared as _reboot_prepared,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_reboot_execution as execution_module
import scylla_vms.ansible.deploy_reboot_reconciliation as reconciliation_module
import scylla_vms.ansible.deploy_reconciliation as deploy_reconciliation_module
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStepStatus,
    DeployBaseOsReconciliationStore,
)
from scylla_vms.ansible.deploy_prerequisites import (
    deploy_prerequisite_evidence_path,
    deploy_prerequisite_execution_path,
)
from scylla_vms.ansible.deploy_reboot import (
    DeployRebootResult,
)
from scylla_vms.ansible.deploy_reboot_execution import (
    DeployRebootEvidence,
    DeployRebootEvidenceEntry,
    DeployRebootEvidenceStore,
    DeployRebootExecution,
    DeployRebootExecutionState,
    DeployRebootExecutionStore,
    StoredDeployRebootEvidence,
    StoredDeployRebootExecution,
    deploy_reboot_evidence_path,
    deploy_reboot_execution_path,
)
from scylla_vms.ansible.deploy_reboot_reconciliation import (
    ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION,
    DeployPostRebootArtifactState,
    DeployPostRebootBranch,
    DeployPostRebootReconciliationStore,
    deploy_post_reboot_reconciliation_path,
    reconcile_deploy_post_reboot_plan,
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

_SECRET = "obviously-fake-post-reboot-secret"
_PRIVATE_PATH = "/private/operator/post-reboot.json"


def _prepared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    reboot_required: bool = True,
    execute: bool = True,
    runner_mode: str = "success",
):
    prepared, _inventory, executables, toolchain = _reboot_prepared(
        tmp_path,
        monkeypatch,
        reboot_required=reboot_required,
    )
    runner = RebootRunner(mode=runner_mode)
    if reboot_required and execute:
        _execute_reboots(prepared, runner, executables, toolchain)
    return prepared, runner, executables, toolchain


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_post_reboot_plan(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployPostRebootReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


def test_no_reboot_branch_is_not_required_and_preserves_next_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(inspect.signature(reconcile_deploy_post_reboot_plan).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    prepared, runner, _executables, _toolchain = _prepared(
        tmp_path,
        monkeypatch,
        reboot_required=False,
    )
    prior = DeployBaseOsReconciliationStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    process_count = len(cast(list[object], runner.specs))

    report = _call(prepared)
    stored = _record(prepared)

    assert report.schema_version == (
        ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    assert stored.record.schema_version == (
        ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION
    )
    assert report.branch is DeployPostRebootBranch.NO_REBOOT_REQUIRED
    assert report.reboot_handling_status == "not-required"
    assert report.reboot_evidence_state == "not-required"
    assert report.reboot_target_count == report.reboot_succeeded_count == 0
    assert report.reconnect_count == report.reboot_clear_count == 0
    assert report.reboot_target_set_digest is None
    assert report.reboot_target_order_digest is None
    assert stored.record.steps == prior.record.steps
    assert tuple(
        (item.playbook, item.instance_count, item.stable_id_count)
        for item in report.next_authorization_required
    ) == (("jump-host-configure", 1, 1),)
    assert report.next_authorization_required_count == 1
    assert report.next_authorization_target_count == 1
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert len(cast(list[object], runner.specs)) == process_count


def test_successful_reboot_scope_clears_only_reboot_blockers_and_no_leapfrog(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    process_count = len(cast(list[object], runner.specs))
    journal = prepared.paths.operations / f"{OPERATION_ID}.json"
    base_reconciliation = DeployBaseOsReconciliationStore(
        prepared.paths, OPERATION_ID
    ).path
    immutable_bytes = (journal.read_bytes(), base_reconciliation.read_bytes())
    show_before = _run_show(prepared.paths)

    report = _call(prepared)
    record = _record(prepared).record

    assert report.branch is DeployPostRebootBranch.REBOOT_REQUIRED
    assert report.reboot_handling_status == "succeeded"
    assert report.reboot_evidence_state == "reboot-evidence-bound"
    assert report.reboot_target_count == report.reboot_succeeded_count == 1
    assert report.reconnect_count == report.reboot_clear_count == 1
    assert report.reboot_target_set_digest is not None
    assert report.reboot_target_order_digest is not None
    assert len(cast(list[object], runner.specs)) == process_count
    assert (journal.read_bytes(), base_reconciliation.read_bytes()) == immutable_bytes
    assert _run_show(prepared.paths) == show_before

    assert all(
        blocker not in {"reboot-required", "reboot-handling-not-performed"}
        for blocker in record.blocker_set
    )
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
    next_required = tuple(
        step
        for step in record.steps
        if step.status
        is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
    )
    assert len(next_required) == 1
    assert next_required[0].mapping_sequence == 4
    assert next_required[0].playbook == "jump-host-configure"
    assert next_required[0].target_ids == ("jump-host-1",)
    assert "deploy-authorization-not-collected" in next_required[0].blockers
    assert "mutating-deploy-execution-unavailable" in next_required[0].blockers
    assert "public-deploy-workflow-unavailable" in next_required[0].blockers
    assert "ordered-deploy-step-not-reached" not in next_required[0].blockers
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
    final = next(
        step
        for step in record.steps
        if step.mapping_sequence
        == len(reconciliation_module.OPERATION_PLAYBOOKS["deploy"])
    )
    assert final.playbook == "evidence-collect"
    assert final.status is DeployBaseOsReconciledStepStatus.NOT_PERFORMED


@pytest.mark.parametrize(
    "tamper",
    ("missing", "partial", "extra", "reordered", "wrong-target"),
)
def test_missing_partial_extra_reordered_and_wrong_target_evidence_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    prepared, _runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    path = deploy_reboot_evidence_path(prepared.paths, OPERATION_ID)
    value = json.loads(path.read_text(encoding="utf-8"))
    entries = cast(list[dict[str, object]], value["entries"])
    if tamper == "missing":
        path.unlink()
    elif tamper == "partial":
        entries.clear()
        value["generation"] = 1
    elif tamper == "extra":
        entries.append(dict(entries[0]))
        value["generation"] = 2
    elif tamper == "reordered":
        entries[0]["sequence"] = 2
    else:
        entries[0]["logical_id"] = "wrong-target"
    if tamper != "missing":
        path.write_bytes(serialize_json(value))
        path.chmod(0o600)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not deploy_post_reboot_reconciliation_path(
        prepared.paths, OPERATION_ID
    ).exists()


@pytest.mark.parametrize("mode", ("failed", "unreachable", "timeout"))
def test_failed_uncertain_and_manual_recovery_execution_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    prepared, runner, executables, toolchain = _prepared(
        tmp_path,
        monkeypatch,
        execute=False,
        runner_mode=mode,
    )
    with pytest.raises(AnsibleError):
        _execute_reboots(prepared, runner, executables, toolchain)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not deploy_post_reboot_reconciliation_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_started_execution_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner, executables, toolchain = _prepared(
        tmp_path,
        monkeypatch,
        execute=False,
    )

    def fail_evidence(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError("injected post-start evidence failure")

    monkeypatch.setattr(DeployRebootEvidenceStore, "append_locked", fail_evidence)
    with pytest.raises(StatePersistenceError, match="manual recovery"):
        _execute_reboots(prepared, runner, executables, toolchain)
    stored = DeployRebootExecutionStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    assert stored.record.state is DeployRebootExecutionState.STARTED
    assert stored.record.attempts[-1].manual_recovery_required
    with pytest.raises(StateConflictError):
        _call(prepared)


@pytest.mark.parametrize(
    "field",
    (
        "services_safe_before",
        "reboot_performed",
        "reconnected",
        "boot_changed",
        "identity_verified",
        "trust_revalidated",
        "machine_evidence_verified",
        "services_safe_after",
        "reboot_required_clear",
    ),
)
def test_false_semantic_gate_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    prepared, _runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    path = deploy_reboot_evidence_path(prepared.paths, OPERATION_ID)
    value = json.loads(path.read_text(encoding="utf-8"))
    value["entries"][0][field] = False
    path.write_bytes(serialize_json(value))
    path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)


@pytest.mark.parametrize(
    ("artifact", "field", "nested"),
    (
        ("base-os-reconciliation", "record_digest", None),
        ("reboot-plan", "record_digest", None),
        ("reboot-authorization", "authorization_digest", None),
        ("reboot-execution", "catalog_digest", "binding"),
        ("connectivity-execution", "source_digest", None),
        ("connectivity-evidence", "source_digest", None),
        ("inventory", "inventory_digest", None),
        ("trust", "entries_digest", None),
        ("readiness", "record_digest", None),
        ("journal", "request_digest", None),
    ),
)
def test_bound_chain_drift_refused_before_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact: str,
    field: str,
    nested: str | None,
) -> None:
    prepared, _runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    paths = prepared.paths
    selected = {
        "base-os-reconciliation": DeployBaseOsReconciliationStore(
            paths, OPERATION_ID
        ).path,
        "reboot-plan": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-reboot-plan.json",
        "reboot-authorization": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-reboot-authorization.json",
        "reboot-execution": deploy_reboot_execution_path(paths, OPERATION_ID),
        "connectivity-execution": deploy_prerequisite_execution_path(
            paths, OPERATION_ID
        ),
        "connectivity-evidence": deploy_prerequisite_evidence_path(paths, OPERATION_ID),
        "inventory": paths.ansible_inventory,
        "trust": paths.ansible_trust,
        "readiness": paths.terraform_plans
        / f"{OPERATION_ID}.terraform-apply-readiness.json",
        "journal": paths.operations / f"{OPERATION_ID}.json",
    }[artifact]
    _tamper_digest(selected, field, nested=nested)
    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _call(prepared)
    assert not deploy_post_reboot_reconciliation_path(paths, OPERATION_ID).exists()


def test_source_catalog_and_base_os_result_drift_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    _tamper_digest(
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-base-os-evidence.json",
        "source_digest",
        nested="binding",
    )
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)


@pytest.mark.parametrize("drift", ("source", "catalog"))
def test_current_source_and_catalog_drift_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, _runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    if drift == "source":
        source = load_ansible_source_bundle()
        monkeypatch.setattr(
            deploy_reconciliation_module,
            "load_ansible_source_bundle",
            lambda: replace(source, digest="sha256:" + "a" * 64),
        )
    else:
        monkeypatch.setattr(
            deploy_reconciliation_module,
            "ansible_operation_catalog_digest",
            lambda: "sha256:" + "b" * 64,
        )
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not deploy_post_reboot_reconciliation_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_exact_reuse_write_failure_permissions_redaction_and_zero_runner_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    process_count = len(cast(list[object], runner.specs))
    original = DeployPostRebootReconciliationStore.write_locked

    def fail_write(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(
        DeployPostRebootReconciliationStore,
        "write_locked",
        fail_write,
    )
    with pytest.raises(StatePersistenceError) as caught:
        _call(prepared)
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    path = deploy_post_reboot_reconciliation_path(prepared.paths, OPERATION_ID)
    assert not path.exists()

    monkeypatch.setattr(
        DeployPostRebootReconciliationStore,
        "write_locked",
        original,
    )
    created = _call(prepared)
    first_bytes = path.read_bytes()
    first_mtime = path.stat().st_mtime_ns
    reused = _call(prepared)
    assert reused.artifact_state is DeployPostRebootArtifactState.REUSED
    assert reused.to_object() == created.to_object() | {"artifact_state": "reused"}
    assert path.read_bytes() == first_bytes
    assert path.stat().st_mtime_ns == first_mtime
    assert path.stat().st_mode & 0o777 == 0o600
    assert len(cast(list[object], runner.specs)) == process_count

    projected = json.dumps(created.to_object(), sort_keys=True)
    persisted = path.read_text(encoding="utf-8")
    for forbidden in (
        _SECRET,
        _PRIVATE_PATH,
        "boot_id",
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "ssh-ed25519",
        "fingerprint",
        "ProxyJump",
        "DSV_DEPLOY_REBOOT_B64",
        "ansible-playbook",
        "--limit",
        "environment",
    ):
        assert forbidden not in projected
        assert forbidden not in persisted


def test_wrong_lock_symlink_permission_and_ambiguity_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        reconcile_deploy_post_reboot_plan(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
        )
    path = deploy_post_reboot_reconciliation_path(prepared.paths, OPERATION_ID)
    target = prepared.paths.operations / "fake-post-reboot-target.json"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _call(prepared)
    path.unlink()
    target.unlink()

    evidence_path = deploy_reboot_evidence_path(prepared.paths, OPERATION_ID)
    evidence_path.chmod(0o644)
    with pytest.raises(UnsafePathError):
        _call(prepared)
    evidence_path.chmod(0o600)

    ambiguous = prepared.paths.operations / (
        f"{{{OPERATION_ID}}}.ansible-deploy-post-reboot-reconciliation.json"
    )
    ambiguous.write_text("{}\n", encoding="utf-8")
    ambiguous.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _call(prepared)


def test_multiple_complete_semantic_targets_validate_in_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = reconciliation_module._load_context(
            prepared.paths, OPERATION_ID, lock=lock
        )
    assert context.plan is not None
    assert context.authorization is not None
    assert context.execution is not None
    assert context.evidence is not None
    scopes, binding = reconciliation_module._rebuild_execution_binding(
        context.base,
        context.base_reconciliation,
        context.plan,
        context.authorization,
    )
    first_scope = scopes[0]
    second_target = replace(
        first_scope.target,
        sequence=2,
        stable_id="jump-host-2",
    )
    second_scope = replace(
        first_scope,
        target=second_target,
        target_plan_digest=reconciliation_module._digest_object(
            second_target.to_object()
        ),
    )
    all_scopes = (first_scope, second_scope)
    binding_values = {
        name: getattr(binding, name) for name in binding.__dataclass_fields__
    }
    binding_values.update(
        {
            "binding_digest": "",
            "target_count": 2,
            "target_set_digest": reconciliation_module._digest_object(
                ["jump-host-1", "jump-host-2"]
            ),
            "target_order_digest": reconciliation_module._digest_object(
                ["jump-host-1", "jump-host-2"]
            ),
        }
    )
    binding_values["binding_digest"] = (
        reconciliation_module._binding_digest_from_values(binding_values)
    )
    multi_binding = type(binding)(**binding_values)
    first_attempt = context.execution.record.attempts[0]
    first_entry = context.evidence.record.entries[0]
    second_result = DeployRebootResult(
        logical_id="jump-host-2",
        role=first_entry.role,
        status=first_entry.status,
        os_family=first_entry.os_family,
        os_version=first_entry.os_version,
        architecture=first_entry.architecture,
        services_safe_before=True,
        reboot_performed=True,
        reconnected=True,
        boot_changed=True,
        identity_verified=True,
        trust_revalidated=True,
        machine_evidence_verified=True,
        services_safe_after=True,
        reboot_required_clear=True,
        elapsed_seconds=first_entry.elapsed_seconds,
        request_digest=second_scope.request_digest,
    )
    entry_values = {
        name: getattr(first_entry, name) for name in first_entry.__dataclass_fields__
    }
    entry_values.update(
        {
            "sequence": 2,
            "stable_id": "jump-host-2",
            "target_plan_digest": second_scope.target_plan_digest,
            "result_digest": reconciliation_module._digest_object(
                second_result.to_object()
            ),
            "evidence_digest": "",
        }
    )
    entry_values["evidence_digest"] = execution_module._entry_digest_from_values(
        entry_values
    )
    second_entry = DeployRebootEvidenceEntry(**entry_values)
    second_attempt = replace(
        first_attempt,
        sequence=2,
        stable_id="jump-host-2",
        target_plan_digest=second_scope.target_plan_digest,
        result_digest=second_entry.result_digest,
        evidence_digest=second_entry.evidence_digest,
    )
    execution = StoredDeployRebootExecution(
        DeployRebootExecution(
            generation=6,
            created_at=context.execution.record.created_at,
            updated_at=context.execution.record.updated_at,
            binding=multi_binding,
            state=DeployRebootExecutionState.SUCCEEDED,
            authorization_consumed=True,
            invocation_count=2,
            completed_target_count=2,
            all_targets_completed=True,
            attempts=(first_attempt, second_attempt),
        ),
        "sha256:" + "e" * 64,
    )
    evidence = StoredDeployRebootEvidence(
        DeployRebootEvidence(
            generation=2,
            created_at=context.evidence.record.created_at,
            updated_at=context.evidence.record.updated_at,
            binding=multi_binding,
            entries=(first_entry, second_entry),
        ),
        "sha256:" + "f" * 64,
    )
    assert reconciliation_module._validate_complete_reboot(
        all_scopes,
        multi_binding,
        execution,
        evidence,
    ) == (first_entry, second_entry)


def _tamper_digest(path: Path, field: str, *, nested: str | None = None) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    if nested is None:
        value[field] = "sha256:" + "d" * 64
    else:
        value[nested][field] = "sha256:" + "d" * 64
    path.write_bytes(serialize_json(value))
    os.chmod(path, 0o600)
