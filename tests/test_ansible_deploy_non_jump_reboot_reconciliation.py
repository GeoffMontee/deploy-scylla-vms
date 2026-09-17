import inspect
import json
import os
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_non_jump_reboot_execution import (
    NonJumpRebootRunner,
)
from test_ansible_deploy_non_jump_reboot_execution import (
    _call as _execute_non_jump_reboots,
)
from test_ansible_deploy_non_jump_reboot_execution import (
    _prepared as _reboot_prepared,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_non_jump_reboot_reconciliation as reconciliation_module
import scylla_vms.ansible.deploy_reconciliation as deploy_reconciliation_module
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_non_jump_reboot_execution import (
    DeployNonJumpRebootEvidenceStore,
    DeployNonJumpRebootExecutionState,
    DeployNonJumpRebootExecutionStore,
    deploy_non_jump_reboot_evidence_path,
    deploy_non_jump_reboot_execution_path,
)
from scylla_vms.ansible.deploy_non_jump_reboot_reconciliation import (
    ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_SCHEMA_VERSION,
    DeployPostNonJumpRebootArtifactState,
    DeployPostNonJumpRebootBranch,
    DeployPostNonJumpRebootReconciliationStore,
    deploy_post_non_jump_reboot_reconciliation_path,
    reconcile_deploy_post_non_jump_reboot_plan,
)
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.persistence import serialize_json

_SECRET = "obviously-fake-post-non-jump-reboot-secret"
_PRIVATE_PATH = "/private/operator/post-non-jump-reboot.json"


def _prepared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    mode: str = "reboot",
    execute: bool = True,
    runner_mode: str = "success",
):
    prepared, executables, toolchain = _reboot_prepared(
        tmp_path, monkeypatch, mode=mode
    )
    runner = NonJumpRebootRunner(mode=runner_mode)
    if mode in {"reboot", "mixed-reboot"} and execute:
        _execute_non_jump_reboots(prepared, runner, executables, toolchain)
    return prepared, runner, executables, toolchain


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_post_non_jump_reboot_plan(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployPostNonJumpRebootReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


def test_no_reboot_branch_preserves_derived_storage_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(
        inspect.signature(reconcile_deploy_post_non_jump_reboot_plan).parameters
    ) == ("state_root", "cluster_name", "operation_id", "lock")
    prepared, runner, _executables, _toolchain = _prepared(
        tmp_path, monkeypatch, mode="no-change"
    )
    process_count = len(cast(list[object], runner.specs))
    prior_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-post-non-jump-base-os-reconciliation.json"
    )
    prior_bytes = prior_path.read_bytes()

    report = _call(prepared)
    stored = _record(prepared)

    assert report.schema_version == (
        ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    assert stored.record.schema_version == (
        ANSIBLE_DEPLOY_POST_NON_JUMP_REBOOT_RECONCILIATION_SCHEMA_VERSION
    )
    assert report.branch is DeployPostNonJumpRebootBranch.NO_REBOOT_REQUIRED
    assert report.reboot_handling_status == "not-required"
    assert report.reboot_evidence_state == "not-required"
    assert report.reboot_target_count == report.reboot_succeeded_count == 0
    assert report.reconnect_count == report.reboot_clear_count == 0
    assert tuple(
        (
            item.playbook,
            item.target_role,
            item.status.value,
            item.instance_count,
        )
        for item in report.next_steps
    ) == (("storage-discover", "scylla", "eligible", 1),)
    assert prior_path.read_bytes() == prior_bytes
    assert not deploy_non_jump_reboot_execution_path(
        prepared.paths, OPERATION_ID
    ).exists()
    assert len(cast(list[object], runner.specs)) == process_count


def test_complete_reboot_clears_only_reboot_blockers_and_advances_one_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    process_count = len(cast(list[object], runner.specs))
    journal = prepared.paths.operations / f"{OPERATION_ID}.json"
    prior = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-post-non-jump-base-os-reconciliation.json"
    )
    immutable = (journal.read_bytes(), prior.read_bytes())
    show_before = _run_show(prepared.paths)

    report = _call(prepared)
    record = _record(prepared).record

    assert report.branch is DeployPostNonJumpRebootBranch.REBOOT_REQUIRED
    assert report.reboot_handling_status == "succeeded"
    assert report.reboot_evidence_state == "non-jump-reboot-evidence-bound"
    assert report.reboot_target_count == report.reboot_succeeded_count == 3
    assert report.reconnect_count == report.boot_changed_count == 3
    assert report.identity_verified_count == report.trust_revalidated_count == 3
    assert report.machine_evidence_verified_count == 3
    assert report.service_safety_count == report.reboot_clear_count == 3
    assert (journal.read_bytes(), prior.read_bytes()) == immutable
    assert len(cast(list[object], runner.specs)) == process_count
    assert _run_show(prepared.paths) == show_before
    assert all(
        blocker not in {"reboot-required", "reboot-handling-not-performed"}
        for blocker in record.blocker_set
    )
    next_steps = tuple(
        step
        for step in record.steps
        if step.status
        in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
    )
    assert len(next_steps) == 1
    assert next_steps[0].playbook == "storage-discover"
    assert next_steps[0].status is DeployBaseOsReconciledStepStatus.ELIGIBLE
    assert next_steps[0].blockers == ()
    assert all(
        step.status
        not in {
            DeployBaseOsReconciledStepStatus.SUCCEEDED,
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
        for step in record.steps
        if step.mapping_sequence > next_steps[0].mapping_sequence
    )


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
def test_every_post_reboot_semantic_gate_is_required(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    prepared, _runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    path = deploy_non_jump_reboot_evidence_path(prepared.paths, OPERATION_ID)
    value = json.loads(path.read_text(encoding="utf-8"))
    value["entries"][0][field] = False
    path.write_bytes(serialize_json(value))
    path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not deploy_post_non_jump_reboot_reconciliation_path(
        prepared.paths, OPERATION_ID
    ).exists()


@pytest.mark.parametrize("tamper", ("missing", "partial", "extra", "reordered"))
def test_missing_partial_extra_and_reordered_evidence_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    prepared, _runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    path = deploy_non_jump_reboot_evidence_path(prepared.paths, OPERATION_ID)
    value = json.loads(path.read_text(encoding="utf-8"))
    entries = cast(list[dict[str, object]], value["entries"])
    if tamper == "missing":
        path.unlink()
    elif tamper == "partial":
        entries.pop()
        value["generation"] = len(entries)
    elif tamper == "extra":
        entries.append(dict(entries[-1]))
        value["generation"] = len(entries)
    else:
        entries[0], entries[1] = entries[1], entries[0]
    if tamper != "missing":
        path.write_bytes(serialize_json(value))
        path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)


@pytest.mark.parametrize("mode", ("failed", "unreachable", "timeout"))
def test_failed_and_uncertain_execution_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    prepared, runner, executables, toolchain = _prepared(
        tmp_path, monkeypatch, execute=False, runner_mode=mode
    )
    with pytest.raises(AnsibleError):
        _execute_non_jump_reboots(prepared, runner, executables, toolchain)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)


def test_started_execution_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner, executables, toolchain = _prepared(
        tmp_path, monkeypatch, execute=False
    )

    def fail_evidence(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError("injected evidence failure")

    monkeypatch.setattr(
        DeployNonJumpRebootEvidenceStore, "append_locked", fail_evidence
    )
    with pytest.raises(StatePersistenceError, match="manual recovery"):
        _execute_non_jump_reboots(prepared, runner, executables, toolchain)
    execution = DeployNonJumpRebootExecutionStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    assert execution.record.state is DeployNonJumpRebootExecutionState.STARTED
    with pytest.raises(StateConflictError):
        _call(prepared)


@pytest.mark.parametrize(
    ("artifact", "field", "nested"),
    (
        ("prior", "record_digest", None),
        ("plan", "record_digest", None),
        ("authorization", "authorization_digest", None),
        ("execution", "catalog_digest", "binding"),
        ("evidence", "source_digest", "binding"),
        ("inventory", "inventory_digest", None),
        ("trust", "entries_digest", None),
        ("readiness", "record_digest", None),
        ("journal", "request_digest", None),
    ),
)
def test_full_chain_drift_refused_before_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact: str,
    field: str,
    nested: str | None,
) -> None:
    prepared, _runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    paths = prepared.paths
    selected = {
        "prior": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-post-non-jump-base-os-reconciliation.json",
        "plan": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-non-jump-reboot-plan.json",
        "authorization": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-non-jump-reboot-authorization.json",
        "execution": deploy_non_jump_reboot_execution_path(paths, OPERATION_ID),
        "evidence": deploy_non_jump_reboot_evidence_path(paths, OPERATION_ID),
        "inventory": paths.ansible_inventory,
        "trust": paths.ansible_trust,
        "readiness": paths.terraform_plans
        / f"{OPERATION_ID}.terraform-apply-readiness.json",
        "journal": paths.operations / f"{OPERATION_ID}.json",
    }[artifact]
    _tamper_digest(selected, field, nested=nested)
    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _call(prepared)
    assert not deploy_post_non_jump_reboot_reconciliation_path(
        paths, OPERATION_ID
    ).exists()


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


def test_exact_reuse_permissions_redaction_write_failure_and_show_recognition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    process_count = len(cast(list[object], runner.specs))
    original = DeployPostNonJumpRebootReconciliationStore.write_locked

    def fail_write(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(
        DeployPostNonJumpRebootReconciliationStore, "write_locked", fail_write
    )
    with pytest.raises(StatePersistenceError) as caught:
        _call(prepared)
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)

    monkeypatch.setattr(
        DeployPostNonJumpRebootReconciliationStore, "write_locked", original
    )
    created = _call(prepared)
    path = deploy_post_non_jump_reboot_reconciliation_path(prepared.paths, OPERATION_ID)
    first_bytes = path.read_bytes()
    first_mtime = path.stat().st_mtime_ns
    show_result = _run_show(prepared.paths)
    assert show_result[1].startswith('{"cluster":')
    assert show_result[2] == ""

    reused = _call(prepared)
    assert reused.artifact_state is DeployPostNonJumpRebootArtifactState.REUSED
    assert path.read_bytes() == first_bytes
    assert path.stat().st_mtime_ns == first_mtime
    assert path.stat().st_mode & 0o777 == 0o600
    assert len(cast(list[object], runner.specs)) == process_count
    persisted = path.read_text(encoding="utf-8")
    projected = json.dumps(created.to_object(), sort_keys=True)
    for forbidden in (
        _SECRET,
        _PRIVATE_PATH,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "ssh-ed25519",
        "fingerprint",
        "ProxyJump",
        "boot_id",
        "DSV_DEPLOY_REBOOT_B64",
        "ansible-playbook",
        "--limit",
        "environment",
    ):
        assert forbidden not in persisted
        assert forbidden not in projected


def test_wrong_lock_symlink_permission_and_ambiguity_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        reconcile_deploy_post_non_jump_reboot_plan(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
        )
    path = deploy_post_non_jump_reboot_reconciliation_path(prepared.paths, OPERATION_ID)
    target = prepared.paths.operations / "fake-post-non-jump-reboot-target.json"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _call(prepared)
    path.unlink()
    target.unlink()

    evidence = deploy_non_jump_reboot_evidence_path(prepared.paths, OPERATION_ID)
    evidence.chmod(0o644)
    with pytest.raises(UnsafePathError):
        _call(prepared)
    evidence.chmod(0o600)

    ambiguous = prepared.paths.operations / (
        f"{{{OPERATION_ID}}}.ansible-deploy-post-non-jump-reboot-reconciliation.json"
    )
    ambiguous.write_text("{}\n", encoding="utf-8")
    ambiguous.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _call(prepared)


def test_next_gate_is_selected_from_first_remaining_active_mapping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    observed: list[tuple[int, str]] = []
    original = reconciliation_module._next_gate_ready

    def observe(step, context):
        observed.append((step.mapping_sequence, step.playbook))
        return original(step, context)

    monkeypatch.setattr(reconciliation_module, "_next_gate_ready", observe)
    _call(prepared)
    assert observed == [(7, "storage-discover")]


def _tamper_digest(path: Path, field: str, *, nested: str | None = None) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    if nested is None:
        value[field] = "sha256:" + "d" * 64
    else:
        value[nested][field] = "sha256:" + "d" * 64
    path.write_bytes(serialize_json(value))
    os.chmod(path, 0o600)
