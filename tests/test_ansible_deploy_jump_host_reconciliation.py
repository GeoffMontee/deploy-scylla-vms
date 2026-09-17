import inspect
import json
import os
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_jump_host_execution import (
    JumpHostRunner,
)
from test_ansible_deploy_jump_host_execution import (
    _call as _execute_jump_host,
)
from test_ansible_deploy_jump_host_execution import (
    _prepared as _jump_host_prepared,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_jump_host_reconciliation as reconciliation_module
import scylla_vms.ansible.deploy_reconciliation as deploy_reconciliation_module
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_jump_host_execution import (
    deploy_jump_host_configure_evidence_path,
    deploy_jump_host_configure_execution_path,
)
from scylla_vms.ansible.deploy_jump_host_reconciliation import (
    ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_SCHEMA_VERSION,
    DeployPostJumpHostConfigureArtifactState,
    DeployPostJumpHostConfigureReconciliationStore,
    deploy_post_jump_host_configure_reconciliation_path,
    reconcile_deploy_jump_host_configure_result,
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

_SECRET = "obviously-fake-post-jump-reconciliation-secret"
_PRIVATE_PATH = "/private/operator/post-jump-reconciliation.json"


def _prepared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    mode: str = "changed",
):
    prepared, executables, toolchain = _jump_host_prepared(tmp_path, monkeypatch)
    runner = JumpHostRunner(mode=mode)
    _execute_jump_host(prepared, runner, executables, toolchain)
    return prepared, runner


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_jump_host_configure_result(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployPostJumpHostConfigureReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


@pytest.mark.parametrize(("mode", "changed"), (("changed", 1), ("noop", 0)))
def test_changed_and_no_change_success_advance_only_immediate_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    changed: int,
) -> None:
    assert tuple(
        inspect.signature(reconcile_deploy_jump_host_configure_result).parameters
    ) == ("state_root", "cluster_name", "operation_id", "lock")
    prepared, runner = _prepared(tmp_path, monkeypatch, mode=mode)
    assert runner.specs is not None
    process_count = len(runner.specs)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    immutable_paths = (
        journal_path,
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-post-reboot-reconciliation.json",
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-jump-host-configure-authorization.json",
        deploy_jump_host_configure_execution_path(prepared.paths, OPERATION_ID),
        deploy_jump_host_configure_evidence_path(prepared.paths, OPERATION_ID),
    )
    immutable = tuple(path.read_bytes() for path in immutable_paths)
    show_before = _run_show(prepared.paths)

    report = _call(prepared)
    stored = _record(prepared)

    assert (
        report.schema_version
        == ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    assert (
        stored.record.schema_version
        == ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_SCHEMA_VERSION
    )
    assert report.artifact_state is DeployPostJumpHostConfigureArtifactState.CREATED
    assert report.jump_target_count == 1
    assert report.changed_count == report.reload_count == changed
    assert report.no_change_count == 1 - changed
    assert report.validated_count == 1
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert len(runner.specs) == process_count
    assert tuple(path.read_bytes() for path in immutable_paths) == immutable
    assert _run_show(prepared.paths) == show_before

    jump = tuple(
        step
        for step in stored.record.steps
        if step.mapping_sequence == 4 and step.playbook == "jump-host-configure"
    )
    assert len(jump) == 1
    assert (
        jump[0].status is DeployBaseOsReconciledStepStatus.SUCCEEDED
        and jump[0].evidence_state
        is DeployBaseOsReconciledEvidenceState.JUMP_HOST_CONFIGURE_BOUND
        and jump[0].evidence_digest is not None
        and not jump[0].blockers
    )
    next_steps = tuple(
        step
        for step in stored.record.steps
        if step.status
        in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
    )
    assert len(next_steps) == 1
    assert next_steps[0].mapping_sequence == 5
    assert next_steps[0].playbook == "connectivity-check"
    assert next_steps[0].condition == "final-routes"
    assert next_steps[0].status is DeployBaseOsReconciledStepStatus.ELIGIBLE
    assert not next_steps[0].blockers
    assert tuple(
        (
            item.playbook,
            item.target_role,
            item.classification.value,
            item.status.value,
            item.target_count,
        )
        for item in report.next_steps
    ) == (("connectivity-check", "all", "read-only", "eligible", 4),)
    assert all(
        step.status
        not in {
            DeployBaseOsReconciledStepStatus.SUCCEEDED,
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
        for step in stored.record.steps
        if step.mapping_sequence > 5
    )
    final = next(
        step
        for step in stored.record.steps
        if step.mapping_sequence
        == len(reconciliation_module.OPERATION_PLAYBOOKS["deploy"])
    )
    assert final.playbook == "evidence-collect"
    assert final.status is DeployBaseOsReconciledStepStatus.NOT_PERFORMED


def test_exact_reentry_is_zero_write_and_zero_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch)
    first = _call(prepared)
    path = deploy_post_jump_host_configure_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    before = path.stat()
    assert runner.specs is not None
    process_count = len(runner.specs)

    second = _call(prepared)

    assert first.reconciliation_artifact_digest == second.reconciliation_artifact_digest
    assert second.artifact_state is DeployPostJumpHostConfigureArtifactState.REUSED
    assert path.stat().st_ino == before.st_ino
    assert path.stat().st_mtime_ns == before.st_mtime_ns
    assert len(runner.specs) == process_count


def test_non_jump_base_os_gate_is_derived_from_unaffected_current_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = reconciliation_module._load_context(
            prepared.paths, OPERATION_ID, lock=lock
        )
    step = next(
        item
        for item in context.post_reconciliation.record.steps
        if item.mapping_sequence == 6
        and item.playbook == "base-os"
        and item.condition == "non-jump-managed-hosts"
    )

    assert reconciliation_module._next_gate_ready(step, context)
    assert not set(step.target_ids) & {entry.stable_id for entry in context.entries}


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("validation_performed", False),
        ("validation_passed", False),
        ("reload_performed", False),
        ("reload_passed", False),
        ("restored", True),
        ("restoration_status", "not-proven"),
        ("route_digest", "0" * 64),
        ("config_digest", "0" * 64),
        ("policy_digest", "0" * 64),
    ),
)
def test_validation_reload_restore_policy_route_and_config_ambiguity_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    path = deploy_jump_host_configure_evidence_path(prepared.paths, OPERATION_ID)
    document = json.loads(path.read_text(encoding="utf-8"))
    cast(list[dict[str, object]], document["entries"])[0][field] = value
    path.write_bytes(serialize_json(document))
    os.chmod(path, 0o600)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not deploy_post_jump_host_configure_reconciliation_path(
        prepared.paths, OPERATION_ID
    ).exists()


@pytest.mark.parametrize("tamper", ("missing", "extra", "duplicate", "wrong-target"))
def test_missing_extra_duplicate_and_wrong_target_evidence_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    path = deploy_jump_host_configure_evidence_path(prepared.paths, OPERATION_ID)
    document = json.loads(path.read_text(encoding="utf-8"))
    entries = cast(list[dict[str, object]], document["entries"])
    if tamper == "missing":
        path.unlink()
    elif tamper in {"extra", "duplicate"}:
        entries.append(dict(entries[0]))
        document["generation"] = 2
        path.write_bytes(serialize_json(document))
    else:
        entries[0]["logical_id"] = "wrong-jump-host"
        path.write_bytes(serialize_json(document))
    if path.exists():
        os.chmod(path, 0o600)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)


@pytest.mark.parametrize(
    "mode",
    ("validation-failed", "reload-failed", "timeout", "interrupted", "unreachable"),
)
def test_failed_or_uncertain_execution_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    prepared, executables, toolchain = _jump_host_prepared(tmp_path, monkeypatch)
    runner = JumpHostRunner(mode=mode)
    with pytest.raises((AnsibleError, KeyboardInterrupt)):
        _execute_jump_host(prepared, runner, executables, toolchain)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)


@pytest.mark.parametrize("state", ("prepared", "started", "failed"))
def test_nonterminal_and_failed_execution_state_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    path = deploy_jump_host_configure_execution_path(prepared.paths, OPERATION_ID)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["state"] = state
    cast(list[dict[str, object]], document["attempts"])[0]["state"] = state
    path.write_bytes(serialize_json(document))
    os.chmod(path, 0o600)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)


@pytest.mark.parametrize(
    "relative_path",
    (
        "ansible/trust.json",
        "ansible/inventory.yml",
        f"terraform/plans/{OPERATION_ID}.terraform-apply-readiness.json",
        f"operations/{OPERATION_ID}.ansible-deploy-post-reboot-reconciliation.json",
        f"operations/{OPERATION_ID}.ansible-deploy-jump-host-configure-authorization.json",
        f"operations/{OPERATION_ID}.json",
    ),
)
def test_full_chain_drift_refused_before_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    path = prepared.paths.cluster_root / relative_path
    document = json.loads(path.read_text(encoding="utf-8"))
    document["unexpected"] = _SECRET
    path.write_bytes(serialize_json(document))
    os.chmod(path, 0o600)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)


@pytest.mark.parametrize("drift", ("source", "catalog"))
def test_source_and_catalog_drift_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
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


def test_lock_path_permissions_symlink_and_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    with pytest.raises(StateLockError):
        reconcile_deploy_jump_host_configure_result(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=cast(ClusterLock, object()),
        )
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        reconcile_deploy_jump_host_configure_result(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
        )

    output = deploy_post_jump_host_configure_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    output.symlink_to(tmp_path / "outside.json")
    with pytest.raises(UnsafePathError):
        _call(prepared)
    output.unlink()

    evidence = deploy_jump_host_configure_evidence_path(prepared.paths, OPERATION_ID)
    evidence.chmod(0o644)
    with pytest.raises(UnsafePathError):
        _call(prepared)
    evidence.chmod(0o600)

    def fail_write(*_args: object, **_kwargs: object) -> object:
        raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(
        reconciliation_module.DeployPostJumpHostConfigureReconciliationStore,
        "write_locked",
        fail_write,
    )
    with pytest.raises(StatePersistenceError) as raised:
        _call(prepared)
    assert _SECRET not in str(raised.value)
    assert _PRIVATE_PATH not in str(raised.value)
    assert not output.exists()


def test_report_and_record_are_redacted_and_owner_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    report = _call(prepared)
    path = deploy_post_jump_host_configure_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    serialized = path.read_text(encoding="utf-8") + json.dumps(
        report.to_object(), sort_keys=True
    )

    assert path.stat().st_mode & 0o777 == 0o600
    assert _SECRET not in serialized
    assert _PRIVATE_PATH not in serialized
    for forbidden in (
        "10.0.",
        "provider_id",
        "private_address",
        "public_address",
        "allowed_routes",
        "host_key",
        "fingerprint",
        'config":',
        'command":',
        'variables":',
        'environment":',
        "raw_output",
    ):
        assert forbidden not in serialized

    document = json.loads(path.read_text(encoding="utf-8"))
    document["unexpected"] = _SECRET
    path.write_bytes(serialize_json(document))
    os.chmod(path, 0o600)
    code, stdout, stderr = _run_show(prepared.paths)
    assert code == 10
    assert not stdout
    assert _SECRET not in stderr
