import inspect
import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from test_ansible_deploy_storage_preflight import (
    StoragePreflightRunner,
)
from test_ansible_deploy_storage_preflight import (
    _execute as _execute_preflight,
)
from test_ansible_deploy_storage_preflight import (
    _prepared as _preflight_prepared,
)
from test_ansible_deploy_storage_preflight import (
    _reconcile as _reconcile_preflight,
)
from test_ansible_deploy_storage_prepare_execution import (
    StoragePrepareRunner,
)
from test_ansible_deploy_storage_prepare_execution import (
    _call as _execute_prepare,
)
from test_ansible_deploy_storage_prepare_execution import (
    _prepared as _prepare_prepared,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_storage_prepare_reconciliation as reconciliation_module
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_storage_preflight import DeployStoragePreflightAction
from scylla_vms.ansible.deploy_storage_prepare_execution import (
    DeployStoragePrepareExecutionState,
    DeployStoragePrepareExecutionStore,
    deploy_storage_prepare_evidence_path,
    deploy_storage_prepare_execution_path,
)
from scylla_vms.ansible.deploy_storage_prepare_reconciliation import (
    ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_SCHEMA_VERSION,
    DeployPostStoragePrepareArtifactState,
    DeployPostStoragePrepareOutcome,
    DeployPostStoragePrepareOutcomeState,
    DeployPostStoragePrepareReconciliationStore,
    deploy_post_storage_prepare_reconciliation_path,
    reconcile_deploy_storage_prepare,
)
from scylla_vms.ansible.storage_preflight import StorageOwnershipStatus
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

_SECRET = "obviously-fake-post-storage-prepare-secret"
_PRIVATE_PATH = "/private/operator/post-storage-prepare.json"


def _prepare_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    disposition: StorageOwnershipStatus,
):
    prepared, _inventory, executables, toolchain = _preflight_prepared(
        tmp_path, monkeypatch, disposition
    )
    preflight_runner = StoragePreflightRunner()
    _execute_preflight(prepared, preflight_runner, executables, toolchain)
    _reconcile_preflight(prepared)
    return prepared, preflight_runner, executables, toolchain


def _fully_prepared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    disposition: StorageOwnershipStatus,
):
    prepared, executables, toolchain = _prepare_prepared(
        tmp_path, monkeypatch, disposition
    )
    runner = StoragePrepareRunner()
    _execute_prepare(prepared, runner, executables, toolchain)
    return prepared, runner, executables, toolchain


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_storage_prepare(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _stored(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployPostStoragePrepareReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


def test_mixed_prepare_wipe_owned_and_blocked_scope_selects_exact_postcheck() -> None:
    outcomes = []
    dispositions = (
        ("scylla-a", StorageOwnershipStatus.CLEAN_NEW),
        ("scylla-b", StorageOwnershipStatus.WIPE_REVIEW_REQUIRED),
        ("scylla-c", StorageOwnershipStatus.OWNED_NOOP),
        ("scylla-d", StorageOwnershipStatus.BLOCKED),
    )
    for index, (stable_id, disposition) in enumerate(dispositions):
        prepared = disposition in {
            StorageOwnershipStatus.CLEAN_NEW,
            StorageOwnershipStatus.WIPE_REVIEW_REQUIRED,
        }
        owned = disposition is StorageOwnershipStatus.OWNED_NOOP
        action = (
            DeployStoragePreflightAction.PREPARE_REQUIRED
            if prepared
            else DeployStoragePreflightAction.OWNED_NOOP
            if owned
            else DeployStoragePreflightAction.BLOCKED
        )
        state = (
            DeployPostStoragePrepareOutcomeState.PREPARE_SUCCEEDED
            if prepared
            else DeployPostStoragePrepareOutcomeState.OWNED_NOOP_CURRENT
            if owned
            else DeployPostStoragePrepareOutcomeState.BLOCKED
        )
        optional = "sha256:" + f"{index + 1:x}" * 64 if prepared else None
        values = {
            "stable_id": stable_id,
            "action": action,
            "disposition": disposition,
            "state": state,
            "current": prepared or owned,
            "mutation_performed": prepared,
            "device_count": 0 if disposition is StorageOwnershipStatus.BLOCKED else 1,
            "device_set_digest": "sha256:" + "a" * 64,
            "preparation_intent_digest": "sha256:" + "b" * 64,
            "wipe_required": (
                disposition is StorageOwnershipStatus.WIPE_REVIEW_REQUIRED
            ),
            "wipe_applied": (
                disposition is StorageOwnershipStatus.WIPE_REVIEW_REQUIRED
            ),
            "authorization_scope_digest": optional,
            "result_digest": optional,
            "execution_evidence_digest": optional,
            "filesystem_uuid_digest": optional,
            "marker_digest": optional,
            "provenance_digest": optional,
            "source_evidence_digest": "sha256:" + "c" * 64,
            "outcome_digest": "",
        }
        values["outcome_digest"] = reconciliation_module._outcome_digest_from_values(
            values
        )
        outcomes.append(DeployPostStoragePrepareOutcome(**values))  # type: ignore[arg-type]

    scopes = reconciliation_module._postcheck_scopes(tuple(outcomes))
    assert tuple(item.stable_id for item in scopes) == (
        "scylla-a",
        "scylla-b",
        "scylla-c",
    )
    assert tuple(item.mutation_performed for item in scopes) == (True, True, False)
    assert tuple(item.source_state for item in scopes) == (
        DeployPostStoragePrepareOutcomeState.PREPARE_SUCCEEDED,
        DeployPostStoragePrepareOutcomeState.PREPARE_SUCCEEDED,
        DeployPostStoragePrepareOutcomeState.OWNED_NOOP_CURRENT,
    )


@pytest.mark.parametrize(
    ("disposition", "prepared_count", "owned_count", "blocked_count", "wipe_count"),
    (
        (StorageOwnershipStatus.CLEAN_NEW, 1, 0, 0, 0),
        (StorageOwnershipStatus.WIPE_REVIEW_REQUIRED, 1, 0, 0, 1),
        (StorageOwnershipStatus.OWNED_NOOP, 0, 1, 0, 0),
        (StorageOwnershipStatus.BLOCKED, 0, 0, 1, 0),
    ),
)
def test_exact_actions_advance_only_current_storage_to_postcheck(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    disposition: StorageOwnershipStatus,
    prepared_count: int,
    owned_count: int,
    blocked_count: int,
    wipe_count: int,
) -> None:
    assert tuple(inspect.signature(reconcile_deploy_storage_prepare).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    if prepared_count:
        prepared, runner, _executables, _toolchain = _fully_prepared(
            tmp_path, monkeypatch, disposition
        )
        assert runner.specs is not None
        process_count = len(runner.specs)
    else:
        prepared, runner, _executables, _toolchain = _prepare_only(
            tmp_path, monkeypatch, disposition
        )
        assert runner.specs is not None
        process_count = len(runner.specs)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_bytes = journal_path.read_bytes()
    show_before = _run_show(prepared.paths)

    report = _call(prepared)
    stored = _stored(prepared)
    path = deploy_post_storage_prepare_reconciliation_path(prepared.paths, OPERATION_ID)
    first_bytes = path.read_bytes()
    first_stat = path.stat()
    reused = _call(prepared)

    assert (
        report.schema_version
        == ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    assert (
        stored.record.schema_version
        == ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_SCHEMA_VERSION
    )
    assert report.artifact_state is DeployPostStoragePrepareArtifactState.CREATED
    assert reused.artifact_state is DeployPostStoragePrepareArtifactState.REUSED
    assert (
        report.prepare_succeeded_count,
        report.owned_noop_current_count,
        report.blocked_count,
        report.wipe_applied_count,
    ) == (prepared_count, owned_count, blocked_count, wipe_count)
    assert report.postcheck_target_count == prepared_count + owned_count
    assert report.general_authorization_consumed is bool(prepared_count)
    assert report.wipe_authorization_consumed_count == wipe_count
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert report.next_execution_state == "not-started"
    assert journal_path.read_bytes() == journal_bytes
    assert _run_show(prepared.paths) == show_before
    assert len(runner.specs) == process_count
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.read_bytes() == first_bytes
    assert path.stat().st_ino == first_stat.st_ino
    assert path.stat().st_mtime_ns == first_stat.st_mtime_ns

    outcome = stored.record.outcomes[0]
    prepare_step = next(
        step
        for step in stored.record.steps
        if step.mapping_sequence == 9 and step.target_ids == (outcome.stable_id,)
    )
    postcheck_step = next(
        step
        for step in stored.record.steps
        if step.mapping_sequence == 10 and step.target_ids == (outcome.stable_id,)
    )
    if prepared_count:
        assert outcome.state is DeployPostStoragePrepareOutcomeState.PREPARE_SUCCEEDED
        assert outcome.mutation_performed
        assert outcome.current
        assert outcome.wipe_applied is bool(wipe_count)
        assert prepare_step.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
        assert (
            prepare_step.evidence_state
            is DeployBaseOsReconciledEvidenceState.STORAGE_PREPARE_BOUND
        )
    elif owned_count:
        assert outcome.state is DeployPostStoragePrepareOutcomeState.OWNED_NOOP_CURRENT
        assert not outcome.mutation_performed
        assert outcome.current
        assert prepare_step.status is DeployBaseOsReconciledStepStatus.NOT_PERFORMED
        assert (
            prepare_step.evidence_state
            is DeployBaseOsReconciledEvidenceState.NOT_REQUIRED
        )
    else:
        assert outcome.state is DeployPostStoragePrepareOutcomeState.BLOCKED
        assert not outcome.mutation_performed
        assert not outcome.current
        assert prepare_step.status is DeployBaseOsReconciledStepStatus.BLOCKED

    if outcome.current:
        assert postcheck_step.status is DeployBaseOsReconciledStepStatus.ELIGIBLE
        assert not postcheck_step.blockers
        scope = stored.record.postcheck_scopes[0]
        assert scope.stable_id == outcome.stable_id
        assert scope.mutation_performed == outcome.mutation_performed
        assert scope.device_set_digest == outcome.device_set_digest
        assert scope.preparation_intent_digest == outcome.preparation_intent_digest
        assert scope.source_evidence_digest == outcome.source_evidence_digest
        assert scope.preparation_evidence_digest == (
            outcome.execution_evidence_digest or outcome.source_evidence_digest
        )
    else:
        assert postcheck_step.status not in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
    assert not any(
        step.mapping_sequence > 10
        and step.status
        in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
        for step in stored.record.steps
    )


def test_partial_started_failed_and_missing_execution_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner, _executables, _toolchain = _prepare_only(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    with pytest.raises(StateConflictError, match="complete authorization"):
        _call(prepared)

    monkeypatch.undo()
    failed_root = tmp_path / "failed"
    failed_root.mkdir(mode=0o700)
    failed, _executables, toolchain = _prepare_prepared(
        failed_root, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    runner = StoragePrepareRunner(mode="failed")
    with pytest.raises(AnsibleError, match="manual recovery required"):
        _execute_prepare(failed, runner, _executables, toolchain)
    execution = DeployStoragePrepareExecutionStore(failed.paths, OPERATION_ID).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    assert execution.record.state is DeployStoragePrepareExecutionState.FAILED
    with pytest.raises(StateConflictError, match="terminal success"):
        _call(failed)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("state", "started"),
        ("general_authorization_consumed", False),
        ("wipe_authorization_consumed_count", 1),
        ("invocation_count", 2),
    ),
)
def test_proof_consumption_partial_and_extra_scope_mismatches_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    prepared, _runner, _executables, _toolchain = _fully_prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    path = deploy_storage_prepare_execution_path(prepared.paths, OPERATION_ID)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload[field] = value
    path.write_bytes(serialize_json(payload))
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not deploy_post_storage_prepare_reconciliation_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_evidence_and_current_chain_drift_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner, _executables, _toolchain = _fully_prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.WIPE_REVIEW_REQUIRED
    )
    evidence_path = deploy_storage_prepare_evidence_path(prepared.paths, OPERATION_ID)
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["entries"][0]["device_set_digest"] = "sha256:" + "e" * 64
    evidence_path.write_bytes(serialize_json(evidence))
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)

    monkeypatch.undo()
    drift_root = tmp_path / "drift"
    drift_root.mkdir(mode=0o700)
    drifted, _runner, _executables, _toolchain = _fully_prepared(
        drift_root, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    journal_path = drifted.paths.operations / f"{OPERATION_ID}.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    journal["request_digest"] = "sha256:" + "f" * 64
    journal_path.write_bytes(serialize_json(journal))
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(drifted)


def test_path_permission_persistence_redaction_and_process_free_behavior(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner, _executables, _toolchain = _fully_prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    assert runner.specs is not None
    process_count = len(runner.specs)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        reconcile_deploy_storage_prepare(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
        )

    forged = replace(prepared.paths, operations=tmp_path / "outside")
    with pytest.raises(StatePersistenceError, match="not canonical"):
        DeployPostStoragePrepareReconciliationStore(forged, OPERATION_ID)

    path = deploy_post_storage_prepare_reconciliation_path(prepared.paths, OPERATION_ID)
    assert path == prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-post-storage-prepare-reconciliation.json"
    )
    outside = tmp_path / "outside-reconciliation.json"
    outside.write_text("{}\n", encoding="utf-8")
    outside.chmod(0o600)
    path.symlink_to(outside)
    with pytest.raises(UnsafePathError):
        _call(prepared)
    path.unlink()
    outside.unlink()

    execution_path = deploy_storage_prepare_execution_path(prepared.paths, OPERATION_ID)
    execution_path.chmod(0o644)
    with pytest.raises(UnsafePathError):
        _call(prepared)
    execution_path.chmod(0o600)

    def fail_subprocess(*args, **kwargs):
        del args, kwargs
        raise AssertionError("reconciliation must not invoke a process")

    monkeypatch.setattr(subprocess, "run", fail_subprocess)
    report = _call(prepared)
    assert len(runner.specs) == process_count
    persisted = path.read_text(encoding="utf-8")
    projected = json.dumps(report.to_object(), sort_keys=True)
    for protected in (
        "/dev/",
        "ocid1.",
        "10.0.",
        "203.0.113.",
        "ssh-ed25519",
        "ProxyJump",
        "ansible-playbook",
        "--limit",
        _SECRET,
        _PRIVATE_PATH,
    ):
        assert protected not in persisted
        assert protected not in projected
    assert "deploy_scylla_vms_" not in projected
    for protected_key in (
        "stable_id",
        "outcomes",
        "postcheck_scopes",
        "command_digest",
        "variables_digest",
    ):
        assert f'"{protected_key}":' not in projected

    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["record_digest"] = "sha256:" + "d" * 64
    path.write_bytes(serialize_json(tampered))
    show_result, show_stdout, show_stderr = _run_show(prepared.paths)
    assert show_result != 0
    assert show_stdout == ""
    assert "record digest conflicts" in show_stderr

    monkeypatch.undo()
    failure_root = tmp_path / "write-failure"
    failure_root.mkdir(mode=0o700)
    failed, _runner, _executables, _toolchain = _fully_prepared(
        failure_root, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )

    def fail_write(self, record, *, lock):
        del self, record, lock
        raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(
        DeployPostStoragePrepareReconciliationStore,
        "write_locked",
        fail_write,
    )
    journal_path = failed.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()
    with pytest.raises(StatePersistenceError, match="persistence failed") as caught:
        _call(failed)
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    assert journal_path.read_bytes() == journal_before
    assert not deploy_post_storage_prepare_reconciliation_path(
        failed.paths, OPERATION_ID
    ).exists()
