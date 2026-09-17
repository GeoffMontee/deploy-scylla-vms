import inspect
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_scylla_install_execution import (
    ScyllaInstallRunner,
    _prepared,
)
from test_ansible_deploy_scylla_install_execution import (
    _call as _execute_install,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_scylla_install_execution import (
    DeployScyllaInstallEvidenceStore,
    DeployScyllaInstallExecutionState,
    DeployScyllaInstallExecutionStore,
    deploy_scylla_install_evidence_path,
    deploy_scylla_install_execution_path,
)
from scylla_vms.ansible.deploy_scylla_install_reconciliation import (
    ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_SCHEMA_VERSION,
    DeployPostScyllaInstallArtifactState,
    DeployPostScyllaInstallReconciliationStore,
    _build_reconciled_steps,
    deploy_post_scylla_install_reconciliation_id_from_filename,
    deploy_post_scylla_install_reconciliation_path,
    reconcile_deploy_scylla_install,
)
from scylla_vms.ansible.deploy_storage_postcheck import (
    DeployPostStoragePostcheckReconciliationStore,
)
from scylla_vms.ansible.scylla_install import SCYLLA_SIGNING_KEY_FINGERPRINT
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock

_PRIVATE_PATH = "/private/operator/post-scylla-install.json"
_SECRET = "obviously-fake-post-scylla-install-secret"


def _complete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str):
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = ScyllaInstallRunner(mode=mode)
    _execute_install(prepared, runner, executables, toolchain)
    return prepared, runner


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_scylla_install(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployPostScyllaInstallReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


@pytest.mark.parametrize(
    ("mode", "changed_count", "no_change_count"),
    (("installed", 1, 0), ("no-change", 0, 1)),
)
def test_strict_success_no_change_idempotence_redaction_and_next_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    changed_count: int,
    no_change_count: int,
) -> None:
    assert tuple(inspect.signature(reconcile_deploy_scylla_install).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    prepared, runner = _complete(tmp_path, monkeypatch, mode)
    assert runner.specs is not None
    process_count = len(runner.specs)
    path = deploy_post_scylla_install_reconciliation_path(prepared.paths, OPERATION_ID)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    prior_paths = tuple(
        item
        for item in prepared.paths.operations.iterdir()
        if item != path and item.is_file()
    )
    prior_bytes = {item: item.read_bytes() for item in prior_paths}
    show_before = _run_show(prepared.paths)

    report = _call(prepared)
    first_bytes = path.read_bytes()
    reused = _call(prepared)
    stored = _record(prepared)
    show_after = _run_show(prepared.paths)

    assert report.schema_version == (
        ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    assert (
        stored.record.schema_version
        == ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_SCHEMA_VERSION
    )
    assert report.artifact_state is DeployPostScyllaInstallArtifactState.CREATED
    assert reused.artifact_state is DeployPostScyllaInstallArtifactState.REUSED
    assert path.read_bytes() == first_bytes
    assert path.stat().st_mode & 0o777 == 0o600
    assert len(runner.specs) == process_count
    assert show_after == show_before
    assert journal_path.read_bytes() == prior_bytes[journal_path]
    assert {item: item.read_bytes() for item in prior_paths} == prior_bytes
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert report.target_count == report.installed_count == 1
    assert report.changed_count == changed_count
    assert report.no_change_count == no_change_count
    assert report.service_safe_count == 1
    assert report.prohibited_action_count == 0
    assert report.next_playbook == "scylla-configure"
    assert report.next_target_count == 1

    install_steps = tuple(
        step
        for step in stored.record.steps
        if step.mapping_sequence == 11 and step.condition_state.value == "active"
    )
    configure_steps = tuple(
        step
        for step in stored.record.steps
        if step.mapping_sequence == 12 and step.condition_state.value == "active"
    )
    assert install_steps
    assert all(
        step.playbook == "scylla-install"
        and step.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
        and step.evidence_state
        is DeployBaseOsReconciledEvidenceState.SCYLLA_INSTALL_BOUND
        and step.evidence_digest is not None
        and not step.blockers
        for step in install_steps
    )
    assert configure_steps
    assert all(
        step.playbook == "scylla-configure"
        and step.status
        is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        and step.evidence_state
        is DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED
        and set(step.blockers)
        == {
            "deploy-authorization-not-collected",
            "mutating-deploy-execution-unavailable",
            "public-deploy-workflow-unavailable",
        }
        for step in configure_steps
    )
    advanced = tuple(
        step
        for step in stored.record.steps
        if step.mapping_sequence > 11
        and step.status
        in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
    )
    assert {step.playbook for step in advanced} == {"scylla-configure"}
    assert not any(
        step.playbook
        in {
            "scylla-bootstrap",
            "scylla-health",
            "manager-agent",
            "monitoring-agent",
        }
        and step.status
        in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
        for step in stored.record.steps
    )

    public = first_bytes.decode() + json.dumps(report.to_object(), sort_keys=True)
    for protected in (
        _PRIVATE_PATH,
        _SECRET,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "downloads.scylladb.com",
        SCYLLA_SIGNING_KEY_FINGERPRINT,
        "BEGIN PGP",
        "ansible-playbook",
        "--limit",
    ):
        assert protected not in public
    report_object = report.to_object()
    assert "stable_id" not in json.dumps(report_object)
    assert deploy_post_scylla_install_reconciliation_id_from_filename(path.name) == (
        OPERATION_ID
    )
    assert (
        deploy_post_scylla_install_reconciliation_id_from_filename(
            f"uppercase-{path.name}"
        )
        is None
    )


def test_refuses_missing_prepared_started_failed_and_uncertain_prefixes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "missing"
    missing.mkdir()
    prepared, executables, toolchain = _prepared(missing, monkeypatch)
    with pytest.raises(StateConflictError, match="complete execution"):
        _call(prepared)
    monkeypatch.undo()

    prepared_root = tmp_path / "prepared"
    prepared_root.mkdir()
    prepared, executables, toolchain = _prepared(prepared_root, monkeypatch)
    original = DeployScyllaInstallExecutionStore.write_locked

    def refuse_start(self, record, **kwargs):
        if record.state is DeployScyllaInstallExecutionState.STARTED:
            raise StatePersistenceError("simulated refusal before invocation")
        return original(self, record, **kwargs)

    monkeypatch.setattr(DeployScyllaInstallExecutionStore, "write_locked", refuse_start)
    with pytest.raises(StatePersistenceError, match="before invocation"):
        _execute_install(
            prepared,
            ScyllaInstallRunner(),
            executables,
            toolchain,
        )
    with pytest.raises(StateConflictError, match="complete evidence"):
        _call(prepared)
    monkeypatch.undo()

    started = tmp_path / "started"
    started.mkdir()
    prepared, executables, toolchain = _prepared(started, monkeypatch)

    def refuse_terminal(self, record, **kwargs):
        if (
            record.state is DeployScyllaInstallExecutionState.SUCCEEDED
            and record.all_scopes_completed
        ):
            raise StatePersistenceError("simulated terminal write failure")
        return original(self, record, **kwargs)

    monkeypatch.setattr(
        DeployScyllaInstallExecutionStore, "write_locked", refuse_terminal
    )
    with pytest.raises(StatePersistenceError, match="terminal persistence"):
        _execute_install(
            prepared,
            ScyllaInstallRunner(),
            executables,
            toolchain,
        )
    with pytest.raises(StateConflictError, match="exact terminal success"):
        _call(prepared)
    monkeypatch.undo()

    failed = tmp_path / "failed"
    failed.mkdir()
    prepared, executables, toolchain = _prepared(failed, monkeypatch)
    with pytest.raises(AnsibleError, match="manual recovery"):
        _execute_install(
            prepared,
            ScyllaInstallRunner(mode="malformed"),
            executables,
            toolchain,
        )
    with pytest.raises(StateConflictError, match="complete evidence"):
        _call(prepared)


def test_refuses_package_service_membership_and_prohibited_action_mismatches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _complete(tmp_path, monkeypatch, "installed")
    path = deploy_scylla_install_evidence_path(prepared.paths, OPERATION_ID)
    original = path.read_bytes()

    def set_entry(name: str, value: object) -> Callable[[dict[str, object]], None]:
        def mutate(document: dict[str, object]) -> None:
            entries = cast(list[dict[str, object]], document["entries"])
            entries[0][name] = value

        return mutate

    mutations: tuple[Callable[[dict[str, object]], None], ...] = (
        set_entry("package_version", "2026.1.invalid"),
        set_entry("service_masked", False),
        set_entry("service_inactive", False),
        set_entry("configuration_performed", True),
        set_entry("storage_mutation_performed", True),
        set_entry("tuning_performed", True),
        set_entry("manager_operation_performed", True),
        set_entry("service_started", True),
        lambda document: cast(list[object], document["entries"]).clear(),
        lambda document: cast(list[object], document["entries"]).append(
            cast(list[object], document["entries"])[0]
        ),
        set_entry("stable_id", "extra-scylla"),
    )
    for mutate in mutations:
        document = cast(dict[str, object], json.loads(original))
        mutate(document)
        path.write_text(json.dumps(document) + "\n", encoding="utf-8")
        path.chmod(0o600)
        with pytest.raises((StateConflictError, StatePersistenceError)):
            _call(prepared)
        assert not deploy_post_scylla_install_reconciliation_path(
            prepared.paths, OPERATION_ID
        ).exists()
    path.write_bytes(original)
    path.chmod(0o600)


def test_refuses_execution_evidence_and_current_state_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _complete(tmp_path, monkeypatch, "installed")
    execution_path = deploy_scylla_install_execution_path(prepared.paths, OPERATION_ID)
    original_execution = execution_path.read_bytes()
    document = cast(dict[str, object], json.loads(original_execution))
    binding = cast(dict[str, object], document["binding"])
    binding["catalog_digest"] = "0" * 64
    execution_path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    execution_path.chmod(0o600)
    with pytest.raises(StatePersistenceError):
        _call(prepared)
    execution_path.write_bytes(original_execution)
    execution_path.chmod(0o600)

    trust_path = prepared.paths.ansible_trust
    original_trust = trust_path.read_bytes()
    trust = cast(dict[str, object], json.loads(original_trust))
    trust["generation"] = cast(int, trust["generation"]) + 1
    trust_path.write_text(json.dumps(trust) + "\n", encoding="utf-8")
    trust_path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    trust_path.write_bytes(original_trust)
    trust_path.chmod(0o600)


def test_refuses_later_gate_leapfrog(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _complete(tmp_path, monkeypatch, "no-change")
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        prior = DeployPostStoragePostcheckReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence = DeployScyllaInstallEvidenceStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    steps = list(prior.record.steps)
    health_index = next(
        index
        for index, step in enumerate(steps)
        if step.mapping_sequence > 12
        and step.playbook == "scylla-health"
        and step.condition_state.value == "active"
    )
    health = steps[health_index]
    steps[health_index] = replace(
        health,
        status=DeployBaseOsReconciledStepStatus.ELIGIBLE,
        evidence_state=DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED,
        evidence_digest="sha256:" + ("a" * 64),
        blockers=(),
    )
    object.__setattr__(prior.record, "steps", tuple(steps))
    configure_source_digest = next(
        step.source_digest for step in steps if step.mapping_sequence == 12
    )
    with pytest.raises(StateConflictError, match="later gate leapfrog"):
        _build_reconciled_steps(
            prior,
            evidence,
            configure_source_digest=configure_source_digest,
        )


def test_wrong_lock_noncanonical_path_and_show_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _complete(tmp_path, monkeypatch, "no-change")
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        reconcile_deploy_scylla_install(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
        )

    _call(prepared)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0
    path = deploy_post_scylla_install_reconciliation_path(prepared.paths, OPERATION_ID)
    target = path.with_name(f"{path.name}.target")
    path.rename(target)
    path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _record(prepared)
    path.unlink()
    target.rename(path)
