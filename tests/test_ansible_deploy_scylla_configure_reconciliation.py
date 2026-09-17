import inspect
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_scylla_configure_execution import (
    ScyllaConfigureRunner,
)
from test_ansible_deploy_scylla_configure_execution import (
    _call as _execute_configure,
)
from test_ansible_deploy_scylla_configure_execution import (
    _prepared as _prepared_configure,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_scylla_configure_execution import (
    DeployScyllaConfigureEvidenceStore,
    deploy_scylla_configure_evidence_path,
)
from scylla_vms.ansible.deploy_scylla_configure_reconciliation import (
    ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_SCHEMA_VERSION,
    DeployPostScyllaConfigureArtifactState,
    DeployPostScyllaConfigureReconciliationStore,
    _build_reconciled_steps,
    _validate_original_mapping,
    deploy_post_scylla_configure_reconciliation_id_from_filename,
    deploy_post_scylla_configure_reconciliation_path,
    reconcile_deploy_scylla_configure,
)
from scylla_vms.ansible.deploy_scylla_install_reconciliation import (
    DeployPostScyllaInstallReconciliationStore,
)
from scylla_vms.ansible.registry import OPERATION_PLAYBOOKS
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock

_PRIVATE_PATH = "/private/operator/post-scylla-configure.json"
_SECRET = "obviously-fake-post-scylla-configure-secret"


def _complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str = "noop",
):
    prepared, executables, toolchain = _prepared_configure(tmp_path, monkeypatch)
    runner = ScyllaConfigureRunner(mode=mode)
    _execute_configure(prepared, runner, executables, toolchain)
    return prepared, runner


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_scylla_configure(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployPostScyllaConfigureReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


@pytest.mark.parametrize(
    ("mode", "changed_count", "no_change_count"),
    (("changed", 1, 0), ("noop", 0, 1)),
)
def test_exact_success_immutable_mapping_bootstrap_block_and_idempotence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    changed_count: int,
    no_change_count: int,
) -> None:
    assert tuple(inspect.signature(reconcile_deploy_scylla_configure).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    prepared, runner = _complete(tmp_path, monkeypatch, mode)
    assert runner.specs is not None
    process_count = len(runner.specs)
    path = deploy_post_scylla_configure_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    prior_paths = tuple(
        item for item in prepared.paths.operations.iterdir() if item.is_file()
    )
    prior_bytes = {item: item.read_bytes() for item in prior_paths}
    show_before = _run_show(prepared.paths)

    report = _call(prepared)
    first_bytes = path.read_bytes()
    reused = _call(prepared)
    stored = _record(prepared)
    show_after = _run_show(prepared.paths)

    assert report.schema_version == (
        ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    assert (
        stored.record.schema_version
        == ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_SCHEMA_VERSION
    )
    assert report.artifact_state is DeployPostScyllaConfigureArtifactState.CREATED
    assert reused.artifact_state is DeployPostScyllaConfigureArtifactState.REUSED
    assert path.read_bytes() == first_bytes
    assert path.stat().st_mode & 0o777 == 0o600
    assert len(runner.specs) == process_count
    assert show_after == show_before
    assert journal_path.read_bytes() == prior_bytes[journal_path]
    assert {item: item.read_bytes() for item in prior_paths} == prior_bytes
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert report.target_count == report.configured_count == 1
    assert report.changed_count == changed_count
    assert report.no_change_count == no_change_count
    assert report.configuration_file_count == 2
    assert report.service_safe_count == 1
    assert report.prohibited_action_count == 0

    original_mapping = OPERATION_PLAYBOOKS["deploy"]
    assert len(original_mapping) == 21
    assert original_mapping[11].playbook == "scylla-configure"
    assert original_mapping[12].playbook == "scylla-health"
    assert all(step.playbook != "scylla-bootstrap" for step in original_mapping)
    assert stored.record.original_mapping_count == 21
    assert not stored.record.bootstrap_in_original_mapping
    assert report.next_procedure_gate == "scylla-bootstrap"
    assert report.bootstrap_gate_state == "blocked"
    assert report.bootstrap_blockers == (
        "bootstrap-plan-required",
        "bootstrap-step-unmodeled",
    )
    assert {
        report.bootstrap_evidence_state,
        report.empty_cluster_evidence_state,
        report.topology_evidence_state,
        report.seed_evidence_state,
        report.health_evidence_state,
        report.capacity_evidence_state,
    } == {"not-performed"}
    assert report.next_authorization_state == "unavailable"
    assert report.next_execution_state == "unavailable"

    configure_steps = tuple(
        step
        for step in stored.record.steps
        if step.mapping_sequence == 12 and step.condition_state.value == "active"
    )
    assert configure_steps
    assert all(
        step.playbook == "scylla-configure"
        and step.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
        and step.evidence_state
        is DeployBaseOsReconciledEvidenceState.SCYLLA_CONFIGURE_BOUND
        and step.evidence_digest is not None
        and not step.blockers
        for step in configure_steps
    )
    assert not any(
        step.mapping_sequence > 12
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
        "/var/lib/scylla",
        "/etc/scylla",
        "SimpleSeedProvider",
        "ansible-playbook",
        "--limit",
        '"seed_stable_ids"',
        '"config"',
    ):
        assert protected not in public
    report_object = report.to_object()
    assert "stable_id" not in json.dumps(report_object)
    assert (
        deploy_post_scylla_configure_reconciliation_id_from_filename(path.name)
        == OPERATION_ID
    )
    assert (
        deploy_post_scylla_configure_reconciliation_id_from_filename(
            f"uppercase-{path.name}"
        )
        is None
    )


def test_refuses_missing_failed_and_uncertain_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "missing"
    missing.mkdir()
    prepared, _executables, _toolchain = _prepared_configure(missing, monkeypatch)
    with pytest.raises(StateConflictError, match="complete execution"):
        _call(prepared)
    monkeypatch.undo()

    failed = tmp_path / "failed"
    failed.mkdir()
    prepared, executables, toolchain = _prepared_configure(failed, monkeypatch)
    with pytest.raises(AnsibleError, match="manual recovery"):
        _execute_configure(
            prepared,
            ScyllaConfigureRunner(mode="malformed"),
            executables,
            toolchain,
        )
    with pytest.raises(StateConflictError, match="complete evidence"):
        _call(prepared)


def test_refuses_config_file_topology_seed_version_directory_and_safety_mismatches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _complete(tmp_path, monkeypatch)
    path = deploy_scylla_configure_evidence_path(prepared.paths, OPERATION_ID)
    original = path.read_bytes()

    def set_entry(name: str, value: object) -> Callable[[dict[str, object]], None]:
        def mutate(document: dict[str, object]) -> None:
            entries = cast(list[dict[str, object]], document["entries"])
            entries[0][name] = value

        return mutate

    mutations: tuple[Callable[[dict[str, object]], None], ...] = (
        set_entry("configuration_file_count", 3),
        set_entry("configuration_file_set_digest", "sha256:" + "1" * 64),
        set_entry("files_root_owned", False),
        set_entry("files_mode_0644", False),
        set_entry("topology_digest", "sha256:" + "2" * 64),
        set_entry("seed_policy_digest", "sha256:" + "3" * 64),
        set_entry("package_version_digest", "sha256:" + "4" * 64),
        set_entry("directory_policy_digest", "sha256:" + "5" * 64),
        set_entry("rendered_config_digest", "sha256:" + "6" * 64),
        set_entry("service_masked", False),
        set_entry("service_inactive", False),
        set_entry("package_install_performed", True),
        set_entry("storage_mutation_performed", True),
        set_entry("tuning_performed", True),
        set_entry("firewall_operation_performed", True),
        set_entry("ssh_operation_performed", True),
        set_entry("manager_operation_performed", True),
        set_entry("service_started", True),
        set_entry("bootstrap_performed", True),
        lambda document: cast(list[object], document["entries"]).clear(),
        lambda document: cast(list[object], document["entries"]).append(
            cast(list[object], document["entries"])[0]
        ),
    )
    for mutate in mutations:
        document = cast(dict[str, object], json.loads(original))
        mutate(document)
        path.write_text(json.dumps(document) + "\n", encoding="utf-8")
        path.chmod(0o600)
        with pytest.raises((StateConflictError, StatePersistenceError)):
            _call(prepared)
        assert not deploy_post_scylla_configure_reconciliation_path(
            prepared.paths, OPERATION_ID
        ).exists()
    path.write_bytes(original)
    path.chmod(0o600)


def test_refuses_chain_drift_later_leapfrog_and_unreviewed_bootstrap_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _complete(tmp_path, monkeypatch)
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

    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        prior = DeployPostScyllaInstallReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence = DeployScyllaConfigureEvidenceStore(
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
        if step.mapping_sequence == 13 and step.condition_state.value == "active"
    )
    health = steps[health_index]
    steps[health_index] = replace(
        health,
        status=DeployBaseOsReconciledStepStatus.ELIGIBLE,
        evidence_state=DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED,
        evidence_digest="sha256:" + "a" * 64,
        blockers=(),
    )
    object.__setattr__(prior.record, "steps", tuple(steps))
    with pytest.raises(StateConflictError, match="later gate leapfrog"):
        _build_reconciled_steps(prior, evidence)

    later = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-scylla-bootstrap-context.json"
    )
    later.write_text("{}\n", encoding="utf-8")
    later.chmod(0o600)
    with pytest.raises(StateConflictError, match="unreviewed bootstrap"):
        _call(prepared)


def test_refuses_original_mapping_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del tmp_path
    original = OPERATION_PLAYBOOKS["deploy"]
    monkeypatch.setitem(
        OPERATION_PLAYBOOKS,
        "deploy",
        (*original[:12], OPERATION_PLAYBOOKS["add-node"][12], *original[12:]),
    )
    with pytest.raises(StateConflictError, match="immutable original deploy mapping"):
        _validate_original_mapping()


def test_wrong_lock_unsafe_path_and_show_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _complete(tmp_path, monkeypatch)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        reconcile_deploy_scylla_configure(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
        )

    _call(prepared)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0
    path = deploy_post_scylla_configure_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    target = path.with_name(f"{path.name}.target")
    path.rename(target)
    path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _record(prepared)
    path.unlink()
    target.rename(path)
