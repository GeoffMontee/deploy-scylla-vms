import inspect
import json
from typing import cast

import pytest
from test_ansible_deploy_manager_backend_local_install_execution import (
    ManagerBackendLocalInstallRunner,
)
from test_ansible_deploy_manager_backend_local_install_execution import (
    _call as _execute_install,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_manager_backend_installation_plan import (
    DeployManagerBackendInstallationSourceState,
)
from scylla_vms.ansible.deploy_manager_backend_local_install_execution import (
    DeployManagerBackendLocalInstallExecutionState,
    DeployManagerBackendLocalInstallExecutionStore,
    deploy_manager_backend_local_install_evidence_path,
)
from scylla_vms.ansible.deploy_manager_backend_local_install_reconciliation import (
    ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_SCHEMA_VERSION,
    DeployPostManagerBackendLocalInstallArtifactState,
    DeployPostManagerBackendLocalInstallReconciliationStore,
    DeployPostManagerBackendLocalInstallStepStatus,
    deploy_post_manager_backend_local_install_reconciliation_id_from_filename,
    deploy_post_manager_backend_local_install_reconciliation_path,
    reconcile_deploy_manager_backend_local_install_result,
)
from scylla_vms.errors import AnsibleError, StateConflictError, StatePersistenceError
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification

pytest_plugins = ("test_ansible_deploy_manager_backend_local_install_execution",)

_PRIVATE_PATH = "/private/operator/post-manager-backend-local-install.json"
_SECRET = "obviously-fake-post-manager-backend-local-install-secret"


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_manager_backend_local_install_result(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployPostManagerBackendLocalInstallReconciliationStore(
            prepared.paths,
            OPERATION_ID,
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


@pytest.mark.parametrize(
    ("mode", "changed_count", "no_change_count"),
    (("installed", 1, 0), ("no-change", 0, 1)),
)
def test_success_reuse_plan_next_boundary_redaction_and_show(
    ready_execution,
    mode: str,
    changed_count: int,
    no_change_count: int,
) -> None:
    assert tuple(
        inspect.signature(
            reconcile_deploy_manager_backend_local_install_result
        ).parameters
    ) == ("state_root", "cluster_name", "operation_id", "lock")
    prepared, executables, toolchain = ready_execution
    runner = ManagerBackendLocalInstallRunner(mode=mode)
    _execute_install(prepared, runner, executables, toolchain)
    assert runner.specs is not None
    process_count = len(runner.specs)

    path = deploy_post_manager_backend_local_install_reconciliation_path(
        prepared.paths,
        OPERATION_ID,
    )
    prior_paths = tuple(
        item
        for item in prepared.paths.operations.iterdir()
        if item != path and item.is_file()
    )
    prior_bytes = {item: item.read_bytes() for item in prior_paths}
    show_before = _run_show(prepared.paths, "--fail-on", "none")

    report = _call(prepared)
    first_bytes = path.read_bytes()
    first_mtime = path.stat().st_mtime_ns
    reused = _call(prepared)
    stored = _record(prepared)

    assert report.schema_version == (
        ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    assert stored.record.schema_version == (
        ANSIBLE_DEPLOY_POST_MANAGER_BACKEND_LOCAL_INSTALL_RECONCILIATION_SCHEMA_VERSION
    )
    assert (
        report.artifact_state
        is DeployPostManagerBackendLocalInstallArtifactState.CREATED
    )
    assert (
        reused.artifact_state
        is DeployPostManagerBackendLocalInstallArtifactState.REUSED
    )
    assert path.read_bytes() == first_bytes
    assert path.stat().st_mtime_ns == first_mtime
    assert path.stat().st_mode & 0o777 == 0o600
    assert len(runner.specs) == process_count
    assert _run_show(prepared.paths, "--fail-on", "none") == show_before
    assert {item: item.read_bytes() for item in prior_paths} == prior_bytes
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert report.changed_count == changed_count
    assert report.no_change_count == no_change_count
    assert report.installed_count == report.service_safe_count == 1
    assert report.prohibited_action_count == 0
    assert report.authorization_consumed
    assert report.process_calls == 0
    assert not report.authorization_created
    assert not report.execution_started

    record = stored.record
    assert record.original_plan_unchanged
    assert record.original_mapping_unchanged
    assert record.original_plan_step_count == record.step_count == 9
    assert tuple(step.sequence for step in record.steps) == tuple(range(1, 10))
    package = record.steps[0]
    next_step = record.steps[1]
    assert package.boundary == "package-install"
    assert package.status is DeployPostManagerBackendLocalInstallStepStatus.SUCCEEDED
    assert package.evidence_state == "package-install-evidence-bound"
    assert package.evidence_digest == record.evidence_digest
    assert not package.blockers
    assert report.next_sequence == next_step.sequence == 2
    assert report.next_boundary == next_step.boundary == "local-storage-allocation"
    assert (
        report.next_classification
        is next_step.classification
        is OperationClassification.MUTATING
    )
    assert (
        report.next_source_state
        is next_step.source_state
        is DeployManagerBackendInstallationSourceState.UNAVAILABLE
    )
    assert (
        report.next_status
        is next_step.status
        is DeployPostManagerBackendLocalInstallStepStatus.BLOCKED
    )
    assert set(next_step.blockers) == {
        "manager-backend-capacity-policy-unknown",
        "manager-backend-storage-allocation-contract-unapproved",
        "manager-backend-storage-allocation-source-unavailable",
        "scylla-storage-manager-role-contract-incompatible",
    }
    assert report.next_implementation_contract == (
        "manager-backend-local-storage-allocation-contract"
    )
    assert all(
        step.status is DeployPostManagerBackendLocalInstallStepStatus.BLOCKED
        for step in record.steps[1:]
    )
    assert {
        "manager-backend-capacity-policy-unknown",
        "manager-backend-tuning-suitability-unknown",
        "manager-backend-scyllamgr-setup-unapproved",
        "manager-backend-file-policy-unapproved",
        "manager-backend-keyspace-rf-schema-policy-unapproved",
        "manager-backend-recovery-semantics-unapproved",
    }.issubset(record.unresolved_blockers)

    public = first_bytes.decode() + json.dumps(report.to_object(), sort_keys=True)
    for protected in (
        _PRIVATE_PATH,
        _SECRET,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "/dev/",
        "repo.scylladb.com",
        "BEGIN PGP",
        "--extra-vars",
        "ANSIBLE_",
    ):
        assert protected not in public
    assert (
        deploy_post_manager_backend_local_install_reconciliation_id_from_filename(
            path.name
        )
        == OPERATION_ID
    )


def test_refuses_missing_and_prepared_prefixes(
    ready_execution,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = ready_execution
    with pytest.raises(StateConflictError, match="complete execution"):
        _call(prepared)

    original_write = DeployManagerBackendLocalInstallExecutionStore.write_locked

    def refuse_started(self, record, **kwargs):
        if record.state is DeployManagerBackendLocalInstallExecutionState.STARTED:
            raise StatePersistenceError("simulated refusal before invocation")
        return original_write(self, record, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(
            DeployManagerBackendLocalInstallExecutionStore,
            "write_locked",
            refuse_started,
        )
        with pytest.raises(StatePersistenceError, match="before invocation"):
            _execute_install(
                prepared,
                ManagerBackendLocalInstallRunner(),
                executables,
                toolchain,
            )
    with pytest.raises(StateConflictError, match="complete evidence"):
        _call(prepared)


@pytest.mark.parametrize(
    "mode",
    ("timeout", "failed", "wrong-target", "forbidden-action"),
)
def test_refuses_failed_uncertain_and_invalid_semantic_results(
    ready_execution,
    mode: str,
) -> None:
    prepared, executables, toolchain = ready_execution
    with pytest.raises(AnsibleError):
        _execute_install(
            prepared,
            ManagerBackendLocalInstallRunner(mode=mode),
            executables,
            toolchain,
        )
    with pytest.raises(StateConflictError, match="complete evidence"):
        _call(prepared)


def test_refuses_evidence_plan_and_current_state_tamper(
    ready_execution,
) -> None:
    prepared, executables, toolchain = ready_execution
    _execute_install(
        prepared,
        ManagerBackendLocalInstallRunner(),
        executables,
        toolchain,
    )
    evidence_path = deploy_manager_backend_local_install_evidence_path(
        prepared.paths,
        OPERATION_ID,
    )
    original_evidence = evidence_path.read_bytes()
    evidence = cast(
        dict[str, object],
        json.loads(evidence_path.read_text(encoding="utf-8")),
    )
    entries = cast(list[dict[str, object]], evidence["entries"])
    entries[0]["service_masked"] = False
    evidence_path.write_text(
        json.dumps(evidence, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    evidence_path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)

    evidence_path.write_bytes(original_evidence)
    evidence_path.chmod(0o600)
    plan_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-manager-backend-installation-plan.json"
    )
    original_plan = plan_path.read_bytes()
    plan = cast(
        dict[str, object],
        json.loads(plan_path.read_text(encoding="utf-8")),
    )
    plan["plan_digest"] = "sha256:" + "0" * 64
    plan_path.write_text(json.dumps(plan, sort_keys=True) + "\n", encoding="utf-8")
    plan_path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)

    plan_path.write_bytes(original_plan)
    plan_path.chmod(0o600)
    inventory_path = prepared.paths.ansible_inventory
    inventory = cast(
        dict[str, object],
        json.loads(inventory_path.read_text(encoding="utf-8")),
    )
    inventory["generation"] = 999
    inventory_path.write_text(
        json.dumps(inventory, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    inventory_path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)


def test_conflicting_reconciliation_fails_closed_and_show_rejects_tamper(
    ready_execution,
) -> None:
    prepared, executables, toolchain = ready_execution
    _execute_install(
        prepared,
        ManagerBackendLocalInstallRunner(),
        executables,
        toolchain,
    )
    _call(prepared)
    path = deploy_post_manager_backend_local_install_reconciliation_path(
        prepared.paths,
        OPERATION_ID,
    )
    document = cast(
        dict[str, object],
        json.loads(path.read_text(encoding="utf-8")),
    )
    document["next_boundary"] = "schema-keyspace-create-verify"
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0


def test_filename_parser_refuses_noncanonical_values() -> None:
    assert (
        deploy_post_manager_backend_local_install_reconciliation_id_from_filename(
            "not-a-uuid.ansible-deploy-post-manager-backend-local-install-"
            "reconciliation.json"
        )
        is None
    )
