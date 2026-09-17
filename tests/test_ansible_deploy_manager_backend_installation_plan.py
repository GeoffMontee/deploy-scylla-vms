import inspect
import json
import shutil
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from test_ansible_deploy_manager_backend_preflight_execution import (
    ManagerBackendPreflightRunner,
)
from test_ansible_deploy_manager_backend_preflight_execution import (
    _call as _execute_preflight,
)
from test_ansible_deploy_manager_backend_preflight_execution import (
    _prepared as _prepare_preflight_execution,
)
from test_ansible_deploy_manager_backend_preflight_reconciliation import (
    _call as _reconcile_preflight,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_manager_backend_installation_plan as installation_module
from scylla_vms.ansible.deploy_manager_backend_installation_plan import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_SCHEMA_VERSION,
    DeployManagerBackendInstallationArtifactState,
    DeployManagerBackendInstallationContextStore,
    DeployManagerBackendInstallationGateState,
    DeployManagerBackendInstallationPlanStatus,
    DeployManagerBackendInstallationPlanStore,
    DeployManagerBackendInstallationSourceState,
    DeployManagerBackendInstallationStorageState,
    _derive_storage_decision,
    deploy_manager_backend_installation_context_path,
    deploy_manager_backend_installation_plan_path,
    plan_deploy_manager_backend_local_installation,
)
from scylla_vms.ansible.deploy_manager_backend_preflight_reconciliation import (
    deploy_manager_backend_preflight_reconciliation_path,
)
from scylla_vms.desired import StorageBackend
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import ObservedStateStore, StoredObservedState
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import ClusterMetadataStore, serialize_json
from scylla_vms.terraform.outputs import StorageManifest, StorageSelectionStatus

_BOUNDARIES = (
    "package-install",
    "local-storage-allocation",
    "local-storage-preflight",
    "local-storage-preparation",
    "local-storage-postcheck",
    "scylla-local-configuration-tuning",
    "one-node-bootstrap-start-health",
    "manager-backend-file-configuration",
    "schema-keyspace-create-verify",
)


@pytest.fixture(scope="module")
def baselines(tmp_path_factory: pytest.TempPathFactory):
    monkeypatch = pytest.MonkeyPatch()
    root = tmp_path_factory.mktemp("manager-backend-installation")
    foundation = root / "foundation"
    foundation.mkdir()
    prepared, executables, toolchain = _prepare_preflight_execution(
        foundation, monkeypatch
    )
    preflight_snapshot = root / "preflight-snapshot"
    shutil.copytree(prepared.paths.state_root, preflight_snapshot)
    ready_runner = ManagerBackendPreflightRunner()
    _execute_preflight(prepared, ready_runner, executables, toolchain)
    _reconcile_preflight(prepared)
    ready_snapshot = root / "ready-snapshot"
    shutil.copytree(prepared.paths.state_root, ready_snapshot)
    _restore(prepared, preflight_snapshot)
    blocked_runner = ManagerBackendPreflightRunner(mode="blocked")
    _execute_preflight(prepared, blocked_runner, executables, toolchain)
    _reconcile_preflight(prepared)
    blocked_snapshot = root / "blocked-snapshot"
    shutil.copytree(prepared.paths.state_root, blocked_snapshot)
    yield prepared, ready_runner, blocked_runner, ready_snapshot, blocked_snapshot
    monkeypatch.undo()


@pytest.fixture
def ready_baseline(baselines):
    prepared, ready_runner, _blocked_runner, ready_snapshot, _blocked_snapshot = (
        baselines
    )
    _restore(prepared, ready_snapshot)
    return prepared, ready_runner


@pytest.fixture
def blocked_baseline(baselines):
    prepared, _ready_runner, blocked_runner, _ready_snapshot, blocked_snapshot = (
        baselines
    )
    _restore(prepared, blocked_snapshot)
    return prepared, blocked_runner


def _restore(prepared, snapshot: Path) -> None:
    shutil.rmtree(prepared.paths.state_root)
    shutil.copytree(snapshot, prepared.paths.state_root)


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return plan_deploy_manager_backend_local_installation(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _records(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = DeployManagerBackendInstallationContextStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        plan = DeployManagerBackendInstallationPlanStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    return context, plan


def _write_document(path: Path, value: dict[str, object]) -> None:
    path.write_bytes(serialize_json(value))
    path.chmod(0o600)


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for item in value.values() for key in _keys(item)}
    if isinstance(value, list):
        return {key for item in value for key in _keys(item)}
    return set()


def test_installation_plan_is_exact_blocked_redacted_and_reuses(
    ready_baseline,
) -> None:
    signature = inspect.signature(plan_deploy_manager_backend_local_installation)
    assert tuple(signature.parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    for forbidden in (
        "package",
        "storage",
        "device",
        "capacity",
        "tuning",
        "config",
        "command",
        "variable",
        "path",
        "text",
        "runner",
        "executable",
        "authorization",
    ):
        assert forbidden not in signature.parameters

    prepared, runner = ready_baseline
    assert runner.specs is not None
    process_count = len(runner.specs)
    context_path = deploy_manager_backend_installation_context_path(
        prepared.paths, OPERATION_ID
    )
    plan_path = deploy_manager_backend_installation_plan_path(
        prepared.paths, OPERATION_ID
    )
    prior_paths = tuple(
        path
        for path in prepared.paths.operations.iterdir()
        if path.is_file() and path not in {context_path, plan_path}
    )
    prior_bytes = {path: path.read_bytes() for path in prior_paths}

    report = _call(prepared)
    context_bytes = context_path.read_bytes()
    plan_bytes = plan_path.read_bytes()
    context_mtime = context_path.stat().st_mtime_ns
    plan_mtime = plan_path.stat().st_mtime_ns
    reused = _call(prepared)
    context, plan = _records(prepared)

    assert (
        report.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_REPORT_SCHEMA_VERSION
    )
    assert (
        context.record.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_SCHEMA_VERSION
    )
    assert (
        plan.record.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_SCHEMA_VERSION
    )
    assert report.context_state is DeployManagerBackendInstallationArtifactState.CREATED
    assert report.plan_state is DeployManagerBackendInstallationArtifactState.CREATED
    assert reused.context_state is DeployManagerBackendInstallationArtifactState.REUSED
    assert reused.plan_state is DeployManagerBackendInstallationArtifactState.REUSED
    assert context_path.read_bytes() == context_bytes
    assert plan_path.read_bytes() == plan_bytes
    assert context_path.stat().st_mtime_ns == context_mtime
    assert plan_path.stat().st_mtime_ns == plan_mtime
    assert context_path.stat().st_mode & 0o777 == 0o600
    assert plan_path.stat().st_mode & 0o777 == 0o600
    assert len(runner.specs) == process_count
    assert all(path.read_bytes() == prior_bytes[path] for path in prior_paths)

    record = context.record
    planned = plan.record
    assert record.host_planning_state.value == "evidence-ready"
    assert record.journal_status is JournalStatus.IN_PROGRESS
    assert record.journal_phase is OperationPhase.VERIFY
    assert record.operating_system == "Ubuntu"
    assert record.operating_system_version == "24.04"
    assert record.architecture in {"amd64", "aarch64"}
    assert record.manager_service_state == "masked-inactive"
    assert record.local_scylla_package_state == "not-installed"
    assert record.local_scylla_service_state == "absent"
    assert record.storage_decision.dedicated_volume_identified
    assert (
        record.storage_decision.state
        is DeployManagerBackendInstallationStorageState.IDENTIFIED
    )
    assert record.storage_decision.root_fallback_policy == "forbidden"
    assert not record.storage_decision.generic_root_capacity_accepted
    assert record.storage_decision.selection_state in {"provisional", "final"}
    assert record.package_reference.authentication_state == "authenticated"
    assert (
        record.package_reference.target_contract_state
        == "manager-backend-local-install-source-available"
    )
    assert (
        record.package_reference.package_set_policy
        == "exact-manager-local-backend-package-set-approved"
    )
    assert record.original_mapping_count == 21
    assert record.original_mapping_unchanged
    assert planned.original_mapping_count == 21
    assert planned.original_mapping_digest == record.original_mapping_digest
    assert planned.original_mapping_unchanged
    assert planned.status is DeployManagerBackendInstallationPlanStatus.BLOCKED
    assert tuple(step.boundary for step in planned.steps) == _BOUNDARIES
    assert tuple(step.sequence for step in planned.steps) == tuple(range(1, 10))
    assert planned.source_available_count == 1
    assert planned.source_unavailable_count == 8
    assert planned.not_performed_count == 9
    assert planned.blocked_count == 8
    assert planned.read_only_step_count == 2
    assert planned.mutating_step_count == 4
    assert planned.sensitive_step_count == 2
    assert planned.destructive_step_count == 1
    package_step = planned.steps[0]
    assert (
        package_step.source_state
        is DeployManagerBackendInstallationSourceState.AVAILABLE
    )
    assert package_step.source_digest is not None
    assert package_step.source_contract_state == "manager-backend-local-install-v1"
    assert package_step.authorization_requirement == "ordinary-approval-required"
    assert (
        package_step.status
        is DeployManagerBackendInstallationPlanStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
    )
    assert package_step.blockers == (
        "deploy-authorization-not-collected",
        "mutating-deploy-execution-unavailable",
        "public-deploy-workflow-unavailable",
    )
    assert all(
        step.source_state is DeployManagerBackendInstallationSourceState.UNAVAILABLE
        and step.source_digest is None
        and step.source_contract_state == "manager-role-source-unavailable"
        and step.performance_state == "not-performed"
        and step.status is DeployManagerBackendInstallationPlanStatus.BLOCKED
        and step.target_ids == (record.manager_target_id,)
        for step in planned.steps[1:]
    )
    assert (
        planned.steps[2].classification is OperationClassification.READ_ONLY
        and planned.steps[2].authorization_requirement == "not-required-read-only"
    )
    assert (
        planned.steps[3].classification is OperationClassification.DESTRUCTIVE
        and planned.steps[3].authorization_requirement == "blocked-before-authorization"
    )
    assert "manager-backend-package-set-unapproved" not in planned.blockers
    assert "manager-backend-capacity-policy-unknown" in planned.blockers
    assert "manager-backend-tuning-suitability-unknown" in planned.blockers
    assert "manager-backend-scyllamgr-setup-unapproved" in planned.blockers
    assert "manager-backend-keyspace-rf-schema-policy-unapproved" in planned.blockers
    assert "scylla-install-manager-role-contract-incompatible" not in planned.blockers
    assert "scylla-storage-manager-role-contract-incompatible" in planned.blockers
    assert "scylla-configure-manager-role-contract-incompatible" in planned.blockers
    assert "scylla-bootstrap-manager-role-contract-incompatible" in planned.blockers
    assert planned.authorization_state == "package-install-authorization-required"
    assert planned.execution_state == "not-performed"
    assert planned.public_workflow_state == "unavailable"
    assert planned.next_implementation_contract == (
        "manager-backend-local-install-execution-owner"
    )

    report_object = report.to_object()
    report_text = json.dumps(report_object, sort_keys=True)
    assert set(report_object) == {
        "artifacts",
        "blockers",
        "journal",
        "next_implementation_contract",
        "operation_id",
        "original_mapping_unchanged",
        "package_reference",
        "schema_version",
        "scope",
        "states",
        "steps",
        "storage",
    }
    report_keys = _keys(report_object)
    for forbidden in (
        "address",
        "provider_id",
        "device_path",
        "serial",
        "command",
        "variable",
        "environment",
        "credential",
        "secret",
    ):
        assert forbidden not in report_keys
    assert "ocid1." not in report_text
    assert "/dev/" not in report_text
    assert "10.0." not in report_text
    persisted_text = context_bytes.decode() + plan_bytes.decode()
    assert "ocid1." not in persisted_text
    assert "/dev/" not in persisted_text
    assert "10.0." not in persisted_text
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


def test_blocked_host_evidence_stays_blocked_and_does_not_hide_design_gates(
    blocked_baseline,
) -> None:
    prepared, _runner = blocked_baseline
    report = _call(prepared)
    context, plan = _records(prepared)
    host_gate = next(
        gate for gate in context.record.gates if gate.name == "host-preflight-evidence"
    )
    local_gate = next(
        gate
        for gate in context.record.gates
        if gate.name == "local-scylla-absent-inactive"
    )
    assert context.record.host_planning_state.value == "blocked"
    assert host_gate.state is DeployManagerBackendInstallationGateState.BLOCKED
    assert local_gate.state is DeployManagerBackendInstallationGateState.BLOCKED
    assert "local-scylla-package-present" in host_gate.blockers
    assert "local-scylla-package-present" in plan.record.blockers
    assert "manager-backend-package-set-unapproved" not in plan.record.blockers
    assert report.status is DeployManagerBackendInstallationPlanStatus.BLOCKED
    assert report.authorization_state == "unavailable"
    assert report.execution_state == "not-performed"


def test_no_dedicated_volume_never_falls_back_to_root_or_generic_capacity(
    ready_baseline,
) -> None:
    prepared, _runner = ready_baseline
    metadata = ClusterMetadataStore(prepared.paths).read(
        expected_cluster_name="example",
        expected_cluster_uuid=CLUSTER_UUID,
        expected_provider="oci",
    )
    observed = ObservedStateStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    manager = next(
        host for host in observed.record.manifest.hosts if host.role.value == "manager"
    )
    boot_only = StorageManifest(
        requested_backend=StorageBackend.BOOT_ONLY,
        selected_backend=StorageBackend.BOOT_ONLY,
        selection_algorithm=manager.storage.selection_algorithm,
        selection_status=StorageSelectionStatus.FINAL,
        policy_digest=manager.storage.policy_digest,
        storage_generation=manager.storage.storage_generation,
        expected_device_count=0,
        raw_total_gib=0,
        usable_total_gib=0,
        layout=None,
        raid_device=None,
        filesystem_type=None,
        filesystem_label=None,
        mount_strategy=None,
        mount_point=None,
        mount_options=(),
        role_allocations=(),
        devices=(),
    )
    host = replace(manager, storage=boot_only)
    manifest = replace(
        observed.record.manifest,
        hosts=tuple(
            host if item.logical_id == manager.logical_id else item
            for item in observed.record.manifest.hosts
        ),
    )
    unvalidated_observation = cast(
        StoredObservedState,
        SimpleNamespace(
            record=SimpleNamespace(manifest=manifest),
            digest=observed.digest,
        ),
    )
    decision = _derive_storage_decision(
        metadata.record.desired_spec,
        unvalidated_observation,
        manager.logical_id,
    )
    assert decision.state is DeployManagerBackendInstallationStorageState.UNMODELED
    assert not decision.dedicated_volume_identified
    assert decision.expected_device_count == 0
    assert decision.volume_identity_digest is None
    assert decision.root_fallback_policy == "forbidden"
    assert not decision.generic_root_capacity_accepted


def test_builds_before_write_and_recovers_exact_context_prefix(
    monkeypatch: pytest.MonkeyPatch,
    ready_baseline,
) -> None:
    prepared, runner = ready_baseline
    assert runner.specs is not None
    process_count = len(runner.specs)
    context_path = deploy_manager_backend_installation_context_path(
        prepared.paths, OPERATION_ID
    )
    plan_path = deploy_manager_backend_installation_plan_path(
        prepared.paths, OPERATION_ID
    )
    original_builder = installation_module._build_plan_record

    def fail_build(*args, **kwargs):
        del args, kwargs
        raise StateConflictError("injected in-memory installation plan failure")

    monkeypatch.setattr(installation_module, "_build_plan_record", fail_build)
    with pytest.raises(StateConflictError, match="in-memory"):
        _call(prepared)
    assert not context_path.exists()
    assert not plan_path.exists()
    monkeypatch.setattr(installation_module, "_build_plan_record", original_builder)

    original_write = DeployManagerBackendInstallationPlanStore.write_locked

    def fail_write(*args, **kwargs):
        del args, kwargs
        raise StatePersistenceError("injected installation plan persistence failure")

    monkeypatch.setattr(
        DeployManagerBackendInstallationPlanStore, "write_locked", fail_write
    )
    with pytest.raises(StatePersistenceError, match="injected"):
        _call(prepared)
    assert context_path.exists()
    context_bytes = context_path.read_bytes()
    assert not plan_path.exists()

    monkeypatch.setattr(
        DeployManagerBackendInstallationPlanStore, "write_locked", original_write
    )
    report = _call(prepared)
    assert report.context_state is DeployManagerBackendInstallationArtifactState.REUSED
    assert report.plan_state is DeployManagerBackendInstallationArtifactState.CREATED
    assert context_path.read_bytes() == context_bytes
    assert len(runner.specs) == process_count


def test_refuses_wrong_lock_missing_chain_tamper_drift_and_ambiguous_history(
    ready_baseline,
    baselines,
) -> None:
    prepared, _runner = ready_baseline
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        plan_deploy_manager_backend_local_installation(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
        )

    conflict = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-manager-backend-installation-execution.json"
    )
    conflict.write_text("{}\n", encoding="utf-8")
    conflict.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous or advanced"):
        _call(prepared)
    conflict.unlink()

    _call(prepared)
    context_path = deploy_manager_backend_installation_context_path(
        prepared.paths, OPERATION_ID
    )
    context = json.loads(context_path.read_text(encoding="utf-8"))
    context["authorization_state"] = "authorized"
    _write_document(context_path, context)
    with pytest.raises(StatePersistenceError):
        _call(prepared)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0

    _prepared, _ready_runner, _blocked_runner, ready_snapshot, _blocked_snapshot = (
        baselines
    )
    _restore(prepared, ready_snapshot)
    deploy_manager_backend_preflight_reconciliation_path(
        prepared.paths, OPERATION_ID
    ).unlink()
    with pytest.raises(StateConflictError):
        _call(prepared)

    _restore(prepared, ready_snapshot)
    trust = json.loads(prepared.paths.ansible_trust.read_text(encoding="utf-8"))
    trust["generation"] += 1
    _write_document(prepared.paths.ansible_trust, trust)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)


def test_refuses_plan_without_context_and_show_rejects_tampered_plan(
    ready_baseline,
    baselines,
) -> None:
    prepared, _runner = ready_baseline
    plan_path = deploy_manager_backend_installation_plan_path(
        prepared.paths, OPERATION_ID
    )
    plan_path.write_text("{}\n", encoding="utf-8")
    plan_path.chmod(0o600)
    with pytest.raises(StateConflictError, match="without its context"):
        _call(prepared)

    _prepared, _ready_runner, _blocked_runner, ready_snapshot, _blocked_snapshot = (
        baselines
    )
    _restore(prepared, ready_snapshot)
    _call(prepared)
    plan_path = deploy_manager_backend_installation_plan_path(
        prepared.paths, OPERATION_ID
    )
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["source_available_count"] = 0
    _write_document(plan_path, plan)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
    with pytest.raises(StatePersistenceError):
        _records(prepared)
