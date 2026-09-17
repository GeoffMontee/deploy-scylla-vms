import inspect
import json
from dataclasses import replace
from types import SimpleNamespace
from typing import cast

import pytest
from test_ansible_deploy_manager_backend_local_install_execution import (
    ManagerBackendLocalInstallRunner,
)
from test_ansible_deploy_manager_backend_local_install_execution import (
    _call as _execute_install,
)
from test_ansible_deploy_manager_backend_local_install_reconciliation import (
    _call as _reconcile_install,
)
from test_provider_source import CLUSTER_UUID
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_manager_backend_storage_allocation_plan as storage_module
from scylla_vms.ansible.deploy_manager_backend_storage_allocation_plan import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_PLAN_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_PLAN_SCHEMA_VERSION,
    DeployManagerBackendStorageAllocationArtifactState,
    DeployManagerBackendStorageAllocationContextStore,
    DeployManagerBackendStorageAllocationPlanStatus,
    DeployManagerBackendStorageAllocationPlanStore,
    DeployManagerBackendStorageAllocationState,
    DeployManagerBackendStorageDiscoverySourceState,
    DeployManagerBackendStorageGuestIdentityState,
    _derive_allocation_decision,
    _DiscoverySourceReference,
    deploy_manager_backend_storage_allocation_context_id_from_filename,
    deploy_manager_backend_storage_allocation_context_path,
    deploy_manager_backend_storage_allocation_plan_id_from_filename,
    deploy_manager_backend_storage_allocation_plan_path,
    plan_deploy_manager_backend_storage_allocation,
)
from scylla_vms.desired import HostRole, StorageBackend
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.inventory import InventoryStore
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import ObservedStateStore, StoredObservedState
from scylla_vms.persistence import ClusterMetadataStore
from scylla_vms.terraform.inputs import TerraformInputStore

pytest_plugins = ("test_ansible_deploy_manager_backend_local_install_execution",)

_DIGEST = "sha256:" + "d" * 64


@pytest.fixture
def ready_storage_plan(ready_execution):
    prepared, executables, toolchain = ready_execution
    runner = ManagerBackendLocalInstallRunner()
    _execute_install(prepared, runner, executables, toolchain)
    _reconcile_install(prepared)
    return prepared, runner


def _available_source(_source):
    return _DiscoverySourceReference(
        DeployManagerBackendStorageDiscoverySourceState.AVAILABLE,
        _DIGEST,
    )


def _unavailable_source(_source):
    return _DiscoverySourceReference(
        DeployManagerBackendStorageDiscoverySourceState.UNAVAILABLE,
        None,
    )


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return plan_deploy_manager_backend_storage_allocation(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _records(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = DeployManagerBackendStorageAllocationContextStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        plan = DeployManagerBackendStorageAllocationPlanStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    return context, plan


def _current_storage_inputs(prepared):
    metadata = ClusterMetadataStore(prepared.paths).read(
        expected_cluster_name="example",
        expected_cluster_uuid=CLUSTER_UUID,
        expected_provider="oci",
    )
    terraform_input = TerraformInputStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    observation = ObservedStateStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    inventory = InventoryStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    return metadata.record.desired_spec, terraform_input, observation, inventory


def _observation_with_hosts(observation, hosts) -> StoredObservedState:
    manifest = replace(observation.record.manifest, hosts=tuple(hosts))
    return cast(
        StoredObservedState,
        SimpleNamespace(
            record=SimpleNamespace(manifest=manifest),
            digest=observation.digest,
        ),
    )


def test_success_exact_reuse_redaction_and_no_caller_storage_input(
    ready_storage_plan,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signature = inspect.signature(plan_deploy_manager_backend_storage_allocation)
    assert tuple(signature.parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    for forbidden in (
        "device",
        "path",
        "action",
        "command",
        "variable",
        "target",
        "volume",
        "capacity",
        "authorization",
        "runner",
    ):
        assert forbidden not in signature.parameters

    monkeypatch.setattr(storage_module, "_derive_discovery_source", _available_source)
    prepared, runner = ready_storage_plan
    assert runner.specs is not None
    process_count = len(runner.specs)
    context_path = deploy_manager_backend_storage_allocation_context_path(
        prepared.paths, OPERATION_ID
    )
    plan_path = deploy_manager_backend_storage_allocation_plan_path(
        prepared.paths, OPERATION_ID
    )
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    reconciliation_path = prepared.paths.operations / (
        f"{OPERATION_ID}."
        "ansible-deploy-post-manager-backend-local-install-reconciliation.json"
    )
    immutable = (journal_path.read_bytes(), reconciliation_path.read_bytes())

    report = _call(prepared)
    context_bytes = context_path.read_bytes()
    plan_bytes = plan_path.read_bytes()
    context_mtime = context_path.stat().st_mtime_ns
    plan_mtime = plan_path.stat().st_mtime_ns
    reused = _call(prepared)
    context, plan = _records(prepared)
    shown_context = DeployManagerBackendStorageAllocationContextStore(
        prepared.paths, OPERATION_ID
    ).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    shown_plan = DeployManagerBackendStorageAllocationPlanStore(
        prepared.paths, OPERATION_ID
    ).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )

    assert (
        report.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_PLAN_REPORT_SCHEMA_VERSION
    )
    assert (
        context.record.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_CONTEXT_SCHEMA_VERSION
    )
    assert (
        plan.record.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_ALLOCATION_PLAN_SCHEMA_VERSION
    )
    assert (
        report.context_state
        is DeployManagerBackendStorageAllocationArtifactState.CREATED
    )
    assert (
        report.plan_state is DeployManagerBackendStorageAllocationArtifactState.CREATED
    )
    assert (
        reused.context_state
        is DeployManagerBackendStorageAllocationArtifactState.REUSED
    )
    assert (
        reused.plan_state is DeployManagerBackendStorageAllocationArtifactState.REUSED
    )
    assert context_path.read_bytes() == context_bytes
    assert plan_path.read_bytes() == plan_bytes
    assert context_path.stat().st_mtime_ns == context_mtime
    assert plan_path.stat().st_mtime_ns == plan_mtime
    assert context_path.stat().st_mode & 0o777 == 0o600
    assert plan_path.stat().st_mode & 0o777 == 0o600
    assert shown_context.artifact_digest == context.artifact_digest
    assert shown_plan.artifact_digest == plan.artifact_digest
    assert len(runner.specs) == process_count
    assert (journal_path.read_bytes(), reconciliation_path.read_bytes()) == immutable

    decision = context.record.allocation
    planned = plan.record
    assert decision.state is DeployManagerBackendStorageAllocationState.EXACT
    assert (
        decision.guest_identity_state
        is DeployManagerBackendStorageGuestIdentityState.AVAILABLE
    )
    assert decision.provider_allocation_identity_digest is not None
    assert decision.root_fallback_policy == "forbidden"
    assert decision.local_nvme_policy == "forbidden"
    assert decision.shared_scylla_storage_policy == "forbidden"
    assert decision.capacity_policy_state == "unknown"
    assert decision.capacity_evaluation_state == "not-evaluated"
    assert planned.source_contract == "manager-backend-storage-discover-v1"
    assert (
        planned.source_state
        is DeployManagerBackendStorageDiscoverySourceState.AVAILABLE
    )
    assert planned.status is DeployManagerBackendStorageAllocationPlanStatus.ELIGIBLE
    assert planned.discovery_target_ids == ("manager-1",)
    assert planned.discovery_target_count == 1
    assert not planned.blockers
    assert planned.classification.value == "read-only"
    assert planned.authorization_state == "not-required-read-only"
    assert planned.execution_state == "not-started"
    assert planned.evidence_state == "not-performed"
    assert planned.mutation_state == "not-performed"
    assert planned.journal_transition_state == "not-performed"
    assert planned.journal_status is JournalStatus.IN_PROGRESS
    assert planned.journal_phase is OperationPhase.VERIFY
    assert report.process_calls == 0
    assert not report.authorization_created
    assert not report.execution_started
    assert not report.mutation_performed
    assert not report.journal_updated

    public = (
        context_bytes.decode()
        + plan_bytes.decode()
        + json.dumps(report.to_object(), sort_keys=True)
    )
    for protected in (
        "ocid1.",
        "/dev/",
        "10.0.",
        "203.0.113.",
        "FAKE-",
        "ansible-playbook",
        "--limit",
        '"variables"',
        '"commands"',
    ):
        assert protected not in public
    assert (
        deploy_manager_backend_storage_allocation_context_id_from_filename(
            context_path.name
        )
        == OPERATION_ID
    )
    assert (
        deploy_manager_backend_storage_allocation_plan_id_from_filename(plan_path.name)
        == OPERATION_ID
    )


def test_missing_source_is_robustly_blocked_with_no_discovery_target(
    ready_storage_plan,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(storage_module, "_derive_discovery_source", _unavailable_source)
    prepared, _runner = ready_storage_plan
    report = _call(prepared)
    _context, plan = _records(prepared)

    assert (
        report.source_state
        is DeployManagerBackendStorageDiscoverySourceState.UNAVAILABLE
    )
    assert report.status is DeployManagerBackendStorageAllocationPlanStatus.BLOCKED
    assert report.discovery_target_count == 0
    assert plan.record.discovery_target_ids == ()
    assert plan.record.blockers == (
        "manager-backend-storage-discovery-source-unavailable",
    )


def test_builds_before_write_and_recovers_exact_context_prefix(
    ready_storage_plan,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(storage_module, "_derive_discovery_source", _available_source)
    prepared, _runner = ready_storage_plan
    context_path = deploy_manager_backend_storage_allocation_context_path(
        prepared.paths, OPERATION_ID
    )
    plan_path = deploy_manager_backend_storage_allocation_plan_path(
        prepared.paths, OPERATION_ID
    )
    original_builder = storage_module._build_plan_record

    def fail_build(*args, **kwargs):
        del args, kwargs
        raise StateConflictError("injected storage plan build failure")

    monkeypatch.setattr(storage_module, "_build_plan_record", fail_build)
    with pytest.raises(StateConflictError, match="build failure"):
        _call(prepared)
    assert not context_path.exists()
    assert not plan_path.exists()
    monkeypatch.setattr(storage_module, "_build_plan_record", original_builder)

    original_write = DeployManagerBackendStorageAllocationPlanStore.write_locked

    def fail_write(*args, **kwargs):
        del args, kwargs
        raise StatePersistenceError("injected storage plan persistence failure")

    monkeypatch.setattr(
        DeployManagerBackendStorageAllocationPlanStore,
        "write_locked",
        fail_write,
    )
    with pytest.raises(StatePersistenceError, match="injected"):
        _call(prepared)
    assert context_path.exists()
    context_bytes = context_path.read_bytes()
    assert not plan_path.exists()

    monkeypatch.setattr(
        DeployManagerBackendStorageAllocationPlanStore,
        "write_locked",
        original_write,
    )
    report = _call(prepared)
    assert (
        report.context_state
        is DeployManagerBackendStorageAllocationArtifactState.REUSED
    )
    assert (
        report.plan_state is DeployManagerBackendStorageAllocationArtifactState.CREATED
    )
    assert context_path.read_bytes() == context_bytes


def test_non_path_identity_is_required_even_with_requested_path(
    ready_storage_plan,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = ready_storage_plan
    desired, terraform_input, observation, inventory = _current_storage_inputs(prepared)
    manager = next(
        host
        for host in observation.record.manifest.hosts
        if host.role is HostRole.MANAGER
    )
    device = replace(
        manager.storage.devices[0],
        expected_by_id=None,
        expected_serial=None,
        expected_wwn=None,
    )
    storage = replace(manager.storage, devices=(device,))
    changed_manager = replace(manager, storage=storage)
    changed_observation = _observation_with_hosts(
        observation,
        (
            changed_manager if host.logical_id == manager.logical_id else host
            for host in observation.record.manifest.hosts
        ),
    )
    decision = _derive_allocation_decision(
        desired,
        terraform_input,
        changed_observation,
        inventory,
        manager.logical_id,
    )
    assert decision.state is DeployManagerBackendStorageAllocationState.EXACT
    assert decision.requested_path_present
    assert decision.requested_path_only
    assert (
        decision.guest_identity_state
        is DeployManagerBackendStorageGuestIdentityState.UNAVAILABLE
    )

    monkeypatch.setattr(
        storage_module,
        "_derive_allocation_decision",
        lambda *args, **kwargs: decision,
    )
    monkeypatch.setattr(storage_module, "_derive_discovery_source", _available_source)
    report = _call(prepared)
    _context, plan = _records(prepared)
    assert report.status is DeployManagerBackendStorageAllocationPlanStatus.BLOCKED
    assert report.discovery_target_count == 0
    assert plan.record.discovery_target_ids == ()
    assert plan.record.blockers == (
        "manager-backend-storage-guest-identity-unavailable",
    )


def test_missing_ambiguous_root_local_and_shared_allocations_are_refused(
    ready_storage_plan,
) -> None:
    prepared, _runner = ready_storage_plan
    desired, terraform_input, observation, inventory = _current_storage_inputs(prepared)
    hosts = observation.record.manifest.hosts
    manager = next(host for host in hosts if host.role is HostRole.MANAGER)
    target = manager.logical_id

    missing = _derive_allocation_decision(
        desired,
        terraform_input,
        _observation_with_hosts(
            observation,
            (host for host in hosts if host.logical_id != target),
        ),
        inventory,
        target,
    )
    assert missing.state is DeployManagerBackendStorageAllocationState.ABSENT
    assert missing.allocation_count == 0
    assert missing.blockers == ("manager-backend-dedicated-storage-absent",)

    ambiguous = _derive_allocation_decision(
        desired,
        terraform_input,
        _observation_with_hosts(observation, (*hosts, manager)),
        inventory,
        target,
    )
    assert ambiguous.state is DeployManagerBackendStorageAllocationState.AMBIGUOUS
    assert ambiguous.blockers == ("manager-backend-dedicated-storage-ambiguous",)

    root_storage = replace(
        manager.storage,
        selected_backend=StorageBackend.BOOT_ONLY,
    )
    root = _derive_allocation_decision(
        desired,
        terraform_input,
        _observation_with_hosts(
            observation,
            (
                replace(manager, storage=root_storage)
                if host.logical_id == target
                else host
                for host in hosts
            ),
        ),
        inventory,
        target,
    )
    assert root.state is DeployManagerBackendStorageAllocationState.FORBIDDEN
    assert "manager-backend-root-storage-forbidden" in root.blockers

    local_storage = replace(
        manager.storage,
        selected_backend=StorageBackend.LOCAL_NVME,
    )
    local = _derive_allocation_decision(
        desired,
        terraform_input,
        _observation_with_hosts(
            observation,
            (
                replace(manager, storage=local_storage)
                if host.logical_id == target
                else host
                for host in hosts
            ),
        ),
        inventory,
        target,
    )
    assert local.state is DeployManagerBackendStorageAllocationState.FORBIDDEN
    assert "manager-backend-local-nvme-forbidden" in local.blockers

    scylla = next(host for host in hosts if host.role is HostRole.SCYLLA)
    shared_device = replace(
        scylla.storage.devices[0],
        provider_volume_id=manager.storage.devices[0].provider_volume_id,
        provider_attachment_id=manager.storage.devices[0].provider_attachment_id,
    )
    shared_scylla = replace(
        scylla,
        storage=replace(scylla.storage, devices=(shared_device,)),
    )
    shared = _derive_allocation_decision(
        desired,
        terraform_input,
        _observation_with_hosts(
            observation,
            (
                shared_scylla if host.logical_id == scylla.logical_id else host
                for host in hosts
            ),
        ),
        inventory,
        target,
    )
    assert shared.state is DeployManagerBackendStorageAllocationState.FORBIDDEN
    assert shared.shared_with_scylla
    assert "manager-backend-shared-scylla-storage-forbidden" in shared.blockers
    assert shared.provider_allocation_identity_digest is None


def test_requires_held_deploy_lock_and_refuses_later_or_drifted_history(
    ready_storage_plan,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(storage_module, "_derive_discovery_source", _available_source)
    prepared, _runner = ready_storage_plan
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        plan_deploy_manager_backend_storage_allocation(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
        )

    later = prepared.paths.operations / (
        f"{OPERATION_ID}."
        "ansible-deploy-manager-backend-storage-discovery-execution.json"
    )
    later.write_text("{}\n", encoding="utf-8")
    later.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous or advanced"):
        _call(prepared)
    later.unlink()

    _call(prepared)
    tfvars_path = prepared.paths.terraform_tfvars
    tfvars_path.write_bytes(tfvars_path.read_bytes() + b" ")
    tfvars_path.chmod(0o600)
    with pytest.raises(StateConflictError):
        _call(prepared)


def test_filename_parsers_refuse_noncanonical_values() -> None:
    assert (
        deploy_manager_backend_storage_allocation_context_id_from_filename(
            "not-a-uuid.ansible-deploy-manager-backend-storage-allocation-context.json"
        )
        is None
    )
    assert (
        deploy_manager_backend_storage_allocation_plan_id_from_filename(
            "not-a-uuid.ansible-deploy-manager-backend-storage-allocation-plan.json"
        )
        is None
    )
