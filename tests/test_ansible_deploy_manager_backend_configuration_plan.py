import inspect
import json
from pathlib import Path

import pytest
from test_ansible_deploy_manager_activation_plan import (
    _call as _plan_activation,
)
from test_ansible_deploy_manager_activation_plan import (
    _prepared as _prepare_activation,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_manager_backend_configuration_plan as backend_module
from scylla_vms.ansible.deploy_manager_backend_configuration_plan import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_SCHEMA_VERSION,
    MANAGER_BACKEND_LOCAL_ONE_NODE_POLICY_SCHEMA_VERSION,
    DeployManagerBackendConfigurationArtifactState,
    DeployManagerBackendConfigurationContextStore,
    DeployManagerBackendConfigurationDecisionState,
    DeployManagerBackendConfigurationGateState,
    DeployManagerBackendConfigurationPlanStatus,
    DeployManagerBackendConfigurationPlanStore,
    DeployManagerBackendConfigurationSourceState,
    DeployManagerBackendMode,
    deploy_manager_backend_configuration_context_id_from_filename,
    deploy_manager_backend_configuration_context_path,
    deploy_manager_backend_configuration_plan_id_from_filename,
    deploy_manager_backend_configuration_plan_path,
    plan_deploy_manager_backend_configuration,
)
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import serialize_json

_PRIVATE_PATH = "/private/operator/manager-backend.json"
_SECRET = "obviously-fake-manager-backend-secret"


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, runner = _prepare_activation(tmp_path, monkeypatch)
    _plan_activation(prepared)
    return prepared, runner


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return plan_deploy_manager_backend_configuration(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _records(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = DeployManagerBackendConfigurationContextStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        plan = DeployManagerBackendConfigurationPlanStore(
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


def test_backend_plan_is_blocked_value_free_immutable_and_mapping_preserving(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signature = inspect.signature(plan_deploy_manager_backend_configuration)
    assert tuple(signature.parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    for forbidden in (
        "backend",
        "host",
        "mode",
        "config",
        "token",
        "auth",
        "credential",
        "port",
        "command",
        "variable",
        "path",
        "text",
    ):
        assert forbidden not in signature.parameters

    prepared, runner = _prepared(tmp_path, monkeypatch)
    monkeypatch.setenv("DEPLOY_SCYLLA_VMS_MANAGER_AUTH_TOKEN", _SECRET)
    assert runner.specs is not None
    process_count = len(runner.specs)
    context_path = deploy_manager_backend_configuration_context_path(
        prepared.paths, OPERATION_ID
    )
    plan_path = deploy_manager_backend_configuration_plan_path(
        prepared.paths, OPERATION_ID
    )
    prior_paths = tuple(
        path
        for path in prepared.paths.operations.iterdir()
        if path not in {context_path, plan_path} and path.is_file()
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
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_REPORT_SCHEMA_VERSION
    )
    assert (
        context.record.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_CONTEXT_SCHEMA_VERSION
    )
    assert (
        plan.record.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_CONFIGURATION_PLAN_SCHEMA_VERSION
    )
    assert (
        report.context_state is DeployManagerBackendConfigurationArtifactState.CREATED
    )
    assert report.plan_state is DeployManagerBackendConfigurationArtifactState.CREATED
    assert reused.context_state is DeployManagerBackendConfigurationArtifactState.REUSED
    assert reused.plan_state is DeployManagerBackendConfigurationArtifactState.REUSED
    assert context_path.read_bytes() == context_bytes
    assert plan_path.read_bytes() == plan_bytes
    assert context_path.stat().st_mtime_ns == context_mtime
    assert plan_path.stat().st_mtime_ns == plan_mtime
    assert context_path.stat().st_mode & 0o777 == 0o600
    assert plan_path.stat().st_mode & 0o777 == 0o600
    assert {path: path.read_bytes() for path in prior_paths} == prior_bytes
    assert len(runner.specs) == process_count
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0

    record = context.record
    planned = plan.record
    assert record.original_mapping_count == planned.original_mapping_count == 21
    assert record.original_mapping_unchanged
    assert planned.original_mapping_unchanged
    assert record.journal_status is planned.journal_status is JournalStatus.IN_PROGRESS
    assert record.journal_phase is planned.journal_phase is OperationPhase.VERIFY
    assert report.classification is OperationClassification.MUTATING
    assert report.status is DeployManagerBackendConfigurationPlanStatus.BLOCKED
    assert (
        report.source_state is DeployManagerBackendConfigurationSourceState.UNAVAILABLE
    )
    assert report.gate_count == 27
    assert report.passed_gate_count == 9
    assert report.unknown_gate_count == 17
    assert report.blocked_gate_count == 1
    assert report.blocker_count == 18
    assert report.next_implementation_contract == (
        "manager-backend-preflight-orchestration-contract"
    )
    assert report.secret_source_state == "not-collected"
    assert planned.step_count == 1
    step = planned.steps[0]
    assert step.boundary == "manager-backend-configuration"
    assert step.classification is OperationClassification.MUTATING
    assert step.target_ids == (record.manager_target_id,)
    assert step.source_state is DeployManagerBackendConfigurationSourceState.UNAVAILABLE
    assert step.source_digest is None
    assert step.authorization_requirement == "blocked-before-authorization"
    assert step.performance_state == "not-performed"
    assert step.status is DeployManagerBackendConfigurationPlanStatus.BLOCKED

    decisions = record.intent
    assert (
        decisions.backend_mode
        is DeployManagerBackendConfigurationDecisionState.APPROVED
    )
    assert decisions.backend_mode_value is DeployManagerBackendMode.LOCAL_ONE_NODE
    policy = decisions.backend_policy
    assert policy.schema_version == MANAGER_BACKEND_LOCAL_ONE_NODE_POLICY_SCHEMA_VERSION
    assert policy.backend_mode is DeployManagerBackendMode.LOCAL_ONE_NODE
    assert policy.target_role == "manager"
    assert policy.managed_data_cluster_backend == "forbidden"
    assert policy.cql_network_ingress == "forbidden"
    assert policy.contact_scope == "loopback-only"
    assert policy.cql_port == 9042
    assert policy.scylla_release == "2026.2"
    assert policy.backend_credentials == policy.backend_tls == "not-required"
    assert policy.manager_service_state == "masked-inactive"
    assert policy.manager_agent_token_policy == "environment-only-required"
    for name in (
        "backend_identity",
        "backend_topology",
        "backend_capacity",
        "backend_health",
        "authentication",
        "tls",
        "schema_bootstrap",
        "contact_point",
        "port",
        "configuration_ownership",
        "configuration_mode",
        "recovery_semantics",
    ):
        assert (
            getattr(decisions, name)
            is DeployManagerBackendConfigurationDecisionState.UNKNOWN
        )
    assert decisions.secret_source_policy == "environment-only"
    assert decisions.secret_source_state == "not-collected"
    assert (
        decisions.source_state
        is DeployManagerBackendConfigurationSourceState.UNAVAILABLE
    )
    assert decisions.source_digest is None

    gates = {gate.name: gate for gate in record.gates}
    for name in (
        "canonical-provenance",
        "manager-target-identity",
        "manager-install-evidence",
        "manager-service-inactive-masked",
        "scylla-final-health",
        "scylla-topology",
        "secret-source-policy",
        "source-catalog-provenance",
        "backend-mode",
    ):
        assert gates[name].state is DeployManagerBackendConfigurationGateState.PASSED
        assert gates[name].evidence_digest is not None
        assert gates[name].blocker is None
    assert gates["source-contract"].state is (
        DeployManagerBackendConfigurationGateState.BLOCKED
    )
    assert {
        "manager-backend-package-availability-unknown",
        "manager-backend-storage-suitability-unknown",
        "manager-backend-tuning-suitability-unknown",
        "manager-backend-identity-unknown",
        "manager-backend-topology-unknown",
        "manager-backend-capacity-unknown",
        "manager-backend-health-unknown",
        "manager-backend-authentication-unapproved",
        "manager-backend-tls-unapproved",
        "manager-backend-secret-source-unbound",
        "manager-backend-schema-bootstrap-unapproved",
        "manager-backend-setup-behavior-unapproved",
        "manager-backend-contact-point-unapproved",
        "manager-backend-port-unapproved",
        "manager-backend-configuration-ownership-unapproved",
        "manager-backend-configuration-mode-unapproved",
        "manager-backend-configuration-source-unavailable",
        "manager-backend-recovery-semantics-unapproved",
    } == set(record.blockers)

    public = (
        context_bytes.decode()
        + plan_bytes.decode()
        + json.dumps(report.to_object(), sort_keys=True)
    )
    for protected in (
        _PRIVATE_PATH,
        _SECRET,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "scylla-manager.yaml",
        "DEPLOY_SCYLLA_VMS_MANAGER_AUTH_TOKEN",
        '"provider_id"',
        '"command"',
        '"variables"',
        '"credentials"',
        '"config_content"',
    ):
        assert protected not in public
    assert (
        deploy_manager_backend_configuration_context_id_from_filename(context_path.name)
        == OPERATION_ID
    )
    assert (
        deploy_manager_backend_configuration_plan_id_from_filename(plan_path.name)
        == OPERATION_ID
    )


def test_backend_plan_refuses_missing_activation_wrong_lock_and_plan_without_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepare_activation(tmp_path, monkeypatch)
    with pytest.raises(StateConflictError, match="activation context and plan"):
        _call(prepared)
    assert not deploy_manager_backend_configuration_context_path(
        prepared.paths, OPERATION_ID
    ).exists()

    _plan_activation(prepared)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        plan_deploy_manager_backend_configuration(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
        )

    plan_path = deploy_manager_backend_configuration_plan_path(
        prepared.paths, OPERATION_ID
    )
    plan_path.write_text("{}\n", encoding="utf-8")
    plan_path.chmod(0o600)
    with pytest.raises(StateConflictError, match="without its context"):
        _call(prepared)


def test_backend_records_build_before_write_and_context_prefix_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    context_path = deploy_manager_backend_configuration_context_path(
        prepared.paths, OPERATION_ID
    )
    plan_path = deploy_manager_backend_configuration_plan_path(
        prepared.paths, OPERATION_ID
    )
    original_builder = backend_module._build_plan_record

    def fail_build(*args, **kwargs):
        del args, kwargs
        raise StateConflictError("injected in-memory backend plan failure")

    monkeypatch.setattr(backend_module, "_build_plan_record", fail_build)
    with pytest.raises(StateConflictError, match="in-memory"):
        _call(prepared)
    assert not context_path.exists()
    assert not plan_path.exists()
    monkeypatch.setattr(backend_module, "_build_plan_record", original_builder)

    original_write = DeployManagerBackendConfigurationPlanStore.write_locked

    def fail_write(*args, **kwargs):
        del args, kwargs
        raise StatePersistenceError("injected backend plan persistence failure")

    monkeypatch.setattr(
        DeployManagerBackendConfigurationPlanStore, "write_locked", fail_write
    )
    with pytest.raises(StatePersistenceError, match="injected"):
        _call(prepared)
    assert context_path.exists()
    context_bytes = context_path.read_bytes()
    assert not plan_path.exists()

    monkeypatch.setattr(
        DeployManagerBackendConfigurationPlanStore, "write_locked", original_write
    )
    report = _call(prepared)
    assert report.context_state is DeployManagerBackendConfigurationArtifactState.REUSED
    assert report.plan_state is DeployManagerBackendConfigurationArtifactState.CREATED
    assert context_path.read_bytes() == context_bytes
    assert len(runner.specs) == process_count


def test_backend_tamper_drift_unreviewed_source_and_ambiguous_history_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    conflict = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-manager-backend-configuration-execution.json"
    )
    conflict.write_text("{}\n", encoding="utf-8")
    conflict.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous or later"):
        _call(prepared)
    conflict.unlink()

    playbook_names = backend_module.PLAYBOOK_NAMES
    monkeypatch.setattr(
        backend_module,
        "PLAYBOOK_NAMES",
        (*playbook_names, "manager-backend-configuration"),
    )
    with pytest.raises(StateConflictError, match="source or catalog"):
        _call(prepared)
    monkeypatch.setattr(backend_module, "PLAYBOOK_NAMES", playbook_names)

    trust_path = prepared.paths.ansible_trust
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    trust["generation"] += 1
    _write_document(trust_path, trust)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)


def test_backend_show_rejects_tampered_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    _call(prepared)
    plan_path = deploy_manager_backend_configuration_plan_path(
        prepared.paths, OPERATION_ID
    )
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["source_available_count"] = 1
    _write_document(plan_path, plan)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
    with pytest.raises(StatePersistenceError):
        _records(prepared)
