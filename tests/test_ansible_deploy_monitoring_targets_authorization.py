import inspect
import json
from pathlib import Path
from typing import cast

import pytest
import test_ansible_deploy_monitoring_agent_reconciliation as agent_fixture
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_monitoring_targets_authorization as authorization_module
from scylla_vms.ansible.deploy_monitoring_agent_reconciliation import (
    deploy_post_monitoring_agent_reconciliation_path,
)
from scylla_vms.ansible.deploy_monitoring_targets_authorization import (
    ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_PROOF_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCHEMA_VERSION,
    DeployMonitoringTargetsApprovalMethod,
    DeployMonitoringTargetsAuthorizationArtifactState,
    DeployMonitoringTargetsAuthorizationProof,
    DeployMonitoringTargetsAuthorizationStore,
    DeployMonitoringTargetsListenPolicy,
    DeployMonitoringTargetsScrapeReadiness,
    _derive_authorization_scope,
    _load_authorization_context,
    authorize_deploy_monitoring_targets,
    deploy_monitoring_targets_authorization_id_from_filename,
    deploy_monitoring_targets_authorization_path,
)
from scylla_vms.ansible.operation_authorization import (
    OPERATION_AUTHORIZATION_FILENAME_SUFFIX,
)
from scylla_vms.desired import HostRole
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import serialize_json

_PRIVATE_PATH = "/private/operator/monitoring-targets-authorization.json"
_SECRET = "obviously-fake-monitoring-targets-authorization-secret"
_PROMPT = "APPROVE targets for 10.0.0.11:9100?"


def _proof(
    method: DeployMonitoringTargetsApprovalMethod = (
        DeployMonitoringTargetsApprovalMethod.INTERACTIVE
    ),
) -> DeployMonitoringTargetsAuthorizationProof:
    return DeployMonitoringTargetsAuthorizationProof(
        approval_method=method,
        approved=True,
    )


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, runner = agent_fixture._complete(tmp_path, monkeypatch)
    agent_fixture._call(prepared)
    return prepared, runner


def _call(prepared, proof: DeployMonitoringTargetsAuthorizationProof):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return authorize_deploy_monitoring_targets(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=proof,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployMonitoringTargetsAuthorizationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


@pytest.mark.parametrize(
    "method",
    (
        DeployMonitoringTargetsApprovalMethod.INTERACTIVE,
        DeployMonitoringTargetsApprovalMethod.CLI_YES,
    ),
)
def test_exact_intent_is_immutable_redacted_and_show_validated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: DeployMonitoringTargetsApprovalMethod,
) -> None:
    signature = inspect.signature(authorize_deploy_monitoring_targets)
    assert tuple(signature.parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "proof",
    )
    for forbidden in (
        "step",
        "target",
        "limit",
        "file",
        "content",
        "label",
        "port",
        "address",
        "command",
        "variable",
        "path",
        "scope",
        "prompt",
        "text",
    ):
        assert forbidden not in signature.parameters

    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    path = deploy_monitoring_targets_authorization_path(prepared.paths, OPERATION_ID)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    prior_paths = tuple(
        item for item in prepared.paths.operations.iterdir() if item.is_file()
    )
    prior_bytes = {item: item.read_bytes() for item in prior_paths}

    report = _call(prepared, _proof(method))
    first_bytes = path.read_bytes()
    first_mtime = path.stat().st_mtime_ns
    reused = _call(prepared, _proof(method))
    stored = _record(prepared)

    assert report.artifact_state is (
        DeployMonitoringTargetsAuthorizationArtifactState.CREATED
    )
    assert reused.artifact_state is (
        DeployMonitoringTargetsAuthorizationArtifactState.REUSED
    )
    assert path.read_bytes() == first_bytes
    assert path.stat().st_mtime_ns == first_mtime
    assert path.stat().st_mode & 0o777 == 0o600
    assert journal_path.read_bytes() == prior_bytes[journal_path]
    assert {item: item.read_bytes() for item in prior_paths} == prior_bytes
    assert len(runner.specs) == process_count

    assert report.schema_version == (
        ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )
    assert report.authorization_schema_version == (
        ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCHEMA_VERSION
    )
    assert report.proof_schema_version == (
        ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    assert report.approval_method is method
    assert report.classification is OperationClassification.MUTATING
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert report.playbook == "monitoring-targets"
    assert report.target_count == 1
    assert report.file_count == 4
    assert report.manager_target_count == 1
    assert report.scylla_target_count > 0
    assert report.node_exporter_target_count == report.scylla_target_count
    assert report.manager_agent_target_count == report.scylla_target_count
    assert report.listen_policy is DeployMonitoringTargetsListenPolicy.NOT_STARTED
    assert (
        report.scrape_readiness is DeployMonitoringTargetsScrapeReadiness.NOT_PERFORMED
    )
    assert report.prohibited_action_count == 0
    assert not report.consumed
    assert report.execution_state == "unavailable"
    assert report.finalization_state == "not-started"
    assert report.public_workflow_state == "unavailable"

    record = stored.record
    scope = record.scope
    assert record.authorization_state == "authorized-pre-execution"
    assert not record.consumed
    assert scope.mapping_sequence == 18
    assert scope.playbook == "monitoring-targets"
    assert scope.target_role == "monitoring"
    assert scope.target_stable_id == report.target_stable_id
    assert scope.file_count == len(authorization_module.TARGET_FILES) == 4
    assert not any(
        (
            scope.scrape_performed,
            scope.exporters_started,
            scope.stack_started,
            scope.containers_started,
            scope.auth_configured,
            scope.public_bind,
            scope.manager_registration_performed,
            scope.scylla_started,
            scope.secrets_written,
            scope.compose_generated,
        )
    )

    persisted = cast(dict[str, object], json.loads(first_bytes))
    assert first_bytes == serialize_json(persisted)
    public = first_bytes.decode() + json.dumps(report.to_object(), sort_keys=True)
    for protected in (
        _PRIVATE_PATH,
        _SECRET,
        _PROMPT,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "scylla_servers.yml",
        "node_exporter_servers.yml",
        "scylla_manager_agents.yml",
        "scylla_manager_servers.yml",
        "/opt/scylla-monitoring",
        '"content"',
        '"labels"',
        '"ports"',
        '"5090"',
        '"9100"',
        '"9180"',
        "ansible-playbook",
        "--limit",
        '"variables"',
        '"commands"',
        "password",
    ):
        assert protected not in public
    assert (
        deploy_monitoring_targets_authorization_id_from_filename(path.name)
        == OPERATION_ID
    )
    assert (
        deploy_monitoring_targets_authorization_id_from_filename(
            f"uppercase-{path.name}"
        )
        is None
    )
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


def test_refuses_missing_denied_destructive_narrow_and_changed_proofs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases = (
        (DeployMonitoringTargetsAuthorizationProof(), "approval is required"),
        (
            DeployMonitoringTargetsAuthorizationProof(
                approval_method=DeployMonitoringTargetsApprovalMethod.INTERACTIVE,
                approved=False,
            ),
            "approval was denied",
        ),
        (
            DeployMonitoringTargetsAuthorizationProof(
                approval_method=DeployMonitoringTargetsApprovalMethod.CLI_YES,
                approved=True,
                allow_destructive=True,
            ),
            "destructive and narrow proofs are inapplicable",
        ),
        (
            DeployMonitoringTargetsAuthorizationProof(
                approval_method=DeployMonitoringTargetsApprovalMethod.INTERACTIVE,
                approved=True,
                destructive_scope_provided=True,
            ),
            "destructive and narrow proofs are inapplicable",
        ),
        (
            DeployMonitoringTargetsAuthorizationProof(
                approval_method=DeployMonitoringTargetsApprovalMethod.INTERACTIVE,
                approved=True,
                narrow_consent_provided=True,
            ),
            "destructive and narrow proofs are inapplicable",
        ),
    )
    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    for proof, message in cases:
        with pytest.raises(StateConflictError, match=message):
            _call(prepared, proof)
    assert not deploy_monitoring_targets_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()

    _call(prepared, _proof())
    with pytest.raises(StateConflictError, match="changed"):
        _call(
            prepared,
            _proof(DeployMonitoringTargetsApprovalMethod.CLI_YES),
        )
    assert len(runner.specs) == process_count


def test_refuses_wrong_role_target_change_service_and_intent_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = _load_authorization_context(prepared.paths, OPERATION_ID, lock=lock)
        loaded = authorization_module._loaded(
            context.agent.authorization_context.manager.authorization_context.monitoring.monitoring.manager.manager.chain.authorization_context
        )
        monitoring = next(
            host
            for host in loaded.planning.base.deploy.inventory.record.inventory.hosts
            if host.role is HostRole.MONITORING
        )
        object.__setattr__(monitoring, "role", HostRole.MANAGER)
        with pytest.raises(StateConflictError, match="current monitoring identity"):
            _derive_authorization_scope(context)
        object.__setattr__(monitoring, "role", HostRole.MONITORING)

        mapped = next(
            step
            for step in context.post_agent.record.steps
            if step.mapping_sequence == 18
        )
        original_targets = mapped.target_ids
        object.__setattr__(mapped, "target_ids", ())
        with pytest.raises(StateConflictError, match="exact active mapped"):
            _derive_authorization_scope(context)
        object.__setattr__(mapped, "target_ids", original_targets)

        manager_entry = (
            context.agent.authorization_context.manager.evidence.record.entries[0]
        )
        object.__setattr__(manager_entry, "server_reachability", "reachable")
        with pytest.raises(StateConflictError, match="Manager-agent service gate"):
            _derive_authorization_scope(context)
        object.__setattr__(manager_entry, "server_reachability", "not-performed")

        manager_server_entry = context.agent.authorization_context.manager.authorization_context.monitoring.monitoring.manager.evidence.record.entries[
            0
        ]
        original_manager_id = manager_server_entry.stable_id
        object.__setattr__(manager_server_entry, "stable_id", "wrong-manager")
        with pytest.raises(
            StateConflictError, match="Manager-server identity or evidence"
        ):
            _derive_authorization_scope(context)
        object.__setattr__(manager_server_entry, "stable_id", original_manager_id)

        original_builder = authorization_module.build_monitoring_targets_payload

        def tampered_builder(*args, **kwargs):
            payload = original_builder(*args, **kwargs)
            payload["public_bind"] = True
            return payload

        monkeypatch.setattr(
            authorization_module,
            "build_monitoring_targets_payload",
            tampered_builder,
        )
        with pytest.raises(StateConflictError, match="prohibition"):
            _derive_authorization_scope(context)
    assert len(runner.specs) == process_count


def test_refuses_missing_reconciliation_source_drift_later_state_and_wrong_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    post_path = deploy_post_monitoring_agent_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    post_bytes = post_path.read_bytes()
    post_path.unlink()
    with pytest.raises(StateConflictError, match="requires post-monitoring-agent"):
        _call(prepared, _proof())
    post_path.write_bytes(post_bytes)
    post_path.chmod(0o600)

    original_source_digest = authorization_module._playbook_source_digest
    monkeypatch.setattr(
        authorization_module,
        "_playbook_source_digest",
        lambda *_args: "sha256:" + "a" * 64,
    )
    with pytest.raises(StateConflictError, match=r"source|exact active mapped"):
        _call(prepared, _proof())
    monkeypatch.setattr(
        authorization_module,
        "_playbook_source_digest",
        original_source_digest,
    )

    generic = prepared.paths.operations / (
        f"{OPERATION_ID}{OPERATION_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    generic.write_text("{}\n", encoding="utf-8")
    generic.chmod(0o600)
    with pytest.raises(StateConflictError, match="generic Ansible authorization"):
        _call(prepared, _proof())
    generic.unlink()

    later = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-monitoring-targets-execution.json"
    )
    later.write_text("{}\n", encoding="utf-8")
    later.chmod(0o600)
    with pytest.raises(StateConflictError, match="later-stage history"):
        _call(prepared, _proof())
    later.unlink()

    canonical_name = deploy_monitoring_targets_authorization_path(
        prepared.paths, OPERATION_ID
    ).name
    ambiguous = prepared.paths.operations / f"ambiguous-{canonical_name}"
    ambiguous.write_text("{}\n", encoding="utf-8")
    ambiguous.chmod(0o600)
    with pytest.raises(StateConflictError, match="artifacts are ambiguous"):
        _call(prepared, _proof())
    ambiguous.unlink()

    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        authorize_deploy_monitoring_targets(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            proof=_proof(),
        )
    assert len(runner.specs) == process_count


def test_store_and_show_reject_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    _call(prepared, _proof())
    path = deploy_monitoring_targets_authorization_path(prepared.paths, OPERATION_ID)
    original = path.read_bytes()
    document = cast(dict[str, object], json.loads(original))
    document["target_count"] = 2
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(StatePersistenceError):
        _record(prepared)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0

    path.write_bytes(original)
    path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0
