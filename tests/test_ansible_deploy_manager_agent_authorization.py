import inspect
import json
from pathlib import Path
from typing import cast

import pytest
import test_ansible_deploy_monitoring_stack_reconciliation as monitoring_fixture
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_manager_agent_authorization as authorization_module
from scylla_vms.ansible.deploy_manager_agent_authorization import (
    ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_PROOF_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_AGENT_PACKAGE_PROVENANCE_SCHEMA_VERSION,
    DeployManagerAgentApprovalMethod,
    DeployManagerAgentAuthorizationArtifactState,
    DeployManagerAgentAuthorizationProof,
    DeployManagerAgentAuthorizationStore,
    DeployManagerAgentServicePolicy,
    _derive_authorization_scopes,
    _derive_package_provenance,
    _load_authorization_context,
    authorize_deploy_manager_agent,
    deploy_manager_agent_authorization_id_from_filename,
    deploy_manager_agent_authorization_path,
)
from scylla_vms.ansible.deploy_monitoring_stack_reconciliation import (
    deploy_post_monitoring_stack_reconciliation_path,
)
from scylla_vms.ansible.manager_agent import (
    MANAGER_PACKAGE_VERSION,
    MANAGER_PACKAGES,
    MANAGER_RELEASE_LINE,
    MANAGER_REPOSITORY_URI,
)
from scylla_vms.desired import HostRole
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import serialize_json

_PRIVATE_PATH = "/private/operator/manager-agent-authorization.json"
_SECRET = "obviously-fake-manager-agent-authorization-secret"
_PROMPT = "APPROVE Manager token fake-token at 10.0.0.11?"


def _proof(
    method: DeployManagerAgentApprovalMethod = (
        DeployManagerAgentApprovalMethod.INTERACTIVE
    ),
) -> DeployManagerAgentAuthorizationProof:
    return DeployManagerAgentAuthorizationProof(
        approval_method=method,
        approved=True,
    )


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, runner = monitoring_fixture._complete(tmp_path, monkeypatch)
    monitoring_fixture._call(prepared)
    return prepared, runner


def _call(prepared, proof: DeployManagerAgentAuthorizationProof):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return authorize_deploy_manager_agent(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=proof,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployManagerAgentAuthorizationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


@pytest.mark.parametrize(
    "method",
    (
        DeployManagerAgentApprovalMethod.INTERACTIVE,
        DeployManagerAgentApprovalMethod.CLI_YES,
    ),
)
def test_exact_complete_scope_is_immutable_redacted_and_process_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: DeployManagerAgentApprovalMethod,
) -> None:
    signature = inspect.signature(authorize_deploy_manager_agent)
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
        "version",
        "package",
        "repository",
        "key",
        "token",
        "config",
        "server",
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
    path = deploy_manager_agent_authorization_path(prepared.paths, OPERATION_ID)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    prior_paths = tuple(
        item for item in prepared.paths.operations.iterdir() if item.is_file()
    )
    prior_bytes = {item: item.read_bytes() for item in prior_paths}
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = _load_authorization_context(prepared.paths, OPERATION_ID, lock=lock)
        expected_ids = next(
            step.target_ids
            for step in context.post_monitoring.record.steps
            if step.mapping_sequence == 16
        )

    report = _call(prepared, _proof(method))
    first_bytes = path.read_bytes()
    reused = _call(prepared, _proof(method))
    stored = _record(prepared)

    assert report.artifact_state is DeployManagerAgentAuthorizationArtifactState.CREATED
    assert reused.artifact_state is DeployManagerAgentAuthorizationArtifactState.REUSED
    assert path.read_bytes() == first_bytes
    assert path.stat().st_mode & 0o777 == 0o600
    assert journal_path.read_bytes() == prior_bytes[journal_path]
    assert {item: item.read_bytes() for item in prior_paths} == prior_bytes
    assert len(runner.specs) == process_count
    assert report.schema_version == (
        ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )
    assert report.authorization_schema_version == (
        ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_SCHEMA_VERSION
    )
    assert report.proof_schema_version == (
        ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    assert report.approval_method is method
    assert report.classification is OperationClassification.MUTATING
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert report.playbook == "manager-agent"
    assert report.target_stable_ids == expected_ids
    assert report.target_count == len(expected_ids)
    assert report.release_line == MANAGER_RELEASE_LINE == "3.12"
    assert report.package_count == len(MANAGER_PACKAGES)
    assert report.service_policy is DeployManagerAgentServicePolicy.DISABLED_INACTIVE
    assert report.prohibited_action_count == 0
    assert not report.consumed
    assert report.execution_state == "unavailable"

    record = stored.record
    assert record.authorization_state == "authorized-pre-execution"
    assert not record.consumed
    assert record.execution_state == "unavailable"
    assert record.target_stable_ids == expected_ids
    assert record.target_count == len(record.scopes) == len(expected_ids)
    assert record.package_provenance.schema_version == (
        ANSIBLE_DEPLOY_MANAGER_AGENT_PACKAGE_PROVENANCE_SCHEMA_VERSION
    )
    for index, scope in enumerate(record.scopes, start=1):
        assert scope.scope_index == index
        assert scope.mapping_sequence == 16
        assert scope.playbook == "manager-agent"
        assert scope.target_role == "scylla"
        assert scope.target_stable_id == expected_ids[index - 1]
        assert scope.service_policy is DeployManagerAgentServicePolicy.DISABLED_INACTIVE
        assert not any(
            (
                scope.configuration_permitted,
                scope.auth_token_permitted,
                scope.helper_slice_permitted,
                scope.server_reachability_performed,
                scope.service_start_permitted,
            )
        )

    persisted = json.loads(first_bytes)
    assert first_bytes == serialize_json(persisted)
    public = first_bytes.decode() + json.dumps(report.to_object(), sort_keys=True)
    for protected in (
        _PRIVATE_PATH,
        _SECRET,
        _PROMPT,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        MANAGER_REPOSITORY_URI,
        MANAGER_PACKAGE_VERSION,
        "fake-token",
        "ansible-playbook",
        "--limit",
        '"variables"',
        '"commands"',
        "password",
    ):
        assert protected not in public
    assert (
        deploy_manager_agent_authorization_id_from_filename(path.name) == OPERATION_ID
    )
    assert (
        deploy_manager_agent_authorization_id_from_filename(f"uppercase-{path.name}")
        is None
    )
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


def test_refuses_missing_denied_destructive_and_narrow_proofs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases = (
        (DeployManagerAgentAuthorizationProof(), "approval is required"),
        (
            DeployManagerAgentAuthorizationProof(
                approval_method=DeployManagerAgentApprovalMethod.INTERACTIVE,
                approved=False,
            ),
            "approval was denied",
        ),
        (
            DeployManagerAgentAuthorizationProof(
                approval_method=DeployManagerAgentApprovalMethod.CLI_YES,
                approved=True,
                allow_destructive=True,
            ),
            "destructive and narrow proofs are inapplicable",
        ),
        (
            DeployManagerAgentAuthorizationProof(
                approval_method=DeployManagerAgentApprovalMethod.INTERACTIVE,
                approved=True,
                destructive_scope_provided=True,
            ),
            "destructive and narrow proofs are inapplicable",
        ),
        (
            DeployManagerAgentAuthorizationProof(
                approval_method=DeployManagerAgentApprovalMethod.INTERACTIVE,
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
    assert len(runner.specs) == process_count
    assert not deploy_manager_agent_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_refuses_wrong_role_incomplete_scope_install_gate_and_payload_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = _load_authorization_context(prepared.paths, OPERATION_ID, lock=lock)
        package = _derive_package_provenance()
        loaded = authorization_module._loaded(
            context.monitoring.monitoring.manager.manager.chain.authorization_context
        )
        scylla = next(
            host
            for host in loaded.planning.base.deploy.inventory.record.inventory.hosts
            if host.role is HostRole.SCYLLA
        )
        object.__setattr__(scylla, "role", HostRole.MANAGER)
        with pytest.raises(StateConflictError, match="complete current Scylla"):
            _derive_authorization_scopes(context, package)
        object.__setattr__(scylla, "role", HostRole.SCYLLA)

        mapped = next(
            step
            for step in context.post_monitoring.record.steps
            if step.mapping_sequence == 16
        )
        original_targets = mapped.target_ids
        object.__setattr__(mapped, "target_ids", original_targets[:-1])
        with pytest.raises(StateConflictError, match="exact active mapped"):
            _derive_authorization_scopes(context, package)
        object.__setattr__(mapped, "target_ids", original_targets)

        install_entry = context.install.evidence.record.entries[0]
        object.__setattr__(install_entry, "service_inactive", False)
        with pytest.raises(StateConflictError, match="Scylla-install gate"):
            _derive_authorization_scopes(context, package)
        object.__setattr__(install_entry, "service_inactive", True)

        original_builder = authorization_module.build_manager_agent_payload

        def tampered_builder(*args, **kwargs):
            payload = original_builder(*args, **kwargs)
            payload["auth_token_configured"] = True
            return payload

        monkeypatch.setattr(
            authorization_module,
            "build_manager_agent_payload",
            tampered_builder,
        )
        with pytest.raises(StateConflictError, match="install-only policy"):
            _derive_authorization_scopes(context, package)
    assert len(runner.specs) == process_count


def test_refuses_missing_reconciliation_drift_later_state_and_changed_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    post_path = deploy_post_monitoring_stack_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    post_bytes = post_path.read_bytes()
    post_path.unlink()
    with pytest.raises(StateConflictError, match="requires post-monitoring-stack"):
        _call(prepared, _proof())
    post_path.write_bytes(post_bytes)
    post_path.chmod(0o600)

    inventory_path = prepared.paths.ansible_inventory
    inventory_bytes = inventory_path.read_bytes()
    with inventory_path.open("a", encoding="utf-8") as stream:
        stream.write(" ")
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, _proof())
    inventory_path.write_bytes(inventory_bytes)
    inventory_path.chmod(0o600)

    later = (
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-monitoring-agent-authorization.json"
    )
    later.write_text("{}\n", encoding="utf-8")
    later.chmod(0o600)
    with pytest.raises(StateConflictError, match="later-stage history"):
        _call(prepared, _proof())
    later.unlink()

    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        authorize_deploy_manager_agent(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            proof=_proof(),
        )

    _call(prepared, _proof())
    with pytest.raises(StateConflictError, match="changed"):
        _call(
            prepared,
            _proof(DeployManagerAgentApprovalMethod.CLI_YES),
        )
    assert len(runner.specs) == process_count


def test_refuses_source_drift_execution_prefix_and_store_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    monkeypatch.setattr(
        authorization_module,
        "_playbook_source_digest",
        lambda *_args: "sha256:" + "a" * 64,
    )
    with pytest.raises(
        StateConflictError, match=r"source|configure gate|exact active mapped"
    ):
        _call(prepared, _proof())
    monkeypatch.undo()

    execution = (
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-manager-agent-execution.json"
    )
    execution.write_text("{}\n", encoding="utf-8")
    execution.chmod(0o600)
    with pytest.raises(StateConflictError, match="later-stage history"):
        _call(prepared, _proof())
    execution.unlink()

    _call(prepared, _proof())
    path = deploy_manager_agent_authorization_path(prepared.paths, OPERATION_ID)
    original = path.read_bytes()
    document = cast(dict[str, object], json.loads(original))
    document["target_count"] = cast(int, document["target_count"]) + 1
    path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(StatePersistenceError):
        _record(prepared)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0

    path.write_bytes(original)
    path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0
    target = path.with_name(f"{path.name}.target")
    path.rename(target)
    path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _record(prepared)
