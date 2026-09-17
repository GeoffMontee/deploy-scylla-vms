import inspect
import json
from pathlib import Path
from typing import cast

import pytest
import test_ansible_deploy_manager_server_reconciliation as manager_fixture
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_monitoring_stack_authorization as authorization_module
from scylla_vms.ansible.deploy_manager_server_reconciliation import (
    deploy_post_manager_server_reconciliation_path,
)
from scylla_vms.ansible.deploy_monitoring_stack_authorization import (
    ANSIBLE_DEPLOY_MONITORING_STACK_ARCHIVE_PROVENANCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_PROOF_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_SCHEMA_VERSION,
    DeployMonitoringStackApprovalMethod,
    DeployMonitoringStackArchitecture,
    DeployMonitoringStackAuthorizationArtifactState,
    DeployMonitoringStackAuthorizationProof,
    DeployMonitoringStackAuthorizationStore,
    DeployMonitoringStackInstallPolicy,
    DeployMonitoringStackListenPolicy,
    DeployMonitoringStackServicePolicy,
    _derive_archive_provenance,
    _derive_authorization_scope,
    _load_authorization_context,
    authorize_deploy_monitoring_stack,
    deploy_monitoring_stack_authorization_id_from_filename,
    deploy_monitoring_stack_authorization_path,
)
from scylla_vms.ansible.monitoring_stack import (
    ARTIFACT_URI,
    CACHE_PATH,
    INSTALL_ROOT,
    SOURCE_COMMIT,
    STACK_ARTIFACTS,
    STACK_RELEASE_LINE,
    STACK_VERSION,
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

_PRIVATE_PATH = "/private/operator/monitoring-stack-authorization.json"
_SECRET = "obviously-fake-monitoring-stack-authorization-secret"
_PROMPT = "APPROVE archive for monitoring-1 at 10.0.0.40?"


def _proof(
    method: DeployMonitoringStackApprovalMethod = (
        DeployMonitoringStackApprovalMethod.INTERACTIVE
    ),
) -> DeployMonitoringStackAuthorizationProof:
    return DeployMonitoringStackAuthorizationProof(
        approval_method=method,
        approved=True,
    )


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, runner = manager_fixture._complete(tmp_path, monkeypatch)
    manager_fixture._call(prepared)
    return prepared, runner


def _call(prepared, proof: DeployMonitoringStackAuthorizationProof):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return authorize_deploy_monitoring_stack(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=proof,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployMonitoringStackAuthorizationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


@pytest.mark.parametrize(
    "method",
    (
        DeployMonitoringStackApprovalMethod.INTERACTIVE,
        DeployMonitoringStackApprovalMethod.CLI_YES,
    ),
)
def test_exact_monitoring_scope_is_immutable_redacted_and_process_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: DeployMonitoringStackApprovalMethod,
) -> None:
    signature = inspect.signature(authorize_deploy_monitoring_stack)
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
        "version",
        "archive",
        "component",
        "auth",
        "bind",
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
    path = deploy_monitoring_stack_authorization_path(prepared.paths, OPERATION_ID)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    prior_paths = tuple(
        item for item in prepared.paths.operations.iterdir() if item.is_file()
    )
    prior_bytes = {item: item.read_bytes() for item in prior_paths}

    report = _call(prepared, _proof(method))
    first_bytes = path.read_bytes()
    reused = _call(prepared, _proof(method))
    stored = _record(prepared)

    assert (
        report.artifact_state is DeployMonitoringStackAuthorizationArtifactState.CREATED
    )
    assert (
        reused.artifact_state is DeployMonitoringStackAuthorizationArtifactState.REUSED
    )
    assert path.read_bytes() == first_bytes
    assert path.stat().st_mode & 0o777 == 0o600
    assert journal_path.read_bytes() == prior_bytes[journal_path]
    assert {item: item.read_bytes() for item in prior_paths} == prior_bytes
    assert len(runner.specs) == process_count
    assert report.schema_version == (
        ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )
    assert report.authorization_schema_version == (
        ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_SCHEMA_VERSION
    )
    assert report.proof_schema_version == (
        ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    assert report.approval_method is method
    assert report.classification is OperationClassification.MUTATING
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert report.target_stable_id == "monitoring-1"
    assert report.target_count == 1
    assert report.release_line == STACK_RELEASE_LINE == "4.16"
    assert report.component_count == len(STACK_ARTIFACTS)
    assert report.architecture is DeployMonitoringStackArchitecture.AMD64
    assert report.install_policy is DeployMonitoringStackInstallPolicy.ARCHIVE_ONLY
    assert report.service_policy is DeployMonitoringStackServicePolicy.DISABLED_INACTIVE
    assert report.listen_policy is DeployMonitoringStackListenPolicy.NOT_STARTED
    assert report.prohibited_action_count == 0
    assert not report.consumed
    assert report.execution_state == "unavailable"

    record = stored.record
    assert record.authorization_state == "authorized-pre-execution"
    assert not record.consumed
    assert record.execution_state == "unavailable"
    assert record.scope.mapping_sequence == 15
    assert record.scope.playbook == "monitoring-stack"
    assert record.scope.target_role == "monitoring"
    assert record.scope.target_stable_id == "monitoring-1"
    assert record.archive_provenance.schema_version == (
        ANSIBLE_DEPLOY_MONITORING_STACK_ARCHIVE_PROVENANCE_SCHEMA_VERSION
    )
    assert (
        record.scope.archive_provenance_digest
        == record.archive_provenance.provenance_digest
    )
    assert not any(
        (
            record.scope.docker_install_permitted,
            record.scope.image_pull_permitted,
            record.scope.compose_permitted,
            record.scope.auth_permitted,
            record.scope.targets_permitted,
            record.scope.containers_permitted,
            record.scope.service_start_permitted,
            record.scope.public_bind_permitted,
            record.scope.manager_registration_permitted,
            record.scope.scylla_start_permitted,
            record.scope.secrets_permitted,
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
        ARTIFACT_URI,
        CACHE_PATH,
        INSTALL_ROOT,
        SOURCE_COMMIT,
        STACK_VERSION,
        "ansible-playbook",
        "--limit",
        '"variables"',
        '"commands"',
        "grafana_admin",
        "password",
    ):
        assert protected not in public
    assert deploy_monitoring_stack_authorization_id_from_filename(path.name) == (
        OPERATION_ID
    )
    assert (
        deploy_monitoring_stack_authorization_id_from_filename(f"uppercase-{path.name}")
        is None
    )
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


def test_refuses_missing_denied_destructive_and_narrow_proofs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases = (
        (DeployMonitoringStackAuthorizationProof(), "approval is required"),
        (
            DeployMonitoringStackAuthorizationProof(
                approval_method=DeployMonitoringStackApprovalMethod.INTERACTIVE,
                approved=False,
            ),
            "approval was denied",
        ),
        (
            DeployMonitoringStackAuthorizationProof(
                approval_method=DeployMonitoringStackApprovalMethod.CLI_YES,
                approved=True,
                allow_destructive=True,
            ),
            "destructive and narrow proofs are inapplicable",
        ),
        (
            DeployMonitoringStackAuthorizationProof(
                approval_method=DeployMonitoringStackApprovalMethod.INTERACTIVE,
                approved=True,
                destructive_scope_provided=True,
            ),
            "destructive and narrow proofs are inapplicable",
        ),
        (
            DeployMonitoringStackAuthorizationProof(
                approval_method=DeployMonitoringStackApprovalMethod.INTERACTIVE,
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
    assert not deploy_monitoring_stack_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_refuses_wrong_role_base_os_gate_and_archive_policy_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = _load_authorization_context(prepared.paths, OPERATION_ID, lock=lock)
        archive = _derive_archive_provenance()
        loaded = authorization_module._loaded(
            context.manager.manager.chain.authorization_context
        )
        monitoring = next(
            host
            for host in loaded.planning.base.deploy.inventory.record.inventory.hosts
            if host.logical_id == "monitoring-1"
        )
        object.__setattr__(monitoring, "role", HostRole.MANAGER)
        with pytest.raises(StateConflictError, match="monitoring identity"):
            _derive_authorization_scope(context, archive)
        object.__setattr__(monitoring, "role", HostRole.MONITORING)

        base_host = next(
            host
            for entry in context.manager.manager.base_os.record.entries
            for host in entry.hosts
            if host.logical_id == "monitoring-1"
        )
        object.__setattr__(base_host, "reboot_required", True)
        with pytest.raises(StateConflictError, match="base-os gate"):
            _derive_authorization_scope(context, archive)
        object.__setattr__(base_host, "reboot_required", False)

        original_builder = authorization_module.build_monitoring_stack_payload

        def tampered_builder(*args, **kwargs):
            payload = original_builder(*args, **kwargs)
            payload["public_bind"] = True
            return payload

        monkeypatch.setattr(
            authorization_module,
            "build_monitoring_stack_payload",
            tampered_builder,
        )
        with pytest.raises(StateConflictError, match="no-public-bind policy"):
            _derive_authorization_scope(context, archive)
    assert len(runner.specs) == process_count


def test_refuses_missing_reconciliation_drift_later_state_and_changed_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    post_path = deploy_post_manager_server_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    post_bytes = post_path.read_bytes()
    post_path.unlink()
    with pytest.raises(StateConflictError, match="requires post-manager-server"):
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
        / f"{OPERATION_ID}.ansible-deploy-manager-agent-authorization.json"
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
        authorize_deploy_monitoring_stack(
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
            _proof(DeployMonitoringStackApprovalMethod.CLI_YES),
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
    with pytest.raises(StateConflictError, match="exact active mapped"):
        _call(prepared, _proof())
    monkeypatch.undo()

    execution = (
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-monitoring-stack-execution.json"
    )
    execution.write_text("{}\n", encoding="utf-8")
    execution.chmod(0o600)
    with pytest.raises(StateConflictError, match="later-stage history"):
        _call(prepared, _proof())
    execution.unlink()

    _call(prepared, _proof())
    path = deploy_monitoring_stack_authorization_path(prepared.paths, OPERATION_ID)
    original = path.read_bytes()
    document = cast(dict[str, object], json.loads(original))
    document["target_count"] = 2
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
