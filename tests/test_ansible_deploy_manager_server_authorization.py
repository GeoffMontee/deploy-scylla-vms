import inspect
import json
from pathlib import Path
from typing import cast

import pytest
import test_ansible_deploy_scylla_health_checkpoint as health_fixture
import test_ansible_deploy_scylla_post_bootstrap_reconciliation as bridge_fixture
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_manager_server_authorization as authorization_module
from scylla_vms.ansible.deploy_manager_server_authorization import (
    ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_PROOF_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_SCHEMA_VERSION,
    DeployManagerServerApprovalMethod,
    DeployManagerServerArchitecture,
    DeployManagerServerAuthorizationArtifactState,
    DeployManagerServerAuthorizationProof,
    DeployManagerServerAuthorizationStore,
    DeployManagerServerBackendPolicy,
    DeployManagerServerServicePolicy,
    _derive_authorization_scope,
    _derive_package_provenance,
    _load_authorization_context,
    authorize_deploy_manager_server,
    deploy_manager_server_authorization_id_from_filename,
    deploy_manager_server_authorization_path,
)
from scylla_vms.ansible.manager_server import (
    MANAGER_PACKAGE_VERSION,
    MANAGER_PACKAGES,
    MANAGER_RELEASE_LINE,
    MANAGER_REPOSITORY_URI,
)
from scylla_vms.ansible.scylla_install import SCYLLA_SIGNING_KEY_FINGERPRINT
from scylla_vms.desired import HostRole
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import serialize_json

_PRIVATE_PATH = "/private/operator/manager-server-authorization.json"
_SECRET = "obviously-fake-manager-server-authorization-secret"
_PROMPT = "APPROVE Manager 3.12 for 10.0.0.30 with key material?"


def _proof(
    method: DeployManagerServerApprovalMethod = (
        DeployManagerServerApprovalMethod.INTERACTIVE
    ),
) -> DeployManagerServerAuthorizationProof:
    return DeployManagerServerAuthorizationProof(
        approval_method=method,
        approved=True,
    )


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, executables, toolchain = health_fixture._prepared(tmp_path, monkeypatch)
    runner = health_fixture.HealthCheckpointRunner()
    health_fixture._call(prepared, runner, executables, toolchain)
    bridge_fixture._call(prepared)
    return prepared, runner


def _call(prepared, proof: DeployManagerServerAuthorizationProof):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return authorize_deploy_manager_server(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=proof,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployManagerServerAuthorizationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


@pytest.mark.parametrize(
    "method",
    (
        DeployManagerServerApprovalMethod.INTERACTIVE,
        DeployManagerServerApprovalMethod.CLI_YES,
    ),
)
def test_exact_manager_scope_is_immutable_redacted_and_process_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: DeployManagerServerApprovalMethod,
) -> None:
    signature = inspect.signature(authorize_deploy_manager_server)
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
        "config",
        "backend",
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
    path = deploy_manager_server_authorization_path(prepared.paths, OPERATION_ID)
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
        report.artifact_state is DeployManagerServerAuthorizationArtifactState.CREATED
    )
    assert reused.artifact_state is DeployManagerServerAuthorizationArtifactState.REUSED
    assert path.read_bytes() == first_bytes
    assert path.stat().st_mode & 0o777 == 0o600
    assert journal_path.read_bytes() == prior_bytes[journal_path]
    assert {item: item.read_bytes() for item in prior_paths} == prior_bytes
    assert len(runner.specs) == process_count
    assert report.schema_version == (
        ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )
    assert report.authorization_schema_version == (
        ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_SCHEMA_VERSION
    )
    assert report.proof_schema_version == (
        ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    assert report.approval_method is method
    assert report.classification is OperationClassification.MUTATING
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert report.target_stable_id == "manager-1"
    assert report.target_count == 1
    assert report.release_line == MANAGER_RELEASE_LINE == "3.12"
    assert report.package_count == len(MANAGER_PACKAGES)
    assert report.architecture is DeployManagerServerArchitecture.AMD64
    assert report.service_policy is DeployManagerServerServicePolicy.MASKED_INACTIVE
    assert report.backend_policy is DeployManagerServerBackendPolicy.UNCONFIGURED
    assert not report.service_start_permitted
    assert not report.registration_permitted
    assert not report.setup_permitted
    assert not report.consumed
    assert report.execution_state == "unavailable"

    record = stored.record
    assert record.authorization_state == "authorized-pre-execution"
    assert not record.consumed
    assert record.execution_state == "unavailable"
    assert record.scope.mapping_sequence == 14
    assert record.scope.playbook == "manager-server"
    assert record.scope.target_role == "manager"
    assert record.scope.target_stable_id == "manager-1"
    assert (
        record.scope.package_provenance_digest
        == record.package_provenance.provenance_digest
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
        SCYLLA_SIGNING_KEY_FINGERPRINT,
        MANAGER_PACKAGE_VERSION,
        "BEGIN PGP",
        "ansible-playbook",
        "--limit",
        '"variables"',
        '"commands"',
        '"backend_configured"',
    ):
        assert protected not in public
    assert deploy_manager_server_authorization_id_from_filename(path.name) == (
        OPERATION_ID
    )
    assert (
        deploy_manager_server_authorization_id_from_filename(f"uppercase-{path.name}")
        is None
    )
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


def test_refuses_missing_denied_destructive_and_narrow_proofs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases = (
        (DeployManagerServerAuthorizationProof(), "approval is required"),
        (
            DeployManagerServerAuthorizationProof(
                approval_method=DeployManagerServerApprovalMethod.INTERACTIVE,
                approved=False,
            ),
            "approval was denied",
        ),
        (
            DeployManagerServerAuthorizationProof(
                approval_method=DeployManagerServerApprovalMethod.CLI_YES,
                approved=True,
                allow_destructive=True,
            ),
            "destructive and narrow proofs are inapplicable",
        ),
        (
            DeployManagerServerAuthorizationProof(
                approval_method=DeployManagerServerApprovalMethod.INTERACTIVE,
                approved=True,
                destructive_scope_provided=True,
            ),
            "destructive and narrow proofs are inapplicable",
        ),
        (
            DeployManagerServerAuthorizationProof(
                approval_method=DeployManagerServerApprovalMethod.INTERACTIVE,
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
    assert not deploy_manager_server_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_refuses_wrong_role_base_os_gate_and_packaged_key_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = _load_authorization_context(prepared.paths, OPERATION_ID, lock=lock)
        package = _derive_package_provenance()
        loaded = authorization_module._loaded(context.chain.authorization_context)
        manager = next(
            host
            for host in loaded.planning.base.deploy.inventory.record.inventory.hosts
            if host.logical_id == "manager-1"
        )
        object.__setattr__(manager, "role", HostRole.MONITORING)
        with pytest.raises(StateConflictError, match="manager identity"):
            _derive_authorization_scope(context, package)
        object.__setattr__(manager, "role", HostRole.MANAGER)

        base_host = next(
            host
            for entry in context.base_os.record.entries
            for host in entry.hosts
            if host.logical_id == "manager-1"
        )
        object.__setattr__(base_host, "reboot_required", True)
        with pytest.raises(StateConflictError, match="base-os gate"):
            _derive_authorization_scope(context, package)
        object.__setattr__(base_host, "reboot_required", False)

    monkeypatch.setattr(
        authorization_module,
        "load_scylla_signing_key",
        lambda: f"{_SECRET} {_PRIVATE_PATH}".encode(),
    )
    with pytest.raises(AnsibleError, match="digest conflicts"):
        _call(prepared, _proof())
    assert len(runner.specs) == process_count


def test_refuses_missing_bridge_drift_later_state_wrong_lock_and_changed_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    bridge_path = (
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-scylla-post-bootstrap-reconciliation.json"
    )
    bridge_bytes = bridge_path.read_bytes()
    bridge_path.unlink()
    with pytest.raises(StateConflictError, match="requires the post-bootstrap bridge"):
        _call(prepared, _proof())
    bridge_path.write_bytes(bridge_bytes)
    bridge_path.chmod(0o600)

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
        / f"{OPERATION_ID}.ansible-deploy-manager-server-execution.json"
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
        authorize_deploy_manager_server(
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
            _proof(DeployManagerServerApprovalMethod.CLI_YES),
        )
    assert len(runner.specs) == process_count


def test_store_rejects_tamper_symlink_and_show_validates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    _call(prepared, _proof())
    path = deploy_manager_server_authorization_path(prepared.paths, OPERATION_ID)
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
