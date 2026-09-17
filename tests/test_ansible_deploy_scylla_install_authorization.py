import inspect
import json
from pathlib import Path

import pytest
from test_ansible_deploy_storage_postcheck import (
    StoragePostcheckRunner,
    _execute,
    _prepared_postcheck,
    _reconcile,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_scylla_install_authorization as authorization_module
from scylla_vms.ansible.deploy_scylla_install_authorization import (
    ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_SCHEMA_VERSION,
    DeployScyllaInstallApprovalMethod,
    DeployScyllaInstallAuthorizationArtifactState,
    DeployScyllaInstallAuthorizationProof,
    DeployScyllaInstallAuthorizationStore,
    authorize_deploy_scylla_install,
    deploy_scylla_install_authorization_path,
)
from scylla_vms.ansible.deploy_storage_postcheck import (
    deploy_post_storage_postcheck_reconciliation_path,
)
from scylla_vms.ansible.scylla_install import (
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_PACKAGES,
    SCYLLA_RELEASE_LINE,
    SCYLLA_REPOSITORY_DEFINITION_DIGEST,
    SCYLLA_SIGNING_KEY_DIGEST,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
)
from scylla_vms.ansible.storage_preflight import StorageOwnershipStatus
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

_PRIVATE_PATH = "/private/operator/scylla-install-authorization.json"
_SECRET = "obviously-fake-scylla-install-authorization-secret"
_PROMPT = "APPROVE 2026.2 on 10.0.0.20 with key material?"


def _proof(
    method: DeployScyllaInstallApprovalMethod = (
        DeployScyllaInstallApprovalMethod.INTERACTIVE
    ),
) -> DeployScyllaInstallAuthorizationProof:
    return DeployScyllaInstallAuthorizationProof(
        approval_method=method,
        approved=True,
    )


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, executables, toolchain = _prepared_postcheck(
        tmp_path,
        monkeypatch,
        StorageOwnershipStatus.CLEAN_NEW,
    )
    runner = StoragePostcheckRunner()
    _execute(prepared, runner, executables, toolchain)
    _reconcile(prepared)
    return prepared, runner


def _call(prepared, proof: DeployScyllaInstallAuthorizationProof):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return authorize_deploy_scylla_install(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=proof,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployScyllaInstallAuthorizationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


@pytest.mark.parametrize(
    "method",
    (
        DeployScyllaInstallApprovalMethod.INTERACTIVE,
        DeployScyllaInstallApprovalMethod.CLI_YES,
    ),
)
def test_exact_scope_is_immutable_redacted_and_process_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: DeployScyllaInstallApprovalMethod,
) -> None:
    signature = inspect.signature(authorize_deploy_scylla_install)
    assert tuple(signature.parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "proof",
    )
    for forbidden in (
        "target",
        "version",
        "package",
        "repository",
        "key",
        "variable",
        "command",
        "path",
        "scope",
        "prompt",
        "text",
    ):
        assert forbidden not in signature.parameters

    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    reconciliation_path = deploy_post_storage_postcheck_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    immutable = (journal_path.read_bytes(), reconciliation_path.read_bytes())
    show_before = _run_show(prepared.paths)

    report = _call(prepared, _proof(method))
    authorization_path = deploy_scylla_install_authorization_path(
        prepared.paths, OPERATION_ID
    )
    first_bytes = authorization_path.read_bytes()
    reused = _call(prepared, _proof(method))
    stored = _record(prepared)
    show_after = _run_show(prepared.paths)

    assert (
        report.artifact_state is DeployScyllaInstallAuthorizationArtifactState.CREATED
    )
    assert reused.artifact_state is DeployScyllaInstallAuthorizationArtifactState.REUSED
    assert authorization_path.read_bytes() == first_bytes
    assert (journal_path.read_bytes(), reconciliation_path.read_bytes()) == immutable
    assert len(runner.specs) == process_count
    assert authorization_path.stat().st_mode & 0o777 == 0o600
    assert report.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )
    assert report.authorization_schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_SCHEMA_VERSION
    )
    assert report.proof_schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    assert report.approval_method is method
    assert report.classification is OperationClassification.MUTATING
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert not report.consumed
    assert report.execution_state == "unavailable"
    assert report.release_line == SCYLLA_RELEASE_LINE == "2026.2"
    assert report.package_version == SCYLLA_PACKAGE_VERSION
    assert report.package_count == len(SCYLLA_PACKAGES)
    assert report.repository_definition_digest == (SCYLLA_REPOSITORY_DEFINITION_DIGEST)
    assert report.signing_key_artifact_digest == SCYLLA_SIGNING_KEY_DIGEST

    record = stored.record
    assert record.authorization_state == "authorized-pre-execution"
    assert not record.consumed
    assert record.execution_state == "unavailable"
    assert record.stable_id_count == len(record.scopes) == 1
    assert record.scopes[0].target_role == "scylla"
    assert record.scopes[0].target_ids == ("scylla-ad-1-1",)
    assert record.scopes[0].mapping_sequence == 11
    assert record.scopes[0].playbook == "scylla-install"
    assert (
        record.scopes[0].package_provenance_digest
        == record.package_provenance.provenance_digest
    )
    assert record.package_provenance.package_count == len(SCYLLA_PACKAGES)
    assert record.package_provenance.release_line == "2026.2"
    assert record.package_provenance.package_version == SCYLLA_PACKAGE_VERSION

    persisted = json.loads(first_bytes)
    assert stored.artifact_digest
    assert first_bytes == serialize_json(persisted)
    public = first_bytes.decode() + json.dumps(report.to_object(), sort_keys=True)
    for protected in (
        _PRIVATE_PATH,
        _SECRET,
        _PROMPT,
        "10.0.0.",
        "ocid1.",
        SCYLLA_SIGNING_KEY_FINGERPRINT,
        "BEGIN PGP",
        "downloads.scylladb.com",
    ):
        assert protected not in public
    assert show_after == show_before


@pytest.mark.parametrize(
    ("proof", "message"),
    (
        (DeployScyllaInstallAuthorizationProof(), "approval is required"),
        (
            DeployScyllaInstallAuthorizationProof(
                approval_method=DeployScyllaInstallApprovalMethod.INTERACTIVE,
                approved=False,
            ),
            "approval was denied",
        ),
        (
            DeployScyllaInstallAuthorizationProof(
                approval_method=DeployScyllaInstallApprovalMethod.CLI_YES,
                approved=True,
                allow_destructive=True,
            ),
            "destructive and narrow proofs are inapplicable",
        ),
        (
            DeployScyllaInstallAuthorizationProof(
                approval_method=DeployScyllaInstallApprovalMethod.INTERACTIVE,
                approved=True,
                destructive_scope_provided=True,
            ),
            "destructive and narrow proofs are inapplicable",
        ),
        (
            DeployScyllaInstallAuthorizationProof(
                approval_method=DeployScyllaInstallApprovalMethod.INTERACTIVE,
                approved=True,
                narrow_consent_provided=True,
            ),
            "destructive and narrow proofs are inapplicable",
        ),
    ),
)
def test_refuses_missing_denied_destructive_and_narrow_proofs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    proof: DeployScyllaInstallAuthorizationProof,
    message: str,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    with pytest.raises(StateConflictError, match=message):
        _call(prepared, proof)
    assert len(runner.specs) == process_count
    assert not deploy_scylla_install_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_refuses_missing_drifted_or_later_state_and_wrong_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    reconciliation_path = deploy_post_storage_postcheck_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    original = reconciliation_path.read_bytes()
    reconciliation_path.unlink()
    with pytest.raises(StateConflictError, match="requires complete"):
        _call(prepared, _proof())
    reconciliation_path.write_bytes(original)
    reconciliation_path.chmod(0o600)

    later = (
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-scylla-install-execution.json"
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
        authorize_deploy_scylla_install(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            proof=_proof(),
        )

    _call(prepared, _proof())
    path = deploy_scylla_install_authorization_path(prepared.paths, OPERATION_ID)
    value = json.loads(path.read_text(encoding="utf-8"))
    value["stable_id_count"] = 2
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    with pytest.raises(StatePersistenceError):
        _call(prepared, _proof())


def test_refuses_tampered_packaged_key_and_changed_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    monkeypatch.setattr(
        authorization_module,
        "load_scylla_signing_key",
        lambda: f"{_SECRET} {_PRIVATE_PATH}".encode(),
    )
    with pytest.raises(AnsibleError, match="digest conflicts"):
        _call(prepared, _proof())
    monkeypatch.undo()

    _call(prepared, _proof())
    with pytest.raises(StateConflictError, match="changed"):
        _call(
            prepared,
            _proof(DeployScyllaInstallApprovalMethod.CLI_YES),
        )


def test_store_rejects_noncanonical_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    _call(prepared, _proof())
    path = deploy_scylla_install_authorization_path(prepared.paths, OPERATION_ID)
    target = path.with_name(f"{path.name}.target")
    path.rename(target)
    path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _record(prepared)
