import inspect

import pytest
from test_ansible_deploy_manager_backend_storage_preflight_execution import (
    ManagerBackendStoragePreflightRunner,
)
from test_ansible_deploy_manager_backend_storage_preflight_execution import (
    _call as _execute_preflight,
)
from test_ansible_deploy_manager_backend_storage_preflight_reconciliation import (
    _call as _reconcile_preflight,
)
from test_ansible_deploy_manager_backend_storage_preflight_reconciliation import (
    _record as _preflight_record,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_manager_backend_storage_prepare_authorization import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_AUTHORIZATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION,
    DeployManagerBackendStoragePrepareApprovalMethod,
    DeployManagerBackendStoragePrepareAuthorizationArtifactState,
    DeployManagerBackendStoragePrepareAuthorizationStore,
    DeployManagerBackendStoragePrepareDestructiveScopeProof,
    DeployManagerBackendStoragePrepareGeneralAuthorizationProof,
    DeployManagerBackendStoragePrepareWipeAuthorizationProof,
    authorize_deploy_manager_backend_storage_prepare,
    deploy_manager_backend_storage_prepare_authorization_id_from_filename,
    deploy_manager_backend_storage_prepare_authorization_path,
)
from scylla_vms.errors import StateConflictError, StateLockError
from scylla_vms.locking import ClusterLock

pytest_plugins = (
    "test_ansible_deploy_manager_backend_storage_preflight_reconciliation",
)

_DIGEST = "sha256:" + ("0" * 64)


def test_proof_models_and_filename_identity_are_strict() -> None:
    scope = DeployManagerBackendStoragePrepareDestructiveScopeProof(1, _DIGEST, _DIGEST)
    general = DeployManagerBackendStoragePrepareGeneralAuthorizationProof(
        approval_method=(DeployManagerBackendStoragePrepareApprovalMethod.INTERACTIVE),
        approved=True,
        allow_destructive=True,
        destructive_scope=scope,
    )
    wipe = DeployManagerBackendStoragePrepareWipeAuthorizationProof(
        True, 1, _DIGEST, _DIGEST
    )
    assert general.destructive_scope is scope
    assert wipe.consented
    name = (
        f"{OPERATION_ID}"
        ".ansible-deploy-manager-backend-storage-prepare-authorization.json"
    )
    assert (
        deploy_manager_backend_storage_prepare_authorization_id_from_filename(name)
        == OPERATION_ID
    )
    assert (
        deploy_manager_backend_storage_prepare_authorization_id_from_filename(
            "not-a-uuid"
            ".ansible-deploy-manager-backend-storage-prepare-authorization.json"
        )
        is None
    )
    with pytest.raises(StateConflictError):
        DeployManagerBackendStoragePrepareDestructiveScopeProof(0, _DIGEST, _DIGEST)


def _prepare(ready_preflight_execution):
    prepared, executables, toolchain = ready_preflight_execution
    _execute_preflight(
        prepared,
        ManagerBackendStoragePreflightRunner(),
        executables,
        toolchain,
    )
    _reconcile_preflight(prepared)
    return prepared


def _proof(prepared, method):
    reconciliation = _preflight_record(prepared)
    return DeployManagerBackendStoragePrepareGeneralAuthorizationProof(
        approval_method=method,
        approved=True,
        allow_destructive=True,
        destructive_scope=(
            DeployManagerBackendStoragePrepareDestructiveScopeProof.from_reconciliation(
                reconciliation
            )
        ),
    )


def _call(prepared, proof, wipe_proof=None):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return authorize_deploy_manager_backend_storage_prepare(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            general_proof=proof,
            wipe_proof=wipe_proof,
        )


@pytest.mark.parametrize(
    "method",
    (
        DeployManagerBackendStoragePrepareApprovalMethod.INTERACTIVE,
        DeployManagerBackendStoragePrepareApprovalMethod.CLI_YES,
    ),
)
def test_authorizes_exact_scope_reuses_and_show_validates(
    ready_preflight_execution,
    method,
) -> None:
    signature = inspect.signature(authorize_deploy_manager_backend_storage_prepare)
    assert tuple(signature.parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "general_proof",
        "wipe_proof",
    )
    prepared = _prepare(ready_preflight_execution)
    proof = _proof(prepared, method)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_bytes = journal_path.read_bytes()

    report = _call(prepared, proof)
    path = deploy_manager_backend_storage_prepare_authorization_path(
        prepared.paths, OPERATION_ID
    )
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        stored = DeployManagerBackendStoragePrepareAuthorizationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    assert (
        report.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )
    assert (
        stored.record.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION
    )
    assert (
        report.artifact_state
        is DeployManagerBackendStoragePrepareAuthorizationArtifactState.CREATED
    )
    assert report.approval_method is method
    assert report.target_count == 1
    assert not report.wipe_required
    assert report.wipe_proof_state == "not-required"
    assert stored.record.authorization_consumption_state == "unconsumed"
    assert stored.record.execution_state == "unavailable"
    assert path.stat().st_mode & 0o777 == 0o600
    assert journal_path.read_bytes() == journal_bytes

    encoded = path.read_text(encoding="utf-8").lower()
    for protected in (
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "/dev/",
        "serial",
        "command",
        "variable",
        "environment",
        "credential",
        "password",
    ):
        assert protected not in encoded

    before = path.read_bytes()
    mtime = path.stat().st_mtime_ns
    reused = _call(prepared, proof)
    assert (
        reused.artifact_state
        is DeployManagerBackendStoragePrepareAuthorizationArtifactState.REUSED
    )
    assert path.read_bytes() == before
    assert path.stat().st_mtime_ns == mtime
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


@pytest.mark.parametrize(
    "proof",
    (
        DeployManagerBackendStoragePrepareGeneralAuthorizationProof(),
        DeployManagerBackendStoragePrepareGeneralAuthorizationProof(
            approval_method=(
                DeployManagerBackendStoragePrepareApprovalMethod.INTERACTIVE
            ),
            approved=False,
            allow_destructive=True,
        ),
        DeployManagerBackendStoragePrepareGeneralAuthorizationProof(
            approval_method=(
                DeployManagerBackendStoragePrepareApprovalMethod.INTERACTIVE
            ),
            approved=True,
            allow_destructive=False,
        ),
    ),
)
def test_refuses_missing_or_denied_general_proof(
    ready_preflight_execution,
    proof,
) -> None:
    prepared = _prepare(ready_preflight_execution)
    with pytest.raises(StateConflictError):
        _call(prepared, proof)


def test_refuses_mismatched_scope_and_overbroad_wipe_proof(
    ready_preflight_execution,
) -> None:
    prepared = _prepare(ready_preflight_execution)
    reconciliation = _preflight_record(prepared)
    proof = _proof(
        prepared,
        DeployManagerBackendStoragePrepareApprovalMethod.INTERACTIVE,
    )
    mismatched = DeployManagerBackendStoragePrepareGeneralAuthorizationProof(
        approval_method=(DeployManagerBackendStoragePrepareApprovalMethod.INTERACTIVE),
        approved=True,
        allow_destructive=True,
        destructive_scope=DeployManagerBackendStoragePrepareDestructiveScopeProof(
            1,
            reconciliation.record.preparation_target_set_digest,
            reconciliation.record.wipe_scope_digest,
        ),
    )
    with pytest.raises(StateConflictError):
        _call(prepared, mismatched)

    wipe = DeployManagerBackendStoragePrepareWipeAuthorizationProof(
        True,
        1,
        reconciliation.record.preparation_target_set_digest,
        reconciliation.record.preparation_scope_digest,
    )
    with pytest.raises(StateConflictError, match="over-broad"):
        _call(prepared, proof, wipe)


def test_requires_matching_held_deploy_lock(ready_preflight_execution) -> None:
    prepared = _prepare(ready_preflight_execution)
    proof = _proof(
        prepared,
        DeployManagerBackendStoragePrepareApprovalMethod.INTERACTIVE,
    )
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        authorize_deploy_manager_backend_storage_prepare(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            general_proof=proof,
        )
