import inspect
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_storage_preflight import (
    StoragePreflightRunner,
)
from test_ansible_deploy_storage_preflight import (
    _execute as _execute_preflight,
)
from test_ansible_deploy_storage_preflight import (
    _prepared as _preflight_prepared,
)
from test_ansible_deploy_storage_preflight import (
    _reconcile as _reconcile_preflight,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_storage_preflight import (
    DeployPostStoragePreflightReconciliationStore,
    deploy_post_storage_preflight_reconciliation_path,
)
from scylla_vms.ansible.deploy_storage_prepare_authorization import (
    ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_PREPARE_GENERAL_PROOF_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_PREPARE_WIPE_PROOF_SCHEMA_VERSION,
    DeployStoragePrepareApprovalMethod,
    DeployStoragePrepareAuthorizationArtifactState,
    DeployStoragePrepareAuthorizationStore,
    DeployStoragePrepareDestructiveScopeProof,
    DeployStoragePrepareGeneralAuthorizationProof,
    DeployStoragePrepareWipeAuthorizationProof,
    authorize_deploy_storage_prepare,
    deploy_storage_prepare_authorization_path,
)
from scylla_vms.ansible.storage_preflight import StorageOwnershipStatus
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

_SECRET = "obviously-fake-storage-prepare-authorization-secret"
_PRIVATE_PATH = "/private/operator/storage-prepare-authorization.json"
_PROMPT = "WIPE /dev/fake and provider device ocid1.volume.fake?"


def _prepared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    disposition: StorageOwnershipStatus,
):
    prepared, _inventory, executables, toolchain = _preflight_prepared(
        tmp_path, monkeypatch, disposition
    )
    runner = StoragePreflightRunner()
    _execute_preflight(prepared, runner, executables, toolchain)
    _reconcile_preflight(prepared)
    return prepared, runner


def _reconciliation(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployPostStoragePreflightReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


def _general(
    prepared,
    *,
    method: DeployStoragePrepareApprovalMethod = (
        DeployStoragePrepareApprovalMethod.INTERACTIVE
    ),
) -> DeployStoragePrepareGeneralAuthorizationProof:
    reconciliation = _reconciliation(prepared)
    return DeployStoragePrepareGeneralAuthorizationProof(
        approval_method=method,
        approved=True,
        allow_destructive=True,
        destructive_scope=(
            DeployStoragePrepareDestructiveScopeProof.from_reconciliation(
                reconciliation
            )
        ),
    )


def _wipe(prepared) -> DeployStoragePrepareWipeAuthorizationProof:
    return DeployStoragePrepareWipeAuthorizationProof.from_reconciliation(
        _reconciliation(prepared)
    )


def _call(
    prepared,
    general_proof: DeployStoragePrepareGeneralAuthorizationProof,
    wipe_proof: DeployStoragePrepareWipeAuthorizationProof | None = None,
):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return authorize_deploy_storage_prepare(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            general_proof=general_proof,
            wipe_proof=wipe_proof,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployStoragePrepareAuthorizationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


@pytest.mark.parametrize(
    "method",
    (
        DeployStoragePrepareApprovalMethod.INTERACTIVE,
        DeployStoragePrepareApprovalMethod.CLI_YES,
    ),
)
def test_exact_no_wipe_scope_is_immutable_redacted_and_process_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: DeployStoragePrepareApprovalMethod,
) -> None:
    signature = inspect.signature(authorize_deploy_storage_prepare)
    assert tuple(signature.parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "general_proof",
        "wipe_proof",
    )
    for forbidden in (
        "target",
        "device",
        "action",
        "path",
        "variable",
        "command",
        "text",
        "prompt",
    ):
        assert forbidden not in signature.parameters

    prepared, runner = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    assert runner.specs is not None
    process_count = len(runner.specs)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    reconciliation_path = deploy_post_storage_preflight_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    immutable = (journal_path.read_bytes(), reconciliation_path.read_bytes())
    show_before = _run_show(prepared.paths)

    proof = _general(prepared, method=method)
    created = _call(prepared, proof)
    stored = _record(prepared)
    path = deploy_storage_prepare_authorization_path(prepared.paths, OPERATION_ID)
    first_bytes = path.read_bytes()
    first_stat = path.stat()
    reused = _call(prepared, proof)

    assert (
        created.schema_version
        == ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )
    assert (
        stored.record.schema_version
        == ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION
    )
    assert (
        stored.record.general_proof.schema_version
        == ANSIBLE_DEPLOY_STORAGE_PREPARE_GENERAL_PROOF_SCHEMA_VERSION
    )
    assert stored.record.wipe_proof is None
    assert (
        created.artifact_state is DeployStoragePrepareAuthorizationArtifactState.CREATED
    )
    assert (
        reused.artifact_state is DeployStoragePrepareAuthorizationArtifactState.REUSED
    )
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.read_bytes() == first_bytes
    assert path.stat().st_ino == first_stat.st_ino
    assert path.stat().st_mtime_ns == first_stat.st_mtime_ns
    assert (journal_path.read_bytes(), reconciliation_path.read_bytes()) == immutable
    assert len(runner.specs) == process_count
    assert _run_show(prepared.paths) == show_before

    assert created.classification is OperationClassification.DESTRUCTIVE
    assert created.prepare_host_count == created.prepare_device_count == 1
    assert created.wipe_host_count == created.wipe_device_count == 0
    assert created.ordinary_approval_method is method
    assert created.ordinary_approval_state == "approved"
    assert created.destructive_flag_state == "matched"
    assert created.destructive_scope_state == "matched"
    assert created.wipe_proof_state == "not-required"
    assert created.wipe_proof_digest is None
    assert created.authorization_state == "authorized-pre-execution"
    assert created.consumed is False
    assert created.execution_state == "unavailable"
    assert created.journal_status is JournalStatus.IN_PROGRESS
    assert created.journal_phase is OperationPhase.VERIFY

    scope = stored.record.scopes[0]
    assert scope.action.value == "prepare-required"
    assert scope.disposition is StorageOwnershipStatus.CLEAN_NEW
    assert scope.wipe_required is False
    persisted = path.read_text(encoding="utf-8")
    projected = json.dumps(created.to_object(), sort_keys=True)
    for protected in (
        "/dev/",
        "fake-data-device",
        "ocid1.",
        "10.0.",
        "203.0.113.",
        "ssh-ed25519",
        "ProxyJump",
        "--limit",
        "ansible-playbook",
        "deploy_scylla_vms_",
        _SECRET,
        _PRIVATE_PATH,
        _PROMPT,
    ):
        assert protected not in persisted
        assert protected not in projected
    for protected_key in (
        "stable_id",
        "command_digest",
        "variables_digest",
        "scopes",
    ):
        assert f'"{protected_key}":' not in projected


def test_wipe_scope_requires_independent_exact_consent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.WIPE_REVIEW_REQUIRED
    )
    assert runner.specs is not None
    process_count = len(runner.specs)
    general = _general(prepared)
    with pytest.raises(StateConflictError, match="separate exact wipe consent"):
        _call(prepared, general)
    assert not deploy_storage_prepare_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()

    report = _call(prepared, general, _wipe(prepared))
    stored = _record(prepared)
    assert report.wipe_host_count == report.wipe_device_count == 1
    assert report.wipe_proof_state == "matched"
    assert report.wipe_proof_digest is not None
    assert stored.record.wipe_proof is not None
    assert (
        stored.record.wipe_proof.schema_version
        == ANSIBLE_DEPLOY_STORAGE_PREPARE_WIPE_PROOF_SCHEMA_VERSION
    )
    assert stored.record.scopes[0].wipe_required
    assert len(runner.specs) == process_count


@pytest.mark.parametrize(
    "disposition",
    (StorageOwnershipStatus.OWNED_NOOP, StorageOwnershipStatus.BLOCKED),
)
def test_owned_noop_and_blocked_hosts_are_never_authorized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    disposition: StorageOwnershipStatus,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch, disposition)
    assert runner.specs is not None
    process_count = len(runner.specs)
    with pytest.raises(StateConflictError, match="no prepare-required scope"):
        _call(
            prepared,
            DeployStoragePrepareGeneralAuthorizationProof(
                approval_method=DeployStoragePrepareApprovalMethod.INTERACTIVE,
                approved=True,
                allow_destructive=True,
            ),
        )
    assert not deploy_storage_prepare_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()
    assert len(runner.specs) == process_count


@pytest.mark.parametrize(
    ("proof_factory", "message"),
    (
        (
            lambda _prepared: DeployStoragePrepareGeneralAuthorizationProof(),
            "ordinary.*approval is required",
        ),
        (
            lambda _prepared: DeployStoragePrepareGeneralAuthorizationProof(
                approval_method=DeployStoragePrepareApprovalMethod.INTERACTIVE,
                approved=False,
                allow_destructive=True,
            ),
            "approval was denied",
        ),
        (
            lambda _prepared: DeployStoragePrepareGeneralAuthorizationProof(
                approval_method=DeployStoragePrepareApprovalMethod.CLI_YES,
                approved=True,
            ),
            "allow-destructive",
        ),
        (
            lambda _prepared: DeployStoragePrepareGeneralAuthorizationProof(
                approval_method=DeployStoragePrepareApprovalMethod.INTERACTIVE,
                approved=True,
                allow_destructive=True,
            ),
            "exact destructive scope proof",
        ),
    ),
)
def test_missing_denied_yes_only_and_destructive_proofs_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    proof_factory,
    message: str,
) -> None:
    prepared, _runner = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    with pytest.raises(StateConflictError, match=message):
        _call(prepared, proof_factory(prepared))
    assert not deploy_storage_prepare_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()


@pytest.mark.parametrize(
    "drift",
    ("broader-count", "narrower-count", "target-digest", "scope-digest"),
)
def test_broader_narrower_and_mismatched_destructive_scopes_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, _runner = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    exact = DeployStoragePrepareDestructiveScopeProof.from_reconciliation(
        _reconciliation(prepared)
    )
    if drift == "broader-count":
        scope = replace(exact, prepare_host_count=exact.prepare_host_count + 1)
    elif drift == "narrower-count":
        scope = replace(exact, prepare_host_count=exact.prepare_host_count - 1)
    elif drift == "target-digest":
        scope = replace(exact, preparation_target_set_digest="sha256:" + "a" * 64)
    else:
        scope = replace(exact, preparation_scope_digest="sha256:" + "b" * 64)
    proof = DeployStoragePrepareGeneralAuthorizationProof(
        approval_method=DeployStoragePrepareApprovalMethod.INTERACTIVE,
        approved=True,
        allow_destructive=True,
        destructive_scope=scope,
    )
    with pytest.raises(StateConflictError, match="does not match"):
        _call(prepared, proof)


@pytest.mark.parametrize(
    "drift",
    ("denied", "broader-count", "narrower-count", "target-digest", "scope-digest"),
)
def test_missing_broader_narrower_and_mismatched_wipe_proofs_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, _runner = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.WIPE_REVIEW_REQUIRED
    )
    exact = _wipe(prepared)
    if drift == "denied":
        proof = replace(exact, consented=False)
    elif drift == "broader-count":
        proof = replace(exact, wipe_host_count=exact.wipe_host_count + 1)
    elif drift == "narrower-count":
        proof = replace(exact, wipe_host_count=exact.wipe_host_count - 1)
    elif drift == "target-digest":
        proof = replace(exact, wipe_target_set_digest="sha256:" + "a" * 64)
    else:
        proof = replace(exact, wipe_scope_digest="sha256:" + "b" * 64)
    with pytest.raises(StateConflictError, match=r"denied|does not match"):
        _call(prepared, _general(prepared), proof)


def test_wipe_proof_cannot_authorize_non_wipe_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    reconciliation = _reconciliation(prepared).record
    extra = DeployStoragePrepareWipeAuthorizationProof(
        True,
        1,
        reconciliation.preparation_target_set_digest,
        reconciliation.preparation_scope_digest,
    )
    with pytest.raises(StateConflictError, match="over-broad"):
        _call(prepared, _general(prepared), extra)


def test_full_chain_drift_and_conflicting_reuse_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    assert runner.specs is not None
    process_count = len(runner.specs)
    proof = _general(prepared)
    _call(prepared, proof)
    with pytest.raises(StateConflictError, match="changed"):
        _call(
            prepared,
            replace(
                proof,
                approval_method=DeployStoragePrepareApprovalMethod.CLI_YES,
            ),
        )
    assert len(runner.specs) == process_count

    second_root = tmp_path / "drift"
    second_root.mkdir(mode=0o700)
    monkeypatch.undo()
    second, second_runner = _prepared(
        second_root, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    path = deploy_post_storage_preflight_reconciliation_path(second.paths, OPERATION_ID)
    value = json.loads(path.read_text(encoding="utf-8"))
    value["record_digest"] = "sha256:" + "f" * 64
    path.write_bytes(serialize_json(value))
    os.chmod(path, 0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(second, _general(second))
    assert second_runner.specs is not None
    assert not deploy_storage_prepare_authorization_path(
        second.paths, OPERATION_ID
    ).exists()


def test_lock_path_permissions_ambiguity_write_failure_and_no_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    assert runner.specs is not None
    process_count = len(runner.specs)
    proof = _general(prepared)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        authorize_deploy_storage_prepare(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            general_proof=proof,
        )

    forged = replace(prepared.paths, operations=tmp_path / "outside")
    with pytest.raises(StatePersistenceError, match="not canonical"):
        DeployStoragePrepareAuthorizationStore(forged, OPERATION_ID)

    path = deploy_storage_prepare_authorization_path(prepared.paths, OPERATION_ID)
    outside = tmp_path / "outside-authorization.json"
    outside.write_text("{}\n", encoding="utf-8")
    outside.chmod(0o600)
    path.symlink_to(outside)
    with pytest.raises(UnsafePathError):
        _call(prepared, proof)
    path.unlink()
    outside.unlink()

    reconciliation_path = deploy_post_storage_preflight_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    reconciliation_path.chmod(0o644)
    with pytest.raises(UnsafePathError):
        _call(prepared, proof)
    reconciliation_path.chmod(0o600)

    ambiguous = prepared.paths.operations / (
        f"{{{OPERATION_ID}}}.ansible-deploy-storage-prepare-authorization.json"
    )
    ambiguous.write_text("{}\n", encoding="utf-8")
    ambiguous.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _call(prepared, proof)
    ambiguous.unlink()

    def fail_subprocess(*args, **kwargs):
        del args, kwargs
        raise AssertionError("storage-prepare authorization must not run a process")

    monkeypatch.setattr(subprocess, "run", fail_subprocess)
    report = _call(prepared, proof)
    assert report.execution_state == "unavailable"
    assert report.to_object()["execution"]["available"] is False
    assert len(runner.specs) == process_count

    monkeypatch.undo()
    second_root = tmp_path / "write-failure"
    second_root.mkdir(mode=0o700)
    second, _runner = _prepared(
        second_root, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )

    def fail_write(self, record, *, lock):
        del self, record, lock
        raise StatePersistenceError(f"simulated {_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(
        DeployStoragePrepareAuthorizationStore,
        "write_locked",
        fail_write,
    )
    journal_path = second.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()
    with pytest.raises(StatePersistenceError, match="persistence failed") as caught:
        _call(second, _general(second))
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    assert journal_path.read_bytes() == journal_before
    assert not deploy_storage_prepare_authorization_path(
        second.paths, OPERATION_ID
    ).exists()


def test_malformed_proof_types_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    general = _general(prepared)
    with (
        ClusterLock(prepared.paths, "deploy", 0) as lock,
        pytest.raises(StateConflictError, match=r"general.*malformed"),
    ):
        authorize_deploy_storage_prepare(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            general_proof=cast(DeployStoragePrepareGeneralAuthorizationProof, object()),
        )
    with (
        ClusterLock(prepared.paths, "deploy", 0) as lock,
        pytest.raises(StateConflictError, match=r"wipe.*malformed"),
    ):
        authorize_deploy_storage_prepare(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            general_proof=general,
            wipe_proof=cast(DeployStoragePrepareWipeAuthorizationProof, object()),
        )
