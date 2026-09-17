import inspect
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_host_reconciliation import (
    _call as _reconcile_host_evidence,
)
from test_ansible_deploy_host_reconciliation import (
    _prepared as _host_reconciliation_prepared,
)
from test_ansible_deploy_host_reconciliation import (
    _replace_host_evidence,
    _with_reboot,
)
from test_provider_source import CLUSTER_UUID
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_reconciliation as reconciliation_module
from scylla_vms.ansible.deploy_authorization import (
    ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_PROOF_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_SCHEMA_VERSION,
    DeployBaseOsApprovalMethod,
    DeployBaseOsAuthorizationArtifactState,
    DeployBaseOsAuthorizationProof,
    DeployBaseOsAuthorizationStore,
    authorize_deploy_base_os,
    deploy_base_os_authorization_path,
)
from scylla_vms.ansible.deploy_host_reconciliation import (
    DeployHostEvidenceReconciliationStore,
    DeployHostReconciledStepStatus,
    deploy_host_evidence_reconciliation_path,
)
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.persistence import serialize_json

_PRIVATE_PATH = "/private/operator/base-os-authorization.json"
_SECRET = "obviously-fake-base-os-authorization-secret"
_PROMPT = "APPROVE base-os on 10.0.0.10?"


def _prepared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    ready: bool = True,
):
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    prepared, inventory, runner = _host_reconciliation_prepared(tmp_path, monkeypatch)
    if ready:
        _replace_host_evidence(
            prepared,
            lambda host: _with_reboot(host, "not-required"),
        )
    _reconcile_host_evidence(prepared)
    return prepared, inventory, runner


def _call(
    prepared,
    proof: DeployBaseOsAuthorizationProof,
):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return authorize_deploy_base_os(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=proof,
        )


def _interactive() -> DeployBaseOsAuthorizationProof:
    return DeployBaseOsAuthorizationProof(
        approval_method=DeployBaseOsApprovalMethod.INTERACTIVE,
        approved=True,
    )


def _yes() -> DeployBaseOsAuthorizationProof:
    return DeployBaseOsAuthorizationProof(
        approval_method=DeployBaseOsApprovalMethod.CLI_YES,
        approved=True,
    )


def _read(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployBaseOsAuthorizationStore(prepared.paths, OPERATION_ID).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


def test_interactive_authorization_is_exact_immutable_redacted_and_process_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(inspect.signature(authorize_deploy_base_os).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "proof",
    )
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    reconciliation_path = deploy_host_evidence_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    journal_before = journal_path.read_bytes()
    reconciliation_before = reconciliation_path.read_bytes()
    process_count = len(runner.specs or ())

    created = _call(prepared, _interactive())
    path = deploy_base_os_authorization_path(prepared.paths, OPERATION_ID)
    authorization_before = path.read_bytes()
    authorization_mtime = path.stat().st_mtime_ns
    reused = _call(prepared, _interactive())
    stored = _read(prepared)

    assert created.schema_version == (
        ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )
    assert created.artifact_state is DeployBaseOsAuthorizationArtifactState.CREATED
    assert reused.artifact_state is DeployBaseOsAuthorizationArtifactState.REUSED
    assert stored.record.schema_version == (
        ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
    )
    assert stored.record.proof.schema_version == (
        ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.read_bytes() == authorization_before
    assert path.stat().st_mtime_ns == authorization_mtime
    assert journal_path.read_bytes() == journal_before
    assert reconciliation_path.read_bytes() == reconciliation_before
    assert len(runner.specs or ()) == process_count

    reconciliation = DeployHostEvidenceReconciliationStore(
        prepared.paths, OPERATION_ID
    ).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    ready = tuple(
        step
        for step in reconciliation.record.steps
        if step.status
        is DeployHostReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
    )
    assert tuple(scope.sequence for scope in stored.record.scopes) == tuple(
        step.sequence for step in ready
    )
    assert tuple(scope.target_ids for scope in stored.record.scopes) == tuple(
        step.target_ids for step in ready
    )
    assert all(scope.playbook == "base-os" for scope in stored.record.scopes)
    assert created.playbook_instance_count == len(ready)
    assert created.stable_id_count == len(
        {target for step in ready for target in step.target_ids}
    )
    assert created.approval_method is DeployBaseOsApprovalMethod.INTERACTIVE
    assert created.classification.value == "mutating"
    assert created.authorization_state == "authorized-pre-execution"
    assert created.consumed is False
    assert created.execution_state == "unavailable"
    assert created.journal_status is JournalStatus.IN_PROGRESS
    assert created.journal_phase is OperationPhase.VERIFY

    persisted = path.read_text(encoding="utf-8")
    projected = json.dumps(created.to_object(), sort_keys=True)
    for protected in (
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "ssh-ed25519",
        "--limit",
        "ansible-playbook",
        "deploy_scylla_vms_",
        _PRIVATE_PATH,
        _SECRET,
        _PROMPT,
    ):
        assert protected not in persisted
        assert protected not in projected
    for protected_key in ("target_ids", "command_digest", "variables_digest"):
        assert protected_key not in projected


def test_plan_permitted_yes_authorizes_only_ordinary_mutating_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch)
    report = _call(prepared, _yes())
    stored = _read(prepared)

    assert report.approval_method is DeployBaseOsApprovalMethod.CLI_YES
    assert stored.record.proof.approved is True
    assert stored.record.proof.allow_destructive is False
    assert stored.record.proof.destructive_scope_provided is False
    assert all(
        scope.classification.value == "mutating"
        and scope.mapping_sequence == 3
        and scope.playbook == "base-os"
        for scope in stored.record.scopes
    )


@pytest.mark.parametrize(
    ("proof", "message"),
    (
        (DeployBaseOsAuthorizationProof(), "approval is required"),
        (
            DeployBaseOsAuthorizationProof(
                approval_method=DeployBaseOsApprovalMethod.INTERACTIVE,
                approved=False,
            ),
            "was denied",
        ),
        (
            DeployBaseOsAuthorizationProof(
                approval_method=DeployBaseOsApprovalMethod.CLI_YES,
                approved=True,
                allow_destructive=True,
            ),
            "inapplicable",
        ),
        (
            DeployBaseOsAuthorizationProof(
                approval_method=DeployBaseOsApprovalMethod.INTERACTIVE,
                approved=True,
                destructive_scope_provided=True,
            ),
            "inapplicable",
        ),
    ),
)
def test_missing_denied_and_destructive_proofs_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    proof: DeployBaseOsAuthorizationProof,
    message: str,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch)
    with pytest.raises(StateConflictError, match=message):
        _call(prepared, proof)
    assert not deploy_base_os_authorization_path(prepared.paths, OPERATION_ID).exists()


def test_malformed_proof_and_no_evidence_ready_scope_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch)
    with (
        ClusterLock(prepared.paths, "deploy", 0) as lock,
        pytest.raises(StateConflictError, match="malformed"),
    ):
        authorize_deploy_base_os(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=cast(DeployBaseOsAuthorizationProof, object()),
        )

    monkeypatch.undo()
    blocked, _inventory, _runner = _prepared(
        tmp_path / "blocked",
        monkeypatch,
        ready=False,
    )
    with pytest.raises(StateConflictError, match="no evidence-ready scope"):
        _call(blocked, _interactive())
    assert not deploy_base_os_authorization_path(blocked.paths, OPERATION_ID).exists()


@pytest.mark.parametrize(
    "scope_drift",
    ("extra-target", "missing-target", "wrong-target", "wrong-step"),
)
def test_tampered_extra_missing_wrong_target_or_step_scope_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scope_drift: str,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch)
    path = deploy_host_evidence_reconciliation_path(prepared.paths, OPERATION_ID)
    value = json.loads(path.read_text(encoding="utf-8"))
    steps = value["steps"]
    ready = next(
        step
        for step in steps
        if step["status"] == "evidence-ready-authorization-required"
    )
    if scope_drift == "extra-target":
        ready["target_ids"].append("extra-host")
        ready["target_ids"].sort()
        ready["target_digest"] = reconciliation_module._digest_object(
            ready["target_ids"]
        )
    elif scope_drift == "missing-target":
        ready["target_ids"] = []
        ready["target_digest"] = reconciliation_module._digest_object([])
    elif scope_drift == "wrong-target":
        ready["target_ids"] = ["wrong-host"]
        ready["target_digest"] = reconciliation_module._digest_object(["wrong-host"])
    else:
        ready["playbook"] = "storage-prepare"
    value["effective_plan_digest"] = reconciliation_module._digest_object(steps)
    value["record_digest"] = ""
    value["record_digest"] = reconciliation_module._digest_object(value)
    path.write_bytes(serialize_json(value))
    path.chmod(0o600)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, _interactive())
    assert not deploy_base_os_authorization_path(prepared.paths, OPERATION_ID).exists()


@pytest.mark.parametrize(
    "drift",
    (
        "context",
        "original-plan",
        "effective-plan",
        "host-reconciliation",
        "readiness",
        "catalog",
        "source",
        "journal",
    ),
)
def test_full_chain_drift_is_refused_before_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch)
    paths = prepared.paths
    if drift == "context":
        _tamper_digest(
            paths.operations / f"{OPERATION_ID}.ansible-deploy-context.json",
            "record_digest",
        )
    elif drift == "original-plan":
        _tamper_digest(
            paths.operations / f"{OPERATION_ID}.ansible-deploy-plan.json",
            "record_digest",
        )
    elif drift == "effective-plan":
        _tamper_digest(
            paths.operations / f"{OPERATION_ID}.ansible-deploy-effective-plan.json",
            "record_digest",
        )
    elif drift == "host-reconciliation":
        _tamper_digest(
            deploy_host_evidence_reconciliation_path(paths, OPERATION_ID),
            "record_digest",
        )
    elif drift == "readiness":
        _tamper_digest(
            paths.terraform_plans / f"{OPERATION_ID}.terraform-apply-readiness.json",
            "record_digest",
        )
    elif drift == "catalog":
        monkeypatch.setattr(
            reconciliation_module,
            "ansible_operation_catalog_digest",
            lambda: "sha256:" + "b" * 64,
        )
    elif drift == "source":
        source = load_ansible_source_bundle()
        monkeypatch.setattr(
            reconciliation_module,
            "load_ansible_source_bundle",
            lambda: replace(source, digest="sha256:" + "c" * 64),
        )
    else:
        _tamper_digest(
            paths.operations / f"{OPERATION_ID}.json",
            "request_digest",
        )

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, _interactive())
    assert not deploy_base_os_authorization_path(paths, OPERATION_ID).exists()


def test_uncertain_execution_and_conflicting_proof_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch)
    uncertain = (
        prepared.paths.operations / f"{OPERATION_ID}.ansible-operation-execution.json"
    )
    uncertain.write_text("{}\n", encoding="utf-8")
    uncertain.chmod(0o600)
    with pytest.raises(StateConflictError, match="uncertain prior execution"):
        _call(prepared, _interactive())
    uncertain.unlink()

    _call(prepared, _interactive())
    with pytest.raises(StateConflictError, match="changed"):
        _call(prepared, _yes())


def test_write_failure_lock_path_symlink_permissions_and_ambiguity_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        authorize_deploy_base_os(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            proof=_interactive(),
        )

    forged = replace(prepared.paths, operations=tmp_path / "outside")
    with pytest.raises(StatePersistenceError, match="not canonical"):
        DeployBaseOsAuthorizationStore(forged, OPERATION_ID)

    path = deploy_base_os_authorization_path(prepared.paths, OPERATION_ID)
    outside = tmp_path / "outside-authorization.json"
    outside.write_text("{}\n", encoding="utf-8")
    outside.chmod(0o600)
    path.symlink_to(outside)
    with pytest.raises(UnsafePathError):
        _call(prepared, _interactive())
    path.unlink()
    outside.unlink()

    reconciliation_path = deploy_host_evidence_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    reconciliation_path.chmod(0o644)
    with pytest.raises(UnsafePathError):
        _call(prepared, _interactive())
    reconciliation_path.chmod(0o600)

    for name in (
        f"{{{OPERATION_ID}}}.ansible-deploy-base-os-authorization.json",
        f"{OPERATION_ID}.duplicate.ansible-deploy-base-os-authorization.json",
    ):
        ambiguous = prepared.paths.operations / name
        ambiguous.write_text("{}\n", encoding="utf-8")
        ambiguous.chmod(0o600)
        with pytest.raises(StateConflictError, match="ambiguous"):
            _call(prepared, _interactive())
        ambiguous.unlink()

    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()

    def fail_write(self, record, *, lock):
        del self, record, lock
        raise StatePersistenceError(f"simulated {_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(
        DeployBaseOsAuthorizationStore,
        "write_locked",
        fail_write,
    )
    with pytest.raises(StatePersistenceError) as caught:
        _call(prepared, _interactive())
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    assert journal_path.read_bytes() == journal_before
    assert not path.exists()


def test_authorization_never_invokes_runner_or_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch)
    process_count = len(runner.specs or ())

    def fail_subprocess(*args, **kwargs):
        del args, kwargs
        raise AssertionError("deploy base-os authorization must not run a process")

    monkeypatch.setattr(subprocess, "run", fail_subprocess)
    report = _call(prepared, _interactive())

    assert len(runner.specs or ()) == process_count
    assert report.execution_state == "unavailable"
    assert report.to_object()["execution"]["available"] is False


def _tamper_digest(path: Path, field: str) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    value[field] = "sha256:" + "d" * 64
    path.write_bytes(serialize_json(value))
    os.chmod(path, 0o600)
