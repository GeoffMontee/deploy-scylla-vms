import inspect
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_final_routes import (
    FinalRoutesRunner,
)
from test_ansible_deploy_final_routes import (
    _execute as _execute_final_routes,
)
from test_ansible_deploy_final_routes import (
    _prepared as _final_routes_prepared,
)
from test_ansible_deploy_final_routes import (
    _reconcile as _reconcile_final_routes,
)
from test_provider_source import CLUSTER_UUID
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_final_routes as final_routes_module
import scylla_vms.ansible.deploy_non_jump_base_os_authorization as authorization_module
import scylla_vms.ansible.deploy_reconciliation as deploy_reconciliation_module
from scylla_vms.ansible.deploy_authorization import (
    deploy_base_os_authorization_path,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_final_routes import (
    DeployPostFinalRoutesReconciliationStore,
    deploy_post_final_routes_reconciliation_path,
)
from scylla_vms.ansible.deploy_non_jump_base_os_authorization import (
    ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_PROOF_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_SCHEMA_VERSION,
    DeployNonJumpBaseOsApprovalMethod,
    DeployNonJumpBaseOsAuthorizationArtifactState,
    DeployNonJumpBaseOsAuthorizationProof,
    DeployNonJumpBaseOsAuthorizationStore,
    authorize_deploy_non_jump_base_os,
    deploy_non_jump_base_os_authorization_path,
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
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import serialize_json

_PRIVATE_PATH = "/private/operator/non-jump-base-os-authorization.json"
_SECRET = "obviously-fake-non-jump-base-os-authorization-secret"
_PROMPT = "APPROVE base-os on 10.0.0.10?"


def _interactive() -> DeployNonJumpBaseOsAuthorizationProof:
    return DeployNonJumpBaseOsAuthorizationProof(
        approval_method=DeployNonJumpBaseOsApprovalMethod.INTERACTIVE,
        approved=True,
    )


def _yes() -> DeployNonJumpBaseOsAuthorizationProof:
    return DeployNonJumpBaseOsAuthorizationProof(
        approval_method=DeployNonJumpBaseOsApprovalMethod.CLI_YES,
        approved=True,
    )


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, executables, toolchain = _final_routes_prepared(tmp_path, monkeypatch)
    runner = FinalRoutesRunner()
    _execute_final_routes(prepared, runner, executables, toolchain)
    _reconcile_final_routes(prepared)
    return prepared, runner


def _call(prepared, proof: DeployNonJumpBaseOsAuthorizationProof):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return authorize_deploy_non_jump_base_os(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=proof,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployNonJumpBaseOsAuthorizationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


@pytest.mark.parametrize(
    ("proof", "method"),
    (
        (_interactive(), DeployNonJumpBaseOsApprovalMethod.INTERACTIVE),
        (_yes(), DeployNonJumpBaseOsApprovalMethod.CLI_YES),
    ),
)
def test_exact_non_jump_scope_is_immutable_redacted_and_process_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    proof: DeployNonJumpBaseOsAuthorizationProof,
    method: DeployNonJumpBaseOsApprovalMethod,
) -> None:
    assert tuple(inspect.signature(authorize_deploy_non_jump_base_os).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "proof",
    )
    for forbidden in (
        "step",
        "target",
        "targets",
        "role",
        "limit",
        "variables",
        "command",
        "path",
        "classification",
        "scope",
        "prompt",
        "text",
    ):
        assert (
            forbidden
            not in inspect.signature(authorize_deploy_non_jump_base_os).parameters
        )
    prepared, runner = _prepared(tmp_path, monkeypatch)
    process_count = len(cast(list[object], runner.specs))
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    reconciliation_path = deploy_post_final_routes_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    earlier_path = deploy_base_os_authorization_path(prepared.paths, OPERATION_ID)
    immutable = (
        journal_path.read_bytes(),
        reconciliation_path.read_bytes(),
        earlier_path.read_bytes(),
    )
    earlier_stat = earlier_path.stat()

    created = _call(prepared, proof)
    stored = _record(prepared)
    path = deploy_non_jump_base_os_authorization_path(prepared.paths, OPERATION_ID)
    first_bytes = path.read_bytes()
    first_stat = path.stat()
    reused = _call(prepared, proof)

    assert (
        created.schema_version
        == ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )
    assert (
        stored.record.schema_version
        == ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
    )
    assert (
        stored.record.proof.schema_version
        == ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    assert (
        created.artifact_state is DeployNonJumpBaseOsAuthorizationArtifactState.CREATED
    )
    assert reused.artifact_state is DeployNonJumpBaseOsAuthorizationArtifactState.REUSED
    assert path != earlier_path
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.read_bytes() == first_bytes
    assert path.stat().st_ino == first_stat.st_ino
    assert path.stat().st_mtime_ns == first_stat.st_mtime_ns
    assert (
        journal_path.read_bytes(),
        reconciliation_path.read_bytes(),
        earlier_path.read_bytes(),
    ) == immutable
    assert earlier_path.stat().st_ino == earlier_stat.st_ino
    assert earlier_path.stat().st_mtime_ns == earlier_stat.st_mtime_ns
    assert len(cast(list[object], runner.specs)) == process_count

    reconciliation = DeployPostFinalRoutesReconciliationStore(
        prepared.paths, OPERATION_ID
    ).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    ready = tuple(
        step
        for step in reconciliation.record.steps
        if step.status
        is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
    )
    assert len(ready) == len(stored.record.scopes) == 1
    scope = stored.record.scopes[0]
    assert scope.sequence == ready[0].sequence
    assert scope.mapping_sequence == 6
    assert scope.playbook == "base-os"
    assert scope.condition == "non-jump-managed-hosts"
    assert scope.classification is OperationClassification.MUTATING
    assert scope.target_role == "all"
    assert scope.target_ids == ready[0].target_ids
    assert set(scope.target_ids) == {
        "manager-1",
        "monitoring-1",
        "scylla-ad-1-1",
    }
    assert "jump-host-1" not in scope.target_ids
    assert stored.record.role_set == ("manager", "monitoring", "scylla")
    assert created.stage == "post-final-routes-non-jump-base-os"
    assert created.scope_kind == "non-jump-managed-hosts"
    assert created.approval_method is method
    assert created.approval_state == "approved"
    assert created.playbook_instance_count == 1
    assert created.role_count == 3
    assert created.stable_id_count == 3
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
        "fingerprint",
        "ProxyJump",
        "--limit",
        "ansible-playbook",
        "deploy_scylla_vms_",
        _PRIVATE_PATH,
        _SECRET,
        _PROMPT,
    ):
        assert protected not in persisted
        assert protected not in projected
    for protected_key in (
        "target_ids",
        "command_digest",
        "variables_digest",
        "role_set",
    ):
        assert f'"{protected_key}":' not in projected


@pytest.mark.parametrize(
    ("proof", "message"),
    (
        (DeployNonJumpBaseOsAuthorizationProof(), "approval is required"),
        (
            DeployNonJumpBaseOsAuthorizationProof(
                approval_method=DeployNonJumpBaseOsApprovalMethod.INTERACTIVE,
                approved=False,
            ),
            "was denied",
        ),
        (
            DeployNonJumpBaseOsAuthorizationProof(
                approval_method=DeployNonJumpBaseOsApprovalMethod.CLI_YES,
                approved=True,
                allow_destructive=True,
            ),
            "inapplicable",
        ),
        (
            DeployNonJumpBaseOsAuthorizationProof(
                approval_method=DeployNonJumpBaseOsApprovalMethod.INTERACTIVE,
                approved=True,
                destructive_scope_provided=True,
            ),
            "inapplicable",
        ),
        (
            DeployNonJumpBaseOsAuthorizationProof(
                approval_method=DeployNonJumpBaseOsApprovalMethod.INTERACTIVE,
                approved=True,
                narrow_consent_provided=True,
            ),
            "inapplicable",
        ),
    ),
)
def test_denied_missing_destructive_and_narrow_proofs_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    proof: DeployNonJumpBaseOsAuthorizationProof,
    message: str,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    with pytest.raises(StateConflictError, match=message):
        _call(prepared, proof)
    assert not deploy_non_jump_base_os_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_malformed_proof_and_no_ready_scope_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    with (
        ClusterLock(prepared.paths, "deploy", 0) as lock,
        pytest.raises(StateConflictError, match="malformed"),
    ):
        authorize_deploy_non_jump_base_os(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=cast(DeployNonJumpBaseOsAuthorizationProof, object()),
        )
    monkeypatch.setattr(
        authorization_module,
        "_derive_authorization_scopes",
        lambda _context: ((), ()),
    )
    with pytest.raises(StateConflictError, match="no evidence-ready scope"):
        _call(prepared, _interactive())


@pytest.mark.parametrize(
    "scope_drift",
    ("jump-target", "extra-target", "missing-target", "wrong-target", "wrong-step"),
)
def test_jump_extra_missing_wrong_target_and_step_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scope_drift: str,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    path = deploy_post_final_routes_reconciliation_path(prepared.paths, OPERATION_ID)
    value = json.loads(path.read_text(encoding="utf-8"))
    steps = value["steps"]
    ready = next(
        step
        for step in steps
        if step["status"] == "evidence-ready-authorization-required"
    )
    if scope_drift == "jump-target":
        ready["target_ids"].append("jump-host-1")
    elif scope_drift == "extra-target":
        ready["target_ids"].append("extra-host")
    elif scope_drift == "missing-target":
        ready["target_ids"] = ready["target_ids"][1:]
    elif scope_drift == "wrong-target":
        ready["target_ids"] = ["wrong-host"]
    else:
        ready["playbook"] = "storage-prepare"
    if scope_drift != "wrong-step":
        ready["target_ids"].sort()
        ready["target_digest"] = final_routes_module._digest_object(ready["target_ids"])
    value["effective_plan_digest"] = final_routes_module._digest_object(steps)
    value["record_digest"] = ""
    value["record_digest"] = final_routes_module._digest_object(value)
    path.write_bytes(serialize_json(value))
    path.chmod(0o600)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, _interactive())
    assert not deploy_non_jump_base_os_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()


@pytest.mark.parametrize(
    "drift",
    (
        "context",
        "original-plan",
        "effective-plan",
        "prerequisite",
        "pre-mutation-execution",
        "pre-mutation-evidence",
        "host-reconciliation",
        "base-os-authorization",
        "base-os-execution",
        "base-os-evidence",
        "base-os-reconciliation",
        "post-reboot",
        "jump-authorization",
        "jump-execution",
        "jump-evidence",
        "post-jump",
        "final-routes-execution",
        "final-routes-evidence",
        "final-routes-reconciliation",
        "inventory",
        "trust",
        "readiness",
        "source",
        "catalog",
        "journal",
    ),
)
def test_full_chain_final_routes_host_evidence_and_current_state_drift_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch)
    paths = prepared.paths
    selected = {
        "context": paths.operations / f"{OPERATION_ID}.ansible-deploy-context.json",
        "original-plan": paths.operations / f"{OPERATION_ID}.ansible-deploy-plan.json",
        "effective-plan": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-effective-plan.json",
        "prerequisite": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-prerequisite-evidence.json",
        "pre-mutation-execution": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-pre-mutation-host-evidence-execution.json",
        "pre-mutation-evidence": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-pre-mutation-host-evidence.json",
        "host-reconciliation": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-host-evidence-reconciliation.json",
        "base-os-authorization": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-base-os-authorization.json",
        "base-os-execution": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-base-os-execution.json",
        "base-os-evidence": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-base-os-evidence.json",
        "base-os-reconciliation": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-base-os-reconciliation.json",
        "post-reboot": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-post-reboot-reconciliation.json",
        "jump-authorization": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-jump-host-configure-authorization.json",
        "jump-execution": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-jump-host-configure-execution.json",
        "jump-evidence": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-jump-host-configure-evidence.json",
        "post-jump": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-post-jump-host-configure-reconciliation.json",
        "final-routes-execution": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-final-routes-execution.json",
        "final-routes-evidence": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-final-routes-evidence.json",
        "final-routes-reconciliation": (
            deploy_post_final_routes_reconciliation_path(paths, OPERATION_ID)
        ),
        "inventory": paths.ansible_inventory,
        "trust": paths.ansible_trust,
        "readiness": paths.terraform_plans
        / f"{OPERATION_ID}.terraform-apply-readiness.json",
        "journal": paths.operations / f"{OPERATION_ID}.json",
    }
    if drift == "source":
        source = load_ansible_source_bundle()
        monkeypatch.setattr(
            deploy_reconciliation_module,
            "load_ansible_source_bundle",
            lambda: replace(source, digest="sha256:" + "a" * 64),
        )
    elif drift == "catalog":
        monkeypatch.setattr(
            deploy_reconciliation_module,
            "ansible_operation_catalog_digest",
            lambda: "sha256:" + "b" * 64,
        )
    else:
        document = json.loads(selected[drift].read_text(encoding="utf-8"))
        document["unexpected"] = _SECRET
        selected[drift].write_bytes(serialize_json(document))
        os.chmod(selected[drift], 0o600)
    process_count = len(cast(list[object], runner.specs))

    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _call(prepared, _interactive())

    assert not deploy_non_jump_base_os_authorization_path(paths, OPERATION_ID).exists()
    assert len(cast(list[object], runner.specs)) == process_count


def test_uncertain_history_conflicting_proof_and_write_failure_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    uncertain = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-non-jump-base-os-execution.json"
    )
    uncertain.write_text("{}\n", encoding="utf-8")
    uncertain.chmod(0o600)
    with pytest.raises(StateConflictError, match="uncertain execution"):
        _call(prepared, _interactive())
    uncertain.unlink()

    _call(prepared, _interactive())
    with pytest.raises(StateConflictError, match="changed"):
        _call(prepared, _yes())

    monkeypatch.undo()
    second_root = tmp_path / "write-failure"
    second_root.mkdir(mode=0o700)
    second, _runner = _prepared(second_root, monkeypatch)

    def fail_write(self, record, *, lock):
        del self, record, lock
        raise StatePersistenceError(f"simulated {_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(
        DeployNonJumpBaseOsAuthorizationStore,
        "write_locked",
        fail_write,
    )
    journal_path = second.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()
    with pytest.raises(StatePersistenceError, match="persistence failed") as caught:
        _call(second, _interactive())
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    assert journal_path.read_bytes() == journal_before
    assert not deploy_non_jump_base_os_authorization_path(
        second.paths, OPERATION_ID
    ).exists()


def test_lock_path_symlink_permissions_ambiguity_and_zero_subprocess_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch)
    process_count = len(cast(list[object], runner.specs))
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        authorize_deploy_non_jump_base_os(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            proof=_interactive(),
        )

    forged = replace(prepared.paths, operations=tmp_path / "outside")
    with pytest.raises(StatePersistenceError, match="not canonical"):
        DeployNonJumpBaseOsAuthorizationStore(forged, OPERATION_ID)

    path = deploy_non_jump_base_os_authorization_path(prepared.paths, OPERATION_ID)
    outside = tmp_path / "outside-authorization.json"
    outside.write_text("{}\n", encoding="utf-8")
    outside.chmod(0o600)
    path.symlink_to(outside)
    with pytest.raises(UnsafePathError):
        _call(prepared, _interactive())
    path.unlink()
    outside.unlink()

    reconciliation_path = deploy_post_final_routes_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    reconciliation_path.chmod(0o644)
    with pytest.raises(UnsafePathError):
        _call(prepared, _interactive())
    reconciliation_path.chmod(0o600)

    ambiguous = prepared.paths.operations / (
        f"{{{OPERATION_ID}}}.ansible-deploy-non-jump-base-os-authorization.json"
    )
    ambiguous.write_text("{}\n", encoding="utf-8")
    ambiguous.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _call(prepared, _interactive())
    ambiguous.unlink()

    def fail_subprocess(*args, **kwargs):
        del args, kwargs
        raise AssertionError("non-jump base-os authorization must not run a process")

    monkeypatch.setattr(subprocess, "run", fail_subprocess)
    report = _call(prepared, _interactive())
    assert report.execution_state == "unavailable"
    assert report.to_object()["execution"]["available"] is False
    assert len(cast(list[object], runner.specs)) == process_count
