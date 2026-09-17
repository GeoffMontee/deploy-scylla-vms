import inspect
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_reboot_reconciliation import (
    _call as _reconcile_post_reboot,
)
from test_ansible_deploy_reboot_reconciliation import (
    _prepared as _post_reboot_prepared,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_jump_host_authorization as authorization_module
import scylla_vms.ansible.deploy_reconciliation as deploy_reconciliation_module
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_jump_host_authorization import (
    ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION,
    DeployJumpHostConfigureApprovalMethod,
    DeployJumpHostConfigureAuthorizationArtifactState,
    DeployJumpHostConfigureAuthorizationProof,
    DeployJumpHostConfigureAuthorizationStore,
    authorize_deploy_jump_host_configure,
    deploy_jump_host_configure_authorization_path,
)
from scylla_vms.ansible.deploy_reboot_reconciliation import (
    DeployPostRebootBranch,
    DeployPostRebootReconciliationStore,
    deploy_post_reboot_reconciliation_path,
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

_PRIVATE_PATH = "/private/operator/jump-host-authorization.json"
_SECRET = "obviously-fake-jump-host-authorization-secret"
_PROMPT = "APPROVE jump configuration for 10.0.0.10?"


def _interactive() -> DeployJumpHostConfigureAuthorizationProof:
    return DeployJumpHostConfigureAuthorizationProof(
        approval_method=DeployJumpHostConfigureApprovalMethod.INTERACTIVE,
        approved=True,
    )


def _yes() -> DeployJumpHostConfigureAuthorizationProof:
    return DeployJumpHostConfigureAuthorizationProof(
        approval_method=DeployJumpHostConfigureApprovalMethod.CLI_YES,
        approved=True,
    )


def _prepared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    reboot_required: bool = True,
):
    prepared, runner, executables, toolchain = _post_reboot_prepared(
        tmp_path,
        monkeypatch,
        reboot_required=reboot_required,
    )
    _reconcile_post_reboot(prepared)
    return prepared, runner, executables, toolchain


def _call(prepared, proof: DeployJumpHostConfigureAuthorizationProof):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return authorize_deploy_jump_host_configure(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=proof,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployJumpHostConfigureAuthorizationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


@pytest.mark.parametrize(
    ("reboot_required", "proof", "method"),
    (
        (
            True,
            _interactive(),
            DeployJumpHostConfigureApprovalMethod.INTERACTIVE,
        ),
        (
            False,
            _yes(),
            DeployJumpHostConfigureApprovalMethod.CLI_YES,
        ),
    ),
)
def test_exact_scope_ordinary_authorization_is_immutable_and_process_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reboot_required: bool,
    proof: DeployJumpHostConfigureAuthorizationProof,
    method: DeployJumpHostConfigureApprovalMethod,
) -> None:
    assert tuple(
        inspect.signature(authorize_deploy_jump_host_configure).parameters
    ) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "proof",
    )
    prepared, runner, _executables, _toolchain = _prepared(
        tmp_path,
        monkeypatch,
        reboot_required=reboot_required,
    )
    process_count = len(cast(list[object], runner.specs))
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    reconciliation_path = deploy_post_reboot_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    immutable_bytes = (journal_path.read_bytes(), reconciliation_path.read_bytes())
    show_before = _run_show(prepared.paths)

    created = _call(prepared, proof)
    stored = _record(prepared)
    path = deploy_jump_host_configure_authorization_path(prepared.paths, OPERATION_ID)
    first_bytes = path.read_bytes()
    first_mtime = path.stat().st_mtime_ns
    reused = _call(prepared, proof)

    assert (
        created.schema_version
        == ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )
    assert (
        stored.record.schema_version
        == ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
    )
    assert (
        stored.record.proof.schema_version
        == ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    assert (
        created.artifact_state
        is DeployJumpHostConfigureAuthorizationArtifactState.CREATED
    )
    assert (
        reused.artifact_state
        is DeployJumpHostConfigureAuthorizationArtifactState.REUSED
    )
    assert path.read_bytes() == first_bytes
    assert path.stat().st_mtime_ns == first_mtime
    assert path.stat().st_mode & 0o777 == 0o600
    assert (journal_path.read_bytes(), reconciliation_path.read_bytes()) == (
        immutable_bytes
    )
    assert _run_show(prepared.paths) == show_before
    assert len(cast(list[object], runner.specs)) == process_count

    post_reboot = DeployPostRebootReconciliationStore(
        prepared.paths, OPERATION_ID
    ).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    ready = tuple(
        step
        for step in post_reboot.record.steps
        if step.status
        is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
    )
    assert tuple(scope.sequence for scope in stored.record.scopes) == tuple(
        step.sequence for step in ready
    )
    assert tuple(scope.target_ids for scope in stored.record.scopes) == tuple(
        step.target_ids for step in ready
    )
    assert all(
        scope.mapping_sequence == 4
        and scope.playbook == "jump-host-configure"
        and scope.target_role == "jump-host"
        and scope.classification is OperationClassification.MUTATING
        for scope in stored.record.scopes
    )
    assert created.playbook_instance_count == len(ready) == 1
    assert created.stable_id_count == 1
    assert created.approval_method is method
    assert created.authorization_state == "authorized-pre-execution"
    assert created.classification is OperationClassification.MUTATING
    assert created.consumed is False
    assert created.execution_state == "unavailable"
    assert created.finalization_state == "not-started"
    assert created.journal_status is JournalStatus.IN_PROGRESS
    assert created.journal_phase is OperationPhase.VERIFY
    assert created.reboot_branch is (
        DeployPostRebootBranch.REBOOT_REQUIRED
        if reboot_required
        else DeployPostRebootBranch.NO_REBOOT_REQUIRED
    )
    optional_reboot = (
        stored.record.reboot_plan_artifact_digest,
        stored.record.reboot_authorization_artifact_digest,
        stored.record.reboot_execution_artifact_digest,
        stored.record.reboot_evidence_artifact_digest,
        stored.record.reboot_evidence_digest,
    )
    assert all(value is not None for value in optional_reboot) is reboot_required

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
        "config_text",
    ):
        assert protected_key not in projected


@pytest.mark.parametrize(
    ("proof", "message"),
    (
        (DeployJumpHostConfigureAuthorizationProof(), "approval is required"),
        (
            DeployJumpHostConfigureAuthorizationProof(
                approval_method=(DeployJumpHostConfigureApprovalMethod.INTERACTIVE),
                approved=False,
            ),
            "was denied",
        ),
        (
            DeployJumpHostConfigureAuthorizationProof(
                approval_method=DeployJumpHostConfigureApprovalMethod.CLI_YES,
                approved=True,
                allow_destructive=True,
            ),
            "inapplicable",
        ),
        (
            DeployJumpHostConfigureAuthorizationProof(
                approval_method=(DeployJumpHostConfigureApprovalMethod.INTERACTIVE),
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
    proof: DeployJumpHostConfigureAuthorizationProof,
    message: str,
) -> None:
    prepared, _runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    with pytest.raises(StateConflictError, match=message):
        _call(prepared, proof)
    assert not deploy_jump_host_configure_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_malformed_proof_no_scope_and_caller_scope_surface_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    with (
        ClusterLock(prepared.paths, "deploy", 0) as lock,
        pytest.raises(StateConflictError, match="malformed"),
    ):
        authorize_deploy_jump_host_configure(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=cast(DeployJumpHostConfigureAuthorizationProof, object()),
        )
    for forbidden in (
        "step",
        "playbook",
        "target",
        "target_ids",
        "limit",
        "variables",
        "commands",
        "paths",
        "classification",
        "scope",
        "prompt",
    ):
        assert (
            forbidden
            not in inspect.signature(authorize_deploy_jump_host_configure).parameters
        )
    monkeypatch.setattr(
        authorization_module, "_derive_authorization_scopes", lambda *_args: ()
    )
    with pytest.raises(StateConflictError, match="no evidence-ready scope"):
        _call(prepared, _interactive())


@pytest.mark.parametrize(
    "scope_drift",
    ("extra-target", "missing-target", "wrong-target", "wrong-step"),
)
def test_extra_missing_wrong_target_or_step_scope_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scope_drift: str,
) -> None:
    prepared, _runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    path = deploy_post_reboot_reconciliation_path(prepared.paths, OPERATION_ID)
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
        ready["target_digest"] = authorization_module._digest_object(
            ready["target_ids"]
        )
    elif scope_drift == "missing-target":
        ready["target_ids"] = []
        ready["target_digest"] = authorization_module._digest_object([])
    elif scope_drift == "wrong-target":
        ready["target_ids"] = ["scylla-ad-1-1"]
        ready["target_digest"] = authorization_module._digest_object(["scylla-ad-1-1"])
    else:
        ready["playbook"] = "storage-prepare"
    value["effective_plan_digest"] = authorization_module._digest_object(steps)
    value["record_digest"] = ""
    value["record_digest"] = authorization_module._digest_object(value)
    path.write_bytes(serialize_json(value))
    path.chmod(0o600)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, _interactive())
    assert not deploy_jump_host_configure_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()


@pytest.mark.parametrize(
    "drift",
    (
        "context",
        "original-plan",
        "effective-plan",
        "prerequisite",
        "pre-mutation",
        "host-reconciliation",
        "base-os-authorization",
        "base-os-execution",
        "base-os-evidence",
        "base-os-reconciliation",
        "reboot-evidence",
        "post-reboot",
        "inventory",
        "trust",
        "readiness",
        "source",
        "catalog",
        "journal",
    ),
)
def test_full_chain_source_catalog_readiness_and_journal_drift_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    paths = prepared.paths
    selected = {
        "context": paths.operations / f"{OPERATION_ID}.ansible-deploy-context.json",
        "original-plan": paths.operations / f"{OPERATION_ID}.ansible-deploy-plan.json",
        "effective-plan": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-effective-plan.json",
        "prerequisite": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-prerequisite-evidence.json",
        "pre-mutation": paths.operations
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
        "reboot-evidence": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-reboot-evidence.json",
        "post-reboot": deploy_post_reboot_reconciliation_path(paths, OPERATION_ID),
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
        _tamper_digest(
            selected[drift],
            (
                "inventory_digest"
                if drift == "inventory"
                else "entries_digest"
                if drift == "trust"
                else "request_digest"
                if drift == "journal"
                else "record_digest"
            ),
        )
    process_count = len(cast(list[object], runner.specs))

    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _call(prepared, _interactive())

    assert not deploy_jump_host_configure_authorization_path(
        paths, OPERATION_ID
    ).exists()
    assert len(cast(list[object], runner.specs)) == process_count


def test_uncertain_execution_conflicting_proof_and_write_failure_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    uncertain = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-jump-host-configure-execution.json"
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
    second, _runner, _executables, _toolchain = _prepared(second_root, monkeypatch)

    def fail_write(self, record, *, lock):
        del self, record, lock
        raise StatePersistenceError(f"simulated {_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(
        DeployJumpHostConfigureAuthorizationStore,
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
    assert not deploy_jump_host_configure_authorization_path(
        second.paths, OPERATION_ID
    ).exists()


def test_lock_path_symlink_permissions_ambiguity_and_zero_subprocess_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner, _executables, _toolchain = _prepared(tmp_path, monkeypatch)
    process_count = len(cast(list[object], runner.specs))
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        authorize_deploy_jump_host_configure(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            proof=_interactive(),
        )

    forged = replace(prepared.paths, operations=tmp_path / "outside")
    with pytest.raises(StatePersistenceError, match="not canonical"):
        DeployJumpHostConfigureAuthorizationStore(forged, OPERATION_ID)

    path = deploy_jump_host_configure_authorization_path(prepared.paths, OPERATION_ID)
    outside = tmp_path / "outside-authorization.json"
    outside.write_text("{}\n", encoding="utf-8")
    outside.chmod(0o600)
    path.symlink_to(outside)
    with pytest.raises(UnsafePathError):
        _call(prepared, _interactive())
    path.unlink()
    outside.unlink()

    reconciliation_path = deploy_post_reboot_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    reconciliation_path.chmod(0o644)
    with pytest.raises(UnsafePathError):
        _call(prepared, _interactive())
    reconciliation_path.chmod(0o600)

    ambiguous = prepared.paths.operations / (
        f"{{{OPERATION_ID}}}.ansible-deploy-jump-host-configure-authorization.json"
    )
    ambiguous.write_text("{}\n", encoding="utf-8")
    ambiguous.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _call(prepared, _interactive())
    ambiguous.unlink()

    def fail_subprocess(*args, **kwargs):
        del args, kwargs
        raise AssertionError("jump-host-configure authorization must not run a process")

    monkeypatch.setattr(subprocess, "run", fail_subprocess)
    report = _call(prepared, _interactive())
    assert report.execution_state == "unavailable"
    assert report.to_object()["execution"]["available"] is False
    assert len(cast(list[object], runner.specs)) == process_count


def _tamper_digest(path: Path, field: str) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    value[field] = "sha256:" + "d" * 64
    path.write_bytes(serialize_json(value))
    os.chmod(path, 0o600)
