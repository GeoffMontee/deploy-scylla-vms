import inspect
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from test_ansible_deploy_non_jump_base_os_reconciliation import (
    _call as _reconcile_non_jump_base_os,
)
from test_ansible_deploy_non_jump_base_os_reconciliation import (
    _prepared as _non_jump_base_os_prepared,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_non_jump_reboot_authorization as reboot_module
import scylla_vms.ansible.deploy_reconciliation as reconciliation_module
from scylla_vms.ansible.deploy_non_jump_base_os_reconciliation import (
    deploy_post_non_jump_base_os_reconciliation_path,
)
from scylla_vms.ansible.deploy_non_jump_reboot_authorization import (
    ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_NON_JUMP_REBOOT_PLAN_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_NON_JUMP_REBOOT_REPORT_SCHEMA_VERSION,
    DeployNonJumpRebootApprovalMethod,
    DeployNonJumpRebootArtifactState,
    DeployNonJumpRebootAuthorizationProof,
    DeployNonJumpRebootAuthorizationStore,
    DeployNonJumpRebootPlanStore,
    deploy_non_jump_reboot_authorization_path,
    deploy_non_jump_reboot_plan_path,
    plan_and_authorize_deploy_non_jump_reboots,
)
from scylla_vms.ansible.source import load_ansible_source_bundle
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

_PRIVATE_PATH = "/private/operator/non-jump-reboot.json"
_SECRET = "obviously-fake-non-jump-reboot-secret"


def _interactive() -> DeployNonJumpRebootAuthorizationProof:
    return DeployNonJumpRebootAuthorizationProof(
        approval_method=DeployNonJumpRebootApprovalMethod.INTERACTIVE,
        approved=True,
    )


def _yes() -> DeployNonJumpRebootAuthorizationProof:
    return DeployNonJumpRebootAuthorizationProof(
        approval_method=DeployNonJumpRebootApprovalMethod.CLI_YES,
        approved=True,
    )


def _prepared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    mode: str,
):
    prepared, inventory, runner = _non_jump_base_os_prepared(
        tmp_path, monkeypatch, mode=mode
    )
    _reconcile_non_jump_base_os(prepared)
    return prepared, inventory, runner


def _call(prepared, proof):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return plan_and_authorize_deploy_non_jump_reboots(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=proof,
        )


def _records(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        plan = DeployNonJumpRebootPlanStore(prepared.paths, OPERATION_ID).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        authorization = DeployNonJumpRebootAuthorizationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    return plan, authorization


def test_no_reboot_is_strict_not_required_and_preserves_storage_discover(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch, mode="no-change")
    process_count = len(runner.specs or ())
    show_before = _run_show(prepared.paths)

    report = _call(prepared, None)

    assert report.schema_version == ANSIBLE_DEPLOY_NON_JUMP_REBOOT_REPORT_SCHEMA_VERSION
    assert report.plan_state is DeployNonJumpRebootArtifactState.NOT_REQUIRED
    assert (
        report.authorization_artifact_state
        is DeployNonJumpRebootArtifactState.NOT_REQUIRED
    )
    assert report.target_count == 0
    assert report.classification is None
    assert report.authorization_state == "not-required"
    assert report.storage_discover_branch_preserved
    assert not report.reconnect_required
    assert not deploy_non_jump_reboot_plan_path(prepared.paths, OPERATION_ID).exists()
    assert not deploy_non_jump_reboot_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()
    assert len(runner.specs or ()) == process_count
    assert _run_show(prepared.paths) == show_before
    with pytest.raises(StateConflictError, match="inapplicable"):
        _call(prepared, _interactive())


@pytest.mark.parametrize(
    ("mode", "expected_count"),
    (("mixed-reboot", 1), ("reboot", 3)),
)
def test_exact_non_jump_scope_order_routes_and_future_gates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    expected_count: int,
) -> None:
    assert tuple(
        inspect.signature(plan_and_authorize_deploy_non_jump_reboots).parameters
    ) == ("state_root", "cluster_name", "operation_id", "lock", "proof")
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch, mode=mode)
    process_count = len(runner.specs or ())
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    reconciliation_path = deploy_post_non_jump_base_os_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    immutable = (journal_path.read_bytes(), reconciliation_path.read_bytes())
    earlier_plan = (
        prepared.paths.operations / f"{OPERATION_ID}.ansible-deploy-reboot-plan.json"
    )
    earlier_authorization = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-reboot-authorization.json"
    )
    earlier_bytes = (earlier_plan.read_bytes(), earlier_authorization.read_bytes())

    report = _call(prepared, _interactive())
    plan, authorization = _records(prepared)

    assert plan.record.schema_version == (
        ANSIBLE_DEPLOY_NON_JUMP_REBOOT_PLAN_SCHEMA_VERSION
    )
    assert authorization.record.schema_version == (
        ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_SCHEMA_VERSION
    )
    assert authorization.record.proof.schema_version == (
        ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    assert report.target_count == expected_count
    assert report.serial == 1
    assert report.ordering_policy == ("non-jump-base-os-execution-then-stable-id/v1")
    assert report.classification is OperationClassification.MUTATING
    assert report.approval_method is DeployNonJumpRebootApprovalMethod.INTERACTIVE
    assert report.authorization_state == "authorized-pre-execution"
    assert not report.authorization_consumed
    assert report.execution_state == "unavailable"
    assert report.reconnect_state == "not-performed"
    assert report.reconnect_required
    assert report.identity_trust_revalidation_required
    assert report.machine_evidence_required
    assert report.service_safety_verification_required
    assert report.reboot_clear_verification_required
    assert not report.storage_discover_branch_preserved
    assert report.blocker_set == ()
    assert tuple(target.sequence for target in plan.record.targets) == tuple(
        range(1, expected_count + 1)
    )
    assert tuple(
        (
            target.base_os_attempt_index,
            target.base_os_step_sequence,
            target.base_os_target_index,
            target.stable_id,
        )
        for target in plan.record.targets
    ) == tuple(
        sorted(
            (
                target.base_os_attempt_index,
                target.base_os_step_sequence,
                target.base_os_target_index,
                target.stable_id,
            )
            for target in plan.record.targets
        )
    )
    assert all(target.role is not HostRole.JUMP_HOST for target in plan.record.targets)
    assert all(target.route_relationship_count >= 2 for target in plan.record.targets)
    assert all(target.reconnect_required for target in plan.record.targets)
    assert all(
        target.identity_trust_revalidation_required
        and target.machine_evidence_required
        and target.service_safety_verification_required
        and target.reboot_clear_verification_required
        for target in plan.record.targets
    )
    assert (
        authorization.record.plan_artifact_digest == plan.artifact_digest
        and authorization.record.target_set_digest == plan.record.target_set_digest
        and authorization.record.target_order_digest == plan.record.target_order_digest
        and authorization.record.route_relationship_digest
        == plan.record.route_relationship_digest
    )
    assert not authorization.record.consumed
    assert (journal_path.read_bytes(), reconciliation_path.read_bytes()) == immutable
    assert (earlier_plan.read_bytes(), earlier_authorization.read_bytes()) == (
        earlier_bytes
    )
    assert len(runner.specs or ()) == process_count
    assert not tuple(prepared.paths.operations.glob("*non-jump-reboot*execution*.json"))

    plan_path = deploy_non_jump_reboot_plan_path(prepared.paths, OPERATION_ID)
    authorization_path = deploy_non_jump_reboot_authorization_path(
        prepared.paths, OPERATION_ID
    )
    original = (plan_path.read_bytes(), authorization_path.read_bytes())
    mtimes = (plan_path.stat().st_mtime_ns, authorization_path.stat().st_mtime_ns)
    reused = _call(prepared, _interactive())
    assert reused.plan_state is DeployNonJumpRebootArtifactState.REUSED
    assert (
        reused.authorization_artifact_state is DeployNonJumpRebootArtifactState.REUSED
    )
    assert (plan_path.read_bytes(), authorization_path.read_bytes()) == original
    assert (plan_path.stat().st_mtime_ns, authorization_path.stat().st_mtime_ns) == (
        mtimes
    )
    assert plan_path.stat().st_mode & 0o777 == 0o600
    assert authorization_path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    ("proof", "message"),
    (
        (None, "approval is required"),
        (DeployNonJumpRebootAuthorizationProof(), "approval is required"),
        (
            DeployNonJumpRebootAuthorizationProof(
                approval_method=DeployNonJumpRebootApprovalMethod.INTERACTIVE,
                approved=False,
            ),
            "approval was denied",
        ),
    ),
)
def test_proof_policy_and_plan_only_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    proof: DeployNonJumpRebootAuthorizationProof | None,
    message: str,
) -> None:
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch, mode="reboot")
    process_count = len(runner.specs or ())
    with pytest.raises(StateConflictError, match=message):
        _call(prepared, proof)
    plan_path = deploy_non_jump_reboot_plan_path(prepared.paths, OPERATION_ID)
    authorization_path = deploy_non_jump_reboot_authorization_path(
        prepared.paths, OPERATION_ID
    )
    assert plan_path.exists()
    assert not authorization_path.exists()
    plan_bytes = plan_path.read_bytes()
    report = _call(prepared, _yes())
    assert report.plan_state is DeployNonJumpRebootArtifactState.REUSED
    assert (
        report.authorization_artifact_state is DeployNonJumpRebootArtifactState.CREATED
    )
    assert report.approval_method is DeployNonJumpRebootApprovalMethod.CLI_YES
    assert plan_path.read_bytes() == plan_bytes
    assert len(runner.specs or ()) == process_count


@pytest.mark.parametrize(
    "proof",
    (
        DeployNonJumpRebootAuthorizationProof(
            approval_method=DeployNonJumpRebootApprovalMethod.INTERACTIVE,
            approved=True,
            allow_destructive=True,
        ),
        DeployNonJumpRebootAuthorizationProof(
            approval_method=DeployNonJumpRebootApprovalMethod.CLI_YES,
            approved=True,
            destructive_scope_provided=True,
        ),
    ),
)
def test_destructive_proof_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    proof: DeployNonJumpRebootAuthorizationProof,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch, mode="reboot")
    with pytest.raises(StateConflictError, match="destructive proof is inapplicable"):
        _call(prepared, proof)
    assert deploy_non_jump_reboot_plan_path(prepared.paths, OPERATION_ID).exists()
    assert not deploy_non_jump_reboot_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_caller_scope_surface_absent_and_changed_proof_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch, mode="reboot")
    signature = inspect.signature(plan_and_authorize_deploy_non_jump_reboots)
    for forbidden in (
        "targets",
        "target_ids",
        "order",
        "routes",
        "commands",
        "variables",
        "paths",
        "classification",
    ):
        assert forbidden not in signature.parameters
    with pytest.raises(TypeError):
        plan_and_authorize_deploy_non_jump_reboots(  # type: ignore[call-arg]
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=None,
            proof=_interactive(),
            target_ids=("broader",),
        )
    _call(prepared, _interactive())
    with pytest.raises(StateConflictError, match="authorization changed"):
        _call(prepared, _yes())


@pytest.mark.parametrize(
    "drift",
    (
        "reconciliation",
        "non-jump-evidence",
        "final-routes",
        "inventory",
        "trust",
        "readiness",
        "source",
        "catalog",
        "journal",
    ),
)
def test_full_chain_and_scope_drift_refused_before_new_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch, mode="reboot")
    paths = prepared.paths
    if drift == "reconciliation":
        _tamper_digest(
            deploy_post_non_jump_base_os_reconciliation_path(paths, OPERATION_ID),
            "record_digest",
        )
    elif drift == "non-jump-evidence":
        _tamper_digest(
            paths.operations
            / f"{OPERATION_ID}.ansible-deploy-non-jump-base-os-evidence.json",
            "binding",
            nested="stable_id_set_digest",
        )
    elif drift == "final-routes":
        _tamper_digest(
            paths.operations
            / f"{OPERATION_ID}.ansible-deploy-final-routes-evidence.json",
            "evidence_digest",
        )
    elif drift == "inventory":
        value = json.loads(paths.ansible_inventory.read_text(encoding="utf-8"))
        value["unexpected"] = _SECRET
        paths.ansible_inventory.write_bytes(serialize_json(value))
        os.chmod(paths.ansible_inventory, 0o600)
    elif drift == "trust":
        _tamper_digest(paths.ansible_trust, "entries_digest")
    elif drift == "readiness":
        _tamper_digest(
            paths.terraform_plans / f"{OPERATION_ID}.terraform-apply-readiness.json",
            "record_digest",
        )
    elif drift == "source":
        source = load_ansible_source_bundle()
        monkeypatch.setattr(
            reconciliation_module,
            "load_ansible_source_bundle",
            lambda: replace(source, digest="sha256:" + "a" * 64),
        )
    elif drift == "catalog":
        monkeypatch.setattr(
            reconciliation_module,
            "ansible_operation_catalog_digest",
            lambda: "sha256:" + "b" * 64,
        )
    else:
        _tamper_digest(paths.operations / f"{OPERATION_ID}.json", "request_digest")
    process_count = len(runner.specs or ())
    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _call(prepared, _interactive())
    assert not deploy_non_jump_reboot_plan_path(paths, OPERATION_ID).exists()
    assert not deploy_non_jump_reboot_authorization_path(paths, OPERATION_ID).exists()
    assert len(runner.specs or ()) == process_count


def test_stable_blockers_persist_plan_without_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch, mode="reboot")
    process_count = len(runner.specs or ())
    original = reboot_module._build_targets

    def blocked(context, candidates):
        targets, _blockers = original(context, candidates)
        return targets, (
            "final-routes-connectivity-incomplete",
            "jump-route-dependency-unresolved",
            "reboot-order-unresolved",
        )

    monkeypatch.setattr(reboot_module, "_build_targets", blocked)
    report = _call(prepared, _interactive())
    assert report.plan_state is DeployNonJumpRebootArtifactState.BLOCKED
    assert (
        report.authorization_artifact_state is DeployNonJumpRebootArtifactState.BLOCKED
    )
    assert report.blocker_set == (
        "final-routes-connectivity-incomplete",
        "jump-route-dependency-unresolved",
        "reboot-order-unresolved",
    )
    assert deploy_non_jump_reboot_plan_path(prepared.paths, OPERATION_ID).exists()
    assert not deploy_non_jump_reboot_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()
    assert len(runner.specs or ()) == process_count


def test_write_failures_preserve_safe_prefix_and_redact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch, mode="reboot")
    process_count = len(runner.specs or ())
    original_plan = DeployNonJumpRebootPlanStore.write_locked
    original_authorization = DeployNonJumpRebootAuthorizationStore.write_locked

    def fail_plan(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(DeployNonJumpRebootPlanStore, "write_locked", fail_plan)
    with pytest.raises(StatePersistenceError, match="plan persistence") as caught:
        _call(prepared, _interactive())
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    assert not deploy_non_jump_reboot_plan_path(prepared.paths, OPERATION_ID).exists()
    monkeypatch.setattr(DeployNonJumpRebootPlanStore, "write_locked", original_plan)

    def fail_authorization(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(
        DeployNonJumpRebootAuthorizationStore,
        "write_locked",
        fail_authorization,
    )
    with pytest.raises(
        StatePersistenceError, match="authorization persistence"
    ) as caught:
        _call(prepared, _interactive())
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    assert deploy_non_jump_reboot_plan_path(prepared.paths, OPERATION_ID).exists()
    assert not deploy_non_jump_reboot_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()
    monkeypatch.setattr(
        DeployNonJumpRebootAuthorizationStore,
        "write_locked",
        original_authorization,
    )
    recovered = _call(prepared, _interactive())
    assert recovered.plan_state is DeployNonJumpRebootArtifactState.REUSED
    assert (
        recovered.authorization_artifact_state
        is DeployNonJumpRebootArtifactState.CREATED
    )
    assert len(runner.specs or ()) == process_count


def test_lock_path_ambiguity_redaction_and_zero_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch, mode="reboot")
    process_count = len(runner.specs or ())
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        plan_and_authorize_deploy_non_jump_reboots(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            proof=_interactive(),
        )
    plan_path = deploy_non_jump_reboot_plan_path(prepared.paths, OPERATION_ID)
    target = prepared.paths.operations / "fake-non-jump-reboot-target.json"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    plan_path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _call(prepared, _interactive())
    plan_path.unlink()
    target.unlink()

    reconciliation_path = deploy_post_non_jump_base_os_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    reconciliation_path.chmod(0o644)
    with pytest.raises(UnsafePathError):
        _call(prepared, _interactive())
    reconciliation_path.chmod(0o600)

    report = _call(prepared, _interactive())
    persisted = plan_path.read_text(
        encoding="utf-8"
    ) + deploy_non_jump_reboot_authorization_path(
        prepared.paths, OPERATION_ID
    ).read_text(encoding="utf-8")
    projected = json.dumps(report.to_object(), sort_keys=True)
    for forbidden in (
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "ssh-ed25519",
        "fingerprint",
        "ProxyJump",
        "PLAY RECAP",
        "ansible-playbook",
        "--limit",
        "environment",
        _PRIVATE_PATH,
        _SECRET,
    ):
        assert forbidden not in persisted
        assert forbidden not in projected
    assert "deploy_scylla_vms_" not in projected
    assert len(runner.specs or ()) == process_count
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY


def _tamper_digest(path: Path, field: str, *, nested: str | None = None) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    if nested is None:
        value[field] = "sha256:" + "d" * 64
    else:
        value[field][nested] = "sha256:" + "d" * 64
    path.write_bytes(serialize_json(value))
    os.chmod(path, 0o600)
