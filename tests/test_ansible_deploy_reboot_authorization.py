import inspect
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from test_ansible_deploy_base_os_reconciliation import (
    _call as _reconcile_base_os,
)
from test_ansible_deploy_base_os_reconciliation import (
    _prepared as _base_os_reconciled_prepared,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_reboot_authorization as reboot_module
import scylla_vms.ansible.deploy_reconciliation as reconciliation_module
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    _load_context as _load_base_os_context,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    deploy_base_os_reconciliation_path,
)
from scylla_vms.ansible.deploy_reboot_authorization import (
    ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_REBOOT_PLAN_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_REBOOT_REPORT_SCHEMA_VERSION,
    DeployRebootApprovalMethod,
    DeployRebootArtifactState,
    DeployRebootAuthorizationProof,
    DeployRebootAuthorizationStore,
    DeployRebootPlanStore,
    _build_targets,
    _RebootCandidate,
    deploy_reboot_authorization_path,
    deploy_reboot_plan_path,
    plan_and_authorize_deploy_reboots,
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

_PRIVATE_PATH = "/private/operator/reboot-plan.json"
_SECRET = "obviously-fake-reboot-authorization-secret"


def _interactive() -> DeployRebootAuthorizationProof:
    return DeployRebootAuthorizationProof(
        approval_method=DeployRebootApprovalMethod.INTERACTIVE,
        approved=True,
    )


def _yes() -> DeployRebootAuthorizationProof:
    return DeployRebootAuthorizationProof(
        approval_method=DeployRebootApprovalMethod.CLI_YES,
        approved=True,
    )


def _prepared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    mode: str,
):
    prepared, inventory, runner = _base_os_reconciled_prepared(
        tmp_path,
        monkeypatch,
        mode=mode,
    )
    _reconcile_base_os(prepared)
    return prepared, inventory, runner


def _call(prepared, proof):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return plan_and_authorize_deploy_reboots(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=proof,
        )


def _records(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        plan = DeployRebootPlanStore(prepared.paths, OPERATION_ID).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        authorization = DeployRebootAuthorizationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    return plan, authorization


def test_no_reboot_is_strict_not_required_without_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, runner = _prepared(
        tmp_path,
        monkeypatch,
        mode="no-change",
    )
    process_count = len(runner.specs or ())
    show_before = _run_show(prepared.paths)

    report = _call(prepared, None)

    assert report.schema_version == ANSIBLE_DEPLOY_REBOOT_REPORT_SCHEMA_VERSION
    assert report.plan_state is DeployRebootArtifactState.NOT_REQUIRED
    assert report.authorization_artifact_state is DeployRebootArtifactState.NOT_REQUIRED
    assert report.target_count == 0
    assert report.role_counts == ()
    assert report.classification is None
    assert report.authorization_state == "not-required"
    assert report.approval_method is None
    assert report.execution_state == "unavailable"
    assert report.reconnect_state == "not-performed"
    assert not report.reconnect_checkpoint_required
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert not deploy_reboot_plan_path(prepared.paths, OPERATION_ID).exists()
    assert not deploy_reboot_authorization_path(prepared.paths, OPERATION_ID).exists()
    assert len(runner.specs or ()) == process_count
    assert _run_show(prepared.paths) == show_before

    with pytest.raises(StateConflictError, match="inapplicable"):
        _call(prepared, _interactive())


def test_exact_reboot_plan_authorization_and_idempotent_zero_process_reuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(inspect.signature(plan_and_authorize_deploy_reboots).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "proof",
    )
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch, mode="reboot")
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    reconciliation_path = deploy_base_os_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    source_bytes = (journal_path.read_bytes(), reconciliation_path.read_bytes())
    show_before = _run_show(prepared.paths)
    process_count = len(runner.specs or ())

    report = _call(prepared, _interactive())
    plan, authorization = _records(prepared)

    assert plan.record.schema_version == ANSIBLE_DEPLOY_REBOOT_PLAN_SCHEMA_VERSION
    assert (
        authorization.record.schema_version
        == ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_SCHEMA_VERSION
    )
    assert report.plan_state is DeployRebootArtifactState.CREATED
    assert report.authorization_artifact_state is DeployRebootArtifactState.CREATED
    assert report.target_count == 1
    assert report.role_counts == (("jump-host", 1),)
    assert report.serial == 1
    assert report.ordering_policy == "base-os-execution-then-stable-id/v1"
    assert report.classification is OperationClassification.MUTATING
    assert report.approval_method is DeployRebootApprovalMethod.INTERACTIVE
    assert report.authorization_state == "authorized-pre-execution"
    assert not report.authorization_consumed
    assert report.execution_state == "unavailable"
    assert report.reconnect_state == "not-performed"
    assert report.reconnect_checkpoint_required
    assert report.identity_trust_revalidation_required
    assert report.machine_evidence_required
    assert report.reboot_clear_verification_required
    assert report.blocker_set == ()
    assert plan.record.targets[0].stable_id == "jump-host-1"
    assert plan.record.targets[0].role is HostRole.JUMP_HOST
    assert plan.record.targets[0].route_relationship_count == 3
    assert plan.record.targets[0].reconnect_required
    assert plan.record.targets[0].identity_trust_revalidation_required
    assert plan.record.targets[0].machine_evidence_required
    assert plan.record.targets[0].reboot_clear_verification_required
    assert authorization.record.reboot_plan_artifact_digest == plan.artifact_digest
    assert authorization.record.target_order_digest == plan.record.target_order_digest
    assert authorization.record.inventory_digest == plan.record.inventory_digest
    assert (
        authorization.record.connectivity_evidence_digest
        == plan.record.connectivity_evidence_digest
    )
    assert authorization.record.blocker_digest == plan.record.blocker_digest
    assert not authorization.record.consumed
    assert journal_path.read_bytes() == source_bytes[0]
    assert reconciliation_path.read_bytes() == source_bytes[1]
    assert not tuple(prepared.paths.operations.glob("*reboot*execution*.json"))
    assert len(runner.specs or ()) == process_count
    assert _run_show(prepared.paths) == show_before

    plan_path = deploy_reboot_plan_path(prepared.paths, OPERATION_ID)
    authorization_path = deploy_reboot_authorization_path(prepared.paths, OPERATION_ID)
    plan_bytes = plan_path.read_bytes()
    authorization_bytes = authorization_path.read_bytes()
    mtimes = (plan_path.stat().st_mtime_ns, authorization_path.stat().st_mtime_ns)
    reused = _call(prepared, _interactive())
    assert reused.plan_state is DeployRebootArtifactState.REUSED
    assert reused.authorization_artifact_state is DeployRebootArtifactState.REUSED
    assert plan_path.read_bytes() == plan_bytes
    assert authorization_path.read_bytes() == authorization_bytes
    assert mtimes == (
        plan_path.stat().st_mtime_ns,
        authorization_path.stat().st_mtime_ns,
    )
    assert len(runner.specs or ()) == process_count
    assert plan_path.stat().st_mode & 0o777 == 0o600
    assert authorization_path.stat().st_mode & 0o777 == 0o600


def test_multiple_target_role_order_serial_and_jump_dependencies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch, mode="reboot")
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = _load_base_os_context(prepared.paths, OPERATION_ID, lock=lock)
    evidence_digest = context.evidence.record.entries[0].evidence_digest
    result_digest = context.evidence.record.entries[0].result_digest
    candidates = (
        _RebootCandidate(
            "monitoring-1", HostRole.MONITORING, 9, evidence_digest, result_digest
        ),
        _RebootCandidate(
            "scylla-ad-1-1", HostRole.SCYLLA, 7, evidence_digest, result_digest
        ),
        _RebootCandidate(
            "jump-host-1", HostRole.JUMP_HOST, 3, evidence_digest, result_digest
        ),
        _RebootCandidate(
            "manager-1", HostRole.MANAGER, 8, evidence_digest, result_digest
        ),
    )

    targets, blockers = _build_targets(context, candidates)

    assert blockers == ()
    assert tuple((target.stable_id, target.role) for target in targets) == (
        ("jump-host-1", HostRole.JUMP_HOST),
        ("scylla-ad-1-1", HostRole.SCYLLA),
        ("manager-1", HostRole.MANAGER),
        ("monitoring-1", HostRole.MONITORING),
    )
    assert tuple(target.sequence for target in targets) == (1, 2, 3, 4)
    assert targets[0].route_relationship_count == 3
    assert tuple(target.route_relationship_count for target in targets[1:]) == (
        1,
        1,
        1,
    )
    assert all(target.reconnect_required for target in targets)
    assert all(
        target.checkpoint_policy
        == "reconnect-identity-machine-reboot-clear-before-next/v1"
        for target in targets
    )

    unsafe_targets, unsafe_blockers = _build_targets(
        context,
        (
            replace(candidates[1], base_os_step_sequence=1),
            replace(candidates[2], base_os_step_sequence=2),
        ),
    )
    assert tuple(target.stable_id for target in unsafe_targets) == (
        "scylla-ad-1-1",
        "jump-host-1",
    )
    assert unsafe_blockers == ("jump-route-order-unresolved",)


def test_stable_order_blocker_persists_plan_without_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch, mode="reboot")
    process_count = len(runner.specs or ())
    original = reboot_module._build_targets

    def blocked(context, candidates):
        targets, _blockers = original(context, candidates)
        return targets, ("jump-route-order-unresolved",)

    monkeypatch.setattr(reboot_module, "_build_targets", blocked)
    report = _call(prepared, _interactive())

    assert report.plan_state is DeployRebootArtifactState.BLOCKED
    assert report.authorization_artifact_state is DeployRebootArtifactState.BLOCKED
    assert report.authorization_state == "blocked"
    assert report.approval_method is None
    assert report.blocker_set == ("jump-route-order-unresolved",)
    plan_path = deploy_reboot_plan_path(prepared.paths, OPERATION_ID)
    assert plan_path.exists()
    assert not deploy_reboot_authorization_path(prepared.paths, OPERATION_ID).exists()
    plan_bytes = plan_path.read_bytes()
    plan_mtime = plan_path.stat().st_mtime_ns
    repeated = _call(prepared, _interactive())
    assert repeated.plan_state is DeployRebootArtifactState.BLOCKED
    assert plan_path.read_bytes() == plan_bytes
    assert plan_path.stat().st_mtime_ns == plan_mtime
    assert len(runner.specs or ()) == process_count


@pytest.mark.parametrize(
    ("proof", "message"),
    (
        (None, "approval is required"),
        (DeployRebootAuthorizationProof(), "approval is required"),
        (
            DeployRebootAuthorizationProof(
                approval_method=DeployRebootApprovalMethod.INTERACTIVE,
                approved=False,
            ),
            "approval was denied",
        ),
    ),
)
def test_missing_and_denied_proof_leave_recoverable_plan_only_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    proof: DeployRebootAuthorizationProof | None,
    message: str,
) -> None:
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch, mode="reboot")
    process_count = len(runner.specs or ())

    with pytest.raises(StateConflictError, match=message):
        _call(prepared, proof)

    plan_path = deploy_reboot_plan_path(prepared.paths, OPERATION_ID)
    authorization_path = deploy_reboot_authorization_path(prepared.paths, OPERATION_ID)
    assert plan_path.exists()
    assert not authorization_path.exists()
    plan_bytes = plan_path.read_bytes()
    report = _call(prepared, _yes())
    assert report.plan_state is DeployRebootArtifactState.REUSED
    assert report.authorization_artifact_state is DeployRebootArtifactState.CREATED
    assert report.approval_method is DeployRebootApprovalMethod.CLI_YES
    assert plan_path.read_bytes() == plan_bytes
    assert len(runner.specs or ()) == process_count


@pytest.mark.parametrize(
    "proof",
    (
        DeployRebootAuthorizationProof(
            approval_method=DeployRebootApprovalMethod.INTERACTIVE,
            approved=True,
            allow_destructive=True,
        ),
        DeployRebootAuthorizationProof(
            approval_method=DeployRebootApprovalMethod.CLI_YES,
            approved=True,
            destructive_scope_provided=True,
        ),
    ),
)
def test_destructive_flags_are_inapplicable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    proof: DeployRebootAuthorizationProof,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch, mode="reboot")
    with pytest.raises(StateConflictError, match="destructive proof is inapplicable"):
        _call(prepared, proof)
    assert deploy_reboot_plan_path(prepared.paths, OPERATION_ID).exists()
    assert not deploy_reboot_authorization_path(prepared.paths, OPERATION_ID).exists()


def test_caller_target_and_order_surface_absent_and_conflicting_proof_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch, mode="reboot")
    signature = inspect.signature(plan_and_authorize_deploy_reboots)
    for forbidden in (
        "targets",
        "target_ids",
        "order",
        "commands",
        "variables",
        "paths",
        "classification",
        "reboot_policy",
    ):
        assert forbidden not in signature.parameters
    with pytest.raises(TypeError):
        plan_and_authorize_deploy_reboots(  # type: ignore[call-arg]
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=None,
            proof=_interactive(),
            target_ids=("extra",),
        )
    _call(prepared, _interactive())
    with pytest.raises(StateConflictError, match="authorization changed"):
        _call(prepared, _yes())


@pytest.mark.parametrize(
    "drift",
    (
        "base-os-evidence",
        "base-os-reconciliation",
        "connectivity",
        "trust",
        "readiness",
        "source",
        "catalog",
        "journal",
    ),
)
def test_stale_bound_chain_refused_without_reboot_tool_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch, mode="reboot")
    paths = prepared.paths
    if drift == "base-os-evidence":
        _tamper_digest(
            paths.operations / f"{OPERATION_ID}.ansible-deploy-base-os-evidence.json",
            "binding",
            nested="source_digest",
        )
    elif drift == "base-os-reconciliation":
        _tamper_digest(
            deploy_base_os_reconciliation_path(paths, OPERATION_ID),
            "record_digest",
        )
    elif drift == "connectivity":
        _tamper_digest(
            paths.operations
            / f"{OPERATION_ID}.ansible-deploy-prerequisite-evidence.json",
            "route_digest",
        )
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
        _tamper_digest(
            paths.operations / f"{OPERATION_ID}.json",
            "request_digest",
        )
    process_count = len(runner.specs or ())

    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _call(prepared, _interactive())

    assert not deploy_reboot_plan_path(paths, OPERATION_ID).exists()
    assert not deploy_reboot_authorization_path(paths, OPERATION_ID).exists()
    assert len(runner.specs or ()) == process_count


def test_write_failures_preserve_only_safe_prefix_and_redact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch, mode="reboot")
    process_count = len(runner.specs or ())
    original_plan = DeployRebootPlanStore.write_locked
    original_authorization = DeployRebootAuthorizationStore.write_locked

    def fail_plan(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(DeployRebootPlanStore, "write_locked", fail_plan)
    with pytest.raises(StatePersistenceError, match="plan persistence") as caught:
        _call(prepared, _interactive())
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    assert not deploy_reboot_plan_path(prepared.paths, OPERATION_ID).exists()

    monkeypatch.setattr(DeployRebootPlanStore, "write_locked", original_plan)

    def fail_authorization(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(
        DeployRebootAuthorizationStore,
        "write_locked",
        fail_authorization,
    )
    with pytest.raises(
        StatePersistenceError, match="authorization persistence"
    ) as caught:
        _call(prepared, _interactive())
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    assert deploy_reboot_plan_path(prepared.paths, OPERATION_ID).exists()
    assert not deploy_reboot_authorization_path(prepared.paths, OPERATION_ID).exists()

    monkeypatch.setattr(
        DeployRebootAuthorizationStore,
        "write_locked",
        original_authorization,
    )
    report = _call(prepared, _interactive())
    assert report.plan_state is DeployRebootArtifactState.REUSED
    assert report.authorization_artifact_state is DeployRebootArtifactState.CREATED
    assert len(runner.specs or ()) == process_count


def test_lock_path_symlink_permissions_redaction_and_zero_reboot_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch, mode="reboot")
    process_count = len(runner.specs or ())
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        plan_and_authorize_deploy_reboots(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            proof=_interactive(),
        )
    assert len(runner.specs or ()) == process_count

    plan_path = deploy_reboot_plan_path(prepared.paths, OPERATION_ID)
    target = prepared.paths.operations / "fake-reboot-target.json"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    plan_path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _call(prepared, _interactive())
    plan_path.unlink()
    target.unlink()

    reconciliation_path = deploy_base_os_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    reconciliation_path.chmod(0o644)
    with pytest.raises(UnsafePathError):
        _call(prepared, _interactive())
    reconciliation_path.chmod(0o600)

    report = _call(prepared, _interactive())
    persisted = plan_path.read_text(
        encoding="utf-8"
    ) + deploy_reboot_authorization_path(prepared.paths, OPERATION_ID).read_text(
        encoding="utf-8"
    )
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


def _tamper_digest(path: Path, field: str, *, nested: str | None = None) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    if nested is None:
        value[field] = "sha256:" + "d" * 64
    else:
        value[field][nested] = "sha256:" + "d" * 64
    path.write_bytes(serialize_json(value))
    os.chmod(path, 0o600)
