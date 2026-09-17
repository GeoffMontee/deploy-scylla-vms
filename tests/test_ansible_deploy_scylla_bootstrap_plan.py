import inspect
import json
from dataclasses import replace
from pathlib import Path

import pytest
from test_ansible_deploy_scylla_configure_reconciliation import (
    _call as _reconcile_configure,
)
from test_ansible_deploy_scylla_configure_reconciliation import (
    _complete as _complete_configure,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_plan import _digest_object
from scylla_vms.ansible.deploy_scylla_bootstrap_plan import (
    ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_SCHEMA_VERSION,
    DeployScyllaBootstrapArtifactState,
    DeployScyllaBootstrapContextStore,
    DeployScyllaBootstrapNewClusterProof,
    DeployScyllaBootstrapPlanStore,
    DeployScyllaBootstrapProofState,
    DeployScyllaBootstrapStepStatus,
    _BootstrapTarget,
    _build_plan_steps,
    _empty_cluster_blockers,
    _EmptyClusterFacts,
    _order_targets,
    deploy_scylla_bootstrap_context_id_from_filename,
    deploy_scylla_bootstrap_context_path,
    deploy_scylla_bootstrap_plan_id_from_filename,
    deploy_scylla_bootstrap_plan_path,
    plan_deploy_scylla_bootstrap,
)
from scylla_vms.ansible.scylla_bootstrap import ScyllaBootstrapMode
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock

_PRIVATE_PATH = "/private/operator/bootstrap-plan.json"
_SECRET = "obviously-fake-bootstrap-plan-secret"


def _proof(
    *,
    capacity: DeployScyllaBootstrapProofState = (
        DeployScyllaBootstrapProofState.CONFIRMED
    ),
) -> DeployScyllaBootstrapNewClusterProof:
    return DeployScyllaBootstrapNewClusterProof(
        new_cluster_intent=DeployScyllaBootstrapProofState.CONFIRMED,
        empty_cluster_review=DeployScyllaBootstrapProofState.CONFIRMED,
        prior_membership_absence=DeployScyllaBootstrapProofState.CONFIRMED,
        capacity_sufficiency=capacity,
    )


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, runner = _complete_configure(tmp_path, monkeypatch)
    _reconcile_configure(prepared)
    return prepared, runner


def _call(prepared, proof: DeployScyllaBootstrapNewClusterProof | None):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return plan_deploy_scylla_bootstrap(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=proof,
        )


def _records(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = DeployScyllaBootstrapContextStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        plan = DeployScyllaBootstrapPlanStore(prepared.paths, OPERATION_ID).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    return context, plan


def _target(
    stable_id: str,
    *,
    rack: str,
    seed: bool = False,
) -> _BootstrapTarget:
    def digest(value: str) -> str:
        return _digest_object(f"{stable_id}:{value}")

    return _BootstrapTarget(
        stable_id=stable_id,
        datacenter="dc1",
        rack=rack,
        target_digest=digest("target"),
        datacenter_digest=digest("dc"),
        rack_digest=digest("rack"),
        package_version_digest=digest("version"),
        storage_evidence_digest=digest("storage"),
        configuration_evidence_digest=digest("configuration"),
        topology_digest=digest("topology"),
        seed_policy_digest=digest("seed"),
        capacity_evidence_digest=digest("capacity"),
        playbook_source_digest=digest("source"),
        is_configured_seed=seed,
    )


def test_complete_empty_cluster_plan_is_immutable_redacted_and_process_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signature = inspect.signature(plan_deploy_scylla_bootstrap)
    assert tuple(signature.parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "proof",
    )
    for forbidden in (
        "target",
        "order",
        "mode",
        "seed",
        "topology",
        "variable",
        "command",
    ):
        assert forbidden not in signature.parameters

    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    context_path = deploy_scylla_bootstrap_context_path(prepared.paths, OPERATION_ID)
    plan_path = deploy_scylla_bootstrap_plan_path(prepared.paths, OPERATION_ID)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()
    show_before = _run_show(prepared.paths)

    report = _call(prepared, _proof())
    context_bytes = context_path.read_bytes()
    plan_bytes = plan_path.read_bytes()
    reused = _call(prepared, _proof())
    context, plan = _records(prepared)
    show_after = _run_show(prepared.paths)

    assert report.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_REPORT_SCHEMA_VERSION
    )
    assert (
        context.record.schema_version
        == ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION
    )
    assert (
        plan.record.schema_version
        == ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_SCHEMA_VERSION
    )
    assert report.context_state is DeployScyllaBootstrapArtifactState.CREATED
    assert report.plan_state is DeployScyllaBootstrapArtifactState.CREATED
    assert reused.context_state is DeployScyllaBootstrapArtifactState.REUSED
    assert reused.plan_state is DeployScyllaBootstrapArtifactState.REUSED
    assert context_path.read_bytes() == context_bytes
    assert plan_path.read_bytes() == plan_bytes
    assert context_path.stat().st_mode & 0o777 == 0o600
    assert plan_path.stat().st_mode & 0o777 == 0o600
    assert journal_path.read_bytes() == journal_before
    assert len(runner.specs) == process_count
    assert show_after == show_before

    assert report.empty_cluster_state == "proven-empty-new-cluster"
    assert report.target_count == report.initial_seed_count == 1
    assert report.join_count == report.waiting_health_count == 0
    assert report.authorization_required_count == 1
    assert report.blocked_count == 0
    assert report.expected_host_id_unknown_count == 1
    assert report.authorization_state == "unavailable"
    assert report.execution_state == "unavailable"
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert context.record.terraform_pre_apply_state.value in {"absent", "present"}
    assert context.record.terraform_plan_change_class.value == "create-only"
    assert context.record.terraform_plan_drift_class.value == "none"
    assert context.record.service_safe_count == context.record.target_count
    assert context.record.service_never_started_count == context.record.target_count
    assert plan.record.original_mapping_count == 21
    assert plan.record.original_mapping_unchanged
    assert plan.record.serial == 1
    assert len(plan.record.steps) == 1
    first = plan.record.steps[0]
    assert first.mode is ScyllaBootstrapMode.INITIAL_SEED
    assert first.status is DeployScyllaBootstrapStepStatus.AUTHORIZATION_REQUIRED
    assert first.expected_host_id_state == "unknown-before-start"
    assert first.preceding_step_digest is None
    assert first.blockers == ("bootstrap-authorization-not-collected",)

    public = (
        context_bytes.decode()
        + plan_bytes.decode()
        + json.dumps(report.to_object(), sort_keys=True)
    )
    for protected in (
        _PRIVATE_PATH,
        _SECRET,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "/var/lib/scylla",
        "/etc/scylla",
        "SimpleSeedProvider",
        "ansible-playbook",
        "--limit",
        '"stable_id"',
        '"seed_stable_ids"',
        '"config"',
        '"provider_id"',
        '"host_id"',
    ):
        assert protected not in public
    assert (
        deploy_scylla_bootstrap_context_id_from_filename(context_path.name)
        == OPERATION_ID
    )
    assert deploy_scylla_bootstrap_plan_id_from_filename(plan_path.name) == OPERATION_ID


@pytest.mark.parametrize(
    ("proof", "blocker"),
    (
        (None, "empty-cluster-review-not-proven"),
        (
            _proof(capacity=DeployScyllaBootstrapProofState.UNKNOWN),
            "capacity-sufficiency-not-proven",
        ),
    ),
)
def test_incomplete_review_or_capacity_blocks_initial_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    proof: DeployScyllaBootstrapNewClusterProof | None,
    blocker: str,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    report = _call(prepared, proof)
    context, plan = _records(prepared)

    assert report.empty_cluster_state == "blocked"
    assert report.authorization_required_count == 0
    assert report.blocked_count == 1
    assert blocker in context.record.blockers
    assert plan.record.steps[0].status is DeployScyllaBootstrapStepStatus.BLOCKED
    assert blocker in plan.record.steps[0].blockers


def test_prior_state_and_service_unknowns_are_empty_cluster_blockers() -> None:
    complete = _EmptyClusterFacts(
        terraform_initial_state_proven=True,
        terraform_create_only=True,
        terraform_drift_free=True,
        terraform_initial_progression=True,
        services_masked_inactive=True,
        services_never_started=True,
        topology_complete=True,
        seed_policy_complete=True,
        storage_capacity_complete=True,
        prior_membership_artifacts_absent=True,
    )
    assert not _empty_cluster_blockers(_proof(), complete)
    assert "terraform-initial-state-proof-not-proven" in _empty_cluster_blockers(
        _proof(), replace(complete, terraform_initial_state_proven=False)
    )
    assert "scylla-never-started-not-proven" in _empty_cluster_blockers(
        _proof(), replace(complete, services_never_started=False)
    )
    assert "storage-capacity-not-proven" in _empty_cluster_blockers(
        _proof(), replace(complete, storage_capacity_complete=False)
    )


def test_deterministic_seed_topology_order_and_join_health_checkpoints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    _call(prepared, _proof())
    context, _plan = _records(prepared)
    targets = (
        _target("node-c", rack="rack-b"),
        _target("node-b", rack="rack-a"),
        _target("node-a", rack="rack-z", seed=True),
        _target("node-d", rack="rack-a"),
    )
    ordered = _order_targets(targets)
    assert tuple(item.stable_id for item in ordered) == (
        "node-a",
        "node-b",
        "node-d",
        "node-c",
    )
    assert _order_targets(tuple(reversed(targets))) == ordered

    steps = _build_plan_steps(context.record, ordered)
    assert steps[0].mode is ScyllaBootstrapMode.INITIAL_SEED
    assert steps[0].status is DeployScyllaBootstrapStepStatus.AUTHORIZATION_REQUIRED
    assert all(
        step.mode is ScyllaBootstrapMode.JOIN_EXISTING
        and step.status is DeployScyllaBootstrapStepStatus.WAITING_FOR_HEALTH_CHECKPOINT
        and step.preceding_step_digest == steps[index - 1].step_digest
        and step.expected_host_id_state == "unknown-before-start"
        and {
            "complete-cluster-health-not-performed",
            "healthy-survivor-evidence-not-performed",
            "target-absence-not-proven",
            "capacity-evidence-not-performed",
            "schema-agreement-not-performed",
        }
        <= set(step.blockers)
        for index, step in enumerate(steps[1:], start=1)
    )


def test_prior_bootstrap_artifact_conflict_and_chain_drift_write_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    conflict = prepared.paths.operations / (
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb."
        "ansible-deploy-scylla-bootstrap-evidence.json"
    )
    conflict.write_text("{}\n", encoding="utf-8")
    conflict.chmod(0o600)
    with pytest.raises(StateConflictError, match="bootstrap/membership"):
        _call(prepared, _proof())
    assert not deploy_scylla_bootstrap_context_path(
        prepared.paths, OPERATION_ID
    ).exists()
    assert not deploy_scylla_bootstrap_plan_path(prepared.paths, OPERATION_ID).exists()
    conflict.unlink()

    trust_path = prepared.paths.ansible_trust
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    trust["generation"] += 1
    trust_path.write_text(json.dumps(trust) + "\n", encoding="utf-8")
    trust_path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, _proof())
    assert not deploy_scylla_bootstrap_context_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_context_only_prefix_recovers_without_process_or_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _prepared(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    original = DeployScyllaBootstrapPlanStore.write_locked

    def fail_plan(*args, **kwargs):
        del args, kwargs
        raise StatePersistenceError("injected plan persistence failure")

    monkeypatch.setattr(DeployScyllaBootstrapPlanStore, "write_locked", fail_plan)
    with pytest.raises(StatePersistenceError, match="injected"):
        _call(prepared, _proof())
    context_path = deploy_scylla_bootstrap_context_path(prepared.paths, OPERATION_ID)
    assert context_path.exists()
    context_bytes = context_path.read_bytes()
    assert not deploy_scylla_bootstrap_plan_path(prepared.paths, OPERATION_ID).exists()

    monkeypatch.setattr(DeployScyllaBootstrapPlanStore, "write_locked", original)
    report = _call(prepared, _proof())
    assert report.context_state is DeployScyllaBootstrapArtifactState.REUSED
    assert report.plan_state is DeployScyllaBootstrapArtifactState.CREATED
    assert context_path.read_bytes() == context_bytes
    assert len(runner.specs) == process_count


def test_wrong_lock_unsafe_path_and_plan_without_context_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        plan_deploy_scylla_bootstrap(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            proof=_proof(),
        )

    plan_path = deploy_scylla_bootstrap_plan_path(prepared.paths, OPERATION_ID)
    plan_path.write_text("{}\n", encoding="utf-8")
    plan_path.chmod(0o600)
    with pytest.raises(StateConflictError, match="without its context"):
        _call(prepared, _proof())
    plan_path.unlink()

    _call(prepared, _proof())
    context_path = deploy_scylla_bootstrap_context_path(prepared.paths, OPERATION_ID)
    target = context_path.with_name(f"{context_path.name}.target")
    context_path.rename(target)
    context_path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _records(prepared)
