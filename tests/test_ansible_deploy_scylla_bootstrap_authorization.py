import inspect
import json
from dataclasses import replace
from pathlib import Path

import pytest
from test_ansible_deploy_scylla_bootstrap_plan import (
    _call as _plan_bootstrap,
)
from test_ansible_deploy_scylla_bootstrap_plan import (
    _prepared,
    _records,
    _target,
)
from test_ansible_deploy_scylla_bootstrap_plan import (
    _proof as _new_cluster_proof,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_scylla_bootstrap_authorization import (
    ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_PROOF_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_SCHEMA_VERSION,
    DeployScyllaBootstrapApprovalMethod,
    DeployScyllaBootstrapAuthorizationArtifactState,
    DeployScyllaBootstrapAuthorizationProof,
    DeployScyllaBootstrapAuthorizationStore,
    DeployScyllaBootstrapNarrowApprovalMethod,
    DeployScyllaBootstrapNarrowScopeProof,
    _partition_authorizable_steps,
    authorize_deploy_scylla_bootstrap_initial_seed,
    deploy_scylla_bootstrap_authorization_id_from_filename,
    deploy_scylla_bootstrap_authorization_path,
)
from scylla_vms.ansible.deploy_scylla_bootstrap_plan import (
    DeployScyllaBootstrapProofState,
    _build_plan_steps,
)
from scylla_vms.ansible.operation_authorization import ConfirmationPolicy
from scylla_vms.ansible.scylla_bootstrap import ScyllaBootstrapMode
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification

_PRIVATE_PATH = "/private/operator/bootstrap-authorization.json"
_SECRET = "obviously-fake-bootstrap-authorization-secret"
_OTHER_DIGEST = "sha256:" + "f" * 64


def _planned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, runner = _prepared(tmp_path, monkeypatch)
    _plan_bootstrap(prepared, _new_cluster_proof())
    return prepared, runner


def _narrow_scope(prepared) -> DeployScyllaBootstrapNarrowScopeProof:
    context, plan = _records(prepared)
    return DeployScyllaBootstrapNarrowScopeProof.from_plan(context.record, plan.record)


def _proof(
    prepared,
    *,
    approval_method: DeployScyllaBootstrapApprovalMethod | None = (
        DeployScyllaBootstrapApprovalMethod.INTERACTIVE
    ),
    approved: bool = True,
    narrow_method: DeployScyllaBootstrapNarrowApprovalMethod | None = (
        DeployScyllaBootstrapNarrowApprovalMethod.INTERACTIVE
    ),
    narrow_approved: bool = True,
    narrow_scope: DeployScyllaBootstrapNarrowScopeProof | None = None,
    allow_destructive: bool = False,
    destructive_scope_provided: bool = False,
) -> DeployScyllaBootstrapAuthorizationProof:
    return DeployScyllaBootstrapAuthorizationProof(
        approval_method=approval_method,
        approved=approved,
        narrow_approval_method=narrow_method,
        narrow_approved=narrow_approved,
        narrow_scope=_narrow_scope(prepared) if narrow_scope is None else narrow_scope,
        allow_destructive=allow_destructive,
        destructive_scope_provided=destructive_scope_provided,
    )


def _call(prepared, proof: DeployScyllaBootstrapAuthorizationProof):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return authorize_deploy_scylla_bootstrap_initial_seed(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=proof,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployScyllaBootstrapAuthorizationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


def test_exact_initial_seed_authorization_is_immutable_redacted_and_process_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(
        inspect.signature(authorize_deploy_scylla_bootstrap_initial_seed).parameters
    ) == ("state_root", "cluster_name", "operation_id", "lock", "proof")
    for forbidden in (
        "target",
        "mode",
        "order",
        "topology",
        "seed",
        "version",
        "storage",
        "configuration",
        "command",
        "variable",
        "path",
    ):
        assert (
            forbidden
            not in inspect.signature(
                authorize_deploy_scylla_bootstrap_initial_seed
            ).parameters
        )

    prepared, runner = _planned(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    authorization_path = deploy_scylla_bootstrap_authorization_path(
        prepared.paths, OPERATION_ID
    )
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()
    show_before = _run_show(prepared.paths)
    proof = _proof(prepared)

    report = _call(prepared, proof)
    first_bytes = authorization_path.read_bytes()
    reused = _call(prepared, proof)
    stored = _record(prepared)
    show_after = _run_show(prepared.paths)

    assert report.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )
    assert (
        stored.record.schema_version
        == ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_SCHEMA_VERSION
    )
    assert (
        stored.record.proof.schema_version
        == ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    assert (
        report.artifact_state is DeployScyllaBootstrapAuthorizationArtifactState.CREATED
    )
    assert (
        reused.artifact_state is DeployScyllaBootstrapAuthorizationArtifactState.REUSED
    )
    assert authorization_path.read_bytes() == first_bytes
    assert authorization_path.stat().st_mode & 0o777 == 0o600
    assert journal_path.read_bytes() == journal_before
    assert show_after == show_before
    assert len(runner.specs) == process_count

    context, plan = _records(prepared)
    first = plan.record.steps[0]
    scope = stored.record.scope
    assert report.classification is OperationClassification.SENSITIVE
    assert report.confirmation_policy is ConfirmationPolicy.SENSITIVE
    assert report.mode is ScyllaBootstrapMode.INITIAL_SEED
    assert report.target_count == 1
    assert report.join_waiting_count == 0
    assert report.consumed is False
    assert report.execution_state == "unavailable"
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert scope.target_digest == first.target_digest
    assert scope.plan_step_digest == first.step_digest
    assert scope.order_digest == plan.record.order_digest
    assert scope.topology_digest == context.record.topology_digest
    assert scope.seed_policy_digest == first.seed_policy_digest
    assert scope.package_version_digest == first.package_version_digest
    assert scope.storage_evidence_digest == first.storage_evidence_digest
    assert scope.configuration_evidence_digest == first.configuration_evidence_digest
    assert scope.capacity_evidence_digest == first.capacity_evidence_digest
    assert scope.empty_cluster_proof_digest == context.record.proof_digest
    assert stored.record.proof.authorization_scope_digest == scope.scope_digest

    public = (
        first_bytes.decode()
        + json.dumps(report.to_object(), sort_keys=True)
        + json.dumps(stored.record.to_object(), sort_keys=True)
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
        '"host_id"',
        '"provider_id"',
        '"variables"',
        '"command"',
        '"path"',
    ):
        assert protected not in public
    assert (
        deploy_scylla_bootstrap_authorization_id_from_filename(authorization_path.name)
        == OPERATION_ID
    )


def test_sensitive_confirmation_requires_separate_exact_scope_and_rejects_destructive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _planned(tmp_path, monkeypatch)
    exact = _narrow_scope(prepared)
    wrong = replace(exact, authorization_scope_digest=_OTHER_DIGEST)
    invalid = (
        (
            DeployScyllaBootstrapAuthorizationProof(
                narrow_approval_method=(
                    DeployScyllaBootstrapNarrowApprovalMethod.INTERACTIVE
                ),
                narrow_approved=True,
                narrow_scope=exact,
            ),
            "ordinary",
        ),
        (_proof(prepared, approved=False), "denied"),
        (
            _proof(prepared, narrow_method=None, narrow_approved=False),
            "exact initial-seed",
        ),
        (_proof(prepared, narrow_approved=False), "exact initial-seed"),
        (_proof(prepared, narrow_scope=wrong), "does not match"),
        (_proof(prepared, allow_destructive=True), "inapplicable"),
        (_proof(prepared, destructive_scope_provided=True), "inapplicable"),
    )
    path = deploy_scylla_bootstrap_authorization_path(prepared.paths, OPERATION_ID)
    for proof, match in invalid:
        with pytest.raises(StateConflictError, match=match):
            _call(prepared, proof)
        assert not path.exists()

    report = _call(
        prepared,
        _proof(
            prepared,
            approval_method=DeployScyllaBootstrapApprovalMethod.CLI_YES,
            narrow_method=DeployScyllaBootstrapNarrowApprovalMethod.CLI_EXPLICIT,
        ),
    )
    assert report.approval_method is DeployScyllaBootstrapApprovalMethod.CLI_YES
    assert (
        report.narrow_approval_method
        is DeployScyllaBootstrapNarrowApprovalMethod.CLI_EXPLICIT
    )


def test_only_initial_seed_is_authorizable_and_joins_remain_waiting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _planned(tmp_path, monkeypatch)
    context, _plan = _records(prepared)
    targets = (
        _target("node-b", rack="rack-b"),
        _target("node-a", rack="rack-a", seed=True),
        _target("node-c", rack="rack-c"),
    )
    steps = _build_plan_steps(context.record, targets)
    initial, joins = _partition_authorizable_steps(steps)

    assert initial.sequence == 1
    assert initial.mode is ScyllaBootstrapMode.INITIAL_SEED
    assert len(joins) == 2
    assert all(
        step.mode is ScyllaBootstrapMode.JOIN_EXISTING
        and step.status.value == "waiting-for-health-checkpoint"
        and step.health_checkpoint_state == "waiting-for-preceding-complete-health"
        and "complete-cluster-health-not-performed" in step.blockers
        and "bootstrap-authorization-not-collected" in step.blockers
        for step in joins
    )
    report = _call(prepared, _proof(prepared))
    assert report.target_count == 1
    assert report.mode is ScyllaBootstrapMode.INITIAL_SEED


def test_incomplete_empty_cluster_proof_cannot_be_bypassed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _prepared(tmp_path, monkeypatch)
    _plan_bootstrap(
        prepared,
        _new_cluster_proof(
            capacity=DeployScyllaBootstrapProofState.UNKNOWN,
        ),
    )
    context, plan = _records(prepared)
    assert context.record.empty_cluster_state == "blocked"
    assert plan.record.authorization_required_count == 0
    fake_scope = DeployScyllaBootstrapNarrowScopeProof(
        target_count=1,
        target_digest=plan.record.steps[0].target_digest,
        plan_step_digest=plan.record.steps[0].step_digest,
        authorization_scope_digest=_OTHER_DIGEST,
    )
    proof = DeployScyllaBootstrapAuthorizationProof(
        approval_method=DeployScyllaBootstrapApprovalMethod.INTERACTIVE,
        approved=True,
        narrow_approval_method=DeployScyllaBootstrapNarrowApprovalMethod.INTERACTIVE,
        narrow_approved=True,
        narrow_scope=fake_scope,
    )

    with pytest.raises(StateConflictError, match="empty-cluster proof"):
        _call(prepared, proof)
    assert not deploy_scylla_bootstrap_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()


@pytest.mark.parametrize(
    "field",
    (
        "target_digest",
        "topology_digest",
        "seed_policy_digest",
        "package_version_digest",
        "storage_evidence_digest",
        "configuration_evidence_digest",
        "capacity_evidence_digest",
        "prerequisite_digest",
        "playbook_source_digest",
    ),
)
def test_target_topology_seed_version_storage_config_capacity_and_source_drift_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    prepared, _runner = _planned(tmp_path, monkeypatch)
    proof = _proof(prepared)
    plan_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-scylla-bootstrap-plan.json"
    )
    value = json.loads(plan_path.read_text(encoding="utf-8"))
    value["steps"][0][field] = _OTHER_DIGEST
    plan_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    plan_path.chmod(0o600)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, proof)
    assert not deploy_scylla_bootstrap_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_trust_readiness_identity_service_and_plan_drift_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _runner = _planned(tmp_path, monkeypatch)
    proof = _proof(prepared)
    trust_path = prepared.paths.ansible_trust
    original_trust = trust_path.read_bytes()
    trust = json.loads(original_trust)
    trust["generation"] += 1
    trust_path.write_text(json.dumps(trust) + "\n", encoding="utf-8")
    trust_path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, proof)
    trust_path.write_bytes(original_trust)
    trust_path.chmod(0o600)

    context_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-scylla-bootstrap-context.json"
    )
    original_context = context_path.read_bytes()
    context = json.loads(original_context)
    context["service_safe_count"] = 0
    context_path.write_text(json.dumps(context) + "\n", encoding="utf-8")
    context_path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, proof)
    context_path.write_bytes(original_context)
    context_path.chmod(0o600)

    with (
        ClusterLock(prepared.paths, "deploy", 0) as lock,
        pytest.raises((StateLockError, StateConflictError)),
    ):
        authorize_deploy_scylla_bootstrap_initial_seed(
            state_root=prepared.paths.state_root,
            cluster_name="other-cluster",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=proof,
        )


def test_later_history_write_failure_wrong_lock_and_unsafe_path_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, runner = _planned(tmp_path, monkeypatch)
    assert runner.specs is not None
    process_count = len(runner.specs)
    proof = _proof(prepared)
    path = deploy_scylla_bootstrap_authorization_path(prepared.paths, OPERATION_ID)
    later = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-scylla-bootstrap-execution.json"
    )
    later.write_text("{}\n", encoding="utf-8")
    later.chmod(0o600)
    with pytest.raises(StateConflictError, match="later membership"):
        _call(prepared, proof)
    later.unlink()
    assert not path.exists()

    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        authorize_deploy_scylla_bootstrap_initial_seed(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            proof=proof,
        )

    original_write = DeployScyllaBootstrapAuthorizationStore.write_locked

    def fail_write(*args, **kwargs):
        del args, kwargs
        raise StatePersistenceError(f"injected {_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(
        DeployScyllaBootstrapAuthorizationStore, "write_locked", fail_write
    )
    with pytest.raises(StatePersistenceError, match="persistence failed"):
        _call(prepared, proof)
    assert not path.exists()
    monkeypatch.setattr(
        DeployScyllaBootstrapAuthorizationStore, "write_locked", original_write
    )

    _call(prepared, proof)
    target = path.with_name(f"{path.name}.target")
    path.rename(target)
    path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _record(prepared)
    assert len(runner.specs) == process_count
