import inspect
import json
import stat
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from test_ansible_deploy_scylla_join_safety import (
    _call as _bind_join_safety,
)
from test_ansible_deploy_scylla_join_safety import (
    _prepared as _prepared_join_safety,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_plan import _digest_object
from scylla_vms.ansible.deploy_scylla_join_authorization import (
    ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_SCHEMA_VERSION,
    DeployScyllaJoinApprovalMethod,
    DeployScyllaJoinAuthorizationArtifactState,
    DeployScyllaJoinAuthorizationProof,
    DeployScyllaJoinAuthorizationStore,
    DeployScyllaJoinNarrowApprovalMethod,
    DeployScyllaJoinNarrowScopeProof,
    _derive_first_join_scope,
    _load_join_authorization_context,
    authorize_deploy_scylla_join_existing,
    deploy_scylla_join_authorization_id_from_filename,
    deploy_scylla_join_authorization_path,
)
from scylla_vms.ansible.deploy_scylla_join_safety import (
    DeployScyllaJoinSafetyProofStatus,
    DeployScyllaJoinSafetyStepStatus,
    _evidence_digest_from_values,
    _gate_digest_from_values,
    deploy_scylla_join_safety_evidence_path,
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

_OTHER_DIGEST = "sha256:" + "f" * 64
_PRIVATE_PATH = "/private/operator/join-authorization.json"
_SECRET = "obviously-fake-join-authorization-secret"
_REQUIRED_GATES = (
    "capacity",
    "completed-prior-membership",
    "schema",
    "seed-health",
    "streaming",
    "survivor-health",
    "target-absence",
    "topology",
)


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared = _prepared_join_safety(tmp_path, monkeypatch)
    _bind_join_safety(prepared, DeployScyllaJoinSafetyProofStatus.PASSED)
    return prepared


def _narrow_scope(prepared) -> DeployScyllaJoinNarrowScopeProof:
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        loaded = _load_join_authorization_context(
            prepared.paths, OPERATION_ID, lock=lock
        )
        return DeployScyllaJoinNarrowScopeProof.from_scope(
            _derive_first_join_scope(loaded)
        )


def _proof(
    prepared,
    *,
    approval_method: DeployScyllaJoinApprovalMethod | None = (
        DeployScyllaJoinApprovalMethod.INTERACTIVE
    ),
    approved: bool = True,
    narrow_method: DeployScyllaJoinNarrowApprovalMethod | None = (
        DeployScyllaJoinNarrowApprovalMethod.INTERACTIVE
    ),
    narrow_approved: bool = True,
    narrow_scope: DeployScyllaJoinNarrowScopeProof | None = None,
    allow_destructive: bool = False,
    destructive_scope_provided: bool = False,
) -> DeployScyllaJoinAuthorizationProof:
    return DeployScyllaJoinAuthorizationProof(
        approval_method=approval_method,
        approved=approved,
        narrow_approval_method=narrow_method,
        narrow_approved=narrow_approved,
        narrow_scope=_narrow_scope(prepared) if narrow_scope is None else narrow_scope,
        allow_destructive=allow_destructive,
        destructive_scope_provided=destructive_scope_provided,
    )


def _call(prepared, proof: DeployScyllaJoinAuthorizationProof):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return authorize_deploy_scylla_join_existing(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=proof,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployScyllaJoinAuthorizationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for item in value.values() for key in _keys(item)}
    if isinstance(value, list):
        return {key for item in value for key in _keys(item)}
    return set()


def test_first_join_authorization_is_distinct_redacted_immutable_and_call_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(
        inspect.signature(authorize_deploy_scylla_join_existing).parameters
    ) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "proof",
    )
    for forbidden in (
        "target",
        "mode",
        "scope",
        "survivor",
        "seed",
        "topology",
        "configuration",
        "version",
        "storage",
        "command",
        "variables",
        "path",
    ):
        assert (
            forbidden
            not in inspect.signature(authorize_deploy_scylla_join_existing).parameters
        )

    prepared = _prepared(tmp_path, monkeypatch)
    proof = _proof(prepared)
    authorization_path = deploy_scylla_join_authorization_path(
        prepared.paths, OPERATION_ID
    )
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()
    show_before = _run_show(prepared.paths)

    def fail_subprocess(*args, **kwargs):
        del args, kwargs
        raise AssertionError("join authorization must not run a process")

    monkeypatch.setattr(subprocess, "run", fail_subprocess)
    report = _call(prepared, proof)
    first_bytes = authorization_path.read_bytes()
    reused = _call(prepared, proof)
    stored = _record(prepared)
    show_after = _run_show(prepared.paths)

    assert report.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )
    assert (
        stored.record.schema_version
        == ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_SCHEMA_VERSION
    )
    assert (
        stored.record.proof.schema_version
        == ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    assert report.artifact_state is DeployScyllaJoinAuthorizationArtifactState.CREATED
    assert reused.artifact_state is DeployScyllaJoinAuthorizationArtifactState.REUSED
    assert authorization_path.read_bytes() == first_bytes
    assert stat.S_IMODE(authorization_path.stat().st_mode) == 0o600
    assert journal_path.read_bytes() == journal_before
    assert show_after == show_before

    scope = stored.record.scope
    assert report.classification is OperationClassification.SENSITIVE
    assert report.confirmation_policy is ConfirmationPolicy.SENSITIVE
    assert report.mode is ScyllaBootstrapMode.JOIN_EXISTING
    assert report.sequence == 2
    assert report.target_count == 1
    assert report.survivor_count == 1
    assert report.active_seed_count == 1
    assert report.active_seed_set_digest == report.survivor_set_digest
    assert report.later_join_count == 1
    assert report.consumed is False
    assert report.execution_state == "unavailable"
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert stored.record.authorization_scope_digest == scope.scope_digest
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
        '"host_id"',
        '"provider_id"',
        '"command"',
        '"variables"',
        '"path"',
    ):
        assert protected not in public
    assert _keys(json.loads(first_bytes)).isdisjoint(
        {
            "address",
            "command",
            "configuration",
            "credential",
            "environment",
            "free_text",
            "host_id",
            "output",
            "path",
            "provider_id",
            "seed",
            "secret",
            "variables",
        }
    )
    assert (
        deploy_scylla_join_authorization_id_from_filename(authorization_path.name)
        == OPERATION_ID
    )

    document = json.loads(first_bytes)
    document["later_join_count"] += 1
    authorization_path.write_text(
        json.dumps(document, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    authorization_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
    authorization_path.write_bytes(first_bytes)
    authorization_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


def test_sensitive_policy_requires_ordinary_and_exact_narrow_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    exact = _narrow_scope(prepared)
    wrong = replace(exact, authorization_scope_digest=_OTHER_DIGEST)
    invalid = (
        (
            DeployScyllaJoinAuthorizationProof(
                narrow_approval_method=DeployScyllaJoinNarrowApprovalMethod.INTERACTIVE,
                narrow_approved=True,
                narrow_scope=exact,
            ),
            "ordinary",
        ),
        (_proof(prepared, approved=False), "denied"),
        (_proof(prepared, narrow_method=None), "target/mode/scope"),
        (_proof(prepared, narrow_approved=False), "target/mode/scope"),
        (_proof(prepared, narrow_scope=wrong), "does not match"),
        (_proof(prepared, allow_destructive=True), "inapplicable"),
        (_proof(prepared, destructive_scope_provided=True), "inapplicable"),
    )
    path = deploy_scylla_join_authorization_path(prepared.paths, OPERATION_ID)
    for proof, message in invalid:
        with pytest.raises(StateConflictError, match=message):
            _call(prepared, proof)
        assert not path.exists()

    report = _call(
        prepared,
        _proof(
            prepared,
            approval_method=DeployScyllaJoinApprovalMethod.CLI_YES,
            narrow_method=DeployScyllaJoinNarrowApprovalMethod.CLI_EXPLICIT,
        ),
    )
    assert report.approval_method is DeployScyllaJoinApprovalMethod.CLI_YES
    assert (
        report.narrow_approval_method
        is DeployScyllaJoinNarrowApprovalMethod.CLI_EXPLICIT
    )


def test_only_first_join_is_authorized_and_later_join_stays_waiting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    report = _call(prepared, _proof(prepared))
    stored = _record(prepared)
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        loaded = _load_join_authorization_context(
            prepared.paths, OPERATION_ID, lock=lock
        )
    steps = loaded.safety_reconciliation.record.steps
    assert report.sequence == 2
    assert report.mode is ScyllaBootstrapMode.JOIN_EXISTING
    assert report.later_join_count == 1
    assert stored.record.scope.target_digest == steps[1].target_digest
    assert steps[1].status is DeployScyllaJoinSafetyStepStatus.AUTHORIZATION_REQUIRED
    assert all(
        step.status is DeployScyllaJoinSafetyStepStatus.WAITING
        and step.authorization_state == "waiting"
        and step.blockers == ("preceding-join-not-completed",)
        for step in steps[2:]
    )


def test_every_required_join_safety_gate_drift_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    proof = _proof(prepared)
    path = deploy_scylla_join_safety_evidence_path(prepared.paths, OPERATION_ID)
    original = path.read_bytes()
    for gate_name in _REQUIRED_GATES:
        value = json.loads(original)
        gate = next(item for item in value["gates"] if item["name"] == gate_name)
        gate["status"] = "failed"
        gate["gate_digest"] = _gate_digest_from_values(gate)
        value["required_passed_count"] = len(_REQUIRED_GATES) - 1
        value["failed_count"] = 1
        value["ready_for_authorization"] = False
        value["authorization_state"] = "not-created"
        value["blockers"] = [f"{gate_name}-failed"]
        value["blocker_digest"] = _digest_object(value["blockers"])
        value["evidence_digest"] = _evidence_digest_from_values(value)
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        path.chmod(0o600)

        with pytest.raises((StateConflictError, StatePersistenceError)):
            _call(prepared, proof)
        assert not deploy_scylla_join_authorization_path(
            prepared.paths, OPERATION_ID
        ).exists()
        path.write_bytes(original)
        path.chmod(0o600)


def test_full_chain_trust_drift_cannot_be_bypassed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    proof = _proof(prepared)
    value = json.loads(prepared.paths.ansible_trust.read_text(encoding="utf-8"))
    value["generation"] += 1
    prepared.paths.ansible_trust.write_text(
        json.dumps(value, sort_keys=True) + "\n", encoding="utf-8"
    )
    prepared.paths.ansible_trust.chmod(0o600)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, proof)
    assert not deploy_scylla_join_authorization_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_wrong_lock_later_history_write_failure_and_unsafe_path_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    proof = _proof(prepared)
    path = deploy_scylla_join_authorization_path(prepared.paths, OPERATION_ID)
    later = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-scylla-join-execution.json"
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
        authorize_deploy_scylla_join_existing(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            proof=proof,
        )

    original_write = DeployScyllaJoinAuthorizationStore.write_locked

    def fail_write(*args, **kwargs):
        del args, kwargs
        raise StatePersistenceError(f"injected {_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(DeployScyllaJoinAuthorizationStore, "write_locked", fail_write)
    with pytest.raises(StatePersistenceError, match="persistence failed"):
        _call(prepared, proof)
    assert not path.exists()
    monkeypatch.setattr(
        DeployScyllaJoinAuthorizationStore, "write_locked", original_write
    )

    _call(prepared, proof)
    target = path.with_name(f"{path.name}.target")
    path.rename(target)
    path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _record(prepared)
    assert (
        deploy_scylla_join_authorization_id_from_filename(
            f"{str(OPERATION_ID).upper()}.ansible-deploy-scylla-join-authorization.json"
        )
        is None
    )
