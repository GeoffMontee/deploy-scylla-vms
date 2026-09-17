import inspect
import json
import stat
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from test_ansible_deploy_scylla_sequence_three_join_safety import (
    _call as _bind_sequence_three_safety,
)
from test_ansible_deploy_scylla_sequence_three_join_safety import (
    _prepared as _prepared_sequence_three_safety,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_operation_composition import _Prepared
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_scylla_join_authorization import (
    DeployScyllaJoinApprovalMethod,
    DeployScyllaJoinNarrowApprovalMethod,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_authorization import (
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_SCHEMA_VERSION,
    DeployScyllaSequenceThreeJoinAuthorizationArtifactState,
    DeployScyllaSequenceThreeJoinAuthorizationProof,
    DeployScyllaSequenceThreeJoinAuthorizationStore,
    DeployScyllaSequenceThreeJoinNarrowScopeProof,
    _derive_sequence_three_join_scope,
    _load_sequence_three_join_authorization_context,
    authorize_deploy_scylla_sequence_three_join,
    deploy_scylla_sequence_three_join_authorization_id_from_filename,
    deploy_scylla_sequence_three_join_authorization_path,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_safety import (
    DeployScyllaSequenceThreeSafetyReconciliationStore,
    DeployScyllaSequenceThreeSafetyStepStatus,
    deploy_scylla_sequence_three_safety_reconciliation_path,
)
from scylla_vms.ansible.operation_authorization import ConfirmationPolicy
from scylla_vms.ansible.scylla_bootstrap import ScyllaBootstrapMode
from scylla_vms.errors import StateConflictError, StateLockError, StatePersistenceError
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification

_PRIVATE_PATH = "/private/operator/sequence-three-authorization.json"
_SECRET = "obviously-fake-sequence-three-authorization-secret"
_OTHER_DIGEST = "sha256:" + "f" * 64


def _prepared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[_Prepared, object, object]:
    prepared, executables, toolchain = _prepared_sequence_three_safety(
        tmp_path, monkeypatch
    )
    _bind_sequence_three_safety(prepared)
    return prepared, executables, toolchain


def _narrow_scope(
    prepared: _Prepared,
) -> DeployScyllaSequenceThreeJoinNarrowScopeProof:
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        loaded = _load_sequence_three_join_authorization_context(
            prepared.paths, OPERATION_ID, lock=lock
        )
        return DeployScyllaSequenceThreeJoinNarrowScopeProof.from_scope(
            _derive_sequence_three_join_scope(loaded)
        )


def _proof(
    prepared: _Prepared,
    *,
    approval_method: DeployScyllaJoinApprovalMethod | None = (
        DeployScyllaJoinApprovalMethod.INTERACTIVE
    ),
    approved: bool = True,
    narrow_method: DeployScyllaJoinNarrowApprovalMethod | None = (
        DeployScyllaJoinNarrowApprovalMethod.INTERACTIVE
    ),
    narrow_approved: bool = True,
    narrow_scope: DeployScyllaSequenceThreeJoinNarrowScopeProof | None = None,
    include_narrow_scope: bool = True,
    allow_destructive: bool = False,
    destructive_scope_provided: bool = False,
) -> DeployScyllaSequenceThreeJoinAuthorizationProof:
    return DeployScyllaSequenceThreeJoinAuthorizationProof(
        approval_method=approval_method,
        approved=approved,
        narrow_approval_method=narrow_method,
        narrow_approved=narrow_approved,
        narrow_scope=(
            _narrow_scope(prepared)
            if narrow_scope is None and include_narrow_scope
            else narrow_scope
        ),
        allow_destructive=allow_destructive,
        destructive_scope_provided=destructive_scope_provided,
    )


def _call(
    prepared: _Prepared,
    proof: DeployScyllaSequenceThreeJoinAuthorizationProof,
):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return authorize_deploy_scylla_sequence_three_join(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=proof,
        )


def _record(prepared: _Prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployScyllaSequenceThreeJoinAuthorizationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


def _reconciliation(prepared: _Prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployScyllaSequenceThreeSafetyReconciliationStore(
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


def test_sequence_three_authorization_is_exact_redacted_and_zero_write_reusable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(
        inspect.signature(authorize_deploy_scylla_sequence_three_join).parameters
    ) == ("state_root", "cluster_name", "operation_id", "lock", "proof")
    forbidden_inputs = {
        "target",
        "mode",
        "order",
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
        "free_text",
    }
    assert forbidden_inputs.isdisjoint(
        inspect.signature(authorize_deploy_scylla_sequence_three_join).parameters
    )

    prepared, _, _ = _prepared(tmp_path, monkeypatch)
    proof = _proof(prepared)
    path = deploy_scylla_sequence_three_join_authorization_path(
        prepared.paths, OPERATION_ID
    )
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()
    show_before = _run_show(prepared.paths)

    def fail_process(*args, **kwargs):
        del args, kwargs
        raise AssertionError("authorization must not invoke a process")

    monkeypatch.setattr(subprocess, "run", fail_process)
    report = _call(prepared, proof)
    first_bytes = path.read_bytes()
    reused = _call(prepared, proof)
    stored = _record(prepared)

    assert report.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )
    assert stored.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_SCHEMA_VERSION
    )
    assert stored.record.proof.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    assert (
        report.artifact_state
        is DeployScyllaSequenceThreeJoinAuthorizationArtifactState.CREATED
    )
    assert (
        reused.artifact_state
        is DeployScyllaSequenceThreeJoinAuthorizationArtifactState.REUSED
    )
    assert path.read_bytes() == first_bytes
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert journal_path.read_bytes() == journal_before
    assert _run_show(prepared.paths) == show_before
    assert report.classification is OperationClassification.SENSITIVE
    assert report.confirmation_policy is ConfirmationPolicy.SENSITIVE
    assert report.sequence == 3
    assert report.mode is ScyllaBootstrapMode.JOIN_EXISTING
    assert report.target_count == 1
    assert report.survivor_count == 2
    assert report.active_seed_count == 1
    assert report.later_join_count == 1
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert not report.consumed
    assert report.execution_state == "unavailable"

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
        "ansible-playbook",
        "--limit",
        '"stable_id"',
        '"host_id"',
        '"provider_id"',
        '"seed"',
        '"route"',
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
            "prompt",
            "provider_id",
            "route",
            "seed",
            "secret",
            "variables",
        }
    )
    assert (
        deploy_scylla_sequence_three_join_authorization_id_from_filename(path.name)
        == OPERATION_ID
    )

    document = json.loads(first_bytes)
    document["later_join_count"] += 1
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
    path.write_bytes(first_bytes)
    path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


def test_sequence_three_sensitive_proof_refusals_and_changed_reentry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _, _ = _prepared(tmp_path, monkeypatch)
    exact = _narrow_scope(prepared)
    path = deploy_scylla_sequence_three_join_authorization_path(
        prepared.paths, OPERATION_ID
    )
    invalid = (
        (
            _proof(
                prepared,
                approval_method=DeployScyllaJoinApprovalMethod.CLI_YES,
                narrow_method=None,
                include_narrow_scope=False,
            ),
            "cli-yes alone",
        ),
        (_proof(prepared, approved=False), "denied"),
        (
            _proof(
                prepared,
                narrow_scope=replace(exact, authorization_scope_digest=_OTHER_DIGEST),
            ),
            "does not match",
        ),
        (_proof(prepared, allow_destructive=True), "inapplicable"),
        (_proof(prepared, destructive_scope_provided=True), "inapplicable"),
    )
    for proof, message in invalid:
        with pytest.raises(StateConflictError, match=message):
            _call(prepared, proof)
        assert not path.exists()

    first = _proof(prepared)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        authorize_deploy_scylla_sequence_three_join(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            proof=first,
        )

    _call(prepared, first)
    original = path.read_bytes()
    with pytest.raises(StateConflictError, match="changed"):
        _call(
            prepared,
            _proof(
                prepared,
                approval_method=DeployScyllaJoinApprovalMethod.CLI_YES,
                narrow_method=DeployScyllaJoinNarrowApprovalMethod.CLI_EXPLICIT,
            ),
        )
    assert path.read_bytes() == original


def test_only_sequence_three_is_authorized_and_later_sequence_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _, _ = _prepared(tmp_path, monkeypatch)
    reconciliation = _reconciliation(prepared)
    steps = reconciliation.record.steps
    assert [step.status for step in steps] == [
        DeployScyllaSequenceThreeSafetyStepStatus.HEALTH_SUCCEEDED,
        DeployScyllaSequenceThreeSafetyStepStatus.HEALTH_SUCCEEDED,
        DeployScyllaSequenceThreeSafetyStepStatus.AUTHORIZATION_REQUIRED,
        DeployScyllaSequenceThreeSafetyStepStatus.WAITING,
    ]
    report = _call(prepared, _proof(prepared))
    stored = _record(prepared)
    assert report.sequence == 3
    assert stored.record.scope.target_digest == steps[2].target_digest
    assert report.later_join_digest == stored.record.later_join_digest

    path = deploy_scylla_sequence_three_join_authorization_path(
        prepared.paths, OPERATION_ID
    )
    path.unlink()
    later_scope = replace(
        _narrow_scope(prepared),
        target_digest=steps[3].target_digest,
    )
    with pytest.raises(StateConflictError, match="does not match"):
        _call(prepared, _proof(prepared, narrow_scope=later_scope))
    assert not path.exists()


def test_sequence_three_safety_tamper_and_current_drift_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _, _ = _prepared(tmp_path, monkeypatch)
    proof = _proof(prepared)
    authorization_path = deploy_scylla_sequence_three_join_authorization_path(
        prepared.paths, OPERATION_ID
    )
    safety_path = deploy_scylla_sequence_three_safety_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    original = safety_path.read_bytes()
    value = json.loads(original)
    value["target_sequence"] = 4
    safety_path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    safety_path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, proof)
    assert not authorization_path.exists()
    safety_path.write_bytes(original)
    safety_path.chmod(0o600)

    inventory = json.loads(prepared.paths.ansible_inventory.read_text(encoding="utf-8"))
    inventory["all"]["hosts"]["scylla-ad-1-3"]["deploy_scylla_vms_scylla_rack"] = (
        "drifted"
    )
    prepared.paths.ansible_inventory.write_text(
        json.dumps(inventory, sort_keys=True) + "\n", encoding="utf-8"
    )
    prepared.paths.ansible_inventory.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, proof)
    assert not authorization_path.exists()
