import inspect
import json
import stat
import uuid
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
import test_ansible_deploy_scylla_post_sequence_three_join_health as health_fixture
import test_ansible_deploy_scylla_sequence_three_join_safety as sequence_fixture
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_operation_composition import _Prepared
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_scylla_join_safety import (
    DeployScyllaJoinSafetyProof,
    DeployScyllaJoinSafetyProofStatus,
    _proof_digest_from_values,
)
from scylla_vms.ansible.deploy_scylla_later_join_safety import (
    ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION,
    DeployScyllaLaterJoinSafetyArtifactState,
    DeployScyllaLaterJoinSafetyContextStore,
    DeployScyllaLaterJoinSafetyEvidenceStore,
    DeployScyllaLaterJoinSafetyReconciliationStore,
    DeployScyllaLaterJoinSafetyReport,
    _LaterJoinSafetyLoaded,
    _load_later_join_safety,
    bind_deploy_scylla_later_join_safety,
    deploy_scylla_later_join_safety_context_id_from_filename,
    deploy_scylla_later_join_safety_context_path,
    deploy_scylla_later_join_safety_evidence_id_from_filename,
    deploy_scylla_later_join_safety_evidence_path,
    deploy_scylla_later_join_safety_reconciliation_id_from_filename,
    deploy_scylla_later_join_safety_reconciliation_path,
)
from scylla_vms.desired import ClusterSpec
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.journal import OperationJournalStore, OperationRecord
from scylla_vms.locking import ClusterLock

_EXTERNAL_GATES = ("backup-policy", "capacity", "quorum", "replication")
_PRIVATE_PATH = "/private/operator/later-join-safety.json"
_SECRET = "obviously-fake-later-join-safety-secret"


def _node_spec(tmp_path: Path, count: int) -> ClusterSpec:
    spec = sequence_fixture._ORIGINAL_SPEC(tmp_path)
    zone = replace(
        spec.zones[0],
        scylla_nodes=count,
        logical_node_ids=tuple(f"scylla-ad-1-{index}" for index in range(1, count + 1)),
    )
    return replace(spec, zones=(zone,))


def _five_node_spec(tmp_path: Path) -> ClusterSpec:
    return _node_spec(tmp_path, 5)


def _three_node_spec(tmp_path: Path) -> ClusterSpec:
    return _node_spec(tmp_path, 3)


def _prepared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    spec: Callable[[Path], ClusterSpec] = _five_node_spec,
) -> tuple[_Prepared, object, object]:
    monkeypatch.setattr(sequence_fixture, "_four_node_spec", spec)
    prepared, executables, toolchain = health_fixture._prepared(tmp_path, monkeypatch)
    health_fixture._call(
        prepared,
        health_fixture.PostSequenceThreeHealthRunner(),
        executables,
        toolchain,
    )
    return prepared, executables, toolchain


def _proofs(
    loaded: _LaterJoinSafetyLoaded,
    *,
    statuses: dict[str, DeployScyllaJoinSafetyProofStatus] | None = None,
) -> tuple[DeployScyllaJoinSafetyProof, ...]:
    selected = statuses or {}
    health = loaded.latest_health_evidence.record
    assert loaded.target_digest is not None
    assert loaded.target_storage_evidence_digest is not None
    assert loaded.target_configuration_evidence_digest is not None
    assert loaded.playbook_source_digest is not None
    return tuple(
        DeployScyllaJoinSafetyProof.create(
            gate=gate,
            status=selected.get(gate, DeployScyllaJoinSafetyProofStatus.PASSED),
            captured_at=health.created_at,
            evidence_digest="sha256:" + f"{index + 5:x}" * 64,
            health_evidence_digest=health.evidence_digest,
            target_digest=loaded.target_digest,
            survivor_set_digest=loaded.survivor_set_digest,
            topology_digest=loaded.current_topology_digest,
            target_storage_evidence_digest=(loaded.target_storage_evidence_digest),
            target_configuration_evidence_digest=(
                loaded.target_configuration_evidence_digest
            ),
            playbook_source_digest=loaded.playbook_source_digest,
        )
        for index, gate in enumerate(_EXTERNAL_GATES)
    )


def _call(
    prepared: _Prepared,
    *,
    statuses: dict[str, DeployScyllaJoinSafetyProofStatus] | None = None,
    transform: Callable[
        [tuple[DeployScyllaJoinSafetyProof, ...]],
        tuple[DeployScyllaJoinSafetyProof, ...],
    ] = lambda value: value,
) -> DeployScyllaLaterJoinSafetyReport:
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        loaded = _load_later_join_safety(prepared.paths, OPERATION_ID, lock=lock)
        return bind_deploy_scylla_later_join_safety(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proofs=transform(_proofs(loaded, statuses=statuses)),
        )


def _records(prepared: _Prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = DeployScyllaLaterJoinSafetyContextStore(
            prepared.paths, OPERATION_ID, 4
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence = DeployScyllaLaterJoinSafetyEvidenceStore(
            prepared.paths, OPERATION_ID, 4
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        reconciliation = DeployScyllaLaterJoinSafetyReconciliationStore(
            prepared.paths, OPERATION_ID, 4
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    return context, evidence, reconciliation


def _replace_proof(
    proof: DeployScyllaJoinSafetyProof, field: str, value: str
) -> DeployScyllaJoinSafetyProof:
    payload = proof.to_object()
    payload[field] = value
    payload["proof_digest"] = _proof_digest_from_values(payload)
    return DeployScyllaJoinSafetyProof.from_object(payload)


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for item in value.values() for key in _keys(item)}
    if isinstance(value, list):
        return {key for item in value for key in _keys(item)}
    return set()


def test_later_join_safety_derives_sequence_four_blocks_later_and_reuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert tuple(
        inspect.signature(bind_deploy_scylla_later_join_safety).parameters
    ) == ("state_root", "cluster_name", "operation_id", "lock", "proofs")
    forbidden = {
        "target",
        "sequence",
        "order",
        "mode",
        "address",
        "command",
        "variables",
        "path",
        "free_text",
    }
    assert forbidden.isdisjoint(
        inspect.signature(bind_deploy_scylla_later_join_safety).parameters
    )
    prepared, _, _ = _prepared(tmp_path, monkeypatch)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()

    report = _call(prepared)
    context, evidence, reconciliation = _records(prepared)

    assert report.required and report.state == "required"
    assert report.context_state is DeployScyllaLaterJoinSafetyArtifactState.CREATED
    assert report.evidence_state is DeployScyllaLaterJoinSafetyArtifactState.CREATED
    assert (
        report.reconciliation_state is DeployScyllaLaterJoinSafetyArtifactState.CREATED
    )
    assert report.target_sequence == 4
    assert report.target_status == "authorization-required"
    assert report.completed_prefix_count == report.survivor_count == 3
    assert report.active_seed_count == 1
    assert report.proof_count == 4
    assert report.failed_count == report.unknown_count == report.blocker_count == 0
    assert report.later_join_count == 1
    assert not report.journal_updated
    assert journal_path.read_bytes() == journal_before
    assert (
        context.record.schema_version
        == ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
    )
    assert (
        evidence.record.schema_version
        == ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
    )
    assert reconciliation.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_LATER_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION
    )
    assert [step.status.value for step in reconciliation.record.steps] == [
        "health-succeeded",
        "health-succeeded",
        "health-succeeded",
        "authorization-required",
        "waiting-for-preceding-complete-health",
    ]
    assert reconciliation.record.steps[4].blockers == ("preceding-join-not-completed",)
    artifacts = (
        deploy_scylla_later_join_safety_context_path(prepared.paths, OPERATION_ID, 4),
        deploy_scylla_later_join_safety_evidence_path(prepared.paths, OPERATION_ID, 4),
        deploy_scylla_later_join_safety_reconciliation_path(
            prepared.paths, OPERATION_ID, 4
        ),
    )
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in artifacts)
    persisted = "".join(path.read_text(encoding="utf-8") for path in artifacts)
    for protected in (
        _PRIVATE_PATH,
        _SECRET,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        '"host_id"',
        '"route"',
        '"seed"',
        '"command"',
        '"variables"',
        '"environment"',
        '"path"',
    ):
        assert protected not in persisted
    assert _keys(json.loads(artifacts[1].read_text(encoding="utf-8"))).isdisjoint(
        {
            "address",
            "command",
            "configuration",
            "credential",
            "environment",
            "host_id",
            "output",
            "provider_id",
            "route",
            "seed",
            "secret",
            "variables",
        }
    )
    assert deploy_scylla_later_join_safety_context_id_from_filename(
        artifacts[0].name
    ) == (OPERATION_ID, 4)
    assert deploy_scylla_later_join_safety_evidence_id_from_filename(
        artifacts[1].name
    ) == (OPERATION_ID, 4)
    assert deploy_scylla_later_join_safety_reconciliation_id_from_filename(
        artifacts[2].name
    ) == (OPERATION_ID, 4)
    before = tuple(path.read_bytes() for path in artifacts)
    reused = _call(prepared)
    assert reused.context_state is DeployScyllaLaterJoinSafetyArtifactState.REUSED
    assert reused.evidence_state is DeployScyllaLaterJoinSafetyArtifactState.REUSED
    assert (
        reused.reconciliation_state is DeployScyllaLaterJoinSafetyArtifactState.REUSED
    )
    assert tuple(path.read_bytes() for path in artifacts) == before
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


def test_later_join_safety_not_required_writes_nothing_and_accepts_no_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _, _ = _prepared(tmp_path, monkeypatch, spec=_three_node_spec)
    paths = (
        deploy_scylla_later_join_safety_context_path(prepared.paths, OPERATION_ID, 4),
        deploy_scylla_later_join_safety_evidence_path(prepared.paths, OPERATION_ID, 4),
        deploy_scylla_later_join_safety_reconciliation_path(
            prepared.paths, OPERATION_ID, 4
        ),
    )
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        report = bind_deploy_scylla_later_join_safety(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proofs=(),
        )
    assert not report.required
    assert report.state == report.target_status == "not-required"
    assert report.target_sequence is None
    assert report.completed_prefix_count == report.survivor_count == 3
    assert not any(path.exists() for path in paths)

    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        loaded = _load_later_join_safety(prepared.paths, OPERATION_ID, lock=lock)
        proof = DeployScyllaJoinSafetyProof.create(
            gate="capacity",
            status=DeployScyllaJoinSafetyProofStatus.PASSED,
            captured_at=loaded.latest_health_evidence.record.created_at,
            evidence_digest="sha256:" + "a" * 64,
            health_evidence_digest=(
                loaded.latest_health_evidence.record.evidence_digest
            ),
            target_digest="sha256:" + "b" * 64,
            survivor_set_digest=loaded.survivor_set_digest,
            topology_digest=loaded.current_topology_digest,
            target_storage_evidence_digest="sha256:" + "c" * 64,
            target_configuration_evidence_digest="sha256:" + "d" * 64,
            playbook_source_digest="sha256:" + "e" * 64,
        )
        with pytest.raises(StateConflictError, match="accepts no proofs"):
            bind_deploy_scylla_later_join_safety(
                state_root=prepared.paths.state_root,
                cluster_name="example",
                operation_id=OPERATION_ID,
                lock=lock,
                proofs=(proof,),
            )
    assert not any(path.exists() for path in paths)


@pytest.mark.parametrize("gate", _EXTERNAL_GATES)
def test_later_join_safety_unknown_external_gate_stays_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gate: str
) -> None:
    prepared, _, _ = _prepared(tmp_path, monkeypatch)
    report = _call(
        prepared,
        statuses={gate: DeployScyllaJoinSafetyProofStatus.UNKNOWN},
    )
    _, evidence, reconciliation = _records(prepared)
    assert report.target_sequence == 4
    assert report.target_status == "blocked"
    assert report.unknown_count == 1
    assert f"{gate}-unknown" in evidence.record.blockers
    assert reconciliation.record.steps[3].status.value == "blocked"
    assert reconciliation.record.steps[4].status.value == (
        "waiting-for-preceding-complete-health"
    )


def test_later_join_safety_refuses_proof_mismatch_and_wrong_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _, _ = _prepared(tmp_path, monkeypatch)
    context_path = deploy_scylla_later_join_safety_context_path(
        prepared.paths, OPERATION_ID, 4
    )
    with pytest.raises(StateConflictError, match="requires exact independent"):
        _call(prepared, transform=lambda proofs: proofs[:-1])
    with pytest.raises(StateConflictError, match="requires exact independent"):
        _call(
            prepared,
            transform=lambda proofs: (proofs[0], proofs[0], *proofs[2:]),
        )
    with pytest.raises(StateConflictError, match="stale or binding-mismatched"):
        _call(
            prepared,
            transform=lambda proofs: (
                _replace_proof(
                    proofs[0],
                    "health_evidence_digest",
                    "sha256:" + "f" * 64,
                ),
                *proofs[1:],
            ),
        )
    assert not context_path.exists()
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        bind_deploy_scylla_later_join_safety(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            proofs=(),
        )


def test_later_join_safety_refuses_noncontiguous_prefix_and_current_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _, _ = _prepared(tmp_path, monkeypatch)
    health_path = prepared.paths.operations / (
        f"{OPERATION_ID}."
        "ansible-deploy-scylla-post-sequence-three-join-health-reconciliation.json"
    )
    original = health_path.read_bytes()
    value = cast(dict[str, object], json.loads(original))
    steps = cast(list[dict[str, object]], value["steps"])
    steps[2]["status"] = "waiting-for-preceding-complete-health"
    health_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    health_path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not deploy_scylla_later_join_safety_context_path(
        prepared.paths, OPERATION_ID, 4
    ).exists()
    health_path.write_bytes(original)
    health_path.chmod(0o600)

    inventory = cast(
        dict[str, object],
        json.loads(prepared.paths.ansible_inventory.read_text(encoding="utf-8")),
    )
    hosts = cast(
        dict[str, dict[str, object]], cast(dict[str, object], inventory["all"])["hosts"]
    )
    hosts["scylla-ad-1-4"]["deploy_scylla_vms_scylla_rack"] = "drifted"
    prepared.paths.ansible_inventory.write_text(
        json.dumps(inventory, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    prepared.paths.ansible_inventory.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not deploy_scylla_later_join_safety_context_path(
        prepared.paths, OPERATION_ID, 4
    ).exists()


def test_later_join_safety_blocks_competing_operation_and_changed_proof_reentry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _, _ = _prepared(tmp_path, monkeypatch)
    report = _call(prepared)
    assert report.target_status == "authorization-required"
    artifacts = (
        deploy_scylla_later_join_safety_context_path(prepared.paths, OPERATION_ID, 4),
        deploy_scylla_later_join_safety_evidence_path(prepared.paths, OPERATION_ID, 4),
        deploy_scylla_later_join_safety_reconciliation_path(
            prepared.paths, OPERATION_ID, 4
        ),
    )
    before = tuple(path.read_bytes() for path in artifacts)

    with pytest.raises(StateConflictError, match="immutable"):
        _call(
            prepared,
            transform=lambda proofs: (
                _replace_proof(
                    proofs[0],
                    "evidence_digest",
                    "sha256:" + "f" * 64,
                ),
                *proofs[1:],
            ),
        )

    competing_id = uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    competing = OperationRecord.create_initial_plan(
        operation_id=competing_id,
        operation="deploy",
        cluster_uuid=CLUSTER_UUID,
        cluster_name="example",
        request_digest="sha256:" + "b" * 64,
        clock=lambda: datetime(2026, 9, 21, tzinfo=UTC),
    )
    OperationJournalStore(prepared.paths, competing_id).write(
        competing,
        expected_generation=0,
        expected_digest=None,
    )
    with pytest.raises(StateConflictError, match="drifted"):
        _call(prepared)
    assert tuple(path.read_bytes() for path in artifacts) == before


def test_later_join_safety_recovers_prefix_and_show_rejects_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _, _ = _prepared(tmp_path, monkeypatch)
    original_write = DeployScyllaLaterJoinSafetyEvidenceStore.write_locked
    failed = False

    def fail_once(self, record, **kwargs):
        nonlocal failed
        if not failed:
            failed = True
            raise StatePersistenceError("later-join evidence persistence failure")
        return original_write(self, record, **kwargs)

    monkeypatch.setattr(
        DeployScyllaLaterJoinSafetyEvidenceStore,
        "write_locked",
        fail_once,
    )
    with pytest.raises(StatePersistenceError, match="evidence persistence"):
        _call(prepared)
    context_path = deploy_scylla_later_join_safety_context_path(
        prepared.paths, OPERATION_ID, 4
    )
    evidence_path = deploy_scylla_later_join_safety_evidence_path(
        prepared.paths, OPERATION_ID, 4
    )
    assert context_path.exists()
    assert not evidence_path.exists()

    report = _call(prepared)
    assert report.context_state is DeployScyllaLaterJoinSafetyArtifactState.REUSED
    assert report.evidence_state is DeployScyllaLaterJoinSafetyArtifactState.CREATED
    reconciliation_path = deploy_scylla_later_join_safety_reconciliation_path(
        prepared.paths, OPERATION_ID, 4
    )
    original = reconciliation_path.read_bytes()
    value = cast(dict[str, object], json.loads(original))
    value["target_sequence"] = 5
    reconciliation_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    reconciliation_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
    reconciliation_path.write_bytes(original)
    reconciliation_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0
