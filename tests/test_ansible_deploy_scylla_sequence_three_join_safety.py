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
import test_ansible_deploy_scylla_join_execution as test_join_execution
import test_provider_source
from test_ansible_deploy_scylla_join_safety import _multi_output
from test_ansible_deploy_scylla_post_join_health import (
    PostJoinHealthRunner,
)
from test_ansible_deploy_scylla_post_join_health import (
    _call as _execute_post_join_health,
)
from test_ansible_deploy_scylla_post_join_health import (
    _prepared as _prepared_post_join_health,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_operation_composition import _Prepared
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_scylla_join_safety import (
    DeployScyllaJoinSafetyProof,
    DeployScyllaJoinSafetyProofStatus,
    _proof_digest_from_values,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_safety import (
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_RECONCILIATION_SCHEMA_VERSION,
    DeployScyllaSequenceThreeSafetyArtifactState,
    DeployScyllaSequenceThreeSafetyContextStore,
    DeployScyllaSequenceThreeSafetyEvidenceStore,
    DeployScyllaSequenceThreeSafetyReconciliationStore,
    DeployScyllaSequenceThreeSafetyReport,
    _load_sequence_three_safety,
    _SequenceThreeSafetyLoaded,
    bind_deploy_scylla_sequence_three_join_safety,
    deploy_scylla_sequence_three_safety_context_id_from_filename,
    deploy_scylla_sequence_three_safety_context_path,
    deploy_scylla_sequence_three_safety_evidence_id_from_filename,
    deploy_scylla_sequence_three_safety_evidence_path,
    deploy_scylla_sequence_three_safety_reconciliation_id_from_filename,
    deploy_scylla_sequence_three_safety_reconciliation_path,
)
from scylla_vms.desired import ClusterSpec
from scylla_vms.errors import StateConflictError, StatePersistenceError
from scylla_vms.journal import OperationJournalStore, OperationRecord
from scylla_vms.locking import ClusterLock

_EXTERNAL_GATES = ("backup-policy", "capacity", "quorum", "replication")
_PRIVATE_PATH = "/private/operator/sequence-three-safety.json"
_SECRET = "obviously-fake-sequence-three-safety-secret"
_ORIGINAL_SPEC = test_provider_source._spec


def _four_node_spec(tmp_path: Path) -> ClusterSpec:
    spec = _ORIGINAL_SPEC(tmp_path)
    zone = replace(
        spec.zones[0],
        scylla_nodes=4,
        logical_node_ids=(
            "scylla-ad-1-1",
            "scylla-ad-1-2",
            "scylla-ad-1-3",
            "scylla-ad-1-4",
        ),
    )
    return replace(spec, zones=(zone,))


def _prepared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[_Prepared, object, object]:
    monkeypatch.setattr(test_join_execution, "_multi_spec", _four_node_spec)
    monkeypatch.setattr(test_join_execution, "_multi_output", _multi_output)
    prepared, executables, toolchain = _prepared_post_join_health(tmp_path, monkeypatch)
    _execute_post_join_health(
        prepared,
        PostJoinHealthRunner(),
        executables,
        toolchain,
    )
    return prepared, executables, toolchain


def _proofs(
    loaded: _SequenceThreeSafetyLoaded,
    *,
    statuses: dict[str, DeployScyllaJoinSafetyProofStatus] | None = None,
) -> tuple[DeployScyllaJoinSafetyProof, ...]:
    selected = statuses or {}
    health = loaded.post_join_health_evidence.record
    return tuple(
        DeployScyllaJoinSafetyProof.create(
            gate=gate,
            status=selected.get(gate, DeployScyllaJoinSafetyProofStatus.PASSED),
            captured_at=health.created_at,
            evidence_digest="sha256:" + f"{index + 1:x}" * 64,
            health_evidence_digest=health.evidence_digest,
            target_digest=loaded.target_digest,
            survivor_set_digest=loaded.survivor_set_digest,
            topology_digest=loaded.current_topology_digest,
            target_storage_evidence_digest=loaded.target_storage_evidence_digest,
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
) -> DeployScyllaSequenceThreeSafetyReport:
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        loaded = _load_sequence_three_safety(prepared.paths, OPERATION_ID, lock=lock)
        return bind_deploy_scylla_sequence_three_join_safety(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proofs=transform(_proofs(loaded, statuses=statuses)),
        )


def _records(prepared: _Prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = DeployScyllaSequenceThreeSafetyContextStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence = DeployScyllaSequenceThreeSafetyEvidenceStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        reconciliation = DeployScyllaSequenceThreeSafetyReconciliationStore(
            prepared.paths, OPERATION_ID
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


def test_sequence_three_safety_success_later_blocking_and_zero_write_reentry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert tuple(
        inspect.signature(bind_deploy_scylla_sequence_three_join_safety).parameters
    ) == ("state_root", "cluster_name", "operation_id", "lock", "proofs")
    prepared, _, _ = _prepared(tmp_path, monkeypatch)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()

    report = _call(prepared)
    context, evidence, reconciliation = _records(prepared)

    assert report.context_state is DeployScyllaSequenceThreeSafetyArtifactState.CREATED
    assert report.evidence_state is DeployScyllaSequenceThreeSafetyArtifactState.CREATED
    assert (
        report.reconciliation_state
        is DeployScyllaSequenceThreeSafetyArtifactState.CREATED
    )
    assert report.target_sequence == 3
    assert report.target_status == "authorization-required"
    assert report.survivor_count == 2
    assert report.active_seed_count == 1
    assert report.proof_count == 4
    assert report.failed_count == report.unknown_count == report.blocker_count == 0
    assert report.later_join_count == 1
    assert not report.journal_updated
    assert journal_path.read_bytes() == journal_before
    assert (
        context.record.schema_version
        == ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_SCHEMA_VERSION
    )
    assert (
        evidence.record.schema_version
        == ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_EVIDENCE_SCHEMA_VERSION
    )
    assert (
        reconciliation.record.schema_version
        == ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_RECONCILIATION_SCHEMA_VERSION
    )
    assert [step.status.value for step in reconciliation.record.steps] == [
        "health-succeeded",
        "health-succeeded",
        "authorization-required",
        "waiting-for-preceding-complete-health",
    ]
    assert reconciliation.record.steps[3].blockers == ("preceding-join-not-completed",)
    paths = (
        deploy_scylla_sequence_three_safety_context_path(prepared.paths, OPERATION_ID),
        deploy_scylla_sequence_three_safety_evidence_path(prepared.paths, OPERATION_ID),
        deploy_scylla_sequence_three_safety_reconciliation_path(
            prepared.paths, OPERATION_ID
        ),
    )
    before = tuple(path.read_bytes() for path in paths)
    reused = _call(prepared)
    assert reused.context_state is DeployScyllaSequenceThreeSafetyArtifactState.REUSED
    assert reused.evidence_state is DeployScyllaSequenceThreeSafetyArtifactState.REUSED
    assert (
        reused.reconciliation_state
        is DeployScyllaSequenceThreeSafetyArtifactState.REUSED
    )
    assert tuple(path.read_bytes() for path in paths) == before
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in paths)
    persisted = "".join(path.read_text(encoding="utf-8") for path in paths)
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
    assert _keys(json.loads(paths[1].read_text(encoding="utf-8"))).isdisjoint(
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
    assert (
        deploy_scylla_sequence_three_safety_context_id_from_filename(paths[0].name)
        == OPERATION_ID
    )
    assert (
        deploy_scylla_sequence_three_safety_evidence_id_from_filename(paths[1].name)
        == OPERATION_ID
    )
    assert (
        deploy_scylla_sequence_three_safety_reconciliation_id_from_filename(
            paths[2].name
        )
        == OPERATION_ID
    )
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


@pytest.mark.parametrize("gate", _EXTERNAL_GATES)
def test_sequence_three_safety_unknown_external_gate_stays_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gate: str
) -> None:
    prepared, _, _ = _prepared(tmp_path, monkeypatch)
    report = _call(
        prepared,
        statuses={gate: DeployScyllaJoinSafetyProofStatus.UNKNOWN},
    )
    _, evidence, reconciliation = _records(prepared)
    assert report.target_status == "blocked"
    assert report.unknown_count == 1
    assert f"{gate}-unknown" in evidence.record.blockers
    assert reconciliation.record.steps[2].status.value == "blocked"
    assert reconciliation.record.steps[3].status.value == (
        "waiting-for-preceding-complete-health"
    )


def test_sequence_three_safety_refuses_missing_duplicate_or_stale_proofs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _, _ = _prepared(tmp_path, monkeypatch)
    context_path = deploy_scylla_sequence_three_safety_context_path(
        prepared.paths, OPERATION_ID
    )
    with pytest.raises(StateConflictError, match="requires exact independent"):
        _call(prepared, transform=lambda proofs: proofs[:-1])
    assert not context_path.exists()
    with pytest.raises(StateConflictError, match="requires exact independent"):
        _call(
            prepared,
            transform=lambda proofs: (proofs[0], proofs[0], *proofs[2:]),
        )
    assert not context_path.exists()
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


def test_sequence_three_safety_refuses_upstream_tamper_and_current_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _, _ = _prepared(tmp_path, monkeypatch)
    post_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-scylla-join-health-reconciliation.json"
    )
    original = post_path.read_bytes()
    value = cast(dict[str, object], json.loads(original))
    value["current_member_count"] = 3
    post_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    post_path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not deploy_scylla_sequence_three_safety_context_path(
        prepared.paths, OPERATION_ID
    ).exists()
    post_path.write_bytes(original)
    post_path.chmod(0o600)

    inventory = cast(
        dict[str, object],
        json.loads(prepared.paths.ansible_inventory.read_text(encoding="utf-8")),
    )
    hosts = cast(
        dict[str, dict[str, object]], cast(dict[str, object], inventory["all"])["hosts"]
    )
    hosts["scylla-ad-1-3"]["deploy_scylla_vms_scylla_rack"] = "drifted"
    prepared.paths.ansible_inventory.write_text(
        json.dumps(inventory, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    prepared.paths.ansible_inventory.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not deploy_scylla_sequence_three_safety_context_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_sequence_three_safety_blocks_competing_active_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _, _ = _prepared(tmp_path, monkeypatch)
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

    report = _call(prepared)
    _, evidence, reconciliation = _records(prepared)
    assert report.target_status == "blocked"
    assert "no-competing-operation-failed" in evidence.record.blockers
    assert reconciliation.record.steps[2].status.value == "blocked"
    assert reconciliation.record.steps[3].status.value == (
        "waiting-for-preceding-complete-health"
    )


def test_sequence_three_safety_recovers_exact_context_prefix_and_show_rejects_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _, _ = _prepared(tmp_path, monkeypatch)
    original_write = DeployScyllaSequenceThreeSafetyEvidenceStore.write_locked
    failed = False

    def fail_once(self, record, **kwargs):
        nonlocal failed
        if not failed:
            failed = True
            raise StatePersistenceError("sequence-three evidence persistence failure")
        return original_write(self, record, **kwargs)

    monkeypatch.setattr(
        DeployScyllaSequenceThreeSafetyEvidenceStore,
        "write_locked",
        fail_once,
    )
    with pytest.raises(StatePersistenceError, match="evidence persistence"):
        _call(prepared)
    context_path = deploy_scylla_sequence_three_safety_context_path(
        prepared.paths, OPERATION_ID
    )
    evidence_path = deploy_scylla_sequence_three_safety_evidence_path(
        prepared.paths, OPERATION_ID
    )
    assert context_path.exists()
    assert not evidence_path.exists()

    report = _call(prepared)
    assert report.context_state is DeployScyllaSequenceThreeSafetyArtifactState.REUSED
    assert report.evidence_state is DeployScyllaSequenceThreeSafetyArtifactState.CREATED
    reconciliation_path = deploy_scylla_sequence_three_safety_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    original = reconciliation_path.read_bytes()
    value = cast(dict[str, object], json.loads(original))
    value["target_sequence"] = 4
    reconciliation_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    reconciliation_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
    reconciliation_path.write_bytes(original)
    reconciliation_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0
