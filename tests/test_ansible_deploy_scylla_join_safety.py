import inspect
import json
import stat
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
import test_provider_source
import test_terraform_apply_inventory
import test_terraform_plan_checkpoint
from test_ansible_deploy_scylla_bootstrap_execution import _HOST_ID
from test_ansible_deploy_scylla_health_checkpoint import (
    HealthCheckpointRunner,
)
from test_ansible_deploy_scylla_health_checkpoint import (
    _call as _execute_health,
)
from test_ansible_deploy_scylla_health_checkpoint import (
    _prepared as _prepared_health,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_apply_inventory import _valid_output as _inventory_valid_output
from test_terraform_operation_composition import _Prepared
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_scylla_join_safety import (
    ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION,
    DeployScyllaJoinSafetyArtifactState,
    DeployScyllaJoinSafetyContextStore,
    DeployScyllaJoinSafetyEvidenceStore,
    DeployScyllaJoinSafetyProof,
    DeployScyllaJoinSafetyProofStatus,
    DeployScyllaJoinSafetyReconciliationStore,
    DeployScyllaJoinSafetyReport,
    _JoinSafetyLoaded,
    _load_join_safety,
    _proof_digest_from_values,
    bind_deploy_scylla_join_safety,
    deploy_scylla_join_safety_context_id_from_filename,
    deploy_scylla_join_safety_context_path,
    deploy_scylla_join_safety_evidence_id_from_filename,
    deploy_scylla_join_safety_evidence_path,
    deploy_scylla_join_safety_reconciliation_id_from_filename,
    deploy_scylla_join_safety_reconciliation_path,
)
from scylla_vms.desired import ClusterSpec
from scylla_vms.errors import StateConflictError, StatePersistenceError
from scylla_vms.locking import ClusterLock

_EVIDENCE_DIGEST = "sha256:" + "e" * 64
_PRIVATE_PATH = "/private/operator/join-safety.json"
_SECRET = "obviously-fake-join-safety-secret"


def _multi_spec(tmp_path: Path) -> ClusterSpec:
    spec = _ORIGINAL_SPEC(tmp_path)
    zone = replace(
        spec.zones[0],
        scylla_nodes=3,
        logical_node_ids=(
            "scylla-ad-1-1",
            "scylla-ad-1-2",
            "scylla-ad-1-3",
        ),
    )
    return replace(spec, zones=(zone,))


_ORIGINAL_SPEC = test_provider_source._spec
_ORIGINAL_OUTPUT = _inventory_valid_output


def _multi_output(prepared: _Prepared) -> dict[str, object]:
    value = _ORIGINAL_OUTPUT(prepared)
    network_envelope = cast(dict[str, object], value["network_evidence"])
    network = cast(dict[str, object], network_envelope["value"])
    subnets = cast(list[dict[str, object]], network["subnets"])
    network["subnets"] = list(
        {(item["zone"], item["role"]): item for item in subnets}.values()
    )
    cast(list[dict[str, object]], network["subnets"]).sort(
        key=lambda item: (str(item["zone"]), str(item["role"]))
    )
    return value


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Prepared:
    monkeypatch.setattr(test_provider_source, "_spec", _multi_spec)
    monkeypatch.setattr(test_terraform_plan_checkpoint, "_spec", _multi_spec)
    monkeypatch.setattr(test_terraform_apply_inventory, "_valid_output", _multi_output)
    prepared, executables, toolchain = _prepared_health(tmp_path, monkeypatch)
    _execute_health(
        prepared,
        HealthCheckpointRunner(),
        executables,
        toolchain,
    )
    return prepared


def _proof(
    loaded: _JoinSafetyLoaded, status: DeployScyllaJoinSafetyProofStatus
) -> DeployScyllaJoinSafetyProof:
    return DeployScyllaJoinSafetyProof.create(
        status=status,
        captured_at=loaded.health_evidence.record.created_at,
        evidence_digest=_EVIDENCE_DIGEST,
        health_evidence_digest=loaded.health_evidence.record.evidence_digest,
        target_digest=loaded.target_digest,
        survivor_set_digest=loaded.survivor_set_digest,
        topology_digest=loaded.current_topology_digest,
        target_storage_evidence_digest=loaded.target_storage_evidence_digest,
        target_configuration_evidence_digest=(
            loaded.target_configuration_evidence_digest
        ),
        playbook_source_digest=loaded.playbook_source_digest,
    )


def _call(
    prepared: _Prepared,
    status: DeployScyllaJoinSafetyProofStatus,
    *,
    transform: Callable[
        [DeployScyllaJoinSafetyProof], DeployScyllaJoinSafetyProof
    ] = lambda value: value,
) -> DeployScyllaJoinSafetyReport:
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        loaded = _load_join_safety(prepared.paths, OPERATION_ID, lock=lock)
        proof = transform(_proof(loaded, status))
        return bind_deploy_scylla_join_safety(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proofs=(proof,),
        )


def _replace_proof(
    proof: DeployScyllaJoinSafetyProof, field: str, replacement: str
) -> DeployScyllaJoinSafetyProof:
    value = proof.to_object()
    value[field] = replacement
    value["proof_digest"] = _proof_digest_from_values(value)
    return DeployScyllaJoinSafetyProof.from_object(value)


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for item in value.values() for key in _keys(item)}
    if isinstance(value, list):
        return {key for item in value for key in _keys(item)}
    return set()


def test_join_safety_api_and_initial_deploy_gate_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert tuple(inspect.signature(bind_deploy_scylla_join_safety).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "proofs",
    )
    prepared = _prepared(tmp_path, monkeypatch)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()

    report = _call(prepared, DeployScyllaJoinSafetyProofStatus.PASSED)

    assert report.context_state is DeployScyllaJoinSafetyArtifactState.CREATED
    assert report.evidence_state is DeployScyllaJoinSafetyArtifactState.CREATED
    assert report.reconciliation_state is DeployScyllaJoinSafetyArtifactState.CREATED
    assert report.required_gate_count == 8
    assert report.required_passed_count == 8
    assert report.not_applicable_gate_count == 3
    assert report.failed_count == 0
    assert report.unknown_count == 0
    assert report.first_join_sequence == 2
    assert report.first_join_status == "authorization-required"
    assert report.later_join_count == 1
    assert report.authorization_state == "not-created"
    assert report.execution_state == "unavailable"
    assert not report.journal_updated
    assert journal_path.read_bytes() == journal_before

    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        context = DeployScyllaJoinSafetyContextStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence = DeployScyllaJoinSafetyEvidenceStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        reconciliation = DeployScyllaJoinSafetyReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    assert context.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
    )
    assert context.record.required_gates == (
        "capacity",
        "completed-prior-membership",
        "schema",
        "seed-health",
        "streaming",
        "survivor-health",
        "target-absence",
        "topology",
    )
    assert context.record.not_applicable_gates == (
        "backup-policy",
        "quorum",
        "replication",
    )
    assert evidence.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
    )
    assert {gate.name: gate.status.value for gate in evidence.record.gates} == {
        "backup-policy": "not-applicable",
        "capacity": "passed",
        "completed-prior-membership": "passed",
        "quorum": "not-applicable",
        "replication": "not-applicable",
        "schema": "passed",
        "seed-health": "passed",
        "streaming": "passed",
        "survivor-health": "passed",
        "target-absence": "passed",
        "topology": "passed",
    }
    assert reconciliation.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION
    )
    assert tuple(step.status.value for step in reconciliation.record.steps) == (
        "health-succeeded",
        "authorization-required",
        "waiting-for-preceding-complete-health",
    )
    _run_show(prepared.paths)


@pytest.mark.parametrize(
    ("proof_status", "expected_status", "expected_blocker"),
    (
        (
            DeployScyllaJoinSafetyProofStatus.FAILED,
            "blocked",
            "capacity-failed",
        ),
        (
            DeployScyllaJoinSafetyProofStatus.UNKNOWN,
            "blocked",
            "capacity-unknown",
        ),
    ),
)
def test_join_safety_never_passes_failed_or_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    proof_status: DeployScyllaJoinSafetyProofStatus,
    expected_status: str,
    expected_blocker: str,
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    report = _call(prepared, proof_status)
    assert report.first_join_status == expected_status
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        evidence = DeployScyllaJoinSafetyEvidenceStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        reconciliation = DeployScyllaJoinSafetyReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    assert expected_blocker in evidence.record.blockers
    assert reconciliation.record.steps[1].status.value == "blocked"
    assert reconciliation.record.steps[2].status.value == (
        "waiting-for-preceding-complete-health"
    )


def test_join_safety_refuses_stale_or_mismatched_proof_without_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    for field in (
        "captured_at",
        "health_evidence_digest",
        "target_digest",
        "survivor_set_digest",
        "topology_digest",
        "target_storage_evidence_digest",
        "target_configuration_evidence_digest",
        "playbook_source_digest",
    ):
        replacement = (
            "2026-09-20T00:00:00Z" if field == "captured_at" else "sha256:" + "f" * 64
        )
        with pytest.raises(StateConflictError, match="stale or binding-mismatched"):
            _call(
                prepared,
                DeployScyllaJoinSafetyProofStatus.PASSED,
                transform=lambda proof, current=field, value=replacement: (
                    _replace_proof(proof, current, value)
                ),
            )
        assert not deploy_scylla_join_safety_context_path(
            prepared.paths, OPERATION_ID
        ).exists()
    with pytest.raises(StateConflictError, match="not-applicable is not permitted"):
        _call(prepared, DeployScyllaJoinSafetyProofStatus.NOT_APPLICABLE)
    assert not deploy_scylla_join_safety_context_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_join_safety_exact_reuse_permissions_paths_and_redaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    first = _call(prepared, DeployScyllaJoinSafetyProofStatus.PASSED)
    paths = (
        deploy_scylla_join_safety_context_path(prepared.paths, OPERATION_ID),
        deploy_scylla_join_safety_evidence_path(prepared.paths, OPERATION_ID),
        deploy_scylla_join_safety_reconciliation_path(prepared.paths, OPERATION_ID),
    )
    before = tuple(path.read_bytes() for path in paths)
    second = _call(prepared, DeployScyllaJoinSafetyProofStatus.PASSED)
    assert first.context_artifact_digest == second.context_artifact_digest
    assert second.context_state is DeployScyllaJoinSafetyArtifactState.REUSED
    assert second.evidence_state is DeployScyllaJoinSafetyArtifactState.REUSED
    assert second.reconciliation_state is DeployScyllaJoinSafetyArtifactState.REUSED
    assert tuple(path.read_bytes() for path in paths) == before
    with pytest.raises(StateConflictError, match="immutable"):
        _call(prepared, DeployScyllaJoinSafetyProofStatus.UNKNOWN)
    assert tuple(path.read_bytes() for path in paths) == before
    for path in paths:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        payload = path.read_text(encoding="utf-8")
        assert _HOST_ID not in payload
        assert "10.0.0." not in payload
        assert "ocid1." not in payload
        assert _PRIVATE_PATH not in payload
        assert _SECRET not in payload
        assert _keys(json.loads(payload)).isdisjoint(
            {
                "address",
                "command",
                "configuration",
                "credential",
                "environment",
                "host_id",
                "output",
                "provider_id",
                "query",
                "secret",
                "variables",
            }
        )
    assert (
        deploy_scylla_join_safety_context_id_from_filename(paths[0].name)
        == OPERATION_ID
    )
    assert (
        deploy_scylla_join_safety_evidence_id_from_filename(paths[1].name)
        == OPERATION_ID
    )
    assert (
        deploy_scylla_join_safety_reconciliation_id_from_filename(paths[2].name)
        == OPERATION_ID
    )
    assert (
        deploy_scylla_join_safety_context_id_from_filename(
            f"{str(OPERATION_ID).upper()}.ansible-deploy-scylla-join-safety-context.json"
        )
        is None
    )


def test_join_safety_refuses_target_or_survivor_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared = _prepared(tmp_path, monkeypatch)
    value = json.loads(prepared.paths.ansible_inventory.read_text(encoding="utf-8"))
    value["all"]["hosts"]["scylla-ad-1-2"]["deploy_scylla_vms_scylla_rack"] = "drifted"
    prepared.paths.ansible_inventory.write_text(
        json.dumps(value, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    prepared.paths.ansible_inventory.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, DeployScyllaJoinSafetyProofStatus.PASSED)
    assert not deploy_scylla_join_safety_context_path(
        prepared.paths, OPERATION_ID
    ).exists()
