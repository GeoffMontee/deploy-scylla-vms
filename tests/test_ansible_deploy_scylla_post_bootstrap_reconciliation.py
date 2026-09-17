import inspect
import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
import test_ansible_deploy_scylla_health_checkpoint as health_fixture
import test_ansible_deploy_scylla_join_authorization as join_authorization_fixture
import test_ansible_deploy_scylla_join_execution as join_execution_fixture
import test_ansible_deploy_scylla_join_safety as join_safety_fixture
import test_ansible_deploy_scylla_post_join_health as post_join_health_fixture
import test_ansible_deploy_scylla_post_later_join_health as later_health_fixture
import test_ansible_deploy_scylla_post_sequence_three_join_health as sequence_three_health_fixture
import test_provider_source
import test_terraform_apply_inventory
import test_terraform_plan_checkpoint
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_scylla_health_checkpoint import (
    deploy_scylla_health_evidence_path,
)
from scylla_vms.ansible.deploy_scylla_join_safety import (
    DeployScyllaJoinSafetyProofStatus,
)
from scylla_vms.ansible.deploy_scylla_post_bootstrap_reconciliation import (
    ANSIBLE_DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_SCHEMA_VERSION,
    DeployPostBootstrapArtifactState,
    DeployPostBootstrapReconciliationStore,
    DeployPostBootstrapStepStatus,
    _final_health_kind,
    deploy_scylla_post_bootstrap_reconciliation_id_from_filename,
    deploy_scylla_post_bootstrap_reconciliation_path,
    reconcile_deploy_scylla_post_bootstrap,
)
from scylla_vms.errors import StateConflictError, StatePersistenceError, UnsafePathError
from scylla_vms.locking import ClusterLock


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_scylla_post_bootstrap(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployPostBootstrapReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


def _two_node_spec(tmp_path: Path):
    spec = join_safety_fixture._ORIGINAL_SPEC(tmp_path)
    zone = replace(
        spec.zones[0],
        scylla_nodes=2,
        logical_node_ids=("scylla-ad-1-1", "scylla-ad-1-2"),
    )
    return replace(spec, zones=(zone,))


def _three_node_spec(tmp_path: Path):
    spec = sequence_three_health_fixture.safety_fixture._ORIGINAL_SPEC(tmp_path)
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


def test_post_bootstrap_bridge_initial_seed_reuses_and_show_validates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert tuple(
        inspect.signature(reconcile_deploy_scylla_post_bootstrap).parameters
    ) == ("state_root", "cluster_name", "operation_id", "lock")
    prepared, executables, toolchain = health_fixture._prepared(tmp_path, monkeypatch)
    health_fixture._call(
        prepared,
        health_fixture.HealthCheckpointRunner(),
        executables,
        toolchain,
    )
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal = journal_path.read_bytes()

    report = _call(prepared)
    stored = _record(prepared)
    path = deploy_scylla_post_bootstrap_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    before = path.read_bytes()

    assert report.artifact_state is DeployPostBootstrapArtifactState.CREATED
    assert report.completed_sequence == report.current_member_count == 1
    assert report.final_health_kind == "initial-seed-health"
    assert report.mapped_health_state == "satisfied-by-final-complete-set-health"
    assert report.next_mapping_sequence == 14
    assert report.next_playbook == "manager-server"
    assert (
        report.next_step_status
        is DeployPostBootstrapStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
    )
    assert report.policy_unknown_count == report.policy_not_performed_count == 2
    assert report.original_mapping_unchanged
    assert report.process_calls == 0
    assert not report.retry_allowed
    assert stored.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_SCHEMA_VERSION
    )
    assert stored.record.original_mapping_count == 21
    assert tuple(sorted({step.mapping_sequence for step in stored.record.steps})) == (
        tuple(range(1, 22))
    )
    mapped_health = tuple(
        step for step in stored.record.steps if step.mapping_sequence == 13
    )
    assert len(mapped_health) == 1
    assert mapped_health[0].status is DeployPostBootstrapStepStatus.SUCCEEDED
    assert not mapped_health[0].blockers
    assert stored.record.steps != ()
    assert path.stat().st_mode & 0o777 == 0o600
    assert deploy_scylla_post_bootstrap_reconciliation_id_from_filename(path.name) == (
        OPERATION_ID
    )
    assert journal_path.read_bytes() == journal
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0

    reused = _call(prepared)
    assert reused.artifact_state is DeployPostBootstrapArtifactState.REUSED
    assert path.read_bytes() == before
    assert journal_path.read_bytes() == journal

    value = cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))
    value["record_digest"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
    with pytest.raises(StatePersistenceError):
        _call(prepared)
    path.write_bytes(before)
    path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


def test_post_bootstrap_bridge_requires_terminal_final_health_and_refuses_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = health_fixture._prepared(tmp_path, monkeypatch)
    path = deploy_scylla_post_bootstrap_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _call(prepared)
    assert not path.exists()

    health_fixture._call(
        prepared,
        health_fixture.HealthCheckpointRunner(),
        executables,
        toolchain,
    )
    evidence_path = deploy_scylla_health_evidence_path(prepared.paths, OPERATION_ID)
    original = evidence_path.read_bytes()
    value = cast(
        dict[str, object], json.loads(evidence_path.read_text(encoding="utf-8"))
    )
    value["strict_complete"] = False
    evidence_path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    evidence_path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not path.exists()
    evidence_path.write_bytes(original)
    evidence_path.chmod(0o600)

    extra = (
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-scylla-join-execution.json"
    )
    extra.write_text("{}\n", encoding="utf-8")
    extra.chmod(0o600)
    with pytest.raises(StateConflictError):
        _call(prepared)
    assert not path.exists()


def test_post_bootstrap_bridge_refuses_current_state_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = health_fixture._prepared(tmp_path, monkeypatch)
    health_fixture._call(
        prepared,
        health_fixture.HealthCheckpointRunner(),
        executables,
        toolchain,
    )
    with prepared.paths.ansible_inventory.open("a", encoding="utf-8") as stream:
        stream.write(" ")
    with pytest.raises(StateConflictError):
        _call(prepared)
    assert not deploy_scylla_post_bootstrap_reconciliation_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_post_bootstrap_bridge_accepts_completed_sequence_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(test_provider_source, "_spec", _two_node_spec)
    monkeypatch.setattr(test_terraform_plan_checkpoint, "_spec", _two_node_spec)
    monkeypatch.setattr(
        test_terraform_apply_inventory,
        "_valid_output",
        join_safety_fixture._multi_output,
    )
    prepared, executables, toolchain = health_fixture._prepared(tmp_path, monkeypatch)
    health_fixture._call(
        prepared,
        health_fixture.HealthCheckpointRunner(),
        executables,
        toolchain,
    )
    join_safety_fixture._call(prepared, DeployScyllaJoinSafetyProofStatus.PASSED)
    join_authorization_fixture._call(
        prepared, join_authorization_fixture._proof(prepared)
    )
    join_execution_fixture._call(
        prepared,
        join_execution_fixture.FirstJoinRunner(),
        executables,
        toolchain,
    )
    post_join_health_fixture._call(
        prepared,
        post_join_health_fixture.PostJoinHealthRunner(),
        executables,
        toolchain,
    )

    report = _call(prepared)
    stored = _record(prepared)

    assert report.completed_sequence == 2
    assert report.current_member_count == 2
    assert report.final_health_kind == "first-join-health"
    assert stored.record.final_health_kind == "first-join-health"


def test_post_bootstrap_bridge_accepts_completed_sequence_three(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        sequence_three_health_fixture.safety_fixture,
        "_four_node_spec",
        _three_node_spec,
    )
    prepared, executables, toolchain = sequence_three_health_fixture._prepared(
        tmp_path, monkeypatch
    )
    sequence_three_health_fixture._call(
        prepared,
        sequence_three_health_fixture.PostSequenceThreeHealthRunner(),
        executables,
        toolchain,
    )

    report = _call(prepared)
    stored = _record(prepared)

    assert report.completed_sequence == 3
    assert report.current_member_count == 3
    assert report.final_health_kind == "sequence-three-health"
    assert stored.record.final_health_kind == "sequence-three-health"


def test_post_bootstrap_bridge_accepts_completed_generic_later_join(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = later_health_fixture._prepared_four_node(
        tmp_path, monkeypatch
    )
    later_health_fixture._call(
        prepared,
        later_health_fixture.PostLaterJoinHealthRunner(),
        executables,
        toolchain,
    )
    report = _call(prepared)
    stored = _record(prepared)

    assert report.completed_sequence == report.current_member_count == 4
    assert report.final_health_kind == "later-join-health"
    assert stored.record.bootstrap_step_count == 4
    assert stored.record.completed_sequence == 4
    assert stored.record.original_mapping_unchanged
    assert len(stored.record.steps) > stored.record.original_mapping_count
    assert (
        sum(
            step.status
            is DeployPostBootstrapStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            for step in stored.record.steps
        )
        == 1
    )
    public = json.dumps(report.to_object(), sort_keys=True)
    for protected in (
        "/private/",
        "host_id",
        "provider_id",
        "seed",
        "command",
        "variable",
        "environment",
        "credential",
        "secret",
    ):
        assert protected not in public.lower()


@pytest.mark.parametrize(
    ("step_count", "expected"),
    (
        (1, "initial-seed-health"),
        (2, "first-join-health"),
        (3, "sequence-three-health"),
        (4, "later-join-health"),
        (8, "later-join-health"),
    ),
)
def test_post_bootstrap_final_health_branch_selection(
    step_count: int, expected: str
) -> None:
    assert _final_health_kind(step_count) == expected
