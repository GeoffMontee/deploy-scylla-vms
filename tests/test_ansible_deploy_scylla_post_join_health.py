import json
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_scylla_bootstrap_execution import (
    _HOST_ID as INITIAL_HOST_ID,
)
from test_ansible_deploy_scylla_join_execution import (
    _HOST_ID as JOIN_HOST_ID,
)
from test_ansible_deploy_scylla_join_execution import (
    FirstJoinRunner,
)
from test_ansible_deploy_scylla_join_execution import (
    _call as _execute_join,
)
from test_ansible_deploy_scylla_join_execution import (
    _prepared as _prepared_join,
)
from test_ansible_scylla_health import SCHEMA, _stdout
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_scylla_health_checkpoint import (
    DeployScyllaHealthArtifactState,
    DeployScyllaHealthExecutionState,
)
from scylla_vms.ansible.deploy_scylla_post_join_health import (
    ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_SCHEMA_VERSION,
    DeployScyllaPostJoinHealthEvidenceStore,
    DeployScyllaPostJoinHealthExecution,
    DeployScyllaPostJoinHealthExecutionStore,
    DeployScyllaPostJoinHealthReconciliationStore,
    deploy_scylla_post_join_health_evidence_path,
    deploy_scylla_post_join_health_execution_path,
    deploy_scylla_post_join_health_reconciliation_path,
    execute_deploy_scylla_post_join_health,
)
from scylla_vms.ansible.scylla_health import (
    SCYLLA_HEALTH_VIEW_SCHEMA_VERSION,
)
from scylla_vms.ansible.scylla_install import SCYLLA_PACKAGE_VERSION
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.process import ProcessResult, ProcessSpec, ProcessTimeoutError
from scylla_vms.state import StatePaths

_THIRD_HOST_ID = "33333333-3333-4333-8333-333333333333"
_PRIVATE_PATH = "/private/operator/post-join-health.json"
_SECRET = "obviously-fake-post-join-health-secret"
_COMMANDS = [
    ["/usr/bin/nodetool", "info"],
    ["/usr/bin/nodetool", "status"],
    ["/usr/bin/nodetool", "describecluster"],
    ["/usr/bin/nodetool", "netstats"],
    ["/usr/bin/nodetool", "version"],
    ["/usr/bin/systemctl", "is-active", "scylla-server.service"],
]


@dataclass
class PostJoinHealthRunner:
    mode: str = "success"
    inspect_started: bool = False
    paths: StatePaths | None = None
    specs: list[ProcessSpec] | None = None
    payloads: list[dict[str, object]] | None = None

    def __post_init__(self) -> None:
        self.specs = []
        self.payloads = []

    def run(self, spec: ProcessSpec) -> ProcessResult:
        assert self.specs is not None
        assert self.payloads is not None
        self.specs.append(spec)
        if spec.argv[-1] == "--version":
            return ProcessResult(0, f"{Path(spec.argv[0]).name} [core 2.20.9]\n", "")
        playbook = next(
            Path(argument).stem
            for argument in spec.argv
            if "/playbooks/" in argument and argument.endswith(".yml")
        )
        if playbook != "scylla-health":
            raise AssertionError(f"unexpected external playbook: {playbook}")
        runtime_path = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        variables = cast(
            dict[str, object], json.loads(runtime_path.read_text(encoding="utf-8"))
        )
        payload = cast(dict[str, object], variables["deploy_scylla_vms_scylla_health"])
        self.payloads.append(payload)
        queried = tuple(cast(list[str], payload["queried_nodes"]))
        assert queried == ("scylla-ad-1-1", "scylla-ad-1-2")
        assert spec.argv[spec.argv.index("--limit") + 1] == ",".join(queried)
        if self.inspect_started:
            assert self.paths is not None
            record = DeployScyllaPostJoinHealthExecution.from_object(
                cast(
                    dict[str, object],
                    json.loads(
                        deploy_scylla_post_join_health_execution_path(
                            self.paths, OPERATION_ID
                        ).read_text(encoding="utf-8")
                    ),
                )
            )
            assert record.state is DeployScyllaHealthExecutionState.STARTED
            assert record.invocation_count == 1
        if self.mode == "timeout":
            raise ProcessTimeoutError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "malformed":
            return ProcessResult(0, "malformed", f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "drift-after-start":
            assert self.paths is not None
            with self.paths.ansible_inventory.open("a", encoding="utf-8") as stream:
                stream.write(" ")

        expected_hosts = {
            cast(str, item["logical_id"]): cast(dict[str, object], item)
            for item in cast(list[dict[str, object]], payload["expected_hosts"])
        }
        host_ids = {
            queried[0]: INITIAL_HOST_ID,
            queried[1]: JOIN_HOST_ID,
        }
        if self.mode == "wrong-joined-host-id":
            host_ids[queried[1]] = _THIRD_HOST_ID
        ring = sorted(
            (
                {
                    "datacenter": expected_hosts[stable_id]["datacenter"],
                    "host_id": host_ids[stable_id],
                    "rack": expected_hosts[stable_id]["rack"],
                    "state": (
                        "DN"
                        if self.mode == "down" and stable_id == queried[1]
                        else "UN"
                    ),
                }
                for stable_id in queried
            ),
            key=lambda item: cast(str, item["host_id"]),
        )
        views = [
            {
                "api_reachable": True,
                "captured_at": "2026-09-21T18:00:00Z",
                "commands": _COMMANDS,
                "cql_reachable": True,
                "datacenter": expected_hosts[stable_id]["datacenter"],
                "errors": [],
                "local_host_id": host_ids[stable_id],
                "logical_id": (
                    queried[0]
                    if self.mode == "duplicate-target" and stable_id == queried[1]
                    else "scylla-ad-1-3"
                    if self.mode == "wrong-target" and stable_id == queried[1]
                    else stable_id
                ),
                "mode": "NORMAL",
                "rack": expected_hosts[stable_id]["rack"],
                "receiving_streams": 0,
                "ring": ring,
                "schema_version": SCYLLA_HEALTH_VIEW_SCHEMA_VERSION,
                "schema_versions": [SCHEMA],
                "sending_streams": 0,
                "service_state": "active",
                "version": SCYLLA_PACKAGE_VERSION,
            }
            for stable_id in queried
        ]
        stdout, exit_code = _stdout(views, queried)
        return ProcessResult(exit_code, stdout, f"{_SECRET} {_PRIVATE_PATH}")


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, executables, toolchain = _prepared_join(tmp_path, monkeypatch)
    _execute_join(prepared, FirstJoinRunner(), executables, toolchain)
    return prepared, executables, toolchain


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_scylla_post_join_health(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )


def _records(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        execution = DeployScyllaPostJoinHealthExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployScyllaPostJoinHealthEvidenceStore(
            prepared.paths, OPERATION_ID
        )
        evidence = (
            evidence_store.read_locked(
                lock,
                expected_cluster_uuid=CLUSTER_UUID,
                expected_cluster_name="example",
            )
            if evidence_store.path.exists()
            else None
        )
        reconciliation_store = DeployScyllaPostJoinHealthReconciliationStore(
            prepared.paths, OPERATION_ID
        )
        reconciliation = (
            reconciliation_store.read_locked(
                lock,
                expected_cluster_uuid=CLUSTER_UUID,
                expected_cluster_name="example",
            )
            if reconciliation_store.path.exists()
            else None
        )
    return execution, evidence, reconciliation


def test_post_join_health_executes_complete_set_blocks_only_next_and_reuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    join_paths = (
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-scylla-join-authorization.json",
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-scylla-join-execution.json",
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-scylla-join-evidence.json",
    )
    immutable = (journal_path.read_bytes(), *(path.read_bytes() for path in join_paths))
    runner = PostJoinHealthRunner(inspect_started=True, paths=prepared.paths)

    report = _call(prepared, runner, executables, toolchain)
    execution, evidence, reconciliation = _records(prepared)

    assert evidence is not None and reconciliation is not None
    assert (
        execution.record.schema_version
        == ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EXECUTION_SCHEMA_VERSION
    )
    assert (
        evidence.record.schema_version
        == ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_EVIDENCE_SCHEMA_VERSION
    )
    assert (
        reconciliation.record.schema_version
        == ANSIBLE_DEPLOY_SCYLLA_JOIN_HEALTH_RECONCILIATION_SCHEMA_VERSION
    )
    assert report.execution_state is DeployScyllaHealthExecutionState.SUCCEEDED
    assert report.current_member_count == report.completed_prior_membership_count == 2
    assert report.desired_member_count == 3
    assert report.future_member_count == 1
    assert report.health_complete
    assert report.host_identity_count == report.up_normal_count == 2
    assert report.service_ready_count == report.api_ready_count == 2
    assert report.cql_ready_count == report.storage_ready_count == 2
    assert report.schema_agreement and report.streaming_idle
    assert report.policy_unknown_count == 4
    assert report.next_join_sequence == 3
    assert report.next_join_status == "blocked"
    assert report.next_join_blocker_count == 4
    assert report.later_join_count == 0
    assert len(runner.specs or []) == 3
    assert len(runner.payloads or []) == 1
    payload = cast(dict[str, object], (runner.payloads or [])[0])
    assert payload["queried_nodes"] == ["scylla-ad-1-1", "scylla-ad-1-2"]
    assert [
        item["logical_id"]
        for item in cast(list[dict[str, object]], payload["expected_hosts"])
    ] == ["scylla-ad-1-1", "scylla-ad-1-2"]
    assert tuple(node.stable_id for node in evidence.record.nodes) == (
        "scylla-ad-1-1",
        "scylla-ad-1-2",
    )
    assert {name: status.value for name, status in evidence.record.policy_states} == {
        "backup-policy": "not-performed",
        "capacity": "unknown",
        "quorum": "unknown",
        "replication": "not-performed",
    }
    assert [step.status.value for step in reconciliation.record.steps] == [
        "health-succeeded",
        "health-succeeded",
        "blocked",
    ]
    assert reconciliation.record.steps[2].blockers == (
        "backup-policy-not-performed",
        "capacity-unknown",
        "quorum-unknown",
        "replication-not-performed",
    )
    artifacts = (
        deploy_scylla_post_join_health_execution_path(prepared.paths, OPERATION_ID),
        deploy_scylla_post_join_health_evidence_path(prepared.paths, OPERATION_ID),
        deploy_scylla_post_join_health_reconciliation_path(
            prepared.paths, OPERATION_ID
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
        INITIAL_HOST_ID,
        JOIN_HOST_ID,
        "ansible-playbook",
        "--limit",
        '"command"',
        '"variables"',
        '"environment"',
        '"path"',
    ):
        assert protected not in persisted
    assert (journal_path.read_bytes(), *(path.read_bytes() for path in join_paths)) == (
        immutable
    )
    before = tuple(path.read_bytes() for path in artifacts)
    zero_runner = PostJoinHealthRunner(mode="timeout")
    reused = _call(prepared, zero_runner, executables, toolchain)
    assert zero_runner.specs == []
    assert (
        reused.reconciliation_artifact_state is DeployScyllaHealthArtifactState.REUSED
    )
    assert tuple(path.read_bytes() for path in artifacts) == before
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


@pytest.mark.parametrize(
    "mode",
    ["down", "wrong-joined-host-id", "wrong-target", "duplicate-target"],
)
def test_post_join_health_refuses_incomplete_semantics_and_never_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = PostJoinHealthRunner(mode=mode)

    with pytest.raises(AnsibleError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    execution, evidence, reconciliation = _records(prepared)
    assert execution.record.state in {
        DeployScyllaHealthExecutionState.FAILED,
        DeployScyllaHealthExecutionState.MALFORMED_RESULT,
    }
    assert execution.record.manual_recovery_required
    if execution.record.state is DeployScyllaHealthExecutionState.FAILED:
        assert evidence is not None and not evidence.record.strict_complete
    else:
        assert evidence is None
    assert reconciliation is None
    process_count = len(runner.specs or [])

    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, runner, executables, toolchain)
    assert len(runner.specs or []) == process_count


def test_post_join_health_timeout_is_permanent_uncertainty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = PostJoinHealthRunner(mode="timeout")
    with pytest.raises(AnsibleError, match="manual recovery") as caught:
        _call(prepared, runner, executables, toolchain)
    assert _PRIVATE_PATH not in str(caught.value)
    assert _SECRET not in str(caught.value)
    execution, evidence, reconciliation = _records(prepared)
    assert execution.record.state is DeployScyllaHealthExecutionState.TIMED_OUT
    assert evidence is None and reconciliation is None
    process_count = len(runner.specs or [])
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, runner, executables, toolchain)
    assert len(runner.specs or []) == process_count


def test_post_join_health_post_call_drift_is_permanent_uncertainty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    drift_runner = PostJoinHealthRunner(
        mode="drift-after-start",
        paths=prepared.paths,
    )
    with pytest.raises(AnsibleError, match="manual recovery"):
        _call(prepared, drift_runner, executables, toolchain)
    execution, evidence, reconciliation = _records(prepared)
    assert execution.record.state is DeployScyllaHealthExecutionState.MALFORMED_RESULT
    assert evidence is None and reconciliation is None


def test_post_join_health_refuses_missing_success_and_upstream_tamper_before_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared_join(tmp_path, monkeypatch)
    runner = PostJoinHealthRunner()
    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []

    _execute_join(prepared, FirstJoinRunner(), executables, toolchain)
    join_evidence_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-scylla-join-evidence.json"
    )
    value = cast(
        dict[str, object],
        json.loads(join_evidence_path.read_text(encoding="utf-8")),
    )
    value["host_id_digest"] = "sha256:" + "f" * 64
    join_evidence_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    join_evidence_path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []


def test_post_join_health_recovers_reconciliation_only_and_show_rejects_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    original_write = DeployScyllaPostJoinHealthReconciliationStore.write_locked
    failed = False

    def fail_once(self, record, **kwargs):
        nonlocal failed
        if not failed:
            failed = True
            raise StatePersistenceError("reconciliation persistence failure")
        return original_write(self, record, **kwargs)

    monkeypatch.setattr(
        DeployScyllaPostJoinHealthReconciliationStore,
        "write_locked",
        fail_once,
    )
    with pytest.raises(StatePersistenceError, match="reconciliation"):
        _call(prepared, PostJoinHealthRunner(), executables, toolchain)
    execution, evidence, reconciliation = _records(prepared)
    assert execution.record.state is DeployScyllaHealthExecutionState.SUCCEEDED
    assert evidence is not None and evidence.record.strict_complete
    assert reconciliation is None

    runner = PostJoinHealthRunner(mode="timeout")
    report = _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
    assert (
        report.reconciliation_artifact_state
        is DeployScyllaHealthArtifactState.RECOVERED
    )
    path = deploy_scylla_post_join_health_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    original = path.read_bytes()
    value = cast(dict[str, object], json.loads(original))
    value["current_member_count"] = 3
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
    path.write_bytes(original)
    path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0
