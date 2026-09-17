import inspect
import json
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

import pytest
import test_ansible_deploy_scylla_sequence_three_join_safety as safety_fixture
from test_ansible_deploy_scylla_bootstrap_execution import (
    _HOST_ID as INITIAL_HOST_ID,
)
from test_ansible_deploy_scylla_join_execution import _HOST_ID as JOIN_HOST_ID
from test_ansible_deploy_scylla_sequence_three_join_execution import (
    _HOST_ID as SEQUENCE_THREE_HOST_ID,
)
from test_ansible_deploy_scylla_sequence_three_join_execution import (
    SequenceThreeJoinRunner,
)
from test_ansible_deploy_scylla_sequence_three_join_execution import (
    _call as _execute_sequence_three,
)
from test_ansible_deploy_scylla_sequence_three_join_execution import (
    _prepared as _prepared_sequence_three,
)
from test_ansible_scylla_health import SCHEMA, _stdout
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_operation_composition import _Prepared
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_scylla_health_checkpoint import (
    DeployScyllaHealthArtifactState,
    DeployScyllaHealthExecutionState,
)
from scylla_vms.ansible.deploy_scylla_post_sequence_three_join_health import (
    ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_RECONCILIATION_SCHEMA_VERSION,
    DeployScyllaPostSequenceThreeHealthEvidenceStore,
    DeployScyllaPostSequenceThreeHealthExecution,
    DeployScyllaPostSequenceThreeHealthExecutionStore,
    DeployScyllaPostSequenceThreeHealthReconciliationStore,
    deploy_scylla_post_sequence_three_health_evidence_path,
    deploy_scylla_post_sequence_three_health_execution_path,
    deploy_scylla_post_sequence_three_health_reconciliation_path,
    execute_deploy_scylla_post_sequence_three_join_health,
)
from scylla_vms.ansible.scylla_health import SCYLLA_HEALTH_VIEW_SCHEMA_VERSION
from scylla_vms.ansible.scylla_install import SCYLLA_PACKAGE_VERSION
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.process import ProcessResult, ProcessSpec, ProcessTimeoutError
from scylla_vms.state import StatePaths

_PRIVATE_PATH = "/private/operator/post-sequence-three-health.json"
_SECRET = "obviously-fake-post-sequence-three-health-secret"
_COMMANDS = [
    ["/usr/bin/nodetool", "info"],
    ["/usr/bin/nodetool", "status"],
    ["/usr/bin/nodetool", "describecluster"],
    ["/usr/bin/nodetool", "netstats"],
    ["/usr/bin/nodetool", "version"],
    ["/usr/bin/systemctl", "is-active", "scylla-server.service"],
]


@dataclass
class PostSequenceThreeHealthRunner:
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
        assert queried == (
            "scylla-ad-1-1",
            "scylla-ad-1-2",
            "scylla-ad-1-3",
        )
        assert spec.argv[spec.argv.index("--limit") + 1] == ",".join(queried)
        if self.inspect_started:
            assert self.paths is not None
            record = DeployScyllaPostSequenceThreeHealthExecution.from_object(
                cast(
                    dict[str, object],
                    json.loads(
                        deploy_scylla_post_sequence_three_health_execution_path(
                            self.paths, OPERATION_ID
                        ).read_text(encoding="utf-8")
                    ),
                )
            )
            assert record.state is DeployScyllaHealthExecutionState.STARTED
            assert record.invocation_count == 1
            assert record.manual_recovery_required
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
            queried[2]: SEQUENCE_THREE_HOST_ID,
        }
        ring = sorted(
            (
                {
                    "datacenter": expected_hosts[stable_id]["datacenter"],
                    "host_id": host_ids[stable_id],
                    "rack": expected_hosts[stable_id]["rack"],
                    "state": (
                        "DN"
                        if self.mode == "down" and stable_id == queried[2]
                        else "UN"
                    ),
                }
                for stable_id in queried
            ),
            key=lambda item: cast(str, item["host_id"]),
        )
        view_ids = queried[:-1] if self.mode == "incomplete-membership" else queried
        views = [
            {
                "api_reachable": True,
                "captured_at": "2026-09-21T20:00:00Z",
                "commands": _COMMANDS,
                "cql_reachable": True,
                "datacenter": expected_hosts[stable_id]["datacenter"],
                "errors": [],
                "local_host_id": host_ids[stable_id],
                "logical_id": stable_id,
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
            for stable_id in view_ids
        ]
        stdout, exit_code = _stdout(views, queried)
        return ProcessResult(exit_code, stdout, f"{_SECRET} {_PRIVATE_PATH}")


def _prepared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[_Prepared, object, object]:
    prepared, executables, toolchain = _prepared_sequence_three(tmp_path, monkeypatch)
    _execute_sequence_three(prepared, SequenceThreeJoinRunner(), executables, toolchain)
    return prepared, executables, toolchain


def _call(
    prepared: _Prepared,
    runner: PostSequenceThreeHealthRunner,
    executables: object,
    toolchain: object,
):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_scylla_post_sequence_three_join_health(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )


def _records(prepared: _Prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        execution = DeployScyllaPostSequenceThreeHealthExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployScyllaPostSequenceThreeHealthEvidenceStore(
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
        reconciliation_store = DeployScyllaPostSequenceThreeHealthReconciliationStore(
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


def test_post_sequence_three_health_success_next_step_unknown_policy_and_reentry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert tuple(
        inspect.signature(
            execute_deploy_scylla_post_sequence_three_join_health
        ).parameters
    ) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "runner",
        "executables",
        "toolchain",
    )
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    sequence_execution_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-scylla-sequence-three-join-execution.json"
    )
    prior = journal_path.read_bytes(), sequence_execution_path.read_bytes()
    runner = PostSequenceThreeHealthRunner(inspect_started=True, paths=prepared.paths)

    report = _call(prepared, runner, executables, toolchain)
    execution, evidence, reconciliation = _records(prepared)

    assert evidence is not None and reconciliation is not None
    assert (
        execution.record.schema_version
        == ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EXECUTION_SCHEMA_VERSION
    )
    assert (
        evidence.record.schema_version
        == ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_EVIDENCE_SCHEMA_VERSION
    )
    assert reconciliation.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_POST_SEQUENCE_THREE_HEALTH_RECONCILIATION_SCHEMA_VERSION
    )
    assert report.execution_state is DeployScyllaHealthExecutionState.SUCCEEDED
    assert report.current_member_count == 3
    assert report.desired_member_count == 4
    assert report.future_member_count == 1
    assert report.health_complete
    assert report.host_identity_count == report.up_normal_count == 3
    assert report.service_ready_count == report.api_ready_count == 3
    assert report.cql_ready_count == report.storage_ready_count == 3
    assert report.schema_agreement and report.streaming_idle
    assert report.policy_unknown_count == 2
    assert report.policy_not_performed_count == 2
    assert not report.bootstrap_sequence_complete
    assert report.next_step_required
    assert report.next_join_sequence == 4
    assert report.next_join_status == "waiting-for-separate-safety-context"
    assert report.next_join_blocker_count == 1
    assert report.later_join_count == 0
    assert [step.status.value for step in reconciliation.record.steps] == [
        "health-succeeded",
        "health-succeeded",
        "health-succeeded",
        "waiting-for-separate-safety-context",
    ]
    assert reconciliation.record.steps[3].blockers == (
        "separate-safety-context-not-created",
    )
    assert {name: state.value for name, state in evidence.record.policy_states} == {
        "backup-policy": "not-performed",
        "capacity": "unknown",
        "quorum": "unknown",
        "replication": "not-performed",
    }
    assert (journal_path.read_bytes(), sequence_execution_path.read_bytes()) == prior
    artifacts = (
        deploy_scylla_post_sequence_three_health_execution_path(
            prepared.paths, OPERATION_ID
        ),
        deploy_scylla_post_sequence_three_health_evidence_path(
            prepared.paths, OPERATION_ID
        ),
        deploy_scylla_post_sequence_three_health_reconciliation_path(
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
        SEQUENCE_THREE_HOST_ID,
        "ansible-playbook",
        "--limit",
        '"command"',
        '"variables"',
        '"environment"',
        '"path"',
    ):
        assert protected not in persisted
    before = tuple(path.read_bytes() for path in artifacts)
    zero_runner = PostSequenceThreeHealthRunner(mode="timeout")
    reused = _call(prepared, zero_runner, executables, toolchain)
    assert zero_runner.specs == []
    assert (
        reused.reconciliation_artifact_state is DeployScyllaHealthArtifactState.REUSED
    )
    assert tuple(path.read_bytes() for path in artifacts) == before
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


@pytest.mark.parametrize(
    ("mode", "expected_state"),
    [
        ("timeout", DeployScyllaHealthExecutionState.TIMED_OUT),
        ("malformed", DeployScyllaHealthExecutionState.MALFORMED_RESULT),
        ("incomplete-membership", DeployScyllaHealthExecutionState.MALFORMED_RESULT),
        ("down", DeployScyllaHealthExecutionState.FAILED),
    ],
)
def test_post_sequence_three_health_failure_is_manual_recovery_and_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    expected_state: DeployScyllaHealthExecutionState,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = PostSequenceThreeHealthRunner(mode=mode)
    with pytest.raises(AnsibleError, match="manual recovery") as caught:
        _call(prepared, runner, executables, toolchain)
    assert _PRIVATE_PATH not in str(caught.value)
    assert _SECRET not in str(caught.value)
    execution, evidence, reconciliation = _records(prepared)
    assert execution.record.state is expected_state
    assert execution.record.manual_recovery_required
    assert not execution.record.automatic_retry_allowed
    assert reconciliation is None
    if expected_state is DeployScyllaHealthExecutionState.FAILED:
        assert evidence is not None and not evidence.record.strict_complete
    else:
        assert evidence is None
    process_count = len(runner.specs or [])
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, runner, executables, toolchain)
    assert len(runner.specs or []) == process_count


def test_post_sequence_three_health_refuses_missing_tamper_and_post_call_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared_sequence_three(tmp_path, monkeypatch)
    runner = PostSequenceThreeHealthRunner()
    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []

    _execute_sequence_three(prepared, SequenceThreeJoinRunner(), executables, toolchain)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        execute_deploy_scylla_post_sequence_three_join_health(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )
    assert runner.specs == []

    evidence_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-scylla-sequence-three-join-evidence.json"
    )
    original = evidence_path.read_bytes()
    value = cast(dict[str, object], json.loads(original))
    value["host_id_digest"] = "sha256:" + "f" * 64
    evidence_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    evidence_path.chmod(0o600)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
    evidence_path.write_bytes(original)
    evidence_path.chmod(0o600)

    with pytest.raises(AnsibleError, match="manual recovery"):
        _call(
            prepared,
            PostSequenceThreeHealthRunner(
                mode="drift-after-start", paths=prepared.paths
            ),
            executables,
            toolchain,
        )
    execution, evidence, reconciliation = _records(prepared)
    assert execution.record.state is DeployScyllaHealthExecutionState.MALFORMED_RESULT
    assert evidence is None and reconciliation is None


def test_post_sequence_three_health_recovers_reconciliation_and_show_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    original_write = DeployScyllaPostSequenceThreeHealthReconciliationStore.write_locked
    failed = False

    def fail_once(self, record, **kwargs):
        nonlocal failed
        if not failed:
            failed = True
            raise StatePersistenceError("reconciliation persistence failure")
        return original_write(self, record, **kwargs)

    monkeypatch.setattr(
        DeployScyllaPostSequenceThreeHealthReconciliationStore,
        "write_locked",
        fail_once,
    )
    with pytest.raises(StatePersistenceError, match="reconciliation"):
        _call(
            prepared,
            PostSequenceThreeHealthRunner(),
            executables,
            toolchain,
        )
    execution, evidence, reconciliation = _records(prepared)
    assert execution.record.state is DeployScyllaHealthExecutionState.SUCCEEDED
    assert evidence is not None and evidence.record.strict_complete
    assert reconciliation is None

    runner = PostSequenceThreeHealthRunner(mode="timeout")
    report = _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
    assert (
        report.reconciliation_artifact_state
        is DeployScyllaHealthArtifactState.RECOVERED
    )
    path = deploy_scylla_post_sequence_three_health_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    original = path.read_bytes()
    value = cast(dict[str, object], json.loads(original))
    value["current_member_count"] = 4
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
    path.write_bytes(original)
    path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


def test_post_sequence_three_health_reports_bootstrap_sequence_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def three_node_spec(path: Path):
        spec = safety_fixture._ORIGINAL_SPEC(path)
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

    monkeypatch.setattr(safety_fixture, "_four_node_spec", three_node_spec)
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    report = _call(
        prepared,
        PostSequenceThreeHealthRunner(),
        executables,
        toolchain,
    )
    _, _, reconciliation = _records(prepared)
    assert reconciliation is not None
    assert report.bootstrap_sequence_complete
    assert not report.next_step_required
    assert report.next_join_sequence is None
    assert report.next_join_status == "not-required"
    assert report.next_join_blocker_count == 0
    assert report.later_join_count == 0
    assert reconciliation.record.bootstrap_sequence_complete
