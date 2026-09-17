import json
import stat
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from test_ansible_deploy_scylla_bootstrap_execution import (
    _HOST_ID,
    BootstrapRunner,
)
from test_ansible_deploy_scylla_bootstrap_execution import (
    _call as _execute_bootstrap,
)
from test_ansible_deploy_scylla_bootstrap_execution import (
    _prepared as _prepared_bootstrap,
)
from test_ansible_scylla_health import _ring, _stdout, _view
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_scylla_bootstrap_plan import ScyllaBootstrapMode
from scylla_vms.ansible.deploy_scylla_health_checkpoint import (
    ANSIBLE_DEPLOY_SCYLLA_HEALTH_CHECKPOINT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_HEALTH_EXECUTION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_HEALTH_REPORT_SCHEMA_VERSION,
    DeployScyllaHealthArtifactState,
    DeployScyllaHealthCheckpointStore,
    DeployScyllaHealthEvidenceStore,
    DeployScyllaHealthExecutionState,
    DeployScyllaHealthExecutionStore,
    build_deploy_scylla_health_checkpoint,
    deploy_scylla_health_checkpoint_path,
    deploy_scylla_health_evidence_path,
    deploy_scylla_health_execution_path,
    execute_deploy_scylla_health_checkpoint,
)
from scylla_vms.ansible.scylla_health import HealthCheckStatus
from scylla_vms.errors import AnsibleError, StateConflictError, UnsafePathError
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.process import ProcessResult, ProcessSpec, ProcessTimeoutError
from scylla_vms.state import StatePaths

_DIGEST = "sha256:" + "a" * 64


@dataclass
class HealthCheckpointRunner:
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
        queried = cast(tuple[str, ...], tuple(payload["queried_nodes"]))
        assert queried == ("scylla-ad-1-1",)
        assert spec.argv[spec.argv.index("--limit") + 1] == queried[0]
        if self.inspect_started:
            assert self.paths is not None
            record = json.loads(
                deploy_scylla_health_execution_path(self.paths, OPERATION_ID).read_text(
                    encoding="utf-8"
                )
            )
            assert record["state"] == "started"
            assert record["invocation_count"] == 1
        if self.mode == "timeout":
            raise ProcessTimeoutError("obviously-fake-health-secret /private/health")
        if self.mode == "malformed":
            return ProcessResult(0, "malformed", "obviously-fake-health-secret")
        if self.mode == "drift-after-start":
            assert self.paths is not None
            with self.paths.ansible_inventory.open("a", encoding="utf-8") as stream:
                stream.write(" ")
        view = _view(queried[0], _HOST_ID, _ring())
        expected = cast(
            dict[str, object],
            cast(list[object], payload["expected_hosts"])[0],
        )
        view["datacenter"] = expected["datacenter"]
        view["rack"] = expected["rack"]
        view["ring"] = [
            {
                "datacenter": expected["datacenter"],
                "host_id": _HOST_ID,
                "rack": expected["rack"],
                "state": "UN",
            }
        ]
        if self.mode == "version-conflict":
            view["version"] = "2026.2.wrong"
        elif self.mode == "down":
            cast(list[dict[str, object]], view["ring"])[0]["state"] = "DN"
        stdout, exit_code = _stdout([view], queried)
        return ProcessResult(exit_code, stdout, "")


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, executables, toolchain = _prepared_bootstrap(tmp_path, monkeypatch)
    _execute_bootstrap(
        prepared,
        BootstrapRunner(),
        executables,
        toolchain,
    )
    return prepared, executables, toolchain


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_scylla_health_checkpoint(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )


def test_health_checkpoint_executes_exact_active_prefix_and_persists_strict_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = HealthCheckpointRunner(inspect_started=True, paths=prepared.paths)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()
    show_before = _run_show(prepared.paths)

    report = _call(prepared, runner, executables, toolchain)

    assert report.schema_version == (ANSIBLE_DEPLOY_SCYLLA_HEALTH_REPORT_SCHEMA_VERSION)
    assert report.execution_state is DeployScyllaHealthExecutionState.SUCCEEDED
    assert report.execution_artifact_state is DeployScyllaHealthArtifactState.CREATED
    assert report.evidence_artifact_state is DeployScyllaHealthArtifactState.CREATED
    assert report.checkpoint_artifact_state is DeployScyllaHealthArtifactState.CREATED
    assert report.active_member_count == 1
    assert report.future_member_count == 0
    assert report.health_complete
    assert report.next_join_status == "not-required"
    assert len(runner.payloads or []) == 1
    assert journal_path.read_bytes() == journal_before
    assert _run_show(prepared.paths) == show_before

    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        execution = DeployScyllaHealthExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence = DeployScyllaHealthEvidenceStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        checkpoint = DeployScyllaHealthCheckpointStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    assert execution.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_HEALTH_EXECUTION_SCHEMA_VERSION
    )
    assert execution.record.state is DeployScyllaHealthExecutionState.SUCCEEDED
    assert evidence.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_HEALTH_EVIDENCE_SCHEMA_VERSION
    )
    assert evidence.record.strict_complete
    assert tuple(node.stable_id for node in evidence.record.nodes) == ("scylla-ad-1-1",)
    assert evidence.record.binding.active_member_count == 1
    assert evidence.record.binding.future_member_count == 0
    assert evidence.record.nodes[0].host_id_digest.startswith("sha256:")
    assert evidence.record.nodes[0].version_digest.startswith("sha256:")
    assert {name: status.value for name, status in evidence.record.policy_states} == {
        "backup-policy": "not-performed",
        "capacity": "unknown",
        "quorum": "unknown",
        "replication": "not-performed",
    }
    assert checkpoint.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_HEALTH_CHECKPOINT_SCHEMA_VERSION
    )
    assert (
        checkpoint.record.steps[0].health_checkpoint_state
        == "complete-current-cluster-health"
    )
    assert checkpoint.record.steps[0].status.value == "health-succeeded"
    assert checkpoint.record.next_join_status == "not-required"
    artifacts = (
        deploy_scylla_health_execution_path(prepared.paths, OPERATION_ID),
        deploy_scylla_health_evidence_path(prepared.paths, OPERATION_ID),
        deploy_scylla_health_checkpoint_path(prepared.paths, OPERATION_ID),
    )
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in artifacts)
    persisted_text = "".join(path.read_text(encoding="utf-8") for path in artifacts)
    assert "10.0." not in persisted_text
    assert "obviously-fake-health-secret" not in persisted_text
    assert "/private/health" not in persisted_text


@pytest.mark.parametrize("mode", ["version-conflict", "down"])
def test_health_checkpoint_exit_zero_is_insufficient(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)

    with pytest.raises(AnsibleError):
        _call(
            prepared,
            HealthCheckpointRunner(mode=mode),
            executables,
            toolchain,
        )

    assert deploy_scylla_health_evidence_path(prepared.paths, OPERATION_ID).exists()
    assert not deploy_scylla_health_checkpoint_path(
        prepared.paths, OPERATION_ID
    ).exists()
    persisted = json.loads(
        deploy_scylla_health_execution_path(prepared.paths, OPERATION_ID).read_text(
            encoding="utf-8"
        )
    )
    assert persisted["state"] == "failed"
    assert persisted["manual_recovery_required"] is True


def test_health_checkpoint_started_timeout_is_never_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = HealthCheckpointRunner(mode="timeout")

    with pytest.raises(AnsibleError, match="manual recovery") as captured:
        _call(prepared, runner, executables, toolchain)
    assert "obviously-fake-health-secret" not in str(captured.value)
    assert "/private/health" not in str(captured.value)
    process_count = len(runner.specs or [])

    with pytest.raises(StateConflictError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    assert len(runner.specs or []) == process_count


def test_health_checkpoint_terminal_reentry_is_zero_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    _call(prepared, HealthCheckpointRunner(), executables, toolchain)
    runner = HealthCheckpointRunner()

    report = _call(prepared, runner, executables, toolchain)

    assert report.checkpoint_artifact_state is DeployScyllaHealthArtifactState.REUSED
    assert runner.specs == []


def test_health_checkpoint_post_invocation_drift_is_uncertain_and_no_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = HealthCheckpointRunner(
        mode="drift-after-start",
        paths=prepared.paths,
    )

    with pytest.raises(AnsibleError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    process_count = len(runner.specs or [])

    with pytest.raises((StateConflictError, AnsibleError)):
        _call(prepared, runner, executables, toolchain)
    assert len(runner.specs or []) == process_count


def test_health_checkpoint_refuses_unsafe_artifact_path_before_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    execution_path = deploy_scylla_health_execution_path(prepared.paths, OPERATION_ID)
    execution_path.symlink_to(tmp_path / "outside-health-execution.json")
    runner = HealthCheckpointRunner()

    with pytest.raises(UnsafePathError):
        _call(prepared, runner, executables, toolchain)

    assert runner.specs == []


def test_health_checkpoint_paths_are_operation_bound(tmp_path: Path) -> None:
    paths = StatePaths.derive(tmp_path / "state", "example")
    execution = deploy_scylla_health_execution_path(paths, OPERATION_ID)
    evidence = deploy_scylla_health_evidence_path(paths, OPERATION_ID)
    checkpoint = deploy_scylla_health_checkpoint_path(paths, OPERATION_ID)
    assert execution.parent == evidence.parent == checkpoint.parent == paths.operations
    assert execution.name.endswith(".ansible-deploy-scylla-health-execution.json")
    assert evidence.name.endswith(".ansible-deploy-scylla-health-evidence.json")
    assert checkpoint.name.endswith(".ansible-deploy-scylla-health-checkpoint.json")


@pytest.mark.parametrize(
    ("policies_passed", "expected_status"),
    [
        (True, "authorization-required"),
        (False, "blocked"),
    ],
)
def test_health_checkpoint_advances_only_first_join_when_all_gates_pass(
    policies_passed: bool, expected_status: str
) -> None:
    context = SimpleNamespace(
        artifact_digest=_DIGEST,
        record=SimpleNamespace(
            operation_id=OPERATION_ID,
            record_digest=_DIGEST,
        ),
    )
    steps = tuple(
        SimpleNamespace(
            sequence=sequence,
            mode=(
                ScyllaBootstrapMode.INITIAL_SEED
                if sequence == 1
                else ScyllaBootstrapMode.JOIN_EXISTING
            ),
            target_digest="sha256:" + str(sequence) * 64,
            step_digest="sha256:" + chr(96 + sequence) * 64,
        )
        for sequence in range(1, 4)
    )
    plan = SimpleNamespace(
        artifact_digest=_DIGEST,
        record=SimpleNamespace(
            operation_id=OPERATION_ID,
            context_record_digest=_DIGEST,
            context_artifact_digest=_DIGEST,
            cluster_uuid=CLUSTER_UUID,
            cluster_name="example",
            request_digest=_DIGEST,
            journal_generation=4,
            journal_digest=_DIGEST,
            journal_status=JournalStatus.IN_PROGRESS,
            journal_phase=OperationPhase.VERIFY,
            plan_digest=_DIGEST,
            steps=steps,
        ),
    )
    policy_state = (
        HealthCheckStatus.PASSED if policies_passed else HealthCheckStatus.UNKNOWN
    )
    evidence = SimpleNamespace(
        strict_complete=True,
        evidence_digest=_DIGEST,
        policy_states=tuple(
            (name, policy_state)
            for name in ("backup-policy", "capacity", "quorum", "replication")
        ),
        join_gate_states=tuple(
            (
                name,
                (
                    HealthCheckStatus.PASSED
                    if policies_passed
                    or name
                    in {
                        "target-absence",
                        "survivor-health",
                        "seed-health",
                        "topology",
                        "schema",
                    }
                    else HealthCheckStatus.UNKNOWN
                ),
            )
            for name in (
                "target-absence",
                "survivor-health",
                "seed-health",
                "topology",
                "schema",
                "capacity",
                "replication",
                "quorum",
                "backup-policy",
            )
        ),
        binding=SimpleNamespace(
            active_member_count=1,
            active_member_set_digest=_DIGEST,
            desired_member_count=3,
            desired_member_set_digest=_DIGEST,
            future_member_count=2,
            future_member_set_digest=_DIGEST,
        ),
    )

    checkpoint = build_deploy_scylla_health_checkpoint(
        context=context,
        plan=plan,
        execution_artifact_digest=_DIGEST,
        evidence_artifact_digest=_DIGEST,
        evidence=evidence,
        created_at="2026-09-21T01:00:00Z",
    )

    assert checkpoint.steps[0].status.value == "health-succeeded"
    assert checkpoint.steps[1].status.value == expected_status
    assert checkpoint.steps[2].status.value == "waiting-for-preceding-complete-health"
    assert checkpoint.next_join_sequence == 2
    assert checkpoint.next_join_status == expected_status
