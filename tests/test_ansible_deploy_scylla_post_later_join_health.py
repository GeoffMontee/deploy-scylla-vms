import inspect
import json
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
import test_ansible_deploy_scylla_later_join_execution as later_join_fixture
import test_ansible_deploy_scylla_later_join_safety as safety_fixture
from test_ansible_deploy_scylla_bootstrap_execution import (
    _HOST_ID as INITIAL_HOST_ID,
)
from test_ansible_deploy_scylla_join_execution import _HOST_ID as JOIN_HOST_ID
from test_ansible_deploy_scylla_sequence_three_join_execution import (
    _HOST_ID as SEQUENCE_THREE_HOST_ID,
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
from scylla_vms.ansible.deploy_scylla_later_join_authorization import (
    authorize_deploy_scylla_later_join,
)
from scylla_vms.ansible.deploy_scylla_later_join_safety import (
    bind_deploy_scylla_later_join_safety,
    deploy_scylla_later_join_safety_context_path,
)
from scylla_vms.ansible.deploy_scylla_post_later_join_health import (
    DeployScyllaPostLaterJoinHealthExecution,
    deploy_scylla_post_later_join_health_evidence_id_from_filename,
    deploy_scylla_post_later_join_health_evidence_path,
    deploy_scylla_post_later_join_health_execution_id_from_filename,
    deploy_scylla_post_later_join_health_execution_path,
    deploy_scylla_post_later_join_health_reconciliation_id_from_filename,
    deploy_scylla_post_later_join_health_reconciliation_path,
    execute_deploy_scylla_post_later_join_health,
    load_completed_later_join_health,
)
from scylla_vms.ansible.scylla_health import SCYLLA_HEALTH_VIEW_SCHEMA_VERSION
from scylla_vms.ansible.scylla_install import SCYLLA_PACKAGE_VERSION
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.process import ProcessResult, ProcessSpec, ProcessTimeoutError
from scylla_vms.state import StatePaths

_PRIVATE_PATH = "/private/operator/post-later-join-health.json"
_SECRET = "obviously-fake-post-later-join-health-secret"
_COMMANDS = [
    ["/usr/bin/nodetool", "info"],
    ["/usr/bin/nodetool", "status"],
    ["/usr/bin/nodetool", "describecluster"],
    ["/usr/bin/nodetool", "netstats"],
    ["/usr/bin/nodetool", "version"],
    ["/usr/bin/systemctl", "is-active", "scylla-server.service"],
]


@dataclass
class PostLaterJoinHealthRunner:
    mode: str = "success"
    inspect_started: bool = False
    paths: StatePaths | None = None
    specs: list[ProcessSpec] | None = None

    def __post_init__(self) -> None:
        self.specs = []

    def run(self, spec: ProcessSpec) -> ProcessResult:
        assert self.specs is not None
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
        queried = tuple(cast(list[str], payload["queried_nodes"]))
        assert queried == (
            "scylla-ad-1-1",
            "scylla-ad-1-2",
            "scylla-ad-1-3",
            "scylla-ad-1-4",
        )
        assert spec.argv[spec.argv.index("--limit") + 1] == ",".join(queried)
        if self.inspect_started:
            assert self.paths is not None
            record = DeployScyllaPostLaterJoinHealthExecution.from_object(
                cast(
                    dict[str, object],
                    json.loads(
                        deploy_scylla_post_later_join_health_execution_path(
                            self.paths, OPERATION_ID, 4
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
            queried[3]: later_join_fixture._HOST_ID,
        }
        ring = sorted(
            (
                {
                    "datacenter": expected_hosts[stable_id]["datacenter"],
                    "host_id": host_ids[stable_id],
                    "rack": expected_hosts[stable_id]["rack"],
                    "state": (
                        "DN"
                        if self.mode == "down" and stable_id == queried[-1]
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
                "captured_at": "2026-09-22T16:00:00Z",
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
    prepared, executables, toolchain = later_join_fixture._prepared(
        tmp_path, monkeypatch
    )
    later_join_fixture._call(
        prepared,
        later_join_fixture.LaterJoinRunner(),
        executables,
        toolchain,
    )
    return prepared, executables, toolchain


def _prepared_four_node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[_Prepared, object, object]:
    prepared, executables, toolchain = safety_fixture._prepared(
        tmp_path,
        monkeypatch,
        spec=lambda path: safety_fixture._node_spec(path, 4),
    )
    safety_fixture._call(prepared)
    later_join_fixture._authorize_later_join(
        prepared,
        later_join_fixture._later_join_authorization_proof(prepared),
    )
    later_join_fixture._call(
        prepared,
        later_join_fixture.LaterJoinRunner(),
        executables,
        toolchain,
    )
    return prepared, executables, toolchain


def _call(
    prepared: _Prepared,
    runner: PostLaterJoinHealthRunner,
    executables: object,
    toolchain: object,
):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_scylla_post_later_join_health(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )


def _artifacts(prepared: _Prepared, sequence: int = 4) -> tuple[Path, Path, Path]:
    return (
        deploy_scylla_post_later_join_health_execution_path(
            prepared.paths, OPERATION_ID, sequence
        ),
        deploy_scylla_post_later_join_health_evidence_path(
            prepared.paths, OPERATION_ID, sequence
        ),
        deploy_scylla_post_later_join_health_reconciliation_path(
            prepared.paths, OPERATION_ID, sequence
        ),
    )


def test_post_later_join_health_succeeds_reuses_and_enables_only_next_safety(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert tuple(
        inspect.signature(execute_deploy_scylla_post_later_join_health).parameters
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
    runner = PostLaterJoinHealthRunner(inspect_started=True, paths=prepared.paths)
    journal = (prepared.paths.operations / f"{OPERATION_ID}.json").read_bytes()
    report = _call(prepared, runner, executables, toolchain)
    assert report.completed_sequence == report.current_member_count == 4
    assert report.next_join_sequence == 5
    assert report.next_join_status == "waiting-for-separate-safety-context"
    assert report.next_step_required
    assert not report.bootstrap_sequence_complete
    assert report.policy_unknown_count == report.policy_not_performed_count == 2
    assert report.execution_state is DeployScyllaHealthExecutionState.SUCCEEDED
    assert len(runner.specs or []) == 3
    paths = _artifacts(prepared)
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in paths)
    assert deploy_scylla_post_later_join_health_execution_id_from_filename(
        paths[0].name
    ) == (OPERATION_ID, 4)
    assert deploy_scylla_post_later_join_health_evidence_id_from_filename(
        paths[1].name
    ) == (OPERATION_ID, 4)
    assert deploy_scylla_post_later_join_health_reconciliation_id_from_filename(
        paths[2].name
    ) == (OPERATION_ID, 4)
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
        '"output"',
        '"path"',
    ):
        assert protected not in persisted
    before = tuple(path.read_bytes() for path in paths)
    reused_runner = PostLaterJoinHealthRunner()
    reused = _call(prepared, reused_runner, executables, toolchain)
    assert reused.execution_artifact_state is DeployScyllaHealthArtifactState.REUSED
    assert reused.evidence_artifact_state is DeployScyllaHealthArtifactState.REUSED
    assert (
        reused.reconciliation_artifact_state is DeployScyllaHealthArtifactState.REUSED
    )
    assert reused_runner.specs == []
    assert tuple(path.read_bytes() for path in paths) == before
    assert (prepared.paths.operations / f"{OPERATION_ID}.json").read_bytes() == journal

    safety = safety_fixture._call(prepared)
    assert safety.target_sequence == 5
    assert deploy_scylla_later_join_safety_context_path(
        prepared.paths, OPERATION_ID, 4
    ).exists()
    assert deploy_scylla_later_join_safety_context_path(
        prepared.paths, OPERATION_ID, 5
    ).exists()
    assert tuple(path.read_bytes() for path in paths) == before
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


def test_post_later_join_health_reports_bootstrap_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared_four_node(tmp_path, monkeypatch)
    report = _call(
        prepared,
        PostLaterJoinHealthRunner(),
        executables,
        toolchain,
    )
    assert report.next_join_sequence is None
    assert report.next_join_status == "not-required"
    assert report.bootstrap_sequence_complete
    assert not report.next_step_required
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        safety = bind_deploy_scylla_later_join_safety(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proofs=(),
        )
        authorization = authorize_deploy_scylla_later_join(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            proof=None,
        )
    assert safety.state == authorization.state == "not-required"
    assert not authorization.required


@pytest.mark.parametrize("mode", ["down", "incomplete-membership", "malformed"])
def test_post_later_join_health_refuses_incomplete_results_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = PostLaterJoinHealthRunner(mode=mode)
    with pytest.raises(AnsibleError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    execution_path, _, reconciliation_path = _artifacts(prepared)
    record = DeployScyllaPostLaterJoinHealthExecution.from_object(
        cast(dict[str, object], json.loads(execution_path.read_text(encoding="utf-8")))
    )
    assert record.manual_recovery_required
    assert not record.automatic_retry_allowed
    assert not reconciliation_path.exists()
    retry = PostLaterJoinHealthRunner()
    with pytest.raises(StateConflictError, match="manual recovery"):
        _call(prepared, retry, executables, toolchain)
    assert retry.specs == []


@pytest.mark.parametrize("mode", ["timeout", "drift-after-start"])
def test_post_later_join_health_started_uncertainty_is_no_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    with pytest.raises(AnsibleError, match="manual recovery"):
        _call(
            prepared,
            PostLaterJoinHealthRunner(mode=mode, paths=prepared.paths),
            executables,
            toolchain,
        )
    retry = PostLaterJoinHealthRunner()
    with pytest.raises((StateConflictError, StatePersistenceError, AnsibleError)):
        _call(prepared, retry, executables, toolchain)
    assert retry.specs == []


def test_post_later_join_health_discovery_and_show_fail_closed_on_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    _call(prepared, PostLaterJoinHealthRunner(), executables, toolchain)
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        completed = load_completed_later_join_health(
            prepared.paths,
            OPERATION_ID,
            lock=lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    assert completed is not None and completed.sequence == 4
    path = _artifacts(prepared)[2]
    original = path.read_bytes()
    value = cast(dict[str, object], json.loads(original))
    value["completed_sequence"] = 5
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
    path.write_bytes(original)
    path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


def test_post_later_join_health_refuses_wrong_lock_before_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = PostLaterJoinHealthRunner()
    with (
        ClusterLock(prepared.paths, "show", 0) as lock,
        pytest.raises(StateLockError),
    ):
        execute_deploy_scylla_post_later_join_health(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )
    assert runner.specs == []
