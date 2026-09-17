import base64
import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

import pytest
import test_ansible_deploy_manager_server_authorization as manager_authorization_fixture
import test_ansible_deploy_manager_server_execution as manager_execution_fixture
import test_ansible_deploy_manager_server_reconciliation as manager_reconciliation_fixture
import test_ansible_deploy_monitoring_stack_authorization as monitoring_authorization_fixture
import test_ansible_deploy_monitoring_stack_execution as monitoring_execution_fixture
import test_ansible_deploy_monitoring_stack_reconciliation as monitoring_fixture
import test_ansible_deploy_scylla_post_bootstrap_reconciliation as bootstrap_fixture
from test_ansible_deploy_manager_agent_authorization import (
    _call as _authorize,
)
from test_ansible_deploy_manager_agent_authorization import _proof
from test_ansible_deploy_monitoring_stack_execution import MonitoringStackRunner
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_manager_agent_execution as execution_module
from scylla_vms.ansible.deploy_manager_agent_execution import (
    ANSIBLE_DEPLOY_MANAGER_AGENT_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_AGENT_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_AGENT_EXECUTION_SCHEMA_VERSION,
    DeployManagerAgentEvidenceStore,
    DeployManagerAgentExecution,
    DeployManagerAgentExecutionState,
    DeployManagerAgentExecutionStore,
    deploy_manager_agent_evidence_path,
    deploy_manager_agent_execution_path,
    execute_deploy_manager_agent,
)
from scylla_vms.ansible.manager_agent import (
    MANAGER_AGENT_SCHEMA_VERSION,
    MANAGER_PACKAGE_VERSION,
    MANAGER_PACKAGES,
    MANAGER_REPOSITORY_URI,
)
from scylla_vms.ansible.registry import LimitPolicy, get_playbook
from scylla_vms.errors import AnsibleError, StateConflictError, StatePersistenceError
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.process import ProcessResult, ProcessSpec, ProcessTimeoutError

_PRIVATE_PATH = "/private/operator/manager-agent-runtime.json"
_SECRET = "obviously-fake-manager-agent-execution-secret"


@dataclass
class ManagerAgentRunner:
    mode: str = "no-change"
    inspect_started: Callable[[], None] | None = None
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
        if playbook != "manager-agent":
            raise AssertionError(f"unexpected playbook or external tool: {playbook}")
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        variables = cast(
            dict[str, object], json.loads(runtime_file.read_text(encoding="utf-8"))
        )
        payload = cast(dict[str, object], variables["deploy_scylla_vms_manager_agent"])
        self.payloads.append(payload)
        if self.inspect_started is not None:
            self.inspect_started()
        if self.mode == "timeout":
            raise ProcessTimeoutError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "malformed":
            return ProcessResult(0, "malformed", f"{_SECRET} {_PRIVATE_PATH}")

        failed = self.mode in {"failed", "unreachable"}
        status = "failed" if failed else self.mode
        if status not in {"installed", "no-change", "failed"}:
            status = "no-change"
        success = status in {"installed", "no-change"}
        result = {
            "auth_token_configured": self.mode == "prohibited-action",
            "blockers": ["execution-failed"] if failed else [],
            "configuration_performed": False,
            "helper_slice_configured": False,
            "installed_version": payload["package_version"] if success else None,
            "logical_id": payload["logical_id"],
            "packages": (
                {name: payload["package_version"] for name in MANAGER_PACKAGES}
                if success
                else {}
            ),
            "provenance": payload["provenance"],
            "repository_digest": cast(dict[str, object], payload["repository"])[
                "definition_digest"
            ],
            "requested_release": payload["release_line"],
            "requested_version": payload["package_version"],
            "schema_version": MANAGER_AGENT_SCHEMA_VERSION,
            "server_reachability": "not-performed",
            "service_enabled": False if success else None,
            "service_inactive": True if success else None,
            "signing_key_digest": cast(dict[str, object], payload["signing_key"])[
                "artifact_digest"
            ],
            "signing_key_fingerprint": cast(dict[str, object], payload["signing_key"])[
                "fingerprint"
            ],
            "status": status,
        }
        encoded = base64.b64encode(
            json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        logical_id = cast(str, payload["logical_id"])
        unreachable = int(self.mode == "unreachable")
        failed_count = int(self.mode == "failed")
        changed = int(status == "installed")
        stdout = (
            f'ok: [{logical_id}] => {{"msg":"DSV_MANAGER_AGENT_B64={encoded}"}}\n'
            "PLAY RECAP *****\n"
            f"{logical_id} : ok=12 changed={changed} unreachable={unreachable} "
            f"failed={failed_count} skipped=0 rescued=0 ignored=0\n"
        )
        exit_code = 4 if unreachable else 2 if failed_count else 0
        return ProcessResult(exit_code, stdout, f"{_SECRET} {_PRIVATE_PATH}")


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, executables, toolchain = monitoring_fixture._prepared(
        tmp_path, monkeypatch
    )
    monitoring_fixture._execute_monitoring(
        prepared,
        MonitoringStackRunner(),
        executables,
        toolchain,
    )
    monitoring_fixture._call(prepared)
    _authorize(prepared, _proof())
    return prepared, executables, toolchain


def _prepared_multi(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        bootstrap_fixture.test_provider_source,
        "_spec",
        bootstrap_fixture._two_node_spec,
    )
    monkeypatch.setattr(
        bootstrap_fixture.test_terraform_plan_checkpoint,
        "_spec",
        bootstrap_fixture._two_node_spec,
    )
    monkeypatch.setattr(
        bootstrap_fixture.test_terraform_apply_inventory,
        "_valid_output",
        bootstrap_fixture.join_safety_fixture._multi_output,
    )
    prepared, executables, toolchain = bootstrap_fixture.health_fixture._prepared(
        tmp_path, monkeypatch
    )
    bootstrap_fixture.health_fixture._call(
        prepared,
        bootstrap_fixture.health_fixture.HealthCheckpointRunner(),
        executables,
        toolchain,
    )
    bootstrap_fixture.join_safety_fixture._call(
        prepared,
        bootstrap_fixture.DeployScyllaJoinSafetyProofStatus.PASSED,
    )
    bootstrap_fixture.join_authorization_fixture._call(
        prepared,
        bootstrap_fixture.join_authorization_fixture._proof(prepared),
    )
    bootstrap_fixture.join_execution_fixture._call(
        prepared,
        bootstrap_fixture.join_execution_fixture.FirstJoinRunner(),
        executables,
        toolchain,
    )
    bootstrap_fixture.post_join_health_fixture._call(
        prepared,
        bootstrap_fixture.post_join_health_fixture.PostJoinHealthRunner(),
        executables,
        toolchain,
    )
    bootstrap_fixture._call(prepared)
    manager_authorization_fixture._call(
        prepared, manager_authorization_fixture._proof()
    )
    manager_execution_fixture._call(
        prepared,
        manager_execution_fixture.ManagerServerRunner(),
        executables,
        toolchain,
    )
    manager_reconciliation_fixture._call(prepared)
    monitoring_authorization_fixture._call(
        prepared, monitoring_authorization_fixture._proof()
    )
    monitoring_execution_fixture._call(
        prepared,
        MonitoringStackRunner(),
        executables,
        toolchain,
    )
    monitoring_fixture._call(prepared)
    _authorize(prepared, _proof())
    return prepared, executables, toolchain


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_manager_agent(
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
        execution = DeployManagerAgentExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployManagerAgentEvidenceStore(prepared.paths, OPERATION_ID)
        evidence = (
            evidence_store.read_locked(
                lock,
                expected_cluster_uuid=CLUSTER_UUID,
                expected_cluster_name="example",
            )
            if evidence_store.path.exists()
            else None
        )
    return execution, evidence


def test_prepared_resume_order_policy_redaction_and_zero_process_reentry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signature = inspect.signature(execute_deploy_manager_agent)
    assert tuple(signature.parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "runner",
        "executables",
        "toolchain",
    )
    for forbidden in (
        "step",
        "target",
        "limit",
        "version",
        "package",
        "repository",
        "key",
        "token",
        "config",
        "server",
        "command",
        "variable",
        "path",
        "result",
        "retry",
    ):
        assert forbidden not in signature.parameters

    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    immutable_paths = (
        prepared.paths.operations / f"{OPERATION_ID}.json",
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-manager-agent-authorization.json",
        prepared.paths.operations
        / f"{OPERATION_ID}.ansible-deploy-post-monitoring-stack-reconciliation.json",
    )
    immutable = {path: path.read_bytes() for path in immutable_paths}
    original_write = DeployManagerAgentExecutionStore.write_locked
    refused = False

    def refuse_first_start(self, record, **kwargs):
        nonlocal refused
        if record.state is DeployManagerAgentExecutionState.STARTED and not refused:
            refused = True
            raise StatePersistenceError("simulated safe pre-invocation refusal")
        return original_write(self, record, **kwargs)

    monkeypatch.setattr(
        DeployManagerAgentExecutionStore, "write_locked", refuse_first_start
    )
    first_runner = ManagerAgentRunner()
    with pytest.raises(StatePersistenceError, match="before invocation"):
        _call(prepared, first_runner, executables, toolchain)
    prepared_execution, evidence = _records(prepared)
    assert prepared_execution.record.state is DeployManagerAgentExecutionState.PREPARED
    assert prepared_execution.record.invocation_count == 0
    assert not prepared_execution.record.authorization_consumed
    assert evidence is None
    assert first_runner.specs is not None and len(first_runner.specs) == 2

    monkeypatch.setattr(
        DeployManagerAgentExecutionStore, "write_locked", original_write
    )
    observed: list[DeployManagerAgentExecutionState] = []

    def inspect_started() -> None:
        value = json.loads(
            deploy_manager_agent_execution_path(prepared.paths, OPERATION_ID).read_text(
                encoding="utf-8"
            )
        )
        record = DeployManagerAgentExecution.from_object(value)
        observed.append(record.state)
        assert record.authorization_consumed
        assert record.attempts[-1].state is DeployManagerAgentExecutionState.STARTED
        assert record.attempts[-1].authorization_consumed_at_start == (
            len(record.attempts) == 1
        )

    runner = ManagerAgentRunner(mode="installed", inspect_started=inspect_started)
    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert evidence is not None
    assert report.schema_version == (
        ANSIBLE_DEPLOY_MANAGER_AGENT_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert report.execution_schema_version == (
        ANSIBLE_DEPLOY_MANAGER_AGENT_EXECUTION_SCHEMA_VERSION
    )
    assert report.evidence_schema_version == (
        ANSIBLE_DEPLOY_MANAGER_AGENT_EVIDENCE_SCHEMA_VERSION
    )
    assert report.execution_state is DeployManagerAgentExecutionState.SUCCEEDED
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert not report.journal_updated
    assert report.authorization_consumed
    assert report.invocation_count == report.scope_count == report.stable_id_count
    assert report.scope_count >= 1
    assert report.installed_count == report.scope_count
    assert report.changed_count == report.scope_count
    assert report.service_safe_count == report.scope_count
    assert report.prohibited_action_count == 0
    assert observed == [DeployManagerAgentExecutionState.STARTED] * report.scope_count
    assert runner.payloads is not None
    ordered_ids = [cast(str, payload["logical_id"]) for payload in runner.payloads]
    assert ordered_ids == sorted(ordered_ids)
    assert tuple(attempt.stable_id for attempt in execution.record.attempts) == tuple(
        ordered_ids
    )
    assert [
        attempt.authorization_consumed_at_start for attempt in execution.record.attempts
    ] == [
        True,
        *([False] * (report.scope_count - 1)),
    ]
    assert all(entry.service_disabled for entry in evidence.record.entries)
    assert all(entry.service_inactive for entry in evidence.record.entries)
    assert all(
        entry.server_reachability == "not-performed"
        for entry in evidence.record.entries
    )
    assert {path: path.read_bytes() for path in immutable_paths} == immutable

    serialized = (
        deploy_manager_agent_execution_path(prepared.paths, OPERATION_ID).read_text()
        + deploy_manager_agent_evidence_path(prepared.paths, OPERATION_ID).read_text()
        + json.dumps(report.to_object(), sort_keys=True)
    )
    for protected in (
        _SECRET,
        _PRIVATE_PATH,
        MANAGER_PACKAGE_VERSION,
        MANAGER_REPOSITORY_URI,
        "obviously-fake-agent-token",
        "obviously-fake-manager-server-value",
    ):
        assert protected not in serialized
    assert (
        deploy_manager_agent_execution_path(prepared.paths, OPERATION_ID).stat().st_mode
        & 0o777
        == 0o600
    )
    assert (
        deploy_manager_agent_evidence_path(prepared.paths, OPERATION_ID).stat().st_mode
        & 0o777
        == 0o600
    )

    execution_bytes = deploy_manager_agent_execution_path(
        prepared.paths, OPERATION_ID
    ).read_bytes()
    evidence_bytes = deploy_manager_agent_evidence_path(
        prepared.paths, OPERATION_ID
    ).read_bytes()
    reentry_runner = ManagerAgentRunner()
    reused = _call(prepared, reentry_runner, executables, toolchain)
    assert reused.execution_state is DeployManagerAgentExecutionState.SUCCEEDED
    assert reentry_runner.specs == []
    assert (
        deploy_manager_agent_execution_path(prepared.paths, OPERATION_ID).read_bytes()
        == execution_bytes
    )
    assert (
        deploy_manager_agent_evidence_path(prepared.paths, OPERATION_ID).read_bytes()
        == evidence_bytes
    )
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0
    evidence_path = deploy_manager_agent_evidence_path(prepared.paths, OPERATION_ID)
    evidence_document = cast(
        dict[str, object], json.loads(evidence_bytes.decode("utf-8"))
    )
    entries = cast(list[dict[str, object]], evidence_document["entries"])
    entries[0]["service_disabled"] = False
    evidence_path.write_text(json.dumps(evidence_document) + "\n", encoding="utf-8")
    evidence_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
    evidence_path.write_bytes(evidence_bytes)
    evidence_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


def test_complete_multi_target_scope_executes_in_immutable_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = _prepared_multi(tmp_path, monkeypatch)
    runner = ManagerAgentRunner()
    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert evidence is not None
    assert report.scope_count == report.stable_id_count == 2
    assert report.invocation_count == 2
    assert runner.payloads is not None
    ordered_ids = tuple(cast(str, payload["logical_id"]) for payload in runner.payloads)
    assert ordered_ids == tuple(sorted(ordered_ids))
    assert (
        tuple(attempt.stable_id for attempt in execution.record.attempts) == ordered_ids
    )
    assert tuple(entry.stable_id for entry in evidence.record.entries) == ordered_ids
    assert tuple(
        attempt.authorization_consumed_at_start for attempt in execution.record.attempts
    ) == (True, False)
    assert execution.record.authorization_consumed
    assert execution.record.all_scopes_completed


@pytest.mark.parametrize(
    ("mode", "state"),
    (
        ("timeout", DeployManagerAgentExecutionState.TIMED_OUT),
        ("malformed", DeployManagerAgentExecutionState.MALFORMED_RESULT),
        ("failed", DeployManagerAgentExecutionState.FAILED),
        ("unreachable", DeployManagerAgentExecutionState.UNREACHABLE),
        ("prohibited-action", DeployManagerAgentExecutionState.MALFORMED_RESULT),
    ),
)
def test_started_failure_is_permanent_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    state: DeployManagerAgentExecutionState,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    with pytest.raises(AnsibleError, match="manual recovery required"):
        _call(prepared, ManagerAgentRunner(mode=mode), executables, toolchain)
    execution, _evidence = _records(prepared)
    assert execution.record.state is state
    assert execution.record.manual_recovery_required
    assert execution.record.authorization_consumed
    assert not execution.record.attempts[-1].automatic_retry_allowed

    retry = ManagerAgentRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, retry, executables, toolchain)
    assert retry.specs == []


def test_evidence_failure_and_post_call_drift_are_durable_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    prepared, executables, toolchain = _prepared(evidence_root, monkeypatch)

    def refuse_evidence(*_args, **_kwargs):
        raise StatePersistenceError("simulated evidence failure")

    monkeypatch.setattr(
        DeployManagerAgentEvidenceStore, "append_locked", refuse_evidence
    )
    with pytest.raises(StatePersistenceError, match="evidence persistence failed"):
        _call(prepared, ManagerAgentRunner(), executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployManagerAgentExecutionState.STARTED
    assert execution.record.manual_recovery_required
    assert evidence is None
    retry = ManagerAgentRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, retry, executables, toolchain)
    assert retry.specs == []

    monkeypatch.undo()
    drift_root = tmp_path / "drift"
    drift_root.mkdir()
    prepared, executables, toolchain = _prepared(drift_root, monkeypatch)
    inventory_path = prepared.paths.ansible_inventory
    original_inventory = inventory_path.read_bytes()

    def drift_after_start() -> None:
        inventory_path.write_bytes(original_inventory + b" ")
        inventory_path.chmod(0o600)

    with pytest.raises(StateConflictError, match="manual recovery required"):
        _call(
            prepared,
            ManagerAgentRunner(inspect_started=drift_after_start),
            executables,
            toolchain,
        )
    inventory_path.write_bytes(original_inventory)
    inventory_path.chmod(0o600)
    execution, _evidence = _records(prepared)
    assert execution.record.state is DeployManagerAgentExecutionState.DRIFTED
    assert execution.record.manual_recovery_required


def test_refuses_tamper_source_drift_later_history_and_catalog_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    authorization_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-manager-agent-authorization.json"
    )
    authorization_bytes = authorization_path.read_bytes()
    authorization = cast(
        dict[str, object], json.loads(authorization_bytes.decode("utf-8"))
    )
    authorization["target_count"] = cast(int, authorization["target_count"]) + 1
    authorization_path.write_text(json.dumps(authorization) + "\n", encoding="utf-8")
    authorization_path.chmod(0o600)
    runner = ManagerAgentRunner()
    with pytest.raises(StatePersistenceError):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
    authorization_path.write_bytes(authorization_bytes)
    authorization_path.chmod(0o600)

    original_source_digest = execution_module._playbook_source_digest
    monkeypatch.setattr(
        execution_module,
        "_playbook_source_digest",
        lambda *_args: "sha256:" + "a" * 64,
    )
    with pytest.raises(StateConflictError):
        _call(prepared, ManagerAgentRunner(), executables, toolchain)
    monkeypatch.setattr(
        execution_module,
        "_playbook_source_digest",
        original_source_digest,
    )

    later = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-monitoring-agent-authorization.json"
    )
    later.write_text("{}\n", encoding="utf-8")
    later.chmod(0o600)
    with pytest.raises(StateConflictError, match="later-stage history"):
        _call(prepared, ManagerAgentRunner(), executables, toolchain)
    later.unlink()

    original_get = execution_module.get_playbook
    monkeypatch.setattr(
        execution_module,
        "get_playbook",
        lambda name: replace(
            original_get(name),
            limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        ),
    )
    with pytest.raises(StateConflictError, match="catalog policy"):
        _call(prepared, ManagerAgentRunner(), executables, toolchain)
    assert get_playbook("manager-agent").limit_policy is LimitPolicy.EXPLICIT
