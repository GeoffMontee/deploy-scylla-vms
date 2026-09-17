import base64
import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
import test_ansible_deploy_monitoring_agent_execution as agent_execution_fixture
import test_ansible_deploy_monitoring_agent_reconciliation as agent_reconciliation_fixture
from test_ansible_deploy_monitoring_targets_authorization import (
    _call as _authorize,
)
from test_ansible_deploy_monitoring_targets_authorization import _proof
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_monitoring_targets_execution as execution_module
from scylla_vms.ansible.deploy_monitoring_targets_execution import (
    ANSIBLE_DEPLOY_MONITORING_TARGETS_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_SCHEMA_VERSION,
    DeployMonitoringTargetsArtifactState,
    DeployMonitoringTargetsEvidenceStore,
    DeployMonitoringTargetsExecution,
    DeployMonitoringTargetsExecutionState,
    DeployMonitoringTargetsExecutionStore,
    deploy_monitoring_targets_evidence_path,
    deploy_monitoring_targets_execution_path,
    execute_deploy_monitoring_targets,
)
from scylla_vms.ansible.monitoring_stack import LISTEN_POLICY, STACK_VERSION
from scylla_vms.ansible.monitoring_targets import (
    INSTALL_ROOT,
    MONITORING_TARGETS_SCHEMA_VERSION,
    SCRAPE_READINESS,
    TARGET_FILES,
)
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.errors import AnsibleError, StateConflictError, StatePersistenceError
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.process import ProcessResult, ProcessSpec, ProcessTimeoutError

_PRIVATE_PATH = "/private/operator/monitoring-targets-runtime.json"
_SECRET = "obviously-fake-monitoring-targets-execution-secret"


@dataclass
class MonitoringTargetsRunner:
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
        if playbook != "monitoring-targets":
            raise AssertionError(f"unexpected playbook or external tool: {playbook}")
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        variables = cast(
            dict[str, object], json.loads(runtime_file.read_text(encoding="utf-8"))
        )
        payload = cast(
            dict[str, object],
            variables["deploy_scylla_vms_monitoring_targets"],
        )
        self.payloads.append(payload)
        if self.inspect_started is not None:
            self.inspect_started()
        if self.mode == "timeout":
            raise ProcessTimeoutError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "malformed":
            return ProcessResult(0, "malformed", f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode in {"failed", "unreachable"}:
            logical_id = cast(str, payload["logical_id"])
            exit_code = 4 if self.mode == "unreachable" else 2
            stdout = (
                "PLAY RECAP *****\n"
                f"{logical_id} : ok=1 changed=0 "
                f"unreachable={int(self.mode == 'unreachable')} "
                f"failed={int(self.mode == 'failed')} "
                "skipped=0 rescued=0 ignored=0\n"
            )
            return ProcessResult(exit_code, stdout, f"{_SECRET} {_PRIVATE_PATH}")
        status = "generated" if self.mode == "generated" else "no-change"
        changed = status == "generated"
        result = {
            "auth_configured": False,
            "blockers": [],
            "compose_generated": False,
            "containers_started": False,
            "documented_scrape_ports": payload["documented_scrape_ports"],
            "exporters_started": False,
            "files": payload["file_digests"],
            "identities": payload["identities"],
            "install_root": payload["install_root"],
            "listen_policy": payload["listen_policy"],
            "logical_id": payload["logical_id"],
            "manager_registration_performed": False,
            "provenance": payload["provenance"],
            "public_bind": self.mode == "prohibited-action",
            "schema_version": MONITORING_TARGETS_SCHEMA_VERSION,
            "scrape_performed": False,
            "scrape_readiness": payload["scrape_readiness"],
            "scylla_started": False,
            "secrets_written": False,
            "stack_started": False,
            "stack_version": payload["stack_version"],
            "status": status,
            "target_counts": payload["target_counts"],
        }
        encoded = base64.b64encode(
            json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        logical_id = cast(str, payload["logical_id"])
        stdout = (
            f'ok: [{logical_id}] => {{"msg":"DSV_MONITORING_TARGETS_B64={encoded}"}}\n'
            "PLAY RECAP *****\n"
            f"{logical_id} : ok=12 changed={int(changed)} unreachable=0 failed=0 "
            "skipped=0 rescued=0 ignored=0\n"
        )
        return ProcessResult(0, stdout, f"{_SECRET} {_PRIVATE_PATH}")


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, executables, toolchain = agent_execution_fixture._prepared(
        tmp_path, monkeypatch
    )
    agent_execution_fixture._call(
        prepared,
        agent_execution_fixture.MonitoringAgentRunner(),
        executables,
        toolchain,
    )
    agent_reconciliation_fixture._call(prepared)
    _authorize(prepared, _proof())
    return prepared, executables, toolchain


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_monitoring_targets(
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
        execution = DeployMonitoringTargetsExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployMonitoringTargetsEvidenceStore(
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
    return execution, evidence


def test_prepared_resume_success_policy_redaction_show_and_zero_call_reentry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signature = inspect.signature(execute_deploy_monitoring_targets)
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
        "archive",
        "component",
        "auth",
        "bind",
        "command",
        "variable",
        "path",
        "result",
        "retry",
    ):
        assert forbidden not in signature.parameters

    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    authorization_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-monitoring-targets-authorization.json"
    )
    post_agent_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-post-monitoring-agent-reconciliation.json"
    )
    immutable = (
        journal_path.read_bytes(),
        authorization_path.read_bytes(),
        post_agent_path.read_bytes(),
    )
    show_before = _run_show(prepared.paths, "--fail-on", "none")
    original_write = DeployMonitoringTargetsExecutionStore.write_locked
    refused = False

    def fail_started(self, record, **kwargs):
        nonlocal refused
        if (
            record.state is DeployMonitoringTargetsExecutionState.STARTED
            and not refused
        ):
            refused = True
            raise StatePersistenceError("simulated safe pre-invocation refusal")
        return original_write(self, record, **kwargs)

    monkeypatch.setattr(
        DeployMonitoringTargetsExecutionStore, "write_locked", fail_started
    )
    first = MonitoringTargetsRunner()
    with pytest.raises(StatePersistenceError, match="before invocation"):
        _call(prepared, first, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployMonitoringTargetsExecutionState.PREPARED
    assert not execution.record.authorization_consumed
    assert execution.record.invocation_count == 0
    assert evidence is None
    assert first.specs is not None and len(first.specs) == 2

    monkeypatch.setattr(
        DeployMonitoringTargetsExecutionStore, "write_locked", original_write
    )
    observed: list[DeployMonitoringTargetsExecutionState] = []

    def inspect_started() -> None:
        value = json.loads(
            deploy_monitoring_targets_execution_path(
                prepared.paths, OPERATION_ID
            ).read_text(encoding="utf-8")
        )
        record = DeployMonitoringTargetsExecution.from_object(value)
        observed.append(record.state)
        assert record.authorization_consumed
        assert record.invocation_count == 1

    runner = MonitoringTargetsRunner(mode="generated", inspect_started=inspect_started)
    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert evidence is not None
    assert observed == [DeployMonitoringTargetsExecutionState.STARTED]
    assert (
        execution.record.schema_version
        == ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_SCHEMA_VERSION
    )
    assert (
        evidence.record.schema_version
        == ANSIBLE_DEPLOY_MONITORING_TARGETS_EVIDENCE_SCHEMA_VERSION
    )
    assert (
        report.schema_version
        == ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert report.execution_state is DeployMonitoringTargetsExecutionState.SUCCEEDED
    assert (
        report.execution_artifact_state is DeployMonitoringTargetsArtifactState.UPDATED
    )
    assert (
        report.evidence_artifact_state is DeployMonitoringTargetsArtifactState.CREATED
    )
    assert report.authorization_consumed
    assert report.invocation_count == report.generated_count == 1
    assert report.changed_count == 1
    assert report.target_stable_id == "monitoring-1"
    assert report.file_count == len(TARGET_FILES) == 4
    assert report.manager_target_count == 1
    assert report.scylla_target_count > 0
    assert report.node_exporter_target_count == report.scylla_target_count
    assert report.manager_agent_target_count == report.scylla_target_count
    assert report.listen_policy == LISTEN_POLICY
    assert report.scrape_readiness == SCRAPE_READINESS
    assert report.prohibited_action_count == 0
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert not report.journal_updated
    assert not report.manual_recovery_required
    assert not report.automatic_retry_allowed
    assert not report.skip_allowed
    assert not report.continue_allowed
    assert not report.rollback_performed
    assert (
        journal_path.read_bytes(),
        authorization_path.read_bytes(),
        post_agent_path.read_bytes(),
    ) == immutable
    assert runner.specs is not None and len(runner.specs) == 3
    assert runner.payloads is not None and len(runner.payloads) == 1
    payload = runner.payloads[0]
    assert payload["stack_version"] == STACK_VERSION
    assert len(cast(list[object], payload["files"])) == len(TARGET_FILES)
    for field in (
        "auth_configured",
        "compose_generated",
        "containers_started",
        "exporters_started",
        "manager_registration_performed",
        "public_bind",
        "scrape_performed",
        "scylla_started",
        "secrets_written",
        "stack_started",
    ):
        assert payload[field] is False
    definition = get_playbook("monitoring-targets")
    assert definition.serial == 1
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.check_mode is CheckMode.PREVIEW
    assert "--check" not in runner.specs[-1].argv
    assert "--tags" not in runner.specs[-1].argv
    assert "monitoring-1" in runner.specs[-1].argv
    entry = evidence.record.entries[0]
    assert entry.stable_id == "monitoring-1"
    assert entry.generated and entry.changed
    assert entry.file_count == len(TARGET_FILES)
    assert entry.listen_policy == LISTEN_POLICY
    assert entry.scrape_readiness == SCRAPE_READINESS
    assert not any(
        (
            entry.scrape_performed,
            entry.exporters_started,
            entry.stack_started,
            entry.containers_started,
            entry.compose_generated,
            entry.auth_configured,
            entry.public_bind,
            entry.manager_registration_performed,
            entry.scylla_started,
            entry.secrets_written,
        )
    )
    assert _run_show(prepared.paths, "--fail-on", "none") == show_before

    for path in (
        deploy_monitoring_targets_execution_path(prepared.paths, OPERATION_ID),
        deploy_monitoring_targets_evidence_path(prepared.paths, OPERATION_ID),
    ):
        assert path.stat().st_mode & 0o777 == 0o600
    persisted = (
        deploy_monitoring_targets_execution_path(
            prepared.paths, OPERATION_ID
        ).read_text(encoding="utf-8")
        + deploy_monitoring_targets_evidence_path(
            prepared.paths, OPERATION_ID
        ).read_text(encoding="utf-8")
        + json.dumps(report.to_object(), sort_keys=True)
    )
    for protected in (
        _PRIVATE_PATH,
        _SECRET,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        INSTALL_ROOT,
        STACK_VERSION,
        "scylla_servers.yml",
        "node_exporter_servers.yml",
        "scylla_manager_agents.yml",
        "scylla_manager_servers.yml",
        '"labels"',
        '"ports"',
        '"5090"',
        '"9100"',
        '"9180"',
        "ansible-playbook",
        "--limit",
        '"variables"',
        '"commands"',
        "grafana_admin",
        "password",
        "PLAY RECAP",
        "DSV_MONITORING_TARGETS_B64",
    ):
        assert protected not in persisted

    zero_runner = MonitoringTargetsRunner(mode="timeout")
    reused = _call(prepared, zero_runner, executables, toolchain)
    assert zero_runner.specs == []
    assert (
        reused.execution_artifact_state is DeployMonitoringTargetsArtifactState.REUSED
    )
    assert reused.evidence_artifact_state is DeployMonitoringTargetsArtifactState.REUSED


@pytest.mark.parametrize(
    ("mode", "expected"),
    (
        ("timeout", DeployMonitoringTargetsExecutionState.TIMED_OUT),
        ("malformed", DeployMonitoringTargetsExecutionState.MALFORMED_RESULT),
        ("failed", DeployMonitoringTargetsExecutionState.FAILED),
        ("unreachable", DeployMonitoringTargetsExecutionState.UNREACHABLE),
        (
            "prohibited-action",
            DeployMonitoringTargetsExecutionState.MALFORMED_RESULT,
        ),
    ),
)
def test_started_uncertainty_is_permanent_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    expected: DeployMonitoringTargetsExecutionState,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = MonitoringTargetsRunner(mode=mode)
    with pytest.raises(AnsibleError, match="manual recovery") as caught:
        _call(prepared, runner, executables, toolchain)
    assert _PRIVATE_PATH not in str(caught.value)
    assert _SECRET not in str(caught.value)
    execution, evidence = _records(prepared)
    assert execution.record.state is expected
    assert execution.record.authorization_consumed
    assert execution.record.manual_recovery_required
    assert not execution.record.attempt.automatic_retry_allowed
    assert evidence is None

    no_retry = MonitoringTargetsRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_evidence_failure_leaves_started_and_forbids_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)

    def fail_evidence(self, record, **kwargs):
        raise StatePersistenceError("simulated evidence failure")

    monkeypatch.setattr(
        DeployMonitoringTargetsEvidenceStore,
        "write_locked",
        fail_evidence,
    )
    with pytest.raises(StatePersistenceError, match="evidence persistence failed"):
        _call(prepared, MonitoringTargetsRunner(), executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployMonitoringTargetsExecutionState.STARTED
    assert execution.record.manual_recovery_required
    assert evidence is None

    no_retry = MonitoringTargetsRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_post_call_drift_is_durable_manual_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    inventory_path = prepared.paths.ansible_inventory

    def drift() -> None:
        with inventory_path.open("a", encoding="utf-8") as stream:
            stream.write(" ")

    runner = MonitoringTargetsRunner(inspect_started=drift)
    with pytest.raises(StateConflictError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployMonitoringTargetsExecutionState.DRIFTED
    assert execution.record.manual_recovery_required
    assert evidence is None


def test_refuses_missing_authorization_source_policy_drift_and_store_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    authorization_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-monitoring-targets-authorization.json"
    )
    authorization_bytes = authorization_path.read_bytes()
    authorization_path.unlink()
    missing_runner = MonitoringTargetsRunner()
    with pytest.raises(StateConflictError, match="requires immutable authorization"):
        _call(prepared, missing_runner, executables, toolchain)
    assert missing_runner.specs == []
    authorization_path.write_bytes(authorization_bytes)
    authorization_path.chmod(0o600)

    monkeypatch.setattr(
        execution_module,
        "_playbook_source_digest",
        lambda *_args: "sha256:" + "a" * 64,
    )
    drift_runner = MonitoringTargetsRunner()
    with pytest.raises(StateConflictError, match="authorized scope conflicts"):
        _call(prepared, drift_runner, executables, toolchain)
    assert drift_runner.specs == []
    monkeypatch.undo()

    later = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-post-monitoring-targets-reconciliation.json"
    )
    later.write_text("{}\n", encoding="utf-8")
    later.chmod(0o600)
    with pytest.raises(StateConflictError, match="later-stage history"):
        _call(prepared, MonitoringTargetsRunner(), executables, toolchain)
    later.unlink()

    _call(prepared, MonitoringTargetsRunner(), executables, toolchain)
    execution_path = deploy_monitoring_targets_execution_path(
        prepared.paths, OPERATION_ID
    )
    original = execution_path.read_bytes()
    document = cast(dict[str, object], json.loads(original))
    document["invocation_count"] = 2
    execution_path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    execution_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0

    execution_path.write_bytes(original)
    execution_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0

    evidence_path = deploy_monitoring_targets_evidence_path(
        prepared.paths, OPERATION_ID
    )
    evidence_original = evidence_path.read_bytes()
    evidence_document = cast(dict[str, object], json.loads(evidence_original))
    entries = cast(list[dict[str, object]], evidence_document["entries"])
    entries[0]["file_count"] = len(TARGET_FILES) + 1
    evidence_path.write_text(
        json.dumps(evidence_document) + "\n",
        encoding="utf-8",
    )
    evidence_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0

    evidence_path.write_bytes(evidence_original)
    evidence_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0
