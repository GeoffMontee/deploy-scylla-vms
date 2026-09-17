import base64
import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
import test_ansible_deploy_scylla_health_checkpoint as health_fixture
import test_ansible_deploy_scylla_post_bootstrap_reconciliation as bridge_fixture
from test_ansible_deploy_manager_server_authorization import (
    _call as _authorize,
)
from test_ansible_deploy_manager_server_authorization import _proof
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_manager_server_execution as execution_module
from scylla_vms.ansible.deploy_manager_server_execution import (
    ANSIBLE_DEPLOY_MANAGER_SERVER_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_SERVER_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_SERVER_EXECUTION_SCHEMA_VERSION,
    DeployManagerServerArtifactState,
    DeployManagerServerEvidenceStore,
    DeployManagerServerExecution,
    DeployManagerServerExecutionState,
    DeployManagerServerExecutionStore,
    deploy_manager_server_evidence_path,
    deploy_manager_server_execution_path,
    execute_deploy_manager_server,
)
from scylla_vms.ansible.manager_server import (
    MANAGER_PACKAGE_VERSION,
    MANAGER_PACKAGES,
    MANAGER_RELEASE_LINE,
    MANAGER_REPOSITORY_DEFINITION_DIGEST,
    MANAGER_REPOSITORY_URI,
    MANAGER_SERVER_SCHEMA_VERSION,
)
from scylla_vms.ansible.registry import get_playbook
from scylla_vms.ansible.scylla_install import (
    SCYLLA_SIGNING_KEY_DIGEST,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
)
from scylla_vms.errors import AnsibleError, StateConflictError, StatePersistenceError
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.process import ProcessResult, ProcessSpec, ProcessTimeoutError

_PRIVATE_PATH = "/private/operator/manager-server-runtime.json"
_SECRET = "obviously-fake-manager-server-execution-secret"


@dataclass
class ManagerServerRunner:
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
        if playbook != "manager-server":
            raise AssertionError(f"unexpected playbook or external tool: {playbook}")
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        variables = cast(
            dict[str, object], json.loads(runtime_file.read_text(encoding="utf-8"))
        )
        payload = cast(dict[str, object], variables["deploy_scylla_vms_manager_server"])
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
        status = "installed" if self.mode == "installed" else "no-change"
        changed = status == "installed"
        result = {
            "backend_configured": False,
            "blockers": [],
            "configuration_performed": False,
            "installed_version": payload["package_version"],
            "logical_id": payload["logical_id"],
            "packages": {name: payload["package_version"] for name in MANAGER_PACKAGES},
            "provenance": payload["provenance"],
            "registration_performed": False,
            "repository_digest": cast(dict[str, object], payload["repository"])[
                "definition_digest"
            ],
            "requested_release": payload["release_line"],
            "requested_version": payload["package_version"],
            "schema_version": MANAGER_SERVER_SCHEMA_VERSION,
            "service_inactive": True,
            "service_masked": True,
            "service_started": False,
            "setup_performed": False,
            "signing_key_digest": cast(dict[str, object], payload["signing_key"])[
                "artifact_digest"
            ],
            "signing_key_fingerprint": cast(dict[str, object], payload["signing_key"])[
                "fingerprint"
            ],
            "status": status,
            "tasks_performed": False,
        }
        encoded = base64.b64encode(
            json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        logical_id = cast(str, payload["logical_id"])
        stdout = (
            f'ok: [{logical_id}] => {{"msg":"DSV_MANAGER_SERVER_B64={encoded}"}}\n'
            "PLAY RECAP *****\n"
            f"{logical_id} : ok=12 changed={int(changed)} unreachable=0 failed=0 "
            "skipped=0 rescued=0 ignored=0\n"
        )
        return ProcessResult(0, stdout, f"{_SECRET} {_PRIVATE_PATH}")


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, executables, toolchain = health_fixture._prepared(tmp_path, monkeypatch)
    health_fixture._call(
        prepared,
        health_fixture.HealthCheckpointRunner(),
        executables,
        toolchain,
    )
    bridge_fixture._call(prepared)
    _authorize(prepared, _proof())
    return prepared, executables, toolchain


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_manager_server(
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
        execution = DeployManagerServerExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployManagerServerEvidenceStore(prepared.paths, OPERATION_ID)
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


def test_exact_prepared_recovery_success_policy_redaction_and_zero_call_reentry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(inspect.signature(execute_deploy_manager_server).parameters) == (
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
    authorization_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-manager-server-authorization.json"
    )
    bridge_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-scylla-post-bootstrap-reconciliation.json"
    )
    immutable = (
        journal_path.read_bytes(),
        authorization_path.read_bytes(),
        bridge_path.read_bytes(),
    )
    show_before = _run_show(prepared.paths, "--fail-on", "none")

    original_write = DeployManagerServerExecutionStore.write_locked
    refused = False

    def fail_started(self, record, **kwargs):
        nonlocal refused
        if record.state is DeployManagerServerExecutionState.STARTED and not refused:
            refused = True
            raise StatePersistenceError("simulated safe pre-invocation refusal")
        return original_write(self, record, **kwargs)

    monkeypatch.setattr(DeployManagerServerExecutionStore, "write_locked", fail_started)
    first = ManagerServerRunner()
    with pytest.raises(StatePersistenceError, match="before invocation"):
        _call(prepared, first, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployManagerServerExecutionState.PREPARED
    assert not execution.record.authorization_consumed
    assert execution.record.invocation_count == 0
    assert evidence is None
    assert first.specs is not None and len(first.specs) == 2

    monkeypatch.setattr(
        DeployManagerServerExecutionStore, "write_locked", original_write
    )
    observed: list[DeployManagerServerExecutionState] = []

    def inspect_started() -> None:
        value = json.loads(
            deploy_manager_server_execution_path(
                prepared.paths, OPERATION_ID
            ).read_text(encoding="utf-8")
        )
        record = DeployManagerServerExecution.from_object(value)
        observed.append(record.state)
        assert record.authorization_consumed
        assert record.invocation_count == 1
        assert record.attempt.authorization_consumed_at_start

    runner = ManagerServerRunner(mode="installed", inspect_started=inspect_started)
    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert evidence is not None
    assert observed == [DeployManagerServerExecutionState.STARTED]
    assert execution.record.schema_version == (
        ANSIBLE_DEPLOY_MANAGER_SERVER_EXECUTION_SCHEMA_VERSION
    )
    assert evidence.record.schema_version == (
        ANSIBLE_DEPLOY_MANAGER_SERVER_EVIDENCE_SCHEMA_VERSION
    )
    assert report.schema_version == (
        ANSIBLE_DEPLOY_MANAGER_SERVER_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert report.execution_state is DeployManagerServerExecutionState.SUCCEEDED
    assert report.execution_artifact_state is DeployManagerServerArtifactState.UPDATED
    assert report.evidence_artifact_state is DeployManagerServerArtifactState.CREATED
    assert report.authorization_consumed
    assert report.invocation_count == report.installed_count == 1
    assert report.changed_count == 1
    assert report.target_stable_id == "manager-1"
    assert report.release_line == MANAGER_RELEASE_LINE == "3.12"
    assert report.package_count == len(MANAGER_PACKAGES)
    assert report.repository_definition_digest == MANAGER_REPOSITORY_DEFINITION_DIGEST
    assert report.signing_key_artifact_digest == SCYLLA_SIGNING_KEY_DIGEST
    assert report.service_safe_count == 1
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
        bridge_path.read_bytes(),
    ) == immutable
    assert runner.specs is not None and len(runner.specs) == 3
    assert runner.payloads is not None and len(runner.payloads) == 1
    payload = runner.payloads[0]
    assert payload["package_version"] == MANAGER_PACKAGE_VERSION
    assert payload["packages"] == list(MANAGER_PACKAGES)
    assert payload["backend_configured"] is False
    assert payload["configuration_performed"] is False
    assert payload["registration_performed"] is False
    assert payload["setup_performed"] is False
    assert payload["tasks_performed"] is False
    assert payload["service_started"] is False
    definition = get_playbook("manager-server")
    assert definition.serial == 1
    assert "--check" not in runner.specs[-1].argv
    assert "--tags" not in runner.specs[-1].argv
    assert "manager-1" in runner.specs[-1].argv
    entry = evidence.record.entries[0]
    assert entry.stable_id == "manager-1"
    assert entry.installed and entry.changed
    assert entry.service_masked and entry.service_inactive
    assert not entry.service_started
    assert not entry.backend_configured
    assert not entry.configuration_performed
    assert not entry.registration_performed
    assert not entry.setup_performed
    assert not entry.tasks_performed
    assert _run_show(prepared.paths, "--fail-on", "none") == show_before

    for path in (
        deploy_manager_server_execution_path(prepared.paths, OPERATION_ID),
        deploy_manager_server_evidence_path(prepared.paths, OPERATION_ID),
    ):
        assert path.stat().st_mode & 0o777 == 0o600
    persisted = (
        deploy_manager_server_execution_path(prepared.paths, OPERATION_ID).read_text(
            encoding="utf-8"
        )
        + deploy_manager_server_evidence_path(prepared.paths, OPERATION_ID).read_text(
            encoding="utf-8"
        )
        + json.dumps(report.to_object(), sort_keys=True)
    )
    for protected in (
        _PRIVATE_PATH,
        _SECRET,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        MANAGER_REPOSITORY_URI,
        SCYLLA_SIGNING_KEY_FINGERPRINT,
        MANAGER_PACKAGE_VERSION,
        "BEGIN PGP",
        "PLAY RECAP",
        "DSV_MANAGER_SERVER_B64",
        "ansible-playbook",
        "--limit",
        '"variables"',
        '"commands"',
    ):
        assert protected not in persisted

    zero_runner = ManagerServerRunner(mode="timeout")
    reused = _call(prepared, zero_runner, executables, toolchain)
    assert zero_runner.specs == []
    assert reused.execution_artifact_state is DeployManagerServerArtifactState.REUSED
    assert reused.evidence_artifact_state is DeployManagerServerArtifactState.REUSED


@pytest.mark.parametrize(
    ("mode", "expected"),
    (
        ("timeout", DeployManagerServerExecutionState.TIMED_OUT),
        ("malformed", DeployManagerServerExecutionState.MALFORMED_RESULT),
        ("failed", DeployManagerServerExecutionState.FAILED),
        ("unreachable", DeployManagerServerExecutionState.UNREACHABLE),
    ),
)
def test_started_uncertainty_is_permanent_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    expected: DeployManagerServerExecutionState,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = ManagerServerRunner(mode=mode)
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

    no_retry = ManagerServerRunner()
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
        DeployManagerServerEvidenceStore,
        "write_locked",
        fail_evidence,
    )
    runner = ManagerServerRunner()
    with pytest.raises(StatePersistenceError, match="evidence persistence failed"):
        _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployManagerServerExecutionState.STARTED
    assert execution.record.manual_recovery_required
    assert evidence is None

    no_retry = ManagerServerRunner()
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

    runner = ManagerServerRunner(inspect_started=drift)
    with pytest.raises(StateConflictError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployManagerServerExecutionState.DRIFTED
    assert execution.record.manual_recovery_required
    assert evidence is None


def test_refuses_source_policy_drift_and_store_tamper_show_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    monkeypatch.setattr(
        execution_module,
        "_playbook_source_digest",
        lambda *_args: "sha256:" + "a" * 64,
    )
    runner = ManagerServerRunner()
    with pytest.raises(StateConflictError, match="authorized scope conflicts"):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []

    monkeypatch.undo()
    _call(prepared, ManagerServerRunner(), executables, toolchain)
    execution_path = deploy_manager_server_execution_path(prepared.paths, OPERATION_ID)
    original = execution_path.read_bytes()
    document = cast(dict[str, object], json.loads(original))
    document["invocation_count"] = 2
    execution_path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    execution_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0

    execution_path.write_bytes(original)
    execution_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0
