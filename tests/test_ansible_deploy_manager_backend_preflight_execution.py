import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_manager_backend_configuration_plan import (
    _call as _plan_backend,
)
from test_ansible_deploy_manager_backend_configuration_plan import (
    _prepared as _prepare_backend,
)
from test_ansible_manager_backend_preflight import _result, _stdout
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_manager_backend_preflight_execution as execution_module
from scylla_vms.ansible.deploy_manager_backend_preflight_execution import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION,
    DeployManagerBackendPreflightEvidenceStore,
    DeployManagerBackendPreflightExecution,
    DeployManagerBackendPreflightExecutionState,
    DeployManagerBackendPreflightExecutionStore,
    deploy_manager_backend_preflight_evidence_path,
    deploy_manager_backend_preflight_execution_path,
    execute_deploy_manager_backend_preflight,
)
from scylla_vms.ansible.manager_backend_preflight import (
    MANAGER_BACKEND_UNRESOLVED_BLOCKERS,
    ManagerBackendPreflightStatus,
)
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.toolchain import (
    AnsibleCoreVersion,
    AnsibleToolchain,
)
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.process import (
    ProcessOutputError,
    ProcessResult,
    ProcessSpec,
    ProcessTimeoutError,
)

_PRIVATE_PATH = "/private/operator/manager-backend-preflight-runtime.json"
_SECRET = "obviously-fake-manager-backend-preflight-secret"


@dataclass
class ManagerBackendPreflightRunner:
    mode: str = "evidence-ready"
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
        if playbook != "manager-backend-preflight":
            raise AssertionError(f"unexpected playbook or external tool: {playbook}")
        assert "--check" in spec.argv
        assert spec.argv[spec.argv.index("--tags") + 1] == "manager-backend-preflight"
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        variables = cast(
            dict[str, object], json.loads(runtime_file.read_text(encoding="utf-8"))
        )
        payload = cast(
            dict[str, object],
            variables["deploy_scylla_vms_manager_backend_preflight"],
        )
        self.payloads.append(payload)
        assert spec.argv[spec.argv.index("--limit") + 1] == payload["logical_id"]
        if self.inspect_started is not None:
            self.inspect_started()
        if self.mode == "timeout":
            raise ProcessTimeoutError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode in {"non-utf8", "oversized-output"}:
            if self.mode == "non-utf8":
                raise ProcessOutputError(f"{_SECRET} {_PRIVATE_PATH}")
            return ProcessResult(0, "x" * 300_000, f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "malformed":
            return ProcessResult(0, "malformed", f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode in {"failed", "unreachable"}:
            logical_id = cast(str, payload["logical_id"])
            unreachable = int(self.mode == "unreachable")
            failed = int(self.mode == "failed")
            return ProcessResult(
                4 if unreachable else 2,
                "PLAY RECAP *****\n"
                f"{logical_id} : ok=1 changed=0 unreachable={unreachable} "
                f"failed={failed} skipped=0 rescued=0 ignored=0\n",
                f"{_SECRET} {_PRIVATE_PATH}",
            )
        result = _result(payload)
        if self.mode == "blocked":
            blockers = list(MANAGER_BACKEND_UNRESOLVED_BLOCKERS)
            blockers.append("local-scylla-package-present")
            result["status"] = "blocked"
            result["local_scylla_package_status"] = "installed"
            result["blockers"] = sorted(blockers)
        elif self.mode == "wrong-target":
            result["logical_id"] = "wrong-target"
        return ProcessResult(
            0,
            _stdout(payload, result),
            f"{_SECRET} {_PRIVATE_PATH}",
        )


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, _runner = _prepare_backend(tmp_path, monkeypatch)
    _plan_backend(prepared)
    executables = ControlledAnsibleExecutables(
        tmp_path / "ansible-playbook", tmp_path / "ansible-inventory"
    )
    toolchain = AnsibleToolchain(AnsibleCoreVersion(2, 20, 9))
    return prepared, executables, toolchain


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_manager_backend_preflight(
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
        execution = DeployManagerBackendPreflightExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployManagerBackendPreflightEvidenceStore(
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


def test_exact_read_only_execution_is_redacted_and_reentry_is_zero_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signature = inspect.signature(execute_deploy_manager_backend_preflight)
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
        "target",
        "limit",
        "evidence",
        "capacity",
        "package",
        "service",
        "config",
        "command",
        "variable",
        "path",
        "result",
        "retry",
    ):
        assert forbidden not in signature.parameters

    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    execution_path = deploy_manager_backend_preflight_execution_path(
        prepared.paths, OPERATION_ID
    )
    evidence_path = deploy_manager_backend_preflight_evidence_path(
        prepared.paths, OPERATION_ID
    )
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_bytes = journal_path.read_bytes()
    prior_paths = tuple(
        path
        for path in prepared.paths.operations.iterdir()
        if path.is_file() and path not in {execution_path, evidence_path}
    )
    prior_bytes = {path: path.read_bytes() for path in prior_paths}
    observed_started: list[bool] = []

    def inspect_started() -> None:
        execution = DeployManagerBackendPreflightExecution.from_object(
            json.loads(execution_path.read_text(encoding="utf-8"))
        )
        observed_started.append(
            execution.state is DeployManagerBackendPreflightExecutionState.STARTED
        )
        assert execution.manual_recovery_required
        assert not evidence_path.exists()

    runner = ManagerBackendPreflightRunner(inspect_started=inspect_started)
    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert evidence is not None
    assert observed_started == [True]
    assert report.schema_version == (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert execution.record.schema_version == (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION
    )
    assert evidence.record.schema_version == (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    )
    assert (
        report.execution_state is DeployManagerBackendPreflightExecutionState.SUCCEEDED
    )
    assert report.semantic_status is ManagerBackendPreflightStatus.EVIDENCE_READY
    assert report.blocker_count == len(MANAGER_BACKEND_UNRESOLVED_BLOCKERS)
    assert evidence.record.approved_mount_count == 1
    assert evidence.record.available_mount_count == 1
    assert evidence.record.approved_mount_status == "available"
    assert len(cast(list[ProcessSpec], runner.specs)) == 3
    assert len(cast(list[dict[str, object]], runner.payloads)) == 1
    assert execution_path.stat().st_mode & 0o777 == 0o600
    assert evidence_path.stat().st_mode & 0o777 == 0o600
    assert journal_path.read_bytes() == journal_bytes
    assert {path: path.read_bytes() for path in prior_paths} == prior_bytes

    encoded = execution_path.read_text() + evidence_path.read_text()
    for protected in (
        _SECRET,
        _PRIVATE_PATH,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "/dev/",
        "--extra-vars",
        "deploy_scylla_vms_manager_backend_preflight",
        "password",
        "credential",
    ):
        assert protected not in encoded

    execution_bytes = execution_path.read_bytes()
    evidence_bytes = evidence_path.read_bytes()
    execution_mtime = execution_path.stat().st_mtime_ns
    evidence_mtime = evidence_path.stat().st_mtime_ns
    reentry_runner = ManagerBackendPreflightRunner()
    reused = _call(prepared, reentry_runner, executables, toolchain)
    assert reused.execution_artifact_state.value == "reused"
    assert reentry_runner.specs == []
    assert execution_path.read_bytes() == execution_bytes
    assert evidence_path.read_bytes() == evidence_bytes
    assert execution_path.stat().st_mtime_ns == execution_mtime
    assert evidence_path.stat().st_mtime_ns == evidence_mtime
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


def test_blocked_host_evidence_is_strict_success_for_later_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    report = _call(
        prepared,
        ManagerBackendPreflightRunner(mode="blocked"),
        executables,
        toolchain,
    )
    _execution, evidence = _records(prepared)
    assert evidence is not None
    assert report.semantic_status is ManagerBackendPreflightStatus.BLOCKED
    assert evidence.record.local_scylla_package_status.value == "installed"
    assert "local-scylla-package-present" in evidence.record.blockers


@pytest.mark.parametrize(
    ("mode", "state"),
    (
        ("timeout", DeployManagerBackendPreflightExecutionState.TIMED_OUT),
        ("non-utf8", DeployManagerBackendPreflightExecutionState.MALFORMED_RESULT),
        (
            "oversized-output",
            DeployManagerBackendPreflightExecutionState.MALFORMED_RESULT,
        ),
        ("malformed", DeployManagerBackendPreflightExecutionState.MALFORMED_RESULT),
        ("wrong-target", DeployManagerBackendPreflightExecutionState.MALFORMED_RESULT),
        ("failed", DeployManagerBackendPreflightExecutionState.FAILED),
        ("unreachable", DeployManagerBackendPreflightExecutionState.UNREACHABLE),
    ),
)
def test_uncertain_or_failed_attempt_is_durable_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    state: DeployManagerBackendPreflightExecutionState,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    with pytest.raises(AnsibleError, match="manual recovery required"):
        _call(
            prepared,
            ManagerBackendPreflightRunner(mode=mode),
            executables,
            toolchain,
        )
    execution, evidence = _records(prepared)
    assert execution.record.state is state
    assert execution.record.exit_code == (
        4 if mode == "unreachable" else 2 if mode == "failed" else None
    )
    assert execution.record.manual_recovery_required
    assert not execution.record.automatic_retry_allowed
    assert evidence is None
    retry = ManagerBackendPreflightRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, retry, executables, toolchain)
    assert retry.specs == []


def test_evidence_persistence_failure_and_post_call_drift_are_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    prepared, executables, toolchain = _prepared(evidence_root, monkeypatch)

    def refuse_evidence(*_args, **_kwargs):
        raise StatePersistenceError("simulated evidence failure")

    monkeypatch.setattr(
        DeployManagerBackendPreflightEvidenceStore,
        "write_locked",
        refuse_evidence,
    )
    with pytest.raises(StatePersistenceError, match="evidence persistence failed"):
        _call(
            prepared,
            ManagerBackendPreflightRunner(),
            executables,
            toolchain,
        )
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployManagerBackendPreflightExecutionState.STARTED
    assert evidence is None
    retry = ManagerBackendPreflightRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, retry, executables, toolchain)
    assert retry.specs == []

    monkeypatch.undo()
    drift_root = tmp_path / "drift"
    drift_root.mkdir()
    prepared, executables, toolchain = _prepared(drift_root, monkeypatch)
    inventory_path = prepared.paths.ansible_inventory
    inventory_bytes = inventory_path.read_bytes()

    def drift_after_start() -> None:
        inventory_path.write_text("{}\n", encoding="utf-8")
        inventory_path.chmod(0o600)

    with pytest.raises(StateConflictError, match="manual recovery required"):
        _call(
            prepared,
            ManagerBackendPreflightRunner(inspect_started=drift_after_start),
            executables,
            toolchain,
        )
    inventory_path.write_bytes(inventory_bytes)
    inventory_path.chmod(0o600)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployManagerBackendPreflightExecutionState.DRIFTED
    assert evidence is None


def test_refuses_wrong_lock_source_drift_and_tampered_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = ManagerBackendPreflightRunner()
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        execute_deploy_manager_backend_preflight(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )
    assert runner.specs == []

    original_source_digest = execution_module._playbook_source_digest
    monkeypatch.setattr(
        execution_module,
        "_playbook_source_digest",
        lambda *_args: "sha256:" + "a" * 64,
    )
    with pytest.raises(StateConflictError):
        _call(
            prepared,
            ManagerBackendPreflightRunner(),
            executables,
            toolchain,
        )
    monkeypatch.setattr(
        execution_module,
        "_playbook_source_digest",
        original_source_digest,
    )

    _call(
        prepared,
        ManagerBackendPreflightRunner(),
        executables,
        toolchain,
    )
    execution_path = deploy_manager_backend_preflight_execution_path(
        prepared.paths, OPERATION_ID
    )
    document = json.loads(execution_path.read_text(encoding="utf-8"))
    document["state"] = "started"
    execution_path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    execution_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
