import inspect
import json
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_manager_backend_local_install_authorization import (
    _call as _authorize_install,
)
from test_ansible_deploy_manager_backend_local_install_authorization import (
    _proof as _install_proof,
)
from test_ansible_deploy_manager_backend_local_install_execution import (
    ManagerBackendLocalInstallRunner,
)
from test_ansible_deploy_manager_backend_local_install_execution import (
    _call as _execute_install,
)
from test_ansible_deploy_manager_backend_local_install_reconciliation import (
    _call as _reconcile_install,
)
from test_ansible_deploy_manager_backend_storage_allocation_plan import (
    _call as _plan_storage,
)
from test_ansible_manager_backend_storage_discover import _stdout
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_manager_backend_installation_plan as installation_module
import scylla_vms.ansible.deploy_manager_backend_local_install_authorization as authorization_module
import scylla_vms.ansible.deploy_manager_backend_storage_discovery_execution as execution_module
import scylla_vms.ansible.manager_backend_local_install as local_install_module
from scylla_vms.ansible.deploy_manager_backend_storage_discovery_execution import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION,
    DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_FILENAME_SUFFIX,
    DeployManagerBackendStorageDiscoveryEvidenceStore,
    DeployManagerBackendStorageDiscoveryExecution,
    DeployManagerBackendStorageDiscoveryExecutionState,
    DeployManagerBackendStorageDiscoveryExecutionStore,
    deploy_manager_backend_storage_discovery_evidence_path,
    deploy_manager_backend_storage_discovery_execution_path,
    execute_deploy_manager_backend_storage_discovery,
)
from scylla_vms.ansible.manager_backend_storage_discover import (
    ManagerBackendStorageDiscoveryStatus,
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

pytest_plugins = ("test_ansible_deploy_manager_backend_local_install_execution",)

_FIXTURE = (
    Path(__file__).parent
    / "fixtures/ansible/manager-backend-storage-discover-result.json"
)
_PRIVATE_PATH = "/private/operator/manager-backend-storage-discovery.json"
_SECRET = "obviously-fake-manager-backend-storage-secret"


@dataclass
class ManagerBackendStorageDiscoveryRunner:
    mode: str = "discovered"
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
        if playbook != "manager-backend-storage-discover":
            raise AssertionError(f"unexpected playbook or external tool: {playbook}")
        assert "--check" in spec.argv
        assert (
            spec.argv[spec.argv.index("--tags") + 1]
            == "manager-backend-storage-discover"
        )
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        variables = cast(
            dict[str, object], json.loads(runtime_file.read_text(encoding="utf-8"))
        )
        payload = cast(
            dict[str, object],
            variables["deploy_scylla_vms_manager_backend_storage_discover"],
        )
        self.payloads.append(payload)
        assert spec.argv[spec.argv.index("--limit") + 1] == payload["logical_id"]
        if self.inspect_started is not None:
            self.inspect_started()
        if self.mode == "timeout":
            raise ProcessTimeoutError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode in {"non-utf8", "oversized-output"}:
            raise ProcessOutputError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "malformed":
            return ProcessResult(0, "malformed", f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode in {"failed", "unreachable"}:
            unreachable = int(self.mode == "unreachable")
            failed = int(self.mode == "failed")
            return ProcessResult(
                4 if unreachable else 2,
                "PLAY RECAP *****\n"
                f"{payload['logical_id']} : ok=1 changed=0 "
                f"unreachable={unreachable} failed={failed} "
                "skipped=0 rescued=0 ignored=0\n",
                f"{_SECRET} {_PRIVATE_PATH}",
            )
        result = cast(
            dict[str, object],
            json.loads(_FIXTURE.read_text(encoding="utf-8")),
        )
        result["manifest_digest"] = payload["manifest_digest"]
        result["provenance"] = payload["provenance"]
        result["total_size_gib"] = payload["expected_size_gib"]
        if self.mode == "blocked":
            result.update(
                {
                    "status": "blocked",
                    "device_count": 0,
                    "total_size_gib": 0,
                    "device_type": "unknown",
                    "signature_status": "unknown",
                    "ownership_status": "unknown",
                    "mount_status": "unknown",
                    "root_status": "unknown",
                    "blockers": ["ambiguous-device-match"],
                }
            )
        elif self.mode == "wrong-target":
            result["logical_id"] = "wrong-target"
        return ProcessResult(0, _stdout(result), f"{_SECRET} {_PRIVATE_PATH}")


@pytest.fixture(scope="module")
def discovery_baseline(
    execution_baseline,
    tmp_path_factory: pytest.TempPathFactory,
):
    prepared, executables, toolchain, snapshot = execution_baseline
    monkeypatch = pytest.MonkeyPatch()
    shutil.rmtree(prepared.paths.state_root)
    shutil.copytree(snapshot, prepared.paths.state_root)
    for module in (
        installation_module,
        local_install_module,
        authorization_module,
    ):
        monkeypatch.setattr(
            module,
            "validate_scylla_signing_key",
            lambda _key: None,
        )
    _authorize_install(prepared, _install_proof())
    _execute_install(
        prepared,
        ManagerBackendLocalInstallRunner(),
        executables,
        toolchain,
    )
    _reconcile_install(prepared)
    _plan_storage(prepared)
    root = tmp_path_factory.mktemp("manager-backend-storage-discovery")
    ready_snapshot = root / "ready-snapshot"
    shutil.copytree(prepared.paths.state_root, ready_snapshot)
    yield prepared, executables, toolchain, ready_snapshot
    monkeypatch.undo()


@pytest.fixture
def ready_discovery(discovery_baseline):
    prepared, executables, toolchain, snapshot = discovery_baseline
    shutil.rmtree(prepared.paths.state_root)
    shutil.copytree(snapshot, prepared.paths.state_root)
    return prepared, executables, toolchain


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_manager_backend_storage_discovery(
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
        execution = DeployManagerBackendStorageDiscoveryExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployManagerBackendStorageDiscoveryEvidenceStore(
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


def test_exact_execution_redaction_show_and_zero_process_reentry(
    ready_discovery,
) -> None:
    signature = inspect.signature(execute_deploy_manager_backend_storage_discovery)
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
        "device",
        "path",
        "manifest",
        "capacity",
        "command",
        "variable",
        "result",
        "retry",
    ):
        assert forbidden not in signature.parameters

    prepared, executables, toolchain = ready_discovery
    execution_path = deploy_manager_backend_storage_discovery_execution_path(
        prepared.paths, OPERATION_ID
    )
    evidence_path = deploy_manager_backend_storage_discovery_evidence_path(
        prepared.paths, OPERATION_ID
    )
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_bytes = journal_path.read_bytes()
    observed_started: list[bool] = []

    def inspect_started() -> None:
        execution = DeployManagerBackendStorageDiscoveryExecution.from_object(
            json.loads(execution_path.read_text(encoding="utf-8"))
        )
        observed_started.append(
            execution.state
            is DeployManagerBackendStorageDiscoveryExecutionState.STARTED
        )
        assert execution.manual_recovery_required
        assert not evidence_path.exists()

    runner = ManagerBackendStorageDiscoveryRunner(inspect_started=inspect_started)
    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert evidence is not None
    assert observed_started == [True]
    assert (
        report.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert (
        execution.record.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION
    )
    assert (
        evidence.record.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION
    )
    assert (
        report.execution_state
        is DeployManagerBackendStorageDiscoveryExecutionState.SUCCEEDED
    )
    assert report.semantic_status is ManagerBackendStorageDiscoveryStatus.DISCOVERED
    assert report.device_count == 1
    assert report.capacity_policy_state == "unknown"
    assert execution_path.stat().st_mode & 0o777 == 0o600
    assert evidence_path.stat().st_mode & 0o777 == 0o600
    assert journal_path.read_bytes() == journal_bytes

    encoded = execution_path.read_text() + evidence_path.read_text()
    for protected in (
        _SECRET,
        _PRIVATE_PATH,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "/dev/",
        "serial",
        "--extra-vars",
        "deploy_scylla_vms_manager_backend_storage_discover",
        "password",
        "credential",
    ):
        assert protected not in encoded.lower()

    execution_bytes = execution_path.read_bytes()
    evidence_bytes = evidence_path.read_bytes()
    execution_mtime = execution_path.stat().st_mtime_ns
    evidence_mtime = evidence_path.stat().st_mtime_ns
    reentry_runner = ManagerBackendStorageDiscoveryRunner()
    reused = _call(prepared, reentry_runner, executables, toolchain)
    assert reused.execution_artifact_state.value == "reused"
    assert reentry_runner.specs == []
    assert execution_path.read_bytes() == execution_bytes
    assert evidence_path.read_bytes() == evidence_bytes
    assert execution_path.stat().st_mtime_ns == execution_mtime
    assert evidence_path.stat().st_mtime_ns == evidence_mtime
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


def test_bounded_blocked_result_is_persisted_without_safety_inference(
    ready_discovery,
) -> None:
    prepared, executables, toolchain = ready_discovery
    report = _call(
        prepared,
        ManagerBackendStorageDiscoveryRunner(mode="blocked"),
        executables,
        toolchain,
    )
    _execution, evidence = _records(prepared)
    assert evidence is not None
    assert report.semantic_status is ManagerBackendStorageDiscoveryStatus.BLOCKED
    assert evidence.record.blockers == ("ambiguous-device-match",)
    assert evidence.record.capacity_policy_state == "unknown"
    assert evidence.record.capacity_evaluation_state == "not-evaluated"


@pytest.mark.parametrize(
    ("mode", "state"),
    (
        ("timeout", DeployManagerBackendStorageDiscoveryExecutionState.TIMED_OUT),
        (
            "non-utf8",
            DeployManagerBackendStorageDiscoveryExecutionState.MALFORMED_RESULT,
        ),
        (
            "oversized-output",
            DeployManagerBackendStorageDiscoveryExecutionState.MALFORMED_RESULT,
        ),
        (
            "malformed",
            DeployManagerBackendStorageDiscoveryExecutionState.MALFORMED_RESULT,
        ),
        (
            "wrong-target",
            DeployManagerBackendStorageDiscoveryExecutionState.MALFORMED_RESULT,
        ),
        ("failed", DeployManagerBackendStorageDiscoveryExecutionState.FAILED),
        (
            "unreachable",
            DeployManagerBackendStorageDiscoveryExecutionState.UNREACHABLE,
        ),
    ),
)
def test_uncertain_or_failed_attempt_is_durable_no_retry(
    ready_discovery,
    mode: str,
    state: DeployManagerBackendStorageDiscoveryExecutionState,
) -> None:
    prepared, executables, toolchain = ready_discovery
    with pytest.raises(AnsibleError, match="manual recovery required"):
        _call(
            prepared,
            ManagerBackendStorageDiscoveryRunner(mode=mode),
            executables,
            toolchain,
        )
    execution, evidence = _records(prepared)
    assert execution.record.state is state
    assert execution.record.manual_recovery_required
    assert not execution.record.automatic_retry_allowed
    assert evidence is None
    retry = ManagerBackendStorageDiscoveryRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, retry, executables, toolchain)
    assert retry.specs == []


def test_post_call_drift_is_no_retry(
    ready_discovery,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = ready_discovery
    inventory_path = prepared.paths.ansible_inventory
    inventory_bytes = inventory_path.read_bytes()

    def drift_after_start() -> None:
        inventory_path.write_text("{}\n", encoding="utf-8")
        inventory_path.chmod(0o600)

    with pytest.raises(StateConflictError, match="manual recovery required"):
        _call(
            prepared,
            ManagerBackendStorageDiscoveryRunner(inspect_started=drift_after_start),
            executables,
            toolchain,
        )
    inventory_path.write_bytes(inventory_bytes)
    inventory_path.chmod(0o600)
    execution, evidence = _records(prepared)
    assert (
        execution.record.state
        is DeployManagerBackendStorageDiscoveryExecutionState.DRIFTED
    )
    assert evidence is None


def test_evidence_write_failure_is_no_retry(
    ready_discovery,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = ready_discovery

    def refuse_evidence(*_args, **_kwargs):
        raise StatePersistenceError("simulated evidence failure")

    monkeypatch.setattr(
        DeployManagerBackendStorageDiscoveryEvidenceStore,
        "write_locked",
        refuse_evidence,
    )
    with pytest.raises(StatePersistenceError, match="evidence persistence failed"):
        _call(
            prepared,
            ManagerBackendStorageDiscoveryRunner(),
            executables,
            toolchain,
        )
    execution, evidence = _records(prepared)
    assert (
        execution.record.state
        is DeployManagerBackendStorageDiscoveryExecutionState.STARTED
    )
    assert evidence is None
    retry = ManagerBackendStorageDiscoveryRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, retry, executables, toolchain)
    assert retry.specs == []


def test_refuses_wrong_lock_source_drift_ambiguity_and_tamper(
    ready_discovery,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = ready_discovery
    runner = ManagerBackendStorageDiscoveryRunner()
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        execute_deploy_manager_backend_storage_discovery(
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
            ManagerBackendStorageDiscoveryRunner(),
            executables,
            toolchain,
        )
    monkeypatch.setattr(
        execution_module,
        "_playbook_source_digest",
        original_source_digest,
    )

    ambiguous = prepared.paths.operations / (
        f"{str(OPERATION_ID).upper()}"
        f"{DEPLOY_MANAGER_BACKEND_STORAGE_DISCOVERY_EXECUTION_FILENAME_SUFFIX}"
    )
    ambiguous.write_text("{}\n", encoding="utf-8")
    ambiguous.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _call(
            prepared,
            ManagerBackendStorageDiscoveryRunner(),
            executables,
            toolchain,
        )
    ambiguous.unlink()

    _call(
        prepared,
        ManagerBackendStorageDiscoveryRunner(),
        executables,
        toolchain,
    )
    execution_path = deploy_manager_backend_storage_discovery_execution_path(
        prepared.paths, OPERATION_ID
    )
    document = json.loads(execution_path.read_text(encoding="utf-8"))
    document["state"] = "started"
    execution_path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    execution_path.chmod(0o600)
    with pytest.raises(StatePersistenceError):
        _call(
            prepared,
            ManagerBackendStorageDiscoveryRunner(),
            executables,
            toolchain,
        )
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
