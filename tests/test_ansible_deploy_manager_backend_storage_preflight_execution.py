import hashlib
import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_manager_backend_storage_discovery_execution import (
    ManagerBackendStorageDiscoveryRunner,
)
from test_ansible_deploy_manager_backend_storage_discovery_execution import (
    _call as _execute_discovery,
)
from test_ansible_deploy_manager_backend_storage_discovery_reconciliation import (
    _call as _reconcile_discovery,
)
from test_ansible_deploy_manager_backend_storage_preflight_plan import (
    _call as _plan_preflight,
)
from test_ansible_manager_backend_storage_preflight import _stdout
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_manager_backend_storage_preflight_execution import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION,
    DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_FILENAME_SUFFIX,
    DeployManagerBackendStoragePreflightEvidenceStore,
    DeployManagerBackendStoragePreflightExecution,
    DeployManagerBackendStoragePreflightExecutionState,
    DeployManagerBackendStoragePreflightExecutionStore,
    deploy_manager_backend_storage_preflight_evidence_path,
    deploy_manager_backend_storage_preflight_execution_path,
    execute_deploy_manager_backend_storage_preflight,
)
from scylla_vms.ansible.manager_backend_storage_preflight import (
    ManagerBackendStoragePreflightDisposition,
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

pytest_plugins = ("test_ansible_deploy_manager_backend_storage_preflight_plan",)

_FIXTURE = (
    Path(__file__).parent
    / "fixtures/ansible/manager-backend-storage-preflight-result.json"
)
_PRIVATE_PATH = "/private/operator/manager-backend-storage-preflight.json"
_SECRET = "obviously-fake-manager-backend-storage-preflight-secret"


def _object_digest(value: object) -> str:
    data = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


@dataclass
class ManagerBackendStoragePreflightRunner:
    mode: str = "prepare-required"
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
        if playbook != "manager-backend-storage-preflight":
            raise AssertionError(f"unexpected playbook or external tool: {playbook}")
        assert "--check" in spec.argv
        assert (
            spec.argv[spec.argv.index("--tags") + 1]
            == "manager-backend-storage-preflight"
        )
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        variables = cast(
            dict[str, object], json.loads(runtime_file.read_text(encoding="utf-8"))
        )
        payload = cast(
            dict[str, object],
            variables["deploy_scylla_vms_manager_backend_storage_preflight"],
        )
        self.payloads.append(payload)
        assert spec.argv[spec.argv.index("--limit") + 1] == payload["stable_id"]
        if self.inspect_started is not None:
            self.inspect_started()
        if self.mode == "interrupted":
            raise KeyboardInterrupt
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
                f"{payload['stable_id']} : ok=1 changed=0 "
                f"unreachable={unreachable} failed={failed} "
                "skipped=0 rescued=0 ignored=0\n",
                f"{_SECRET} {_PRIVATE_PATH}",
            )
        result = cast(
            dict[str, object],
            json.loads(_FIXTURE.read_text(encoding="utf-8")),
        )
        result.update(
            {
                "stable_id": payload["stable_id"],
                "capacity_policy_state": payload["capacity_policy_state"],
                "capacity_sufficiency_state": payload["capacity_sufficiency_state"],
                "requested_size_gib": payload["requested_size_gib"],
                "observed_size_gib": payload["observed_size_gib"],
                "device_size_gib": payload["observed_size_gib"],
                "device_set_digest": payload["discovery_device_set_digest"],
                "preparation_intent_digest": payload["preparation_intent_digest"],
                "provenance_digest": _object_digest(payload["provenance"]),
                "not_performed": payload["not_performed"],
            }
        )
        if self.mode == "owned-noop":
            result.update(
                {
                    "disposition": "owned-noop",
                    "actions": [],
                    "wipe_required": False,
                    "signature_state": "present",
                    "ownership_state": "manager-owned",
                    "mount_state": "expected-mounted",
                    "fstab_state": "expected",
                    "role_marker_state": "expected",
                    "blockers": [],
                    "blocker_digest": _object_digest([]),
                }
            )
        elif self.mode in {"blocked", "blocked-wipe"}:
            blockers = (
                ["foreign-signature"]
                if self.mode == "blocked-wipe"
                else ["device-identity-mismatch"]
            )
            result.update(
                {
                    "disposition": "blocked",
                    "actions": [],
                    "wipe_required": self.mode == "blocked-wipe",
                    "signature_state": (
                        "present" if self.mode == "blocked-wipe" else "unknown"
                    ),
                    "ownership_state": (
                        "unowned" if self.mode == "blocked-wipe" else "unknown"
                    ),
                    "mount_state": "unknown",
                    "fstab_state": "unknown",
                    "role_marker_state": "unknown",
                    "blockers": blockers,
                    "blocker_digest": _object_digest(blockers),
                }
            )
        elif self.mode == "wrong-target":
            result["stable_id"] = "wrong-target"
        return ProcessResult(0, _stdout(result), f"{_SECRET} {_PRIVATE_PATH}")


@pytest.fixture
def ready_preflight_execution(ready_discovery):
    prepared, executables, toolchain = ready_discovery
    _execute_discovery(
        prepared,
        ManagerBackendStorageDiscoveryRunner(),
        executables,
        toolchain,
    )
    _reconcile_discovery(prepared)
    _plan_preflight(prepared)
    return prepared, executables, toolchain


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_manager_backend_storage_preflight(
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
        execution = DeployManagerBackendStoragePreflightExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployManagerBackendStoragePreflightEvidenceStore(
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
    ready_preflight_execution,
) -> None:
    signature = inspect.signature(execute_deploy_manager_backend_storage_preflight)
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
        "action",
        "layout",
        "capacity",
        "evidence",
        "command",
        "variable",
        "result",
        "retry",
    ):
        assert forbidden not in signature.parameters

    prepared, executables, toolchain = ready_preflight_execution
    execution_path = deploy_manager_backend_storage_preflight_execution_path(
        prepared.paths, OPERATION_ID
    )
    evidence_path = deploy_manager_backend_storage_preflight_evidence_path(
        prepared.paths, OPERATION_ID
    )
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_bytes = journal_path.read_bytes()
    observed_started: list[bool] = []

    def inspect_started() -> None:
        execution = DeployManagerBackendStoragePreflightExecution.from_object(
            json.loads(execution_path.read_text(encoding="utf-8"))
        )
        observed_started.append(
            execution.state
            is DeployManagerBackendStoragePreflightExecutionState.STARTED
        )
        assert execution.manual_recovery_required
        assert not evidence_path.exists()

    runner = ManagerBackendStoragePreflightRunner(inspect_started=inspect_started)
    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert evidence is not None
    assert observed_started == [True]
    assert (
        report.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert (
        execution.record.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION
    )
    assert (
        evidence.record.schema_version
        == ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    )
    assert (
        report.execution_state
        is DeployManagerBackendStoragePreflightExecutionState.SUCCEEDED
    )
    assert (
        report.disposition is ManagerBackendStoragePreflightDisposition.PREPARE_REQUIRED
    )
    assert report.capacity_sufficiency_state == "not-proven"
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
        "deploy_scylla_vms_manager_backend_storage_preflight",
        "password",
        "credential",
    ):
        assert protected not in encoded.lower()

    execution_bytes = execution_path.read_bytes()
    evidence_bytes = evidence_path.read_bytes()
    execution_mtime = execution_path.stat().st_mtime_ns
    evidence_mtime = evidence_path.stat().st_mtime_ns
    reentry_runner = ManagerBackendStoragePreflightRunner()
    reused = _call(prepared, reentry_runner, executables, toolchain)
    assert reused.execution_artifact_state.value == "reused"
    assert reentry_runner.specs == []
    assert execution_path.read_bytes() == execution_bytes
    assert evidence_path.read_bytes() == evidence_bytes
    assert execution_path.stat().st_mtime_ns == execution_mtime
    assert evidence_path.stat().st_mtime_ns == evidence_mtime
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


@pytest.mark.parametrize(
    ("mode", "disposition", "wipe_required"),
    (
        ("owned-noop", ManagerBackendStoragePreflightDisposition.OWNED_NOOP, False),
        ("blocked", ManagerBackendStoragePreflightDisposition.BLOCKED, False),
        ("blocked-wipe", ManagerBackendStoragePreflightDisposition.BLOCKED, True),
    ),
)
def test_bounded_dispositions_are_persisted_without_safety_inference(
    ready_preflight_execution,
    mode: str,
    disposition: ManagerBackendStoragePreflightDisposition,
    wipe_required: bool,
) -> None:
    prepared, executables, toolchain = ready_preflight_execution
    report = _call(
        prepared,
        ManagerBackendStoragePreflightRunner(mode=mode),
        executables,
        toolchain,
    )
    _execution, evidence = _records(prepared)
    assert evidence is not None
    assert report.disposition is disposition
    assert evidence.record.wipe_required is wipe_required
    assert evidence.record.capacity_sufficiency_state == "not-proven"


@pytest.mark.parametrize(
    ("mode", "state"),
    (
        (
            "interrupted",
            DeployManagerBackendStoragePreflightExecutionState.INTERRUPTED,
        ),
        ("timeout", DeployManagerBackendStoragePreflightExecutionState.TIMED_OUT),
        (
            "non-utf8",
            DeployManagerBackendStoragePreflightExecutionState.MALFORMED_RESULT,
        ),
        (
            "oversized-output",
            DeployManagerBackendStoragePreflightExecutionState.MALFORMED_RESULT,
        ),
        (
            "malformed",
            DeployManagerBackendStoragePreflightExecutionState.MALFORMED_RESULT,
        ),
        (
            "wrong-target",
            DeployManagerBackendStoragePreflightExecutionState.MALFORMED_RESULT,
        ),
        ("failed", DeployManagerBackendStoragePreflightExecutionState.FAILED),
        ("unreachable", DeployManagerBackendStoragePreflightExecutionState.UNREACHABLE),
    ),
)
def test_uncertain_or_failed_attempt_is_durable_no_retry(
    ready_preflight_execution,
    mode: str,
    state: DeployManagerBackendStoragePreflightExecutionState,
) -> None:
    prepared, executables, toolchain = ready_preflight_execution
    with pytest.raises(AnsibleError, match="manual recovery required"):
        _call(
            prepared,
            ManagerBackendStoragePreflightRunner(mode=mode),
            executables,
            toolchain,
        )
    execution, evidence = _records(prepared)
    assert execution.record.state is state
    assert execution.record.manual_recovery_required
    assert not execution.record.automatic_retry_allowed
    assert evidence is None
    retry = ManagerBackendStoragePreflightRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, retry, executables, toolchain)
    assert retry.specs == []


def test_post_call_drift_is_no_retry(
    ready_preflight_execution,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = ready_preflight_execution
    inventory_path = prepared.paths.ansible_inventory

    def drift_after_start() -> None:
        inventory_path.write_text("{}\n", encoding="utf-8")
        inventory_path.chmod(0o600)

    with pytest.raises(StateConflictError, match="manual recovery required"):
        _call(
            prepared,
            ManagerBackendStoragePreflightRunner(inspect_started=drift_after_start),
            executables,
            toolchain,
        )
    execution, evidence = _records(prepared)
    assert (
        execution.record.state
        is DeployManagerBackendStoragePreflightExecutionState.DRIFTED
    )
    assert evidence is None


def test_evidence_write_failure_is_no_retry(
    ready_preflight_execution,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = ready_preflight_execution

    def refuse_evidence(*_args, **_kwargs):
        raise StatePersistenceError("simulated evidence failure")

    monkeypatch.setattr(
        DeployManagerBackendStoragePreflightEvidenceStore,
        "write_locked",
        refuse_evidence,
    )
    with pytest.raises(StatePersistenceError, match="evidence persistence failed"):
        _call(
            prepared,
            ManagerBackendStoragePreflightRunner(),
            executables,
            toolchain,
        )
    execution, evidence = _records(prepared)
    assert (
        execution.record.state
        is DeployManagerBackendStoragePreflightExecutionState.STARTED
    )
    assert evidence is None
    retry = ManagerBackendStoragePreflightRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, retry, executables, toolchain)
    assert retry.specs == []


def test_refuses_wrong_lock_ambiguity_and_tamper(
    ready_preflight_execution,
) -> None:
    prepared, executables, toolchain = ready_preflight_execution
    runner = ManagerBackendStoragePreflightRunner()
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        execute_deploy_manager_backend_storage_preflight(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )
    assert runner.specs == []

    ambiguous = prepared.paths.operations / (
        f"{str(OPERATION_ID).upper()}"
        f"{DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_FILENAME_SUFFIX}"
    )
    ambiguous.write_text("{}\n", encoding="utf-8")
    ambiguous.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _call(
            prepared,
            ManagerBackendStoragePreflightRunner(),
            executables,
            toolchain,
        )
    ambiguous.unlink()

    _call(
        prepared,
        ManagerBackendStoragePreflightRunner(),
        executables,
        toolchain,
    )
    execution_path = deploy_manager_backend_storage_preflight_execution_path(
        prepared.paths, OPERATION_ID
    )
    document = json.loads(execution_path.read_text(encoding="utf-8"))
    document["state"] = "started"
    execution_path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    execution_path.chmod(0o600)
    with pytest.raises(StatePersistenceError):
        _call(
            prepared,
            ManagerBackendStoragePreflightRunner(),
            executables,
            toolchain,
        )
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
