import base64
import inspect
import json
import shutil
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_manager_backend_local_install_authorization import (
    _call as _authorize,
)
from test_ansible_deploy_manager_backend_local_install_authorization import (
    _proof,
)
from test_ansible_deploy_manager_backend_preflight_execution import (
    ManagerBackendPreflightRunner,
)
from test_ansible_deploy_manager_backend_preflight_execution import (
    _call as _execute_preflight,
)
from test_ansible_deploy_manager_backend_preflight_execution import (
    _prepared as _prepare_preflight_execution,
)
from test_ansible_deploy_manager_backend_preflight_reconciliation import (
    _call as _reconcile_preflight,
)
from test_ansible_manager_backend_local_install import _result
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_manager_backend_installation_plan as installation_module
import scylla_vms.ansible.deploy_manager_backend_local_install_authorization as authorization_module
import scylla_vms.ansible.deploy_manager_backend_local_install_execution as execution_module
import scylla_vms.ansible.manager_backend_local_install as local_install_module
from scylla_vms.ansible.deploy_manager_backend_installation_plan import (
    plan_deploy_manager_backend_local_installation,
)
from scylla_vms.ansible.deploy_manager_backend_local_install_authorization import (
    deploy_manager_backend_local_install_authorization_path,
)
from scylla_vms.ansible.deploy_manager_backend_local_install_execution import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_SCHEMA_VERSION,
    DeployManagerBackendLocalInstallArtifactState,
    DeployManagerBackendLocalInstallEvidenceStore,
    DeployManagerBackendLocalInstallExecution,
    DeployManagerBackendLocalInstallExecutionState,
    DeployManagerBackendLocalInstallExecutionStore,
    deploy_manager_backend_local_install_evidence_id_from_filename,
    deploy_manager_backend_local_install_evidence_path,
    deploy_manager_backend_local_install_execution_id_from_filename,
    deploy_manager_backend_local_install_execution_path,
    execute_deploy_manager_backend_local_install,
)
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_install import (
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_PACKAGES,
    SCYLLA_RELEASE_LINE,
    SCYLLA_REPOSITORY_DEFINITION_DIGEST,
    SCYLLA_REPOSITORY_URI,
    SCYLLA_SIGNING_KEY_DIGEST,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
)
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.errors import AnsibleError, StateConflictError, StatePersistenceError
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.process import (
    ProcessOutputError,
    ProcessResult,
    ProcessSpec,
    ProcessTimeoutError,
)

_PRIVATE_PATH = "/private/operator/manager-backend-local-install-runtime.json"
_SECRET = "obviously-fake-manager-backend-local-install-execution-secret"


@pytest.fixture(scope="module")
def execution_baseline(tmp_path_factory: pytest.TempPathFactory):
    monkeypatch = pytest.MonkeyPatch()
    root = tmp_path_factory.mktemp("manager-backend-local-install-execution")
    foundation = root / "foundation"
    foundation.mkdir()
    prepared, executables, toolchain = _prepare_preflight_execution(
        foundation,
        monkeypatch,
    )
    _execute_preflight(
        prepared,
        ManagerBackendPreflightRunner(),
        executables,
        toolchain,
    )
    _reconcile_preflight(prepared)
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        plan_deploy_manager_backend_local_installation(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )
    snapshot = root / "ready-snapshot"
    shutil.copytree(prepared.paths.state_root, snapshot)
    yield prepared, executables, toolchain, snapshot
    monkeypatch.undo()


@pytest.fixture
def ready_execution(execution_baseline, monkeypatch: pytest.MonkeyPatch):
    prepared, executables, toolchain, snapshot = execution_baseline
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
    _authorize(prepared, _proof())
    return prepared, executables, toolchain


@dataclass
class ManagerBackendLocalInstallRunner:
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
        if playbook != "manager-backend-local-install":
            raise AssertionError(f"unexpected playbook or external tool: {playbook}")
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        variables = cast(
            dict[str, object],
            json.loads(runtime_file.read_text(encoding="utf-8")),
        )
        payload = cast(
            dict[str, object],
            variables["deploy_scylla_vms_manager_backend_local_install"],
        )
        self.payloads.append(payload)
        if self.inspect_started is not None:
            self.inspect_started()
        if self.mode == "timeout":
            raise ProcessTimeoutError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "non-utf8":
            raise ProcessOutputError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "oversized":
            return ProcessResult(0, "x" * (512 * 1024 + 1), _SECRET)
        if self.mode == "malformed":
            return ProcessResult(0, "malformed", f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "unreachable":
            logical_id = cast(str, payload["logical_id"])
            return ProcessResult(
                4,
                "PLAY RECAP *****\n"
                f"{logical_id} : ok=0 changed=0 unreachable=1 failed=0 "
                "skipped=0 rescued=0 ignored=0\n",
                f"{_SECRET} {_PRIVATE_PATH}",
            )

        status = "failed" if self.mode == "failed" else self.mode
        if status not in {"failed", "installed", "no-change"}:
            status = "no-change"
        value = _result(payload, status)
        if self.mode == "wrong-target":
            value["logical_id"] = "manager-2"
        if self.mode == "forbidden-action":
            value["scylla_setup_performed"] = True
        encoded = base64.b64encode(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        changed = int(status == "installed")
        failed = int(status == "failed")
        logical_id = cast(str, payload["logical_id"])
        return ProcessResult(
            2 if failed else 0,
            f"ok: [{logical_id}] => "
            f'{{"msg":"DSV_MANAGER_BACKEND_LOCAL_INSTALL_B64={encoded}"}}\n'
            "PLAY RECAP *****\n"
            f"{logical_id} : ok=14 changed={changed} unreachable=0 "
            f"failed={failed} skipped=0 rescued=0 ignored=0\n",
            f"{_SECRET} {_PRIVATE_PATH}",
        )


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_manager_backend_local_install(
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
        execution = DeployManagerBackendLocalInstallExecutionStore(
            prepared.paths,
            OPERATION_ID,
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployManagerBackendLocalInstallEvidenceStore(
            prepared.paths,
            OPERATION_ID,
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


def test_prepared_resume_success_policy_redaction_and_zero_process_reentry(
    ready_execution,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(
        inspect.signature(execute_deploy_manager_backend_local_install).parameters
    ) == (
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
        "package",
        "version",
        "repository",
        "key",
        "command",
        "variable",
        "path",
        "result",
        "retry",
    ):
        assert (
            forbidden
            not in inspect.signature(
                execute_deploy_manager_backend_local_install
            ).parameters
        )

    prepared, executables, toolchain = ready_execution
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    authorization_path = deploy_manager_backend_local_install_authorization_path(
        prepared.paths,
        OPERATION_ID,
    )
    installation_plan_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-manager-backend-installation-plan.json"
    )
    immutable = (
        journal_path.read_bytes(),
        authorization_path.read_bytes(),
        installation_plan_path.read_bytes(),
    )

    original_write = DeployManagerBackendLocalInstallExecutionStore.write_locked
    refused = False

    def fail_started(self, record, **kwargs):
        nonlocal refused
        if (
            record.state is DeployManagerBackendLocalInstallExecutionState.STARTED
            and not refused
        ):
            refused = True
            raise StatePersistenceError("simulated safe pre-invocation refusal")
        return original_write(self, record, **kwargs)

    monkeypatch.setattr(
        DeployManagerBackendLocalInstallExecutionStore,
        "write_locked",
        fail_started,
    )
    first = ManagerBackendLocalInstallRunner()
    with pytest.raises(StatePersistenceError, match="before invocation"):
        _call(prepared, first, executables, toolchain)
    execution, evidence = _records(prepared)
    assert (
        execution.record.state
        is DeployManagerBackendLocalInstallExecutionState.PREPARED
    )
    assert not execution.record.authorization_consumed
    assert execution.record.invocation_count == 0
    assert evidence is None
    assert first.specs is not None and len(first.specs) == 2

    monkeypatch.setattr(
        DeployManagerBackendLocalInstallExecutionStore,
        "write_locked",
        original_write,
    )
    observed: list[DeployManagerBackendLocalInstallExecutionState] = []

    def inspect_started() -> None:
        document = json.loads(
            deploy_manager_backend_local_install_execution_path(
                prepared.paths,
                OPERATION_ID,
            ).read_text(encoding="utf-8")
        )
        record = DeployManagerBackendLocalInstallExecution.from_object(document)
        observed.append(record.state)
        assert record.authorization_consumed
        assert record.invocation_count == 1

    runner = ManagerBackendLocalInstallRunner(
        mode="installed",
        inspect_started=inspect_started,
    )
    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert evidence is not None
    assert observed == [DeployManagerBackendLocalInstallExecutionState.STARTED]
    assert execution.record.schema_version == (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_SCHEMA_VERSION
    )
    assert evidence.record.schema_version == (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_SCHEMA_VERSION
    )
    assert report.schema_version == (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert (
        report.execution_state
        is DeployManagerBackendLocalInstallExecutionState.SUCCEEDED
    )
    assert (
        report.execution_artifact_state
        is DeployManagerBackendLocalInstallArtifactState.UPDATED
    )
    assert (
        report.evidence_artifact_state
        is DeployManagerBackendLocalInstallArtifactState.CREATED
    )
    assert report.authorization_consumed
    assert report.invocation_count == report.installed_count == 1
    assert report.changed_count == 1
    assert report.target_stable_id == "manager-1"
    assert report.release_line == SCYLLA_RELEASE_LINE == "2026.2"
    assert report.package_count == len(SCYLLA_PACKAGES)
    assert report.repository_definition_digest == SCYLLA_REPOSITORY_DEFINITION_DIGEST
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
        installation_plan_path.read_bytes(),
    ) == immutable

    assert runner.specs is not None and len(runner.specs) == 3
    assert runner.payloads is not None and len(runner.payloads) == 1
    payload = runner.payloads[0]
    assert payload["logical_id"] == "manager-1"
    assert payload["package_version"] == SCYLLA_PACKAGE_VERSION
    assert payload["packages"] == list(SCYLLA_PACKAGES)
    definition = get_playbook("manager-backend-local-install")
    assert definition.classification is OperationClassification.MUTATING
    assert definition.serial == 1
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.check_mode is CheckMode.PREVIEW
    assert definition.any_errors_fatal
    assert "--check" not in runner.specs[-1].argv
    assert runner.specs[-1].argv[runner.specs[-1].argv.index("--tags") + 1] == (
        ",".join(definition.tags)
    )
    assert runner.specs[-1].argv[runner.specs[-1].argv.index("--limit") + 1] == (
        "manager-1"
    )
    entry = evidence.record.entries[0]
    assert entry.stable_id == "manager-1"
    assert entry.installed and entry.changed
    assert entry.service_masked and entry.service_inactive
    assert entry.prohibited_action_count == 0
    assert entry.storage_decision_digest == report.storage_decision_digest

    execution_path = deploy_manager_backend_local_install_execution_path(
        prepared.paths,
        OPERATION_ID,
    )
    evidence_path = deploy_manager_backend_local_install_evidence_path(
        prepared.paths,
        OPERATION_ID,
    )
    assert execution_path.stat().st_mode & 0o777 == 0o600
    assert evidence_path.stat().st_mode & 0o777 == 0o600
    persisted = (
        execution_path.read_text(encoding="utf-8")
        + evidence_path.read_text(encoding="utf-8")
        + json.dumps(report.to_object(), sort_keys=True)
    )
    for protected in (
        _PRIVATE_PATH,
        _SECRET,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "/dev/",
        SCYLLA_REPOSITORY_URI,
        SCYLLA_SIGNING_KEY_FINGERPRINT,
        SCYLLA_PACKAGE_VERSION,
        "BEGIN PGP",
        "PLAY RECAP",
        "DSV_MANAGER_BACKEND_LOCAL_INSTALL_B64",
        "ansible-playbook",
        "--limit",
        '"variables"',
        '"commands"',
    ):
        assert protected not in persisted
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0

    execution_bytes = execution_path.read_bytes()
    evidence_bytes = evidence_path.read_bytes()
    execution_mtime = execution_path.stat().st_mtime_ns
    evidence_mtime = evidence_path.stat().st_mtime_ns
    zero_runner = ManagerBackendLocalInstallRunner(mode="timeout")
    reused = _call(prepared, zero_runner, executables, toolchain)
    assert zero_runner.specs == []
    assert (
        reused.execution_artifact_state
        is DeployManagerBackendLocalInstallArtifactState.REUSED
    )
    assert (
        reused.evidence_artifact_state
        is DeployManagerBackendLocalInstallArtifactState.REUSED
    )
    assert execution_path.read_bytes() == execution_bytes
    assert evidence_path.read_bytes() == evidence_bytes
    assert execution_path.stat().st_mtime_ns == execution_mtime
    assert evidence_path.stat().st_mtime_ns == evidence_mtime
    assert (
        deploy_manager_backend_local_install_execution_id_from_filename(
            execution_path.name
        )
        == OPERATION_ID
    )
    assert (
        deploy_manager_backend_local_install_evidence_id_from_filename(
            evidence_path.name
        )
        == OPERATION_ID
    )


@pytest.mark.parametrize(
    ("mode", "expected"),
    (
        ("timeout", DeployManagerBackendLocalInstallExecutionState.TIMED_OUT),
        ("non-utf8", DeployManagerBackendLocalInstallExecutionState.MALFORMED_RESULT),
        ("oversized", DeployManagerBackendLocalInstallExecutionState.MALFORMED_RESULT),
        ("malformed", DeployManagerBackendLocalInstallExecutionState.MALFORMED_RESULT),
        (
            "wrong-target",
            DeployManagerBackendLocalInstallExecutionState.MALFORMED_RESULT,
        ),
        (
            "forbidden-action",
            DeployManagerBackendLocalInstallExecutionState.MALFORMED_RESULT,
        ),
        ("failed", DeployManagerBackendLocalInstallExecutionState.FAILED),
        ("unreachable", DeployManagerBackendLocalInstallExecutionState.UNREACHABLE),
    ),
)
def test_started_failure_is_permanent_no_retry(
    ready_execution,
    mode: str,
    expected: DeployManagerBackendLocalInstallExecutionState,
) -> None:
    prepared, executables, toolchain = ready_execution
    runner = ManagerBackendLocalInstallRunner(mode=mode)
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

    retry = ManagerBackendLocalInstallRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, retry, executables, toolchain)
    assert retry.specs == []


def test_evidence_persistence_failure_leaves_started_and_forbids_retry(
    ready_execution,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = ready_execution

    def fail_evidence(self, record, **kwargs):
        raise StatePersistenceError("simulated evidence failure")

    monkeypatch.setattr(
        DeployManagerBackendLocalInstallEvidenceStore,
        "write_locked",
        fail_evidence,
    )
    runner = ManagerBackendLocalInstallRunner()
    with pytest.raises(StatePersistenceError, match="evidence persistence failed"):
        _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert (
        execution.record.state is DeployManagerBackendLocalInstallExecutionState.STARTED
    )
    assert execution.record.manual_recovery_required
    assert evidence is None

    retry = ManagerBackendLocalInstallRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, retry, executables, toolchain)
    assert retry.specs == []


def test_post_call_drift_is_durable_manual_recovery(ready_execution) -> None:
    prepared, executables, toolchain = ready_execution
    inventory_path = prepared.paths.ansible_inventory

    def drift() -> None:
        with inventory_path.open("ab") as stream:
            stream.write(b" ")

    runner = ManagerBackendLocalInstallRunner(inspect_started=drift)
    with pytest.raises(StateConflictError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert (
        execution.record.state is DeployManagerBackendLocalInstallExecutionState.DRIFTED
    )
    assert execution.record.manual_recovery_required
    assert evidence is None


def test_refuses_source_policy_drift_and_show_validates_tamper(
    ready_execution,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = ready_execution
    source = load_ansible_source_bundle()
    monkeypatch.setattr(
        local_install_module,
        "load_ansible_source_bundle",
        lambda: replace(source, digest="sha256:" + "0" * 64),
    )
    runner = ManagerBackendLocalInstallRunner()
    with pytest.raises(StateConflictError, match="source"):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []

    monkeypatch.setattr(
        local_install_module,
        "load_ansible_source_bundle",
        lambda: source,
    )
    definition = get_playbook("manager-backend-local-install")
    monkeypatch.setattr(
        execution_module,
        "get_playbook",
        lambda name: (
            replace(definition, serial=2)
            if name == "manager-backend-local-install"
            else get_playbook(name)
        ),
    )
    with pytest.raises(StateConflictError, match="policy conflicts"):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []

    monkeypatch.setattr(execution_module, "get_playbook", get_playbook)
    _call(
        prepared,
        ManagerBackendLocalInstallRunner(),
        executables,
        toolchain,
    )
    execution_path = deploy_manager_backend_local_install_execution_path(
        prepared.paths,
        OPERATION_ID,
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
