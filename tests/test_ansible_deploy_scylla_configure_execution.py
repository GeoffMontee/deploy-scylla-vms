import base64
import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_scylla_configure_authorization import (
    _call as _authorize_configure,
)
from test_ansible_deploy_scylla_configure_authorization import _proof
from test_ansible_deploy_scylla_install_execution import (
    ScyllaInstallRunner,
)
from test_ansible_deploy_scylla_install_execution import (
    _call as _execute_install,
)
from test_ansible_deploy_scylla_install_execution import (
    _prepared as _prepared_install,
)
from test_ansible_deploy_scylla_install_reconciliation import (
    _call as _reconcile_install,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_scylla_configure_execution import (
    ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_SCHEMA_VERSION,
    DeployScyllaConfigureArtifactState,
    DeployScyllaConfigureEvidenceStore,
    DeployScyllaConfigureExecution,
    DeployScyllaConfigureExecutionState,
    DeployScyllaConfigureExecutionStore,
    deploy_scylla_configure_evidence_path,
    deploy_scylla_configure_execution_path,
    execute_deploy_scylla_configure,
)
from scylla_vms.ansible.scylla_configure import SCYLLA_CONFIGURE_SCHEMA_VERSION
from scylla_vms.ansible.scylla_install import (
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_RELEASE_LINE,
)
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.process import ProcessResult, ProcessSpec, ProcessTimeoutError

_PRIVATE_PATH = "/private/operator/scylla-configure-runtime.json"
_SECRET = "obviously-fake-scylla-configure-execution-secret"


@dataclass
class ScyllaConfigureRunner:
    mode: str = "noop"
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
        if playbook != "scylla-configure":
            raise AssertionError(f"unexpected playbook or external tool: {playbook}")
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        variables = cast(
            dict[str, object], json.loads(runtime_file.read_text(encoding="utf-8"))
        )
        payload = cast(
            dict[str, object], variables["deploy_scylla_vms_scylla_configure"]
        )
        self.payloads.append(payload)
        if self.inspect_started is not None:
            self.inspect_started()
        if self.mode == "timeout":
            raise ProcessTimeoutError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "malformed":
            return ProcessResult(0, "malformed", f"{_SECRET} {_PRIVATE_PATH}")

        failed = self.mode in {"failed", "service-active", "wrong-config"}
        blockers = (
            ["service-active"]
            if self.mode == "service-active"
            else ["execution-failed"]
            if failed
            else []
        )
        status = (
            "failed"
            if failed
            else "noop"
            if self.mode in {"prohibited", "wrong-files", "wrong-mode"}
            else self.mode
        )
        config_digest = (
            "sha256:" + "b" * 64
            if self.mode == "wrong-config"
            else payload["config_digest"]
        )
        file_digests = (
            {} if failed else dict(cast(dict[str, str], payload["file_digests"]))
        )
        if self.mode == "wrong-files":
            file_digests["unexpected.yaml"] = "sha256:" + "b" * 64
        result = {
            "blockers": blockers,
            "bootstrap_performed": False,
            "config_digest": config_digest,
            "configuration_file_digests": file_digests,
            "files_mode_0644": None if failed else self.mode != "wrong-mode",
            "files_root_owned": None if failed else True,
            "firewall_operation_performed": False,
            "installed_version": None if failed else payload["package_version"],
            "logical_id": payload["logical_id"],
            "manager_operation_performed": False,
            "package_install_performed": self.mode == "prohibited",
            "prerequisite_digests": payload["provenance"],
            "runtime_validation_performed": False,
            "schema_version": SCYLLA_CONFIGURE_SCHEMA_VERSION,
            "seed_digest": payload["seed_digest"],
            "service_inactive": None if failed else True,
            "service_masked": None if failed else True,
            "service_started": False,
            "ssh_operation_performed": False,
            "status": status,
            "storage_mutation_performed": False,
            "topology_digest": payload["topology_digest"],
            "tuning_performed": False,
        }
        encoded = base64.b64encode(
            json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        logical_id = cast(str, payload["logical_id"])
        changed = status == "changed"
        stdout = (
            f"ok: [{logical_id}] => "
            f'{{"msg":"DSV_SCYLLA_CONFIGURE_B64={encoded}"}}\n'
            "PLAY RECAP *****\n"
            f"{logical_id} : ok=12 changed={int(changed)} unreachable=0 "
            f"failed={int(failed)} skipped=0 rescued=0 ignored=0\n"
        )
        return ProcessResult(2 if failed else 0, stdout, f"{_SECRET} {_PRIVATE_PATH}")


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, executables, toolchain = _prepared_install(tmp_path, monkeypatch)
    _execute_install(
        prepared,
        ScyllaInstallRunner(),
        executables,
        toolchain,
    )
    _reconcile_install(prepared)
    _authorize_configure(prepared, _proof())
    return prepared, executables, toolchain


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_scylla_configure(
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
        execution = DeployScyllaConfigureExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployScyllaConfigureEvidenceStore(
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


@pytest.mark.parametrize(("mode", "changed"), (("changed", True), ("noop", False)))
def test_exact_scope_success_evidence_redaction_and_zero_call_reentry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    changed: bool,
) -> None:
    assert tuple(inspect.signature(execute_deploy_scylla_configure).parameters) == (
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
        f"{OPERATION_ID}.ansible-deploy-scylla-configure-authorization.json"
    )
    immutable = (journal_path.read_bytes(), authorization_path.read_bytes())
    show_before = _run_show(prepared.paths)
    observed: list[DeployScyllaConfigureExecutionState] = []

    def inspect_started() -> None:
        record = DeployScyllaConfigureExecution.from_object(
            json.loads(
                deploy_scylla_configure_execution_path(
                    prepared.paths, OPERATION_ID
                ).read_text(encoding="utf-8")
            )
        )
        observed.append(record.state)
        assert record.authorization_consumed
        assert record.invocation_count == 1

    runner = ScyllaConfigureRunner(mode=mode, inspect_started=inspect_started)
    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert evidence is not None
    assert observed == [DeployScyllaConfigureExecutionState.STARTED]
    assert report.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert execution.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_SCHEMA_VERSION
    )
    assert evidence.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_SCHEMA_VERSION
    )
    assert report.execution_state is DeployScyllaConfigureExecutionState.SUCCEEDED
    assert report.execution_artifact_state is DeployScyllaConfigureArtifactState.UPDATED
    assert report.evidence_artifact_state is DeployScyllaConfigureArtifactState.CREATED
    assert report.authorization_consumed
    assert report.invocation_count == report.scope_count == 1
    assert report.configured_count == 1
    assert report.changed_count == int(changed)
    assert report.configuration_file_count == 2
    assert report.service_safe_count == 1
    assert report.prohibited_action_count == 0
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert not report.journal_updated
    assert report.reconciliation_state == "not-performed"
    assert report.bootstrap_state == "not-performed"
    assert not report.automatic_retry_allowed
    assert not report.skip_allowed
    assert not report.continue_allowed
    assert not report.rollback_performed
    assert (journal_path.read_bytes(), authorization_path.read_bytes()) == immutable
    assert _run_show(prepared.paths) == show_before

    assert runner.specs is not None and len(runner.specs) == 3
    assert runner.payloads is not None and len(runner.payloads) == 1
    payload = runner.payloads[0]
    assert payload["release_line"] == SCYLLA_RELEASE_LINE == "2026.2"
    assert payload["package_version"] == SCYLLA_PACKAGE_VERSION
    assert set(cast(dict[str, str], payload["file_digests"])) == {
        "cassandra-rackdc.properties",
        "scylla.yaml",
    }
    entry = evidence.record.entries[0]
    assert entry.stable_id == "scylla-ad-1-1"
    assert entry.configured and entry.changed is changed
    assert entry.configuration_file_count == 2
    assert entry.files_root_owned and entry.files_mode_0644
    assert entry.seed_count == 1 and entry.directory_count == 4
    assert entry.template_count == 2
    assert entry.service_masked and entry.service_inactive
    assert not entry.runtime_validation_performed
    assert not any(
        (
            entry.package_install_performed,
            entry.storage_mutation_performed,
            entry.tuning_performed,
            entry.firewall_operation_performed,
            entry.ssh_operation_performed,
            entry.manager_operation_performed,
            entry.service_started,
            entry.bootstrap_performed,
        )
    )
    for path in (
        deploy_scylla_configure_execution_path(prepared.paths, OPERATION_ID),
        deploy_scylla_configure_evidence_path(prepared.paths, OPERATION_ID),
    ):
        assert path.stat().st_mode & 0o777 == 0o600
    persisted = (
        deploy_scylla_configure_execution_path(prepared.paths, OPERATION_ID).read_text(
            encoding="utf-8"
        )
        + deploy_scylla_configure_evidence_path(prepared.paths, OPERATION_ID).read_text(
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
        "SimpleSeedProvider",
        "/var/lib/scylla",
        "/etc/scylla",
        "ansible-playbook",
        "--limit",
        '"seed_stable_ids"',
        '"config"',
    ):
        assert protected not in persisted

    zero_runner = ScyllaConfigureRunner(mode="timeout")
    reused = _call(prepared, zero_runner, executables, toolchain)
    assert zero_runner.specs == []
    assert reused.execution_artifact_state is DeployScyllaConfigureArtifactState.REUSED
    assert reused.evidence_artifact_state is DeployScyllaConfigureArtifactState.REUSED


def test_prepared_prefix_resumes_without_consuming_before_started(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    original_write = DeployScyllaConfigureExecutionStore.write_locked
    refused = False

    def fail_started(self, record, **kwargs):
        nonlocal refused
        if record.state is DeployScyllaConfigureExecutionState.STARTED and not refused:
            refused = True
            raise StatePersistenceError("simulated safe pre-invocation refusal")
        return original_write(self, record, **kwargs)

    monkeypatch.setattr(
        DeployScyllaConfigureExecutionStore, "write_locked", fail_started
    )
    first = ScyllaConfigureRunner()
    with pytest.raises(StatePersistenceError, match="before invocation"):
        _call(prepared, first, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployScyllaConfigureExecutionState.PREPARED
    assert not execution.record.authorization_consumed
    assert execution.record.invocation_count == 0
    assert evidence is None
    assert first.specs is not None and len(first.specs) == 2

    monkeypatch.setattr(
        DeployScyllaConfigureExecutionStore, "write_locked", original_write
    )
    runner = ScyllaConfigureRunner()
    report = _call(prepared, runner, executables, toolchain)
    assert report.execution_state is DeployScyllaConfigureExecutionState.SUCCEEDED
    assert runner.specs is not None and len(runner.specs) == 3


@pytest.mark.parametrize(
    ("mode", "state"),
    (
        ("malformed", DeployScyllaConfigureExecutionState.MALFORMED_RESULT),
        ("timeout", DeployScyllaConfigureExecutionState.TIMED_OUT),
        ("failed", DeployScyllaConfigureExecutionState.FAILED),
        ("service-active", DeployScyllaConfigureExecutionState.FAILED),
        ("wrong-config", DeployScyllaConfigureExecutionState.MALFORMED_RESULT),
        ("wrong-files", DeployScyllaConfigureExecutionState.MALFORMED_RESULT),
        ("wrong-mode", DeployScyllaConfigureExecutionState.MALFORMED_RESULT),
        ("prohibited", DeployScyllaConfigureExecutionState.MALFORMED_RESULT),
    ),
)
def test_malformed_failure_timeout_and_scope_conflicts_are_permanent_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    state: DeployScyllaConfigureExecutionState,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = ScyllaConfigureRunner(mode=mode)
    with pytest.raises(AnsibleError, match="manual recovery") as caught:
        _call(prepared, runner, executables, toolchain)
    assert _PRIVATE_PATH not in str(caught.value)
    assert _SECRET not in str(caught.value)
    execution, evidence = _records(prepared)
    assert execution.record.state is state
    assert execution.record.authorization_consumed
    assert execution.record.manual_recovery_required
    assert not execution.record.attempts[-1].automatic_retry_allowed
    assert evidence is None

    no_retry = ScyllaConfigureRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_evidence_persistence_failure_leaves_started_and_forbids_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)

    def fail_evidence(*_args, **_kwargs):
        raise StatePersistenceError("simulated evidence persistence failure")

    monkeypatch.setattr(
        DeployScyllaConfigureEvidenceStore, "append_locked", fail_evidence
    )
    with pytest.raises(StatePersistenceError, match="manual recovery"):
        _call(prepared, ScyllaConfigureRunner(), executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployScyllaConfigureExecutionState.STARTED
    assert execution.record.authorization_consumed
    assert execution.record.manual_recovery_required
    assert evidence is None

    runner = ScyllaConfigureRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []


def test_refuses_authorization_drift_wrong_lock_and_unsafe_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    authorization = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-scylla-configure-authorization.json"
    )
    original = authorization.read_bytes()
    document = cast(dict[str, object], json.loads(original))
    document["target_count"] = 2
    authorization.write_text(json.dumps(document) + "\n", encoding="utf-8")
    authorization.chmod(0o600)
    runner = ScyllaConfigureRunner()
    with pytest.raises(StatePersistenceError):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
    authorization.write_bytes(original)
    authorization.chmod(0o600)

    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError, match="matching operation"),
    ):
        execute_deploy_scylla_configure(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )

    path = deploy_scylla_configure_execution_path(prepared.paths, OPERATION_ID)
    target = path.with_name(f"{path.name}.target")
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
