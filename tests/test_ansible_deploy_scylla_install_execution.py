import base64
import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_scylla_install_authorization import (
    _call as _authorize,
)
from test_ansible_deploy_scylla_install_authorization import _proof
from test_ansible_deploy_storage_postcheck import (
    StoragePostcheckRunner,
    _prepared_postcheck,
    _reconcile,
)
from test_ansible_deploy_storage_postcheck import _execute as _execute_postcheck
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_scylla_install_execution import (
    ANSIBLE_DEPLOY_SCYLLA_INSTALL_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_SCHEMA_VERSION,
    DeployScyllaInstallArtifactState,
    DeployScyllaInstallEvidenceStore,
    DeployScyllaInstallExecution,
    DeployScyllaInstallExecutionState,
    DeployScyllaInstallExecutionStore,
    deploy_scylla_install_evidence_path,
    deploy_scylla_install_execution_path,
    execute_deploy_scylla_install,
)
from scylla_vms.ansible.scylla_install import (
    SCYLLA_EDITION,
    SCYLLA_INSTALL_SCHEMA_VERSION,
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_PACKAGES,
    SCYLLA_RELEASE_LINE,
    SCYLLA_REPOSITORY_DEFINITION_DIGEST,
    SCYLLA_SIGNING_KEY_DIGEST,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
)
from scylla_vms.ansible.storage_preflight import StorageOwnershipStatus
from scylla_vms.errors import AnsibleError, StateConflictError, StatePersistenceError
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.process import ProcessResult, ProcessSpec, ProcessTimeoutError

_PRIVATE_PATH = "/private/operator/scylla-install-runtime.json"
_SECRET = "obviously-fake-scylla-install-execution-secret"


@dataclass
class ScyllaInstallRunner:
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
        if playbook != "scylla-install":
            raise AssertionError(f"unexpected playbook or external tool: {playbook}")
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        variables = cast(
            dict[str, object], json.loads(runtime_file.read_text(encoding="utf-8"))
        )
        payload = cast(dict[str, object], variables["deploy_scylla_vms_scylla_install"])
        self.payloads.append(payload)
        if self.inspect_started is not None:
            self.inspect_started()
        if self.mode == "timeout":
            raise ProcessTimeoutError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "malformed":
            return ProcessResult(0, "malformed", f"{_SECRET} {_PRIVATE_PATH}")
        status = "installed" if self.mode == "installed" else "no-change"
        changed = status == "installed"
        result = {
            "blockers": [],
            "configuration_performed": False,
            "installed_edition": payload["edition"],
            "installed_version": payload["package_version"],
            "logical_id": payload["logical_id"],
            "manager_operation_performed": False,
            "packages": {name: payload["package_version"] for name in SCYLLA_PACKAGES},
            "provenance": payload["provenance"],
            "repository_digest": cast(dict[str, object], payload["repository"])[
                "definition_digest"
            ],
            "requested_edition": payload["edition"],
            "requested_version": payload["package_version"],
            "schema_version": SCYLLA_INSTALL_SCHEMA_VERSION,
            "service_inactive": True,
            "service_masked": True,
            "service_started": False,
            "signing_key_digest": cast(dict[str, object], payload["signing_key"])[
                "artifact_digest"
            ],
            "signing_key_fingerprint": cast(dict[str, object], payload["signing_key"])[
                "fingerprint"
            ],
            "status": status,
            "storage_mutation_performed": False,
            "tuning_performed": False,
        }
        encoded = base64.b64encode(
            json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        logical_id = cast(str, payload["logical_id"])
        stdout = (
            f'ok: [{logical_id}] => {{"msg":"DSV_SCYLLA_INSTALL_B64={encoded}"}}\n'
            "PLAY RECAP *****\n"
            f"{logical_id} : ok=12 changed={int(changed)} unreachable=0 failed=0 "
            "skipped=0 rescued=0 ignored=0\n"
        )
        return ProcessResult(0, stdout, f"{_SECRET} {_PRIVATE_PATH}")


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, executables, toolchain = _prepared_postcheck(
        tmp_path,
        monkeypatch,
        StorageOwnershipStatus.CLEAN_NEW,
    )
    _execute_postcheck(
        prepared,
        StoragePostcheckRunner(),
        executables,
        toolchain,
    )
    _reconcile(prepared)
    _authorize(prepared, _proof())
    return prepared, executables, toolchain


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_scylla_install(
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
        execution = DeployScyllaInstallExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployScyllaInstallEvidenceStore(prepared.paths, OPERATION_ID)
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


def test_exact_scope_prepared_recovery_success_and_zero_call_reentry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(inspect.signature(execute_deploy_scylla_install).parameters) == (
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
        f"{OPERATION_ID}.ansible-deploy-scylla-install-authorization.json"
    )
    reconciliation_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-post-storage-postcheck-reconciliation.json"
    )
    immutable = (
        journal_path.read_bytes(),
        authorization_path.read_bytes(),
        reconciliation_path.read_bytes(),
    )
    show_before = _run_show(prepared.paths)

    original_write = DeployScyllaInstallExecutionStore.write_locked
    refused = False

    def fail_started(self, record, **kwargs):
        nonlocal refused
        if record.state is DeployScyllaInstallExecutionState.STARTED and not refused:
            refused = True
            raise StatePersistenceError("simulated safe pre-invocation refusal")
        return original_write(self, record, **kwargs)

    monkeypatch.setattr(DeployScyllaInstallExecutionStore, "write_locked", fail_started)
    first = ScyllaInstallRunner()
    with pytest.raises(StatePersistenceError, match="before invocation"):
        _call(prepared, first, executables, toolchain)
    prepared_execution, evidence = _records(prepared)
    assert prepared_execution.record.state is DeployScyllaInstallExecutionState.PREPARED
    assert not prepared_execution.record.authorization_consumed
    assert prepared_execution.record.invocation_count == 0
    assert evidence is None
    assert first.specs is not None and len(first.specs) == 2

    monkeypatch.setattr(
        DeployScyllaInstallExecutionStore, "write_locked", original_write
    )
    observed: list[DeployScyllaInstallExecutionState] = []

    def inspect_started() -> None:
        value = json.loads(
            deploy_scylla_install_execution_path(
                prepared.paths, OPERATION_ID
            ).read_text(encoding="utf-8")
        )
        record = DeployScyllaInstallExecution.from_object(value)
        observed.append(record.state)
        assert record.authorization_consumed
        assert record.invocation_count == 1
        assert record.attempts[0].authorization_consumed_at_start

    runner = ScyllaInstallRunner(mode="installed", inspect_started=inspect_started)
    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert evidence is not None
    assert observed == [DeployScyllaInstallExecutionState.STARTED]
    assert report.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert execution.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_SCHEMA_VERSION
    )
    assert evidence.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_INSTALL_EVIDENCE_SCHEMA_VERSION
    )
    assert report.execution_state is DeployScyllaInstallExecutionState.SUCCEEDED
    assert report.execution_artifact_state is DeployScyllaInstallArtifactState.UPDATED
    assert report.evidence_artifact_state is DeployScyllaInstallArtifactState.CREATED
    assert report.authorization_consumed
    assert report.invocation_count == report.scope_count == report.stable_id_count == 1
    assert report.installed_count == report.changed_count == 1
    assert report.package_version == SCYLLA_PACKAGE_VERSION
    assert report.package_count == len(SCYLLA_PACKAGES)
    assert report.repository_definition_digest == SCYLLA_REPOSITORY_DEFINITION_DIGEST
    assert report.signing_key_artifact_digest == SCYLLA_SIGNING_KEY_DIGEST
    assert report.service_safe_count == 1
    assert report.prohibited_action_count == 0
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert not report.journal_updated
    assert not report.automatic_retry_allowed
    assert not report.skip_allowed
    assert not report.continue_allowed
    assert not report.rollback_performed
    assert (
        journal_path.read_bytes(),
        authorization_path.read_bytes(),
        reconciliation_path.read_bytes(),
    ) == immutable

    assert runner.specs is not None and len(runner.specs) == 3
    assert runner.payloads is not None and len(runner.payloads) == 1
    payload = runner.payloads[0]
    assert payload["release_line"] == SCYLLA_RELEASE_LINE == "2026.2"
    assert payload["edition"] == SCYLLA_EDITION
    assert payload["package_version"] == SCYLLA_PACKAGE_VERSION
    assert payload["packages"] == list(SCYLLA_PACKAGES)
    assert (
        cast(dict[str, object], payload["repository"])["definition_digest"]
        == SCYLLA_REPOSITORY_DEFINITION_DIGEST
    )
    assert (
        cast(dict[str, object], payload["signing_key"])["artifact_digest"]
        == SCYLLA_SIGNING_KEY_DIGEST
    )
    entry = evidence.record.entries[0]
    assert entry.stable_id == "scylla-ad-1-1"
    assert entry.installed and entry.changed
    assert entry.service_masked and entry.service_inactive
    assert not entry.configuration_performed
    assert not entry.storage_mutation_performed
    assert not entry.tuning_performed
    assert not entry.manager_operation_performed
    assert not entry.service_started
    assert _run_show(prepared.paths) == show_before

    for path in (
        deploy_scylla_install_execution_path(prepared.paths, OPERATION_ID),
        deploy_scylla_install_evidence_path(prepared.paths, OPERATION_ID),
    ):
        assert path.stat().st_mode & 0o777 == 0o600
    persisted = (
        deploy_scylla_install_execution_path(prepared.paths, OPERATION_ID).read_text(
            encoding="utf-8"
        )
        + deploy_scylla_install_evidence_path(prepared.paths, OPERATION_ID).read_text(
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
        "BEGIN PGP",
        "downloads.scylladb.com",
        SCYLLA_SIGNING_KEY_FINGERPRINT,
        "PLAY RECAP",
        "DSV_SCYLLA_INSTALL_B64",
        "ansible-playbook",
        "--limit",
    ):
        assert protected not in persisted

    zero_runner = ScyllaInstallRunner(mode="timeout")
    reused = _call(prepared, zero_runner, executables, toolchain)
    assert zero_runner.specs == []
    assert reused.execution_artifact_state is DeployScyllaInstallArtifactState.REUSED
    assert reused.evidence_artifact_state is DeployScyllaInstallArtifactState.REUSED
    assert (
        reused.to_object()
        | {
            "execution": {
                **cast(dict[str, object], reused.to_object()["execution"]),
                "artifact_state": report.execution_artifact_state.value,
            },
            "evidence": {
                **cast(dict[str, object], reused.to_object()["evidence"]),
                "artifact_state": report.evidence_artifact_state.value,
            },
        }
        == report.to_object()
    )


@pytest.mark.parametrize("mode", ("malformed", "timeout"))
def test_uncertain_invocation_is_permanent_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = ScyllaInstallRunner(mode=mode)
    with pytest.raises(AnsibleError, match="manual recovery") as caught:
        _call(prepared, runner, executables, toolchain)
    assert _PRIVATE_PATH not in str(caught.value)
    assert _SECRET not in str(caught.value)
    execution, evidence = _records(prepared)
    expected = (
        DeployScyllaInstallExecutionState.TIMED_OUT
        if mode == "timeout"
        else DeployScyllaInstallExecutionState.MALFORMED_RESULT
    )
    assert execution.record.state is expected
    assert execution.record.authorization_consumed
    assert execution.record.manual_recovery_required
    assert not execution.record.attempts[-1].automatic_retry_allowed
    assert evidence is None

    no_retry = ScyllaInstallRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []
