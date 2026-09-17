import base64
import inspect
import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import pytest
from test_ansible_deploy_jump_host_authorization import (
    _call as _authorize_jump_host,
)
from test_ansible_deploy_jump_host_authorization import (
    _interactive,
)
from test_ansible_deploy_jump_host_authorization import (
    _prepared as _authorization_prepared,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_jump_host_execution as execution_module
import scylla_vms.ansible.deploy_reconciliation as reconciliation_module
from scylla_vms.ansible.deploy_jump_host_execution import (
    ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_SCHEMA_VERSION,
    DeployJumpHostConfigureEvidenceStore,
    DeployJumpHostConfigureExecution,
    DeployJumpHostConfigureExecutionState,
    DeployJumpHostConfigureExecutionStore,
    DeployJumpHostConfigureRestorationStatus,
    deploy_jump_host_configure_evidence_path,
    deploy_jump_host_configure_execution_path,
    execute_deploy_jump_host_configure,
)
from scylla_vms.ansible.jump_host_configure import (
    JUMP_HOST_CONFIGURE_SCHEMA_VERSION,
)
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.persistence import serialize_json
from scylla_vms.process import (
    ProcessOutputError,
    ProcessResult,
    ProcessSpec,
    ProcessTimeoutError,
)

_PRIVATE_PATH = "/private/operator/jump-host-runtime.json"
_SECRET = "obviously-fake-jump-host-execution-secret"


@dataclass
class JumpHostRunner:
    mode: str = "changed"
    inspect_started: Any = None
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
            name = Path(spec.argv[0]).name
            return ProcessResult(0, f"{name} [core 2.20.9]\n", "")
        playbook = next(
            Path(argument).stem
            for argument in spec.argv
            if "/playbooks/" in argument and argument.endswith(".yml")
        )
        if playbook != "jump-host-configure":
            raise AssertionError(f"unexpected playbook or external tool: {playbook}")
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        variables = cast(
            dict[str, object], json.loads(runtime_file.read_text(encoding="utf-8"))
        )
        payload = cast(
            dict[str, object], variables["deploy_scylla_vms_jump_host_configure"]
        )
        self.payloads.append(payload)
        if self.inspect_started is not None:
            self.inspect_started()
        if self.mode == "timeout":
            raise ProcessTimeoutError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "interrupted":
            raise KeyboardInterrupt
        if self.mode == "non-utf8":
            raise ProcessOutputError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "oversized":
            return ProcessResult(0, "x" * (512 * 1024 + 1), _SECRET)
        return self._result(payload)

    def _result(self, payload: dict[str, object]) -> ProcessResult:
        logical_id = cast(str, payload["logical_id"])
        if self.mode == "malformed":
            return ProcessResult(0, self._recap(logical_id, 0, 0), _SECRET)
        if self.mode == "unreachable":
            return ProcessResult(4, self._recap(logical_id, 1, 0), _SECRET)
        if self.mode == "nonzero":
            return ProcessResult(2, self._recap(logical_id, 0, 1), _SECRET)
        status = "noop" if self.mode == "noop" else "changed"
        blockers: list[str] = []
        validation_performed = True
        validation_passed: bool | None = True
        reload_performed = status == "changed"
        reload_passed: bool | None = True if reload_performed else None
        exit_code = 0
        failed = 0
        if self.mode == "validation-failed":
            status = "failed"
            blockers = ["sshd-validation-failed"]
            validation_passed = False
            reload_performed = False
            reload_passed = None
            exit_code = 2
            failed = 1
        elif self.mode == "reload-failed":
            status = "failed"
            blockers = ["reload-failed"]
            reload_performed = True
            reload_passed = False
            exit_code = 2
            failed = 1
        elif self.mode == "host-key-mismatch":
            status = "failed"
            blockers = ["host-key-mismatch"]
            validation_performed = False
            validation_passed = None
            reload_performed = False
            reload_passed = None
            exit_code = 2
            failed = 1
        value: dict[str, object] = {
            "allowed_route_digest": payload["allowed_route_digest"],
            "blockers": blockers,
            "config_digest": payload["config_digest"],
            "host_key_digest": payload["host_key_digest"],
            "logical_id": (
                "wrong-jump-host" if self.mode == "wrong-target" else logical_id
            ),
            "provenance_digests": payload["provenance"],
            "reload_passed": reload_passed,
            "reload_performed": reload_performed,
            "schema_version": JUMP_HOST_CONFIGURE_SCHEMA_VERSION,
            "status": status,
            "validation_passed": validation_passed,
            "validation_performed": validation_performed,
        }
        if self.mode == "extra-field":
            value["raw_output"] = _SECRET
        marker = self._marker(value, logical_id)
        if self.mode == "duplicate":
            marker += marker
        stdout = marker + self._recap(
            logical_id,
            0,
            failed,
            changed=int(status == "changed"),
        )
        if self.mode == "extra":
            stdout += self._recap_row("extra-jump-host", 0, 0)
        return ProcessResult(exit_code, stdout, f"{_SECRET} {_PRIVATE_PATH}")

    @staticmethod
    def _marker(value: dict[str, object], logical_id: str) -> str:
        encoded = base64.b64encode(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        return (
            f'ok: [{logical_id}] => {{"msg":"DSV_JUMP_HOST_CONFIGURE_B64={encoded}"}}\n'
        )

    @classmethod
    def _recap(
        cls,
        logical_id: str,
        unreachable: int,
        failed: int,
        *,
        changed: int = 0,
    ) -> str:
        return "PLAY RECAP *****\n" + cls._recap_row(
            logical_id,
            unreachable,
            failed,
            changed=changed,
        )

    @staticmethod
    def _recap_row(
        logical_id: str,
        unreachable: int,
        failed: int,
        *,
        changed: int = 0,
    ) -> str:
        return (
            f"{logical_id} : ok=8 changed={changed} unreachable={unreachable} "
            f"failed={failed} skipped=0 rescued=0 ignored=0\n"
        )


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, _prior_runner, executables, toolchain = _authorization_prepared(
        tmp_path, monkeypatch
    )
    _authorize_jump_host(prepared, _interactive())
    return prepared, executables, toolchain


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_jump_host_configure(
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
        execution = DeployJumpHostConfigureExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployJumpHostConfigureEvidenceStore(
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


@pytest.mark.parametrize(("mode", "changed"), (("changed", 1), ("noop", 0)))
def test_exact_command_scope_variables_success_and_zero_call_reentry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    changed: int,
) -> None:
    assert tuple(inspect.signature(execute_deploy_jump_host_configure).parameters) == (
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
        f"{OPERATION_ID}.ansible-deploy-jump-host-configure-authorization.json"
    )
    reconciliation_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-post-reboot-reconciliation.json"
    )
    immutable = (
        journal_path.read_bytes(),
        authorization_path.read_bytes(),
        reconciliation_path.read_bytes(),
    )
    show_before = _run_show(prepared.paths)
    runner = JumpHostRunner(mode=mode)

    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)

    assert (
        report.schema_version
        == ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert (
        execution.record.schema_version
        == ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_SCHEMA_VERSION
    )
    assert evidence is not None
    assert (
        evidence.record.schema_version
        == ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_SCHEMA_VERSION
    )
    assert report.execution_state is DeployJumpHostConfigureExecutionState.SUCCEEDED
    assert report.authorization_consumed
    assert report.invocation_count == report.target_count == 1
    assert report.changed_count == report.reload_count == changed
    assert report.restored_count == 0
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert (
        journal_path.read_bytes(),
        authorization_path.read_bytes(),
        reconciliation_path.read_bytes(),
    ) == immutable
    assert _run_show(prepared.paths) == show_before
    assert not json.loads(authorization_path.read_text(encoding="utf-8"))["consumed"]

    assert runner.specs is not None
    assert tuple(Path(spec.argv[0]).name for spec in runner.specs) == (
        "ansible-playbook",
        "ansible-inventory",
        "ansible-playbook",
    )
    spec = runner.specs[-1]
    attempt = execution.record.attempts[0]
    assert spec.argv[spec.argv.index("--limit") + 1] == attempt.stable_id
    assert spec.argv[-1].endswith("/playbooks/jump-host-configure.yml")
    assert spec.argv[spec.argv.index("--tags") + 1] == "jump-host-configure"
    assert "--skip-tags" not in spec.argv
    assert "--check" not in spec.argv
    assert "--diff" not in spec.argv
    assert spec.cwd == prepared.paths.ansible
    assert set(spec.environment.names) == {
        "ANSIBLE_CONFIG",
        "ANSIBLE_HOST_KEY_CHECKING",
        "ANSIBLE_LOCAL_TEMP",
        "ANSIBLE_NOCOLOR",
        "ANSIBLE_RETRY_FILES_ENABLED",
        "HOME",
        "LANG",
        "LC_ALL",
        "PYTHONUNBUFFERED",
        "__CF_USER_TEXT_ENCODING",
    }
    assert runner.payloads is not None
    assert len(runner.payloads) == 1
    payload = runner.payloads[0]
    assert payload["logical_id"] == attempt.stable_id
    assert payload["config_digest"] == attempt.config_digest
    assert payload["allowed_route_digest"] == attempt.route_digest
    assert tuple(payload["allowed_routes"]) == tuple(sorted(payload["allowed_routes"]))
    assert not tuple(prepared.paths.ansible_local_tmp.iterdir())

    entry = evidence.record.entries[0]
    assert entry.applied
    assert entry.changed is bool(changed)
    assert entry.validation_performed and entry.validation_passed
    assert entry.reload_performed is bool(changed)
    assert entry.reload_passed is (True if changed else None)
    assert not entry.restored
    assert (
        entry.restoration_status
        is DeployJumpHostConfigureRestorationStatus.NOT_REQUIRED
    )
    for path in (
        deploy_jump_host_configure_execution_path(prepared.paths, OPERATION_ID),
        deploy_jump_host_configure_evidence_path(prepared.paths, OPERATION_ID),
    ):
        assert path.stat().st_mode & 0o777 == 0o600
    serialized = (
        deploy_jump_host_configure_execution_path(
            prepared.paths, OPERATION_ID
        ).read_text(encoding="utf-8")
        + deploy_jump_host_configure_evidence_path(
            prepared.paths, OPERATION_ID
        ).read_text(encoding="utf-8")
        + json.dumps(report.to_object(), sort_keys=True)
    )
    for protected in (
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "ssh-ed25519",
        "SHA256:",
        "PermitOpen",
        "PasswordAuthentication",
        "DSV_JUMP_HOST_CONFIGURE_B64",
        "PLAY RECAP",
        "--limit",
        "ansible-playbook",
        "deploy_scylla_vms_",
        _PRIVATE_PATH,
        _SECRET,
    ):
        assert protected not in serialized

    call_count = len(runner.specs)
    reused = _call(prepared, runner, executables, toolchain)
    assert reused.execution_artifact_state.value == "reused"
    assert reused.evidence_artifact_state.value == "reused"
    assert len(runner.specs) == call_count


@pytest.mark.parametrize(
    "mode",
    (
        "malformed",
        "extra",
        "duplicate",
        "wrong-target",
        "extra-field",
        "oversized",
    ),
)
def test_malformed_missing_extra_duplicate_wrong_or_oversize_is_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = JumpHostRunner(mode=mode)
    with pytest.raises(AnsibleError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert (
        execution.record.state is DeployJumpHostConfigureExecutionState.MALFORMED_RESULT
    )
    assert execution.record.authorization_consumed
    assert evidence is None
    playbook_calls = len(cast(list[dict[str, object]], runner.payloads))
    assert playbook_calls == 1

    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, runner, executables, toolchain)
    assert len(cast(list[dict[str, object]], runner.payloads)) == playbook_calls


@pytest.mark.parametrize(
    ("mode", "state", "has_evidence"),
    (
        ("validation-failed", DeployJumpHostConfigureExecutionState.FAILED, True),
        ("reload-failed", DeployJumpHostConfigureExecutionState.FAILED, True),
        ("host-key-mismatch", DeployJumpHostConfigureExecutionState.FAILED, True),
        ("unreachable", DeployJumpHostConfigureExecutionState.UNREACHABLE, True),
        ("nonzero", DeployJumpHostConfigureExecutionState.FAILED, True),
        ("timeout", DeployJumpHostConfigureExecutionState.TIMED_OUT, False),
        ("interrupted", DeployJumpHostConfigureExecutionState.INTERRUPTED, False),
        ("non-utf8", DeployJumpHostConfigureExecutionState.MALFORMED_RESULT, False),
    ),
)
def test_failure_validation_reload_restore_and_process_outcomes_are_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    state: DeployJumpHostConfigureExecutionState,
    has_evidence: bool,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = JumpHostRunner(mode=mode)
    with pytest.raises((AnsibleError, StatePersistenceError), match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is state
    assert execution.record.authorization_consumed
    assert execution.record.invocation_count == 1
    assert execution.record.attempts[-1].manual_recovery_required
    assert not execution.record.attempts[-1].automatic_retry_allowed
    assert (evidence is not None) is has_evidence
    if evidence is not None:
        entry = evidence.record.entries[-1]
        assert not entry.applied
        assert not entry.restored
        assert (
            entry.restoration_status
            is DeployJumpHostConfigureRestorationStatus.NOT_PROVEN
        )
        if mode == "validation-failed":
            assert entry.validation_performed
            assert entry.validation_passed is False
            assert not entry.reload_performed
        if mode == "reload-failed":
            assert entry.validation_passed
            assert entry.reload_performed
            assert entry.reload_passed is False
    playbook_calls = len(cast(list[dict[str, object]], runner.payloads))
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, runner, executables, toolchain)
    assert len(cast(list[dict[str, object]], runner.payloads)) == playbook_calls


def test_prepared_recovery_and_started_consumption_precede_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    original = DeployJumpHostConfigureExecutionStore.write_locked
    refused = False

    def fail_started(self, record, **kwargs):
        nonlocal refused
        if (
            record.state is DeployJumpHostConfigureExecutionState.STARTED
            and not refused
        ):
            refused = True
            raise StatePersistenceError("simulated safe pre-invocation refusal")
        return original(self, record, **kwargs)

    monkeypatch.setattr(
        DeployJumpHostConfigureExecutionStore, "write_locked", fail_started
    )
    first = JumpHostRunner()
    with pytest.raises(StatePersistenceError, match="before invocation"):
        _call(prepared, first, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployJumpHostConfigureExecutionState.PREPARED
    assert not execution.record.authorization_consumed
    assert execution.record.invocation_count == 0
    assert evidence is None
    assert first.payloads == []

    monkeypatch.setattr(DeployJumpHostConfigureExecutionStore, "write_locked", original)
    observed: list[DeployJumpHostConfigureExecutionState] = []

    def inspect_started() -> None:
        value = json.loads(
            deploy_jump_host_configure_execution_path(
                prepared.paths, OPERATION_ID
            ).read_text(encoding="utf-8")
        )
        record = DeployJumpHostConfigureExecution.from_object(value)
        observed.append(record.state)
        assert record.authorization_consumed
        assert record.invocation_count == 1

    resumed = JumpHostRunner(inspect_started=inspect_started)
    report = _call(prepared, resumed, executables, toolchain)
    assert report.execution_state is DeployJumpHostConfigureExecutionState.SUCCEEDED
    assert observed == [DeployJumpHostConfigureExecutionState.STARTED]


@pytest.mark.parametrize("failure_point", ("evidence", "terminal"))
def test_post_call_evidence_or_terminal_persistence_failure_never_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)

    def fail_evidence(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")

    if failure_point == "evidence":
        monkeypatch.setattr(
            DeployJumpHostConfigureEvidenceStore, "append_locked", fail_evidence
        )
    else:
        original_write = DeployJumpHostConfigureExecutionStore.write_locked

        def fail_terminal(self, record, **kwargs):
            if record.state is DeployJumpHostConfigureExecutionState.SUCCEEDED:
                raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")
            return original_write(self, record, **kwargs)

        monkeypatch.setattr(
            DeployJumpHostConfigureExecutionStore, "write_locked", fail_terminal
        )
    runner = JumpHostRunner()
    with pytest.raises(StatePersistenceError, match="manual recovery") as caught:
        _call(prepared, runner, executables, toolchain)
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployJumpHostConfigureExecutionState.STARTED
    assert execution.record.authorization_consumed
    assert (evidence is not None) is (failure_point == "terminal")
    calls = len(cast(list[dict[str, object]], runner.payloads))
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, runner, executables, toolchain)
    assert len(cast(list[dict[str, object]], runner.payloads)) == calls


@pytest.mark.parametrize(
    "drift",
    (
        "authorization",
        "post-reboot",
        "inventory",
        "trust",
        "readiness",
        "catalog",
        "source",
        "toolchain",
        "journal",
    ),
)
def test_chain_route_trust_source_catalog_toolchain_and_journal_drift_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    paths = prepared.paths
    selected = {
        "authorization": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-jump-host-configure-authorization.json",
        "post-reboot": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-post-reboot-reconciliation.json",
        "inventory": paths.ansible_inventory,
        "trust": paths.ansible_trust,
        "readiness": paths.terraform_plans
        / f"{OPERATION_ID}.terraform-apply-readiness.json",
        "journal": paths.operations / f"{OPERATION_ID}.json",
    }
    if drift == "source":
        source = load_ansible_source_bundle()
        monkeypatch.setattr(
            reconciliation_module,
            "load_ansible_source_bundle",
            lambda: replace(source, digest="sha256:" + "a" * 64),
        )
    elif drift == "catalog":
        monkeypatch.setattr(
            reconciliation_module,
            "ansible_operation_catalog_digest",
            lambda: "sha256:" + "b" * 64,
        )
    elif drift == "toolchain":
        toolchain = type(toolchain)(type(toolchain.core)(2, 19, 9))
    else:
        _tamper_digest(
            selected[drift],
            (
                "inventory_digest"
                if drift == "inventory"
                else "entries_digest"
                if drift == "trust"
                else "request_digest"
                if drift == "journal"
                else "authorization_digest"
                if drift == "authorization"
                else "record_digest"
            ),
        )
    runner = JumpHostRunner()
    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
    assert not deploy_jump_host_configure_execution_path(
        prepared.paths, OPERATION_ID
    ).exists()


@pytest.mark.parametrize("drift_field", ("route", "config", "policy"))
def test_route_permit_open_config_and_policy_drift_after_prepared_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift_field: str,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    original_write = DeployJumpHostConfigureExecutionStore.write_locked

    def fail_started(self, record, **kwargs):
        if record.state is DeployJumpHostConfigureExecutionState.STARTED:
            raise StatePersistenceError("stop at prepared")
        return original_write(self, record, **kwargs)

    monkeypatch.setattr(
        DeployJumpHostConfigureExecutionStore, "write_locked", fail_started
    )
    with pytest.raises(StatePersistenceError, match="before invocation"):
        _call(prepared, JumpHostRunner(), executables, toolchain)
    monkeypatch.setattr(
        DeployJumpHostConfigureExecutionStore, "write_locked", original_write
    )
    if drift_field == "policy":
        monkeypatch.setattr(
            execution_module,
            "_policy_digest",
            lambda: "sha256:" + "c" * 64,
        )
    else:
        original_payload = execution_module.build_jump_host_configure_payload

        def drifted_payload(*args, **kwargs):
            payload = original_payload(*args, **kwargs)
            field = (
                "allowed_route_digest" if drift_field == "route" else "config_digest"
            )
            return {**payload, field: "sha256:" + "c" * 64}

        monkeypatch.setattr(
            execution_module, "build_jump_host_configure_payload", drifted_payload
        )
    runner = JumpHostRunner()
    with pytest.raises((StateConflictError, StatePersistenceError, AnsibleError)):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []


def test_api_lock_path_permissions_and_arbitrary_inputs_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    parameters = inspect.signature(execute_deploy_jump_host_configure).parameters
    forbidden = {
        "step",
        "playbook",
        "target",
        "targets",
        "limit",
        "variables",
        "path",
        "command",
        "environment",
        "authorization",
        "result",
        "loop",
    }
    assert forbidden.isdisjoint(parameters)
    runner = JumpHostRunner()
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        execute_deploy_jump_host_configure(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )
    assert runner.specs == []

    path = deploy_jump_host_configure_execution_path(prepared.paths, OPERATION_ID)
    outside = tmp_path / "outside-execution.json"
    outside.write_text("{}\n", encoding="utf-8")
    outside.chmod(0o600)
    path.symlink_to(outside)
    with pytest.raises(UnsafePathError):
        _call(prepared, runner, executables, toolchain)
    path.unlink()
    outside.unlink()

    authorization_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-jump-host-configure-authorization.json"
    )
    authorization_path.chmod(0o644)
    with pytest.raises(UnsafePathError):
        _call(prepared, runner, executables, toolchain)
    authorization_path.chmod(0o600)

    ambiguous = prepared.paths.operations / (
        f"{{{OPERATION_ID}}}.ansible-deploy-jump-host-configure-execution.json"
    )
    ambiguous.write_text("{}\n", encoding="utf-8")
    ambiguous.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []


def _tamper_digest(path: Path, field: str) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    value[field] = "sha256:" + "d" * 64
    path.write_bytes(serialize_json(value))
    os.chmod(path, 0o600)
