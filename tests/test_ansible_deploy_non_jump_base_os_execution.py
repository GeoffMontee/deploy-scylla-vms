import base64
import inspect
import json
import os
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import pytest
from test_ansible_deploy_final_routes import FinalRoutesRunner
from test_ansible_deploy_final_routes import _execute as _execute_final_routes
from test_ansible_deploy_final_routes import _prepared as _final_routes_prepared
from test_ansible_deploy_final_routes import _reconcile as _reconcile_final_routes
from test_ansible_deploy_non_jump_base_os_authorization import (
    _call as _authorize,
)
from test_ansible_deploy_non_jump_base_os_authorization import (
    _interactive,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_reconciliation as reconciliation_module
from scylla_vms.ansible.base_os import BASE_OS_EVIDENCE_SCHEMA_VERSION
from scylla_vms.ansible.deploy_final_routes import (
    deploy_post_final_routes_reconciliation_path,
)
from scylla_vms.ansible.deploy_non_jump_base_os_execution import (
    ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EXECUTION_SCHEMA_VERSION,
    DeployNonJumpBaseOsEvidenceStore,
    DeployNonJumpBaseOsExecution,
    DeployNonJumpBaseOsExecutionState,
    DeployNonJumpBaseOsExecutionStore,
    deploy_non_jump_base_os_evidence_path,
    deploy_non_jump_base_os_execution_path,
    execute_deploy_non_jump_base_os,
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

_PRIVATE_PATH = "/private/operator/base-os-runtime.json"
_SECRET = "obviously-fake-base-os-execution-secret"


@dataclass
class BaseOsRunner:
    inventory: Any
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
            name = Path(spec.argv[0]).name
            return ProcessResult(0, f"{name} [core 2.20.9]\n", "")
        playbook = next(
            Path(argument).stem
            for argument in spec.argv
            if "/playbooks/" in argument and argument.endswith(".yml")
        )
        if playbook != "base-os":
            raise AssertionError(f"unexpected playbook or external tool: {playbook}")
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        self.payloads.append(
            cast(
                dict[str, object],
                json.loads(runtime_file.read_text(encoding="utf-8")),
            )
        )
        if self.inspect_started is not None:
            self.inspect_started()
        if self.mode == "timeout":
            raise ProcessTimeoutError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "interrupted":
            raise KeyboardInterrupt
        if self.mode == "non-utf8":
            raise ProcessOutputError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "oversized":
            return ProcessResult(0, "x" * (1024 * 1024 + 1), _SECRET)
        limit = tuple(spec.argv[spec.argv.index("--limit") + 1].split(","))
        return self._result(limit)

    def _result(self, limit: tuple[str, ...]) -> ProcessResult:
        markers: list[str] = []
        recaps: list[str] = []
        for index, logical_id in enumerate(limit):
            changed = self.mode in {"changed", "reboot", "mixed-reboot"}
            reboot_required = self.mode == "reboot" or (
                self.mode == "mixed-reboot" and index == 0
            )
            status = (
                "reboot-required"
                if reboot_required
                else "changed"
                if changed
                else "no-change"
            )
            reason = (
                "reboot-required"
                if reboot_required
                else "applied"
                if changed
                else "already-current"
            )
            failed = self.mode == "nonzero" and index == 0
            unreachable = self.mode == "unreachable" and index == 0
            omitted = self.mode in {"missing", "malformed"} and index == 0
            marker_id = (
                "wrong-host" if self.mode == "wrong-host" and index == 0 else logical_id
            )
            if failed:
                status = "failure"
                reason = "execution-failed"
                changed = reboot_required = False
            if not omitted and not unreachable:
                markers.append(
                    self._marker(
                        marker_id,
                        status=status,
                        reason=reason,
                        changed=changed,
                        reboot_required=reboot_required,
                    )
                )
                if self.mode == "duplicate" and index == 0:
                    markers.append(markers[-1])
            recaps.append(
                f"{logical_id} : ok=8 changed={int(changed)} "
                f"unreachable={int(unreachable)} failed={int(failed)} "
                "skipped=0 rescued=0 ignored=0"
            )
        if self.mode == "extra":
            markers.append(
                self._marker(
                    "extra-host",
                    status="no-change",
                    reason="already-current",
                    changed=False,
                    reboot_required=False,
                )
            )
            recaps.append(
                "extra-host : ok=8 changed=0 unreachable=0 failed=0 "
                "skipped=0 rescued=0 ignored=0"
            )
        stdout = "".join(markers) + "PLAY RECAP *****\n" + "\n".join(recaps) + "\n"
        exit_code = (
            4 if self.mode == "unreachable" else 2 if self.mode == "nonzero" else 0
        )
        return ProcessResult(exit_code, stdout, f"{_SECRET} {_PRIVATE_PATH}")

    @staticmethod
    def _marker(
        logical_id: str,
        *,
        status: str,
        reason: str,
        changed: bool,
        reboot_required: bool,
    ) -> str:
        value = {
            "changed": changed,
            "logical_id": logical_id,
            "reason": reason,
            "reboot_required": reboot_required,
            "schema_version": BASE_OS_EVIDENCE_SCHEMA_VERSION,
            "status": status,
        }
        encoded = base64.b64encode(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        return f'ok: [{logical_id}] => {{"msg":"DSV_BASE_OS_B64={encoded}"}}\n'


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, executables, toolchain = _final_routes_prepared(tmp_path, monkeypatch)
    _execute_final_routes(prepared, FinalRoutesRunner(), executables, toolchain)
    _reconcile_final_routes(prepared)
    _authorize(prepared, _interactive())
    return prepared, None, executables, toolchain


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_non_jump_base_os(
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
        execution = DeployNonJumpBaseOsExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployNonJumpBaseOsEvidenceStore(prepared.paths, OPERATION_ID)
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


def test_exact_authorized_scope_command_variables_success_and_zero_call_reentry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(inspect.signature(execute_deploy_non_jump_base_os).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "runner",
        "executables",
        "toolchain",
    )
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    authorization_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-non-jump-base-os-authorization.json"
    )
    effective_plan_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-effective-plan.json"
    )
    journal_before = journal_path.read_bytes()
    authorization_before = authorization_path.read_bytes()
    effective_plan_before = effective_plan_path.read_bytes()
    show_before = _run_show(prepared.paths)
    runner = BaseOsRunner(inventory)

    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)

    assert report.schema_version == (
        ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert execution.record.schema_version == (
        ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EXECUTION_SCHEMA_VERSION
    )
    assert evidence is not None
    assert (
        evidence.record.schema_version
        == ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EVIDENCE_SCHEMA_VERSION
    )
    assert report.execution_state is DeployNonJumpBaseOsExecutionState.SUCCEEDED
    assert report.authorization_consumed
    assert report.invocation_count == report.scope_count == 1
    assert report.stable_id_count == 3
    assert report.changed_count == 0
    assert not report.reboot_required
    assert report.stage == "post-final-routes-non-jump-base-os"
    assert report.scope_kind == "non-jump-managed-hosts"
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert journal_path.read_bytes() == journal_before
    assert authorization_path.read_bytes() == authorization_before
    assert effective_plan_path.read_bytes() == effective_plan_before
    assert not json.loads(authorization_before)["consumed"]
    assert execution.record.attempts[0].authorization_command_digest != (
        execution.record.attempts[0].command_digest
    )
    assert execution.record.attempts[0].authorization_consumed
    assert execution.record.attempts[0].invocation_may_have_occurred
    assert not execution.record.attempts[0].automatic_retry_allowed

    assert runner.specs is not None
    assert tuple(Path(spec.argv[0]).name for spec in runner.specs) == (
        "ansible-playbook",
        "ansible-inventory",
        "ansible-playbook",
    )
    assert runner.payloads == [
        {
            "deploy_scylla_vms_image_architecture": "amd64",
            "deploy_scylla_vms_image_operating_system": "Ubuntu",
            "deploy_scylla_vms_image_operating_system_version": "24.04",
        }
    ]
    assert len(runner.specs) == 3
    spec = runner.specs[-1]
    attempt = execution.record.attempts[0]
    assert attempt.target_ids == (
        "manager-1",
        "monitoring-1",
        "scylla-ad-1-1",
    )
    assert "jump-host-1" not in attempt.target_ids
    assert spec.argv[spec.argv.index("--limit") + 1] == ",".join(attempt.target_ids)
    assert spec.argv[-1].endswith("/playbooks/base-os.yml")
    assert "--check" not in spec.argv
    assert "--diff" not in spec.argv
    assert "--tags" not in spec.argv
    assert "--skip-tags" not in spec.argv
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
    host = evidence.record.entries[0].hosts[0]
    assert (
        host.os_family,
        host.os_version,
        host.image_architecture,
        host.guest_architecture,
    ) == ("Ubuntu", "24.04", "amd64", "x86_64")
    assert host.applied
    assert host.prerequisite_policy_status == "satisfied"
    assert host.timesync_service_status == "enabled-active"
    assert not tuple(prepared.paths.ansible_local_tmp.iterdir())
    assert _run_show(prepared.paths) == show_before

    for path in (
        deploy_non_jump_base_os_execution_path(prepared.paths, OPERATION_ID),
        deploy_non_jump_base_os_evidence_path(prepared.paths, OPERATION_ID),
    ):
        assert path.stat().st_mode & 0o777 == 0o600
    persisted = deploy_non_jump_base_os_execution_path(
        prepared.paths, OPERATION_ID
    ).read_text(encoding="utf-8") + deploy_non_jump_base_os_evidence_path(
        prepared.paths, OPERATION_ID
    ).read_text(encoding="utf-8")
    projected = json.dumps(report.to_object(), sort_keys=True)
    for forbidden in (
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "ssh-ed25519",
        "PLAY RECAP",
        "DSV_BASE_OS_B64",
        "--limit",
        "ansible-playbook",
        "deploy_scylla_vms_",
        _PRIVATE_PATH,
        _SECRET,
    ):
        assert forbidden not in persisted
        assert forbidden not in projected

    with pytest.raises(StateConflictError, match="uncertain execution"):
        _authorize(prepared, _interactive())
    zero_runner = BaseOsRunner(inventory, mode="timeout")
    reused = _call(prepared, zero_runner, executables, toolchain)
    assert zero_runner.specs == []
    assert reused.to_object() == report.to_object()


@pytest.mark.parametrize(
    ("mode", "changed", "reboot"),
    (("no-change", 0, 0), ("changed", 3, 0), ("reboot", 3, 3)),
)
def test_changed_no_change_and_reboot_required_semantic_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    changed: int,
    reboot: int,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    report = _call(
        prepared,
        BaseOsRunner(inventory, mode=mode),
        executables,
        toolchain,
    )
    _execution, evidence = _records(prepared)
    assert evidence is not None
    host = evidence.record.entries[0].hosts[0]
    assert report.changed_count == changed
    assert report.reboot_required_count == reboot
    assert report.reboot_required is bool(reboot)
    assert not report.reboot_performed
    assert host.changed is bool(changed)
    assert host.reboot_required is bool(reboot)


@pytest.mark.parametrize(
    "mode",
    ("malformed", "missing", "extra", "duplicate", "wrong-host", "oversized"),
)
def test_exit_zero_malformed_wrong_missing_extra_duplicate_and_oversize_are_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = BaseOsRunner(inventory, mode=mode)
    with pytest.raises(AnsibleError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployNonJumpBaseOsExecutionState.MALFORMED_RESULT
    assert execution.record.authorization_consumed
    assert execution.record.attempts[-1].manual_recovery_required
    assert evidence is None

    no_retry = BaseOsRunner(inventory)
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


@pytest.mark.parametrize(
    ("mode", "state", "has_evidence"),
    (
        ("nonzero", DeployNonJumpBaseOsExecutionState.FAILED, True),
        ("unreachable", DeployNonJumpBaseOsExecutionState.UNREACHABLE, True),
        ("timeout", DeployNonJumpBaseOsExecutionState.TIMED_OUT, False),
        ("interrupted", DeployNonJumpBaseOsExecutionState.INTERRUPTED, False),
        ("non-utf8", DeployNonJumpBaseOsExecutionState.MALFORMED_RESULT, False),
    ),
)
def test_nonzero_timeout_interruption_unreachable_and_non_utf8_are_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    state: DeployNonJumpBaseOsExecutionState,
    has_evidence: bool,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    with pytest.raises((AnsibleError, StatePersistenceError), match="manual recovery"):
        _call(
            prepared,
            BaseOsRunner(inventory, mode=mode),
            executables,
            toolchain,
        )
    execution, evidence = _records(prepared)
    assert execution.record.state is state
    assert (evidence is not None) is has_evidence
    assert not execution.record.attempts[-1].automatic_retry_allowed

    no_retry = BaseOsRunner(inventory)
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_prepared_recovery_and_started_consumption_precede_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    original = DeployNonJumpBaseOsExecutionStore.write_locked
    refused = False

    def fail_started(self, record, **kwargs):
        nonlocal refused
        if record.state is DeployNonJumpBaseOsExecutionState.STARTED and not refused:
            refused = True
            raise StatePersistenceError("simulated safe pre-invocation refusal")
        return original(self, record, **kwargs)

    monkeypatch.setattr(DeployNonJumpBaseOsExecutionStore, "write_locked", fail_started)
    first = BaseOsRunner(inventory)
    with pytest.raises(StatePersistenceError, match="before invocation"):
        _call(prepared, first, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployNonJumpBaseOsExecutionState.PREPARED
    assert not execution.record.authorization_consumed
    assert execution.record.invocation_count == 0
    assert evidence is None
    assert first.specs is not None
    assert len(first.specs) == 2

    monkeypatch.setattr(DeployNonJumpBaseOsExecutionStore, "write_locked", original)
    observed: list[DeployNonJumpBaseOsExecutionState] = []

    def inspect_started() -> None:
        value = json.loads(
            deploy_non_jump_base_os_execution_path(
                prepared.paths, OPERATION_ID
            ).read_text(encoding="utf-8")
        )
        record = DeployNonJumpBaseOsExecution.from_object(value)
        observed.append(record.state)
        assert record.authorization_consumed
        assert record.invocation_count == 1

    resumed = BaseOsRunner(inventory, inspect_started=inspect_started)
    report = _call(prepared, resumed, executables, toolchain)
    assert report.execution_state is DeployNonJumpBaseOsExecutionState.SUCCEEDED
    assert observed == [DeployNonJumpBaseOsExecutionState.STARTED]


@pytest.mark.parametrize("failure_point", ("evidence", "terminal"))
def test_post_invocation_persistence_failure_is_permanent_manual_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)

    def fail_evidence(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")

    if failure_point == "evidence":
        monkeypatch.setattr(
            DeployNonJumpBaseOsEvidenceStore, "append_locked", fail_evidence
        )
    else:
        original_write = DeployNonJumpBaseOsExecutionStore.write_locked

        def fail_terminal(self, record, **kwargs):
            if record.state is DeployNonJumpBaseOsExecutionState.SUCCEEDED:
                raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")
            return original_write(self, record, **kwargs)

        monkeypatch.setattr(
            DeployNonJumpBaseOsExecutionStore, "write_locked", fail_terminal
        )
    with pytest.raises(StatePersistenceError, match="manual recovery") as caught:
        _call(prepared, BaseOsRunner(inventory), executables, toolchain)
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployNonJumpBaseOsExecutionState.STARTED
    assert execution.record.authorization_consumed
    assert (evidence is not None) is (failure_point == "terminal")

    no_retry = BaseOsRunner(inventory)
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_post_invocation_state_drift_leaves_started_manual_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)

    def drift_after_start() -> None:
        _tamper_digest(
            prepared.paths.operations / f"{OPERATION_ID}.json",
            "request_digest",
        )

    runner = BaseOsRunner(inventory, inspect_started=drift_after_start)
    with pytest.raises(StateConflictError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployNonJumpBaseOsExecutionState.STARTED
    assert execution.record.authorization_consumed
    assert execution.record.attempts[-1].manual_recovery_required
    assert evidence is None

    no_retry = BaseOsRunner(inventory)
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


@pytest.mark.parametrize(
    "drift",
    (
        "authorization",
        "original-plan",
        "effective-plan",
        "host-evidence",
        "final-routes-execution",
        "final-routes-evidence",
        "final-routes-reconciliation",
        "inventory",
        "trust",
        "readiness",
        "catalog",
        "source",
        "toolchain",
        "journal",
    ),
)
def test_authorization_plan_evidence_readiness_catalog_source_toolchain_journal_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    paths = prepared.paths
    direct_artifacts = {
        "final-routes-execution": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-final-routes-execution.json",
        "final-routes-evidence": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-final-routes-evidence.json",
        "final-routes-reconciliation": deploy_post_final_routes_reconciliation_path(
            paths, OPERATION_ID
        ),
        "inventory": paths.ansible_inventory,
        "trust": paths.ansible_trust,
    }
    if drift in direct_artifacts:
        document = json.loads(direct_artifacts[drift].read_text(encoding="utf-8"))
        document["unexpected"] = _SECRET
        direct_artifacts[drift].write_bytes(serialize_json(document))
        os.chmod(direct_artifacts[drift], 0o600)
    elif drift == "authorization":
        _tamper_digest(
            paths.operations
            / f"{OPERATION_ID}.ansible-deploy-non-jump-base-os-authorization.json",
            "authorization_digest",
        )
    elif drift == "original-plan":
        _tamper_digest(
            paths.operations / f"{OPERATION_ID}.ansible-deploy-plan.json",
            "record_digest",
        )
    elif drift == "effective-plan":
        _tamper_digest(
            paths.operations / f"{OPERATION_ID}.ansible-deploy-effective-plan.json",
            "record_digest",
        )
    elif drift == "host-evidence":
        evidence_path = paths.operations / (
            f"{OPERATION_ID}.ansible-deploy-pre-mutation-host-evidence.json"
        )
        value = json.loads(evidence_path.read_text(encoding="utf-8"))
        value["entries"][0]["evidence_digest"] = "sha256:" + "e" * 64
        evidence_path.write_bytes(serialize_json(value))
        os.chmod(evidence_path, 0o600)
    elif drift == "readiness":
        _tamper_digest(
            paths.terraform_plans / f"{OPERATION_ID}.terraform-apply-readiness.json",
            "record_digest",
        )
    elif drift == "catalog":
        monkeypatch.setattr(
            reconciliation_module,
            "ansible_operation_catalog_digest",
            lambda: "sha256:" + "b" * 64,
        )
    elif drift == "source":
        source = load_ansible_source_bundle()
        monkeypatch.setattr(
            reconciliation_module,
            "load_ansible_source_bundle",
            lambda: replace(source, digest="sha256:" + "c" * 64),
        )
    elif drift == "toolchain":
        toolchain = type(toolchain)(type(toolchain.core)(2, 19, 9))
    else:
        _tamper_digest(
            paths.operations / f"{OPERATION_ID}.json",
            "request_digest",
        )
    runner = BaseOsRunner(inventory)
    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []


def test_lock_symlink_permissions_ambiguity_and_caller_scope_refusal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = BaseOsRunner(inventory)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        execute_deploy_non_jump_base_os(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )
    assert runner.specs == []
    assert "limit" not in inspect.signature(execute_deploy_non_jump_base_os).parameters
    assert (
        "variables" not in inspect.signature(execute_deploy_non_jump_base_os).parameters
    )
    assert (
        "environment"
        not in inspect.signature(execute_deploy_non_jump_base_os).parameters
    )
    assert (
        "playbook" not in inspect.signature(execute_deploy_non_jump_base_os).parameters
    )

    execution_path = deploy_non_jump_base_os_execution_path(
        prepared.paths, OPERATION_ID
    )
    target = prepared.paths.operations / "fake-base-os-target.json"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    execution_path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
    execution_path.unlink()
    target.unlink()

    reconciliation_path = deploy_post_final_routes_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    reconciliation_path.chmod(0o644)
    with pytest.raises(UnsafePathError):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
    reconciliation_path.chmod(0o600)

    ambiguous = prepared.paths.operations / (
        f"{{{OPERATION_ID}}}{'.ansible-deploy-non-jump-base-os-execution.json'}"
    )
    ambiguous.write_text("{}\n", encoding="utf-8")
    ambiguous.chmod(0o600)
    with pytest.raises(StateConflictError, match="conflicting execution history"):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []


def _tamper_digest(path: Path, field: str) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    value[field] = "sha256:" + "d" * 64
    path.write_bytes(serialize_json(value))
    os.chmod(path, 0o600)
