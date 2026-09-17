import base64
import inspect
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import pytest
from test_ansible_deploy_base_os_execution import (
    BaseOsRunner,
)
from test_ansible_deploy_base_os_execution import (
    _call as _execute_base_os,
)
from test_ansible_deploy_base_os_execution import (
    _prepared as _base_os_prepared,
)
from test_ansible_deploy_base_os_reconciliation import (
    _call as _reconcile_base_os,
)
from test_ansible_deploy_reboot_authorization import (
    _call as _authorize_reboot,
)
from test_ansible_deploy_reboot_authorization import (
    _interactive,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_reboot_execution as reboot_execution_module
from scylla_vms.ansible.deploy_reboot import DEPLOY_REBOOT_RESULT_SCHEMA_VERSION
from scylla_vms.ansible.deploy_reboot_execution import (
    ANSIBLE_DEPLOY_REBOOT_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_REBOOT_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_REBOOT_EXECUTION_SCHEMA_VERSION,
    DeployRebootEvidenceStore,
    DeployRebootExecutionState,
    DeployRebootExecutionStore,
    deploy_reboot_evidence_path,
    deploy_reboot_execution_path,
    execute_deploy_reboots,
)
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.process import (
    ProcessOutputError,
    ProcessResult,
    ProcessSpec,
    ProcessTimeoutError,
)

_SECRET = "obviously-fake-reboot-secret"
_PRIVATE_PATH = "/private/operator/reboot-runtime.json"


@dataclass
class RebootRunner:
    mode: str = "success"
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
        if playbook != "deploy-reboot":
            raise AssertionError(f"unexpected playbook or external tool: {playbook}")
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        payload = cast(
            dict[str, object], json.loads(runtime_file.read_text(encoding="utf-8"))
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
            return ProcessResult(0, "x" * (1024 * 1024 + 1), _SECRET)
        request = cast(dict[str, object], payload["deploy_scylla_vms_deploy_reboot"])
        logical_id = cast(str, request["logical_id"])
        if self.mode == "malformed":
            return ProcessResult(0, self._recap(logical_id, 0, 0), "")
        if self.mode == "unsupported-exit":
            return ProcessResult(1, self._recap(logical_id, 0, 1), _SECRET)
        if self.mode in {"failed", "active-service"}:
            return ProcessResult(2, self._recap(logical_id, 0, 1), _SECRET)
        if self.mode == "unreachable":
            return ProcessResult(4, self._recap(logical_id, 1, 0), _SECRET)
        value: dict[str, object] = {
            "architecture": request["architecture"],
            "boot_changed": True,
            "elapsed_seconds": 12,
            "identity_verified": True,
            "logical_id": logical_id,
            "machine_evidence_verified": True,
            "os_family": "Ubuntu",
            "os_version": "24.04",
            "reboot_performed": True,
            "reboot_required_clear": True,
            "reconnected": True,
            "request_digest": request["request_digest"],
            "role": request["role"],
            "schema_version": DEPLOY_REBOOT_RESULT_SCHEMA_VERSION,
            "services_safe_after": True,
            "services_safe_before": True,
            "status": "succeeded",
            "trust_revalidated": True,
        }
        if self.mode == "boot-unchanged":
            value["boot_changed"] = False
        elif self.mode == "reboot-required":
            value["reboot_required_clear"] = False
        elif self.mode == "identity-mismatch":
            value["logical_id"] = "wrong-stable-id"
        elif self.mode == "trust-mismatch":
            value["trust_revalidated"] = False
        elif self.mode == "os-mismatch":
            value["os_version"] = "22.04"
        elif self.mode == "arch-mismatch":
            value["architecture"] = (
                "aarch64" if request["architecture"] == "x86_64" else "x86_64"
            )
        encoded = base64.b64encode(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        stdout = (
            f'ok: [{logical_id}] => {{"msg":"DSV_DEPLOY_REBOOT_B64={encoded}"}}\n'
            f"{self._recap(logical_id, 0, 0)}"
        )
        return ProcessResult(0, stdout, "")

    @staticmethod
    def _recap(logical_id: str, unreachable: int, failed: int) -> str:
        return (
            "PLAY RECAP\n"
            f"{logical_id} : ok=12 changed=1 unreachable={unreachable} "
            f"failed={failed} skipped=0 rescued=0 ignored=0\n"
        )


def _prepared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    reboot_required: bool = True,
):
    prepared, inventory, executables, toolchain = _base_os_prepared(
        tmp_path, monkeypatch
    )
    base_runner = BaseOsRunner(
        inventory, mode="reboot" if reboot_required else "no-change"
    )
    _execute_base_os(prepared, base_runner, executables, toolchain)
    _reconcile_base_os(prepared)
    if reboot_required:
        _authorize_reboot(prepared, _interactive())
    return prepared, inventory, executables, toolchain


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_reboots(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )


def test_serial_reboot_consumes_authorization_before_call_and_reuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _, executables, toolchain = _prepared(tmp_path, monkeypatch)

    def inspect_started() -> None:
        stored = DeployRebootExecutionStore(prepared.paths, OPERATION_ID).read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        assert stored.record.state is DeployRebootExecutionState.STARTED
        assert stored.record.authorization_consumed
        assert stored.record.invocation_count == 1
        assert stored.record.attempts[0].manual_recovery_required

    runner = RebootRunner(inspect_started=inspect_started)
    report = _call(prepared, runner, executables, toolchain)
    assert (
        report.schema_version == ANSIBLE_DEPLOY_REBOOT_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert report.execution_state == "succeeded"
    assert report.authorization_consumed
    assert report.target_count == report.completed_target_count == 1
    assert report.invocation_count == 1
    assert report.post_reboot_evidence_state == "post-reboot-evidence-ready"
    assert report.reconnect_count == report.identity_verified_count == 1
    assert report.trust_revalidated_count == report.machine_evidence_verified_count == 1
    assert report.boot_changed_count == report.reboot_clear_count == 1
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    _run_show(prepared.paths)
    assert runner.payloads is not None
    assert len(runner.payloads) == 1
    assert set(runner.payloads[0]) == {"deploy_scylla_vms_deploy_reboot"}
    playbooks = [
        Path(argument).stem
        for spec in cast(list[ProcessSpec], runner.specs)
        for argument in spec.argv
        if "/playbooks/" in argument and argument.endswith(".yml")
    ]
    assert playbooks == ["deploy-reboot"]

    calls = len(cast(list[ProcessSpec], runner.specs))
    reused = _call(prepared, runner, executables, toolchain)
    assert reused.execution_artifact_state.value == "reused"
    assert reused.evidence_artifact_state.value == "reused"
    assert len(cast(list[ProcessSpec], runner.specs)) == calls

    execution = json.loads(
        deploy_reboot_execution_path(prepared.paths, OPERATION_ID).read_text(
            encoding="utf-8"
        )
    )
    evidence = json.loads(
        deploy_reboot_evidence_path(prepared.paths, OPERATION_ID).read_text(
            encoding="utf-8"
        )
    )
    assert execution["schema_version"] == ANSIBLE_DEPLOY_REBOOT_EXECUTION_SCHEMA_VERSION
    assert evidence["schema_version"] == ANSIBLE_DEPLOY_REBOOT_EVIDENCE_SCHEMA_VERSION
    serialized = json.dumps({"execution": execution, "evidence": evidence})
    for protected in (
        _SECRET,
        _PRIVATE_PATH,
        "boot_id",
        "ssh-ed25519",
        "10.0.",
        "DSV_DEPLOY_REBOOT_B64",
    ):
        assert protected not in serialized


def test_no_reboot_is_write_and_process_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _, executables, toolchain = _prepared(
        tmp_path, monkeypatch, reboot_required=False
    )
    runner = RebootRunner()
    report = _call(prepared, runner, executables, toolchain)
    assert report.execution_state == "not-required"
    assert report.target_count == report.invocation_count == 0
    assert not deploy_reboot_execution_path(prepared.paths, OPERATION_ID).exists()
    assert not deploy_reboot_evidence_path(prepared.paths, OPERATION_ID).exists()
    assert runner.specs == []


def test_succeeded_prefix_resumes_only_the_next_serial_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _, executables, toolchain = _prepared(tmp_path, monkeypatch)
    original_load = reboot_execution_module._load_execution_context

    def load_two_scope_context(*args, **kwargs):
        context = original_load(*args, **kwargs)
        first = context.scopes[0]
        second_target = replace(first.target, sequence=2)
        _, validated, variables_digest, command_digest = kwargs[
            "builder"
        ].validate_operation_step(
            "deploy-reboot",
            step_sequence=2,
            limit=(second_target.stable_id,),
            variables=dict(first.variables),
            tags=("deploy-reboot",),
            check=False,
            diff=False,
            verbosity=0,
        )
        second_target_digest = reboot_execution_module._digest_object(
            second_target.to_object()
        )
        second = reboot_execution_module._RebootScope(
            target=second_target,
            variables=validated,
            variables_digest=variables_digest,
            command_digest=command_digest,
            source_digest=first.source_digest,
            request_digest=first.request_digest,
            target_plan_digest=second_target_digest,
        )
        values = {
            name: getattr(context.binding, name)
            for name in context.binding.__dataclass_fields__
        }
        values.update(
            {
                "binding_digest": "",
                "execution_scope_digest": reboot_execution_module._digest_object(
                    [
                        first.command_digest,
                        first.request_digest,
                        command_digest,
                        first.request_digest,
                    ]
                ),
                "target_count": 2,
                "target_order_digest": reboot_execution_module._digest_object(
                    [first.target.stable_id, second.target.stable_id]
                ),
                "target_set_digest": reboot_execution_module._digest_object(
                    sorted({first.target.stable_id, second.target.stable_id})
                ),
            }
        )
        values["binding_digest"] = reboot_execution_module._binding_digest_from_values(
            values
        )
        binding = reboot_execution_module.DeployRebootExecutionBinding(**values)
        return reboot_execution_module._ExecutionContext(
            context.base,
            context.reconciliation,
            context.plan,
            context.authorization,
            binding,
            (first, second),
            context.metadata,
            context.inventory,
            context.readiness,
        )

    monkeypatch.setattr(
        reboot_execution_module, "_load_execution_context", load_two_scope_context
    )
    original_write = DeployRebootExecutionStore.write_locked
    injected = False

    def fail_second_prepare(self, record, **kwargs):
        nonlocal injected
        if (
            not injected
            and record.state is DeployRebootExecutionState.PREPARED
            and len(record.attempts) == 2
        ):
            injected = True
            raise StatePersistenceError("injected pre-invocation persistence failure")
        return original_write(self, record, **kwargs)

    monkeypatch.setattr(DeployRebootExecutionStore, "write_locked", fail_second_prepare)
    runner = RebootRunner()
    with pytest.raises(StatePersistenceError, match="before invocation"):
        _call(prepared, runner, executables, toolchain)
    assert len(cast(list[dict[str, object]], runner.payloads)) == 1

    report = _call(prepared, runner, executables, toolchain)
    assert report.execution_state == "succeeded"
    assert report.target_count == report.completed_target_count == 2
    assert report.invocation_count == 2
    assert len(cast(list[dict[str, object]], runner.payloads)) == 2
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        execution = DeployRebootExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    assert tuple(attempt.sequence for attempt in execution.record.attempts) == (1, 2)
    assert all(
        attempt.state is DeployRebootExecutionState.SUCCEEDED
        for attempt in execution.record.attempts
    )


@pytest.mark.parametrize(
    "mode",
    [
        "boot-unchanged",
        "reboot-required",
        "identity-mismatch",
        "trust-mismatch",
        "os-mismatch",
        "arch-mismatch",
        "malformed",
        "unsupported-exit",
        "non-utf8",
        "oversized",
    ],
)
def test_invalid_or_unsafe_result_is_uncertain_and_never_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    prepared, _, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = RebootRunner(mode=mode)
    with pytest.raises(AnsibleError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    playbook_calls = len(cast(list[dict[str, object]], runner.payloads))
    assert playbook_calls == 1
    with pytest.raises(StateConflictError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    assert len(cast(list[dict[str, object]], runner.payloads)) == playbook_calls
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        stored = DeployRebootExecutionStore(prepared.paths, OPERATION_ID).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    assert stored.record.attempts[-1].manual_recovery_required
    assert not stored.record.attempts[-1].automatic_retry_allowed
    assert stored.record.invocation_count == 1


@pytest.mark.parametrize(
    ("mode", "exception"),
    [
        ("timeout", AnsibleError),
        ("interrupted", AnsibleError),
        ("failed", AnsibleError),
        ("active-service", AnsibleError),
        ("unreachable", AnsibleError),
    ],
)
def test_failed_or_uncertain_call_stops_without_skip_or_continue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    exception: type[BaseException],
) -> None:
    prepared, _, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = RebootRunner(mode=mode)
    with pytest.raises(exception, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        execution = DeployRebootExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence = (
            DeployRebootEvidenceStore(prepared.paths, OPERATION_ID).read_locked(
                lock,
                expected_cluster_uuid=CLUSTER_UUID,
                expected_cluster_name="example",
            )
            if deploy_reboot_evidence_path(prepared.paths, OPERATION_ID).exists()
            else None
        )
    assert len(execution.record.attempts) == 1
    assert execution.record.invocation_count == 1
    assert execution.record.attempts[-1].manual_recovery_required
    if mode in {"failed", "active-service", "unreachable"}:
        assert evidence is not None
        assert len(evidence.record.entries) == 1
        assert evidence.record.entries[0].status.value in {"failed", "unreachable"}
    else:
        assert evidence is None


def test_api_refuses_wrong_lock_and_has_no_caller_scope_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _, executables, toolchain = _prepared(tmp_path, monkeypatch)
    parameters = inspect.signature(execute_deploy_reboots).parameters
    assert set(parameters) == {
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "runner",
        "executables",
        "toolchain",
    }
    forbidden = {
        "target",
        "order",
        "limit",
        "variables",
        "playbook",
        "path",
        "command",
        "environment",
        "result",
    }
    assert forbidden.isdisjoint(parameters)
    runner = RebootRunner()
    with (
        ClusterLock(prepared.paths, "add-node", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        execute_deploy_reboots(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )
    assert runner.specs == []
