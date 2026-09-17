import base64
import inspect
import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import pytest
from test_ansible_deploy_non_jump_base_os_execution import (
    BaseOsRunner,
)
from test_ansible_deploy_non_jump_base_os_execution import (
    _call as _execute_non_jump_base_os,
)
from test_ansible_deploy_non_jump_base_os_execution import (
    _prepared as _non_jump_base_os_prepared,
)
from test_ansible_deploy_non_jump_base_os_reconciliation import (
    _call as _reconcile_non_jump_base_os,
)
from test_ansible_deploy_non_jump_reboot_authorization import (
    _call as _authorize_non_jump_reboot,
)
from test_ansible_deploy_non_jump_reboot_authorization import (
    _interactive,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_reconciliation as reconciliation_module
from scylla_vms.ansible.deploy_non_jump_reboot_authorization import (
    DeployNonJumpRebootPlanStore,
)
from scylla_vms.ansible.deploy_non_jump_reboot_execution import (
    ANSIBLE_DEPLOY_NON_JUMP_REBOOT_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_NON_JUMP_REBOOT_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_NON_JUMP_REBOOT_EXECUTION_SCHEMA_VERSION,
    DeployNonJumpRebootEvidenceStore,
    DeployNonJumpRebootExecutionState,
    DeployNonJumpRebootExecutionStore,
    deploy_non_jump_reboot_evidence_path,
    deploy_non_jump_reboot_execution_path,
    execute_deploy_non_jump_reboots,
)
from scylla_vms.ansible.deploy_reboot import DEPLOY_REBOOT_RESULT_SCHEMA_VERSION
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

_SECRET = "obviously-fake-non-jump-reboot-execution-secret"
_PRIVATE_PATH = "/private/operator/non-jump-reboot-execution.json"


@dataclass
class NonJumpRebootRunner:
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
        playbooks = [
            Path(argument).stem
            for argument in spec.argv
            if "/playbooks/" in argument and argument.endswith(".yml")
        ]
        if playbooks != ["deploy-reboot"]:
            raise AssertionError(f"unexpected product call: {playbooks}")
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
        if self.mode == "failed":
            return ProcessResult(2, self._recap(logical_id, 0, 1), _SECRET)
        if self.mode == "unreachable":
            return ProcessResult(4, self._recap(logical_id, 1, 0), _SECRET)
        value: dict[str, object] = {
            "architecture": request["architecture"],
            "boot_changed": True,
            "elapsed_seconds": 17,
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
        false_gate = {
            "reboot-not-performed": "reboot_performed",
            "reconnect-failed": "reconnected",
            "boot-unchanged": "boot_changed",
            "identity-unverified": "identity_verified",
            "trust-unverified": "trust_revalidated",
            "machine-evidence-unverified": "machine_evidence_verified",
            "unsafe-before": "services_safe_before",
            "unsafe-after": "services_safe_after",
            "reboot-required": "reboot_required_clear",
        }.get(self.mode)
        if false_gate is not None:
            value[false_gate] = False
        elif self.mode == "wrong-host":
            value["logical_id"] = "wrong-stable-id"
        elif self.mode == "wrong-role":
            value["role"] = "jump-host"
        elif self.mode == "wrong-request":
            value["request_digest"] = "sha256:" + "d" * 64
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
    mode: str = "reboot",
):
    prepared, inventory, executables, toolchain = _non_jump_base_os_prepared(
        tmp_path, monkeypatch
    )
    base_runner = BaseOsRunner(inventory, mode=mode)
    _execute_non_jump_base_os(prepared, base_runner, executables, toolchain)
    _reconcile_non_jump_base_os(prepared)
    if mode in {"reboot", "mixed-reboot"}:
        _authorize_non_jump_reboot(prepared, _interactive())
    return prepared, executables, toolchain


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_non_jump_reboots(
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
        execution = DeployNonJumpRebootExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployNonJumpRebootEvidenceStore(prepared.paths, OPERATION_ID)
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


def test_exact_serial_scope_consumes_authorization_and_reentry_is_zero_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert tuple(inspect.signature(execute_deploy_non_jump_reboots).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "runner",
        "executables",
        "toolchain",
    )
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    paths = prepared.paths
    plan = DeployNonJumpRebootPlanStore(paths, OPERATION_ID).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    journal_path = paths.operations / f"{OPERATION_ID}.json"
    authorization_path = paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-non-jump-reboot-authorization.json"
    )
    earlier_execution_path = paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-reboot-execution.json"
    )
    earlier_evidence_path = paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-reboot-evidence.json"
    )
    immutable = {
        journal_path: journal_path.read_bytes(),
        authorization_path: authorization_path.read_bytes(),
        earlier_execution_path: earlier_execution_path.read_bytes(),
        earlier_evidence_path: earlier_evidence_path.read_bytes(),
    }

    def inspect_started() -> None:
        execution = DeployNonJumpRebootExecutionStore(
            prepared.paths, OPERATION_ID
        ).read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        assert execution.record.state is DeployNonJumpRebootExecutionState.STARTED
        assert execution.record.authorization_consumed
        assert execution.record.attempts[-1].manual_recovery_required
        assert not execution.record.attempts[-1].automatic_retry_allowed

    runner = NonJumpRebootRunner(inspect_started=inspect_started)
    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert report.schema_version == (
        ANSIBLE_DEPLOY_NON_JUMP_REBOOT_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert execution.record.schema_version == (
        ANSIBLE_DEPLOY_NON_JUMP_REBOOT_EXECUTION_SCHEMA_VERSION
    )
    assert evidence is not None
    assert (
        evidence.record.schema_version
        == ANSIBLE_DEPLOY_NON_JUMP_REBOOT_EVIDENCE_SCHEMA_VERSION
    )
    assert report.execution_state == "succeeded"
    assert report.authorization_consumed
    assert report.target_count == report.completed_target_count == 3
    assert report.invocation_count == 3
    assert report.reconnect_count == report.identity_verified_count == 3
    assert report.trust_revalidated_count == 3
    assert report.machine_evidence_verified_count == 3
    assert report.service_safety_count == 3
    assert report.boot_changed_count == report.reboot_clear_count == 3
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert tuple(attempt.stable_id for attempt in execution.record.attempts) == tuple(
        target.stable_id for target in plan.record.targets
    )
    assert tuple(entry.stable_id for entry in evidence.record.entries) == tuple(
        target.stable_id for target in plan.record.targets
    )
    assert runner.payloads is not None
    assert tuple(
        cast(dict[str, object], payload["deploy_scylla_vms_deploy_reboot"])[
            "logical_id"
        ]
        for payload in runner.payloads
    ) == tuple(target.stable_id for target in plan.record.targets)
    assert all(path.read_bytes() == content for path, content in immutable.items())
    assert deploy_non_jump_reboot_execution_path(paths, OPERATION_ID) not in immutable
    assert deploy_non_jump_reboot_evidence_path(paths, OPERATION_ID) not in immutable
    assert (
        deploy_non_jump_reboot_execution_path(paths, OPERATION_ID).stat().st_mode
        & 0o777
        == 0o600
    )
    assert (
        deploy_non_jump_reboot_evidence_path(paths, OPERATION_ID).stat().st_mode & 0o777
        == 0o600
    )
    show_result = _run_show(paths)
    assert show_result[1].startswith('{"cluster":')
    assert show_result[2] == ""

    persisted = (
        deploy_non_jump_reboot_execution_path(paths, OPERATION_ID).read_text(
            encoding="utf-8"
        )
        + deploy_non_jump_reboot_evidence_path(paths, OPERATION_ID).read_text(
            encoding="utf-8"
        )
        + json.dumps(report.to_object(), sort_keys=True)
    )
    for forbidden in (
        _SECRET,
        _PRIVATE_PATH,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "ssh-ed25519",
        "fingerprint",
        "ProxyJump",
        "boot_id",
        "DSV_DEPLOY_REBOOT_B64",
        "ansible-playbook",
        "--limit",
    ):
        assert forbidden not in persisted
    process_count = len(cast(list[ProcessSpec], runner.specs))
    reused = _call(prepared, runner, executables, toolchain)
    assert reused.execution_artifact_state.value == "reused"
    assert reused.evidence_artifact_state.value == "reused"
    assert len(cast(list[ProcessSpec], runner.specs)) == process_count


def test_no_reboot_is_write_and_process_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(
        tmp_path, monkeypatch, mode="no-change"
    )
    runner = NonJumpRebootRunner()
    report = _call(prepared, runner, executables, toolchain)
    assert report.execution_state == "not-required"
    assert report.target_count == report.invocation_count == 0
    assert runner.specs == []
    assert not deploy_non_jump_reboot_execution_path(
        prepared.paths, OPERATION_ID
    ).exists()
    assert not deploy_non_jump_reboot_evidence_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_succeeded_prefix_resumes_only_next_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    original = DeployNonJumpRebootExecutionStore.write_locked
    injected = False

    def fail_second_prepare(self, record, **kwargs):
        nonlocal injected
        if (
            not injected
            and record.state is DeployNonJumpRebootExecutionState.PREPARED
            and len(record.attempts) == 2
        ):
            injected = True
            raise StatePersistenceError(
                f"injected before invocation {_SECRET} {_PRIVATE_PATH}"
            )
        return original(self, record, **kwargs)

    monkeypatch.setattr(
        DeployNonJumpRebootExecutionStore, "write_locked", fail_second_prepare
    )
    runner = NonJumpRebootRunner()
    with pytest.raises(StatePersistenceError, match="before invocation") as caught:
        _call(prepared, runner, executables, toolchain)
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    assert len(cast(list[dict[str, object]], runner.payloads)) == 1

    report = _call(prepared, runner, executables, toolchain)
    assert report.execution_state == "succeeded"
    assert report.target_count == report.invocation_count == 3
    assert len(cast(list[dict[str, object]], runner.payloads)) == 3


def test_post_call_drift_leaves_started_manual_recovery_and_never_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    original = journal_path.read_bytes()

    def drift_after_started() -> None:
        _tamper_digest(journal_path, "request_digest")

    runner = NonJumpRebootRunner(inspect_started=drift_after_started)
    with pytest.raises(StateConflictError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    assert len(cast(list[dict[str, object]], runner.payloads)) == 1
    journal_path.write_bytes(original)
    os.chmod(journal_path, 0o600)
    with pytest.raises(StateConflictError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    assert len(cast(list[dict[str, object]], runner.payloads)) == 1


@pytest.mark.parametrize(
    "mode",
    (
        "reboot-not-performed",
        "reconnect-failed",
        "boot-unchanged",
        "identity-unverified",
        "trust-unverified",
        "machine-evidence-unverified",
        "unsafe-before",
        "unsafe-after",
        "reboot-required",
        "wrong-host",
        "wrong-role",
        "wrong-request",
        "os-mismatch",
        "arch-mismatch",
        "malformed",
        "unsupported-exit",
        "non-utf8",
        "oversized",
        "timeout",
        "interrupted",
        "failed",
        "unreachable",
    ),
)
def test_started_failure_or_uncertainty_is_permanent_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = NonJumpRebootRunner(mode=mode)
    with pytest.raises((AnsibleError, StatePersistenceError), match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    payload_count = len(cast(list[dict[str, object]], runner.payloads))
    assert payload_count == 1
    with pytest.raises(StateConflictError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    assert len(cast(list[dict[str, object]], runner.payloads)) == payload_count
    execution, _evidence = _records(prepared)
    assert execution.record.invocation_count == 1
    assert len(execution.record.attempts) == 1
    assert execution.record.attempts[-1].manual_recovery_required
    assert not execution.record.attempts[-1].automatic_retry_allowed


@pytest.mark.parametrize(
    "drift",
    (
        "plan",
        "authorization",
        "reconciliation",
        "non-jump-evidence",
        "final-routes",
        "inventory",
        "trust",
        "readiness",
        "source",
        "catalog",
        "journal",
        "toolchain",
    ),
)
def test_full_chain_drift_refused_before_reboot_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    paths = prepared.paths
    if drift == "plan":
        _tamper_digest(
            paths.operations
            / f"{OPERATION_ID}.ansible-deploy-non-jump-reboot-plan.json",
            "record_digest",
        )
    elif drift == "authorization":
        _tamper_digest(
            paths.operations
            / f"{OPERATION_ID}.ansible-deploy-non-jump-reboot-authorization.json",
            "authorization_digest",
        )
    elif drift == "reconciliation":
        _tamper_digest(
            paths.operations
            / (
                f"{OPERATION_ID}."
                "ansible-deploy-post-non-jump-base-os-reconciliation.json"
            ),
            "record_digest",
        )
    elif drift == "non-jump-evidence":
        _tamper_digest(
            paths.operations
            / f"{OPERATION_ID}.ansible-deploy-non-jump-base-os-evidence.json",
            "binding",
            nested="stable_id_set_digest",
        )
    elif drift == "final-routes":
        _tamper_digest(
            paths.operations
            / f"{OPERATION_ID}.ansible-deploy-final-routes-evidence.json",
            "evidence_digest",
        )
    elif drift == "inventory":
        value = json.loads(paths.ansible_inventory.read_text(encoding="utf-8"))
        value["unexpected"] = _SECRET
        paths.ansible_inventory.write_bytes(serialize_json(value))
        os.chmod(paths.ansible_inventory, 0o600)
    elif drift == "trust":
        _tamper_digest(paths.ansible_trust, "entries_digest")
    elif drift == "readiness":
        _tamper_digest(
            paths.terraform_plans / f"{OPERATION_ID}.terraform-apply-readiness.json",
            "record_digest",
        )
    elif drift == "source":
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
    elif drift == "journal":
        _tamper_digest(paths.operations / f"{OPERATION_ID}.json", "request_digest")
    else:
        toolchain = type(toolchain)(type(toolchain.core)(2, 19, 9))
    runner = NonJumpRebootRunner()
    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _call(prepared, runner, executables, toolchain)
    assert runner.payloads == []
    assert not deploy_non_jump_reboot_execution_path(paths, OPERATION_ID).exists()
    assert not deploy_non_jump_reboot_evidence_path(paths, OPERATION_ID).exists()


@pytest.mark.parametrize("failure_point", ("started", "evidence", "terminal"))
def test_persistence_failure_never_retries_started_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = NonJumpRebootRunner()
    original_execution_write = DeployNonJumpRebootExecutionStore.write_locked
    original_evidence_write = DeployNonJumpRebootEvidenceStore.append_locked

    def fail_execution(self, record, **kwargs):
        if (
            failure_point == "started"
            and record.state is DeployNonJumpRebootExecutionState.STARTED
        ) or (
            failure_point == "terminal"
            and record.state is DeployNonJumpRebootExecutionState.SUCCEEDED
        ):
            raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")
        return original_execution_write(self, record, **kwargs)

    def fail_evidence(self, record, **kwargs):
        if failure_point == "evidence":
            raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")
        return original_evidence_write(self, record, **kwargs)

    monkeypatch.setattr(
        DeployNonJumpRebootExecutionStore, "write_locked", fail_execution
    )
    monkeypatch.setattr(
        DeployNonJumpRebootEvidenceStore, "append_locked", fail_evidence
    )
    expected = "before invocation" if failure_point == "started" else "manual recovery"
    with pytest.raises(StatePersistenceError, match=expected) as caught:
        _call(prepared, runner, executables, toolchain)
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    payload_count = len(cast(list[dict[str, object]], runner.payloads))
    if failure_point == "started":
        assert payload_count == 0
        monkeypatch.setattr(
            DeployNonJumpRebootExecutionStore,
            "write_locked",
            original_execution_write,
        )
        report = _call(prepared, runner, executables, toolchain)
        assert report.execution_state == "succeeded"
        return
    assert payload_count == 1
    with pytest.raises(StateConflictError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    assert len(cast(list[dict[str, object]], runner.payloads)) == payload_count


def test_wrong_lock_ambiguous_path_and_caller_scope_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = NonJumpRebootRunner()
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        execute_deploy_non_jump_reboots(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )
    with pytest.raises(TypeError):
        execute_deploy_non_jump_reboots(  # type: ignore[call-arg]
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=None,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
            target_ids=("forbidden",),
        )
    target = prepared.paths.operations / "fake-non-jump-reboot-execution.json"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    path = deploy_non_jump_reboot_execution_path(prepared.paths, OPERATION_ID)
    path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _call(prepared, runner, executables, toolchain)
    assert runner.payloads == []


def _tamper_digest(path: Path, field: str, *, nested: str | None = None) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    if nested is None:
        value[field] = "sha256:" + "d" * 64
    else:
        value[field][nested] = "sha256:" + "d" * 64
    path.write_bytes(serialize_json(value))
    os.chmod(path, 0o600)
