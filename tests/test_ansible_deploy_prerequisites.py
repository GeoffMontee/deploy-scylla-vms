import base64
import inspect
import json
import os
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import pytest
from test_provider_source import CLUSTER_UUID
from test_terraform_apply_readiness import (
    _call as _readiness_call,
)
from test_terraform_apply_readiness import (
    _prepared as _readiness_prepared,
)
from test_terraform_apply_readiness import (
    _runner as _readiness_runner,
)
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_prerequisites as prerequisite_module
from scylla_vms.ansible.deploy_plan import (
    DeployAnsibleContextStore,
    DeployAnsiblePlanStore,
    bind_deploy_ansible_plan,
)
from scylla_vms.ansible.deploy_prerequisites import (
    ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_PREREQUISITE_EXECUTION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_PREREQUISITE_REPORT_SCHEMA_VERSION,
    DeployPrerequisiteEvidence,
    DeployPrerequisiteEvidenceStatus,
    DeployPrerequisiteEvidenceStore,
    DeployPrerequisiteExecution,
    DeployPrerequisiteExecutionStore,
    deploy_prerequisite_evidence_path,
    deploy_prerequisite_execution_path,
    execute_deploy_ansible_prerequisites,
)
from scylla_vms.ansible.operation_execution import ExecutionAttemptState
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
from scylla_vms.process import (
    ProcessOutputError,
    ProcessResult,
    ProcessSpec,
    ProcessTimeoutError,
)

_PRIVATE_PATH = "/private/operator/id_ed25519"
_SECRET = "obviously-fake-deploy-prerequisite-secret"


@dataclass
class PrerequisiteRunner:
    inventory: Any
    mode: str = "success"
    inspect_started: Callable[[str], None] | None = None
    specs: list[ProcessSpec] | None = None
    payloads: list[dict[str, object]] | None = None

    def __post_init__(self) -> None:
        self.specs = []
        self.payloads = []

    @property
    def host_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(host.logical_id for host in self.inventory.record.inventory.hosts)
        )

    def run(self, spec: ProcessSpec) -> ProcessResult:
        assert self.specs is not None
        assert self.payloads is not None
        self.specs.append(spec)
        if spec.argv[-1] == "--version":
            name = Path(spec.argv[0]).name
            return ProcessResult(0, f"{name} [core 2.20.9]\n", "")
        if "--extra-vars" not in spec.argv:
            raise AssertionError(f"unexpected fake command: {spec.argv!r}")
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        payload = cast(
            dict[str, object],
            json.loads(runtime_file.read_text(encoding="utf-8")),
        )
        self.payloads.append(payload)
        playbook = next(
            Path(argument).stem
            for argument in spec.argv
            if "/playbooks/" in argument and argument.endswith(".yml")
        )
        if self.inspect_started is not None:
            self.inspect_started(playbook)
        if playbook == "inventory-preflight":
            if self.mode == "preflight-timeout":
                raise ProcessTimeoutError(f"{_SECRET} {_PRIVATE_PATH}")
            if self.mode == "preflight-failed":
                return ProcessResult(2, self._preflight(failed=True), _SECRET)
            return ProcessResult(0, self._preflight(), _SECRET)
        if playbook != "connectivity-check":
            raise AssertionError(f"mutating or unexpected playbook: {playbook}")
        if self.mode == "connectivity-timeout":
            raise ProcessTimeoutError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "connectivity-interrupted":
            raise KeyboardInterrupt
        if self.mode == "connectivity-non-utf8":
            raise ProcessOutputError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "connectivity-malformed":
            return ProcessResult(0, "not strict evidence", _SECRET)
        if self.mode == "connectivity-oversized":
            return ProcessResult(0, "x" * 262_145, _SECRET)
        if self.mode == "connectivity-failed":
            return ProcessResult(
                2, self._connectivity(failed=self.host_ids[0]), _SECRET
            )
        if self.mode == "connectivity-unreachable":
            return ProcessResult(
                4, self._connectivity(unreachable=self.host_ids[0]), _SECRET
            )
        if self.mode == "connectivity-missing":
            return ProcessResult(0, self._connectivity(missing=True), _SECRET)
        if self.mode == "connectivity-extra":
            return ProcessResult(0, self._connectivity(extra=True), _SECRET)
        if self.mode == "connectivity-duplicate":
            return ProcessResult(0, self._connectivity(duplicate=True), _SECRET)
        return ProcessResult(0, self._connectivity(), _SECRET)

    def _preflight(self, *, failed: bool = False) -> str:
        inventory = self.inventory
        record = inventory.record
        marker = ""
        if not failed:
            value = {
                "host_count": len(record.inventory.hosts),
                "inventory_file_digest": inventory.digest,
                "inventory_generation": record.generation,
                "observation_digest": record.source_manifest_digest,
                "observation_generation": record.source_manifest_generation,
                "schema_version": ("deploy-scylla-vms.ansible-inventory-preflight/v1"),
                "status": "passed",
                "target_count": len(self.host_ids),
            }
            encoded = base64.b64encode(
                json.dumps(value, sort_keys=True).encode()
            ).decode()
            marker = (
                f"ok: [{self.host_ids[0]}] => "
                f'{{"msg":"DSV_INVENTORY_PREFLIGHT_B64={encoded}"}}\n'
            )
        rows = []
        for index, logical_id in enumerate(self.host_ids):
            failed_count = int(failed and index == 0)
            rows.append(
                f"{logical_id} : ok=3 changed=0 unreachable=0 "
                f"failed={failed_count} skipped=0 rescued=0 ignored=0"
            )
        return marker + "PLAY RECAP *****\n" + "\n".join(rows) + "\n"

    def _connectivity(
        self,
        *,
        failed: str | None = None,
        unreachable: str | None = None,
        missing: bool = False,
        extra: bool = False,
        duplicate: bool = False,
    ) -> str:
        host_ids = self.host_ids[:-1] if missing else self.host_ids
        rows = [
            (
                f"{logical_id} : ok=2 changed=0 "
                f"unreachable={int(logical_id == unreachable)} "
                f"failed={int(logical_id == failed)} "
                "skipped=0 rescued=0 ignored=0"
            )
            for logical_id in host_ids
        ]
        if extra:
            rows.append(
                "extra-host : ok=2 changed=0 unreachable=0 failed=0 "
                "skipped=0 rescued=0 ignored=0"
            )
        if duplicate:
            rows.append(rows[0])
        return "PLAY RECAP *****\n" + "\n".join(rows) + "\n"


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, inventory, executables, toolchain = _readiness_prepared(
        tmp_path, monkeypatch
    )
    readiness_runner = _readiness_runner(inventory)
    _readiness_call(
        prepared,
        readiness_runner,
        executables,
        toolchain,
    )
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        bind_deploy_ansible_plan(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )
    return prepared, inventory, executables, toolchain


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_ansible_prerequisites(
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
        execution = DeployPrerequisiteExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence = DeployPrerequisiteEvidenceStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    return execution, evidence


def test_narrow_api_runs_exact_two_steps_and_reentry_is_zero_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(
        inspect.signature(execute_deploy_ansible_prerequisites).parameters
    ) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "runner",
        "executables",
        "toolchain",
    )
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    plan_before = DeployAnsiblePlanStore(prepared.paths, OPERATION_ID).path.read_bytes()
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()
    runner = PrerequisiteRunner(inventory)

    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)

    assert report.schema_version == ANSIBLE_DEPLOY_PREREQUISITE_REPORT_SCHEMA_VERSION
    assert report.status == "deploy-prerequisites-ready"
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert execution.record.schema_version == (
        ANSIBLE_DEPLOY_PREREQUISITE_EXECUTION_SCHEMA_VERSION
    )
    assert execution.record.generation == 4
    assert execution.record.all_steps_completed
    assert tuple(attempt.playbook for attempt in execution.record.attempts) == (
        "inventory-preflight",
        "connectivity-check",
    )
    assert all(
        attempt.state is ExecutionAttemptState.SUCCEEDED
        for attempt in execution.record.attempts
    )
    assert evidence.record.schema_version == (
        ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_SCHEMA_VERSION
    )
    assert evidence.record.generation == 2
    assert all(
        entry.status is DeployPrerequisiteEvidenceStatus.PASSED
        for entry in evidence.record.entries
    )
    assert evidence.record.entries[0].inventory_parity_status == "passed"
    assert evidence.record.entries[1].ssh_connectivity_status == "passed"
    assert evidence.record.entries[1].destination_probe_count == 0

    tampered_evidence = evidence.record.to_object()
    cast(dict[str, object], cast(list[object], tampered_evidence["entries"])[0])[
        "evidence_digest"
    ] = "sha256:" + "f" * 64
    with pytest.raises(StatePersistenceError, match="semantic evidence digest"):
        DeployPrerequisiteEvidence.from_object(tampered_evidence)

    assert runner.specs is not None
    assert runner.payloads is not None
    assert len(runner.specs) == 4
    playbook_specs = runner.specs[2:]
    assert tuple(
        next(
            Path(argument).stem
            for argument in spec.argv
            if "/playbooks/" in argument and argument.endswith(".yml")
        )
        for spec in playbook_specs
    ) == (
        "inventory-preflight",
        "connectivity-check",
    )
    host_ids = runner.host_ids
    for spec in playbook_specs:
        assert spec.argv[spec.argv.index("--limit") + 1] == ",".join(host_ids)
        assert "--tags" not in spec.argv
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
    connectivity_values = runner.payloads[1]
    assert set(runner.payloads[0]["deploy_scylla_vms_operation_targets"]) == set(
        host_ids
    )
    assert connectivity_values["deploy_scylla_vms_destination_probes"] == []
    assert connectivity_values["deploy_scylla_vms_connect_timeout_seconds"] == 10.0
    assert connectivity_values["deploy_scylla_vms_probe_timeout_seconds"] == 10
    assert (
        DeployAnsiblePlanStore(prepared.paths, OPERATION_ID).path.read_bytes()
        == plan_before
    )
    assert journal_path.read_bytes() == journal_before
    assert (
        deploy_prerequisite_execution_path(prepared.paths, OPERATION_ID).stat().st_mode
        & 0o777
        == 0o600
    )
    assert (
        deploy_prerequisite_evidence_path(prepared.paths, OPERATION_ID).stat().st_mode
        & 0o777
        == 0o600
    )
    persisted = deploy_prerequisite_execution_path(
        prepared.paths, OPERATION_ID
    ).read_text(encoding="utf-8") + deploy_prerequisite_evidence_path(
        prepared.paths, OPERATION_ID
    ).read_text(encoding="utf-8")
    for forbidden in (
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "ssh-ed25519",
        "fingerprint",
        "PLAY RECAP",
        "DSV_INVENTORY_PREFLIGHT",
        _PRIVATE_PATH,
        _SECRET,
    ):
        assert forbidden not in persisted

    zero_runner = PrerequisiteRunner(inventory, mode="connectivity-timeout")
    reused = _call(prepared, zero_runner, executables, toolchain)
    assert zero_runner.specs == []
    assert reused.to_object() == report.to_object()


def test_preflight_failure_is_durable_and_prevents_connectivity_and_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    observed_states: list[ExecutionAttemptState] = []

    def inspect_started(playbook: str) -> None:
        assert playbook == "inventory-preflight"
        value = json.loads(
            deploy_prerequisite_execution_path(prepared.paths, OPERATION_ID).read_text(
                encoding="utf-8"
            )
        )
        observed_states.append(DeployPrerequisiteExecution.from_object(value).state)

    runner = PrerequisiteRunner(
        inventory,
        mode="preflight-failed",
        inspect_started=inspect_started,
    )
    with pytest.raises(AnsibleError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert observed_states == [ExecutionAttemptState.STARTED]
    assert execution.record.state is ExecutionAttemptState.FAILED
    assert execution.record.attempts[0].manual_recovery_required
    assert not execution.record.attempts[0].automatic_retry_allowed
    assert len(evidence.record.entries) == 1
    assert evidence.record.entries[0].status is (
        DeployPrerequisiteEvidenceStatus.FAILED
    )
    assert runner.specs is not None
    assert len(runner.specs) == 3

    no_retry = PrerequisiteRunner(inventory)
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


@pytest.mark.parametrize(
    ("mode", "expected_state", "evidence_count"),
    [
        ("connectivity-failed", ExecutionAttemptState.FAILED, 2),
        ("connectivity-unreachable", ExecutionAttemptState.UNREACHABLE, 2),
        ("connectivity-timeout", ExecutionAttemptState.TIMED_OUT, 1),
        ("connectivity-interrupted", ExecutionAttemptState.INTERRUPTED, 1),
        ("connectivity-malformed", ExecutionAttemptState.MALFORMED_RESULT, 1),
        ("connectivity-non-utf8", ExecutionAttemptState.MALFORMED_RESULT, 1),
        ("connectivity-oversized", ExecutionAttemptState.MALFORMED_RESULT, 1),
        ("connectivity-missing", ExecutionAttemptState.MALFORMED_RESULT, 1),
        ("connectivity-extra", ExecutionAttemptState.MALFORMED_RESULT, 1),
        ("connectivity-duplicate", ExecutionAttemptState.MALFORMED_RESULT, 1),
    ],
)
def test_connectivity_failures_are_manual_recovery_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    expected_state: ExecutionAttemptState,
    evidence_count: int,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = PrerequisiteRunner(inventory, mode=mode)
    with pytest.raises(AnsibleError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is expected_state
    assert execution.record.attempts[0].state is ExecutionAttemptState.SUCCEEDED
    assert execution.record.attempts[1].state is expected_state
    assert execution.record.attempts[1].manual_recovery_required
    assert len(evidence.record.entries) == evidence_count
    assert runner.specs is not None
    assert len(runner.specs) == 4

    no_retry = PrerequisiteRunner(inventory)
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_succeeded_prefix_resumes_only_connectivity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    original = DeployPrerequisiteExecutionStore.write_locked
    refused = False

    def fail_second_intent(self, record, **kwargs):
        nonlocal refused
        if len(record.attempts) == 2 and not refused:
            refused = True
            raise StatePersistenceError("simulated safe pre-invocation failure")
        return original(self, record, **kwargs)

    monkeypatch.setattr(
        DeployPrerequisiteExecutionStore, "write_locked", fail_second_intent
    )
    first = PrerequisiteRunner(inventory)
    with pytest.raises(StatePersistenceError, match="pre-invocation"):
        _call(prepared, first, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is ExecutionAttemptState.SUCCEEDED
    assert len(execution.record.attempts) == 1
    assert len(evidence.record.entries) == 1
    assert first.specs is not None
    assert len(first.specs) == 3

    monkeypatch.setattr(DeployPrerequisiteExecutionStore, "write_locked", original)
    resumed = PrerequisiteRunner(inventory)
    report = _call(prepared, resumed, executables, toolchain)
    assert report.status == "deploy-prerequisites-ready"
    assert resumed.specs is not None
    assert len(resumed.specs) == 3
    assert (
        next(
            Path(argument).stem
            for argument in resumed.specs[2].argv
            if "/playbooks/" in argument and argument.endswith(".yml")
        )
        == "connectivity-check"
    )


def test_post_invocation_evidence_failure_leaves_started_and_forbids_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)

    def fail_evidence(self, record, **kwargs):
        raise StatePersistenceError(
            f"simulated {_SECRET} {_PRIVATE_PATH} persistence failure"
        )

    monkeypatch.setattr(DeployPrerequisiteEvidenceStore, "append_locked", fail_evidence)
    runner = PrerequisiteRunner(inventory)
    with pytest.raises(StatePersistenceError, match="manual recovery") as caught:
        _call(prepared, runner, executables, toolchain)
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    execution, evidence = _read_optional_records(prepared)
    assert execution is not None
    assert evidence is None
    assert execution.record.state is ExecutionAttemptState.STARTED
    assert runner.specs is not None
    assert len(runner.specs) == 3
    persisted = deploy_prerequisite_execution_path(
        prepared.paths, OPERATION_ID
    ).read_text(encoding="utf-8")
    assert _SECRET not in persisted
    assert _PRIVATE_PATH not in persisted

    no_retry = PrerequisiteRunner(inventory)
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_post_evidence_terminal_failure_is_uncertain_and_forbids_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    original = DeployPrerequisiteExecutionStore.write_locked

    def fail_terminal(self, record, **kwargs):
        if (
            len(record.attempts) == 1
            and record.attempts[0].state is ExecutionAttemptState.SUCCEEDED
        ):
            raise StatePersistenceError(f"simulated {_SECRET} terminal failure")
        return original(self, record, **kwargs)

    monkeypatch.setattr(DeployPrerequisiteExecutionStore, "write_locked", fail_terminal)
    runner = PrerequisiteRunner(inventory)
    with pytest.raises(StatePersistenceError, match="manual recovery") as caught:
        _call(prepared, runner, executables, toolchain)
    assert _SECRET not in str(caught.value)
    execution, evidence = _records(prepared)
    assert execution.record.state is ExecutionAttemptState.STARTED
    assert len(evidence.record.entries) == 1
    assert runner.specs is not None
    assert len(runner.specs) == 3

    monkeypatch.setattr(DeployPrerequisiteExecutionStore, "write_locked", original)
    no_retry = PrerequisiteRunner(inventory)
    with pytest.raises(StateConflictError, match="prefixes conflict"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_plan_context_readiness_trust_catalog_source_toolchain_and_journal_drift_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cases = (
        "plan",
        "context",
        "readiness",
        "trust",
        "catalog",
        "source",
        "toolchain",
        "journal",
    )
    for case in cases:
        case_root = tmp_path / case
        case_root.mkdir(mode=0o700)
        prepared, inventory, executables, toolchain = _prepared(case_root, monkeypatch)
        if case == "plan":
            path = DeployAnsiblePlanStore(prepared.paths, OPERATION_ID).path
            _tamper_digest(path, "record_digest")
        elif case == "context":
            path = DeployAnsibleContextStore(prepared.paths, OPERATION_ID).path
            _tamper_digest(path, "record_digest")
        elif case == "readiness":
            path = prepared.paths.terraform_plans / (
                f"{OPERATION_ID}.terraform-apply-readiness.json"
            )
            _tamper_digest(path, "readiness_digest")
        elif case == "trust":
            _tamper_digest(prepared.paths.ansible_trust, "entries_digest")
        elif case == "catalog":
            monkeypatch.setattr(
                prerequisite_module,
                "ansible_operation_catalog_digest",
                lambda: "sha256:" + "b" * 64,
            )
        elif case == "source":
            source = load_ansible_source_bundle()
            monkeypatch.setattr(
                prerequisite_module,
                "load_ansible_source_bundle",
                lambda source=source: replace_source_digest(source),
            )
        elif case == "toolchain":
            toolchain = type(toolchain)(type(toolchain.core)(2, 19, 9))
        elif case == "journal":
            _tamper_digest(
                prepared.paths.operations / f"{OPERATION_ID}.json",
                "request_digest",
            )
        runner = PrerequisiteRunner(inventory)
        with pytest.raises(
            (StateConflictError, StatePersistenceError),
        ):
            _call(prepared, runner, executables, toolchain)
        assert runner.specs == []
        monkeypatch.undo()


def test_lock_symlink_and_permissions_fail_closed_before_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = PrerequisiteRunner(inventory)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        execute_deploy_ansible_prerequisites(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )
    assert runner.specs == []

    execution_path = deploy_prerequisite_execution_path(prepared.paths, OPERATION_ID)
    target = prepared.paths.operations / "fake-target.json"
    target.write_text("{}", encoding="utf-8")
    os.chmod(target, 0o600)
    execution_path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
    execution_path.unlink()
    target.unlink()

    plan_path = DeployAnsiblePlanStore(prepared.paths, OPERATION_ID).path
    os.chmod(plan_path, 0o644)
    with pytest.raises(UnsafePathError):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []


def _read_optional_records(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        execution_store = DeployPrerequisiteExecutionStore(prepared.paths, OPERATION_ID)
        evidence_store = DeployPrerequisiteEvidenceStore(prepared.paths, OPERATION_ID)
        execution = (
            execution_store.read_locked(
                lock,
                expected_cluster_uuid=CLUSTER_UUID,
                expected_cluster_name="example",
            )
            if execution_store.path.exists()
            else None
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


def _tamper_digest(path: Path, field: str) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    value[field] = "sha256:" + "c" * 64
    path.write_text(json.dumps(value), encoding="utf-8")
    os.chmod(path, 0o600)


def replace_source_digest(source):
    return replace(source, digest="sha256:" + "d" * 64)
