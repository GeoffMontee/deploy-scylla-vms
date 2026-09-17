import base64
import inspect
import json
import os
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import pytest
from test_ansible_deploy_prerequisites import (
    PrerequisiteRunner,
)
from test_ansible_deploy_prerequisites import (
    _call as _prerequisite_call,
)
from test_ansible_deploy_prerequisites import (
    _prepared as _prerequisite_prepared,
)
from test_provider_source import CLUSTER_UUID
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_reconciliation as reconciliation_module
from scylla_vms.ansible.deploy_host_evidence import (
    ANSIBLE_DEPLOY_PRE_MUTATION_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_PRE_MUTATION_EXECUTION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_PRE_MUTATION_REPORT_SCHEMA_VERSION,
    DeployPreMutationEvidence,
    DeployPreMutationEvidenceStore,
    DeployPreMutationExecution,
    DeployPreMutationExecutionStore,
    PreMutationEvidenceStatus,
    deploy_pre_mutation_evidence_path,
    deploy_pre_mutation_execution_path,
    execute_deploy_pre_mutation_host_evidence,
)
from scylla_vms.ansible.deploy_reconciliation import (
    DeployEffectivePlanStore,
    reconcile_deploy_ansible_plan,
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
from scylla_vms.persistence import serialize_json
from scylla_vms.process import (
    ProcessOutputError,
    ProcessResult,
    ProcessSpec,
    ProcessTimeoutError,
)

_PRIVATE_PATH = "/private/operator/id_ed25519"
_SECRET = "obviously-fake-pre-mutation-secret"
_ROLE_ORDER = ("jump-host", "scylla", "manager", "monitoring")
_ROLE_SERVICES = {
    "jump-host": (),
    "scylla": ("scylla-server.service",),
    "manager": ("scylla-manager.service",),
    "monitoring": ("grafana-server.service", "prometheus.service"),
}


@dataclass
class HostEvidenceRunner:
    inventory: Any
    mode: str = "success"
    inspect_started: Callable[[str], None] | None = None
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
        if playbook != "evidence-collect":
            raise AssertionError(f"unexpected or mutating playbook: {playbook}")
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        self.payloads.append(
            cast(
                dict[str, object],
                json.loads(runtime_file.read_text(encoding="utf-8")),
            )
        )
        limit = tuple(spec.argv[spec.argv.index("--limit") + 1].split(","))
        if self.inspect_started is not None:
            self.inspect_started(limit[0])
        if self.mode == "timeout":
            raise ProcessTimeoutError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "interrupted":
            raise KeyboardInterrupt
        if self.mode == "non-utf8":
            raise ProcessOutputError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "oversized":
            return ProcessResult(0, "x" * (1024 * 1024 + 1), _SECRET)
        return self._evidence_result(limit)

    def _evidence_result(self, limit: tuple[str, ...]) -> ProcessResult:
        hosts = {
            host.logical_id: host for host in self.inventory.record.inventory.hosts
        }
        markers: list[str] = []
        recaps: list[str] = []
        for index, logical_id in enumerate(limit):
            host = hosts[logical_id]
            role = host.role.value
            unavailable = self.mode == "unreachable" and index == 0
            failed = self.mode == "failure" and index == 0
            omit = self.mode in {"missing", "malformed"} and index == 0
            value = self._host(logical_id, role)
            if self.mode == "wrong-role" and index == 0:
                value["role"] = "manager" if role != "manager" else "monitoring"
            if self.mode == "protected-os" and index == 0:
                cast(dict[str, object], value["system"])["os_name"] = "Ubuntu 10.0.0.1"
            if self.mode == "protected-provider" and index == 0:
                cast(dict[str, object], value["system"])["os_name"] = (
                    "ocid1.instance.oc1.fake"
                )
            if self.mode == "unsupported":
                system = cast(dict[str, object], value["system"])
                system["os_name"] = "Fedora"
                system["os_version"] = "41"
                system["architecture"] = "sparc64"
            if not unavailable and not omit:
                markers.append(self._marker(logical_id, value))
                if self.mode == "duplicate" and index == 0:
                    markers.append(self._marker(logical_id, value))
            recaps.append(
                f"{logical_id} : ok=8 changed=0 "
                f"unreachable={int(unavailable)} failed={int(failed)} "
                "skipped=0 rescued=0 ignored=0"
            )
        if self.mode == "extra":
            extra = self._host("extra-host", "jump-host")
            markers.append(self._marker("extra-host", extra))
            recaps.append(
                "extra-host : ok=8 changed=0 unreachable=0 failed=0 "
                "skipped=0 rescued=0 ignored=0"
            )
        stdout = "".join(markers) + "PLAY RECAP *****\n" + "\n".join(recaps) + "\n"
        exit_code = (
            4 if self.mode == "unreachable" else 2 if self.mode == "failure" else 0
        )
        return ProcessResult(exit_code, stdout, _SECRET)

    @staticmethod
    def _marker(logical_id: str, value: dict[str, object]) -> str:
        encoded = base64.b64encode(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        return f'ok: [{logical_id}] => {{"msg":"DSV_EVIDENCE_B64={encoded}"}}\n'

    @staticmethod
    def _host(logical_id: str, role: str) -> dict[str, object]:
        services = [
            {"name": name, "status": "inactive"} for name in _ROLE_SERVICES[role]
        ]
        return {
            "block_devices": {
                "items": [{"name": "sda", "rotational": False, "size": "100.00 GB"}],
                "status": "available",
            },
            "errors": [],
            "filesystems": {
                "items": [
                    {
                        "available_bytes": 80_000_000_000,
                        "mount": "/",
                        "total_bytes": 100_000_000_000,
                        "used_percent": 20.0,
                    }
                ],
                "status": "available",
            },
            "logical_id": logical_id,
            "role": role,
            "schema_version": "deploy-scylla-vms.ansible-host-evidence/v1",
            "scylla_health": {
                "status": "unavailable" if role == "scylla" else "not-performed"
            },
            "service_version": {
                "status": "not-performed" if role == "jump-host" else "unavailable",
                "value": None,
            },
            "services": services,
            "status": "complete",
            "system": {
                "architecture": "x86_64",
                "cpu_count": 4,
                "current_time": "2026-09-19T08:39:00Z",
                "kernel": "6.8.0-1018-oracle",
                "memory_mib": 8192,
                "os_name": "Ubuntu",
                "os_version": "24.04",
                "uptime_seconds": 3600,
            },
        }


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, inventory, executables, toolchain = _prerequisite_prepared(
        tmp_path, monkeypatch
    )
    _prerequisite_call(
        prepared,
        PrerequisiteRunner(inventory),
        executables,
        toolchain,
    )
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        reconcile_deploy_ansible_plan(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )
    return prepared, inventory, executables, toolchain


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_pre_mutation_host_evidence(
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
        execution = DeployPreMutationExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence = DeployPreMutationEvidenceStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    return execution, evidence


def test_narrow_role_batched_success_is_redacted_and_reentry_is_zero_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(
        inspect.signature(execute_deploy_pre_mutation_host_evidence).parameters
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
    effective_path = DeployEffectivePlanStore(prepared.paths, OPERATION_ID).path
    effective_before = effective_path.read_bytes()
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()
    runner = HostEvidenceRunner(inventory)

    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)

    assert report.schema_version == ANSIBLE_DEPLOY_PRE_MUTATION_REPORT_SCHEMA_VERSION
    assert report.status == "pre-mutation-host-evidence-collected"
    assert report.checkpoint_kind == "pre-mutation-host-evidence"
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert not report.effective_plan_reconciled
    assert report.mapped_final_evidence_state == "not-performed"
    assert execution.record.schema_version == (
        ANSIBLE_DEPLOY_PRE_MUTATION_EXECUTION_SCHEMA_VERSION
    )
    assert evidence.record.schema_version == (
        ANSIBLE_DEPLOY_PRE_MUTATION_EVIDENCE_SCHEMA_VERSION
    )
    assert execution.record.all_batches_completed
    assert execution.record.binding == evidence.record.binding
    assert tuple(entry.role.value for entry in evidence.record.entries) == tuple(
        role
        for role in _ROLE_ORDER
        if any(host.role.value == role for host in inventory.record.inventory.hosts)
    )
    assert all(
        entry.status is PreMutationEvidenceStatus.SUCCEEDED
        for entry in evidence.record.entries
    )
    assert all(
        host.reboot_required == "not-collected"
        for entry in evidence.record.entries
        for host in entry.hosts
    )
    assert report.complete_host_count == report.host_count
    assert report.host_count == len(inventory.record.inventory.hosts)

    assert runner.specs is not None
    assert runner.payloads is not None
    assert len(runner.specs) == 2 + report.batch_count
    playbook_specs = runner.specs[2:]
    expected_batches = tuple(entry.hosts for entry in evidence.record.entries)
    assert tuple(
        tuple(spec.argv[spec.argv.index("--limit") + 1].split(","))
        for spec in playbook_specs
    ) == tuple(tuple(host.logical_id for host in batch) for batch in expected_batches)
    for spec in playbook_specs:
        assert any(
            argument.endswith("/playbooks/evidence-collect.yml")
            for argument in spec.argv
        )
        assert "--check" in spec.argv
        assert "--tags" not in spec.argv
        assert "--skip-tags" not in spec.argv
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
    assert all(
        payload["deploy_scylla_vms_evidence_timeout_seconds"] == 10
        for payload in runner.payloads
    )

    assert effective_path.read_bytes() == effective_before
    assert journal_path.read_bytes() == journal_before
    assert (
        deploy_pre_mutation_execution_path(prepared.paths, OPERATION_ID).stat().st_mode
        & 0o777
        == 0o600
    )
    assert (
        deploy_pre_mutation_evidence_path(prepared.paths, OPERATION_ID).stat().st_mode
        & 0o777
        == 0o600
    )
    persisted = deploy_pre_mutation_execution_path(
        prepared.paths, OPERATION_ID
    ).read_text(encoding="utf-8") + deploy_pre_mutation_evidence_path(
        prepared.paths, OPERATION_ID
    ).read_text(encoding="utf-8")
    projected = json.dumps(report.to_object(), sort_keys=True)
    for forbidden in (
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "ssh-ed25519",
        "fingerprint",
        "/dev/",
        '"name":"sda"',
        "PLAY RECAP",
        "DSV_EVIDENCE_B64",
        "current_time",
        "kernel",
        "uptime_seconds",
        _PRIVATE_PATH,
        _SECRET,
    ):
        assert forbidden not in persisted
        assert forbidden not in projected

    zero_runner = HostEvidenceRunner(inventory, mode="timeout")
    reused = _call(prepared, zero_runner, executables, toolchain)
    assert zero_runner.specs == []
    assert reused.to_object() == report.to_object()


def test_unsupported_os_and_architecture_are_bounded_blockers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    report = _call(
        prepared,
        HostEvidenceRunner(inventory, mode="unsupported"),
        executables,
        toolchain,
    )
    blockers = dict(report.blocker_counts)
    assert blockers == {
        "unsupported-architecture": report.host_count,
        "unsupported-os-family": report.host_count,
        "unsupported-os-version": report.host_count,
    }
    assert report.blocked_host_count == report.host_count
    assert dict(report.os_counts) == {"Fedora 41": report.host_count}
    assert dict(report.architecture_counts) == {"sparc64": report.host_count}


@pytest.mark.parametrize(
    ("mode", "expected_state", "evidence_entries"),
    [
        ("timeout", ExecutionAttemptState.TIMED_OUT, 0),
        ("interrupted", ExecutionAttemptState.INTERRUPTED, 0),
        ("non-utf8", ExecutionAttemptState.MALFORMED_RESULT, 0),
        ("oversized", ExecutionAttemptState.MALFORMED_RESULT, 0),
        ("malformed", ExecutionAttemptState.MALFORMED_RESULT, 0),
        ("missing", ExecutionAttemptState.MALFORMED_RESULT, 0),
        ("extra", ExecutionAttemptState.MALFORMED_RESULT, 0),
        ("duplicate", ExecutionAttemptState.MALFORMED_RESULT, 0),
        ("wrong-role", ExecutionAttemptState.MALFORMED_RESULT, 0),
        ("protected-os", ExecutionAttemptState.MALFORMED_RESULT, 0),
        ("protected-provider", ExecutionAttemptState.MALFORMED_RESULT, 0),
        ("failure", ExecutionAttemptState.FAILED, 1),
        ("unreachable", ExecutionAttemptState.UNREACHABLE, 1),
    ],
)
def test_failed_uncertain_and_malformed_results_are_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    expected_state: ExecutionAttemptState,
    evidence_entries: int,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = HostEvidenceRunner(inventory, mode=mode)
    with pytest.raises((AnsibleError, StatePersistenceError), match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    execution_store = DeployPreMutationExecutionStore(prepared.paths, OPERATION_ID)
    evidence_store = DeployPreMutationEvidenceStore(prepared.paths, OPERATION_ID)
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        execution = execution_store.read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
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
    assert execution.record.state is expected_state
    assert execution.record.attempts[-1].manual_recovery_required
    assert not execution.record.attempts[-1].automatic_retry_allowed
    actual_evidence_entries = (
        len(evidence.record.entries) if evidence is not None else 0
    )
    assert actual_evidence_entries == evidence_entries

    no_retry = HostEvidenceRunner(inventory)
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_intent_precedes_call_and_succeeded_prefix_resumes_next_role(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    observed: list[ExecutionAttemptState] = []

    def inspect_started(_logical_id: str) -> None:
        value = json.loads(
            deploy_pre_mutation_execution_path(prepared.paths, OPERATION_ID).read_text(
                encoding="utf-8"
            )
        )
        observed.append(DeployPreMutationExecution.from_object(value).state)

    original = DeployPreMutationExecutionStore.write_locked
    refused = False

    def fail_second_intent(self, record, **kwargs):
        nonlocal refused
        if len(record.attempts) == 2 and not refused:
            refused = True
            raise StatePersistenceError("simulated safe pre-invocation failure")
        return original(self, record, **kwargs)

    monkeypatch.setattr(
        DeployPreMutationExecutionStore, "write_locked", fail_second_intent
    )
    first = HostEvidenceRunner(inventory, inspect_started=inspect_started)
    with pytest.raises(StatePersistenceError, match="pre-invocation"):
        _call(prepared, first, executables, toolchain)
    execution, evidence = _records(prepared)
    assert observed == [ExecutionAttemptState.STARTED]
    assert execution.record.state is ExecutionAttemptState.SUCCEEDED
    assert len(execution.record.attempts) == 1
    assert len(evidence.record.entries) == 1

    monkeypatch.setattr(DeployPreMutationExecutionStore, "write_locked", original)
    resumed = HostEvidenceRunner(inventory)
    report = _call(prepared, resumed, executables, toolchain)
    assert report.status == "pre-mutation-host-evidence-collected"
    assert resumed.specs is not None
    assert len(resumed.specs) == 2 + report.batch_count - 1


@pytest.mark.parametrize(
    "drift",
    ("effective-plan", "catalog", "source", "toolchain", "journal", "permissions"),
)
def test_chain_catalog_source_toolchain_and_path_drift_fail_before_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    if drift == "effective-plan":
        _tamper_digest(
            DeployEffectivePlanStore(prepared.paths, OPERATION_ID).path,
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
    elif drift == "journal":
        _tamper_digest(
            prepared.paths.operations / f"{OPERATION_ID}.json",
            "request_digest",
        )
    else:
        DeployEffectivePlanStore(prepared.paths, OPERATION_ID).path.chmod(0o644)
    runner = HostEvidenceRunner(inventory)
    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []


def test_post_invocation_persistence_failures_leave_started_and_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)

    def fail_evidence(self, record, **kwargs):
        raise StatePersistenceError(
            f"simulated {_SECRET} {_PRIVATE_PATH} persistence failure"
        )

    monkeypatch.setattr(DeployPreMutationEvidenceStore, "append_locked", fail_evidence)
    runner = HostEvidenceRunner(inventory)
    with pytest.raises(StatePersistenceError, match="manual recovery") as caught:
        _call(prepared, runner, executables, toolchain)
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    execution_store = DeployPreMutationExecutionStore(prepared.paths, OPERATION_ID)
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        execution = execution_store.read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    assert execution.record.state is ExecutionAttemptState.STARTED
    assert not deploy_pre_mutation_evidence_path(prepared.paths, OPERATION_ID).exists()


def test_post_invocation_chain_drift_leaves_started_and_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    effective_path = DeployEffectivePlanStore(prepared.paths, OPERATION_ID).path
    effective_before = effective_path.read_bytes()

    def tamper_after_intent(_logical_id: str) -> None:
        _tamper_digest(effective_path, "record_digest")

    runner = HostEvidenceRunner(inventory, inspect_started=tamper_after_intent)
    with pytest.raises(StateConflictError, match="manual recovery"):
        _call(prepared, runner, executables, toolchain)
    effective_path.write_bytes(effective_before)
    effective_path.chmod(0o600)

    no_retry = HostEvidenceRunner(inventory)
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_lock_symlink_and_ambiguous_paths_fail_before_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = HostEvidenceRunner(inventory)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        execute_deploy_pre_mutation_host_evidence(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )
    assert runner.specs == []

    execution_path = deploy_pre_mutation_execution_path(prepared.paths, OPERATION_ID)
    target = prepared.paths.operations / "fake-pre-mutation-target.json"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    execution_path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
    execution_path.unlink()
    target.unlink()

    ambiguous = prepared.paths.operations / (
        f"{{{OPERATION_ID}}}.ansible-deploy-pre-mutation-host-evidence.json"
    )
    ambiguous.write_text("{}\n", encoding="utf-8")
    ambiguous.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []


def test_persisted_models_reject_digest_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    _call(prepared, HostEvidenceRunner(inventory), executables, toolchain)
    _execution, evidence = _records(prepared)
    value = evidence.record.to_object()
    entries = cast(list[object], value["entries"])
    cast(dict[str, object], entries[0])["evidence_digest"] = "sha256:" + "f" * 64
    with pytest.raises(StatePersistenceError, match="semantic evidence digest"):
        DeployPreMutationEvidence.from_object(value)


def _tamper_digest(path: Path, field: str) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    value[field] = "sha256:" + "d" * 64
    path.write_bytes(serialize_json(value))
    os.chmod(path, 0o600)
