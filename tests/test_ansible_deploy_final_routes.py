import inspect
import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import pytest
from test_ansible_deploy_jump_host_execution import (
    JumpHostRunner,
)
from test_ansible_deploy_jump_host_execution import (
    _call as _execute_jump_host,
)
from test_ansible_deploy_jump_host_execution import (
    _prepared as _jump_host_prepared,
)
from test_ansible_deploy_jump_host_reconciliation import (
    _call as _reconcile_jump_host,
)
from test_provider_source import CLUSTER_UUID
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_final_routes as final_routes_module
import scylla_vms.ansible.deploy_reconciliation as deploy_reconciliation_module
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_final_routes import (
    ANSIBLE_DEPLOY_FINAL_ROUTES_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION,
    DeployFinalRoutesEvidenceStore,
    DeployFinalRoutesExecution,
    DeployFinalRoutesExecutionState,
    DeployFinalRoutesExecutionStore,
    DeployPostFinalRoutesReconciliationStore,
    deploy_final_routes_evidence_path,
    deploy_final_routes_execution_path,
    deploy_post_final_routes_reconciliation_path,
    execute_deploy_final_routes_connectivity,
    reconcile_deploy_final_routes_connectivity,
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

_SECRET = "obviously-fake-final-routes-secret"
_PRIVATE_PATH = "/private/operator/final-routes.json"


@dataclass
class FinalRoutesRunner:
    mode: str = "success"
    inspect_started: Any = None
    specs: list[ProcessSpec] | None = None
    variables: list[dict[str, object]] | None = None

    def __post_init__(self) -> None:
        self.specs = []
        self.variables = []

    def run(self, spec: ProcessSpec) -> ProcessResult:
        assert self.specs is not None
        assert self.variables is not None
        self.specs.append(spec)
        if spec.argv[-1] == "--version":
            name = Path(spec.argv[0]).name
            return ProcessResult(0, f"{name} [core 2.20.9]\n", "")
        playbook = next(
            Path(argument).stem
            for argument in spec.argv
            if "/playbooks/" in argument and argument.endswith(".yml")
        )
        if playbook != "connectivity-check":
            raise AssertionError(f"unexpected playbook or external tool: {playbook}")
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        variables = cast(
            dict[str, object], json.loads(runtime_file.read_text(encoding="utf-8"))
        )
        self.variables.append(variables)
        if self.inspect_started is not None:
            self.inspect_started()
        if self.mode == "timeout":
            raise ProcessTimeoutError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "interrupted":
            raise KeyboardInterrupt
        if self.mode == "non-utf8":
            raise ProcessOutputError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "oversized":
            return ProcessResult(0, "x" * (262_144 + 1), _SECRET)
        return self._result(variables)

    def _result(self, variables: dict[str, object]) -> ProcessResult:
        raw = cast(
            list[dict[str, object]],
            variables["deploy_scylla_vms_destination_probes"],
        )
        probes = [dict(item) for item in raw]
        jump_id = cast(str, probes[0]["jump_host_id"])
        if self.mode == "missing-pair":
            probes.pop()
        elif self.mode == "extra-pair":
            extra = dict(probes[0])
            extra["target_logical_id"] = "extra-target"
            probes.append(extra)
        elif self.mode == "wrong-pair":
            probes[0]["port"] = 1
        lines = []
        for index, probe in enumerate(probes):
            status = "failed" if self.mode == "pair-failed" and index == 0 else "passed"
            lines.append(
                'ok: [{jump}] => {{"msg": "DSV_TCP {jump} {target} '
                '{role} {port} {status}"}}\n'.format(
                    jump=probe["jump_host_id"],
                    target=probe["target_logical_id"],
                    role=probe["role"],
                    port=probe["port"],
                    status=status,
                )
            )
        if self.mode == "duplicate-pair":
            lines.append(lines[0])
        if self.mode == "malformed":
            return ProcessResult(0, "no recap", _SECRET)
        recap_host = "wrong-jump" if self.mode == "wrong-host" else jump_id
        unreachable = int(self.mode == "unreachable")
        failed = int(self.mode == "nonzero")
        exit_code = 4 if unreachable else 2 if failed else 0
        lines.extend(
            (
                "PLAY RECAP *****\n",
                f"{recap_host} : ok=8 changed=0 unreachable={unreachable} "
                f"failed={failed} skipped=0 rescued=0 ignored=0\n",
            )
        )
        return ProcessResult(exit_code, "".join(lines), f"{_SECRET} {_PRIVATE_PATH}")


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, executables, toolchain = _jump_host_prepared(tmp_path, monkeypatch)
    _execute_jump_host(prepared, JumpHostRunner(), executables, toolchain)
    _reconcile_jump_host(prepared)
    return prepared, executables, toolchain


def _execute(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_final_routes_connectivity(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )


def _reconcile(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_final_routes_connectivity(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _records(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        execution = DeployFinalRoutesExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployFinalRoutesEvidenceStore(prepared.paths, OPERATION_ID)
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


def test_exact_scope_command_success_reentry_and_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(
        inspect.signature(execute_deploy_final_routes_connectivity).parameters
    ) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "runner",
        "executables",
        "toolchain",
    )
    assert tuple(
        inspect.signature(reconcile_deploy_final_routes_connectivity).parameters
    ) == ("state_root", "cluster_name", "operation_id", "lock")
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()
    runner = FinalRoutesRunner()

    report = _execute(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)

    assert (
        report.schema_version
        == ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert (
        execution.record.schema_version
        == ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_SCHEMA_VERSION
    )
    assert evidence is not None
    assert (
        evidence.record.schema_version
        == ANSIBLE_DEPLOY_FINAL_ROUTES_EVIDENCE_SCHEMA_VERSION
    )
    assert report.execution_state is DeployFinalRoutesExecutionState.SUCCEEDED
    assert report.invocation_count == 1
    assert report.jump_count == report.reachable_jump_count == 1
    assert report.destination_pair_count == report.passed_pair_count == 7
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert journal_path.read_bytes() == journal_before
    assert runner.specs is not None and runner.variables is not None
    assert tuple(Path(spec.argv[0]).name for spec in runner.specs) == (
        "ansible-playbook",
        "ansible-inventory",
        "ansible-playbook",
    )
    spec = runner.specs[-1]
    assert spec.argv[spec.argv.index("--limit") + 1] == "jump-host-1"
    assert spec.argv[-1].endswith("/playbooks/connectivity-check.yml")
    assert "--tags" not in spec.argv
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
    probes = cast(
        list[dict[str, object]],
        runner.variables[0]["deploy_scylla_vms_destination_probes"],
    )
    assert len(probes) == 7
    assert {cast(str, item["jump_host_id"]) for item in probes} == {"jump-host-1"}
    assert {(cast(str, item["role"]), cast(int, item["port"])) for item in probes} == {
        ("manager", 5080),
        ("monitoring", 3000),
        ("monitoring", 9090),
        ("scylla", 7000),
        ("scylla", 7001),
        ("scylla", 9042),
        ("scylla", 9142),
    }
    assert not tuple(prepared.paths.ansible_local_tmp.iterdir())

    call_count = len(runner.specs)
    reused = _execute(prepared, runner, executables, toolchain)
    assert reused.execution_artifact_state.value == "reused"
    assert reused.evidence_artifact_state.value == "reused"
    assert len(runner.specs) == call_count

    reconciled = _reconcile(prepared)
    assert (
        reconciled.schema_version
        == ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        stored = DeployPostFinalRoutesReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    assert (
        stored.record.schema_version
        == ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION
    )
    final_routes = next(
        step for step in stored.record.steps if step.mapping_sequence == 5
    )
    assert final_routes.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
    assert (
        final_routes.evidence_state
        is DeployBaseOsReconciledEvidenceState.FINAL_ROUTES_CONNECTIVITY_BOUND
    )
    next_steps = tuple(
        step
        for step in stored.record.steps
        if step.status
        in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
    )
    assert len(next_steps) == 1
    assert next_steps[0].mapping_sequence == 6
    assert next_steps[0].playbook == "base-os"
    assert next_steps[0].condition == "non-jump-managed-hosts"
    assert (
        next_steps[0].status
        is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
    )
    assert set(next_steps[0].target_ids) == {
        "manager-1",
        "monitoring-1",
        "scylla-ad-1-1",
    }
    assert all(
        step.status
        not in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
        for step in stored.record.steps
        if step.mapping_sequence > 6
    )
    reconciliation_path = deploy_post_final_routes_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    before = reconciliation_path.stat()
    reused_reconciliation = _reconcile(prepared)
    assert reused_reconciliation.artifact_state.value == "reused"
    assert reconciliation_path.stat().st_ino == before.st_ino
    assert reconciliation_path.stat().st_mtime_ns == before.st_mtime_ns


@pytest.mark.parametrize(
    "mode",
    (
        "missing-pair",
        "extra-pair",
        "duplicate-pair",
        "wrong-pair",
        "wrong-host",
        "malformed",
        "oversized",
        "non-utf8",
    ),
)
def test_malformed_membership_and_output_are_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = FinalRoutesRunner(mode=mode)
    with pytest.raises(AnsibleError, match="manual recovery"):
        _execute(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployFinalRoutesExecutionState.MALFORMED_RESULT
    assert evidence is None
    assert execution.record.manual_recovery_required
    assert not execution.record.automatic_retry_allowed
    assert runner.variables is not None
    calls = len(runner.variables)
    with pytest.raises(StateConflictError, match="cannot retry"):
        _execute(prepared, runner, executables, toolchain)
    assert len(runner.variables) == calls
    with pytest.raises(StateConflictError):
        _reconcile(prepared)


@pytest.mark.parametrize(
    ("mode", "state", "has_evidence"),
    (
        ("pair-failed", DeployFinalRoutesExecutionState.FAILED, True),
        ("unreachable", DeployFinalRoutesExecutionState.UNREACHABLE, True),
        ("nonzero", DeployFinalRoutesExecutionState.FAILED, True),
        ("timeout", DeployFinalRoutesExecutionState.TIMED_OUT, False),
        ("interrupted", DeployFinalRoutesExecutionState.INTERRUPTED, False),
    ),
)
def test_failed_unreachable_timeout_and_interruption_are_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    state: DeployFinalRoutesExecutionState,
    has_evidence: bool,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = FinalRoutesRunner(mode=mode)
    with pytest.raises(AnsibleError, match="manual recovery"):
        _execute(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is state
    assert (evidence is not None) is has_evidence
    assert execution.record.manual_recovery_required
    assert not execution.record.automatic_retry_allowed
    assert runner.variables is not None
    calls = len(runner.variables)
    with pytest.raises(StateConflictError, match="cannot retry"):
        _execute(prepared, runner, executables, toolchain)
    assert len(runner.variables) == calls


def test_started_is_durable_before_call_and_post_call_failures_never_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    observed: list[DeployFinalRoutesExecutionState] = []

    def inspect_started() -> None:
        document = json.loads(
            deploy_final_routes_execution_path(prepared.paths, OPERATION_ID).read_text(
                encoding="utf-8"
            )
        )
        record = DeployFinalRoutesExecution.from_object(document)
        observed.append(record.state)
        assert record.invocation_count == 1
        assert record.manual_recovery_required

    def fail_evidence(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(DeployFinalRoutesEvidenceStore, "write_locked", fail_evidence)
    runner = FinalRoutesRunner(inspect_started=inspect_started)
    with pytest.raises(StatePersistenceError, match="manual recovery") as caught:
        _execute(prepared, runner, executables, toolchain)
    assert observed == [DeployFinalRoutesExecutionState.STARTED]
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployFinalRoutesExecutionState.STARTED
    assert evidence is None
    assert runner.variables is not None
    calls = len(runner.variables)
    with pytest.raises(StateConflictError, match="cannot retry"):
        _execute(prepared, runner, executables, toolchain)
    assert len(runner.variables) == calls


@pytest.mark.parametrize(
    "drift",
    (
        "post-jump",
        "inventory",
        "trust",
        "readiness",
        "journal",
        "source",
        "catalog",
        "toolchain",
    ),
)
def test_full_chain_route_trust_source_catalog_toolchain_and_journal_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    paths = prepared.paths
    selected = {
        "post-jump": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-post-jump-host-configure-reconciliation.json",
        "inventory": paths.ansible_inventory,
        "trust": paths.ansible_trust,
        "readiness": paths.terraform_plans
        / f"{OPERATION_ID}.terraform-apply-readiness.json",
        "journal": paths.operations / f"{OPERATION_ID}.json",
    }
    if drift == "source":
        source = load_ansible_source_bundle()
        monkeypatch.setattr(
            deploy_reconciliation_module,
            "load_ansible_source_bundle",
            lambda: replace(source, digest="sha256:" + "a" * 64),
        )
    elif drift == "catalog":
        monkeypatch.setattr(
            deploy_reconciliation_module,
            "ansible_operation_catalog_digest",
            lambda: "sha256:" + "b" * 64,
        )
    elif drift == "toolchain":
        toolchain = type(toolchain)(type(toolchain.core)(2, 19, 9))
    else:
        document = json.loads(selected[drift].read_text(encoding="utf-8"))
        document["unexpected"] = _SECRET
        selected[drift].write_bytes(serialize_json(document))
        os.chmod(selected[drift], 0o600)
    runner = FinalRoutesRunner()
    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _execute(prepared, runner, executables, toolchain)
    assert runner.specs == []
    assert not deploy_final_routes_execution_path(prepared.paths, OPERATION_ID).exists()


def test_route_scope_refuses_public_direct_unknown_and_arbitrary_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    parameters = inspect.signature(execute_deploy_final_routes_connectivity).parameters
    assert {
        "playbook",
        "target",
        "targets",
        "destination",
        "host",
        "port",
        "role",
        "limit",
        "variables",
        "command",
        "path",
        "environment",
        "result",
        "status",
    }.isdisjoint(parameters)
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        post = final_routes_module._load_post_jump_context(
            prepared.paths, OPERATION_ID, lock=lock
        )
        inventory = (
            post.post.base.host.loaded.planning.base.deploy.inventory.record.inventory
        )
    hosts = list(inventory.hosts)
    private = next(host for host in hosts if host.role.value == "scylla")
    public = replace(private, private_address="203.0.113.8", ansible_host="203.0.113.8")
    with pytest.raises(StateConflictError):
        final_routes_module._derive_destination_pairs((public,), ("jump-host-1",))
    direct = replace(private, route_mode="direct", jump_host_id=None)
    with pytest.raises(StateConflictError):
        final_routes_module._derive_destination_pairs((direct,), ("jump-host-1",))
    runner = FinalRoutesRunner()
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        execute_deploy_final_routes_connectivity(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )
    assert runner.specs == []


def test_paths_permissions_redaction_and_reconciliation_write_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    execution_path = deploy_final_routes_execution_path(prepared.paths, OPERATION_ID)
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    outside.chmod(0o600)
    execution_path.symlink_to(outside)
    with pytest.raises(UnsafePathError):
        _execute(prepared, FinalRoutesRunner(), executables, toolchain)
    execution_path.unlink()
    outside.unlink()

    report = _execute(prepared, FinalRoutesRunner(), executables, toolchain)
    evidence_path = deploy_final_routes_evidence_path(prepared.paths, OPERATION_ID)
    for path in (execution_path, evidence_path):
        assert path.stat().st_mode & 0o777 == 0o600
    serialized = (
        execution_path.read_text(encoding="utf-8")
        + evidence_path.read_text(encoding="utf-8")
        + json.dumps(report.to_object(), sort_keys=True)
    )
    for protected in (
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "ssh-ed25519",
        "SHA256:",
        "DSV_TCP",
        "PLAY RECAP",
        "--limit",
        "ansible-playbook",
        "deploy_scylla_vms_",
        _PRIVATE_PATH,
        _SECRET,
    ):
        assert protected not in serialized

    original = DeployPostFinalRoutesReconciliationStore.write_locked
    failed = False

    def fail_once(self, record, **kwargs):
        nonlocal failed
        if not failed:
            failed = True
            raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")
        return original(self, record, **kwargs)

    monkeypatch.setattr(
        DeployPostFinalRoutesReconciliationStore, "write_locked", fail_once
    )
    with pytest.raises(StatePersistenceError) as caught:
        _reconcile(prepared)
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    assert not deploy_post_final_routes_reconciliation_path(
        prepared.paths, OPERATION_ID
    ).exists()
    reconciled = _reconcile(prepared)
    assert reconciled.artifact_state.value == "created"
