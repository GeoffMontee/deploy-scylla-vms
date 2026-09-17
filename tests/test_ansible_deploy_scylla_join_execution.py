import base64
import hashlib
import inspect
import json
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
import test_provider_source
import test_terraform_apply_inventory
import test_terraform_plan_checkpoint
from test_ansible_deploy_scylla_health_checkpoint import (
    HealthCheckpointRunner,
)
from test_ansible_deploy_scylla_health_checkpoint import (
    _call as _execute_health,
)
from test_ansible_deploy_scylla_health_checkpoint import (
    _prepared as _prepared_health,
)
from test_ansible_deploy_scylla_join_authorization import (
    _call as _authorize_join,
)
from test_ansible_deploy_scylla_join_authorization import (
    _proof as _join_authorization_proof,
)
from test_ansible_deploy_scylla_join_safety import (
    _call as _bind_join_safety,
)
from test_ansible_deploy_scylla_join_safety import (
    _multi_output,
    _multi_spec,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_scylla_join_execution import (
    ANSIBLE_DEPLOY_SCYLLA_JOIN_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_SCHEMA_VERSION,
    DeployScyllaJoinArtifactState,
    DeployScyllaJoinEvidenceStore,
    DeployScyllaJoinExecution,
    DeployScyllaJoinExecutionState,
    DeployScyllaJoinExecutionStore,
    deploy_scylla_join_evidence_path,
    deploy_scylla_join_execution_path,
    execute_deploy_scylla_first_join,
)
from scylla_vms.ansible.deploy_scylla_join_safety import (
    DeployScyllaJoinSafetyProofStatus,
)
from scylla_vms.ansible.scylla_bootstrap import (
    SCYLLA_BOOTSTRAP_SCHEMA_VERSION,
    MutationBoundary,
    ScyllaBootstrapMode,
    ScyllaBootstrapStatus,
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
from scylla_vms.process import (
    ProcessOutputError,
    ProcessResult,
    ProcessSpec,
    ProcessTimeoutError,
)
from scylla_vms.state import StatePaths

_HOST_ID = "99999999-9999-4999-8999-999999999999"
_HOST_DIGEST = "sha256:" + hashlib.sha256(_HOST_ID.encode()).hexdigest()
_RING_DIGEST = "sha256:" + "d" * 64
_OTHER_DIGEST = "sha256:" + "f" * 64
_PRIVATE_PATH = "/private/operator/first-join.json"
_SECRET = "obviously-fake-first-join-secret"


@dataclass
class FirstJoinRunner:
    mode: str = "success"
    inspect_started: bool = False
    paths: StatePaths | None = None
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
        if playbook != "scylla-bootstrap":
            raise AssertionError(f"unexpected external playbook: {playbook}")
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        variables = cast(
            dict[str, object], json.loads(runtime_file.read_text(encoding="utf-8"))
        )
        payload = cast(
            dict[str, object], variables["deploy_scylla_vms_scylla_bootstrap"]
        )
        self.payloads.append(payload)
        if self.inspect_started:
            assert self.paths is not None
            record = DeployScyllaJoinExecution.from_object(
                json.loads(
                    deploy_scylla_join_execution_path(
                        self.paths, OPERATION_ID
                    ).read_text(encoding="utf-8")
                )
            )
            assert record.state is DeployScyllaJoinExecutionState.STARTED
            assert record.ordinary_authorization_consumed
            assert record.narrow_authorization_consumed
            assert record.invocation_count == 1
        if self.mode == "timeout":
            raise ProcessTimeoutError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "runner-error":
            raise ProcessOutputError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "malformed":
            return ProcessResult(0, "malformed", f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "drift-after-start":
            assert self.paths is not None
            authorization_path = self.paths.operations / (
                f"{OPERATION_ID}.ansible-deploy-scylla-join-authorization.json"
            )
            authorization = cast(
                dict[str, object],
                json.loads(authorization_path.read_text(encoding="utf-8")),
            )
            authorization["validated_chain_digest"] = _OTHER_DIGEST
            authorization_path.write_text(
                json.dumps(authorization) + "\n", encoding="utf-8"
            )
            authorization_path.chmod(0o600)

        target = cast(str, payload["logical_id"])
        result_target = "wrong-target" if self.mode == "wrong-target" else target
        result_mode = "initial-seed" if self.mode == "wrong-mode" else payload["mode"]
        result = {
            "blockers": [],
            "datacenter": payload["datacenter"],
            "host_id_digest": _HOST_DIGEST,
            "mode": result_mode,
            "mutation_boundary": "ring-membership-may-have-changed",
            "prerequisite_digests": payload["prerequisite_digests"],
            "rack": payload["rack"],
            "recovery_required": False,
            "ring_membership_digest": _RING_DIGEST,
            "schema_version": SCYLLA_BOOTSTRAP_SCHEMA_VERSION,
            "service_state": "active",
            "status": "bootstrapped",
            "streaming_state": "complete",
            "target_logical_id": result_target,
        }
        encoded = base64.b64encode(
            json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        stdout = (
            f'{{"msg":"DSV_SCYLLA_BOOTSTRAP_B64={encoded}"}}\n'
            "PLAY RECAP *****\n"
            f"{target} : ok=15 changed=1 unreachable=0 failed=0 "
            "skipped=0 rescued=0 ignored=0\n"
        )
        return ProcessResult(0, stdout, f"{_SECRET} {_PRIVATE_PATH}")


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(test_provider_source, "_spec", _multi_spec)
    monkeypatch.setattr(test_terraform_plan_checkpoint, "_spec", _multi_spec)
    monkeypatch.setattr(test_terraform_apply_inventory, "_valid_output", _multi_output)
    prepared, executables, toolchain = _prepared_health(tmp_path, monkeypatch)
    _execute_health(
        prepared,
        HealthCheckpointRunner(),
        executables,
        toolchain,
    )
    _bind_join_safety(prepared, DeployScyllaJoinSafetyProofStatus.PASSED)
    _authorize_join(prepared, _join_authorization_proof(prepared))
    return prepared, executables, toolchain


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_scylla_first_join(
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
        execution = DeployScyllaJoinExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployScyllaJoinEvidenceStore(prepared.paths, OPERATION_ID)
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


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for item in value.values() for key in _keys(item)}
    if isinstance(value, list):
        return {key for item in value for key in _keys(item)}
    return set()


def test_first_join_success_is_redacted_and_zero_process_on_reentry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert tuple(inspect.signature(execute_deploy_scylla_first_join).parameters) == (
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
        f"{OPERATION_ID}.ansible-deploy-scylla-join-authorization.json"
    )
    immutable = journal_path.read_bytes(), authorization_path.read_bytes()
    show_before = _run_show(prepared.paths)
    runner = FirstJoinRunner(inspect_started=True, paths=prepared.paths)

    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)

    assert evidence is not None
    assert report.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert (
        execution.record.schema_version
        == ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_SCHEMA_VERSION
    )
    assert evidence.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_EVIDENCE_SCHEMA_VERSION
    )
    assert report.execution_state is DeployScyllaJoinExecutionState.SUCCEEDED
    assert report.execution_artifact_state is DeployScyllaJoinArtifactState.UPDATED
    assert report.evidence_artifact_state is DeployScyllaJoinArtifactState.CREATED
    assert report.sequence == 2
    assert report.mode is ScyllaBootstrapMode.JOIN_EXISTING
    assert report.target_count == report.invocation_count == 1
    assert report.survivor_count == report.active_seed_count == 1
    assert report.later_join_count == 1
    assert report.bootstrapped_count == 1
    assert report.host_identity_count == report.ring_identity_count == 1
    assert report.target_absence_revalidated_count == 1
    assert report.survivor_health_revalidated_count == 1
    assert report.capacity_revalidated_count == 1
    assert report.topology_revalidated_count == 1
    assert report.cql_ready_count == report.nodetool_verified_count == 1
    assert report.schema_agreement_count == report.streaming_complete_count == 1
    assert not report.manual_recovery_required
    assert not report.automatic_retry_allowed
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert not report.journal_updated
    assert (journal_path.read_bytes(), authorization_path.read_bytes()) == immutable
    assert runner.specs is not None and len(runner.specs) == 3
    assert runner.payloads is not None and len(runner.payloads) == 1
    payload = runner.payloads[0]
    assert payload["logical_id"] == "scylla-ad-1-2"
    assert payload["mode"] == "join-existing"
    assert payload["seed_stable_ids"] == ["scylla-ad-1-1"]
    authorization = cast(dict[str, object], payload["authorization"])
    assert authorization["existing_member_count"] == 1
    assert authorization["healthy_member_ids"] == ["scylla-ad-1-1"]
    assert authorization["healthy_seed_ids"] == ["scylla-ad-1-1"]

    entry = evidence.record
    assert entry.stable_id == "scylla-ad-1-2"
    assert entry.status is ScyllaBootstrapStatus.BOOTSTRAPPED
    assert entry.mutation_boundary is MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED
    assert entry.target_absence_revalidated
    assert entry.survivor_health_revalidated
    assert entry.seed_health_revalidated
    assert entry.capacity_revalidated
    assert entry.topology_revalidated
    assert entry.service_active and entry.cql_ready
    assert entry.nodetool_membership_verified
    assert entry.schema_agreement and entry.streaming_complete
    assert entry.host_id_digest == _HOST_DIGEST
    assert entry.ring_membership_digest == _RING_DIGEST
    for path in (
        deploy_scylla_join_execution_path(prepared.paths, OPERATION_ID),
        deploy_scylla_join_evidence_path(prepared.paths, OPERATION_ID),
    ):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    persisted = (
        deploy_scylla_join_execution_path(prepared.paths, OPERATION_ID).read_text()
        + deploy_scylla_join_evidence_path(prepared.paths, OPERATION_ID).read_text()
        + json.dumps(report.to_object(), sort_keys=True)
    )
    for protected in (
        _PRIVATE_PATH,
        _SECRET,
        "10.0.",
        "203.0.113.",
        "ocid1.",
        _HOST_ID,
        "SimpleSeedProvider",
        "/var/lib/scylla",
        "/etc/scylla",
        "ansible-playbook",
        "--limit",
        '"seed_stable_ids"',
        '"config_file_digests"',
        '"provider_id"',
        '"command"',
        '"variables"',
        '"environment"',
        '"path"',
    ):
        assert protected not in persisted
    assert _keys(json.loads(persisted.splitlines()[0])).isdisjoint(
        {"address", "command", "environment", "output", "path", "provider_id", "seed"}
    )

    zero_runner = FirstJoinRunner(mode="timeout")
    reused = _call(prepared, zero_runner, executables, toolchain)
    assert zero_runner.specs == []
    assert reused.execution_artifact_state is DeployScyllaJoinArtifactState.REUSED
    assert reused.evidence_artifact_state is DeployScyllaJoinArtifactState.REUSED
    assert _run_show(prepared.paths) == show_before


@pytest.mark.parametrize(
    ("mode", "state"),
    (
        ("malformed", DeployScyllaJoinExecutionState.MALFORMED_RESULT),
        ("timeout", DeployScyllaJoinExecutionState.TIMED_OUT),
        ("runner-error", DeployScyllaJoinExecutionState.MALFORMED_RESULT),
        ("wrong-target", DeployScyllaJoinExecutionState.MALFORMED_RESULT),
        ("wrong-mode", DeployScyllaJoinExecutionState.MALFORMED_RESULT),
    ),
)
def test_uncertain_result_is_manual_recovery_and_permanent_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    state: DeployScyllaJoinExecutionState,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    with pytest.raises(AnsibleError, match="manual recovery") as caught:
        _call(prepared, FirstJoinRunner(mode=mode), executables, toolchain)
    assert _PRIVATE_PATH not in str(caught.value)
    assert _SECRET not in str(caught.value)
    execution, evidence = _records(prepared)
    assert execution.record.state is state
    assert execution.record.manual_recovery_required
    assert execution.record.ordinary_authorization_consumed
    assert execution.record.narrow_authorization_consumed
    assert not execution.record.automatic_retry_allowed
    assert evidence is None
    no_retry = FirstJoinRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_prepared_prefix_recovers_but_evidence_failure_never_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    original_execution_write = DeployScyllaJoinExecutionStore.write_locked
    refuse_started = True

    def fail_started(self, record, **kwargs):
        nonlocal refuse_started
        if record.state is DeployScyllaJoinExecutionState.STARTED and refuse_started:
            refuse_started = False
            raise StatePersistenceError("safe pre-invocation refusal")
        return original_execution_write(self, record, **kwargs)

    monkeypatch.setattr(DeployScyllaJoinExecutionStore, "write_locked", fail_started)
    first = FirstJoinRunner()
    with pytest.raises(StatePersistenceError, match="before invocation"):
        _call(prepared, first, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployScyllaJoinExecutionState.PREPARED
    assert execution.record.invocation_count == 0
    assert not execution.record.ordinary_authorization_consumed
    assert evidence is None
    assert first.specs is not None and len(first.specs) == 2
    monkeypatch.setattr(
        DeployScyllaJoinExecutionStore,
        "write_locked",
        original_execution_write,
    )

    def fail_evidence(*_args, **_kwargs):
        raise StatePersistenceError("evidence persistence failure")

    monkeypatch.setattr(DeployScyllaJoinEvidenceStore, "write_locked", fail_evidence)
    with pytest.raises(StatePersistenceError, match="manual recovery"):
        _call(prepared, FirstJoinRunner(), executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployScyllaJoinExecutionState.STARTED
    assert execution.record.manual_recovery_required
    assert evidence is None
    no_retry = FirstJoinRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_terminal_write_failure_preserves_evidence_and_never_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    original_write = DeployScyllaJoinExecutionStore.write_locked

    def fail_terminal(self, record, **kwargs):
        if record.state is DeployScyllaJoinExecutionState.SUCCEEDED:
            raise StatePersistenceError("terminal persistence failure")
        return original_write(self, record, **kwargs)

    monkeypatch.setattr(DeployScyllaJoinExecutionStore, "write_locked", fail_terminal)
    with pytest.raises(StatePersistenceError, match="manual recovery"):
        _call(prepared, FirstJoinRunner(), executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployScyllaJoinExecutionState.STARTED
    assert execution.record.manual_recovery_required
    assert evidence is not None
    assert evidence.record.status is ScyllaBootstrapStatus.BOOTSTRAPPED
    no_retry = FirstJoinRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_authorization_tamper_wrong_lock_and_drift_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    authorization_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-scylla-join-authorization.json"
    )
    original = authorization_path.read_bytes()
    value = cast(dict[str, object], json.loads(original))
    value["validated_chain_digest"] = _OTHER_DIGEST
    authorization_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    authorization_path.chmod(0o600)
    runner = FirstJoinRunner()
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
    authorization_path.write_bytes(original)
    authorization_path.chmod(0o600)

    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        execute_deploy_scylla_first_join(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )

    with pytest.raises(StateConflictError, match="manual recovery"):
        _call(
            prepared,
            FirstJoinRunner(mode="drift-after-start", paths=prepared.paths),
            executables,
            toolchain,
        )
    authorization_path.write_bytes(original)
    authorization_path.chmod(0o600)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployScyllaJoinExecutionState.MALFORMED_RESULT
    assert evidence is None


def test_unsafe_execution_path_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    path = deploy_scylla_join_execution_path(prepared.paths, OPERATION_ID)
    target = path.with_name(f"{path.name}.target")
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _call(prepared, FirstJoinRunner(), executables, toolchain)


def test_show_validates_first_join_execution_and_evidence_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    _call(prepared, FirstJoinRunner(), executables, toolchain)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0
    evidence_path = deploy_scylla_join_evidence_path(prepared.paths, OPERATION_ID)
    original = evidence_path.read_bytes()
    value = json.loads(original)
    value["sequence"] = 3
    evidence_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    evidence_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
    evidence_path.write_bytes(original)
    evidence_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0
