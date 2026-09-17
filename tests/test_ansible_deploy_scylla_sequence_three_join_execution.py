import base64
import hashlib
import inspect
import json
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_scylla_sequence_three_join_authorization import (
    _call as _authorize_sequence_three,
)
from test_ansible_deploy_scylla_sequence_three_join_authorization import (
    _prepared as _prepared_sequence_three_authorization,
)
from test_ansible_deploy_scylla_sequence_three_join_authorization import (
    _proof as _sequence_three_authorization_proof,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_operation_composition import _Prepared
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_scylla_sequence_three_join_authorization import (
    deploy_scylla_sequence_three_join_authorization_path,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_execution import (
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_SCHEMA_VERSION,
    DeployScyllaSequenceThreeJoinArtifactState,
    DeployScyllaSequenceThreeJoinEvidenceStore,
    DeployScyllaSequenceThreeJoinExecution,
    DeployScyllaSequenceThreeJoinExecutionState,
    DeployScyllaSequenceThreeJoinExecutionStore,
    deploy_scylla_sequence_three_join_evidence_path,
    deploy_scylla_sequence_three_join_execution_path,
    execute_deploy_scylla_sequence_three_join,
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

_HOST_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
_HOST_DIGEST = "sha256:" + hashlib.sha256(_HOST_ID.encode()).hexdigest()
_RING_DIGEST = "sha256:" + "d" * 64
_OTHER_DIGEST = "sha256:" + "f" * 64
_PRIVATE_PATH = "/private/operator/sequence-three-join.json"
_SECRET = "obviously-fake-sequence-three-join-secret"


@dataclass
class SequenceThreeJoinRunner:
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
            record = DeployScyllaSequenceThreeJoinExecution.from_object(
                json.loads(
                    deploy_scylla_sequence_three_join_execution_path(
                        self.paths, OPERATION_ID
                    ).read_text(encoding="utf-8")
                )
            )
            assert record.state is DeployScyllaSequenceThreeJoinExecutionState.STARTED
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
            authorization_path = deploy_scylla_sequence_three_join_authorization_path(
                self.paths, OPERATION_ID
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


def _prepared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[_Prepared, object, object]:
    prepared, executables, toolchain = _prepared_sequence_three_authorization(
        tmp_path, monkeypatch
    )
    _authorize_sequence_three(prepared, _sequence_three_authorization_proof(prepared))
    return prepared, executables, toolchain


def _call(
    prepared: _Prepared,
    runner: SequenceThreeJoinRunner,
    executables: object,
    toolchain: object,
):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_scylla_sequence_three_join(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )


def _records(prepared: _Prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        execution = DeployScyllaSequenceThreeJoinExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployScyllaSequenceThreeJoinEvidenceStore(
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


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for item in value.values() for key in _keys(item)}
    if isinstance(value, list):
        return {key for item in value for key in _keys(item)}
    return set()


def test_sequence_three_join_success_is_exact_redacted_and_zero_process_on_reentry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert tuple(
        inspect.signature(execute_deploy_scylla_sequence_three_join).parameters
    ) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "runner",
        "executables",
        "toolchain",
    )
    forbidden = {
        "target",
        "mode",
        "order",
        "scope",
        "variables",
        "command",
        "path",
        "result",
        "retry",
    }
    assert forbidden.isdisjoint(
        inspect.signature(execute_deploy_scylla_sequence_three_join).parameters
    )
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    authorization_path = deploy_scylla_sequence_three_join_authorization_path(
        prepared.paths, OPERATION_ID
    )
    prior = journal_path.read_bytes(), authorization_path.read_bytes()
    show_before = _run_show(prepared.paths)
    runner = SequenceThreeJoinRunner(inspect_started=True, paths=prepared.paths)

    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)

    assert evidence is not None
    assert report.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert execution.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_SCHEMA_VERSION
    )
    assert evidence.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EVIDENCE_SCHEMA_VERSION
    )
    assert (
        report.execution_state is DeployScyllaSequenceThreeJoinExecutionState.SUCCEEDED
    )
    assert (
        report.execution_artifact_state
        is DeployScyllaSequenceThreeJoinArtifactState.UPDATED
    )
    assert (
        report.evidence_artifact_state
        is DeployScyllaSequenceThreeJoinArtifactState.CREATED
    )
    assert report.sequence == 3
    assert report.mode is ScyllaBootstrapMode.JOIN_EXISTING
    assert report.survivor_count == 2
    assert report.active_seed_count == 1
    assert report.later_join_count == 1
    assert report.post_join_health_state == "not-performed"
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert not report.journal_updated
    assert (journal_path.read_bytes(), authorization_path.read_bytes()) == prior
    assert runner.specs is not None and len(runner.specs) == 3
    assert runner.payloads is not None and len(runner.payloads) == 1
    payload = runner.payloads[0]
    assert payload["logical_id"] == "scylla-ad-1-3"
    assert payload["mode"] == "join-existing"
    assert payload["seed_stable_ids"] == ["scylla-ad-1-1"]
    authorization = cast(dict[str, object], payload["authorization"])
    assert authorization["existing_member_count"] == 2
    assert authorization["healthy_member_ids"] == [
        "scylla-ad-1-1",
        "scylla-ad-1-2",
    ]
    entry = evidence.record
    assert entry.stable_id == "scylla-ad-1-3"
    assert entry.sequence == 3
    assert entry.status is ScyllaBootstrapStatus.BOOTSTRAPPED
    assert entry.mutation_boundary is MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED
    assert entry.schema_agreement and entry.streaming_complete
    assert entry.host_id_digest == _HOST_DIGEST
    for path in (
        deploy_scylla_sequence_three_join_execution_path(prepared.paths, OPERATION_ID),
        deploy_scylla_sequence_three_join_evidence_path(prepared.paths, OPERATION_ID),
    ):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    persisted = (
        deploy_scylla_sequence_three_join_execution_path(
            prepared.paths, OPERATION_ID
        ).read_text()
        + deploy_scylla_sequence_three_join_evidence_path(
            prepared.paths, OPERATION_ID
        ).read_text()
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
        '"provider_id"',
        '"command"',
        '"variables"',
        '"environment"',
        '"path"',
    ):
        assert protected not in persisted
    assert _keys(json.loads(persisted.splitlines()[0])).isdisjoint(
        {"address", "command", "environment", "output", "path", "provider_id"}
    )

    zero_runner = SequenceThreeJoinRunner(mode="timeout")
    reused = _call(prepared, zero_runner, executables, toolchain)
    assert zero_runner.specs == []
    assert (
        reused.execution_artifact_state
        is DeployScyllaSequenceThreeJoinArtifactState.REUSED
    )
    assert (
        reused.evidence_artifact_state
        is DeployScyllaSequenceThreeJoinArtifactState.REUSED
    )
    assert _run_show(prepared.paths) == show_before

    evidence_path = deploy_scylla_sequence_three_join_evidence_path(
        prepared.paths, OPERATION_ID
    )
    original = evidence_path.read_bytes()
    value = json.loads(original)
    value["sequence"] = 4
    evidence_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    evidence_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] != 0
    evidence_path.write_bytes(original)
    evidence_path.chmod(0o600)
    assert _run_show(prepared.paths, "--fail-on", "none")[0] == 0


@pytest.mark.parametrize(
    ("mode", "state"),
    (
        ("malformed", DeployScyllaSequenceThreeJoinExecutionState.MALFORMED_RESULT),
        ("timeout", DeployScyllaSequenceThreeJoinExecutionState.TIMED_OUT),
    ),
)
def test_sequence_three_join_uncertainty_is_manual_recovery_and_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    state: DeployScyllaSequenceThreeJoinExecutionState,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    with pytest.raises(AnsibleError, match="manual recovery") as caught:
        _call(
            prepared,
            SequenceThreeJoinRunner(mode=mode),
            executables,
            toolchain,
        )
    assert _PRIVATE_PATH not in str(caught.value)
    assert _SECRET not in str(caught.value)
    execution, evidence = _records(prepared)
    assert execution.record.state is state
    assert execution.record.manual_recovery_required
    assert execution.record.ordinary_authorization_consumed
    assert execution.record.narrow_authorization_consumed
    assert not execution.record.automatic_retry_allowed
    assert evidence is None
    no_retry = SequenceThreeJoinRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_sequence_three_join_prepared_resume_and_evidence_failure_never_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    original_execution_write = DeployScyllaSequenceThreeJoinExecutionStore.write_locked
    refuse_started = True

    def fail_started(self, record, **kwargs):
        nonlocal refuse_started
        if (
            record.state is DeployScyllaSequenceThreeJoinExecutionState.STARTED
            and refuse_started
        ):
            refuse_started = False
            raise StatePersistenceError("safe pre-invocation refusal")
        return original_execution_write(self, record, **kwargs)

    monkeypatch.setattr(
        DeployScyllaSequenceThreeJoinExecutionStore,
        "write_locked",
        fail_started,
    )
    first = SequenceThreeJoinRunner()
    with pytest.raises(StatePersistenceError, match="before invocation"):
        _call(prepared, first, executables, toolchain)
    execution, evidence = _records(prepared)
    assert (
        execution.record.state is DeployScyllaSequenceThreeJoinExecutionState.PREPARED
    )
    assert execution.record.invocation_count == 0
    assert not execution.record.ordinary_authorization_consumed
    assert evidence is None
    assert first.specs is not None and len(first.specs) == 2
    monkeypatch.setattr(
        DeployScyllaSequenceThreeJoinExecutionStore,
        "write_locked",
        original_execution_write,
    )

    def fail_evidence(*_args, **_kwargs):
        raise StatePersistenceError("evidence persistence failure")

    monkeypatch.setattr(
        DeployScyllaSequenceThreeJoinEvidenceStore,
        "write_locked",
        fail_evidence,
    )
    with pytest.raises(StatePersistenceError, match="manual recovery"):
        _call(prepared, SequenceThreeJoinRunner(), executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployScyllaSequenceThreeJoinExecutionState.STARTED
    assert execution.record.manual_recovery_required
    assert evidence is None
    no_retry = SequenceThreeJoinRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_sequence_three_join_tamper_drift_wrong_lock_and_later_history_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    authorization_path = deploy_scylla_sequence_three_join_authorization_path(
        prepared.paths, OPERATION_ID
    )
    original = authorization_path.read_bytes()
    value = cast(dict[str, object], json.loads(original))
    value["validated_chain_digest"] = _OTHER_DIGEST
    authorization_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    authorization_path.chmod(0o600)
    runner = SequenceThreeJoinRunner()
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
    authorization_path.write_bytes(original)
    authorization_path.chmod(0o600)

    later_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-scylla-sequence-three-join-health.json"
    )
    later_path.write_text("{}\n", encoding="utf-8")
    later_path.chmod(0o600)
    with pytest.raises(StateConflictError, match="later membership"):
        _call(prepared, SequenceThreeJoinRunner(), executables, toolchain)
    later_path.unlink()

    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        execute_deploy_scylla_sequence_three_join(
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
            SequenceThreeJoinRunner(mode="drift-after-start", paths=prepared.paths),
            executables,
            toolchain,
        )
    authorization_path.write_bytes(original)
    authorization_path.chmod(0o600)
    execution, evidence = _records(prepared)
    assert (
        execution.record.state
        is DeployScyllaSequenceThreeJoinExecutionState.MALFORMED_RESULT
    )
    assert evidence is None
