import base64
import hashlib
import inspect
import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_scylla_bootstrap_authorization import (
    _call as _authorize_bootstrap,
)
from test_ansible_deploy_scylla_bootstrap_authorization import (
    _proof as _bootstrap_authorization_proof,
)
from test_ansible_deploy_scylla_bootstrap_plan import (
    _call as _plan_bootstrap,
)
from test_ansible_deploy_scylla_bootstrap_plan import (
    _proof as _new_cluster_proof,
)
from test_ansible_deploy_scylla_configure_execution import (
    ScyllaConfigureRunner,
)
from test_ansible_deploy_scylla_configure_execution import (
    _call as _execute_configure,
)
from test_ansible_deploy_scylla_configure_execution import (
    _prepared as _prepared_configure,
)
from test_ansible_deploy_scylla_configure_reconciliation import (
    _call as _reconcile_configure,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_scylla_bootstrap_execution import (
    ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_SCHEMA_VERSION,
    DeployScyllaBootstrapArtifactState,
    DeployScyllaBootstrapEvidenceStore,
    DeployScyllaBootstrapExecution,
    DeployScyllaBootstrapExecutionState,
    DeployScyllaBootstrapExecutionStore,
    deploy_scylla_bootstrap_evidence_path,
    deploy_scylla_bootstrap_execution_path,
    execute_deploy_scylla_bootstrap_initial_seed,
)
from scylla_vms.ansible.scylla_bootstrap import (
    SCYLLA_BOOTSTRAP_SCHEMA_VERSION,
    MutationBoundary,
    ScyllaBootstrapStatus,
)
from scylla_vms.ansible.scylla_install import (
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_RELEASE_LINE,
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

_DIGEST = "sha256:" + "a" * 64
_HOST_ID = "11111111-1111-4111-8111-111111111111"
_HOST_DIGEST = "sha256:" + hashlib.sha256(_HOST_ID.encode()).hexdigest()
_RING_DIGEST = "sha256:" + "c" * 64
_PRIVATE_PATH = "/private/operator/bootstrap-execution.json"
_SECRET = "obviously-fake-bootstrap-execution-secret"


@dataclass
class BootstrapRunner:
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
            raise AssertionError(f"unexpected playbook or external tool: {playbook}")
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
            record = DeployScyllaBootstrapExecution.from_object(
                json.loads(
                    deploy_scylla_bootstrap_execution_path(
                        self.paths, OPERATION_ID
                    ).read_text(encoding="utf-8")
                )
            )
            assert record.state is DeployScyllaBootstrapExecutionState.STARTED
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
                f"{OPERATION_ID}.ansible-deploy-scylla-bootstrap-authorization.json"
            )
            authorization = cast(
                dict[str, object],
                json.loads(authorization_path.read_text(encoding="utf-8")),
            )
            authorization["validated_chain_digest"] = _DIGEST
            authorization_path.write_text(
                json.dumps(authorization) + "\n", encoding="utf-8"
            )
            authorization_path.chmod(0o600)

        status = "bootstrapped"
        boundary = "ring-membership-may-have-changed"
        service_state = "active"
        streaming_state = "complete"
        host_digest: str | None = _HOST_DIGEST
        ring_digest: str | None = _RING_DIGEST
        blockers: list[str] = []
        recovery_required = False
        exit_code = 0
        failed = 0
        if self.mode == "never-joined":
            status = "failed"
            boundary = "service-unmasked-started"
            service_state = "masked"
            streaming_state = "unknown"
            host_digest = None
            blockers = ["execution-failed"]
            recovery_required = True
            exit_code = 2
            failed = 1
        elif self.mode == "joined-uncertain":
            status = "failed"
            service_state = "unknown-preserved"
            streaming_state = "unknown"
            host_digest = None
            blockers = ["join-incomplete"]
            recovery_required = True
            exit_code = 2
            failed = 1
        elif self.mode == "wrong-target":
            payload = dict(payload)
            payload["logical_id"] = "wrong-target"
        elif self.mode == "wrong-mode":
            status = "failed"
            boundary = "service-unmasked-started"
            service_state = "masked"
            streaming_state = "unknown"
            host_digest = None
            blockers = ["execution-failed"]
            recovery_required = True
            exit_code = 2
            failed = 1

        result = {
            "blockers": blockers,
            "datacenter": payload["datacenter"],
            "host_id_digest": host_digest,
            "mode": ("join-existing" if self.mode == "wrong-mode" else payload["mode"]),
            "mutation_boundary": boundary,
            "prerequisite_digests": payload["prerequisite_digests"],
            "rack": payload["rack"],
            "recovery_required": recovery_required,
            "ring_membership_digest": ring_digest,
            "schema_version": SCYLLA_BOOTSTRAP_SCHEMA_VERSION,
            "service_state": service_state,
            "status": status,
            "streaming_state": streaming_state,
            "target_logical_id": payload["logical_id"],
        }
        encoded = base64.b64encode(
            json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        logical_id = cast(str, payload["logical_id"])
        stdout = (
            f'{{"msg":"DSV_SCYLLA_BOOTSTRAP_B64={encoded}"}}\n'
            "PLAY RECAP *****\n"
            f"{logical_id} : ok=15 changed=1 unreachable=0 failed={failed} "
            "skipped=0 rescued=0 ignored=0\n"
        )
        return ProcessResult(exit_code, stdout, f"{_SECRET} {_PRIVATE_PATH}")


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, executables, toolchain = _prepared_configure(tmp_path, monkeypatch)
    _execute_configure(
        prepared,
        ScyllaConfigureRunner(),
        executables,
        toolchain,
    )
    _reconcile_configure(prepared)
    _plan_bootstrap(prepared, _new_cluster_proof())
    _authorize_bootstrap(prepared, _bootstrap_authorization_proof(prepared))
    return prepared, executables, toolchain


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_scylla_bootstrap_initial_seed(
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
        execution = DeployScyllaBootstrapExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployScyllaBootstrapEvidenceStore(
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


def test_exact_initial_seed_success_is_redacted_and_zero_call_on_reentry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert tuple(
        inspect.signature(execute_deploy_scylla_bootstrap_initial_seed).parameters
    ) == (
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
        f"{OPERATION_ID}.ansible-deploy-scylla-bootstrap-authorization.json"
    )
    immutable = (journal_path.read_bytes(), authorization_path.read_bytes())
    show_before = _run_show(prepared.paths)
    runner = BootstrapRunner(
        inspect_started=True,
        paths=prepared.paths,
    )
    report = _call(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert evidence is not None

    assert report.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert execution.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_SCHEMA_VERSION
    )
    assert evidence.record.schema_version == (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EVIDENCE_SCHEMA_VERSION
    )
    assert report.execution_state is DeployScyllaBootstrapExecutionState.SUCCEEDED
    assert report.execution_artifact_state is DeployScyllaBootstrapArtifactState.UPDATED
    assert report.evidence_artifact_state is DeployScyllaBootstrapArtifactState.CREATED
    assert report.ordinary_authorization_consumed
    assert report.narrow_authorization_consumed
    assert report.invocation_count == report.target_count == 1
    assert report.bootstrapped_count == 1
    assert report.host_identity_count == report.ring_identity_count == 1
    assert report.pre_start_revalidated_count == 1
    assert report.cql_ready_count == report.nodetool_verified_count == 1
    assert report.schema_agreement_count == report.streaming_complete_count == 1
    assert report.membership_may_have_changed_count == 1
    assert report.node_preserved_count == 1
    assert report.remask_count == 0
    assert not report.manual_recovery_required
    assert not report.automatic_retry_allowed
    assert not report.restart_allowed
    assert not report.destroy_allowed
    assert not report.removenode_allowed
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert not report.journal_updated
    assert report.join_authorization_state == "unavailable"
    assert report.health_reconciliation_state == "not-performed"
    assert (journal_path.read_bytes(), authorization_path.read_bytes()) == immutable
    assert _run_show(prepared.paths) == show_before
    assert runner.specs is not None and len(runner.specs) == 3
    assert runner.payloads is not None and len(runner.payloads) == 1
    payload = runner.payloads[0]
    assert payload["logical_id"] == "scylla-ad-1-1"
    assert payload["mode"] == "initial-seed"
    assert payload["seed_stable_ids"] == ["scylla-ad-1-1"]
    assert payload["release_line"] == SCYLLA_RELEASE_LINE
    assert payload["package_version"] == SCYLLA_PACKAGE_VERSION
    assert payload["bootstrap_timeout_seconds"] == 7200

    entry = evidence.record.entry
    assert entry.stable_id == "scylla-ad-1-1"
    assert entry.status is ScyllaBootstrapStatus.BOOTSTRAPPED
    assert entry.mutation_boundary is MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED
    assert entry.pre_start_revalidated
    assert entry.unmask_start_boundary_crossed
    assert entry.cql_ready and entry.nodetool_membership_verified
    assert entry.schema_agreement and entry.streaming_complete
    assert entry.node_preserved and not entry.remask_performed
    assert entry.host_id_digest == _HOST_DIGEST
    assert entry.ring_membership_digest == _RING_DIGEST
    for path in (
        deploy_scylla_bootstrap_execution_path(prepared.paths, OPERATION_ID),
        deploy_scylla_bootstrap_evidence_path(prepared.paths, OPERATION_ID),
    ):
        assert path.stat().st_mode & 0o777 == 0o600
    persisted = (
        deploy_scylla_bootstrap_execution_path(prepared.paths, OPERATION_ID).read_text(
            encoding="utf-8"
        )
        + deploy_scylla_bootstrap_evidence_path(prepared.paths, OPERATION_ID).read_text(
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
        "SimpleSeedProvider",
        "/var/lib/scylla",
        "/etc/scylla",
        "ansible-playbook",
        "--limit",
        '"seed_stable_ids"',
        '"config_file_digests"',
        '"host_id"',
        '"variables"',
        '"command"',
        '"path"',
    ):
        assert protected not in persisted

    zero_runner = BootstrapRunner(mode="timeout")
    reused = _call(prepared, zero_runner, executables, toolchain)
    assert zero_runner.specs == []
    assert reused.execution_artifact_state is DeployScyllaBootstrapArtifactState.REUSED
    assert reused.evidence_artifact_state is DeployScyllaBootstrapArtifactState.REUSED


@pytest.mark.parametrize(
    ("mode", "boundary", "remasked", "membership_may_have_changed"),
    (
        ("never-joined", MutationBoundary.SERVICE_UNMASKED_STARTED, True, False),
        (
            "joined-uncertain",
            MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED,
            False,
            True,
        ),
    ),
)
def test_strict_failed_result_preserves_recovery_semantics_and_never_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    boundary: MutationBoundary,
    remasked: bool,
    membership_may_have_changed: bool,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    with pytest.raises(AnsibleError, match="manual recovery"):
        _call(prepared, BootstrapRunner(mode=mode), executables, toolchain)
    execution, evidence = _records(prepared)
    assert evidence is not None
    assert execution.record.state is DeployScyllaBootstrapExecutionState.FAILED
    assert execution.record.ordinary_authorization_consumed
    assert execution.record.narrow_authorization_consumed
    assert execution.record.manual_recovery_required
    assert not execution.record.attempt.automatic_retry_allowed
    assert not execution.record.attempt.restart_allowed
    assert not execution.record.attempt.destroy_allowed
    assert not execution.record.attempt.removenode_allowed
    entry = evidence.record.entry
    assert entry.status is ScyllaBootstrapStatus.FAILED
    assert entry.mutation_boundary is boundary
    assert entry.remask_performed is remasked
    assert entry.never_joined_proven is remasked
    assert entry.membership_may_have_changed is membership_may_have_changed
    assert entry.node_preserved
    assert entry.recovery_required

    no_retry = BootstrapRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


@pytest.mark.parametrize(
    ("mode", "state"),
    (
        ("malformed", DeployScyllaBootstrapExecutionState.MALFORMED_RESULT),
        ("timeout", DeployScyllaBootstrapExecutionState.TIMED_OUT),
        ("runner-error", DeployScyllaBootstrapExecutionState.MALFORMED_RESULT),
        ("wrong-target", DeployScyllaBootstrapExecutionState.MALFORMED_RESULT),
        ("wrong-mode", DeployScyllaBootstrapExecutionState.MALFORMED_RESULT),
    ),
)
def test_uncertain_failures_are_permanent_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    state: DeployScyllaBootstrapExecutionState,
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    with pytest.raises(AnsibleError, match="manual recovery") as caught:
        _call(prepared, BootstrapRunner(mode=mode), executables, toolchain)
    assert _PRIVATE_PATH not in str(caught.value)
    assert _SECRET not in str(caught.value)
    execution, evidence = _records(prepared)
    assert execution.record.state is state
    assert execution.record.manual_recovery_required
    assert evidence is None
    no_retry = BootstrapRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_prepared_and_persistence_failures_respect_at_most_once_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    original_execution_write = DeployScyllaBootstrapExecutionStore.write_locked
    fail_started_once = True

    def fail_started(self, record, **kwargs):
        nonlocal fail_started_once
        if (
            record.state is DeployScyllaBootstrapExecutionState.STARTED
            and fail_started_once
        ):
            fail_started_once = False
            raise StatePersistenceError("safe pre-invocation refusal")
        return original_execution_write(self, record, **kwargs)

    monkeypatch.setattr(
        DeployScyllaBootstrapExecutionStore, "write_locked", fail_started
    )
    first = BootstrapRunner()
    with pytest.raises(StatePersistenceError, match="before invocation"):
        _call(prepared, first, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployScyllaBootstrapExecutionState.PREPARED
    assert execution.record.invocation_count == 0
    assert not execution.record.ordinary_authorization_consumed
    assert evidence is None
    assert first.specs is not None and len(first.specs) == 2
    monkeypatch.setattr(
        DeployScyllaBootstrapExecutionStore,
        "write_locked",
        original_execution_write,
    )

    def fail_evidence(*_args, **_kwargs):
        raise StatePersistenceError("evidence persistence failure")

    monkeypatch.setattr(
        DeployScyllaBootstrapEvidenceStore, "write_locked", fail_evidence
    )
    with pytest.raises(StatePersistenceError, match="manual recovery"):
        _call(prepared, BootstrapRunner(), executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployScyllaBootstrapExecutionState.STARTED
    assert execution.record.manual_recovery_required
    assert evidence is None
    no_retry = BootstrapRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_terminal_execution_write_failure_is_uncertain_and_never_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    original_write = DeployScyllaBootstrapExecutionStore.write_locked
    terminal_failed = False

    def fail_terminal(self, record, **kwargs):
        nonlocal terminal_failed
        if (
            record.state is DeployScyllaBootstrapExecutionState.SUCCEEDED
            and not terminal_failed
        ):
            terminal_failed = True
            raise StatePersistenceError("terminal persistence failure")
        return original_write(self, record, **kwargs)

    monkeypatch.setattr(
        DeployScyllaBootstrapExecutionStore, "write_locked", fail_terminal
    )
    with pytest.raises(StatePersistenceError, match="manual recovery"):
        _call(prepared, BootstrapRunner(), executables, toolchain)
    execution, evidence = _records(prepared)
    assert evidence is not None
    assert execution.record.state is DeployScyllaBootstrapExecutionState.STARTED
    assert execution.record.manual_recovery_required
    assert execution.record.invocation_count == 1
    assert not execution.record.attempt.automatic_retry_allowed
    assert not execution.record.attempt.restart_allowed
    assert not execution.record.attempt.destroy_allowed
    assert not execution.record.attempt.removenode_allowed
    no_retry = BootstrapRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_post_invocation_drift_is_manual_recovery_and_never_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    authorization_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-scylla-bootstrap-authorization.json"
    )
    authorization_bytes = authorization_path.read_bytes()
    with pytest.raises(StateConflictError, match="manual recovery"):
        _call(
            prepared,
            BootstrapRunner(mode="drift-after-start", paths=prepared.paths),
            executables,
            toolchain,
        )
    execution, evidence = _records(prepared)
    assert (
        execution.record.state is DeployScyllaBootstrapExecutionState.MALFORMED_RESULT
    )
    assert execution.record.manual_recovery_required
    assert evidence is None
    authorization_path.write_bytes(authorization_bytes)
    authorization_path.chmod(0o600)
    no_retry = BootstrapRunner()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _call(prepared, no_retry, executables, toolchain)
    assert no_retry.specs == []


def test_scope_drift_wrong_lock_unsafe_path_and_later_history_refuse_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared(tmp_path, monkeypatch)
    authorization_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-scylla-bootstrap-authorization.json"
    )
    original = authorization_path.read_bytes()
    value = cast(dict[str, object], json.loads(original.decode("utf-8")))
    value["validated_chain_digest"] = _DIGEST
    authorization_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    authorization_path.chmod(0o600)
    runner = BootstrapRunner()
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
    authorization_path.write_bytes(original)
    authorization_path.chmod(0o600)

    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        execute_deploy_scylla_bootstrap_initial_seed(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )

    later = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-scylla-health.json"
    )
    later.write_text("{}\n", encoding="utf-8")
    later.chmod(0o600)
    with pytest.raises(StateConflictError, match="later membership"):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
    later.unlink()

    path = deploy_scylla_bootstrap_execution_path(prepared.paths, OPERATION_ID)
    target = path.with_name(f"{path.name}.target")
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
