import inspect
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from test_terraform_apply_authorization import (
    _authorize,
    _destructive_proof,
    _ordinary,
)
from test_terraform_operation_composition import _compose, _prepare, _rewrite_json
from test_terraform_plan_checkpoint import (
    ADDRESS_MARKER,
    OPERATION_ID,
    SECRET_MARKER,
    _change,
    _toolchain,
)
from test_terraform_state_safeguard import _safeguard

from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    ToolExecutionError,
    UnsafePathError,
)
from scylla_vms.journal import (
    EvidenceResult,
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.process import (
    ProcessOutputError,
    ProcessResult,
    ProcessSpec,
    ProcessTimeoutError,
)
from scylla_vms.terraform.apply_execution import (
    TERRAFORM_APPLY_EXECUTION_REPORT_SCHEMA_VERSION,
    TERRAFORM_APPLY_EXECUTION_SCHEMA_VERSION,
    TerraformApplyExecutionState,
    TerraformApplyExecutionStore,
    execute_deploy_apply,
    terraform_apply_execution_path,
)
from scylla_vms.terraform.commands import TerraformCommandBuilder
from scylla_vms.terraform.service import TerraformService
from scylla_vms.terraform.state_safeguard import terraform_state_backup_path
from scylla_vms.terraform.toolchain import TerraformToolchain, TerraformVersion

_OTHER_DIGEST = "sha256:" + "f" * 64


def _executable(tmp_path: Path) -> Path:
    path = tmp_path / "terraform"
    path.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    path.chmod(0o700)
    return path


def _ready(tmp_path: Path, *, write_state: bool = True):
    prepared = _prepare(tmp_path, write_state=write_state)
    _compose(prepared)
    _authorize(prepared, _ordinary())
    _safeguard(prepared)
    return prepared


def _execute(prepared, executable: Path, runner, *, toolchain=None):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_apply(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            lock,
            runner,
            executable,
            toolchain or _toolchain(),
        )


class FakeRunner:
    def __init__(
        self,
        *,
        exit_code: int = 0,
        failure: str | None = None,
        inspect_started: Callable[[], None] | None = None,
    ) -> None:
        self.exit_code = exit_code
        self.failure = failure
        self.inspect_started = inspect_started
        self.calls: list[ProcessSpec] = []

    def run(self, spec: ProcessSpec) -> ProcessResult:
        self.calls.append(spec)
        if self.inspect_started is not None:
            self.inspect_started()
        if self.failure == "timeout":
            raise ProcessTimeoutError("fake timeout SHOULD-NOT-PERSIST")
        if self.failure in {"non-utf8", "oversized"}:
            raise ProcessOutputError("fake invalid output SHOULD-NOT-PERSIST")
        if self.failure == "interrupted":
            raise KeyboardInterrupt
        if self.failure == "error":
            raise ToolExecutionError("fake runner error SHOULD-NOT-PERSIST")
        if self.failure == "malformed":
            return ProcessResult(999, "SHOULD-NOT-PERSIST", "")
        return ProcessResult(
            self.exit_code,
            f"stdout {SECRET_MARKER} {ADDRESS_MARKER}",
            "provider diagnostic SHOULD-NOT-PERSIST",
        )


def test_exact_apply_command_environment_and_success_pending_verification(
    tmp_path: Path,
) -> None:
    prepared = _ready(tmp_path)
    executable = _executable(tmp_path)
    authorization_path = (
        prepared.paths.terraform_plans
        / f"{OPERATION_ID}.terraform-apply-authorization.json"
    )
    authorization_before = authorization_path.read_bytes()

    def inspect_started() -> None:
        value = json.loads(
            terraform_apply_execution_path(prepared.paths, OPERATION_ID).read_text(
                encoding="utf-8"
            )
        )
        assert value["execution_state"] == "started"
        assert value["authorization_consumed"] is True
        assert value["generation"] == 2

    runner = FakeRunner(inspect_started=inspect_started)
    report = _execute(prepared, executable, runner)
    execution_path = terraform_apply_execution_path(prepared.paths, OPERATION_ID)
    persisted = execution_path.read_text(encoding="utf-8")
    projection = json.dumps(report.to_object(), sort_keys=True)

    assert report.schema_version == TERRAFORM_APPLY_EXECUTION_REPORT_SCHEMA_VERSION
    assert report.execution_schema_version == TERRAFORM_APPLY_EXECUTION_SCHEMA_VERSION
    assert report.execution_state is (
        TerraformApplyExecutionState.PROCESS_SUCCEEDED_VERIFICATION_PENDING
    )
    assert report.exit_code == 0
    assert report.runner_invoked is True
    assert report.invocation_may_have_occurred is True
    assert report.authorization_consumed is True
    assert report.terminal_outcome_persisted is True
    assert report.verification_required is True
    assert report.manual_recovery_required is False
    assert report.automatic_retry_allowed is False
    assert execution_path.stat().st_mode & 0o777 == 0o600
    assert authorization_path.read_bytes() == authorization_before

    assert len(runner.calls) == 1
    call = runner.calls[0]
    assert call.argv == (
        str(executable),
        f"-chdir={prepared.paths.terraform_work}",
        "apply",
        "-input=false",
        "-no-color",
        "-lock=true",
        "-lock-timeout=30s",
        str(prepared.paths.terraform_plans / f"{OPERATION_ID}.tfplan"),
    )
    assert call.cwd == prepared.paths.cluster_root
    assert call.timeout_seconds == 300.0
    assert call.max_output_bytes == 4 * 1024 * 1024
    expected_environment = {
        "CHECKPOINT_DISABLE",
        "HOME",
        "LANG",
        "LC_ALL",
        "TF_DATA_DIR",
        "TF_IN_AUTOMATION",
        "TF_INPUT",
        "TF_PLUGIN_CACHE_DIR",
    }
    if sys.platform == "darwin":
        expected_environment.add("__CF_USER_TEXT_ENCODING")
    assert set(call.environment.names) == expected_environment
    assert call.environment.for_subprocess()["TF_DATA_DIR"] == str(
        prepared.paths.terraform_data
    )
    assert call.environment.for_subprocess()["TF_PLUGIN_CACHE_DIR"] == str(
        prepared.paths.terraform_plugin_cache
    )
    forbidden = (
        "-auto-approve",
        "-destroy",
        "-target",
        "-replace",
        "-refresh-only",
        "-parallelism",
        "-var",
        "-var-file",
        "TF_CLI_ARGS",
        "TF_VAR_",
        "TF_WORKSPACE",
        "HTTP_PROXY",
    )
    assert not any(
        argument == item or argument.startswith(f"{item}=")
        for argument in call.argv
        for item in forbidden
    )
    assert not any(
        name.startswith(("TF_CLI_ARGS", "TF_VAR_", "TF_WORKSPACE")) or "PROXY" in name
        for name in call.environment.names
    )
    journal = json.loads(
        (prepared.paths.operations / f"{OPERATION_ID}.json").read_text(encoding="utf-8")
    )
    assert journal["generation"] == 3
    assert journal["status"] == JournalStatus.IN_PROGRESS.value
    assert journal["phase"] == OperationPhase.EXECUTE.value
    assert journal["evidence"][1]["phase"] == OperationPhase.EXECUTE.value
    assert journal["evidence"][1]["result"] == EvidenceResult.VALIDATED.value
    assert journal["evidence"][1]["summary_code"] == "terraform-apply-intent"
    for protected in (
        SECRET_MARKER,
        ADDRESS_MARKER,
        "SHOULD-NOT-PERSIST",
        str(tmp_path),
        "apply -input",
        "TF_DATA_DIR",
        "resources",
        "instances",
    ):
        assert protected not in persisted
        assert protected not in projection


@pytest.mark.parametrize(
    ("failure", "exit_code", "expected"),
    [
        (None, 1, TerraformApplyExecutionState.PROCESS_FAILED_UNCERTAIN),
        ("timeout", 0, TerraformApplyExecutionState.PROCESS_TIMED_OUT_UNCERTAIN),
        (
            "interrupted",
            0,
            TerraformApplyExecutionState.PROCESS_INTERRUPTED_UNCERTAIN,
        ),
        (
            "non-utf8",
            0,
            TerraformApplyExecutionState.PROCESS_OUTPUT_INVALID_UNCERTAIN,
        ),
        (
            "oversized",
            0,
            TerraformApplyExecutionState.PROCESS_OUTPUT_INVALID_UNCERTAIN,
        ),
        ("error", 0, TerraformApplyExecutionState.PROCESS_ERROR_UNCERTAIN),
        (
            "malformed",
            0,
            TerraformApplyExecutionState.PROCESS_MALFORMED_RESULT_UNCERTAIN,
        ),
    ],
)
def test_uncertain_process_outcomes_are_terminal_and_nonretryable(
    tmp_path: Path,
    failure: str | None,
    exit_code: int,
    expected: TerraformApplyExecutionState,
) -> None:
    prepared = _ready(tmp_path)
    runner = FakeRunner(exit_code=exit_code, failure=failure)

    report = _execute(prepared, _executable(tmp_path), runner)

    assert report.execution_state is expected
    assert report.manual_recovery_required is True
    assert report.verification_required is True
    assert report.automatic_retry_allowed is False
    assert report.exit_code == (exit_code if failure is None else None)
    assert len(runner.calls) == 1


def test_exact_terminal_reentry_never_invokes_runner_again(tmp_path: Path) -> None:
    prepared = _ready(tmp_path)
    executable = _executable(tmp_path)
    first = FakeRunner()
    created = _execute(prepared, executable, first)
    execution_before = terraform_apply_execution_path(
        prepared.paths, OPERATION_ID
    ).read_bytes()
    journal_before = (prepared.paths.operations / f"{OPERATION_ID}.json").read_bytes()
    replay = FakeRunner()

    report = _execute(prepared, executable, replay)

    assert not replay.calls
    assert report.runner_invoked is False
    assert report.invocation_may_have_occurred is True
    assert report.execution_state is created.execution_state
    assert report.execution_record_digest == created.execution_record_digest
    assert (
        terraform_apply_execution_path(prepared.paths, OPERATION_ID).read_bytes()
        == execution_before
    )
    assert (
        prepared.paths.operations / f"{OPERATION_ID}.json"
    ).read_bytes() == journal_before


def test_absent_initial_state_uses_bound_absence_proof_without_fake_backup(
    tmp_path: Path,
) -> None:
    prepared = _ready(tmp_path, write_state=False)
    runner = FakeRunner()

    report = _execute(prepared, _executable(tmp_path), runner)
    value = json.loads(
        terraform_apply_execution_path(prepared.paths, OPERATION_ID).read_text(
            encoding="utf-8"
        )
    )

    assert report.execution_state is (
        TerraformApplyExecutionState.PROCESS_SUCCEEDED_VERIFICATION_PENDING
    )
    assert value["backup_digest"] is None
    assert isinstance(value["absent_proof_digest"], str)
    assert not terraform_state_backup_path(prepared.paths, OPERATION_ID).exists()
    assert len(runner.calls) == 1


def test_prepared_prefix_recovers_exactly_without_prior_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _ready(tmp_path)
    executable = _executable(tmp_path)
    original_write = OperationJournalStore.write

    def fail_intent(self, record, *, expected_generation, expected_digest):
        del self, record, expected_generation, expected_digest
        raise StatePersistenceError("injected intent journal write failure")

    monkeypatch.setattr(OperationJournalStore, "write", fail_intent)
    failed_runner = FakeRunner()
    with pytest.raises(StatePersistenceError, match="injected intent"):
        _execute(prepared, executable, failed_runner)
    assert not failed_runner.calls
    prepared_value = json.loads(
        terraform_apply_execution_path(prepared.paths, OPERATION_ID).read_text(
            encoding="utf-8"
        )
    )
    assert prepared_value["execution_state"] == "prepared"
    assert prepared_value["authorization_consumed"] is False

    monkeypatch.setattr(OperationJournalStore, "write", original_write)
    runner = FakeRunner()
    report = _execute(prepared, executable, runner)
    assert report.recovered_prepared_prefix is True
    assert len(runner.calls) == 1


def test_prepared_record_write_failure_precedes_journal_and_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _ready(tmp_path)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_before = journal_path.read_bytes()
    original_write = TerraformApplyExecutionStore.write_locked

    def fail_prepared(self, record, *, expected_generation, expected_digest, lock):
        if record.execution_state is TerraformApplyExecutionState.PREPARED:
            raise StatePersistenceError("injected prepared write failure")
        return original_write(
            self,
            record,
            expected_generation=expected_generation,
            expected_digest=expected_digest,
            lock=lock,
        )

    monkeypatch.setattr(TerraformApplyExecutionStore, "write_locked", fail_prepared)
    runner = FakeRunner()
    with pytest.raises(StatePersistenceError, match="injected prepared"):
        _execute(prepared, _executable(tmp_path), runner)
    assert not runner.calls
    assert journal_path.read_bytes() == journal_before
    assert not terraform_apply_execution_path(prepared.paths, OPERATION_ID).exists()


def test_started_record_write_failure_precedes_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _ready(tmp_path)
    original_write = TerraformApplyExecutionStore.write_locked

    def fail_started(self, record, *, expected_generation, expected_digest, lock):
        if record.execution_state is TerraformApplyExecutionState.STARTED:
            raise StatePersistenceError("injected started write failure")
        return original_write(
            self,
            record,
            expected_generation=expected_generation,
            expected_digest=expected_digest,
            lock=lock,
        )

    monkeypatch.setattr(TerraformApplyExecutionStore, "write_locked", fail_started)
    runner = FakeRunner()
    with pytest.raises(StatePersistenceError, match="injected started"):
        _execute(prepared, _executable(tmp_path), runner)
    assert not runner.calls
    value = json.loads(
        terraform_apply_execution_path(prepared.paths, OPERATION_ID).read_text(
            encoding="utf-8"
        )
    )
    assert value["execution_state"] == "prepared"
    journal = json.loads(
        (prepared.paths.operations / f"{OPERATION_ID}.json").read_text(encoding="utf-8")
    )
    assert journal["phase"] == OperationPhase.EXECUTE.value
    monkeypatch.setattr(TerraformApplyExecutionStore, "write_locked", original_write)
    recovered = FakeRunner()
    report = _execute(prepared, _executable(tmp_path), recovered)
    assert report.recovered_prepared_prefix is True
    assert len(recovered.calls) == 1


def test_terminal_persistence_failure_leaves_started_and_forbids_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _ready(tmp_path)
    executable = _executable(tmp_path)
    original_write = TerraformApplyExecutionStore.write_locked

    def fail_terminal(self, record, *, expected_generation, expected_digest, lock):
        if record.generation == 3:
            raise StatePersistenceError("injected terminal persistence failure")
        return original_write(
            self,
            record,
            expected_generation=expected_generation,
            expected_digest=expected_digest,
            lock=lock,
        )

    monkeypatch.setattr(TerraformApplyExecutionStore, "write_locked", fail_terminal)
    first = FakeRunner()
    with pytest.raises(StatePersistenceError, match="injected terminal"):
        _execute(prepared, executable, first)
    assert len(first.calls) == 1
    value = json.loads(
        terraform_apply_execution_path(prepared.paths, OPERATION_ID).read_text(
            encoding="utf-8"
        )
    )
    assert value["execution_state"] == "started"
    assert value["authorization_consumed"] is True

    monkeypatch.setattr(TerraformApplyExecutionStore, "write_locked", original_write)
    replay = FakeRunner()
    report = _execute(prepared, executable, replay)
    assert not replay.calls
    assert report.runner_invoked is False
    assert report.execution_state is TerraformApplyExecutionState.STARTED
    assert report.manual_recovery_required is True
    assert report.terminal_outcome_persisted is False


def test_no_change_plan_is_refused_without_execution_record(tmp_path: Path) -> None:
    prepared = _prepare(tmp_path, resource_changes=[])
    _compose(prepared)
    runner = FakeRunner()
    with (
        ClusterLock(prepared.paths, "deploy", 0) as lock,
        pytest.raises(StateConflictError, match="apply-required"),
    ):
        execute_deploy_apply(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            lock,
            runner,
            _executable(tmp_path),
            _toolchain(),
        )
    assert not runner.calls
    assert not terraform_apply_execution_path(prepared.paths, OPERATION_ID).exists()


@pytest.mark.parametrize(
    "artifact",
    [
        "authorization",
        "safeguard",
        "backup",
        "state",
        "saved-plan",
        "checkpoint",
        "source-record",
        "source-body",
        "tfvars",
        "backend",
        "journal",
        "toolchain",
    ],
)
def test_missing_or_stale_bound_artifacts_fail_before_runner(
    tmp_path: Path, artifact: str
) -> None:
    prepared = _ready(tmp_path)
    toolchain = _toolchain()
    if artifact == "authorization":
        (
            prepared.paths.terraform_plans
            / f"{OPERATION_ID}.terraform-apply-authorization.json"
        ).unlink()
    elif artifact == "safeguard":
        (
            prepared.paths.terraform_plans
            / f"{OPERATION_ID}.terraform-state-safeguard.json"
        ).unlink()
    elif artifact == "backup":
        terraform_state_backup_path(prepared.paths, OPERATION_ID).unlink()
    elif artifact == "state":
        value = json.loads(prepared.paths.terraform_state.read_text(encoding="utf-8"))
        value["serial"] += 1
        prepared.paths.terraform_state.write_text(
            json.dumps(value, sort_keys=True), encoding="utf-8"
        )
        prepared.paths.terraform_state.chmod(0o600)
    elif artifact == "saved-plan":
        path = prepared.paths.terraform_plans / f"{OPERATION_ID}.tfplan"
        path.write_bytes(path.read_bytes() + b"tampered")
        path.chmod(0o600)
    elif artifact == "checkpoint":
        (
            prepared.paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json"
        ).unlink()
    elif artifact == "source-record":
        _rewrite_json(
            prepared.paths.terraform_source_record,
            lambda value: None,
            canonical=False,
        )
    elif artifact == "source-body":
        path = prepared.paths.terraform_work / "main.tf"
        path.write_bytes(path.read_bytes() + b"\n# drift\n")
        path.chmod(0o600)
    elif artifact == "tfvars":
        _rewrite_json(
            prepared.paths.terraform_tfvars,
            lambda value: None,
            canonical=False,
        )
    elif artifact == "backend":
        path = prepared.paths.terraform_work / "terraform.tfstate"
        path.write_text("{}", encoding="utf-8")
        path.chmod(0o600)
    elif artifact == "journal":
        _rewrite_json(
            prepared.paths.operations / f"{OPERATION_ID}.json",
            lambda value: value.__setitem__("generation", 7),
        )
    else:
        toolchain = TerraformToolchain(TerraformVersion(1, 7, 0))
    runner = FakeRunner()

    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _execute(
            prepared,
            _executable(tmp_path),
            runner,
            toolchain=toolchain,
        )
    assert not runner.calls
    assert not terraform_apply_execution_path(prepared.paths, OPERATION_ID).exists()


def test_destructive_authorization_proof_tamper_fails_before_runner(
    tmp_path: Path,
) -> None:
    prepared = _prepare(
        tmp_path,
        resource_changes=[
            _change("oci_core_instance.replaced", ["delete", "create"]),
            _change("oci_core_instance.deleted", ["delete"]),
        ],
    )
    _compose(prepared)
    _authorize(prepared, _destructive_proof(prepared))
    _safeguard(prepared)
    authorization_path = (
        prepared.paths.terraform_plans
        / f"{OPERATION_ID}.terraform-apply-authorization.json"
    )
    _rewrite_json(
        authorization_path,
        lambda value: value["proof"].__setitem__("proof_digest", _OTHER_DIGEST),
    )
    runner = FakeRunner()

    with pytest.raises(StatePersistenceError, match="proof digest conflicts"):
        _execute(prepared, _executable(tmp_path), runner)
    assert not runner.calls


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "permissions"])
def test_execution_companion_path_safety_is_fail_closed(
    tmp_path: Path, kind: str
) -> None:
    prepared = _ready(tmp_path)
    execution_path = terraform_apply_execution_path(prepared.paths, OPERATION_ID)
    execution_path.write_text("{}", encoding="utf-8")
    execution_path.chmod(0o600)
    if kind == "symlink":
        outside = tmp_path / "outside-execution"
        execution_path.replace(outside)
        execution_path.symlink_to(outside)
    elif kind == "hardlink":
        os.link(execution_path, tmp_path / "execution-hardlink")
    else:
        execution_path.chmod(0o644)
    runner = FakeRunner()

    with pytest.raises((StatePersistenceError, UnsafePathError)):
        _execute(prepared, _executable(tmp_path), runner)
    assert not runner.calls


def test_api_surface_lock_and_builder_have_no_destroy_or_freeform_inputs(
    tmp_path: Path,
) -> None:
    prepared = _ready(tmp_path)
    executable = _executable(tmp_path)
    runner = FakeRunner()
    unlocked = ClusterLock(prepared.paths, "deploy", 0)
    with pytest.raises(StateLockError, match="acquired"):
        execute_deploy_apply(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            unlocked,
            runner,
            executable,
            _toolchain(),
        )
    parameters = tuple(inspect.signature(execute_deploy_apply).parameters)
    builder = TerraformCommandBuilder(executable, prepared.paths)

    assert parameters == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "runner",
        "terraform_executable",
        "toolchain",
    )
    assert not hasattr(builder, "destroy")
    assert not hasattr(builder, "apply")
    assert not hasattr(TerraformService, "apply_plan")
    assert not runner.calls
