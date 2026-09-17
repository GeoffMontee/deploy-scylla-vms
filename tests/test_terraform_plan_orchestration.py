import inspect
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from test_terraform_plan_checkpoint import (
    ADDRESS_MARKER,
    NOW,
    OPERATION_ID,
    SECRET_MARKER,
    _change,
    _paths,
    _plan_json,
    _prepare_foundation,
    _toolchain,
    _write_owner_file,
)

from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    TerraformError,
    UnsafePathError,
)
from scylla_vms.journal import OperationJournalStore
from scylla_vms.locking import ClusterLock
from scylla_vms.process import (
    ProcessOutputError,
    ProcessResult,
    ProcessSpec,
    ProcessTimeoutError,
)
from scylla_vms.state import StatePaths
from scylla_vms.terraform.operation_composition import DeployPlanCompositionState
from scylla_vms.terraform.plan import (
    TerraformPlanChangeClass,
    TerraformPlanCheckpointService,
    TerraformPlanCheckpointStore,
)
from scylla_vms.terraform.plan_orchestration import (
    TERRAFORM_DEPLOY_PLAN_ORCHESTRATION_REPORT_SCHEMA_VERSION,
    TerraformPlanOrchestrationStageState,
    orchestrate_deploy_plan,
)
from scylla_vms.terraform.toolchain import TerraformToolchain, TerraformVersion

_PLAN_LIMIT = 64 * 1024 * 1024


def _executable(tmp_path: Path) -> Path:
    path = tmp_path / "terraform"
    path.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    path.chmod(0o700)
    return path


def _prepare_paths(
    tmp_path: Path,
    *,
    keep_saved_plan: bool,
    write_state: bool = True,
) -> StatePaths:
    paths = _paths(tmp_path)
    with ClusterLock(paths, "deploy", 0) as lock:
        _prepare_foundation(
            tmp_path,
            paths,
            lock,
            write_state=write_state,
        )
    if not keep_saved_plan:
        (paths.terraform_plans / f"{OPERATION_ID}.tfplan").unlink()
    return paths


class FakeRunner:
    def __init__(
        self,
        plan_json: str,
        *,
        plan_exit: int,
        plan_bytes: bytes = b"fake immutable Terraform plan",
        failure: str | None = None,
        after_plan: Callable[[], None] | None = None,
    ) -> None:
        self.plan_json = plan_json
        self.plan_exit = plan_exit
        self.plan_bytes = plan_bytes
        self.failure = failure
        self.after_plan = after_plan
        self.calls: list[ProcessSpec] = []

    def run(self, spec: ProcessSpec) -> ProcessResult:
        self.calls.append(spec)
        command = spec.argv[2]
        if command == "plan":
            if self.failure == "plan-timeout":
                raise ProcessTimeoutError("fake timeout with SHOULD-NOT-PERSIST")
            if self.failure == "plan-output":
                raise ProcessOutputError("fake output with SHOULD-NOT-PERSIST")
            output = next(
                argument.removeprefix("-out=")
                for argument in spec.argv
                if argument.startswith("-out=")
            )
            if self.failure != "plan-missing-stage":
                _write_owner_file(Path(output), self.plan_bytes)
            if self.failure == "plan-unsafe-stage":
                Path(output).chmod(0o644)
            if self.after_plan is not None:
                self.after_plan()
            return ProcessResult(self.plan_exit, "", "provider diagnostic secret")
        if command == "show":
            if self.failure == "show-timeout":
                raise ProcessTimeoutError("fake timeout with SHOULD-NOT-PERSIST")
            if self.failure == "show-output":
                raise ProcessOutputError("fake non-UTF8 or oversized output")
            return ProcessResult(0, self.plan_json, "provider diagnostic secret")
        raise AssertionError(f"unexpected Terraform command: {command}")


def _orchestrate(
    paths: StatePaths,
    executable: Path,
    runner: FakeRunner,
    *,
    toolchain: TerraformToolchain | None = None,
):
    with ClusterLock(paths, "deploy", 0) as lock:
        return orchestrate_deploy_plan(
            paths.state_root,
            "example",
            OPERATION_ID,
            lock,
            runner,
            executable,
            toolchain or _toolchain(),
        )


@pytest.mark.parametrize(
    ("changes", "exit_code", "expected_class"),
    [
        ([], 0, TerraformPlanChangeClass.NO_CHANGES),
        (
            [_change("oci_core_instance.created", ["create"])],
            2,
            TerraformPlanChangeClass.CREATE_ONLY,
        ),
    ],
)
def test_fresh_plan_show_checkpoint_and_journal_order(
    tmp_path: Path,
    changes: list[dict[str, object]],
    exit_code: int,
    expected_class: TerraformPlanChangeClass,
) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=False)
    executable = _executable(tmp_path)
    runner = FakeRunner(
        _plan_json(resource_changes=changes),
        plan_exit=exit_code,
    )

    report = _orchestrate(paths, executable, runner)
    final_plan = paths.terraform_plans / f"{OPERATION_ID}.tfplan"
    checkpoint_path = paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json"

    assert report.schema_version == (
        TERRAFORM_DEPLOY_PLAN_ORCHESTRATION_REPORT_SCHEMA_VERSION
    )
    assert report.saved_plan_state is TerraformPlanOrchestrationStageState.CREATED
    assert report.review_state is TerraformPlanOrchestrationStageState.CREATED
    assert report.checkpoint_state is TerraformPlanOrchestrationStageState.CREATED
    assert report.journal_state is DeployPlanCompositionState.CREATED
    assert report.summary.change_class is expected_class
    assert report.plan_subprocess_calls == 1
    assert report.show_subprocess_calls == 1
    assert [call.argv[2] for call in runner.calls] == ["plan", "show"]
    assert final_plan.read_bytes() == b"fake immutable Terraform plan"
    assert not (paths.terraform_plans / f"{OPERATION_ID}.tfplan.staging").exists()
    assert checkpoint_path.exists()
    assert final_plan.stat().st_mode & 0o777 == 0o600
    assert checkpoint_path.stat().st_mode & 0o777 == 0o600


def test_commands_environment_and_cwd_are_exactly_anchored(tmp_path: Path) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=False)
    executable = _executable(tmp_path)
    runner = FakeRunner(
        _plan_json(resource_changes=[_change("oci_core_instance.created", ["create"])]),
        plan_exit=2,
    )

    _orchestrate(paths, executable, runner)

    plan, show = runner.calls
    prefix = (str(executable), f"-chdir={paths.terraform_work}")
    assert plan.argv == (
        *prefix,
        "plan",
        "-input=false",
        "-no-color",
        "-detailed-exitcode",
        "-lock=true",
        "-lock-timeout=30s",
        f"-state={paths.terraform_state}",
        f"-out={paths.terraform_plans / f'{OPERATION_ID}.tfplan.staging'}",
    )
    assert show.argv == (
        *prefix,
        "show",
        "-json",
        "-no-color",
        str(paths.terraform_plans / f"{OPERATION_ID}.tfplan.staging"),
    )
    for call in runner.calls:
        assert call.cwd == paths.cluster_root
        expected = {
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
            expected.add("__CF_USER_TEXT_ENCODING")
        assert set(call.environment.names) == expected
        assert call.environment.for_subprocess()["TF_DATA_DIR"] == str(
            paths.terraform_data
        )
        assert call.environment.for_subprocess()["TF_PLUGIN_CACHE_DIR"] == str(
            paths.terraform_plugin_cache
        )
        assert not any(
            item.startswith(("TF_CLI_ARGS", "TF_VAR_", "TF_WORKSPACE", "HTTP_PROXY"))
            for item in call.environment.names
        )


def test_saved_plan_only_recovery_runs_show_without_replanning(tmp_path: Path) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=True)
    executable = _executable(tmp_path)
    runner = FakeRunner(
        _plan_json(resource_changes=[_change("oci_core_instance.created", ["create"])]),
        plan_exit=2,
    )

    report = _orchestrate(paths, executable, runner)

    assert [call.argv[2] for call in runner.calls] == ["show"]
    assert runner.calls[0].argv[-1] == str(
        paths.terraform_plans / f"{OPERATION_ID}.tfplan"
    )
    assert report.saved_plan_state is TerraformPlanOrchestrationStageState.REUSED
    assert report.review_state is TerraformPlanOrchestrationStageState.CREATED
    assert report.checkpoint_state is TerraformPlanOrchestrationStageState.CREATED
    assert report.plan_subprocess_calls == 0
    assert report.show_subprocess_calls == 1


def test_checkpoint_only_recovery_composes_without_runner_call(tmp_path: Path) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=True)
    executable = _executable(tmp_path)
    plan_json = _plan_json(
        resource_changes=[_change("oci_core_instance.created", ["create"])]
    )
    with ClusterLock(paths, "deploy", 0) as lock:
        TerraformPlanCheckpointService(paths).capture_locked(
            operation_id=OPERATION_ID,
            operation="deploy",
            toolchain=_toolchain(),
            plan_json=plan_json,
            clock=lambda: NOW,
            lock=lock,
        )
    runner = FakeRunner(plan_json, plan_exit=2)

    report = _orchestrate(paths, executable, runner)

    assert not runner.calls
    assert report.saved_plan_state is TerraformPlanOrchestrationStageState.REUSED
    assert report.review_state is TerraformPlanOrchestrationStageState.REUSED
    assert report.checkpoint_state is TerraformPlanOrchestrationStageState.REUSED
    assert report.journal_state is DeployPlanCompositionState.CREATED


def test_terminal_reentry_is_zero_plan_show_and_write(tmp_path: Path) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=False)
    executable = _executable(tmp_path)
    plan_json = _plan_json(
        resource_changes=[_change("oci_core_instance.created", ["create"])]
    )
    runner = FakeRunner(plan_json, plan_exit=2)
    first = _orchestrate(paths, executable, runner)
    plan_before = (paths.terraform_plans / f"{OPERATION_ID}.tfplan").read_bytes()
    checkpoint_before = (
        paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json"
    ).read_bytes()
    journal_before = (paths.operations / f"{OPERATION_ID}.json").read_bytes()
    runner.calls.clear()

    second = _orchestrate(paths, executable, runner)

    assert not runner.calls
    assert second.journal_state is DeployPlanCompositionState.REUSED
    assert second.journal_digest == first.journal_digest
    assert (paths.terraform_plans / f"{OPERATION_ID}.tfplan").read_bytes() == (
        plan_before
    )
    assert (
        paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json"
    ).read_bytes() == checkpoint_before
    assert (paths.operations / f"{OPERATION_ID}.json").read_bytes() == journal_before


@pytest.mark.parametrize(
    ("exit_code", "changes"),
    [
        (0, [_change("oci_core_instance.created", ["create"])]),
        (2, []),
    ],
)
def test_detailed_exit_status_must_match_strict_show_evidence(
    tmp_path: Path,
    exit_code: int,
    changes: list[dict[str, object]],
) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=False)
    runner = FakeRunner(
        _plan_json(resource_changes=changes),
        plan_exit=exit_code,
    )

    with pytest.raises(TerraformError, match="exit status conflicts"):
        _orchestrate(paths, _executable(tmp_path), runner)

    assert (paths.terraform_plans / f"{OPERATION_ID}.tfplan.staging").exists()
    assert not (paths.terraform_plans / f"{OPERATION_ID}.tfplan").exists()


@pytest.mark.parametrize(
    ("plan_json", "failure"),
    [
        ("not-json", None),
        ("x" * (4 * 1024 * 1024 + 1), None),
        (_plan_json(), "show-output"),
        (_plan_json(), "show-timeout"),
    ],
)
def test_malformed_oversized_non_utf8_and_timed_out_show_fail_closed(
    tmp_path: Path,
    plan_json: str,
    failure: str | None,
) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=False)
    runner = FakeRunner(plan_json, plan_exit=0, failure=failure)

    with pytest.raises(TerraformError):
        _orchestrate(paths, _executable(tmp_path), runner)

    assert (paths.terraform_plans / f"{OPERATION_ID}.tfplan.staging").exists()
    assert not (paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json").exists()


@pytest.mark.parametrize(
    ("plan_exit", "failure"),
    [
        (1, None),
        (0, "plan-timeout"),
        (0, "plan-output"),
        (0, "plan-missing-stage"),
        (0, "plan-unsafe-stage"),
    ],
)
def test_plan_failure_timeout_and_output_error_fail_closed(
    tmp_path: Path,
    plan_exit: int,
    failure: str | None,
) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=False)
    runner = FakeRunner(_plan_json(), plan_exit=plan_exit, failure=failure)

    with pytest.raises(
        (TerraformError, StatePersistenceError, UnsafePathError),
        match=r"plan command failed|invalid exit|required state|0600",
    ):
        _orchestrate(paths, _executable(tmp_path), runner)

    assert not (paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json").exists()


def test_promotion_failure_retains_staging_and_requires_manual_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=False)
    executable = _executable(tmp_path)
    runner = FakeRunner(_plan_json(), plan_exit=0)

    def fail_link(*args, **kwargs):
        del args, kwargs
        raise OSError("injected promotion failure")

    monkeypatch.setattr(os, "link", fail_link)
    with pytest.raises(StatePersistenceError, match="promotion failed"):
        _orchestrate(paths, executable, runner)
    assert (paths.terraform_plans / f"{OPERATION_ID}.tfplan.staging").exists()
    calls = len(runner.calls)

    monkeypatch.undo()
    with pytest.raises(StateConflictError, match="manual recovery"):
        _orchestrate(paths, executable, runner)
    assert len(runner.calls) == calls


def test_checkpoint_write_failure_recovers_from_promoted_saved_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=False)
    executable = _executable(tmp_path)
    runner = FakeRunner(_plan_json(), plan_exit=0)

    def fail_write(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError("injected checkpoint write failure")

    monkeypatch.setattr(TerraformPlanCheckpointStore, "write_locked", fail_write)
    with pytest.raises(StatePersistenceError, match="injected checkpoint"):
        _orchestrate(paths, executable, runner)
    assert (paths.terraform_plans / f"{OPERATION_ID}.tfplan").exists()
    assert not (paths.terraform_plans / f"{OPERATION_ID}.tfplan.staging").exists()
    assert not (paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json").exists()
    assert [call.argv[2] for call in runner.calls] == ["plan", "show"]

    monkeypatch.undo()
    recovered = _orchestrate(paths, executable, runner)
    assert [call.argv[2] for call in runner.calls] == ["plan", "show", "show"]
    assert recovered.saved_plan_state is TerraformPlanOrchestrationStageState.REUSED


def test_journal_write_failure_leaves_recoverable_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=False)
    executable = _executable(tmp_path)
    runner = FakeRunner(_plan_json(), plan_exit=0)

    def fail_write(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError("injected journal write failure")

    monkeypatch.setattr(OperationJournalStore, "write", fail_write)
    with pytest.raises(StatePersistenceError, match="injected journal"):
        _orchestrate(paths, executable, runner)
    assert (paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json").exists()
    assert [call.argv[2] for call in runner.calls] == ["plan", "show"]

    monkeypatch.undo()
    recovered = _orchestrate(paths, executable, runner)
    assert [call.argv[2] for call in runner.calls] == ["plan", "show"]
    assert recovered.checkpoint_state is TerraformPlanOrchestrationStageState.REUSED
    assert recovered.journal_state is DeployPlanCompositionState.CREATED


@pytest.mark.parametrize("artifact", ["journal", "state", "tfvars", "source"])
def test_saved_plan_only_recovery_refuses_bound_input_drift(
    tmp_path: Path,
    artifact: str,
) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=True)
    selected = {
        "journal": paths.operations / f"{OPERATION_ID}.json",
        "state": paths.terraform_state,
        "tfvars": paths.terraform_tfvars,
        "source": paths.terraform_work / "main.tf",
    }[artifact]
    selected.write_bytes(selected.read_bytes() + b"\n")
    selected.chmod(0o600)
    runner = FakeRunner(_plan_json(), plan_exit=0)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _orchestrate(paths, _executable(tmp_path), runner)

    assert not runner.calls


def test_unexpected_backend_state_fails_before_runner(tmp_path: Path) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=False)
    unexpected = paths.cluster_root / "terraform.tfstate"
    _write_owner_file(unexpected, "{}")
    runner = FakeRunner(_plan_json(), plan_exit=0)

    with pytest.raises(StateConflictError, match="unexpected Terraform state"):
        _orchestrate(paths, _executable(tmp_path), runner)

    assert not runner.calls


def test_input_drift_during_plan_fails_before_show_promotion(
    tmp_path: Path,
) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=False)

    def mutate_tfvars() -> None:
        paths.terraform_tfvars.write_bytes(paths.terraform_tfvars.read_bytes() + b" ")
        paths.terraform_tfvars.chmod(0o600)

    runner = FakeRunner(
        _plan_json(),
        plan_exit=0,
        after_plan=mutate_tfvars,
    )

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _orchestrate(paths, _executable(tmp_path), runner)

    assert [call.argv[2] for call in runner.calls] == ["plan", "show"]
    assert (paths.terraform_plans / f"{OPERATION_ID}.tfplan.staging").exists()
    assert not (paths.terraform_plans / f"{OPERATION_ID}.tfplan").exists()


def test_checkpoint_recovery_refuses_toolchain_drift_before_runner(
    tmp_path: Path,
) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=True)
    plan_json = _plan_json()
    with ClusterLock(paths, "deploy", 0) as lock:
        TerraformPlanCheckpointService(paths).capture_locked(
            operation_id=OPERATION_ID,
            operation="deploy",
            toolchain=_toolchain(),
            plan_json=plan_json,
            clock=lambda: NOW,
            lock=lock,
        )
    runner = FakeRunner(plan_json, plan_exit=0)

    with pytest.raises(StateConflictError, match="toolchain version conflicts"):
        _orchestrate(
            paths,
            _executable(tmp_path),
            runner,
            toolchain=TerraformToolchain(TerraformVersion(1, 7, 0)),
        )

    assert not runner.calls


def test_checkpointed_saved_plan_is_immutable_on_reentry(tmp_path: Path) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=True)
    plan_json = _plan_json()
    with ClusterLock(paths, "deploy", 0) as lock:
        TerraformPlanCheckpointService(paths).capture_locked(
            operation_id=OPERATION_ID,
            operation="deploy",
            toolchain=_toolchain(),
            plan_json=plan_json,
            clock=lambda: NOW,
            lock=lock,
        )
    saved_plan = paths.terraform_plans / f"{OPERATION_ID}.tfplan"
    _write_owner_file(saved_plan, saved_plan.read_bytes() + b"tampered")
    runner = FakeRunner(plan_json, plan_exit=0)

    with pytest.raises(StateConflictError, match="stale or changed"):
        _orchestrate(paths, _executable(tmp_path), runner)

    assert not runner.calls


def test_ambiguous_staging_extra_and_conflicting_checkpoint_fail_closed(
    tmp_path: Path,
) -> None:
    staging_root = tmp_path / "staging"
    staging_root.mkdir()
    staging_paths = _prepare_paths(staging_root, keep_saved_plan=False)
    _write_owner_file(
        staging_paths.terraform_plans / f"{OPERATION_ID}.tfplan.staging",
        b"partial",
    )
    staging_runner = FakeRunner(_plan_json(), plan_exit=0)
    with pytest.raises(StateConflictError, match="manual recovery"):
        _orchestrate(
            staging_paths,
            _executable(staging_root),
            staging_runner,
        )
    assert not staging_runner.calls

    extra_root = tmp_path / "extra"
    extra_root.mkdir()
    extra_paths = _prepare_paths(extra_root, keep_saved_plan=True)
    _write_owner_file(
        extra_paths.terraform_plans / f".{OPERATION_ID}.unknown.tmp",
        b"ambiguous",
    )
    extra_runner = FakeRunner(_plan_json(), plan_exit=0)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _orchestrate(extra_paths, _executable(extra_root), extra_runner)
    assert not extra_runner.calls

    checkpoint_root = tmp_path / "checkpoint"
    checkpoint_root.mkdir()
    checkpoint_paths = _prepare_paths(checkpoint_root, keep_saved_plan=True)
    _write_owner_file(
        checkpoint_paths.terraform_plans / f"{OPERATION_ID}.terraform-plan.json",
        "{}",
    )
    checkpoint_runner = FakeRunner(_plan_json(), plan_exit=0)
    with pytest.raises(StatePersistenceError):
        _orchestrate(
            checkpoint_paths,
            _executable(checkpoint_root),
            checkpoint_runner,
        )
    assert not checkpoint_runner.calls


@pytest.mark.parametrize("kind", ["empty", "permissions", "oversized", "hardlink"])
def test_saved_plan_file_safety_contract(
    tmp_path: Path,
    kind: str,
) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=True)
    plan = paths.terraform_plans / f"{OPERATION_ID}.tfplan"
    if kind == "empty":
        _write_owner_file(plan, b"")
    elif kind == "permissions":
        plan.chmod(0o644)
    elif kind == "oversized":
        plan.write_bytes(b"x")
        plan.chmod(0o600)
        with plan.open("r+b") as stream:
            stream.truncate(_PLAN_LIMIT + 1)
    else:
        os.link(plan, tmp_path / "second-plan-link")
    runner = FakeRunner(_plan_json(), plan_exit=0)

    with pytest.raises((StatePersistenceError, UnsafePathError)):
        _orchestrate(paths, _executable(tmp_path), runner)

    assert not runner.calls


def test_saved_plan_symlink_is_refused_before_runner(tmp_path: Path) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=True)
    plan = paths.terraform_plans / f"{OPERATION_ID}.tfplan"
    outside = tmp_path / "outside-plan"
    plan.replace(outside)
    plan.symlink_to(outside)
    runner = FakeRunner(_plan_json(), plan_exit=0)

    with pytest.raises(UnsafePathError, match="symbolic link"):
        _orchestrate(paths, _executable(tmp_path), runner)

    assert not runner.calls


def test_report_and_errors_do_not_expose_plan_address_secret_or_paths(
    tmp_path: Path,
) -> None:
    paths = _prepare_paths(tmp_path, keep_saved_plan=False)
    runner = FakeRunner(
        _plan_json(
            resource_changes=[
                _change('oci_core_instance.host["scylla-ad-1-1"]', ["create"])
            ]
        ),
        plan_exit=2,
        plan_bytes=b"binary SHOULD-NOT-PERSIST-secret-value",
    )

    report = _orchestrate(paths, _executable(tmp_path), runner)
    rendered = json.dumps(report.to_object(), sort_keys=True)

    for protected in (
        SECRET_MARKER,
        ADDRESS_MARKER,
        str(tmp_path),
        "oci_core_instance",
        "binary SHOULD-NOT-PERSIST",
        "provider diagnostic secret",
    ):
        assert protected not in rendered


def test_api_refuses_arbitrary_inputs_and_never_builds_apply_or_destroy(
    tmp_path: Path,
) -> None:
    parameters = inspect.signature(orchestrate_deploy_plan).parameters
    for forbidden in (
        "cwd",
        "source",
        "backend",
        "state",
        "plan_path",
        "command",
        "args",
        "variables",
        "environment",
        "plan_json",
        "authorization",
    ):
        assert forbidden not in parameters

    paths = _prepare_paths(tmp_path, keep_saved_plan=False)
    runner = FakeRunner(_plan_json(), plan_exit=0)
    unlocked = ClusterLock(paths, "deploy", 0)
    with pytest.raises(StateLockError, match="matching acquired"):
        orchestrate_deploy_plan(
            paths.state_root,
            "example",
            OPERATION_ID,
            unlocked,
            runner,
            _executable(tmp_path),
            _toolchain(),
        )
    assert not runner.calls

    report = _orchestrate(paths, _executable(tmp_path), runner)
    assert all(call.argv[2] in {"plan", "show"} for call in runner.calls)
    assert not any(
        argument in {"apply", "destroy"}
        for call in runner.calls
        for argument in call.argv
    )
    projected = report.to_object()
    assert projected["authorization"]["plan_approved"] is False
    assert projected["execution"]["apply_command_available"] is False
    assert projected["recovery"] == {
        "automatic_replan_performed": False,
        "automatic_retry_allowed": False,
        "idempotent_reentry_allowed": True,
        "manual_recovery_required": False,
    }
