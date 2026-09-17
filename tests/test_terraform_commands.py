import json
import sys
import uuid
from pathlib import Path

import pytest

from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    TerraformError,
    UnsafePathError,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.process import ProcessResult, ProcessSpec
from scylla_vms.state import StatePaths, initialize_state_layout
from scylla_vms.terraform.commands import (
    TerraformCommandBuilder,
    TerraformCommandKind,
)
from scylla_vms.terraform.service import TerraformService
from scylla_vms.terraform.toolchain import (
    TerraformVersion,
    TerraformVersionError,
    parse_terraform_version_json,
)

OPERATION_ID = uuid.UUID("22222222-2222-4222-8222-222222222222")


def _executable(tmp_path: Path) -> Path:
    path = tmp_path / "terraform"
    path.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    path.chmod(0o700)
    return path


def _builder(tmp_path: Path) -> tuple[StatePaths, TerraformCommandBuilder]:
    paths = StatePaths.derive(tmp_path / "state", "example")
    initialize_state_layout(paths)
    return paths, TerraformCommandBuilder(_executable(tmp_path), paths)


def _version_payload(version: str = "1.5.0") -> str:
    return json.dumps(
        {
            "platform": "darwin_arm64",
            "provider_selections": {},
            "terraform_outdated": False,
            "terraform_version": version,
        }
    )


@pytest.mark.parametrize("version", ["1.5.0", "1.13.7", "1.99.99"])
def test_version_contract_accepts_supported_stable_versions(version: str) -> None:
    parsed = parse_terraform_version_json(_version_payload(version))
    assert str(parsed) == version


@pytest.mark.parametrize(
    "payload",
    [
        _version_payload("1.4.9"),
        _version_payload("2.0.0"),
        _version_payload("1.5.0-alpha.1"),
        "{}",
        '{"terraform_version":"1.5.0","terraform_version":"1.6.0"}',
        "Terraform v1.5.0",
    ],
)
def test_version_contract_rejects_unsupported_or_malformed_output(
    payload: str,
) -> None:
    with pytest.raises(TerraformVersionError):
        parse_terraform_version_json(payload)


def test_commands_are_fully_anchored_and_exact(tmp_path: Path) -> None:
    paths, builder = _builder(tmp_path)
    paths.terraform_state.write_text("{}", encoding="utf-8")
    paths.terraform_state.chmod(0o600)
    plan_command = builder.plan(OPERATION_ID)
    plan_path = paths.terraform_plans / f"{OPERATION_ID}.tfplan"
    plan_path.write_bytes(b"exact saved plan")
    plan_path.chmod(0o600)

    commands = {
        "version": builder.version(),
        "init": builder.init(),
        "fmt": builder.fmt_check(),
        "validate": builder.validate(),
        "plan": plan_command,
        "apply": builder.apply_plan(OPERATION_ID),
        "output": builder.output(),
    }

    prefix = (
        str(tmp_path / "terraform"),
        f"-chdir={paths.terraform_work}",
    )
    assert commands["version"].process.argv == (*prefix, "version", "-json")
    assert commands["init"].process.argv == (
        *prefix,
        "init",
        "-input=false",
        "-no-color",
        "-lockfile=readonly",
        "-lock-timeout=30s",
        f"-backend-config=path={paths.terraform_state}",
    )
    assert commands["fmt"].process.argv == (
        *prefix,
        "fmt",
        "-check",
        "-diff",
        "-recursive",
    )
    assert commands["validate"].process.argv == (
        *prefix,
        "validate",
        "-json",
        "-no-color",
    )
    assert commands["plan"].process.argv == (
        *prefix,
        "plan",
        "-input=false",
        "-no-color",
        "-detailed-exitcode",
        "-lock=true",
        "-lock-timeout=30s",
        f"-state={paths.terraform_state}",
        f"-out={paths.terraform_plans / f'{OPERATION_ID}.tfplan'}",
    )
    assert commands["apply"].process.argv == (
        *prefix,
        "apply",
        "-input=false",
        "-no-color",
        "-lock=true",
        "-lock-timeout=30s",
        str(paths.terraform_plans / f"{OPERATION_ID}.tfplan"),
    )
    assert commands["apply"].process.allowed_exit_codes == frozenset(range(-255, 256))
    assert commands["output"].process.argv == (
        *prefix,
        "output",
        "-json",
        "-no-color",
        f"-state={paths.terraform_state}",
    )
    for command in commands.values():
        assert command.process.cwd == paths.cluster_root
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
        assert set(command.process.environment.names) == expected_environment
        assert str(paths.cluster_root) not in repr(command)


def test_plan_paths_refuse_preexisting_and_symlink_files(tmp_path: Path) -> None:
    paths, builder = _builder(tmp_path)
    plan_path = paths.terraform_plans / f"{OPERATION_ID}.tfplan"
    plan_path.write_text("existing", encoding="utf-8")
    plan_path.chmod(0o600)
    with pytest.raises(TerraformError, match="already exists"):
        builder.plan(OPERATION_ID)
    plan_path.unlink()
    target = tmp_path / "outside-plan"
    target.write_text("outside", encoding="utf-8")
    plan_path.symlink_to(target)
    with pytest.raises(UnsafePathError, match=r"canonical|symbolic link"):
        builder.plan(OPERATION_ID)


def test_builder_exposes_only_exact_plan_apply_and_no_destroy(tmp_path: Path) -> None:
    _, builder = _builder(tmp_path)
    assert hasattr(builder, "apply_plan")
    assert not hasattr(builder, "apply")
    assert not hasattr(builder, "destroy")


class FakeRunner:
    def __init__(self, exit_code: int = 0, stdout: str = "") -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.calls: list[ProcessSpec] = []

    def run(self, spec: ProcessSpec) -> ProcessResult:
        self.calls.append(spec)
        for argument in spec.argv:
            if argument.startswith("-out="):
                path = Path(argument.removeprefix("-out="))
                path.write_text("fake plan", encoding="utf-8")
                path.chmod(0o600)
        return ProcessResult(self.exit_code, self.stdout, "")


@pytest.mark.parametrize(("exit_code", "has_changes"), [(0, False), (2, True)])
def test_service_requires_lock_and_interprets_detailed_exit_codes(
    tmp_path: Path, exit_code: int, has_changes: bool
) -> None:
    paths, builder = _builder(tmp_path)
    runner = FakeRunner(exit_code)
    service = TerraformService(builder, runner)
    lock = ClusterLock(paths, "deploy", 0)
    with pytest.raises(StateLockError):
        service.plan(lock, OPERATION_ID)
    with lock:
        result = service.plan(lock, OPERATION_ID)
    assert result.has_changes is has_changes
    assert result.plan_path.name == f"{OPERATION_ID}.tfplan"
    assert str(paths.cluster_root) not in repr(result)
    assert runner.calls[0].allowed_exit_codes == frozenset({0, 2})


def test_service_version_is_machine_readable_and_lock_gated(tmp_path: Path) -> None:
    paths, builder = _builder(tmp_path)
    service = TerraformService(builder, FakeRunner(stdout=_version_payload("1.6.6")))
    with ClusterLock(paths, "deploy", 0) as lock:
        toolchain = service.version(lock)
    assert toolchain.version == TerraformVersion(1, 6, 6)


def test_init_refuses_unexpected_state_before_runner(tmp_path: Path) -> None:
    paths, builder = _builder(tmp_path)
    candidate = tmp_path / "unexpected"
    candidate.mkdir()
    (candidate / "terraform.tfstate").write_text("{}", encoding="utf-8")
    runner = FakeRunner()
    service = TerraformService(builder, runner)
    with ClusterLock(paths, "deploy", 0) as lock, pytest.raises(StateConflictError):
        service.init(lock, unexpected_state_roots=(candidate,))
    assert not runner.calls


def test_command_construction_does_not_write_files(tmp_path: Path) -> None:
    paths, builder = _builder(tmp_path)
    plan_command = builder.plan(OPERATION_ID)
    plan_path = paths.terraform_plans / f"{OPERATION_ID}.tfplan"
    plan_path.write_bytes(b"exact saved plan")
    plan_path.chmod(0o600)
    before = sorted(
        path.relative_to(paths.cluster_root) for path in paths.cluster_root.rglob("*")
    )
    builder.version()
    builder.init()
    builder.fmt_check()
    builder.validate()
    assert plan_command.kind is TerraformCommandKind.PLAN
    builder.apply_plan(OPERATION_ID)
    after = sorted(
        path.relative_to(paths.cluster_root) for path in paths.cluster_root.rglob("*")
    )
    assert after == before
    assert plan_path.read_bytes() == b"exact saved plan"
    assert "destroy" not in {command.value for command in TerraformCommandKind}
