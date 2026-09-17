import json
import os
import signal
import sys
from pathlib import Path

import pytest

from scylla_vms.errors import ToolExecutionError, ToolPrerequisiteError
from scylla_vms.process import (
    ControlledEnvironment,
    ExecutableNotFoundError,
    ProcessExitError,
    ProcessLaunchError,
    ProcessRunner,
    ProcessSpec,
    discover_executable,
)


def _executable(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "fake-tool"
    path.write_text(f"#!{sys.executable}\n{body}\n", encoding="utf-8")
    path.chmod(0o700)
    return path


def _spec(
    executable: Path,
    tmp_path: Path,
    *arguments: str,
    environment: ControlledEnvironment | None = None,
    timeout: float = 2,
    limit: int = 4096,
    allowed: frozenset[int] = frozenset({0}),
    sensitive_values: tuple[str, ...] = (),
) -> ProcessSpec:
    return ProcessSpec(
        (str(executable), *arguments),
        tmp_path,
        environment or ControlledEnvironment.create({}, allowed_names=()),
        timeout,
        limit,
        allowed,
        sensitive_values,
    )


def test_runner_uses_exact_argv_cwd_and_allowlisted_environment(tmp_path: Path) -> None:
    executable = _executable(
        tmp_path,
        "import json, os, sys\n"
        "print(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd(), "
        "'env': dict(os.environ)}, sort_keys=True))",
    )
    environment = ControlledEnvironment.create(
        {"APP_SAFE": "safe-value"}, allowed_names={"APP_SAFE"}
    )

    result = ProcessRunner().run(
        _spec(executable, tmp_path, "literal;not-a-shell", environment=environment)
    )
    payload = json.loads(result.stdout)

    assert payload["argv"] == ["literal;not-a-shell"]
    assert payload["cwd"] == str(tmp_path)
    assert payload["env"]["APP_SAFE"] == "safe-value"
    assert payload["env"]["LANG"] == "C.UTF-8"
    assert payload["env"]["LC_ALL"] == "C.UTF-8"
    assert set(payload["env"]) <= {
        "APP_SAFE",
        "LANG",
        "LC_ALL",
        "__CF_USER_TEXT_ENCODING",
    }


def test_runner_redacts_output_and_hides_request_values_from_repr(
    tmp_path: Path,
) -> None:
    secret = "obviously-fake-secret-value"
    executable = _executable(
        tmp_path,
        "import os, sys\n"
        "print(os.environ['APP_SECRET'])\n"
        "print('TOKEN=' + os.environ['APP_SECRET'], file=sys.stderr)",
    )
    environment = ControlledEnvironment.create(
        {"APP_SECRET": secret},
        allowed_names={"APP_SECRET"},
        sensitive_names={"APP_SECRET"},
    )
    spec = _spec(executable, tmp_path, environment=environment)

    result = ProcessRunner().run(spec)

    assert secret not in result.stdout
    assert secret not in result.stderr
    assert secret not in repr(spec)
    assert secret not in repr(environment)
    assert secret not in repr(result)
    assert "[REDACTED]" in result.stdout


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("import time; time.sleep(10)", "timed out"),
        ("import sys; sys.stdout.write('x' * 10000)", "size limit"),
        ("import os; os.write(1, b'\\xff')", "valid UTF-8"),
        ("raise SystemExit(17)", "exit code 17"),
    ],
)
def test_runner_has_stable_bounded_failure_modes(
    tmp_path: Path, body: str, message: str
) -> None:
    executable = _executable(tmp_path, body)
    with pytest.raises(ToolExecutionError, match=message):
        ProcessRunner().run(
            _spec(
                executable,
                tmp_path,
                timeout=0.05 if "sleep" in body else 2,
                limit=128,
            )
        )


def test_runner_accepts_only_explicit_nonzero_codes(tmp_path: Path) -> None:
    executable = _executable(tmp_path, "raise SystemExit(2)")
    result = ProcessRunner().run(_spec(executable, tmp_path, allowed=frozenset({0, 2})))
    assert result.exit_code == 2


def test_runner_reports_signal_exit_without_exposing_output(tmp_path: Path) -> None:
    executable = _executable(
        tmp_path,
        "import os, signal; os.kill(os.getpid(), signal.SIGTERM)",
    )
    with pytest.raises(ProcessExitError, match=rf"exit code {-signal.SIGTERM}"):
        ProcessRunner().run(_spec(executable, tmp_path))


def test_launch_failure_preserves_a_typed_safe_cause(tmp_path: Path) -> None:
    executable = _executable(tmp_path, "pass")
    spec = _spec(executable, tmp_path)
    executable.unlink()
    with pytest.raises(ProcessLaunchError, match="could not be launched") as captured:
        ProcessRunner().run(spec)
    assert isinstance(captured.value.__cause__, OSError)
    assert str(executable) not in str(captured.value)


def test_environment_and_argv_reject_unapproved_or_secret_bearing_values(
    tmp_path: Path,
) -> None:
    executable = _executable(tmp_path, "pass")
    with pytest.raises(ToolPrerequisiteError, match="unapproved"):
        ControlledEnvironment.create({"TF_CLI_ARGS": "-lock=false"}, allowed_names=())
    environment = ControlledEnvironment.create(
        {"APP_SECRET": "fake-secret"},
        allowed_names={"APP_SECRET"},
        sensitive_names={"APP_SECRET"},
    )
    with pytest.raises(ToolPrerequisiteError, match="forbidden"):
        _spec(executable, tmp_path, "--password=fake", environment=environment)
    with pytest.raises(ToolPrerequisiteError, match="forbidden"):
        _spec(executable, tmp_path, "fake-secret", environment=environment)


def test_discovery_uses_only_explicit_directories_and_rejects_symlinks(
    tmp_path: Path,
) -> None:
    executable = _executable(tmp_path, "pass")
    assert discover_executable("fake-tool", (tmp_path,)) == executable
    symlink = tmp_path / "linked-tool"
    symlink.symlink_to(executable)
    with pytest.raises(ExecutableNotFoundError, match="unavailable"):
        discover_executable("linked-tool", (tmp_path,))
    with pytest.raises(ExecutableNotFoundError, match="unavailable"):
        discover_executable("not-present", (tmp_path,))


def test_process_spec_rejects_noncanonical_working_directory(tmp_path: Path) -> None:
    executable = _executable(tmp_path, "pass")
    alias = tmp_path / "alias"
    target = tmp_path / "target"
    target.mkdir()
    alias.symlink_to(target)
    with pytest.raises(ToolPrerequisiteError, match="canonical"):
        _spec(executable, alias)


@pytest.mark.skipif(os.name != "posix", reason="executable mode is POSIX-specific")
def test_discovery_rejects_non_executable_file(tmp_path: Path) -> None:
    path = tmp_path / "fake-tool"
    path.write_text("not executable", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(ExecutableNotFoundError, match="unavailable"):
        discover_executable("fake-tool", (tmp_path,))
