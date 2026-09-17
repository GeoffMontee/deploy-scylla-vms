"""Controlled external-process execution with bounded redacted output."""

import os
import re
import selectors
import stat
import subprocess
import sys
import time
from collections.abc import Iterable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path

from scylla_vms.errors import ToolExecutionError, ToolPrerequisiteError
from scylla_vms.redaction import redact

_EXECUTABLE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SECRET_ARGUMENT = re.compile(
    r"(?i)(?:^|[-_])(?:password|passphrase|secret|token|private[-_]?key)(?:$|[-_=])"
)
_BASE_ENVIRONMENT = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
if sys.platform == "darwin":
    _BASE_ENVIRONMENT["__CF_USER_TEXT_ENCODING"] = f"0x{os.getuid():X}:0x0:0x0"
_BASE_ENVIRONMENT_NAMES = frozenset(_BASE_ENVIRONMENT)


class ExecutableNotFoundError(ToolPrerequisiteError):
    """An explicitly searched executable was unavailable."""


class ProcessLaunchError(ToolPrerequisiteError):
    """The operating system refused a validated process launch."""


class ProcessTimeoutError(ToolExecutionError):
    """A controlled process exceeded its deadline."""


class ProcessOutputError(ToolExecutionError):
    """Controlled process output was oversized or malformed."""


class ProcessExitError(ToolExecutionError):
    """A controlled process returned an unapproved exit status."""


@dataclass(frozen=True, slots=True)
class EnvironmentVariable:
    """One controlled child-process variable."""

    name: str
    value: str = field(repr=False)
    sensitive: bool = False


@dataclass(frozen=True, slots=True)
class ControlledEnvironment:
    """Exact child environment; values are never included in representations."""

    variables: tuple[EnvironmentVariable, ...] = field(repr=False)

    @classmethod
    def create(
        cls,
        values: Mapping[str, str],
        *,
        allowed_names: Iterable[str],
        sensitive_names: Iterable[str] = (),
    ) -> "ControlledEnvironment":
        if not all(isinstance(name, str) for name in values):
            raise ToolPrerequisiteError("child environment variable name is invalid")
        if not all(isinstance(value, str) for value in values.values()):
            raise ToolPrerequisiteError("child environment variable value is invalid")
        allowed = frozenset(allowed_names) | _BASE_ENVIRONMENT_NAMES
        unknown = sorted(set(values) - allowed)
        if unknown:
            raise ToolPrerequisiteError(
                "child environment contains unapproved variable name(s): "
                + ", ".join(unknown)
            )
        sensitive = frozenset(sensitive_names)
        if not sensitive <= set(values):
            raise ToolPrerequisiteError(
                "sensitive child environment names must be present and allowlisted"
            )
        merged = {**_BASE_ENVIRONMENT, **values}
        variables: list[EnvironmentVariable] = []
        for name in sorted(merged):
            value = merged[name]
            if (
                not name.isascii()
                or not name
                or "=" in name
                or "\0" in name
                or not isinstance(value, str)
                or "\0" in value
            ):
                raise ToolPrerequisiteError("child environment entry is invalid")
            variables.append(EnvironmentVariable(name, value, name in sensitive))
        return cls(tuple(variables))

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(variable.name for variable in self.variables)

    def for_subprocess(self) -> dict[str, str]:
        return {variable.name: variable.value for variable in self.variables}

    def sensitive_values(self) -> tuple[str, ...]:
        return tuple(
            variable.value for variable in self.variables if variable.sensitive
        )


@dataclass(frozen=True, slots=True)
class ProcessSpec:
    """Fully resolved process request with no ambient path or environment lookup."""

    argv: tuple[str, ...] = field(repr=False)
    cwd: Path = field(repr=False)
    environment: ControlledEnvironment = field(repr=False)
    timeout_seconds: float
    max_output_bytes: int
    allowed_exit_codes: frozenset[int] = frozenset({0})
    sensitive_values: tuple[str, ...] = field(default=(), repr=False)
    sensitive_paths: tuple[Path, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        if not self.argv or not all(
            isinstance(argument, str) and argument and "\0" not in argument
            for argument in self.argv
        ):
            raise ToolPrerequisiteError("process argv must contain non-empty strings")
        executable = Path(self.argv[0])
        validate_executable(executable)
        if not self.cwd.is_absolute() or self.cwd.resolve(strict=False) != self.cwd:
            raise ToolPrerequisiteError("process working directory must be canonical")
        try:
            cwd_stat = self.cwd.lstat()
        except OSError as error:
            raise ToolPrerequisiteError(
                "process working directory is unavailable"
            ) from error
        if stat.S_ISLNK(cwd_stat.st_mode) or not stat.S_ISDIR(cwd_stat.st_mode):
            raise ToolPrerequisiteError(
                "process working directory must be a non-symlink directory"
            )
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or self.timeout_seconds <= 0
        ):
            raise ToolPrerequisiteError("process timeout must be positive")
        if (
            isinstance(self.max_output_bytes, bool)
            or not isinstance(self.max_output_bytes, int)
            or self.max_output_bytes < 1
        ):
            raise ToolPrerequisiteError("process output limit must be positive")
        if not self.allowed_exit_codes or not all(
            isinstance(code, int) and not isinstance(code, bool)
            for code in self.allowed_exit_codes
        ):
            raise ToolPrerequisiteError("allowed process exit codes are invalid")
        protected = tuple(
            value
            for value in (*self.sensitive_values, *self.environment.sensitive_values())
            if value
        )
        if not all(isinstance(value, str) and "\0" not in value for value in protected):
            raise ToolPrerequisiteError("protected process value is invalid")
        for argument in self.argv:
            if _SECRET_ARGUMENT.search(argument) or "-----BEGIN " in argument:
                raise ToolPrerequisiteError(
                    "secret-bearing process arguments are forbidden"
                )
            if any(value in argument for value in protected):
                raise ToolPrerequisiteError(
                    "protected environment values are forbidden in process arguments"
                )
        for path in self.sensitive_paths:
            if not path.is_absolute():
                raise ToolPrerequisiteError("sensitive process paths must be absolute")

    @property
    def executable(self) -> Path:
        return Path(self.argv[0])

    def display_argv(self) -> tuple[str, ...]:
        protected_paths = tuple(str(path) for path in self.sensitive_paths)
        result: list[str] = []
        for argument in self.argv:
            displayed = redact(
                argument,
                (*self.sensitive_values, *self.environment.sensitive_values()),
            )
            for path in protected_paths:
                displayed = displayed.replace(path, "[REDACTED_PATH]")
            result.append(displayed)
        return tuple(result)


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """Deterministic sanitized process result."""

    exit_code: int
    stdout: str = field(repr=False)
    stderr: str = field(repr=False)


class ProcessRunner:
    """Launch controlled subprocesses without a shell or ambient environment."""

    def run(self, spec: ProcessSpec) -> ProcessResult:
        try:
            process = subprocess.Popen(
                list(spec.argv),
                cwd=spec.cwd,
                env=spec.environment.for_subprocess(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                umask=0o077,
            )
        except OSError as error:
            raise ProcessLaunchError(
                "controlled process could not be launched"
            ) from error
        stdout, stderr = self._capture(process, spec)
        try:
            decoded_stdout = stdout.decode("utf-8", errors="strict")
            decoded_stderr = stderr.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ProcessOutputError(
                "controlled process output is not valid UTF-8"
            ) from error
        sanitized_stdout = _sanitize_output(decoded_stdout, spec)
        sanitized_stderr = _sanitize_output(decoded_stderr, spec)
        if process.returncode not in spec.allowed_exit_codes:
            raise ProcessExitError(
                f"controlled process failed with exit code {process.returncode}"
            )
        return ProcessResult(process.returncode, sanitized_stdout, sanitized_stderr)

    def _capture(
        self, process: subprocess.Popen[bytes], spec: ProcessSpec
    ) -> tuple[bytes, bytes]:
        if process.stdout is None or process.stderr is None:
            _terminate(process)
            raise ToolExecutionError("controlled process capture was unavailable")
        selector = selectors.DefaultSelector()
        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        streams = {
            process.stdout.fileno(): stdout_buffer,
            process.stderr.fileno(): stderr_buffer,
        }
        for descriptor in streams:
            selector.register(descriptor, selectors.EVENT_READ)
        total = 0
        deadline = time.monotonic() + spec.timeout_seconds
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _terminate(process)
                    raise ProcessTimeoutError("controlled process timed out")
                events = selector.select(remaining)
                if not events:
                    _terminate(process)
                    raise ProcessTimeoutError("controlled process timed out")
                for key, _ in events:
                    descriptor = key.fd
                    if descriptor not in streams:
                        continue
                    chunk = os.read(descriptor, 65536)
                    if not chunk:
                        selector.unregister(descriptor)
                        continue
                    total += len(chunk)
                    if total > spec.max_output_bytes:
                        _terminate(process)
                        raise ProcessOutputError(
                            "controlled process output exceeded the size limit"
                        )
                    streams[descriptor].extend(chunk)
            process.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            _terminate(process)
            raise ProcessTimeoutError("controlled process timed out") from error
        except KeyboardInterrupt:
            _terminate(process)
            raise
        except OSError as error:
            _terminate(process)
            raise ProcessOutputError(
                "controlled process output could not be captured"
            ) from error
        finally:
            selector.close()
            process.stdout.close()
            process.stderr.close()
        return bytes(stdout_buffer), bytes(stderr_buffer)


def discover_executable(name: str, directories: Sequence[Path]) -> Path:
    """Resolve an executable from explicit directories without ambient PATH."""

    if not _EXECUTABLE_NAME.fullmatch(name):
        raise ToolPrerequisiteError("executable name is invalid")
    for directory in directories:
        if not directory.is_absolute() or directory.resolve(strict=False) != directory:
            raise ToolPrerequisiteError(
                "executable search directories must be canonical and absolute"
            )
        candidate = directory / name
        try:
            validate_executable(candidate)
        except ToolPrerequisiteError:
            continue
        return candidate
    raise ExecutableNotFoundError(f"required executable is unavailable: {name}")


def validate_executable(path: Path) -> Path:
    """Validate one explicit executable path without following a symlink."""

    if not path.is_absolute() or path.resolve(strict=False) != path:
        raise ToolPrerequisiteError("executable path must be canonical and absolute")
    try:
        path_stat = path.lstat()
    except OSError as error:
        raise ToolPrerequisiteError("executable path is unavailable") from error
    if (
        stat.S_ISLNK(path_stat.st_mode)
        or not stat.S_ISREG(path_stat.st_mode)
        or path_stat.st_nlink != 1
        or not os.access(path, os.X_OK)
    ):
        raise ToolPrerequisiteError(
            "executable must be a singly linked executable regular file"
        )
    return path


def _sanitize_output(value: str, spec: ProcessSpec) -> str:
    sanitized = redact(
        value,
        (*spec.sensitive_values, *spec.environment.sensitive_values()),
    )
    for path in spec.sensitive_paths:
        sanitized = sanitized.replace(str(path), "[REDACTED_PATH]")
    return sanitized


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.kill()
    with suppress(subprocess.TimeoutExpired):
        process.wait(timeout=1)
