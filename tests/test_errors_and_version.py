from pathlib import Path

from scylla_vms import __version__
from scylla_vms.errors import (
    ConfigurationError,
    ExitCode,
    OperationNotImplementedError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.redaction import redact

ROOT = Path(__file__).resolve().parents[1]


def test_stable_failure_exit_codes() -> None:
    assert ConfigurationError.exit_code is ExitCode.CONFIGURATION
    assert UnsafePathError.exit_code is ExitCode.UNSAFE_REFUSAL
    assert StateLockError.exit_code is ExitCode.LOCK_CONFLICT
    assert StateConflictError.exit_code is ExitCode.DRIFT_CONFLICT
    assert StatePersistenceError.exit_code is ExitCode.UNSAFE_REFUSAL
    assert OperationNotImplementedError.exit_code is ExitCode.UNSAFE_REFUSAL


def test_redaction_removes_explicit_and_assignment_secrets() -> None:
    secret = "fake-sensitive-literal"
    diagnostic = (
        f"failed with API_TOKEN={secret}; second occurrence {secret} "
        "and PASSWORD=another-fake-value"
    )

    result = redact(diagnostic, [secret])

    assert secret not in result
    assert "another-fake-value" not in result
    assert result.count("[REDACTED]") == 3


def test_version_files_are_consistent() -> None:
    version_file = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert __version__ == version_file
    assert f'version = "{version_file}"' in pyproject
