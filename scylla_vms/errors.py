"""Stable application failures and public exit codes."""

from enum import IntEnum


class ExitCode(IntEnum):
    """Public process exit codes defined by the implementation plan."""

    SUCCESS = 0
    CONFIGURATION = 2
    PREREQUISITE = 3
    LOCK_CONFLICT = 4
    DRIFT_CONFLICT = 5
    TERRAFORM = 6
    ANSIBLE = 7
    HEALTH = 8
    CANCELLED = 9
    UNSAFE_REFUSAL = 10
    INTERNAL = 70


class ApplicationError(Exception):
    """Base class for failures safe to map at the CLI boundary."""

    exit_code = ExitCode.INTERNAL


class ConfigurationError(ApplicationError):
    """Invalid CLI or non-secret configuration."""

    exit_code = ExitCode.CONFIGURATION


class UnsafePathError(ApplicationError):
    """A state path failed a safety invariant."""

    exit_code = ExitCode.UNSAFE_REFUSAL


class StateLockError(ApplicationError):
    """A cluster lock could not be acquired safely."""

    exit_code = ExitCode.LOCK_CONFLICT


class StateConflictError(ApplicationError):
    """Canonical and unexpected state identities conflict."""

    exit_code = ExitCode.DRIFT_CONFLICT


class StatePersistenceError(ApplicationError):
    """Persisted application state is missing, corrupt, or unsafe."""

    exit_code = ExitCode.UNSAFE_REFUSAL


class OperationNotImplementedError(ApplicationError):
    """A registered operation has no executable workflow yet."""

    exit_code = ExitCode.UNSAFE_REFUSAL


class ToolPrerequisiteError(ApplicationError):
    """An external executable or controlled launch prerequisite is unavailable."""

    exit_code = ExitCode.PREREQUISITE


class ToolExecutionError(ApplicationError):
    """A controlled external process failed or returned unusable output."""

    exit_code = ExitCode.PREREQUISITE


class TerraformError(ApplicationError):
    """A validated Terraform command failed."""

    exit_code = ExitCode.TERRAFORM


class AnsibleError(ApplicationError):
    """A validated Ansible command or orchestration contract failed."""

    exit_code = ExitCode.ANSIBLE
