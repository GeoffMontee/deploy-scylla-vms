"""Pure, fully anchored Terraform command construction."""

import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from scylla_vms.errors import TerraformError, UnsafePathError
from scylla_vms.process import ControlledEnvironment, ProcessSpec, validate_executable
from scylla_vms.state import (
    StatePaths,
    validate_state_directory,
    validate_state_file,
)
from scylla_vms.terraform.source import (
    StoredTerraformSource,
    validate_staged_source,
)

DEFAULT_TERRAFORM_TIMEOUT_SECONDS = 300.0
DEFAULT_TERRAFORM_OUTPUT_LIMIT = 4 * 1024 * 1024
_TERRAFORM_ENVIRONMENT_NAMES = frozenset(
    {
        "CHECKPOINT_DISABLE",
        "HOME",
        "TF_DATA_DIR",
        "TF_IN_AUTOMATION",
        "TF_INPUT",
        "TF_PLUGIN_CACHE_DIR",
    }
)


class TerraformCommandKind(Enum):
    """Terraform phases exposed by the controlled command boundary."""

    VERSION = "version"
    INIT = "init"
    FMT_CHECK = "fmt-check"
    VALIDATE = "validate"
    PLAN = "plan"
    SHOW_PLAN = "show-plan"
    APPLY_PLAN = "apply-plan"
    OUTPUT = "output"


@dataclass(frozen=True, slots=True)
class TerraformCommand:
    """A typed Terraform phase and its controlled process request."""

    kind: TerraformCommandKind
    process: ProcessSpec
    plan_path: Path | None = field(default=None, repr=False)
    source_digest: str | None = None


class TerraformCommandBuilder:
    """Construct commands that cannot escape one canonical cluster root."""

    def __init__(
        self,
        executable: Path,
        paths: StatePaths,
        *,
        timeout_seconds: float = DEFAULT_TERRAFORM_TIMEOUT_SECONDS,
        output_limit: int = DEFAULT_TERRAFORM_OUTPUT_LIMIT,
        terraform_lock_timeout_seconds: float = 30.0,
        source: StoredTerraformSource | None = None,
    ) -> None:
        self._executable = validate_executable(executable)
        expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
        if expected != paths:
            raise UnsafePathError("Terraform paths do not match the canonical layout")
        for path in (
            paths.terraform,
            paths.terraform_work,
            paths.terraform_data,
            paths.terraform_plugin_cache,
            paths.terraform_state,
            paths.terraform_plans,
        ):
            _require_below(path, paths.cluster_root)
        validate_state_directory(paths.terraform_work)
        validate_state_directory(paths.terraform_data)
        validate_state_directory(paths.terraform_plugin_cache)
        validate_state_directory(paths.terraform_plans)
        validate_state_file(paths.terraform_state, allow_missing=True)
        self._paths = paths
        if source is not None:
            validate_staged_source(paths, source)
        self._source_digest = (
            source.record.bundle_digest if source is not None else None
        )
        self._source_planning_ready = (
            source.record.planning_ready if source is not None else None
        )
        self._timeout = timeout_seconds
        self._output_limit = output_limit
        if terraform_lock_timeout_seconds < 0:
            raise TerraformError("Terraform lock timeout must not be negative")
        self._lock_timeout = _seconds(terraform_lock_timeout_seconds)
        self._environment = ControlledEnvironment.create(
            {
                "CHECKPOINT_DISABLE": "1",
                "HOME": str(paths.terraform),
                "TF_DATA_DIR": str(paths.terraform_data),
                "TF_IN_AUTOMATION": "1",
                "TF_INPUT": "0",
                "TF_PLUGIN_CACHE_DIR": str(paths.terraform_plugin_cache),
            },
            allowed_names=_TERRAFORM_ENVIRONMENT_NAMES,
        )

    @property
    def paths(self) -> StatePaths:
        return self._paths

    def version(self) -> TerraformCommand:
        return self._command(TerraformCommandKind.VERSION, ("version", "-json"))

    def init(self) -> TerraformCommand:
        return self._command(
            TerraformCommandKind.INIT,
            (
                "init",
                "-input=false",
                "-no-color",
                "-lockfile=readonly",
                f"-lock-timeout={self._lock_timeout}",
                f"-backend-config=path={self._paths.terraform_state}",
            ),
        )

    def fmt_check(self) -> TerraformCommand:
        return self._command(
            TerraformCommandKind.FMT_CHECK,
            ("fmt", "-check", "-diff", "-recursive"),
        )

    def validate(self) -> TerraformCommand:
        return self._command(
            TerraformCommandKind.VALIDATE,
            ("validate", "-json", "-no-color"),
        )

    def plan(self, operation_id: uuid.UUID) -> TerraformCommand:
        return self._plan_command(self.plan_path(operation_id, must_exist=False))

    def plan_staged(self, operation_id: uuid.UUID) -> TerraformCommand:
        """Build a plan command that can publish only to its staging path."""

        return self._plan_command(self.staged_plan_path(operation_id, must_exist=False))

    def _plan_command(self, plan_path: Path) -> TerraformCommand:
        if self._source_planning_ready is False:
            raise TerraformError("staged Terraform source is not planning-ready")
        if plan_path.exists():
            raise TerraformError("Terraform plan path already exists")
        return self._command(
            TerraformCommandKind.PLAN,
            (
                "plan",
                "-input=false",
                "-no-color",
                "-detailed-exitcode",
                "-lock=true",
                f"-lock-timeout={self._lock_timeout}",
                f"-state={self._paths.terraform_state}",
                f"-out={plan_path}",
            ),
            allowed_exit_codes=frozenset({0, 2}),
            plan_path=plan_path,
        )

    def show_plan(self, operation_id: uuid.UUID) -> TerraformCommand:
        plan_path = self.plan_path(operation_id, must_exist=True)
        return self._show_plan_command(plan_path)

    def show_staged_plan(self, operation_id: uuid.UUID) -> TerraformCommand:
        """Build an exact show command for the operation's staged saved plan."""

        return self._show_plan_command(
            self.staged_plan_path(operation_id, must_exist=True)
        )

    def _show_plan_command(self, plan_path: Path) -> TerraformCommand:
        return self._command(
            TerraformCommandKind.SHOW_PLAN,
            ("show", "-json", "-no-color", str(plan_path)),
            plan_path=plan_path,
        )

    def apply_plan(self, operation_id: uuid.UUID) -> TerraformCommand:
        """Build the sole exact-saved-plan apply command."""

        if self._source_planning_ready is False:
            raise TerraformError("staged Terraform source is not apply-ready")
        plan_path = self.plan_path(operation_id, must_exist=True)
        return self._command(
            TerraformCommandKind.APPLY_PLAN,
            (
                "apply",
                "-input=false",
                "-no-color",
                "-lock=true",
                f"-lock-timeout={self._lock_timeout}",
                str(plan_path),
            ),
            # Terraform may have crossed the mutation boundary before any
            # nonzero result. The execution owner records the bounded status
            # instead of allowing the generic runner to discard it.
            allowed_exit_codes=frozenset(range(-255, 256)),
            plan_path=plan_path,
        )

    def output(self) -> TerraformCommand:
        validate_state_file(self._paths.terraform_state)
        return self._command(
            TerraformCommandKind.OUTPUT,
            (
                "output",
                "-json",
                "-no-color",
                f"-state={self._paths.terraform_state}",
            ),
        )

    def plan_path(self, operation_id: uuid.UUID, *, must_exist: bool) -> Path:
        if not isinstance(operation_id, uuid.UUID) or str(operation_id) != str(
            uuid.UUID(str(operation_id))
        ):
            raise TerraformError("Terraform plan operation ID is invalid")
        path = self._paths.terraform_plans / f"{operation_id}.tfplan"
        _require_below(path, self._paths.cluster_root)
        validate_state_file(path, allow_missing=not must_exist)
        return path

    def staged_plan_path(self, operation_id: uuid.UUID, *, must_exist: bool) -> Path:
        if not isinstance(operation_id, uuid.UUID) or str(operation_id) != str(
            uuid.UUID(str(operation_id))
        ):
            raise TerraformError("Terraform plan operation ID is invalid")
        path = self._paths.terraform_plans / f"{operation_id}.tfplan.staging"
        _require_below(path, self._paths.cluster_root)
        validate_state_file(path, allow_missing=not must_exist)
        return path

    def _command(
        self,
        kind: TerraformCommandKind,
        arguments: tuple[str, ...],
        *,
        allowed_exit_codes: frozenset[int] = frozenset({0}),
        plan_path: Path | None = None,
    ) -> TerraformCommand:
        argv = (
            str(self._executable),
            f"-chdir={self._paths.terraform_work}",
            *arguments,
        )
        return TerraformCommand(
            kind,
            ProcessSpec(
                argv=argv,
                cwd=self._paths.cluster_root,
                environment=self._environment,
                timeout_seconds=self._timeout,
                max_output_bytes=self._output_limit,
                allowed_exit_codes=allowed_exit_codes,
                sensitive_paths=(self._paths.cluster_root,),
            ),
            plan_path,
            self._source_digest,
        )


def _require_below(path: Path, root: Path) -> None:
    if not path.is_absolute() or path.resolve(strict=False) != path:
        raise UnsafePathError("Terraform path must be canonical and absolute")
    if path == root or root not in path.parents:
        raise UnsafePathError("Terraform path escapes the canonical cluster root")


def _seconds(value: float) -> str:
    return f"{value:g}s"
