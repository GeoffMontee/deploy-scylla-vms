"""Lock-gated execution of non-apply Terraform phases."""

import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from scylla_vms.errors import TerraformError, ToolExecutionError, ToolPrerequisiteError
from scylla_vms.locking import ClusterLock
from scylla_vms.process import ProcessResult, ProcessSpec
from scylla_vms.state import (
    refuse_unexpected_terraform_state,
    validate_state_file,
)
from scylla_vms.terraform.commands import TerraformCommand, TerraformCommandBuilder
from scylla_vms.terraform.toolchain import (
    TerraformToolchain,
    parse_terraform_version_json,
)


class ProcessRunnerProtocol(Protocol):
    def run(self, spec: ProcessSpec) -> ProcessResult:
        """Run one fully controlled process request."""


@dataclass(frozen=True, slots=True)
class TerraformPlanResult:
    """Interpreted result of Terraform's detailed plan exit status."""

    has_changes: bool
    plan_path: Path = field(repr=False)


class TerraformService:
    """Execute only version/init/fmt/validate/plan/show/output commands."""

    def __init__(
        self, builder: TerraformCommandBuilder, runner: ProcessRunnerProtocol
    ) -> None:
        self._builder = builder
        self._runner = runner

    def version(self, lock: ClusterLock) -> TerraformToolchain:
        lock.assert_held_for(self._builder.paths)
        result = self._run(self._builder.version())
        return TerraformToolchain(parse_terraform_version_json(result.stdout))

    def init(
        self, lock: ClusterLock, *, unexpected_state_roots: tuple[Path, ...]
    ) -> ProcessResult:
        lock.assert_held_for(self._builder.paths)
        refuse_unexpected_terraform_state(self._builder.paths, unexpected_state_roots)
        return self._run(self._builder.init())

    def fmt_check(self, lock: ClusterLock) -> ProcessResult:
        lock.assert_held_for(self._builder.paths)
        return self._run(self._builder.fmt_check())

    def validate(self, lock: ClusterLock) -> ProcessResult:
        lock.assert_held_for(self._builder.paths)
        return self._run(self._builder.validate())

    def plan(self, lock: ClusterLock, operation_id: uuid.UUID) -> TerraformPlanResult:
        lock.assert_held_for(self._builder.paths)
        command = self._builder.plan(operation_id)
        return self._run_plan(command)

    def plan_staged(
        self, lock: ClusterLock, operation_id: uuid.UUID
    ) -> TerraformPlanResult:
        """Create only the operation's canonical same-directory staging plan."""

        lock.assert_held_for(self._builder.paths)
        command = self._builder.plan_staged(operation_id)
        return self._run_plan(command)

    def _run_plan(self, command: TerraformCommand) -> TerraformPlanResult:
        result = self._run(command)
        if command.plan_path is None:
            raise TerraformError("Terraform plan command has no output path")
        validate_state_file(command.plan_path)
        return TerraformPlanResult(result.exit_code == 2, command.plan_path)

    def show_plan(self, lock: ClusterLock, operation_id: uuid.UUID) -> str:
        lock.assert_held_for(self._builder.paths)
        return self._run(self._builder.show_plan(operation_id)).stdout

    def show_staged_plan(self, lock: ClusterLock, operation_id: uuid.UUID) -> str:
        """Render only the operation's canonical staged saved plan."""

        lock.assert_held_for(self._builder.paths)
        return self._run(self._builder.show_staged_plan(operation_id)).stdout

    def output(self, lock: ClusterLock) -> str:
        lock.assert_held_for(self._builder.paths)
        return self._run(self._builder.output()).stdout

    def _run(self, command: TerraformCommand) -> ProcessResult:
        try:
            result = self._runner.run(command.process)
        except (ToolExecutionError, ToolPrerequisiteError) as error:
            raise TerraformError(
                f"Terraform {command.kind.value} command failed"
            ) from error
        if result.exit_code not in command.process.allowed_exit_codes:
            raise TerraformError(
                f"Terraform {command.kind.value} returned an invalid exit status"
            )
        return result
