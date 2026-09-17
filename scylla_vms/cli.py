"""Argparse and configuration boundary for the non-executable operation CLI."""

import argparse
import sys
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Never, TextIO, cast

from scylla_vms import __version__
from scylla_vms.ansible.service import ProcessRunnerProtocol
from scylla_vms.config import resolve_operation_request
from scylla_vms.contracts import (
    CORE_FIELDS,
    FieldSpec,
    ValueKind,
    default_for_operation,
    fields_for_operation,
)
from scylla_vms.errors import (
    ApplicationError,
    ConfigurationError,
    ExitCode,
    OperationNotImplementedError,
)
from scylla_vms.models import OperationRequest
from scylla_vms.operations import OPERATIONS
from scylla_vms.redaction import redact


class _ArgumentParser(argparse.ArgumentParser):
    _stdout: TextIO = sys.stdout
    _stderr: TextIO = sys.stderr

    def set_streams(
        self, *, stdout: TextIO | None = None, stderr: TextIO | None = None
    ) -> None:
        self._stdout = stdout or sys.stdout
        self._stderr = stderr or sys.stderr

    def _print_message(self, message: str | None, file: object | None = None) -> None:
        if message:
            target = cast(TextIO | None, file)
            if target is None or target is sys.stdout:
                target = self._stdout
            elif target is sys.stderr:
                target = self._stderr
            target.write(message)

    def error(self, message: str) -> Never:
        raise ConfigurationError(message)


def build_parser(
    *, stdout: TextIO | None = None, stderr: TextIO | None = None
) -> argparse.ArgumentParser:
    """Build all exact allowlists from the immutable contract registry."""

    parser = _ArgumentParser(
        prog="deploy-scylla-vms",
        description=(
            "Inspect validated local ScyllaDB VM cluster state. Show and guarded "
            "jump-host checks are implemented; all mutating workflows remain disabled."
        ),
    )
    parser.set_streams(stdout=stdout, stderr=stderr)
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    for field in CORE_FIELDS:
        _add_field(parser, field)

    core_names = {field.name for field in CORE_FIELDS}
    subparsers = parser.add_subparsers(
        title="registered operations",
        dest="operation",
        required=True,
        parser_class=_ArgumentParser,
    )
    for operation in OPERATIONS:
        subparser = subparsers.add_parser(
            operation.name,
            help=operation.summary,
            description=(
                f"{operation.summary} "
                + (
                    "This release reads validated local persisted state without "
                    "writing or performing external checks."
                    if operation.name == "show"
                    else (
                        "This release performs guarded read-only Ansible checks "
                        "against validated persisted jump hosts."
                        if operation.name == "check-jump-hosts"
                        else "This release validates the documented request contract, "
                        "then exits without side effects."
                    )
                )
            ),
        )
        subparser.set_streams(stdout=stdout, stderr=stderr)
        subparser.set_defaults(operation=operation.name)
        for field in fields_for_operation(operation.name):
            if field.name not in core_names:
                _add_field(subparser, field, operation.name)
    return parser


def parse_operation_request(
    argv: Sequence[str],
    *,
    environ: Mapping[str, str] | None = None,
    default_state_root: Path | None = None,
) -> OperationRequest:
    """Parse and validate a request without executing or creating state."""

    parser = build_parser()
    arguments = parser.parse_args(argv)
    factory = None if default_state_root is None else lambda: default_state_root
    return resolve_operation_request(
        vars(arguments), environ=environ, default_state_root=factory
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    clock: Callable[[], datetime] | None = None,
    process_runner: ProcessRunnerProtocol | None = None,
    ansible_playbook_executable: Path | None = None,
    ansible_inventory_executable: Path | None = None,
) -> int:
    """Run the CLI and map known failures to stable public exit codes."""

    output = stdout or sys.stdout
    errors = stderr or sys.stderr
    parser = build_parser(stdout=output, stderr=errors)
    try:
        arguments = parser.parse_args(argv)
        request = resolve_operation_request(vars(arguments), environ=environ)
        if request.operation.name == "show":
            from scylla_vms.show import run_show

            return run_show(request, output, clock=clock)
        if request.operation.name == "check-jump-hosts":
            from scylla_vms.check_jump_hosts import run_check_jump_hosts

            return run_check_jump_hosts(
                request,
                output,
                runner=process_runner,
                playbook_executable=ansible_playbook_executable,
                inventory_executable=ansible_inventory_executable,
                clock=clock,
            )
        raise OperationNotImplementedError(
            f"operation '{request.operation.name}' request is valid but its workflow "
            "is not implemented; no state or infrastructure changes were made"
        )
    except ApplicationError as error:
        errors.write(f"error: {redact(str(error))}\n")
        return int(error.exit_code)
    except KeyboardInterrupt:
        errors.write("error: operation cancelled\n")
        return int(ExitCode.CANCELLED)


def _add_field(
    parser: argparse.ArgumentParser,
    field: FieldSpec,
    operation: str | None = None,
) -> None:
    help_text = _field_help(field, operation)
    if field.kind is ValueKind.BOOLEAN:
        parser.add_argument(
            field.flag,
            dest=field.name,
            default=None,
            action="store_true",
            help=help_text,
        )
    elif field.kind in {ValueKind.ENUM, ValueKind.ENUM_LIST}:
        parser.add_argument(
            field.flag,
            dest=field.name,
            default=None,
            action="append" if field.repeatable else "store",
            type=_normalized_enum,
            choices=field.choices,
            help=help_text,
        )
    else:
        parser.add_argument(
            field.flag,
            dest=field.name,
            default=None,
            action="append" if field.repeatable else "store",
            metavar=_metavar(field),
            help=help_text,
        )


def _field_help(field: FieldSpec, operation: str | None) -> str:
    description = field.help or f"Validate the documented {field.flag} request value."
    details: list[str] = []
    if field.environment is not None:
        details.append(f"environment: {field.environment}")
    default = (
        field.default if operation is None else default_for_operation(operation, field)
    )
    if field.name == "state_dir":
        details.append("default: platform user state directory")
    elif default is not None:
        if default == ():
            details.append("default: empty")
        else:
            details.append(f"default: {default}")
    elif field.name != "config":
        details.append("no built-in default; see PLAN.md")
    if not details:
        return description
    return f"{description} ({'; '.join(details)})"


def _metavar(field: FieldSpec) -> str:
    if field.kind in {
        ValueKind.STRING_MAP,
        ValueKind.INTEGER_MAP,
        ValueKind.ENUM_MAP,
        ValueKind.CIDR_MAP,
    }:
        return "KEY=VALUE"
    if field.kind is ValueKind.PATH:
        return "PATH"
    if field.kind is ValueKind.INTEGER:
        return "INTEGER"
    if field.kind is ValueKind.FLOAT:
        return "SECONDS"
    if field.kind is ValueKind.UUID:
        return "UUID"
    if field.kind is ValueKind.CIDR:
        return "CIDR"
    return "VALUE"


def _normalized_enum(value: str) -> str:
    normalized = value.strip().lower()
    if not normalized or not normalized.isascii():
        raise argparse.ArgumentTypeError("must be a non-empty ASCII registry name")
    return normalized
