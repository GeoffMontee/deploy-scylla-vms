"""Controlled OpenSSH host-key discovery and local inspection boundary."""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from scylla_vms.ansible.trust import (
    HostEndpoint,
    HostKeyCandidate,
    TrustCaptureSource,
    parse_keyscan_output,
)
from scylla_vms.errors import AnsibleError, ToolExecutionError, ToolPrerequisiteError
from scylla_vms.process import (
    ControlledEnvironment,
    ProcessResult,
    ProcessSpec,
    validate_executable,
)
from scylla_vms.state import StatePaths, validate_state_directory, validate_state_file

_SSH_ENVIRONMENT = frozenset({"HOME"})
_KEYSCAN_TYPES = ("ecdsa", "ed25519")


class ProcessRunnerProtocol(Protocol):
    def run(self, spec: ProcessSpec) -> ProcessResult:
        """Run one controlled process."""


@dataclass(frozen=True, slots=True)
class SSHKeyCommand:
    process: ProcessSpec
    action: str


class SSHKeyCommandBuilder:
    """Build only direct keyscan and local known-host inspection commands."""

    def __init__(
        self,
        keyscan_executable: Path,
        keygen_executable: Path,
        paths: StatePaths,
        *,
        timeout_seconds: float = 15.0,
        output_limit: int = 128 * 1024,
    ) -> None:
        self._keyscan = validate_executable(keyscan_executable)
        self._keygen = validate_executable(keygen_executable)
        validate_state_directory(paths.ansible)
        validate_state_directory(paths.ansible_home)
        validate_state_file(paths.known_hosts, allow_missing=True)
        self._paths = paths
        self._timeout = timeout_seconds
        self._output_limit = output_limit
        self._environment = ControlledEnvironment.create(
            {"HOME": str(paths.ansible_home)}, allowed_names=_SSH_ENVIRONMENT
        )

    @property
    def paths(self) -> StatePaths:
        return self._paths

    def scan(
        self, endpoint: HostEndpoint, *, jump_host_id: str | None
    ) -> SSHKeyCommand:
        if jump_host_id is not None:
            raise AnsibleError(
                "private host-key scan through a jump is unsupported by the safe "
                "portable boundary; trust jump hosts first, then supply independently "
                "verified private-host candidates"
            )
        timeout = max(1, min(60, int(self._timeout)))
        return self._command(
            "scan",
            self._keyscan,
            (
                "-T",
                str(timeout),
                "-p",
                str(endpoint.port),
                "-t",
                ",".join(_KEYSCAN_TYPES),
                endpoint.address,
            ),
            endpoint,
        )

    def inspect(self, endpoint: HostEndpoint) -> SSHKeyCommand:
        validate_state_file(self._paths.known_hosts)
        return self._command(
            "inspect",
            self._keygen,
            (
                "-F",
                endpoint.known_hosts_name,
                "-f",
                str(self._paths.known_hosts),
            ),
            endpoint,
        )

    def _command(
        self,
        action: str,
        executable: Path,
        arguments: tuple[str, ...],
        endpoint: HostEndpoint,
    ) -> SSHKeyCommand:
        return SSHKeyCommand(
            ProcessSpec(
                argv=(str(executable), *arguments),
                cwd=self._paths.ansible,
                environment=self._environment,
                timeout_seconds=self._timeout,
                max_output_bytes=self._output_limit,
                sensitive_paths=(
                    self._paths.cluster_root,
                    self._paths.known_hosts,
                ),
            ),
            action,
        )


class SSHKeyDiscoveryService:
    """Run candidate discovery without granting trust."""

    def __init__(
        self, builder: SSHKeyCommandBuilder, runner: ProcessRunnerProtocol
    ) -> None:
        self._builder = builder
        self._runner = runner

    def discover(
        self,
        *,
        logical_id: str,
        provider_id: str,
        endpoint: HostEndpoint,
        jump_host_id: str | None,
        captured_at: datetime,
    ) -> tuple[HostKeyCandidate, ...]:
        command = self._builder.scan(endpoint, jump_host_id=jump_host_id)
        try:
            result = self._runner.run(command.process)
        except (ToolExecutionError, ToolPrerequisiteError) as error:
            raise AnsibleError("SSH host-key candidate discovery failed") from error
        if result.exit_code != 0:
            raise AnsibleError("SSH host-key candidate discovery failed")
        return parse_keyscan_output(
            result.stdout,
            logical_id=logical_id,
            provider_id=provider_id,
            endpoint=endpoint,
            jump_host_id=jump_host_id,
            captured_at=captured_at,
            maximum_bytes=command.process.max_output_bytes,
        )

    def inspect(
        self,
        *,
        logical_id: str,
        provider_id: str,
        endpoint: HostEndpoint,
        jump_host_id: str | None,
        inspected_at: datetime,
    ) -> tuple[HostKeyCandidate, ...]:
        """Inspect only the canonical local known-hosts file."""

        command = self._builder.inspect(endpoint)
        try:
            result = self._runner.run(command.process)
        except (ToolExecutionError, ToolPrerequisiteError) as error:
            raise AnsibleError("SSH known-host inspection failed") from error
        if result.exit_code != 0:
            raise AnsibleError("SSH known-host inspection failed")
        return parse_keyscan_output(
            result.stdout,
            logical_id=logical_id,
            provider_id=provider_id,
            endpoint=endpoint,
            jump_host_id=jump_host_id,
            captured_at=inspected_at,
            capture_source=TrustCaptureSource.LOCAL_KNOWN_HOSTS,
            maximum_bytes=command.process.max_output_bytes,
        )
