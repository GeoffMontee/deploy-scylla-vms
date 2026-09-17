"""Pure, anchored Ansible command construction."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from scylla_vms.ansible.registry import CheckMode, PlaybookDefinition, get_playbook
from scylla_vms.ansible.source import packaged_playbook_path
from scylla_vms.errors import AnsibleError, StatePersistenceError, UnsafePathError
from scylla_vms.persistence import digest_bytes, serialize_json
from scylla_vms.process import ControlledEnvironment, ProcessSpec, validate_executable
from scylla_vms.state import (
    StatePaths,
    validate_state_directory,
    validate_state_file,
)

DEFAULT_ANSIBLE_TIMEOUT_SECONDS = 1800.0
DEFAULT_ANSIBLE_OUTPUT_LIMIT = 4 * 1024 * 1024
_ENVIRONMENT_NAMES = frozenset(
    {
        "ANSIBLE_CONFIG",
        "ANSIBLE_HOST_KEY_CHECKING",
        "ANSIBLE_LOCAL_TEMP",
        "ANSIBLE_LOG_PATH",
        "ANSIBLE_NOCOLOR",
        "ANSIBLE_RETRY_FILES_ENABLED",
        "HOME",
        "PYTHONUNBUFFERED",
    }
)
_NON_PERSISTENT_LOG_PLAYBOOKS = frozenset({"routed-keyscan"})
_NON_PERSISTENT_LOG_PATH = "/dev/null"


class AnsibleCommandKind(StrEnum):
    VERSION = "version"
    INVENTORY_LIST = "inventory-list"
    INVENTORY_GRAPH = "inventory-graph"
    PLAYBOOK = "playbook"
    SYNTAX_CHECK = "syntax-check"


@dataclass(frozen=True, slots=True)
class AnsibleCommand:
    kind: AnsibleCommandKind
    process: ProcessSpec
    playbook: str | None = None


class AnsibleCommandBuilder:
    """Build only registry-known playbook and inventory invocations."""

    def __init__(
        self,
        playbook_executable: Path,
        inventory_executable: Path,
        paths: StatePaths,
        *,
        timeout_seconds: float = DEFAULT_ANSIBLE_TIMEOUT_SECONDS,
        output_limit: int = DEFAULT_ANSIBLE_OUTPUT_LIMIT,
    ) -> None:
        self._playbook_executable = validate_executable(playbook_executable)
        self._inventory_executable = validate_executable(inventory_executable)
        expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
        if expected != paths:
            raise UnsafePathError("Ansible paths do not match the canonical layout")
        for directory in (
            paths.ansible,
            paths.ansible_home,
            paths.ansible_local_tmp,
            paths.ansible_fact_cache,
            paths.ansible_control_path,
        ):
            validate_state_directory(directory)
        for file_path in (
            paths.ansible_config,
            paths.ansible_inventory,
            paths.known_hosts,
            paths.ansible_ssh_config,
        ):
            validate_state_file(file_path)
        self._paths = paths
        self._timeout = timeout_seconds
        self._output_limit = output_limit
        environment = {
            "ANSIBLE_CONFIG": str(paths.ansible_config),
            "ANSIBLE_HOST_KEY_CHECKING": "True",
            "ANSIBLE_LOCAL_TEMP": str(paths.ansible_local_tmp),
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_RETRY_FILES_ENABLED": "False",
            "HOME": str(paths.ansible_home),
            "PYTHONUNBUFFERED": "1",
        }
        self._environment = ControlledEnvironment.create(
            environment,
            allowed_names=_ENVIRONMENT_NAMES,
        )
        self._non_persistent_log_environment = ControlledEnvironment.create(
            {**environment, "ANSIBLE_LOG_PATH": _NON_PERSISTENT_LOG_PATH},
            allowed_names=_ENVIRONMENT_NAMES,
        )

    @property
    def paths(self) -> StatePaths:
        return self._paths

    def playbook_version(self) -> AnsibleCommand:
        return self._command(
            AnsibleCommandKind.VERSION,
            self._playbook_executable,
            ("--version",),
        )

    def inventory_version(self) -> AnsibleCommand:
        return self._command(
            AnsibleCommandKind.VERSION,
            self._inventory_executable,
            ("--version",),
        )

    def inventory_list(self) -> AnsibleCommand:
        return self._inventory_command(AnsibleCommandKind.INVENTORY_LIST, "--list")

    def inventory_graph(self) -> AnsibleCommand:
        return self._inventory_command(AnsibleCommandKind.INVENTORY_GRAPH, "--graph")

    def syntax_check(self, name: str) -> AnsibleCommand:
        playbook = get_playbook(name)
        self._require_source(playbook)
        return self._command(
            AnsibleCommandKind.SYNTAX_CHECK,
            self._playbook_executable,
            (
                "--inventory",
                str(self._paths.ansible_inventory),
                "--syntax-check",
                str(packaged_playbook_path(name)),
            ),
            playbook=playbook.name,
        )

    def validate_playbook_request(
        self,
        name: str,
        *,
        limit: tuple[str, ...],
        tags: tuple[str, ...] = (),
        check: bool = False,
        diff: bool = False,
        verbosity: int = 0,
    ) -> tuple[PlaybookDefinition, str]:
        """Validate pure registry policy before any runtime file or process exists."""

        return validate_playbook_request_policy(
            name,
            limit=limit,
            tags=tags,
            check=check,
            diff=diff,
            verbosity=verbosity,
        )

    def validate_operation_step(
        self,
        name: str,
        *,
        step_sequence: int,
        limit: tuple[str, ...],
        variables: Mapping[str, object],
        tags: tuple[str, ...] = (),
        check: bool = False,
        diff: bool = False,
        verbosity: int = 0,
    ) -> tuple[PlaybookDefinition, dict[str, object], str, str]:
        """Rebuild the deterministic command intent through anchored policy."""

        definition, _ = self.validate_playbook_request(
            name,
            limit=limit,
            tags=tags,
            check=check,
            diff=diff,
            verbosity=verbosity,
        )
        if (
            isinstance(step_sequence, bool)
            or not isinstance(step_sequence, int)
            or step_sequence < 1
        ):
            raise AnsibleError("Ansible operation step sequence is invalid")
        if not isinstance(variables, Mapping) or not all(
            isinstance(key, str) for key in variables
        ):
            raise AnsibleError("Ansible operation step variables are invalid")
        validated = definition.validate_variables(dict(variables))
        variables_digest = digest_bytes(serialize_json(validated))
        command_digest = ansible_command_intent_digest(
            definition,
            step_sequence=step_sequence,
            limit=limit,
            variables_digest=variables_digest,
            tags=tags,
            check=check,
            diff=diff,
            verbosity=verbosity,
        )
        return definition, validated, variables_digest, command_digest

    def playbook(
        self,
        name: str,
        *,
        limit: tuple[str, ...],
        extra_vars_path: Path,
        tags: tuple[str, ...] = (),
        check: bool = False,
        diff: bool = False,
        verbosity: int = 0,
    ) -> AnsibleCommand:
        definition, selected = self.validate_playbook_request(
            name,
            limit=limit,
            tags=tags,
            check=check,
            diff=diff,
            verbosity=verbosity,
        )
        self._validate_extra_vars_path(extra_vars_path)
        arguments: list[str] = [
            "--inventory",
            str(self._paths.ansible_inventory),
            "--limit",
            selected,
            "--extra-vars",
            f"@{extra_vars_path}",
        ]
        if tags:
            arguments.extend(("--tags", ",".join(tags)))
        if check:
            arguments.append("--check")
        if diff:
            arguments.append("--diff")
        if verbosity:
            arguments.append("-" + "v" * verbosity)
        arguments.append(str(packaged_playbook_path(name)))
        return self._command(
            AnsibleCommandKind.PLAYBOOK,
            self._playbook_executable,
            tuple(arguments),
            playbook=definition.name,
            environment=(
                self._non_persistent_log_environment
                if definition.name in _NON_PERSISTENT_LOG_PLAYBOOKS
                else self._environment
            ),
            # Preserve bounded result/failure recaps for strict result parsers.
            allowed_exit_codes=frozenset({0, 2, 4}),
        )

    def _require_source(self, definition: PlaybookDefinition) -> None:
        if not definition.source_available:
            raise AnsibleError(
                f"Ansible playbook source is unavailable: {definition.name}"
            )

    def _validate_extra_vars_path(self, path: Path) -> None:
        if (
            not path.is_absolute()
            or path.resolve(strict=False) != path
            or path.parent != self._paths.ansible_local_tmp
            or not path.name.startswith("extra-vars-")
            or path.suffix != ".json"
        ):
            raise AnsibleError(
                "Ansible extra-vars path is not an approved runtime file"
            )
        try:
            validate_state_file(path)
        except (StatePersistenceError, UnsafePathError) as error:
            raise AnsibleError("Ansible extra-vars runtime file is unsafe") from error

    def _inventory_command(
        self, kind: AnsibleCommandKind, action: str
    ) -> AnsibleCommand:
        return self._command(
            kind,
            self._inventory_executable,
            ("--inventory", str(self._paths.ansible_inventory), action),
        )

    def _command(
        self,
        kind: AnsibleCommandKind,
        executable: Path,
        arguments: tuple[str, ...],
        *,
        playbook: str | None = None,
        environment: ControlledEnvironment | None = None,
        allowed_exit_codes: frozenset[int] = frozenset({0}),
    ) -> AnsibleCommand:
        return AnsibleCommand(
            kind,
            ProcessSpec(
                argv=(str(executable), *arguments),
                cwd=self._paths.ansible,
                environment=environment or self._environment,
                timeout_seconds=self._timeout,
                max_output_bytes=self._output_limit,
                allowed_exit_codes=allowed_exit_codes,
                sensitive_paths=(self._paths.cluster_root,),
            ),
            playbook,
        )


def validate_playbook_request_policy(
    name: str,
    *,
    limit: tuple[str, ...],
    tags: tuple[str, ...] = (),
    check: bool = False,
    diff: bool = False,
    verbosity: int = 0,
) -> tuple[PlaybookDefinition, str]:
    """Validate registry command policy without paths, files, or executables."""

    definition = get_playbook(name)
    if not definition.source_available:
        raise AnsibleError(f"Ansible playbook source is unavailable: {definition.name}")
    if check and definition.check_mode is CheckMode.REFUSED:
        raise AnsibleError(f"Ansible check mode is refused for {name}")
    if diff and not check:
        raise AnsibleError("Ansible diff requires explicit check mode")
    if diff and not definition.diff_mode:
        raise AnsibleError(f"Ansible diff mode is refused for {name}")
    if isinstance(verbosity, bool) or not 0 <= verbosity <= 3:
        raise AnsibleError("Ansible verbosity must be between zero and three")
    unknown_tags = sorted(set(tags) - set(definition.tags))
    if tags != tuple(dict.fromkeys(tags)) or unknown_tags:
        raise AnsibleError("Ansible tags are not allowlisted for the playbook")
    return definition, definition.validate_limit(limit)


def ansible_command_intent_digest(
    definition: PlaybookDefinition,
    *,
    step_sequence: int,
    limit: tuple[str, ...],
    variables_digest: str,
    tags: tuple[str, ...],
    check: bool,
    diff: bool,
    verbosity: int,
) -> str:
    """Digest one registry-validated command intent without runtime file paths."""

    return digest_bytes(
        serialize_json(
            {
                "check": check,
                "diff": diff,
                "limit": list(limit),
                "playbook": definition.name,
                "result_schema_version": definition.execution_result_schema_version,
                "schema_version": "deploy-scylla-vms.ansible-command-intent/v1",
                "step_sequence": step_sequence,
                "tags": list(tags),
                "variables_digest": variables_digest,
                "verbosity": verbosity,
            }
        )
    )
