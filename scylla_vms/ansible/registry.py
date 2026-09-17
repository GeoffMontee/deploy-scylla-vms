"""Immutable allowlist for packaged playbooks and operation mappings."""

import ipaddress
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from scylla_vms.errors import AnsibleError
from scylla_vms.operations import OperationClassification

_LIMIT_ITEM = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_VARIABLE = re.compile(r"deploy_scylla_vms_[a-z][a-z0-9_]{0,95}\Z")
_SECRET_VALUE = re.compile(
    r"(?i)(?:-----BEGIN [^-]*PRIVATE KEY-----|"
    r"(?:password|passphrase|secret|token)\s*[:=])"
)
_RFC1918 = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class CheckMode(StrEnum):
    SUPPORTED = "supported"
    PREVIEW = "preview"
    REFUSED = "refused"


class LimitPolicy(StrEnum):
    """How Python must scope a registry-approved playbook."""

    EXPLICIT = "explicit"
    SINGLE_LOGICAL_HOST = "single-logical-host"
    PYTHON_COMPUTED_SERIAL_SET = "python-computed-serial-set"


class VariableType(StrEnum):
    BOOLEAN = "boolean"
    FLOAT = "float"
    INTEGER = "integer"
    POSITIVE_INTEGER = "positive-integer"
    STRING = "string"
    STRING_LIST = "string-list"
    DESTINATION_PROBE_LIST = "destination-probe-list"
    JSON_OBJECT = "json-object"
    ROUTED_KEYSCAN_REQUEST = "routed-keyscan-request"


@dataclass(frozen=True, slots=True)
class VariableDefinition:
    name: str
    value_type: VariableType
    choices: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _VARIABLE.fullmatch(self.name):
            raise AnsibleError("Ansible variable name is invalid")

    def validate(self, value: object) -> object:
        if self.value_type is VariableType.BOOLEAN:
            valid = isinstance(value, bool)
        elif self.value_type is VariableType.FLOAT:
            valid = (
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and float(value) > 0
            )
        elif self.value_type in {
            VariableType.INTEGER,
            VariableType.POSITIVE_INTEGER,
        }:
            valid = (
                isinstance(value, int)
                and not isinstance(value, bool)
                and value
                >= (1 if self.value_type is VariableType.POSITIVE_INTEGER else 0)
                and (
                    self.value_type is not VariableType.POSITIVE_INTEGER or value <= 60
                )
            )
        elif self.value_type is VariableType.STRING:
            valid = (
                isinstance(value, str)
                and bool(value)
                and len(value) <= 4096
                and "\0" not in value
                and _SECRET_VALUE.search(value) is None
            )
        elif self.value_type is VariableType.STRING_LIST:
            valid = (
                isinstance(value, list)
                and len(value) <= 256
                and all(
                    isinstance(item, str)
                    and item
                    and len(item) <= 4096
                    and "\0" not in item
                    and _SECRET_VALUE.search(item) is None
                    for item in value
                )
                and value == sorted(set(value))
            )
        elif self.value_type is VariableType.JSON_OBJECT:
            valid = _valid_json_object(value)
        elif self.value_type is VariableType.ROUTED_KEYSCAN_REQUEST:
            from scylla_vms.ansible.routed_keyscan import (
                validate_routed_keyscan_request,
            )

            valid = validate_routed_keyscan_request(value)
        else:
            valid = _valid_destination_probes(value)
        if not valid or (self.choices and value not in self.choices):
            raise AnsibleError(f"Ansible variable value is invalid: {self.name}")
        return value


COMMON_VARIABLES = (
    VariableDefinition("deploy_scylla_vms_cluster_uuid", VariableType.STRING),
    VariableDefinition("deploy_scylla_vms_inventory_digest", VariableType.STRING),
    VariableDefinition("deploy_scylla_vms_checkpoint_id", VariableType.STRING),
    VariableDefinition("deploy_scylla_vms_scylla_version", VariableType.STRING),
    VariableDefinition(
        "deploy_scylla_vms_os_family",
        VariableType.STRING,
        ("Debian", "Ubuntu"),
    ),
    VariableDefinition("deploy_scylla_vms_os_major", VariableType.STRING, ("24",)),
)


@dataclass(frozen=True, slots=True)
class PlaybookDefinition:
    name: str
    target_groups: tuple[str, ...]
    classification: OperationClassification
    check_mode: CheckMode
    diff_mode: bool
    limit_policy: LimitPolicy
    serial: int | None
    any_errors_fatal: bool
    inventory_freshness_required: bool
    host_key_gate_required: bool
    pre_health_gate: bool
    post_health_gate: bool
    source_available: bool
    variables: tuple[VariableDefinition, ...] = COMMON_VARIABLES
    tags: tuple[str, ...] = ()

    @property
    def filename(self) -> str:
        return f"{self.name}.yml"

    @property
    def execution_result_schema_version(self) -> str:
        """Return the strict receipt schema required at the executor boundary."""

        return f"deploy-scylla-vms.ansible-executor-result.{self.name}/v1"

    @property
    def hosts(self) -> str:
        return ":".join(self.target_groups)

    def validate_limit(self, limit: tuple[str, ...]) -> str:
        if not limit or limit != tuple(dict.fromkeys(limit)):
            raise AnsibleError("Ansible host limit must be explicit and unique")
        if not all(_LIMIT_ITEM.fullmatch(item) for item in limit):
            raise AnsibleError(
                "Ansible host limit contains an invalid stable ID or group"
            )
        if self.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST and (
            len(limit) != 1 or limit[0] in {"all", self.hosts}
        ):
            raise AnsibleError(
                "topology mutation requires exactly one stable logical host ID"
            )
        return ",".join(limit)

    def validate_variables(self, values: dict[str, object]) -> dict[str, object]:
        definitions = {item.name: item for item in self.variables}
        unknown = sorted(set(values) - set(definitions))
        if unknown:
            raise AnsibleError(
                "Ansible variables are not allowlisted: " + ", ".join(unknown)
            )
        return {
            name: definitions[name].validate(values[name]) for name in sorted(values)
        }


def _variable(
    name: str, value_type: VariableType = VariableType.STRING, *choices: str
) -> VariableDefinition:
    return VariableDefinition(name, value_type, choices)


def _book(
    name: str,
    target_groups: str | tuple[str, ...],
    classification: OperationClassification,
    check: CheckMode,
    *,
    serial: int | None = None,
    limit_policy: LimitPolicy = LimitPolicy.EXPLICIT,
    pre: bool = False,
    post: bool = False,
    variables: tuple[VariableDefinition, ...] = (),
    tags: tuple[str, ...] = (),
    source_available: bool = False,
    any_errors_fatal: bool = True,
) -> PlaybookDefinition:
    return PlaybookDefinition(
        name,
        (target_groups,) if isinstance(target_groups, str) else target_groups,
        classification,
        check,
        check is CheckMode.PREVIEW,
        limit_policy,
        serial,
        any_errors_fatal,
        True,
        True,
        pre,
        post,
        source_available,
        (*COMMON_VARIABLES, *variables),
        tags,
    )


_READ = OperationClassification.READ_ONLY
_MUTATE = OperationClassification.MUTATING
_SENSITIVE = OperationClassification.SENSITIVE
_DESTRUCTIVE = OperationClassification.DESTRUCTIVE

PLAYBOOKS = (
    _book(
        "inventory-preflight",
        "all",
        _READ,
        CheckMode.SUPPORTED,
        tags=("preflight",),
        source_available=True,
    ),
    _book(
        "connectivity-check",
        "all",
        _READ,
        CheckMode.SUPPORTED,
        serial=5,
        tags=("connectivity",),
        variables=(
            _variable(
                "deploy_scylla_vms_connect_timeout_seconds",
                VariableType.FLOAT,
            ),
            _variable(
                "deploy_scylla_vms_destination_probes",
                VariableType.DESTINATION_PROBE_LIST,
            ),
            _variable(
                "deploy_scylla_vms_probe_timeout_seconds",
                VariableType.INTEGER,
            ),
        ),
        source_available=True,
        any_errors_fatal=False,
    ),
    _book(
        "routed-keyscan",
        "jump_hosts",
        _READ,
        CheckMode.SUPPORTED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        tags=("routed-keyscan", "preflight", "collect", "verify"),
        variables=(
            _variable(
                "deploy_scylla_vms_routed_keyscan",
                VariableType.ROUTED_KEYSCAN_REQUEST,
            ),
        ),
        source_available=True,
    ),
    _book(
        "evidence-collect",
        "all",
        _READ,
        CheckMode.SUPPORTED,
        serial=5,
        tags=("evidence",),
        variables=(
            _variable(
                "deploy_scylla_vms_evidence_timeout_seconds",
                VariableType.POSITIVE_INTEGER,
            ),
        ),
        source_available=True,
        any_errors_fatal=False,
    ),
    _book(
        "jump-host-configure",
        "jump_hosts",
        _MUTATE,
        CheckMode.PREVIEW,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        variables=(
            _variable(
                "deploy_scylla_vms_jump_host_configure",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=(
            "jump-host-configure",
            "preflight",
            "configure",
            "validate",
            "reload",
            "verify",
        ),
        source_available=True,
    ),
    _book(
        "base-os",
        "all",
        _MUTATE,
        CheckMode.PREVIEW,
        serial=1,
        variables=(
            _variable(
                "deploy_scylla_vms_image_operating_system",
                VariableType.STRING,
                "Ubuntu",
            ),
            _variable(
                "deploy_scylla_vms_image_operating_system_version",
                VariableType.STRING,
                "24.04",
            ),
            _variable(
                "deploy_scylla_vms_image_architecture",
                VariableType.STRING,
                "amd64",
                "aarch64",
            ),
        ),
        tags=("base-os",),
        source_available=True,
    ),
    _book(
        "deploy-reboot",
        "all",
        _MUTATE,
        CheckMode.REFUSED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        variables=(
            _variable(
                "deploy_scylla_vms_deploy_reboot",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=("deploy-reboot",),
        source_available=True,
    ),
    _book(
        "storage-discover",
        "scylla",
        _READ,
        CheckMode.SUPPORTED,
        serial=5,
        tags=("storage",),
        source_available=True,
        any_errors_fatal=False,
    ),
    _book(
        "storage-preflight",
        "scylla",
        _READ,
        CheckMode.SUPPORTED,
        serial=5,
        tags=("storage", "preflight"),
        variables=(
            _variable(
                "deploy_scylla_vms_storage_preflight",
                VariableType.JSON_OBJECT,
            ),
        ),
        source_available=True,
        any_errors_fatal=False,
    ),
    _book(
        "storage-prepare",
        "scylla",
        _DESTRUCTIVE,
        CheckMode.REFUSED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        variables=(
            _variable(
                "deploy_scylla_vms_storage_prepare",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=("storage", "prepare"),
        source_available=True,
    ),
    _book(
        "storage-postcheck",
        "scylla",
        _READ,
        CheckMode.SUPPORTED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        variables=(
            _variable(
                "deploy_scylla_vms_storage_postcheck",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=("storage", "postcheck"),
        source_available=True,
    ),
    _book(
        "storage-retire",
        "scylla",
        _DESTRUCTIVE,
        CheckMode.REFUSED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        variables=(
            _variable(
                "deploy_scylla_vms_storage_retire",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=("storage", "retire"),
        source_available=True,
    ),
    _book(
        "scylla-install",
        "scylla",
        _MUTATE,
        CheckMode.PREVIEW,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        variables=(
            _variable(
                "deploy_scylla_vms_scylla_install",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=("scylla-install", "preflight", "packages", "verify"),
        source_available=True,
    ),
    _book(
        "scylla-configure",
        "scylla",
        _MUTATE,
        CheckMode.PREVIEW,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        variables=(
            _variable(
                "deploy_scylla_vms_scylla_configure",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=(
            "scylla-configure",
            "preflight",
            "configure",
            "service-safety",
            "verify",
        ),
        source_available=True,
    ),
    _book(
        "scylla-health",
        "scylla",
        _READ,
        CheckMode.SUPPORTED,
        serial=5,
        post=True,
        variables=(
            _variable(
                "deploy_scylla_vms_scylla_health",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=("scylla-health", "health"),
        source_available=True,
        any_errors_fatal=False,
    ),
    _book(
        "manager-agent",
        "scylla",
        _MUTATE,
        CheckMode.PREVIEW,
        serial=1,
        variables=(
            _variable(
                "deploy_scylla_vms_manager_agent",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=("manager-agent", "preflight", "packages", "verify"),
        source_available=True,
    ),
    _book(
        "monitoring-agent",
        "scylla",
        _MUTATE,
        CheckMode.PREVIEW,
        serial=1,
        variables=(
            _variable(
                "deploy_scylla_vms_monitoring_agent",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=("monitoring-agent", "preflight", "packages", "verify"),
        source_available=True,
    ),
    _book(
        "manager-server",
        "manager",
        _MUTATE,
        CheckMode.PREVIEW,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        variables=(
            _variable(
                "deploy_scylla_vms_manager_server",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=("manager-server", "preflight", "packages", "verify"),
        source_available=True,
    ),
    _book(
        "manager-backend-preflight",
        "manager",
        _READ,
        CheckMode.SUPPORTED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        pre=True,
        variables=(
            _variable(
                "deploy_scylla_vms_manager_backend_preflight",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=(
            "manager-backend-preflight",
            "preflight",
            "inspect",
            "verify",
        ),
        source_available=True,
    ),
    _book(
        "manager-backend-storage-discover",
        "manager",
        _READ,
        CheckMode.SUPPORTED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        pre=True,
        variables=(
            _variable(
                "deploy_scylla_vms_manager_backend_storage_discover",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=(
            "manager-backend-storage-discover",
            "preflight",
            "inspect",
            "verify",
        ),
        source_available=True,
    ),
    _book(
        "manager-backend-storage-preflight",
        "manager",
        _READ,
        CheckMode.SUPPORTED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        pre=True,
        variables=(
            _variable(
                "deploy_scylla_vms_manager_backend_storage_preflight",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=(
            "manager-backend-storage-preflight",
            "preflight",
            "inspect",
            "verify",
        ),
        source_available=True,
    ),
    _book(
        "manager-backend-storage-prepare",
        "manager",
        _DESTRUCTIVE,
        CheckMode.REFUSED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        variables=(
            _variable(
                "deploy_scylla_vms_manager_backend_storage_prepare",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=("manager-backend-storage-prepare", "storage", "prepare"),
        source_available=True,
    ),
    _book(
        "manager-backend-local-install",
        "manager",
        _MUTATE,
        CheckMode.PREVIEW,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        variables=(
            _variable(
                "deploy_scylla_vms_manager_backend_local_install",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=(
            "manager-backend-local-install",
            "preflight",
            "packages",
            "verify",
        ),
        source_available=True,
    ),
    _book(
        "monitoring-stack",
        "monitoring",
        _MUTATE,
        CheckMode.PREVIEW,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        variables=(
            _variable(
                "deploy_scylla_vms_monitoring_stack",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=("monitoring-stack", "preflight", "packages", "verify"),
        source_available=True,
    ),
    _book(
        "monitoring-targets",
        "monitoring",
        _MUTATE,
        CheckMode.PREVIEW,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        post=True,
        variables=(
            _variable(
                "deploy_scylla_vms_monitoring_targets",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=("monitoring-targets", "preflight", "targets", "verify"),
        source_available=True,
    ),
    _book(
        "manager-tasks",
        "manager",
        _SENSITIVE,
        CheckMode.PREVIEW,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        variables=(
            _variable(
                "deploy_scylla_vms_manager_tasks",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=("manager-tasks", "preflight", "inspect", "verify"),
        source_available=True,
    ),
    _book(
        "scylla-bootstrap",
        "scylla",
        _SENSITIVE,
        CheckMode.REFUSED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        post=True,
        variables=(
            _variable(
                "deploy_scylla_vms_scylla_bootstrap",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=(
            "scylla-bootstrap",
            "preflight",
            "revalidate",
            "start",
            "verify",
            "recovery",
        ),
        source_available=True,
    ),
    _book(
        "scylla-remove-live",
        "scylla",
        _DESTRUCTIVE,
        CheckMode.REFUSED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        pre=True,
        post=True,
        variables=(
            _variable(
                "deploy_scylla_vms_scylla_remove_live",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=(
            "scylla-remove-live",
            "preflight",
            "revalidate",
            "decommission",
            "verify",
            "recovery",
        ),
        source_available=True,
    ),
    _book(
        "scylla-remove-dead",
        "scylla",
        _DESTRUCTIVE,
        CheckMode.REFUSED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        pre=True,
        post=True,
        variables=(
            _variable(
                "deploy_scylla_vms_scylla_remove_dead",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=(
            "scylla-remove-dead",
            "preflight",
            "revalidate",
            "removenode",
            "verify",
            "recovery",
        ),
        source_available=True,
    ),
    _book(
        "scylla-replace-dead",
        "scylla",
        _DESTRUCTIVE,
        CheckMode.REFUSED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        pre=True,
        post=True,
        variables=(
            _variable(
                "deploy_scylla_vms_scylla_replace_dead",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=(
            "scylla-replace-dead",
            "preflight",
            "revalidate",
            "configure-key",
            "start",
            "verify",
            "recovery",
        ),
        source_available=True,
    ),
    _book(
        "scylla-cleanup",
        "scylla",
        _SENSITIVE,
        CheckMode.REFUSED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        pre=True,
        post=True,
        variables=(
            _variable(
                "deploy_scylla_vms_scylla_cleanup",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=(
            "scylla-cleanup",
            "preflight",
            "revalidate",
            "cleanup",
            "verify",
            "recovery",
        ),
        source_available=True,
    ),
    _book(
        "scylla-repair",
        "scylla",
        _SENSITIVE,
        CheckMode.REFUSED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        pre=True,
        post=True,
        variables=(
            _variable(
                "deploy_scylla_vms_scylla_repair",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=(
            "scylla-repair",
            "preflight",
            "revalidate",
            "repair",
            "verify",
            "recovery",
        ),
        source_available=True,
    ),
    _book(
        "service-converge",
        "all",
        _MUTATE,
        CheckMode.PREVIEW,
        serial=1,
        pre=True,
        post=True,
        variables=(
            _variable(
                "deploy_scylla_vms_service_scope",
                VariableType.STRING,
                "base",
                "jump-host",
                "manager-agent",
                "manager-server",
                "monitoring-agent",
                "monitoring-stack",
                "monitoring-targets",
                "scylla",
            ),
            _variable(
                "deploy_scylla_vms_restart_policy",
                VariableType.STRING,
                "always",
                "if-required",
                "never",
            ),
            _variable(
                "deploy_scylla_vms_service_converge",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=(
            "service-converge",
            "preflight",
            "inspect",
            "converge",
            "verify",
        ),
        source_available=True,
    ),
    _book(
        "scylla-cluster-shutdown",
        "scylla",
        _DESTRUCTIVE,
        CheckMode.REFUSED,
        serial=1,
        pre=True,
        variables=(
            _variable(
                "deploy_scylla_vms_scylla_cluster_shutdown",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=(
            "scylla-cluster-shutdown",
            "preflight",
            "inspect",
            "verify",
        ),
        source_available=True,
    ),
    _book(
        "os-upgrade-preflight",
        "all",
        _READ,
        CheckMode.SUPPORTED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        pre=True,
        variables=(
            _variable(
                "deploy_scylla_vms_os_upgrade_preflight",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=(
            "os-upgrade-preflight",
            "preflight",
            "inspect",
            "verify",
        ),
        source_available=True,
    ),
    _book(
        "os-upgrade-in-place",
        "all",
        _SENSITIVE,
        CheckMode.REFUSED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        pre=True,
        post=True,
        variables=(
            _variable(
                "deploy_scylla_vms_os_upgrade_in_place",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=("os-upgrade-in-place", "preflight", "verify"),
        source_available=True,
    ),
    _book(
        "os-reprovision-prepare",
        "all",
        _DESTRUCTIVE,
        CheckMode.REFUSED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        pre=True,
        variables=(
            _variable(
                "deploy_scylla_vms_os_reprovision_prepare",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=("os-reprovision-prepare", "preflight", "verify"),
        source_available=True,
    ),
    _book(
        "os-upgrade-postcheck",
        "all",
        _READ,
        CheckMode.SUPPORTED,
        serial=1,
        limit_policy=LimitPolicy.SINGLE_LOGICAL_HOST,
        post=True,
        variables=(
            _variable(
                "deploy_scylla_vms_os_upgrade_postcheck",
                VariableType.JSON_OBJECT,
            ),
        ),
        tags=(
            "os-upgrade-postcheck",
            "preflight",
            "inspect",
            "verify",
        ),
        source_available=True,
    ),
)


def _valid_destination_probes(value: object) -> bool:
    if not isinstance(value, list) or len(value) > 64:
        return False
    normalized: list[tuple[str, str, str, str, int]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "address",
            "jump_host_id",
            "port",
            "role",
            "target_logical_id",
        }:
            return False
        address = item["address"]
        jump_host_id = item["jump_host_id"]
        port = item["port"]
        role = item["role"]
        target_logical_id = item["target_logical_id"]
        if (
            not isinstance(address, str)
            or not isinstance(jump_host_id, str)
            or not isinstance(target_logical_id, str)
            or not _LIMIT_ITEM.fullmatch(jump_host_id)
            or not _LIMIT_ITEM.fullmatch(target_logical_id)
            or jump_host_id == target_logical_id
            or role not in {"manager", "monitoring", "scylla"}
            or isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            return False
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError:
            return False
        if not isinstance(parsed_address, ipaddress.IPv4Address) or not any(
            parsed_address in network for network in _RFC1918
        ):
            return False
        normalized.append((jump_host_id, target_logical_id, str(role), address, port))
    return normalized == sorted(set(normalized))


def _valid_json_object(value: object) -> bool:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError):
        return False
    return (
        isinstance(value, dict)
        and bool(value)
        and len(encoded.encode("utf-8")) <= 256 * 1024
        and _SECRET_VALUE.search(encoded) is None
    )


@dataclass(frozen=True, slots=True)
class OperationPlaybookStep:
    playbook: str
    condition: str = "always"


def _steps(*items: str | tuple[str, str]) -> tuple[OperationPlaybookStep, ...]:
    return tuple(
        OperationPlaybookStep(item[0], item[1])
        if isinstance(item, tuple)
        else OperationPlaybookStep(item)
        for item in items
    )


# Conditional labels preserve PLAN.md branches without pretending every branch runs.
OPERATION_PLAYBOOKS = {
    "deploy": _steps(
        "inventory-preflight",
        "connectivity-check",
        ("base-os", "jump-hosts-exist"),
        ("jump-host-configure", "jump-hosts-exist"),
        ("connectivity-check", "final-routes"),
        ("base-os", "non-jump-managed-hosts"),
        "storage-discover",
        "storage-preflight",
        "storage-prepare",
        "storage-postcheck",
        "scylla-install",
        "scylla-configure",
        "scylla-health",
        "manager-server",
        "monitoring-stack",
        "manager-agent",
        "monitoring-agent",
        "monitoring-targets",
        ("manager-tasks", "explicit-task-action"),
        "scylla-health",
        "evidence-collect",
    ),
    "add-node": _steps(
        "inventory-preflight",
        "connectivity-check",
        "scylla-health",
        "manager-tasks",
        "connectivity-check",
        "base-os",
        "storage-discover",
        "storage-preflight",
        "storage-prepare",
        "storage-postcheck",
        "scylla-install",
        "scylla-configure",
        "scylla-bootstrap",
        "scylla-health",
        "manager-agent",
        "monitoring-agent",
        ("scylla-cleanup", "cleanup-run"),
        "monitoring-targets",
        "manager-tasks",
        "evidence-collect",
    ),
    "scale-out": _steps(
        "inventory-preflight",
        "connectivity-check",
        "scylla-health",
        "manager-tasks",
        "connectivity-check",
        "base-os",
        "storage-discover",
        "storage-preflight",
        "storage-prepare",
        "storage-postcheck",
        "scylla-install",
        "scylla-configure",
        "scylla-bootstrap",
        "scylla-health",
        "manager-agent",
        "monitoring-agent",
        ("scylla-cleanup", "cleanup-run"),
        "monitoring-targets",
        "manager-tasks",
        "evidence-collect",
    ),
    "replace-node": _steps(
        "inventory-preflight",
        "connectivity-check",
        "scylla-health",
        "evidence-collect",
        "manager-tasks",
        "connectivity-check",
        "base-os",
        "storage-discover",
        "storage-preflight",
        "storage-prepare",
        "storage-postcheck",
        "scylla-install",
        "scylla-configure",
        "scylla-replace-dead",
        "scylla-health",
        "manager-agent",
        "monitoring-agent",
        ("scylla-repair", "procedure-requires"),
        "monitoring-targets",
        "manager-tasks",
        "scylla-health",
        "evidence-collect",
    ),
    "destroy-node": _steps(
        "inventory-preflight",
        "connectivity-check",
        "scylla-health",
        "evidence-collect",
        "manager-tasks",
        ("scylla-remove-live", "live"),
        ("scylla-repair", "dead-requires"),
        ("scylla-remove-dead", "dead"),
        "scylla-health",
        ("storage-retire", "reachable"),
        "monitoring-targets",
        "manager-tasks",
        "scylla-health",
        "evidence-collect",
    ),
    "scale-in": _steps(
        "inventory-preflight",
        "connectivity-check",
        "scylla-health",
        "manager-tasks",
        "evidence-collect",
        ("scylla-remove-live", "live"),
        ("scylla-repair", "dead-requires"),
        ("scylla-remove-dead", "dead"),
        "scylla-health",
        ("storage-retire", "reachable"),
        "monitoring-targets",
        "manager-tasks",
        "scylla-health",
        "evidence-collect",
    ),
    "destroy": _steps(
        "inventory-preflight",
        "connectivity-check",
        "scylla-health",
        "manager-tasks",
        "evidence-collect",
        "manager-tasks",
        ("scylla-cluster-shutdown", "normal"),
        ("scylla-remove-live", "runbook-live"),
        ("scylla-repair", "runbook-dead-requires"),
        ("scylla-remove-dead", "runbook-dead"),
        ("scylla-health", "between-removals"),
        "evidence-collect",
        "storage-retire",
    ),
    "redeploy": _steps(
        "inventory-preflight",
        "connectivity-check",
        ("scylla-health", "scylla-scope"),
        "storage-discover",
        "storage-preflight",
        "evidence-collect",
        ("service-converge", "service-scope"),
        ("base-os", "host-or-cluster"),
        ("storage-prepare", "new-stateless-host"),
        ("storage-postcheck", "prepared-scylla-storage"),
        ("jump-host-configure", "jump-host"),
        ("scylla-install", "cluster"),
        ("scylla-configure", "scylla-cluster"),
        ("manager-server", "manager-or-cluster"),
        ("monitoring-stack", "monitoring-or-cluster"),
        ("manager-agent", "scylla-cluster"),
        ("monitoring-agent", "scylla-cluster"),
        ("monitoring-targets", "cluster"),
        ("scylla-health", "scylla-scope"),
        "evidence-collect",
    ),
    "refresh-monitoring": _steps(
        "inventory-preflight",
        "connectivity-check",
        "scylla-health",
        "monitoring-targets",
        ("monitoring-stack", "stack-selected"),
        ("manager-server", "integration-selected"),
        "evidence-collect",
    ),
    "upgrade-os": _steps(
        "inventory-preflight",
        "connectivity-check",
        ("scylla-health", "applicable"),
        "storage-discover",
        "storage-preflight",
        "manager-tasks",
        "evidence-collect",
        "os-upgrade-preflight",
        ("os-upgrade-in-place", "in-place"),
        ("os-reprovision-prepare", "reprovision"),
        ("connectivity-check", "after-reprovision"),
        ("base-os", "after-reprovision"),
        ("storage-prepare", "approved-new-storage"),
        ("storage-postcheck", "prepared-scylla-storage"),
        ("jump-host-configure", "jump-host"),
        ("manager-server", "manager"),
        ("monitoring-stack", "monitoring"),
        ("scylla-install", "delegated-replace"),
        ("scylla-configure", "delegated-replace"),
        ("scylla-replace-dead", "delegated-replace"),
        ("manager-agent", "delegated-replace"),
        ("monitoring-agent", "delegated-replace"),
        "os-upgrade-postcheck",
        ("scylla-health", "applicable"),
        "manager-tasks",
        "evidence-collect",
    ),
    "check-jump-hosts": _steps("inventory-preflight", "connectivity-check"),
    "show": (),
}

PLAYBOOK_NAMES = tuple(playbook.name for playbook in PLAYBOOKS)
OPERATION_PLAYBOOK_EXPORT = tuple(
    (
        operation,
        tuple((step.playbook, step.condition) for step in steps),
    )
    for operation, steps in sorted(OPERATION_PLAYBOOKS.items())
)


def get_playbook(name: str) -> PlaybookDefinition:
    if not isinstance(name, str) or "/" in name or "\\" in name:
        raise AnsibleError("Ansible playbook is not registry-approved")
    for playbook in PLAYBOOKS:
        if playbook.name == name:
            return playbook
    raise AnsibleError("Ansible playbook is not registry-approved")
