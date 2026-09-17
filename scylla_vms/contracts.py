"""Declarative CLI and environment contract from the implementation plan."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from scylla_vms.models import DeferredValue, OptionValue


class ValueKind(StrEnum):
    """Supported strict option encodings."""

    STRING = "string"
    BOOLEAN = "boolean"
    ENUM = "enum"
    INTEGER = "integer"
    FLOAT = "float"
    PATH = "path"
    UUID = "uuid"
    CIDR = "cidr"
    STRING_LIST = "string-list"
    ENUM_LIST = "enum-list"
    STRING_MAP = "string-map"
    INTEGER_MAP = "integer-map"
    ENUM_MAP = "enum-map"
    CIDR_MAP = "cidr-map"


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """One allowlisted CLI/environment field."""

    name: str
    kind: ValueKind
    environment: str | None = None
    choices: tuple[str, ...] = ()
    default: OptionValue = None
    minimum: float | None = None
    maximum: float | None = None
    repeatable: bool = False
    help: str = ""

    @property
    def flag(self) -> str:
        return "--" + self.name.replace("_", "-")


@dataclass(frozen=True, slots=True)
class OperationContract:
    """The exact shared groups and own fields accepted by an operation."""

    groups: tuple[str, ...]
    fields: tuple[FieldSpec, ...]


def _env(name: str) -> str:
    return f"DEPLOY_SCYLLA_VMS_{name.upper()}"


def _string(
    name: str,
    *,
    environment: str | None = None,
    default: OptionValue = None,
    repeatable: bool = False,
    help: str = "",
) -> FieldSpec:
    resolved_default = () if repeatable and default is None else default
    return FieldSpec(
        name,
        ValueKind.STRING_LIST if repeatable else ValueKind.STRING,
        environment=environment,
        default=resolved_default,
        repeatable=repeatable,
        help=help,
    )


def _enum(
    name: str,
    choices: tuple[str, ...],
    *,
    environment: str | None = None,
    default: OptionValue = None,
    repeatable: bool = False,
    help: str = "",
) -> FieldSpec:
    resolved_default = () if repeatable and default is None else default
    return FieldSpec(
        name,
        ValueKind.ENUM_LIST if repeatable else ValueKind.ENUM,
        environment=environment,
        choices=choices,
        default=resolved_default,
        repeatable=repeatable,
        help=help,
    )


def _int(
    name: str,
    *,
    environment: str | None = None,
    default: OptionValue = None,
    minimum: int | None = None,
    maximum: int | None = None,
    help: str = "",
) -> FieldSpec:
    return FieldSpec(
        name,
        ValueKind.INTEGER,
        environment=environment,
        default=default,
        minimum=minimum,
        maximum=maximum,
        help=help,
    )


def _float(
    name: str,
    *,
    environment: str | None = None,
    default: OptionValue = None,
    minimum: float | None = None,
    help: str = "",
) -> FieldSpec:
    return FieldSpec(
        name,
        ValueKind.FLOAT,
        environment=environment,
        default=default,
        minimum=minimum,
        help=help,
    )


def _path(
    name: str,
    *,
    environment: str | None = None,
    help: str = "",
) -> FieldSpec:
    return FieldSpec(name, ValueKind.PATH, environment=environment, help=help)


def _mapping(
    name: str,
    kind: ValueKind,
    *,
    choices: tuple[str, ...] = (),
    help: str = "",
) -> FieldSpec:
    return FieldSpec(
        name,
        kind,
        choices=choices,
        repeatable=True,
        default=(),
        help=help,
    )


def _action(name: str, *, help: str = "") -> FieldSpec:
    return FieldSpec(name, ValueKind.BOOLEAN, default=False, help=help)


CORE_FIELDS: tuple[FieldSpec, ...] = (
    _enum(
        "cloud_provider",
        ("oci",),
        environment=_env("cloud_provider"),
        default="oci",
        help="Select the provider adapter.",
    ),
    _string(
        "cluster_name",
        environment=_env("cluster_name"),
        help="Select the validated cluster identity.",
    ),
    _path(
        "state_dir",
        environment=_env("state_dir"),
        help="Select the external application state root.",
    ),
    _path(
        "config",
        environment=_env("config"),
        help="Load strict non-secret TOML defaults.",
    ),
    _enum(
        "log_level",
        ("debug", "info", "warning", "error"),
        environment=_env("log_level"),
        default="info",
        help="Set diagnostic verbosity.",
    ),
    _action("json", help="Request stable JSON output."),
    _float(
        "lock_timeout_seconds",
        environment=_env("lock_timeout_seconds"),
        default=30.0,
        minimum=0,
        help="Bound cluster-lock acquisition.",
    ),
    _action("non_interactive", help="Disable future interactive prompts."),
)

MUTATE_FIELDS: tuple[FieldSpec, ...] = (
    _action("dry_run", help="Resolve and validate without mutation."),
    _action("plan", help="Request a future protected plan without apply."),
    _action("yes", help="Accept ordinary future mutation prompts."),
    _int(
        "operation_timeout_seconds",
        environment=_env("operation_timeout_seconds"),
        default=3600,
        minimum=1,
        help="Bound one future mutating operation.",
    ),
)

DESTRUCTIVE_FIELDS: tuple[FieldSpec, ...] = (
    _action(
        "allow_destructive",
        help="Acknowledge a future destructive operation class.",
    ),
)

OCI_CONTEXT_FIELDS: tuple[FieldSpec, ...] = (
    _string("oci_region", environment=_env("oci_region")),
    _string("oci_compartment_id", environment=_env("oci_compartment_id")),
    _enum(
        "oci_auth_mode",
        ("api-key", "instance-principal", "resource-principal"),
        environment=_env("oci_auth_mode"),
    ),
)

NETWORK_FIELDS: tuple[FieldSpec, ...] = (
    _enum(
        "network_mode",
        ("create", "existing"),
        environment=_env("network_mode"),
    ),
    _string("oci_vcn_id", environment=_env("oci_vcn_id")),
    FieldSpec(
        "oci_vcn_cidr",
        ValueKind.CIDR,
        environment=_env("oci_vcn_cidr"),
        help="Set the explicit private IPv4 CIDR for a managed VCN.",
    ),
    _mapping(
        "oci_subnet",
        ValueKind.STRING_MAP,
        help="Map each deployed role to one existing subnet OCID.",
    ),
    _mapping(
        "oci_private_subnet_cidr",
        ValueKind.CIDR_MAP,
        help="Map every canonical zone to one managed private subnet CIDR.",
    ),
    _mapping(
        "oci_public_subnet_cidr",
        ValueKind.CIDR_MAP,
        help="Map each public jump-host zone to one managed public subnet CIDR.",
    ),
    FieldSpec(
        "oci_public_jump_hosts",
        ValueKind.BOOLEAN,
        environment=_env("oci_public_jump_hosts"),
        default=False,
        help="Allow managed jump hosts to receive public IPs.",
    ),
    FieldSpec(
        "operator_cidr",
        ValueKind.CIDR,
        default=(),
        repeatable=True,
        help="Allow one canonical operator CIDR.",
    ),
    _string("ssh_user", environment=_env("ssh_user")),
    _path("ssh_public_key_path", environment=_env("ssh_public_key_path")),
)


def _image_fields(role: str) -> tuple[FieldSpec, ...]:
    return (
        _string(
            f"{role}_image_operating_system",
            environment=_env(f"{role}_image_operating_system"),
            help=f"Require an exact OCI platform-image OS for {role}.",
        ),
        _string(
            f"{role}_image_operating_system_version",
            environment=_env(f"{role}_image_operating_system_version"),
            help=f"Require an explicit OCI platform-image version for {role}.",
        ),
        _enum(
            f"{role}_image_version_match",
            ("exact", "prefix"),
            environment=_env(f"{role}_image_version_match"),
            default="exact",
            help=f"Choose exact or prefix OCI image-version matching for {role}.",
        ),
    )


IMAGE_FIELDS: tuple[FieldSpec, ...] = (
    _image_fields("scylla")
    + _image_fields("manager")
    + _image_fields("monitoring")
    + _image_fields("jump_host")
)

TOPOLOGY_FIELDS: tuple[FieldSpec, ...] = (
    _string("zone", repeatable=True),
    _mapping("nodes_per_zone", ValueKind.INTEGER_MAP),
    _string("scylla_datacenter", environment=_env("scylla_datacenter")),
    _mapping("scylla_rack", ValueKind.STRING_MAP),
    _int(
        "jump_host_count",
        environment=_env("jump_host_count"),
        minimum=0,
    ),
)

SHAPE_FIELDS: tuple[FieldSpec, ...] = (
    _string("scylla_instance_type", environment=_env("scylla_instance_type")),
    _string("manager_instance_type", environment=_env("manager_instance_type")),
    _string("monitoring_instance_type", environment=_env("monitoring_instance_type")),
    _string("jump_host_instance_type", environment=_env("jump_host_instance_type")),
)

SCYLLA_STORAGE_FIELDS: tuple[FieldSpec, ...] = (
    _enum(
        "scylla_storage_backend",
        ("auto", "local-nvme", "block-volume"),
        environment=_env("scylla_storage_backend"),
    ),
    _int(
        "scylla_storage_min_device_count",
        environment=_env("scylla_storage_min_device_count"),
        minimum=1,
    ),
    _int(
        "scylla_storage_min_total_gib",
        environment=_env("scylla_storage_min_total_gib"),
        minimum=1,
    ),
    _enum(
        "scylla_storage_layout",
        ("single", "raid0"),
        environment=_env("scylla_storage_layout"),
    ),
    _int(
        "scylla_block_volume_count",
        environment=_env("scylla_block_volume_count"),
        minimum=1,
    ),
    _int(
        "scylla_block_volume_size_gib",
        environment=_env("scylla_block_volume_size_gib"),
        minimum=1,
    ),
    _int(
        "scylla_block_volume_vpus_per_gb",
        environment=_env("scylla_block_volume_vpus_per_gb"),
        minimum=0,
    ),
    _enum(
        "scylla_block_volume_attachment_type",
        ("iscsi", "paravirtualized"),
        environment=_env("scylla_block_volume_attachment_type"),
    ),
    _enum(
        "scylla_block_volume_retention",
        ("retain", "delete"),
        environment=_env("scylla_block_volume_retention"),
    ),
    _string(
        "scylla_block_volume_key_id",
        environment=_env("scylla_block_volume_key_id"),
    ),
    _enum(
        "scylla_block_volume_in_transit_encryption",
        ("enabled", "disabled"),
        environment=_env("scylla_block_volume_in_transit_encryption"),
    ),
    _enum(
        "scylla_block_volume_chap",
        ("enabled", "disabled"),
        default="disabled",
    ),
)


def _service_storage(prefix: str) -> tuple[FieldSpec, ...]:
    return (
        _int(
            f"{prefix}_data_volume_size_gib",
            environment=_env(f"{prefix}_data_volume_size_gib"),
            minimum=1,
        ),
        _int(
            f"{prefix}_data_volume_vpus_per_gb",
            environment=_env(f"{prefix}_data_volume_vpus_per_gb"),
            minimum=0,
        ),
        _enum(
            f"{prefix}_data_volume_attachment_type",
            ("iscsi", "paravirtualized"),
            environment=_env(f"{prefix}_data_volume_attachment_type"),
        ),
        _enum(
            f"{prefix}_data_volume_retention",
            ("retain", "delete"),
            environment=_env(f"{prefix}_data_volume_retention"),
        ),
        _string(
            f"{prefix}_data_volume_key_id",
            environment=_env(f"{prefix}_data_volume_key_id"),
        ),
        _enum(
            f"{prefix}_data_volume_in_transit_encryption",
            ("enabled", "disabled"),
            environment=_env(f"{prefix}_data_volume_in_transit_encryption"),
        ),
    )


SERVICE_STORAGE_FIELDS = _service_storage("manager") + _service_storage("monitoring")

GROUP_FIELDS: Mapping[str, tuple[FieldSpec, ...]] = MappingProxyType(
    {
        "core": CORE_FIELDS,
        "mutate": MUTATE_FIELDS,
        "destructive": DESTRUCTIVE_FIELDS,
        "oci-context": OCI_CONTEXT_FIELDS,
        "network": NETWORK_FIELDS,
        "images": IMAGE_FIELDS,
        "topology": TOPOLOGY_FIELDS,
        "shapes": SHAPE_FIELDS,
        "scylla-storage": SCYLLA_STORAGE_FIELDS,
        "service-storage": SERVICE_STORAGE_FIELDS,
    }
)

PERSISTED_FIELD_NAMES = frozenset(
    {
        "oci_region",
        "oci_compartment_id",
        "network_mode",
        "oci_vcn_id",
        "oci_vcn_cidr",
        "oci_private_subnet_cidr",
        "oci_public_subnet_cidr",
        "oci_public_jump_hosts",
        *(field.name for field in IMAGE_FIELDS),
        "ssh_user",
        "ssh_public_key_path",
        "scylla_datacenter",
        "jump_host_count",
        "scylla_instance_type",
        "manager_instance_type",
        "monitoring_instance_type",
        "jump_host_instance_type",
        "scylla_storage_backend",
        "scylla_storage_min_device_count",
        "scylla_storage_min_total_gib",
        "scylla_storage_layout",
        "scylla_block_volume_count",
        "scylla_block_volume_size_gib",
        "scylla_block_volume_vpus_per_gb",
        "scylla_block_volume_attachment_type",
        "scylla_block_volume_retention",
        "scylla_block_volume_key_id",
        "scylla_block_volume_in_transit_encryption",
        "manager_data_volume_size_gib",
        "manager_data_volume_vpus_per_gb",
        "manager_data_volume_attachment_type",
        "manager_data_volume_retention",
        "manager_data_volume_key_id",
        "manager_data_volume_in_transit_encryption",
        "monitoring_data_volume_size_gib",
        "monitoring_data_volume_vpus_per_gb",
        "monitoring_data_volume_attachment_type",
        "monitoring_data_volume_retention",
        "monitoring_data_volume_key_id",
        "monitoring_data_volume_in_transit_encryption",
        "expected_rack",
    }
)

DEPLOY_DEFAULTS: Mapping[str, OptionValue] = MappingProxyType(
    {
        "network_mode": "create",
        "jump_host_count": 0,
        "scylla_datacenter": DeferredValue.DERIVED,
        "ssh_user": DeferredValue.DERIVED,
        "manager_zone": DeferredValue.DERIVED,
        "monitoring_zone": DeferredValue.DERIVED,
        "scylla_storage_backend": "auto",
        "scylla_block_volume_in_transit_encryption": "disabled",
        "manager_data_volume_retention": "retain",
        "manager_data_volume_in_transit_encryption": "disabled",
        "monitoring_data_volume_retention": "retain",
        "monitoring_data_volume_in_transit_encryption": "disabled",
    }
)

_DEPLOY_FIELDS = (
    _int("manager_count", environment=_env("manager_count"), default=1, minimum=1),
    _int(
        "monitoring_count",
        environment=_env("monitoring_count"),
        default=1,
        minimum=1,
    ),
    _string("manager_zone", environment=_env("manager_zone")),
    _string("monitoring_zone", environment=_env("monitoring_zone")),
)

_ADD_NODE_FIELDS = (
    _string("node_id"),
    _string("zone"),
    _string("expected_rack"),
    _enum("cleanup", ("run", "defer"), default="run"),
    _int(
        "bootstrap_timeout_seconds",
        environment=_env("bootstrap_timeout_seconds"),
        default=7200,
        minimum=1,
    ),
    _action("wipe_storage"),
    _string("confirm_wipe_device", repeatable=True),
)

_SCALE_OUT_FIELDS = (
    _mapping("nodes_per_zone", ValueKind.INTEGER_MAP),
    _mapping("add_nodes_per_zone", ValueKind.INTEGER_MAP),
    _mapping("node_id", ValueKind.STRING_MAP),
    _int("max_new_nodes", default=1, minimum=1),
    _enum("cleanup", ("run", "defer"), default="run"),
    _int(
        "bootstrap_timeout_seconds",
        environment=_env("bootstrap_timeout_seconds"),
        default=7200,
        minimum=1,
    ),
)

_REPLACE_NODE_FIELDS = (
    _string("node_id"),
    FieldSpec("failed_host_id", ValueKind.UUID),
    _string("reason"),
    _enum("storage_source", ("new", "reuse-retained"), default="new"),
    _string("retained_volume_id", repeatable=True),
    _enum("old_volume_disposition", ("policy", "retain", "delete"), default="policy"),
    _action("wipe_storage"),
    _string("confirm_wipe_device", repeatable=True),
    _enum("repair_mode", ("auto", "required", "skip-if-supported"), default="auto"),
    _int(
        "replacement_timeout_seconds",
        environment=_env("replacement_timeout_seconds"),
        default=7200,
        minimum=1,
    ),
    _string("confirm_replace_node"),
)

_DESTROY_NODE_FIELDS = (
    _string("node_id"),
    _enum("removal_mode", ("live", "dead")),
    FieldSpec("failed_host_id", ValueKind.UUID),
    _enum("volume_disposition", ("policy", "retain", "delete"), default="policy"),
    _int(
        "decommission_timeout_seconds",
        environment=_env("decommission_timeout_seconds"),
        default=7200,
        minimum=1,
    ),
    _string("confirm_destroy_node"),
)

_SCALE_IN_FIELDS = (
    _mapping("nodes_per_zone", ValueKind.INTEGER_MAP),
    _string("remove_node", repeatable=True),
    _enum("selection_policy", ("highest-ordinal",), default="highest-ordinal"),
    _int("max_remove_nodes", default=1, minimum=1),
    _mapping(
        "removal_mode",
        ValueKind.ENUM_MAP,
        choices=("live", "dead"),
    ),
    _mapping("failed_host_id", ValueKind.STRING_MAP),
    _mapping(
        "volume_disposition",
        ValueKind.ENUM_MAP,
        choices=("policy", "retain", "delete"),
    ),
    _int(
        "decommission_timeout_seconds",
        environment=_env("decommission_timeout_seconds"),
        default=7200,
        minimum=1,
    ),
    _string("confirm_scale_in"),
)

_DESTROY_FIELDS = (
    _enum("block_volume_disposition", ("policy", "retain", "delete"), default="policy"),
    _enum(
        "shared_resource_disposition",
        ("retain", "delete-if-owned"),
        default="retain",
    ),
    _enum("state_retention", ("keep",), default="keep"),
    _enum(
        "diagnostic_retention",
        ("sanitized", "protected-full"),
        default="sanitized",
    ),
    _string("confirm_destroy_cluster"),
)

_REDEPLOY_FIELDS = (
    _enum("scope", ("service", "host", "cluster")),
    _string("target_host"),
    _enum(
        "component",
        (
            "base",
            "scylla",
            "manager-agent",
            "monitoring-agent",
            "manager-server",
            "monitoring-stack",
            "monitoring-targets",
            "jump-host",
            "all",
        ),
        repeatable=True,
    ),
    _enum(
        "infrastructure",
        ("configuration-only", "reconcile", "recreate-stateless"),
        default="configuration-only",
    ),
    _enum("restart_policy", ("never", "if-required", "always"), default="if-required"),
    _string("confirm_recreate_host"),
)

_REFRESH_MONITORING_FIELDS = (
    _enum(
        "target",
        ("targets", "monitoring-stack", "manager-integration"),
        default=("targets", "monitoring-stack"),
        repeatable=True,
    ),
    _enum("source", ("terraform",), default="terraform"),
    _enum(
        "service_action",
        ("check-only", "reload-if-supported", "restart"),
        default="reload-if-supported",
    ),
    _enum("stale_target_policy", ("fail", "remove"), default="fail"),
    _action("confirm_monitoring_restart"),
    _int(
        "monitoring_timeout_seconds",
        environment=_env("monitoring_timeout_seconds"),
        default=600,
        minimum=1,
    ),
)

_UPGRADE_OS_FIELDS = (
    _enum("strategy", ("auto", "in-place", "reprovision"), default="auto"),
    _enum(
        "target_role",
        ("scylla", "manager", "monitoring", "jump-host"),
        repeatable=True,
    ),
    _string("target_host", repeatable=True),
    _string("target_os_version", environment=_env("target_os_version")),
    _string("package_channel", environment=_env("os_package_channel")),
    _string("image_id", environment=_env("oci_image_id")),
    _int("max_unavailable", default=1, minimum=1, maximum=1),
    _int(
        "health_timeout_seconds",
        environment=_env("health_timeout_seconds"),
        default=1800,
        minimum=1,
    ),
    _int(
        "reboot_timeout_seconds",
        environment=_env("reboot_timeout_seconds"),
        default=1800,
        minimum=1,
    ),
    FieldSpec("resume_operation", ValueKind.UUID),
    _string("confirm_reprovision_host", repeatable=True),
)

_CHECK_JUMP_HOSTS_FIELDS = (
    _string("jump_host", repeatable=True),
    _enum(
        "destination",
        ("assigned", "scylla", "manager", "monitoring", "all"),
        default=("assigned",),
        repeatable=True,
    ),
    _enum("depth", ("bastion", "route", "all-targets"), default="route"),
    _mapping(
        "destination_check",
        ValueKind.INTEGER_MAP,
        help=(
            "Add an allowlisted ROLE=PORT private TCP probe: "
            "scylla=7000|7001|9042|9142, manager=5080, or "
            "monitoring=3000|9090."
        ),
    ),
    _float(
        "connect_timeout_seconds",
        environment=_env("ssh_connect_timeout_seconds"),
        default=10.0,
        minimum=0.0000001,
    ),
    _int(
        "check_timeout_seconds",
        environment=_env("jump_check_timeout_seconds"),
        default=300,
        minimum=1,
    ),
)

_SHOW_FIELDS = (
    _enum(
        "section",
        (
            "summary",
            "topology",
            "hosts",
            "storage",
            "services",
            "freshness",
            "operations",
            "drift",
            "health",
            "all",
        ),
        default=("all",),
        repeatable=True,
    ),
    _string("node_id", repeatable=True),
    _enum(
        "live",
        ("provider", "connectivity", "health", "all"),
        default=(),
        repeatable=True,
        help="Request a live source (not implemented).",
    ),
    _action("include_addresses"),
    _enum(
        "fail_on",
        ("stale", "drift", "conflict", "unhealthy", "unknown", "none"),
        default=("conflict",),
        repeatable=True,
    ),
    _int(
        "live_timeout_seconds",
        environment=_env("show_live_timeout_seconds"),
        default=300,
        minimum=1,
    ),
)

OPERATION_CONTRACTS: Mapping[str, OperationContract] = MappingProxyType(
    {
        "deploy": OperationContract(
            (
                "mutate",
                "oci-context",
                "network",
                "images",
                "topology",
                "shapes",
                "scylla-storage",
                "service-storage",
            ),
            _DEPLOY_FIELDS,
        ),
        "add-node": OperationContract(
            ("mutate", "oci-context", "scylla-storage"),
            (
                _string(
                    "scylla_instance_type", environment=_env("scylla_instance_type")
                ),
                *_ADD_NODE_FIELDS,
            ),
        ),
        "replace-node": OperationContract(
            ("mutate", "destructive", "oci-context", "scylla-storage"),
            (
                _string(
                    "scylla_instance_type", environment=_env("scylla_instance_type")
                ),
                *_REPLACE_NODE_FIELDS,
            ),
        ),
        "destroy-node": OperationContract(
            ("mutate", "destructive", "oci-context"), _DESTROY_NODE_FIELDS
        ),
        "destroy": OperationContract(
            ("mutate", "destructive", "oci-context"), _DESTROY_FIELDS
        ),
        "scale-out": OperationContract(
            ("mutate", "oci-context", "scylla-storage"),
            (
                _string(
                    "scylla_instance_type", environment=_env("scylla_instance_type")
                ),
                *_SCALE_OUT_FIELDS,
            ),
        ),
        "scale-in": OperationContract(
            ("mutate", "destructive", "oci-context"), _SCALE_IN_FIELDS
        ),
        "redeploy": OperationContract(
            ("mutate", "destructive", "oci-context", "network", "service-storage"),
            (
                _string(
                    "manager_instance_type", environment=_env("manager_instance_type")
                ),
                _string(
                    "monitoring_instance_type",
                    environment=_env("monitoring_instance_type"),
                ),
                _string(
                    "jump_host_instance_type",
                    environment=_env("jump_host_instance_type"),
                ),
                *_REDEPLOY_FIELDS,
            ),
        ),
        "refresh-monitoring": OperationContract(
            ("mutate", "oci-context"), _REFRESH_MONITORING_FIELDS
        ),
        "upgrade-os": OperationContract(
            ("mutate", "destructive", "oci-context"), _UPGRADE_OS_FIELDS
        ),
        "check-jump-hosts": OperationContract(
            ("oci-context",), _CHECK_JUMP_HOSTS_FIELDS
        ),
        "show": OperationContract(("oci-context",), _SHOW_FIELDS),
    }
)


def default_for_operation(operation: str, field: FieldSpec) -> OptionValue:
    """Return the documented default/deferred source for one operation field."""

    if operation == "deploy" and field.name in DEPLOY_DEFAULTS:
        return DEPLOY_DEFAULTS[field.name]
    if operation == "show" and field.name in {
        "oci_region",
        "oci_compartment_id",
    }:
        return DeferredValue.PERSISTED
    if operation not in {"deploy", "show"} and field.name in PERSISTED_FIELD_NAMES:
        return DeferredValue.PERSISTED
    return field.default


def fields_for_operation(operation: str) -> tuple[FieldSpec, ...]:
    """Return core plus exact operation fields, rejecting duplicate definitions."""

    contract = OPERATION_CONTRACTS[operation]
    fields = list(CORE_FIELDS)
    for group in contract.groups:
        fields.extend(GROUP_FIELDS[group])
    fields.extend(contract.fields)
    unique: dict[str, FieldSpec] = {}
    for field in fields:
        if field.name in unique:
            raise ValueError(f"duplicate field in {operation}: {field.name}")
        unique[field.name] = field
    return tuple(unique.values())


def _build_environment_fields() -> Mapping[str, FieldSpec]:
    fields_by_environment = {
        field.environment: field
        for fields in GROUP_FIELDS.values()
        for field in fields
        if field.environment is not None
    }
    for operation_contract in OPERATION_CONTRACTS.values():
        for operation_field in operation_contract.fields:
            if operation_field.environment is not None:
                fields_by_environment[operation_field.environment] = operation_field
    return MappingProxyType(fields_by_environment)


NON_SECRET_ENVIRONMENT_FIELDS = _build_environment_fields()

DESIRED_CONFIG_FIELD_NAMES = frozenset(
    {
        "cloud_provider",
        "cluster_name",
        "oci_region",
        "oci_compartment_id",
        "network_mode",
        "oci_vcn_id",
        "oci_vcn_cidr",
        "oci_private_subnet_cidr",
        "oci_public_subnet_cidr",
        "oci_public_jump_hosts",
        *(field.name for field in IMAGE_FIELDS),
        "oci_subnet",
        "operator_cidr",
        "ssh_user",
        "ssh_public_key_path",
        "zone",
        "nodes_per_zone",
        "scylla_datacenter",
        "scylla_rack",
        "jump_host_count",
        "scylla_instance_type",
        "manager_instance_type",
        "monitoring_instance_type",
        "jump_host_instance_type",
        "scylla_storage_backend",
        "scylla_storage_min_device_count",
        "scylla_storage_min_total_gib",
        "scylla_storage_layout",
        "scylla_block_volume_count",
        "scylla_block_volume_size_gib",
        "scylla_block_volume_vpus_per_gb",
        "scylla_block_volume_attachment_type",
        "scylla_block_volume_retention",
        "scylla_block_volume_key_id",
        "scylla_block_volume_in_transit_encryption",
        "scylla_block_volume_chap",
        "manager_data_volume_size_gib",
        "manager_data_volume_vpus_per_gb",
        "manager_data_volume_attachment_type",
        "manager_data_volume_retention",
        "manager_data_volume_key_id",
        "manager_data_volume_in_transit_encryption",
        "monitoring_data_volume_size_gib",
        "monitoring_data_volume_vpus_per_gb",
        "monitoring_data_volume_attachment_type",
        "monitoring_data_volume_retention",
        "monitoring_data_volume_key_id",
        "monitoring_data_volume_in_transit_encryption",
        "manager_count",
        "monitoring_count",
        "manager_zone",
        "monitoring_zone",
    }
)

DESIRED_CONFIG_FIELDS: Mapping[str, FieldSpec] = MappingProxyType(
    {
        field.name: field
        for field in fields_for_operation("deploy")
        if field.name in DESIRED_CONFIG_FIELD_NAMES
    }
)
