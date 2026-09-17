"""Cross-field validation for operation request contracts."""

import ipaddress
import re
import uuid
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType

from scylla_vms.errors import ConfigurationError
from scylla_vms.models import DeferredValue, ResolvedOption, ValueSource

_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TOPOLOGY_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_OCI_REGION = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
_OCI_SHAPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
DESTINATION_CHECK_PORTS = {
    "manager": frozenset({5080}),
    "monitoring": frozenset({3000, 9090}),
    "scylla": frozenset({7000, 7001, 9042, 9142}),
}


def validate_operation_options(
    operation: str, options: dict[str, ResolvedOption]
) -> None:
    """Validate locally decidable operation rules without persisted state."""

    _validate_common(operation, options)
    validator = _VALIDATORS[operation]
    validator(options)


def _validate_common(operation: str, options: dict[str, ResolvedOption]) -> None:
    if (
        "dry_run" in options
        and _boolean(options, "dry_run")
        and _boolean(options, "plan")
    ):
        raise ConfigurationError("--dry-run and --plan are mutually exclusive")

    for name in (
        "zone",
        "node_id",
        "target_host",
        "target_role",
        "component",
        "target",
        "jump_host",
        "destination",
        "section",
        "live",
        "fail_on",
        "remove_node",
        "confirm_wipe_device",
        "confirm_reprovision_host",
        "retained_volume_id",
    ):
        if name in options:
            value = options[name].value
            if isinstance(value, tuple):
                strings = tuple(item for item in value if isinstance(item, str))
                if len(strings) == len(value):
                    _require_unique(strings, "--" + name.replace("_", "-"))

    if "oci_region" in options:
        region = _optional_string(options, "oci_region")
        if region is not None and not _OCI_REGION.fullmatch(region):
            raise ConfigurationError("--oci-region has invalid syntax")
    if "oci_compartment_id" in options:
        compartment = _optional_string(options, "oci_compartment_id")
        if compartment is not None:
            _validate_ocid(compartment, "--oci-compartment-id")
    for name in (
        "oci_vcn_id",
        "scylla_block_volume_key_id",
        "manager_data_volume_key_id",
        "monitoring_data_volume_key_id",
        "image_id",
    ):
        if name in options:
            identifier = _optional_string(options, name)
            if identifier is not None:
                _validate_ocid(identifier, "--" + name.replace("_", "-"))

    for name in (
        "scylla_instance_type",
        "manager_instance_type",
        "monitoring_instance_type",
        "jump_host_instance_type",
    ):
        if name in options:
            shape = _optional_string(options, name)
            if shape is not None and not _OCI_SHAPE.fullmatch(shape):
                raise ConfigurationError(
                    f"--{name.replace('_', '-')} has invalid shape syntax"
                )

    # Local read-only operations do not cross the provider adapter boundary.
    auth_required = operation not in {"check-jump-hosts", "show"}
    if auth_required and _optional_string(options, "oci_auth_mode") is None:
        raise ConfigurationError("--oci-auth-mode is required for this operation")

    if "non_interactive" in options and _boolean(options, "non_interactive"):
        is_preview = _boolean(options, "dry_run") or _boolean(options, "plan")
        if not is_preview and "yes" in options and not _boolean(options, "yes"):
            raise ConfigurationError("--non-interactive execution requires --yes")


def _validate_deploy(options: dict[str, ResolvedOption]) -> None:
    _require_concrete(options, "oci_region")
    _require_concrete(options, "oci_compartment_id")
    zones = _strings(options, "zone")
    if not zones:
        raise ConfigurationError("deploy requires at least one --zone")
    _require_unique(zones, "--zone")

    node_counts = _map(options, "nodes_per_zone")
    if set(node_counts) != set(zones):
        raise ConfigurationError(
            "--nodes-per-zone must define every declared --zone exactly once"
        )
    _require_integer_values(node_counts, "--nodes-per-zone", minimum=0)

    racks = _map(options, "scylla_rack")
    if not set(racks).issubset(zones):
        raise ConfigurationError("--scylla-rack contains an unknown zone")
    rack_values = tuple(str(value) for value in racks.values())
    _require_unique(rack_values, "--scylla-rack values")
    for rack in rack_values:
        _validate_topology_name(rack, "--scylla-rack")
    datacenter = _optional_string(options, "scylla_datacenter")
    if datacenter is not None:
        _validate_topology_name(datacenter, "--scylla-datacenter")

    for name in (
        "scylla_instance_type",
        "manager_instance_type",
        "monitoring_instance_type",
    ):
        _require_concrete(options, name)
    jump_count = _integer(options, "jump_host_count")
    image_roles = ["scylla", "manager", "monitoring"]
    if jump_count > 0:
        image_roles.append("jump_host")
    for role in image_roles:
        _require_concrete(options, f"{role}_image_operating_system")
        _require_concrete(options, f"{role}_image_operating_system_version")
        if (
            _string(options, f"{role}_image_operating_system") != "Ubuntu"
            or _string(options, f"{role}_image_operating_system_version") != "24.04"
            or _string(options, f"{role}_image_version_match") != "exact"
        ):
            raise ConfigurationError(
                "new OCI desired state supports only exact Ubuntu 24.04 "
                f"image filters: {role.replace('_', '-')}"
            )
    if jump_count == 0 and any(
        _is_concrete(options, f"jump_host_image_{suffix}")
        for suffix in ("operating_system", "operating_system_version")
    ):
        raise ConfigurationError(
            "jump-host image filters are forbidden when jump-host count is zero"
        )
    if jump_count > 0:
        _require_concrete(options, "jump_host_instance_type")
    elif _is_concrete(options, "jump_host_instance_type"):
        raise ConfigurationError(
            "--jump-host-instance-type is forbidden when jump-host count is zero"
        )

    if _integer(options, "manager_count") != 1:
        raise ConfigurationError("--manager-count must be exactly 1")
    if _integer(options, "monitoring_count") != 1:
        raise ConfigurationError("--monitoring-count must be exactly 1")
    for name in ("manager_zone", "monitoring_zone"):
        value = _optional_string(options, name)
        if value is not None and value not in zones:
            raise ConfigurationError(f"--{name.replace('_', '-')} must name a zone")

    network_mode = _string(options, "network_mode")
    subnets = _map(options, "oci_subnet")
    vcn = _optional_string(options, "oci_vcn_id")
    vcn_cidr = _optional_string(options, "oci_vcn_cidr")
    private_cidrs = _map(options, "oci_private_subnet_cidr")
    public_cidrs = _map(options, "oci_public_subnet_cidr")
    public_jump_hosts = _boolean(options, "oci_public_jump_hosts")
    if network_mode == "create":
        if vcn is not None or subnets:
            raise ConfigurationError(
                "--network-mode create forbids --oci-vcn-id and --oci-subnet"
            )
        if vcn_cidr is None:
            raise ConfigurationError("--network-mode create requires --oci-vcn-cidr")
        if set(private_cidrs) != set(zones):
            raise ConfigurationError(
                "--oci-private-subnet-cidr must define every zone exactly once"
            )
        if not set(public_cidrs).issubset(zones):
            raise ConfigurationError(
                "--oci-public-subnet-cidr contains an unknown zone"
            )
        if public_jump_hosts:
            if jump_count == 0 or not public_cidrs:
                raise ConfigurationError(
                    "public jump hosts require jump hosts and public subnet CIDRs"
                )
        elif public_cidrs:
            raise ConfigurationError(
                "--oci-public-subnet-cidr requires --oci-public-jump-hosts"
            )
        _validate_managed_network_cidrs(vcn_cidr, private_cidrs, public_cidrs)
    else:
        if vcn_cidr is not None or private_cidrs or public_cidrs:
            raise ConfigurationError(
                "--network-mode existing forbids managed network CIDRs"
            )
        if vcn is None:
            raise ConfigurationError("--network-mode existing requires --oci-vcn-id")
        _validate_ocid(vcn, "--oci-vcn-id")
        required_roles = {"manager", "monitoring"}
        if sum(value for value in node_counts.values() if isinstance(value, int)) > 0:
            required_roles.add("scylla")
        if jump_count > 0:
            required_roles.add("jump-host")
        if set(subnets) != required_roles:
            raise ConfigurationError(
                "--oci-subnet must define every deployed role exactly once"
            )
        for subnet in subnets.values():
            _validate_ocid(str(subnet), "--oci-subnet")
    if public_jump_hosts and not _strings(options, "operator_cidr"):
        raise ConfigurationError("public jump hosts require --operator-cidr")

    public_key = _path(options, "ssh_public_key_path")
    if not public_key.is_file():
        raise ConfigurationError("--ssh-public-key-path must be a readable file")

    _validate_scylla_storage(options, require_concrete=True)
    for prefix in ("manager", "monitoring"):
        for suffix in (
            "data_volume_size_gib",
            "data_volume_vpus_per_gb",
            "data_volume_attachment_type",
        ):
            _require_concrete(options, f"{prefix}_{suffix}")


def _validate_add_node(options: dict[str, ResolvedOption]) -> None:
    _validate_logical_id(_string(options, "node_id"), "--node-id")
    _require_concrete(options, "zone")
    expected_rack = _optional_string(options, "expected_rack")
    if expected_rack is not None:
        _validate_topology_name(expected_rack, "--expected-rack")
    _validate_wipe_pair(options)
    _validate_scylla_storage(options, require_concrete=False)


def _validate_scale_out(options: dict[str, ResolvedOption]) -> None:
    desired = _map(options, "nodes_per_zone")
    additions = _map(options, "add_nodes_per_zone")
    if bool(desired) == bool(additions):
        raise ConfigurationError(
            "exactly one of --nodes-per-zone or --add-nodes-per-zone is required"
        )
    if desired:
        _require_integer_values(desired, "--nodes-per-zone", minimum=0)
    if additions:
        _require_integer_values(additions, "--add-nodes-per-zone", minimum=1)
    node_ids = _map(options, "node_id")
    for zone, logical_id in node_ids.items():
        if zone not in (desired or additions):
            raise ConfigurationError("--node-id contains an unknown zone")
        _validate_logical_id(str(logical_id), "--node-id")
    _validate_scylla_storage(options, require_concrete=False)


def _validate_replace_node(options: dict[str, ResolvedOption]) -> None:
    node_id = _string(options, "node_id")
    _validate_logical_id(node_id, "--node-id")
    _require_concrete(options, "failed_host_id")
    reason = _string(options, "reason")
    if len(reason) > 500:
        raise ConfigurationError("--reason must not exceed 500 characters")
    source = _string(options, "storage_source")
    retained = _strings(options, "retained_volume_id")
    for volume_id in retained:
        _validate_ocid(volume_id, "--retained-volume-id")
    if source == "reuse-retained":
        if not retained or not _boolean(options, "wipe_storage"):
            raise ConfigurationError(
                "reuse-retained requires --retained-volume-id and --wipe-storage"
            )
        if _string(options, "old_volume_disposition") != "retain":
            raise ConfigurationError(
                "reuse-retained requires --old-volume-disposition retain"
            )
    elif retained:
        raise ConfigurationError(
            "--retained-volume-id is valid only with --storage-source reuse-retained"
        )
    _validate_wipe_pair(options)
    _validate_exact_confirmation(options, "confirm_replace_node", node_id)
    _validate_destructive_authorization(options, "confirm_replace_node")
    _validate_scylla_storage(options, require_concrete=False)


def _validate_destroy_node(options: dict[str, ResolvedOption]) -> None:
    node_id = _string(options, "node_id")
    _validate_logical_id(node_id, "--node-id")
    mode = _string(options, "removal_mode")
    failed = _optional_string(options, "failed_host_id")
    if mode == "dead" and failed is None:
        raise ConfigurationError("--removal-mode dead requires --failed-host-id")
    if mode == "live" and failed is not None:
        raise ConfigurationError("--removal-mode live forbids --failed-host-id")
    _validate_exact_confirmation(options, "confirm_destroy_node", node_id)
    _validate_destructive_authorization(options, "confirm_destroy_node")


def _validate_scale_in(options: dict[str, ResolvedOption]) -> None:
    desired = _map(options, "nodes_per_zone")
    removals = _strings(options, "remove_node")
    if bool(desired) == bool(removals):
        raise ConfigurationError(
            "exactly one of --nodes-per-zone or --remove-node is required"
        )
    if desired:
        _require_integer_values(desired, "--nodes-per-zone", minimum=0)
    for node_id in removals:
        _validate_logical_id(node_id, "--remove-node")
    if removals and options["selection_policy"].source is ValueSource.CLI:
        raise ConfigurationError(
            "--selection-policy is valid only with --nodes-per-zone"
        )
    if removals:
        options["selection_policy"] = ResolvedOption(
            "selection_policy", None, ValueSource.UNSET
        )

    modes = _map(options, "removal_mode")
    failed_ids = _map(options, "failed_host_id")
    dispositions = _map(options, "volume_disposition")
    selected = set(removals)
    if selected and not _is_preview(options) and set(modes) != selected:
        raise ConfigurationError(
            "--removal-mode must define every selected --remove-node"
        )
    for node_id, mode in modes.items():
        _validate_logical_id(node_id, "--removal-mode")
        if str(mode) == "dead":
            if node_id not in failed_ids:
                raise ConfigurationError(
                    "every dead removal requires a matching --failed-host-id"
                )
        elif node_id in failed_ids:
            raise ConfigurationError("live removals forbid a matching --failed-host-id")
    for node_id, host_id in failed_ids.items():
        _validate_logical_id(node_id, "--failed-host-id")
        _validate_uuid(str(host_id), "--failed-host-id")
    for node_id in dispositions:
        _validate_logical_id(node_id, "--volume-disposition")
    if selected and not set(dispositions).issubset(selected):
        raise ConfigurationError("--volume-disposition contains an unselected node")
    _validate_exact_confirmation(
        options, "confirm_scale_in", _string(options, "cluster_name")
    )
    _validate_destructive_authorization(options, "confirm_scale_in")


def _validate_destroy(options: dict[str, ResolvedOption]) -> None:
    confirmation = _optional_string(options, "confirm_destroy_cluster")
    if confirmation is not None:
        cluster_name = _string(options, "cluster_name")
        prefix = f"{cluster_name}:"
        if not confirmation.startswith(prefix):
            raise ConfigurationError(
                "--confirm-destroy-cluster must start with the exact cluster name"
            )
        _validate_uuid(confirmation.removeprefix(prefix), "--confirm-destroy-cluster")
    _validate_destructive_authorization(options, "confirm_destroy_cluster")


def _validate_redeploy(options: dict[str, ResolvedOption]) -> None:
    scope = _string(options, "scope")
    target = _optional_string(options, "target_host")
    components = _strings(options, "component")
    infrastructure = _string(options, "infrastructure")
    if scope == "host":
        if target is None:
            raise ConfigurationError("--scope host requires --target-host")
        _validate_logical_id(target, "--target-host")
    elif target is not None:
        raise ConfigurationError("--target-host is valid only with --scope host")
    if scope == "service" and not components:
        raise ConfigurationError("--scope service requires --component")
    if scope == "cluster":
        if not components:
            options["component"] = ResolvedOption(
                "component", ("all",), ValueSource.DEFAULT
            )
            components = ("all",)
        elif components != ("all",):
            raise ConfigurationError("--scope cluster accepts only --component all")
    elif scope == "host" and not components:
        options["component"] = ResolvedOption(
            "component", DeferredValue.DERIVED, ValueSource.DERIVED
        )
    if "all" in components and len(components) != 1:
        raise ConfigurationError("--component all cannot be combined")

    if infrastructure == "recreate-stateless":
        if scope != "host" or target is None:
            raise ConfigurationError(
                "recreate-stateless requires --scope host and --target-host"
            )
        _validate_exact_confirmation(options, "confirm_recreate_host", target)
        _validate_destructive_authorization(options, "confirm_recreate_host")
    else:
        if _is_concrete(options, "confirm_recreate_host"):
            raise ConfigurationError(
                "--confirm-recreate-host requires recreate-stateless"
            )
        if _boolean(options, "allow_destructive"):
            raise ConfigurationError("--allow-destructive requires recreate-stateless")
    if infrastructure == "reconcile" and scope != "cluster":
        raise ConfigurationError("--infrastructure reconcile requires --scope cluster")

    network_names = (
        "network_mode",
        "oci_vcn_id",
        "oci_subnet",
        "operator_cidr",
        "ssh_user",
        "ssh_public_key_path",
    )
    if not (scope == "cluster" and infrastructure == "reconcile") and any(
        options[name].source
        in {ValueSource.CLI, ValueSource.ENVIRONMENT, ValueSource.CONFIG}
        for name in network_names
    ):
        raise ConfigurationError(
            "network options require --scope cluster --infrastructure reconcile"
        )

    recreate_names = (
        "manager_instance_type",
        "monitoring_instance_type",
        "jump_host_instance_type",
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
    )
    if infrastructure != "recreate-stateless" and any(
        options[name].source
        in {ValueSource.CLI, ValueSource.ENVIRONMENT, ValueSource.CONFIG}
        for name in recreate_names
    ):
        raise ConfigurationError(
            "shape/service-storage options require recreate-stateless"
        )


def _validate_refresh_monitoring(options: dict[str, ResolvedOption]) -> None:
    action = _string(options, "service_action")
    confirmation = _boolean(options, "confirm_monitoring_restart")
    if action != "restart" and confirmation:
        raise ConfigurationError(
            "--confirm-monitoring-restart requires --service-action restart"
        )
    if (
        action == "restart"
        and _boolean(options, "non_interactive")
        and not confirmation
        and not _is_preview(options)
    ):
        raise ConfigurationError(
            "non-interactive restart requires --confirm-monitoring-restart"
        )


def _validate_upgrade_os(options: dict[str, ResolvedOption]) -> None:
    roles = _strings(options, "target_role")
    hosts = _strings(options, "target_host")
    if bool(roles) == bool(hosts):
        raise ConfigurationError(
            "exactly one of --target-role or --target-host is required"
        )
    for host in hosts:
        _validate_logical_id(host, "--target-host")
    _require_concrete(options, "target_os_version")
    strategy = _string(options, "strategy")
    package = _optional_string(options, "package_channel")
    image = _optional_string(options, "image_id")
    if strategy == "in-place":
        if package is None or image is not None:
            raise ConfigurationError(
                "in-place requires --package-channel and forbids --image-id"
            )
        if _boolean(options, "allow_destructive"):
            raise ConfigurationError(
                "--allow-destructive is forbidden for in-place upgrades"
            )
    elif strategy == "reprovision":
        if image is None or package is not None:
            raise ConfigurationError(
                "reprovision requires --image-id and forbids --package-channel"
            )
        _validate_reprovision_confirmations(options, hosts)
    elif package is None:
        raise ConfigurationError("auto strategy requires --package-channel")


def _validate_check_jump_hosts(options: dict[str, ResolvedOption]) -> None:
    destinations = _strings(options, "destination")
    _require_unique(destinations, "--destination")
    if "all" in destinations and len(destinations) != 1:
        raise ConfigurationError("--destination all cannot be combined")
    checks = _map(options, "destination_check")
    if not set(checks).issubset(DESTINATION_CHECK_PORTS):
        raise ConfigurationError("--destination-check contains an unknown role")
    _require_integer_values(checks, "--destination-check", minimum=1, maximum=65535)
    for role, port in checks.items():
        if port not in DESTINATION_CHECK_PORTS[role]:
            allowed = ", ".join(
                str(value) for value in sorted(DESTINATION_CHECK_PORTS[role])
            )
            raise ConfigurationError(
                f"--destination-check {role} port is not allowlisted; allowed: "
                f"{allowed}"
            )
    jump_hosts = _strings(options, "jump_host")
    _require_unique(jump_hosts, "--jump-host")
    for host in jump_hosts:
        _validate_logical_id(host, "--jump-host")


def _validate_show(options: dict[str, ResolvedOption]) -> None:
    sections = _strings(options, "section")
    lives = _strings(options, "live")
    failures = _strings(options, "fail_on")
    if "all" in sections and len(sections) != 1:
        raise ConfigurationError("--section all cannot be combined")
    if "all" in lives and len(lives) != 1:
        raise ConfigurationError("--live all cannot be combined")
    if "none" in failures and len(failures) != 1:
        raise ConfigurationError("--fail-on none cannot be combined")
    for node_id in _strings(options, "node_id"):
        _validate_logical_id(node_id, "--node-id")


def _validate_scylla_storage(
    options: dict[str, ResolvedOption], *, require_concrete: bool
) -> None:
    backend_value = options["scylla_storage_backend"].value
    if backend_value is DeferredValue.PERSISTED and not require_concrete:
        return
    backend = _string(options, "scylla_storage_backend")
    local_names = (
        "scylla_storage_min_device_count",
        "scylla_storage_min_total_gib",
    )
    block_names = (
        "scylla_block_volume_count",
        "scylla_block_volume_size_gib",
        "scylla_block_volume_vpus_per_gb",
        "scylla_block_volume_attachment_type",
        "scylla_block_volume_retention",
    )
    if backend in {"auto", "local-nvme"}:
        for name in local_names:
            _require_concrete(options, name)
    if backend in {"auto", "block-volume"}:
        for name in block_names:
            _require_concrete(options, name)
    if backend == "local-nvme":
        _forbid_concrete(options, block_names)
    if backend == "block-volume":
        _forbid_concrete(options, local_names)
    if _string(options, "scylla_block_volume_chap") == "enabled":
        raise ConfigurationError("--scylla-block-volume-chap enabled is not supported")
    count = _optional_integer(options, "scylla_block_volume_count")
    local_count = _optional_integer(options, "scylla_storage_min_device_count")
    effective_count = count if backend != "local-nvme" else local_count
    layout = _optional_string(options, "scylla_storage_layout")
    if effective_count is not None and effective_count > 1 and layout is None:
        raise ConfigurationError(
            "--scylla-storage-layout is required for multiple devices"
        )
    if effective_count == 1 and layout is None:
        options["scylla_storage_layout"] = ResolvedOption(
            "scylla_storage_layout", "single", ValueSource.DEFAULT
        )


def _validate_wipe_pair(options: dict[str, ResolvedOption]) -> None:
    wipe = _boolean(options, "wipe_storage")
    confirmations = _strings(options, "confirm_wipe_device")
    if wipe != bool(confirmations):
        raise ConfigurationError(
            "--wipe-storage and --confirm-wipe-device are required together"
        )


def _validate_destructive_authorization(
    options: dict[str, ResolvedOption], confirmation_name: str
) -> None:
    if _is_preview(options):
        return
    if not _boolean(options, "allow_destructive"):
        raise ConfigurationError("destructive execution requires --allow-destructive")
    if _boolean(options, "non_interactive") and not _is_concrete(
        options, confirmation_name
    ):
        flag = "--" + confirmation_name.replace("_", "-")
        raise ConfigurationError(
            f"non-interactive destructive execution requires {flag}"
        )


def _validate_exact_confirmation(
    options: dict[str, ResolvedOption], name: str, expected: str
) -> None:
    actual = _optional_string(options, name)
    if actual is not None and actual != expected:
        raise ConfigurationError(
            f"--{name.replace('_', '-')} must exactly match its target"
        )


def _validate_reprovision_confirmations(
    options: dict[str, ResolvedOption], hosts: tuple[str, ...]
) -> None:
    if _is_preview(options):
        return
    if not _boolean(options, "allow_destructive"):
        raise ConfigurationError("reprovision execution requires --allow-destructive")
    confirmed = set(_strings(options, "confirm_reprovision_host"))
    if hosts and confirmed != set(hosts):
        raise ConfigurationError(
            "--confirm-reprovision-host must match every target host"
        )


def _validate_topology_name(value: str, flag: str) -> None:
    if not _TOPOLOGY_NAME.fullmatch(value) or "--" in value or value.endswith("-"):
        raise ConfigurationError(f"{flag} has invalid normalized topology syntax")


def _validate_logical_id(value: str, flag: str) -> None:
    if not value.isascii() or not _LOGICAL_ID.fullmatch(value):
        raise ConfigurationError(f"{flag} has invalid stable logical ID syntax")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return
    raise ConfigurationError(f"{flag} must not be an IP address")


def _validate_ocid(value: str, flag: str) -> None:
    if (
        not value.isascii()
        or not value.startswith("ocid1.")
        or any(character.isspace() for character in value)
        or len(value) > 255
    ):
        raise ConfigurationError(f"{flag} must be an OCI OCID")


def _validate_managed_network_cidrs(
    vcn_value: str,
    private_values: Mapping[str, object],
    public_values: Mapping[str, object],
) -> None:
    vcn = _rfc1918_network(vcn_value, "--oci-vcn-cidr")
    networks: list[ipaddress.IPv4Network] = []
    for value in (*private_values.values(), *public_values.values()):
        if not isinstance(value, str):
            raise ConfigurationError("managed subnet CIDR must be a string")
        subnet = _rfc1918_network(value, "managed subnet CIDR")
        if not subnet.subnet_of(vcn):
            raise ConfigurationError("managed subnet CIDR must be inside the VCN")
        if any(subnet.overlaps(existing) for existing in networks):
            raise ConfigurationError("managed subnet CIDRs must not overlap")
        networks.append(subnet)


def _rfc1918_network(value: str, label: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise ConfigurationError(f"{label} must be canonical") from error
    if not isinstance(network, ipaddress.IPv4Network):
        raise ConfigurationError(f"{label} must be IPv4")
    private_ranges = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    if not any(network.subnet_of(item) for item in private_ranges):
        raise ConfigurationError(f"{label} must use RFC 1918 address space")
    if not 16 <= network.prefixlen <= 30:
        raise ConfigurationError(f"{label} prefix must be between /16 and /30")
    return network


def _validate_uuid(value: str, flag: str) -> None:
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise ConfigurationError(f"{flag} must be a UUID") from error
    if str(parsed) != value.lower():
        raise ConfigurationError(f"{flag} must use canonical UUID spelling")


def _forbid_concrete(
    options: dict[str, ResolvedOption], names: tuple[str, ...]
) -> None:
    present = [name for name in names if _is_concrete(options, name)]
    if present:
        flags = ", ".join("--" + name.replace("_", "-") for name in present)
        raise ConfigurationError(f"selected storage backend forbids: {flags}")


def _require_concrete(options: dict[str, ResolvedOption], name: str) -> None:
    if not _is_concrete(options, name):
        raise ConfigurationError(
            f"--{name.replace('_', '-')} is required for this operation"
        )


def _is_concrete(options: dict[str, ResolvedOption], name: str) -> bool:
    value = options[name].value
    return value is not None and not isinstance(value, DeferredValue)


def _is_preview(options: dict[str, ResolvedOption]) -> bool:
    return _boolean(options, "dry_run") or _boolean(options, "plan")


def _boolean(options: dict[str, ResolvedOption], name: str) -> bool:
    if name not in options:
        return False
    value = options[name].value
    if not isinstance(value, bool):
        raise ConfigurationError(f"{name} did not resolve to a boolean")
    return value


def _string(options: dict[str, ResolvedOption], name: str) -> str:
    value = options[name].value
    if not isinstance(value, str):
        raise ConfigurationError(f"required setting is missing: {name}")
    return value


def _optional_string(options: dict[str, ResolvedOption], name: str) -> str | None:
    value = options[name].value
    if value is None or isinstance(value, DeferredValue):
        return None
    if not isinstance(value, str):
        raise ConfigurationError(f"{name} did not resolve to a string")
    return value


def _integer(options: dict[str, ResolvedOption], name: str) -> int:
    value = options[name].value
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigurationError(f"required integer is missing: {name}")
    return value


def _optional_integer(options: dict[str, ResolvedOption], name: str) -> int | None:
    value = options[name].value
    if value is None or isinstance(value, DeferredValue):
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigurationError(f"{name} did not resolve to an integer")
    return value


def _path(options: dict[str, ResolvedOption], name: str) -> Path:
    value = options[name].value
    if not isinstance(value, Path):
        raise ConfigurationError(f"required path is missing: {name}")
    return value


def _strings(options: dict[str, ResolvedOption], name: str) -> tuple[str, ...]:
    if name not in options:
        return ()
    value = options[name].value
    if not isinstance(value, tuple):
        raise ConfigurationError(f"{name} did not resolve to a list")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ConfigurationError(f"{name} contains a non-string")
        result.append(item)
    return tuple(result)


def _map(
    options: dict[str, ResolvedOption], name: str
) -> dict[str, str | int | float | bool | Path | DeferredValue | None]:
    value = options[name].value
    if not isinstance(value, tuple):
        raise ConfigurationError(f"{name} did not resolve to a mapping")
    result: dict[str, str | int | float | bool | Path | DeferredValue | None] = {}
    for item in value:
        if not isinstance(item, tuple) or len(item) != 2:
            raise ConfigurationError(f"{name} contains an invalid mapping entry")
        key, item_value = item
        if not isinstance(key, str):
            raise ConfigurationError(f"{name} contains a non-string key")
        result[key] = item_value
    return result


def _require_integer_values(
    values: Mapping[str, object],
    flag: str,
    *,
    minimum: int,
    maximum: int | None = None,
) -> None:
    for value in values.values():
        if not isinstance(value, int) or isinstance(value, bool):
            raise ConfigurationError(f"{flag} values must be integers")
        if value < minimum or (maximum is not None and value > maximum):
            if maximum is None:
                raise ConfigurationError(f"{flag} values must be at least {minimum}")
            raise ConfigurationError(
                f"{flag} values must be between {minimum} and {maximum}"
            )


def _require_unique(values: tuple[str, ...], flag: str) -> None:
    if len(values) != len(set(values)):
        raise ConfigurationError(f"{flag} values must be unique")


_VALIDATORS = MappingProxyType(
    {
        "deploy": _validate_deploy,
        "add-node": _validate_add_node,
        "replace-node": _validate_replace_node,
        "destroy-node": _validate_destroy_node,
        "destroy": _validate_destroy,
        "scale-out": _validate_scale_out,
        "scale-in": _validate_scale_in,
        "redeploy": _validate_redeploy,
        "refresh-monitoring": _validate_refresh_monitoring,
        "upgrade-os": _validate_upgrade_os,
        "check-jump-hosts": _validate_check_jump_hosts,
        "show": _validate_show,
    }
)
