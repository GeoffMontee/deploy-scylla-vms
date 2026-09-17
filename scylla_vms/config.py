"""Strict CLI/environment resolution into immutable operation requests."""

import ipaddress
import math
import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_state_path

from scylla_vms.config_file import load_config
from scylla_vms.contracts import (
    NON_SECRET_ENVIRONMENT_FIELDS,
    FieldSpec,
    ValueKind,
    default_for_operation,
    fields_for_operation,
)
from scylla_vms.errors import ConfigurationError
from scylla_vms.models import (
    DeferredValue,
    OperationRequest,
    OptionValue,
    ResolvedOption,
    ScalarValue,
    ValueSource,
)
from scylla_vms.operations import get_operation
from scylla_vms.providers import ProviderDefinition, get_provider
from scylla_vms.secrets import SECRET_ENVIRONMENT_NAMES, SecretInputs
from scylla_vms.state import StatePaths, resolve_state_root, validate_cluster_name

_PREFIX = "DEPLOY_SCYLLA_VMS_"
_CANONICAL_INTEGER = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_CANONICAL_FLOAT = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")


def resolve_operation_request(
    arguments: Mapping[str, object],
    *,
    environ: Mapping[str, str] | None = None,
    default_state_root: Callable[[], Path] | None = None,
) -> OperationRequest:
    """Resolve one operation, reading optional TOML but never writing state."""

    source_environment = os.environ if environ is None else environ
    operation_name = arguments.get("operation")
    if not isinstance(operation_name, str):
        raise ConfigurationError("an operation is required")
    operation = get_operation(operation_name)
    fields = fields_for_operation(operation_name)
    _validate_application_environment(source_environment, fields)
    secrets = SecretInputs.from_environment(source_environment)
    config_field = next(field for field in fields if field.name == "config")
    config_option = _resolve_field(
        config_field, arguments, source_environment, operation_name, {}
    )
    config_path = config_option.value
    if config_path is not None and not isinstance(config_path, Path):
        raise ConfigurationError("configuration path did not resolve to a path")
    loaded_config = load_config(config_path)

    resolved = tuple(
        _resolve_field(
            field,
            arguments,
            source_environment,
            operation_name,
            loaded_config.values,
        )
        for field in fields
    )
    values = {item.name: item for item in resolved}

    provider_name = _required_string(values["cloud_provider"])
    try:
        provider = get_provider(provider_name)
    except KeyError as error:
        raise ConfigurationError(
            f"unsupported cloud provider: {provider_name}"
        ) from error

    cluster_name = validate_cluster_name(_required_string(values["cluster_name"]))
    state_option = values["state_dir"]
    if state_option.value is None:
        factory = default_state_root or (
            lambda: user_state_path("deploy-scylla-vms", appauthor=False)
        )
        state_root = resolve_state_root(factory())
        state_option = ResolvedOption("state_dir", state_root, ValueSource.DEFAULT)
        resolved = tuple(
            state_option if item.name == "state_dir" else item for item in resolved
        )
        values["state_dir"] = state_option
    elif isinstance(state_option.value, Path):
        state_root = resolve_state_root(state_option.value)
    else:
        raise ConfigurationError("state directory did not resolve to a path")

    from scylla_vms.validation import validate_operation_options

    validate_operation_options(operation_name, values)
    auth_mode = values.get("oci_auth_mode")
    if auth_mode is not None and isinstance(auth_mode.value, str):
        region = values.get("oci_region")
        region_value = (
            region.value
            if region is not None and isinstance(region.value, str)
            else None
        )
        secrets.validate_oci_auth_mode(auth_mode.value, region_value)
    resolved = tuple(values[item.name] for item in resolved)
    return OperationRequest(
        operation=operation,
        provider=provider,
        cluster_name=cluster_name,
        state_root=state_root,
        paths=StatePaths.derive(state_root, cluster_name),
        options=resolved,
        secrets=secrets,
    )


def _resolve_field(
    field: FieldSpec,
    arguments: Mapping[str, object],
    environ: Mapping[str, str],
    operation: str,
    config_values: Mapping[str, object],
) -> ResolvedOption:
    cli_value = arguments.get(field.name)
    if cli_value is not None:
        return ResolvedOption(
            field.name, _parse_value(field, cli_value), ValueSource.CLI
        )
    if field.environment is not None and field.environment in environ:
        return ResolvedOption(
            field.name,
            _parse_value(field, environ[field.environment]),
            ValueSource.ENVIRONMENT,
        )
    if field.name in config_values:
        return ResolvedOption(
            field.name,
            _parse_config_value(field, config_values[field.name]),
            ValueSource.CONFIG,
        )

    default = default_for_operation(operation, field)
    if default is DeferredValue.PERSISTED:
        return ResolvedOption(field.name, default, ValueSource.PERSISTED)
    if default is DeferredValue.DERIVED:
        return ResolvedOption(field.name, default, ValueSource.DERIVED)
    if default is None:
        return ResolvedOption(field.name, None, ValueSource.UNSET)
    return ResolvedOption(field.name, default, ValueSource.DEFAULT)


def _parse_config_value(field: FieldSpec, raw: object) -> OptionValue:
    if field.kind is ValueKind.BOOLEAN:
        if isinstance(raw, bool):
            return raw
        raise ConfigurationError(f"config field {field.name} must be a boolean")
    if field.repeatable:
        if field.kind in {
            ValueKind.STRING_MAP,
            ValueKind.INTEGER_MAP,
            ValueKind.ENUM_MAP,
            ValueKind.CIDR_MAP,
        }:
            if not isinstance(raw, dict):
                raise ConfigurationError(f"config field {field.name} must be a table")
            return _parse_config_mapping(field, raw)
        if not isinstance(raw, list):
            raise ConfigurationError(f"config field {field.name} must be an array")
        return tuple(_parse_config_repeated(field, item) for item in raw)
    if field.kind is ValueKind.INTEGER:
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise ConfigurationError(f"config field {field.name} must be an integer")
        _check_range(field, float(raw))
        return raw
    if field.kind is ValueKind.FLOAT:
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise ConfigurationError(f"config field {field.name} must be a number")
        value = float(raw)
        if not math.isfinite(value):
            raise ConfigurationError(f"config field {field.name} must be finite")
        _check_range(field, value)
        return value
    if not isinstance(raw, str):
        raise ConfigurationError(f"config field {field.name} must be a string")
    return _parse_scalar(field, raw)


def _parse_config_repeated(field: FieldSpec, raw: object) -> str:
    if not isinstance(raw, str):
        raise ConfigurationError(f"config array {field.name} must contain only strings")
    return _parse_repeated_item(field, raw)


def _parse_config_mapping(
    field: FieldSpec, raw: dict[object, object]
) -> tuple[tuple[str, ScalarValue], ...]:
    result: list[tuple[str, ScalarValue]] = []
    keys: set[str] = set()
    for raw_key in sorted(raw, key=str):
        if not isinstance(raw_key, str) or not raw_key.strip():
            raise ConfigurationError(
                f"config table {field.name} keys must be non-empty strings"
            )
        key = raw_key.strip()
        if key in keys:
            raise ConfigurationError(
                f"config table {field.name} has a duplicate normalized key"
            )
        keys.add(key)
        raw_value = raw[raw_key]
        value: ScalarValue
        if field.kind is ValueKind.INTEGER_MAP:
            if isinstance(raw_value, bool) or not isinstance(raw_value, int):
                raise ConfigurationError(
                    f"config table {field.name} values must be integers"
                )
            _check_range(field, float(raw_value))
            value = raw_value
        elif field.kind is ValueKind.ENUM_MAP:
            if not isinstance(raw_value, str):
                raise ConfigurationError(
                    f"config table {field.name} values must be strings"
                )
            value = _parse_enum(raw_value, field)
        elif field.kind is ValueKind.CIDR_MAP:
            if not isinstance(raw_value, str):
                raise ConfigurationError(
                    f"config table {field.name} values must be strings"
                )
            value = _parse_cidr(raw_value, field.flag)
        else:
            if not isinstance(raw_value, str):
                raise ConfigurationError(
                    f"config table {field.name} values must be strings"
                )
            value = _non_empty(raw_value, f"config field {field.name}")
        result.append((key, value))
    return tuple(result)


def _parse_value(field: FieldSpec, raw: object) -> OptionValue:
    if field.kind is ValueKind.BOOLEAN:
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str) and raw in {"true", "false"}:
            return raw == "true"
        raise ConfigurationError(f"{field.flag} must be true or false")

    if field.repeatable:
        if not isinstance(raw, list):
            raise ConfigurationError(f"{field.flag} must be supplied as CLI values")
        if field.kind in {
            ValueKind.STRING_MAP,
            ValueKind.INTEGER_MAP,
            ValueKind.ENUM_MAP,
            ValueKind.CIDR_MAP,
        }:
            return _parse_mapping(field, raw)
        return tuple(_parse_repeated_item(field, item) for item in raw)

    if not isinstance(raw, str):
        raise ConfigurationError(f"{field.flag} has an invalid value type")
    return _parse_scalar(field, raw)


def _parse_repeated_item(field: FieldSpec, raw: object) -> str:
    if not isinstance(raw, str):
        raise ConfigurationError(f"{field.flag} has an invalid repeated value")
    if field.kind is ValueKind.STRING_LIST:
        return _non_empty(raw, field.flag)
    if field.kind is ValueKind.ENUM_LIST:
        return _parse_enum(raw, field)
    if field.kind is ValueKind.CIDR:
        return _parse_cidr(raw, field.flag)
    raise ConfigurationError(f"{field.flag} has an unsupported repeated encoding")


def _parse_scalar(field: FieldSpec, raw: str) -> ScalarValue:
    if field.kind is ValueKind.STRING:
        return _non_empty(raw, field.flag)
    if field.kind is ValueKind.ENUM:
        return _parse_enum(raw, field)
    if field.kind is ValueKind.INTEGER:
        return _parse_integer(raw, field)
    if field.kind is ValueKind.FLOAT:
        return _parse_float(raw, field)
    if field.kind is ValueKind.PATH:
        return _parse_absolute_path(raw, field.flag)
    if field.kind is ValueKind.UUID:
        return _parse_uuid(raw, field.flag)
    if field.kind is ValueKind.CIDR:
        return _parse_cidr(raw, field.flag)
    raise ConfigurationError(f"{field.flag} has an unsupported scalar encoding")


def _parse_enum(raw: str, field: FieldSpec) -> str:
    value = _non_empty(raw, field.flag).lower()
    if not value.isascii() or value not in field.choices:
        choices = ", ".join(field.choices)
        raise ConfigurationError(f"{field.flag} must be one of: {choices}")
    return value


def _parse_integer(raw: str, field: FieldSpec) -> int:
    value = _non_empty(raw, field.flag)
    if not value.isascii() or not _CANONICAL_INTEGER.fullmatch(value):
        raise ConfigurationError(f"{field.flag} must be a canonical base-10 integer")
    parsed = int(value)
    _check_range(field, float(parsed))
    return parsed


def _parse_float(raw: str, field: FieldSpec) -> float:
    value = _non_empty(raw, field.flag)
    if not value.isascii() or not _CANONICAL_FLOAT.fullmatch(value):
        raise ConfigurationError(f"{field.flag} must be a finite decimal number")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ConfigurationError(f"{field.flag} must be finite")
    _check_range(field, parsed)
    return parsed


def _check_range(field: FieldSpec, value: float) -> None:
    if field.minimum is not None and value < field.minimum:
        raise ConfigurationError(f"{field.flag} must be at least {field.minimum:g}")
    if field.maximum is not None and value > field.maximum:
        raise ConfigurationError(f"{field.flag} must be at most {field.maximum:g}")


def _parse_absolute_path(raw: str, flag: str) -> Path:
    value = _non_empty(raw, flag)
    path = Path(value)
    if value.startswith("~"):
        try:
            path = path.expanduser()
        except RuntimeError as error:
            raise ConfigurationError(f"{flag} has an unknown user") from error
    if not path.is_absolute():
        raise ConfigurationError(
            f"{flag} must be absolute or start with a resolvable '~'"
        )
    return path


def _parse_uuid(raw: str, flag: str) -> str:
    value = _non_empty(raw, flag).lower()
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise ConfigurationError(f"{flag} must be a UUID") from error
    canonical = str(parsed)
    if value != canonical:
        raise ConfigurationError(f"{flag} must use canonical UUID spelling")
    return canonical


def _parse_cidr(raw: str, flag: str) -> str:
    value = _non_empty(raw, flag)
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise ConfigurationError(f"{flag} must be a canonical CIDR") from error
    canonical = str(network)
    if value.lower() != canonical:
        raise ConfigurationError(f"{flag} must use canonical CIDR spelling")
    return canonical


def _parse_mapping(
    field: FieldSpec, raw_values: list[object]
) -> tuple[tuple[str, ScalarValue], ...]:
    result: list[tuple[str, ScalarValue]] = []
    keys: set[str] = set()
    for raw in raw_values:
        if not isinstance(raw, str) or raw.count("=") != 1:
            raise ConfigurationError(f"{field.flag} must use KEY=VALUE")
        raw_key, raw_value = raw.split("=", 1)
        key = _non_empty(raw_key, field.flag)
        if key in keys:
            raise ConfigurationError(f"{field.flag} has duplicate key: {key}")
        keys.add(key)
        scalar: ScalarValue
        if field.kind is ValueKind.INTEGER_MAP:
            scalar = _parse_integer(
                raw_value,
                FieldSpec(
                    field.name,
                    ValueKind.INTEGER,
                    minimum=field.minimum,
                    maximum=field.maximum,
                ),
            )
        elif field.kind is ValueKind.ENUM_MAP:
            scalar = _parse_enum(
                raw_value,
                FieldSpec(field.name, ValueKind.ENUM, choices=field.choices),
            )
        elif field.kind is ValueKind.CIDR_MAP:
            scalar = _parse_cidr(raw_value, field.flag)
        else:
            scalar = _non_empty(raw_value, field.flag)
        result.append((key, scalar))
    return tuple(result)


def _required_string(option: ResolvedOption) -> str:
    if not isinstance(option.value, str):
        raise ConfigurationError(f"required setting is missing: {option.name}")
    return option.value


def _non_empty(value: str, label: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ConfigurationError(f"{label} must not be empty")
    return normalized


def _validate_application_environment(
    environ: Mapping[str, str], fields: tuple[FieldSpec, ...]
) -> None:
    known_application_names = set(NON_SECRET_ENVIRONMENT_FIELDS) | {
        name for name in SECRET_ENVIRONMENT_NAMES if name.startswith(_PREFIX)
    }
    unknown = sorted(
        name
        for name in environ
        if name.startswith(_PREFIX) and name not in known_application_names
    )
    if unknown:
        raise ConfigurationError(
            "unknown deploy-scylla-vms environment variable(s): " + ", ".join(unknown)
        )

    accepted = {field.environment for field in fields if field.environment is not None}
    forbidden = sorted(
        name
        for name in environ
        if name in NON_SECRET_ENVIRONMENT_FIELDS and name not in accepted
    )
    if forbidden:
        raise ConfigurationError(
            "environment variable(s) are not accepted by this operation: "
            + ", ".join(forbidden)
        )


@dataclass(frozen=True, slots=True)
class ResolvedCommonConfig:
    """Backward-compatible common boundary used by focused state tests."""

    provider: ProviderDefinition
    cluster_name: str
    state_root: Path
    paths: StatePaths
    provider_source: ValueSource
    cluster_name_source: ValueSource
    state_root_source: ValueSource


def resolve_common_config(
    *,
    cli_provider: str | None,
    cli_cluster_name: str | None,
    cli_state_dir: str | None,
    environ: Mapping[str, str] | None = None,
    default_state_root: Callable[[], Path] | None = None,
) -> ResolvedCommonConfig:
    """Resolve only the original three common settings without state writes."""

    source_environment = os.environ if environ is None else environ
    _validate_application_environment(source_environment, fields_for_operation("show"))
    provider_raw, provider_source = _resolve_common_string(
        cli_provider,
        source_environment,
        "DEPLOY_SCYLLA_VMS_CLOUD_PROVIDER",
        "oci",
    )
    provider_name = provider_raw.lower()
    try:
        provider = get_provider(provider_name)
    except KeyError as error:
        raise ConfigurationError(
            f"unsupported cloud provider: {provider_name}"
        ) from error
    cluster_raw, cluster_source = _resolve_common_string(
        cli_cluster_name,
        source_environment,
        "DEPLOY_SCYLLA_VMS_CLUSTER_NAME",
        None,
    )
    cluster_name = validate_cluster_name(cluster_raw)
    if cli_state_dir is not None:
        state_raw = cli_state_dir
        state_source = ValueSource.CLI
    elif "DEPLOY_SCYLLA_VMS_STATE_DIR" in source_environment:
        state_raw = source_environment["DEPLOY_SCYLLA_VMS_STATE_DIR"]
        state_source = ValueSource.ENVIRONMENT
    else:
        factory = default_state_root or (
            lambda: user_state_path("deploy-scylla-vms", appauthor=False)
        )
        state_raw = str(factory())
        state_source = ValueSource.DEFAULT
    state_root = resolve_state_root(_non_empty(state_raw, "state directory"))
    return ResolvedCommonConfig(
        provider,
        cluster_name,
        state_root,
        StatePaths.derive(state_root, cluster_name),
        provider_source,
        cluster_source,
        state_source,
    )


def _resolve_common_string(
    cli: str | None,
    environ: Mapping[str, str],
    environment_name: str,
    default: str | None,
) -> tuple[str, ValueSource]:
    if cli is not None:
        return _non_empty(cli, "CLI option"), ValueSource.CLI
    if environment_name in environ:
        return (
            _non_empty(environ[environment_name], environment_name),
            ValueSource.ENVIRONMENT,
        )
    if default is not None:
        return default, ValueSource.DEFAULT
    raise ConfigurationError(
        f"required setting is missing: {environment_name} or its CLI option"
    )
