import re
from io import StringIO
from pathlib import Path

import pytest

from scylla_vms.cli import build_parser, parse_operation_request
from scylla_vms.config import resolve_operation_request
from scylla_vms.contracts import (
    CORE_FIELDS,
    GROUP_FIELDS,
    NON_SECRET_ENVIRONMENT_FIELDS,
    OPERATION_CONTRACTS,
    fields_for_operation,
)
from scylla_vms.errors import ConfigurationError
from scylla_vms.models import DeferredValue, ValueSource
from scylla_vms.secrets import SECRET_ENVIRONMENT_NAMES

HOST_UUID = "00000000-0000-4000-8000-000000000001"
ROOT = Path(__file__).resolve().parents[1]

EXPECTED_GROUPS = {
    "deploy": (
        "mutate",
        "oci-context",
        "network",
        "images",
        "topology",
        "shapes",
        "scylla-storage",
        "service-storage",
    ),
    "add-node": ("mutate", "oci-context", "scylla-storage"),
    "replace-node": (
        "mutate",
        "destructive",
        "oci-context",
        "scylla-storage",
    ),
    "destroy-node": ("mutate", "destructive", "oci-context"),
    "destroy": ("mutate", "destructive", "oci-context"),
    "scale-out": ("mutate", "oci-context", "scylla-storage"),
    "scale-in": ("mutate", "destructive", "oci-context"),
    "redeploy": (
        "mutate",
        "destructive",
        "oci-context",
        "network",
        "service-storage",
    ),
    "refresh-monitoring": ("mutate", "oci-context"),
    "upgrade-os": ("mutate", "destructive", "oci-context"),
    "check-jump-hosts": ("oci-context",),
    "show": ("oci-context",),
}

EXPECTED_OPERATION_FIELDS = {
    "deploy": {"manager_count", "monitoring_count", "manager_zone", "monitoring_zone"},
    "add-node": {
        "scylla_instance_type",
        "node_id",
        "zone",
        "expected_rack",
        "cleanup",
        "bootstrap_timeout_seconds",
        "wipe_storage",
        "confirm_wipe_device",
    },
    "replace-node": {
        "scylla_instance_type",
        "node_id",
        "failed_host_id",
        "reason",
        "storage_source",
        "retained_volume_id",
        "old_volume_disposition",
        "wipe_storage",
        "confirm_wipe_device",
        "repair_mode",
        "replacement_timeout_seconds",
        "confirm_replace_node",
    },
    "destroy-node": {
        "node_id",
        "removal_mode",
        "failed_host_id",
        "volume_disposition",
        "decommission_timeout_seconds",
        "confirm_destroy_node",
    },
    "destroy": {
        "block_volume_disposition",
        "shared_resource_disposition",
        "state_retention",
        "diagnostic_retention",
        "confirm_destroy_cluster",
    },
    "scale-out": {
        "scylla_instance_type",
        "nodes_per_zone",
        "add_nodes_per_zone",
        "node_id",
        "max_new_nodes",
        "cleanup",
        "bootstrap_timeout_seconds",
    },
    "scale-in": {
        "nodes_per_zone",
        "remove_node",
        "selection_policy",
        "max_remove_nodes",
        "removal_mode",
        "failed_host_id",
        "volume_disposition",
        "decommission_timeout_seconds",
        "confirm_scale_in",
    },
    "redeploy": {
        "manager_instance_type",
        "monitoring_instance_type",
        "jump_host_instance_type",
        "scope",
        "target_host",
        "component",
        "infrastructure",
        "restart_policy",
        "confirm_recreate_host",
    },
    "refresh-monitoring": {
        "target",
        "source",
        "service_action",
        "stale_target_policy",
        "confirm_monitoring_restart",
        "monitoring_timeout_seconds",
    },
    "upgrade-os": {
        "strategy",
        "target_role",
        "target_host",
        "target_os_version",
        "package_channel",
        "image_id",
        "max_unavailable",
        "health_timeout_seconds",
        "reboot_timeout_seconds",
        "resume_operation",
        "confirm_reprovision_host",
    },
    "check-jump-hosts": {
        "jump_host",
        "destination",
        "depth",
        "destination_check",
        "connect_timeout_seconds",
        "check_timeout_seconds",
    },
    "show": {
        "section",
        "node_id",
        "live",
        "include_addresses",
        "fail_on",
        "live_timeout_seconds",
    },
}


def _base(tmp_path: Path, operation: str) -> list[str]:
    return [
        "--cluster-name",
        "example",
        "--state-dir",
        str(tmp_path / "state"),
        operation,
    ]


def _existing_preview(tmp_path: Path, operation: str) -> list[str]:
    return [
        *_base(tmp_path, operation),
        "--dry-run",
        "--oci-auth-mode",
        "instance-principal",
    ]


def test_operation_group_and_field_registry_matches_plan() -> None:
    assert set(OPERATION_CONTRACTS) == set(EXPECTED_GROUPS)
    core_names = {field.name for field in CORE_FIELDS}
    for operation, groups in EXPECTED_GROUPS.items():
        contract = OPERATION_CONTRACTS[operation]
        assert contract.groups == groups
        assert {field.name for field in contract.fields} == EXPECTED_OPERATION_FIELDS[
            operation
        ]
        expected = core_names | {
            field.name for group in groups for field in GROUP_FIELDS[group]
        }
        expected |= EXPECTED_OPERATION_FIELDS[operation]
        assert {field.name for field in fields_for_operation(operation)} == expected


@pytest.mark.parametrize("operation", sorted(EXPECTED_OPERATION_FIELDS))
def test_operation_help_lists_every_operation_specific_flag(operation: str) -> None:
    output = StringIO()
    parser = build_parser(stdout=output)
    with pytest.raises(SystemExit) as raised:
        parser.parse_args([operation, "--help"])

    assert raised.value.code == 0
    rendered = output.getvalue()
    normalized = " ".join(rendered.split())
    if operation == "show":
        assert "reads validated local persisted state without writing" in normalized
    elif operation == "check-jump-hosts":
        assert "performs guarded read-only Ansible checks" in normalized
    else:
        assert "exits without side effects" in normalized
    for field_name in EXPECTED_OPERATION_FIELDS[operation]:
        assert "--" + field_name.replace("_", "-") in rendered


def test_environment_registry_entries_are_unique_and_cli_compatible() -> None:
    definitions: dict[str, object] = {}
    for operation in OPERATION_CONTRACTS:
        for field in fields_for_operation(operation):
            if field.environment is None:
                continue
            previous = definitions.setdefault(field.environment, field)
            assert previous == field
            assert field.environment in NON_SECRET_ENVIRONMENT_FIELDS
            assert field.flag.startswith("--")


def test_application_environment_registry_matches_plan_document() -> None:
    plan = (ROOT / "PLAN.md").read_text(encoding="utf-8")
    documented = set(re.findall(r"`(DEPLOY_SCYLLA_VMS_[A-Z0-9_]+)`", plan))
    implemented = set(NON_SECRET_ENVIRONMENT_FIELDS) | {
        name
        for name in SECRET_ENVIRONMENT_NAMES
        if name.startswith("DEPLOY_SCYLLA_VMS_")
    }
    assert implemented == documented


@pytest.mark.parametrize(
    ("operation", "forbidden"),
    [
        ("deploy", "--allow-destructive"),
        ("add-node", "--manager-instance-type"),
        ("replace-node", "--network-mode"),
        ("destroy-node", "--scylla-instance-type"),
        ("destroy", "--zone"),
        ("scale-out", "--operator-cidr"),
        ("scale-in", "--scylla-storage-backend"),
        ("redeploy", "--scylla-instance-type"),
        ("refresh-monitoring", "--allow-destructive"),
        ("upgrade-os", "--network-mode"),
        ("check-jump-hosts", "--dry-run"),
        ("show", "--plan"),
    ],
)
def test_each_operation_rejects_an_unrelated_flag(
    tmp_path: Path, operation: str, forbidden: str
) -> None:
    parser = build_parser()
    with pytest.raises(ConfigurationError, match="unrecognized arguments"):
        parser.parse_args([*_base(tmp_path, operation), forbidden])


def test_global_flags_after_subcommand_are_rejected(tmp_path: Path) -> None:
    parser = build_parser()
    with pytest.raises(ConfigurationError, match="unrecognized arguments"):
        parser.parse_args(["show", "--cluster-name", "example"])


def test_core_environment_precedence_and_typed_defaults(tmp_path: Path) -> None:
    request = parse_operation_request(
        [
            "--cluster-name",
            "cli-cluster",
            "--state-dir",
            str(tmp_path / "state"),
            "--log-level",
            "warning",
            "show",
        ],
        environ={
            "DEPLOY_SCYLLA_VMS_CLUSTER_NAME": "env-cluster",
            "DEPLOY_SCYLLA_VMS_LOG_LEVEL": "debug",
            "DEPLOY_SCYLLA_VMS_LOCK_TIMEOUT_SECONDS": "0",
        },
    )

    assert request.cluster_name == "cli-cluster"
    assert request.option("cluster_name").source is ValueSource.CLI
    assert request.option("log_level").value == "warning"
    assert request.option("log_level").source is ValueSource.CLI
    assert request.option("lock_timeout_seconds").value == 0.0
    assert request.option("lock_timeout_seconds").source is ValueSource.ENVIRONMENT
    assert request.option("section").value == ("all",)
    assert request.option("live").value == ()
    assert request.option("oci_auth_mode").source is ValueSource.UNSET
    assert request.option("oci_region").source is ValueSource.PERSISTED
    assert not request.has_sensitive_output


def test_show_tracks_cli_only_sensitive_output_classification(tmp_path: Path) -> None:
    request = parse_operation_request(
        [*_base(tmp_path, "show"), "--include-addresses"],
        environ={},
    )
    assert request.has_sensitive_output


@pytest.mark.parametrize(
    ("environment_name", "value", "message"),
    [
        (
            "DEPLOY_SCYLLA_VMS_LOCK_TIMEOUT_SECONDS",
            "nan",
            "finite decimal",
        ),
        (
            "DEPLOY_SCYLLA_VMS_LOCK_TIMEOUT_SECONDS",
            "1e2",
            "finite decimal",
        ),
        (
            "DEPLOY_SCYLLA_VMS_SHOW_LIVE_TIMEOUT_SECONDS",
            "01",
            "canonical base-10",
        ),
        (
            "DEPLOY_SCYLLA_VMS_SHOW_LIVE_TIMEOUT_SECONDS",
            "0",
            "at least 1",
        ),
    ],
)
def test_environment_numbers_are_strict(
    tmp_path: Path, environment_name: str, value: str, message: str
) -> None:
    with pytest.raises(ConfigurationError, match=message):
        parse_operation_request(
            _base(tmp_path, "show"),
            environ={environment_name: value},
        )


def test_repeatable_map_parsing_preserves_zero_and_rejects_duplicates(
    tmp_path: Path,
) -> None:
    request = parse_operation_request(
        [
            *_existing_preview(tmp_path, "scale-out"),
            "--nodes-per-zone",
            "AD-1=0",
        ],
        environ={},
    )
    assert request.option("nodes_per_zone").value == (("AD-1", 0),)

    with pytest.raises(ConfigurationError, match="duplicate key"):
        parse_operation_request(
            [
                *_existing_preview(tmp_path, "scale-out"),
                "--add-nodes-per-zone",
                "AD-1=1",
                "--add-nodes-per-zone",
                "AD-1=2",
            ],
            environ={},
        )


@pytest.mark.parametrize(
    "arguments",
    [
        ["--dry-run", "--plan"],
        ["--add-nodes-per-zone", "AD-1=1", "--nodes-per-zone", "AD-1=2"],
    ],
)
def test_scale_out_mutual_exclusions(tmp_path: Path, arguments: list[str]) -> None:
    with pytest.raises(ConfigurationError, match=r"mutually exclusive|exactly one"):
        parse_operation_request(
            [*_existing_preview(tmp_path, "scale-out"), *arguments],
            environ={},
        )


def test_wipe_flags_are_required_together(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="required together"):
        parse_operation_request(
            [
                *_existing_preview(tmp_path, "add-node"),
                "--node-id",
                "scylla-ad1-2",
                "--zone",
                "AD-1",
                "--wipe-storage",
            ],
            environ={},
        )


def test_persisted_baseline_is_explicit_for_existing_cluster(
    tmp_path: Path,
) -> None:
    request = parse_operation_request(
        [
            *_existing_preview(tmp_path, "add-node"),
            "--node-id",
            "scylla-ad1-2",
            "--zone",
            "AD-1",
        ],
        environ={},
    )

    assert request.option("scylla_storage_backend").value is DeferredValue.PERSISTED
    assert request.option("scylla_storage_backend").source is ValueSource.PERSISTED
    assert request.option("expected_rack").value is DeferredValue.PERSISTED


def test_cli_only_destructive_authorization_has_no_environment_path(
    tmp_path: Path,
) -> None:
    with pytest.raises(ConfigurationError, match=r"unknown.*ALLOW_DESTRUCTIVE"):
        parse_operation_request(
            [
                *_existing_preview(tmp_path, "destroy-node"),
                "--node-id",
                "scylla-ad1-1",
                "--removal-mode",
                "live",
            ],
            environ={"DEPLOY_SCYLLA_VMS_ALLOW_DESTRUCTIVE": "true"},
        )


def test_show_filter_exclusions(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="section all cannot be combined"):
        parse_operation_request(
            [
                *_base(tmp_path, "show"),
                "--section",
                "all",
                "--section",
                "hosts",
            ],
            environ={},
        )
    with pytest.raises(ConfigurationError, match="fail-on none cannot be combined"):
        parse_operation_request(
            [
                *_base(tmp_path, "show"),
                "--fail-on",
                "none",
                "--fail-on",
                "drift",
            ],
            environ={},
        )


def test_config_path_loads_non_secret_defaults(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        'schema_version = "deploy-scylla-vms.config/v2"\n'
        "[cluster]\n"
        'cluster_name = "example"\n',
        encoding="utf-8",
    )
    request = parse_operation_request(
        [
            "--state-dir",
            str(tmp_path / "state"),
            "--config",
            str(config),
            "show",
        ],
        environ={},
    )
    assert request.cluster_name == "example"
    assert request.option("cluster_name").source is ValueSource.CONFIG


def test_direct_resolver_rejects_unknown_operation_environment(
    tmp_path: Path,
) -> None:
    parser = build_parser()
    arguments = vars(
        parser.parse_args(
            [
                "--cluster-name",
                "example",
                "--state-dir",
                str(tmp_path / "state"),
                "show",
            ]
        )
    )
    with pytest.raises(ConfigurationError, match="not accepted by this operation"):
        resolve_operation_request(
            arguments,
            environ={"DEPLOY_SCYLLA_VMS_TARGET_OS_VERSION": "fixture"},
        )
