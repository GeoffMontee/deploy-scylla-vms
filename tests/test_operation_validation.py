from pathlib import Path

import pytest

from scylla_vms.cli import parse_operation_request
from scylla_vms.errors import ConfigurationError
from scylla_vms.models import DeferredValue, ValueSource

HOST_UUID = "00000000-0000-4000-8000-000000000001"


def _base(tmp_path: Path, operation: str, *, preview: bool = True) -> list[str]:
    arguments = [
        "--cluster-name",
        "example",
        "--state-dir",
        str(tmp_path / "state"),
        operation,
    ]
    if preview:
        arguments.append("--dry-run")
    arguments.extend(["--oci-auth-mode", "instance-principal"])
    return arguments


def test_dead_node_removal_requires_host_uuid_and_live_forbids_it(
    tmp_path: Path,
) -> None:
    with pytest.raises(ConfigurationError, match="dead requires"):
        parse_operation_request(
            [
                *_base(tmp_path, "destroy-node"),
                "--node-id",
                "scylla-ad1-1",
                "--removal-mode",
                "dead",
            ],
            environ={},
        )
    with pytest.raises(ConfigurationError, match="live forbids"):
        parse_operation_request(
            [
                *_base(tmp_path, "destroy-node"),
                "--node-id",
                "scylla-ad1-1",
                "--removal-mode",
                "live",
                "--failed-host-id",
                HOST_UUID,
            ],
            environ={},
        )


def test_logical_node_selectors_reject_ip_addresses(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="must not be an IP address"):
        parse_operation_request(
            [
                *_base(tmp_path, "destroy-node"),
                "--node-id",
                "192.0.2.10",
                "--removal-mode",
                "live",
            ],
            environ={},
        )


def test_noninteractive_destructive_execution_needs_class_and_exact_target(
    tmp_path: Path,
) -> None:
    execution = [
        "--cluster-name",
        "example",
        "--state-dir",
        str(tmp_path / "state"),
        "--non-interactive",
        "destroy-node",
        "--oci-auth-mode",
        "instance-principal",
        "--yes",
        "--node-id",
        "scylla-ad1-1",
        "--removal-mode",
        "live",
    ]
    with pytest.raises(ConfigurationError, match="allow-destructive"):
        parse_operation_request(execution, environ={})
    with pytest.raises(ConfigurationError, match="confirm-destroy-node"):
        parse_operation_request(
            [*execution, "--allow-destructive"],
            environ={},
        )
    with pytest.raises(ConfigurationError, match="exactly match"):
        parse_operation_request(
            [
                *execution,
                "--allow-destructive",
                "--confirm-destroy-node",
                "scylla-ad1-2",
            ],
            environ={},
        )


def test_scale_in_requires_exactly_one_selector_family(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="exactly one"):
        parse_operation_request(_base(tmp_path, "scale-in"), environ={})
    with pytest.raises(ConfigurationError, match="exactly one"):
        parse_operation_request(
            [
                *_base(tmp_path, "scale-in"),
                "--nodes-per-zone",
                "AD-1=1",
                "--remove-node",
                "scylla-ad1-2",
            ],
            environ={},
        )


def test_scale_in_explicit_ids_leave_selection_policy_unset(tmp_path: Path) -> None:
    request = parse_operation_request(
        [
            *_base(tmp_path, "scale-in"),
            "--remove-node",
            "scylla-ad1-2",
        ],
        environ={},
    )
    assert request.option("selection_policy").value is None
    assert request.option("selection_policy").source is ValueSource.UNSET


def test_redeploy_scope_and_conditional_group_rules(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="requires --target-host"):
        parse_operation_request(
            [*_base(tmp_path, "redeploy"), "--scope", "host"],
            environ={},
        )
    with pytest.raises(ConfigurationError, match="requires --component"):
        parse_operation_request(
            [*_base(tmp_path, "redeploy"), "--scope", "service"],
            environ={},
        )
    with pytest.raises(ConfigurationError, match="network options require"):
        parse_operation_request(
            [
                *_base(tmp_path, "redeploy"),
                "--scope",
                "cluster",
                "--network-mode",
                "create",
            ],
            environ={},
        )

    request = parse_operation_request(
        [*_base(tmp_path, "redeploy"), "--scope", "cluster"],
        environ={},
    )
    assert request.option("component").value == ("all",)
    assert request.option("component").source is ValueSource.DEFAULT

    host_request = parse_operation_request(
        [
            *_base(tmp_path, "redeploy"),
            "--scope",
            "host",
            "--target-host",
            "manager-1",
        ],
        environ={},
    )
    assert host_request.option("component").value is DeferredValue.DERIVED


@pytest.mark.parametrize(
    ("strategy", "extra", "message"),
    [
        ("in-place", ["--image-id", "ocid1.image.oc1..fixture"], "in-place"),
        ("reprovision", ["--package-channel", "stable"], "reprovision"),
        ("auto", [], "package-channel"),
    ],
)
def test_upgrade_strategy_required_and_forbidden_inputs(
    tmp_path: Path, strategy: str, extra: list[str], message: str
) -> None:
    with pytest.raises(ConfigurationError, match=message):
        parse_operation_request(
            [
                *_base(tmp_path, "upgrade-os"),
                "--strategy",
                strategy,
                "--target-role",
                "scylla",
                "--target-os-version",
                "fixture-os-1",
                *extra,
            ],
            environ={},
        )


def test_upgrade_target_families_are_mutually_exclusive(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="exactly one"):
        parse_operation_request(
            [
                *_base(tmp_path, "upgrade-os"),
                "--target-role",
                "scylla",
                "--target-host",
                "scylla-ad1-1",
                "--target-os-version",
                "fixture-os-1",
                "--package-channel",
                "stable",
            ],
            environ={},
        )


def test_monitoring_restart_acknowledgement_is_narrow(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match=r"requires.*restart"):
        parse_operation_request(
            [
                *_base(tmp_path, "refresh-monitoring"),
                "--confirm-monitoring-restart",
            ],
            environ={},
        )


def test_check_destination_roles_and_ports_are_validated(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="unknown role"):
        parse_operation_request(
            [
                "--cluster-name",
                "example",
                "--state-dir",
                str(tmp_path / "state"),
                "check-jump-hosts",
                "--oci-auth-mode",
                "instance-principal",
                "--destination-check",
                "database=9042",
            ],
            environ={},
        )
    with pytest.raises(ConfigurationError, match="between 1 and 65535"):
        parse_operation_request(
            [
                "--cluster-name",
                "example",
                "--state-dir",
                str(tmp_path / "state"),
                "check-jump-hosts",
                "--oci-auth-mode",
                "instance-principal",
                "--destination-check",
                "scylla=65536",
            ],
            environ={},
        )
