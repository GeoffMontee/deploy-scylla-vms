import subprocess
import sys
from io import StringIO
from pathlib import Path

import pytest

from scylla_vms.cli import main
from scylla_vms.errors import ExitCode
from scylla_vms.operations import OPERATIONS

ROOT = Path(__file__).resolve().parents[1]
ENTRY_POINT = ROOT / "deploy_scylla_vms.py"
HOST_UUID = "00000000-0000-4000-8000-000000000001"


def _run_entry_point(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ENTRY_POINT), *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def _valid_operation_arguments(
    operation: str, tmp_path: Path, public_key: Path
) -> list[str]:
    common = [
        "--cluster-name",
        "example",
        "--state-dir",
        str(tmp_path / "state"),
    ]
    auth_preview = ["--dry-run", "--oci-auth-mode", "instance-principal"]
    operation_arguments: dict[str, list[str]] = {
        "deploy": [
            *auth_preview,
            "--oci-region",
            "us-ashburn-1",
            "--oci-compartment-id",
            "ocid1.compartment.oc1..example",
            "--scylla-image-operating-system",
            "Ubuntu",
            "--scylla-image-operating-system-version",
            "24.04",
            "--manager-image-operating-system",
            "Ubuntu",
            "--manager-image-operating-system-version",
            "24.04",
            "--monitoring-image-operating-system",
            "Ubuntu",
            "--monitoring-image-operating-system-version",
            "24.04",
            "--zone",
            "AD-1",
            "--nodes-per-zone",
            "AD-1=1",
            "--oci-vcn-cidr",
            "10.0.0.0/16",
            "--oci-private-subnet-cidr",
            "AD-1=10.0.1.0/24",
            "--scylla-instance-type",
            "VM.Standard.E5.Flex",
            "--manager-instance-type",
            "VM.Standard.E5.Flex",
            "--monitoring-instance-type",
            "VM.Standard.E5.Flex",
            "--ssh-public-key-path",
            str(public_key),
            "--scylla-storage-backend",
            "block-volume",
            "--scylla-block-volume-count",
            "1",
            "--scylla-block-volume-size-gib",
            "100",
            "--scylla-block-volume-vpus-per-gb",
            "10",
            "--scylla-block-volume-attachment-type",
            "paravirtualized",
            "--scylla-block-volume-retention",
            "delete",
            "--manager-data-volume-size-gib",
            "50",
            "--manager-data-volume-vpus-per-gb",
            "10",
            "--manager-data-volume-attachment-type",
            "paravirtualized",
            "--monitoring-data-volume-size-gib",
            "50",
            "--monitoring-data-volume-vpus-per-gb",
            "10",
            "--monitoring-data-volume-attachment-type",
            "paravirtualized",
        ],
        "add-node": [
            *auth_preview,
            "--node-id",
            "scylla-ad1-2",
            "--zone",
            "AD-1",
        ],
        "replace-node": [
            *auth_preview,
            "--node-id",
            "scylla-ad1-1",
            "--failed-host-id",
            HOST_UUID,
            "--reason",
            "fixture replacement",
        ],
        "destroy-node": [
            *auth_preview,
            "--node-id",
            "scylla-ad1-1",
            "--removal-mode",
            "live",
        ],
        "destroy": auth_preview,
        "scale-out": [
            *auth_preview,
            "--add-nodes-per-zone",
            "AD-1=1",
        ],
        "scale-in": [
            *auth_preview,
            "--remove-node",
            "scylla-ad1-2",
        ],
        "redeploy": [
            *auth_preview,
            "--scope",
            "cluster",
        ],
        "refresh-monitoring": auth_preview,
        "upgrade-os": [
            *auth_preview,
            "--strategy",
            "in-place",
            "--target-role",
            "scylla",
            "--target-os-version",
            "fixture-os-1",
            "--package-channel",
            "fixture-stable",
        ],
        "check-jump-hosts": [
            "--oci-auth-mode",
            "instance-principal",
        ],
        "show": [],
    }
    return [*common, operation, *operation_arguments[operation]]


def test_root_help_is_truthful_and_lists_every_operation() -> None:
    result = _run_entry_point("--help")

    assert result.returncode == ExitCode.SUCCESS
    normalized_output = " ".join(result.stdout.split())
    assert "Show and guarded jump-host checks are implemented" in normalized_output
    assert "all mutating workflows remain disabled" in normalized_output
    for operation in OPERATIONS:
        assert operation.name in result.stdout
    assert result.stderr == ""


def test_version_comes_from_package_metadata_constant() -> None:
    result = _run_entry_point("--version")

    assert result.returncode == ExitCode.SUCCESS
    assert result.stdout == "deploy-scylla-vms 26.9.1\n"
    assert result.stderr == ""


@pytest.mark.parametrize(
    "operation", [item.name for item in OPERATIONS if not item.implemented]
)
def test_every_valid_operation_request_refuses_execution_without_writes(
    tmp_path: Path,
    operation: str,
) -> None:
    public_key = tmp_path / "id_fixture.pub"
    public_key.write_text("ssh-ed25519 AAAAfixture", encoding="utf-8")
    state_root = tmp_path / "state"
    stdout = StringIO()
    stderr = StringIO()

    result = main(
        _valid_operation_arguments(operation, tmp_path, public_key),
        environ={},
        stdout=stdout,
        stderr=stderr,
    )

    assert result == ExitCode.UNSAFE_REFUSAL
    assert stdout.getvalue() == ""
    assert "request is valid but its workflow is not implemented" in stderr.getvalue()
    assert "no state or infrastructure changes were made" in stderr.getvalue()
    assert not state_root.exists()


def test_unsupported_cli_provider_has_stable_configuration_exit(
    tmp_path: Path,
) -> None:
    stderr = StringIO()

    result = main(
        [
            "--cloud-provider",
            "aws",
            "--cluster-name",
            "example",
            "--state-dir",
            str(tmp_path / "state"),
            "show",
        ],
        environ={},
        stderr=stderr,
    )

    assert result == ExitCode.CONFIGURATION
    assert "invalid choice" in stderr.getvalue()


def test_operation_allowlist_rejects_unrelated_flag(tmp_path: Path) -> None:
    stderr = StringIO()

    result = main(
        [
            "--cluster-name",
            "example",
            "--state-dir",
            str(tmp_path / "state"),
            "show",
            "--zone",
            "AD-1",
        ],
        environ={},
        stderr=stderr,
    )

    assert result == ExitCode.CONFIGURATION
    assert "unrecognized arguments: --zone AD-1" in stderr.getvalue()


def test_unknown_secret_environment_value_is_not_echoed(tmp_path: Path) -> None:
    secret = "not-a-real-token-value"
    stderr = StringIO()

    result = main(
        [
            "--cluster-name",
            "example",
            "--state-dir",
            str(tmp_path / "state"),
            "show",
        ],
        environ={"DEPLOY_SCYLLA_VMS_UNKNOWN_TOKEN": secret},
        stderr=stderr,
    )

    assert result == ExitCode.CONFIGURATION
    assert secret not in stderr.getvalue()
    assert "DEPLOY_SCYLLA_VMS_UNKNOWN_TOKEN" in stderr.getvalue()


def test_forbidden_secret_cli_value_is_not_echoed(tmp_path: Path) -> None:
    secret = "not-a-real-private-key"
    stderr = StringIO()

    result = main(
        [
            "--cluster-name",
            "example",
            "--state-dir",
            str(tmp_path / "state"),
            "show",
            "--ssh-private-key",
            secret,
        ],
        environ={},
        stderr=stderr,
    )

    assert result == ExitCode.CONFIGURATION
    assert secret not in stderr.getvalue()
    assert "--ssh-private-key [REDACTED]" in stderr.getvalue()
