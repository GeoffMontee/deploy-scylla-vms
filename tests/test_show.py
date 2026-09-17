import json
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import pytest

from scylla_vms.cli import main
from scylla_vms.desired import (
    AttachmentType,
    BlockVolumePolicy,
    ClusterSpec,
    HostRole,
    ImageFilter,
    ImageVersionMatch,
    NetworkMode,
    NetworkPolicy,
    ServiceSpec,
    StorageBackend,
    StorageLayout,
    StoragePolicy,
    TopologyLabel,
    VolumeRetention,
    ZoneSpec,
)
from scylla_vms.errors import ExitCode
from scylla_vms.journal import OperationJournalStore, OperationRecord
from scylla_vms.locking import ClusterLock
from scylla_vms.models import ValueSource
from scylla_vms.persistence import (
    ClusterMetadata,
    ClusterMetadataStore,
    digest_bytes,
    serialize_json,
)
from scylla_vms.show import SHOW_SCHEMA_VERSION, SHOW_SECTIONS
from scylla_vms.state import StatePaths, initialize_state_layout

ROOT = Path(__file__).resolve().parents[1]
ENTRY_POINT = ROOT / "deploy_scylla_vms.py"
CLUSTER_UUID = uuid.UUID("11111111-1111-4111-8111-111111111111")
GENERATED_AT = datetime(2026, 9, 17, 15, 0, tzinfo=UTC)
PRIVATE_PATH = "/fixture/do-not-render/id_private"
CUSTOMER_KEY_ID = "ocid1.key.oc1..do-not-render-key-id"


def _block(size: int, *, key_id: str | None = None) -> BlockVolumePolicy:
    return BlockVolumePolicy(
        1,
        size,
        10,
        AttachmentType.PARAVIRTUALIZED,
        VolumeRetention.RETAIN,
        key_id,
        True,
    )


def _spec() -> ClusterSpec:
    return ClusterSpec(
        CLUSTER_UUID,
        "example",
        "oci",
        "us-ashburn-1",
        "ocid1.compartment.oc1..showfixture",
        TopologyLabel("show-dc", "explicit"),
        "VM.Standard.E5.Flex",
        (
            ZoneSpec(
                "AD-1",
                1,
                TopologyLabel("rack-a", "explicit"),
                ("scylla-ad-1-1",),
            ),
            ZoneSpec(
                "AD-2",
                1,
                TopologyLabel("rack-b", "explicit"),
                ("scylla-ad-2-1",),
            ),
        ),
        (
            ServiceSpec(
                HostRole.MANAGER,
                1,
                ("AD-1",),
                "VM.Standard.E5.Flex",
                ("manager-1",),
            ),
            ServiceSpec(
                HostRole.MONITORING,
                1,
                ("AD-2",),
                "VM.Standard.E5.Flex",
                ("monitoring-1",),
            ),
            ServiceSpec(
                HostRole.JUMP_HOST,
                1,
                ("AD-1",),
                "VM.Standard.E5.Flex",
                ("jump-host-1",),
            ),
        ),
        NetworkPolicy(
            NetworkMode.EXISTING,
            "ocid1.vcn.oc1..showfixture",
            (
                (HostRole.JUMP_HOST, "ocid1.subnet.oc1..jumpfixture"),
                (HostRole.MANAGER, "ocid1.subnet.oc1..managerfixture"),
                (HostRole.MONITORING, "ocid1.subnet.oc1..monitoringfixture"),
                (HostRole.SCYLLA, "ocid1.subnet.oc1..scyllafixture"),
            ),
            ("198.51.100.0/24",),
            "opc",
            Path(PRIVATE_PATH),
        ),
        (
            StoragePolicy(
                HostRole.SCYLLA,
                StorageBackend.BLOCK_VOLUME,
                StorageLayout.SINGLE,
                None,
                None,
                _block(100, key_id=CUSTOMER_KEY_ID),
            ),
            StoragePolicy(
                HostRole.MANAGER,
                StorageBackend.BLOCK_VOLUME,
                StorageLayout.SINGLE,
                None,
                None,
                _block(50),
            ),
            StoragePolicy(
                HostRole.MONITORING,
                StorageBackend.BLOCK_VOLUME,
                StorageLayout.SINGLE,
                None,
                None,
                _block(75),
            ),
            StoragePolicy(
                HostRole.JUMP_HOST,
                StorageBackend.BOOT_ONLY,
                None,
                None,
                None,
                None,
            ),
        ),
        (
            ("cluster_name", ValueSource.CLI),
            ("oci_region", ValueSource.CONFIG),
            ("scylla_instance_type", ValueSource.ENVIRONMENT),
        ),
        tuple(
            (role, ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT))
            for role in (
                HostRole.JUMP_HOST,
                HostRole.MANAGER,
                HostRole.MONITORING,
                HostRole.SCYLLA,
            )
        ),
    )


def _create_state(tmp_path: Path) -> StatePaths:
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    paths = StatePaths.derive(tmp_path / "state", "example")
    initialize_state_layout(paths)
    metadata = ClusterMetadata.create(
        cluster_uuid=CLUSTER_UUID,
        cluster_name="example",
        provider="oci",
        request_digest=digest_bytes(b"sanitized show fixture"),
        desired_spec=_spec(),
        clock=lambda: datetime(2026, 9, 17, 14, 0, tzinfo=UTC),
    )
    ClusterMetadataStore(paths).write(
        metadata, expected_generation=0, expected_digest=None
    )
    return paths


def _arguments(paths: StatePaths, *operation_arguments: str) -> list[str]:
    return [
        "--cluster-name",
        "example",
        "--state-dir",
        str(paths.state_root),
        *(("--json",) if "--human" not in operation_arguments else ()),
        "show",
        *(item for item in operation_arguments if item != "--human"),
    ]


def _run(
    paths: StatePaths,
    *operation_arguments: str,
    environ: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    result = main(
        _arguments(paths, *operation_arguments),
        environ={} if environ is None else environ,
        stdout=stdout,
        stderr=stderr,
        clock=lambda: GENERATED_AT,
    )
    return result, stdout.getvalue(), stderr.getvalue()


def _snapshot(root: Path) -> tuple[tuple[str, ...], dict[str, bytes]]:
    directories: list[str] = []
    files: dict[str, bytes] = {}
    for current, names, filenames in os.walk(root):
        relative = Path(current).relative_to(root)
        directories.extend(str(relative / name) for name in sorted(names))
        for filename in sorted(filenames):
            path = Path(current) / filename
            files[str(path.relative_to(root))] = path.read_bytes()
    return tuple(directories), files


def test_show_human_renders_local_desired_state_without_credentials(
    tmp_path: Path,
) -> None:
    paths = _create_state(tmp_path)
    before = _snapshot(paths.state_root)

    result, stdout, stderr = _run(paths, "--human")

    assert result == ExitCode.SUCCESS
    assert stderr == ""
    assert f"Cluster report ({SHOW_SCHEMA_VERSION})" in stdout
    assert "Cluster: example (11111111-1111-4111-8111-111111111111)" in stdout
    assert "scylla-ad-1-1" in stdout
    assert "Terraform-observed state is unavailable" in stdout
    assert "scylla_ring: unknown" in stdout
    assert _snapshot(paths.state_root) == before


def test_show_json_has_exact_envelope_ordering_and_redaction(tmp_path: Path) -> None:
    paths = _create_state(tmp_path)
    secret = "not-a-real-manager-token"

    first_result, first_stdout, first_stderr = _run(
        paths,
        environ={"DEPLOY_SCYLLA_VMS_MANAGER_AUTH_TOKEN": secret},
    )
    second_result, second_stdout, second_stderr = _run(paths)

    assert first_result == second_result == ExitCode.SUCCESS
    assert first_stderr == second_stderr == ""
    assert first_stdout == second_stdout
    report = json.loads(first_stdout)
    assert set(report) == {
        "cluster",
        "exit_status",
        "findings",
        "generated_at",
        "schema_version",
        "sections",
        "selected_sections",
        "sources",
    }
    assert report["schema_version"] == SHOW_SCHEMA_VERSION
    assert set(report["cluster"]) == {
        "created_at",
        "desired_spec_digest",
        "generation",
        "metadata_digest",
        "metadata_schema_version",
        "name",
        "provider",
        "provenance",
        "updated_at",
        "uuid",
    }
    assert report["selected_sections"] == list(SHOW_SECTIONS)
    assert list(report["sections"]) == sorted(report["sections"])
    assert report["sections"]["hosts"]["addresses"] == {
        "items": [],
        "requested": False,
        "status": "unavailable",
    }
    assert report["sections"]["drift"]["status"] == "unknown"
    assert report["sections"]["readiness"]["trust"]["status"] == "incomplete"
    assert report["sections"]["readiness"]["route"]["status"] == "unknown"
    assert report["sections"]["readiness"]["fingerprints"] == []
    assert report["sources"]["metadata"]["status"] == "fresh"
    assert report["sources"]["provider"]["status"] == "not-performed"
    assert report["sources"]["terraform"]["status"] == "unavailable"
    assert report["sources"]["ssh_trust"]["status"] == "unavailable"
    assert report["exit_status"]["code"] == 0
    assert len(report["sections"]["hosts"]["items"]) == 5
    assert report["sections"]["summary"]["network"]["mode"] == "existing"
    assert report["sections"]["summary"]["network"]["ssh_public_key_configured"] is True
    assert report["sections"]["summary"]["desired_provenance"] == {
        "cluster_name": "cli",
        "oci_region": "config",
        "scylla_instance_type": "environment",
    }
    for forbidden in (secret, PRIVATE_PATH, CUSTOMER_KEY_ID, "PRIVATE KEY"):
        assert forbidden not in first_stdout
    assert (
        report["sections"]["storage"]["policies"][0]["block_volume"][
            "customer_key_configured"
        ]
        is True
    )


def test_show_sections_and_stable_node_filter_apply_after_validation(
    tmp_path: Path,
) -> None:
    paths = _create_state(tmp_path)

    result, stdout, stderr = _run(
        paths,
        "--section",
        "hosts",
        "--node-id",
        "scylla-ad-2-1",
    )

    assert result == ExitCode.SUCCESS
    assert stderr == ""
    report = json.loads(stdout)
    assert report["selected_sections"] == ["hosts"]
    assert set(report["sections"]) == {"hosts"}
    assert [item["logical_id"] for item in report["sections"]["hosts"]["items"]] == [
        "scylla-ad-2-1"
    ]

    result, stdout, stderr = _run(paths, "--node-id", "unknown-node")
    assert result == ExitCode.CONFIGURATION
    assert stdout == ""
    assert "unknown --node-id: unknown-node" in stderr


def test_show_include_addresses_never_manufactures_unavailable_values(
    tmp_path: Path,
) -> None:
    paths = _create_state(tmp_path)

    result, stdout, stderr = _run(paths, "--include-addresses")

    assert result == ExitCode.SUCCESS
    assert stderr == ""
    addresses = json.loads(stdout)["sections"]["hosts"]["addresses"]
    assert addresses == {"items": [], "requested": True, "status": "unavailable"}


@pytest.mark.parametrize("live_source", ["provider", "connectivity", "health", "all"])
def test_show_live_sources_are_explicitly_unimplemented_without_authentication(
    tmp_path: Path, live_source: str
) -> None:
    paths = StatePaths.derive(tmp_path / "missing", "example")

    result, stdout, stderr = _run(paths, "--live", live_source)

    assert result == ExitCode.UNSAFE_REFUSAL
    assert stdout == ""
    assert f"show live source(s) are not implemented: {live_source}" in stderr
    assert not paths.state_root.exists()


def test_show_fail_on_evaluates_only_rendered_local_findings(tmp_path: Path) -> None:
    paths = _create_state(tmp_path)

    result, stdout, stderr = _run(paths, "--fail-on", "unknown")
    assert result == ExitCode.DRIFT_CONFLICT
    assert stderr == ""
    report = json.loads(stdout)
    assert report["exit_status"] == {
        "code": 5,
        "fail_on": ["unknown"],
        "triggered_by": ["unknown"],
    }

    result, stdout, stderr = _run(paths, "--fail-on", "none")
    assert result == ExitCode.SUCCESS
    assert stderr == ""
    assert json.loads(stdout)["exit_status"]["triggered_by"] == []

    result, stdout, stderr = _run(paths, "--fail-on", "stale")
    assert result == ExitCode.SUCCESS
    assert stderr == ""
    assert json.loads(stdout)["exit_status"]["triggered_by"] == []


def test_show_persisted_identity_assertions_conflict_without_rewriting(
    tmp_path: Path,
) -> None:
    paths = _create_state(tmp_path)
    before = paths.cluster_metadata.read_bytes()

    result, stdout, stderr = _run(
        paths,
        environ={"DEPLOY_SCYLLA_VMS_OCI_REGION": "us-phoenix-1"},
    )

    assert result == ExitCode.DRIFT_CONFLICT
    assert stdout == ""
    assert "read-only request conflicts with persisted field: oci_region" in stderr
    assert paths.cluster_metadata.read_bytes() == before


def test_show_missing_cluster_is_non_mutating_and_uses_stable_error(
    tmp_path: Path,
) -> None:
    paths = StatePaths.derive(tmp_path / "state", "example")

    result, stdout, stderr = _run(paths)

    assert result == ExitCode.UNSAFE_REFUSAL
    assert stdout == ""
    assert "required state path does not exist" in stderr
    assert not paths.state_root.exists()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", "deploy-scylla-vms.cluster/v999", "unsupported"),
        ("generation", 0, "generation must be positive"),
        ("cluster_name", "other", "identity does not match"),
    ],
)
def test_show_rejects_invalid_cluster_schema_generation_and_identity(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    paths = _create_state(tmp_path)
    document = json.loads(paths.cluster_metadata.read_text(encoding="utf-8"))
    document[field] = value
    paths.cluster_metadata.write_bytes(serialize_json(document))
    paths.cluster_metadata.chmod(0o600)

    result, stdout, stderr = _run(paths)

    assert result == ExitCode.UNSAFE_REFUSAL
    assert stdout == ""
    assert message in stderr


def test_show_rejects_corrupt_and_invalid_digest_state(tmp_path: Path) -> None:
    paths = _create_state(tmp_path)
    paths.cluster_metadata.write_text("{not-json", encoding="utf-8")
    paths.cluster_metadata.chmod(0o600)
    result, stdout, stderr = _run(paths)
    assert result == ExitCode.UNSAFE_REFUSAL
    assert stdout == ""
    assert "invalid JSON" in stderr

    paths = _create_state(tmp_path / "digest")
    document = json.loads(paths.cluster_metadata.read_text(encoding="utf-8"))
    document["provenance"]["request_digest"] = "not-a-digest"
    paths.cluster_metadata.write_bytes(serialize_json(document))
    paths.cluster_metadata.chmod(0o600)
    result, stdout, stderr = _run(paths)
    assert result == ExitCode.UNSAFE_REFUSAL
    assert stdout == ""
    assert "canonical SHA-256 digest" in stderr


def test_show_rejects_unsafe_permissions_symlinks_and_unexpected_state(
    tmp_path: Path,
) -> None:
    paths = _create_state(tmp_path / "permissions")
    paths.cluster_root.chmod(0o755)
    result, stdout, stderr = _run(paths)
    assert result == ExitCode.UNSAFE_REFUSAL
    assert stdout == ""
    assert "permissions must be 0700" in stderr

    real_paths = _create_state(tmp_path / "symlink")
    alias = tmp_path / "state-alias"
    alias.symlink_to(real_paths.state_root, target_is_directory=True)
    stderr_stream = StringIO()
    result = main(
        [
            "--cluster-name",
            "example",
            "--state-dir",
            str(alias),
            "show",
        ],
        environ={},
        stderr=stderr_stream,
    )
    assert result == ExitCode.UNSAFE_REFUSAL
    assert "symbolic link" in stderr_stream.getvalue()

    paths = _create_state(tmp_path / "unexpected")
    unexpected = paths.cluster_root / "terraform.tfstate"
    unexpected.write_text("not read", encoding="utf-8")
    unexpected.chmod(0o600)
    result, stdout, stderr = _run(paths)
    assert result == ExitCode.DRIFT_CONFLICT
    assert stdout == ""
    assert "unexpected Terraform state metadata" in stderr


def test_show_lock_contention_refuses_without_changing_owner_metadata(
    tmp_path: Path,
) -> None:
    paths = _create_state(tmp_path)
    lock = ClusterLock(paths, "deploy", 0).acquire()
    try:
        owner = paths.lock.read_bytes()
        result, stdout, stderr = _run(
            paths, environ={"DEPLOY_SCYLLA_VMS_LOCK_TIMEOUT_SECONDS": "0"}
        )
        assert result == ExitCode.LOCK_CONFLICT
        assert stdout == ""
        assert "cluster lock is held" in stderr
        assert paths.lock.read_bytes() == owner
    finally:
        lock.release()


def test_show_projects_only_validated_latest_operation_summary(tmp_path: Path) -> None:
    paths = _create_state(tmp_path)
    operation_id = uuid.UUID("22222222-2222-4222-8222-222222222222")
    record = OperationRecord.create(
        operation_id=operation_id,
        operation="deploy",
        cluster_uuid=CLUSTER_UUID,
        cluster_name="example",
        request_digest=digest_bytes(b"journal fixture"),
        clock=lambda: datetime(2026, 9, 17, 14, 30, tzinfo=UTC),
    )
    OperationJournalStore(paths, operation_id).write(
        record, expected_generation=0, expected_digest=None
    )

    conflict_result, conflict_stdout, conflict_stderr = _run(
        paths, "--section", "operations"
    )
    assert conflict_result == ExitCode.DRIFT_CONFLICT
    assert conflict_stderr == ""
    assert json.loads(conflict_stdout)["exit_status"]["triggered_by"] == ["conflict"]

    result, stdout, stderr = _run(paths, "--section", "operations", "--fail-on", "none")

    assert result == ExitCode.SUCCESS
    assert stderr == ""
    latest = json.loads(stdout)["sections"]["operations"]["latest"]
    assert latest["operation_id"] == str(operation_id)
    assert latest["status"] == "pending"
    assert "request_digest" not in latest


def test_show_refuses_structurally_invalid_optional_journal(tmp_path: Path) -> None:
    paths = _create_state(tmp_path)
    invalid = paths.operations / "not-an-operation-id.json"
    invalid.write_text("{}\n", encoding="utf-8")
    invalid.chmod(0o600)

    result, stdout, stderr = _run(paths, "--section", "summary")

    assert result == ExitCode.UNSAFE_REFUSAL
    assert stdout == ""
    assert "operation journal filename is invalid" in stderr


def test_source_script_and_installed_console_render_same_report_shape(
    tmp_path: Path,
) -> None:
    paths = _create_state(tmp_path)
    arguments = _arguments(paths, "--section", "summary")
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith("DEPLOY_SCYLLA_VMS_")
    }
    console = Path(sys.executable).with_name("deploy-scylla-vms")

    source_result = subprocess.run(
        [sys.executable, str(ENTRY_POINT), *arguments],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    console_result = subprocess.run(
        [str(console), *arguments],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert source_result.returncode == console_result.returncode == ExitCode.SUCCESS
    assert source_result.stderr == console_result.stderr == ""
    source_report = json.loads(source_result.stdout)
    console_report = json.loads(console_result.stdout)
    source_report.pop("generated_at")
    console_report.pop("generated_at")
    assert source_report == console_report
