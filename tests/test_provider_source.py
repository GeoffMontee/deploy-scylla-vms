import base64
import os
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scylla_vms.desired import (
    AttachmentType,
    BlockVolumePolicy,
    ChangeDisposition,
    ClusterSpec,
    HostRole,
    ImageFilter,
    ImageVersionMatch,
    NetworkMode,
    NetworkPolicy,
    ProposedChange,
    ServiceSpec,
    StorageBackend,
    StorageLayout,
    StoragePolicy,
    TopologyLabel,
    VolumeRetention,
    ZoneSpec,
)
from scylla_vms.errors import (
    ConfigurationError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    TerraformError,
    UnsafePathError,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.models import ValueSource
from scylla_vms.oci import (
    OciCapabilities,
    OciImageCandidate,
    OciSelectedImage,
    OciShapeCapability,
    OciTerraformInput,
)
from scylla_vms.providers import get_provider_adapter, provider_names
from scylla_vms.ssh_public import (
    MAXIMUM_PUBLIC_KEY_BYTES,
    read_public_ssh_key,
    validate_public_ssh_key_text,
)
from scylla_vms.state import StatePaths, initialize_state_layout
from scylla_vms.terraform.commands import TerraformCommandBuilder
from scylla_vms.terraform.inputs import (
    TerraformInputRecord,
    TerraformInputStore,
)
from scylla_vms.terraform.source import (
    ApprovedSourceBundle,
    TerraformSourceStager,
    TerraformSourceStore,
)

CLUSTER_UUID = uuid.UUID("22222222-2222-4222-8222-222222222222")
NOW = datetime(2026, 9, 17, 17, 0, tzinfo=UTC)


def _public_key() -> str:
    algorithm = b"ssh-ed25519"
    key = b"\0" * 32
    blob = (
        len(algorithm).to_bytes(4, "big")
        + algorithm
        + len(key).to_bytes(4, "big")
        + key
    )
    return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " fake@example"


def _block(size: int) -> BlockVolumePolicy:
    return BlockVolumePolicy(
        1,
        size,
        10,
        AttachmentType.PARAVIRTUALIZED,
        VolumeRetention.RETAIN,
        None,
        True,
    )


def _spec(tmp_path: Path) -> ClusterSpec:
    key_path = tmp_path / "bootstrap.pub"
    key_path.write_text(_public_key() + "\n", encoding="utf-8")
    key_path.chmod(0o600)
    return ClusterSpec(
        CLUSTER_UUID,
        "example",
        "oci",
        "us-ashburn-1",
        "ocid1.compartment.oc1..fake",
        TopologyLabel("example-dc", "explicit"),
        "VM.Standard.E5.Flex",
        (
            ZoneSpec(
                "AD-1",
                1,
                TopologyLabel("rack-a", "explicit"),
                ("scylla-ad-1-1",),
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
                ("AD-1",),
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
            "ocid1.vcn.oc1..fake",
            (
                (HostRole.JUMP_HOST, "ocid1.subnet.oc1..jump"),
                (HostRole.MANAGER, "ocid1.subnet.oc1..manager"),
                (HostRole.MONITORING, "ocid1.subnet.oc1..monitoring"),
                (HostRole.SCYLLA, "ocid1.subnet.oc1..scylla"),
            ),
            ("198.51.100.0/24",),
            "opc",
            key_path,
        ),
        (
            StoragePolicy(
                HostRole.SCYLLA,
                StorageBackend.AUTO,
                StorageLayout.SINGLE,
                1,
                400,
                _block(500),
            ),
            StoragePolicy(
                HostRole.MANAGER,
                StorageBackend.BLOCK_VOLUME,
                StorageLayout.SINGLE,
                None,
                None,
                _block(100),
            ),
            StoragePolicy(
                HostRole.MONITORING,
                StorageBackend.BLOCK_VOLUME,
                StorageLayout.SINGLE,
                None,
                None,
                _block(200),
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
        (("cluster_name", ValueSource.CLI),),
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


def _capabilities(*, local_count: int = 2, local_gib: int = 1000) -> OciCapabilities:
    return OciCapabilities(
        "us-ashburn-1",
        ("AD-1",),
        (
            OciShapeCapability(
                "VM.Standard.E5.Flex",
                "amd64",
                ("AD-1",),
                local_count,
                local_gib,
            ),
        ),
        (
            OciImageCandidate(
                "ocid1.image.oc1.iad.fakeimage",
                "Canonical-Ubuntu-24.04-2026.09.01-0",
                "2026-09-01T00:00:00Z",
                "Ubuntu",
                "24.04",
                "amd64",
                ("VM.Standard.E5.Flex",),
                "AVAILABLE",
            ),
        ),
    )


def _input(tmp_path: Path) -> OciTerraformInput:
    spec = _spec(tmp_path)
    value = get_provider_adapter("oci").build_terraform_input(
        spec,
        _capabilities(),
        public_ssh_key=read_public_ssh_key(spec.network.ssh_public_key_path),
    )
    assert isinstance(value, OciTerraformInput)
    return value


def _paths(tmp_path: Path) -> StatePaths:
    paths = StatePaths.derive(tmp_path / "state", "example")
    initialize_state_layout(paths)
    return paths


def _bundle(version: str = "oci-root/v1") -> ApprovedSourceBundle:
    return ApprovedSourceBundle.build(
        version=version,
        planning_ready=False,
        files={
            "versions.tf": (
                b'terraform {\n  required_version = ">= 1.5.0, < 2.0.0"\n}\n'
            ),
            "variables.tf": (
                b'variable "deploy_scylla_vms_input" {\n  type = any\n}\n\n'
                b'variable "deploy_scylla_vms_metadata" {\n  type = any\n}\n'
            ),
        },
    )


def test_provider_registry_has_only_real_oci_adapter() -> None:
    assert provider_names() == ("oci",)
    assert get_provider_adapter("oci").name == "oci"
    for unsupported in ("aws", "gcp"):
        with pytest.raises(KeyError):
            get_provider_adapter(unsupported)


def test_oci_adapter_is_deterministic_pure_and_capability_bound(
    tmp_path: Path,
) -> None:
    spec = _spec(tmp_path)
    before = set(tmp_path.iterdir())
    key = read_public_ssh_key(spec.network.ssh_public_key_path)
    first = get_provider_adapter("oci").build_terraform_input(
        spec, _capabilities(), public_ssh_key=key
    )
    second = get_provider_adapter("oci").build_terraform_input(
        spec, _capabilities(), public_ssh_key=key
    )
    assert first == second
    assert first.digest() == second.digest()
    assert set(tmp_path.iterdir()) == before
    assert isinstance(first, OciTerraformInput)
    assert tuple(host.logical_id for host in first.hosts) == tuple(
        sorted(host.logical_id for host in first.hosts)
    )
    scylla = next(host for host in first.hosts if host.role is HostRole.SCYLLA)
    assert scylla.storage.selected_backend is StorageBackend.LOCAL_NVME
    assert scylla.storage.provider_local_device_count == 2
    assert scylla.storage.provider_local_total_gib == 1000
    assert all(not host.assign_public_ip for host in first.hosts)
    assert first.network.operator_cidrs == ("198.51.100.0/24",)

    fallback = get_provider_adapter("oci").build_terraform_input(
        spec, _capabilities(local_count=0, local_gib=0), public_ssh_key=key
    )
    assert isinstance(fallback, OciTerraformInput)
    scylla = next(host for host in fallback.hosts if host.role is HostRole.SCYLLA)
    assert scylla.storage.selected_backend is StorageBackend.BLOCK_VOLUME
    assert scylla.storage.provider_local_device_count is None


def test_oci_adapter_refuses_unknown_capabilities_and_change_intent(
    tmp_path: Path,
) -> None:
    spec = _spec(tmp_path)
    key = read_public_ssh_key(spec.network.ssh_public_key_path)
    wrong_region = replace(_capabilities(), region="us-phoenix-1")
    with pytest.raises(ConfigurationError, match="region"):
        get_provider_adapter("oci").build_terraform_input(
            spec, wrong_region, public_ssh_key=key
        )
    missing_shape = replace(_capabilities(), shapes=())
    with pytest.raises(ConfigurationError, match="shape"):
        get_provider_adapter("oci").build_terraform_input(
            spec, missing_shape, public_ssh_key=key
        )
    local_only = replace(
        spec,
        storage=(
            StoragePolicy(
                HostRole.SCYLLA,
                StorageBackend.LOCAL_NVME,
                StorageLayout.SINGLE,
                1,
                400,
                None,
            ),
            *spec.storage[1:],
        ),
    )
    with pytest.raises(ConfigurationError, match="local-NVMe capability"):
        get_provider_adapter("oci").build_terraform_input(
            local_only,
            _capabilities(local_count=0, local_gib=0),
            public_ssh_key=key,
        )
    change = ProposedChange(
        "scylla_instance_type",
        "VM.Standard.E5.Flex",
        "VM.Standard.E6.Flex",
        ValueSource.CLI,
        ChangeDisposition.PROPOSED_CHANGE,
    )
    with pytest.raises(StateConflictError, match="workflow"):
        get_provider_adapter("oci").build_terraform_input(
            spec,
            _capabilities(),
            public_ssh_key=key,
            change_intent=(change,),
        )


def test_oci_image_resolution_refuses_no_match_and_tied_newest(
    tmp_path: Path,
) -> None:
    spec = _spec(tmp_path)
    key = read_public_ssh_key(spec.network.ssh_public_key_path)
    with pytest.raises(ConfigurationError, match="no AVAILABLE"):
        get_provider_adapter("oci").build_terraform_input(
            spec, replace(_capabilities(), images=()), public_ssh_key=key
        )

    first = _capabilities().images[0]
    tied = replace(
        first,
        image_id="ocid1.image.oc1.iad.fakeimage2",
        display_name="Canonical-Ubuntu-24.04-tied",
    )
    with pytest.raises(ConfigurationError, match="ambiguous"):
        get_provider_adapter("oci").build_terraform_input(
            spec,
            replace(_capabilities(), images=(first, tied)),
            public_ssh_key=key,
        )


def test_oci_existing_host_image_evidence_is_pinned(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    key = read_public_ssh_key(spec.network.ssh_public_key_path)
    prior = _capabilities().images[0]
    newer = replace(
        prior,
        image_id="ocid1.image.oc1.iad.fakeimage2",
        display_name="Canonical-Ubuntu-24.04-2026.09.15-0",
        time_created="2026-09-15T00:00:00Z",
    )
    pinned = OciSelectedImage(
        prior.image_id,
        prior.display_name,
        prior.time_created,
        prior.operating_system,
        prior.operating_system_version,
        prior.architecture,
    )
    capabilities = replace(
        _capabilities(),
        images=(prior, newer),
        pinned_images=(("scylla-ad-1-1", pinned),),
    )

    value = get_provider_adapter("oci").build_terraform_input(
        spec, capabilities, public_ssh_key=key
    )
    assert isinstance(value, OciTerraformInput)
    images = {host.logical_id: host.image_id for host in value.hosts}
    assert images["scylla-ad-1-1"] == prior.image_id
    assert images["manager-1"] == newer.image_id


def test_oci_input_round_trip_rejects_unknown_and_secret_fields(
    tmp_path: Path,
) -> None:
    terraform_input = _input(tmp_path)
    value = terraform_input.to_object()
    assert OciTerraformInput.from_object(value) == terraform_input
    assert OciTerraformInput.from_object(value).digest() == terraform_input.digest()

    unknown = terraform_input.to_object()
    unknown["unexpected"] = True
    with pytest.raises(ConfigurationError, match="schema"):
        OciTerraformInput.from_object(unknown)

    secret = terraform_input.to_object()
    secret["api_token"] = "obviously-fake"
    with pytest.raises(ConfigurationError, match="secret-like"):
        OciTerraformInput.from_object(secret)
    conflicting = terraform_input.to_object()
    hosts = conflicting["hosts"]
    assert isinstance(hosts, list)
    first_host = hosts[0]
    assert isinstance(first_host, dict)
    storage = first_host["storage"]
    assert isinstance(storage, dict)
    storage["policy_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ConfigurationError, match="policy digest"):
        OciTerraformInput.from_object(conflicting)
    with pytest.raises(ConfigurationError, match="private"):
        validate_public_ssh_key_text("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n")
    with pytest.raises(ConfigurationError, match="payload"):
        validate_public_ssh_key_text("ssh-ed25519 not-base64")
    conflicting_algorithm = _public_key().replace("ssh-ed25519", "ssh-rsa", 1)
    with pytest.raises(ConfigurationError, match="algorithm"):
        validate_public_ssh_key_text(conflicting_algorithm)


def test_public_key_reader_rejects_links_permissions_and_size(tmp_path: Path) -> None:
    key = tmp_path / "key.pub"
    key.write_text(_public_key() + "\n", encoding="utf-8")
    key.chmod(0o600)
    assert read_public_ssh_key(key) == _public_key()

    key.chmod(0o622)
    with pytest.raises(UnsafePathError, match="writable"):
        read_public_ssh_key(key)
    key.chmod(0o600)
    linked = tmp_path / "linked.pub"
    os.link(key, linked)
    with pytest.raises(UnsafePathError, match="singly linked"):
        read_public_ssh_key(key)
    linked.unlink()

    alias = tmp_path / "alias.pub"
    alias.symlink_to(key)
    with pytest.raises(UnsafePathError, match=r"open|canonical"):
        read_public_ssh_key(alias)
    alias.unlink()
    key.write_bytes(b"x" * (MAXIMUM_PUBLIC_KEY_BYTES + 1))
    with pytest.raises(ConfigurationError, match="size"):
        read_public_ssh_key(key)


def test_tfvars_store_requires_lock_and_preserves_atomic_generations(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    record = TerraformInputRecord.create(_input(tmp_path), clock=lambda: NOW)
    store = TerraformInputStore(paths)
    unlocked = ClusterLock(paths, "deploy", 0)
    with pytest.raises(StateLockError):
        store.write_locked(
            record, expected_generation=0, expected_digest=None, lock=unlocked
        )
    with ClusterLock(paths, "deploy", 0) as lock:
        stored = store.write_locked(
            record, expected_generation=0, expected_digest=None, lock=lock
        )
    assert paths.terraform_tfvars.stat().st_mode & 0o777 == 0o600
    assert (
        store.read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
            expected_provider="oci",
        )
        == stored
    )
    next_record = record.next_generation(
        record.terraform_input, clock=lambda: NOW + timedelta(seconds=1)
    )
    failing = TerraformInputStore(
        paths,
        replace=lambda _source, _target: (_ for _ in ()).throw(OSError("fake")),
    )
    before = paths.terraform_tfvars.read_bytes()
    with (
        ClusterLock(paths, "deploy", 0) as lock,
        pytest.raises(StatePersistenceError, match="atomic"),
    ):
        failing.write_locked(
            next_record,
            expected_generation=1,
            expected_digest=stored.digest,
            lock=lock,
        )
    assert paths.terraform_tfvars.read_bytes() == before


def test_source_bundle_and_staging_are_deterministic_idempotent_and_bound(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    input_record = TerraformInputRecord.create(_input(tmp_path), clock=lambda: NOW)
    bundle = _bundle()
    assert bundle == _bundle()
    stager = TerraformSourceStager(paths, token_factory=lambda: "first")
    with ClusterLock(paths, "deploy", 0) as lock:
        TerraformInputStore(paths).write_locked(
            input_record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        stored = stager.stage_locked(
            bundle,
            cluster_uuid=CLUSTER_UUID,
            cluster_name="example",
            clock=lambda: NOW,
            lock=lock,
        )
    assert stored.record.source_version == "oci-root/v1"
    assert not stored.record.planning_ready
    assert paths.terraform_tfvars.exists()
    assert all(
        path.stat().st_mode & 0o777 == 0o600 for path in paths.terraform_work.iterdir()
    )
    before = {
        path.relative_to(paths.terraform).as_posix(): path.read_bytes()
        for path in paths.terraform.rglob("*")
        if path.is_file()
    }
    with ClusterLock(paths, "deploy", 0) as lock:
        repeated = stager.stage_locked(
            bundle,
            cluster_uuid=CLUSTER_UUID,
            cluster_name="example",
            clock=lambda: NOW + timedelta(seconds=1),
            lock=lock,
        )
    assert repeated == stored
    after = {
        path.relative_to(paths.terraform).as_posix(): path.read_bytes()
        for path in paths.terraform.rglob("*")
        if path.is_file()
    }
    assert after == before
    executable = tmp_path / "terraform"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    command = TerraformCommandBuilder(executable, paths, source=stored).fmt_check()
    assert command.source_digest == bundle.digest
    assert command.process.argv[1] == f"-chdir={paths.terraform_work}"
    with pytest.raises(TerraformError, match="not planning-ready"):
        TerraformCommandBuilder(executable, paths, source=stored).plan(uuid.uuid4())


def test_source_staging_refuses_tamper_downgrade_and_active_state(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    stager = TerraformSourceStager(paths, token_factory=lambda: "stage")
    with ClusterLock(paths, "deploy", 0) as lock:
        stored = stager.stage_locked(
            _bundle("oci-root/v2"),
            cluster_uuid=CLUSTER_UUID,
            cluster_name="example",
            clock=lambda: NOW,
            lock=lock,
        )
    versions = paths.terraform_work / "versions.tf"
    versions.write_text("tampered\n", encoding="utf-8")
    versions.chmod(0o600)
    with (
        ClusterLock(paths, "deploy", 0) as lock,
        pytest.raises(StatePersistenceError, match="tampered"),
    ):
        stager.stage_locked(
            _bundle("oci-root/v2"),
            cluster_uuid=CLUSTER_UUID,
            cluster_name="example",
            clock=lambda: NOW,
            lock=lock,
        )
    versions.write_bytes(
        next(
            file for file in _bundle("oci-root/v2").files if file.path == "versions.tf"
        ).content
    )
    versions.chmod(0o600)
    with (
        ClusterLock(paths, "deploy", 0) as lock,
        pytest.raises(StatePersistenceError, match="downgrade"),
    ):
        stager.stage_locked(
            _bundle("oci-root/v1"),
            cluster_uuid=CLUSTER_UUID,
            cluster_name="example",
            clock=lambda: NOW,
            lock=lock,
        )
    paths.terraform_state.write_text("fake state", encoding="utf-8")
    paths.terraform_state.chmod(0o600)
    with (
        ClusterLock(paths, "deploy", 0) as lock,
        pytest.raises(StatePersistenceError, match="active state"),
    ):
        stager.stage_locked(
            ApprovedSourceBundle.build(
                version="oci-root/v3",
                planning_ready=False,
                files={
                    **{file.path: file.content for file in _bundle().files},
                    "outputs.tf": b'output "contract" { value = "v3" }\n',
                },
            ),
            cluster_uuid=CLUSTER_UUID,
            cluster_name="example",
            clock=lambda: NOW,
            lock=lock,
        )
    assert (
        TerraformSourceStore(paths).read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        == stored
    )


def test_source_staging_rollback_preserves_previous_tree_and_record(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    with ClusterLock(paths, "deploy", 0) as lock:
        first = TerraformSourceStager(
            paths, token_factory=lambda: "first"
        ).stage_locked(
            _bundle(),
            cluster_uuid=CLUSTER_UUID,
            cluster_name="example",
            clock=lambda: NOW,
            lock=lock,
        )
    before = {
        path.relative_to(paths.terraform).as_posix(): path.read_bytes()
        for path in paths.terraform.rglob("*")
        if path.is_file()
    }
    second_bundle = ApprovedSourceBundle.build(
        version="oci-root/v2",
        planning_ready=False,
        files={
            **{file.path: file.content for file in _bundle().files},
            "outputs.tf": b'output "contract" { value = "v2" }\n',
        },
    )
    failing_store = TerraformSourceStore(
        paths,
        replace=lambda _source, _target: (_ for _ in ()).throw(OSError("fake")),
    )
    failing = TerraformSourceStager(
        paths, store=failing_store, token_factory=lambda: "second"
    )
    with (
        ClusterLock(paths, "deploy", 0) as lock,
        pytest.raises(StatePersistenceError, match="atomic"),
    ):
        failing.stage_locked(
            second_bundle,
            cluster_uuid=CLUSTER_UUID,
            cluster_name="example",
            clock=lambda: NOW + timedelta(seconds=1),
            lock=lock,
        )
    after = {
        path.relative_to(paths.terraform).as_posix(): path.read_bytes()
        for path in paths.terraform.rglob("*")
        if path.is_file()
    }
    assert after == before
    assert (
        TerraformSourceStore(paths).read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        == first
    )


def test_source_staging_requires_lock_and_rejects_unexpected_or_symlinked_work(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    stager = TerraformSourceStager(paths, token_factory=lambda: "guard")
    unlocked = ClusterLock(paths, "deploy", 0)
    with pytest.raises(StateLockError):
        stager.stage_locked(
            _bundle(),
            cluster_uuid=CLUSTER_UUID,
            cluster_name="example",
            clock=lambda: NOW,
            lock=unlocked,
        )

    unexpected = paths.terraform_work / "unexpected.tf"
    unexpected.write_text("terraform {}\n", encoding="utf-8")
    unexpected.chmod(0o600)
    with (
        ClusterLock(paths, "deploy", 0) as lock,
        pytest.raises(StatePersistenceError, match="unexpected"),
    ):
        stager.stage_locked(
            _bundle(),
            cluster_uuid=CLUSTER_UUID,
            cluster_name="example",
            clock=lambda: NOW,
            lock=lock,
        )
    unexpected.unlink()
    outside = tmp_path / "outside.tf"
    outside.write_text("terraform {}\n", encoding="utf-8")
    outside.chmod(0o600)
    (paths.terraform_work / "linked.tf").symlink_to(outside)
    with (
        ClusterLock(paths, "deploy", 0) as lock,
        pytest.raises(UnsafePathError, match="symbolic link"),
    ):
        stager.stage_locked(
            _bundle(),
            cluster_uuid=CLUSTER_UUID,
            cluster_name="example",
            clock=lambda: NOW,
            lock=lock,
        )
    (paths.terraform_work / "linked.tf").unlink()
    os.link(outside, paths.terraform_work / "linked.tf")
    with (
        ClusterLock(paths, "deploy", 0) as lock,
        pytest.raises(UnsafePathError, match="singly linked"),
    ):
        stager.stage_locked(
            _bundle(),
            cluster_uuid=CLUSTER_UUID,
            cluster_name="example",
            clock=lambda: NOW,
            lock=lock,
        )


@pytest.mark.parametrize(
    "files",
    [
        {"../main.tf": b"terraform {}\n"},
        {"/main.tf": b"terraform {}\n"},
        {"main.tf": b'variable "api_token" { type = string }\n'},
    ],
)
def test_source_bundle_rejects_unsafe_paths_and_secret_variables(
    files: dict[str, bytes],
) -> None:
    with pytest.raises(StatePersistenceError):
        ApprovedSourceBundle.build(
            version="oci-root/v1", files=files, planning_ready=False
        )


def test_source_static_contract_has_no_resources_or_public_exposure() -> None:
    text = "\n".join(file.content.decode("utf-8") for file in _bundle().files).lower()
    assert 'resource "' not in text
    assert "0.0.0.0/0" not in text
    assert "assign_public_ip" not in text
    assert ".terraform.lock.hcl" not in {file.path for file in _bundle().files}
