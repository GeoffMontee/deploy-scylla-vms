import base64
import hashlib
import json
import struct
import sys
import uuid
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scylla_vms.ansible.readiness import (
    EvidenceStatus,
    RouteReadiness,
    TrustReadiness,
    build_readiness_report,
    validate_inventory_machine_output,
    validate_routes,
)
from scylla_vms.ansible.ssh import SSHKeyCommandBuilder, SSHKeyDiscoveryService
from scylla_vms.ansible.trust import (
    TRUST_SCHEMA_VERSION,
    HostEndpoint,
    HostKeyCandidate,
    StoredTrustRecord,
    TrustCaptureSource,
    TrustedHostKey,
    TrustRecord,
    TrustStore,
    confirm_host_key_candidate,
    parse_keyscan_output,
)
from scylla_vms.desired import HostRole
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.inventory import (
    HostTrustStatus,
    InventoryHost,
    InventoryModel,
    InventoryRecord,
    StoredInventoryRecord,
    _groups_for_hosts,
    _inventory_digest,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import ObservedStateRecord, StoredObservedState
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import digest_bytes
from scylla_vms.process import ProcessResult, ProcessSpec, ProcessTimeoutError
from scylla_vms.state import StatePaths, initialize_state_layout

CLUSTER_UUID = uuid.UUID("11111111-1111-4111-8111-111111111111")
SOURCE_DIGEST = "sha256:" + "a" * 64
CAPTURED = datetime(2026, 9, 17, 20, 0, tzinfo=UTC)


class FakeRunner:
    def __init__(self, result: ProcessResult | None = None) -> None:
        self.result = result or ProcessResult(0, "", "")
        self.specs: list[ProcessSpec] = []
        self.error: Exception | None = None

    def run(self, spec: ProcessSpec) -> ProcessResult:
        self.specs.append(spec)
        if self.error is not None:
            raise self.error
        return self.result


def _ssh_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _ed25519_key(seed: int) -> str:
    blob = _ssh_string(b"ssh-ed25519") + _ssh_string(bytes([seed]) * 32)
    return base64.b64encode(blob).decode("ascii")


def _ecdsa_key(seed: int) -> str:
    blob = (
        _ssh_string(b"ecdsa-sha2-nistp256")
        + _ssh_string(b"nistp256")
        + _ssh_string(b"\x04" + bytes([seed]) * 64)
    )
    return base64.b64encode(blob).decode("ascii")


def _fingerprint(public_key: str) -> str:
    digest = hashlib.sha256(base64.b64decode(public_key)).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _host(
    logical_id: str,
    role: HostRole,
    address: str,
    *,
    public: str | None = None,
    jump: str | None = None,
    zone: str = "AD-1",
) -> InventoryHost:
    return InventoryHost(
        logical_id,
        role,
        zone,
        f"ocid1.instance.oc1.iad.fake{logical_id.replace('-', '')}",
        address,
        public,
        public if role is HostRole.JUMP_HOST and public is not None else address,
        "opc",
        "VM.Standard.E5.Flex",
        "example-dc" if role is HostRole.SCYLLA else None,
        "rack-a" if role is HostRole.SCYLLA else None,
        "proxy-jump" if jump else "direct",
        jump,
        "boot-only",
        0,
        0,
        0,
        False,
        1,
        SOURCE_DIGEST,
    )


def _inventory(hosts: tuple[InventoryHost, ...]) -> StoredInventoryRecord:
    ordered = tuple(sorted(hosts, key=lambda host: host.logical_id))
    model = InventoryModel(
        ordered, _groups_for_hosts(ordered), HostTrustStatus.UNAVAILABLE
    )
    record = InventoryRecord(
        1,
        CLUSTER_UUID,
        "example",
        "oci",
        "2026-09-17T20:00:00Z",
        1,
        SOURCE_DIGEST,
        _inventory_digest(model),
        model,
    )
    encoded = json.dumps(
        record.to_object(), sort_keys=True, separators=(",", ":")
    ).encode()
    return StoredInventoryRecord(record, digest_bytes(encoded))


def _observed(inventory: StoredInventoryRecord) -> StoredObservedState:
    record = cast(
        ObservedStateRecord,
        SimpleNamespace(
            cluster_uuid=CLUSTER_UUID,
            cluster_name="example",
            provider="oci",
            generation=inventory.record.source_manifest_generation,
            manifest_digest=inventory.record.source_manifest_digest,
            captured_at="2026-09-17T20:00:00Z",
        ),
    )
    return cast(
        StoredObservedState, SimpleNamespace(record=record, digest=SOURCE_DIGEST)
    )


def _candidate(host: InventoryHost, seed: int = 1) -> HostKeyCandidate:
    key = _ed25519_key(seed)
    return HostKeyCandidate(
        host.logical_id,
        host.provider_id,
        HostEndpoint(host.ansible_host),
        host.jump_host_id,
        "ssh-ed25519",
        key,
        _fingerprint(key),
        "2026-09-17T20:00:00Z",
        TrustCaptureSource.SUPPLIED_CANDIDATE,
    )


def _trusted(host: InventoryHost, seed: int = 1) -> TrustedHostKey:
    return confirm_host_key_candidate(
        _candidate(host, seed),
        explicitly_confirmed=True,
        confirmed_at=CAPTURED + timedelta(minutes=1),
    )


def _trust(
    inventory: StoredInventoryRecord, seeds: tuple[int, ...] | None = None
) -> StoredTrustRecord:
    selected = seeds or tuple(range(1, len(inventory.record.inventory.hosts) + 1))
    entries = tuple(
        _trusted(host, seed)
        for host, seed in zip(inventory.record.inventory.hosts, selected, strict=True)
    )
    record = TrustRecord.create(
        _observed(inventory).record, inventory.record, entries, generation=1
    )
    return StoredTrustRecord(
        record, digest_bytes(json.dumps(record.to_object()).encode())
    )


def _paths(tmp_path: Path) -> StatePaths:
    paths = StatePaths.derive(tmp_path / "state", "example")
    initialize_state_layout(paths)
    return paths


def _executable(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    path.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    path.chmod(0o700)
    return path


def test_candidate_parsing_requires_explicit_independent_confirmation() -> None:
    key = _ed25519_key(1)
    endpoint = HostEndpoint("203.0.113.10")
    candidates = parse_keyscan_output(
        f"203.0.113.10 ssh-ed25519 {key}\n"
        f"203.0.113.10 ecdsa-sha2-nistp256 {_ecdsa_key(2)}\n",
        logical_id="jump-host-1",
        provider_id="ocid1.instance.oc1.iad.fakejump",
        endpoint=endpoint,
        jump_host_id=None,
        captured_at=CAPTURED,
    )
    assert [candidate.algorithm for candidate in candidates] == [
        "ecdsa-sha2-nistp256",
        "ssh-ed25519",
    ]
    candidate = candidates[1]
    with pytest.raises(StateConflictError, match="explicit confirmation"):
        confirm_host_key_candidate(candidate, confirmed_at=CAPTURED)
    confirmed = confirm_host_key_candidate(
        candidate,
        expected_fingerprint=candidate.fingerprint,
        confirmed_at=CAPTURED + timedelta(seconds=1),
    )
    assert confirmed.fingerprint == candidate.fingerprint
    with pytest.raises(StateConflictError, match="conflicts"):
        confirm_host_key_candidate(
            candidate,
            expected_fingerprint="SHA256:" + "A" * 43,
            confirmed_at=CAPTURED,
        )
    with pytest.raises(StatePersistenceError, match="disallowed"):
        parse_keyscan_output(
            "203.0.113.10 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ==\n",
            logical_id="jump-host-1",
            provider_id="ocid1.instance.oc1.iad.fakejump",
            endpoint=endpoint,
            jump_host_id=None,
            captured_at=CAPTURED,
        )
    with pytest.raises(StateConflictError, match="algorithm and blob"):
        parse_keyscan_output(
            f"203.0.113.10 ecdsa-sha2-nistp256 {key}\n",
            logical_id="jump-host-1",
            provider_id="ocid1.instance.oc1.iad.fakejump",
            endpoint=endpoint,
            jump_host_id=None,
            captured_at=CAPTURED,
        )
    with pytest.raises(StateConflictError, match="duplicates"):
        parse_keyscan_output(
            f"203.0.113.10 ssh-ed25519 {key}\n203.0.113.10 ssh-ed25519 {key}\n",
            logical_id="jump-host-1",
            provider_id="ocid1.instance.oc1.iad.fakejump",
            endpoint=endpoint,
            jump_host_id=None,
            captured_at=CAPTURED,
        )
    with pytest.raises(StatePersistenceError, match="size limit"):
        parse_keyscan_output(
            "x" * 100,
            logical_id="jump-host-1",
            provider_id="ocid1.instance.oc1.iad.fakejump",
            endpoint=endpoint,
            jump_host_id=None,
            captured_at=CAPTURED,
            maximum_bytes=10,
        )
    with pytest.raises(StatePersistenceError, match="malformed"):
        parse_keyscan_output(
            "203.0.113.10 ssh-ed25519 !!!\n",
            logical_id="jump-host-1",
            provider_id="ocid1.instance.oc1.iad.fakejump",
            endpoint=endpoint,
            jump_host_id=None,
            captured_at=CAPTURED,
        )


def test_trust_record_round_trip_store_runtime_and_changed_key_refusal(
    tmp_path: Path,
) -> None:
    host = _host("jump-host-1", HostRole.JUMP_HOST, "10.0.0.10", public="203.0.113.10")
    inventory = _inventory((host,))
    observed = _observed(inventory)
    record = TrustRecord.create(
        observed.record, inventory.record, (_trusted(host),), generation=1
    )
    assert TrustRecord.from_object(record.to_object()) == record
    assert record.schema_version == TRUST_SCHEMA_VERSION
    with pytest.raises(FrozenInstanceError):
        record.generation = 2  # type: ignore[misc]

    paths = _paths(tmp_path)
    store = TrustStore(paths)
    with ClusterLock(paths, "deploy", 0) as lock:
        stored = store.write_locked(
            record,
            observed,
            inventory,
            approved=True,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    assert paths.ansible_trust.stat().st_mode & 0o777 == 0o600
    assert paths.known_hosts.stat().st_mode & 0o777 == 0o600
    assert paths.ansible_ssh_config.stat().st_mode & 0o777 == 0o600
    assert record.entries[0].public_key in paths.known_hosts.read_text(encoding="utf-8")
    ssh_config = paths.ansible_ssh_config.read_text(encoding="utf-8")
    assert "StrictHostKeyChecking yes" in ssh_config
    assert f'UserKnownHostsFile "{paths.known_hosts}"' in ssh_config
    assert "ProxyCommand" not in ssh_config
    store.validate_runtime(stored, inventory)

    changed = TrustRecord.create(
        observed.record, inventory.record, (_trusted(host, 2),), generation=2
    )
    with (
        ClusterLock(paths, "deploy", 0) as lock,
        pytest.raises(StateConflictError, match="replacement workflow"),
    ):
        store.write_locked(
            changed,
            observed,
            inventory,
            approved=True,
            expected_generation=1,
            expected_digest=stored.digest,
            lock=lock,
        )


def test_trust_store_atomic_failure_and_unsafe_link_refusal(tmp_path: Path) -> None:
    host = _host("jump-host-1", HostRole.JUMP_HOST, "10.0.0.10", public="203.0.113.10")
    inventory = _inventory((host,))
    observed = _observed(inventory)
    first = TrustRecord.create(
        observed.record, inventory.record, (_trusted(host),), generation=1
    )
    paths = _paths(tmp_path)
    with ClusterLock(paths, "deploy", 0) as lock:
        stored = TrustStore(paths).write_locked(
            first,
            observed,
            inventory,
            approved=True,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    before = paths.ansible_trust.read_bytes()

    def fail_replace(_source: Path, _target: Path) -> None:
        raise OSError("simulated replacement failure")

    second = replace(first, generation=2)
    with (
        ClusterLock(paths, "deploy", 0) as lock,
        pytest.raises(StatePersistenceError),
    ):
        TrustStore(
            paths, replace=fail_replace, token_factory=lambda: "failure"
        ).write_locked(
            second,
            observed,
            inventory,
            approved=True,
            expected_generation=1,
            expected_digest=stored.digest,
            lock=lock,
        )
    assert paths.ansible_trust.read_bytes() == before
    assert not tuple(paths.ansible.glob(".*.tmp"))

    unsafe_parent = tmp_path / "unsafe"
    unsafe_parent.mkdir(mode=0o700)
    unsafe = _paths(unsafe_parent)
    target = unsafe.ansible / "actual-trust.json"
    target.write_bytes(before)
    target.chmod(0o600)
    unsafe.ansible_trust.symlink_to(target)
    with pytest.raises((StatePersistenceError, UnsafePathError)):
        TrustStore(unsafe).read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
            expected_provider="oci",
        )

    hardlink_parent = tmp_path / "hardlink"
    hardlink_parent.mkdir(mode=0o700)
    hardlink = _paths(hardlink_parent)
    source = hardlink.ansible / "source.json"
    source.write_bytes(before)
    source.chmod(0o600)
    hardlink.ansible_trust.hardlink_to(source)
    with pytest.raises(UnsafePathError):
        TrustStore(hardlink).read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
            expected_provider="oci",
        )

    corrupt_parent = tmp_path / "corrupt"
    corrupt_parent.mkdir(mode=0o700)
    corrupt = _paths(corrupt_parent)
    value = first.to_object()
    value["schema_version"] = "deploy-scylla-vms.ssh-trust/v999"
    corrupt.ansible_trust.write_text(json.dumps(value), encoding="utf-8")
    corrupt.ansible_trust.chmod(0o600)
    with pytest.raises(StatePersistenceError, match="unsupported SSH trust schema"):
        TrustStore(corrupt).read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
            expected_provider="oci",
        )


def test_direct_discovery_is_controlled_and_private_jump_scan_refuses(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    key = _ed25519_key(1)
    runner = FakeRunner(ProcessResult(0, f"203.0.113.10 ssh-ed25519 {key}\n", ""))
    builder = SSHKeyCommandBuilder(
        _executable(tmp_path, "ssh-keyscan"),
        _executable(tmp_path, "ssh-keygen"),
        paths,
    )
    service = SSHKeyDiscoveryService(builder, runner)
    candidates = service.discover(
        logical_id="jump-host-1",
        provider_id="ocid1.instance.oc1.iad.fakejump",
        endpoint=HostEndpoint("203.0.113.10"),
        jump_host_id=None,
        captured_at=CAPTURED,
    )
    assert len(candidates) == 1
    assert runner.specs[0].argv == (
        str(tmp_path / "ssh-keyscan"),
        "-T",
        "15",
        "-p",
        "22",
        "-t",
        "ecdsa,ed25519",
        "203.0.113.10",
    )
    assert runner.specs[0].cwd == paths.ansible
    assert runner.specs[0].environment.for_subprocess()["HOME"] == str(
        paths.ansible_home
    )
    paths.known_hosts.write_text(f"203.0.113.10 ssh-ed25519 {key}\n", encoding="utf-8")
    paths.known_hosts.chmod(0o600)
    inspected = service.inspect(
        logical_id="jump-host-1",
        provider_id="ocid1.instance.oc1.iad.fakejump",
        endpoint=HostEndpoint("203.0.113.10"),
        jump_host_id=None,
        inspected_at=CAPTURED,
    )
    assert inspected[0].fingerprint == candidates[0].fingerprint
    assert inspected[0].capture_source is TrustCaptureSource.LOCAL_KNOWN_HOSTS
    assert runner.specs[1].argv == (
        str(tmp_path / "ssh-keygen"),
        "-F",
        "203.0.113.10",
        "-f",
        str(paths.known_hosts),
    )
    with pytest.raises(AnsibleError, match=r"two-phase|trust jump hosts"):
        builder.scan(HostEndpoint("10.0.1.10"), jump_host_id="jump-host-1")
    runner.error = ProcessTimeoutError("fake timeout")
    with pytest.raises(AnsibleError, match="discovery failed"):
        service.discover(
            logical_id="jump-host-1",
            provider_id="ocid1.instance.oc1.iad.fakejump",
            endpoint=HostEndpoint("203.0.113.10"),
            jump_host_id=None,
            captured_at=CAPTURED,
        )
    runner.error = None
    runner.result = ProcessResult(1, "", "fake failure")
    with pytest.raises(AnsibleError, match="discovery failed"):
        service.discover(
            logical_id="jump-host-1",
            provider_id="ocid1.instance.oc1.iad.fakejump",
            endpoint=HostEndpoint("203.0.113.10"),
            jump_host_id=None,
            captured_at=CAPTURED,
        )
    assert not tuple(paths.ansible_local_tmp.iterdir())


def test_zero_one_and_multiple_jump_route_policy_and_identity_conflicts() -> None:
    direct = _inventory((_host("manager-1", HostRole.MANAGER, "10.0.1.10"),))
    assert validate_routes(direct, _trust(direct)).status is RouteReadiness.VALID

    jump = _host("jump-host-1", HostRole.JUMP_HOST, "10.0.0.10", public="203.0.113.10")
    manager = _host("manager-1", HostRole.MANAGER, "10.0.1.10", jump="jump-host-1")
    one = _inventory((jump, manager))
    assert validate_routes(one, _trust(one)).status is RouteReadiness.VALID

    jumps = (
        _host("jump-a", HostRole.JUMP_HOST, "10.0.0.11", public="203.0.113.11"),
        _host("jump-b", HostRole.JUMP_HOST, "10.0.0.12", public="203.0.113.12"),
    )
    selected_index = int(hashlib.sha256(b"scylla-1").hexdigest()[:8], 16) % len(jumps)
    scylla = _host(
        "scylla-1",
        HostRole.SCYLLA,
        "10.0.2.10",
        jump=tuple(sorted(host.logical_id for host in jumps))[selected_index],
    )
    multiple = _inventory((*jumps, scylla))
    assert validate_routes(multiple, _trust(multiple)).status is RouteReadiness.VALID
    wrong = replace(
        scylla,
        jump_host_id="jump-a" if scylla.jump_host_id == "jump-b" else "jump-b",
    )
    invalid = _inventory((*jumps, wrong))
    report = validate_routes(invalid, _trust(invalid))
    assert report.status is RouteReadiness.INVALID
    assert any("ambiguous-jump-policy" in finding for finding in report.findings)


def test_machine_inventory_validation_and_readiness_blockers() -> None:
    jump = _host("jump-host-1", HostRole.JUMP_HOST, "10.0.0.10", public="203.0.113.10")
    manager = _host("manager-1", HostRole.MANAGER, "10.0.1.10", jump="jump-host-1")
    inventory = _inventory((jump, manager))
    with pytest.raises(StateConflictError, match="identity collisions"):
        TrustRecord.create(
            _observed(inventory).record,
            inventory.record,
            (_trusted(jump, 1), _trusted(manager, 1)),
            generation=1,
        )
    listed = json.dumps(inventory.record.to_machine_object(), sort_keys=True)
    graph = "@all:\n" + "".join(
        f"  |--@{group.name}:\n" + "".join(f"  |  |--{host}\n" for host in group.hosts)
        for group in inventory.record.inventory.groups
    )
    evidence = validate_inventory_machine_output(listed, graph, inventory)
    transformed = json.loads(listed)
    all_group = cast(dict[str, object], transformed["all"])
    children = cast(list[str], all_group["children"])
    children.insert(0, "ungrouped")
    transformed["ungrouped"] = {"hosts": []}
    all_vars = cast(dict[str, object], all_group["vars"])
    transformed_meta = cast(dict[str, object], transformed["_meta"])
    transformed_hostvars = cast(dict[str, object], transformed_meta["hostvars"])
    for logical_id, values in tuple(transformed_hostvars.items()):
        transformed_hostvars[logical_id] = {
            **all_vars,
            **cast(dict[str, object], values),
        }
    transformed_graph = graph.replace("@all:\n", "@all:\n  |--@ungrouped:\n")
    validate_inventory_machine_output(
        json.dumps(transformed), transformed_graph, inventory
    )
    trust = _trust(inventory)
    report = build_readiness_report(
        _observed(inventory), inventory, trust, machine_evidence=evidence
    )
    assert report.status is EvidenceStatus.FRESH
    assert report.trust_status is TrustReadiness.COMPLETE
    assert report.route_status is RouteReadiness.VALID
    assert report.blockers_for(OperationClassification.DESTRUCTIVE) == ()
    public_object = report.to_public_object()
    public = json.dumps(public_object)
    fingerprints = cast(list[dict[str, str]], public_object["fingerprints"])
    assert fingerprints[0]["capture_source"] == "supplied-candidate"
    assert fingerprints[0]["confirmation"] == "explicit-operator"
    for forbidden in ("203.0.113.10", "10.0.1.10", trust.record.entries[0].public_key):
        assert forbidden not in public

    unsafe = inventory.record.to_machine_object()
    meta = cast(dict[str, object], unsafe["_meta"])
    hostvars = cast(dict[str, object], meta["hostvars"])
    first = cast(dict[str, object], hostvars["jump-host-1"])
    first["api_token"] = "not-a-real-secret"
    with pytest.raises(StateConflictError, match="unsafe variable"):
        validate_inventory_machine_output(json.dumps(unsafe), graph, inventory)
    incomplete = build_readiness_report(_observed(inventory), inventory, None)
    assert incomplete.status is EvidenceStatus.UNKNOWN
    assert "trust-incomplete" in incomplete.blockers_for(
        OperationClassification.SENSITIVE
    )
