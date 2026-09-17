import base64
import hashlib
import json
import struct
import sys
import uuid
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scylla_vms.ansible.commands import AnsibleCommandBuilder
from scylla_vms.ansible.readiness import (
    InventoryMachineEvidence,
    ReadinessReport,
    build_readiness_report,
)
from scylla_vms.ansible.registry import get_playbook
from scylla_vms.ansible.routed_keyscan import (
    ROUTED_KEYSCAN_COLLECTION_SCHEMA_VERSION,
    ROUTED_KEYSCAN_MAXIMUM_OUTPUT_BYTES,
    ROUTED_KEYSCAN_REQUEST_SCHEMA_VERSION,
    ROUTED_KEYSCAN_RESULT_SCHEMA_VERSION,
    RoutedCandidateStatus,
    build_routed_keyscan_request,
    collect_routed_host_key_candidates,
    parse_routed_keyscan_execution,
    routed_keyscan_route_digest,
)
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.ansible.source import stage_ansible_config
from scylla_vms.ansible.trust import (
    HostEndpoint,
    HostKeyCandidate,
    StoredTrustRecord,
    TrustCaptureSource,
    TrustedHostKey,
    TrustRecord,
    TrustStore,
    confirm_host_key_candidate,
)
from scylla_vms.desired import HostRole
from scylla_vms.errors import AnsibleError, StateConflictError
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
from scylla_vms.persistence import ClusterMetadata, digest_bytes, serialize_json
from scylla_vms.process import ProcessResult, ProcessSpec
from scylla_vms.state import StatePaths, initialize_state_layout

CLUSTER_UUID = uuid.UUID("11111111-1111-4111-8111-111111111111")
SOURCE_DIGEST = "sha256:" + "a" * 64
CAPTURED = datetime(2026, 9, 18, 18, 0, tzinfo=UTC)


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
    private_address: str,
    *,
    public_address: str | None = None,
    jump_host_id: str | None = None,
) -> InventoryHost:
    return InventoryHost(
        logical_id,
        role,
        "AD-1",
        f"ocid1.instance.oc1.iad.fake{logical_id.replace('-', '')}",
        private_address,
        public_address,
        (
            public_address
            if role is HostRole.JUMP_HOST and public_address is not None
            else private_address
        ),
        "ubuntu",
        "VM.Standard.E5.Flex",
        "example-dc" if role is HostRole.SCYLLA else None,
        "rack-a" if role is HostRole.SCYLLA else None,
        "proxy-jump" if jump_host_id else "direct",
        jump_host_id,
        "boot-only",
        0,
        0,
        0,
        False,
        1,
        SOURCE_DIGEST,
    )


def _inventory(hosts: tuple[InventoryHost, ...]) -> StoredInventoryRecord:
    ordered = tuple(sorted(hosts, key=lambda item: item.logical_id))
    model = InventoryModel(
        ordered,
        _groups_for_hosts(ordered),
        HostTrustStatus.UNAVAILABLE,
    )
    record = InventoryRecord(
        1,
        CLUSTER_UUID,
        "example",
        "oci",
        "2026-09-18T18:00:00Z",
        1,
        SOURCE_DIGEST,
        _inventory_digest(model),
        model,
    )
    data = serialize_json(record.to_object())
    return StoredInventoryRecord(record, digest_bytes(data))


def _observed(inventory: StoredInventoryRecord) -> StoredObservedState:
    record = cast(
        ObservedStateRecord,
        SimpleNamespace(
            cluster_uuid=CLUSTER_UUID,
            cluster_name="example",
            provider="oci",
            generation=inventory.record.source_manifest_generation,
            manifest_digest=inventory.record.source_manifest_digest,
            captured_at="2026-09-18T18:00:00Z",
        ),
    )
    return cast(
        StoredObservedState,
        SimpleNamespace(record=record, digest=SOURCE_DIGEST),
    )


def _candidate(host: InventoryHost, seed: int) -> HostKeyCandidate:
    public_key = _ed25519_key(seed)
    return HostKeyCandidate(
        host.logical_id,
        host.provider_id,
        HostEndpoint(host.ansible_host),
        host.jump_host_id,
        "ssh-ed25519",
        public_key,
        _fingerprint(public_key),
        "2026-09-18T18:00:00Z",
        TrustCaptureSource.SUPPLIED_CANDIDATE,
    )


def _trusted(host: InventoryHost, seed: int) -> TrustedHostKey:
    return confirm_host_key_candidate(
        _candidate(host, seed),
        explicitly_confirmed=True,
        confirmed_at=CAPTURED + timedelta(seconds=1),
    )


def _executable(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    path.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    path.chmod(0o700)
    return path


class RoutedFakeRunner:
    def __init__(
        self,
        *,
        key_seed: int = 9,
        target_status: str = "collected",
        blocker: str | None = None,
    ) -> None:
        self.key_seed = key_seed
        self.target_status = target_status
        self.blocker = blocker
        self.specs: list[ProcessSpec] = []
        self.runtime_payloads: list[dict[str, object]] = []

    def run(self, spec: ProcessSpec) -> ProcessResult:
        self.specs.append(spec)
        if spec.argv[-1] == "--version":
            name = Path(spec.argv[0]).name
            return ProcessResult(0, f"{name} [core 2.19.3]\n", "")
        argument = spec.argv[spec.argv.index("--extra-vars") + 1]
        path = Path(argument.removeprefix("@"))
        values = json.loads(path.read_text(encoding="utf-8"))
        self.runtime_payloads.append(values)
        payload = cast(dict[str, object], values["deploy_scylla_vms_routed_keyscan"])
        targets = cast(list[dict[str, object]], payload["targets"])
        results: list[dict[str, object]] = []
        for index, target in enumerate(targets):
            if self.target_status == "collected":
                ed25519 = _ed25519_key(self.key_seed + index)
                ecdsa = _ecdsa_key(self.key_seed + index + 20)
                keys = [
                    {
                        "algorithm": "ecdsa-sha2-nistp256",
                        "fingerprint": _fingerprint(ecdsa),
                        "public_key": ecdsa,
                    },
                    {
                        "algorithm": "ssh-ed25519",
                        "fingerprint": _fingerprint(ed25519),
                        "public_key": ed25519,
                    },
                ]
            else:
                keys = []
            results.append(
                {
                    "blocker": self.blocker,
                    "keys": keys,
                    "logical_id": target["logical_id"],
                    "route_digest": target["route_digest"],
                    "status": self.target_status,
                }
            )
        collected = sum(item["status"] == "collected" for item in results)
        status = (
            "success"
            if collected == len(results)
            else "partial-failure"
            if collected
            else "failure"
        )
        result = {
            "jump_host_id": payload["jump_host_id"],
            "request_digest": payload["request_digest"],
            "schema_version": ROUTED_KEYSCAN_RESULT_SCHEMA_VERSION,
            "status": status,
            "targets": results,
        }
        marker = base64.b64encode(
            json.dumps(result, separators=(",", ":"), sort_keys=True).encode()
        ).decode()
        jump_host_id = cast(str, payload["jump_host_id"])
        stdout = (
            f'ok: [{jump_host_id}] => {{"msg": '
            f'"DSV_ROUTED_KEYSCAN_B64={marker}"}}\n'
            "PLAY RECAP *****\n"
            f"{jump_host_id} : ok=4 changed=0 unreachable=0 failed=0 "
            "skipped=0 rescued=0 ignored=0\n"
        )
        for protected in spec.sensitive_values:
            stdout = stdout.replace(protected, "[REDACTED]")
        return ProcessResult(0, stdout, "")


def _setup(
    tmp_path: Path,
    *,
    trust_jump: bool = True,
    trust_private: bool = False,
) -> tuple[
    StatePaths,
    ClusterMetadata,
    StoredObservedState,
    StoredInventoryRecord,
    StoredTrustRecord,
    ReadinessReport,
    InventoryHost,
    InventoryHost,
]:
    paths = StatePaths.derive(tmp_path / "state", "example")
    initialize_state_layout(paths)
    jump = _host(
        "jump-host-1",
        HostRole.JUMP_HOST,
        "10.0.0.10",
        public_address="203.0.113.10",
    )
    private = _host(
        "manager-1",
        HostRole.MANAGER,
        "10.0.1.10",
        jump_host_id=jump.logical_id,
    )
    inventory = _inventory((jump, private))
    paths.ansible_inventory.write_bytes(serialize_json(inventory.record.to_object()))
    paths.ansible_inventory.chmod(0o600)
    observed = _observed(inventory)
    trusted_entries: list[TrustedHostKey] = []
    if trust_jump:
        trusted_entries.append(_trusted(jump, 1))
    if trust_private:
        trusted_entries.append(_trusted(private, 2))
    record = TrustRecord.create(
        observed.record,
        inventory.record,
        tuple(trusted_entries),
        generation=1,
    )
    with ClusterLock(paths, "deploy", 0) as lock:
        stored_trust = TrustStore(paths).write_locked(
            record,
            observed,
            inventory,
            approved=True,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        stage_ansible_config(paths, lock=lock)
    marker = digest_bytes(b"machine-evidence")
    readiness = build_readiness_report(
        observed,
        inventory,
        stored_trust,
        machine_evidence=InventoryMachineEvidence(
            marker,
            marker,
            len(inventory.record.inventory.hosts),
            len(inventory.record.inventory.groups),
        ),
    )
    metadata = cast(
        ClusterMetadata,
        SimpleNamespace(
            cluster_uuid=CLUSTER_UUID,
            cluster_name="example",
            provider="oci",
        ),
    )
    return (
        paths,
        metadata,
        observed,
        inventory,
        stored_trust,
        readiness,
        jump,
        private,
    )


def _service(
    tmp_path: Path,
    paths: StatePaths,
    runner: RoutedFakeRunner,
) -> AnsibleService:
    return AnsibleService(
        AnsibleCommandBuilder(
            _executable(tmp_path, "ansible-playbook"),
            _executable(tmp_path, "ansible-inventory"),
            paths,
        ),
        runner,
    )


def _snapshot(paths: StatePaths) -> dict[str, bytes]:
    return {
        str(path.relative_to(paths.cluster_root)): path.read_bytes()
        for path in paths.cluster_root.rglob("*")
        if path.is_file()
    }


def test_routed_collection_is_stable_id_only_address_free_and_write_free(
    tmp_path: Path,
) -> None:
    (
        paths,
        metadata,
        observed,
        inventory,
        trust,
        readiness,
        _jump,
        private,
    ) = _setup(tmp_path)
    runner = RoutedFakeRunner()
    service = _service(tmp_path, paths, runner)
    before = _snapshot(paths)
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        collection = collect_routed_host_key_candidates(
            service,
            lock,
            metadata,
            observed,
            inventory,
            trust,
            readiness,
            target_logical_ids=(private.logical_id,),
            captured_at=CAPTURED,
        )
    assert collection.schema_version == ROUTED_KEYSCAN_COLLECTION_SCHEMA_VERSION
    assert collection.status == "collected"
    assert [candidate.algorithm for candidate in collection.targets[0].candidates] == [
        "ecdsa-sha2-nistp256",
        "ssh-ed25519",
    ]
    assert all(
        candidate.capture_source is TrustCaptureSource.ROUTED_JUMP_KEYSCAN
        for candidate in collection.targets[0].candidates
    )
    public = json.dumps(collection.to_public_object(), sort_keys=True)
    for forbidden in (
        private.private_address,
        private.provider_id,
        collection.targets[0].candidates[0].public_key,
        "/usr/bin/ssh-keyscan",
    ):
        assert forbidden not in public
    assert _snapshot(paths) == before
    assert not tuple(paths.ansible_local_tmp.iterdir())
    process = runner.specs[-1]
    assert private.private_address not in " ".join(process.argv)
    assert "ProxyCommand" not in " ".join(process.argv)
    assert process.environment.for_subprocess()["ANSIBLE_HOST_KEY_CHECKING"] == "True"
    assert process.environment.for_subprocess()["ANSIBLE_LOG_PATH"] == "/dev/null"
    runtime = cast(
        dict[str, object],
        runner.runtime_payloads[0]["deploy_scylla_vms_routed_keyscan"],
    )
    route = cast(list[dict[str, object]], runtime["targets"])[0]
    assert private.private_address in process.sensitive_values
    assert runtime["request_digest"] not in process.sensitive_values
    assert route["route_digest"] not in process.sensitive_values
    assert route["address"] == private.private_address
    ssh_config = paths.ansible_ssh_config.read_text(encoding="utf-8")
    assert "StrictHostKeyChecking yes" in ssh_config
    assert "accept-new" not in ssh_config
    assert "ProxyCommand" not in ssh_config


def test_request_refuses_arbitrary_endpoint_port_options_and_route() -> None:
    definition = get_playbook("routed-keyscan")
    assert definition.hosts == "jump_hosts"
    assert definition.serial == 1
    assert definition.check_mode.value == "supported"
    valid: dict[str, object] = {
        "collection_time": "2026-09-18T12:00:00Z",
        "jump_host_id": "jump-host-1",
        "provenance": {
            "inventory_digest": SOURCE_DIGEST,
            "inventory_generation": 1,
            "observation_digest": SOURCE_DIGEST,
            "observation_generation": 1,
            "readiness_digest": SOURCE_DIGEST,
            "readiness_schema_version": ("deploy-scylla-vms.ansible-readiness/v1"),
            "trust_digest": SOURCE_DIGEST,
            "trust_generation": 1,
        },
        "schema_version": ROUTED_KEYSCAN_REQUEST_SCHEMA_VERSION,
        "targets": [
            {
                "address": "10.0.1.10",
                "logical_id": "manager-1",
                "port": 22,
                "route_digest": SOURCE_DIGEST,
            }
        ],
        "timeout_policy": {
            "approved_key_types": ["ecdsa-sha2-nistp256", "ssh-ed25519"],
            "executable": "/usr/bin/ssh-keyscan",
            "maximum_output_bytes_per_target": ROUTED_KEYSCAN_MAXIMUM_OUTPUT_BYTES,
            "port": 22,
            "seconds_per_target": 10,
        },
    }
    valid["request_digest"] = digest_bytes(serialize_json(valid))
    assert definition.validate_variables({"deploy_scylla_vms_routed_keyscan": valid})
    mutations: tuple[Callable[[dict[str, object]], None], ...] = (
        lambda value: cast(list[dict[str, object]], value["targets"])[0].update(
            address="example.invalid"
        ),
        lambda value: cast(list[dict[str, object]], value["targets"])[0].update(
            port=23
        ),
        lambda value: cast(dict[str, object], value["timeout_policy"]).update(
            options=["-4"]
        ),
        lambda value: cast(dict[str, object], value["timeout_policy"]).update(
            executable="/tmp/ssh-keyscan"
        ),
        lambda value: value.update(collection_time="not-a-timestamp"),
    )
    for mutation in mutations:
        changed = cast(dict[str, object], json.loads(json.dumps(valid)))
        mutation(changed)
        changed["request_digest"] = digest_bytes(
            serialize_json(
                {key: item for key, item in changed.items() if key != "request_digest"}
            )
        )
        with pytest.raises(AnsibleError, match="value is invalid"):
            definition.validate_variables({"deploy_scylla_vms_routed_keyscan": changed})


def test_untrusted_jump_nonprivate_target_and_readiness_drift_refuse(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path)
    paths, metadata, observed, inventory, trust, readiness, _jump, private = setup
    service = _service(tmp_path, paths, RoutedFakeRunner())
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        with pytest.raises(StateConflictError, match="drifted"):
            collect_routed_host_key_candidates(
                service,
                lock,
                metadata,
                observed,
                inventory,
                trust,
                replace(readiness, inventory_digest=SOURCE_DIGEST),
                target_logical_ids=(private.logical_id,),
                captured_at=CAPTURED,
            )

    untrusted_root = tmp_path / "untrusted"
    untrusted_root.mkdir()
    (
        untrusted_paths,
        untrusted_metadata,
        untrusted_observed,
        untrusted_inventory,
        untrusted_trust,
        untrusted_readiness,
        _untrusted_jump,
        untrusted_private,
    ) = _setup(untrusted_root, trust_jump=False)
    untrusted_tools = tmp_path / "untrusted-tools"
    untrusted_tools.mkdir()
    untrusted_service = _service(
        untrusted_tools,
        untrusted_paths,
        RoutedFakeRunner(),
    )
    with ClusterLock(untrusted_paths, "deploy", 0) as lock:
        untrusted_service.version(lock)
        with pytest.raises(StateConflictError, match="readiness is unsatisfied"):
            collect_routed_host_key_candidates(
                untrusted_service,
                lock,
                untrusted_metadata,
                untrusted_observed,
                untrusted_inventory,
                untrusted_trust,
                untrusted_readiness,
                target_logical_ids=(untrusted_private.logical_id,),
                captured_at=CAPTURED,
            )
    with (
        ClusterLock(paths, "deploy", 0) as lock,
        pytest.raises(StateConflictError, match="target or trusted jump"),
    ):
        collect_routed_host_key_candidates(
            service,
            lock,
            metadata,
            observed,
            inventory,
            trust,
            readiness,
            target_logical_ids=("jump-host-1",),
            captured_at=CAPTURED,
        )


def test_existing_and_changed_trust_are_blocked_not_promoted(tmp_path: Path) -> None:
    (
        paths,
        metadata,
        observed,
        inventory,
        trust,
        readiness,
        _jump,
        private,
    ) = _setup(tmp_path, trust_private=True)
    existing = next(
        entry
        for entry in trust.record.entries
        if entry.logical_id == private.logical_id
    )
    for seed, blocker in (
        (2, "existing-trust-requires-replacement-workflow"),
        (9, "changed-key-replacement-required"),
    ):
        runner = RoutedFakeRunner(key_seed=seed)
        (tmp_path / f"tools-{seed}").mkdir()
        service = _service(tmp_path / f"tools-{seed}", paths, runner)
        with ClusterLock(paths, "deploy", 0) as lock:
            service.version(lock)
            collection = collect_routed_host_key_candidates(
                service,
                lock,
                metadata,
                observed,
                inventory,
                trust,
                readiness,
                target_logical_ids=(private.logical_id,),
                captured_at=CAPTURED,
            )
        assert collection.status == "blocked"
        assert collection.targets[0].status is RoutedCandidateStatus.BLOCKED
        assert collection.targets[0].blockers == (blocker,)
        assert (
            trust.record.entries[
                tuple(entry.logical_id for entry in trust.record.entries).index(
                    private.logical_id
                )
            ]
            == existing
        )


@pytest.mark.parametrize(
    ("target_status", "blocker"),
    [
        ("timed-out", "scan-timeout"),
        ("unreachable", "target-unreachable"),
        ("failed", "invalid-output"),
        ("failed", "output-limit-exceeded"),
    ],
)
def test_timeout_unreachable_and_failure_are_bounded_results(
    tmp_path: Path,
    target_status: str,
    blocker: str,
) -> None:
    (
        paths,
        metadata,
        observed,
        inventory,
        trust,
        readiness,
        _jump,
        private,
    ) = _setup(tmp_path)
    runner = RoutedFakeRunner(target_status=target_status, blocker=blocker)
    service = _service(tmp_path, paths, runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        collection = collect_routed_host_key_candidates(
            service,
            lock,
            metadata,
            observed,
            inventory,
            trust,
            readiness,
            target_logical_ids=(private.logical_id,),
            captured_at=CAPTURED,
        )
    assert collection.status == "failed"
    assert collection.targets[0].status.value == target_status
    assert collection.targets[0].blockers == (blocker,)
    assert collection.targets[0].candidates == ()


def test_parser_rejects_malformed_duplicate_unexpected_and_address_output(
    tmp_path: Path,
) -> None:
    (
        _paths,
        _metadata,
        _observed_state,
        inventory,
        trust,
        readiness,
        jump,
        private,
    ) = _setup(tmp_path)
    payload = build_routed_keyscan_request(
        inventory,
        trust,
        readiness,
        jump_host_id=jump.logical_id,
        targets=(private,),
        collection_time="2026-09-18T12:00:00Z",
        timeout_seconds=10,
    )
    public_key = _ed25519_key(5)
    key = {
        "algorithm": "ssh-ed25519",
        "fingerprint": _fingerprint(public_key),
        "public_key": public_key,
    }
    target = {
        "blocker": None,
        "keys": [key],
        "logical_id": private.logical_id,
        "route_digest": routed_keyscan_route_digest(jump, private),
        "status": "collected",
    }
    result: dict[str, object] = {
        "jump_host_id": jump.logical_id,
        "request_digest": payload["request_digest"],
        "schema_version": ROUTED_KEYSCAN_RESULT_SCHEMA_VERSION,
        "status": "success",
        "targets": [target],
    }

    def output(value: dict[str, object], prefix: str = "") -> str:
        marker = base64.b64encode(
            json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        ).decode()
        return (
            prefix
            + f"DSV_ROUTED_KEYSCAN_B64={marker}\nPLAY RECAP *****\n"
            + f"{jump.logical_id} : ok=4 changed=0 unreachable=0 failed=0 "
            "skipped=0 rescued=0 ignored=0\n"
        )

    parse_routed_keyscan_execution(output(result), payload, jump.logical_id, 0)
    malformed_cases: list[str] = [
        "DSV_ROUTED_KEYSCAN_B64=!!!\nPLAY RECAP *****\n",
        output(result, prefix=f"failure at {private.private_address}\n"),
        "x" * (512 * 1024 + 1),
    ]
    duplicated = json.loads(json.dumps(result))
    cast(list[dict[str, object]], duplicated["targets"])[0]["keys"] = [key, key]
    malformed_cases.append(output(duplicated))
    alternate_public_key = _ed25519_key(6)
    alternate = {
        "algorithm": "ssh-ed25519",
        "fingerprint": _fingerprint(alternate_public_key),
        "public_key": alternate_public_key,
    }
    duplicate_algorithm = json.loads(json.dumps(result))
    cast(list[dict[str, object]], duplicate_algorithm["targets"])[0]["keys"] = sorted(
        [key, alternate], key=lambda item: item["fingerprint"]
    )
    malformed_cases.append(output(duplicate_algorithm))
    unexpected = json.loads(json.dumps(result))
    cast(list[dict[str, object]], unexpected["targets"])[0]["logical_id"] = "other-1"
    malformed_cases.append(output(unexpected))
    malformed_key = json.loads(json.dumps(result))
    cast(
        list[dict[str, object]],
        cast(list[dict[str, object]], malformed_key["targets"])[0]["keys"],
    )[0]["public_key"] = "!!!"
    malformed_cases.append(output(malformed_key))
    for value in malformed_cases:
        with pytest.raises(AnsibleError):
            parse_routed_keyscan_execution(value, payload, jump.logical_id, 0)


def test_packaged_module_has_no_shell_proxy_or_tofu_boundary() -> None:
    root = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles/routed_keyscan"
    )
    module = (root / "library/routed_keyscan.py").read_text(encoding="utf-8")
    tasks = (root / "tasks/main.yml").read_text(encoding="utf-8")
    playbook = (root.parents[1] / "routed-keyscan.yml").read_text(encoding="utf-8")
    assert 'EXECUTABLE = "/usr/bin/ssh-keyscan"' in module
    assert "shell=False" in module
    assert '"no_log": True' in module
    assert "ProxyCommand" not in module + tasks + playbook
    assert "StrictHostKeyChecking=no" not in module + tasks + playbook
    assert "accept-new" not in module + tasks + playbook
    assert "ansible.builtin.shell" not in module + tasks + playbook
    assert "no_log: true" in tasks
