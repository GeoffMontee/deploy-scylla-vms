import base64
import json
import shutil
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from test_ansible import (
    FakeRunner,
    _builder,
    _inventory,
    _metadata,
    _paths,
    _readiness,
)
from test_check_jump_hosts import GENERATED_AT, _prepared_state

from scylla_vms.ansible.evidence import (
    EVIDENCE_SCHEMA_VERSION,
    EvidenceRecord,
    EvidenceStatus,
    EvidenceStore,
    parse_collected_evidence,
)
from scylla_vms.ansible.registry import get_playbook
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.errors import AnsibleError, StatePersistenceError
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import ObservedStateStore
from scylla_vms.persistence import ClusterMetadataStore
from scylla_vms.process import ProcessResult, ProcessTimeoutError


def _host_object(
    *,
    logical_id: str = "jump-host-1",
    role: str = "jump-host",
) -> dict[str, object]:
    services: list[dict[str, str]]
    health: str
    if role == "jump-host":
        services = []
        health = "not-performed"
    elif role == "manager":
        services = [{"name": "scylla-manager.service", "status": "running"}]
        health = "not-performed"
    elif role == "monitoring":
        services = [
            {"name": "grafana-server.service", "status": "running"},
            {"name": "prometheus.service", "status": "running"},
        ]
        health = "not-performed"
    else:
        services = [{"name": "scylla-server.service", "status": "running"}]
        health = "passed"
    return {
        "block_devices": {
            "items": [{"name": "sda", "rotational": False, "size": "100.00 GB"}],
            "status": "available",
        },
        "errors": [],
        "filesystems": {
            "items": [
                {
                    "available_bytes": 750,
                    "mount": "/",
                    "total_bytes": 1000,
                    "used_percent": 25.0,
                }
            ],
            "status": "available",
        },
        "logical_id": logical_id,
        "role": role,
        "schema_version": "deploy-scylla-vms.ansible-host-evidence/v1",
        "scylla_health": {"status": health},
        "service_version": {
            "status": "not-performed" if role == "jump-host" else "unavailable",
            "value": None,
        },
        "services": services,
        "status": "complete",
        "system": {
            "architecture": "aarch64",
            "cpu_count": 4,
            "current_time": "2026-09-17T22:00:00Z",
            "kernel": "6.12.0",
            "memory_mib": 8192,
            "os_name": "Ubuntu",
            "os_version": "24.04",
            "uptime_seconds": 3600,
        },
    }


def _stdout(
    host: dict[str, object] | None = None,
    *,
    unreachable: int = 0,
    failed: int = 0,
) -> str:
    marker = ""
    if host is not None:
        encoded = base64.b64encode(
            json.dumps(host, separators=(",", ":"), sort_keys=True).encode()
        ).decode()
        marker = f'ok: [jump-host-1] => {{"msg": "DSV_EVIDENCE_B64={encoded}"}}\n'
    return (
        marker
        + "PLAY RECAP *****\n"
        + f"jump-host-1 : ok=8 changed=0 unreachable={unreachable} "
        + f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


def test_parse_complete_and_unavailable_evidence() -> None:
    inventory = _inventory()
    complete = parse_collected_evidence(
        _stdout(_host_object()), inventory, ("jump-host-1",), 0
    )
    assert complete.status is EvidenceStatus.COMPLETE
    assert complete.hosts[0].system["memory_mib"] == 8192
    assert complete.hosts[0].block_devices[0].to_object() == {
        "name": "sda",
        "rotational": False,
        "size": "100.00 GB",
    }
    assert "serial" not in json.dumps(complete.hosts[0].to_object())

    unavailable = parse_collected_evidence(
        _stdout(unreachable=1), inventory, ("jump-host-1",), 4
    )
    assert unavailable.status is EvidenceStatus.UNAVAILABLE
    assert unavailable.hosts[0].errors == ("host-unreachable",)
    assert unavailable.hosts[0].scylla_health == "not-performed"


def test_evidence_timeout_variable_is_strictly_bounded() -> None:
    definition = get_playbook("evidence-collect")
    assert definition.validate_variables(
        {"deploy_scylla_vms_evidence_timeout_seconds": 60}
    ) == {"deploy_scylla_vms_evidence_timeout_seconds": 60}
    for value in (0, 61, True, "10"):
        with pytest.raises(AnsibleError, match="value is invalid"):
            definition.validate_variables(
                {"deploy_scylla_vms_evidence_timeout_seconds": value}
            )
    with pytest.raises(AnsibleError, match="not allowlisted"):
        definition.validate_variables({"arbitrary_command": "id"})


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value.update({"environment": {}}),
        lambda value: value["services"].append(
            {"name": "arbitrary.service", "status": "running"}
        ),
        lambda value: value["service_version"].update(
            {"status": "available", "value": "token=do-not-render"}
        ),
        lambda value: value["filesystems"]["items"].append(
            {
                "available_bytes": 1,
                "mount": "/private",
                "total_bytes": 1,
                "used_percent": 0,
            }
        ),
    ],
)
def test_evidence_schema_rejects_unknown_or_sensitive_data(
    mutator: object,
) -> None:
    value = _host_object()
    mutator(value)  # type: ignore[operator]
    with pytest.raises(AnsibleError, match="schema is invalid"):
        parse_collected_evidence(_stdout(value), _inventory(), ("jump-host-1",), 0)


def test_evidence_parser_rejects_malformed_oversized_and_wrong_role() -> None:
    inventory = _inventory()
    with pytest.raises(AnsibleError, match="marker is malformed"):
        parse_collected_evidence(
            'ok: {"msg": "DSV_EVIDENCE_B64=***"}\n' + _stdout(),
            inventory,
            ("jump-host-1",),
            0,
        )
    with pytest.raises(AnsibleError, match="exceeds the evidence limit"):
        parse_collected_evidence(
            "x" * (1024 * 1024 + 1), inventory, ("jump-host-1",), 0
        )
    wrong_role = _host_object(role="scylla")
    with pytest.raises(AnsibleError, match="role conflicts"):
        parse_collected_evidence(_stdout(wrong_role), inventory, ("jump-host-1",), 0)


def test_service_collects_without_persistence_and_uses_exact_limit(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    inventory = _inventory()
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.19.3]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.19.3]\n", ""),
            ProcessResult(0, _stdout(_host_object()), ""),
        ]
    )
    service = AnsibleService(_builder(tmp_path, paths), runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute(
            lock,
            _metadata(),
            inventory,
            "evidence-collect",
            limit=("jump-host-1",),
            variables={"deploy_scylla_vms_evidence_timeout_seconds": 10},
            readiness=_readiness(inventory),
            check=True,
        )
    assert result.evidence is not None
    assert result.evidence.status is EvidenceStatus.COMPLETE
    assert result.stdout == ""
    assert result.stderr == ""
    spec = runner.specs[-1]
    assert spec.argv[spec.argv.index("--limit") + 1] == "jump-host-1"
    assert spec.allowed_exit_codes == frozenset({0, 2, 4})
    assert not paths.diagnostics_evidence.exists()
    assert not tuple(paths.ansible_local_tmp.iterdir())


def test_service_timeout_cleans_runtime_file(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    inventory = _inventory()
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.19.3]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.19.3]\n", ""),
        ]
    )
    service = AnsibleService(_builder(tmp_path, paths), runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        runner.error = ProcessTimeoutError("sensitive timeout detail")
        with pytest.raises(AnsibleError, match="evidence-collect command failed"):
            service.execute(
                lock,
                _metadata(),
                inventory,
                "evidence-collect",
                limit=("jump-host-1",),
                variables={"deploy_scylla_vms_evidence_timeout_seconds": 10},
                readiness=_readiness(inventory),
                check=True,
            )
    assert not paths.diagnostics_evidence.exists()
    assert not tuple(paths.ansible_local_tmp.iterdir())


def test_evidence_store_atomic_guards_permissions_and_failure_preservation(
    tmp_path: Path,
) -> None:
    paths, inventory, trust = _prepared_state(tmp_path)
    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name="example", expected_provider="oci"
    )
    observed = ObservedStateStore(paths).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    collected = parse_collected_evidence(
        _stdout(_host_object()), inventory, ("jump-host-1",), 0
    )
    record = EvidenceRecord.create(
        metadata.record,
        observed,
        inventory,
        trust,
        collected,
        generation=1,
        clock=lambda: GENERATED_AT,
    )
    store = EvidenceStore(paths)
    with ClusterLock(paths, "deploy", 0) as lock:
        with pytest.raises(StatePersistenceError, match="explicit approval"):
            store.write_locked(
                record,
                observed,
                inventory,
                trust,
                approved=False,
                expected_generation=0,
                expected_digest=None,
                lock=lock,
            )
        first = store.write_locked(
            record,
            observed,
            inventory,
            trust,
            approved=True,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        with pytest.raises(StatePersistenceError, match="source bindings are stale"):
            store.write_locked(
                replace(record, generation=2),
                replace(observed, digest="sha256:" + "0" * 64),
                inventory,
                trust,
                approved=True,
                expected_generation=1,
                expected_digest=first.digest,
                lock=lock,
            )
    assert paths.diagnostics_evidence.stat().st_mode & 0o777 == 0o600
    assert store.read() == first
    assert first.record.schema_version == EVIDENCE_SCHEMA_VERSION
    before = paths.diagnostics_evidence.read_bytes()
    second = replace(
        record,
        generation=2,
        captured_at=(GENERATED_AT + timedelta(seconds=1))
        .isoformat()
        .replace("+00:00", "Z"),
    )
    failing = EvidenceStore(
        paths,
        replace=lambda _source, _target: (_ for _ in ()).throw(OSError("simulated")),
    )
    with (
        ClusterLock(paths, "deploy", 0) as lock,
        pytest.raises(StatePersistenceError, match="atomic"),
    ):
        failing.write_locked(
            second,
            observed,
            inventory,
            trust,
            approved=True,
            expected_generation=1,
            expected_digest=first.digest,
            lock=lock,
        )
    assert paths.diagnostics_evidence.read_bytes() == before
    with (
        ClusterLock(paths, "deploy", 0) as lock,
        pytest.raises(StatePersistenceError, match="concurrently"),
    ):
        store.write_locked(
            second,
            observed,
            inventory,
            trust,
            approved=True,
            expected_generation=7,
            expected_digest=first.digest,
            lock=lock,
        )


def test_evidence_persistence_schema_is_strict(tmp_path: Path) -> None:
    paths, inventory, trust = _prepared_state(tmp_path)
    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name="example", expected_provider="oci"
    )
    observed = ObservedStateStore(paths).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    collected = parse_collected_evidence(
        _stdout(_host_object()), inventory, ("jump-host-1",), 0
    )
    record = EvidenceRecord.create(
        metadata.record,
        observed,
        inventory,
        trust,
        collected,
        generation=1,
        clock=lambda: datetime(2026, 9, 17, 22, tzinfo=UTC),
    )
    value = record.to_object()
    value["raw_stdout"] = "forbidden"
    with pytest.raises(StatePersistenceError, match="fields do not match"):
        EvidenceRecord.from_object(value)


def test_evidence_playbook_runs_locally_in_check_mode() -> None:
    executable = shutil.which("ansible-playbook")
    if executable is None:
        pytest.skip("Ansible development executable is unavailable")
    playbook = (
        Path(__file__).parents[1]
        / "scylla_vms"
        / "ansible"
        / "content"
        / "playbooks"
        / "evidence-collect.yml"
    )
    extra_vars = {
        "deploy_scylla_vms_evidence_timeout_seconds": 5,
        "deploy_scylla_vms_host_key_checking_required": True,
        "deploy_scylla_vms_logical_id": "localhost",
        "deploy_scylla_vms_role": "jump-host",
    }
    result = subprocess.run(
        [
            executable,
            "--check",
            "-i",
            "localhost,",
            "-c",
            "local",
            "-e",
            json.dumps(extra_vars, separators=(",", ":"), sort_keys=True),
            str(playbook),
        ],
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="strict",
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "DSV_EVIDENCE_B64=" in result.stdout
    assert "changed=0" in result.stdout


def test_evidence_playbook_forbids_unbounded_collection() -> None:
    playbook = (
        Path(__file__).parents[1]
        / "scylla_vms"
        / "ansible"
        / "content"
        / "playbooks"
        / "evidence-collect.yml"
    )
    text = playbook.read_text(encoding="utf-8")
    for forbidden in (
        "ansible.builtin.find",
        "ansible.builtin.shell",
        "ansible.builtin.slurp",
        "ansible_env",
        "cloud-init",
        "journalctl",
        "lookup('env'",
        "package_facts",
        "printenv",
        "proc/",
    ):
        assert forbidden not in text
    assert "argv:" in text
    assert "no_log: true" in text
    assert "gather_timeout:" in text
    assert "  hosts: all\n" in text
    assert "  gather_facts: false\n" in text
    assert "  become: false\n" in text
    assert "  strategy: linear\n" in text
    assert "  serial: 5\n" in text
    assert "  any_errors_fatal: false\n" in text
    assert "  max_fail_percentage: 100\n" in text
    assert "  check_mode: true\n" in text
    assert "changed_when: false" in text
    assert "failed_when: false" in text
