import json
import os
from dataclasses import replace
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import pytest
from test_ansible import _inventory_preflight_output
from test_observed_inventory import _state
from test_ssh_trust_readiness import _trusted

from scylla_vms.ansible.service import (
    ConnectivityEvidence,
    ConnectivityStatus,
    HostConnectivityEvidence,
    HostConnectivityStatus,
)
from scylla_vms.ansible.source import stage_ansible_config
from scylla_vms.ansible.trust import StoredTrustRecord, TrustRecord, TrustStore
from scylla_vms.check_jump_hosts import JumpHostState, _report
from scylla_vms.cli import main
from scylla_vms.errors import ExitCode
from scylla_vms.inventory import (
    InventoryStore,
    StoredInventoryRecord,
    prepare_inventory_refresh,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import ObservedStateStore
from scylla_vms.persistence import ClusterMetadataStore
from scylla_vms.process import ProcessResult, ProcessSpec, ProcessTimeoutError
from scylla_vms.state import StatePaths

GENERATED_AT = datetime(2026, 9, 17, 22, 0, tzinfo=UTC)


class FakeRunner:
    def __init__(
        self,
        results: list[ProcessResult],
        *,
        fail_at: int | None = None,
        error: Exception | None = None,
    ) -> None:
        self.results = list(results)
        self.fail_at = fail_at
        self.error = error
        self.specs: list[ProcessSpec] = []
        self.payloads: list[object] = []

    def run(self, spec: ProcessSpec) -> ProcessResult:
        self.specs.append(spec)
        if "--extra-vars" in spec.argv:
            path = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
            self.payloads.append(json.loads(path.read_text(encoding="utf-8")))
        if self.fail_at == len(self.specs):
            raise self.error or ProcessTimeoutError("simulated timeout")
        result = self.results.pop(0)
        stdout = result.stdout
        stderr = result.stderr
        for value in spec.sensitive_values:
            stdout = stdout.replace(value, "[REDACTED]")
            stderr = stderr.replace(value, "[REDACTED]")
        return ProcessResult(result.exit_code, stdout, stderr)


def _prepared_state(
    tmp_path: Path,
) -> tuple[StatePaths, StoredInventoryRecord, StoredTrustRecord]:
    paths, metadata, observed_record = _state(tmp_path)
    ClusterMetadataStore(paths).write(
        metadata, expected_generation=0, expected_digest=None
    )
    with ClusterLock(paths, "deploy", 0) as lock:
        observed = ObservedStateStore(paths).write_locked(
            observed_record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        prepared = prepare_inventory_refresh(
            metadata, observed, None, clock=lambda: GENERATED_AT
        )
        assert prepared.candidate is not None
        inventory = InventoryStore(paths).write_locked(
            prepared.candidate,
            expected_generation=0,
            expected_digest=None,
            approved=True,
            lock=lock,
        )
        entries = tuple(
            _trusted(host, index)
            for index, host in enumerate(inventory.record.inventory.hosts, start=1)
        )
        trust_record = TrustRecord.create(
            observed.record, inventory.record, entries, generation=1
        )
        trust = TrustStore(paths).write_locked(
            trust_record,
            observed,
            inventory,
            approved=True,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        stage_ansible_config(paths, lock=lock)
    return paths, inventory, trust


def _graph(inventory: StoredInventoryRecord) -> str:
    record = inventory.record
    return "@all:\n" + "".join(
        f"  |--@{group.name}:\n" + "".join(f"  |  |--{host}\n" for host in group.hosts)
        for group in record.inventory.groups
    )


def _results(
    inventory: StoredInventoryRecord, recap: str, *, exit_code: int = 0
) -> list[ProcessResult]:
    record = inventory.record
    return [
        ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
        ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
        ProcessResult(0, json.dumps(record.to_machine_object()), ""),
        ProcessResult(0, _graph(inventory), ""),
        ProcessResult(0, _inventory_preflight_output(inventory), ""),
        ProcessResult(exit_code, recap, ""),
    ]


def _recap(*, unreachable: int = 0, failed: int = 0) -> str:
    return (
        "PLAY RECAP *****\n"
        f"jump-host-1 : ok=2 changed=0 unreachable={unreachable} "
        f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


def _tcp_recap(
    target: str,
    role: str,
    port: int,
    *,
    status: str = "passed",
) -> str:
    return (
        f"TASK [Emit redacted destination TCP evidence]\n"
        f'ok: [jump-host-1] => {{"msg": "DSV_TCP jump-host-1 '
        f'{target} {role} {port} {status}"}}\n' + _recap()
    )


def _arguments(paths: StatePaths, *extra: str, json_output: bool = True) -> list[str]:
    return [
        "--cluster-name",
        "example",
        "--state-dir",
        str(paths.state_root),
        *(("--json",) if json_output else ()),
        "check-jump-hosts",
        *extra,
    ]


def _run(
    paths: StatePaths,
    runner: FakeRunner,
    *extra: str,
    json_output: bool = True,
) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    result = main(
        _arguments(paths, *extra, json_output=json_output),
        environ={},
        stdout=stdout,
        stderr=stderr,
        clock=lambda: GENERATED_AT,
        process_runner=runner,
        ansible_playbook_executable=Path(os.sys.executable).resolve(),
        ansible_inventory_executable=Path(os.sys.executable).resolve(),
    )
    return result, stdout.getvalue(), stderr.getvalue()


def _snapshot(paths: StatePaths) -> dict[str, bytes]:
    return {
        str(path.relative_to(paths.state_root)): path.read_bytes()
        for path in (
            paths.cluster_metadata,
            paths.terraform_observed,
            paths.ansible_inventory,
            paths.ansible_trust,
            paths.known_hosts,
            paths.ansible_ssh_config,
        )
    }


def test_check_jump_hosts_json_success_exact_limits_and_no_writes(
    tmp_path: Path,
) -> None:
    paths, inventory, _ = _prepared_state(tmp_path)
    runner = FakeRunner(_results(inventory, _recap()))
    before = _snapshot(paths)
    result, stdout, stderr = _run(
        paths,
        runner,
        "--jump-host",
        "jump-host-1",
        "--connect-timeout-seconds",
        "2.5",
    )
    report = json.loads(stdout)
    assert result == ExitCode.SUCCESS
    assert stderr == ""
    assert report["schema_version"] == "deploy-scylla-vms.check-jump-hosts/v2"
    assert report["selection"]["stable_ids"] == ["jump-host-1"]
    assert report["checks"]["inventory_preflight"] == "passed"
    assert report["checks"]["connectivity"] == "success"
    assert report["jumps"][0]["connectivity"] == "reachable"
    playbook_specs = [spec for spec in runner.specs if "--limit" in spec.argv]
    assert len(playbook_specs) == 2
    assert all(
        spec.argv[spec.argv.index("--limit") + 1] == "jump-host-1"
        for spec in playbook_specs
    )
    assert runner.payloads[1] == {
        "deploy_scylla_vms_connect_timeout_seconds": 2.5,
        "deploy_scylla_vms_destination_probes": [],
        "deploy_scylla_vms_probe_timeout_seconds": 3,
    }
    assert all(
        spec.environment.for_subprocess()["ANSIBLE_HOST_KEY_CHECKING"] == "True"
        for spec in runner.specs
    )
    assert _snapshot(paths) == before
    rendered = json.dumps(report)
    assert "203.0.113.10" not in rendered
    assert "PRIVATE KEY" not in rendered


def test_check_jump_hosts_human_and_partial_failure(tmp_path: Path) -> None:
    paths, inventory, _ = _prepared_state(tmp_path)
    runner = FakeRunner(_results(inventory, _recap(unreachable=1), exit_code=4))
    result, stdout, stderr = _run(paths, runner, json_output=False)
    assert result == ExitCode.ANSIBLE
    assert stderr == ""
    assert "Cluster: example" in stdout
    assert "Connectivity: failure" in stdout
    assert "jump-host-1: unreachable" in stdout
    assert "203.0.113.10" not in stdout


@pytest.mark.parametrize(
    ("role", "port", "target"),
    [
        ("scylla", 9042, "scylla-ad-1-1"),
        ("manager", 5080, "manager-1"),
        ("monitoring", 9090, "monitoring-1"),
    ],
)
def test_destination_tcp_probe_success_exact_typed_vars_and_redaction(
    tmp_path: Path, role: str, port: int, target: str
) -> None:
    paths, inventory, _ = _prepared_state(tmp_path)
    before = _snapshot(paths)
    runner = FakeRunner(_results(inventory, _tcp_recap(target, role, port)))
    result, stdout, stderr = _run(
        paths,
        runner,
        "--destination-check",
        f"{role}={port}",
        "--destination",
        role,
    )
    report = json.loads(stdout)
    assert result == ExitCode.SUCCESS
    assert stderr == ""
    assert report["checks"]["destination_tcp"] == "success"
    assert report["destination_probes"] == [
        {
            "jump_host_id": "jump-host-1",
            "port": port,
            "protocol": "tcp",
            "role": role,
            "status": "passed",
            "target_logical_id": target,
        }
    ]
    probe = runner.payloads[1]["deploy_scylla_vms_destination_probes"][0]
    assert probe == {
        "address": next(
            host.private_address
            for host in inventory.record.inventory.hosts
            if host.logical_id == target
        ),
        "jump_host_id": "jump-host-1",
        "port": port,
        "role": role,
        "target_logical_id": target,
    }
    assert _snapshot(paths) == before
    assert probe["address"] not in stdout
    assert all(
        not isinstance(value, str) or "--limit" not in value for value in probe.values()
    )


def test_destination_tcp_probe_partial_failure_and_all_targets(
    tmp_path: Path,
) -> None:
    paths, inventory, _ = _prepared_state(tmp_path)
    runner = FakeRunner(
        _results(
            inventory,
            _tcp_recap("scylla-ad-1-1", "scylla", 9042, status="failed"),
        )
    )
    result, stdout, stderr = _run(
        paths,
        runner,
        "--depth",
        "all-targets",
        "--destination-check",
        "scylla=9042",
    )
    report = json.loads(stdout)
    assert result == ExitCode.ANSIBLE
    assert stderr == ""
    assert report["checks"]["connectivity"] == "partial-failure"
    assert report["checks"]["destination_tcp"] == "failure"
    assert report["destination_probes"][0]["status"] == "failed"


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (("--destination-check", "jump-host=22"), "unknown role"),
        (("--destination-check", "scylla=22"), "not allowlisted"),
        (("--destination-check", "scylla=0"), "between 1 and 65535"),
        (("--destination-check", "scylla=65536"), "between 1 and 65535"),
        (("--destination-check", "scylla=tcp://9042"), "base-10 integer"),
        (("--destination-check", "scylla-1=9042"), "unknown role"),
        (("--destination-check", "198.51.100.10=9042"), "unknown role"),
        (
            (
                "--destination-check",
                "scylla=9042",
                "--destination-check",
                "scylla=9042",
            ),
            "duplicate key",
        ),
    ],
)
def test_destination_tcp_probe_rejects_malformed_public_or_unapproved_syntax(
    tmp_path: Path, arguments: tuple[str, ...], message: str
) -> None:
    paths, _, _ = _prepared_state(tmp_path)
    result, stdout, stderr = _run(paths, FakeRunner([]), *arguments)
    assert result == ExitCode.CONFIGURATION
    assert stdout == ""
    assert message in stderr


def test_destination_tcp_probe_rejects_depth_and_destination_conflicts(
    tmp_path: Path,
) -> None:
    paths, _, _ = _prepared_state(tmp_path)
    for arguments, message in (
        (
            ("--depth", "bastion", "--destination-check", "scylla=9042"),
            "requires --depth route",
        ),
        (
            (
                "--destination",
                "manager",
                "--destination-check",
                "scylla=9042",
            ),
            "excluded by --destination",
        ),
    ):
        runner = FakeRunner([])
        result, stdout, stderr = _run(paths, runner, *arguments)
        assert result == ExitCode.CONFIGURATION
        assert stdout == ""
        assert message in stderr
        assert not runner.specs


def test_check_jump_hosts_filters_and_unsupported_scopes(tmp_path: Path) -> None:
    paths, inventory, _ = _prepared_state(tmp_path)
    runner = FakeRunner(_results(inventory, _recap()))
    result, stdout, stderr = _run(paths, runner, "--jump-host", "manager-1")
    assert result == ExitCode.CONFIGURATION
    assert stdout == ""
    assert "unknown or non-jump" in stderr
    assert not runner.specs

    result, stdout, stderr = _run(
        paths,
        FakeRunner([]),
        "--jump-host",
        "jump-host-1",
        "--jump-host",
        "jump-host-1",
    )
    assert result == ExitCode.CONFIGURATION
    assert stdout == ""
    assert "--jump-host values must be unique" in stderr

    result, stdout, stderr = _run(paths, FakeRunner([]), "--depth", "all-targets")
    assert result == ExitCode.UNSAFE_REFUSAL
    assert stdout == ""
    assert "no checks were performed" in stderr


@pytest.mark.parametrize(
    ("missing", "message"),
    [
        ("terraform_observed", "required state path does not exist"),
        ("ansible_inventory", "required state path does not exist"),
        ("ansible_trust", "required state path does not exist"),
    ],
)
def test_check_jump_hosts_missing_evidence_refuses_before_ansible(
    tmp_path: Path, missing: str, message: str
) -> None:
    paths, _, _ = _prepared_state(tmp_path)
    getattr(paths, missing).unlink()
    runner = FakeRunner([])
    result, stdout, stderr = _run(paths, runner)
    assert result == ExitCode.UNSAFE_REFUSAL
    assert stdout == ""
    assert message in stderr
    assert not runner.specs


def test_check_jump_hosts_preflight_and_timeout_reports(tmp_path: Path) -> None:
    paths, inventory, _ = _prepared_state(tmp_path)
    preflight = FakeRunner(
        _results(inventory, _recap())[:4],
        fail_at=5,
        error=ProcessTimeoutError("fake path and address"),
    )
    result, stdout, stderr = _run(paths, preflight)
    assert result == ExitCode.ANSIBLE
    assert stderr == ""
    assert json.loads(stdout)["checks"]["inventory_preflight"] == "timeout"

    connectivity = FakeRunner(
        _results(inventory, _recap())[:5],
        fail_at=6,
        error=ProcessTimeoutError("fake path and address"),
    )
    result, stdout, stderr = _run(paths, connectivity)
    assert result == ExitCode.ANSIBLE
    assert stderr == ""
    assert json.loads(stdout)["checks"]["connectivity"] == "timeout"


def test_check_jump_hosts_zero_and_multiple_jump_projections(tmp_path: Path) -> None:
    paths, inventory, trust = _prepared_state(tmp_path)
    cluster = ClusterMetadataStore(paths).read(
        expected_cluster_name="example", expected_provider="oci"
    )
    observed = ObservedStateStore(paths).read(
        expected_cluster_uuid=cluster.record.cluster_uuid,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    jump = next(
        host
        for host in inventory.record.inventory.hosts
        if host.logical_id == "jump-host-1"
    )
    empty = JumpHostState(
        cluster, observed, inventory, trust, (), "route", ("assigned",), ()
    )
    empty_report = _report(empty, None, None, generated_at="2026-09-17T22:00:00Z")
    assert empty_report.selection["count"] == 0
    assert empty_report.checks["connectivity"] == "not-performed-no-jump-hosts"
    second = replace(
        jump,
        logical_id="jump-host-2",
        provider_id="ocid1.instance.oc1.iad.fakejumphost2",
    )
    multiple = replace(empty, selected=(jump, second))
    evidence = ConnectivityEvidence(
        ConnectivityStatus.PARTIAL_FAILURE,
        (
            HostConnectivityEvidence("jump-host-1", HostConnectivityStatus.REACHABLE),
            HostConnectivityEvidence("jump-host-2", HostConnectivityStatus.UNREACHABLE),
        ),
    )
    multiple_report = _report(
        multiple, None, evidence, generated_at="2026-09-17T22:00:00Z"
    )
    assert multiple_report.selection["stable_ids"] == [
        "jump-host-1",
        "jump-host-2",
    ]
    assert multiple_report.exit_code == ExitCode.ANSIBLE


@pytest.mark.parametrize(
    "recap",
    ["missing recap", "PLAY RECAP *****\nbad line\n", "x" * 262_145],
)
def test_check_jump_hosts_malformed_or_oversized_evidence_is_redacted_failure(
    tmp_path: Path, recap: str
) -> None:
    paths, inventory, _ = _prepared_state(tmp_path)
    runner = FakeRunner(_results(inventory, recap))
    result, stdout, stderr = _run(paths, runner)
    assert result == ExitCode.ANSIBLE
    assert stderr == ""
    assert json.loads(stdout)["checks"]["connectivity"] == "invalid-evidence"


@pytest.mark.parametrize("path_name", ["known_hosts", "ansible_ssh_config"])
def test_check_jump_hosts_changed_trust_or_route_refuses_before_playbooks(
    tmp_path: Path, path_name: str
) -> None:
    paths, inventory, _ = _prepared_state(tmp_path)
    path = getattr(paths, path_name)
    path.write_text("tampered\n", encoding="utf-8")
    path.chmod(0o600)
    runner = FakeRunner(_results(inventory, _recap()))
    result, stdout, stderr = _run(paths, runner)
    assert result == ExitCode.DRIFT_CONFLICT
    assert stdout == ""
    assert "conflicts" in stderr
    assert not runner.specs


def test_check_jump_hosts_lock_conflict_and_address_flag_refusal(
    tmp_path: Path,
) -> None:
    paths, inventory, _ = _prepared_state(tmp_path)
    runner = FakeRunner(_results(inventory, _recap()))
    with ClusterLock(paths, "deploy", 0):
        result, stdout, stderr = _run(paths, runner)
    assert result == ExitCode.LOCK_CONFLICT
    assert stdout == ""
    assert "lock is held" in stderr
    assert not runner.specs

    result, stdout, stderr = _run(paths, FakeRunner([]), "--include-addresses")
    assert result == ExitCode.CONFIGURATION
    assert stdout == ""
    assert "unrecognized arguments" in stderr
