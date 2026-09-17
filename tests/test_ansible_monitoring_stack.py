import base64
import json
import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from test_ansible import DIGEST, FakeRunner, _builder, _metadata, _paths
from test_ssh_trust_readiness import _host, _inventory, _observed

from scylla_vms.ansible.base_os import (
    BaseOsEvidence,
    BaseOsHostEvidence,
    BaseOsStatus,
)
from scylla_vms.ansible.monitoring_stack import (
    ARTIFACT_DIGEST,
    ARTIFACT_URI,
    CACHE_PATH,
    DOCUMENTED_PORTS,
    INSTALL_ROOT,
    LISTEN_POLICY,
    MONITORING_STACK_SCHEMA_VERSION,
    SOURCE_COMMIT,
    STACK_ARTIFACTS,
    STACK_RELEASE_LINE,
    STACK_SERVICE_UNIT,
    STACK_VERSION,
    MonitoringStackStatus,
    build_monitoring_stack_payload,
    parse_monitoring_stack_execution,
)
from scylla_vms.ansible.readiness import (
    EvidenceStatus,
    ReadinessReport,
    RouteReadiness,
    RouteReport,
    TrustReadiness,
)
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.desired import HostRole, ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.process import ProcessResult, ProcessTimeoutError

VERSION = STACK_VERSION


def _cluster_inventory():
    jump = _host(
        "jump-host-1",
        HostRole.JUMP_HOST,
        "10.0.0.10",
        public="203.0.113.10",
    )
    scylla = _host(
        "scylla-ad-1-1",
        HostRole.SCYLLA,
        "10.0.0.20",
        jump="jump-host-1",
    )
    manager = _host(
        "manager-1",
        HostRole.MANAGER,
        "10.0.0.30",
        jump="jump-host-1",
    )
    monitoring = _host(
        "monitoring-1",
        HostRole.MONITORING,
        "10.0.0.40",
        jump="jump-host-1",
    )
    inventory = _inventory((jump, scylla, manager, monitoring))
    return inventory, _observed(inventory)


def _readiness(inventory: object) -> ReadinessReport:
    stored = cast(Any, inventory)
    return ReadinessReport(
        EvidenceStatus.FRESH,
        EvidenceStatus.FRESH,
        TrustReadiness.COMPLETE,
        RouteReadiness.VALID,
        stored.record.source_manifest_generation,
        stored.record.source_manifest_digest,
        stored.record.generation,
        stored.digest,
        1,
        DIGEST,
        len(stored.record.inventory.hosts),
        len(stored.record.inventory.hosts),
        (),
        RouteReport(RouteReadiness.VALID, 1, 3, 1, ()),
        tuple((classification, ()) for classification in OperationClassification),
    )


def _base_os(logical_id: str = "monitoring-1") -> BaseOsEvidence:
    return BaseOsEvidence(
        BaseOsStatus.NO_CHANGE,
        (
            BaseOsHostEvidence(
                logical_id,
                BaseOsStatus.NO_CHANGE,
                False,
                False,
                "already-current",
            ),
        ),
    )


def _context() -> tuple[dict[str, object], object, object, object]:
    inventory, observed = _cluster_inventory()
    metadata = _metadata()
    payload = build_monitoring_stack_payload(
        metadata,
        observed,
        inventory,
        _readiness(inventory),
        _base_os(),
        logical_id="monitoring-1",
        image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
        architecture="amd64",
        stack_version=VERSION,
        cluster_spec_digest=DIGEST,
    )
    return payload, metadata, observed, inventory


def _result(payload: dict[str, object], status: str = "no-change") -> dict[str, object]:
    success = status in {"installed", "no-change"}
    return {
        "artifact_digest": cast(dict[str, object], payload["artifact"])["digest"],
        "artifacts": dict(payload["artifacts"]) if success else {},
        "auth_configured": False,
        "blockers": [] if status != "failed" else ["execution-failed"],
        "compose_generated": False,
        "containers_started": False,
        "documented_ports": payload["documented_ports"],
        "installed_version": payload["stack_version"] if success else None,
        "listen_policy": LISTEN_POLICY,
        "logical_id": payload["logical_id"],
        "manager_registration_performed": False,
        "provenance": payload["provenance"],
        "public_bind": False,
        "requested_release": payload["release_line"],
        "requested_version": payload["stack_version"],
        "schema_version": MONITORING_STACK_SCHEMA_VERSION,
        "scylla_started": False,
        "secrets_written": False,
        "service_enabled": False if success else None,
        "service_inactive": True if success else None,
        "source_commit": payload["source_commit"],
        "status": status,
        "targets_generated": False,
    }


def _stdout(
    payload: dict[str, object],
    status: str = "no-change",
    *,
    failed: int = 0,
) -> str:
    encoded = base64.b64encode(
        json.dumps(_result(payload, status), sort_keys=True).encode()
    ).decode()
    changed = 1 if status == "installed" else 0
    return (
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_MONITORING_STACK_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=12 changed={changed} unreachable=0 "
        f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


def test_monitoring_stack_payload_is_exact_and_rejects_unsafe_versions() -> None:
    payload, metadata, observed, inventory = _context()
    assert payload["release_line"] == STACK_RELEASE_LINE
    assert payload["channel"] == "stable"
    assert payload["stack_version"] == VERSION
    assert payload["artifacts"] == STACK_ARTIFACTS
    assert payload["service_unit"] == STACK_SERVICE_UNIT
    assert payload["listen_policy"] == LISTEN_POLICY
    assert payload["documented_ports"] == DOCUMENTED_PORTS
    assert payload["install_root"] == INSTALL_ROOT
    assert payload["cache_path"] == CACHE_PATH
    assert payload["source_commit"] == SOURCE_COMMIT
    assert payload["auth_configured"] is False
    assert payload["compose_generated"] is False
    assert payload["containers_started"] is False
    assert payload["targets_generated"] is False
    assert payload["manager_registration_performed"] is False
    assert payload["public_bind"] is False
    assert payload["scylla_started"] is False
    assert payload["secrets_written"] is False
    assert cast(dict[str, object], payload["artifact"])["uri"] == ARTIFACT_URI
    assert cast(dict[str, object], payload["artifact"])["digest"] == ARTIFACT_DIGEST
    assert "latest" not in json.dumps(payload, sort_keys=True)

    readiness = _readiness(inventory)
    for version in ("latest", "4.16", "4.15.0", "4.16.1", "4.16.0-rc1"):
        with pytest.raises(AnsibleError, match=r"exact 4\.16\.0"):
            build_monitoring_stack_payload(
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                readiness,
                _base_os(),
                logical_id="monitoring-1",
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                stack_version=version,
                cluster_spec_digest=DIGEST,
            )


def test_monitoring_stack_refuses_non_monitoring_targets_stale_base_os_and_os() -> None:
    payload, metadata, observed, inventory = _context()
    assert payload
    readiness = _readiness(inventory)
    for logical_id in ("scylla-ad-1-1", "jump-host-1", "manager-1"):
        with pytest.raises(StateConflictError, match="monitoring stable ID"):
            build_monitoring_stack_payload(
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                readiness,
                _base_os(logical_id),
                logical_id=logical_id,
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                stack_version=VERSION,
                cluster_spec_digest=DIGEST,
            )
    reboot = BaseOsEvidence(
        BaseOsStatus.REBOOT_REQUIRED,
        (
            replace(
                _base_os().hosts[0],
                status=BaseOsStatus.REBOOT_REQUIRED,
                reboot_required=True,
            ),
        ),
    )
    missing = BaseOsEvidence(BaseOsStatus.FAILURE, ())
    stale = replace(_readiness(inventory), trust_digest=None)
    ubuntu = ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT)
    for base_os, ready in (
        (reboot, readiness),
        (missing, readiness),
        (_base_os(), stale),
    ):
        with pytest.raises(StateConflictError):
            build_monitoring_stack_payload(
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                ready,
                base_os,
                logical_id="monitoring-1",
                image_filter=ubuntu,
                architecture="amd64",
                stack_version=VERSION,
                cluster_spec_digest=DIGEST,
            )
    with pytest.raises(StateConflictError, match=r"Ubuntu 24\.04"):
        build_monitoring_stack_payload(
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            readiness,
            _base_os(),
            logical_id="monitoring-1",
            image_filter=ImageFilter("Oracle Linux", "9", ImageVersionMatch.EXACT),
            architecture="amd64",
            stack_version=VERSION,
            cluster_spec_digest=DIGEST,
        )


@pytest.mark.parametrize(
    "status", ["installed", "no-change", "not-predicted", "failed"]
)
def test_monitoring_stack_result_parser_statuses(status: str) -> None:
    payload, *_ = _context()
    evidence = parse_monitoring_stack_execution(
        _stdout(payload, status, failed=1 if status == "failed" else 0),
        expected_payload=payload,
        exit_code=2 if status == "failed" else 0,
    )
    assert evidence.status is MonitoringStackStatus(status)
    assert evidence.listen_policy == LISTEN_POLICY
    assert evidence.targets_generated is False
    assert evidence.auth_configured is False
    assert evidence.public_bind is False
    assert evidence.manager_registration_performed is False
    assert evidence.scylla_started is False
    assert evidence.secrets_written is False
    assert evidence.compose_generated is False
    assert evidence.containers_started is False
    assert evidence.documented_ports == tuple(sorted(DOCUMENTED_PORTS.items()))
    if evidence.status in {
        MonitoringStackStatus.INSTALLED,
        MonitoringStackStatus.NO_CHANGE,
    }:
        assert evidence.service_enabled is False
        assert evidence.service_inactive is True
        assert evidence.artifacts == tuple(sorted(STACK_ARTIFACTS.items()))
        assert evidence.installed_version == VERSION


def test_monitoring_stack_parser_refuses_malformed_public_bind_and_conflicts() -> None:
    payload, *_ = _context()
    with pytest.raises(AnsibleError, match="exceeds"):
        parse_monitoring_stack_execution(
            "x" * (512 * 1024 + 1), expected_payload=payload, exit_code=2
        )
    with pytest.raises(AnsibleError):
        parse_monitoring_stack_execution(
            _stdout(payload, "no-change", failed=1),
            expected_payload=payload,
            exit_code=2,
        )
    for field, value in (
        ("auth_configured", True),
        ("compose_generated", True),
        ("containers_started", True),
        ("manager_registration_performed", True),
        ("public_bind", True),
        ("scylla_started", True),
        ("secrets_written", True),
        ("targets_generated", True),
        ("service_enabled", True),
        ("service_inactive", False),
        ("listen_policy", "0.0.0.0"),
    ):
        claimed = _result(payload, "no-change")
        claimed[field] = value
        encoded = base64.b64encode(
            json.dumps(claimed, sort_keys=True).encode()
        ).decode()
        stdout = (
            f"ok: [{payload['logical_id']}] => "
            f'{{"msg":"DSV_MONITORING_STACK_B64={encoded}"}}\nPLAY RECAP *****\n'
            f"{payload['logical_id']} : ok=12 changed=0 unreachable=0 "
            "failed=0 skipped=0 rescued=0 ignored=0\n"
        )
        with pytest.raises(AnsibleError):
            parse_monitoring_stack_execution(
                stdout, expected_payload=payload, exit_code=0
            )
    failed = (
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=1 changed=0 unreachable=1 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    evidence = parse_monitoring_stack_execution(
        failed, expected_payload=payload, exit_code=4
    )
    assert evidence.status is MonitoringStackStatus.FAILED
    assert evidence.blockers == ("execution-failed",)
    definition = get_playbook("monitoring-stack")
    with pytest.raises(AnsibleError, match="variable value is invalid"):
        definition.validate_variables(
            {"deploy_scylla_vms_monitoring_stack": {"note": "token: obviously-fake"}}
        )


@pytest.mark.parametrize(
    ("check", "status"), [(False, "installed"), (True, "not-predicted")]
)
def test_service_success_failure_timeout_malformed_and_redaction(
    tmp_path: Path, check: bool, status: str
) -> None:
    payload, metadata, observed, inventory = _context()
    paths = _paths(tmp_path)
    result_body = _result(payload, status)
    encoded = base64.b64encode(
        json.dumps(result_body, sort_keys=True).encode()
    ).decode()
    changed = 1 if status == "installed" else 0
    stdout = (
        "203.0.113.10 secret-token\n"
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_MONITORING_STACK_B64={encoded}"}}\nPLAY RECAP *****\n'
        f"{payload['logical_id']} : ok=12 changed={changed} unreachable=0 "
        "failed=0 skipped=0 rescued=0 ignored=0\n"
    )
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(0, stdout, ""),
        ]
    )
    service = AnsibleService(_builder(tmp_path, paths), runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute_monitoring_stack(
            lock,
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            _base_os(),
            limit=("monitoring-1",),
            readiness=_readiness(inventory),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
            stack_version=VERSION,
            cluster_spec_digest=DIGEST,
            check=check,
        )
    assert result.monitoring_stack is not None
    assert result.monitoring_stack.status is MonitoringStackStatus(status)
    assert result.stdout == result.stderr == ""
    assert runner.runtime_payloads[-1] == {
        "deploy_scylla_vms_monitoring_stack": payload
    }
    assert "--limit" in runner.specs[-1].argv
    assert "monitoring-1" in runner.specs[-1].argv
    assert ("--check" in runner.specs[-1].argv) is check
    assert "203.0.113.10" in runner.specs[-1].sensitive_values
    assert "10.0.0.40" in runner.specs[-1].sensitive_values
    assert not tuple(paths.ansible_local_tmp.iterdir())

    fail_runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(2, _stdout(payload, "failed", failed=1), ""),
        ]
    )
    fail_service = AnsibleService(_builder(tmp_path, paths), fail_runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        fail_service.version(lock)
        failed = fail_service.execute_monitoring_stack(
            lock,
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            _base_os(),
            limit=("monitoring-1",),
            readiness=_readiness(inventory),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
            stack_version=VERSION,
            cluster_spec_digest=DIGEST,
        )
    assert failed.monitoring_stack is not None
    assert failed.monitoring_stack.status is MonitoringStackStatus.FAILED

    timeout_runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
        ]
    )
    timeout_service = AnsibleService(_builder(tmp_path, paths), timeout_runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        timeout_service.version(lock)
        timeout_runner.error = ProcessTimeoutError("token=obviously-fake")
        with pytest.raises(
            AnsibleError, match="monitoring-stack command failed"
        ) as caught:
            timeout_service.execute_monitoring_stack(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                _base_os(),
                limit=("monitoring-1",),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                stack_version=VERSION,
                cluster_spec_digest=DIGEST,
            )
    assert "obviously-fake" not in str(caught.value)
    assert not tuple(paths.ansible_local_tmp.iterdir())

    malformed_runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(0, "PLAY RECAP *****\n", ""),
        ]
    )
    malformed_service = AnsibleService(_builder(tmp_path, paths), malformed_runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        malformed_service.version(lock)
        with pytest.raises(AnsibleError, match="recap membership conflicts"):
            malformed_service.execute_monitoring_stack(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                _base_os(),
                limit=("monitoring-1",),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                stack_version=VERSION,
                cluster_spec_digest=DIGEST,
            )


def test_execute_monitoring_stack_requires_one_monitoring_target(
    tmp_path: Path,
) -> None:
    payload, metadata, observed, inventory = _context()
    assert payload
    paths = _paths(tmp_path)
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
        ]
    )
    service = AnsibleService(_builder(tmp_path, paths), runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        with pytest.raises(StateConflictError, match="one exact target"):
            service.execute_monitoring_stack(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                _base_os(),
                limit=("monitoring-1", "manager-1"),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                stack_version=VERSION,
                cluster_spec_digest=DIGEST,
            )
        with pytest.raises(StateConflictError, match="monitoring stable ID"):
            service.execute_monitoring_stack(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                _base_os("scylla-ad-1-1"),
                limit=("scylla-ad-1-1",),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                stack_version=VERSION,
                cluster_spec_digest=DIGEST,
            )


def test_monitoring_stack_registry_dependency_and_static_safety() -> None:
    definition = get_playbook("monitoring-stack")
    assert definition.source_available
    assert definition.hosts == "monitoring"
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert definition.check_mode is CheckMode.PREVIEW
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.classification is OperationClassification.MUTATING
    assert definition.pre_health_gate is False
    assert definition.post_health_gate is False
    assert definition.tags == (
        "monitoring-stack",
        "preflight",
        "packages",
        "verify",
    )
    assert callable(AnsibleService.execute_monitoring_stack)
    bundle_paths = {item.path for item in load_ansible_source_bundle().files}
    assert {
        "playbooks/monitoring-stack.yml",
        "playbooks/roles/monitoring_stack/files/scylla-monitoring-4.16.0.provenance.yml",
    } <= bundle_paths
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content"
    playbook = (root / "playbooks/monitoring-stack.yml").read_text(encoding="utf-8")
    provenance = (
        root
        / "playbooks/roles/monitoring_stack/files/scylla-monitoring-4.16.0.provenance.yml"
    ).read_text(encoding="utf-8")
    for required in (
        "gather_facts: true",
        "serial: 1",
        "any_errors_fatal: true",
        "hosts: monitoring",
        "ansible.builtin.get_url:",
        "ansible.builtin.unarchive:",
        "validate_certs: true",
        "checksum:",
        "listen_policy': 'not-started'",
        "auth_configured': false",
        "compose_generated': false",
        "containers_started': false",
        "public_bind': false",
        "targets_generated': false",
        "secrets_written': false",
        "4.16.0",
        SOURCE_COMMIT,
        ARTIFACT_DIGEST.removeprefix("sha256:"),
        "docker.service",
    ):
        assert required in playbook
    lowered = playbook.lower()
    for forbidden in (
        "ansible.builtin.shell",
        "apt_key",
        "keyserver",
        "curl",
        "wget",
        "http://",
        "state: started",
        "latest",
        "0.0.0.0",
        "start-all.sh",
        "docker-compose",
        "gf_security_admin_password",
        "gf_auth_anonymous",
        "scylla_servers.yml",
        "scyllamgr_setup",
        "node_exporter_install",
        "auth_token:",
        "selinux",
        "reboot:",
        "validate_certs: false",
        "trusted=yes",
        "firewall",
        "iptables",
        "sshd_config",
        "hosts: scylla",
        "hosts: jump",
        "hosts: manager",
        "hosts: all",
    ):
        assert forbidden not in lowered
    for required in (
        'retrieved_at: "2026-09-18"',
        ARTIFACT_DIGEST.removeprefix("sha256:"),
        SOURCE_COMMIT,
        "monitoring.docs.scylladb.com/stable/install/monitoring-stack.html",
        'official_stack_version: "4.16.0"',
        'official_scylla_versions_include: "2026.2"',
        "grafana: 3000",
        "prometheus: 9090",
        "alertmanager: 9093",
        "unsigned_container_images: not-pulled",
        "Refuse latest",
        "This slice places the digest-checked official archive only",
    ):
        assert required in provenance


def test_monitoring_stack_playbook_syntax_check_is_local_and_write_free(
    tmp_path: Path,
) -> None:
    executable = shutil.which("ansible-playbook")
    if executable is None:
        pytest.skip("Ansible development executable is unavailable")
    playbook = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/monitoring-stack.yml"
    )
    local_tmp = tmp_path / "ansible-tmp"
    local_tmp.mkdir()
    result = subprocess.run(
        [
            executable,
            "--syntax-check",
            "-i",
            "localhost,",
            str(playbook),
        ],
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="strict",
        timeout=30,
        env={
            **os.environ,
            "ANSIBLE_LOCAL_TEMP": str(local_tmp),
            "HOME": str(tmp_path),
        },
    )
    assert result.returncode == 0, result.stderr
    assert "playbook: " in result.stdout
    assert not tuple(local_tmp.iterdir())
