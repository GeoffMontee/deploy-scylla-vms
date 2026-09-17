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
    DOCUMENTED_PORTS,
    LISTEN_POLICY,
    SOURCE_COMMIT,
    STACK_ARTIFACTS,
    STACK_RELEASE_LINE,
    STACK_VERSION,
    MonitoringStackEvidence,
    MonitoringStackStatus,
)
from scylla_vms.ansible.monitoring_targets import (
    INSTALL_ROOT,
    MANAGER_METRICS_PORT,
    MONITORING_TARGETS_SCHEMA_VERSION,
    SCRAPE_PORTS,
    SCRAPE_READINESS,
    STACK_SERVICE_UNIT,
    TARGET_DIRECTORY,
    TARGET_FILES,
    MonitoringTargetsStatus,
    build_monitoring_targets_payload,
    parse_monitoring_targets_execution,
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


def _stack(
    inventory: object,
    observed: object,
    logical_id: str = "monitoring-1",
    *,
    status: MonitoringStackStatus = MonitoringStackStatus.NO_CHANGE,
) -> MonitoringStackEvidence:
    stored = cast(Any, inventory)
    observed_stored = cast(Any, observed)
    return MonitoringStackEvidence(
        logical_id,
        status,
        STACK_RELEASE_LINE,
        STACK_VERSION,
        STACK_VERSION if status is not MonitoringStackStatus.FAILED else None,
        tuple(sorted(STACK_ARTIFACTS.items()))
        if status is not MonitoringStackStatus.FAILED
        else (),
        ARTIFACT_DIGEST,
        SOURCE_COMMIT,
        False if status is not MonitoringStackStatus.FAILED else None,
        True if status is not MonitoringStackStatus.FAILED else None,
        False,
        LISTEN_POLICY,
        tuple(sorted(DOCUMENTED_PORTS.items())),
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        (
            ("base_os_digest", DIGEST),
            ("cluster_spec_digest", DIGEST),
            ("inventory_digest", stored.digest),
            ("observation_digest", observed_stored.digest),
            ("trust_digest", DIGEST),
        ),
        () if status is not MonitoringStackStatus.FAILED else ("execution-failed",),
    )


def _context() -> tuple[dict[str, object], object, object, object, object]:
    inventory, observed = _cluster_inventory()
    metadata = _metadata()
    stack = _stack(inventory, observed)
    payload = build_monitoring_targets_payload(
        metadata,
        observed,
        inventory,
        _readiness(inventory),
        _base_os(),
        stack,
        logical_id="monitoring-1",
        image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
        architecture="amd64",
        cluster_spec_digest=DIGEST,
    )
    return payload, metadata, observed, inventory, stack


def _result(payload: dict[str, object], status: str = "no-change") -> dict[str, object]:
    success = status in {"generated", "no-change"}
    files = dict(cast(dict[str, str], payload["file_digests"])) if success else {}
    return {
        "auth_configured": False,
        "blockers": [] if status != "failed" else ["execution-failed"],
        "compose_generated": False,
        "containers_started": False,
        "documented_scrape_ports": payload["documented_scrape_ports"],
        "exporters_started": False,
        "files": files,
        "identities": payload["identities"],
        "install_root": payload["install_root"],
        "listen_policy": LISTEN_POLICY,
        "logical_id": payload["logical_id"],
        "manager_registration_performed": False,
        "provenance": payload["provenance"],
        "public_bind": False,
        "schema_version": MONITORING_TARGETS_SCHEMA_VERSION,
        "scrape_performed": False,
        "scrape_readiness": SCRAPE_READINESS,
        "scylla_started": False,
        "secrets_written": False,
        "stack_started": False,
        "stack_version": payload["stack_version"],
        "status": status,
        "target_counts": payload["target_counts"],
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
    changed = 1 if status == "generated" else 0
    return (
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_MONITORING_TARGETS_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=12 changed={changed} unreachable=0 "
        f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


def test_monitoring_targets_payload_is_official_and_address_bound() -> None:
    payload, metadata, observed, inventory, stack = _context()
    assert payload["stack_version"] == STACK_VERSION
    assert payload["install_root"] == INSTALL_ROOT
    assert payload["target_directory"] == TARGET_DIRECTORY
    assert payload["listen_policy"] == LISTEN_POLICY
    assert payload["scrape_readiness"] == SCRAPE_READINESS
    assert payload["service_unit"] == STACK_SERVICE_UNIT
    assert payload["documented_scrape_ports"] == SCRAPE_PORTS
    assert payload["public_bind"] is False
    assert payload["scrape_performed"] is False
    assert payload["exporters_started"] is False
    assert payload["stack_started"] is False
    assert payload["containers_started"] is False
    assert payload["auth_configured"] is False
    assert payload["secrets_written"] is False
    assert payload["manager_registration_performed"] is False
    assert payload["scylla_started"] is False
    files = cast(list[dict[str, str]], payload["files"])
    assert [item["name"] for item in files] == list(TARGET_FILES)
    scylla = next(item for item in files if item["name"] == "scylla_servers.yml")
    node = next(item for item in files if item["name"] == "node_exporter_servers.yml")
    agents = next(item for item in files if item["name"] == "scylla_manager_agents.yml")
    manager = next(
        item for item in files if item["name"] == "scylla_manager_servers.yml"
    )
    assert scylla["content"] == node["content"] == agents["content"]
    assert "10.0.0.20" in scylla["content"]
    assert "cluster: example" in scylla["content"]
    assert "dc: example-dc" in scylla["content"]
    assert ":9180" not in scylla["content"]
    assert ":9100" not in scylla["content"]
    assert f"10.0.0.30:{MANAGER_METRICS_PORT}" in manager["content"]
    assert "10.0.0.10" not in scylla["content"]
    assert "10.0.0.10" not in manager["content"]
    assert "203.0.113.10" not in json.dumps(payload["file_digests"])
    assert payload["target_counts"] == {
        "manager": 1,
        "manager_agent": 1,
        "node_exporter": 1,
        "scylla": 1,
    }
    encoded_identities = json.dumps(payload["identities"])
    assert "scylla-ad-1-1" not in encoded_identities
    assert "10.0.0." not in encoded_identities
    assert stack.logical_id == "monitoring-1"
    assert metadata.cluster_name == "example"
    assert observed is not None
    assert inventory.digest == payload["provenance"]["inventory_digest"]


def test_monitoring_targets_refuses_non_monitoring_stale_stack_base_os_and_os() -> None:
    payload, metadata, observed, inventory, stack = _context()
    assert payload
    readiness = _readiness(inventory)
    ubuntu = ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT)
    for logical_id in ("scylla-ad-1-1", "jump-host-1", "manager-1"):
        with pytest.raises(StateConflictError, match="monitoring stable ID"):
            build_monitoring_targets_payload(
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                readiness,
                _base_os(logical_id),
                stack,
                logical_id=logical_id,
                image_filter=ubuntu,
                architecture="amd64",
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
    failed_stack = _stack(inventory, observed, status=MonitoringStackStatus.FAILED)
    stale_stack = replace(
        stack,
        provenance=tuple(
            (key, DIGEST if key == "inventory_digest" else value)
            for key, value in stack.provenance
        ),
    )
    for base_os, ready, current_stack in (
        (reboot, readiness, stack),
        (missing, readiness, stack),
        (_base_os(), stale, stack),
        (_base_os(), readiness, failed_stack),
        (_base_os(), readiness, stale_stack),
    ):
        with pytest.raises(StateConflictError):
            build_monitoring_targets_payload(
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                ready,
                base_os,
                current_stack,
                logical_id="monitoring-1",
                image_filter=ubuntu,
                architecture="amd64",
                cluster_spec_digest=DIGEST,
            )
    with pytest.raises(StateConflictError, match=r"Ubuntu 24\.04"):
        build_monitoring_targets_payload(
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            readiness,
            _base_os(),
            stack,
            logical_id="monitoring-1",
            image_filter=ImageFilter("Oracle Linux", "9", ImageVersionMatch.EXACT),
            architecture="amd64",
            cluster_spec_digest=DIGEST,
        )


def test_monitoring_targets_refuses_missing_roles_and_non_rfc1918() -> None:
    jump = _host(
        "jump-host-1",
        HostRole.JUMP_HOST,
        "10.0.0.10",
        public="203.0.113.10",
    )
    monitoring = _host(
        "monitoring-1",
        HostRole.MONITORING,
        "10.0.0.40",
        jump="jump-host-1",
    )
    manager = _host(
        "manager-1",
        HostRole.MANAGER,
        "10.0.0.30",
        jump="jump-host-1",
    )
    public_scylla = replace(
        _host("scylla-ad-1-1", HostRole.SCYLLA, "10.0.0.20", jump="jump-host-1"),
        ansible_host="203.0.113.20",
        private_address="203.0.113.20",
    )
    ubuntu = ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT)
    missing_scylla = _inventory((jump, manager, monitoring))
    missing_observed = _observed(missing_scylla)
    with pytest.raises(StateConflictError, match="Scylla hosts"):
        build_monitoring_targets_payload(
            _metadata(),  # type: ignore[arg-type]
            missing_observed,  # type: ignore[arg-type]
            missing_scylla,  # type: ignore[arg-type]
            _readiness(missing_scylla),
            _base_os(),
            _stack(missing_scylla, missing_observed),
            logical_id="monitoring-1",
            image_filter=ubuntu,
            architecture="amd64",
            cluster_spec_digest=DIGEST,
        )
    public_inventory = _inventory((jump, public_scylla, manager, monitoring))
    public_observed = _observed(public_inventory)
    with pytest.raises(StateConflictError, match="RFC 1918"):
        build_monitoring_targets_payload(
            _metadata(),  # type: ignore[arg-type]
            public_observed,  # type: ignore[arg-type]
            public_inventory,  # type: ignore[arg-type]
            _readiness(public_inventory),
            _base_os(),
            _stack(public_inventory, public_observed),
            logical_id="monitoring-1",
            image_filter=ubuntu,
            architecture="amd64",
            cluster_spec_digest=DIGEST,
        )


def test_parse_monitoring_targets_success_failure_malformed_and_redaction() -> None:
    payload, _, _, _, _ = _context()
    generated = parse_monitoring_targets_execution(
        _stdout(payload, "generated"), expected_payload=payload, exit_code=0
    )
    assert generated.status is MonitoringTargetsStatus.GENERATED
    assert generated.scrape_readiness == SCRAPE_READINESS
    assert generated.scrape_performed is False
    assert generated.public_bind is False
    assert generated.files
    encoded = json.dumps(
        {
            "files": dict(generated.files),
            "identities": dict(generated.identities),
            "logical_id": generated.logical_id,
        }
    )
    assert "10.0.0." not in encoded
    assert "203.0.113." not in encoded
    assert "scylla-ad-1-1" not in encoded
    check = parse_monitoring_targets_execution(
        _stdout(payload, "not-predicted"), expected_payload=payload, exit_code=0
    )
    assert check.status is MonitoringTargetsStatus.NOT_PREDICTED
    assert check.files == ()
    failed = parse_monitoring_targets_execution(
        _stdout(payload, "failed", failed=1), expected_payload=payload, exit_code=2
    )
    assert failed.status is MonitoringTargetsStatus.FAILED
    assert failed.blockers == ("execution-failed",)
    claimed = _result(payload, "no-change")
    claimed["public_bind"] = True
    encoded_bad = base64.b64encode(
        json.dumps(claimed, sort_keys=True).encode()
    ).decode()
    stdout = (
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_MONITORING_TARGETS_B64={encoded_bad}"}}\nPLAY RECAP *****\n'
        f"{payload['logical_id']} : ok=12 changed=0 unreachable=0 "
        "failed=0 skipped=0 rescued=0 ignored=0\n"
    )
    with pytest.raises(AnsibleError):
        parse_monitoring_targets_execution(
            stdout, expected_payload=payload, exit_code=0
        )
    addressed = _result(payload, "no-change")
    addressed["listen_policy"] = "10.0.0.20"
    encoded_addr = base64.b64encode(
        json.dumps(addressed, sort_keys=True).encode()
    ).decode()
    addr_stdout = (
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_MONITORING_TARGETS_B64={encoded_addr}"}}\nPLAY RECAP *****\n'
        f"{payload['logical_id']} : ok=12 changed=0 unreachable=0 "
        "failed=0 skipped=0 rescued=0 ignored=0\n"
    )
    with pytest.raises(AnsibleError):
        parse_monitoring_targets_execution(
            addr_stdout, expected_payload=payload, exit_code=0
        )
    recap_failed = (
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=1 changed=0 unreachable=1 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    evidence = parse_monitoring_targets_execution(
        recap_failed, expected_payload=payload, exit_code=4
    )
    assert evidence.status is MonitoringTargetsStatus.FAILED
    definition = get_playbook("monitoring-targets")
    with pytest.raises(AnsibleError, match="variable value is invalid"):
        definition.validate_variables(
            {"deploy_scylla_vms_monitoring_targets": {"note": "token: obviously-fake"}}
        )


@pytest.mark.parametrize(
    ("check", "status"), [(False, "generated"), (True, "not-predicted")]
)
def test_service_success_failure_timeout_malformed_and_redaction(
    tmp_path: Path, check: bool, status: str
) -> None:
    payload, metadata, observed, inventory, stack = _context()
    paths = _paths(tmp_path)
    result_body = _result(payload, status)
    encoded = base64.b64encode(
        json.dumps(result_body, sort_keys=True).encode()
    ).decode()
    changed = 1 if status == "generated" else 0
    stdout = (
        "203.0.113.10 secret-token\n"
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_MONITORING_TARGETS_B64={encoded}"}}\nPLAY RECAP *****\n'
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
        result = service.execute_monitoring_targets(
            lock,
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            _base_os(),
            stack,
            limit=("monitoring-1",),
            readiness=_readiness(inventory),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
            cluster_spec_digest=DIGEST,
            check=check,
        )
    assert result.monitoring_targets is not None
    assert result.monitoring_targets.status is MonitoringTargetsStatus(status)
    assert result.stdout == result.stderr == ""
    assert runner.runtime_payloads[-1] == {
        "deploy_scylla_vms_monitoring_targets": payload
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
        failed = fail_service.execute_monitoring_targets(
            lock,
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            _base_os(),
            stack,
            limit=("monitoring-1",),
            readiness=_readiness(inventory),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
            cluster_spec_digest=DIGEST,
        )
    assert failed.monitoring_targets is not None
    assert failed.monitoring_targets.status is MonitoringTargetsStatus.FAILED

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
            AnsibleError, match="monitoring-targets command failed"
        ) as caught:
            timeout_service.execute_monitoring_targets(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                _base_os(),
                stack,
                limit=("monitoring-1",),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
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
            malformed_service.execute_monitoring_targets(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                _base_os(),
                stack,
                limit=("monitoring-1",),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                cluster_spec_digest=DIGEST,
            )


def test_execute_monitoring_targets_requires_one_monitoring_target(
    tmp_path: Path,
) -> None:
    payload, metadata, observed, inventory, stack = _context()
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
            service.execute_monitoring_targets(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                _base_os(),
                stack,
                limit=("monitoring-1", "manager-1"),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                cluster_spec_digest=DIGEST,
            )
        with pytest.raises(StateConflictError, match="monitoring stable ID"):
            service.execute_monitoring_targets(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                _base_os("scylla-ad-1-1"),
                stack,
                limit=("scylla-ad-1-1",),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                cluster_spec_digest=DIGEST,
            )


def test_monitoring_targets_registry_dependency_and_static_safety() -> None:
    definition = get_playbook("monitoring-targets")
    assert definition.source_available
    assert definition.hosts == "monitoring"
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert definition.check_mode is CheckMode.PREVIEW
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.classification is OperationClassification.MUTATING
    assert definition.pre_health_gate is False
    assert definition.post_health_gate is True
    assert definition.tags == (
        "monitoring-targets",
        "preflight",
        "targets",
        "verify",
    )
    assert callable(AnsibleService.execute_monitoring_targets)
    bundle_paths = {item.path for item in load_ansible_source_bundle().files}
    assert {
        "playbooks/monitoring-targets.yml",
        "playbooks/roles/monitoring_targets/files/scylla-monitoring-4.16.0-targets.provenance.yml",
    } <= bundle_paths
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content"
    playbook = (root / "playbooks/monitoring-targets.yml").read_text(encoding="utf-8")
    provenance = (
        root
        / "playbooks/roles/monitoring_targets/files/"
        / "scylla-monitoring-4.16.0-targets.provenance.yml"
    ).read_text(encoding="utf-8")
    for required in (
        "gather_facts: true",
        "serial: 1",
        "any_errors_fatal: true",
        "hosts: monitoring",
        "scylla_servers.yml",
        "node_exporter_servers.yml",
        "scylla_manager_agents.yml",
        "scylla_manager_servers.yml",
        "listen_policy': 'not-started'",
        "scrape_readiness': 'not-performed'",
        "scrape_performed': false",
        "auth_configured': false",
        "compose_generated': false",
        "containers_started': false",
        "public_bind': false",
        "secrets_written': false",
        "4.16.0",
        SOURCE_COMMIT,
        "docker.service",
        "ansible.builtin.copy:",
        "checksum_algorithm: sha256",
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
        "genconfig.py",
    ):
        assert forbidden not in lowered
    for required in (
        'retrieved_at: "2026-09-18"',
        SOURCE_COMMIT,
        "monitoring.docs.scylladb.com/branch-4.16/install/monitoring-stack.html",
        'official_stack_version: "4.16.0"',
        "scylla: 9180",
        "node_exporter: 9100",
        "manager_agent: 5090",
        "manager: 5090",
        "official-reuse-of-scylla-servers",
        "scrape-readiness stays",
    ):
        assert required in provenance


def test_monitoring_targets_playbook_syntax_check_is_local_and_write_free(
    tmp_path: Path,
) -> None:
    executable = shutil.which("ansible-playbook")
    if executable is None:
        pytest.skip("Ansible development executable is unavailable")
    playbook = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/monitoring-targets.yml"
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
