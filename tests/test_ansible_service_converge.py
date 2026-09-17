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
from scylla_vms.ansible.jump_host_configure import (
    JUMP_HOST_CONFIGURE_SCHEMA_VERSION,
    JumpHostConfigureEvidence,
    JumpHostConfigureStatus,
)
from scylla_vms.ansible.manager_agent import (
    MANAGER_AGENT_SCHEMA_VERSION,
    ManagerAgentEvidence,
    ManagerAgentStatus,
)
from scylla_vms.ansible.manager_server import (
    MANAGER_PACKAGES,
    ManagerServerEvidence,
    ManagerServerStatus,
)
from scylla_vms.ansible.monitoring_agent import (
    MONITORING_AGENT_SCHEMA_VERSION,
    MonitoringAgentEvidence,
    MonitoringAgentStatus,
)
from scylla_vms.ansible.monitoring_stack import (
    MONITORING_STACK_SCHEMA_VERSION,
    MonitoringStackEvidence,
    MonitoringStackStatus,
)
from scylla_vms.ansible.monitoring_targets import (
    MONITORING_TARGETS_SCHEMA_VERSION,
    MonitoringTargetsEvidence,
    MonitoringTargetsStatus,
)
from scylla_vms.ansible.readiness import (
    EvidenceStatus,
    ReadinessReport,
    RouteReadiness,
    RouteReport,
    TrustReadiness,
)
from scylla_vms.ansible.registry import PLAYBOOKS, CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_install import (
    SCYLLA_PACKAGES,
    ScyllaInstallEvidence,
    ScyllaInstallStatus,
)
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.ansible.service_converge import (
    NOT_PERFORMED,
    RESTART_POLICIES,
    SERVICE_CONVERGE_SCHEMA_VERSION,
    SERVICE_SCOPES,
    TIMESYNC_UNIT,
    ServiceConvergePrerequisites,
    ServiceConvergeStatus,
    build_service_converge_payload,
    parse_service_converge_execution,
    scope_units,
)
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.desired import HostRole, ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.process import ProcessResult, ProcessTimeoutError

SCYLLA_VERSION = "2026.2.1-0.20260915.abcdef123456-1"
MANAGER_VERSION = "3.12.1~0.20260911.6f499af46"
SCOPE_TARGETS = {
    "base": "jump-host-1",
    "jump-host": "jump-host-1",
    "manager-agent": "scylla-ad-1-1",
    "manager-server": "manager-1",
    "monitoring-agent": "scylla-ad-1-1",
    "monitoring-stack": "monitoring-1",
    "monitoring-targets": "monitoring-1",
    "scylla": "scylla-ad-1-1",
}


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


def _base_os(logical_id: str) -> BaseOsEvidence:
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


def _provenance(inventory: object, observed: object) -> tuple[tuple[str, str], ...]:
    return (
        ("inventory_digest", cast(Any, inventory).digest),
        ("observation_digest", cast(Any, observed).digest),
    )


def _prerequisites(
    inventory: object,
    observed: object,
    *,
    logical_id: str,
    jump_status: JumpHostConfigureStatus = JumpHostConfigureStatus.NOOP,
    scylla_status: ScyllaInstallStatus = ScyllaInstallStatus.NO_CHANGE,
    scylla_masked: bool | None = True,
    scylla_inactive: bool | None = True,
) -> ServiceConvergePrerequisites:
    provenance = _provenance(inventory, observed)
    return ServiceConvergePrerequisites(
        jump_host_configure=JumpHostConfigureEvidence(
            logical_id,
            jump_status,
            DIGEST,
            DIGEST,
            DIGEST,
            provenance,
            True,
            True,
            False,
            None,
            (),
            JUMP_HOST_CONFIGURE_SCHEMA_VERSION,
        ),
        scylla_install=ScyllaInstallEvidence(
            logical_id,
            scylla_status,
            "enterprise",
            SCYLLA_VERSION,
            "enterprise",
            SCYLLA_VERSION,
            tuple((name, SCYLLA_VERSION) for name in SCYLLA_PACKAGES),
            DIGEST,
            "6C6ECC84F42AF147BD2A65AEC503C686B007F39E",
            DIGEST,
            scylla_masked,
            scylla_inactive,
            False,
            False,
            False,
            False,
            False,
            provenance,
            (),
        ),
        manager_agent=ManagerAgentEvidence(
            logical_id,
            ManagerAgentStatus.NO_CHANGE,
            "3.12",
            MANAGER_VERSION,
            MANAGER_VERSION,
            (("scylla-manager-agent", MANAGER_VERSION),),
            DIGEST,
            "6C6ECC84F42AF147BD2A65AEC503C686B007F39E",
            DIGEST,
            False,
            True,
            False,
            False,
            False,
            "not-performed",
            provenance,
            (),
            MANAGER_AGENT_SCHEMA_VERSION,
        ),
        manager_server=ManagerServerEvidence(
            logical_id,
            ManagerServerStatus.NO_CHANGE,
            "3.12",
            MANAGER_VERSION,
            MANAGER_VERSION,
            tuple((name, MANAGER_VERSION) for name in MANAGER_PACKAGES),
            DIGEST,
            "6C6ECC84F42AF147BD2A65AEC503C686B007F39E",
            DIGEST,
            True,
            True,
            False,
            False,
            False,
            False,
            False,
            False,
            provenance,
            (),
        ),
        monitoring_agent=MonitoringAgentEvidence(
            logical_id,
            MonitoringAgentStatus.NO_CHANGE,
            "2026.2",
            SCYLLA_VERSION,
            SCYLLA_VERSION,
            (("scylla-node-exporter", SCYLLA_VERSION),),
            DIGEST,
            "6C6ECC84F42AF147BD2A65AEC503C686B007F39E",
            DIGEST,
            False,
            True,
            "not-started",
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            provenance,
            (),
            MONITORING_AGENT_SCHEMA_VERSION,
        ),
        monitoring_stack=MonitoringStackEvidence(
            logical_id,
            MonitoringStackStatus.NO_CHANGE,
            "4.16",
            "4.16.0",
            "4.16.0",
            (("stack", "4.16.0"),),
            DIGEST,
            "fac61b89b229a69d2af2d88b7e09a6316c3924e4",
            False,
            True,
            False,
            "not-started",
            (("grafana", 3000),),
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            provenance,
            (),
            MONITORING_STACK_SCHEMA_VERSION,
        ),
        monitoring_targets=MonitoringTargetsEvidence(
            logical_id,
            MonitoringTargetsStatus.NO_CHANGE,
            "4.16.0",
            "/opt/scylla-monitoring/4.16.0",
            (("scylla_servers.yml", DIGEST),),
            (("scylla", 1),),
            (("scylla", ("scylla-ad-1-1",)),),
            (("scylla", 9180),),
            "not-started",
            "not-performed",
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            provenance,
            (),
            MONITORING_TARGETS_SCHEMA_VERSION,
        ),
    )


def _context(
    service_scope: str = "base",
    *,
    logical_id: str | None = None,
    restart_policy: str = "if-required",
):
    inventory, observed = _cluster_inventory()
    target = logical_id or SCOPE_TARGETS[service_scope]
    payload = build_service_converge_payload(
        _metadata(),
        observed,
        inventory,
        _readiness(inventory),
        _base_os(target),
        _prerequisites(inventory, observed, logical_id=target),
        logical_id=target,
        image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
        architecture="amd64",
        cluster_spec_digest=DIGEST,
        service_scope=service_scope,
        restart_policy=restart_policy,
    )
    return payload, observed, inventory


def _unit_result(
    unit: dict[str, object],
    *,
    status: str,
    applied: bool = False,
    started: bool = False,
    restarted: bool = False,
) -> dict[str, object]:
    success = status in {"converged", "no-change"}
    return {
        "applied": applied,
        "desired_active": unit["desired_active"],
        "desired_enabled": unit["desired_enabled"],
        "not_performed": []
        if unit["start_allowed"]
        else ["restart", "start", "unmask"],
        "observed_active": unit["desired_active"] if success else None,
        "observed_enabled": unit["desired_enabled"] if success else None,
        "restarted": restarted,
        "start_allowed": unit["start_allowed"],
        "started": started,
        "unit": unit["unit"],
    }


def _result(
    payload: dict[str, object],
    status: str = "no-change",
    *,
    applied: bool = False,
    started: bool = False,
    restarted: bool = False,
    blockers: list[str] | None = None,
) -> dict[str, object]:
    units = [
        _unit_result(
            cast(dict[str, object], unit),
            status=status,
            applied=applied and bool(unit["start_allowed"]),
            started=started and bool(unit["start_allowed"]),
            restarted=restarted and bool(unit["start_allowed"]),
        )
        for unit in cast(list[object], payload["units"])
    ]
    if status == "failed" and blockers is None:
        blockers = ["execution-failed"]
    elif blockers is None:
        blockers = []
    return {
        "applied": applied,
        "blockers": blockers,
        "logical_id": payload["logical_id"],
        "not_performed": list(NOT_PERFORMED),
        "provenance": payload["provenance"],
        "restart_policy": payload["restart_policy"],
        "restarted": restarted,
        "schema_version": SERVICE_CONVERGE_SCHEMA_VERSION,
        "service_scope": payload["service_scope"],
        "started": started,
        "status": status,
        "units": units,
    }


def _stdout(
    payload: dict[str, object],
    status: str = "no-change",
    *,
    failed: int = 0,
    changed: int | None = None,
    applied: bool = False,
    started: bool = False,
    restarted: bool = False,
    blockers: list[str] | None = None,
) -> str:
    encoded = base64.b64encode(
        json.dumps(
            _result(
                payload,
                status,
                applied=applied,
                started=started,
                restarted=restarted,
                blockers=blockers,
            ),
            sort_keys=True,
        ).encode()
    ).decode()
    if changed is None:
        changed = 1 if status == "converged" else 0
    return (
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_SERVICE_CONVERGE_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=8 changed={changed} unreachable=0 "
        f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


@pytest.mark.parametrize("service_scope", SERVICE_SCOPES)
def test_service_converge_payload_is_role_aware_and_allowlisted(
    service_scope: str,
) -> None:
    payload, *_ = _context(service_scope)
    assert payload["schema_version"] == SERVICE_CONVERGE_SCHEMA_VERSION
    assert payload["service_scope"] == service_scope
    assert payload["restart_policy"] == "if-required"
    assert payload["applied"] is False
    assert payload["started"] is False
    assert payload["not_performed"] == list(NOT_PERFORMED)
    assert payload["units"] == [dict(item) for item in scope_units(service_scope)]
    for unit in cast(list[dict[str, object]], payload["units"]):
        assert unit["start_allowed"] is (unit["unit"] == TIMESYNC_UNIT)
        if not unit["start_allowed"]:
            assert unit["not_performed"] == ["restart", "start", "unmask"]
    encoded = json.dumps(payload, sort_keys=True)
    assert "token:" not in encoded
    assert "password" not in encoded


def test_service_converge_refuses_unknown_scope_policy_and_os() -> None:
    inventory, observed = _cluster_inventory()
    prerequisites = _prerequisites(inventory, observed, logical_id="jump-host-1")
    with pytest.raises(AnsibleError, match="scope is not allowlisted"):
        build_service_converge_payload(
            _metadata(),
            observed,
            inventory,
            _readiness(inventory),
            _base_os("jump-host-1"),
            prerequisites,
            logical_id="jump-host-1",
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
            cluster_spec_digest=DIGEST,
            service_scope="all",
        )
    with pytest.raises(AnsibleError, match="restart policy"):
        build_service_converge_payload(
            _metadata(),
            observed,
            inventory,
            _readiness(inventory),
            _base_os("jump-host-1"),
            prerequisites,
            logical_id="jump-host-1",
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
            cluster_spec_digest=DIGEST,
            service_scope="base",
            restart_policy="unless-stopped",
        )
    for image in (
        ImageFilter("Oracle Linux", "9", ImageVersionMatch.EXACT),
        ImageFilter("Ubuntu", "22.04", ImageVersionMatch.EXACT),
    ):
        with pytest.raises(StateConflictError, match=r"Ubuntu 24\.04"):
            build_service_converge_payload(
                _metadata(),
                observed,
                inventory,
                _readiness(inventory),
                _base_os("jump-host-1"),
                prerequisites,
                logical_id="jump-host-1",
                image_filter=image,
                architecture="amd64",
                cluster_spec_digest=DIGEST,
                service_scope="base",
            )


@pytest.mark.parametrize(
    ("service_scope", "wrong_id"),
    [
        ("jump-host", "scylla-ad-1-1"),
        ("scylla", "manager-1"),
        ("manager-agent", "manager-1"),
        ("manager-server", "scylla-ad-1-1"),
        ("monitoring-agent", "monitoring-1"),
        ("monitoring-stack", "scylla-ad-1-1"),
        ("monitoring-targets", "jump-host-1"),
    ],
)
def test_service_converge_refuses_wrong_role_targets(
    service_scope: str, wrong_id: str
) -> None:
    inventory, observed = _cluster_inventory()
    with pytest.raises(StateConflictError, match="stable ID"):
        build_service_converge_payload(
            _metadata(),
            observed,
            inventory,
            _readiness(inventory),
            _base_os(wrong_id),
            _prerequisites(inventory, observed, logical_id=wrong_id),
            logical_id=wrong_id,
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
            cluster_spec_digest=DIGEST,
            service_scope=service_scope,
        )


def test_service_converge_refuses_stale_missing_and_active_evidence() -> None:
    inventory, observed = _cluster_inventory()
    readiness = _readiness(inventory)
    ubuntu = ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT)
    reboot = BaseOsEvidence(
        BaseOsStatus.REBOOT_REQUIRED,
        (
            replace(
                _base_os("scylla-ad-1-1").hosts[0],
                status=BaseOsStatus.REBOOT_REQUIRED,
                reboot_required=True,
            ),
        ),
    )
    with pytest.raises(StateConflictError, match="current base-os"):
        build_service_converge_payload(
            _metadata(),
            observed,
            inventory,
            readiness,
            reboot,
            _prerequisites(inventory, observed, logical_id="scylla-ad-1-1"),
            logical_id="scylla-ad-1-1",
            image_filter=ubuntu,
            architecture="amd64",
            cluster_spec_digest=DIGEST,
            service_scope="scylla",
        )
    stale = replace(_readiness(inventory), trust_digest=None)
    with pytest.raises(StateConflictError, match="provenance"):
        build_service_converge_payload(
            _metadata(),
            observed,
            inventory,
            stale,
            _base_os("scylla-ad-1-1"),
            _prerequisites(inventory, observed, logical_id="scylla-ad-1-1"),
            logical_id="scylla-ad-1-1",
            image_filter=ubuntu,
            architecture="amd64",
            cluster_spec_digest=DIGEST,
            service_scope="scylla",
        )
    missing = ServiceConvergePrerequisites()
    with pytest.raises(StateConflictError, match="current scylla-install"):
        build_service_converge_payload(
            _metadata(),
            observed,
            inventory,
            readiness,
            _base_os("scylla-ad-1-1"),
            missing,
            logical_id="scylla-ad-1-1",
            image_filter=ubuntu,
            architecture="amd64",
            cluster_spec_digest=DIGEST,
            service_scope="scylla",
        )
    active = _prerequisites(
        inventory,
        observed,
        logical_id="scylla-ad-1-1",
        scylla_masked=False,
        scylla_inactive=False,
    )
    with pytest.raises(StateConflictError, match="current scylla-install"):
        build_service_converge_payload(
            _metadata(),
            observed,
            inventory,
            readiness,
            _base_os("scylla-ad-1-1"),
            active,
            logical_id="scylla-ad-1-1",
            image_filter=ubuntu,
            architecture="amd64",
            cluster_spec_digest=DIGEST,
            service_scope="scylla",
        )
    stale_jump = _prerequisites(inventory, observed, logical_id="jump-host-1")
    stale_jump = replace(
        stale_jump,
        jump_host_configure=replace(
            cast(JumpHostConfigureEvidence, stale_jump.jump_host_configure),
            provenance_digests=(("inventory_digest", "sha256:" + "b" * 64),),
        ),
    )
    with pytest.raises(StateConflictError, match="current jump-host-configure"):
        build_service_converge_payload(
            _metadata(),
            observed,
            inventory,
            readiness,
            _base_os("jump-host-1"),
            stale_jump,
            logical_id="jump-host-1",
            image_filter=ubuntu,
            architecture="amd64",
            cluster_spec_digest=DIGEST,
            service_scope="jump-host",
        )


def test_service_converge_parser_statuses_and_forbidden_start_refusal() -> None:
    payload, *_ = _context("base")
    no_change = parse_service_converge_execution(
        _stdout(payload, "no-change"), expected_payload=payload, exit_code=0
    )
    assert no_change.status is ServiceConvergeStatus.NO_CHANGE
    assert no_change.applied is False
    assert no_change.units[0].unit == TIMESYNC_UNIT
    assert no_change.units[0].start_allowed is True
    converged = parse_service_converge_execution(
        _stdout(payload, "converged", applied=True, started=True),
        expected_payload=payload,
        exit_code=0,
    )
    assert converged.status is ServiceConvergeStatus.CONVERGED
    assert converged.started is True
    predicted = parse_service_converge_execution(
        _stdout(payload, "not-predicted"), expected_payload=payload, exit_code=0
    )
    assert predicted.status is ServiceConvergeStatus.NOT_PREDICTED
    failed = parse_service_converge_execution(
        _stdout(payload, "failed", failed=1),
        expected_payload=payload,
        exit_code=2,
    )
    assert failed.status is ServiceConvergeStatus.FAILED
    scylla_payload, *_ = _context("scylla")
    claimed = _result(scylla_payload, "no-change")
    claimed["units"][0]["started"] = True
    claimed["started"] = True
    encoded = base64.b64encode(json.dumps(claimed, sort_keys=True).encode()).decode()
    stdout = (
        f"ok: [{scylla_payload['logical_id']}] => "
        f'{{"msg":"DSV_SERVICE_CONVERGE_B64={encoded}"}}\nPLAY RECAP *****\n'
        f"{scylla_payload['logical_id']} : ok=8 changed=0 unreachable=0 "
        "failed=0 skipped=0 rescued=0 ignored=0\n"
    )
    with pytest.raises(AnsibleError, match="forbidden start"):
        parse_service_converge_execution(
            stdout, expected_payload=scylla_payload, exit_code=0
        )
    extra = _result(scylla_payload, "no-change")
    extra["units"].append(
        {
            "applied": False,
            "desired_active": "active",
            "desired_enabled": "enabled",
            "not_performed": [],
            "observed_active": "active",
            "observed_enabled": "enabled",
            "restarted": False,
            "start_allowed": True,
            "started": False,
            "unit": "sshd.service",
        }
    )
    encoded = base64.b64encode(json.dumps(extra, sort_keys=True).encode()).decode()
    stdout = (
        f"ok: [{scylla_payload['logical_id']}] => "
        f'{{"msg":"DSV_SERVICE_CONVERGE_B64={encoded}"}}\nPLAY RECAP *****\n'
        f"{scylla_payload['logical_id']} : ok=8 changed=0 unreachable=0 "
        "failed=0 skipped=0 rescued=0 ignored=0\n"
    )
    with pytest.raises(AnsibleError, match="units are invalid"):
        parse_service_converge_execution(
            stdout, expected_payload=scylla_payload, exit_code=0
        )


def test_service_converge_parser_refuses_malformed_secrets_and_mutations() -> None:
    payload, *_ = _context("scylla")
    with pytest.raises(AnsibleError, match="exceeds"):
        parse_service_converge_execution(
            "x" * (512 * 1024 + 1), expected_payload=payload, exit_code=2
        )
    with pytest.raises(AnsibleError):
        parse_service_converge_execution(
            _stdout(payload, "no-change", failed=1),
            expected_payload=payload,
            exit_code=2,
        )
    claimed = _result(payload, "no-change")
    claimed["applied"] = True
    encoded = base64.b64encode(json.dumps(claimed, sort_keys=True).encode()).decode()
    stdout = (
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_SERVICE_CONVERGE_B64={encoded}"}}\nPLAY RECAP *****\n'
        f"{payload['logical_id']} : ok=8 changed=0 unreachable=0 "
        "failed=0 skipped=0 rescued=0 ignored=0\n"
    )
    with pytest.raises(AnsibleError, match="unit mutation flags"):
        parse_service_converge_execution(stdout, expected_payload=payload, exit_code=0)
    failed = (
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=1 changed=0 unreachable=1 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    evidence = parse_service_converge_execution(
        failed, expected_payload=payload, exit_code=4
    )
    assert evidence.status is ServiceConvergeStatus.FAILED
    assert evidence.blockers == ("execution-failed",)
    definition = get_playbook("service-converge")
    with pytest.raises(AnsibleError, match="variable value is invalid"):
        definition.validate_variables(
            {"deploy_scylla_vms_service_converge": {"note": "token: obviously-fake"}}
        )


@pytest.mark.parametrize(
    ("check", "status"), [(False, "no-change"), (True, "not-predicted")]
)
def test_service_success_failure_timeout_malformed_and_redaction(
    tmp_path: Path, check: bool, status: str
) -> None:
    payload, observed, inventory = _context("base")
    paths = _paths(tmp_path)
    stdout = "203.0.113.10 secret-token\n" + _stdout(payload, status)
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
        result = service.execute_service_converge(
            lock,
            _metadata(),
            observed,
            inventory,
            _base_os("jump-host-1"),
            _prerequisites(inventory, observed, logical_id="jump-host-1"),
            limit=("jump-host-1",),
            readiness=_readiness(inventory),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
            cluster_spec_digest=DIGEST,
            service_scope="base",
            check=check,
        )
    assert result.service_converge is not None
    assert result.service_converge.status is ServiceConvergeStatus(status)
    assert result.service_converge.applied is False
    assert result.stdout == result.stderr == ""
    assert runner.runtime_payloads[-1]["deploy_scylla_vms_service_converge"] == payload
    assert runner.runtime_payloads[-1]["deploy_scylla_vms_service_scope"] == "base"
    assert "--limit" in runner.specs[-1].argv
    assert "jump-host-1" in runner.specs[-1].argv
    assert ("--check" in runner.specs[-1].argv) is check
    assert "203.0.113.10" in runner.specs[-1].sensitive_values
    assert "10.0.0.10" in runner.specs[-1].sensitive_values
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
        failed = fail_service.execute_service_converge(
            lock,
            _metadata(),
            observed,
            inventory,
            _base_os("jump-host-1"),
            _prerequisites(inventory, observed, logical_id="jump-host-1"),
            limit=("jump-host-1",),
            readiness=_readiness(inventory),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
            cluster_spec_digest=DIGEST,
            service_scope="base",
        )
    assert failed.service_converge is not None
    assert failed.service_converge.status is ServiceConvergeStatus.FAILED

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
            AnsibleError, match="service-converge command failed"
        ) as caught:
            timeout_service.execute_service_converge(
                lock,
                _metadata(),
                observed,
                inventory,
                _base_os("jump-host-1"),
                _prerequisites(inventory, observed, logical_id="jump-host-1"),
                limit=("jump-host-1",),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                cluster_spec_digest=DIGEST,
                service_scope="base",
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
            malformed_service.execute_service_converge(
                lock,
                _metadata(),
                observed,
                inventory,
                _base_os("jump-host-1"),
                _prerequisites(inventory, observed, logical_id="jump-host-1"),
                limit=("jump-host-1",),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                cluster_spec_digest=DIGEST,
                service_scope="base",
            )


def test_execute_service_converge_requires_one_matching_target(tmp_path: Path) -> None:
    _, observed, inventory = _context("base")
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
            service.execute_service_converge(
                lock,
                _metadata(),
                observed,
                inventory,
                _base_os("jump-host-1"),
                _prerequisites(inventory, observed, logical_id="jump-host-1"),
                limit=("jump-host-1", "scylla-ad-1-1"),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                cluster_spec_digest=DIGEST,
                service_scope="base",
            )
        with pytest.raises(StateConflictError, match="manager stable ID"):
            service.execute_service_converge(
                lock,
                _metadata(),
                observed,
                inventory,
                _base_os("scylla-ad-1-1"),
                _prerequisites(inventory, observed, logical_id="scylla-ad-1-1"),
                limit=("scylla-ad-1-1",),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                cluster_spec_digest=DIGEST,
                service_scope="manager-server",
            )


def test_service_converge_registry_dependency_and_static_safety() -> None:
    definition = get_playbook("service-converge")
    assert definition.source_available
    assert definition.hosts == "all"
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert definition.check_mode is CheckMode.PREVIEW
    assert definition.limit_policy is LimitPolicy.EXPLICIT
    assert definition.classification is OperationClassification.MUTATING
    assert definition.pre_health_gate is True
    assert definition.post_health_gate is True
    assert definition.tags == (
        "service-converge",
        "preflight",
        "inspect",
        "converge",
        "verify",
    )
    validated = definition.validate_variables(
        {
            "deploy_scylla_vms_restart_policy": "never",
            "deploy_scylla_vms_service_scope": "scylla",
            "deploy_scylla_vms_service_converge": {
                "schema_version": SERVICE_CONVERGE_SCHEMA_VERSION
            },
        }
    )
    assert validated["deploy_scylla_vms_restart_policy"] == "never"
    assert RESTART_POLICIES == ("always", "if-required", "never")
    assert callable(AnsibleService.execute_service_converge)
    assert {book.name for book in PLAYBOOKS if book.source_available} >= {
        "service-converge"
    }
    bundle_paths = {item.path for item in load_ansible_source_bundle().files}
    assert {
        "playbooks/service-converge.yml",
        "playbooks/roles/service_converge/tasks/main.yml",
        "playbooks/roles/service_converge/library/service_converge.py",
        "playbooks/roles/service_converge/files/service-converge.provenance.yml",
    } <= bundle_paths
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content"
    playbook = (root / "playbooks/service-converge.yml").read_text(encoding="utf-8")
    tasks = (root / "playbooks/roles/service_converge/tasks/main.yml").read_text(
        encoding="utf-8"
    )
    module = (
        root / "playbooks/roles/service_converge/library/service_converge.py"
    ).read_text(encoding="utf-8")
    provenance = (
        root / "playbooks/roles/service_converge/files/service-converge.provenance.yml"
    ).read_text(encoding="utf-8")
    for required in (
        "gather_facts: true",
        "serial: 1",
        "any_errors_fatal: true",
        "hosts: all",
        "status': 'not-predicted'",
        "deploy_scylla_vms_service_scope",
        "deploy_scylla_vms_restart_policy",
    ):
        assert required in playbook
    assert "service_converge:" in tasks
    assert "intent:" in tasks
    for required in (
        TIMESYNC_UNIT,
        "scylla-server.service",
        "scylla-manager.service",
        "scylla-manager-agent.service",
        "scylla-node-exporter.service",
        "/usr/bin/systemctl",
        "enable",
        "--now",
        "is-enabled",
        "is-active",
        "start_allowed is not (unit == TIMESYNC_UNIT)",
    ):
        assert required in module
    assert "systemctl unmask" not in module
    assert 'scylla-server.service", "enable"' not in module
    lowered = playbook.lower() + tasks.lower()
    for forbidden in (
        "ansible.builtin.shell",
        "ansible.builtin.get_url",
        "ansible.builtin.uri",
        "apt_key",
        "curl",
        "wget",
        "http://",
        "systemctl unmask",
        "scyllamgr_setup",
        "auth_token:",
        "reboot:",
        "validate_certs: false",
        "trusted=yes",
        "firewall",
        "iptables",
        "sshd_config",
    ):
        assert forbidden not in lowered
    for required in (
        'retrieved_at: "2026-09-18"',
        "systemd-timesyncd.service",
        "scylla-server.service",
        "scylla-manager.service",
        "never crosses it",
        "This slice validates Ubuntu 24.04",
    ):
        assert required in provenance


def test_service_converge_playbook_syntax_check_is_local_and_write_free(
    tmp_path: Path,
) -> None:
    executable = shutil.which("ansible-playbook")
    if executable is None:
        pytest.skip("Ansible development executable is unavailable")
    playbook = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/service-converge.yml"
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
