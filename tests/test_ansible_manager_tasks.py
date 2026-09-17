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
from scylla_vms.ansible.manager_server import (
    MANAGER_PACKAGES,
    MANAGER_RELEASE_LINE,
    MANAGER_REPOSITORY_DEFINITION_DIGEST,
    MANAGER_SERVICE_UNIT,
    ManagerServerEvidence,
    ManagerServerStatus,
)
from scylla_vms.ansible.manager_tasks import (
    EXPECTED_BLOCKERS,
    MANAGER_TASK_ACTIONS,
    MANAGER_TASK_KINDS,
    MANAGER_TASKS_SCHEMA_VERSION,
    NOT_PERFORMED,
    ManagerTasksStatus,
    build_manager_tasks_payload,
    parse_manager_tasks_execution,
)
from scylla_vms.ansible.readiness import (
    EvidenceStatus,
    ReadinessReport,
    RouteReadiness,
    RouteReport,
    TrustReadiness,
)
from scylla_vms.ansible.registry import PLAYBOOKS, CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_install import SCYLLA_SIGNING_KEY_DIGEST
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.desired import HostRole, ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.process import ProcessResult, ProcessTimeoutError

VERSION = "3.12.1~0.20260911.6f499af46"


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


def _base_os(logical_id: str = "manager-1") -> BaseOsEvidence:
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


def _manager_server(
    inventory: object,
    observed: object,
    *,
    logical_id: str = "manager-1",
    status: ManagerServerStatus = ManagerServerStatus.NO_CHANGE,
    service_masked: bool | None = True,
    service_inactive: bool | None = True,
    service_started: bool = False,
    backend_configured: bool = False,
    registration_performed: bool = False,
    setup_performed: bool = False,
    inventory_digest: str | None = None,
    observation_digest: str | None = None,
) -> ManagerServerEvidence:
    stored = cast(Any, inventory)
    seen = cast(Any, observed)
    return ManagerServerEvidence(
        logical_id,
        status,
        MANAGER_RELEASE_LINE,
        VERSION,
        VERSION if status is not ManagerServerStatus.FAILED else None,
        tuple((name, VERSION) for name in MANAGER_PACKAGES),
        MANAGER_REPOSITORY_DEFINITION_DIGEST,
        "6C6ECC84F42AF147BD2A65AEC503C686B007F39E",
        SCYLLA_SIGNING_KEY_DIGEST,
        service_masked,
        service_inactive,
        service_started,
        backend_configured,
        False,
        registration_performed,
        setup_performed,
        False,
        (
            ("base_os_digest", DIGEST),
            ("cluster_spec_digest", DIGEST),
            ("inventory_digest", inventory_digest or stored.digest),
            ("observation_digest", observation_digest or seen.digest),
            ("trust_digest", DIGEST),
        ),
        (),
    )


def _context(action: str = "inspect"):
    inventory, observed = _cluster_inventory()
    metadata = _metadata()
    payload = build_manager_tasks_payload(
        metadata,
        observed,
        inventory,
        _readiness(inventory),
        _base_os(),
        _manager_server(inventory, observed),
        logical_id="manager-1",
        image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
        architecture="amd64",
        cluster_spec_digest=DIGEST,
        action=action,
    )
    return payload, metadata, observed, inventory


def _result(
    payload: dict[str, object], status: str = "not-performed"
) -> dict[str, object]:
    success = status == "not-performed"
    blockers: list[str] = []
    if success:
        blockers = list(EXPECTED_BLOCKERS)
    elif status == "failed":
        blockers = ["execution-failed"]
    return {
        "action": payload["action"],
        "applied": False,
        "auth_token_used": False,
        "backend_configured": False,
        "backup_task_created": False,
        "blockers": blockers,
        "inspect_performed": False,
        "logical_id": payload["logical_id"],
        "not_performed": list(NOT_PERFORMED),
        "provenance": payload["provenance"],
        "quiesce_performed": False,
        "registration_performed": False,
        "repair_task_created": False,
        "requested_kinds": list(MANAGER_TASK_KINDS),
        "resume_performed": False,
        "schema_version": MANAGER_TASKS_SCHEMA_VERSION,
        "scylla_started": False,
        "sctool_invoked": False,
        "secrets_written": False,
        "service_inactive": True if success else None,
        "service_masked": True if success else None,
        "service_started": False,
        "setup_performed": False,
        "status": status,
        "validate_performed": False,
    }


def _stdout(
    payload: dict[str, object],
    status: str = "not-performed",
    *,
    failed: int = 0,
) -> str:
    encoded = base64.b64encode(
        json.dumps(_result(payload, status), sort_keys=True).encode()
    ).decode()
    return (
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_MANAGER_TASKS_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=8 changed=0 unreachable=0 "
        f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


def test_manager_tasks_payload_is_exact_and_refuses_unsafe_actions() -> None:
    payload, metadata, observed, inventory = _context()
    assert payload["action"] == "inspect"
    assert payload["requested_kinds"] == list(MANAGER_TASK_KINDS)
    assert payload["requested_release"] == MANAGER_RELEASE_LINE
    assert payload["service_unit"] == MANAGER_SERVICE_UNIT
    assert payload["applied"] is False
    assert payload["backend_configured"] is False
    assert payload["registration_performed"] is False
    assert payload["service_started"] is False
    assert payload["sctool_invoked"] is False
    assert payload["auth_token_used"] is False
    assert payload["not_performed"] == list(NOT_PERFORMED)
    assert payload["expected_blockers"] == list(EXPECTED_BLOCKERS)
    encoded = json.dumps(payload, sort_keys=True)
    assert "token:" not in encoded
    assert "password" not in encoded
    for action in ("create", "start", "latest", ""):
        with pytest.raises(AnsibleError, match="inspect, quiesce, resume, or validate"):
            build_manager_tasks_payload(
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                _readiness(inventory),
                _base_os(),
                _manager_server(inventory, observed),
                logical_id="manager-1",
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                cluster_spec_digest=DIGEST,
                action=action,
            )


@pytest.mark.parametrize("action", MANAGER_TASK_ACTIONS)
def test_manager_tasks_payload_accepts_plan_actions(action: str) -> None:
    payload, *_ = _context(action)
    assert payload["action"] == action
    assert payload["applied"] is False


def test_manager_tasks_refuses_non_manager_stale_evidence_and_os() -> None:
    _, metadata, observed, inventory = _context()
    readiness = _readiness(inventory)
    server = _manager_server(inventory, observed)
    for logical_id in ("scylla-ad-1-1", "jump-host-1", "monitoring-1"):
        with pytest.raises(StateConflictError, match="manager stable ID"):
            build_manager_tasks_payload(
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                readiness,
                _base_os(logical_id),
                server,
                logical_id=logical_id,
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
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
    stale_ready = replace(_readiness(inventory), trust_digest=None)
    ubuntu = ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT)
    for base_os, ready in (
        (reboot, readiness),
        (missing, readiness),
        (_base_os(), stale_ready),
    ):
        with pytest.raises(StateConflictError):
            build_manager_tasks_payload(
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                ready,
                base_os,
                server,
                logical_id="manager-1",
                image_filter=ubuntu,
                architecture="amd64",
                cluster_spec_digest=DIGEST,
            )
    for image in (
        ImageFilter("Oracle Linux", "9", ImageVersionMatch.EXACT),
        ImageFilter("Ubuntu", "22.04", ImageVersionMatch.EXACT),
    ):
        with pytest.raises(StateConflictError, match=r"Ubuntu 24\.04"):
            build_manager_tasks_payload(
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                readiness,
                _base_os(),
                server,
                logical_id="manager-1",
                image_filter=image,
                architecture="amd64",
                cluster_spec_digest=DIGEST,
            )
    stale_server = _manager_server(
        inventory, observed, inventory_digest="sha256:" + "b" * 64
    )
    missing_server = _manager_server(
        inventory, observed, status=ManagerServerStatus.FAILED
    )
    active_server = _manager_server(
        inventory, observed, service_masked=False, service_inactive=False
    )
    registered = _manager_server(inventory, observed, registration_performed=True)
    for bad_server in (stale_server, missing_server, active_server, registered):
        with pytest.raises(StateConflictError, match="current manager-server"):
            build_manager_tasks_payload(
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                readiness,
                _base_os(),
                bad_server,
                logical_id="manager-1",
                image_filter=ubuntu,
                architecture="amd64",
                cluster_spec_digest=DIGEST,
            )


@pytest.mark.parametrize(
    ("status", "exit_code", "expected"),
    [
        ("not-performed", 0, ManagerTasksStatus.NOT_PERFORMED),
        ("not-predicted", 0, ManagerTasksStatus.NOT_PREDICTED),
        ("failed", 2, ManagerTasksStatus.FAILED),
    ],
)
def test_manager_tasks_result_parser_statuses(
    status: str, exit_code: int, expected: ManagerTasksStatus
) -> None:
    payload, *_ = _context()
    result = _result(payload, status)
    encoded = base64.b64encode(json.dumps(result, sort_keys=True).encode()).decode()
    failed = 1 if status == "failed" else 0
    stdout = (
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_MANAGER_TASKS_B64={encoded}"}}\nPLAY RECAP *****\n'
        f"{payload['logical_id']} : ok=8 changed=0 unreachable=0 "
        f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )
    evidence = parse_manager_tasks_execution(
        stdout, expected_payload=payload, exit_code=exit_code
    )
    assert evidence.status is expected
    assert evidence.applied is False
    assert evidence.sctool_invoked is False
    assert evidence.backend_configured is False
    assert evidence.registration_performed is False
    assert evidence.service_started is False
    assert evidence.requested_kinds == MANAGER_TASK_KINDS
    assert evidence.not_performed == NOT_PERFORMED
    if expected is ManagerTasksStatus.NOT_PERFORMED:
        assert evidence.service_masked is True
        assert evidence.service_inactive is True
        assert evidence.blockers == EXPECTED_BLOCKERS


def test_manager_tasks_parser_refuses_malformed_secrets_and_mutations() -> None:
    payload, *_ = _context()
    with pytest.raises(AnsibleError, match="exceeds"):
        parse_manager_tasks_execution(
            "x" * (512 * 1024 + 1), expected_payload=payload, exit_code=2
        )
    with pytest.raises(AnsibleError):
        parse_manager_tasks_execution(
            _stdout(payload, "not-performed", failed=1),
            expected_payload=payload,
            exit_code=2,
        )
    for field, value in (
        ("applied", True),
        ("sctool_invoked", True),
        ("auth_token_used", True),
        ("backend_configured", True),
        ("registration_performed", True),
        ("service_started", True),
        ("secrets_written", True),
        ("inspect_performed", True),
        ("backup_task_created", True),
    ):
        claimed = _result(payload, "not-performed")
        claimed[field] = value
        encoded = base64.b64encode(
            json.dumps(claimed, sort_keys=True).encode()
        ).decode()
        stdout = (
            f"ok: [{payload['logical_id']}] => "
            f'{{"msg":"DSV_MANAGER_TASKS_B64={encoded}"}}\nPLAY RECAP *****\n'
            f"{payload['logical_id']} : ok=8 changed=0 unreachable=0 "
            "failed=0 skipped=0 rescued=0 ignored=0\n"
        )
        with pytest.raises(AnsibleError, match="forbidden mutation"):
            parse_manager_tasks_execution(stdout, expected_payload=payload, exit_code=0)
    failed = (
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=1 changed=0 unreachable=1 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    evidence = parse_manager_tasks_execution(
        failed, expected_payload=payload, exit_code=4
    )
    assert evidence.status is ManagerTasksStatus.FAILED
    assert evidence.blockers == ("execution-failed",)
    definition = get_playbook("manager-tasks")
    with pytest.raises(AnsibleError, match="variable value is invalid"):
        definition.validate_variables(
            {"deploy_scylla_vms_manager_tasks": {"note": "token: obviously-fake"}}
        )


@pytest.mark.parametrize(
    ("check", "status"), [(False, "not-performed"), (True, "not-predicted")]
)
def test_service_success_failure_timeout_malformed_and_redaction(
    tmp_path: Path, check: bool, status: str
) -> None:
    payload, metadata, observed, inventory = _context()
    paths = _paths(tmp_path)
    encoded = base64.b64encode(
        json.dumps(_result(payload, status), sort_keys=True).encode()
    ).decode()
    stdout = (
        "203.0.113.10 secret-token\n"
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_MANAGER_TASKS_B64={encoded}"}}\nPLAY RECAP *****\n'
        f"{payload['logical_id']} : ok=8 changed=0 unreachable=0 "
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
        result = service.execute_manager_tasks(
            lock,
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            _base_os(),
            _manager_server(inventory, observed),
            limit=("manager-1",),
            readiness=_readiness(inventory),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
            cluster_spec_digest=DIGEST,
            check=check,
        )
    assert result.manager_tasks is not None
    assert result.manager_tasks.status is ManagerTasksStatus(status)
    assert result.manager_tasks.applied is False
    assert result.stdout == result.stderr == ""
    assert runner.runtime_payloads[-1] == {"deploy_scylla_vms_manager_tasks": payload}
    assert "--limit" in runner.specs[-1].argv
    assert "manager-1" in runner.specs[-1].argv
    assert ("--check" in runner.specs[-1].argv) is check
    assert "203.0.113.10" in runner.specs[-1].sensitive_values
    assert "10.0.0.30" in runner.specs[-1].sensitive_values
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
        failed = fail_service.execute_manager_tasks(
            lock,
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            _base_os(),
            _manager_server(inventory, observed),
            limit=("manager-1",),
            readiness=_readiness(inventory),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
            cluster_spec_digest=DIGEST,
        )
    assert failed.manager_tasks is not None
    assert failed.manager_tasks.status is ManagerTasksStatus.FAILED

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
            AnsibleError, match="manager-tasks command failed"
        ) as caught:
            timeout_service.execute_manager_tasks(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                _base_os(),
                _manager_server(inventory, observed),
                limit=("manager-1",),
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
            malformed_service.execute_manager_tasks(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                _base_os(),
                _manager_server(inventory, observed),
                limit=("manager-1",),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                cluster_spec_digest=DIGEST,
            )


def test_execute_manager_tasks_requires_one_manager_target(tmp_path: Path) -> None:
    _, metadata, observed, inventory = _context()
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
            service.execute_manager_tasks(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                _base_os(),
                _manager_server(inventory, observed),
                limit=("manager-1", "manager-2"),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                cluster_spec_digest=DIGEST,
            )
        with pytest.raises(StateConflictError, match="manager stable ID"):
            service.execute_manager_tasks(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                _base_os("scylla-ad-1-1"),
                _manager_server(inventory, observed, logical_id="scylla-ad-1-1"),
                limit=("scylla-ad-1-1",),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                cluster_spec_digest=DIGEST,
            )


def test_manager_tasks_registry_dependency_and_static_safety() -> None:
    definition = get_playbook("manager-tasks")
    assert definition.source_available
    assert definition.hosts == "manager"
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert definition.check_mode is CheckMode.PREVIEW
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.classification is OperationClassification.SENSITIVE
    assert definition.pre_health_gate is False
    assert definition.post_health_gate is False
    assert definition.tags == (
        "manager-tasks",
        "preflight",
        "inspect",
        "verify",
    )
    assert callable(AnsibleService.execute_manager_tasks)
    assert {book.name for book in PLAYBOOKS if book.source_available} >= {
        "manager-tasks"
    }
    bundle_paths = {item.path for item in load_ansible_source_bundle().files}
    assert {
        "playbooks/manager-tasks.yml",
        "playbooks/roles/manager_tasks/files/scylladb-manager-3.12-tasks.provenance.yml",
    } <= bundle_paths
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content"
    playbook = (root / "playbooks/manager-tasks.yml").read_text(encoding="utf-8")
    provenance = (
        root
        / "playbooks/roles/manager_tasks/files/scylladb-manager-3.12-tasks.provenance.yml"
    ).read_text(encoding="utf-8")
    for required in (
        "gather_facts: true",
        "serial: 1",
        "any_errors_fatal: true",
        "hosts: manager",
        "ansible.builtin.command:",
        "argv:",
        "/usr/bin/systemctl",
        "is-enabled",
        "is-active",
        "scylla-manager.service",
        "applied': false",
        "backend_configured': false",
        "registration_performed': false",
        "service_started': false",
        "sctool_invoked': false",
        "status': 'not-performed'",
        "status': 'not-predicted'",
    ):
        assert required in playbook
    lowered = playbook.lower()
    for forbidden in (
        "ansible.builtin.shell",
        "ansible.builtin.get_url",
        "ansible.builtin.uri",
        "apt_key",
        "curl",
        "wget",
        "http://",
        "state: started",
        "masked: false",
        "systemctl unmask",
        "scyllamgr_setup",
        "scyllamgr_auth_token_gen",
        "auth_token:",
        "scylla-manager.yaml",
        "sctool tasks",
        "sctool suspend",
        "sctool resume",
        "sctool backup",
        "sctool repair",
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
        "manager.docs.scylladb.com/branch-3.12/sctool/task.html",
        "sctool suspend --cluster",
        "sctool resume --cluster",
        "sctool tasks",
        "sctool backup",
        "sctool repair",
        "scylla-manager.service",
        "http://127.0.0.1:5080/api/v1",
        "This slice validates Ubuntu 24.04",
        "never invokes",
    ):
        assert required in provenance


def test_manager_tasks_playbook_syntax_check_is_local_and_write_free(
    tmp_path: Path,
) -> None:
    executable = shutil.which("ansible-playbook")
    if executable is None:
        pytest.skip("Ansible development executable is unavailable")
    playbook = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/manager-tasks.yml"
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
