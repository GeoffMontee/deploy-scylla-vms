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
from scylla_vms.ansible.manager_agent import (
    MANAGER_REPOSITORY_DEFINITION_DIGEST as AGENT_REPO_DIGEST,
)
from scylla_vms.ansible.manager_agent import (
    MANAGER_REPOSITORY_URI as AGENT_REPO_URI,
)
from scylla_vms.ansible.manager_server import (
    MANAGER_PACKAGES,
    MANAGER_RELEASE_LINE,
    MANAGER_REPOSITORY_DEFINITION_DIGEST,
    MANAGER_REPOSITORY_URI,
    MANAGER_SERVER_SCHEMA_VERSION,
    MANAGER_SERVICE_UNIT,
    ManagerServerStatus,
    build_manager_server_payload,
    parse_manager_server_execution,
)
from scylla_vms.ansible.readiness import (
    EvidenceStatus,
    ReadinessReport,
    RouteReadiness,
    RouteReport,
    TrustReadiness,
)
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_install import (
    SCYLLA_SIGNING_KEY_DIGEST,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
)
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


def _context() -> tuple[dict[str, object], object, object, object]:
    inventory, observed = _cluster_inventory()
    metadata = _metadata()
    payload = build_manager_server_payload(
        metadata,
        observed,
        inventory,
        _readiness(inventory),
        _base_os(),
        logical_id="manager-1",
        image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
        architecture="amd64",
        package_version=VERSION,
        cluster_spec_digest=DIGEST,
    )
    return payload, metadata, observed, inventory


def _result(payload: dict[str, object], status: str = "no-change") -> dict[str, object]:
    success = status in {"installed", "no-change"}
    return {
        "backend_configured": False,
        "blockers": [] if status != "failed" else ["execution-failed"],
        "configuration_performed": False,
        "installed_version": payload["package_version"] if success else None,
        "logical_id": payload["logical_id"],
        "packages": (
            {name: payload["package_version"] for name in MANAGER_PACKAGES}
            if success
            else {}
        ),
        "provenance": payload["provenance"],
        "registration_performed": False,
        "repository_digest": cast(dict[str, object], payload["repository"])[
            "definition_digest"
        ],
        "requested_release": payload["release_line"],
        "requested_version": payload["package_version"],
        "schema_version": MANAGER_SERVER_SCHEMA_VERSION,
        "service_inactive": True if success else None,
        "service_masked": True if success else None,
        "service_started": False,
        "setup_performed": False,
        "signing_key_digest": cast(dict[str, object], payload["signing_key"])[
            "artifact_digest"
        ],
        "signing_key_fingerprint": cast(dict[str, object], payload["signing_key"])[
            "fingerprint"
        ],
        "status": status,
        "tasks_performed": False,
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
        f'{{"msg":"DSV_MANAGER_SERVER_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=12 changed={changed} unreachable=0 "
        f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


def test_manager_server_payload_is_exact_and_rejects_unsafe_versions() -> None:
    payload, metadata, observed, inventory = _context()
    assert payload["release_line"] == MANAGER_RELEASE_LINE
    assert payload["channel"] == "stable"
    assert payload["packages"] == list(MANAGER_PACKAGES)
    assert payload["packages"] == [
        "scylla-manager-client",
        "scylla-manager-server",
    ]
    assert payload["service_unit"] == MANAGER_SERVICE_UNIT == "scylla-manager.service"
    assert payload["backend_configured"] is False
    assert payload["configuration_performed"] is False
    assert payload["registration_performed"] is False
    assert payload["service_started"] is False
    assert payload["setup_performed"] is False
    assert payload["tasks_performed"] is False
    assert MANAGER_REPOSITORY_URI == AGENT_REPO_URI
    assert MANAGER_REPOSITORY_DEFINITION_DIGEST == AGENT_REPO_DIGEST
    assert (
        cast(dict[str, object], payload["repository"])["definition_digest"]
        == MANAGER_REPOSITORY_DEFINITION_DIGEST
    )
    assert (
        cast(dict[str, object], payload["signing_key"])["fingerprint"]
        == SCYLLA_SIGNING_KEY_FINGERPRINT
    )
    assert (
        cast(dict[str, object], payload["signing_key"])["artifact_digest"]
        == SCYLLA_SIGNING_KEY_DIGEST
    )
    encoded = json.dumps(payload, sort_keys=True)
    assert "token:" not in encoded
    assert "password" not in encoded
    for version in (
        "latest",
        "3.12",
        "3.11.1~0.20260911.6f499af46",
        "3.12.1-0.20260911.6f499af46",
    ):
        with pytest.raises(AnsibleError, match=r"exact 3\.12"):
            build_manager_server_payload(
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                _readiness(inventory),
                _base_os(),
                logical_id="manager-1",
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                package_version=version,
                cluster_spec_digest=DIGEST,
            )


def test_manager_server_refuses_non_manager_targets_stale_base_os_and_os() -> None:
    payload, metadata, observed, inventory = _context()
    assert payload
    readiness = _readiness(inventory)
    for logical_id in ("scylla-ad-1-1", "jump-host-1", "monitoring-1"):
        with pytest.raises(StateConflictError, match="manager stable ID"):
            build_manager_server_payload(
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                readiness,
                _base_os(logical_id),
                logical_id=logical_id,
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                package_version=VERSION,
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
            build_manager_server_payload(
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                ready,
                base_os,
                logical_id="manager-1",
                image_filter=ubuntu,
                architecture="amd64",
                package_version=VERSION,
                cluster_spec_digest=DIGEST,
            )
    for image in (
        ImageFilter("Oracle Linux", "9", ImageVersionMatch.EXACT),
        ImageFilter("Ubuntu", "22.04", ImageVersionMatch.EXACT),
    ):
        with pytest.raises(StateConflictError, match=r"Ubuntu 24\.04"):
            build_manager_server_payload(
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                readiness,
                _base_os(),
                logical_id="manager-1",
                image_filter=image,
                architecture="amd64",
                package_version=VERSION,
                cluster_spec_digest=DIGEST,
            )


@pytest.mark.parametrize(
    ("status", "exit_code", "expected"),
    [
        ("installed", 0, ManagerServerStatus.INSTALLED),
        ("no-change", 0, ManagerServerStatus.NO_CHANGE),
        ("not-predicted", 0, ManagerServerStatus.NOT_PREDICTED),
        ("failed", 2, ManagerServerStatus.FAILED),
    ],
)
def test_manager_server_result_parser_statuses(
    status: str, exit_code: int, expected: ManagerServerStatus
) -> None:
    payload, *_ = _context()
    result = _result(payload, status)
    if status == "not-predicted":
        result.update(
            {
                "blockers": [],
                "installed_version": None,
                "packages": {},
                "service_inactive": None,
                "service_masked": None,
            }
        )
    encoded = base64.b64encode(json.dumps(result, sort_keys=True).encode()).decode()
    changed = 1 if status == "installed" else 0
    failed = 1 if status == "failed" else 0
    stdout = (
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_MANAGER_SERVER_B64={encoded}"}}\nPLAY RECAP *****\n'
        f"{payload['logical_id']} : ok=12 changed={changed} unreachable=0 "
        f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )
    evidence = parse_manager_server_execution(
        stdout, expected_payload=payload, exit_code=exit_code
    )
    assert evidence.status is expected
    assert evidence.backend_configured is False
    assert evidence.configuration_performed is False
    assert evidence.registration_performed is False
    assert evidence.service_started is False
    assert evidence.setup_performed is False
    assert evidence.tasks_performed is False
    if expected in {ManagerServerStatus.INSTALLED, ManagerServerStatus.NO_CHANGE}:
        assert evidence.service_masked is True
        assert evidence.service_inactive is True
        assert evidence.packages == tuple((name, VERSION) for name in MANAGER_PACKAGES)


def test_manager_server_parser_refuses_malformed_secrets_and_conflicts() -> None:
    payload, *_ = _context()
    with pytest.raises(AnsibleError, match="exceeds"):
        parse_manager_server_execution(
            "x" * (512 * 1024 + 1), expected_payload=payload, exit_code=2
        )
    with pytest.raises(AnsibleError):
        parse_manager_server_execution(
            _stdout(payload, "no-change", failed=1),
            expected_payload=payload,
            exit_code=2,
        )
    for field, value in (
        ("backend_configured", True),
        ("configuration_performed", True),
        ("registration_performed", True),
        ("service_started", True),
        ("setup_performed", True),
        ("tasks_performed", True),
        ("service_masked", False),
        ("service_inactive", False),
    ):
        claimed = _result(payload, "no-change")
        claimed[field] = value
        encoded = base64.b64encode(
            json.dumps(claimed, sort_keys=True).encode()
        ).decode()
        stdout = (
            f"ok: [{payload['logical_id']}] => "
            f'{{"msg":"DSV_MANAGER_SERVER_B64={encoded}"}}\nPLAY RECAP *****\n'
            f"{payload['logical_id']} : ok=12 changed=0 unreachable=0 "
            "failed=0 skipped=0 rescued=0 ignored=0\n"
        )
        with pytest.raises(AnsibleError, match="success evidence conflicts"):
            parse_manager_server_execution(
                stdout, expected_payload=payload, exit_code=0
            )
    failed = (
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=1 changed=0 unreachable=1 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    evidence = parse_manager_server_execution(
        failed, expected_payload=payload, exit_code=4
    )
    assert evidence.status is ManagerServerStatus.FAILED
    assert evidence.blockers == ("execution-failed",)
    definition = get_playbook("manager-server")
    with pytest.raises(AnsibleError, match="variable value is invalid"):
        definition.validate_variables(
            {"deploy_scylla_vms_manager_server": {"note": "token: obviously-fake"}}
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
    if status == "not-predicted":
        result_body.update(
            {
                "installed_version": None,
                "packages": {},
                "service_inactive": None,
                "service_masked": None,
            }
        )
    encoded = base64.b64encode(
        json.dumps(result_body, sort_keys=True).encode()
    ).decode()
    changed = 1 if status == "installed" else 0
    stdout = (
        "203.0.113.10 secret-token\n"
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_MANAGER_SERVER_B64={encoded}"}}\nPLAY RECAP *****\n'
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
        result = service.execute_manager_server(
            lock,
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            _base_os(),
            limit=("manager-1",),
            readiness=_readiness(inventory),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
            package_version=VERSION,
            cluster_spec_digest=DIGEST,
            check=check,
        )
    assert result.manager_server is not None
    assert result.manager_server.status is ManagerServerStatus(status)
    assert result.stdout == result.stderr == ""
    assert runner.runtime_payloads[-1] == {"deploy_scylla_vms_manager_server": payload}
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
        failed = fail_service.execute_manager_server(
            lock,
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            _base_os(),
            limit=("manager-1",),
            readiness=_readiness(inventory),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
            package_version=VERSION,
            cluster_spec_digest=DIGEST,
        )
    assert failed.manager_server is not None
    assert failed.manager_server.status is ManagerServerStatus.FAILED

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
            AnsibleError, match="manager-server command failed"
        ) as caught:
            timeout_service.execute_manager_server(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                _base_os(),
                limit=("manager-1",),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                package_version=VERSION,
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
            malformed_service.execute_manager_server(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                _base_os(),
                limit=("manager-1",),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                package_version=VERSION,
                cluster_spec_digest=DIGEST,
            )


def test_execute_manager_server_requires_one_manager_target(tmp_path: Path) -> None:
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
            service.execute_manager_server(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                _base_os(),
                limit=("manager-1", "manager-2"),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                package_version=VERSION,
                cluster_spec_digest=DIGEST,
            )
        with pytest.raises(StateConflictError, match="manager stable ID"):
            service.execute_manager_server(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                _base_os("scylla-ad-1-1"),
                limit=("scylla-ad-1-1",),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                package_version=VERSION,
                cluster_spec_digest=DIGEST,
            )


def test_manager_server_registry_dependency_and_static_safety() -> None:
    definition = get_playbook("manager-server")
    assert definition.source_available
    assert definition.hosts == "manager"
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert definition.check_mode is CheckMode.PREVIEW
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.classification is OperationClassification.MUTATING
    assert definition.pre_health_gate is False
    assert definition.post_health_gate is False
    assert definition.tags == (
        "manager-server",
        "preflight",
        "packages",
        "verify",
    )
    assert callable(AnsibleService.execute_manager_server)
    bundle_paths = {item.path for item in load_ansible_source_bundle().files}
    assert {
        "playbooks/manager-server.yml",
        "playbooks/roles/manager_server/files/scylladb-manager-3.12-key.provenance.yml",
    } <= bundle_paths
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content"
    playbook = (root / "playbooks/manager-server.yml").read_text(encoding="utf-8")
    provenance = (
        root
        / "playbooks/roles/manager_server/files/scylladb-manager-3.12-key.provenance.yml"
    ).read_text(encoding="utf-8")
    for required in (
        "gather_facts: true",
        "serial: 1",
        "any_errors_fatal: true",
        "hosts: manager",
        "ansible.builtin.copy:",
        "ansible.builtin.deb822_repository:",
        "ansible.builtin.apt:",
        "policy_rc_d: 101",
        "masked: true",
        "state: stopped",
        "signed_by: /etc/apt/keyrings/scylladb-2026.asc",
        "backend_configured': false",
        "registration_performed': false",
        "service_started': false",
        "setup_performed': false",
        "scylla-manager-client",
        "scylla-manager-server",
        SCYLLA_SIGNING_KEY_FINGERPRINT,
        SCYLLA_SIGNING_KEY_DIGEST,
    ):
        assert required in playbook
    lowered = playbook.lower()
    for forbidden in (
        "ansible.builtin.shell",
        "ansible.builtin.get_url",
        "apt_key",
        "keyserver",
        "curl",
        "wget",
        "http://",
        "state: started",
        "latest",
        "scyllamgr_setup",
        "scyllamgr_auth_token_gen",
        "auth_token:",
        "scylla-manager.yaml",
        "sctool",
        "scylla_setup",
        "selinux",
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
        SCYLLA_SIGNING_KEY_FINGERPRINT,
        SCYLLA_SIGNING_KEY_DIGEST.removeprefix("sha256:"),
        "manager.docs.scylladb.com/stable/install-scylla-manager.html",
        "signed_inrelease:",
        "documented_short_key_id_not_used: A43E06657BAC99E3",
        "scylla-manager-server",
        "scylla-manager-client",
        "scylla-manager.service",
        "Refuse any key-revocation",
        "This slice installs packages only",
    ):
        assert required in provenance


def test_manager_server_playbook_syntax_check_is_local_and_write_free(
    tmp_path: Path,
) -> None:
    executable = shutil.which("ansible-playbook")
    if executable is None:
        pytest.skip("Ansible development executable is unavailable")
    playbook = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/manager-server.yml"
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
