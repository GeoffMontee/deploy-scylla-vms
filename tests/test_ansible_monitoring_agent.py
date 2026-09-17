import base64
import json
import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible import DIGEST, FakeRunner, _builder, _paths, _readiness
from test_ansible_scylla_install import (
    VERSION as SCYLLA_VERSION,
)
from test_ansible_scylla_install import (
    _context as _install_context,
)
from test_ansible_scylla_install import (
    _stdout as _install_stdout,
)
from test_ansible_storage import _postcheck_context

from scylla_vms.ansible.base_os import (
    BaseOsEvidence,
    BaseOsStatus,
)
from scylla_vms.ansible.monitoring_agent import (
    LISTEN_POLICY,
    MONITORING_AGENT_PACKAGES,
    MONITORING_AGENT_SCHEMA_VERSION,
    MONITORING_AGENT_SERVICE,
    NODE_EXPORTER_PORT,
    MonitoringAgentStatus,
    build_monitoring_agent_payload,
    parse_monitoring_agent_execution,
)
from scylla_vms.ansible.registry import CheckMode, get_playbook
from scylla_vms.ansible.scylla_install import (
    SCYLLA_REPOSITORY_DEFINITION_DIGEST,
    SCYLLA_REPOSITORY_URI,
    SCYLLA_SIGNING_KEY_DIGEST,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
    ScyllaInstallEvidence,
    ScyllaInstallStatus,
    parse_scylla_install_execution,
)
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.desired import ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.process import ProcessResult, ProcessTimeoutError

VERSION = SCYLLA_VERSION


def _install() -> ScyllaInstallEvidence:
    install_payload, _ = _install_context()
    return parse_scylla_install_execution(
        _install_stdout(install_payload),
        expected_payload=install_payload,
        exit_code=0,
    )


def _context() -> tuple[dict[str, object], BaseOsEvidence]:
    install = _install()
    metadata, observed, inventory, *_ = _postcheck_context()
    logical_id = install.logical_id
    install_payload, base_os = _install_context()
    assert logical_id == install_payload["logical_id"]
    payload = build_monitoring_agent_payload(
        metadata,
        observed,
        inventory,
        _readiness(inventory),
        base_os,
        install,
        logical_id=logical_id,
        image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
        architecture="amd64",
        package_version=VERSION,
        cluster_spec_digest=DIGEST,
    )
    return payload, base_os


def _result(payload: dict[str, object], status: str = "no-change") -> dict[str, object]:
    success = status in {"installed", "no-change"}
    return {
        "blockers": [] if status != "failed" else ["execution-failed"],
        "configuration_performed": False,
        "installed_version": payload["package_version"] if success else None,
        "listen_policy": LISTEN_POLICY,
        "logical_id": payload["logical_id"],
        "manager_registration_performed": False,
        "packages": (
            {name: payload["package_version"] for name in MONITORING_AGENT_PACKAGES}
            if success
            else {}
        ),
        "process_exporter_installed": False,
        "provenance": payload["provenance"],
        "repository_digest": cast(dict[str, object], payload["repository"])[
            "definition_digest"
        ],
        "requested_release": payload["release_line"],
        "requested_version": payload["package_version"],
        "schema_version": MONITORING_AGENT_SCHEMA_VERSION,
        "scylla_started": False,
        "secrets_written": False,
        "service_enabled": False if success else None,
        "service_inactive": True if success else None,
        "signing_key_digest": cast(dict[str, object], payload["signing_key"])[
            "artifact_digest"
        ],
        "signing_key_fingerprint": cast(dict[str, object], payload["signing_key"])[
            "fingerprint"
        ],
        "stack_installed": False,
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
        f'{{"msg":"DSV_MONITORING_AGENT_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=12 changed={changed} unreachable=0 "
        f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


def test_monitoring_agent_payload_is_exact_and_rejects_unsafe_versions() -> None:
    payload, _ = _context()
    assert payload["release_line"] == "2026.2"
    assert payload["channel"] == "stable"
    assert payload["packages"] == list(MONITORING_AGENT_PACKAGES)
    assert payload["service_unit"] == MONITORING_AGENT_SERVICE
    assert payload["listen_policy"] == LISTEN_POLICY
    assert payload["documented_metrics_port"] == NODE_EXPORTER_PORT
    assert payload["configuration_performed"] is False
    assert payload["process_exporter_installed"] is False
    assert payload["stack_installed"] is False
    assert payload["targets_generated"] is False
    assert payload["manager_registration_performed"] is False
    assert payload["scylla_started"] is False
    assert payload["secrets_written"] is False
    assert (
        cast(dict[str, object], payload["repository"])["uri"] == SCYLLA_REPOSITORY_URI
    )
    assert (
        cast(dict[str, object], payload["repository"])["definition_digest"]
        == SCYLLA_REPOSITORY_DEFINITION_DIGEST
    )
    assert (
        cast(dict[str, object], payload["signing_key"])["fingerprint"]
        == SCYLLA_SIGNING_KEY_FINGERPRINT
    )
    assert (
        cast(dict[str, object], payload["signing_key"])["artifact_digest"]
        == SCYLLA_SIGNING_KEY_DIGEST
    )

    install = _install()
    metadata, observed, inventory, *_ = _postcheck_context()
    logical_id = install.logical_id
    _, base_os = _install_context()
    for version in (
        "latest",
        "2026.2",
        "2026.1.1-0.20260915.abcdef123456-1",
        "2026.2.1~0.20260915.abcdef123456",
    ):
        with pytest.raises(AnsibleError, match=r"exact 2026\.2"):
            build_monitoring_agent_payload(
                metadata,
                observed,
                inventory,
                _readiness(inventory),
                base_os,
                install,
                logical_id=logical_id,
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                package_version=version,
                cluster_spec_digest=DIGEST,
            )
    mismatched = "2026.2.9-0.20260915.abcdef123456-1"
    with pytest.raises(StateConflictError, match="current Scylla install"):
        build_monitoring_agent_payload(
            metadata,
            observed,
            inventory,
            _readiness(inventory),
            base_os,
            install,
            logical_id=logical_id,
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
            package_version=mismatched,
            cluster_spec_digest=DIGEST,
        )


def test_monitoring_agent_requires_current_base_os_install_role_and_os() -> None:
    payload, base_os = _context()
    assert payload
    install = _install()
    metadata, observed, inventory, *_ = _postcheck_context()
    logical_id = install.logical_id
    reboot = BaseOsEvidence(
        BaseOsStatus.REBOOT_REQUIRED,
        (
            replace(
                base_os.hosts[0],
                status=BaseOsStatus.REBOOT_REQUIRED,
                reboot_required=True,
            ),
        ),
    )
    for changed_base, changed_install, readiness, image, target in (
        (reboot, install, _readiness(inventory), _ubuntu(), logical_id),
        (
            base_os,
            replace(install, status=ScyllaInstallStatus.FAILED),
            _readiness(inventory),
            _ubuntu(),
            logical_id,
        ),
        (
            base_os,
            replace(install, logical_id="other-node"),
            _readiness(inventory),
            _ubuntu(),
            logical_id,
        ),
        (
            base_os,
            install,
            replace(_readiness(inventory), trust_digest=None),
            _ubuntu(),
            logical_id,
        ),
        (
            base_os,
            install,
            _readiness(inventory),
            ImageFilter("Oracle Linux", "9", ImageVersionMatch.EXACT),
            logical_id,
        ),
        (
            base_os,
            install,
            _readiness(inventory),
            ImageFilter("Ubuntu", "22.04", ImageVersionMatch.EXACT),
            logical_id,
        ),
        (base_os, install, _readiness(inventory), _ubuntu(), "jump-host-1"),
        (base_os, install, _readiness(inventory), _ubuntu(), "manager-1"),
        (base_os, install, _readiness(inventory), _ubuntu(), "monitoring-1"),
    ):
        with pytest.raises(StateConflictError):
            build_monitoring_agent_payload(
                metadata,
                observed,
                inventory,
                readiness,
                changed_base,
                changed_install,
                logical_id=target,
                image_filter=image,
                architecture="amd64",
                package_version=VERSION,
                cluster_spec_digest=DIGEST,
            )


def _ubuntu() -> ImageFilter:
    return ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT)


@pytest.mark.parametrize(
    ("status", "exit_code", "expected"),
    [
        ("installed", 0, MonitoringAgentStatus.INSTALLED),
        ("no-change", 0, MonitoringAgentStatus.NO_CHANGE),
        ("not-predicted", 0, MonitoringAgentStatus.NOT_PREDICTED),
        ("failed", 2, MonitoringAgentStatus.FAILED),
    ],
)
def test_monitoring_agent_result_parser_statuses(
    status: str, exit_code: int, expected: MonitoringAgentStatus
) -> None:
    payload, _ = _context()
    result = _result(payload, status)
    if status == "not-predicted":
        result.update(
            {
                "blockers": [],
                "installed_version": None,
                "packages": {},
                "service_enabled": None,
                "service_inactive": None,
            }
        )
    encoded = base64.b64encode(json.dumps(result, sort_keys=True).encode()).decode()
    changed = 1 if status == "installed" else 0
    failed = 1 if status == "failed" else 0
    stdout = (
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_MONITORING_AGENT_B64={encoded}"}}\nPLAY RECAP *****\n'
        f"{payload['logical_id']} : ok=12 changed={changed} unreachable=0 "
        f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )
    evidence = parse_monitoring_agent_execution(
        stdout, expected_payload=payload, exit_code=exit_code
    )
    assert evidence.status is expected
    assert evidence.listen_policy == LISTEN_POLICY
    assert evidence.configuration_performed is False
    assert evidence.process_exporter_installed is False
    assert evidence.stack_installed is False
    assert evidence.targets_generated is False
    assert evidence.manager_registration_performed is False
    assert evidence.scylla_started is False
    assert evidence.secrets_written is False
    if expected in {MonitoringAgentStatus.INSTALLED, MonitoringAgentStatus.NO_CHANGE}:
        assert evidence.service_enabled is False
        assert evidence.service_inactive is True
        assert evidence.packages == tuple(
            (name, VERSION) for name in MONITORING_AGENT_PACKAGES
        )


def test_monitoring_agent_parser_refuses_malformed_public_bind_and_conflicts() -> None:
    payload, _ = _context()
    with pytest.raises(AnsibleError, match="exceeds"):
        parse_monitoring_agent_execution(
            "x" * (512 * 1024 + 1), expected_payload=payload, exit_code=2
        )
    with pytest.raises(AnsibleError):
        parse_monitoring_agent_execution(
            _stdout(payload, "no-change", failed=1),
            expected_payload=payload,
            exit_code=2,
        )
    claimed = _result(payload, "no-change")
    claimed["listen_policy"] = "private"
    encoded = base64.b64encode(json.dumps(claimed, sort_keys=True).encode()).decode()
    stdout = (
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_MONITORING_AGENT_B64={encoded}"}}\nPLAY RECAP *****\n'
        f"{payload['logical_id']} : ok=12 changed=0 unreachable=0 "
        "failed=0 skipped=0 rescued=0 ignored=0\n"
    )
    with pytest.raises(AnsibleError, match="evidence conflicts"):
        parse_monitoring_agent_execution(stdout, expected_payload=payload, exit_code=0)
    started = _result(payload, "no-change")
    started["stack_installed"] = True
    encoded = base64.b64encode(json.dumps(started, sort_keys=True).encode()).decode()
    stdout = (
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_MONITORING_AGENT_B64={encoded}"}}\nPLAY RECAP *****\n'
        f"{payload['logical_id']} : ok=12 changed=0 unreachable=0 "
        "failed=0 skipped=0 rescued=0 ignored=0\n"
    )
    with pytest.raises(AnsibleError, match="success evidence conflicts"):
        parse_monitoring_agent_execution(stdout, expected_payload=payload, exit_code=0)
    failed = (
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=1 changed=0 unreachable=1 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    evidence = parse_monitoring_agent_execution(
        failed, expected_payload=payload, exit_code=4
    )
    assert evidence.status is MonitoringAgentStatus.FAILED
    assert evidence.blockers == ("execution-failed",)
    definition = get_playbook("monitoring-agent")
    with pytest.raises(AnsibleError, match="variable value is invalid"):
        definition.validate_variables(
            {"deploy_scylla_vms_monitoring_agent": {"note": "token: obviously-fake"}}
        )


@pytest.mark.parametrize(
    ("check", "status"), [(False, "installed"), (True, "not-predicted")]
)
def test_service_success_failure_timeout_malformed_and_redaction(
    tmp_path: Path, check: bool, status: str
) -> None:
    payload, base_os = _context()
    install = _install()
    metadata, observed, inventory, *_ = _postcheck_context()
    paths = _paths(tmp_path)
    result_body = _result(payload, status)
    if status == "not-predicted":
        result_body.update(
            {
                "installed_version": None,
                "packages": {},
                "service_enabled": None,
                "service_inactive": None,
            }
        )
    encoded = base64.b64encode(
        json.dumps(result_body, sort_keys=True).encode()
    ).decode()
    changed = 1 if status == "installed" else 0
    stdout = (
        "203.0.113.10 secret-token\n"
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_MONITORING_AGENT_B64={encoded}"}}\nPLAY RECAP *****\n'
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
        result = service.execute_monitoring_agent(
            lock,
            metadata,
            observed,
            inventory,
            base_os,
            install,
            limit=(cast(str, payload["logical_id"]),),
            readiness=_readiness(inventory),
            image_filter=_ubuntu(),
            architecture="amd64",
            package_version=VERSION,
            cluster_spec_digest=DIGEST,
            check=check,
        )
    assert result.monitoring_agent is not None
    assert result.monitoring_agent.status is MonitoringAgentStatus(status)
    assert result.stdout == result.stderr == ""
    assert runner.runtime_payloads[-1] == {
        "deploy_scylla_vms_monitoring_agent": payload
    }
    assert "--limit" in runner.specs[-1].argv
    assert cast(str, payload["logical_id"]) in runner.specs[-1].argv
    assert ("--check" in runner.specs[-1].argv) is check
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
        failed = fail_service.execute_monitoring_agent(
            lock,
            metadata,
            observed,
            inventory,
            base_os,
            install,
            limit=(cast(str, payload["logical_id"]),),
            readiness=_readiness(inventory),
            image_filter=_ubuntu(),
            architecture="amd64",
            package_version=VERSION,
            cluster_spec_digest=DIGEST,
        )
    assert failed.monitoring_agent is not None
    assert failed.monitoring_agent.status is MonitoringAgentStatus.FAILED

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
            AnsibleError, match="monitoring-agent command failed"
        ) as caught:
            timeout_service.execute_monitoring_agent(
                lock,
                metadata,
                observed,
                inventory,
                base_os,
                install,
                limit=(cast(str, payload["logical_id"]),),
                readiness=_readiness(inventory),
                image_filter=_ubuntu(),
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
            malformed_service.execute_monitoring_agent(
                lock,
                metadata,
                observed,
                inventory,
                base_os,
                install,
                limit=(cast(str, payload["logical_id"]),),
                readiness=_readiness(inventory),
                image_filter=_ubuntu(),
                architecture="amd64",
                package_version=VERSION,
                cluster_spec_digest=DIGEST,
            )


def test_execute_monitoring_agent_requires_one_scylla_target(tmp_path: Path) -> None:
    _, base_os = _context()
    install = _install()
    metadata, observed, inventory, *_ = _postcheck_context()
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
            service.execute_monitoring_agent(
                lock,
                metadata,
                observed,
                inventory,
                base_os,
                install,
                limit=(install.logical_id, "scylla-ad-1-2"),
                readiness=_readiness(inventory),
                image_filter=_ubuntu(),
                architecture="amd64",
                package_version=VERSION,
                cluster_spec_digest=DIGEST,
            )
        with pytest.raises(StateConflictError, match="not a Scylla stable ID"):
            service.execute_monitoring_agent(
                lock,
                metadata,
                observed,
                inventory,
                base_os,
                install,
                limit=("jump-host-1",),
                readiness=_readiness(inventory),
                image_filter=_ubuntu(),
                architecture="amd64",
                package_version=VERSION,
                cluster_spec_digest=DIGEST,
            )


def test_monitoring_agent_registry_dependency_and_static_safety() -> None:
    definition = get_playbook("monitoring-agent")
    assert definition.source_available
    assert definition.hosts == "scylla"
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert definition.check_mode is CheckMode.PREVIEW
    assert definition.classification is OperationClassification.MUTATING
    assert definition.pre_health_gate is False
    assert definition.post_health_gate is False
    assert definition.tags == (
        "monitoring-agent",
        "preflight",
        "packages",
        "verify",
    )
    assert callable(AnsibleService.execute_monitoring_agent)
    bundle_paths = {item.path for item in load_ansible_source_bundle().files}
    assert {
        "playbooks/monitoring-agent.yml",
        "playbooks/roles/monitoring_agent/files/scylladb-2026-node-exporter.provenance.yml",
    } <= bundle_paths
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content"
    playbook = (root / "playbooks/monitoring-agent.yml").read_text(encoding="utf-8")
    provenance = (
        root
        / "playbooks/roles/monitoring_agent/files/scylladb-2026-node-exporter.provenance.yml"
    ).read_text(encoding="utf-8")
    for required in (
        "gather_facts: true",
        "serial: 1",
        "any_errors_fatal: true",
        "hosts: scylla",
        "ansible.builtin.copy:",
        "ansible.builtin.deb822_repository:",
        "ansible.builtin.apt:",
        "policy_rc_d: 101",
        "enabled: false",
        "state: stopped",
        "signed_by: /etc/apt/keyrings/scylladb-2026.asc",
        "listen_policy': 'not-started'",
        "process_exporter_installed': false",
        "stack_installed': false",
        "targets_generated': false",
        "scylla-node-exporter",
        SCYLLA_SIGNING_KEY_FINGERPRINT,
        SCYLLA_SIGNING_KEY_DIGEST,
    ):
        assert required in playbook
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
        "0.0.0.0",
        "node_exporter_install",
        "scyllamgr_setup",
        "scylla_setup",
        "auth_token:",
        "docker",
        "grafana",
        "prometheus.yml",
        "scylla_servers.yml",
        "selinux",
        "reboot:",
        "validate_certs: false",
        "trusted=yes",
        "hosts: jump",
        "hosts: manager",
        "hosts: monitoring",
        "hosts: all",
    ):
        assert forbidden not in playbook.lower()
    for required in (
        'retrieved_at: "2026-09-18"',
        SCYLLA_SIGNING_KEY_FINGERPRINT,
        SCYLLA_SIGNING_KEY_DIGEST.removeprefix("sha256:"),
        "monitoring.docs.scylladb.com/stable/install/monitoring-stack.html",
        "official_documented_metrics_port: 9100",
        "process_exporter_per_node_package: not-documented",
        "documented_short_key_id_not_used: A43E06657BAC99E3",
        "Refuse latest",
        "This slice installs the official node-exporter package only",
    ):
        assert required in provenance


def test_monitoring_agent_playbook_syntax_check_is_local_and_write_free(
    tmp_path: Path,
) -> None:
    executable = shutil.which("ansible-playbook")
    if executable is None:
        pytest.skip("Ansible development executable is unavailable")
    playbook = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/monitoring-agent.yml"
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
