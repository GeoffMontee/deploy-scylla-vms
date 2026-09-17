import base64
import json
import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible import DIGEST, _readiness
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
from scylla_vms.ansible.manager_agent import (
    MANAGER_AGENT_SCHEMA_VERSION,
    MANAGER_PACKAGE_VERSION,
    MANAGER_PACKAGES,
    MANAGER_RELEASE_LINE,
    MANAGER_REPOSITORY_DEFINITION_DIGEST,
    ManagerAgentStatus,
    build_manager_agent_payload,
    parse_manager_agent_execution,
)
from scylla_vms.ansible.registry import CheckMode, get_playbook
from scylla_vms.ansible.scylla_install import (
    SCYLLA_SIGNING_KEY_DIGEST,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
    ScyllaInstallStatus,
    parse_scylla_install_execution,
)
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.desired import ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.operations import OperationClassification

VERSION = MANAGER_PACKAGE_VERSION


def _context() -> tuple[dict[str, object], BaseOsEvidence]:
    install_payload, base_os = _install_context()
    install = parse_scylla_install_execution(
        _install_stdout(install_payload),
        expected_payload=install_payload,
        exit_code=0,
    )
    metadata, observed, inventory, *_ = _postcheck_context()
    logical_id = cast(str, install_payload["logical_id"])
    payload = build_manager_agent_payload(
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
        "auth_token_configured": False,
        "blockers": [] if status != "failed" else ["execution-failed"],
        "configuration_performed": False,
        "helper_slice_configured": False,
        "installed_version": payload["package_version"] if success else None,
        "logical_id": payload["logical_id"],
        "packages": (
            {name: payload["package_version"] for name in MANAGER_PACKAGES}
            if success
            else {}
        ),
        "provenance": payload["provenance"],
        "repository_digest": cast(dict[str, object], payload["repository"])[
            "definition_digest"
        ],
        "requested_release": payload["release_line"],
        "requested_version": payload["package_version"],
        "schema_version": MANAGER_AGENT_SCHEMA_VERSION,
        "server_reachability": "not-performed",
        "service_enabled": False if success else None,
        "service_inactive": True if success else None,
        "signing_key_digest": cast(dict[str, object], payload["signing_key"])[
            "artifact_digest"
        ],
        "signing_key_fingerprint": cast(dict[str, object], payload["signing_key"])[
            "fingerprint"
        ],
        "status": status,
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
        f'{{"msg":"DSV_MANAGER_AGENT_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=12 changed={changed} unreachable=0 "
        f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


def test_manager_agent_payload_is_exact_and_rejects_unsafe_versions() -> None:
    payload, _ = _context()
    assert payload["release_line"] == MANAGER_RELEASE_LINE
    assert payload["channel"] == "stable"
    assert payload["packages"] == list(MANAGER_PACKAGES)
    assert payload["configuration_performed"] is False
    assert payload["auth_token_configured"] is False
    assert payload["helper_slice_configured"] is False
    assert payload["server_reachability"] == "not-performed"
    assert payload["documented_https_port"] == 10001
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

    install_payload, base_os = _install_context()
    install = parse_scylla_install_execution(
        _install_stdout(install_payload),
        expected_payload=install_payload,
        exit_code=0,
    )
    metadata, observed, inventory, *_ = _postcheck_context()
    logical_id = cast(str, install_payload["logical_id"])
    for version in (
        "latest",
        "3.12",
        "3.11.1~0.20260911.6f499af46",
        "3.12.1-0.20260911.6f499af46",
    ):
        with pytest.raises(AnsibleError, match=r"exact 3\.12"):
            build_manager_agent_payload(
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
    assert SCYLLA_VERSION


def test_manager_agent_requires_current_base_os_install_and_provenance() -> None:
    payload, base_os = _context()
    assert payload
    install_payload, _ = _install_context()
    install = parse_scylla_install_execution(
        _install_stdout(install_payload),
        expected_payload=install_payload,
        exit_code=0,
    )
    metadata, observed, inventory, *_ = _postcheck_context()
    logical_id = cast(str, install_payload["logical_id"])
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
    for changed_base, changed_install, readiness in (
        (reboot, install, _readiness(inventory)),
        (
            base_os,
            replace(install, status=ScyllaInstallStatus.FAILED),
            _readiness(inventory),
        ),
        (
            base_os,
            replace(install, logical_id="other-node"),
            _readiness(inventory),
        ),
        (
            base_os,
            install,
            replace(_readiness(inventory), trust_digest=None),
        ),
    ):
        with pytest.raises(StateConflictError):
            build_manager_agent_payload(
                metadata,
                observed,
                inventory,
                readiness,
                changed_base,
                changed_install,
                logical_id=logical_id,
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                package_version=VERSION,
                cluster_spec_digest=DIGEST,
            )


@pytest.mark.parametrize(
    ("status", "exit_code", "expected"),
    [
        ("installed", 0, ManagerAgentStatus.INSTALLED),
        ("no-change", 0, ManagerAgentStatus.NO_CHANGE),
        ("not-predicted", 0, ManagerAgentStatus.NOT_PREDICTED),
        ("failed", 2, ManagerAgentStatus.FAILED),
    ],
)
def test_manager_agent_result_parser_statuses(
    status: str, exit_code: int, expected: ManagerAgentStatus
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
        f'{{"msg":"DSV_MANAGER_AGENT_B64={encoded}"}}\nPLAY RECAP *****\n'
        f"{payload['logical_id']} : ok=12 changed={changed} unreachable=0 "
        f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )
    evidence = parse_manager_agent_execution(
        stdout, expected_payload=payload, exit_code=exit_code
    )
    assert evidence.status is expected
    assert evidence.configuration_performed is False
    assert evidence.auth_token_configured is False
    assert evidence.server_reachability == "not-performed"


def test_manager_agent_parser_refuses_malformed_oversize_and_conflicts() -> None:
    payload, _ = _context()
    with pytest.raises(AnsibleError, match="exceeds"):
        parse_manager_agent_execution(
            "x" * (512 * 1024 + 1), expected_payload=payload, exit_code=2
        )
    with pytest.raises(AnsibleError):
        parse_manager_agent_execution(
            _stdout(payload, "no-change", failed=1),
            expected_payload=payload,
            exit_code=2,
        )
    claimed = _result(payload, "no-change")
    claimed["configuration_performed"] = True
    encoded = base64.b64encode(json.dumps(claimed, sort_keys=True).encode()).decode()
    stdout = (
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_MANAGER_AGENT_B64={encoded}"}}\nPLAY RECAP *****\n'
        f"{payload['logical_id']} : ok=12 changed=0 unreachable=0 "
        "failed=0 skipped=0 rescued=0 ignored=0\n"
    )
    with pytest.raises(AnsibleError, match="success evidence conflicts"):
        parse_manager_agent_execution(stdout, expected_payload=payload, exit_code=0)
    failed = (
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=1 changed=0 unreachable=1 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    evidence = parse_manager_agent_execution(
        failed, expected_payload=payload, exit_code=4
    )
    assert evidence.status is ManagerAgentStatus.FAILED
    assert evidence.blockers == ("execution-failed",)


def test_manager_agent_registry_dependency_and_static_safety() -> None:
    definition = get_playbook("manager-agent")
    assert definition.source_available
    assert definition.hosts == "scylla"
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert definition.check_mode is CheckMode.PREVIEW
    assert definition.classification is OperationClassification.MUTATING
    assert definition.pre_health_gate is False
    assert definition.post_health_gate is False
    assert definition.tags == (
        "manager-agent",
        "preflight",
        "packages",
        "verify",
    )
    bundle_paths = {item.path for item in load_ansible_source_bundle().files}
    assert {
        "playbooks/manager-agent.yml",
        "playbooks/roles/manager_agent/files/scylladb-manager-3.12-key.provenance.yml",
    } <= bundle_paths
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content"
    playbook = (root / "playbooks/manager-agent.yml").read_text(encoding="utf-8")
    provenance = (
        root
        / "playbooks/roles/manager_agent/files/scylladb-manager-3.12-key.provenance.yml"
    ).read_text(encoding="utf-8")
    for required in (
        "gather_facts: true",
        "serial: 1",
        "any_errors_fatal: true",
        "ansible.builtin.copy:",
        "ansible.builtin.deb822_repository:",
        "ansible.builtin.apt:",
        "policy_rc_d: 101",
        "enabled: false",
        "state: stopped",
        "signed_by: /etc/apt/keyrings/scylladb-2026.asc",
        "configuration_performed': false",
        "server_reachability': 'not-performed'",
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
        "scyllamgr_agent_setup",
        "scyllamgr_auth_token_gen",
        "auth_token:",
        "scylla-manager.yaml",
        "scylla-server",
        "scylla_setup",
        "selinux",
        "reboot:",
        "validate_certs: false",
        "trusted=yes",
    ):
        assert forbidden not in playbook.lower()
    for required in (
        'retrieved_at: "2026-09-18"',
        SCYLLA_SIGNING_KEY_FINGERPRINT,
        SCYLLA_SIGNING_KEY_DIGEST.removeprefix("sha256:"),
        "manager.docs.scylladb.com/stable/compatibility-matrix.html",
        "signed_inrelease:",
        "documented_short_key_id_not_used: A43E06657BAC99E3",
        "Refuse any key-revocation",
    ):
        assert required in provenance


def test_manager_agent_playbook_syntax_check_is_local_and_write_free(
    tmp_path: Path,
) -> None:
    executable = shutil.which("ansible-playbook")
    if executable is None:
        pytest.skip("Ansible development executable is unavailable")
    playbook = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/manager-agent.yml"
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
