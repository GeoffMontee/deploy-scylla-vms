import base64
import json
import os
import shutil
import subprocess
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

from scylla_vms.ansible.base_os import (
    BASE_OS_EVIDENCE_SCHEMA_VERSION,
    SUPPORTED_BASE_OS_MATRIX,
    BaseOsStatus,
    base_os_variables,
    parse_base_os_evidence,
)
from scylla_vms.ansible.registry import PLAYBOOKS, get_playbook
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.desired import ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError
from scylla_vms.locking import ClusterLock
from scylla_vms.process import ProcessResult, ProcessTimeoutError


def _marker(
    *,
    logical_id: str = "jump-host-1",
    status: str = "no-change",
    changed: bool = False,
    reboot_required: bool = False,
    reason: str = "already-current",
) -> str:
    value = {
        "changed": changed,
        "logical_id": logical_id,
        "reason": reason,
        "reboot_required": reboot_required,
        "schema_version": BASE_OS_EVIDENCE_SCHEMA_VERSION,
        "status": status,
    }
    encoded = base64.b64encode(
        json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    ).decode()
    return f'ok: [{logical_id}] => {{"msg": "DSV_BASE_OS_B64={encoded}"}}\n'


def _stdout(
    marker: str,
    *,
    changed: int = 0,
    unreachable: int = 0,
    failed: int = 0,
) -> str:
    return (
        marker
        + "PLAY RECAP *****\n"
        + f"jump-host-1 : ok=8 changed={changed} unreachable={unreachable} "
        + f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


def _variables() -> dict[str, object]:
    return {
        "deploy_scylla_vms_image_architecture": "amd64",
        "deploy_scylla_vms_image_operating_system": "Ubuntu",
        "deploy_scylla_vms_image_operating_system_version": "24.04",
    }


def test_base_os_registry_matrix_source_and_package_parity() -> None:
    definition = get_playbook("base-os")
    assert definition.source_available
    assert definition.hosts == "all"
    assert definition.serial == 1
    assert definition.tags == ("base-os",)
    assert {book.name for book in PLAYBOOKS if book.source_available} == {
        "base-os",
        "connectivity-check",
        "deploy-reboot",
        "evidence-collect",
        "inventory-preflight",
        "jump-host-configure",
        "manager-agent",
        "manager-server",
        "manager-tasks",
        "monitoring-agent",
        "monitoring-stack",
        "monitoring-targets",
        "os-reprovision-prepare",
        "os-upgrade-in-place",
        "os-upgrade-postcheck",
        "os-upgrade-preflight",
        "routed-keyscan",
        "scylla-bootstrap",
        "scylla-cleanup",
        "scylla-cluster-shutdown",
        "scylla-configure",
        "scylla-health",
        "scylla-install",
        "scylla-remove-dead",
        "scylla-remove-live",
        "scylla-replace-dead",
        "scylla-repair",
        "service-converge",
        "storage-discover",
        "storage-postcheck",
        "storage-preflight",
        "storage-prepare",
        "storage-retire",
    }
    assert definition.validate_variables(_variables()) == _variables()
    arm = {**_variables(), "deploy_scylla_vms_image_architecture": "aarch64"}
    assert definition.validate_variables(arm) == arm
    assert SUPPORTED_BASE_OS_MATRIX == (
        ("Ubuntu", "24.04", "amd64", "Ubuntu", "24.04", "x86_64"),
        ("Ubuntu", "24.04", "aarch64", "Ubuntu", "24.04", "aarch64"),
    )
    assert (
        base_os_variables(
            ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT), "amd64"
        )
        == _variables()
    )
    with pytest.raises(AnsibleError, match="unsupported"):
        base_os_variables(
            ImageFilter("Ubuntu", "24.04", ImageVersionMatch.PREFIX), "amd64"
        )
    for name, value in (
        ("deploy_scylla_vms_image_operating_system", "Debian"),
        ("deploy_scylla_vms_image_operating_system_version", "9"),
        ("deploy_scylla_vms_image_architecture", "ppc64le"),
    ):
        with pytest.raises(AnsibleError, match="variable value is invalid"):
            definition.validate_variables({**_variables(), name: value})

    bundle_paths = {item.path for item in load_ansible_source_bundle().files}
    expected = {
        "playbooks/base-os.yml",
        "playbooks/roles/base_os/tasks/Ubuntu.yml",
        "playbooks/roles/base_os/tasks/main.yml",
    }
    assert expected <= bundle_paths
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content"
    assert {
        str(path.relative_to(root))
        for pattern in ("*.asc", "*.j2", "*.yml", "*.py")
        for path in root.rglob(pattern)
        if path.is_file()
    } == bundle_paths - {"ansible.cfg"}


def test_base_os_static_safety_and_minimal_scope() -> None:
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content"
    text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            root / "playbooks/base-os.yml",
            root / "playbooks/roles/base_os/tasks/main.yml",
            root / "playbooks/roles/base_os/tasks/Ubuntu.yml",
        )
    )
    assert "  hosts: all\n" in text
    assert "  become: true\n" in text
    assert "  serial: 1\n" in text
    assert "  any_errors_fatal: true\n" in text
    assert "ansible.builtin.setup:" in text
    assert "ansible.builtin.apt:" in text
    assert "ansible.builtin.systemd_service:" in text
    assert "name: systemd-timesyncd" in text
    assert "ansible.builtin.reboot" not in text
    assert "ansible.builtin.shell" not in text
    assert "ansible.builtin.mount" not in text
    assert "ansible.builtin.filesystem" not in text
    assert "scylla-server" not in text.lower()
    assert "scylla-enterprise" not in text.lower()
    assert "scylla.repo" not in text.lower()
    for forbidden in (
        "selinux: disabled",
        "setenforce",
        "apparmor",
        "firewalld",
        "iptables",
        "passwordauthentication",
        "permitemptypasswords",
        "swapoff",
        "sysctl",
        "/etc/yum.repos.d",
    ):
        assert forbidden not in text.lower()


def test_base_os_parser_changed_no_change_reboot_unsupported_and_failure() -> None:
    no_change = parse_base_os_evidence(_stdout(_marker()), ("jump-host-1",), 0)
    assert no_change.status is BaseOsStatus.NO_CHANGE

    changed = parse_base_os_evidence(
        _stdout(
            _marker(status="changed", changed=True, reason="applied"),
            changed=2,
        ),
        ("jump-host-1",),
        0,
    )
    assert changed.status is BaseOsStatus.CHANGED

    reboot = parse_base_os_evidence(
        _stdout(
            _marker(
                status="reboot-required",
                changed=True,
                reboot_required=True,
                reason="reboot-required",
            ),
            changed=1,
        ),
        ("jump-host-1",),
        0,
    )
    assert reboot.status is BaseOsStatus.REBOOT_REQUIRED

    unsupported = parse_base_os_evidence(
        _stdout(
            _marker(
                status="unsupported",
                reason="guest-facts-mismatch",
            ),
            failed=1,
        ),
        ("jump-host-1",),
        2,
    )
    assert unsupported.status is BaseOsStatus.UNSUPPORTED

    failure = parse_base_os_evidence(_stdout("", unreachable=1), ("jump-host-1",), 4)
    assert failure.status is BaseOsStatus.FAILURE


@pytest.mark.parametrize(
    "stdout,exit_code",
    [
        ("PLAY RECAP *****\n", 0),
        (_stdout("DSV_BASE_OS_B64=***\n"), 2),
        (_stdout(_marker()) + _marker(), 0),
        (_stdout(_marker(status="changed", changed=True, reason="applied")), 0),
        (_stdout(_marker()), 2),
        ("x" * (1024 * 1024 + 1), 2),
    ],
)
def test_base_os_parser_rejects_malformed_or_conflicting_evidence(
    stdout: str, exit_code: int
) -> None:
    with pytest.raises(AnsibleError):
        parse_base_os_evidence(stdout, ("jump-host-1",), exit_code)


def test_base_os_service_exact_argv_vars_gates_redaction_and_no_writes(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    inventory = _inventory()
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.19.3]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.19.3]\n", ""),
            ProcessResult(
                0,
                _stdout(_marker()),
                "token=obviously-fake should not be retained",
            ),
        ]
    )
    service = AnsibleService(_builder(tmp_path, paths), runner)
    before = {
        path: path.read_bytes()
        for path in (
            paths.ansible_inventory,
            paths.known_hosts,
            paths.ansible_ssh_config,
        )
    }
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute(
            lock,
            _metadata(),
            inventory,
            "base-os",
            limit=("jump-host-1",),
            variables=_variables(),
            readiness=_readiness(inventory),
            tags=("base-os",),
            check=True,
            diff=True,
        )
    assert result.base_os is not None
    assert result.base_os.status is BaseOsStatus.NO_CHANGE
    assert result.stdout == result.stderr == ""
    spec = runner.specs[-1]
    assert spec.argv[spec.argv.index("--limit") + 1] == "jump-host-1"
    assert spec.argv[spec.argv.index("--tags") + 1] == "base-os"
    assert spec.argv[-3:-1] == ("--check", "--diff")
    assert spec.argv[-1].endswith("/playbooks/base-os.yml")
    assert spec.allowed_exit_codes == frozenset({0, 2, 4})
    assert runner.runtime_payloads == [_variables()]
    assert {
        path: path.read_bytes()
        for path in (
            paths.ansible_inventory,
            paths.known_hosts,
            paths.ansible_ssh_config,
        )
    } == before
    assert not tuple(paths.ansible_local_tmp.iterdir())


def test_base_os_service_timeout_is_redacted_and_cleans_runtime(
    tmp_path: Path,
) -> None:
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
        runner.error = ProcessTimeoutError("token=obviously-fake")
        with pytest.raises(AnsibleError, match="base-os command failed") as caught:
            service.execute(
                lock,
                _metadata(),
                inventory,
                "base-os",
                limit=("jump-host-1",),
                variables=_variables(),
                readiness=_readiness(inventory),
            )
    assert "obviously-fake" not in str(caught.value)
    assert not tuple(paths.ansible_local_tmp.iterdir())


def test_base_os_playbook_syntax_check_is_local_and_write_free(
    tmp_path: Path,
) -> None:
    executable = shutil.which("ansible-playbook")
    if executable is None:
        pytest.skip("Ansible development executable is unavailable")
    playbook = (
        Path(__file__).parents[1] / "scylla_vms/ansible/content/playbooks/base-os.yml"
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
