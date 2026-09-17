import base64
import json
import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from test_ansible import FakeRunner, _builder, _paths
from test_ansible_os_upgrade_preflight import (
    OPERATION_ID,
    TARGETS,
)
from test_ansible_os_upgrade_preflight import (
    _context as _preflight_context,
)
from test_ansible_os_upgrade_preflight import _result as _preflight_result
from test_ansible_os_upgrade_preflight import (
    _stdout as _preflight_stdout,
)
from test_ansible_service_converge import _readiness

from scylla_vms.ansible.os_upgrade_in_place import (
    ACTION_NOT_PERFORMED,
    MUTATION_BOUNDARY,
    NOT_PERFORMED,
    OS_UPGRADE_IN_PLACE_SCHEMA_VERSION,
    OsUpgradeInPlaceStatus,
    build_os_upgrade_in_place_authorization,
    build_os_upgrade_in_place_payload,
    parse_os_upgrade_in_place_execution,
)
from scylla_vms.ansible.os_upgrade_preflight import (
    OsUpgradePreflightStatus,
    parse_os_upgrade_preflight_execution,
)
from scylla_vms.ansible.registry import (
    PLAYBOOKS,
    CheckMode,
    LimitPolicy,
    get_playbook,
)
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.desired import HostRole, ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.process import ProcessResult, ProcessTimeoutError


def _context(
    role: HostRole = HostRole.JUMP_HOST,
    *,
    target_os: str = "Ubuntu",
    target_version: str = "26.04",
    architecture: str = "amd64",
) -> tuple[
    dict[str, object],
    Any,
    Any,
    Any,
    Any,
    Any,
    Any,
    Any,
    Any,
]:
    (
        preflight_payload,
        metadata,
        observed,
        inventory,
        base_os,
        prerequisites,
        intent,
    ) = _preflight_context(
        role,
        target_os=target_os,
        target_version=target_version,
    )
    preflight = parse_os_upgrade_preflight_execution(
        _preflight_stdout(
            preflight_payload,
            result=_preflight_result(preflight_payload),
        ),
        expected_payload=preflight_payload,
        exit_code=0,
    )
    readiness = _readiness(inventory)
    authorization = build_os_upgrade_in_place_authorization(
        metadata,
        observed,
        inventory,
        readiness,
        preflight,
        operation_id=OPERATION_ID,
    )
    payload = build_os_upgrade_in_place_payload(
        metadata,
        observed,
        inventory,
        readiness,
        base_os,
        prerequisites,
        intent,
        preflight,
        authorization,
        limit=(TARGETS[role],),
        image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
        architecture=architecture,
    )
    return (
        payload,
        metadata,
        observed,
        inventory,
        base_os,
        prerequisites,
        intent,
        preflight,
        authorization,
    )


def _result(
    payload: dict[str, object],
    *,
    status: str = "blocked",
    blockers: list[str] | None = None,
) -> dict[str, object]:
    return {
        "applied": False,
        "architecture": payload["architecture"],
        "automatic_retry": False,
        "blockers": blockers if blockers is not None else payload["expected_blockers"],
        "configuration_action": ACTION_NOT_PERFORMED,
        "current_operating_system": payload["current_operating_system"],
        "current_operating_system_version": payload["current_operating_system_version"],
        "kernel_action": ACTION_NOT_PERFORMED,
        "logical_id": payload["logical_id"],
        "mutation_boundary": MUTATION_BOUNDARY,
        "not_performed": payload["not_performed"],
        "package_action": ACTION_NOT_PERFORMED,
        "provenance": payload["provenance"],
        "reboot_action": ACTION_NOT_PERFORMED,
        "recovery_required": False,
        "role": payload["role"],
        "schema_version": OS_UPGRADE_IN_PLACE_SCHEMA_VERSION,
        "service_action": ACTION_NOT_PERFORMED,
        "source_action": ACTION_NOT_PERFORMED,
        "status": status,
        "target_operating_system": payload["target_operating_system"],
        "target_operating_system_version": payload["target_operating_system_version"],
        "transition_classification": "unapproved",
    }


def _stdout(
    payload: dict[str, object],
    *,
    result: dict[str, object] | None = None,
    failed: int = 0,
    unreachable: int = 0,
    noise: str = "",
) -> str:
    encoded = base64.b64encode(
        json.dumps(result or _result(payload), sort_keys=True).encode()
    ).decode()
    return (
        noise
        + f"ok: [{payload['logical_id']}] => "
        + f'{{"msg":"DSV_OS_UPGRADE_IN_PLACE_B64={encoded}"}}\n'
        + "PLAY RECAP *****\n"
        + f"{payload['logical_id']} : ok=4 changed=0 unreachable={unreachable} "
        + f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


@pytest.mark.parametrize(
    ("role", "expected_blockers"),
    [
        (HostRole.JUMP_HOST, ["target-transition-unapproved"]),
        (
            HostRole.SCYLLA,
            ["shutdown-sequence-unreviewed", "target-transition-unapproved"],
        ),
    ],
)
def test_payload_is_exact_role_aware_and_always_blocked(
    role: HostRole,
    expected_blockers: list[str],
) -> None:
    payload, *_ = _context(role)
    assert payload["schema_version"] == OS_UPGRADE_IN_PLACE_SCHEMA_VERSION
    assert payload["logical_id"] == TARGETS[role]
    assert payload["role"] == role.value
    assert payload["transition_classification"] == "unapproved"
    assert payload["mutation_boundary"] == MUTATION_BOUNDARY
    assert payload["recovery_required"] is False
    assert payload["expected_blockers"] == expected_blockers
    assert payload["not_performed"] == list(NOT_PERFORMED)
    for field in (
        "package_action",
        "source_action",
        "service_action",
        "reboot_action",
        "kernel_action",
        "configuration_action",
    ):
        assert payload[field] == ACTION_NOT_PERFORMED
    encoded = json.dumps(payload, sort_keys=True)
    assert "10.0.0." not in encoded
    assert "203.0.113." not in encoded
    assert "ocid1." not in encoded
    assert "token:" not in encoded


def test_payload_refuses_wrong_stable_id_and_ineligible_role() -> None:
    (
        _,
        metadata,
        observed,
        inventory,
        base_os,
        prerequisites,
        intent,
        preflight,
        authorization,
    ) = _context()
    with pytest.raises(StateConflictError, match="one exact stable ID"):
        build_os_upgrade_in_place_payload(
            metadata,
            observed,
            inventory,
            _readiness(inventory),
            base_os,
            prerequisites,
            intent,
            preflight,
            authorization,
            limit=("manager-1",),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )
    with pytest.raises(StateConflictError, match="explicitly eligible"):
        _context(HostRole.MANAGER)
    with pytest.raises(StateConflictError, match="explicitly eligible"):
        _context(HostRole.MONITORING)


def test_same_unsupported_and_architecture_mismatch_are_refused() -> None:
    with pytest.raises(StateConflictError, match="not an upgrade"):
        _context(target_version="24.04")
    with pytest.raises(StateConflictError, match="target OS is unsupported"):
        _context(target_os="Oracle Linux", target_version="9")
    with pytest.raises(StateConflictError, match="architecture evidence mismatches"):
        _context(architecture="aarch64")


def test_stale_failed_or_ineligible_preflight_and_authorization_are_refused() -> None:
    (
        _,
        metadata,
        observed,
        inventory,
        base_os,
        prerequisites,
        intent,
        preflight,
        authorization,
    ) = _context()
    readiness = _readiness(inventory)
    stale = replace(
        preflight,
        provenance=tuple(
            (name, "sha256:" + "1" * 64 if name == "trust_digest" else value)
            for name, value in preflight.provenance
        ),
    )
    for invalid in (
        stale,
        replace(
            preflight,
            status=OsUpgradePreflightStatus.FAILED,
            blockers=("execution-failed",),
        ),
        replace(preflight, rolling_eligible=False),
    ):
        with pytest.raises(StateConflictError, match="eligible preflight"):
            build_os_upgrade_in_place_payload(
                metadata,
                observed,
                inventory,
                readiness,
                base_os,
                prerequisites,
                intent,
                invalid,
                authorization,
                limit=(TARGETS[HostRole.JUMP_HOST],),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
            )
    with pytest.raises(StateConflictError, match="authorization"):
        build_os_upgrade_in_place_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            prerequisites,
            intent,
            preflight,
            replace(authorization, reviewed=False),
            limit=(TARGETS[HostRole.JUMP_HOST],),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )


def test_parser_accepts_only_blocked_not_performed_or_conservative_failure() -> None:
    payload, *_ = _context(HostRole.SCYLLA)
    evidence = parse_os_upgrade_in_place_execution(
        _stdout(payload),
        expected_payload=payload,
        exit_code=0,
    )
    assert evidence.status is OsUpgradeInPlaceStatus.BLOCKED
    assert evidence.applied is False
    assert evidence.package_action == ACTION_NOT_PERFORMED
    assert evidence.service_action == ACTION_NOT_PERFORMED
    assert evidence.reboot_action == ACTION_NOT_PERFORMED
    assert evidence.automatic_retry is False
    assert evidence.recovery_required is False
    assert evidence.blockers == (
        "shutdown-sequence-unreviewed",
        "target-transition-unapproved",
    )

    failed = parse_os_upgrade_in_place_execution(
        (
            "PLAY RECAP *****\n"
            f"{payload['logical_id']} : ok=1 changed=0 unreachable=1 failed=0 "
            "skipped=0 rescued=0 ignored=0\n"
        ),
        expected_payload=payload,
        exit_code=4,
    )
    assert failed.status is OsUpgradeInPlaceStatus.FAILED
    assert failed.blockers == ("host-unreachable",)
    assert failed.mutation_boundary == MUTATION_BOUNDARY
    assert failed.recovery_required is False


def test_parser_refuses_mutation_malformed_duplicate_and_secret_evidence() -> None:
    payload, *_ = _context()
    with pytest.raises(AnsibleError, match="exceeds"):
        parse_os_upgrade_in_place_execution(
            "x" * (512 * 1024 + 1),
            expected_payload=payload,
            exit_code=2,
        )
    with pytest.raises(AnsibleError, match="reported a mutation"):
        parse_os_upgrade_in_place_execution(
            _stdout(payload).replace("changed=0", "changed=1"),
            expected_payload=payload,
            exit_code=0,
        )
    claimed = _result(payload)
    claimed["package_action"] = "completed"
    with pytest.raises(AnsibleError, match="forbidden action"):
        parse_os_upgrade_in_place_execution(
            _stdout(payload, result=claimed),
            expected_payload=payload,
            exit_code=0,
        )
    duplicate_json = json.dumps(
        _result(payload), sort_keys=True, separators=(",", ":")
    ).replace('"status":"blocked"', '"status":"blocked","status":"blocked"')
    duplicate_marker = base64.b64encode(duplicate_json.encode()).decode()
    host = cast(str, payload["logical_id"])
    duplicate = (
        f'ok: [{host}] => {{"msg":"DSV_OS_UPGRADE_IN_PLACE_B64={duplicate_marker}"}}\n'
        "PLAY RECAP *****\n"
        f"{host} : ok=4 changed=0 unreachable=0 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    with pytest.raises(AnsibleError):
        parse_os_upgrade_in_place_execution(
            duplicate,
            expected_payload=payload,
            exit_code=0,
        )
    secret = _result(payload, blockers=["token: obviously-fake"])
    with pytest.raises(AnsibleError):
        parse_os_upgrade_in_place_execution(
            _stdout(payload, result=secret),
            expected_payload=payload,
            exit_code=0,
        )


def test_service_success_failure_timeout_malformed_redaction_and_check_refusal(
    tmp_path: Path,
) -> None:
    (
        payload,
        metadata,
        observed,
        inventory,
        base_os,
        prerequisites,
        intent,
        preflight,
        authorization,
    ) = _context()
    paths = _paths(tmp_path)
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(
                0,
                _stdout(
                    payload,
                    noise="203.0.113.10 token=obviously-fake\n",
                ),
                "",
            ),
        ]
    )
    service = AnsibleService(_builder(tmp_path, paths), runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute_os_upgrade_in_place(
            lock,
            metadata,
            observed,
            inventory,
            base_os,
            prerequisites,
            intent,
            preflight,
            authorization,
            limit=(TARGETS[HostRole.JUMP_HOST],),
            readiness=_readiness(inventory),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )
        with pytest.raises(AnsibleError, match="check mode is refused"):
            service.execute_os_upgrade_in_place(
                lock,
                metadata,
                observed,
                inventory,
                base_os,
                prerequisites,
                intent,
                preflight,
                authorization,
                limit=(TARGETS[HostRole.JUMP_HOST],),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                check=True,
            )
    assert result.os_upgrade_in_place is not None
    assert result.os_upgrade_in_place.status is OsUpgradeInPlaceStatus.BLOCKED
    assert result.stdout == result.stderr == ""
    assert "--check" not in runner.specs[-1].argv
    assert "203.0.113.10" in runner.specs[-1].sensitive_values
    assert not tuple(paths.ansible_local_tmp.iterdir())

    failure_runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(
                2,
                _stdout(
                    payload,
                    result=_result(
                        payload,
                        status="failed",
                        blockers=["execution-failed"],
                    ),
                    failed=1,
                ),
                "",
            ),
        ]
    )
    failure_service = AnsibleService(_builder(tmp_path, paths), failure_runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        failure_service.version(lock)
        failed = failure_service.execute_os_upgrade_in_place(
            lock,
            metadata,
            observed,
            inventory,
            base_os,
            prerequisites,
            intent,
            preflight,
            authorization,
            limit=(TARGETS[HostRole.JUMP_HOST],),
            readiness=_readiness(inventory),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )
    assert failed.os_upgrade_in_place is not None
    assert failed.os_upgrade_in_place.status is OsUpgradeInPlaceStatus.FAILED

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
        with pytest.raises(AnsibleError) as caught:
            timeout_service.execute_os_upgrade_in_place(
                lock,
                metadata,
                observed,
                inventory,
                base_os,
                prerequisites,
                intent,
                preflight,
                authorization,
                limit=(TARGETS[HostRole.JUMP_HOST],),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
            )
    assert "obviously-fake" not in str(caught.value)

    with pytest.raises(AnsibleError, match="membership"):
        parse_os_upgrade_in_place_execution(
            "PLAY RECAP *****\n",
            expected_payload=payload,
            exit_code=2,
        )


def test_registry_source_package_and_static_no_mutation_contract() -> None:
    definition = get_playbook("os-upgrade-in-place")
    payload, *_ = _context()
    assert definition.source_available
    assert definition.hosts == "all"
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert definition.check_mode is CheckMode.REFUSED
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.classification is OperationClassification.SENSITIVE
    assert definition.pre_health_gate
    assert definition.post_health_gate
    assert definition.tags == (
        "os-upgrade-in-place",
        "preflight",
        "verify",
    )
    assert callable(AnsibleService.execute_os_upgrade_in_place)
    assert definition.validate_variables(
        {"deploy_scylla_vms_os_upgrade_in_place": payload}
    ) == {"deploy_scylla_vms_os_upgrade_in_place": payload}
    with pytest.raises(AnsibleError, match="not allowlisted"):
        definition.validate_variables({"deploy_scylla_vms_target_os_version": "26.04"})
    assert len([book for book in PLAYBOOKS if book.source_available]) == 34
    bundle_paths = {item.path for item in load_ansible_source_bundle().files}
    expected = {
        "playbooks/os-upgrade-in-place.yml",
        "playbooks/roles/os_upgrade_in_place/files/os-upgrade-in-place.provenance.yml",
    }
    assert expected <= bundle_paths
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content"
    text = "\n".join((root / path).read_text(encoding="utf-8") for path in expected)
    lowered = text.lower()
    for required in (
        "gather_facts: true",
        "serial: 1",
        "any_errors_fatal: true",
        "hosts: all",
        "check mode is refused",
        "target-transition-unapproved",
        "shutdown-sequence-unreviewed",
        "mutation_boundary: not-started",
        'retrieved_at: "2026-09-18"',
    ):
        assert required in text
    for forbidden in (
        "ansible.builtin.shell",
        "ansible.builtin.apt",
        "ansible.builtin.command",
        "ansible.builtin.reboot",
        "ansible.builtin.service",
        "ansible.builtin.systemd",
        "/usr/bin/apt",
        "/usr/bin/apt-get",
        "/usr/sbin/reboot",
        "/usr/bin/systemctl",
        "validate_certs: false",
    ):
        assert forbidden not in lowered


def test_playbook_syntax_check_is_local_and_write_free(tmp_path: Path) -> None:
    executable = shutil.which("ansible-playbook")
    if executable is None:
        pytest.skip("Ansible development executable is unavailable")
    playbook = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/os-upgrade-in-place.yml"
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
