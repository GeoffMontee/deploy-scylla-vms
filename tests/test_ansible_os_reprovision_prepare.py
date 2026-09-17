import base64
import json
import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from test_ansible import DIGEST, FakeRunner, _builder, _paths
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

from scylla_vms.ansible.os_reprovision_prepare import (
    ACTION_NOT_PERFORMED,
    MUTATION_BOUNDARY,
    NOT_PERFORMED,
    OS_REPROVISION_PREPARE_SCHEMA_VERSION,
    OsReprovisionPrepareStatus,
    ReprovisionReadiness,
    ReprovisionStorageDisposition,
    build_os_reprovision_current_provider_facts,
    build_os_reprovision_prepare_authorization,
    build_os_reprovision_prepare_payload,
    build_os_reprovision_role_safety_evidence,
    parse_os_reprovision_prepare_execution,
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
    membership: ReprovisionReadiness | None = None,
    lifecycle_path: str | None = None,
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
    Any,
    Any,
]:
    preflight_context = cast(
        tuple[Any, Any, Any, Any, Any, Any, Any],
        _preflight_context(
            role,
            target_os=target_os,
            target_version=target_version,
            strategy="reprovision",
        ),
    )
    (
        preflight_payload,
        metadata,
        observed,
        inventory,
        base_os,
        prerequisites,
        intent,
    ) = preflight_context
    preflight = parse_os_upgrade_preflight_execution(
        _preflight_stdout(
            preflight_payload,
            result=_preflight_result(preflight_payload),
        ),
        expected_payload=preflight_payload,
        exit_code=0,
    )
    current_provider = build_os_reprovision_current_provider_facts(
        inventory,
        logical_id=TARGETS[role],
        current_operating_system="Ubuntu",
        current_operating_system_version="24.04",
        architecture=architecture,
        image_id_digest="sha256:" + "2" * 64,
        source_digest="sha256:" + "3" * 64,
    )
    if membership is None:
        membership = (
            ReprovisionReadiness.UNKNOWN
            if role is HostRole.SCYLLA
            else ReprovisionReadiness.NOT_PERFORMED
        )
    if lifecycle_path is None:
        lifecycle_path = (
            "replace-node-delegation-required"
            if role is HostRole.SCYLLA
            else "stateless-replacement-reviewed"
        )
    role_safety = build_os_reprovision_role_safety_evidence(
        TARGETS[role],
        role,
        topology_digest=DIGEST,
        storage_disposition=(
            ReprovisionStorageDisposition.NONE
            if role is HostRole.JUMP_HOST
            else ReprovisionStorageDisposition.RETAIN
        ),
        lifecycle_path=lifecycle_path,
        lifecycle_evidence_digest="sha256:" + "4" * 64,
        membership_readiness=membership,
        service_readiness=(
            ReprovisionReadiness.PASSED
            if role in {HostRole.JUMP_HOST, HostRole.SCYLLA}
            else ReprovisionReadiness.UNKNOWN
        ),
        replacement_availability=ReprovisionReadiness.PASSED,
        route_redundancy=ReprovisionReadiness.PASSED,
        restore_readiness=(
            ReprovisionReadiness.UNKNOWN
            if role in {HostRole.MANAGER, HostRole.MONITORING}
            else ReprovisionReadiness.NOT_PERFORMED
        ),
        reregistration_readiness=(
            ReprovisionReadiness.UNKNOWN
            if role is HostRole.MANAGER
            else ReprovisionReadiness.NOT_PERFORMED
        ),
        retrust_readiness=ReprovisionReadiness.NOT_PERFORMED,
    )
    readiness = _readiness(inventory)
    authorization = build_os_reprovision_prepare_authorization(
        metadata,
        observed,
        inventory,
        readiness,
        preflight,
        current_provider,
        role_safety,
        intent,
        operation_id=OPERATION_ID,
        confirmed_target=TARGETS[role],
    )
    payload = build_os_reprovision_prepare_payload(
        metadata,
        observed,
        inventory,
        readiness,
        base_os,
        prerequisites,
        intent,
        preflight,
        current_provider,
        role_safety,
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
        current_provider,
        role_safety,
        authorization,
    )


_RESULT_FIELDS = {
    "applied",
    "automatic_retry",
    "blockers",
    "configuration_action",
    "current_architecture",
    "current_image_facts_digest",
    "current_image_id_digest",
    "current_operating_system",
    "current_operating_system_version",
    "current_provider_id_digest",
    "desired_state_action",
    "lifecycle_path",
    "logical_id",
    "membership_action",
    "membership_readiness",
    "mutation_boundary",
    "not_performed",
    "package_action",
    "provider_action",
    "provider_identity_policy",
    "provider_source_digests",
    "provenance",
    "reboot_action",
    "recovery_required",
    "registration_action",
    "replacement_provider_id_state",
    "reprovision_classification",
    "restore_action",
    "role",
    "role_classification",
    "schema_version",
    "service_action",
    "service_readiness",
    "stable_identity_preserved",
    "storage_action",
    "storage_disposition",
    "target_architecture",
    "target_image_facts_digest",
    "target_image_id_digest",
    "target_operating_system",
    "target_operating_system_version",
    "terraform_action",
    "transition_classification",
    "trust_action",
    "vm_action",
}


def _result(
    payload: dict[str, object],
    *,
    status: str = "blocked",
    blockers: list[str] | None = None,
) -> dict[str, object]:
    result = {name: payload[name] for name in _RESULT_FIELDS}
    result["status"] = status
    if blockers is not None:
        result["blockers"] = blockers
    return result


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
        + f'{{"msg":"DSV_OS_REPROVISION_PREPARE_B64={encoded}"}}\n'
        + "PLAY RECAP *****\n"
        + f"{payload['logical_id']} : ok=4 changed=0 unreachable={unreachable} "
        + f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


@pytest.mark.parametrize(
    ("role", "required_blockers"),
    [
        (HostRole.JUMP_HOST, {"jump-route-revalidation-required"}),
        (
            HostRole.MANAGER,
            {
                "manager-reregistration-unimplemented",
                "manager-restore-unimplemented",
                "manager-service-readiness-unimplemented",
            },
        ),
        (
            HostRole.MONITORING,
            {
                "monitoring-restore-unimplemented",
                "monitoring-service-readiness-unimplemented",
                "monitoring-target-refresh-unimplemented",
            },
        ),
        (
            HostRole.SCYLLA,
            {
                "scylla-membership-handling-unproven",
                "scylla-reprovision-requires-replace-node",
            },
        ),
    ],
)
def test_payload_is_exact_role_aware_validation_only(
    role: HostRole,
    required_blockers: set[str],
) -> None:
    payload, *_ = _context(role)
    assert payload["schema_version"] == OS_REPROVISION_PREPARE_SCHEMA_VERSION
    assert payload["logical_id"] == TARGETS[role]
    assert payload["role"] == role.value
    assert payload["transition_classification"] == "unapproved"
    assert payload["reprovision_classification"] == "validation-only"
    assert payload["mutation_boundary"] == MUTATION_BOUNDARY
    assert payload["recovery_required"] is False
    assert payload["stable_identity_preserved"] is True
    assert payload["provider_identity_policy"] == "must-change-after-replacement"
    assert payload["replacement_provider_id_state"] == "not-created"
    assert required_blockers <= set(cast(list[str], payload["blockers"]))
    assert "target-transition-unapproved" in cast(list[str], payload["blockers"])
    assert payload["not_performed"] == list(NOT_PERFORMED)
    for field in (
        "configuration_action",
        "desired_state_action",
        "membership_action",
        "package_action",
        "provider_action",
        "reboot_action",
        "registration_action",
        "restore_action",
        "service_action",
        "storage_action",
        "terraform_action",
        "trust_action",
        "vm_action",
    ):
        assert payload[field] == ACTION_NOT_PERFORMED
    encoded = json.dumps(payload, sort_keys=True)
    assert "10.0.0." not in encoded
    assert "203.0.113." not in encoded
    assert "ocid1." not in encoded
    assert "/dev/" not in encoded
    assert "token:" not in encoded


def test_exact_identity_provider_facts_and_authorization_are_required() -> None:
    (
        _,
        metadata,
        observed,
        inventory,
        base_os,
        prerequisites,
        intent,
        preflight,
        current_provider,
        role_safety,
        authorization,
    ) = _context()
    arguments = (
        metadata,
        observed,
        inventory,
        _readiness(inventory),
        base_os,
        prerequisites,
        intent,
        preflight,
        current_provider,
        role_safety,
        authorization,
    )
    with pytest.raises(StateConflictError, match="one exact stable ID"):
        build_os_reprovision_prepare_payload(
            *arguments,
            limit=("manager-1",),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )
    with pytest.raises(StateConflictError, match="provider facts conflict"):
        build_os_reprovision_prepare_payload(
            *arguments[:8],
            replace(current_provider, provider_id_digest=DIGEST),
            *arguments[9:],
            limit=(TARGETS[HostRole.JUMP_HOST],),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )
    with pytest.raises(StateConflictError, match="authorization"):
        build_os_reprovision_prepare_payload(
            *arguments[:-1],
            replace(authorization, confirmed_target="manager-1"),
            limit=(TARGETS[HostRole.JUMP_HOST],),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )


def test_missing_provider_facts_and_transition_conflicts_are_refused() -> None:
    with pytest.raises(StateConflictError, match="same-version"):
        _context(target_version="24.04")
    with pytest.raises(StateConflictError, match="operating system is unsupported"):
        _context(target_os="Oracle Linux", target_version="9")
    (
        _,
        metadata,
        observed,
        inventory,
        base_os,
        prerequisites,
        intent,
        preflight,
        _,
        role_safety,
        authorization,
    ) = _context()
    with pytest.raises(StateConflictError, match="current provider image facts"):
        build_os_reprovision_prepare_payload(
            metadata,
            observed,
            inventory,
            _readiness(inventory),
            base_os,
            prerequisites,
            intent,
            preflight,
            cast(Any, None),
            role_safety,
            authorization,
            limit=(TARGETS[HostRole.JUMP_HOST],),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )
    with pytest.raises(StateConflictError, match="target provider image facts"):
        build_os_reprovision_prepare_payload(
            metadata,
            observed,
            inventory,
            _readiness(inventory),
            base_os,
            prerequisites,
            replace(intent, provider_image=None),
            preflight,
            cast(Any, None),
            role_safety,
            authorization,
            limit=(TARGETS[HostRole.JUMP_HOST],),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )


def test_stale_failed_and_ineligible_preflight_are_refused() -> None:
    (
        _,
        metadata,
        observed,
        inventory,
        base_os,
        prerequisites,
        intent,
        preflight,
        current_provider,
        role_safety,
        authorization,
    ) = _context()
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
            build_os_reprovision_prepare_payload(
                metadata,
                observed,
                inventory,
                _readiness(inventory),
                base_os,
                prerequisites,
                intent,
                invalid,
                current_provider,
                role_safety,
                authorization,
                limit=(TARGETS[HostRole.JUMP_HOST],),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
            )


def test_scylla_membership_lifecycle_and_storage_ambiguity_fail_closed() -> None:
    with pytest.raises(StateConflictError, match="membership evidence conflict"):
        _context(
            HostRole.SCYLLA,
            membership=ReprovisionReadiness.UNKNOWN,
            lifecycle_path="remove-live-completed",
        )
    with pytest.raises(StateConflictError, match="not independently reviewed"):
        _context(HostRole.SCYLLA, lifecycle_path="shutdown-unproven")
    with pytest.raises(StateConflictError, match="storage disposition"):
        build_os_reprovision_role_safety_evidence(
            TARGETS[HostRole.SCYLLA],
            HostRole.SCYLLA,
            topology_digest=DIGEST,
            storage_disposition=ReprovisionStorageDisposition.NONE,
            lifecycle_path="replace-node-delegation-required",
            lifecycle_evidence_digest=DIGEST,
            membership_readiness=ReprovisionReadiness.UNKNOWN,
            service_readiness=ReprovisionReadiness.UNKNOWN,
            replacement_availability=ReprovisionReadiness.PASSED,
            route_redundancy=ReprovisionReadiness.PASSED,
            restore_readiness=ReprovisionReadiness.NOT_PERFORMED,
            reregistration_readiness=ReprovisionReadiness.NOT_PERFORMED,
            retrust_readiness=ReprovisionReadiness.NOT_PERFORMED,
        )
    with pytest.raises(StateConflictError, match="restore or service readiness"):
        build_os_reprovision_role_safety_evidence(
            TARGETS[HostRole.MANAGER],
            HostRole.MANAGER,
            topology_digest=DIGEST,
            storage_disposition=ReprovisionStorageDisposition.RETAIN,
            lifecycle_path="stateless-replacement-reviewed",
            lifecycle_evidence_digest=DIGEST,
            membership_readiness=ReprovisionReadiness.NOT_PERFORMED,
            service_readiness=ReprovisionReadiness.PASSED,
            replacement_availability=ReprovisionReadiness.PASSED,
            route_redundancy=ReprovisionReadiness.PASSED,
            restore_readiness=ReprovisionReadiness.PASSED,
            reregistration_readiness=ReprovisionReadiness.PASSED,
            retrust_readiness=ReprovisionReadiness.NOT_PERFORMED,
        )


def test_parser_accepts_only_blocked_or_conservative_failure() -> None:
    payload, *_ = _context(HostRole.SCYLLA)
    evidence = parse_os_reprovision_prepare_execution(
        _stdout(payload),
        expected_payload=payload,
        exit_code=0,
    )
    assert evidence.status is OsReprovisionPrepareStatus.BLOCKED
    assert evidence.applied is False
    assert evidence.automatic_retry is False
    assert evidence.package_action == ACTION_NOT_PERFORMED
    assert evidence.provider_action == ACTION_NOT_PERFORMED
    assert evidence.terraform_action == ACTION_NOT_PERFORMED
    assert evidence.vm_action == ACTION_NOT_PERFORMED
    assert evidence.storage_action == ACTION_NOT_PERFORMED
    assert evidence.service_action == ACTION_NOT_PERFORMED
    assert evidence.membership_action == ACTION_NOT_PERFORMED
    assert evidence.mutation_boundary == MUTATION_BOUNDARY
    assert evidence.recovery_required is False
    assert "scylla-reprovision-requires-replace-node" in evidence.blockers

    failed = parse_os_reprovision_prepare_execution(
        (
            "PLAY RECAP *****\n"
            f"{payload['logical_id']} : ok=1 changed=0 unreachable=1 failed=0 "
            "skipped=0 rescued=0 ignored=0\n"
        ),
        expected_payload=payload,
        exit_code=4,
    )
    assert failed.status is OsReprovisionPrepareStatus.FAILED
    assert failed.blockers == ("host-unreachable",)


def test_parser_refuses_mutation_malformed_duplicate_and_secret_evidence() -> None:
    payload, *_ = _context()
    with pytest.raises(AnsibleError, match="exceeds"):
        parse_os_reprovision_prepare_execution(
            "x" * (512 * 1024 + 1),
            expected_payload=payload,
            exit_code=2,
        )
    with pytest.raises(AnsibleError, match="reported a mutation"):
        parse_os_reprovision_prepare_execution(
            _stdout(payload).replace("changed=0", "changed=1"),
            expected_payload=payload,
            exit_code=0,
        )
    claimed = _result(payload)
    claimed["terraform_action"] = "completed"
    with pytest.raises(AnsibleError, match="forbidden action"):
        parse_os_reprovision_prepare_execution(
            _stdout(payload, result=claimed),
            expected_payload=payload,
            exit_code=0,
        )
    duplicate_json = json.dumps(
        _result(payload), sort_keys=True, separators=(",", ":")
    ).replace('"status":"blocked"', '"status":"blocked","status":"blocked"')
    marker = base64.b64encode(duplicate_json.encode()).decode()
    host = cast(str, payload["logical_id"])
    duplicate = (
        f'ok: [{host}] => {{"msg":"DSV_OS_REPROVISION_PREPARE_B64={marker}"}}\n'
        "PLAY RECAP *****\n"
        f"{host} : ok=4 changed=0 unreachable=0 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    with pytest.raises(AnsibleError):
        parse_os_reprovision_prepare_execution(
            duplicate,
            expected_payload=payload,
            exit_code=0,
        )
    secret = _result(payload, blockers=["token: obviously-fake"])
    with pytest.raises(AnsibleError):
        parse_os_reprovision_prepare_execution(
            _stdout(payload, result=secret),
            expected_payload=payload,
            exit_code=0,
        )


def test_service_success_failure_timeout_redaction_and_check_refusal(
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
        current_provider,
        role_safety,
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
    call = (
        metadata,
        observed,
        inventory,
        base_os,
        prerequisites,
        intent,
        preflight,
        current_provider,
        role_safety,
        authorization,
    )
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute_os_reprovision_prepare(
            lock,
            *call,
            limit=(TARGETS[HostRole.JUMP_HOST],),
            readiness=_readiness(inventory),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )
        with pytest.raises(AnsibleError, match="check mode is refused"):
            service.execute_os_reprovision_prepare(
                lock,
                *call,
                limit=(TARGETS[HostRole.JUMP_HOST],),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
                check=True,
            )
    assert result.os_reprovision_prepare is not None
    assert result.os_reprovision_prepare.status is OsReprovisionPrepareStatus.BLOCKED
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
        failure = failure_service.execute_os_reprovision_prepare(
            lock,
            *call,
            limit=(TARGETS[HostRole.JUMP_HOST],),
            readiness=_readiness(inventory),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )
    assert failure.os_reprovision_prepare is not None
    assert failure.os_reprovision_prepare.status is OsReprovisionPrepareStatus.FAILED

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
            timeout_service.execute_os_reprovision_prepare(
                lock,
                *call,
                limit=(TARGETS[HostRole.JUMP_HOST],),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
            )
    assert "obviously-fake" not in str(caught.value)


def test_registry_source_package_and_static_no_mutation_contract() -> None:
    definition = get_playbook("os-reprovision-prepare")
    payload, *_ = _context()
    assert definition.source_available
    assert definition.hosts == "all"
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert definition.check_mode is CheckMode.REFUSED
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.classification is OperationClassification.DESTRUCTIVE
    assert definition.pre_health_gate
    assert not definition.post_health_gate
    assert definition.tags == (
        "os-reprovision-prepare",
        "preflight",
        "verify",
    )
    assert callable(AnsibleService.execute_os_reprovision_prepare)
    assert definition.validate_variables(
        {"deploy_scylla_vms_os_reprovision_prepare": payload}
    ) == {"deploy_scylla_vms_os_reprovision_prepare": payload}
    assert len([book for book in PLAYBOOKS if book.source_available]) == 34
    bundle_paths = {item.path for item in load_ansible_source_bundle().files}
    expected = {
        "playbooks/os-reprovision-prepare.yml",
        (
            "playbooks/roles/os_reprovision_prepare/files/"
            "os-reprovision-prepare.provenance.yml"
        ),
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
        "terraform-replacement-orchestration-unimplemented",
        "mutation_boundary: not-started",
        "source_available_meaning",
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
        "/usr/bin/terraform",
        "/usr/bin/oci",
        "/usr/bin/apt",
        "/usr/bin/apt-get",
        "/usr/sbin/reboot",
        "/usr/bin/systemctl",
        "/dev/",
        "validate_certs: false",
    ):
        assert forbidden not in lowered


def test_playbook_syntax_check_is_local_and_write_free(tmp_path: Path) -> None:
    executable = shutil.which("ansible-playbook")
    if executable is None:
        pytest.skip("Ansible development executable is unavailable")
    playbook = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/os-reprovision-prepare.yml"
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
