import base64
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from test_ansible import FakeRunner, _builder, _paths
from test_ansible_os_reprovision_prepare import (
    _context as _reprovision_context,
)
from test_ansible_os_reprovision_prepare import _result as _reprovision_result
from test_ansible_os_reprovision_prepare import _stdout as _reprovision_stdout
from test_ansible_os_upgrade_in_place import (
    _context as _in_place_context,
)
from test_ansible_os_upgrade_in_place import _result as _in_place_result
from test_ansible_os_upgrade_in_place import _stdout as _in_place_stdout
from test_ansible_os_upgrade_preflight import OPERATION_ID, TARGETS
from test_ansible_service_converge import _readiness

from scylla_vms.ansible.os_reprovision_prepare import (
    parse_os_reprovision_prepare_execution,
)
from scylla_vms.ansible.os_upgrade_in_place import (
    parse_os_upgrade_in_place_execution,
)
from scylla_vms.ansible.os_upgrade_postcheck import (
    NOT_PERFORMED,
    OS_UPGRADE_POSTCHECK_SCHEMA_VERSION,
    SOURCE_UPGRADE_NOT_PERFORMED,
    VERIFICATION_NAMES,
    OsUpgradePostcheckStatus,
    TransitionClassification,
    build_os_upgrade_postcheck_payload,
    classify_postcheck_transition,
    parse_os_upgrade_postcheck_execution,
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
    expected_kernel_release_digest: str | None = None,
) -> tuple[
    dict[str, object],
    Any,
    Any,
    Any,
    Any,
    Any,
    Any,
    Any,
]:
    if role in {HostRole.MANAGER, HostRole.MONITORING}:
        (
            source_payload,
            metadata,
            observed,
            inventory,
            base_os,
            prerequisites,
            _intent,
            _preflight,
            _current_provider,
            _role_safety,
            authorization,
        ) = _reprovision_context(role)
        source_result = parse_os_reprovision_prepare_execution(
            _reprovision_stdout(
                source_payload,
                result=_reprovision_result(source_payload),
            ),
            expected_payload=source_payload,
            exit_code=0,
        )
    else:
        (
            source_payload,
            metadata,
            observed,
            inventory,
            base_os,
            prerequisites,
            _intent,
            _preflight,
            authorization,
        ) = _in_place_context(role)
        source_result = parse_os_upgrade_in_place_execution(
            _in_place_stdout(
                source_payload,
                result=_in_place_result(source_payload),
            ),
            expected_payload=source_payload,
            exit_code=0,
        )
    readiness = _readiness(inventory)
    payload = build_os_upgrade_postcheck_payload(
        metadata,
        observed,
        inventory,
        readiness,
        base_os,
        prerequisites,
        source_result,
        authorization,
        operation_id=OPERATION_ID,
        limit=(TARGETS[role],),
        image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
        architecture="amd64",
        expected_kernel_release_digest=expected_kernel_release_digest,
    )
    return (
        payload,
        metadata,
        observed,
        inventory,
        base_os,
        prerequisites,
        source_result,
        authorization,
    )


def _result(
    payload: dict[str, object],
    *,
    gate_changes: dict[str, str] | None = None,
    extra_blockers: tuple[str, ...] = (),
    current_os: str = "Ubuntu",
    current_version: str = "24.04",
    current_architecture: str = "amd64",
) -> dict[str, object]:
    gates = [
        dict(cast(dict[str, object], item))
        for item in cast(list[object], payload["controller_gates"])
    ]
    host_defaults = {
        "architecture": "passed",
        "broken-packages": "passed",
        "kernel": (
            "passed"
            if payload["expected_kernel_release_digest"] is not None
            else "unknown"
        ),
        "operating-system": "failed",
        "package-state": "passed",
        "reboot-required": "passed",
    }
    if (
        next(item["status"] for item in gates if item["name"] == "service-policy")
        != "unknown"
    ):
        host_defaults["service-policy"] = "passed"
    host_defaults.update(gate_changes or {})
    for gate in gates:
        if gate["name"] in host_defaults:
            gate["status"] = host_defaults[cast(str, gate["name"])]
    statuses = {cast(str, item["name"]): cast(str, item["status"]) for item in gates}
    blocker_rules = {
        ("architecture", "failed"): "architecture-mismatch",
        ("broken-packages", "failed"): "broken-packages",
        ("kernel", "failed"): "kernel-mismatch",
        ("kernel", "unknown"): "kernel-policy-undefined",
        ("operating-system", "failed"): "current-os-mismatch",
        ("package-state", "failed"): "package-state-mismatch",
        ("package-state", "unknown"): "package-inspection-failed",
        ("reboot-required", "failed"): "reboot-required",
        ("service-policy", "failed"): "service-policy-mismatch",
        ("service-policy", "unknown"): "service-policy-unknown",
    }
    host_blockers = {
        blocker
        for (gate, status), blocker in blocker_rules.items()
        if statuses[gate] == status
    }
    host_blocker_names = set(blocker_rules.values())
    blockers = sorted(
        {
            *(
                set(cast(list[str], payload["controller_blockers"]))
                - host_blocker_names
            ),
            *host_blockers,
            *extra_blockers,
        }
    )
    performed = tuple(
        name
        for name in VERIFICATION_NAMES
        if statuses[name] != "not-performed"
        and not (name == "kernel" and payload["expected_kernel_release_digest"] is None)
    )
    target_matches = (
        current_os == payload["target_operating_system"]
        and current_version == payload["target_operating_system_version"]
        and current_architecture == payload["target_architecture"]
    )
    digest = "sha256:" + "5" * 64
    return {
        "automatic_remediation": False,
        "blockers": blockers,
        "current_architecture": current_architecture,
        "current_kernel_release_digest": digest,
        "current_operating_system": current_os,
        "current_operating_system_version": current_version,
        "current_package_state_digest": digest,
        "current_provider_id_digest": payload["current_provider_id_digest"],
        "current_service_state_digest": (
            digest if statuses["service-policy"] != "unknown" else None
        ),
        "gates": gates,
        "inventory_generation": payload["inventory_generation"],
        "logical_id": payload["logical_id"],
        "mutation_performed": False,
        "not_performed": payload["not_performed"],
        "observation_generation": payload["observation_generation"],
        "previous_architecture": payload["previous_architecture"],
        "previous_operating_system": payload["previous_operating_system"],
        "previous_operating_system_version": payload[
            "previous_operating_system_version"
        ],
        "provenance": payload["provenance"],
        "remediation_performed": False,
        "role": payload["role"],
        "schema_version": OS_UPGRADE_POSTCHECK_SCHEMA_VERSION,
        "source_mode": payload["source_mode"],
        "source_result_digest": payload["source_result_digest"],
        "source_schema_version": payload["source_schema_version"],
        "source_status": payload["source_status"],
        "source_upgrade_performed": False,
        "status": "blocked",
        "target_architecture": payload["target_architecture"],
        "target_operating_system": payload["target_operating_system"],
        "target_operating_system_version": payload["target_operating_system_version"],
        "transition_classification": payload["transition_classification"],
        "transition_comparison": "matched" if target_matches else "mismatched",
        "trust_generation": payload["trust_generation"],
        "verification_not_performed": sorted(set(VERIFICATION_NAMES) - set(performed)),
        "verification_performed": sorted(performed),
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
        + f'{{"msg":"DSV_OS_UPGRADE_POSTCHECK_B64={encoded}"}}\n'
        + "PLAY RECAP *****\n"
        + f"{payload['logical_id']} : ok=4 changed=0 unreachable={unreachable} "
        + f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


@pytest.mark.parametrize("role", list(HostRole))
def test_payload_binds_exact_role_identity_source_and_current_evidence(
    role: HostRole,
) -> None:
    payload, *_ = _context(role)
    assert payload["schema_version"] == OS_UPGRADE_POSTCHECK_SCHEMA_VERSION
    assert payload["logical_id"] == TARGETS[role]
    assert payload["role"] == role.value
    assert payload["source_mode"] in {"in-place", "reprovision"}
    assert payload["source_upgrade_performed"] is False
    assert payload["transition_classification"] == "unapproved"
    assert SOURCE_UPGRADE_NOT_PERFORMED in payload["controller_blockers"]
    assert payload["not_performed"] == list(NOT_PERFORMED)
    assert payload["verification_names"] == list(VERIFICATION_NAMES)
    assert payload["current_provider_id_digest"].startswith("sha256:")
    encoded = json.dumps(payload, sort_keys=True)
    assert "ocid1." not in encoded
    assert "10.0.0." not in encoded
    assert "203.0.113." not in encoded
    assert "token=" not in encoded


def test_payload_rejects_missing_stale_or_mutated_source_evidence() -> None:
    (
        _payload,
        metadata,
        observed,
        inventory,
        base_os,
        prerequisites,
        source,
        authorization,
    ) = _context()
    kwargs = {
        "operation_id": OPERATION_ID,
        "limit": (TARGETS[HostRole.JUMP_HOST],),
        "image_filter": ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
        "architecture": "amd64",
    }
    readiness = _readiness(inventory)
    with pytest.raises(StateConflictError, match="source result type"):
        build_os_upgrade_postcheck_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            prerequisites,
            cast(Any, None),
            authorization,
            **kwargs,
        )
    with pytest.raises(StateConflictError, match="source evidence"):
        build_os_upgrade_postcheck_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            prerequisites,
            replace(source, mutation_boundary="command-started"),
            authorization,
            **kwargs,
        )
    with pytest.raises(StateConflictError, match="source operation"):
        build_os_upgrade_postcheck_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            prerequisites,
            source,
            replace(authorization, reviewed=False),
            **kwargs,
        )
    with pytest.raises(StateConflictError, match="one exact"):
        build_os_upgrade_postcheck_payload(
            metadata,
            observed,
            inventory,
            readiness,
            base_os,
            prerequisites,
            source,
            authorization,
            **{**kwargs, "limit": ()},
        )


def test_payload_rejects_role_stable_and_provider_identity_conflicts() -> None:
    (
        _payload,
        metadata,
        observed,
        inventory,
        base_os,
        prerequisites,
        source,
        authorization,
    ) = _context(HostRole.MANAGER)
    common = {
        "operation_id": OPERATION_ID,
        "image_filter": ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
        "architecture": "amd64",
    }
    readiness = _readiness(inventory)
    for conflicted_source, conflicted_authorization, limit in (
        (
            replace(source, role=HostRole.MONITORING),
            authorization,
            (TARGETS[HostRole.MANAGER],),
        ),
        (
            source,
            authorization,
            (TARGETS[HostRole.JUMP_HOST],),
        ),
        (
            source,
            replace(
                authorization,
                provider_id_digest="sha256:" + "7" * 64,
            ),
            (TARGETS[HostRole.MANAGER],),
        ),
    ):
        with pytest.raises(StateConflictError, match="source operation"):
            build_os_upgrade_postcheck_payload(
                metadata,
                observed,
                inventory,
                readiness,
                base_os,
                prerequisites,
                conflicted_source,
                conflicted_authorization,
                limit=limit,
                **common,
            )


@pytest.mark.parametrize(
    ("previous", "target", "expected"),
    [
        (
            ("Ubuntu", "24.04", "amd64"),
            ("Ubuntu", "24.04", "amd64"),
            TransitionClassification.SAME_VERSION,
        ),
        (
            ("Ubuntu", "24.04", "amd64"),
            ("Ubuntu", "26.04", "amd64"),
            TransitionClassification.UNAPPROVED,
        ),
        (
            ("Ubuntu", "24.04", "amd64"),
            ("Oracle Linux", "9", "amd64"),
            TransitionClassification.UNSUPPORTED,
        ),
        (
            ("Ubuntu", "24.04", "amd64"),
            ("Ubuntu", "26.04", "sparc"),
            TransitionClassification.UNSUPPORTED,
        ),
    ],
)
def test_transition_classification_never_invents_approval(
    previous: tuple[str, str, str],
    target: tuple[str, str, str],
    expected: TransitionClassification,
) -> None:
    assert classify_postcheck_transition(*previous, *target) is expected


@pytest.mark.parametrize("role", list(HostRole))
def test_parser_accepts_strict_blocked_read_only_evidence(role: HostRole) -> None:
    payload, *_ = _context(role)
    evidence = parse_os_upgrade_postcheck_execution(
        _stdout(payload),
        expected_payload=payload,
        exit_code=0,
    )
    assert evidence.status is OsUpgradePostcheckStatus.BLOCKED
    assert evidence.source_upgrade_performed is False
    assert evidence.mutation_performed is False
    assert evidence.remediation_performed is False
    assert SOURCE_UPGRADE_NOT_PERFORMED in evidence.blockers
    assert "current-os-mismatch" in evidence.blockers
    assert "kernel-policy-undefined" in evidence.blockers


@pytest.mark.parametrize(
    ("gate", "status", "blocker"),
    [
        ("architecture", "failed", "architecture-mismatch"),
        ("broken-packages", "failed", "broken-packages"),
        ("kernel", "failed", "kernel-mismatch"),
        ("operating-system", "failed", "current-os-mismatch"),
        ("package-state", "failed", "package-state-mismatch"),
        ("package-state", "unknown", "package-inspection-failed"),
        ("reboot-required", "failed", "reboot-required"),
        ("service-policy", "failed", "service-policy-mismatch"),
    ],
)
def test_parser_preserves_exact_host_mismatch_blocker(
    gate: str,
    status: str,
    blocker: str,
) -> None:
    payload, *_ = _context(
        expected_kernel_release_digest=(
            "sha256:" + "9" * 64 if gate == "kernel" else None
        )
    )
    result = _result(payload, gate_changes={gate: status})
    evidence = parse_os_upgrade_postcheck_execution(
        _stdout(payload, result=result),
        expected_payload=payload,
        exit_code=0,
    )
    assert blocker in evidence.blockers


def test_parser_rejects_mutation_malformed_conflicting_and_secret_evidence() -> None:
    payload, *_ = _context()
    mutation = _result(payload)
    mutation["mutation_performed"] = True
    with pytest.raises(AnsibleError, match="forbidden mutation"):
        parse_os_upgrade_postcheck_execution(
            _stdout(payload, result=mutation),
            expected_payload=payload,
            exit_code=0,
        )
    duplicate = _result(payload)
    duplicate["source_result_digest"] = "sha256:" + "8" * 64
    with pytest.raises(AnsibleError, match="conflicts"):
        parse_os_upgrade_postcheck_execution(
            _stdout(payload, result=duplicate),
            expected_payload=payload,
            exit_code=0,
        )
    with pytest.raises(AnsibleError, match="malformed"):
        parse_os_upgrade_postcheck_execution(
            "DSV_OS_UPGRADE_POSTCHECK_B64=not_base64!\n"
            + "PLAY RECAP *****\n"
            + f"{payload['logical_id']} : ok=1 changed=0 unreachable=0 "
            + "failed=0 skipped=0 rescued=0 ignored=0\n",
            expected_payload=payload,
            exit_code=0,
        )
    secret = _result(payload)
    secret["current_operating_system"] = "password=obviously-fake"
    with pytest.raises(AnsibleError) as caught:
        parse_os_upgrade_postcheck_execution(
            _stdout(payload, result=secret),
            expected_payload=payload,
            exit_code=0,
        )
    assert "obviously-fake" not in str(caught.value)


def test_parser_conservatively_normalizes_execution_failure() -> None:
    payload, *_ = _context()
    stdout = (
        "PLAY RECAP *****\n"
        + f"{payload['logical_id']} : ok=1 changed=0 unreachable=1 "
        + "failed=0 skipped=0 rescued=0 ignored=0\n"
    )
    evidence = parse_os_upgrade_postcheck_execution(
        stdout,
        expected_payload=payload,
        exit_code=4,
    )
    assert evidence.status is OsUpgradePostcheckStatus.FAILED
    assert evidence.blockers == ("host-unreachable",)
    assert evidence.verification_performed == ()
    assert evidence.verification_not_performed == VERIFICATION_NAMES


def test_service_executes_check_mode_and_redacts_results(tmp_path: Path) -> None:
    (
        payload,
        metadata,
        observed,
        inventory,
        base_os,
        prerequisites,
        source,
        authorization,
    ) = _context()
    paths = _paths(tmp_path)
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(0, _stdout(payload), ""),
        ]
    )
    service = AnsibleService(_builder(tmp_path, paths), runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute_os_upgrade_postcheck(
            lock,
            metadata,
            observed,
            inventory,
            base_os,
            prerequisites,
            source,
            authorization,
            operation_id=OPERATION_ID,
            limit=(TARGETS[HostRole.JUMP_HOST],),
            readiness=_readiness(inventory),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
            check=True,
        )
    assert result.os_upgrade_postcheck is not None
    assert result.os_upgrade_postcheck.status is OsUpgradePostcheckStatus.BLOCKED
    assert result.stdout == result.stderr == ""
    assert "--check" in runner.specs[-1].argv

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
            timeout_service.execute_os_upgrade_postcheck(
                lock,
                metadata,
                observed,
                inventory,
                base_os,
                prerequisites,
                source,
                authorization,
                operation_id=OPERATION_ID,
                limit=(TARGETS[HostRole.JUMP_HOST],),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
            )
    assert "obviously-fake" not in str(caught.value)


def test_registry_source_package_and_static_no_mutation_contract() -> None:
    definition = get_playbook("os-upgrade-postcheck")
    payload, *_ = _context()
    assert definition.source_available
    assert definition.hosts == "all"
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert definition.check_mode is CheckMode.SUPPORTED
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.classification is OperationClassification.READ_ONLY
    assert definition.post_health_gate
    assert definition.validate_variables(
        {"deploy_scylla_vms_os_upgrade_postcheck": payload}
    ) == {"deploy_scylla_vms_os_upgrade_postcheck": payload}
    with pytest.raises(AnsibleError, match="not allowlisted"):
        definition.validate_variables({"deploy_scylla_vms_target_os_version": "26.04"})
    assert len([book for book in PLAYBOOKS if book.source_available]) == 34
    assert not [book.name for book in PLAYBOOKS if not book.source_available]
    bundle_paths = {item.path for item in load_ansible_source_bundle().files}
    expected = {
        "playbooks/os-upgrade-postcheck.yml",
        "playbooks/roles/os_upgrade_postcheck/files/"
        "os-upgrade-postcheck.provenance.yml",
        "playbooks/roles/os_upgrade_postcheck/library/os_upgrade_postcheck.py",
        "playbooks/roles/os_upgrade_postcheck/tasks/main.yml",
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
        "supports_check_mode=True",
        "source-upgrade-not-performed",
        "mutation_performed",
        "remediation_performed",
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
        "validate_certs: false",
    ):
        assert forbidden not in lowered
