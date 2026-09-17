import base64
import importlib.util
import json
import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from test_ansible import DIGEST, FakeRunner, _builder, _metadata, _paths
from test_ansible_service_converge import (
    SCYLLA_VERSION,
    _base_os,
    _cluster_inventory,
    _prerequisites,
    _readiness,
)

from scylla_vms.ansible.base_os import BaseOsStatus
from scylla_vms.ansible.os_upgrade_preflight import (
    GATE_NAMES,
    NOT_PERFORMED,
    OS_UPGRADE_PREFLIGHT_SCHEMA_VERSION,
    GateStatus,
    OsUpgradePreflightPrerequisites,
    OsUpgradePreflightStatus,
    TransitionClassification,
    build_os_upgrade_preflight_intent,
    build_os_upgrade_preflight_payload,
    build_provider_image_facts,
    build_role_safety_evidence,
    build_scylla_rolling_safety_evidence,
    classify_transition,
    os_upgrade_space_policy_digest,
    parse_os_upgrade_preflight_execution,
)
from scylla_vms.ansible.registry import (
    PLAYBOOKS,
    CheckMode,
    LimitPolicy,
    get_playbook,
)
from scylla_vms.ansible.scylla_configure import (
    SCYLLA_CONFIGURE_SCHEMA_VERSION,
    ScyllaConfigureEvidence,
    ScyllaConfigureStatus,
)
from scylla_vms.ansible.scylla_health import (
    SCYLLA_HEALTH_SCHEMA_VERSION,
    HealthReadiness,
    ScyllaHealthEvidence,
    ScyllaNodeHealth,
)
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.ansible.storage_postcheck import (
    STORAGE_POSTCHECK_SCHEMA_VERSION,
    StoragePostcheckEvidence,
)
from scylla_vms.desired import HostRole, ImageFilter, ImageVersionMatch
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.process import ProcessResult, ProcessTimeoutError

OPERATION_ID = "55555555-5555-4555-8555-555555555555"
TARGETS = {
    HostRole.JUMP_HOST: "jump-host-1",
    HostRole.MANAGER: "manager-1",
    HostRole.MONITORING: "monitoring-1",
    HostRole.SCYLLA: "scylla-ad-1-1",
}


def _scylla_health(inventory: object, observed: object) -> ScyllaHealthEvidence:
    stored = cast(Any, inventory)
    seen = cast(Any, observed)
    logical_id = TARGETS[HostRole.SCYLLA]
    node = ScyllaNodeHealth(
        logical_id,
        "11111111-1111-4111-8111-111111111111",
        DIGEST,
        "UN",
        "dc1",
        "rack1",
        SCYLLA_VERSION,
        "active",
        True,
        True,
        True,
        500,
        (),
        (),
    )
    return ScyllaHealthEvidence(
        HealthReadiness.READY,
        "all-nodes-cross-view",
        (logical_id,),
        "2026-09-18T12:00:00Z",
        "2026-09-18T12:00:01Z",
        (node,),
        (),
        DIGEST,
        True,
        DIGEST,
        "complete",
        (),
        (
            ("inventory_digest", stored.digest),
            ("observation_digest", seen.digest),
            ("trust_digest", DIGEST),
        ),
        (),
        SCYLLA_HEALTH_SCHEMA_VERSION,
    )


def _scylla_storage(inventory: object, observed: object) -> StoragePostcheckEvidence:
    stored = cast(Any, inventory)
    seen = cast(Any, observed)
    return StoragePostcheckEvidence(
        TARGETS[HostRole.SCYLLA],
        "block-volume",
        "single",
        True,
        (),
        (),
        ((DIGEST, 500 * 1024**3),),
        (
            ("inventory_digest", stored.digest),
            ("observation_digest", seen.digest),
        ),
        STORAGE_POSTCHECK_SCHEMA_VERSION,
    )


def _scylla_configure(inventory: object, observed: object) -> ScyllaConfigureEvidence:
    stored = cast(Any, inventory)
    seen = cast(Any, observed)
    return ScyllaConfigureEvidence(
        logical_id=TARGETS[HostRole.SCYLLA],
        status=ScyllaConfigureStatus.NOOP,
        config_digest=DIGEST,
        topology_digest=DIGEST,
        seed_digest=DIGEST,
        configuration_file_digests=(
            ("cassandra-rackdc.properties", DIGEST),
            ("scylla.yaml", DIGEST),
        ),
        files_root_owned=True,
        files_mode_0644=True,
        installed_version=SCYLLA_VERSION,
        service_masked=True,
        service_inactive=True,
        runtime_validation_performed=False,
        package_install_performed=False,
        storage_mutation_performed=False,
        tuning_performed=False,
        firewall_operation_performed=False,
        ssh_operation_performed=False,
        manager_operation_performed=False,
        service_started=False,
        bootstrap_performed=False,
        prerequisite_digests=(
            ("inventory_digest", stored.digest),
            ("observation_digest", seen.digest),
        ),
        blockers=(),
        schema_version=SCYLLA_CONFIGURE_SCHEMA_VERSION,
    )


def _context(
    role: HostRole = HostRole.JUMP_HOST,
    *,
    target_os: str = "Ubuntu",
    target_version: str = "24.04",
    strategy: str = "auto",
    rolling_status: GateStatus = GateStatus.PASSED,
    no_active_topology_work: bool = True,
) -> tuple[
    dict[str, object],
    object,
    object,
    object,
    object,
    OsUpgradePreflightPrerequisites,
    object,
]:
    inventory, observed = _cluster_inventory()
    metadata = _metadata()
    logical_id = TARGETS[role]
    service_prerequisites = _prerequisites(inventory, observed, logical_id=logical_id)
    health = _scylla_health(inventory, observed)
    role_safety = build_role_safety_evidence(
        logical_id,
        role,
        route=GateStatus.PASSED,
        availability=GateStatus.PASSED,
    )
    prerequisites = OsUpgradePreflightPrerequisites(
        role_safety,
        scylla_install=(
            service_prerequisites.scylla_install if role is HostRole.SCYLLA else None
        ),
        scylla_configure=(
            _scylla_configure(inventory, observed) if role is HostRole.SCYLLA else None
        ),
        storage_postcheck=(
            _scylla_storage(inventory, observed) if role is HostRole.SCYLLA else None
        ),
        scylla_health=health if role is HostRole.SCYLLA else None,
        scylla_rolling=(
            build_scylla_rolling_safety_evidence(
                logical_id,
                health,
                replication=rolling_status,
                quorum=rolling_status,
                capacity=rolling_status,
                backup_policy=rolling_status,
                no_active_topology_work=no_active_topology_work,
                shutdown_not_started=True,
                drain_not_started=True,
            )
            if role is HostRole.SCYLLA
            else None
        ),
        jump_host_configure=(
            service_prerequisites.jump_host_configure
            if role is HostRole.JUMP_HOST
            else None
        ),
        manager_server=(
            service_prerequisites.manager_server if role is HostRole.MANAGER else None
        ),
        monitoring_stack=(
            service_prerequisites.monitoring_stack
            if role is HostRole.MONITORING
            else None
        ),
        monitoring_targets=(
            service_prerequisites.monitoring_targets
            if role is HostRole.MONITORING
            else None
        ),
    )
    provider = None
    package_policy = DIGEST
    if strategy == "reprovision":
        package_policy = None
        provider = build_provider_image_facts(
            operating_system=target_os,
            operating_system_version=target_version,
            architecture="amd64",
            image_id_digest=DIGEST,
            source_digest=DIGEST,
            available=True,
            replacement_plan_reviewed=True,
        )
    intent = build_os_upgrade_preflight_intent(
        metadata,
        operation_id=OPERATION_ID,
        logical_id=logical_id,
        strategy=strategy,
        target_operating_system=target_os,
        target_operating_system_version=target_version,
        package_policy_digest=package_policy,
        provider_image=provider,
        minimum_root_free_bytes=1024,
        minimum_boot_free_bytes=512,
        space_policy_digest=os_upgrade_space_policy_digest(1024, 512),
    )
    base_os = _base_os(logical_id)
    payload = build_os_upgrade_preflight_payload(
        metadata,
        observed,
        inventory,
        _readiness(inventory),
        base_os,
        prerequisites,
        intent,
        limit=(logical_id,),
        image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
        architecture="amd64",
    )
    return (
        payload,
        metadata,
        observed,
        inventory,
        base_os,
        prerequisites,
        intent,
    )


def _result(
    payload: dict[str, object],
    *,
    status: str = "blocked",
    gate_changes: dict[str, str] | None = None,
    extra_blockers: tuple[str, ...] = (),
) -> dict[str, object]:
    if status == "failed":
        gates = [{"name": name, "status": "unknown"} for name in GATE_NAMES]
        blockers = ["execution-failed"]
        rolling = False
    else:
        gates = [
            dict(cast(dict[str, object], item))
            for item in cast(list[object], payload["controller_gates"])
        ]
        host_defaults = {
            "architecture": "passed",
            "boot-space": "passed",
            "broken-packages": "passed",
            "kernel-family": "passed",
            "package-locks": "passed",
            "reboot-required": "passed",
            "root-space": "passed",
        }
        host_defaults.update(gate_changes or {})
        for gate in gates:
            if gate["name"] in host_defaults:
                gate["status"] = host_defaults[cast(str, gate["name"])]
        blockers = sorted(
            {*cast(list[str], payload["controller_blockers"]), *extra_blockers}
        )
        rolling = payload["rolling_eligible"]
    return {
        "architecture": payload["architecture"],
        "blockers": blockers,
        "current_operating_system": payload["current_operating_system"],
        "current_operating_system_version": payload["current_operating_system_version"],
        "gates": gates,
        "logical_id": payload["logical_id"],
        "not_performed": payload["not_performed"],
        "provenance": payload["provenance"],
        "requested_strategy": payload["requested_strategy"],
        "role": payload["role"],
        "rolling_eligible": rolling,
        "schema_version": OS_UPGRADE_PREFLIGHT_SCHEMA_VERSION,
        "selected_path": "not-performed",
        "status": status,
        "target_operating_system": payload["target_operating_system"],
        "target_operating_system_version": payload["target_operating_system_version"],
        "transition_classification": payload["transition_classification"],
    }


def _stdout(
    payload: dict[str, object],
    *,
    result: dict[str, object] | None = None,
    failed: int = 0,
    unreachable: int = 0,
    noise: str = "",
) -> str:
    value = result or _result(payload)
    encoded = base64.b64encode(json.dumps(value, sort_keys=True).encode()).decode()
    return (
        noise
        + f"ok: [{payload['logical_id']}] => "
        + f'{{"msg":"DSV_OS_UPGRADE_PREFLIGHT_B64={encoded}"}}\n'
        + "PLAY RECAP *****\n"
        + f"{payload['logical_id']} : ok=8 changed=0 unreachable={unreachable} "
        + f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


@pytest.mark.parametrize(
    ("role", "required_blocker", "rolling"),
    [
        (HostRole.JUMP_HOST, "target-transition-undefined", True),
        (HostRole.MANAGER, "manager-backend-unconfigured", False),
        (HostRole.MONITORING, "monitoring-stack-not-started", False),
        (HostRole.SCYLLA, "target-transition-undefined", True),
    ],
)
def test_role_aware_payload_is_exact_and_fail_closed(
    role: HostRole, required_blocker: str, rolling: bool
) -> None:
    payload, *_ = _context(role)
    assert payload["schema_version"] == OS_UPGRADE_PREFLIGHT_SCHEMA_VERSION
    assert payload["role"] == role.value
    assert payload["rolling_eligible"] is rolling
    assert required_blocker in payload["controller_blockers"]
    assert payload["transition_classification"] == "undefined"
    assert payload["selected_path"] == "not-performed"
    assert payload["not_performed"] == list(NOT_PERFORMED)
    rendered = json.dumps(payload, sort_keys=True)
    assert "10.0.0." not in rendered
    assert "203.0.113." not in rendered
    assert "ocid1." not in rendered
    assert "token:" not in rendered


def test_intent_binds_exact_space_policy() -> None:
    _, metadata, *_ = _context(HostRole.JUMP_HOST)
    with pytest.raises(StateConflictError, match="space policy digest"):
        build_os_upgrade_preflight_intent(
            metadata,  # type: ignore[arg-type]
            operation_id=OPERATION_ID,
            logical_id=TARGETS[HostRole.JUMP_HOST],
            strategy="in-place",
            target_operating_system="Ubuntu",
            target_operating_system_version="24.04",
            package_policy_digest=DIGEST,
            provider_image=None,
            minimum_root_free_bytes=1024,
            minimum_boot_free_bytes=512,
            space_policy_digest=DIGEST,
        )


def test_missing_stale_and_unsupported_current_evidence_is_refused() -> None:
    payload, metadata, observed, inventory, base_os, prerequisites, intent = _context(
        HostRole.MANAGER
    )
    del payload
    stale = replace(_readiness(inventory), trust_digest=None)
    with pytest.raises(StateConflictError, match="provenance"):
        build_os_upgrade_preflight_payload(
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            stale,
            base_os,  # type: ignore[arg-type]
            prerequisites,
            intent,  # type: ignore[arg-type]
            limit=(TARGETS[HostRole.MANAGER],),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )
    with pytest.raises(StateConflictError, match="incomplete"):
        build_os_upgrade_preflight_payload(
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            _readiness(inventory),
            base_os,  # type: ignore[arg-type]
            replace(prerequisites, manager_server=None),
            intent,  # type: ignore[arg-type]
            limit=(TARGETS[HostRole.MANAGER],),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )
    failed_base = replace(
        base_os,
        status=BaseOsStatus.FAILURE,
        hosts=(
            replace(
                cast(Any, base_os).hosts[0],
                status=BaseOsStatus.FAILURE,
                reason="execution-failed",
            ),
        ),
    )
    with pytest.raises(StateConflictError, match="base-os"):
        build_os_upgrade_preflight_payload(
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            _readiness(inventory),
            failed_base,  # type: ignore[arg-type]
            prerequisites,
            intent,  # type: ignore[arg-type]
            limit=(TARGETS[HostRole.MANAGER],),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )
    with pytest.raises(StateConflictError, match="unsupported current OS"):
        build_os_upgrade_preflight_payload(
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            _readiness(inventory),
            base_os,  # type: ignore[arg-type]
            prerequisites,
            intent,  # type: ignore[arg-type]
            limit=(TARGETS[HostRole.MANAGER],),
            image_filter=ImageFilter("Oracle Linux", "9", ImageVersionMatch.EXACT),
            architecture="amd64",
        )


def test_undefined_and_unsupported_transitions_never_select_a_path() -> None:
    undefined, *_ = _context()
    unsupported, *_ = _context(target_version="26.04")
    other_os, *_ = _context(target_os="Oracle Linux")
    reprovision, *_ = _context(target_version="26.04", strategy="reprovision")
    assert classify_transition("Ubuntu", "24.04") is TransitionClassification.UNDEFINED
    assert (
        classify_transition("Ubuntu", "26.04") is TransitionClassification.UNSUPPORTED
    )
    assert undefined["controller_gates"][-1]["status"] == "unknown"  # type: ignore[index]
    for payload in (unsupported, other_os, reprovision):
        assert payload["transition_classification"] == "unsupported"
        assert payload["selected_path"] == "not-performed"
        assert "target-transition-unsupported" in payload["controller_blockers"]
    assert reprovision["controller_gates"][13]["status"] == "passed"  # type: ignore[index]


def test_reprovision_provider_architecture_mismatch_is_blocked() -> None:
    _, metadata, observed, inventory, base_os, prerequisites, _ = _context(
        HostRole.JUMP_HOST
    )
    provider = build_provider_image_facts(
        operating_system="Ubuntu",
        operating_system_version="26.04",
        architecture="aarch64",
        image_id_digest=DIGEST,
        source_digest=DIGEST,
        available=True,
        replacement_plan_reviewed=True,
    )
    intent = build_os_upgrade_preflight_intent(
        metadata,  # type: ignore[arg-type]
        operation_id=OPERATION_ID,
        logical_id=TARGETS[HostRole.JUMP_HOST],
        strategy="reprovision",
        target_operating_system="Ubuntu",
        target_operating_system_version="26.04",
        package_policy_digest=None,
        provider_image=provider,
        minimum_root_free_bytes=1024,
        minimum_boot_free_bytes=512,
        space_policy_digest=os_upgrade_space_policy_digest(1024, 512),
    )
    payload = build_os_upgrade_preflight_payload(
        metadata,  # type: ignore[arg-type]
        observed,  # type: ignore[arg-type]
        inventory,  # type: ignore[arg-type]
        _readiness(inventory),
        base_os,  # type: ignore[arg-type]
        prerequisites,
        intent,
        limit=(TARGETS[HostRole.JUMP_HOST],),
        image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
        architecture="amd64",
    )
    assert "provider-image-mismatch" in payload["controller_blockers"]
    provider_gate = next(
        item
        for item in cast(list[dict[str, object]], payload["controller_gates"])
        if item["name"] == "provider-image"
    )
    assert provider_gate["status"] == "failed"


@pytest.mark.parametrize(
    ("status", "blocker"),
    [
        (GateStatus.UNKNOWN, "replication-unknown"),
        (GateStatus.FAILED, "replication-failed"),
    ],
)
def test_scylla_unknown_or_failed_safety_gates_refuse_rolling(
    status: GateStatus, blocker: str
) -> None:
    payload, *_ = _context(HostRole.SCYLLA, rolling_status=status)
    assert payload["rolling_eligible"] is False
    assert blocker in payload["controller_blockers"]
    gates = {
        item["name"]: item["status"]
        for item in cast(list[dict[str, str]], payload["controller_gates"])
    }
    assert gates["replication"] == status.value
    assert gates["quorum"] == status.value
    assert gates["capacity"] == status.value
    assert gates["backup-policy"] == status.value
    topology, *_ = _context(HostRole.SCYLLA, no_active_topology_work=False)
    assert topology["rolling_eligible"] is False
    assert "topology-work-active" in topology["controller_blockers"]


@pytest.mark.parametrize(
    ("gate", "blocker"),
    [
        ("package-locks", "package-manager-lock-held"),
        ("broken-packages", "broken-packages"),
        ("reboot-required", "reboot-required"),
        ("root-space", "root-space-insufficient"),
        ("boot-space", "boot-space-insufficient"),
    ],
)
def test_parser_retains_bounded_host_blockers(gate: str, blocker: str) -> None:
    payload, *_ = _context()
    evidence = parse_os_upgrade_preflight_execution(
        _stdout(
            payload,
            result=_result(
                payload,
                gate_changes={gate: "failed"},
                extra_blockers=(blocker,),
            ),
        ),
        expected_payload=payload,
        exit_code=0,
    )
    assert evidence.status is OsUpgradePreflightStatus.BLOCKED
    assert blocker in evidence.blockers
    assert (
        dict((item.name, item.status) for item in evidence.gates)[gate]
        is GateStatus.FAILED
    )


def test_parser_refuses_mutation_malformed_duplicate_and_secret_evidence() -> None:
    payload, *_ = _context()
    with pytest.raises(AnsibleError, match="exceeds"):
        parse_os_upgrade_preflight_execution(
            "x" * (512 * 1024 + 1),
            expected_payload=payload,
            exit_code=2,
        )
    changed = _stdout(payload).replace("changed=0", "changed=1")
    with pytest.raises(AnsibleError, match="mutation"):
        parse_os_upgrade_preflight_execution(
            changed, expected_payload=payload, exit_code=0
        )
    inconsistent_host_gate = _result(
        payload, gate_changes={"reboot-required": "failed"}
    )
    with pytest.raises(AnsibleError, match="host gate blockers"):
        parse_os_upgrade_preflight_execution(
            _stdout(payload, result=inconsistent_host_gate),
            expected_payload=payload,
            exit_code=0,
        )
    duplicate_json = json.dumps(
        _result(payload), sort_keys=True, separators=(",", ":")
    ).replace(
        '"status":"blocked"',
        '"status":"blocked","status":"blocked"',
    )
    duplicate_marker = base64.b64encode(duplicate_json.encode()).decode()
    host = cast(str, payload["logical_id"])
    duplicate = (
        f"ok: [{host}] => "
        f'{{"msg":"DSV_OS_UPGRADE_PREFLIGHT_B64={duplicate_marker}"}}\n'
        "PLAY RECAP *****\n"
        f"{host} : ok=8 changed=0 unreachable=0 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    with pytest.raises(AnsibleError):
        parse_os_upgrade_preflight_execution(
            duplicate, expected_payload=payload, exit_code=0
        )
    secret = _result(payload)
    secret["blockers"] = [*cast(list[str], secret["blockers"]), "token: fake"]
    encoded = base64.b64encode(json.dumps(secret).encode()).decode()
    stdout = (
        f'ok: [{host}] => {{"msg":"DSV_OS_UPGRADE_PREFLIGHT_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"{host} : ok=8 changed=0 unreachable=0 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    with pytest.raises(AnsibleError):
        parse_os_upgrade_preflight_execution(
            stdout, expected_payload=payload, exit_code=0
        )


def test_service_check_mode_success_failure_timeout_malformed_and_redaction(
    tmp_path: Path,
) -> None:
    payload, metadata, observed, inventory, base_os, prerequisites, intent = _context()
    stdout = _stdout(
        payload,
        noise="203.0.113.10 token=obviously-fake\n",
    )
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(0, stdout, ""),
        ]
    )
    paths = _paths(tmp_path)
    service = AnsibleService(_builder(tmp_path, paths), runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute_os_upgrade_preflight(
            lock,
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            base_os,  # type: ignore[arg-type]
            prerequisites,
            intent,  # type: ignore[arg-type]
            limit=(TARGETS[HostRole.JUMP_HOST],),
            readiness=_readiness(inventory),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
            check=True,
        )
    assert result.os_upgrade_preflight is not None
    assert result.os_upgrade_preflight.status is OsUpgradePreflightStatus.BLOCKED
    assert result.stdout == result.stderr == ""
    assert "--check" in runner.specs[-1].argv
    assert "203.0.113.10" in runner.specs[-1].sensitive_values
    assert not tuple(paths.ansible_local_tmp.iterdir())

    failed_runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(
                2,
                _stdout(payload, result=_result(payload, status="failed"), failed=1),
                "",
            ),
        ]
    )
    failed_service = AnsibleService(_builder(tmp_path, paths), failed_runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        failed_service.version(lock)
        failed = failed_service.execute_os_upgrade_preflight(
            lock,
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            base_os,  # type: ignore[arg-type]
            prerequisites,
            intent,  # type: ignore[arg-type]
            limit=(TARGETS[HostRole.JUMP_HOST],),
            readiness=_readiness(inventory),
            image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
            architecture="amd64",
        )
    assert failed.os_upgrade_preflight is not None
    assert failed.os_upgrade_preflight.status is OsUpgradePreflightStatus.FAILED

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
            timeout_service.execute_os_upgrade_preflight(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                base_os,  # type: ignore[arg-type]
                prerequisites,
                intent,  # type: ignore[arg-type]
                limit=(TARGETS[HostRole.JUMP_HOST],),
                readiness=_readiness(inventory),
                image_filter=ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT),
                architecture="amd64",
            )
    assert "obviously-fake" not in str(caught.value)

    with pytest.raises(AnsibleError, match="membership"):
        parse_os_upgrade_preflight_execution(
            "PLAY RECAP *****\n",
            expected_payload=payload,
            exit_code=2,
        )


def test_registry_source_package_and_static_read_only_contract() -> None:
    definition = get_playbook("os-upgrade-preflight")
    assert definition.source_available
    assert definition.hosts == "all"
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert definition.check_mode is CheckMode.SUPPORTED
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.classification is OperationClassification.READ_ONLY
    assert definition.pre_health_gate
    assert definition.tags == (
        "os-upgrade-preflight",
        "preflight",
        "inspect",
        "verify",
    )
    assert callable(AnsibleService.execute_os_upgrade_preflight)
    assert len([book for book in PLAYBOOKS if book.source_available]) == 34
    bundle_paths = {item.path for item in load_ansible_source_bundle().files}
    expected = {
        "playbooks/os-upgrade-preflight.yml",
        "playbooks/roles/os_upgrade_preflight/tasks/main.yml",
        "playbooks/roles/os_upgrade_preflight/library/os_upgrade_preflight.py",
        "playbooks/roles/os_upgrade_preflight/files/os-upgrade-preflight.provenance.yml",
    }
    assert expected <= bundle_paths
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content"
    text = "\n".join((root / path).read_text(encoding="utf-8") for path in expected)
    lowered = text.lower()
    for required in (
        "gather_facts: true",
        "serial: 1",
        "hosts: all",
        "supports_check_mode=True",
        "/usr/bin/dpkg",
        "--audit",
        "/run/reboot-required",
        "/proc/locks",
        "statvfs",
        "package-currency-not-performed",
        'retrieved_at: "2026-09-18"',
    ):
        assert required in text
    for forbidden in (
        "ansible.builtin.shell",
        "ansible.builtin.apt",
        "ansible.builtin.reboot",
        'do-release-upgrade",',
        'apt-get",',
        'systemctl", "stop',
        'systemctl", "start',
        "oci cli",
        "terraform apply",
        "validate_certs: false",
    ):
        assert forbidden not in lowered


def test_remote_module_reports_package_reboot_lock_and_space_gates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _remote_module()
    payload, *_ = _context()
    monkeypatch.setattr(module.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(module.platform, "release", lambda: "6.8.0-fake")
    monkeypatch.setattr(module, "_run_dpkg_audit", lambda _: True)
    monkeypatch.setattr(module, "_lock_status", lambda: "clear")
    monkeypatch.setattr(module, "_free_bytes", lambda _: 10_000)
    monkeypatch.setattr(module, "REBOOT_REQUIRED", tmp_path / "reboot-required")
    result = module._inspect(payload, 15)
    gates = {item["name"]: item["status"] for item in result["gates"]}
    assert result["status"] == "blocked"
    assert gates["broken-packages"] == "passed"
    assert gates["package-locks"] == "passed"
    assert gates["reboot-required"] == "passed"
    assert gates["root-space"] == "passed"
    assert gates["boot-space"] == "passed"
    assert result["selected_path"] == "not-performed"

    (tmp_path / "reboot-required").write_text("", encoding="utf-8")
    monkeypatch.setattr(module, "_run_dpkg_audit", lambda _: False)
    monkeypatch.setattr(module, "_lock_status", lambda: "held")
    monkeypatch.setattr(module, "_free_bytes", lambda _: 0)
    blocked = module._inspect(payload, 15)
    assert {
        "reboot-required",
        "broken-packages",
        "package-manager-lock-held",
        "root-space-insufficient",
        "boot-space-insufficient",
    } <= set(blocked["blockers"])

    def _timeout(*args: object, **kwargs: object) -> object:
        del kwargs
        raise subprocess.TimeoutExpired(cast(list[str], args[0]), 1)

    fresh_module = _remote_module()
    monkeypatch.setattr(fresh_module.subprocess, "run", _timeout)
    with pytest.raises(fresh_module.PreflightError) as caught:
        fresh_module._run_dpkg_audit(1)
    assert caught.value.blocker == "execution-failed"


def test_playbook_syntax_check_is_local_and_write_free(tmp_path: Path) -> None:
    executable = shutil.which("ansible-playbook")
    if executable is None:
        pytest.skip("Ansible development executable is unavailable")
    playbook = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/os-upgrade-preflight.yml"
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


def _remote_module() -> Any:
    path = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles/os_upgrade_preflight/library"
        / "os_upgrade_preflight.py"
    )
    spec = importlib.util.spec_from_file_location("os_upgrade_preflight_remote", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
