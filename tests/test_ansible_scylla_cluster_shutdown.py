import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from test_ansible import DIGEST, FakeRunner, _builder, _paths, _readiness
from test_ansible_scylla_configure import _context
from test_ansible_scylla_health import HOST_1, _health_context, _ring, _stdout
from test_ansible_scylla_health import _view as _health_view

from scylla_vms.ansible.manager_tasks import (
    EXPECTED_BLOCKERS as MANAGER_BLOCKERS,
)
from scylla_vms.ansible.manager_tasks import (
    MANAGER_SERVICE_UNIT,
    ManagerTasksEvidence,
    ManagerTasksStatus,
)
from scylla_vms.ansible.manager_tasks import (
    NOT_PERFORMED as MANAGER_NOT_PERFORMED,
)
from scylla_vms.ansible.registry import PLAYBOOKS, CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_cluster_shutdown import (
    EXPECTED_BLOCKERS,
    MUTATION_BOUNDARY,
    NOT_PERFORMED,
    SCYLLA_CLUSTER_SHUTDOWN_SCHEMA_VERSION,
    NodeShutdownState,
    ScyllaClusterShutdownAuthorization,
    ScyllaClusterShutdownStatus,
    build_scylla_cluster_shutdown_payload,
    parse_scylla_cluster_shutdown_execution,
)
from scylla_vms.ansible.scylla_health import (
    HealthReadiness,
    parse_scylla_health_execution,
)
from scylla_vms.ansible.scylla_remove_live import scylla_health_evidence_digest
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.process import ProcessResult, ProcessTimeoutError

OPERATION_ID = "44444444-4444-4444-8444-444444444444"


def _manager_tasks(logical_id: str = "manager-1") -> ManagerTasksEvidence:
    return ManagerTasksEvidence(
        logical_id,
        ManagerTasksStatus.NOT_PERFORMED,
        "quiesce",
        ("backup", "repair"),
        False,
        MANAGER_SERVICE_UNIT,
        True,
        True,
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
        False,
        False,
        False,
        False,
        MANAGER_NOT_PERFORMED,
        (("inventory_digest", DIGEST), ("observation_digest", DIGEST)),
        MANAGER_BLOCKERS,
    )


def _manager_digest(manager_tasks: ManagerTasksEvidence) -> str:
    payload = {
        "action": manager_tasks.action,
        "applied": manager_tasks.applied,
        "blockers": list(manager_tasks.blockers),
        "logical_id": manager_tasks.logical_id,
        "quiesce_performed": manager_tasks.quiesce_performed,
        "registration_performed": manager_tasks.registration_performed,
        "service_started": manager_tasks.service_started,
        "sctool_invoked": manager_tasks.sctool_invoked,
        "status": manager_tasks.status.value,
    }
    encoded = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _shutdown_context(
    *,
    health_changes: dict[str, object] | None = None,
    authorization_changes: dict[str, object] | None = None,
    manager_changes: dict[str, object] | None = None,
    limit: tuple[str, ...] | None = None,
):
    _, metadata, observed, _, _, _ = _context()
    health_payload, inventory = _health_context()
    queried = tuple(cast(list[str], health_payload["queried_nodes"]))
    stdout, rc = _stdout(
        [_health_view("scylla-ad-1-1", HOST_1, _ring())],
        queried,
    )
    health = parse_scylla_health_execution(
        stdout, expected_payload=health_payload, exit_code=rc
    )
    if health_changes:
        health = replace(health, **health_changes)
    manager_tasks = _manager_tasks()
    if manager_changes:
        manager_tasks = replace(manager_tasks, **manager_changes)
    readiness = _readiness(inventory)
    scylla_ids = tuple(
        host.logical_id
        for host in inventory.record.inventory.hosts
        if host.role.value == "scylla"
    )
    authorization = ScyllaClusterShutdownAuthorization(
        operation_id=OPERATION_ID,
        cluster_uuid=str(metadata.cluster_uuid),
        authorization_digest=DIGEST,
        health_digest=scylla_health_evidence_digest(health),
        topology_digest=cast(str, health.topology_digest),
        observation_digest=observed.digest,
        inventory_digest=inventory.digest,
        trust_digest=cast(str, readiness.trust_digest),
        manager_tasks_digest=_manager_digest(manager_tasks),
        confirmed_cluster=f"{metadata.cluster_name}:{metadata.cluster_uuid}",
        manager_applicability="not-applicable",
        allow_manager_not_applicable=True,
        allow_destructive=True,
        reviewed=True,
        no_competing_operation=True,
    )
    if authorization_changes:
        authorization = replace(authorization, **authorization_changes)
    payload = build_scylla_cluster_shutdown_payload(
        metadata,
        observed,
        inventory,
        readiness,
        health,
        manager_tasks,
        authorization,
        limit=limit or scylla_ids,
    )
    return payload, metadata, observed, inventory, health, manager_tasks, authorization


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _result(
    payload: dict[str, object],
    status: str = "not-performed",
    *,
    logical_id: str | None = None,
) -> dict[str, object]:
    host = cast(dict[str, object], cast(list[object], payload["hosts"])[0])
    target = logical_id or _text(host["logical_id"])
    success = status == "not-performed"
    predicted = status == "not-predicted"
    state = "not-performed" if success else "not-predicted" if predicted else "unknown"
    return {
        "applied": False,
        "blockers": list(EXPECTED_BLOCKERS)
        if success
        else []
        if predicted
        else ["service-inspect-failed"],
        "decommission_performed": False,
        "drain_performed": False,
        "manager_quiesce_performed": False,
        "mask_performed": False,
        "mutation_boundary": MUTATION_BOUNDARY,
        "nodes": [
            {
                "drain_state": state,
                "host_id_digest": _digest(_text(host["host_id"])),
                "logical_id": target,
                "mask_state": state,
                "observed_active": "active" if success else None,
                "observed_enabled": "enabled" if success else None,
                "stop_state": state,
            }
        ],
        "not_performed": list(NOT_PERFORMED),
        "provenance": payload["provenance"],
        "recovery_required": False,
        "removenode_performed": False,
        "schema_version": SCYLLA_CLUSTER_SHUTDOWN_SCHEMA_VERSION,
        "start_performed": False,
        "status": status,
        "stop_performed": False,
        "storage_wiped": False,
        "terraform_ran": False,
        "vm_destroyed": False,
    }


def _text(value: object) -> str:
    assert isinstance(value, str)
    return value


def _stdout_for(
    payload: dict[str, object],
    status: str = "not-performed",
    *,
    failed: int = 0,
    unreachable: int = 0,
) -> str:
    host = _text(
        cast(dict[str, object], cast(list[object], payload["hosts"])[0])["logical_id"]
    )
    encoded = base64.b64encode(
        json.dumps(_result(payload, status), sort_keys=True).encode()
    ).decode()
    return (
        f"ok: [{host}] => "
        f'{{"msg":"DSV_SCYLLA_CLUSTER_SHUTDOWN_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"{host} : ok=8 changed=0 unreachable={unreachable} "
        f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


def test_cluster_shutdown_payload_is_exact_and_refuses_unsafe_targets() -> None:
    payload, metadata, observed, inventory, health, manager_tasks, authorization = (
        _shutdown_context()
    )
    assert payload["schema_version"] == SCYLLA_CLUSTER_SHUTDOWN_SCHEMA_VERSION
    assert payload["applied"] is False
    assert payload["drain_performed"] is False
    assert payload["stop_performed"] is False
    assert payload["mask_performed"] is False
    assert payload["manager_quiesce_performed"] is False
    assert payload["decommission_performed"] is False
    assert payload["removenode_performed"] is False
    assert payload["terraform_ran"] is False
    assert payload["vm_destroyed"] is False
    assert payload["storage_wiped"] is False
    assert payload["not_performed"] == list(NOT_PERFORMED)
    assert payload["expected_blockers"] == list(EXPECTED_BLOCKERS)
    assert payload["authorization"]["manager_applicability"] == "not-applicable"
    encoded = json.dumps(payload, sort_keys=True)
    assert "token:" not in encoded
    assert "password" not in encoded
    assert "10.0.0." not in encoded
    with pytest.raises(StateConflictError, match="exact complete Scylla set"):
        build_scylla_cluster_shutdown_payload(
            metadata,
            observed,
            inventory,
            _readiness(inventory),
            health,
            manager_tasks,
            authorization,
            limit=("jump-host-1",),
        )
    with pytest.raises(StateConflictError, match="exact complete Scylla set"):
        build_scylla_cluster_shutdown_payload(
            metadata,
            observed,
            inventory,
            _readiness(inventory),
            health,
            manager_tasks,
            authorization,
            limit=(),
        )


def test_cluster_shutdown_refuses_stale_health_manager_and_authorization() -> None:
    payload, metadata, observed, inventory, health, manager_tasks, authorization = (
        _shutdown_context()
    )
    scylla_ids = tuple(
        host.logical_id
        for host in inventory.record.inventory.hosts
        if host.role.value == "scylla"
    )
    blocked = replace(
        health, status=HealthReadiness.BLOCKED, blockers=("node-not-up-normal",)
    )
    with pytest.raises(StateConflictError, match="full-cluster health"):
        build_scylla_cluster_shutdown_payload(
            metadata,
            observed,
            inventory,
            _readiness(inventory),
            blocked,
            manager_tasks,
            authorization,
            limit=scylla_ids,
        )
    stale_ready = replace(_readiness(inventory), trust_digest=None)
    with pytest.raises(StateConflictError, match="provenance"):
        build_scylla_cluster_shutdown_payload(
            metadata,
            observed,
            inventory,
            stale_ready,
            health,
            manager_tasks,
            authorization,
            limit=scylla_ids,
        )
    started_manager = replace(
        manager_tasks,
        status=ManagerTasksStatus.FAILED,
        quiesce_performed=True,
        blockers=("execution-failed",),
    )
    with pytest.raises(StateConflictError, match="not-performed evidence"):
        build_scylla_cluster_shutdown_payload(
            metadata,
            observed,
            inventory,
            _readiness(inventory),
            health,
            started_manager,
            authorization,
            limit=scylla_ids,
        )
    unauthorized = replace(authorization, reviewed=False)
    with pytest.raises(StateConflictError, match="authorization"):
        build_scylla_cluster_shutdown_payload(
            metadata,
            observed,
            inventory,
            _readiness(inventory),
            health,
            manager_tasks,
            unauthorized,
            limit=scylla_ids,
        )
    claimed_quiesce = replace(
        authorization,
        manager_applicability="quiesced",
        allow_manager_not_applicable=False,
    )
    with pytest.raises(StateConflictError, match="authorization"):
        build_scylla_cluster_shutdown_payload(
            metadata,
            observed,
            inventory,
            _readiness(inventory),
            health,
            manager_tasks,
            claimed_quiesce,
            limit=scylla_ids,
        )
    del payload


@pytest.mark.parametrize(
    ("status", "exit_code", "failed", "expected"),
    [
        ("not-performed", 0, 0, ScyllaClusterShutdownStatus.NOT_PERFORMED),
        ("not-predicted", 2, 1, ScyllaClusterShutdownStatus.NOT_PREDICTED),
        ("failed", 2, 1, ScyllaClusterShutdownStatus.FAILED),
    ],
)
def test_cluster_shutdown_result_parser_statuses(
    status: str,
    exit_code: int,
    failed: int,
    expected: ScyllaClusterShutdownStatus,
) -> None:
    payload, *_ = _shutdown_context()
    evidence = parse_scylla_cluster_shutdown_execution(
        _stdout_for(payload, status, failed=failed),
        expected_payload=payload,
        exit_code=exit_code,
    )
    assert evidence.status is expected
    assert evidence.applied is False
    assert evidence.drain_performed is False
    assert evidence.stop_performed is False
    assert evidence.mutation_boundary == MUTATION_BOUNDARY
    assert evidence.recovery_required is False
    assert evidence.not_performed == NOT_PERFORMED
    assert len(evidence.nodes) == 1
    if expected is ScyllaClusterShutdownStatus.NOT_PERFORMED:
        assert evidence.blockers == EXPECTED_BLOCKERS
        assert evidence.nodes[0].drain_state is NodeShutdownState.NOT_PERFORMED
        assert evidence.nodes[0].observed_enabled == "enabled"
        assert evidence.nodes[0].observed_active == "active"
    if expected is ScyllaClusterShutdownStatus.NOT_PREDICTED:
        assert evidence.blockers == ()
        assert evidence.nodes[0].observed_enabled is None


def test_cluster_shutdown_parser_refuses_malformed_secrets_and_mutations() -> None:
    payload, *_ = _shutdown_context()
    with pytest.raises(AnsibleError, match="exceeds"):
        parse_scylla_cluster_shutdown_execution(
            "x" * (512 * 1024 + 1), expected_payload=payload, exit_code=2
        )
    with pytest.raises(AnsibleError):
        parse_scylla_cluster_shutdown_execution(
            _stdout_for(payload, "not-performed", failed=1),
            expected_payload=payload,
            exit_code=2,
        )
    for field in (
        "applied",
        "drain_performed",
        "stop_performed",
        "mask_performed",
        "manager_quiesce_performed",
        "decommission_performed",
        "removenode_performed",
        "start_performed",
        "terraform_ran",
        "vm_destroyed",
        "storage_wiped",
    ):
        claimed = _result(payload, "not-performed")
        claimed[field] = True
        encoded = base64.b64encode(
            json.dumps(claimed, sort_keys=True).encode()
        ).decode()
        host = _text(
            cast(dict[str, object], cast(list[object], payload["hosts"])[0])[
                "logical_id"
            ]
        )
        stdout = (
            f"ok: [{host}] => "
            f'{{"msg":"DSV_SCYLLA_CLUSTER_SHUTDOWN_B64={encoded}"}}\nPLAY RECAP *****\n'
            f"{host} : ok=8 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0\n"
        )
        with pytest.raises(AnsibleError, match="forbidden mutation"):
            parse_scylla_cluster_shutdown_execution(
                stdout, expected_payload=payload, exit_code=0
            )
    failed = (
        "PLAY RECAP *****\n"
        "scylla-ad-1-1 : ok=1 changed=0 unreachable=1 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    evidence = parse_scylla_cluster_shutdown_execution(
        failed, expected_payload=payload, exit_code=4
    )
    assert evidence.status is ScyllaClusterShutdownStatus.FAILED
    assert evidence.blockers == ("execution-failed",)
    definition = get_playbook("scylla-cluster-shutdown")
    with pytest.raises(AnsibleError, match="variable value is invalid"):
        definition.validate_variables(
            {
                "deploy_scylla_vms_scylla_cluster_shutdown": {
                    "note": "token: obviously-fake"
                }
            }
        )


def test_service_success_failure_timeout_malformed_and_redaction(
    tmp_path: Path,
) -> None:
    payload, metadata, observed, inventory, health, manager_tasks, authorization = (
        _shutdown_context()
    )
    paths = _paths(tmp_path)
    stdout = "203.0.113.10 secret-token\n" + _stdout_for(payload)
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
        result = service.execute_scylla_cluster_shutdown(
            lock,
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            health,
            manager_tasks,
            authorization,
            limit=("scylla-ad-1-1",),
            readiness=_readiness(inventory),
        )
        with pytest.raises(AnsibleError, match="check mode is refused"):
            service.execute_scylla_cluster_shutdown(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                health,
                manager_tasks,
                authorization,
                limit=("scylla-ad-1-1",),
                readiness=_readiness(inventory),
                check=True,
            )
    assert result.scylla_cluster_shutdown is not None
    assert (
        result.scylla_cluster_shutdown.status
        is ScyllaClusterShutdownStatus.NOT_PERFORMED
    )
    assert result.stdout == result.stderr == ""
    assert runner.runtime_payloads[-1] == {
        "deploy_scylla_vms_scylla_cluster_shutdown": payload
    }
    assert "--limit" in runner.specs[-1].argv
    assert "scylla-ad-1-1" in runner.specs[-1].argv
    assert "--check" not in runner.specs[-1].argv
    assert "10.0.0.20" in runner.specs[-1].sensitive_values
    assert "ocid1.instance.oc1.iad.fakescylla" in runner.specs[-1].sensitive_values
    assert not tuple(paths.ansible_local_tmp.iterdir())

    fail_stdout = _stdout_for(payload, "failed", failed=1)
    fail_runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(2, fail_stdout, ""),
        ]
    )
    fail_service = AnsibleService(_builder(tmp_path, paths), fail_runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        fail_service.version(lock)
        failed = fail_service.execute_scylla_cluster_shutdown(
            lock,
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            health,
            manager_tasks,
            authorization,
            limit=("scylla-ad-1-1",),
            readiness=_readiness(inventory),
        )
    assert failed.scylla_cluster_shutdown is not None
    assert failed.scylla_cluster_shutdown.status is ScyllaClusterShutdownStatus.FAILED

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
            AnsibleError, match="scylla-cluster-shutdown command failed"
        ) as caught:
            timeout_service.execute_scylla_cluster_shutdown(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                health,
                manager_tasks,
                authorization,
                limit=("scylla-ad-1-1",),
                readiness=_readiness(inventory),
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
            malformed_service.execute_scylla_cluster_shutdown(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                health,
                manager_tasks,
                authorization,
                limit=("scylla-ad-1-1",),
                readiness=_readiness(inventory),
            )


def test_execute_cluster_shutdown_requires_complete_scylla_set(tmp_path: Path) -> None:
    _, metadata, observed, inventory, health, manager_tasks, authorization = (
        _shutdown_context()
    )
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
        with pytest.raises(StateConflictError, match="exact complete Scylla set"):
            service.execute_scylla_cluster_shutdown(
                lock,
                metadata,  # type: ignore[arg-type]
                observed,  # type: ignore[arg-type]
                inventory,  # type: ignore[arg-type]
                health,
                manager_tasks,
                authorization,
                limit=("scylla-ad-1-1", "scylla-ad-2-1"),
                readiness=_readiness(inventory),
            )


def test_cluster_shutdown_registry_dependency_and_static_safety() -> None:
    definition = get_playbook("scylla-cluster-shutdown")
    assert definition.source_available
    assert definition.hosts == "scylla"
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert definition.check_mode is CheckMode.REFUSED
    assert definition.limit_policy is LimitPolicy.EXPLICIT
    assert definition.classification is OperationClassification.DESTRUCTIVE
    assert definition.pre_health_gate is True
    assert definition.post_health_gate is False
    assert definition.tags == (
        "scylla-cluster-shutdown",
        "preflight",
        "inspect",
        "verify",
    )
    assert callable(AnsibleService.execute_scylla_cluster_shutdown)
    assert {book.name for book in PLAYBOOKS if book.source_available} >= {
        "scylla-cluster-shutdown"
    }
    bundle_paths = {item.path for item in load_ansible_source_bundle().files}
    assert {
        "playbooks/scylla-cluster-shutdown.yml",
        "playbooks/roles/scylla_cluster_shutdown/tasks/main.yml",
        "playbooks/roles/scylla_cluster_shutdown/library/scylla_cluster_shutdown.py",
        "playbooks/roles/scylla_cluster_shutdown/files/scylla-cluster-shutdown.provenance.yml",
    } <= bundle_paths
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content"
    playbook = (root / "playbooks/scylla-cluster-shutdown.yml").read_text(
        encoding="utf-8"
    )
    tasks = (root / "playbooks/roles/scylla_cluster_shutdown/tasks/main.yml").read_text(
        encoding="utf-8"
    )
    module = (
        root
        / "playbooks/roles/scylla_cluster_shutdown/library/scylla_cluster_shutdown.py"
    ).read_text(encoding="utf-8")
    provenance = (
        root
        / "playbooks/roles/scylla_cluster_shutdown/files/scylla-cluster-shutdown.provenance.yml"
    ).read_text(encoding="utf-8")
    for required in (
        "gather_facts: true",
        "serial: 1",
        "any_errors_fatal: true",
        "hosts: scylla",
        "status': 'not-predicted'",
        "check mode is refused",
    ):
        assert required in playbook
    assert "status: not-performed" in tasks
    assert "scylla_cluster_shutdown:" in tasks
    assert "action: inspect" in tasks
    for required in (
        "/usr/bin/systemctl",
        "is-enabled",
        "is-active",
        "scylla-server.service",
        "official-command-order-unreviewed",
        'REFUSED_ACTIONS = {"drain", "mask", "shutdown", "stop"}',
    ):
        assert required in module
    lowered = playbook.lower() + tasks.lower() + module.lower()
    for forbidden in (
        "ansible.builtin.shell",
        "ansible.builtin.get_url",
        "ansible.builtin.uri",
        "nodetool drain",
        "systemctl stop",
        "systemctl mask",
        "systemctl unmask",
        "reboot:",
        "validate_certs: false",
        "trusted=yes",
        "firewall",
        "iptables",
    ):
        assert forbidden not in lowered
    for required in (
        'retrieved_at: "2026-09-18"',
        "docs.scylladb.com/manual/stable/operating-scylla/",
        "docs.scylladb.com/manual/stable/operating-scylla/admin.html",
        "scylla-server.service",
        "never runs nodetool drain",
        "This slice validates Ubuntu 24.04",
    ):
        assert required in provenance


def test_cluster_shutdown_playbook_syntax_check_is_local_and_write_free(
    tmp_path: Path,
) -> None:
    executable = shutil.which("ansible-playbook")
    if executable is None:
        pytest.skip("Ansible development executable is unavailable")
    playbook = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/scylla-cluster-shutdown.yml"
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


def test_cluster_shutdown_module_inspects_and_refuses_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _remote_module()
    commands: list[list[str]] = []

    def _fake_run(argv: list[str], **kwargs: object) -> object:
        commands.append(list(argv))
        if kwargs.get("timeout") == 1:
            raise subprocess.TimeoutExpired(list(argv), 1)
        stdout = "enabled" if argv[1] == "is-enabled" else "active"
        return subprocess.CompletedProcess(argv, 0, stdout, "")

    monkeypatch.setattr(module.subprocess, "run", _fake_run)
    inspection = module._inspect(15)
    assert inspection == {
        "active": "active",
        "enabled": "enabled",
        "unit": "scylla-server.service",
    }
    assert commands == [
        ["/usr/bin/systemctl", "is-enabled", "scylla-server.service"],
        ["/usr/bin/systemctl", "is-active", "scylla-server.service"],
    ]
    with pytest.raises(module.ShutdownError) as timed:
        module._run(["/usr/bin/systemctl", "is-active", "scylla-server.service"], 1)
    assert timed.value.blocker == "execution-interrupted"


def _remote_module() -> Any:
    path = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles/scylla_cluster_shutdown/library"
        / "scylla_cluster_shutdown.py"
    )
    spec = importlib.util.spec_from_file_location("shutdown_remote", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
