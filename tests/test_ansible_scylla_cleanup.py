import base64
import hashlib
import importlib.util
import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible import DIGEST, _readiness
from test_ansible_scylla_configure import _context
from test_ansible_scylla_health import HOST_1, HOST_2, _health_context, _ring, _stdout
from test_ansible_scylla_health import _view as _health_view
from test_ansible_scylla_install import VERSION

from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_cleanup import (
    SCYLLA_CLEANUP_SCHEMA_VERSION,
    CleanupMutationBoundary,
    CleanupOperation,
    CleanupTopologyChangeEvidence,
    ScyllaCleanupAuthorization,
    ScyllaCleanupStatus,
    _topology_change_digest,
    build_scylla_cleanup_payload,
    parse_scylla_cleanup_execution,
    scylla_cleanup_checkpoint_evidence,
    scylla_cleanup_interrupted_evidence,
)
from scylla_vms.ansible.scylla_health import (
    HealthReadiness,
    parse_scylla_health_execution,
)
from scylla_vms.ansible.scylla_remove_live import scylla_health_evidence_digest
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.journal import EvidenceResult


def _cleanup_context(
    *,
    operation: CleanupOperation = CleanupOperation.ADD_NODE,
    joined_ids: tuple[str, ...] = ("scylla-ad-2-1",),
    target: str = "scylla-ad-1-1",
    health_changes: dict[str, object] | None = None,
    topology_changes: dict[str, object] | None = None,
    authorization_changes: dict[str, object] | None = None,
) -> tuple[dict[str, object], ScyllaCleanupAuthorization]:
    _, metadata, observed, _, _, _ = _context()
    health_payload, inventory = _health_context(multi=True)
    queried = tuple(cast(list[str], health_payload["queried_nodes"]))
    stdout, rc = _stdout(
        [
            _health_view("scylla-ad-1-1", HOST_1, _ring(include_peer=True)),
            _health_view("scylla-ad-2-1", HOST_2, _ring(include_peer=True)),
        ],
        queried,
    )
    health = parse_scylla_health_execution(
        stdout, expected_payload=health_payload, exit_code=rc
    )
    assert health.status is HealthReadiness.UNKNOWN
    if health_changes:
        health = replace(health, **health_changes)
    topology = CleanupTopologyChangeEvidence(
        operation,
        "55555555-5555-4555-8555-555555555555",
        "completed",
        tuple(item for item in queried if item not in joined_ids),
        joined_ids,
        cast(str, health.topology_digest),
        DIGEST,
        False,
        False,
        None,
    )
    if topology_changes:
        topology = replace(topology, **topology_changes)
    topology_digest = _topology_change_digest(topology)
    readiness = _readiness(inventory)
    host_id = HOST_1 if target == "scylla-ad-1-1" else HOST_2
    authorization = ScyllaCleanupAuthorization(
        operation_id=topology.operation_id,
        cluster_uuid=str(metadata.cluster_uuid),
        stable_id=target,
        host_id=host_id,
        observation_digest=observed.digest,
        inventory_digest=inventory.digest,
        trust_digest=cast(str, readiness.trust_digest),
        config_digest=DIGEST,
        storage_digest=DIGEST,
        health_digest=scylla_health_evidence_digest(health),
        health_captured_at=health.captured_at_end,
        topology_change_digest=topology_digest,
        repair_result_digest=topology.repair_result_digest,
        disk_headroom_digest=DIGEST,
        authorization_digest=DIGEST,
        confirmed_target=target,
        disk_headroom_passed=True,
        no_competing_operation=True,
        reviewed=True,
    )
    if authorization_changes:
        authorization = replace(authorization, **authorization_changes)
    payload = build_scylla_cleanup_payload(
        metadata,
        observed,
        inventory,
        readiness,
        health,
        topology,
        authorization,
        package_version=VERSION,
        timeout_seconds=7200,
    )
    return payload, authorization


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _result(payload: dict[str, object], status: str = "completed") -> dict[str, object]:
    success = status == "completed"
    not_predicted = status == "not-predicted"
    return {
        "blockers": [] if success or not_predicted else ["cleanup-timeout"],
        "command_evidence": (
            "exit-zero" if success else "not-run" if not_predicted else "unknown"
        ),
        "host_id_digest": _digest(cast(str, payload["host_id"])),
        "mutation_boundary": (
            "postchecks-passed"
            if success
            else "not-started"
            if not_predicted
            else "command-started"
        ),
        "pending_work_evidence": (
            "none" if success else "not-predicted" if not_predicted else "not-proven"
        ),
        "post_health_digest": DIGEST if success else None,
        "pre_health_digest": payload["health_digest"],
        "recovery_required": not success and not not_predicted,
        "repair_result_digest": payload["repair_result_digest"],
        "schema_version": SCYLLA_CLEANUP_SCHEMA_VERSION,
        "stable_id": payload["stable_id"],
        "status": status,
        "topology_change_digest": payload["topology_change_digest"],
    }


def _output(payload: dict[str, object], status: str = "completed") -> str:
    marker = base64.b64encode(json.dumps(_result(payload, status)).encode()).decode()
    changed = int(status not in {"not-predicted"})
    failed = int(status in {"failed", "not-predicted"})
    return (
        f"DSV_SCYLLA_CLEANUP_B64={marker}\nPLAY RECAP *****\n"
        f"{payload['stable_id']} : ok=8 changed={changed} unreachable=0 "
        f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


def test_valid_post_add_and_scale_cleanup_paths() -> None:
    payload, _ = _cleanup_context()
    assert payload["cleanup_command"] == ["/usr/bin/nodetool", "cleanup"]
    evidence = parse_scylla_cleanup_execution(
        _output(payload), expected_payload=payload, exit_code=0
    )
    assert evidence.status is ScyllaCleanupStatus.COMPLETED
    assert evidence.pending_work_evidence == "none"
    assert (
        scylla_cleanup_checkpoint_evidence(evidence).result is EvidenceResult.COMPLETED
    )

    scaled, _ = _cleanup_context(
        operation=CleanupOperation.SCALE_OUT,
        target="scylla-ad-1-1",
    )
    assert scaled["stable_id"] == "scylla-ad-1-1"

    repaired, _ = _cleanup_context(
        topology_changes={
            "repair_required": True,
            "repair_completed": True,
            "repair_result_digest": DIGEST,
        }
    )
    assert repaired["repair_result_digest"] == DIGEST


@pytest.mark.parametrize(
    "changes",
    [
        {"reviewed": False},
        {"confirmed_target": "scylla-ad-2-1"},
        {"disk_headroom_passed": False},
        {"no_competing_operation": False},
        {"prior_cleanup_started": True},
        {"host_id": HOST_2},
        {"health_captured_at": "2020-01-01T00:00:00Z"},
        {"config_digest": "invalid"},
        {"storage_digest": "invalid"},
        {"topology_change_digest": DIGEST},
    ],
)
def test_stale_target_disk_auth_and_competing_refused(
    changes: dict[str, object],
) -> None:
    with pytest.raises((StateConflictError, AnsibleError)):
        _cleanup_context(authorization_changes=changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"status": HealthReadiness.BLOCKED},
        {"schema_agreement": False},
        {"streaming_state": "active"},
        {"query_policy": "coordinator-known-identities"},
        {"queried_nodes": ("scylla-ad-1-1",)},
        {"topology_digest": None},
    ],
)
def test_health_topology_schema_and_streaming_refused(
    changes: dict[str, object],
) -> None:
    with pytest.raises(StateConflictError):
        _cleanup_context(health_changes=changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"status": "in-progress"},
        {"recovery_required": True},
        {"post_topology_digest": DIGEST},
        {"repair_required": True},
        {"repair_completed": True},
        {"repair_result_digest": DIGEST},
    ],
)
def test_incomplete_topology_and_repair_refused(changes: dict[str, object]) -> None:
    with pytest.raises((StateConflictError, AnsibleError)):
        _cleanup_context(topology_changes=changes)


def test_last_new_target_is_refused() -> None:
    with pytest.raises(StateConflictError):
        _cleanup_context(target="scylla-ad-2-1")
    with pytest.raises(StateConflictError):
        _cleanup_context(
            operation=CleanupOperation.SCALE_OUT,
            joined_ids=("scylla-ad-1-1", "scylla-ad-2-1"),
            target="scylla-ad-2-1",
        )


@pytest.mark.parametrize(("status", "exit_code"), [("failed", 2), ("not-predicted", 2)])
def test_failure_and_check_refusal(status: str, exit_code: int) -> None:
    payload, _ = _cleanup_context()
    evidence = parse_scylla_cleanup_execution(
        _output(payload, status), expected_payload=payload, exit_code=exit_code
    )
    assert evidence.status.value == status


def test_timeout_interruption_pending_and_post_health_fail_closed() -> None:
    payload, _ = _cleanup_context()
    interrupted = scylla_cleanup_interrupted_evidence(payload)
    assert interrupted.recovery_required
    assert interrupted.blockers == ("execution-interrupted",)
    assert interrupted.mutation_boundary is CleanupMutationBoundary.COMMAND_STARTED
    for blocker in ("pending-work", "post-health-failed", "command-failed"):
        value = _result(payload, "failed")
        value["blockers"] = [blocker]
        marker = base64.b64encode(json.dumps(value).encode()).decode()
        output = (
            f"DSV_SCYLLA_CLEANUP_B64={marker}\nPLAY RECAP *****\n"
            f"{payload['stable_id']} : ok=1 changed=1 unreachable=0 failed=1 "
            "skipped=0 rescued=0 ignored=0\n"
        )
        evidence = parse_scylla_cleanup_execution(
            output, expected_payload=payload, exit_code=2
        )
        assert evidence.recovery_required
    assert "10.0.0." not in _output(payload)


def test_registry_package_service_and_exact_command_contract() -> None:
    definition = get_playbook("scylla-cleanup")
    assert definition.source_available
    assert definition.check_mode is CheckMode.REFUSED
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert callable(AnsibleService.execute_scylla_cleanup)
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content/playbooks"
    text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            root / "scylla-cleanup.yml",
            root / "roles/scylla_cleanup/tasks/main.yml",
            root / "roles/scylla_cleanup/library/scylla_cleanup.py",
        )
    ).lower()
    for required in (
        "serial: 1",
        "any_errors_fatal: true",
        "become: true",
        '["/usr/bin/nodetool", "cleanup"]',
        '["/usr/bin/nodetool", "compactionstats"]',
        "shell=false",
        "supports_check_mode=false",
        "do not retry automatically",
    ):
        assert required in text
    for forbidden in (
        "ansible.builtin.shell",
        '["/usr/bin/nodetool", "cleanup",',
        "popen(",
        "start_new_session",
    ):
        assert forbidden not in text


def test_fake_service_refuses_any_limit_except_cleanup_target() -> None:
    _, authorization = _cleanup_context()

    class FakeBuilder:
        paths = object()

    class FakeLock:
        def assert_held_for(self, paths: object) -> None:
            assert paths is FakeBuilder.paths

    service = object.__new__(AnsibleService)
    service._builder = FakeBuilder()
    with pytest.raises(StateConflictError, match="exact authorized stable ID"):
        service.execute_scylla_cleanup(
            FakeLock(),
            cast(object, None),
            cast(object, None),
            cast(object, None),
            cast(object, None),
            cast(object, None),
            authorization,
            limit=("scylla-ad-2-1",),
            readiness=cast(object, None),
            package_version=VERSION,
            timeout_seconds=7200,
        )


def test_remote_module_poll_and_health_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _remote_module()
    expected = [
        {"datacenter": "dc1", "host_id": HOST_1, "rack": "rack1", "state": "UN"},
        {"datacenter": "dc1", "host_id": HOST_2, "rack": "rack2", "state": "UN"},
    ]
    status = (
        "Datacenter: dc1\n"
        f"UN 10.0.0.1 1 GB 1 50% {HOST_1} rack1\n"
        f"UN 10.0.0.2 1 GB 1 50% {HOST_2} rack2\n"
    )
    outputs = {
        "info": f"ID : {HOST_1}",
        "status": status,
        "describecluster": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa: [x]",
        "netstats": "Mode: NORMAL\nNot sending any streams.\nNot receiving any streams.",
        "compactionstats": "pending tasks: 0",
        "version": "ReleaseVersion: 2026.2.1",
    }
    monkeypatch.setattr(
        module, "_run", lambda argv, timeout: (0, outputs[argv[1]], False)
    )
    inspection = module._inspect_once(expected, HOST_1, "2026.2.1", 60)
    assert inspection["health_ok"]
    assert not inspection["pending_work"]
    outputs["compactionstats"] = "pending tasks: 1\ncleanup active"
    assert module._inspect_once(expected, HOST_1, "2026.2.1", 60)["pending_work"]
    outputs["status"] = status.replace("UN 10.0.0.2", "DN 10.0.0.2")
    assert not module._inspect_once(expected, HOST_1, "2026.2.1", 60)["health_ok"]


def _remote_module() -> object:
    path = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles/scylla_cleanup/library"
        / "scylla_cleanup.py"
    )
    spec = importlib.util.spec_from_file_location("cleanup_remote", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
