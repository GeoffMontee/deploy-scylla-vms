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

from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_health import parse_scylla_health_execution
from scylla_vms.ansible.scylla_remove_dead import (
    SCYLLA_REMOVE_DEAD_SCHEMA_VERSION,
    DeadTargetEvidence,
    ReachabilityStatus,
    ScyllaRemoveDeadAuthorization,
    ScyllaRemoveDeadStatus,
    SurvivorRingView,
    _object_digest,
    build_scylla_remove_dead_payload,
    parse_scylla_remove_dead_execution,
    scylla_remove_dead_checkpoint_evidence,
    scylla_remove_dead_interrupted_evidence,
)
from scylla_vms.ansible.scylla_remove_live import (
    SafetyCheckStatus,
    ScyllaRemovalSafetyEvidence,
    scylla_health_evidence_digest,
)
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.journal import EvidenceResult


def _context_payload(
    *,
    target_changes: dict[str, object] | None = None,
    authorization_changes: dict[str, object] | None = None,
    health_changes: dict[str, object] | None = None,
    safety_changes: dict[str, object] | None = None,
) -> tuple[dict[str, object], ScyllaRemoveDeadAuthorization]:
    _, metadata, observed, _, _, _ = _context()
    health_payload, inventory = _health_context(multi=True)
    queried = tuple(cast(list[str], health_payload["queried_nodes"]))
    ring = _ring(include_peer=True)
    stdout, rc = _stdout(
        [
            _health_view("scylla-ad-1-1", HOST_1, ring),
            _health_view("scylla-ad-2-1", HOST_2, ring),
        ],
        queried,
    )
    full_health = parse_scylla_health_execution(
        stdout, expected_payload=health_payload, exit_code=rc
    )
    survivor = full_health.nodes[1]
    survivor_health = replace(
        full_health,
        query_policy="dead-target-survivor-quorum",
        queried_nodes=(survivor.logical_id,),
        nodes=(survivor,),
    )
    if health_changes:
        survivor_health = replace(survivor_health, **health_changes)
    target_host = inventory.record.inventory.hosts[0]
    coordinator_host = inventory.record.inventory.hosts[1]
    ring_digest = "sha256:" + "a" * 64
    dead_target = DeadTargetEvidence(
        captured_at=survivor_health.captured_at_end,
        target_stable_id=target_host.logical_id,
        target_host_id=HOST_1,
        target_provider_id=target_host.provider_id,
        provider_identity_unchanged=True,
        ssh_reachability=ReachabilityStatus.UNREACHABLE,
        service_reachability=ReachabilityStatus.UNREACHABLE,
        provider_lifecycle_reachability=ReachabilityStatus.UNREACHABLE,
        survivor_views=(
            SurvivorRingView(
                coordinator_host.logical_id,
                HOST_2,
                HOST_1,
                "DN",
                ring_digest,
                True,
                True,
            ),
        ),
    )
    if target_changes:
        dead_target = replace(dead_target, **target_changes)
    post_topology = [
        {
            "datacenter": survivor.datacenter,
            "host_id": survivor.host_id,
            "rack": survivor.rack,
            "state": "UN",
        }
    ]
    health_digest = scylla_health_evidence_digest(survivor_health)
    safety = ScyllaRemovalSafetyEvidence(
        captured_at=survivor_health.captured_at_end,
        health_digest=health_digest,
        surviving_stable_ids=(survivor.logical_id,),
        intended_post_topology_digest=_object_digest(post_topology),
        replication=SafetyCheckStatus.PASSED,
        quorum=SafetyCheckStatus.PASSED,
        capacity=SafetyCheckStatus.PASSED,
        backup_policy=SafetyCheckStatus.PASSED,
    )
    if safety_changes:
        safety = replace(safety, **safety_changes)
    readiness = _readiness(inventory)
    authorization = ScyllaRemoveDeadAuthorization(
        operation_id="11111111-1111-4111-8111-111111111111",
        cluster_uuid=str(metadata.cluster_uuid),
        target_stable_id=target_host.logical_id,
        target_host_id=HOST_1,
        target_provider_id=target_host.provider_id,
        coordinator_stable_id=coordinator_host.logical_id,
        health_digest=health_digest,
        observation_digest=observed.digest,
        inventory_digest=inventory.digest,
        trust_digest=cast(str, readiness.trust_digest),
        intended_post_topology_digest=safety.intended_post_topology_digest,
        authorization_digest=DIGEST,
        confirmed_target=target_host.logical_id,
        allow_destructive=True,
        reviewed=True,
    )
    if authorization_changes:
        authorization = replace(authorization, **authorization_changes)
    payload = build_scylla_remove_dead_payload(
        metadata,
        observed,
        inventory,
        readiness,
        survivor_health,
        dead_target,
        safety,
        authorization,
        timeout_seconds=7200,
    )
    return payload, authorization


def _result(payload: dict[str, object], status: str = "removed") -> dict[str, object]:
    target = cast(dict[str, object], payload["target"])
    coordinator = cast(dict[str, object], payload["coordinator"])
    success = status == "removed"
    not_predicted = status == "not-predicted"
    return {
        "blockers": [] if success or not_predicted else ["recovery-required"],
        "command_boundary": (
            "completed" if success else "not-started" if not_predicted else "started"
        ),
        "coordinator_host_id_digest": _digest(cast(str, coordinator["host_id"])),
        "coordinator_stable_id": coordinator["stable_id"],
        "mutation_boundary": (
            "target-absent"
            if success
            else "unchanged"
            if not_predicted
            else "may-have-changed"
        ),
        "post_evidence_digest": DIGEST if success else None,
        "postconditions": {
            name: "passed"
            if success
            else "not-performed"
            if not_predicted
            else "unknown"
            for name in (
                "expected-topology",
                "no-streaming",
                "removal-finished",
                "schema-agreement",
                "survivors-up-normal",
                "target-absent",
            )
        },
        "pre_evidence_digest": payload["pre_evidence_digest"],
        "recovery_required": not success and not not_predicted,
        "removal_command": [
            "/usr/bin/nodetool",
            "removenode",
            target["host_id"],
        ],
        "removal_status": "complete" if success else "not-performed",
        "schema_version": SCYLLA_REMOVE_DEAD_SCHEMA_VERSION,
        "status": status,
        "status_command": ["/usr/bin/nodetool", "removenode", "status"],
        "target_host_id_digest": _digest(cast(str, target["host_id"])),
        "target_stable_id": target["stable_id"],
    }


def _output(payload: dict[str, object], status: str = "removed") -> str:
    encoded = base64.b64encode(
        json.dumps(_result(payload, status), sort_keys=True).encode()
    ).decode()
    coordinator = cast(dict[str, object], payload["coordinator"])
    return (
        f'{{"msg":"DSV_SCYLLA_REMOVE_DEAD_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"{coordinator['stable_id']} : ok=9 changed={int(status != 'not-predicted')} "
        f"unreachable=0 failed={int(status != 'removed')} skipped=0 rescued=0 "
        "ignored=0\n"
    )


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def test_payload_runs_only_on_coordinator_and_binds_dead_target() -> None:
    payload, authorization = _context_payload()
    target = cast(dict[str, object], payload["target"])
    coordinator = cast(dict[str, object], payload["coordinator"])
    assert target["stable_id"] == authorization.target_stable_id
    assert coordinator["stable_id"] == authorization.coordinator_stable_id
    assert target["stable_id"] != coordinator["stable_id"]
    assert payload["required_survivor_quorum"] == [coordinator["stable_id"]]
    assert payload["schema_version"] == SCYLLA_REMOVE_DEAD_SCHEMA_VERSION


@pytest.mark.parametrize(
    "field",
    [
        "ssh_reachability",
        "service_reachability",
        "provider_lifecycle_reachability",
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        ReachabilityStatus.REACHABLE,
        ReachabilityStatus.AMBIGUOUS,
        ReachabilityStatus.NOT_PERFORMED,
    ],
)
def test_reachable_or_ambiguous_target_is_refused(
    field: str, value: ReachabilityStatus
) -> None:
    with pytest.raises(StateConflictError):
        _context_payload(target_changes={field: value})


@pytest.mark.parametrize(
    "changes",
    [
        {"provider_identity_unchanged": False},
        {"target_host_id": HOST_2},
        {"target_provider_id": "ocid1.instance.oc1.iad.changed"},
        {"active_membership_operation": "replace"},
        {"survivor_views": ()},
    ],
)
def test_identity_view_and_active_operation_conflicts_are_refused(
    changes: dict[str, object],
) -> None:
    with pytest.raises((StateConflictError, AnsibleError)):
        _context_payload(target_changes=changes)


@pytest.mark.parametrize(
    "field",
    ["replication", "quorum", "capacity", "backup_policy"],
)
def test_every_independent_safety_gate_must_pass(field: str) -> None:
    with pytest.raises(StateConflictError):
        _context_payload(safety_changes={field: SafetyCheckStatus.UNKNOWN})


@pytest.mark.parametrize(
    "changes",
    [
        {"reviewed": False},
        {"allow_destructive": False},
        {"confirmed_target": "scylla-ad-2-1"},
        {"coordinator_stable_id": "scylla-ad-1-1"},
        {"target_host_id": HOST_2},
        {"prior_command_started": True},
        {"trust_digest": "sha256:" + "b" * 64},
    ],
)
def test_narrow_authorization_and_coordinator_failures_are_refused(
    changes: dict[str, object],
) -> None:
    with pytest.raises((StateConflictError, AnsibleError, StopIteration)):
        _context_payload(authorization_changes=changes)


def test_unhealthy_survivor_is_refused() -> None:
    with pytest.raises(StateConflictError):
        _context_payload(health_changes={"schema_agreement": False})
    with pytest.raises(StateConflictError):
        _context_payload(health_changes={"streaming_state": "active"})


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("removed", ScyllaRemoveDeadStatus.REMOVED),
        ("failed", ScyllaRemoveDeadStatus.FAILED),
        ("not-predicted", ScyllaRemoveDeadStatus.NOT_PREDICTED),
    ],
)
def test_result_success_failure_and_check_refusal(
    status: str, expected: ScyllaRemoveDeadStatus
) -> None:
    payload, _ = _context_payload()
    result = parse_scylla_remove_dead_execution(
        _output(payload, status),
        expected_payload=payload,
        exit_code=0 if status == "removed" else 2,
    )
    assert result.status is expected
    assert result.removal_command == (
        "/usr/bin/nodetool",
        "removenode",
        HOST_1,
    )
    assert result.status_command == (
        "/usr/bin/nodetool",
        "removenode",
        "status",
    )
    if status != "not-predicted":
        checkpoint = scylla_remove_dead_checkpoint_evidence(result)
        assert checkpoint.result is (
            EvidenceResult.COMPLETED if status == "removed" else EvidenceResult.FAILED
        )


def test_interruption_is_journaled_and_never_authorizes_retry() -> None:
    payload, _ = _context_payload()
    result = scylla_remove_dead_interrupted_evidence(payload)
    assert result.command_boundary.value == "started"
    assert result.mutation_boundary.value == "may-have-changed"
    assert result.recovery_required
    assert result.blockers == ("execution-interrupted",)
    assert (
        scylla_remove_dead_checkpoint_evidence(result).summary_code
        == "scylla-removenode-started-recovery-required"
    )


def test_parser_refuses_postcondition_disagreement_and_malformed_output() -> None:
    payload, _ = _context_payload()
    bad = _result(payload)
    cast(dict[str, str], bad["postconditions"])["target-absent"] = "failed"
    encoded = base64.b64encode(json.dumps(bad, sort_keys=True).encode()).decode()
    coordinator = cast(dict[str, object], payload["coordinator"])
    output = (
        f"DSV_SCYLLA_REMOVE_DEAD_B64={encoded}\nPLAY RECAP *****\n"
        f"{coordinator['stable_id']} : ok=1 changed=1 unreachable=0 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    for value in ("", output, "x" * (512 * 1024 + 1)):
        with pytest.raises(AnsibleError):
            parse_scylla_remove_dead_execution(
                value, expected_payload=payload, exit_code=0
            )


def test_registry_package_and_role_enforce_dead_target_boundary() -> None:
    definition = get_playbook("scylla-remove-dead")
    assert definition.source_available
    assert definition.check_mode is CheckMode.REFUSED
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert callable(AnsibleService.execute_scylla_remove_dead)
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content/playbooks"
    text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            root / "scylla-remove-dead.yml",
            root / "roles/scylla_remove_dead/tasks/main.yml",
            root / "roles/scylla_remove_dead/library/scylla_remove_dead.py",
        )
    )
    assert "gather_facts: true" in text
    assert "become: true" in text
    assert "serial: 1" in text
    assert "any_errors_fatal: true" in text
    assert '["/usr/bin/nodetool", "removenode", target_host_id]' in text
    assert '["/usr/bin/nodetool", "removenode", "status"]' in text
    assert "shell=False" in text
    assert "ansible.builtin.shell" not in text
    for forbidden in ("terraform", "oci_core", "wipefs", "decommission"):
        assert forbidden not in text.lower()


def test_remote_module_exact_argv_status_success_timeout_and_no_force(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles/scylla_remove_dead/library"
        / "scylla_remove_dead.py"
    )
    spec = importlib.util.spec_from_file_location("remove_dead_remote", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls: list[list[str]] = []

    class Completed:
        returncode = 0
        stdout = b"No token removals in process.\n"

    def fake_run(argv: list[str], **kwargs: object) -> Completed:
        assert kwargs["shell"] is False
        calls.append(argv)
        return Completed()

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    module._run(["/usr/bin/nodetool", "removenode", HOST_1], 10)
    module._run(["/usr/bin/nodetool", "removenode", "status"], 10)
    assert calls == [
        ["/usr/bin/nodetool", "removenode", HOST_1],
        ["/usr/bin/nodetool", "removenode", "status"],
    ]
    assert all("force" not in item for call in calls for item in call)


def test_remote_postcheck_proves_success_and_times_out_without_force(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles/scylla_remove_dead/library"
        / "scylla_remove_dead.py"
    )
    spec = importlib.util.spec_from_file_location("remove_dead_postcheck", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    topology = [
        {
            "datacenter": "dc1",
            "host_id": HOST_2,
            "rack": "rack2",
            "state": "UN",
        }
    ]
    inspection = {
        "command_ok": True,
        "host_id": HOST_2,
        "ring": topology,
        "schema_agreed": True,
        "streaming_complete": True,
    }
    commands: list[list[str]] = []

    def complete(argv: list[str], timeout: int) -> tuple[int, str]:
        commands.append(argv)
        return 0, "No token removals in process.\n"

    monkeypatch.setattr(module, "_run", complete)
    monkeypatch.setattr(module, "_inspect", lambda target, timeout: inspection)
    result = module._postcheck(topology, HOST_1, module._digest(topology), 1)
    assert result["complete"] is True
    assert result["removal_status"] == "complete"
    assert commands == [["/usr/bin/nodetool", "removenode", "status"]]

    monkeypatch.setattr(module, "_run", lambda argv, timeout: (0, "Removal active"))
    times = [0.0, 0.0, 1.0, 1.0]
    monkeypatch.setattr(
        module.time, "monotonic", lambda: times.pop(0) if times else 1.0
    )
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    timed_out = module._postcheck(topology, HOST_1, module._digest(topology), 1)
    assert timed_out["complete"] is False
    assert timed_out["postconditions"]["removal-finished"] == "unknown"
