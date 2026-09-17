import base64
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
from scylla_vms.ansible.scylla_health import (
    HealthReadiness,
    parse_scylla_health_execution,
)
from scylla_vms.ansible.scylla_remove_live import (
    SCYLLA_REMOVE_LIVE_SCHEMA_VERSION,
    SafetyCheckStatus,
    ScyllaRemovalSafetyEvidence,
    ScyllaRemoveLiveAuthorization,
    ScyllaRemoveLiveStatus,
    _object_digest,
    build_scylla_remove_live_payload,
    parse_scylla_remove_live_execution,
    scylla_health_evidence_digest,
    scylla_remove_live_checkpoint_evidence,
    scylla_remove_live_interrupted_evidence,
)
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.journal import EvidenceResult


def _context_payload(
    *,
    safety_changes: dict[str, object] | None = None,
    authorization_changes: dict[str, object] | None = None,
    health_changes: dict[str, object] | None = None,
) -> tuple[dict[str, object], ScyllaRemoveLiveAuthorization]:
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
    health = parse_scylla_health_execution(
        stdout, expected_payload=health_payload, exit_code=rc
    )
    if health_changes:
        health = replace(health, **health_changes)
    target = health.nodes[0]
    survivors = (health.nodes[1].logical_id,)
    post_topology = [
        {
            "datacenter": health.nodes[1].datacenter,
            "host_id": health.nodes[1].host_id,
            "rack": health.nodes[1].rack,
            "state": "UN",
        }
    ]
    health_digest = scylla_health_evidence_digest(health)
    safety = ScyllaRemovalSafetyEvidence(
        captured_at=health.captured_at_end,
        health_digest=health_digest,
        surviving_stable_ids=survivors,
        intended_post_topology_digest=_object_digest(post_topology),
        replication=SafetyCheckStatus.PASSED,
        quorum=SafetyCheckStatus.PASSED,
        capacity=SafetyCheckStatus.PASSED,
        backup_policy=SafetyCheckStatus.PASSED,
    )
    if safety_changes:
        safety = replace(safety, **safety_changes)
    host = inventory.record.inventory.hosts[0]
    authorization = ScyllaRemoveLiveAuthorization(
        operation_id="11111111-1111-4111-8111-111111111111",
        cluster_uuid=str(metadata.cluster_uuid),
        target_logical_id=target.logical_id,
        target_host_id=cast(str, target.host_id),
        target_provider_id=host.provider_id,
        target_datacenter=target.datacenter,
        target_rack=target.rack,
        desired_removal_intent_digest=DIGEST,
        authorization_digest=DIGEST,
        health_generation=7,
        health_digest=health_digest,
        intended_post_topology_digest=safety.intended_post_topology_digest,
        confirmed_target=target.logical_id,
        allow_destructive=True,
        reviewed=True,
    )
    if authorization_changes:
        authorization = replace(authorization, **authorization_changes)
    payload = build_scylla_remove_live_payload(
        metadata,
        observed,
        inventory,
        _readiness(inventory),
        health,
        safety,
        authorization,
        config_digest=DIGEST,
        storage_digest=DIGEST,
        decommission_timeout_seconds=7200,
    )
    return payload, authorization


def _result(payload: dict[str, object], status: str = "removed") -> dict[str, object]:
    target = cast(dict[str, object], payload["target"])
    success = status == "removed"
    not_predicted = status == "not-predicted"
    return {
        "blockers": [] if success or not_predicted else ["recovery-required"],
        "command_boundary": (
            "completed" if success else "not-started" if not_predicted else "started"
        ),
        "decommission_command": ["/usr/bin/nodetool", "decommission"],
        "membership_boundary": (
            "target-absent"
            if success
            else "unchanged"
            if not_predicted
            else "may-have-changed"
        ),
        "post_health_digest": DIGEST if success else None,
        "postconditions": {
            name: "passed"
            if success
            else "not-performed"
            if not_predicted
            else "unknown"
            for name in (
                "expected-topology",
                "no-streaming",
                "schema-agreement",
                "survivors-up-normal",
                "target-absent",
            )
        },
        "pre_health_digest": payload["pre_health_digest"],
        "recovery_required": not success and not not_predicted,
        "schema_version": SCYLLA_REMOVE_LIVE_SCHEMA_VERSION,
        "status": status,
        "target_host_id_digest": "sha256:"
        + __import__("hashlib")
        .sha256(cast(str, target["host_id"]).encode())
        .hexdigest(),
        "target_logical_id": target["logical_id"],
    }


def _execution_output(payload: dict[str, object], status: str = "removed") -> str:
    encoded = base64.b64encode(
        json.dumps(_result(payload, status), sort_keys=True).encode()
    ).decode()
    failed = status != "removed"
    changed = status != "not-predicted"
    target = cast(dict[str, object], payload["target"])
    return (
        f'{{"msg":"DSV_SCYLLA_REMOVE_LIVE_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"{target['logical_id']} : ok=8 changed={int(changed)} unreachable=0 "
        f"failed={int(failed)} skipped=0 rescued=0 ignored=0\n"
    )


def test_valid_payload_binds_target_health_safety_and_post_topology() -> None:
    payload, authorization = _context_payload()
    target = cast(dict[str, object], payload["target"])
    assert target["logical_id"] == authorization.target_logical_id
    assert target["host_id"] == authorization.target_host_id
    assert payload["surviving_stable_ids"] == ["scylla-ad-2-1"]
    assert payload["coordinator_stable_id"] == "scylla-ad-2-1"
    assert payload["schema_version"] == SCYLLA_REMOVE_LIVE_SCHEMA_VERSION
    assert set(cast(dict[str, str], payload["prerequisite_digests"])) == {
        "config_digest",
        "inventory_digest",
        "observation_digest",
        "safety_evidence_digest",
        "storage_digest",
        "trust_digest",
    }


@pytest.mark.parametrize(
    "field",
    ["replication", "quorum", "capacity", "backup_policy"],
)
@pytest.mark.parametrize(
    "status",
    [
        SafetyCheckStatus.UNKNOWN,
        SafetyCheckStatus.NOT_PERFORMED,
        SafetyCheckStatus.FAILED,
    ],
)
def test_unknown_or_failed_independent_safety_never_passes(
    field: str, status: SafetyCheckStatus
) -> None:
    with pytest.raises(StateConflictError):
        _context_payload(safety_changes={field: status})


@pytest.mark.parametrize(
    "changes",
    [
        {"reviewed": False},
        {"allow_destructive": False},
        {"confirmed_target": "scylla-ad-2-1"},
        {"target_host_id": HOST_2},
        {"target_provider_id": "ocid1.instance.oc1.iad.wrong"},
        {"target_datacenter": "wrong"},
        {"target_rack": "wrong"},
        {"health_digest": "sha256:" + "b" * 64},
        {"intended_post_topology_digest": "sha256:" + "b" * 64},
        {"prior_command_started": True},
    ],
)
def test_target_authorization_and_retry_mismatches_are_refused(
    changes: dict[str, object],
) -> None:
    with pytest.raises((StateConflictError, AnsibleError)):
        _context_payload(authorization_changes=changes)


def test_stale_and_unhealthy_health_are_refused() -> None:
    with pytest.raises(StateConflictError):
        _context_payload(safety_changes={"captured_at": "2026-09-17T01:00:00Z"})
    with pytest.raises(StateConflictError):
        _context_payload(health_changes={"blockers": ("streaming-active",)})
    with pytest.raises(StateConflictError):
        _context_payload(health_changes={"status": HealthReadiness.BLOCKED})


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("removed", ScyllaRemoveLiveStatus.REMOVED),
        ("failed", ScyllaRemoveLiveStatus.FAILED),
        ("not-predicted", ScyllaRemoveLiveStatus.NOT_PREDICTED),
    ],
)
def test_result_contract_success_failure_interruption_and_check_refusal(
    status: str, expected: ScyllaRemoveLiveStatus
) -> None:
    payload, _ = _context_payload()
    result = parse_scylla_remove_live_execution(
        _execution_output(payload, status),
        expected_payload=payload,
        exit_code=0 if status == "removed" else 2,
    )
    assert result.status is expected
    assert result.decommission_command == ("/usr/bin/nodetool", "decommission")
    assert result.recovery_required is (status == "failed")
    assert "10.0.0." not in repr(result)
    if status != "not-predicted":
        checkpoint = scylla_remove_live_checkpoint_evidence(result)
        assert checkpoint.result is (
            EvidenceResult.COMPLETED if status == "removed" else EvidenceResult.FAILED
        )


def test_interruption_without_result_is_conservatively_journaled() -> None:
    payload, _ = _context_payload()
    evidence = scylla_remove_live_interrupted_evidence(payload)
    assert evidence.command_boundary.value == "started"
    assert evidence.membership_boundary.value == "may-have-changed"
    assert evidence.blockers == ("execution-interrupted",)
    assert evidence.recovery_required
    checkpoint = scylla_remove_live_checkpoint_evidence(evidence)
    assert checkpoint.result is EvidenceResult.FAILED
    assert checkpoint.summary_code == "scylla-decommission-started-recovery-required"


def test_parser_refuses_postcondition_disagreement_and_raw_or_malformed_output() -> (
    None
):
    payload, _ = _context_payload()
    bad = _result(payload)
    cast(dict[str, str], bad["postconditions"])["target-absent"] = "failed"
    encoded = base64.b64encode(json.dumps(bad, sort_keys=True).encode()).decode()
    target = cast(dict[str, object], payload["target"])
    output = (
        f"DSV_SCYLLA_REMOVE_LIVE_B64={encoded}\nPLAY RECAP *****\n"
        f"{target['logical_id']} : ok=1 changed=1 unreachable=0 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    for value in ("", output, "x" * (512 * 1024 + 1)):
        with pytest.raises(AnsibleError):
            parse_scylla_remove_live_execution(
                value, expected_payload=payload, exit_code=0
            )


def test_registry_package_and_role_enforce_exact_destructive_boundary() -> None:
    definition = get_playbook("scylla-remove-live")
    assert definition.source_available
    assert definition.check_mode is CheckMode.REFUSED
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert callable(AnsibleService.execute_scylla_remove_live)
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content/playbooks"
    text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            root / "scylla-remove-live.yml",
            root / "roles/scylla_remove_live/tasks/main.yml",
            root / "roles/scylla_remove_live/library/scylla_remove_live.py",
        )
    )
    assert "gather_facts: true" in text
    assert "become: true" in text
    assert "serial: 1" in text
    assert "any_errors_fatal: true" in text
    assert '["/usr/bin/nodetool", "decommission"]' in text
    assert "shell=False" in text
    assert "ansible.builtin.shell" not in text
    for forbidden in ("removenode", "terraform", "oci_core", "wipefs"):
        assert forbidden not in text.lower()


def test_remote_module_uses_exact_argv_and_no_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles/scylla_remove_live/library"
        / "scylla_remove_live.py"
    )
    spec = importlib.util.spec_from_file_location("remove_live_remote", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls: list[tuple[list[str], dict[str, object]]] = []

    class Completed:
        returncode = 0
        stdout = b""

    def fake_run(argv: list[str], **kwargs: object) -> Completed:
        calls.append((argv, kwargs))
        return Completed()

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    module._run(["/usr/bin/nodetool", "decommission"], 7200)
    assert calls == [
        (
            ["/usr/bin/nodetool", "decommission"],
            {
                "capture_output": True,
                "check": False,
                "shell": False,
                "timeout": 7200,
            },
        )
    ]


def test_remote_postcheck_proves_success_and_times_out_on_disagreement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles/scylla_remove_live/library"
        / "scylla_remove_live.py"
    )
    spec = importlib.util.spec_from_file_location("remove_live_postcheck", path)
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
    healthy = {
        "command_ok": True,
        "host_id": HOST_2,
        "ring": topology,
        "schema_agreed": True,
        "streaming_complete": True,
    }
    monkeypatch.setattr(module, "_inspect", lambda timeout: healthy)
    success = module._postcheck(topology, HOST_1, module._digest(topology), 1)
    assert success["complete"] is True
    assert success["post_health_digest"].startswith("sha256:")

    disagreement = {**healthy, "ring": [dict(topology[0], state="DN")]}
    monkeypatch.setattr(module, "_inspect", lambda timeout: disagreement)
    times = [0.0, 0.0, 1.0, 1.0]
    monkeypatch.setattr(
        module.time, "monotonic", lambda: times.pop(0) if times else 1.0
    )
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    failed = module._postcheck(topology, HOST_1, module._digest(topology), 1)
    assert failed["complete"] is False
    assert failed["postconditions"]["expected-topology"] == "failed"
    assert failed["postconditions"]["survivors-up-normal"] == "unknown"
