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
from test_ansible_scylla_replace_dead import _output as _replacement_output
from test_ansible_scylla_replace_dead import _replacement_context

from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_bootstrap import (
    MutationBoundary,
    ScyllaBootstrapEvidence,
    ScyllaBootstrapMode,
    ScyllaBootstrapStatus,
)
from scylla_vms.ansible.scylla_health import (
    HealthReadiness,
    parse_scylla_health_execution,
)
from scylla_vms.ansible.scylla_remove_live import scylla_health_evidence_digest
from scylla_vms.ansible.scylla_repair import (
    SCYLLA_REPAIR_SCHEMA_VERSION,
    RepairMutationBoundary,
    ScyllaRepairAuthorization,
    ScyllaRepairReason,
    ScyllaRepairStatus,
    _source_result_digest,
    build_scylla_repair_payload,
    parse_scylla_repair_execution,
    scylla_repair_checkpoint_evidence,
    scylla_repair_interrupted_evidence,
)
from scylla_vms.ansible.scylla_replace_dead import (
    RepairBasedNodeOperationsEvidence,
    parse_scylla_replace_dead_execution,
)
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.journal import EvidenceResult


def _repair_context(
    *,
    health_changes: dict[str, object] | None = None,
    authorization_changes: dict[str, object] | None = None,
    rbno_complete: bool = False,
    post_bootstrap: bool = False,
    version: str = VERSION,
) -> tuple[dict[str, object], ScyllaRepairAuthorization]:
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
    if post_bootstrap:
        source = ScyllaBootstrapEvidence(
            ScyllaBootstrapMode.JOIN_EXISTING,
            ScyllaBootstrapStatus.BOOTSTRAPPED,
            "scylla-ad-1-1",
            "active",
            DIGEST,
            _digest(HOST_1),
            "dc1",
            "rack1",
            "complete",
            (("authorization_digest", DIGEST),),
            MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED,
            False,
            (),
        )
    else:
        replacement_payload, _ = _replacement_context(
            rbno_changes=(
                {"enabled": True, "replacement_complete": True}
                if rbno_complete
                else None
            )
        )
        source = parse_scylla_replace_dead_execution(
            _replacement_output(replacement_payload),
            expected_payload=replacement_payload,
            exit_code=0,
        )
    rbno = RepairBasedNodeOperationsEvidence(rbno_complete, rbno_complete, DIGEST)
    source_digest = _source_result_digest(source)
    readiness = _readiness(inventory)
    authorization = ScyllaRepairAuthorization(
        operation_id="44444444-4444-4444-8444-444444444444",
        cluster_uuid=str(metadata.cluster_uuid),
        stable_id="scylla-ad-1-1",
        host_id=HOST_1,
        reason=(
            ScyllaRepairReason.POST_BOOTSTRAP
            if post_bootstrap
            else ScyllaRepairReason.POST_REPLACEMENT
        ),
        observation_digest=observed.digest,
        inventory_digest=inventory.digest,
        trust_digest=cast(str, readiness.trust_digest),
        config_digest=DIGEST,
        storage_digest=DIGEST,
        health_digest=scylla_health_evidence_digest(health),
        health_captured_at=health.captured_at_end,
        source_result_digest=source_digest,
        capacity_digest=DIGEST,
        quorum_digest=DIGEST,
        authorization_digest=DIGEST,
        confirmed_target="scylla-ad-1-1",
        capacity_passed=True,
        quorum_passed=True,
        no_competing_operation=True,
        reviewed=True,
    )
    if authorization_changes:
        authorization = replace(authorization, **authorization_changes)
    payload = build_scylla_repair_payload(
        metadata,
        observed,
        inventory,
        readiness,
        health,
        source,
        rbno,
        authorization,
        package_version=version,
        timeout_seconds=7200,
    )
    return payload, authorization


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _result(payload: dict[str, object], status: str = "completed") -> dict[str, object]:
    skipped = status == "rbno-skipped"
    success = status in {"completed", "rbno-skipped"}
    not_predicted = status == "not-predicted"
    return {
        "blockers": [] if success or not_predicted else ["repair-timeout"],
        "command_evidence": (
            "not-run"
            if skipped or not_predicted
            else "exit-zero"
            if success
            else "unknown"
        ),
        "completion_cryptographically_proven": skipped,
        "completion_evidence": (
            "rbno-enabled-complete"
            if skipped
            else "command-and-postchecks"
            if success
            else "not-predicted"
            if not_predicted
            else "not-proven"
        ),
        "explicit_review_required": status in {"completed", "failed"},
        "host_id_digest": _digest(cast(str, payload["host_id"])),
        "mutation_boundary": (
            "not-started"
            if skipped or not_predicted
            else "postchecks-passed"
            if success
            else "command-started"
        ),
        "post_health_digest": (
            payload["health_digest"] if skipped else DIGEST if success else None
        ),
        "pre_health_digest": payload["health_digest"],
        "reason": payload["reason"],
        "rbno_skip": payload["rbno_skip"],
        "recovery_required": not success and not not_predicted,
        "schema_version": SCYLLA_REPAIR_SCHEMA_VERSION,
        "source_result_digest": payload["source_result_digest"],
        "stable_id": payload["stable_id"],
        "status": status,
    }


def _output(payload: dict[str, object], status: str = "completed") -> str:
    marker = base64.b64encode(json.dumps(_result(payload, status)).encode()).decode()
    return (
        f"DSV_SCYLLA_REPAIR_B64={marker}\nPLAY RECAP *****\n"
        f"{payload['stable_id']} : ok=8 changed={int(status not in {'rbno-skipped', 'not-predicted'})} "
        f"unreachable=0 failed={int(status == 'failed' or status == 'not-predicted')} "
        "skipped=0 rescued=0 ignored=0\n"
    )


def test_direct_repair_and_strict_rbno_skip() -> None:
    payload, _ = _repair_context()
    assert payload["repair_command"] == ["/usr/bin/nodetool", "repair"]
    assert payload["rbno_skip"] is False
    evidence = parse_scylla_repair_execution(
        _output(payload), expected_payload=payload, exit_code=0
    )
    assert evidence.status is ScyllaRepairStatus.COMPLETED
    assert evidence.explicit_review_required
    assert not evidence.completion_cryptographically_proven
    assert (
        scylla_repair_checkpoint_evidence(evidence).result is EvidenceResult.COMPLETED
    )

    skipped, _ = _repair_context(rbno_complete=True)
    evidence = parse_scylla_repair_execution(
        _output(skipped, "rbno-skipped"), expected_payload=skipped, exit_code=0
    )
    assert evidence.status is ScyllaRepairStatus.RBNO_SKIPPED
    assert evidence.mutation_boundary is RepairMutationBoundary.NOT_STARTED
    bootstrap, _ = _repair_context(post_bootstrap=True)
    assert bootstrap["reason"] == "post-bootstrap"
    assert bootstrap["rbno_skip"] is False


@pytest.mark.parametrize(
    "changes",
    [
        {"reviewed": False},
        {"confirmed_target": "scylla-ad-2-1"},
        {"capacity_passed": False},
        {"quorum_passed": False},
        {"no_competing_operation": False},
        {"prior_repair_started": True},
        {"host_id": HOST_2},
        {"health_captured_at": "2020-01-01T00:00:00Z"},
        {"config_digest": "invalid"},
        {"storage_digest": "invalid"},
        {"source_result_digest": DIGEST},
    ],
)
def test_stale_target_auth_capacity_quorum_and_competing_refused(
    changes: dict[str, object],
) -> None:
    with pytest.raises((StateConflictError, AnsibleError)):
        _repair_context(authorization_changes=changes)


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
def test_every_full_health_topology_schema_streaming_gate_refused(
    changes: dict[str, object],
) -> None:
    with pytest.raises(StateConflictError):
        _repair_context(health_changes=changes)


def test_version_reason_and_incomplete_rbno_refused() -> None:
    with pytest.raises(StateConflictError):
        _repair_context(version="2026.2")
    with pytest.raises(StateConflictError):
        _repair_context(
            authorization_changes={"reason": ScyllaRepairReason.POST_BOOTSTRAP}
        )


@pytest.mark.parametrize(
    ("status", "exit_code"),
    [("failed", 2), ("not-predicted", 2)],
)
def test_failure_and_check_refusal(status: str, exit_code: int) -> None:
    payload, _ = _repair_context()
    evidence = parse_scylla_repair_execution(
        _output(payload, status), expected_payload=payload, exit_code=exit_code
    )
    assert evidence.status.value == status


def test_timeout_interruption_and_malformed_evidence_require_recovery() -> None:
    payload, _ = _repair_context()
    interrupted = scylla_repair_interrupted_evidence(payload)
    assert interrupted.recovery_required
    assert interrupted.blockers == ("execution-interrupted",)
    assert (
        "recovery-required"
        in scylla_repair_checkpoint_evidence(interrupted).summary_code
    )
    bad = _result(payload)
    bad["completion_evidence"] = "exit-code-only"
    marker = base64.b64encode(json.dumps(bad).encode()).decode()
    with pytest.raises(AnsibleError):
        parse_scylla_repair_execution(
            f"DSV_SCYLLA_REPAIR_B64={marker}\nPLAY RECAP *****\n"
            f"{payload['stable_id']} : ok=1 changed=1 unreachable=0 failed=0 "
            "skipped=0 rescued=0 ignored=0\n",
            expected_payload=payload,
            exit_code=0,
        )
    assert "10.0.0." not in _output(payload)


def test_registry_package_service_and_exact_command_contract() -> None:
    definition = get_playbook("scylla-repair")
    assert definition.source_available
    assert definition.check_mode is CheckMode.REFUSED
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert callable(AnsibleService.execute_scylla_repair)
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content/playbooks"
    text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            root / "scylla-repair.yml",
            root / "roles/scylla_repair/tasks/main.yml",
            root / "roles/scylla_repair/library/scylla_repair.py",
        )
    )
    for required in (
        "serial: 1",
        "any_errors_fatal: true",
        "become: true",
        '["/usr/bin/nodetool", "repair"]',
        '["/usr/bin/nodetool", "compactionstats"]',
        "shell=False",
        "supports_check_mode=False",
        "Do not retry automatically",
    ):
        assert required.lower() in text.lower()
    for forbidden in (
        "ansible.builtin.shell",
        '["/usr/bin/nodetool", "repair",',
        '"-pr"',
        "popen(",
        "start_new_session",
    ):
        assert forbidden not in text.lower()


def test_fake_service_refuses_any_limit_except_repair_target() -> None:
    _, authorization = _repair_context()

    class FakeBuilder:
        paths = object()

    class FakeLock:
        def assert_held_for(self, paths: object) -> None:
            assert paths is FakeBuilder.paths

    service = object.__new__(AnsibleService)
    service._builder = FakeBuilder()
    with pytest.raises(StateConflictError, match="exact authorized stable ID"):
        service.execute_scylla_repair(
            FakeLock(),
            cast(object, None),
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


def test_remote_module_success_timeout_post_health_and_pending_work(
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
        module,
        "_run",
        lambda argv, timeout: (0, outputs[argv[1]], False),
    )
    inspection = module._inspect(expected, HOST_1, "2026.2.1", 60)
    assert inspection["health_ok"]
    assert not inspection["pending_compactions"]
    outputs["compactionstats"] = "pending tasks: 1\nrepair active"
    pending = module._inspect(expected, HOST_1, "2026.2.1", 60)
    assert pending["pending_compactions"]
    assert pending["pending_repair"]
    outputs["status"] = status.replace("UN 10.0.0.2", "DN 10.0.0.2")
    assert not module._inspect(expected, HOST_1, "2026.2.1", 60)["health_ok"]


def _remote_module() -> object:
    path = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles/scylla_repair/library"
        / "scylla_repair.py"
    )
    spec = importlib.util.spec_from_file_location("repair_remote", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
