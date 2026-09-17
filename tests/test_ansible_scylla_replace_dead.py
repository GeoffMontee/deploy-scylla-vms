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
from test_ansible_scylla_configure import _stdout as _configure_stdout
from test_ansible_scylla_health import HOST_1, HOST_2, _health_context, _ring, _stdout
from test_ansible_scylla_health import _view as _health_view
from test_ansible_scylla_install import VERSION
from test_ansible_scylla_install import _context as _install_context
from test_ansible_scylla_install import _stdout as _install_stdout

from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_configure import parse_scylla_configure_execution
from scylla_vms.ansible.scylla_health import parse_scylla_health_execution
from scylla_vms.ansible.scylla_install import parse_scylla_install_execution
from scylla_vms.ansible.scylla_remove_dead import (
    ReachabilityStatus,
    SurvivorRingView,
)
from scylla_vms.ansible.scylla_remove_live import (
    SafetyCheckStatus,
    ScyllaRemovalSafetyEvidence,
    scylla_health_evidence_digest,
)
from scylla_vms.ansible.scylla_replace_dead import (
    SCYLLA_REPLACE_DEAD_SCHEMA_VERSION,
    RepairBasedNodeOperationsEvidence,
    ReplacementMutationBoundary,
    ReplacementTargetEvidence,
    ScyllaReplaceDeadAuthorization,
    ScyllaReplaceDeadStatus,
    _object_digest,
    build_scylla_replace_dead_payload,
    parse_scylla_replace_dead_execution,
    scylla_replace_dead_checkpoint_evidence,
    scylla_replace_dead_interrupted_evidence,
)
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.journal import EvidenceResult

OLD_PROVIDER = "ocid1.instance.oc1.iad.deadold"


def _replacement_context(
    *,
    target_changes: dict[str, object] | None = None,
    safety_changes: dict[str, object] | None = None,
    rbno_changes: dict[str, object] | None = None,
    authorization_changes: dict[str, object] | None = None,
    storage_changes: dict[str, object] | None = None,
    configure_changes: dict[str, object] | None = None,
    version: str = VERSION,
) -> tuple[dict[str, object], ScyllaReplaceDeadAuthorization]:
    configure_payload, metadata, observed, _, _, storage = _context()
    configure = parse_scylla_configure_execution(
        _configure_stdout(configure_payload),
        expected_payload=configure_payload,
        exit_code=0,
    )
    install_payload, _ = _install_context()
    install = parse_scylla_install_execution(
        _install_stdout(install_payload),
        expected_payload=install_payload,
        exit_code=0,
    )
    health_payload, inventory = _health_context(multi=True)
    queried = tuple(cast(list[str], health_payload["queried_nodes"]))
    stdout, rc = _stdout(
        [
            _health_view("scylla-ad-1-1", HOST_1, _ring(include_peer=True)),
            _health_view("scylla-ad-2-1", HOST_2, _ring(include_peer=True)),
        ],
        queried,
    )
    full_health = parse_scylla_health_execution(
        stdout, expected_payload=health_payload, exit_code=rc
    )
    survivor = full_health.nodes[1]
    health = replace(
        full_health,
        query_policy="replacement-survivor-quorum",
        queried_nodes=(survivor.logical_id,),
        nodes=(survivor,),
    )
    current_target = inventory.record.inventory.hosts[0]
    current_survivor = inventory.record.inventory.hosts[1]
    target = ReplacementTargetEvidence(
        captured_at=health.captured_at_end,
        stable_id=current_target.logical_id,
        old_host_id=HOST_1,
        old_provider_id=OLD_PROVIDER,
        new_provider_id=current_target.provider_id,
        ssh_reachability=ReachabilityStatus.UNREACHABLE,
        service_reachability=ReachabilityStatus.UNREACHABLE,
        provider_lifecycle_reachability=ReachabilityStatus.UNREACHABLE,
        survivor_views=(
            SurvivorRingView(
                current_survivor.logical_id,
                HOST_2,
                HOST_1,
                "DN",
                DIGEST,
                True,
                True,
            ),
        ),
        mapping_reviewed=True,
        replacement_absent_from_ring=True,
    )
    if target_changes:
        target = replace(target, **target_changes)
    health_digest = scylla_health_evidence_digest(health)
    safety = ScyllaRemovalSafetyEvidence(
        captured_at=health.captured_at_end,
        health_digest=health_digest,
        surviving_stable_ids=(current_survivor.logical_id,),
        intended_post_topology_digest=DIGEST,
        replication=SafetyCheckStatus.PASSED,
        quorum=SafetyCheckStatus.PASSED,
        capacity=SafetyCheckStatus.PASSED,
        backup_policy=SafetyCheckStatus.PASSED,
    )
    if safety_changes:
        safety = replace(safety, **safety_changes)
    rbno = RepairBasedNodeOperationsEvidence(False, False, DIGEST)
    if rbno_changes:
        rbno = replace(rbno, **rbno_changes)
    if storage_changes:
        storage = replace(storage, **storage_changes)
    if configure_changes:
        configure = replace(configure, **configure_changes)
    readiness = _readiness(inventory)
    storage_digest = _object_digest(
        {
            "backend": storage.backend,
            "blockers": list(storage.blockers),
            "checks": [(item.name, item.status.value) for item in storage.checks],
            "devices": list(storage.devices),
            "layout": storage.layout,
            "logical_id": storage.logical_id,
            "provenance": dict(storage.provenance),
            "readiness_for_scylla": storage.readiness_for_scylla,
        }
    )
    authorization = ScyllaReplaceDeadAuthorization(
        operation_id="33333333-3333-4333-8333-333333333333",
        cluster_uuid=str(metadata.cluster_uuid),
        stable_id=current_target.logical_id,
        old_host_id=HOST_1,
        old_provider_id=OLD_PROVIDER,
        new_provider_id=current_target.provider_id,
        observation_digest=observed.digest,
        inventory_digest=inventory.digest,
        trust_digest=cast(str, readiness.trust_digest),
        storage_digest=storage_digest,
        config_digest=configure.config_digest,
        health_digest=health_digest,
        topology_digest=DIGEST,
        intended_post_state_digest=DIGEST,
        authorization_digest=DIGEST,
        config_file_digests=tuple(
            sorted(cast(dict[str, str], configure_payload["file_digests"]).items())
        ),
        confirmed_target=current_target.logical_id,
        allow_destructive=True,
        reviewed=True,
    )
    if authorization_changes:
        authorization = replace(authorization, **authorization_changes)
    payload = build_scylla_replace_dead_payload(
        metadata,
        observed,
        inventory,
        readiness,
        health,
        target,
        safety,
        storage,
        install,
        configure,
        rbno,
        authorization,
        package_version=version,
        timeout_seconds=7200,
    )
    return payload, authorization


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _result(payload: dict[str, object], status: str = "replaced") -> dict[str, object]:
    success = status == "replaced"
    not_predicted = status == "not-predicted"
    return {
        "blockers": [] if success or not_predicted else ["replacement-timeout"],
        "config_digest": payload["config_digest"],
        "intended_post_state_digest": payload["intended_post_state_digest"],
        "mutation_boundary": (
            "membership-proven"
            if success
            else "not-started"
            if not_predicted
            else "membership-may-have-changed"
        ),
        "new_host_id_digest": _digest(HOST_2) if success else None,
        "new_provider_id_digest": payload["new_provider_id_digest"],
        "old_host_id_digest": _digest(cast(str, payload["old_host_id"])),
        "old_provider_id_digest": payload["old_provider_id_digest"],
        "post_evidence_digest": DIGEST if success else None,
        "postconditions": {
            name: (
                "passed" if success else "not-performed" if not_predicted else "unknown"
            )
            for name in (
                "expected-topology",
                "new-host-id",
                "no-streaming",
                "old-host-id-absent",
                "replacement-up-normal",
                "schema-agreement",
            )
        },
        "pre_evidence_digest": payload["pre_evidence_digest"],
        "rbno_status": (
            "enabled-complete"
            if cast(dict[str, object], payload["rbno"])["complete"]
            else "repair-required"
        ),
        "recovery_required": not success and not not_predicted,
        "repair_required": payload["repair_required"],
        "replacement_key_retained": success,
        "ring_status": "UN"
        if success
        else "not-checked"
        if not_predicted
        else "unknown",
        "schema_version": SCYLLA_REPLACE_DEAD_SCHEMA_VERSION,
        "stable_id": payload["stable_id"],
        "status": status,
        "storage_digest": payload["storage_digest"],
        "streaming_status": (
            "complete" if success else "not-checked" if not_predicted else "unknown"
        ),
        "topology_digest": payload["topology_digest"],
    }


def _output(payload: dict[str, object], status: str = "replaced") -> str:
    encoded = base64.b64encode(
        json.dumps(_result(payload, status), sort_keys=True).encode()
    ).decode()
    return (
        f"DSV_SCYLLA_REPLACE_DEAD_B64={encoded}\nPLAY RECAP *****\n"
        f"{payload['stable_id']} : ok=12 changed={int(status != 'not-predicted')} "
        f"unreachable=0 failed={int(status != 'replaced')} skipped=0 rescued=0 "
        "ignored=0\n"
    )


def test_valid_replacement_and_rbno_variants_bind_exact_transition() -> None:
    payload, authorization = _replacement_context()
    assert payload["stable_id"] == authorization.stable_id
    assert payload["repair_required"] is True
    assert payload["old_provider_id_digest"] != payload["new_provider_id_digest"]
    rbno_payload, _ = _replacement_context(
        rbno_changes={"enabled": True, "replacement_complete": True}
    )
    assert rbno_payload["repair_required"] is False


@pytest.mark.parametrize(
    "changes",
    [
        {"ssh_reachability": ReachabilityStatus.REACHABLE},
        {"service_reachability": ReachabilityStatus.AMBIGUOUS},
        {"provider_lifecycle_reachability": ReachabilityStatus.NOT_PERFORMED},
        {"mapping_reviewed": False},
        {"replacement_absent_from_ring": False},
        {"active_topology_operation": "replacement"},
        {"removenode_status": "started"},
        {"old_host_id": HOST_2},
        {"new_provider_id": OLD_PROVIDER},
        {"survivor_views": ()},
    ],
)
def test_dead_identity_quorum_topology_and_removal_conflicts_refused(
    changes: dict[str, object],
) -> None:
    with pytest.raises((StateConflictError, AnsibleError)):
        _replacement_context(target_changes=changes)


@pytest.mark.parametrize(
    "field", ["replication", "quorum", "capacity", "backup_policy"]
)
def test_every_replacement_safety_gate_must_pass(field: str) -> None:
    with pytest.raises(StateConflictError):
        _replacement_context(safety_changes={field: SafetyCheckStatus.UNKNOWN})


@pytest.mark.parametrize(
    "changes",
    [
        {"reviewed": False},
        {"allow_destructive": False},
        {"confirmed_target": "scylla-ad-2-1"},
        {"old_provider_id": "changed"},
        {"new_provider_id": "changed"},
        {"old_host_id": HOST_2},
        {"prior_key_written": True},
        {"prior_service_started": True},
        {"config_digest": "sha256:" + "b" * 64},
        {"storage_digest": "sha256:" + "b" * 64},
        {"topology_digest": "invalid"},
    ],
)
def test_narrow_authorization_conflicts_refused(changes: dict[str, object]) -> None:
    with pytest.raises((StateConflictError, AnsibleError)):
        _replacement_context(authorization_changes=changes)


def test_version_storage_config_and_rbno_conflicts_refused() -> None:
    for kwargs in (
        {"version": "2026.2"},
        {"storage_changes": {"readiness_for_scylla": False}},
        {"configure_changes": {"service_inactive": False}},
        {"rbno_changes": {"replacement_complete": True}},
    ):
        with pytest.raises((StateConflictError, AnsibleError)):
            _replacement_context(**kwargs)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("replaced", ScyllaReplaceDeadStatus.REPLACED),
        ("failed", ScyllaReplaceDeadStatus.FAILED),
        ("not-predicted", ScyllaReplaceDeadStatus.NOT_PREDICTED),
    ],
)
def test_result_success_failure_and_check_refusal(
    status: str, expected: ScyllaReplaceDeadStatus
) -> None:
    payload, _ = _replacement_context()
    evidence = parse_scylla_replace_dead_execution(
        _output(payload, status),
        expected_payload=payload,
        exit_code=0 if status == "replaced" else 2,
    )
    assert evidence.status is expected
    if status == "replaced":
        assert (
            evidence.mutation_boundary is ReplacementMutationBoundary.MEMBERSHIP_PROVEN
        )
        assert evidence.replacement_key_retained
        assert (
            scylla_replace_dead_checkpoint_evidence(evidence).result
            is EvidenceResult.COMPLETED
        )


def test_interruption_requires_recovery_and_preserves_key() -> None:
    payload, _ = _replacement_context()
    evidence = scylla_replace_dead_interrupted_evidence(payload)
    assert evidence.recovery_required
    assert evidence.replacement_key_retained
    assert evidence.blockers == ("execution-interrupted",)
    assert (
        scylla_replace_dead_checkpoint_evidence(evidence).summary_code
        == "scylla-replacement-recovery-required"
    )


def test_parser_refuses_inconsistent_views_raw_and_malformed_results() -> None:
    payload, _ = _replacement_context()
    bad = _result(payload)
    cast(dict[str, str], bad["postconditions"])["old-host-id-absent"] = "failed"
    encoded = base64.b64encode(json.dumps(bad).encode()).decode()
    output = (
        f"DSV_SCYLLA_REPLACE_DEAD_B64={encoded}\nPLAY RECAP *****\n"
        f"{payload['stable_id']} : ok=1 changed=1 unreachable=0 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    for value in ("", output, "x" * (512 * 1024 + 1)):
        with pytest.raises(AnsibleError):
            parse_scylla_replace_dead_execution(
                value, expected_payload=payload, exit_code=0
            )
    assert "10.0.0." not in _output(payload)


def test_registry_package_role_and_module_enforce_exact_procedure() -> None:
    definition = get_playbook("scylla-replace-dead")
    assert definition.source_available
    assert definition.check_mode is CheckMode.REFUSED
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert callable(AnsibleService.execute_scylla_replace_dead)
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content/playbooks"
    text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            root / "scylla-replace-dead.yml",
            root / "roles/scylla_replace_dead/tasks/main.yml",
            root / "roles/scylla_replace_dead/library/scylla_replace_dead.py",
        )
    )
    for required in (
        "gather_facts: true",
        "become: true",
        "serial: 1",
        "any_errors_fatal: true",
        "replace_node_first_boot:",
        '["/usr/bin/nodetool", "gossipinfo"]',
        '["/usr/bin/nodetool", "status"]',
        '["/usr/bin/nodetool", "netstats"]',
        "ansible.builtin.systemd_service:",
        "state: started",
        "shell=False",
    ):
        assert required in text
    for forbidden in (
        "replace_address:",
        "replace_address_first_boot:",
        '["/usr/bin/nodetool", "removenode"',
        "ansible.builtin.shell",
        "wipefs",
        "terraform",
    ):
        assert forbidden not in text.lower()


def test_fake_service_refuses_any_limit_except_replacement_target() -> None:
    _, authorization = _replacement_context()

    class FakeBuilder:
        paths = object()

    class FakeLock:
        def assert_held_for(self, paths: object) -> None:
            assert paths is FakeBuilder.paths

    service = object.__new__(AnsibleService)
    service._builder = FakeBuilder()
    with pytest.raises(StateConflictError, match="new stable logical target"):
        service.execute_scylla_replace_dead(
            FakeLock(),
            cast(object, None),
            cast(object, None),
            cast(object, None),
            cast(object, None),
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


def test_remote_module_atomically_writes_exact_key_and_polls_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _remote_module()
    config = tmp_path / "scylla.yaml"
    config.write_text("cluster_name: example\n", encoding="utf-8")
    monkeypatch.setattr(module, "_CONFIG", config)
    module._write_key(HOST_1, module._file_digest(config.read_bytes()))
    assert config.read_text(encoding="utf-8") == (
        f"cluster_name: example\nreplace_node_first_boot: {HOST_1}\n"
    )
    with pytest.raises(ValueError):
        module._write_key(HOST_1, module._file_digest(config.read_bytes()))

    status = (
        "Datacenter: dc1\n"
        f"UN 10.0.0.2 1 GB 1 100% {HOST_2} rack2\n"
        "UN 10.0.0.3 1 GB 1 100% "
        "33333333-3333-4333-8333-333333333333 rack1\n"
    )
    outputs = {
        "gossipinfo": f"HOST_ID:{HOST_2}\nHOST_ID:33333333-3333-4333-8333-333333333333",
        "status": status,
        "describecluster": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa: [x]",
        "netstats": (
            "Mode: NORMAL\nNot sending any streams.\nNot receiving any streams."
        ),
    }
    monkeypatch.setattr(
        module,
        "_run",
        lambda argv, timeout: (0, outputs[argv[1]]),
    )
    result = module._postcheck(
        [
            {
                "datacenter": "dc1",
                "host_id": HOST_2,
                "rack": "rack2",
                "state": "UN",
            }
        ],
        HOST_1,
        "dc1",
        "rack1",
        DIGEST,
        1,
    )
    assert result["complete"] is True
    assert set(cast(dict[str, str], result["postconditions"]).values()) == {"passed"}

    monkeypatch.setattr(module, "_run", lambda argv, timeout: (1, ""))
    times = iter((0.0, 0.0, 1.0, 1.0))
    monkeypatch.setattr(module.time, "monotonic", lambda: next(times, 1.0))
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    timed_out = module._postcheck(
        [
            {
                "datacenter": "dc1",
                "host_id": HOST_2,
                "rack": "rack2",
                "state": "UN",
            }
        ],
        HOST_1,
        "dc1",
        "rack1",
        DIGEST,
        1,
    )
    assert timed_out["complete"] is False
    assert (
        cast(dict[str, str], timed_out["postconditions"])["no-streaming"] == "unknown"
    )


def _remote_module() -> object:
    path = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles/scylla_replace_dead/library"
        / "scylla_replace_dead.py"
    )
    spec = importlib.util.spec_from_file_location("replace_dead_remote", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
