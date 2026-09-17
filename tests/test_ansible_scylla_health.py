import base64
import importlib.util
import json
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible import DIGEST, _readiness
from test_ansible_scylla_configure import _context

from scylla_vms.ansible.registry import CheckMode, get_playbook
from scylla_vms.ansible.scylla_health import (
    SCYLLA_HEALTH_SCHEMA_VERSION,
    SCYLLA_HEALTH_VIEW_SCHEMA_VERSION,
    HealthCheckStatus,
    HealthReadiness,
    build_scylla_health_payload,
    parse_scylla_health_execution,
)
from scylla_vms.ansible.scylla_install import SCYLLA_PACKAGE_VERSION
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import (
    InventoryModel,
    StoredInventoryRecord,
    _groups_for_hosts,
    _inventory_digest,
)

HOST_1 = "11111111-1111-4111-8111-111111111111"
HOST_2 = "22222222-2222-4222-8222-222222222222"
SCHEMA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def _health_context(
    *,
    multi: bool = False,
    limit: tuple[str, ...] | None = None,
    active_stable_ids: tuple[str, ...] | None = None,
) -> tuple[dict[str, object], StoredInventoryRecord]:
    _, metadata, observed, inventory, _, storage = _context()
    storages = (storage,)
    if multi:
        original = inventory.record.inventory.hosts[0]
        peer = replace(
            original,
            logical_id="scylla-ad-2-1",
            zone="AD-2",
            provider_id="ocid1.instance.oc1.iad.fakepeer",
            private_address="10.0.0.21",
            ansible_host="10.0.0.21",
            scylla_rack="rack2",
        )
        hosts = tuple(sorted((original, peer), key=lambda item: item.logical_id))
        model = InventoryModel(
            hosts,
            _groups_for_hosts(hosts),
            inventory.record.inventory.host_trust_status,
        )
        inventory = StoredInventoryRecord(
            replace(
                inventory.record,
                inventory=model,
                inventory_digest=_inventory_digest(model),
            ),
            DIGEST,
        )
        storages = (storage, replace(storage, logical_id=peer.logical_id))
    scylla_ids = tuple(
        host.logical_id
        for host in inventory.record.inventory.hosts
        if host.role.value == "scylla"
    )
    active_ids = active_stable_ids or scylla_ids
    storages = tuple(item for item in storages if item.logical_id in active_ids)
    payload = build_scylla_health_payload(
        metadata,
        observed,
        inventory,
        _readiness(inventory),
        storages,
        limit=limit or active_ids,
        timeout_seconds=30,
        active_stable_ids=active_ids,
    )
    return payload, inventory


def test_health_payload_scopes_current_membership_separately_from_waiting_nodes() -> (
    None
):
    payload, _ = _health_context(
        multi=True,
        active_stable_ids=("scylla-ad-1-1",),
    )

    assert payload["queried_nodes"] == ["scylla-ad-1-1"]
    assert [
        cast(dict[str, object], item)["logical_id"]
        for item in cast(list[object], payload["expected_hosts"])
    ] == ["scylla-ad-1-1"]


def _view(
    logical_id: str,
    host_id: str,
    ring: list[dict[str, object]],
    *,
    schemas: list[str] | None = None,
    state_errors: list[str] | None = None,
    service_state: str = "active",
    cql: bool = True,
    api: bool = True,
    mode: str = "NORMAL",
    sending: int = 0,
    receiving: int = 0,
    version: str = SCYLLA_PACKAGE_VERSION,
) -> dict[str, object]:
    expected = {
        "scylla-ad-1-1": ("dc1", "rack1"),
        "scylla-ad-2-1": ("dc1", "rack2"),
    }[logical_id]
    return {
        "api_reachable": api,
        "captured_at": "2026-09-18T01:00:00Z",
        "commands": [
            ["/usr/bin/nodetool", "info"],
            ["/usr/bin/nodetool", "status"],
            ["/usr/bin/nodetool", "describecluster"],
            ["/usr/bin/nodetool", "netstats"],
            ["/usr/bin/nodetool", "version"],
            ["/usr/bin/systemctl", "is-active", "scylla-server.service"],
        ],
        "cql_reachable": cql,
        "datacenter": expected[0],
        "errors": state_errors or [],
        "local_host_id": host_id,
        "logical_id": logical_id,
        "mode": mode,
        "rack": expected[1],
        "receiving_streams": receiving,
        "ring": ring,
        "schema_version": SCYLLA_HEALTH_VIEW_SCHEMA_VERSION,
        "schema_versions": schemas or [SCHEMA],
        "sending_streams": sending,
        "service_state": service_state,
        "version": version,
    }


def _ring(
    *,
    state_1: str = "UN",
    state_2: str = "UN",
    rack_1: str = "rack1",
    include_peer: bool = False,
    extra: bool = False,
) -> list[dict[str, object]]:
    rows = [
        {
            "datacenter": "dc1",
            "host_id": HOST_1,
            "rack": rack_1,
            "state": state_1,
        }
    ]
    if include_peer:
        rows.append(
            {
                "datacenter": "dc1",
                "host_id": HOST_2,
                "rack": "rack2",
                "state": state_2,
            }
        )
    if extra:
        rows.append(
            {
                "datacenter": "dc1",
                "host_id": "33333333-3333-4333-8333-333333333333",
                "rack": "rack3",
                "state": "UN",
            }
        )
    return sorted(rows, key=lambda row: cast(str, row["host_id"]))


def _stdout(
    views: list[dict[str, object]],
    queried: tuple[str, ...],
    *,
    failed: set[str] | None = None,
    unreachable: set[str] | None = None,
) -> tuple[str, int]:
    failed = failed or set()
    unreachable = unreachable or set()
    lines = []
    by_id = {cast(str, view["logical_id"]): view for view in views}
    for logical_id in sorted(by_id):
        encoded = base64.b64encode(
            json.dumps(by_id[logical_id], sort_keys=True).encode()
        ).decode()
        lines.append(f'{{"msg":"DSV_SCYLLA_HEALTH_B64={encoded}"}}')
    lines.append("PLAY RECAP *****")
    for logical_id in queried:
        lines.append(
            f"{logical_id} : ok=4 changed=0 "
            f"unreachable={int(logical_id in unreachable)} "
            f"failed={int(logical_id in failed)} skipped=0 rescued=0 ignored=0"
        )
    return "\n".join(lines) + "\n", 2 if failed or unreachable else 0


def test_single_node_health_is_read_only_ready_but_strong_gates_are_blocked() -> None:
    payload, _ = _health_context()
    queried = cast(tuple[str, ...], tuple(payload["queried_nodes"]))
    stdout, rc = _stdout(
        [_view("scylla-ad-1-1", HOST_1, _ring())],
        queried,
    )
    evidence = parse_scylla_health_execution(
        stdout, expected_payload=payload, exit_code=rc
    )
    assert evidence.schema_version == SCYLLA_HEALTH_SCHEMA_VERSION
    assert evidence.status is HealthReadiness.UNKNOWN
    assert evidence.nodes[0].state == "UN"
    assert evidence.schema_agreement is True
    assert evidence.streaming_state == "complete"
    assert evidence.nodes[0].version == SCYLLA_PACKAGE_VERSION
    assert dict(
        (gate.operation_class, gate.readiness) for gate in evidence.operation_gates
    ) == {
        "destructive": HealthReadiness.BLOCKED,
        "mutating": HealthReadiness.BLOCKED,
        "read-only": HealthReadiness.READY,
        "sensitive": HealthReadiness.BLOCKED,
    }
    checks = {check.name: check.status for check in evidence.checks}
    assert checks["quorum"] is HealthCheckStatus.UNKNOWN
    assert checks["replication"] is HealthCheckStatus.NOT_PERFORMED
    assert checks["backup-policy"] is HealthCheckStatus.NOT_PERFORMED
    assert checks["capacity"] is HealthCheckStatus.UNKNOWN


def test_multi_zone_cross_views_map_stable_ids_by_local_host_ids() -> None:
    payload, _ = _health_context(multi=True)
    queried = tuple(cast(list[str], payload["queried_nodes"]))
    ring = _ring(include_peer=True)
    stdout, rc = _stdout(
        [
            _view("scylla-ad-1-1", HOST_1, ring),
            _view("scylla-ad-2-1", HOST_2, ring),
        ],
        queried,
    )
    evidence = parse_scylla_health_execution(
        stdout, expected_payload=payload, exit_code=rc
    )
    assert evidence.status is HealthReadiness.UNKNOWN
    assert [(node.logical_id, node.host_id, node.rack) for node in evidence.nodes] == [
        ("scylla-ad-1-1", HOST_1, "rack1"),
        ("scylla-ad-2-1", HOST_2, "rack2"),
    ]
    assert evidence.topology_digest is not None


@pytest.mark.parametrize("state", ["UJ", "UL", "UM", "DN", "DJ", "DL", "DM"])
def test_every_transitional_or_down_node_state_blocks_health(state: str) -> None:
    payload, _ = _health_context()
    queried = tuple(cast(list[str], payload["queried_nodes"]))
    stdout, rc = _stdout(
        [_view("scylla-ad-1-1", HOST_1, _ring(state_1=state))],
        queried,
    )
    evidence = parse_scylla_health_execution(
        stdout, expected_payload=payload, exit_code=rc
    )
    assert evidence.status is HealthReadiness.BLOCKED
    assert "node-not-up-normal" in evidence.nodes[0].blockers


@pytest.mark.parametrize(
    ("mutation", "blocker"),
    [
        ("topology", "topology-conflict"),
        ("extra", "extra-ring-member"),
        ("missing", "missing-ring-member"),
        ("schema", "schema-disagreement"),
        ("streaming", "streaming-active"),
        ("service", "service-inactive"),
        ("cql", "cql-unreachable"),
        ("api", "api-unreachable"),
        ("version", "version-conflict"),
    ],
)
def test_topology_membership_schema_streaming_and_reachability_fail_closed(
    mutation: str, blocker: str
) -> None:
    payload, _ = _health_context()
    queried = tuple(cast(list[str], payload["queried_nodes"]))
    ring = _ring(rack_1="wrong" if mutation == "topology" else "rack1")
    if mutation == "extra":
        ring = _ring(extra=True)
    if mutation == "missing":
        ring = []
    view = _view(
        "scylla-ad-1-1",
        HOST_1,
        ring,
        schemas=sorted([SCHEMA, HOST_2]) if mutation == "schema" else None,
        service_state="inactive" if mutation == "service" else "active",
        cql=mutation != "cql",
        api=mutation != "api",
        sending=1 if mutation == "streaming" else 0,
        version="2026.2.wrong" if mutation == "version" else SCYLLA_PACKAGE_VERSION,
    )
    stdout, rc = _stdout([view], queried)
    evidence = parse_scylla_health_execution(
        stdout, expected_payload=payload, exit_code=rc
    )
    assert evidence.status is HealthReadiness.BLOCKED
    assert blocker in evidence.blockers


def test_inconsistent_views_and_duplicate_local_identity_are_blocked() -> None:
    payload, _ = _health_context(multi=True)
    queried = tuple(cast(list[str], payload["queried_nodes"]))
    stdout, rc = _stdout(
        [
            _view("scylla-ad-1-1", HOST_1, _ring(include_peer=True)),
            _view(
                "scylla-ad-2-1",
                HOST_1,
                _ring(include_peer=True, state_2="DN"),
            ),
        ],
        queried,
    )
    evidence = parse_scylla_health_execution(
        stdout, expected_payload=payload, exit_code=rc
    )
    assert {"duplicate-host-id", "inconsistent-ring-view"} <= set(evidence.blockers)


def test_partial_unreachable_and_bounded_command_failure_are_redacted() -> None:
    payload, _ = _health_context(multi=True)
    queried = tuple(cast(list[str], payload["queried_nodes"]))
    failed_view = _view(
        "scylla-ad-1-1",
        HOST_1,
        _ring(include_peer=True),
        state_errors=["netstats"],
    )
    stdout, rc = _stdout(
        [failed_view],
        queried,
        failed={"scylla-ad-1-1"},
        unreachable={"scylla-ad-2-1"},
    )
    evidence = parse_scylla_health_execution(
        stdout, expected_payload=payload, exit_code=rc
    )
    assert evidence.status is HealthReadiness.BLOCKED
    assert {"view-command-failed", "host-unreachable"} <= set(evidence.blockers)
    rendered = repr(evidence)
    assert "10.0.0." not in rendered
    assert "ocid1." not in rendered


def test_parser_refuses_malformed_oversize_duplicate_and_exit_conflicts() -> None:
    payload, _ = _health_context()
    queried = tuple(cast(list[str], payload["queried_nodes"]))
    view = _view("scylla-ad-1-1", HOST_1, _ring())
    valid, _ = _stdout([view], queried)
    cases = (
        "",
        "DSV_SCYLLA_HEALTH_B64=bad\nPLAY RECAP *****\n",
        "x" * (1024 * 1024 + 1),
        valid.replace("PLAY RECAP", valid.splitlines()[0] + "\nPLAY RECAP"),
    )
    for stdout in cases:
        with pytest.raises(AnsibleError):
            parse_scylla_health_execution(stdout, expected_payload=payload, exit_code=2)


def test_coordinator_requires_complete_prior_host_id_map() -> None:
    _, metadata, observed, original_inventory, _, storage = _context()
    _, inventory = _health_context(multi=True)
    original = original_inventory.record.inventory.hosts[0]
    peer_storage = replace(storage, logical_id="scylla-ad-2-1")
    readiness = _readiness(inventory)
    logical_id = original.logical_id
    with pytest.raises(StateConflictError):
        build_scylla_health_payload(
            metadata,
            observed,
            inventory,
            readiness,
            (storage, peer_storage),
            limit=(logical_id,),
            timeout_seconds=30,
            known_host_ids={},
        )
    payload = build_scylla_health_payload(
        metadata,
        observed,
        inventory,
        readiness,
        (storage, peer_storage),
        limit=(logical_id,),
        timeout_seconds=30,
        known_host_ids={logical_id: HOST_1, "scylla-ad-2-1": HOST_2},
    )
    assert payload["query_policy"] == "coordinator-known-identities"
    queried = tuple(cast(list[str], payload["queried_nodes"]))
    stdout, rc = _stdout(
        [_view(logical_id, HOST_1, _ring(include_peer=True))],
        queried,
    )
    evidence = parse_scylla_health_execution(
        stdout, expected_payload=payload, exit_code=rc
    )
    assert "node-not-queried" in evidence.blockers
    assert evidence.nodes[1].state == "UN"


def test_registry_playbook_role_and_module_are_strictly_read_only() -> None:
    definition = get_playbook("scylla-health")
    assert definition.source_available
    assert definition.check_mode is CheckMode.SUPPORTED
    assert definition.serial == 5
    assert not definition.any_errors_fatal
    assert callable(AnsibleService.execute_scylla_health)
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content/playbooks"
    text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            root / "scylla-health.yml",
            root / "roles/scylla_health/tasks/main.yml",
            root / "roles/scylla_health/library/scylla_health.py",
        )
    )
    for command in ("info", "status", "describecluster", "netstats"):
        assert command in text
    assert "shell=False" in text
    assert "subprocess.run" in text
    assert "ansible.builtin.shell" not in text
    assert "become: false" in text
    for forbidden in ("repair", "cleanup", "snapshot", "restart", "refresh"):
        assert f'"{forbidden}"' not in text


def test_remote_collector_uses_exact_argv_and_bounds_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles/scylla_health/library"
        / "scylla_health.py"
    )
    spec = importlib.util.spec_from_file_location("health_remote_module", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls: list[tuple[list[str], dict[str, object]]] = []

    class Completed:
        returncode = 0
        stdout = b"bounded"

    def fake_run(argv: list[str], **kwargs: object) -> Completed:
        calls.append((argv, kwargs))
        return Completed()

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    assert module._run(["/usr/bin/nodetool", "status"], 12) == (0, "bounded")
    assert calls == [
        (
            ["/usr/bin/nodetool", "status"],
            {
                "capture_output": True,
                "check": False,
                "shell": False,
                "timeout": 12,
            },
        )
    ]

    class Oversize:
        returncode = 0
        stdout = b"x" * (256 * 1024 + 1)

    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: Oversize())
    assert module._run(["/usr/bin/nodetool", "status"], 12) == (1, "")

    def timeout(*args: object, **kwargs: object) -> object:
        raise subprocess.TimeoutExpired(["/usr/bin/nodetool", "status"], 12)

    monkeypatch.setattr(module.subprocess, "run", timeout)
    assert module._run(["/usr/bin/nodetool", "status"], 12) == (1, "")


def test_remote_status_parser_retains_address_only_for_internal_reconciliation() -> (
    None
):
    path = (
        Path(__file__).parents[1]
        / "scylla_vms/ansible/content/playbooks/roles/scylla_health/library"
        / "scylla_health.py"
    )
    spec = importlib.util.spec_from_file_location("health_remote_parser", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rows = module._ring(f"Datacenter: dc1\nUN 10.0.0.20 1 TB 256 ? {HOST_1} rack1\n")
    assert rows == [
        {
            "address": "10.0.0.20",
            "datacenter": "dc1",
            "host_id": HOST_1,
            "rack": "rack1",
            "state": "UN",
        }
    ]
