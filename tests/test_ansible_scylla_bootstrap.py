import base64
import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible import DIGEST, _readiness
from test_ansible_scylla_configure import _context as _configure_context
from test_ansible_scylla_configure import _stdout as _configure_stdout
from test_ansible_scylla_install import VERSION
from test_ansible_scylla_install import _context as _install_context
from test_ansible_scylla_install import _stdout as _install_stdout

from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_bootstrap import (
    SCYLLA_BOOTSTRAP_SCHEMA_VERSION,
    MutationBoundary,
    ScyllaBootstrapAuthorization,
    ScyllaBootstrapMode,
    ScyllaBootstrapStatus,
    bootstrap_checkpoint_evidence,
    build_scylla_bootstrap_payload,
    parse_scylla_bootstrap_execution,
)
from scylla_vms.ansible.scylla_configure import (
    SeedSelectionMode,
    build_scylla_configure_payload,
    parse_scylla_configure_execution,
    select_scylla_seeds,
)
from scylla_vms.ansible.scylla_install import parse_scylla_install_execution
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import (
    InventoryModel,
    StoredInventoryRecord,
    _groups_for_hosts,
    _inventory_digest,
)
from scylla_vms.journal import EvidenceResult, OperationPhase


def _bootstrap_context(
    mode: ScyllaBootstrapMode = ScyllaBootstrapMode.INITIAL_SEED,
    readiness_changes: dict[str, object] | None = None,
    storage_changes: dict[str, object] | None = None,
    install_changes: dict[str, object] | None = None,
    configure_changes: dict[str, object] | None = None,
    requested_package_version: str = VERSION,
    **authorization_changes: object,
) -> tuple[dict[str, object], ScyllaBootstrapAuthorization]:
    configure_payload, metadata, observed, inventory, base_os, storage = (
        _configure_context()
    )
    install_payload, _ = _install_context()
    install = parse_scylla_install_execution(
        _install_stdout(install_payload),
        expected_payload=install_payload,
        exit_code=0,
    )
    if storage_changes:
        storage = replace(storage, **storage_changes)
    if install_changes:
        install = replace(install, **install_changes)
    logical_id = cast(str, configure_payload["logical_id"])
    if mode is ScyllaBootstrapMode.JOIN_EXISTING:
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
        seed_policy = select_scylla_seeds(
            inventory,
            mode=SeedSelectionMode.ADD,
            target_logical_id=logical_id,
            healthy_surviving_ids=(peer.logical_id,),
        )
        configure_payload = build_scylla_configure_payload(
            metadata,
            observed,
            inventory,
            _readiness(inventory),
            base_os,
            storage,
            install,
            seed_policy,
            logical_id=logical_id,
            package_version=VERSION,
            architecture="amd64",
            cluster_spec_digest=DIGEST,
        )
        healthy = (peer.logical_id,)
    else:
        seed_policy = select_scylla_seeds(
            inventory,
            mode=SeedSelectionMode.INITIAL,
            target_logical_id=logical_id,
        )
        healthy = ()
    configure = parse_scylla_configure_execution(
        _configure_stdout(configure_payload),
        expected_payload=configure_payload,
        exit_code=0,
    )
    if configure_changes:
        configure = replace(configure, **configure_changes)
    authorization = ScyllaBootstrapAuthorization(
        operation_id="operation-11111111",
        mode=mode,
        target_logical_id=logical_id,
        intent_digest=DIGEST,
        authorization_digest=DIGEST,
        reviewed=True,
        target_present_in_ring=False,
        existing_member_count=len(healthy),
        live_cluster_state_absent=not healthy,
        healthy_member_ids=healthy,
        healthy_seed_ids=healthy,
        capacity_check_passed=bool(healthy),
        topology_check_passed=bool(healthy),
        schema_agreement=bool(healthy),
        config_file_digests=tuple(
            sorted(cast(dict[str, str], configure_payload["file_digests"]).items())
        ),
    )
    authorization = replace(authorization, **authorization_changes)
    readiness = _readiness(inventory)
    if readiness_changes:
        readiness = replace(readiness, **readiness_changes)
    payload = build_scylla_bootstrap_payload(
        metadata,
        observed,
        inventory,
        readiness,
        storage,
        install,
        configure,
        seed_policy,
        authorization,
        package_version=requested_package_version,
        bootstrap_timeout_seconds=7200,
        cluster_spec_digest=DIGEST,
    )
    return payload, authorization


def _result(
    payload: dict[str, object], status: str = "bootstrapped"
) -> dict[str, object]:
    if status == "not-predicted":
        return {
            "blockers": [],
            "datacenter": payload["datacenter"],
            "host_id_digest": None,
            "mode": payload["mode"],
            "mutation_boundary": "not-reached",
            "prerequisite_digests": payload["prerequisite_digests"],
            "rack": payload["rack"],
            "recovery_required": False,
            "ring_membership_digest": None,
            "schema_version": SCYLLA_BOOTSTRAP_SCHEMA_VERSION,
            "service_state": "not-checked",
            "status": status,
            "streaming_state": "not-checked",
            "target_logical_id": payload["logical_id"],
        }
    success = status == "bootstrapped"
    return {
        "blockers": [] if success else ["join-incomplete"],
        "datacenter": payload["datacenter"],
        "host_id_digest": DIGEST if success else None,
        "mode": payload["mode"],
        "mutation_boundary": "ring-membership-may-have-changed",
        "prerequisite_digests": payload["prerequisite_digests"],
        "rack": payload["rack"],
        "recovery_required": not success,
        "ring_membership_digest": DIGEST,
        "schema_version": SCYLLA_BOOTSTRAP_SCHEMA_VERSION,
        "service_state": "active" if success else "unknown-preserved",
        "status": status,
        "streaming_state": "complete" if success else "unknown",
        "target_logical_id": payload["logical_id"],
    }


def _stdout(payload: dict[str, object], status: str = "bootstrapped") -> str:
    encoded = base64.b64encode(
        json.dumps(_result(payload, status), sort_keys=True).encode()
    ).decode()
    failed = 0 if status == "bootstrapped" else 1
    changed = 1 if status != "not-predicted" else 0
    return (
        f'{{"msg":"DSV_SCYLLA_BOOTSTRAP_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=15 changed={changed} unreachable=0 failed={failed} "
        "skipped=0 rescued=0 ignored=0\n"
    )


@pytest.mark.parametrize(
    "mode", [ScyllaBootstrapMode.INITIAL_SEED, ScyllaBootstrapMode.JOIN_EXISTING]
)
def test_explicit_initial_and_join_payloads_are_valid_and_bound(
    mode: ScyllaBootstrapMode,
) -> None:
    payload, authorization = _bootstrap_context(mode)
    assert payload["mode"] == mode.value
    assert payload["logical_id"] == authorization.target_logical_id
    assert payload["release_line"] == "2026.2"
    assert set(cast(dict[str, str], payload["prerequisite_digests"])) == {
        "authorization_digest",
        "cluster_spec_digest",
        "config_digest",
        "install_digest",
        "inventory_digest",
        "observation_digest",
        "seed_digest",
        "storage_digest",
        "topology_digest",
        "trust_digest",
    }
    if mode is ScyllaBootstrapMode.INITIAL_SEED:
        assert payload["seed_stable_ids"] == [payload["logical_id"]]
    else:
        assert payload["logical_id"] not in cast(list[str], payload["seed_stable_ids"])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("reviewed", False),
        ("target_present_in_ring", True),
        ("live_cluster_state_absent", False),
        ("existing_member_count", 1),
    ],
)
def test_initial_seed_refuses_nonempty_unreviewed_or_existing_target(
    field: str, value: object
) -> None:
    with pytest.raises((StateConflictError, AnsibleError)):
        _bootstrap_context(**{field: value})


def test_join_refuses_unhealthy_self_only_stale_and_drifted_evidence() -> None:
    for changes in (
        {"healthy_seed_ids": ()},
        {"capacity_check_passed": False},
        {"topology_check_passed": False},
        {"schema_agreement": False},
        {"target_present_in_ring": True},
        {"healthy_member_ids": ("scylla-ad-1-1",)},
        {"authorization_digest": "invalid"},
    ):
        with pytest.raises((StateConflictError, AnsibleError)):
            _bootstrap_context(ScyllaBootstrapMode.JOIN_EXISTING, **changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"readiness_changes": {"observation_digest": "sha256:" + "b" * 64}},
        {"storage_changes": {"readiness_for_scylla": False}},
        {"install_changes": {"service_masked": False}},
        {"configure_changes": {"service_inactive": False}},
        {"configure_changes": {"config_digest": "sha256:" + "b" * 64}},
        {"requested_package_version": "2026.2-invalid"},
    ],
)
def test_bootstrap_refuses_stale_or_drifted_prerequisites(
    changes: dict[str, object],
) -> None:
    with pytest.raises((StateConflictError, AnsibleError)):
        _bootstrap_context(**changes)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("bootstrapped", ScyllaBootstrapStatus.BOOTSTRAPPED),
        ("failed", ScyllaBootstrapStatus.FAILED),
    ],
)
def test_parser_accepts_success_and_partial_failure_recovery(
    status: str, expected: ScyllaBootstrapStatus
) -> None:
    payload, _ = _bootstrap_context()
    evidence = parse_scylla_bootstrap_execution(
        _stdout(payload, status),
        expected_payload=payload,
        exit_code=0 if status == "bootstrapped" else 2,
    )
    assert evidence.status is expected
    assert (
        evidence.mutation_boundary is MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED
    )
    assert evidence.recovery_required is (status == "failed")
    checkpoint = bootstrap_checkpoint_evidence(evidence)
    assert checkpoint.phase is OperationPhase.EXECUTE
    assert checkpoint.result is (
        EvidenceResult.FAILED if status == "failed" else EvidenceResult.COMPLETED
    )
    assert (checkpoint.summary_code == "scylla-membership-may-have-changed") is (
        status == "failed"
    )


def test_parser_preserves_truthful_check_mode_refusal() -> None:
    payload, _ = _bootstrap_context()
    evidence = parse_scylla_bootstrap_execution(
        _stdout(payload, "not-predicted"),
        expected_payload=payload,
        exit_code=2,
    )
    assert evidence.status is ScyllaBootstrapStatus.NOT_PREDICTED
    assert evidence.mutation_boundary is MutationBoundary.NOT_REACHED


def test_parser_rejects_timeout_malformed_raw_and_secret_like_results() -> None:
    payload, _ = _bootstrap_context()
    for stdout in (
        "",
        "DSV_SCYLLA_BOOTSTRAP_B64=not-base64\nPLAY RECAP *****\n",
        "x" * (512 * 1024 + 1),
    ):
        with pytest.raises(AnsibleError):
            parse_scylla_bootstrap_execution(
                stdout, expected_payload=payload, exit_code=2
            )
    output = _stdout(payload)
    assert "10.0.0." not in output
    assert "password" not in output.lower()


def test_registry_and_packaged_role_enforce_single_serial_systemd_boundary() -> None:
    definition = get_playbook("scylla-bootstrap")
    assert definition.source_available
    assert definition.check_mode is CheckMode.REFUSED
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.serial == 1
    assert definition.any_errors_fatal
    assert callable(AnsibleService.execute_scylla_bootstrap)
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content/playbooks"
    playbook = (root / "scylla-bootstrap.yml").read_text(encoding="utf-8")
    role = (root / "roles/scylla_bootstrap/tasks/main.yml").read_text(encoding="utf-8")
    assert "gather_facts: true" in playbook
    assert "become: true" in playbook
    assert "serial: 1" in playbook
    assert "any_errors_fatal: true" in playbook
    assert "ansible.builtin.systemd_service:" in role
    assert "state: started" in role
    assert "/usr/bin/nodetool" in role
    assert "argv:" in role
    assert "ansible.builtin.shell" not in (playbook + role)
    assert "ring-membership-may-have-changed" in role
