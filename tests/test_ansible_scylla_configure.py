import base64
import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_ansible import DIGEST, FakeRunner, _builder, _paths, _readiness
from test_ansible_scylla_install import (
    VERSION,
)
from test_ansible_scylla_install import (
    _context as _install_context,
)
from test_ansible_scylla_install import (
    _stdout as _install_stdout,
)
from test_ansible_storage import (
    _postcheck_context,
    _postcheck_result,
    _postcheck_stdout,
    _scylla_inventory,
)

from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_configure import (
    SCYLLA_CONFIGURE_DIRECTORIES,
    SCYLLA_CONFIGURE_KEYS,
    SCYLLA_CONFIGURE_SCHEMA_VERSION,
    ScyllaConfigureStatus,
    SeedSelectionMode,
    build_scylla_configure_payload,
    parse_scylla_configure_execution,
    select_scylla_seeds,
)
from scylla_vms.ansible.scylla_install import parse_scylla_install_execution
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.ansible.storage_postcheck import parse_storage_postcheck_execution
from scylla_vms.desired import HostRole
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import (
    InventoryGroup,
    InventoryModel,
    StoredInventoryRecord,
    _groups_for_hosts,
    _inventory_digest,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.process import ProcessResult


def _context() -> tuple[dict[str, object], object, object, object, object, object]:
    metadata, observed, inventory, *_, postcheck_payload = _postcheck_context()
    storage = parse_storage_postcheck_execution(
        _postcheck_stdout(_postcheck_result(postcheck_payload)),
        expected_payload=postcheck_payload,
        exit_code=0,
    )
    install_payload, base_os = _install_context()
    install = parse_scylla_install_execution(
        _install_stdout(install_payload),
        expected_payload=install_payload,
        exit_code=0,
    )
    logical_id = cast(str, postcheck_payload["logical_id"])
    seed_policy = select_scylla_seeds(
        inventory,
        mode=SeedSelectionMode.INITIAL,
        target_logical_id=logical_id,
    )
    payload = build_scylla_configure_payload(
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
    return payload, metadata, observed, inventory, base_os, storage


def _result(payload: dict[str, object], status: str = "noop") -> dict[str, object]:
    success = status in {"changed", "noop"}
    return {
        "blockers": [] if status != "failed" else ["execution-failed"],
        "bootstrap_performed": False,
        "config_digest": payload["config_digest"],
        "configuration_file_digests": (payload["file_digests"] if success else {}),
        "files_mode_0644": True if success else None,
        "files_root_owned": True if success else None,
        "firewall_operation_performed": False,
        "installed_version": payload["package_version"] if success else None,
        "logical_id": payload["logical_id"],
        "manager_operation_performed": False,
        "package_install_performed": False,
        "prerequisite_digests": payload["provenance"],
        "runtime_validation_performed": False,
        "schema_version": SCYLLA_CONFIGURE_SCHEMA_VERSION,
        "seed_digest": payload["seed_digest"],
        "service_inactive": True if success else None,
        "service_masked": True if success else None,
        "service_started": False,
        "ssh_operation_performed": False,
        "status": status,
        "storage_mutation_performed": False,
        "topology_digest": payload["topology_digest"],
        "tuning_performed": False,
    }


def _stdout(
    payload: dict[str, object], status: str = "noop", *, failed: int = 0
) -> str:
    result = _result(payload, status)
    if status == "not-predicted":
        result.update(
            {
                "installed_version": None,
                "service_inactive": None,
                "service_masked": None,
            }
        )
    encoded = base64.b64encode(json.dumps(result, sort_keys=True).encode()).decode()
    changed = 1 if status == "changed" else 0
    return (
        f"ok: [{payload['logical_id']}] => "
        f'{{"msg":"DSV_SCYLLA_CONFIGURE_B64={encoded}"}}\n'
        "PLAY RECAP *****\n"
        f"{payload['logical_id']} : ok=12 changed={changed} unreachable=0 "
        f"failed={failed} skipped=0 rescued=0 ignored=0\n"
    )


def _multizone_inventory(count: int = 7) -> StoredInventoryRecord:
    stored = _scylla_inventory()
    original = stored.record.inventory.hosts[0]
    hosts = tuple(
        replace(
            original,
            logical_id=f"scylla-ad-{(index % 3) + 1}-{index + 1}",
            zone=f"AD-{(index % 3) + 1}",
            provider_id=f"ocid1.instance.oc1.iad.fakescylla{index + 1}",
            private_address=f"10.0.1.{index + 20}",
            ansible_host=f"10.0.1.{index + 20}",
            scylla_rack=f"rack{(index % 3) + 1}",
        )
        for index in range(count)
    )
    groups = [
        InventoryGroup("jump_hosts", ()),
        InventoryGroup("manager", ()),
        InventoryGroup("monitoring", ()),
        InventoryGroup("scylla", tuple(sorted(host.logical_id for host in hosts))),
        InventoryGroup(
            "scylla_dc_dc1", tuple(sorted(host.logical_id for host in hosts))
        ),
    ]
    for rack in ("rack1", "rack2", "rack3"):
        members = tuple(
            sorted(host.logical_id for host in hosts if host.scylla_rack == rack)
        )
        if members:
            groups.append(InventoryGroup(f"scylla_rack_{rack}", members))
    for zone in ("AD-1", "AD-2", "AD-3"):
        members = tuple(sorted(host.logical_id for host in hosts if host.zone == zone))
        if members:
            groups.append(
                InventoryGroup(f"zone_{zone.lower().replace('-', '_')}", members)
            )
    model = InventoryModel(
        tuple(sorted(hosts, key=lambda host: host.logical_id)),
        tuple(sorted(groups, key=lambda group: group.name)),
        stored.record.inventory.host_trust_status,
    )
    record = replace(
        stored.record, inventory=model, inventory_digest=_inventory_digest(model)
    )
    return StoredInventoryRecord(record, DIGEST)


def test_single_node_payload_contains_only_exact_configuration_contract() -> None:
    payload, *_ = _context()
    config = cast(dict[str, object], payload["config"])
    topology = cast(dict[str, str], payload["topology"])
    assert tuple(sorted(config)) == SCYLLA_CONFIGURE_KEYS
    assert tuple(config["data_file_directories"]) == (SCYLLA_CONFIGURE_DIRECTORIES[0],)
    assert config["commitlog_directory"] == SCYLLA_CONFIGURE_DIRECTORIES[1]
    assert config["hints_directory"] == SCYLLA_CONFIGURE_DIRECTORIES[2]
    assert config["view_hints_directory"] == SCYLLA_CONFIGURE_DIRECTORIES[3]
    assert topology == {"cluster_name": "example", "datacenter": "dc1", "rack": "rack1"}
    assert payload["runtime_validation_performed"] is False
    assert payload["seed_stable_ids"] == ["scylla-ad-1-1"]
    encoded = json.dumps(payload)
    assert "203.0.113" not in encoded
    assert "password" not in encoded.lower()


def test_multizone_seed_policy_is_deterministic_bounded_and_preserves_survivors() -> (
    None
):
    inventory = _multizone_inventory()
    ids = tuple(host.logical_id for host in inventory.record.inventory.hosts)
    target = ids[-1]
    healthy = tuple(sorted(ids[:-1]))
    first = select_scylla_seeds(
        inventory,
        mode=SeedSelectionMode.ADD,
        target_logical_id=target,
        healthy_surviving_ids=healthy,
        persisted_seed_ids=(healthy[1],),
    )
    second = select_scylla_seeds(
        inventory,
        mode=SeedSelectionMode.ADD,
        target_logical_id=target,
        healthy_surviving_ids=healthy,
        persisted_seed_ids=(healthy[1],),
    )
    assert first == second
    assert len(first.stable_ids) == 3
    assert first.stable_ids[0] == healthy[1]
    assert target not in first.stable_ids
    racks = {
        host.logical_id: host.scylla_rack for host in inventory.record.inventory.hosts
    }
    assert len({racks[item] for item in first.stable_ids}) == 3


def test_seed_selection_rejects_unknown_duplicate_public_and_self_only_inputs() -> None:
    inventory = _multizone_inventory(3)
    ids = tuple(host.logical_id for host in inventory.record.inventory.hosts)
    with pytest.raises(StateConflictError):
        select_scylla_seeds(
            inventory,
            mode=SeedSelectionMode.REPLACE,
            target_logical_id=ids[-1],
            healthy_surviving_ids=(ids[0], ids[0]),
        )
    with pytest.raises(StateConflictError):
        select_scylla_seeds(
            inventory,
            mode=SeedSelectionMode.ADD,
            target_logical_id=ids[-1],
            healthy_surviving_ids=(ids[-1],),
        )

    payload, metadata, observed, original, base_os, storage = _context()
    install_payload, _ = _install_context()
    install = parse_scylla_install_execution(
        _install_stdout(install_payload),
        expected_payload=install_payload,
        exit_code=0,
    )
    old = original.record.inventory.hosts[0]
    public_host = replace(
        old, private_address="203.0.113.20", ansible_host="203.0.113.20"
    )
    groups = tuple(
        replace(group, hosts=(public_host.logical_id,) if group.hosts else ())
        for group in original.record.inventory.groups
    )
    model = InventoryModel(
        (public_host,), groups, original.record.inventory.host_trust_status
    )
    public_inventory = StoredInventoryRecord(
        replace(
            original.record,
            inventory=model,
            inventory_digest=_inventory_digest(model),
        ),
        original.digest,
    )
    policy = select_scylla_seeds(
        public_inventory,
        mode=SeedSelectionMode.INITIAL,
        target_logical_id=public_host.logical_id,
    )
    with pytest.raises(StateConflictError, match="RFC 1918"):
        build_scylla_configure_payload(
            metadata,
            observed,
            public_inventory,
            _readiness(public_inventory),
            base_os,
            storage,
            install,
            policy,
            logical_id=public_host.logical_id,
            package_version=VERSION,
            architecture="amd64",
            cluster_spec_digest=DIGEST,
        )
    peer = replace(
        old,
        logical_id="scylla-ad-2-1",
        zone="AD-2",
        provider_id="ocid1.instance.oc1.iad.fakescyllapeer",
        scylla_rack="rack2",
    )
    duplicate_hosts = tuple(sorted((old, peer), key=lambda item: item.logical_id))
    duplicate_model = InventoryModel(
        duplicate_hosts,
        _groups_for_hosts(duplicate_hosts),
        original.record.inventory.host_trust_status,
    )
    duplicate_inventory = StoredInventoryRecord(
        replace(
            original.record,
            inventory=duplicate_model,
            inventory_digest=_inventory_digest(duplicate_model),
        ),
        original.digest,
    )
    duplicate_policy = select_scylla_seeds(
        duplicate_inventory,
        mode=SeedSelectionMode.INITIAL,
        target_logical_id=old.logical_id,
    )
    with pytest.raises(StateConflictError, match="duplicated"):
        build_scylla_configure_payload(
            metadata,
            observed,
            duplicate_inventory,
            _readiness(duplicate_inventory),
            base_os,
            storage,
            install,
            duplicate_policy,
            logical_id=old.logical_id,
            package_version=VERSION,
            architecture="amd64",
            cluster_spec_digest=DIGEST,
        )
    assert payload


def test_configuration_refuses_relabel_and_prerequisite_provenance_mismatches() -> None:
    payload, metadata, observed, inventory, base_os, storage = _context()
    install_payload, _ = _install_context()
    install = parse_scylla_install_execution(
        _install_stdout(install_payload),
        expected_payload=install_payload,
        exit_code=0,
    )
    policy = select_scylla_seeds(
        inventory,
        mode=SeedSelectionMode.INITIAL,
        target_logical_id=cast(str, payload["logical_id"]),
    )
    prior = parse_scylla_configure_execution(
        _stdout(payload), expected_payload=payload, exit_code=0
    )
    host = inventory.record.inventory.hosts[0]
    relabeled = replace(host, scylla_rack="rack2")
    groups = (
        InventoryGroup("jump_hosts", ()),
        InventoryGroup("manager", ()),
        InventoryGroup("monitoring", ()),
        InventoryGroup("scylla", (relabeled.logical_id,)),
        InventoryGroup("scylla_dc_dc1", (relabeled.logical_id,)),
        InventoryGroup("scylla_rack_rack2", (relabeled.logical_id,)),
        InventoryGroup("zone_ad_1", (relabeled.logical_id,)),
    )
    model = InventoryModel(
        (relabeled,), groups, inventory.record.inventory.host_trust_status
    )
    changed_inventory = StoredInventoryRecord(
        replace(
            inventory.record,
            inventory=model,
            inventory_digest=_inventory_digest(model),
        ),
        inventory.digest,
    )
    changed_policy = select_scylla_seeds(
        changed_inventory,
        mode=SeedSelectionMode.INITIAL,
        target_logical_id=relabeled.logical_id,
    )
    with pytest.raises(StateConflictError, match="relabel"):
        build_scylla_configure_payload(
            metadata,
            observed,
            changed_inventory,
            _readiness(changed_inventory),
            base_os,
            storage,
            install,
            changed_policy,
            logical_id=relabeled.logical_id,
            package_version=VERSION,
            architecture="amd64",
            cluster_spec_digest=DIGEST,
            prior_configuration=prior,
        )
    for changed_install in (
        replace(install, service_masked=False),
        replace(install, installed_version="2026.2.0-invalid"),
    ):
        with pytest.raises(StateConflictError, match="requires current"):
            build_scylla_configure_payload(
                metadata,
                observed,
                inventory,
                _readiness(inventory),
                base_os,
                storage,
                changed_install,
                policy,
                logical_id=host.logical_id,
                package_version=VERSION,
                architecture="amd64",
                cluster_spec_digest=DIGEST,
            )
    stale_install = replace(
        install,
        provenance=tuple(
            (name, "sha256:" + "b" * 64 if name == "trust_digest" else value)
            for name, value in install.provenance
        ),
    )
    with pytest.raises(StateConflictError, match="digests conflict"):
        build_scylla_configure_payload(
            metadata,
            observed,
            inventory,
            _readiness(inventory),
            base_os,
            storage,
            stale_install,
            policy,
            logical_id=host.logical_id,
            package_version=VERSION,
            architecture="amd64",
            cluster_spec_digest=DIGEST,
        )


@pytest.mark.parametrize(
    ("status", "exit_code", "expected"),
    [
        ("changed", 0, ScyllaConfigureStatus.CHANGED),
        ("noop", 0, ScyllaConfigureStatus.NOOP),
        ("not-predicted", 0, ScyllaConfigureStatus.NOT_PREDICTED),
        ("failed", 2, ScyllaConfigureStatus.FAILED),
    ],
)
def test_configure_result_parser_statuses(
    status: str, exit_code: int, expected: ScyllaConfigureStatus
) -> None:
    payload, *_ = _context()
    failed = 1 if status == "failed" else 0
    evidence = parse_scylla_configure_execution(
        _stdout(payload, status, failed=failed),
        expected_payload=payload,
        exit_code=exit_code,
    )
    assert evidence.status is expected
    assert not evidence.runtime_validation_performed


def test_parser_rejects_raw_conflicts_unknown_blockers_and_oversize() -> None:
    payload, *_ = _context()
    with pytest.raises(AnsibleError, match="exceeds"):
        parse_scylla_configure_execution(
            "x" * (512 * 1024 + 1), expected_payload=payload, exit_code=2
        )
    result = _result(payload)
    result["config_digest"] = "sha256:" + "b" * 64
    encoded = base64.b64encode(json.dumps(result).encode()).decode()
    stdout = (
        f'{{"msg":"DSV_SCYLLA_CONFIGURE_B64={encoded}"}}\nPLAY RECAP *****\n'
        f"{payload['logical_id']} : ok=1 changed=0 unreachable=0 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    with pytest.raises(AnsibleError, match="digests conflict"):
        parse_scylla_configure_execution(stdout, expected_payload=payload, exit_code=0)


@pytest.mark.parametrize(
    ("check", "status"),
    [(False, "changed"), (True, "not-predicted")],
)
def test_service_uses_exact_limit_vars_redaction_and_normalized_result(
    tmp_path: Path, check: bool, status: str
) -> None:
    payload, metadata, observed, inventory, base_os, storage = _context()
    install_payload, _ = _install_context()
    install = parse_scylla_install_execution(
        _install_stdout(install_payload),
        expected_payload=install_payload,
        exit_code=0,
    )
    target = cast(str, payload["logical_id"])
    policy = select_scylla_seeds(
        inventory,  # type: ignore[arg-type]
        mode=SeedSelectionMode.INITIAL,
        target_logical_id=target,
    )
    paths = _paths(tmp_path)
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(0, _stdout(payload, status), ""),
        ]
    )
    service = AnsibleService(_builder(tmp_path, paths), runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute_scylla_configure(
            lock,
            metadata,  # type: ignore[arg-type]
            observed,  # type: ignore[arg-type]
            inventory,  # type: ignore[arg-type]
            base_os,  # type: ignore[arg-type]
            storage,  # type: ignore[arg-type]
            install,
            policy,
            limit=(target,),
            readiness=_readiness(inventory),  # type: ignore[arg-type]
            package_version=VERSION,
            architecture="amd64",
            cluster_spec_digest=DIGEST,
            check=check,
        )
    assert result.scylla_configure is not None
    assert result.scylla_configure.status is ScyllaConfigureStatus(status)
    assert result.stdout == result.stderr == ""
    runtime = cast(dict[str, object], runner.runtime_payloads[-1])
    assert runtime == {"deploy_scylla_vms_scylla_configure": payload}
    assert "--limit" in runner.specs[-1].argv
    assert target in runner.specs[-1].argv
    assert ("--check" in runner.specs[-1].argv) is check
    assert "10.0.0.20" in runner.specs[-1].sensitive_values
    assert not tuple(paths.ansible_local_tmp.iterdir())


def test_registry_templates_modes_and_forbidden_actions_are_exact() -> None:
    definition = get_playbook("scylla-configure")
    assert definition.source_available
    assert definition.hosts == "scylla"
    assert definition.serial == 1
    assert definition.limit_policy is LimitPolicy.SINGLE_LOGICAL_HOST
    assert definition.any_errors_fatal
    assert definition.check_mode is CheckMode.PREVIEW
    assert definition.tags == (
        "scylla-configure",
        "preflight",
        "configure",
        "service-safety",
        "verify",
    )
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content/playbooks"
    playbook = (root / "scylla-configure.yml").read_text(encoding="utf-8")
    tasks = (root / "roles/scylla_configure/tasks/main.yml").read_text(encoding="utf-8")
    scylla_yaml = (root / "roles/scylla_configure/templates/scylla.yaml.j2").read_text(
        encoding="utf-8"
    )
    rackdc = (
        root / "roles/scylla_configure/templates/cassandra-rackdc.properties.j2"
    ).read_text(encoding="utf-8")
    assert "gather_facts: true" in playbook
    assert "become: true" in playbook
    assert "serial: 1" in playbook
    assert "any_errors_fatal: true" in playbook
    assert "status': 'not-predicted'" in playbook
    assert "owner: root" in tasks
    assert "group: root" in tasks
    assert 'mode: "0644"' in tasks
    assert "masked: true" in tasks
    assert "state: stopped" in tasks
    assert (
        tuple(
            sorted(
                line.split(":", 1)[0]
                for line in scylla_yaml.splitlines()
                if line and not line.startswith(" ")
            )
        )
        == SCYLLA_CONFIGURE_KEYS
    )
    assert rackdc.splitlines() == [
        "dc={{ deploy_scylla_vms_scylla_configure.topology.datacenter }}",
        "rack={{ deploy_scylla_vms_scylla_configure.topology.rack }}",
        "prefer_local=true",
    ]
    all_text = (playbook + tasks + scylla_yaml + rackdc).lower()
    for forbidden in (
        "state: started",
        "ansible.builtin.apt:",
        "ansible.builtin.package:",
        "ansible.builtin.shell:",
        "scylla_setup",
        "nodetool",
        "manager-agent",
        "ansible.builtin.ufw:",
        "ansible.posix.firewalld:",
        "iptables",
        "reboot:",
        "mount:",
        "mkfs",
    ):
        assert forbidden not in all_text
    assert "runtime_validation_performed': false" in all_text
    assert HostRole.SCYLLA.value == "scylla"
