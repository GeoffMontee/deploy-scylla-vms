import base64
import json
import re
import sys
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import scylla_vms.ansible.commands as command_module
import scylla_vms.ansible.service as service_module
from scylla_vms.ansible.commands import AnsibleCommandBuilder
from scylla_vms.ansible.readiness import (
    EvidenceStatus,
    ReadinessReport,
    RouteReadiness,
    RouteReport,
    TrustReadiness,
)
from scylla_vms.ansible.registry import (
    OPERATION_PLAYBOOK_EXPORT,
    OPERATION_PLAYBOOKS,
    PLAYBOOK_NAMES,
    PLAYBOOKS,
    LimitPolicy,
    get_playbook,
)
from scylla_vms.ansible.service import (
    AnsibleService,
    ConnectivityStatus,
    DestinationProbeStatus,
    HostConnectivityStatus,
    parse_connectivity_evidence,
)
from scylla_vms.ansible.source import (
    load_ansible_source_bundle,
    stage_ansible_config,
)
from scylla_vms.ansible.toolchain import (
    DEPENDENCY_BLOCKER,
    AnsibleCoreVersion,
    AnsibleVersionError,
    parse_ansible_core_version,
)
from scylla_vms.desired import HostRole
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    ToolPrerequisiteError,
)
from scylla_vms.inventory import (
    HostTrustStatus,
    InventoryGroup,
    InventoryHost,
    InventoryModel,
    InventoryRecord,
    StoredInventoryRecord,
    _inventory_digest,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import ObservedStateRecord, StoredObservedState
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import ClusterMetadata
from scylla_vms.process import (
    ProcessResult,
    ProcessSpec,
    ProcessTimeoutError,
)
from scylla_vms.state import StatePaths, initialize_state_layout

CLUSTER_UUID = uuid.UUID("11111111-1111-4111-8111-111111111111")
DIGEST = "sha256:" + "a" * 64


class FakeRunner:
    def __init__(
        self,
        results: list[ProcessResult] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.results = list(results or [])
        self.error = error
        self.specs: list[ProcessSpec] = []
        self.runtime_modes: list[int] = []
        self.runtime_payloads: list[object] = []

    def run(self, spec: ProcessSpec) -> ProcessResult:
        self.specs.append(spec)
        if "--extra-vars" in spec.argv:
            argument = spec.argv[spec.argv.index("--extra-vars") + 1]
            path = Path(argument.removeprefix("@"))
            self.runtime_modes.append(path.stat().st_mode & 0o777)
            self.runtime_payloads.append(json.loads(path.read_text(encoding="utf-8")))
        if self.error is not None:
            raise self.error
        result = self.results.pop(0) if self.results else ProcessResult(0, "", "")
        stdout = result.stdout
        stderr = result.stderr
        for sensitive in spec.sensitive_values:
            stdout = stdout.replace(sensitive, "[REDACTED]")
            stderr = stderr.replace(sensitive, "[REDACTED]")
        return ProcessResult(result.exit_code, stdout, stderr)


def _executable(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    path.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n", encoding="utf-8")
    path.chmod(0o700)
    return path


def _paths(tmp_path: Path) -> StatePaths:
    paths = StatePaths.derive(tmp_path / "state", "example")
    initialize_state_layout(paths)
    paths.ansible_inventory.write_text("{}\n", encoding="utf-8")
    paths.ansible_inventory.chmod(0o600)
    paths.known_hosts.write_text("", encoding="utf-8")
    paths.known_hosts.chmod(0o600)
    paths.ansible_ssh_config.write_text("", encoding="utf-8")
    paths.ansible_ssh_config.chmod(0o600)
    with ClusterLock(paths, "deploy", 0) as lock:
        stage_ansible_config(paths, lock=lock)
    return paths


def _builder(tmp_path: Path, paths: StatePaths) -> AnsibleCommandBuilder:
    return AnsibleCommandBuilder(
        _executable(tmp_path, "ansible-playbook"),
        _executable(tmp_path, "ansible-inventory"),
        paths,
    )


def _inventory(
    trust: HostTrustStatus = HostTrustStatus.VERIFIED,
) -> StoredInventoryRecord:
    host = InventoryHost(
        "jump-host-1",
        HostRole.JUMP_HOST,
        "AD-1",
        "ocid1.instance.oc1.iad.fakejump",
        "10.0.0.10",
        "203.0.113.10",
        "203.0.113.10",
        "opc",
        "VM.Standard.E5.Flex",
        None,
        None,
        "direct",
        None,
        "boot-only",
        0,
        0,
        0,
        False,
        1,
        DIGEST,
    )
    groups = (
        InventoryGroup("jump_hosts", ("jump-host-1",)),
        InventoryGroup("manager", ()),
        InventoryGroup("monitoring", ()),
        InventoryGroup("scylla", ()),
        InventoryGroup("zone_ad_1", ("jump-host-1",)),
    )
    model = InventoryModel((host,), groups, trust)
    record = InventoryRecord(
        1,
        CLUSTER_UUID,
        "example",
        "oci",
        "2026-09-17T20:00:00Z",
        1,
        DIGEST,
        _inventory_digest(model),
        model,
    )
    return StoredInventoryRecord(record, DIGEST)


def _observed(
    *, generation: int = 1, manifest_digest: str = DIGEST
) -> StoredObservedState:
    record = cast(
        ObservedStateRecord,
        SimpleNamespace(
            cluster_uuid=CLUSTER_UUID,
            cluster_name="example",
            provider="oci",
            generation=generation,
            manifest_digest=manifest_digest,
            captured_at="2026-09-17T20:00:00Z",
        ),
    )
    return cast(StoredObservedState, SimpleNamespace(record=record, digest=DIGEST))


def _metadata() -> ClusterMetadata:
    return cast(
        ClusterMetadata,
        SimpleNamespace(
            cluster_uuid=CLUSTER_UUID, cluster_name="example", provider="oci"
        ),
    )


def _readiness(
    inventory: StoredInventoryRecord, *, blockers: tuple[str, ...] = ()
) -> ReadinessReport:
    return ReadinessReport(
        EvidenceStatus.FRESH,
        EvidenceStatus.FRESH,
        TrustReadiness.COMPLETE,
        RouteReadiness.VALID,
        1,
        DIGEST,
        inventory.record.generation,
        inventory.digest,
        1,
        DIGEST,
        len(inventory.record.inventory.hosts),
        len(inventory.record.inventory.hosts),
        (),
        RouteReport(RouteReadiness.VALID, 1, 0, 1, ()),
        tuple((classification, blockers) for classification in OperationClassification),
    )


def _inventory_preflight_output(
    inventory: StoredInventoryRecord,
    expected_hosts: tuple[str, ...] = ("jump-host-1",),
) -> str:
    record = inventory.record
    payload = {
        "host_count": len(record.inventory.hosts),
        "inventory_file_digest": inventory.digest,
        "inventory_generation": record.generation,
        "observation_digest": record.source_manifest_digest,
        "observation_generation": record.source_manifest_generation,
        "schema_version": "deploy-scylla-vms.ansible-inventory-preflight/v1",
        "status": "passed",
        "target_count": len(expected_hosts),
    }
    marker = base64.b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ).decode()
    return (
        f"ok: [{expected_hosts[0]}] => "
        f'{{"msg": "DSV_INVENTORY_PREFLIGHT_B64={marker}"}}\n'
        "PLAY RECAP *****\n"
        f"{expected_hosts[0]} : ok=3 changed=0 unreachable=0 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )


@pytest.mark.parametrize("name", ["ansible-playbook", "ansible-inventory"])
def test_ansible_version_contract(name: str) -> None:
    assert parse_ansible_core_version(
        f"{name} [core 2.19.3]\n", expected_executable=name
    ) == AnsibleCoreVersion(2, 19, 3)
    for invalid in (
        f"{name} [core 2.16.9]\n",
        f"{name} [core 2.21.0]\n",
        f"{name} [core 2.19.0rc1]\n",
        "ansible 2.19.0\n",
        "",
        b"\xff",
        "x" * (64 * 1024 + 1),
    ):
        with pytest.raises(AnsibleVersionError):
            parse_ansible_core_version(invalid, expected_executable=name)
    other = "ansible-inventory" if name == "ansible-playbook" else "ansible-playbook"
    with pytest.raises(AnsibleVersionError, match="wrong executable"):
        parse_ansible_core_version(f"{other} [core 2.19.3]\n", expected_executable=name)


def test_registry_matches_plan_catalog_and_closed_mappings() -> None:
    plan = (Path(__file__).parents[1] / "PLAN.md").read_text(encoding="utf-8")
    catalog = plan[plan.index("### Proposed playbook catalog") :]
    catalog = catalog[: catalog.index("## 8. SSH, bastions, and host trust")]
    documented = set(re.findall(r"`ansible/playbooks/([a-z0-9-]+)\.yml`", catalog))
    assert {book.name for book in PLAYBOOKS} == documented
    assert len(PLAYBOOKS) == 38
    assert tuple(book.name for book in PLAYBOOKS) == PLAYBOOK_NAMES
    assert dict(OPERATION_PLAYBOOK_EXPORT) == {
        operation: tuple((step.playbook, step.condition) for step in steps)
        for operation, steps in OPERATION_PLAYBOOKS.items()
    }
    assert len({book.name for book in PLAYBOOKS}) == len(PLAYBOOKS)
    assert set(OPERATION_PLAYBOOKS) == {
        "add-node",
        "check-jump-hosts",
        "deploy",
        "destroy",
        "destroy-node",
        "redeploy",
        "refresh-monitoring",
        "replace-node",
        "scale-in",
        "scale-out",
        "show",
        "upgrade-os",
    }
    assert OPERATION_PLAYBOOKS["show"] == ()
    assert all(
        get_playbook(step.playbook).name == step.playbook
        for steps in OPERATION_PLAYBOOKS.values()
        for step in steps
    )
    deploy = [step.playbook for step in OPERATION_PLAYBOOKS["deploy"]]
    assert deploy[:6] == [
        "inventory-preflight",
        "connectivity-check",
        "base-os",
        "jump-host-configure",
        "connectivity-check",
        "base-os",
    ]
    assert (
        get_playbook("scylla-remove-live").limit_policy
        is LimitPolicy.SINGLE_LOGICAL_HOST
    )
    assert {book.name for book in PLAYBOOKS if book.source_available} == {
        "base-os",
        "connectivity-check",
        "deploy-reboot",
        "evidence-collect",
        "inventory-preflight",
        "jump-host-configure",
        "manager-agent",
        "manager-backend-local-install",
        "manager-backend-preflight",
        "manager-backend-storage-discover",
        "manager-backend-storage-preflight",
        "manager-backend-storage-prepare",
        "manager-server",
        "manager-tasks",
        "monitoring-agent",
        "monitoring-stack",
        "monitoring-targets",
        "os-reprovision-prepare",
        "os-upgrade-in-place",
        "os-upgrade-postcheck",
        "os-upgrade-preflight",
        "routed-keyscan",
        "scylla-bootstrap",
        "scylla-cleanup",
        "scylla-cluster-shutdown",
        "scylla-configure",
        "scylla-health",
        "scylla-install",
        "scylla-remove-dead",
        "scylla-remove-live",
        "scylla-replace-dead",
        "scylla-repair",
        "service-converge",
        "storage-discover",
        "storage-postcheck",
        "storage-preflight",
        "storage-prepare",
        "storage-retire",
    }


def test_packaged_support_files_and_static_safety_contracts() -> None:
    bundle = load_ansible_source_bundle()
    assert bundle.version == "ansible-content/v1"
    assert {item.path for item in bundle.files} == {
        "ansible.cfg",
        "playbooks/base-os.yml",
        "playbooks/connectivity-check.yml",
        "playbooks/deploy-reboot.yml",
        "playbooks/evidence-collect.yml",
        "playbooks/inventory-preflight.yml",
        "playbooks/jump-host-configure.yml",
        "playbooks/manager-agent.yml",
        "playbooks/manager-backend-local-install.yml",
        "playbooks/manager-backend-preflight.yml",
        "playbooks/manager-backend-storage-discover.yml",
        "playbooks/manager-backend-storage-preflight.yml",
        "playbooks/manager-backend-storage-prepare.yml",
        "playbooks/manager-server.yml",
        "playbooks/manager-tasks.yml",
        "playbooks/monitoring-agent.yml",
        "playbooks/monitoring-stack.yml",
        "playbooks/monitoring-targets.yml",
        "playbooks/os-reprovision-prepare.yml",
        "playbooks/os-upgrade-in-place.yml",
        "playbooks/os-upgrade-postcheck.yml",
        "playbooks/os-upgrade-preflight.yml",
        "playbooks/routed-keyscan.yml",
        "playbooks/scylla-bootstrap.yml",
        "playbooks/scylla-cleanup.yml",
        "playbooks/scylla-cluster-shutdown.yml",
        "playbooks/scylla-configure.yml",
        "playbooks/scylla-health.yml",
        "playbooks/scylla-install.yml",
        "playbooks/scylla-remove-dead.yml",
        "playbooks/scylla-remove-live.yml",
        "playbooks/scylla-replace-dead.yml",
        "playbooks/scylla-repair.yml",
        "playbooks/service-converge.yml",
        "playbooks/storage-discover.yml",
        "playbooks/storage-postcheck.yml",
        "playbooks/storage-preflight.yml",
        "playbooks/storage-prepare.yml",
        "playbooks/storage-retire.yml",
        "requirements.yml",
        "playbooks/roles/base_os/tasks/Ubuntu.yml",
        "playbooks/roles/base_os/tasks/main.yml",
        "playbooks/roles/jump_host_configure/handlers/main.yml",
        "playbooks/roles/jump_host_configure/library/jump_host_configure.py",
        "playbooks/roles/jump_host_configure/tasks/main.yml",
        "playbooks/roles/manager_agent/files/scylladb-manager-3.12-key.provenance.yml",
        "playbooks/roles/manager_backend_local_install/files/manager-backend-local-install.provenance.yml",
        "playbooks/roles/manager_backend_local_install/tasks/main.yml",
        "playbooks/roles/manager_backend_preflight/files/manager-backend-preflight.provenance.yml",
        "playbooks/roles/manager_backend_preflight/library/manager_backend_preflight.py",
        "playbooks/roles/manager_backend_preflight/tasks/main.yml",
        "playbooks/roles/manager_backend_storage_discover/files/manager-backend-storage-discover.provenance.yml",
        "playbooks/roles/manager_backend_storage_discover/library/manager_backend_storage_discover.py",
        "playbooks/roles/manager_backend_storage_discover/tasks/main.yml",
        "playbooks/roles/manager_backend_storage_preflight/files/manager-backend-storage-preflight.provenance.yml",
        "playbooks/roles/manager_backend_storage_preflight/library/manager_backend_storage_preflight.py",
        "playbooks/roles/manager_backend_storage_preflight/tasks/main.yml",
        "playbooks/roles/manager_backend_storage_prepare/files/manager-backend-storage-prepare.provenance.yml",
        "playbooks/roles/manager_backend_storage_prepare/library/manager_backend_storage_prepare.py",
        "playbooks/roles/manager_backend_storage_prepare/tasks/main.yml",
        "playbooks/roles/manager_server/files/scylladb-manager-3.12-key.provenance.yml",
        "playbooks/roles/manager_tasks/files/scylladb-manager-3.12-tasks.provenance.yml",
        "playbooks/roles/monitoring_agent/files/scylladb-2026-node-exporter.provenance.yml",
        "playbooks/roles/monitoring_stack/files/scylla-monitoring-4.16.0.provenance.yml",
        "playbooks/roles/monitoring_targets/files/scylla-monitoring-4.16.0-targets.provenance.yml",
        "playbooks/roles/os_reprovision_prepare/files/os-reprovision-prepare.provenance.yml",
        "playbooks/roles/os_upgrade_in_place/files/os-upgrade-in-place.provenance.yml",
        "playbooks/roles/os_upgrade_postcheck/files/os-upgrade-postcheck.provenance.yml",
        "playbooks/roles/os_upgrade_postcheck/library/os_upgrade_postcheck.py",
        "playbooks/roles/os_upgrade_postcheck/tasks/main.yml",
        "playbooks/roles/os_upgrade_preflight/files/os-upgrade-preflight.provenance.yml",
        "playbooks/roles/os_upgrade_preflight/library/os_upgrade_preflight.py",
        "playbooks/roles/os_upgrade_preflight/tasks/main.yml",
        "playbooks/roles/routed_keyscan/library/routed_keyscan.py",
        "playbooks/roles/routed_keyscan/tasks/main.yml",
        "playbooks/roles/scylla_bootstrap/tasks/main.yml",
        "playbooks/roles/scylla_cleanup/library/scylla_cleanup.py",
        "playbooks/roles/scylla_cleanup/tasks/main.yml",
        "playbooks/roles/scylla_cluster_shutdown/files/scylla-cluster-shutdown.provenance.yml",
        "playbooks/roles/scylla_cluster_shutdown/library/scylla_cluster_shutdown.py",
        "playbooks/roles/scylla_cluster_shutdown/tasks/main.yml",
        "playbooks/roles/scylla_configure/tasks/main.yml",
        "playbooks/roles/scylla_configure/templates/cassandra-rackdc.properties.j2",
        "playbooks/roles/scylla_configure/templates/scylla.yaml.j2",
        "playbooks/roles/scylla_health/library/scylla_health.py",
        "playbooks/roles/scylla_health/tasks/main.yml",
        "playbooks/roles/scylla_install/files/scylladb-2026.asc",
        "playbooks/roles/scylla_install/files/scylladb-2026-key.provenance.yml",
        "playbooks/roles/scylla_remove_dead/library/scylla_remove_dead.py",
        "playbooks/roles/scylla_remove_dead/tasks/main.yml",
        "playbooks/roles/scylla_remove_live/library/scylla_remove_live.py",
        "playbooks/roles/scylla_remove_live/tasks/main.yml",
        "playbooks/roles/scylla_replace_dead/library/scylla_replace_dead.py",
        "playbooks/roles/scylla_replace_dead/tasks/main.yml",
        "playbooks/roles/scylla_repair/library/scylla_repair.py",
        "playbooks/roles/scylla_repair/tasks/main.yml",
        "playbooks/roles/service_converge/files/service-converge.provenance.yml",
        "playbooks/roles/service_converge/library/service_converge.py",
        "playbooks/roles/service_converge/tasks/main.yml",
        "playbooks/roles/storage_discover/library/storage_discover.py",
        "playbooks/roles/storage_discover/tasks/main.yml",
        "playbooks/roles/storage_postcheck/library/storage_postcheck.py",
        "playbooks/roles/storage_postcheck/tasks/main.yml",
        "playbooks/roles/storage_preflight/tasks/main.yml",
        "playbooks/roles/storage_prepare/library/storage_prepare.py",
        "playbooks/roles/storage_prepare/tasks/main.yml",
        "playbooks/roles/storage_retire/library/storage_retire.py",
        "playbooks/roles/storage_retire/tasks/main.yml",
    }
    root = Path(__file__).parents[1] / "scylla_vms/ansible/content"
    assert {path.name for path in (root / "playbooks").glob("*.yml")} == {
        "base-os.yml",
        "connectivity-check.yml",
        "deploy-reboot.yml",
        "evidence-collect.yml",
        "inventory-preflight.yml",
        "jump-host-configure.yml",
        "manager-agent.yml",
        "manager-backend-local-install.yml",
        "manager-backend-preflight.yml",
        "manager-backend-storage-discover.yml",
        "manager-backend-storage-preflight.yml",
        "manager-backend-storage-prepare.yml",
        "manager-server.yml",
        "manager-tasks.yml",
        "monitoring-agent.yml",
        "monitoring-stack.yml",
        "monitoring-targets.yml",
        "os-reprovision-prepare.yml",
        "os-upgrade-in-place.yml",
        "os-upgrade-postcheck.yml",
        "os-upgrade-preflight.yml",
        "routed-keyscan.yml",
        "scylla-bootstrap.yml",
        "scylla-cleanup.yml",
        "scylla-cluster-shutdown.yml",
        "scylla-configure.yml",
        "scylla-health.yml",
        "scylla-install.yml",
        "scylla-remove-dead.yml",
        "scylla-remove-live.yml",
        "scylla-replace-dead.yml",
        "scylla-repair.yml",
        "service-converge.yml",
        "storage-discover.yml",
        "storage-postcheck.yml",
        "storage-preflight.yml",
        "storage-prepare.yml",
        "storage-retire.yml",
    }
    config = (root / "ansible.cfg").read_text(encoding="utf-8")
    assert "host_key_checking = True" in config
    assert "retry_files_enabled = False" in config
    assert "StrictHostKeyChecking=no" not in config
    assert "@@INVENTORY@@" in config
    assert "@@LOG_PATH@@" in config
    requirements = (root / "requirements.yml").read_text(encoding="utf-8")
    assert "collections: []" in requirements
    assert "name: scylladb.scylla_node" in requirements
    assert "42592128ff0399be8ffa18dbc985c4b026e7abd0" in requirements
    assert "future Scylla configuration" in DEPENDENCY_BLOCKER
    package_config = (Path(__file__).parents[1] / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    assert '"content/**/*.yml"' in package_config
    assert '"content/**/*.asc"' in package_config
    assert '"content/**/*.j2"' in package_config
    for playbook in (root / "playbooks").glob("*.yml"):
        text = playbook.read_text(encoding="utf-8")
        assert "StrictHostKeyChecking=no" not in text
        assert "host_key_checking = False" not in text
        assert "ansible.builtin.shell" not in text
        assert "ansible.builtin.uri" not in text
        if playbook.name in {
            "evidence-collect.yml",
            "manager-agent.yml",
            "manager-server.yml",
            "manager-tasks.yml",
            "monitoring-agent.yml",
            "monitoring-stack.yml",
            "monitoring-targets.yml",
            "scylla-install.yml",
        }:
            assert "ansible.builtin.command:" in text
            assert "argv:" in text
            assert "_raw_params:" not in text
        else:
            assert "ansible.builtin.command" not in text
    connectivity = (root / "playbooks/connectivity-check.yml").read_text(
        encoding="utf-8"
    )
    assert "ansible.builtin.ping:" in connectivity
    assert "ansible.builtin.wait_for:" in connectivity
    assert "state: started" in connectivity
    assert "failed_when: false" in connectivity
    assert "DSV_TCP" in connectivity
    reboot = (root / "playbooks/deploy-reboot.yml").read_text(encoding="utf-8")
    assert "serial: 1" in reboot
    assert "any_errors_fatal: true" in reboot
    assert "not ansible_check_mode" in reboot
    assert "ansible.builtin.reboot:" in reboot
    assert "reboot_timeout:" in reboot
    assert "connect_timeout:" in reboot
    assert "ansible.builtin.slurp:" in reboot
    assert "/proc/sys/kernel/random/boot_id" in reboot
    assert "| hash('sha256')" in reboot
    assert "/var/run/reboot-required" in reboot
    assert "deploy_scylla_vms_host_key_checking_required is sameas true" in reboot
    assert "DSV_DEPLOY_REBOOT_B64=" in reboot
    assert "ansible.builtin.shell" not in reboot
    assert "ansible.builtin.command" not in reboot


def test_staged_config_anchors_every_controller_runtime_path(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    text = paths.ansible_config.read_text(encoding="utf-8")
    assert "@@" not in text
    for path in (
        paths.ansible_inventory,
        paths.ansible_home,
        paths.ansible_local_tmp,
        paths.ansible_fact_cache,
        paths.ansible_control_path,
        paths.ansible_ssh_config,
        paths.ansible_log,
    ):
        assert str(path) in text
    assert paths.ansible_config.stat().st_mode & 0o777 == 0o600


def test_builder_exact_environment_and_missing_source_refusal(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    builder = _builder(tmp_path, paths)
    command = builder.inventory_list()
    assert command.process.argv == (
        str(tmp_path / "ansible-inventory"),
        "--inventory",
        str(paths.ansible_inventory),
        "--list",
    )
    assert command.process.cwd == paths.ansible
    assert command.process.environment.for_subprocess() == {
        "ANSIBLE_CONFIG": str(paths.ansible_config),
        "ANSIBLE_HOST_KEY_CHECKING": "True",
        "ANSIBLE_LOCAL_TEMP": str(paths.ansible_local_tmp),
        "ANSIBLE_NOCOLOR": "1",
        "ANSIBLE_RETRY_FILES_ENABLED": "False",
        "HOME": str(paths.ansible_home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONUNBUFFERED": "1",
        **(
            {"__CF_USER_TEXT_ENCODING": f"0x{__import__('os').getuid():X}:0x0:0x0"}
            if sys.platform == "darwin"
            else {}
        ),
    }
    assert builder.syntax_check("inventory-preflight").playbook == "inventory-preflight"
    assert builder.syntax_check("routed-keyscan").playbook == "routed-keyscan"
    assert builder.syntax_check("evidence-collect").playbook == "evidence-collect"
    assert builder.syntax_check("base-os").playbook == "base-os"
    assert builder.syntax_check("deploy-reboot").playbook == "deploy-reboot"
    assert builder.syntax_check("jump-host-configure").playbook == "jump-host-configure"
    assert builder.syntax_check("manager-agent").playbook == "manager-agent"
    assert builder.syntax_check("manager-server").playbook == "manager-server"
    assert builder.syntax_check("manager-tasks").playbook == "manager-tasks"
    assert builder.syntax_check("storage-retire").playbook == "storage-retire"
    assert builder.syntax_check("service-converge").playbook == "service-converge"
    assert (
        builder.syntax_check("scylla-cluster-shutdown").playbook
        == "scylla-cluster-shutdown"
    )
    assert (
        builder.syntax_check("os-reprovision-prepare").playbook
        == "os-reprovision-prepare"
    )
    with pytest.raises(AnsibleError, match="registry-approved"):
        builder.syntax_check("../../arbitrary")
    with pytest.raises(ToolPrerequisiteError):
        AnsibleCommandBuilder(
            tmp_path / "missing-playbook",
            tmp_path / "missing-inventory",
            paths,
        )


def test_builder_closes_tags_limits_modes_and_uses_runtime_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    builder = _builder(tmp_path, paths)
    definition = replace(get_playbook("inventory-preflight"), source_available=True)
    fixture = (
        Path(__file__).parent / "fixtures" / "ansible" / "localhost-check.yml"
    ).resolve()
    monkeypatch.setattr(command_module, "get_playbook", lambda _: definition)
    monkeypatch.setattr(command_module, "packaged_playbook_path", lambda _: fixture)
    runtime = paths.ansible_local_tmp / "extra-vars-test.json"
    runtime.write_text("{}\n", encoding="utf-8")
    runtime.chmod(0o600)
    command = builder.playbook(
        "inventory-preflight",
        limit=("jump-host-1",),
        extra_vars_path=runtime,
        tags=("preflight",),
        check=True,
        verbosity=2,
    )
    assert command.process.argv == (
        str(tmp_path / "ansible-playbook"),
        "--inventory",
        str(paths.ansible_inventory),
        "--limit",
        "jump-host-1",
        "--extra-vars",
        f"@{runtime}",
        "--tags",
        "preflight",
        "--check",
        "-vv",
        str(fixture),
    )
    assert str(paths.cluster_root) not in repr(command)
    assert any(
        "[REDACTED_PATH]" in argument for argument in command.process.display_argv()
    )
    with pytest.raises(AnsibleError, match="allowlisted"):
        builder.playbook(
            "inventory-preflight",
            limit=("jump-host-1",),
            extra_vars_path=runtime,
            tags=("skip-safety",),
        )
    with pytest.raises(AnsibleError, match="diff requires"):
        builder.playbook(
            "inventory-preflight",
            limit=("jump-host-1",),
            extra_vars_path=runtime,
            diff=True,
        )
    with pytest.raises(AnsibleError, match="diff mode is refused"):
        builder.playbook(
            "inventory-preflight",
            limit=("jump-host-1",),
            extra_vars_path=runtime,
            check=True,
            diff=True,
        )
    with pytest.raises(AnsibleError, match="approved runtime"):
        builder.playbook(
            "inventory-preflight",
            limit=("jump-host-1",),
            extra_vars_path=tmp_path / "vars.json",
        )


def test_service_versions_and_validates_fresh_inventory(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    inventory = _inventory()
    listed = json.dumps(inventory.record.to_machine_object())
    graph = "@all:\n" + "".join(
        f"  |--@{group.name}:\n" + "".join(f"  |  |--{host}\n" for host in group.hosts)
        for group in inventory.record.inventory.groups
    )
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.19.3]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.19.3]\n", ""),
            ProcessResult(0, listed, ""),
            ProcessResult(0, graph, ""),
        ]
    )
    service = AnsibleService(_builder(tmp_path, paths), runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        assert service.version(lock).core == AnsibleCoreVersion(2, 19, 3)
        report = service.validate_inventory(lock, _observed(), inventory, None)
        assert report.machine_status is EvidenceStatus.FRESH
        assert report.trust_status is TrustReadiness.INCOMPLETE
    assert len(runner.specs) == 4
    runner.results.extend((ProcessResult(0, listed, ""), ProcessResult(0, graph, "")))
    with ClusterLock(paths, "deploy", 0) as lock:
        stale = service.validate_inventory(
            lock, _observed(generation=2), inventory, None
        )
    assert stale.source_status is EvidenceStatus.STALE


def test_service_refuses_conflicting_versions_and_malformed_inventory(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    mismatch = AnsibleService(
        _builder(tmp_path, paths),
        FakeRunner(
            [
                ProcessResult(0, "ansible-playbook [core 2.20.8]\n", ""),
                ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ]
        ),
    )
    with (
        ClusterLock(paths, "deploy", 0) as lock,
        pytest.raises(AnsibleError, match="versions conflict"),
    ):
        mismatch.version(lock)

    malformed = AnsibleService(
        _builder(tmp_path, paths),
        FakeRunner(
            [
                ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
                ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
                ProcessResult(0, "{not-json", ""),
                ProcessResult(0, "@all:\n", ""),
            ]
        ),
    )
    with ClusterLock(paths, "deploy", 0) as lock:
        malformed.version(lock)
    with ClusterLock(paths, "deploy", 0) as lock:
        report = malformed.validate_inventory(lock, _observed(), _inventory(), None)
    assert report.machine_status is EvidenceStatus.CONFLICT


def test_service_refuses_unknown_source_before_runtime_write(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.19.3]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.19.3]\n", ""),
        ]
    )
    service = AnsibleService(_builder(tmp_path, paths), runner)
    metadata = _metadata()
    inventory = _inventory()
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        with pytest.raises(AnsibleError, match="registry-approved"):
            service.syntax_check(lock, "not-cataloged")
        with pytest.raises(AnsibleError, match="registry-approved"):
            service.execute(
                lock,
                metadata,
                inventory,
                "not-cataloged",
                limit=("jump-host-1",),
                variables={},
                readiness=_readiness(inventory),
            )
    assert not tuple(paths.ansible_local_tmp.iterdir())


@pytest.mark.parametrize("fail", [False, True])
def test_service_runtime_vars_are_owner_only_and_always_cleaned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail: bool
) -> None:
    paths = _paths(tmp_path)
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.19.3]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.19.3]\n", ""),
            ProcessResult(0, _inventory_preflight_output(_inventory()), ""),
        ],
        AnsibleError("simulated failure") if fail else None,
    )
    if fail:
        runner.error = None
    service = AnsibleService(_builder(tmp_path, paths), runner)
    original = get_playbook("inventory-preflight")
    available = replace(original, source_available=True)
    fixture = (
        Path(__file__).parent / "fixtures" / "ansible" / "localhost-check.yml"
    ).resolve()
    monkeypatch.setattr(service_module, "get_playbook", lambda _: available)
    monkeypatch.setattr(command_module, "get_playbook", lambda _: available)
    monkeypatch.setattr(command_module, "packaged_playbook_path", lambda _: fixture)
    inventory = _inventory()
    metadata = _metadata()
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        if fail:
            runner.error = ProcessTimeoutError("simulated timeout")
            with pytest.raises(AnsibleError):
                service.execute(
                    lock,
                    metadata,
                    inventory,
                    "inventory-preflight",
                    limit=("jump-host-1",),
                    variables={"deploy_scylla_vms_cluster_uuid": str(CLUSTER_UUID)},
                    readiness=_readiness(inventory),
                    check=True,
                )
        else:
            service.execute(
                lock,
                metadata,
                inventory,
                "inventory-preflight",
                limit=("jump-host-1",),
                variables={"deploy_scylla_vms_cluster_uuid": str(CLUSTER_UUID)},
                readiness=_readiness(inventory),
                check=True,
            )
    assert runner.runtime_modes == [0o600]
    payload = cast(dict[str, object], runner.runtime_payloads[0])
    assert payload["deploy_scylla_vms_cluster_uuid"] == str(CLUSTER_UUID)
    assert payload["deploy_scylla_vms_operation_targets"] == ["jump-host-1"]
    expected_hosts = cast(
        list[dict[str, object]], payload["deploy_scylla_vms_expected_hosts"]
    )
    assert expected_hosts[0]["logical_id"] == "jump-host-1"
    assert "ocid1.instance.oc1.iad.fakejump" in runner.specs[-1].sensitive_values
    assert "203.0.113.10" in runner.specs[-1].sensitive_values
    assert str(CLUSTER_UUID) in runner.specs[-1].sensitive_values
    assert not tuple(paths.ansible_local_tmp.iterdir())


def test_connectivity_evidence_success_partial_failure_and_conflicts() -> None:
    success = (
        "PLAY RECAP ****\n"
        "jump-host-1 : ok=2 changed=0 unreachable=0 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    evidence = parse_connectivity_evidence(success, ("jump-host-1",), 0)
    assert evidence.status is ConnectivityStatus.SUCCESS
    assert evidence.hosts[0].status is HostConnectivityStatus.REACHABLE
    destination = (
        'ok: [jump-host-1] => {"msg": "DSV_TCP jump-host-1 '
        'scylla-1 scylla 9042 passed"}\n' + success
    )
    evidence = parse_connectivity_evidence(
        destination,
        ("jump-host-1",),
        0,
        expected_probes=(("jump-host-1", "scylla-1", "scylla", 9042),),
    )
    assert evidence.destination_probes[0].status is DestinationProbeStatus.PASSED
    failed_destination = destination.replace("9042 passed", "9042 failed")
    evidence = parse_connectivity_evidence(
        failed_destination,
        ("jump-host-1",),
        0,
        expected_probes=(("jump-host-1", "scylla-1", "scylla", 9042),),
    )
    assert evidence.status is ConnectivityStatus.PARTIAL_FAILURE
    assert evidence.destination_probes[0].status is DestinationProbeStatus.FAILED
    with pytest.raises(AnsibleError, match="incomplete"):
        parse_connectivity_evidence(
            success,
            ("jump-host-1",),
            0,
            expected_probes=(("jump-host-1", "scylla-1", "scylla", 9042),),
        )

    partial = (
        "PLAY RECAP ****\n"
        "jump-host-1 : ok=2 changed=0 unreachable=0 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
        "manager-1 : ok=1 changed=0 unreachable=1 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    evidence = parse_connectivity_evidence(partial, ("jump-host-1", "manager-1"), 4)
    assert evidence.status is ConnectivityStatus.PARTIAL_FAILURE
    assert dict((item.logical_id, item.status) for item in evidence.hosts) == {
        "jump-host-1": HostConnectivityStatus.REACHABLE,
        "manager-1": HostConnectivityStatus.UNREACHABLE,
    }
    with pytest.raises(AnsibleError, match="membership conflicts"):
        parse_connectivity_evidence(success, ("manager-1",), 0)
    with pytest.raises(AnsibleError, match="exit status conflicts"):
        parse_connectivity_evidence(success, ("jump-host-1",), 4)


def test_destination_probe_variable_schema_rejects_public_self_and_excess() -> None:
    definition = get_playbook("connectivity-check")

    def probe(index: int) -> dict[str, object]:
        return {
            "address": f"10.0.0.{index + 1}",
            "jump_host_id": "jump-host-1",
            "port": 9042,
            "role": "scylla",
            "target_logical_id": f"scylla-{index + 1}",
        }

    assert definition.validate_variables(
        {"deploy_scylla_vms_destination_probes": [probe(0)]}
    )
    public = probe(0)
    public["address"] = "203.0.113.20"
    self_probe = probe(0)
    self_probe["target_logical_id"] = "jump-host-1"
    for value in (public, self_probe):
        with pytest.raises(AnsibleError, match="variable value is invalid"):
            definition.validate_variables(
                {"deploy_scylla_vms_destination_probes": [value]}
            )
    with pytest.raises(AnsibleError, match="variable value is invalid"):
        definition.validate_variables(
            {
                "deploy_scylla_vms_destination_probes": [
                    probe(index) for index in range(65)
                ]
            }
        )


def test_connectivity_service_preserves_partial_results_and_timeout(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    partial = (
        "PLAY RECAP ****\n"
        "jump-host-1 : ok=1 changed=0 unreachable=1 failed=0 "
        "skipped=0 rescued=0 ignored=0\n"
    )
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.19.3]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.19.3]\n", ""),
            ProcessResult(4, partial, "redacted failure"),
        ]
    )
    inventory = _inventory()
    service = AnsibleService(_builder(tmp_path, paths), runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute(
            lock,
            _metadata(),
            inventory,
            "connectivity-check",
            limit=("jump-host-1",),
            variables={},
            readiness=_readiness(inventory),
            check=True,
        )
    assert result.exit_code == 4
    assert result.connectivity is not None
    assert result.connectivity.status is ConnectivityStatus.FAILURE
    assert runner.specs[-1].allowed_exit_codes == frozenset({0, 2, 4})
    assert not tuple(paths.ansible_local_tmp.iterdir())


def test_inventory_preflight_runs_locally_in_check_mode(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    inventory = _inventory()
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.19.3]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.19.3]\n", ""),
            ProcessResult(0, _inventory_preflight_output(inventory), ""),
        ]
    )
    before_inventory = paths.ansible_inventory.read_bytes()
    before_known_hosts = paths.known_hosts.read_bytes()
    service = AnsibleService(_builder(tmp_path, paths), runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute(
            lock,
            _metadata(),
            inventory,
            "inventory-preflight",
            limit=("jump-host-1",),
            variables={},
            readiness=_readiness(inventory),
            check=True,
        )
    assert result.exit_code == 0
    assert result.inventory_preflight is not None
    assert result.inventory_preflight.status == "passed"
    assert result.stdout == result.stderr == ""
    assert runner.specs[-1].argv[-2] == "--check"
    assert paths.ansible_inventory.read_bytes() == before_inventory
    assert paths.known_hosts.read_bytes() == before_known_hosts
    assert not tuple(paths.ansible_local_tmp.iterdir())

    timeout_runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.19.3]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.19.3]\n", ""),
        ]
    )
    timeout_service = AnsibleService(_builder(tmp_path, paths), timeout_runner)
    with ClusterLock(paths, "deploy", 0) as lock:
        timeout_service.version(lock)
        timeout_runner.error = ProcessTimeoutError("simulated timeout")
        with pytest.raises(AnsibleError, match="connectivity-check command failed"):
            timeout_service.execute(
                lock,
                _metadata(),
                inventory,
                "connectivity-check",
                limit=("jump-host-1",),
                variables={},
                readiness=_readiness(inventory),
            )
    assert not tuple(paths.ansible_local_tmp.iterdir())


def test_service_refuses_untrusted_inventory_unknown_limit_and_bad_vars(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.19.3]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.19.3]\n", ""),
        ]
    )
    service = AnsibleService(_builder(tmp_path, paths), runner)
    metadata = _metadata()
    inventory = _inventory()
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        with pytest.raises(StateConflictError, match="readiness"):
            service.execute(
                lock,
                metadata,
                inventory,
                "connectivity-check",
                limit=("jump-host-1",),
                variables={},
                readiness=_readiness(inventory, blockers=("trust-incomplete",)),
            )
        with pytest.raises(StateConflictError, match="unknown stable"):
            service.execute(
                lock,
                metadata,
                inventory,
                "inventory-preflight",
                limit=("arbitrary-host",),
                variables={},
                readiness=_readiness(inventory),
            )
        with pytest.raises(AnsibleError, match="allowlisted"):
            service.execute(
                lock,
                metadata,
                inventory,
                "inventory-preflight",
                limit=("jump-host-1",),
                variables={"password": "not-allowed"},
                readiness=_readiness(inventory),
            )
        with pytest.raises(AnsibleError, match="value is invalid"):
            service.execute(
                lock,
                metadata,
                inventory,
                "inventory-preflight",
                limit=("jump-host-1",),
                variables={"deploy_scylla_vms_checkpoint_id": "token=not-allowed"},
                readiness=_readiness(inventory),
            )
    assert not tuple(paths.ansible_local_tmp.iterdir())


def test_preflight_requires_fresh_inventory_but_not_host_trust(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.19.3]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.19.3]\n", ""),
            ProcessResult(0, _inventory_preflight_output(_inventory()), ""),
        ]
    )
    inventory = _inventory()
    service = AnsibleService(_builder(tmp_path, paths), runner)
    trust_only_blocker = _readiness(inventory, blockers=("trust-incomplete",))
    with ClusterLock(paths, "deploy", 0) as lock:
        service.version(lock)
        result = service.execute(
            lock,
            _metadata(),
            inventory,
            "inventory-preflight",
            limit=("jump-host-1",),
            variables={},
            readiness=trust_only_blocker,
        )
        assert result.exit_code == 0
        stale = replace(trust_only_blocker, source_status=EvidenceStatus.STALE)
        with pytest.raises(StateConflictError, match="fresh source"):
            service.execute(
                lock,
                _metadata(),
                inventory,
                "inventory-preflight",
                limit=("jump-host-1",),
                variables={},
                readiness=stale,
            )
    assert not tuple(paths.ansible_local_tmp.iterdir())
