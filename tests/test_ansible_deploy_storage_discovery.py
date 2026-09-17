import base64
import inspect
import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

import pytest
from test_ansible_deploy_non_jump_reboot_reconciliation import (
    _call as _reconcile_non_jump_reboot,
)
from test_ansible_deploy_non_jump_reboot_reconciliation import (
    _prepared as _post_reboot_prepared,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_reconciliation as deploy_reconciliation_module
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_storage_discovery import (
    ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION,
    DeployPostStorageDiscoveryReconciliationStore,
    DeployStorageDiscoveryEvidenceStore,
    DeployStorageDiscoveryExecution,
    DeployStorageDiscoveryExecutionState,
    DeployStorageDiscoveryExecutionStore,
    deploy_post_storage_discovery_reconciliation_path,
    deploy_storage_discovery_evidence_path,
    deploy_storage_discovery_execution_path,
    execute_deploy_storage_discovery,
    reconcile_deploy_storage_discovery,
)
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.ansible.storage import STORAGE_DISCOVERY_SCHEMA_VERSION
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.inventory import InventoryStore, StoredInventoryRecord
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.persistence import serialize_json
from scylla_vms.process import (
    ProcessOutputError,
    ProcessResult,
    ProcessSpec,
    ProcessTimeoutError,
)

_SECRET = "obviously-fake-storage-discovery-secret"
_PRIVATE_PATH = "/private/operator/storage-discovery.json"


@dataclass
class StorageDiscoveryRunner:
    inventory: StoredInventoryRecord
    mode: str = "success"
    inspect_started: Any = None
    specs: list[ProcessSpec] | None = None
    variables: list[dict[str, object]] | None = None

    def __post_init__(self) -> None:
        self.specs = []
        self.variables = []

    def run(self, spec: ProcessSpec) -> ProcessResult:
        assert self.specs is not None
        assert self.variables is not None
        self.specs.append(spec)
        if spec.argv[-1] == "--version":
            name = Path(spec.argv[0]).name
            return ProcessResult(0, f"{name} [core 2.20.9]\n", "")
        playbook = next(
            Path(argument).stem
            for argument in spec.argv
            if "/playbooks/" in argument and argument.endswith(".yml")
        )
        if playbook != "storage-discover":
            raise AssertionError(f"unexpected playbook or external tool: {playbook}")
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        variables = cast(
            dict[str, object], json.loads(runtime_file.read_text(encoding="utf-8"))
        )
        self.variables.append(variables)
        if self.inspect_started is not None:
            self.inspect_started()
        if self.mode == "timeout":
            raise ProcessTimeoutError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "interrupted":
            raise KeyboardInterrupt
        if self.mode == "non-utf8":
            raise ProcessOutputError(f"{_SECRET} {_PRIVATE_PATH}")
        if self.mode == "oversized":
            return ProcessResult(0, "x" * (4 * 1024 * 1024 + 1), _SECRET)
        limit = tuple(spec.argv[spec.argv.index("--limit") + 1].split(","))
        return self._result(limit, variables)

    def _result(
        self, limit: tuple[str, ...], variables: dict[str, object]
    ) -> ProcessResult:
        hosts = {
            host.logical_id: host for host in self.inventory.record.inventory.hosts
        }
        markers: list[str] = []
        recaps: list[str] = []
        for index, stable_id in enumerate(limit):
            failed = self.mode == "nonzero" and index == 0
            unreachable = self.mode == "unreachable" and index == 0
            omit = self.mode in {"missing-host", "malformed"} and index == 0
            if not omit and not unreachable:
                marker_id = "wrong-host" if self.mode == "wrong-host" else stable_id
                value = self._host(
                    marker_id,
                    hosts[stable_id],
                    variables,
                    device_mode=self.mode,
                )
                markers.append(self._marker(marker_id, value))
                if self.mode == "duplicate-host" and index == 0:
                    markers.append(markers[-1])
            recaps.append(
                f"{stable_id} : ok=3 changed=0 "
                f"unreachable={int(unreachable)} failed={int(failed)} "
                "skipped=0 rescued=0 ignored=0"
            )
        if self.mode == "extra-host":
            source = hosts[limit[0]]
            markers.append(
                self._marker(
                    "extra-host",
                    self._host("extra-host", source, variables, device_mode="success"),
                )
            )
            recaps.append(
                "extra-host : ok=3 changed=0 unreachable=0 failed=0 "
                "skipped=0 rescued=0 ignored=0"
            )
        stdout = "".join(markers) + "PLAY RECAP *****\n" + "\n".join(recaps) + "\n"
        exit_code = (
            4 if self.mode == "unreachable" else 2 if self.mode == "nonzero" else 0
        )
        stderr = "" if self.mode == "unreachable" else (f"{_SECRET} {_PRIVATE_PATH}")
        return ProcessResult(exit_code, stdout, stderr)

    def _host(
        self,
        stable_id: str,
        inventory_host: Any,
        variables: dict[str, object],
        *,
        device_mode: str,
    ) -> dict[str, object]:
        devices = [self._device()]
        if device_mode == "duplicate-device":
            devices.append(dict(devices[0]))
        elif device_mode == "missing-device-field":
            devices[0].pop("size_bytes")
        elif device_mode == "extra-devices":
            devices = [
                self._device(
                    stable_id=f"by-id:fake-device-{index:03d}",
                    path=f"/dev/fake{index:03d}",
                )
                for index in range(257)
            ]
        return {
            "cluster_uuid": variables["deploy_scylla_vms_cluster_uuid"],
            "devices": devices,
            "host_manifest_digest": (
                variables["deploy_scylla_vms_host_manifest_digest"]
            ),
            "inventory_digest": (variables["deploy_scylla_vms_inventory_file_digest"]),
            "inventory_generation": (
                variables["deploy_scylla_vms_inventory_generation"]
            ),
            "logical_id": stable_id,
            "mounts": ["/"],
            "observation_digest": (variables["deploy_scylla_vms_observation_digest"]),
            "observation_generation": (
                variables["deploy_scylla_vms_observation_generation"]
            ),
            "provider_id": inventory_host.provider_id,
            "schema_version": STORAGE_DISCOVERY_SCHEMA_VERSION,
            "storage_generation": inventory_host.storage_generation,
            "storage_policy_digest": inventory_host.storage_policy_digest,
            "tools": {
                "blkid": "available",
                "by-id": "available",
                "findmnt": "available",
                "lsblk": "available",
                "lvm": "unavailable",
                "md": "unavailable",
                "nvme": "unavailable",
                "wipefs": "available",
            },
        }

    @staticmethod
    def _device(
        *,
        stable_id: str = "by-id:fake-data-device",
        path: str = "/dev/sdb",
    ) -> dict[str, object]:
        return {
            "boot_ancestor": False,
            "by_id": [f"/dev/disk/by-id/{stable_id.removeprefix('by-id:')}"],
            "filesystem": None,
            "holders": [],
            "kind": "disk",
            "mount_points": [],
            "nvme": None,
            "ownership": None,
            "ownership_marker": "absent",
            "parents": [],
            "path": path,
            "provider_attachment_ids": [
                "ocid1.volume.oc1.iad.fake",
                "ocid1.volumeattachment.oc1.iad.fake",
            ],
            "root_ancestor": False,
            "serial": "sensitive-fake-serial",
            "signatures": [],
            "size_bytes": 536_870_912_000,
            "stable_id": stable_id,
            "transport": "scsi",
            "wwn": "sensitive-fake-wwn",
        }

    @staticmethod
    def _marker(stable_id: str, value: dict[str, object]) -> str:
        encoded = base64.b64encode(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        return f'ok: [{stable_id}] => {{"msg":"DSV_STORAGE_DISCOVERY_B64={encoded}"}}\n'


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, _runner, executables, toolchain = _post_reboot_prepared(
        tmp_path, monkeypatch, mode="no-change"
    )
    _reconcile_non_jump_reboot(prepared)
    inventory = InventoryStore(prepared.paths).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
        expected_provider="oci",
    )
    return prepared, inventory, executables, toolchain


def _execute(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_storage_discovery(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )


def _reconcile(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_storage_discovery(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _records(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        execution = DeployStorageDiscoveryExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployStorageDiscoveryEvidenceStore(
            prepared.paths, OPERATION_ID
        )
        evidence = (
            evidence_store.read_locked(
                lock,
                expected_cluster_uuid=CLUSTER_UUID,
                expected_cluster_name="example",
            )
            if evidence_store.path.exists()
            else None
        )
    return execution, evidence


def test_exact_scope_command_hashed_evidence_reentry_and_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(inspect.signature(execute_deploy_storage_discovery).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "runner",
        "executables",
        "toolchain",
    )
    assert tuple(inspect.signature(reconcile_deploy_storage_discovery).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    prior_path = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-post-non-jump-reboot-reconciliation.json"
    )
    immutable = (journal_path.read_bytes(), prior_path.read_bytes())
    show_before = _run_show(prepared.paths)
    runner = StorageDiscoveryRunner(inventory)

    report = _execute(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)

    assert (
        report.schema_version
        == ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert (
        execution.record.schema_version
        == ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EXECUTION_SCHEMA_VERSION
    )
    assert evidence is not None
    assert (
        evidence.record.schema_version
        == ANSIBLE_DEPLOY_STORAGE_DISCOVERY_EVIDENCE_SCHEMA_VERSION
    )
    assert report.execution_state is DeployStorageDiscoveryExecutionState.SUCCEEDED
    assert report.invocation_count == 1
    assert report.target_count == report.discovered_host_count == 1
    assert report.device_count == 1
    assert report.journal_status is JournalStatus.IN_PROGRESS
    assert report.journal_phase is OperationPhase.VERIFY
    assert (journal_path.read_bytes(), prior_path.read_bytes()) == immutable
    assert runner.specs is not None and runner.variables is not None
    assert tuple(Path(spec.argv[0]).name for spec in runner.specs) == (
        "ansible-playbook",
        "ansible-inventory",
        "ansible-playbook",
    )
    playbook_sources = tuple(
        argument
        for observed in runner.specs
        for argument in observed.argv
        if "/playbooks/" in argument
    )
    assert len(playbook_sources) == 1
    assert playbook_sources[0].endswith("/playbooks/storage-discover.yml")
    spec = runner.specs[-1]
    assert spec.argv[spec.argv.index("--limit") + 1] == "scylla-ad-1-1"
    assert spec.argv[-1].endswith("/playbooks/storage-discover.yml")
    assert "--check" not in spec.argv
    assert "--tags" not in spec.argv
    assert spec.cwd == prepared.paths.ansible
    assert runner.variables[0]["deploy_scylla_vms_inventory_generation"] == (
        inventory.record.generation
    )
    assert not tuple(prepared.paths.ansible_local_tmp.iterdir())
    assert _run_show(prepared.paths) == show_before

    persisted = deploy_storage_discovery_execution_path(
        prepared.paths, OPERATION_ID
    ).read_text(encoding="utf-8") + deploy_storage_discovery_evidence_path(
        prepared.paths, OPERATION_ID
    ).read_text(encoding="utf-8")
    projected = json.dumps(report.to_object(), sort_keys=True)
    for forbidden in (
        "/dev/",
        "fake-data-device",
        "sensitive-fake-serial",
        "sensitive-fake-wwn",
        "ocid1.",
        "10.0.",
        "203.0.113.",
        "DSV_STORAGE_DISCOVERY_B64",
        "PLAY RECAP",
        "--limit",
        "ansible-playbook",
        "deploy_scylla_vms_",
        _SECRET,
        _PRIVATE_PATH,
    ):
        assert forbidden not in persisted
        assert forbidden not in projected
    for path in (
        deploy_storage_discovery_execution_path(prepared.paths, OPERATION_ID),
        deploy_storage_discovery_evidence_path(prepared.paths, OPERATION_ID),
    ):
        assert path.stat().st_mode & 0o777 == 0o600

    call_count = len(runner.specs)
    reused = _execute(prepared, runner, executables, toolchain)
    assert reused.execution_artifact_state.value == "reused"
    assert reused.evidence_artifact_state.value == "reused"
    assert len(runner.specs) == call_count

    reconciled = _reconcile(prepared)
    assert (
        reconciled.schema_version
        == ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        stored = DeployPostStorageDiscoveryReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    assert (
        stored.record.schema_version
        == ANSIBLE_DEPLOY_POST_STORAGE_DISCOVERY_RECONCILIATION_SCHEMA_VERSION
    )
    discovered = next(
        step for step in stored.record.steps if step.mapping_sequence == 7
    )
    assert discovered.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
    assert (
        discovered.evidence_state
        is DeployBaseOsReconciledEvidenceState.STORAGE_DISCOVERY_BOUND
    )
    next_steps = tuple(
        step
        for step in stored.record.steps
        if step.status
        in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
    )
    assert len(next_steps) == 1
    assert next_steps[0].mapping_sequence == 8
    assert next_steps[0].playbook == "storage-preflight"
    assert next_steps[0].status is DeployBaseOsReconciledStepStatus.ELIGIBLE
    assert all(
        step.status
        not in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
        for step in stored.record.steps
        if step.mapping_sequence > 8
    )
    reconciliation_path = deploy_post_storage_discovery_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    before = reconciliation_path.stat()
    reused_reconciliation = _reconcile(prepared)
    assert reused_reconciliation.artifact_state.value == "reused"
    assert reconciliation_path.stat().st_ino == before.st_ino
    assert reconciliation_path.stat().st_mtime_ns == before.st_mtime_ns


@pytest.mark.parametrize(
    "mode",
    (
        "malformed",
        "missing-host",
        "extra-host",
        "duplicate-host",
        "wrong-host",
        "duplicate-device",
        "missing-device-field",
        "extra-devices",
        "oversized",
        "non-utf8",
    ),
)
def test_malformed_host_and_device_results_are_permanent_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = StorageDiscoveryRunner(inventory, mode=mode)
    with pytest.raises(AnsibleError, match="manual recovery"):
        _execute(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert (
        execution.record.state is DeployStorageDiscoveryExecutionState.MALFORMED_RESULT
    )
    assert evidence is None
    assert execution.record.manual_recovery_required
    assert not execution.record.automatic_retry_allowed
    calls = len(cast(list[object], runner.specs))
    with pytest.raises(StateConflictError, match="cannot retry"):
        _execute(prepared, runner, executables, toolchain)
    assert len(cast(list[object], runner.specs)) == calls
    with pytest.raises(StateConflictError):
        _reconcile(prepared)


@pytest.mark.parametrize(
    ("mode", "state", "has_evidence"),
    (
        (
            "nonzero",
            DeployStorageDiscoveryExecutionState.MALFORMED_RESULT,
            False,
        ),
        ("unreachable", DeployStorageDiscoveryExecutionState.UNREACHABLE, True),
        ("timeout", DeployStorageDiscoveryExecutionState.TIMED_OUT, False),
        ("interrupted", DeployStorageDiscoveryExecutionState.INTERRUPTED, False),
    ),
)
def test_all_failures_are_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    state: DeployStorageDiscoveryExecutionState,
    has_evidence: bool,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = StorageDiscoveryRunner(inventory, mode=mode)
    with pytest.raises((AnsibleError, StatePersistenceError), match="manual recovery"):
        _execute(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is state
    assert (evidence is not None) is has_evidence
    calls = len(cast(list[object], runner.specs))
    with pytest.raises(StateConflictError, match="cannot retry"):
        _execute(prepared, runner, executables, toolchain)
    assert len(cast(list[object], runner.specs)) == calls


def test_started_is_durable_before_call_and_post_call_failure_never_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    observed: list[DeployStorageDiscoveryExecutionState] = []

    def inspect_started() -> None:
        document = json.loads(
            deploy_storage_discovery_execution_path(
                prepared.paths, OPERATION_ID
            ).read_text(encoding="utf-8")
        )
        record = DeployStorageDiscoveryExecution.from_object(document)
        observed.append(record.state)
        assert record.invocation_count == 1
        assert record.manual_recovery_required

    def fail_evidence(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError(f"{_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(
        DeployStorageDiscoveryEvidenceStore, "write_locked", fail_evidence
    )
    runner = StorageDiscoveryRunner(inventory, inspect_started=inspect_started)
    with pytest.raises(StatePersistenceError, match="manual recovery") as caught:
        _execute(prepared, runner, executables, toolchain)
    assert observed == [DeployStorageDiscoveryExecutionState.STARTED]
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployStorageDiscoveryExecutionState.STARTED
    assert evidence is None
    calls = len(cast(list[object], runner.specs))
    with pytest.raises(StateConflictError, match="cannot retry"):
        _execute(prepared, runner, executables, toolchain)
    assert len(cast(list[object], runner.specs)) == calls


@pytest.mark.parametrize(
    "drift",
    ("prior", "inventory", "trust", "readiness", "journal", "source", "catalog"),
)
def test_full_chain_drift_refused_before_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    paths = prepared.paths
    selected = {
        "prior": paths.operations
        / f"{OPERATION_ID}.ansible-deploy-post-non-jump-reboot-reconciliation.json",
        "inventory": paths.ansible_inventory,
        "trust": paths.ansible_trust,
        "readiness": paths.terraform_plans
        / f"{OPERATION_ID}.terraform-apply-readiness.json",
        "journal": paths.operations / f"{OPERATION_ID}.json",
    }
    if drift == "source":
        source = load_ansible_source_bundle()
        monkeypatch.setattr(
            deploy_reconciliation_module,
            "load_ansible_source_bundle",
            lambda: replace(source, digest="sha256:" + "a" * 64),
        )
    elif drift == "catalog":
        monkeypatch.setattr(
            deploy_reconciliation_module,
            "ansible_operation_catalog_digest",
            lambda: "sha256:" + "b" * 64,
        )
    else:
        document = json.loads(selected[drift].read_text(encoding="utf-8"))
        document["unexpected"] = _SECRET
        selected[drift].write_bytes(serialize_json(document))
        os.chmod(selected[drift], 0o600)
    runner = StorageDiscoveryRunner(inventory)
    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _execute(prepared, runner, executables, toolchain)
    assert runner.specs == []
    assert not deploy_storage_discovery_execution_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_lock_paths_permissions_ambiguity_and_no_arbitrary_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    parameters = inspect.signature(execute_deploy_storage_discovery).parameters
    assert {
        "playbook",
        "target",
        "targets",
        "limit",
        "variables",
        "command",
        "path",
        "environment",
        "result",
        "status",
    }.isdisjoint(parameters)
    runner = StorageDiscoveryRunner(inventory)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        execute_deploy_storage_discovery(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )
    assert runner.specs == []

    execution_path = deploy_storage_discovery_execution_path(
        prepared.paths, OPERATION_ID
    )
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    outside.chmod(0o600)
    execution_path.symlink_to(outside)
    with pytest.raises(UnsafePathError):
        _execute(prepared, runner, executables, toolchain)
    execution_path.unlink()
    outside.unlink()

    prior = prepared.paths.operations / (
        f"{OPERATION_ID}.ansible-deploy-post-non-jump-reboot-reconciliation.json"
    )
    prior.chmod(0o644)
    with pytest.raises(UnsafePathError):
        _execute(prepared, runner, executables, toolchain)
    prior.chmod(0o600)

    ambiguous = prepared.paths.operations / (
        f"{{{OPERATION_ID}}}{'.ansible-deploy-storage-discovery-execution.json'}"
    )
    ambiguous.write_text("{}\n", encoding="utf-8")
    ambiguous.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _execute(prepared, runner, executables, toolchain)
    assert runner.specs == []
