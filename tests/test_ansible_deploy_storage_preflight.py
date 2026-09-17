import base64
import inspect
import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from test_ansible_deploy_storage_discovery import (
    StorageDiscoveryRunner,
)
from test_ansible_deploy_storage_discovery import (
    _execute as _execute_discovery,
)
from test_ansible_deploy_storage_discovery import (
    _prepared as _discovery_prepared,
)
from test_ansible_deploy_storage_discovery import (
    _reconcile as _reconcile_discovery,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_storage_discovery as discovery_module
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_storage_discovery import (
    deploy_post_storage_discovery_reconciliation_path,
)
from scylla_vms.ansible.deploy_storage_preflight import (
    ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION,
    DeployPostStoragePreflightReconciliationStore,
    DeployStoragePreflightAction,
    DeployStoragePreflightEvidenceStore,
    DeployStoragePreflightExecutionState,
    DeployStoragePreflightExecutionStore,
    deploy_post_storage_preflight_reconciliation_path,
    deploy_storage_preflight_evidence_path,
    deploy_storage_preflight_execution_path,
    execute_deploy_storage_preflight,
    reconcile_deploy_storage_preflight,
)
from scylla_vms.ansible.storage_preflight import (
    SelectedStorageDevice,
    StorageHostPreflight,
    StorageOwnershipStatus,
    StoragePreflightResult,
)
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.persistence import digest_bytes, serialize_json
from scylla_vms.process import ProcessResult, ProcessSpec, ProcessTimeoutError

_SECRET = "obviously-fake-storage-preflight-secret"
_PRIVATE_PATH = "/private/operator/storage-preflight.json"
_DEVICE_ID = "device-sha256:" + "d" * 64
_INTENT_DIGEST = "sha256:" + "c" * 64
_CAPACITY_BYTES = 1000 * 1024**3


@dataclass
class StoragePreflightRunner:
    mode: str = "success"
    inspect_started: Any = None
    specs: list[ProcessSpec] | None = None
    variables: list[dict[str, object]] | None = None
    playbook_calls: int = 0

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
        if playbook != "storage-preflight":
            raise AssertionError(f"unexpected playbook or external tool: {playbook}")
        self.playbook_calls += 1
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
        if self.mode == "oversized":
            return ProcessResult(0, "x" * (2 * 1024 * 1024 + 1), _SECRET)
        hosts = cast(
            dict[str, dict[str, object]],
            variables["deploy_scylla_vms_storage_preflight"],
        )
        return self._result(hosts)

    def _result(self, hosts: dict[str, dict[str, object]]) -> ProcessResult:
        markers: list[str] = []
        recaps: list[str] = []
        for index, (stable_id, source) in enumerate(hosts.items()):
            value = dict(source)
            marker_id = stable_id
            if self.mode == "wrong-host" and index == 0:
                marker_id = "wrong-host"
                value["logical_id"] = marker_id
            if self.mode == "malformed" and index == 0:
                value["unexpected"] = True
            if self.mode == "wrong-schema" and index == 0:
                value["schema_version"] = "deploy-scylla-vms.invalid/v1"
            if self.mode == "mismatched-digest" and index == 0:
                value["preparation_intent_digest"] = "sha256:" + "e" * 64
            devices = cast(list[dict[str, object]], value["devices"])
            if self.mode == "missing-device" and index == 0:
                value["devices"] = []
            elif self.mode == "extra-device" and index == 0:
                value["devices"] = [
                    *devices,
                    {
                        "capacity_bytes": _CAPACITY_BYTES,
                        "identity": "device-sha256:" + "e" * 64,
                    },
                ]
            elif self.mode == "duplicate-device" and index == 0:
                value["devices"] = [*devices, dict(devices[0])]
            if not (self.mode == "missing-host" and index == 0):
                markers.append(self._marker(marker_id, value))
                if self.mode == "duplicate-host" and index == 0:
                    markers.append(markers[-1])
            failed = self.mode == "nonzero" and index == 0
            unreachable = self.mode == "unreachable" and index == 0
            recaps.append(
                f"{stable_id} : ok=3 changed=0 "
                f"unreachable={int(unreachable)} failed={int(failed)} "
                "skipped=0 rescued=0 ignored=0"
            )
        if self.mode == "extra-host":
            value = dict(next(iter(hosts.values())))
            value["logical_id"] = "extra-host"
            markers.append(self._marker("extra-host", value))
            recaps.append(
                "extra-host : ok=3 changed=0 unreachable=0 failed=0 "
                "skipped=0 rescued=0 ignored=0"
            )
        stdout = "".join(markers) + "PLAY RECAP *****\n" + "\n".join(recaps) + "\n"
        exit_code = (
            4 if self.mode == "unreachable" else 2 if self.mode == "nonzero" else 0
        )
        return ProcessResult(exit_code, stdout, f"{_SECRET} {_PRIVATE_PATH}")

    @staticmethod
    def _marker(stable_id: str, value: dict[str, object]) -> str:
        encoded = base64.b64encode(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        return f'ok: [{stable_id}] => {{"msg":"DSV_STORAGE_PREFLIGHT_B64={encoded}"}}\n'


def _host(
    stable_id: str,
    disposition: StorageOwnershipStatus,
) -> StorageHostPreflight:
    blocked = disposition is StorageOwnershipStatus.BLOCKED
    devices = (
        ()
        if blocked
        else (SelectedStorageDevice(_DEVICE_ID, _CAPACITY_BYTES, "by-id:fake-nvme"),)
    )
    return StorageHostPreflight(
        logical_id=stable_id,
        backend="local-nvme",
        layout="single",
        capacity_bytes=0 if blocked else _CAPACITY_BYTES,
        ownership_status=disposition,
        blockers=("capacity-conflict",) if blocked else (),
        wipe_required=disposition is StorageOwnershipStatus.WIPE_REVIEW_REQUIRED,
        preparation_intent_digest=_INTENT_DIGEST,
        devices=devices,
    )


def _prepared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    disposition: StorageOwnershipStatus = StorageOwnershipStatus.BLOCKED,
):
    prepared, inventory, executables, toolchain = _discovery_prepared(
        tmp_path, monkeypatch
    )
    stable_ids = tuple(
        host.logical_id
        for host in inventory.record.inventory.hosts
        if host.role.value == "scylla"
    )
    result = StoragePreflightResult(
        tuple(_host(item, disposition) for item in stable_ids)
    )
    monkeypatch.setattr(
        discovery_module,
        "reconcile_storage_preflight",
        lambda *_args, **_kwargs: result,
    )
    _execute_discovery(
        prepared, StorageDiscoveryRunner(inventory), executables, toolchain
    )
    _reconcile_discovery(prepared)
    return prepared, inventory, executables, toolchain


def _execute(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_storage_preflight(
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
        return reconcile_deploy_storage_preflight(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _records(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        execution = DeployStoragePreflightExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployStoragePreflightEvidenceStore(
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


@pytest.mark.parametrize(
    ("disposition", "action", "blocked", "owned", "prepare", "wipe"),
    [
        (
            StorageOwnershipStatus.BLOCKED,
            DeployStoragePreflightAction.BLOCKED,
            1,
            0,
            0,
            0,
        ),
        (
            StorageOwnershipStatus.OWNED_NOOP,
            DeployStoragePreflightAction.OWNED_NOOP,
            0,
            1,
            0,
            0,
        ),
        (
            StorageOwnershipStatus.CLEAN_NEW,
            DeployStoragePreflightAction.PREPARE_REQUIRED,
            0,
            0,
            1,
            0,
        ),
        (
            StorageOwnershipStatus.WIPE_REVIEW_REQUIRED,
            DeployStoragePreflightAction.PREPARE_REQUIRED,
            0,
            0,
            1,
            1,
        ),
    ],
)
def test_exact_actions_scope_wipe_separation_reentry_and_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    disposition: StorageOwnershipStatus,
    action: DeployStoragePreflightAction,
    blocked: int,
    owned: int,
    prepare: int,
    wipe: int,
) -> None:
    assert tuple(inspect.signature(execute_deploy_storage_preflight).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "runner",
        "executables",
        "toolchain",
    )
    prepared, _inventory, executables, toolchain = _prepared(
        tmp_path, monkeypatch, disposition
    )
    runner = StoragePreflightRunner()
    report = _execute(prepared, runner, executables, toolchain)
    assert report.schema_version == (
        ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_REPORT_SCHEMA_VERSION
    )
    assert report.execution_schema_version == (
        ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION
    )
    assert report.evidence_schema_version == (
        ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    )
    assert report.execution_state is DeployStoragePreflightExecutionState.SUCCEEDED
    assert (
        report.blocked_host_count,
        report.owned_noop_host_count,
        report.prepare_required_host_count,
        report.wipe_required_host_count,
    ) == (blocked, owned, prepare, wipe)
    assert runner.playbook_calls == 1
    assert runner.variables is not None
    assert set(runner.variables[0]) == {"deploy_scylla_vms_storage_preflight"}
    assert runner.specs is not None
    playbook_spec = next(spec for spec in runner.specs if spec.argv[-1] != "--version")
    assert "--check" in playbook_spec.argv
    assert "--diff" not in playbook_spec.argv
    assert "--tags" not in playbook_spec.argv
    assert _SECRET not in json.dumps(report, default=str)
    assert _PRIVATE_PATH not in json.dumps(report, default=str)

    execution, evidence = _records(prepared)
    assert execution.record.binding.target_count == 1
    assert evidence is not None
    host = evidence.record.hosts[0]
    assert host.action is action
    assert host.disposition is disposition
    persisted = json.dumps(evidence.record.to_object(), sort_keys=True)
    assert "/dev/" not in persisted
    assert "by-id:fake-nvme" not in persisted
    assert host.device_set_digest in persisted

    reconciliation = _reconcile(prepared)
    assert reconciliation.schema_version == (
        ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    assert reconciliation.reconciliation_schema_version == (
        ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
    )
    assert len(reconciliation.preparation_scopes) == prepare
    assert reconciliation.wipe_required_host_count == wipe
    if prepare:
        scope = reconciliation.preparation_scopes[0]
        assert scope.disposition is disposition
        assert scope.wipe_required is bool(wipe)
        assert scope.device_set_digest == host.device_set_digest
        next_step = next(
            item
            for item in reconciliation.next_steps
            if item.playbook == "storage-prepare"
        )
        assert (
            next_step.status
            is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        )
    elif owned:
        stored = DeployPostStoragePreflightReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        storage_prepare = next(
            item for item in stored.record.steps if item.playbook == "storage-prepare"
        )
        assert storage_prepare.status is DeployBaseOsReconciledStepStatus.NOT_PERFORMED
        assert (
            storage_prepare.evidence_state
            is DeployBaseOsReconciledEvidenceState.NOT_REQUIRED
        )
        assert not storage_prepare.blockers
    else:
        assert "storage-preflight-blocked" in reconciliation.blocker_set

    process_count = len(runner.specs)
    reused = _execute(prepared, runner, executables, toolchain)
    reused_reconciliation = _reconcile(prepared)
    assert runner.playbook_calls == 1
    assert len(runner.specs) == process_count
    assert reused.execution_artifact_digest == report.execution_artifact_digest
    assert (
        reused_reconciliation.reconciliation_artifact_digest
        == reconciliation.reconciliation_artifact_digest
    )


@pytest.mark.parametrize(
    "mode",
    [
        "malformed",
        "missing-host",
        "extra-host",
        "duplicate-host",
        "wrong-host",
        "wrong-schema",
        "mismatched-digest",
        "missing-device",
        "extra-device",
        "duplicate-device",
        "nonzero",
        "unreachable",
        "timeout",
        "interrupted",
        "oversized",
    ],
)
def test_strict_result_failures_are_uncertain_and_never_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    prepared, _inventory, executables, toolchain = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    runner = StoragePreflightRunner(mode)
    with pytest.raises(AnsibleError, match="manual recovery required"):
        _execute(prepared, runner, executables, toolchain)
    assert runner.playbook_calls == 1
    execution, evidence = _records(prepared)
    assert execution.record.manual_recovery_required
    assert execution.record.invocation_may_have_occurred
    assert evidence is None
    with pytest.raises(StateConflictError, match="cannot retry"):
        _execute(prepared, runner, executables, toolchain)
    assert runner.playbook_calls == 1


def test_started_intent_precedes_runner_and_show_recognizes_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, executables, toolchain = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    show_before = _run_show(prepared.paths)

    def inspect_started() -> None:
        execution = DeployStoragePreflightExecutionStore(
            prepared.paths, OPERATION_ID
        ).read(
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
        evidence_store = DeployStoragePreflightEvidenceStore(
            prepared.paths, OPERATION_ID
        )
        assert execution.record.state is DeployStoragePreflightExecutionState.STARTED
        assert execution.record.manual_recovery_required
        assert not evidence_store.path.exists()

    runner = StoragePreflightRunner(inspect_started=inspect_started)
    _execute(prepared, runner, executables, toolchain)
    _reconcile(prepared)
    assert _run_show(prepared.paths) == show_before
    for path in (
        deploy_storage_preflight_execution_path(prepared.paths, OPERATION_ID),
        deploy_storage_preflight_evidence_path(prepared.paths, OPERATION_ID),
        deploy_post_storage_preflight_reconciliation_path(prepared.paths, OPERATION_ID),
    ):
        assert path.stat().st_mode & 0o777 == 0o600


def test_wrong_lock_and_prior_reconciliation_drift_fail_before_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, executables, toolchain = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    runner = StoragePreflightRunner()
    with (
        ClusterLock(prepared.paths, "check-jump-hosts", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        execute_deploy_storage_preflight(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
            runner=runner,
            executables=executables,
            toolchain=toolchain,
        )
    prior_path = deploy_post_storage_discovery_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    value = json.loads(prior_path.read_text(encoding="utf-8"))
    value["record_digest"] = "sha256:" + "f" * 64
    prior_path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _execute(prepared, runner, executables, toolchain)
    assert runner.playbook_calls == 0
    assert not deploy_storage_preflight_execution_path(
        prepared.paths, OPERATION_ID
    ).exists()
    assert not deploy_storage_preflight_evidence_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_post_call_evidence_persistence_failure_is_permanent_no_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, executables, toolchain = _prepared(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    runner = StoragePreflightRunner()

    def fail_write(*_args: object, **_kwargs: object) -> None:
        raise StatePersistenceError("injected fake evidence persistence failure")

    monkeypatch.setattr(DeployStoragePreflightEvidenceStore, "write_locked", fail_write)
    with pytest.raises(StatePersistenceError, match="manual recovery required"):
        _execute(prepared, runner, executables, toolchain)
    execution, evidence = _records(prepared)
    assert execution.record.state is DeployStoragePreflightExecutionState.STARTED
    assert execution.record.manual_recovery_required
    assert evidence is None
    assert runner.playbook_calls == 1
    with pytest.raises(StateConflictError, match="cannot retry"):
        _execute(prepared, runner, executables, toolchain)
    assert runner.playbook_calls == 1


def test_mixed_scope_selects_only_prepare_required_and_keeps_wipe_separate() -> None:
    from scylla_vms.ansible.deploy_storage_preflight import (
        DeployStoragePreflightHostEvidence,
        _preparation_scopes,
    )

    def projected(
        stable_id: str,
        disposition: StorageOwnershipStatus,
    ) -> DeployStoragePreflightHostEvidence:
        action = (
            DeployStoragePreflightAction.BLOCKED
            if disposition is StorageOwnershipStatus.BLOCKED
            else DeployStoragePreflightAction.OWNED_NOOP
            if disposition is StorageOwnershipStatus.OWNED_NOOP
            else DeployStoragePreflightAction.PREPARE_REQUIRED
        )
        blockers = (
            ("capacity-conflict",)
            if action is DeployStoragePreflightAction.BLOCKED
            else ()
        )
        values = {
            "stable_id": stable_id,
            "disposition": disposition,
            "action": action,
            "backend": "local-nvme",
            "layout": "single",
            "capacity_bytes": 0 if blockers else _CAPACITY_BYTES,
            "device_count": 0 if blockers else 1,
            "device_set_digest": "sha256:" + "a" * 64,
            "desired_policy_digest": "sha256:" + "1" * 64,
            "manifest_digest": "sha256:" + "2" * 64,
            "discovery_digest": "sha256:" + "3" * 64,
            "preparation_intent_digest": _INTENT_DIGEST,
            "wipe_required": (
                disposition is StorageOwnershipStatus.WIPE_REVIEW_REQUIRED
            ),
            "blocker_set": blockers,
            "blocker_digest": digest_bytes(serialize_json({"value": list(blockers)})),
            "status_digest": "",
        }
        from scylla_vms.ansible.deploy_storage_preflight import (
            _host_status_digest_from_values,
        )

        values["status_digest"] = _host_status_digest_from_values(values)
        return DeployStoragePreflightHostEvidence(**values)  # type: ignore[arg-type]

    hosts = (
        projected("scylla-a", StorageOwnershipStatus.BLOCKED),
        projected("scylla-b", StorageOwnershipStatus.OWNED_NOOP),
        projected("scylla-c", StorageOwnershipStatus.CLEAN_NEW),
        projected("scylla-d", StorageOwnershipStatus.WIPE_REVIEW_REQUIRED),
    )
    evidence = cast(Any, SimpleNamespace(record=SimpleNamespace(hosts=hosts)))
    scopes = _preparation_scopes(evidence)
    assert tuple(item.stable_id for item in scopes) == ("scylla-c", "scylla-d")
    assert tuple(item.wipe_required for item in scopes) == (False, True)
    assert all(
        item.disposition
        in {
            StorageOwnershipStatus.CLEAN_NEW,
            StorageOwnershipStatus.WIPE_REVIEW_REQUIRED,
        }
        for item in scopes
    )
