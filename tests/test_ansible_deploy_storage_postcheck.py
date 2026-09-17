import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
from test_ansible_deploy_storage_prepare_reconciliation import (
    _call as _reconcile_prepare,
)
from test_ansible_deploy_storage_prepare_reconciliation import (
    _fully_prepared,
    _prepare_only,
)
from test_ansible_storage import (
    _postcheck_context,
    _postcheck_result,
    _postcheck_stdout,
)
from test_provider_source import CLUSTER_UUID
from test_show import _run as _run_show
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_storage_postcheck import (
    DeployPostStoragePostcheckReconciliationStore,
    DeployStoragePostcheckArtifactState,
    DeployStoragePostcheckExecutionState,
    DeployStoragePostcheckExecutionStore,
    deploy_post_storage_postcheck_reconciliation_path,
    deploy_storage_postcheck_evidence_path,
    deploy_storage_postcheck_execution_path,
    execute_deploy_storage_postcheck,
    reconcile_deploy_storage_postcheck,
)
from scylla_vms.ansible.storage_postcheck import parse_storage_postcheck_execution
from scylla_vms.ansible.storage_preflight import StorageOwnershipStatus
from scylla_vms.errors import AnsibleError, StateConflictError, StatePersistenceError
from scylla_vms.locking import ClusterLock
from scylla_vms.process import ProcessResult, ProcessSpec

_CHECKS = (
    "capacity",
    "device-membership",
    "filesystem",
    "fstab",
    "holders",
    "marker",
    "mount",
    "permissions",
    "provenance",
    "raid",
    "signatures",
    "tools",
)
_PRIVATE_PATH = "/private/operator/postcheck-device"
_SECRET = "obviously-fake-postcheck-secret"


@dataclass
class StoragePostcheckRunner:
    blocker: str | None = None
    malformed: bool = False
    specs: list[ProcessSpec] | None = None
    playbook_calls: int = 0

    def __post_init__(self) -> None:
        self.specs = []

    def run(self, spec: ProcessSpec) -> ProcessResult:
        assert self.specs is not None
        self.specs.append(spec)
        if spec.argv[-1] == "--version":
            return ProcessResult(0, f"{Path(spec.argv[0]).name} [core 2.20.9]\n", "")
        playbook = next(
            Path(argument).stem
            for argument in spec.argv
            if "/playbooks/" in argument and argument.endswith(".yml")
        )
        if playbook != "storage-postcheck":
            raise AssertionError(f"unexpected playbook or external tool: {playbook}")
        self.playbook_calls += 1
        runtime_file = Path(spec.argv[spec.argv.index("--extra-vars") + 1][1:])
        variables = cast(
            dict[str, object], json.loads(runtime_file.read_text(encoding="utf-8"))
        )
        payload = cast(
            dict[str, object], variables["deploy_scylla_vms_storage_postcheck"]
        )
        if self.malformed:
            return ProcessResult(0, "malformed", f"{_SECRET} {_PRIVATE_PATH}")
        failed = self.blocker is not None
        check_name = (
            {
                "device-identity-conflict": "device-membership",
                "device-membership-conflict": "device-membership",
                "filesystem-conflict": "filesystem",
                "fstab-conflict": "fstab",
                "holder-conflict": "holders",
                "marker-conflict": "marker",
                "mount-conflict": "mount",
                "permission-conflict": "permissions",
                "provenance-conflict": "provenance",
                "raid-conflict": "raid",
                "signature-conflict": "signatures",
                "capacity-conflict": "capacity",
                "tool-evidence-unavailable": "tools",
                "verification-incomplete": "tools",
            }.get(self.blocker)
            if failed
            else None
        )
        devices = cast(list[dict[str, object]], payload["devices"])
        provenance = {
            "device_set_digest": payload["prepare_device_set_digest"],
            "discovery_digest": payload["discovery_digest"],
            "inventory_digest": payload["inventory_digest"],
            "observation_digest": payload["observation_digest"],
            "policy_digest": payload["policy_digest"],
            "preflight_evidence_digest": payload["preflight_evidence_digest"],
            "preparation_evidence_digest": payload["preparation_evidence_digest"],
            "preparation_intent_digest": payload["preparation_intent_digest"],
        }
        value = {
            "backend": payload["backend"],
            "blockers": [] if self.blocker is None else [self.blocker],
            "checks": [
                {
                    "name": name,
                    "status": "failed" if name == check_name else "passed",
                }
                for name in _CHECKS
            ],
            "devices": devices,
            "layout": payload["layout"],
            "logical_id": payload["logical_id"],
            "provenance": provenance,
            "readiness_for_scylla": not failed,
            "schema_version": "deploy-scylla-vms.ansible-storage-postcheck/v1",
        }
        encoded = base64.b64encode(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        logical_id = cast(str, payload["logical_id"])
        stdout = (
            f'ok: [{logical_id}] => {{"msg": '
            f'"DSV_STORAGE_POSTCHECK_B64={encoded}"}}\n'
            "PLAY RECAP *****\n"
            f"{logical_id} : ok=5 changed=0 unreachable=0 "
            f"failed={1 if failed else 0} skipped=0 rescued=0 ignored=0\n"
        )
        return ProcessResult(2 if failed else 0, stdout, "")


def _prepared_postcheck(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    disposition: StorageOwnershipStatus,
):
    if disposition is StorageOwnershipStatus.OWNED_NOOP:
        prepared, _prior_runner, executables, toolchain = _prepare_only(
            tmp_path, monkeypatch, disposition
        )
    else:
        prepared, _prior_runner, executables, toolchain = _fully_prepared(
            tmp_path, monkeypatch, disposition
        )
    _reconcile_prepare(prepared)
    return prepared, executables, toolchain


def _execute(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return execute_deploy_storage_postcheck(
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
        return reconcile_deploy_storage_postcheck(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


@pytest.mark.parametrize(
    "disposition",
    (StorageOwnershipStatus.CLEAN_NEW, StorageOwnershipStatus.OWNED_NOOP),
)
def test_postcheck_success_reentry_redaction_and_next_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    disposition: StorageOwnershipStatus,
) -> None:
    prepared, executables, toolchain = _prepared_postcheck(
        tmp_path, monkeypatch, disposition
    )
    journal_path = prepared.paths.operations / f"{OPERATION_ID}.json"
    journal_bytes = journal_path.read_bytes()
    runner = StoragePostcheckRunner()

    report = _execute(prepared, runner, executables, toolchain)
    reused = _execute(prepared, runner, executables, toolchain)
    reconciled = _reconcile(prepared)
    reconciliation_path = deploy_post_storage_postcheck_reconciliation_path(
        prepared.paths, OPERATION_ID
    )
    first_bytes = reconciliation_path.read_bytes()
    reconciliation_reused = _reconcile(prepared)
    execution_reused_after_reconciliation = _execute(
        prepared, runner, executables, toolchain
    )
    show = _run_show(prepared.paths)

    assert report.execution_state is DeployStoragePostcheckExecutionState.SUCCEEDED
    assert reused.execution_artifact_state is DeployStoragePostcheckArtifactState.REUSED
    assert runner.playbook_calls == 1
    assert runner.specs is not None
    playbook_specs = [spec for spec in runner.specs if spec.argv[-1] != "--version"]
    assert len(playbook_specs) == 1
    assert "--check" in playbook_specs[0].argv
    assert all(
        forbidden not in playbook_specs[0].argv
        for forbidden in ("storage-prepare", "scylla-install", "terraform", "oci")
    )
    assert reconciled.next_playbook == "scylla-install"
    assert reconciled.next_target_count == 1
    assert (
        reconciliation_reused.artifact_state
        is DeployStoragePostcheckArtifactState.REUSED
    )
    assert (
        execution_reused_after_reconciliation.execution_artifact_state
        is DeployStoragePostcheckArtifactState.REUSED
    )
    assert reconciliation_path.read_bytes() == first_bytes
    assert journal_path.read_bytes() == journal_bytes
    assert show

    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        stored = DeployPostStoragePostcheckReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    postcheck = tuple(
        step
        for step in stored.record.steps
        if step.playbook == "storage-postcheck"
        and step.condition_state.value == "active"
    )
    install = tuple(
        step
        for step in stored.record.steps
        if step.playbook == "scylla-install" and step.condition_state.value == "active"
    )
    assert all(
        step.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
        and step.evidence_state
        is DeployBaseOsReconciledEvidenceState.STORAGE_POSTCHECK_BOUND
        for step in postcheck
    )
    assert all(
        step.status
        is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        for step in install
    )
    advanced = tuple(
        step
        for step in stored.record.steps
        if step.status
        in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
    )
    assert advanced
    assert {step.playbook for step in advanced} == {"scylla-install"}
    public = (
        deploy_storage_postcheck_execution_path(prepared.paths, OPERATION_ID).read_text(
            encoding="utf-8"
        )
        + deploy_storage_postcheck_evidence_path(
            prepared.paths, OPERATION_ID
        ).read_text(encoding="utf-8")
        + first_bytes.decode()
    )
    assert "/dev/" not in public
    assert "ocid1." not in public
    assert _PRIVATE_PATH not in public
    assert _SECRET not in public
    for path in (
        deploy_storage_postcheck_execution_path(prepared.paths, OPERATION_ID),
        deploy_storage_postcheck_evidence_path(prepared.paths, OPERATION_ID),
        reconciliation_path,
    ):
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "blocker",
    (
        "capacity-conflict",
        "device-identity-conflict",
        "device-membership-conflict",
        "filesystem-conflict",
        "fstab-conflict",
        "holder-conflict",
        "marker-conflict",
        "mount-conflict",
        "permission-conflict",
        "provenance-conflict",
        "raid-conflict",
        "signature-conflict",
        "tool-evidence-unavailable",
        "verification-incomplete",
    ),
)
def test_postcheck_blockers_fail_and_never_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    blocker: str,
) -> None:
    prepared, executables, toolchain = _prepared_postcheck(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    runner = StoragePostcheckRunner(blocker=blocker)
    with pytest.raises(AnsibleError, match="manual recovery"):
        _execute(prepared, runner, executables, toolchain)
    with pytest.raises(StateConflictError, match="cannot retry"):
        _execute(prepared, runner, executables, toolchain)
    assert runner.playbook_calls == 1
    with pytest.raises(StateConflictError, match="complete current evidence"):
        _reconcile(prepared)


def test_postcheck_malformed_result_is_durable_and_no_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared_postcheck(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    runner = StoragePostcheckRunner(malformed=True)
    with pytest.raises(AnsibleError, match="malformed"):
        _execute(prepared, runner, executables, toolchain)
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        stored = DeployStoragePostcheckExecutionStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )
    assert stored.record.state is DeployStoragePostcheckExecutionState.MALFORMED_RESULT
    assert stored.record.manual_recovery_required
    assert not deploy_storage_postcheck_evidence_path(
        prepared.paths, OPERATION_ID
    ).exists()
    with pytest.raises(StateConflictError, match="cannot retry"):
        _execute(prepared, runner, executables, toolchain)
    assert runner.playbook_calls == 1


def test_postcheck_refuses_execution_evidence_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, executables, toolchain = _prepared_postcheck(
        tmp_path, monkeypatch, StorageOwnershipStatus.CLEAN_NEW
    )
    runner = StoragePostcheckRunner()
    _execute(prepared, runner, executables, toolchain)
    evidence_path = deploy_storage_postcheck_evidence_path(prepared.paths, OPERATION_ID)
    value = json.loads(evidence_path.read_text(encoding="utf-8"))
    value["entries"][0]["blocker_count"] = 1
    evidence_path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    with pytest.raises(StatePersistenceError):
        _reconcile(prepared)


@pytest.mark.parametrize(
    "mode",
    (
        "missing-host",
        "extra-host",
        "extra-field",
        "duplicate-result",
        "missing-check",
        "extra-device",
    ),
)
def test_postcheck_strict_result_refuses_incomplete_extra_and_duplicate(
    mode: str,
) -> None:
    *_, payload = _postcheck_context()
    result = _postcheck_result(payload)
    stdout = _postcheck_stdout(result)
    if mode == "missing-host":
        stdout = ""
    elif mode == "extra-host":
        extra = dict(result)
        extra["logical_id"] = "unexpected-scylla"
        stdout += _postcheck_stdout(extra)
    elif mode == "extra-field":
        result["unexpected"] = True
        stdout = _postcheck_stdout(result)
    elif mode == "duplicate-result":
        stdout += _postcheck_stdout(result)
    elif mode == "missing-check":
        cast(list[object], result["checks"]).pop()
        stdout = _postcheck_stdout(result)
    else:
        devices = cast(list[object], result["devices"])
        devices.append(devices[0])
        stdout = _postcheck_stdout(result)
    with pytest.raises(AnsibleError):
        parse_storage_postcheck_execution(
            stdout,
            expected_payload=payload,
            exit_code=0,
        )
