import inspect
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from test_ansible_deploy_host_evidence import (
    HostEvidenceRunner,
)
from test_ansible_deploy_host_evidence import (
    _call as _host_evidence_call,
)
from test_ansible_deploy_host_evidence import (
    _prepared as _host_evidence_prepared,
)
from test_provider_source import CLUSTER_UUID
from test_terraform_plan_checkpoint import OPERATION_ID

import scylla_vms.ansible.deploy_host_reconciliation as host_reconciliation_module
import scylla_vms.ansible.deploy_reconciliation as reconciliation_module
from scylla_vms.ansible.deploy_host_evidence import (
    DeployPreMutationEvidenceStore,
    PreMutationHostEvidence,
    PreMutationServiceState,
    deploy_pre_mutation_evidence_path,
    deploy_pre_mutation_execution_path,
)
from scylla_vms.ansible.deploy_host_reconciliation import (
    ANSIBLE_DEPLOY_HOST_RECONCILIATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_HOST_RECONCILIATION_SCHEMA_VERSION,
    DeployHostEvidenceReconciliation,
    DeployHostEvidenceReconciliationStore,
    DeployHostReconciledEvidenceState,
    DeployHostReconciledStepStatus,
    DeployHostReconciliationArtifactState,
    deploy_host_evidence_reconciliation_path,
    reconcile_deploy_pre_mutation_host_evidence,
)
from scylla_vms.ansible.deploy_reconciliation import DeployEffectivePlanStore
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.persistence import serialize_json

_PRIVATE_PATH = "/private/operator/host-reconciliation.json"
_SECRET = "obviously-fake-host-reconciliation-secret"


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, inventory, executables, toolchain = _host_evidence_prepared(
        tmp_path, monkeypatch
    )
    runner = HostEvidenceRunner(inventory)
    _host_evidence_call(prepared, runner, executables, toolchain)
    return prepared, inventory, runner


def _call(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return reconcile_deploy_pre_mutation_host_evidence(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=lock,
        )


def _record(prepared):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return DeployHostEvidenceReconciliationStore(
            prepared.paths, OPERATION_ID
        ).read_locked(
            lock,
            expected_cluster_uuid=CLUSTER_UUID,
            expected_cluster_name="example",
        )


def _replace_host_evidence(
    prepared,
    transform,
) -> None:
    store = DeployPreMutationEvidenceStore(prepared.paths, OPERATION_ID)
    stored = store.read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    entries = []
    for entry in stored.record.entries:
        hosts = tuple(transform(host) for host in entry.hosts)
        value = entry.to_object()
        value["hosts"] = [host.to_object() for host in hosts]
        value["evidence_digest"] = ""
        entries.append(
            replace(
                entry,
                hosts=hosts,
                evidence_digest=host_reconciliation_module._digest_object(value),
            )
        )
    record = replace(stored.record, entries=tuple(entries))
    store.path.write_bytes(serialize_json(record.to_object()))
    os.chmod(store.path, 0o600)


def _with_reboot(host: PreMutationHostEvidence, value: str):
    return replace(host, reboot_required=value)


def test_successful_reconciliation_is_immutable_redacted_and_process_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(
        inspect.signature(reconcile_deploy_pre_mutation_host_evidence).parameters
    ) == ("state_root", "cluster_name", "operation_id", "lock")
    prepared, _inventory, runner = _prepared(tmp_path, monkeypatch)
    original_paths = (
        prepared.paths.operations / f"{OPERATION_ID}.json",
        DeployEffectivePlanStore(prepared.paths, OPERATION_ID).path,
        deploy_pre_mutation_execution_path(prepared.paths, OPERATION_ID),
        deploy_pre_mutation_evidence_path(prepared.paths, OPERATION_ID),
    )
    original_bytes = tuple(path.read_bytes() for path in original_paths)
    process_count = len(runner.specs or ())

    created = _call(prepared)
    path = deploy_host_evidence_reconciliation_path(prepared.paths, OPERATION_ID)
    first_bytes = path.read_bytes()
    first_mtime = path.stat().st_mtime_ns
    reused = _call(prepared)
    stored = _record(prepared)

    assert created.schema_version == (
        ANSIBLE_DEPLOY_HOST_RECONCILIATION_REPORT_SCHEMA_VERSION
    )
    assert created.artifact_state is DeployHostReconciliationArtifactState.CREATED
    assert reused.artifact_state is DeployHostReconciliationArtifactState.REUSED
    assert reused.to_object() == created.to_object() | {"artifact_state": "reused"}
    assert stored.record.schema_version == (
        ANSIBLE_DEPLOY_HOST_RECONCILIATION_SCHEMA_VERSION
    )
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.read_bytes() == first_bytes
    assert path.stat().st_mtime_ns == first_mtime
    assert tuple(path.read_bytes() for path in original_paths) == original_bytes
    assert len(runner.specs or ()) == process_count
    assert created.journal_status is JournalStatus.IN_PROGRESS
    assert created.journal_phase is OperationPhase.VERIFY
    assert created.succeeded_count == 2
    assert created.authorization_required_count == 0
    assert created.next_authorization_required == ()
    assert created.mutating_execution_state == "blocked"
    assert created.authorization_state == "not-collected"
    assert created.mapped_final_evidence_state == "not-performed"
    assert "reboot-requirement-not-collected" in created.blocker_set

    prior = DeployEffectivePlanStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    assert len(stored.record.steps) == len(prior.record.steps)
    for step, previous in zip(stored.record.steps, prior.record.steps, strict=True):
        assert (
            step.sequence,
            step.mapping_sequence,
            step.playbook,
            step.condition,
            step.condition_state,
            step.classification,
            step.target_role,
            step.target_ids,
            step.target_digest,
            step.limit_policy,
            step.serial,
            step.check_mode,
            step.variable_names,
            step.variables_digest,
            step.source_digest,
            step.command_digest,
            step.original_step_digest,
        ) == (
            previous.sequence,
            previous.mapping_sequence,
            previous.playbook,
            previous.condition,
            previous.condition_state,
            previous.classification,
            previous.target_role,
            previous.target_ids,
            previous.target_digest,
            previous.limit_policy,
            previous.serial,
            previous.check_mode,
            previous.variable_names,
            previous.variables_digest,
            previous.source_digest,
            previous.command_digest,
            previous.original_step_digest,
        )
    assert all(
        step.status is DeployHostReconciledStepStatus.SUCCEEDED
        and step.evidence_state is DeployHostReconciledEvidenceState.PREREQUISITE_BOUND
        for step in stored.record.steps[:2]
    )
    assert all(
        step.status
        not in {
            DeployHostReconciledStepStatus.SUCCEEDED,
            DeployHostReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
        for step in stored.record.steps[2:]
    )
    final_evidence = tuple(
        step for step in stored.record.steps if step.playbook == "evidence-collect"
    )
    assert len(final_evidence) == 1
    assert final_evidence[0].status is DeployHostReconciledStepStatus.NOT_PERFORMED
    assert (
        final_evidence[0].evidence_state
        is DeployHostReconciledEvidenceState.NOT_PERFORMED
    )
    assert final_evidence[0].evidence_digest is None

    projected = json.dumps(created.to_object(), sort_keys=True)
    persisted = path.read_text(encoding="utf-8")
    for forbidden in (
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "ssh-ed25519",
        "fingerprint",
        "/dev/",
        '"name":"sda"',
        "PLAY RECAP",
        "DSV_EVIDENCE_B64",
        "command_digest",
        "variables_digest",
        "target_ids",
        "environment",
        _PRIVATE_PATH,
        _SECRET,
    ):
        assert forbidden not in projected
    for forbidden in (
        "10.0.",
        "203.0.113.",
        "ocid1.",
        "ssh-ed25519",
        "fingerprint",
        "/dev/",
        '"name":"sda"',
        "PLAY RECAP",
        "DSV_EVIDENCE_B64",
        "environment",
        _PRIVATE_PATH,
        _SECRET,
    ):
        assert forbidden not in persisted


def test_only_justified_next_base_os_is_authorization_required(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch)
    _replace_host_evidence(
        prepared,
        lambda host: _with_reboot(host, "not-required"),
    )

    report = _call(prepared)
    stored = _record(prepared)
    assert report.authorization_required_count > 0
    assert tuple(
        (item.playbook, item.role) for item in report.next_authorization_required
    ) == (("base-os", "jump-host"),)
    required = tuple(
        step
        for step in stored.record.steps
        if step.status
        is DeployHostReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
    )
    assert required
    assert all(step.mapping_sequence == 3 for step in required)
    assert all(step.playbook == "base-os" for step in required)
    assert all(
        step.evidence_state is DeployHostReconciledEvidenceState.HOST_GATES_EVALUATED
        and step.evidence_digest is not None
        and "deploy-authorization-not-collected" in step.blockers
        and "mutating-deploy-execution-unavailable" in step.blockers
        and "public-deploy-workflow-unavailable" in step.blockers
        for step in required
    )
    assert all(
        step.status
        is not DeployHostReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        for step in stored.record.steps
        if step.mapping_sequence != 3
    )
    assert not hasattr(DeployHostReconciledStepStatus, "EXECUTABLE")
    assert not hasattr(DeployHostReconciledStepStatus, "ELIGIBLE")


@pytest.mark.parametrize(
    ("case", "expected_blocker", "gate", "state_count"),
    (
        ("unsupported-os", "unsupported-os-family", "platform", "failed_count"),
        (
            "unsupported-architecture",
            "unsupported-architecture",
            "platform",
            "failed_count",
        ),
        (
            "reboot-required",
            "reboot-required",
            "reboot-requirement",
            "failed_count",
        ),
        ("service-active", "service-state-active", "service-state", "failed_count"),
        (
            "capacity",
            "capacity-evidence-unavailable",
            "capacity-evidence",
            "unknown_count",
        ),
        (
            "mount",
            "mount-evidence-unavailable",
            "mount-evidence",
            "unknown_count",
        ),
        (
            "device",
            "device-evidence-unavailable",
            "device-evidence",
            "unknown_count",
        ),
    ),
)
def test_host_gate_blockers_remain_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    expected_blocker: str,
    gate: str,
    state_count: str,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch)

    def transform(host: PreMutationHostEvidence) -> PreMutationHostEvidence:
        host = replace(host, reboot_required="not-required")
        if case == "unsupported-os":
            return replace(host, os_family="Fedora", os_version="41")
        if case == "unsupported-architecture":
            return replace(host, architecture="sparc64")
        if case == "reboot-required":
            return replace(host, reboot_required="required")
        if case == "service-active" and host.services:
            return replace(
                host,
                services=tuple(
                    PreMutationServiceState(service.name, "active")
                    for service in host.services
                ),
            )
        if case == "capacity":
            return replace(host, cpu_count=None)
        if case == "mount":
            return replace(host, filesystem_status="unavailable", mount_count=0)
        if case == "device" and host.role.value == "scylla":
            return replace(
                host,
                block_device_status="unavailable",
                block_device_count=0,
            )
        return host

    _replace_host_evidence(prepared, transform)
    report = _call(prepared)
    assert expected_blocker in report.blocker_set
    gate_count = {item.gate: item for item in report.host_gate_counts}[gate]
    assert getattr(gate_count, state_count) >= 1


@pytest.mark.parametrize(
    "mode",
    ("missing", "extra", "duplicate", "wrong-role", "reordered"),
)
def test_missing_extra_duplicate_wrong_role_and_reordered_evidence_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch)
    path = deploy_pre_mutation_evidence_path(prepared.paths, OPERATION_ID)
    value = json.loads(path.read_text(encoding="utf-8"))
    entries = value["entries"]
    assert isinstance(entries, list)
    if mode == "missing":
        entries.pop()
        value["generation"] = len(entries)
    elif mode == "reordered":
        entries.reverse()
    else:
        first = entries[0]
        assert isinstance(first, dict)
        hosts = first["hosts"]
        assert isinstance(hosts, list)
        if mode == "extra":
            extra = dict(hosts[0])
            extra["logical_id"] = "extra-host"
            hosts.append(extra)
        elif mode == "duplicate":
            hosts.append(dict(hosts[0]))
        else:
            hosts[0]["role"] = "manager"
        first["target_count"] = len(hosts)
    path.write_bytes(serialize_json(value))
    os.chmod(path, 0o600)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not deploy_host_evidence_reconciliation_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_uncertain_execution_is_refused_without_runner_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _host_evidence_prepared(
        tmp_path, monkeypatch
    )
    runner = HostEvidenceRunner(inventory, mode="timeout")
    with pytest.raises(AnsibleError):
        _host_evidence_call(prepared, runner, executables, toolchain)
    process_count = len(runner.specs or ())
    with pytest.raises(StateConflictError):
        _call(prepared)
    assert len(runner.specs or ()) == process_count
    assert not deploy_host_evidence_reconciliation_path(
        prepared.paths, OPERATION_ID
    ).exists()


@pytest.mark.parametrize(
    "drift",
    (
        "effective-plan",
        "host-evidence",
        "readiness",
        "journal",
        "catalog",
        "source",
    ),
)
def test_chain_effective_catalog_source_and_journal_drift_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch)
    if drift == "effective-plan":
        _tamper_digest(
            DeployEffectivePlanStore(prepared.paths, OPERATION_ID).path,
            "record_digest",
        )
    elif drift == "host-evidence":
        path = deploy_pre_mutation_evidence_path(prepared.paths, OPERATION_ID)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["entries"][0]["evidence_digest"] = "sha256:" + "d" * 64
        path.write_bytes(serialize_json(value))
        os.chmod(path, 0o600)
    elif drift == "readiness":
        _tamper_digest(
            prepared.paths.terraform_plans
            / f"{OPERATION_ID}.terraform-apply-readiness.json",
            "record_digest",
        )
    elif drift == "journal":
        _tamper_digest(
            prepared.paths.operations / f"{OPERATION_ID}.json",
            "request_digest",
        )
    elif drift == "catalog":
        monkeypatch.setattr(
            reconciliation_module,
            "ansible_operation_catalog_digest",
            lambda: "sha256:" + "b" * 64,
        )
    else:
        source = load_ansible_source_bundle()
        monkeypatch.setattr(
            reconciliation_module,
            "load_ansible_source_bundle",
            lambda: replace(source, digest="sha256:" + "c" * 64),
        )

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared)
    assert not deploy_host_evidence_reconciliation_path(
        prepared.paths, OPERATION_ID
    ).exists()


def test_write_failure_lock_symlink_permissions_and_ambiguous_path_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch)
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError),
    ):
        reconcile_deploy_pre_mutation_host_evidence(
            state_root=prepared.paths.state_root,
            cluster_name="example",
            operation_id=OPERATION_ID,
            lock=wrong_lock,
        )

    path = deploy_host_evidence_reconciliation_path(prepared.paths, OPERATION_ID)
    target = prepared.paths.operations / "outside-host-reconciliation.json"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    path.symlink_to(target)
    with pytest.raises(UnsafePathError):
        _call(prepared)
    path.unlink()
    target.unlink()

    evidence_path = deploy_pre_mutation_evidence_path(prepared.paths, OPERATION_ID)
    evidence_path.chmod(0o644)
    with pytest.raises(UnsafePathError):
        _call(prepared)
    evidence_path.chmod(0o600)

    ambiguous = prepared.paths.operations / (
        f"{{{OPERATION_ID}}}{host_reconciliation_module.DEPLOY_HOST_RECONCILIATION_FILENAME_SUFFIX}"
    )
    ambiguous.write_text("{}\n", encoding="utf-8")
    ambiguous.chmod(0o600)
    with pytest.raises(StateConflictError, match="ambiguous"):
        _call(prepared)
    ambiguous.unlink()

    original_paths = (
        DeployEffectivePlanStore(prepared.paths, OPERATION_ID).path,
        deploy_pre_mutation_evidence_path(prepared.paths, OPERATION_ID),
        prepared.paths.operations / f"{OPERATION_ID}.json",
    )
    original_bytes = tuple(item.read_bytes() for item in original_paths)

    def fail_write(self, record, *, lock):
        del self, record, lock
        raise StatePersistenceError(f"simulated {_SECRET} {_PRIVATE_PATH}")

    monkeypatch.setattr(
        DeployHostEvidenceReconciliationStore, "write_locked", fail_write
    )
    with pytest.raises(StatePersistenceError) as caught:
        _call(prepared)
    assert _SECRET not in str(caught.value)
    assert _PRIVATE_PATH not in str(caught.value)
    assert tuple(item.read_bytes() for item in original_paths) == original_bytes
    assert not path.exists()


def test_persisted_record_rejects_status_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _inventory, _runner = _prepared(tmp_path, monkeypatch)
    _call(prepared)
    value = _record(prepared).record.to_object()
    steps = value["steps"]
    assert isinstance(steps, list)
    step = steps[2]
    assert isinstance(step, dict)
    step["status"] = "evidence-ready-authorization-required"
    with pytest.raises(StatePersistenceError):
        DeployHostEvidenceReconciliation.from_object(value)


def _tamper_digest(
    path: Path,
    field: str,
    *,
    replacement: str | None = None,
) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    value[field] = replacement or "sha256:" + "d" * 64
    path.write_bytes(serialize_json(value))
    os.chmod(path, 0o600)
