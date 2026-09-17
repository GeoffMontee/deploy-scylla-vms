import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
import test_terraform_apply_trust as trust_helpers
from test_ansible import _executable
from test_provider_source import CLUSTER_UUID
from test_terraform_plan_checkpoint import OPERATION_ID

from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.toolchain import AnsibleCoreVersion, AnsibleToolchain
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    ToolPrerequisiteError,
    UnsafePathError,
)
from scylla_vms.journal import JournalStatus, OperationJournalStore, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.process import ProcessResult, ProcessSpec
from scylla_vms.terraform.apply_readiness import (
    TERRAFORM_APPLY_READINESS_REPORT_SCHEMA_VERSION,
    TERRAFORM_APPLY_READINESS_SCHEMA_VERSION,
    TerraformApplyReadinessCompanionState,
    TerraformApplyReadinessStageState,
    TerraformApplyReadinessStore,
    terraform_apply_readiness_path,
    validate_deploy_ansible_readiness,
)
from scylla_vms.terraform.apply_trust import terraform_apply_trust_path


@dataclass
class ReadinessRunner:
    results: list[ProcessResult]
    specs: list[ProcessSpec] | None = None
    error_at: int | None = None
    error: Exception | None = None
    after_run: Callable[[int], None] | None = None

    def __post_init__(self) -> None:
        self.specs = []

    def run(self, spec: ProcessSpec) -> ProcessResult:
        assert self.specs is not None
        self.specs.append(spec)
        if self.error_at == len(self.specs):
            raise self.error or ToolPrerequisiteError(
                "fake controlled runner prerequisite failure"
            )
        if not self.results:
            raise AssertionError("unexpected controlled runner invocation")
        result = self.results.pop(0)
        stdout = result.stdout
        stderr = result.stderr
        for value in spec.sensitive_values:
            if isinstance(stdout, bytes):
                stdout = stdout.replace(value.encode(), b"[REDACTED]")
            else:
                stdout = stdout.replace(value, "[REDACTED]")
            if isinstance(stderr, bytes):
                stderr = stderr.replace(value.encode(), b"[REDACTED]")
            else:
                stderr = stderr.replace(value, "[REDACTED]")
        sanitized = ProcessResult(
            result.exit_code,
            cast(str, stdout),
            cast(str, stderr),
        )
        if self.after_run is not None:
            self.after_run(len(self.specs))
        return sanitized


def _prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prepared, observation, inventory = trust_helpers._prepared(tmp_path, monkeypatch)
    trust_helpers._complete(prepared, observation, inventory)
    executables = ControlledAnsibleExecutables(
        _executable(tmp_path, "ansible-playbook"),
        _executable(tmp_path, "ansible-inventory"),
    )
    toolchain = AnsibleToolchain(AnsibleCoreVersion(2, 20, 9))
    return prepared, inventory, executables, toolchain


def _runner(inventory, *, listed: str | bytes | None = None) -> ReadinessRunner:
    machine = (
        json.dumps(inventory.record.to_machine_object(), sort_keys=True)
        if listed is None
        else listed
    )
    return ReadinessRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ProcessResult(0, cast(str, machine), ""),
        ]
    )


def _call(prepared, runner, executables, toolchain):
    with ClusterLock(prepared.paths, "deploy", 0) as lock:
        return validate_deploy_ansible_readiness(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            lock,
            runner,
            executables,
            toolchain,
        )


def test_api_is_narrow_and_happy_path_is_local_redacted_and_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(inspect.signature(validate_deploy_ansible_readiness).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "runner",
        "executables",
        "toolchain",
    )
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = _runner(inventory)

    report = _call(prepared, runner, executables, toolchain)

    assert report.schema_version == TERRAFORM_APPLY_READINESS_REPORT_SCHEMA_VERSION
    assert report.config_state is TerraformApplyReadinessStageState.CREATED
    assert report.toolchain_state is TerraformApplyReadinessStageState.VALIDATED
    assert (
        report.machine_validation_state is TerraformApplyReadinessStageState.VALIDATED
    )
    assert report.companion_state is TerraformApplyReadinessCompanionState.CREATED
    assert report.readiness_status == "fresh"
    assert report.remote_connectivity_status == "not-performed"
    assert report.remote_health_status == "not-performed"
    assert report.remote_playbook_status == "not-performed"
    assert report.ansible_deployment_state == "not-started"
    assert report.finalization_state == "not-started"
    assert report.runner_invoked
    assert report.automatic_retry_allowed
    assert not report.manual_recovery_required
    assert runner.specs is not None
    assert [spec.argv[1:] for spec in runner.specs] == [
        ("--version",),
        ("--version",),
        (
            "--inventory",
            str(prepared.paths.ansible_inventory),
            "--list",
        ),
    ]
    assert all(spec.cwd == prepared.paths.ansible for spec in runner.specs)
    inventory_spec = runner.specs[-1]
    environment = inventory_spec.environment.for_subprocess()
    assert environment["ANSIBLE_CONFIG"] == str(prepared.paths.ansible_config)
    assert environment["LC_ALL"] == "C.UTF-8"
    assert "PATH" not in environment
    assert "ANSIBLE_INVENTORY_PLUGINS" not in environment
    assert "ANSIBLE_CALLBACK_PLUGINS" not in environment
    assert inventory_spec.timeout_seconds > 0
    assert inventory_spec.max_output_bytes == 4 * 1024 * 1024

    config = prepared.paths.ansible_config.read_text(encoding="utf-8")
    assert prepared.paths.ansible_config.stat().st_mode & 0o777 == 0o600
    assert "host_key_checking = True" in config
    assert str(prepared.paths.ansible_inventory) in config
    assert str(prepared.paths.ansible_ssh_config) in config
    assert str(prepared.paths.logs / "ansible.log") in config
    assert str(prepared.paths.ansible_home) in config
    assert str(prepared.paths.ansible_local_tmp) in config
    assert str(prepared.paths.ansible_control_path) in config
    ssh_config = prepared.paths.ansible_ssh_config.read_text(encoding="utf-8")
    assert str(prepared.paths.known_hosts) in ssh_config
    assert "StrictHostKeyChecking yes" in ssh_config

    companion_path = terraform_apply_readiness_path(prepared.paths, OPERATION_ID)
    companion_text = companion_path.read_text(encoding="utf-8")
    report_text = json.dumps(report.to_object(), sort_keys=True)
    for protected in (
        "10.0.0.",
        "ocid1.instance",
        "ssh-ed25519",
        str(prepared.paths.state_root),
        '"hostvars"',
    ):
        assert protected not in companion_text
        assert protected not in report_text
    stored = TerraformApplyReadinessStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    assert stored.record.schema_version == TERRAFORM_APPLY_READINESS_SCHEMA_VERSION

    journal = OperationJournalStore(prepared.paths, OPERATION_ID).read(
        expected_cluster_uuid=CLUSTER_UUID,
        expected_cluster_name="example",
    )
    assert journal.record.status is JournalStatus.IN_PROGRESS
    assert journal.record.phase is OperationPhase.VERIFY

    replay_runner = ReadinessRunner([])
    replay = _call(prepared, replay_runner, executables, toolchain)
    assert replay.config_state is TerraformApplyReadinessStageState.REUSED
    assert replay.toolchain_state is TerraformApplyReadinessStageState.REUSED
    assert replay.machine_validation_state is TerraformApplyReadinessStageState.REUSED
    assert replay.companion_state is TerraformApplyReadinessCompanionState.REUSED
    assert not replay.runner_invoked
    assert replay_runner.specs == []


@pytest.mark.parametrize("trust_state", ["missing", "staged", "conflicting"])
def test_incomplete_or_conflicting_trust_is_refused_before_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    trust_state: str,
) -> None:
    prepared, observation, inventory = trust_helpers._prepared(tmp_path, monkeypatch)
    if trust_state == "staged":
        trust_helpers._jump_stage(prepared, observation, inventory)
    else:
        trust_helpers._complete(prepared, observation, inventory)
        if trust_state == "missing":
            terraform_apply_trust_path(prepared.paths, OPERATION_ID).unlink()
        else:
            prepared.paths.known_hosts.write_text("conflict\n", encoding="utf-8")
            prepared.paths.known_hosts.chmod(0o600)
    executables = ControlledAnsibleExecutables(
        _executable(tmp_path, "ansible-playbook"),
        _executable(tmp_path, "ansible-inventory"),
    )
    runner = ReadinessRunner([])
    with (
        ClusterLock(prepared.paths, "deploy", 0) as lock,
        pytest.raises(StateConflictError),
    ):
        validate_deploy_ansible_readiness(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            lock,
            runner,
            executables,
            AnsibleToolchain(AnsibleCoreVersion(2, 20, 9)),
        )
    assert runner.specs == []
    assert not terraform_apply_readiness_path(prepared.paths, OPERATION_ID).exists()


@pytest.mark.parametrize(
    ("listed", "message"),
    [
        ("{not-json", "local Ansible inventory validation failed"),
        (b"\xff", "local Ansible inventory validation failed"),
        ("[" + (" " * (4 * 1024 * 1024)) + "]", "local Ansible inventory"),
    ],
)
def test_malformed_machine_output_fails_without_companion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    listed: str | bytes,
    message: str,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    runner = _runner(inventory, listed=listed)
    with pytest.raises(AnsibleError, match=message):
        _call(prepared, runner, executables, toolchain)
    assert not terraform_apply_readiness_path(prepared.paths, OPERATION_ID).exists()
    assert runner.specs is not None and len(runner.specs) == 3


def test_toolchain_conflict_and_machine_route_conflict_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    mismatch = ReadinessRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.8]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.8]\n", ""),
        ]
    )
    with pytest.raises(ToolPrerequisiteError, match="differs"):
        _call(prepared, mismatch, executables, toolchain)
    assert mismatch.specs is not None and len(mismatch.specs) == 2

    machine = inventory.record.to_machine_object()
    meta = cast(dict[str, object], machine["_meta"])
    hostvars = cast(dict[str, object], meta["hostvars"])
    private_id = next(
        host.logical_id
        for host in inventory.record.inventory.hosts
        if host.jump_host_id is not None
    )
    private_vars = cast(dict[str, object], hostvars[private_id])
    private_vars["deploy_scylla_vms_jump_host_id"] = "wrong-jump"
    conflict = _runner(inventory, listed=json.dumps(machine, sort_keys=True))
    with pytest.raises(AnsibleError, match="local Ansible inventory validation failed"):
        _call(prepared, conflict, executables, toolchain)
    assert not terraform_apply_readiness_path(prepared.paths, OPERATION_ID).exists()


@pytest.mark.parametrize("failure", ["unsupported", "version-mismatch", "runner-error"])
def test_toolchain_failures_stop_before_machine_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    prepared, _, executables, toolchain = _prepared(tmp_path, monkeypatch)
    if failure == "unsupported":
        runner = ReadinessRunner(
            [ProcessResult(0, "ansible-playbook [core 2.21.0]\n", "")]
        )
    elif failure == "version-mismatch":
        runner = ReadinessRunner(
            [
                ProcessResult(0, "ansible-playbook [core 2.20.8]\n", ""),
                ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
            ]
        )
    else:
        runner = ReadinessRunner([], error_at=1)
    with pytest.raises(ToolPrerequisiteError, match="toolchain validation failed"):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs is not None
    assert 1 <= len(runner.specs) <= 2
    assert not terraform_apply_readiness_path(prepared.paths, OPERATION_ID).exists()


@pytest.mark.parametrize("conflict", ["host", "group", "hostvar"])
def test_machine_inventory_identity_group_and_hostvar_conflicts_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    conflict: str,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    machine = inventory.record.to_machine_object()
    meta = cast(dict[str, object], machine["_meta"])
    hostvars = cast(dict[str, object], meta["hostvars"])
    first_id = sorted(hostvars)[0]
    if conflict == "host":
        hostvars["extra-host"] = hostvars.pop(first_id)
    elif conflict == "group":
        machine["unexpected-group"] = {"hosts": [first_id]}
    else:
        first = cast(dict[str, object], hostvars[first_id])
        first["deploy_scylla_vms_role"] = "wrong-role"
    runner = _runner(inventory, listed=json.dumps(machine, sort_keys=True))
    with pytest.raises(AnsibleError, match="local Ansible inventory validation failed"):
        _call(prepared, runner, executables, toolchain)
    assert not terraform_apply_readiness_path(prepared.paths, OPERATION_ID).exists()


def test_companion_write_failure_repeats_only_safe_local_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    original_write = TerraformApplyReadinessStore.write_locked

    def fail_write(*_args: object, **_kwargs: object) -> object:
        raise StatePersistenceError("injected companion write failure")

    monkeypatch.setattr(TerraformApplyReadinessStore, "write_locked", fail_write)
    with pytest.raises(StatePersistenceError, match="injected"):
        _call(prepared, _runner(inventory), executables, toolchain)
    assert prepared.paths.ansible_config.exists()
    assert not terraform_apply_readiness_path(prepared.paths, OPERATION_ID).exists()

    monkeypatch.setattr(TerraformApplyReadinessStore, "write_locked", original_write)
    recovered_runner = _runner(inventory)
    recovered = _call(prepared, recovered_runner, executables, toolchain)
    assert recovered.config_state is TerraformApplyReadinessStageState.REUSED
    assert recovered.companion_state is TerraformApplyReadinessCompanionState.CREATED
    assert recovered.runner_invoked
    assert recovered_runner.specs is not None
    assert len(recovered_runner.specs) == 3


def test_trust_derivative_change_during_local_validation_leaves_no_companion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)

    def mutate_after_inventory(call_count: int) -> None:
        if call_count == 3:
            prepared.paths.known_hosts.write_text("changed\n", encoding="utf-8")
            prepared.paths.known_hosts.chmod(0o600)

    runner = _runner(inventory)
    runner.after_run = mutate_after_inventory
    with pytest.raises(
        AnsibleError,
        match="local Ansible inventory validation failed",
    ):
        _call(prepared, runner, executables, toolchain)
    assert not terraform_apply_readiness_path(prepared.paths, OPERATION_ID).exists()


@pytest.mark.parametrize(
    "artifact_name",
    [
        "terraform_source_record",
        "terraform_observed",
        "ansible_inventory",
        "ansible_trust",
    ],
)
def test_bound_artifact_drift_is_refused_before_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_name: str,
) -> None:
    prepared, _, executables, toolchain = _prepared(tmp_path, monkeypatch)
    path = cast(Path, getattr(prepared.paths, artifact_name))
    value = json.loads(path.read_text(encoding="utf-8"))
    value["unexpected"] = True
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    path.chmod(0o600)
    runner = ReadinessRunner([])
    with pytest.raises((StateConflictError, StatePersistenceError)):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
    assert not terraform_apply_readiness_path(prepared.paths, OPERATION_ID).exists()


@pytest.mark.parametrize("unsafe_state", ["config-symlink", "companion-mode"])
def test_canonical_path_symlink_and_permission_conflicts_fail_before_reentry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_state: str,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    if unsafe_state == "config-symlink":
        target = prepared.paths.ansible / "unexpected.cfg"
        target.write_text("[defaults]\n", encoding="utf-8")
        target.chmod(0o600)
        prepared.paths.ansible_config.symlink_to(target)
    else:
        _call(prepared, _runner(inventory), executables, toolchain)
        terraform_apply_readiness_path(prepared.paths, OPERATION_ID).chmod(0o644)
    runner = ReadinessRunner([])
    with pytest.raises((StatePersistenceError, UnsafePathError)):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []


def test_requires_matching_held_lock_and_rejects_conflicting_companion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, inventory, executables, toolchain = _prepared(tmp_path, monkeypatch)
    with pytest.raises(StateLockError):
        validate_deploy_ansible_readiness(
            prepared.paths.state_root,
            "example",
            OPERATION_ID,
            cast(ClusterLock, object()),
            _runner(inventory),
            executables,
            toolchain,
        )

    _call(prepared, _runner(inventory), executables, toolchain)
    path = terraform_apply_readiness_path(prepared.paths, OPERATION_ID)
    value = json.loads(path.read_text(encoding="utf-8"))
    value["remote_health_status"] = "performed"
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    path.chmod(0o600)
    runner = ReadinessRunner([])
    with pytest.raises(StatePersistenceError):
        _call(prepared, runner, executables, toolchain)
    assert runner.specs == []
