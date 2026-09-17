import inspect
import json
import math
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_ansible import DIGEST, _executable, _inventory_preflight_output
from test_ansible_operation_binding import _OPERATION_ID, _request
from test_check_jump_hosts import _graph, _prepared_state, _recap

from scylla_vms.ansible.commands import AnsibleCommandBuilder
from scylla_vms.ansible.operation_binding import (
    OperationPlanBindingStore,
    StoredOperationPlanBinding,
    build_operation_plan_binding,
    normalized_operation_request_digest,
)
from scylla_vms.ansible.operation_context import (
    OperationContextStore,
    StoredOperationContext,
    build_operation_context,
)
from scylla_vms.ansible.operation_coordinator import (
    ANSIBLE_OPERATION_COORDINATOR_REPORT_SCHEMA_VERSION,
    AnsibleOperationCoordinatorReport,
    ControlledAnsibleExecutables,
    coordinate_ansible_operation_step,
)
from scylla_vms.ansible.operation_execution import (
    ExecutionAttemptState,
    OperationExecutionStore,
    StoredOperationExecution,
)
from scylla_vms.ansible.orchestration import (
    AnsibleOperationPlan,
    AnsibleStepIntent,
    ansible_operation_plan_checkpoint_evidence,
)
from scylla_vms.ansible.readiness import (
    InventoryMachineEvidence,
    ReadinessReport,
    build_readiness_report,
)
from scylla_vms.ansible.service import AnsibleService
from scylla_vms.ansible.trust import StoredTrustRecord
from scylla_vms.check_jump_hosts import resolve_jump_host_operation_selection
from scylla_vms.cli import parse_operation_request
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    ToolPrerequisiteError,
    UnsafePathError,
)
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.journal import (
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    OperationRecord,
)
from scylla_vms.locking import ClusterLock, ClusterReadLock
from scylla_vms.models import OperationRequest
from scylla_vms.observed import ObservedStateStore, StoredObservedState
from scylla_vms.persistence import (
    ClusterMetadataStore,
    StoredClusterMetadata,
    serialize_json,
)
from scylla_vms.process import ProcessResult, ProcessSpec
from scylla_vms.state import StatePaths

_OTHER_DIGEST = "sha256:" + "b" * 64
_SECRET = "obviously-fake-secret-value"
_PRIVATE_PATH = "/private/operator/id_ed25519"


def _clock(second: int) -> datetime:
    return datetime(2026, 9, 18, 15, 0, second, tzinfo=UTC)


def _intents_for_request(
    request: OperationRequest,
    inventory: StoredInventoryRecord,
) -> tuple[AnsibleStepIntent, ...]:
    selection = resolve_jump_host_operation_selection(request, inventory)
    selected = tuple(host.logical_id for host in selection.selected)
    timeout = request.option("connect_timeout_seconds").value
    assert isinstance(timeout, float)
    return (
        AnsibleStepIntent(1, selected, {}, check=True),
        AnsibleStepIntent(
            2,
            selected,
            {
                "deploy_scylla_vms_connect_timeout_seconds": timeout,
                "deploy_scylla_vms_destination_probes": [
                    probe.to_variable() for probe in selection.probes
                ],
                "deploy_scylla_vms_probe_timeout_seconds": max(1, math.ceil(timeout)),
            },
            check=True,
        ),
    )


@dataclass(frozen=True)
class PreparedCoordinator:
    paths: StatePaths
    metadata: StoredClusterMetadata
    observed: StoredObservedState
    inventory: StoredInventoryRecord
    trust: StoredTrustRecord
    request: OperationRequest
    readiness: ReadinessReport
    plan: AnsibleOperationPlan
    binding: StoredOperationPlanBinding
    operation_context: StoredOperationContext
    executables: ControlledAnsibleExecutables


@dataclass
class FakeCoordinatorRunner:
    results: list[ProcessResult]
    fail_at: int | None = None
    error: Exception | None = None
    checkpoint_path: Path | None = None
    specs: list[ProcessSpec] | None = None
    saw_started: bool = False

    def __post_init__(self) -> None:
        self.specs = []

    def run(self, spec: ProcessSpec) -> ProcessResult:
        assert self.specs is not None
        self.specs.append(spec)
        if "--extra-vars" in spec.argv and self.checkpoint_path is not None:
            value = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
            self.saw_started = value["attempts"][-1]["state"] == "started"
        if self.fail_at == len(self.specs):
            raise self.error or RuntimeError(f"{_SECRET} {_PRIVATE_PATH}")
        if not self.results:
            raise AssertionError("unexpected controlled runner invocation")
        result = self.results.pop(0)
        stdout = result.stdout
        stderr = result.stderr
        for value in spec.sensitive_values:
            stdout = stdout.replace(value, "[REDACTED]")
            stderr = stderr.replace(value, "[REDACTED]")
        for path in spec.sensitive_paths:
            stdout = stdout.replace(str(path), "[REDACTED_PATH]")
            stderr = stderr.replace(str(path), "[REDACTED_PATH]")
        return ProcessResult(result.exit_code, stdout, stderr)


def _prepare(
    tmp_path: Path,
    *,
    request_arguments: tuple[str, ...] = (),
) -> PreparedCoordinator:
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    paths, inventory, trust = _prepared_state(tmp_path)
    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name="example",
        expected_provider="oci",
    )
    observed = ObservedStateStore(paths).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_provider=metadata.record.provider,
    )
    readiness = build_readiness_report(
        observed,
        inventory,
        trust,
        machine_evidence=InventoryMachineEvidence(
            DIGEST,
            DIGEST,
            len(inventory.record.inventory.hosts),
            len(inventory.record.inventory.groups),
        ),
    )
    request = (
        _request(paths)
        if not request_arguments
        else parse_operation_request(
            [
                "--cluster-name",
                "example",
                "--state-dir",
                str(paths.state_root),
                "check-jump-hosts",
                *request_arguments,
            ],
            environ={},
        )
    )
    intents = _intents_for_request(request, inventory)
    executables = ControlledAnsibleExecutables(
        _executable(tmp_path, "ansible-playbook"),
        _executable(tmp_path, "ansible-inventory"),
    )
    service = AnsibleService(
        AnsibleCommandBuilder(
            executables.playbook,
            executables.inventory,
            paths,
        ),
        FakeCoordinatorRunner([]),
    )
    with ClusterLock(paths, request.operation.name, 0) as lock:
        plan = service.plan_operation(
            lock,
            metadata.record,
            inventory,
            request.operation.name,
            readiness=readiness,
            active_conditions=(),
            intents=intents,
        )
        pending = OperationRecord.create(
            operation_id=_OPERATION_ID,
            operation=request.operation.name,
            cluster_uuid=metadata.record.cluster_uuid,
            cluster_name=metadata.record.cluster_name,
            request_digest=normalized_operation_request_digest(request),
            clock=lambda: _clock(0),
        )
        journal_store = OperationJournalStore(paths, _OPERATION_ID)
        initial = journal_store.write(
            pending,
            expected_generation=0,
            expected_digest=None,
        )
        journal = journal_store.write(
            pending.transition(
                status=JournalStatus.IN_PROGRESS,
                phase=OperationPhase.PLAN,
                evidence=(ansible_operation_plan_checkpoint_evidence(plan),),
                clock=lambda: _clock(1),
            ),
            expected_generation=initial.record.generation,
            expected_digest=initial.digest,
        )
        candidate = build_operation_plan_binding(
            metadata.record,
            request,
            _OPERATION_ID,
            plan,
            readiness,
            journal,
            clock=lambda: _clock(2),
        )
        binding = OperationPlanBindingStore(paths, _OPERATION_ID).write_locked(
            candidate,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        operation_context = OperationContextStore(paths, _OPERATION_ID).write_locked(
            build_operation_context(
                metadata.record,
                request,
                _OPERATION_ID,
                plan,
                binding,
                clock=lambda: _clock(3),
            ),
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    return PreparedCoordinator(
        paths,
        metadata,
        observed,
        inventory,
        trust,
        request,
        readiness,
        plan,
        binding,
        operation_context,
        executables,
    )


def _results(
    prepared: PreparedCoordinator,
    playbook_result: ProcessResult | None = None,
    *,
    playbook_version: str = "2.20.9",
    inventory_version: str = "2.20.9",
) -> list[ProcessResult]:
    return [
        ProcessResult(
            0,
            f"ansible-playbook [core {playbook_version}]\n",
            f"{_SECRET} {_PRIVATE_PATH}",
        ),
        ProcessResult(
            0,
            f"ansible-inventory [core {inventory_version}]\n",
            "",
        ),
        ProcessResult(
            0,
            json.dumps(prepared.inventory.record.to_machine_object()),
            "",
        ),
        ProcessResult(0, _graph(prepared.inventory), ""),
        playbook_result
        or ProcessResult(
            0,
            _inventory_preflight_output(prepared.inventory),
            f"{_SECRET} {_PRIVATE_PATH}",
        ),
    ]


def _coordinate(
    prepared: PreparedCoordinator,
    runner: FakeCoordinatorRunner,
) -> AnsibleOperationCoordinatorReport:
    with ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock:
        return coordinate_ansible_operation_step(
            prepared.paths.state_root,
            prepared.metadata.record.cluster_name,
            _OPERATION_ID,
            lock,
            runner=runner,
            executables=prepared.executables,
        )


def _read_execution(prepared: PreparedCoordinator) -> StoredOperationExecution:
    with ClusterReadLock(prepared.paths, 0) as lock:
        return OperationExecutionStore(
            prepared.paths,
            _OPERATION_ID,
        ).read_locked(
            lock,
            expected_cluster_uuid=prepared.metadata.record.cluster_uuid,
            expected_cluster_name=prepared.metadata.record.cluster_name,
            expected_operation=prepared.request.operation.name,
        )


def test_coordinator_loads_canonical_context_and_hands_off_exactly_one_step(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    execution_path = OperationExecutionStore(prepared.paths, _OPERATION_ID).path
    runner = FakeCoordinatorRunner(
        _results(prepared),
        checkpoint_path=execution_path,
    )

    report = _coordinate(prepared, runner)

    assert report.schema_version == ANSIBLE_OPERATION_COORDINATOR_REPORT_SCHEMA_VERSION
    assert report.execution_state is ExecutionAttemptState.SUCCEEDED
    assert report.attempt_index == 1
    assert report.step_sequence == 1
    assert not report.all_steps_completed
    assert not report.manual_recovery_required
    assert not report.automatic_retry_allowed
    assert runner.saw_started
    assert runner.specs is not None
    assert len(runner.specs) == 5
    playbooks = [spec for spec in runner.specs if "--extra-vars" in spec.argv]
    assert len(playbooks) == 1
    assert all(spec.cwd == prepared.paths.ansible for spec in runner.specs)
    assert all("PATH" not in spec.environment.names for spec in runner.specs)
    assert all(
        not {
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ANSIBLE_CALLBACK_PLUGINS",
            "ANSIBLE_INVENTORY_PLUGINS",
            "ANSIBLE_LIBRARY",
        }
        & set(spec.environment.names)
        for spec in runner.specs
    )
    encoded = json.dumps(report.to_object())
    assert _SECRET not in encoded
    assert _PRIVATE_PATH not in encoded
    assert str(_OPERATION_ID) not in encoded
    assert str(prepared.metadata.record.cluster_uuid) not in encoded
    assert "jump-host-1" not in encoded
    assert set(report.to_object()) == {
        "attempt",
        "digests",
        "operation",
        "schema_version",
        "schemas",
    }
    assert (
        dict(report.schemas)["context"]
        == prepared.operation_context.record.schema_version
    )
    assert dict(report.digests)["context"] == prepared.operation_context.digest


def test_coordinator_reconstructs_nondefault_safe_context(
    tmp_path: Path,
) -> None:
    prepared = _prepare(
        tmp_path,
        request_arguments=(
            "--jump-host",
            "jump-host-1",
            "--destination",
            "scylla",
            "--depth",
            "route",
            "--destination-check",
            "scylla=9042",
            "--connect-timeout-seconds",
            "2.5",
            "--check-timeout-seconds",
            "45",
        ),
    )
    runner = FakeCoordinatorRunner(_results(prepared))

    report = _coordinate(prepared, runner)

    assert report.execution_state is ExecutionAttemptState.SUCCEEDED
    assert runner.specs is not None
    assert len(runner.specs) == 5
    persisted = OperationContextStore(prepared.paths, _OPERATION_ID).path.read_text(
        encoding="utf-8"
    )
    assert "10.0.0." not in persisted
    assert "203.0.113." not in persisted


@pytest.mark.parametrize(
    ("playbook_version", "inventory_version"),
    [
        ("2.16.9", "2.16.9"),
        ("2.20.9", "2.19.8"),
    ],
)
def test_toolchain_refusal_precedes_durable_start(
    tmp_path: Path,
    playbook_version: str,
    inventory_version: str,
) -> None:
    prepared = _prepare(tmp_path)
    runner = FakeCoordinatorRunner(
        _results(
            prepared,
            playbook_version=playbook_version,
            inventory_version=inventory_version,
        )
    )

    with pytest.raises(ToolPrerequisiteError, match="toolchain validation failed"):
        _coordinate(prepared, runner)

    assert not OperationExecutionStore(prepared.paths, _OPERATION_ID).path.exists()
    assert runner.specs is not None
    assert not [spec for spec in runner.specs if "--extra-vars" in spec.argv]


def test_toolchain_failure_is_redacted_retry_safe_and_before_started(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    failed = FakeCoordinatorRunner(
        [],
        fail_at=1,
        error=ToolPrerequisiteError(f"{_SECRET} {_PRIVATE_PATH}"),
    )
    with pytest.raises(ToolPrerequisiteError) as captured:
        _coordinate(prepared, failed)
    assert _SECRET not in str(captured.value)
    assert _PRIVATE_PATH not in str(captured.value)
    assert not OperationExecutionStore(prepared.paths, _OPERATION_ID).path.exists()

    healthy = FakeCoordinatorRunner(_results(prepared))
    report = _coordinate(prepared, healthy)
    assert report.execution_state is ExecutionAttemptState.SUCCEEDED


@pytest.mark.parametrize(
    "change",
    ["readiness", "source", "catalog", "plan"],
)
def test_bound_context_drift_refuses_before_adapter_invocation(
    tmp_path: Path,
    change: str,
) -> None:
    prepared = _prepare(tmp_path)
    binding_path = OperationPlanBindingStore(prepared.paths, _OPERATION_ID).path
    document = json.loads(binding_path.read_text(encoding="utf-8"))
    document[
        {
            "readiness": "readiness_digest",
            "source": "source_digest",
            "catalog": "catalog_digest",
            "plan": "plan_digest",
        }[change]
    ] = _OTHER_DIGEST
    binding_path.write_bytes(serialize_json(document))
    binding_path.chmod(0o600)
    runner = FakeCoordinatorRunner(_results(prepared))

    with pytest.raises(StateConflictError, match=r"drifted|binding"):
        _coordinate(prepared, runner)

    assert not OperationExecutionStore(prepared.paths, _OPERATION_ID).path.exists()
    assert runner.specs is not None
    assert not [spec for spec in runner.specs if "--extra-vars" in spec.argv]


@pytest.mark.parametrize(
    "artifact",
    [
        "missing-binding",
        "malformed-binding",
        "missing-context",
        "malformed-context",
        "missing-trust",
        "malformed-trust",
        "malformed-authorization",
        "malformed-execution",
    ],
)
def test_missing_or_malformed_canonical_artifacts_fail_closed(
    tmp_path: Path,
    artifact: str,
) -> None:
    prepared = _prepare(tmp_path)
    binding_path = OperationPlanBindingStore(prepared.paths, _OPERATION_ID).path
    if artifact == "missing-binding":
        binding_path.unlink()
    elif artifact == "malformed-binding":
        binding_path.write_text("{}\n", encoding="utf-8")
    elif artifact == "missing-context":
        OperationContextStore(prepared.paths, _OPERATION_ID).path.unlink()
    elif artifact == "malformed-context":
        OperationContextStore(prepared.paths, _OPERATION_ID).path.write_text(
            "{}\n", encoding="utf-8"
        )
    elif artifact == "missing-trust":
        prepared.paths.ansible_trust.unlink()
    elif artifact == "malformed-trust":
        prepared.paths.ansible_trust.write_text("{}\n", encoding="utf-8")
    elif artifact == "malformed-authorization":
        path = (
            prepared.paths.operations
            / f"{_OPERATION_ID}.ansible-operation-authorization.json"
        )
        path.write_text("{}\n", encoding="utf-8")
        path.chmod(0o600)
    else:  # malformed-execution
        path = OperationExecutionStore(prepared.paths, _OPERATION_ID).path
        path.write_text("{}\n", encoding="utf-8")
        path.chmod(0o600)
    runner = FakeCoordinatorRunner(_results(prepared))

    with pytest.raises((StatePersistenceError, UnsafePathError)):
        _coordinate(prepared, runner)

    assert runner.specs == []


def test_completed_and_recovery_required_execution_never_invoke_again(
    tmp_path: Path,
) -> None:
    completed = _prepare(tmp_path / "completed")
    first = FakeCoordinatorRunner(_results(completed))
    _coordinate(completed, first)
    second = FakeCoordinatorRunner(_results(completed, ProcessResult(0, _recap(), "")))
    report = _coordinate(completed, second)
    assert report.all_steps_completed
    assert report.step_sequence == 2
    refused = FakeCoordinatorRunner([])
    with pytest.raises(StateConflictError, match="fully consumed"):
        _coordinate(completed, refused)
    assert refused.specs == []

    recovery = _prepare(tmp_path / "recovery")
    failed = FakeCoordinatorRunner(
        _results(recovery)[:4],
        fail_at=5,
        checkpoint_path=OperationExecutionStore(recovery.paths, _OPERATION_ID).path,
    )
    with pytest.raises(AnsibleError, match="failed after invocation"):
        _coordinate(recovery, failed)
    stored = _read_execution(recovery)
    assert stored.record.state is ExecutionAttemptState.FAILED
    assert stored.record.attempts[-1].manual_recovery_required
    assert not stored.record.attempts[-1].automatic_retry_allowed
    assert failed.saw_started
    retry = FakeCoordinatorRunner([])
    with pytest.raises(StateConflictError, match="manual recovery review"):
        _coordinate(recovery, retry)
    assert retry.specs == []


def test_lock_scope_and_entry_point_reject_injection_surfaces(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    runner = FakeCoordinatorRunner(_results(prepared))
    unlocked = ClusterLock(prepared.paths, prepared.request.operation.name, 0)
    with pytest.raises(StateLockError):
        coordinate_ansible_operation_step(
            prepared.paths.state_root,
            prepared.metadata.record.cluster_name,
            _OPERATION_ID,
            unlocked,
            runner=runner,
            executables=prepared.executables,
        )
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError, match="matching operation"),
    ):
        coordinate_ansible_operation_step(
            prepared.paths.state_root,
            prepared.metadata.record.cluster_name,
            _OPERATION_ID,
            wrong_lock,
            runner=runner,
            executables=prepared.executables,
        )
    assert runner.specs == []

    parameters = inspect.signature(coordinate_ansible_operation_step).parameters
    assert tuple(parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
        "runner",
        "executables",
    )
    unsafe = _executable(tmp_path, "arbitrary-command")
    with pytest.raises(ToolPrerequisiteError, match="exact sibling pair"):
        ControlledAnsibleExecutables(unsafe, prepared.executables.inventory)
    with (
        ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock,
        pytest.raises(UnsafePathError, match="canonical"),
    ):
        coordinate_ansible_operation_step(
            prepared.paths.state_root / ".." / "state",
            prepared.metadata.record.cluster_name,
            _OPERATION_ID,
            lock,
            runner=runner,
            executables=prepared.executables,
        )


@pytest.mark.skipif(not hasattr(Path, "symlink_to"), reason="symlink support required")
def test_canonical_permissions_and_symlinks_are_refused(tmp_path: Path) -> None:
    permissions = _prepare(tmp_path / "permissions")
    OperationPlanBindingStore(permissions.paths, _OPERATION_ID).path.chmod(0o644)
    with (
        ClusterLock(permissions.paths, permissions.request.operation.name, 0) as lock,
        pytest.raises(UnsafePathError, match="0600"),
    ):
        coordinate_ansible_operation_step(
            permissions.paths.state_root,
            permissions.metadata.record.cluster_name,
            _OPERATION_ID,
            lock,
            runner=FakeCoordinatorRunner([]),
            executables=permissions.executables,
        )

    symlink = _prepare(tmp_path / "symlink")
    target = tmp_path / "outside-inventory.yml"
    target.write_bytes(symlink.paths.ansible_inventory.read_bytes())
    target.chmod(0o600)
    symlink.paths.ansible_inventory.unlink()
    symlink.paths.ansible_inventory.symlink_to(target)
    with (
        ClusterLock(symlink.paths, symlink.request.operation.name, 0) as lock,
        pytest.raises(UnsafePathError, match="symbolic link"),
    ):
        coordinate_ansible_operation_step(
            symlink.paths.state_root,
            symlink.metadata.record.cluster_name,
            _OPERATION_ID,
            lock,
            runner=FakeCoordinatorRunner([]),
            executables=symlink.executables,
        )


def test_non_uuid_operation_identity_is_refused(tmp_path: Path) -> None:
    prepared = _prepare(tmp_path)
    with (
        ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock,
        pytest.raises(StatePersistenceError, match="must be a UUID"),
    ):
        coordinate_ansible_operation_step(
            prepared.paths.state_root,
            prepared.metadata.record.cluster_name,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",  # type: ignore[arg-type]
            lock,
            runner=FakeCoordinatorRunner([]),
            executables=prepared.executables,
        )
    assert isinstance(_OPERATION_ID, uuid.UUID)
