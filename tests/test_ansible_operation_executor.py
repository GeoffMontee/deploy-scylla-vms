import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, fields, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from test_ansible import DIGEST, FakeRunner, _builder
from test_ansible_operation_binding import (
    _OPERATION_ID,
    _intents,
    _request,
)
from test_check_jump_hosts import _prepared_state

import scylla_vms.ansible.operation_executor as executor_module
from scylla_vms.ansible.operation_binding import (
    OperationPlanBindingStore,
    StoredOperationPlanBinding,
    build_operation_plan_binding,
    normalized_operation_request_digest,
)
from scylla_vms.ansible.operation_context import (
    OperationContextStore,
    build_operation_context,
)
from scylla_vms.ansible.operation_evidence import OperationEvidenceStore
from scylla_vms.ansible.operation_execution import (
    ExecutionAttemptState,
    OperationExecutionStore,
    OperationStepExecution,
    StoredOperationExecution,
    handoff_operation_step,
)
from scylla_vms.ansible.operation_executor import (
    ControlledAnsibleExecutionContext,
    ControlledAnsibleOperationExecutor,
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
from scylla_vms.ansible.service import AnsibleService, InventoryPreflightEvidence
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.ansible.trust import StoredTrustRecord
from scylla_vms.errors import AnsibleError, StateConflictError
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
from scylla_vms.persistence import ClusterMetadataStore, StoredClusterMetadata
from scylla_vms.process import ProcessOutputError, ProcessResult, ProcessTimeoutError
from scylla_vms.state import StatePaths

_OTHER_DIGEST = "sha256:" + "b" * 64
_SECRET = "obviously-fake-secret-value"
_PRIVATE_PATH = "/private/operator/id_ed25519"


@dataclass
class PreparedAdapter:
    paths: StatePaths
    metadata: StoredClusterMetadata
    observed: StoredObservedState
    inventory: StoredInventoryRecord
    trust: StoredTrustRecord
    readiness: ReadinessReport
    request: OperationRequest
    plan: AnsibleOperationPlan
    intents: tuple[AnsibleStepIntent, ...]
    binding: StoredOperationPlanBinding
    service: AnsibleService
    runner: FakeRunner

    def context(
        self,
        lock: ClusterLock,
        *,
        readiness: ReadinessReport | None = None,
    ) -> ControlledAnsibleExecutionContext:
        return ControlledAnsibleExecutionContext(
            self.paths,
            lock,
            self.metadata,
            self.observed,
            self.inventory,
            self.trust,
            readiness or self.readiness,
            self.binding,
        )


class _StartedCheckpoint(BaseException):
    pass


@dataclass
class _StartOnlyExecutor:
    step: OperationStepExecution | None = None

    def execute(self, step: OperationStepExecution) -> dict[str, object]:
        self.step = step
        raise _StartedCheckpoint


def _clock(second: int) -> datetime:
    return datetime(2026, 9, 18, 14, 0, second, tzinfo=UTC)


def _clock_sequence(*seconds: int) -> Callable[[], datetime]:
    values = iter(_clock(second) for second in seconds)
    return lambda: next(values)


def _prepare(tmp_path: Path) -> PreparedAdapter:
    paths, inventory, trust = _prepared_state(tmp_path)
    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name="example", expected_provider="oci"
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
    request = _request(paths)
    intents = _intents()
    runner = FakeRunner(
        [
            ProcessResult(0, "ansible-playbook [core 2.20.9]\n", ""),
            ProcessResult(0, "ansible-inventory [core 2.20.9]\n", ""),
        ]
    )
    service = AnsibleService(_builder(tmp_path, paths), runner)
    journal_store = OperationJournalStore(paths, _OPERATION_ID)
    binding_store = OperationPlanBindingStore(paths, _OPERATION_ID)
    with ClusterLock(paths, request.operation.name, 0) as lock:
        service.version(lock)
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
        initial = journal_store.write(
            pending, expected_generation=0, expected_digest=None
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
        binding = binding_store.write_locked(
            build_operation_plan_binding(
                metadata.record,
                request,
                _OPERATION_ID,
                plan,
                readiness,
                journal,
                clock=lambda: _clock(2),
            ),
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        OperationContextStore(paths, _OPERATION_ID).write_locked(
            build_operation_context(
                metadata.record,
                request,
                _OPERATION_ID,
                plan,
                binding,
                clock=lambda: _clock(2),
            ),
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    runner.specs.clear()
    runner.runtime_modes.clear()
    runner.runtime_payloads.clear()
    return PreparedAdapter(
        paths,
        metadata,
        observed,
        inventory,
        trust,
        readiness,
        request,
        plan,
        intents,
        binding,
        service,
        runner,
    )


def _inventory_result(
    prepared: PreparedAdapter,
    *,
    schema_version: str = "deploy-scylla-vms.ansible-inventory-preflight/v1",
    exit_code: int = 0,
    failed: int = 0,
    unreachable: int = 0,
    include_marker: bool = True,
    prefix: str = "",
) -> ProcessResult:
    record = prepared.inventory.record
    payload = {
        "host_count": len(record.inventory.hosts),
        "inventory_file_digest": prepared.inventory.digest,
        "inventory_generation": record.generation,
        "observation_digest": record.source_manifest_digest,
        "observation_generation": record.source_manifest_generation,
        "schema_version": schema_version,
        "status": "passed",
        "target_count": 1,
    }
    marker = ""
    if include_marker:
        encoded = base64.b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        ).decode()
        marker = f'TASK result\nok: [jump-host-1] => {{"msg": "DSV_INVENTORY_PREFLIGHT_B64={encoded}"}}\n'
    recap = (
        "PLAY RECAP *****\n"
        f"jump-host-1 : ok=3 changed=0 unreachable={unreachable} failed={failed} "
        "skipped=0 rescued=0 ignored=0\n"
    )
    return ProcessResult(exit_code, prefix + marker + recap, "")


def _handoff(
    prepared: PreparedAdapter,
    *,
    evidence_store: OperationEvidenceStore | None = None,
) -> StoredOperationExecution:
    with ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock:
        executor = ControlledAnsibleOperationExecutor(
            prepared.service,
            prepared.context(lock),
            evidence_store=evidence_store,
        )
        return handoff_operation_step(
            lock,
            prepared.metadata.record,
            prepared.request,
            _OPERATION_ID,
            prepared.plan,
            prepared.readiness,
            prepared.intents,
            executor,
            clock=_clock_sequence(3, 4),
        )


def _read_execution(prepared: PreparedAdapter) -> StoredOperationExecution:
    with ClusterReadLock(prepared.paths, 0) as lock:
        return OperationExecutionStore(prepared.paths, _OPERATION_ID).read_locked(
            lock,
            expected_cluster_uuid=prepared.metadata.record.cluster_uuid,
            expected_cluster_name=prepared.metadata.record.cluster_name,
            expected_operation=prepared.request.operation.name,
        )


def _persist_started(prepared: PreparedAdapter) -> OperationStepExecution:
    executor = _StartOnlyExecutor()
    with (
        ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock,
        pytest.raises(_StartedCheckpoint),
    ):
        handoff_operation_step(
            lock,
            prepared.metadata.record,
            prepared.request,
            _OPERATION_ID,
            prepared.plan,
            prepared.readiness,
            prepared.intents,
            executor,
            clock=lambda: _clock(3),
        )
    assert executor.step is not None
    return executor.step


def _step(prepared: PreparedAdapter) -> OperationStepExecution:
    intent = prepared.intents[0]
    definition, variables, variables_digest, command_digest = (
        prepared.service.command_builder.validate_operation_step(
            "inventory-preflight",
            step_sequence=1,
            limit=intent.limit,
            variables=intent.variables,
            tags=intent.tags,
            check=intent.check,
            diff=intent.diff,
            verbosity=intent.verbosity,
        )
    )
    source = load_ansible_source_bundle()
    source_digest = {item.path: item.digest for item in source.files}[
        "playbooks/inventory-preflight.yml"
    ]
    return OperationStepExecution(
        _OPERATION_ID,
        prepared.request.operation.name,
        1,
        definition.name,
        definition.classification,
        intent.limit,
        variables,
        intent.tags,
        intent.check,
        intent.diff,
        intent.verbosity,
        variables_digest,
        command_digest,
        source_digest,
        definition.execution_result_schema_version,
    )


def test_strict_adapter_handoff_uses_one_anchored_invocation_and_persists_no_raw(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    prepared.runner.results.append(
        _inventory_result(
            prepared,
            prefix=f"ignored {_SECRET} {_PRIVATE_PATH}\n",
        )
    )

    stored = _handoff(prepared)

    attempt = stored.record.attempts[0]
    assert attempt.state is ExecutionAttemptState.SUCCEEDED
    assert len(prepared.runner.specs) == 1
    spec = prepared.runner.specs[0]
    assert Path(spec.argv[0]).is_absolute()
    assert spec.cwd == prepared.paths.ansible
    assert spec.argv[spec.argv.index("--inventory") + 1] == str(
        prepared.paths.ansible_inventory
    )
    assert spec.argv[spec.argv.index("--limit") + 1] == "jump-host-1"
    assert spec.argv[-1].endswith("/playbooks/inventory-preflight.yml")
    assert "--check" in spec.argv
    assert "--skip-tags" not in spec.argv
    assert attempt.command_digest == _step(prepared).command_digest
    assert not tuple(prepared.paths.ansible_local_tmp.iterdir())
    persisted = OperationExecutionStore(prepared.paths, _OPERATION_ID).path.read_text(
        encoding="utf-8"
    )
    assert _SECRET not in persisted
    assert _PRIVATE_PATH not in persisted
    assert "PLAY RECAP" not in persisted
    assert "DSV_INVENTORY_PREFLIGHT" not in persisted


@pytest.mark.parametrize(
    ("result", "error"),
    [
        ("missing", None),
        ("wrong-schema", None),
        ("oversized", None),
        ("non-utf8", ProcessOutputError("invalid output")),
    ],
)
def test_adapter_maps_malformed_output_without_persisting_it(
    tmp_path: Path,
    result: str,
    error: Exception | None,
) -> None:
    prepared = _prepare(tmp_path)
    if error is not None:
        prepared.runner.error = error
    elif result == "missing":
        prepared.runner.results.append(
            _inventory_result(prepared, include_marker=False)
        )
    elif result == "wrong-schema":
        prepared.runner.results.append(
            _inventory_result(prepared, schema_version="wrong/v1")
        )
    else:
        prepared.runner.results.append(
            _inventory_result(prepared, prefix="x" * 262_145)
        )

    with pytest.raises(AnsibleError, match="malformed strict result"):
        _handoff(prepared)

    attempt = _read_execution(prepared).record.attempts[0]
    assert attempt.state is ExecutionAttemptState.MALFORMED_RESULT
    assert attempt.exit_code is None
    persisted = OperationExecutionStore(prepared.paths, _OPERATION_ID).path.read_text(
        encoding="utf-8"
    )
    assert "wrong/v1" not in persisted
    assert "xxxxx" not in persisted
    assert len(prepared.runner.specs) == 1


@pytest.mark.parametrize(
    ("mode", "state"),
    [
        ("failed", ExecutionAttemptState.FAILED),
        ("unreachable", ExecutionAttemptState.UNREACHABLE),
        ("timed-out", ExecutionAttemptState.TIMED_OUT),
        ("interrupted", ExecutionAttemptState.INTERRUPTED),
    ],
)
def test_adapter_maps_controlled_terminal_outcomes(
    tmp_path: Path,
    mode: str,
    state: ExecutionAttemptState,
) -> None:
    prepared = _prepare(tmp_path)
    if mode == "failed":
        prepared.runner.results.append(
            _inventory_result(prepared, exit_code=2, failed=1, include_marker=False)
        )
    elif mode == "unreachable":
        prepared.runner.results.append(
            _inventory_result(
                prepared, exit_code=4, unreachable=1, include_marker=False
            )
        )
    elif mode == "timed-out":
        prepared.runner.error = ProcessTimeoutError(f"{_SECRET} {_PRIVATE_PATH}")
    else:
        prepared.runner.error = cast(Exception, KeyboardInterrupt())

    stored = _handoff(prepared)

    assert stored.record.attempts[0].state is state
    assert len(prepared.runner.specs) == 1
    encoded = json.dumps(stored.to_public_object())
    assert _SECRET not in encoded
    assert _PRIVATE_PATH not in encoded


@pytest.mark.parametrize(
    "drift",
    ["inventory", "trust", "config", "source", "catalog", "readiness"],
)
def test_adapter_refuses_current_context_drift_before_runner_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    prepared = _prepare(tmp_path)
    step = _persist_started(prepared)
    readiness = prepared.readiness
    if drift == "inventory":
        prepared.paths.ansible_inventory.write_text("{}\n", encoding="utf-8")
    elif drift == "trust":
        prepared.paths.known_hosts.write_text("tampered\n", encoding="utf-8")
    elif drift == "config":
        with prepared.paths.ansible_config.open("a", encoding="utf-8") as stream:
            stream.write("# tampered\n")
    elif drift == "source":
        source = load_ansible_source_bundle()
        monkeypatch.setattr(
            executor_module,
            "load_ansible_source_bundle",
            lambda: replace(source, digest=_OTHER_DIGEST),
        )
    elif drift == "catalog":
        monkeypatch.setattr(
            executor_module, "ansible_operation_catalog_digest", lambda: _OTHER_DIGEST
        )
    else:
        readiness = replace(prepared.readiness, inventory_digest=_OTHER_DIGEST)

    with ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock:
        executor = ControlledAnsibleOperationExecutor(
            prepared.service, prepared.context(lock, readiness=readiness)
        )
        receipt = executor.execute(step)

    assert receipt["status"] == "failed"
    assert set(receipt) == {
        "schema_version",
        "step_sequence",
        "playbook",
        "command_digest",
        "status",
        "exit_code",
        "evidence_digest",
    }
    assert prepared.runner.specs == []


def test_adapter_api_cannot_accept_paths_arguments_environment_or_unbound_intent(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    step = _persist_started(prepared)
    assert {item.name for item in fields(ControlledAnsibleExecutionContext)} == {
        "paths",
        "lock",
        "metadata",
        "observed",
        "inventory",
        "trust",
        "readiness",
        "binding",
    }
    assert not {
        "executable",
        "cwd",
        "inventory_path",
        "playbook_path",
        "extra_vars_path",
        "environment",
        "cli_args",
        "skip_tags",
    } & {item.name for item in fields(OperationStepExecution)}
    invalid_steps = (
        replace(step, playbook="../../operator.yml"),
        replace(step, limit=("all",)),
        replace(step, tags=("arbitrary",)),
        replace(step, variables={"arbitrary": _SECRET}),
        replace(step, command_digest=_OTHER_DIGEST),
    )
    with ClusterLock(prepared.paths, prepared.request.operation.name, 0) as lock:
        executor = ControlledAnsibleOperationExecutor(
            prepared.service, prepared.context(lock)
        )
        for invalid in invalid_steps:
            assert executor.execute(invalid)["status"] == "failed"
    assert prepared.runner.specs == []


def test_validation_only_blocked_evidence_is_never_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert (
        executor_module._result_status(
            0,
            {
                "applied": False,
                "blockers": ["target-transition-unapproved"],
                "status": "blocked",
            },
        )
        == "failed"
    )
    prepared = _prepare(tmp_path)
    prepared.runner.results.append(_inventory_result(prepared))
    monkeypatch.setattr(
        executor_module,
        "_parse_strict_evidence",
        lambda *_args: InventoryPreflightEvidence(
            "failed",
            len(prepared.inventory.record.inventory.hosts),
            1,
            prepared.inventory.record.generation,
            prepared.inventory.digest,
            prepared.inventory.record.source_manifest_generation,
            prepared.inventory.record.source_manifest_digest,
        ),
    )

    stored = _handoff(prepared)

    assert stored.record.attempts[0].exit_code == 0
    assert stored.record.attempts[0].state is ExecutionAttemptState.FAILED


def test_evidence_persistence_failure_after_fake_execution_forbids_retry(
    tmp_path: Path,
) -> None:
    prepared = _prepare(tmp_path)
    prepared.runner.results.append(_inventory_result(prepared))

    evidence_store = OperationEvidenceStore(
        prepared.paths,
        _OPERATION_ID,
        token_factory=lambda: "collision",
    )
    temporary = evidence_store.path.with_name(
        f".{evidence_store.path.name}.collision.tmp"
    )
    temporary.write_text("", encoding="utf-8")
    temporary.chmod(0o600)
    with pytest.raises(AnsibleError, match="failed after invocation"):
        _handoff(prepared, evidence_store=evidence_store)

    attempt = _read_execution(prepared).record.attempts[0]
    assert attempt.state is ExecutionAttemptState.FAILED
    assert attempt.manual_recovery_required
    assert not attempt.automatic_retry_allowed
    assert len(prepared.runner.specs) == 1
    assert not evidence_store.path.exists()
    calls = len(prepared.runner.specs)
    with pytest.raises(StateConflictError, match="manual recovery review"):
        _handoff(prepared)
    assert len(prepared.runner.specs) == calls
