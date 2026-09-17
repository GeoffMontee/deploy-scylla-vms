import inspect
import json
from dataclasses import replace
from pathlib import Path

import pytest
from test_ansible_operation_binding import _OPERATION_ID
from test_ansible_operation_coordinator import (
    _PRIVATE_PATH,
    _SECRET,
    FakeCoordinatorRunner,
    PreparedCoordinator,
    _prepare,
    _results,
)
from test_ansible_operation_orchestrator import _orchestrate, _successful_results
from test_check_jump_hosts import _recap, _tcp_recap

import scylla_vms.ansible.operation_finalization as finalization_module
from scylla_vms.ansible.operation_binding import OperationPlanBindingStore
from scylla_vms.ansible.operation_evidence import OperationEvidenceStore
from scylla_vms.ansible.operation_execution import (
    ExecutionAttemptState,
    OperationExecutionStore,
)
from scylla_vms.ansible.operation_finalization import (
    ANSIBLE_CHECK_JUMP_HOSTS_RESULT_SCHEMA_VERSION,
    ANSIBLE_OPERATION_FINALIZATION_REPORT_SCHEMA_VERSION,
    ANSIBLE_OPERATION_FINALIZATION_SCHEMA_VERSION,
    FinalizationCompanionState,
    OperationFinalizationStore,
    finalize_prepared_check_jump_hosts,
    operation_finalization_id_from_filename,
    operation_finalization_path,
)
from scylla_vms.cli import parse_operation_request
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import (
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
)
from scylla_vms.locking import ClusterLock, ClusterReadLock
from scylla_vms.persistence import serialize_json
from scylla_vms.process import ProcessResult, ProcessRunner
from scylla_vms.show_state import load_local_show_state

_OTHER_DIGEST = "sha256:" + "b" * 64


def _complete(
    tmp_path: Path,
    *,
    request_arguments: tuple[str, ...] = (),
    connectivity_result: ProcessResult | None = None,
) -> PreparedCoordinator:
    prepared = _prepare(tmp_path, request_arguments=request_arguments)
    if connectivity_result is None:
        runner = FakeCoordinatorRunner(_successful_results(prepared))
    else:
        runner = FakeCoordinatorRunner(
            [*_results(prepared), *_results(prepared, connectivity_result)]
        )
    _orchestrate(prepared, runner)
    return prepared


def _finalize(prepared: PreparedCoordinator):
    with ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock:
        return finalize_prepared_check_jump_hosts(
            prepared.paths.state_root,
            prepared.metadata.record.cluster_name,
            _OPERATION_ID,
            lock,
        )


def _read_journal(prepared: PreparedCoordinator):
    return OperationJournalStore(prepared.paths, _OPERATION_ID).read(
        expected_cluster_uuid=prepared.metadata.record.cluster_uuid,
        expected_cluster_name=prepared.metadata.record.cluster_name,
    )


def _read_finalization(prepared: PreparedCoordinator):
    with ClusterReadLock(prepared.paths, 0) as lock:
        return OperationFinalizationStore(
            prepared.paths,
            _OPERATION_ID,
        ).read_locked(
            lock,
            expected_cluster_uuid=prepared.metadata.record.cluster_uuid,
            expected_cluster_name=prepared.metadata.record.cluster_name,
            expected_operation="check-jump-hosts",
        )


def _write_document(path: Path, document: dict[str, object]) -> None:
    path.write_bytes(serialize_json(document))
    path.chmod(0o600)


def test_successful_semantic_finalization_is_address_free_and_completes_journal(
    tmp_path: Path,
) -> None:
    prepared = _complete(
        tmp_path,
        request_arguments=(
            "--destination",
            "scylla",
            "--depth",
            "route",
            "--destination-check",
            "scylla=9042",
        ),
        connectivity_result=ProcessResult(
            0,
            _tcp_recap("scylla-ad-1-1", "scylla", 9042),
            "",
        ),
    )
    bound_generation = prepared.binding.record.journal_generation

    report = _finalize(prepared)
    stored = _read_finalization(prepared)
    journal = _read_journal(prepared)

    assert report.schema_version == ANSIBLE_OPERATION_FINALIZATION_REPORT_SCHEMA_VERSION
    assert report.companion_state is FinalizationCompanionState.CREATED
    assert (
        report.result.schema_version == ANSIBLE_CHECK_JUMP_HOSTS_RESULT_SCHEMA_VERSION
    )
    assert report.result.exit_code == 0
    assert report.result.connectivity.value == "success"
    assert report.result.destination_tcp.value == "success"
    assert report.result.selected_stable_ids == ("jump-host-1",)
    assert report.result.to_object()["jumps"] == [
        {
            "connectivity": "reachable",
            "logical_id": "jump-host-1",
            "trust": "verified",
        }
    ]
    assert tuple(item.to_object() for item in report.result.destination_probes) == (
        {
            "jump_host_id": "jump-host-1",
            "port": 9042,
            "protocol": "tcp",
            "role": "scylla",
            "status": "passed",
            "target_logical_id": "scylla-ad-1-1",
        },
    )
    assert stored.record.schema_version == ANSIBLE_OPERATION_FINALIZATION_SCHEMA_VERSION
    assert stored.record.result == report.result
    assert journal.record.status is JournalStatus.SUCCEEDED
    assert journal.record.phase is OperationPhase.JOURNAL
    assert journal.record.generation == bound_generation + 2
    assert tuple(item.phase for item in journal.record.evidence) == (
        OperationPhase.PLAN,
        OperationPhase.VERIFY,
    )
    assert journal.record.evidence[-1].digest == stored.digest
    assert journal.record.evidence[-1].summary_code == "check-jump-hosts-verified"
    assert (
        OperationFinalizationStore(prepared.paths, _OPERATION_ID).path.stat().st_mode
        & 0o777
        == 0o600
    )

    encoded = json.dumps(report.to_object())
    persisted = OperationFinalizationStore(
        prepared.paths, _OPERATION_ID
    ).path.read_text(encoding="utf-8")
    for forbidden in (
        "10.0.0.",
        "203.0.113.",
        "PRIVATE KEY",
        "PLAY RECAP",
        "DSV_TCP",
        "command_digest",
        "environment",
        "known_hosts",
        "route_mode",
        "stdout",
        "stderr",
        "variables_digest",
        _SECRET,
        _PRIVATE_PATH,
    ):
        assert forbidden not in encoded
        assert forbidden not in persisted


def test_idempotent_reentry_performs_no_writes_or_process_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _complete(tmp_path)
    first = _finalize(prepared)
    finalization_path = OperationFinalizationStore(prepared.paths, _OPERATION_ID).path
    journal_path = prepared.paths.operations / f"{_OPERATION_ID}.json"
    before = (finalization_path.read_bytes(), journal_path.read_bytes())

    def refuse_process(self, spec):
        del self, spec
        raise AssertionError("finalization must not invoke a process")

    monkeypatch.setattr(ProcessRunner, "run", refuse_process)
    repeated = _finalize(prepared)

    assert first.result == repeated.result
    assert repeated.companion_state is FinalizationCompanionState.REUSED
    assert (finalization_path.read_bytes(), journal_path.read_bytes()) == before


def test_local_show_validates_finalization_companions_without_writing(
    tmp_path: Path,
) -> None:
    prepared = _complete(tmp_path)
    _finalize(prepared)
    request = parse_operation_request(
        [
            "--cluster-name",
            prepared.metadata.record.cluster_name,
            "--state-dir",
            str(prepared.paths.state_root),
            "show",
        ],
        environ={},
    )
    operation_files = {
        path.name: path.read_bytes() for path in prepared.paths.operations.iterdir()
    }

    with ClusterReadLock(prepared.paths, 0) as lock:
        state = load_local_show_state(request, lock)

    assert state.latest_operation is not None
    assert state.latest_operation.record.status is JournalStatus.SUCCEEDED
    assert {
        path.name: path.read_bytes() for path in prepared.paths.operations.iterdir()
    } == operation_files


@pytest.mark.parametrize(
    ("exit_code", "recap", "expected_state"),
    [
        (2, _recap(failed=1), ExecutionAttemptState.FAILED),
        (4, _recap(unreachable=1), ExecutionAttemptState.UNREACHABLE),
    ],
)
def test_failed_or_unreachable_execution_is_uncertain_and_never_finalized(
    tmp_path: Path,
    exit_code: int,
    recap: str,
    expected_state: ExecutionAttemptState,
) -> None:
    prepared = _complete(
        tmp_path,
        connectivity_result=ProcessResult(exit_code, recap, ""),
    )
    with ClusterReadLock(prepared.paths, 0) as read_lock:
        execution = OperationExecutionStore(prepared.paths, _OPERATION_ID).read_locked(
            read_lock,
            expected_cluster_uuid=prepared.metadata.record.cluster_uuid,
            expected_cluster_name=prepared.metadata.record.cluster_name,
            expected_operation="check-jump-hosts",
        )
    assert execution.record.state is expected_state

    with pytest.raises(StateConflictError, match=r"incomplete|recovery"):
        _finalize(prepared)

    assert not OperationFinalizationStore(prepared.paths, _OPERATION_ID).path.exists()
    journal = _read_journal(prepared)
    assert journal.record.status is JournalStatus.IN_PROGRESS
    assert journal.record.phase is OperationPhase.PLAN


def test_bounded_failed_destination_fact_remains_failed_execution_uncertainty(
    tmp_path: Path,
) -> None:
    prepared = _complete(
        tmp_path,
        request_arguments=(
            "--destination",
            "scylla",
            "--depth",
            "route",
            "--destination-check",
            "scylla=9042",
        ),
        connectivity_result=ProcessResult(
            0,
            _tcp_recap(
                "scylla-ad-1-1",
                "scylla",
                9042,
                status="failed",
            ),
            "",
        ),
    )

    with pytest.raises(StateConflictError, match=r"incomplete|recovery"):
        _finalize(prepared)

    assert not OperationFinalizationStore(prepared.paths, _OPERATION_ID).path.exists()
    assert _read_journal(prepared).record.phase is OperationPhase.PLAN


@pytest.mark.parametrize("mutation", ["missing", "stale", "extra", "reordered"])
def test_missing_stale_extra_or_reordered_evidence_fails_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    prepared = _complete(tmp_path)
    path = OperationEvidenceStore(prepared.paths, _OPERATION_ID).path
    if mutation == "missing":
        path.unlink()
    else:
        document = json.loads(path.read_text(encoding="utf-8"))
        if mutation == "stale":
            document["inventory_digest"] = _OTHER_DIGEST
        elif mutation == "extra":
            document["generation"] = 3
            document["entries"].append(document["entries"][-1])
        else:
            document["entries"].reverse()
        _write_document(path, document)

    with pytest.raises((StateConflictError, StatePersistenceError, UnsafePathError)):
        _finalize(prepared)

    assert not OperationFinalizationStore(prepared.paths, _OPERATION_ID).path.exists()
    assert _read_journal(prepared).record.phase is OperationPhase.PLAN


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("operation", "show"),
        ("effective_classification", "mutating"),
    ],
)
def test_wrong_kind_or_class_is_refused_before_writes(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    prepared = _complete(tmp_path)
    path = OperationPlanBindingStore(prepared.paths, _OPERATION_ID).path
    document = json.loads(path.read_text(encoding="utf-8"))
    document[field] = value
    _write_document(path, document)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _finalize(prepared)

    assert not OperationFinalizationStore(prepared.paths, _OPERATION_ID).path.exists()


def test_current_catalog_provenance_drift_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _complete(tmp_path)
    monkeypatch.setattr(
        finalization_module, "ansible_operation_catalog_digest", lambda: _OTHER_DIGEST
    )

    with pytest.raises(StateConflictError, match="source or catalog drifted"):
        _finalize(prepared)

    assert not OperationFinalizationStore(prepared.paths, _OPERATION_ID).path.exists()


@pytest.mark.parametrize(
    "state_file",
    ["observation", "inventory", "trust"],
)
def test_current_persisted_provenance_drift_is_refused(
    tmp_path: Path,
    state_file: str,
) -> None:
    prepared = _complete(tmp_path)
    path = {
        "observation": prepared.paths.terraform_observed,
        "inventory": prepared.paths.ansible_inventory,
        "trust": prepared.paths.ansible_trust,
    }[state_file]
    document = json.loads(path.read_text(encoding="utf-8"))
    if state_file == "inventory":
        document["all"]["vars"]["deploy_scylla_vms_record"]["generation"] += 1
    else:
        document["generation"] += 1
    _write_document(path, document)

    with pytest.raises(StateConflictError, match=r"evidence drifted|trust is stale"):
        _finalize(prepared)

    assert not OperationFinalizationStore(prepared.paths, _OPERATION_ID).path.exists()


def test_finalization_write_failure_leaves_bound_plan_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _complete(tmp_path)
    journal_path = prepared.paths.operations / f"{_OPERATION_ID}.json"
    before = journal_path.read_bytes()

    def fail_write(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError("injected finalization write failure")

    monkeypatch.setattr(OperationFinalizationStore, "write_locked", fail_write)
    with pytest.raises(StatePersistenceError, match="injected finalization"):
        _finalize(prepared)

    assert journal_path.read_bytes() == before
    assert not OperationFinalizationStore(prepared.paths, _OPERATION_ID).path.exists()


def test_journal_append_failure_after_finalization_recovers_exactly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _complete(tmp_path)
    journal_path = prepared.paths.operations / f"{_OPERATION_ID}.json"
    before = journal_path.read_bytes()

    def fail_write(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError("injected journal append failure")

    monkeypatch.setattr(OperationJournalStore, "write", fail_write)
    with pytest.raises(StatePersistenceError, match="journal append"):
        _finalize(prepared)

    finalization_path = OperationFinalizationStore(prepared.paths, _OPERATION_ID).path
    finalization_before = finalization_path.read_bytes()
    assert journal_path.read_bytes() == before

    monkeypatch.undo()
    recovered = _finalize(prepared)
    assert recovered.companion_state is FinalizationCompanionState.REUSED
    assert finalization_path.read_bytes() == finalization_before
    assert _read_journal(prepared).record.status is JournalStatus.SUCCEEDED


def test_terminal_journal_failure_recovers_from_exact_verify_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _complete(tmp_path)
    original = OperationJournalStore.write

    def fail_terminal(self, record, **kwargs):
        if record.status is JournalStatus.SUCCEEDED:
            raise StatePersistenceError("injected terminal journal failure")
        return original(self, record, **kwargs)

    monkeypatch.setattr(OperationJournalStore, "write", fail_terminal)
    with pytest.raises(StatePersistenceError, match="terminal journal"):
        _finalize(prepared)

    partial = _read_journal(prepared)
    assert partial.record.status is JournalStatus.IN_PROGRESS
    assert partial.record.phase is OperationPhase.VERIFY
    assert OperationFinalizationStore(prepared.paths, _OPERATION_ID).path.exists()

    monkeypatch.undo()
    recovered = _finalize(prepared)
    assert recovered.companion_state is FinalizationCompanionState.REUSED
    assert _read_journal(prepared).record.status is JournalStatus.SUCCEEDED


@pytest.mark.parametrize("mutation", ["conflicting", "duplicate"])
def test_conflicting_or_duplicate_journal_events_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    prepared = _complete(tmp_path)

    def fail_write(self, record, **kwargs):
        del self, record, kwargs
        raise StatePersistenceError("pause after finalization")

    monkeypatch.setattr(OperationJournalStore, "write", fail_write)
    with pytest.raises(StatePersistenceError, match="pause after finalization"):
        _finalize(prepared)
    monkeypatch.undo()

    path = prepared.paths.operations / f"{_OPERATION_ID}.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["generation"] += 1
    document["phase"] = OperationPhase.VERIFY.value
    document["updated_at"] = "2026-09-18T23:59:59Z"
    document["evidence"].append(
        {
            "digest": _OTHER_DIGEST,
            "phase": OperationPhase.VERIFY.value,
            "result": "completed",
            "summary_code": "check-jump-hosts-verified",
        }
    )
    if mutation == "duplicate":
        document["generation"] += 1
        document["evidence"].append(document["evidence"][-1])
    _write_document(path, document)

    with pytest.raises((StateConflictError, StatePersistenceError)):
        _finalize(prepared)

    assert json.loads(path.read_text(encoding="utf-8")) == document


def test_api_lock_path_permissions_and_symlink_guards(
    tmp_path: Path,
) -> None:
    prepared = _complete(tmp_path / "locks")
    expected_path = prepared.paths.operations / (
        f"{_OPERATION_ID}.ansible-operation-finalization.json"
    )
    assert operation_finalization_path(prepared.paths, _OPERATION_ID) == expected_path
    assert operation_finalization_id_from_filename(expected_path.name) == _OPERATION_ID
    assert (
        operation_finalization_id_from_filename(
            f"{str(_OPERATION_ID).upper()}.ansible-operation-finalization.json"
        )
        is None
    )
    assert operation_finalization_id_from_filename("../other.json") is None
    assert tuple(inspect.signature(finalize_prepared_check_jump_hosts).parameters) == (
        "state_root",
        "cluster_name",
        "operation_id",
        "lock",
    )
    unlocked = ClusterLock(prepared.paths, "check-jump-hosts", 0)
    with pytest.raises(StateLockError):
        finalize_prepared_check_jump_hosts(
            prepared.paths.state_root,
            prepared.metadata.record.cluster_name,
            _OPERATION_ID,
            unlocked,
        )
    with (
        ClusterReadLock(prepared.paths, 0) as read_lock,
        pytest.raises(StateLockError, match="requires an acquired cluster lock"),
    ):
        finalize_prepared_check_jump_hosts(
            prepared.paths.state_root,
            prepared.metadata.record.cluster_name,
            _OPERATION_ID,
            read_lock,
        )
    with (
        ClusterLock(prepared.paths, "show", 0) as wrong_lock,
        pytest.raises(StateLockError, match="matching operation"),
    ):
        finalize_prepared_check_jump_hosts(
            prepared.paths.state_root,
            prepared.metadata.record.cluster_name,
            _OPERATION_ID,
            wrong_lock,
        )
    with (
        ClusterLock(prepared.paths, "check-jump-hosts", 0) as lock,
        pytest.raises(UnsafePathError, match="canonical"),
    ):
        finalize_prepared_check_jump_hosts(
            prepared.paths.state_root / ".." / "state",
            prepared.metadata.record.cluster_name,
            _OPERATION_ID,
            lock,
        )
    with pytest.raises(UnsafePathError, match="not canonical"):
        OperationFinalizationStore(
            replace(prepared.paths, operations=prepared.paths.logs),
            _OPERATION_ID,
        )

    _finalize(prepared)
    finalization_path = OperationFinalizationStore(prepared.paths, _OPERATION_ID).path
    finalization_path.chmod(0o644)
    with pytest.raises(UnsafePathError, match="0600"):
        _finalize(prepared)

    symlinked = _complete(tmp_path / "symlink")
    symlink_path = OperationFinalizationStore(symlinked.paths, _OPERATION_ID).path
    target = symlinked.paths.operations / "outside-finalization.json"
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    symlink_path.symlink_to(target)
    with pytest.raises(UnsafePathError, match="symbolic link"):
        _finalize(symlinked)
