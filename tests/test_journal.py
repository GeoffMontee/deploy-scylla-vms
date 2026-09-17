import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scylla_vms.errors import StatePersistenceError
from scylla_vms.journal import (
    CheckpointEvidence,
    EvidenceResult,
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    OperationRecord,
    digest_summary,
    validate_transition,
)
from scylla_vms.persistence import digest_bytes
from scylla_vms.state import StatePaths, initialize_state_layout

_CLUSTER_UUID = uuid.UUID("11111111-1111-4111-8111-111111111111")
_OPERATION_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
_REQUEST_DIGEST = digest_bytes(b"request")
_VERIFY_DIGEST = digest_summary({"check": "postconditions", "result": "healthy"})


def _clock(minute: int) -> datetime:
    return datetime(2026, 9, 17, 12, minute, tzinfo=UTC)


def _record() -> OperationRecord:
    return OperationRecord.create(
        operation_id=_OPERATION_ID,
        operation="deploy",
        cluster_uuid=_CLUSTER_UUID,
        cluster_name="example",
        request_digest=_REQUEST_DIGEST,
        clock=lambda: _clock(0),
    )


def _store(tmp_path: Path) -> OperationJournalStore:
    paths = StatePaths.derive(tmp_path / "state", "example")
    initialize_state_layout(paths)
    return OperationJournalStore(
        paths, _OPERATION_ID, token_factory=lambda: "journaltemp"
    )


def test_journal_round_trip_and_verified_success_transition(tmp_path: Path) -> None:
    store = _store(tmp_path)
    pending = _record()
    first = store.write(pending, expected_generation=0, expected_digest=None)
    verification = CheckpointEvidence(
        OperationPhase.VERIFY,
        EvidenceResult.COMPLETED,
        _VERIFY_DIGEST,
        "postconditions-healthy",
    )
    in_progress = pending.transition(
        status=JournalStatus.IN_PROGRESS,
        phase=OperationPhase.VERIFY,
        evidence=(verification,),
        clock=lambda: _clock(1),
    )
    second = store.write(
        in_progress,
        expected_generation=first.record.generation,
        expected_digest=first.digest,
    )
    succeeded = in_progress.transition(
        status=JournalStatus.SUCCEEDED,
        phase=OperationPhase.JOURNAL,
        evidence=(verification,),
        clock=lambda: _clock(2),
    )
    final = store.write(
        succeeded,
        expected_generation=second.record.generation,
        expected_digest=second.digest,
    )

    assert (
        store.read(expected_cluster_uuid=_CLUSTER_UUID, expected_cluster_name="example")
        == final
    )
    with pytest.raises(StatePersistenceError, match="status transition"):
        succeeded.transition(
            status=JournalStatus.IN_PROGRESS,
            phase=OperationPhase.UNLOCK,
            evidence=(verification,),
            clock=lambda: _clock(3),
        )


def test_interrupted_resume_requires_fresh_revalidation_digest() -> None:
    pending = _record()
    running = pending.transition(
        status=JournalStatus.IN_PROGRESS,
        phase=OperationPhase.EXECUTE,
        evidence=(),
        clock=lambda: _clock(1),
    )
    interrupted = running.transition(
        status=JournalStatus.INTERRUPTED,
        phase=OperationPhase.EXECUTE,
        evidence=(),
        clock=lambda: _clock(2),
    )

    with pytest.raises(StatePersistenceError, match="fresh revalidation"):
        interrupted.transition(
            status=JournalStatus.IN_PROGRESS,
            phase=OperationPhase.EXECUTE,
            evidence=(),
            clock=lambda: _clock(3),
        )

    resumed = interrupted.transition(
        status=JournalStatus.IN_PROGRESS,
        phase=OperationPhase.EXECUTE,
        evidence=(),
        resume_revalidation_digest=digest_bytes(b"fresh reconciliation"),
        clock=lambda: _clock(3),
    )
    assert resumed.resume_revalidation_digest is not None


def test_journal_rejects_phase_regression_evidence_rewrite_and_unverified_success() -> (
    None
):
    pending = _record()
    running = pending.transition(
        status=JournalStatus.IN_PROGRESS,
        phase=OperationPhase.RECONCILE,
        evidence=(),
        clock=lambda: _clock(1),
    )
    regressed = OperationRecord(
        generation=3,
        operation_id=running.operation_id,
        operation=running.operation,
        cluster_uuid=running.cluster_uuid,
        cluster_name=running.cluster_name,
        status=JournalStatus.IN_PROGRESS,
        phase=OperationPhase.LOCK,
        created_at=running.created_at,
        updated_at="2026-09-17T12:02:00Z",
        request_digest=running.request_digest,
        resume_revalidation_digest=None,
        evidence=(),
    )
    with pytest.raises(StatePersistenceError, match="phase must not regress"):
        validate_transition(running, regressed)

    with pytest.raises(StatePersistenceError, match="verification evidence"):
        OperationRecord(
            generation=3,
            operation_id=running.operation_id,
            operation=running.operation,
            cluster_uuid=running.cluster_uuid,
            cluster_name=running.cluster_name,
            status=JournalStatus.SUCCEEDED,
            phase=OperationPhase.JOURNAL,
            created_at=running.created_at,
            updated_at="2026-09-17T12:02:00Z",
            request_digest=running.request_digest,
            resume_revalidation_digest=None,
            evidence=(),
        )

    evidence = CheckpointEvidence(
        OperationPhase.RECONCILE,
        EvidenceResult.VALIDATED,
        digest_bytes(b"first"),
        "identity-matched",
    )
    with_evidence = OperationRecord(
        generation=3,
        operation_id=running.operation_id,
        operation=running.operation,
        cluster_uuid=running.cluster_uuid,
        cluster_name=running.cluster_name,
        status=JournalStatus.INTERRUPTED,
        phase=OperationPhase.RECONCILE,
        created_at=running.created_at,
        updated_at="2026-09-17T12:02:00Z",
        request_digest=running.request_digest,
        resume_revalidation_digest=None,
        evidence=(evidence,),
    )
    validate_transition(running, with_evidence)
    rewritten = CheckpointEvidence(
        OperationPhase.RECONCILE,
        EvidenceResult.FAILED,
        digest_bytes(b"changed"),
        "identity-conflict",
    )
    candidate = OperationRecord(
        generation=4,
        operation_id=running.operation_id,
        operation=running.operation,
        cluster_uuid=running.cluster_uuid,
        cluster_name=running.cluster_name,
        status=JournalStatus.IN_PROGRESS,
        phase=OperationPhase.RECONCILE,
        created_at=running.created_at,
        updated_at="2026-09-17T12:03:00Z",
        request_digest=running.request_digest,
        resume_revalidation_digest=digest_bytes(b"revalidated"),
        evidence=(rewritten,),
    )
    with pytest.raises(StatePersistenceError, match="append-only"):
        validate_transition(with_evidence, candidate)


def test_journal_store_rejects_identity_and_generation_mismatch(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    first = store.write(_record(), expected_generation=0, expected_digest=None)

    with pytest.raises(StatePersistenceError, match="identity mismatch"):
        store.read(expected_cluster_uuid=uuid.uuid4(), expected_cluster_name="example")
    with pytest.raises(StatePersistenceError, match="changed concurrently"):
        store.write(
            _record().transition(
                status=JournalStatus.IN_PROGRESS,
                phase=OperationPhase.LOCK,
                evidence=(),
                clock=lambda: _clock(1),
            ),
            expected_generation=999,
            expected_digest=first.digest,
        )


def test_journal_schema_rejects_unknown_fields_and_secret_summary_text() -> None:
    value = _record().to_object()
    value["password"] = "must-not-persist"
    with pytest.raises(StatePersistenceError, match="fields do not match"):
        OperationRecord.from_object(value)

    with pytest.raises(StatePersistenceError, match="summary code"):
        CheckpointEvidence(
            OperationPhase.PLAN,
            EvidenceResult.COMPLETED,
            digest_bytes(b"plan"),
            "token=secret",
        )
