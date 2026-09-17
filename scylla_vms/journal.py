"""Strict append-only operation checkpoint records and transitions."""

import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.errors import ConfigurationError, StatePersistenceError
from scylla_vms.operations import get_operation
from scylla_vms.persistence import (
    AtomicJsonFile,
    digest_bytes,
    format_timestamp,
    parse_timestamp,
    parse_uuid,
    require_exact_keys,
    require_string,
    serialize_json,
    validate_digest,
)
from scylla_vms.state import StatePaths, validate_cluster_name, validate_state_directory

JOURNAL_SCHEMA_VERSION = "deploy-scylla-vms.operation/v1"
_SUMMARY_CODE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")


class JournalStatus(StrEnum):
    """Durable operation status; terminal success still requires live revalidation."""

    PENDING = "pending"
    IN_PROGRESS = "in-progress"
    INTERRUPTED = "interrupted"
    FAILED = "failed"
    SUCCEEDED = "succeeded"


class OperationPhase(StrEnum):
    """Ordered common operation phases from the normative workflow."""

    PARSE_RESOLVE = "parse-resolve"
    LOCK = "lock"
    LOAD_METADATA = "load-metadata"
    RECONCILE = "reconcile"
    VALIDATE_PRECONDITIONS = "validate-preconditions"
    PLAN = "plan"
    CONFIRM = "confirm"
    EXECUTE = "execute"
    VERIFY = "verify"
    JOURNAL = "journal"
    UNLOCK = "unlock"


class EvidenceResult(StrEnum):
    """Bounded non-secret evidence result."""

    VALIDATED = "validated"
    COMPLETED = "completed"
    FAILED = "failed"
    UNKNOWN = "unknown"


_PHASE_INDEX = {phase: index for index, phase in enumerate(OperationPhase)}


@dataclass(frozen=True, slots=True)
class CheckpointEvidence:
    """One append-only digest and bounded summary code for a completed check."""

    phase: OperationPhase
    result: EvidenceResult
    digest: str
    summary_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.phase, OperationPhase):
            raise StatePersistenceError("checkpoint evidence phase is invalid")
        if not isinstance(self.result, EvidenceResult):
            raise StatePersistenceError("checkpoint evidence result is invalid")
        validate_digest(self.digest, "checkpoint evidence digest")
        if not _SUMMARY_CODE.fullmatch(self.summary_code):
            raise StatePersistenceError("checkpoint summary code is invalid")

    def to_object(self) -> dict[str, object]:
        return {
            "digest": self.digest,
            "phase": self.phase.value,
            "result": self.result.value,
            "summary_code": self.summary_code,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> "CheckpointEvidence":
        require_exact_keys(
            value, {"digest", "phase", "result", "summary_code"}, "checkpoint evidence"
        )
        try:
            phase = OperationPhase(require_string(value, "phase"))
            result = EvidenceResult(require_string(value, "result"))
        except ValueError as error:
            raise StatePersistenceError(
                "checkpoint evidence enum is invalid"
            ) from error
        return cls(
            phase=phase,
            result=result,
            digest=require_string(value, "digest"),
            summary_code=require_string(value, "summary_code"),
        )


@dataclass(frozen=True, slots=True)
class OperationRecord:
    """One complete generation of an operation journal/checkpoint."""

    generation: int
    operation_id: uuid.UUID
    operation: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    status: JournalStatus
    phase: OperationPhase
    created_at: str
    updated_at: str
    request_digest: str
    resume_revalidation_digest: str | None
    evidence: tuple[CheckpointEvidence, ...]
    schema_version: str = JOURNAL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != JOURNAL_SCHEMA_VERSION:
            raise StatePersistenceError("unsupported operation journal schema version")
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation < 1
        ):
            raise StatePersistenceError("operation generation must be positive")
        if not isinstance(self.operation_id, uuid.UUID) or not isinstance(
            self.cluster_uuid, uuid.UUID
        ):
            raise StatePersistenceError("operation identities must be UUIDs")
        if not isinstance(self.operation, str) or not isinstance(
            self.cluster_name, str
        ):
            raise StatePersistenceError("operation journal identity is invalid")
        try:
            get_operation(self.operation)
            validate_cluster_name(self.cluster_name)
        except (ConfigurationError, KeyError) as error:
            raise StatePersistenceError(
                "operation journal identity is invalid"
            ) from error
        if not isinstance(self.status, JournalStatus) or not isinstance(
            self.phase, OperationPhase
        ):
            raise StatePersistenceError("operation journal status or phase is invalid")
        if not isinstance(self.created_at, str) or not isinstance(self.updated_at, str):
            raise StatePersistenceError("operation journal timestamps must be strings")
        created = parse_timestamp(self.created_at)
        updated = parse_timestamp(self.updated_at)
        if updated < created:
            raise StatePersistenceError("operation journal timestamp regressed")
        validate_digest(self.request_digest, "operation request digest")
        if self.resume_revalidation_digest is not None:
            validate_digest(
                self.resume_revalidation_digest, "resume revalidation digest"
            )
        if not isinstance(self.evidence, tuple):
            raise StatePersistenceError("operation evidence must be immutable")
        if not all(isinstance(item, CheckpointEvidence) for item in self.evidence):
            raise StatePersistenceError("operation evidence entry is invalid")
        phases = tuple(item.phase for item in self.evidence)
        if len(set(phases)) != len(phases):
            raise StatePersistenceError("operation evidence phases must be unique")
        if tuple(sorted(phases, key=_PHASE_INDEX.__getitem__)) != phases:
            raise StatePersistenceError("operation evidence phases must be ordered")
        if any(
            _PHASE_INDEX[item.phase] > _PHASE_INDEX[self.phase]
            for item in self.evidence
        ):
            raise StatePersistenceError(
                "operation evidence is ahead of the journal phase"
            )
        if self.status is JournalStatus.SUCCEEDED and not any(
            item.phase is OperationPhase.VERIFY
            and item.result is EvidenceResult.COMPLETED
            for item in self.evidence
        ):
            raise StatePersistenceError(
                "successful operation requires completed verification evidence"
            )

    @classmethod
    def create(
        cls,
        *,
        operation_id: uuid.UUID,
        operation: str,
        cluster_uuid: uuid.UUID,
        cluster_name: str,
        request_digest: str,
        clock: Callable[[], datetime],
    ) -> "OperationRecord":
        """Create a deterministic pending generation without executing a phase."""

        timestamp = format_timestamp(clock())
        return cls(
            generation=1,
            operation_id=operation_id,
            operation=operation,
            cluster_uuid=cluster_uuid,
            cluster_name=cluster_name,
            status=JournalStatus.PENDING,
            phase=OperationPhase.PARSE_RESOLVE,
            created_at=timestamp,
            updated_at=timestamp,
            request_digest=request_digest,
            resume_revalidation_digest=None,
            evidence=(),
        )

    @classmethod
    def create_initial_plan(
        cls,
        *,
        operation_id: uuid.UUID,
        operation: str,
        cluster_uuid: uuid.UUID,
        cluster_name: str,
        request_digest: str,
        clock: Callable[[], datetime],
    ) -> "OperationRecord":
        """Create the sole journal shape permitted before plan resolution."""

        timestamp = format_timestamp(clock())
        return cls(
            generation=1,
            operation_id=operation_id,
            operation=operation,
            cluster_uuid=cluster_uuid,
            cluster_name=cluster_name,
            status=JournalStatus.IN_PROGRESS,
            phase=OperationPhase.PLAN,
            created_at=timestamp,
            updated_at=timestamp,
            request_digest=request_digest,
            resume_revalidation_digest=None,
            evidence=(),
        )

    def transition(
        self,
        *,
        status: JournalStatus,
        phase: OperationPhase,
        evidence: tuple[CheckpointEvidence, ...],
        clock: Callable[[], datetime],
        resume_revalidation_digest: str | None = None,
    ) -> "OperationRecord":
        """Build and validate the next append-only generation."""

        candidate = OperationRecord(
            generation=self.generation + 1,
            operation_id=self.operation_id,
            operation=self.operation,
            cluster_uuid=self.cluster_uuid,
            cluster_name=self.cluster_name,
            status=status,
            phase=phase,
            created_at=self.created_at,
            updated_at=format_timestamp(clock()),
            request_digest=self.request_digest,
            resume_revalidation_digest=resume_revalidation_digest,
            evidence=evidence,
        )
        validate_transition(self, candidate)
        return candidate

    def to_object(self) -> dict[str, object]:
        return {
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "created_at": self.created_at,
            "evidence": [item.to_object() for item in self.evidence],
            "generation": self.generation,
            "operation": self.operation,
            "operation_id": str(self.operation_id),
            "phase": self.phase.value,
            "request_digest": self.request_digest,
            "resume_revalidation_digest": self.resume_revalidation_digest,
            "schema_version": self.schema_version,
            "status": self.status.value,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> "OperationRecord":
        require_exact_keys(
            value,
            {
                "cluster_name",
                "cluster_uuid",
                "created_at",
                "evidence",
                "generation",
                "operation",
                "operation_id",
                "phase",
                "request_digest",
                "resume_revalidation_digest",
                "schema_version",
                "status",
                "updated_at",
            },
            "operation journal",
        )
        if require_string(value, "schema_version") != JOURNAL_SCHEMA_VERSION:
            raise StatePersistenceError("unsupported operation journal schema version")
        generation = value["generation"]
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise StatePersistenceError("operation generation must be an integer")
        evidence_value = value["evidence"]
        if not isinstance(evidence_value, list):
            raise StatePersistenceError("operation evidence must be an array")
        evidence = tuple(
            CheckpointEvidence.from_object(cast(dict[str, object], item))
            if isinstance(item, dict)
            else _invalid_evidence()
            for item in evidence_value
        )
        resume = value["resume_revalidation_digest"]
        if resume is not None and not isinstance(resume, str):
            raise StatePersistenceError(
                "resume revalidation digest must be null or string"
            )
        try:
            status = JournalStatus(require_string(value, "status"))
            phase = OperationPhase(require_string(value, "phase"))
        except ValueError as error:
            raise StatePersistenceError("operation journal enum is invalid") from error
        return cls(
            generation=generation,
            operation_id=parse_uuid(
                require_string(value, "operation_id"), "operation ID"
            ),
            operation=require_string(value, "operation"),
            cluster_uuid=parse_uuid(
                require_string(value, "cluster_uuid"), "cluster UUID"
            ),
            cluster_name=require_string(value, "cluster_name"),
            status=status,
            phase=phase,
            created_at=require_string(value, "created_at"),
            updated_at=require_string(value, "updated_at"),
            request_digest=require_string(value, "request_digest"),
            resume_revalidation_digest=resume,
            evidence=evidence,
        )


@dataclass(frozen=True, slots=True)
class StoredOperationRecord:
    record: OperationRecord
    digest: str


class OperationJournalStore:
    """Persist generations for one operation ID below the canonical directory."""

    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self._paths = paths
        self._operation_id = operation_id
        self._path = paths.operations / f"{operation_id}.json"
        if self._path.parent != paths.operations:
            raise StatePersistenceError("operation journal path is not canonical")
        self._file = AtomicJsonFile(
            self._path, replace=replace, token_factory=token_factory
        )

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredOperationRecord:
        value, digest = self._file.read()
        record = OperationRecord.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError("operation journal identity mismatch")
        return StoredOperationRecord(record, digest)

    def write(
        self,
        record: OperationRecord,
        *,
        expected_generation: int,
        expected_digest: str | None,
    ) -> StoredOperationRecord:
        validate_state_directory(self._paths.operations)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError("operation journal ID mismatch")
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial operation journal write requires generation one"
                )
        else:
            current_value, current_digest = self._file.read()
            current = OperationRecord.from_object(current_value)
            if expected_digest is None:
                raise StatePersistenceError(
                    "journal update requires the expected prior digest"
                )
            if (
                current_digest != expected_digest
                or current.generation != expected_generation
            ):
                raise StatePersistenceError("operation journal changed concurrently")
            validate_transition(current, record)
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredOperationRecord(record, digest)


def validate_transition(previous: OperationRecord, current: OperationRecord) -> None:
    """Enforce immutable identity, append-only evidence, and phase/status rules."""

    if current.generation != previous.generation + 1:
        raise StatePersistenceError("operation generation must increase by exactly one")
    if (
        current.operation_id != previous.operation_id
        or current.operation != previous.operation
        or current.cluster_uuid != previous.cluster_uuid
        or current.cluster_name != previous.cluster_name
        or current.created_at != previous.created_at
        or current.request_digest != previous.request_digest
    ):
        raise StatePersistenceError("operation journal identity fields are immutable")
    if parse_timestamp(current.updated_at) < parse_timestamp(previous.updated_at):
        raise StatePersistenceError("operation journal update time regressed")
    if current.evidence[: len(previous.evidence)] != previous.evidence:
        raise StatePersistenceError("operation checkpoint evidence is append-only")
    if _PHASE_INDEX[current.phase] < _PHASE_INDEX[previous.phase]:
        raise StatePersistenceError("operation phase must not regress")
    allowed = {
        JournalStatus.PENDING: {JournalStatus.IN_PROGRESS},
        JournalStatus.IN_PROGRESS: {
            JournalStatus.IN_PROGRESS,
            JournalStatus.INTERRUPTED,
            JournalStatus.FAILED,
            JournalStatus.SUCCEEDED,
        },
        JournalStatus.INTERRUPTED: {JournalStatus.IN_PROGRESS},
        JournalStatus.FAILED: set(),
        JournalStatus.SUCCEEDED: set(),
    }
    if current.status not in allowed[previous.status]:
        raise StatePersistenceError("operation status transition is invalid")
    if (
        previous.status is JournalStatus.IN_PROGRESS
        and current.status is JournalStatus.IN_PROGRESS
        and current.phase is previous.phase
        and not (
            is_initial_plan_record(previous)
            and len(current.evidence) == 1
            and current.evidence[0].phase is OperationPhase.PLAN
        )
    ):
        raise StatePersistenceError("in-progress transition must advance the phase")
    if previous.status is JournalStatus.INTERRUPTED:
        if current.resume_revalidation_digest is None:
            raise StatePersistenceError(
                "interrupted operation resume requires fresh revalidation evidence"
            )
    elif current.resume_revalidation_digest != previous.resume_revalidation_digest:
        raise StatePersistenceError(
            "resume revalidation digest may change only when resuming"
        )


def is_initial_plan_record(record: OperationRecord) -> bool:
    """Recognize the exact initiation-owned state before plan evidence exists."""

    return (
        record.generation == 1
        and record.status is JournalStatus.IN_PROGRESS
        and record.phase is OperationPhase.PLAN
        and record.resume_revalidation_digest is None
        and record.evidence == ()
    )


def _invalid_evidence() -> CheckpointEvidence:
    raise StatePersistenceError("operation evidence entry must be an object")


def digest_summary(value: Mapping[str, object]) -> str:
    """Digest a caller-sanitized summary without retaining its contents."""

    return digest_bytes(serialize_json(value))
