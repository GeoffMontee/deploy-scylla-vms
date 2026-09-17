"""Internal lock-bound ownership of the initial common operation journal."""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from scylla_vms.ansible.operation_authorization import (
    OPERATION_AUTHORIZATION_FILENAME_SUFFIX,
)
from scylla_vms.ansible.operation_binding import (
    OPERATION_BINDING_FILENAME_SUFFIX,
    normalized_operation_request_digest,
)
from scylla_vms.ansible.operation_context import (
    OPERATION_CONTEXT_FILENAME_SUFFIX,
    OPERATION_CONTEXT_UNMODELED,
    validate_check_jump_hosts_operation_request,
)
from scylla_vms.ansible.operation_evidence import (
    OPERATION_EVIDENCE_FILENAME_SUFFIX,
)
from scylla_vms.ansible.operation_execution import (
    OPERATION_EXECUTION_FILENAME_SUFFIX,
)
from scylla_vms.ansible.operation_finalization import (
    OPERATION_FINALIZATION_FILENAME_SUFFIX,
)
from scylla_vms.errors import (
    ConfigurationError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.journal import (
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    OperationRecord,
    StoredOperationRecord,
    is_initial_plan_record,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.models import OperationRequest
from scylla_vms.operations import (
    OperationClassification,
    OperationDefinition,
    get_operation,
)
from scylla_vms.persistence import (
    ClusterMetadataStore,
    StoredClusterMetadata,
    digest_bytes,
    serialize_json,
    validate_digest,
)
from scylla_vms.state import (
    StatePaths,
    refuse_unexpected_terraform_state,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)

ANSIBLE_OPERATION_INITIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-operation-initiation-report/v1"
)

_OPERATION = "check-jump-hosts"
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ACTIVE_STATUSES = frozenset(
    {
        JournalStatus.PENDING,
        JournalStatus.IN_PROGRESS,
        JournalStatus.INTERRUPTED,
    }
)
_COMPANION_SUFFIXES = (
    ".ansible-deploy-context.json",
    ".ansible-deploy-plan.json",
    ".ansible-deploy-prerequisite-execution.json",
    ".ansible-deploy-prerequisite-evidence.json",
    ".ansible-deploy-effective-plan.json",
    ".ansible-deploy-pre-mutation-host-evidence-execution.json",
    ".ansible-deploy-pre-mutation-host-evidence.json",
    ".ansible-deploy-host-evidence-reconciliation.json",
    ".ansible-deploy-base-os-authorization.json",
    ".ansible-deploy-base-os-execution.json",
    ".ansible-deploy-base-os-evidence.json",
    ".ansible-deploy-base-os-reconciliation.json",
    ".ansible-deploy-reboot-plan.json",
    ".ansible-deploy-reboot-authorization.json",
    OPERATION_AUTHORIZATION_FILENAME_SUFFIX,
    OPERATION_BINDING_FILENAME_SUFFIX,
    OPERATION_CONTEXT_FILENAME_SUFFIX,
    OPERATION_EVIDENCE_FILENAME_SUFFIX,
    OPERATION_EXECUTION_FILENAME_SUFFIX,
    OPERATION_FINALIZATION_FILENAME_SUFFIX,
)
_WRONG_KIND = "operation-kind-conflict"
_WRONG_CLASS = "operation-classification-conflict"
_ACTIVE_CONFLICT = "active-operation-conflict"


class OperationInitiationState(StrEnum):
    """Bounded outcome of attempting to own the initial journal."""

    CREATED = "created"
    REUSED = "reused"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class OperationInitiationReport:
    """Strict redacted projection of initial common-journal ownership."""

    operation_id: uuid.UUID
    operation: str
    operation_classification: OperationClassification
    state: OperationInitiationState
    blockers: tuple[str, ...]
    selected_stable_ids: tuple[str, ...]
    target_count: int
    request_digest: str | None
    journal_digest: str | None
    journal_generation: int | None
    journal_status: JournalStatus | None
    journal_phase: OperationPhase | None
    schema_version: str = ANSIBLE_OPERATION_INITIATION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_OPERATION_INITIATION_REPORT_SCHEMA_VERSION
            or not isinstance(self.operation_id, uuid.UUID)
            or not isinstance(self.operation_classification, OperationClassification)
            or not isinstance(self.state, OperationInitiationState)
        ):
            raise StatePersistenceError(
                "operation initiation report identity is invalid"
            )
        try:
            operation = get_operation(self.operation)
        except KeyError as error:
            raise StatePersistenceError(
                "operation initiation report kind is invalid"
            ) from error
        if operation.classification is not self.operation_classification:
            raise StatePersistenceError(
                "operation initiation report classification conflicts"
            )
        if self.blockers != tuple(sorted(set(self.blockers))) or not all(
            _BLOCKER.fullmatch(value) for value in self.blockers
        ):
            raise StatePersistenceError("operation initiation blockers are invalid")
        if (
            self.selected_stable_ids != tuple(sorted(set(self.selected_stable_ids)))
            or not all(_is_safe_stable_id(value) for value in self.selected_stable_ids)
            or isinstance(self.target_count, bool)
            or self.target_count != len(self.selected_stable_ids)
        ):
            raise StatePersistenceError("operation initiation targets are invalid")
        if self.request_digest is not None:
            validate_digest(self.request_digest, "operation initiation request digest")
        if self.journal_digest is not None:
            validate_digest(self.journal_digest, "operation initiation journal digest")
        if self.journal_generation is not None and (
            isinstance(self.journal_generation, bool)
            or not isinstance(self.journal_generation, int)
            or self.journal_generation < 1
        ):
            raise StatePersistenceError(
                "operation initiation journal generation is invalid"
            )
        if (
            self.journal_status is not None
            and not isinstance(self.journal_status, JournalStatus)
        ) or (
            self.journal_phase is not None
            and not isinstance(self.journal_phase, OperationPhase)
        ):
            raise StatePersistenceError("operation initiation journal state is invalid")
        journal_values = (
            self.journal_digest,
            self.journal_generation,
            self.journal_status,
            self.journal_phase,
        )
        if any(value is None for value in journal_values) != all(
            value is None for value in journal_values
        ):
            raise StatePersistenceError(
                "operation initiation journal provenance is incomplete"
            )
        if self.state in {
            OperationInitiationState.CREATED,
            OperationInitiationState.REUSED,
        }:
            if (
                self.operation != _OPERATION
                or self.operation_classification
                is not OperationClassification.READ_ONLY
                or self.blockers
                or self.request_digest is None
                or self.journal_generation != 1
                or self.journal_status is not JournalStatus.IN_PROGRESS
                or self.journal_phase is not OperationPhase.PLAN
            ):
                raise StatePersistenceError(
                    "successful operation initiation report conflicts"
                )
        elif not self.blockers or any(value is not None for value in journal_values):
            raise StatePersistenceError("blocked operation initiation report conflicts")

    def to_object(self) -> dict[str, object]:
        return {
            "blockers": list(self.blockers),
            "journal": {
                "digest": self.journal_digest,
                "generation": self.journal_generation,
                "phase": (
                    None if self.journal_phase is None else self.journal_phase.value
                ),
                "status": (
                    None if self.journal_status is None else self.journal_status.value
                ),
            },
            "operation": {
                "classification": self.operation_classification.value,
                "id": str(self.operation_id),
                "kind": self.operation,
                "selected_stable_ids": list(self.selected_stable_ids),
                "target_count": self.target_count,
            },
            "request_digest": self.request_digest,
            "schema_version": self.schema_version,
            "state": self.state.value,
        }


@dataclass(frozen=True, slots=True)
class _OperationHistory:
    journals: tuple[StoredOperationRecord, ...]
    companion_ids: frozenset[uuid.UUID]


def initiate_check_jump_hosts_operation(
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    operation_kind: str,
    request: OperationRequest,
    lock: ClusterLock,
    *,
    clock: Callable[[], datetime] | None = None,
) -> OperationInitiationReport:
    """Create or exactly reuse only the modeled operation's initial PLAN journal."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError("operation initiation ID must be a UUID")
    if not isinstance(request, OperationRequest):
        raise StateConflictError("operation initiation request is invalid")
    operation = _registered_operation(operation_kind)
    if operation.name != _OPERATION or request.operation.name != _OPERATION:
        return _blocked_report(
            operation_id,
            operation,
            blockers=(OPERATION_CONTEXT_UNMODELED, _WRONG_KIND),
        )
    if (
        operation.classification is not OperationClassification.READ_ONLY
        or request.operation != operation
        or not operation.implemented
    ):
        return _blocked_report(
            operation_id,
            operation,
            blockers=(_WRONG_CLASS,),
        )

    paths = StatePaths.derive(state_root, cluster_name)
    if not isinstance(lock, ClusterLock):
        raise StateLockError("operation initiation requires an acquired cluster lock")
    lock.assert_held_for_operation(paths, _OPERATION)
    if (
        request.paths != paths
        or request.state_root != paths.state_root
        or request.cluster_name != paths.cluster_root.name
        or request.provider.name != "oci"
    ):
        raise StateConflictError("operation initiation request identity conflicts")
    values = validate_check_jump_hosts_operation_request(request)
    selected_stable_ids = tuple(sorted(values.jump_hosts))
    request_digest = normalized_operation_request_digest(request)

    _validate_initialized_layout(paths)
    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name=paths.cluster_root.name,
        expected_provider=request.provider.name,
    )
    _refuse_cross_cluster_uuid_reuse(paths, operation_id)
    history = _load_operation_history(paths, metadata)
    if operation_id in history.companion_ids:
        raise StateConflictError(
            "operation initiation refuses pre-existing companion history"
        )
    existing = tuple(
        stored
        for stored in history.journals
        if stored.record.operation_id == operation_id
    )
    if len(existing) > 1:
        raise StateConflictError("operation initiation history is ambiguous")
    active_others = tuple(
        stored
        for stored in history.journals
        if stored.record.operation_id != operation_id
        and stored.record.status in _ACTIVE_STATUSES
    )
    if active_others:
        return _blocked_report(
            operation_id,
            operation,
            blockers=(_ACTIVE_CONFLICT,),
            selected_stable_ids=selected_stable_ids,
            request_digest=request_digest,
        )
    if existing:
        stored = existing[0]
        if (
            stored.record.operation != _OPERATION
            or stored.record.cluster_uuid != metadata.record.cluster_uuid
            or stored.record.cluster_name != metadata.record.cluster_name
            or stored.record.request_digest != request_digest
            or not is_initial_plan_record(stored.record)
        ):
            raise StateConflictError(
                "operation initiation UUID or request history conflicts"
            )
        return _journal_report(
            operation,
            stored,
            OperationInitiationState.REUSED,
            selected_stable_ids,
        )

    record = OperationRecord.create_initial_plan(
        operation_id=operation_id,
        operation=_OPERATION,
        cluster_uuid=metadata.record.cluster_uuid,
        cluster_name=metadata.record.cluster_name,
        request_digest=request_digest,
        clock=clock or _utc_now,
    )
    predicted_digest = digest_bytes(serialize_json(record.to_object()))
    report = OperationInitiationReport(
        operation_id=operation_id,
        operation=operation.name,
        operation_classification=operation.classification,
        state=OperationInitiationState.CREATED,
        blockers=(),
        selected_stable_ids=selected_stable_ids,
        target_count=len(selected_stable_ids),
        request_digest=request_digest,
        journal_digest=predicted_digest,
        journal_generation=record.generation,
        journal_status=record.status,
        journal_phase=record.phase,
    )
    stored = OperationJournalStore(paths, operation_id).write(
        record,
        expected_generation=0,
        expected_digest=None,
    )
    if stored.digest != predicted_digest:
        raise StatePersistenceError("operation initiation journal digest changed")
    return report


def _registered_operation(operation_kind: str) -> OperationDefinition:
    if not isinstance(operation_kind, str):
        raise StateConflictError("operation initiation kind is invalid")
    try:
        return get_operation(operation_kind)
    except KeyError as error:
        raise StateConflictError(
            "operation initiation kind is not registered"
        ) from error


def _validate_initialized_layout(paths: StatePaths) -> None:
    expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
    if expected != paths:
        raise StateConflictError("operation initiation paths are not canonical")
    for directory in paths.directory_paths:
        validate_state_directory(directory)
    validate_state_file(paths.cluster_metadata)
    refuse_unexpected_terraform_state(paths, (paths.cluster_root,))


def _load_operation_history(
    paths: StatePaths,
    metadata: StoredClusterMetadata,
) -> _OperationHistory:
    journals: list[StoredOperationRecord] = []
    companions: set[uuid.UUID] = set()
    try:
        entries = tuple(sorted(paths.operations.iterdir(), key=lambda item: item.name))
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list operation initiation history"
        ) from error
    for entry in entries:
        validate_state_file(entry)
        identifier, companion = _operation_artifact_identity(entry.name)
        if companion:
            companions.add(identifier)
            continue
        journals.append(
            OperationJournalStore(paths, identifier).read(
                expected_cluster_uuid=metadata.record.cluster_uuid,
                expected_cluster_name=metadata.record.cluster_name,
            )
        )
    return _OperationHistory(tuple(journals), frozenset(companions))


def _refuse_cross_cluster_uuid_reuse(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> None:
    try:
        clusters = tuple(sorted(paths.clusters.iterdir(), key=lambda item: item.name))
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely inspect cluster identities"
        ) from error
    for cluster in clusters:
        validate_state_directory(cluster)
        try:
            other_name = validate_cluster_name(cluster.name)
        except ConfigurationError as error:
            raise StatePersistenceError("cluster state name is invalid") from error
        if other_name == paths.cluster_root.name:
            continue
        other_paths = StatePaths.derive(paths.state_root, other_name)
        validate_state_directory(other_paths.operations)
        try:
            entries = tuple(other_paths.operations.iterdir())
        except OSError as error:
            raise StatePersistenceError(
                "cannot safely inspect cross-cluster operation history"
            ) from error
        for entry in entries:
            validate_state_file(entry)
            identifier, _ = _operation_artifact_identity(entry.name)
            if identifier == operation_id:
                raise StateConflictError(
                    "operation initiation UUID is already used by another cluster"
                )


def _operation_artifact_identity(name: str) -> tuple[uuid.UUID, bool]:
    for suffix in _COMPANION_SUFFIXES:
        if name.endswith(suffix):
            return _canonical_uuid(name[: -len(suffix)]), True
    if name.endswith(".json"):
        return _canonical_uuid(name[:-5]), False
    raise StatePersistenceError("operation initiation history filename is invalid")


def _canonical_uuid(value: str) -> uuid.UUID:
    try:
        identifier = uuid.UUID(value)
    except ValueError as error:
        raise StatePersistenceError(
            "operation initiation history filename is invalid"
        ) from error
    if str(identifier) != value:
        raise StatePersistenceError(
            "operation initiation history UUID is not canonical"
        )
    return identifier


def _journal_report(
    operation: OperationDefinition,
    stored: StoredOperationRecord,
    state: OperationInitiationState,
    selected_stable_ids: tuple[str, ...],
) -> OperationInitiationReport:
    return OperationInitiationReport(
        operation_id=stored.record.operation_id,
        operation=operation.name,
        operation_classification=operation.classification,
        state=state,
        blockers=(),
        selected_stable_ids=selected_stable_ids,
        target_count=len(selected_stable_ids),
        request_digest=stored.record.request_digest,
        journal_digest=stored.digest,
        journal_generation=stored.record.generation,
        journal_status=stored.record.status,
        journal_phase=stored.record.phase,
    )


def _blocked_report(
    operation_id: uuid.UUID,
    operation: OperationDefinition,
    *,
    blockers: tuple[str, ...],
    selected_stable_ids: tuple[str, ...] = (),
    request_digest: str | None = None,
) -> OperationInitiationReport:
    return OperationInitiationReport(
        operation_id=operation_id,
        operation=operation.name,
        operation_classification=operation.classification,
        state=OperationInitiationState.BLOCKED,
        blockers=tuple(sorted(set(blockers))),
        selected_stable_ids=selected_stable_ids,
        target_count=len(selected_stable_ids),
        request_digest=request_digest,
        journal_digest=None,
        journal_generation=None,
        journal_status=None,
        journal_phase=None,
    )


def _is_safe_stable_id(value: object) -> bool:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or _LOGICAL_ID.fullmatch(value) is None
    ):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return True
    return False


def _utc_now() -> datetime:
    return datetime.now(UTC)
