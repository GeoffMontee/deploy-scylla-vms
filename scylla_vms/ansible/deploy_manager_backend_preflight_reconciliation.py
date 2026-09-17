"""Immutable reconciliation of operation-bound Manager backend preflight."""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import Enum, StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.deploy_manager_backend_configuration_plan import (
    _load_planning_context as _load_backend_planning_context,
)
from scylla_vms.ansible.deploy_manager_backend_preflight_execution import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION,
    DeployManagerBackendPreflightArtifactState,
    DeployManagerBackendPreflightEvidence,
    DeployManagerBackendPreflightEvidenceStore,
    DeployManagerBackendPreflightExecutionState,
    DeployManagerBackendPreflightExecutionStore,
    StoredDeployManagerBackendPreflightEvidence,
    StoredDeployManagerBackendPreflightExecution,
    _load_execution_context,
    _require_canonical_paths,
    _validate_execution_prefix,
)
from scylla_vms.ansible.deploy_plan import _digest_object, _require_operation_id
from scylla_vms.ansible.manager_backend_preflight import (
    MANAGER_BACKEND_UNRESOLVED_BLOCKERS,
    ManagerBackendPreflightStatus,
)
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.journal import JOURNAL_SCHEMA_VERSION, JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
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
from scylla_vms.state import (
    StatePaths,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)

ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_GATE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-preflight-reconciliation-gate/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-preflight-reconciliation/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-preflight-"
    "reconciliation-report/v1"
)

DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-preflight-reconciliation.json"
)

_OPERATION = "deploy"
_NEXT_IMPLEMENTATION_CONTRACT = "manager-backend-local-installation-plan-contract"
_UNAVAILABLE = "unavailable"
_NOT_STARTED = "not-started"
_NOT_PERFORMED = "not-performed"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BLOCKER = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,127}\Z")

_GATE_BLOCKERS = (
    ("package-availability", "manager-backend-package-availability-unknown"),
    ("storage-suitability", "manager-backend-storage-suitability-unknown"),
    ("tuning-suitability", "manager-backend-tuning-suitability-unknown"),
    ("capacity-policy", "manager-backend-capacity-policy-unknown"),
    ("setup-behavior", "manager-backend-setup-behavior-unapproved"),
    ("schema-keyspace-policy", "manager-backend-schema-bootstrap-unapproved"),
    ("recovery-semantics", "manager-backend-recovery-semantics-unapproved"),
    (
        "backend-configuration-source",
        "manager-backend-configuration-source-unavailable",
    ),
)


class DeployManagerBackendPreflightReconciliationGateState(StrEnum):
    PASSED = "passed"
    UNKNOWN = "unknown"
    BLOCKED = "blocked"
    NOT_PERFORMED = "not-performed"


class DeployManagerBackendPreflightInstallationPlanningState(StrEnum):
    EVIDENCE_READY = "evidence-ready"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class DeployManagerBackendPreflightReconciliationGate:
    name: str
    state: DeployManagerBackendPreflightReconciliationGateState
    blockers: tuple[str, ...]
    evidence_digest: str
    gate_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_GATE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_GATE_SCHEMA_VERSION
            or _BLOCKER.fullmatch(self.name) is None
            or self.blockers != tuple(sorted(set(self.blockers)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blockers)
            or (
                self.state
                is DeployManagerBackendPreflightReconciliationGateState.PASSED
                and self.blockers
            )
            or (
                self.state
                in {
                    DeployManagerBackendPreflightReconciliationGateState.UNKNOWN,
                    DeployManagerBackendPreflightReconciliationGateState.BLOCKED,
                }
                and not self.blockers
            )
            or self.gate_digest != _record_digest(self, "gate_digest")
        ):
            raise StatePersistenceError(
                "deploy Manager backend preflight reconciliation gate conflicts"
            )
        validate_digest(
            self.evidence_digest,
            "Manager backend preflight reconciliation gate evidence digest",
        )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendPreflightReconciliationGate:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend preflight reconciliation gate",
        )
        try:
            return cls(
                name=require_string(value, "name"),
                state=DeployManagerBackendPreflightReconciliationGateState(
                    require_string(value, "state")
                ),
                blockers=_string_tuple(value["blockers"], "blockers"),
                evidence_digest=require_string(value, "evidence_digest"),
                gate_digest=require_string(value, "gate_digest"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Manager backend preflight reconciliation gate state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerBackendPreflightReconciliation:
    generation: int
    created_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    backend_context_artifact_digest: str
    backend_context_record_digest: str
    backend_plan_artifact_digest: str
    backend_plan_digest: str
    execution_artifact_digest: str
    execution_binding_digest: str
    evidence_artifact_digest: str
    evidence_digest: str
    result_digest: str
    provenance_digest: str
    source_digest: str
    playbook_source_digest: str
    toolchain_evidence_digest: str
    target_stable_id: str
    target_set_digest: str
    semantic_status: ManagerBackendPreflightStatus
    host_evidence_ready: bool
    host_observed_blockers: tuple[str, ...]
    host_observed_blocker_count: int
    host_observed_blocker_digest: str
    gates: tuple[DeployManagerBackendPreflightReconciliationGate, ...]
    gate_count: int
    passed_gate_count: int
    unknown_gate_count: int
    blocked_gate_count: int
    not_performed_gate_count: int
    blockers: tuple[str, ...]
    blocker_count: int
    blocker_digest: str
    installation_planning_state: DeployManagerBackendPreflightInstallationPlanningState
    backend_operational_readiness: str
    mutation_authorization_state: str
    mutation_execution_state: str
    public_workflow_state: str
    next_implementation_contract: str
    record_digest: str
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        expected_status = (
            DeployManagerBackendPreflightInstallationPlanningState.EVIDENCE_READY
            if self.host_evidence_ready
            else DeployManagerBackendPreflightInstallationPlanningState.BLOCKED
        )
        expected_gate_specs = (
            (
                "host-preflight-evidence",
                (
                    DeployManagerBackendPreflightReconciliationGateState.PASSED
                    if self.host_evidence_ready
                    else DeployManagerBackendPreflightReconciliationGateState.BLOCKED
                ),
                self.host_observed_blockers,
            ),
            *(
                (
                    name,
                    (
                        DeployManagerBackendPreflightReconciliationGateState.UNKNOWN
                        if blocker.endswith("-unknown")
                        else DeployManagerBackendPreflightReconciliationGateState.BLOCKED
                    ),
                    (blocker,),
                )
                for name, blocker in _GATE_BLOCKERS
            ),
            (
                "backend-operational-readiness",
                DeployManagerBackendPreflightReconciliationGateState.NOT_PERFORMED,
                (),
            ),
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
            or self.target_set_digest != _digest_object([self.target_stable_id])
            or self.host_evidence_ready
            != (self.semantic_status is ManagerBackendPreflightStatus.EVIDENCE_READY)
            or self.semantic_status is ManagerBackendPreflightStatus.FAILED
            or self.host_observed_blockers
            != tuple(sorted(set(self.host_observed_blockers)))
            or self.host_observed_blocker_count != len(self.host_observed_blockers)
            or self.host_observed_blocker_digest
            != _digest_object(list(self.host_observed_blockers))
            or tuple((gate.name, gate.state, gate.blockers) for gate in self.gates)
            != expected_gate_specs
            or any(gate.evidence_digest != self.evidence_digest for gate in self.gates)
            or self.gate_count != len(self.gates)
            or self.gate_count != len(_GATE_BLOCKERS) + 2
            or self.passed_gate_count
            != sum(
                gate.state
                is DeployManagerBackendPreflightReconciliationGateState.PASSED
                for gate in self.gates
            )
            or self.unknown_gate_count
            != sum(
                gate.state
                is DeployManagerBackendPreflightReconciliationGateState.UNKNOWN
                for gate in self.gates
            )
            or self.blocked_gate_count
            != sum(
                gate.state
                is DeployManagerBackendPreflightReconciliationGateState.BLOCKED
                for gate in self.gates
            )
            or self.not_performed_gate_count
            != sum(
                gate.state
                is DeployManagerBackendPreflightReconciliationGateState.NOT_PERFORMED
                for gate in self.gates
            )
            or self.blockers != tuple(sorted(set(self.blockers)))
            or self.blockers
            != tuple(
                sorted({blocker for gate in self.gates for blocker in gate.blockers})
            )
            or not set(MANAGER_BACKEND_UNRESOLVED_BLOCKERS).issubset(self.blockers)
            or self.blocker_count != len(self.blockers)
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.installation_planning_state is not expected_status
            or self.backend_operational_readiness != _NOT_PERFORMED
            or self.mutation_authorization_state != _UNAVAILABLE
            or self.mutation_execution_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
            or self.next_implementation_contract != _NEXT_IMPLEMENTATION_CONTRACT
            or self.record_digest != _record_digest(self, "record_digest")
        ):
            raise StatePersistenceError(
                "deploy Manager backend preflight reconciliation conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for count in (
            self.journal_generation,
            self.gate_count,
            self.unknown_gate_count,
            self.blocked_gate_count,
            self.not_performed_gate_count,
            self.blocker_count,
        ):
            _positive_integer(count, "Manager backend preflight reconciliation count")
        for digest in _digest_fields(self):
            validate_digest(digest, "Manager backend preflight reconciliation digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendPreflightReconciliation:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend preflight reconciliation",
        )
        integers = {
            "generation",
            "journal_generation",
            "host_observed_blocker_count",
            "gate_count",
            "passed_gate_count",
            "unknown_gate_count",
            "blocked_gate_count",
            "not_performed_gate_count",
            "blocker_count",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in integers:
                    parsed[name] = _integer(item, name)
                elif name in {"cluster_uuid", "operation_id"}:
                    parsed[name] = parse_uuid(require_string(value, name), name)
                elif name == "journal_status":
                    parsed[name] = JournalStatus(require_string(value, name))
                elif name == "journal_phase":
                    parsed[name] = OperationPhase(require_string(value, name))
                elif name == "semantic_status":
                    parsed[name] = ManagerBackendPreflightStatus(
                        require_string(value, name)
                    )
                elif name == "installation_planning_state":
                    parsed[name] = (
                        DeployManagerBackendPreflightInstallationPlanningState(
                            require_string(value, name)
                        )
                    )
                elif name == "host_evidence_ready":
                    parsed[name] = _boolean(item, name)
                elif name in {"host_observed_blockers", "blockers"}:
                    parsed[name] = _string_tuple(item, name)
                elif name == "gates":
                    parsed[name] = tuple(
                        DeployManagerBackendPreflightReconciliationGate.from_object(
                            _mapping(gate, "reconciliation gate")
                        )
                        for gate in _array(item, name)
                    )
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Manager backend preflight reconciliation enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendPreflightReconciliation:
    record: DeployManagerBackendPreflightReconciliation
    artifact_digest: str


class DeployManagerBackendPreflightReconciliationStore:
    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        _require_canonical_paths(paths)
        self._paths = paths
        self._operation_id = _require_operation_id(operation_id)
        self._path = deploy_manager_backend_preflight_reconciliation_path(
            paths, operation_id
        )
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployManagerBackendPreflightReconciliation:
        value, digest = self._file.read()
        record = DeployManagerBackendPreflightReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy Manager backend preflight reconciliation identity conflicts"
            )
        return StoredDeployManagerBackendPreflightReconciliation(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendPreflightReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendPreflightReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerBackendPreflightReconciliation,
        DeployManagerBackendPreflightArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy Manager backend preflight reconciliation operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy Manager backend preflight reconciliation is immutable"
                )
            return current, DeployManagerBackendPreflightArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerBackendPreflightReconciliation(record, digest),
            DeployManagerBackendPreflightArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendPreflightReconciliationReport:
    operation_id: uuid.UUID
    artifact_state: DeployManagerBackendPreflightArtifactState
    artifact_digest: str
    record_digest: str
    semantic_status: ManagerBackendPreflightStatus
    installation_planning_state: DeployManagerBackendPreflightInstallationPlanningState
    target_stable_id: str
    target_set_digest: str
    gate_count: int
    passed_gate_count: int
    unknown_gate_count: int
    blocked_gate_count: int
    not_performed_gate_count: int
    blocker_count: int
    blocker_digest: str
    backend_operational_readiness: str
    mutation_authorization_state: str
    mutation_execution_state: str
    next_implementation_contract: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_REPORT_SCHEMA_VERSION
            or self.gate_count != len(_GATE_BLOCKERS) + 2
            or self.unknown_gate_count < 4
            or self.blocked_gate_count < 4
            or self.not_performed_gate_count != 1
            or self.blocker_count < len(MANAGER_BACKEND_UNRESOLVED_BLOCKERS)
            or self.backend_operational_readiness != _NOT_PERFORMED
            or self.mutation_authorization_state != _UNAVAILABLE
            or self.mutation_execution_state != _NOT_STARTED
            or self.next_implementation_contract != _NEXT_IMPLEMENTATION_CONTRACT
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError(
                "deploy Manager backend preflight reconciliation report conflicts"
            )
        for digest in (
            self.artifact_digest,
            self.record_digest,
            self.target_set_digest,
            self.blocker_digest,
        ):
            validate_digest(
                digest, "Manager backend preflight reconciliation report digest"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "artifact": {
                "digest": self.artifact_digest,
                "record_digest": self.record_digest,
                "state": self.artifact_state.value,
            },
            "blockers": {
                "count": self.blocker_count,
                "digest": self.blocker_digest,
            },
            "gates": {
                "blocked_count": self.blocked_gate_count,
                "count": self.gate_count,
                "not_performed_count": self.not_performed_gate_count,
                "passed_count": self.passed_gate_count,
                "unknown_count": self.unknown_gate_count,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "next": {
                "backend_operational_readiness": (self.backend_operational_readiness),
                "contract": self.next_implementation_contract,
                "installation_planning_state": self.installation_planning_state.value,
                "mutation_authorization_state": self.mutation_authorization_state,
                "mutation_execution_state": self.mutation_execution_state,
            },
            "operation_id": str(self.operation_id),
            "schema_version": self.schema_version,
            "scope": {
                "target_set_digest": self.target_set_digest,
                "target_stable_id": self.target_stable_id,
            },
            "semantic_status": self.semantic_status.value,
        }


@dataclass(frozen=True, slots=True)
class _ReconciliationContext:
    execution: StoredDeployManagerBackendPreflightExecution
    evidence: StoredDeployManagerBackendPreflightEvidence


def reconcile_deploy_manager_backend_preflight(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployManagerBackendPreflightReconciliationReport:
    """Persist or exactly reuse bounded local-backend planning reconciliation."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _refuse_ambiguous_artifacts(paths, operation_id)
    context = _load_reconciliation_context(paths, operation_id, lock=lock)
    store = DeployManagerBackendPreflightReconciliationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    existing = (
        store.read_locked(
            lock,
            expected_cluster_uuid=context.execution.record.binding.cluster_uuid,
            expected_cluster_name=context.execution.record.binding.cluster_name,
        )
        if store.path.exists()
        else None
    )
    record = _build_record(
        context, created_at=None if existing is None else existing.record.created_at
    )
    stored, state = store.write_locked(record, lock=lock)
    return _build_report(stored, state=state)


def deploy_manager_backend_preflight_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}"
        f"{DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Manager backend preflight reconciliation path is not canonical"
        )
    return path


def deploy_manager_backend_preflight_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(
        DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_FILENAME_SUFFIX
    ):
        return None
    value = name[
        : -len(DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_FILENAME_SUFFIX)
    ]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _load_reconciliation_context(
    paths: StatePaths, operation_id: uuid.UUID, *, lock: ClusterLock
) -> _ReconciliationContext:
    planning = _load_backend_planning_context(paths, operation_id, lock=lock)
    metadata = planning.activation.record
    execution_store = DeployManagerBackendPreflightExecutionStore(paths, operation_id)
    evidence_store = DeployManagerBackendPreflightEvidenceStore(paths, operation_id)
    for path, label in (
        (execution_store.path, "execution"),
        (evidence_store.path, "semantic evidence"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"Manager backend preflight reconciliation requires complete {label}"
            )
    execution = execution_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    binding = execution.record.binding
    current = _load_execution_context(
        paths,
        operation_id,
        lock=lock,
        toolchain_version=binding.toolchain_version,
        executable_identity_digest=binding.executable_identity_digest,
        toolchain_evidence_digest=binding.toolchain_evidence_digest,
    )
    evidence = evidence_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    _validate_execution_prefix(current, execution, evidence)
    if (
        execution.record.state
        is not DeployManagerBackendPreflightExecutionState.SUCCEEDED
        or execution.record.manual_recovery_required
        or execution.record.automatic_retry_allowed
        or execution.record.generation != 2
        or evidence.record.status is ManagerBackendPreflightStatus.FAILED
    ):
        raise StateConflictError(
            "Manager backend preflight reconciliation requires exact terminal success"
        )
    return _ReconciliationContext(execution, evidence)


def _build_gates(
    evidence: DeployManagerBackendPreflightEvidence,
) -> tuple[DeployManagerBackendPreflightReconciliationGate, ...]:
    unresolved = set(MANAGER_BACKEND_UNRESOLVED_BLOCKERS)
    observed = tuple(sorted(set(evidence.blockers) - unresolved))
    values: list[
        tuple[
            str, DeployManagerBackendPreflightReconciliationGateState, tuple[str, ...]
        ]
    ] = [
        (
            "host-preflight-evidence",
            (
                DeployManagerBackendPreflightReconciliationGateState.PASSED
                if evidence.status is ManagerBackendPreflightStatus.EVIDENCE_READY
                else DeployManagerBackendPreflightReconciliationGateState.BLOCKED
            ),
            observed,
        )
    ]
    for name, blocker in _GATE_BLOCKERS:
        state = (
            DeployManagerBackendPreflightReconciliationGateState.UNKNOWN
            if blocker.endswith("-unknown")
            else DeployManagerBackendPreflightReconciliationGateState.BLOCKED
        )
        values.append((name, state, (blocker,)))
    values.append(
        (
            "backend-operational-readiness",
            DeployManagerBackendPreflightReconciliationGateState.NOT_PERFORMED,
            (),
        )
    )
    gates: list[DeployManagerBackendPreflightReconciliationGate] = []
    for name, state, blockers in values:
        fields: dict[str, object] = {
            "name": name,
            "state": state,
            "blockers": blockers,
            "evidence_digest": evidence.evidence_digest,
            "gate_digest": "",
        }
        fields["gate_digest"] = _record_digest_from_values(fields, "gate_digest")
        gates.append(
            DeployManagerBackendPreflightReconciliationGate(**fields)  # type: ignore[arg-type]
        )
    return tuple(gates)


def _build_record(
    context: _ReconciliationContext, *, created_at: str | None
) -> DeployManagerBackendPreflightReconciliation:
    execution = context.execution
    evidence = context.evidence
    binding = execution.record.binding
    gates = _build_gates(evidence.record)
    unresolved = set(MANAGER_BACKEND_UNRESOLVED_BLOCKERS)
    observed = tuple(sorted(set(evidence.record.blockers) - unresolved))
    blockers = tuple(sorted(set(evidence.record.blockers)))
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at or _timestamp(),
        "cluster_uuid": binding.cluster_uuid,
        "cluster_name": binding.cluster_name,
        "operation_id": binding.operation_id,
        "operation": _OPERATION,
        "request_digest": binding.request_digest,
        "journal_generation": binding.journal_generation,
        "journal_digest": binding.journal_digest,
        "journal_status": binding.journal_status,
        "journal_phase": binding.journal_phase,
        "backend_context_artifact_digest": binding.backend_context_artifact_digest,
        "backend_context_record_digest": binding.backend_context_record_digest,
        "backend_plan_artifact_digest": binding.backend_plan_artifact_digest,
        "backend_plan_digest": binding.backend_plan_digest,
        "execution_artifact_digest": execution.artifact_digest,
        "execution_binding_digest": binding.binding_digest,
        "evidence_artifact_digest": evidence.artifact_digest,
        "evidence_digest": evidence.record.evidence_digest,
        "result_digest": evidence.record.result_digest,
        "provenance_digest": evidence.record.provenance_digest,
        "source_digest": binding.source_digest,
        "playbook_source_digest": binding.playbook_source_digest,
        "toolchain_evidence_digest": binding.toolchain_evidence_digest,
        "target_stable_id": binding.target_stable_id,
        "target_set_digest": binding.target_set_digest,
        "semantic_status": evidence.record.status,
        "host_evidence_ready": (
            evidence.record.status is ManagerBackendPreflightStatus.EVIDENCE_READY
        ),
        "host_observed_blockers": observed,
        "host_observed_blocker_count": len(observed),
        "host_observed_blocker_digest": _digest_object(list(observed)),
        "gates": gates,
        "gate_count": len(gates),
        "passed_gate_count": sum(
            gate.state is DeployManagerBackendPreflightReconciliationGateState.PASSED
            for gate in gates
        ),
        "unknown_gate_count": sum(
            gate.state is DeployManagerBackendPreflightReconciliationGateState.UNKNOWN
            for gate in gates
        ),
        "blocked_gate_count": sum(
            gate.state is DeployManagerBackendPreflightReconciliationGateState.BLOCKED
            for gate in gates
        ),
        "not_performed_gate_count": sum(
            gate.state
            is DeployManagerBackendPreflightReconciliationGateState.NOT_PERFORMED
            for gate in gates
        ),
        "blockers": blockers,
        "blocker_count": len(blockers),
        "blocker_digest": _digest_object(list(blockers)),
        "installation_planning_state": (
            DeployManagerBackendPreflightInstallationPlanningState.EVIDENCE_READY
            if evidence.record.status is ManagerBackendPreflightStatus.EVIDENCE_READY
            else DeployManagerBackendPreflightInstallationPlanningState.BLOCKED
        ),
        "backend_operational_readiness": _NOT_PERFORMED,
        "mutation_authorization_state": _UNAVAILABLE,
        "mutation_execution_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "next_implementation_contract": _NEXT_IMPLEMENTATION_CONTRACT,
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(values, "record_digest")
    return DeployManagerBackendPreflightReconciliation(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployManagerBackendPreflightReconciliation,
    *,
    state: DeployManagerBackendPreflightArtifactState,
) -> DeployManagerBackendPreflightReconciliationReport:
    record = stored.record
    return DeployManagerBackendPreflightReconciliationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        artifact_digest=stored.artifact_digest,
        record_digest=record.record_digest,
        semantic_status=record.semantic_status,
        installation_planning_state=record.installation_planning_state,
        target_stable_id=record.target_stable_id,
        target_set_digest=record.target_set_digest,
        gate_count=record.gate_count,
        passed_gate_count=record.passed_gate_count,
        unknown_gate_count=record.unknown_gate_count,
        blocked_gate_count=record.blocked_gate_count,
        not_performed_gate_count=record.not_performed_gate_count,
        blocker_count=record.blocker_count,
        blocker_digest=record.blocker_digest,
        backend_operational_readiness=record.backend_operational_readiness,
        mutation_authorization_state=record.mutation_authorization_state,
        mutation_execution_state=record.mutation_execution_state,
        next_implementation_contract=record.next_implementation_contract,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
    )


_StoredRecord = (
    DeployManagerBackendPreflightReconciliationGate
    | DeployManagerBackendPreflightReconciliation
)


def _record_digest(record: _StoredRecord, digest_field: str) -> str:
    return _record_digest_from_values(
        cast(Mapping[str, object], asdict(record)), digest_field
    )


def _record_digest_from_values(values: Mapping[str, object], digest_field: str) -> str:
    copied = dict(values)
    for name in tuple(copied):
        if name == "schema_version" or name.endswith("_schema_version"):
            copied.pop(name)
    copied[digest_field] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(cast(Mapping[str, object], _jsonable(copied))))


def _dataclass_object(value: _StoredRecord) -> dict[str, object]:
    return cast(dict[str, object], _jsonable(asdict(value)))


def _jsonable(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, DeployManagerBackendPreflightReconciliationGate):
        return value.to_object()
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest_fields(
    value: DeployManagerBackendPreflightReconciliation,
) -> tuple[str, ...]:
    return tuple(
        cast(str, field_value)
        for field_name, field_value in asdict(value).items()
        if field_name.endswith("_digest") and field_value is not None
    )


def _timestamp() -> str:
    return format_timestamp(datetime.now(UTC))


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy Manager backend preflight reconciliation requires "
            "an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Manager backend preflight "
            "reconciliation artifacts"
        ) from error
    canonical = str(operation_id)
    suffix = DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_FILENAME_SUFFIX
    for entry in entries:
        if not entry.name.endswith(suffix):
            continue
        prefix = entry.name[: -len(suffix)]
        try:
            parsed = uuid.UUID(prefix)
        except ValueError:
            parsed = None
        if prefix != canonical and (
            parsed is None or parsed == operation_id or canonical in prefix
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy Manager backend preflight reconciliation artifacts "
                "are ambiguous"
            )


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise StatePersistenceError(f"{label} must be an array")
    return value


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise StatePersistenceError(f"{label} must be an array of strings")
    return tuple(cast(list[str], value))


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _positive_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be a boolean")
    return value
