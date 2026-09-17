"""Deploy-bound final-routes connectivity execution and reconciliation.

This internal owner runs exactly the read-only final-routes connectivity gate
made eligible by post-jump-host reconciliation.  Runtime jump limits and
address-bearing probes are derived only from canonical inventory routes; only
address-free semantic evidence is persisted.
"""

from __future__ import annotations

import ipaddress
import os
import re
import uuid
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.commands import (
    AnsibleCommandBuilder,
    ansible_command_intent_digest,
    validate_playbook_request_policy,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStep,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_jump_host_reconciliation import (
    ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_SCHEMA_VERSION,
    DeployPostJumpHostConfigureReconciliationStore,
    StoredDeployPostJumpHostConfigureReconciliation,
    _PostJumpHostContext,
)
from scylla_vms.ansible.deploy_jump_host_reconciliation import (
    _build_record as _build_post_jump_record,
)
from scylla_vms.ansible.deploy_jump_host_reconciliation import (
    _build_steps as _build_post_jump_steps,
)
from scylla_vms.ansible.deploy_jump_host_reconciliation import (
    _load_context as _load_post_jump_context,
)
from scylla_vms.ansible.deploy_jump_host_reconciliation import (
    _next_gate_ready as _post_jump_next_gate_ready,
)
from scylla_vms.ansible.deploy_plan import (
    DeployConditionState,
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.operation_binding import readiness_binding_digest
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.registry import OPERATION_PLAYBOOKS, get_playbook
from scylla_vms.ansible.service import (
    AnsibleExecutionResult,
    AnsibleResultError,
    AnsibleService,
    ConnectivityStatus,
    DestinationProbeStatus,
    HostConnectivityStatus,
    ProcessRunnerProtocol,
)
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION
from scylla_vms.ansible.toolchain import AnsibleToolchain
from scylla_vms.ansible.trust import TrustStore
from scylla_vms.desired import HostRole
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.inventory import InventoryHost
from scylla_vms.journal import JOURNAL_SCHEMA_VERSION, JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
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
from scylla_vms.process import ProcessOutputError, ProcessTimeoutError
from scylla_vms.state import (
    StatePaths,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)
from scylla_vms.terraform.apply_readiness import (
    TERRAFORM_APPLY_READINESS_SCHEMA_VERSION,
    _executable_identity_digest,
    _reconstructed_readiness,
    _toolchain_evidence_digest,
    _validate_toolchain_dependency,
)
from scylla_vms.validation import DESTINATION_CHECK_PORTS

ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-final-routes-execution-binding/v1"
)
ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-final-routes-execution/v1"
)
ANSIBLE_DEPLOY_FINAL_ROUTES_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-final-routes-evidence/v1"
)
ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-final-routes-execution-report/v1"
)
ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-final-routes-reconciliation/v1"
)
ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-final-routes-reconciliation-report/v1"
)

DEPLOY_FINAL_ROUTES_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-final-routes-execution.json"
)
DEPLOY_FINAL_ROUTES_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-final-routes-evidence.json"
)
DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-post-final-routes-reconciliation.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "connectivity-check"
_CONDITION = "final-routes"
_MAPPING_SEQUENCE = 5
_FINAL_EVIDENCE_MAPPING = len(OPERATION_PLAYBOOKS[_OPERATION])
_CONNECT_TIMEOUT_SECONDS = 10.0
_PROBE_TIMEOUT_SECONDS = 10
_MAX_DESTINATION_PAIRS = 64
_RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_NOT_STARTED = "not-started"
_NOT_PERFORMED = "not-performed"
_UNAVAILABLE = "unavailable"
_ORDER_BLOCKER = "ordered-deploy-step-not-reached"
_AUTHORIZATION_BLOCKER = "deploy-authorization-not-collected"
_PUBLIC_WORKFLOW_BLOCKER = "public-deploy-workflow-unavailable"
_CLASS_BLOCKERS = {
    OperationClassification.MUTATING: "mutating-deploy-execution-unavailable",
    OperationClassification.SENSITIVE: "sensitive-deploy-execution-unavailable",
    OperationClassification.DESTRUCTIVE: "destructive-deploy-execution-unavailable",
}
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")


class DeployFinalRoutesExecutionState(StrEnum):
    """Durable state of the sole final-routes invocation."""

    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"


class DeployFinalRoutesArtifactState(StrEnum):
    """Persistence state returned by the internal owners."""

    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployFinalRoutesExecutionBinding:
    """Address-free binding of the full chain and exact runtime intent."""

    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    post_jump_artifact_digest: str
    post_jump_record_digest: str
    post_jump_effective_plan_digest: str
    full_chain_digest: str
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    trust_generation: int
    trust_artifact_digest: str
    trust_entries_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    initial_connectivity_execution_digest: str
    initial_connectivity_evidence_digest: str
    jump_execution_digest: str
    jump_evidence_digest: str
    catalog_digest: str
    source_version: str
    source_digest: str
    playbook_source_digest: str
    toolchain_version: str
    executable_identity_digest: str
    toolchain_evidence_digest: str
    step_sequence: int
    step_digest: str
    planned_target_digest: str
    jump_count: int
    jump_set_digest: str
    destination_pair_count: int
    destination_pair_set_digest: str
    route_request_digest: str
    variables_digest: str
    command_digest: str
    binding_digest: str
    post_jump_schema_version: str = (
        ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_BINDING_SCHEMA_VERSION
            or self.post_jump_schema_version
            != ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
        ):
            raise StatePersistenceError("final-routes execution binding is invalid")
        validate_cluster_name(self.cluster_name)
        for value in (
            self.journal_generation,
            self.inventory_generation,
            self.trust_generation,
            self.step_sequence,
            self.jump_count,
            self.destination_pair_count,
        ):
            _positive_integer(value, "final-routes binding count")
        if self.destination_pair_count > _MAX_DESTINATION_PAIRS:
            raise StatePersistenceError("final-routes destination scope is too large")
        for digest_value in _binding_digests(self):
            validate_digest(digest_value, "final-routes binding digest")
        if self.binding_digest != _binding_digest(self):
            raise StatePersistenceError("final-routes binding digest conflicts")

    def to_object(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            result[name] = (
                str(value)
                if isinstance(value, uuid.UUID)
                else value.value
                if isinstance(value, (JournalStatus, OperationPhase))
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployFinalRoutesExecutionBinding:
        require_exact_keys(value, set(cls.__dataclass_fields__), "final-routes binding")
        integer_fields = {
            "journal_generation",
            "inventory_generation",
            "trust_generation",
            "step_sequence",
            "jump_count",
            "destination_pair_count",
        }
        parsed: dict[str, object] = {}
        for name in cls.__dataclass_fields__:
            if name in {"cluster_uuid", "operation_id"}:
                parsed[name] = parse_uuid(require_string(value, name), name)
            elif name in integer_fields:
                parsed[name] = _integer(value[name], name)
            elif name == "journal_status":
                parsed[name] = _enum(
                    JournalStatus, require_string(value, name), "journal status"
                )
            elif name == "journal_phase":
                parsed[name] = _enum(
                    OperationPhase, require_string(value, name), "journal phase"
                )
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployFinalRoutesExecution:
    """Generation-guarded at-most-once final-routes execution."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployFinalRoutesExecutionBinding
    state: DeployFinalRoutesExecutionState
    invocation_count: int
    invocation_may_have_occurred: bool
    completed: bool
    exit_code: int | None
    result_digest: str | None
    evidence_digest: str | None
    manual_recovery_required: bool
    automatic_retry_allowed: bool = False
    schema_version: str = ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_SCHEMA_VERSION
            or self.generation not in {1, 2}
            or self.invocation_count != 1
            or not self.invocation_may_have_occurred
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError("final-routes execution summary is invalid")
        created = parse_timestamp(self.created_at)
        updated = parse_timestamp(self.updated_at)
        if updated < created:
            raise StatePersistenceError("final-routes execution timestamps conflict")
        if self.state is DeployFinalRoutesExecutionState.STARTED:
            valid = (
                self.generation == 1
                and not self.completed
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.manual_recovery_required
            )
        elif self.state in {
            DeployFinalRoutesExecutionState.SUCCEEDED,
            DeployFinalRoutesExecutionState.FAILED,
            DeployFinalRoutesExecutionState.UNREACHABLE,
        }:
            valid = (
                self.generation == 2
                and self.completed
                and self.exit_code is not None
                and self.result_digest is not None
                and self.evidence_digest is not None
                and self.manual_recovery_required
                == (self.state is not DeployFinalRoutesExecutionState.SUCCEEDED)
            )
        else:
            valid = (
                self.generation == 2
                and not self.completed
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.manual_recovery_required
            )
        if not valid:
            raise StatePersistenceError("final-routes execution state conflicts")
        for value in (self.result_digest, self.evidence_digest):
            if value is not None:
                validate_digest(value, "final-routes execution outcome digest")

    def to_object(self) -> dict[str, object]:
        return {
            "automatic_retry_allowed": self.automatic_retry_allowed,
            "binding": self.binding.to_object(),
            "completed": self.completed,
            "created_at": self.created_at,
            "evidence_digest": self.evidence_digest,
            "exit_code": self.exit_code,
            "generation": self.generation,
            "invocation_count": self.invocation_count,
            "invocation_may_have_occurred": self.invocation_may_have_occurred,
            "manual_recovery_required": self.manual_recovery_required,
            "result_digest": self.result_digest,
            "schema_version": self.schema_version,
            "state": self.state.value,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployFinalRoutesExecution:
        require_exact_keys(
            value, set(cls.__dataclass_fields__), "final-routes execution"
        )
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                updated_at=require_string(value, "updated_at"),
                binding=DeployFinalRoutesExecutionBinding.from_object(
                    _mapping(value["binding"], "execution binding")
                ),
                state=DeployFinalRoutesExecutionState(require_string(value, "state")),
                invocation_count=_integer(
                    value["invocation_count"], "invocation count"
                ),
                invocation_may_have_occurred=_boolean(
                    value["invocation_may_have_occurred"],
                    "invocation may have occurred",
                ),
                completed=_boolean(value["completed"], "completed"),
                exit_code=_optional_integer(value["exit_code"], "exit code"),
                result_digest=_optional_string(value["result_digest"], "result digest"),
                evidence_digest=_optional_string(
                    value["evidence_digest"], "evidence digest"
                ),
                manual_recovery_required=_boolean(
                    value["manual_recovery_required"], "manual recovery required"
                ),
                automatic_retry_allowed=_boolean(
                    value["automatic_retry_allowed"], "automatic retry allowed"
                ),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "final-routes execution enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployFinalRoutesHostEvidence:
    """Address-free SSH outcome for one selected jump."""

    stable_id: str
    status: HostConnectivityStatus

    def __post_init__(self) -> None:
        if _LOGICAL_ID.fullmatch(self.stable_id) is None or not isinstance(
            self.status, HostConnectivityStatus
        ):
            raise StatePersistenceError("final-routes host evidence is invalid")

    def to_object(self) -> dict[str, object]:
        return {"stable_id": self.stable_id, "status": self.status.value}

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployFinalRoutesHostEvidence:
        require_exact_keys(value, {"stable_id", "status"}, "final-routes host evidence")
        try:
            return cls(
                require_string(value, "stable_id"),
                HostConnectivityStatus(require_string(value, "status")),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "final-routes host evidence status is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployFinalRoutesPairEvidence:
    """Address-free outcome for one inventory-assigned destination pair."""

    jump_stable_id: str
    target_stable_id: str
    role: str
    port: int
    status: DestinationProbeStatus

    def __post_init__(self) -> None:
        if (
            _LOGICAL_ID.fullmatch(self.jump_stable_id) is None
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
            or self.role not in DESTINATION_CHECK_PORTS
            or isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or self.port not in DESTINATION_CHECK_PORTS[self.role]
            or not isinstance(self.status, DestinationProbeStatus)
        ):
            raise StatePersistenceError("final-routes pair evidence is invalid")

    @property
    def key(self) -> tuple[str, str, str, int]:
        return (
            self.jump_stable_id,
            self.target_stable_id,
            self.role,
            self.port,
        )

    def to_object(self) -> dict[str, object]:
        return {
            "jump_stable_id": self.jump_stable_id,
            "port": self.port,
            "role": self.role,
            "status": self.status.value,
            "target_stable_id": self.target_stable_id,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployFinalRoutesPairEvidence:
        require_exact_keys(
            value,
            {
                "jump_stable_id",
                "port",
                "role",
                "status",
                "target_stable_id",
            },
            "final-routes pair evidence",
        )
        try:
            return cls(
                require_string(value, "jump_stable_id"),
                require_string(value, "target_stable_id"),
                require_string(value, "role"),
                _integer(value["port"], "port"),
                DestinationProbeStatus(require_string(value, "status")),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "final-routes pair evidence status is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployFinalRoutesEvidence:
    """Immutable address-free semantic evidence for the exact route check."""

    generation: int
    created_at: str
    binding: DeployFinalRoutesExecutionBinding
    status: ConnectivityStatus
    hosts: tuple[DeployFinalRoutesHostEvidence, ...]
    pairs: tuple[DeployFinalRoutesPairEvidence, ...]
    reachable_jump_count: int
    passed_pair_count: int
    result_digest: str
    evidence_digest: str
    schema_version: str = ANSIBLE_DEPLOY_FINAL_ROUTES_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_FINAL_ROUTES_EVIDENCE_SCHEMA_VERSION
            or self.generation != 1
            or not isinstance(self.status, ConnectivityStatus)
            or len(self.hosts) != self.binding.jump_count
            or len(self.pairs) != self.binding.destination_pair_count
            or tuple(item.stable_id for item in self.hosts)
            != tuple(sorted({item.stable_id for item in self.hosts}))
            or tuple(item.key for item in self.pairs)
            != tuple(sorted({item.key for item in self.pairs}))
            or self.reachable_jump_count
            != sum(
                item.status is HostConnectivityStatus.REACHABLE for item in self.hosts
            )
            or self.passed_pair_count
            != sum(item.status is DestinationProbeStatus.PASSED for item in self.pairs)
        ):
            raise StatePersistenceError("final-routes evidence summary conflicts")
        parse_timestamp(self.created_at)
        for value in (self.result_digest, self.evidence_digest):
            validate_digest(value, "final-routes evidence digest")
        if self.result_digest != _result_digest(self.hosts, self.pairs, self.status):
            raise StatePersistenceError("final-routes result digest conflicts")
        if self.evidence_digest != _evidence_digest(
            self.binding, self.result_digest, self.status
        ):
            raise StatePersistenceError("final-routes semantic digest conflicts")

    @property
    def successful(self) -> bool:
        return (
            self.status is ConnectivityStatus.SUCCESS
            and self.reachable_jump_count == len(self.hosts)
            and self.passed_pair_count == len(self.pairs)
        )

    def to_object(self) -> dict[str, object]:
        return {
            "binding": self.binding.to_object(),
            "created_at": self.created_at,
            "evidence_digest": self.evidence_digest,
            "generation": self.generation,
            "hosts": [item.to_object() for item in self.hosts],
            "pairs": [item.to_object() for item in self.pairs],
            "passed_pair_count": self.passed_pair_count,
            "reachable_jump_count": self.reachable_jump_count,
            "result_digest": self.result_digest,
            "schema_version": self.schema_version,
            "status": self.status.value,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployFinalRoutesEvidence:
        require_exact_keys(
            value, set(cls.__dataclass_fields__), "final-routes evidence"
        )
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                binding=DeployFinalRoutesExecutionBinding.from_object(
                    _mapping(value["binding"], "evidence binding")
                ),
                status=ConnectivityStatus(require_string(value, "status")),
                hosts=tuple(
                    DeployFinalRoutesHostEvidence.from_object(
                        _mapping(item, "host evidence")
                    )
                    for item in _array(value["hosts"], "host evidence")
                ),
                pairs=tuple(
                    DeployFinalRoutesPairEvidence.from_object(
                        _mapping(item, "pair evidence")
                    )
                    for item in _array(value["pairs"], "pair evidence")
                ),
                reachable_jump_count=_integer(
                    value["reachable_jump_count"], "reachable jump count"
                ),
                passed_pair_count=_integer(
                    value["passed_pair_count"], "passed pair count"
                ),
                result_digest=require_string(value, "result_digest"),
                evidence_digest=require_string(value, "evidence_digest"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "final-routes evidence enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class StoredDeployFinalRoutesExecution:
    record: DeployFinalRoutesExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployFinalRoutesEvidence:
    record: DeployFinalRoutesEvidence
    artifact_digest: str


class DeployFinalRoutesExecutionStore:
    """Generation-guarded owner-only execution store."""

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
        self._path = deploy_final_routes_execution_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployFinalRoutesExecution:
        value, digest = self._file.read()
        record = DeployFinalRoutesExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError("final-routes execution identity conflicts")
        return StoredDeployFinalRoutesExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployFinalRoutesExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployFinalRoutesExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployFinalRoutesExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError("final-routes execution operation conflicts")
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if (
                current.record.generation != expected_generation
                or current.artifact_digest != expected_digest
                or current.record.state is not DeployFinalRoutesExecutionState.STARTED
                or record.generation != 2
                or record.created_at != current.record.created_at
                or record.binding != current.record.binding
            ):
                raise StateConflictError("final-routes execution transition conflicts")
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
            or record.state is not DeployFinalRoutesExecutionState.STARTED
        ):
            raise StateConflictError("final-routes initial execution conflicts")
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployFinalRoutesExecution(record, digest)


class DeployFinalRoutesEvidenceStore:
    """Immutable owner-only semantic evidence store."""

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
        self._path = deploy_final_routes_evidence_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployFinalRoutesEvidence:
        value, digest = self._file.read()
        record = DeployFinalRoutesEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError("final-routes evidence identity conflicts")
        return StoredDeployFinalRoutesEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployFinalRoutesEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployFinalRoutesEvidence,
        *,
        lock: ClusterLock,
    ) -> tuple[StoredDeployFinalRoutesEvidence, DeployFinalRoutesArtifactState]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError("final-routes evidence operation conflicts")
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if current.record != record:
                raise StateConflictError("final-routes evidence is immutable")
            return current, DeployFinalRoutesArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployFinalRoutesEvidence(record, digest),
            DeployFinalRoutesArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployFinalRoutesExecutionReport:
    """Strict redacted final-routes execution projection."""

    operation_id: uuid.UUID
    execution_artifact_state: DeployFinalRoutesArtifactState
    evidence_artifact_state: DeployFinalRoutesArtifactState
    execution_state: DeployFinalRoutesExecutionState
    execution_artifact_digest: str
    evidence_artifact_digest: str
    binding_digest: str
    invocation_count: int
    jump_count: int
    jump_set_digest: str
    destination_pair_count: int
    destination_pair_set_digest: str
    reachable_jump_count: int
    passed_pair_count: int
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    journal_status: JournalStatus
    journal_phase: OperationPhase
    execution_schema_version: str = ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_SCHEMA_VERSION
    evidence_schema_version: str = ANSIBLE_DEPLOY_FINAL_ROUTES_EVIDENCE_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_REPORT_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_FINAL_ROUTES_EVIDENCE_SCHEMA_VERSION
            or self.execution_state is not DeployFinalRoutesExecutionState.SUCCEEDED
            or self.invocation_count != 1
            or self.jump_count < 1
            or self.destination_pair_count < 1
            or self.reachable_jump_count != self.jump_count
            or self.passed_pair_count != self.destination_pair_count
            or self.manual_recovery_required
            or self.automatic_retry_allowed
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError("final-routes execution report is invalid")
        for value in (
            self.execution_artifact_digest,
            self.evidence_artifact_digest,
            self.binding_digest,
            self.jump_set_digest,
            self.destination_pair_set_digest,
        ):
            validate_digest(value, "final-routes report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "artifacts": {
                "evidence_digest": self.evidence_artifact_digest,
                "evidence_state": self.evidence_artifact_state.value,
                "execution_digest": self.execution_artifact_digest,
                "execution_state": self.execution_artifact_state.value,
            },
            "execution": {
                "automatic_retry_allowed": self.automatic_retry_allowed,
                "binding_digest": self.binding_digest,
                "invocation_count": self.invocation_count,
                "manual_recovery_required": self.manual_recovery_required,
                "state": self.execution_state.value,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "operation_id": str(self.operation_id),
            "result": {
                "passed_pair_count": self.passed_pair_count,
                "reachable_jump_count": self.reachable_jump_count,
            },
            "schema_version": self.schema_version,
            "schemas": {
                "evidence": self.evidence_schema_version,
                "execution": self.execution_schema_version,
            },
            "scope": {
                "destination_pair_count": self.destination_pair_count,
                "destination_pair_set_digest": self.destination_pair_set_digest,
                "jump_count": self.jump_count,
                "jump_set_digest": self.jump_set_digest,
            },
        }


@dataclass(frozen=True, slots=True)
class _FinalRoutesScope:
    step: DeployBaseOsReconciledStep
    jumps: tuple[str, ...]
    pairs: tuple[tuple[str, str, str, str, int], ...]
    variables: Mapping[str, object]
    variables_digest: str
    command_digest: str
    source_digest: str
    pair_set_digest: str
    route_request_digest: str


@dataclass(frozen=True, slots=True)
class _FinalRoutesContext:
    post: _PostJumpHostContext
    reconciliation: StoredDeployPostJumpHostConfigureReconciliation
    scope: _FinalRoutesScope
    binding: DeployFinalRoutesExecutionBinding


def execute_deploy_final_routes_connectivity(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployFinalRoutesExecutionReport:
    """Execute exactly one immutable final-routes connectivity instance."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _validate_toolchain_dependency(toolchain)
    executable_identity_digest = _executable_identity_digest(executables)
    toolchain_evidence_digest = _toolchain_evidence_digest(
        toolchain, executable_identity_digest
    )
    _refuse_ambiguous_artifacts(paths, operation_id)
    context = _load_final_routes_context(
        paths,
        operation_id,
        lock=lock,
        toolchain_version=str(toolchain.core),
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    metadata = context.post.post.base.host.loaded.planning.base.deploy.metadata.record
    execution_store = DeployFinalRoutesExecutionStore(paths, operation_id)
    evidence_store = DeployFinalRoutesEvidenceStore(paths, operation_id)
    for path in (execution_store.path, evidence_store.path):
        validate_state_file(path, allow_missing=True)
    execution = (
        execution_store.read_locked(
            lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
        )
        if execution_store.path.exists()
        else None
    )
    evidence = (
        evidence_store.read_locked(
            lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
        )
        if evidence_store.path.exists()
        else None
    )
    _validate_execution_prefix(context, execution, evidence)
    if execution is not None:
        if (
            execution.record.state is DeployFinalRoutesExecutionState.SUCCEEDED
            and evidence is not None
            and evidence.record.successful
        ):
            return _build_execution_report(
                execution,
                evidence,
                execution_state=DeployFinalRoutesArtifactState.REUSED,
                evidence_state=DeployFinalRoutesArtifactState.REUSED,
            )
        raise StateConflictError(
            "final-routes execution requires manual recovery and cannot retry"
        )

    builder = AnsibleCommandBuilder(executables.playbook, executables.inventory, paths)
    definition, validated, variables_digest, command_digest = (
        builder.validate_operation_step(
            _PLAYBOOK,
            step_sequence=context.scope.step.sequence,
            limit=context.scope.jumps,
            variables=dict(context.scope.variables),
            tags=(),
            check=False,
            diff=False,
            verbosity=0,
        )
    )
    if (
        definition.name != _PLAYBOOK
        or variables_digest != context.scope.variables_digest
        or command_digest != context.scope.command_digest
    ):
        raise StateConflictError("final-routes command identity conflicts")
    service = AnsibleService(builder, runner)
    discovered = service.version(lock)
    if discovered != toolchain:
        raise StateConflictError("final-routes Ansible toolchain drifted")
    before = _load_final_routes_context(
        paths,
        operation_id,
        lock=lock,
        toolchain_version=str(toolchain.core),
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    if before.binding != context.binding:
        raise StateConflictError("final-routes state drifted before invocation")
    now = _timestamp()
    started = DeployFinalRoutesExecution(
        generation=1,
        created_at=now,
        updated_at=now,
        binding=context.binding,
        state=DeployFinalRoutesExecutionState.STARTED,
        invocation_count=1,
        invocation_may_have_occurred=True,
        completed=False,
        exit_code=None,
        result_digest=None,
        evidence_digest=None,
        manual_recovery_required=True,
    )
    try:
        execution = execution_store.write_locked(
            started, expected_generation=0, expected_digest=None, lock=lock
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "final-routes started intent persistence failed before invocation"
        ) from error

    readiness = _reconstructed_readiness(
        context.post.post.base.host.loaded.planning.base
    )
    try:
        result, observed_command_digest = service.execute_operation_step(
            lock,
            metadata,
            context.post.post.base.host.loaded.planning.base.deploy.inventory,
            _PLAYBOOK,
            step_sequence=context.scope.step.sequence,
            limit=context.scope.jumps,
            variables=validated,
            readiness=readiness,
            tags=(),
            check=False,
            diff=False,
            verbosity=0,
        )
        if observed_command_digest != context.scope.command_digest:
            raise AnsibleResultError("final-routes command result identity conflicts")
    except KeyboardInterrupt:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployFinalRoutesExecutionState.INTERRUPTED,
            lock=lock,
        )
        raise AnsibleError(
            "final-routes execution was interrupted; manual recovery required"
        ) from None
    except AnsibleError as error:
        _persist_uncertain_or_raise(
            execution_store, execution, _failure_state(error), lock=lock
        )
        raise AnsibleError(
            "final-routes execution is uncertain; manual recovery required"
        ) from error

    try:
        after = _load_final_routes_context(
            paths,
            operation_id,
            lock=lock,
            toolchain_version=str(toolchain.core),
            executable_identity_digest=executable_identity_digest,
            toolchain_evidence_digest=toolchain_evidence_digest,
        )
    except (StateConflictError, StatePersistenceError) as error:
        raise StateConflictError(
            "final-routes state changed after invocation; manual recovery required"
        ) from error
    if after.binding != context.binding:
        raise StateConflictError(
            "final-routes state changed after invocation; manual recovery required"
        )
    try:
        evidence_record = _semantic_evidence(context, result)
    except (AnsibleError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployFinalRoutesExecutionState.MALFORMED_RESULT,
            lock=lock,
        )
        raise AnsibleError(
            "final-routes result is malformed; manual recovery required"
        ) from error
    try:
        evidence, evidence_state = evidence_store.write_locked(
            evidence_record, lock=lock
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "final-routes evidence persistence failed; manual recovery required"
        ) from error
    terminal_state = _terminal_state(evidence_record, result.exit_code)
    terminal = replace(
        execution.record,
        generation=2,
        updated_at=_timestamp(),
        state=terminal_state,
        completed=terminal_state
        in {
            DeployFinalRoutesExecutionState.SUCCEEDED,
            DeployFinalRoutesExecutionState.FAILED,
            DeployFinalRoutesExecutionState.UNREACHABLE,
        },
        exit_code=result.exit_code,
        result_digest=evidence_record.result_digest,
        evidence_digest=evidence_record.evidence_digest,
        manual_recovery_required=(
            terminal_state is not DeployFinalRoutesExecutionState.SUCCEEDED
        ),
    )
    try:
        execution = execution_store.write_locked(
            terminal,
            expected_generation=execution.record.generation,
            expected_digest=execution.artifact_digest,
            lock=lock,
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "final-routes terminal persistence failed; manual recovery required"
        ) from error
    if terminal_state is not DeployFinalRoutesExecutionState.SUCCEEDED:
        raise AnsibleError("final-routes connectivity failed; manual recovery required")
    return _build_execution_report(
        execution,
        evidence,
        execution_state=DeployFinalRoutesArtifactState.UPDATED,
        evidence_state=evidence_state,
    )


def deploy_final_routes_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_FINAL_ROUTES_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError("final-routes execution path is not canonical")
    return path


def deploy_final_routes_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_FINAL_ROUTES_EVIDENCE_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError("final-routes evidence path is not canonical")
    return path


def deploy_final_routes_execution_id_from_filename(name: str) -> uuid.UUID | None:
    return _id_from_filename(name, DEPLOY_FINAL_ROUTES_EXECUTION_FILENAME_SUFFIX)


def deploy_final_routes_evidence_id_from_filename(name: str) -> uuid.UUID | None:
    return _id_from_filename(name, DEPLOY_FINAL_ROUTES_EVIDENCE_FILENAME_SUFFIX)


def _load_final_routes_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
    toolchain_version: str,
    executable_identity_digest: str,
    toolchain_evidence_digest: str,
) -> _FinalRoutesContext:
    post = _load_post_jump_context(paths, operation_id, lock=lock)
    loaded = post.post.base.host.loaded
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    readiness_record = planning.readiness.record
    if (
        readiness_record.playbook_version != toolchain_version
        or readiness_record.inventory_version != toolchain_version
        or readiness_record.executable_identity_digest != executable_identity_digest
        or readiness_record.toolchain_evidence_digest != toolchain_evidence_digest
        or readiness_record.remote_playbook_status != _NOT_PERFORMED
    ):
        raise StateConflictError(
            "final-routes readiness or toolchain binding conflicts"
        )
    readiness = _reconstructed_readiness(planning.base)
    if readiness_binding_digest(readiness) != readiness_record.readiness_digest:
        raise StateConflictError("final-routes readiness is stale")
    readiness.require_ready(OperationClassification.READ_ONLY)
    TrustStore(paths).validate_runtime(planning.base.trust, deploy.inventory)
    store = DeployPostJumpHostConfigureReconciliationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    if not store.path.exists():
        raise StateConflictError(
            "final-routes execution requires post-jump-host reconciliation"
        )
    reconciliation = store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected = _build_post_jump_record(
        post,
        steps=_build_post_jump_steps(post),
        created_at=reconciliation.record.created_at,
    )
    if reconciliation.record != expected:
        raise StateConflictError("final-routes post-jump reconciliation drifted")
    scope = _derive_scope(post, reconciliation)
    journal = deploy.journal
    values: dict[str, object] = {
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_name": metadata.cluster_name,
        "operation_id": operation_id,
        "operation": _OPERATION,
        "request_digest": journal.record.request_digest,
        "journal_generation": journal.record.generation,
        "journal_digest": journal.digest,
        "journal_status": journal.record.status,
        "journal_phase": journal.record.phase,
        "post_jump_artifact_digest": reconciliation.artifact_digest,
        "post_jump_record_digest": reconciliation.record.record_digest,
        "post_jump_effective_plan_digest": (
            reconciliation.record.effective_plan_digest
        ),
        "full_chain_digest": _full_chain_digest(post, reconciliation),
        "inventory_generation": deploy.inventory.record.generation,
        "inventory_artifact_digest": deploy.inventory.digest,
        "inventory_digest": deploy.inventory.record.inventory_digest,
        "trust_generation": planning.base.trust.record.generation,
        "trust_artifact_digest": planning.base.trust.digest,
        "trust_entries_digest": planning.base.trust.record.entries_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": readiness_record.record_digest,
        "initial_connectivity_execution_digest": loaded.execution.artifact_digest,
        "initial_connectivity_evidence_digest": loaded.evidence.artifact_digest,
        "jump_execution_digest": post.execution.artifact_digest,
        "jump_evidence_digest": post.evidence.artifact_digest,
        "catalog_digest": loaded.catalog_digest,
        "source_version": loaded.source.version,
        "source_digest": loaded.source.digest,
        "playbook_source_digest": scope.source_digest,
        "toolchain_version": toolchain_version,
        "executable_identity_digest": executable_identity_digest,
        "toolchain_evidence_digest": toolchain_evidence_digest,
        "step_sequence": scope.step.sequence,
        "step_digest": _digest_object(scope.step.to_object()),
        "planned_target_digest": scope.step.target_digest,
        "jump_count": len(scope.jumps),
        "jump_set_digest": _digest_object(list(scope.jumps)),
        "destination_pair_count": len(scope.pairs),
        "destination_pair_set_digest": scope.pair_set_digest,
        "route_request_digest": scope.route_request_digest,
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "binding_digest": "",
    }
    values["binding_digest"] = _binding_digest_from_values(values)
    binding = DeployFinalRoutesExecutionBinding(**values)  # type: ignore[arg-type]
    return _FinalRoutesContext(post, reconciliation, scope, binding)


def _derive_scope(
    post: _PostJumpHostContext,
    reconciliation: StoredDeployPostJumpHostConfigureReconciliation,
) -> _FinalRoutesScope:
    planning = post.post.base.host.loaded.planning
    loaded = post.post.base.host.loaded
    inventory_hosts = planning.base.deploy.inventory.record.inventory.hosts
    all_ids = tuple(sorted(host.logical_id for host in inventory_hosts))
    selected = tuple(
        step
        for step in reconciliation.record.steps
        if step.mapping_sequence == _MAPPING_SEQUENCE
    )
    if (
        len(selected) != 1
        or selected[0].playbook != _PLAYBOOK
        or selected[0].condition != _CONDITION
        or selected[0].condition_state is not DeployConditionState.ACTIVE
        or selected[0].classification is not OperationClassification.READ_ONLY
        or selected[0].status is not DeployBaseOsReconciledStepStatus.ELIGIBLE
        or selected[0].target_ids != all_ids
        or selected[0].target_digest != _digest_object(list(all_ids))
        or selected[0].source_digest
        != _playbook_source_digest(loaded.source, _PLAYBOOK)
    ):
        raise StateConflictError("final-routes eligible step identity conflicts")
    jumps = tuple(
        sorted(
            host.logical_id
            for host in inventory_hosts
            if host.role is HostRole.JUMP_HOST
        )
    )
    if not jumps:
        raise StateConflictError("final-routes jump-host scope is unavailable")
    pairs = _derive_destination_pairs(inventory_hosts, jumps)
    if not pairs:
        raise StateConflictError("final-routes destination scope is unavailable")
    variables: dict[str, object] = {
        "deploy_scylla_vms_connect_timeout_seconds": _CONNECT_TIMEOUT_SECONDS,
        "deploy_scylla_vms_destination_probes": [
            {
                "address": address,
                "jump_host_id": jump,
                "port": port,
                "role": role,
                "target_logical_id": target,
            }
            for jump, target, role, address, port in pairs
        ],
        "deploy_scylla_vms_probe_timeout_seconds": _PROBE_TIMEOUT_SECONDS,
    }
    definition = get_playbook(_PLAYBOOK)
    validate_playbook_request_policy(
        _PLAYBOOK,
        limit=jumps,
        tags=(),
        check=False,
        diff=False,
        verbosity=0,
    )
    validated = definition.validate_variables(variables)
    variables_digest = digest_bytes(serialize_json(validated))
    command_digest = ansible_command_intent_digest(
        definition,
        step_sequence=selected[0].sequence,
        limit=jumps,
        variables_digest=variables_digest,
        tags=(),
        check=False,
        diff=False,
        verbosity=0,
    )
    address_free = [
        {"jump": jump, "port": port, "role": role, "target": target}
        for jump, target, role, _address, port in pairs
    ]
    return _FinalRoutesScope(
        selected[0],
        jumps,
        pairs,
        validated,
        variables_digest,
        command_digest,
        _playbook_source_digest(loaded.source, _PLAYBOOK),
        _digest_object(address_free),
        _digest_object(
            {
                "inventory_artifact_digest": (planning.base.deploy.inventory.digest),
                "pairs": [
                    {
                        "address": address,
                        "jump": jump,
                        "port": port,
                        "role": role,
                        "target": target,
                    }
                    for jump, target, role, address, port in pairs
                ],
                "trust_artifact_digest": planning.base.trust.digest,
            }
        ),
    )


def _derive_destination_pairs(
    hosts: tuple[InventoryHost, ...], jumps: tuple[str, ...]
) -> tuple[tuple[str, str, str, str, int], ...]:
    jump_set = set(jumps)
    pairs: list[tuple[str, str, str, str, int]] = []
    for host in hosts:
        if host.role is HostRole.JUMP_HOST:
            continue
        role = host.role.value
        try:
            address = ipaddress.ip_address(host.private_address)
        except ValueError as error:
            raise StateConflictError(
                "final-routes destination address is invalid"
            ) from error
        if (
            role not in DESTINATION_CHECK_PORTS
            or host.route_mode != "proxy-jump"
            or host.jump_host_id not in jump_set
            or host.ansible_host != host.private_address
            or not isinstance(address, ipaddress.IPv4Address)
            or not any(address in network for network in _RFC1918_NETWORKS)
        ):
            raise StateConflictError(
                "final-routes destination conflicts with canonical routing"
            )
        pairs.extend(
            (
                host.jump_host_id,
                host.logical_id,
                role,
                host.private_address,
                port,
            )
            for port in sorted(DESTINATION_CHECK_PORTS[role])
        )
    result = tuple(sorted(pairs))
    address_free = tuple(
        (jump, target, role, port) for jump, target, role, _address, port in result
    )
    if len(result) > _MAX_DESTINATION_PAIRS or address_free != tuple(
        sorted(set(address_free))
    ):
        raise StateConflictError(
            "final-routes destination scope is duplicated or too large"
        )
    return result


def _validate_execution_prefix(
    context: _FinalRoutesContext,
    execution: StoredDeployFinalRoutesExecution | None,
    evidence: StoredDeployFinalRoutesEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError("final-routes evidence exists without intent")
        return
    if execution.record.binding != context.binding:
        raise StateConflictError("final-routes execution provenance is stale")
    if evidence is not None:
        if (
            evidence.record.binding != context.binding
            or execution.record.result_digest != evidence.record.result_digest
            or execution.record.evidence_digest != evidence.record.evidence_digest
        ):
            raise StateConflictError("final-routes semantic evidence conflicts")
    elif execution.record.state in {
        DeployFinalRoutesExecutionState.SUCCEEDED,
        DeployFinalRoutesExecutionState.FAILED,
        DeployFinalRoutesExecutionState.UNREACHABLE,
    }:
        raise StateConflictError("final-routes terminal evidence is missing")


def _semantic_evidence(
    context: _FinalRoutesContext, result: AnsibleExecutionResult
) -> DeployFinalRoutesEvidence:
    parsed = result.connectivity
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.READ_ONLY
        or result.check_mode
        or result.stdout
        or result.stderr
        or parsed is None
    ):
        raise AnsibleResultError("final-routes result identity conflicts")
    hosts = tuple(
        DeployFinalRoutesHostEvidence(item.logical_id, item.status)
        for item in parsed.hosts
    )
    pairs = tuple(
        DeployFinalRoutesPairEvidence(
            item.jump_host_id,
            item.target_logical_id,
            item.role,
            item.port,
            item.status,
        )
        for item in parsed.destination_probes
    )
    expected_pairs = tuple(
        (jump, target, role, port)
        for jump, target, role, _address, port in context.scope.pairs
    )
    if (
        tuple(item.stable_id for item in hosts) != context.scope.jumps
        or tuple(item.key for item in pairs) != expected_pairs
    ):
        raise AnsibleResultError("final-routes result membership conflicts")
    result_digest = _result_digest(hosts, pairs, parsed.status)
    return DeployFinalRoutesEvidence(
        generation=1,
        created_at=_timestamp(),
        binding=context.binding,
        status=parsed.status,
        hosts=hosts,
        pairs=pairs,
        reachable_jump_count=sum(
            item.status is HostConnectivityStatus.REACHABLE for item in hosts
        ),
        passed_pair_count=sum(
            item.status is DestinationProbeStatus.PASSED for item in pairs
        ),
        result_digest=result_digest,
        evidence_digest=_evidence_digest(context.binding, result_digest, parsed.status),
    )


def _terminal_state(
    evidence: DeployFinalRoutesEvidence, exit_code: int
) -> DeployFinalRoutesExecutionState:
    if exit_code == 0 and evidence.successful:
        return DeployFinalRoutesExecutionState.SUCCEEDED
    if exit_code == 4 or any(
        item.status is HostConnectivityStatus.UNREACHABLE for item in evidence.hosts
    ):
        return DeployFinalRoutesExecutionState.UNREACHABLE
    return DeployFinalRoutesExecutionState.FAILED


def _persist_uncertain_or_raise(
    store: DeployFinalRoutesExecutionStore,
    current: StoredDeployFinalRoutesExecution,
    state: DeployFinalRoutesExecutionState,
    *,
    lock: ClusterLock,
) -> None:
    try:
        record = replace(
            current.record,
            generation=2,
            updated_at=_timestamp(),
            state=state,
            manual_recovery_required=True,
        )
        store.write_locked(
            record,
            expected_generation=current.record.generation,
            expected_digest=current.artifact_digest,
            lock=lock,
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "final-routes uncertain outcome persistence failed; "
            "manual recovery required"
        ) from error


def _build_execution_report(
    execution: StoredDeployFinalRoutesExecution,
    evidence: StoredDeployFinalRoutesEvidence,
    *,
    execution_state: DeployFinalRoutesArtifactState,
    evidence_state: DeployFinalRoutesArtifactState,
) -> DeployFinalRoutesExecutionReport:
    record = execution.record
    semantic = evidence.record
    if (
        record.state is not DeployFinalRoutesExecutionState.SUCCEEDED
        or not semantic.successful
        or record.result_digest != semantic.result_digest
        or record.evidence_digest != semantic.evidence_digest
    ):
        raise StateConflictError("final-routes success evidence is incomplete")
    return DeployFinalRoutesExecutionReport(
        operation_id=record.binding.operation_id,
        execution_artifact_state=execution_state,
        evidence_artifact_state=evidence_state,
        execution_state=record.state,
        execution_artifact_digest=execution.artifact_digest,
        evidence_artifact_digest=evidence.artifact_digest,
        binding_digest=record.binding.binding_digest,
        invocation_count=record.invocation_count,
        jump_count=record.binding.jump_count,
        jump_set_digest=record.binding.jump_set_digest,
        destination_pair_count=record.binding.destination_pair_count,
        destination_pair_set_digest=record.binding.destination_pair_set_digest,
        reachable_jump_count=semantic.reachable_jump_count,
        passed_pair_count=semantic.passed_pair_count,
        manual_recovery_required=record.manual_recovery_required,
        automatic_retry_allowed=record.automatic_retry_allowed,
        journal_status=record.binding.journal_status,
        journal_phase=record.binding.journal_phase,
    )


@dataclass(frozen=True, slots=True)
class DeployPostFinalRoutesReconciliation:
    """Immutable effective deploy plan after final-routes success."""

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
    post_jump_artifact_digest: str
    post_jump_record_digest: str
    post_jump_effective_plan_digest: str
    execution_artifact_digest: str
    execution_binding_digest: str
    evidence_artifact_digest: str
    evidence_digest: str
    jump_count: int
    jump_set_digest: str
    destination_pair_count: int
    destination_pair_set_digest: str
    steps: tuple[DeployBaseOsReconciledStep, ...]
    step_count: int
    succeeded_count: int
    authorization_required_count: int
    eligible_count: int
    blocked_count: int
    not_performed_count: int
    blocker_set: tuple[str, ...]
    blocker_digest: str
    effective_plan_digest: str
    finalization_state: str
    public_workflow_state: str
    record_digest: str
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    post_jump_schema_version: str = (
        ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_SCHEMA_VERSION
    )
    execution_schema_version: str = ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_SCHEMA_VERSION
    evidence_schema_version: str = ANSIBLE_DEPLOY_FINAL_ROUTES_EVIDENCE_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.post_jump_schema_version
            != ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_FINAL_ROUTES_EVIDENCE_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
        ):
            raise StatePersistenceError("post-final-routes identity is invalid")
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        counts = Counter(step.status for step in self.steps)
        blockers = tuple(
            sorted({blocker for step in self.steps for blocker in step.blockers})
        )
        if (
            self.journal_generation < 1
            or self.jump_count < 1
            or self.destination_pair_count < 1
            or self.step_count != len(self.steps)
            or self.succeeded_count
            != counts[DeployBaseOsReconciledStepStatus.SUCCEEDED]
            or self.authorization_required_count
            != counts[
                DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            ]
            or self.eligible_count != counts[DeployBaseOsReconciledStepStatus.ELIGIBLE]
            or self.blocked_count != counts[DeployBaseOsReconciledStepStatus.BLOCKED]
            or self.not_performed_count
            != counts[DeployBaseOsReconciledStepStatus.NOT_PERFORMED]
            or blockers != self.blocker_set
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blocker_set)
            or self.blocker_digest != _digest_object(list(self.blocker_set))
            or self.effective_plan_digest
            != _digest_object([step.to_object() for step in self.steps])
        ):
            raise StatePersistenceError("post-final-routes summary conflicts")
        for value in _reconciliation_digests(self):
            validate_digest(value, "post-final-routes digest")
        if self.record_digest != _reconciliation_record_digest(self):
            raise StatePersistenceError("post-final-routes record digest conflicts")

    def to_object(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            result[name] = (
                str(value)
                if isinstance(value, uuid.UUID)
                else value.value
                if isinstance(value, (JournalStatus, OperationPhase))
                else [step.to_object() for step in value]
                if name == "steps"
                else list(value)
                if name == "blocker_set"
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployPostFinalRoutesReconciliation:
        require_exact_keys(
            value, set(cls.__dataclass_fields__), "post-final-routes reconciliation"
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "jump_count",
            "destination_pair_count",
            "step_count",
            "succeeded_count",
            "authorization_required_count",
            "eligible_count",
            "blocked_count",
            "not_performed_count",
        }
        parsed: dict[str, object] = {}
        for name in cls.__dataclass_fields__:
            if name in integer_fields:
                parsed[name] = _integer(value[name], name)
            elif name in {"cluster_uuid", "operation_id"}:
                parsed[name] = parse_uuid(require_string(value, name), name)
            elif name == "journal_status":
                parsed[name] = _enum(
                    JournalStatus, require_string(value, name), "journal status"
                )
            elif name == "journal_phase":
                parsed[name] = _enum(
                    OperationPhase, require_string(value, name), "journal phase"
                )
            elif name == "steps":
                parsed[name] = tuple(
                    DeployBaseOsReconciledStep.from_object(
                        _mapping(item, "reconciled step")
                    )
                    for item in _array(value[name], "reconciled steps")
                )
            elif name == "blocker_set":
                parsed[name] = _string_tuple(value[name], name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployPostFinalRoutesReconciliation:
    record: DeployPostFinalRoutesReconciliation
    artifact_digest: str


class DeployPostFinalRoutesReconciliationStore:
    """Immutable owner-only post-final-routes reconciliation store."""

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
        self._path = deploy_post_final_routes_reconciliation_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployPostFinalRoutesReconciliation:
        value, digest = self._file.read()
        record = DeployPostFinalRoutesReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "post-final-routes reconciliation identity conflicts"
            )
        return StoredDeployPostFinalRoutesReconciliation(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPostFinalRoutesReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployPostFinalRoutesReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployPostFinalRoutesReconciliation, DeployFinalRoutesArtifactState
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "post-final-routes reconciliation operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "post-final-routes reconciliation is immutable"
                )
            return current, DeployFinalRoutesArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployPostFinalRoutesReconciliation(record, digest),
            DeployFinalRoutesArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployPostFinalRoutesNextStepSummary:
    """Redacted immediate-next-gate grouping."""

    playbook: str
    target_role: str
    classification: OperationClassification
    status: DeployBaseOsReconciledStepStatus
    instance_count: int
    target_count: int
    target_set_digest: str
    instance_digest: str

    def __post_init__(self) -> None:
        if (
            get_playbook(self.playbook).classification is not self.classification
            or self.status
            not in {
                DeployBaseOsReconciledStepStatus.ELIGIBLE,
                DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
            }
            or self.instance_count < 1
            or self.target_count < 1
        ):
            raise StatePersistenceError("post-final-routes next step is invalid")
        validate_digest(self.target_set_digest, "next target digest")
        validate_digest(self.instance_digest, "next instance digest")

    def to_object(self) -> dict[str, object]:
        return {
            "classification": self.classification.value,
            "instance_count": self.instance_count,
            "instance_digest": self.instance_digest,
            "playbook": self.playbook,
            "status": self.status.value,
            "target_count": self.target_count,
            "target_role": self.target_role,
            "target_set_digest": self.target_set_digest,
        }


@dataclass(frozen=True, slots=True)
class DeployPostFinalRoutesReconciliationReport:
    """Strict redacted post-final-routes reconciliation projection."""

    operation_id: uuid.UUID
    artifact_state: DeployFinalRoutesArtifactState
    reconciliation_artifact_digest: str
    reconciliation_record_digest: str
    effective_plan_digest: str
    jump_count: int
    jump_set_digest: str
    destination_pair_count: int
    destination_pair_set_digest: str
    succeeded_count: int
    authorization_required_count: int
    eligible_count: int
    blocked_count: int
    not_performed_count: int
    next_steps: tuple[DeployPostFinalRoutesNextStepSummary, ...]
    next_step_count: int
    next_target_count: int
    next_target_set_digest: str
    blocker_set: tuple[str, ...]
    blocker_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    finalization_state: str
    public_workflow_state: str
    reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_REPORT_SCHEMA_VERSION
            or self.reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION
            or self.jump_count < 1
            or self.destination_pair_count < 1
            or self.next_step_count
            != sum(item.instance_count for item in self.next_steps)
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or self.blocker_digest != _digest_object(list(self.blocker_set))
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
        ):
            raise StatePersistenceError(
                "post-final-routes reconciliation report is invalid"
            )
        for value in (
            self.reconciliation_artifact_digest,
            self.reconciliation_record_digest,
            self.effective_plan_digest,
            self.jump_set_digest,
            self.destination_pair_set_digest,
            self.next_target_set_digest,
            self.blocker_digest,
        ):
            validate_digest(value, "post-final-routes report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "artifact_state": self.artifact_state.value,
            "blockers": {
                "digest": self.blocker_digest,
                "values": list(self.blocker_set),
            },
            "final_routes": {
                "destination_pair_count": self.destination_pair_count,
                "destination_pair_set_digest": self.destination_pair_set_digest,
                "jump_count": self.jump_count,
                "jump_set_digest": self.jump_set_digest,
                "status": "succeeded",
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "next": {
                "step_count": self.next_step_count,
                "steps": [item.to_object() for item in self.next_steps],
                "target_count": self.next_target_count,
                "target_set_digest": self.next_target_set_digest,
            },
            "operation_id": str(self.operation_id),
            "provenance": {
                "effective_plan_digest": self.effective_plan_digest,
                "reconciliation_artifact_digest": self.reconciliation_artifact_digest,
                "reconciliation_record_digest": self.reconciliation_record_digest,
            },
            "schema_version": self.schema_version,
            "schemas": {"reconciliation": self.reconciliation_schema_version},
            "states": {
                "finalization": self.finalization_state,
                "public_workflow": self.public_workflow_state,
            },
            "steps": {
                "authorization_required_count": self.authorization_required_count,
                "blocked_count": self.blocked_count,
                "eligible_count": self.eligible_count,
                "not_performed_count": self.not_performed_count,
                "succeeded_count": self.succeeded_count,
            },
        }


def reconcile_deploy_final_routes_connectivity(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployPostFinalRoutesReconciliationReport:
    """Persist immutable final-routes success and only its immediate next gate."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _refuse_ambiguous_artifacts(paths, operation_id)
    post = _load_post_jump_context(paths, operation_id, lock=lock)
    metadata = post.post.base.host.loaded.planning.base.deploy.metadata.record
    execution_store = DeployFinalRoutesExecutionStore(paths, operation_id)
    evidence_store = DeployFinalRoutesEvidenceStore(paths, operation_id)
    for path, label in (
        (execution_store.path, "execution"),
        (evidence_store.path, "evidence"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"post-final-routes reconciliation requires complete {label}"
            )
    execution = execution_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    evidence = evidence_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    context = _load_final_routes_context(
        paths,
        operation_id,
        lock=lock,
        toolchain_version=execution.record.binding.toolchain_version,
        executable_identity_digest=(
            execution.record.binding.executable_identity_digest
        ),
        toolchain_evidence_digest=(execution.record.binding.toolchain_evidence_digest),
    )
    _validate_execution_prefix(context, execution, evidence)
    if (
        execution.record.state is not DeployFinalRoutesExecutionState.SUCCEEDED
        or not evidence.record.successful
    ):
        raise StateConflictError(
            "post-final-routes reconciliation requires certain successful execution"
        )
    steps = _build_reconciled_steps(context, evidence)
    store = DeployPostFinalRoutesReconciliationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    existing = (
        store.read_locked(
            lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
        )
        if store.path.exists()
        else None
    )
    created_at = existing.record.created_at if existing is not None else _timestamp()
    record = _build_reconciliation_record(
        context,
        execution,
        evidence,
        steps=steps,
        created_at=created_at,
    )
    if existing is not None and existing.record != record:
        raise StateConflictError(
            "post-final-routes reconciliation is immutable; use a new operation"
        )
    try:
        stored, state = store.write_locked(record, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "post-final-routes reconciliation persistence failed"
        ) from error
    return _build_reconciliation_report(stored, state=state)


def deploy_post_final_routes_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "post-final-routes reconciliation path is not canonical"
        )
    return path


def deploy_post_final_routes_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(
        name, DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_FILENAME_SUFFIX
    )


def _build_reconciled_steps(
    context: _FinalRoutesContext,
    evidence: StoredDeployFinalRoutesEvidence,
) -> tuple[DeployBaseOsReconciledStep, ...]:
    prior_steps = context.reconciliation.record.steps
    remaining_mappings = tuple(
        sorted(
            {
                step.mapping_sequence
                for step in prior_steps
                if step.mapping_sequence > _MAPPING_SEQUENCE
                and step.mapping_sequence != _FINAL_EVIDENCE_MAPPING
                and step.condition_state is DeployConditionState.ACTIVE
                and step.status is not DeployBaseOsReconciledStepStatus.SUCCEEDED
            }
        )
    )
    next_mapping = remaining_mappings[0] if remaining_mappings else None
    result: list[DeployBaseOsReconciledStep] = []
    for prior in prior_steps:
        prior_digest = _digest_object(prior.to_object())
        if prior.mapping_sequence == _MAPPING_SEQUENCE:
            if (
                prior.playbook != _PLAYBOOK
                or prior.condition != _CONDITION
                or prior.status is not DeployBaseOsReconciledStepStatus.ELIGIBLE
                or prior.sequence != context.scope.step.sequence
            ):
                raise StateConflictError(
                    "post-final-routes executed step identity drifted"
                )
            result.append(
                replace(
                    prior,
                    prior_reconciled_step_digest=prior_digest,
                    status=DeployBaseOsReconciledStepStatus.SUCCEEDED,
                    evidence_state=(
                        DeployBaseOsReconciledEvidenceState.FINAL_ROUTES_CONNECTIVITY_BOUND
                    ),
                    evidence_digest=evidence.record.evidence_digest,
                    blockers=(),
                )
            )
            continue
        if (
            prior.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
            or prior.condition_state is DeployConditionState.INACTIVE
        ):
            result.append(replace(prior, prior_reconciled_step_digest=prior_digest))
            continue
        if prior.mapping_sequence == _FINAL_EVIDENCE_MAPPING:
            result.append(
                replace(
                    prior,
                    prior_reconciled_step_digest=prior_digest,
                    status=DeployBaseOsReconciledStepStatus.NOT_PERFORMED,
                    evidence_state=DeployBaseOsReconciledEvidenceState.NOT_PERFORMED,
                    evidence_digest=None,
                    blockers=tuple(sorted({*prior.blockers, _ORDER_BLOCKER})),
                )
            )
            continue
        if prior.mapping_sequence == next_mapping and _post_jump_next_gate_ready(
            prior, context.post
        ):
            status = (
                DeployBaseOsReconciledStepStatus.ELIGIBLE
                if prior.classification is OperationClassification.READ_ONLY
                else DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            )
            blockers = (
                ()
                if prior.classification is OperationClassification.READ_ONLY
                else tuple(
                    sorted(
                        {
                            _AUTHORIZATION_BLOCKER,
                            _CLASS_BLOCKERS[prior.classification],
                            _PUBLIC_WORKFLOW_BLOCKER,
                        }
                    )
                )
            )
            result.append(
                replace(
                    prior,
                    prior_reconciled_step_digest=prior_digest,
                    status=status,
                    evidence_state=(
                        DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED
                    ),
                    evidence_digest=_next_gate_digest(prior, context, evidence),
                    blockers=blockers,
                )
            )
            continue
        result.append(
            replace(
                prior,
                prior_reconciled_step_digest=prior_digest,
                status=(
                    DeployBaseOsReconciledStepStatus.NOT_PERFORMED
                    if prior.classification is OperationClassification.READ_ONLY
                    else DeployBaseOsReconciledStepStatus.BLOCKED
                ),
                evidence_state=DeployBaseOsReconciledEvidenceState.NOT_PERFORMED,
                evidence_digest=None,
                blockers=tuple(sorted({*prior.blockers, _ORDER_BLOCKER})),
            )
        )
    return tuple(result)


def _next_gate_digest(
    step: DeployBaseOsReconciledStep,
    context: _FinalRoutesContext,
    evidence: StoredDeployFinalRoutesEvidence,
) -> str:
    planning = context.post.post.base.host.loaded.planning
    return _digest_object(
        {
            "evidence_artifact_digest": evidence.artifact_digest,
            "evidence_digest": evidence.record.evidence_digest,
            "inventory_artifact_digest": planning.base.deploy.inventory.digest,
            "playbook": step.playbook,
            "readiness_record_digest": planning.readiness.record.record_digest,
            "sequence": step.sequence,
            "target_digest": step.target_digest,
            "trust_artifact_digest": planning.base.trust.digest,
        }
    )


def _build_reconciliation_record(
    context: _FinalRoutesContext,
    execution: StoredDeployFinalRoutesExecution,
    evidence: StoredDeployFinalRoutesEvidence,
    *,
    steps: tuple[DeployBaseOsReconciledStep, ...],
    created_at: str,
) -> DeployPostFinalRoutesReconciliation:
    binding = execution.record.binding
    counts = Counter(step.status for step in steps)
    blockers = tuple(sorted({item for step in steps for item in step.blockers}))
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": binding.cluster_uuid,
        "cluster_name": binding.cluster_name,
        "operation_id": binding.operation_id,
        "operation": binding.operation,
        "request_digest": binding.request_digest,
        "journal_generation": binding.journal_generation,
        "journal_digest": binding.journal_digest,
        "journal_status": binding.journal_status,
        "journal_phase": binding.journal_phase,
        "post_jump_artifact_digest": binding.post_jump_artifact_digest,
        "post_jump_record_digest": binding.post_jump_record_digest,
        "post_jump_effective_plan_digest": binding.post_jump_effective_plan_digest,
        "execution_artifact_digest": execution.artifact_digest,
        "execution_binding_digest": binding.binding_digest,
        "evidence_artifact_digest": evidence.artifact_digest,
        "evidence_digest": evidence.record.evidence_digest,
        "jump_count": binding.jump_count,
        "jump_set_digest": binding.jump_set_digest,
        "destination_pair_count": binding.destination_pair_count,
        "destination_pair_set_digest": binding.destination_pair_set_digest,
        "steps": steps,
        "step_count": len(steps),
        "succeeded_count": counts[DeployBaseOsReconciledStepStatus.SUCCEEDED],
        "authorization_required_count": counts[
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        ],
        "eligible_count": counts[DeployBaseOsReconciledStepStatus.ELIGIBLE],
        "blocked_count": counts[DeployBaseOsReconciledStepStatus.BLOCKED],
        "not_performed_count": counts[DeployBaseOsReconciledStepStatus.NOT_PERFORMED],
        "blocker_set": blockers,
        "blocker_digest": _digest_object(list(blockers)),
        "effective_plan_digest": _digest_object([step.to_object() for step in steps]),
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "record_digest": "",
    }
    values["record_digest"] = _reconciliation_record_digest_from_values(values)
    return DeployPostFinalRoutesReconciliation(**values)  # type: ignore[arg-type]


def _build_reconciliation_report(
    stored: StoredDeployPostFinalRoutesReconciliation,
    *,
    state: DeployFinalRoutesArtifactState,
) -> DeployPostFinalRoutesReconciliationReport:
    record = stored.record
    selected = tuple(
        step
        for step in record.steps
        if step.status
        in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
    )
    grouped: dict[
        tuple[
            str,
            str,
            OperationClassification,
            DeployBaseOsReconciledStepStatus,
        ],
        list[DeployBaseOsReconciledStep],
    ] = {}
    for step in selected:
        grouped.setdefault(
            (step.playbook, step.target_role, step.classification, step.status), []
        ).append(step)
    summaries: list[DeployPostFinalRoutesNextStepSummary] = []
    for (playbook, role, classification, status), steps in sorted(
        grouped.items(),
        key=lambda item: (
            item[0][0],
            item[0][1],
            item[0][2].value,
            item[0][3].value,
        ),
    ):
        targets = tuple(sorted({item for step in steps for item in step.target_ids}))
        summaries.append(
            DeployPostFinalRoutesNextStepSummary(
                playbook,
                role,
                classification,
                status,
                len(steps),
                len(targets),
                _digest_object(list(targets)),
                _digest_object(
                    [
                        {
                            "evidence_digest": step.evidence_digest,
                            "sequence": step.sequence,
                            "target_digest": step.target_digest,
                        }
                        for step in steps
                    ]
                ),
            )
        )
    target_ids = tuple(
        sorted({target for step in selected for target in step.target_ids})
    )
    return DeployPostFinalRoutesReconciliationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        reconciliation_artifact_digest=stored.artifact_digest,
        reconciliation_record_digest=record.record_digest,
        effective_plan_digest=record.effective_plan_digest,
        jump_count=record.jump_count,
        jump_set_digest=record.jump_set_digest,
        destination_pair_count=record.destination_pair_count,
        destination_pair_set_digest=record.destination_pair_set_digest,
        succeeded_count=record.succeeded_count,
        authorization_required_count=record.authorization_required_count,
        eligible_count=record.eligible_count,
        blocked_count=record.blocked_count,
        not_performed_count=record.not_performed_count,
        next_steps=tuple(summaries),
        next_step_count=len(selected),
        next_target_count=len(target_ids),
        next_target_set_digest=_digest_object(list(target_ids)),
        blocker_set=record.blocker_set,
        blocker_digest=record.blocker_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        finalization_state=record.finalization_state,
        public_workflow_state=record.public_workflow_state,
    )


def _full_chain_digest(
    post: _PostJumpHostContext,
    reconciliation: StoredDeployPostJumpHostConfigureReconciliation,
) -> str:
    loaded = post.post.base.host.loaded
    planning = loaded.planning
    return _digest_object(
        {
            "catalog_digest": loaded.catalog_digest,
            "context_artifact_digest": loaded.context.artifact_digest,
            "effective_plan_artifact_digest": (
                post.post.base.host.prior_effective.artifact_digest
            ),
            "host_reconciliation_artifact_digest": (
                post.post.base.prior.artifact_digest
            ),
            "jump_authorization_artifact_digest": post.authorization.artifact_digest,
            "jump_evidence_artifact_digest": post.evidence.artifact_digest,
            "jump_execution_artifact_digest": post.execution.artifact_digest,
            "original_plan_artifact_digest": loaded.plan.artifact_digest,
            "post_jump_artifact_digest": reconciliation.artifact_digest,
            "post_reboot_artifact_digest": post.post_reconciliation.artifact_digest,
            "prerequisite_evidence_artifact_digest": loaded.evidence.artifact_digest,
            "prerequisite_execution_artifact_digest": loaded.execution.artifact_digest,
            "readiness_artifact_digest": planning.readiness.artifact_digest,
            "source_digest": loaded.source.digest,
        }
    )


def _result_digest(
    hosts: tuple[DeployFinalRoutesHostEvidence, ...],
    pairs: tuple[DeployFinalRoutesPairEvidence, ...],
    status: ConnectivityStatus,
) -> str:
    return _digest_object(
        {
            "hosts": [item.to_object() for item in hosts],
            "pairs": [item.to_object() for item in pairs],
            "status": status.value,
        }
    )


def _evidence_digest(
    binding: DeployFinalRoutesExecutionBinding,
    result_digest: str,
    status: ConnectivityStatus,
) -> str:
    return _digest_object(
        {
            "command_digest": binding.command_digest,
            "destination_pair_set_digest": binding.destination_pair_set_digest,
            "jump_set_digest": binding.jump_set_digest,
            "playbook_source_digest": binding.playbook_source_digest,
            "result_digest": result_digest,
            "route_request_digest": binding.route_request_digest,
            "status": status.value,
            "step_digest": binding.step_digest,
        }
    )


def _failure_state(error: AnsibleError) -> DeployFinalRoutesExecutionState:
    if isinstance(error, AnsibleResultError):
        return DeployFinalRoutesExecutionState.MALFORMED_RESULT
    cause = error.__cause__
    if isinstance(cause, ProcessTimeoutError):
        return DeployFinalRoutesExecutionState.TIMED_OUT
    if isinstance(cause, ProcessOutputError):
        return DeployFinalRoutesExecutionState.MALFORMED_RESULT
    return DeployFinalRoutesExecutionState.FAILED


def _binding_digests(
    binding: DeployFinalRoutesExecutionBinding,
) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(binding, name))
        for name in binding.__dataclass_fields__
        if name.endswith("_digest")
    )


def _binding_digest(binding: DeployFinalRoutesExecutionBinding) -> str:
    value = binding.to_object()
    value["binding_digest"] = ""
    return _digest_object(value)


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployFinalRoutesExecutionBinding.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(item, (JournalStatus, OperationPhase))
            else item
        )
    value["binding_digest"] = ""
    return _digest_object(value)


def _reconciliation_digests(
    record: DeployPostFinalRoutesReconciliation,
) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(record, name))
        for name in record.__dataclass_fields__
        if name.endswith("_digest")
    )


def _reconciliation_record_digest(
    record: DeployPostFinalRoutesReconciliation,
) -> str:
    value = record.to_object()
    value["record_digest"] = ""
    return _digest_object(value)


def _reconciliation_record_digest_from_values(
    values: Mapping[str, object],
) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployPostFinalRoutesReconciliation.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(item, (JournalStatus, OperationPhase))
            else [step.to_object() for step in item]
            if name == "steps" and isinstance(item, tuple)
            else list(item)
            if name == "blocker_set" and isinstance(item, tuple)
            else item
        )
    value["record_digest"] = ""
    return _digest_object(value)


def _timestamp() -> str:
    return format_timestamp(datetime.now(UTC))


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError("final-routes paths are not canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError("final-routes execution requires an acquired deploy lock")
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list final-routes artifacts"
        ) from error
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_FINAL_ROUTES_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_FINAL_ROUTES_EVIDENCE_FILENAME_SUFFIX,
        DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_FILENAME_SUFFIX,
    )
    for entry in entries:
        suffix = next(
            (candidate for candidate in suffixes if entry.name.endswith(candidate)),
            None,
        )
        if suffix is None:
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
            raise StateConflictError("final-routes artifacts are ambiguous")


def _id_from_filename(name: str, suffix: str) -> uuid.UUID | None:
    if not name.endswith(suffix):
        return None
    value = name[: -len(suffix)]
    try:
        identifier = uuid.UUID(value)
    except ValueError:
        return None
    return identifier if str(identifier) == value else None


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


def _optional_integer(value: object, label: str) -> int | None:
    if value is None:
        return None
    return _integer(value, label)


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise StatePersistenceError(f"{label} must be a string or null")
    return value


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise StatePersistenceError(f"{label} must be a string array")
    return tuple(value)


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise StatePersistenceError(f"{label} must be an array")
    return value


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _enum(enum_type: type[StrEnum], value: str, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except ValueError as error:
        raise StatePersistenceError(f"{label} is invalid") from error


__all__ = [
    "ANSIBLE_DEPLOY_FINAL_ROUTES_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_BINDING_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION",
    "DEPLOY_FINAL_ROUTES_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_FINAL_ROUTES_EXECUTION_FILENAME_SUFFIX",
    "DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_FILENAME_SUFFIX",
    "DeployFinalRoutesArtifactState",
    "DeployFinalRoutesEvidence",
    "DeployFinalRoutesEvidenceStore",
    "DeployFinalRoutesExecution",
    "DeployFinalRoutesExecutionBinding",
    "DeployFinalRoutesExecutionReport",
    "DeployFinalRoutesExecutionState",
    "DeployFinalRoutesExecutionStore",
    "DeployFinalRoutesHostEvidence",
    "DeployFinalRoutesPairEvidence",
    "DeployPostFinalRoutesNextStepSummary",
    "DeployPostFinalRoutesReconciliation",
    "DeployPostFinalRoutesReconciliationReport",
    "DeployPostFinalRoutesReconciliationStore",
    "StoredDeployFinalRoutesEvidence",
    "StoredDeployFinalRoutesExecution",
    "StoredDeployPostFinalRoutesReconciliation",
    "deploy_final_routes_evidence_id_from_filename",
    "deploy_final_routes_evidence_path",
    "deploy_final_routes_execution_id_from_filename",
    "deploy_final_routes_execution_path",
    "deploy_post_final_routes_reconciliation_id_from_filename",
    "deploy_post_final_routes_reconciliation_path",
    "execute_deploy_final_routes_connectivity",
    "reconcile_deploy_final_routes_connectivity",
]
