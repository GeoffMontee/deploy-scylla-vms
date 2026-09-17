"""Durable execution ownership for the authorized first Scylla join.

This internal owner revalidates the exact initial-seed, current-health,
join-safety, and first-join authorization chain.  It derives sequence two from
canonical state, records prepared and started intent before the sole controlled
call, and persists only address-free semantic evidence.  It never advances the
common journal or authorizes a later join.
"""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.commands import AnsibleCommandBuilder
from scylla_vms.ansible.deploy_plan import (
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import _loaded
from scylla_vms.ansible.deploy_scylla_configure_reconciliation import (
    _load_reconciliation_context,
)
from scylla_vms.ansible.deploy_scylla_join_authorization import (
    ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_SCHEMA_VERSION,
    DeployScyllaJoinAuthorizationStore,
    StoredDeployScyllaJoinAuthorization,
    _build_authorization,
    _derive_first_join_scope,
    _load_join_authorization_context,
)
from scylla_vms.ansible.deploy_scylla_join_safety import (
    ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION,
)
from scylla_vms.ansible.operation_binding import readiness_binding_digest
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_bootstrap import (
    SCYLLA_BOOTSTRAP_SCHEMA_VERSION,
    MutationBoundary,
    ScyllaBootstrapEvidence,
    ScyllaBootstrapMode,
    ScyllaBootstrapStatus,
    parse_scylla_bootstrap_execution,
)
from scylla_vms.ansible.scylla_install import (
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_RELEASE_LINE,
)
from scylla_vms.ansible.service import (
    AnsibleExecutionResult,
    AnsibleResultError,
    AnsibleService,
    ProcessRunnerProtocol,
)
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION
from scylla_vms.ansible.toolchain import (
    AnsibleToolchain,
    AnsibleVersionError,
    parse_ansible_core_version,
)
from scylla_vms.desired import HostRole
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.journal import JOURNAL_SCHEMA_VERSION, JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import (
    AtomicJsonFile,
    ClusterMetadata,
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

ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-execution-binding/v1"
)
ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-execution/v1"
)
ANSIBLE_DEPLOY_SCYLLA_JOIN_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-evidence/v1"
)
ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-join-execution-report/v1"
)

DEPLOY_SCYLLA_JOIN_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-join-execution.json"
)
DEPLOY_SCYLLA_JOIN_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-join-evidence.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "scylla-bootstrap"
_STAGE = "first-join-existing-execution"
_SCOPE_KIND = "authorized-reconciled-sequence-two"
_BOOTSTRAP_TIMEOUT_SECONDS = 7200
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SUCCESS_BLOCKERS: tuple[str, ...] = ()
_NEVER_JOINED_BLOCKERS = ("execution-failed",)
_MAY_HAVE_JOINED_BLOCKERS = ("join-incomplete",)


class DeployScyllaJoinExecutionState(StrEnum):
    PREPARED = "prepared"
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"


class DeployScyllaJoinArtifactState(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployScyllaJoinExecutionBinding:
    """Value-free binding for one exact sequence-two execution."""

    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    bootstrap_context_artifact_digest: str
    bootstrap_context_record_digest: str
    bootstrap_plan_artifact_digest: str
    bootstrap_plan_digest: str
    initial_execution_artifact_digest: str
    initial_evidence_artifact_digest: str
    initial_evidence_digest: str
    health_execution_artifact_digest: str
    health_evidence_artifact_digest: str
    health_evidence_digest: str
    health_checkpoint_artifact_digest: str
    health_checkpoint_digest: str
    safety_context_artifact_digest: str
    safety_context_digest: str
    safety_evidence_artifact_digest: str
    safety_evidence_digest: str
    safety_reconciliation_artifact_digest: str
    safety_reconciliation_digest: str
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_scope_digest: str
    authorization_proof_digest: str
    validated_chain_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    catalog_digest: str
    source_version: str
    source_digest: str
    playbook_source_digest: str
    toolchain_version: str
    executable_identity_digest: str
    toolchain_evidence_digest: str
    observation_generation: int
    observation_artifact_digest: str
    observation_manifest_digest: str
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    trust_generation: int
    trust_artifact_digest: str
    trust_entries_digest: str
    sequence: int
    target_digest: str
    plan_step_digest: str
    preceding_step_digest: str
    health_checkpoint_step_digest: str
    join_safety_step_digest: str
    survivor_count: int
    survivor_set_digest: str
    survivor_health_digest: str
    active_seed_count: int
    active_seed_set_digest: str
    topology_digest: str
    target_topology_digest: str
    schema_digest: str
    membership_digest: str
    seed_policy_digest: str
    package_version_digest: str
    storage_evidence_digest: str
    configuration_evidence_digest: str
    capacity_evidence_digest: str
    prerequisite_digest: str
    variables_digest: str
    command_digest: str
    execution_scope_digest: str
    later_join_count: int
    later_join_digest: str
    binding_digest: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_SCHEMA_VERSION
    )
    safety_context_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
    )
    safety_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
    )
    safety_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_BINDING_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_AUTHORIZATION_SCHEMA_VERSION
            or self.safety_context_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_CONTEXT_SCHEMA_VERSION
            or self.safety_evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_EVIDENCE_SCHEMA_VERSION
            or self.safety_reconciliation_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_SAFETY_RECONCILIATION_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.sequence != 2
            or self.survivor_count < 1
            or self.active_seed_count < 1
            or self.active_seed_count > self.survivor_count
            or self.later_join_count < 0
            or self.binding_digest != _binding_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla first-join execution binding conflicts"
            )
        validate_cluster_name(self.cluster_name)
        for value in (
            self.journal_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
        ):
            _positive_integer(value, "first-join binding generation")
        for digest in _digest_fields(self):
            if digest is None:
                raise StatePersistenceError(
                    "deploy Scylla first-join binding digest is missing"
                )
            validate_digest(digest, "first-join binding digest")
        _validate_toolchain_version(self.toolchain_version)

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaJoinExecutionBinding:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={
                "journal_generation",
                "observation_generation",
                "inventory_generation",
                "trust_generation",
                "sequence",
                "survivor_count",
                "active_seed_count",
                "later_join_count",
            },
            uuid_fields={"cluster_uuid", "operation_id"},
            enum_fields={
                "journal_status": JournalStatus,
                "journal_phase": OperationPhase,
            },
            label="first-join execution binding",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaJoinExecution:
    """Generation-guarded at-most-once state."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployScyllaJoinExecutionBinding
    state: DeployScyllaJoinExecutionState
    stable_id: str
    mode: ScyllaBootstrapMode
    prepared_at: str
    started_at: str | None
    completed_at: str | None
    ordinary_authorization_consumed: bool
    narrow_authorization_consumed: bool
    invocation_count: int
    invocation_may_have_occurred: bool
    completed: bool
    exit_code: int | None
    result_digest: str | None
    evidence_digest: str | None
    mutation_boundary: MutationBoundary | None
    membership_may_have_changed: bool | None
    node_preserved: bool | None
    remask_performed: bool | None
    manual_recovery_required: bool
    automatic_retry_allowed: bool = False
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_SCHEMA_VERSION
            or self.generation < 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError("deploy Scylla first-join execution conflicts")
        prepared = parse_timestamp(self.prepared_at)
        created = parse_timestamp(self.created_at)
        updated = parse_timestamp(self.updated_at)
        started = _optional_timestamp(self.started_at)
        completed_at = _optional_timestamp(self.completed_at)
        if (
            prepared < created
            or updated < created
            or (started is not None and started < prepared)
            or (completed_at is not None and started is None)
            or (
                completed_at is not None
                and started is not None
                and completed_at < started
            )
        ):
            raise StatePersistenceError(
                "deploy Scylla first-join execution timestamps conflict"
            )
        consumed = (
            self.ordinary_authorization_consumed and self.narrow_authorization_consumed
        )
        no_result = (
            self.exit_code is None
            and self.result_digest is None
            and self.evidence_digest is None
            and self.mutation_boundary is None
            and self.membership_may_have_changed is None
            and self.node_preserved is None
            and self.remask_performed is None
        )
        if self.state is DeployScyllaJoinExecutionState.PREPARED:
            valid = (
                self.invocation_count == 0
                and not self.invocation_may_have_occurred
                and not consumed
                and not self.ordinary_authorization_consumed
                and not self.narrow_authorization_consumed
                and started is None
                and completed_at is None
                and not self.completed
                and no_result
                and not self.manual_recovery_required
            )
        elif self.state is DeployScyllaJoinExecutionState.STARTED:
            valid = (
                self.invocation_count == 1
                and self.invocation_may_have_occurred
                and consumed
                and started is not None
                and completed_at is None
                and not self.completed
                and no_result
                and self.manual_recovery_required
            )
        elif self.state is DeployScyllaJoinExecutionState.SUCCEEDED:
            valid = (
                self.invocation_count == 1
                and self.invocation_may_have_occurred
                and consumed
                and started is not None
                and completed_at is not None
                and self.completed
                and self.exit_code == 0
                and self.result_digest is not None
                and self.evidence_digest is not None
                and self.mutation_boundary
                is MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED
                and self.membership_may_have_changed is True
                and self.node_preserved is True
                and self.remask_performed is False
                and not self.manual_recovery_required
            )
        elif self.state is DeployScyllaJoinExecutionState.FAILED:
            valid = (
                self.invocation_count == 1
                and self.invocation_may_have_occurred
                and consumed
                and started is not None
                and completed_at is not None
                and self.completed
                and self.exit_code is not None
                and self.result_digest is not None
                and self.evidence_digest is not None
                and self.mutation_boundary
                in {
                    MutationBoundary.SERVICE_UNMASKED_STARTED,
                    MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED,
                }
                and self.membership_may_have_changed
                == (
                    self.mutation_boundary
                    is MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED
                )
                and self.node_preserved is True
                and self.remask_performed
                == (self.mutation_boundary is MutationBoundary.SERVICE_UNMASKED_STARTED)
                and self.manual_recovery_required
            )
        else:
            valid = (
                self.invocation_count == 1
                and self.invocation_may_have_occurred
                and consumed
                and started is not None
                and completed_at is not None
                and not self.completed
                and no_result
                and self.manual_recovery_required
            )
        if not valid:
            raise StatePersistenceError(
                "deploy Scylla first-join execution state conflicts"
            )
        for value in (self.result_digest, self.evidence_digest):
            if value is not None:
                validate_digest(value, "first-join execution digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, nested_fields={"binding"})

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaJoinExecution:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={"generation", "invocation_count"},
            boolean_fields={
                "ordinary_authorization_consumed",
                "narrow_authorization_consumed",
                "invocation_may_have_occurred",
                "completed",
                "manual_recovery_required",
                "automatic_retry_allowed",
            },
            enum_fields={
                "state": DeployScyllaJoinExecutionState,
                "mode": ScyllaBootstrapMode,
            },
            optional_string_fields={
                "started_at",
                "completed_at",
                "result_digest",
                "evidence_digest",
            },
            optional_integer_fields={"exit_code"},
            optional_boolean_fields={
                "membership_may_have_changed",
                "node_preserved",
                "remask_performed",
            },
            skip_fields={"binding", "mutation_boundary"},
            label="first-join execution",
        )
        parsed["binding"] = DeployScyllaJoinExecutionBinding.from_object(
            _mapping(value["binding"], "first-join binding")
        )
        boundary = _optional_string(value["mutation_boundary"], "mutation boundary")
        try:
            parsed["mutation_boundary"] = (
                None if boundary is None else MutationBoundary(boundary)
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Scylla first-join mutation boundary is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaJoinEvidence:
    """Immutable address-free semantic evidence for sequence two."""

    generation: int
    created_at: str
    binding: DeployScyllaJoinExecutionBinding
    stable_id: str
    sequence: int
    mode: ScyllaBootstrapMode
    status: ScyllaBootstrapStatus
    datacenter_digest: str
    rack_digest: str
    topology_digest: str
    package_version_digest: str
    prerequisite_digest: str
    survivor_count: int
    survivor_set_digest: str
    active_seed_count: int
    active_seed_set_digest: str
    prior_membership_digest: str
    prior_schema_digest: str
    host_id_digest: str | None
    ring_membership_digest: str | None
    blocker_count: int
    blocker_digest: str
    prerequisite_revalidated: bool
    target_absence_revalidated: bool
    survivor_health_revalidated: bool
    seed_health_revalidated: bool
    capacity_revalidated: bool
    topology_revalidated: bool
    service_active: bool
    cql_ready: bool
    nodetool_membership_verified: bool
    schema_agreement: bool
    streaming_complete: bool
    never_joined_proven: bool
    membership_may_have_changed: bool
    remask_performed: bool
    node_preserved: bool
    recovery_required: bool
    automatic_retry_allowed: bool
    mutation_boundary: MutationBoundary
    variables_digest: str
    command_digest: str
    source_digest: str
    result_digest: str
    evidence_digest: str
    result_schema_version: str = SCYLLA_BOOTSTRAP_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        success = self.status is ScyllaBootstrapStatus.BOOTSTRAPPED
        never_joined = (
            self.status is ScyllaBootstrapStatus.FAILED
            and self.mutation_boundary is MutationBoundary.SERVICE_UNMASKED_STARTED
        )
        may_have_joined = (
            self.mutation_boundary is MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED
        )
        if (
            self.schema_version != ANSIBLE_DEPLOY_SCYLLA_JOIN_EVIDENCE_SCHEMA_VERSION
            or self.result_schema_version != SCYLLA_BOOTSTRAP_SCHEMA_VERSION
            or self.sequence != 2
            or self.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or self.status is ScyllaBootstrapStatus.NOT_PREDICTED
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.survivor_count < 1
            or self.active_seed_count < 1
            or self.active_seed_count > self.survivor_count
            or self.blocker_count < 0
            or not all(
                (
                    self.prerequisite_revalidated,
                    self.target_absence_revalidated,
                    self.survivor_health_revalidated,
                    self.seed_health_revalidated,
                    self.capacity_revalidated,
                    self.topology_revalidated,
                )
            )
            or self.never_joined_proven != never_joined
            or self.membership_may_have_changed != may_have_joined
            or self.remask_performed != never_joined
            or not self.node_preserved
            or self.recovery_required != (not success)
            or self.automatic_retry_allowed
            or self.evidence_digest != _evidence_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla first-join semantic evidence conflicts"
            )
        if success:
            valid = (
                self.host_id_digest is not None
                and self.ring_membership_digest is not None
                and self.blocker_count == 0
                and self.service_active
                and self.cql_ready
                and self.nodetool_membership_verified
                and self.schema_agreement
                and self.streaming_complete
                and not self.remask_performed
            )
        elif never_joined:
            valid = (
                self.host_id_digest is None
                and self.blocker_count == 1
                and not self.service_active
                and not self.cql_ready
                and not self.nodetool_membership_verified
                and not self.schema_agreement
                and not self.streaming_complete
            )
        else:
            valid = (
                self.status is ScyllaBootstrapStatus.FAILED
                and self.host_id_digest is None
                and self.ring_membership_digest is not None
                and self.blocker_count == 1
                and not self.service_active
                and not self.cql_ready
                and not self.nodetool_membership_verified
                and not self.schema_agreement
                and not self.streaming_complete
                and not self.remask_performed
            )
        if not valid:
            raise StatePersistenceError(
                "deploy Scylla first-join result semantics conflict"
            )
        parse_timestamp(self.created_at)
        for value in _digest_fields(self):
            if value is not None:
                validate_digest(value, "first-join evidence digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, nested_fields={"binding"})

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaJoinEvidence:
        parsed = _parse_dataclass(
            cls,
            value,
            integer_fields={
                "generation",
                "sequence",
                "survivor_count",
                "active_seed_count",
                "blocker_count",
            },
            boolean_fields={
                "prerequisite_revalidated",
                "target_absence_revalidated",
                "survivor_health_revalidated",
                "seed_health_revalidated",
                "capacity_revalidated",
                "topology_revalidated",
                "service_active",
                "cql_ready",
                "nodetool_membership_verified",
                "schema_agreement",
                "streaming_complete",
                "never_joined_proven",
                "membership_may_have_changed",
                "remask_performed",
                "node_preserved",
                "recovery_required",
                "automatic_retry_allowed",
            },
            enum_fields={
                "mode": ScyllaBootstrapMode,
                "status": ScyllaBootstrapStatus,
                "mutation_boundary": MutationBoundary,
            },
            optional_string_fields={"host_id_digest", "ring_membership_digest"},
            skip_fields={"binding"},
            label="first-join evidence",
        )
        parsed["binding"] = DeployScyllaJoinExecutionBinding.from_object(
            _mapping(value["binding"], "first-join evidence binding")
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaJoinExecution:
    record: DeployScyllaJoinExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaJoinEvidence:
    record: DeployScyllaJoinEvidence
    artifact_digest: str


class DeployScyllaJoinExecutionStore:
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
        self._path = deploy_scylla_join_execution_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaJoinExecution:
        value, artifact_digest = self._file.read()
        record = DeployScyllaJoinExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy Scylla first-join execution identity conflicts"
            )
        return StoredDeployScyllaJoinExecution(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaJoinExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaJoinExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployScyllaJoinExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy Scylla first-join execution operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if (
                expected_digest is None
                or current.artifact_digest != expected_digest
                or current.record.generation != expected_generation
            ):
                raise StatePersistenceError(
                    "deploy Scylla first-join execution changed concurrently"
                )
            _validate_execution_transition(current.record, record)
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
            or record.state is not DeployScyllaJoinExecutionState.PREPARED
        ):
            raise StatePersistenceError(
                "initial deploy Scylla first-join execution generation conflicts"
            )
        artifact_digest = self._file.write(
            record.to_object(), expected_digest=expected_digest
        )
        return StoredDeployScyllaJoinExecution(record, artifact_digest)


class DeployScyllaJoinEvidenceStore:
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
        self._path = deploy_scylla_join_evidence_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaJoinEvidence:
        value, artifact_digest = self._file.read()
        record = DeployScyllaJoinEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy Scylla first-join evidence identity conflicts"
            )
        return StoredDeployScyllaJoinEvidence(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaJoinEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaJoinEvidence,
        *,
        lock: ClusterLock,
    ) -> tuple[StoredDeployScyllaJoinEvidence, DeployScyllaJoinArtifactState]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy Scylla first-join evidence is immutable"
                )
            return current, DeployScyllaJoinArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaJoinEvidence(record, artifact_digest),
            DeployScyllaJoinArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaJoinExecutionReport:
    operation_id: uuid.UUID
    execution_state: DeployScyllaJoinExecutionState
    execution_artifact_state: DeployScyllaJoinArtifactState
    evidence_artifact_state: DeployScyllaJoinArtifactState
    execution_artifact_digest: str
    evidence_artifact_digest: str
    binding_digest: str
    authorization_artifact_digest: str
    authorization_digest: str
    ordinary_authorization_consumed: bool
    narrow_authorization_consumed: bool
    stage: str
    scope_kind: str
    invocation_count: int
    target_count: int
    target_digest: str
    sequence: int
    mode: ScyllaBootstrapMode
    survivor_count: int
    active_seed_count: int
    later_join_count: int
    bootstrapped_count: int
    host_identity_count: int
    ring_identity_count: int
    prerequisite_revalidated_count: int
    target_absence_revalidated_count: int
    survivor_health_revalidated_count: int
    capacity_revalidated_count: int
    topology_revalidated_count: int
    cql_ready_count: int
    nodetool_verified_count: int
    schema_agreement_count: int
    streaming_complete_count: int
    membership_may_have_changed_count: int
    node_preserved_count: int
    result_digest: str
    evidence_digest: str
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    journal_status: JournalStatus
    journal_phase: OperationPhase
    journal_updated: bool = False
    later_join_state: str = "waiting-for-preceding-complete-health"
    public_workflow_state: str = "unavailable"
    execution_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_SCHEMA_VERSION
    evidence_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_EVIDENCE_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        one_counts = (
            self.invocation_count,
            self.target_count,
            self.bootstrapped_count,
            self.host_identity_count,
            self.ring_identity_count,
            self.prerequisite_revalidated_count,
            self.target_absence_revalidated_count,
            self.survivor_health_revalidated_count,
            self.capacity_revalidated_count,
            self.topology_revalidated_count,
            self.cql_ready_count,
            self.nodetool_verified_count,
            self.schema_agreement_count,
            self.streaming_complete_count,
            self.membership_may_have_changed_count,
            self.node_preserved_count,
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_REPORT_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_JOIN_EVIDENCE_SCHEMA_VERSION
            or self.execution_state is not DeployScyllaJoinExecutionState.SUCCEEDED
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.sequence != 2
            or self.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or any(value != 1 for value in one_counts)
            or self.survivor_count < 1
            or self.active_seed_count < 1
            or not self.ordinary_authorization_consumed
            or not self.narrow_authorization_consumed
            or self.manual_recovery_required
            or self.automatic_retry_allowed
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.journal_updated
            or self.later_join_state != "waiting-for-preceding-complete-health"
            or self.public_workflow_state != "unavailable"
        ):
            raise StatePersistenceError(
                "deploy Scylla first-join execution report conflicts"
            )
        for digest in _digest_fields(self):
            if digest is None:
                raise StatePersistenceError(
                    "deploy Scylla first-join report digest is missing"
                )
            validate_digest(digest, "first-join report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "authorization": {
                "artifact_digest": self.authorization_artifact_digest,
                "digest": self.authorization_digest,
                "narrow_consumed": self.narrow_authorization_consumed,
                "ordinary_consumed": self.ordinary_authorization_consumed,
            },
            "evidence": {
                "artifact_digest": self.evidence_artifact_digest,
                "artifact_state": self.evidence_artifact_state.value,
                "bootstrapped_count": self.bootstrapped_count,
                "capacity_revalidated_count": self.capacity_revalidated_count,
                "cql_ready_count": self.cql_ready_count,
                "digest": self.evidence_digest,
                "host_identity_count": self.host_identity_count,
                "membership_may_have_changed_count": (
                    self.membership_may_have_changed_count
                ),
                "node_preserved_count": self.node_preserved_count,
                "nodetool_verified_count": self.nodetool_verified_count,
                "prerequisite_revalidated_count": (self.prerequisite_revalidated_count),
                "ring_identity_count": self.ring_identity_count,
                "schema_agreement_count": self.schema_agreement_count,
                "schema_version": self.evidence_schema_version,
                "streaming_complete_count": self.streaming_complete_count,
                "survivor_health_revalidated_count": (
                    self.survivor_health_revalidated_count
                ),
                "target_absence_revalidated_count": (
                    self.target_absence_revalidated_count
                ),
                "topology_revalidated_count": self.topology_revalidated_count,
            },
            "execution": {
                "artifact_digest": self.execution_artifact_digest,
                "artifact_state": self.execution_artifact_state.value,
                "automatic_retry_allowed": self.automatic_retry_allowed,
                "binding_digest": self.binding_digest,
                "invocation_count": self.invocation_count,
                "manual_recovery_required": self.manual_recovery_required,
                "result_digest": self.result_digest,
                "schema_version": self.execution_schema_version,
                "state": self.execution_state.value,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": self.journal_updated,
            },
            "later_joins": {
                "count": self.later_join_count,
                "state": self.later_join_state,
            },
            "operation": {
                "id": str(self.operation_id),
                "kind": _OPERATION,
                "public_workflow_state": self.public_workflow_state,
            },
            "schema_version": self.schema_version,
            "scope": {
                "active_seed_count": self.active_seed_count,
                "kind": self.scope_kind,
                "mode": self.mode.value,
                "sequence": self.sequence,
                "survivor_count": self.survivor_count,
                "target_count": self.target_count,
                "target_digest": self.target_digest,
            },
            "stage": self.stage,
        }


@dataclass(frozen=True, slots=True)
class _ExecutionScope:
    stable_id: str
    payload: Mapping[str, object]
    variables: tuple[tuple[str, object], ...]
    variables_digest: str
    command_digest: str
    source_digest: str


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    authorization: StoredDeployScyllaJoinAuthorization
    binding: DeployScyllaJoinExecutionBinding
    scope: _ExecutionScope
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport


def execute_deploy_scylla_first_join(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployScyllaJoinExecutionReport:
    """Execute only the canonical authorized sequence-two join."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _validate_toolchain_dependency(toolchain)
    executable_identity_digest = _executable_identity_digest(executables)
    toolchain_evidence_digest = _toolchain_evidence_digest(
        toolchain, executable_identity_digest
    )
    _refuse_ambiguous_or_later_artifacts(paths, operation_id)
    builder = AnsibleCommandBuilder(executables.playbook, executables.inventory, paths)
    context = _load_execution_context(
        paths,
        operation_id,
        lock=lock,
        builder=builder,
        toolchain=toolchain,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    execution_store = DeployScyllaJoinExecutionStore(paths, operation_id)
    evidence_store = DeployScyllaJoinEvidenceStore(paths, operation_id)
    for path in (execution_store.path, evidence_store.path):
        validate_state_file(path, allow_missing=True)
    execution = _read_execution(execution_store, context, lock)
    evidence = _read_evidence(evidence_store, context, lock)
    _validate_prefix(context, execution, evidence)
    if (
        execution is not None
        and execution.record.state is DeployScyllaJoinExecutionState.SUCCEEDED
    ):
        if evidence is None:
            raise StateConflictError(
                "completed deploy Scylla first-join evidence is unavailable"
            )
        return _build_report(
            context,
            execution,
            evidence,
            execution_state=DeployScyllaJoinArtifactState.REUSED,
            evidence_state=DeployScyllaJoinArtifactState.REUSED,
        )
    if (
        execution is not None
        and execution.record.state is not DeployScyllaJoinExecutionState.PREPARED
    ):
        raise StateConflictError(
            "deploy Scylla first-join execution requires manual recovery "
            "and cannot retry"
        )

    service = AnsibleService(builder, runner)
    if service.version(lock) != toolchain:
        raise StateConflictError("deploy Scylla first-join toolchain drifted")
    before_prepared = _load_execution_context(
        paths,
        operation_id,
        lock=lock,
        builder=builder,
        toolchain=toolchain,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    if before_prepared.binding != context.binding:
        raise StateConflictError(
            "deploy Scylla first-join state drifted before prepared intent"
        )
    _validate_prefix(before_prepared, execution, evidence)
    if execution is None:
        try:
            execution = _persist_prepared(before_prepared, execution_store, lock=lock)
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy Scylla first-join prepared intent persistence failed "
                "before invocation"
            ) from error

    before_start = _load_execution_context(
        paths,
        operation_id,
        lock=lock,
        builder=builder,
        toolchain=toolchain,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    if before_start.binding != context.binding:
        raise StateConflictError("deploy Scylla first-join state drifted before start")
    _validate_prefix(before_start, execution, evidence)
    try:
        execution = _persist_started(execution_store, execution, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy Scylla first-join authorization consumption failed "
            "before invocation"
        ) from error

    try:
        result, command_digest = service.execute_operation_step(
            lock,
            before_start.metadata,
            before_start.inventory,
            _PLAYBOOK,
            step_sequence=1,
            limit=(before_start.scope.stable_id,),
            variables=dict(before_start.scope.variables),
            readiness=before_start.readiness,
            tags=(_PLAYBOOK,),
            check=False,
            diff=False,
            verbosity=0,
        )
        if command_digest != before_start.scope.command_digest:
            raise AnsibleResultError(
                "deploy Scylla first-join command result identity conflicts"
            )
    except KeyboardInterrupt:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployScyllaJoinExecutionState.INTERRUPTED,
            lock=lock,
        )
        raise AnsibleError(
            "deploy Scylla first join was interrupted; manual recovery required"
        ) from None
    except (AnsibleError, StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            (
                _failure_state(error)
                if isinstance(error, AnsibleError)
                else DeployScyllaJoinExecutionState.MALFORMED_RESULT
            ),
            lock=lock,
        )
        raise AnsibleError(
            "deploy Scylla first-join execution is uncertain; manual recovery required"
        ) from error

    try:
        after = _load_execution_context(
            paths,
            operation_id,
            lock=lock,
            builder=builder,
            toolchain=toolchain,
            executable_identity_digest=executable_identity_digest,
            toolchain_evidence_digest=toolchain_evidence_digest,
        )
        if after.binding != context.binding:
            raise StateConflictError(
                "deploy Scylla first-join state changed after invocation"
            )
    except (StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployScyllaJoinExecutionState.MALFORMED_RESULT,
            lock=lock,
        )
        raise StateConflictError(
            "deploy Scylla first-join state changed after invocation; "
            "manual recovery required"
        ) from error

    try:
        evidence_record = _semantic_evidence(before_start, result)
    except (AnsibleError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            (
                _failure_state(error)
                if isinstance(error, AnsibleError)
                else DeployScyllaJoinExecutionState.MALFORMED_RESULT
            ),
            lock=lock,
        )
        raise AnsibleError(
            "deploy Scylla first-join result is not strict semantic evidence; "
            "manual recovery required"
        ) from error

    try:
        evidence, evidence_state = evidence_store.write_locked(
            evidence_record, lock=lock
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy Scylla first-join evidence persistence failed; "
            "manual recovery required"
        ) from error
    terminal_state = (
        DeployScyllaJoinExecutionState.SUCCEEDED
        if evidence_record.status is ScyllaBootstrapStatus.BOOTSTRAPPED
        else DeployScyllaJoinExecutionState.FAILED
    )
    try:
        execution = _persist_terminal(
            execution_store,
            execution,
            evidence=evidence_record,
            exit_code=result.exit_code,
            state=terminal_state,
            lock=lock,
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy Scylla first-join terminal persistence failed; "
            "manual recovery required"
        ) from error
    if terminal_state is DeployScyllaJoinExecutionState.FAILED:
        raise AnsibleError(
            "deploy Scylla first-join preserved strict failure evidence; "
            "manual recovery required and automatic retry is forbidden"
        )
    return _build_report(
        context,
        execution,
        evidence,
        execution_state=DeployScyllaJoinArtifactState.UPDATED,
        evidence_state=evidence_state,
    )


def deploy_scylla_join_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths, operation_id, DEPLOY_SCYLLA_JOIN_EXECUTION_FILENAME_SUFFIX
    )


def deploy_scylla_join_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths, operation_id, DEPLOY_SCYLLA_JOIN_EVIDENCE_FILENAME_SUFFIX
    )


def deploy_scylla_join_execution_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_JOIN_EXECUTION_FILENAME_SUFFIX
    )


def deploy_scylla_join_evidence_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_JOIN_EVIDENCE_FILENAME_SUFFIX
    )


def _load_execution_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
    builder: AnsibleCommandBuilder,
    toolchain: AnsibleToolchain,
    executable_identity_digest: str,
    toolchain_evidence_digest: str,
) -> _ExecutionContext:
    authorized = _load_join_authorization_context(paths, operation_id, lock=lock)
    scope = _derive_first_join_scope(authorized)
    configure = _load_reconciliation_context(paths, operation_id, lock=lock)
    loaded = _loaded(configure.authorization_context)
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    inventory = deploy.inventory
    journal = deploy.journal
    readiness_record = planning.readiness.record
    identity = authorized.chain.health_evidence.record.binding
    if (
        identity.cluster_uuid != metadata.cluster_uuid
        or identity.cluster_name != metadata.cluster_name
        or journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
        or scope.sequence != 2
        or scope.mode is not ScyllaBootstrapMode.JOIN_EXISTING
        or readiness_record.executable_identity_digest != executable_identity_digest
        or readiness_record.toolchain_evidence_digest != toolchain_evidence_digest
        or readiness_record.playbook_version != str(toolchain.core)
        or readiness_record.inventory_version != str(toolchain.core)
        or readiness_record.remote_playbook_status != "not-performed"
    ):
        raise StateConflictError(
            "deploy Scylla first-join journal, readiness, or toolchain conflicts"
        )
    readiness = _reconstructed_readiness(planning.base)
    if readiness_binding_digest(readiness) != readiness_record.readiness_digest:
        raise StateConflictError("deploy Scylla first-join readiness is stale")
    readiness.require_ready(OperationClassification.SENSITIVE)

    authorization_store = DeployScyllaJoinAuthorizationStore(paths, operation_id)
    validate_state_file(authorization_store.path, allow_missing=True)
    if not authorization_store.path.exists():
        raise StateConflictError(
            "deploy Scylla first-join execution requires immutable authorization"
        )
    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_authorization = _build_authorization(
        authorized,
        scope=scope,
        proof=authorization.record.proof,
        created_at=authorization.record.created_at,
    )
    if (
        authorization.record != expected_authorization
        or authorization.record.consumed
        or authorization.record.authorization_state != "authorized-pre-execution"
        or authorization.record.execution_state != "unavailable"
        or authorization.record.scope.sequence != 2
        or authorization.record.scope.mode is not ScyllaBootstrapMode.JOIN_EXISTING
    ):
        raise StateConflictError(
            "deploy Scylla first-join authorization is stale or consumed"
        )

    definition = get_playbook(_PLAYBOOK)
    source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
    if (
        definition.classification is not OperationClassification.SENSITIVE
        or definition.hosts != HostRole.SCYLLA.value
        or definition.serial != 1
        or not definition.any_errors_fatal
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.check_mode is not CheckMode.REFUSED
        or not definition.source_available
        or source_digest != scope.playbook_source_digest
    ):
        raise StateConflictError(
            "deploy Scylla first-join catalog or source policy conflicts"
        )

    hosts = {
        host.logical_id: host
        for host in inventory.record.inventory.hosts
        if host.role is HostRole.SCYLLA
    }
    matching = tuple(
        stable_id
        for stable_id in sorted(hosts)
        if _digest_object(stable_id) == scope.target_digest
    )
    if len(matching) != 1:
        raise StateConflictError("deploy Scylla first-join target is ambiguous")
    stable_id = matching[0]
    host = hosts[stable_id]
    if not isinstance(host.scylla_datacenter, str) or not isinstance(
        host.scylla_rack, str
    ):
        raise StateConflictError("deploy Scylla first-join topology is incomplete")
    health = authorized.chain.health_evidence.record
    survivor_ids = tuple(node.stable_id for node in health.nodes)
    if (
        survivor_ids != tuple(sorted(set(survivor_ids)))
        or len(survivor_ids) != scope.survivor_count
        or _digest_object(list(survivor_ids)) != scope.survivor_set_digest
        or stable_id in survivor_ids
    ):
        raise StateConflictError(
            "deploy Scylla first-join survivor membership conflicts"
        )

    intents = tuple(
        intent for intent in configure.intents if intent.target_ids == (stable_id,)
    )
    storage_entries = {
        item.stable_id: item
        for item in configure.authorization_context.install.authorization_context.evidence.record.entries
    }
    install_entries = {
        item.stable_id: item
        for item in configure.authorization_context.install.evidence.record.entries
    }
    configure_entries = {
        item.stable_id: item for item in configure.evidence.record.entries
    }
    if (
        len(intents) != 1
        or stable_id not in storage_entries
        or stable_id not in install_entries
        or stable_id not in configure_entries
    ):
        raise StateConflictError(
            "deploy Scylla first-join prerequisite membership conflicts"
        )
    intent = intents[0]
    storage = storage_entries[stable_id]
    install = install_entries[stable_id]
    configuration = configure_entries[stable_id]
    configure_payload = _mapping(
        dict(intent.variables)["deploy_scylla_vms_scylla_configure"],
        "Scylla configure payload",
    )
    file_digests = _string_mapping(
        configure_payload["file_digests"], "configuration file digests"
    )
    seed_ids = _string_tuple(
        configure_payload["seed_stable_ids"], "configured seed identities"
    )
    plan_step = authorized.chain.bootstrap_plan.record.steps[1]
    safety_step = authorized.safety_reconciliation.record.steps[1]
    checkpoint_step = authorized.chain.health_checkpoint.record.steps[1]
    capacity_digest = _digest_object(
        {
            "capacity_bytes": storage.capacity_bytes,
            "device_set_digest": storage.device_set_digest,
            "stable_id": stable_id,
        }
    )
    if (
        plan_step.sequence != 2
        or plan_step.mode is not ScyllaBootstrapMode.JOIN_EXISTING
        or plan_step.preceding_step_digest
        != authorized.chain.bootstrap_plan.record.steps[0].step_digest
        or scope.target_digest != _digest_object(stable_id)
        or scope.bootstrap_plan_step_digest != plan_step.step_digest
        or scope.health_checkpoint_step_digest != checkpoint_step.step_digest
        or scope.join_safety_step_digest != safety_step.step_digest
        or scope.target_topology_digest != configuration.topology_digest
        or scope.seed_policy_digest != configuration.seed_policy_digest
        or configure_payload["seed_digest"] != scope.seed_policy_digest
        or not seed_ids
        or tuple(sorted(seed_ids)) != seed_ids
        or not set(seed_ids) <= set(survivor_ids)
        or stable_id in seed_ids
        or _digest_object(list(seed_ids)) != scope.active_seed_set_digest
        or len(seed_ids) != scope.active_seed_count
        or scope.package_version_digest != _digest_object(SCYLLA_PACKAGE_VERSION)
        or configuration.package_version_digest != scope.package_version_digest
        or install.package_version != SCYLLA_PACKAGE_VERSION
        or not install.installed
        or not install.service_masked
        or not install.service_inactive
        or install.service_started
        or scope.storage_evidence_digest != storage.evidence_digest
        or not storage.readiness_for_scylla
        or storage.failed_check_count
        or storage.unknown_check_count
        or storage.blocker_count
        or scope.configuration_evidence_digest != configuration.evidence_digest
        or not configuration.configured
        or not configuration.service_masked
        or not configuration.service_inactive
        or configuration.service_started
        or configuration.bootstrap_performed
        or scope.capacity_evidence_digest != capacity_digest
        or scope.playbook_source_digest != source_digest
        or scope.topology_digest != health.topology_digest
        or scope.schema_digest != health.schema_digest
        or scope.membership_digest != health.membership_digest
        or _digest_object(host.scylla_datacenter) != plan_step.datacenter_digest
        or _digest_object(host.scylla_rack) != plan_step.rack_digest
        or set(file_digests) != {"cassandra-rackdc.properties", "scylla.yaml"}
        or any(not _is_digest(value) for value in file_digests.values())
    ):
        raise StateConflictError(
            "deploy Scylla first-join target, health, topology, seed, "
            "configuration, storage, or version scope conflicts"
        )

    prerequisite_digests = {
        "authorization_digest": authorization.record.authorization_digest,
        "cluster_spec_digest": metadata.desired_spec.digest(),
        "config_digest": configuration.evidence_digest,
        "install_digest": install.evidence_digest,
        "inventory_digest": inventory.digest,
        "observation_digest": deploy.observation.digest,
        "seed_digest": scope.seed_policy_digest,
        "storage_digest": storage.evidence_digest,
        "topology_digest": configuration.topology_digest,
        "trust_digest": planning.base.trust.digest,
    }
    payload: dict[str, object] = {
        "authorization": {
            "authorization_digest": authorization.record.authorization_digest,
            "capacity_check_passed": True,
            "existing_member_count": len(survivor_ids),
            "healthy_member_ids": list(survivor_ids),
            "healthy_seed_ids": list(seed_ids),
            "intent_digest": scope.scope_digest,
            "live_cluster_state_absent": False,
            "reviewed": True,
            "schema_agreement": True,
            "target_present_in_ring": False,
            "topology_check_passed": True,
        },
        "bootstrap_timeout_seconds": _BOOTSTRAP_TIMEOUT_SECONDS,
        "cluster_uuid": str(metadata.cluster_uuid),
        "config_file_digests": file_digests,
        "datacenter": host.scylla_datacenter,
        "logical_id": stable_id,
        "mode": ScyllaBootstrapMode.JOIN_EXISTING.value,
        "operation_id": str(operation_id),
        "package_version": SCYLLA_PACKAGE_VERSION,
        "prerequisite_digests": prerequisite_digests,
        "rack": host.scylla_rack,
        "release_line": SCYLLA_RELEASE_LINE,
        "schema_version": SCYLLA_BOOTSTRAP_SCHEMA_VERSION,
        "seed_stable_ids": list(seed_ids),
    }
    variables: dict[str, object] = {"deploy_scylla_vms_scylla_bootstrap": payload}
    selected, validated, variables_digest, command_digest = (
        builder.validate_operation_step(
            _PLAYBOOK,
            step_sequence=1,
            limit=(stable_id,),
            variables=variables,
            tags=(_PLAYBOOK,),
            check=False,
            diff=False,
            verbosity=0,
        )
    )
    if (
        selected != definition
        or validated != definition.validate_variables(variables)
        or variables_digest != digest_bytes(serialize_json(validated))
    ):
        raise StateConflictError(
            "deploy Scylla first-join anchored command policy conflicts"
        )
    execution_scope_digest = _digest_object(
        {
            "authorization_scope_digest": scope.scope_digest,
            "command_digest": command_digest,
            "mode": ScyllaBootstrapMode.JOIN_EXISTING.value,
            "plan_step_digest": scope.bootstrap_plan_step_digest,
            "sequence": 2,
            "source_digest": source_digest,
            "target_digest": scope.target_digest,
            "variables_digest": variables_digest,
        }
    )
    later = authorized.safety_reconciliation.record.steps[2:]
    later_digest = _digest_object(
        [
            {
                "sequence": item.sequence,
                "status": item.status.value,
                "step_digest": item.step_digest,
                "target_digest": item.target_digest,
            }
            for item in later
        ]
    )
    context = authorized.chain.bootstrap_context.record
    trust = planning.base.trust
    binding_values: dict[str, object] = {
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_name": metadata.cluster_name,
        "operation_id": operation_id,
        "operation": _OPERATION,
        "request_digest": journal.record.request_digest,
        "journal_generation": journal.record.generation,
        "journal_digest": journal.digest,
        "journal_status": journal.record.status,
        "journal_phase": journal.record.phase,
        "bootstrap_context_artifact_digest": (
            authorized.chain.bootstrap_context.artifact_digest
        ),
        "bootstrap_context_record_digest": context.record_digest,
        "bootstrap_plan_artifact_digest": (
            authorized.chain.bootstrap_plan.artifact_digest
        ),
        "bootstrap_plan_digest": (authorized.chain.bootstrap_plan.record.plan_digest),
        "initial_execution_artifact_digest": (
            authorized.chain.bootstrap_execution.artifact_digest
        ),
        "initial_evidence_artifact_digest": (
            authorized.chain.bootstrap_evidence.artifact_digest
        ),
        "initial_evidence_digest": (
            authorized.chain.bootstrap_evidence.record.entry.evidence_digest
        ),
        "health_execution_artifact_digest": (
            authorized.chain.health_execution.artifact_digest
        ),
        "health_evidence_artifact_digest": (
            authorized.chain.health_evidence.artifact_digest
        ),
        "health_evidence_digest": health.evidence_digest,
        "health_checkpoint_artifact_digest": (
            authorized.chain.health_checkpoint.artifact_digest
        ),
        "health_checkpoint_digest": (
            authorized.chain.health_checkpoint.record.checkpoint_digest
        ),
        "safety_context_artifact_digest": authorized.safety_context.artifact_digest,
        "safety_context_digest": authorized.safety_context.record.context_digest,
        "safety_evidence_artifact_digest": authorized.safety_evidence.artifact_digest,
        "safety_evidence_digest": authorized.safety_evidence.record.evidence_digest,
        "safety_reconciliation_artifact_digest": (
            authorized.safety_reconciliation.artifact_digest
        ),
        "safety_reconciliation_digest": (
            authorized.safety_reconciliation.record.reconciliation_digest
        ),
        "authorization_artifact_digest": authorization.artifact_digest,
        "authorization_digest": authorization.record.authorization_digest,
        "authorization_scope_digest": authorization.record.authorization_scope_digest,
        "authorization_proof_digest": authorization.record.proof.proof_digest,
        "validated_chain_digest": authorization.record.validated_chain_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": readiness_record.record_digest,
        "catalog_digest": loaded.catalog_digest,
        "source_version": loaded.source.version,
        "source_digest": loaded.source.digest,
        "playbook_source_digest": source_digest,
        "toolchain_version": str(toolchain.core),
        "executable_identity_digest": executable_identity_digest,
        "toolchain_evidence_digest": toolchain_evidence_digest,
        "observation_generation": deploy.observation.record.generation,
        "observation_artifact_digest": deploy.observation.digest,
        "observation_manifest_digest": deploy.observation.record.manifest_digest,
        "inventory_generation": inventory.record.generation,
        "inventory_artifact_digest": inventory.digest,
        "inventory_digest": inventory.record.inventory_digest,
        "trust_generation": trust.record.generation,
        "trust_artifact_digest": trust.digest,
        "trust_entries_digest": trust.record.entries_digest,
        "sequence": 2,
        "target_digest": scope.target_digest,
        "plan_step_digest": scope.bootstrap_plan_step_digest,
        "preceding_step_digest": plan_step.preceding_step_digest,
        "health_checkpoint_step_digest": scope.health_checkpoint_step_digest,
        "join_safety_step_digest": scope.join_safety_step_digest,
        "survivor_count": scope.survivor_count,
        "survivor_set_digest": scope.survivor_set_digest,
        "survivor_health_digest": scope.survivor_health_digest,
        "active_seed_count": scope.active_seed_count,
        "active_seed_set_digest": scope.active_seed_set_digest,
        "topology_digest": scope.topology_digest,
        "target_topology_digest": scope.target_topology_digest,
        "schema_digest": scope.schema_digest,
        "membership_digest": scope.membership_digest,
        "seed_policy_digest": scope.seed_policy_digest,
        "package_version_digest": scope.package_version_digest,
        "storage_evidence_digest": scope.storage_evidence_digest,
        "configuration_evidence_digest": scope.configuration_evidence_digest,
        "capacity_evidence_digest": scope.capacity_evidence_digest,
        "prerequisite_digest": _digest_object(prerequisite_digests),
        "variables_digest": variables_digest,
        "command_digest": command_digest,
        "execution_scope_digest": execution_scope_digest,
        "later_join_count": len(later),
        "later_join_digest": later_digest,
        "binding_digest": "",
    }
    binding_values["binding_digest"] = _binding_digest_from_values(binding_values)
    return _ExecutionContext(
        authorization=authorization,
        binding=DeployScyllaJoinExecutionBinding(
            **binding_values  # type: ignore[arg-type]
        ),
        scope=_ExecutionScope(
            stable_id=stable_id,
            payload=payload,
            variables=tuple(sorted(validated.items())),
            variables_digest=variables_digest,
            command_digest=command_digest,
            source_digest=source_digest,
        ),
        metadata=metadata,
        inventory=inventory,
        readiness=readiness,
    )


def _semantic_evidence(
    context: _ExecutionContext, result: AnsibleExecutionResult
) -> DeployScyllaJoinEvidence:
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.SENSITIVE
        or result.check_mode
        or result.scylla_bootstrap is not None
    ):
        raise AnsibleResultError(
            "deploy Scylla first-join strict result identity conflicts"
        )
    try:
        parsed = parse_scylla_bootstrap_execution(
            result.stdout,
            expected_payload=dict(context.scope.payload),
            exit_code=result.exit_code,
        )
    except AnsibleError as error:
        raise AnsibleResultError(
            "deploy Scylla first-join strict result is malformed"
        ) from error
    _validate_semantic_result(parsed, context)
    success = parsed.status is ScyllaBootstrapStatus.BOOTSTRAPPED
    never_joined = (
        parsed.status is ScyllaBootstrapStatus.FAILED
        and parsed.mutation_boundary is MutationBoundary.SERVICE_UNMASKED_STARTED
    )
    prerequisite_digest = _digest_object(dict(parsed.prerequisite_digests))
    result_digest = _digest_object(
        {
            "blocker_digest": _digest_object(list(parsed.blockers)),
            "host_id_digest": parsed.host_id_digest,
            "mode": parsed.mode.value,
            "mutation_boundary": parsed.mutation_boundary.value,
            "prerequisite_digest": prerequisite_digest,
            "recovery_required": parsed.recovery_required,
            "ring_membership_digest": parsed.ring_membership_digest,
            "status": parsed.status.value,
            "streaming_state": parsed.streaming_state,
            "target_digest": _digest_object(parsed.target_logical_id),
        }
    )
    values: dict[str, object] = {
        "generation": 1,
        "created_at": _timestamp(),
        "binding": context.binding,
        "stable_id": context.scope.stable_id,
        "sequence": 2,
        "mode": parsed.mode,
        "status": parsed.status,
        "datacenter_digest": _digest_object(parsed.datacenter),
        "rack_digest": _digest_object(parsed.rack),
        "topology_digest": context.binding.target_topology_digest,
        "package_version_digest": context.binding.package_version_digest,
        "prerequisite_digest": prerequisite_digest,
        "survivor_count": context.binding.survivor_count,
        "survivor_set_digest": context.binding.survivor_set_digest,
        "active_seed_count": context.binding.active_seed_count,
        "active_seed_set_digest": context.binding.active_seed_set_digest,
        "prior_membership_digest": context.binding.membership_digest,
        "prior_schema_digest": context.binding.schema_digest,
        "host_id_digest": parsed.host_id_digest,
        "ring_membership_digest": parsed.ring_membership_digest,
        "blocker_count": len(parsed.blockers),
        "blocker_digest": _digest_object(list(parsed.blockers)),
        "prerequisite_revalidated": True,
        "target_absence_revalidated": True,
        "survivor_health_revalidated": True,
        "seed_health_revalidated": True,
        "capacity_revalidated": True,
        "topology_revalidated": True,
        "service_active": success,
        "cql_ready": success,
        "nodetool_membership_verified": success,
        "schema_agreement": success,
        "streaming_complete": success,
        "never_joined_proven": never_joined,
        "membership_may_have_changed": (
            parsed.mutation_boundary
            is MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED
        ),
        "remask_performed": never_joined,
        "node_preserved": True,
        "recovery_required": parsed.recovery_required,
        "automatic_retry_allowed": False,
        "mutation_boundary": parsed.mutation_boundary,
        "variables_digest": context.scope.variables_digest,
        "command_digest": context.scope.command_digest,
        "source_digest": context.scope.source_digest,
        "result_digest": result_digest,
        "evidence_digest": "",
    }
    values["evidence_digest"] = _evidence_digest_from_values(values)
    return DeployScyllaJoinEvidence(**values)  # type: ignore[arg-type]


def _validate_semantic_result(
    evidence: ScyllaBootstrapEvidence, context: _ExecutionContext
) -> None:
    payload = context.scope.payload
    if (
        evidence.mode is not ScyllaBootstrapMode.JOIN_EXISTING
        or evidence.target_logical_id != context.scope.stable_id
        or evidence.datacenter != payload["datacenter"]
        or evidence.rack != payload["rack"]
        or dict(evidence.prerequisite_digests) != payload["prerequisite_digests"]
        or evidence.mutation_boundary is MutationBoundary.NOT_REACHED
    ):
        raise AnsibleResultError("deploy Scylla first-join result scope conflicts")
    if evidence.status is ScyllaBootstrapStatus.BOOTSTRAPPED:
        if (
            evidence.service_state != "active"
            or evidence.streaming_state != "complete"
            or evidence.host_id_digest is None
            or evidence.ring_membership_digest is None
            or evidence.mutation_boundary
            is not MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED
            or evidence.recovery_required
            or evidence.blockers != _SUCCESS_BLOCKERS
        ):
            raise AnsibleResultError(
                "deploy Scylla first-join success evidence conflicts"
            )
        return
    if evidence.status is not ScyllaBootstrapStatus.FAILED:
        raise AnsibleResultError(
            "deploy Scylla first-join check-mode result is forbidden"
        )
    if evidence.mutation_boundary is MutationBoundary.SERVICE_UNMASKED_STARTED:
        valid = (
            evidence.service_state == "masked"
            and evidence.streaming_state == "unknown"
            and evidence.host_id_digest is None
            and evidence.recovery_required
            and evidence.blockers == _NEVER_JOINED_BLOCKERS
        )
    else:
        valid = (
            evidence.mutation_boundary
            is MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED
            and evidence.service_state == "unknown-preserved"
            and evidence.streaming_state == "unknown"
            and evidence.host_id_digest is None
            and evidence.ring_membership_digest is not None
            and evidence.recovery_required
            and evidence.blockers == _MAY_HAVE_JOINED_BLOCKERS
        )
    if not valid:
        raise AnsibleResultError(
            "deploy Scylla first-join failure recovery evidence conflicts"
        )


def _read_execution(
    store: DeployScyllaJoinExecutionStore,
    context: _ExecutionContext,
    lock: ClusterLock,
) -> StoredDeployScyllaJoinExecution | None:
    return (
        store.read_locked(
            lock,
            expected_cluster_uuid=context.binding.cluster_uuid,
            expected_cluster_name=context.binding.cluster_name,
        )
        if store.path.exists()
        else None
    )


def _read_evidence(
    store: DeployScyllaJoinEvidenceStore,
    context: _ExecutionContext,
    lock: ClusterLock,
) -> StoredDeployScyllaJoinEvidence | None:
    return (
        store.read_locked(
            lock,
            expected_cluster_uuid=context.binding.cluster_uuid,
            expected_cluster_name=context.binding.cluster_name,
        )
        if store.path.exists()
        else None
    )


def _validate_prefix(
    context: _ExecutionContext,
    execution: StoredDeployScyllaJoinExecution | None,
    evidence: StoredDeployScyllaJoinEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "deploy Scylla first-join evidence exists without execution"
            )
        return
    record = execution.record
    if (
        record.binding != context.binding
        or record.stable_id != context.scope.stable_id
        or record.mode is not ScyllaBootstrapMode.JOIN_EXISTING
    ):
        raise StateConflictError(
            "deploy Scylla first-join execution provenance is stale"
        )
    if evidence is None:
        if record.state in {
            DeployScyllaJoinExecutionState.SUCCEEDED,
            DeployScyllaJoinExecutionState.FAILED,
        }:
            raise StateConflictError(
                "deploy Scylla first-join terminal evidence is missing"
            )
        return
    if (
        evidence.record.binding != context.binding
        or evidence.record.stable_id != context.scope.stable_id
        or evidence.record.variables_digest != context.scope.variables_digest
        or evidence.record.command_digest != context.scope.command_digest
        or evidence.record.source_digest != context.scope.source_digest
        or (
            record.result_digest is not None
            and record.result_digest != evidence.record.result_digest
        )
        or (
            record.evidence_digest is not None
            and record.evidence_digest != evidence.record.evidence_digest
        )
        or record.state
        not in {
            DeployScyllaJoinExecutionState.STARTED,
            DeployScyllaJoinExecutionState.SUCCEEDED,
            DeployScyllaJoinExecutionState.FAILED,
        }
    ):
        raise StateConflictError(
            "deploy Scylla first-join execution and evidence conflict"
        )


def _persist_prepared(
    context: _ExecutionContext,
    store: DeployScyllaJoinExecutionStore,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaJoinExecution:
    now = _timestamp()
    return store.write_locked(
        DeployScyllaJoinExecution(
            generation=1,
            created_at=now,
            updated_at=now,
            binding=context.binding,
            state=DeployScyllaJoinExecutionState.PREPARED,
            stable_id=context.scope.stable_id,
            mode=ScyllaBootstrapMode.JOIN_EXISTING,
            prepared_at=now,
            started_at=None,
            completed_at=None,
            ordinary_authorization_consumed=False,
            narrow_authorization_consumed=False,
            invocation_count=0,
            invocation_may_have_occurred=False,
            completed=False,
            exit_code=None,
            result_digest=None,
            evidence_digest=None,
            mutation_boundary=None,
            membership_may_have_changed=None,
            node_preserved=None,
            remask_performed=None,
            manual_recovery_required=False,
        ),
        expected_generation=0,
        expected_digest=None,
        lock=lock,
    )


def _persist_started(
    store: DeployScyllaJoinExecutionStore,
    current: StoredDeployScyllaJoinExecution,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaJoinExecution:
    if current.record.state is not DeployScyllaJoinExecutionState.PREPARED:
        raise StateConflictError(
            "deploy Scylla first-join start requires prepared intent"
        )
    now = _timestamp()
    return store.write_locked(
        replace(
            current.record,
            generation=current.record.generation + 1,
            updated_at=now,
            state=DeployScyllaJoinExecutionState.STARTED,
            started_at=now,
            ordinary_authorization_consumed=True,
            narrow_authorization_consumed=True,
            invocation_count=1,
            invocation_may_have_occurred=True,
            manual_recovery_required=True,
        ),
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _persist_uncertain_or_raise(
    store: DeployScyllaJoinExecutionStore,
    current: StoredDeployScyllaJoinExecution,
    state: DeployScyllaJoinExecutionState,
    *,
    lock: ClusterLock,
) -> None:
    try:
        _persist_uncertain(store, current, state, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy Scylla first-join uncertain outcome persistence failed; "
            "manual recovery required"
        ) from error


def _persist_uncertain(
    store: DeployScyllaJoinExecutionStore,
    current: StoredDeployScyllaJoinExecution,
    state: DeployScyllaJoinExecutionState,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaJoinExecution:
    if (
        current.record.state is not DeployScyllaJoinExecutionState.STARTED
        or state
        not in {
            DeployScyllaJoinExecutionState.FAILED,
            DeployScyllaJoinExecutionState.TIMED_OUT,
            DeployScyllaJoinExecutionState.INTERRUPTED,
            DeployScyllaJoinExecutionState.UNREACHABLE,
            DeployScyllaJoinExecutionState.MALFORMED_RESULT,
        }
    ):
        raise StatePersistenceError(
            "deploy Scylla first-join uncertain transition conflicts"
        )
    now = _timestamp()
    return store.write_locked(
        replace(
            current.record,
            generation=current.record.generation + 1,
            updated_at=now,
            state=state,
            completed_at=now,
            manual_recovery_required=True,
        ),
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _persist_terminal(
    store: DeployScyllaJoinExecutionStore,
    current: StoredDeployScyllaJoinExecution,
    *,
    evidence: DeployScyllaJoinEvidence,
    exit_code: int,
    state: DeployScyllaJoinExecutionState,
    lock: ClusterLock,
) -> StoredDeployScyllaJoinExecution:
    if (
        current.record.state is not DeployScyllaJoinExecutionState.STARTED
        or state
        not in {
            DeployScyllaJoinExecutionState.SUCCEEDED,
            DeployScyllaJoinExecutionState.FAILED,
        }
        or (state is DeployScyllaJoinExecutionState.SUCCEEDED)
        != (evidence.status is ScyllaBootstrapStatus.BOOTSTRAPPED)
    ):
        raise StateConflictError(
            "deploy Scylla first-join terminal transition conflicts"
        )
    now = _timestamp()
    return store.write_locked(
        replace(
            current.record,
            generation=current.record.generation + 1,
            updated_at=now,
            state=state,
            completed_at=now,
            completed=True,
            exit_code=exit_code,
            result_digest=evidence.result_digest,
            evidence_digest=evidence.evidence_digest,
            mutation_boundary=evidence.mutation_boundary,
            membership_may_have_changed=evidence.membership_may_have_changed,
            node_preserved=evidence.node_preserved,
            remask_performed=evidence.remask_performed,
            manual_recovery_required=evidence.recovery_required,
        ),
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _build_report(
    context: _ExecutionContext,
    execution: StoredDeployScyllaJoinExecution,
    evidence: StoredDeployScyllaJoinEvidence,
    *,
    execution_state: DeployScyllaJoinArtifactState,
    evidence_state: DeployScyllaJoinArtifactState,
) -> DeployScyllaJoinExecutionReport:
    record = evidence.record
    if (
        execution.record.state is not DeployScyllaJoinExecutionState.SUCCEEDED
        or not execution.record.completed
        or record.status is not ScyllaBootstrapStatus.BOOTSTRAPPED
    ):
        raise StateConflictError("deploy Scylla first-join execution is not successful")
    return DeployScyllaJoinExecutionReport(
        operation_id=context.binding.operation_id,
        execution_state=execution.record.state,
        execution_artifact_state=execution_state,
        evidence_artifact_state=evidence_state,
        execution_artifact_digest=execution.artifact_digest,
        evidence_artifact_digest=evidence.artifact_digest,
        binding_digest=context.binding.binding_digest,
        authorization_artifact_digest=context.authorization.artifact_digest,
        authorization_digest=context.authorization.record.authorization_digest,
        ordinary_authorization_consumed=(
            execution.record.ordinary_authorization_consumed
        ),
        narrow_authorization_consumed=(execution.record.narrow_authorization_consumed),
        stage=_STAGE,
        scope_kind=_SCOPE_KIND,
        invocation_count=execution.record.invocation_count,
        target_count=1,
        target_digest=context.binding.target_digest,
        sequence=2,
        mode=record.mode,
        survivor_count=record.survivor_count,
        active_seed_count=record.active_seed_count,
        later_join_count=context.binding.later_join_count,
        bootstrapped_count=1,
        host_identity_count=int(record.host_id_digest is not None),
        ring_identity_count=int(record.ring_membership_digest is not None),
        prerequisite_revalidated_count=int(record.prerequisite_revalidated),
        target_absence_revalidated_count=int(record.target_absence_revalidated),
        survivor_health_revalidated_count=int(record.survivor_health_revalidated),
        capacity_revalidated_count=int(record.capacity_revalidated),
        topology_revalidated_count=int(record.topology_revalidated),
        cql_ready_count=int(record.cql_ready),
        nodetool_verified_count=int(record.nodetool_membership_verified),
        schema_agreement_count=int(record.schema_agreement),
        streaming_complete_count=int(record.streaming_complete),
        membership_may_have_changed_count=int(record.membership_may_have_changed),
        node_preserved_count=int(record.node_preserved),
        result_digest=record.result_digest,
        evidence_digest=record.evidence_digest,
        manual_recovery_required=False,
        automatic_retry_allowed=False,
        journal_status=context.binding.journal_status,
        journal_phase=context.binding.journal_phase,
    )


def _validate_execution_transition(
    current: DeployScyllaJoinExecution,
    replacement: DeployScyllaJoinExecution,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or current.completed
    ):
        raise StatePersistenceError(
            "deploy Scylla first-join execution transition is invalid"
        )
    if current.state is DeployScyllaJoinExecutionState.PREPARED:
        valid = replacement.state is DeployScyllaJoinExecutionState.STARTED
    elif current.state is DeployScyllaJoinExecutionState.STARTED:
        valid = replacement.state not in {
            DeployScyllaJoinExecutionState.PREPARED,
            DeployScyllaJoinExecutionState.STARTED,
        }
    else:
        valid = False
    if not valid:
        raise StatePersistenceError(
            "deploy Scylla first-join execution transition conflicts"
        )


def _binding_digest(record: DeployScyllaJoinExecutionBinding) -> str:
    return _binding_digest_from_values(record.to_object())


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for name, field in DeployScyllaJoinExecutionBinding.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["binding_digest"] = ""
    return _digest_object(value)


def _evidence_digest(record: DeployScyllaJoinEvidence) -> str:
    return _evidence_digest_from_values(record.to_object())


def _evidence_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for name, field in DeployScyllaJoinEvidence.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["evidence_digest"] = ""
    return _digest_object(value)


def _failure_state(error: AnsibleError) -> DeployScyllaJoinExecutionState:
    cause = error.__cause__
    if isinstance(cause, ProcessTimeoutError):
        return DeployScyllaJoinExecutionState.TIMED_OUT
    if isinstance(cause, ProcessOutputError):
        return DeployScyllaJoinExecutionState.MALFORMED_RESULT
    message = str(error).lower()
    if "unreachable" in message:
        return DeployScyllaJoinExecutionState.UNREACHABLE
    if isinstance(error, AnsibleResultError) or "malformed" in message:
        return DeployScyllaJoinExecutionState.MALFORMED_RESULT
    return DeployScyllaJoinExecutionState.FAILED


def _artifact_path(paths: StatePaths, operation_id: uuid.UUID, suffix: str) -> Path:
    _require_canonical_paths(paths)
    path = paths.operations / f"{_require_operation_id(operation_id)}{suffix}"
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Scylla first-join artifact path is not canonical"
        )
    return path


def _operation_id_from_filename(name: str, suffix: str) -> uuid.UUID | None:
    if not name.endswith(suffix):
        return None
    value = name[: -len(suffix)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _refuse_ambiguous_or_later_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Scylla first-join artifacts"
        ) from error
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_SCYLLA_JOIN_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_JOIN_EVIDENCE_FILENAME_SUFFIX,
    )
    later_fragments = (
        ".ansible-deploy-post-scylla-join",
        ".ansible-deploy-scylla-join-health",
        ".ansible-scylla-remove",
        ".ansible-scylla-replace",
        ".ansible-scylla-repair",
        ".ansible-scylla-cleanup",
    )
    for entry in entries:
        if entry.name.startswith(canonical) and any(
            fragment in entry.name for fragment in later_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy Scylla first-join execution refuses later membership history"
            )
        for suffix in suffixes:
            if not entry.name.endswith(suffix):
                continue
            prefix = entry.name[: -len(suffix)]
            try:
                parsed = uuid.UUID(prefix)
            except ValueError:
                parsed = None
            if parsed == operation_id and prefix != canonical:
                validate_state_file(entry)
                raise StateConflictError(
                    "deploy Scylla first-join artifacts are ambiguous"
                )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError("deploy Scylla first-join paths are not canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy Scylla first-join execution requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _timestamp() -> str:
    return format_timestamp(datetime.now(UTC))


def _validate_toolchain_version(value: str) -> None:
    try:
        parse_ansible_core_version(
            f"ansible-playbook [core {value}]\n",
            expected_executable="ansible-playbook",
        )
    except AnsibleVersionError as error:
        raise StatePersistenceError(
            "deploy Scylla first-join toolchain version is invalid"
        ) from error


def _dataclass_object(
    value: object, *, nested_fields: set[str] | None = None
) -> dict[str, object]:
    nested = nested_fields or set()
    result: dict[str, object] = {}
    for name in value.__dataclass_fields__:  # type: ignore[attr-defined]
        item = getattr(value, name)
        result[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(item, StrEnum)
            else item.to_object()
            if name in nested
            else item
        )
    return result


def _parse_dataclass(
    data_type: type[object],
    value: Mapping[str, object],
    *,
    integer_fields: set[str] | None = None,
    uuid_fields: set[str] | None = None,
    boolean_fields: set[str] | None = None,
    enum_fields: Mapping[str, type[StrEnum]] | None = None,
    optional_string_fields: set[str] | None = None,
    optional_integer_fields: set[str] | None = None,
    optional_boolean_fields: set[str] | None = None,
    skip_fields: set[str] | None = None,
    label: str,
) -> dict[str, object]:
    require_exact_keys(value, set(data_type.__dataclass_fields__), label)  # type: ignore[attr-defined]
    integers = integer_fields or set()
    uuids = uuid_fields or set()
    booleans = boolean_fields or set()
    enums = enum_fields or {}
    optional_strings = optional_string_fields or set()
    optional_integers = optional_integer_fields or set()
    optional_booleans = optional_boolean_fields or set()
    skipped = skip_fields or set()
    parsed: dict[str, object] = {}
    try:
        for name in data_type.__dataclass_fields__:  # type: ignore[attr-defined]
            if name in skipped:
                continue
            item = value[name]
            if name in integers:
                parsed[name] = _integer(item, name)
            elif name in uuids:
                parsed[name] = parse_uuid(require_string(value, name), name)
            elif name in booleans:
                parsed[name] = _boolean(item, name)
            elif name in enums:
                parsed[name] = enums[name](require_string(value, name))
            elif name in optional_strings:
                parsed[name] = _optional_string(item, name)
            elif name in optional_integers:
                parsed[name] = _optional_integer(item, name)
            elif name in optional_booleans:
                parsed[name] = _optional_boolean(item, name)
            else:
                parsed[name] = require_string(value, name)
    except ValueError as error:
        raise StatePersistenceError(f"deploy Scylla {label} enum is invalid") from error
    return parsed


def _json_object(values: Mapping[str, object]) -> dict[str, object]:
    return {name: _json_value(item) for name, item in values.items()}


def _json_value(value: object) -> object:
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, Mapping):
        return {str(name): _json_value(item) for name, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if hasattr(value, "to_object"):
        return _json_value(value.to_object())
    return value


def _digest_fields(value: object) -> tuple[str | None, ...]:
    return tuple(
        cast(str | None, getattr(value, name))
        for name in value.__dataclass_fields__  # type: ignore[attr-defined]
        if name.endswith("_digest")
    )


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _string_mapping(value: object, label: str) -> dict[str, str]:
    mapping = _mapping(value, label)
    if not all(isinstance(item, str) for item in mapping.values()):
        raise StatePersistenceError(f"{label} must contain strings")
    return cast(dict[str, str], dict(mapping))


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise StatePersistenceError(f"{label} must be a string array")
    return tuple(value)


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _positive_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be a boolean")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    return None if value is None else _integer(value, label)


def _optional_boolean(value: object, label: str) -> bool | None:
    return None if value is None else _boolean(value, label)


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise StatePersistenceError(f"{label} must be a string or null")
    return value


def _optional_timestamp(value: str | None) -> datetime | None:
    return None if value is None else parse_timestamp(value)


def _is_digest(value: str) -> bool:
    try:
        validate_digest(value, "digest")
    except StatePersistenceError:
        return False
    return True


__all__ = [
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_BINDING_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_JOIN_EXECUTION_SCHEMA_VERSION",
    "DEPLOY_SCYLLA_JOIN_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_SCYLLA_JOIN_EXECUTION_FILENAME_SUFFIX",
    "DeployScyllaJoinArtifactState",
    "DeployScyllaJoinEvidence",
    "DeployScyllaJoinEvidenceStore",
    "DeployScyllaJoinExecution",
    "DeployScyllaJoinExecutionBinding",
    "DeployScyllaJoinExecutionReport",
    "DeployScyllaJoinExecutionState",
    "DeployScyllaJoinExecutionStore",
    "StoredDeployScyllaJoinEvidence",
    "StoredDeployScyllaJoinExecution",
    "deploy_scylla_join_evidence_id_from_filename",
    "deploy_scylla_join_evidence_path",
    "deploy_scylla_join_execution_id_from_filename",
    "deploy_scylla_join_execution_path",
    "execute_deploy_scylla_first_join",
]
