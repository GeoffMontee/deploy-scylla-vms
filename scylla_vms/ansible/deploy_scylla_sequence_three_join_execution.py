"""Durable execution ownership for the authorized sequence-three Scylla join.

This internal owner revalidates the exact sequence-two, post-join-health,
sequence-three safety, and authorization chain. It derives only sequence three
from canonical state, records prepared and started intent before the sole
controlled call, and persists only address-free semantic evidence. It never
advances the common journal, performs post-join health, or authorizes a later
join.
"""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

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
from scylla_vms.ansible.deploy_scylla_join_execution import (
    DeployScyllaJoinArtifactState,
    DeployScyllaJoinExecutionState,
    _dataclass_object,
    _digest_fields,
    _failure_state,
    _is_digest,
    _json_object,
    _json_value,
    _mapping,
    _optional_string,
    _optional_timestamp,
    _parse_dataclass,
    _positive_integer,
    _string_mapping,
    _string_tuple,
    _validate_toolchain_version,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_authorization import (
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_SCHEMA_VERSION,
    DeployScyllaSequenceThreeJoinAuthorizationStore,
    StoredDeployScyllaSequenceThreeJoinAuthorization,
    _build_authorization,
    _derive_sequence_three_join_scope,
    _load_sequence_three_join_authorization_context,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_safety import (
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_RECONCILIATION_SCHEMA_VERSION,
    DeployScyllaSequenceThreeSafetyStepStatus,
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
from scylla_vms.ansible.toolchain import AnsibleToolchain
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
    serialize_json,
    validate_digest,
)
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

ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-sequence-three-join-execution-binding/v1"
)
ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-sequence-three-join-execution/v1"
)
ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-sequence-three-join-evidence/v1"
)
ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-sequence-three-join-execution-report/v1"
)

DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-sequence-three-join-execution.json"
)
DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-sequence-three-join-evidence.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "scylla-bootstrap"
_STAGE = "sequence-three-join-existing-execution"
_SCOPE_KIND = "authorized-reconciled-sequence-three"
_TARGET_SEQUENCE = 3
_CURRENT_MEMBER_COUNT = 2
_BOOTSTRAP_TIMEOUT_SECONDS = 7200
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SUCCESS_BLOCKERS: tuple[str, ...] = ()
_NEVER_JOINED_BLOCKERS = ("execution-failed",)
_MAY_HAVE_JOINED_BLOCKERS = ("join-incomplete",)

DeployScyllaSequenceThreeJoinExecutionState = DeployScyllaJoinExecutionState
DeployScyllaSequenceThreeJoinArtifactState = DeployScyllaJoinArtifactState


@dataclass(frozen=True, slots=True)
class DeployScyllaSequenceThreeJoinExecutionBinding:
    """Value-free binding for the one exact sequence-three execution."""

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
    first_join_authorization_artifact_digest: str
    first_join_authorization_digest: str
    first_join_execution_artifact_digest: str
    first_join_execution_binding_digest: str
    first_join_evidence_artifact_digest: str
    first_join_evidence_digest: str
    post_join_health_execution_artifact_digest: str
    post_join_health_evidence_artifact_digest: str
    post_join_health_evidence_digest: str
    post_join_health_reconciliation_artifact_digest: str
    post_join_health_reconciliation_digest: str
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
    current_state_digest: str
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
    post_join_health_step_digest: str
    sequence_three_safety_step_digest: str
    survivor_count: int
    survivor_set_digest: str
    survivor_health_digest: str
    active_seed_count: int
    active_seed_set_digest: str
    topology_digest: str
    target_topology_digest: str
    schema_digest: str
    membership_digest: str
    host_mapping_digest: str
    seed_policy_digest: str
    package_version_digest: str
    storage_evidence_digest: str
    configuration_evidence_digest: str
    capacity_evidence_digest: str
    backup_policy_evidence_digest: str
    capacity_policy_evidence_digest: str
    quorum_evidence_digest: str
    replication_evidence_digest: str
    prerequisite_digest: str
    variables_digest: str
    command_digest: str
    execution_scope_digest: str
    later_join_count: int
    later_join_digest: str
    binding_digest: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_SCHEMA_VERSION
    )
    safety_context_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_SCHEMA_VERSION
    )
    safety_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_EVIDENCE_SCHEMA_VERSION
    )
    safety_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_RECONCILIATION_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_BINDING_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_BINDING_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_AUTHORIZATION_SCHEMA_VERSION
            or self.safety_context_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_CONTEXT_SCHEMA_VERSION
            or self.safety_evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_EVIDENCE_SCHEMA_VERSION
            or self.safety_reconciliation_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_SAFETY_RECONCILIATION_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.sequence != _TARGET_SEQUENCE
            or self.survivor_count != _CURRENT_MEMBER_COUNT
            or self.active_seed_count != 1
            or self.later_join_count < 0
            or self.binding_digest != _binding_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla sequence-three join execution binding conflicts"
            )
        validate_cluster_name(self.cluster_name)
        for generation in (
            self.journal_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
        ):
            _positive_integer(generation, "sequence-three join binding generation")
        for digest in _digest_fields(self):
            if digest is None:
                raise StatePersistenceError(
                    "deploy Scylla sequence-three join binding digest is missing"
                )
            validate_digest(digest, "sequence-three join binding digest")
        _validate_toolchain_version(self.toolchain_version)

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaSequenceThreeJoinExecutionBinding:
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
            label="sequence-three join execution binding",
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaSequenceThreeJoinExecution:
    """Generation-guarded at-most-once sequence-three execution state."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployScyllaSequenceThreeJoinExecutionBinding
    state: DeployScyllaSequenceThreeJoinExecutionState
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
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_SCHEMA_VERSION
            or self.generation < 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy Scylla sequence-three join execution conflicts"
            )
        prepared = _optional_timestamp(self.prepared_at)
        created = _optional_timestamp(self.created_at)
        updated = _optional_timestamp(self.updated_at)
        started = _optional_timestamp(self.started_at)
        completed_at = _optional_timestamp(self.completed_at)
        if (
            prepared is None
            or created is None
            or updated is None
            or prepared < created
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
                "deploy Scylla sequence-three join execution timestamps conflict"
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
        if self.state is DeployScyllaSequenceThreeJoinExecutionState.PREPARED:
            valid = (
                self.invocation_count == 0
                and not self.invocation_may_have_occurred
                and not self.ordinary_authorization_consumed
                and not self.narrow_authorization_consumed
                and started is None
                and completed_at is None
                and not self.completed
                and no_result
                and not self.manual_recovery_required
            )
        elif self.state is DeployScyllaSequenceThreeJoinExecutionState.STARTED:
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
        elif self.state is DeployScyllaSequenceThreeJoinExecutionState.SUCCEEDED:
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
        elif self.state is DeployScyllaSequenceThreeJoinExecutionState.FAILED:
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
                "deploy Scylla sequence-three join execution state conflicts"
            )
        for value in (self.result_digest, self.evidence_digest):
            if value is not None:
                validate_digest(value, "sequence-three join execution digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, nested_fields={"binding"})

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaSequenceThreeJoinExecution:
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
                "state": DeployScyllaSequenceThreeJoinExecutionState,
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
            label="sequence-three join execution",
        )
        parsed["binding"] = DeployScyllaSequenceThreeJoinExecutionBinding.from_object(
            _mapping(value["binding"], "sequence-three join binding")
        )
        boundary = _optional_string(value["mutation_boundary"], "mutation boundary")
        try:
            parsed["mutation_boundary"] = (
                None if boundary is None else MutationBoundary(boundary)
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Scylla sequence-three join mutation boundary is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaSequenceThreeJoinEvidence:
    """Immutable address-free semantic evidence for sequence three."""

    generation: int
    created_at: str
    binding: DeployScyllaSequenceThreeJoinExecutionBinding
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
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EVIDENCE_SCHEMA_VERSION
    )

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
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EVIDENCE_SCHEMA_VERSION
            or self.result_schema_version != SCYLLA_BOOTSTRAP_SCHEMA_VERSION
            or self.sequence != _TARGET_SEQUENCE
            or self.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or self.status is ScyllaBootstrapStatus.NOT_PREDICTED
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.survivor_count != _CURRENT_MEMBER_COUNT
            or self.active_seed_count != 1
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
                "deploy Scylla sequence-three join semantic evidence conflicts"
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
                "deploy Scylla sequence-three join result semantics conflict"
            )
        if _optional_timestamp(self.created_at) is None:
            raise StatePersistenceError(
                "deploy Scylla sequence-three join evidence timestamp is missing"
            )
        for value in _digest_fields(self):
            if value is not None:
                validate_digest(value, "sequence-three join evidence digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, nested_fields={"binding"})

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaSequenceThreeJoinEvidence:
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
            label="sequence-three join evidence",
        )
        parsed["binding"] = DeployScyllaSequenceThreeJoinExecutionBinding.from_object(
            _mapping(value["binding"], "sequence-three join evidence binding")
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaSequenceThreeJoinExecution:
    record: DeployScyllaSequenceThreeJoinExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaSequenceThreeJoinEvidence:
    record: DeployScyllaSequenceThreeJoinEvidence
    artifact_digest: str


class DeployScyllaSequenceThreeJoinExecutionStore:
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
        self._path = deploy_scylla_sequence_three_join_execution_path(
            paths, operation_id
        )
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
    ) -> StoredDeployScyllaSequenceThreeJoinExecution:
        value, artifact_digest = self._file.read()
        record = DeployScyllaSequenceThreeJoinExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy Scylla sequence-three join execution identity conflicts"
            )
        return StoredDeployScyllaSequenceThreeJoinExecution(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaSequenceThreeJoinExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaSequenceThreeJoinExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployScyllaSequenceThreeJoinExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy Scylla sequence-three join execution operation conflicts"
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
                    "deploy Scylla sequence-three join execution changed concurrently"
                )
            _validate_execution_transition(current.record, record)
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
            or record.state is not DeployScyllaSequenceThreeJoinExecutionState.PREPARED
        ):
            raise StatePersistenceError(
                "initial deploy Scylla sequence-three join execution "
                "generation conflicts"
            )
        artifact_digest = self._file.write(
            record.to_object(), expected_digest=expected_digest
        )
        return StoredDeployScyllaSequenceThreeJoinExecution(record, artifact_digest)


class DeployScyllaSequenceThreeJoinEvidenceStore:
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
        self._path = deploy_scylla_sequence_three_join_evidence_path(
            paths, operation_id
        )
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
    ) -> StoredDeployScyllaSequenceThreeJoinEvidence:
        value, artifact_digest = self._file.read()
        record = DeployScyllaSequenceThreeJoinEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy Scylla sequence-three join evidence identity conflicts"
            )
        return StoredDeployScyllaSequenceThreeJoinEvidence(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaSequenceThreeJoinEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaSequenceThreeJoinEvidence,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployScyllaSequenceThreeJoinEvidence,
        DeployScyllaSequenceThreeJoinArtifactState,
    ]:
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
                    "deploy Scylla sequence-three join evidence is immutable"
                )
            return current, DeployScyllaSequenceThreeJoinArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaSequenceThreeJoinEvidence(record, artifact_digest),
            DeployScyllaSequenceThreeJoinArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaSequenceThreeJoinExecutionReport:
    operation_id: uuid.UUID
    execution_state: DeployScyllaSequenceThreeJoinExecutionState
    execution_artifact_state: DeployScyllaSequenceThreeJoinArtifactState
    evidence_artifact_state: DeployScyllaSequenceThreeJoinArtifactState
    execution_artifact_digest: str
    evidence_artifact_digest: str
    binding_digest: str
    authorization_artifact_digest: str
    authorization_digest: str
    ordinary_authorization_consumed: bool
    narrow_authorization_consumed: bool
    invocation_count: int
    target_digest: str
    survivor_count: int
    active_seed_count: int
    later_join_count: int
    result_digest: str
    evidence_digest: str
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    journal_status: JournalStatus
    journal_phase: OperationPhase
    stage: str = _STAGE
    scope_kind: str = _SCOPE_KIND
    target_count: int = 1
    sequence: int = _TARGET_SEQUENCE
    mode: ScyllaBootstrapMode = ScyllaBootstrapMode.JOIN_EXISTING
    bootstrapped_count: int = 1
    host_identity_count: int = 1
    ring_identity_count: int = 1
    prerequisite_revalidated_count: int = 1
    target_absence_revalidated_count: int = 1
    survivor_health_revalidated_count: int = 1
    capacity_revalidated_count: int = 1
    topology_revalidated_count: int = 1
    cql_ready_count: int = 1
    nodetool_verified_count: int = 1
    schema_agreement_count: int = 1
    streaming_complete_count: int = 1
    membership_may_have_changed_count: int = 1
    node_preserved_count: int = 1
    journal_updated: bool = False
    later_join_state: str = "waiting-for-preceding-complete-health"
    post_join_health_state: str = "not-performed"
    public_workflow_state: str = "unavailable"
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EVIDENCE_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_REPORT_SCHEMA_VERSION
    )

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
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_REPORT_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EVIDENCE_SCHEMA_VERSION
            or self.execution_state
            is not DeployScyllaSequenceThreeJoinExecutionState.SUCCEEDED
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.sequence != _TARGET_SEQUENCE
            or self.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or any(value != 1 for value in one_counts)
            or self.survivor_count != _CURRENT_MEMBER_COUNT
            or self.active_seed_count != 1
            or not self.ordinary_authorization_consumed
            or not self.narrow_authorization_consumed
            or self.manual_recovery_required
            or self.automatic_retry_allowed
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.journal_updated
            or self.later_join_state != "waiting-for-preceding-complete-health"
            or self.post_join_health_state != "not-performed"
            or self.public_workflow_state != "unavailable"
        ):
            raise StatePersistenceError(
                "deploy Scylla sequence-three join execution report conflicts"
            )
        for value in _digest_fields(self):
            if value is None:
                raise StatePersistenceError(
                    "deploy Scylla sequence-three join report digest is missing"
                )
            validate_digest(value, "sequence-three join report digest")

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
            "post_join_health": self.post_join_health_state,
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
    authorization: StoredDeployScyllaSequenceThreeJoinAuthorization
    binding: DeployScyllaSequenceThreeJoinExecutionBinding
    scope: _ExecutionScope
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport


def execute_deploy_scylla_sequence_three_join(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployScyllaSequenceThreeJoinExecutionReport:
    """Execute only the canonical authorized sequence-three join."""

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
    execution_store = DeployScyllaSequenceThreeJoinExecutionStore(paths, operation_id)
    evidence_store = DeployScyllaSequenceThreeJoinEvidenceStore(paths, operation_id)
    for path in (execution_store.path, evidence_store.path):
        validate_state_file(path, allow_missing=True)
    execution = _read_execution(execution_store, context, lock)
    evidence = _read_evidence(evidence_store, context, lock)
    _validate_prefix(context, execution, evidence)
    if (
        execution is not None
        and execution.record.state
        is DeployScyllaSequenceThreeJoinExecutionState.SUCCEEDED
    ):
        if evidence is None:
            raise StateConflictError(
                "completed deploy Scylla sequence-three join evidence is unavailable"
            )
        return _build_report(
            context,
            execution,
            evidence,
            execution_state=DeployScyllaSequenceThreeJoinArtifactState.REUSED,
            evidence_state=DeployScyllaSequenceThreeJoinArtifactState.REUSED,
        )
    if (
        execution is not None
        and execution.record.state
        is not DeployScyllaSequenceThreeJoinExecutionState.PREPARED
    ):
        raise StateConflictError(
            "deploy Scylla sequence-three join execution requires manual recovery "
            "and cannot retry"
        )

    service = AnsibleService(builder, runner)
    if service.version(lock) != toolchain:
        raise StateConflictError("deploy Scylla sequence-three join toolchain drifted")
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
            "deploy Scylla sequence-three join state drifted before prepared intent"
        )
    _validate_prefix(before_prepared, execution, evidence)
    if execution is None:
        try:
            execution = _persist_prepared(before_prepared, execution_store, lock=lock)
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy Scylla sequence-three join prepared intent persistence "
                "failed before invocation"
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
        raise StateConflictError(
            "deploy Scylla sequence-three join state drifted before start"
        )
    _validate_prefix(before_start, execution, evidence)
    try:
        execution = _persist_started(execution_store, execution, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy Scylla sequence-three join authorization consumption "
            "failed before invocation"
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
                "deploy Scylla sequence-three join command result identity conflicts"
            )
    except KeyboardInterrupt:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployScyllaSequenceThreeJoinExecutionState.INTERRUPTED,
            lock=lock,
        )
        raise AnsibleError(
            "deploy Scylla sequence-three join was interrupted; "
            "manual recovery required"
        ) from None
    except (AnsibleError, StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            (
                _failure_state(error)
                if isinstance(error, AnsibleError)
                else DeployScyllaSequenceThreeJoinExecutionState.MALFORMED_RESULT
            ),
            lock=lock,
        )
        raise AnsibleError(
            "deploy Scylla sequence-three join execution is uncertain; "
            "manual recovery required"
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
                "deploy Scylla sequence-three join state changed after invocation"
            )
    except (StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployScyllaSequenceThreeJoinExecutionState.MALFORMED_RESULT,
            lock=lock,
        )
        raise StateConflictError(
            "deploy Scylla sequence-three join state changed after invocation; "
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
                else DeployScyllaSequenceThreeJoinExecutionState.MALFORMED_RESULT
            ),
            lock=lock,
        )
        raise AnsibleError(
            "deploy Scylla sequence-three join result is not strict semantic "
            "evidence; manual recovery required"
        ) from error

    try:
        evidence, evidence_state = evidence_store.write_locked(
            evidence_record, lock=lock
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy Scylla sequence-three join evidence persistence failed; "
            "manual recovery required"
        ) from error
    terminal_state = (
        DeployScyllaSequenceThreeJoinExecutionState.SUCCEEDED
        if evidence_record.status is ScyllaBootstrapStatus.BOOTSTRAPPED
        else DeployScyllaSequenceThreeJoinExecutionState.FAILED
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
            "deploy Scylla sequence-three join terminal persistence failed; "
            "manual recovery required"
        ) from error
    if terminal_state is DeployScyllaSequenceThreeJoinExecutionState.FAILED:
        raise AnsibleError(
            "deploy Scylla sequence-three join preserved strict failure evidence; "
            "manual recovery required and automatic retry is forbidden"
        )
    return _build_report(
        context,
        execution,
        evidence,
        execution_state=DeployScyllaSequenceThreeJoinArtifactState.UPDATED,
        evidence_state=evidence_state,
    )


def deploy_scylla_sequence_three_join_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths,
        operation_id,
        DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_FILENAME_SUFFIX,
    )


def deploy_scylla_sequence_three_join_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _artifact_path(
        paths,
        operation_id,
        DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EVIDENCE_FILENAME_SUFFIX,
    )


def deploy_scylla_sequence_three_join_execution_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_FILENAME_SUFFIX
    )


def deploy_scylla_sequence_three_join_evidence_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EVIDENCE_FILENAME_SUFFIX
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
    authorized = _load_sequence_three_join_authorization_context(
        paths, operation_id, lock=lock
    )
    scope = _derive_sequence_three_join_scope(authorized)
    chain = authorized.chain
    configure = _load_reconciliation_context(paths, operation_id, lock=lock)
    current = _loaded(configure.authorization_context)
    planning = current.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    inventory = deploy.inventory
    journal = deploy.journal
    readiness_record = planning.readiness.record
    identity = chain.post_join_health_evidence.record.binding
    if (
        identity.cluster_uuid != metadata.cluster_uuid
        or identity.cluster_name != metadata.cluster_name
        or journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
        or scope.sequence != _TARGET_SEQUENCE
        or scope.mode is not ScyllaBootstrapMode.JOIN_EXISTING
        or readiness_record.executable_identity_digest != executable_identity_digest
        or readiness_record.toolchain_evidence_digest != toolchain_evidence_digest
        or readiness_record.playbook_version != str(toolchain.core)
        or readiness_record.inventory_version != str(toolchain.core)
        or readiness_record.remote_playbook_status != "not-performed"
    ):
        raise StateConflictError(
            "deploy Scylla sequence-three join journal, readiness, or "
            "toolchain conflicts"
        )
    readiness = _reconstructed_readiness(planning.base)
    if readiness_binding_digest(readiness) != readiness_record.readiness_digest:
        raise StateConflictError("deploy Scylla sequence-three join readiness is stale")
    readiness.require_ready(OperationClassification.SENSITIVE)

    authorization_store = DeployScyllaSequenceThreeJoinAuthorizationStore(
        paths, operation_id
    )
    validate_state_file(authorization_store.path, allow_missing=True)
    if not authorization_store.path.exists():
        raise StateConflictError(
            "deploy Scylla sequence-three join execution requires "
            "immutable authorization"
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
        or authorization.record.scope.sequence != _TARGET_SEQUENCE
        or authorization.record.scope.mode is not ScyllaBootstrapMode.JOIN_EXISTING
    ):
        raise StateConflictError(
            "deploy Scylla sequence-three join authorization is stale or consumed"
        )

    definition = get_playbook(_PLAYBOOK)
    source_digest = _playbook_source_digest(current.source, _PLAYBOOK)
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
            "deploy Scylla sequence-three join catalog or source policy conflicts"
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
        raise StateConflictError(
            "deploy Scylla sequence-three join target is ambiguous"
        )
    stable_id = matching[0]
    host = hosts[stable_id]
    if not isinstance(host.scylla_datacenter, str) or not isinstance(
        host.scylla_rack, str
    ):
        raise StateConflictError(
            "deploy Scylla sequence-three join topology is incomplete"
        )
    survivor_ids = chain.survivor_ids
    if (
        survivor_ids != tuple(sorted(set(survivor_ids)))
        or len(survivor_ids) != _CURRENT_MEMBER_COUNT
        or _digest_object(list(survivor_ids)) != scope.survivor_set_digest
        or stable_id in survivor_ids
    ):
        raise StateConflictError(
            "deploy Scylla sequence-three join survivor membership conflicts"
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
            "deploy Scylla sequence-three join prerequisite membership conflicts"
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
    plan_step = chain.plan_steps[_TARGET_SEQUENCE - 1]
    preceding_step = chain.plan_steps[_TARGET_SEQUENCE - 2]
    safety_step = authorized.safety_reconciliation.record.steps[_TARGET_SEQUENCE - 1]
    health_step = chain.health_steps[_TARGET_SEQUENCE - 1]
    capacity_digest = _digest_object(
        {
            "capacity_bytes": storage.capacity_bytes,
            "device_set_digest": storage.device_set_digest,
            "stable_id": stable_id,
        }
    )
    if (
        plan_step.sequence != _TARGET_SEQUENCE
        or plan_step.mode is not ScyllaBootstrapMode.JOIN_EXISTING
        or plan_step.preceding_step_digest != preceding_step.step_digest
        or preceding_step.sequence != _CURRENT_MEMBER_COUNT
        or scope.target_digest != _digest_object(stable_id)
        or scope.bootstrap_plan_step_digest != plan_step.step_digest
        or scope.post_join_health_step_digest != health_step.step_digest
        or scope.safety_step_digest != safety_step.step_digest
        or safety_step.status
        is not DeployScyllaSequenceThreeSafetyStepStatus.AUTHORIZATION_REQUIRED
        or safety_step.authorization_state != "authorization-required"
        or safety_step.blockers != ("join-authorization-not-collected",)
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
        or scope.target_capacity_evidence_digest != capacity_digest
        or scope.playbook_source_digest != source_digest
        or scope.topology_digest != chain.current_topology_digest
        or scope.schema_digest != chain.current_schema_digest
        or scope.membership_digest != chain.current_membership_digest
        or scope.host_mapping_digest != chain.current_host_mapping_digest
        or _digest_object(host.scylla_datacenter) != plan_step.datacenter_digest
        or _digest_object(host.scylla_rack) != plan_step.rack_digest
        or set(file_digests) != {"cassandra-rackdc.properties", "scylla.yaml"}
        or any(not _is_digest(value) for value in file_digests.values())
    ):
        raise StateConflictError(
            "deploy Scylla sequence-three join target, health, topology, seed, "
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
            "deploy Scylla sequence-three join anchored command policy conflicts"
        )
    execution_scope_digest = _digest_object(
        {
            "authorization_scope_digest": scope.scope_digest,
            "command_digest": command_digest,
            "mode": ScyllaBootstrapMode.JOIN_EXISTING.value,
            "plan_step_digest": scope.bootstrap_plan_step_digest,
            "sequence": _TARGET_SEQUENCE,
            "source_digest": source_digest,
            "target_digest": scope.target_digest,
            "variables_digest": variables_digest,
        }
    )
    later = authorized.safety_reconciliation.record.steps[_TARGET_SEQUENCE:]
    if any(
        item.status is not DeployScyllaSequenceThreeSafetyStepStatus.WAITING
        or item.authorization_state != "waiting"
        or item.blockers != ("preceding-join-not-completed",)
        for item in later
    ):
        raise StateConflictError(
            "deploy Scylla sequence-three join later sequence scope advanced"
        )
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
    trust = planning.base.trust
    bootstrap_context = chain.bootstrap_context_artifact_digest
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
        "bootstrap_context_artifact_digest": bootstrap_context,
        "bootstrap_context_record_digest": chain.bootstrap_context_record_digest,
        "bootstrap_plan_artifact_digest": chain.bootstrap_plan_artifact_digest,
        "bootstrap_plan_digest": chain.bootstrap_plan_digest,
        "first_join_authorization_artifact_digest": (
            chain.first_join_authorization.artifact_digest
        ),
        "first_join_authorization_digest": (
            chain.first_join_authorization.record.authorization_digest
        ),
        "first_join_execution_artifact_digest": (
            chain.first_join_execution.artifact_digest
        ),
        "first_join_execution_binding_digest": (
            chain.first_join_execution.record.binding.binding_digest
        ),
        "first_join_evidence_artifact_digest": (
            chain.first_join_evidence.artifact_digest
        ),
        "first_join_evidence_digest": chain.first_join_evidence.record.evidence_digest,
        "post_join_health_execution_artifact_digest": (
            chain.post_join_health_execution.artifact_digest
        ),
        "post_join_health_evidence_artifact_digest": (
            chain.post_join_health_evidence.artifact_digest
        ),
        "post_join_health_evidence_digest": (
            chain.post_join_health_evidence.record.evidence_digest
        ),
        "post_join_health_reconciliation_artifact_digest": (
            chain.post_join_health_reconciliation.artifact_digest
        ),
        "post_join_health_reconciliation_digest": (
            chain.post_join_health_reconciliation.record.reconciliation_digest
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
        "current_state_digest": authorization.record.current_state_digest,
        "validated_chain_digest": authorization.record.validated_chain_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": readiness_record.record_digest,
        "catalog_digest": current.catalog_digest,
        "source_version": current.source.version,
        "source_digest": current.source.digest,
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
        "sequence": _TARGET_SEQUENCE,
        "target_digest": scope.target_digest,
        "plan_step_digest": scope.bootstrap_plan_step_digest,
        "preceding_step_digest": plan_step.preceding_step_digest,
        "post_join_health_step_digest": scope.post_join_health_step_digest,
        "sequence_three_safety_step_digest": scope.safety_step_digest,
        "survivor_count": scope.survivor_count,
        "survivor_set_digest": scope.survivor_set_digest,
        "survivor_health_digest": scope.survivor_health_digest,
        "active_seed_count": scope.active_seed_count,
        "active_seed_set_digest": scope.active_seed_set_digest,
        "topology_digest": scope.topology_digest,
        "target_topology_digest": scope.target_topology_digest,
        "schema_digest": scope.schema_digest,
        "membership_digest": scope.membership_digest,
        "host_mapping_digest": scope.host_mapping_digest,
        "seed_policy_digest": scope.seed_policy_digest,
        "package_version_digest": scope.package_version_digest,
        "storage_evidence_digest": scope.storage_evidence_digest,
        "configuration_evidence_digest": scope.configuration_evidence_digest,
        "capacity_evidence_digest": scope.target_capacity_evidence_digest,
        "backup_policy_evidence_digest": scope.backup_policy_evidence_digest,
        "capacity_policy_evidence_digest": scope.capacity_policy_evidence_digest,
        "quorum_evidence_digest": scope.quorum_evidence_digest,
        "replication_evidence_digest": scope.replication_evidence_digest,
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
        binding=DeployScyllaSequenceThreeJoinExecutionBinding(
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
) -> DeployScyllaSequenceThreeJoinEvidence:
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.SENSITIVE
        or result.check_mode
        or result.scylla_bootstrap is not None
    ):
        raise AnsibleResultError(
            "deploy Scylla sequence-three join strict result identity conflicts"
        )
    try:
        parsed = parse_scylla_bootstrap_execution(
            result.stdout,
            expected_payload=dict(context.scope.payload),
            exit_code=result.exit_code,
        )
    except AnsibleError as error:
        raise AnsibleResultError(
            "deploy Scylla sequence-three join strict result is malformed"
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
        "sequence": _TARGET_SEQUENCE,
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
    return DeployScyllaSequenceThreeJoinEvidence(**values)  # type: ignore[arg-type]


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
        raise AnsibleResultError(
            "deploy Scylla sequence-three join result scope conflicts"
        )
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
                "deploy Scylla sequence-three join success evidence conflicts"
            )
        return
    if evidence.status is not ScyllaBootstrapStatus.FAILED:
        raise AnsibleResultError(
            "deploy Scylla sequence-three join check-mode result is forbidden"
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
            "deploy Scylla sequence-three join failure recovery evidence conflicts"
        )


def _read_execution(
    store: DeployScyllaSequenceThreeJoinExecutionStore,
    context: _ExecutionContext,
    lock: ClusterLock,
) -> StoredDeployScyllaSequenceThreeJoinExecution | None:
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
    store: DeployScyllaSequenceThreeJoinEvidenceStore,
    context: _ExecutionContext,
    lock: ClusterLock,
) -> StoredDeployScyllaSequenceThreeJoinEvidence | None:
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
    execution: StoredDeployScyllaSequenceThreeJoinExecution | None,
    evidence: StoredDeployScyllaSequenceThreeJoinEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "deploy Scylla sequence-three join evidence exists without execution"
            )
        return
    record = execution.record
    if (
        record.binding != context.binding
        or record.stable_id != context.scope.stable_id
        or record.mode is not ScyllaBootstrapMode.JOIN_EXISTING
    ):
        raise StateConflictError(
            "deploy Scylla sequence-three join execution provenance is stale"
        )
    if evidence is None:
        if record.state in {
            DeployScyllaSequenceThreeJoinExecutionState.SUCCEEDED,
            DeployScyllaSequenceThreeJoinExecutionState.FAILED,
        }:
            raise StateConflictError(
                "deploy Scylla sequence-three join terminal evidence is missing"
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
            DeployScyllaSequenceThreeJoinExecutionState.STARTED,
            DeployScyllaSequenceThreeJoinExecutionState.SUCCEEDED,
            DeployScyllaSequenceThreeJoinExecutionState.FAILED,
        }
    ):
        raise StateConflictError(
            "deploy Scylla sequence-three join execution and evidence conflict"
        )


def _persist_prepared(
    context: _ExecutionContext,
    store: DeployScyllaSequenceThreeJoinExecutionStore,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaSequenceThreeJoinExecution:
    now = _timestamp()
    return store.write_locked(
        DeployScyllaSequenceThreeJoinExecution(
            generation=1,
            created_at=now,
            updated_at=now,
            binding=context.binding,
            state=DeployScyllaSequenceThreeJoinExecutionState.PREPARED,
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
    store: DeployScyllaSequenceThreeJoinExecutionStore,
    current: StoredDeployScyllaSequenceThreeJoinExecution,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaSequenceThreeJoinExecution:
    if current.record.state is not DeployScyllaSequenceThreeJoinExecutionState.PREPARED:
        raise StateConflictError(
            "deploy Scylla sequence-three join start requires prepared intent"
        )
    now = _timestamp()
    return store.write_locked(
        replace(
            current.record,
            generation=current.record.generation + 1,
            updated_at=now,
            state=DeployScyllaSequenceThreeJoinExecutionState.STARTED,
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
    store: DeployScyllaSequenceThreeJoinExecutionStore,
    current: StoredDeployScyllaSequenceThreeJoinExecution,
    state: DeployScyllaSequenceThreeJoinExecutionState,
    *,
    lock: ClusterLock,
) -> None:
    try:
        _persist_uncertain(store, current, state, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy Scylla sequence-three join uncertain outcome persistence failed; "
            "manual recovery required"
        ) from error


def _persist_uncertain(
    store: DeployScyllaSequenceThreeJoinExecutionStore,
    current: StoredDeployScyllaSequenceThreeJoinExecution,
    state: DeployScyllaSequenceThreeJoinExecutionState,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaSequenceThreeJoinExecution:
    if (
        current.record.state is not DeployScyllaSequenceThreeJoinExecutionState.STARTED
        or state
        not in {
            DeployScyllaSequenceThreeJoinExecutionState.FAILED,
            DeployScyllaSequenceThreeJoinExecutionState.TIMED_OUT,
            DeployScyllaSequenceThreeJoinExecutionState.INTERRUPTED,
            DeployScyllaSequenceThreeJoinExecutionState.UNREACHABLE,
            DeployScyllaSequenceThreeJoinExecutionState.MALFORMED_RESULT,
        }
    ):
        raise StatePersistenceError(
            "deploy Scylla sequence-three join uncertain transition conflicts"
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
    store: DeployScyllaSequenceThreeJoinExecutionStore,
    current: StoredDeployScyllaSequenceThreeJoinExecution,
    *,
    evidence: DeployScyllaSequenceThreeJoinEvidence,
    exit_code: int,
    state: DeployScyllaSequenceThreeJoinExecutionState,
    lock: ClusterLock,
) -> StoredDeployScyllaSequenceThreeJoinExecution:
    if (
        current.record.state is not DeployScyllaSequenceThreeJoinExecutionState.STARTED
        or state
        not in {
            DeployScyllaSequenceThreeJoinExecutionState.SUCCEEDED,
            DeployScyllaSequenceThreeJoinExecutionState.FAILED,
        }
        or (state is DeployScyllaSequenceThreeJoinExecutionState.SUCCEEDED)
        != (evidence.status is ScyllaBootstrapStatus.BOOTSTRAPPED)
    ):
        raise StateConflictError(
            "deploy Scylla sequence-three join terminal transition conflicts"
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
    execution: StoredDeployScyllaSequenceThreeJoinExecution,
    evidence: StoredDeployScyllaSequenceThreeJoinEvidence,
    *,
    execution_state: DeployScyllaSequenceThreeJoinArtifactState,
    evidence_state: DeployScyllaSequenceThreeJoinArtifactState,
) -> DeployScyllaSequenceThreeJoinExecutionReport:
    record = evidence.record
    if (
        execution.record.state
        is not DeployScyllaSequenceThreeJoinExecutionState.SUCCEEDED
        or not execution.record.completed
        or record.status is not ScyllaBootstrapStatus.BOOTSTRAPPED
    ):
        raise StateConflictError(
            "deploy Scylla sequence-three join execution is not successful"
        )
    return DeployScyllaSequenceThreeJoinExecutionReport(
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
        invocation_count=execution.record.invocation_count,
        target_digest=context.binding.target_digest,
        survivor_count=record.survivor_count,
        active_seed_count=record.active_seed_count,
        later_join_count=context.binding.later_join_count,
        result_digest=record.result_digest,
        evidence_digest=record.evidence_digest,
        manual_recovery_required=False,
        automatic_retry_allowed=False,
        journal_status=context.binding.journal_status,
        journal_phase=context.binding.journal_phase,
    )


def _validate_execution_transition(
    current: DeployScyllaSequenceThreeJoinExecution,
    replacement: DeployScyllaSequenceThreeJoinExecution,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or current.completed
    ):
        raise StatePersistenceError(
            "deploy Scylla sequence-three join execution transition is invalid"
        )
    if current.state is DeployScyllaSequenceThreeJoinExecutionState.PREPARED:
        valid = replacement.state is DeployScyllaSequenceThreeJoinExecutionState.STARTED
    elif current.state is DeployScyllaSequenceThreeJoinExecutionState.STARTED:
        valid = replacement.state not in {
            DeployScyllaSequenceThreeJoinExecutionState.PREPARED,
            DeployScyllaSequenceThreeJoinExecutionState.STARTED,
        }
    else:
        valid = False
    if not valid:
        raise StatePersistenceError(
            "deploy Scylla sequence-three join execution transition conflicts"
        )


def _binding_digest(record: DeployScyllaSequenceThreeJoinExecutionBinding) -> str:
    return _binding_digest_from_values(record.to_object())


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for (
        name,
        field,
    ) in DeployScyllaSequenceThreeJoinExecutionBinding.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["binding_digest"] = ""
    return _digest_object(value)


def _evidence_digest(record: DeployScyllaSequenceThreeJoinEvidence) -> str:
    return _evidence_digest_from_values(record.to_object())


def _evidence_digest_from_values(values: Mapping[str, object]) -> str:
    value = _json_object(values)
    for (
        name,
        field,
    ) in DeployScyllaSequenceThreeJoinEvidence.__dataclass_fields__.items():
        value.setdefault(name, _json_value(field.default))
    value["evidence_digest"] = ""
    return _digest_object(value)


def _artifact_path(paths: StatePaths, operation_id: uuid.UUID, suffix: str) -> Path:
    _require_canonical_paths(paths)
    path = paths.operations / f"{_require_operation_id(operation_id)}{suffix}"
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Scylla sequence-three join artifact path is not canonical"
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
            "cannot safely list deploy Scylla sequence-three join artifacts"
        ) from error
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EVIDENCE_FILENAME_SUFFIX,
    )
    later_fragments = (
        ".ansible-deploy-scylla-sequence-three-join-health",
        ".ansible-deploy-post-scylla-sequence-three-join",
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
                "deploy Scylla sequence-three join execution refuses later "
                "membership history"
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
                    "deploy Scylla sequence-three join artifacts are ambiguous"
                )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy Scylla sequence-three join paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy Scylla sequence-three join execution requires an "
            "acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _timestamp() -> str:
    return format_timestamp(datetime.now(UTC))


__all__ = [
    "ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_BINDING_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_SCHEMA_VERSION",
    "DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_SCYLLA_SEQUENCE_THREE_JOIN_EXECUTION_FILENAME_SUFFIX",
    "DeployScyllaSequenceThreeJoinArtifactState",
    "DeployScyllaSequenceThreeJoinEvidence",
    "DeployScyllaSequenceThreeJoinEvidenceStore",
    "DeployScyllaSequenceThreeJoinExecution",
    "DeployScyllaSequenceThreeJoinExecutionBinding",
    "DeployScyllaSequenceThreeJoinExecutionReport",
    "DeployScyllaSequenceThreeJoinExecutionState",
    "DeployScyllaSequenceThreeJoinExecutionStore",
    "StoredDeployScyllaSequenceThreeJoinEvidence",
    "StoredDeployScyllaSequenceThreeJoinExecution",
    "deploy_scylla_sequence_three_join_evidence_id_from_filename",
    "deploy_scylla_sequence_three_join_evidence_path",
    "deploy_scylla_sequence_three_join_execution_id_from_filename",
    "deploy_scylla_sequence_three_join_execution_path",
    "execute_deploy_scylla_sequence_three_join",
]
