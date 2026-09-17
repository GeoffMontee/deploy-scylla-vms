"""Durable execution ownership for the exact authorized initial Scylla seed.

This internal owner revalidates the complete deploy chain, reconstructs the
single protected initial-seed payload from canonical state, records prepared
and started intent before the controlled call, and persists only redacted
semantic evidence.  It never authorizes a join, advances the common journal,
or retries an invocation that may have crossed the membership boundary.
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
from scylla_vms.ansible.deploy_scylla_bootstrap_authorization import (
    ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_SCHEMA_VERSION,
    DeployScyllaBootstrapAuthorizationStore,
    StoredDeployScyllaBootstrapAuthorization,
    _build_authorization,
    _derive_initial_seed_scope,
    _load_authorization_context,
)
from scylla_vms.ansible.deploy_scylla_bootstrap_plan import (
    ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_SCHEMA_VERSION,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import _loaded
from scylla_vms.ansible.deploy_scylla_configure_reconciliation import (
    _load_reconciliation_context,
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
from scylla_vms.ansible.scylla_configure import (
    SeedSelectionMode,
    select_scylla_seeds,
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

ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-bootstrap-execution-binding/v1"
)
ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-bootstrap-execution/v1"
)
ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EVIDENCE_ENTRY_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-bootstrap-evidence-entry/v1"
)
ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-bootstrap-evidence/v1"
)
ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-bootstrap-execution-report/v1"
)

DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-bootstrap-execution.json"
)
DEPLOY_SCYLLA_BOOTSTRAP_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-bootstrap-evidence.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "scylla-bootstrap"
_STAGE = "post-scylla-configure-bootstrap-initial-seed"
_SCOPE_KIND = "initial-seed-first-membership-start"
_BOOTSTRAP_TIMEOUT_SECONDS = 7200
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SUCCESS_BLOCKERS: tuple[str, ...] = ()
_NEVER_JOINED_BLOCKERS = ("execution-failed",)
_MAY_HAVE_JOINED_BLOCKERS = ("join-incomplete",)


class DeployScyllaBootstrapExecutionState(StrEnum):
    """Durable at-most-once states for the sole initial-seed attempt."""

    PREPARED = "prepared"
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"


class DeployScyllaBootstrapArtifactState(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployScyllaBootstrapExecutionBinding:
    """Address-free full-chain, authorization, source, and command binding."""

    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    context_artifact_digest: str
    context_record_digest: str
    plan_artifact_digest: str
    plan_digest: str
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_scope_digest: str
    authorization_proof_digest: str
    validated_chain_digest: str
    post_configure_artifact_digest: str
    storage_evidence_artifact_digest: str
    install_evidence_artifact_digest: str
    configure_evidence_artifact_digest: str
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
    target_digest: str
    plan_step_digest: str
    topology_digest: str
    target_topology_digest: str
    seed_policy_digest: str
    package_version_digest: str
    storage_evidence_digest: str
    configuration_evidence_digest: str
    capacity_evidence_digest: str
    prerequisite_digest: str
    variables_digest: str
    command_digest: str
    execution_scope_digest: str
    binding_digest: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_SCHEMA_VERSION
    )
    context_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION
    plan_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_SCHEMA_VERSION
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_BINDING_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_BINDING_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_AUTHORIZATION_SCHEMA_VERSION
            or self.context_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION
            or self.plan_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap execution binding is invalid"
            )
        validate_cluster_name(self.cluster_name)
        for count in (
            self.journal_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
        ):
            _positive_integer(count, "deploy Scylla bootstrap binding count")
        for value in _digest_fields(self):
            if value is not None:
                validate_digest(value, "deploy Scylla bootstrap binding digest")
        _validate_toolchain_version(self.toolchain_version)
        if self.binding_digest != _binding_digest(self):
            raise StatePersistenceError(
                "deploy Scylla bootstrap execution binding digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaBootstrapExecutionBinding:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Scylla bootstrap execution binding",
        )
        integers = {
            "journal_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                if name in {"cluster_uuid", "operation_id"}:
                    parsed[name] = parse_uuid(require_string(value, name), name)
                elif name in integers:
                    parsed[name] = _integer(value[name], name)
                elif name == "journal_status":
                    parsed[name] = JournalStatus(require_string(value, name))
                elif name == "journal_phase":
                    parsed[name] = OperationPhase(require_string(value, name))
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Scylla bootstrap binding enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaBootstrapExecutionAttempt:
    """One prepared, started, or terminal initial-seed attempt."""

    stable_id: str
    mode: ScyllaBootstrapMode
    target_digest: str
    plan_step_digest: str
    authorization_scope_digest: str
    variables_digest: str
    command_digest: str
    source_digest: str
    state: DeployScyllaBootstrapExecutionState
    prepared_at: str
    started_at: str | None
    completed_at: str | None
    ordinary_authorization_consumed: bool
    narrow_authorization_consumed: bool
    invocation_may_have_occurred: bool
    exit_code: int | None
    result_digest: str | None
    evidence_digest: str | None
    mutation_boundary: MutationBoundary | None
    membership_may_have_changed: bool | None
    node_preserved: bool | None
    remask_performed: bool | None
    manual_recovery_required: bool
    automatic_retry_allowed: bool = False
    restart_allowed: bool = False
    destroy_allowed: bool = False
    removenode_allowed: bool = False
    result_schema_version: str = SCYLLA_BOOTSTRAP_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.mode is not ScyllaBootstrapMode.INITIAL_SEED
            or not isinstance(self.state, DeployScyllaBootstrapExecutionState)
            or self.result_schema_version != SCYLLA_BOOTSTRAP_SCHEMA_VERSION
            or self.automatic_retry_allowed
            or self.restart_allowed
            or self.destroy_allowed
            or self.removenode_allowed
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap execution attempt is invalid"
            )
        for value in (
            self.target_digest,
            self.plan_step_digest,
            self.authorization_scope_digest,
            self.variables_digest,
            self.command_digest,
            self.source_digest,
            self.result_digest,
            self.evidence_digest,
        ):
            if value is not None:
                validate_digest(value, "deploy Scylla bootstrap attempt digest")
        prepared = parse_timestamp(self.prepared_at)
        started = _optional_timestamp(self.started_at)
        completed = _optional_timestamp(self.completed_at)
        if (
            (started is not None and started < prepared)
            or (completed is not None and started is None)
            or (completed is not None and started is not None and completed < started)
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap attempt timestamps conflict"
            )
        consumed = (
            self.ordinary_authorization_consumed and self.narrow_authorization_consumed
        )
        no_semantic_result = (
            self.exit_code is None
            and self.result_digest is None
            and self.evidence_digest is None
            and self.mutation_boundary is None
            and self.membership_may_have_changed is None
            and self.node_preserved is None
            and self.remask_performed is None
        )
        if self.state is DeployScyllaBootstrapExecutionState.PREPARED:
            valid = (
                started is None
                and completed is None
                and not consumed
                and not self.ordinary_authorization_consumed
                and not self.narrow_authorization_consumed
                and not self.invocation_may_have_occurred
                and no_semantic_result
                and not self.manual_recovery_required
            )
        elif self.state is DeployScyllaBootstrapExecutionState.STARTED:
            valid = (
                started is not None
                and completed is None
                and consumed
                and self.invocation_may_have_occurred
                and no_semantic_result
                and self.manual_recovery_required
            )
        elif self.state is DeployScyllaBootstrapExecutionState.SUCCEEDED:
            valid = (
                started is not None
                and completed is not None
                and consumed
                and self.invocation_may_have_occurred
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
        elif self.state is DeployScyllaBootstrapExecutionState.FAILED:
            valid = (
                started is not None
                and completed is not None
                and consumed
                and self.invocation_may_have_occurred
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
                started is not None
                and completed is not None
                and consumed
                and self.invocation_may_have_occurred
                and no_semantic_result
                and self.manual_recovery_required
            )
        if not valid:
            raise StatePersistenceError(
                "deploy Scylla bootstrap attempt state conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaBootstrapExecutionAttempt:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Scylla bootstrap execution attempt",
        )
        try:
            boundary = _optional_string(value["mutation_boundary"], "mutation boundary")
            return cls(
                stable_id=require_string(value, "stable_id"),
                mode=ScyllaBootstrapMode(require_string(value, "mode")),
                target_digest=require_string(value, "target_digest"),
                plan_step_digest=require_string(value, "plan_step_digest"),
                authorization_scope_digest=require_string(
                    value, "authorization_scope_digest"
                ),
                variables_digest=require_string(value, "variables_digest"),
                command_digest=require_string(value, "command_digest"),
                source_digest=require_string(value, "source_digest"),
                state=DeployScyllaBootstrapExecutionState(
                    require_string(value, "state")
                ),
                prepared_at=require_string(value, "prepared_at"),
                started_at=_optional_string(value["started_at"], "started_at"),
                completed_at=_optional_string(value["completed_at"], "completed_at"),
                ordinary_authorization_consumed=_boolean(
                    value["ordinary_authorization_consumed"], "ordinary consumption"
                ),
                narrow_authorization_consumed=_boolean(
                    value["narrow_authorization_consumed"], "narrow consumption"
                ),
                invocation_may_have_occurred=_boolean(
                    value["invocation_may_have_occurred"], "invocation state"
                ),
                exit_code=_optional_integer(value["exit_code"], "exit code"),
                result_digest=_optional_string(value["result_digest"], "result digest"),
                evidence_digest=_optional_string(
                    value["evidence_digest"], "evidence digest"
                ),
                mutation_boundary=(
                    None if boundary is None else MutationBoundary(boundary)
                ),
                membership_may_have_changed=_optional_boolean(
                    value["membership_may_have_changed"], "membership state"
                ),
                node_preserved=_optional_boolean(
                    value["node_preserved"], "node preservation"
                ),
                remask_performed=_optional_boolean(
                    value["remask_performed"], "remask state"
                ),
                manual_recovery_required=_boolean(
                    value["manual_recovery_required"], "manual recovery"
                ),
                automatic_retry_allowed=_boolean(
                    value["automatic_retry_allowed"], "automatic retry"
                ),
                restart_allowed=_boolean(value["restart_allowed"], "restart policy"),
                destroy_allowed=_boolean(value["destroy_allowed"], "destroy policy"),
                removenode_allowed=_boolean(
                    value["removenode_allowed"], "removenode policy"
                ),
                result_schema_version=require_string(value, "result_schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Scylla bootstrap attempt enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployScyllaBootstrapExecution:
    """Generation-guarded execution state for one exact initial seed."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployScyllaBootstrapExecutionBinding
    state: DeployScyllaBootstrapExecutionState
    ordinary_authorization_consumed: bool
    narrow_authorization_consumed: bool
    invocation_count: int
    completed: bool
    attempt: DeployScyllaBootstrapExecutionAttempt
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        invoked = self.state is not DeployScyllaBootstrapExecutionState.PREPARED
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_SCHEMA_VERSION
            or self.generation < 1
            or self.state is not self.attempt.state
            or self.ordinary_authorization_consumed != invoked
            or self.narrow_authorization_consumed != invoked
            or self.invocation_count != int(invoked)
            or self.completed
            != (
                self.state
                in {
                    DeployScyllaBootstrapExecutionState.SUCCEEDED,
                    DeployScyllaBootstrapExecutionState.FAILED,
                }
            )
            or self.attempt.ordinary_authorization_consumed
            != self.ordinary_authorization_consumed
            or self.attempt.narrow_authorization_consumed
            != self.narrow_authorization_consumed
            or parse_timestamp(self.updated_at) < parse_timestamp(self.created_at)
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap execution summary conflicts"
            )

    @property
    def manual_recovery_required(self) -> bool:
        return self.attempt.manual_recovery_required

    def to_object(self) -> dict[str, object]:
        return {
            "attempt": self.attempt.to_object(),
            "binding": self.binding.to_object(),
            "completed": self.completed,
            "created_at": self.created_at,
            "generation": self.generation,
            "invocation_count": self.invocation_count,
            "narrow_authorization_consumed": self.narrow_authorization_consumed,
            "ordinary_authorization_consumed": self.ordinary_authorization_consumed,
            "schema_version": self.schema_version,
            "state": self.state.value,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaBootstrapExecution:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Scylla bootstrap execution",
        )
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                updated_at=require_string(value, "updated_at"),
                binding=DeployScyllaBootstrapExecutionBinding.from_object(
                    _mapping(value["binding"], "binding")
                ),
                state=DeployScyllaBootstrapExecutionState(
                    require_string(value, "state")
                ),
                ordinary_authorization_consumed=_boolean(
                    value["ordinary_authorization_consumed"], "ordinary consumption"
                ),
                narrow_authorization_consumed=_boolean(
                    value["narrow_authorization_consumed"], "narrow consumption"
                ),
                invocation_count=_integer(
                    value["invocation_count"], "invocation count"
                ),
                completed=_boolean(value["completed"], "completion"),
                attempt=DeployScyllaBootstrapExecutionAttempt.from_object(
                    _mapping(value["attempt"], "attempt")
                ),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Scylla bootstrap execution state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployScyllaBootstrapEvidenceEntry:
    """Strict redacted source-contract evidence for the initial seed."""

    stable_id: str
    mode: ScyllaBootstrapMode
    status: ScyllaBootstrapStatus
    datacenter_digest: str
    rack_digest: str
    topology_digest: str
    package_version_digest: str
    prerequisite_digest: str
    host_id_digest: str | None
    ring_membership_digest: str | None
    blocker_count: int
    blocker_digest: str
    pre_start_revalidated: bool
    unmask_start_boundary_crossed: bool
    cql_ready: bool
    nodetool_membership_verified: bool
    schema_agreement: bool
    streaming_complete: bool
    service_active: bool
    never_joined_proven: bool
    membership_may_have_changed: bool
    remask_performed: bool
    node_preserved: bool
    recovery_required: bool
    automatic_retry_allowed: bool
    restart_performed: bool
    destroy_performed: bool
    removenode_performed: bool
    mutation_boundary: MutationBoundary
    variables_digest: str
    command_digest: str
    source_digest: str
    result_digest: str
    evidence_digest: str
    result_schema_version: str = SCYLLA_BOOTSTRAP_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EVIDENCE_ENTRY_SCHEMA_VERSION

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
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EVIDENCE_ENTRY_SCHEMA_VERSION
            or self.result_schema_version != SCYLLA_BOOTSTRAP_SCHEMA_VERSION
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.mode is not ScyllaBootstrapMode.INITIAL_SEED
            or self.status is ScyllaBootstrapStatus.NOT_PREDICTED
            or self.blocker_count < 0
            or not self.pre_start_revalidated
            or not self.unmask_start_boundary_crossed
            or self.never_joined_proven != never_joined
            or self.membership_may_have_changed != may_have_joined
            or self.remask_performed != never_joined
            or not self.node_preserved
            or self.recovery_required != (not success)
            or self.automatic_retry_allowed
            or self.restart_performed
            or self.destroy_performed
            or self.removenode_performed
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap semantic evidence conflicts"
            )
        if success:
            valid = (
                self.host_id_digest is not None
                and self.ring_membership_digest is not None
                and self.blocker_count == 0
                and self.cql_ready
                and self.nodetool_membership_verified
                and self.schema_agreement
                and self.streaming_complete
                and self.service_active
                and not self.remask_performed
            )
        elif never_joined:
            valid = (
                self.host_id_digest is None
                and self.blocker_count == 1
                and not self.cql_ready
                and not self.nodetool_membership_verified
                and not self.schema_agreement
                and not self.streaming_complete
                and not self.service_active
            )
        else:
            valid = (
                self.status is ScyllaBootstrapStatus.FAILED
                and self.host_id_digest is None
                and self.ring_membership_digest is not None
                and self.blocker_count == 1
                and not self.cql_ready
                and not self.nodetool_membership_verified
                and not self.schema_agreement
                and not self.streaming_complete
                and not self.service_active
                and not self.remask_performed
            )
        if not valid:
            raise StatePersistenceError(
                "deploy Scylla bootstrap result semantics conflict"
            )
        for value in _digest_fields(self):
            if value is not None:
                validate_digest(value, "deploy Scylla bootstrap evidence digest")
        if self.evidence_digest != _evidence_entry_digest(self):
            raise StatePersistenceError(
                "deploy Scylla bootstrap evidence digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaBootstrapEvidenceEntry:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Scylla bootstrap evidence entry",
        )
        booleans = {
            "pre_start_revalidated",
            "unmask_start_boundary_crossed",
            "cql_ready",
            "nodetool_membership_verified",
            "schema_agreement",
            "streaming_complete",
            "service_active",
            "never_joined_proven",
            "membership_may_have_changed",
            "remask_performed",
            "node_preserved",
            "recovery_required",
            "automatic_retry_allowed",
            "restart_performed",
            "destroy_performed",
            "removenode_performed",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                if name == "blocker_count":
                    parsed[name] = _integer(value[name], name)
                elif name in booleans:
                    parsed[name] = _boolean(value[name], name)
                elif name == "mode":
                    parsed[name] = ScyllaBootstrapMode(require_string(value, name))
                elif name == "status":
                    parsed[name] = ScyllaBootstrapStatus(require_string(value, name))
                elif name == "mutation_boundary":
                    parsed[name] = MutationBoundary(require_string(value, name))
                elif name in {"host_id_digest", "ring_membership_digest"}:
                    parsed[name] = _optional_string(value[name], name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Scylla bootstrap evidence enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaBootstrapEvidence:
    """Owner-only semantic evidence for the sole exact attempt."""

    generation: int
    created_at: str
    binding: DeployScyllaBootstrapExecutionBinding
    entry: DeployScyllaBootstrapEvidenceEntry
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EVIDENCE_SCHEMA_VERSION
            or self.generation != 1
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap evidence record conflicts"
            )
        parse_timestamp(self.created_at)

    def to_object(self) -> dict[str, object]:
        return {
            "binding": self.binding.to_object(),
            "created_at": self.created_at,
            "entry": self.entry.to_object(),
            "generation": self.generation,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaBootstrapEvidence:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Scylla bootstrap evidence",
        )
        return cls(
            generation=_integer(value["generation"], "generation"),
            created_at=require_string(value, "created_at"),
            binding=DeployScyllaBootstrapExecutionBinding.from_object(
                _mapping(value["binding"], "binding")
            ),
            entry=DeployScyllaBootstrapEvidenceEntry.from_object(
                _mapping(value["entry"], "entry")
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaBootstrapExecution:
    record: DeployScyllaBootstrapExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaBootstrapEvidence:
    record: DeployScyllaBootstrapEvidence
    artifact_digest: str


class DeployScyllaBootstrapExecutionStore:
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
        self._path = deploy_scylla_bootstrap_execution_path(paths, operation_id)
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
    ) -> StoredDeployScyllaBootstrapExecution:
        value, digest = self._file.read()
        record = DeployScyllaBootstrapExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap execution identity conflicts"
            )
        return StoredDeployScyllaBootstrapExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaBootstrapExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaBootstrapExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployScyllaBootstrapExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy Scylla bootstrap execution operation conflicts"
            )
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial deploy Scylla bootstrap generation conflicts"
                )
        else:
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
                    "deploy Scylla bootstrap execution changed concurrently"
                )
            _validate_execution_transition(current.record, record)
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployScyllaBootstrapExecution(record, digest)


class DeployScyllaBootstrapEvidenceStore:
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
        self._path = deploy_scylla_bootstrap_evidence_path(paths, operation_id)
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
    ) -> StoredDeployScyllaBootstrapEvidence:
        value, digest = self._file.read()
        record = DeployScyllaBootstrapEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap evidence identity conflicts"
            )
        return StoredDeployScyllaBootstrapEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaBootstrapEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaBootstrapEvidence,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployScyllaBootstrapEvidence,
        DeployScyllaBootstrapArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy Scylla bootstrap evidence operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy Scylla bootstrap evidence is immutable"
                )
            return current, DeployScyllaBootstrapArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaBootstrapEvidence(record, digest),
            DeployScyllaBootstrapArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaBootstrapExecutionReport:
    """Strict count/digest/enum-only successful execution projection."""

    operation_id: uuid.UUID
    execution_state: DeployScyllaBootstrapExecutionState
    execution_artifact_state: DeployScyllaBootstrapArtifactState
    evidence_artifact_state: DeployScyllaBootstrapArtifactState
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
    mode: ScyllaBootstrapMode
    bootstrapped_count: int
    host_identity_count: int
    ring_identity_count: int
    pre_start_revalidated_count: int
    cql_ready_count: int
    nodetool_verified_count: int
    schema_agreement_count: int
    streaming_complete_count: int
    membership_may_have_changed_count: int
    node_preserved_count: int
    remask_count: int
    result_digest: str
    evidence_digest: str
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    restart_allowed: bool
    destroy_allowed: bool
    removenode_allowed: bool
    journal_status: JournalStatus
    journal_phase: OperationPhase
    journal_updated: bool = False
    join_authorization_state: str = "unavailable"
    health_reconciliation_state: str = "not-performed"
    public_workflow_state: str = "unavailable"
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EVIDENCE_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        one_counts = (
            self.invocation_count,
            self.target_count,
            self.bootstrapped_count,
            self.host_identity_count,
            self.ring_identity_count,
            self.pre_start_revalidated_count,
            self.cql_ready_count,
            self.nodetool_verified_count,
            self.schema_agreement_count,
            self.streaming_complete_count,
            self.membership_may_have_changed_count,
            self.node_preserved_count,
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_REPORT_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EVIDENCE_SCHEMA_VERSION
            or self.execution_state is not DeployScyllaBootstrapExecutionState.SUCCEEDED
            or not self.ordinary_authorization_consumed
            or not self.narrow_authorization_consumed
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.mode is not ScyllaBootstrapMode.INITIAL_SEED
            or any(value != 1 for value in one_counts)
            or self.remask_count
            or self.manual_recovery_required
            or self.automatic_retry_allowed
            or self.restart_allowed
            or self.destroy_allowed
            or self.removenode_allowed
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.journal_updated
            or self.join_authorization_state != "unavailable"
            or self.health_reconciliation_state != "not-performed"
            or self.public_workflow_state != "unavailable"
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap execution report conflicts"
            )
        for value in _digest_fields(self):
            if value is not None:
                validate_digest(value, "deploy Scylla bootstrap report digest")

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
                "cql_ready_count": self.cql_ready_count,
                "digest": self.evidence_digest,
                "host_identity_count": self.host_identity_count,
                "membership_may_have_changed_count": (
                    self.membership_may_have_changed_count
                ),
                "node_preserved_count": self.node_preserved_count,
                "nodetool_verified_count": self.nodetool_verified_count,
                "pre_start_revalidated_count": self.pre_start_revalidated_count,
                "remask_count": self.remask_count,
                "ring_identity_count": self.ring_identity_count,
                "schema_agreement_count": self.schema_agreement_count,
                "schema_version": self.evidence_schema_version,
                "streaming_complete_count": self.streaming_complete_count,
            },
            "execution": {
                "artifact_digest": self.execution_artifact_digest,
                "artifact_state": self.execution_artifact_state.value,
                "automatic_retry_allowed": self.automatic_retry_allowed,
                "binding_digest": self.binding_digest,
                "destroy_allowed": self.destroy_allowed,
                "invocation_count": self.invocation_count,
                "manual_recovery_required": self.manual_recovery_required,
                "removenode_allowed": self.removenode_allowed,
                "restart_allowed": self.restart_allowed,
                "result_digest": self.result_digest,
                "schema_version": self.execution_schema_version,
                "state": self.execution_state.value,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": self.journal_updated,
            },
            "operation": {
                "health_reconciliation_state": self.health_reconciliation_state,
                "id": str(self.operation_id),
                "join_authorization_state": self.join_authorization_state,
                "kind": _OPERATION,
                "public_workflow_state": self.public_workflow_state,
            },
            "schema_version": self.schema_version,
            "scope": {
                "kind": self.scope_kind,
                "mode": self.mode.value,
                "target_count": self.target_count,
                "target_digest": self.target_digest,
            },
            "stage": self.stage,
        }


@dataclass(frozen=True, slots=True)
class _ExecutionScope:
    stable_id: str
    variables: tuple[tuple[str, object], ...]
    payload: Mapping[str, object]
    variables_digest: str
    command_digest: str
    source_digest: str


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    authorization: StoredDeployScyllaBootstrapAuthorization
    binding: DeployScyllaBootstrapExecutionBinding
    scope: _ExecutionScope
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport


def execute_deploy_scylla_bootstrap_initial_seed(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployScyllaBootstrapExecutionReport:
    """Execute only the exact authorized initial seed through a controlled runner."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _validate_toolchain_dependency(toolchain)
    executable_identity_digest = _executable_identity_digest(executables)
    toolchain_evidence_digest = _toolchain_evidence_digest(
        toolchain, executable_identity_digest
    )
    _refuse_ambiguous_or_later_artifacts(paths, operation_id)
    builder = AnsibleCommandBuilder(
        executables.playbook,
        executables.inventory,
        paths,
    )
    context = _load_execution_context(
        paths,
        operation_id,
        lock=lock,
        builder=builder,
        toolchain=toolchain,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    execution_store = DeployScyllaBootstrapExecutionStore(paths, operation_id)
    evidence_store = DeployScyllaBootstrapEvidenceStore(paths, operation_id)
    for path in (execution_store.path, evidence_store.path):
        validate_state_file(path, allow_missing=True)
    execution = (
        execution_store.read_locked(
            lock,
            expected_cluster_uuid=context.binding.cluster_uuid,
            expected_cluster_name=context.binding.cluster_name,
        )
        if execution_store.path.exists()
        else None
    )
    evidence = (
        evidence_store.read_locked(
            lock,
            expected_cluster_uuid=context.binding.cluster_uuid,
            expected_cluster_name=context.binding.cluster_name,
        )
        if evidence_store.path.exists()
        else None
    )
    _validate_prefix(context, execution, evidence)
    if (
        execution is not None
        and execution.record.state is DeployScyllaBootstrapExecutionState.SUCCEEDED
    ):
        if evidence is None:
            raise StateConflictError(
                "completed deploy Scylla bootstrap evidence is unavailable"
            )
        return _build_report(
            context,
            execution,
            evidence,
            execution_state=DeployScyllaBootstrapArtifactState.REUSED,
            evidence_state=DeployScyllaBootstrapArtifactState.REUSED,
        )
    if execution is not None and execution.record.state is not (
        DeployScyllaBootstrapExecutionState.PREPARED
    ):
        raise StateConflictError(
            "deploy Scylla bootstrap execution requires manual recovery "
            "and cannot retry"
        )

    service = AnsibleService(builder, runner)
    discovered = service.version(lock)
    if discovered != toolchain:
        raise StateConflictError("deploy Scylla bootstrap toolchain drifted")
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
            "deploy Scylla bootstrap state drifted before prepared intent"
        )
    _validate_prefix(before_prepared, execution, evidence)
    if execution is None:
        try:
            execution = _persist_prepared(before_prepared, execution_store, lock=lock)
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy Scylla bootstrap prepared intent persistence failed "
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
        raise StateConflictError("deploy Scylla bootstrap state drifted before start")
    _validate_prefix(before_start, execution, evidence)
    try:
        execution = _persist_started(execution_store, execution, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy Scylla bootstrap authorization consumption failed before invocation"
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
                "deploy Scylla bootstrap command result identity conflicts"
            )
    except KeyboardInterrupt:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployScyllaBootstrapExecutionState.INTERRUPTED,
            lock=lock,
        )
        raise AnsibleError(
            "deploy Scylla bootstrap was interrupted; manual recovery required"
        ) from None
    except (AnsibleError, StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            (
                _failure_state(error)
                if isinstance(error, AnsibleError)
                else DeployScyllaBootstrapExecutionState.MALFORMED_RESULT
            ),
            lock=lock,
        )
        raise AnsibleError(
            "deploy Scylla bootstrap execution is uncertain; manual recovery required"
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
                "deploy Scylla bootstrap state changed after invocation"
            )
    except (StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployScyllaBootstrapExecutionState.MALFORMED_RESULT,
            lock=lock,
        )
        raise StateConflictError(
            "deploy Scylla bootstrap state changed after invocation; "
            "manual recovery required"
        ) from error

    try:
        entry = _semantic_entry(before_start.scope, result)
    except (AnsibleError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            (
                _failure_state(error)
                if isinstance(error, AnsibleError)
                else DeployScyllaBootstrapExecutionState.MALFORMED_RESULT
            ),
            lock=lock,
        )
        raise AnsibleError(
            "deploy Scylla bootstrap result is not strict semantic evidence; "
            "manual recovery required"
        ) from error

    try:
        evidence_record = DeployScyllaBootstrapEvidence(
            generation=1,
            created_at=_timestamp(),
            binding=context.binding,
            entry=entry,
        )
        evidence, evidence_state = evidence_store.write_locked(
            evidence_record, lock=lock
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy Scylla bootstrap evidence persistence failed; "
            "manual recovery required"
        ) from error

    terminal_state = (
        DeployScyllaBootstrapExecutionState.SUCCEEDED
        if entry.status is ScyllaBootstrapStatus.BOOTSTRAPPED
        else DeployScyllaBootstrapExecutionState.FAILED
    )
    try:
        execution = _persist_terminal(
            execution_store,
            execution,
            entry=entry,
            exit_code=result.exit_code,
            state=terminal_state,
            lock=lock,
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy Scylla bootstrap terminal persistence failed; "
            "manual recovery required"
        ) from error
    if terminal_state is DeployScyllaBootstrapExecutionState.FAILED:
        raise AnsibleError(
            "deploy Scylla bootstrap preserved strict failure evidence; "
            "manual recovery required and automatic retry is forbidden"
        )
    return _build_report(
        context,
        execution,
        evidence,
        execution_state=DeployScyllaBootstrapArtifactState.UPDATED,
        evidence_state=evidence_state,
    )


def deploy_scylla_bootstrap_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Scylla bootstrap execution path is not canonical"
        )
    return path


def deploy_scylla_bootstrap_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_SCYLLA_BOOTSTRAP_EVIDENCE_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Scylla bootstrap evidence path is not canonical"
        )
    return path


def deploy_scylla_bootstrap_execution_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_FILENAME_SUFFIX
    )


def deploy_scylla_bootstrap_evidence_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_BOOTSTRAP_EVIDENCE_FILENAME_SUFFIX
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
    bootstrap = _load_authorization_context(paths, operation_id, lock=lock)
    context = bootstrap.context.record
    plan = bootstrap.plan.record
    configure = _load_reconciliation_context(paths, operation_id, lock=lock)
    loaded = _loaded(configure.authorization_context)
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    journal = deploy.journal
    inventory = deploy.inventory
    readiness_record = planning.readiness.record
    if (
        context.cluster_uuid != metadata.cluster_uuid
        or context.cluster_name != metadata.cluster_name
        or journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
        or context.journal_generation != journal.record.generation
        or context.journal_digest != journal.digest
        or context.request_digest != journal.record.request_digest
        or readiness_record.executable_identity_digest != executable_identity_digest
        or readiness_record.toolchain_evidence_digest != toolchain_evidence_digest
        or readiness_record.playbook_version != str(toolchain.core)
        or readiness_record.inventory_version != str(toolchain.core)
        or readiness_record.remote_playbook_status != "not-performed"
    ):
        raise StateConflictError(
            "deploy Scylla bootstrap journal, readiness, or toolchain conflicts"
        )
    readiness = _reconstructed_readiness(planning.base)
    if readiness_binding_digest(readiness) != readiness_record.readiness_digest:
        raise StateConflictError("deploy Scylla bootstrap readiness is stale")
    readiness.require_ready(OperationClassification.SENSITIVE)

    authorization_store = DeployScyllaBootstrapAuthorizationStore(paths, operation_id)
    validate_state_file(authorization_store.path, allow_missing=True)
    if not authorization_store.path.exists():
        raise StateConflictError(
            "deploy Scylla bootstrap execution requires immutable authorization"
        )
    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    scope = _derive_initial_seed_scope(context, plan)
    expected_authorization = _build_authorization(
        bootstrap,
        scope=scope,
        proof=authorization.record.proof,
        created_at=authorization.record.created_at,
    )
    if (
        authorization.record != expected_authorization
        or authorization.record.consumed
        or authorization.record.authorization_state != "authorized-pre-execution"
        or authorization.record.execution_state != "unavailable"
        or authorization.record.scope.mode is not ScyllaBootstrapMode.INITIAL_SEED
    ):
        raise StateConflictError(
            "deploy Scylla bootstrap authorization is stale or consumed"
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
            "deploy Scylla bootstrap catalog or source policy conflicts"
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
            "deploy Scylla bootstrap initial-seed target is ambiguous"
        )
    stable_id = matching[0]
    host = hosts[stable_id]
    if not isinstance(host.scylla_datacenter, str) or not isinstance(
        host.scylla_rack, str
    ):
        raise StateConflictError("deploy Scylla bootstrap topology is incomplete")

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
            "deploy Scylla bootstrap prerequisite membership conflicts"
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
    seed_policy = select_scylla_seeds(
        inventory,
        mode=SeedSelectionMode.INITIAL,
        target_logical_id=stable_id,
    )
    capacity_digest = _digest_object(
        {
            "capacity_bytes": storage.capacity_bytes,
            "device_set_digest": storage.device_set_digest,
            "stable_id": stable_id,
        }
    )
    if (
        scope.target_digest != _digest_object(stable_id)
        or scope.target_topology_digest != configuration.topology_digest
        or scope.seed_policy_digest != configuration.seed_policy_digest
        or scope.seed_policy_digest != seed_policy.digest
        or seed_ids != (stable_id,)
        or configure_payload["seed_digest"] != seed_policy.digest
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
        or scope.prerequisite_digest != plan.steps[0].prerequisite_digest
        or scope.playbook_source_digest != source_digest
        or scope.target_topology_digest != configure_payload["topology_digest"]
        or scope.seed_policy_digest != configure_payload["seed_digest"]
        or _digest_object(host.scylla_datacenter) != plan.steps[0].datacenter_digest
        or _digest_object(host.scylla_rack) != plan.steps[0].rack_digest
        or set(file_digests) != {"cassandra-rackdc.properties", "scylla.yaml"}
        or any(not _is_digest(value) for value in file_digests.values())
    ):
        raise StateConflictError(
            "deploy Scylla bootstrap target, topology, seed, configuration, "
            "storage, or version scope conflicts"
        )

    prerequisite_digests = {
        "authorization_digest": authorization.record.authorization_digest,
        "cluster_spec_digest": metadata.desired_spec.digest(),
        "config_digest": configuration.evidence_digest,
        "install_digest": install.evidence_digest,
        "inventory_digest": inventory.digest,
        "observation_digest": deploy.observation.digest,
        "seed_digest": seed_policy.digest,
        "storage_digest": storage.evidence_digest,
        "topology_digest": configuration.topology_digest,
        "trust_digest": planning.base.trust.digest,
    }
    payload: dict[str, object] = {
        "authorization": {
            "authorization_digest": authorization.record.authorization_digest,
            "capacity_check_passed": True,
            "existing_member_count": 0,
            "healthy_member_ids": [],
            "healthy_seed_ids": [],
            "intent_digest": scope.scope_digest,
            "live_cluster_state_absent": True,
            "reviewed": True,
            "schema_agreement": False,
            "target_present_in_ring": False,
            "topology_check_passed": True,
        },
        "bootstrap_timeout_seconds": _BOOTSTRAP_TIMEOUT_SECONDS,
        "cluster_uuid": str(metadata.cluster_uuid),
        "config_file_digests": file_digests,
        "datacenter": host.scylla_datacenter,
        "logical_id": stable_id,
        "mode": ScyllaBootstrapMode.INITIAL_SEED.value,
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
            "deploy Scylla bootstrap anchored command policy conflicts"
        )
    execution_scope_digest = _digest_object(
        {
            "authorization_scope_digest": scope.scope_digest,
            "command_digest": command_digest,
            "mode": ScyllaBootstrapMode.INITIAL_SEED.value,
            "plan_step_digest": scope.plan_step_digest,
            "source_digest": source_digest,
            "target_digest": scope.target_digest,
            "variables_digest": variables_digest,
        }
    )
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
        "context_artifact_digest": bootstrap.context.artifact_digest,
        "context_record_digest": context.record_digest,
        "plan_artifact_digest": bootstrap.plan.artifact_digest,
        "plan_digest": plan.plan_digest,
        "authorization_artifact_digest": authorization.artifact_digest,
        "authorization_digest": authorization.record.authorization_digest,
        "authorization_scope_digest": authorization.record.authorization_scope_digest,
        "authorization_proof_digest": authorization.record.proof.proof_digest,
        "validated_chain_digest": authorization.record.validated_chain_digest,
        "post_configure_artifact_digest": context.post_configure_artifact_digest,
        "storage_evidence_artifact_digest": (context.storage_evidence_artifact_digest),
        "install_evidence_artifact_digest": (context.install_evidence_artifact_digest),
        "configure_evidence_artifact_digest": (
            context.configure_evidence_artifact_digest
        ),
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
        "target_digest": scope.target_digest,
        "plan_step_digest": scope.plan_step_digest,
        "topology_digest": scope.topology_digest,
        "target_topology_digest": scope.target_topology_digest,
        "seed_policy_digest": scope.seed_policy_digest,
        "package_version_digest": scope.package_version_digest,
        "storage_evidence_digest": scope.storage_evidence_digest,
        "configuration_evidence_digest": scope.configuration_evidence_digest,
        "capacity_evidence_digest": scope.capacity_evidence_digest,
        "prerequisite_digest": scope.prerequisite_digest,
        "variables_digest": variables_digest,
        "command_digest": command_digest,
        "execution_scope_digest": execution_scope_digest,
        "binding_digest": "",
    }
    binding_values["binding_digest"] = _binding_digest_from_values(binding_values)
    return _ExecutionContext(
        authorization=authorization,
        binding=DeployScyllaBootstrapExecutionBinding(
            **binding_values  # type: ignore[arg-type]
        ),
        scope=_ExecutionScope(
            stable_id=stable_id,
            variables=tuple(sorted(validated.items())),
            payload=payload,
            variables_digest=variables_digest,
            command_digest=command_digest,
            source_digest=source_digest,
        ),
        metadata=metadata,
        inventory=inventory,
        readiness=readiness,
    )


def _validate_prefix(
    context: _ExecutionContext,
    execution: StoredDeployScyllaBootstrapExecution | None,
    evidence: StoredDeployScyllaBootstrapEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "deploy Scylla bootstrap evidence exists without execution"
            )
        return
    attempt = execution.record.attempt
    if (
        execution.record.binding != context.binding
        or attempt.stable_id != context.scope.stable_id
        or attempt.mode is not ScyllaBootstrapMode.INITIAL_SEED
        or attempt.target_digest != context.binding.target_digest
        or attempt.plan_step_digest != context.binding.plan_step_digest
        or attempt.authorization_scope_digest
        != context.binding.authorization_scope_digest
        or attempt.variables_digest != context.scope.variables_digest
        or attempt.command_digest != context.scope.command_digest
        or attempt.source_digest != context.scope.source_digest
    ):
        raise StateConflictError(
            "deploy Scylla bootstrap execution provenance is stale"
        )
    if evidence is None:
        if execution.record.state in {
            DeployScyllaBootstrapExecutionState.SUCCEEDED,
            DeployScyllaBootstrapExecutionState.FAILED,
        }:
            raise StateConflictError(
                "deploy Scylla bootstrap terminal evidence is missing"
            )
        return
    entry = evidence.record.entry
    if (
        evidence.record.binding != context.binding
        or entry.stable_id != context.scope.stable_id
        or entry.variables_digest != context.scope.variables_digest
        or entry.command_digest != context.scope.command_digest
        or entry.source_digest != context.scope.source_digest
        or (
            attempt.result_digest is not None
            and attempt.result_digest != entry.result_digest
        )
        or (
            attempt.evidence_digest is not None
            and attempt.evidence_digest != entry.evidence_digest
        )
        or execution.record.state
        not in {
            DeployScyllaBootstrapExecutionState.STARTED,
            DeployScyllaBootstrapExecutionState.SUCCEEDED,
            DeployScyllaBootstrapExecutionState.FAILED,
        }
    ):
        raise StateConflictError(
            "deploy Scylla bootstrap execution and evidence conflict"
        )


def _persist_prepared(
    context: _ExecutionContext,
    store: DeployScyllaBootstrapExecutionStore,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaBootstrapExecution:
    now = _timestamp()
    attempt = DeployScyllaBootstrapExecutionAttempt(
        stable_id=context.scope.stable_id,
        mode=ScyllaBootstrapMode.INITIAL_SEED,
        target_digest=context.binding.target_digest,
        plan_step_digest=context.binding.plan_step_digest,
        authorization_scope_digest=context.binding.authorization_scope_digest,
        variables_digest=context.scope.variables_digest,
        command_digest=context.scope.command_digest,
        source_digest=context.scope.source_digest,
        state=DeployScyllaBootstrapExecutionState.PREPARED,
        prepared_at=now,
        started_at=None,
        completed_at=None,
        ordinary_authorization_consumed=False,
        narrow_authorization_consumed=False,
        invocation_may_have_occurred=False,
        exit_code=None,
        result_digest=None,
        evidence_digest=None,
        mutation_boundary=None,
        membership_may_have_changed=None,
        node_preserved=None,
        remask_performed=None,
        manual_recovery_required=False,
    )
    return store.write_locked(
        DeployScyllaBootstrapExecution(
            generation=1,
            created_at=now,
            updated_at=now,
            binding=context.binding,
            state=DeployScyllaBootstrapExecutionState.PREPARED,
            ordinary_authorization_consumed=False,
            narrow_authorization_consumed=False,
            invocation_count=0,
            completed=False,
            attempt=attempt,
        ),
        expected_generation=0,
        expected_digest=None,
        lock=lock,
    )


def _persist_started(
    store: DeployScyllaBootstrapExecutionStore,
    current: StoredDeployScyllaBootstrapExecution,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaBootstrapExecution:
    if current.record.state is not DeployScyllaBootstrapExecutionState.PREPARED:
        raise StateConflictError(
            "deploy Scylla bootstrap start requires prepared intent"
        )
    now = _timestamp()
    attempt = replace(
        current.record.attempt,
        state=DeployScyllaBootstrapExecutionState.STARTED,
        started_at=now,
        ordinary_authorization_consumed=True,
        narrow_authorization_consumed=True,
        invocation_may_have_occurred=True,
        manual_recovery_required=True,
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=DeployScyllaBootstrapExecutionState.STARTED,
        ordinary_authorization_consumed=True,
        narrow_authorization_consumed=True,
        invocation_count=1,
        attempt=attempt,
    )
    return store.write_locked(
        record,
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _persist_uncertain_or_raise(
    store: DeployScyllaBootstrapExecutionStore,
    current: StoredDeployScyllaBootstrapExecution,
    state: DeployScyllaBootstrapExecutionState,
    *,
    lock: ClusterLock,
) -> None:
    try:
        _persist_uncertain(store, current, state, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy Scylla bootstrap uncertain outcome persistence failed; "
            "manual recovery required"
        ) from error


def _persist_uncertain(
    store: DeployScyllaBootstrapExecutionStore,
    current: StoredDeployScyllaBootstrapExecution,
    state: DeployScyllaBootstrapExecutionState,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaBootstrapExecution:
    if (
        current.record.state is not DeployScyllaBootstrapExecutionState.STARTED
        or state
        not in {
            DeployScyllaBootstrapExecutionState.FAILED,
            DeployScyllaBootstrapExecutionState.TIMED_OUT,
            DeployScyllaBootstrapExecutionState.INTERRUPTED,
            DeployScyllaBootstrapExecutionState.UNREACHABLE,
            DeployScyllaBootstrapExecutionState.MALFORMED_RESULT,
        }
    ):
        raise StatePersistenceError(
            "deploy Scylla bootstrap uncertain transition conflicts"
        )
    now = _timestamp()
    attempt = replace(
        current.record.attempt,
        state=state,
        completed_at=now,
        manual_recovery_required=True,
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=state,
        completed=False,
        attempt=attempt,
    )
    return store.write_locked(
        record,
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _persist_terminal(
    store: DeployScyllaBootstrapExecutionStore,
    current: StoredDeployScyllaBootstrapExecution,
    *,
    entry: DeployScyllaBootstrapEvidenceEntry,
    exit_code: int,
    state: DeployScyllaBootstrapExecutionState,
    lock: ClusterLock,
) -> StoredDeployScyllaBootstrapExecution:
    if (
        current.record.state is not DeployScyllaBootstrapExecutionState.STARTED
        or state
        not in {
            DeployScyllaBootstrapExecutionState.SUCCEEDED,
            DeployScyllaBootstrapExecutionState.FAILED,
        }
        or (state is DeployScyllaBootstrapExecutionState.SUCCEEDED)
        != (entry.status is ScyllaBootstrapStatus.BOOTSTRAPPED)
    ):
        raise StateConflictError(
            "deploy Scylla bootstrap terminal transition conflicts"
        )
    now = _timestamp()
    attempt = replace(
        current.record.attempt,
        state=state,
        completed_at=now,
        exit_code=exit_code,
        result_digest=entry.result_digest,
        evidence_digest=entry.evidence_digest,
        mutation_boundary=entry.mutation_boundary,
        membership_may_have_changed=entry.membership_may_have_changed,
        node_preserved=entry.node_preserved,
        remask_performed=entry.remask_performed,
        manual_recovery_required=entry.recovery_required,
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=state,
        completed=True,
        attempt=attempt,
    )
    return store.write_locked(
        record,
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _semantic_entry(
    scope: _ExecutionScope, result: AnsibleExecutionResult
) -> DeployScyllaBootstrapEvidenceEntry:
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.SENSITIVE
        or result.check_mode
        or result.scylla_bootstrap is not None
    ):
        raise AnsibleResultError(
            "deploy Scylla bootstrap strict result identity conflicts"
        )
    try:
        parsed = parse_scylla_bootstrap_execution(
            result.stdout,
            expected_payload=dict(scope.payload),
            exit_code=result.exit_code,
        )
    except AnsibleError as error:
        raise AnsibleResultError(
            "deploy Scylla bootstrap strict result is malformed"
        ) from error
    _validate_semantic_result(parsed, scope)
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
    payload = scope.payload
    values: dict[str, object] = {
        "stable_id": scope.stable_id,
        "mode": parsed.mode,
        "status": parsed.status,
        "datacenter_digest": _digest_object(parsed.datacenter),
        "rack_digest": _digest_object(parsed.rack),
        "topology_digest": cast(
            str,
            cast(Mapping[str, object], payload["prerequisite_digests"])[
                "topology_digest"
            ],
        ),
        "package_version_digest": _digest_object(payload["package_version"]),
        "prerequisite_digest": prerequisite_digest,
        "host_id_digest": parsed.host_id_digest,
        "ring_membership_digest": parsed.ring_membership_digest,
        "blocker_count": len(parsed.blockers),
        "blocker_digest": _digest_object(list(parsed.blockers)),
        "pre_start_revalidated": True,
        "unmask_start_boundary_crossed": True,
        "cql_ready": success,
        "nodetool_membership_verified": success,
        "schema_agreement": success,
        "streaming_complete": success,
        "service_active": success,
        "never_joined_proven": never_joined,
        "membership_may_have_changed": (
            parsed.mutation_boundary
            is MutationBoundary.RING_MEMBERSHIP_MAY_HAVE_CHANGED
        ),
        "remask_performed": never_joined,
        "node_preserved": True,
        "recovery_required": parsed.recovery_required,
        "automatic_retry_allowed": False,
        "restart_performed": False,
        "destroy_performed": False,
        "removenode_performed": False,
        "mutation_boundary": parsed.mutation_boundary,
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "source_digest": scope.source_digest,
        "result_digest": result_digest,
        "evidence_digest": "",
    }
    values["evidence_digest"] = _evidence_entry_digest_from_values(values)
    return DeployScyllaBootstrapEvidenceEntry(**values)  # type: ignore[arg-type]


def _validate_semantic_result(
    evidence: ScyllaBootstrapEvidence,
    scope: _ExecutionScope,
) -> None:
    payload = scope.payload
    if (
        evidence.mode is not ScyllaBootstrapMode.INITIAL_SEED
        or evidence.target_logical_id != scope.stable_id
        or evidence.datacenter != payload["datacenter"]
        or evidence.rack != payload["rack"]
        or dict(evidence.prerequisite_digests) != payload["prerequisite_digests"]
        or evidence.mutation_boundary is MutationBoundary.NOT_REACHED
    ):
        raise AnsibleResultError("deploy Scylla bootstrap result scope conflicts")
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
                "deploy Scylla bootstrap success evidence conflicts"
            )
        return
    if evidence.status is not ScyllaBootstrapStatus.FAILED:
        raise AnsibleResultError(
            "deploy Scylla bootstrap check-mode result is forbidden"
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
            "deploy Scylla bootstrap failure recovery evidence conflicts"
        )


def _build_report(
    context: _ExecutionContext,
    execution: StoredDeployScyllaBootstrapExecution,
    evidence: StoredDeployScyllaBootstrapEvidence,
    *,
    execution_state: DeployScyllaBootstrapArtifactState,
    evidence_state: DeployScyllaBootstrapArtifactState,
) -> DeployScyllaBootstrapExecutionReport:
    entry = evidence.record.entry
    if (
        execution.record.state is not DeployScyllaBootstrapExecutionState.SUCCEEDED
        or not execution.record.completed
        or entry.status is not ScyllaBootstrapStatus.BOOTSTRAPPED
    ):
        raise StateConflictError("deploy Scylla bootstrap execution is not successful")
    return DeployScyllaBootstrapExecutionReport(
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
        mode=entry.mode,
        bootstrapped_count=1,
        host_identity_count=int(entry.host_id_digest is not None),
        ring_identity_count=int(entry.ring_membership_digest is not None),
        pre_start_revalidated_count=int(entry.pre_start_revalidated),
        cql_ready_count=int(entry.cql_ready),
        nodetool_verified_count=int(entry.nodetool_membership_verified),
        schema_agreement_count=int(entry.schema_agreement),
        streaming_complete_count=int(entry.streaming_complete),
        membership_may_have_changed_count=int(entry.membership_may_have_changed),
        node_preserved_count=int(entry.node_preserved),
        remask_count=int(entry.remask_performed),
        result_digest=entry.result_digest,
        evidence_digest=entry.evidence_digest,
        manual_recovery_required=False,
        automatic_retry_allowed=False,
        restart_allowed=False,
        destroy_allowed=False,
        removenode_allowed=False,
        journal_status=context.binding.journal_status,
        journal_phase=context.binding.journal_phase,
    )


def _failure_state(error: AnsibleError) -> DeployScyllaBootstrapExecutionState:
    cause = error.__cause__
    if isinstance(cause, ProcessTimeoutError):
        return DeployScyllaBootstrapExecutionState.TIMED_OUT
    if isinstance(cause, ProcessOutputError):
        return DeployScyllaBootstrapExecutionState.MALFORMED_RESULT
    message = str(error).lower()
    if "unreachable" in message:
        return DeployScyllaBootstrapExecutionState.UNREACHABLE
    if isinstance(error, AnsibleResultError) or "malformed" in message:
        return DeployScyllaBootstrapExecutionState.MALFORMED_RESULT
    return DeployScyllaBootstrapExecutionState.FAILED


def _validate_execution_transition(
    current: DeployScyllaBootstrapExecution,
    replacement: DeployScyllaBootstrapExecution,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or current.completed
    ):
        raise StatePersistenceError(
            "deploy Scylla bootstrap execution transition is invalid"
        )
    if current.state is DeployScyllaBootstrapExecutionState.PREPARED:
        valid = replacement.state is DeployScyllaBootstrapExecutionState.STARTED
    elif current.state is DeployScyllaBootstrapExecutionState.STARTED:
        valid = replacement.state not in {
            DeployScyllaBootstrapExecutionState.PREPARED,
            DeployScyllaBootstrapExecutionState.STARTED,
        }
    else:
        valid = False
    if not valid:
        raise StatePersistenceError(
            "deploy Scylla bootstrap execution transition conflicts"
        )


def _binding_digest(binding: DeployScyllaBootstrapExecutionBinding) -> str:
    value = binding.to_object()
    value["binding_digest"] = ""
    return _digest_object(value)


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployScyllaBootstrapExecutionBinding.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(item, StrEnum)
            else item
        )
    value["binding_digest"] = ""
    return _digest_object(value)


def _evidence_entry_digest(entry: DeployScyllaBootstrapEvidenceEntry) -> str:
    value = entry.to_object()
    value["evidence_digest"] = ""
    return _digest_object(value)


def _evidence_entry_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployScyllaBootstrapEvidenceEntry.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = item.value if isinstance(item, StrEnum) else item
    value["evidence_digest"] = ""
    return _digest_object(value)


def _dataclass_object(value: object) -> dict[str, object]:
    result: dict[str, object] = {}
    for name in value.__dataclass_fields__:  # type: ignore[attr-defined]
        item = getattr(value, name)
        result[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(item, StrEnum)
            else item
        )
    return result


def _digest_fields(value: object) -> tuple[str | None, ...]:
    return tuple(
        cast(str | None, getattr(value, name))
        for name in value.__dataclass_fields__  # type: ignore[attr-defined]
        if name.endswith("_digest")
    )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy Scylla bootstrap execution paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy Scylla bootstrap execution requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_or_later_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Scylla bootstrap execution artifacts"
        ) from error
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_BOOTSTRAP_EVIDENCE_FILENAME_SUFFIX,
    )
    later_fragments = (
        ".ansible-deploy-post-scylla-bootstrap",
        ".ansible-deploy-scylla-health",
        ".ansible-scylla-health",
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
                "deploy Scylla bootstrap execution refuses later membership history"
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
                    "deploy Scylla bootstrap execution artifacts are ambiguous"
                )


def _operation_id_from_filename(name: str, suffix: str) -> uuid.UUID | None:
    if not name.endswith(suffix):
        return None
    value = name[: -len(suffix)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


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
            "deploy Scylla bootstrap toolchain version is invalid"
        ) from error


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


def _optional_integer(value: object, label: str) -> int | None:
    return None if value is None else _integer(value, label)


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be a boolean")
    return value


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


def _positive_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


def _is_digest(value: str) -> bool:
    try:
        validate_digest(value, "digest")
    except StatePersistenceError:
        return False
    return True


__all__ = [
    "ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EVIDENCE_ENTRY_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_BINDING_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_SCHEMA_VERSION",
    "DEPLOY_SCYLLA_BOOTSTRAP_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_SCYLLA_BOOTSTRAP_EXECUTION_FILENAME_SUFFIX",
    "DeployScyllaBootstrapArtifactState",
    "DeployScyllaBootstrapEvidence",
    "DeployScyllaBootstrapEvidenceEntry",
    "DeployScyllaBootstrapEvidenceStore",
    "DeployScyllaBootstrapExecution",
    "DeployScyllaBootstrapExecutionAttempt",
    "DeployScyllaBootstrapExecutionBinding",
    "DeployScyllaBootstrapExecutionReport",
    "DeployScyllaBootstrapExecutionState",
    "DeployScyllaBootstrapExecutionStore",
    "StoredDeployScyllaBootstrapEvidence",
    "StoredDeployScyllaBootstrapExecution",
    "deploy_scylla_bootstrap_evidence_id_from_filename",
    "deploy_scylla_bootstrap_evidence_path",
    "deploy_scylla_bootstrap_execution_id_from_filename",
    "deploy_scylla_bootstrap_execution_path",
    "execute_deploy_scylla_bootstrap_initial_seed",
]
