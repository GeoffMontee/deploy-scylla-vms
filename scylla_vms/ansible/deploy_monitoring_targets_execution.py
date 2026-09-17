"""Durable exact execution and evidence for mapped deploy ``monitoring-targets``.

This internal owner derives one exact official target-file intent from
canonical state, consumes immutable authorization at durable ``started``
intent, and persists only bounded address-free semantic evidence. Any outcome
after start that is not strict success requires manual recovery and is never
retried.
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

from scylla_vms.ansible.base_os import (
    BaseOsEvidence,
    BaseOsHostEvidence,
    BaseOsStatus,
)
from scylla_vms.ansible.commands import AnsibleCommandBuilder
from scylla_vms.ansible.deploy_monitoring_targets_authorization import (
    ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCHEMA_VERSION,
    DeployMonitoringTargetsAuthorizationScope,
    DeployMonitoringTargetsAuthorizationStore,
    StoredDeployMonitoringTargetsAuthorization,
    _AuthorizationContext,
    _build_authorization,
    _derive_authorization_scope,
    _load_authorization_context,
    _reconstruct_stack_evidence,
    _validate_target_payload,
)
from scylla_vms.ansible.deploy_plan import (
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import _loaded
from scylla_vms.ansible.monitoring_stack import (
    LISTEN_POLICY,
    STACK_VERSION,
    build_monitoring_stack_payload,
)
from scylla_vms.ansible.monitoring_targets import (
    MONITORING_TARGETS_SCHEMA_VERSION,
    SCRAPE_READINESS,
    TARGET_FILES,
    MonitoringTargetsEvidence,
    MonitoringTargetsStatus,
    build_monitoring_targets_payload,
    parse_monitoring_targets_execution,
)
from scylla_vms.ansible.operation_binding import readiness_binding_digest
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
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
from scylla_vms.desired import HostRole, ImageFilter, ImageVersionMatch
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
    format_timestamp,
    parse_timestamp,
    parse_uuid,
    require_exact_keys,
    require_string,
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

ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-monitoring-targets-execution-binding/v1"
)
ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-monitoring-targets-execution/v1"
)
ANSIBLE_DEPLOY_MONITORING_TARGETS_EVIDENCE_ENTRY_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-monitoring-targets-evidence-entry/v1"
)
ANSIBLE_DEPLOY_MONITORING_TARGETS_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-monitoring-targets-evidence/v1"
)
ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-monitoring-targets-execution-report/v1"
)

DEPLOY_MONITORING_TARGETS_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-monitoring-targets-execution.json"
)
DEPLOY_MONITORING_TARGETS_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-monitoring-targets-evidence.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "monitoring-targets"
_STAGE = "post-monitoring-agent-monitoring-targets"
_SCOPE_KIND = "monitoring-target-files-generation"
_MAPPING_SEQUENCE = 18
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SUCCESS_STATUSES = frozenset(
    {MonitoringTargetsStatus.GENERATED, MonitoringTargetsStatus.NO_CHANGE}
)


class DeployMonitoringTargetsExecutionState(StrEnum):
    """Bounded durable states for the one authorized target-file attempt."""

    PREPARED = "prepared"
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"
    DRIFTED = "drifted"


class DeployMonitoringTargetsArtifactState(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployMonitoringTargetsExecutionBinding:
    """Address-free authorization, chain, source, and toolchain binding."""

    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_scope_digest: str
    authorization_proof_digest: str
    post_monitoring_agent_artifact_digest: str
    post_monitoring_agent_record_digest: str
    post_monitoring_agent_effective_plan_digest: str
    monitoring_stack_evidence_artifact_digest: str
    manager_server_evidence_artifact_digest: str
    manager_agent_evidence_artifact_digest: str
    monitoring_agent_evidence_artifact_digest: str
    base_os_artifact_digest: str
    base_os_evidence_digest: str
    metadata_generation: int
    metadata_artifact_digest: str
    desired_spec_digest: str
    observation_generation: int
    observation_artifact_digest: str
    observation_manifest_digest: str
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    trust_generation: int
    trust_artifact_digest: str
    trust_entries_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    catalog_digest: str
    source_version: str
    source_digest: str
    playbook_source_digest: str
    toolchain_version: str
    executable_identity_digest: str
    toolchain_evidence_digest: str
    target_stable_id: str
    target_set_digest: str
    target_intent_digest: str
    variables_digest: str
    command_digest: str
    execution_scope_digest: str
    binding_digest: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_BINDING_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_BINDING_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or not self.target_stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
            or self.target_set_digest != _digest_object([self.target_stable_id])
        ):
            raise StatePersistenceError(
                "deploy monitoring-targets execution binding is invalid"
            )
        validate_cluster_name(self.cluster_name)
        for count in (
            self.journal_generation,
            self.metadata_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
        ):
            _positive_integer(count, "deploy monitoring-targets binding generation")
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy monitoring-targets binding digest")
        _validate_toolchain_version(self.toolchain_version)
        if self.binding_digest != _binding_digest(self):
            raise StatePersistenceError(
                "deploy monitoring-targets execution binding digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployMonitoringTargetsExecutionBinding:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy monitoring-targets execution binding",
        )
        integers = {
            "journal_generation",
            "metadata_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
        }
        parsed: dict[str, object] = {}
        for name in cls.__dataclass_fields__:
            if name in {"cluster_uuid", "operation_id"}:
                parsed[name] = parse_uuid(require_string(value, name), name)
            elif name in integers:
                parsed[name] = _integer(value[name], name)
            elif name == "journal_status":
                parsed[name] = _enum(JournalStatus, require_string(value, name), name)
            elif name == "journal_phase":
                parsed[name] = _enum(OperationPhase, require_string(value, name), name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployMonitoringTargetsExecutionAttempt:
    """One exact prepared, started, or terminal target-file attempt."""

    attempt_index: int
    mapping_sequence: int
    stable_id: str
    target_digest: str
    authorization_scope_digest: str
    authorization_variables_digest: str
    authorization_command_digest: str
    variables_digest: str
    command_digest: str
    source_digest: str
    stack_version_digest: str
    target_intent_digest: str
    state: DeployMonitoringTargetsExecutionState
    prepared_at: str
    started_at: str | None
    completed_at: str | None
    authorization_consumed_at_start: bool
    invocation_may_have_occurred: bool
    exit_code: int | None
    result_digest: str | None
    evidence_digest: str | None
    manual_recovery_required: bool
    automatic_retry_allowed: bool = False
    result_schema_version: str = MONITORING_TARGETS_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.attempt_index != 1
            or self.mapping_sequence != _MAPPING_SEQUENCE
            or not self.stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.result_schema_version != MONITORING_TARGETS_SCHEMA_VERSION
            or self.stack_version_digest != _digest_object(STACK_VERSION)
            or not isinstance(self.state, DeployMonitoringTargetsExecutionState)
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy monitoring-targets execution attempt is invalid"
            )
        for digest in (
            self.target_digest,
            self.authorization_scope_digest,
            self.authorization_variables_digest,
            self.authorization_command_digest,
            self.variables_digest,
            self.command_digest,
            self.source_digest,
            self.stack_version_digest,
            self.target_intent_digest,
            self.result_digest,
            self.evidence_digest,
        ):
            if digest is not None:
                validate_digest(digest, "deploy monitoring-targets attempt digest")
        prepared = parse_timestamp(self.prepared_at)
        started = _optional_timestamp(self.started_at)
        completed = _optional_timestamp(self.completed_at)
        if (
            (started is not None and started < prepared)
            or (completed is not None and started is None)
            or (completed is not None and started is not None and completed < started)
        ):
            raise StatePersistenceError(
                "deploy monitoring-targets attempt timestamps conflict"
            )
        if self.state is DeployMonitoringTargetsExecutionState.PREPARED:
            valid = (
                started is None
                and completed is None
                and not self.authorization_consumed_at_start
                and not self.invocation_may_have_occurred
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and not self.manual_recovery_required
            )
        elif self.state is DeployMonitoringTargetsExecutionState.STARTED:
            valid = (
                started is not None
                and completed is None
                and self.authorization_consumed_at_start
                and self.invocation_may_have_occurred
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.manual_recovery_required
            )
        elif self.state is DeployMonitoringTargetsExecutionState.SUCCEEDED:
            valid = (
                started is not None
                and completed is not None
                and self.authorization_consumed_at_start
                and self.invocation_may_have_occurred
                and self.exit_code == 0
                and self.result_digest is not None
                and self.evidence_digest is not None
                and not self.manual_recovery_required
            )
        else:
            valid = (
                started is not None
                and completed is not None
                and self.authorization_consumed_at_start
                and self.invocation_may_have_occurred
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.manual_recovery_required
            )
        if not valid:
            raise StatePersistenceError(
                "deploy monitoring-targets attempt state conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployMonitoringTargetsExecutionAttempt:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy monitoring-targets execution attempt",
        )
        try:
            return cls(
                attempt_index=_integer(value["attempt_index"], "attempt index"),
                mapping_sequence=_integer(
                    value["mapping_sequence"], "mapping sequence"
                ),
                stable_id=require_string(value, "stable_id"),
                target_digest=require_string(value, "target_digest"),
                authorization_scope_digest=require_string(
                    value, "authorization_scope_digest"
                ),
                authorization_variables_digest=require_string(
                    value, "authorization_variables_digest"
                ),
                authorization_command_digest=require_string(
                    value, "authorization_command_digest"
                ),
                variables_digest=require_string(value, "variables_digest"),
                command_digest=require_string(value, "command_digest"),
                source_digest=require_string(value, "source_digest"),
                stack_version_digest=require_string(value, "stack_version_digest"),
                target_intent_digest=require_string(value, "target_intent_digest"),
                state=DeployMonitoringTargetsExecutionState(
                    require_string(value, "state")
                ),
                prepared_at=require_string(value, "prepared_at"),
                started_at=_optional_string(value["started_at"], "started_at"),
                completed_at=_optional_string(value["completed_at"], "completed_at"),
                authorization_consumed_at_start=_boolean(
                    value["authorization_consumed_at_start"],
                    "authorization consumption",
                ),
                invocation_may_have_occurred=_boolean(
                    value["invocation_may_have_occurred"], "invocation state"
                ),
                exit_code=_optional_integer(value["exit_code"], "exit code"),
                result_digest=_optional_string(value["result_digest"], "result digest"),
                evidence_digest=_optional_string(
                    value["evidence_digest"], "evidence digest"
                ),
                manual_recovery_required=_boolean(
                    value["manual_recovery_required"], "manual recovery"
                ),
                automatic_retry_allowed=_boolean(
                    value["automatic_retry_allowed"], "automatic retry"
                ),
                result_schema_version=require_string(value, "result_schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy monitoring-targets attempt state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployMonitoringTargetsExecution:
    """Generation-guarded single-attempt execution state."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployMonitoringTargetsExecutionBinding
    state: DeployMonitoringTargetsExecutionState
    authorization_consumed: bool
    invocation_count: int
    completed: bool
    attempt: DeployMonitoringTargetsExecutionAttempt
    schema_version: str = ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        invoked = self.state is not DeployMonitoringTargetsExecutionState.PREPARED
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_SCHEMA_VERSION
            or self.generation < 1
            or self.state is not self.attempt.state
            or self.authorization_consumed != invoked
            or self.invocation_count != int(invoked)
            or self.completed
            != (self.state is DeployMonitoringTargetsExecutionState.SUCCEEDED)
            or parse_timestamp(self.updated_at) < parse_timestamp(self.created_at)
            or self.attempt.stable_id != self.binding.target_stable_id
            or self.attempt.target_digest != self.binding.target_set_digest
            or self.attempt.authorization_scope_digest
            != self.binding.authorization_scope_digest
            or self.attempt.variables_digest != self.binding.variables_digest
            or self.attempt.command_digest != self.binding.command_digest
            or self.attempt.source_digest != self.binding.playbook_source_digest
            or self.attempt.target_intent_digest != self.binding.target_intent_digest
        ):
            raise StatePersistenceError(
                "deploy monitoring-targets execution summary conflicts"
            )

    @property
    def manual_recovery_required(self) -> bool:
        return self.state not in {
            DeployMonitoringTargetsExecutionState.PREPARED,
            DeployMonitoringTargetsExecutionState.SUCCEEDED,
        }

    def to_object(self) -> dict[str, object]:
        return {
            "attempt": self.attempt.to_object(),
            "authorization_consumed": self.authorization_consumed,
            "binding": self.binding.to_object(),
            "completed": self.completed,
            "created_at": self.created_at,
            "generation": self.generation,
            "invocation_count": self.invocation_count,
            "schema_version": self.schema_version,
            "state": self.state.value,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployMonitoringTargetsExecution:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy monitoring-targets execution",
        )
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                updated_at=require_string(value, "updated_at"),
                binding=DeployMonitoringTargetsExecutionBinding.from_object(
                    _mapping(value["binding"], "binding")
                ),
                state=DeployMonitoringTargetsExecutionState(
                    require_string(value, "state")
                ),
                authorization_consumed=_boolean(
                    value["authorization_consumed"], "authorization consumption"
                ),
                invocation_count=_integer(
                    value["invocation_count"], "invocation count"
                ),
                completed=_boolean(value["completed"], "completion"),
                attempt=DeployMonitoringTargetsExecutionAttempt.from_object(
                    _mapping(value["attempt"], "attempt")
                ),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy monitoring-targets execution state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployMonitoringTargetsEvidenceEntry:
    """Strict redacted semantic evidence for successful target generation."""

    attempt_index: int
    mapping_sequence: int
    stable_id: str
    image_architecture: str
    status: MonitoringTargetsStatus
    generated: bool
    changed: bool
    stack_version_digest: str
    file_count: int
    file_set_digest: str
    file_content_set_digest: str
    manager_target_count: int
    scylla_target_count: int
    node_exporter_target_count: int
    manager_agent_target_count: int
    manager_identity_set_digest: str
    scylla_identity_set_digest: str
    listen_policy: str
    scrape_readiness: str
    scrape_performed: bool
    exporters_started: bool
    stack_started: bool
    containers_started: bool
    compose_generated: bool
    auth_configured: bool
    public_bind: bool
    manager_registration_performed: bool
    scylla_started: bool
    secrets_written: bool
    provenance_digest: str
    variables_digest: str
    command_digest: str
    source_digest: str
    result_digest: str
    evidence_digest: str
    manual_recovery_required: bool = False
    automatic_retry_allowed: bool = False
    result_schema_version: str = MONITORING_TARGETS_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_TARGETS_EVIDENCE_ENTRY_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        prohibited = (
            self.scrape_performed,
            self.exporters_started,
            self.stack_started,
            self.containers_started,
            self.compose_generated,
            self.auth_configured,
            self.public_bind,
            self.manager_registration_performed,
            self.scylla_started,
            self.secrets_written,
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MONITORING_TARGETS_EVIDENCE_ENTRY_SCHEMA_VERSION
            or self.result_schema_version != MONITORING_TARGETS_SCHEMA_VERSION
            or self.attempt_index != 1
            or self.mapping_sequence != _MAPPING_SEQUENCE
            or not self.stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.image_architecture not in {"amd64", "aarch64"}
            or self.status not in _SUCCESS_STATUSES
            or not self.generated
            or self.changed != (self.status is MonitoringTargetsStatus.GENERATED)
            or self.stack_version_digest != _digest_object(STACK_VERSION)
            or self.file_count != len(TARGET_FILES)
            or self.manager_target_count != 1
            or self.scylla_target_count < 1
            or self.node_exporter_target_count != self.scylla_target_count
            or self.manager_agent_target_count != self.scylla_target_count
            or self.listen_policy != LISTEN_POLICY
            or self.scrape_readiness != SCRAPE_READINESS
            or any(prohibited)
            or self.manual_recovery_required
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy monitoring-targets semantic evidence conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy monitoring-targets evidence digest")
        if self.evidence_digest != _evidence_entry_digest(self):
            raise StatePersistenceError(
                "deploy monitoring-targets evidence digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployMonitoringTargetsEvidenceEntry:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy monitoring-targets evidence entry",
        )
        integers = {
            "attempt_index",
            "mapping_sequence",
            "file_count",
            "manager_target_count",
            "scylla_target_count",
            "node_exporter_target_count",
            "manager_agent_target_count",
        }
        booleans = {
            "generated",
            "changed",
            "scrape_performed",
            "exporters_started",
            "stack_started",
            "containers_started",
            "compose_generated",
            "auth_configured",
            "public_bind",
            "manager_registration_performed",
            "scylla_started",
            "secrets_written",
            "manual_recovery_required",
            "automatic_retry_allowed",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                if name in integers:
                    parsed[name] = _integer(value[name], name)
                elif name in booleans:
                    parsed[name] = _boolean(value[name], name)
                elif name == "status":
                    parsed[name] = MonitoringTargetsStatus(require_string(value, name))
                else:
                    parsed[name] = require_string(value, name)
            return cls(**parsed)  # type: ignore[arg-type]
        except ValueError as error:
            raise StatePersistenceError(
                "deploy monitoring-targets evidence status is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployMonitoringTargetsEvidence:
    """Immutable one-entry semantic-evidence prefix."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployMonitoringTargetsExecutionBinding
    entries: tuple[DeployMonitoringTargetsEvidenceEntry, ...]
    schema_version: str = ANSIBLE_DEPLOY_MONITORING_TARGETS_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        entry = self.entries[0] if len(self.entries) == 1 else None
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MONITORING_TARGETS_EVIDENCE_SCHEMA_VERSION
            or self.generation != 1
            or len(self.entries) != 1
            or parse_timestamp(self.updated_at) < parse_timestamp(self.created_at)
            or entry is None
            or entry.stable_id != self.binding.target_stable_id
            or entry.mapping_sequence != _MAPPING_SEQUENCE
            or entry.variables_digest != self.binding.variables_digest
            or entry.command_digest != self.binding.command_digest
            or entry.source_digest != self.binding.playbook_source_digest
        ):
            raise StatePersistenceError(
                "deploy monitoring-targets evidence prefix conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "binding": self.binding.to_object(),
            "created_at": self.created_at,
            "entries": [entry.to_object() for entry in self.entries],
            "generation": self.generation,
            "schema_version": self.schema_version,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployMonitoringTargetsEvidence:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy monitoring-targets evidence",
        )
        return cls(
            generation=_integer(value["generation"], "generation"),
            created_at=require_string(value, "created_at"),
            updated_at=require_string(value, "updated_at"),
            binding=DeployMonitoringTargetsExecutionBinding.from_object(
                _mapping(value["binding"], "binding")
            ),
            entries=tuple(
                DeployMonitoringTargetsEvidenceEntry.from_object(
                    _mapping(item, "evidence entry")
                )
                for item in _array(value["entries"], "evidence entries")
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredDeployMonitoringTargetsExecution:
    record: DeployMonitoringTargetsExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployMonitoringTargetsEvidence:
    record: DeployMonitoringTargetsEvidence
    artifact_digest: str


class DeployMonitoringTargetsExecutionStore:
    """Generation-guarded owner-only execution state."""

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
        self._path = deploy_monitoring_targets_execution_path(paths, operation_id)
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
    ) -> StoredDeployMonitoringTargetsExecution:
        value, digest = self._file.read()
        record = DeployMonitoringTargetsExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy monitoring-targets execution identity conflicts"
            )
        return StoredDeployMonitoringTargetsExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployMonitoringTargetsExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployMonitoringTargetsExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployMonitoringTargetsExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy monitoring-targets execution operation conflicts"
            )
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial deploy monitoring-targets execution generation conflicts"
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
                    "deploy monitoring-targets execution changed concurrently"
                )
            _validate_execution_transition(current.record, record)
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployMonitoringTargetsExecution(record, digest)


class DeployMonitoringTargetsEvidenceStore:
    """Create-once owner-only semantic evidence."""

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
        self._path = deploy_monitoring_targets_evidence_path(paths, operation_id)
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
    ) -> StoredDeployMonitoringTargetsEvidence:
        value, digest = self._file.read()
        record = DeployMonitoringTargetsEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy monitoring-targets evidence identity conflicts"
            )
        return StoredDeployMonitoringTargetsEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployMonitoringTargetsEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployMonitoringTargetsEvidence,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployMonitoringTargetsEvidence,
        DeployMonitoringTargetsArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy monitoring-targets evidence operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy monitoring-targets evidence is immutable"
                )
            return current, DeployMonitoringTargetsArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployMonitoringTargetsEvidence(record, digest),
            DeployMonitoringTargetsArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployMonitoringTargetsExecutionReport:
    """Strict redacted successful execution report."""

    operation_id: uuid.UUID
    execution_state: DeployMonitoringTargetsExecutionState
    execution_artifact_state: DeployMonitoringTargetsArtifactState
    evidence_artifact_state: DeployMonitoringTargetsArtifactState
    execution_artifact_digest: str
    evidence_artifact_digest: str
    binding_digest: str
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_consumed: bool
    target_stable_id: str
    target_set_digest: str
    stage: str
    scope_kind: str
    invocation_count: int
    generated_count: int
    changed_count: int
    stack_version_digest: str
    file_count: int
    file_set_digest: str
    file_content_set_digest: str
    manager_target_count: int
    scylla_target_count: int
    node_exporter_target_count: int
    manager_agent_target_count: int
    manager_identity_set_digest: str
    scylla_identity_set_digest: str
    listen_policy: str
    scrape_readiness: str
    prohibited_action_count: int
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    skip_allowed: bool
    continue_allowed: bool
    rollback_performed: bool
    journal_status: JournalStatus
    journal_phase: OperationPhase
    journal_updated: bool = False
    reconciliation_state: str = "not-performed"
    public_workflow_state: str = "unavailable"
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCHEMA_VERSION
    )
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_TARGETS_EVIDENCE_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_MONITORING_TARGETS_EVIDENCE_SCHEMA_VERSION
            or self.execution_state
            is not DeployMonitoringTargetsExecutionState.SUCCEEDED
            or not self.authorization_consumed
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.invocation_count != 1
            or self.generated_count != 1
            or self.file_count != len(TARGET_FILES)
            or self.manager_target_count != 1
            or self.scylla_target_count < 1
            or self.node_exporter_target_count != self.scylla_target_count
            or self.manager_agent_target_count != self.scylla_target_count
            or self.listen_policy != LISTEN_POLICY
            or self.scrape_readiness != SCRAPE_READINESS
            or self.prohibited_action_count
            or self.manual_recovery_required
            or self.automatic_retry_allowed
            or self.skip_allowed
            or self.continue_allowed
            or self.rollback_performed
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.journal_updated
            or self.reconciliation_state != "not-performed"
            or self.public_workflow_state != "unavailable"
        ):
            raise StatePersistenceError(
                "deploy monitoring-targets execution report is invalid"
            )
        if (
            not self.target_stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
        ):
            raise StatePersistenceError(
                "deploy monitoring-targets report target is invalid"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy monitoring-targets report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "authorization": {
                "artifact_digest": self.authorization_artifact_digest,
                "consumed": self.authorization_consumed,
                "digest": self.authorization_digest,
                "schema_version": self.authorization_schema_version,
            },
            "evidence": {
                "artifact_digest": self.evidence_artifact_digest,
                "artifact_state": self.evidence_artifact_state.value,
                "generated_count": self.generated_count,
                "listen_policy": self.listen_policy,
                "prohibited_action_count": self.prohibited_action_count,
                "schema_version": self.evidence_schema_version,
                "scrape_readiness": self.scrape_readiness,
            },
            "execution": {
                "artifact_digest": self.execution_artifact_digest,
                "artifact_state": self.execution_artifact_state.value,
                "automatic_retry_allowed": self.automatic_retry_allowed,
                "binding_digest": self.binding_digest,
                "continue_allowed": self.continue_allowed,
                "invocation_count": self.invocation_count,
                "manual_recovery_required": self.manual_recovery_required,
                "rollback_performed": self.rollback_performed,
                "schema_version": self.execution_schema_version,
                "skip_allowed": self.skip_allowed,
                "state": self.execution_state.value,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": self.journal_updated,
            },
            "operation": {
                "id": str(self.operation_id),
                "kind": _OPERATION,
                "public_workflow_state": self.public_workflow_state,
                "reconciliation_state": self.reconciliation_state,
            },
            "schema_version": self.schema_version,
            "scope": {
                "changed_count": self.changed_count,
                "kind": self.scope_kind,
                "target_count": 1,
                "target_set_digest": self.target_set_digest,
                "target_stable_id": self.target_stable_id,
            },
            "stage": self.stage,
            "target_policy": {
                "file_content_set_digest": self.file_content_set_digest,
                "file_count": self.file_count,
                "file_set_digest": self.file_set_digest,
                "manager_agent_target_count": self.manager_agent_target_count,
                "manager_identity_set_digest": self.manager_identity_set_digest,
                "manager_target_count": self.manager_target_count,
                "node_exporter_target_count": self.node_exporter_target_count,
                "scylla_identity_set_digest": self.scylla_identity_set_digest,
                "scylla_target_count": self.scylla_target_count,
                "stack_version_digest": self.stack_version_digest,
            },
        }


@dataclass(frozen=True, slots=True)
class _ExecutionScope:
    authorization: DeployMonitoringTargetsAuthorizationScope
    authorization_scope_digest: str
    variables: tuple[tuple[str, object], ...]
    variables_digest: str
    command_digest: str
    source_digest: str
    step_sequence: int
    image_architecture: str


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    authorization_context: _AuthorizationContext
    authorization: StoredDeployMonitoringTargetsAuthorization
    binding: DeployMonitoringTargetsExecutionBinding
    scope: _ExecutionScope
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport


def execute_deploy_monitoring_targets(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployMonitoringTargetsExecutionReport:
    """Execute only the exact immutable authorized monitoring-targets scope."""

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
    execution_store = DeployMonitoringTargetsExecutionStore(paths, operation_id)
    evidence_store = DeployMonitoringTargetsEvidenceStore(paths, operation_id)
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
    if execution is not None and execution.record.completed:
        if evidence is None:
            raise StateConflictError(
                "completed deploy monitoring-targets evidence is unavailable"
            )
        return _build_report(
            context,
            execution,
            evidence,
            execution_state=DeployMonitoringTargetsArtifactState.REUSED,
            evidence_state=DeployMonitoringTargetsArtifactState.REUSED,
        )
    if (
        execution is not None
        and execution.record.state is not DeployMonitoringTargetsExecutionState.PREPARED
    ):
        raise StateConflictError(
            "deploy monitoring-targets execution requires manual recovery and "
            "cannot retry"
        )

    service = AnsibleService(builder, runner)
    discovered = service.version(lock)
    if discovered != toolchain:
        raise StateConflictError("deploy monitoring-targets toolchain drifted")
    context = _load_execution_context(
        paths,
        operation_id,
        lock=lock,
        builder=builder,
        toolchain=toolchain,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    _validate_prefix(context, execution, evidence)
    if execution is None:
        try:
            execution = _persist_prepared(context, execution_store, lock=lock)
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy monitoring-targets prepared intent persistence failed "
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
        raise StateConflictError("deploy monitoring-targets state drifted before start")
    _validate_prefix(before_start, execution, evidence)
    try:
        execution = _persist_started(execution_store, execution, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy monitoring-targets authorization consumption failed before invocation"
        ) from error

    scope = before_start.scope
    try:
        result, command_digest = service.execute_operation_step(
            lock,
            before_start.metadata,
            before_start.inventory,
            _PLAYBOOK,
            step_sequence=scope.step_sequence,
            limit=(scope.authorization.target_stable_id,),
            variables=dict(scope.variables),
            readiness=before_start.readiness,
            tags=(),
            check=False,
            diff=False,
            verbosity=0,
        )
        if command_digest != scope.command_digest:
            raise AnsibleResultError(
                "deploy monitoring-targets command result identity conflicts"
            )
    except KeyboardInterrupt:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployMonitoringTargetsExecutionState.INTERRUPTED,
            lock=lock,
        )
        raise AnsibleError(
            "deploy monitoring-targets execution was interrupted; "
            "manual recovery required"
        ) from None
    except (AnsibleError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            (
                _failure_state(error)
                if isinstance(error, AnsibleError)
                else DeployMonitoringTargetsExecutionState.MALFORMED_RESULT
            ),
            lock=lock,
        )
        raise AnsibleError(
            "deploy monitoring-targets execution is uncertain; manual recovery required"
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
                "deploy monitoring-targets state changed after invocation"
            )
    except (StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployMonitoringTargetsExecutionState.DRIFTED,
            lock=lock,
        )
        raise StateConflictError(
            "deploy monitoring-targets state changed after invocation; "
            "manual recovery required"
        ) from error

    try:
        entry = _semantic_entry(scope, result)
    except (AnsibleError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            (
                _failure_state(error)
                if isinstance(error, AnsibleError)
                else DeployMonitoringTargetsExecutionState.MALFORMED_RESULT
            ),
            lock=lock,
        )
        raise AnsibleError(
            "deploy monitoring-targets result is not strict successful evidence; "
            "manual recovery required"
        ) from error

    try:
        evidence, evidence_state = _persist_evidence(
            context, evidence_store, entry, lock=lock
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy monitoring-targets evidence persistence failed; "
            "manual recovery required"
        ) from error
    try:
        execution = _persist_terminal_success(
            execution_store,
            execution,
            entry=entry,
            lock=lock,
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy monitoring-targets terminal persistence failed; "
            "manual recovery required"
        ) from error
    _validate_prefix(context, execution, evidence)
    return _build_report(
        context,
        execution,
        evidence,
        execution_state=DeployMonitoringTargetsArtifactState.UPDATED,
        evidence_state=evidence_state,
    )


def deploy_monitoring_targets_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MONITORING_TARGETS_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy monitoring-targets execution path is not canonical"
        )
    return path


def deploy_monitoring_targets_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MONITORING_TARGETS_EVIDENCE_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy monitoring-targets evidence path is not canonical"
        )
    return path


def deploy_monitoring_targets_execution_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_MONITORING_TARGETS_EXECUTION_FILENAME_SUFFIX
    )


def deploy_monitoring_targets_evidence_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_MONITORING_TARGETS_EVIDENCE_FILENAME_SUFFIX
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
    authorization_context = _load_authorization_context(paths, operation_id, lock=lock)
    monitoring_agent_context = authorization_context.agent.authorization_context
    manager_agent_context = monitoring_agent_context.manager.authorization_context
    loaded = _loaded(
        manager_agent_context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    journal = deploy.journal
    readiness_record = planning.readiness.record
    if (
        journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
        or readiness_record.executable_identity_digest != executable_identity_digest
        or readiness_record.toolchain_evidence_digest != toolchain_evidence_digest
        or readiness_record.playbook_version != str(toolchain.core)
        or readiness_record.inventory_version != str(toolchain.core)
        or readiness_record.remote_playbook_status != "not-performed"
    ):
        raise StateConflictError(
            "deploy monitoring-targets readiness, journal, or toolchain conflicts"
        )
    readiness = _reconstructed_readiness(planning.base)
    if readiness_binding_digest(readiness) != readiness_record.readiness_digest:
        raise StateConflictError("deploy monitoring-targets readiness is stale")
    readiness.require_ready(OperationClassification.MUTATING)

    authorization_store = DeployMonitoringTargetsAuthorizationStore(paths, operation_id)
    validate_state_file(authorization_store.path, allow_missing=True)
    if not authorization_store.path.exists():
        raise StateConflictError(
            "deploy monitoring-targets execution requires immutable authorization"
        )
    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    authorized_scope = _derive_authorization_scope(authorization_context)
    expected_authorization = _build_authorization(
        authorization_context,
        scope=authorized_scope,
        proof=authorization.record.proof,
        created_at=authorization.record.created_at,
    )
    if (
        authorization.record != expected_authorization
        or authorization.record.consumed
        or authorization.record.authorization_state != "authorized-pre-execution"
        or authorization.record.execution_state != "unavailable"
    ):
        raise StateConflictError(
            "deploy monitoring-targets authorization is stale or consumed"
        )

    scope = _derive_execution_scope(
        authorization_context,
        authorization,
        readiness=readiness,
        builder=builder,
    )
    trust = planning.base.trust
    post = authorization_context.post_agent
    stack_evidence = manager_agent_context.monitoring.evidence
    manager_server_evidence = (
        manager_agent_context.monitoring.monitoring.manager.evidence
    )
    manager_agent_evidence = monitoring_agent_context.manager.evidence
    monitoring_agent_evidence = authorization_context.agent.evidence
    base_os = manager_agent_context.monitoring.monitoring.manager.manager.base_os
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
        "authorization_artifact_digest": authorization.artifact_digest,
        "authorization_digest": authorization.record.authorization_digest,
        "authorization_scope_digest": authorization.record.authorization_scope_digest,
        "authorization_proof_digest": authorization.record.proof.proof_digest,
        "post_monitoring_agent_artifact_digest": post.artifact_digest,
        "post_monitoring_agent_record_digest": post.record.record_digest,
        "post_monitoring_agent_effective_plan_digest": (
            authorization.record.post_monitoring_agent_effective_plan_digest
        ),
        "monitoring_stack_evidence_artifact_digest": stack_evidence.artifact_digest,
        "manager_server_evidence_artifact_digest": (
            manager_server_evidence.artifact_digest
        ),
        "manager_agent_evidence_artifact_digest": (
            manager_agent_evidence.artifact_digest
        ),
        "monitoring_agent_evidence_artifact_digest": (
            monitoring_agent_evidence.artifact_digest
        ),
        "base_os_artifact_digest": base_os.artifact_digest,
        "base_os_evidence_digest": authorized_scope.base_os_evidence_digest,
        "metadata_generation": metadata.generation,
        "metadata_artifact_digest": deploy.metadata.digest,
        "desired_spec_digest": metadata.desired_spec.digest(),
        "observation_generation": deploy.observation.record.generation,
        "observation_artifact_digest": deploy.observation.digest,
        "observation_manifest_digest": deploy.observation.record.manifest_digest,
        "inventory_generation": deploy.inventory.record.generation,
        "inventory_artifact_digest": deploy.inventory.digest,
        "inventory_digest": deploy.inventory.record.inventory_digest,
        "trust_generation": trust.record.generation,
        "trust_artifact_digest": trust.digest,
        "trust_entries_digest": trust.record.entries_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": readiness_record.record_digest,
        "catalog_digest": loaded.catalog_digest,
        "source_version": loaded.source.version,
        "source_digest": loaded.source.digest,
        "playbook_source_digest": scope.source_digest,
        "toolchain_version": str(toolchain.core),
        "executable_identity_digest": executable_identity_digest,
        "toolchain_evidence_digest": toolchain_evidence_digest,
        "target_stable_id": authorized_scope.target_stable_id,
        "target_set_digest": authorized_scope.target_digest,
        "target_intent_digest": authorized_scope.target_intent_digest,
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "execution_scope_digest": _digest_object(
            {
                "authorization_scope_digest": scope.authorization_scope_digest,
                "command_digest": scope.command_digest,
                "mapping_sequence": _MAPPING_SEQUENCE,
                "source_digest": scope.source_digest,
                "target_intent_digest": authorized_scope.target_intent_digest,
                "target_set_digest": authorized_scope.target_digest,
                "variables_digest": scope.variables_digest,
            }
        ),
        "binding_digest": "",
    }
    binding_values["binding_digest"] = _binding_digest_from_values(binding_values)
    return _ExecutionContext(
        authorization_context,
        authorization,
        DeployMonitoringTargetsExecutionBinding(**binding_values),  # type: ignore[arg-type]
        scope,
        metadata,
        deploy.inventory,
        readiness,
    )


def _derive_execution_scope(
    context: _AuthorizationContext,
    authorization: StoredDeployMonitoringTargetsAuthorization,
    *,
    readiness: ReadinessReport,
    builder: AnsibleCommandBuilder,
) -> _ExecutionScope:
    monitoring_agent_context = context.agent.authorization_context
    manager_agent_context = monitoring_agent_context.manager.authorization_context
    loaded = _loaded(
        manager_agent_context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    authorized = authorization.record.scope
    definition = get_playbook(_PLAYBOOK)
    source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
    steps = tuple(
        step
        for step in context.post_agent.record.steps
        if step.mapping_sequence == _MAPPING_SEQUENCE
    )
    base_matches = tuple(
        (entry, host)
        for entry in manager_agent_context.monitoring.monitoring.manager.manager.base_os.record.entries
        for host in entry.hosts
        if host.logical_id == authorized.target_stable_id
    )
    image_filter = dict(metadata.desired_spec.image_filters).get(HostRole.MONITORING)
    if (
        len(steps) != 1
        or len(base_matches) != 1
        or image_filter != ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT)
        or authorized.playbook != _PLAYBOOK
        or authorized.mapping_sequence != _MAPPING_SEQUENCE
        or authorized.classification is not OperationClassification.MUTATING
        or authorized.target_role != HostRole.MONITORING.value
        or authorized.source_digest != source_digest
        or definition.classification is not OperationClassification.MUTATING
        or definition.hosts != HostRole.MONITORING.value
        or definition.serial != 1
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.check_mode is not CheckMode.PREVIEW
        or not definition.any_errors_fatal
        or not definition.source_available
    ):
        raise StateConflictError(
            "deploy monitoring-targets exact authorized scope conflicts"
        )
    step = steps[0]
    base_entry, base_host = base_matches[0]
    if (
        len(step.target_ids) != 1
        or step.target_ids[0] != authorized.target_stable_id
        or base_host.os_family != "Ubuntu"
        or base_host.os_version != "24.04"
        or base_host.image_architecture not in {"amd64", "aarch64"}
        or base_host.status not in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
        or not base_host.applied
        or base_host.reboot_required
        or base_entry.evidence_digest != authorized.base_os_evidence_digest
    ):
        raise StateConflictError(
            "deploy monitoring-targets current target or base-os evidence conflicts"
        )
    base_os = BaseOsEvidence(
        base_host.status,
        (
            BaseOsHostEvidence(
                base_host.logical_id,
                base_host.status,
                base_host.changed,
                base_host.reboot_required,
                "canonical-deploy-evidence",
            ),
        ),
    )
    stack_entry = manager_agent_context.monitoring.evidence.record.entries[0]
    stack_payload = build_monitoring_stack_payload(
        metadata,
        deploy.observation,
        deploy.inventory,
        readiness,
        base_os,
        logical_id=authorized.target_stable_id,
        image_filter=image_filter,
        architecture=base_host.image_architecture,
        stack_version=STACK_VERSION,
        cluster_spec_digest=metadata.desired_spec.digest(),
    )
    stack = _reconstruct_stack_evidence(stack_entry, stack_payload)
    target_readiness = replace(
        readiness,
        observation_digest=deploy.observation.digest,
    )
    payload = build_monitoring_targets_payload(
        metadata,
        deploy.observation,
        deploy.inventory,
        target_readiness,
        base_os,
        stack,
        logical_id=authorized.target_stable_id,
        image_filter=image_filter,
        architecture=base_host.image_architecture,
        cluster_spec_digest=metadata.desired_spec.digest(),
    )
    scylla_ids = tuple(
        sorted(
            host.logical_id
            for host in deploy.inventory.record.inventory.hosts
            if host.role is HostRole.SCYLLA
        )
    )
    manager_ids = tuple(
        sorted(
            host.logical_id
            for host in deploy.inventory.record.inventory.hosts
            if host.role is HostRole.MANAGER
        )
    )
    intent = _validate_target_payload(
        payload,
        stable_id=authorized.target_stable_id,
        scylla_ids=scylla_ids,
        manager_ids=manager_ids,
    )
    if (
        any(getattr(authorized, name) != value for name, value in intent.items())
        or payload.get("listen_policy") != LISTEN_POLICY
        or payload.get("scrape_readiness") != SCRAPE_READINESS
    ):
        raise StateConflictError(
            "deploy monitoring-targets official target-file intent conflicts"
        )
    variables = {"deploy_scylla_vms_monitoring_targets": payload}
    selected, validated, variables_digest, command_digest = (
        builder.validate_operation_step(
            _PLAYBOOK,
            step_sequence=step.sequence,
            limit=(authorized.target_stable_id,),
            variables=variables,
            tags=(),
            check=False,
            diff=False,
            verbosity=0,
        )
    )
    if (
        selected != definition
        or variables_digest != authorized.variables_digest
        or command_digest != authorized.command_digest
    ):
        raise StateConflictError(
            "deploy monitoring-targets anchored command policy conflicts"
        )
    return _ExecutionScope(
        authorized,
        _digest_object(authorized.to_object()),
        tuple(sorted(validated.items())),
        variables_digest,
        command_digest,
        source_digest,
        step.sequence,
        base_host.image_architecture,
    )


def _validate_prefix(
    context: _ExecutionContext,
    execution: StoredDeployMonitoringTargetsExecution | None,
    evidence: StoredDeployMonitoringTargetsEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "deploy monitoring-targets evidence exists without execution"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError(
            "deploy monitoring-targets execution provenance is stale"
        )
    attempt = execution.record.attempt
    scope = context.scope
    authorized = scope.authorization
    if (
        attempt.mapping_sequence != authorized.mapping_sequence
        or attempt.stable_id != authorized.target_stable_id
        or attempt.target_digest != authorized.target_digest
        or attempt.authorization_scope_digest != scope.authorization_scope_digest
        or attempt.authorization_variables_digest != authorized.variables_digest
        or attempt.authorization_command_digest != authorized.command_digest
        or attempt.variables_digest != scope.variables_digest
        or attempt.command_digest != scope.command_digest
        or attempt.source_digest != scope.source_digest
        or attempt.target_intent_digest != context.binding.target_intent_digest
    ):
        raise StateConflictError("deploy monitoring-targets execution scope conflicts")
    if evidence is None:
        if execution.record.state is DeployMonitoringTargetsExecutionState.SUCCEEDED:
            raise StateConflictError(
                "deploy monitoring-targets success evidence is missing"
            )
        return
    if evidence.record.binding != context.binding or execution.record.state not in {
        DeployMonitoringTargetsExecutionState.STARTED,
        DeployMonitoringTargetsExecutionState.SUCCEEDED,
    }:
        raise StateConflictError(
            "deploy monitoring-targets execution/evidence prefixes conflict"
        )
    entry = evidence.record.entries[0]
    if (
        entry.stable_id != authorized.target_stable_id
        or entry.mapping_sequence != authorized.mapping_sequence
        or entry.variables_digest != scope.variables_digest
        or entry.command_digest != scope.command_digest
        or entry.source_digest != scope.source_digest
        or (
            attempt.result_digest is not None
            and attempt.result_digest != entry.result_digest
        )
        or (
            attempt.evidence_digest is not None
            and attempt.evidence_digest != entry.evidence_digest
        )
    ):
        raise StateConflictError(
            "deploy monitoring-targets semantic evidence conflicts"
        )


def _persist_prepared(
    context: _ExecutionContext,
    store: DeployMonitoringTargetsExecutionStore,
    *,
    lock: ClusterLock,
) -> StoredDeployMonitoringTargetsExecution:
    now = _timestamp()
    scope = context.scope
    attempt = DeployMonitoringTargetsExecutionAttempt(
        attempt_index=1,
        mapping_sequence=_MAPPING_SEQUENCE,
        stable_id=scope.authorization.target_stable_id,
        target_digest=scope.authorization.target_digest,
        authorization_scope_digest=scope.authorization_scope_digest,
        authorization_variables_digest=scope.authorization.variables_digest,
        authorization_command_digest=scope.authorization.command_digest,
        variables_digest=scope.variables_digest,
        command_digest=scope.command_digest,
        source_digest=scope.source_digest,
        stack_version_digest=_digest_object(STACK_VERSION),
        target_intent_digest=context.binding.target_intent_digest,
        state=DeployMonitoringTargetsExecutionState.PREPARED,
        prepared_at=now,
        started_at=None,
        completed_at=None,
        authorization_consumed_at_start=False,
        invocation_may_have_occurred=False,
        exit_code=None,
        result_digest=None,
        evidence_digest=None,
        manual_recovery_required=False,
    )
    record = DeployMonitoringTargetsExecution(
        generation=1,
        created_at=now,
        updated_at=now,
        binding=context.binding,
        state=DeployMonitoringTargetsExecutionState.PREPARED,
        authorization_consumed=False,
        invocation_count=0,
        completed=False,
        attempt=attempt,
    )
    return store.write_locked(
        record,
        expected_generation=0,
        expected_digest=None,
        lock=lock,
    )


def _persist_started(
    store: DeployMonitoringTargetsExecutionStore,
    current: StoredDeployMonitoringTargetsExecution,
    *,
    lock: ClusterLock,
) -> StoredDeployMonitoringTargetsExecution:
    if current.record.state is not DeployMonitoringTargetsExecutionState.PREPARED:
        raise StateConflictError(
            "deploy monitoring-targets start requires prepared intent"
        )
    now = _timestamp()
    attempt = replace(
        current.record.attempt,
        state=DeployMonitoringTargetsExecutionState.STARTED,
        started_at=now,
        authorization_consumed_at_start=True,
        invocation_may_have_occurred=True,
        manual_recovery_required=True,
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=DeployMonitoringTargetsExecutionState.STARTED,
        authorization_consumed=True,
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
    store: DeployMonitoringTargetsExecutionStore,
    current: StoredDeployMonitoringTargetsExecution,
    state: DeployMonitoringTargetsExecutionState,
    *,
    lock: ClusterLock,
) -> None:
    try:
        _persist_uncertain(store, current, state, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy monitoring-targets uncertain outcome persistence failed; "
            "manual recovery required"
        ) from error


def _persist_uncertain(
    store: DeployMonitoringTargetsExecutionStore,
    current: StoredDeployMonitoringTargetsExecution,
    state: DeployMonitoringTargetsExecutionState,
    *,
    lock: ClusterLock,
) -> StoredDeployMonitoringTargetsExecution:
    if (
        current.record.state is not DeployMonitoringTargetsExecutionState.STARTED
        or state
        not in {
            DeployMonitoringTargetsExecutionState.FAILED,
            DeployMonitoringTargetsExecutionState.TIMED_OUT,
            DeployMonitoringTargetsExecutionState.INTERRUPTED,
            DeployMonitoringTargetsExecutionState.UNREACHABLE,
            DeployMonitoringTargetsExecutionState.MALFORMED_RESULT,
            DeployMonitoringTargetsExecutionState.DRIFTED,
        }
    ):
        raise StatePersistenceError(
            "deploy monitoring-targets uncertain transition conflicts"
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
        attempt=attempt,
    )
    return store.write_locked(
        record,
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _persist_evidence(
    context: _ExecutionContext,
    store: DeployMonitoringTargetsEvidenceStore,
    entry: DeployMonitoringTargetsEvidenceEntry,
    *,
    lock: ClusterLock,
) -> tuple[
    StoredDeployMonitoringTargetsEvidence,
    DeployMonitoringTargetsArtifactState,
]:
    now = _timestamp()
    record = DeployMonitoringTargetsEvidence(
        generation=1,
        created_at=now,
        updated_at=now,
        binding=context.binding,
        entries=(entry,),
    )
    return store.write_locked(record, lock=lock)


def _persist_terminal_success(
    store: DeployMonitoringTargetsExecutionStore,
    current: StoredDeployMonitoringTargetsExecution,
    *,
    entry: DeployMonitoringTargetsEvidenceEntry,
    lock: ClusterLock,
) -> StoredDeployMonitoringTargetsExecution:
    if current.record.state is not DeployMonitoringTargetsExecutionState.STARTED:
        raise StateConflictError(
            "deploy monitoring-targets terminal transition conflicts"
        )
    now = _timestamp()
    attempt = replace(
        current.record.attempt,
        state=DeployMonitoringTargetsExecutionState.SUCCEEDED,
        completed_at=now,
        exit_code=0,
        result_digest=entry.result_digest,
        evidence_digest=entry.evidence_digest,
        manual_recovery_required=False,
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=DeployMonitoringTargetsExecutionState.SUCCEEDED,
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
) -> DeployMonitoringTargetsEvidenceEntry:
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.MUTATING
        or result.check_mode
        or result.monitoring_targets is not None
    ):
        raise AnsibleResultError(
            "deploy monitoring-targets strict result identity conflicts"
        )
    payload = cast(
        dict[str, object],
        dict(scope.variables)["deploy_scylla_vms_monitoring_targets"],
    )
    try:
        parsed = parse_monitoring_targets_execution(
            result.stdout,
            expected_payload=payload,
            exit_code=result.exit_code,
        )
    except AnsibleError as error:
        raise AnsibleResultError(
            "deploy monitoring-targets strict result is malformed"
        ) from error
    if parsed.status not in _SUCCESS_STATUSES:
        message = "unreachable" if result.exit_code == 4 else "execution failed"
        raise AnsibleError(f"deploy monitoring-targets {message}")
    _validate_success_evidence(parsed, scope.authorization)
    prohibited = _prohibited_result_flags(parsed)
    files = tuple(parsed.files)
    content_set_digest = _digest_object(sorted(digest for _path, digest in files))
    file_set_digest = _digest_object(
        sorted(
            _digest_object({"name": Path(path).name, "path": path})
            for path, _digest in files
        )
    )
    counts = dict(parsed.target_counts)
    identities = dict(parsed.identities)
    result_digest = _digest_object(
        {
            "changed": parsed.status is MonitoringTargetsStatus.GENERATED,
            "file_content_set_digest": content_set_digest,
            "file_count": len(files),
            "file_set_digest": file_set_digest,
            "listen_policy": parsed.listen_policy,
            "logical_id": parsed.logical_id,
            "manager_agent_target_count": counts["manager_agent"],
            "manager_identity_set_digest": _digest_object(list(identities["manager"])),
            "manager_target_count": counts["manager"],
            "node_exporter_target_count": counts["node_exporter"],
            "prohibited_action_count": sum(prohibited),
            "provenance_digest": _digest_object(dict(parsed.provenance)),
            "schema_version": parsed.schema_version,
            "scrape_readiness": parsed.scrape_readiness,
            "scylla_identity_set_digest": _digest_object(list(identities["scylla"])),
            "scylla_target_count": counts["scylla"],
            "status": parsed.status.value,
        }
    )
    values: dict[str, object] = {
        "attempt_index": 1,
        "mapping_sequence": _MAPPING_SEQUENCE,
        "stable_id": scope.authorization.target_stable_id,
        "image_architecture": scope.image_architecture,
        "status": parsed.status,
        "generated": True,
        "changed": parsed.status is MonitoringTargetsStatus.GENERATED,
        "stack_version_digest": _digest_object(STACK_VERSION),
        "file_count": len(files),
        "file_set_digest": file_set_digest,
        "file_content_set_digest": content_set_digest,
        "manager_target_count": counts["manager"],
        "scylla_target_count": counts["scylla"],
        "node_exporter_target_count": counts["node_exporter"],
        "manager_agent_target_count": counts["manager_agent"],
        "manager_identity_set_digest": _digest_object(list(identities["manager"])),
        "scylla_identity_set_digest": _digest_object(list(identities["scylla"])),
        "listen_policy": parsed.listen_policy,
        "scrape_readiness": parsed.scrape_readiness,
        "scrape_performed": parsed.scrape_performed,
        "exporters_started": parsed.exporters_started,
        "stack_started": parsed.stack_started,
        "containers_started": parsed.containers_started,
        "compose_generated": parsed.compose_generated,
        "auth_configured": parsed.auth_configured,
        "public_bind": parsed.public_bind,
        "manager_registration_performed": parsed.manager_registration_performed,
        "scylla_started": parsed.scylla_started,
        "secrets_written": parsed.secrets_written,
        "provenance_digest": _digest_object(dict(parsed.provenance)),
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "source_digest": scope.source_digest,
        "result_digest": result_digest,
        "evidence_digest": "",
    }
    values["evidence_digest"] = _evidence_entry_digest_from_values(values)
    return DeployMonitoringTargetsEvidenceEntry(**values)  # type: ignore[arg-type]


def _validate_success_evidence(
    evidence: MonitoringTargetsEvidence,
    authorized: DeployMonitoringTargetsAuthorizationScope,
) -> None:
    files = tuple(evidence.files)
    counts = dict(evidence.target_counts)
    identities = dict(evidence.identities)
    file_set_digest = _digest_object(
        sorted(
            _digest_object({"name": Path(path).name, "path": path})
            for path, _digest in files
        )
    )
    content_set_digest = _digest_object(sorted(digest for _path, digest in files))
    if (
        evidence.logical_id != authorized.target_stable_id
        or evidence.stack_version != STACK_VERSION
        or len(files) != authorized.file_count
        or file_set_digest != authorized.file_set_digest
        or content_set_digest != authorized.file_content_set_digest
        or counts.get("manager") != authorized.manager_target_count
        or counts.get("scylla") != authorized.scylla_target_count
        or counts.get("node_exporter") != authorized.node_exporter_target_count
        or counts.get("manager_agent") != authorized.manager_agent_target_count
        or _digest_object(list(identities.get("manager", ())))
        != authorized.manager_identity_set_digest
        or _digest_object(list(identities.get("scylla", ())))
        != authorized.scylla_identity_set_digest
        or evidence.listen_policy != LISTEN_POLICY
        or evidence.scrape_readiness != SCRAPE_READINESS
        or any(_prohibited_result_flags(evidence))
        or evidence.blockers
    ):
        raise AnsibleResultError(
            "deploy monitoring-targets successful evidence conflicts"
        )


def _prohibited_result_flags(
    evidence: MonitoringTargetsEvidence,
) -> tuple[bool, ...]:
    return (
        evidence.scrape_performed,
        evidence.exporters_started,
        evidence.stack_started,
        evidence.containers_started,
        evidence.compose_generated,
        evidence.auth_configured,
        evidence.public_bind,
        evidence.manager_registration_performed,
        evidence.scylla_started,
        evidence.secrets_written,
    )


def _build_report(
    context: _ExecutionContext,
    execution: StoredDeployMonitoringTargetsExecution,
    evidence: StoredDeployMonitoringTargetsEvidence,
    *,
    execution_state: DeployMonitoringTargetsArtifactState,
    evidence_state: DeployMonitoringTargetsArtifactState,
) -> DeployMonitoringTargetsExecutionReport:
    if (
        not execution.record.completed
        or execution.record.state is not DeployMonitoringTargetsExecutionState.SUCCEEDED
        or len(evidence.record.entries) != 1
    ):
        raise StateConflictError("deploy monitoring-targets execution is not complete")
    entry = evidence.record.entries[0]
    prohibited = (
        entry.scrape_performed,
        entry.exporters_started,
        entry.stack_started,
        entry.containers_started,
        entry.compose_generated,
        entry.auth_configured,
        entry.public_bind,
        entry.manager_registration_performed,
        entry.scylla_started,
        entry.secrets_written,
    )
    return DeployMonitoringTargetsExecutionReport(
        operation_id=context.binding.operation_id,
        execution_state=execution.record.state,
        execution_artifact_state=execution_state,
        evidence_artifact_state=evidence_state,
        execution_artifact_digest=execution.artifact_digest,
        evidence_artifact_digest=evidence.artifact_digest,
        binding_digest=context.binding.binding_digest,
        authorization_artifact_digest=context.authorization.artifact_digest,
        authorization_digest=context.authorization.record.authorization_digest,
        authorization_consumed=execution.record.authorization_consumed,
        target_stable_id=context.binding.target_stable_id,
        target_set_digest=context.binding.target_set_digest,
        stage=_STAGE,
        scope_kind=_SCOPE_KIND,
        invocation_count=execution.record.invocation_count,
        generated_count=int(entry.generated),
        changed_count=int(entry.changed),
        stack_version_digest=entry.stack_version_digest,
        file_count=entry.file_count,
        file_set_digest=entry.file_set_digest,
        file_content_set_digest=entry.file_content_set_digest,
        manager_target_count=entry.manager_target_count,
        scylla_target_count=entry.scylla_target_count,
        node_exporter_target_count=entry.node_exporter_target_count,
        manager_agent_target_count=entry.manager_agent_target_count,
        manager_identity_set_digest=entry.manager_identity_set_digest,
        scylla_identity_set_digest=entry.scylla_identity_set_digest,
        listen_policy=entry.listen_policy,
        scrape_readiness=entry.scrape_readiness,
        prohibited_action_count=sum(prohibited),
        manual_recovery_required=False,
        automatic_retry_allowed=False,
        skip_allowed=False,
        continue_allowed=False,
        rollback_performed=False,
        journal_status=context.binding.journal_status,
        journal_phase=context.binding.journal_phase,
    )


def _failure_state(error: AnsibleError) -> DeployMonitoringTargetsExecutionState:
    cause = error.__cause__
    if isinstance(cause, ProcessTimeoutError):
        return DeployMonitoringTargetsExecutionState.TIMED_OUT
    if isinstance(cause, ProcessOutputError):
        return DeployMonitoringTargetsExecutionState.MALFORMED_RESULT
    message = str(error).lower()
    if "unreachable" in message:
        return DeployMonitoringTargetsExecutionState.UNREACHABLE
    if isinstance(error, AnsibleResultError) or "malformed" in message:
        return DeployMonitoringTargetsExecutionState.MALFORMED_RESULT
    return DeployMonitoringTargetsExecutionState.FAILED


def _validate_execution_transition(
    current: DeployMonitoringTargetsExecution,
    replacement: DeployMonitoringTargetsExecution,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or current.completed
    ):
        raise StatePersistenceError(
            "deploy monitoring-targets execution transition is invalid"
        )
    if current.state is DeployMonitoringTargetsExecutionState.PREPARED:
        valid = replacement.state is DeployMonitoringTargetsExecutionState.STARTED
    elif current.state is DeployMonitoringTargetsExecutionState.STARTED:
        valid = replacement.state not in {
            DeployMonitoringTargetsExecutionState.PREPARED,
            DeployMonitoringTargetsExecutionState.STARTED,
        }
    else:
        valid = False
    if not valid:
        raise StatePersistenceError(
            "deploy monitoring-targets execution transition conflicts"
        )


def _binding_digest(binding: DeployMonitoringTargetsExecutionBinding) -> str:
    value = binding.to_object()
    value["binding_digest"] = ""
    return _digest_object(value)


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployMonitoringTargetsExecutionBinding.__dataclass_fields__.items():
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


def _evidence_entry_digest(entry: DeployMonitoringTargetsEvidenceEntry) -> str:
    value = entry.to_object()
    value["evidence_digest"] = ""
    return _digest_object(value)


def _evidence_entry_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployMonitoringTargetsEvidenceEntry.__dataclass_fields__.items():
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


def _digest_fields(value: object) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(value, name))
        for name in value.__dataclass_fields__  # type: ignore[attr-defined]
        if name.endswith("_digest")
    )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy monitoring-targets execution paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy monitoring-targets execution requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_or_later_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy monitoring-targets execution artifacts"
        ) from error
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_MONITORING_TARGETS_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_MONITORING_TARGETS_EVIDENCE_FILENAME_SUFFIX,
    )
    later_fragments = (
        ".ansible-deploy-post-monitoring-targets-reconciliation.json",
        ".ansible-deploy-manager-tasks",
        ".ansible-deploy-final-evidence",
    )
    for entry in entries:
        if entry.name.startswith(canonical) and any(
            fragment in entry.name for fragment in later_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy monitoring-targets execution refuses later-stage history"
            )
        for suffix in suffixes:
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
                    "deploy monitoring-targets execution artifacts are ambiguous"
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
            "deploy monitoring-targets toolchain version is invalid"
        ) from error


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise StatePersistenceError(f"{label} must be an array")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    if value is None:
        return None
    return _integer(value, label)


def _positive_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be a boolean")
    return value


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise StatePersistenceError(f"{label} must be a string or null")
    return value


def _optional_timestamp(value: str | None) -> datetime | None:
    return None if value is None else parse_timestamp(value)


def _enum(enum_type: type[StrEnum], value: str, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except ValueError as error:
        raise StatePersistenceError(f"{label} is invalid") from error


__all__ = [
    "ANSIBLE_DEPLOY_MONITORING_TARGETS_EVIDENCE_ENTRY_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MONITORING_TARGETS_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_BINDING_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MONITORING_TARGETS_EXECUTION_SCHEMA_VERSION",
    "DEPLOY_MONITORING_TARGETS_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_MONITORING_TARGETS_EXECUTION_FILENAME_SUFFIX",
    "DeployMonitoringTargetsArtifactState",
    "DeployMonitoringTargetsEvidence",
    "DeployMonitoringTargetsEvidenceEntry",
    "DeployMonitoringTargetsEvidenceStore",
    "DeployMonitoringTargetsExecution",
    "DeployMonitoringTargetsExecutionAttempt",
    "DeployMonitoringTargetsExecutionBinding",
    "DeployMonitoringTargetsExecutionReport",
    "DeployMonitoringTargetsExecutionState",
    "DeployMonitoringTargetsExecutionStore",
    "StoredDeployMonitoringTargetsEvidence",
    "StoredDeployMonitoringTargetsExecution",
    "deploy_monitoring_targets_evidence_id_from_filename",
    "deploy_monitoring_targets_evidence_path",
    "deploy_monitoring_targets_execution_id_from_filename",
    "deploy_monitoring_targets_execution_path",
    "execute_deploy_monitoring_targets",
]
