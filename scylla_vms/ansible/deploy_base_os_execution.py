"""Exact-scope deploy ``base-os`` execution with durable authorization use.

This internal owner derives every executable input from canonical state.  It
records a retry-safe prepared prefix, consumes the immutable authorization in a
durable started record immediately before effect, and never retries a started
attempt automatically.
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
    BASE_OS_EVIDENCE_SCHEMA_VERSION,
    BaseOsEvidence,
    BaseOsHostEvidence,
    BaseOsStatus,
    base_os_variables,
)
from scylla_vms.ansible.commands import AnsibleCommandBuilder
from scylla_vms.ansible.deploy_authorization import (
    ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_SCHEMA_VERSION,
    DeployBaseOsAuthorizationScope,
    DeployBaseOsAuthorizationStore,
    StoredDeployBaseOsAuthorization,
    _build_authorization,
    _derive_authorization_scopes,
)
from scylla_vms.ansible.deploy_host_evidence import (
    DeployPreMutationEvidenceEntry,
    PreMutationHostEvidence,
)
from scylla_vms.ansible.deploy_host_reconciliation import (
    ANSIBLE_DEPLOY_HOST_RECONCILIATION_SCHEMA_VERSION,
    DeployHostEvidenceReconciliationStore,
    StoredDeployHostEvidenceReconciliation,
    _build_reconciled_steps,
    _build_reconciliation_record,
    _HostReconciliationContext,
    _load_host_reconciliation_context,
)
from scylla_vms.ansible.deploy_plan import (
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.evidence import EvidenceStatus
from scylla_vms.ansible.operation_binding import readiness_binding_digest
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.readiness import ReadinessReport
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
from scylla_vms.desired import ImageVersionMatch
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

ANSIBLE_DEPLOY_BASE_OS_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-base-os-execution-binding/v1"
)
ANSIBLE_DEPLOY_BASE_OS_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-base-os-execution/v1"
)
ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-base-os-evidence/v1"
)
ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_ENTRY_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-base-os-evidence-entry/v1"
)
ANSIBLE_DEPLOY_BASE_OS_HOST_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-base-os-host-evidence/v1"
)
ANSIBLE_DEPLOY_BASE_OS_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-base-os-execution-report/v1"
)

DEPLOY_BASE_OS_EXECUTION_FILENAME_SUFFIX = ".ansible-deploy-base-os-execution.json"
DEPLOY_BASE_OS_EVIDENCE_FILENAME_SUFFIX = ".ansible-deploy-base-os-evidence.json"

_OPERATION = "deploy"
_PLAYBOOK = "base-os"
_MAPPING_SEQUENCE = 3
_SUCCESS_STATUSES = frozenset(
    {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED, BaseOsStatus.REBOOT_REQUIRED}
)
_SAFE_GUEST_ARCHITECTURES = {"x86_64": "amd64", "aarch64": "aarch64"}
_SAFE_SERVICE_STATES = frozenset({"inactive", "stopped"})
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SUPPORTED_OS_VERSION = re.compile(r"24\.04(?:\.[0-9]+)?\Z")


class DeployBaseOsExecutionState(StrEnum):
    """Bounded durable states for exact authorized playbook instances."""

    PREPARED = "prepared"
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"


@dataclass(frozen=True, slots=True)
class DeployBaseOsExecutionBinding:
    """Address-free binding of authorization, current state, and toolchain."""

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
    host_reconciliation_artifact_digest: str
    host_reconciliation_record_digest: str
    host_reconciled_plan_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    catalog_digest: str
    source_version: str
    source_digest: str
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
    scope_count: int
    stable_id_count: int
    stable_id_set_digest: str
    execution_scope_digest: str
    binding_digest: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
    )
    host_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_HOST_RECONCILIATION_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_BASE_OS_EXECUTION_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_BASE_OS_EXECUTION_BINDING_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
            or self.host_reconciliation_schema_version
            != ANSIBLE_DEPLOY_HOST_RECONCILIATION_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
        ):
            raise StatePersistenceError("deploy base-os execution binding is invalid")
        validate_cluster_name(self.cluster_name)
        for value, label in (
            (self.journal_generation, "journal generation"),
            (self.observation_generation, "observation generation"),
            (self.inventory_generation, "inventory generation"),
            (self.trust_generation, "trust generation"),
            (self.scope_count, "scope count"),
            (self.stable_id_count, "stable-ID count"),
        ):
            _positive_integer(value, f"deploy base-os {label}")
        _validate_toolchain_version(self.toolchain_version)
        for digest_value in _binding_digests(self):
            validate_digest(digest_value, "deploy base-os execution binding digest")
        if self.binding_digest != _binding_digest(self):
            raise StatePersistenceError(
                "deploy base-os execution binding digest conflicts"
            )

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
    def from_object(cls, value: Mapping[str, object]) -> DeployBaseOsExecutionBinding:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy base-os execution binding",
        )
        integer_fields = {
            "journal_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
            "scope_count",
            "stable_id_count",
        }
        parsed: dict[str, object] = {}
        for name in cls.__dataclass_fields__:
            if name == "cluster_uuid":
                parsed[name] = parse_uuid(
                    require_string(value, name), "base-os binding cluster UUID"
                )
            elif name == "operation_id":
                parsed[name] = parse_uuid(
                    require_string(value, name), "base-os binding operation ID"
                )
            elif name == "journal_status":
                parsed[name] = _enum(
                    JournalStatus,
                    require_string(value, name),
                    "base-os binding journal status",
                )
            elif name == "journal_phase":
                parsed[name] = _enum(
                    OperationPhase,
                    require_string(value, name),
                    "base-os binding journal phase",
                )
            elif name in integer_fields:
                parsed[name] = _integer(value[name], name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployBaseOsExecutionAttempt:
    """One prepared, started, or terminal exact authorized instance."""

    attempt_index: int
    step_sequence: int
    target_ids: tuple[str, ...]
    target_digest: str
    authorization_scope_digest: str
    authorization_variables_digest: str
    authorization_command_digest: str
    variables_digest: str
    command_digest: str
    source_digest: str
    result_schema_version: str
    state: DeployBaseOsExecutionState
    prepared_at: str
    started_at: str | None
    completed_at: str | None
    authorization_consumed: bool
    invocation_may_have_occurred: bool
    exit_code: int | None
    result_digest: str | None
    evidence_digest: str | None
    manual_recovery_required: bool
    automatic_retry_allowed: bool = False

    def __post_init__(self) -> None:
        if (
            self.attempt_index < 1
            or self.step_sequence < 1
            or self.target_ids != tuple(sorted(set(self.target_ids)))
            or not self.target_ids
            or any(_LOGICAL_ID.fullmatch(item) is None for item in self.target_ids)
            or self.target_digest != _digest_object(list(self.target_ids))
            or self.result_schema_version != BASE_OS_EVIDENCE_SCHEMA_VERSION
            or not isinstance(self.state, DeployBaseOsExecutionState)
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError("deploy base-os execution attempt is invalid")
        prepared = parse_timestamp(self.prepared_at)
        started = _optional_timestamp(self.started_at)
        completed = _optional_timestamp(self.completed_at)
        if (
            (started is not None and started < prepared)
            or (completed is not None and started is None)
            or (completed is not None and started is not None and completed < started)
        ):
            raise StatePersistenceError("deploy base-os attempt timestamps are invalid")
        for digest_value in (
            self.target_digest,
            self.authorization_scope_digest,
            self.authorization_variables_digest,
            self.authorization_command_digest,
            self.variables_digest,
            self.command_digest,
            self.source_digest,
        ):
            validate_digest(digest_value, "deploy base-os attempt digest")
        for optional_digest in (self.result_digest, self.evidence_digest):
            if optional_digest is not None:
                validate_digest(optional_digest, "deploy base-os outcome digest")
        if self.exit_code is not None and (
            isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)
        ):
            raise StatePersistenceError("deploy base-os exit code is invalid")
        self._validate_state(started, completed)

    def _validate_state(
        self,
        started: datetime | None,
        completed: datetime | None,
    ) -> None:
        if self.state is DeployBaseOsExecutionState.PREPARED:
            if (
                started is not None
                or completed is not None
                or self.authorization_consumed
                or self.invocation_may_have_occurred
                or self.exit_code is not None
                or self.result_digest is not None
                or self.evidence_digest is not None
                or self.manual_recovery_required
            ):
                raise StatePersistenceError(
                    "prepared deploy base-os attempt fields conflict"
                )
            return
        if (
            started is None
            or not self.authorization_consumed
            or not self.invocation_may_have_occurred
        ):
            raise StatePersistenceError(
                "started deploy base-os authorization consumption conflicts"
            )
        if self.state is DeployBaseOsExecutionState.STARTED:
            if (
                completed is not None
                or self.exit_code is not None
                or self.result_digest is not None
                or self.evidence_digest is not None
                or not self.manual_recovery_required
            ):
                raise StatePersistenceError("started deploy base-os fields conflict")
            return
        if completed is None:
            raise StatePersistenceError("terminal deploy base-os time is missing")
        if self.state is DeployBaseOsExecutionState.SUCCEEDED:
            if (
                self.exit_code != 0
                or self.result_digest is None
                or self.evidence_digest is None
                or self.manual_recovery_required
            ):
                raise StatePersistenceError(
                    "successful deploy base-os evidence conflicts"
                )
        elif self.state in {
            DeployBaseOsExecutionState.FAILED,
            DeployBaseOsExecutionState.UNREACHABLE,
        }:
            if (
                self.exit_code is None
                or self.exit_code == 0
                or self.result_digest is None
                or self.evidence_digest is None
                or not self.manual_recovery_required
            ):
                raise StatePersistenceError("failed deploy base-os evidence conflicts")
        elif (
            self.exit_code is not None
            or self.result_digest is not None
            or self.evidence_digest is not None
            or not self.manual_recovery_required
        ):
            raise StatePersistenceError("uncertain deploy base-os evidence conflicts")

    def to_object(self) -> dict[str, object]:
        return {
            "attempt_index": self.attempt_index,
            "authorization_command_digest": self.authorization_command_digest,
            "authorization_consumed": self.authorization_consumed,
            "authorization_scope_digest": self.authorization_scope_digest,
            "authorization_variables_digest": self.authorization_variables_digest,
            "automatic_retry_allowed": self.automatic_retry_allowed,
            "command_digest": self.command_digest,
            "completed_at": self.completed_at,
            "evidence_digest": self.evidence_digest,
            "exit_code": self.exit_code,
            "invocation_may_have_occurred": self.invocation_may_have_occurred,
            "manual_recovery_required": self.manual_recovery_required,
            "prepared_at": self.prepared_at,
            "result_digest": self.result_digest,
            "result_schema_version": self.result_schema_version,
            "source_digest": self.source_digest,
            "started_at": self.started_at,
            "state": self.state.value,
            "step_sequence": self.step_sequence,
            "target_digest": self.target_digest,
            "target_ids": list(self.target_ids),
            "variables_digest": self.variables_digest,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployBaseOsExecutionAttempt:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy base-os execution attempt",
        )
        target_ids = value["target_ids"]
        if not isinstance(target_ids, list) or not all(
            isinstance(item, str) for item in target_ids
        ):
            raise StatePersistenceError("deploy base-os target IDs are invalid")
        return cls(
            attempt_index=_integer(value["attempt_index"], "attempt index"),
            step_sequence=_integer(value["step_sequence"], "step sequence"),
            target_ids=tuple(cast(list[str], target_ids)),
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
            result_schema_version=require_string(value, "result_schema_version"),
            state=cast(
                DeployBaseOsExecutionState,
                _enum(
                    DeployBaseOsExecutionState,
                    require_string(value, "state"),
                    "base-os attempt state",
                ),
            ),
            prepared_at=require_string(value, "prepared_at"),
            started_at=_optional_string(value["started_at"], "started_at"),
            completed_at=_optional_string(value["completed_at"], "completed_at"),
            authorization_consumed=_boolean(
                value["authorization_consumed"], "authorization consumed"
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
        )


@dataclass(frozen=True, slots=True)
class DeployBaseOsExecution:
    """Generation-guarded exact-scope durable execution state."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployBaseOsExecutionBinding
    state: DeployBaseOsExecutionState
    authorization_consumed: bool
    invocation_count: int
    all_scopes_completed: bool
    attempts: tuple[DeployBaseOsExecutionAttempt, ...]
    schema_version: str = ANSIBLE_DEPLOY_BASE_OS_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_BASE_OS_EXECUTION_SCHEMA_VERSION
            or not isinstance(self.binding, DeployBaseOsExecutionBinding)
            or not isinstance(self.state, DeployBaseOsExecutionState)
        ):
            raise StatePersistenceError("deploy base-os execution is invalid")
        _positive_integer(self.generation, "deploy base-os execution generation")
        if parse_timestamp(self.updated_at) < parse_timestamp(self.created_at):
            raise StatePersistenceError("deploy base-os execution timestamp regressed")
        if not 1 <= len(self.attempts) <= self.binding.scope_count:
            raise StatePersistenceError("deploy base-os attempt count is invalid")
        if tuple(attempt.attempt_index for attempt in self.attempts) != tuple(
            range(1, len(self.attempts) + 1)
        ):
            raise StatePersistenceError("deploy base-os attempt order conflicts")
        if (
            any(
                attempt.state is not DeployBaseOsExecutionState.SUCCEEDED
                for attempt in self.attempts[:-1]
            )
            or self.attempts[-1].state is not self.state
        ):
            raise StatePersistenceError("deploy base-os execution prefix conflicts")
        expected_invocations = sum(
            attempt.state is not DeployBaseOsExecutionState.PREPARED
            for attempt in self.attempts
        )
        if (
            self.invocation_count != expected_invocations
            or self.authorization_consumed != (expected_invocations > 0)
            or self.all_scopes_completed
            != (
                len(self.attempts) == self.binding.scope_count
                and all(
                    attempt.state is DeployBaseOsExecutionState.SUCCEEDED
                    for attempt in self.attempts
                )
            )
        ):
            raise StatePersistenceError("deploy base-os execution summary conflicts")

    def to_object(self) -> dict[str, object]:
        return {
            "all_scopes_completed": self.all_scopes_completed,
            "attempts": [attempt.to_object() for attempt in self.attempts],
            "authorization_consumed": self.authorization_consumed,
            "binding": self.binding.to_object(),
            "created_at": self.created_at,
            "generation": self.generation,
            "invocation_count": self.invocation_count,
            "schema_version": self.schema_version,
            "state": self.state.value,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployBaseOsExecution:
        require_exact_keys(
            value,
            {
                "all_scopes_completed",
                "attempts",
                "authorization_consumed",
                "binding",
                "created_at",
                "generation",
                "invocation_count",
                "schema_version",
                "state",
                "updated_at",
            },
            "deploy base-os execution",
        )
        binding = value["binding"]
        attempts = value["attempts"]
        if not isinstance(binding, Mapping) or not isinstance(attempts, list):
            raise StatePersistenceError("deploy base-os execution content is invalid")
        return cls(
            generation=_integer(value["generation"], "execution generation"),
            created_at=require_string(value, "created_at"),
            updated_at=require_string(value, "updated_at"),
            binding=DeployBaseOsExecutionBinding.from_object(binding),
            state=cast(
                DeployBaseOsExecutionState,
                _enum(
                    DeployBaseOsExecutionState,
                    require_string(value, "state"),
                    "base-os execution state",
                ),
            ),
            authorization_consumed=_boolean(
                value["authorization_consumed"], "authorization consumed"
            ),
            invocation_count=_integer(value["invocation_count"], "invocation count"),
            all_scopes_completed=_boolean(
                value["all_scopes_completed"], "scope completion"
            ),
            attempts=tuple(
                DeployBaseOsExecutionAttempt.from_object(
                    _mapping(item, "base-os execution attempt")
                )
                for item in attempts
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployBaseOsHostEvidence:
    """Address-free successful or failed facts for one exact stable ID."""

    logical_id: str
    os_family: str
    os_version: str
    image_architecture: str
    guest_architecture: str
    status: BaseOsStatus
    applied: bool
    changed: bool
    reboot_required: bool
    prerequisite_policy_status: str
    timesync_service_status: str
    schema_version: str = ANSIBLE_DEPLOY_BASE_OS_HOST_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        succeeded = self.status in _SUCCESS_STATUSES
        if (
            self.schema_version != ANSIBLE_DEPLOY_BASE_OS_HOST_EVIDENCE_SCHEMA_VERSION
            or _LOGICAL_ID.fullmatch(self.logical_id) is None
            or self.os_family != "Ubuntu"
            or self.os_version != "24.04"
            or self.image_architecture not in {"amd64", "aarch64"}
            or self.guest_architecture not in _SAFE_GUEST_ARCHITECTURES
            or _SAFE_GUEST_ARCHITECTURES[self.guest_architecture]
            != self.image_architecture
            or not isinstance(self.status, BaseOsStatus)
            or self.applied is not succeeded
            or self.prerequisite_policy_status
            != ("satisfied" if succeeded else "unverified")
            or self.timesync_service_status
            != ("enabled-active" if succeeded else "unverified")
        ):
            raise StatePersistenceError("deploy base-os host evidence is invalid")
        if (
            (
                self.status is BaseOsStatus.NO_CHANGE
                and (self.changed or self.reboot_required)
            )
            or (
                self.status is BaseOsStatus.CHANGED
                and (not self.changed or self.reboot_required)
            )
            or (
                self.status is BaseOsStatus.REBOOT_REQUIRED and not self.reboot_required
            )
            or (
                self.status in {BaseOsStatus.UNSUPPORTED, BaseOsStatus.FAILURE}
                and (self.changed or self.reboot_required)
            )
        ):
            raise StatePersistenceError("deploy base-os host outcome conflicts")

    def to_object(self) -> dict[str, object]:
        return {
            "applied": self.applied,
            "changed": self.changed,
            "guest_architecture": self.guest_architecture,
            "image_architecture": self.image_architecture,
            "logical_id": self.logical_id,
            "os_family": self.os_family,
            "os_version": self.os_version,
            "prerequisite_policy_status": self.prerequisite_policy_status,
            "reboot_required": self.reboot_required,
            "schema_version": self.schema_version,
            "status": self.status.value,
            "timesync_service_status": self.timesync_service_status,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployBaseOsHostEvidence:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy base-os host evidence",
        )
        return cls(
            logical_id=require_string(value, "logical_id"),
            os_family=require_string(value, "os_family"),
            os_version=require_string(value, "os_version"),
            image_architecture=require_string(value, "image_architecture"),
            guest_architecture=require_string(value, "guest_architecture"),
            status=cast(
                BaseOsStatus,
                _enum(
                    BaseOsStatus,
                    require_string(value, "status"),
                    "base-os host status",
                ),
            ),
            applied=_boolean(value["applied"], "applied"),
            changed=_boolean(value["changed"], "changed"),
            reboot_required=_boolean(value["reboot_required"], "reboot required"),
            prerequisite_policy_status=require_string(
                value, "prerequisite_policy_status"
            ),
            timesync_service_status=require_string(value, "timesync_service_status"),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployBaseOsEvidenceEntry:
    """One exact scope's strict semantic result projection."""

    attempt_index: int
    step_sequence: int
    target_count: int
    target_set_digest: str
    variables_digest: str
    command_digest: str
    source_digest: str
    result_schema_version: str
    result_digest: str
    evidence_digest: str
    status: BaseOsStatus
    hosts: tuple[DeployBaseOsHostEvidence, ...]
    schema_version: str = ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_ENTRY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_ENTRY_SCHEMA_VERSION
            or self.attempt_index < 1
            or self.step_sequence < 1
            or self.target_count != len(self.hosts)
            or self.target_count < 1
            or tuple(host.logical_id for host in self.hosts)
            != tuple(sorted(host.logical_id for host in self.hosts))
            or not isinstance(self.status, BaseOsStatus)
            or self.target_set_digest
            != _digest_object([host.logical_id for host in self.hosts])
            or self.result_schema_version != BASE_OS_EVIDENCE_SCHEMA_VERSION
        ):
            raise StatePersistenceError("deploy base-os evidence entry is invalid")
        for digest_value in (
            self.target_set_digest,
            self.variables_digest,
            self.command_digest,
            self.source_digest,
            self.result_digest,
            self.evidence_digest,
        ):
            validate_digest(digest_value, "deploy base-os evidence digest")
        if self.evidence_digest != _entry_evidence_digest(self):
            raise StatePersistenceError("deploy base-os evidence digest conflicts")

    def to_object(self) -> dict[str, object]:
        return {
            "attempt_index": self.attempt_index,
            "command_digest": self.command_digest,
            "evidence_digest": self.evidence_digest,
            "hosts": [host.to_object() for host in self.hosts],
            "result_digest": self.result_digest,
            "result_schema_version": self.result_schema_version,
            "schema_version": self.schema_version,
            "source_digest": self.source_digest,
            "status": self.status.value,
            "step_sequence": self.step_sequence,
            "target_count": self.target_count,
            "target_set_digest": self.target_set_digest,
            "variables_digest": self.variables_digest,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployBaseOsEvidenceEntry:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy base-os evidence entry",
        )
        hosts = value["hosts"]
        if not isinstance(hosts, list):
            raise StatePersistenceError("deploy base-os evidence hosts are invalid")
        return cls(
            attempt_index=_integer(value["attempt_index"], "attempt index"),
            step_sequence=_integer(value["step_sequence"], "step sequence"),
            target_count=_integer(value["target_count"], "target count"),
            target_set_digest=require_string(value, "target_set_digest"),
            variables_digest=require_string(value, "variables_digest"),
            command_digest=require_string(value, "command_digest"),
            source_digest=require_string(value, "source_digest"),
            result_schema_version=require_string(value, "result_schema_version"),
            result_digest=require_string(value, "result_digest"),
            evidence_digest=require_string(value, "evidence_digest"),
            status=cast(
                BaseOsStatus,
                _enum(
                    BaseOsStatus,
                    require_string(value, "status"),
                    "base-os evidence status",
                ),
            ),
            hosts=tuple(
                DeployBaseOsHostEvidence.from_object(
                    _mapping(item, "base-os host evidence")
                )
                for item in hosts
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployBaseOsEvidence:
    """Immutable-prefix semantic evidence for authorized base-OS scopes."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployBaseOsExecutionBinding
    entries: tuple[DeployBaseOsEvidenceEntry, ...]
    schema_version: str = ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_SCHEMA_VERSION
            or not isinstance(self.binding, DeployBaseOsExecutionBinding)
        ):
            raise StatePersistenceError("deploy base-os evidence is invalid")
        _positive_integer(self.generation, "deploy base-os evidence generation")
        if (
            parse_timestamp(self.updated_at) < parse_timestamp(self.created_at)
            or self.generation != len(self.entries)
            or not 1 <= len(self.entries) <= self.binding.scope_count
            or tuple(entry.attempt_index for entry in self.entries)
            != tuple(range(1, len(self.entries) + 1))
        ):
            raise StatePersistenceError("deploy base-os evidence prefix is invalid")

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
    def from_object(cls, value: Mapping[str, object]) -> DeployBaseOsEvidence:
        require_exact_keys(
            value,
            {
                "binding",
                "created_at",
                "entries",
                "generation",
                "schema_version",
                "updated_at",
            },
            "deploy base-os evidence",
        )
        binding = value["binding"]
        entries = value["entries"]
        if not isinstance(binding, Mapping) or not isinstance(entries, list):
            raise StatePersistenceError("deploy base-os evidence content is invalid")
        return cls(
            generation=_integer(value["generation"], "evidence generation"),
            created_at=require_string(value, "created_at"),
            updated_at=require_string(value, "updated_at"),
            binding=DeployBaseOsExecutionBinding.from_object(binding),
            entries=tuple(
                DeployBaseOsEvidenceEntry.from_object(
                    _mapping(item, "base-os evidence entry")
                )
                for item in entries
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredDeployBaseOsExecution:
    record: DeployBaseOsExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployBaseOsEvidence:
    record: DeployBaseOsEvidence
    artifact_digest: str


class DeployBaseOsExecutionStore:
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
        self._path = deploy_base_os_execution_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path,
            replace=replace_file,
            token_factory=token_factory,
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployBaseOsExecution:
        value, artifact_digest = self._file.read()
        record = DeployBaseOsExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError("deploy base-os execution identity conflicts")
        return StoredDeployBaseOsExecution(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployBaseOsExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployBaseOsExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployBaseOsExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError("deploy base-os execution operation conflicts")
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial deploy base-os execution generation conflicts"
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
                    "deploy base-os execution changed concurrently"
                )
            _validate_execution_transition(current.record, record)
        artifact_digest = self._file.write(
            record.to_object(), expected_digest=expected_digest
        )
        return StoredDeployBaseOsExecution(record, artifact_digest)


class DeployBaseOsEvidenceStore:
    """Immutable-prefix owner-only semantic evidence."""

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
        self._path = deploy_base_os_evidence_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path,
            replace=replace_file,
            token_factory=token_factory,
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployBaseOsEvidence:
        value, artifact_digest = self._file.read()
        record = DeployBaseOsEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError("deploy base-os evidence identity conflicts")
        return StoredDeployBaseOsEvidence(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployBaseOsEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def append_locked(
        self,
        record: DeployBaseOsEvidence,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployBaseOsEvidence:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError("deploy base-os evidence operation conflicts")
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial deploy base-os evidence generation conflicts"
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
                    "deploy base-os evidence changed concurrently"
                )
            _validate_evidence_transition(current.record, record)
        artifact_digest = self._file.write(
            record.to_object(), expected_digest=expected_digest
        )
        return StoredDeployBaseOsEvidence(record, artifact_digest)


@dataclass(frozen=True, slots=True)
class DeployBaseOsExecutionReport:
    """Strict redacted successful execution report."""

    operation_id: uuid.UUID
    execution_state: DeployBaseOsExecutionState
    execution_artifact_digest: str
    evidence_artifact_digest: str
    binding_digest: str
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_consumed: bool
    invocation_count: int
    scope_count: int
    stable_id_count: int
    stable_id_set_digest: str
    changed_count: int
    reboot_required_count: int
    reboot_required: bool
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    reboot_performed: bool
    journal_status: JournalStatus
    journal_phase: OperationPhase
    execution_schema_version: str = ANSIBLE_DEPLOY_BASE_OS_EXECUTION_SCHEMA_VERSION
    evidence_schema_version: str = ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_SCHEMA_VERSION
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
    )
    schema_version: str = ANSIBLE_DEPLOY_BASE_OS_EXECUTION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_BASE_OS_EXECUTION_REPORT_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_BASE_OS_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
            or self.execution_state is not DeployBaseOsExecutionState.SUCCEEDED
            or not self.authorization_consumed
            or self.manual_recovery_required
            or self.automatic_retry_allowed
            or self.reboot_performed
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError("deploy base-os execution report is invalid")
        for value, label in (
            (self.invocation_count, "invocation count"),
            (self.scope_count, "scope count"),
            (self.stable_id_count, "stable-ID count"),
            (self.changed_count, "changed count"),
            (self.reboot_required_count, "reboot count"),
        ):
            _nonnegative_integer(value, f"deploy base-os report {label}")
        if (
            self.invocation_count != self.scope_count
            or self.scope_count < 1
            or self.stable_id_count < 1
            or self.changed_count > self.stable_id_count
            or self.reboot_required_count > self.stable_id_count
            or self.reboot_required != (self.reboot_required_count > 0)
        ):
            raise StatePersistenceError("deploy base-os report counts conflict")
        for digest_value in (
            self.execution_artifact_digest,
            self.evidence_artifact_digest,
            self.binding_digest,
            self.authorization_artifact_digest,
            self.authorization_digest,
            self.stable_id_set_digest,
        ):
            validate_digest(digest_value, "deploy base-os execution report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "authorization": {
                "artifact_digest": self.authorization_artifact_digest,
                "consumed": self.authorization_consumed,
                "digest": self.authorization_digest,
                "schema_version": self.authorization_schema_version,
            },
            "execution": {
                "artifact_digest": self.execution_artifact_digest,
                "automatic_retry_allowed": self.automatic_retry_allowed,
                "binding_digest": self.binding_digest,
                "invocation_count": self.invocation_count,
                "manual_recovery_required": self.manual_recovery_required,
                "schema_version": self.execution_schema_version,
                "state": self.execution_state.value,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "operation_id": str(self.operation_id),
            "result": {
                "changed_count": self.changed_count,
                "evidence_artifact_digest": self.evidence_artifact_digest,
                "evidence_schema_version": self.evidence_schema_version,
                "reboot_performed": self.reboot_performed,
                "reboot_required": self.reboot_required,
                "reboot_required_count": self.reboot_required_count,
            },
            "schema_version": self.schema_version,
            "scope": {
                "instance_count": self.scope_count,
                "stable_id_count": self.stable_id_count,
                "stable_id_set_digest": self.stable_id_set_digest,
            },
        }


@dataclass(frozen=True, slots=True)
class _ExecutionScope:
    attempt_index: int
    authorization: DeployBaseOsAuthorizationScope
    authorization_scope_digest: str
    variables: Mapping[str, object]
    variables_digest: str
    command_digest: str
    source_digest: str
    guest_architecture: str
    image_architecture: str
    pre_mutation_hosts: tuple[PreMutationHostEvidence, ...]


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    reconciliation: StoredDeployHostEvidenceReconciliation
    authorization: StoredDeployBaseOsAuthorization
    binding: DeployBaseOsExecutionBinding
    scopes: tuple[_ExecutionScope, ...]
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport


def execute_deploy_base_os(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployBaseOsExecutionReport:
    """Execute only exact immutable authorized base-OS scopes."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _validate_toolchain_dependency(toolchain)
    executable_identity_digest = _executable_identity_digest(executables)
    toolchain_evidence_digest = _toolchain_evidence_digest(
        toolchain, executable_identity_digest
    )
    _refuse_ambiguous_artifacts(paths, operation_id)
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
    metadata = context.reconciliation.record
    execution_store = DeployBaseOsExecutionStore(paths, operation_id)
    evidence_store = DeployBaseOsEvidenceStore(paths, operation_id)
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
    _validate_prefix(context, execution, evidence)
    if execution is not None and execution.record.all_scopes_completed:
        if evidence is None:
            raise StateConflictError("completed deploy base-os evidence is unavailable")
        return _build_report(context, execution, evidence)
    if execution is not None and execution.record.state not in {
        DeployBaseOsExecutionState.PREPARED,
        DeployBaseOsExecutionState.SUCCEEDED,
    }:
        raise StateConflictError(
            "deploy base-os execution requires manual recovery and cannot retry"
        )

    service = AnsibleService(builder, runner)
    discovered = service.version(lock)
    if discovered != toolchain:
        raise StateConflictError("deploy base-os toolchain drifted")

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
    next_index = len(execution.record.attempts) if execution is not None else 0
    if (
        execution is None
        or execution.record.state is DeployBaseOsExecutionState.SUCCEEDED
    ):
        scope = context.scopes[next_index]
        try:
            execution = _persist_prepared(
                context,
                execution_store,
                execution,
                scope,
                lock=lock,
            )
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy base-os prepared intent persistence failed before invocation"
            ) from error
    else:
        scope = context.scopes[next_index - 1]
    assert execution is not None

    while True:
        if execution.record.state is DeployBaseOsExecutionState.PREPARED:
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
                raise StateConflictError("deploy base-os state drifted before start")
            _validate_prefix(before_start, execution, evidence)
            scope = before_start.scopes[len(execution.record.attempts) - 1]
            try:
                execution = _persist_started(
                    execution_store,
                    execution,
                    lock=lock,
                )
            except StatePersistenceError as error:
                raise StatePersistenceError(
                    "deploy base-os authorization consumption failed before invocation"
                ) from error

            try:
                result, observed_command_digest = service.execute_operation_step(
                    lock,
                    before_start.metadata,
                    before_start.inventory,
                    _PLAYBOOK,
                    step_sequence=scope.authorization.sequence,
                    limit=scope.authorization.target_ids,
                    variables=dict(scope.variables),
                    readiness=before_start.readiness,
                    tags=(),
                    check=False,
                    diff=False,
                    verbosity=0,
                )
                if observed_command_digest != scope.command_digest:
                    raise AnsibleResultError(
                        "deploy base-os command result identity conflicts"
                    )
            except KeyboardInterrupt:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    DeployBaseOsExecutionState.INTERRUPTED,
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy base-os execution was interrupted; manual recovery required"
                ) from None
            except AnsibleError as error:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    _failure_state(error),
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy base-os execution is uncertain; manual recovery required"
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
            except (StateConflictError, StatePersistenceError) as error:
                raise StateConflictError(
                    "deploy base-os state changed after invocation; "
                    "manual recovery required"
                ) from error
            if after.binding != context.binding:
                raise StateConflictError(
                    "deploy base-os state changed after invocation; "
                    "manual recovery required"
                )
            try:
                entry = _semantic_entry(scope, result)
            except (AnsibleError, StatePersistenceError) as error:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    DeployBaseOsExecutionState.MALFORMED_RESULT,
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy base-os result is malformed; manual recovery required"
                ) from error
            try:
                evidence = _persist_evidence(
                    context,
                    evidence_store,
                    evidence,
                    entry,
                    lock=lock,
                )
            except StatePersistenceError as error:
                raise StatePersistenceError(
                    "deploy base-os evidence persistence failed; "
                    "manual recovery required"
                ) from error
            terminal_state = _terminal_state(entry, result.exit_code)
            try:
                execution = _persist_terminal(
                    context,
                    execution_store,
                    execution,
                    state=terminal_state,
                    exit_code=result.exit_code,
                    result_digest=entry.result_digest,
                    evidence_digest=entry.evidence_digest,
                    lock=lock,
                )
            except StatePersistenceError as error:
                raise StatePersistenceError(
                    "deploy base-os terminal persistence failed; "
                    "manual recovery required"
                ) from error
            if terminal_state is not DeployBaseOsExecutionState.SUCCEEDED:
                raise AnsibleError(
                    "deploy base-os execution failed; manual recovery required"
                )

        if execution.record.all_scopes_completed:
            break
        next_scope = context.scopes[len(execution.record.attempts)]
        try:
            execution = _persist_prepared(
                context,
                execution_store,
                execution,
                next_scope,
                lock=lock,
            )
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy base-os next prepared intent failed before invocation"
            ) from error

    if evidence is None:
        raise StatePersistenceError("deploy base-os completion evidence is missing")
    _validate_prefix(context, execution, evidence)
    return _build_report(context, execution, evidence)


def deploy_base_os_execution_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = (
        paths.operations / f"{operation_id}{DEPLOY_BASE_OS_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError("deploy base-os execution path is not canonical")
    return path


def deploy_base_os_evidence_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / f"{operation_id}{DEPLOY_BASE_OS_EVIDENCE_FILENAME_SUFFIX}"
    if path.parent != paths.operations:
        raise StatePersistenceError("deploy base-os evidence path is not canonical")
    return path


def deploy_base_os_execution_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(name, DEPLOY_BASE_OS_EXECUTION_FILENAME_SUFFIX)


def deploy_base_os_evidence_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(name, DEPLOY_BASE_OS_EVIDENCE_FILENAME_SUFFIX)


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
    host_context = _load_host_reconciliation_context(paths, operation_id, lock=lock)
    planning = host_context.loaded.planning
    metadata = planning.base.deploy.metadata.record
    journal = planning.base.deploy.journal
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
            "deploy base-os readiness, journal, or toolchain conflicts"
        )
    readiness = _reconstructed_readiness(planning.base)
    if readiness_binding_digest(readiness) != readiness_record.readiness_digest:
        raise StateConflictError("deploy base-os readiness is stale")
    readiness.require_ready(OperationClassification.MUTATING)

    reconciliation_store = DeployHostEvidenceReconciliationStore(paths, operation_id)
    authorization_store = DeployBaseOsAuthorizationStore(paths, operation_id)
    for path, message in (
        (reconciliation_store.path, "host-evidence reconciliation"),
        (authorization_store.path, "immutable authorization"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(f"deploy base-os execution requires {message}")
    reconciliation = reconciliation_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_reconciliation = _build_reconciliation_record(
        host_context,
        steps=_build_reconciled_steps(host_context),
        created_at=reconciliation.record.created_at,
    )
    if reconciliation.record != expected_reconciliation:
        raise StateConflictError("deploy base-os reconciliation drifted")
    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    authorization_scopes = _derive_authorization_scopes(reconciliation)
    expected_authorization = _build_authorization(
        reconciliation,
        scopes=authorization_scopes,
        proof=authorization.record.proof,
        created_at=authorization.record.created_at,
    )
    if authorization.record != expected_authorization or authorization.record.consumed:
        raise StateConflictError("deploy base-os authorization is stale or consumed")

    scopes = _derive_execution_scopes(
        host_context,
        authorization,
        builder=builder,
    )
    stable_ids = tuple(
        sorted(
            {target for scope in scopes for target in scope.authorization.target_ids}
        )
    )
    scope_values = [
        {
            "attempt_index": scope.attempt_index,
            "authorization_command_digest": (scope.authorization.command_digest),
            "authorization_scope_digest": scope.authorization_scope_digest,
            "authorization_variables_digest": (scope.authorization.variables_digest),
            "command_digest": scope.command_digest,
            "source_digest": scope.source_digest,
            "step_sequence": scope.authorization.sequence,
            "target_digest": scope.authorization.target_digest,
            "variables_digest": scope.variables_digest,
        }
        for scope in scopes
    ]
    deploy = planning.base.deploy
    trust = planning.base.trust
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
        "authorization_artifact_digest": authorization.artifact_digest,
        "authorization_digest": authorization.record.authorization_digest,
        "authorization_scope_digest": (authorization.record.authorization_scope_digest),
        "authorization_proof_digest": authorization.record.proof.proof_digest,
        "host_reconciliation_artifact_digest": reconciliation.artifact_digest,
        "host_reconciliation_record_digest": reconciliation.record.record_digest,
        "host_reconciled_plan_digest": reconciliation.record.effective_plan_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": readiness_record.record_digest,
        "catalog_digest": host_context.loaded.catalog_digest,
        "source_version": host_context.loaded.source.version,
        "source_digest": host_context.loaded.source.digest,
        "toolchain_version": str(toolchain.core),
        "executable_identity_digest": executable_identity_digest,
        "toolchain_evidence_digest": toolchain_evidence_digest,
        "observation_generation": deploy.observation.record.generation,
        "observation_artifact_digest": deploy.observation.digest,
        "observation_manifest_digest": deploy.observation.record.manifest_digest,
        "inventory_generation": deploy.inventory.record.generation,
        "inventory_artifact_digest": deploy.inventory.digest,
        "inventory_digest": deploy.inventory.record.inventory_digest,
        "trust_generation": trust.record.generation,
        "trust_artifact_digest": trust.digest,
        "trust_entries_digest": trust.record.entries_digest,
        "scope_count": len(scopes),
        "stable_id_count": len(stable_ids),
        "stable_id_set_digest": _digest_object(list(stable_ids)),
        "execution_scope_digest": _digest_object(scope_values),
        "binding_digest": "",
    }
    values["binding_digest"] = _binding_digest_from_values(values)
    binding = DeployBaseOsExecutionBinding(**values)  # type: ignore[arg-type]
    return _ExecutionContext(
        reconciliation,
        authorization,
        binding,
        scopes,
        metadata,
        deploy.inventory,
        readiness,
    )


def _derive_execution_scopes(
    host_context: _HostReconciliationContext,
    authorization: StoredDeployBaseOsAuthorization,
    *,
    builder: AnsibleCommandBuilder,
) -> tuple[_ExecutionScope, ...]:
    context = host_context
    loaded = context.loaded
    planning = loaded.planning
    inventory_hosts = {
        host.logical_id: host
        for host in planning.base.deploy.inventory.record.inventory.hosts
    }
    desired_filters = dict(
        planning.base.deploy.metadata.record.desired_spec.image_filters
    )
    evidence_hosts: dict[str, PreMutationHostEvidence] = {}
    for entry in context.evidence.record.entries:
        assert isinstance(entry, DeployPreMutationEvidenceEntry)
        for persisted_host in entry.hosts:
            if persisted_host.logical_id in evidence_hosts:
                raise StateConflictError("deploy base-os host evidence is duplicated")
            evidence_hosts[persisted_host.logical_id] = persisted_host
    source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
    scopes: list[_ExecutionScope] = []
    for attempt_index, authorized in enumerate(authorization.record.scopes, start=1):
        if (
            authorized.mapping_sequence != _MAPPING_SEQUENCE
            or authorized.playbook != _PLAYBOOK
            or authorized.classification is not OperationClassification.MUTATING
            or authorized.source_digest != source_digest
        ):
            raise StateConflictError("deploy base-os authorized scope drifted")
        hosts: list[PreMutationHostEvidence] = []
        image_architectures: set[str] = set()
        guest_architectures: set[str] = set()
        selected_filter = None
        for target_id in authorized.target_ids:
            inventory_host = inventory_hosts.get(target_id)
            selected_host = evidence_hosts.get(target_id)
            if inventory_host is None or selected_host is None:
                raise StateConflictError(
                    "deploy base-os target evidence is unavailable"
                )
            if (
                inventory_host.role is not selected_host.role
                or (
                    authorized.target_role != "all"
                    and inventory_host.role.value != authorized.target_role
                )
                or selected_host.evidence_status is not EvidenceStatus.COMPLETE
                or selected_host.os_family != "Ubuntu"
                or selected_host.os_version is None
                or _SUPPORTED_OS_VERSION.fullmatch(selected_host.os_version) is None
                or selected_host.architecture not in _SAFE_GUEST_ARCHITECTURES
                or selected_host.reboot_required != "not-required"
                or selected_host.blockers
                or any(
                    service.status not in _SAFE_SERVICE_STATES
                    for service in selected_host.services
                )
            ):
                raise StateConflictError("deploy base-os target is not evidence-ready")
            image_filter = desired_filters.get(inventory_host.role)
            if (
                image_filter is None
                or image_filter.operating_system != "Ubuntu"
                or image_filter.operating_system_version != "24.04"
                or image_filter.version_match is not ImageVersionMatch.EXACT
            ):
                raise StateConflictError(
                    "deploy base-os desired image evidence is unsupported"
                )
            if selected_filter is not None and image_filter != selected_filter:
                raise StateConflictError(
                    "deploy base-os authorized scope mixes image filters"
                )
            selected_filter = image_filter
            assert selected_host.architecture is not None
            guest_architectures.add(selected_host.architecture)
            image_architectures.add(
                _SAFE_GUEST_ARCHITECTURES[selected_host.architecture]
            )
            hosts.append(selected_host)
        if (
            selected_filter is None
            or len(image_architectures) != 1
            or len(guest_architectures) != 1
        ):
            raise StateConflictError(
                "deploy base-os authorized scope mixes architectures"
            )
        image_architecture = next(iter(image_architectures))
        guest_architecture = next(iter(guest_architectures))
        variables = base_os_variables(selected_filter, image_architecture)
        _, validated, variables_digest, command_digest = (
            builder.validate_operation_step(
                _PLAYBOOK,
                step_sequence=authorized.sequence,
                limit=authorized.target_ids,
                variables=variables,
                tags=(),
                check=False,
                diff=False,
                verbosity=0,
            )
        )
        scopes.append(
            _ExecutionScope(
                attempt_index,
                authorized,
                _digest_object(authorized.to_object()),
                validated,
                variables_digest,
                command_digest,
                source_digest,
                guest_architecture,
                image_architecture,
                tuple(hosts),
            )
        )
    if (
        not scopes
        or len(scopes) != authorization.record.playbook_instance_count
        or tuple(scope.authorization.sequence for scope in scopes)
        != tuple(sorted(scope.authorization.sequence for scope in scopes))
    ):
        raise StateConflictError("deploy base-os execution scope is unavailable")
    return tuple(scopes)


def _validate_prefix(
    context: _ExecutionContext,
    execution: StoredDeployBaseOsExecution | None,
    evidence: StoredDeployBaseOsEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError("deploy base-os evidence exists without intent")
        return
    if execution.record.binding != context.binding:
        raise StateConflictError("deploy base-os execution provenance is stale")
    if evidence is not None and evidence.record.binding != context.binding:
        raise StateConflictError("deploy base-os evidence provenance is stale")
    for index, attempt in enumerate(execution.record.attempts):
        scope = context.scopes[index]
        authorized = scope.authorization
        if (
            attempt.attempt_index != index + 1
            or attempt.step_sequence != authorized.sequence
            or attempt.target_ids != authorized.target_ids
            or attempt.target_digest != authorized.target_digest
            or attempt.authorization_scope_digest != scope.authorization_scope_digest
            or attempt.authorization_variables_digest != authorized.variables_digest
            or attempt.authorization_command_digest != authorized.command_digest
            or attempt.variables_digest != scope.variables_digest
            or attempt.command_digest != scope.command_digest
            or attempt.source_digest != scope.source_digest
        ):
            raise StateConflictError("deploy base-os execution scope conflicts")
    entries = evidence.record.entries if evidence is not None else ()
    if len(entries) > len(execution.record.attempts):
        raise StateConflictError("deploy base-os evidence prefix conflicts")
    for index, entry in enumerate(entries):
        attempt = execution.record.attempts[index]
        scope = context.scopes[index]
        if (
            attempt.state is DeployBaseOsExecutionState.PREPARED
            or entry.attempt_index != index + 1
            or entry.step_sequence != scope.authorization.sequence
            or entry.target_count != len(scope.authorization.target_ids)
            or entry.target_set_digest != scope.authorization.target_digest
            or entry.variables_digest != scope.variables_digest
            or entry.command_digest != scope.command_digest
            or entry.source_digest != scope.source_digest
            or tuple(host.logical_id for host in entry.hosts)
            != scope.authorization.target_ids
            or (
                attempt.result_digest is not None
                and attempt.result_digest != entry.result_digest
            )
            or (
                attempt.evidence_digest is not None
                and attempt.evidence_digest != entry.evidence_digest
            )
        ):
            raise StateConflictError("deploy base-os semantic evidence conflicts")
    required_entries = sum(
        attempt.state
        in {
            DeployBaseOsExecutionState.SUCCEEDED,
            DeployBaseOsExecutionState.FAILED,
            DeployBaseOsExecutionState.UNREACHABLE,
        }
        for attempt in execution.record.attempts
    )
    allowed_started_extra = (
        1
        if execution.record.state is DeployBaseOsExecutionState.STARTED
        and len(entries) == required_entries + 1
        else 0
    )
    if len(entries) != required_entries + allowed_started_extra:
        raise StateConflictError("deploy base-os execution/evidence prefixes conflict")


def _persist_prepared(
    context: _ExecutionContext,
    store: DeployBaseOsExecutionStore,
    current: StoredDeployBaseOsExecution | None,
    scope: _ExecutionScope,
    *,
    lock: ClusterLock,
) -> StoredDeployBaseOsExecution:
    now = _timestamp()
    attempt = DeployBaseOsExecutionAttempt(
        attempt_index=scope.attempt_index,
        step_sequence=scope.authorization.sequence,
        target_ids=scope.authorization.target_ids,
        target_digest=scope.authorization.target_digest,
        authorization_scope_digest=scope.authorization_scope_digest,
        authorization_variables_digest=scope.authorization.variables_digest,
        authorization_command_digest=scope.authorization.command_digest,
        variables_digest=scope.variables_digest,
        command_digest=scope.command_digest,
        source_digest=scope.source_digest,
        result_schema_version=BASE_OS_EVIDENCE_SCHEMA_VERSION,
        state=DeployBaseOsExecutionState.PREPARED,
        prepared_at=now,
        started_at=None,
        completed_at=None,
        authorization_consumed=False,
        invocation_may_have_occurred=False,
        exit_code=None,
        result_digest=None,
        evidence_digest=None,
        manual_recovery_required=False,
    )
    if current is None:
        record = DeployBaseOsExecution(
            generation=1,
            created_at=now,
            updated_at=now,
            binding=context.binding,
            state=DeployBaseOsExecutionState.PREPARED,
            authorization_consumed=False,
            invocation_count=0,
            all_scopes_completed=False,
            attempts=(attempt,),
        )
        return store.write_locked(
            record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    if current.record.state is not DeployBaseOsExecutionState.SUCCEEDED:
        raise StateConflictError("deploy base-os cannot prepare after uncertain state")
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=DeployBaseOsExecutionState.PREPARED,
        all_scopes_completed=False,
        attempts=(*current.record.attempts, attempt),
    )
    return store.write_locked(
        record,
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _persist_started(
    store: DeployBaseOsExecutionStore,
    current: StoredDeployBaseOsExecution,
    *,
    lock: ClusterLock,
) -> StoredDeployBaseOsExecution:
    if current.record.state is not DeployBaseOsExecutionState.PREPARED:
        raise StateConflictError("deploy base-os start requires prepared intent")
    now = _timestamp()
    attempt = replace(
        current.record.attempts[-1],
        state=DeployBaseOsExecutionState.STARTED,
        started_at=now,
        authorization_consumed=True,
        invocation_may_have_occurred=True,
        manual_recovery_required=True,
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=DeployBaseOsExecutionState.STARTED,
        authorization_consumed=True,
        invocation_count=current.record.invocation_count + 1,
        attempts=(*current.record.attempts[:-1], attempt),
    )
    return store.write_locked(
        record,
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _persist_uncertain_or_raise(
    store: DeployBaseOsExecutionStore,
    current: StoredDeployBaseOsExecution,
    state: DeployBaseOsExecutionState,
    *,
    lock: ClusterLock,
) -> None:
    try:
        _persist_uncertain(store, current, state, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy base-os uncertain outcome persistence failed; "
            "manual recovery required"
        ) from error


def _persist_uncertain(
    store: DeployBaseOsExecutionStore,
    current: StoredDeployBaseOsExecution,
    state: DeployBaseOsExecutionState,
    *,
    lock: ClusterLock,
) -> StoredDeployBaseOsExecution:
    if state not in {
        DeployBaseOsExecutionState.FAILED,
        DeployBaseOsExecutionState.TIMED_OUT,
        DeployBaseOsExecutionState.INTERRUPTED,
        DeployBaseOsExecutionState.MALFORMED_RESULT,
    }:
        raise StatePersistenceError("deploy base-os uncertain state is invalid")
    now = _timestamp()
    attempt = replace(
        current.record.attempts[-1],
        state=state,
        completed_at=now,
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=state,
        attempts=(*current.record.attempts[:-1], attempt),
    )
    return store.write_locked(
        record,
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _persist_terminal(
    context: _ExecutionContext,
    store: DeployBaseOsExecutionStore,
    current: StoredDeployBaseOsExecution,
    *,
    state: DeployBaseOsExecutionState,
    exit_code: int,
    result_digest: str,
    evidence_digest: str,
    lock: ClusterLock,
) -> StoredDeployBaseOsExecution:
    now = _timestamp()
    attempt = replace(
        current.record.attempts[-1],
        state=state,
        completed_at=now,
        exit_code=exit_code,
        result_digest=result_digest,
        evidence_digest=evidence_digest,
        manual_recovery_required=state is not DeployBaseOsExecutionState.SUCCEEDED,
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=state,
        all_scopes_completed=(
            state is DeployBaseOsExecutionState.SUCCEEDED
            and len(current.record.attempts) == len(context.scopes)
        ),
        attempts=(*current.record.attempts[:-1], attempt),
    )
    return store.write_locked(
        record,
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _persist_evidence(
    context: _ExecutionContext,
    store: DeployBaseOsEvidenceStore,
    current: StoredDeployBaseOsEvidence | None,
    entry: DeployBaseOsEvidenceEntry,
    *,
    lock: ClusterLock,
) -> StoredDeployBaseOsEvidence:
    now = _timestamp()
    if current is None:
        record = DeployBaseOsEvidence(
            generation=1,
            created_at=now,
            updated_at=now,
            binding=context.binding,
            entries=(entry,),
        )
        return store.append_locked(
            record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        entries=(*current.record.entries, entry),
    )
    return store.append_locked(
        record,
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _semantic_entry(
    scope: _ExecutionScope,
    result: AnsibleExecutionResult,
) -> DeployBaseOsEvidenceEntry:
    base_os = result.base_os
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.MUTATING
        or result.check_mode
        or base_os is None
        or result.inventory_preflight is not None
        or result.connectivity is not None
        or result.evidence is not None
        or tuple(host.logical_id for host in base_os.hosts)
        != scope.authorization.target_ids
    ):
        raise AnsibleResultError("deploy base-os result identity conflicts")
    expected_hosts = {host.logical_id: host for host in scope.pre_mutation_hosts}
    hosts = tuple(
        _project_host(
            host,
            expected_hosts[host.logical_id],
            image_architecture=scope.image_architecture,
            guest_architecture=scope.guest_architecture,
        )
        for host in base_os.hosts
    )
    result_digest = _base_os_result_digest(base_os)
    values: dict[str, object] = {
        "attempt_index": scope.attempt_index,
        "step_sequence": scope.authorization.sequence,
        "target_count": len(hosts),
        "target_set_digest": scope.authorization.target_digest,
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "source_digest": scope.source_digest,
        "result_schema_version": BASE_OS_EVIDENCE_SCHEMA_VERSION,
        "result_digest": result_digest,
        "evidence_digest": "",
        "status": base_os.status,
        "hosts": hosts,
    }
    values["evidence_digest"] = _entry_evidence_digest_from_values(values)
    return DeployBaseOsEvidenceEntry(**values)  # type: ignore[arg-type]


def _project_host(
    result: BaseOsHostEvidence,
    prior: PreMutationHostEvidence,
    *,
    image_architecture: str,
    guest_architecture: str,
) -> DeployBaseOsHostEvidence:
    if (
        prior.logical_id != result.logical_id
        or prior.os_family != "Ubuntu"
        or prior.os_version is None
        or _SUPPORTED_OS_VERSION.fullmatch(prior.os_version) is None
        or prior.architecture != guest_architecture
    ):
        raise AnsibleResultError("deploy base-os host provenance conflicts")
    _validate_result_reason(result)
    succeeded = result.status in _SUCCESS_STATUSES
    return DeployBaseOsHostEvidence(
        logical_id=result.logical_id,
        os_family="Ubuntu",
        os_version="24.04",
        image_architecture=image_architecture,
        guest_architecture=guest_architecture,
        status=result.status,
        applied=succeeded,
        changed=result.changed,
        reboot_required=result.reboot_required,
        prerequisite_policy_status=("satisfied" if succeeded else "unverified"),
        timesync_service_status=("enabled-active" if succeeded else "unverified"),
    )


def _validate_result_reason(host: BaseOsHostEvidence) -> None:
    expected = {
        BaseOsStatus.NO_CHANGE: {"already-current"},
        BaseOsStatus.CHANGED: {"applied"},
        BaseOsStatus.REBOOT_REQUIRED: {"reboot-required"},
        BaseOsStatus.UNSUPPORTED: {
            "image-evidence-unsupported",
            "guest-facts-mismatch",
        },
        BaseOsStatus.FAILURE: {"execution-failed"},
    }
    if host.reason not in expected[host.status]:
        raise AnsibleResultError("deploy base-os result reason conflicts")


def _base_os_result_digest(evidence: BaseOsEvidence) -> str:
    return _digest_object(
        {
            "hosts": [
                {
                    "changed": host.changed,
                    "logical_id": host.logical_id,
                    "reason": host.reason,
                    "reboot_required": host.reboot_required,
                    "status": host.status.value,
                }
                for host in evidence.hosts
            ],
            "schema_version": BASE_OS_EVIDENCE_SCHEMA_VERSION,
            "status": evidence.status.value,
        }
    )


def _terminal_state(
    entry: DeployBaseOsEvidenceEntry,
    exit_code: int,
) -> DeployBaseOsExecutionState:
    if exit_code == 0 and entry.status in _SUCCESS_STATUSES:
        return DeployBaseOsExecutionState.SUCCEEDED
    if exit_code == 4:
        return DeployBaseOsExecutionState.UNREACHABLE
    return DeployBaseOsExecutionState.FAILED


def _build_report(
    context: _ExecutionContext,
    execution: StoredDeployBaseOsExecution,
    evidence: StoredDeployBaseOsEvidence,
) -> DeployBaseOsExecutionReport:
    if (
        not execution.record.all_scopes_completed
        or execution.record.state is not DeployBaseOsExecutionState.SUCCEEDED
        or len(evidence.record.entries) != len(context.scopes)
        or any(
            entry.status not in _SUCCESS_STATUSES for entry in evidence.record.entries
        )
    ):
        raise StateConflictError("deploy base-os execution is not complete")
    hosts = tuple(host for entry in evidence.record.entries for host in entry.hosts)
    return DeployBaseOsExecutionReport(
        operation_id=context.binding.operation_id,
        execution_state=execution.record.state,
        execution_artifact_digest=execution.artifact_digest,
        evidence_artifact_digest=evidence.artifact_digest,
        binding_digest=context.binding.binding_digest,
        authorization_artifact_digest=context.authorization.artifact_digest,
        authorization_digest=context.authorization.record.authorization_digest,
        authorization_consumed=execution.record.authorization_consumed,
        invocation_count=execution.record.invocation_count,
        scope_count=context.binding.scope_count,
        stable_id_count=context.binding.stable_id_count,
        stable_id_set_digest=context.binding.stable_id_set_digest,
        changed_count=sum(host.changed for host in hosts),
        reboot_required_count=sum(host.reboot_required for host in hosts),
        reboot_required=any(host.reboot_required for host in hosts),
        manual_recovery_required=False,
        automatic_retry_allowed=False,
        reboot_performed=False,
        journal_status=context.binding.journal_status,
        journal_phase=context.binding.journal_phase,
    )


def _validate_execution_transition(
    current: DeployBaseOsExecution,
    replacement: DeployBaseOsExecution,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or current.all_scopes_completed
        or current.state
        not in {
            DeployBaseOsExecutionState.PREPARED,
            DeployBaseOsExecutionState.STARTED,
            DeployBaseOsExecutionState.SUCCEEDED,
        }
    ):
        raise StatePersistenceError("deploy base-os execution transition is invalid")
    if current.state is DeployBaseOsExecutionState.PREPARED:
        if (
            len(replacement.attempts) != len(current.attempts)
            or replacement.attempts[:-1] != current.attempts[:-1]
            or replacement.attempts[-1].state is not DeployBaseOsExecutionState.STARTED
        ):
            raise StatePersistenceError("deploy base-os start transition is invalid")
    elif current.state is DeployBaseOsExecutionState.STARTED:
        if (
            len(replacement.attempts) != len(current.attempts)
            or replacement.attempts[:-1] != current.attempts[:-1]
            or replacement.attempts[-1].state
            in {
                DeployBaseOsExecutionState.PREPARED,
                DeployBaseOsExecutionState.STARTED,
            }
        ):
            raise StatePersistenceError("deploy base-os terminal transition is invalid")
    elif (
        len(current.attempts) >= current.binding.scope_count
        or replacement.attempts[:-1] != current.attempts
        or replacement.attempts[-1].state is not DeployBaseOsExecutionState.PREPARED
    ):
        raise StatePersistenceError("deploy base-os next-scope transition is invalid")


def _validate_evidence_transition(
    current: DeployBaseOsEvidence,
    replacement: DeployBaseOsEvidence,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or replacement.entries[:-1] != current.entries
        or len(replacement.entries) != len(current.entries) + 1
    ):
        raise StatePersistenceError("deploy base-os evidence transition is invalid")


def _failure_state(error: AnsibleError) -> DeployBaseOsExecutionState:
    if isinstance(error, AnsibleResultError):
        return DeployBaseOsExecutionState.MALFORMED_RESULT
    cause = error.__cause__
    if isinstance(cause, ProcessTimeoutError):
        return DeployBaseOsExecutionState.TIMED_OUT
    if isinstance(cause, ProcessOutputError):
        return DeployBaseOsExecutionState.MALFORMED_RESULT
    return DeployBaseOsExecutionState.FAILED


def _binding_digests(binding: DeployBaseOsExecutionBinding) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(binding, name))
        for name in binding.__dataclass_fields__
        if name.endswith("_digest")
    )


def _binding_digest(binding: DeployBaseOsExecutionBinding) -> str:
    value = binding.to_object()
    value["binding_digest"] = ""
    return _digest_object(value)


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployBaseOsExecutionBinding.__dataclass_fields__.items():
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


def _entry_evidence_digest(entry: DeployBaseOsEvidenceEntry) -> str:
    value = entry.to_object()
    value["evidence_digest"] = ""
    return _digest_object(value)


def _entry_evidence_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployBaseOsEvidenceEntry.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            item.value
            if isinstance(item, BaseOsStatus)
            else [host.to_object() for host in item]
            if name == "hosts" and isinstance(item, tuple)
            else item
        )
    value["evidence_digest"] = ""
    return _digest_object(value)


def _require_canonical_paths(paths: StatePaths) -> None:
    if StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths:
        raise StatePersistenceError("deploy base-os execution paths are not canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError("deploy base-os execution requires an acquired lock")
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy base-os execution artifacts"
        ) from error
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_BASE_OS_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_BASE_OS_EVIDENCE_FILENAME_SUFFIX,
    )
    allowed_executions = {
        f"{operation_id}.ansible-deploy-prerequisite-execution.json",
        (f"{operation_id}.ansible-deploy-pre-mutation-host-evidence-execution.json"),
        f"{operation_id}{DEPLOY_BASE_OS_EXECUTION_FILENAME_SUFFIX}",
    }
    for entry in entries:
        if (
            str(operation_id) in entry.name
            and "execution" in entry.name
            and entry.name not in allowed_executions
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy base-os execution refuses conflicting execution history"
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
                    "deploy base-os execution artifacts are ambiguous"
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
            "deploy base-os toolchain version is invalid"
        ) from error


def _enum(enum_type: type[StrEnum], value: str, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except ValueError as error:
        raise StatePersistenceError(f"{label} is invalid") from error


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    if value is None:
        return None
    return _integer(value, label)


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


def _positive_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


def _nonnegative_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StatePersistenceError(f"{label} must be nonnegative")


__all__ = [
    "ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_ENTRY_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_BASE_OS_EXECUTION_BINDING_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_BASE_OS_EXECUTION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_BASE_OS_EXECUTION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_BASE_OS_HOST_EVIDENCE_SCHEMA_VERSION",
    "DEPLOY_BASE_OS_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_BASE_OS_EXECUTION_FILENAME_SUFFIX",
    "DeployBaseOsEvidence",
    "DeployBaseOsEvidenceEntry",
    "DeployBaseOsEvidenceStore",
    "DeployBaseOsExecution",
    "DeployBaseOsExecutionAttempt",
    "DeployBaseOsExecutionBinding",
    "DeployBaseOsExecutionReport",
    "DeployBaseOsExecutionState",
    "DeployBaseOsExecutionStore",
    "DeployBaseOsHostEvidence",
    "StoredDeployBaseOsEvidence",
    "StoredDeployBaseOsExecution",
    "deploy_base_os_evidence_id_from_filename",
    "deploy_base_os_evidence_path",
    "deploy_base_os_execution_id_from_filename",
    "deploy_base_os_execution_path",
    "execute_deploy_base_os",
]
