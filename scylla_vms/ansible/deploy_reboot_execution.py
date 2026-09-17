"""Immutable serial deploy reboot execution with strict reconnect checkpoints.

This internal owner derives every target, variable, and command from canonical
operation state.  It records durable started intent before each reboot and
never retries or advances after an uncertain started attempt.
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
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciliationStore,
    StoredDeployBaseOsReconciliation,
    _BaseOsReconciliationContext,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    _build_record as _build_base_os_reconciliation,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    _build_steps as _build_base_os_reconciled_steps,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    _load_context as _load_base_os_context,
)
from scylla_vms.ansible.deploy_plan import (
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_reboot import (
    DEPLOY_REBOOT_RESULT_SCHEMA_VERSION,
    DeployRebootResult,
    DeployRebootResultStatus,
    deploy_reboot_variables,
)
from scylla_vms.ansible.deploy_reboot_authorization import (
    DeployRebootAuthorizationStore,
    DeployRebootPlanStore,
    DeployRebootPlanTarget,
    StoredDeployRebootAuthorization,
    StoredDeployRebootPlan,
    _build_authorization,
    _build_plan,
    _build_targets,
    _derive_candidates,
    deploy_reboot_authorization_path,
    deploy_reboot_plan_path,
)
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
from scylla_vms.ansible.toolchain import AnsibleToolchain
from scylla_vms.ansible.trust import TrustStore
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

ANSIBLE_DEPLOY_REBOOT_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-reboot-execution-binding/v1"
)
ANSIBLE_DEPLOY_REBOOT_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-reboot-execution/v1"
)
ANSIBLE_DEPLOY_REBOOT_EVIDENCE_ENTRY_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-reboot-evidence-entry/v1"
)
ANSIBLE_DEPLOY_REBOOT_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-reboot-evidence/v1"
)
ANSIBLE_DEPLOY_REBOOT_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-reboot-execution-report/v1"
)

DEPLOY_REBOOT_EXECUTION_FILENAME_SUFFIX = ".ansible-deploy-reboot-execution.json"
DEPLOY_REBOOT_EVIDENCE_FILENAME_SUFFIX = ".ansible-deploy-reboot-evidence.json"

_OPERATION = "deploy"
_PLAYBOOK = "deploy-reboot"
_NOT_REQUIRED = "not-required"
_POST_REBOOT_EVIDENCE_READY = "post-reboot-evidence-ready"
_SUPPORTED_ARCHITECTURES = frozenset({"x86_64", "aarch64"})
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class DeployRebootExecutionState(StrEnum):
    """Durable serial execution states."""

    PREPARED = "prepared"
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"


class DeployRebootArtifactState(StrEnum):
    """Persistence outcome for execution/evidence companions."""

    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"
    NOT_REQUIRED = "not-required"


@dataclass(frozen=True, slots=True)
class DeployRebootExecutionBinding:
    """Exact address-free provenance for the whole ordered reboot scope."""

    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    reboot_plan_artifact_digest: str
    reboot_plan_record_digest: str
    reboot_authorization_artifact_digest: str
    reboot_authorization_digest: str
    reboot_authorization_proof_digest: str
    base_os_reconciliation_artifact_digest: str
    base_os_reconciliation_record_digest: str
    base_os_execution_artifact_digest: str
    base_os_evidence_artifact_digest: str
    connectivity_execution_artifact_digest: str
    connectivity_evidence_artifact_digest: str
    connectivity_evidence_digest: str
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
    target_count: int
    target_set_digest: str
    target_order_digest: str
    role_batch_digest: str
    execution_scope_digest: str
    binding_digest: str
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_REBOOT_EXECUTION_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_REBOOT_EXECUTION_BINDING_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
            or self.journal_generation < 1
            or self.inventory_generation < 1
            or self.trust_generation < 1
            or self.target_count < 1
        ):
            raise StatePersistenceError("deploy reboot execution binding is invalid")
        validate_cluster_name(self.cluster_name)
        for value in _binding_digests(self):
            validate_digest(value, "deploy reboot execution binding digest")
        if self.binding_digest != _binding_digest(self):
            raise StatePersistenceError(
                "deploy reboot execution binding digest conflicts"
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
    def from_object(cls, value: Mapping[str, object]) -> DeployRebootExecutionBinding:
        require_exact_keys(value, set(cls.__dataclass_fields__), "reboot binding")
        integer_fields = {
            "journal_generation",
            "inventory_generation",
            "trust_generation",
            "target_count",
        }
        parsed: dict[str, object] = {}
        for name in cls.__dataclass_fields__:
            item = value[name]
            if name in integer_fields:
                parsed[name] = _integer(item, name)
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
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployRebootExecutionAttempt:
    """One durable exact-target attempt."""

    sequence: int
    stable_id: str
    role: HostRole
    target_plan_digest: str
    variables_digest: str
    command_digest: str
    source_digest: str
    request_digest: str
    state: DeployRebootExecutionState
    prepared_at: str
    started_at: str | None
    completed_at: str | None
    authorization_consumed: bool
    invocation_may_have_occurred: bool
    exit_code: int | None
    result_digest: str | None
    evidence_digest: str | None
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    result_schema_version: str = DEPLOY_REBOOT_RESULT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.sequence < 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or not isinstance(self.role, HostRole)
            or not isinstance(self.state, DeployRebootExecutionState)
            or self.result_schema_version != DEPLOY_REBOOT_RESULT_SCHEMA_VERSION
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError("deploy reboot attempt identity is invalid")
        parse_timestamp(self.prepared_at)
        if self.started_at is not None:
            parse_timestamp(self.started_at)
        if self.completed_at is not None:
            parse_timestamp(self.completed_at)
        for value in (
            self.target_plan_digest,
            self.variables_digest,
            self.command_digest,
            self.source_digest,
            self.request_digest,
        ):
            validate_digest(value, "deploy reboot attempt digest")
        for outcome_digest in (self.result_digest, self.evidence_digest):
            if outcome_digest is not None:
                validate_digest(outcome_digest, "deploy reboot attempt outcome digest")
        if self.state is DeployRebootExecutionState.PREPARED:
            valid = (
                self.started_at is None
                and self.completed_at is None
                and not self.invocation_may_have_occurred
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and not self.manual_recovery_required
            )
        elif self.state is DeployRebootExecutionState.STARTED:
            valid = (
                self.started_at is not None
                and self.completed_at is None
                and self.authorization_consumed
                and self.invocation_may_have_occurred
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.manual_recovery_required
            )
        else:
            valid = (
                self.started_at is not None
                and self.completed_at is not None
                and self.authorization_consumed
                and self.invocation_may_have_occurred
                and self.manual_recovery_required
                == (self.state is not DeployRebootExecutionState.SUCCEEDED)
            )
            if self.state in {
                DeployRebootExecutionState.SUCCEEDED,
                DeployRebootExecutionState.FAILED,
                DeployRebootExecutionState.UNREACHABLE,
            }:
                valid = (
                    valid
                    and self.exit_code is not None
                    and self.result_digest is not None
                    and self.evidence_digest is not None
                )
            else:
                valid = (
                    valid
                    and self.exit_code is None
                    and self.result_digest is None
                    and self.evidence_digest is None
                )
        if not valid:
            raise StatePersistenceError("deploy reboot attempt state is invalid")

    def to_object(self) -> dict[str, object]:
        return {
            "authorization_consumed": self.authorization_consumed,
            "automatic_retry_allowed": self.automatic_retry_allowed,
            "command_digest": self.command_digest,
            "completed_at": self.completed_at,
            "evidence_digest": self.evidence_digest,
            "exit_code": self.exit_code,
            "invocation_may_have_occurred": self.invocation_may_have_occurred,
            "manual_recovery_required": self.manual_recovery_required,
            "prepared_at": self.prepared_at,
            "request_digest": self.request_digest,
            "result_digest": self.result_digest,
            "result_schema_version": self.result_schema_version,
            "role": self.role.value,
            "sequence": self.sequence,
            "source_digest": self.source_digest,
            "stable_id": self.stable_id,
            "started_at": self.started_at,
            "state": self.state.value,
            "target_plan_digest": self.target_plan_digest,
            "variables_digest": self.variables_digest,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployRebootExecutionAttempt:
        require_exact_keys(value, set(cls.__dataclass_fields__), "reboot attempt")
        try:
            return cls(
                sequence=_integer(value["sequence"], "sequence"),
                stable_id=require_string(value, "stable_id"),
                role=HostRole(require_string(value, "role")),
                target_plan_digest=require_string(value, "target_plan_digest"),
                variables_digest=require_string(value, "variables_digest"),
                command_digest=require_string(value, "command_digest"),
                source_digest=require_string(value, "source_digest"),
                request_digest=require_string(value, "request_digest"),
                state=DeployRebootExecutionState(require_string(value, "state")),
                prepared_at=require_string(value, "prepared_at"),
                started_at=_optional_string(value["started_at"], "started_at"),
                completed_at=_optional_string(value["completed_at"], "completed_at"),
                authorization_consumed=_boolean(
                    value["authorization_consumed"], "authorization_consumed"
                ),
                invocation_may_have_occurred=_boolean(
                    value["invocation_may_have_occurred"],
                    "invocation_may_have_occurred",
                ),
                exit_code=_optional_integer(value["exit_code"], "exit_code"),
                result_digest=_optional_string(value["result_digest"], "result_digest"),
                evidence_digest=_optional_string(
                    value["evidence_digest"], "evidence_digest"
                ),
                manual_recovery_required=_boolean(
                    value["manual_recovery_required"], "manual_recovery_required"
                ),
                automatic_retry_allowed=_boolean(
                    value["automatic_retry_allowed"], "automatic_retry_allowed"
                ),
                result_schema_version=require_string(value, "result_schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy reboot attempt enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployRebootExecution:
    """Generation-guarded serial execution companion."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployRebootExecutionBinding
    state: DeployRebootExecutionState
    authorization_consumed: bool
    invocation_count: int
    completed_target_count: int
    all_targets_completed: bool
    attempts: tuple[DeployRebootExecutionAttempt, ...]
    schema_version: str = ANSIBLE_DEPLOY_REBOOT_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_REBOOT_EXECUTION_SCHEMA_VERSION
            or self.generation < 1
            or self.invocation_count < 0
            or self.completed_target_count < 0
            or self.invocation_count > len(self.attempts)
            or self.completed_target_count
            != sum(
                attempt.state is DeployRebootExecutionState.SUCCEEDED
                for attempt in self.attempts
            )
            or tuple(attempt.sequence for attempt in self.attempts)
            != tuple(range(1, len(self.attempts) + 1))
            or len(self.attempts) > self.binding.target_count
            or self.authorization_consumed != (self.invocation_count > 0)
            or self.all_targets_completed
            != (
                self.state is DeployRebootExecutionState.SUCCEEDED
                and self.completed_target_count == self.binding.target_count
            )
            or not self.attempts
            or self.state is not self.attempts[-1].state
        ):
            raise StatePersistenceError("deploy reboot execution summary conflicts")
        parse_timestamp(self.created_at)
        parse_timestamp(self.updated_at)
        if any(
            attempt.state is not DeployRebootExecutionState.SUCCEEDED
            for attempt in self.attempts[:-1]
        ):
            raise StatePersistenceError("deploy reboot execution skipped uncertainty")

    def to_object(self) -> dict[str, object]:
        return {
            "all_targets_completed": self.all_targets_completed,
            "attempts": [attempt.to_object() for attempt in self.attempts],
            "authorization_consumed": self.authorization_consumed,
            "binding": self.binding.to_object(),
            "completed_target_count": self.completed_target_count,
            "created_at": self.created_at,
            "generation": self.generation,
            "invocation_count": self.invocation_count,
            "schema_version": self.schema_version,
            "state": self.state.value,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployRebootExecution:
        require_exact_keys(value, set(cls.__dataclass_fields__), "reboot execution")
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                updated_at=require_string(value, "updated_at"),
                binding=DeployRebootExecutionBinding.from_object(
                    _mapping(value["binding"], "reboot binding")
                ),
                state=DeployRebootExecutionState(require_string(value, "state")),
                authorization_consumed=_boolean(
                    value["authorization_consumed"], "authorization_consumed"
                ),
                invocation_count=_integer(
                    value["invocation_count"], "invocation_count"
                ),
                completed_target_count=_integer(
                    value["completed_target_count"], "completed_target_count"
                ),
                all_targets_completed=_boolean(
                    value["all_targets_completed"], "all_targets_completed"
                ),
                attempts=tuple(
                    DeployRebootExecutionAttempt.from_object(
                        _mapping(item, "reboot attempt")
                    )
                    for item in _array(value["attempts"], "reboot attempts")
                ),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy reboot execution enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployRebootEvidenceEntry:
    """One strict post-reboot semantic checkpoint."""

    sequence: int
    stable_id: str
    role: HostRole
    status: DeployRebootResultStatus
    os_family: str
    os_version: str
    architecture: str
    services_safe_before: bool
    reboot_performed: bool
    reconnected: bool
    boot_changed: bool
    identity_verified: bool
    trust_revalidated: bool
    machine_evidence_verified: bool
    services_safe_after: bool
    reboot_required_clear: bool
    elapsed_seconds: int
    target_plan_digest: str
    variables_digest: str
    command_digest: str
    source_digest: str
    request_digest: str
    result_digest: str
    evidence_digest: str
    result_schema_version: str = DEPLOY_REBOOT_RESULT_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_REBOOT_EVIDENCE_ENTRY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_REBOOT_EVIDENCE_ENTRY_SCHEMA_VERSION
            or self.result_schema_version != DEPLOY_REBOOT_RESULT_SCHEMA_VERSION
            or self.sequence < 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.os_family != "Ubuntu"
            or self.os_version != "24.04"
            or self.architecture not in _SUPPORTED_ARCHITECTURES
            or self.elapsed_seconds < 0
            or self.elapsed_seconds > 1800
        ):
            raise StatePersistenceError("deploy reboot evidence entry is invalid")
        for value in (
            self.target_plan_digest,
            self.variables_digest,
            self.command_digest,
            self.source_digest,
            self.request_digest,
            self.result_digest,
            self.evidence_digest,
        ):
            validate_digest(value, "deploy reboot evidence digest")
        if self.evidence_digest != _entry_digest(self):
            raise StatePersistenceError("deploy reboot evidence digest conflicts")
        DeployRebootResult(
            self.stable_id,
            self.role,
            self.status,
            self.os_family,
            self.os_version,
            self.architecture,
            self.services_safe_before,
            self.reboot_performed,
            self.reconnected,
            self.boot_changed,
            self.identity_verified,
            self.trust_revalidated,
            self.machine_evidence_verified,
            self.services_safe_after,
            self.reboot_required_clear,
            self.elapsed_seconds,
            self.request_digest,
        )

    def to_object(self) -> dict[str, object]:
        result = {
            "architecture": self.architecture,
            "boot_changed": self.boot_changed,
            "command_digest": self.command_digest,
            "elapsed_seconds": self.elapsed_seconds,
            "evidence_digest": self.evidence_digest,
            "identity_verified": self.identity_verified,
            "logical_id": self.stable_id,
            "machine_evidence_verified": self.machine_evidence_verified,
            "os_family": self.os_family,
            "os_version": self.os_version,
            "reboot_performed": self.reboot_performed,
            "reboot_required_clear": self.reboot_required_clear,
            "reconnected": self.reconnected,
            "request_digest": self.request_digest,
            "result_digest": self.result_digest,
            "result_schema_version": self.result_schema_version,
            "role": self.role.value,
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "services_safe_after": self.services_safe_after,
            "services_safe_before": self.services_safe_before,
            "source_digest": self.source_digest,
            "status": self.status.value,
            "target_plan_digest": self.target_plan_digest,
            "trust_revalidated": self.trust_revalidated,
            "variables_digest": self.variables_digest,
        }
        return result

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployRebootEvidenceEntry:
        expected_keys = set(cls.__dataclass_fields__)
        expected_keys.remove("stable_id")
        expected_keys.add("logical_id")
        require_exact_keys(value, expected_keys, "reboot evidence entry")
        try:
            return cls(
                sequence=_integer(value["sequence"], "sequence"),
                stable_id=require_string(value, "logical_id"),
                role=HostRole(require_string(value, "role")),
                status=DeployRebootResultStatus(require_string(value, "status")),
                os_family=require_string(value, "os_family"),
                os_version=require_string(value, "os_version"),
                architecture=require_string(value, "architecture"),
                services_safe_before=_boolean(
                    value["services_safe_before"], "services_safe_before"
                ),
                reboot_performed=_boolean(
                    value["reboot_performed"], "reboot_performed"
                ),
                reconnected=_boolean(value["reconnected"], "reconnected"),
                boot_changed=_boolean(value["boot_changed"], "boot_changed"),
                identity_verified=_boolean(
                    value["identity_verified"], "identity_verified"
                ),
                trust_revalidated=_boolean(
                    value["trust_revalidated"], "trust_revalidated"
                ),
                machine_evidence_verified=_boolean(
                    value["machine_evidence_verified"],
                    "machine_evidence_verified",
                ),
                services_safe_after=_boolean(
                    value["services_safe_after"], "services_safe_after"
                ),
                reboot_required_clear=_boolean(
                    value["reboot_required_clear"], "reboot_required_clear"
                ),
                elapsed_seconds=_integer(value["elapsed_seconds"], "elapsed_seconds"),
                target_plan_digest=require_string(value, "target_plan_digest"),
                variables_digest=require_string(value, "variables_digest"),
                command_digest=require_string(value, "command_digest"),
                source_digest=require_string(value, "source_digest"),
                request_digest=require_string(value, "request_digest"),
                result_digest=require_string(value, "result_digest"),
                evidence_digest=require_string(value, "evidence_digest"),
                result_schema_version=require_string(value, "result_schema_version"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy reboot evidence enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployRebootEvidence:
    """Immutable-prefix post-reboot semantic evidence."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployRebootExecutionBinding
    entries: tuple[DeployRebootEvidenceEntry, ...]
    schema_version: str = ANSIBLE_DEPLOY_REBOOT_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_REBOOT_EVIDENCE_SCHEMA_VERSION
            or self.generation < 1
            or not self.entries
            or self.generation != len(self.entries)
            or len(self.entries) > self.binding.target_count
            or tuple(entry.sequence for entry in self.entries)
            != tuple(range(1, len(self.entries) + 1))
        ):
            raise StatePersistenceError("deploy reboot evidence summary conflicts")
        parse_timestamp(self.created_at)
        parse_timestamp(self.updated_at)

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
    def from_object(cls, value: Mapping[str, object]) -> DeployRebootEvidence:
        require_exact_keys(value, set(cls.__dataclass_fields__), "reboot evidence")
        return cls(
            generation=_integer(value["generation"], "generation"),
            created_at=require_string(value, "created_at"),
            updated_at=require_string(value, "updated_at"),
            binding=DeployRebootExecutionBinding.from_object(
                _mapping(value["binding"], "reboot evidence binding")
            ),
            entries=tuple(
                DeployRebootEvidenceEntry.from_object(
                    _mapping(item, "reboot evidence entry")
                )
                for item in _array(value["entries"], "reboot evidence entries")
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredDeployRebootExecution:
    record: DeployRebootExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployRebootEvidence:
    record: DeployRebootEvidence
    artifact_digest: str


class DeployRebootExecutionStore:
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
        self._path = deploy_reboot_execution_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployRebootExecution:
        value, artifact_digest = self._file.read()
        record = DeployRebootExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError("deploy reboot execution identity conflicts")
        return StoredDeployRebootExecution(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployRebootExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployRebootExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployRebootExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError("deploy reboot execution operation conflicts")
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if (
                current.record.generation != expected_generation
                or current.artifact_digest != expected_digest
            ):
                raise StateConflictError("deploy reboot execution changed concurrently")
            _validate_execution_transition(current.record, record)
        elif expected_generation != 0 or expected_digest is not None:
            raise StateConflictError("deploy reboot execution prefix is missing")
        elif record.generation != 1:
            raise StatePersistenceError("deploy reboot initial execution is invalid")
        artifact_digest = self._file.write(
            record.to_object(), expected_digest=expected_digest
        )
        return StoredDeployRebootExecution(record, artifact_digest)


class DeployRebootEvidenceStore:
    """Generation-guarded immutable-prefix evidence store."""

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
        self._path = deploy_reboot_evidence_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployRebootEvidence:
        value, artifact_digest = self._file.read()
        record = DeployRebootEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError("deploy reboot evidence identity conflicts")
        return StoredDeployRebootEvidence(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployRebootEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def append_locked(
        self,
        record: DeployRebootEvidence,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployRebootEvidence:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError("deploy reboot evidence operation conflicts")
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if (
                current.record.generation != expected_generation
                or current.artifact_digest != expected_digest
            ):
                raise StateConflictError("deploy reboot evidence changed concurrently")
            if (
                record.generation != current.record.generation + 1
                or record.created_at != current.record.created_at
                or record.binding != current.record.binding
                or record.entries[:-1] != current.record.entries
                or len(record.entries) != len(current.record.entries) + 1
            ):
                raise StatePersistenceError(
                    "deploy reboot evidence transition is invalid"
                )
        elif expected_generation != 0 or expected_digest is not None:
            raise StateConflictError("deploy reboot evidence prefix is missing")
        elif record.generation != 1 or len(record.entries) != 1:
            raise StatePersistenceError("deploy reboot initial evidence is invalid")
        artifact_digest = self._file.write(
            record.to_object(), expected_digest=expected_digest
        )
        return StoredDeployRebootEvidence(record, artifact_digest)


@dataclass(frozen=True, slots=True)
class DeployRebootExecutionReport:
    """Strict redacted execution projection."""

    operation_id: uuid.UUID
    execution_artifact_state: DeployRebootArtifactState
    evidence_artifact_state: DeployRebootArtifactState
    execution_state: str
    execution_artifact_digest: str | None
    evidence_artifact_digest: str | None
    binding_digest: str | None
    authorization_consumed: bool
    target_count: int
    completed_target_count: int
    invocation_count: int
    target_set_digest: str | None
    target_order_digest: str | None
    reconnect_count: int
    identity_verified_count: int
    trust_revalidated_count: int
    machine_evidence_verified_count: int
    boot_changed_count: int
    reboot_clear_count: int
    post_reboot_evidence_state: str
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    journal_status: JournalStatus
    journal_phase: OperationPhase
    execution_schema_version: str = ANSIBLE_DEPLOY_REBOOT_EXECUTION_SCHEMA_VERSION
    evidence_schema_version: str = ANSIBLE_DEPLOY_REBOOT_EVIDENCE_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_REBOOT_EXECUTION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_REBOOT_EXECUTION_REPORT_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_REBOOT_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_REBOOT_EVIDENCE_SCHEMA_VERSION
            or not isinstance(self.operation_id, uuid.UUID)
            or self.target_count < 0
            or self.completed_target_count < 0
            or self.invocation_count < 0
            or self.completed_target_count > self.target_count
            or self.automatic_retry_allowed
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError("deploy reboot execution report is invalid")
        counts = (
            self.reconnect_count,
            self.identity_verified_count,
            self.trust_revalidated_count,
            self.machine_evidence_verified_count,
            self.boot_changed_count,
            self.reboot_clear_count,
        )
        if any(count < 0 or count > self.completed_target_count for count in counts):
            raise StatePersistenceError("deploy reboot report gate counts conflict")
        for value in (
            self.execution_artifact_digest,
            self.evidence_artifact_digest,
            self.binding_digest,
            self.target_set_digest,
            self.target_order_digest,
        ):
            if value is not None:
                validate_digest(value, "deploy reboot report digest")
        if self.execution_artifact_state is DeployRebootArtifactState.NOT_REQUIRED:
            if (
                self.evidence_artifact_state
                is not DeployRebootArtifactState.NOT_REQUIRED
                or self.execution_state != _NOT_REQUIRED
                or self.target_count
                or self.authorization_consumed
                or self.post_reboot_evidence_state != _NOT_REQUIRED
                or any(counts)
                or any(
                    value is not None
                    for value in (
                        self.execution_artifact_digest,
                        self.evidence_artifact_digest,
                        self.binding_digest,
                        self.target_set_digest,
                        self.target_order_digest,
                    )
                )
            ):
                raise StatePersistenceError(
                    "deploy reboot not-required report conflicts"
                )
        elif (
            self.execution_state != DeployRebootExecutionState.SUCCEEDED.value
            or not self.authorization_consumed
            or self.completed_target_count != self.target_count
            or self.invocation_count != self.target_count
            or any(count != self.target_count for count in counts)
            or self.post_reboot_evidence_state != _POST_REBOOT_EVIDENCE_READY
            or self.manual_recovery_required
            or any(
                value is None
                for value in (
                    self.execution_artifact_digest,
                    self.evidence_artifact_digest,
                    self.binding_digest,
                    self.target_set_digest,
                    self.target_order_digest,
                )
            )
        ):
            raise StatePersistenceError("deploy reboot success report conflicts")

    def to_object(self) -> dict[str, object]:
        return {
            "artifacts": {
                "evidence_digest": self.evidence_artifact_digest,
                "evidence_state": self.evidence_artifact_state.value,
                "execution_digest": self.execution_artifact_digest,
                "execution_state": self.execution_artifact_state.value,
            },
            "authorization": {"consumed": self.authorization_consumed},
            "evidence": {
                "boot_changed_count": self.boot_changed_count,
                "identity_verified_count": self.identity_verified_count,
                "machine_evidence_verified_count": (
                    self.machine_evidence_verified_count
                ),
                "reboot_clear_count": self.reboot_clear_count,
                "reconnect_count": self.reconnect_count,
                "state": self.post_reboot_evidence_state,
                "trust_revalidated_count": self.trust_revalidated_count,
            },
            "execution": {
                "automatic_retry_allowed": self.automatic_retry_allowed,
                "binding_digest": self.binding_digest,
                "completed_target_count": self.completed_target_count,
                "invocation_count": self.invocation_count,
                "manual_recovery_required": self.manual_recovery_required,
                "state": self.execution_state,
                "target_count": self.target_count,
                "target_order_digest": self.target_order_digest,
                "target_set_digest": self.target_set_digest,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "operation_id": str(self.operation_id),
            "schema_version": self.schema_version,
            "schemas": {
                "evidence": self.evidence_schema_version,
                "execution": self.execution_schema_version,
            },
        }


@dataclass(frozen=True, slots=True)
class _RebootScope:
    target: DeployRebootPlanTarget
    variables: Mapping[str, object]
    variables_digest: str
    command_digest: str
    source_digest: str
    request_digest: str
    target_plan_digest: str


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    base: _BaseOsReconciliationContext
    reconciliation: StoredDeployBaseOsReconciliation
    plan: StoredDeployRebootPlan
    authorization: StoredDeployRebootAuthorization
    binding: DeployRebootExecutionBinding
    scopes: tuple[_RebootScope, ...]
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport


def execute_deploy_reboots(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployRebootExecutionReport:
    """Execute the exact immutable reboot order with one strict checkpoint each."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _refuse_ambiguous_artifacts(paths, operation_id)
    execution_store = DeployRebootExecutionStore(paths, operation_id)
    evidence_store = DeployRebootEvidenceStore(paths, operation_id)
    for path in (execution_store.path, evidence_store.path):
        validate_state_file(path, allow_missing=True)

    base = _load_base_os_context(paths, operation_id, lock=lock)
    reconciliation = _load_reconciliation(paths, operation_id, base, lock=lock)
    if not reconciliation.record.reboot_required:
        if any(
            path.exists()
            for path in (
                deploy_reboot_plan_path(paths, operation_id),
                deploy_reboot_authorization_path(paths, operation_id),
                execution_store.path,
                evidence_store.path,
            )
        ):
            raise StateConflictError(
                "deploy reboot artifacts conflict with no-reboot evidence"
            )
        return _not_required_report(operation_id, reconciliation)

    _validate_toolchain_dependency(toolchain)
    executable_identity_digest = _executable_identity_digest(executables)
    toolchain_evidence_digest = _toolchain_evidence_digest(
        toolchain, executable_identity_digest
    )
    builder = AnsibleCommandBuilder(
        executables.playbook,
        executables.inventory,
        paths,
    )
    context = _load_execution_context(
        paths,
        operation_id,
        base=base,
        reconciliation=reconciliation,
        lock=lock,
        builder=builder,
        toolchain=toolchain,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    metadata = context.metadata
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
    if execution is not None and execution.record.all_targets_completed:
        if evidence is None:
            raise StateConflictError("completed deploy reboot evidence is unavailable")
        return _build_report(context, execution, evidence, reused=True)
    if execution is not None and execution.record.state not in {
        DeployRebootExecutionState.PREPARED,
        DeployRebootExecutionState.SUCCEEDED,
    }:
        raise StateConflictError(
            "deploy reboot execution requires manual recovery and cannot retry"
        )

    service = AnsibleService(builder, runner)
    discovered = service.version(lock)
    if discovered != toolchain:
        raise StateConflictError("deploy reboot toolchain drifted")
    context = _load_execution_context(
        paths,
        operation_id,
        base=_load_base_os_context(paths, operation_id, lock=lock),
        reconciliation=_load_reconciliation(
            paths,
            operation_id,
            _load_base_os_context(paths, operation_id, lock=lock),
            lock=lock,
        ),
        lock=lock,
        builder=builder,
        toolchain=toolchain,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    _validate_prefix(context, execution, evidence)

    if (
        execution is None
        or execution.record.state is DeployRebootExecutionState.SUCCEEDED
    ):
        scope = context.scopes[len(execution.record.attempts) if execution else 0]
        try:
            execution = _persist_prepared(
                context, execution_store, execution, scope, lock=lock
            )
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy reboot prepared intent persistence failed before invocation"
            ) from error

    assert execution is not None
    while True:
        if execution.record.state is DeployRebootExecutionState.PREPARED:
            before = _load_execution_context(
                paths,
                operation_id,
                base=_load_base_os_context(paths, operation_id, lock=lock),
                reconciliation=_load_reconciliation(
                    paths,
                    operation_id,
                    _load_base_os_context(paths, operation_id, lock=lock),
                    lock=lock,
                ),
                lock=lock,
                builder=builder,
                toolchain=toolchain,
                executable_identity_digest=executable_identity_digest,
                toolchain_evidence_digest=toolchain_evidence_digest,
            )
            if before.binding != context.binding:
                raise StateConflictError("deploy reboot state drifted before start")
            _validate_prefix(before, execution, evidence)
            scope = before.scopes[len(execution.record.attempts) - 1]
            try:
                execution = _persist_started(execution_store, execution, lock=lock)
            except StatePersistenceError as error:
                raise StatePersistenceError(
                    "deploy reboot authorization consumption failed before invocation"
                ) from error
            try:
                result, observed_command_digest = service.execute_operation_step(
                    lock,
                    before.metadata,
                    before.inventory,
                    _PLAYBOOK,
                    step_sequence=scope.target.sequence,
                    limit=(scope.target.stable_id,),
                    variables=dict(scope.variables),
                    readiness=before.readiness,
                    tags=(_PLAYBOOK,),
                    check=False,
                    diff=False,
                    verbosity=0,
                )
                if observed_command_digest != scope.command_digest:
                    raise AnsibleResultError(
                        "deploy reboot command result identity conflicts"
                    )
            except KeyboardInterrupt:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    DeployRebootExecutionState.INTERRUPTED,
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy reboot execution was interrupted; manual recovery required"
                ) from None
            except AnsibleError as error:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    _failure_state(error),
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy reboot execution is uncertain; manual recovery required"
                ) from error

            try:
                after_base = _load_base_os_context(paths, operation_id, lock=lock)
                after = _load_execution_context(
                    paths,
                    operation_id,
                    base=after_base,
                    reconciliation=_load_reconciliation(
                        paths, operation_id, after_base, lock=lock
                    ),
                    lock=lock,
                    builder=builder,
                    toolchain=toolchain,
                    executable_identity_digest=executable_identity_digest,
                    toolchain_evidence_digest=toolchain_evidence_digest,
                )
            except (StateConflictError, StatePersistenceError) as error:
                raise StateConflictError(
                    "deploy reboot state changed after invocation; "
                    "manual recovery required"
                ) from error
            if after.binding != context.binding:
                raise StateConflictError(
                    "deploy reboot state changed after invocation; "
                    "manual recovery required"
                )
            try:
                entry = _semantic_entry(scope, result)
            except (AnsibleError, StatePersistenceError) as error:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    DeployRebootExecutionState.MALFORMED_RESULT,
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy reboot result is malformed; manual recovery required"
                ) from error
            try:
                evidence = _persist_evidence(
                    context, evidence_store, evidence, entry, lock=lock
                )
            except StatePersistenceError as error:
                raise StatePersistenceError(
                    "deploy reboot evidence persistence failed; "
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
                    "deploy reboot terminal persistence failed; "
                    "manual recovery required"
                ) from error
            if terminal_state is not DeployRebootExecutionState.SUCCEEDED:
                raise AnsibleError(
                    "deploy reboot execution failed; manual recovery required"
                )

        if execution.record.all_targets_completed:
            break
        next_scope = context.scopes[len(execution.record.attempts)]
        try:
            execution = _persist_prepared(
                context, execution_store, execution, next_scope, lock=lock
            )
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy reboot next prepared intent failed before invocation"
            ) from error
    if evidence is None:
        raise StatePersistenceError("deploy reboot completion evidence is missing")
    _validate_prefix(context, execution, evidence)
    return _build_report(context, execution, evidence, reused=False)


def deploy_reboot_execution_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / f"{operation_id}{DEPLOY_REBOOT_EXECUTION_FILENAME_SUFFIX}"
    if path.parent != paths.operations:
        raise StatePersistenceError("deploy reboot execution path is not canonical")
    return path


def deploy_reboot_evidence_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / f"{operation_id}{DEPLOY_REBOOT_EVIDENCE_FILENAME_SUFFIX}"
    if path.parent != paths.operations:
        raise StatePersistenceError("deploy reboot evidence path is not canonical")
    return path


def deploy_reboot_execution_id_from_filename(name: str) -> uuid.UUID | None:
    return _id_from_filename(name, DEPLOY_REBOOT_EXECUTION_FILENAME_SUFFIX)


def deploy_reboot_evidence_id_from_filename(name: str) -> uuid.UUID | None:
    return _id_from_filename(name, DEPLOY_REBOOT_EVIDENCE_FILENAME_SUFFIX)


def _load_reconciliation(
    paths: StatePaths,
    operation_id: uuid.UUID,
    base: _BaseOsReconciliationContext,
    *,
    lock: ClusterLock,
) -> StoredDeployBaseOsReconciliation:
    metadata = base.host.loaded.planning.base.deploy.metadata.record
    store = DeployBaseOsReconciliationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    if not store.path.exists():
        raise StateConflictError("deploy reboot execution requires reconciliation")
    stored = store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected = _build_base_os_reconciliation(
        base,
        steps=_build_base_os_reconciled_steps(base),
        created_at=stored.record.created_at,
    )
    if stored.record != expected:
        raise StateConflictError("deploy reboot reconciliation drifted")
    return stored


def _load_execution_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    base: _BaseOsReconciliationContext,
    reconciliation: StoredDeployBaseOsReconciliation,
    lock: ClusterLock,
    builder: AnsibleCommandBuilder,
    toolchain: AnsibleToolchain,
    executable_identity_digest: str,
    toolchain_evidence_digest: str,
) -> _ExecutionContext:
    planning = base.host.loaded.planning
    loaded = base.host.loaded
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    journal = deploy.journal
    readiness_record = planning.readiness.record
    if (
        journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
        or not reconciliation.record.reboot_required
        or readiness_record.executable_identity_digest != executable_identity_digest
        or readiness_record.toolchain_evidence_digest != toolchain_evidence_digest
        or readiness_record.playbook_version != str(toolchain.core)
        or readiness_record.inventory_version != str(toolchain.core)
        or readiness_record.remote_playbook_status != "not-performed"
    ):
        raise StateConflictError(
            "deploy reboot readiness, journal, or toolchain conflicts"
        )
    readiness = _reconstructed_readiness(planning.base)
    if readiness_binding_digest(readiness) != readiness_record.readiness_digest:
        raise StateConflictError("deploy reboot readiness is stale")
    readiness.require_ready(OperationClassification.MUTATING)
    TrustStore(paths).validate_runtime(planning.base.trust, deploy.inventory)

    plan_store = DeployRebootPlanStore(paths, operation_id)
    authorization_store = DeployRebootAuthorizationStore(paths, operation_id)
    for path, label in (
        (plan_store.path, "immutable plan"),
        (authorization_store.path, "immutable authorization"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(f"deploy reboot execution requires {label}")
    plan = plan_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    candidates = _derive_candidates(base, reconciliation)
    targets, blockers = _build_targets(base, candidates)
    expected_plan = _build_plan(
        base,
        reconciliation,
        targets=targets,
        blockers=blockers,
        created_at=plan.record.created_at,
    )
    if (
        plan.record != expected_plan
        or blockers
        or plan.record.blocker_set
        or plan.record.planning_state != "ready-for-authorization"
    ):
        raise StateConflictError("deploy reboot plan is blocked, stale, or drifted")
    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_authorization = _build_authorization(
        plan,
        proof=authorization.record.proof,
        created_at=authorization.record.created_at,
    )
    if (
        authorization.record != expected_authorization
        or authorization.record.consumed
        or authorization.record.authorization_state != "authorized-pre-execution"
    ):
        raise StateConflictError("deploy reboot authorization is stale or consumed")

    source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
    base_os_hosts = {
        host.logical_id: host
        for entry in base.evidence.record.entries
        for host in entry.hosts
    }
    scopes: list[_RebootScope] = []
    for target in plan.record.targets:
        host = base_os_hosts.get(target.stable_id)
        inventory_host = next(
            (
                item
                for item in deploy.inventory.record.inventory.hosts
                if item.logical_id == target.stable_id
            ),
            None,
        )
        if (
            host is None
            or inventory_host is None
            or inventory_host.role is not target.role
            or host.status.value != "reboot-required"
            or not host.reboot_required
            or host.os_family != "Ubuntu"
            or host.os_version != "24.04"
            or host.guest_architecture not in _SUPPORTED_ARCHITECTURES
            or not host.applied
            or host.prerequisite_policy_status != "satisfied"
            or host.timesync_service_status != "enabled-active"
        ):
            raise StateConflictError("deploy reboot target evidence is not safe")
        target_plan_digest = _digest_object(target.to_object())
        request_digest = _digest_object(
            {
                "authorization_digest": authorization.record.authorization_digest,
                "base_os_evidence_digest": target.base_os_evidence_digest,
                "base_os_result_digest": target.base_os_result_digest,
                "operation_id": str(operation_id),
                "plan_record_digest": plan.record.record_digest,
                "source_digest": source_digest,
                "target_plan_digest": target_plan_digest,
                "trust_identity_digest": target.trust_identity_digest,
            }
        )
        variables = deploy_reboot_variables(
            operation_id=str(operation_id),
            logical_id=target.stable_id,
            role=target.role,
            architecture=host.guest_architecture,
            request_digest=request_digest,
        )
        _, validated, variables_digest, command_digest = (
            builder.validate_operation_step(
                _PLAYBOOK,
                step_sequence=target.sequence,
                limit=(target.stable_id,),
                variables=variables,
                tags=(_PLAYBOOK,),
                check=False,
                diff=False,
                verbosity=0,
            )
        )
        scopes.append(
            _RebootScope(
                target,
                validated,
                variables_digest,
                command_digest,
                source_digest,
                request_digest,
                target_plan_digest,
            )
        )
    if (
        not scopes
        or len(scopes) != plan.record.target_count
        or tuple(scope.target.sequence for scope in scopes)
        != tuple(range(1, len(scopes) + 1))
    ):
        raise StateConflictError("deploy reboot execution scope is unavailable")
    scope_digest = _digest_object(
        [
            {
                "command_digest": scope.command_digest,
                "request_digest": scope.request_digest,
                "sequence": scope.target.sequence,
                "source_digest": scope.source_digest,
                "target_plan_digest": scope.target_plan_digest,
                "variables_digest": scope.variables_digest,
            }
            for scope in scopes
        ]
    )
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
        "reboot_plan_artifact_digest": plan.artifact_digest,
        "reboot_plan_record_digest": plan.record.record_digest,
        "reboot_authorization_artifact_digest": authorization.artifact_digest,
        "reboot_authorization_digest": authorization.record.authorization_digest,
        "reboot_authorization_proof_digest": authorization.record.proof.proof_digest,
        "base_os_reconciliation_artifact_digest": reconciliation.artifact_digest,
        "base_os_reconciliation_record_digest": reconciliation.record.record_digest,
        "base_os_execution_artifact_digest": base.execution.artifact_digest,
        "base_os_evidence_artifact_digest": base.evidence.artifact_digest,
        "connectivity_execution_artifact_digest": loaded.execution.artifact_digest,
        "connectivity_evidence_artifact_digest": loaded.evidence.artifact_digest,
        "connectivity_evidence_digest": plan.record.connectivity_evidence_digest,
        "inventory_generation": deploy.inventory.record.generation,
        "inventory_artifact_digest": deploy.inventory.digest,
        "inventory_digest": deploy.inventory.record.inventory_digest,
        "trust_generation": planning.base.trust.record.generation,
        "trust_artifact_digest": planning.base.trust.digest,
        "trust_entries_digest": planning.base.trust.record.entries_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": readiness_record.record_digest,
        "catalog_digest": loaded.catalog_digest,
        "source_version": loaded.source.version,
        "source_digest": loaded.source.digest,
        "playbook_source_digest": source_digest,
        "toolchain_version": str(toolchain.core),
        "executable_identity_digest": executable_identity_digest,
        "toolchain_evidence_digest": toolchain_evidence_digest,
        "target_count": plan.record.target_count,
        "target_set_digest": plan.record.target_set_digest,
        "target_order_digest": plan.record.target_order_digest,
        "role_batch_digest": plan.record.role_batch_digest,
        "execution_scope_digest": scope_digest,
        "binding_digest": "",
    }
    binding_values["binding_digest"] = _binding_digest_from_values(binding_values)
    binding = DeployRebootExecutionBinding(**binding_values)  # type: ignore[arg-type]
    return _ExecutionContext(
        base,
        reconciliation,
        plan,
        authorization,
        binding,
        tuple(scopes),
        metadata,
        deploy.inventory,
        readiness,
    )


def _validate_prefix(
    context: _ExecutionContext,
    execution: StoredDeployRebootExecution | None,
    evidence: StoredDeployRebootEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError("deploy reboot evidence exists without intent")
        return
    if execution.record.binding != context.binding:
        raise StateConflictError("deploy reboot execution provenance is stale")
    if evidence is not None and evidence.record.binding != context.binding:
        raise StateConflictError("deploy reboot evidence provenance is stale")
    for index, attempt in enumerate(execution.record.attempts):
        if index >= len(context.scopes):
            raise StateConflictError("deploy reboot execution has extra attempts")
        scope = context.scopes[index]
        if (
            attempt.sequence != scope.target.sequence
            or attempt.stable_id != scope.target.stable_id
            or attempt.role is not scope.target.role
            or attempt.target_plan_digest != scope.target_plan_digest
            or attempt.variables_digest != scope.variables_digest
            or attempt.command_digest != scope.command_digest
            or attempt.source_digest != scope.source_digest
            or attempt.request_digest != scope.request_digest
        ):
            raise StateConflictError("deploy reboot execution scope conflicts")
    entries = evidence.record.entries if evidence is not None else ()
    if len(entries) > len(execution.record.attempts):
        raise StateConflictError("deploy reboot evidence prefix conflicts")
    for index, entry in enumerate(entries):
        attempt = execution.record.attempts[index]
        scope = context.scopes[index]
        if (
            attempt.state is DeployRebootExecutionState.PREPARED
            or entry.sequence != scope.target.sequence
            or entry.stable_id != scope.target.stable_id
            or entry.role is not scope.target.role
            or entry.target_plan_digest != scope.target_plan_digest
            or entry.variables_digest != scope.variables_digest
            or entry.command_digest != scope.command_digest
            or entry.source_digest != scope.source_digest
            or entry.request_digest != scope.request_digest
            or (
                attempt.result_digest is not None
                and attempt.result_digest != entry.result_digest
            )
            or (
                attempt.evidence_digest is not None
                and attempt.evidence_digest != entry.evidence_digest
            )
        ):
            raise StateConflictError("deploy reboot semantic evidence conflicts")
    terminal_with_evidence = sum(
        attempt.state
        in {
            DeployRebootExecutionState.SUCCEEDED,
            DeployRebootExecutionState.FAILED,
            DeployRebootExecutionState.UNREACHABLE,
        }
        for attempt in execution.record.attempts
    )
    allowed_started_extra = (
        1
        if execution.record.state is DeployRebootExecutionState.STARTED
        and len(entries) == terminal_with_evidence + 1
        else 0
    )
    if len(entries) != terminal_with_evidence + allowed_started_extra:
        raise StateConflictError("deploy reboot execution/evidence prefixes conflict")
    if any(
        entry.status is not DeployRebootResultStatus.SUCCEEDED for entry in entries[:-1]
    ):
        raise StateConflictError("deploy reboot execution continued after failure")


def _persist_prepared(
    context: _ExecutionContext,
    store: DeployRebootExecutionStore,
    current: StoredDeployRebootExecution | None,
    scope: _RebootScope,
    *,
    lock: ClusterLock,
) -> StoredDeployRebootExecution:
    now = _timestamp()
    attempt = DeployRebootExecutionAttempt(
        sequence=scope.target.sequence,
        stable_id=scope.target.stable_id,
        role=scope.target.role,
        target_plan_digest=scope.target_plan_digest,
        variables_digest=scope.variables_digest,
        command_digest=scope.command_digest,
        source_digest=scope.source_digest,
        request_digest=scope.request_digest,
        state=DeployRebootExecutionState.PREPARED,
        prepared_at=now,
        started_at=None,
        completed_at=None,
        authorization_consumed=(
            current.record.authorization_consumed if current is not None else False
        ),
        invocation_may_have_occurred=False,
        exit_code=None,
        result_digest=None,
        evidence_digest=None,
        manual_recovery_required=False,
        automatic_retry_allowed=False,
    )
    if current is None:
        record = DeployRebootExecution(
            generation=1,
            created_at=now,
            updated_at=now,
            binding=context.binding,
            state=DeployRebootExecutionState.PREPARED,
            authorization_consumed=False,
            invocation_count=0,
            completed_target_count=0,
            all_targets_completed=False,
            attempts=(attempt,),
        )
        return store.write_locked(
            record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    if current.record.state is not DeployRebootExecutionState.SUCCEEDED:
        raise StateConflictError("deploy reboot cannot prepare after uncertain state")
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=DeployRebootExecutionState.PREPARED,
        all_targets_completed=False,
        attempts=(*current.record.attempts, attempt),
    )
    return store.write_locked(
        record,
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _persist_started(
    store: DeployRebootExecutionStore,
    current: StoredDeployRebootExecution,
    *,
    lock: ClusterLock,
) -> StoredDeployRebootExecution:
    if current.record.state is not DeployRebootExecutionState.PREPARED:
        raise StateConflictError("deploy reboot start requires prepared intent")
    now = _timestamp()
    attempt = replace(
        current.record.attempts[-1],
        state=DeployRebootExecutionState.STARTED,
        started_at=now,
        authorization_consumed=True,
        invocation_may_have_occurred=True,
        manual_recovery_required=True,
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=DeployRebootExecutionState.STARTED,
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
    store: DeployRebootExecutionStore,
    current: StoredDeployRebootExecution,
    state: DeployRebootExecutionState,
    *,
    lock: ClusterLock,
) -> None:
    try:
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
        store.write_locked(
            record,
            expected_generation=current.record.generation,
            expected_digest=current.artifact_digest,
            lock=lock,
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy reboot uncertain outcome persistence failed; "
            "manual recovery required"
        ) from error


def _persist_evidence(
    context: _ExecutionContext,
    store: DeployRebootEvidenceStore,
    current: StoredDeployRebootEvidence | None,
    entry: DeployRebootEvidenceEntry,
    *,
    lock: ClusterLock,
) -> StoredDeployRebootEvidence:
    now = _timestamp()
    if current is None:
        record = DeployRebootEvidence(
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


def _persist_terminal(
    context: _ExecutionContext,
    store: DeployRebootExecutionStore,
    current: StoredDeployRebootExecution,
    *,
    state: DeployRebootExecutionState,
    exit_code: int,
    result_digest: str,
    evidence_digest: str,
    lock: ClusterLock,
) -> StoredDeployRebootExecution:
    now = _timestamp()
    attempt = replace(
        current.record.attempts[-1],
        state=state,
        completed_at=now,
        exit_code=exit_code,
        result_digest=result_digest,
        evidence_digest=evidence_digest,
        manual_recovery_required=state is not DeployRebootExecutionState.SUCCEEDED,
    )
    completed = current.record.completed_target_count + int(
        state is DeployRebootExecutionState.SUCCEEDED
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=state,
        completed_target_count=completed,
        all_targets_completed=(
            state is DeployRebootExecutionState.SUCCEEDED
            and completed == context.binding.target_count
        ),
        attempts=(*current.record.attempts[:-1], attempt),
    )
    return store.write_locked(
        record,
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _semantic_entry(
    scope: _RebootScope, result: AnsibleExecutionResult
) -> DeployRebootEvidenceEntry:
    reboot = result.deploy_reboot
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.MUTATING
        or result.check_mode
        or reboot is None
        or result.stdout
        or result.stderr
        or reboot.logical_id != scope.target.stable_id
        or reboot.role is not scope.target.role
        or reboot.request_digest != scope.request_digest
    ):
        raise AnsibleResultError("deploy reboot result identity conflicts")
    result_digest = _digest_object(reboot.to_object())
    values: dict[str, object] = {
        "sequence": scope.target.sequence,
        "stable_id": reboot.logical_id,
        "role": reboot.role,
        "status": reboot.status,
        "os_family": reboot.os_family,
        "os_version": reboot.os_version,
        "architecture": reboot.architecture,
        "services_safe_before": reboot.services_safe_before,
        "reboot_performed": reboot.reboot_performed,
        "reconnected": reboot.reconnected,
        "boot_changed": reboot.boot_changed,
        "identity_verified": reboot.identity_verified,
        "trust_revalidated": reboot.trust_revalidated,
        "machine_evidence_verified": reboot.machine_evidence_verified,
        "services_safe_after": reboot.services_safe_after,
        "reboot_required_clear": reboot.reboot_required_clear,
        "elapsed_seconds": reboot.elapsed_seconds,
        "target_plan_digest": scope.target_plan_digest,
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "source_digest": scope.source_digest,
        "request_digest": scope.request_digest,
        "result_digest": result_digest,
        "evidence_digest": "",
    }
    values["evidence_digest"] = _entry_digest_from_values(values)
    return DeployRebootEvidenceEntry(**values)  # type: ignore[arg-type]


def _terminal_state(
    entry: DeployRebootEvidenceEntry, exit_code: int
) -> DeployRebootExecutionState:
    if exit_code == 0 and entry.status is DeployRebootResultStatus.SUCCEEDED:
        return DeployRebootExecutionState.SUCCEEDED
    if exit_code == 4 or entry.status is DeployRebootResultStatus.UNREACHABLE:
        return DeployRebootExecutionState.UNREACHABLE
    return DeployRebootExecutionState.FAILED


def _build_report(
    context: _ExecutionContext,
    execution: StoredDeployRebootExecution,
    evidence: StoredDeployRebootEvidence,
    *,
    reused: bool,
) -> DeployRebootExecutionReport:
    entries = evidence.record.entries
    if (
        not execution.record.all_targets_completed
        or execution.record.state is not DeployRebootExecutionState.SUCCEEDED
        or len(entries) != context.binding.target_count
        or any(
            entry.status is not DeployRebootResultStatus.SUCCEEDED for entry in entries
        )
    ):
        raise StateConflictError("deploy reboot execution is not complete")
    return DeployRebootExecutionReport(
        operation_id=context.binding.operation_id,
        execution_artifact_state=(
            DeployRebootArtifactState.REUSED
            if reused
            else DeployRebootArtifactState.UPDATED
            if execution.record.generation > 3
            else DeployRebootArtifactState.CREATED
        ),
        evidence_artifact_state=(
            DeployRebootArtifactState.REUSED
            if reused
            else DeployRebootArtifactState.UPDATED
            if evidence.record.generation > 1
            else DeployRebootArtifactState.CREATED
        ),
        execution_state=execution.record.state.value,
        execution_artifact_digest=execution.artifact_digest,
        evidence_artifact_digest=evidence.artifact_digest,
        binding_digest=context.binding.binding_digest,
        authorization_consumed=execution.record.authorization_consumed,
        target_count=context.binding.target_count,
        completed_target_count=execution.record.completed_target_count,
        invocation_count=execution.record.invocation_count,
        target_set_digest=context.binding.target_set_digest,
        target_order_digest=context.binding.target_order_digest,
        reconnect_count=sum(entry.reconnected for entry in entries),
        identity_verified_count=sum(entry.identity_verified for entry in entries),
        trust_revalidated_count=sum(entry.trust_revalidated for entry in entries),
        machine_evidence_verified_count=sum(
            entry.machine_evidence_verified for entry in entries
        ),
        boot_changed_count=sum(entry.boot_changed for entry in entries),
        reboot_clear_count=sum(entry.reboot_required_clear for entry in entries),
        post_reboot_evidence_state=_POST_REBOOT_EVIDENCE_READY,
        manual_recovery_required=False,
        automatic_retry_allowed=False,
        journal_status=context.binding.journal_status,
        journal_phase=context.binding.journal_phase,
    )


def _not_required_report(
    operation_id: uuid.UUID,
    reconciliation: StoredDeployBaseOsReconciliation,
) -> DeployRebootExecutionReport:
    return DeployRebootExecutionReport(
        operation_id=operation_id,
        execution_artifact_state=DeployRebootArtifactState.NOT_REQUIRED,
        evidence_artifact_state=DeployRebootArtifactState.NOT_REQUIRED,
        execution_state=_NOT_REQUIRED,
        execution_artifact_digest=None,
        evidence_artifact_digest=None,
        binding_digest=None,
        authorization_consumed=False,
        target_count=0,
        completed_target_count=0,
        invocation_count=0,
        target_set_digest=None,
        target_order_digest=None,
        reconnect_count=0,
        identity_verified_count=0,
        trust_revalidated_count=0,
        machine_evidence_verified_count=0,
        boot_changed_count=0,
        reboot_clear_count=0,
        post_reboot_evidence_state=_NOT_REQUIRED,
        manual_recovery_required=False,
        automatic_retry_allowed=False,
        journal_status=reconciliation.record.journal_status,
        journal_phase=reconciliation.record.journal_phase,
    )


def _validate_execution_transition(
    current: DeployRebootExecution,
    replacement: DeployRebootExecution,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or current.all_targets_completed
        or current.state
        not in {
            DeployRebootExecutionState.PREPARED,
            DeployRebootExecutionState.STARTED,
            DeployRebootExecutionState.SUCCEEDED,
        }
    ):
        raise StatePersistenceError("deploy reboot execution transition is invalid")
    if current.state is DeployRebootExecutionState.PREPARED:
        valid = (
            len(replacement.attempts) == len(current.attempts)
            and replacement.attempts[:-1] == current.attempts[:-1]
            and replacement.attempts[-1].state is DeployRebootExecutionState.STARTED
        )
    elif current.state is DeployRebootExecutionState.STARTED:
        valid = (
            len(replacement.attempts) == len(current.attempts)
            and replacement.attempts[:-1] == current.attempts[:-1]
            and replacement.attempts[-1].state
            not in {
                DeployRebootExecutionState.PREPARED,
                DeployRebootExecutionState.STARTED,
            }
        )
    else:
        valid = (
            len(current.attempts) < current.binding.target_count
            and replacement.attempts[:-1] == current.attempts
            and replacement.attempts[-1].state is DeployRebootExecutionState.PREPARED
        )
    if not valid:
        raise StatePersistenceError("deploy reboot execution transition conflicts")


def _failure_state(error: AnsibleError) -> DeployRebootExecutionState:
    if isinstance(error, AnsibleResultError):
        return DeployRebootExecutionState.MALFORMED_RESULT
    cause = error.__cause__
    if isinstance(cause, ProcessTimeoutError):
        return DeployRebootExecutionState.TIMED_OUT
    if isinstance(cause, ProcessOutputError):
        return DeployRebootExecutionState.MALFORMED_RESULT
    return DeployRebootExecutionState.FAILED


def _binding_digests(binding: DeployRebootExecutionBinding) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(binding, name))
        for name in binding.__dataclass_fields__
        if name.endswith("_digest")
    )


def _binding_digest(binding: DeployRebootExecutionBinding) -> str:
    value = binding.to_object()
    value["binding_digest"] = ""
    return _digest_object(value)


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployRebootExecutionBinding.__dataclass_fields__.items():
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


def _entry_digest(entry: DeployRebootEvidenceEntry) -> str:
    value = entry.to_object()
    value["evidence_digest"] = ""
    return _digest_object(value)


def _entry_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployRebootEvidenceEntry.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            item.value
            if isinstance(item, (HostRole, DeployRebootResultStatus))
            else item
        )
    value["evidence_digest"] = ""
    value["logical_id"] = value.pop("stable_id")
    return _digest_object(value)


def _timestamp() -> str:
    return format_timestamp(datetime.now(UTC))


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError("deploy reboot execution paths are not canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy reboot execution requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy reboot execution artifacts"
        ) from error
    canonical = str(operation_id)
    for suffix in (
        DEPLOY_REBOOT_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_REBOOT_EVIDENCE_FILENAME_SUFFIX,
    ):
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
                    "deploy reboot execution artifacts are ambiguous"
                )


def _id_from_filename(name: str, suffix: str) -> uuid.UUID | None:
    if not name.endswith(suffix):
        return None
    value = name[: -len(suffix)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


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
        raise StatePersistenceError(f"deploy reboot {label} is invalid") from error


__all__ = [
    "ANSIBLE_DEPLOY_REBOOT_EVIDENCE_ENTRY_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_REBOOT_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_REBOOT_EXECUTION_BINDING_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_REBOOT_EXECUTION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_REBOOT_EXECUTION_SCHEMA_VERSION",
    "DEPLOY_REBOOT_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_REBOOT_EXECUTION_FILENAME_SUFFIX",
    "DeployRebootArtifactState",
    "DeployRebootEvidence",
    "DeployRebootEvidenceEntry",
    "DeployRebootEvidenceStore",
    "DeployRebootExecution",
    "DeployRebootExecutionAttempt",
    "DeployRebootExecutionBinding",
    "DeployRebootExecutionReport",
    "DeployRebootExecutionState",
    "DeployRebootExecutionStore",
    "StoredDeployRebootEvidence",
    "StoredDeployRebootExecution",
    "deploy_reboot_evidence_id_from_filename",
    "deploy_reboot_evidence_path",
    "deploy_reboot_execution_id_from_filename",
    "deploy_reboot_execution_path",
    "execute_deploy_reboots",
]
