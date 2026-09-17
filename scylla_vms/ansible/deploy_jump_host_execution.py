"""Exact-scope deploy jump-host configuration execution.

This internal owner derives every executable input from canonical operation
state, records durable started intent before the one-host effect, and treats
every started ambiguity as manual-recovery/no-retry.
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
from scylla_vms.ansible.deploy_jump_host_authorization import (
    ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION,
    DeployJumpHostConfigureAuthorizationScope,
    DeployJumpHostConfigureAuthorizationStore,
    StoredDeployJumpHostConfigureAuthorization,
    _build_authorization,
    _derive_authorization_scopes,
)
from scylla_vms.ansible.deploy_plan import (
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_reboot_reconciliation import (
    ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION,
    DeployPostRebootReconciliationStore,
    StoredDeployPostRebootReconciliation,
    _PostRebootContext,
)
from scylla_vms.ansible.deploy_reboot_reconciliation import (
    _build_record as _build_post_reboot_record,
)
from scylla_vms.ansible.deploy_reboot_reconciliation import (
    _build_steps as _build_post_reboot_steps,
)
from scylla_vms.ansible.deploy_reboot_reconciliation import (
    _load_context as _load_post_reboot_context,
)
from scylla_vms.ansible.jump_host_configure import (
    JUMP_HOST_CONFIGURE_SCHEMA_VERSION,
    JumpHostConfigurationAuthorization,
    JumpHostConfigureEvidence,
    JumpHostConfigureStatus,
    authorize_jump_host_configuration,
    build_jump_host_configure_payload,
    parse_jump_host_configure_execution,
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
from scylla_vms.ansible.trust import StoredTrustRecord, TrustStore
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.journal import JOURNAL_SCHEMA_VERSION, JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import StoredObservedState
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

ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-jump-host-configure-execution-binding/v1"
)
ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-jump-host-configure-execution/v1"
)
ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_ENTRY_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-jump-host-configure-evidence-entry/v1"
)
ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-jump-host-configure-evidence/v1"
)
ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-jump-host-configure-execution-report/v1"
)

DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-jump-host-configure-execution.json"
)
DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-jump-host-configure-evidence.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "jump-host-configure"
_MAPPING_SEQUENCE = 4
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SUCCESS_STATUSES = frozenset(
    {JumpHostConfigureStatus.CHANGED, JumpHostConfigureStatus.NOOP}
)
_BLOCKERS = frozenset(
    {
        "execution-failed",
        "host-key-mismatch",
        "reload-failed",
        "sshd-validation-failed",
    }
)


class DeployJumpHostConfigureExecutionState(StrEnum):
    """Durable exact-target execution states."""

    PREPARED = "prepared"
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"


class DeployJumpHostConfigureArtifactState(StrEnum):
    """Persistence result for execution and evidence companions."""

    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"


class DeployJumpHostConfigureRestorationStatus(StrEnum):
    """Truthful bounded restore evidence."""

    NOT_REQUIRED = "not-required"
    NOT_PROVEN = "not-proven"


@dataclass(frozen=True, slots=True)
class DeployJumpHostConfigureExecutionBinding:
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
    configuration_intent_digest: str
    post_reboot_reconciliation_artifact_digest: str
    post_reboot_reconciliation_record_digest: str
    post_reboot_effective_plan_digest: str
    connectivity_evidence_digest: str
    observation_generation: int
    observation_artifact_digest: str
    observation_manifest_digest: str
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    route_digest: str
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
    scope_count: int
    target_count: int
    target_set_digest: str
    execution_scope_digest: str
    policy_digest: str
    binding_digest: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
    )
    post_reboot_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_BINDING_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_BINDING_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
            or self.post_reboot_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
        ):
            raise StatePersistenceError(
                "deploy jump-host-configure execution binding is invalid"
            )
        validate_cluster_name(self.cluster_name)
        for count_value, label in (
            (self.journal_generation, "journal generation"),
            (self.observation_generation, "observation generation"),
            (self.inventory_generation, "inventory generation"),
            (self.trust_generation, "trust generation"),
            (self.scope_count, "scope count"),
            (self.target_count, "target count"),
        ):
            _positive_integer(count_value, f"jump-host-configure {label}")
        if self.target_count != self.scope_count:
            raise StatePersistenceError(
                "deploy jump-host-configure execution scope counts conflict"
            )
        for digest_value in _binding_digests(self):
            validate_digest(
                digest_value, "jump-host-configure execution binding digest"
            )
        if self.binding_digest != _binding_digest(self):
            raise StatePersistenceError(
                "deploy jump-host-configure execution binding digest conflicts"
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
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployJumpHostConfigureExecutionBinding:
        require_exact_keys(
            value, set(cls.__dataclass_fields__), "jump execution binding"
        )
        integer_fields = {
            "journal_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
            "scope_count",
            "target_count",
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
class DeployJumpHostConfigureExecutionAttempt:
    """One prepared, started, or terminal exact jump-host attempt."""

    attempt_index: int
    step_sequence: int
    stable_id: str
    authorization_scope_digest: str
    authorization_variables_digest: str
    authorization_command_digest: str
    variables_digest: str
    command_digest: str
    source_digest: str
    configuration_authorization_digest: str
    policy_digest: str
    route_digest: str
    config_digest: str
    state: DeployJumpHostConfigureExecutionState
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
    result_schema_version: str = JUMP_HOST_CONFIGURE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.attempt_index < 1
            or self.step_sequence < 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or not isinstance(self.state, DeployJumpHostConfigureExecutionState)
            or self.result_schema_version != JUMP_HOST_CONFIGURE_SCHEMA_VERSION
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy jump-host-configure execution attempt is invalid"
            )
        prepared = parse_timestamp(self.prepared_at)
        started = _optional_timestamp(self.started_at)
        completed = _optional_timestamp(self.completed_at)
        if (
            (started is not None and started < prepared)
            or (completed is not None and started is None)
            or (completed is not None and started is not None and completed < started)
        ):
            raise StatePersistenceError(
                "deploy jump-host-configure attempt timestamps are invalid"
            )
        for digest_value in (
            self.authorization_scope_digest,
            self.authorization_variables_digest,
            self.authorization_command_digest,
            self.variables_digest,
            self.command_digest,
            self.source_digest,
            self.configuration_authorization_digest,
            self.policy_digest,
            self.route_digest,
            self.config_digest,
        ):
            validate_digest(digest_value, "jump-host-configure attempt digest")
        for outcome_digest in (self.result_digest, self.evidence_digest):
            if outcome_digest is not None:
                validate_digest(outcome_digest, "jump-host-configure outcome digest")
        self._validate_state(started, completed)

    def _validate_state(
        self, started: datetime | None, completed: datetime | None
    ) -> None:
        if self.state is DeployJumpHostConfigureExecutionState.PREPARED:
            valid = (
                started is None
                and completed is None
                and not self.authorization_consumed
                and not self.invocation_may_have_occurred
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and not self.manual_recovery_required
            )
        elif self.state is DeployJumpHostConfigureExecutionState.STARTED:
            valid = (
                started is not None
                and completed is None
                and self.authorization_consumed
                and self.invocation_may_have_occurred
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.manual_recovery_required
            )
        else:
            valid = (
                started is not None
                and completed is not None
                and self.authorization_consumed
                and self.invocation_may_have_occurred
                and self.manual_recovery_required
                == (self.state is not DeployJumpHostConfigureExecutionState.SUCCEEDED)
            )
            if self.state in {
                DeployJumpHostConfigureExecutionState.SUCCEEDED,
                DeployJumpHostConfigureExecutionState.FAILED,
                DeployJumpHostConfigureExecutionState.UNREACHABLE,
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
            raise StatePersistenceError(
                "deploy jump-host-configure attempt state conflicts"
            )

    def to_object(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            result[name] = value.value if isinstance(value, StrEnum) else value
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployJumpHostConfigureExecutionAttempt:
        require_exact_keys(
            value, set(cls.__dataclass_fields__), "jump execution attempt"
        )
        try:
            return cls(
                attempt_index=_integer(value["attempt_index"], "attempt index"),
                step_sequence=_integer(value["step_sequence"], "step sequence"),
                stable_id=require_string(value, "stable_id"),
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
                configuration_authorization_digest=require_string(
                    value, "configuration_authorization_digest"
                ),
                policy_digest=require_string(value, "policy_digest"),
                route_digest=require_string(value, "route_digest"),
                config_digest=require_string(value, "config_digest"),
                state=DeployJumpHostConfigureExecutionState(
                    require_string(value, "state")
                ),
                prepared_at=require_string(value, "prepared_at"),
                started_at=_optional_string(value["started_at"], "started_at"),
                completed_at=_optional_string(value["completed_at"], "completed_at"),
                authorization_consumed=_boolean(
                    value["authorization_consumed"], "authorization consumed"
                ),
                invocation_may_have_occurred=_boolean(
                    value["invocation_may_have_occurred"],
                    "invocation may have occurred",
                ),
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
                result_schema_version=require_string(value, "result_schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy jump-host-configure attempt enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployJumpHostConfigureExecution:
    """Generation-guarded serial execution companion."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployJumpHostConfigureExecutionBinding
    state: DeployJumpHostConfigureExecutionState
    authorization_consumed: bool
    invocation_count: int
    completed_target_count: int
    all_targets_completed: bool
    attempts: tuple[DeployJumpHostConfigureExecutionAttempt, ...]
    schema_version: str = ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_SCHEMA_VERSION
            or self.generation < 1
            or not self.attempts
            or len(self.attempts) > self.binding.scope_count
            or tuple(attempt.attempt_index for attempt in self.attempts)
            != tuple(range(1, len(self.attempts) + 1))
            or self.invocation_count
            != sum(attempt.invocation_may_have_occurred for attempt in self.attempts)
            or self.completed_target_count
            != sum(
                attempt.state is DeployJumpHostConfigureExecutionState.SUCCEEDED
                for attempt in self.attempts
            )
            or self.authorization_consumed != (self.invocation_count > 0)
            or self.state is not self.attempts[-1].state
            or self.all_targets_completed
            != (
                self.state is DeployJumpHostConfigureExecutionState.SUCCEEDED
                and self.completed_target_count == self.binding.target_count
            )
        ):
            raise StatePersistenceError(
                "deploy jump-host-configure execution summary conflicts"
            )
        parse_timestamp(self.created_at)
        parse_timestamp(self.updated_at)
        if any(
            attempt.state is not DeployJumpHostConfigureExecutionState.SUCCEEDED
            for attempt in self.attempts[:-1]
        ):
            raise StatePersistenceError(
                "deploy jump-host-configure execution skipped uncertainty"
            )

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
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployJumpHostConfigureExecution:
        require_exact_keys(value, set(cls.__dataclass_fields__), "jump execution")
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                updated_at=require_string(value, "updated_at"),
                binding=DeployJumpHostConfigureExecutionBinding.from_object(
                    _mapping(value["binding"], "execution binding")
                ),
                state=DeployJumpHostConfigureExecutionState(
                    require_string(value, "state")
                ),
                authorization_consumed=_boolean(
                    value["authorization_consumed"], "authorization consumed"
                ),
                invocation_count=_integer(
                    value["invocation_count"], "invocation count"
                ),
                completed_target_count=_integer(
                    value["completed_target_count"], "completed target count"
                ),
                all_targets_completed=_boolean(
                    value["all_targets_completed"], "all targets completed"
                ),
                attempts=tuple(
                    DeployJumpHostConfigureExecutionAttempt.from_object(
                        _mapping(item, "execution attempt")
                    )
                    for item in _array(value["attempts"], "execution attempts")
                ),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy jump-host-configure execution enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployJumpHostConfigureEvidenceEntry:
    """Address-free semantic evidence for one exact target."""

    attempt_index: int
    step_sequence: int
    stable_id: str
    status: JumpHostConfigureStatus
    changed: bool
    applied: bool
    validation_performed: bool
    validation_passed: bool | None
    reload_performed: bool
    reload_passed: bool | None
    restored: bool
    restoration_status: DeployJumpHostConfigureRestorationStatus
    blocker_status: tuple[str, ...]
    policy_digest: str
    route_digest: str
    config_digest: str
    configuration_authorization_digest: str
    result_digest: str
    source_digest: str
    evidence_digest: str
    result_schema_version: str = JUMP_HOST_CONFIGURE_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_ENTRY_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        success = self.status in _SUCCESS_STATUSES
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_ENTRY_SCHEMA_VERSION
            or self.result_schema_version != JUMP_HOST_CONFIGURE_SCHEMA_VERSION
            or self.attempt_index < 1
            or self.step_sequence < 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.changed != (self.status is JumpHostConfigureStatus.CHANGED)
            or self.applied != success
            or self.blocker_status != tuple(sorted(set(self.blocker_status)))
            or not set(self.blocker_status) <= _BLOCKERS
            or not isinstance(
                self.restoration_status, DeployJumpHostConfigureRestorationStatus
            )
            or self.restored
        ):
            raise StatePersistenceError(
                "deploy jump-host-configure semantic evidence is invalid"
            )
        if success:
            valid = (
                not self.blocker_status
                and self.validation_performed
                and self.validation_passed is True
                and self.reload_performed == self.changed
                and self.reload_passed == (True if self.changed else None)
                and self.restoration_status
                is DeployJumpHostConfigureRestorationStatus.NOT_REQUIRED
            )
        else:
            valid = (
                self.status is JumpHostConfigureStatus.FAILED
                and bool(self.blocker_status)
                and self.restoration_status
                is DeployJumpHostConfigureRestorationStatus.NOT_PROVEN
            )
        if not valid:
            raise StatePersistenceError(
                "deploy jump-host-configure semantic outcome conflicts"
            )
        for value in (
            self.policy_digest,
            self.route_digest,
            self.config_digest,
            self.configuration_authorization_digest,
            self.result_digest,
            self.source_digest,
            self.evidence_digest,
        ):
            validate_digest(value, "jump-host-configure evidence digest")
        if self.evidence_digest != _entry_digest(self):
            raise StatePersistenceError(
                "deploy jump-host-configure evidence digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "applied": self.applied,
            "attempt_index": self.attempt_index,
            "blocker_status": list(self.blocker_status),
            "changed": self.changed,
            "config_digest": self.config_digest,
            "configuration_authorization_digest": (
                self.configuration_authorization_digest
            ),
            "evidence_digest": self.evidence_digest,
            "logical_id": self.stable_id,
            "policy_digest": self.policy_digest,
            "reload_passed": self.reload_passed,
            "reload_performed": self.reload_performed,
            "restoration_status": self.restoration_status.value,
            "restored": self.restored,
            "result_digest": self.result_digest,
            "result_schema_version": self.result_schema_version,
            "route_digest": self.route_digest,
            "schema_version": self.schema_version,
            "source_digest": self.source_digest,
            "status": self.status.value,
            "step_sequence": self.step_sequence,
            "validation_passed": self.validation_passed,
            "validation_performed": self.validation_performed,
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployJumpHostConfigureEvidenceEntry:
        expected = set(cls.__dataclass_fields__)
        expected.remove("stable_id")
        expected.add("logical_id")
        require_exact_keys(value, expected, "jump evidence entry")
        try:
            return cls(
                attempt_index=_integer(value["attempt_index"], "attempt index"),
                step_sequence=_integer(value["step_sequence"], "step sequence"),
                stable_id=require_string(value, "logical_id"),
                status=JumpHostConfigureStatus(require_string(value, "status")),
                changed=_boolean(value["changed"], "changed"),
                applied=_boolean(value["applied"], "applied"),
                validation_performed=_boolean(
                    value["validation_performed"], "validation performed"
                ),
                validation_passed=_optional_boolean(
                    value["validation_passed"], "validation passed"
                ),
                reload_performed=_boolean(
                    value["reload_performed"], "reload performed"
                ),
                reload_passed=_optional_boolean(
                    value["reload_passed"], "reload passed"
                ),
                restored=_boolean(value["restored"], "restored"),
                restoration_status=DeployJumpHostConfigureRestorationStatus(
                    require_string(value, "restoration_status")
                ),
                blocker_status=_string_tuple(value["blocker_status"], "blocker status"),
                policy_digest=require_string(value, "policy_digest"),
                route_digest=require_string(value, "route_digest"),
                config_digest=require_string(value, "config_digest"),
                configuration_authorization_digest=require_string(
                    value, "configuration_authorization_digest"
                ),
                result_digest=require_string(value, "result_digest"),
                source_digest=require_string(value, "source_digest"),
                evidence_digest=require_string(value, "evidence_digest"),
                result_schema_version=require_string(value, "result_schema_version"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy jump-host-configure evidence enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployJumpHostConfigureEvidence:
    """Immutable-prefix semantic evidence companion."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployJumpHostConfigureExecutionBinding
    entries: tuple[DeployJumpHostConfigureEvidenceEntry, ...]
    schema_version: str = ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_SCHEMA_VERSION
            or self.generation != len(self.entries)
            or not 1 <= len(self.entries) <= self.binding.target_count
            or tuple(entry.attempt_index for entry in self.entries)
            != tuple(range(1, len(self.entries) + 1))
        ):
            raise StatePersistenceError(
                "deploy jump-host-configure evidence prefix conflicts"
            )
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
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployJumpHostConfigureEvidence:
        require_exact_keys(value, set(cls.__dataclass_fields__), "jump evidence")
        return cls(
            generation=_integer(value["generation"], "generation"),
            created_at=require_string(value, "created_at"),
            updated_at=require_string(value, "updated_at"),
            binding=DeployJumpHostConfigureExecutionBinding.from_object(
                _mapping(value["binding"], "evidence binding")
            ),
            entries=tuple(
                DeployJumpHostConfigureEvidenceEntry.from_object(
                    _mapping(item, "evidence entry")
                )
                for item in _array(value["entries"], "evidence entries")
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredDeployJumpHostConfigureExecution:
    record: DeployJumpHostConfigureExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployJumpHostConfigureEvidence:
    record: DeployJumpHostConfigureEvidence
    artifact_digest: str


class DeployJumpHostConfigureExecutionStore:
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
        self._path = deploy_jump_host_configure_execution_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployJumpHostConfigureExecution:
        value, digest = self._file.read()
        record = DeployJumpHostConfigureExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy jump-host-configure execution identity conflicts"
            )
        return StoredDeployJumpHostConfigureExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployJumpHostConfigureExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployJumpHostConfigureExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployJumpHostConfigureExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy jump-host-configure execution operation conflicts"
            )
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
                raise StateConflictError(
                    "deploy jump-host-configure execution changed concurrently"
                )
            _validate_execution_transition(current.record, record)
        elif expected_generation != 0 or expected_digest is not None:
            raise StateConflictError(
                "deploy jump-host-configure execution prefix is missing"
            )
        elif record.generation != 1:
            raise StatePersistenceError(
                "deploy jump-host-configure initial execution is invalid"
            )
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployJumpHostConfigureExecution(record, digest)


class DeployJumpHostConfigureEvidenceStore:
    """Generation-guarded owner-only semantic evidence store."""

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
        self._path = deploy_jump_host_configure_evidence_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployJumpHostConfigureEvidence:
        value, digest = self._file.read()
        record = DeployJumpHostConfigureEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy jump-host-configure evidence identity conflicts"
            )
        return StoredDeployJumpHostConfigureEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployJumpHostConfigureEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def append_locked(
        self,
        record: DeployJumpHostConfigureEvidence,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployJumpHostConfigureEvidence:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy jump-host-configure evidence operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if (
                current.record.generation != expected_generation
                or current.artifact_digest != expected_digest
                or record.generation != current.record.generation + 1
                or record.created_at != current.record.created_at
                or record.binding != current.record.binding
                or record.entries[:-1] != current.record.entries
            ):
                raise StateConflictError(
                    "deploy jump-host-configure evidence transition conflicts"
                )
        elif expected_generation != 0 or expected_digest is not None:
            raise StateConflictError(
                "deploy jump-host-configure evidence prefix is missing"
            )
        elif record.generation != 1 or len(record.entries) != 1:
            raise StatePersistenceError(
                "deploy jump-host-configure initial evidence is invalid"
            )
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployJumpHostConfigureEvidence(record, digest)


@dataclass(frozen=True, slots=True)
class DeployJumpHostConfigureExecutionReport:
    """Strict redacted successful execution projection."""

    operation_id: uuid.UUID
    execution_artifact_state: DeployJumpHostConfigureArtifactState
    evidence_artifact_state: DeployJumpHostConfigureArtifactState
    execution_state: DeployJumpHostConfigureExecutionState
    execution_artifact_digest: str
    evidence_artifact_digest: str
    binding_digest: str
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_consumed: bool
    invocation_count: int
    target_count: int
    target_set_digest: str
    changed_count: int
    reload_count: int
    restored_count: int
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    journal_status: JournalStatus
    journal_phase: OperationPhase
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_SCHEMA_VERSION
    )
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_REPORT_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
            or self.execution_state
            is not DeployJumpHostConfigureExecutionState.SUCCEEDED
            or not self.authorization_consumed
            or self.manual_recovery_required
            or self.automatic_retry_allowed
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.invocation_count != self.target_count
            or self.target_count < 1
            or not 0 <= self.changed_count <= self.target_count
            or not 0 <= self.reload_count <= self.target_count
            or self.reload_count != self.changed_count
            or self.restored_count != 0
        ):
            raise StatePersistenceError(
                "deploy jump-host-configure execution report is invalid"
            )
        for value in (
            self.execution_artifact_digest,
            self.evidence_artifact_digest,
            self.binding_digest,
            self.authorization_artifact_digest,
            self.authorization_digest,
            self.target_set_digest,
        ):
            validate_digest(value, "jump-host-configure report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "artifacts": {
                "evidence_digest": self.evidence_artifact_digest,
                "evidence_state": self.evidence_artifact_state.value,
                "execution_digest": self.execution_artifact_digest,
                "execution_state": self.execution_artifact_state.value,
            },
            "authorization": {
                "artifact_digest": self.authorization_artifact_digest,
                "consumed": self.authorization_consumed,
                "digest": self.authorization_digest,
                "schema_version": self.authorization_schema_version,
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
                "changed_count": self.changed_count,
                "reload_count": self.reload_count,
                "restored_count": self.restored_count,
            },
            "schema_version": self.schema_version,
            "schemas": {
                "evidence": self.evidence_schema_version,
                "execution": self.execution_schema_version,
            },
            "scope": {
                "target_count": self.target_count,
                "target_set_digest": self.target_set_digest,
            },
        }


@dataclass(frozen=True, slots=True)
class _ExecutionScope:
    attempt_index: int
    authorization: DeployJumpHostConfigureAuthorizationScope
    authorization_scope_digest: str
    stable_id: str
    base_os: BaseOsEvidence
    configuration_authorization: JumpHostConfigurationAuthorization
    payload: Mapping[str, object]
    variables: Mapping[str, object]
    variables_digest: str
    command_digest: str
    source_digest: str
    policy_digest: str
    route_digest: str
    config_digest: str


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    post_reboot: _PostRebootContext
    reconciliation: StoredDeployPostRebootReconciliation
    authorization: StoredDeployJumpHostConfigureAuthorization
    binding: DeployJumpHostConfigureExecutionBinding
    scopes: tuple[_ExecutionScope, ...]
    metadata: ClusterMetadata
    observed: StoredObservedState
    inventory: StoredInventoryRecord
    trust: StoredTrustRecord
    readiness: ReadinessReport


def execute_deploy_jump_host_configure(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployJumpHostConfigureExecutionReport:
    """Execute only exact immutable authorized jump-host configuration scopes."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _validate_toolchain_dependency(toolchain)
    executable_identity_digest = _executable_identity_digest(executables)
    toolchain_evidence_digest = _toolchain_evidence_digest(
        toolchain, executable_identity_digest
    )
    _refuse_ambiguous_artifacts(paths, operation_id)
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
    execution_store = DeployJumpHostConfigureExecutionStore(paths, operation_id)
    evidence_store = DeployJumpHostConfigureEvidenceStore(paths, operation_id)
    for path in (execution_store.path, evidence_store.path):
        validate_state_file(path, allow_missing=True)
    execution = (
        execution_store.read_locked(
            lock,
            expected_cluster_uuid=context.metadata.cluster_uuid,
            expected_cluster_name=context.metadata.cluster_name,
        )
        if execution_store.path.exists()
        else None
    )
    evidence = (
        evidence_store.read_locked(
            lock,
            expected_cluster_uuid=context.metadata.cluster_uuid,
            expected_cluster_name=context.metadata.cluster_name,
        )
        if evidence_store.path.exists()
        else None
    )
    _validate_prefix(context, execution, evidence)
    if execution is not None and execution.record.all_targets_completed:
        if evidence is None:
            raise StateConflictError(
                "completed deploy jump-host-configure evidence is unavailable"
            )
        return _build_report(context, execution, evidence, reused=True)
    if execution is not None and execution.record.state not in {
        DeployJumpHostConfigureExecutionState.PREPARED,
        DeployJumpHostConfigureExecutionState.SUCCEEDED,
    }:
        raise StateConflictError(
            "deploy jump-host-configure execution requires manual recovery "
            "and cannot retry"
        )

    service = AnsibleService(builder, runner)
    discovered = service.version(lock)
    if discovered != toolchain:
        raise StateConflictError("deploy jump-host-configure toolchain drifted")
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
    if (
        execution is None
        or execution.record.state is DeployJumpHostConfigureExecutionState.SUCCEEDED
    ):
        scope = context.scopes[len(execution.record.attempts) if execution else 0]
        try:
            execution = _persist_prepared(
                context, execution_store, execution, scope, lock=lock
            )
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy jump-host-configure prepared intent persistence failed "
                "before invocation"
            ) from error
    assert execution is not None

    while True:
        if execution.record.state is DeployJumpHostConfigureExecutionState.PREPARED:
            before = _load_execution_context(
                paths,
                operation_id,
                lock=lock,
                builder=builder,
                toolchain=toolchain,
                executable_identity_digest=executable_identity_digest,
                toolchain_evidence_digest=toolchain_evidence_digest,
            )
            if before.binding != context.binding:
                raise StateConflictError(
                    "deploy jump-host-configure state drifted before start"
                )
            _validate_prefix(before, execution, evidence)
            scope = before.scopes[len(execution.record.attempts) - 1]
            try:
                execution = _persist_started(execution_store, execution, lock=lock)
            except StatePersistenceError as error:
                raise StatePersistenceError(
                    "deploy jump-host-configure authorization consumption failed "
                    "before invocation"
                ) from error
            try:
                raw_result, observed_command_digest = service.execute_operation_step(
                    lock,
                    before.metadata,
                    before.inventory,
                    _PLAYBOOK,
                    step_sequence=scope.authorization.sequence,
                    limit=(scope.stable_id,),
                    variables=dict(scope.variables),
                    readiness=before.readiness,
                    tags=(_PLAYBOOK,),
                    check=False,
                    diff=False,
                    verbosity=0,
                )
                if observed_command_digest != scope.command_digest:
                    raise AnsibleResultError(
                        "deploy jump-host-configure command result identity conflicts"
                    )
                try:
                    parsed = parse_jump_host_configure_execution(
                        raw_result.stdout,
                        expected_payload=dict(scope.payload),
                        exit_code=raw_result.exit_code,
                    )
                except AnsibleError as error:
                    raise AnsibleResultError(
                        "deploy jump-host-configure strict result is malformed"
                    ) from error
                result = replace(
                    raw_result,
                    stdout="",
                    stderr="",
                    jump_host_configure=parsed,
                )
            except KeyboardInterrupt:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    DeployJumpHostConfigureExecutionState.INTERRUPTED,
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy jump-host-configure execution was interrupted; "
                    "manual recovery required"
                ) from None
            except AnsibleError as error:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    _failure_state(error),
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy jump-host-configure execution is uncertain; "
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
            except (StateConflictError, StatePersistenceError) as error:
                raise StateConflictError(
                    "deploy jump-host-configure state changed after invocation; "
                    "manual recovery required"
                ) from error
            if after.binding != context.binding:
                raise StateConflictError(
                    "deploy jump-host-configure state changed after invocation; "
                    "manual recovery required"
                )
            try:
                entry = _semantic_entry(scope, result)
            except (AnsibleError, StatePersistenceError) as error:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    DeployJumpHostConfigureExecutionState.MALFORMED_RESULT,
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy jump-host-configure result is malformed; "
                    "manual recovery required"
                ) from error
            try:
                evidence = _persist_evidence(
                    context, evidence_store, evidence, entry, lock=lock
                )
            except StatePersistenceError as error:
                raise StatePersistenceError(
                    "deploy jump-host-configure evidence persistence failed; "
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
                    "deploy jump-host-configure terminal persistence failed; "
                    "manual recovery required"
                ) from error
            if terminal_state is not DeployJumpHostConfigureExecutionState.SUCCEEDED:
                raise AnsibleError(
                    "deploy jump-host-configure execution failed; "
                    "manual recovery required"
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
                "deploy jump-host-configure next prepared intent failed "
                "before invocation"
            ) from error
    if evidence is None:
        raise StatePersistenceError(
            "deploy jump-host-configure completion evidence is missing"
        )
    _validate_prefix(context, execution, evidence)
    return _build_report(context, execution, evidence, reused=False)


def deploy_jump_host_configure_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy jump-host-configure execution path is not canonical"
        )
    return path


def deploy_jump_host_configure_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy jump-host-configure evidence path is not canonical"
        )
    return path


def deploy_jump_host_configure_execution_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(name, DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_FILENAME_SUFFIX)


def deploy_jump_host_configure_evidence_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(name, DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_FILENAME_SUFFIX)


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
    post = _load_post_reboot_context(paths, operation_id, lock=lock)
    planning = post.base.host.loaded.planning
    loaded = post.base.host.loaded
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
            "deploy jump-host-configure readiness, journal, or toolchain conflicts"
        )
    readiness = _reconstructed_readiness(planning.base)
    if readiness_binding_digest(readiness) != readiness_record.readiness_digest:
        raise StateConflictError("deploy jump-host-configure readiness is stale")
    readiness.require_ready(OperationClassification.MUTATING)
    TrustStore(paths).validate_runtime(planning.base.trust, deploy.inventory)

    reconciliation_store = DeployPostRebootReconciliationStore(paths, operation_id)
    authorization_store = DeployJumpHostConfigureAuthorizationStore(paths, operation_id)
    for path, label in (
        (reconciliation_store.path, "post-reboot reconciliation"),
        (authorization_store.path, "immutable authorization"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"deploy jump-host-configure execution requires {label}"
            )
    reconciliation = reconciliation_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_reconciliation = _build_post_reboot_record(
        post,
        steps=_build_post_reboot_steps(post),
        created_at=reconciliation.record.created_at,
    )
    if reconciliation.record != expected_reconciliation:
        raise StateConflictError(
            "deploy jump-host-configure post-reboot reconciliation drifted"
        )
    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    authorization_scopes = _derive_authorization_scopes(post, reconciliation)
    expected_authorization = _build_authorization(
        post,
        reconciliation,
        scopes=authorization_scopes,
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
            "deploy jump-host-configure authorization is stale or consumed"
        )
    scopes = _derive_execution_scopes(
        post,
        authorization,
        readiness=readiness,
        builder=builder,
    )
    stable_ids = tuple(scope.stable_id for scope in scopes)
    scope_values = [
        {
            "attempt_index": scope.attempt_index,
            "authorization_command_digest": scope.authorization.command_digest,
            "authorization_scope_digest": scope.authorization_scope_digest,
            "authorization_variables_digest": scope.authorization.variables_digest,
            "command_digest": scope.command_digest,
            "config_digest": scope.config_digest,
            "configuration_authorization_digest": (
                scope.configuration_authorization.authorization_digest
            ),
            "policy_digest": scope.policy_digest,
            "route_digest": scope.route_digest,
            "source_digest": scope.source_digest,
            "stable_id_digest": _digest_object(scope.stable_id),
            "step_sequence": scope.authorization.sequence,
            "variables_digest": scope.variables_digest,
        }
        for scope in scopes
    ]
    record = authorization.record
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
        "authorization_digest": record.authorization_digest,
        "authorization_scope_digest": record.authorization_scope_digest,
        "authorization_proof_digest": record.proof.proof_digest,
        "configuration_intent_digest": record.configuration_intent_digest,
        "post_reboot_reconciliation_artifact_digest": reconciliation.artifact_digest,
        "post_reboot_reconciliation_record_digest": reconciliation.record.record_digest,
        "post_reboot_effective_plan_digest": (
            reconciliation.record.effective_plan_digest
        ),
        "connectivity_evidence_digest": record.connectivity_evidence_digest,
        "observation_generation": deploy.observation.record.generation,
        "observation_artifact_digest": deploy.observation.digest,
        "observation_manifest_digest": deploy.observation.record.manifest_digest,
        "inventory_generation": deploy.inventory.record.generation,
        "inventory_artifact_digest": deploy.inventory.digest,
        "inventory_digest": deploy.inventory.record.inventory_digest,
        "route_digest": record.route_digest,
        "trust_generation": planning.base.trust.record.generation,
        "trust_artifact_digest": planning.base.trust.digest,
        "trust_entries_digest": planning.base.trust.record.entries_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": readiness_record.record_digest,
        "catalog_digest": loaded.catalog_digest,
        "source_version": loaded.source.version,
        "source_digest": loaded.source.digest,
        "playbook_source_digest": _playbook_source_digest(loaded.source, _PLAYBOOK),
        "toolchain_version": str(toolchain.core),
        "executable_identity_digest": executable_identity_digest,
        "toolchain_evidence_digest": toolchain_evidence_digest,
        "scope_count": len(scopes),
        "target_count": len(stable_ids),
        "target_set_digest": _digest_object(sorted(stable_ids)),
        "execution_scope_digest": _digest_object(scope_values),
        "policy_digest": _policy_digest(),
        "binding_digest": "",
    }
    values["binding_digest"] = _binding_digest_from_values(values)
    binding = DeployJumpHostConfigureExecutionBinding(**values)  # type: ignore[arg-type]
    return _ExecutionContext(
        post,
        reconciliation,
        authorization,
        binding,
        scopes,
        metadata,
        deploy.observation,
        deploy.inventory,
        planning.base.trust,
        readiness,
    )


def _derive_execution_scopes(
    post: _PostRebootContext,
    authorization: StoredDeployJumpHostConfigureAuthorization,
    *,
    readiness: ReadinessReport,
    builder: AnsibleCommandBuilder,
) -> tuple[_ExecutionScope, ...]:
    planning = post.base.host.loaded.planning
    loaded = post.base.host.loaded
    deploy = planning.base.deploy
    source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
    base_hosts = {
        host.logical_id: host
        for entry in post.base.evidence.record.entries
        for host in entry.hosts
    }
    scopes: list[_ExecutionScope] = []
    for index, authorized in enumerate(authorization.record.scopes, start=1):
        if (
            authorized.mapping_sequence != _MAPPING_SEQUENCE
            or authorized.playbook != _PLAYBOOK
            or authorized.classification is not OperationClassification.MUTATING
            or authorized.target_role != "jump-host"
            or len(authorized.target_ids) != 1
            or authorized.source_digest != source_digest
        ):
            raise StateConflictError(
                "deploy jump-host-configure authorized scope drifted"
            )
        stable_id = authorized.target_ids[0]
        persisted = base_hosts.get(stable_id)
        if (
            persisted is None
            or not persisted.applied
            or persisted.os_family != "Ubuntu"
            or persisted.os_version != "24.04"
            or persisted.prerequisite_policy_status != "satisfied"
            or persisted.timesync_service_status != "enabled-active"
        ):
            raise StateConflictError(
                "deploy jump-host-configure base-OS evidence is not ready"
            )
        # Post-reboot reconciliation proves any prior reboot-required result was
        # completed and cleared. Project only that superseded fact into the
        # existing narrow role-level authorization contract.
        current_status = (
            BaseOsStatus.CHANGED if persisted.changed else BaseOsStatus.NO_CHANGE
        )
        base_os = BaseOsEvidence(
            current_status,
            (
                BaseOsHostEvidence(
                    stable_id,
                    current_status,
                    persisted.changed,
                    False,
                    "applied" if persisted.changed else "already-current",
                ),
            ),
        )
        config_authorization = authorize_jump_host_configuration(
            deploy.metadata.record,
            deploy.observation,
            deploy.inventory,
            planning.base.trust,
            readiness,
            base_os,
            operation_id=str(authorization.record.operation_id),
            target_logical_id=stable_id,
        )
        payload = build_jump_host_configure_payload(
            deploy.metadata.record,
            deploy.observation,
            deploy.inventory,
            planning.base.trust,
            readiness,
            base_os,
            config_authorization,
        )
        route_digest = _payload_digest(payload, "allowed_route_digest")
        config_digest = _payload_digest(payload, "config_digest")
        variables = {"deploy_scylla_vms_jump_host_configure": payload}
        _, validated, variables_digest, command_digest = (
            builder.validate_operation_step(
                _PLAYBOOK,
                step_sequence=authorized.sequence,
                limit=(stable_id,),
                variables=variables,
                tags=(_PLAYBOOK,),
                check=False,
                diff=False,
                verbosity=0,
            )
        )
        scopes.append(
            _ExecutionScope(
                index,
                authorized,
                _digest_object(authorized.to_object()),
                stable_id,
                base_os,
                config_authorization,
                payload,
                validated,
                variables_digest,
                command_digest,
                source_digest,
                _policy_digest(),
                route_digest,
                config_digest,
            )
        )
    if (
        not scopes
        or len(scopes) != authorization.record.playbook_instance_count
        or len(scopes) != authorization.record.stable_id_count
        or tuple(scope.authorization.sequence for scope in scopes)
        != tuple(sorted(scope.authorization.sequence for scope in scopes))
        or tuple(scope.stable_id for scope in scopes)
        != tuple(sorted(scope.stable_id for scope in scopes))
    ):
        raise StateConflictError(
            "deploy jump-host-configure execution scope is unavailable"
        )
    return tuple(scopes)


def _validate_prefix(
    context: _ExecutionContext,
    execution: StoredDeployJumpHostConfigureExecution | None,
    evidence: StoredDeployJumpHostConfigureEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "deploy jump-host-configure evidence exists without intent"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError(
            "deploy jump-host-configure execution provenance is stale"
        )
    if evidence is not None and evidence.record.binding != context.binding:
        raise StateConflictError(
            "deploy jump-host-configure evidence provenance is stale"
        )
    for index, attempt in enumerate(execution.record.attempts):
        if index >= len(context.scopes):
            raise StateConflictError(
                "deploy jump-host-configure execution has extra attempts"
            )
        scope = context.scopes[index]
        if (
            attempt.attempt_index != scope.attempt_index
            or attempt.step_sequence != scope.authorization.sequence
            or attempt.stable_id != scope.stable_id
            or attempt.authorization_scope_digest != scope.authorization_scope_digest
            or attempt.authorization_variables_digest
            != scope.authorization.variables_digest
            or attempt.authorization_command_digest
            != scope.authorization.command_digest
            or attempt.variables_digest != scope.variables_digest
            or attempt.command_digest != scope.command_digest
            or attempt.source_digest != scope.source_digest
            or attempt.configuration_authorization_digest
            != scope.configuration_authorization.authorization_digest
            or attempt.policy_digest != scope.policy_digest
            or attempt.route_digest != scope.route_digest
            or attempt.config_digest != scope.config_digest
        ):
            raise StateConflictError(
                "deploy jump-host-configure execution scope conflicts"
            )
    entries = evidence.record.entries if evidence is not None else ()
    if len(entries) > len(execution.record.attempts):
        raise StateConflictError("deploy jump-host-configure evidence prefix conflicts")
    for index, entry in enumerate(entries):
        attempt = execution.record.attempts[index]
        scope = context.scopes[index]
        if (
            attempt.state is DeployJumpHostConfigureExecutionState.PREPARED
            or entry.attempt_index != scope.attempt_index
            or entry.step_sequence != scope.authorization.sequence
            or entry.stable_id != scope.stable_id
            or entry.policy_digest != scope.policy_digest
            or entry.route_digest != scope.route_digest
            or entry.config_digest != scope.config_digest
            or entry.configuration_authorization_digest
            != scope.configuration_authorization.authorization_digest
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
                "deploy jump-host-configure semantic evidence conflicts"
            )
    required = sum(
        attempt.state
        in {
            DeployJumpHostConfigureExecutionState.SUCCEEDED,
            DeployJumpHostConfigureExecutionState.FAILED,
            DeployJumpHostConfigureExecutionState.UNREACHABLE,
        }
        for attempt in execution.record.attempts
    )
    started_extra = (
        1
        if execution.record.state is DeployJumpHostConfigureExecutionState.STARTED
        and len(entries) == required + 1
        else 0
    )
    if len(entries) != required + started_extra:
        raise StateConflictError(
            "deploy jump-host-configure execution/evidence prefixes conflict"
        )
    if any(entry.status not in _SUCCESS_STATUSES for entry in entries[:-1]):
        raise StateConflictError(
            "deploy jump-host-configure execution continued after failure"
        )


def _persist_prepared(
    context: _ExecutionContext,
    store: DeployJumpHostConfigureExecutionStore,
    current: StoredDeployJumpHostConfigureExecution | None,
    scope: _ExecutionScope,
    *,
    lock: ClusterLock,
) -> StoredDeployJumpHostConfigureExecution:
    now = _timestamp()
    attempt = DeployJumpHostConfigureExecutionAttempt(
        attempt_index=scope.attempt_index,
        step_sequence=scope.authorization.sequence,
        stable_id=scope.stable_id,
        authorization_scope_digest=scope.authorization_scope_digest,
        authorization_variables_digest=scope.authorization.variables_digest,
        authorization_command_digest=scope.authorization.command_digest,
        variables_digest=scope.variables_digest,
        command_digest=scope.command_digest,
        source_digest=scope.source_digest,
        configuration_authorization_digest=(
            scope.configuration_authorization.authorization_digest
        ),
        policy_digest=scope.policy_digest,
        route_digest=scope.route_digest,
        config_digest=scope.config_digest,
        state=DeployJumpHostConfigureExecutionState.PREPARED,
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
        record = DeployJumpHostConfigureExecution(
            generation=1,
            created_at=now,
            updated_at=now,
            binding=context.binding,
            state=DeployJumpHostConfigureExecutionState.PREPARED,
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
    if current.record.state is not DeployJumpHostConfigureExecutionState.SUCCEEDED:
        raise StateConflictError(
            "deploy jump-host-configure cannot prepare after uncertain state"
        )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=DeployJumpHostConfigureExecutionState.PREPARED,
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
    store: DeployJumpHostConfigureExecutionStore,
    current: StoredDeployJumpHostConfigureExecution,
    *,
    lock: ClusterLock,
) -> StoredDeployJumpHostConfigureExecution:
    if current.record.state is not DeployJumpHostConfigureExecutionState.PREPARED:
        raise StateConflictError(
            "deploy jump-host-configure start requires prepared intent"
        )
    now = _timestamp()
    attempt = replace(
        current.record.attempts[-1],
        state=DeployJumpHostConfigureExecutionState.STARTED,
        started_at=now,
        authorization_consumed=True,
        invocation_may_have_occurred=True,
        manual_recovery_required=True,
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=DeployJumpHostConfigureExecutionState.STARTED,
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
    store: DeployJumpHostConfigureExecutionStore,
    current: StoredDeployJumpHostConfigureExecution,
    state: DeployJumpHostConfigureExecutionState,
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
            "deploy jump-host-configure uncertain outcome persistence failed; "
            "manual recovery required"
        ) from error


def _persist_evidence(
    context: _ExecutionContext,
    store: DeployJumpHostConfigureEvidenceStore,
    current: StoredDeployJumpHostConfigureEvidence | None,
    entry: DeployJumpHostConfigureEvidenceEntry,
    *,
    lock: ClusterLock,
) -> StoredDeployJumpHostConfigureEvidence:
    now = _timestamp()
    if current is None:
        record = DeployJumpHostConfigureEvidence(
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
    store: DeployJumpHostConfigureExecutionStore,
    current: StoredDeployJumpHostConfigureExecution,
    *,
    state: DeployJumpHostConfigureExecutionState,
    exit_code: int,
    result_digest: str,
    evidence_digest: str,
    lock: ClusterLock,
) -> StoredDeployJumpHostConfigureExecution:
    now = _timestamp()
    attempt = replace(
        current.record.attempts[-1],
        state=state,
        completed_at=now,
        exit_code=exit_code,
        result_digest=result_digest,
        evidence_digest=evidence_digest,
        manual_recovery_required=(
            state is not DeployJumpHostConfigureExecutionState.SUCCEEDED
        ),
    )
    completed = current.record.completed_target_count + int(
        state is DeployJumpHostConfigureExecutionState.SUCCEEDED
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=state,
        completed_target_count=completed,
        all_targets_completed=(
            state is DeployJumpHostConfigureExecutionState.SUCCEEDED
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
    scope: _ExecutionScope,
    result: AnsibleExecutionResult,
) -> DeployJumpHostConfigureEvidenceEntry:
    evidence = result.jump_host_configure
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.MUTATING
        or result.check_mode
        or result.stdout
        or result.stderr
        or evidence is None
        or evidence.logical_id != scope.stable_id
        or evidence.config_digest != scope.config_digest
        or evidence.allowed_route_digest != scope.route_digest
        or tuple(name for name, _value in evidence.provenance_digests)
        != ("base_os_digest", "inventory_digest", "observation_digest", "trust_digest")
    ):
        raise AnsibleResultError("deploy jump-host-configure result identity conflicts")
    result_digest = _result_digest(evidence)
    success = evidence.status in _SUCCESS_STATUSES
    values: dict[str, object] = {
        "attempt_index": scope.attempt_index,
        "step_sequence": scope.authorization.sequence,
        "stable_id": evidence.logical_id,
        "status": evidence.status,
        "changed": evidence.status is JumpHostConfigureStatus.CHANGED,
        "applied": success,
        "validation_performed": evidence.validation_performed,
        "validation_passed": evidence.validation_passed,
        "reload_performed": evidence.reload_performed,
        "reload_passed": evidence.reload_passed,
        # The role restores internally on its bounded post-write validation
        # failure, but its v1 public result does not prove that branch. Never
        # promote implementation knowledge into retry authorization.
        "restored": False,
        "restoration_status": (
            DeployJumpHostConfigureRestorationStatus.NOT_REQUIRED
            if success
            else DeployJumpHostConfigureRestorationStatus.NOT_PROVEN
        ),
        "blocker_status": evidence.blockers,
        "policy_digest": scope.policy_digest,
        "route_digest": scope.route_digest,
        "config_digest": scope.config_digest,
        "configuration_authorization_digest": (
            scope.configuration_authorization.authorization_digest
        ),
        "result_digest": result_digest,
        "source_digest": scope.source_digest,
        "evidence_digest": "",
    }
    values["evidence_digest"] = _entry_digest_from_values(values)
    return DeployJumpHostConfigureEvidenceEntry(**values)  # type: ignore[arg-type]


def _terminal_state(
    entry: DeployJumpHostConfigureEvidenceEntry, exit_code: int
) -> DeployJumpHostConfigureExecutionState:
    if exit_code == 0 and entry.status in _SUCCESS_STATUSES:
        return DeployJumpHostConfigureExecutionState.SUCCEEDED
    if exit_code == 4:
        return DeployJumpHostConfigureExecutionState.UNREACHABLE
    return DeployJumpHostConfigureExecutionState.FAILED


def _build_report(
    context: _ExecutionContext,
    execution: StoredDeployJumpHostConfigureExecution,
    evidence: StoredDeployJumpHostConfigureEvidence,
    *,
    reused: bool,
) -> DeployJumpHostConfigureExecutionReport:
    entries = evidence.record.entries
    if (
        not execution.record.all_targets_completed
        or execution.record.state is not DeployJumpHostConfigureExecutionState.SUCCEEDED
        or len(entries) != context.binding.target_count
        or any(entry.status not in _SUCCESS_STATUSES for entry in entries)
    ):
        raise StateConflictError("deploy jump-host-configure execution is not complete")
    return DeployJumpHostConfigureExecutionReport(
        operation_id=context.binding.operation_id,
        execution_artifact_state=(
            DeployJumpHostConfigureArtifactState.REUSED
            if reused
            else DeployJumpHostConfigureArtifactState.UPDATED
            if execution.record.generation > 3
            else DeployJumpHostConfigureArtifactState.CREATED
        ),
        evidence_artifact_state=(
            DeployJumpHostConfigureArtifactState.REUSED
            if reused
            else DeployJumpHostConfigureArtifactState.UPDATED
            if evidence.record.generation > 1
            else DeployJumpHostConfigureArtifactState.CREATED
        ),
        execution_state=execution.record.state,
        execution_artifact_digest=execution.artifact_digest,
        evidence_artifact_digest=evidence.artifact_digest,
        binding_digest=context.binding.binding_digest,
        authorization_artifact_digest=context.authorization.artifact_digest,
        authorization_digest=context.authorization.record.authorization_digest,
        authorization_consumed=execution.record.authorization_consumed,
        invocation_count=execution.record.invocation_count,
        target_count=context.binding.target_count,
        target_set_digest=context.binding.target_set_digest,
        changed_count=sum(entry.changed for entry in entries),
        reload_count=sum(entry.reload_performed for entry in entries),
        restored_count=sum(entry.restored for entry in entries),
        manual_recovery_required=False,
        automatic_retry_allowed=False,
        journal_status=context.binding.journal_status,
        journal_phase=context.binding.journal_phase,
    )


def _validate_execution_transition(
    current: DeployJumpHostConfigureExecution,
    replacement: DeployJumpHostConfigureExecution,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or current.all_targets_completed
        or current.state
        not in {
            DeployJumpHostConfigureExecutionState.PREPARED,
            DeployJumpHostConfigureExecutionState.STARTED,
            DeployJumpHostConfigureExecutionState.SUCCEEDED,
        }
    ):
        raise StatePersistenceError(
            "deploy jump-host-configure execution transition is invalid"
        )
    if current.state is DeployJumpHostConfigureExecutionState.PREPARED:
        valid = (
            len(replacement.attempts) == len(current.attempts)
            and replacement.attempts[:-1] == current.attempts[:-1]
            and replacement.attempts[-1].state
            is DeployJumpHostConfigureExecutionState.STARTED
        )
    elif current.state is DeployJumpHostConfigureExecutionState.STARTED:
        valid = (
            len(replacement.attempts) == len(current.attempts)
            and replacement.attempts[:-1] == current.attempts[:-1]
            and replacement.attempts[-1].state
            not in {
                DeployJumpHostConfigureExecutionState.PREPARED,
                DeployJumpHostConfigureExecutionState.STARTED,
            }
        )
    else:
        valid = (
            len(current.attempts) < current.binding.scope_count
            and replacement.attempts[:-1] == current.attempts
            and replacement.attempts[-1].state
            is DeployJumpHostConfigureExecutionState.PREPARED
        )
    if not valid:
        raise StatePersistenceError(
            "deploy jump-host-configure execution transition conflicts"
        )


def _result_digest(evidence: JumpHostConfigureEvidence) -> str:
    return _digest_object(
        {
            "allowed_route_digest": evidence.allowed_route_digest,
            "blockers": list(evidence.blockers),
            "config_digest": evidence.config_digest,
            "host_key_digest": evidence.host_key_digest,
            "logical_id": evidence.logical_id,
            "provenance_digests": dict(evidence.provenance_digests),
            "reload_passed": evidence.reload_passed,
            "reload_performed": evidence.reload_performed,
            "schema_version": evidence.schema_version,
            "status": evidence.status.value,
            "validation_passed": evidence.validation_passed,
            "validation_performed": evidence.validation_performed,
        }
    )


def _policy_digest() -> str:
    return _digest_object(
        {
            "authentication": "public-key-only",
            "forwarding": "local-permit-open-only",
            "host_key_checking": "required",
            "reload": "ubuntu-ssh-after-validated-change",
            "root_login": "disabled",
            "validation": "host-key-and-sshd",
        }
    )


def _payload_digest(payload: Mapping[str, object], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str):
        raise StateConflictError(
            "deploy jump-host-configure payload digest is unavailable"
        )
    validate_digest(value, f"jump-host-configure {name}")
    return value


def _failure_state(error: AnsibleError) -> DeployJumpHostConfigureExecutionState:
    if isinstance(error, AnsibleResultError):
        return DeployJumpHostConfigureExecutionState.MALFORMED_RESULT
    cause = error.__cause__
    if isinstance(cause, ProcessTimeoutError):
        return DeployJumpHostConfigureExecutionState.TIMED_OUT
    if isinstance(cause, ProcessOutputError):
        return DeployJumpHostConfigureExecutionState.MALFORMED_RESULT
    # The specialized service returns FAILED/UNREACHABLE as parsed semantic
    # evidence rather than raising. Any remaining AnsibleError has no strict
    # result projection and is therefore an uncertain malformed outcome.
    return DeployJumpHostConfigureExecutionState.MALFORMED_RESULT


def _binding_digests(
    binding: DeployJumpHostConfigureExecutionBinding,
) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(binding, name))
        for name in binding.__dataclass_fields__
        if name.endswith("_digest")
    )


def _binding_digest(binding: DeployJumpHostConfigureExecutionBinding) -> str:
    value = binding.to_object()
    value["binding_digest"] = ""
    return _digest_object(value)


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployJumpHostConfigureExecutionBinding.__dataclass_fields__.items():
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


def _entry_digest(entry: DeployJumpHostConfigureEvidenceEntry) -> str:
    value = entry.to_object()
    value["evidence_digest"] = ""
    return _digest_object(value)


def _entry_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployJumpHostConfigureEvidenceEntry.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            item.value
            if isinstance(item, StrEnum)
            else list(item)
            if isinstance(item, tuple)
            else item
        )
    value["logical_id"] = value.pop("stable_id")
    value["evidence_digest"] = ""
    return _digest_object(value)


def _timestamp() -> str:
    return format_timestamp(datetime.now(UTC))


def _optional_timestamp(value: str | None) -> datetime | None:
    return parse_timestamp(value) if value is not None else None


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy jump-host-configure execution paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy jump-host-configure execution requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy jump-host-configure execution artifacts"
        ) from error
    canonical = str(operation_id)
    for suffix in (
        DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_FILENAME_SUFFIX,
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
                    "deploy jump-host-configure execution artifacts are ambiguous"
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


def _positive_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


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


def _optional_boolean(value: object, label: str) -> bool | None:
    if value is not None and not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be a boolean or null")
    return value


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
        raise StatePersistenceError(
            f"deploy jump-host-configure {label} is invalid"
        ) from error


__all__ = [
    "ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_ENTRY_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_BINDING_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_SCHEMA_VERSION",
    "DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_FILENAME_SUFFIX",
    "DeployJumpHostConfigureArtifactState",
    "DeployJumpHostConfigureEvidence",
    "DeployJumpHostConfigureEvidenceEntry",
    "DeployJumpHostConfigureEvidenceStore",
    "DeployJumpHostConfigureExecution",
    "DeployJumpHostConfigureExecutionAttempt",
    "DeployJumpHostConfigureExecutionBinding",
    "DeployJumpHostConfigureExecutionReport",
    "DeployJumpHostConfigureExecutionState",
    "DeployJumpHostConfigureExecutionStore",
    "DeployJumpHostConfigureRestorationStatus",
    "StoredDeployJumpHostConfigureEvidence",
    "StoredDeployJumpHostConfigureExecution",
    "deploy_jump_host_configure_evidence_id_from_filename",
    "deploy_jump_host_configure_evidence_path",
    "deploy_jump_host_configure_execution_id_from_filename",
    "deploy_jump_host_configure_execution_path",
    "execute_deploy_jump_host_configure",
]
