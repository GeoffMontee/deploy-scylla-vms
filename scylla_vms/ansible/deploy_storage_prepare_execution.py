"""Durable exact-scope deploy ``storage-prepare`` execution.

This internal owner derives every target and runtime value from canonical state,
records prepared and started prefixes before each destructive call, consumes
general authorization at the first started boundary, and consumes wipe consent
only when an exact wipe-required target reaches that boundary.
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
from scylla_vms.ansible.deploy_plan import _digest_object, _playbook_source_digest
from scylla_vms.ansible.deploy_storage_preflight import (
    ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION,
    DeployStoragePreflightAction,
    DeployStoragePreflightHostEvidence,
)
from scylla_vms.ansible.deploy_storage_prepare_authorization import (
    ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_PREPARE_GENERAL_PROOF_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_PREPARE_WIPE_PROOF_SCHEMA_VERSION,
    DeployStoragePrepareAuthorizationScope,
    DeployStoragePrepareAuthorizationStore,
    StoredDeployStoragePrepareAuthorization,
    _AuthorizationContext,
    _build_authorization,
    _derive_authorization_scopes,
    _load_authorization_context,
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
from scylla_vms.ansible.storage_preflight import (
    StorageOwnershipStatus,
    StoragePreflightResult,
)
from scylla_vms.ansible.storage_prepare import (
    STORAGE_PREPARE_SCHEMA_VERSION,
    IrreversibleStepStatus,
    StoragePreparationAuthorization,
    StoragePrepareEvidence,
    StoragePrepareStatus,
    build_deploy_storage_prepare_payload,
    parse_storage_prepare_execution,
)
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

ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-prepare-execution-binding/v1"
)
ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-prepare-execution/v1"
)
ANSIBLE_DEPLOY_STORAGE_PREPARE_EVIDENCE_ENTRY_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-prepare-evidence-entry/v1"
)
ANSIBLE_DEPLOY_STORAGE_PREPARE_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-prepare-evidence/v1"
)
ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-prepare-execution-report/v1"
)

DEPLOY_STORAGE_PREPARE_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-storage-prepare-execution.json"
)
DEPLOY_STORAGE_PREPARE_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-storage-prepare-evidence.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "storage-prepare"
_MAPPING_SEQUENCE = 9
_STAGE = "post-storage-preflight-storage-prepare"
_SCOPE_KIND = "prepare-required-storage"
_ACTION = DeployStoragePreflightAction.PREPARE_REQUIRED
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SAFE_COMPLETION_STATES = frozenset({"completed", "failed"})
_SAFE_MUTATION_BOUNDARIES = frozenset(
    {"not-crossed", "crossed", "completed", "unknown"}
)


class DeployStoragePrepareExecutionState(StrEnum):
    """Bounded durable states for exact destructive attempts."""

    PREPARED = "prepared"
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"


class DeployStoragePrepareArtifactState(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployStoragePrepareExecutionBinding:
    """Address- and device-path-free authorization and state binding."""

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
    general_proof_digest: str
    wipe_proof_digest: str | None
    preflight_reconciliation_artifact_digest: str
    preflight_reconciliation_record_digest: str
    preflight_evidence_artifact_digest: str
    preflight_evidence_digest: str
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
    wipe_scope_count: int
    wipe_target_set_digest: str
    execution_scope_digest: str
    binding_digest: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION
    )
    general_proof_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREPARE_GENERAL_PROOF_SCHEMA_VERSION
    )
    wipe_proof_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREPARE_WIPE_PROOF_SCHEMA_VERSION
    )
    reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
    )
    preflight_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_BINDING_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_BINDING_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION
            or self.general_proof_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_GENERAL_PROOF_SCHEMA_VERSION
            or self.wipe_proof_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_WIPE_PROOF_SCHEMA_VERSION
            or self.reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
            or self.preflight_evidence_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
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
                "deploy storage-prepare execution binding is invalid"
            )
        validate_cluster_name(self.cluster_name)
        for value in (
            self.journal_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
            self.scope_count,
            self.stable_id_count,
        ):
            _positive_integer(value, "deploy storage-prepare binding count")
        _nonnegative_integer(
            self.wipe_scope_count, "deploy storage-prepare wipe scope count"
        )
        if (
            self.stable_id_count != self.scope_count
            or self.wipe_scope_count > self.scope_count
            or (self.wipe_scope_count == 0) != (self.wipe_proof_digest is None)
        ):
            raise StatePersistenceError(
                "deploy storage-prepare binding scope summary conflicts"
            )
        _validate_toolchain_version(self.toolchain_version)
        for digest in _binding_digests(self):
            if digest is not None:
                validate_digest(digest, "deploy storage-prepare binding digest")
        if self.binding_digest != _binding_digest(self):
            raise StatePersistenceError(
                "deploy storage-prepare execution binding digest conflicts"
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
    ) -> DeployStoragePrepareExecutionBinding:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy storage-prepare execution binding",
        )
        integer_fields = {
            "journal_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
            "scope_count",
            "stable_id_count",
            "wipe_scope_count",
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
            elif name == "wipe_proof_digest":
                parsed[name] = _optional_string(value[name], name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployStoragePrepareExecutionAttempt:
    """One strict prepared, started, or terminal target attempt."""

    attempt_index: int
    step_sequence: int
    stable_id: str
    action: DeployStoragePreflightAction
    disposition: StorageOwnershipStatus
    device_count: int
    device_set_digest: str
    preparation_intent_digest: str
    wipe_required: bool
    authorization_scope_digest: str
    variables_digest: str
    command_digest: str
    source_digest: str
    result_schema_version: str
    state: DeployStoragePrepareExecutionState
    prepared_at: str
    started_at: str | None
    completed_at: str | None
    general_authorization_consumed_at_start: bool
    wipe_authorization_consumed_at_start: bool
    invocation_may_have_occurred: bool
    exit_code: int | None
    result_digest: str | None
    evidence_digest: str | None
    immediate_device_revalidation: bool | None
    wipe_applied: bool | None
    mutation_boundary: str
    irreversible_step_status: str | None
    first_irreversible_step: str | None
    manual_recovery_required: bool
    automatic_retry_allowed: bool = False

    def __post_init__(self) -> None:
        if (
            self.attempt_index < 1
            or self.step_sequence < 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.action is not _ACTION
            or self.disposition
            not in {
                StorageOwnershipStatus.CLEAN_NEW,
                StorageOwnershipStatus.WIPE_REVIEW_REQUIRED,
            }
            or self.wipe_required
            != (self.disposition is StorageOwnershipStatus.WIPE_REVIEW_REQUIRED)
            or self.device_count < 1
            or self.result_schema_version != STORAGE_PREPARE_SCHEMA_VERSION
            or self.mutation_boundary not in _SAFE_MUTATION_BOUNDARIES
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy storage-prepare execution attempt is invalid"
            )
        for digest in (
            self.device_set_digest,
            self.preparation_intent_digest,
            self.authorization_scope_digest,
            self.variables_digest,
            self.command_digest,
            self.source_digest,
        ):
            validate_digest(digest, "deploy storage-prepare attempt digest")
        for optional_digest in (self.result_digest, self.evidence_digest):
            if optional_digest is not None:
                validate_digest(optional_digest, "deploy storage-prepare result digest")
        prepared = parse_timestamp(self.prepared_at)
        started = _optional_timestamp(self.started_at)
        completed = _optional_timestamp(self.completed_at)
        if (
            (started is not None and started < prepared)
            or (completed is not None and started is None)
            or (completed is not None and started is not None and completed < started)
        ):
            raise StatePersistenceError(
                "deploy storage-prepare attempt timestamps conflict"
            )
        self._validate_state(started, completed)

    def _validate_state(
        self, started: datetime | None, completed: datetime | None
    ) -> None:
        if self.state is DeployStoragePrepareExecutionState.PREPARED:
            valid = (
                started is None
                and completed is None
                and not self.general_authorization_consumed_at_start
                and not self.wipe_authorization_consumed_at_start
                and not self.invocation_may_have_occurred
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.immediate_device_revalidation is None
                and self.wipe_applied is None
                and self.mutation_boundary == "not-crossed"
                and self.irreversible_step_status is None
                and self.first_irreversible_step is None
                and not self.manual_recovery_required
            )
        elif self.state is DeployStoragePrepareExecutionState.STARTED:
            valid = (
                started is not None
                and completed is None
                and self.invocation_may_have_occurred
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.immediate_device_revalidation is None
                and self.wipe_applied is None
                and self.mutation_boundary == "unknown"
                and self.irreversible_step_status is None
                and self.first_irreversible_step is None
                and self.manual_recovery_required
            )
        elif self.state in {
            DeployStoragePrepareExecutionState.SUCCEEDED,
            DeployStoragePrepareExecutionState.FAILED,
            DeployStoragePrepareExecutionState.UNREACHABLE,
        }:
            valid = (
                started is not None
                and completed is not None
                and self.invocation_may_have_occurred
                and self.exit_code is not None
                and self.result_digest is not None
                and self.evidence_digest is not None
                and self.immediate_device_revalidation is not None
                and self.wipe_applied is not None
                and self.mutation_boundary != "unknown"
                and self.irreversible_step_status is not None
                and self.manual_recovery_required
                == (self.state is not DeployStoragePrepareExecutionState.SUCCEEDED)
            )
        else:
            valid = (
                started is not None
                and completed is not None
                and self.invocation_may_have_occurred
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.immediate_device_revalidation is None
                and self.wipe_applied is None
                and self.mutation_boundary == "unknown"
                and self.irreversible_step_status is None
                and self.first_irreversible_step is None
                and self.manual_recovery_required
            )
        if not valid or (
            self.state is DeployStoragePrepareExecutionState.SUCCEEDED
            and (
                self.exit_code != 0
                or self.mutation_boundary != "completed"
                or self.irreversible_step_status
                != IrreversibleStepStatus.COMPLETED.value
            )
        ):
            raise StatePersistenceError(
                "deploy storage-prepare execution attempt state conflicts"
            )
        if self.state is not DeployStoragePrepareExecutionState.PREPARED and (
            self.general_authorization_consumed_at_start != (self.attempt_index == 1)
            or self.wipe_authorization_consumed_at_start != self.wipe_required
        ):
            raise StatePersistenceError(
                "deploy storage-prepare proof consumption conflicts"
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
    ) -> DeployStoragePrepareExecutionAttempt:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy storage-prepare execution attempt",
        )
        try:
            return cls(
                attempt_index=_integer(value["attempt_index"], "attempt index"),
                step_sequence=_integer(value["step_sequence"], "step sequence"),
                stable_id=require_string(value, "stable_id"),
                action=DeployStoragePreflightAction(require_string(value, "action")),
                disposition=StorageOwnershipStatus(
                    require_string(value, "disposition")
                ),
                device_count=_integer(value["device_count"], "device count"),
                device_set_digest=require_string(value, "device_set_digest"),
                preparation_intent_digest=require_string(
                    value, "preparation_intent_digest"
                ),
                wipe_required=_boolean(value["wipe_required"], "wipe required"),
                authorization_scope_digest=require_string(
                    value, "authorization_scope_digest"
                ),
                variables_digest=require_string(value, "variables_digest"),
                command_digest=require_string(value, "command_digest"),
                source_digest=require_string(value, "source_digest"),
                result_schema_version=require_string(value, "result_schema_version"),
                state=DeployStoragePrepareExecutionState(
                    require_string(value, "state")
                ),
                prepared_at=require_string(value, "prepared_at"),
                started_at=_optional_string(value["started_at"], "started_at"),
                completed_at=_optional_string(value["completed_at"], "completed_at"),
                general_authorization_consumed_at_start=_boolean(
                    value["general_authorization_consumed_at_start"],
                    "general authorization consumption",
                ),
                wipe_authorization_consumed_at_start=_boolean(
                    value["wipe_authorization_consumed_at_start"],
                    "wipe authorization consumption",
                ),
                invocation_may_have_occurred=_boolean(
                    value["invocation_may_have_occurred"], "invocation state"
                ),
                exit_code=_optional_integer(value["exit_code"], "exit code"),
                result_digest=_optional_string(value["result_digest"], "result digest"),
                evidence_digest=_optional_string(
                    value["evidence_digest"], "evidence digest"
                ),
                immediate_device_revalidation=_optional_boolean(
                    value["immediate_device_revalidation"],
                    "immediate device revalidation",
                ),
                wipe_applied=_optional_boolean(value["wipe_applied"], "wipe applied"),
                mutation_boundary=require_string(value, "mutation_boundary"),
                irreversible_step_status=_optional_string(
                    value["irreversible_step_status"],
                    "irreversible step status",
                ),
                first_irreversible_step=_optional_string(
                    value["first_irreversible_step"], "first irreversible step"
                ),
                manual_recovery_required=_boolean(
                    value["manual_recovery_required"], "manual recovery"
                ),
                automatic_retry_allowed=_boolean(
                    value["automatic_retry_allowed"], "automatic retry"
                ),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy storage-prepare attempt enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployStoragePrepareExecution:
    """Generation-guarded strict-prefix destructive execution."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployStoragePrepareExecutionBinding
    state: DeployStoragePrepareExecutionState
    general_authorization_consumed: bool
    wipe_authorization_consumed_count: int
    wipe_authorization_consumed_target_set_digest: str
    invocation_count: int
    all_scopes_completed: bool
    attempts: tuple[DeployStoragePrepareExecutionAttempt, ...]
    schema_version: str = ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_SCHEMA_VERSION
            or not isinstance(self.binding, DeployStoragePrepareExecutionBinding)
            or not isinstance(self.state, DeployStoragePrepareExecutionState)
        ):
            raise StatePersistenceError("deploy storage-prepare execution is invalid")
        _positive_integer(self.generation, "storage-prepare execution generation")
        validate_digest(
            self.wipe_authorization_consumed_target_set_digest,
            "storage-prepare consumed wipe target digest",
        )
        if (
            parse_timestamp(self.updated_at) < parse_timestamp(self.created_at)
            or not 1 <= len(self.attempts) <= self.binding.scope_count
            or tuple(attempt.attempt_index for attempt in self.attempts)
            != tuple(range(1, len(self.attempts) + 1))
            or any(
                attempt.state is not DeployStoragePrepareExecutionState.SUCCEEDED
                for attempt in self.attempts[:-1]
            )
            or self.attempts[-1].state is not self.state
        ):
            raise StatePersistenceError(
                "deploy storage-prepare execution prefix conflicts"
            )
        invoked = tuple(
            item
            for item in self.attempts
            if item.state is not DeployStoragePrepareExecutionState.PREPARED
        )
        consumed_wipe = tuple(item.stable_id for item in invoked if item.wipe_required)
        if (
            self.invocation_count != len(invoked)
            or self.general_authorization_consumed != bool(invoked)
            or self.wipe_authorization_consumed_count != len(consumed_wipe)
            or self.wipe_authorization_consumed_target_set_digest
            != _digest_object(list(consumed_wipe))
            or self.all_scopes_completed
            != (
                len(self.attempts) == self.binding.scope_count
                and all(
                    item.state is DeployStoragePrepareExecutionState.SUCCEEDED
                    for item in self.attempts
                )
            )
        ):
            raise StatePersistenceError(
                "deploy storage-prepare execution summary conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "all_scopes_completed": self.all_scopes_completed,
            "attempts": [item.to_object() for item in self.attempts],
            "binding": self.binding.to_object(),
            "created_at": self.created_at,
            "general_authorization_consumed": self.general_authorization_consumed,
            "generation": self.generation,
            "invocation_count": self.invocation_count,
            "schema_version": self.schema_version,
            "state": self.state.value,
            "updated_at": self.updated_at,
            "wipe_authorization_consumed_count": (
                self.wipe_authorization_consumed_count
            ),
            "wipe_authorization_consumed_target_set_digest": (
                self.wipe_authorization_consumed_target_set_digest
            ),
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployStoragePrepareExecution:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy storage-prepare execution",
        )
        return cls(
            generation=_integer(value["generation"], "generation"),
            created_at=require_string(value, "created_at"),
            updated_at=require_string(value, "updated_at"),
            binding=DeployStoragePrepareExecutionBinding.from_object(
                _mapping(value["binding"], "execution binding")
            ),
            state=cast(
                DeployStoragePrepareExecutionState,
                _enum(
                    DeployStoragePrepareExecutionState,
                    require_string(value, "state"),
                    "execution state",
                ),
            ),
            general_authorization_consumed=_boolean(
                value["general_authorization_consumed"],
                "general authorization consumption",
            ),
            wipe_authorization_consumed_count=_integer(
                value["wipe_authorization_consumed_count"],
                "wipe authorization consumed count",
            ),
            wipe_authorization_consumed_target_set_digest=require_string(
                value, "wipe_authorization_consumed_target_set_digest"
            ),
            invocation_count=_integer(value["invocation_count"], "invocation count"),
            all_scopes_completed=_boolean(
                value["all_scopes_completed"], "scope completion"
            ),
            attempts=tuple(
                DeployStoragePrepareExecutionAttempt.from_object(
                    _mapping(item, "execution attempt")
                )
                for item in _array(value["attempts"], "execution attempts")
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployStoragePrepareEvidenceEntry:
    """Address- and device-path-free semantic result for one target."""

    attempt_index: int
    step_sequence: int
    stable_id: str
    action: DeployStoragePreflightAction
    disposition: StorageOwnershipStatus
    device_count: int
    device_set_digest: str
    preparation_intent_digest: str
    wipe_required: bool
    wipe_applied: bool
    status: StoragePrepareStatus
    completion_state: str
    immediate_device_revalidation: bool
    mutation_boundary: str
    irreversible_step_status: IrreversibleStepStatus
    first_irreversible_step: str | None
    completed_step_count: int
    completed_step_digest: str
    verification_count: int
    verification_digest: str
    filesystem_uuid_digest: str | None
    marker_digest: str | None
    provenance_digest: str
    variables_digest: str
    command_digest: str
    source_digest: str
    result_digest: str
    evidence_digest: str
    manual_recovery_required: bool
    automatic_retry_allowed: bool = False
    result_schema_version: str = STORAGE_PREPARE_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_STORAGE_PREPARE_EVIDENCE_ENTRY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.attempt_index < 1
            or self.step_sequence < 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.action is not _ACTION
            or self.disposition
            not in {
                StorageOwnershipStatus.CLEAN_NEW,
                StorageOwnershipStatus.WIPE_REVIEW_REQUIRED,
            }
            or self.device_count < 1
            or self.wipe_required
            != (self.disposition is StorageOwnershipStatus.WIPE_REVIEW_REQUIRED)
            or self.completion_state not in _SAFE_COMPLETION_STATES
            or self.mutation_boundary not in _SAFE_MUTATION_BOUNDARIES - {"unknown"}
            or self.completed_step_count < 0
            or self.verification_count < 0
            or self.result_schema_version != STORAGE_PREPARE_SCHEMA_VERSION
            or self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_EVIDENCE_ENTRY_SCHEMA_VERSION
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy storage-prepare evidence entry is invalid"
            )
        for digest in (
            self.device_set_digest,
            self.preparation_intent_digest,
            self.completed_step_digest,
            self.verification_digest,
            self.provenance_digest,
            self.variables_digest,
            self.command_digest,
            self.source_digest,
            self.result_digest,
            self.evidence_digest,
        ):
            validate_digest(digest, "deploy storage-prepare evidence digest")
        for optional_digest in (self.filesystem_uuid_digest, self.marker_digest):
            if optional_digest is not None:
                validate_digest(
                    optional_digest, "deploy storage-prepare evidence digest"
                )
        successful = self.status is StoragePrepareStatus.CHANGED
        if (
            self.completion_state != ("completed" if successful else "failed")
            or self.manual_recovery_required == successful
            or (
                successful
                and (
                    not self.immediate_device_revalidation
                    or self.irreversible_step_status
                    is not IrreversibleStepStatus.COMPLETED
                    or self.mutation_boundary != "completed"
                    or self.filesystem_uuid_digest is None
                    or self.marker_digest is None
                    or self.completed_step_count < 1
                    or self.verification_count < 1
                )
            )
            or (successful and self.wipe_applied != self.wipe_required)
        ):
            raise StatePersistenceError(
                "deploy storage-prepare evidence outcome conflicts"
            )
        if self.evidence_digest != _entry_evidence_digest(self):
            raise StatePersistenceError(
                "deploy storage-prepare evidence digest conflicts"
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
    ) -> DeployStoragePrepareEvidenceEntry:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy storage-prepare evidence entry",
        )
        try:
            return cls(
                attempt_index=_integer(value["attempt_index"], "attempt index"),
                step_sequence=_integer(value["step_sequence"], "step sequence"),
                stable_id=require_string(value, "stable_id"),
                action=DeployStoragePreflightAction(require_string(value, "action")),
                disposition=StorageOwnershipStatus(
                    require_string(value, "disposition")
                ),
                device_count=_integer(value["device_count"], "device count"),
                device_set_digest=require_string(value, "device_set_digest"),
                preparation_intent_digest=require_string(
                    value, "preparation_intent_digest"
                ),
                wipe_required=_boolean(value["wipe_required"], "wipe required"),
                wipe_applied=_boolean(value["wipe_applied"], "wipe applied"),
                status=StoragePrepareStatus(require_string(value, "status")),
                completion_state=require_string(value, "completion_state"),
                immediate_device_revalidation=_boolean(
                    value["immediate_device_revalidation"],
                    "immediate device revalidation",
                ),
                mutation_boundary=require_string(value, "mutation_boundary"),
                irreversible_step_status=IrreversibleStepStatus(
                    require_string(value, "irreversible_step_status")
                ),
                first_irreversible_step=_optional_string(
                    value["first_irreversible_step"], "first irreversible step"
                ),
                completed_step_count=_integer(
                    value["completed_step_count"], "completed step count"
                ),
                completed_step_digest=require_string(value, "completed_step_digest"),
                verification_count=_integer(
                    value["verification_count"], "verification count"
                ),
                verification_digest=require_string(value, "verification_digest"),
                filesystem_uuid_digest=_optional_string(
                    value["filesystem_uuid_digest"], "filesystem UUID digest"
                ),
                marker_digest=_optional_string(value["marker_digest"], "marker digest"),
                provenance_digest=require_string(value, "provenance_digest"),
                variables_digest=require_string(value, "variables_digest"),
                command_digest=require_string(value, "command_digest"),
                source_digest=require_string(value, "source_digest"),
                result_digest=require_string(value, "result_digest"),
                evidence_digest=require_string(value, "evidence_digest"),
                manual_recovery_required=_boolean(
                    value["manual_recovery_required"], "manual recovery"
                ),
                automatic_retry_allowed=_boolean(
                    value["automatic_retry_allowed"], "automatic retry"
                ),
                result_schema_version=require_string(value, "result_schema_version"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy storage-prepare evidence enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployStoragePrepareEvidence:
    """Immutable-prefix semantic evidence for exact destructive scopes."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployStoragePrepareExecutionBinding
    entries: tuple[DeployStoragePrepareEvidenceEntry, ...]
    schema_version: str = ANSIBLE_DEPLOY_STORAGE_PREPARE_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_EVIDENCE_SCHEMA_VERSION
            or self.generation != len(self.entries)
            or not 1 <= len(self.entries) <= self.binding.scope_count
            or tuple(item.attempt_index for item in self.entries)
            != tuple(range(1, len(self.entries) + 1))
            or parse_timestamp(self.updated_at) < parse_timestamp(self.created_at)
        ):
            raise StatePersistenceError(
                "deploy storage-prepare evidence prefix is invalid"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "binding": self.binding.to_object(),
            "created_at": self.created_at,
            "entries": [item.to_object() for item in self.entries],
            "generation": self.generation,
            "schema_version": self.schema_version,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployStoragePrepareEvidence:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy storage-prepare evidence",
        )
        return cls(
            generation=_integer(value["generation"], "generation"),
            created_at=require_string(value, "created_at"),
            updated_at=require_string(value, "updated_at"),
            binding=DeployStoragePrepareExecutionBinding.from_object(
                _mapping(value["binding"], "evidence binding")
            ),
            entries=tuple(
                DeployStoragePrepareEvidenceEntry.from_object(
                    _mapping(item, "evidence entry")
                )
                for item in _array(value["entries"], "evidence entries")
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredDeployStoragePrepareExecution:
    record: DeployStoragePrepareExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployStoragePrepareEvidence:
    record: DeployStoragePrepareEvidence
    artifact_digest: str


class DeployStoragePrepareExecutionStore:
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
        self._path = deploy_storage_prepare_execution_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployStoragePrepareExecution:
        value, digest = self._file.read()
        record = DeployStoragePrepareExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy storage-prepare execution identity conflicts"
            )
        return StoredDeployStoragePrepareExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployStoragePrepareExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployStoragePrepareExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployStoragePrepareExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy storage-prepare execution operation conflicts"
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
                    "deploy storage-prepare execution changed concurrently"
                )
            _validate_execution_transition(current.record, record)
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
            or record.state is not DeployStoragePrepareExecutionState.PREPARED
        ):
            raise StatePersistenceError(
                "initial deploy storage-prepare execution conflicts"
            )
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployStoragePrepareExecution(record, digest)


class DeployStoragePrepareEvidenceStore:
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
        self._path = deploy_storage_prepare_evidence_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployStoragePrepareEvidence:
        value, digest = self._file.read()
        record = DeployStoragePrepareEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy storage-prepare evidence identity conflicts"
            )
        return StoredDeployStoragePrepareEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployStoragePrepareEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def append_locked(
        self,
        record: DeployStoragePrepareEvidence,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployStoragePrepareEvidence:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy storage-prepare evidence operation conflicts"
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
                or record.generation != current.record.generation + 1
                or record.created_at != current.record.created_at
                or record.binding != current.record.binding
                or record.entries[:-1] != current.record.entries
            ):
                raise StatePersistenceError(
                    "deploy storage-prepare evidence transition conflicts"
                )
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
        ):
            raise StatePersistenceError(
                "initial deploy storage-prepare evidence conflicts"
            )
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployStoragePrepareEvidence(record, digest)


@dataclass(frozen=True, slots=True)
class DeployStoragePrepareExecutionReport:
    """Strict redacted report for complete successful execution."""

    operation_id: uuid.UUID
    execution_state: DeployStoragePrepareExecutionState
    execution_artifact_state: DeployStoragePrepareArtifactState
    evidence_artifact_state: DeployStoragePrepareArtifactState
    execution_artifact_digest: str
    evidence_artifact_digest: str
    binding_digest: str
    authorization_artifact_digest: str
    authorization_digest: str
    general_authorization_consumed: bool
    general_proof_digest: str
    wipe_proof_state: str
    wipe_proof_digest: str | None
    wipe_authorization_consumed_count: int
    wipe_authorization_consumed_target_set_digest: str
    stage: str
    scope_kind: str
    invocation_count: int
    scope_count: int
    stable_id_count: int
    stable_id_set_digest: str
    wipe_scope_count: int
    prepared_count: int
    started_count: int
    succeeded_count: int
    changed_count: int
    wipe_applied_count: int
    device_count: int
    device_set_digest: str
    result_digest: str
    evidence_digest: str
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    skip_allowed: bool
    continue_after_uncertainty_allowed: bool
    rollback_performed: bool
    reconciliation_state: str
    postcheck_state: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREPARE_EVIDENCE_SCHEMA_VERSION
    )
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION
    )
    schema_version: str = ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_REPORT_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_EVIDENCE_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION
            or self.execution_state is not DeployStoragePrepareExecutionState.SUCCEEDED
            or self.execution_artifact_state
            not in {
                DeployStoragePrepareArtifactState.UPDATED,
                DeployStoragePrepareArtifactState.REUSED,
            }
            or self.evidence_artifact_state
            not in {
                DeployStoragePrepareArtifactState.CREATED,
                DeployStoragePrepareArtifactState.UPDATED,
                DeployStoragePrepareArtifactState.REUSED,
            }
            or not self.general_authorization_consumed
            or self.wipe_proof_state
            != ("consumed" if self.wipe_scope_count else "not-required")
            or (self.wipe_scope_count == 0) != (self.wipe_proof_digest is None)
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.manual_recovery_required
            or self.automatic_retry_allowed
            or self.skip_allowed
            or self.continue_after_uncertainty_allowed
            or self.rollback_performed
            or self.reconciliation_state != "not-performed"
            or self.postcheck_state != "not-performed"
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError(
                "deploy storage-prepare execution report is invalid"
            )
        if (
            self.invocation_count != self.scope_count
            or self.scope_count != self.stable_id_count
            or self.prepared_count != self.scope_count
            or self.started_count != self.scope_count
            or self.succeeded_count != self.scope_count
            or self.changed_count != self.scope_count
            or self.wipe_authorization_consumed_count != self.wipe_scope_count
            or self.wipe_applied_count != self.wipe_scope_count
            or self.device_count < self.scope_count
        ):
            raise StatePersistenceError(
                "deploy storage-prepare execution report counts conflict"
            )
        for name in self.__dataclass_fields__:
            if name.endswith("_digest"):
                value = getattr(self, name)
                if value is not None:
                    validate_digest(
                        cast(str, value),
                        "deploy storage-prepare report digest",
                    )

    def to_object(self) -> dict[str, object]:
        return {
            "authorization": {
                "artifact_digest": self.authorization_artifact_digest,
                "digest": self.authorization_digest,
                "general_consumed": self.general_authorization_consumed,
                "general_proof_digest": self.general_proof_digest,
                "schema_version": self.authorization_schema_version,
                "wipe_consumed_count": self.wipe_authorization_consumed_count,
                "wipe_consumed_target_set_digest": (
                    self.wipe_authorization_consumed_target_set_digest
                ),
                "wipe_proof_digest": self.wipe_proof_digest,
                "wipe_proof_state": self.wipe_proof_state,
            },
            "execution": {
                "artifact_digest": self.execution_artifact_digest,
                "artifact_state": self.execution_artifact_state.value,
                "automatic_retry_allowed": self.automatic_retry_allowed,
                "binding_digest": self.binding_digest,
                "continue_after_uncertainty_allowed": (
                    self.continue_after_uncertainty_allowed
                ),
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
                "updated": False,
            },
            "operation_id": str(self.operation_id),
            "result": {
                "changed_count": self.changed_count,
                "device_count": self.device_count,
                "device_set_digest": self.device_set_digest,
                "evidence_artifact_digest": self.evidence_artifact_digest,
                "evidence_artifact_state": self.evidence_artifact_state.value,
                "evidence_digest": self.evidence_digest,
                "evidence_schema_version": self.evidence_schema_version,
                "postcheck_state": self.postcheck_state,
                "reconciliation_state": self.reconciliation_state,
                "result_digest": self.result_digest,
                "wipe_applied_count": self.wipe_applied_count,
            },
            "schema_version": self.schema_version,
            "scope": {
                "instance_count": self.scope_count,
                "kind": self.scope_kind,
                "prepared_count": self.prepared_count,
                "stable_id_count": self.stable_id_count,
                "stable_id_set_digest": self.stable_id_set_digest,
                "started_count": self.started_count,
                "succeeded_count": self.succeeded_count,
                "wipe_scope_count": self.wipe_scope_count,
            },
            "stage": self.stage,
        }


@dataclass(frozen=True, slots=True)
class _ExecutionScope:
    attempt_index: int
    authorization: DeployStoragePrepareAuthorizationScope
    preflight_host: DeployStoragePreflightHostEvidence
    preflight: StoragePreflightResult
    variables: Mapping[str, object]
    variables_digest: str
    command_digest: str
    source_digest: str
    provenance_digest: str


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    authorization: StoredDeployStoragePrepareAuthorization
    binding: DeployStoragePrepareExecutionBinding
    scopes: tuple[_ExecutionScope, ...]
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport


def execute_deploy_storage_prepare(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployStoragePrepareExecutionReport:
    """Execute only immutable authorized prepare-required storage scopes."""

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
    execution_store = DeployStoragePrepareExecutionStore(paths, operation_id)
    evidence_store = DeployStoragePrepareEvidenceStore(paths, operation_id)
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
    if execution is not None and execution.record.all_scopes_completed:
        if evidence is None:
            raise StateConflictError(
                "completed deploy storage-prepare evidence is unavailable"
            )
        return _build_report(
            context,
            execution,
            evidence,
            execution_state=DeployStoragePrepareArtifactState.REUSED,
            evidence_state=DeployStoragePrepareArtifactState.REUSED,
        )
    if execution is not None and execution.record.state not in {
        DeployStoragePrepareExecutionState.PREPARED,
        DeployStoragePrepareExecutionState.SUCCEEDED,
    }:
        raise StateConflictError(
            "deploy storage-prepare execution requires manual recovery and cannot retry"
        )

    service = AnsibleService(builder, runner)
    discovered = service.version(lock)
    if discovered != toolchain:
        raise StateConflictError("deploy storage-prepare Ansible toolchain drifted")
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
        or execution.record.state is DeployStoragePrepareExecutionState.SUCCEEDED
    ):
        execution = _persist_prepared(
            context,
            execution_store,
            execution,
            context.scopes[next_index],
            lock=lock,
        )
    assert execution is not None
    execution_artifact_state = DeployStoragePrepareArtifactState.UPDATED
    evidence_artifact_state = (
        DeployStoragePrepareArtifactState.UPDATED
        if evidence is not None
        else DeployStoragePrepareArtifactState.CREATED
    )

    while True:
        if execution.record.state is DeployStoragePrepareExecutionState.PREPARED:
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
                    "deploy storage-prepare state drifted before start"
                )
            _validate_prefix(before, execution, evidence)
            scope = before.scopes[len(execution.record.attempts) - 1]
            try:
                execution = _persist_started(execution_store, execution, lock=lock)
            except StatePersistenceError as error:
                raise StatePersistenceError(
                    "deploy storage-prepare authorization consumption failed "
                    "before invocation"
                ) from error
            try:
                result, observed_command_digest = service.execute_operation_step(
                    lock,
                    before.metadata,
                    before.inventory,
                    _PLAYBOOK,
                    step_sequence=scope.authorization.sequence,
                    limit=(scope.authorization.stable_id,),
                    variables=dict(scope.variables),
                    readiness=before.readiness,
                    tags=(),
                    check=False,
                    diff=False,
                    verbosity=0,
                )
                if observed_command_digest != scope.command_digest:
                    raise AnsibleResultError(
                        "deploy storage-prepare command result identity conflicts"
                    )
            except KeyboardInterrupt:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    DeployStoragePrepareExecutionState.INTERRUPTED,
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy storage-prepare execution was interrupted; "
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
                    "deploy storage-prepare execution is uncertain; "
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
                    "deploy storage-prepare state changed after invocation; "
                    "manual recovery required"
                ) from error
            if after.binding != context.binding:
                raise StateConflictError(
                    "deploy storage-prepare state changed after invocation; "
                    "manual recovery required"
                )
            try:
                entry = _semantic_entry(scope, result)
            except (AnsibleError, StatePersistenceError) as error:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    DeployStoragePrepareExecutionState.MALFORMED_RESULT,
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy storage-prepare result is malformed; "
                    "manual recovery required"
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
                    "deploy storage-prepare evidence persistence failed; "
                    "manual recovery required"
                ) from error
            terminal_state = _terminal_state(entry, result.exit_code)
            try:
                execution = _persist_terminal(
                    context,
                    execution_store,
                    execution,
                    entry=entry,
                    state=terminal_state,
                    exit_code=result.exit_code,
                    lock=lock,
                )
            except StatePersistenceError as error:
                raise StatePersistenceError(
                    "deploy storage-prepare terminal persistence failed; "
                    "manual recovery required"
                ) from error
            if terminal_state is not DeployStoragePrepareExecutionState.SUCCEEDED:
                raise AnsibleError(
                    "deploy storage-prepare execution failed; manual recovery required"
                )

        if execution.record.all_scopes_completed:
            break
        execution = _persist_prepared(
            context,
            execution_store,
            execution,
            context.scopes[len(execution.record.attempts)],
            lock=lock,
        )

    if evidence is None:
        raise StatePersistenceError(
            "deploy storage-prepare completion evidence is missing"
        )
    _validate_prefix(context, execution, evidence)
    return _build_report(
        context,
        execution,
        evidence,
        execution_state=execution_artifact_state,
        evidence_state=evidence_artifact_state,
    )


def deploy_storage_prepare_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_STORAGE_PREPARE_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy storage-prepare execution path is not canonical"
        )
    return path


def deploy_storage_prepare_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_STORAGE_PREPARE_EVIDENCE_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy storage-prepare evidence path is not canonical"
        )
    return path


def deploy_storage_prepare_execution_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_STORAGE_PREPARE_EXECUTION_FILENAME_SUFFIX
    )


def deploy_storage_prepare_evidence_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_STORAGE_PREPARE_EVIDENCE_FILENAME_SUFFIX
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
    preflight = authorization_context.preflight
    loaded = preflight.discovery.post.chain.authorization_context.final_routes.post.post.base.host.loaded
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
        or preflight.binding.toolchain_version != str(toolchain.core)
        or preflight.binding.executable_identity_digest != executable_identity_digest
        or preflight.binding.toolchain_evidence_digest != toolchain_evidence_digest
    ):
        raise StateConflictError(
            "deploy storage-prepare readiness, journal, or toolchain conflicts"
        )
    readiness = _reconstructed_readiness(planning.base)
    if readiness_binding_digest(readiness) != readiness_record.readiness_digest:
        raise StateConflictError("deploy storage-prepare readiness is stale")
    readiness.require_ready(OperationClassification.DESTRUCTIVE)

    authorization_store = DeployStoragePrepareAuthorizationStore(paths, operation_id)
    validate_state_file(authorization_store.path, allow_missing=True)
    if not authorization_store.path.exists():
        raise StateConflictError(
            "deploy storage-prepare execution requires immutable authorization"
        )
    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    authorization_scopes = _derive_authorization_scopes(authorization_context)
    expected_authorization = _build_authorization(
        authorization_context,
        scopes=authorization_scopes,
        general_proof=authorization.record.general_proof,
        wipe_proof=authorization.record.wipe_proof,
        created_at=authorization.record.created_at,
    )
    if (
        authorization.record != expected_authorization
        or authorization.record.consumed
        or authorization.record.authorization_state != "authorized-pre-execution"
        or authorization.record.execution_state != "unavailable"
    ):
        raise StateConflictError(
            "deploy storage-prepare authorization is stale or consumed"
        )
    scopes = _derive_execution_scopes(
        authorization_context,
        authorization,
        builder=builder,
    )
    stable_ids = tuple(scope.authorization.stable_id for scope in scopes)
    wipe_ids = tuple(
        scope.authorization.stable_id
        for scope in scopes
        if scope.authorization.wipe_required
    )
    scope_values = [
        {
            "action": scope.authorization.action.value,
            "attempt_index": scope.attempt_index,
            "authorization_scope_digest": scope.authorization.scope_digest,
            "command_digest": scope.command_digest,
            "device_set_digest": scope.authorization.device_set_digest,
            "disposition": scope.authorization.disposition.value,
            "preparation_intent_digest": (
                scope.authorization.preparation_intent_digest
            ),
            "provenance_digest": scope.provenance_digest,
            "source_digest": scope.source_digest,
            "stable_id_digest": scope.authorization.stable_id_digest,
            "step_sequence": scope.authorization.sequence,
            "variables_digest": scope.variables_digest,
            "wipe_required": scope.authorization.wipe_required,
        }
        for scope in scopes
    ]
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
        "general_proof_digest": authorization.record.general_proof.proof_digest,
        "wipe_proof_digest": (
            None
            if authorization.record.wipe_proof is None
            else authorization.record.wipe_proof.proof_digest
        ),
        "preflight_reconciliation_artifact_digest": (
            authorization_context.reconciliation.artifact_digest
        ),
        "preflight_reconciliation_record_digest": (
            authorization_context.reconciliation.record.record_digest
        ),
        "preflight_evidence_artifact_digest": (
            authorization_context.evidence.artifact_digest
        ),
        "preflight_evidence_digest": (
            authorization_context.evidence.record.evidence_digest
        ),
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": readiness_record.record_digest,
        "catalog_digest": loaded.catalog_digest,
        "source_version": loaded.source.version,
        "source_digest": loaded.source.digest,
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
        "wipe_scope_count": len(wipe_ids),
        "wipe_target_set_digest": _digest_object(list(wipe_ids)),
        "execution_scope_digest": _digest_object(scope_values),
        "binding_digest": "",
    }
    values["binding_digest"] = _binding_digest_from_values(values)
    binding = DeployStoragePrepareExecutionBinding(**values)  # type: ignore[arg-type]
    return _ExecutionContext(
        authorization,
        binding,
        scopes,
        metadata,
        deploy.inventory,
        readiness,
    )


def _derive_execution_scopes(
    authorization_context: _AuthorizationContext,
    authorization: StoredDeployStoragePrepareAuthorization,
    *,
    builder: AnsibleCommandBuilder,
) -> tuple[_ExecutionScope, ...]:
    context = authorization_context
    preflight = context.preflight
    loaded = preflight.discovery.post.chain.authorization_context.final_routes.post.post.base.host.loaded
    deploy = loaded.planning.base.deploy
    evidence_hosts = {item.stable_id: item for item in context.evidence.record.hosts}
    preflight_hosts = {item.logical_id: item for item in preflight.preflight.hosts}
    source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
    definition = get_playbook(_PLAYBOOK)
    if (
        definition.classification is not OperationClassification.DESTRUCTIVE
        or definition.hosts != HostRole.SCYLLA.value
        or definition.serial != 1
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.check_mode is not CheckMode.REFUSED
        or not definition.source_available
    ):
        raise StateConflictError("deploy storage-prepare catalog policy conflicts")
    scopes: list[_ExecutionScope] = []
    for attempt_index, authorized in enumerate(authorization.record.scopes, start=1):
        host = evidence_hosts.get(authorized.stable_id)
        source_preflight = preflight_hosts.get(authorized.stable_id)
        if (
            authorized.mapping_sequence != _MAPPING_SEQUENCE
            or authorized.playbook != _PLAYBOOK
            or authorized.classification is not OperationClassification.DESTRUCTIVE
            or authorized.action is not _ACTION
            or authorized.source_digest != source_digest
            or host is None
            or source_preflight is None
            or host.action is not _ACTION
            or host.blocker_set
            or host.disposition is not authorized.disposition
            or host.device_count != authorized.device_count
            or host.device_set_digest != authorized.device_set_digest
            or host.preparation_intent_digest != authorized.preparation_intent_digest
            or host.wipe_required != authorized.wipe_required
            or source_preflight.ownership_status is not authorized.disposition
            or source_preflight.blockers
        ):
            raise StateConflictError("deploy storage-prepare authorized scope drifted")
        narrow_preflight = StoragePreflightResult((source_preflight,))
        runtime_authorization = StoragePreparationAuthorization(
            operation_id=authorization.record.operation_id,
            logical_id=authorized.stable_id,
            preparation_intent_digest=authorized.preparation_intent_digest,
            device_set_digest=authorized.device_set_digest,
            preparation_approved=True,
            wipe_acknowledged=authorized.wipe_required,
        )
        payload = build_deploy_storage_prepare_payload(
            deploy.metadata.record,
            deploy.observation,
            deploy.inventory,
            narrow_preflight,
            runtime_authorization,
            discovery_digest=authorization.record.preflight_evidence_digest,
            preflight_evidence_digest=authorization.record.preflight_evidence_digest,
            limit=(authorized.stable_id,),
            check=False,
        )
        variables = {"deploy_scylla_vms_storage_prepare": payload}
        selected_definition, validated, variables_digest, command_digest = (
            builder.validate_operation_step(
                _PLAYBOOK,
                step_sequence=authorized.sequence,
                limit=(authorized.stable_id,),
                variables=variables,
                tags=(),
                check=False,
                diff=False,
                verbosity=0,
            )
        )
        if (
            selected_definition != definition
            or authorized.target_digest != _digest_object([authorized.stable_id])
            or authorized.stable_id_digest != _digest_object(authorized.stable_id)
        ):
            raise StateConflictError("deploy storage-prepare command scope conflicts")
        provenance = payload["provenance_digest"]
        if not isinstance(provenance, str):
            raise StateConflictError(
                "deploy storage-prepare runtime provenance is invalid"
            )
        scopes.append(
            _ExecutionScope(
                attempt_index,
                authorized,
                host,
                narrow_preflight,
                validated,
                variables_digest,
                command_digest,
                source_digest,
                provenance,
            )
        )
    if (
        not scopes
        or len(scopes) != authorization.record.prepare_host_count
        or tuple(scope.authorization.stable_id for scope in scopes)
        != tuple(sorted(scope.authorization.stable_id for scope in scopes))
        or tuple(scope.authorization.sequence for scope in scopes)
        != tuple(sorted(scope.authorization.sequence for scope in scopes))
    ):
        raise StateConflictError(
            "deploy storage-prepare execution scope is unavailable"
        )
    return tuple(scopes)


def _validate_prefix(
    context: _ExecutionContext,
    execution: StoredDeployStoragePrepareExecution | None,
    evidence: StoredDeployStoragePrepareEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "deploy storage-prepare evidence exists without intent"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError("deploy storage-prepare execution provenance is stale")
    if evidence is not None and evidence.record.binding != context.binding:
        raise StateConflictError("deploy storage-prepare evidence provenance is stale")
    for index, attempt in enumerate(execution.record.attempts):
        scope = context.scopes[index]
        authorized = scope.authorization
        if (
            attempt.attempt_index != index + 1
            or attempt.step_sequence != authorized.sequence
            or attempt.stable_id != authorized.stable_id
            or attempt.action is not authorized.action
            or attempt.disposition is not authorized.disposition
            or attempt.device_count != authorized.device_count
            or attempt.device_set_digest != authorized.device_set_digest
            or attempt.preparation_intent_digest != authorized.preparation_intent_digest
            or attempt.wipe_required != authorized.wipe_required
            or attempt.authorization_scope_digest != authorized.scope_digest
            or attempt.variables_digest != scope.variables_digest
            or attempt.command_digest != scope.command_digest
            or attempt.source_digest != scope.source_digest
        ):
            raise StateConflictError("deploy storage-prepare execution scope conflicts")
    entries = evidence.record.entries if evidence is not None else ()
    if len(entries) > len(execution.record.attempts):
        raise StateConflictError("deploy storage-prepare evidence prefix conflicts")
    for index, entry in enumerate(entries):
        attempt = execution.record.attempts[index]
        scope = context.scopes[index]
        if (
            attempt.state is DeployStoragePrepareExecutionState.PREPARED
            or entry.attempt_index != index + 1
            or entry.step_sequence != scope.authorization.sequence
            or entry.stable_id != scope.authorization.stable_id
            or entry.device_set_digest != scope.authorization.device_set_digest
            or entry.preparation_intent_digest
            != scope.authorization.preparation_intent_digest
            or entry.provenance_digest != scope.provenance_digest
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
                "deploy storage-prepare semantic evidence conflicts"
            )
    required_entries = sum(
        attempt.state
        in {
            DeployStoragePrepareExecutionState.SUCCEEDED,
            DeployStoragePrepareExecutionState.FAILED,
            DeployStoragePrepareExecutionState.UNREACHABLE,
        }
        for attempt in execution.record.attempts
    )
    started_extra = (
        1
        if execution.record.state is DeployStoragePrepareExecutionState.STARTED
        and len(entries) == required_entries + 1
        else 0
    )
    if len(entries) != required_entries + started_extra:
        raise StateConflictError(
            "deploy storage-prepare execution/evidence prefixes conflict"
        )


def _persist_prepared(
    context: _ExecutionContext,
    store: DeployStoragePrepareExecutionStore,
    current: StoredDeployStoragePrepareExecution | None,
    scope: _ExecutionScope,
    *,
    lock: ClusterLock,
) -> StoredDeployStoragePrepareExecution:
    now = _timestamp()
    attempt = DeployStoragePrepareExecutionAttempt(
        attempt_index=scope.attempt_index,
        step_sequence=scope.authorization.sequence,
        stable_id=scope.authorization.stable_id,
        action=scope.authorization.action,
        disposition=scope.authorization.disposition,
        device_count=scope.authorization.device_count,
        device_set_digest=scope.authorization.device_set_digest,
        preparation_intent_digest=scope.authorization.preparation_intent_digest,
        wipe_required=scope.authorization.wipe_required,
        authorization_scope_digest=scope.authorization.scope_digest,
        variables_digest=scope.variables_digest,
        command_digest=scope.command_digest,
        source_digest=scope.source_digest,
        result_schema_version=STORAGE_PREPARE_SCHEMA_VERSION,
        state=DeployStoragePrepareExecutionState.PREPARED,
        prepared_at=now,
        started_at=None,
        completed_at=None,
        general_authorization_consumed_at_start=False,
        wipe_authorization_consumed_at_start=False,
        invocation_may_have_occurred=False,
        exit_code=None,
        result_digest=None,
        evidence_digest=None,
        immediate_device_revalidation=None,
        wipe_applied=None,
        mutation_boundary="not-crossed",
        irreversible_step_status=None,
        first_irreversible_step=None,
        manual_recovery_required=False,
    )
    if current is None:
        record = DeployStoragePrepareExecution(
            generation=1,
            created_at=now,
            updated_at=now,
            binding=context.binding,
            state=DeployStoragePrepareExecutionState.PREPARED,
            general_authorization_consumed=False,
            wipe_authorization_consumed_count=0,
            wipe_authorization_consumed_target_set_digest=_digest_object([]),
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
    if current.record.state is not DeployStoragePrepareExecutionState.SUCCEEDED:
        raise StateConflictError(
            "deploy storage-prepare cannot prepare after uncertain state"
        )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=DeployStoragePrepareExecutionState.PREPARED,
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
    store: DeployStoragePrepareExecutionStore,
    current: StoredDeployStoragePrepareExecution,
    *,
    lock: ClusterLock,
) -> StoredDeployStoragePrepareExecution:
    if current.record.state is not DeployStoragePrepareExecutionState.PREPARED:
        raise StateConflictError(
            "deploy storage-prepare start requires prepared intent"
        )
    now = _timestamp()
    previous = current.record.attempts[-1]
    attempt = replace(
        previous,
        state=DeployStoragePrepareExecutionState.STARTED,
        started_at=now,
        general_authorization_consumed_at_start=previous.attempt_index == 1,
        wipe_authorization_consumed_at_start=previous.wipe_required,
        invocation_may_have_occurred=True,
        mutation_boundary="unknown",
        manual_recovery_required=True,
    )
    attempts = (*current.record.attempts[:-1], attempt)
    consumed_wipe = tuple(
        item.stable_id
        for item in attempts
        if item.state is not DeployStoragePrepareExecutionState.PREPARED
        and item.wipe_required
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=DeployStoragePrepareExecutionState.STARTED,
        general_authorization_consumed=True,
        wipe_authorization_consumed_count=len(consumed_wipe),
        wipe_authorization_consumed_target_set_digest=_digest_object(
            list(consumed_wipe)
        ),
        invocation_count=current.record.invocation_count + 1,
        attempts=attempts,
    )
    return store.write_locked(
        record,
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _persist_uncertain_or_raise(
    store: DeployStoragePrepareExecutionStore,
    current: StoredDeployStoragePrepareExecution,
    state: DeployStoragePrepareExecutionState,
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
            "deploy storage-prepare uncertain outcome persistence failed; "
            "manual recovery required"
        ) from error


def _persist_terminal(
    context: _ExecutionContext,
    store: DeployStoragePrepareExecutionStore,
    current: StoredDeployStoragePrepareExecution,
    *,
    entry: DeployStoragePrepareEvidenceEntry,
    state: DeployStoragePrepareExecutionState,
    exit_code: int,
    lock: ClusterLock,
) -> StoredDeployStoragePrepareExecution:
    now = _timestamp()
    attempt = replace(
        current.record.attempts[-1],
        state=state,
        completed_at=now,
        exit_code=exit_code,
        result_digest=entry.result_digest,
        evidence_digest=entry.evidence_digest,
        immediate_device_revalidation=entry.immediate_device_revalidation,
        wipe_applied=entry.wipe_applied,
        mutation_boundary=entry.mutation_boundary,
        irreversible_step_status=entry.irreversible_step_status.value,
        first_irreversible_step=entry.first_irreversible_step,
        manual_recovery_required=state
        is not DeployStoragePrepareExecutionState.SUCCEEDED,
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=state,
        all_scopes_completed=(
            state is DeployStoragePrepareExecutionState.SUCCEEDED
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
    store: DeployStoragePrepareEvidenceStore,
    current: StoredDeployStoragePrepareEvidence | None,
    entry: DeployStoragePrepareEvidenceEntry,
    *,
    lock: ClusterLock,
) -> StoredDeployStoragePrepareEvidence:
    now = _timestamp()
    if current is None:
        record = DeployStoragePrepareEvidence(
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
) -> DeployStoragePrepareEvidenceEntry:
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.DESTRUCTIVE
        or result.check_mode
        or result.storage_prepare is not None
        or result.storage_discovery is not None
        or result.storage_preflight is not None
    ):
        raise AnsibleResultError("deploy storage-prepare result identity conflicts")
    parsed = parse_storage_prepare_execution(
        result.stdout,
        expected_logical_id=scope.authorization.stable_id,
        expected_backend=scope.preflight_host.backend,
        expected_layout=scope.preflight_host.layout,
        expected_device_set_digest=scope.authorization.device_set_digest,
        exit_code=result.exit_code,
        require_deploy_proof=True,
        expected_action=_ACTION.value,
        expected_disposition=scope.authorization.disposition.value,
        expected_preparation_intent_digest=(
            scope.authorization.preparation_intent_digest
        ),
        expected_provenance_digest=scope.provenance_digest,
    )
    if parsed.status not in {StoragePrepareStatus.CHANGED, StoragePrepareStatus.FAILED}:
        raise AnsibleResultError("deploy storage-prepare returned a prohibited action")
    successful = parsed.status is StoragePrepareStatus.CHANGED
    result_digest = _storage_prepare_result_digest(parsed)
    values: dict[str, object] = {
        "attempt_index": scope.attempt_index,
        "step_sequence": scope.authorization.sequence,
        "stable_id": scope.authorization.stable_id,
        "action": _ACTION,
        "disposition": scope.authorization.disposition,
        "device_count": scope.authorization.device_count,
        "device_set_digest": scope.authorization.device_set_digest,
        "preparation_intent_digest": (scope.authorization.preparation_intent_digest),
        "wipe_required": scope.authorization.wipe_required,
        "wipe_applied": bool(parsed.wipe_applied),
        "status": parsed.status,
        "completion_state": "completed" if successful else "failed",
        "immediate_device_revalidation": bool(parsed.immediate_device_revalidation),
        "mutation_boundary": cast(str, parsed.mutation_boundary),
        "irreversible_step_status": parsed.irreversible_step_status,
        "first_irreversible_step": parsed.first_irreversible_step,
        "completed_step_count": len(parsed.completed_steps),
        "completed_step_digest": _digest_object(list(parsed.completed_steps)),
        "verification_count": len(parsed.post_action_verification),
        "verification_digest": _digest_object(
            {key: value for key, value in parsed.post_action_verification}
        ),
        "filesystem_uuid_digest": parsed.filesystem_uuid_digest,
        "marker_digest": parsed.marker_digest,
        "provenance_digest": scope.provenance_digest,
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "source_digest": scope.source_digest,
        "result_digest": result_digest,
        "evidence_digest": "",
        "manual_recovery_required": not successful,
    }
    values["evidence_digest"] = _entry_evidence_digest_from_values(values)
    return DeployStoragePrepareEvidenceEntry(**values)  # type: ignore[arg-type]


def _storage_prepare_result_digest(result: StoragePrepareEvidence) -> str:
    return _digest_object(
        {
            "action": result.action,
            "backend": result.backend,
            "completed": result.completed,
            "completed_steps": list(result.completed_steps),
            "device_set_digest": result.device_set_digest,
            "disposition": result.disposition,
            "filesystem_uuid_digest": result.filesystem_uuid_digest,
            "first_irreversible_step": result.first_irreversible_step,
            "immediate_device_revalidation": (result.immediate_device_revalidation),
            "irreversible_step_status": result.irreversible_step_status.value,
            "layout": result.layout,
            "logical_id": result.logical_id,
            "marker_digest": result.marker_digest,
            "mutation_boundary": result.mutation_boundary,
            "post_action_verification": dict(result.post_action_verification),
            "preparation_intent_digest": result.preparation_intent_digest,
            "provenance_digest": result.provenance_digest,
            "schema_version": result.schema_version,
            "status": result.status.value,
            "wipe_applied": result.wipe_applied,
        }
    )


def _terminal_state(
    entry: DeployStoragePrepareEvidenceEntry, exit_code: int
) -> DeployStoragePrepareExecutionState:
    if (
        exit_code == 0
        and entry.status is StoragePrepareStatus.CHANGED
        and entry.completion_state == "completed"
        and entry.immediate_device_revalidation
        and entry.mutation_boundary == "completed"
    ):
        return DeployStoragePrepareExecutionState.SUCCEEDED
    if exit_code == 4:
        return DeployStoragePrepareExecutionState.UNREACHABLE
    return DeployStoragePrepareExecutionState.FAILED


def _build_report(
    context: _ExecutionContext,
    execution: StoredDeployStoragePrepareExecution,
    evidence: StoredDeployStoragePrepareEvidence,
    *,
    execution_state: DeployStoragePrepareArtifactState,
    evidence_state: DeployStoragePrepareArtifactState,
) -> DeployStoragePrepareExecutionReport:
    if (
        not execution.record.all_scopes_completed
        or execution.record.state is not DeployStoragePrepareExecutionState.SUCCEEDED
        or len(evidence.record.entries) != len(context.scopes)
        or any(
            entry.status is not StoragePrepareStatus.CHANGED
            or entry.completion_state != "completed"
            for entry in evidence.record.entries
        )
    ):
        raise StateConflictError("deploy storage-prepare execution is not complete")
    entries = evidence.record.entries
    result_digest = _digest_object([entry.result_digest for entry in entries])
    evidence_digest = _digest_object([entry.evidence_digest for entry in entries])
    device_set_digest = _digest_object(
        [
            {
                "device_set_digest": entry.device_set_digest,
                "stable_id": entry.stable_id,
            }
            for entry in entries
        ]
    )
    return DeployStoragePrepareExecutionReport(
        operation_id=context.binding.operation_id,
        execution_state=execution.record.state,
        execution_artifact_state=execution_state,
        evidence_artifact_state=evidence_state,
        execution_artifact_digest=execution.artifact_digest,
        evidence_artifact_digest=evidence.artifact_digest,
        binding_digest=context.binding.binding_digest,
        authorization_artifact_digest=context.authorization.artifact_digest,
        authorization_digest=context.authorization.record.authorization_digest,
        general_authorization_consumed=(
            execution.record.general_authorization_consumed
        ),
        general_proof_digest=context.authorization.record.general_proof.proof_digest,
        wipe_proof_state=(
            "consumed" if context.binding.wipe_scope_count else "not-required"
        ),
        wipe_proof_digest=context.binding.wipe_proof_digest,
        wipe_authorization_consumed_count=(
            execution.record.wipe_authorization_consumed_count
        ),
        wipe_authorization_consumed_target_set_digest=(
            execution.record.wipe_authorization_consumed_target_set_digest
        ),
        stage=_STAGE,
        scope_kind=_SCOPE_KIND,
        invocation_count=execution.record.invocation_count,
        scope_count=context.binding.scope_count,
        stable_id_count=context.binding.stable_id_count,
        stable_id_set_digest=context.binding.stable_id_set_digest,
        wipe_scope_count=context.binding.wipe_scope_count,
        prepared_count=len(execution.record.attempts),
        started_count=execution.record.invocation_count,
        succeeded_count=sum(
            item.state is DeployStoragePrepareExecutionState.SUCCEEDED
            for item in execution.record.attempts
        ),
        changed_count=sum(
            entry.status is StoragePrepareStatus.CHANGED for entry in entries
        ),
        wipe_applied_count=sum(entry.wipe_applied for entry in entries),
        device_count=sum(entry.device_count for entry in entries),
        device_set_digest=device_set_digest,
        result_digest=result_digest,
        evidence_digest=evidence_digest,
        manual_recovery_required=False,
        automatic_retry_allowed=False,
        skip_allowed=False,
        continue_after_uncertainty_allowed=False,
        rollback_performed=False,
        reconciliation_state="not-performed",
        postcheck_state="not-performed",
        journal_status=context.binding.journal_status,
        journal_phase=context.binding.journal_phase,
    )


def _validate_execution_transition(
    current: DeployStoragePrepareExecution,
    replacement: DeployStoragePrepareExecution,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or current.all_scopes_completed
        or current.state
        not in {
            DeployStoragePrepareExecutionState.PREPARED,
            DeployStoragePrepareExecutionState.STARTED,
            DeployStoragePrepareExecutionState.SUCCEEDED,
        }
    ):
        raise StatePersistenceError(
            "deploy storage-prepare execution transition is invalid"
        )
    if current.state is DeployStoragePrepareExecutionState.PREPARED:
        valid = (
            len(replacement.attempts) == len(current.attempts)
            and replacement.attempts[:-1] == current.attempts[:-1]
            and _attempt_identity(replacement.attempts[-1])
            == _attempt_identity(current.attempts[-1])
            and replacement.attempts[-1].state
            is DeployStoragePrepareExecutionState.STARTED
        )
    elif current.state is DeployStoragePrepareExecutionState.STARTED:
        valid = (
            len(replacement.attempts) == len(current.attempts)
            and replacement.attempts[:-1] == current.attempts[:-1]
            and _attempt_identity(replacement.attempts[-1])
            == _attempt_identity(current.attempts[-1])
            and replacement.attempts[-1].started_at == current.attempts[-1].started_at
            and replacement.attempts[-1].general_authorization_consumed_at_start
            == current.attempts[-1].general_authorization_consumed_at_start
            and replacement.attempts[-1].wipe_authorization_consumed_at_start
            == current.attempts[-1].wipe_authorization_consumed_at_start
            and replacement.attempts[-1].state
            not in {
                DeployStoragePrepareExecutionState.PREPARED,
                DeployStoragePrepareExecutionState.STARTED,
            }
        )
    else:
        valid = (
            len(current.attempts) < current.binding.scope_count
            and replacement.attempts[:-1] == current.attempts
            and replacement.attempts[-1].state
            is DeployStoragePrepareExecutionState.PREPARED
        )
    if not valid:
        raise StatePersistenceError(
            "deploy storage-prepare execution transition conflicts"
        )


def _attempt_identity(
    attempt: DeployStoragePrepareExecutionAttempt,
) -> tuple[object, ...]:
    return (
        attempt.attempt_index,
        attempt.step_sequence,
        attempt.stable_id,
        attempt.action,
        attempt.disposition,
        attempt.device_count,
        attempt.device_set_digest,
        attempt.preparation_intent_digest,
        attempt.wipe_required,
        attempt.authorization_scope_digest,
        attempt.variables_digest,
        attempt.command_digest,
        attempt.source_digest,
        attempt.result_schema_version,
        attempt.prepared_at,
    )


def _failure_state(error: AnsibleError) -> DeployStoragePrepareExecutionState:
    if isinstance(error, AnsibleResultError):
        return DeployStoragePrepareExecutionState.MALFORMED_RESULT
    cause = error.__cause__
    if isinstance(cause, ProcessTimeoutError):
        return DeployStoragePrepareExecutionState.TIMED_OUT
    if isinstance(cause, ProcessOutputError):
        return DeployStoragePrepareExecutionState.MALFORMED_RESULT
    return DeployStoragePrepareExecutionState.FAILED


def _binding_digests(
    binding: DeployStoragePrepareExecutionBinding,
) -> tuple[str | None, ...]:
    return tuple(
        cast(str | None, getattr(binding, name))
        for name in binding.__dataclass_fields__
        if name.endswith("_digest")
    )


def _binding_digest(binding: DeployStoragePrepareExecutionBinding) -> str:
    value = binding.to_object()
    value["binding_digest"] = ""
    return _digest_object(value)


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployStoragePrepareExecutionBinding.__dataclass_fields__.items():
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


def _entry_evidence_digest(entry: DeployStoragePrepareEvidenceEntry) -> str:
    value = entry.to_object()
    value["evidence_digest"] = ""
    return _digest_object(value)


def _entry_evidence_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployStoragePrepareEvidenceEntry.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = item.value if isinstance(item, StrEnum) else item
    value["evidence_digest"] = ""
    return _digest_object(value)


def _require_canonical_paths(paths: StatePaths) -> None:
    if StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths:
        raise StatePersistenceError(
            "deploy storage-prepare execution paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy storage-prepare execution requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy storage-prepare execution artifacts"
        ) from error
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_STORAGE_PREPARE_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_STORAGE_PREPARE_EVIDENCE_FILENAME_SUFFIX,
    )
    forbidden_fragments = (
        ".ansible-deploy-post-storage-prepare-reconciliation.json",
        ".ansible-deploy-storage-postcheck",
    )
    for entry in entries:
        if entry.name.startswith(canonical) and any(
            fragment in entry.name for fragment in forbidden_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy storage-prepare execution refuses later-stage history"
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
                    "deploy storage-prepare execution artifacts are ambiguous"
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


def _require_operation_id(value: uuid.UUID) -> uuid.UUID:
    if not isinstance(value, uuid.UUID):
        raise StatePersistenceError(
            "deploy storage-prepare execution operation ID is invalid"
        )
    return value


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
            "deploy storage-prepare toolchain version is invalid"
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


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise StatePersistenceError(f"{label} must be an array")
    return value


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
    if value is None:
        return None
    return _boolean(value, label)


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
    "ANSIBLE_DEPLOY_STORAGE_PREPARE_EVIDENCE_ENTRY_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_STORAGE_PREPARE_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_BINDING_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_SCHEMA_VERSION",
    "DEPLOY_STORAGE_PREPARE_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_STORAGE_PREPARE_EXECUTION_FILENAME_SUFFIX",
    "DeployStoragePrepareArtifactState",
    "DeployStoragePrepareEvidence",
    "DeployStoragePrepareEvidenceEntry",
    "DeployStoragePrepareEvidenceStore",
    "DeployStoragePrepareExecution",
    "DeployStoragePrepareExecutionAttempt",
    "DeployStoragePrepareExecutionBinding",
    "DeployStoragePrepareExecutionReport",
    "DeployStoragePrepareExecutionState",
    "DeployStoragePrepareExecutionStore",
    "StoredDeployStoragePrepareEvidence",
    "StoredDeployStoragePrepareExecution",
    "deploy_storage_prepare_evidence_id_from_filename",
    "deploy_storage_prepare_evidence_path",
    "deploy_storage_prepare_execution_id_from_filename",
    "deploy_storage_prepare_execution_path",
    "execute_deploy_storage_prepare",
]
