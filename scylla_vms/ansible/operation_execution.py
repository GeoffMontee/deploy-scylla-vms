"""Durable, single-step internal Ansible operation execution handoff."""

import ipaddress
import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast

from scylla_vms.ansible.commands import ansible_command_intent_digest
from scylla_vms.ansible.operation_authorization import (
    ANSIBLE_OPERATION_AUTHORIZATION_SCHEMA_VERSION,
)
from scylla_vms.ansible.operation_binding import (
    ANSIBLE_OPERATION_BINDING_SCHEMA_VERSION,
    OperationPlanBindingStore,
    OperationResumeValidation,
    StoredOperationPlanBinding,
    validate_operation_plan_checkpoint_for_execution,
)
from scylla_vms.ansible.operation_context import OperationContextStore
from scylla_vms.ansible.operation_evidence import (
    verify_persisted_operation_evidence_entry,
)
from scylla_vms.ansible.orchestration import (
    ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION,
    AnsibleOperationPlan,
    AnsibleOperationPlanStatus,
    AnsibleOperationPlanStep,
    AnsibleOperationStepStatus,
    AnsibleStepIntent,
)
from scylla_vms.ansible.readiness import READINESS_SCHEMA_VERSION, ReadinessReport
from scylla_vms.ansible.registry import (
    OPERATION_PLAYBOOKS,
    CheckMode,
    PlaybookDefinition,
    get_playbook,
)
from scylla_vms.ansible.source import AnsibleSourceBundle, load_ansible_source_bundle
from scylla_vms.errors import (
    AnsibleError,
    ConfigurationError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.journal import JOURNAL_SCHEMA_VERSION, JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.models import OperationRequest
from scylla_vms.operations import OperationClassification, get_operation
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
from scylla_vms.state import (
    StatePaths,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)

ANSIBLE_OPERATION_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-operation-execution/v1"
)
OPERATION_EXECUTION_FILENAME_SUFFIX = ".ansible-operation-execution.json"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SOURCE_VERSION = re.compile(r"[a-z][a-z0-9-]{0,63}/v[1-9][0-9]{0,8}\Z")
_CLASSIFICATION_RANK = {
    OperationClassification.READ_ONLY: 0,
    OperationClassification.MUTATING: 1,
    OperationClassification.SENSITIVE: 2,
    OperationClassification.DESTRUCTIVE: 3,
}
_EXECUTOR_RECEIPT_FIELDS = {
    "command_digest",
    "evidence_digest",
    "exit_code",
    "playbook",
    "schema_version",
    "status",
    "step_sequence",
}


class AuthorizationConsumption(StrEnum):
    """How the immutable authorization applies to this execution record."""

    NOT_REQUIRED = "not-required"
    CONSUMED = "consumed"


class ExecutionAttemptState(StrEnum):
    """Durable intent and bounded terminal outcomes for one exact step."""

    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"


class ExecutorReceiptStatus(StrEnum):
    """Strict statuses an executor adapter may return after result parsing."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNREACHABLE = "unreachable"


class OperationStepTimedOut(AnsibleError):
    """The injected executor cannot prove completion before its deadline."""


class OperationStepInterrupted(AnsibleError):
    """The injected executor was interrupted after invocation began."""


class OperationStepMalformedResult(AnsibleError):
    """The executor could not produce strict bounded result evidence."""


@dataclass(frozen=True, slots=True)
class OperationStepExecution:
    """One exact executor request; variable values are runtime-only."""

    operation_id: uuid.UUID
    operation: str
    step_sequence: int
    playbook: str
    classification: OperationClassification
    limit: tuple[str, ...]
    variables: Mapping[str, object] = field(repr=False)
    tags: tuple[str, ...]
    check: bool
    diff: bool
    verbosity: int
    variables_digest: str
    command_digest: str
    playbook_source_digest: str
    result_schema_version: str

    def to_public_object(self) -> dict[str, object]:
        """Project only stable IDs and immutable command/source digests."""

        return {
            "classification": self.classification.value,
            "command_digest": self.command_digest,
            "limit": list(self.limit),
            "operation": self.operation,
            "operation_id": str(self.operation_id),
            "playbook": self.playbook,
            "playbook_source_digest": self.playbook_source_digest,
            "result_schema_version": self.result_schema_version,
            "step_sequence": self.step_sequence,
            "variables_digest": self.variables_digest,
        }


class OperationStepExecutor(Protocol):
    """Adapter boundary that returns a strict, already-parsed result receipt."""

    def execute(self, step: OperationStepExecution) -> Mapping[str, object]:
        """Execute exactly one supplied step and return no raw output."""


@dataclass(frozen=True, slots=True)
class ExecutionAttempt:
    """One intent-before-effect record and its optional terminal outcome."""

    attempt_index: int
    step_sequence: int
    playbook: str
    classification: OperationClassification
    limit: tuple[str, ...]
    variables_digest: str
    command_digest: str
    playbook_source_digest: str
    result_schema_version: str
    state: ExecutionAttemptState
    started_at: str
    completed_at: str | None
    exit_code: int | None
    result_digest: str | None
    manual_recovery_required: bool
    automatic_retry_allowed: bool = False

    def __post_init__(self) -> None:
        if (
            isinstance(self.attempt_index, bool)
            or not isinstance(self.attempt_index, int)
            or self.attempt_index < 1
            or isinstance(self.step_sequence, bool)
            or not isinstance(self.step_sequence, int)
            or self.step_sequence < 1
        ):
            raise StatePersistenceError("execution attempt sequence is invalid")
        try:
            definition = get_playbook(self.playbook)
        except AnsibleError as error:
            raise StatePersistenceError(
                "execution attempt playbook is not catalog-approved"
            ) from error
        if (
            not isinstance(self.classification, OperationClassification)
            or definition.classification is not self.classification
        ):
            raise StatePersistenceError(
                "execution attempt classification conflicts with the catalog"
            )
        _validate_stable_ids(self.limit)
        for label, value in (
            ("execution variables digest", self.variables_digest),
            ("execution command digest", self.command_digest),
            ("execution playbook source digest", self.playbook_source_digest),
        ):
            validate_digest(value, label)
        if self.result_schema_version != definition.execution_result_schema_version:
            raise StatePersistenceError("execution result schema conflicts")
        parse_timestamp(self.started_at)
        if not isinstance(self.state, ExecutionAttemptState):
            raise StatePersistenceError("execution attempt state is invalid")
        if not isinstance(self.manual_recovery_required, bool) or not isinstance(
            self.automatic_retry_allowed, bool
        ):
            raise StatePersistenceError("execution recovery policy is invalid")
        if self.automatic_retry_allowed:
            raise StatePersistenceError("execution attempts must never allow retry")
        if self.exit_code is not None and (
            isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)
        ):
            raise StatePersistenceError("execution result exit code is invalid")
        if self.result_digest is not None:
            validate_digest(self.result_digest, "execution result digest")

        if self.state is ExecutionAttemptState.STARTED:
            if (
                self.completed_at is not None
                or self.exit_code is not None
                or self.result_digest is not None
                or not self.manual_recovery_required
            ):
                raise StatePersistenceError(
                    "started execution attempt terminal fields conflict"
                )
            return
        if self.completed_at is None:
            raise StatePersistenceError(
                "terminal execution attempt completion time is missing"
            )
        if parse_timestamp(self.completed_at) < parse_timestamp(self.started_at):
            raise StatePersistenceError("execution attempt completion time regressed")
        if self.state is ExecutionAttemptState.SUCCEEDED:
            if (
                self.exit_code != 0
                or self.result_digest is None
                or self.manual_recovery_required
            ):
                raise StatePersistenceError(
                    "successful execution attempt evidence conflicts"
                )
        elif self.state is ExecutionAttemptState.UNREACHABLE:
            if (
                self.exit_code is None
                or self.exit_code == 0
                or self.result_digest is None
                or not self.manual_recovery_required
            ):
                raise StatePersistenceError(
                    "failed execution attempt evidence conflicts"
                )
        elif self.state is ExecutionAttemptState.FAILED:
            has_result = self.exit_code is not None or self.result_digest is not None
            if (
                has_result and (self.exit_code is None or self.result_digest is None)
            ) or not self.manual_recovery_required:
                raise StatePersistenceError(
                    "failed execution attempt evidence conflicts"
                )
        elif (
            self.exit_code is not None
            or self.result_digest is not None
            or not self.manual_recovery_required
        ):
            raise StatePersistenceError(
                "uncertain execution attempt evidence conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "attempt_index": self.attempt_index,
            "automatic_retry_allowed": self.automatic_retry_allowed,
            "classification": self.classification.value,
            "command_digest": self.command_digest,
            "completed_at": self.completed_at,
            "exit_code": self.exit_code,
            "limit": list(self.limit),
            "manual_recovery_required": self.manual_recovery_required,
            "playbook": self.playbook,
            "playbook_source_digest": self.playbook_source_digest,
            "result_digest": self.result_digest,
            "result_schema_version": self.result_schema_version,
            "started_at": self.started_at,
            "state": self.state.value,
            "step_sequence": self.step_sequence,
            "variables_digest": self.variables_digest,
        }

    def to_public_object(self) -> dict[str, object]:
        """Return a path-, value-, output-, address-, and key-free projection."""

        return self.to_object()

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> "ExecutionAttempt":
        require_exact_keys(
            value,
            {
                "attempt_index",
                "automatic_retry_allowed",
                "classification",
                "command_digest",
                "completed_at",
                "exit_code",
                "limit",
                "manual_recovery_required",
                "playbook",
                "playbook_source_digest",
                "result_digest",
                "result_schema_version",
                "started_at",
                "state",
                "step_sequence",
                "variables_digest",
            },
            "execution attempt",
        )
        limit_value = value["limit"]
        if not isinstance(limit_value, list) or not all(
            isinstance(item, str) for item in limit_value
        ):
            raise StatePersistenceError("execution attempt limit is invalid")
        try:
            classification = OperationClassification(
                require_string(value, "classification")
            )
            state = ExecutionAttemptState(require_string(value, "state"))
        except ValueError as error:
            raise StatePersistenceError("execution attempt enum is invalid") from error
        return cls(
            attempt_index=_integer(value["attempt_index"], "execution attempt index"),
            step_sequence=_integer(value["step_sequence"], "execution step sequence"),
            playbook=require_string(value, "playbook"),
            classification=classification,
            limit=tuple(cast(list[str], limit_value)),
            variables_digest=require_string(value, "variables_digest"),
            command_digest=require_string(value, "command_digest"),
            playbook_source_digest=require_string(value, "playbook_source_digest"),
            result_schema_version=require_string(value, "result_schema_version"),
            state=state,
            started_at=require_string(value, "started_at"),
            completed_at=_optional_string(value["completed_at"], "completed_at"),
            exit_code=_optional_integer(value["exit_code"], "execution exit code"),
            result_digest=_optional_string(value["result_digest"], "result_digest"),
            manual_recovery_required=_boolean(
                value["manual_recovery_required"], "manual recovery"
            ),
            automatic_retry_allowed=_boolean(
                value["automatic_retry_allowed"], "automatic retry"
            ),
        )


@dataclass(frozen=True, slots=True)
class OperationExecution:
    """Durable execution companion; the common v1 journal remains at PLAN."""

    generation: int
    created_at: str
    updated_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    operation_classification: OperationClassification
    effective_classification: OperationClassification
    request_digest: str
    plan_schema_version: str
    plan_digest: str
    binding_schema_version: str
    binding_generation: int
    binding_digest: str
    authorization_consumption: AuthorizationConsumption
    authorization_schema_version: str | None
    authorization_generation: int | None
    authorization_digest: str | None
    authorization_consumed_at: str | None
    catalog_digest: str
    source_version: str
    source_digest: str
    readiness_schema_version: str
    readiness_digest: str
    observation_generation: int
    observation_digest: str
    inventory_generation: int
    inventory_digest: str
    trust_generation: int
    trust_digest: str
    journal_schema_version: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    checkpoint_revalidation_digest: str
    executable_step_count: int
    state: ExecutionAttemptState
    all_steps_completed: bool
    attempts: tuple[ExecutionAttempt, ...]
    schema_version: str = ANSIBLE_OPERATION_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != ANSIBLE_OPERATION_EXECUTION_SCHEMA_VERSION:
            raise StatePersistenceError(
                "unsupported Ansible operation execution schema version"
            )
        _validate_generation(self.generation, "execution")
        if not isinstance(self.cluster_uuid, uuid.UUID) or not isinstance(
            self.operation_id, uuid.UUID
        ):
            raise StatePersistenceError("execution identities must be UUIDs")
        try:
            validate_cluster_name(self.cluster_name)
            operation = get_operation(self.operation)
        except (ConfigurationError, KeyError) as error:
            raise StatePersistenceError("execution identity is invalid") from error
        if (
            operation.classification is not self.operation_classification
            or not isinstance(self.effective_classification, OperationClassification)
            or _CLASSIFICATION_RANK[self.effective_classification]
            < _CLASSIFICATION_RANK[self.operation_classification]
        ):
            raise StatePersistenceError("execution classification conflicts")
        created = parse_timestamp(self.created_at)
        updated = parse_timestamp(self.updated_at)
        if updated < created:
            raise StatePersistenceError("execution timestamp regressed")
        for label, value in (
            ("execution request digest", self.request_digest),
            ("execution plan digest", self.plan_digest),
            ("execution binding digest", self.binding_digest),
            ("execution catalog digest", self.catalog_digest),
            ("execution source digest", self.source_digest),
            ("execution readiness digest", self.readiness_digest),
            ("execution observation digest", self.observation_digest),
            ("execution inventory digest", self.inventory_digest),
            ("execution trust digest", self.trust_digest),
            ("execution journal digest", self.journal_digest),
            (
                "execution checkpoint revalidation digest",
                self.checkpoint_revalidation_digest,
            ),
        ):
            validate_digest(value, label)
        if (
            self.plan_schema_version != ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION
            or self.binding_schema_version != ANSIBLE_OPERATION_BINDING_SCHEMA_VERSION
            or self.readiness_schema_version != READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or not _SOURCE_VERSION.fullmatch(self.source_version)
        ):
            raise StatePersistenceError("execution provenance schema conflicts")
        for generation, label in (
            (self.binding_generation, "execution binding"),
            (self.observation_generation, "execution observation"),
            (self.inventory_generation, "execution inventory"),
            (self.trust_generation, "execution trust"),
            (self.journal_generation, "execution journal"),
        ):
            _validate_generation(generation, label)
        if (
            self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.PLAN
        ):
            raise StatePersistenceError(
                "execution must remain bound to the common PLAN journal checkpoint"
            )
        if not isinstance(self.authorization_consumption, AuthorizationConsumption):
            raise StatePersistenceError("execution authorization state is invalid")
        authorization_values = (
            self.authorization_schema_version,
            self.authorization_generation,
            self.authorization_digest,
            self.authorization_consumed_at,
        )
        if self.authorization_consumption is AuthorizationConsumption.NOT_REQUIRED:
            if any(value is not None for value in authorization_values):
                raise StatePersistenceError(
                    "read-only execution authorization fields must be absent"
                )
        else:
            if (
                self.authorization_schema_version
                != ANSIBLE_OPERATION_AUTHORIZATION_SCHEMA_VERSION
                or self.authorization_generation != 1
                or self.authorization_digest is None
                or self.authorization_consumed_at is None
            ):
                raise StatePersistenceError(
                    "execution authorization consumption is incomplete"
                )
            validate_digest(
                self.authorization_digest, "consumed execution authorization digest"
            )
            parse_timestamp(self.authorization_consumed_at)
        if (
            isinstance(self.executable_step_count, bool)
            or not isinstance(self.executable_step_count, int)
            or self.executable_step_count < 1
            or not isinstance(self.state, ExecutionAttemptState)
            or not isinstance(self.all_steps_completed, bool)
            or not isinstance(self.attempts, tuple)
            or not self.attempts
            or len(self.attempts) > self.executable_step_count
            or not all(isinstance(item, ExecutionAttempt) for item in self.attempts)
        ):
            raise StatePersistenceError("execution attempt history is invalid")
        if tuple(item.attempt_index for item in self.attempts) != tuple(
            range(1, len(self.attempts) + 1)
        ) or tuple(item.step_sequence for item in self.attempts) != tuple(
            sorted({item.step_sequence for item in self.attempts})
        ):
            raise StatePersistenceError(
                "execution attempt history is duplicated or unordered"
            )
        if any(
            item.state is not ExecutionAttemptState.SUCCEEDED
            for item in self.attempts[:-1]
        ):
            raise StatePersistenceError(
                "execution cannot advance beyond an uncertain attempt"
            )
        if self.state is not self.attempts[-1].state:
            raise StatePersistenceError("execution state conflicts with latest attempt")
        expected_complete = (
            len(self.attempts) == self.executable_step_count
            and self.state is ExecutionAttemptState.SUCCEEDED
        )
        if self.all_steps_completed is not expected_complete:
            raise StatePersistenceError("execution completion state conflicts")

    def to_object(self) -> dict[str, object]:
        return {
            "all_steps_completed": self.all_steps_completed,
            "attempts": [attempt.to_object() for attempt in self.attempts],
            "authorization_consumed_at": self.authorization_consumed_at,
            "authorization_consumption": self.authorization_consumption.value,
            "authorization_digest": self.authorization_digest,
            "authorization_generation": self.authorization_generation,
            "authorization_schema_version": self.authorization_schema_version,
            "binding_digest": self.binding_digest,
            "binding_generation": self.binding_generation,
            "binding_schema_version": self.binding_schema_version,
            "catalog_digest": self.catalog_digest,
            "checkpoint_revalidation_digest": self.checkpoint_revalidation_digest,
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "created_at": self.created_at,
            "effective_classification": self.effective_classification.value,
            "executable_step_count": self.executable_step_count,
            "generation": self.generation,
            "inventory_digest": self.inventory_digest,
            "inventory_generation": self.inventory_generation,
            "journal_digest": self.journal_digest,
            "journal_generation": self.journal_generation,
            "journal_phase": self.journal_phase.value,
            "journal_schema_version": self.journal_schema_version,
            "journal_status": self.journal_status.value,
            "observation_digest": self.observation_digest,
            "observation_generation": self.observation_generation,
            "operation": self.operation,
            "operation_classification": self.operation_classification.value,
            "operation_id": str(self.operation_id),
            "plan_digest": self.plan_digest,
            "plan_schema_version": self.plan_schema_version,
            "readiness_digest": self.readiness_digest,
            "readiness_schema_version": self.readiness_schema_version,
            "request_digest": self.request_digest,
            "schema_version": self.schema_version,
            "source_digest": self.source_digest,
            "source_version": self.source_version,
            "state": self.state.value,
            "trust_digest": self.trust_digest,
            "trust_generation": self.trust_generation,
            "updated_at": self.updated_at,
        }

    def to_public_object(self) -> dict[str, object]:
        """Allowlist only states, stable step IDs, and provenance digests."""

        return {
            "all_steps_completed": self.all_steps_completed,
            "attempts": [attempt.to_public_object() for attempt in self.attempts],
            "authorization": {
                "consumption": self.authorization_consumption.value,
                "digest": self.authorization_digest,
                "schema_version": self.authorization_schema_version,
            },
            "binding_digest": self.binding_digest,
            "catalog_digest": self.catalog_digest,
            "checkpoint_revalidation_digest": self.checkpoint_revalidation_digest,
            "effective_classification": self.effective_classification.value,
            "executable_step_count": self.executable_step_count,
            "generation": self.generation,
            "journal": {
                "digest": self.journal_digest,
                "generation": self.journal_generation,
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
            },
            "operation": self.operation,
            "operation_classification": self.operation_classification.value,
            "operation_id": str(self.operation_id),
            "plan_digest": self.plan_digest,
            "readiness_digest": self.readiness_digest,
            "request_digest": self.request_digest,
            "schema_version": self.schema_version,
            "source_digest": self.source_digest,
            "state": self.state.value,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> "OperationExecution":
        require_exact_keys(
            value,
            {
                "all_steps_completed",
                "attempts",
                "authorization_consumed_at",
                "authorization_consumption",
                "authorization_digest",
                "authorization_generation",
                "authorization_schema_version",
                "binding_digest",
                "binding_generation",
                "binding_schema_version",
                "catalog_digest",
                "checkpoint_revalidation_digest",
                "cluster_name",
                "cluster_uuid",
                "created_at",
                "effective_classification",
                "executable_step_count",
                "generation",
                "inventory_digest",
                "inventory_generation",
                "journal_digest",
                "journal_generation",
                "journal_phase",
                "journal_schema_version",
                "journal_status",
                "observation_digest",
                "observation_generation",
                "operation",
                "operation_classification",
                "operation_id",
                "plan_digest",
                "plan_schema_version",
                "readiness_digest",
                "readiness_schema_version",
                "request_digest",
                "schema_version",
                "source_digest",
                "source_version",
                "state",
                "trust_digest",
                "trust_generation",
                "updated_at",
            },
            "Ansible operation execution",
        )
        if (
            require_string(value, "schema_version")
            != ANSIBLE_OPERATION_EXECUTION_SCHEMA_VERSION
        ):
            raise StatePersistenceError(
                "unsupported Ansible operation execution schema version"
            )
        attempts_value = value["attempts"]
        if not isinstance(attempts_value, list) or not all(
            isinstance(item, dict) for item in attempts_value
        ):
            raise StatePersistenceError("execution attempts are invalid")
        try:
            operation_classification = OperationClassification(
                require_string(value, "operation_classification")
            )
            effective_classification = OperationClassification(
                require_string(value, "effective_classification")
            )
            authorization_consumption = AuthorizationConsumption(
                require_string(value, "authorization_consumption")
            )
            journal_status = JournalStatus(require_string(value, "journal_status"))
            journal_phase = OperationPhase(require_string(value, "journal_phase"))
            state = ExecutionAttemptState(require_string(value, "state"))
        except ValueError as error:
            raise StatePersistenceError("execution enum is invalid") from error
        return cls(
            generation=_integer(value["generation"], "execution generation"),
            created_at=require_string(value, "created_at"),
            updated_at=require_string(value, "updated_at"),
            cluster_uuid=parse_uuid(
                require_string(value, "cluster_uuid"), "cluster UUID"
            ),
            cluster_name=require_string(value, "cluster_name"),
            operation_id=parse_uuid(
                require_string(value, "operation_id"), "operation ID"
            ),
            operation=require_string(value, "operation"),
            operation_classification=operation_classification,
            effective_classification=effective_classification,
            request_digest=require_string(value, "request_digest"),
            plan_schema_version=require_string(value, "plan_schema_version"),
            plan_digest=require_string(value, "plan_digest"),
            binding_schema_version=require_string(value, "binding_schema_version"),
            binding_generation=_integer(
                value["binding_generation"], "binding generation"
            ),
            binding_digest=require_string(value, "binding_digest"),
            authorization_consumption=authorization_consumption,
            authorization_schema_version=_optional_string(
                value["authorization_schema_version"],
                "authorization_schema_version",
            ),
            authorization_generation=_optional_integer(
                value["authorization_generation"], "authorization generation"
            ),
            authorization_digest=_optional_string(
                value["authorization_digest"], "authorization_digest"
            ),
            authorization_consumed_at=_optional_string(
                value["authorization_consumed_at"], "authorization_consumed_at"
            ),
            catalog_digest=require_string(value, "catalog_digest"),
            source_version=require_string(value, "source_version"),
            source_digest=require_string(value, "source_digest"),
            readiness_schema_version=require_string(value, "readiness_schema_version"),
            readiness_digest=require_string(value, "readiness_digest"),
            observation_generation=_integer(
                value["observation_generation"], "observation generation"
            ),
            observation_digest=require_string(value, "observation_digest"),
            inventory_generation=_integer(
                value["inventory_generation"], "inventory generation"
            ),
            inventory_digest=require_string(value, "inventory_digest"),
            trust_generation=_integer(value["trust_generation"], "trust generation"),
            trust_digest=require_string(value, "trust_digest"),
            journal_schema_version=require_string(value, "journal_schema_version"),
            journal_generation=_integer(
                value["journal_generation"], "journal generation"
            ),
            journal_digest=require_string(value, "journal_digest"),
            journal_status=journal_status,
            journal_phase=journal_phase,
            checkpoint_revalidation_digest=require_string(
                value, "checkpoint_revalidation_digest"
            ),
            executable_step_count=_integer(
                value["executable_step_count"], "executable step count"
            ),
            state=state,
            all_steps_completed=_boolean(
                value["all_steps_completed"], "all steps completed"
            ),
            attempts=tuple(
                ExecutionAttempt.from_object(cast(dict[str, object], item))
                for item in attempts_value
            ),
        )


@dataclass(frozen=True, slots=True)
class StoredOperationExecution:
    record: OperationExecution
    digest: str

    def to_public_object(self) -> dict[str, object]:
        value = self.record.to_public_object()
        value["execution_digest"] = self.digest
        return value


class OperationExecutionStore:
    """Persist one generation-guarded execution companion per operation."""

    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        _require_canonical_paths(paths)
        if not isinstance(operation_id, uuid.UUID):
            raise StatePersistenceError("operation execution ID must be a UUID")
        self._paths = paths
        self._operation_id = operation_id
        self._path = operation_execution_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path,
            replace=replace_file,
            token_factory=token_factory,
        )

    @property
    def path(self) -> Path:
        return self._path

    def read_locked(
        self,
        lock: object,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
        expected_operation: str | None = None,
    ) -> StoredOperationExecution:
        _assert_read_lock(lock, self._paths)
        value, digest = self._file.read()
        record = OperationExecution.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or (
                expected_operation is not None
                and record.operation != expected_operation
            )
        ):
            raise StatePersistenceError("Ansible operation execution identity mismatch")
        return StoredOperationExecution(record, digest)

    def write_locked(
        self,
        record: OperationExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredOperationExecution:
        _assert_operation_lock(lock, self._paths, record.operation)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError("Ansible operation execution ID mismatch")
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial operation execution write requires generation one"
                )
        else:
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
                expected_operation=record.operation,
            )
            if (
                expected_digest is None
                or current.digest != expected_digest
                or current.record.generation != expected_generation
            ):
                raise StatePersistenceError(
                    "Ansible operation execution changed concurrently"
                )
            _validate_execution_transition(current.record, record)
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredOperationExecution(record, digest)


def handoff_operation_step(
    lock: ClusterLock,
    metadata: ClusterMetadata,
    request: OperationRequest,
    operation_id: uuid.UUID,
    plan: AnsibleOperationPlan,
    readiness: ReadinessReport,
    intents: tuple[AnsibleStepIntent, ...],
    executor: OperationStepExecutor,
    *,
    clock: Callable[[], datetime],
    store: OperationExecutionStore | None = None,
) -> StoredOperationExecution:
    """Durably start, invoke, and checkpoint at most one deterministic step."""

    _assert_operation_lock(lock, request.paths, request.operation.name)
    validation = validate_operation_plan_checkpoint_for_execution(
        lock,
        metadata,
        request,
        operation_id,
        plan,
        readiness,
    )
    source = load_ansible_source_bundle()
    steps = _validate_ready_plan_and_intents(plan, intents, source)
    binding = OperationPlanBindingStore(request.paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
        expected_operation=request.operation.name,
    )
    selected_store = store or OperationExecutionStore(request.paths, operation_id)
    if selected_store.path != operation_execution_path(request.paths, operation_id):
        raise StateConflictError("operation execution store scope conflicts")
    validate_state_file(selected_store.path, allow_missing=True)
    existing = (
        selected_store.read_locked(
            lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
            expected_operation=request.operation.name,
        )
        if selected_store.path.exists()
        else None
    )
    if existing is not None:
        _validate_current_execution(
            existing.record,
            validation,
            binding.digest,
            steps,
        )
        if existing.record.state is not ExecutionAttemptState.SUCCEEDED:
            raise StateConflictError(
                "started or uncertain execution requires manual recovery review"
            )
        if existing.record.all_steps_completed:
            raise StateConflictError(
                "operation execution step set was already fully consumed"
            )
        step, intent, command_digest, playbook_source_digest = steps[
            len(existing.record.attempts)
        ]
        started_at = format_timestamp(clock())
        attempt = _started_attempt(
            existing.record,
            step,
            intent,
            command_digest,
            playbook_source_digest,
            started_at,
        )
        started_record = replace(
            existing.record,
            generation=existing.record.generation + 1,
            updated_at=started_at,
            state=ExecutionAttemptState.STARTED,
            all_steps_completed=False,
            attempts=(*existing.record.attempts, attempt),
        )
        started = selected_store.write_locked(
            started_record,
            expected_generation=existing.record.generation,
            expected_digest=existing.digest,
            lock=lock,
        )
    else:
        step, intent, command_digest, playbook_source_digest = steps[0]
        started_at = format_timestamp(clock())
        attempt = _started_attempt(
            None,
            step,
            intent,
            command_digest,
            playbook_source_digest,
            started_at,
        )
        record = _initial_execution_record(
            metadata,
            request,
            operation_id,
            plan,
            validation,
            binding,
            len(steps),
            attempt,
            started_at,
        )
        started = selected_store.write_locked(
            record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )

    execution = _executor_request(
        operation_id,
        request.operation.name,
        step,
        intent,
        command_digest,
        playbook_source_digest,
    )
    try:
        receipt = executor.execute(execution)
    except OperationStepTimedOut:
        return _finish_attempt(
            selected_store,
            started,
            ExecutionAttemptState.TIMED_OUT,
            clock=clock,
            lock=lock,
        )
    except OperationStepInterrupted:
        return _finish_attempt(
            selected_store,
            started,
            ExecutionAttemptState.INTERRUPTED,
            clock=clock,
            lock=lock,
        )
    except OperationStepMalformedResult:
        _finish_attempt(
            selected_store,
            started,
            ExecutionAttemptState.MALFORMED_RESULT,
            clock=clock,
            lock=lock,
        )
        raise AnsibleError(
            "operation step executor returned malformed strict result evidence"
        ) from None
    except KeyboardInterrupt:
        _finish_attempt(
            selected_store,
            started,
            ExecutionAttemptState.INTERRUPTED,
            clock=clock,
            lock=lock,
        )
        raise
    except Exception as error:
        _finish_attempt(
            selected_store,
            started,
            ExecutionAttemptState.FAILED,
            clock=clock,
            lock=lock,
        )
        raise AnsibleError("operation step executor failed after invocation") from error

    try:
        state, exit_code, evidence_digest, result_digest = _parse_executor_receipt(
            receipt, execution
        )
    except (AnsibleError, StatePersistenceError, KeyError, TypeError, ValueError):
        _finish_attempt(
            selected_store,
            started,
            ExecutionAttemptState.MALFORMED_RESULT,
            clock=clock,
            lock=lock,
        )
        raise AnsibleError(
            "operation step executor returned malformed strict result evidence"
        ) from None
    if (
        request.operation.name == "check-jump-hosts"
        and state is ExecutionAttemptState.SUCCEEDED
    ):
        try:
            operation_context = OperationContextStore(
                request.paths, operation_id
            ).read_locked(
                lock,
                expected_cluster_uuid=metadata.cluster_uuid,
                expected_cluster_name=metadata.cluster_name,
                expected_operation=request.operation.name,
            )
            verify_persisted_operation_evidence_entry(
                lock,
                request.paths,
                binding,
                operation_context,
                readiness,
                execution,
                evidence_digest,
            )
        except (
            StateConflictError,
            StateLockError,
            StatePersistenceError,
            UnsafePathError,
        ):
            _finish_attempt(
                selected_store,
                started,
                ExecutionAttemptState.MALFORMED_RESULT,
                clock=clock,
                lock=lock,
            )
            raise AnsibleError(
                "operation step durable semantic evidence is missing or mismatched"
            ) from None
    return _finish_attempt(
        selected_store,
        started,
        state,
        clock=clock,
        lock=lock,
        exit_code=exit_code,
        result_digest=result_digest,
    )


def operation_execution_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError("operation execution ID must be a UUID")
    path = paths.operations / f"{operation_id}{OPERATION_EXECUTION_FILENAME_SUFFIX}"
    if path.parent != paths.operations:
        raise StatePersistenceError("Ansible operation execution path is not canonical")
    return path


def operation_execution_id_from_filename(name: str) -> uuid.UUID | None:
    if not name.endswith(OPERATION_EXECUTION_FILENAME_SUFFIX):
        return None
    identifier_text = name[: -len(OPERATION_EXECUTION_FILENAME_SUFFIX)]
    try:
        identifier = uuid.UUID(identifier_text)
    except ValueError:
        return None
    return identifier if str(identifier) == identifier_text else None


def executor_result_receipt(
    step: OperationStepExecution,
    status: ExecutorReceiptStatus,
    *,
    exit_code: int,
    evidence_digest: str,
) -> dict[str, object]:
    """Build the strict no-output receipt used by fake and future adapters."""

    return {
        "command_digest": step.command_digest,
        "evidence_digest": evidence_digest,
        "exit_code": exit_code,
        "playbook": step.playbook,
        "schema_version": step.result_schema_version,
        "status": status.value,
        "step_sequence": step.step_sequence,
    }


def _validate_ready_plan_and_intents(
    plan: AnsibleOperationPlan,
    intents: tuple[AnsibleStepIntent, ...],
    source: AnsibleSourceBundle,
) -> tuple[tuple[AnsibleOperationPlanStep, AnsibleStepIntent, str, str], ...]:
    if (
        plan.schema_version != ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION
        or plan.status is not AnsibleOperationPlanStatus.READY
        or not plan.operation_implemented
        or plan.blockers
    ):
        raise StateConflictError(
            "operation execution requires an unblocked internally executable plan"
        )
    mapped = OPERATION_PLAYBOOKS.get(plan.operation)
    if mapped is None or len(mapped) != len(plan.steps):
        raise StateConflictError("operation execution plan catalog shape drifted")
    intents_by_sequence = {intent.sequence: intent for intent in intents}
    if (
        not isinstance(intents, tuple)
        or len(intents_by_sequence) != len(intents)
        or any(not isinstance(intent, AnsibleStepIntent) for intent in intents)
    ):
        raise StateConflictError("operation execution intents are invalid")
    selected_conditions = set(plan.active_conditions)
    selected: list[tuple[AnsibleOperationPlanStep, AnsibleStepIntent, str, str]] = []
    source_digests = {item.path: item.digest for item in source.files}
    selected_classifications: list[OperationClassification] = [
        plan.operation_classification
    ]
    for sequence, (mapped_step, step) in enumerate(
        zip(mapped, plan.steps, strict=True), start=1
    ):
        expected_selected = (
            mapped_step.condition == "always"
            or mapped_step.condition in selected_conditions
        )
        if (
            step.sequence != sequence
            or step.playbook != mapped_step.playbook
            or step.condition != mapped_step.condition
        ):
            raise StateConflictError(
                "operation execution plan catalog position drifted"
            )
        definition = get_playbook(step.playbook)
        if step.classification is not definition.classification:
            raise StateConflictError("operation execution step classification drifted")
        if not expected_selected:
            if (
                step.status is not AnsibleOperationStepStatus.SKIPPED
                or step.limit
                or step.variable_names
                or step.variables_digest is not None
                or step.check_mode is not None
                or step.blockers
                or sequence in intents_by_sequence
            ):
                raise StateConflictError(
                    "operation execution skipped step binding drifted"
                )
            continue
        if (
            step.status is not AnsibleOperationStepStatus.READY
            or step.blockers
            or not definition.source_available
        ):
            raise StateConflictError("operation execution selected step is not ready")
        intent = intents_by_sequence.get(sequence)
        if intent is None:
            raise StateConflictError("operation execution step intent is missing")
        variables_digest, command_digest = _validate_step_intent(
            definition, step, intent
        )
        playbook_source_digest = source_digests.get(f"playbooks/{definition.filename}")
        if playbook_source_digest is None:
            raise StateConflictError(
                "operation execution playbook source binding is missing"
            )
        validate_digest(
            playbook_source_digest, "operation execution playbook source digest"
        )
        selected.append(
            (
                step,
                intent,
                command_digest,
                playbook_source_digest,
            )
        )
        selected_classifications.append(definition.classification)
        if variables_digest != step.variables_digest:
            raise StateConflictError("operation execution variables digest drifted")
    if set(intents_by_sequence) != {item[0].sequence for item in selected}:
        raise StateConflictError("operation execution intent set drifted")
    effective = max(selected_classifications, key=_CLASSIFICATION_RANK.__getitem__)
    if not selected or effective is not plan.effective_classification:
        raise StateConflictError("operation execution effective classification drifted")
    return tuple(selected)


def _validate_step_intent(
    definition: PlaybookDefinition,
    step: AnsibleOperationPlanStep,
    intent: AnsibleStepIntent,
) -> tuple[str, str]:
    definition.validate_limit(intent.limit)
    if intent.limit != step.limit or intent.check is not step.check_mode:
        raise StateConflictError("operation execution limit or check mode drifted")
    if intent.check and definition.check_mode is CheckMode.REFUSED:
        raise StateConflictError("operation execution check mode is refused")
    if intent.diff and (not intent.check or not definition.diff_mode):
        raise StateConflictError("operation execution diff mode is refused")
    if (
        isinstance(intent.verbosity, bool)
        or not isinstance(intent.verbosity, int)
        or not 0 <= intent.verbosity <= 3
        or intent.tags != tuple(dict.fromkeys(intent.tags))
        or not set(intent.tags) <= set(definition.tags)
    ):
        raise StateConflictError("operation execution command policy drifted")
    validated = definition.validate_variables(dict(intent.variables))
    variables_digest = digest_bytes(serialize_json(validated))
    if tuple(validated) != step.variable_names:
        raise StateConflictError("operation execution variable names drifted")
    command_digest = ansible_command_intent_digest(
        definition,
        step_sequence=step.sequence,
        limit=intent.limit,
        variables_digest=variables_digest,
        tags=intent.tags,
        check=intent.check,
        diff=intent.diff,
        verbosity=intent.verbosity,
    )
    return variables_digest, command_digest


def _started_attempt(
    current: OperationExecution | None,
    step: AnsibleOperationPlanStep,
    intent: AnsibleStepIntent,
    command_digest: str,
    playbook_source_digest: str,
    started_at: str,
) -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_index=1 if current is None else len(current.attempts) + 1,
        step_sequence=step.sequence,
        playbook=step.playbook,
        classification=step.classification,
        limit=step.limit,
        variables_digest=cast(str, step.variables_digest),
        command_digest=command_digest,
        playbook_source_digest=playbook_source_digest,
        result_schema_version=get_playbook(
            step.playbook
        ).execution_result_schema_version,
        state=ExecutionAttemptState.STARTED,
        started_at=started_at,
        completed_at=None,
        exit_code=None,
        result_digest=None,
        manual_recovery_required=True,
    )


def _initial_execution_record(
    metadata: ClusterMetadata,
    request: OperationRequest,
    operation_id: uuid.UUID,
    plan: AnsibleOperationPlan,
    validation: OperationResumeValidation,
    binding: StoredOperationPlanBinding,
    executable_step_count: int,
    attempt: ExecutionAttempt,
    timestamp: str,
) -> OperationExecution:
    consumed = validation.authorization_digest is not None
    bound = binding.record
    return OperationExecution(
        generation=1,
        created_at=timestamp,
        updated_at=timestamp,
        cluster_uuid=metadata.cluster_uuid,
        cluster_name=metadata.cluster_name,
        operation_id=operation_id,
        operation=request.operation.name,
        operation_classification=request.operation.classification,
        effective_classification=plan.effective_classification,
        request_digest=validation.request_digest,
        plan_schema_version=plan.schema_version,
        plan_digest=validation.plan_digest,
        binding_schema_version=bound.schema_version,
        binding_generation=bound.generation,
        binding_digest=binding.digest,
        authorization_consumption=(
            AuthorizationConsumption.CONSUMED
            if consumed
            else AuthorizationConsumption.NOT_REQUIRED
        ),
        authorization_schema_version=validation.authorization_schema_version,
        authorization_generation=1 if consumed else None,
        authorization_digest=validation.authorization_digest,
        authorization_consumed_at=timestamp if consumed else None,
        catalog_digest=validation.catalog_digest,
        source_version=bound.source_version,
        source_digest=validation.source_digest,
        readiness_schema_version=bound.readiness_schema_version,
        readiness_digest=validation.readiness_digest,
        observation_generation=cast(int, bound.observation_generation),
        observation_digest=cast(str, bound.observation_digest),
        inventory_generation=bound.inventory_generation,
        inventory_digest=bound.inventory_digest,
        trust_generation=cast(int, bound.trust_generation),
        trust_digest=cast(str, bound.trust_digest),
        journal_schema_version=bound.journal_schema_version,
        journal_generation=bound.journal_generation,
        journal_digest=bound.journal_digest,
        journal_status=JournalStatus.IN_PROGRESS,
        journal_phase=OperationPhase.PLAN,
        checkpoint_revalidation_digest=validation.revalidation_digest,
        executable_step_count=executable_step_count,
        state=ExecutionAttemptState.STARTED,
        all_steps_completed=False,
        attempts=(attempt,),
    )


def _executor_request(
    operation_id: uuid.UUID,
    operation: str,
    step: AnsibleOperationPlanStep,
    intent: AnsibleStepIntent,
    command_digest: str,
    playbook_source_digest: str,
) -> OperationStepExecution:
    return OperationStepExecution(
        operation_id=operation_id,
        operation=operation,
        step_sequence=step.sequence,
        playbook=step.playbook,
        classification=step.classification,
        limit=step.limit,
        variables=dict(intent.variables),
        tags=intent.tags,
        check=intent.check,
        diff=intent.diff,
        verbosity=intent.verbosity,
        variables_digest=cast(str, step.variables_digest),
        command_digest=command_digest,
        playbook_source_digest=playbook_source_digest,
        result_schema_version=get_playbook(
            step.playbook
        ).execution_result_schema_version,
    )


def _parse_executor_receipt(
    value: Mapping[str, object],
    expected: OperationStepExecution,
) -> tuple[ExecutionAttemptState, int, str, str]:
    if not isinstance(value, Mapping):
        raise AnsibleError("executor result receipt must be an object")
    require_exact_keys(value, _EXECUTOR_RECEIPT_FIELDS, "executor result receipt")
    if (
        require_string(value, "schema_version") != expected.result_schema_version
        or require_string(value, "playbook") != expected.playbook
        or require_string(value, "command_digest") != expected.command_digest
        or _integer(value["step_sequence"], "executor result step sequence")
        != expected.step_sequence
    ):
        raise AnsibleError("executor result receipt identity conflicts")
    evidence_digest = require_string(value, "evidence_digest")
    validate_digest(evidence_digest, "executor result evidence digest")
    exit_code = _integer(value["exit_code"], "executor result exit code")
    try:
        status = ExecutorReceiptStatus(require_string(value, "status"))
    except ValueError as error:
        raise AnsibleError("executor result receipt status is invalid") from error
    if status is ExecutorReceiptStatus.SUCCEEDED and exit_code != 0:
        raise AnsibleError("executor result status conflicts with exit code")
    state = {
        ExecutorReceiptStatus.SUCCEEDED: ExecutionAttemptState.SUCCEEDED,
        ExecutorReceiptStatus.FAILED: ExecutionAttemptState.FAILED,
        ExecutorReceiptStatus.UNREACHABLE: ExecutionAttemptState.UNREACHABLE,
    }[status]
    return (
        state,
        exit_code,
        evidence_digest,
        digest_bytes(serialize_json(dict(value))),
    )


def _finish_attempt(
    store: OperationExecutionStore,
    started: StoredOperationExecution,
    state: ExecutionAttemptState,
    *,
    clock: Callable[[], datetime],
    lock: ClusterLock,
    exit_code: int | None = None,
    result_digest: str | None = None,
) -> StoredOperationExecution:
    timestamp = format_timestamp(clock())
    attempt = replace(
        started.record.attempts[-1],
        state=state,
        completed_at=timestamp,
        exit_code=exit_code,
        result_digest=result_digest,
        manual_recovery_required=state is not ExecutionAttemptState.SUCCEEDED,
    )
    candidate = replace(
        started.record,
        generation=started.record.generation + 1,
        updated_at=timestamp,
        state=state,
        all_steps_completed=(
            state is ExecutionAttemptState.SUCCEEDED
            and len(started.record.attempts) == started.record.executable_step_count
        ),
        attempts=(*started.record.attempts[:-1], attempt),
    )
    return store.write_locked(
        candidate,
        expected_generation=started.record.generation,
        expected_digest=started.digest,
        lock=lock,
    )


def _validate_current_execution(
    current: OperationExecution,
    validation: OperationResumeValidation,
    binding_digest: str,
    steps: tuple[tuple[AnsibleOperationPlanStep, AnsibleStepIntent, str, str], ...],
) -> None:
    if (
        current.operation_id != validation.operation_id
        or current.operation != validation.operation
        or current.operation_classification is not validation.operation_classification
        or current.effective_classification is not validation.effective_classification
        or current.request_digest != validation.request_digest
        or current.plan_digest != validation.plan_digest
        or current.binding_digest != binding_digest
        or current.authorization_digest != validation.authorization_digest
        or current.catalog_digest != validation.catalog_digest
        or current.source_digest != validation.source_digest
        or current.readiness_digest != validation.readiness_digest
        or current.checkpoint_revalidation_digest != validation.revalidation_digest
        or current.executable_step_count != len(steps)
    ):
        raise StateConflictError(
            "operation execution checkpoint or current evidence drifted"
        )
    for attempt, (step, _, command_digest, source_digest) in zip(
        current.attempts, steps[: len(current.attempts)], strict=True
    ):
        if (
            attempt.step_sequence != step.sequence
            or attempt.playbook != step.playbook
            or attempt.classification is not step.classification
            or attempt.limit != step.limit
            or attempt.variables_digest != step.variables_digest
            or attempt.command_digest != command_digest
            or attempt.playbook_source_digest != source_digest
        ):
            raise StateConflictError("operation execution prior step binding drifted")


def _validate_execution_transition(
    previous: OperationExecution,
    current: OperationExecution,
) -> None:
    if current.generation != previous.generation + 1:
        raise StatePersistenceError(
            "operation execution generation must increase by exactly one"
        )
    immutable_previous = previous.to_object()
    immutable_current = current.to_object()
    for key in {
        "all_steps_completed",
        "attempts",
        "generation",
        "state",
        "updated_at",
    }:
        immutable_previous.pop(key)
        immutable_current.pop(key)
    if immutable_previous != immutable_current:
        raise StatePersistenceError(
            "operation execution identity or provenance fields are immutable"
        )
    if parse_timestamp(current.updated_at) < parse_timestamp(previous.updated_at):
        raise StatePersistenceError("operation execution update time regressed")
    if len(current.attempts) == len(previous.attempts):
        if (
            previous.state is not ExecutionAttemptState.STARTED
            or current.state is ExecutionAttemptState.STARTED
            or current.attempts[:-1] != previous.attempts[:-1]
            or replace(
                current.attempts[-1],
                state=ExecutionAttemptState.STARTED,
                completed_at=None,
                exit_code=None,
                result_digest=None,
                manual_recovery_required=True,
            )
            != previous.attempts[-1]
        ):
            raise StatePersistenceError(
                "operation execution terminal transition is invalid"
            )
        return
    if (
        len(current.attempts) != len(previous.attempts) + 1
        or previous.state is not ExecutionAttemptState.SUCCEEDED
        or previous.all_steps_completed
        or current.attempts[:-1] != previous.attempts
        or current.attempts[-1].state is not ExecutionAttemptState.STARTED
    ):
        raise StatePersistenceError("operation execution step append is invalid")


def _require_canonical_paths(paths: StatePaths) -> None:
    expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
    if expected != paths or paths.operations.parent != paths.cluster_root:
        raise UnsafePathError("Ansible operation execution paths are not canonical")


def _assert_operation_lock(
    lock: ClusterLock, paths: StatePaths, operation: str
) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Ansible operation execution requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, operation)


def _assert_read_lock(lock: object, paths: StatePaths) -> None:
    assertion = getattr(lock, "assert_held_for", None)
    if not callable(assertion):
        raise StateLockError(
            "Ansible operation execution read requires an acquired cluster lock"
        )
    assertion(paths)


def _validate_stable_ids(values: tuple[str, ...]) -> None:
    if (
        not values
        or values != tuple(dict.fromkeys(values))
        or not all(
            isinstance(value, str)
            and value.isascii()
            and _LOGICAL_ID.fullmatch(value) is not None
            and not _is_ip_address(value)
            for value in values
        )
    ):
        raise StatePersistenceError("execution stable-ID limit is invalid")


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _validate_generation(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} generation is invalid")


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    if value is None:
        return None
    return _integer(value, label)


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise StatePersistenceError(f"{label} must be null or a non-empty string")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be boolean")
    return value
