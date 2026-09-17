"""Durable operation-bound ``scylla-configure`` execution and evidence.

This internal owner consumes one exact immutable authorization, reconstructs
the protected configuration payload from canonical state, records durable
prepared/started intent before every controlled call, and permanently refuses
automatic retry after an invocation may have occurred.
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
from scylla_vms.ansible.deploy_plan import _digest_object, _require_operation_id
from scylla_vms.ansible.deploy_scylla_configure_authorization import (
    ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION,
    DeployScyllaConfigureAuthorizationScope,
    DeployScyllaConfigureAuthorizationStore,
    StoredDeployScyllaConfigureAuthorization,
    _build_authorization,
    _derive_configuration_intents,
    _DerivedConfigurationIntent,
    _load_authorization_context,
    _loaded,
)
from scylla_vms.ansible.operation_binding import readiness_binding_digest
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_configure import (
    SCYLLA_CONFIGURE_DIRECTORIES,
    SCYLLA_CONFIGURE_SCHEMA_VERSION,
    ScyllaConfigureEvidence,
    ScyllaConfigureStatus,
    parse_scylla_configure_execution,
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

ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-configure-execution-binding/v1"
)
ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-configure-execution/v1"
)
ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_ENTRY_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-configure-evidence-entry/v1"
)
ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-configure-evidence/v1"
)
ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-configure-execution-report/v1"
)

DEPLOY_SCYLLA_CONFIGURE_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-configure-execution.json"
)
DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-configure-evidence.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "scylla-configure"
_MAPPING_SEQUENCE = 12
_STAGE = "post-scylla-install-scylla-configure"
_SCOPE_KIND = "installed-scylla-configuration"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SUCCESS_STATUSES = frozenset(
    {ScyllaConfigureStatus.CHANGED, ScyllaConfigureStatus.NOOP}
)
_CONFIGURATION_FILE_COUNT = 2
_TEMPLATE_COUNT = 2


class DeployScyllaConfigureExecutionState(StrEnum):
    """Bounded durable states for one exact authorized configuration attempt."""

    PREPARED = "prepared"
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"


class DeployScyllaConfigureArtifactState(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployScyllaConfigureExecutionBinding:
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
    configuration_intent_digest: str
    post_install_reconciliation_artifact_digest: str
    post_install_reconciliation_record_digest: str
    install_execution_artifact_digest: str
    install_evidence_artifact_digest: str
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
    scope_count: int
    stable_id_count: int
    stable_id_set_digest: str
    execution_scope_digest: str
    binding_digest: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_BINDING_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_BINDING_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.scope_count < 1
            or self.stable_id_count != self.scope_count
        ):
            raise StatePersistenceError(
                "deploy scylla-configure execution binding is invalid"
            )
        validate_cluster_name(self.cluster_name)
        for count in (
            self.journal_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
            self.scope_count,
            self.stable_id_count,
        ):
            _positive_integer(count, "deploy scylla-configure binding count")
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy scylla-configure binding digest")
        _validate_toolchain_version(self.toolchain_version)
        if self.binding_digest != _binding_digest(self):
            raise StatePersistenceError(
                "deploy scylla-configure execution binding digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaConfigureExecutionBinding:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy scylla-configure execution binding",
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
            if name in {"cluster_uuid", "operation_id"}:
                parsed[name] = parse_uuid(require_string(value, name), name)
            elif name in integer_fields:
                parsed[name] = _integer(value[name], name)
            elif name == "journal_status":
                parsed[name] = _enum(JournalStatus, require_string(value, name), name)
            elif name == "journal_phase":
                parsed[name] = _enum(OperationPhase, require_string(value, name), name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployScyllaConfigureExecutionAttempt:
    """One exact prepared, started, or terminal configuration attempt."""

    attempt_index: int
    step_sequence: int
    stable_id: str
    target_digest: str
    authorization_scope_digest: str
    authorization_variables_digest: str
    authorization_command_digest: str
    variables_digest: str
    command_digest: str
    source_digest: str
    configuration_intent_digest: str
    state: DeployScyllaConfigureExecutionState
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
    result_schema_version: str = SCYLLA_CONFIGURE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.attempt_index < 1
            or self.step_sequence < 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.result_schema_version != SCYLLA_CONFIGURE_SCHEMA_VERSION
            or not isinstance(self.state, DeployScyllaConfigureExecutionState)
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy scylla-configure execution attempt is invalid"
            )
        for digest in (
            self.target_digest,
            self.authorization_scope_digest,
            self.authorization_variables_digest,
            self.authorization_command_digest,
            self.variables_digest,
            self.command_digest,
            self.source_digest,
            self.configuration_intent_digest,
            self.result_digest,
            self.evidence_digest,
        ):
            if digest is not None:
                validate_digest(digest, "deploy scylla-configure attempt digest")
        prepared = parse_timestamp(self.prepared_at)
        started = _optional_timestamp(self.started_at)
        completed = _optional_timestamp(self.completed_at)
        if (
            (started is not None and started < prepared)
            or (completed is not None and started is None)
            or (completed is not None and started is not None and completed < started)
        ):
            raise StatePersistenceError(
                "deploy scylla-configure attempt timestamps conflict"
            )
        if self.state is DeployScyllaConfigureExecutionState.PREPARED:
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
        elif self.state is DeployScyllaConfigureExecutionState.STARTED:
            valid = (
                started is not None
                and completed is None
                and self.invocation_may_have_occurred
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.manual_recovery_required
            )
        elif self.state is DeployScyllaConfigureExecutionState.SUCCEEDED:
            valid = (
                started is not None
                and completed is not None
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
                and self.invocation_may_have_occurred
                and self.result_digest is None
                and self.evidence_digest is None
                and self.manual_recovery_required
            )
        if (
            not valid
            or (
                self.state is not DeployScyllaConfigureExecutionState.PREPARED
                and self.authorization_consumed_at_start != (self.attempt_index == 1)
            )
            or (
                self.state is DeployScyllaConfigureExecutionState.PREPARED
                and self.authorization_consumed_at_start
            )
        ):
            raise StatePersistenceError(
                "deploy scylla-configure attempt state conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaConfigureExecutionAttempt:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy scylla-configure execution attempt",
        )
        try:
            return cls(
                attempt_index=_integer(value["attempt_index"], "attempt index"),
                step_sequence=_integer(value["step_sequence"], "step sequence"),
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
                configuration_intent_digest=require_string(
                    value, "configuration_intent_digest"
                ),
                state=DeployScyllaConfigureExecutionState(
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
                "deploy scylla-configure attempt state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployScyllaConfigureExecution:
    """Generation-guarded exact-prefix execution state."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployScyllaConfigureExecutionBinding
    state: DeployScyllaConfigureExecutionState
    authorization_consumed: bool
    invocation_count: int
    all_scopes_completed: bool
    attempts: tuple[DeployScyllaConfigureExecutionAttempt, ...]
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        invoked = tuple(
            attempt
            for attempt in self.attempts
            if attempt.state is not DeployScyllaConfigureExecutionState.PREPARED
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_SCHEMA_VERSION
            or self.generation < 1
            or not self.attempts
            or len(self.attempts) > self.binding.scope_count
            or self.state is not self.attempts[-1].state
            or tuple(item.attempt_index for item in self.attempts)
            != tuple(range(1, len(self.attempts) + 1))
            or any(
                attempt.state is not DeployScyllaConfigureExecutionState.SUCCEEDED
                for attempt in self.attempts[:-1]
            )
            or self.invocation_count != len(invoked)
            or self.authorization_consumed != bool(invoked)
            or self.all_scopes_completed
            != (
                self.state is DeployScyllaConfigureExecutionState.SUCCEEDED
                and len(self.attempts) == self.binding.scope_count
            )
        ):
            raise StatePersistenceError(
                "deploy scylla-configure execution summary conflicts"
            )
        if parse_timestamp(self.updated_at) < parse_timestamp(self.created_at):
            raise StatePersistenceError(
                "deploy scylla-configure execution timestamps conflict"
            )

    @property
    def manual_recovery_required(self) -> bool:
        return self.state not in {
            DeployScyllaConfigureExecutionState.PREPARED,
            DeployScyllaConfigureExecutionState.SUCCEEDED,
        } or any(item.manual_recovery_required for item in self.attempts)

    def to_object(self) -> dict[str, object]:
        return {
            "all_scopes_completed": self.all_scopes_completed,
            "attempts": [item.to_object() for item in self.attempts],
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
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaConfigureExecution:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy scylla-configure execution",
        )
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                updated_at=require_string(value, "updated_at"),
                binding=DeployScyllaConfigureExecutionBinding.from_object(
                    _mapping(value["binding"], "binding")
                ),
                state=DeployScyllaConfigureExecutionState(
                    require_string(value, "state")
                ),
                authorization_consumed=_boolean(
                    value["authorization_consumed"], "authorization consumption"
                ),
                invocation_count=_integer(
                    value["invocation_count"], "invocation count"
                ),
                all_scopes_completed=_boolean(
                    value["all_scopes_completed"], "completion"
                ),
                attempts=tuple(
                    DeployScyllaConfigureExecutionAttempt.from_object(
                        _mapping(item, "attempt")
                    )
                    for item in _array(value["attempts"], "attempts")
                ),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy scylla-configure execution state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployScyllaConfigureEvidenceEntry:
    """Strict address- and value-free evidence for one successful scope."""

    attempt_index: int
    step_sequence: int
    stable_id: str
    status: ScyllaConfigureStatus
    configured: bool
    changed: bool
    release_line_digest: str
    package_version_digest: str
    configuration_file_count: int
    configuration_file_set_digest: str
    files_root_owned: bool
    files_mode_0644: bool
    cluster_name_digest: str
    datacenter_digest: str
    rack_digest: str
    private_identity_digest: str
    seed_count: int
    seed_policy_digest: str
    directory_count: int
    directory_policy_digest: str
    template_count: int
    template_source_digest: str
    rendered_config_digest: str
    topology_digest: str
    role_source_digest: str
    playbook_source_digest: str
    configuration_intent_digest: str
    service_masked: bool
    service_inactive: bool
    runtime_validation_performed: bool
    package_install_performed: bool
    storage_mutation_performed: bool
    tuning_performed: bool
    firewall_operation_performed: bool
    ssh_operation_performed: bool
    manager_operation_performed: bool
    service_started: bool
    bootstrap_performed: bool
    provenance_digest: str
    variables_digest: str
    command_digest: str
    source_digest: str
    result_digest: str
    evidence_digest: str
    manual_recovery_required: bool = False
    automatic_retry_allowed: bool = False
    result_schema_version: str = SCYLLA_CONFIGURE_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_ENTRY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_ENTRY_SCHEMA_VERSION
            or self.result_schema_version != SCYLLA_CONFIGURE_SCHEMA_VERSION
            or self.attempt_index < 1
            or self.step_sequence < 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.status not in _SUCCESS_STATUSES
            or not self.configured
            or self.changed != (self.status is ScyllaConfigureStatus.CHANGED)
            or self.configuration_file_count != _CONFIGURATION_FILE_COUNT
            or not self.files_root_owned
            or not self.files_mode_0644
            or self.seed_count != 1
            or self.directory_count != len(SCYLLA_CONFIGURE_DIRECTORIES)
            or self.template_count != _TEMPLATE_COUNT
            or not self.service_masked
            or not self.service_inactive
            or self.runtime_validation_performed
            or self.package_install_performed
            or self.storage_mutation_performed
            or self.tuning_performed
            or self.firewall_operation_performed
            or self.ssh_operation_performed
            or self.manager_operation_performed
            or self.service_started
            or self.bootstrap_performed
            or self.manual_recovery_required
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy scylla-configure semantic evidence conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy scylla-configure evidence digest")
        if self.evidence_digest != _evidence_entry_digest(self):
            raise StatePersistenceError(
                "deploy scylla-configure evidence digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaConfigureEvidenceEntry:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy scylla-configure evidence entry",
        )
        integer_fields = {
            "attempt_index",
            "step_sequence",
            "configuration_file_count",
            "seed_count",
            "directory_count",
            "template_count",
        }
        boolean_fields = {
            "configured",
            "changed",
            "files_root_owned",
            "files_mode_0644",
            "service_masked",
            "service_inactive",
            "runtime_validation_performed",
            "package_install_performed",
            "storage_mutation_performed",
            "tuning_performed",
            "firewall_operation_performed",
            "ssh_operation_performed",
            "manager_operation_performed",
            "service_started",
            "bootstrap_performed",
            "manual_recovery_required",
            "automatic_retry_allowed",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                if name in integer_fields:
                    parsed[name] = _integer(value[name], name)
                elif name in boolean_fields:
                    parsed[name] = _boolean(value[name], name)
                elif name == "status":
                    parsed[name] = ScyllaConfigureStatus(require_string(value, name))
                else:
                    parsed[name] = require_string(value, name)
            return cls(**parsed)  # type: ignore[arg-type]
        except ValueError as error:
            raise StatePersistenceError(
                "deploy scylla-configure evidence status is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployScyllaConfigureEvidence:
    """Immutable-prefix owner-only successful semantic evidence."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployScyllaConfigureExecutionBinding
    entries: tuple[DeployScyllaConfigureEvidenceEntry, ...]
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_SCHEMA_VERSION
            or self.generation != len(self.entries)
            or not 1 <= len(self.entries) <= self.binding.scope_count
            or tuple(item.attempt_index for item in self.entries)
            != tuple(range(1, len(self.entries) + 1))
            or parse_timestamp(self.updated_at) < parse_timestamp(self.created_at)
        ):
            raise StatePersistenceError(
                "deploy scylla-configure evidence prefix conflicts"
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
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaConfigureEvidence:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy scylla-configure evidence",
        )
        return cls(
            generation=_integer(value["generation"], "generation"),
            created_at=require_string(value, "created_at"),
            updated_at=require_string(value, "updated_at"),
            binding=DeployScyllaConfigureExecutionBinding.from_object(
                _mapping(value["binding"], "binding")
            ),
            entries=tuple(
                DeployScyllaConfigureEvidenceEntry.from_object(
                    _mapping(item, "evidence entry")
                )
                for item in _array(value["entries"], "evidence entries")
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaConfigureExecution:
    record: DeployScyllaConfigureExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaConfigureEvidence:
    record: DeployScyllaConfigureEvidence
    artifact_digest: str


class DeployScyllaConfigureExecutionStore:
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
        self._path = deploy_scylla_configure_execution_path(paths, operation_id)
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
    ) -> StoredDeployScyllaConfigureExecution:
        value, digest = self._file.read()
        record = DeployScyllaConfigureExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy scylla-configure execution identity conflicts"
            )
        return StoredDeployScyllaConfigureExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaConfigureExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaConfigureExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployScyllaConfigureExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy scylla-configure execution operation conflicts"
            )
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial deploy scylla-configure execution generation conflicts"
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
                    "deploy scylla-configure execution changed concurrently"
                )
            _validate_execution_transition(current.record, record)
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployScyllaConfigureExecution(record, digest)


class DeployScyllaConfigureEvidenceStore:
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
        self._path = deploy_scylla_configure_evidence_path(paths, operation_id)
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
    ) -> StoredDeployScyllaConfigureEvidence:
        value, digest = self._file.read()
        record = DeployScyllaConfigureEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy scylla-configure evidence identity conflicts"
            )
        return StoredDeployScyllaConfigureEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaConfigureEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def append_locked(
        self,
        record: DeployScyllaConfigureEvidence,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployScyllaConfigureEvidence:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy scylla-configure evidence operation conflicts"
            )
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial deploy scylla-configure evidence generation conflicts"
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
                    "deploy scylla-configure evidence changed concurrently"
                )
            _validate_evidence_transition(current.record, record)
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployScyllaConfigureEvidence(record, digest)


@dataclass(frozen=True, slots=True)
class DeployScyllaConfigureExecutionReport:
    """Strict count/digest/enum-only successful execution report."""

    operation_id: uuid.UUID
    execution_state: DeployScyllaConfigureExecutionState
    execution_artifact_state: DeployScyllaConfigureArtifactState
    evidence_artifact_state: DeployScyllaConfigureArtifactState
    execution_artifact_digest: str
    evidence_artifact_digest: str
    binding_digest: str
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_consumed: bool
    stage: str
    scope_kind: str
    invocation_count: int
    scope_count: int
    stable_id_count: int
    stable_id_set_digest: str
    configured_count: int
    changed_count: int
    configuration_file_count: int
    configuration_file_set_digest: str
    service_safe_count: int
    prohibited_action_count: int
    configuration_intent_digest: str
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    skip_allowed: bool
    continue_allowed: bool
    rollback_performed: bool
    journal_status: JournalStatus
    journal_phase: OperationPhase
    journal_updated: bool = False
    reconciliation_state: str = "not-performed"
    bootstrap_state: str = "not-performed"
    public_workflow_state: str = "unavailable"
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
    )
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_SCHEMA_VERSION
            or self.execution_state is not DeployScyllaConfigureExecutionState.SUCCEEDED
            or not self.authorization_consumed
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.invocation_count != self.scope_count
            or self.scope_count != self.stable_id_count
            or self.configured_count != self.scope_count
            or self.configuration_file_count
            != self.scope_count * _CONFIGURATION_FILE_COUNT
            or self.service_safe_count != self.scope_count
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
            or self.bootstrap_state != "not-performed"
            or self.public_workflow_state != "unavailable"
        ):
            raise StatePersistenceError(
                "deploy scylla-configure execution report is invalid"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy scylla-configure report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "authorization": {
                "artifact_digest": self.authorization_artifact_digest,
                "consumed": self.authorization_consumed,
                "digest": self.authorization_digest,
                "schema_version": self.authorization_schema_version,
            },
            "configuration": {
                "changed_count": self.changed_count,
                "configured_count": self.configured_count,
                "file_count": self.configuration_file_count,
                "file_set_digest": self.configuration_file_set_digest,
                "intent_digest": self.configuration_intent_digest,
                "prohibited_action_count": self.prohibited_action_count,
                "service_safe_count": self.service_safe_count,
            },
            "evidence": {
                "artifact_digest": self.evidence_artifact_digest,
                "artifact_state": self.evidence_artifact_state.value,
                "schema_version": self.evidence_schema_version,
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
                "bootstrap_state": self.bootstrap_state,
                "id": str(self.operation_id),
                "kind": _OPERATION,
                "public_workflow_state": self.public_workflow_state,
                "reconciliation_state": self.reconciliation_state,
            },
            "schema_version": self.schema_version,
            "scope": {
                "instance_count": self.scope_count,
                "kind": self.scope_kind,
                "stable_id_count": self.stable_id_count,
                "stable_id_set_digest": self.stable_id_set_digest,
            },
            "stage": self.stage,
        }


@dataclass(frozen=True, slots=True)
class _ExecutionScope:
    attempt_index: int
    authorization: DeployScyllaConfigureAuthorizationScope
    authorization_scope_digest: str
    target_ids: tuple[str, ...]
    variables: tuple[tuple[str, object], ...]
    variables_digest: str
    command_digest: str
    source_digest: str


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    authorization: StoredDeployScyllaConfigureAuthorization
    binding: DeployScyllaConfigureExecutionBinding
    scopes: tuple[_ExecutionScope, ...]
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport


def execute_deploy_scylla_configure(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployScyllaConfigureExecutionReport:
    """Execute only exact immutable authorized Scylla configuration scopes."""

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
    execution_store = DeployScyllaConfigureExecutionStore(paths, operation_id)
    evidence_store = DeployScyllaConfigureEvidenceStore(paths, operation_id)
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
                "completed deploy scylla-configure evidence is unavailable"
            )
        return _build_report(
            context,
            execution,
            evidence,
            execution_state=DeployScyllaConfigureArtifactState.REUSED,
            evidence_state=DeployScyllaConfigureArtifactState.REUSED,
        )
    if execution is not None and execution.record.state not in {
        DeployScyllaConfigureExecutionState.PREPARED,
        DeployScyllaConfigureExecutionState.SUCCEEDED,
    }:
        raise StateConflictError(
            "deploy scylla-configure execution requires manual recovery "
            "and cannot retry"
        )

    service = AnsibleService(builder, runner)
    discovered = service.version(lock)
    if discovered != toolchain:
        raise StateConflictError("deploy scylla-configure toolchain drifted")
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
    evidence_initially_present = evidence is not None

    next_index = len(execution.record.attempts) if execution is not None else 0
    if (
        execution is None
        or execution.record.state is DeployScyllaConfigureExecutionState.SUCCEEDED
    ):
        try:
            execution = _persist_prepared(
                context,
                execution_store,
                execution,
                context.scopes[next_index],
                lock=lock,
            )
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy scylla-configure prepared intent persistence failed "
                "before invocation"
            ) from error
    assert execution is not None

    while True:
        if execution.record.state is DeployScyllaConfigureExecutionState.PREPARED:
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
                    "deploy scylla-configure state drifted before start"
                )
            _validate_prefix(before_start, execution, evidence)
            scope = before_start.scopes[len(execution.record.attempts) - 1]
            try:
                execution = _persist_started(execution_store, execution, lock=lock)
            except StatePersistenceError as error:
                raise StatePersistenceError(
                    "deploy scylla-configure authorization consumption failed "
                    "before invocation"
                ) from error
            try:
                result, command_digest = service.execute_operation_step(
                    lock,
                    before_start.metadata,
                    before_start.inventory,
                    _PLAYBOOK,
                    step_sequence=scope.authorization.sequence,
                    limit=scope.target_ids,
                    variables=dict(scope.variables),
                    readiness=before_start.readiness,
                    tags=(),
                    check=False,
                    diff=False,
                    verbosity=0,
                )
                if command_digest != scope.command_digest:
                    raise AnsibleResultError(
                        "deploy scylla-configure command result identity conflicts"
                    )
            except KeyboardInterrupt:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    DeployScyllaConfigureExecutionState.INTERRUPTED,
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy scylla-configure execution was interrupted; "
                    "manual recovery required"
                ) from None
            except (AnsibleError, StatePersistenceError) as error:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    (
                        _failure_state(error)
                        if isinstance(error, AnsibleError)
                        else DeployScyllaConfigureExecutionState.MALFORMED_RESULT
                    ),
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy scylla-configure execution is uncertain; "
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
                        "deploy scylla-configure state changed after invocation"
                    )
            except (StateConflictError, StatePersistenceError) as error:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    DeployScyllaConfigureExecutionState.MALFORMED_RESULT,
                    lock=lock,
                )
                raise StateConflictError(
                    "deploy scylla-configure state changed after invocation; "
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
                        else DeployScyllaConfigureExecutionState.MALFORMED_RESULT
                    ),
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy scylla-configure result is not strict successful "
                    "evidence; manual recovery required"
                ) from error
            try:
                evidence = _persist_evidence(
                    context, evidence_store, evidence, entry, lock=lock
                )
            except StatePersistenceError as error:
                raise StatePersistenceError(
                    "deploy scylla-configure evidence persistence failed; "
                    "manual recovery required"
                ) from error
            try:
                execution = _persist_terminal_success(
                    context,
                    execution_store,
                    execution,
                    entry=entry,
                    lock=lock,
                )
            except StatePersistenceError as error:
                raise StatePersistenceError(
                    "deploy scylla-configure terminal persistence failed; "
                    "manual recovery required"
                ) from error

        if execution.record.all_scopes_completed:
            break
        try:
            execution = _persist_prepared(
                context,
                execution_store,
                execution,
                context.scopes[len(execution.record.attempts)],
                lock=lock,
            )
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy scylla-configure next prepared intent failed before invocation"
            ) from error

    if evidence is None:
        raise StatePersistenceError(
            "deploy scylla-configure completion evidence is missing"
        )
    _validate_prefix(context, execution, evidence)
    return _build_report(
        context,
        execution,
        evidence,
        execution_state=DeployScyllaConfigureArtifactState.UPDATED,
        evidence_state=(
            DeployScyllaConfigureArtifactState.UPDATED
            if evidence_initially_present
            else DeployScyllaConfigureArtifactState.CREATED
        ),
    )


def deploy_scylla_configure_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = (
        paths.operations
        / f"{operation_id}{DEPLOY_SCYLLA_CONFIGURE_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy scylla-configure execution path is not canonical"
        )
    return path


def deploy_scylla_configure_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = (
        paths.operations
        / f"{operation_id}{DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy scylla-configure evidence path is not canonical"
        )
    return path


def deploy_scylla_configure_execution_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_CONFIGURE_EXECUTION_FILENAME_SUFFIX
    )


def deploy_scylla_configure_evidence_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_FILENAME_SUFFIX
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
    loaded = _loaded(authorization_context)
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
            "deploy scylla-configure readiness, journal, or toolchain conflicts"
        )
    readiness = _reconstructed_readiness(planning.base)
    if readiness_binding_digest(readiness) != readiness_record.readiness_digest:
        raise StateConflictError("deploy scylla-configure readiness is stale")
    readiness.require_ready(OperationClassification.MUTATING)

    authorization_store = DeployScyllaConfigureAuthorizationStore(paths, operation_id)
    validate_state_file(authorization_store.path, allow_missing=True)
    if not authorization_store.path.exists():
        raise StateConflictError(
            "deploy scylla-configure execution requires immutable authorization"
        )
    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    intents = _derive_configuration_intents(
        authorization_context, paths=paths, lock=lock
    )
    scopes = tuple(intent.scope for intent in intents)
    expected_authorization = _build_authorization(
        authorization_context,
        scopes=scopes,
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
            "deploy scylla-configure authorization is stale or consumed"
        )
    execution_scopes = _derive_execution_scopes(authorization, intents, builder=builder)
    stable_ids = tuple(sorted(scope.target_ids[0] for scope in execution_scopes))
    scope_values = [
        {
            "attempt_index": scope.attempt_index,
            "authorization_command_digest": scope.authorization.command_digest,
            "authorization_scope_digest": scope.authorization_scope_digest,
            "authorization_variables_digest": scope.authorization.variables_digest,
            "command_digest": scope.command_digest,
            "configuration_intent_digest": (
                scope.authorization.configuration_intent_digest
            ),
            "source_digest": scope.source_digest,
            "target_digest": scope.authorization.target_digest,
            "variables_digest": scope.variables_digest,
        }
        for scope in execution_scopes
    ]
    trust = planning.base.trust
    reconciliation = authorization_context.reconciliation
    install = authorization_context.install
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
        "authorization_scope_digest": authorization.record.authorization_scope_digest,
        "authorization_proof_digest": authorization.record.proof.proof_digest,
        "configuration_intent_digest": (
            authorization.record.configuration_intent_digest
        ),
        "post_install_reconciliation_artifact_digest": reconciliation.artifact_digest,
        "post_install_reconciliation_record_digest": reconciliation.record.record_digest,
        "install_execution_artifact_digest": install.execution.artifact_digest,
        "install_evidence_artifact_digest": install.evidence.artifact_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": readiness_record.record_digest,
        "catalog_digest": loaded.catalog_digest,
        "source_version": loaded.source.version,
        "source_digest": loaded.source.digest,
        "playbook_source_digest": execution_scopes[0].source_digest,
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
        "scope_count": len(execution_scopes),
        "stable_id_count": len(stable_ids),
        "stable_id_set_digest": _digest_object(list(stable_ids)),
        "execution_scope_digest": _digest_object(scope_values),
        "binding_digest": "",
    }
    values["binding_digest"] = _binding_digest_from_values(values)
    return _ExecutionContext(
        authorization,
        DeployScyllaConfigureExecutionBinding(**values),  # type: ignore[arg-type]
        execution_scopes,
        metadata,
        deploy.inventory,
        readiness,
    )


def _derive_execution_scopes(
    authorization: StoredDeployScyllaConfigureAuthorization,
    intents: tuple[_DerivedConfigurationIntent, ...],
    *,
    builder: AnsibleCommandBuilder,
) -> tuple[_ExecutionScope, ...]:
    definition = get_playbook(_PLAYBOOK)
    if (
        definition.classification is not OperationClassification.MUTATING
        or definition.hosts != HostRole.SCYLLA.value
        or definition.serial != 1
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.check_mode is not CheckMode.PREVIEW
        or not definition.source_available
    ):
        raise StateConflictError("deploy scylla-configure catalog policy conflicts")
    if len(intents) != len(authorization.record.scopes):
        raise StateConflictError(
            "deploy scylla-configure authorization scope count conflicts"
        )
    scopes: list[_ExecutionScope] = []
    for attempt_index, (intent, authorized) in enumerate(
        zip(intents, authorization.record.scopes, strict=True), start=1
    ):
        derived_scope = intent.scope
        target_ids = intent.target_ids
        variables = intent.variables
        variables_digest = intent.variables_digest
        command_digest = intent.command_digest
        source_digest = intent.source_digest
        if (
            derived_scope != authorized
            or authorized.mapping_sequence != _MAPPING_SEQUENCE
            or authorized.classification is not OperationClassification.MUTATING
            or len(target_ids) != 1
            or authorized.target_digest != _digest_object(list(target_ids))
            or variables_digest != authorized.variables_digest
            or command_digest != authorized.command_digest
        ):
            raise StateConflictError(
                "deploy scylla-configure exact authorized scope conflicts"
            )
        selected, validated, rebuilt_variables_digest, rebuilt_command_digest = (
            builder.validate_operation_step(
                _PLAYBOOK,
                step_sequence=authorized.sequence,
                limit=target_ids,
                variables=dict(variables),
                tags=(),
                check=False,
                diff=False,
                verbosity=0,
            )
        )
        if (
            selected != definition
            or tuple(sorted(validated.items())) != variables
            or rebuilt_variables_digest != variables_digest
            or rebuilt_command_digest != command_digest
        ):
            raise StateConflictError(
                "deploy scylla-configure anchored command policy conflicts"
            )
        scopes.append(
            _ExecutionScope(
                attempt_index=attempt_index,
                authorization=authorized,
                authorization_scope_digest=_digest_object(authorized.to_object()),
                target_ids=target_ids,
                variables=variables,
                variables_digest=variables_digest,
                command_digest=command_digest,
                source_digest=source_digest,
            )
        )
    if (
        not scopes
        or tuple(scope.authorization.sequence for scope in scopes)
        != tuple(sorted(scope.authorization.sequence for scope in scopes))
        or tuple(scope.target_ids[0] for scope in scopes)
        != tuple(sorted(scope.target_ids[0] for scope in scopes))
    ):
        raise StateConflictError("deploy scylla-configure execution order conflicts")
    return tuple(scopes)


def _validate_prefix(
    context: _ExecutionContext,
    execution: StoredDeployScyllaConfigureExecution | None,
    evidence: StoredDeployScyllaConfigureEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "deploy scylla-configure evidence exists without execution"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError(
            "deploy scylla-configure execution provenance is stale"
        )
    if evidence is not None and evidence.record.binding != context.binding:
        raise StateConflictError("deploy scylla-configure evidence provenance is stale")
    for index, attempt in enumerate(execution.record.attempts):
        scope = context.scopes[index]
        authorized = scope.authorization
        if (
            attempt.attempt_index != index + 1
            or attempt.step_sequence != authorized.sequence
            or attempt.stable_id != scope.target_ids[0]
            or attempt.target_digest != authorized.target_digest
            or attempt.authorization_scope_digest != scope.authorization_scope_digest
            or attempt.authorization_variables_digest != authorized.variables_digest
            or attempt.authorization_command_digest != authorized.command_digest
            or attempt.variables_digest != scope.variables_digest
            or attempt.command_digest != scope.command_digest
            or attempt.source_digest != scope.source_digest
            or attempt.configuration_intent_digest
            != authorized.configuration_intent_digest
        ):
            raise StateConflictError(
                "deploy scylla-configure execution scope conflicts"
            )
    entries = evidence.record.entries if evidence is not None else ()
    succeeded = tuple(
        attempt
        for attempt in execution.record.attempts
        if attempt.state is DeployScyllaConfigureExecutionState.SUCCEEDED
    )
    if len(entries) not in {
        len(succeeded),
        len(succeeded)
        + (
            1
            if execution.record.state is DeployScyllaConfigureExecutionState.STARTED
            else 0
        ),
    }:
        raise StateConflictError(
            "deploy scylla-configure execution/evidence prefixes conflict"
        )
    for index, entry in enumerate(entries):
        attempt = execution.record.attempts[index]
        scope = context.scopes[index]
        if (
            entry.attempt_index != index + 1
            or entry.step_sequence != scope.authorization.sequence
            or entry.stable_id != scope.target_ids[0]
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
                "deploy scylla-configure semantic evidence conflicts"
            )


def _persist_prepared(
    context: _ExecutionContext,
    store: DeployScyllaConfigureExecutionStore,
    current: StoredDeployScyllaConfigureExecution | None,
    scope: _ExecutionScope,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaConfigureExecution:
    now = _timestamp()
    attempt = DeployScyllaConfigureExecutionAttempt(
        attempt_index=scope.attempt_index,
        step_sequence=scope.authorization.sequence,
        stable_id=scope.target_ids[0],
        target_digest=scope.authorization.target_digest,
        authorization_scope_digest=scope.authorization_scope_digest,
        authorization_variables_digest=scope.authorization.variables_digest,
        authorization_command_digest=scope.authorization.command_digest,
        variables_digest=scope.variables_digest,
        command_digest=scope.command_digest,
        source_digest=scope.source_digest,
        configuration_intent_digest=(scope.authorization.configuration_intent_digest),
        state=DeployScyllaConfigureExecutionState.PREPARED,
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
    if current is None:
        record = DeployScyllaConfigureExecution(
            generation=1,
            created_at=now,
            updated_at=now,
            binding=context.binding,
            state=DeployScyllaConfigureExecutionState.PREPARED,
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
    if current.record.state is not DeployScyllaConfigureExecutionState.SUCCEEDED:
        raise StateConflictError(
            "deploy scylla-configure cannot prepare after uncertain execution"
        )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=DeployScyllaConfigureExecutionState.PREPARED,
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
    store: DeployScyllaConfigureExecutionStore,
    current: StoredDeployScyllaConfigureExecution,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaConfigureExecution:
    if current.record.state is not DeployScyllaConfigureExecutionState.PREPARED:
        raise StateConflictError(
            "deploy scylla-configure start requires prepared intent"
        )
    now = _timestamp()
    attempt = replace(
        current.record.attempts[-1],
        state=DeployScyllaConfigureExecutionState.STARTED,
        started_at=now,
        authorization_consumed_at_start=(
            current.record.attempts[-1].attempt_index == 1
        ),
        invocation_may_have_occurred=True,
        manual_recovery_required=True,
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=DeployScyllaConfigureExecutionState.STARTED,
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
    store: DeployScyllaConfigureExecutionStore,
    current: StoredDeployScyllaConfigureExecution,
    state: DeployScyllaConfigureExecutionState,
    *,
    lock: ClusterLock,
) -> None:
    try:
        _persist_uncertain(store, current, state, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy scylla-configure uncertain outcome persistence failed; "
            "manual recovery required"
        ) from error


def _persist_uncertain(
    store: DeployScyllaConfigureExecutionStore,
    current: StoredDeployScyllaConfigureExecution,
    state: DeployScyllaConfigureExecutionState,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaConfigureExecution:
    if (
        current.record.state is not DeployScyllaConfigureExecutionState.STARTED
        or state
        not in {
            DeployScyllaConfigureExecutionState.FAILED,
            DeployScyllaConfigureExecutionState.TIMED_OUT,
            DeployScyllaConfigureExecutionState.INTERRUPTED,
            DeployScyllaConfigureExecutionState.UNREACHABLE,
            DeployScyllaConfigureExecutionState.MALFORMED_RESULT,
        }
    ):
        raise StatePersistenceError(
            "deploy scylla-configure uncertain transition conflicts"
        )
    now = _timestamp()
    attempt = replace(
        current.record.attempts[-1],
        state=state,
        completed_at=now,
        exit_code=None,
        manual_recovery_required=True,
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


def _persist_terminal_success(
    context: _ExecutionContext,
    store: DeployScyllaConfigureExecutionStore,
    current: StoredDeployScyllaConfigureExecution,
    *,
    entry: DeployScyllaConfigureEvidenceEntry,
    lock: ClusterLock,
) -> StoredDeployScyllaConfigureExecution:
    if current.record.state is not DeployScyllaConfigureExecutionState.STARTED:
        raise StateConflictError(
            "deploy scylla-configure terminal transition conflicts"
        )
    now = _timestamp()
    attempt = replace(
        current.record.attempts[-1],
        state=DeployScyllaConfigureExecutionState.SUCCEEDED,
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
        state=DeployScyllaConfigureExecutionState.SUCCEEDED,
        all_scopes_completed=(len(current.record.attempts) == len(context.scopes)),
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
    store: DeployScyllaConfigureEvidenceStore,
    current: StoredDeployScyllaConfigureEvidence | None,
    entry: DeployScyllaConfigureEvidenceEntry,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaConfigureEvidence:
    if current is not None and len(current.record.entries) >= entry.attempt_index:
        existing = current.record.entries[entry.attempt_index - 1]
        if existing != entry:
            raise StateConflictError(
                "deploy scylla-configure evidence conflicts with existing entry"
            )
        return current
    if current is not None and len(current.record.entries) != entry.attempt_index - 1:
        raise StateConflictError("deploy scylla-configure evidence sequence conflicts")
    now = _timestamp()
    record = DeployScyllaConfigureEvidence(
        generation=1 if current is None else current.record.generation + 1,
        created_at=now if current is None else current.record.created_at,
        updated_at=now,
        binding=context.binding,
        entries=(() if current is None else current.record.entries) + (entry,),
    )
    return store.append_locked(
        record,
        expected_generation=0 if current is None else current.record.generation,
        expected_digest=None if current is None else current.artifact_digest,
        lock=lock,
    )


def _semantic_entry(
    scope: _ExecutionScope, result: AnsibleExecutionResult
) -> DeployScyllaConfigureEvidenceEntry:
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.MUTATING
        or result.check_mode
        or result.scylla_configure is not None
    ):
        raise AnsibleResultError(
            "deploy scylla-configure strict result identity conflicts"
        )
    payload = cast(
        dict[str, object],
        dict(scope.variables)["deploy_scylla_vms_scylla_configure"],
    )
    try:
        parsed = parse_scylla_configure_execution(
            result.stdout,
            expected_payload=payload,
            exit_code=result.exit_code,
        )
    except AnsibleError as error:
        raise AnsibleResultError(
            "deploy scylla-configure strict result is malformed"
        ) from error
    if parsed.status not in _SUCCESS_STATUSES:
        message = "unreachable" if result.exit_code == 4 else "execution failed"
        raise AnsibleError(f"deploy scylla-configure {message}")
    _validate_success_evidence(parsed, scope)
    file_digests = dict(parsed.configuration_file_digests)
    result_digest = _digest_object(
        {
            "config_digest": parsed.config_digest,
            "installed_version_digest": _digest_object(parsed.installed_version),
            "logical_id": parsed.logical_id,
            "prerequisite_digest": _digest_object(dict(parsed.prerequisite_digests)),
            "runtime_validation_performed": parsed.runtime_validation_performed,
            "seed_digest": parsed.seed_digest,
            "service_inactive": parsed.service_inactive,
            "service_masked": parsed.service_masked,
            "status": parsed.status.value,
            "topology_digest": parsed.topology_digest,
        }
    )
    authorized = scope.authorization
    values: dict[str, object] = {
        "attempt_index": scope.attempt_index,
        "step_sequence": authorized.sequence,
        "stable_id": scope.target_ids[0],
        "status": parsed.status,
        "configured": True,
        "changed": parsed.status is ScyllaConfigureStatus.CHANGED,
        "release_line_digest": _digest_object(SCYLLA_RELEASE_LINE),
        "package_version_digest": authorized.package_version_digest,
        "configuration_file_count": len(file_digests),
        "configuration_file_set_digest": _digest_object(sorted(file_digests)),
        "files_root_owned": cast(bool, parsed.files_root_owned),
        "files_mode_0644": cast(bool, parsed.files_mode_0644),
        "cluster_name_digest": authorized.cluster_name_digest,
        "datacenter_digest": authorized.datacenter_digest,
        "rack_digest": authorized.rack_digest,
        "private_identity_digest": authorized.private_identity_digest,
        "seed_count": authorized.seed_count,
        "seed_policy_digest": authorized.seed_policy_digest,
        "directory_count": authorized.directory_count,
        "directory_policy_digest": authorized.directory_policy_digest,
        "template_count": authorized.template_count,
        "template_source_digest": authorized.template_source_digest,
        "rendered_config_digest": authorized.rendered_config_digest,
        "topology_digest": parsed.topology_digest,
        "role_source_digest": authorized.role_source_digest,
        "playbook_source_digest": authorized.playbook_source_digest,
        "configuration_intent_digest": authorized.configuration_intent_digest,
        "service_masked": cast(bool, parsed.service_masked),
        "service_inactive": cast(bool, parsed.service_inactive),
        "runtime_validation_performed": parsed.runtime_validation_performed,
        "package_install_performed": parsed.package_install_performed,
        "storage_mutation_performed": parsed.storage_mutation_performed,
        "tuning_performed": parsed.tuning_performed,
        "firewall_operation_performed": parsed.firewall_operation_performed,
        "ssh_operation_performed": parsed.ssh_operation_performed,
        "manager_operation_performed": parsed.manager_operation_performed,
        "service_started": parsed.service_started,
        "bootstrap_performed": parsed.bootstrap_performed,
        "provenance_digest": _digest_object(dict(parsed.prerequisite_digests)),
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "source_digest": scope.source_digest,
        "result_digest": result_digest,
        "evidence_digest": "",
    }
    values["evidence_digest"] = _evidence_entry_digest_from_values(values)
    return DeployScyllaConfigureEvidenceEntry(**values)  # type: ignore[arg-type]


def _validate_success_evidence(
    evidence: ScyllaConfigureEvidence, scope: _ExecutionScope
) -> None:
    authorized = scope.authorization
    payload = cast(
        dict[str, object],
        dict(scope.variables)["deploy_scylla_vms_scylla_configure"],
    )
    file_digests = cast(dict[str, str], payload["file_digests"])
    if (
        evidence.logical_id != scope.target_ids[0]
        or evidence.installed_version != SCYLLA_PACKAGE_VERSION
        or evidence.config_digest != authorized.rendered_config_digest
        or evidence.seed_digest != authorized.seed_policy_digest
        or evidence.service_masked is not True
        or evidence.service_inactive is not True
        or evidence.files_root_owned is not True
        or evidence.files_mode_0644 is not True
        or evidence.runtime_validation_performed
        or evidence.package_install_performed
        or evidence.storage_mutation_performed
        or evidence.tuning_performed
        or evidence.firewall_operation_performed
        or evidence.ssh_operation_performed
        or evidence.manager_operation_performed
        or evidence.service_started
        or evidence.bootstrap_performed
        or evidence.blockers
        or dict(evidence.configuration_file_digests) != file_digests
        or set(file_digests) != {"cassandra-rackdc.properties", "scylla.yaml"}
        or len(file_digests) != _CONFIGURATION_FILE_COUNT
        or payload["release_line"] != SCYLLA_RELEASE_LINE
        or payload["package_version"] != SCYLLA_PACKAGE_VERSION
        or payload["config_digest"] != authorized.rendered_config_digest
        or payload["seed_digest"] != authorized.seed_policy_digest
        or _digest_object(list(SCYLLA_CONFIGURE_DIRECTORIES))
        != authorized.directory_policy_digest
    ):
        raise AnsibleResultError(
            "deploy scylla-configure successful evidence conflicts"
        )


def _build_report(
    context: _ExecutionContext,
    execution: StoredDeployScyllaConfigureExecution,
    evidence: StoredDeployScyllaConfigureEvidence,
    *,
    execution_state: DeployScyllaConfigureArtifactState,
    evidence_state: DeployScyllaConfigureArtifactState,
) -> DeployScyllaConfigureExecutionReport:
    if (
        not execution.record.all_scopes_completed
        or execution.record.state is not DeployScyllaConfigureExecutionState.SUCCEEDED
        or len(evidence.record.entries) != len(context.scopes)
    ):
        raise StateConflictError("deploy scylla-configure execution is not complete")
    entries = evidence.record.entries
    return DeployScyllaConfigureExecutionReport(
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
        stage=_STAGE,
        scope_kind=_SCOPE_KIND,
        invocation_count=execution.record.invocation_count,
        scope_count=context.binding.scope_count,
        stable_id_count=context.binding.stable_id_count,
        stable_id_set_digest=context.binding.stable_id_set_digest,
        configured_count=sum(entry.configured for entry in entries),
        changed_count=sum(entry.changed for entry in entries),
        configuration_file_count=sum(
            entry.configuration_file_count for entry in entries
        ),
        configuration_file_set_digest=_digest_object(
            [entry.configuration_file_set_digest for entry in entries]
        ),
        service_safe_count=sum(
            entry.service_masked and entry.service_inactive for entry in entries
        ),
        prohibited_action_count=sum(
            entry.package_install_performed
            or entry.storage_mutation_performed
            or entry.tuning_performed
            or entry.firewall_operation_performed
            or entry.ssh_operation_performed
            or entry.manager_operation_performed
            or entry.service_started
            or entry.bootstrap_performed
            for entry in entries
        ),
        configuration_intent_digest=context.binding.configuration_intent_digest,
        manual_recovery_required=False,
        automatic_retry_allowed=False,
        skip_allowed=False,
        continue_allowed=False,
        rollback_performed=False,
        journal_status=context.binding.journal_status,
        journal_phase=context.binding.journal_phase,
    )


def _failure_state(
    error: AnsibleError,
) -> DeployScyllaConfigureExecutionState:
    cause = error.__cause__
    if isinstance(cause, ProcessTimeoutError):
        return DeployScyllaConfigureExecutionState.TIMED_OUT
    if isinstance(cause, ProcessOutputError):
        return DeployScyllaConfigureExecutionState.MALFORMED_RESULT
    message = str(error).lower()
    if "unreachable" in message:
        return DeployScyllaConfigureExecutionState.UNREACHABLE
    if isinstance(error, AnsibleResultError) or "malformed" in message:
        return DeployScyllaConfigureExecutionState.MALFORMED_RESULT
    return DeployScyllaConfigureExecutionState.FAILED


def _validate_execution_transition(
    current: DeployScyllaConfigureExecution,
    replacement: DeployScyllaConfigureExecution,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or current.all_scopes_completed
        or current.state
        not in {
            DeployScyllaConfigureExecutionState.PREPARED,
            DeployScyllaConfigureExecutionState.STARTED,
            DeployScyllaConfigureExecutionState.SUCCEEDED,
        }
    ):
        raise StatePersistenceError(
            "deploy scylla-configure execution transition is invalid"
        )
    if current.state is DeployScyllaConfigureExecutionState.PREPARED:
        valid = (
            len(replacement.attempts) == len(current.attempts)
            and replacement.attempts[:-1] == current.attempts[:-1]
            and replacement.attempts[-1].state
            is DeployScyllaConfigureExecutionState.STARTED
        )
    elif current.state is DeployScyllaConfigureExecutionState.STARTED:
        valid = (
            len(replacement.attempts) == len(current.attempts)
            and replacement.attempts[:-1] == current.attempts[:-1]
            and replacement.attempts[-1].state
            not in {
                DeployScyllaConfigureExecutionState.PREPARED,
                DeployScyllaConfigureExecutionState.STARTED,
            }
        )
    else:
        valid = (
            len(current.attempts) < current.binding.scope_count
            and replacement.attempts[:-1] == current.attempts
            and replacement.attempts[-1].state
            is DeployScyllaConfigureExecutionState.PREPARED
        )
    if not valid:
        raise StatePersistenceError(
            "deploy scylla-configure execution transition conflicts"
        )


def _validate_evidence_transition(
    current: DeployScyllaConfigureEvidence,
    replacement: DeployScyllaConfigureEvidence,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or replacement.entries[:-1] != current.entries
        or len(replacement.entries) != len(current.entries) + 1
    ):
        raise StatePersistenceError(
            "deploy scylla-configure evidence transition is invalid"
        )


def _binding_digest(binding: DeployScyllaConfigureExecutionBinding) -> str:
    value = binding.to_object()
    value["binding_digest"] = ""
    return _digest_object(value)


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployScyllaConfigureExecutionBinding.__dataclass_fields__.items():
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


def _evidence_entry_digest(entry: DeployScyllaConfigureEvidenceEntry) -> str:
    value = entry.to_object()
    value["evidence_digest"] = ""
    return _digest_object(value)


def _evidence_entry_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployScyllaConfigureEvidenceEntry.__dataclass_fields__.items():
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
    if StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths:
        raise StatePersistenceError(
            "deploy scylla-configure execution paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy scylla-configure execution requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy scylla-configure execution artifacts"
        ) from error
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_SCYLLA_CONFIGURE_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_FILENAME_SUFFIX,
    )
    for entry in entries:
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
                    "deploy scylla-configure execution artifacts are ambiguous"
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
            "deploy scylla-configure toolchain version is invalid"
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


def _enum(enum_type: type[StrEnum], value: str, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except ValueError as error:
        raise StatePersistenceError(f"{label} is invalid") from error


__all__ = [
    "ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_ENTRY_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_BINDING_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_SCHEMA_VERSION",
    "DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_SCYLLA_CONFIGURE_EXECUTION_FILENAME_SUFFIX",
    "DeployScyllaConfigureArtifactState",
    "DeployScyllaConfigureEvidence",
    "DeployScyllaConfigureEvidenceEntry",
    "DeployScyllaConfigureEvidenceStore",
    "DeployScyllaConfigureExecution",
    "DeployScyllaConfigureExecutionAttempt",
    "DeployScyllaConfigureExecutionBinding",
    "DeployScyllaConfigureExecutionReport",
    "DeployScyllaConfigureExecutionState",
    "DeployScyllaConfigureExecutionStore",
    "StoredDeployScyllaConfigureEvidence",
    "StoredDeployScyllaConfigureExecution",
    "deploy_scylla_configure_evidence_id_from_filename",
    "deploy_scylla_configure_evidence_path",
    "deploy_scylla_configure_execution_id_from_filename",
    "deploy_scylla_configure_execution_path",
    "execute_deploy_scylla_configure",
]
