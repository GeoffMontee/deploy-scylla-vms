"""Durable exact-scope deploy ``scylla-install`` execution and evidence.

This internal owner consumes only immutable operation-bound authorization. It
records prepared and started intent before each controlled call, keeps strict
address-free semantic evidence, and permanently refuses automatic retry after
an invocation may have occurred.
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
from scylla_vms.ansible.deploy_non_jump_base_os_execution import (
    DeployNonJumpBaseOsEvidenceStore,
    StoredDeployNonJumpBaseOsEvidence,
)
from scylla_vms.ansible.deploy_plan import (
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_scylla_install_authorization import (
    ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_SCHEMA_VERSION,
    DeployScyllaInstallAuthorizationScope,
    DeployScyllaInstallAuthorizationStore,
    StoredDeployScyllaInstallAuthorization,
    _AuthorizationContext,
    _build_authorization,
    _derive_authorization_scopes,
    _derive_package_provenance,
    _load_authorization_context,
    _signing_key_identity_digest,
)
from scylla_vms.ansible.operation_binding import readiness_binding_digest
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_install import (
    SCYLLA_CHANNEL,
    SCYLLA_EDITION,
    SCYLLA_INSTALL_SCHEMA_VERSION,
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_PACKAGES,
    SCYLLA_RELEASE_LINE,
    SCYLLA_REPOSITORY_DEFINITION_DIGEST,
    SCYLLA_REPOSITORY_URI,
    SCYLLA_ROLE_COMMIT,
    SCYLLA_SIGNING_KEY_DIGEST,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
    SCYLLA_SIGNING_KEY_RESOURCE,
    ScyllaInstallEvidence,
    ScyllaInstallStatus,
    parse_scylla_install_execution,
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
from scylla_vms.desired import HostRole, ImageVersionMatch
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

ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-install-execution-binding/v1"
)
ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-install-execution/v1"
)
ANSIBLE_DEPLOY_SCYLLA_INSTALL_EVIDENCE_ENTRY_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-install-evidence-entry/v1"
)
ANSIBLE_DEPLOY_SCYLLA_INSTALL_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-install-evidence/v1"
)
ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-install-execution-report/v1"
)

DEPLOY_SCYLLA_INSTALL_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-install-execution.json"
)
DEPLOY_SCYLLA_INSTALL_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-install-evidence.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "scylla-install"
_STAGE = "post-storage-postcheck-scylla-install"
_SCOPE_KIND = "postchecked-scylla-hosts"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SUCCESS_STATUSES = frozenset(
    {ScyllaInstallStatus.INSTALLED, ScyllaInstallStatus.NO_CHANGE}
)


class DeployScyllaInstallExecutionState(StrEnum):
    """Bounded durable states for exact authorized install attempts."""

    PREPARED = "prepared"
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"


class DeployScyllaInstallArtifactState(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployScyllaInstallExecutionBinding:
    """Address-free authorization, state, source, and toolchain binding."""

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
    postcheck_reconciliation_artifact_digest: str
    postcheck_reconciliation_record_digest: str
    postcheck_evidence_artifact_digest: str
    postcheck_evidence_digest: str
    base_os_evidence_artifact_digest: str
    base_os_evidence_digest: str
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
    package_provenance_digest: str
    scope_count: int
    stable_id_count: int
    stable_id_set_digest: str
    execution_scope_digest: str
    binding_digest: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_BINDING_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.scope_count < 1
            or self.stable_id_count < 1
        ):
            raise StatePersistenceError(
                "deploy scylla-install execution binding is invalid"
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
            _positive_integer(count, "deploy scylla-install binding count")
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy scylla-install binding digest")
        _validate_toolchain_version(self.toolchain_version)
        if self.binding_digest != _binding_digest(self):
            raise StatePersistenceError(
                "deploy scylla-install execution binding digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaInstallExecutionBinding:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy scylla-install execution binding",
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
class DeployScyllaInstallExecutionAttempt:
    """One exact prepared, started, or terminal authorized install attempt."""

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
    package_version: str
    package_provenance_digest: str
    state: DeployScyllaInstallExecutionState
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
    result_schema_version: str = SCYLLA_INSTALL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.attempt_index < 1
            or self.step_sequence < 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.package_version != SCYLLA_PACKAGE_VERSION
            or self.result_schema_version != SCYLLA_INSTALL_SCHEMA_VERSION
            or not isinstance(self.state, DeployScyllaInstallExecutionState)
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy scylla-install execution attempt is invalid"
            )
        for digest in (
            self.target_digest,
            self.authorization_scope_digest,
            self.authorization_variables_digest,
            self.authorization_command_digest,
            self.variables_digest,
            self.command_digest,
            self.source_digest,
            self.package_provenance_digest,
            self.result_digest,
            self.evidence_digest,
        ):
            if digest is not None:
                validate_digest(digest, "deploy scylla-install attempt digest")
        prepared = parse_timestamp(self.prepared_at)
        started = _optional_timestamp(self.started_at)
        completed = _optional_timestamp(self.completed_at)
        if (
            (started is not None and started < prepared)
            or (completed is not None and started is None)
            or (completed is not None and started is not None and completed < started)
        ):
            raise StatePersistenceError(
                "deploy scylla-install attempt timestamps conflict"
            )
        if self.state is DeployScyllaInstallExecutionState.PREPARED:
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
        elif self.state is DeployScyllaInstallExecutionState.STARTED:
            valid = (
                started is not None
                and completed is None
                and self.invocation_may_have_occurred
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.manual_recovery_required
            )
        elif self.state is DeployScyllaInstallExecutionState.SUCCEEDED:
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
                self.state is not DeployScyllaInstallExecutionState.PREPARED
                and self.authorization_consumed_at_start != (self.attempt_index == 1)
            )
            or (
                self.state is DeployScyllaInstallExecutionState.PREPARED
                and self.authorization_consumed_at_start
            )
        ):
            raise StatePersistenceError("deploy scylla-install attempt state conflicts")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaInstallExecutionAttempt:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy scylla-install attempt",
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
                package_version=require_string(value, "package_version"),
                package_provenance_digest=require_string(
                    value, "package_provenance_digest"
                ),
                state=DeployScyllaInstallExecutionState(require_string(value, "state")),
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
                "deploy scylla-install attempt state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployScyllaInstallExecution:
    """Generation-guarded exact-prefix execution state."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployScyllaInstallExecutionBinding
    state: DeployScyllaInstallExecutionState
    authorization_consumed: bool
    invocation_count: int
    all_scopes_completed: bool
    attempts: tuple[DeployScyllaInstallExecutionAttempt, ...]
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        invoked = tuple(
            attempt
            for attempt in self.attempts
            if attempt.state is not DeployScyllaInstallExecutionState.PREPARED
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_SCHEMA_VERSION
            or self.generation < 1
            or not self.attempts
            or len(self.attempts) > self.binding.scope_count
            or self.state is not self.attempts[-1].state
            or tuple(item.attempt_index for item in self.attempts)
            != tuple(range(1, len(self.attempts) + 1))
            or any(
                attempt.state is not DeployScyllaInstallExecutionState.SUCCEEDED
                for attempt in self.attempts[:-1]
            )
            or self.invocation_count != len(invoked)
            or self.authorization_consumed != bool(invoked)
            or self.all_scopes_completed
            != (
                self.state is DeployScyllaInstallExecutionState.SUCCEEDED
                and len(self.attempts) == self.binding.scope_count
            )
        ):
            raise StatePersistenceError(
                "deploy scylla-install execution summary conflicts"
            )
        if parse_timestamp(self.updated_at) < parse_timestamp(self.created_at):
            raise StatePersistenceError(
                "deploy scylla-install execution timestamps conflict"
            )

    @property
    def manual_recovery_required(self) -> bool:
        return self.state not in {
            DeployScyllaInstallExecutionState.PREPARED,
            DeployScyllaInstallExecutionState.SUCCEEDED,
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
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaInstallExecution:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy scylla-install execution",
        )
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                updated_at=require_string(value, "updated_at"),
                binding=DeployScyllaInstallExecutionBinding.from_object(
                    _mapping(value["binding"], "binding")
                ),
                state=DeployScyllaInstallExecutionState(require_string(value, "state")),
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
                    DeployScyllaInstallExecutionAttempt.from_object(
                        _mapping(item, "attempt")
                    )
                    for item in _array(value["attempts"], "attempts")
                ),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy scylla-install execution state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployScyllaInstallEvidenceEntry:
    """Strict address-free semantic evidence for one successful install scope."""

    attempt_index: int
    step_sequence: int
    stable_id: str
    image_architecture: str
    status: ScyllaInstallStatus
    installed: bool
    changed: bool
    package_version: str
    package_count: int
    package_set_digest: str
    repository_definition_digest: str
    signing_key_artifact_digest: str
    signing_key_identity_digest: str
    service_masked: bool
    service_inactive: bool
    configuration_performed: bool
    storage_mutation_performed: bool
    tuning_performed: bool
    manager_operation_performed: bool
    service_started: bool
    provenance_digest: str
    variables_digest: str
    command_digest: str
    source_digest: str
    result_digest: str
    evidence_digest: str
    manual_recovery_required: bool = False
    automatic_retry_allowed: bool = False
    result_schema_version: str = SCYLLA_INSTALL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_INSTALL_EVIDENCE_ENTRY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_INSTALL_EVIDENCE_ENTRY_SCHEMA_VERSION
            or self.result_schema_version != SCYLLA_INSTALL_SCHEMA_VERSION
            or self.attempt_index < 1
            or self.step_sequence < 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.image_architecture not in {"amd64", "aarch64"}
            or self.status not in _SUCCESS_STATUSES
            or not self.installed
            or self.changed != (self.status is ScyllaInstallStatus.INSTALLED)
            or self.package_version != SCYLLA_PACKAGE_VERSION
            or self.package_count != len(SCYLLA_PACKAGES)
            or self.package_set_digest != _digest_object(list(SCYLLA_PACKAGES))
            or self.repository_definition_digest != SCYLLA_REPOSITORY_DEFINITION_DIGEST
            or self.signing_key_artifact_digest != SCYLLA_SIGNING_KEY_DIGEST
            or self.signing_key_identity_digest != _signing_key_identity_digest()
            or not self.service_masked
            or not self.service_inactive
            or self.configuration_performed
            or self.storage_mutation_performed
            or self.tuning_performed
            or self.manager_operation_performed
            or self.service_started
            or self.manual_recovery_required
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy scylla-install semantic evidence conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy scylla-install evidence digest")
        if self.evidence_digest != _evidence_entry_digest(self):
            raise StatePersistenceError(
                "deploy scylla-install evidence digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaInstallEvidenceEntry:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy scylla-install evidence entry",
        )
        try:
            parsed: dict[str, object] = {}
            integer_fields = {"attempt_index", "step_sequence", "package_count"}
            boolean_fields = {
                "installed",
                "changed",
                "service_masked",
                "service_inactive",
                "configuration_performed",
                "storage_mutation_performed",
                "tuning_performed",
                "manager_operation_performed",
                "service_started",
                "manual_recovery_required",
                "automatic_retry_allowed",
            }
            for name in cls.__dataclass_fields__:
                if name in integer_fields:
                    parsed[name] = _integer(value[name], name)
                elif name in boolean_fields:
                    parsed[name] = _boolean(value[name], name)
                elif name == "status":
                    parsed[name] = ScyllaInstallStatus(require_string(value, name))
                else:
                    parsed[name] = require_string(value, name)
            return cls(**parsed)  # type: ignore[arg-type]
        except ValueError as error:
            raise StatePersistenceError(
                "deploy scylla-install evidence status is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployScyllaInstallEvidence:
    """Immutable-prefix owner-only successful semantic evidence."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployScyllaInstallExecutionBinding
    entries: tuple[DeployScyllaInstallEvidenceEntry, ...]
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_INSTALL_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_SCYLLA_INSTALL_EVIDENCE_SCHEMA_VERSION
            or self.generation != len(self.entries)
            or not 1 <= len(self.entries) <= self.binding.scope_count
            or tuple(item.attempt_index for item in self.entries)
            != tuple(range(1, len(self.entries) + 1))
            or parse_timestamp(self.updated_at) < parse_timestamp(self.created_at)
        ):
            raise StatePersistenceError(
                "deploy scylla-install evidence prefix conflicts"
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
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaInstallEvidence:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy scylla-install evidence",
        )
        return cls(
            generation=_integer(value["generation"], "generation"),
            created_at=require_string(value, "created_at"),
            updated_at=require_string(value, "updated_at"),
            binding=DeployScyllaInstallExecutionBinding.from_object(
                _mapping(value["binding"], "binding")
            ),
            entries=tuple(
                DeployScyllaInstallEvidenceEntry.from_object(
                    _mapping(item, "evidence entry")
                )
                for item in _array(value["entries"], "evidence entries")
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaInstallExecution:
    record: DeployScyllaInstallExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaInstallEvidence:
    record: DeployScyllaInstallEvidence
    artifact_digest: str


class DeployScyllaInstallExecutionStore:
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
        self._path = deploy_scylla_install_execution_path(paths, operation_id)
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
    ) -> StoredDeployScyllaInstallExecution:
        value, digest = self._file.read()
        record = DeployScyllaInstallExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy scylla-install execution identity conflicts"
            )
        return StoredDeployScyllaInstallExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaInstallExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaInstallExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployScyllaInstallExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy scylla-install execution operation conflicts"
            )
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial deploy scylla-install execution generation conflicts"
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
                    "deploy scylla-install execution changed concurrently"
                )
            _validate_execution_transition(current.record, record)
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployScyllaInstallExecution(record, digest)


class DeployScyllaInstallEvidenceStore:
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
        self._path = deploy_scylla_install_evidence_path(paths, operation_id)
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
    ) -> StoredDeployScyllaInstallEvidence:
        value, digest = self._file.read()
        record = DeployScyllaInstallEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy scylla-install evidence identity conflicts"
            )
        return StoredDeployScyllaInstallEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaInstallEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def append_locked(
        self,
        record: DeployScyllaInstallEvidence,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployScyllaInstallEvidence:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy scylla-install evidence operation conflicts"
            )
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial deploy scylla-install evidence generation conflicts"
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
                    "deploy scylla-install evidence changed concurrently"
                )
            _validate_evidence_transition(current.record, record)
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployScyllaInstallEvidence(record, digest)


@dataclass(frozen=True, slots=True)
class DeployScyllaInstallExecutionReport:
    """Strict redacted successful execution report."""

    operation_id: uuid.UUID
    execution_state: DeployScyllaInstallExecutionState
    execution_artifact_state: DeployScyllaInstallArtifactState
    evidence_artifact_state: DeployScyllaInstallArtifactState
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
    installed_count: int
    changed_count: int
    package_version: str
    package_count: int
    package_set_digest: str
    package_provenance_digest: str
    repository_definition_digest: str
    signing_key_artifact_digest: str
    signing_key_identity_digest: str
    service_safe_count: int
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
        ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_SCHEMA_VERSION
    )
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_INSTALL_EVIDENCE_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_INSTALL_EVIDENCE_SCHEMA_VERSION
            or self.execution_state is not DeployScyllaInstallExecutionState.SUCCEEDED
            or not self.authorization_consumed
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.invocation_count != self.scope_count
            or self.scope_count != self.stable_id_count
            or self.installed_count != self.scope_count
            or self.service_safe_count != self.scope_count
            or self.package_version != SCYLLA_PACKAGE_VERSION
            or self.package_count != len(SCYLLA_PACKAGES)
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
                "deploy scylla-install execution report is invalid"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy scylla-install report digest")

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
                "installed_count": self.installed_count,
                "prohibited_action_count": self.prohibited_action_count,
                "schema_version": self.evidence_schema_version,
                "service_safe_count": self.service_safe_count,
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
            "package_policy": {
                "changed_count": self.changed_count,
                "package_count": self.package_count,
                "package_set_digest": self.package_set_digest,
                "package_version": self.package_version,
                "provenance_digest": self.package_provenance_digest,
                "repository_definition_digest": self.repository_definition_digest,
                "signing_key_artifact_digest": self.signing_key_artifact_digest,
                "signing_key_identity_digest": self.signing_key_identity_digest,
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
    authorization: DeployScyllaInstallAuthorizationScope
    authorization_scope_digest: str
    variables: tuple[tuple[str, object], ...]
    variables_digest: str
    command_digest: str
    source_digest: str
    image_architecture: str
    signing_key_identity_digest: str


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    authorization: StoredDeployScyllaInstallAuthorization
    binding: DeployScyllaInstallExecutionBinding
    scopes: tuple[_ExecutionScope, ...]
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport


def execute_deploy_scylla_install(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployScyllaInstallExecutionReport:
    """Execute only exact immutable authorized Scylla-install scopes."""

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
    execution_store = DeployScyllaInstallExecutionStore(paths, operation_id)
    evidence_store = DeployScyllaInstallEvidenceStore(paths, operation_id)
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
                "completed deploy scylla-install evidence is unavailable"
            )
        return _build_report(
            context,
            execution,
            evidence,
            execution_state=DeployScyllaInstallArtifactState.REUSED,
            evidence_state=DeployScyllaInstallArtifactState.REUSED,
        )
    if execution is not None and execution.record.state not in {
        DeployScyllaInstallExecutionState.PREPARED,
        DeployScyllaInstallExecutionState.SUCCEEDED,
    }:
        raise StateConflictError(
            "deploy scylla-install execution requires manual recovery and cannot retry"
        )

    service = AnsibleService(builder, runner)
    discovered = service.version(lock)
    if discovered != toolchain:
        raise StateConflictError("deploy scylla-install toolchain drifted")
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
        or execution.record.state is DeployScyllaInstallExecutionState.SUCCEEDED
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
                "deploy scylla-install prepared intent persistence failed "
                "before invocation"
            ) from error
    assert execution is not None

    while True:
        if execution.record.state is DeployScyllaInstallExecutionState.PREPARED:
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
                    "deploy scylla-install state drifted before start"
                )
            _validate_prefix(before_start, execution, evidence)
            scope = before_start.scopes[len(execution.record.attempts) - 1]
            try:
                execution = _persist_started(execution_store, execution, lock=lock)
            except StatePersistenceError as error:
                raise StatePersistenceError(
                    "deploy scylla-install authorization consumption failed "
                    "before invocation"
                ) from error
            try:
                result, command_digest = service.execute_operation_step(
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
                if command_digest != scope.command_digest:
                    raise AnsibleResultError(
                        "deploy scylla-install command result identity conflicts"
                    )
            except KeyboardInterrupt:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    DeployScyllaInstallExecutionState.INTERRUPTED,
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy scylla-install execution was interrupted; "
                    "manual recovery required"
                ) from None
            except (AnsibleError, StatePersistenceError) as error:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    (
                        _failure_state(error)
                        if isinstance(error, AnsibleError)
                        else DeployScyllaInstallExecutionState.MALFORMED_RESULT
                    ),
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy scylla-install execution is uncertain; "
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
                    "deploy scylla-install state changed after invocation; "
                    "manual recovery required"
                ) from error
            if after.binding != context.binding:
                raise StateConflictError(
                    "deploy scylla-install state changed after invocation; "
                    "manual recovery required"
                )
            try:
                entry = _semantic_entry(scope, result)
            except (AnsibleError, StatePersistenceError) as error:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    (
                        _failure_state(error)
                        if isinstance(error, AnsibleError)
                        else DeployScyllaInstallExecutionState.MALFORMED_RESULT
                    ),
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy scylla-install result is not strict successful "
                    "evidence; manual recovery required"
                ) from error
            try:
                evidence = _persist_evidence(
                    context, evidence_store, evidence, entry, lock=lock
                )
            except StatePersistenceError as error:
                raise StatePersistenceError(
                    "deploy scylla-install evidence persistence failed; "
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
                    "deploy scylla-install terminal persistence failed; "
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
                "deploy scylla-install next prepared intent failed before invocation"
            ) from error

    if evidence is None:
        raise StatePersistenceError(
            "deploy scylla-install completion evidence is missing"
        )
    _validate_prefix(context, execution, evidence)
    return _build_report(
        context,
        execution,
        evidence,
        execution_state=DeployScyllaInstallArtifactState.UPDATED,
        evidence_state=(
            DeployScyllaInstallArtifactState.UPDATED
            if evidence_initially_present
            else DeployScyllaInstallArtifactState.CREATED
        ),
    )


def deploy_scylla_install_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = (
        paths.operations
        / f"{operation_id}{DEPLOY_SCYLLA_INSTALL_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy scylla-install execution path is not canonical"
        )
    return path


def deploy_scylla_install_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = (
        paths.operations
        / f"{operation_id}{DEPLOY_SCYLLA_INSTALL_EVIDENCE_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy scylla-install evidence path is not canonical"
        )
    return path


def deploy_scylla_install_execution_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_INSTALL_EXECUTION_FILENAME_SUFFIX
    )


def deploy_scylla_install_evidence_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_SCYLLA_INSTALL_EVIDENCE_FILENAME_SUFFIX
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
    post = authorization_context.post
    loaded = post.authorization_context.preflight.discovery.post.chain.authorization_context.final_routes.post.post.base.host.loaded
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
            "deploy scylla-install readiness, journal, or toolchain conflicts"
        )
    readiness = _reconstructed_readiness(planning.base)
    if readiness_binding_digest(readiness) != readiness_record.readiness_digest:
        raise StateConflictError("deploy scylla-install readiness is stale")
    readiness.require_ready(OperationClassification.MUTATING)

    authorization_store = DeployScyllaInstallAuthorizationStore(paths, operation_id)
    validate_state_file(authorization_store.path, allow_missing=True)
    if not authorization_store.path.exists():
        raise StateConflictError(
            "deploy scylla-install execution requires immutable authorization"
        )
    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    package_provenance = _derive_package_provenance()
    scopes = _derive_authorization_scopes(authorization_context, package_provenance)
    expected_authorization = _build_authorization(
        authorization_context,
        scopes=scopes,
        package_provenance=package_provenance,
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
            "deploy scylla-install authorization is stale or consumed"
        )

    base_store = DeployNonJumpBaseOsEvidenceStore(paths, operation_id)
    validate_state_file(base_store.path, allow_missing=True)
    if not base_store.path.exists():
        raise StateConflictError(
            "deploy scylla-install requires current base-os evidence"
        )
    base_evidence = base_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    execution_scopes = _derive_execution_scopes(
        authorization_context,
        authorization,
        base_evidence,
        builder=builder,
    )
    stable_ids = tuple(
        sorted(scope.authorization.target_ids[0] for scope in execution_scopes)
    )
    scope_values = [
        {
            "attempt_index": scope.attempt_index,
            "authorization_command_digest": scope.authorization.command_digest,
            "authorization_scope_digest": scope.authorization_scope_digest,
            "authorization_variables_digest": scope.authorization.variables_digest,
            "command_digest": scope.command_digest,
            "source_digest": scope.source_digest,
            "target_digest": scope.authorization.target_digest,
            "variables_digest": scope.variables_digest,
        }
        for scope in execution_scopes
    ]
    base_entry_digests = tuple(
        entry.evidence_digest
        for entry in base_evidence.record.entries
        if any(host.logical_id in stable_ids for host in entry.hosts)
    )
    if not base_entry_digests:
        raise StateConflictError(
            "deploy scylla-install base-os evidence scope is unavailable"
        )
    trust = planning.base.trust
    reconciliation = authorization_context.reconciliation
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
        "postcheck_reconciliation_artifact_digest": reconciliation.artifact_digest,
        "postcheck_reconciliation_record_digest": reconciliation.record.record_digest,
        "postcheck_evidence_artifact_digest": (
            authorization_context.evidence.artifact_digest
        ),
        "postcheck_evidence_digest": reconciliation.record.evidence_digest,
        "base_os_evidence_artifact_digest": base_evidence.artifact_digest,
        "base_os_evidence_digest": _digest_object(list(base_entry_digests)),
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": readiness_record.record_digest,
        "catalog_digest": loaded.catalog_digest,
        "source_version": loaded.source.version,
        "source_digest": loaded.source.digest,
        "playbook_source_digest": _playbook_source_digest(loaded.source, _PLAYBOOK),
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
        "package_provenance_digest": package_provenance.provenance_digest,
        "scope_count": len(execution_scopes),
        "stable_id_count": len(stable_ids),
        "stable_id_set_digest": _digest_object(list(stable_ids)),
        "execution_scope_digest": _digest_object(scope_values),
        "binding_digest": "",
    }
    values["binding_digest"] = _binding_digest_from_values(values)
    return _ExecutionContext(
        authorization,
        DeployScyllaInstallExecutionBinding(**values),  # type: ignore[arg-type]
        execution_scopes,
        metadata,
        deploy.inventory,
        readiness,
    )


def _derive_execution_scopes(
    authorization_context: _AuthorizationContext,
    authorization: StoredDeployScyllaInstallAuthorization,
    base_evidence: StoredDeployNonJumpBaseOsEvidence,
    *,
    builder: AnsibleCommandBuilder,
) -> tuple[_ExecutionScope, ...]:
    post = authorization_context.post
    loaded = post.authorization_context.preflight.discovery.post.chain.authorization_context.final_routes.post.post.base.host.loaded
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    definition = get_playbook(_PLAYBOOK)
    source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
    if (
        definition.classification is not OperationClassification.MUTATING
        or definition.hosts != HostRole.SCYLLA.value
        or definition.serial != 1
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.check_mode is not CheckMode.PREVIEW
        or not definition.source_available
    ):
        raise StateConflictError("deploy scylla-install catalog policy conflicts")
    inventory_hosts = {
        host.logical_id: host for host in deploy.inventory.record.inventory.hosts
    }
    base_hosts = {
        host.logical_id: host
        for entry in base_evidence.record.entries
        for host in entry.hosts
    }
    storage_entries = {
        entry.stable_id: entry
        for entry in authorization_context.evidence.record.entries
    }
    desired_filter = dict(metadata.desired_spec.image_filters).get(HostRole.SCYLLA)
    if (
        desired_filter is None
        or desired_filter.operating_system != "Ubuntu"
        or desired_filter.operating_system_version != "24.04"
        or desired_filter.version_match is not ImageVersionMatch.EXACT
    ):
        raise StateConflictError(
            "deploy scylla-install desired image evidence is unsupported"
        )
    scopes: list[_ExecutionScope] = []
    for attempt_index, authorized in enumerate(authorization.record.scopes, start=1):
        stable_id = authorized.target_ids[0]
        inventory_host = inventory_hosts.get(stable_id)
        base_host = base_hosts.get(stable_id)
        storage_entry = storage_entries.get(stable_id)
        if (
            authorized.playbook != _PLAYBOOK
            or authorized.mapping_sequence != 11
            or authorized.classification is not OperationClassification.MUTATING
            or authorized.target_role != HostRole.SCYLLA.value
            or len(authorized.target_ids) != 1
            or authorized.source_digest != source_digest
            or inventory_host is None
            or inventory_host.role is not HostRole.SCYLLA
            or base_host is None
            or not base_host.applied
            or base_host.os_family != "Ubuntu"
            or base_host.os_version != "24.04"
            or base_host.image_architecture not in {"amd64", "aarch64"}
            or storage_entry is None
            or not storage_entry.readiness_for_scylla
            or storage_entry.failed_check_count
            or storage_entry.unknown_check_count
            or storage_entry.blocker_count
            or storage_entry.manual_recovery_required
        ):
            raise StateConflictError(
                "deploy scylla-install exact authorized scope conflicts"
            )
        payload = {
            "architecture": base_host.image_architecture,
            "channel": SCYLLA_CHANNEL,
            "cluster_uuid": str(metadata.cluster_uuid),
            "edition": SCYLLA_EDITION,
            "image_operating_system": "Ubuntu",
            "image_operating_system_version": "24.04",
            "logical_id": stable_id,
            "package_version": SCYLLA_PACKAGE_VERSION,
            "packages": list(SCYLLA_PACKAGES),
            "provenance": {
                "base_os_digest": next(
                    entry.evidence_digest
                    for entry in base_evidence.record.entries
                    if any(host.logical_id == stable_id for host in entry.hosts)
                ),
                "cluster_spec_digest": _digest_object(
                    metadata.desired_spec.to_object()
                ),
                "inventory_digest": deploy.inventory.digest,
                "observation_digest": deploy.observation.digest,
                "storage_postcheck_digest": storage_entry.evidence_digest,
                "trust_digest": planning.base.trust.digest,
            },
            "release_line": SCYLLA_RELEASE_LINE,
            "repository": {
                "definition_digest": SCYLLA_REPOSITORY_DEFINITION_DIGEST,
                "uri": SCYLLA_REPOSITORY_URI,
            },
            "schema_version": SCYLLA_INSTALL_SCHEMA_VERSION,
            "signing_key": {
                "artifact_digest": SCYLLA_SIGNING_KEY_DIGEST,
                "fingerprint": SCYLLA_SIGNING_KEY_FINGERPRINT,
                "resource": SCYLLA_SIGNING_KEY_RESOURCE,
            },
            "upstream_role_commit": SCYLLA_ROLE_COMMIT,
        }
        variables = {"deploy_scylla_vms_scylla_install": payload}
        selected, validated, variables_digest, command_digest = (
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
        if selected != definition:
            raise StateConflictError(
                "deploy scylla-install anchored command policy conflicts"
            )
        scopes.append(
            _ExecutionScope(
                attempt_index,
                authorized,
                _digest_object(authorized.to_object()),
                tuple(sorted(validated.items())),
                variables_digest,
                command_digest,
                source_digest,
                base_host.image_architecture,
                authorization.record.package_provenance.signing_key_identity_digest,
            )
        )
    if (
        not scopes
        or tuple(scope.authorization.sequence for scope in scopes)
        != tuple(sorted(scope.authorization.sequence for scope in scopes))
        or tuple(scope.authorization.target_ids[0] for scope in scopes)
        != tuple(sorted(scope.authorization.target_ids[0] for scope in scopes))
    ):
        raise StateConflictError("deploy scylla-install execution order conflicts")
    return tuple(scopes)


def _validate_prefix(
    context: _ExecutionContext,
    execution: StoredDeployScyllaInstallExecution | None,
    evidence: StoredDeployScyllaInstallEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "deploy scylla-install evidence exists without execution"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError("deploy scylla-install execution provenance is stale")
    if evidence is not None and evidence.record.binding != context.binding:
        raise StateConflictError("deploy scylla-install evidence provenance is stale")
    for index, attempt in enumerate(execution.record.attempts):
        scope = context.scopes[index]
        authorized = scope.authorization
        if (
            attempt.attempt_index != index + 1
            or attempt.step_sequence != authorized.sequence
            or attempt.stable_id != authorized.target_ids[0]
            or attempt.target_digest != authorized.target_digest
            or attempt.authorization_scope_digest != scope.authorization_scope_digest
            or attempt.authorization_variables_digest != authorized.variables_digest
            or attempt.authorization_command_digest != authorized.command_digest
            or attempt.variables_digest != scope.variables_digest
            or attempt.command_digest != scope.command_digest
            or attempt.source_digest != scope.source_digest
            or attempt.package_provenance_digest
            != context.binding.package_provenance_digest
        ):
            raise StateConflictError("deploy scylla-install execution scope conflicts")
    entries = evidence.record.entries if evidence is not None else ()
    succeeded = tuple(
        attempt
        for attempt in execution.record.attempts
        if attempt.state is DeployScyllaInstallExecutionState.SUCCEEDED
    )
    if len(entries) not in {
        len(succeeded),
        len(succeeded)
        + (
            1
            if execution.record.state is DeployScyllaInstallExecutionState.STARTED
            else 0
        ),
    }:
        raise StateConflictError(
            "deploy scylla-install execution/evidence prefixes conflict"
        )
    for index, entry in enumerate(entries):
        attempt = execution.record.attempts[index]
        scope = context.scopes[index]
        if (
            entry.attempt_index != index + 1
            or entry.step_sequence != scope.authorization.sequence
            or entry.stable_id != scope.authorization.target_ids[0]
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
                "deploy scylla-install semantic evidence conflicts"
            )


def _persist_prepared(
    context: _ExecutionContext,
    store: DeployScyllaInstallExecutionStore,
    current: StoredDeployScyllaInstallExecution | None,
    scope: _ExecutionScope,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaInstallExecution:
    now = _timestamp()
    attempt = DeployScyllaInstallExecutionAttempt(
        attempt_index=scope.attempt_index,
        step_sequence=scope.authorization.sequence,
        stable_id=scope.authorization.target_ids[0],
        target_digest=scope.authorization.target_digest,
        authorization_scope_digest=scope.authorization_scope_digest,
        authorization_variables_digest=scope.authorization.variables_digest,
        authorization_command_digest=scope.authorization.command_digest,
        variables_digest=scope.variables_digest,
        command_digest=scope.command_digest,
        source_digest=scope.source_digest,
        package_version=SCYLLA_PACKAGE_VERSION,
        package_provenance_digest=context.binding.package_provenance_digest,
        state=DeployScyllaInstallExecutionState.PREPARED,
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
        record = DeployScyllaInstallExecution(
            generation=1,
            created_at=now,
            updated_at=now,
            binding=context.binding,
            state=DeployScyllaInstallExecutionState.PREPARED,
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
    if current.record.state is not DeployScyllaInstallExecutionState.SUCCEEDED:
        raise StateConflictError(
            "deploy scylla-install cannot prepare after uncertain execution"
        )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=DeployScyllaInstallExecutionState.PREPARED,
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
    store: DeployScyllaInstallExecutionStore,
    current: StoredDeployScyllaInstallExecution,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaInstallExecution:
    if current.record.state is not DeployScyllaInstallExecutionState.PREPARED:
        raise StateConflictError("deploy scylla-install start requires prepared intent")
    now = _timestamp()
    attempt = replace(
        current.record.attempts[-1],
        state=DeployScyllaInstallExecutionState.STARTED,
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
        state=DeployScyllaInstallExecutionState.STARTED,
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
    store: DeployScyllaInstallExecutionStore,
    current: StoredDeployScyllaInstallExecution,
    state: DeployScyllaInstallExecutionState,
    *,
    lock: ClusterLock,
) -> None:
    try:
        _persist_uncertain(store, current, state, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy scylla-install uncertain outcome persistence failed; "
            "manual recovery required"
        ) from error


def _persist_uncertain(
    store: DeployScyllaInstallExecutionStore,
    current: StoredDeployScyllaInstallExecution,
    state: DeployScyllaInstallExecutionState,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaInstallExecution:
    if (
        current.record.state is not DeployScyllaInstallExecutionState.STARTED
        or state
        not in {
            DeployScyllaInstallExecutionState.FAILED,
            DeployScyllaInstallExecutionState.TIMED_OUT,
            DeployScyllaInstallExecutionState.INTERRUPTED,
            DeployScyllaInstallExecutionState.UNREACHABLE,
            DeployScyllaInstallExecutionState.MALFORMED_RESULT,
        }
    ):
        raise StatePersistenceError(
            "deploy scylla-install uncertain transition conflicts"
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
    store: DeployScyllaInstallExecutionStore,
    current: StoredDeployScyllaInstallExecution,
    *,
    entry: DeployScyllaInstallEvidenceEntry,
    lock: ClusterLock,
) -> StoredDeployScyllaInstallExecution:
    if current.record.state is not DeployScyllaInstallExecutionState.STARTED:
        raise StateConflictError("deploy scylla-install terminal transition conflicts")
    now = _timestamp()
    attempt = replace(
        current.record.attempts[-1],
        state=DeployScyllaInstallExecutionState.SUCCEEDED,
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
        state=DeployScyllaInstallExecutionState.SUCCEEDED,
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
    store: DeployScyllaInstallEvidenceStore,
    current: StoredDeployScyllaInstallEvidence | None,
    entry: DeployScyllaInstallEvidenceEntry,
    *,
    lock: ClusterLock,
) -> StoredDeployScyllaInstallEvidence:
    if current is not None and len(current.record.entries) >= entry.attempt_index:
        existing = current.record.entries[entry.attempt_index - 1]
        if existing != entry:
            raise StateConflictError(
                "deploy scylla-install evidence conflicts with existing entry"
            )
        return current
    if current is not None and len(current.record.entries) != entry.attempt_index - 1:
        raise StateConflictError("deploy scylla-install evidence sequence conflicts")
    now = _timestamp()
    record = DeployScyllaInstallEvidence(
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
) -> DeployScyllaInstallEvidenceEntry:
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.MUTATING
        or result.check_mode
        or result.scylla_install is not None
    ):
        raise AnsibleResultError(
            "deploy scylla-install strict result identity conflicts"
        )
    payload = cast(
        dict[str, object],
        dict(scope.variables)["deploy_scylla_vms_scylla_install"],
    )
    try:
        parsed = parse_scylla_install_execution(
            result.stdout,
            expected_payload=payload,
            exit_code=result.exit_code,
        )
    except AnsibleError as error:
        raise AnsibleResultError(
            "deploy scylla-install strict result is malformed"
        ) from error
    if parsed.status not in _SUCCESS_STATUSES:
        message = "unreachable" if result.exit_code == 4 else "execution failed"
        raise AnsibleError(f"deploy scylla-install {message}")
    _validate_success_evidence(parsed)
    package = dict(parsed.packages)
    result_digest = _digest_object(
        {
            "changed": parsed.status is ScyllaInstallStatus.INSTALLED,
            "configuration_performed": parsed.configuration_performed,
            "installed_edition": parsed.installed_edition,
            "installed_version": parsed.installed_version,
            "logical_id": parsed.logical_id,
            "manager_operation_performed": parsed.manager_operation_performed,
            "package_set_digest": _digest_object(package),
            "provenance_digest": _digest_object(dict(parsed.provenance)),
            "repository_definition_digest": parsed.repository_digest,
            "schema_version": parsed.schema_version,
            "service_inactive": parsed.service_inactive,
            "service_masked": parsed.service_masked,
            "service_started": parsed.service_started,
            "signing_key_artifact_digest": parsed.signing_key_digest,
            "status": parsed.status.value,
            "storage_mutation_performed": parsed.storage_mutation_performed,
            "tuning_performed": parsed.tuning_performed,
        }
    )
    values: dict[str, object] = {
        "attempt_index": scope.attempt_index,
        "step_sequence": scope.authorization.sequence,
        "stable_id": scope.authorization.target_ids[0],
        "image_architecture": scope.image_architecture,
        "status": parsed.status,
        "installed": True,
        "changed": parsed.status is ScyllaInstallStatus.INSTALLED,
        "package_version": SCYLLA_PACKAGE_VERSION,
        "package_count": len(parsed.packages),
        "package_set_digest": _digest_object([name for name, _ in parsed.packages]),
        "repository_definition_digest": parsed.repository_digest,
        "signing_key_artifact_digest": parsed.signing_key_digest,
        "signing_key_identity_digest": scope.signing_key_identity_digest,
        "service_masked": cast(bool, parsed.service_masked),
        "service_inactive": cast(bool, parsed.service_inactive),
        "configuration_performed": cast(bool, parsed.configuration_performed),
        "storage_mutation_performed": cast(bool, parsed.storage_mutation_performed),
        "tuning_performed": cast(bool, parsed.tuning_performed),
        "manager_operation_performed": cast(bool, parsed.manager_operation_performed),
        "service_started": cast(bool, parsed.service_started),
        "provenance_digest": _digest_object(dict(parsed.provenance)),
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "source_digest": scope.source_digest,
        "result_digest": result_digest,
        "evidence_digest": "",
    }
    values["evidence_digest"] = _evidence_entry_digest_from_values(values)
    return DeployScyllaInstallEvidenceEntry(**values)  # type: ignore[arg-type]


def _validate_success_evidence(evidence: ScyllaInstallEvidence) -> None:
    if (
        evidence.logical_id == ""
        or evidence.requested_edition != SCYLLA_EDITION
        or evidence.requested_version != SCYLLA_PACKAGE_VERSION
        or evidence.installed_edition != SCYLLA_EDITION
        or evidence.installed_version != SCYLLA_PACKAGE_VERSION
        or evidence.packages
        != tuple((name, SCYLLA_PACKAGE_VERSION) for name in SCYLLA_PACKAGES)
        or evidence.repository_digest != SCYLLA_REPOSITORY_DEFINITION_DIGEST
        or evidence.signing_key_digest != SCYLLA_SIGNING_KEY_DIGEST
        or evidence.signing_key_fingerprint != SCYLLA_SIGNING_KEY_FINGERPRINT
        or evidence.service_masked is not True
        or evidence.service_inactive is not True
        or evidence.configuration_performed is not False
        or evidence.storage_mutation_performed is not False
        or evidence.tuning_performed is not False
        or evidence.manager_operation_performed is not False
        or evidence.service_started is not False
        or evidence.blockers
    ):
        raise AnsibleResultError("deploy scylla-install successful evidence conflicts")


def _build_report(
    context: _ExecutionContext,
    execution: StoredDeployScyllaInstallExecution,
    evidence: StoredDeployScyllaInstallEvidence,
    *,
    execution_state: DeployScyllaInstallArtifactState,
    evidence_state: DeployScyllaInstallArtifactState,
) -> DeployScyllaInstallExecutionReport:
    if (
        not execution.record.all_scopes_completed
        or execution.record.state is not DeployScyllaInstallExecutionState.SUCCEEDED
        or len(evidence.record.entries) != len(context.scopes)
    ):
        raise StateConflictError("deploy scylla-install execution is not complete")
    package = context.authorization.record.package_provenance
    entries = evidence.record.entries
    return DeployScyllaInstallExecutionReport(
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
        installed_count=sum(entry.installed for entry in entries),
        changed_count=sum(entry.changed for entry in entries),
        package_version=package.package_version,
        package_count=package.package_count,
        package_set_digest=package.package_set_digest,
        package_provenance_digest=package.provenance_digest,
        repository_definition_digest=package.repository_definition_digest,
        signing_key_artifact_digest=package.signing_key_artifact_digest,
        signing_key_identity_digest=package.signing_key_identity_digest,
        service_safe_count=sum(
            entry.service_masked and entry.service_inactive for entry in entries
        ),
        prohibited_action_count=sum(
            entry.configuration_performed
            or entry.storage_mutation_performed
            or entry.tuning_performed
            or entry.manager_operation_performed
            or entry.service_started
            for entry in entries
        ),
        manual_recovery_required=False,
        automatic_retry_allowed=False,
        skip_allowed=False,
        continue_allowed=False,
        rollback_performed=False,
        journal_status=context.binding.journal_status,
        journal_phase=context.binding.journal_phase,
    )


def _failure_state(error: AnsibleError) -> DeployScyllaInstallExecutionState:
    cause = error.__cause__
    if isinstance(cause, ProcessTimeoutError):
        return DeployScyllaInstallExecutionState.TIMED_OUT
    if isinstance(cause, ProcessOutputError):
        return DeployScyllaInstallExecutionState.MALFORMED_RESULT
    message = str(error).lower()
    if "unreachable" in message:
        return DeployScyllaInstallExecutionState.UNREACHABLE
    if isinstance(error, AnsibleResultError) or "malformed" in message:
        return DeployScyllaInstallExecutionState.MALFORMED_RESULT
    return DeployScyllaInstallExecutionState.FAILED


def _validate_execution_transition(
    current: DeployScyllaInstallExecution,
    replacement: DeployScyllaInstallExecution,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or current.all_scopes_completed
        or current.state
        not in {
            DeployScyllaInstallExecutionState.PREPARED,
            DeployScyllaInstallExecutionState.STARTED,
            DeployScyllaInstallExecutionState.SUCCEEDED,
        }
    ):
        raise StatePersistenceError(
            "deploy scylla-install execution transition is invalid"
        )
    if current.state is DeployScyllaInstallExecutionState.PREPARED:
        valid = (
            len(replacement.attempts) == len(current.attempts)
            and replacement.attempts[:-1] == current.attempts[:-1]
            and replacement.attempts[-1].state
            is DeployScyllaInstallExecutionState.STARTED
        )
    elif current.state is DeployScyllaInstallExecutionState.STARTED:
        valid = (
            len(replacement.attempts) == len(current.attempts)
            and replacement.attempts[:-1] == current.attempts[:-1]
            and replacement.attempts[-1].state
            not in {
                DeployScyllaInstallExecutionState.PREPARED,
                DeployScyllaInstallExecutionState.STARTED,
            }
        )
    else:
        valid = (
            len(current.attempts) < current.binding.scope_count
            and replacement.attempts[:-1] == current.attempts
            and replacement.attempts[-1].state
            is DeployScyllaInstallExecutionState.PREPARED
        )
    if not valid:
        raise StatePersistenceError(
            "deploy scylla-install execution transition conflicts"
        )


def _validate_evidence_transition(
    current: DeployScyllaInstallEvidence,
    replacement: DeployScyllaInstallEvidence,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or replacement.entries[:-1] != current.entries
        or len(replacement.entries) != len(current.entries) + 1
    ):
        raise StatePersistenceError(
            "deploy scylla-install evidence transition is invalid"
        )


def _binding_digest(binding: DeployScyllaInstallExecutionBinding) -> str:
    value = binding.to_object()
    value["binding_digest"] = ""
    return _digest_object(value)


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployScyllaInstallExecutionBinding.__dataclass_fields__.items():
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


def _evidence_entry_digest(entry: DeployScyllaInstallEvidenceEntry) -> str:
    value = entry.to_object()
    value["evidence_digest"] = ""
    return _digest_object(value)


def _evidence_entry_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployScyllaInstallEvidenceEntry.__dataclass_fields__.items():
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
            "deploy scylla-install execution paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy scylla-install execution requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy scylla-install execution artifacts"
        ) from error
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_SCYLLA_INSTALL_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_SCYLLA_INSTALL_EVIDENCE_FILENAME_SUFFIX,
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
                    "deploy scylla-install execution artifacts are ambiguous"
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
            "deploy scylla-install toolchain version is invalid"
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
    "ANSIBLE_DEPLOY_SCYLLA_INSTALL_EVIDENCE_ENTRY_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_INSTALL_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_BINDING_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_SCHEMA_VERSION",
    "DEPLOY_SCYLLA_INSTALL_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_SCYLLA_INSTALL_EXECUTION_FILENAME_SUFFIX",
    "DeployScyllaInstallArtifactState",
    "DeployScyllaInstallEvidence",
    "DeployScyllaInstallEvidenceEntry",
    "DeployScyllaInstallEvidenceStore",
    "DeployScyllaInstallExecution",
    "DeployScyllaInstallExecutionAttempt",
    "DeployScyllaInstallExecutionBinding",
    "DeployScyllaInstallExecutionReport",
    "DeployScyllaInstallExecutionState",
    "DeployScyllaInstallExecutionStore",
    "StoredDeployScyllaInstallEvidence",
    "StoredDeployScyllaInstallExecution",
    "deploy_scylla_install_evidence_id_from_filename",
    "deploy_scylla_install_evidence_path",
    "deploy_scylla_install_execution_id_from_filename",
    "deploy_scylla_install_execution_path",
    "execute_deploy_scylla_install",
]
