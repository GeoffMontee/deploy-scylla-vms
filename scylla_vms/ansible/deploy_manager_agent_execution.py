"""Durable exact-scope deploy ``manager-agent`` execution and evidence.

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

from scylla_vms.ansible.base_os import (
    BaseOsEvidence,
    BaseOsHostEvidence,
)
from scylla_vms.ansible.commands import AnsibleCommandBuilder
from scylla_vms.ansible.deploy_manager_agent_authorization import (
    ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_SCHEMA_VERSION,
    DeployManagerAgentAuthorizationScope,
    DeployManagerAgentAuthorizationStore,
    StoredDeployManagerAgentAuthorization,
    _AuthorizationContext,
    _build_authorization,
    _derive_authorization_scopes,
    _derive_package_provenance,
    _load_authorization_context,
    _scylla_install_evidence,
    _signing_key_identity_digest,
    _validate_prerequisite_entry,
)
from scylla_vms.ansible.deploy_plan import (
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import _loaded
from scylla_vms.ansible.manager_agent import (
    MANAGER_AGENT_SCHEMA_VERSION,
    MANAGER_PACKAGE_VERSION,
    MANAGER_PACKAGES,
    MANAGER_RELEASE_LINE,
    MANAGER_REPOSITORY_DEFINITION_DIGEST,
    ManagerAgentEvidence,
    ManagerAgentStatus,
    build_manager_agent_payload,
    parse_manager_agent_execution,
)
from scylla_vms.ansible.operation_binding import readiness_binding_digest
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_install import (
    SCYLLA_SIGNING_KEY_DIGEST,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
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

ANSIBLE_DEPLOY_MANAGER_AGENT_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-agent-execution-binding/v1"
)
ANSIBLE_DEPLOY_MANAGER_AGENT_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-agent-execution/v1"
)
ANSIBLE_DEPLOY_MANAGER_AGENT_EVIDENCE_ENTRY_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-agent-evidence-entry/v1"
)
ANSIBLE_DEPLOY_MANAGER_AGENT_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-agent-evidence/v1"
)
ANSIBLE_DEPLOY_MANAGER_AGENT_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-agent-execution-report/v1"
)

DEPLOY_MANAGER_AGENT_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-agent-execution.json"
)
DEPLOY_MANAGER_AGENT_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-agent-evidence.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "manager-agent"
_STAGE = "post-monitoring-stack-manager-agent-execution"
_SCOPE_KIND = "bootstrap-healthy-scylla-manager-agent-install"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SUCCESS_STATUSES = frozenset(
    {ManagerAgentStatus.INSTALLED, ManagerAgentStatus.NO_CHANGE}
)


class DeployManagerAgentExecutionState(StrEnum):
    """Bounded durable states for exact authorized install attempts."""

    PREPARED = "prepared"
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"
    DRIFTED = "drifted"


class DeployManagerAgentArtifactState(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployManagerAgentExecutionBinding:
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
    post_monitoring_artifact_digest: str
    post_monitoring_record_digest: str
    post_monitoring_effective_plan_digest: str
    install_reconciliation_artifact_digest: str
    install_reconciliation_record_digest: str
    install_evidence_artifact_digest: str
    install_evidence_digest: str
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
    package_provenance_digest: str
    scope_count: int
    stable_id_count: int
    stable_id_set_digest: str
    execution_scope_digest: str
    binding_digest: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_AGENT_EXECUTION_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_AGENT_EXECUTION_BINDING_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.scope_count < 1
            or self.stable_id_count < 1
            or self.scope_count != self.stable_id_count
        ):
            raise StatePersistenceError(
                "deploy manager-agent execution binding is invalid"
            )
        validate_cluster_name(self.cluster_name)
        for count in (
            self.journal_generation,
            self.metadata_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
            self.scope_count,
            self.stable_id_count,
        ):
            _positive_integer(count, "deploy manager-agent binding count")
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy manager-agent binding digest")
        _validate_toolchain_version(self.toolchain_version)
        if self.binding_digest != _binding_digest(self):
            raise StatePersistenceError(
                "deploy manager-agent execution binding digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerAgentExecutionBinding:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy manager-agent execution binding",
        )
        integer_fields = {
            "journal_generation",
            "metadata_generation",
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
class DeployManagerAgentExecutionAttempt:
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
    package_version_digest: str
    package_provenance_digest: str
    state: DeployManagerAgentExecutionState
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
    result_schema_version: str = MANAGER_AGENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.attempt_index < 1
            or self.step_sequence < 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.package_version_digest != _digest_object(MANAGER_PACKAGE_VERSION)
            or self.result_schema_version != MANAGER_AGENT_SCHEMA_VERSION
            or not isinstance(self.state, DeployManagerAgentExecutionState)
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy manager-agent execution attempt is invalid"
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
                validate_digest(digest, "deploy manager-agent attempt digest")
        prepared = parse_timestamp(self.prepared_at)
        started = _optional_timestamp(self.started_at)
        completed = _optional_timestamp(self.completed_at)
        if (
            (started is not None and started < prepared)
            or (completed is not None and started is None)
            or (completed is not None and started is not None and completed < started)
        ):
            raise StatePersistenceError(
                "deploy manager-agent attempt timestamps conflict"
            )
        if self.state is DeployManagerAgentExecutionState.PREPARED:
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
        elif self.state is DeployManagerAgentExecutionState.STARTED:
            valid = (
                started is not None
                and completed is None
                and self.invocation_may_have_occurred
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.manual_recovery_required
            )
        elif self.state is DeployManagerAgentExecutionState.SUCCEEDED:
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
                self.state is not DeployManagerAgentExecutionState.PREPARED
                and self.authorization_consumed_at_start != (self.attempt_index == 1)
            )
            or (
                self.state is DeployManagerAgentExecutionState.PREPARED
                and self.authorization_consumed_at_start
            )
        ):
            raise StatePersistenceError("deploy manager-agent attempt state conflicts")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerAgentExecutionAttempt:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy manager-agent attempt",
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
                package_version_digest=require_string(value, "package_version_digest"),
                package_provenance_digest=require_string(
                    value, "package_provenance_digest"
                ),
                state=DeployManagerAgentExecutionState(require_string(value, "state")),
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
                "deploy manager-agent attempt state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerAgentExecution:
    """Generation-guarded exact-prefix execution state."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployManagerAgentExecutionBinding
    state: DeployManagerAgentExecutionState
    authorization_consumed: bool
    invocation_count: int
    all_scopes_completed: bool
    attempts: tuple[DeployManagerAgentExecutionAttempt, ...]
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_AGENT_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        invoked = tuple(
            attempt
            for attempt in self.attempts
            if attempt.state is not DeployManagerAgentExecutionState.PREPARED
        )
        if (
            self.schema_version != ANSIBLE_DEPLOY_MANAGER_AGENT_EXECUTION_SCHEMA_VERSION
            or self.generation < 1
            or not self.attempts
            or len(self.attempts) > self.binding.scope_count
            or self.state is not self.attempts[-1].state
            or tuple(item.attempt_index for item in self.attempts)
            != tuple(range(1, len(self.attempts) + 1))
            or any(
                attempt.state is not DeployManagerAgentExecutionState.SUCCEEDED
                for attempt in self.attempts[:-1]
            )
            or self.invocation_count != len(invoked)
            or self.authorization_consumed != bool(invoked)
            or self.all_scopes_completed
            != (
                self.state is DeployManagerAgentExecutionState.SUCCEEDED
                and len(self.attempts) == self.binding.scope_count
            )
        ):
            raise StatePersistenceError(
                "deploy manager-agent execution summary conflicts"
            )
        if parse_timestamp(self.updated_at) < parse_timestamp(self.created_at):
            raise StatePersistenceError(
                "deploy manager-agent execution timestamps conflict"
            )

    @property
    def manual_recovery_required(self) -> bool:
        return self.state not in {
            DeployManagerAgentExecutionState.PREPARED,
            DeployManagerAgentExecutionState.SUCCEEDED,
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
    def from_object(cls, value: Mapping[str, object]) -> DeployManagerAgentExecution:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy manager-agent execution",
        )
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                updated_at=require_string(value, "updated_at"),
                binding=DeployManagerAgentExecutionBinding.from_object(
                    _mapping(value["binding"], "binding")
                ),
                state=DeployManagerAgentExecutionState(require_string(value, "state")),
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
                    DeployManagerAgentExecutionAttempt.from_object(
                        _mapping(item, "attempt")
                    )
                    for item in _array(value["attempts"], "attempts")
                ),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy manager-agent execution state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerAgentEvidenceEntry:
    """Strict address-free semantic evidence for one successful install scope."""

    attempt_index: int
    step_sequence: int
    stable_id: str
    image_architecture: str
    status: ManagerAgentStatus
    installed: bool
    changed: bool
    package_version_digest: str
    package_count: int
    package_set_digest: str
    repository_definition_digest: str
    signing_key_artifact_digest: str
    signing_key_identity_digest: str
    service_disabled: bool
    service_inactive: bool
    configuration_performed: bool
    auth_token_configured: bool
    helper_slice_configured: bool
    server_reachability: str
    service_started: bool
    provenance_digest: str
    variables_digest: str
    command_digest: str
    source_digest: str
    result_digest: str
    evidence_digest: str
    manual_recovery_required: bool = False
    automatic_retry_allowed: bool = False
    result_schema_version: str = MANAGER_AGENT_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_AGENT_EVIDENCE_ENTRY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_AGENT_EVIDENCE_ENTRY_SCHEMA_VERSION
            or self.result_schema_version != MANAGER_AGENT_SCHEMA_VERSION
            or self.attempt_index < 1
            or self.step_sequence < 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.image_architecture not in {"amd64", "aarch64"}
            or self.status not in _SUCCESS_STATUSES
            or not self.installed
            or self.changed != (self.status is ManagerAgentStatus.INSTALLED)
            or self.package_version_digest != _digest_object(MANAGER_PACKAGE_VERSION)
            or self.package_count != len(MANAGER_PACKAGES)
            or self.package_set_digest != _digest_object(list(MANAGER_PACKAGES))
            or self.repository_definition_digest != MANAGER_REPOSITORY_DEFINITION_DIGEST
            or self.signing_key_artifact_digest != SCYLLA_SIGNING_KEY_DIGEST
            or self.signing_key_identity_digest != _signing_key_identity_digest()
            or not self.service_disabled
            or not self.service_inactive
            or self.configuration_performed
            or self.auth_token_configured
            or self.helper_slice_configured
            or self.server_reachability != "not-performed"
            or self.service_started
            or self.manual_recovery_required
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy manager-agent semantic evidence conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy manager-agent evidence digest")
        if self.evidence_digest != _evidence_entry_digest(self):
            raise StatePersistenceError(
                "deploy manager-agent evidence digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerAgentEvidenceEntry:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy manager-agent evidence entry",
        )
        try:
            parsed: dict[str, object] = {}
            integer_fields = {"attempt_index", "step_sequence", "package_count"}
            boolean_fields = {
                "installed",
                "changed",
                "service_disabled",
                "service_inactive",
                "configuration_performed",
                "auth_token_configured",
                "helper_slice_configured",
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
                    parsed[name] = ManagerAgentStatus(require_string(value, name))
                else:
                    parsed[name] = require_string(value, name)
            return cls(**parsed)  # type: ignore[arg-type]
        except ValueError as error:
            raise StatePersistenceError(
                "deploy manager-agent evidence status is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerAgentEvidence:
    """Immutable-prefix owner-only successful semantic evidence."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployManagerAgentExecutionBinding
    entries: tuple[DeployManagerAgentEvidenceEntry, ...]
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_AGENT_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_MANAGER_AGENT_EVIDENCE_SCHEMA_VERSION
            or self.generation != len(self.entries)
            or not 1 <= len(self.entries) <= self.binding.scope_count
            or tuple(item.attempt_index for item in self.entries)
            != tuple(range(1, len(self.entries) + 1))
            or parse_timestamp(self.updated_at) < parse_timestamp(self.created_at)
        ):
            raise StatePersistenceError(
                "deploy manager-agent evidence prefix conflicts"
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
    def from_object(cls, value: Mapping[str, object]) -> DeployManagerAgentEvidence:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy manager-agent evidence",
        )
        return cls(
            generation=_integer(value["generation"], "generation"),
            created_at=require_string(value, "created_at"),
            updated_at=require_string(value, "updated_at"),
            binding=DeployManagerAgentExecutionBinding.from_object(
                _mapping(value["binding"], "binding")
            ),
            entries=tuple(
                DeployManagerAgentEvidenceEntry.from_object(
                    _mapping(item, "evidence entry")
                )
                for item in _array(value["entries"], "evidence entries")
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredDeployManagerAgentExecution:
    record: DeployManagerAgentExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployManagerAgentEvidence:
    record: DeployManagerAgentEvidence
    artifact_digest: str


class DeployManagerAgentExecutionStore:
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
        self._path = deploy_manager_agent_execution_path(paths, operation_id)
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
    ) -> StoredDeployManagerAgentExecution:
        value, digest = self._file.read()
        record = DeployManagerAgentExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy manager-agent execution identity conflicts"
            )
        return StoredDeployManagerAgentExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerAgentExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerAgentExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployManagerAgentExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy manager-agent execution operation conflicts"
            )
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial deploy manager-agent execution generation conflicts"
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
                    "deploy manager-agent execution changed concurrently"
                )
            _validate_execution_transition(current.record, record)
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployManagerAgentExecution(record, digest)


class DeployManagerAgentEvidenceStore:
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
        self._path = deploy_manager_agent_evidence_path(paths, operation_id)
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
    ) -> StoredDeployManagerAgentEvidence:
        value, digest = self._file.read()
        record = DeployManagerAgentEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy manager-agent evidence identity conflicts"
            )
        return StoredDeployManagerAgentEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerAgentEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def append_locked(
        self,
        record: DeployManagerAgentEvidence,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployManagerAgentEvidence:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy manager-agent evidence operation conflicts"
            )
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial deploy manager-agent evidence generation conflicts"
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
                    "deploy manager-agent evidence changed concurrently"
                )
            _validate_evidence_transition(current.record, record)
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployManagerAgentEvidence(record, digest)


@dataclass(frozen=True, slots=True)
class DeployManagerAgentExecutionReport:
    """Strict redacted successful execution report."""

    operation_id: uuid.UUID
    execution_state: DeployManagerAgentExecutionState
    execution_artifact_state: DeployManagerAgentArtifactState
    evidence_artifact_state: DeployManagerAgentArtifactState
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
    package_version_digest: str
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
        ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_SCHEMA_VERSION
    )
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_AGENT_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = ANSIBLE_DEPLOY_MANAGER_AGENT_EVIDENCE_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_AGENT_EXECUTION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_AGENT_EXECUTION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_MANAGER_AGENT_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_MANAGER_AGENT_EVIDENCE_SCHEMA_VERSION
            or self.execution_state is not DeployManagerAgentExecutionState.SUCCEEDED
            or not self.authorization_consumed
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.invocation_count != self.scope_count
            or self.scope_count != self.stable_id_count
            or self.installed_count != self.scope_count
            or self.service_safe_count != self.scope_count
            or self.package_version_digest != _digest_object(MANAGER_PACKAGE_VERSION)
            or self.package_count != len(MANAGER_PACKAGES)
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
                "deploy manager-agent execution report is invalid"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy manager-agent report digest")

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
                "package_version_digest": self.package_version_digest,
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
    authorization: DeployManagerAgentAuthorizationScope
    authorization_scope_digest: str
    variables: tuple[tuple[str, object], ...]
    variables_digest: str
    command_digest: str
    source_digest: str
    image_architecture: str
    signing_key_identity_digest: str


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    authorization: StoredDeployManagerAgentAuthorization
    binding: DeployManagerAgentExecutionBinding
    scopes: tuple[_ExecutionScope, ...]
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport


def execute_deploy_manager_agent(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployManagerAgentExecutionReport:
    """Execute only exact immutable authorized Manager-agent scopes."""

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
    execution_store = DeployManagerAgentExecutionStore(paths, operation_id)
    evidence_store = DeployManagerAgentEvidenceStore(paths, operation_id)
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
                "completed deploy manager-agent evidence is unavailable"
            )
        return _build_report(
            context,
            execution,
            evidence,
            execution_state=DeployManagerAgentArtifactState.REUSED,
            evidence_state=DeployManagerAgentArtifactState.REUSED,
        )
    if execution is not None and execution.record.state not in {
        DeployManagerAgentExecutionState.PREPARED,
        DeployManagerAgentExecutionState.SUCCEEDED,
    }:
        raise StateConflictError(
            "deploy manager-agent execution requires manual recovery and cannot retry"
        )

    service = AnsibleService(builder, runner)
    discovered = service.version(lock)
    if discovered != toolchain:
        raise StateConflictError("deploy manager-agent toolchain drifted")
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
        or execution.record.state is DeployManagerAgentExecutionState.SUCCEEDED
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
                "deploy manager-agent prepared intent persistence failed "
                "before invocation"
            ) from error
    assert execution is not None

    while True:
        if execution.record.state is DeployManagerAgentExecutionState.PREPARED:
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
                    "deploy manager-agent state drifted before start"
                )
            _validate_prefix(before_start, execution, evidence)
            scope = before_start.scopes[len(execution.record.attempts) - 1]
            try:
                execution = _persist_started(execution_store, execution, lock=lock)
            except StatePersistenceError as error:
                raise StatePersistenceError(
                    "deploy manager-agent authorization consumption failed "
                    "before invocation"
                ) from error
            try:
                result, command_digest = service.execute_operation_step(
                    lock,
                    before_start.metadata,
                    before_start.inventory,
                    _PLAYBOOK,
                    step_sequence=scope.authorization.step_sequence,
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
                        "deploy manager-agent command result identity conflicts"
                    )
            except KeyboardInterrupt:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    DeployManagerAgentExecutionState.INTERRUPTED,
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy manager-agent execution was interrupted; "
                    "manual recovery required"
                ) from None
            except (AnsibleError, StateConflictError, StatePersistenceError) as error:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    (
                        DeployManagerAgentExecutionState.DRIFTED
                        if isinstance(error, StateConflictError)
                        else _failure_state(error)
                        if isinstance(error, AnsibleError)
                        else DeployManagerAgentExecutionState.MALFORMED_RESULT
                    ),
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy manager-agent execution is uncertain; "
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
            except (AnsibleError, StateConflictError, StatePersistenceError) as error:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    DeployManagerAgentExecutionState.DRIFTED,
                    lock=lock,
                )
                raise StateConflictError(
                    "deploy manager-agent state changed after invocation; "
                    "manual recovery required"
                ) from error
            if after.binding != context.binding:
                _persist_uncertain_or_raise(
                    execution_store,
                    execution,
                    DeployManagerAgentExecutionState.DRIFTED,
                    lock=lock,
                )
                raise StateConflictError(
                    "deploy manager-agent state changed after invocation; "
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
                        else DeployManagerAgentExecutionState.MALFORMED_RESULT
                    ),
                    lock=lock,
                )
                raise AnsibleError(
                    "deploy manager-agent result is not strict successful "
                    "evidence; manual recovery required"
                ) from error
            try:
                evidence = _persist_evidence(
                    context, evidence_store, evidence, entry, lock=lock
                )
            except StatePersistenceError as error:
                raise StatePersistenceError(
                    "deploy manager-agent evidence persistence failed; "
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
                    "deploy manager-agent terminal persistence failed; "
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
                "deploy manager-agent next prepared intent failed before invocation"
            ) from error

    if evidence is None:
        raise StatePersistenceError(
            "deploy manager-agent completion evidence is missing"
        )
    _validate_prefix(context, execution, evidence)
    return _build_report(
        context,
        execution,
        evidence,
        execution_state=DeployManagerAgentArtifactState.UPDATED,
        evidence_state=(
            DeployManagerAgentArtifactState.UPDATED
            if evidence_initially_present
            else DeployManagerAgentArtifactState.CREATED
        ),
    )


def deploy_manager_agent_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = (
        paths.operations
        / f"{operation_id}{DEPLOY_MANAGER_AGENT_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy manager-agent execution path is not canonical"
        )
    return path


def deploy_manager_agent_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = (
        paths.operations
        / f"{operation_id}{DEPLOY_MANAGER_AGENT_EVIDENCE_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy manager-agent evidence path is not canonical"
        )
    return path


def deploy_manager_agent_execution_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_MANAGER_AGENT_EXECUTION_FILENAME_SUFFIX
    )


def deploy_manager_agent_evidence_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_MANAGER_AGENT_EVIDENCE_FILENAME_SUFFIX
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
    loaded = _loaded(
        authorization_context.monitoring.monitoring.manager.manager.chain.authorization_context
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
            "deploy manager-agent readiness, journal, or toolchain conflicts"
        )
    readiness = _reconstructed_readiness(planning.base)
    if readiness_binding_digest(readiness) != readiness_record.readiness_digest:
        raise StateConflictError("deploy manager-agent readiness is stale")
    readiness.require_ready(OperationClassification.MUTATING)

    authorization_store = DeployManagerAgentAuthorizationStore(paths, operation_id)
    validate_state_file(authorization_store.path, allow_missing=True)
    if not authorization_store.path.exists():
        raise StateConflictError(
            "deploy manager-agent execution requires immutable authorization"
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
            "deploy manager-agent authorization is stale or consumed"
        )

    execution_scopes = _derive_execution_scopes(
        authorization_context,
        authorization,
        readiness,
        builder=builder,
    )
    stable_ids = tuple(
        scope.authorization.target_stable_id for scope in execution_scopes
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
    trust = planning.base.trust
    post_monitoring = authorization_context.post_monitoring
    post_install = authorization_context.post_install
    install = authorization_context.install.evidence
    base_os = authorization_context.monitoring.monitoring.manager.manager.base_os
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
        "post_monitoring_artifact_digest": post_monitoring.artifact_digest,
        "post_monitoring_record_digest": post_monitoring.record.record_digest,
        "post_monitoring_effective_plan_digest": _digest_object(
            [step.to_object() for step in post_monitoring.record.steps]
        ),
        "install_reconciliation_artifact_digest": post_install.artifact_digest,
        "install_reconciliation_record_digest": post_install.record.record_digest,
        "install_evidence_artifact_digest": install.artifact_digest,
        "install_evidence_digest": _digest_object(
            [entry.evidence_digest for entry in install.record.entries]
        ),
        "base_os_evidence_artifact_digest": base_os.artifact_digest,
        "base_os_evidence_digest": authorization.record.base_os_evidence_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": readiness_record.record_digest,
        "catalog_digest": loaded.catalog_digest,
        "source_version": loaded.source.version,
        "source_digest": loaded.source.digest,
        "playbook_source_digest": _playbook_source_digest(loaded.source, _PLAYBOOK),
        "toolchain_version": str(toolchain.core),
        "executable_identity_digest": executable_identity_digest,
        "toolchain_evidence_digest": toolchain_evidence_digest,
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
        DeployManagerAgentExecutionBinding(**values),  # type: ignore[arg-type]
        execution_scopes,
        metadata,
        deploy.inventory,
        readiness,
    )


def _derive_execution_scopes(
    authorization_context: _AuthorizationContext,
    authorization: StoredDeployManagerAgentAuthorization,
    readiness: ReadinessReport,
    *,
    builder: AnsibleCommandBuilder,
) -> tuple[_ExecutionScope, ...]:
    loaded = _loaded(
        authorization_context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    definition = get_playbook(_PLAYBOOK)
    source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
    if (
        definition.classification is not OperationClassification.MUTATING
        or definition.hosts != HostRole.SCYLLA.value
        or definition.serial != 1
        or definition.limit_policy is not LimitPolicy.EXPLICIT
        or definition.check_mode is not CheckMode.PREVIEW
        or not definition.any_errors_fatal
        or not definition.source_available
    ):
        raise StateConflictError("deploy manager-agent catalog policy conflicts")
    stable_ids = tuple(scope.target_stable_id for scope in authorization.record.scopes)
    if stable_ids != authorization.record.target_stable_ids or stable_ids != tuple(
        sorted(set(stable_ids))
    ):
        raise StateConflictError("deploy manager-agent authorization order conflicts")
    base_by_id = {
        host.logical_id: (entry, host)
        for entry in authorization_context.monitoring.monitoring.manager.manager.base_os.record.entries
        for host in entry.hosts
        if host.logical_id in stable_ids
    }
    install_by_id = {
        entry.stable_id: entry
        for entry in authorization_context.install.evidence.record.entries
    }
    desired_filter = dict(metadata.desired_spec.image_filters).get(HostRole.SCYLLA)
    if desired_filter != ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT):
        raise StateConflictError(
            "deploy manager-agent desired image evidence is unsupported"
        )
    scopes: list[_ExecutionScope] = []
    for attempt_index, authorized in enumerate(authorization.record.scopes, start=1):
        stable_id = authorized.target_stable_id
        base_value = base_by_id.get(stable_id)
        install_entry = install_by_id.get(stable_id)
        if (
            authorized.playbook != _PLAYBOOK
            or authorized.scope_index != attempt_index
            or authorized.mapping_sequence != 16
            or authorized.classification is not OperationClassification.MUTATING
            or authorized.target_role != HostRole.SCYLLA.value
            or authorized.source_digest != source_digest
            or base_value is None
            or install_entry is None
        ):
            raise StateConflictError(
                "deploy manager-agent exact authorized scope conflicts"
            )
        _base_entry, base_host = base_value
        _validate_prerequisite_entry(stable_id, base_host, install_entry)
        base_evidence = BaseOsEvidence(
            base_host.status,
            (
                BaseOsHostEvidence(
                    stable_id,
                    base_host.status,
                    base_host.changed,
                    base_host.reboot_required,
                    "canonical-deploy-evidence",
                ),
            ),
        )
        install_evidence = _scylla_install_evidence(
            install_entry,
            observation_digest=deploy.observation.digest,
            inventory_digest=deploy.inventory.digest,
        )
        payload = build_manager_agent_payload(
            metadata,
            deploy.observation,
            deploy.inventory,
            readiness,
            base_evidence,
            install_evidence,
            logical_id=stable_id,
            image_filter=desired_filter,
            architecture=base_host.image_architecture,
            package_version=MANAGER_PACKAGE_VERSION,
            cluster_spec_digest=metadata.desired_spec.digest(),
        )
        if (
            payload.get("auth_token_configured") is not False
            or payload.get("configuration_performed") is not False
            or payload.get("helper_slice_configured") is not False
            or payload.get("server_reachability") != "not-performed"
            or payload.get("packages") != list(MANAGER_PACKAGES)
        ):
            raise StateConflictError(
                "deploy manager-agent install-only policy conflicts"
            )
        variables = {"deploy_scylla_vms_manager_agent": payload}
        selected, validated, variables_digest, command_digest = (
            builder.validate_operation_step(
                _PLAYBOOK,
                step_sequence=authorized.step_sequence,
                limit=(stable_id,),
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
                "deploy manager-agent anchored command policy conflicts"
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
        or tuple(scope.authorization.scope_index for scope in scopes)
        != tuple(range(1, len(scopes) + 1))
        or tuple(scope.authorization.target_stable_id for scope in scopes)
        != tuple(sorted(scope.authorization.target_stable_id for scope in scopes))
    ):
        raise StateConflictError("deploy manager-agent execution order conflicts")
    return tuple(scopes)


def _validate_prefix(
    context: _ExecutionContext,
    execution: StoredDeployManagerAgentExecution | None,
    evidence: StoredDeployManagerAgentEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "deploy manager-agent evidence exists without execution"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError("deploy manager-agent execution provenance is stale")
    if evidence is not None and evidence.record.binding != context.binding:
        raise StateConflictError("deploy manager-agent evidence provenance is stale")
    for index, attempt in enumerate(execution.record.attempts):
        scope = context.scopes[index]
        authorized = scope.authorization
        if (
            attempt.attempt_index != index + 1
            or attempt.step_sequence != authorized.step_sequence
            or attempt.stable_id != authorized.target_stable_id
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
            raise StateConflictError("deploy manager-agent execution scope conflicts")
    entries = evidence.record.entries if evidence is not None else ()
    succeeded = tuple(
        attempt
        for attempt in execution.record.attempts
        if attempt.state is DeployManagerAgentExecutionState.SUCCEEDED
    )
    if len(entries) not in {
        len(succeeded),
        len(succeeded)
        + (
            1
            if execution.record.state is DeployManagerAgentExecutionState.STARTED
            else 0
        ),
    }:
        raise StateConflictError(
            "deploy manager-agent execution/evidence prefixes conflict"
        )
    for index, entry in enumerate(entries):
        attempt = execution.record.attempts[index]
        scope = context.scopes[index]
        if (
            entry.attempt_index != index + 1
            or entry.step_sequence != scope.authorization.step_sequence
            or entry.stable_id != scope.authorization.target_stable_id
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
            raise StateConflictError("deploy manager-agent semantic evidence conflicts")


def _persist_prepared(
    context: _ExecutionContext,
    store: DeployManagerAgentExecutionStore,
    current: StoredDeployManagerAgentExecution | None,
    scope: _ExecutionScope,
    *,
    lock: ClusterLock,
) -> StoredDeployManagerAgentExecution:
    now = _timestamp()
    attempt = DeployManagerAgentExecutionAttempt(
        attempt_index=scope.attempt_index,
        step_sequence=scope.authorization.step_sequence,
        stable_id=scope.authorization.target_stable_id,
        target_digest=scope.authorization.target_digest,
        authorization_scope_digest=scope.authorization_scope_digest,
        authorization_variables_digest=scope.authorization.variables_digest,
        authorization_command_digest=scope.authorization.command_digest,
        variables_digest=scope.variables_digest,
        command_digest=scope.command_digest,
        source_digest=scope.source_digest,
        package_version_digest=_digest_object(MANAGER_PACKAGE_VERSION),
        package_provenance_digest=context.binding.package_provenance_digest,
        state=DeployManagerAgentExecutionState.PREPARED,
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
        record = DeployManagerAgentExecution(
            generation=1,
            created_at=now,
            updated_at=now,
            binding=context.binding,
            state=DeployManagerAgentExecutionState.PREPARED,
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
    if current.record.state is not DeployManagerAgentExecutionState.SUCCEEDED:
        raise StateConflictError(
            "deploy manager-agent cannot prepare after uncertain execution"
        )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=DeployManagerAgentExecutionState.PREPARED,
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
    store: DeployManagerAgentExecutionStore,
    current: StoredDeployManagerAgentExecution,
    *,
    lock: ClusterLock,
) -> StoredDeployManagerAgentExecution:
    if current.record.state is not DeployManagerAgentExecutionState.PREPARED:
        raise StateConflictError("deploy manager-agent start requires prepared intent")
    now = _timestamp()
    attempt = replace(
        current.record.attempts[-1],
        state=DeployManagerAgentExecutionState.STARTED,
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
        state=DeployManagerAgentExecutionState.STARTED,
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
    store: DeployManagerAgentExecutionStore,
    current: StoredDeployManagerAgentExecution,
    state: DeployManagerAgentExecutionState,
    *,
    lock: ClusterLock,
) -> None:
    try:
        _persist_uncertain(store, current, state, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy manager-agent uncertain outcome persistence failed; "
            "manual recovery required"
        ) from error


def _persist_uncertain(
    store: DeployManagerAgentExecutionStore,
    current: StoredDeployManagerAgentExecution,
    state: DeployManagerAgentExecutionState,
    *,
    lock: ClusterLock,
) -> StoredDeployManagerAgentExecution:
    if (
        current.record.state is not DeployManagerAgentExecutionState.STARTED
        or state
        not in {
            DeployManagerAgentExecutionState.FAILED,
            DeployManagerAgentExecutionState.TIMED_OUT,
            DeployManagerAgentExecutionState.INTERRUPTED,
            DeployManagerAgentExecutionState.UNREACHABLE,
            DeployManagerAgentExecutionState.MALFORMED_RESULT,
            DeployManagerAgentExecutionState.DRIFTED,
        }
    ):
        raise StatePersistenceError(
            "deploy manager-agent uncertain transition conflicts"
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
    store: DeployManagerAgentExecutionStore,
    current: StoredDeployManagerAgentExecution,
    *,
    entry: DeployManagerAgentEvidenceEntry,
    lock: ClusterLock,
) -> StoredDeployManagerAgentExecution:
    if current.record.state is not DeployManagerAgentExecutionState.STARTED:
        raise StateConflictError("deploy manager-agent terminal transition conflicts")
    now = _timestamp()
    attempt = replace(
        current.record.attempts[-1],
        state=DeployManagerAgentExecutionState.SUCCEEDED,
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
        state=DeployManagerAgentExecutionState.SUCCEEDED,
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
    store: DeployManagerAgentEvidenceStore,
    current: StoredDeployManagerAgentEvidence | None,
    entry: DeployManagerAgentEvidenceEntry,
    *,
    lock: ClusterLock,
) -> StoredDeployManagerAgentEvidence:
    if current is not None and len(current.record.entries) >= entry.attempt_index:
        existing = current.record.entries[entry.attempt_index - 1]
        if existing != entry:
            raise StateConflictError(
                "deploy manager-agent evidence conflicts with existing entry"
            )
        return current
    if current is not None and len(current.record.entries) != entry.attempt_index - 1:
        raise StateConflictError("deploy manager-agent evidence sequence conflicts")
    now = _timestamp()
    record = DeployManagerAgentEvidence(
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
) -> DeployManagerAgentEvidenceEntry:
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.MUTATING
        or result.check_mode
        or result.manager_agent is not None
    ):
        raise AnsibleResultError(
            "deploy manager-agent strict result identity conflicts"
        )
    payload = cast(
        dict[str, object],
        dict(scope.variables)["deploy_scylla_vms_manager_agent"],
    )
    try:
        parsed = parse_manager_agent_execution(
            result.stdout,
            expected_payload=payload,
            exit_code=result.exit_code,
        )
    except AnsibleError as error:
        raise AnsibleResultError(
            "deploy manager-agent strict result is malformed"
        ) from error
    if parsed.status not in _SUCCESS_STATUSES:
        message = "unreachable" if result.exit_code == 4 else "execution failed"
        raise AnsibleError(f"deploy manager-agent {message}")
    _validate_success_evidence(parsed)
    package = dict(parsed.packages)
    result_digest = _digest_object(
        {
            "auth_token_configured": parsed.auth_token_configured,
            "changed": parsed.status is ManagerAgentStatus.INSTALLED,
            "configuration_performed": parsed.configuration_performed,
            "helper_slice_configured": parsed.helper_slice_configured,
            "logical_id": parsed.logical_id,
            "package_set_digest": _digest_object(package),
            "package_version_digest": _digest_object(MANAGER_PACKAGE_VERSION),
            "provenance_digest": _digest_object(dict(parsed.provenance)),
            "repository_definition_digest": parsed.repository_digest,
            "schema_version": parsed.schema_version,
            "server_reachability": parsed.server_reachability,
            "service_disabled": parsed.service_enabled is False,
            "service_inactive": parsed.service_inactive,
            "signing_key_artifact_digest": parsed.signing_key_digest,
            "status": parsed.status.value,
        }
    )
    values: dict[str, object] = {
        "attempt_index": scope.attempt_index,
        "step_sequence": scope.authorization.step_sequence,
        "stable_id": scope.authorization.target_stable_id,
        "image_architecture": scope.image_architecture,
        "status": parsed.status,
        "installed": True,
        "changed": parsed.status is ManagerAgentStatus.INSTALLED,
        "package_version_digest": _digest_object(MANAGER_PACKAGE_VERSION),
        "package_count": len(parsed.packages),
        "package_set_digest": _digest_object([name for name, _ in parsed.packages]),
        "repository_definition_digest": parsed.repository_digest,
        "signing_key_artifact_digest": parsed.signing_key_digest,
        "signing_key_identity_digest": scope.signing_key_identity_digest,
        "service_disabled": parsed.service_enabled is False,
        "service_inactive": cast(bool, parsed.service_inactive),
        "configuration_performed": parsed.configuration_performed,
        "auth_token_configured": parsed.auth_token_configured,
        "helper_slice_configured": parsed.helper_slice_configured,
        "server_reachability": parsed.server_reachability,
        "service_started": False,
        "provenance_digest": _digest_object(dict(parsed.provenance)),
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "source_digest": scope.source_digest,
        "result_digest": result_digest,
        "evidence_digest": "",
    }
    values["evidence_digest"] = _evidence_entry_digest_from_values(values)
    return DeployManagerAgentEvidenceEntry(**values)  # type: ignore[arg-type]


def _validate_success_evidence(evidence: ManagerAgentEvidence) -> None:
    if (
        evidence.logical_id == ""
        or evidence.requested_release != MANAGER_RELEASE_LINE
        or evidence.requested_version != MANAGER_PACKAGE_VERSION
        or evidence.installed_version != MANAGER_PACKAGE_VERSION
        or evidence.packages
        != tuple((name, MANAGER_PACKAGE_VERSION) for name in MANAGER_PACKAGES)
        or evidence.repository_digest != MANAGER_REPOSITORY_DEFINITION_DIGEST
        or evidence.signing_key_digest != SCYLLA_SIGNING_KEY_DIGEST
        or evidence.signing_key_fingerprint != SCYLLA_SIGNING_KEY_FINGERPRINT
        or evidence.service_enabled is not False
        or evidence.service_inactive is not True
        or evidence.configuration_performed is not False
        or evidence.auth_token_configured is not False
        or evidence.helper_slice_configured is not False
        or evidence.server_reachability != "not-performed"
        or evidence.blockers
    ):
        raise AnsibleResultError("deploy manager-agent successful evidence conflicts")


def _build_report(
    context: _ExecutionContext,
    execution: StoredDeployManagerAgentExecution,
    evidence: StoredDeployManagerAgentEvidence,
    *,
    execution_state: DeployManagerAgentArtifactState,
    evidence_state: DeployManagerAgentArtifactState,
) -> DeployManagerAgentExecutionReport:
    if (
        not execution.record.all_scopes_completed
        or execution.record.state is not DeployManagerAgentExecutionState.SUCCEEDED
        or len(evidence.record.entries) != len(context.scopes)
    ):
        raise StateConflictError("deploy manager-agent execution is not complete")
    package = context.authorization.record.package_provenance
    entries = evidence.record.entries
    return DeployManagerAgentExecutionReport(
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
        package_version_digest=package.package_version_digest,
        package_count=package.package_count,
        package_set_digest=package.package_set_digest,
        package_provenance_digest=package.provenance_digest,
        repository_definition_digest=package.repository_definition_digest,
        signing_key_artifact_digest=package.signing_key_artifact_digest,
        signing_key_identity_digest=package.signing_key_identity_digest,
        service_safe_count=sum(
            entry.service_disabled and entry.service_inactive for entry in entries
        ),
        prohibited_action_count=sum(
            entry.configuration_performed
            or entry.auth_token_configured
            or entry.helper_slice_configured
            or entry.server_reachability != "not-performed"
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


def _failure_state(error: AnsibleError) -> DeployManagerAgentExecutionState:
    cause = error.__cause__
    if isinstance(cause, ProcessTimeoutError):
        return DeployManagerAgentExecutionState.TIMED_OUT
    if isinstance(cause, ProcessOutputError):
        return DeployManagerAgentExecutionState.MALFORMED_RESULT
    message = str(error).lower()
    if "unreachable" in message:
        return DeployManagerAgentExecutionState.UNREACHABLE
    if isinstance(error, AnsibleResultError) or "malformed" in message:
        return DeployManagerAgentExecutionState.MALFORMED_RESULT
    return DeployManagerAgentExecutionState.FAILED


def _validate_execution_transition(
    current: DeployManagerAgentExecution,
    replacement: DeployManagerAgentExecution,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or current.all_scopes_completed
        or current.state
        not in {
            DeployManagerAgentExecutionState.PREPARED,
            DeployManagerAgentExecutionState.STARTED,
            DeployManagerAgentExecutionState.SUCCEEDED,
        }
    ):
        raise StatePersistenceError(
            "deploy manager-agent execution transition is invalid"
        )
    if current.state is DeployManagerAgentExecutionState.PREPARED:
        valid = (
            len(replacement.attempts) == len(current.attempts)
            and replacement.attempts[:-1] == current.attempts[:-1]
            and replacement.attempts[-1].state
            is DeployManagerAgentExecutionState.STARTED
        )
    elif current.state is DeployManagerAgentExecutionState.STARTED:
        valid = (
            len(replacement.attempts) == len(current.attempts)
            and replacement.attempts[:-1] == current.attempts[:-1]
            and replacement.attempts[-1].state
            not in {
                DeployManagerAgentExecutionState.PREPARED,
                DeployManagerAgentExecutionState.STARTED,
            }
        )
    else:
        valid = (
            len(current.attempts) < current.binding.scope_count
            and replacement.attempts[:-1] == current.attempts
            and replacement.attempts[-1].state
            is DeployManagerAgentExecutionState.PREPARED
        )
    if not valid:
        raise StatePersistenceError(
            "deploy manager-agent execution transition conflicts"
        )


def _validate_evidence_transition(
    current: DeployManagerAgentEvidence,
    replacement: DeployManagerAgentEvidence,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or replacement.entries[:-1] != current.entries
        or len(replacement.entries) != len(current.entries) + 1
    ):
        raise StatePersistenceError(
            "deploy manager-agent evidence transition is invalid"
        )


def _binding_digest(binding: DeployManagerAgentExecutionBinding) -> str:
    value = binding.to_object()
    value["binding_digest"] = ""
    return _digest_object(value)


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployManagerAgentExecutionBinding.__dataclass_fields__.items():
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


def _evidence_entry_digest(entry: DeployManagerAgentEvidenceEntry) -> str:
    value = entry.to_object()
    value["evidence_digest"] = ""
    return _digest_object(value)


def _evidence_entry_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployManagerAgentEvidenceEntry.__dataclass_fields__.items():
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
            "deploy manager-agent execution paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy manager-agent execution requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy manager-agent execution artifacts"
        ) from error
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_MANAGER_AGENT_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_MANAGER_AGENT_EVIDENCE_FILENAME_SUFFIX,
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
            if prefix != canonical and (
                parsed is None or parsed == operation_id or canonical in prefix
            ):
                validate_state_file(entry)
                raise StateConflictError(
                    "deploy manager-agent execution artifacts are ambiguous"
                )
    forbidden_fragments = (
        ".ansible-deploy-post-manager-agent-reconciliation.json",
        ".ansible-deploy-monitoring-agent",
        ".ansible-deploy-monitoring-targets",
        ".ansible-deploy-manager-tasks",
    )
    for entry in entries:
        if entry.name.startswith(canonical) and any(
            fragment in entry.name for fragment in forbidden_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy manager-agent execution refuses later-stage history"
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
            "deploy manager-agent toolchain version is invalid"
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
    "ANSIBLE_DEPLOY_MANAGER_AGENT_EVIDENCE_ENTRY_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_AGENT_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_AGENT_EXECUTION_BINDING_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_AGENT_EXECUTION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_AGENT_EXECUTION_SCHEMA_VERSION",
    "DEPLOY_MANAGER_AGENT_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_MANAGER_AGENT_EXECUTION_FILENAME_SUFFIX",
    "DeployManagerAgentArtifactState",
    "DeployManagerAgentEvidence",
    "DeployManagerAgentEvidenceEntry",
    "DeployManagerAgentEvidenceStore",
    "DeployManagerAgentExecution",
    "DeployManagerAgentExecutionAttempt",
    "DeployManagerAgentExecutionBinding",
    "DeployManagerAgentExecutionReport",
    "DeployManagerAgentExecutionState",
    "DeployManagerAgentExecutionStore",
    "StoredDeployManagerAgentEvidence",
    "StoredDeployManagerAgentExecution",
    "deploy_manager_agent_evidence_id_from_filename",
    "deploy_manager_agent_evidence_path",
    "deploy_manager_agent_execution_id_from_filename",
    "deploy_manager_agent_execution_path",
    "execute_deploy_manager_agent",
]
