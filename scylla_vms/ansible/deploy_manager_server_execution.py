"""Durable exact execution and evidence for mapped deploy ``manager-server``.

This internal owner derives one install-only Manager target from canonical
state, consumes the immutable authorization at durable ``started`` intent, and
persists only bounded address-free semantic evidence.  Any outcome after start
that is not strict success requires manual recovery and is never retried.
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
from scylla_vms.ansible.deploy_manager_server_authorization import (
    ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_SCHEMA_VERSION,
    DeployManagerServerAuthorizationScope,
    DeployManagerServerAuthorizationStore,
    StoredDeployManagerServerAuthorization,
    _AuthorizationContext,
    _build_authorization,
    _derive_authorization_scope,
    _derive_package_provenance,
    _load_authorization_context,
    _signing_key_identity_digest,
)
from scylla_vms.ansible.deploy_plan import (
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import _loaded
from scylla_vms.ansible.manager_server import (
    MANAGER_PACKAGE_VERSION,
    MANAGER_PACKAGES,
    MANAGER_RELEASE_LINE,
    MANAGER_REPOSITORY_DEFINITION_DIGEST,
    MANAGER_SERVER_SCHEMA_VERSION,
    ManagerServerEvidence,
    ManagerServerStatus,
    build_manager_server_payload,
    parse_manager_server_execution,
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

ANSIBLE_DEPLOY_MANAGER_SERVER_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-server-execution-binding/v1"
)
ANSIBLE_DEPLOY_MANAGER_SERVER_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-server-execution/v1"
)
ANSIBLE_DEPLOY_MANAGER_SERVER_EVIDENCE_ENTRY_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-server-evidence-entry/v1"
)
ANSIBLE_DEPLOY_MANAGER_SERVER_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-server-evidence/v1"
)
ANSIBLE_DEPLOY_MANAGER_SERVER_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-server-execution-report/v1"
)

DEPLOY_MANAGER_SERVER_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-server-execution.json"
)
DEPLOY_MANAGER_SERVER_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-server-evidence.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "manager-server"
_STAGE = "post-bootstrap-manager-server"
_SCOPE_KIND = "bootstrap-healthy-manager-install"
_MAPPING_SEQUENCE = 14
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SUCCESS_STATUSES = frozenset(
    {ManagerServerStatus.INSTALLED, ManagerServerStatus.NO_CHANGE}
)


class DeployManagerServerExecutionState(StrEnum):
    """Bounded durable states for the one authorized Manager attempt."""

    PREPARED = "prepared"
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"
    DRIFTED = "drifted"


class DeployManagerServerArtifactState(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployManagerServerExecutionBinding:
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
    post_bootstrap_artifact_digest: str
    post_bootstrap_record_digest: str
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
    package_provenance_digest: str
    variables_digest: str
    command_digest: str
    execution_scope_digest: str
    binding_digest: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_SERVER_EXECUTION_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_SERVER_EXECUTION_BINDING_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_SCHEMA_VERSION
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
                "deploy manager-server execution binding is invalid"
            )
        validate_cluster_name(self.cluster_name)
        for count in (
            self.journal_generation,
            self.metadata_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
        ):
            _positive_integer(count, "deploy manager-server binding generation")
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy manager-server binding digest")
        _validate_toolchain_version(self.toolchain_version)
        if self.binding_digest != _binding_digest(self):
            raise StatePersistenceError(
                "deploy manager-server execution binding digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerServerExecutionBinding:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy manager-server execution binding",
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
class DeployManagerServerExecutionAttempt:
    """One exact prepared, started, or terminal Manager installation attempt."""

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
    package_version_digest: str
    package_provenance_digest: str
    state: DeployManagerServerExecutionState
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
    result_schema_version: str = MANAGER_SERVER_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.attempt_index != 1
            or self.mapping_sequence != _MAPPING_SEQUENCE
            or not self.stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.result_schema_version != MANAGER_SERVER_SCHEMA_VERSION
            or self.package_version_digest != _digest_object(MANAGER_PACKAGE_VERSION)
            or not isinstance(self.state, DeployManagerServerExecutionState)
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy manager-server execution attempt is invalid"
            )
        for digest in (
            self.target_digest,
            self.authorization_scope_digest,
            self.authorization_variables_digest,
            self.authorization_command_digest,
            self.variables_digest,
            self.command_digest,
            self.source_digest,
            self.package_version_digest,
            self.package_provenance_digest,
            self.result_digest,
            self.evidence_digest,
        ):
            if digest is not None:
                validate_digest(digest, "deploy manager-server attempt digest")
        prepared = parse_timestamp(self.prepared_at)
        started = _optional_timestamp(self.started_at)
        completed = _optional_timestamp(self.completed_at)
        if (
            (started is not None and started < prepared)
            or (completed is not None and started is None)
            or (completed is not None and started is not None and completed < started)
        ):
            raise StatePersistenceError(
                "deploy manager-server attempt timestamps conflict"
            )
        if self.state is DeployManagerServerExecutionState.PREPARED:
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
        elif self.state is DeployManagerServerExecutionState.STARTED:
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
        elif self.state is DeployManagerServerExecutionState.SUCCEEDED:
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
            raise StatePersistenceError("deploy manager-server attempt state conflicts")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerServerExecutionAttempt:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy manager-server execution attempt",
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
                package_version_digest=require_string(value, "package_version_digest"),
                package_provenance_digest=require_string(
                    value, "package_provenance_digest"
                ),
                state=DeployManagerServerExecutionState(require_string(value, "state")),
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
                "deploy manager-server attempt state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerServerExecution:
    """Generation-guarded single-attempt execution state."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployManagerServerExecutionBinding
    state: DeployManagerServerExecutionState
    authorization_consumed: bool
    invocation_count: int
    completed: bool
    attempt: DeployManagerServerExecutionAttempt
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_SERVER_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        invoked = self.state is not DeployManagerServerExecutionState.PREPARED
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_SERVER_EXECUTION_SCHEMA_VERSION
            or self.generation < 1
            or self.state is not self.attempt.state
            or self.authorization_consumed != invoked
            or self.invocation_count != int(invoked)
            or self.completed
            != (self.state is DeployManagerServerExecutionState.SUCCEEDED)
            or parse_timestamp(self.updated_at) < parse_timestamp(self.created_at)
        ):
            raise StatePersistenceError(
                "deploy manager-server execution summary conflicts"
            )

    @property
    def manual_recovery_required(self) -> bool:
        return self.state not in {
            DeployManagerServerExecutionState.PREPARED,
            DeployManagerServerExecutionState.SUCCEEDED,
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
    def from_object(cls, value: Mapping[str, object]) -> DeployManagerServerExecution:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy manager-server execution",
        )
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                updated_at=require_string(value, "updated_at"),
                binding=DeployManagerServerExecutionBinding.from_object(
                    _mapping(value["binding"], "binding")
                ),
                state=DeployManagerServerExecutionState(require_string(value, "state")),
                authorization_consumed=_boolean(
                    value["authorization_consumed"], "authorization consumption"
                ),
                invocation_count=_integer(
                    value["invocation_count"], "invocation count"
                ),
                completed=_boolean(value["completed"], "completion"),
                attempt=DeployManagerServerExecutionAttempt.from_object(
                    _mapping(value["attempt"], "attempt")
                ),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy manager-server execution state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerServerEvidenceEntry:
    """Strict redacted semantic evidence for the successful install."""

    attempt_index: int
    mapping_sequence: int
    stable_id: str
    image_architecture: str
    status: ManagerServerStatus
    installed: bool
    changed: bool
    release_line: str
    package_version_digest: str
    package_count: int
    package_set_digest: str
    repository_definition_digest: str
    signing_key_artifact_digest: str
    signing_key_identity_digest: str
    service_masked: bool
    service_inactive: bool
    service_started: bool
    backend_configured: bool
    configuration_performed: bool
    registration_performed: bool
    setup_performed: bool
    tasks_performed: bool
    provenance_digest: str
    variables_digest: str
    command_digest: str
    source_digest: str
    result_digest: str
    evidence_digest: str
    manual_recovery_required: bool = False
    automatic_retry_allowed: bool = False
    result_schema_version: str = MANAGER_SERVER_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_SERVER_EVIDENCE_ENTRY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_SERVER_EVIDENCE_ENTRY_SCHEMA_VERSION
            or self.result_schema_version != MANAGER_SERVER_SCHEMA_VERSION
            or self.attempt_index != 1
            or self.mapping_sequence != _MAPPING_SEQUENCE
            or not self.stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.image_architecture not in {"amd64", "aarch64"}
            or self.status not in _SUCCESS_STATUSES
            or not self.installed
            or self.changed != (self.status is ManagerServerStatus.INSTALLED)
            or self.release_line != MANAGER_RELEASE_LINE
            or self.package_version_digest != _digest_object(MANAGER_PACKAGE_VERSION)
            or self.package_count != len(MANAGER_PACKAGES)
            or self.package_set_digest != _digest_object(list(MANAGER_PACKAGES))
            or self.repository_definition_digest != MANAGER_REPOSITORY_DEFINITION_DIGEST
            or self.signing_key_identity_digest != _signing_key_identity_digest()
            or not self.service_masked
            or not self.service_inactive
            or self.service_started
            or self.backend_configured
            or self.configuration_performed
            or self.registration_performed
            or self.setup_performed
            or self.tasks_performed
            or self.manual_recovery_required
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy manager-server semantic evidence conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy manager-server evidence digest")
        if self.evidence_digest != _evidence_entry_digest(self):
            raise StatePersistenceError(
                "deploy manager-server evidence digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerServerEvidenceEntry:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy manager-server evidence entry",
        )
        integers = {"attempt_index", "mapping_sequence", "package_count"}
        booleans = {
            "installed",
            "changed",
            "service_masked",
            "service_inactive",
            "service_started",
            "backend_configured",
            "configuration_performed",
            "registration_performed",
            "setup_performed",
            "tasks_performed",
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
                    parsed[name] = ManagerServerStatus(require_string(value, name))
                else:
                    parsed[name] = require_string(value, name)
            return cls(**parsed)  # type: ignore[arg-type]
        except ValueError as error:
            raise StatePersistenceError(
                "deploy manager-server evidence status is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerServerEvidence:
    """Immutable one-entry semantic-evidence prefix."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployManagerServerExecutionBinding
    entries: tuple[DeployManagerServerEvidenceEntry, ...]
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_SERVER_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_MANAGER_SERVER_EVIDENCE_SCHEMA_VERSION
            or self.generation != 1
            or len(self.entries) != 1
            or parse_timestamp(self.updated_at) < parse_timestamp(self.created_at)
        ):
            raise StatePersistenceError(
                "deploy manager-server evidence prefix conflicts"
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
    def from_object(cls, value: Mapping[str, object]) -> DeployManagerServerEvidence:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy manager-server evidence",
        )
        return cls(
            generation=_integer(value["generation"], "generation"),
            created_at=require_string(value, "created_at"),
            updated_at=require_string(value, "updated_at"),
            binding=DeployManagerServerExecutionBinding.from_object(
                _mapping(value["binding"], "binding")
            ),
            entries=tuple(
                DeployManagerServerEvidenceEntry.from_object(
                    _mapping(item, "evidence entry")
                )
                for item in _array(value["entries"], "evidence entries")
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredDeployManagerServerExecution:
    record: DeployManagerServerExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployManagerServerEvidence:
    record: DeployManagerServerEvidence
    artifact_digest: str


class DeployManagerServerExecutionStore:
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
        self._path = deploy_manager_server_execution_path(paths, operation_id)
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
    ) -> StoredDeployManagerServerExecution:
        value, digest = self._file.read()
        record = DeployManagerServerExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy manager-server execution identity conflicts"
            )
        return StoredDeployManagerServerExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerServerExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerServerExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployManagerServerExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy manager-server execution operation conflicts"
            )
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial deploy manager-server execution generation conflicts"
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
                    "deploy manager-server execution changed concurrently"
                )
            _validate_execution_transition(current.record, record)
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployManagerServerExecution(record, digest)


class DeployManagerServerEvidenceStore:
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
        self._path = deploy_manager_server_evidence_path(paths, operation_id)
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
    ) -> StoredDeployManagerServerEvidence:
        value, digest = self._file.read()
        record = DeployManagerServerEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy manager-server evidence identity conflicts"
            )
        return StoredDeployManagerServerEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerServerEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerServerEvidence,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerServerEvidence,
        DeployManagerServerArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy manager-server evidence operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if current.record != record:
                raise StateConflictError("deploy manager-server evidence is immutable")
            return current, DeployManagerServerArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerServerEvidence(record, digest),
            DeployManagerServerArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerServerExecutionReport:
    """Strict redacted successful execution report."""

    operation_id: uuid.UUID
    execution_state: DeployManagerServerExecutionState
    execution_artifact_state: DeployManagerServerArtifactState
    evidence_artifact_state: DeployManagerServerArtifactState
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
    installed_count: int
    changed_count: int
    release_line: str
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
        ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_SCHEMA_VERSION
    )
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_SERVER_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = ANSIBLE_DEPLOY_MANAGER_SERVER_EVIDENCE_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_SERVER_EXECUTION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_SERVER_EXECUTION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_MANAGER_SERVER_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_MANAGER_SERVER_EVIDENCE_SCHEMA_VERSION
            or self.execution_state is not DeployManagerServerExecutionState.SUCCEEDED
            or not self.authorization_consumed
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.invocation_count != 1
            or self.installed_count != 1
            or self.release_line != MANAGER_RELEASE_LINE
            or self.package_count != len(MANAGER_PACKAGES)
            or self.service_safe_count != 1
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
                "deploy manager-server execution report is invalid"
            )
        if (
            not self.target_stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
        ):
            raise StatePersistenceError(
                "deploy manager-server report target is invalid"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy manager-server report digest")

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
                "release_line": self.release_line,
                "repository_definition_digest": self.repository_definition_digest,
                "signing_key_artifact_digest": self.signing_key_artifact_digest,
                "signing_key_identity_digest": self.signing_key_identity_digest,
            },
            "schema_version": self.schema_version,
            "scope": {
                "kind": self.scope_kind,
                "target_count": 1,
                "target_set_digest": self.target_set_digest,
                "target_stable_id": self.target_stable_id,
            },
            "stage": self.stage,
        }


@dataclass(frozen=True, slots=True)
class _ExecutionScope:
    authorization: DeployManagerServerAuthorizationScope
    authorization_scope_digest: str
    variables: tuple[tuple[str, object], ...]
    variables_digest: str
    command_digest: str
    source_digest: str
    step_sequence: int
    image_architecture: str
    signing_key_identity_digest: str


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    authorization: StoredDeployManagerServerAuthorization
    binding: DeployManagerServerExecutionBinding
    scope: _ExecutionScope
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport


def execute_deploy_manager_server(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployManagerServerExecutionReport:
    """Execute only the exact immutable authorized Manager-server scope."""

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
    execution_store = DeployManagerServerExecutionStore(paths, operation_id)
    evidence_store = DeployManagerServerEvidenceStore(paths, operation_id)
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
                "completed deploy manager-server evidence is unavailable"
            )
        return _build_report(
            context,
            execution,
            evidence,
            execution_state=DeployManagerServerArtifactState.REUSED,
            evidence_state=DeployManagerServerArtifactState.REUSED,
        )
    if (
        execution is not None
        and execution.record.state is not DeployManagerServerExecutionState.PREPARED
    ):
        raise StateConflictError(
            "deploy manager-server execution requires manual recovery and cannot retry"
        )

    service = AnsibleService(builder, runner)
    discovered = service.version(lock)
    if discovered != toolchain:
        raise StateConflictError("deploy manager-server toolchain drifted")
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
                "deploy manager-server prepared intent persistence failed "
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
        raise StateConflictError("deploy manager-server state drifted before start")
    _validate_prefix(before_start, execution, evidence)
    try:
        execution = _persist_started(execution_store, execution, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy manager-server authorization consumption failed before invocation"
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
                "deploy manager-server command result identity conflicts"
            )
    except KeyboardInterrupt:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployManagerServerExecutionState.INTERRUPTED,
            lock=lock,
        )
        raise AnsibleError(
            "deploy manager-server execution was interrupted; manual recovery required"
        ) from None
    except (AnsibleError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            (
                _failure_state(error)
                if isinstance(error, AnsibleError)
                else DeployManagerServerExecutionState.MALFORMED_RESULT
            ),
            lock=lock,
        )
        raise AnsibleError(
            "deploy manager-server execution is uncertain; manual recovery required"
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
                "deploy manager-server state changed after invocation"
            )
    except (StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployManagerServerExecutionState.DRIFTED,
            lock=lock,
        )
        raise StateConflictError(
            "deploy manager-server state changed after invocation; "
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
                else DeployManagerServerExecutionState.MALFORMED_RESULT
            ),
            lock=lock,
        )
        raise AnsibleError(
            "deploy manager-server result is not strict successful evidence; "
            "manual recovery required"
        ) from error

    try:
        evidence, evidence_state = _persist_evidence(
            context, evidence_store, entry, lock=lock
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy manager-server evidence persistence failed; "
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
            "deploy manager-server terminal persistence failed; "
            "manual recovery required"
        ) from error
    _validate_prefix(context, execution, evidence)
    return _build_report(
        context,
        execution,
        evidence,
        execution_state=DeployManagerServerArtifactState.UPDATED,
        evidence_state=evidence_state,
    )


def deploy_manager_server_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MANAGER_SERVER_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy manager-server execution path is not canonical"
        )
    return path


def deploy_manager_server_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MANAGER_SERVER_EVIDENCE_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy manager-server evidence path is not canonical"
        )
    return path


def deploy_manager_server_execution_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_MANAGER_SERVER_EXECUTION_FILENAME_SUFFIX
    )


def deploy_manager_server_evidence_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_MANAGER_SERVER_EVIDENCE_FILENAME_SUFFIX
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
    loaded = _loaded(authorization_context.chain.authorization_context)
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
            "deploy manager-server readiness, journal, or toolchain conflicts"
        )
    readiness = _reconstructed_readiness(planning.base)
    if readiness_binding_digest(readiness) != readiness_record.readiness_digest:
        raise StateConflictError("deploy manager-server readiness is stale")
    readiness.require_ready(OperationClassification.MUTATING)

    authorization_store = DeployManagerServerAuthorizationStore(paths, operation_id)
    validate_state_file(authorization_store.path, allow_missing=True)
    if not authorization_store.path.exists():
        raise StateConflictError(
            "deploy manager-server execution requires immutable authorization"
        )
    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    package = _derive_package_provenance()
    authorized_scope = _derive_authorization_scope(authorization_context, package)
    expected_authorization = _build_authorization(
        authorization_context,
        scope=authorized_scope,
        package_provenance=package,
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
            "deploy manager-server authorization is stale or consumed"
        )

    scope = _derive_execution_scope(
        authorization_context,
        authorization,
        readiness=readiness,
        builder=builder,
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
        "authorization_artifact_digest": authorization.artifact_digest,
        "authorization_digest": authorization.record.authorization_digest,
        "authorization_scope_digest": authorization.record.authorization_scope_digest,
        "authorization_proof_digest": authorization.record.proof.proof_digest,
        "post_bootstrap_artifact_digest": (
            authorization_context.bridge.artifact_digest
        ),
        "post_bootstrap_record_digest": (
            authorization_context.bridge.record.record_digest
        ),
        "base_os_artifact_digest": authorization_context.base_os.artifact_digest,
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
        "package_provenance_digest": package.provenance_digest,
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "execution_scope_digest": _digest_object(
            {
                "authorization_scope_digest": scope.authorization_scope_digest,
                "command_digest": scope.command_digest,
                "mapping_sequence": _MAPPING_SEQUENCE,
                "source_digest": scope.source_digest,
                "target_set_digest": authorized_scope.target_digest,
                "variables_digest": scope.variables_digest,
            }
        ),
        "binding_digest": "",
    }
    binding_values["binding_digest"] = _binding_digest_from_values(binding_values)
    return _ExecutionContext(
        authorization,
        DeployManagerServerExecutionBinding(**binding_values),  # type: ignore[arg-type]
        scope,
        metadata,
        deploy.inventory,
        readiness,
    )


def _derive_execution_scope(
    context: _AuthorizationContext,
    authorization: StoredDeployManagerServerAuthorization,
    *,
    readiness: ReadinessReport,
    builder: AnsibleCommandBuilder,
) -> _ExecutionScope:
    loaded = _loaded(context.chain.authorization_context)
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    authorized = authorization.record.scope
    definition = get_playbook(_PLAYBOOK)
    source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
    prior_steps = tuple(
        step
        for step in context.post_configure.record.steps
        if step.mapping_sequence == _MAPPING_SEQUENCE
    )
    base_matches = tuple(
        (entry, host)
        for entry in context.base_os.record.entries
        for host in entry.hosts
        if host.logical_id == authorized.target_stable_id
    )
    image_filter = dict(metadata.desired_spec.image_filters).get(HostRole.MANAGER)
    if (
        len(prior_steps) != 1
        or len(base_matches) != 1
        or image_filter != ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT)
        or authorized.playbook != _PLAYBOOK
        or authorized.mapping_sequence != _MAPPING_SEQUENCE
        or authorized.classification is not OperationClassification.MUTATING
        or authorized.target_role != HostRole.MANAGER.value
        or authorized.source_digest != source_digest
        or definition.classification is not OperationClassification.MUTATING
        or definition.hosts != HostRole.MANAGER.value
        or definition.serial != 1
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.check_mode is not CheckMode.PREVIEW
        or not definition.any_errors_fatal
        or not definition.source_available
    ):
        raise StateConflictError(
            "deploy manager-server exact authorized scope conflicts"
        )
    prior_step = prior_steps[0]
    base_entry, base_host = base_matches[0]
    if (
        len(prior_step.target_ids) != 1
        or prior_step.target_ids[0] != authorized.target_stable_id
        or base_host.os_family != "Ubuntu"
        or base_host.os_version != "24.04"
        or base_host.image_architecture not in {"amd64", "aarch64"}
        or base_host.status not in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
        or not base_host.applied
        or base_host.reboot_required
        or base_entry.evidence_digest != authorized.base_os_evidence_digest
    ):
        raise StateConflictError(
            "deploy manager-server current target or base-os evidence conflicts"
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
    payload = build_manager_server_payload(
        metadata,
        deploy.observation,
        deploy.inventory,
        readiness,
        base_os,
        logical_id=authorized.target_stable_id,
        image_filter=image_filter,
        architecture=base_host.image_architecture,
        package_version=MANAGER_PACKAGE_VERSION,
        cluster_spec_digest=metadata.desired_spec.digest(),
    )
    if (
        payload["backend_configured"] is not False
        or payload["configuration_performed"] is not False
        or payload["registration_performed"] is not False
        or payload["service_started"] is not False
        or payload["setup_performed"] is not False
        or payload["tasks_performed"] is not False
        or payload["packages"] != list(MANAGER_PACKAGES)
    ):
        raise StateConflictError(
            "deploy manager-server install-only variables conflict"
        )
    variables = {"deploy_scylla_vms_manager_server": payload}
    selected, validated, variables_digest, command_digest = (
        builder.validate_operation_step(
            _PLAYBOOK,
            step_sequence=prior_step.sequence,
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
            "deploy manager-server anchored command policy conflicts"
        )
    return _ExecutionScope(
        authorized,
        _digest_object(authorized.to_object()),
        tuple(sorted(validated.items())),
        variables_digest,
        command_digest,
        source_digest,
        prior_step.sequence,
        base_host.image_architecture,
        authorization.record.package_provenance.signing_key_identity_digest,
    )


def _validate_prefix(
    context: _ExecutionContext,
    execution: StoredDeployManagerServerExecution | None,
    evidence: StoredDeployManagerServerEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "deploy manager-server evidence exists without execution"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError("deploy manager-server execution provenance is stale")
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
        or attempt.package_provenance_digest
        != context.binding.package_provenance_digest
    ):
        raise StateConflictError("deploy manager-server execution scope conflicts")
    if evidence is None:
        if execution.record.state is DeployManagerServerExecutionState.SUCCEEDED:
            raise StateConflictError(
                "deploy manager-server success evidence is missing"
            )
        return
    if evidence.record.binding != context.binding or execution.record.state not in {
        DeployManagerServerExecutionState.STARTED,
        DeployManagerServerExecutionState.SUCCEEDED,
    }:
        raise StateConflictError(
            "deploy manager-server execution/evidence prefixes conflict"
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
        raise StateConflictError("deploy manager-server semantic evidence conflicts")


def _persist_prepared(
    context: _ExecutionContext,
    store: DeployManagerServerExecutionStore,
    *,
    lock: ClusterLock,
) -> StoredDeployManagerServerExecution:
    now = _timestamp()
    scope = context.scope
    attempt = DeployManagerServerExecutionAttempt(
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
        package_version_digest=_digest_object(MANAGER_PACKAGE_VERSION),
        package_provenance_digest=context.binding.package_provenance_digest,
        state=DeployManagerServerExecutionState.PREPARED,
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
    record = DeployManagerServerExecution(
        generation=1,
        created_at=now,
        updated_at=now,
        binding=context.binding,
        state=DeployManagerServerExecutionState.PREPARED,
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
    store: DeployManagerServerExecutionStore,
    current: StoredDeployManagerServerExecution,
    *,
    lock: ClusterLock,
) -> StoredDeployManagerServerExecution:
    if current.record.state is not DeployManagerServerExecutionState.PREPARED:
        raise StateConflictError("deploy manager-server start requires prepared intent")
    now = _timestamp()
    attempt = replace(
        current.record.attempt,
        state=DeployManagerServerExecutionState.STARTED,
        started_at=now,
        authorization_consumed_at_start=True,
        invocation_may_have_occurred=True,
        manual_recovery_required=True,
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=DeployManagerServerExecutionState.STARTED,
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
    store: DeployManagerServerExecutionStore,
    current: StoredDeployManagerServerExecution,
    state: DeployManagerServerExecutionState,
    *,
    lock: ClusterLock,
) -> None:
    try:
        _persist_uncertain(store, current, state, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy manager-server uncertain outcome persistence failed; "
            "manual recovery required"
        ) from error


def _persist_uncertain(
    store: DeployManagerServerExecutionStore,
    current: StoredDeployManagerServerExecution,
    state: DeployManagerServerExecutionState,
    *,
    lock: ClusterLock,
) -> StoredDeployManagerServerExecution:
    if (
        current.record.state is not DeployManagerServerExecutionState.STARTED
        or state
        not in {
            DeployManagerServerExecutionState.FAILED,
            DeployManagerServerExecutionState.TIMED_OUT,
            DeployManagerServerExecutionState.INTERRUPTED,
            DeployManagerServerExecutionState.UNREACHABLE,
            DeployManagerServerExecutionState.MALFORMED_RESULT,
            DeployManagerServerExecutionState.DRIFTED,
        }
    ):
        raise StatePersistenceError(
            "deploy manager-server uncertain transition conflicts"
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
    store: DeployManagerServerEvidenceStore,
    entry: DeployManagerServerEvidenceEntry,
    *,
    lock: ClusterLock,
) -> tuple[
    StoredDeployManagerServerEvidence,
    DeployManagerServerArtifactState,
]:
    now = _timestamp()
    record = DeployManagerServerEvidence(
        generation=1,
        created_at=now,
        updated_at=now,
        binding=context.binding,
        entries=(entry,),
    )
    return store.write_locked(record, lock=lock)


def _persist_terminal_success(
    store: DeployManagerServerExecutionStore,
    current: StoredDeployManagerServerExecution,
    *,
    entry: DeployManagerServerEvidenceEntry,
    lock: ClusterLock,
) -> StoredDeployManagerServerExecution:
    if current.record.state is not DeployManagerServerExecutionState.STARTED:
        raise StateConflictError("deploy manager-server terminal transition conflicts")
    now = _timestamp()
    attempt = replace(
        current.record.attempt,
        state=DeployManagerServerExecutionState.SUCCEEDED,
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
        state=DeployManagerServerExecutionState.SUCCEEDED,
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
) -> DeployManagerServerEvidenceEntry:
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.MUTATING
        or result.check_mode
        or result.manager_server is not None
    ):
        raise AnsibleResultError(
            "deploy manager-server strict result identity conflicts"
        )
    payload = cast(
        dict[str, object],
        dict(scope.variables)["deploy_scylla_vms_manager_server"],
    )
    try:
        parsed = parse_manager_server_execution(
            result.stdout,
            expected_payload=payload,
            exit_code=result.exit_code,
        )
    except AnsibleError as error:
        raise AnsibleResultError(
            "deploy manager-server strict result is malformed"
        ) from error
    if parsed.status not in _SUCCESS_STATUSES:
        message = "unreachable" if result.exit_code == 4 else "execution failed"
        raise AnsibleError(f"deploy manager-server {message}")
    _validate_success_evidence(parsed, scope.authorization.target_stable_id)
    result_digest = _digest_object(
        {
            "backend_configured": parsed.backend_configured,
            "changed": parsed.status is ManagerServerStatus.INSTALLED,
            "configuration_performed": parsed.configuration_performed,
            "logical_id": parsed.logical_id,
            "package_set_digest": _digest_object(
                [name for name, _version in parsed.packages]
            ),
            "provenance_digest": _digest_object(dict(parsed.provenance)),
            "registration_performed": parsed.registration_performed,
            "repository_definition_digest": parsed.repository_digest,
            "schema_version": parsed.schema_version,
            "service_inactive": parsed.service_inactive,
            "service_masked": parsed.service_masked,
            "service_started": parsed.service_started,
            "setup_performed": parsed.setup_performed,
            "signing_key_artifact_digest": parsed.signing_key_digest,
            "status": parsed.status.value,
            "tasks_performed": parsed.tasks_performed,
        }
    )
    values: dict[str, object] = {
        "attempt_index": 1,
        "mapping_sequence": _MAPPING_SEQUENCE,
        "stable_id": scope.authorization.target_stable_id,
        "image_architecture": scope.image_architecture,
        "status": parsed.status,
        "installed": True,
        "changed": parsed.status is ManagerServerStatus.INSTALLED,
        "release_line": MANAGER_RELEASE_LINE,
        "package_version_digest": _digest_object(MANAGER_PACKAGE_VERSION),
        "package_count": len(parsed.packages),
        "package_set_digest": _digest_object(
            [name for name, _version in parsed.packages]
        ),
        "repository_definition_digest": parsed.repository_digest,
        "signing_key_artifact_digest": parsed.signing_key_digest,
        "signing_key_identity_digest": scope.signing_key_identity_digest,
        "service_masked": cast(bool, parsed.service_masked),
        "service_inactive": cast(bool, parsed.service_inactive),
        "service_started": parsed.service_started,
        "backend_configured": parsed.backend_configured,
        "configuration_performed": parsed.configuration_performed,
        "registration_performed": parsed.registration_performed,
        "setup_performed": parsed.setup_performed,
        "tasks_performed": parsed.tasks_performed,
        "provenance_digest": _digest_object(dict(parsed.provenance)),
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "source_digest": scope.source_digest,
        "result_digest": result_digest,
        "evidence_digest": "",
    }
    values["evidence_digest"] = _evidence_entry_digest_from_values(values)
    return DeployManagerServerEvidenceEntry(**values)  # type: ignore[arg-type]


def _validate_success_evidence(
    evidence: ManagerServerEvidence, expected_stable_id: str
) -> None:
    if (
        evidence.logical_id != expected_stable_id
        or evidence.requested_release != MANAGER_RELEASE_LINE
        or evidence.requested_version != MANAGER_PACKAGE_VERSION
        or evidence.installed_version != MANAGER_PACKAGE_VERSION
        or evidence.packages
        != tuple((name, MANAGER_PACKAGE_VERSION) for name in MANAGER_PACKAGES)
        or evidence.repository_digest != MANAGER_REPOSITORY_DEFINITION_DIGEST
        or evidence.service_masked is not True
        or evidence.service_inactive is not True
        or evidence.service_started
        or evidence.backend_configured
        or evidence.configuration_performed
        or evidence.registration_performed
        or evidence.setup_performed
        or evidence.tasks_performed
        or evidence.blockers
    ):
        raise AnsibleResultError("deploy manager-server successful evidence conflicts")


def _build_report(
    context: _ExecutionContext,
    execution: StoredDeployManagerServerExecution,
    evidence: StoredDeployManagerServerEvidence,
    *,
    execution_state: DeployManagerServerArtifactState,
    evidence_state: DeployManagerServerArtifactState,
) -> DeployManagerServerExecutionReport:
    if (
        not execution.record.completed
        or execution.record.state is not DeployManagerServerExecutionState.SUCCEEDED
        or len(evidence.record.entries) != 1
    ):
        raise StateConflictError("deploy manager-server execution is not complete")
    package = context.authorization.record.package_provenance
    entry = evidence.record.entries[0]
    return DeployManagerServerExecutionReport(
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
        installed_count=int(entry.installed),
        changed_count=int(entry.changed),
        release_line=package.release_line,
        package_version_digest=package.package_version_digest,
        package_count=package.package_count,
        package_set_digest=package.package_set_digest,
        package_provenance_digest=package.provenance_digest,
        repository_definition_digest=package.repository_definition_digest,
        signing_key_artifact_digest=package.signing_key_artifact_digest,
        signing_key_identity_digest=package.signing_key_identity_digest,
        service_safe_count=int(entry.service_masked and entry.service_inactive),
        prohibited_action_count=sum(
            (
                entry.service_started,
                entry.backend_configured,
                entry.configuration_performed,
                entry.registration_performed,
                entry.setup_performed,
                entry.tasks_performed,
            )
        ),
        manual_recovery_required=False,
        automatic_retry_allowed=False,
        skip_allowed=False,
        continue_allowed=False,
        rollback_performed=False,
        journal_status=context.binding.journal_status,
        journal_phase=context.binding.journal_phase,
    )


def _failure_state(error: AnsibleError) -> DeployManagerServerExecutionState:
    cause = error.__cause__
    if isinstance(cause, ProcessTimeoutError):
        return DeployManagerServerExecutionState.TIMED_OUT
    if isinstance(cause, ProcessOutputError):
        return DeployManagerServerExecutionState.MALFORMED_RESULT
    message = str(error).lower()
    if "unreachable" in message:
        return DeployManagerServerExecutionState.UNREACHABLE
    if isinstance(error, AnsibleResultError) or "malformed" in message:
        return DeployManagerServerExecutionState.MALFORMED_RESULT
    return DeployManagerServerExecutionState.FAILED


def _validate_execution_transition(
    current: DeployManagerServerExecution,
    replacement: DeployManagerServerExecution,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or current.completed
    ):
        raise StatePersistenceError(
            "deploy manager-server execution transition is invalid"
        )
    if current.state is DeployManagerServerExecutionState.PREPARED:
        valid = replacement.state is DeployManagerServerExecutionState.STARTED
    elif current.state is DeployManagerServerExecutionState.STARTED:
        valid = replacement.state not in {
            DeployManagerServerExecutionState.PREPARED,
            DeployManagerServerExecutionState.STARTED,
        }
    else:
        valid = False
    if not valid:
        raise StatePersistenceError(
            "deploy manager-server execution transition conflicts"
        )


def _binding_digest(binding: DeployManagerServerExecutionBinding) -> str:
    value = binding.to_object()
    value["binding_digest"] = ""
    return _digest_object(value)


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployManagerServerExecutionBinding.__dataclass_fields__.items():
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


def _evidence_entry_digest(entry: DeployManagerServerEvidenceEntry) -> str:
    value = entry.to_object()
    value["evidence_digest"] = ""
    return _digest_object(value)


def _evidence_entry_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployManagerServerEvidenceEntry.__dataclass_fields__.items():
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
            "deploy manager-server execution paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy manager-server execution requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_or_later_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy manager-server execution artifacts"
        ) from error
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_MANAGER_SERVER_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_MANAGER_SERVER_EVIDENCE_FILENAME_SUFFIX,
    )
    later_fragments = (
        ".ansible-deploy-post-manager-server-reconciliation.json",
        ".ansible-deploy-monitoring-stack",
        ".ansible-deploy-manager-agent",
        ".ansible-deploy-monitoring-agent",
        ".ansible-deploy-monitoring-targets",
        ".ansible-deploy-manager-tasks",
    )
    for entry in entries:
        if entry.name.startswith(canonical) and any(
            fragment in entry.name for fragment in later_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy manager-server execution refuses later-stage history"
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
                    "deploy manager-server execution artifacts are ambiguous"
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
            "deploy manager-server toolchain version is invalid"
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
    "ANSIBLE_DEPLOY_MANAGER_SERVER_EVIDENCE_ENTRY_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_SERVER_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_SERVER_EXECUTION_BINDING_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_SERVER_EXECUTION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_SERVER_EXECUTION_SCHEMA_VERSION",
    "DEPLOY_MANAGER_SERVER_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_MANAGER_SERVER_EXECUTION_FILENAME_SUFFIX",
    "DeployManagerServerArtifactState",
    "DeployManagerServerEvidence",
    "DeployManagerServerEvidenceEntry",
    "DeployManagerServerEvidenceStore",
    "DeployManagerServerExecution",
    "DeployManagerServerExecutionAttempt",
    "DeployManagerServerExecutionBinding",
    "DeployManagerServerExecutionReport",
    "DeployManagerServerExecutionState",
    "DeployManagerServerExecutionStore",
    "StoredDeployManagerServerEvidence",
    "StoredDeployManagerServerExecution",
    "deploy_manager_server_evidence_id_from_filename",
    "deploy_manager_server_evidence_path",
    "deploy_manager_server_execution_id_from_filename",
    "deploy_manager_server_execution_path",
    "execute_deploy_manager_server",
]
