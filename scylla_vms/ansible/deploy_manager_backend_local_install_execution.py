"""Durable execution for the authorized Manager-local package boundary.

This internal owner derives the exact package-only invocation from canonical
state, records retry-safe prepared and consuming started intents, and persists
only strict redacted semantic evidence.  Any non-success after started is
manual-recovery-only and is never retried automatically.
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
from scylla_vms.ansible.deploy_manager_backend_local_install_authorization import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCHEMA_VERSION,
    DeployManagerBackendLocalInstallAuthorizationScope,
    DeployManagerBackendLocalInstallAuthorizationStore,
    StoredDeployManagerBackendLocalInstallAuthorization,
    _AuthorizationContext,
    _build_authorization,
    _build_payload,
    _derive_authorization_scope,
    _derive_package_provenance,
    _load_authorization_context,
)
from scylla_vms.ansible.deploy_plan import _digest_object, _require_operation_id
from scylla_vms.ansible.manager_backend_local_install import (
    MANAGER_BACKEND_LOCAL_INSTALL_FORBIDDEN_ACTIONS,
    MANAGER_BACKEND_LOCAL_INSTALL_PLAYBOOK,
    MANAGER_BACKEND_LOCAL_INSTALL_SCHEMA_VERSION,
    ManagerBackendLocalInstallEvidence,
    ManagerBackendLocalInstallStatus,
    parse_manager_backend_local_install_execution,
)
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_install import (
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_PACKAGES,
    SCYLLA_RELEASE_LINE,
    SCYLLA_REPOSITORY_DEFINITION_DIGEST,
    SCYLLA_SIGNING_KEY_DIGEST,
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
    _toolchain_evidence_digest,
    _validate_toolchain_dependency,
)

ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-local-install-"
    "execution-binding/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-local-install-execution/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_ENTRY_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-local-install-evidence-entry/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-local-install-evidence/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-local-install-execution-report/v1"
)

DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-local-install-execution.json"
)
DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-local-install-evidence.json"
)

_OPERATION = "deploy"
_PLAYBOOK = MANAGER_BACKEND_LOCAL_INSTALL_PLAYBOOK
_STAGE = "manager-backend-local-package-install"
_SCOPE_KIND = "local-one-node-manager-package-install"
_STEP_SEQUENCE = 1
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SUCCESS_STATUSES = frozenset(
    {
        ManagerBackendLocalInstallStatus.INSTALLED,
        ManagerBackendLocalInstallStatus.NO_CHANGE,
    }
)


class DeployManagerBackendLocalInstallExecutionState(StrEnum):
    """Durable states for the sole authorized package attempt."""

    PREPARED = "prepared"
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"
    DRIFTED = "drifted"


class DeployManagerBackendLocalInstallArtifactState(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployManagerBackendLocalInstallExecutionBinding:
    """Address-free authorization, provenance, controller, and toolchain binding."""

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
    backend_context_artifact_digest: str
    backend_context_record_digest: str
    backend_plan_artifact_digest: str
    backend_plan_digest: str
    preflight_execution_artifact_digest: str
    preflight_execution_binding_digest: str
    preflight_evidence_artifact_digest: str
    preflight_evidence_digest: str
    preflight_reconciliation_artifact_digest: str
    preflight_reconciliation_record_digest: str
    installation_context_artifact_digest: str
    installation_context_record_digest: str
    installation_plan_artifact_digest: str
    installation_plan_digest: str
    base_os_evidence_artifact_digest: str
    base_os_evidence_digest: str
    manager_server_evidence_artifact_digest: str
    manager_server_evidence_digest: str
    manager_server_provenance_digest: str
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
    config_digest: str
    known_hosts_digest: str
    ssh_config_digest: str
    catalog_digest: str
    source_version: str
    source_digest: str
    playbook_source_digest: str
    toolchain_version: str
    executable_identity_digest: str
    toolchain_evidence_digest: str
    target_stable_id: str
    target_set_digest: str
    architecture: str
    package_version_digest: str
    package_set_digest: str
    package_provenance_digest: str
    repository_definition_digest: str
    signing_key_artifact_digest: str
    signing_key_identity_digest: str
    storage_decision_digest: str
    variables_digest: str
    command_digest: str
    command_policy_digest: str
    execution_scope_digest: str
    binding_digest: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_BINDING_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_BINDING_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or not self.target_stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
            or self.target_set_digest != _digest_object([self.target_stable_id])
            or self.architecture not in {"amd64", "aarch64"}
            or self.package_version_digest != _digest_object(SCYLLA_PACKAGE_VERSION)
            or self.package_set_digest != _digest_object(list(SCYLLA_PACKAGES))
            or self.repository_definition_digest != SCYLLA_REPOSITORY_DEFINITION_DIGEST
            or self.signing_key_artifact_digest != SCYLLA_SIGNING_KEY_DIGEST
        ):
            raise StatePersistenceError(
                "deploy Manager backend local install execution binding is invalid"
            )
        validate_cluster_name(self.cluster_name)
        for count in (
            self.journal_generation,
            self.metadata_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
        ):
            _positive_integer(
                count,
                "deploy Manager backend local install binding generation",
            )
        for digest in _digest_fields(self):
            validate_digest(
                digest,
                "deploy Manager backend local install binding digest",
            )
        _validate_toolchain_version(self.toolchain_version)
        if self.binding_digest != _binding_digest(self):
            raise StatePersistenceError(
                "deploy Manager backend local install binding digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls,
        value: Mapping[str, object],
    ) -> DeployManagerBackendLocalInstallExecutionBinding:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend local install execution binding",
        )
        integer_fields = {
            "journal_generation",
            "metadata_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                if name in {"cluster_uuid", "operation_id"}:
                    parsed[name] = parse_uuid(require_string(value, name), name)
                elif name in integer_fields:
                    parsed[name] = _integer(value[name], name)
                elif name == "journal_status":
                    parsed[name] = JournalStatus(require_string(value, name))
                elif name == "journal_phase":
                    parsed[name] = OperationPhase(require_string(value, name))
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Manager backend local install binding enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployManagerBackendLocalInstallExecutionAttempt:
    """One exact prepared, started, or terminal package-install attempt."""

    attempt_index: int
    step_sequence: int
    boundary: str
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
    storage_decision_digest: str
    state: DeployManagerBackendLocalInstallExecutionState
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
    result_schema_version: str = MANAGER_BACKEND_LOCAL_INSTALL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.attempt_index != 1
            or self.step_sequence != _STEP_SEQUENCE
            or self.boundary != "package-install"
            or not self.stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.package_version_digest != _digest_object(SCYLLA_PACKAGE_VERSION)
            or self.result_schema_version
            != MANAGER_BACKEND_LOCAL_INSTALL_SCHEMA_VERSION
            or not isinstance(
                self.state,
                DeployManagerBackendLocalInstallExecutionState,
            )
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy Manager backend local install attempt is invalid"
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
            self.storage_decision_digest,
            self.result_digest,
            self.evidence_digest,
        ):
            if digest is not None:
                validate_digest(
                    digest,
                    "deploy Manager backend local install attempt digest",
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
                "deploy Manager backend local install attempt timestamps conflict"
            )
        if self.state is DeployManagerBackendLocalInstallExecutionState.PREPARED:
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
        elif self.state is DeployManagerBackendLocalInstallExecutionState.STARTED:
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
        elif self.state is DeployManagerBackendLocalInstallExecutionState.SUCCEEDED:
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
                "deploy Manager backend local install attempt state conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls,
        value: Mapping[str, object],
    ) -> DeployManagerBackendLocalInstallExecutionAttempt:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend local install execution attempt",
        )
        try:
            return cls(
                attempt_index=_integer(value["attempt_index"], "attempt index"),
                step_sequence=_integer(value["step_sequence"], "step sequence"),
                boundary=require_string(value, "boundary"),
                stable_id=require_string(value, "stable_id"),
                target_digest=require_string(value, "target_digest"),
                authorization_scope_digest=require_string(
                    value,
                    "authorization_scope_digest",
                ),
                authorization_variables_digest=require_string(
                    value,
                    "authorization_variables_digest",
                ),
                authorization_command_digest=require_string(
                    value,
                    "authorization_command_digest",
                ),
                variables_digest=require_string(value, "variables_digest"),
                command_digest=require_string(value, "command_digest"),
                source_digest=require_string(value, "source_digest"),
                package_version_digest=require_string(
                    value,
                    "package_version_digest",
                ),
                package_provenance_digest=require_string(
                    value,
                    "package_provenance_digest",
                ),
                storage_decision_digest=require_string(
                    value,
                    "storage_decision_digest",
                ),
                state=DeployManagerBackendLocalInstallExecutionState(
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
                    value["invocation_may_have_occurred"],
                    "invocation state",
                ),
                exit_code=_optional_integer(value["exit_code"], "exit code"),
                result_digest=_optional_string(value["result_digest"], "result digest"),
                evidence_digest=_optional_string(
                    value["evidence_digest"],
                    "evidence digest",
                ),
                manual_recovery_required=_boolean(
                    value["manual_recovery_required"],
                    "manual recovery",
                ),
                automatic_retry_allowed=_boolean(
                    value["automatic_retry_allowed"],
                    "automatic retry",
                ),
                result_schema_version=require_string(value, "result_schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Manager backend local install attempt state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerBackendLocalInstallExecution:
    """Generation-guarded single-attempt execution state."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployManagerBackendLocalInstallExecutionBinding
    state: DeployManagerBackendLocalInstallExecutionState
    authorization_consumed: bool
    invocation_count: int
    completed: bool
    attempt: DeployManagerBackendLocalInstallExecutionAttempt
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        invoked = (
            self.state is not DeployManagerBackendLocalInstallExecutionState.PREPARED
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_SCHEMA_VERSION
            or self.generation < 1
            or self.state is not self.attempt.state
            or self.authorization_consumed != invoked
            or self.invocation_count != int(invoked)
            or self.completed
            != (self.state is DeployManagerBackendLocalInstallExecutionState.SUCCEEDED)
            or parse_timestamp(self.updated_at) < parse_timestamp(self.created_at)
        ):
            raise StatePersistenceError(
                "deploy Manager backend local install execution summary conflicts"
            )

    @property
    def manual_recovery_required(self) -> bool:
        return self.state not in {
            DeployManagerBackendLocalInstallExecutionState.PREPARED,
            DeployManagerBackendLocalInstallExecutionState.SUCCEEDED,
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
        cls,
        value: Mapping[str, object],
    ) -> DeployManagerBackendLocalInstallExecution:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend local install execution",
        )
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                updated_at=require_string(value, "updated_at"),
                binding=DeployManagerBackendLocalInstallExecutionBinding.from_object(
                    _mapping(value["binding"], "binding")
                ),
                state=DeployManagerBackendLocalInstallExecutionState(
                    require_string(value, "state")
                ),
                authorization_consumed=_boolean(
                    value["authorization_consumed"],
                    "authorization consumption",
                ),
                invocation_count=_integer(
                    value["invocation_count"],
                    "invocation count",
                ),
                completed=_boolean(value["completed"], "completion"),
                attempt=DeployManagerBackendLocalInstallExecutionAttempt.from_object(
                    _mapping(value["attempt"], "attempt")
                ),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Manager backend local install execution state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerBackendLocalInstallEvidenceEntry:
    """Strict redacted semantic evidence for the successful package boundary."""

    attempt_index: int
    step_sequence: int
    boundary: str
    stable_id: str
    role: str
    operating_system: str
    operating_system_version: str
    architecture: str
    status: ManagerBackendLocalInstallStatus
    installed: bool
    changed: bool
    release_line: str
    package_version_digest: str
    package_count: int
    package_set_digest: str
    repository_definition_digest: str
    signing_key_artifact_digest: str
    signing_key_identity_digest: str
    source_digest: str
    command_policy_digest: str
    provenance_digest: str
    storage_decision_digest: str
    variables_digest: str
    command_digest: str
    service_masked: bool
    service_inactive: bool
    prohibited_action_count: int
    prohibited_actions_digest: str
    result_digest: str
    evidence_digest: str
    manual_recovery_required: bool = False
    automatic_retry_allowed: bool = False
    result_schema_version: str = MANAGER_BACKEND_LOCAL_INSTALL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_ENTRY_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_ENTRY_SCHEMA_VERSION
            or self.result_schema_version
            != MANAGER_BACKEND_LOCAL_INSTALL_SCHEMA_VERSION
            or self.attempt_index != 1
            or self.step_sequence != _STEP_SEQUENCE
            or self.boundary != "package-install"
            or not self.stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.role != "manager"
            or self.operating_system != "Ubuntu"
            or self.operating_system_version != "24.04"
            or self.architecture not in {"amd64", "aarch64"}
            or self.status not in _SUCCESS_STATUSES
            or not self.installed
            or self.changed
            != (self.status is ManagerBackendLocalInstallStatus.INSTALLED)
            or self.release_line != SCYLLA_RELEASE_LINE
            or self.package_version_digest != _digest_object(SCYLLA_PACKAGE_VERSION)
            or self.package_count != len(SCYLLA_PACKAGES)
            or self.package_set_digest != _digest_object(list(SCYLLA_PACKAGES))
            or self.repository_definition_digest != SCYLLA_REPOSITORY_DEFINITION_DIGEST
            or self.signing_key_artifact_digest != SCYLLA_SIGNING_KEY_DIGEST
            or not self.service_masked
            or not self.service_inactive
            or self.prohibited_action_count != 0
            or self.prohibited_actions_digest
            != _digest_object(
                {
                    name: False
                    for name in MANAGER_BACKEND_LOCAL_INSTALL_FORBIDDEN_ACTIONS
                }
            )
            or self.manual_recovery_required
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy Manager backend local install semantic evidence conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(
                digest,
                "deploy Manager backend local install evidence digest",
            )
        if self.evidence_digest != _evidence_entry_digest(self):
            raise StatePersistenceError(
                "deploy Manager backend local install evidence digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls,
        value: Mapping[str, object],
    ) -> DeployManagerBackendLocalInstallEvidenceEntry:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend local install evidence entry",
        )
        integer_fields = {
            "attempt_index",
            "step_sequence",
            "package_count",
            "prohibited_action_count",
        }
        boolean_fields = {
            "installed",
            "changed",
            "service_masked",
            "service_inactive",
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
                    parsed[name] = ManagerBackendLocalInstallStatus(
                        require_string(value, name)
                    )
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Manager backend local install evidence status is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployManagerBackendLocalInstallEvidence:
    """Immutable one-entry semantic-evidence prefix."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployManagerBackendLocalInstallExecutionBinding
    entries: tuple[DeployManagerBackendLocalInstallEvidenceEntry, ...]
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_SCHEMA_VERSION
            or self.generation != 1
            or len(self.entries) != 1
            or parse_timestamp(self.updated_at) < parse_timestamp(self.created_at)
        ):
            raise StatePersistenceError(
                "deploy Manager backend local install evidence prefix conflicts"
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
        cls,
        value: Mapping[str, object],
    ) -> DeployManagerBackendLocalInstallEvidence:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend local install evidence",
        )
        return cls(
            generation=_integer(value["generation"], "generation"),
            created_at=require_string(value, "created_at"),
            updated_at=require_string(value, "updated_at"),
            binding=DeployManagerBackendLocalInstallExecutionBinding.from_object(
                _mapping(value["binding"], "binding")
            ),
            entries=tuple(
                DeployManagerBackendLocalInstallEvidenceEntry.from_object(
                    _mapping(item, "evidence entry")
                )
                for item in _array(value["entries"], "evidence entries")
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendLocalInstallExecution:
    record: DeployManagerBackendLocalInstallExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendLocalInstallEvidence:
    record: DeployManagerBackendLocalInstallEvidence
    artifact_digest: str


class DeployManagerBackendLocalInstallExecutionStore:
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
        self._path = deploy_manager_backend_local_install_execution_path(
            paths,
            operation_id,
        )
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
    ) -> StoredDeployManagerBackendLocalInstallExecution:
        value, digest = self._file.read()
        record = DeployManagerBackendLocalInstallExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy Manager backend local install execution identity conflicts"
            )
        return StoredDeployManagerBackendLocalInstallExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendLocalInstallExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendLocalInstallExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployManagerBackendLocalInstallExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy Manager backend local install execution operation conflicts"
            )
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
                or record.state
                is not DeployManagerBackendLocalInstallExecutionState.PREPARED
            ):
                raise StatePersistenceError(
                    "initial deploy Manager backend local install generation conflicts"
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
                    "deploy Manager backend local install execution changed concurrently"
                )
            _validate_execution_transition(current.record, record)
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployManagerBackendLocalInstallExecution(record, digest)


class DeployManagerBackendLocalInstallEvidenceStore:
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
        self._path = deploy_manager_backend_local_install_evidence_path(
            paths,
            operation_id,
        )
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
    ) -> StoredDeployManagerBackendLocalInstallEvidence:
        value, digest = self._file.read()
        record = DeployManagerBackendLocalInstallEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy Manager backend local install evidence identity conflicts"
            )
        return StoredDeployManagerBackendLocalInstallEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendLocalInstallEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendLocalInstallEvidence,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerBackendLocalInstallEvidence,
        DeployManagerBackendLocalInstallArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy Manager backend local install evidence operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy Manager backend local install evidence is immutable"
                )
            return (
                current,
                DeployManagerBackendLocalInstallArtifactState.REUSED,
            )
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerBackendLocalInstallEvidence(record, digest),
            DeployManagerBackendLocalInstallArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendLocalInstallExecutionReport:
    """Strict redacted report for one successful package-only attempt."""

    operation_id: uuid.UUID
    execution_state: DeployManagerBackendLocalInstallExecutionState
    execution_artifact_state: DeployManagerBackendLocalInstallArtifactState
    evidence_artifact_state: DeployManagerBackendLocalInstallArtifactState
    execution_artifact_digest: str
    evidence_artifact_digest: str
    binding_digest: str
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_consumed: bool
    target_stable_id: str
    target_set_digest: str
    architecture: str
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
    storage_decision_digest: str
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
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCHEMA_VERSION
    )
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_SCHEMA_VERSION
            or self.execution_state
            is not DeployManagerBackendLocalInstallExecutionState.SUCCEEDED
            or not self.authorization_consumed
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.invocation_count != 1
            or self.installed_count != 1
            or self.release_line != SCYLLA_RELEASE_LINE
            or self.package_count != len(SCYLLA_PACKAGES)
            or self.service_safe_count != 1
            or self.prohibited_action_count != 0
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
                "deploy Manager backend local install execution report is invalid"
            )
        if (
            not self.target_stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
            or self.architecture not in {"amd64", "aarch64"}
        ):
            raise StatePersistenceError(
                "deploy Manager backend local install report target is invalid"
            )
        for digest in _digest_fields(self):
            validate_digest(
                digest,
                "deploy Manager backend local install report digest",
            )

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
                "architecture": self.architecture,
                "kind": self.scope_kind,
                "storage_decision_digest": self.storage_decision_digest,
                "target_count": 1,
                "target_set_digest": self.target_set_digest,
                "target_stable_id": self.target_stable_id,
            },
            "stage": self.stage,
        }


@dataclass(frozen=True, slots=True)
class _ExecutionScope:
    authorization: DeployManagerBackendLocalInstallAuthorizationScope
    authorization_scope_digest: str
    variables: tuple[tuple[str, object], ...]
    variables_digest: str
    command_digest: str
    source_digest: str
    signing_key_identity_digest: str
    step_sequence: int
    payload: dict[str, object]


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    authorization_context: _AuthorizationContext
    authorization: StoredDeployManagerBackendLocalInstallAuthorization
    binding: DeployManagerBackendLocalInstallExecutionBinding
    scope: _ExecutionScope
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport


def execute_deploy_manager_backend_local_install(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployManagerBackendLocalInstallExecutionReport:
    """Execute the exact immutable authorized local-backend package scope."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _validate_toolchain_dependency(toolchain)
    executable_identity_digest = _executable_identity_digest(executables)
    toolchain_evidence_digest = _toolchain_evidence_digest(
        toolchain,
        executable_identity_digest,
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
    execution_store = DeployManagerBackendLocalInstallExecutionStore(
        paths,
        operation_id,
    )
    evidence_store = DeployManagerBackendLocalInstallEvidenceStore(
        paths,
        operation_id,
    )
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
                "completed deploy Manager backend local install evidence is unavailable"
            )
        return _build_report(
            context,
            execution,
            evidence,
            execution_state=DeployManagerBackendLocalInstallArtifactState.REUSED,
            evidence_state=DeployManagerBackendLocalInstallArtifactState.REUSED,
        )
    if (
        execution is not None
        and execution.record.state
        is not DeployManagerBackendLocalInstallExecutionState.PREPARED
    ):
        raise StateConflictError(
            "deploy Manager backend local install requires manual recovery "
            "and cannot retry"
        )

    service = AnsibleService(builder, runner)
    if service.version(lock) != toolchain:
        raise StateConflictError(
            "deploy Manager backend local install Ansible toolchain drifted"
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
    _validate_prefix(context, execution, evidence)
    if execution is None:
        try:
            execution = _persist_prepared(context, execution_store, lock=lock)
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy Manager backend local install prepared intent persistence "
                "failed before invocation"
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
        raise StateConflictError(
            "deploy Manager backend local install state drifted before start"
        )
    _validate_prefix(before_start, execution, evidence)
    try:
        execution = _persist_started(execution_store, execution, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy Manager backend local install authorization consumption "
            "failed before invocation"
        ) from error

    scope = before_start.scope
    definition = get_playbook(_PLAYBOOK)
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
            tags=definition.tags,
            check=False,
            diff=False,
            verbosity=0,
        )
        if command_digest != scope.command_digest:
            raise AnsibleResultError(
                "deploy Manager backend local install command result identity conflicts"
            )
    except KeyboardInterrupt:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployManagerBackendLocalInstallExecutionState.INTERRUPTED,
            lock=lock,
        )
        raise AnsibleError(
            "deploy Manager backend local install was interrupted; "
            "manual recovery required"
        ) from None
    except (AnsibleError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            (
                _failure_state(error)
                if isinstance(error, AnsibleError)
                else DeployManagerBackendLocalInstallExecutionState.MALFORMED_RESULT
            ),
            lock=lock,
        )
        raise AnsibleError(
            "deploy Manager backend local install execution is uncertain; "
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
                "deploy Manager backend local install state changed after invocation"
            )
    except (StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployManagerBackendLocalInstallExecutionState.DRIFTED,
            lock=lock,
        )
        raise StateConflictError(
            "deploy Manager backend local install state changed after invocation; "
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
                else DeployManagerBackendLocalInstallExecutionState.MALFORMED_RESULT
            ),
            lock=lock,
        )
        raise AnsibleError(
            "deploy Manager backend local install result is not strict successful "
            "evidence; manual recovery required"
        ) from error

    try:
        evidence, evidence_state = _persist_evidence(
            context,
            evidence_store,
            entry,
            lock=lock,
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy Manager backend local install evidence persistence failed; "
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
            "deploy Manager backend local install terminal persistence failed; "
            "manual recovery required"
        ) from error
    _validate_prefix(context, execution, evidence)
    return _build_report(
        context,
        execution,
        evidence,
        execution_state=DeployManagerBackendLocalInstallArtifactState.UPDATED,
        evidence_state=evidence_state,
    )


def deploy_manager_backend_local_install_execution_path(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}"
        f"{DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Manager backend local install execution path is not canonical"
        )
    return path


def deploy_manager_backend_local_install_evidence_path(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Manager backend local install evidence path is not canonical"
        )
    return path


def deploy_manager_backend_local_install_execution_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name,
        DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_FILENAME_SUFFIX,
    )


def deploy_manager_backend_local_install_evidence_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name,
        DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_FILENAME_SUFFIX,
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
    planning = authorization_context.planning
    current = planning.execution_context
    metadata = current.metadata
    preflight_binding = current.binding
    if (
        preflight_binding.journal_status is not JournalStatus.IN_PROGRESS
        or preflight_binding.journal_phase is not OperationPhase.VERIFY
        or preflight_binding.toolchain_version != str(toolchain.core)
        or preflight_binding.executable_identity_digest != executable_identity_digest
        or preflight_binding.toolchain_evidence_digest != toolchain_evidence_digest
    ):
        raise StateConflictError(
            "deploy Manager backend local install journal, controller, or "
            "toolchain conflicts"
        )
    current.readiness.require_ready(OperationClassification.MUTATING)

    authorization_store = DeployManagerBackendLocalInstallAuthorizationStore(
        paths,
        operation_id,
    )
    validate_state_file(authorization_store.path, allow_missing=True)
    if not authorization_store.path.exists():
        raise StateConflictError(
            "deploy Manager backend local install execution requires "
            "immutable authorization"
        )
    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    payload = _build_payload(authorization_context)
    package = _derive_package_provenance(authorization_context, payload)
    authorized_scope = _derive_authorization_scope(
        authorization_context,
        payload,
        package,
    )
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
            "deploy Manager backend local install authorization is stale or consumed"
        )

    scope = _derive_execution_scope(
        authorization,
        authorized_scope,
        payload,
        builder=builder,
    )
    record = authorization.record
    binding_values: dict[str, object] = {
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_name": metadata.cluster_name,
        "operation_id": operation_id,
        "operation": _OPERATION,
        "request_digest": record.request_digest,
        "journal_generation": record.journal_generation,
        "journal_digest": record.journal_digest,
        "journal_status": record.journal_status,
        "journal_phase": record.journal_phase,
        "authorization_artifact_digest": authorization.artifact_digest,
        "authorization_digest": record.authorization_digest,
        "authorization_scope_digest": record.authorization_scope_digest,
        "authorization_proof_digest": record.proof.proof_digest,
        "backend_context_artifact_digest": record.backend_context_artifact_digest,
        "backend_context_record_digest": record.backend_context_record_digest,
        "backend_plan_artifact_digest": record.backend_plan_artifact_digest,
        "backend_plan_digest": record.backend_plan_digest,
        "preflight_execution_artifact_digest": (
            record.preflight_execution_artifact_digest
        ),
        "preflight_execution_binding_digest": (
            record.preflight_execution_binding_digest
        ),
        "preflight_evidence_artifact_digest": (
            record.preflight_evidence_artifact_digest
        ),
        "preflight_evidence_digest": record.preflight_evidence_digest,
        "preflight_reconciliation_artifact_digest": (
            record.preflight_reconciliation_artifact_digest
        ),
        "preflight_reconciliation_record_digest": (
            record.preflight_reconciliation_record_digest
        ),
        "installation_context_artifact_digest": (
            record.installation_context_artifact_digest
        ),
        "installation_context_record_digest": (
            record.installation_context_record_digest
        ),
        "installation_plan_artifact_digest": (record.installation_plan_artifact_digest),
        "installation_plan_digest": record.installation_plan_digest,
        "base_os_evidence_artifact_digest": (record.base_os_evidence_artifact_digest),
        "base_os_evidence_digest": record.base_os_evidence_digest,
        "manager_server_evidence_artifact_digest": (
            record.manager_server_evidence_artifact_digest
        ),
        "manager_server_evidence_digest": record.manager_server_evidence_digest,
        "manager_server_provenance_digest": (record.manager_server_provenance_digest),
        "metadata_generation": record.metadata_generation,
        "metadata_artifact_digest": record.metadata_artifact_digest,
        "desired_spec_digest": record.desired_spec_digest,
        "observation_generation": record.observation_generation,
        "observation_artifact_digest": record.observation_artifact_digest,
        "observation_manifest_digest": record.observation_manifest_digest,
        "inventory_generation": record.inventory_generation,
        "inventory_artifact_digest": record.inventory_artifact_digest,
        "inventory_digest": record.inventory_digest,
        "trust_generation": record.trust_generation,
        "trust_artifact_digest": record.trust_artifact_digest,
        "trust_entries_digest": record.trust_entries_digest,
        "readiness_artifact_digest": record.readiness_artifact_digest,
        "readiness_record_digest": record.readiness_record_digest,
        "config_digest": preflight_binding.config_digest,
        "known_hosts_digest": preflight_binding.known_hosts_digest,
        "ssh_config_digest": preflight_binding.ssh_config_digest,
        "catalog_digest": record.catalog_digest,
        "source_version": ANSIBLE_SOURCE_VERSION,
        "source_digest": record.ansible_source_digest,
        "playbook_source_digest": scope.source_digest,
        "toolchain_version": str(toolchain.core),
        "executable_identity_digest": executable_identity_digest,
        "toolchain_evidence_digest": toolchain_evidence_digest,
        "target_stable_id": authorized_scope.target_stable_id,
        "target_set_digest": authorized_scope.target_digest,
        "architecture": authorized_scope.architecture.value,
        "package_version_digest": package.package_version_digest,
        "package_set_digest": package.package_set_digest,
        "package_provenance_digest": package.provenance_digest,
        "repository_definition_digest": package.repository_definition_digest,
        "signing_key_artifact_digest": package.signing_key_artifact_digest,
        "signing_key_identity_digest": package.signing_key_identity_digest,
        "storage_decision_digest": authorized_scope.storage_decision_digest,
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "command_policy_digest": authorized_scope.command_policy_digest,
        "execution_scope_digest": _digest_object(
            {
                "authorization_scope_digest": scope.authorization_scope_digest,
                "command_digest": scope.command_digest,
                "package_provenance_digest": package.provenance_digest,
                "source_digest": scope.source_digest,
                "storage_decision_digest": authorized_scope.storage_decision_digest,
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
        DeployManagerBackendLocalInstallExecutionBinding(**binding_values),  # type: ignore[arg-type]
        scope,
        metadata,
        current.inventory,
        current.readiness,
    )


def _derive_execution_scope(
    authorization: StoredDeployManagerBackendLocalInstallAuthorization,
    authorized: DeployManagerBackendLocalInstallAuthorizationScope,
    payload: dict[str, object],
    *,
    builder: AnsibleCommandBuilder,
) -> _ExecutionScope:
    definition = get_playbook(_PLAYBOOK)
    if (
        authorized.playbook != _PLAYBOOK
        or authorized.step_sequence != _STEP_SEQUENCE
        or authorized.boundary != "package-install"
        or authorized.classification is not OperationClassification.MUTATING
        or authorized.target_role != "manager"
        or authorized.package_install_permitted is not True
        or any(
            (
                authorized.setup_permitted,
                authorized.storage_mutation_permitted,
                authorized.tuning_permitted,
                authorized.configuration_permitted,
                authorized.schema_permitted,
                authorized.manager_actions_permitted,
                authorized.service_start_permitted,
            )
        )
        or definition.classification is not OperationClassification.MUTATING
        or definition.hosts != "manager"
        or definition.serial != 1
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.check_mode is not CheckMode.PREVIEW
        or not definition.any_errors_fatal
        or not definition.source_available
    ):
        raise StateConflictError(
            "deploy Manager backend local install exact authorized policy conflicts"
        )
    variables = {"deploy_scylla_vms_manager_backend_local_install": payload}
    selected, validated, variables_digest, command_digest = (
        builder.validate_operation_step(
            _PLAYBOOK,
            step_sequence=authorized.step_sequence,
            limit=(authorized.target_stable_id,),
            variables=variables,
            tags=definition.tags,
            check=False,
            diff=False,
            verbosity=0,
        )
    )
    if (
        selected != definition
        or variables_digest != authorized.variables_digest
        or command_digest != authorized.command_digest
        or authorized.source_digest
        != authorization.record.package_provenance.source_digest
        or authorized.playbook_source_digest
        != authorization.record.package_provenance.playbook_source_digest
    ):
        raise StateConflictError(
            "deploy Manager backend local install anchored command or source conflicts"
        )
    return _ExecutionScope(
        authorized,
        _digest_object(authorized.to_object()),
        tuple(sorted(validated.items())),
        variables_digest,
        command_digest,
        authorized.playbook_source_digest,
        authorization.record.package_provenance.signing_key_identity_digest,
        authorized.step_sequence,
        payload,
    )


def _validate_prefix(
    context: _ExecutionContext,
    execution: StoredDeployManagerBackendLocalInstallExecution | None,
    evidence: StoredDeployManagerBackendLocalInstallEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "deploy Manager backend local install evidence exists without execution"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError(
            "deploy Manager backend local install execution provenance is stale"
        )
    attempt = execution.record.attempt
    scope = context.scope
    authorized = scope.authorization
    if (
        attempt.step_sequence != authorized.step_sequence
        or attempt.boundary != authorized.boundary
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
        or attempt.storage_decision_digest != context.binding.storage_decision_digest
    ):
        raise StateConflictError(
            "deploy Manager backend local install execution scope conflicts"
        )
    if evidence is None:
        if (
            execution.record.state
            is DeployManagerBackendLocalInstallExecutionState.SUCCEEDED
        ):
            raise StateConflictError(
                "deploy Manager backend local install success evidence is missing"
            )
        return
    if evidence.record.binding != context.binding or execution.record.state not in {
        DeployManagerBackendLocalInstallExecutionState.STARTED,
        DeployManagerBackendLocalInstallExecutionState.SUCCEEDED,
    }:
        raise StateConflictError(
            "deploy Manager backend local install execution/evidence prefixes conflict"
        )
    entry = evidence.record.entries[0]
    if (
        entry.stable_id != authorized.target_stable_id
        or entry.step_sequence != authorized.step_sequence
        or entry.variables_digest != scope.variables_digest
        or entry.command_digest != scope.command_digest
        or entry.source_digest != authorized.source_digest
        or entry.signing_key_identity_digest != scope.signing_key_identity_digest
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
            "deploy Manager backend local install semantic evidence conflicts"
        )


def _persist_prepared(
    context: _ExecutionContext,
    store: DeployManagerBackendLocalInstallExecutionStore,
    *,
    lock: ClusterLock,
) -> StoredDeployManagerBackendLocalInstallExecution:
    now = _timestamp()
    scope = context.scope
    attempt = DeployManagerBackendLocalInstallExecutionAttempt(
        attempt_index=1,
        step_sequence=scope.authorization.step_sequence,
        boundary=scope.authorization.boundary,
        stable_id=scope.authorization.target_stable_id,
        target_digest=scope.authorization.target_digest,
        authorization_scope_digest=scope.authorization_scope_digest,
        authorization_variables_digest=scope.authorization.variables_digest,
        authorization_command_digest=scope.authorization.command_digest,
        variables_digest=scope.variables_digest,
        command_digest=scope.command_digest,
        source_digest=scope.source_digest,
        package_version_digest=_digest_object(SCYLLA_PACKAGE_VERSION),
        package_provenance_digest=context.binding.package_provenance_digest,
        storage_decision_digest=context.binding.storage_decision_digest,
        state=DeployManagerBackendLocalInstallExecutionState.PREPARED,
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
    record = DeployManagerBackendLocalInstallExecution(
        generation=1,
        created_at=now,
        updated_at=now,
        binding=context.binding,
        state=DeployManagerBackendLocalInstallExecutionState.PREPARED,
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
    store: DeployManagerBackendLocalInstallExecutionStore,
    current: StoredDeployManagerBackendLocalInstallExecution,
    *,
    lock: ClusterLock,
) -> StoredDeployManagerBackendLocalInstallExecution:
    if (
        current.record.state
        is not DeployManagerBackendLocalInstallExecutionState.PREPARED
    ):
        raise StateConflictError(
            "deploy Manager backend local install start requires prepared intent"
        )
    now = _timestamp()
    attempt = replace(
        current.record.attempt,
        state=DeployManagerBackendLocalInstallExecutionState.STARTED,
        started_at=now,
        authorization_consumed_at_start=True,
        invocation_may_have_occurred=True,
        manual_recovery_required=True,
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=DeployManagerBackendLocalInstallExecutionState.STARTED,
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
    store: DeployManagerBackendLocalInstallExecutionStore,
    current: StoredDeployManagerBackendLocalInstallExecution,
    state: DeployManagerBackendLocalInstallExecutionState,
    *,
    lock: ClusterLock,
) -> None:
    try:
        _persist_uncertain(store, current, state, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy Manager backend local install uncertain outcome persistence "
            "failed; manual recovery required"
        ) from error


def _persist_uncertain(
    store: DeployManagerBackendLocalInstallExecutionStore,
    current: StoredDeployManagerBackendLocalInstallExecution,
    state: DeployManagerBackendLocalInstallExecutionState,
    *,
    lock: ClusterLock,
) -> StoredDeployManagerBackendLocalInstallExecution:
    if (
        current.record.state
        is not DeployManagerBackendLocalInstallExecutionState.STARTED
        or state
        not in {
            DeployManagerBackendLocalInstallExecutionState.FAILED,
            DeployManagerBackendLocalInstallExecutionState.TIMED_OUT,
            DeployManagerBackendLocalInstallExecutionState.INTERRUPTED,
            DeployManagerBackendLocalInstallExecutionState.UNREACHABLE,
            DeployManagerBackendLocalInstallExecutionState.MALFORMED_RESULT,
            DeployManagerBackendLocalInstallExecutionState.DRIFTED,
        }
    ):
        raise StatePersistenceError(
            "deploy Manager backend local install uncertain transition conflicts"
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
    store: DeployManagerBackendLocalInstallEvidenceStore,
    entry: DeployManagerBackendLocalInstallEvidenceEntry,
    *,
    lock: ClusterLock,
) -> tuple[
    StoredDeployManagerBackendLocalInstallEvidence,
    DeployManagerBackendLocalInstallArtifactState,
]:
    now = _timestamp()
    record = DeployManagerBackendLocalInstallEvidence(
        generation=1,
        created_at=now,
        updated_at=now,
        binding=context.binding,
        entries=(entry,),
    )
    return store.write_locked(record, lock=lock)


def _persist_terminal_success(
    store: DeployManagerBackendLocalInstallExecutionStore,
    current: StoredDeployManagerBackendLocalInstallExecution,
    *,
    entry: DeployManagerBackendLocalInstallEvidenceEntry,
    lock: ClusterLock,
) -> StoredDeployManagerBackendLocalInstallExecution:
    if (
        current.record.state
        is not DeployManagerBackendLocalInstallExecutionState.STARTED
    ):
        raise StateConflictError(
            "deploy Manager backend local install terminal transition conflicts"
        )
    now = _timestamp()
    attempt = replace(
        current.record.attempt,
        state=DeployManagerBackendLocalInstallExecutionState.SUCCEEDED,
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
        state=DeployManagerBackendLocalInstallExecutionState.SUCCEEDED,
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
    scope: _ExecutionScope,
    result: AnsibleExecutionResult,
) -> DeployManagerBackendLocalInstallEvidenceEntry:
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.MUTATING
        or result.check_mode
        or result.manager_backend_local_install is not None
    ):
        raise AnsibleResultError(
            "deploy Manager backend local install strict result identity conflicts"
        )
    try:
        parsed = parse_manager_backend_local_install_execution(
            result.stdout,
            expected_payload=scope.payload,
            exit_code=result.exit_code,
        )
    except AnsibleError as error:
        raise AnsibleResultError(
            "deploy Manager backend local install strict result is malformed"
        ) from error
    if parsed.status not in _SUCCESS_STATUSES:
        message = "unreachable" if result.exit_code == 4 else "execution failed"
        raise AnsibleError(f"deploy Manager backend local install {message}")
    _validate_success_evidence(parsed, scope.authorization.target_stable_id)
    prohibited = _prohibited_result_flags(parsed)
    prohibited_projection = dict(
        zip(
            MANAGER_BACKEND_LOCAL_INSTALL_FORBIDDEN_ACTIONS,
            prohibited,
            strict=True,
        )
    )
    provenance_digest = _digest_object(dict(parsed.provenance))
    result_digest = _digest_object(
        {
            "changed": parsed.changed,
            "command_policy_digest": parsed.command_policy_digest,
            "logical_id": parsed.logical_id,
            "package_set_digest": _digest_object(
                [name for name, _version in parsed.packages]
            ),
            "prohibited_actions_digest": _digest_object(prohibited_projection),
            "provenance_digest": provenance_digest,
            "repository_definition_digest": parsed.repository_digest,
            "schema_version": parsed.schema_version,
            "service_inactive": parsed.service_inactive,
            "service_masked": parsed.service_masked,
            "signing_key_artifact_digest": parsed.signing_key_digest,
            "source_digest": parsed.source_digest,
            "status": parsed.status.value,
        }
    )
    package = scope.authorization
    values: dict[str, object] = {
        "attempt_index": 1,
        "step_sequence": package.step_sequence,
        "boundary": package.boundary,
        "stable_id": package.target_stable_id,
        "role": parsed.role,
        "operating_system": parsed.operating_system,
        "operating_system_version": parsed.operating_system_version,
        "architecture": parsed.architecture,
        "status": parsed.status,
        "installed": True,
        "changed": parsed.changed,
        "release_line": SCYLLA_RELEASE_LINE,
        "package_version_digest": _digest_object(SCYLLA_PACKAGE_VERSION),
        "package_count": len(parsed.packages),
        "package_set_digest": _digest_object(
            [name for name, _version in parsed.packages]
        ),
        "repository_definition_digest": parsed.repository_digest,
        "signing_key_artifact_digest": parsed.signing_key_digest,
        "signing_key_identity_digest": scope.signing_key_identity_digest,
        "source_digest": parsed.source_digest,
        "command_policy_digest": parsed.command_policy_digest,
        "provenance_digest": provenance_digest,
        "storage_decision_digest": package.storage_decision_digest,
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "service_masked": cast(bool, parsed.service_masked),
        "service_inactive": cast(bool, parsed.service_inactive),
        "prohibited_action_count": sum(prohibited),
        "prohibited_actions_digest": _digest_object(prohibited_projection),
        "result_digest": result_digest,
        "evidence_digest": "",
    }
    values["evidence_digest"] = _evidence_entry_digest_from_values(values)
    return DeployManagerBackendLocalInstallEvidenceEntry(**values)  # type: ignore[arg-type]


def _validate_success_evidence(
    evidence: ManagerBackendLocalInstallEvidence,
    expected_stable_id: str,
) -> None:
    if (
        evidence.logical_id != expected_stable_id
        or evidence.role != "manager"
        or evidence.operating_system != "Ubuntu"
        or evidence.operating_system_version != "24.04"
        or evidence.architecture not in {"amd64", "aarch64"}
        or evidence.requested_release != SCYLLA_RELEASE_LINE
        or evidence.requested_version != SCYLLA_PACKAGE_VERSION
        or evidence.installed_version != SCYLLA_PACKAGE_VERSION
        or evidence.packages
        != tuple((name, SCYLLA_PACKAGE_VERSION) for name in SCYLLA_PACKAGES)
        or evidence.repository_digest != SCYLLA_REPOSITORY_DEFINITION_DIGEST
        or evidence.signing_key_digest != SCYLLA_SIGNING_KEY_DIGEST
        or evidence.service_masked is not True
        or evidence.service_inactive is not True
        or any(_prohibited_result_flags(evidence))
        or evidence.blockers
    ):
        raise AnsibleResultError(
            "deploy Manager backend local install successful evidence conflicts"
        )


def _prohibited_result_flags(
    evidence: ManagerBackendLocalInstallEvidence,
) -> tuple[bool, ...]:
    return tuple(
        cast(bool, getattr(evidence, name))
        for name in MANAGER_BACKEND_LOCAL_INSTALL_FORBIDDEN_ACTIONS
    )


def _build_report(
    context: _ExecutionContext,
    execution: StoredDeployManagerBackendLocalInstallExecution,
    evidence: StoredDeployManagerBackendLocalInstallEvidence,
    *,
    execution_state: DeployManagerBackendLocalInstallArtifactState,
    evidence_state: DeployManagerBackendLocalInstallArtifactState,
) -> DeployManagerBackendLocalInstallExecutionReport:
    if (
        not execution.record.completed
        or execution.record.state
        is not DeployManagerBackendLocalInstallExecutionState.SUCCEEDED
        or len(evidence.record.entries) != 1
    ):
        raise StateConflictError(
            "deploy Manager backend local install execution is not complete"
        )
    package = context.authorization.record.package_provenance
    entry = evidence.record.entries[0]
    return DeployManagerBackendLocalInstallExecutionReport(
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
        architecture=context.binding.architecture,
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
        storage_decision_digest=context.binding.storage_decision_digest,
        service_safe_count=int(entry.service_masked and entry.service_inactive),
        prohibited_action_count=entry.prohibited_action_count,
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
) -> DeployManagerBackendLocalInstallExecutionState:
    current: BaseException | None = error
    while current is not None:
        if isinstance(current, ProcessTimeoutError):
            return DeployManagerBackendLocalInstallExecutionState.TIMED_OUT
        if isinstance(current, ProcessOutputError):
            return DeployManagerBackendLocalInstallExecutionState.MALFORMED_RESULT
        current = current.__cause__
    message = str(error).lower()
    if "unreachable" in message:
        return DeployManagerBackendLocalInstallExecutionState.UNREACHABLE
    if isinstance(error, AnsibleResultError) or "malformed" in message:
        return DeployManagerBackendLocalInstallExecutionState.MALFORMED_RESULT
    return DeployManagerBackendLocalInstallExecutionState.FAILED


def _validate_execution_transition(
    current: DeployManagerBackendLocalInstallExecution,
    replacement: DeployManagerBackendLocalInstallExecution,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or current.completed
    ):
        raise StatePersistenceError(
            "deploy Manager backend local install execution transition is invalid"
        )
    if current.state is DeployManagerBackendLocalInstallExecutionState.PREPARED:
        valid = (
            replacement.state is DeployManagerBackendLocalInstallExecutionState.STARTED
        )
    elif current.state is DeployManagerBackendLocalInstallExecutionState.STARTED:
        valid = replacement.state not in {
            DeployManagerBackendLocalInstallExecutionState.PREPARED,
            DeployManagerBackendLocalInstallExecutionState.STARTED,
        }
    else:
        valid = False
    if not valid:
        raise StatePersistenceError(
            "deploy Manager backend local install execution transition conflicts"
        )


def _binding_digest(
    binding: DeployManagerBackendLocalInstallExecutionBinding,
) -> str:
    value = binding.to_object()
    value["binding_digest"] = ""
    return _digest_object(value)


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployManagerBackendLocalInstallExecutionBinding.__dataclass_fields__.items():
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


def _evidence_entry_digest(
    entry: DeployManagerBackendLocalInstallEvidenceEntry,
) -> str:
    value = entry.to_object()
    value["evidence_digest"] = ""
    return _digest_object(value)


def _evidence_entry_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployManagerBackendLocalInstallEvidenceEntry.__dataclass_fields__.items():
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
            "deploy Manager backend local install execution paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy Manager backend local install execution requires "
            "an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_or_later_artifacts(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Manager backend local install artifacts"
        ) from error
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_FILENAME_SUFFIX,
    )
    later_fragments = (
        ".ansible-deploy-post-manager-backend-local-install-reconciliation.json",
        ".ansible-deploy-manager-backend-storage",
        ".ansible-deploy-manager-backend-file-configuration",
        ".ansible-deploy-manager-backend-schema",
    )
    for entry in entries:
        if entry.name.startswith(canonical) and any(
            fragment in entry.name for fragment in later_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy Manager backend local install refuses later-stage history"
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
                    "deploy Manager backend local install artifacts are ambiguous"
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
            "deploy Manager backend local install toolchain version is invalid"
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


__all__ = [
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_ENTRY_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_BINDING_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_SCHEMA_VERSION",
    "DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_EXECUTION_FILENAME_SUFFIX",
    "DeployManagerBackendLocalInstallArtifactState",
    "DeployManagerBackendLocalInstallEvidence",
    "DeployManagerBackendLocalInstallEvidenceEntry",
    "DeployManagerBackendLocalInstallEvidenceStore",
    "DeployManagerBackendLocalInstallExecution",
    "DeployManagerBackendLocalInstallExecutionAttempt",
    "DeployManagerBackendLocalInstallExecutionBinding",
    "DeployManagerBackendLocalInstallExecutionReport",
    "DeployManagerBackendLocalInstallExecutionState",
    "DeployManagerBackendLocalInstallExecutionStore",
    "StoredDeployManagerBackendLocalInstallEvidence",
    "StoredDeployManagerBackendLocalInstallExecution",
    "deploy_manager_backend_local_install_evidence_id_from_filename",
    "deploy_manager_backend_local_install_evidence_path",
    "deploy_manager_backend_local_install_execution_id_from_filename",
    "deploy_manager_backend_local_install_execution_path",
    "execute_deploy_manager_backend_local_install",
]
