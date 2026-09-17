"""Operation-bound Manager backend storage preflight execution and evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from enum import Enum, StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.commands import (
    AnsibleCommandBuilder,
    ansible_command_intent_digest,
)
from scylla_vms.ansible.deploy_manager_backend_storage_discovery_execution import (
    _load_execution_context as _load_discovery_execution_context,
)
from scylla_vms.ansible.deploy_manager_backend_storage_preflight_plan import (
    DeployManagerBackendStoragePreflightContextStore,
    DeployManagerBackendStoragePreflightPlanStatus,
    DeployManagerBackendStoragePreflightPlanStore,
    DeployManagerBackendStoragePreflightSourceState,
    StoredDeployManagerBackendStoragePreflightContext,
    StoredDeployManagerBackendStoragePreflightPlan,
    _build_context_record,
    _build_plan_record,
    _load_planning_context,
    _PlanningContext,
)
from scylla_vms.ansible.deploy_plan import (
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.manager_backend_storage_preflight import (
    MANAGER_BACKEND_STORAGE_PREFLIGHT_SCHEMA_VERSION,
    ManagerBackendStoragePreflightDisposition,
    build_manager_backend_storage_preflight_payload,
)
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.readiness import ReadinessReport
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.service import (
    AnsibleExecutionResult,
    AnsibleResultError,
    AnsibleService,
    ProcessRunnerProtocol,
)
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION, validate_ansible_config
from scylla_vms.ansible.toolchain import AnsibleToolchain
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
    digest_bytes,
    format_timestamp,
    parse_timestamp,
    parse_uuid,
    require_exact_keys,
    require_string,
    serialize_json,
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
from scylla_vms.terraform.inputs import StoredTerraformInput

ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-"
    "execution-binding/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-execution/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-evidence/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-storage-preflight-"
    "execution-report/v1"
)

DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-storage-preflight-execution.json"
)
DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-storage-preflight-evidence.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "manager-backend-storage-preflight"
_STEP_SEQUENCE = 1
_TAGS = (_PLAYBOOK,)
_PREPARATION_ACTIONS = (
    "create-xfs",
    "mount-scylla-data-root",
    "write-fstab",
    "write-manager-one-node-marker",
)
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ACTION = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")


class DeployManagerBackendStoragePreflightExecutionState(StrEnum):
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"
    DRIFTED = "drifted"


class DeployManagerBackendStoragePreflightArtifactState(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStoragePreflightExecutionBinding:
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    preflight_context_artifact_digest: str
    preflight_context_record_digest: str
    preflight_plan_artifact_digest: str
    preflight_plan_digest: str
    package_reconciliation_artifact_digest: str
    package_reconciliation_record_digest: str
    allocation_context_artifact_digest: str
    allocation_context_record_digest: str
    allocation_plan_artifact_digest: str
    allocation_plan_digest: str
    discovery_execution_artifact_digest: str
    discovery_execution_binding_digest: str
    discovery_evidence_artifact_digest: str
    discovery_evidence_digest: str
    discovery_reconciliation_artifact_digest: str
    discovery_reconciliation_record_digest: str
    full_chain_digest: str
    metadata_generation: int
    metadata_artifact_digest: str
    desired_spec_digest: str
    terraform_input_generation: int
    terraform_input_artifact_digest: str
    terraform_input_digest: str
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
    storage_policy_digest: str
    desired_policy_digest: str
    manifest_digest: str
    discovery_device_set_digest: str
    discovery_evidence_projection_digest: str
    preparation_intent_digest: str
    variables_digest: str
    command_digest: str
    binding_digest: str
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_BINDING_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
            or self.target_set_digest != _digest_object([self.target_stable_id])
            or self.binding_digest != _binding_digest(self)
        ):
            raise StatePersistenceError(
                "Manager backend storage preflight execution binding conflicts"
            )
        validate_cluster_name(self.cluster_name)
        for value in (
            self.journal_generation,
            self.metadata_generation,
            self.terraform_input_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
        ):
            _positive_integer(value, "Manager backend storage preflight generation")
        for digest_value in _digest_fields(self):
            validate_digest(
                digest_value,
                "Manager backend storage preflight execution binding digest",
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendStoragePreflightExecutionBinding:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend storage preflight execution binding",
        )
        integers = {
            "journal_generation",
            "metadata_generation",
            "terraform_input_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                if name in integers:
                    parsed[name] = _integer(value[name], name)
                elif name in {"cluster_uuid", "operation_id"}:
                    parsed[name] = parse_uuid(require_string(value, name), name)
                elif name == "journal_status":
                    parsed[name] = JournalStatus(require_string(value, name))
                elif name == "journal_phase":
                    parsed[name] = OperationPhase(require_string(value, name))
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend storage preflight binding enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStoragePreflightExecution:
    generation: int
    created_at: str
    updated_at: str
    binding: DeployManagerBackendStoragePreflightExecutionBinding
    state: DeployManagerBackendStoragePreflightExecutionState
    invocation_count: int
    invocation_may_have_occurred: bool
    completed: bool
    exit_code: int | None
    result_digest: str | None
    evidence_digest: str | None
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION
            or self.generation not in {1, 2}
            or self.invocation_count != 1
            or not self.invocation_may_have_occurred
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "Manager backend storage preflight execution conflicts"
            )
        parse_timestamp(self.created_at)
        if parse_timestamp(self.updated_at) < parse_timestamp(self.created_at):
            raise StatePersistenceError(
                "Manager backend storage preflight execution timestamps conflict"
            )
        if self.state is DeployManagerBackendStoragePreflightExecutionState.STARTED:
            valid = (
                self.generation == 1
                and not self.completed
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.manual_recovery_required
            )
        elif self.state is DeployManagerBackendStoragePreflightExecutionState.SUCCEEDED:
            valid = (
                self.generation == 2
                and self.completed
                and self.exit_code == 0
                and self.result_digest is not None
                and self.evidence_digest is not None
                and not self.manual_recovery_required
            )
        else:
            process_failure = self.state in {
                DeployManagerBackendStoragePreflightExecutionState.FAILED,
                DeployManagerBackendStoragePreflightExecutionState.UNREACHABLE,
            }
            valid = (
                self.generation == 2
                and not self.completed
                and self.manual_recovery_required
                and self.result_digest is None
                and self.evidence_digest is None
                and (
                    (process_failure and self.exit_code not in {None, 0})
                    or (not process_failure and self.exit_code is None)
                )
            )
        if not valid:
            raise StatePersistenceError(
                "Manager backend storage preflight execution state conflicts"
            )
        for value in (self.result_digest, self.evidence_digest):
            if value is not None:
                validate_digest(
                    value, "Manager backend storage preflight execution digest"
                )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendStoragePreflightExecution:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend storage preflight execution",
        )
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                updated_at=require_string(value, "updated_at"),
                binding=DeployManagerBackendStoragePreflightExecutionBinding.from_object(
                    _mapping(value["binding"], "binding")
                ),
                state=DeployManagerBackendStoragePreflightExecutionState(
                    require_string(value, "state")
                ),
                invocation_count=_integer(
                    value["invocation_count"], "invocation count"
                ),
                invocation_may_have_occurred=_boolean(
                    value["invocation_may_have_occurred"],
                    "invocation may have occurred",
                ),
                completed=_boolean(value["completed"], "completed"),
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
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend storage preflight execution enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStoragePreflightEvidence:
    generation: int
    created_at: str
    binding: DeployManagerBackendStoragePreflightExecutionBinding
    stable_id: str
    backend: str
    layout: str
    capacity_policy_state: str
    capacity_sufficiency_state: str
    disposition: ManagerBackendStoragePreflightDisposition
    actions: tuple[str, ...]
    wipe_required: bool
    device_count: int
    requested_size_gib: int
    observed_size_gib: int
    device_size_gib: int
    desired_policy_digest: str
    manifest_digest: str
    discovery_digest: str
    device_set_digest: str
    blocker_count: int
    blocker_digest: str
    status_digest: str
    preparation_intent_digest: str
    provenance_digest: str
    result_digest: str
    evidence_digest: str
    result_schema_version: str = MANAGER_BACKEND_STORAGE_PREFLIGHT_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
            or self.result_schema_version
            != MANAGER_BACKEND_STORAGE_PREFLIGHT_SCHEMA_VERSION
            or self.generation != 1
            or self.stable_id != self.binding.target_stable_id
            or self.backend != "block-volume"
            or self.layout != "single"
            or self.capacity_policy_state != "operator-selected-allocation-conformance"
            or self.capacity_sufficiency_state != "not-proven"
            or self.actions != tuple(sorted(set(self.actions)))
            or any(_ACTION.fullmatch(item) is None for item in self.actions)
            or not 0 <= self.device_count <= 1
            or min(
                self.requested_size_gib,
                self.observed_size_gib,
                self.device_size_gib,
            )
            < 0
            or self.blocker_count < 0
            or self.desired_policy_digest != self.binding.desired_policy_digest
            or self.manifest_digest != self.binding.manifest_digest
            or self.discovery_digest
            != self.binding.discovery_evidence_projection_digest
            or self.preparation_intent_digest != self.binding.preparation_intent_digest
            or self.provenance_digest != self.binding.full_chain_digest
            or self.status_digest != _status_digest(self)
            or self.result_digest != _semantic_result_digest(self)
            or self.evidence_digest != _evidence_digest(self)
        ):
            raise StatePersistenceError(
                "Manager backend storage preflight semantic evidence conflicts"
            )
        if self.disposition is ManagerBackendStoragePreflightDisposition.OWNED_NOOP:
            valid = (
                not self.actions
                and not self.wipe_required
                and self.blocker_count == 0
                and self.device_count == 1
            )
        elif (
            self.disposition
            is ManagerBackendStoragePreflightDisposition.PREPARE_REQUIRED
        ):
            valid = (
                self.actions == _PREPARATION_ACTIONS
                and not self.wipe_required
                and self.blocker_count == 0
                and self.device_count == 1
            )
        else:
            valid = not self.actions and self.blocker_count > 0
        if not valid:
            raise StatePersistenceError(
                "Manager backend storage preflight disposition evidence conflicts"
            )
        parse_timestamp(self.created_at)
        for value in _digest_fields(self):
            validate_digest(value, "Manager backend storage preflight evidence digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendStoragePreflightEvidence:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend storage preflight evidence",
        )
        integers = {
            "generation",
            "device_count",
            "requested_size_gib",
            "observed_size_gib",
            "device_size_gib",
            "blocker_count",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in integers:
                    parsed[name] = _integer(item, name)
                elif name == "binding":
                    parsed[name] = (
                        DeployManagerBackendStoragePreflightExecutionBinding.from_object(
                            _mapping(item, name)
                        )
                    )
                elif name == "disposition":
                    parsed[name] = ManagerBackendStoragePreflightDisposition(
                        require_string(value, name)
                    )
                elif name == "actions":
                    parsed[name] = _string_tuple(item, name)
                elif name == "wipe_required":
                    parsed[name] = _boolean(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend storage preflight evidence enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendStoragePreflightExecution:
    record: DeployManagerBackendStoragePreflightExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendStoragePreflightEvidence:
    record: DeployManagerBackendStoragePreflightEvidence
    artifact_digest: str


class DeployManagerBackendStoragePreflightExecutionStore:
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
        self._path = deploy_manager_backend_storage_preflight_execution_path(
            paths, operation_id
        )
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployManagerBackendStoragePreflightExecution:
        value, digest = self._file.read()
        record = DeployManagerBackendStoragePreflightExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "Manager backend storage preflight execution identity conflicts"
            )
        return StoredDeployManagerBackendStoragePreflightExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendStoragePreflightExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendStoragePreflightExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployManagerBackendStoragePreflightExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Manager backend storage preflight execution operation conflicts"
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
                or current.record.state
                is not DeployManagerBackendStoragePreflightExecutionState.STARTED
                or record.generation != 2
                or record.created_at != current.record.created_at
                or record.binding != current.record.binding
            ):
                raise StateConflictError(
                    "Manager backend storage preflight execution transition conflicts"
                )
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
            or record.state
            is not DeployManagerBackendStoragePreflightExecutionState.STARTED
        ):
            raise StateConflictError(
                "Manager backend storage preflight initial execution conflicts"
            )
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployManagerBackendStoragePreflightExecution(record, digest)


class DeployManagerBackendStoragePreflightEvidenceStore:
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
        self._path = deploy_manager_backend_storage_preflight_evidence_path(
            paths, operation_id
        )
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployManagerBackendStoragePreflightEvidence:
        value, digest = self._file.read()
        record = DeployManagerBackendStoragePreflightEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "Manager backend storage preflight evidence identity conflicts"
            )
        return StoredDeployManagerBackendStoragePreflightEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendStoragePreflightEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendStoragePreflightEvidence,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerBackendStoragePreflightEvidence,
        DeployManagerBackendStoragePreflightArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Manager backend storage preflight evidence operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "Manager backend storage preflight evidence is immutable"
                )
            return (
                current,
                DeployManagerBackendStoragePreflightArtifactState.REUSED,
            )
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerBackendStoragePreflightEvidence(record, digest),
            DeployManagerBackendStoragePreflightArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendStoragePreflightExecutionReport:
    operation_id: uuid.UUID
    execution_artifact_state: DeployManagerBackendStoragePreflightArtifactState
    evidence_artifact_state: DeployManagerBackendStoragePreflightArtifactState
    execution_state: DeployManagerBackendStoragePreflightExecutionState
    execution_artifact_digest: str
    evidence_artifact_digest: str
    binding_digest: str
    target_stable_id: str
    target_set_digest: str
    disposition: ManagerBackendStoragePreflightDisposition
    action_count: int
    blocker_count: int
    status_digest: str
    wipe_required: bool
    invocation_count: int
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    capacity_sufficiency_state: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_REPORT_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
            or self.execution_state
            is not DeployManagerBackendStoragePreflightExecutionState.SUCCEEDED
            or self.action_count < 0
            or self.blocker_count < 0
            or self.invocation_count != 1
            or self.manual_recovery_required
            or self.automatic_retry_allowed
            or self.capacity_sufficiency_state != "not-proven"
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError(
                "Manager backend storage preflight execution report conflicts"
            )
        for value in (
            self.execution_artifact_digest,
            self.evidence_artifact_digest,
            self.binding_digest,
            self.target_set_digest,
            self.status_digest,
        ):
            validate_digest(
                value, "Manager backend storage preflight execution report digest"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "artifacts": {
                "evidence_digest": self.evidence_artifact_digest,
                "evidence_state": self.evidence_artifact_state.value,
                "execution_digest": self.execution_artifact_digest,
                "execution_state": self.execution_artifact_state.value,
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
                "action_count": self.action_count,
                "blocker_count": self.blocker_count,
                "capacity_sufficiency_state": self.capacity_sufficiency_state,
                "disposition": self.disposition.value,
                "status_digest": self.status_digest,
                "wipe_required": self.wipe_required,
            },
            "schema_version": self.schema_version,
            "schemas": {
                "evidence": self.evidence_schema_version,
                "execution": self.execution_schema_version,
            },
            "scope": {
                "target_set_digest": self.target_set_digest,
                "target_stable_id": self.target_stable_id,
            },
        }


@dataclass(frozen=True, slots=True)
class _ExecutionScope:
    target_stable_id: str
    variables: Mapping[str, object]
    variables_digest: str
    command_digest: str
    source_digest: str
    payload: dict[str, object]


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    planning: _PlanningContext
    preflight_context: StoredDeployManagerBackendStoragePreflightContext
    preflight_plan: StoredDeployManagerBackendStoragePreflightPlan
    binding: DeployManagerBackendStoragePreflightExecutionBinding
    metadata: ClusterMetadata
    terraform_input: StoredTerraformInput
    observation: StoredObservedState
    inventory: StoredInventoryRecord
    readiness: ReadinessReport
    scope: _ExecutionScope


def execute_deploy_manager_backend_storage_preflight(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployManagerBackendStoragePreflightExecutionReport:
    """Execute the exact read-only Manager backend storage preflight once."""

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
        toolchain_version=str(toolchain.core),
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    execution_store = DeployManagerBackendStoragePreflightExecutionStore(
        paths, operation_id
    )
    evidence_store = DeployManagerBackendStoragePreflightEvidenceStore(
        paths, operation_id
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
    _validate_execution_prefix(context, execution, evidence)
    if execution is not None:
        if (
            execution.record.state
            is DeployManagerBackendStoragePreflightExecutionState.SUCCEEDED
            and evidence is not None
        ):
            return _build_report(
                execution,
                evidence,
                execution_state=DeployManagerBackendStoragePreflightArtifactState.REUSED,
                evidence_state=DeployManagerBackendStoragePreflightArtifactState.REUSED,
            )
        raise StateConflictError(
            "Manager backend storage preflight requires manual recovery "
            "and cannot retry"
        )

    service = AnsibleService(builder, runner)
    if service.version(lock) != toolchain:
        raise StateConflictError(
            "Manager backend storage preflight Ansible toolchain drifted"
        )
    before = _load_execution_context(
        paths,
        operation_id,
        lock=lock,
        builder=builder,
        toolchain_version=str(toolchain.core),
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    if before.binding != context.binding:
        raise StateConflictError(
            "Manager backend storage preflight state drifted before invocation"
        )

    now = _timestamp()
    started = DeployManagerBackendStoragePreflightExecution(
        generation=1,
        created_at=now,
        updated_at=now,
        binding=context.binding,
        state=DeployManagerBackendStoragePreflightExecutionState.STARTED,
        invocation_count=1,
        invocation_may_have_occurred=True,
        completed=False,
        exit_code=None,
        result_digest=None,
        evidence_digest=None,
        manual_recovery_required=True,
        automatic_retry_allowed=False,
    )
    try:
        execution = execution_store.write_locked(
            started,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "Manager backend storage preflight started intent persistence "
            "failed before invocation"
        ) from error

    try:
        result = service.execute_manager_backend_storage_preflight(
            lock,
            context.metadata,
            context.terraform_input,
            context.observation,
            context.inventory,
            context.planning.discovery_reconciliation,
            context.preflight_context,
            context.preflight_plan,
            limit=(context.scope.target_stable_id,),
            readiness=context.readiness,
            check=True,
            verbosity=0,
        )
    except KeyboardInterrupt:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployManagerBackendStoragePreflightExecutionState.INTERRUPTED,
            lock=lock,
        )
        raise AnsibleError(
            "Manager backend storage preflight was interrupted; "
            "manual recovery required"
        ) from None
    except AnsibleError as error:
        _persist_uncertain_or_raise(
            execution_store, execution, _failure_state(error), lock=lock
        )
        raise AnsibleError(
            "Manager backend storage preflight execution is uncertain; "
            "manual recovery required"
        ) from error

    try:
        after = _load_execution_context(
            paths,
            operation_id,
            lock=lock,
            builder=builder,
            toolchain_version=str(toolchain.core),
            executable_identity_digest=executable_identity_digest,
            toolchain_evidence_digest=toolchain_evidence_digest,
        )
        if after.binding != context.binding:
            raise StateConflictError(
                "Manager backend storage preflight state changed after invocation"
            )
    except (StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployManagerBackendStoragePreflightExecutionState.DRIFTED,
            lock=lock,
        )
        raise StateConflictError(
            "Manager backend storage preflight state changed after invocation; "
            "manual recovery required"
        ) from error

    if result.exit_code != 0:
        state = (
            DeployManagerBackendStoragePreflightExecutionState.UNREACHABLE
            if result.exit_code == 4
            else DeployManagerBackendStoragePreflightExecutionState.FAILED
        )
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            state,
            lock=lock,
            exit_code=result.exit_code,
        )
        raise AnsibleError(
            "Manager backend storage preflight failed; manual recovery required"
        )
    try:
        evidence_record = _build_semantic_evidence(context, result)
    except (AnsibleError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployManagerBackendStoragePreflightExecutionState.MALFORMED_RESULT,
            lock=lock,
        )
        raise AnsibleError(
            "Manager backend storage preflight result is malformed; "
            "manual recovery required"
        ) from error
    try:
        evidence, evidence_state = evidence_store.write_locked(
            evidence_record, lock=lock
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "Manager backend storage preflight evidence persistence failed; "
            "manual recovery required"
        ) from error
    terminal = replace(
        execution.record,
        generation=2,
        updated_at=_timestamp(),
        state=DeployManagerBackendStoragePreflightExecutionState.SUCCEEDED,
        completed=True,
        exit_code=0,
        result_digest=evidence.record.result_digest,
        evidence_digest=evidence.record.evidence_digest,
        manual_recovery_required=False,
    )
    try:
        execution = execution_store.write_locked(
            terminal,
            expected_generation=execution.record.generation,
            expected_digest=execution.artifact_digest,
            lock=lock,
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "Manager backend storage preflight terminal persistence failed; "
            "manual recovery required"
        ) from error
    return _build_report(
        execution,
        evidence,
        execution_state=DeployManagerBackendStoragePreflightArtifactState.UPDATED,
        evidence_state=evidence_state,
    )


def deploy_manager_backend_storage_preflight_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}"
        f"{DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "Manager backend storage preflight execution path is not canonical"
        )
    return path


def deploy_manager_backend_storage_preflight_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}"
        f"{DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EVIDENCE_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "Manager backend storage preflight evidence path is not canonical"
        )
    return path


def deploy_manager_backend_storage_preflight_execution_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(
        name, DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_FILENAME_SUFFIX
    )


def deploy_manager_backend_storage_preflight_evidence_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(
        name, DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EVIDENCE_FILENAME_SUFFIX
    )


def _load_execution_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
    builder: AnsibleCommandBuilder | None,
    toolchain_version: str,
    executable_identity_digest: str,
    toolchain_evidence_digest: str,
) -> _ExecutionContext:
    planning = _load_planning_context(paths, operation_id, lock=lock)
    current = planning.current
    metadata = current.metadata
    context_store = DeployManagerBackendStoragePreflightContextStore(
        paths, operation_id
    )
    plan_store = DeployManagerBackendStoragePreflightPlanStore(paths, operation_id)
    for path, label in (
        (context_store.path, "context"),
        (plan_store.path, "plan"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"Manager backend storage preflight execution requires exact {label}"
            )
    preflight_context = context_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    preflight_plan = plan_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_context = _build_context_record(
        planning, created_at=preflight_context.record.created_at
    )
    expected_plan = _build_plan_record(
        preflight_context,
        source=planning.source,
        created_at=preflight_plan.record.created_at,
    )
    if (
        preflight_context.record != expected_context
        or preflight_plan.record != expected_plan
    ):
        raise StateConflictError(
            "Manager backend storage preflight immutable planning drifted"
        )

    discovery = _load_discovery_execution_context(
        paths,
        operation_id,
        lock=lock,
        builder=None,
        toolchain_version=toolchain_version,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    readiness_record = current.readiness.record
    if (
        discovery.metadata.cluster_uuid != metadata.cluster_uuid
        or discovery.metadata.cluster_name != metadata.cluster_name
        or discovery.observation.digest != current.observation.digest
        or discovery.inventory.digest != current.inventory.digest
        or readiness_record.playbook_version != toolchain_version
        or readiness_record.inventory_version != toolchain_version
        or readiness_record.executable_identity_digest != executable_identity_digest
        or readiness_record.toolchain_evidence_digest != toolchain_evidence_digest
        or readiness_record.remote_playbook_status != "not-performed"
        or readiness_record.config_digest != validate_ansible_config(paths)
    ):
        raise StateConflictError(
            "Manager backend storage preflight controller, readiness, "
            "or toolchain conflicts"
        )
    discovery.readiness.require_ready(OperationClassification.READ_ONLY)
    scope = _derive_scope(
        planning,
        preflight_context,
        preflight_plan,
        readiness=discovery.readiness,
        builder=builder,
    )
    context_record = preflight_context.record
    plan_record = preflight_plan.record
    allocation_context = planning.allocation_context
    allocation_plan = planning.allocation_plan
    discovery_record = planning.discovery_reconciliation.record
    package_record = current.package_reconciliation.record
    full_chain_digest = _digest_object(
        {
            "allocation_context_artifact": allocation_context.artifact_digest,
            "allocation_context_record": allocation_context.record.record_digest,
            "allocation_plan_artifact": allocation_plan.artifact_digest,
            "allocation_plan_record": allocation_plan.record.plan_digest,
            "discovery_execution": discovery_record.execution_artifact_digest,
            "discovery_evidence": discovery_record.evidence_artifact_digest,
            "discovery_reconciliation": (
                planning.discovery_reconciliation.artifact_digest
            ),
            "package_reconciliation_artifact": (
                current.package_reconciliation.artifact_digest
            ),
            "package_reconciliation_record": package_record.record_digest,
            "preflight_context_artifact": preflight_context.artifact_digest,
            "preflight_context_record": context_record.record_digest,
            "preflight_plan_artifact": preflight_plan.artifact_digest,
            "preflight_plan_record": plan_record.plan_digest,
        }
    )
    payload_provenance = _mapping(
        scope.payload["provenance"], "Manager backend storage preflight provenance"
    )
    values: dict[str, object] = {
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_name": metadata.cluster_name,
        "operation_id": operation_id,
        "operation": _OPERATION,
        "request_digest": context_record.request_digest,
        "journal_generation": context_record.journal_generation,
        "journal_digest": context_record.journal_digest,
        "journal_status": context_record.journal_status,
        "journal_phase": context_record.journal_phase,
        "preflight_context_artifact_digest": preflight_context.artifact_digest,
        "preflight_context_record_digest": context_record.record_digest,
        "preflight_plan_artifact_digest": preflight_plan.artifact_digest,
        "preflight_plan_digest": plan_record.plan_digest,
        "package_reconciliation_artifact_digest": (
            current.package_reconciliation.artifact_digest
        ),
        "package_reconciliation_record_digest": package_record.record_digest,
        "allocation_context_artifact_digest": allocation_context.artifact_digest,
        "allocation_context_record_digest": allocation_context.record.record_digest,
        "allocation_plan_artifact_digest": allocation_plan.artifact_digest,
        "allocation_plan_digest": allocation_plan.record.plan_digest,
        "discovery_execution_artifact_digest": (
            discovery_record.execution_artifact_digest
        ),
        "discovery_execution_binding_digest": (
            discovery_record.execution_binding_digest
        ),
        "discovery_evidence_artifact_digest": (
            discovery_record.evidence_artifact_digest
        ),
        "discovery_evidence_digest": discovery_record.evidence_digest,
        "discovery_reconciliation_artifact_digest": (
            planning.discovery_reconciliation.artifact_digest
        ),
        "discovery_reconciliation_record_digest": discovery_record.record_digest,
        "full_chain_digest": full_chain_digest,
        "metadata_generation": context_record.metadata_generation,
        "metadata_artifact_digest": context_record.metadata_artifact_digest,
        "desired_spec_digest": context_record.desired_spec_digest,
        "terraform_input_generation": context_record.terraform_input_generation,
        "terraform_input_artifact_digest": (
            context_record.terraform_input_artifact_digest
        ),
        "terraform_input_digest": context_record.terraform_input_digest,
        "observation_generation": context_record.observation_generation,
        "observation_artifact_digest": context_record.observation_artifact_digest,
        "observation_manifest_digest": context_record.observation_manifest_digest,
        "inventory_generation": context_record.inventory_generation,
        "inventory_artifact_digest": context_record.inventory_artifact_digest,
        "inventory_digest": context_record.inventory_digest,
        "trust_generation": context_record.trust_generation,
        "trust_artifact_digest": context_record.trust_artifact_digest,
        "trust_entries_digest": context_record.trust_entries_digest,
        "readiness_artifact_digest": context_record.readiness_artifact_digest,
        "readiness_record_digest": context_record.readiness_record_digest,
        "config_digest": readiness_record.config_digest,
        "known_hosts_digest": readiness_record.known_hosts_digest,
        "ssh_config_digest": readiness_record.ssh_config_digest,
        "catalog_digest": context_record.catalog_digest,
        "source_version": context_record.ansible_source_version,
        "source_digest": context_record.ansible_source_digest,
        "playbook_source_digest": scope.source_digest,
        "toolchain_version": toolchain_version,
        "executable_identity_digest": executable_identity_digest,
        "toolchain_evidence_digest": toolchain_evidence_digest,
        "target_stable_id": scope.target_stable_id,
        "target_set_digest": _digest_object([scope.target_stable_id]),
        "storage_policy_digest": context_record.storage_policy.policy_digest,
        "desired_policy_digest": context_record.storage_policy.desired_policy_digest,
        "manifest_digest": context_record.storage_policy.observed_manifest_digest,
        "discovery_device_set_digest": (
            context_record.storage_policy.device_set_digest
        ),
        "discovery_evidence_projection_digest": _digest_object(
            {
                "device_set_digest": discovery_record.device_set_digest,
                "evidence_digest": discovery_record.evidence_digest,
                "provenance_digest": discovery_record.provenance_digest,
                "record_digest": discovery_record.record_digest,
                "topology_digest": discovery_record.topology_digest,
            }
        ),
        "preparation_intent_digest": (
            context_record.storage_policy.preparation_intent_digest
        ),
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "binding_digest": "",
    }
    if _payload_object_digest(dict(payload_provenance)) != cast(
        str, scope.payload["provenance_digest"]
    ):
        raise StateConflictError(
            "Manager backend storage preflight payload provenance conflicts"
        )
    values["binding_digest"] = _binding_digest_from_values(values)
    return _ExecutionContext(
        planning,
        preflight_context,
        preflight_plan,
        DeployManagerBackendStoragePreflightExecutionBinding(**values),  # type: ignore[arg-type]
        metadata,
        current.terraform_input,
        current.observation,
        current.inventory,
        discovery.readiness,
        scope,
    )


def _derive_scope(
    planning: _PlanningContext,
    context: StoredDeployManagerBackendStoragePreflightContext,
    plan: StoredDeployManagerBackendStoragePreflightPlan,
    *,
    readiness: ReadinessReport,
    builder: AnsibleCommandBuilder | None,
) -> _ExecutionScope:
    current = planning.current
    target = context.record.manager_target_id
    definition = get_playbook(_PLAYBOOK)
    if (
        plan.record.status
        is not DeployManagerBackendStoragePreflightPlanStatus.ELIGIBLE
        or plan.record.source_state
        is not DeployManagerBackendStoragePreflightSourceState.AVAILABLE
        or plan.record.source_digest is None
        or plan.record.manager_target_id != target
        or plan.record.target_count != 1
        or definition.classification is not OperationClassification.READ_ONLY
        or definition.hosts != "manager"
        or definition.serial != 1
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.check_mode is not CheckMode.SUPPORTED
        or not definition.any_errors_fatal
        or not definition.source_available
    ):
        raise StateConflictError(
            "Manager backend storage preflight exact target or source policy conflicts"
        )
    payload = build_manager_backend_storage_preflight_payload(
        current.metadata,
        current.terraform_input,
        current.observation,
        current.inventory,
        readiness,
        planning.discovery_reconciliation,
        context,
        plan,
    )
    variables: dict[str, object] = {
        "deploy_scylla_vms_manager_backend_storage_preflight": payload
    }
    if builder is not None:
        selected, validated, variables_digest, command_digest = (
            builder.validate_operation_step(
                _PLAYBOOK,
                step_sequence=_STEP_SEQUENCE,
                limit=(target,),
                variables=variables,
                tags=_TAGS,
                check=True,
                diff=False,
                verbosity=0,
            )
        )
    else:
        selected = definition
        validated = definition.validate_variables(variables)
        variables_digest = digest_bytes(serialize_json(validated))
        command_digest = ansible_command_intent_digest(
            definition,
            step_sequence=_STEP_SEQUENCE,
            limit=(target,),
            variables_digest=variables_digest,
            tags=_TAGS,
            check=True,
            diff=False,
            verbosity=0,
        )
    source_digest = _playbook_source_digest(planning.source_bundle, _PLAYBOOK)
    source_matches = tuple(
        item.digest
        for item in planning.source_bundle.files
        if item.path == f"playbooks/{definition.filename}"
    )
    if (
        selected != definition
        or len(source_matches) != 1
        or source_digest != source_matches[0]
        or source_digest != plan.record.source_digest
    ):
        raise StateConflictError(
            "Manager backend storage preflight command or source identity conflicts"
        )
    return _ExecutionScope(
        target,
        validated,
        variables_digest,
        command_digest,
        source_digest,
        payload,
    )


def _validate_execution_prefix(
    context: _ExecutionContext,
    execution: StoredDeployManagerBackendStoragePreflightExecution | None,
    evidence: StoredDeployManagerBackendStoragePreflightEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "Manager backend storage preflight evidence exists without execution"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError(
            "Manager backend storage preflight execution provenance is stale"
        )
    if evidence is not None:
        if (
            evidence.record.binding != context.binding
            or execution.record.state
            not in {
                DeployManagerBackendStoragePreflightExecutionState.STARTED,
                DeployManagerBackendStoragePreflightExecutionState.SUCCEEDED,
            }
            or (
                execution.record.result_digest is not None
                and execution.record.result_digest != evidence.record.result_digest
            )
            or (
                execution.record.evidence_digest is not None
                and execution.record.evidence_digest != evidence.record.evidence_digest
            )
        ):
            raise StateConflictError(
                "Manager backend storage preflight semantic evidence conflicts"
            )
    elif (
        execution.record.state
        is DeployManagerBackendStoragePreflightExecutionState.SUCCEEDED
    ):
        raise StateConflictError(
            "Manager backend storage preflight success evidence is missing"
        )


def _build_semantic_evidence(
    context: _ExecutionContext,
    result: AnsibleExecutionResult,
) -> DeployManagerBackendStoragePreflightEvidence:
    parsed = result.manager_backend_storage_preflight
    payload = context.scope.payload
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.READ_ONLY
        or not result.check_mode
        or result.stdout
        or result.stderr
        or result.exit_code != 0
        or parsed is None
        or parsed.stable_id != context.scope.target_stable_id
        or parsed.backend != "block-volume"
        or parsed.layout != "single"
        or parsed.capacity_policy_state != payload["capacity_policy_state"]
        or parsed.capacity_sufficiency_state != "not-proven"
        or parsed.requested_size_gib != payload["requested_size_gib"]
        or parsed.observed_size_gib != payload["observed_size_gib"]
        or parsed.device_set_digest != payload["discovery_device_set_digest"]
        or parsed.preparation_intent_digest != payload["preparation_intent_digest"]
        or parsed.provenance_digest != payload["provenance_digest"]
    ):
        raise AnsibleResultError(
            "Manager backend storage preflight result identity conflicts"
        )
    desired_policy_digest = context.binding.desired_policy_digest
    discovery_digest = context.binding.discovery_evidence_projection_digest
    values: dict[str, object] = {
        "generation": 1,
        "created_at": _timestamp(),
        "binding": context.binding,
        "stable_id": parsed.stable_id,
        "backend": parsed.backend,
        "layout": parsed.layout,
        "capacity_policy_state": parsed.capacity_policy_state,
        "capacity_sufficiency_state": parsed.capacity_sufficiency_state,
        "disposition": parsed.disposition,
        "actions": parsed.actions,
        "wipe_required": parsed.wipe_required,
        "device_count": parsed.device_count,
        "requested_size_gib": parsed.requested_size_gib,
        "observed_size_gib": parsed.observed_size_gib,
        "device_size_gib": parsed.device_size_gib,
        "desired_policy_digest": desired_policy_digest,
        "manifest_digest": context.binding.manifest_digest,
        "discovery_digest": discovery_digest,
        "device_set_digest": parsed.device_set_digest,
        "blocker_count": len(parsed.blockers),
        "blocker_digest": parsed.blocker_digest,
        "status_digest": "",
        "preparation_intent_digest": parsed.preparation_intent_digest,
        "provenance_digest": context.binding.full_chain_digest,
        "result_digest": "",
        "evidence_digest": "",
    }
    values["status_digest"] = _status_digest_from_values(values)
    values["result_digest"] = _semantic_result_digest_from_values(values)
    values["evidence_digest"] = _evidence_digest_from_values(values)
    return DeployManagerBackendStoragePreflightEvidence(**values)  # type: ignore[arg-type]


def _persist_uncertain_or_raise(
    store: DeployManagerBackendStoragePreflightExecutionStore,
    current: StoredDeployManagerBackendStoragePreflightExecution,
    state: DeployManagerBackendStoragePreflightExecutionState,
    *,
    lock: ClusterLock,
    exit_code: int | None = None,
) -> None:
    try:
        record = replace(
            current.record,
            generation=2,
            updated_at=_timestamp(),
            state=state,
            completed=False,
            exit_code=exit_code,
            result_digest=None,
            evidence_digest=None,
            manual_recovery_required=True,
        )
        store.write_locked(
            record,
            expected_generation=current.record.generation,
            expected_digest=current.artifact_digest,
            lock=lock,
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "Manager backend storage preflight uncertain outcome persistence "
            "failed; manual recovery required"
        ) from error


def _failure_state(
    error: AnsibleError,
) -> DeployManagerBackendStoragePreflightExecutionState:
    current: BaseException | None = error
    while current is not None:
        if isinstance(current, ProcessTimeoutError):
            return DeployManagerBackendStoragePreflightExecutionState.TIMED_OUT
        if isinstance(current, ProcessOutputError):
            return DeployManagerBackendStoragePreflightExecutionState.MALFORMED_RESULT
        current = current.__cause__
    return DeployManagerBackendStoragePreflightExecutionState.MALFORMED_RESULT


def _build_report(
    execution: StoredDeployManagerBackendStoragePreflightExecution,
    evidence: StoredDeployManagerBackendStoragePreflightEvidence,
    *,
    execution_state: DeployManagerBackendStoragePreflightArtifactState,
    evidence_state: DeployManagerBackendStoragePreflightArtifactState,
) -> DeployManagerBackendStoragePreflightExecutionReport:
    if (
        execution.record.state
        is not DeployManagerBackendStoragePreflightExecutionState.SUCCEEDED
        or execution.record.result_digest != evidence.record.result_digest
        or execution.record.evidence_digest != evidence.record.evidence_digest
    ):
        raise StateConflictError(
            "Manager backend storage preflight success evidence is incomplete"
        )
    binding = execution.record.binding
    record = evidence.record
    return DeployManagerBackendStoragePreflightExecutionReport(
        operation_id=binding.operation_id,
        execution_artifact_state=execution_state,
        evidence_artifact_state=evidence_state,
        execution_state=execution.record.state,
        execution_artifact_digest=execution.artifact_digest,
        evidence_artifact_digest=evidence.artifact_digest,
        binding_digest=binding.binding_digest,
        target_stable_id=binding.target_stable_id,
        target_set_digest=binding.target_set_digest,
        disposition=record.disposition,
        action_count=len(record.actions),
        blocker_count=record.blocker_count,
        status_digest=record.status_digest,
        wipe_required=record.wipe_required,
        invocation_count=execution.record.invocation_count,
        manual_recovery_required=execution.record.manual_recovery_required,
        automatic_retry_allowed=execution.record.automatic_retry_allowed,
        capacity_sufficiency_state=record.capacity_sufficiency_state,
        journal_status=binding.journal_status,
        journal_phase=binding.journal_phase,
    )


def _binding_digest(
    binding: DeployManagerBackendStoragePreflightExecutionBinding,
) -> str:
    return _binding_digest_from_values(binding.to_object())


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    copied = dict(values)
    for name in (
        "journal_schema_version",
        "readiness_schema_version",
        "schema_version",
    ):
        copied.pop(name, None)
    copied["binding_digest"] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(cast(Mapping[str, object], _jsonable(copied))))


def _status_projection(values: Mapping[str, object]) -> dict[str, object]:
    disposition = values["disposition"]
    return {
        "actions": list(cast(tuple[str, ...], values["actions"])),
        "backend": values["backend"],
        "blocker_count": values["blocker_count"],
        "blocker_digest": values["blocker_digest"],
        "capacity_policy_state": values["capacity_policy_state"],
        "capacity_sufficiency_state": values["capacity_sufficiency_state"],
        "device_count": values["device_count"],
        "device_set_digest": values["device_set_digest"],
        "device_size_gib": values["device_size_gib"],
        "discovery_digest": values["discovery_digest"],
        "disposition": (
            disposition.value
            if isinstance(disposition, ManagerBackendStoragePreflightDisposition)
            else disposition
        ),
        "layout": values["layout"],
        "manifest_digest": values["manifest_digest"],
        "observed_size_gib": values["observed_size_gib"],
        "preparation_intent_digest": values["preparation_intent_digest"],
        "requested_size_gib": values["requested_size_gib"],
        "stable_id": values["stable_id"],
        "wipe_required": values["wipe_required"],
    }


def _status_digest(record: DeployManagerBackendStoragePreflightEvidence) -> str:
    return _status_digest_from_values(record.to_object())


def _payload_object_digest(value: object) -> str:
    data = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _status_digest_from_values(values: Mapping[str, object]) -> str:
    return _digest_object(_status_projection(values))


def _semantic_result_digest(
    record: DeployManagerBackendStoragePreflightEvidence,
) -> str:
    return _semantic_result_digest_from_values(record.to_object())


def _semantic_result_digest_from_values(values: Mapping[str, object]) -> str:
    return _digest_object(
        {
            **_status_projection(values),
            "desired_policy_digest": values["desired_policy_digest"],
            "provenance_digest": values["provenance_digest"],
            "status_digest": values["status_digest"],
        }
    )


def _evidence_digest(
    record: DeployManagerBackendStoragePreflightEvidence,
) -> str:
    return _evidence_digest_from_values(record.to_object())


def _evidence_digest_from_values(values: Mapping[str, object]) -> str:
    copied = dict(values)
    copied.pop("result_schema_version", None)
    copied.pop("schema_version", None)
    copied["evidence_digest"] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(cast(Mapping[str, object], _jsonable(copied))))


_StoredRecord = (
    DeployManagerBackendStoragePreflightExecutionBinding
    | DeployManagerBackendStoragePreflightExecution
    | DeployManagerBackendStoragePreflightEvidence
)


def _dataclass_object(value: _StoredRecord) -> dict[str, object]:
    return cast(dict[str, object], _jsonable(asdict(value)))


def _jsonable(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(
        value,
        (
            DeployManagerBackendStoragePreflightExecutionBinding,
            DeployManagerBackendStoragePreflightExecution,
            DeployManagerBackendStoragePreflightEvidence,
        ),
    ):
        return value.to_object()
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest_fields(value: _StoredRecord) -> tuple[str, ...]:
    return tuple(
        cast(str, field_value)
        for field_name, field_value in asdict(value).items()
        if field_name.endswith("_digest") and field_value is not None
    )


def _timestamp() -> str:
    return format_timestamp(datetime.now(UTC))


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "Manager backend storage preflight paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Manager backend storage preflight requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list Manager backend storage preflight artifacts"
        ) from error
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EVIDENCE_FILENAME_SUFFIX,
    )
    for entry in entries:
        suffix = next(
            (candidate for candidate in suffixes if entry.name.endswith(candidate)),
            None,
        )
        if suffix is None:
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
                "Manager backend storage preflight artifacts are ambiguous"
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


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise StatePersistenceError(f"{label} must be an array of strings")
    return tuple(cast(list[str], value))


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _positive_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be a boolean")
    return value


def _optional_integer(value: object, label: str) -> int | None:
    if value is None:
        return None
    return _integer(value, label)


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise StatePersistenceError(f"{label} must be a string or null")
    return value


__all__ = [
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_BINDING_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION",
    "DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EVIDENCE_FILENAME_SUFFIX",
    "DEPLOY_MANAGER_BACKEND_STORAGE_PREFLIGHT_EXECUTION_FILENAME_SUFFIX",
    "DeployManagerBackendStoragePreflightArtifactState",
    "DeployManagerBackendStoragePreflightEvidence",
    "DeployManagerBackendStoragePreflightEvidenceStore",
    "DeployManagerBackendStoragePreflightExecution",
    "DeployManagerBackendStoragePreflightExecutionBinding",
    "DeployManagerBackendStoragePreflightExecutionReport",
    "DeployManagerBackendStoragePreflightExecutionState",
    "DeployManagerBackendStoragePreflightExecutionStore",
    "StoredDeployManagerBackendStoragePreflightEvidence",
    "StoredDeployManagerBackendStoragePreflightExecution",
    "deploy_manager_backend_storage_preflight_evidence_id_from_filename",
    "deploy_manager_backend_storage_preflight_evidence_path",
    "deploy_manager_backend_storage_preflight_execution_id_from_filename",
    "deploy_manager_backend_storage_preflight_execution_path",
    "execute_deploy_manager_backend_storage_preflight",
]
