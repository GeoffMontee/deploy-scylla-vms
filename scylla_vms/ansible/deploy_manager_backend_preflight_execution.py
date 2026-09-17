"""Operation-bound Manager local-backend preflight execution and evidence."""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from enum import Enum, StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.base_os import (
    BaseOsEvidence,
    BaseOsHostEvidence,
    BaseOsStatus,
)
from scylla_vms.ansible.commands import (
    AnsibleCommandBuilder,
    ansible_command_intent_digest,
    validate_playbook_request_policy,
)
from scylla_vms.ansible.deploy_manager_activation_plan import (
    _load_planning_context as _load_activation_planning_context,
)
from scylla_vms.ansible.deploy_manager_agent_authorization import (
    _AuthorizationContext as _ManagerAgentAuthorizationContext,
)
from scylla_vms.ansible.deploy_manager_backend_configuration_plan import (
    DeployManagerBackendConfigurationContextStore,
    DeployManagerBackendConfigurationPlanStatus,
    DeployManagerBackendConfigurationPlanStore,
    DeployManagerBackendConfigurationSourceState,
    DeployManagerBackendMode,
    StoredDeployManagerBackendConfigurationContext,
    StoredDeployManagerBackendConfigurationPlan,
)
from scylla_vms.ansible.deploy_manager_backend_configuration_plan import (
    _build_context_record as _build_backend_context_record,
)
from scylla_vms.ansible.deploy_manager_backend_configuration_plan import (
    _build_plan_record as _build_backend_plan_record,
)
from scylla_vms.ansible.deploy_manager_backend_configuration_plan import (
    _build_plan_step as _build_backend_plan_step,
)
from scylla_vms.ansible.deploy_manager_backend_configuration_plan import (
    _load_planning_context as _load_backend_planning_context,
)
from scylla_vms.ansible.deploy_monitoring_targets_reconciliation import (
    _load_context as _load_post_targets_context,
)
from scylla_vms.ansible.deploy_plan import (
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_reconciliation import (
    _ReconciliationContext as _DeployReconciliationContext,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import _loaded
from scylla_vms.ansible.manager_backend_preflight import (
    MANAGER_BACKEND_MODE,
    MANAGER_BACKEND_NOT_PERFORMED,
    MANAGER_BACKEND_PREFLIGHT_SCHEMA_VERSION,
    MANAGER_BACKEND_SCYLLA_RELEASE,
    MANAGER_BACKEND_UNRESOLVED_BLOCKERS,
    ManagerBackendLoopbackStatus,
    ManagerBackendPackageStatus,
    ManagerBackendPreflightStatus,
    ManagerBackendServiceStatus,
    build_manager_backend_preflight_payload,
)
from scylla_vms.ansible.manager_server import (
    MANAGER_PACKAGE_VERSION,
    MANAGER_PACKAGES,
    MANAGER_RELEASE_LINE,
    MANAGER_REPOSITORY_DEFINITION_DIGEST,
    ManagerServerEvidence,
    ManagerServerStatus,
    build_manager_server_payload,
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
from scylla_vms.ansible.source import validate_ansible_config
from scylla_vms.ansible.toolchain import AnsibleToolchain
from scylla_vms.ansible.trust import TrustStore
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
    _reconstructed_readiness,
    _toolchain_evidence_digest,
    _validate_toolchain_dependency,
)

ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-preflight-execution-binding/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-preflight-execution/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-preflight-evidence/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-preflight-execution-report/v1"
)

DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-preflight-execution.json"
)
DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-preflight-evidence.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "manager-backend-preflight"
_STEP_SEQUENCE = 1
_TAGS = (_PLAYBOOK,)
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_OBSERVED_BLOCKERS = frozenset(
    {
        "approved-mount-unavailable",
        "architecture-mismatch",
        "capacity-evidence-unavailable",
        "local-scylla-package-present",
        "local-scylla-service-state-unsafe",
        "loopback-unavailable",
        "manager-package-mismatch",
        "manager-service-state-unsafe",
        "operating-system-mismatch",
        "reboot-required",
    }
)


class DeployManagerBackendPreflightExecutionState(StrEnum):
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"
    DRIFTED = "drifted"


class DeployManagerBackendPreflightArtifactState(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployManagerBackendPreflightExecutionBinding:
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    backend_context_artifact_digest: str
    backend_context_record_digest: str
    backend_plan_artifact_digest: str
    backend_plan_digest: str
    activation_context_artifact_digest: str
    activation_context_record_digest: str
    activation_plan_artifact_digest: str
    activation_plan_digest: str
    post_targets_artifact_digest: str
    post_targets_record_digest: str
    post_bootstrap_artifact_digest: str
    post_bootstrap_record_digest: str
    final_health_evidence_digest: str
    final_health_reconciliation_digest: str
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
    manager_server_evidence_artifact_digest: str
    manager_server_evidence_digest: str
    manager_server_provenance_digest: str
    manager_agent_evidence_artifact_digest: str
    manager_agent_evidence_set_digest: str
    manager_agent_provenance_set_digest: str
    base_os_evidence_artifact_digest: str
    base_os_evidence_digest: str
    toolchain_version: str
    executable_identity_digest: str
    toolchain_evidence_digest: str
    target_stable_id: str
    target_set_digest: str
    backend_policy_digest: str
    variables_digest: str
    command_digest: str
    binding_digest: str
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_BINDING_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_BINDING_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
            or self.target_set_digest != _digest_object([self.target_stable_id])
            or self.binding_digest != _binding_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Manager backend preflight execution binding conflicts"
            )
        validate_cluster_name(self.cluster_name)
        for count in (
            self.journal_generation,
            self.metadata_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
        ):
            _positive_integer(count, "Manager backend preflight binding count")
        for value in _digest_fields(self):
            validate_digest(value, "Manager backend preflight binding digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendPreflightExecutionBinding:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend preflight execution binding",
        )
        integers = {
            "journal_generation",
            "metadata_generation",
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
                "deploy Manager backend preflight binding enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployManagerBackendPreflightExecution:
    generation: int
    created_at: str
    updated_at: str
    binding: DeployManagerBackendPreflightExecutionBinding
    state: DeployManagerBackendPreflightExecutionState
    invocation_count: int
    invocation_may_have_occurred: bool
    completed: bool
    exit_code: int | None
    result_digest: str | None
    evidence_digest: str | None
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION
            or self.generation not in {1, 2}
            or self.invocation_count != 1
            or not self.invocation_may_have_occurred
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy Manager backend preflight execution conflicts"
            )
        parse_timestamp(self.created_at)
        if parse_timestamp(self.updated_at) < parse_timestamp(self.created_at):
            raise StatePersistenceError(
                "deploy Manager backend preflight execution timestamps conflict"
            )
        if self.state is DeployManagerBackendPreflightExecutionState.STARTED:
            if (
                self.generation != 1
                or self.completed
                or self.exit_code is not None
                or self.result_digest is not None
                or self.evidence_digest is not None
                or not self.manual_recovery_required
            ):
                raise StatePersistenceError(
                    "deploy Manager backend preflight started state conflicts"
                )
        elif self.state is DeployManagerBackendPreflightExecutionState.SUCCEEDED:
            if (
                self.generation != 2
                or not self.completed
                or self.exit_code != 0
                or self.result_digest is None
                or self.evidence_digest is None
                or self.manual_recovery_required
            ):
                raise StatePersistenceError(
                    "deploy Manager backend preflight success state conflicts"
                )
        elif (
            self.generation != 2
            or self.completed
            or not self.manual_recovery_required
            or self.result_digest is not None
            or self.evidence_digest is not None
            or (
                self.state
                in {
                    DeployManagerBackendPreflightExecutionState.FAILED,
                    DeployManagerBackendPreflightExecutionState.UNREACHABLE,
                }
                and (self.exit_code is None or self.exit_code == 0)
            )
            or (
                self.state
                not in {
                    DeployManagerBackendPreflightExecutionState.FAILED,
                    DeployManagerBackendPreflightExecutionState.UNREACHABLE,
                }
                and self.exit_code is not None
            )
        ):
            raise StatePersistenceError(
                "deploy Manager backend preflight uncertain state conflicts"
            )
        for digest in (self.result_digest, self.evidence_digest):
            if digest is not None:
                validate_digest(digest, "Manager backend preflight execution digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendPreflightExecution:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend preflight execution",
        )
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                updated_at=require_string(value, "updated_at"),
                binding=DeployManagerBackendPreflightExecutionBinding.from_object(
                    _mapping(value["binding"], "binding")
                ),
                state=DeployManagerBackendPreflightExecutionState(
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
                "deploy Manager backend preflight execution state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerBackendPreflightEvidence:
    generation: int
    created_at: str
    binding: DeployManagerBackendPreflightExecutionBinding
    stable_id: str
    role: str
    status: ManagerBackendPreflightStatus
    backend_mode: str
    scylla_release: str
    operating_system: str
    operating_system_version: str
    architecture: str
    cpu_count: int
    memory_bytes: int
    root_total_bytes: int
    root_free_bytes: int
    approved_mount_count: int
    available_mount_count: int
    approved_mount_status: str
    manager_package_status: ManagerBackendPackageStatus
    local_scylla_package_status: ManagerBackendPackageStatus
    package_availability_status: str
    manager_service_status: ManagerBackendServiceStatus
    local_scylla_service_status: ManagerBackendServiceStatus
    reboot_required: bool
    loopback_policy_status: ManagerBackendLoopbackStatus
    configuration_status: str
    schema_status: str
    operational_readiness: str
    not_performed: tuple[str, ...]
    blockers: tuple[str, ...]
    provenance_digest: str
    result_digest: str
    evidence_digest: str
    result_schema_version: str = MANAGER_BACKEND_PREFLIGHT_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        observed_blockers = set(self.blockers) - set(
            MANAGER_BACKEND_UNRESOLVED_BLOCKERS
        )
        host_ready = (
            self.manager_package_status is ManagerBackendPackageStatus.INSTALLED
            and self.local_scylla_package_status
            is ManagerBackendPackageStatus.NOT_INSTALLED
            and self.manager_service_status
            is ManagerBackendServiceStatus.MASKED_INACTIVE
            and self.local_scylla_service_status is ManagerBackendServiceStatus.ABSENT
            and not self.reboot_required
            and self.loopback_policy_status is ManagerBackendLoopbackStatus.AVAILABLE
            and self.approved_mount_status == "available"
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
            or self.result_schema_version != MANAGER_BACKEND_PREFLIGHT_SCHEMA_VERSION
            or self.generation != 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.stable_id != self.binding.target_stable_id
            or self.role != HostRole.MANAGER.value
            or self.status
            not in {
                ManagerBackendPreflightStatus.EVIDENCE_READY,
                ManagerBackendPreflightStatus.BLOCKED,
            }
            or self.backend_mode != MANAGER_BACKEND_MODE
            or self.scylla_release != MANAGER_BACKEND_SCYLLA_RELEASE
            or self.operating_system != "Ubuntu"
            or self.operating_system_version != "24.04"
            or self.architecture not in {"amd64", "aarch64"}
            or not 1 <= self.cpu_count <= 4096
            or not 0 <= self.memory_bytes <= 2**63 - 1
            or not 0 <= self.root_total_bytes <= 2**63 - 1
            or not 0 <= self.root_free_bytes <= self.root_total_bytes
            or not 0 <= self.approved_mount_count <= 32
            or not 0 <= self.available_mount_count <= self.approved_mount_count
            or self.memory_bytes == 0
            or self.root_total_bytes == 0
            or self.approved_mount_status
            != (
                "available"
                if self.approved_mount_count == self.available_mount_count == 1
                else "unavailable"
            )
            or self.package_availability_status != "not-performed"
            or self.configuration_status != "not-inspected"
            or self.schema_status != "not-inspected"
            or self.operational_readiness != "not-performed"
            or self.not_performed != MANAGER_BACKEND_NOT_PERFORMED
            or not set(MANAGER_BACKEND_UNRESOLVED_BLOCKERS).issubset(self.blockers)
            or not set(self.blockers)
            <= set(MANAGER_BACKEND_UNRESOLVED_BLOCKERS) | _OBSERVED_BLOCKERS
            or len(self.blockers)
            > (len(MANAGER_BACKEND_UNRESOLVED_BLOCKERS) + len(_OBSERVED_BLOCKERS))
            or self.blockers != tuple(sorted(set(self.blockers)))
            or (
                self.status is ManagerBackendPreflightStatus.EVIDENCE_READY
                and (not host_ready or observed_blockers)
            )
            or (
                self.status is ManagerBackendPreflightStatus.BLOCKED
                and (host_ready or not observed_blockers)
            )
            or self.result_digest != _semantic_result_digest(self)
            or self.evidence_digest != _evidence_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Manager backend preflight semantic evidence conflicts"
            )
        parse_timestamp(self.created_at)
        for value in (
            self.provenance_digest,
            self.result_digest,
            self.evidence_digest,
        ):
            validate_digest(value, "Manager backend preflight evidence digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendPreflightEvidence:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend preflight evidence",
        )
        integers = {
            "generation",
            "cpu_count",
            "memory_bytes",
            "root_total_bytes",
            "root_free_bytes",
            "approved_mount_count",
            "available_mount_count",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in integers:
                    parsed[name] = _integer(item, name)
                elif name == "binding":
                    parsed[name] = (
                        DeployManagerBackendPreflightExecutionBinding.from_object(
                            _mapping(item, name)
                        )
                    )
                elif name == "status":
                    parsed[name] = ManagerBackendPreflightStatus(
                        require_string(value, name)
                    )
                elif name in {
                    "manager_package_status",
                    "local_scylla_package_status",
                }:
                    parsed[name] = ManagerBackendPackageStatus(
                        require_string(value, name)
                    )
                elif name in {
                    "manager_service_status",
                    "local_scylla_service_status",
                }:
                    parsed[name] = ManagerBackendServiceStatus(
                        require_string(value, name)
                    )
                elif name == "loopback_policy_status":
                    parsed[name] = ManagerBackendLoopbackStatus(
                        require_string(value, name)
                    )
                elif name == "reboot_required":
                    parsed[name] = _boolean(item, name)
                elif name in {"not_performed", "blockers"}:
                    parsed[name] = _string_tuple(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Manager backend preflight evidence enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendPreflightExecution:
    record: DeployManagerBackendPreflightExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendPreflightEvidence:
    record: DeployManagerBackendPreflightEvidence
    artifact_digest: str


class DeployManagerBackendPreflightExecutionStore:
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
        self._path = deploy_manager_backend_preflight_execution_path(
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
    ) -> StoredDeployManagerBackendPreflightExecution:
        value, digest = self._file.read()
        record = DeployManagerBackendPreflightExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy Manager backend preflight execution identity conflicts"
            )
        return StoredDeployManagerBackendPreflightExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendPreflightExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendPreflightExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployManagerBackendPreflightExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy Manager backend preflight execution operation conflicts"
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
                is not DeployManagerBackendPreflightExecutionState.STARTED
                or record.generation != 2
                or record.created_at != current.record.created_at
                or record.binding != current.record.binding
            ):
                raise StateConflictError(
                    "deploy Manager backend preflight execution transition conflicts"
                )
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
            or record.state is not DeployManagerBackendPreflightExecutionState.STARTED
        ):
            raise StateConflictError(
                "deploy Manager backend preflight initial execution conflicts"
            )
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployManagerBackendPreflightExecution(record, digest)


class DeployManagerBackendPreflightEvidenceStore:
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
        self._path = deploy_manager_backend_preflight_evidence_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployManagerBackendPreflightEvidence:
        value, digest = self._file.read()
        record = DeployManagerBackendPreflightEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy Manager backend preflight evidence identity conflicts"
            )
        return StoredDeployManagerBackendPreflightEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendPreflightEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendPreflightEvidence,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerBackendPreflightEvidence,
        DeployManagerBackendPreflightArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy Manager backend preflight evidence operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.binding.cluster_uuid,
                expected_cluster_name=record.binding.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy Manager backend preflight evidence is immutable"
                )
            return current, DeployManagerBackendPreflightArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerBackendPreflightEvidence(record, digest),
            DeployManagerBackendPreflightArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendPreflightExecutionReport:
    operation_id: uuid.UUID
    execution_artifact_state: DeployManagerBackendPreflightArtifactState
    evidence_artifact_state: DeployManagerBackendPreflightArtifactState
    execution_state: DeployManagerBackendPreflightExecutionState
    execution_artifact_digest: str
    evidence_artifact_digest: str
    binding_digest: str
    target_stable_id: str
    target_set_digest: str
    semantic_status: ManagerBackendPreflightStatus
    blocker_count: int
    blocker_digest: str
    invocation_count: int
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    journal_status: JournalStatus
    journal_phase: OperationPhase
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_REPORT_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
            or self.execution_state
            is not DeployManagerBackendPreflightExecutionState.SUCCEEDED
            or self.semantic_status is ManagerBackendPreflightStatus.FAILED
            or self.invocation_count != 1
            or self.blocker_count < len(MANAGER_BACKEND_UNRESOLVED_BLOCKERS)
            or self.manual_recovery_required
            or self.automatic_retry_allowed
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError(
                "deploy Manager backend preflight execution report conflicts"
            )
        for digest in (
            self.execution_artifact_digest,
            self.evidence_artifact_digest,
            self.binding_digest,
            self.target_set_digest,
            self.blocker_digest,
        ):
            validate_digest(digest, "Manager backend preflight report digest")

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
                "blocker_count": self.blocker_count,
                "blocker_digest": self.blocker_digest,
                "status": self.semantic_status.value,
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
    backend_policy_digest: str
    image_filter: ImageFilter
    architecture: str
    base_os: BaseOsEvidence
    manager_server: ManagerServerEvidence


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    backend_context: StoredDeployManagerBackendConfigurationContext
    backend_plan: StoredDeployManagerBackendConfigurationPlan
    binding: DeployManagerBackendPreflightExecutionBinding
    metadata: ClusterMetadata
    observation: StoredObservedState
    inventory: StoredInventoryRecord
    readiness: ReadinessReport
    scope: _ExecutionScope


def execute_deploy_manager_backend_preflight(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployManagerBackendPreflightExecutionReport:
    """Execute the exact read-only Manager backend preflight once."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _validate_toolchain_dependency(toolchain)
    executable_identity_digest = _executable_identity_digest(executables)
    toolchain_evidence_digest = _toolchain_evidence_digest(
        toolchain, executable_identity_digest
    )
    _refuse_ambiguous_artifacts(paths, operation_id)
    context = _load_execution_context(
        paths,
        operation_id,
        lock=lock,
        toolchain_version=str(toolchain.core),
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    execution_store = DeployManagerBackendPreflightExecutionStore(paths, operation_id)
    evidence_store = DeployManagerBackendPreflightEvidenceStore(paths, operation_id)
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
    _validate_execution_prefix(context, execution, evidence)
    if execution is not None:
        if (
            execution.record.state
            is DeployManagerBackendPreflightExecutionState.SUCCEEDED
            and evidence is not None
        ):
            return _build_report(
                execution,
                evidence,
                execution_state=DeployManagerBackendPreflightArtifactState.REUSED,
                evidence_state=DeployManagerBackendPreflightArtifactState.REUSED,
            )
        raise StateConflictError(
            "deploy Manager backend preflight requires manual recovery and cannot retry"
        )

    builder = AnsibleCommandBuilder(executables.playbook, executables.inventory, paths)
    definition, _validated, variables_digest, command_digest = (
        builder.validate_operation_step(
            _PLAYBOOK,
            step_sequence=_STEP_SEQUENCE,
            limit=(context.scope.target_stable_id,),
            variables=dict(context.scope.variables),
            tags=_TAGS,
            check=True,
            diff=False,
            verbosity=0,
        )
    )
    if (
        definition != get_playbook(_PLAYBOOK)
        or variables_digest != context.scope.variables_digest
        or command_digest != context.scope.command_digest
    ):
        raise StateConflictError(
            "deploy Manager backend preflight command identity conflicts"
        )
    service = AnsibleService(builder, runner)
    if service.version(lock) != toolchain:
        raise StateConflictError(
            "deploy Manager backend preflight Ansible toolchain drifted"
        )
    before = _load_execution_context(
        paths,
        operation_id,
        lock=lock,
        toolchain_version=str(toolchain.core),
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    if before.binding != context.binding:
        raise StateConflictError(
            "deploy Manager backend preflight state drifted before invocation"
        )

    now = _timestamp()
    started = DeployManagerBackendPreflightExecution(
        generation=1,
        created_at=now,
        updated_at=now,
        binding=context.binding,
        state=DeployManagerBackendPreflightExecutionState.STARTED,
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
            started, expected_generation=0, expected_digest=None, lock=lock
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy Manager backend preflight started intent persistence failed "
            "before invocation"
        ) from error

    try:
        result = service.execute_manager_backend_preflight(
            lock,
            context.metadata,
            context.observation,
            context.inventory,
            context.scope.base_os,
            context.scope.manager_server,
            context.backend_context,
            context.backend_plan,
            limit=(context.scope.target_stable_id,),
            readiness=context.readiness,
            image_filter=context.scope.image_filter,
            architecture=context.scope.architecture,
            check=True,
            verbosity=0,
        )
    except KeyboardInterrupt:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployManagerBackendPreflightExecutionState.INTERRUPTED,
            lock=lock,
        )
        raise AnsibleError(
            "deploy Manager backend preflight was interrupted; manual recovery required"
        ) from None
    except AnsibleError as error:
        _persist_uncertain_or_raise(
            execution_store, execution, _failure_state(error), lock=lock
        )
        raise AnsibleError(
            "deploy Manager backend preflight execution is uncertain; "
            "manual recovery required"
        ) from error

    try:
        after = _load_execution_context(
            paths,
            operation_id,
            lock=lock,
            toolchain_version=str(toolchain.core),
            executable_identity_digest=executable_identity_digest,
            toolchain_evidence_digest=toolchain_evidence_digest,
        )
        if after.binding != context.binding:
            raise StateConflictError(
                "deploy Manager backend preflight state changed after invocation"
            )
    except (StateConflictError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployManagerBackendPreflightExecutionState.DRIFTED,
            lock=lock,
        )
        raise StateConflictError(
            "deploy Manager backend preflight state changed after invocation; "
            "manual recovery required"
        ) from error

    if result.exit_code != 0:
        state = (
            DeployManagerBackendPreflightExecutionState.UNREACHABLE
            if result.exit_code == 4
            else DeployManagerBackendPreflightExecutionState.FAILED
        )
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            state,
            lock=lock,
            exit_code=result.exit_code,
        )
        raise AnsibleError(
            "deploy Manager backend preflight failed; manual recovery required"
        )
    try:
        evidence_record = _build_semantic_evidence(context, result)
    except (AnsibleError, StatePersistenceError) as error:
        _persist_uncertain_or_raise(
            execution_store,
            execution,
            DeployManagerBackendPreflightExecutionState.MALFORMED_RESULT,
            lock=lock,
        )
        raise AnsibleError(
            "deploy Manager backend preflight result is malformed; "
            "manual recovery required"
        ) from error
    try:
        evidence, evidence_state = evidence_store.write_locked(
            evidence_record, lock=lock
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy Manager backend preflight evidence persistence failed; "
            "manual recovery required"
        ) from error
    terminal = replace(
        execution.record,
        generation=2,
        updated_at=_timestamp(),
        state=DeployManagerBackendPreflightExecutionState.SUCCEEDED,
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
            "deploy Manager backend preflight terminal persistence failed; "
            "manual recovery required"
        ) from error
    return _build_report(
        execution,
        evidence,
        execution_state=DeployManagerBackendPreflightArtifactState.UPDATED,
        evidence_state=evidence_state,
    )


def deploy_manager_backend_preflight_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Manager backend preflight execution path is not canonical"
        )
    return path


def deploy_manager_backend_preflight_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Manager backend preflight evidence path is not canonical"
        )
    return path


def deploy_manager_backend_preflight_execution_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(
        name, DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_FILENAME_SUFFIX
    )


def deploy_manager_backend_preflight_evidence_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(
        name, DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_FILENAME_SUFFIX
    )


def _load_execution_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
    toolchain_version: str,
    executable_identity_digest: str,
    toolchain_evidence_digest: str,
) -> _ExecutionContext:
    planning = _load_backend_planning_context(paths, operation_id, lock=lock)
    metadata = planning.activation.record
    context_store = DeployManagerBackendConfigurationContextStore(paths, operation_id)
    plan_store = DeployManagerBackendConfigurationPlanStore(paths, operation_id)
    for path, label in (
        (context_store.path, "context"),
        (plan_store.path, "plan"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"deploy Manager backend preflight requires the exact backend {label}"
            )
    backend_context = context_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_context = _build_backend_context_record(
        planning, created_at=backend_context.record.created_at
    )
    if backend_context.record != expected_context:
        raise StateConflictError(
            "deploy Manager backend preflight backend context drifted"
        )
    backend_plan = plan_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_plan = _build_backend_plan_record(
        backend_context,
        step=_build_backend_plan_step(backend_context.record),
        created_at=backend_plan.record.created_at,
    )
    if backend_plan.record != expected_plan:
        raise StateConflictError(
            "deploy Manager backend preflight backend plan drifted"
        )

    activation = _load_activation_planning_context(paths, operation_id, lock=lock)
    post_targets = _load_post_targets_context(paths, operation_id, lock=lock)
    authorization_context = post_targets.authorization_context
    agent_context = authorization_context.agent.authorization_context
    manager_agent_context = agent_context.manager.authorization_context
    loaded = _loaded(
        manager_agent_context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    deploy = loaded.planning.base.deploy
    cluster_metadata = deploy.metadata.record
    readiness_record = loaded.planning.readiness.record
    if (
        cluster_metadata.cluster_uuid != metadata.cluster_uuid
        or cluster_metadata.cluster_name != metadata.cluster_name
        or backend_context.record.activation_context_artifact_digest
        != planning.activation.artifact_digest
        or backend_context.record.post_targets_artifact_digest
        != activation.post_targets.artifact_digest
        or readiness_record.playbook_version != toolchain_version
        or readiness_record.inventory_version != toolchain_version
        or readiness_record.executable_identity_digest != executable_identity_digest
        or readiness_record.toolchain_evidence_digest != toolchain_evidence_digest
        or readiness_record.remote_playbook_status != "not-performed"
        or readiness_record.config_digest != validate_ansible_config(paths)
    ):
        raise StateConflictError(
            "deploy Manager backend preflight canonical chain or toolchain conflicts"
        )
    readiness = _reconstructed_readiness(loaded.planning.base)
    if readiness_binding_digest(readiness) != readiness_record.readiness_digest:
        raise StateConflictError("deploy Manager backend preflight readiness is stale")
    readiness.require_ready(OperationClassification.READ_ONLY)
    TrustStore(paths).validate_runtime(loaded.planning.base.trust, deploy.inventory)
    scope = _derive_scope(
        backend_context,
        backend_plan,
        loaded=loaded,
        manager_agent_context=manager_agent_context,
        readiness=readiness,
    )
    record = backend_context.record
    journal = deploy.journal
    values: dict[str, object] = {
        "cluster_uuid": cluster_metadata.cluster_uuid,
        "cluster_name": cluster_metadata.cluster_name,
        "operation_id": operation_id,
        "operation": _OPERATION,
        "request_digest": journal.record.request_digest,
        "journal_generation": journal.record.generation,
        "journal_digest": journal.digest,
        "journal_status": journal.record.status,
        "journal_phase": journal.record.phase,
        "backend_context_artifact_digest": backend_context.artifact_digest,
        "backend_context_record_digest": record.record_digest,
        "backend_plan_artifact_digest": backend_plan.artifact_digest,
        "backend_plan_digest": backend_plan.record.plan_digest,
        "activation_context_artifact_digest": record.activation_context_artifact_digest,
        "activation_context_record_digest": record.activation_context_record_digest,
        "activation_plan_artifact_digest": record.activation_plan_artifact_digest,
        "activation_plan_digest": record.activation_plan_digest,
        "post_targets_artifact_digest": record.post_targets_artifact_digest,
        "post_targets_record_digest": record.post_targets_record_digest,
        "post_bootstrap_artifact_digest": record.post_bootstrap_artifact_digest,
        "post_bootstrap_record_digest": record.post_bootstrap_record_digest,
        "final_health_evidence_digest": record.final_health_evidence_digest,
        "final_health_reconciliation_digest": (
            record.final_health_reconciliation_digest
        ),
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
        "config_digest": readiness_record.config_digest,
        "known_hosts_digest": readiness_record.known_hosts_digest,
        "ssh_config_digest": readiness_record.ssh_config_digest,
        "catalog_digest": record.catalog_digest,
        "source_version": record.ansible_source_version,
        "source_digest": record.ansible_source_digest,
        "playbook_source_digest": scope.source_digest,
        "manager_server_evidence_artifact_digest": (
            record.manager_server_evidence_artifact_digest
        ),
        "manager_server_evidence_digest": record.manager_server_evidence_digest,
        "manager_server_provenance_digest": (record.manager_server_provenance_digest),
        "manager_agent_evidence_artifact_digest": (
            record.manager_agent_evidence_artifact_digest
        ),
        "manager_agent_evidence_set_digest": (record.manager_agent_evidence_set_digest),
        "manager_agent_provenance_set_digest": (
            record.manager_agent_provenance_set_digest
        ),
        "base_os_evidence_artifact_digest": (
            manager_agent_context.monitoring.monitoring.manager.manager.base_os.artifact_digest
        ),
        "base_os_evidence_digest": _base_os_evidence_digest(
            manager_agent_context, scope.target_stable_id
        ),
        "toolchain_version": toolchain_version,
        "executable_identity_digest": executable_identity_digest,
        "toolchain_evidence_digest": toolchain_evidence_digest,
        "target_stable_id": scope.target_stable_id,
        "target_set_digest": _digest_object([scope.target_stable_id]),
        "backend_policy_digest": scope.backend_policy_digest,
        "variables_digest": scope.variables_digest,
        "command_digest": scope.command_digest,
        "binding_digest": "",
    }
    values["binding_digest"] = _binding_digest_from_values(values)
    binding = DeployManagerBackendPreflightExecutionBinding(**values)  # type: ignore[arg-type]
    return _ExecutionContext(
        backend_context,
        backend_plan,
        binding,
        cluster_metadata,
        deploy.observation,
        deploy.inventory,
        readiness,
        scope,
    )


def _derive_scope(
    backend_context: StoredDeployManagerBackendConfigurationContext,
    backend_plan: StoredDeployManagerBackendConfigurationPlan,
    *,
    loaded: _DeployReconciliationContext,
    manager_agent_context: _ManagerAgentAuthorizationContext,
    readiness: ReadinessReport,
) -> _ExecutionScope:
    planning = loaded.planning
    deploy = planning.base.deploy
    source = loaded.source
    base_os_store = manager_agent_context.monitoring.monitoring.manager.manager.base_os
    server_evidence = manager_agent_context.monitoring.monitoring.manager.evidence
    target = backend_context.record.manager_target_id
    matches = tuple(
        (entry, host)
        for entry in base_os_store.record.entries
        for host in entry.hosts
        if host.logical_id == target
    )
    definition = get_playbook(_PLAYBOOK)
    plan_steps = backend_plan.record.steps
    image_filter = dict(deploy.metadata.record.desired_spec.image_filters).get(
        HostRole.MANAGER
    )
    if (
        len(matches) != 1
        or len(server_evidence.record.entries) != 1
        or len(plan_steps) != 1
        or backend_context.record.status
        is not DeployManagerBackendConfigurationPlanStatus.BLOCKED
        or plan_steps[0].source_state
        is not DeployManagerBackendConfigurationSourceState.UNAVAILABLE
        or backend_context.record.intent.backend_mode_value
        is not DeployManagerBackendMode.LOCAL_ONE_NODE
        or image_filter != ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT)
        or definition.classification is not OperationClassification.READ_ONLY
        or definition.hosts != HostRole.MANAGER.value
        or definition.serial != 1
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.check_mode is not CheckMode.SUPPORTED
        or not definition.any_errors_fatal
        or not definition.source_available
    ):
        raise StateConflictError(
            "deploy Manager backend preflight canonical target or catalog policy conflicts"
        )
    _base_entry, base_host = matches[0]
    if (
        base_host.os_family != "Ubuntu"
        or base_host.os_version != "24.04"
        or base_host.image_architecture not in {"amd64", "aarch64"}
        or base_host.status not in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
        or not base_host.applied
        or base_host.reboot_required
    ):
        raise StateConflictError(
            "deploy Manager backend preflight base-OS evidence conflicts"
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
    manager_entry = server_evidence.record.entries[0]
    server_payload = build_manager_server_payload(
        deploy.metadata.record,
        deploy.observation,
        deploy.inventory,
        readiness,
        base_os,
        logical_id=target,
        image_filter=image_filter,
        architecture=base_host.image_architecture,
        package_version=MANAGER_PACKAGE_VERSION,
        cluster_spec_digest=deploy.metadata.record.desired_spec.digest(),
    )
    provenance = tuple(
        sorted(
            (
                str(name),
                str(value),
            )
            for name, value in _mapping(
                server_payload["provenance"], "Manager server provenance"
            ).items()
        )
    )
    manager_server = ManagerServerEvidence(
        logical_id=target,
        status=manager_entry.status,
        requested_release=MANAGER_RELEASE_LINE,
        requested_version=MANAGER_PACKAGE_VERSION,
        installed_version=MANAGER_PACKAGE_VERSION,
        packages=tuple((name, MANAGER_PACKAGE_VERSION) for name in MANAGER_PACKAGES),
        repository_digest=MANAGER_REPOSITORY_DEFINITION_DIGEST,
        signing_key_fingerprint=SCYLLA_SIGNING_KEY_FINGERPRINT,
        signing_key_digest=SCYLLA_SIGNING_KEY_DIGEST,
        service_masked=manager_entry.service_masked,
        service_inactive=manager_entry.service_inactive,
        service_started=manager_entry.service_started,
        backend_configured=manager_entry.backend_configured,
        configuration_performed=manager_entry.configuration_performed,
        registration_performed=manager_entry.registration_performed,
        setup_performed=manager_entry.setup_performed,
        tasks_performed=manager_entry.tasks_performed,
        provenance=provenance,
        blockers=(),
    )
    if (
        manager_entry.stable_id != target
        or manager_entry.status
        not in {ManagerServerStatus.INSTALLED, ManagerServerStatus.NO_CHANGE}
        or manager_entry.evidence_digest
        != backend_context.record.manager_server_evidence_digest
        or manager_entry.provenance_digest != _digest_object(dict(provenance))
        or server_evidence.artifact_digest
        != backend_context.record.manager_server_evidence_artifact_digest
    ):
        raise StateConflictError(
            "deploy Manager backend preflight Manager install evidence conflicts"
        )
    payload = build_manager_backend_preflight_payload(
        deploy.metadata.record,
        deploy.observation,
        deploy.inventory,
        readiness,
        base_os,
        manager_server,
        backend_context,
        backend_plan,
        logical_id=target,
        image_filter=image_filter,
        architecture=base_host.image_architecture,
    )
    variables: dict[str, object] = {
        "deploy_scylla_vms_manager_backend_preflight": payload
    }
    validate_playbook_request_policy(
        _PLAYBOOK,
        limit=(target,),
        tags=_TAGS,
        check=True,
        diff=False,
        verbosity=0,
    )
    expected_source_path = f"playbooks/{definition.filename}"
    source_matches = tuple(
        item.digest for item in source.files if item.path == expected_source_path
    )
    source_digest = _playbook_source_digest(source, _PLAYBOOK)
    if len(source_matches) != 1 or source_digest != source_matches[0]:
        raise StateConflictError(
            "deploy Manager backend preflight playbook source conflicts"
        )
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
    return _ExecutionScope(
        target,
        validated,
        variables_digest,
        command_digest,
        source_digest,
        backend_context.record.intent.backend_policy.policy_digest,
        image_filter,
        base_host.image_architecture,
        base_os,
        manager_server,
    )


def _base_os_evidence_digest(
    manager_agent_context: _ManagerAgentAuthorizationContext, target: str
) -> str:
    base_os = manager_agent_context.monitoring.monitoring.manager.manager.base_os
    matches = tuple(
        entry.evidence_digest
        for entry in base_os.record.entries
        if any(host.logical_id == target for host in entry.hosts)
    )
    if len(matches) != 1:
        raise StateConflictError(
            "deploy Manager backend preflight base-OS provenance conflicts"
        )
    return matches[0]


def _validate_execution_prefix(
    context: _ExecutionContext,
    execution: StoredDeployManagerBackendPreflightExecution | None,
    evidence: StoredDeployManagerBackendPreflightEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "deploy Manager backend preflight evidence exists without execution"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError(
            "deploy Manager backend preflight execution provenance is stale"
        )
    if evidence is not None:
        if (
            evidence.record.binding != context.binding
            or execution.record.state
            is not DeployManagerBackendPreflightExecutionState.SUCCEEDED
            or execution.record.result_digest != evidence.record.result_digest
            or execution.record.evidence_digest != evidence.record.evidence_digest
        ):
            raise StateConflictError(
                "deploy Manager backend preflight semantic evidence conflicts"
            )
    elif (
        execution.record.state is DeployManagerBackendPreflightExecutionState.SUCCEEDED
    ):
        raise StateConflictError(
            "deploy Manager backend preflight success evidence is missing"
        )


def _build_semantic_evidence(
    context: _ExecutionContext, result: AnsibleExecutionResult
) -> DeployManagerBackendPreflightEvidence:
    parsed = result.manager_backend_preflight
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.READ_ONLY
        or not result.check_mode
        or result.stdout
        or result.stderr
        or result.exit_code != 0
        or parsed is None
        or parsed.logical_id != context.scope.target_stable_id
        or parsed.status is ManagerBackendPreflightStatus.FAILED
        or parsed.role != HostRole.MANAGER.value
        or parsed.operating_system != "Ubuntu"
        or parsed.operating_system_version != "24.04"
        or parsed.architecture != context.scope.architecture
        or any(
            value is None
            for value in (
                parsed.capacity.cpu_count,
                parsed.capacity.memory_bytes,
                parsed.capacity.root_total_bytes,
                parsed.capacity.root_free_bytes,
                parsed.capacity.approved_mount_count,
                parsed.capacity.available_mount_count,
                parsed.reboot_required,
            )
        )
    ):
        raise AnsibleResultError(
            "deploy Manager backend preflight result identity conflicts"
        )
    projection: dict[str, object] = {
        "stable_id": parsed.logical_id,
        "role": parsed.role,
        "status": parsed.status.value,
        "backend_mode": parsed.backend_mode,
        "scylla_release": parsed.scylla_release,
        "operating_system": parsed.operating_system,
        "operating_system_version": parsed.operating_system_version,
        "architecture": parsed.architecture,
        "capacity": {
            "cpu_count": parsed.capacity.cpu_count,
            "memory_bytes": parsed.capacity.memory_bytes,
            "root_total_bytes": parsed.capacity.root_total_bytes,
            "root_free_bytes": parsed.capacity.root_free_bytes,
            "approved_mount_count": parsed.capacity.approved_mount_count,
            "available_mount_count": parsed.capacity.available_mount_count,
            "approved_mount_status": (
                "available"
                if parsed.capacity.approved_mount_count
                == parsed.capacity.available_mount_count
                == 1
                else "unavailable"
            ),
        },
        "manager_package_status": parsed.manager_package_status.value,
        "local_scylla_package_status": parsed.local_scylla_package_status.value,
        "package_availability_status": parsed.package_availability_status,
        "manager_service_status": parsed.manager_service_status.value,
        "local_scylla_service_status": parsed.local_scylla_service_status.value,
        "reboot_required": parsed.reboot_required,
        "loopback_policy_status": parsed.loopback_policy_status.value,
        "configuration_status": parsed.configuration_status,
        "schema_status": parsed.schema_status,
        "operational_readiness": parsed.operational_readiness,
        "not_performed": list(parsed.not_performed),
        "blockers": list(parsed.blockers),
        "provenance_digest": _digest_object(dict(parsed.provenance)),
    }
    result_digest = _digest_object(projection)
    now = _timestamp()
    values: dict[str, object] = {
        "generation": 1,
        "created_at": now,
        "binding": context.binding,
        "stable_id": parsed.logical_id,
        "role": parsed.role,
        "status": parsed.status,
        "backend_mode": parsed.backend_mode,
        "scylla_release": parsed.scylla_release,
        "operating_system": parsed.operating_system,
        "operating_system_version": parsed.operating_system_version,
        "architecture": parsed.architecture,
        "cpu_count": cast(int, parsed.capacity.cpu_count),
        "memory_bytes": cast(int, parsed.capacity.memory_bytes),
        "root_total_bytes": cast(int, parsed.capacity.root_total_bytes),
        "root_free_bytes": cast(int, parsed.capacity.root_free_bytes),
        "approved_mount_count": cast(int, parsed.capacity.approved_mount_count),
        "available_mount_count": cast(int, parsed.capacity.available_mount_count),
        "approved_mount_status": (
            "available"
            if parsed.capacity.approved_mount_count
            == parsed.capacity.available_mount_count
            == 1
            else "unavailable"
        ),
        "manager_package_status": parsed.manager_package_status,
        "local_scylla_package_status": parsed.local_scylla_package_status,
        "package_availability_status": parsed.package_availability_status,
        "manager_service_status": parsed.manager_service_status,
        "local_scylla_service_status": parsed.local_scylla_service_status,
        "reboot_required": cast(bool, parsed.reboot_required),
        "loopback_policy_status": parsed.loopback_policy_status,
        "configuration_status": parsed.configuration_status,
        "schema_status": parsed.schema_status,
        "operational_readiness": parsed.operational_readiness,
        "not_performed": parsed.not_performed,
        "blockers": parsed.blockers,
        "provenance_digest": _digest_object(dict(parsed.provenance)),
        "result_digest": result_digest,
        "evidence_digest": "",
    }
    values["evidence_digest"] = _evidence_digest_from_values(values)
    return DeployManagerBackendPreflightEvidence(**values)  # type: ignore[arg-type]


def _persist_uncertain_or_raise(
    store: DeployManagerBackendPreflightExecutionStore,
    current: StoredDeployManagerBackendPreflightExecution,
    state: DeployManagerBackendPreflightExecutionState,
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
            "deploy Manager backend preflight uncertain outcome persistence failed; "
            "manual recovery required"
        ) from error


def _failure_state(error: AnsibleError) -> DeployManagerBackendPreflightExecutionState:
    current: BaseException | None = error
    while current is not None:
        if isinstance(current, ProcessTimeoutError):
            return DeployManagerBackendPreflightExecutionState.TIMED_OUT
        if isinstance(current, ProcessOutputError):
            return DeployManagerBackendPreflightExecutionState.MALFORMED_RESULT
        current = current.__cause__
    return DeployManagerBackendPreflightExecutionState.MALFORMED_RESULT


def _build_report(
    execution: StoredDeployManagerBackendPreflightExecution,
    evidence: StoredDeployManagerBackendPreflightEvidence,
    *,
    execution_state: DeployManagerBackendPreflightArtifactState,
    evidence_state: DeployManagerBackendPreflightArtifactState,
) -> DeployManagerBackendPreflightExecutionReport:
    if (
        execution.record.state
        is not DeployManagerBackendPreflightExecutionState.SUCCEEDED
        or execution.record.result_digest != evidence.record.result_digest
        or execution.record.evidence_digest != evidence.record.evidence_digest
    ):
        raise StateConflictError(
            "deploy Manager backend preflight success evidence is incomplete"
        )
    binding = execution.record.binding
    return DeployManagerBackendPreflightExecutionReport(
        operation_id=binding.operation_id,
        execution_artifact_state=execution_state,
        evidence_artifact_state=evidence_state,
        execution_state=execution.record.state,
        execution_artifact_digest=execution.artifact_digest,
        evidence_artifact_digest=evidence.artifact_digest,
        binding_digest=binding.binding_digest,
        target_stable_id=binding.target_stable_id,
        target_set_digest=binding.target_set_digest,
        semantic_status=evidence.record.status,
        blocker_count=len(evidence.record.blockers),
        blocker_digest=_digest_object(list(evidence.record.blockers)),
        invocation_count=execution.record.invocation_count,
        manual_recovery_required=execution.record.manual_recovery_required,
        automatic_retry_allowed=execution.record.automatic_retry_allowed,
        journal_status=binding.journal_status,
        journal_phase=binding.journal_phase,
    )


def _binding_digest(
    binding: DeployManagerBackendPreflightExecutionBinding,
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


def _evidence_digest(record: DeployManagerBackendPreflightEvidence) -> str:
    return _evidence_digest_from_values(record.to_object())


def _semantic_result_digest(record: DeployManagerBackendPreflightEvidence) -> str:
    return _digest_object(
        {
            "stable_id": record.stable_id,
            "role": record.role,
            "status": record.status.value,
            "backend_mode": record.backend_mode,
            "scylla_release": record.scylla_release,
            "operating_system": record.operating_system,
            "operating_system_version": record.operating_system_version,
            "architecture": record.architecture,
            "capacity": {
                "cpu_count": record.cpu_count,
                "memory_bytes": record.memory_bytes,
                "root_total_bytes": record.root_total_bytes,
                "root_free_bytes": record.root_free_bytes,
                "approved_mount_count": record.approved_mount_count,
                "available_mount_count": record.available_mount_count,
                "approved_mount_status": record.approved_mount_status,
            },
            "manager_package_status": record.manager_package_status.value,
            "local_scylla_package_status": record.local_scylla_package_status.value,
            "package_availability_status": record.package_availability_status,
            "manager_service_status": record.manager_service_status.value,
            "local_scylla_service_status": record.local_scylla_service_status.value,
            "reboot_required": record.reboot_required,
            "loopback_policy_status": record.loopback_policy_status.value,
            "configuration_status": record.configuration_status,
            "schema_status": record.schema_status,
            "operational_readiness": record.operational_readiness,
            "not_performed": list(record.not_performed),
            "blockers": list(record.blockers),
            "provenance_digest": record.provenance_digest,
        }
    )


def _evidence_digest_from_values(values: Mapping[str, object]) -> str:
    copied = dict(values)
    copied.pop("result_schema_version", None)
    copied.pop("schema_version", None)
    copied["evidence_digest"] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(cast(Mapping[str, object], _jsonable(copied))))


_StoredRecord = (
    DeployManagerBackendPreflightExecutionBinding
    | DeployManagerBackendPreflightExecution
    | DeployManagerBackendPreflightEvidence
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
            DeployManagerBackendPreflightExecutionBinding,
            DeployManagerBackendPreflightExecution,
            DeployManagerBackendPreflightEvidence,
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
        if (field_name.endswith("_digest") and field_value is not None)
    )


def _timestamp() -> str:
    return format_timestamp(datetime.now(UTC))


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy Manager backend preflight paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy Manager backend preflight requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Manager backend preflight artifacts"
        ) from error
    canonical = str(operation_id)
    suffixes = (
        DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_FILENAME_SUFFIX,
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
                "deploy Manager backend preflight artifacts are ambiguous"
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
