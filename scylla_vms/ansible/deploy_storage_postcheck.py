"""Operation-bound storage postcheck execution and immutable reconciliation."""

from __future__ import annotations

import os
import re
import uuid
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.commands import (
    AnsibleCommandBuilder,
    ansible_command_intent_digest,
    validate_playbook_request_policy,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStep,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_plan import (
    DeployConditionState,
    _digest_object,
    _playbook_source_digest,
)
from scylla_vms.ansible.deploy_storage_prepare_reconciliation import (
    ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_SCHEMA_VERSION,
    DeployPostStoragePrepareOutcomeState,
    DeployPostStoragePrepareReconciliationStore,
    DeployStoragePostcheckScope,
    StoredDeployPostStoragePrepareReconciliation,
)
from scylla_vms.ansible.deploy_storage_prepare_reconciliation import (
    _build_record as _build_post_storage_prepare_record,
)
from scylla_vms.ansible.deploy_storage_prepare_reconciliation import (
    _build_steps as _build_post_storage_prepare_steps,
)
from scylla_vms.ansible.deploy_storage_prepare_reconciliation import (
    _load_context as _load_post_storage_prepare_context,
)
from scylla_vms.ansible.deploy_storage_prepare_reconciliation import (
    _ReconciliationContext as _StoragePrepareReconciliationContext,
)
from scylla_vms.ansible.operation_binding import readiness_binding_digest
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.readiness import (
    ReadinessReport,
)
from scylla_vms.ansible.registry import (
    OPERATION_PLAYBOOKS,
    CheckMode,
    LimitPolicy,
    get_playbook,
)
from scylla_vms.ansible.service import (
    AnsibleExecutionResult,
    AnsibleResultError,
    AnsibleService,
    ProcessRunnerProtocol,
)
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION
from scylla_vms.ansible.storage_postcheck import (
    STORAGE_POSTCHECK_SCHEMA_VERSION,
    StorageCheckStatus,
    build_deploy_storage_postcheck_payload,
    parse_storage_postcheck_execution,
)
from scylla_vms.ansible.storage_prepare import (
    IrreversibleStepStatus,
    StoragePrepareEvidence,
    StoragePrepareStatus,
)
from scylla_vms.ansible.toolchain import (
    AnsibleToolchain,
    AnsibleVersionError,
    parse_ansible_core_version,
)
from scylla_vms.ansible.trust import TrustStore
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
    ClusterMetadataStore,
    digest_bytes,
    format_timestamp,
    parse_timestamp,
    parse_uuid,
    require_exact_keys,
    require_string,
    serialize_json,
    validate_digest,
)
from scylla_vms.process import ProcessTimeoutError
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

ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EXECUTION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-postcheck-execution-binding/v1"
)
ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-postcheck-execution/v1"
)
ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EVIDENCE_ENTRY_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-postcheck-evidence-entry/v1"
)
ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-postcheck-evidence/v1"
)
ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EXECUTION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-postcheck-execution-report/v1"
)
ANSIBLE_DEPLOY_POST_STORAGE_POSTCHECK_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-storage-postcheck-reconciliation/v1"
)
ANSIBLE_DEPLOY_POST_STORAGE_POSTCHECK_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-storage-postcheck-reconciliation-report/v1"
)

DEPLOY_STORAGE_POSTCHECK_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-storage-postcheck-execution.json"
)
DEPLOY_STORAGE_POSTCHECK_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-storage-postcheck-evidence.json"
)
DEPLOY_POST_STORAGE_POSTCHECK_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-post-storage-postcheck-reconciliation.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "storage-postcheck"
_NEXT_PLAYBOOK = "scylla-install"
_MAPPING_SEQUENCE = 10
_FINAL_EVIDENCE_MAPPING = len(OPERATION_PLAYBOOKS[_OPERATION])
_ORDER_BLOCKER = "ordered-deploy-step-not-reached"
_AUTHORIZATION_BLOCKER = "deploy-authorization-not-collected"
_CLASS_BLOCKER = "mutating-deploy-execution-unavailable"
_PUBLIC_WORKFLOW_BLOCKER = "public-deploy-workflow-unavailable"
_NOT_STARTED = "not-started"
_UNAVAILABLE = "unavailable"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")
_REQUIRED_CHECKS = frozenset(
    {
        "capacity",
        "device-membership",
        "filesystem",
        "fstab",
        "holders",
        "marker",
        "mount",
        "permissions",
        "provenance",
        "raid",
        "signatures",
        "tools",
    }
)


class DeployStoragePostcheckExecutionState(StrEnum):
    STARTED = "started"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    INTERRUPTED = "interrupted"
    UNREACHABLE = "unreachable"
    MALFORMED_RESULT = "malformed-result"


class DeployStoragePostcheckArtifactState(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployStoragePostcheckExecutionBinding:
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    prior_reconciliation_artifact_digest: str
    prior_reconciliation_record_digest: str
    prior_effective_plan_digest: str
    validated_chain_digest: str
    observation_generation: int
    observation_artifact_digest: str
    observation_manifest_digest: str
    desired_storage_policy_digest: str
    storage_manifest_digest: str
    discovery_evidence_digest: str
    preflight_evidence_digest: str
    preparation_evidence_digest: str
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
    scope_count: int
    stable_id_set_digest: str
    execution_scope_digest: str
    binding_digest: str
    prior_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EXECUTION_BINDING_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EXECUTION_BINDING_SCHEMA_VERSION
            or self.prior_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.scope_count < 1
        ):
            raise StatePersistenceError(
                "deploy storage-postcheck execution binding is invalid"
            )
        validate_cluster_name(self.cluster_name)
        for value in (
            self.journal_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
        ):
            _positive_integer(value, "storage-postcheck binding count")
        for digest_value in _digest_fields(self):
            validate_digest(digest_value, "storage-postcheck binding digest")
        _validate_toolchain_version(self.toolchain_version)
        if self.binding_digest != _binding_digest(self):
            raise StatePersistenceError(
                "deploy storage-postcheck execution binding digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployStoragePostcheckExecutionBinding:
        require_exact_keys(value, set(cls.__dataclass_fields__), "postcheck binding")
        parsed: dict[str, object] = {}
        integers = {
            "journal_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
            "scope_count",
        }
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
class DeployStoragePostcheckExecutionAttempt:
    attempt_index: int
    step_sequence: int
    stable_id: str
    source_state: DeployPostStoragePrepareOutcomeState
    backend: str
    layout: str
    capacity_bytes: int
    device_count: int
    device_set_digest: str
    preparation_intent_digest: str
    preparation_evidence_digest: str
    variables_digest: str
    command_digest: str
    source_digest: str
    state: DeployStoragePostcheckExecutionState
    started_at: str
    completed_at: str | None
    invocation_may_have_occurred: bool
    exit_code: int | None
    result_digest: str | None
    evidence_digest: str | None
    readiness_for_scylla: bool | None
    check_status_digest: str | None
    blocker_digest: str | None
    manual_recovery_required: bool
    automatic_retry_allowed: bool = False
    result_schema_version: str = STORAGE_POSTCHECK_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.attempt_index < 1
            or self.step_sequence < 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or not isinstance(self.source_state, DeployPostStoragePrepareOutcomeState)
            or self.backend not in {"block-volume", "local-nvme"}
            or self.layout not in {"single", "raid0"}
            or self.capacity_bytes < 1
            or self.device_count < 1
            or self.result_schema_version != STORAGE_POSTCHECK_SCHEMA_VERSION
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError("deploy storage-postcheck attempt is invalid")
        started = parse_timestamp(self.started_at)
        completed = _optional_timestamp(self.completed_at)
        if completed is not None and completed < started:
            raise StatePersistenceError(
                "deploy storage-postcheck attempt timestamps conflict"
            )
        if self.state is DeployStoragePostcheckExecutionState.STARTED:
            valid = (
                completed is None
                and self.invocation_may_have_occurred
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.readiness_for_scylla is None
                and self.check_status_digest is None
                and self.blocker_digest is None
                and self.manual_recovery_required
            )
        elif self.state in {
            DeployStoragePostcheckExecutionState.SUCCEEDED,
            DeployStoragePostcheckExecutionState.FAILED,
            DeployStoragePostcheckExecutionState.UNREACHABLE,
        }:
            valid = (
                completed is not None
                and self.invocation_may_have_occurred
                and self.exit_code is not None
                and self.result_digest is not None
                and self.evidence_digest is not None
                and self.readiness_for_scylla is not None
                and self.check_status_digest is not None
                and self.blocker_digest is not None
                and self.manual_recovery_required
                == (self.state is not DeployStoragePostcheckExecutionState.SUCCEEDED)
            )
        else:
            valid = (
                completed is not None
                and self.invocation_may_have_occurred
                and self.exit_code is None
                and self.result_digest is None
                and self.evidence_digest is None
                and self.readiness_for_scylla is None
                and self.check_status_digest is None
                and self.blocker_digest is None
                and self.manual_recovery_required
            )
        if not valid:
            raise StatePersistenceError(
                "deploy storage-postcheck attempt state conflicts"
            )
        for digest in (
            self.device_set_digest,
            self.preparation_intent_digest,
            self.preparation_evidence_digest,
            self.variables_digest,
            self.command_digest,
            self.source_digest,
            self.result_digest,
            self.evidence_digest,
            self.check_status_digest,
            self.blocker_digest,
        ):
            if digest is not None:
                validate_digest(digest, "storage-postcheck attempt digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployStoragePostcheckExecutionAttempt:
        require_exact_keys(value, set(cls.__dataclass_fields__), "postcheck attempt")
        try:
            return cls(
                attempt_index=_integer(value["attempt_index"], "attempt index"),
                step_sequence=_integer(value["step_sequence"], "step sequence"),
                stable_id=require_string(value, "stable_id"),
                source_state=DeployPostStoragePrepareOutcomeState(
                    require_string(value, "source_state")
                ),
                backend=require_string(value, "backend"),
                layout=require_string(value, "layout"),
                capacity_bytes=_integer(value["capacity_bytes"], "capacity bytes"),
                device_count=_integer(value["device_count"], "device count"),
                device_set_digest=require_string(value, "device_set_digest"),
                preparation_intent_digest=require_string(
                    value, "preparation_intent_digest"
                ),
                preparation_evidence_digest=require_string(
                    value, "preparation_evidence_digest"
                ),
                variables_digest=require_string(value, "variables_digest"),
                command_digest=require_string(value, "command_digest"),
                source_digest=require_string(value, "source_digest"),
                state=DeployStoragePostcheckExecutionState(
                    require_string(value, "state")
                ),
                started_at=require_string(value, "started_at"),
                completed_at=_optional_string(value["completed_at"], "completed_at"),
                invocation_may_have_occurred=_boolean(
                    value["invocation_may_have_occurred"], "invocation state"
                ),
                exit_code=_optional_integer(value["exit_code"], "exit code"),
                result_digest=_optional_string(value["result_digest"], "result digest"),
                evidence_digest=_optional_string(
                    value["evidence_digest"], "evidence digest"
                ),
                readiness_for_scylla=_optional_boolean(
                    value["readiness_for_scylla"], "readiness"
                ),
                check_status_digest=_optional_string(
                    value["check_status_digest"], "check status digest"
                ),
                blocker_digest=_optional_string(
                    value["blocker_digest"], "blocker digest"
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
                "deploy storage-postcheck attempt enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployStoragePostcheckExecution:
    generation: int
    created_at: str
    updated_at: str
    binding: DeployStoragePostcheckExecutionBinding
    state: DeployStoragePostcheckExecutionState
    invocation_count: int
    all_scopes_completed: bool
    attempts: tuple[DeployStoragePostcheckExecutionAttempt, ...]
    schema_version: str = ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EXECUTION_SCHEMA_VERSION
            or self.generation < 1
            or self.invocation_count != len(self.attempts)
            or not self.attempts
            or self.attempts[-1].state is not self.state
            or len(self.attempts) > self.binding.scope_count
            or tuple(item.attempt_index for item in self.attempts)
            != tuple(range(1, len(self.attempts) + 1))
            or self.all_scopes_completed
            != (
                self.state is DeployStoragePostcheckExecutionState.SUCCEEDED
                and len(self.attempts) == self.binding.scope_count
            )
        ):
            raise StatePersistenceError(
                "deploy storage-postcheck execution summary conflicts"
            )
        created = parse_timestamp(self.created_at)
        updated = parse_timestamp(self.updated_at)
        if updated < created:
            raise StatePersistenceError(
                "deploy storage-postcheck execution timestamps conflict"
            )

    @property
    def succeeded_count(self) -> int:
        return sum(
            item.state is DeployStoragePostcheckExecutionState.SUCCEEDED
            for item in self.attempts
        )

    @property
    def manual_recovery_required(self) -> bool:
        return any(item.manual_recovery_required for item in self.attempts) and (
            self.state is not DeployStoragePostcheckExecutionState.SUCCEEDED
        )

    @property
    def automatic_retry_allowed(self) -> bool:
        return False

    def to_object(self) -> dict[str, object]:
        return {
            "all_scopes_completed": self.all_scopes_completed,
            "attempts": [item.to_object() for item in self.attempts],
            "binding": self.binding.to_object(),
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
    ) -> DeployStoragePostcheckExecution:
        require_exact_keys(value, set(cls.__dataclass_fields__), "postcheck execution")
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                updated_at=require_string(value, "updated_at"),
                binding=DeployStoragePostcheckExecutionBinding.from_object(
                    _mapping(value["binding"], "binding")
                ),
                state=DeployStoragePostcheckExecutionState(
                    require_string(value, "state")
                ),
                invocation_count=_integer(
                    value["invocation_count"], "invocation count"
                ),
                all_scopes_completed=_boolean(
                    value["all_scopes_completed"], "completion"
                ),
                attempts=tuple(
                    DeployStoragePostcheckExecutionAttempt.from_object(
                        _mapping(item, "attempt")
                    )
                    for item in _array(value["attempts"], "attempts")
                ),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy storage-postcheck execution enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployStoragePostcheckEvidenceEntry:
    attempt_index: int
    step_sequence: int
    stable_id: str
    source_state: DeployPostStoragePrepareOutcomeState
    backend: str
    layout: str
    capacity_bytes: int
    device_count: int
    device_set_digest: str
    preparation_intent_digest: str
    preparation_evidence_digest: str
    passed_check_count: int
    failed_check_count: int
    unknown_check_count: int
    check_status_digest: str
    blocker_count: int
    blocker_digest: str
    provenance_digest: str
    result_digest: str
    evidence_digest: str
    readiness_for_scylla: bool
    manual_recovery_required: bool
    automatic_retry_allowed: bool = False
    result_schema_version: str = STORAGE_POSTCHECK_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EVIDENCE_ENTRY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EVIDENCE_ENTRY_SCHEMA_VERSION
            or self.result_schema_version != STORAGE_POSTCHECK_SCHEMA_VERSION
            or self.attempt_index < 1
            or self.step_sequence < 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.capacity_bytes < 1
            or self.device_count < 1
            or min(
                self.passed_check_count,
                self.failed_check_count,
                self.unknown_check_count,
                self.blocker_count,
            )
            < 0
            or self.passed_check_count
            + self.failed_check_count
            + self.unknown_check_count
            != 12
            or self.readiness_for_scylla
            != (
                self.passed_check_count == 12
                and self.failed_check_count == 0
                and self.unknown_check_count == 0
                and self.blocker_count == 0
            )
            or self.manual_recovery_required == self.readiness_for_scylla
            or self.automatic_retry_allowed
        ):
            raise StatePersistenceError(
                "deploy storage-postcheck evidence entry conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(value, "storage-postcheck evidence digest")
        if self.evidence_digest != _entry_digest(self):
            raise StatePersistenceError(
                "deploy storage-postcheck evidence digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployStoragePostcheckEvidenceEntry:
        require_exact_keys(
            value, set(cls.__dataclass_fields__), "postcheck evidence entry"
        )
        try:
            return cls(
                attempt_index=_integer(value["attempt_index"], "attempt index"),
                step_sequence=_integer(value["step_sequence"], "step sequence"),
                stable_id=require_string(value, "stable_id"),
                source_state=DeployPostStoragePrepareOutcomeState(
                    require_string(value, "source_state")
                ),
                backend=require_string(value, "backend"),
                layout=require_string(value, "layout"),
                capacity_bytes=_integer(value["capacity_bytes"], "capacity bytes"),
                device_count=_integer(value["device_count"], "device count"),
                device_set_digest=require_string(value, "device_set_digest"),
                preparation_intent_digest=require_string(
                    value, "preparation_intent_digest"
                ),
                preparation_evidence_digest=require_string(
                    value, "preparation_evidence_digest"
                ),
                passed_check_count=_integer(
                    value["passed_check_count"], "passed count"
                ),
                failed_check_count=_integer(
                    value["failed_check_count"], "failed count"
                ),
                unknown_check_count=_integer(
                    value["unknown_check_count"], "unknown count"
                ),
                check_status_digest=require_string(value, "check_status_digest"),
                blocker_count=_integer(value["blocker_count"], "blocker count"),
                blocker_digest=require_string(value, "blocker_digest"),
                provenance_digest=require_string(value, "provenance_digest"),
                result_digest=require_string(value, "result_digest"),
                evidence_digest=require_string(value, "evidence_digest"),
                readiness_for_scylla=_boolean(
                    value["readiness_for_scylla"], "readiness"
                ),
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
                "deploy storage-postcheck evidence enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployStoragePostcheckEvidence:
    generation: int
    created_at: str
    updated_at: str
    binding: DeployStoragePostcheckExecutionBinding
    entries: tuple[DeployStoragePostcheckEvidenceEntry, ...]
    schema_version: str = ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EVIDENCE_SCHEMA_VERSION
            or self.generation != len(self.entries)
            or not self.entries
            or len(self.entries) > self.binding.scope_count
            or tuple(item.attempt_index for item in self.entries)
            != tuple(range(1, len(self.entries) + 1))
        ):
            raise StatePersistenceError(
                "deploy storage-postcheck evidence prefix conflicts"
            )
        created = parse_timestamp(self.created_at)
        updated = parse_timestamp(self.updated_at)
        if updated < created:
            raise StatePersistenceError(
                "deploy storage-postcheck evidence timestamps conflict"
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
    def from_object(cls, value: Mapping[str, object]) -> DeployStoragePostcheckEvidence:
        require_exact_keys(value, set(cls.__dataclass_fields__), "postcheck evidence")
        return cls(
            generation=_integer(value["generation"], "generation"),
            created_at=require_string(value, "created_at"),
            updated_at=require_string(value, "updated_at"),
            binding=DeployStoragePostcheckExecutionBinding.from_object(
                _mapping(value["binding"], "binding")
            ),
            entries=tuple(
                DeployStoragePostcheckEvidenceEntry.from_object(
                    _mapping(item, "evidence entry")
                )
                for item in _array(value["entries"], "evidence entries")
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredDeployStoragePostcheckExecution:
    record: DeployStoragePostcheckExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployStoragePostcheckEvidence:
    record: DeployStoragePostcheckEvidence
    artifact_digest: str


class DeployStoragePostcheckExecutionStore:
    """Generation-guarded owner-only postcheck intent."""

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
        self._path = deploy_storage_postcheck_execution_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployStoragePostcheckExecution:
        value, digest = self._file.read()
        record = DeployStoragePostcheckExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy storage-postcheck execution identity conflicts"
            )
        return StoredDeployStoragePostcheckExecution(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployStoragePostcheckExecution:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployStoragePostcheckExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployStoragePostcheckExecution:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy storage-postcheck execution operation conflicts"
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
            ):
                raise StateConflictError(
                    "deploy storage-postcheck execution transition conflicts"
                )
            _validate_execution_transition(current.record, record)
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
            or record.state is not DeployStoragePostcheckExecutionState.STARTED
            or len(record.attempts) != 1
        ):
            raise StateConflictError(
                "deploy storage-postcheck initial execution conflicts"
            )
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployStoragePostcheckExecution(record, digest)


class DeployStoragePostcheckEvidenceStore:
    """Immutable-prefix owner-only postcheck evidence."""

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
        self._path = deploy_storage_postcheck_evidence_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployStoragePostcheckEvidence:
        value, digest = self._file.read()
        record = DeployStoragePostcheckEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy storage-postcheck evidence identity conflicts"
            )
        return StoredDeployStoragePostcheckEvidence(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployStoragePostcheckEvidence:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def append_locked(
        self,
        record: DeployStoragePostcheckEvidence,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployStoragePostcheckEvidence:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy storage-postcheck evidence operation conflicts"
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
                    "deploy storage-postcheck evidence prefix conflicts"
                )
        elif (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
            or len(record.entries) != 1
        ):
            raise StateConflictError(
                "initial deploy storage-postcheck evidence conflicts"
            )
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredDeployStoragePostcheckEvidence(record, digest)


@dataclass(frozen=True, slots=True)
class DeployStoragePostcheckExecutionReport:
    operation_id: uuid.UUID
    execution_artifact_state: DeployStoragePostcheckArtifactState
    evidence_artifact_state: DeployStoragePostcheckArtifactState
    execution_state: DeployStoragePostcheckExecutionState
    execution_artifact_digest: str
    evidence_artifact_digest: str
    binding_digest: str
    invocation_count: int
    scope_count: int
    target_set_digest: str
    succeeded_count: int
    prepared_source_count: int
    owned_noop_source_count: int
    device_count: int
    capacity_bytes: int
    result_digest: str
    evidence_digest: str
    check_status_digest: str
    blocker_digest: str
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    journal_status: JournalStatus
    journal_phase: OperationPhase
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EVIDENCE_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EXECUTION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EXECUTION_REPORT_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EVIDENCE_SCHEMA_VERSION
            or self.execution_state
            is not DeployStoragePostcheckExecutionState.SUCCEEDED
            or self.invocation_count != self.scope_count
            or self.succeeded_count != self.scope_count
            or self.prepared_source_count + self.owned_noop_source_count
            != self.scope_count
            or self.device_count < self.scope_count
            or self.capacity_bytes < self.device_count
            or self.manual_recovery_required
            or self.automatic_retry_allowed
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError(
                "deploy storage-postcheck execution report conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(value, "storage-postcheck report digest")

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
                "blocker_digest": self.blocker_digest,
                "capacity_bytes": self.capacity_bytes,
                "check_status_digest": self.check_status_digest,
                "device_count": self.device_count,
                "evidence_digest": self.evidence_digest,
                "result_digest": self.result_digest,
                "succeeded_count": self.succeeded_count,
            },
            "schema_version": self.schema_version,
            "schemas": {
                "evidence": self.evidence_schema_version,
                "execution": self.execution_schema_version,
            },
            "scope": {
                "count": self.scope_count,
                "owned_noop_source_count": self.owned_noop_source_count,
                "prepared_source_count": self.prepared_source_count,
                "target_set_digest": self.target_set_digest,
            },
        }


@dataclass(frozen=True, slots=True)
class _ExecutionScope:
    attempt_index: int
    step: DeployBaseOsReconciledStep
    prior_scope: DeployStoragePostcheckScope
    source_state: DeployPostStoragePrepareOutcomeState
    backend: str
    layout: str
    capacity_bytes: int
    device_count: int
    device_set_digest: str
    preparation_intent_digest: str
    preparation_evidence_digest: str
    variables: Mapping[str, object]
    variables_digest: str
    command_digest: str
    source_digest: str


@dataclass(frozen=True, slots=True)
class _ExecutionContext:
    prior: StoredDeployPostStoragePrepareReconciliation
    binding: DeployStoragePostcheckExecutionBinding
    scopes: tuple[_ExecutionScope, ...]
    metadata: ClusterMetadata
    inventory: StoredInventoryRecord
    readiness: ReadinessReport


def execute_deploy_storage_postcheck(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployStoragePostcheckExecutionReport:
    """Execute each exact eligible storage postcheck once in immutable order."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _validate_toolchain_dependency(toolchain)
    executable_identity_digest = _executable_identity_digest(executables)
    toolchain_evidence_digest = _toolchain_evidence_digest(
        toolchain, executable_identity_digest
    )
    _refuse_ambiguous_or_later_artifacts(paths, operation_id)
    context = _load_execution_context(
        paths,
        operation_id,
        lock=lock,
        toolchain_version=str(toolchain.core),
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    builder = AnsibleCommandBuilder(executables.playbook, executables.inventory, paths)
    _validate_builder_scopes(builder, context)
    execution_store = DeployStoragePostcheckExecutionStore(paths, operation_id)
    evidence_store = DeployStoragePostcheckEvidenceStore(paths, operation_id)
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
        assert evidence is not None
        _validate_existing_post_storage_postcheck_reconciliation(
            paths, operation_id, context.prior, execution, evidence, lock=lock
        )
        return _build_execution_report(
            context,
            execution,
            evidence,
            execution_state=DeployStoragePostcheckArtifactState.REUSED,
            evidence_state=DeployStoragePostcheckArtifactState.REUSED,
        )
    if execution is not None and execution.record.state is not (
        DeployStoragePostcheckExecutionState.SUCCEEDED
    ):
        raise StateConflictError(
            "deploy storage-postcheck execution requires manual recovery and cannot retry"
        )

    service = AnsibleService(builder, runner)
    if service.version(lock) != toolchain:
        raise StateConflictError("deploy storage-postcheck Ansible toolchain drifted")
    execution_state = (
        DeployStoragePostcheckArtifactState.UPDATED
        if execution is not None
        else DeployStoragePostcheckArtifactState.CREATED
    )
    evidence_state = (
        DeployStoragePostcheckArtifactState.UPDATED
        if evidence is not None
        else DeployStoragePostcheckArtifactState.CREATED
    )
    while execution is None or not execution.record.all_scopes_completed:
        next_index = 0 if execution is None else len(execution.record.attempts)
        scope = context.scopes[next_index]
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
                "deploy storage-postcheck state drifted before invocation"
            )
        _validate_prefix(before, execution, evidence)
        execution = _persist_started(
            context, execution_store, execution, scope, lock=lock
        )
        try:
            result, observed_command_digest = service.execute_operation_step(
                lock,
                before.metadata,
                before.inventory,
                _PLAYBOOK,
                step_sequence=scope.step.sequence,
                limit=(scope.prior_scope.stable_id,),
                variables=dict(scope.variables),
                readiness=before.readiness,
                tags=(),
                check=True,
                diff=False,
                verbosity=0,
            )
            if observed_command_digest != scope.command_digest:
                raise AnsibleResultError(
                    "deploy storage-postcheck command result identity conflicts"
                )
        except KeyboardInterrupt:
            _persist_uncertain_or_raise(
                execution_store,
                execution,
                DeployStoragePostcheckExecutionState.INTERRUPTED,
                lock=lock,
            )
            raise AnsibleError(
                "deploy storage-postcheck execution was interrupted; "
                "manual recovery required"
            ) from None
        except AnsibleError as error:
            _persist_uncertain_or_raise(
                execution_store, execution, _failure_state(error), lock=lock
            )
            raise AnsibleError(
                "deploy storage-postcheck execution is uncertain; "
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
        except (StateConflictError, StatePersistenceError) as error:
            raise StateConflictError(
                "deploy storage-postcheck state changed after invocation; "
                "manual recovery required"
            ) from error
        if after.binding != context.binding:
            raise StateConflictError(
                "deploy storage-postcheck state changed after invocation; "
                "manual recovery required"
            )
        try:
            entry = _semantic_entry(scope, result)
        except (AnsibleError, StatePersistenceError) as error:
            _persist_uncertain_or_raise(
                execution_store,
                execution,
                DeployStoragePostcheckExecutionState.MALFORMED_RESULT,
                lock=lock,
            )
            raise AnsibleError(
                "deploy storage-postcheck result is malformed; manual recovery required"
            ) from error
        try:
            evidence = _persist_evidence(
                context, evidence_store, evidence, entry, lock=lock
            )
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy storage-postcheck evidence persistence failed; "
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
                "deploy storage-postcheck terminal persistence failed; "
                "manual recovery required"
            ) from error
        if terminal_state is not DeployStoragePostcheckExecutionState.SUCCEEDED:
            raise AnsibleError(
                "deploy storage-postcheck verification failed; manual recovery required"
            )
    assert evidence is not None
    _validate_prefix(context, execution, evidence)
    return _build_execution_report(
        context,
        execution,
        evidence,
        execution_state=execution_state,
        evidence_state=evidence_state,
    )


def deploy_storage_postcheck_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _operation_path(
        paths, operation_id, DEPLOY_STORAGE_POSTCHECK_EXECUTION_FILENAME_SUFFIX
    )


def deploy_storage_postcheck_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _operation_path(
        paths, operation_id, DEPLOY_STORAGE_POSTCHECK_EVIDENCE_FILENAME_SUFFIX
    )


def deploy_storage_postcheck_execution_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_STORAGE_POSTCHECK_EXECUTION_FILENAME_SUFFIX
    )


def deploy_storage_postcheck_evidence_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_STORAGE_POSTCHECK_EVIDENCE_FILENAME_SUFFIX
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
    post = _load_post_storage_prepare_context(paths, operation_id, lock=lock)
    preflight = post.authorization_context.preflight
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
        or readiness_record.playbook_version != toolchain_version
        or readiness_record.inventory_version != toolchain_version
        or readiness_record.remote_playbook_status != "not-performed"
        or preflight.binding.toolchain_version != toolchain_version
        or preflight.binding.executable_identity_digest != executable_identity_digest
        or preflight.binding.toolchain_evidence_digest != toolchain_evidence_digest
    ):
        raise StateConflictError(
            "deploy storage-postcheck readiness, journal, or toolchain conflicts"
        )
    readiness = _reconstructed_readiness(planning.base)
    if readiness_binding_digest(readiness) != readiness_record.readiness_digest:
        raise StateConflictError("deploy storage-postcheck readiness is stale")
    readiness.require_ready(OperationClassification.READ_ONLY)
    TrustStore(paths).validate_runtime(planning.base.trust, deploy.inventory)
    prior_store = DeployPostStoragePrepareReconciliationStore(paths, operation_id)
    validate_state_file(prior_store.path, allow_missing=True)
    if not prior_store.path.exists():
        raise StateConflictError(
            "deploy storage-postcheck requires post-storage-prepare reconciliation"
        )
    prior = prior_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_prior = _build_post_storage_prepare_record(
        post,
        steps=_build_post_storage_prepare_steps(post),
        created_at=prior.record.created_at,
    )
    if prior.record != expected_prior:
        raise StateConflictError(
            "deploy storage-postcheck prior reconciliation drifted"
        )
    scopes = _derive_execution_scopes(post, prior)
    desired_policy = next(
        (
            item
            for item in metadata.desired_spec.storage
            if item.role is HostRole.SCYLLA
        ),
        None,
    )
    if desired_policy is None:
        raise StateConflictError(
            "deploy storage-postcheck desired Scylla storage policy is unavailable"
        )
    desired_policy_digest = _digest_object(desired_policy.to_object())
    storage_manifest_digest = _digest_object(
        deploy.observation.record.manifest.to_persistence_object()
    )
    preflight_evidence = post.authorization_context.evidence
    preparation_evidence_digest = _digest_object(
        [
            {
                "preparation_evidence_digest": scope.preparation_evidence_digest,
                "source_state": scope.source_state.value,
                "stable_id": scope.prior_scope.stable_id,
            }
            for scope in scopes
        ]
    )
    scope_values = [
        {
            "command_digest": scope.command_digest,
            "device_set_digest": scope.device_set_digest,
            "preparation_evidence_digest": scope.preparation_evidence_digest,
            "preparation_intent_digest": scope.preparation_intent_digest,
            "source_digest": scope.source_digest,
            "source_state": scope.source_state.value,
            "stable_id": scope.prior_scope.stable_id,
            "step_sequence": scope.step.sequence,
            "variables_digest": scope.variables_digest,
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
        "prior_reconciliation_artifact_digest": prior.artifact_digest,
        "prior_reconciliation_record_digest": prior.record.record_digest,
        "prior_effective_plan_digest": prior.record.effective_plan_digest,
        "validated_chain_digest": _digest_object(
            {
                "catalog_digest": loaded.catalog_digest,
                "prior_artifact_digest": prior.artifact_digest,
                "prior_record_digest": prior.record.record_digest,
                "source_digest": loaded.source.digest,
                "storage_manifest_digest": storage_manifest_digest,
            }
        ),
        "observation_generation": deploy.observation.record.generation,
        "observation_artifact_digest": deploy.observation.digest,
        "observation_manifest_digest": deploy.observation.record.manifest_digest,
        "desired_storage_policy_digest": desired_policy_digest,
        "storage_manifest_digest": storage_manifest_digest,
        "discovery_evidence_digest": (
            preflight.discovery_evidence.record.evidence_digest
        ),
        "preflight_evidence_digest": preflight_evidence.record.evidence_digest,
        "preparation_evidence_digest": preparation_evidence_digest,
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
        "playbook_source_digest": _playbook_source_digest(loaded.source, _PLAYBOOK),
        "toolchain_version": toolchain_version,
        "executable_identity_digest": executable_identity_digest,
        "toolchain_evidence_digest": toolchain_evidence_digest,
        "scope_count": len(scopes),
        "stable_id_set_digest": _digest_object(
            [scope.prior_scope.stable_id for scope in scopes]
        ),
        "execution_scope_digest": _digest_object(scope_values),
        "binding_digest": "",
    }
    values["binding_digest"] = _binding_digest_from_values(values)
    return _ExecutionContext(
        prior,
        DeployStoragePostcheckExecutionBinding(**values),  # type: ignore[arg-type]
        scopes,
        metadata,
        deploy.inventory,
        readiness,
    )


def _derive_execution_scopes(
    post: _StoragePrepareReconciliationContext,
    prior: StoredDeployPostStoragePrepareReconciliation,
) -> tuple[_ExecutionScope, ...]:
    authorization_context = post.authorization_context
    preflight = authorization_context.preflight
    loaded = preflight.discovery.post.chain.authorization_context.final_routes.post.post.base.host.loaded
    deploy = loaded.planning.base.deploy
    source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
    definition = get_playbook(_PLAYBOOK)
    if (
        definition.classification is not OperationClassification.READ_ONLY
        or definition.hosts != HostRole.SCYLLA.value
        or definition.serial != 1
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.check_mode is not CheckMode.SUPPORTED
        or not definition.source_available
    ):
        raise StateConflictError("deploy storage-postcheck catalog policy conflicts")
    scope_by_id = {item.stable_id: item for item in prior.record.postcheck_scopes}
    outcomes = {item.stable_id: item for item in post.outcomes}
    evidence_hosts = {
        item.stable_id: item for item in authorization_context.evidence.record.hosts
    }
    domain_hosts = {item.logical_id: item for item in preflight.preflight.hosts}
    prepare_entries = (
        {}
        if post.evidence is None
        else {item.stable_id: item for item in post.evidence.record.entries}
    )
    selected = tuple(
        step
        for step in prior.record.steps
        if step.mapping_sequence == _MAPPING_SEQUENCE
        and step.status is DeployBaseOsReconciledStepStatus.ELIGIBLE
    )
    if (
        not selected
        or len(selected) != len(scope_by_id)
        or tuple(step.target_ids[0] for step in selected) != tuple(scope_by_id)
    ):
        raise StateConflictError(
            "deploy storage-postcheck eligible scope identity conflicts"
        )
    scopes: list[_ExecutionScope] = []
    for attempt_index, step in enumerate(selected, start=1):
        stable_id = step.target_ids[0]
        prior_scope = scope_by_id.get(stable_id)
        outcome = outcomes.get(stable_id)
        evidence_host = evidence_hosts.get(stable_id)
        domain_host = domain_hosts.get(stable_id)
        if (
            prior_scope is None
            or outcome is None
            or evidence_host is None
            or domain_host is None
            or step.playbook != _PLAYBOOK
            or step.condition_state is not DeployConditionState.ACTIVE
            or step.classification is not OperationClassification.READ_ONLY
            or step.target_role != HostRole.SCYLLA.value
            or len(step.target_ids) != 1
            or step.target_digest != _digest_object([stable_id])
            or step.source_digest != source_digest
            or evidence_host.blocker_set
            or evidence_host.device_set_digest != prior_scope.device_set_digest
            or evidence_host.preparation_intent_digest
            != prior_scope.preparation_intent_digest
            or domain_host.logical_id != stable_id
            or domain_host.backend != evidence_host.backend
            or domain_host.layout != evidence_host.layout
            or domain_host.capacity_bytes != evidence_host.capacity_bytes
            or len(domain_host.devices) != evidence_host.device_count
            or outcome.outcome_digest
            != next(
                item.outcome_digest
                for item in prior.record.outcomes
                if item.stable_id == stable_id
            )
        ):
            raise StateConflictError(
                "deploy storage-postcheck exact scope provenance conflicts"
            )
        if outcome.state is DeployPostStoragePrepareOutcomeState.PREPARE_SUCCEEDED:
            entry = prepare_entries.get(stable_id)
            if (
                entry is None
                or outcome.execution_evidence_digest != entry.evidence_digest
                or outcome.filesystem_uuid_digest != entry.filesystem_uuid_digest
                or outcome.marker_digest != entry.marker_digest
            ):
                raise StateConflictError(
                    "deploy storage-postcheck preparation evidence conflicts"
                )
            preparation = StoragePrepareEvidence(
                logical_id=stable_id,
                status=StoragePrepareStatus.CHANGED,
                backend=evidence_host.backend,
                layout=evidence_host.layout,
                device_set_digest=evidence_host.device_set_digest,
                filesystem_uuid_digest=entry.filesystem_uuid_digest,
                marker_digest=entry.marker_digest,
                irreversible_step_status=IrreversibleStepStatus.COMPLETED,
                completed_steps=(),
                post_action_verification=(),
            )
        elif outcome.state is DeployPostStoragePrepareOutcomeState.OWNED_NOOP_CURRENT:
            if stable_id in prepare_entries or outcome.mutation_performed:
                raise StateConflictError(
                    "deploy storage-postcheck owned-noop provenance conflicts"
                )
            preparation = StoragePrepareEvidence(
                logical_id=stable_id,
                status=StoragePrepareStatus.NOOP,
                backend=evidence_host.backend,
                layout=evidence_host.layout,
                device_set_digest=evidence_host.device_set_digest,
                filesystem_uuid_digest=None,
                marker_digest=None,
                irreversible_step_status=IrreversibleStepStatus.NOT_STARTED,
                completed_steps=(),
                post_action_verification=(),
            )
        else:
            raise StateConflictError(
                "blocked storage cannot enter deploy storage-postcheck"
            )
        narrow_preflight = type(preflight.preflight)((domain_host,))
        payload = build_deploy_storage_postcheck_payload(
            deploy.metadata.record,
            deploy.observation,
            deploy.inventory,
            narrow_preflight,
            preparation,
            discovery_evidence_digest=preflight.discovery_evidence.record.evidence_digest,
            preflight_evidence_digest=authorization_context.evidence.record.evidence_digest,
            preparation_evidence_digest=prior_scope.preparation_evidence_digest,
            limit=(stable_id,),
        )
        variables: dict[str, object] = {"deploy_scylla_vms_storage_postcheck": payload}
        validate_playbook_request_policy(
            _PLAYBOOK,
            limit=(stable_id,),
            tags=(),
            check=True,
            diff=False,
            verbosity=0,
        )
        validated = definition.validate_variables(variables)
        variables_digest = digest_bytes(serialize_json(validated))
        command_digest = ansible_command_intent_digest(
            definition,
            step_sequence=step.sequence,
            limit=(stable_id,),
            variables_digest=variables_digest,
            tags=(),
            check=True,
            diff=False,
            verbosity=0,
        )
        scopes.append(
            _ExecutionScope(
                attempt_index,
                step,
                prior_scope,
                outcome.state,
                evidence_host.backend,
                evidence_host.layout,
                evidence_host.capacity_bytes,
                evidence_host.device_count,
                evidence_host.device_set_digest,
                evidence_host.preparation_intent_digest,
                prior_scope.preparation_evidence_digest,
                validated,
                variables_digest,
                command_digest,
                source_digest,
            )
        )
    if tuple(scope.prior_scope.stable_id for scope in scopes) != tuple(
        sorted(scope.prior_scope.stable_id for scope in scopes)
    ):
        raise StateConflictError("deploy storage-postcheck execution order conflicts")
    return tuple(scopes)


def _validate_builder_scopes(
    builder: AnsibleCommandBuilder, context: _ExecutionContext
) -> None:
    definition = get_playbook(_PLAYBOOK)
    for scope in context.scopes:
        selected, validated, variables_digest, command_digest = (
            builder.validate_operation_step(
                _PLAYBOOK,
                step_sequence=scope.step.sequence,
                limit=(scope.prior_scope.stable_id,),
                variables=dict(scope.variables),
                tags=(),
                check=True,
                diff=False,
                verbosity=0,
            )
        )
        if (
            selected != definition
            or validated != scope.variables
            or variables_digest != scope.variables_digest
            or command_digest != scope.command_digest
        ):
            raise StateConflictError(
                "deploy storage-postcheck anchored command identity conflicts"
            )


def _persist_started(
    context: _ExecutionContext,
    store: DeployStoragePostcheckExecutionStore,
    current: StoredDeployStoragePostcheckExecution | None,
    scope: _ExecutionScope,
    *,
    lock: ClusterLock,
) -> StoredDeployStoragePostcheckExecution:
    now = format_timestamp(utc_now())
    attempt = DeployStoragePostcheckExecutionAttempt(
        attempt_index=scope.attempt_index,
        step_sequence=scope.step.sequence,
        stable_id=scope.prior_scope.stable_id,
        source_state=scope.source_state,
        backend=scope.backend,
        layout=scope.layout,
        capacity_bytes=scope.capacity_bytes,
        device_count=scope.device_count,
        device_set_digest=scope.device_set_digest,
        preparation_intent_digest=scope.preparation_intent_digest,
        preparation_evidence_digest=scope.preparation_evidence_digest,
        variables_digest=scope.variables_digest,
        command_digest=scope.command_digest,
        source_digest=scope.source_digest,
        state=DeployStoragePostcheckExecutionState.STARTED,
        started_at=now,
        completed_at=None,
        invocation_may_have_occurred=True,
        exit_code=None,
        result_digest=None,
        evidence_digest=None,
        readiness_for_scylla=None,
        check_status_digest=None,
        blocker_digest=None,
        manual_recovery_required=True,
        automatic_retry_allowed=False,
    )
    record = DeployStoragePostcheckExecution(
        generation=1 if current is None else current.record.generation + 1,
        created_at=now if current is None else current.record.created_at,
        updated_at=now,
        binding=context.binding,
        state=DeployStoragePostcheckExecutionState.STARTED,
        invocation_count=scope.attempt_index,
        all_scopes_completed=False,
        attempts=(() if current is None else current.record.attempts) + (attempt,),
    )
    return store.write_locked(
        record,
        expected_generation=0 if current is None else current.record.generation,
        expected_digest=None if current is None else current.artifact_digest,
        lock=lock,
    )


def _persist_uncertain_or_raise(
    store: DeployStoragePostcheckExecutionStore,
    current: StoredDeployStoragePostcheckExecution,
    state: DeployStoragePostcheckExecutionState,
    *,
    lock: ClusterLock,
) -> StoredDeployStoragePostcheckExecution:
    if current.record.state is not DeployStoragePostcheckExecutionState.STARTED:
        raise StateConflictError(
            "deploy storage-postcheck uncertain transition conflicts"
        )
    attempt = current.record.attempts[-1]
    now = format_timestamp(utc_now())
    replacement = replace(
        attempt,
        state=state,
        completed_at=now,
        manual_recovery_required=True,
        automatic_retry_allowed=False,
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=state,
        attempts=(*current.record.attempts[:-1], replacement),
    )
    return store.write_locked(
        record,
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _persist_evidence(
    context: _ExecutionContext,
    store: DeployStoragePostcheckEvidenceStore,
    current: StoredDeployStoragePostcheckEvidence | None,
    entry: DeployStoragePostcheckEvidenceEntry,
    *,
    lock: ClusterLock,
) -> StoredDeployStoragePostcheckEvidence:
    if current is not None and len(current.record.entries) >= entry.attempt_index:
        existing = current.record.entries[entry.attempt_index - 1]
        if existing != entry:
            raise StateConflictError(
                "deploy storage-postcheck evidence conflicts with existing entry"
            )
        return current
    if current is not None and len(current.record.entries) != entry.attempt_index - 1:
        raise StateConflictError("deploy storage-postcheck evidence sequence conflicts")
    now = format_timestamp(utc_now())
    record = DeployStoragePostcheckEvidence(
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


def _persist_terminal(
    context: _ExecutionContext,
    store: DeployStoragePostcheckExecutionStore,
    current: StoredDeployStoragePostcheckExecution,
    *,
    entry: DeployStoragePostcheckEvidenceEntry,
    state: DeployStoragePostcheckExecutionState,
    exit_code: int,
    lock: ClusterLock,
) -> StoredDeployStoragePostcheckExecution:
    if (
        current.record.state is not DeployStoragePostcheckExecutionState.STARTED
        or current.record.attempts[-1].attempt_index != entry.attempt_index
    ):
        raise StateConflictError(
            "deploy storage-postcheck terminal transition conflicts"
        )
    attempt = current.record.attempts[-1]
    now = format_timestamp(utc_now())
    replacement = replace(
        attempt,
        state=state,
        completed_at=now,
        result_digest=entry.result_digest,
        evidence_digest=entry.evidence_digest,
        readiness_for_scylla=entry.readiness_for_scylla,
        check_status_digest=entry.check_status_digest,
        blocker_digest=entry.blocker_digest,
        exit_code=exit_code,
        manual_recovery_required=(
            state is not DeployStoragePostcheckExecutionState.SUCCEEDED
        ),
        automatic_retry_allowed=False,
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=state,
        all_scopes_completed=(
            state is DeployStoragePostcheckExecutionState.SUCCEEDED
            and len(current.record.attempts) == context.binding.scope_count
        ),
        attempts=(*current.record.attempts[:-1], replacement),
    )
    stored = store.write_locked(
        record,
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )
    if (
        state is DeployStoragePostcheckExecutionState.SUCCEEDED
        and len(record.attempts) > context.binding.scope_count
    ):
        raise StateConflictError("deploy storage-postcheck execution scope overflow")
    return stored


def _semantic_entry(
    scope: _ExecutionScope, result: AnsibleExecutionResult
) -> DeployStoragePostcheckEvidenceEntry:
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.READ_ONLY
        or not result.check_mode
        or result.storage_postcheck is not None
        or result.storage_discovery is not None
        or result.storage_preflight is not None
        or result.storage_prepare is not None
    ):
        raise AnsibleResultError(
            "deploy storage-postcheck strict result identity conflicts"
        )
    payload = cast(
        dict[str, object],
        scope.variables["deploy_scylla_vms_storage_postcheck"],
    )
    evidence = parse_storage_postcheck_execution(
        result.stdout,
        expected_payload=payload,
        exit_code=result.exit_code,
    )
    if (
        evidence is None
        or evidence.schema_version != STORAGE_POSTCHECK_SCHEMA_VERSION
        or evidence.logical_id != scope.prior_scope.stable_id
        or evidence.backend != scope.backend
        or evidence.layout != scope.layout
    ):
        raise AnsibleResultError(
            "deploy storage-postcheck strict result identity conflicts"
        )
    identities = tuple(identity for identity, _ in evidence.devices)
    capacities = tuple(capacity for _, capacity in evidence.devices)
    if (
        not identities
        or identities != tuple(sorted(set(identities)))
        or _deploy_device_set_digest(identities) != scope.device_set_digest
        or len(identities) != scope.device_count
        or sum(capacities) != scope.capacity_bytes
        or any(capacity <= 0 for capacity in capacities)
    ):
        raise AnsibleResultError("deploy storage-postcheck device evidence conflicts")
    checks = tuple((item.name, item.status.value) for item in evidence.checks)
    check_names = tuple(name for name, _ in checks)
    if check_names != tuple(sorted(_REQUIRED_CHECKS)):
        raise AnsibleResultError(
            "deploy storage-postcheck required checks are incomplete"
        )
    passed = sum(item.status is StorageCheckStatus.PASSED for item in evidence.checks)
    failed = sum(item.status is StorageCheckStatus.FAILED for item in evidence.checks)
    unknown = sum(item.status is StorageCheckStatus.UNKNOWN for item in evidence.checks)
    blockers = tuple(sorted(evidence.blockers))
    if blockers != evidence.blockers or len(set(blockers)) != len(blockers):
        raise AnsibleResultError(
            "deploy storage-postcheck blockers are not uniquely sorted"
        )
    provenance = dict(evidence.provenance)
    required_provenance = {
        "device_set_digest": payload["prepare_device_set_digest"],
        "discovery_digest": payload["discovery_digest"],
        "inventory_digest": payload["inventory_digest"],
        "observation_digest": payload["observation_digest"],
        "policy_digest": payload["policy_digest"],
        "preflight_evidence_digest": payload["preflight_evidence_digest"],
        "preparation_evidence_digest": payload["preparation_evidence_digest"],
        "preparation_intent_digest": payload["preparation_intent_digest"],
    }
    if any(
        provenance.get(key) != value for key, value in required_provenance.items()
    ) or set(provenance) - {
        *required_provenance,
        "filesystem_uuid_digest",
        "marker_digest",
    }:
        raise AnsibleResultError(
            "deploy storage-postcheck provenance evidence conflicts"
        )
    checks_digest = _digest_object(
        [{"name": name, "status": status} for name, status in checks]
    )
    blocker_digest = _digest_object(list(blockers))
    result_value = {
        "backend": evidence.backend,
        "blocker_digest": blocker_digest,
        "capacity_bytes": sum(capacities),
        "checks_digest": checks_digest,
        "device_count": len(identities),
        "device_set_digest": scope.device_set_digest,
        "layout": evidence.layout,
        "logical_id": evidence.logical_id,
        "provenance_digest": _digest_object(provenance),
        "readiness_for_scylla": evidence.readiness_for_scylla,
        "schema_version": evidence.schema_version,
    }
    result_digest = _digest_object(result_value)
    provenance_digest = _digest_object(provenance)
    entry_values: dict[str, object] = {
        "attempt_index": scope.attempt_index,
        "step_sequence": scope.step.sequence,
        "stable_id": scope.prior_scope.stable_id,
        "source_state": scope.source_state,
        "backend": scope.backend,
        "layout": scope.layout,
        "readiness_for_scylla": evidence.readiness_for_scylla,
        "device_count": len(identities),
        "capacity_bytes": sum(capacities),
        "passed_check_count": passed,
        "failed_check_count": failed,
        "unknown_check_count": unknown,
        "blocker_count": len(blockers),
        "device_set_digest": scope.device_set_digest,
        "preparation_intent_digest": scope.preparation_intent_digest,
        "preparation_evidence_digest": scope.preparation_evidence_digest,
        "check_status_digest": checks_digest,
        "blocker_digest": blocker_digest,
        "provenance_digest": provenance_digest,
        "result_digest": result_digest,
        "evidence_digest": "",
        "manual_recovery_required": not evidence.readiness_for_scylla,
        "automatic_retry_allowed": False,
    }
    entry_values["evidence_digest"] = _evidence_entry_digest_from_values(entry_values)
    return DeployStoragePostcheckEvidenceEntry(**entry_values)  # type: ignore[arg-type]


def _terminal_state(
    entry: DeployStoragePostcheckEvidenceEntry, exit_code: int
) -> DeployStoragePostcheckExecutionState:
    if exit_code not in {0, 2, 4}:
        return DeployStoragePostcheckExecutionState.FAILED
    if (
        exit_code == 0
        and entry.readiness_for_scylla
        and entry.failed_check_count == 0
        and entry.unknown_check_count == 0
        and entry.blocker_count == 0
        and entry.passed_check_count == len(_REQUIRED_CHECKS)
    ):
        return DeployStoragePostcheckExecutionState.SUCCEEDED
    return DeployStoragePostcheckExecutionState.FAILED


def _failure_state(error: AnsibleError) -> DeployStoragePostcheckExecutionState:
    if isinstance(error, ProcessTimeoutError):
        return DeployStoragePostcheckExecutionState.TIMED_OUT
    message = str(error).lower()
    if "unreachable" in message:
        return DeployStoragePostcheckExecutionState.UNREACHABLE
    if isinstance(error, AnsibleResultError) or "malformed" in message:
        return DeployStoragePostcheckExecutionState.MALFORMED_RESULT
    return DeployStoragePostcheckExecutionState.FAILED


def _validate_prefix(
    context: _ExecutionContext,
    execution: StoredDeployStoragePostcheckExecution | None,
    evidence: StoredDeployStoragePostcheckEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "deploy storage-postcheck evidence exists without execution"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError("deploy storage-postcheck execution binding drifted")
    if len(execution.record.attempts) > context.binding.scope_count:
        raise StateConflictError(
            "deploy storage-postcheck execution has extra attempts"
        )
    for index, attempt in enumerate(execution.record.attempts, start=1):
        scope = context.scopes[index - 1]
        if (
            attempt.attempt_index != index
            or attempt.step_sequence != scope.step.sequence
            or attempt.stable_id != scope.prior_scope.stable_id
            or attempt.source_state is not scope.source_state
            or attempt.backend != scope.backend
            or attempt.layout != scope.layout
            or attempt.capacity_bytes != scope.capacity_bytes
            or attempt.device_count != scope.device_count
            or attempt.source_digest != scope.source_digest
            or attempt.variables_digest != scope.variables_digest
            or attempt.command_digest != scope.command_digest
            or attempt.device_set_digest != scope.device_set_digest
            or attempt.preparation_intent_digest != scope.preparation_intent_digest
            or attempt.preparation_evidence_digest != scope.preparation_evidence_digest
        ):
            raise StateConflictError(
                "deploy storage-postcheck attempt provenance drifted"
            )
        if index < len(execution.record.attempts) and (
            attempt.state is not DeployStoragePostcheckExecutionState.SUCCEEDED
        ):
            raise StateConflictError(
                "deploy storage-postcheck execution advanced past failed attempt"
            )
    completed_count = execution.record.succeeded_count
    if evidence is None:
        if completed_count or any(
            item.evidence_digest is not None for item in execution.record.attempts
        ):
            raise StateConflictError("deploy storage-postcheck evidence is missing")
        return
    if evidence.record.binding != context.binding:
        raise StateConflictError("deploy storage-postcheck evidence binding drifted")
    semantic_count = sum(
        item.evidence_digest is not None for item in execution.record.attempts
    )
    if len(evidence.record.entries) not in {
        semantic_count,
        semantic_count
        + (
            1
            if execution.record.state is DeployStoragePostcheckExecutionState.STARTED
            else 0
        ),
    }:
        raise StateConflictError(
            "deploy storage-postcheck execution/evidence prefix conflicts"
        )
    for index, entry in enumerate(evidence.record.entries, start=1):
        scope = context.scopes[index - 1]
        attempt = execution.record.attempts[index - 1]
        if (
            entry.attempt_index != index
            or entry.stable_id != scope.prior_scope.stable_id
            or entry.step_sequence != scope.step.sequence
            or entry.source_state is not scope.source_state
            or entry.device_set_digest != scope.device_set_digest
            or entry.preparation_intent_digest != scope.preparation_intent_digest
            or entry.preparation_evidence_digest != scope.preparation_evidence_digest
            or (
                attempt.state is not DeployStoragePostcheckExecutionState.STARTED
                and (
                    attempt.evidence_digest != entry.evidence_digest
                    or attempt.result_digest != entry.result_digest
                )
            )
        ):
            raise StateConflictError("deploy storage-postcheck evidence prefix drifted")


def _validate_execution_transition(
    previous: DeployStoragePostcheckExecution,
    current: DeployStoragePostcheckExecution,
) -> None:
    if previous.state is DeployStoragePostcheckExecutionState.STARTED:
        if (
            len(current.attempts) != len(previous.attempts)
            or current.attempts[:-1] != previous.attempts[:-1]
            or current.attempts[-1].state
            is DeployStoragePostcheckExecutionState.STARTED
        ):
            raise StateConflictError(
                "deploy storage-postcheck started transition is invalid"
            )
    elif previous.state is DeployStoragePostcheckExecutionState.SUCCEEDED:
        if (
            len(current.attempts) != len(previous.attempts) + 1
            or current.attempts[:-1] != previous.attempts
            or current.attempts[-1].state
            is not DeployStoragePostcheckExecutionState.STARTED
        ):
            raise StateConflictError(
                "deploy storage-postcheck next attempt transition is invalid"
            )
    else:
        raise StateConflictError(
            "deploy storage-postcheck terminal failure cannot transition"
        )


def _build_execution_report(
    context: _ExecutionContext,
    execution: StoredDeployStoragePostcheckExecution,
    evidence: StoredDeployStoragePostcheckEvidence,
    *,
    execution_state: DeployStoragePostcheckArtifactState,
    evidence_state: DeployStoragePostcheckArtifactState,
) -> DeployStoragePostcheckExecutionReport:
    entries = evidence.record.entries
    return DeployStoragePostcheckExecutionReport(
        operation_id=context.binding.operation_id,
        execution_artifact_state=execution_state,
        evidence_artifact_state=evidence_state,
        execution_state=execution.record.state,
        execution_artifact_digest=execution.artifact_digest,
        evidence_artifact_digest=evidence.artifact_digest,
        binding_digest=context.binding.binding_digest,
        invocation_count=len(execution.record.attempts),
        scope_count=context.binding.scope_count,
        target_set_digest=context.binding.stable_id_set_digest,
        succeeded_count=execution.record.succeeded_count,
        prepared_source_count=sum(
            item.source_state is DeployPostStoragePrepareOutcomeState.PREPARE_SUCCEEDED
            for item in entries
        ),
        owned_noop_source_count=sum(
            item.source_state is DeployPostStoragePrepareOutcomeState.OWNED_NOOP_CURRENT
            for item in entries
        ),
        device_count=sum(item.device_count for item in entries),
        capacity_bytes=sum(item.capacity_bytes for item in entries),
        result_digest=_digest_object([item.result_digest for item in entries]),
        evidence_digest=_digest_object([item.evidence_digest for item in entries]),
        check_status_digest=_digest_object(
            [item.check_status_digest for item in entries]
        ),
        blocker_digest=_digest_object([item.blocker_digest for item in entries]),
        manual_recovery_required=execution.record.manual_recovery_required,
        automatic_retry_allowed=execution.record.automatic_retry_allowed,
        journal_status=context.binding.journal_status,
        journal_phase=context.binding.journal_phase,
    )


def _validate_existing_post_storage_postcheck_reconciliation(
    paths: StatePaths,
    operation_id: uuid.UUID,
    prior: StoredDeployPostStoragePrepareReconciliation,
    execution: StoredDeployStoragePostcheckExecution,
    evidence: StoredDeployStoragePostcheckEvidence,
    *,
    lock: ClusterLock,
) -> None:
    store = DeployPostStoragePostcheckReconciliationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    if not store.path.exists():
        return
    current = store.read_locked(
        lock,
        expected_cluster_uuid=prior.record.cluster_uuid,
        expected_cluster_name=prior.record.cluster_name,
    )
    steps = _build_post_storage_postcheck_steps(prior, evidence)
    expected = _build_post_storage_postcheck_record(
        prior,
        execution,
        evidence,
        steps=steps,
        created_at=current.record.created_at,
    )
    if current.record != expected:
        raise StateConflictError(
            "post-storage-postcheck reconciliation conflicts with execution"
        )


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    return _digest_object(
        {
            key: (
                value.value
                if isinstance(value, (JournalStatus, OperationPhase))
                else str(value)
                if isinstance(value, uuid.UUID)
                else value
            )
            for key, value in values.items()
            if not key.endswith("schema_version")
        }
        | {"binding_digest": ""}
    )


def _binding_digest(binding: DeployStoragePostcheckExecutionBinding) -> str:
    value = {
        key: item
        for key, item in binding.to_object().items()
        if not key.endswith("schema_version")
    }
    value["binding_digest"] = ""
    return _digest_object(value)


def _evidence_entry_digest_from_values(values: Mapping[str, object]) -> str:
    return _digest_object(
        {
            key: value.value if isinstance(value, StrEnum) else value
            for key, value in values.items()
            if not key.endswith("schema_version")
        }
        | {"evidence_digest": ""}
    )


def _entry_digest(entry: DeployStoragePostcheckEvidenceEntry) -> str:
    value = {
        key: item
        for key, item in entry.to_object().items()
        if not key.endswith("schema_version")
    }
    value["evidence_digest"] = ""
    return _digest_object(value)


def _dataclass_object(value: object) -> dict[str, object]:
    return {
        name: (
            item.value
            if isinstance((item := getattr(value, name)), StrEnum)
            else str(item)
            if isinstance(item, uuid.UUID)
            else item
        )
        for name in value.__dataclass_fields__  # type: ignore[attr-defined]
    }


def _deploy_device_set_digest(identities: tuple[str, ...]) -> str:
    if (
        not identities
        or identities != tuple(sorted(set(identities)))
        or any(
            re.fullmatch(r"device-sha256:[0-9a-f]{64}", item) is None
            for item in identities
        )
    ):
        raise AnsibleResultError(
            "deploy storage-postcheck device identities are invalid"
        )
    return _digest_object(list(identities))


def _digest_fields(value: object) -> tuple[str, ...]:
    return tuple(
        item
        for name in value.__dataclass_fields__  # type: ignore[attr-defined]
        if (name.endswith("_digest") or name == "binding_digest")
        and isinstance((item := getattr(value, name)), str)
    )


def _operation_path(paths: StatePaths, operation_id: uuid.UUID, suffix: str) -> Path:
    operation_id = _require_operation_id(operation_id)
    return paths.operations / f"{operation_id}{suffix}"


def _operation_id_from_filename(name: str, suffix: str) -> uuid.UUID | None:
    if not name.endswith(suffix):
        return None
    try:
        return _require_operation_id(uuid.UUID(name[: -len(suffix)]))
    except (ValueError, StatePersistenceError):
        return None


def _require_operation_id(value: uuid.UUID) -> uuid.UUID:
    if value.version != 4 or value.variant != uuid.RFC_4122:
        raise StatePersistenceError(
            "deploy storage-postcheck operation ID must be an RFC 4122 UUIDv4"
        )
    return value


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError("deploy storage-postcheck paths must be canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy storage-postcheck requires the matching held operation lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_or_later_artifacts(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> None:
    known = {
        DEPLOY_STORAGE_POSTCHECK_EXECUTION_FILENAME_SUFFIX,
        DEPLOY_STORAGE_POSTCHECK_EVIDENCE_FILENAME_SUFFIX,
        DEPLOY_POST_STORAGE_POSTCHECK_RECONCILIATION_FILENAME_SUFFIX,
    }
    prefix = f"{operation_id}."
    for child in paths.operations.iterdir():
        if (
            child.name.startswith(prefix)
            and "storage-postcheck" in child.name
            and not any(child.name == f"{operation_id}{suffix}" for suffix in known)
        ):
            raise StateConflictError(
                "ambiguous deploy storage-postcheck operation artifact exists"
            )


@dataclass(frozen=True, slots=True)
class DeployPostStoragePostcheckReconciliation:
    generation: int
    created_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    prior_reconciliation_artifact_digest: str
    prior_reconciliation_record_digest: str
    prior_effective_plan_digest: str
    execution_artifact_digest: str
    execution_binding_digest: str
    evidence_artifact_digest: str
    evidence_binding_digest: str
    target_count: int
    target_set_digest: str
    prepared_source_count: int
    owned_noop_source_count: int
    device_count: int
    capacity_bytes: int
    result_digest: str
    evidence_digest: str
    check_status_digest: str
    blocker_digest: str
    steps: tuple[DeployBaseOsReconciledStep, ...]
    step_count: int
    succeeded_count: int
    authorization_required_count: int
    eligible_count: int
    plan_blocked_count: int
    not_performed_count: int
    next_playbook: str
    next_target_count: int
    next_target_set_digest: str
    effective_plan_digest: str
    finalization_state: str
    public_workflow_state: str
    record_digest: str
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EVIDENCE_SCHEMA_VERSION
    )
    prior_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_POSTCHECK_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_POSTCHECK_RECONCILIATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EVIDENCE_SCHEMA_VERSION
            or self.prior_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.target_count < 1
            or self.target_count
            != self.prepared_source_count + self.owned_noop_source_count
            or self.device_count < self.target_count
            or self.capacity_bytes < self.device_count
            or self.next_playbook != "scylla-install"
            or self.next_target_count != self.target_count
            or self.step_count != len(self.steps)
            or self.finalization_state != "not-started"
            or self.public_workflow_state != "unavailable"
        ):
            raise StatePersistenceError(
                "post-storage-postcheck reconciliation identity is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        counts = Counter(step.status for step in self.steps)
        if (
            self.succeeded_count != counts[DeployBaseOsReconciledStepStatus.SUCCEEDED]
            or self.authorization_required_count
            != counts[
                DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            ]
            or self.eligible_count != counts[DeployBaseOsReconciledStepStatus.ELIGIBLE]
            or self.plan_blocked_count
            != counts[DeployBaseOsReconciledStepStatus.BLOCKED]
            or self.not_performed_count
            != counts[DeployBaseOsReconciledStepStatus.NOT_PERFORMED]
            or self.next_target_set_digest
            != _digest_object(
                sorted(
                    target
                    for step in self.steps
                    if step.playbook == self.next_playbook
                    and step.status
                    is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
                    for target in step.target_ids
                )
            )
            or self.effective_plan_digest
            != _digest_object([step.to_object() for step in self.steps])
            or self.record_digest != _postcheck_reconciliation_record_digest(self)
        ):
            raise StatePersistenceError(
                "post-storage-postcheck reconciliation summary conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(value, "post-storage-postcheck reconciliation digest")

    def to_object(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            result[name] = (
                [item.to_object() for item in value]
                if name == "steps"
                else value.value
                if isinstance(value, StrEnum)
                else str(value)
                if isinstance(value, uuid.UUID)
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployPostStoragePostcheckReconciliation:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "post-storage-postcheck reconciliation",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "target_count",
            "prepared_source_count",
            "owned_noop_source_count",
            "device_count",
            "capacity_bytes",
            "step_count",
            "succeeded_count",
            "authorization_required_count",
            "eligible_count",
            "plan_blocked_count",
            "not_performed_count",
            "next_target_count",
        }
        kwargs: dict[str, object] = {}
        for name in cls.__dataclass_fields__:
            raw = value[name]
            if name in integer_fields:
                kwargs[name] = _integer(raw, name)
            elif name in {"cluster_uuid", "operation_id"}:
                kwargs[name] = parse_uuid(
                    require_string(value, name), name.replace("_", " ")
                )
            elif name == "journal_status":
                kwargs[name] = JournalStatus(require_string(value, name))
            elif name == "journal_phase":
                kwargs[name] = OperationPhase(require_string(value, name))
            elif name == "steps":
                if not isinstance(raw, list):
                    raise StatePersistenceError(
                        "post-storage-postcheck steps must be a list"
                    )
                kwargs[name] = tuple(
                    DeployBaseOsReconciledStep.from_object(_mapping(item, "step"))
                    for item in raw
                )
            else:
                kwargs[name] = require_string(value, name)
        return cls(**kwargs)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployPostStoragePostcheckReconciliation:
    record: DeployPostStoragePostcheckReconciliation
    artifact_digest: str


class DeployPostStoragePostcheckReconciliationStore:
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
        self._path = deploy_post_storage_postcheck_reconciliation_path(
            paths, operation_id
        )
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPostStoragePostcheckReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def read(
        self,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPostStoragePostcheckReconciliation:
        value, digest = self._file.read()
        record = DeployPostStoragePostcheckReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "post-storage-postcheck reconciliation identity conflicts"
            )
        return StoredDeployPostStoragePostcheckReconciliation(record, digest)

    def write_locked(
        self,
        record: DeployPostStoragePostcheckReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployPostStoragePostcheckReconciliation,
        DeployStoragePostcheckArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "post-storage-postcheck reconciliation is immutable"
                )
            return current, DeployStoragePostcheckArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployPostStoragePostcheckReconciliation(record, digest),
            DeployStoragePostcheckArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployPostStoragePostcheckReconciliationReport:
    operation_id: uuid.UUID
    artifact_state: DeployStoragePostcheckArtifactState
    reconciliation_artifact_digest: str
    reconciliation_record_digest: str
    effective_plan_digest: str
    target_count: int
    target_set_digest: str
    prepared_source_count: int
    owned_noop_source_count: int
    device_count: int
    capacity_bytes: int
    succeeded_count: int
    authorization_required_count: int
    eligible_count: int
    blocked_count: int
    not_performed_count: int
    next_playbook: str
    next_target_count: int
    next_target_set_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_POSTCHECK_RECONCILIATION_REPORT_SCHEMA_VERSION
    )

    def to_object(self) -> dict[str, object]:
        return {
            "artifact": {
                "digest": self.reconciliation_artifact_digest,
                "state": self.artifact_state.value,
            },
            "counts": {
                "authorization_required": self.authorization_required_count,
                "blocked": self.blocked_count,
                "eligible": self.eligible_count,
                "not_performed": self.not_performed_count,
                "succeeded": self.succeeded_count,
            },
            "effective_plan_digest": self.effective_plan_digest,
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "next_gate": {
                "playbook": self.next_playbook,
                "target_count": self.next_target_count,
                "target_set_digest": self.next_target_set_digest,
            },
            "operation_id": str(self.operation_id),
            "record_digest": self.reconciliation_record_digest,
            "schema_version": self.schema_version,
            "storage_postcheck": {
                "capacity_bytes": self.capacity_bytes,
                "device_count": self.device_count,
                "owned_noop_source_count": self.owned_noop_source_count,
                "prepared_source_count": self.prepared_source_count,
                "target_count": self.target_count,
                "target_set_digest": self.target_set_digest,
            },
        }


def reconcile_deploy_storage_postcheck(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployPostStoragePostcheckReconciliationReport:
    """Bind complete successful postcheck evidence and expose only install approval."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _refuse_ambiguous_or_later_artifacts(paths, operation_id)
    prior_store = DeployPostStoragePrepareReconciliationStore(paths, operation_id)
    prior = prior_store.read_locked(
        lock,
        expected_cluster_uuid=_cluster_uuid(paths),
        expected_cluster_name=cluster_name,
    )
    current_context = _load_post_storage_prepare_context(paths, operation_id, lock=lock)
    expected_prior = _build_post_storage_prepare_record(
        current_context,
        steps=_build_post_storage_prepare_steps(current_context),
        created_at=prior.record.created_at,
    )
    if prior.record != expected_prior:
        raise StateConflictError(
            "post-storage-postcheck prior chain is stale or drifted"
        )
    execution_store = DeployStoragePostcheckExecutionStore(paths, operation_id)
    evidence_store = DeployStoragePostcheckEvidenceStore(paths, operation_id)
    for path in (execution_store.path, evidence_store.path):
        validate_state_file(path, allow_missing=False)
    execution = execution_store.read_locked(
        lock,
        expected_cluster_uuid=prior.record.cluster_uuid,
        expected_cluster_name=prior.record.cluster_name,
    )
    evidence = evidence_store.read_locked(
        lock,
        expected_cluster_uuid=prior.record.cluster_uuid,
        expected_cluster_name=prior.record.cluster_name,
    )
    if (
        execution.record.binding.prior_reconciliation_artifact_digest
        != prior.artifact_digest
        or execution.record.binding.prior_reconciliation_record_digest
        != prior.record.record_digest
        or evidence.record.binding != execution.record.binding
        or not execution.record.all_scopes_completed
        or len(evidence.record.entries) != execution.record.binding.scope_count
        or any(
            not item.readiness_for_scylla
            or item.failed_check_count
            or item.unknown_check_count
            or item.blocker_count
            for item in evidence.record.entries
        )
    ):
        raise StateConflictError(
            "post-storage-postcheck reconciliation requires complete current evidence"
        )
    steps = _build_post_storage_postcheck_steps(prior, evidence)
    store = DeployPostStoragePostcheckReconciliationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    existing = (
        store.read_locked(
            lock,
            expected_cluster_uuid=prior.record.cluster_uuid,
            expected_cluster_name=prior.record.cluster_name,
        )
        if store.path.exists()
        else None
    )
    record = _build_post_storage_postcheck_record(
        prior,
        execution,
        evidence,
        steps=steps,
        created_at=None if existing is None else existing.record.created_at,
    )
    stored, state = store.write_locked(record, lock=lock)
    return _post_storage_postcheck_report(stored, state)


def deploy_post_storage_postcheck_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    return _operation_path(
        paths,
        operation_id,
        DEPLOY_POST_STORAGE_POSTCHECK_RECONCILIATION_FILENAME_SUFFIX,
    )


def deploy_post_storage_postcheck_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_POST_STORAGE_POSTCHECK_RECONCILIATION_FILENAME_SUFFIX
    )


def _build_post_storage_postcheck_steps(
    prior: StoredDeployPostStoragePrepareReconciliation,
    evidence: StoredDeployStoragePostcheckEvidence,
) -> tuple[DeployBaseOsReconciledStep, ...]:
    entries = {item.stable_id: item for item in evidence.record.entries}
    if tuple(entries) != tuple(sorted(entries)):
        raise StateConflictError("post-storage-postcheck evidence order conflicts")
    result: list[DeployBaseOsReconciledStep] = []
    postcheck_seen: set[str] = set()
    install_started = False
    for step in prior.record.steps:
        prior_digest = _digest_object(step.to_object())
        if (
            step.mapping_sequence == _MAPPING_SEQUENCE
            and step.condition_state is DeployConditionState.ACTIVE
        ):
            stable_id = step.target_ids[0]
            entry = entries.get(stable_id)
            if (
                step.playbook != _PLAYBOOK
                or step.status is not DeployBaseOsReconciledStepStatus.ELIGIBLE
                or entry is None
            ):
                raise StateConflictError(
                    "post-storage-postcheck executed scope drifted"
                )
            postcheck_seen.add(stable_id)
            result.append(
                replace(
                    step,
                    prior_reconciled_step_digest=prior_digest,
                    status=DeployBaseOsReconciledStepStatus.SUCCEEDED,
                    evidence_state=(
                        DeployBaseOsReconciledEvidenceState.STORAGE_POSTCHECK_BOUND
                    ),
                    evidence_digest=entry.evidence_digest,
                    blockers=(),
                )
            )
            continue
        if (
            step.mapping_sequence == _MAPPING_SEQUENCE + 1
            and step.condition_state is DeployConditionState.ACTIVE
        ):
            if step.playbook != "scylla-install":
                raise StateConflictError(
                    "post-storage-postcheck immediate next gate drifted"
                )
            if step.status not in {
                DeployBaseOsReconciledStepStatus.BLOCKED,
                DeployBaseOsReconciledStepStatus.NOT_PERFORMED,
            } or set(step.target_ids) - set(entries):
                raise StateConflictError(
                    "post-storage-postcheck install gate conflicts"
                )
            install_started = True
            result.append(
                replace(
                    step,
                    prior_reconciled_step_digest=prior_digest,
                    status=(
                        DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
                    ),
                    evidence_state=(
                        DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED
                    ),
                    evidence_digest=_digest_object(
                        {
                            "playbook": step.playbook,
                            "step_digest": prior_digest,
                            "targets": [
                                entries[target].evidence_digest
                                for target in step.target_ids
                            ],
                        }
                    ),
                    blockers=(
                        "deploy-authorization-not-collected",
                        "mutating-deploy-execution-unavailable",
                        "public-deploy-workflow-unavailable",
                    ),
                )
            )
            continue
        if step.mapping_sequence > _MAPPING_SEQUENCE + 1 and step.status in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }:
            raise StateConflictError(
                "post-storage-postcheck refuses a later-gate leapfrog"
            )
        result.append(replace(step, prior_reconciled_step_digest=prior_digest))
    if postcheck_seen != set(entries) or not install_started:
        raise StateConflictError(
            "post-storage-postcheck scope or immediate next gate is incomplete"
        )
    return tuple(result)


def _build_post_storage_postcheck_record(
    prior: StoredDeployPostStoragePrepareReconciliation,
    execution: StoredDeployStoragePostcheckExecution,
    evidence: StoredDeployStoragePostcheckEvidence,
    *,
    steps: tuple[DeployBaseOsReconciledStep, ...],
    created_at: str | None = None,
) -> DeployPostStoragePostcheckReconciliation:
    entries = evidence.record.entries
    counts = Counter(step.status for step in steps)
    next_targets = sorted(
        target
        for step in steps
        if step.playbook == "scylla-install"
        and step.status
        is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        for target in step.target_ids
    )
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at or format_timestamp(utc_now()),
        "cluster_uuid": prior.record.cluster_uuid,
        "cluster_name": prior.record.cluster_name,
        "operation_id": prior.record.operation_id,
        "operation": prior.record.operation,
        "request_digest": prior.record.request_digest,
        "journal_generation": prior.record.journal_generation,
        "journal_digest": prior.record.journal_digest,
        "journal_status": prior.record.journal_status,
        "journal_phase": prior.record.journal_phase,
        "prior_reconciliation_artifact_digest": prior.artifact_digest,
        "prior_reconciliation_record_digest": prior.record.record_digest,
        "prior_effective_plan_digest": prior.record.effective_plan_digest,
        "execution_artifact_digest": execution.artifact_digest,
        "execution_binding_digest": execution.record.binding.binding_digest,
        "evidence_artifact_digest": evidence.artifact_digest,
        "evidence_binding_digest": evidence.record.binding.binding_digest,
        "target_count": len(entries),
        "target_set_digest": _digest_object([item.stable_id for item in entries]),
        "prepared_source_count": sum(
            item.source_state is DeployPostStoragePrepareOutcomeState.PREPARE_SUCCEEDED
            for item in entries
        ),
        "owned_noop_source_count": sum(
            item.source_state is DeployPostStoragePrepareOutcomeState.OWNED_NOOP_CURRENT
            for item in entries
        ),
        "device_count": sum(item.device_count for item in entries),
        "capacity_bytes": sum(item.capacity_bytes for item in entries),
        "result_digest": _digest_object([item.result_digest for item in entries]),
        "evidence_digest": _digest_object([item.evidence_digest for item in entries]),
        "check_status_digest": _digest_object(
            [item.check_status_digest for item in entries]
        ),
        "blocker_digest": _digest_object([item.blocker_digest for item in entries]),
        "steps": steps,
        "step_count": len(steps),
        "succeeded_count": counts[DeployBaseOsReconciledStepStatus.SUCCEEDED],
        "authorization_required_count": counts[
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        ],
        "eligible_count": counts[DeployBaseOsReconciledStepStatus.ELIGIBLE],
        "plan_blocked_count": counts[DeployBaseOsReconciledStepStatus.BLOCKED],
        "not_performed_count": counts[DeployBaseOsReconciledStepStatus.NOT_PERFORMED],
        "next_playbook": "scylla-install",
        "next_target_count": len(next_targets),
        "next_target_set_digest": _digest_object(next_targets),
        "effective_plan_digest": _digest_object([step.to_object() for step in steps]),
        "finalization_state": "not-started",
        "public_workflow_state": "unavailable",
        "record_digest": "",
    }
    values["record_digest"] = _postcheck_reconciliation_digest_from_values(values)
    return DeployPostStoragePostcheckReconciliation(
        **values  # type: ignore[arg-type]
    )


def _post_storage_postcheck_report(
    stored: StoredDeployPostStoragePostcheckReconciliation,
    state: DeployStoragePostcheckArtifactState,
) -> DeployPostStoragePostcheckReconciliationReport:
    record = stored.record
    return DeployPostStoragePostcheckReconciliationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        reconciliation_artifact_digest=stored.artifact_digest,
        reconciliation_record_digest=record.record_digest,
        effective_plan_digest=record.effective_plan_digest,
        target_count=record.target_count,
        target_set_digest=record.target_set_digest,
        prepared_source_count=record.prepared_source_count,
        owned_noop_source_count=record.owned_noop_source_count,
        device_count=record.device_count,
        capacity_bytes=record.capacity_bytes,
        succeeded_count=record.succeeded_count,
        authorization_required_count=record.authorization_required_count,
        eligible_count=record.eligible_count,
        blocked_count=record.plan_blocked_count,
        not_performed_count=record.not_performed_count,
        next_playbook=record.next_playbook,
        next_target_count=record.next_target_count,
        next_target_set_digest=record.next_target_set_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
    )


def _postcheck_reconciliation_record_digest(
    record: DeployPostStoragePostcheckReconciliation,
) -> str:
    value = {
        key: item
        for key, item in record.to_object().items()
        if not key.endswith("schema_version")
    }
    value["record_digest"] = ""
    return _digest_object(value)


def _postcheck_reconciliation_digest_from_values(
    values: Mapping[str, object],
) -> str:
    result: dict[str, object] = {}
    for key, value in values.items():
        if key == "record_digest" or key.endswith("schema_version"):
            continue
        if key == "steps":
            if not isinstance(value, tuple) or not all(
                isinstance(item, DeployBaseOsReconciledStep) for item in value
            ):
                raise StatePersistenceError("post-storage-postcheck steps are invalid")
            result[key] = [
                cast(DeployBaseOsReconciledStep, item).to_object() for item in value
            ]
        elif isinstance(value, StrEnum):
            result[key] = value.value
        elif isinstance(value, uuid.UUID):
            result[key] = str(value)
        else:
            result[key] = value
    result["record_digest"] = ""
    return _digest_object(result)


def _cluster_uuid(paths: StatePaths) -> uuid.UUID:
    return (
        ClusterMetadataStore(paths)
        .read(expected_cluster_name=paths.cluster_root.name)
        .record.cluster_uuid
    )


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StatePersistenceError(f"{label} must be a non-negative integer")
    return value


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise StatePersistenceError(f"{label} must be an object")
    return value


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise StatePersistenceError(f"{label} must be a list")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be a boolean")
    return value


def _optional_boolean(value: object, label: str) -> bool | None:
    if value is None:
        return None
    return _boolean(value, label)


def _optional_integer(value: object, label: str) -> int | None:
    if value is None:
        return None
    return _integer(value, label)


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise StatePersistenceError(f"{label} must be a non-empty string or null")
    return value


def _optional_timestamp(value: str | None) -> datetime | None:
    return None if value is None else parse_timestamp(value)


def _positive_integer(value: object, label: str) -> int:
    result = _integer(value, label)
    if result < 1:
        raise StatePersistenceError(f"{label} must be positive")
    return result


def _enum(enum_type: type[StrEnum], value: str, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except ValueError as error:
        raise StatePersistenceError(f"{label} is invalid") from error


def _validate_toolchain_version(value: str) -> None:
    try:
        parse_ansible_core_version(
            f"ansible-playbook [core {value}]\n",
            expected_executable="ansible-playbook",
        )
    except AnsibleVersionError as error:
        raise StatePersistenceError(
            "deploy storage-postcheck toolchain version is invalid"
        ) from error


def utc_now() -> datetime:
    return datetime.now(UTC)
