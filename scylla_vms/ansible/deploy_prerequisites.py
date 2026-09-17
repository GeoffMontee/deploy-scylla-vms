"""Deploy-only execution of the two reviewed read-only Ansible prerequisites.

The generic operation execution schema is intentionally PLAN-phase-bound.
Deploy has already crossed Terraform apply and remains in VERIFY, so this
module owns separate intent-before-effect execution and semantic-evidence
companions without changing the common journal or enabling the public workflow.
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
from scylla_vms.ansible.deploy_plan import (
    ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION,
    DeployAnsibleContextStore,
    DeployAnsiblePlanStep,
    DeployAnsiblePlanStore,
    DeployIntentContext,
    StoredDeployAnsibleContext,
    StoredDeployAnsiblePlan,
    _assert_operation_lock,
    _build_context,
    _build_plan,
    _build_steps,
    _DeployPlanningContext,
    _load_deploy_planning_context,
    _playbook_source_digest,
    _require_operation_id,
    _safe_variable_values,
)
from scylla_vms.ansible.operation_binding import readiness_binding_digest
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.operation_evidence import (
    CONNECTIVITY_PROJECTION_SCHEMA_VERSION,
)
from scylla_vms.ansible.operation_execution import (
    ExecutionAttempt,
    ExecutionAttemptState,
)
from scylla_vms.ansible.orchestration import ansible_operation_catalog_digest
from scylla_vms.ansible.registry import (
    CheckMode,
    LimitPolicy,
    get_playbook,
)
from scylla_vms.ansible.service import (
    AnsibleExecutionResult,
    AnsibleResultError,
    AnsibleService,
    ConnectivityEvidence,
    ConnectivityStatus,
    HostConnectivityStatus,
    InventoryPreflightEvidence,
    ProcessRunnerProtocol,
)
from scylla_vms.ansible.source import (
    ANSIBLE_SOURCE_VERSION,
    AnsibleSourceBundle,
    load_ansible_source_bundle,
)
from scylla_vms.ansible.toolchain import (
    AnsibleToolchain,
    AnsibleVersionError,
    parse_ansible_core_version,
)
from scylla_vms.errors import (
    AnsibleError,
    StateConflictError,
    StatePersistenceError,
)
from scylla_vms.journal import JOURNAL_SCHEMA_VERSION, JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import (
    AtomicJsonFile,
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

ANSIBLE_DEPLOY_PREREQUISITE_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-prerequisite-execution/v1"
)
ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-prerequisite-evidence/v1"
)
ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_ENTRY_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-prerequisite-evidence-entry/v1"
)
ANSIBLE_DEPLOY_PREREQUISITE_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-prerequisite-report/v1"
)
DEPLOY_PREREQUISITE_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-prerequisite-execution.json"
)
DEPLOY_PREREQUISITE_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-prerequisite-evidence.json"
)

_OPERATION = "deploy"
_READY = "deploy-prerequisites-ready"
_REQUIRED_PLAYBOOKS = ("inventory-preflight", "connectivity-check")
_RESULT_SCHEMAS = (
    "deploy-scylla-vms.ansible-inventory-preflight/v1",
    CONNECTIVITY_PROJECTION_SCHEMA_VERSION,
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class DeployPrerequisiteEvidenceStatus(StrEnum):
    """Bounded semantic result status for one prerequisite."""

    PASSED = "passed"
    FAILED = "failed"
    UNREACHABLE = "unreachable"


@dataclass(frozen=True, slots=True)
class DeployPrerequisiteExecution:
    """Durable intent and terminal state for at most two exact steps."""

    generation: int
    created_at: str
    updated_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    context_artifact_digest: str
    context_record_digest: str
    plan_artifact_digest: str
    plan_record_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    catalog_digest: str
    source_version: str
    source_digest: str
    toolchain_version: str
    executable_identity_digest: str
    toolchain_evidence_digest: str
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    trust_generation: int
    trust_artifact_digest: str
    trust_entries_digest: str
    host_count: int
    host_set_digest: str
    route_digest: str
    required_step_count: int
    state: ExecutionAttemptState
    all_steps_completed: bool
    attempts: tuple[ExecutionAttempt, ...]
    context_schema_version: str = ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
    plan_schema_version: str = ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_PREREQUISITE_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_PREREQUISITE_EXECUTION_SCHEMA_VERSION
            or self.context_schema_version != ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
            or self.plan_schema_version != ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or self.required_step_count != len(_REQUIRED_PLAYBOOKS)
        ):
            raise StatePersistenceError(
                "deploy prerequisite execution provenance is unsupported"
            )
        _positive_integer(self.generation, "execution generation")
        _positive_integer(self.journal_generation, "journal generation")
        _positive_integer(self.inventory_generation, "inventory generation")
        _positive_integer(self.trust_generation, "trust generation")
        _positive_integer(self.host_count, "host count")
        if not isinstance(self.cluster_uuid, uuid.UUID) or not isinstance(
            self.operation_id, uuid.UUID
        ):
            raise StatePersistenceError(
                "deploy prerequisite execution identities are invalid"
            )
        validate_cluster_name(self.cluster_name)
        _validate_toolchain_version(self.toolchain_version)
        created = parse_timestamp(self.created_at)
        updated = parse_timestamp(self.updated_at)
        if updated < created:
            raise StatePersistenceError(
                "deploy prerequisite execution timestamp regressed"
            )
        for value in _execution_binding_digests(self):
            validate_digest(value, "deploy prerequisite execution digest")
        if not isinstance(self.state, ExecutionAttemptState):
            raise StatePersistenceError(
                "deploy prerequisite execution state is invalid"
            )
        if not isinstance(self.all_steps_completed, bool):
            raise StatePersistenceError(
                "deploy prerequisite completion state is invalid"
            )
        _validate_execution_attempts(
            self.attempts,
            state=self.state,
            all_steps_completed=self.all_steps_completed,
        )

    def to_object(self) -> dict[str, object]:
        return {
            "all_steps_completed": self.all_steps_completed,
            "attempts": [attempt.to_object() for attempt in self.attempts],
            "catalog_digest": self.catalog_digest,
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "context_artifact_digest": self.context_artifact_digest,
            "context_record_digest": self.context_record_digest,
            "context_schema_version": self.context_schema_version,
            "created_at": self.created_at,
            "executable_identity_digest": self.executable_identity_digest,
            "generation": self.generation,
            "host_count": self.host_count,
            "host_set_digest": self.host_set_digest,
            "inventory_artifact_digest": self.inventory_artifact_digest,
            "inventory_digest": self.inventory_digest,
            "inventory_generation": self.inventory_generation,
            "journal_digest": self.journal_digest,
            "journal_generation": self.journal_generation,
            "journal_phase": self.journal_phase.value,
            "journal_schema_version": self.journal_schema_version,
            "journal_status": self.journal_status.value,
            "operation": self.operation,
            "operation_id": str(self.operation_id),
            "plan_artifact_digest": self.plan_artifact_digest,
            "plan_record_digest": self.plan_record_digest,
            "plan_schema_version": self.plan_schema_version,
            "readiness_artifact_digest": self.readiness_artifact_digest,
            "readiness_record_digest": self.readiness_record_digest,
            "readiness_schema_version": self.readiness_schema_version,
            "request_digest": self.request_digest,
            "required_step_count": self.required_step_count,
            "route_digest": self.route_digest,
            "schema_version": self.schema_version,
            "source_digest": self.source_digest,
            "source_version": self.source_version,
            "state": self.state.value,
            "toolchain_evidence_digest": self.toolchain_evidence_digest,
            "toolchain_version": self.toolchain_version,
            "trust_artifact_digest": self.trust_artifact_digest,
            "trust_entries_digest": self.trust_entries_digest,
            "trust_generation": self.trust_generation,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployPrerequisiteExecution:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy prerequisite execution",
        )
        attempts_value = value["attempts"]
        if not isinstance(attempts_value, list) or not all(
            isinstance(item, dict) for item in attempts_value
        ):
            raise StatePersistenceError(
                "deploy prerequisite execution attempts are invalid"
            )
        try:
            state = ExecutionAttemptState(require_string(value, "state"))
            journal_status = JournalStatus(require_string(value, "journal_status"))
            journal_phase = OperationPhase(require_string(value, "journal_phase"))
        except ValueError as error:
            raise StatePersistenceError(
                "deploy prerequisite execution enum is invalid"
            ) from error
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
            request_digest=require_string(value, "request_digest"),
            journal_generation=_integer(
                value["journal_generation"], "journal generation"
            ),
            journal_digest=require_string(value, "journal_digest"),
            journal_status=journal_status,
            journal_phase=journal_phase,
            context_artifact_digest=require_string(value, "context_artifact_digest"),
            context_record_digest=require_string(value, "context_record_digest"),
            plan_artifact_digest=require_string(value, "plan_artifact_digest"),
            plan_record_digest=require_string(value, "plan_record_digest"),
            readiness_artifact_digest=require_string(
                value, "readiness_artifact_digest"
            ),
            readiness_record_digest=require_string(value, "readiness_record_digest"),
            catalog_digest=require_string(value, "catalog_digest"),
            source_version=require_string(value, "source_version"),
            source_digest=require_string(value, "source_digest"),
            toolchain_version=require_string(value, "toolchain_version"),
            executable_identity_digest=require_string(
                value, "executable_identity_digest"
            ),
            toolchain_evidence_digest=require_string(
                value, "toolchain_evidence_digest"
            ),
            inventory_generation=_integer(
                value["inventory_generation"], "inventory generation"
            ),
            inventory_artifact_digest=require_string(
                value, "inventory_artifact_digest"
            ),
            inventory_digest=require_string(value, "inventory_digest"),
            trust_generation=_integer(value["trust_generation"], "trust generation"),
            trust_artifact_digest=require_string(value, "trust_artifact_digest"),
            trust_entries_digest=require_string(value, "trust_entries_digest"),
            host_count=_integer(value["host_count"], "host count"),
            host_set_digest=require_string(value, "host_set_digest"),
            route_digest=require_string(value, "route_digest"),
            required_step_count=_integer(
                value["required_step_count"], "required step count"
            ),
            state=state,
            all_steps_completed=_boolean(
                value["all_steps_completed"], "all steps completed"
            ),
            attempts=tuple(
                ExecutionAttempt.from_object(cast(dict[str, object], item))
                for item in attempts_value
            ),
            context_schema_version=require_string(value, "context_schema_version"),
            plan_schema_version=require_string(value, "plan_schema_version"),
            readiness_schema_version=require_string(value, "readiness_schema_version"),
            journal_schema_version=require_string(value, "journal_schema_version"),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployPrerequisiteEvidenceEntry:
    """Address-free semantic evidence for one exact prerequisite step."""

    sequence: int
    mapping_sequence: int
    playbook: str
    result_schema_version: str
    plan_command_digest: str
    command_digest: str
    variables_digest: str
    source_digest: str
    result_digest: str
    evidence_digest: str
    target_count: int
    target_set_digest: str
    status: DeployPrerequisiteEvidenceStatus
    inventory_parity_status: str
    ssh_connectivity_status: str
    reachable_host_count: int
    failed_host_count: int
    unreachable_host_count: int
    destination_probe_count: int
    schema_version: str = ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_ENTRY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_ENTRY_SCHEMA_VERSION
            or self.sequence not in {1, 2}
            or self.mapping_sequence != self.sequence
            or self.playbook != _REQUIRED_PLAYBOOKS[self.sequence - 1]
            or self.result_schema_version != _RESULT_SCHEMAS[self.sequence - 1]
            or not isinstance(self.status, DeployPrerequisiteEvidenceStatus)
        ):
            raise StatePersistenceError(
                "deploy prerequisite evidence entry identity is invalid"
            )
        for digest_value in (
            self.plan_command_digest,
            self.command_digest,
            self.variables_digest,
            self.source_digest,
            self.result_digest,
            self.evidence_digest,
            self.target_set_digest,
        ):
            validate_digest(digest_value, "deploy prerequisite evidence entry digest")
        for count_value in (
            self.target_count,
            self.reachable_host_count,
            self.failed_host_count,
            self.unreachable_host_count,
            self.destination_probe_count,
        ):
            _nonnegative_integer(count_value, "deploy prerequisite evidence count")
        if self.target_count < 1 or self.destination_probe_count != 0:
            raise StatePersistenceError(
                "deploy prerequisite evidence target summary is invalid"
            )
        if self.sequence == 1:
            if (
                self.inventory_parity_status != self.status.value
                or self.ssh_connectivity_status != "not-performed"
                or any(
                    (
                        self.reachable_host_count,
                        self.failed_host_count,
                        self.unreachable_host_count,
                    )
                )
            ):
                raise StatePersistenceError(
                    "inventory prerequisite semantic evidence conflicts"
                )
        else:
            if (
                self.inventory_parity_status != "not-applicable"
                or self.ssh_connectivity_status != self.status.value
                or self.reachable_host_count
                + self.failed_host_count
                + self.unreachable_host_count
                != self.target_count
            ):
                raise StatePersistenceError(
                    "connectivity prerequisite semantic evidence conflicts"
                )
        if self.evidence_digest != _entry_evidence_digest(self):
            raise StatePersistenceError(
                "deploy prerequisite semantic evidence digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "command_digest": self.command_digest,
            "destination_probe_count": self.destination_probe_count,
            "evidence_digest": self.evidence_digest,
            "failed_host_count": self.failed_host_count,
            "inventory_parity_status": self.inventory_parity_status,
            "mapping_sequence": self.mapping_sequence,
            "plan_command_digest": self.plan_command_digest,
            "playbook": self.playbook,
            "reachable_host_count": self.reachable_host_count,
            "result_digest": self.result_digest,
            "result_schema_version": self.result_schema_version,
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "source_digest": self.source_digest,
            "ssh_connectivity_status": self.ssh_connectivity_status,
            "status": self.status.value,
            "target_count": self.target_count,
            "target_set_digest": self.target_set_digest,
            "unreachable_host_count": self.unreachable_host_count,
            "variables_digest": self.variables_digest,
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployPrerequisiteEvidenceEntry:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy prerequisite evidence entry",
        )
        try:
            status = DeployPrerequisiteEvidenceStatus(require_string(value, "status"))
        except ValueError as error:
            raise StatePersistenceError(
                "deploy prerequisite evidence status is invalid"
            ) from error
        return cls(
            sequence=_integer(value["sequence"], "evidence sequence"),
            mapping_sequence=_integer(value["mapping_sequence"], "mapping sequence"),
            playbook=require_string(value, "playbook"),
            result_schema_version=require_string(value, "result_schema_version"),
            plan_command_digest=require_string(value, "plan_command_digest"),
            command_digest=require_string(value, "command_digest"),
            variables_digest=require_string(value, "variables_digest"),
            source_digest=require_string(value, "source_digest"),
            result_digest=require_string(value, "result_digest"),
            evidence_digest=require_string(value, "evidence_digest"),
            target_count=_integer(value["target_count"], "target count"),
            target_set_digest=require_string(value, "target_set_digest"),
            status=status,
            inventory_parity_status=require_string(value, "inventory_parity_status"),
            ssh_connectivity_status=require_string(value, "ssh_connectivity_status"),
            reachable_host_count=_integer(
                value["reachable_host_count"], "reachable host count"
            ),
            failed_host_count=_integer(value["failed_host_count"], "failed host count"),
            unreachable_host_count=_integer(
                value["unreachable_host_count"], "unreachable host count"
            ),
            destination_probe_count=_integer(
                value["destination_probe_count"], "destination probe count"
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployPrerequisiteEvidence:
    """Immutable-prefix semantic companion for the reviewed prerequisites."""

    generation: int
    created_at: str
    updated_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    context_artifact_digest: str
    context_record_digest: str
    plan_artifact_digest: str
    plan_record_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    catalog_digest: str
    source_version: str
    source_digest: str
    toolchain_version: str
    executable_identity_digest: str
    toolchain_evidence_digest: str
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    trust_generation: int
    trust_artifact_digest: str
    trust_entries_digest: str
    host_count: int
    host_set_digest: str
    route_digest: str
    entries: tuple[DeployPrerequisiteEvidenceEntry, ...]
    context_schema_version: str = ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
    plan_schema_version: str = ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_SCHEMA_VERSION
            or self.context_schema_version != ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
            or self.plan_schema_version != ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or self.operation != _OPERATION
        ):
            raise StatePersistenceError(
                "deploy prerequisite evidence provenance is unsupported"
            )
        _positive_integer(self.generation, "evidence generation")
        _positive_integer(self.journal_generation, "journal generation")
        _positive_integer(self.inventory_generation, "inventory generation")
        _positive_integer(self.trust_generation, "trust generation")
        _positive_integer(self.host_count, "host count")
        if not isinstance(self.cluster_uuid, uuid.UUID) or not isinstance(
            self.operation_id, uuid.UUID
        ):
            raise StatePersistenceError(
                "deploy prerequisite evidence identities are invalid"
            )
        validate_cluster_name(self.cluster_name)
        _validate_toolchain_version(self.toolchain_version)
        created = parse_timestamp(self.created_at)
        updated = parse_timestamp(self.updated_at)
        if updated < created:
            raise StatePersistenceError(
                "deploy prerequisite evidence timestamp regressed"
            )
        for value in _evidence_binding_digests(self):
            validate_digest(value, "deploy prerequisite evidence digest")
        if self.generation != len(self.entries) or not 1 <= len(self.entries) <= 2:
            raise StatePersistenceError(
                "deploy prerequisite evidence generation conflicts"
            )
        if tuple(entry.sequence for entry in self.entries) != tuple(
            range(1, len(self.entries) + 1)
        ):
            raise StatePersistenceError("deploy prerequisite evidence order conflicts")

    def to_object(self) -> dict[str, object]:
        return {
            "catalog_digest": self.catalog_digest,
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "context_artifact_digest": self.context_artifact_digest,
            "context_record_digest": self.context_record_digest,
            "context_schema_version": self.context_schema_version,
            "created_at": self.created_at,
            "entries": [entry.to_object() for entry in self.entries],
            "executable_identity_digest": self.executable_identity_digest,
            "generation": self.generation,
            "host_count": self.host_count,
            "host_set_digest": self.host_set_digest,
            "inventory_artifact_digest": self.inventory_artifact_digest,
            "inventory_digest": self.inventory_digest,
            "inventory_generation": self.inventory_generation,
            "journal_digest": self.journal_digest,
            "journal_generation": self.journal_generation,
            "journal_schema_version": self.journal_schema_version,
            "operation": self.operation,
            "operation_id": str(self.operation_id),
            "plan_artifact_digest": self.plan_artifact_digest,
            "plan_record_digest": self.plan_record_digest,
            "plan_schema_version": self.plan_schema_version,
            "readiness_artifact_digest": self.readiness_artifact_digest,
            "readiness_record_digest": self.readiness_record_digest,
            "readiness_schema_version": self.readiness_schema_version,
            "request_digest": self.request_digest,
            "route_digest": self.route_digest,
            "schema_version": self.schema_version,
            "source_digest": self.source_digest,
            "source_version": self.source_version,
            "toolchain_evidence_digest": self.toolchain_evidence_digest,
            "toolchain_version": self.toolchain_version,
            "trust_artifact_digest": self.trust_artifact_digest,
            "trust_entries_digest": self.trust_entries_digest,
            "trust_generation": self.trust_generation,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployPrerequisiteEvidence:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy prerequisite evidence",
        )
        entries_value = value["entries"]
        if not isinstance(entries_value, list) or not all(
            isinstance(item, dict) for item in entries_value
        ):
            raise StatePersistenceError(
                "deploy prerequisite evidence entries are invalid"
            )
        return cls(
            generation=_integer(value["generation"], "evidence generation"),
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
            request_digest=require_string(value, "request_digest"),
            journal_generation=_integer(
                value["journal_generation"], "journal generation"
            ),
            journal_digest=require_string(value, "journal_digest"),
            context_artifact_digest=require_string(value, "context_artifact_digest"),
            context_record_digest=require_string(value, "context_record_digest"),
            plan_artifact_digest=require_string(value, "plan_artifact_digest"),
            plan_record_digest=require_string(value, "plan_record_digest"),
            readiness_artifact_digest=require_string(
                value, "readiness_artifact_digest"
            ),
            readiness_record_digest=require_string(value, "readiness_record_digest"),
            catalog_digest=require_string(value, "catalog_digest"),
            source_version=require_string(value, "source_version"),
            source_digest=require_string(value, "source_digest"),
            toolchain_version=require_string(value, "toolchain_version"),
            executable_identity_digest=require_string(
                value, "executable_identity_digest"
            ),
            toolchain_evidence_digest=require_string(
                value, "toolchain_evidence_digest"
            ),
            inventory_generation=_integer(
                value["inventory_generation"], "inventory generation"
            ),
            inventory_artifact_digest=require_string(
                value, "inventory_artifact_digest"
            ),
            inventory_digest=require_string(value, "inventory_digest"),
            trust_generation=_integer(value["trust_generation"], "trust generation"),
            trust_artifact_digest=require_string(value, "trust_artifact_digest"),
            trust_entries_digest=require_string(value, "trust_entries_digest"),
            host_count=_integer(value["host_count"], "host count"),
            host_set_digest=require_string(value, "host_set_digest"),
            route_digest=require_string(value, "route_digest"),
            entries=tuple(
                DeployPrerequisiteEvidenceEntry.from_object(
                    cast(dict[str, object], item)
                )
                for item in entries_value
            ),
            context_schema_version=require_string(value, "context_schema_version"),
            plan_schema_version=require_string(value, "plan_schema_version"),
            readiness_schema_version=require_string(value, "readiness_schema_version"),
            journal_schema_version=require_string(value, "journal_schema_version"),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredDeployPrerequisiteExecution:
    record: DeployPrerequisiteExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployPrerequisiteEvidence:
    record: DeployPrerequisiteEvidence
    artifact_digest: str


class DeployPrerequisiteExecutionStore:
    """Generation-guarded owner-only deploy prerequisite execution state."""

    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        _require_canonical_paths(paths)
        self._operation_id = _require_operation_id(operation_id)
        self._paths = paths
        self._path = deploy_prerequisite_execution_path(paths, operation_id)
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
    ) -> StoredDeployPrerequisiteExecution:
        value, artifact_digest = self._file.read()
        record = DeployPrerequisiteExecution.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy prerequisite execution identity mismatch"
            )
        return StoredDeployPrerequisiteExecution(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPrerequisiteExecution:
        _assert_operation_lock(lock, self._paths, self._operation_id)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployPrerequisiteExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployPrerequisiteExecution:
        _assert_operation_lock(lock, self._paths, self._operation_id)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy prerequisite execution operation mismatch"
            )
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial deploy prerequisite execution generation conflicts"
                )
        else:
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if (
                expected_digest is None
                or current.artifact_digest != expected_digest
                or current.record.generation != expected_generation
            ):
                raise StatePersistenceError(
                    "deploy prerequisite execution changed concurrently"
                )
            _validate_execution_transition(current.record, record)
        artifact_digest = self._file.write(
            record.to_object(), expected_digest=expected_digest
        )
        return StoredDeployPrerequisiteExecution(record, artifact_digest)


class DeployPrerequisiteEvidenceStore:
    """Immutable-prefix owner-only deploy prerequisite semantic evidence."""

    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        _require_canonical_paths(paths)
        self._operation_id = _require_operation_id(operation_id)
        self._paths = paths
        self._path = deploy_prerequisite_evidence_path(paths, operation_id)
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
    ) -> StoredDeployPrerequisiteEvidence:
        value, artifact_digest = self._file.read()
        record = DeployPrerequisiteEvidence.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy prerequisite evidence identity mismatch"
            )
        return StoredDeployPrerequisiteEvidence(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPrerequisiteEvidence:
        _assert_operation_lock(lock, self._paths, self._operation_id)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def append_locked(
        self,
        record: DeployPrerequisiteEvidence,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployPrerequisiteEvidence:
        _assert_operation_lock(lock, self._paths, self._operation_id)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy prerequisite evidence operation mismatch"
            )
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial deploy prerequisite evidence generation conflicts"
                )
        else:
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if (
                expected_digest is None
                or current.artifact_digest != expected_digest
                or current.record.generation != expected_generation
            ):
                raise StatePersistenceError(
                    "deploy prerequisite evidence changed concurrently"
                )
            _validate_evidence_transition(current.record, record)
        artifact_digest = self._file.write(
            record.to_object(), expected_digest=expected_digest
        )
        return StoredDeployPrerequisiteEvidence(record, artifact_digest)


@dataclass(frozen=True, slots=True)
class DeployPrerequisiteReport:
    """Strict address-free successful result projection."""

    operation_id: uuid.UUID
    status: str
    step_count: int
    host_count: int
    host_set_digest: str
    route_digest: str
    execution_schema_version: str
    execution_artifact_digest: str
    evidence_schema_version: str
    evidence_artifact_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    schema_version: str = ANSIBLE_DEPLOY_PREREQUISITE_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_PREREQUISITE_REPORT_SCHEMA_VERSION
            or self.status != _READY
            or self.step_count != len(_REQUIRED_PLAYBOOKS)
            or self.host_count < 1
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_PREREQUISITE_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_SCHEMA_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError("deploy prerequisite report is invalid")
        for value in (
            self.host_set_digest,
            self.route_digest,
            self.execution_artifact_digest,
            self.evidence_artifact_digest,
        ):
            validate_digest(value, "deploy prerequisite report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "evidence_artifact_digest": self.evidence_artifact_digest,
            "evidence_schema_version": self.evidence_schema_version,
            "execution_artifact_digest": self.execution_artifact_digest,
            "execution_schema_version": self.execution_schema_version,
            "host_count": self.host_count,
            "host_set_digest": self.host_set_digest,
            "journal_phase": self.journal_phase.value,
            "journal_status": self.journal_status.value,
            "operation_id": str(self.operation_id),
            "route_digest": self.route_digest,
            "schema_version": self.schema_version,
            "status": self.status,
            "step_count": self.step_count,
        }


@dataclass(frozen=True, slots=True)
class _RuntimeContext:
    planning: _DeployPlanningContext
    context: StoredDeployAnsibleContext
    plan: StoredDeployAnsiblePlan
    steps: tuple[DeployAnsiblePlanStep, DeployAnsiblePlanStep]
    source: AnsibleSourceBundle
    catalog_digest: str
    host_ids: tuple[str, ...]
    host_set_digest: str
    executable_identity_digest: str
    toolchain_evidence_digest: str


def execute_deploy_ansible_prerequisites(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployPrerequisiteReport:
    """Execute only inventory parity and initial all-host SSH connectivity."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths, operation_id)
    _validate_toolchain_dependency(toolchain)
    executable_identity_digest = _executable_identity_digest(executables)
    toolchain_evidence_digest = _toolchain_evidence_digest(
        toolchain, executable_identity_digest
    )
    runtime = _load_runtime_context(
        paths,
        operation_id,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
        toolchain=toolchain,
    )
    metadata = runtime.planning.base.deploy.metadata.record
    execution_store = DeployPrerequisiteExecutionStore(paths, operation_id)
    evidence_store = DeployPrerequisiteEvidenceStore(paths, operation_id)
    for store_path in (execution_store.path, evidence_store.path):
        validate_state_file(store_path, allow_missing=True)

    execution = (
        execution_store.read_locked(
            lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
        )
        if execution_store.path.exists()
        else None
    )
    evidence = (
        evidence_store.read_locked(
            lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
        )
        if evidence_store.path.exists()
        else None
    )
    _validate_prefix(runtime, execution, evidence)
    if execution is not None and execution.record.all_steps_completed:
        if evidence is None or len(evidence.record.entries) != len(_REQUIRED_PLAYBOOKS):
            raise StateConflictError(
                "deploy prerequisite completion evidence is unavailable"
            )
        return _build_report(execution, evidence)
    if (
        execution is not None
        and execution.record.state is not ExecutionAttemptState.SUCCEEDED
    ):
        raise StateConflictError(
            "deploy prerequisite execution requires manual recovery and cannot retry"
        )

    builder = AnsibleCommandBuilder(
        executables.playbook,
        executables.inventory,
        paths,
    )
    service = AnsibleService(builder, runner)
    discovered_toolchain = service.version(lock)
    if discovered_toolchain != toolchain:
        raise StateConflictError("deploy prerequisite Ansible toolchain drifted")

    # Probe completion is deliberately before durable remote-effect intent.
    # Revalidate every canonical binding after the safe local probes.
    runtime = _load_runtime_context(
        paths,
        operation_id,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
        toolchain=toolchain,
    )
    _validate_prefix(runtime, execution, evidence)
    readiness = _reconstructed_readiness(runtime.planning.base)
    current_index = len(execution.record.attempts) if execution is not None else 0
    while current_index < len(runtime.steps):
        step = runtime.steps[current_index]
        variables = _safe_variable_values(
            runtime.planning,
            definition=get_playbook(step.playbook),
            target_ids=step.target_ids,
        )
        _, validated, variables_digest, command_digest = (
            builder.validate_operation_step(
                step.playbook,
                step_sequence=step.sequence,
                limit=step.target_ids,
                variables=variables,
                tags=(),
                check=False,
                diff=False,
                verbosity=0,
            )
        )
        if (
            variables_digest != step.variables_digest
            or command_digest != step.command_digest
        ):
            raise StateConflictError(
                "deploy prerequisite command identity conflicts with the plan"
            )
        now = _timestamp()
        attempt = ExecutionAttempt(
            attempt_index=current_index + 1,
            step_sequence=step.sequence,
            playbook=step.playbook,
            classification=OperationClassification.READ_ONLY,
            limit=step.target_ids,
            variables_digest=variables_digest,
            command_digest=command_digest,
            playbook_source_digest=step.source_digest,
            result_schema_version=get_playbook(
                step.playbook
            ).execution_result_schema_version,
            state=ExecutionAttemptState.STARTED,
            started_at=now,
            completed_at=None,
            exit_code=None,
            result_digest=None,
            manual_recovery_required=True,
        )
        execution = _persist_started(
            runtime,
            execution_store,
            execution,
            attempt,
            lock=lock,
            now=now,
        )
        try:
            result, observed_command_digest = service.execute_operation_step(
                lock,
                metadata,
                runtime.planning.base.deploy.inventory,
                step.playbook,
                step_sequence=step.sequence,
                limit=step.target_ids,
                variables=validated,
                readiness=readiness,
                tags=(),
                check=False,
                diff=False,
                verbosity=0,
            )
            if observed_command_digest != command_digest:
                raise AnsibleResultError("Ansible command result identity conflicts")
        except KeyboardInterrupt:
            try:
                _persist_uncertain(
                    execution_store,
                    execution,
                    ExecutionAttemptState.INTERRUPTED,
                    lock=lock,
                )
            except StatePersistenceError as error:
                raise StatePersistenceError(
                    "deploy prerequisite interruption persistence failed; "
                    "manual recovery required"
                ) from error
            raise AnsibleError(
                "deploy prerequisite execution was interrupted; manual recovery required"
            ) from None
        except AnsibleError as error:
            failure_state = _failure_state(error)
            try:
                _persist_uncertain(
                    execution_store,
                    execution,
                    failure_state,
                    lock=lock,
                )
            except StatePersistenceError as persistence_error:
                raise StatePersistenceError(
                    "deploy prerequisite failure persistence failed; "
                    "manual recovery required"
                ) from persistence_error
            raise AnsibleError(
                "deploy prerequisite execution is uncertain; manual recovery required"
            ) from error

        # A changed chain after invocation is uncertain. Leave durable STARTED
        # intent and never retry the effect automatically.
        runtime_after = _load_runtime_context(
            paths,
            operation_id,
            executable_identity_digest=executable_identity_digest,
            toolchain_evidence_digest=toolchain_evidence_digest,
            toolchain=toolchain,
        )
        if _runtime_binding_digest(runtime_after) != _runtime_binding_digest(runtime):
            raise StateConflictError(
                "deploy prerequisite state changed after invocation; "
                "manual recovery required"
            )
        entry = _semantic_entry(step, result, command_digest)
        try:
            evidence = _persist_evidence(
                runtime,
                evidence_store,
                evidence,
                entry,
                lock=lock,
            )
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy prerequisite evidence persistence failed; "
                "manual recovery required"
            ) from error
        terminal_state = _terminal_state(entry)
        try:
            execution = _persist_terminal(
                execution_store,
                execution,
                terminal_state,
                result.exit_code,
                entry.result_digest,
                lock=lock,
            )
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy prerequisite terminal persistence failed; "
                "manual recovery required"
            ) from error
        if terminal_state is not ExecutionAttemptState.SUCCEEDED:
            raise AnsibleError(
                "deploy prerequisite evidence failed; manual recovery required"
            )
        current_index += 1

    if execution is None or evidence is None:
        raise StatePersistenceError("deploy prerequisite completion is unavailable")
    _validate_prefix(runtime, execution, evidence)
    return _build_report(execution, evidence)


def deploy_prerequisite_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = (
        paths.operations
        / f"{operation_id}{DEPLOY_PREREQUISITE_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy prerequisite execution path is not canonical"
        )
    return path


def deploy_prerequisite_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = (
        paths.operations
        / f"{operation_id}{DEPLOY_PREREQUISITE_EVIDENCE_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy prerequisite evidence path is not canonical"
        )
    return path


def deploy_prerequisite_execution_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_PREREQUISITE_EXECUTION_FILENAME_SUFFIX
    )


def deploy_prerequisite_evidence_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_PREREQUISITE_EVIDENCE_FILENAME_SUFFIX
    )


def _load_runtime_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    executable_identity_digest: str,
    toolchain_evidence_digest: str,
    toolchain: AnsibleToolchain,
) -> _RuntimeContext:
    planning = _load_deploy_planning_context(paths, operation_id)
    journal = planning.base.deploy.journal
    if (
        journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
    ):
        raise StateConflictError(
            "deploy prerequisites require the unchanged VERIFY journal"
        )
    readiness = planning.readiness.record
    if (
        readiness.executable_identity_digest != executable_identity_digest
        or readiness.toolchain_evidence_digest != toolchain_evidence_digest
        or readiness.playbook_version != str(toolchain.core)
        or readiness.inventory_version != str(toolchain.core)
        or readiness.remote_connectivity_status != "not-performed"
        or readiness.remote_health_status != "not-performed"
        or readiness.remote_playbook_status != "not-performed"
    ):
        raise StateConflictError(
            "deploy prerequisite executable or readiness binding conflicts"
        )
    reconstructed = _reconstructed_readiness(planning.base)
    if readiness_binding_digest(reconstructed) != readiness.readiness_digest:
        raise StateConflictError("deploy prerequisite readiness is stale")
    reconstructed.require_ready(OperationClassification.READ_ONLY)

    source = load_ansible_source_bundle()
    catalog_digest = ansible_operation_catalog_digest()
    metadata = planning.base.deploy.metadata.record
    context_store = DeployAnsibleContextStore(paths, operation_id)
    plan_store = DeployAnsiblePlanStore(paths, operation_id)
    for store_path in (context_store.path, plan_store.path):
        validate_state_file(store_path, allow_missing=True)
        if not store_path.exists():
            raise StateConflictError(
                "deploy prerequisite context and plan must already exist"
            )
    stored_context = context_store.read(
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    stored_plan = plan_store.read(
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_context = _build_context(
        planning,
        source_bundle=source,
        catalog_digest=catalog_digest,
        intent=DeployIntentContext(),
        created_at=stored_context.record.created_at,
    )
    if stored_context.record != expected_context:
        raise StateConflictError("deploy prerequisite context is stale or changed")
    expected_steps = _build_steps(planning, source_bundle=source)
    expected_plan = _build_plan(
        context_record=expected_context,
        context_artifact_digest=stored_context.artifact_digest,
        steps=expected_steps,
        source_bundle=source,
        catalog_digest=catalog_digest,
        created_at=stored_context.record.created_at,
    )
    if stored_plan.record != expected_plan:
        raise StateConflictError("deploy prerequisite plan is stale or changed")

    matches = tuple(
        tuple(
            step
            for step in stored_plan.record.steps
            if step.mapping_sequence == mapping_sequence
        )
        for mapping_sequence in (1, 2)
    )
    if any(len(group) != 1 for group in matches):
        raise StateConflictError(
            "deploy prerequisite plan has missing or duplicate prerequisite steps"
        )
    steps = (matches[0][0], matches[1][0])
    host_ids = tuple(
        sorted(
            host.logical_id
            for host in planning.base.deploy.inventory.record.inventory.hosts
        )
    )
    for index, step in enumerate(steps, start=1):
        if (
            step.sequence != index
            or step.mapping_sequence != index
            or step.playbook != _REQUIRED_PLAYBOOKS[index - 1]
            or step.condition != "always"
            or step.classification is not OperationClassification.READ_ONLY
            or step.target_ids != host_ids
            or step.target_digest != _digest_object(list(host_ids))
            or step.target_role != "all"
            or step.limit_policy is not LimitPolicy.EXPLICIT
            or step.check_mode is not CheckMode.SUPPORTED
            or step.source_digest != _playbook_source_digest(source, step.playbook)
        ):
            raise StateConflictError("deploy prerequisite plan step identity conflicts")
    return _RuntimeContext(
        planning,
        stored_context,
        stored_plan,
        steps,
        source,
        catalog_digest,
        host_ids,
        _digest_object(list(host_ids)),
        executable_identity_digest,
        toolchain_evidence_digest,
    )


def _validate_prefix(
    runtime: _RuntimeContext,
    execution: StoredDeployPrerequisiteExecution | None,
    evidence: StoredDeployPrerequisiteEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "deploy prerequisite evidence exists without execution"
            )
        return
    _validate_execution_binding(runtime, execution.record)
    if evidence is not None:
        _validate_evidence_binding(runtime, evidence.record)
    attempts = execution.record.attempts
    entries = evidence.record.entries if evidence is not None else ()
    for index, attempt in enumerate(attempts):
        step = runtime.steps[index]
        if (
            attempt.attempt_index != index + 1
            or attempt.step_sequence != step.sequence
            or attempt.playbook != step.playbook
            or attempt.classification is not OperationClassification.READ_ONLY
            or attempt.limit != step.target_ids
            or attempt.variables_digest != step.variables_digest
            or attempt.command_digest != step.command_digest
            or attempt.playbook_source_digest != step.source_digest
            or attempt.result_schema_version
            != get_playbook(step.playbook).execution_result_schema_version
        ):
            raise StateConflictError(
                "deploy prerequisite execution prefix conflicts with the plan"
            )
    if any(
        attempt.state is not ExecutionAttemptState.SUCCEEDED
        for attempt in attempts[:-1]
    ):
        raise StateConflictError("deploy prerequisite execution history conflicts")
    expected_evidence_count = sum(
        attempt.result_digest is not None for attempt in attempts
    )
    if len(entries) != expected_evidence_count:
        raise StateConflictError(
            "deploy prerequisite execution and evidence prefixes conflict"
        )
    for index, entry in enumerate(entries):
        attempt = attempts[index]
        step = runtime.steps[index]
        if (
            entry.sequence != step.sequence
            or entry.mapping_sequence != step.mapping_sequence
            or entry.playbook != step.playbook
            or entry.plan_command_digest != step.command_digest
            or entry.command_digest != attempt.command_digest
            or entry.variables_digest != attempt.variables_digest
            or entry.source_digest != attempt.playbook_source_digest
            or entry.result_digest != attempt.result_digest
            or entry.target_count != len(step.target_ids)
            or entry.target_set_digest != step.target_digest
        ):
            raise StateConflictError(
                "deploy prerequisite semantic evidence prefix conflicts"
            )
    if execution.record.all_steps_completed and (
        len(attempts) != 2
        or len(entries) != 2
        or any(
            attempt.state is not ExecutionAttemptState.SUCCEEDED for attempt in attempts
        )
        or any(
            entry.status is not DeployPrerequisiteEvidenceStatus.PASSED
            for entry in entries
        )
    ):
        raise StateConflictError("deploy prerequisite completion prefix conflicts")


def _persist_started(
    runtime: _RuntimeContext,
    store: DeployPrerequisiteExecutionStore,
    current: StoredDeployPrerequisiteExecution | None,
    attempt: ExecutionAttempt,
    *,
    lock: ClusterLock,
    now: str,
) -> StoredDeployPrerequisiteExecution:
    if current is None:
        planning = runtime.planning
        readiness = planning.readiness
        metadata = planning.base.deploy.metadata.record
        journal = planning.base.deploy.journal
        inventory = planning.base.deploy.inventory
        trust = planning.base.trust
        record = DeployPrerequisiteExecution(
            generation=1,
            created_at=now,
            updated_at=now,
            cluster_uuid=metadata.cluster_uuid,
            cluster_name=metadata.cluster_name,
            operation_id=journal.record.operation_id,
            operation=_OPERATION,
            request_digest=journal.record.request_digest,
            journal_generation=journal.record.generation,
            journal_digest=journal.digest,
            journal_status=journal.record.status,
            journal_phase=journal.record.phase,
            context_artifact_digest=runtime.context.artifact_digest,
            context_record_digest=runtime.context.record.record_digest,
            plan_artifact_digest=runtime.plan.artifact_digest,
            plan_record_digest=runtime.plan.record.record_digest,
            readiness_artifact_digest=readiness.artifact_digest,
            readiness_record_digest=readiness.record.record_digest,
            catalog_digest=runtime.catalog_digest,
            source_version=runtime.source.version,
            source_digest=runtime.source.digest,
            toolchain_version=readiness.record.playbook_version,
            executable_identity_digest=runtime.executable_identity_digest,
            toolchain_evidence_digest=runtime.toolchain_evidence_digest,
            inventory_generation=inventory.record.generation,
            inventory_artifact_digest=inventory.digest,
            inventory_digest=inventory.record.inventory_digest,
            trust_generation=trust.record.generation,
            trust_artifact_digest=trust.digest,
            trust_entries_digest=trust.record.entries_digest,
            host_count=len(runtime.host_ids),
            host_set_digest=runtime.host_set_digest,
            route_digest=readiness.record.route_digest,
            required_step_count=2,
            state=ExecutionAttemptState.STARTED,
            all_steps_completed=False,
            attempts=(attempt,),
        )
        return store.write_locked(
            record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    if current.record.state is not ExecutionAttemptState.SUCCEEDED:
        raise StateConflictError("deploy prerequisite started state cannot be retried")
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=ExecutionAttemptState.STARTED,
        all_steps_completed=False,
        attempts=(*current.record.attempts, attempt),
    )
    return store.write_locked(
        record,
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _persist_uncertain(
    store: DeployPrerequisiteExecutionStore,
    current: StoredDeployPrerequisiteExecution,
    state: ExecutionAttemptState,
    *,
    lock: ClusterLock,
) -> StoredDeployPrerequisiteExecution:
    if state not in {
        ExecutionAttemptState.FAILED,
        ExecutionAttemptState.TIMED_OUT,
        ExecutionAttemptState.INTERRUPTED,
        ExecutionAttemptState.MALFORMED_RESULT,
    }:
        raise StatePersistenceError(
            "deploy prerequisite uncertain terminal state is invalid"
        )
    attempt = replace(
        current.record.attempts[-1],
        state=state,
        completed_at=_timestamp(),
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=attempt.completed_at or current.record.updated_at,
        state=state,
        attempts=(*current.record.attempts[:-1], attempt),
    )
    return store.write_locked(
        record,
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _persist_terminal(
    store: DeployPrerequisiteExecutionStore,
    current: StoredDeployPrerequisiteExecution,
    state: ExecutionAttemptState,
    exit_code: int,
    result_digest: str,
    *,
    lock: ClusterLock,
) -> StoredDeployPrerequisiteExecution:
    completed_at = _timestamp()
    attempt = replace(
        current.record.attempts[-1],
        state=state,
        completed_at=completed_at,
        exit_code=exit_code,
        result_digest=result_digest,
        manual_recovery_required=state is not ExecutionAttemptState.SUCCEEDED,
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=completed_at,
        state=state,
        all_steps_completed=(
            state is ExecutionAttemptState.SUCCEEDED
            and len(current.record.attempts) == len(_REQUIRED_PLAYBOOKS)
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
    runtime: _RuntimeContext,
    store: DeployPrerequisiteEvidenceStore,
    current: StoredDeployPrerequisiteEvidence | None,
    entry: DeployPrerequisiteEvidenceEntry,
    *,
    lock: ClusterLock,
) -> StoredDeployPrerequisiteEvidence:
    now = _timestamp()
    if current is None:
        planning = runtime.planning
        readiness = planning.readiness
        metadata = planning.base.deploy.metadata.record
        journal = planning.base.deploy.journal
        inventory = planning.base.deploy.inventory
        trust = planning.base.trust
        record = DeployPrerequisiteEvidence(
            generation=1,
            created_at=now,
            updated_at=now,
            cluster_uuid=metadata.cluster_uuid,
            cluster_name=metadata.cluster_name,
            operation_id=journal.record.operation_id,
            operation=_OPERATION,
            request_digest=journal.record.request_digest,
            journal_generation=journal.record.generation,
            journal_digest=journal.digest,
            context_artifact_digest=runtime.context.artifact_digest,
            context_record_digest=runtime.context.record.record_digest,
            plan_artifact_digest=runtime.plan.artifact_digest,
            plan_record_digest=runtime.plan.record.record_digest,
            readiness_artifact_digest=readiness.artifact_digest,
            readiness_record_digest=readiness.record.record_digest,
            catalog_digest=runtime.catalog_digest,
            source_version=runtime.source.version,
            source_digest=runtime.source.digest,
            toolchain_version=readiness.record.playbook_version,
            executable_identity_digest=runtime.executable_identity_digest,
            toolchain_evidence_digest=runtime.toolchain_evidence_digest,
            inventory_generation=inventory.record.generation,
            inventory_artifact_digest=inventory.digest,
            inventory_digest=inventory.record.inventory_digest,
            trust_generation=trust.record.generation,
            trust_artifact_digest=trust.digest,
            trust_entries_digest=trust.record.entries_digest,
            host_count=len(runtime.host_ids),
            host_set_digest=runtime.host_set_digest,
            route_digest=readiness.record.route_digest,
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
    step: DeployAnsiblePlanStep,
    result: AnsibleExecutionResult,
    command_digest: str,
) -> DeployPrerequisiteEvidenceEntry:
    if (
        result.playbook != step.playbook
        or result.classification is not OperationClassification.READ_ONLY
        or result.check_mode
        or result.exit_code not in {0, 2, 4}
    ):
        raise AnsibleResultError("deploy prerequisite result identity conflicts")
    if step.playbook == "inventory-preflight":
        evidence = result.inventory_preflight
        if (
            evidence is None
            or result.connectivity is not None
            or evidence.target_count != len(step.target_ids)
        ):
            raise AnsibleResultError(
                "deploy inventory prerequisite result is incomplete"
            )
        result_object = _preflight_result_object(evidence)
        result_digest = _digest_object(result_object)
        status = DeployPrerequisiteEvidenceStatus(evidence.status)
        semantic = {
            "inventory_parity_status": status.value,
            "playbook": step.playbook,
            "result_digest": result_digest,
            "sequence": step.sequence,
            "target_count": len(step.target_ids),
            "target_set_digest": step.target_digest,
        }
        return DeployPrerequisiteEvidenceEntry(
            sequence=step.sequence,
            mapping_sequence=step.mapping_sequence,
            playbook=step.playbook,
            result_schema_version=evidence.schema_version,
            plan_command_digest=step.command_digest,
            command_digest=command_digest,
            variables_digest=step.variables_digest,
            source_digest=step.source_digest,
            result_digest=result_digest,
            evidence_digest=_digest_object(semantic),
            target_count=len(step.target_ids),
            target_set_digest=step.target_digest,
            status=status,
            inventory_parity_status=status.value,
            ssh_connectivity_status="not-performed",
            reachable_host_count=0,
            failed_host_count=0,
            unreachable_host_count=0,
            destination_probe_count=0,
        )

    connectivity = result.connectivity
    if (
        connectivity is None
        or result.inventory_preflight is not None
        or connectivity.destination_probes
        or tuple(item.logical_id for item in connectivity.hosts)
        != tuple(sorted(step.target_ids))
        or len(connectivity.hosts) != len(step.target_ids)
    ):
        raise AnsibleResultError(
            "deploy connectivity prerequisite result is incomplete"
        )
    reachable = sum(
        item.status is HostConnectivityStatus.REACHABLE for item in connectivity.hosts
    )
    failed = sum(
        item.status is HostConnectivityStatus.FAILED for item in connectivity.hosts
    )
    unreachable = sum(
        item.status is HostConnectivityStatus.UNREACHABLE for item in connectivity.hosts
    )
    status = (
        DeployPrerequisiteEvidenceStatus.PASSED
        if connectivity.status is ConnectivityStatus.SUCCESS
        else DeployPrerequisiteEvidenceStatus.UNREACHABLE
        if unreachable
        else DeployPrerequisiteEvidenceStatus.FAILED
    )
    result_object = _connectivity_result_object(connectivity)
    result_digest = _digest_object(result_object)
    semantic = {
        "failed_host_count": failed,
        "playbook": step.playbook,
        "reachable_host_count": reachable,
        "result_digest": result_digest,
        "sequence": step.sequence,
        "status": status.value,
        "target_count": len(step.target_ids),
        "target_set_digest": step.target_digest,
        "unreachable_host_count": unreachable,
    }
    return DeployPrerequisiteEvidenceEntry(
        sequence=step.sequence,
        mapping_sequence=step.mapping_sequence,
        playbook=step.playbook,
        result_schema_version=CONNECTIVITY_PROJECTION_SCHEMA_VERSION,
        plan_command_digest=step.command_digest,
        command_digest=command_digest,
        variables_digest=step.variables_digest,
        source_digest=step.source_digest,
        result_digest=result_digest,
        evidence_digest=_digest_object(semantic),
        target_count=len(step.target_ids),
        target_set_digest=step.target_digest,
        status=status,
        inventory_parity_status="not-applicable",
        ssh_connectivity_status=status.value,
        reachable_host_count=reachable,
        failed_host_count=failed,
        unreachable_host_count=unreachable,
        destination_probe_count=0,
    )


def _preflight_result_object(
    evidence: InventoryPreflightEvidence,
) -> dict[str, object]:
    return {
        "host_count": evidence.host_count,
        "inventory_file_digest": evidence.inventory_file_digest,
        "inventory_generation": evidence.inventory_generation,
        "observation_digest": evidence.observation_digest,
        "observation_generation": evidence.observation_generation,
        "schema_version": evidence.schema_version,
        "status": evidence.status,
        "target_count": evidence.target_count,
    }


def _connectivity_result_object(
    evidence: ConnectivityEvidence,
) -> dict[str, object]:
    return {
        "destination_probe_count": len(evidence.destination_probes),
        "hosts": [
            {"logical_id": item.logical_id, "status": item.status.value}
            for item in evidence.hosts
        ],
        "schema_version": CONNECTIVITY_PROJECTION_SCHEMA_VERSION,
        "status": evidence.status.value,
    }


def _terminal_state(
    entry: DeployPrerequisiteEvidenceEntry,
) -> ExecutionAttemptState:
    if entry.status is DeployPrerequisiteEvidenceStatus.PASSED:
        return ExecutionAttemptState.SUCCEEDED
    if entry.status is DeployPrerequisiteEvidenceStatus.UNREACHABLE:
        return ExecutionAttemptState.UNREACHABLE
    return ExecutionAttemptState.FAILED


def _entry_evidence_digest(entry: DeployPrerequisiteEvidenceEntry) -> str:
    if entry.sequence == 1:
        value = {
            "inventory_parity_status": entry.inventory_parity_status,
            "playbook": entry.playbook,
            "result_digest": entry.result_digest,
            "sequence": entry.sequence,
            "target_count": entry.target_count,
            "target_set_digest": entry.target_set_digest,
        }
    else:
        value = {
            "failed_host_count": entry.failed_host_count,
            "playbook": entry.playbook,
            "reachable_host_count": entry.reachable_host_count,
            "result_digest": entry.result_digest,
            "sequence": entry.sequence,
            "status": entry.status.value,
            "target_count": entry.target_count,
            "target_set_digest": entry.target_set_digest,
            "unreachable_host_count": entry.unreachable_host_count,
        }
    return _digest_object(value)


def _failure_state(error: AnsibleError) -> ExecutionAttemptState:
    if isinstance(error, AnsibleResultError):
        return ExecutionAttemptState.MALFORMED_RESULT
    cause = error.__cause__
    if isinstance(cause, ProcessTimeoutError):
        return ExecutionAttemptState.TIMED_OUT
    if isinstance(cause, ProcessOutputError):
        return ExecutionAttemptState.MALFORMED_RESULT
    return ExecutionAttemptState.FAILED


def _build_report(
    execution: StoredDeployPrerequisiteExecution,
    evidence: StoredDeployPrerequisiteEvidence,
) -> DeployPrerequisiteReport:
    if (
        not execution.record.all_steps_completed
        or len(evidence.record.entries) != 2
        or any(
            entry.status is not DeployPrerequisiteEvidenceStatus.PASSED
            for entry in evidence.record.entries
        )
    ):
        raise StateConflictError("deploy prerequisites are not ready")
    return DeployPrerequisiteReport(
        operation_id=execution.record.operation_id,
        status=_READY,
        step_count=2,
        host_count=execution.record.host_count,
        host_set_digest=execution.record.host_set_digest,
        route_digest=execution.record.route_digest,
        execution_schema_version=execution.record.schema_version,
        execution_artifact_digest=execution.artifact_digest,
        evidence_schema_version=evidence.record.schema_version,
        evidence_artifact_digest=evidence.artifact_digest,
        journal_status=execution.record.journal_status,
        journal_phase=execution.record.journal_phase,
    )


def _validate_execution_attempts(
    attempts: tuple[ExecutionAttempt, ...],
    *,
    state: ExecutionAttemptState,
    all_steps_completed: bool,
) -> None:
    if not 1 <= len(attempts) <= len(_REQUIRED_PLAYBOOKS):
        raise StatePersistenceError(
            "deploy prerequisite execution attempt count is invalid"
        )
    for index, attempt in enumerate(attempts, start=1):
        if (
            attempt.attempt_index != index
            or attempt.step_sequence != index
            or attempt.playbook != _REQUIRED_PLAYBOOKS[index - 1]
            or attempt.classification is not OperationClassification.READ_ONLY
        ):
            raise StatePersistenceError(
                "deploy prerequisite execution attempt order conflicts"
            )
    if attempts[-1].state is not state:
        raise StatePersistenceError("deploy prerequisite execution summary conflicts")
    if any(
        attempt.state is not ExecutionAttemptState.SUCCEEDED
        for attempt in attempts[:-1]
    ):
        raise StatePersistenceError("deploy prerequisite execution history is invalid")
    if all_steps_completed != (
        len(attempts) == len(_REQUIRED_PLAYBOOKS)
        and all(
            attempt.state is ExecutionAttemptState.SUCCEEDED for attempt in attempts
        )
    ):
        raise StatePersistenceError("deploy prerequisite completion state conflicts")


def _validate_execution_transition(
    current: DeployPrerequisiteExecution,
    replacement: DeployPrerequisiteExecution,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or _execution_binding(current) != _execution_binding(replacement)
        or current.all_steps_completed
        or current.state
        not in {ExecutionAttemptState.STARTED, ExecutionAttemptState.SUCCEEDED}
    ):
        raise StatePersistenceError(
            "deploy prerequisite execution transition is invalid"
        )
    if current.state is ExecutionAttemptState.STARTED:
        if (
            len(replacement.attempts) != len(current.attempts)
            or replacement.attempts[:-1] != current.attempts[:-1]
            or replacement.attempts[-1].state is ExecutionAttemptState.STARTED
        ):
            raise StatePersistenceError(
                "deploy prerequisite terminal transition is invalid"
            )
    elif (
        len(current.attempts) >= len(_REQUIRED_PLAYBOOKS)
        or replacement.attempts[:-1] != current.attempts
        or replacement.attempts[-1].state is not ExecutionAttemptState.STARTED
    ):
        raise StatePersistenceError(
            "deploy prerequisite next-step transition is invalid"
        )


def _validate_evidence_transition(
    current: DeployPrerequisiteEvidence,
    replacement: DeployPrerequisiteEvidence,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or _evidence_binding(current) != _evidence_binding(replacement)
        or replacement.entries[:-1] != current.entries
        or len(replacement.entries) != len(current.entries) + 1
    ):
        raise StatePersistenceError(
            "deploy prerequisite evidence transition is invalid"
        )


def _validate_execution_binding(
    runtime: _RuntimeContext, record: DeployPrerequisiteExecution
) -> None:
    planning = runtime.planning
    readiness = planning.readiness
    metadata = planning.base.deploy.metadata.record
    journal = planning.base.deploy.journal
    inventory = planning.base.deploy.inventory
    trust = planning.base.trust
    expected = (
        metadata.cluster_uuid,
        metadata.cluster_name,
        journal.record.operation_id,
        journal.record.request_digest,
        journal.record.generation,
        journal.digest,
        journal.record.status,
        journal.record.phase,
        runtime.context.artifact_digest,
        runtime.context.record.record_digest,
        runtime.plan.artifact_digest,
        runtime.plan.record.record_digest,
        readiness.artifact_digest,
        readiness.record.record_digest,
        runtime.catalog_digest,
        runtime.source.version,
        runtime.source.digest,
        readiness.record.playbook_version,
        runtime.executable_identity_digest,
        runtime.toolchain_evidence_digest,
        inventory.record.generation,
        inventory.digest,
        inventory.record.inventory_digest,
        trust.record.generation,
        trust.digest,
        trust.record.entries_digest,
        len(runtime.host_ids),
        runtime.host_set_digest,
        readiness.record.route_digest,
    )
    if _execution_binding(record) != expected:
        raise StateConflictError("deploy prerequisite execution provenance is stale")


def _validate_evidence_binding(
    runtime: _RuntimeContext, record: DeployPrerequisiteEvidence
) -> None:
    planning = runtime.planning
    readiness = planning.readiness
    metadata = planning.base.deploy.metadata.record
    journal = planning.base.deploy.journal
    inventory = planning.base.deploy.inventory
    trust = planning.base.trust
    expected = (
        metadata.cluster_uuid,
        metadata.cluster_name,
        journal.record.operation_id,
        journal.record.request_digest,
        journal.record.generation,
        journal.digest,
        runtime.context.artifact_digest,
        runtime.context.record.record_digest,
        runtime.plan.artifact_digest,
        runtime.plan.record.record_digest,
        readiness.artifact_digest,
        readiness.record.record_digest,
        runtime.catalog_digest,
        runtime.source.version,
        runtime.source.digest,
        readiness.record.playbook_version,
        runtime.executable_identity_digest,
        runtime.toolchain_evidence_digest,
        inventory.record.generation,
        inventory.digest,
        inventory.record.inventory_digest,
        trust.record.generation,
        trust.digest,
        trust.record.entries_digest,
        len(runtime.host_ids),
        runtime.host_set_digest,
        readiness.record.route_digest,
    )
    if _evidence_binding(record) != expected:
        raise StateConflictError("deploy prerequisite evidence provenance is stale")


def _execution_binding(record: DeployPrerequisiteExecution) -> tuple[object, ...]:
    return (
        record.cluster_uuid,
        record.cluster_name,
        record.operation_id,
        record.request_digest,
        record.journal_generation,
        record.journal_digest,
        record.journal_status,
        record.journal_phase,
        record.context_artifact_digest,
        record.context_record_digest,
        record.plan_artifact_digest,
        record.plan_record_digest,
        record.readiness_artifact_digest,
        record.readiness_record_digest,
        record.catalog_digest,
        record.source_version,
        record.source_digest,
        record.toolchain_version,
        record.executable_identity_digest,
        record.toolchain_evidence_digest,
        record.inventory_generation,
        record.inventory_artifact_digest,
        record.inventory_digest,
        record.trust_generation,
        record.trust_artifact_digest,
        record.trust_entries_digest,
        record.host_count,
        record.host_set_digest,
        record.route_digest,
    )


def _evidence_binding(record: DeployPrerequisiteEvidence) -> tuple[object, ...]:
    return (
        record.cluster_uuid,
        record.cluster_name,
        record.operation_id,
        record.request_digest,
        record.journal_generation,
        record.journal_digest,
        record.context_artifact_digest,
        record.context_record_digest,
        record.plan_artifact_digest,
        record.plan_record_digest,
        record.readiness_artifact_digest,
        record.readiness_record_digest,
        record.catalog_digest,
        record.source_version,
        record.source_digest,
        record.toolchain_version,
        record.executable_identity_digest,
        record.toolchain_evidence_digest,
        record.inventory_generation,
        record.inventory_artifact_digest,
        record.inventory_digest,
        record.trust_generation,
        record.trust_artifact_digest,
        record.trust_entries_digest,
        record.host_count,
        record.host_set_digest,
        record.route_digest,
    )


def _execution_binding_digests(
    record: DeployPrerequisiteExecution,
) -> tuple[str, ...]:
    return tuple(
        value
        for value in (
            record.request_digest,
            record.journal_digest,
            record.context_artifact_digest,
            record.context_record_digest,
            record.plan_artifact_digest,
            record.plan_record_digest,
            record.readiness_artifact_digest,
            record.readiness_record_digest,
            record.catalog_digest,
            record.source_digest,
            record.executable_identity_digest,
            record.toolchain_evidence_digest,
            record.inventory_artifact_digest,
            record.inventory_digest,
            record.trust_artifact_digest,
            record.trust_entries_digest,
            record.host_set_digest,
            record.route_digest,
        )
    )


def _evidence_binding_digests(
    record: DeployPrerequisiteEvidence,
) -> tuple[str, ...]:
    return tuple(
        value
        for value in (
            record.request_digest,
            record.journal_digest,
            record.context_artifact_digest,
            record.context_record_digest,
            record.plan_artifact_digest,
            record.plan_record_digest,
            record.readiness_artifact_digest,
            record.readiness_record_digest,
            record.catalog_digest,
            record.source_digest,
            record.executable_identity_digest,
            record.toolchain_evidence_digest,
            record.inventory_artifact_digest,
            record.inventory_digest,
            record.trust_artifact_digest,
            record.trust_entries_digest,
            record.host_set_digest,
            record.route_digest,
        )
    )


def _runtime_binding_digest(runtime: _RuntimeContext) -> str:
    return _digest_object(
        {
            "catalog_digest": runtime.catalog_digest,
            "context_artifact_digest": runtime.context.artifact_digest,
            "context_record_digest": runtime.context.record.record_digest,
            "executable_identity_digest": runtime.executable_identity_digest,
            "host_set_digest": runtime.host_set_digest,
            "plan_artifact_digest": runtime.plan.artifact_digest,
            "plan_record_digest": runtime.plan.record.record_digest,
            "source_digest": runtime.source.digest,
            "toolchain_evidence_digest": runtime.toolchain_evidence_digest,
        }
    )


def _digest_object(value: object) -> str:
    return digest_bytes(serialize_json({"value": value}))


def _timestamp() -> str:
    return format_timestamp(datetime.now(tz=UTC))


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be a boolean")
    return value


def _positive_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


def _nonnegative_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StatePersistenceError(f"{label} must be nonnegative")


def _validate_toolchain_version(value: str) -> None:
    try:
        parse_ansible_core_version(
            f"ansible-playbook [core {value}]\n",
            expected_executable="ansible-playbook",
        )
    except AnsibleVersionError as error:
        raise StatePersistenceError(
            "deploy prerequisite toolchain version is invalid"
        ) from error


def _require_canonical_paths(paths: StatePaths) -> None:
    if StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths:
        raise StatePersistenceError("deploy prerequisite paths are not canonical")


def _operation_id_from_filename(name: str, suffix: str) -> uuid.UUID | None:
    if not name.endswith(suffix):
        return None
    value = name[: -len(suffix)]
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return None
    return parsed if str(parsed) == value else None
