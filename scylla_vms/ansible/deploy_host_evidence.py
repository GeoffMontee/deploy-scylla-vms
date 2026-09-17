"""Deploy-only pre-mutation host-evidence checkpoint.

This owner deliberately executes the reviewed ``evidence-collect`` source as a
separate checkpoint.  It does not complete the final mapped deploy evidence
step, reconcile the immutable effective plan, or authorize a mutation.
"""

from __future__ import annotations

import ipaddress
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

from scylla_vms.ansible.commands import AnsibleCommandBuilder
from scylla_vms.ansible.deploy_plan import (
    ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION,
    _assert_operation_lock,
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_prerequisites import (
    ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_PREREQUISITE_EXECUTION_SCHEMA_VERSION,
)
from scylla_vms.ansible.deploy_reconciliation import (
    ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION,
    DeployEffectiveEvidenceState,
    DeployEffectivePlanStore,
    DeployEffectiveStepStatus,
    StoredDeployEffectivePlan,
    _build_effective_plan,
    _build_effective_steps,
    _load_reconciliation_context,
    _ReconciliationContext,
)
from scylla_vms.ansible.evidence import (
    HOST_EVIDENCE_SCHEMA_VERSION,
    EvidenceStatus,
    HostEvidence,
)
from scylla_vms.ansible.operation_binding import readiness_binding_digest
from scylla_vms.ansible.operation_coordinator import ControlledAnsibleExecutables
from scylla_vms.ansible.operation_execution import (
    ExecutionAttempt,
    ExecutionAttemptState,
)
from scylla_vms.ansible.registry import get_playbook
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
    StatePersistenceError,
)
from scylla_vms.journal import JOURNAL_SCHEMA_VERSION, JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification
from scylla_vms.persistence import (
    AtomicJsonFile,
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

ANSIBLE_DEPLOY_PRE_MUTATION_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-pre-mutation-host-evidence-binding/v1"
)
ANSIBLE_DEPLOY_PRE_MUTATION_EXECUTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-pre-mutation-host-evidence-execution/v1"
)
ANSIBLE_DEPLOY_PRE_MUTATION_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-pre-mutation-host-evidence/v1"
)
ANSIBLE_DEPLOY_PRE_MUTATION_EVIDENCE_ENTRY_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-pre-mutation-host-evidence-entry/v1"
)
ANSIBLE_DEPLOY_PRE_MUTATION_HOST_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-pre-mutation-host/v1"
)
ANSIBLE_DEPLOY_PRE_MUTATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-pre-mutation-host-evidence-report/v1"
)

DEPLOY_PRE_MUTATION_EXECUTION_FILENAME_SUFFIX = (
    ".ansible-deploy-pre-mutation-host-evidence-execution.json"
)
DEPLOY_PRE_MUTATION_EVIDENCE_FILENAME_SUFFIX = (
    ".ansible-deploy-pre-mutation-host-evidence.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "evidence-collect"
_CHECKPOINT_KIND = "pre-mutation-host-evidence"
_COLLECTED = "pre-mutation-host-evidence-collected"
_REBOOT_NOT_COLLECTED = "not-collected"
_EVIDENCE_TIMEOUT_SECONDS = 10
_ROLE_ORDER = (
    HostRole.JUMP_HOST,
    HostRole.SCYLLA,
    HostRole.MANAGER,
    HostRole.MONITORING,
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")
_FACT_TEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,127}\Z")
_VERSION_TEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._()+-]{0,127}\Z")
_SECRET_TEXT = re.compile(r"(?i)(?:credential|password|private[-_ ]?key|secret|token)")
_PROVIDER_ID_TEXT = re.compile(r"(?i)\bocid1\.")
_IPV4_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![A-Za-z0-9])"
)
_SERVICE_STATES = frozenset(
    {"active", "inactive", "running", "stopped", "unknown", "unavailable"}
)
_ROLE_SERVICES = {
    HostRole.JUMP_HOST: (),
    HostRole.SCYLLA: ("scylla-server.service",),
    HostRole.MANAGER: ("scylla-manager.service",),
    HostRole.MONITORING: ("grafana-server.service", "prometheus.service"),
}


class PreMutationEvidenceStatus(StrEnum):
    """Bounded terminal semantic state for one deterministic role batch."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNREACHABLE = "unreachable"


@dataclass(frozen=True, slots=True)
class DeployPreMutationBinding:
    """Exact canonical chain and distinct checkpoint identity."""

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
    original_plan_artifact_digest: str
    original_plan_record_digest: str
    effective_plan_artifact_digest: str
    effective_plan_record_digest: str
    effective_plan_digest: str
    prerequisite_execution_artifact_digest: str
    prerequisite_evidence_artifact_digest: str
    prerequisite_evidence_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    catalog_digest: str
    source_version: str
    source_digest: str
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
    host_count: int
    host_set_digest: str
    batch_count: int
    batch_plan_digest: str
    checkpoint_kind: str
    checkpoint_digest: str
    binding_digest: str
    context_schema_version: str = ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
    original_plan_schema_version: str = ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION
    effective_plan_schema_version: str = ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION
    prerequisite_execution_schema_version: str = (
        ANSIBLE_DEPLOY_PREREQUISITE_EXECUTION_SCHEMA_VERSION
    )
    prerequisite_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_PRE_MUTATION_BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_PRE_MUTATION_BINDING_SCHEMA_VERSION
            or self.context_schema_version != ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
            or self.original_plan_schema_version != ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION
            or self.effective_plan_schema_version
            != ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION
            or self.prerequisite_execution_schema_version
            != ANSIBLE_DEPLOY_PREREQUISITE_EXECUTION_SCHEMA_VERSION
            or self.prerequisite_evidence_schema_version
            != ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.source_version != ANSIBLE_SOURCE_VERSION
            or self.checkpoint_kind != _CHECKPOINT_KIND
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
        ):
            raise StatePersistenceError("pre-mutation evidence binding is unsupported")
        validate_cluster_name(self.cluster_name)
        for value, label in (
            (self.journal_generation, "journal generation"),
            (self.observation_generation, "observation generation"),
            (self.inventory_generation, "inventory generation"),
            (self.trust_generation, "trust generation"),
            (self.host_count, "host count"),
            (self.batch_count, "batch count"),
        ):
            _positive_integer(value, label)
        if self.batch_count > len(_ROLE_ORDER):
            raise StatePersistenceError("pre-mutation evidence batch count is invalid")
        _validate_toolchain_version(self.toolchain_version)
        for digest_value in _binding_digests(self):
            validate_digest(digest_value, "pre-mutation evidence binding digest")
        if self.binding_digest != _binding_digest(self):
            raise StatePersistenceError(
                "pre-mutation evidence binding digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            result[name] = (
                str(value)
                if isinstance(value, uuid.UUID)
                else value.value
                if isinstance(value, (JournalStatus, OperationPhase))
                else value
            )
        return result

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployPreMutationBinding:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "pre-mutation evidence binding",
        )
        try:
            journal_status = JournalStatus(require_string(value, "journal_status"))
            journal_phase = OperationPhase(require_string(value, "journal_phase"))
        except ValueError as error:
            raise StatePersistenceError(
                "pre-mutation evidence binding enum is invalid"
            ) from error
        integer_fields = {
            "journal_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
            "host_count",
            "batch_count",
        }
        parsed: dict[str, object] = {}
        for name in cls.__dataclass_fields__:
            if name == "cluster_uuid":
                parsed[name] = parse_uuid(
                    require_string(value, name), "binding cluster UUID"
                )
            elif name == "operation_id":
                parsed[name] = parse_uuid(
                    require_string(value, name), "binding operation ID"
                )
            elif name == "journal_status":
                parsed[name] = journal_status
            elif name == "journal_phase":
                parsed[name] = journal_phase
            elif name in integer_fields:
                parsed[name] = _integer(value[name], name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployPreMutationExecution:
    """Durable intent and terminal state for deterministic role batches."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployPreMutationBinding
    state: ExecutionAttemptState
    all_batches_completed: bool
    attempts: tuple[ExecutionAttempt, ...]
    schema_version: str = ANSIBLE_DEPLOY_PRE_MUTATION_EXECUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_PRE_MUTATION_EXECUTION_SCHEMA_VERSION
            or not isinstance(self.binding, DeployPreMutationBinding)
            or not isinstance(self.state, ExecutionAttemptState)
            or not isinstance(self.all_batches_completed, bool)
        ):
            raise StatePersistenceError("pre-mutation execution identity is invalid")
        _positive_integer(self.generation, "execution generation")
        created = parse_timestamp(self.created_at)
        updated = parse_timestamp(self.updated_at)
        if updated < created:
            raise StatePersistenceError("pre-mutation execution timestamp regressed")
        _validate_attempts(
            self.attempts,
            state=self.state,
            all_batches_completed=self.all_batches_completed,
            batch_count=self.binding.batch_count,
        )

    def to_object(self) -> dict[str, object]:
        return {
            "all_batches_completed": self.all_batches_completed,
            "attempts": [attempt.to_object() for attempt in self.attempts],
            "binding": self.binding.to_object(),
            "created_at": self.created_at,
            "generation": self.generation,
            "schema_version": self.schema_version,
            "state": self.state.value,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployPreMutationExecution:
        require_exact_keys(
            value,
            {
                "all_batches_completed",
                "attempts",
                "binding",
                "created_at",
                "generation",
                "schema_version",
                "state",
                "updated_at",
            },
            "pre-mutation execution",
        )
        binding = value["binding"]
        attempts = value["attempts"]
        if not isinstance(binding, Mapping) or not isinstance(attempts, list):
            raise StatePersistenceError("pre-mutation execution content is invalid")
        try:
            state = ExecutionAttemptState(require_string(value, "state"))
        except ValueError as error:
            raise StatePersistenceError(
                "pre-mutation execution state is invalid"
            ) from error
        return cls(
            generation=_integer(value["generation"], "execution generation"),
            created_at=require_string(value, "created_at"),
            updated_at=require_string(value, "updated_at"),
            binding=DeployPreMutationBinding.from_object(binding),
            state=state,
            all_batches_completed=_boolean(
                value["all_batches_completed"], "execution completion"
            ),
            attempts=tuple(
                ExecutionAttempt.from_object(_mapping(item, "execution attempt"))
                for item in attempts
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class PreMutationServiceState:
    """One allowlisted service state without service output."""

    name: str
    status: str

    def __post_init__(self) -> None:
        if (
            self.name
            not in {
                service for services in _ROLE_SERVICES.values() for service in services
            }
            or self.status not in _SERVICE_STATES
        ):
            raise StatePersistenceError("pre-mutation service state is invalid")

    def to_object(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status}

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> PreMutationServiceState:
        require_exact_keys(value, {"name", "status"}, "pre-mutation service state")
        return cls(require_string(value, "name"), require_string(value, "status"))


@dataclass(frozen=True, slots=True)
class PreMutationHostEvidence:
    """Address-free host facts retained for later pre-mutation gates."""

    logical_id: str
    role: HostRole
    evidence_status: EvidenceStatus
    os_family: str | None
    os_version: str | None
    architecture: str | None
    reboot_required: str
    cpu_count: int | None
    memory_mib: int | None
    filesystem_status: str
    mount_count: int
    mount_evidence_digest: str
    block_device_status: str
    block_device_count: int
    device_set_digest: str
    services: tuple[PreMutationServiceState, ...]
    role_health_status: str
    role_health_digest: str
    blockers: tuple[str, ...]
    schema_version: str = ANSIBLE_DEPLOY_PRE_MUTATION_HOST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_PRE_MUTATION_HOST_SCHEMA_VERSION
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", self.logical_id)
            or not isinstance(self.role, HostRole)
            or not isinstance(self.evidence_status, EvidenceStatus)
            or self.reboot_required
            not in {_REBOOT_NOT_COLLECTED, "not-required", "required"}
            or self.filesystem_status not in {"available", "unavailable"}
            or self.block_device_status not in {"available", "unavailable"}
        ):
            raise StatePersistenceError("pre-mutation host evidence is invalid")
        for value, label in (
            (self.cpu_count, "CPU count"),
            (self.memory_mib, "memory"),
        ):
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 0
            ):
                raise StatePersistenceError(f"pre-mutation host {label} is invalid")
        _nonnegative_integer(self.mount_count, "mount count")
        _nonnegative_integer(self.block_device_count, "block-device count")
        for digest_value in (
            self.mount_evidence_digest,
            self.device_set_digest,
            self.role_health_digest,
        ):
            validate_digest(digest_value, "pre-mutation host digest")
        for fact_value, label, pattern in (
            (self.os_family, "OS family", _FACT_TEXT),
            (self.os_version, "OS version", _VERSION_TEXT),
            (self.architecture, "architecture", _VERSION_TEXT),
        ):
            _validate_optional_fact(fact_value, label, pattern)
        if (
            tuple(service.name for service in self.services)
            != _ROLE_SERVICES[self.role]
        ):
            raise StatePersistenceError(
                "pre-mutation host service applicability conflicts"
            )
        allowed_health = (
            {"passed", "failed", "unavailable"}
            if self.role is HostRole.SCYLLA
            else {"not-performed"}
        )
        if self.role_health_status not in allowed_health:
            raise StatePersistenceError(
                "pre-mutation role health applicability conflicts"
            )
        if self.blockers != tuple(sorted(set(self.blockers))) or any(
            not _BLOCKER.fullmatch(item) for item in self.blockers
        ):
            raise StatePersistenceError("pre-mutation host blockers are invalid")

    def to_object(self) -> dict[str, object]:
        return {
            "architecture": self.architecture,
            "block_device_count": self.block_device_count,
            "block_device_status": self.block_device_status,
            "blockers": list(self.blockers),
            "cpu_count": self.cpu_count,
            "device_set_digest": self.device_set_digest,
            "evidence_status": self.evidence_status.value,
            "filesystem_status": self.filesystem_status,
            "logical_id": self.logical_id,
            "memory_mib": self.memory_mib,
            "mount_count": self.mount_count,
            "mount_evidence_digest": self.mount_evidence_digest,
            "os_family": self.os_family,
            "os_version": self.os_version,
            "reboot_required": self.reboot_required,
            "role": self.role.value,
            "role_health_digest": self.role_health_digest,
            "role_health_status": self.role_health_status,
            "schema_version": self.schema_version,
            "services": [service.to_object() for service in self.services],
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> PreMutationHostEvidence:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "pre-mutation host evidence",
        )
        services = value["services"]
        if not isinstance(services, list):
            raise StatePersistenceError("pre-mutation host services are invalid")
        try:
            role = HostRole(require_string(value, "role"))
            status = EvidenceStatus(require_string(value, "evidence_status"))
        except ValueError as error:
            raise StatePersistenceError("pre-mutation host enum is invalid") from error
        return cls(
            logical_id=require_string(value, "logical_id"),
            role=role,
            evidence_status=status,
            os_family=_optional_string(value["os_family"], "OS family"),
            os_version=_optional_string(value["os_version"], "OS version"),
            architecture=_optional_string(value["architecture"], "architecture"),
            reboot_required=require_string(value, "reboot_required"),
            cpu_count=_optional_integer(value["cpu_count"], "CPU count"),
            memory_mib=_optional_integer(value["memory_mib"], "memory"),
            filesystem_status=require_string(value, "filesystem_status"),
            mount_count=_integer(value["mount_count"], "mount count"),
            mount_evidence_digest=require_string(value, "mount_evidence_digest"),
            block_device_status=require_string(value, "block_device_status"),
            block_device_count=_integer(
                value["block_device_count"], "block-device count"
            ),
            device_set_digest=require_string(value, "device_set_digest"),
            services=tuple(
                PreMutationServiceState.from_object(
                    _mapping(item, "pre-mutation service")
                )
                for item in services
            ),
            role_health_status=require_string(value, "role_health_status"),
            role_health_digest=require_string(value, "role_health_digest"),
            blockers=_string_tuple(value["blockers"], "host blockers"),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployPreMutationEvidenceEntry:
    """One deterministic role batch and its strict semantic evidence."""

    sequence: int
    role: HostRole
    playbook: str
    result_schema_version: str
    host_evidence_schema_version: str
    variables_digest: str
    command_digest: str
    source_digest: str
    result_digest: str
    evidence_digest: str
    target_count: int
    target_set_digest: str
    status: PreMutationEvidenceStatus
    hosts: tuple[PreMutationHostEvidence, ...]
    schema_version: str = ANSIBLE_DEPLOY_PRE_MUTATION_EVIDENCE_ENTRY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        definition = get_playbook(_PLAYBOOK)
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_PRE_MUTATION_EVIDENCE_ENTRY_SCHEMA_VERSION
            or self.sequence < 1
            or not isinstance(self.role, HostRole)
            or self.playbook != _PLAYBOOK
            or self.result_schema_version != definition.execution_result_schema_version
            or self.host_evidence_schema_version != HOST_EVIDENCE_SCHEMA_VERSION
            or not isinstance(self.status, PreMutationEvidenceStatus)
            or self.target_count != len(self.hosts)
            or self.target_count < 1
            or tuple(host.logical_id for host in self.hosts)
            != tuple(sorted(host.logical_id for host in self.hosts))
            or any(host.role is not self.role for host in self.hosts)
        ):
            raise StatePersistenceError(
                "pre-mutation evidence entry identity is invalid"
            )
        for value in (
            self.variables_digest,
            self.command_digest,
            self.source_digest,
            self.result_digest,
            self.evidence_digest,
            self.target_set_digest,
        ):
            validate_digest(value, "pre-mutation evidence entry digest")
        if self.target_set_digest != _digest_object(
            [host.logical_id for host in self.hosts]
        ):
            raise StatePersistenceError("pre-mutation evidence target digest conflicts")
        if self.evidence_digest != _entry_evidence_digest(self):
            raise StatePersistenceError(
                "pre-mutation semantic evidence digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "command_digest": self.command_digest,
            "evidence_digest": self.evidence_digest,
            "host_evidence_schema_version": self.host_evidence_schema_version,
            "hosts": [host.to_object() for host in self.hosts],
            "playbook": self.playbook,
            "result_digest": self.result_digest,
            "result_schema_version": self.result_schema_version,
            "role": self.role.value,
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "source_digest": self.source_digest,
            "status": self.status.value,
            "target_count": self.target_count,
            "target_set_digest": self.target_set_digest,
            "variables_digest": self.variables_digest,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployPreMutationEvidenceEntry:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "pre-mutation evidence entry",
        )
        hosts = value["hosts"]
        if not isinstance(hosts, list):
            raise StatePersistenceError("pre-mutation evidence hosts are invalid")
        try:
            role = HostRole(require_string(value, "role"))
            status = PreMutationEvidenceStatus(require_string(value, "status"))
        except ValueError as error:
            raise StatePersistenceError(
                "pre-mutation evidence entry enum is invalid"
            ) from error
        return cls(
            sequence=_integer(value["sequence"], "evidence sequence"),
            role=role,
            playbook=require_string(value, "playbook"),
            result_schema_version=require_string(value, "result_schema_version"),
            host_evidence_schema_version=require_string(
                value, "host_evidence_schema_version"
            ),
            variables_digest=require_string(value, "variables_digest"),
            command_digest=require_string(value, "command_digest"),
            source_digest=require_string(value, "source_digest"),
            result_digest=require_string(value, "result_digest"),
            evidence_digest=require_string(value, "evidence_digest"),
            target_count=_integer(value["target_count"], "target count"),
            target_set_digest=require_string(value, "target_set_digest"),
            status=status,
            hosts=tuple(
                PreMutationHostEvidence.from_object(_mapping(item, "pre-mutation host"))
                for item in hosts
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployPreMutationEvidence:
    """Immutable-prefix semantic companion for the distinct checkpoint."""

    generation: int
    created_at: str
    updated_at: str
    binding: DeployPreMutationBinding
    entries: tuple[DeployPreMutationEvidenceEntry, ...]
    schema_version: str = ANSIBLE_DEPLOY_PRE_MUTATION_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_PRE_MUTATION_EVIDENCE_SCHEMA_VERSION
            or not isinstance(self.binding, DeployPreMutationBinding)
        ):
            raise StatePersistenceError("pre-mutation evidence identity is invalid")
        _positive_integer(self.generation, "evidence generation")
        if parse_timestamp(self.updated_at) < parse_timestamp(self.created_at):
            raise StatePersistenceError("pre-mutation evidence timestamp regressed")
        if (
            self.generation != len(self.entries)
            or not 1 <= len(self.entries) <= self.binding.batch_count
            or tuple(entry.sequence for entry in self.entries)
            != tuple(range(1, len(self.entries) + 1))
        ):
            raise StatePersistenceError("pre-mutation evidence prefix is invalid")

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
    def from_object(cls, value: Mapping[str, object]) -> DeployPreMutationEvidence:
        require_exact_keys(
            value,
            {
                "binding",
                "created_at",
                "entries",
                "generation",
                "schema_version",
                "updated_at",
            },
            "pre-mutation evidence",
        )
        binding = value["binding"]
        entries = value["entries"]
        if not isinstance(binding, Mapping) or not isinstance(entries, list):
            raise StatePersistenceError("pre-mutation evidence content is invalid")
        return cls(
            generation=_integer(value["generation"], "evidence generation"),
            created_at=require_string(value, "created_at"),
            updated_at=require_string(value, "updated_at"),
            binding=DeployPreMutationBinding.from_object(binding),
            entries=tuple(
                DeployPreMutationEvidenceEntry.from_object(
                    _mapping(item, "pre-mutation evidence entry")
                )
                for item in entries
            ),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StoredDeployPreMutationExecution:
    record: DeployPreMutationExecution
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class StoredDeployPreMutationEvidence:
    record: DeployPreMutationEvidence
    artifact_digest: str


class DeployPreMutationExecutionStore:
    """Generation-guarded owner-only pre-mutation execution state."""

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
        self._path = deploy_pre_mutation_execution_path(paths, operation_id)
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
    ) -> StoredDeployPreMutationExecution:
        value, artifact_digest = self._file.read()
        record = DeployPreMutationExecution.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError("pre-mutation execution identity conflicts")
        return StoredDeployPreMutationExecution(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPreMutationExecution:
        _assert_operation_lock(lock, self._paths, self._operation_id)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployPreMutationExecution,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployPreMutationExecution:
        _assert_operation_lock(lock, self._paths, self._operation_id)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError("pre-mutation execution operation conflicts")
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial pre-mutation execution generation conflicts"
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
                    "pre-mutation execution changed concurrently"
                )
            _validate_execution_transition(current.record, record)
        artifact_digest = self._file.write(
            record.to_object(), expected_digest=expected_digest
        )
        return StoredDeployPreMutationExecution(record, artifact_digest)


class DeployPreMutationEvidenceStore:
    """Immutable-prefix owner-only pre-mutation semantic evidence."""

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
        self._path = deploy_pre_mutation_evidence_path(paths, operation_id)
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
    ) -> StoredDeployPreMutationEvidence:
        value, artifact_digest = self._file.read()
        record = DeployPreMutationEvidence.from_object(value)
        if (
            record.binding.operation_id != self._operation_id
            or record.binding.cluster_uuid != expected_cluster_uuid
            or record.binding.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError("pre-mutation evidence identity conflicts")
        return StoredDeployPreMutationEvidence(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPreMutationEvidence:
        _assert_operation_lock(lock, self._paths, self._operation_id)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def append_locked(
        self,
        record: DeployPreMutationEvidence,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredDeployPreMutationEvidence:
        _assert_operation_lock(lock, self._paths, self._operation_id)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.binding.operation_id != self._operation_id:
            raise StatePersistenceError("pre-mutation evidence operation conflicts")
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial pre-mutation evidence generation conflicts"
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
                    "pre-mutation evidence changed concurrently"
                )
            _validate_evidence_transition(current.record, record)
        artifact_digest = self._file.write(
            record.to_object(), expected_digest=expected_digest
        )
        return StoredDeployPreMutationEvidence(record, artifact_digest)


@dataclass(frozen=True, slots=True)
class DeployPreMutationReport:
    """Strict redacted report for the completed distinct checkpoint."""

    operation_id: uuid.UUID
    status: str
    checkpoint_kind: str
    checkpoint_digest: str
    binding_digest: str
    execution_schema_version: str
    execution_artifact_digest: str
    evidence_schema_version: str
    evidence_artifact_digest: str
    effective_plan_schema_version: str
    effective_plan_artifact_digest: str
    effective_plan_digest: str
    batch_count: int
    host_count: int
    complete_host_count: int
    blocked_host_count: int
    role_counts: tuple[tuple[str, int], ...]
    os_counts: tuple[tuple[str, int], ...]
    architecture_counts: tuple[tuple[str, int], ...]
    blocker_counts: tuple[tuple[str, int], ...]
    blocker_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    manual_recovery_required: bool
    automatic_retry_allowed: bool
    effective_plan_reconciled: bool
    mapped_final_evidence_state: str
    schema_version: str = ANSIBLE_DEPLOY_PRE_MUTATION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_PRE_MUTATION_REPORT_SCHEMA_VERSION
            or self.status != _COLLECTED
            or self.checkpoint_kind != _CHECKPOINT_KIND
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_PRE_MUTATION_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_PRE_MUTATION_EVIDENCE_SCHEMA_VERSION
            or self.effective_plan_schema_version
            != ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.manual_recovery_required
            or self.automatic_retry_allowed
            or self.effective_plan_reconciled
            or self.mapped_final_evidence_state != "not-performed"
        ):
            raise StatePersistenceError("pre-mutation evidence report is invalid")
        for value, label in (
            (self.batch_count, "batch count"),
            (self.host_count, "host count"),
            (self.complete_host_count, "complete host count"),
            (self.blocked_host_count, "blocked host count"),
        ):
            _nonnegative_integer(value, label)
        if (
            self.batch_count < 1
            or self.host_count < 1
            or self.complete_host_count != self.host_count
            or self.blocked_host_count > self.host_count
        ):
            raise StatePersistenceError("pre-mutation evidence report counts conflict")
        for counts in (
            self.role_counts,
            self.os_counts,
            self.architecture_counts,
            self.blocker_counts,
        ):
            _validate_counts(counts)
        for digest_value in (
            self.checkpoint_digest,
            self.binding_digest,
            self.execution_artifact_digest,
            self.evidence_artifact_digest,
            self.effective_plan_artifact_digest,
            self.effective_plan_digest,
            self.blocker_digest,
        ):
            validate_digest(digest_value, "pre-mutation evidence report digest")
        if self.blocker_digest != _digest_object(
            [{"blocker": key, "count": count} for key, count in self.blocker_counts]
        ):
            raise StatePersistenceError(
                "pre-mutation evidence report blocker digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "architecture_counts": _counts_object(self.architecture_counts),
            "automatic_retry_allowed": self.automatic_retry_allowed,
            "batch_count": self.batch_count,
            "binding_digest": self.binding_digest,
            "blocked_host_count": self.blocked_host_count,
            "blocker_counts": _counts_object(self.blocker_counts),
            "blocker_digest": self.blocker_digest,
            "checkpoint_digest": self.checkpoint_digest,
            "checkpoint_kind": self.checkpoint_kind,
            "complete_host_count": self.complete_host_count,
            "effective_plan_artifact_digest": self.effective_plan_artifact_digest,
            "effective_plan_digest": self.effective_plan_digest,
            "effective_plan_reconciled": self.effective_plan_reconciled,
            "effective_plan_schema_version": self.effective_plan_schema_version,
            "evidence_artifact_digest": self.evidence_artifact_digest,
            "evidence_schema_version": self.evidence_schema_version,
            "execution_artifact_digest": self.execution_artifact_digest,
            "execution_schema_version": self.execution_schema_version,
            "host_count": self.host_count,
            "journal_phase": self.journal_phase.value,
            "journal_status": self.journal_status.value,
            "manual_recovery_required": self.manual_recovery_required,
            "mapped_final_evidence_state": self.mapped_final_evidence_state,
            "operation_id": str(self.operation_id),
            "os_counts": _counts_object(self.os_counts),
            "role_counts": _counts_object(self.role_counts),
            "schema_version": self.schema_version,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class _RoleBatch:
    sequence: int
    role: HostRole
    target_ids: tuple[str, ...]
    target_digest: str
    variables: Mapping[str, object]
    variables_digest: str
    command_digest: str
    source_digest: str


@dataclass(frozen=True, slots=True)
class _CheckpointContext:
    loaded: _ReconciliationContext
    effective_plan: StoredDeployEffectivePlan
    binding: DeployPreMutationBinding
    batches: tuple[_RoleBatch, ...]


def execute_deploy_pre_mutation_host_evidence(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    runner: ProcessRunnerProtocol,
    executables: ControlledAnsibleExecutables,
    toolchain: AnsibleToolchain,
) -> DeployPreMutationReport:
    """Collect exact role-batched host facts as a distinct deploy checkpoint."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths, operation_id)
    _validate_toolchain_dependency(toolchain)
    executable_identity_digest = _executable_identity_digest(executables)
    toolchain_evidence_digest = _toolchain_evidence_digest(
        toolchain, executable_identity_digest
    )
    _refuse_ambiguous_checkpoint_artifacts(paths, operation_id)
    builder = AnsibleCommandBuilder(
        executables.playbook,
        executables.inventory,
        paths,
    )
    context = _load_checkpoint_context(
        paths,
        operation_id,
        lock=lock,
        builder=builder,
        toolchain=toolchain,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    metadata = context.loaded.planning.base.deploy.metadata.record
    execution_store = DeployPreMutationExecutionStore(paths, operation_id)
    evidence_store = DeployPreMutationEvidenceStore(paths, operation_id)
    for path in (execution_store.path, evidence_store.path):
        validate_state_file(path, allow_missing=True)
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
    _validate_prefix(context, execution, evidence)
    if execution is not None and execution.record.all_batches_completed:
        if evidence is None or len(evidence.record.entries) != len(context.batches):
            raise StateConflictError(
                "completed pre-mutation host evidence is unavailable"
            )
        return _build_report(context, execution, evidence)
    if (
        execution is not None
        and execution.record.state is not ExecutionAttemptState.SUCCEEDED
    ):
        raise StateConflictError(
            "pre-mutation host evidence requires manual recovery and cannot retry"
        )

    service = AnsibleService(builder, runner)
    discovered = service.version(lock)
    if discovered != toolchain:
        raise StateConflictError("pre-mutation host-evidence toolchain drifted")

    context = _load_checkpoint_context(
        paths,
        operation_id,
        lock=lock,
        builder=builder,
        toolchain=toolchain,
        executable_identity_digest=executable_identity_digest,
        toolchain_evidence_digest=toolchain_evidence_digest,
    )
    _validate_prefix(context, execution, evidence)
    readiness = _reconstructed_readiness(context.loaded.planning.base)
    current_index = len(execution.record.attempts) if execution is not None else 0
    while current_index < len(context.batches):
        batch = context.batches[current_index]
        _, validated, variables_digest, command_digest = (
            builder.validate_operation_step(
                _PLAYBOOK,
                step_sequence=batch.sequence,
                limit=batch.target_ids,
                variables=batch.variables,
                tags=(),
                check=True,
                diff=False,
                verbosity=0,
            )
        )
        if (
            variables_digest != batch.variables_digest
            or command_digest != batch.command_digest
        ):
            raise StateConflictError(
                "pre-mutation host-evidence command identity conflicts"
            )
        now = _timestamp()
        attempt = ExecutionAttempt(
            attempt_index=current_index + 1,
            step_sequence=batch.sequence,
            playbook=_PLAYBOOK,
            classification=OperationClassification.READ_ONLY,
            limit=batch.target_ids,
            variables_digest=variables_digest,
            command_digest=command_digest,
            playbook_source_digest=batch.source_digest,
            result_schema_version=get_playbook(
                _PLAYBOOK
            ).execution_result_schema_version,
            state=ExecutionAttemptState.STARTED,
            started_at=now,
            completed_at=None,
            exit_code=None,
            result_digest=None,
            manual_recovery_required=True,
        )
        execution = _persist_started(
            context,
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
                context.loaded.planning.base.deploy.inventory,
                _PLAYBOOK,
                step_sequence=batch.sequence,
                limit=batch.target_ids,
                variables=validated,
                readiness=readiness,
                tags=(),
                check=True,
                diff=False,
                verbosity=0,
            )
            if observed_command_digest != command_digest:
                raise AnsibleResultError("Ansible command result identity conflicts")
        except KeyboardInterrupt:
            _persist_uncertain_or_raise(
                execution_store,
                execution,
                ExecutionAttemptState.INTERRUPTED,
                lock=lock,
                message="pre-mutation host-evidence interruption persistence failed",
            )
            raise AnsibleError(
                "pre-mutation host-evidence execution was interrupted; "
                "manual recovery required"
            ) from None
        except AnsibleError as error:
            _persist_uncertain_or_raise(
                execution_store,
                execution,
                _failure_state(error),
                lock=lock,
                message="pre-mutation host-evidence failure persistence failed",
            )
            raise AnsibleError(
                "pre-mutation host-evidence execution is uncertain; "
                "manual recovery required"
            ) from error

        try:
            after = _load_checkpoint_context(
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
                "pre-mutation host-evidence state changed after invocation; "
                "manual recovery required"
            ) from error
        if after.binding.binding_digest != context.binding.binding_digest:
            raise StateConflictError(
                "pre-mutation host-evidence state changed after invocation; "
                "manual recovery required"
            )
        try:
            entry = _semantic_entry(batch, result)
        except (AnsibleError, StatePersistenceError) as error:
            _persist_uncertain_or_raise(
                execution_store,
                execution,
                ExecutionAttemptState.MALFORMED_RESULT,
                lock=lock,
                message=(
                    "pre-mutation host-evidence malformed-result persistence failed"
                ),
            )
            raise AnsibleError(
                "pre-mutation host-evidence result is malformed; "
                "manual recovery required"
            ) from error
        try:
            evidence = _persist_evidence(
                context,
                evidence_store,
                evidence,
                entry,
                lock=lock,
            )
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "pre-mutation host-evidence persistence failed; "
                "manual recovery required"
            ) from error
        terminal_state = _terminal_state(entry)
        try:
            execution = _persist_terminal(
                context,
                execution_store,
                execution,
                terminal_state,
                result.exit_code,
                entry.result_digest,
                lock=lock,
            )
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "pre-mutation host-evidence terminal persistence failed; "
                "manual recovery required"
            ) from error
        if terminal_state is not ExecutionAttemptState.SUCCEEDED:
            raise AnsibleError(
                "pre-mutation host evidence failed; manual recovery required"
            )
        current_index += 1

    if execution is None or evidence is None:
        raise StatePersistenceError("pre-mutation host-evidence completion is missing")
    _validate_prefix(context, execution, evidence)
    return _build_report(context, execution, evidence)


def deploy_pre_mutation_execution_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = (
        paths.operations
        / f"{operation_id}{DEPLOY_PRE_MUTATION_EXECUTION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "pre-mutation host-evidence execution path is not canonical"
        )
    return path


def deploy_pre_mutation_evidence_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = (
        paths.operations
        / f"{operation_id}{DEPLOY_PRE_MUTATION_EVIDENCE_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError("pre-mutation host-evidence path is not canonical")
    return path


def deploy_pre_mutation_execution_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_PRE_MUTATION_EXECUTION_FILENAME_SUFFIX
    )


def deploy_pre_mutation_evidence_id_from_filename(name: str) -> uuid.UUID | None:
    return _operation_id_from_filename(
        name, DEPLOY_PRE_MUTATION_EVIDENCE_FILENAME_SUFFIX
    )


def _load_checkpoint_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
    builder: AnsibleCommandBuilder,
    toolchain: AnsibleToolchain,
    executable_identity_digest: str,
    toolchain_evidence_digest: str,
) -> _CheckpointContext:
    loaded = _load_reconciliation_context(paths, operation_id, lock=lock)
    planning = loaded.planning
    journal = planning.base.deploy.journal
    readiness = planning.readiness.record
    if (
        journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
        or readiness.executable_identity_digest != executable_identity_digest
        or readiness.toolchain_evidence_digest != toolchain_evidence_digest
        or readiness.playbook_version != str(toolchain.core)
        or readiness.inventory_version != str(toolchain.core)
        or readiness.remote_playbook_status != "not-performed"
    ):
        raise StateConflictError(
            "pre-mutation host-evidence readiness or toolchain conflicts"
        )
    reconstructed = _reconstructed_readiness(planning.base)
    if readiness_binding_digest(reconstructed) != readiness.readiness_digest:
        raise StateConflictError("pre-mutation host-evidence readiness is stale")
    reconstructed.require_ready(OperationClassification.READ_ONLY)

    metadata = planning.base.deploy.metadata.record
    effective_store = DeployEffectivePlanStore(paths, operation_id)
    validate_state_file(effective_store.path, allow_missing=True)
    if not effective_store.path.exists():
        raise StateConflictError(
            "pre-mutation host evidence requires the effective deploy plan"
        )
    effective = effective_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_steps = _build_effective_steps(loaded.plan.record.steps, loaded.evidence)
    expected_effective = _build_effective_plan(
        loaded,
        effective_steps=expected_steps,
        created_at=effective.record.created_at,
    )
    if effective.record != expected_effective:
        raise StateConflictError(
            "pre-mutation host-evidence effective plan is stale or changed"
        )
    mapped_evidence = tuple(
        step for step in effective.record.steps if step.playbook == _PLAYBOOK
    )
    if not mapped_evidence or any(
        step.status is not DeployEffectiveStepStatus.NOT_PERFORMED
        or step.evidence_state is not DeployEffectiveEvidenceState.NOT_PERFORMED
        or step.evidence_digest is not None
        for step in mapped_evidence
    ):
        raise StateConflictError(
            "mapped deploy host evidence must remain not performed"
        )

    inventory_hosts = planning.base.deploy.inventory.record.inventory.hosts
    batches: list[_RoleBatch] = []
    source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
    variables: dict[str, object] = {
        "deploy_scylla_vms_evidence_timeout_seconds": _EVIDENCE_TIMEOUT_SECONDS
    }
    for role in _ROLE_ORDER:
        target_ids = tuple(
            sorted(host.logical_id for host in inventory_hosts if host.role is role)
        )
        if not target_ids:
            continue
        sequence = len(batches) + 1
        _, validated, variables_digest, command_digest = (
            builder.validate_operation_step(
                _PLAYBOOK,
                step_sequence=sequence,
                limit=target_ids,
                variables=variables,
                tags=(),
                check=True,
                diff=False,
                verbosity=0,
            )
        )
        batches.append(
            _RoleBatch(
                sequence,
                role,
                target_ids,
                _digest_object(list(target_ids)),
                validated,
                variables_digest,
                command_digest,
                source_digest,
            )
        )
    if not batches:
        raise StateConflictError("pre-mutation host-evidence targets are unavailable")

    all_host_ids = tuple(sorted(host.logical_id for host in inventory_hosts))
    if tuple(sorted(host for batch in batches for host in batch.target_ids)) != (
        all_host_ids
    ):
        raise StateConflictError("pre-mutation host-evidence target coverage conflicts")
    prerequisite_evidence_digest = _digest_object(
        [entry.evidence_digest for entry in loaded.evidence.record.entries]
    )
    batch_plan_digest = _digest_object(
        [
            {
                "command_digest": batch.command_digest,
                "role": batch.role.value,
                "sequence": batch.sequence,
                "source_digest": batch.source_digest,
                "target_digest": batch.target_digest,
                "variables_digest": batch.variables_digest,
            }
            for batch in batches
        ]
    )
    checkpoint_digest = _digest_object(
        {
            "batch_plan_digest": batch_plan_digest,
            "checkpoint_kind": _CHECKPOINT_KIND,
            "effective_plan_digest": effective.record.effective_plan_digest,
            "host_evidence_schema_version": HOST_EVIDENCE_SCHEMA_VERSION,
            "playbook": _PLAYBOOK,
            "schema_version": ANSIBLE_DEPLOY_PRE_MUTATION_BINDING_SCHEMA_VERSION,
        }
    )
    deploy = planning.base.deploy
    trust = planning.base.trust
    binding_values: dict[str, object] = {
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_name": metadata.cluster_name,
        "operation_id": journal.record.operation_id,
        "operation": _OPERATION,
        "request_digest": journal.record.request_digest,
        "journal_generation": journal.record.generation,
        "journal_digest": journal.digest,
        "journal_status": journal.record.status,
        "journal_phase": journal.record.phase,
        "context_artifact_digest": loaded.context.artifact_digest,
        "context_record_digest": loaded.context.record.record_digest,
        "original_plan_artifact_digest": loaded.plan.artifact_digest,
        "original_plan_record_digest": loaded.plan.record.record_digest,
        "effective_plan_artifact_digest": effective.artifact_digest,
        "effective_plan_record_digest": effective.record.record_digest,
        "effective_plan_digest": effective.record.effective_plan_digest,
        "prerequisite_execution_artifact_digest": loaded.execution.artifact_digest,
        "prerequisite_evidence_artifact_digest": loaded.evidence.artifact_digest,
        "prerequisite_evidence_digest": prerequisite_evidence_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": readiness.record_digest,
        "catalog_digest": loaded.catalog_digest,
        "source_version": loaded.source.version,
        "source_digest": loaded.source.digest,
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
        "host_count": len(all_host_ids),
        "host_set_digest": _digest_object(list(all_host_ids)),
        "batch_count": len(batches),
        "batch_plan_digest": batch_plan_digest,
        "checkpoint_kind": _CHECKPOINT_KIND,
        "checkpoint_digest": checkpoint_digest,
        "binding_digest": "",
    }
    binding_values["binding_digest"] = _binding_digest_from_values(binding_values)
    binding = DeployPreMutationBinding(**binding_values)  # type: ignore[arg-type]
    return _CheckpointContext(loaded, effective, binding, tuple(batches))


def _validate_prefix(
    context: _CheckpointContext,
    execution: StoredDeployPreMutationExecution | None,
    evidence: StoredDeployPreMutationEvidence | None,
) -> None:
    if execution is None:
        if evidence is not None:
            raise StateConflictError(
                "pre-mutation evidence exists without execution intent"
            )
        return
    if execution.record.binding != context.binding:
        raise StateConflictError("pre-mutation execution provenance is stale")
    if evidence is not None and evidence.record.binding != context.binding:
        raise StateConflictError("pre-mutation evidence provenance is stale")
    attempts = execution.record.attempts
    entries = evidence.record.entries if evidence is not None else ()
    for index, attempt in enumerate(attempts):
        batch = context.batches[index]
        if (
            attempt.attempt_index != index + 1
            or attempt.step_sequence != batch.sequence
            or attempt.playbook != _PLAYBOOK
            or attempt.classification is not OperationClassification.READ_ONLY
            or attempt.limit != batch.target_ids
            or attempt.variables_digest != batch.variables_digest
            or attempt.command_digest != batch.command_digest
            or attempt.playbook_source_digest != batch.source_digest
        ):
            raise StateConflictError(
                "pre-mutation execution prefix conflicts with the checkpoint"
            )
    expected_evidence_count = sum(
        attempt.result_digest is not None for attempt in attempts
    )
    if len(entries) != expected_evidence_count:
        raise StateConflictError(
            "pre-mutation execution and evidence prefixes conflict"
        )
    for index, entry in enumerate(entries):
        attempt = attempts[index]
        batch = context.batches[index]
        if (
            entry.sequence != batch.sequence
            or entry.role is not batch.role
            or entry.variables_digest != attempt.variables_digest
            or entry.command_digest != attempt.command_digest
            or entry.source_digest != attempt.playbook_source_digest
            or entry.result_digest != attempt.result_digest
            or entry.target_count != len(batch.target_ids)
            or entry.target_set_digest != batch.target_digest
            or tuple(host.logical_id for host in entry.hosts) != batch.target_ids
        ):
            raise StateConflictError("pre-mutation semantic evidence prefix conflicts")
    if execution.record.all_batches_completed and (
        len(attempts) != len(context.batches)
        or len(entries) != len(context.batches)
        or any(
            attempt.state is not ExecutionAttemptState.SUCCEEDED for attempt in attempts
        )
        or any(
            entry.status is not PreMutationEvidenceStatus.SUCCEEDED for entry in entries
        )
    ):
        raise StateConflictError("pre-mutation completion prefix conflicts")


def _persist_started(
    context: _CheckpointContext,
    store: DeployPreMutationExecutionStore,
    current: StoredDeployPreMutationExecution | None,
    attempt: ExecutionAttempt,
    *,
    lock: ClusterLock,
    now: str,
) -> StoredDeployPreMutationExecution:
    if current is None:
        record = DeployPreMutationExecution(
            generation=1,
            created_at=now,
            updated_at=now,
            binding=context.binding,
            state=ExecutionAttemptState.STARTED,
            all_batches_completed=False,
            attempts=(attempt,),
        )
        return store.write_locked(
            record,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
    if current.record.state is not ExecutionAttemptState.SUCCEEDED:
        raise StateConflictError("pre-mutation started state cannot be retried")
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=now,
        state=ExecutionAttemptState.STARTED,
        all_batches_completed=False,
        attempts=(*current.record.attempts, attempt),
    )
    return store.write_locked(
        record,
        expected_generation=current.record.generation,
        expected_digest=current.artifact_digest,
        lock=lock,
    )


def _persist_uncertain_or_raise(
    store: DeployPreMutationExecutionStore,
    current: StoredDeployPreMutationExecution,
    state: ExecutionAttemptState,
    *,
    lock: ClusterLock,
    message: str,
) -> None:
    try:
        _persist_uncertain(store, current, state, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(f"{message}; manual recovery required") from error


def _persist_uncertain(
    store: DeployPreMutationExecutionStore,
    current: StoredDeployPreMutationExecution,
    state: ExecutionAttemptState,
    *,
    lock: ClusterLock,
) -> StoredDeployPreMutationExecution:
    if state not in {
        ExecutionAttemptState.FAILED,
        ExecutionAttemptState.TIMED_OUT,
        ExecutionAttemptState.INTERRUPTED,
        ExecutionAttemptState.MALFORMED_RESULT,
    }:
        raise StatePersistenceError("pre-mutation uncertain state is invalid")
    completed_at = _timestamp()
    attempt = replace(
        current.record.attempts[-1],
        state=state,
        completed_at=completed_at,
    )
    record = replace(
        current.record,
        generation=current.record.generation + 1,
        updated_at=completed_at,
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
    context: _CheckpointContext,
    store: DeployPreMutationExecutionStore,
    current: StoredDeployPreMutationExecution,
    state: ExecutionAttemptState,
    exit_code: int,
    result_digest: str,
    *,
    lock: ClusterLock,
) -> StoredDeployPreMutationExecution:
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
        all_batches_completed=(
            state is ExecutionAttemptState.SUCCEEDED
            and len(current.record.attempts) == len(context.batches)
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
    context: _CheckpointContext,
    store: DeployPreMutationEvidenceStore,
    current: StoredDeployPreMutationEvidence | None,
    entry: DeployPreMutationEvidenceEntry,
    *,
    lock: ClusterLock,
) -> StoredDeployPreMutationEvidence:
    now = _timestamp()
    if current is None:
        record = DeployPreMutationEvidence(
            generation=1,
            created_at=now,
            updated_at=now,
            binding=context.binding,
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
    batch: _RoleBatch,
    result: AnsibleExecutionResult,
) -> DeployPreMutationEvidenceEntry:
    evidence = result.evidence
    if (
        result.playbook != _PLAYBOOK
        or result.classification is not OperationClassification.READ_ONLY
        or not result.check_mode
        or result.inventory_preflight is not None
        or result.connectivity is not None
        or evidence is None
        or tuple(host.logical_id for host in evidence.hosts) != batch.target_ids
        or any(host.role is not batch.role for host in evidence.hosts)
    ):
        raise AnsibleResultError("pre-mutation host-evidence result identity conflicts")
    hosts = tuple(_project_host(host) for host in evidence.hosts)
    result_digest = _digest_object(
        {
            "hosts": [host.to_object() for host in evidence.hosts],
            "status": evidence.status.value,
        }
    )
    status = (
        PreMutationEvidenceStatus.UNREACHABLE
        if result.exit_code == 4
        or any("host-unreachable" in host.errors for host in evidence.hosts)
        else PreMutationEvidenceStatus.FAILED
        if result.exit_code != 0
        or evidence.status is not EvidenceStatus.COMPLETE
        or any(not _host_evidence_complete(host) for host in hosts)
        else PreMutationEvidenceStatus.SUCCEEDED
    )
    values: dict[str, object] = {
        "sequence": batch.sequence,
        "role": batch.role,
        "playbook": _PLAYBOOK,
        "result_schema_version": get_playbook(
            _PLAYBOOK
        ).execution_result_schema_version,
        "host_evidence_schema_version": HOST_EVIDENCE_SCHEMA_VERSION,
        "variables_digest": batch.variables_digest,
        "command_digest": batch.command_digest,
        "source_digest": batch.source_digest,
        "result_digest": result_digest,
        "evidence_digest": "",
        "target_count": len(batch.target_ids),
        "target_set_digest": batch.target_digest,
        "status": status,
        "hosts": hosts,
    }
    values["evidence_digest"] = _entry_evidence_digest_from_values(values)
    return DeployPreMutationEvidenceEntry(**values)  # type: ignore[arg-type]


def _project_host(host: HostEvidence) -> PreMutationHostEvidence:
    system = host.system
    os_family = _fact_string(system.get("os_name"), "OS family", _FACT_TEXT)
    os_version = _fact_string(system.get("os_version"), "OS version", _VERSION_TEXT)
    architecture = _fact_string(
        system.get("architecture"), "architecture", _VERSION_TEXT
    )
    cpu_count = _fact_integer(system.get("cpu_count"), "CPU count")
    memory_mib = _fact_integer(system.get("memory_mib"), "memory")
    blockers: set[str] = set()
    if host.status is not EvidenceStatus.COMPLETE:
        blockers.add("host-evidence-unavailable")
    if os_family is None or os_version is None or architecture is None:
        blockers.add("system-identity-unavailable")
    else:
        if os_family.casefold() != "ubuntu":
            blockers.add("unsupported-os-family")
        if re.fullmatch(r"24\.04(?:\.[0-9]+)?", os_version) is None:
            blockers.add("unsupported-os-version")
        if architecture not in {"x86_64", "aarch64"}:
            blockers.add("unsupported-architecture")
    if cpu_count is None or cpu_count < 1 or memory_mib is None or memory_mib < 1:
        blockers.add("capacity-evidence-unavailable")
    if host.filesystem_status != "available" or not any(
        item.mount == "/" for item in host.filesystems
    ):
        blockers.add("mount-evidence-unavailable")
    if host.block_device_status != "available":
        blockers.add("device-evidence-unavailable")
    services = tuple(
        PreMutationServiceState(service.name, service.status)
        for service in host.services
    )
    mount_digest = _digest_object(
        [filesystem.to_object() for filesystem in host.filesystems]
    )
    device_digest = _digest_object(
        [device.to_object() for device in host.block_devices]
    )
    health_digest = _digest_object(
        {
            "role": host.role.value,
            "service_version_status": host.service_version_status,
            "status": host.scylla_health,
        }
    )
    return PreMutationHostEvidence(
        logical_id=host.logical_id,
        role=host.role,
        evidence_status=host.status,
        os_family=os_family,
        os_version=os_version,
        architecture=architecture,
        reboot_required=_REBOOT_NOT_COLLECTED,
        cpu_count=cpu_count,
        memory_mib=memory_mib,
        filesystem_status=host.filesystem_status,
        mount_count=len(host.filesystems),
        mount_evidence_digest=mount_digest,
        block_device_status=host.block_device_status,
        block_device_count=len(host.block_devices),
        device_set_digest=device_digest,
        services=services,
        role_health_status=host.scylla_health,
        role_health_digest=health_digest,
        blockers=tuple(sorted(blockers)),
    )


def _host_evidence_complete(host: PreMutationHostEvidence) -> bool:
    # Completion means the selected host returned one strict role-applicable
    # envelope. Individual bounded facts may truthfully be unavailable and are
    # reconciled as unknown/blocking by the later host-gate owner.
    return host.evidence_status is EvidenceStatus.COMPLETE


def _terminal_state(
    entry: DeployPreMutationEvidenceEntry,
) -> ExecutionAttemptState:
    if entry.status is PreMutationEvidenceStatus.SUCCEEDED:
        return ExecutionAttemptState.SUCCEEDED
    if entry.status is PreMutationEvidenceStatus.UNREACHABLE:
        return ExecutionAttemptState.UNREACHABLE
    return ExecutionAttemptState.FAILED


def _build_report(
    context: _CheckpointContext,
    execution: StoredDeployPreMutationExecution,
    evidence: StoredDeployPreMutationEvidence,
) -> DeployPreMutationReport:
    if (
        not execution.record.all_batches_completed
        or len(evidence.record.entries) != len(context.batches)
        or any(
            entry.status is not PreMutationEvidenceStatus.SUCCEEDED
            for entry in evidence.record.entries
        )
    ):
        raise StateConflictError("pre-mutation host evidence is not complete")
    hosts = tuple(host for entry in evidence.record.entries for host in entry.hosts)
    role_counts = _counter_tuple(Counter(host.role.value for host in hosts))
    os_counts = _counter_tuple(
        Counter(f"{host.os_family} {host.os_version}" for host in hosts)
    )
    architecture_counts = _counter_tuple(
        Counter(cast(str, host.architecture) for host in hosts)
    )
    blockers = Counter(blocker for host in hosts for blocker in host.blockers)
    blocker_counts = _counter_tuple(blockers)
    return DeployPreMutationReport(
        operation_id=context.binding.operation_id,
        status=_COLLECTED,
        checkpoint_kind=context.binding.checkpoint_kind,
        checkpoint_digest=context.binding.checkpoint_digest,
        binding_digest=context.binding.binding_digest,
        execution_schema_version=execution.record.schema_version,
        execution_artifact_digest=execution.artifact_digest,
        evidence_schema_version=evidence.record.schema_version,
        evidence_artifact_digest=evidence.artifact_digest,
        effective_plan_schema_version=context.effective_plan.record.schema_version,
        effective_plan_artifact_digest=context.effective_plan.artifact_digest,
        effective_plan_digest=context.effective_plan.record.effective_plan_digest,
        batch_count=len(evidence.record.entries),
        host_count=len(hosts),
        complete_host_count=sum(
            host.evidence_status is EvidenceStatus.COMPLETE for host in hosts
        ),
        blocked_host_count=sum(bool(host.blockers) for host in hosts),
        role_counts=role_counts,
        os_counts=os_counts,
        architecture_counts=architecture_counts,
        blocker_counts=blocker_counts,
        blocker_digest=_digest_object(
            [{"blocker": key, "count": count} for key, count in blocker_counts]
        ),
        journal_status=context.binding.journal_status,
        journal_phase=context.binding.journal_phase,
        manual_recovery_required=False,
        automatic_retry_allowed=False,
        effective_plan_reconciled=False,
        mapped_final_evidence_state="not-performed",
    )


def _validate_attempts(
    attempts: tuple[ExecutionAttempt, ...],
    *,
    state: ExecutionAttemptState,
    all_batches_completed: bool,
    batch_count: int,
) -> None:
    if not 1 <= len(attempts) <= batch_count:
        raise StatePersistenceError("pre-mutation execution attempt count is invalid")
    for index, attempt in enumerate(attempts, start=1):
        if (
            attempt.attempt_index != index
            or attempt.step_sequence != index
            or attempt.playbook != _PLAYBOOK
            or attempt.classification is not OperationClassification.READ_ONLY
        ):
            raise StatePersistenceError(
                "pre-mutation execution attempt order conflicts"
            )
    if attempts[-1].state is not state or any(
        attempt.state is not ExecutionAttemptState.SUCCEEDED
        for attempt in attempts[:-1]
    ):
        raise StatePersistenceError("pre-mutation execution state conflicts")
    if all_batches_completed != (
        len(attempts) == batch_count
        and all(
            attempt.state is ExecutionAttemptState.SUCCEEDED for attempt in attempts
        )
    ):
        raise StatePersistenceError("pre-mutation execution completion conflicts")


def _validate_execution_transition(
    current: DeployPreMutationExecution,
    replacement: DeployPreMutationExecution,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or current.all_batches_completed
        or current.state
        not in {ExecutionAttemptState.STARTED, ExecutionAttemptState.SUCCEEDED}
    ):
        raise StatePersistenceError("pre-mutation execution transition is invalid")
    if current.state is ExecutionAttemptState.STARTED:
        if (
            len(replacement.attempts) != len(current.attempts)
            or replacement.attempts[:-1] != current.attempts[:-1]
            or replacement.attempts[-1].state is ExecutionAttemptState.STARTED
        ):
            raise StatePersistenceError("pre-mutation terminal transition is invalid")
    elif (
        len(current.attempts) >= current.binding.batch_count
        or replacement.attempts[:-1] != current.attempts
        or replacement.attempts[-1].state is not ExecutionAttemptState.STARTED
    ):
        raise StatePersistenceError("pre-mutation next-batch transition is invalid")


def _validate_evidence_transition(
    current: DeployPreMutationEvidence,
    replacement: DeployPreMutationEvidence,
) -> None:
    if (
        replacement.generation != current.generation + 1
        or replacement.created_at != current.created_at
        or replacement.binding != current.binding
        or replacement.entries[:-1] != current.entries
        or len(replacement.entries) != len(current.entries) + 1
    ):
        raise StatePersistenceError("pre-mutation evidence transition is invalid")


def _binding_digests(binding: DeployPreMutationBinding) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(binding, name))
        for name in binding.__dataclass_fields__
        if name.endswith("_digest")
    )


def _binding_digest(binding: DeployPreMutationBinding) -> str:
    value = binding.to_object()
    value["binding_digest"] = ""
    return _digest_object(value)


def _binding_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployPreMutationBinding.__dataclass_fields__.items():
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


def _entry_evidence_digest(entry: DeployPreMutationEvidenceEntry) -> str:
    value = entry.to_object()
    value["evidence_digest"] = ""
    return _digest_object(value)


def _entry_evidence_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployPreMutationEvidenceEntry.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            item.value
            if isinstance(item, (HostRole, PreMutationEvidenceStatus))
            else [host.to_object() for host in item]
            if name == "hosts" and isinstance(item, tuple)
            else item
        )
    value["evidence_digest"] = ""
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


def _fact_string(value: object, label: str, pattern: re.Pattern[str]) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise AnsibleResultError(f"pre-mutation {label} is invalid")
    _validate_optional_fact(value, label, pattern)
    return value


def _validate_optional_fact(
    value: str | None, label: str, pattern: re.Pattern[str]
) -> None:
    if value is None:
        return
    if (
        pattern.fullmatch(value) is None
        or _SECRET_TEXT.search(value) is not None
        or _PROVIDER_ID_TEXT.search(value) is not None
        or _is_ip_address(value)
    ):
        raise StatePersistenceError(f"pre-mutation {label} is protected or invalid")


def _fact_integer(value: object, label: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AnsibleResultError(f"pre-mutation {label} is invalid")
    return value


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        for candidate in _IPV4_CANDIDATE.finditer(value):
            try:
                ipaddress.ip_address(candidate.group(0))
            except ValueError:
                continue
            return True
        return False
    return True


def _validate_counts(values: tuple[tuple[str, int], ...]) -> None:
    if values != tuple(sorted(values)) or len(values) != len(
        {key for key, _ in values}
    ):
        raise StatePersistenceError("pre-mutation report counts are unordered")
    for key, count in values:
        if (
            not isinstance(key, str)
            or not key
            or len(key) > 256
            or _SECRET_TEXT.search(key) is not None
            or _is_ip_address(key)
        ):
            raise StatePersistenceError("pre-mutation report count key is invalid")
        _positive_integer(count, "report count")


def _counter_tuple(counter: Counter[str]) -> tuple[tuple[str, int], ...]:
    return tuple(sorted(counter.items()))


def _counts_object(values: tuple[tuple[str, int], ...]) -> list[dict[str, object]]:
    return [{"name": key, "count": count} for key, count in values]


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


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
    if not isinstance(value, str):
        raise StatePersistenceError(f"{label} must be a string or null")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be a boolean")
    return value


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise StatePersistenceError(f"{label} must be a string array")
    return tuple(value)


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
            "pre-mutation host-evidence toolchain version is invalid"
        ) from error


def _require_canonical_paths(paths: StatePaths) -> None:
    if StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths:
        raise StatePersistenceError(
            "pre-mutation host-evidence paths are not canonical"
        )


def _refuse_ambiguous_checkpoint_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list pre-mutation host-evidence artifacts"
        ) from error
    canonical = str(operation_id)
    for entry in entries:
        for suffix in (
            DEPLOY_PRE_MUTATION_EXECUTION_FILENAME_SUFFIX,
            DEPLOY_PRE_MUTATION_EVIDENCE_FILENAME_SUFFIX,
        ):
            if not entry.name.endswith(suffix):
                continue
            prefix = entry.name[: -len(suffix)]
            try:
                parsed = uuid.UUID(prefix)
            except ValueError:
                continue
            if parsed == operation_id and prefix != canonical:
                validate_state_file(entry)
                raise StateConflictError(
                    "pre-mutation host-evidence artifacts are ambiguous"
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
