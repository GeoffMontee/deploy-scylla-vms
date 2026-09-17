"""Immutable authorization for the mapped deploy ``monitoring-targets`` step.

This internal owner revalidates the exact post-monitoring-agent reconciliation,
rebuilds the official Scylla Monitoring 4.16.0 target intent, and persists only
an unconsumed ordinary approval checkpoint. It does not write target files,
execute Ansible, start monitoring, or advance the common journal.
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
from scylla_vms.ansible.commands import ansible_command_intent_digest
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_manager_agent_execution import (
    DeployManagerAgentEvidenceEntry,
)
from scylla_vms.ansible.deploy_manager_server_execution import (
    DeployManagerServerEvidenceEntry,
)
from scylla_vms.ansible.deploy_monitoring_agent_execution import (
    DeployMonitoringAgentEvidenceEntry,
)
from scylla_vms.ansible.deploy_monitoring_agent_reconciliation import (
    ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_SCHEMA_VERSION,
    DeployPostMonitoringAgentReconciliationStore,
    StoredDeployPostMonitoringAgentReconciliation,
)
from scylla_vms.ansible.deploy_monitoring_agent_reconciliation import (
    _build_record as _build_post_agent_record,
)
from scylla_vms.ansible.deploy_monitoring_agent_reconciliation import (
    _build_steps as _build_post_agent_steps,
)
from scylla_vms.ansible.deploy_monitoring_agent_reconciliation import (
    _load_context as _load_agent_context,
)
from scylla_vms.ansible.deploy_monitoring_agent_reconciliation import (
    _ReconciliationContext as _AgentReconciliationContext,
)
from scylla_vms.ansible.deploy_monitoring_stack_execution import (
    DeployMonitoringStackEvidenceEntry,
)
from scylla_vms.ansible.deploy_plan import (
    DeployConditionState,
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import _loaded
from scylla_vms.ansible.manager_agent import ManagerAgentStatus
from scylla_vms.ansible.manager_server import ManagerServerStatus
from scylla_vms.ansible.monitoring_agent import (
    LISTEN_POLICY as MONITORING_AGENT_LISTEN_POLICY,
)
from scylla_vms.ansible.monitoring_agent import MonitoringAgentStatus
from scylla_vms.ansible.monitoring_stack import (
    ARTIFACT_DIGEST,
    DOCUMENTED_PORTS,
    SOURCE_COMMIT,
    STACK_ARTIFACTS,
    STACK_RELEASE_LINE,
    STACK_VERSION,
    MonitoringStackEvidence,
    MonitoringStackStatus,
    build_monitoring_stack_payload,
)
from scylla_vms.ansible.monitoring_stack import (
    LISTEN_POLICY as MONITORING_STACK_LISTEN_POLICY,
)
from scylla_vms.ansible.monitoring_targets import (
    MONITORING_TARGETS_SCHEMA_VERSION,
    SCRAPE_PORTS,
    SCRAPE_READINESS,
    TARGET_DIRECTORY,
    TARGET_FILES,
    build_monitoring_targets_payload,
)
from scylla_vms.ansible.operation_authorization import (
    OPERATION_AUTHORIZATION_FILENAME_SUFFIX,
)
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION
from scylla_vms.desired import HostRole, ImageFilter, ImageVersionMatch
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
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
from scylla_vms.state import (
    StatePaths,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)
from scylla_vms.terraform.apply_readiness import _reconstructed_readiness

ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-monitoring-targets-authorization-proof/v1"
)
ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCOPE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-monitoring-targets-authorization-scope/v1"
)
ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-monitoring-targets-authorization/v1"
)
ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-monitoring-targets-authorization-report/v1"
)
DEPLOY_MONITORING_TARGETS_AUTHORIZATION_FILENAME_SUFFIX = (
    ".ansible-deploy-monitoring-targets-authorization.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "monitoring-targets"
_MAPPING_SEQUENCE = 18
_TARGET_ROLE = HostRole.MONITORING.value
_STAGE = "post-monitoring-agent-monitoring-targets"
_SCOPE_KIND = "monitoring-target-files-generation"
_AUTHORIZED = "authorized-pre-execution"
_EXECUTION_UNAVAILABLE = "unavailable"
_FINALIZATION_NOT_STARTED = "not-started"
_PUBLIC_WORKFLOW_UNAVAILABLE = "unavailable"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_EXPECTED_BLOCKERS = (
    "deploy-authorization-not-collected",
    "mutating-deploy-execution-unavailable",
    "public-deploy-workflow-unavailable",
)


class DeployMonitoringTargetsApprovalMethod(StrEnum):
    """PLAN-permitted ordinary approval methods."""

    INTERACTIVE = "interactive"
    CLI_YES = "cli-yes"


class DeployMonitoringTargetsArchitecture(StrEnum):
    """Closed OCI image architecture policy."""

    AMD64 = "amd64"
    AARCH64 = "aarch64"


class DeployMonitoringTargetsListenPolicy(StrEnum):
    """Required pre-start listen policy."""

    NOT_STARTED = "not-started"


class DeployMonitoringTargetsScrapeReadiness(StrEnum):
    """Scrape validation remains outside this authorization."""

    NOT_PERFORMED = "not-performed"


class DeployMonitoringTargetsAuthorizationArtifactState(StrEnum):
    """Immutable authorization persistence result."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployMonitoringTargetsAuthorizationProof:
    """Already-normalized ordinary approval without caller-owned scope."""

    approval_method: DeployMonitoringTargetsApprovalMethod | None = None
    approved: bool = False
    allow_destructive: bool = False
    destructive_scope_provided: bool = False
    narrow_consent_provided: bool = False

    def __post_init__(self) -> None:
        if self.approval_method is not None and not isinstance(
            self.approval_method, DeployMonitoringTargetsApprovalMethod
        ):
            raise StateConflictError(
                "deploy monitoring-targets approval method is invalid"
            )
        if not all(
            isinstance(value, bool)
            for value in (
                self.approved,
                self.allow_destructive,
                self.destructive_scope_provided,
                self.narrow_consent_provided,
            )
        ):
            raise StateConflictError(
                "deploy monitoring-targets authorization proof is malformed"
            )


@dataclass(frozen=True, slots=True)
class DeployMonitoringTargetsProofDecision:
    """Persisted ordinary proof bound to the exact derived target intent."""

    approval_method: DeployMonitoringTargetsApprovalMethod
    approved: bool
    allow_destructive: bool
    destructive_scope_provided: bool
    narrow_consent_provided: bool
    proof_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or not isinstance(
                self.approval_method, DeployMonitoringTargetsApprovalMethod
            )
            or self.approved is not True
            or self.allow_destructive
            or self.destructive_scope_provided
            or self.narrow_consent_provided
        ):
            raise StatePersistenceError(
                "deploy monitoring-targets authorization proof state is invalid"
            )
        validate_digest(
            self.proof_digest, "deploy monitoring-targets authorization proof digest"
        )

    def to_object(self) -> dict[str, object]:
        return {
            "allow_destructive": self.allow_destructive,
            "approval_method": self.approval_method.value,
            "approved": self.approved,
            "destructive_scope_provided": self.destructive_scope_provided,
            "narrow_consent_provided": self.narrow_consent_provided,
            "proof_digest": self.proof_digest,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployMonitoringTargetsProofDecision:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy monitoring-targets authorization proof",
        )
        try:
            method = DeployMonitoringTargetsApprovalMethod(
                require_string(value, "approval_method")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy monitoring-targets authorization proof method is invalid"
            ) from error
        return cls(
            approval_method=method,
            approved=_boolean(value["approved"], "approved"),
            allow_destructive=_boolean(value["allow_destructive"], "allow destructive"),
            destructive_scope_provided=_boolean(
                value["destructive_scope_provided"], "destructive scope"
            ),
            narrow_consent_provided=_boolean(
                value["narrow_consent_provided"], "narrow consent"
            ),
            proof_digest=require_string(value, "proof_digest"),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployMonitoringTargetsAuthorizationScope:
    """One exact redacted official monitoring target-file intent."""

    step_sequence: int
    mapping_sequence: int
    playbook: str
    classification: OperationClassification
    target_role: str
    target_stable_id: str
    target_digest: str
    architecture: DeployMonitoringTargetsArchitecture
    image_policy_digest: str
    file_count: int
    file_set_digest: str
    file_content_set_digest: str
    manager_target_count: int
    scylla_target_count: int
    node_exporter_target_count: int
    manager_agent_target_count: int
    manager_identity_set_digest: str
    scylla_identity_set_digest: str
    listen_policy: DeployMonitoringTargetsListenPolicy
    scrape_readiness: DeployMonitoringTargetsScrapeReadiness
    scrape_performed: bool
    exporters_started: bool
    stack_started: bool
    containers_started: bool
    auth_configured: bool
    public_bind: bool
    manager_registration_performed: bool
    scylla_started: bool
    secrets_written: bool
    compose_generated: bool
    variables_digest: str
    source_digest: str
    command_digest: str
    gate_evidence_digest: str
    base_os_evidence_digest: str
    monitoring_stack_evidence_digest: str
    manager_server_evidence_digest: str
    manager_agent_evidence_set_digest: str
    monitoring_agent_evidence_set_digest: str
    reconciled_step_digest: str
    prior_reconciled_step_digest: str
    original_step_digest: str
    target_intent_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCOPE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        definition = get_playbook(self.playbook)
        prohibited = (
            self.scrape_performed,
            self.exporters_started,
            self.stack_started,
            self.containers_started,
            self.auth_configured,
            self.public_bind,
            self.manager_registration_performed,
            self.scylla_started,
            self.secrets_written,
            self.compose_generated,
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCOPE_SCHEMA_VERSION
            or self.step_sequence < 1
            or self.mapping_sequence != _MAPPING_SEQUENCE
            or self.playbook != _PLAYBOOK
            or self.classification is not OperationClassification.MUTATING
            or definition.classification is not self.classification
            or self.target_role != _TARGET_ROLE
            or not self.target_stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
            or self.target_digest != _digest_object([self.target_stable_id])
            or not isinstance(self.architecture, DeployMonitoringTargetsArchitecture)
            or self.file_count != len(TARGET_FILES)
            or self.manager_target_count != 1
            or self.scylla_target_count < 1
            or self.node_exporter_target_count != self.scylla_target_count
            or self.manager_agent_target_count != self.scylla_target_count
            or self.listen_policy is not DeployMonitoringTargetsListenPolicy.NOT_STARTED
            or self.scrape_readiness
            is not DeployMonitoringTargetsScrapeReadiness.NOT_PERFORMED
            or any(prohibited)
            or self.target_intent_digest != _scope_intent_digest(self)
        ):
            raise StatePersistenceError(
                "deploy monitoring-targets authorization scope policy is invalid"
            )
        for digest in _digest_fields(self):
            validate_digest(
                digest, "deploy monitoring-targets authorization scope digest"
            )

    def to_object(self) -> dict[str, object]:
        return {
            name: (
                value.value
                if isinstance(value, (StrEnum, OperationClassification))
                else value
            )
            for name in self.__dataclass_fields__
            if (value := getattr(self, name)) is not None
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployMonitoringTargetsAuthorizationScope:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy monitoring-targets authorization scope",
        )
        integer_fields = {
            "step_sequence",
            "mapping_sequence",
            "file_count",
            "manager_target_count",
            "scylla_target_count",
            "node_exporter_target_count",
            "manager_agent_target_count",
        }
        boolean_fields = {
            "scrape_performed",
            "exporters_started",
            "stack_started",
            "containers_started",
            "auth_configured",
            "public_bind",
            "manager_registration_performed",
            "scylla_started",
            "secrets_written",
            "compose_generated",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in integer_fields:
                    parsed[name] = _integer(item, name)
                elif name == "classification":
                    parsed[name] = OperationClassification(require_string(value, name))
                elif name == "architecture":
                    parsed[name] = DeployMonitoringTargetsArchitecture(
                        require_string(value, name)
                    )
                elif name == "listen_policy":
                    parsed[name] = DeployMonitoringTargetsListenPolicy(
                        require_string(value, name)
                    )
                elif name == "scrape_readiness":
                    parsed[name] = DeployMonitoringTargetsScrapeReadiness(
                        require_string(value, name)
                    )
                elif name in boolean_fields:
                    parsed[name] = _boolean(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy monitoring-targets authorization scope enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployMonitoringTargetsAuthorization:
    """Immutable unconsumed authorization for one exact target-file intent."""

    generation: int
    created_at: str
    cluster_uuid: uuid.UUID
    cluster_identity_digest: str
    operation_id: uuid.UUID
    operation: str
    stage: str
    scope_kind: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
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
    post_monitoring_agent_artifact_digest: str
    post_monitoring_agent_record_digest: str
    post_monitoring_agent_effective_plan_digest: str
    monitoring_stack_evidence_artifact_digest: str
    monitoring_stack_evidence_digest: str
    manager_server_evidence_artifact_digest: str
    manager_server_evidence_digest: str
    manager_agent_evidence_artifact_digest: str
    manager_agent_evidence_set_digest: str
    monitoring_agent_evidence_artifact_digest: str
    monitoring_agent_evidence_set_digest: str
    base_os_artifact_digest: str
    base_os_evidence_digest: str
    catalog_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    classification: OperationClassification
    scope: DeployMonitoringTargetsAuthorizationScope
    target_count: int
    target_set_digest: str
    authorization_scope_digest: str
    proof: DeployMonitoringTargetsProofDecision
    authorization_state: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_digest: str
    post_monitoring_agent_schema_version: str = (
        ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCHEMA_VERSION
            or self.post_monitoring_agent_schema_version
            != ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.classification is not OperationClassification.MUTATING
            or self.target_count != 1
            or self.target_set_digest != self.scope.target_digest
            or self.authorization_scope_digest != _digest_object(self.scope.to_object())
            or self.monitoring_stack_evidence_digest
            != self.scope.monitoring_stack_evidence_digest
            or self.manager_server_evidence_digest
            != self.scope.manager_server_evidence_digest
            or self.manager_agent_evidence_set_digest
            != self.scope.manager_agent_evidence_set_digest
            or self.monitoring_agent_evidence_set_digest
            != self.scope.monitoring_agent_evidence_set_digest
            or self.authorization_state != _AUTHORIZED
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError(
                "deploy monitoring-targets authorization identity or state is invalid"
            )
        parse_timestamp(self.created_at)
        for count in (
            self.journal_generation,
            self.metadata_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
            self.target_count,
        ):
            _positive_integer(
                count, "deploy monitoring-targets authorization generation or count"
            )
        for digest in _digest_fields(self):
            validate_digest(
                digest, "deploy monitoring-targets authorization binding digest"
            )
        if self.proof.proof_digest != _proof_digest(self, self.proof.to_object()):
            raise StatePersistenceError(
                "deploy monitoring-targets authorization proof digest conflicts"
            )
        if self.authorization_digest != _authorization_digest(self):
            raise StatePersistenceError(
                "deploy monitoring-targets authorization digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            result[name] = (
                str(value)
                if isinstance(value, uuid.UUID)
                else value.value
                if isinstance(
                    value, (JournalStatus, OperationPhase, OperationClassification)
                )
                else value.to_object()
                if name in {"scope", "proof"}
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployMonitoringTargetsAuthorization:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy monitoring-targets authorization",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "metadata_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
            "target_count",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in integer_fields:
                    parsed[name] = _integer(item, name)
                elif name in {"cluster_uuid", "operation_id"}:
                    parsed[name] = parse_uuid(require_string(value, name), name)
                elif name == "journal_status":
                    parsed[name] = JournalStatus(require_string(value, name))
                elif name == "journal_phase":
                    parsed[name] = OperationPhase(require_string(value, name))
                elif name == "classification":
                    parsed[name] = OperationClassification(require_string(value, name))
                elif name == "scope":
                    parsed[name] = (
                        DeployMonitoringTargetsAuthorizationScope.from_object(
                            _mapping(item, "deploy monitoring-targets scope")
                        )
                    )
                elif name == "proof":
                    parsed[name] = DeployMonitoringTargetsProofDecision.from_object(
                        _mapping(item, "deploy monitoring-targets proof")
                    )
                elif name == "consumed":
                    parsed[name] = _boolean(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy monitoring-targets authorization enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployMonitoringTargetsAuthorization:
    record: DeployMonitoringTargetsAuthorization
    artifact_digest: str


class DeployMonitoringTargetsAuthorizationStore:
    """Owner-only immutable authorization at the canonical operation path."""

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
        self._path = deploy_monitoring_targets_authorization_path(paths, operation_id)
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
    ) -> StoredDeployMonitoringTargetsAuthorization:
        value, artifact_digest = self._file.read()
        record = DeployMonitoringTargetsAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_identity_digest
            != _cluster_identity_digest(expected_cluster_uuid, expected_cluster_name)
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "deploy monitoring-targets authorization identity conflicts"
            )
        return StoredDeployMonitoringTargetsAuthorization(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployMonitoringTargetsAuthorization:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployMonitoringTargetsAuthorization,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployMonitoringTargetsAuthorization,
        DeployMonitoringTargetsAuthorizationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy monitoring-targets authorization operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=self._paths.cluster_root.name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy monitoring-targets authorization is immutable; "
                    "use a new operation"
                )
            return current, DeployMonitoringTargetsAuthorizationArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployMonitoringTargetsAuthorization(record, artifact_digest),
            DeployMonitoringTargetsAuthorizationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployMonitoringTargetsAuthorizationReport:
    """Strict redacted authorization report without generated target data."""

    operation_id: uuid.UUID
    artifact_state: DeployMonitoringTargetsAuthorizationArtifactState
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_state: str
    stage: str
    scope_kind: str
    approval_method: DeployMonitoringTargetsApprovalMethod
    approval_state: str
    proof_digest: str
    classification: OperationClassification
    playbook: str
    target_stable_id: str
    target_count: int
    target_set_digest: str
    authorization_scope_digest: str
    architecture: DeployMonitoringTargetsArchitecture
    file_count: int
    file_set_digest: str
    file_content_set_digest: str
    manager_target_count: int
    scylla_target_count: int
    node_exporter_target_count: int
    manager_agent_target_count: int
    manager_identity_set_digest: str
    scylla_identity_set_digest: str
    listen_policy: DeployMonitoringTargetsListenPolicy
    scrape_readiness: DeployMonitoringTargetsScrapeReadiness
    prohibited_action_count: int
    post_monitoring_agent_artifact_digest: str
    post_monitoring_agent_record_digest: str
    monitoring_stack_evidence_digest: str
    manager_server_evidence_digest: str
    manager_agent_evidence_set_digest: str
    monitoring_agent_evidence_set_digest: str
    base_os_artifact_digest: str
    base_os_evidence_digest: str
    inventory_artifact_digest: str
    trust_artifact_digest: str
    readiness_artifact_digest: str
    catalog_digest: str
    ansible_source_digest: str
    blockers_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    journal_digest: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCHEMA_VERSION
    )
    proof_schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    post_monitoring_agent_schema_version: str = (
        ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or self.post_monitoring_agent_schema_version
            != ANSIBLE_DEPLOY_POST_MONITORING_AGENT_RECONCILIATION_SCHEMA_VERSION
            or self.authorization_state != _AUTHORIZED
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.approval_state != "approved"
            or self.classification is not OperationClassification.MUTATING
            or self.playbook != _PLAYBOOK
            or self.target_count != 1
            or self.file_count != len(TARGET_FILES)
            or self.manager_target_count != 1
            or self.scylla_target_count < 1
            or self.node_exporter_target_count != self.scylla_target_count
            or self.manager_agent_target_count != self.scylla_target_count
            or self.listen_policy is not DeployMonitoringTargetsListenPolicy.NOT_STARTED
            or self.scrape_readiness
            is not DeployMonitoringTargetsScrapeReadiness.NOT_PERFORMED
            or self.prohibited_action_count
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError(
                "deploy monitoring-targets authorization report is invalid"
            )
        if (
            not self.target_stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
        ):
            raise StatePersistenceError(
                "deploy monitoring-targets authorization report target is invalid"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy monitoring-targets report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "approval": {
                "digest": self.proof_digest,
                "method": self.approval_method.value,
                "state": self.approval_state,
            },
            "authorization": {
                "artifact_digest": self.authorization_artifact_digest,
                "consumed": self.consumed,
                "digest": self.authorization_digest,
                "schema_version": self.authorization_schema_version,
                "state": self.authorization_state,
            },
            "execution": {
                "available": False,
                "finalization_state": self.finalization_state,
                "public_workflow_state": self.public_workflow_state,
                "state": self.execution_state,
            },
            "journal": {
                "digest": self.journal_digest,
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "operation": {
                "classification": self.classification.value,
                "id": str(self.operation_id),
                "kind": _OPERATION,
            },
            "policy": {
                "architecture": self.architecture.value,
                "file_content_set_digest": self.file_content_set_digest,
                "file_count": self.file_count,
                "file_set_digest": self.file_set_digest,
                "listen": self.listen_policy.value,
                "manager_agent_target_count": self.manager_agent_target_count,
                "manager_identity_set_digest": self.manager_identity_set_digest,
                "manager_target_count": self.manager_target_count,
                "node_exporter_target_count": self.node_exporter_target_count,
                "prohibited_action_count": self.prohibited_action_count,
                "scrape_readiness": self.scrape_readiness.value,
                "scylla_identity_set_digest": self.scylla_identity_set_digest,
                "scylla_target_count": self.scylla_target_count,
            },
            "provenance": {
                "ansible_source_digest": self.ansible_source_digest,
                "base_os": {
                    "artifact_digest": self.base_os_artifact_digest,
                    "evidence_digest": self.base_os_evidence_digest,
                },
                "catalog_digest": self.catalog_digest,
                "inventory_artifact_digest": self.inventory_artifact_digest,
                "manager_agent_evidence_set_digest": (
                    self.manager_agent_evidence_set_digest
                ),
                "manager_server_evidence_digest": self.manager_server_evidence_digest,
                "monitoring_agent_evidence_set_digest": (
                    self.monitoring_agent_evidence_set_digest
                ),
                "monitoring_stack_evidence_digest": (
                    self.monitoring_stack_evidence_digest
                ),
                "post_monitoring_agent": {
                    "artifact_digest": self.post_monitoring_agent_artifact_digest,
                    "record_digest": self.post_monitoring_agent_record_digest,
                    "schema_version": self.post_monitoring_agent_schema_version,
                },
                "readiness_artifact_digest": self.readiness_artifact_digest,
                "trust_artifact_digest": self.trust_artifact_digest,
            },
            "result": self.artifact_state.value,
            "schema_version": self.schema_version,
            "scope": {
                "digest": self.authorization_scope_digest,
                "kind": self.scope_kind,
                "playbook": self.playbook,
                "target_count": self.target_count,
                "target_set_digest": self.target_set_digest,
                "target_stable_id": self.target_stable_id,
            },
            "stage": self.stage,
        }


@dataclass(frozen=True, slots=True)
class _AuthorizationContext:
    agent: _AgentReconciliationContext
    post_agent: StoredDeployPostMonitoringAgentReconciliation


def authorize_deploy_monitoring_targets(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proof: DeployMonitoringTargetsAuthorizationProof,
) -> DeployMonitoringTargetsAuthorizationReport:
    """Authorize the exact mapped monitoring target-file intent."""

    if not isinstance(proof, DeployMonitoringTargetsAuthorizationProof):
        raise StateConflictError(
            "deploy monitoring-targets authorization proof is malformed"
        )
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_authorization_artifacts(paths, operation_id)
    _refuse_incompatible_or_later_artifacts(paths, operation_id)
    context = _load_authorization_context(paths, operation_id, lock=lock)
    loaded = _loaded(
        context.agent.authorization_context.manager.authorization_context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    metadata = loaded.planning.base.deploy.metadata.record
    scope = _derive_authorization_scope(context)
    scope_digest = _digest_object(scope.to_object())
    decision = _normalize_proof(proof, context=context, scope_digest=scope_digest)
    store = DeployMonitoringTargetsAuthorizationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    if store.path.exists():
        stored = store.read_locked(
            lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
        )
        expected = _build_authorization(
            context,
            scope=scope,
            proof=decision,
            created_at=stored.record.created_at,
        )
        if stored.record != expected:
            raise StateConflictError(
                "deploy monitoring-targets authorization changed; "
                "re-plan with a new operation"
            )
        state = DeployMonitoringTargetsAuthorizationArtifactState.REUSED
    else:
        record = _build_authorization(
            context,
            scope=scope,
            proof=decision,
            created_at=format_timestamp(datetime.now(UTC)),
        )
        try:
            stored, state = store.write_locked(record, lock=lock)
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy monitoring-targets authorization persistence failed"
            ) from error
    return _build_report(stored, state=state)


def deploy_monitoring_targets_authorization_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the canonical operation-bound monitoring-targets path."""

    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MONITORING_TARGETS_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy monitoring-targets authorization path is not canonical"
        )
    return path


def deploy_monitoring_targets_authorization_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    suffix = DEPLOY_MONITORING_TARGETS_AUTHORIZATION_FILENAME_SUFFIX
    if not name.endswith(suffix):
        return None
    value = name[: -len(suffix)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _load_authorization_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
) -> _AuthorizationContext:
    agent = _load_agent_context(paths, operation_id, lock=lock)
    loaded = _loaded(
        agent.authorization_context.manager.authorization_context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    metadata = loaded.planning.base.deploy.metadata.record
    store = DeployPostMonitoringAgentReconciliationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    if not store.path.exists():
        raise StateConflictError(
            "deploy monitoring-targets authorization requires post-monitoring-agent "
            "reconciliation"
        )
    post_agent = store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_steps = _build_post_agent_steps(agent)
    expected = _build_post_agent_record(
        agent,
        steps=expected_steps,
        created_at=post_agent.record.created_at,
    )
    if post_agent.record != expected:
        raise StateConflictError(
            "deploy monitoring-targets post-monitoring-agent reconciliation drifted"
        )
    return _AuthorizationContext(agent, post_agent)


def _derive_authorization_scope(
    context: _AuthorizationContext,
) -> DeployMonitoringTargetsAuthorizationScope:
    agent = context.agent
    monitoring_agent_context = agent.authorization_context
    manager_agent_context = monitoring_agent_context.manager.authorization_context
    loaded = _loaded(
        manager_agent_context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    post = context.post_agent.record
    steps = tuple(
        step for step in post.steps if step.mapping_sequence == _MAPPING_SEQUENCE
    )
    if len(steps) != 1:
        raise StateConflictError(
            "deploy monitoring-targets mapped authorization scope is ambiguous"
        )
    step = steps[0]
    definition = get_playbook(_PLAYBOOK)
    source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
    if (
        post.next_mapping_sequence != _MAPPING_SEQUENCE
        or post.next_playbook != _PLAYBOOK
        or post.next_step_status
        is not DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        or post.authorization_required_count != 1
        or post.next_target_count != 1
        or step.status
        is not DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        or step.playbook != _PLAYBOOK
        or step.condition_state is not DeployConditionState.ACTIVE
        or step.classification is not OperationClassification.MUTATING
        or step.target_role != _TARGET_ROLE
        or len(step.target_ids) != 1
        or step.target_digest != post.next_target_set_digest
        or step.evidence_state != "next-gates-evaluated"
        or step.evidence_digest is None
        or step.blockers != _EXPECTED_BLOCKERS
        or step.source_digest != source_digest
        or definition.classification is not OperationClassification.MUTATING
        or definition.hosts != _TARGET_ROLE
        or definition.serial != 1
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.check_mode is not CheckMode.PREVIEW
        or not definition.any_errors_fatal
        or not definition.source_available
    ):
        raise StateConflictError(
            "only the exact active mapped monitoring-targets step may be authorized"
        )
    stable_id = step.target_ids[0]
    monitoring_hosts = tuple(
        host
        for host in deploy.inventory.record.inventory.hosts
        if host.role is HostRole.MONITORING
    )
    if (
        len(monitoring_hosts) != 1
        or monitoring_hosts[0].logical_id != stable_id
        or _digest_object([stable_id]) != step.target_digest
    ):
        raise StateConflictError(
            "deploy monitoring-targets target is not the exact current monitoring "
            "identity"
        )
    base_os = manager_agent_context.monitoring.monitoring.manager.manager.base_os
    base_matches = tuple(
        (entry, host)
        for entry in base_os.record.entries
        for host in entry.hosts
        if host.logical_id == stable_id
    )
    if len(base_matches) != 1:
        raise StateConflictError(
            "deploy monitoring-targets requires exact current monitoring base-os "
            "evidence"
        )
    base_entry, base_host = base_matches[0]
    image_filter = dict(metadata.desired_spec.image_filters).get(HostRole.MONITORING)
    if (
        image_filter != ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT)
        or base_host.os_family != "Ubuntu"
        or base_host.os_version != "24.04"
        or base_host.status not in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
        or not base_host.applied
        or base_host.reboot_required
        or base_host.image_architecture not in {"amd64", "aarch64"}
        or base_entry.status not in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
    ):
        raise StateConflictError(
            "deploy monitoring-targets Ubuntu, architecture, or base-os gate conflicts"
        )

    manager_server = (
        manager_agent_context.monitoring.monitoring.manager.evidence.record.entries
    )
    stack_entries = manager_agent_context.monitoring.evidence.record.entries
    manager_agents = monitoring_agent_context.manager.evidence.record.entries
    monitoring_agents = agent.evidence.record.entries
    scylla_ids = tuple(
        sorted(
            host.logical_id
            for host in deploy.inventory.record.inventory.hosts
            if host.role is HostRole.SCYLLA
        )
    )
    manager_ids = tuple(
        sorted(
            host.logical_id
            for host in deploy.inventory.record.inventory.hosts
            if host.role is HostRole.MANAGER
        )
    )
    _validate_service_prerequisites(
        stable_id=stable_id,
        scylla_ids=scylla_ids,
        manager_ids=manager_ids,
        manager_server=manager_server,
        stack_entries=stack_entries,
        manager_agents=manager_agents,
        monitoring_agents=monitoring_agents,
    )

    readiness = _reconstructed_readiness(planning.base)
    current_base = BaseOsEvidence(
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
    stack_entry = stack_entries[0]
    stack_payload = build_monitoring_stack_payload(
        metadata,
        deploy.observation,
        deploy.inventory,
        readiness,
        current_base,
        logical_id=stable_id,
        image_filter=image_filter,
        architecture=base_host.image_architecture,
        stack_version=STACK_VERSION,
        cluster_spec_digest=metadata.desired_spec.digest(),
    )
    stack = _reconstruct_stack_evidence(stack_entry, stack_payload)
    # The target payload contract binds the complete observed artifact while
    # the generic readiness projection and stack payload retain its manifest.
    target_readiness = replace(
        readiness,
        observation_digest=deploy.observation.digest,
    )
    payload = build_monitoring_targets_payload(
        metadata,
        deploy.observation,
        deploy.inventory,
        target_readiness,
        current_base,
        stack,
        logical_id=stable_id,
        image_filter=image_filter,
        architecture=base_host.image_architecture,
        cluster_spec_digest=metadata.desired_spec.digest(),
    )
    intent = _validate_target_payload(
        payload,
        stable_id=stable_id,
        scylla_ids=scylla_ids,
        manager_ids=manager_ids,
    )
    variables = definition.validate_variables(
        {"deploy_scylla_vms_monitoring_targets": payload}
    )
    variables_digest = digest_bytes(serialize_json(variables))
    command_digest = ansible_command_intent_digest(
        definition,
        step_sequence=step.sequence,
        limit=step.target_ids,
        variables_digest=variables_digest,
        tags=(),
        check=False,
        diff=False,
        verbosity=0,
    )
    manager_server_entry = manager_server[0]
    values: dict[str, object] = {
        "step_sequence": step.sequence,
        "mapping_sequence": _MAPPING_SEQUENCE,
        "playbook": _PLAYBOOK,
        "classification": OperationClassification.MUTATING,
        "target_role": _TARGET_ROLE,
        "target_stable_id": stable_id,
        "target_digest": step.target_digest,
        "architecture": DeployMonitoringTargetsArchitecture(
            base_host.image_architecture
        ),
        "image_policy_digest": _digest_object(image_filter.to_object()),
        **intent,
        "listen_policy": DeployMonitoringTargetsListenPolicy.NOT_STARTED,
        "scrape_readiness": DeployMonitoringTargetsScrapeReadiness.NOT_PERFORMED,
        "scrape_performed": False,
        "exporters_started": False,
        "stack_started": False,
        "containers_started": False,
        "auth_configured": False,
        "public_bind": False,
        "manager_registration_performed": False,
        "scylla_started": False,
        "secrets_written": False,
        "compose_generated": False,
        "variables_digest": variables_digest,
        "source_digest": source_digest,
        "command_digest": command_digest,
        "gate_evidence_digest": step.evidence_digest,
        "base_os_evidence_digest": base_entry.evidence_digest,
        "monitoring_stack_evidence_digest": stack_entry.evidence_digest,
        "manager_server_evidence_digest": manager_server_entry.evidence_digest,
        "manager_agent_evidence_set_digest": _digest_object(
            [entry.evidence_digest for entry in manager_agents]
        ),
        "monitoring_agent_evidence_set_digest": _digest_object(
            [entry.evidence_digest for entry in monitoring_agents]
        ),
        "reconciled_step_digest": step.step_digest,
        "prior_reconciled_step_digest": step.prior_step_digest,
        "original_step_digest": step.original_step_digest,
        "target_intent_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCOPE_SCHEMA_VERSION
        ),
    }
    values["target_intent_digest"] = _scope_intent_digest_from_values(values)
    return DeployMonitoringTargetsAuthorizationScope(**values)  # type: ignore[arg-type]


def _validate_service_prerequisites(
    *,
    stable_id: str,
    scylla_ids: tuple[str, ...],
    manager_ids: tuple[str, ...],
    manager_server: tuple[DeployManagerServerEvidenceEntry, ...],
    stack_entries: tuple[DeployMonitoringStackEvidenceEntry, ...],
    manager_agents: tuple[DeployManagerAgentEvidenceEntry, ...],
    monitoring_agents: tuple[DeployMonitoringAgentEvidenceEntry, ...],
) -> None:
    if not scylla_ids:
        raise StateConflictError(
            "deploy monitoring-targets requires the complete current Scylla set"
        )
    if (
        len(manager_ids) != 1
        or len(manager_server) != 1
        or manager_server[0].stable_id != manager_ids[0]
    ):
        raise StateConflictError(
            "deploy monitoring-targets Manager-server identity or evidence is ambiguous"
        )
    server = manager_server[0]
    if (
        server.status
        not in {ManagerServerStatus.INSTALLED, ManagerServerStatus.NO_CHANGE}
        or not server.installed
        or not server.service_masked
        or not server.service_inactive
        or server.service_started
        or server.backend_configured
        or server.configuration_performed
        or server.registration_performed
        or server.setup_performed
        or server.tasks_performed
        or server.manual_recovery_required
        or server.automatic_retry_allowed
    ):
        raise StateConflictError(
            "deploy monitoring-targets Manager-server service gate conflicts"
        )
    if len(stack_entries) != 1 or stack_entries[0].stable_id != stable_id:
        raise StateConflictError(
            "deploy monitoring-targets monitoring-stack evidence is ambiguous"
        )
    stack = stack_entries[0]
    if (
        stack.status
        not in {MonitoringStackStatus.INSTALLED, MonitoringStackStatus.NO_CHANGE}
        or not stack.installed
        or stack.stack_version_digest != _digest_object(STACK_VERSION)
        or stack.archive_artifact_digest != ARTIFACT_DIGEST
        or not stack.service_disabled
        or not stack.service_inactive
        or stack.listen_policy != MONITORING_STACK_LISTEN_POLICY
        or any(
            (
                stack.docker_install_performed,
                stack.image_pull_performed,
                stack.compose_generated,
                stack.auth_configured,
                stack.targets_generated,
                stack.containers_started,
                stack.service_started,
                stack.public_bind,
                stack.manager_registration_performed,
                stack.scylla_started,
                stack.secrets_written,
                stack.manual_recovery_required,
                stack.automatic_retry_allowed,
            )
        )
    ):
        raise StateConflictError(
            "deploy monitoring-targets stack version, service, or listen gate conflicts"
        )
    if (
        tuple(entry.stable_id for entry in manager_agents) != scylla_ids
        or tuple(entry.stable_id for entry in monitoring_agents) != scylla_ids
    ):
        raise StateConflictError(
            "deploy monitoring-targets agent evidence does not cover the complete "
            "Scylla set"
        )
    if any(
        entry.status not in {ManagerAgentStatus.INSTALLED, ManagerAgentStatus.NO_CHANGE}
        or not entry.installed
        or not entry.service_disabled
        or not entry.service_inactive
        or entry.configuration_performed
        or entry.auth_token_configured
        or entry.helper_slice_configured
        or entry.server_reachability != "not-performed"
        or entry.service_started
        or entry.manual_recovery_required
        or entry.automatic_retry_allowed
        for entry in manager_agents
    ):
        raise StateConflictError(
            "deploy monitoring-targets Manager-agent service gate conflicts"
        )
    if any(
        entry.status
        not in {MonitoringAgentStatus.INSTALLED, MonitoringAgentStatus.NO_CHANGE}
        or not entry.installed
        or not entry.service_disabled
        or not entry.service_inactive
        or entry.listen_policy != MONITORING_AGENT_LISTEN_POLICY
        or entry.configuration_performed
        or entry.process_exporter_installed
        or entry.stack_installed
        or entry.targets_generated
        or entry.manager_registration_performed
        or entry.service_started
        or entry.scylla_started
        or entry.secrets_written
        or entry.manual_recovery_required
        or entry.automatic_retry_allowed
        for entry in monitoring_agents
    ):
        raise StateConflictError(
            "deploy monitoring-targets Monitoring-agent service or listen gate conflicts"
        )


def _reconstruct_stack_evidence(
    entry: DeployMonitoringStackEvidenceEntry,
    payload: Mapping[str, object],
) -> MonitoringStackEvidence:
    artifacts = _string_mapping(payload.get("artifacts"), "stack artifacts")
    provenance = _string_mapping(payload.get("provenance"), "stack provenance")
    documented = _integer_mapping(
        payload.get("documented_ports"), "stack documented ports"
    )
    if (
        artifacts != dict(STACK_ARTIFACTS)
        or documented != dict(DOCUMENTED_PORTS)
        or payload.get("logical_id") != entry.stable_id
        or payload.get("stack_version") != STACK_VERSION
        or payload.get("source_commit") != SOURCE_COMMIT
        or payload.get("listen_policy") != MONITORING_STACK_LISTEN_POLICY
        or entry.component_set_digest != _digest_object(dict(sorted(artifacts.items())))
        or entry.documented_port_set_digest
        != _digest_object(dict(sorted(documented.items())))
        or entry.provenance_digest != _digest_object(dict(provenance))
    ):
        raise StateConflictError(
            "deploy monitoring-targets current monitoring-stack intent drifted"
        )
    return MonitoringStackEvidence(
        logical_id=entry.stable_id,
        status=entry.status,
        requested_release=STACK_RELEASE_LINE,
        requested_version=STACK_VERSION,
        installed_version=STACK_VERSION,
        artifacts=tuple(sorted(artifacts.items())),
        artifact_digest=entry.archive_artifact_digest,
        source_commit=SOURCE_COMMIT,
        service_enabled=False,
        service_inactive=True,
        containers_started=False,
        listen_policy=MONITORING_STACK_LISTEN_POLICY,
        documented_ports=tuple(sorted(documented.items())),
        targets_generated=False,
        auth_configured=False,
        public_bind=False,
        manager_registration_performed=False,
        scylla_started=False,
        secrets_written=False,
        compose_generated=False,
        provenance=tuple(sorted(provenance.items())),
        blockers=(),
    )


def _validate_target_payload(
    payload: Mapping[str, object],
    *,
    stable_id: str,
    scylla_ids: tuple[str, ...],
    manager_ids: tuple[str, ...],
) -> dict[str, object]:
    files = _array(payload.get("files"), "monitoring target files")
    file_digests = _string_mapping(
        payload.get("file_digests"), "monitoring target file digests"
    )
    target_counts = _integer_mapping(
        payload.get("target_counts"), "monitoring target counts"
    )
    identities_value = _mapping(payload.get("identities"), "monitoring identities")
    identities = {
        role: _string_tuple(items, f"{role} identities")
        for role, items in identities_value.items()
    }
    expected_identity_set = tuple(
        sorted(digest_bytes(stable_id.encode("utf-8")) for stable_id in scylla_ids)
    )
    expected_manager_identity_set = tuple(
        sorted(digest_bytes(stable_id.encode("utf-8")) for stable_id in manager_ids)
    )
    expected_counts = {
        "manager": 1,
        "manager_agent": len(scylla_ids),
        "node_exporter": len(scylla_ids),
        "scylla": len(scylla_ids),
    }
    expected_files: dict[str, tuple[str, str]] = {}
    for item in files:
        value = _mapping(item, "monitoring target file")
        require_exact_keys(
            value, {"content", "digest", "name", "path"}, "monitoring target file"
        )
        name = require_string(value, "name")
        path = require_string(value, "path")
        content = require_string(value, "content")
        digest = require_string(value, "digest")
        validate_digest(digest, "monitoring target content digest")
        if (
            name in expected_files
            or name not in TARGET_FILES
            or path != f"{TARGET_DIRECTORY}/{name}"
            or digest != digest_bytes(content.encode("utf-8"))
        ):
            raise StateConflictError(
                "deploy monitoring-targets official file intent conflicts"
            )
        expected_files[name] = (path, digest)
    expected_file_digests = {path: digest for path, digest in expected_files.values()}
    prohibited_fields = (
        "auth_configured",
        "compose_generated",
        "containers_started",
        "exporters_started",
        "manager_registration_performed",
        "public_bind",
        "scrape_performed",
        "scylla_started",
        "secrets_written",
        "stack_started",
    )
    if (
        len(expected_files) != len(TARGET_FILES)
        or set(expected_files) != set(TARGET_FILES)
        or file_digests != expected_file_digests
        or payload.get("logical_id") != stable_id
        or payload.get("schema_version") != MONITORING_TARGETS_SCHEMA_VERSION
        or payload.get("stack_version") != STACK_VERSION
        or payload.get("listen_policy") != MONITORING_STACK_LISTEN_POLICY
        or payload.get("scrape_readiness") != SCRAPE_READINESS
        or payload.get("documented_scrape_ports") != dict(SCRAPE_PORTS)
        or payload.get("target_directory") != TARGET_DIRECTORY
        or any(payload.get(name) is not False for name in prohibited_fields)
        or target_counts != expected_counts
        or set(identities) != {"manager", "manager_agent", "node_exporter", "scylla"}
        or len(expected_manager_identity_set) != 1
        or tuple(identities["manager"]) != expected_manager_identity_set
        or tuple(identities["manager_agent"]) != expected_identity_set
        or tuple(identities["node_exporter"]) != expected_identity_set
        or tuple(identities["scylla"]) != expected_identity_set
    ):
        raise StateConflictError(
            "deploy monitoring-targets official target intent or prohibition conflicts"
        )
    content_digests = tuple(sorted(digest for _path, digest in expected_files.values()))
    file_identity_digests = tuple(
        sorted(
            _digest_object({"name": name, "path": path})
            for name, (path, _digest) in expected_files.items()
        )
    )
    return {
        "file_count": len(expected_files),
        "file_set_digest": _digest_object(list(file_identity_digests)),
        "file_content_set_digest": _digest_object(list(content_digests)),
        "manager_target_count": target_counts["manager"],
        "scylla_target_count": target_counts["scylla"],
        "node_exporter_target_count": target_counts["node_exporter"],
        "manager_agent_target_count": target_counts["manager_agent"],
        "manager_identity_set_digest": _digest_object(list(identities["manager"])),
        "scylla_identity_set_digest": _digest_object(list(identities["scylla"])),
    }


def _normalize_proof(
    proof: DeployMonitoringTargetsAuthorizationProof,
    *,
    context: _AuthorizationContext,
    scope_digest: str,
) -> DeployMonitoringTargetsProofDecision:
    if proof.approval_method is None:
        raise StateConflictError(
            "ordinary deploy monitoring-targets approval is required"
        )
    if not proof.approved:
        raise StateConflictError(
            "ordinary deploy monitoring-targets approval was denied"
        )
    if (
        proof.allow_destructive
        or proof.destructive_scope_provided
        or proof.narrow_consent_provided
    ):
        raise StateConflictError(
            "destructive and narrow proofs are inapplicable to mutating "
            "monitoring-targets authorization"
        )
    post = context.post_agent
    values: dict[str, object] = {
        "allow_destructive": False,
        "approval_method": proof.approval_method.value,
        "approved": True,
        "destructive_scope_provided": False,
        "narrow_consent_provided": False,
        "proof_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_PROOF_SCHEMA_VERSION
        ),
    }
    values["proof_digest"] = _proof_digest_values(
        cluster_uuid=post.record.cluster_uuid,
        operation_id=post.record.operation_id,
        request_digest=post.record.request_digest,
        journal_digest=post.record.journal_digest,
        post_monitoring_agent_artifact_digest=post.artifact_digest,
        post_monitoring_agent_record_digest=post.record.record_digest,
        scope_digest=scope_digest,
        proof=values,
    )
    return DeployMonitoringTargetsProofDecision.from_object(values)


def _build_authorization(
    context: _AuthorizationContext,
    *,
    scope: DeployMonitoringTargetsAuthorizationScope,
    proof: DeployMonitoringTargetsProofDecision,
    created_at: str,
) -> DeployMonitoringTargetsAuthorization:
    agent = context.agent
    monitoring_agent_context = agent.authorization_context
    manager_agent_context = monitoring_agent_context.manager.authorization_context
    loaded = _loaded(
        manager_agent_context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    post = context.post_agent.record
    base_os = manager_agent_context.monitoring.monitoring.manager.manager.base_os
    stack_evidence = manager_agent_context.monitoring.evidence
    manager_server_evidence = (
        manager_agent_context.monitoring.monitoring.manager.evidence
    )
    manager_agent_evidence = monitoring_agent_context.manager.evidence
    monitoring_agent_evidence = agent.evidence
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_identity_digest": _cluster_identity_digest(
            metadata.cluster_uuid, metadata.cluster_name
        ),
        "operation_id": post.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "scope_kind": _SCOPE_KIND,
        "request_digest": post.request_digest,
        "journal_generation": post.journal_generation,
        "journal_digest": post.journal_digest,
        "journal_status": post.journal_status,
        "journal_phase": post.journal_phase,
        "metadata_generation": metadata.generation,
        "metadata_artifact_digest": deploy.metadata.digest,
        "desired_spec_digest": metadata.desired_spec.digest(),
        "observation_generation": deploy.observation.record.generation,
        "observation_artifact_digest": deploy.observation.digest,
        "observation_manifest_digest": deploy.observation.record.manifest_digest,
        "inventory_generation": deploy.inventory.record.generation,
        "inventory_artifact_digest": deploy.inventory.digest,
        "inventory_digest": deploy.inventory.record.inventory_digest,
        "trust_generation": planning.base.trust.record.generation,
        "trust_artifact_digest": planning.base.trust.digest,
        "trust_entries_digest": planning.base.trust.record.entries_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": planning.readiness.record.record_digest,
        "post_monitoring_agent_artifact_digest": context.post_agent.artifact_digest,
        "post_monitoring_agent_record_digest": post.record_digest,
        "post_monitoring_agent_effective_plan_digest": _digest_object(
            [step.to_object() for step in post.steps]
        ),
        "monitoring_stack_evidence_artifact_digest": stack_evidence.artifact_digest,
        "monitoring_stack_evidence_digest": scope.monitoring_stack_evidence_digest,
        "manager_server_evidence_artifact_digest": (
            manager_server_evidence.artifact_digest
        ),
        "manager_server_evidence_digest": scope.manager_server_evidence_digest,
        "manager_agent_evidence_artifact_digest": (
            manager_agent_evidence.artifact_digest
        ),
        "manager_agent_evidence_set_digest": (scope.manager_agent_evidence_set_digest),
        "monitoring_agent_evidence_artifact_digest": (
            monitoring_agent_evidence.artifact_digest
        ),
        "monitoring_agent_evidence_set_digest": (
            scope.monitoring_agent_evidence_set_digest
        ),
        "base_os_artifact_digest": base_os.artifact_digest,
        "base_os_evidence_digest": scope.base_os_evidence_digest,
        "catalog_digest": loaded.catalog_digest,
        "ansible_source_version": loaded.source.version,
        "ansible_source_digest": loaded.source.digest,
        "classification": OperationClassification.MUTATING,
        "scope": scope,
        "target_count": 1,
        "target_set_digest": scope.target_digest,
        "authorization_scope_digest": _digest_object(scope.to_object()),
        "proof": proof,
        "authorization_state": _AUTHORIZED,
        "consumed": False,
        "execution_state": _EXECUTION_UNAVAILABLE,
        "finalization_state": _FINALIZATION_NOT_STARTED,
        "public_workflow_state": _PUBLIC_WORKFLOW_UNAVAILABLE,
        "authorization_digest": "",
    }
    if (
        deploy.journal.record.generation != post.journal_generation
        or deploy.journal.digest != post.journal_digest
        or deploy.journal.record.status is not JournalStatus.IN_PROGRESS
        or deploy.journal.record.phase is not OperationPhase.VERIFY
        or loaded.catalog_digest != post.catalog_digest
        or loaded.source.digest != post.ansible_source_digest
        or post.inventory_artifact_digest != deploy.inventory.digest
        or post.trust_artifact_digest != planning.base.trust.digest
        or post.readiness_artifact_digest != planning.readiness.artifact_digest
        or stack_evidence.record.binding.inventory_artifact_digest
        != deploy.inventory.digest
        or manager_server_evidence.record.binding.inventory_artifact_digest
        != deploy.inventory.digest
        or manager_agent_evidence.record.binding.inventory_artifact_digest
        != deploy.inventory.digest
        or monitoring_agent_evidence.record.binding.inventory_artifact_digest
        != deploy.inventory.digest
        or base_os.record.binding.inventory_artifact_digest != deploy.inventory.digest
        or base_os.record.binding.trust_artifact_digest != planning.base.trust.digest
        or base_os.record.binding.readiness_artifact_digest
        != planning.readiness.artifact_digest
    ):
        raise StateConflictError(
            "deploy monitoring-targets inventory, trust, readiness, journal, "
            "evidence, or source binding drifted"
        )
    values["authorization_digest"] = _authorization_digest_from_values(values)
    return DeployMonitoringTargetsAuthorization(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployMonitoringTargetsAuthorization,
    *,
    state: DeployMonitoringTargetsAuthorizationArtifactState,
) -> DeployMonitoringTargetsAuthorizationReport:
    record = stored.record
    scope = record.scope
    prohibited = (
        scope.scrape_performed,
        scope.exporters_started,
        scope.stack_started,
        scope.containers_started,
        scope.auth_configured,
        scope.public_bind,
        scope.manager_registration_performed,
        scope.scylla_started,
        scope.secrets_written,
        scope.compose_generated,
    )
    return DeployMonitoringTargetsAuthorizationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        authorization_artifact_digest=stored.artifact_digest,
        authorization_digest=record.authorization_digest,
        authorization_state=record.authorization_state,
        stage=record.stage,
        scope_kind=record.scope_kind,
        approval_method=record.proof.approval_method,
        approval_state="approved",
        proof_digest=record.proof.proof_digest,
        classification=record.classification,
        playbook=scope.playbook,
        target_stable_id=scope.target_stable_id,
        target_count=record.target_count,
        target_set_digest=record.target_set_digest,
        authorization_scope_digest=record.authorization_scope_digest,
        architecture=scope.architecture,
        file_count=scope.file_count,
        file_set_digest=scope.file_set_digest,
        file_content_set_digest=scope.file_content_set_digest,
        manager_target_count=scope.manager_target_count,
        scylla_target_count=scope.scylla_target_count,
        node_exporter_target_count=scope.node_exporter_target_count,
        manager_agent_target_count=scope.manager_agent_target_count,
        manager_identity_set_digest=scope.manager_identity_set_digest,
        scylla_identity_set_digest=scope.scylla_identity_set_digest,
        listen_policy=scope.listen_policy,
        scrape_readiness=scope.scrape_readiness,
        prohibited_action_count=sum(prohibited),
        post_monitoring_agent_artifact_digest=(
            record.post_monitoring_agent_artifact_digest
        ),
        post_monitoring_agent_record_digest=(
            record.post_monitoring_agent_record_digest
        ),
        monitoring_stack_evidence_digest=record.monitoring_stack_evidence_digest,
        manager_server_evidence_digest=record.manager_server_evidence_digest,
        manager_agent_evidence_set_digest=record.manager_agent_evidence_set_digest,
        monitoring_agent_evidence_set_digest=(
            record.monitoring_agent_evidence_set_digest
        ),
        base_os_artifact_digest=record.base_os_artifact_digest,
        base_os_evidence_digest=record.base_os_evidence_digest,
        inventory_artifact_digest=record.inventory_artifact_digest,
        trust_artifact_digest=record.trust_artifact_digest,
        readiness_artifact_digest=record.readiness_artifact_digest,
        catalog_digest=record.catalog_digest,
        ansible_source_digest=record.ansible_source_digest,
        blockers_digest=_digest_object(
            {
                "authorization_required": False,
                "execution_available": False,
                "public_workflow_available": False,
            }
        ),
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        journal_digest=record.journal_digest,
        consumed=record.consumed,
        execution_state=record.execution_state,
        finalization_state=record.finalization_state,
        public_workflow_state=record.public_workflow_state,
    )


def _scope_intent_digest(
    scope: DeployMonitoringTargetsAuthorizationScope,
) -> str:
    return _scope_intent_digest_from_values(scope.to_object())


def _scope_intent_digest_from_values(values: Mapping[str, object]) -> str:
    value = dict(values)
    value["target_intent_digest"] = ""
    return _digest_object(value)


def _proof_digest(
    record: DeployMonitoringTargetsAuthorization,
    proof: Mapping[str, object],
) -> str:
    return _proof_digest_values(
        cluster_uuid=record.cluster_uuid,
        operation_id=record.operation_id,
        request_digest=record.request_digest,
        journal_digest=record.journal_digest,
        post_monitoring_agent_artifact_digest=(
            record.post_monitoring_agent_artifact_digest
        ),
        post_monitoring_agent_record_digest=(
            record.post_monitoring_agent_record_digest
        ),
        scope_digest=record.authorization_scope_digest,
        proof=proof,
    )


def _proof_digest_values(
    *,
    cluster_uuid: uuid.UUID,
    operation_id: uuid.UUID,
    request_digest: str,
    journal_digest: str,
    post_monitoring_agent_artifact_digest: str,
    post_monitoring_agent_record_digest: str,
    scope_digest: str,
    proof: Mapping[str, object],
) -> str:
    proof_value = dict(proof)
    proof_value["proof_digest"] = ""
    return _digest_object(
        {
            "authorization_scope_digest": scope_digest,
            "cluster_uuid": str(cluster_uuid),
            "journal_digest": journal_digest,
            "operation": _OPERATION,
            "operation_id": str(operation_id),
            "post_monitoring_agent_artifact_digest": (
                post_monitoring_agent_artifact_digest
            ),
            "post_monitoring_agent_record_digest": (
                post_monitoring_agent_record_digest
            ),
            "proof": proof_value,
            "request_digest": request_digest,
            "schema_version": (
                ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_PROOF_SCHEMA_VERSION
            ),
            "stage": _STAGE,
        }
    )


def _authorization_digest(record: DeployMonitoringTargetsAuthorization) -> str:
    return _authorization_digest_from_values(record.to_object())


def _authorization_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployMonitoringTargetsAuthorization.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(
                item, (JournalStatus, OperationPhase, OperationClassification)
            )
            else item.to_object()
            if name in {"scope", "proof"} and hasattr(item, "to_object")
            else item
        )
    value["authorization_digest"] = ""
    return _digest_object(value)


def _cluster_identity_digest(cluster_uuid: uuid.UUID, cluster_name: str) -> str:
    validate_cluster_name(cluster_name)
    return _digest_object(
        {"cluster_name": cluster_name, "cluster_uuid": str(cluster_uuid)}
    )


def _refuse_incompatible_or_later_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    generic = (
        paths.operations / f"{operation_id}{OPERATION_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    validate_state_file(generic, allow_missing=True)
    if generic.exists():
        raise StateConflictError(
            "generic Ansible authorization is incompatible with deploy VERIFY binding"
        )
    forbidden_fragments = (
        ".ansible-deploy-monitoring-targets-execution.json",
        ".ansible-deploy-monitoring-targets-evidence.json",
        ".ansible-deploy-post-monitoring-targets-reconciliation.json",
        ".ansible-deploy-manager-tasks",
        ".ansible-deploy-post-manager-tasks",
        ".ansible-deploy-final-evidence",
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy monitoring-targets operation history"
        ) from error
    prefix = str(operation_id)
    for entry in entries:
        if entry.name.startswith(prefix) and any(
            fragment in entry.name for fragment in forbidden_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy monitoring-targets authorization refuses execution "
                "or later-stage history"
            )


def _refuse_ambiguous_authorization_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy monitoring-targets authorization history"
        ) from error
    canonical = str(operation_id)
    suffix = DEPLOY_MONITORING_TARGETS_AUTHORIZATION_FILENAME_SUFFIX
    for entry in entries:
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
                "deploy monitoring-targets authorization artifacts are ambiguous"
            )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy monitoring-targets authorization paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy monitoring-targets authorization requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _digest_fields(value: object) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(value, name))
        for name in value.__dataclass_fields__  # type: ignore[attr-defined]
        if name.endswith("_digest") and isinstance(getattr(value, name), str)
    )


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


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise StatePersistenceError(f"{label} must be an array")
    return value


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise StatePersistenceError(f"{label} must be an array of strings")
    return tuple(value)


def _string_mapping(value: object, label: str) -> dict[str, str]:
    mapping = _mapping(value, label)
    if not all(isinstance(item, str) for item in mapping.values()):
        raise StatePersistenceError(f"{label} must contain strings")
    return {key: cast(str, item) for key, item in mapping.items()}


def _integer_mapping(value: object, label: str) -> dict[str, int]:
    mapping = _mapping(value, label)
    if not all(
        isinstance(item, int) and not isinstance(item, bool)
        for item in mapping.values()
    ):
        raise StatePersistenceError(f"{label} must contain integers")
    return {key: cast(int, item) for key, item in mapping.items()}


__all__ = [
    "ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_PROOF_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MONITORING_TARGETS_AUTHORIZATION_SCOPE_SCHEMA_VERSION",
    "DEPLOY_MONITORING_TARGETS_AUTHORIZATION_FILENAME_SUFFIX",
    "DeployMonitoringTargetsApprovalMethod",
    "DeployMonitoringTargetsArchitecture",
    "DeployMonitoringTargetsAuthorization",
    "DeployMonitoringTargetsAuthorizationArtifactState",
    "DeployMonitoringTargetsAuthorizationProof",
    "DeployMonitoringTargetsAuthorizationReport",
    "DeployMonitoringTargetsAuthorizationScope",
    "DeployMonitoringTargetsAuthorizationStore",
    "DeployMonitoringTargetsListenPolicy",
    "DeployMonitoringTargetsProofDecision",
    "DeployMonitoringTargetsScrapeReadiness",
    "StoredDeployMonitoringTargetsAuthorization",
    "authorize_deploy_monitoring_targets",
    "deploy_monitoring_targets_authorization_id_from_filename",
    "deploy_monitoring_targets_authorization_path",
]
