"""Immutable authorization for the mapped deploy ``monitoring-stack`` step.

This internal owner reloads the exact post-Manager reconciliation, derives one
digest-pinned Scylla Monitoring 4.16.0 archive-install intent, and persists only
an unconsumed ordinary approval checkpoint.  It does not execute Ansible,
change a host, or advance the common operation journal.
"""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
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
from scylla_vms.ansible.deploy_manager_server_reconciliation import (
    ANSIBLE_DEPLOY_POST_MANAGER_SERVER_RECONCILIATION_SCHEMA_VERSION,
    DeployPostManagerServerReconciliationStore,
    StoredDeployPostManagerServerReconciliation,
)
from scylla_vms.ansible.deploy_manager_server_reconciliation import (
    _build_record as _build_post_manager_record,
)
from scylla_vms.ansible.deploy_manager_server_reconciliation import (
    _build_steps as _build_post_manager_steps,
)
from scylla_vms.ansible.deploy_manager_server_reconciliation import (
    _load_context as _load_manager_context,
)
from scylla_vms.ansible.deploy_manager_server_reconciliation import (
    _ReconciliationContext as _ManagerReconciliationContext,
)
from scylla_vms.ansible.deploy_plan import (
    DeployConditionState,
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import _loaded
from scylla_vms.ansible.monitoring_stack import (
    ARTIFACT_DIGEST,
    ARTIFACT_URI,
    CACHE_PATH,
    DOCUMENTED_PORTS,
    INSTALL_ROOT,
    LISTEN_POLICY,
    SOURCE_COMMIT,
    STACK_ARTIFACTS,
    STACK_CHANNEL,
    STACK_RELEASE_LINE,
    STACK_SERVICE_UNIT,
    STACK_VERSION,
    build_monitoring_stack_payload,
)
from scylla_vms.ansible.operation_authorization import (
    OPERATION_AUTHORIZATION_FILENAME_SUFFIX,
)
from scylla_vms.ansible.readiness import EvidenceStatus
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

ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-monitoring-stack-authorization-proof/v1"
)
ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_SCOPE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-monitoring-stack-authorization-scope/v1"
)
ANSIBLE_DEPLOY_MONITORING_STACK_ARCHIVE_PROVENANCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-monitoring-stack-archive-provenance/v1"
)
ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-monitoring-stack-authorization/v1"
)
ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-monitoring-stack-authorization-report/v1"
)
DEPLOY_MONITORING_STACK_AUTHORIZATION_FILENAME_SUFFIX = (
    ".ansible-deploy-monitoring-stack-authorization.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "monitoring-stack"
_MAPPING_SEQUENCE = 15
_TARGET_ROLE = HostRole.MONITORING.value
_STAGE = "post-manager-server-monitoring-stack"
_SCOPE_KIND = "manager-installed-monitoring-archive-install"
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


class DeployMonitoringStackApprovalMethod(StrEnum):
    """PLAN-permitted ordinary approval methods."""

    INTERACTIVE = "interactive"
    CLI_YES = "cli-yes"


class DeployMonitoringStackArchitecture(StrEnum):
    """Closed OCI image architecture policy."""

    AMD64 = "amd64"
    AARCH64 = "aarch64"


class DeployMonitoringStackInstallPolicy(StrEnum):
    """The only mutation authorized by this slice."""

    ARCHIVE_ONLY = "archive-only"


class DeployMonitoringStackServicePolicy(StrEnum):
    """The required Docker service state after archive placement."""

    DISABLED_INACTIVE = "disabled-inactive"


class DeployMonitoringStackListenPolicy(StrEnum):
    """The only accepted listen policy before later reviewed startup."""

    NOT_STARTED = "not-started"


class DeployMonitoringStackAuthorizationArtifactState(StrEnum):
    """Immutable authorization persistence result."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployMonitoringStackAuthorizationProof:
    """Already-normalized ordinary approval without caller-owned scope."""

    approval_method: DeployMonitoringStackApprovalMethod | None = None
    approved: bool = False
    allow_destructive: bool = False
    destructive_scope_provided: bool = False
    narrow_consent_provided: bool = False

    def __post_init__(self) -> None:
        if self.approval_method is not None and not isinstance(
            self.approval_method, DeployMonitoringStackApprovalMethod
        ):
            raise StateConflictError(
                "deploy monitoring-stack approval method is invalid"
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
                "deploy monitoring-stack authorization proof is malformed"
            )


@dataclass(frozen=True, slots=True)
class DeployMonitoringStackProofDecision:
    """Persisted ordinary proof bound to exact derived scope."""

    approval_method: DeployMonitoringStackApprovalMethod
    approved: bool
    allow_destructive: bool
    destructive_scope_provided: bool
    narrow_consent_provided: bool
    proof_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or not isinstance(self.approval_method, DeployMonitoringStackApprovalMethod)
            or self.approved is not True
            or self.allow_destructive is not False
            or self.destructive_scope_provided is not False
            or self.narrow_consent_provided is not False
        ):
            raise StatePersistenceError(
                "deploy monitoring-stack authorization proof state is invalid"
            )
        validate_digest(
            self.proof_digest, "deploy monitoring-stack authorization proof digest"
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
    ) -> DeployMonitoringStackProofDecision:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy monitoring-stack authorization proof",
        )
        try:
            method = DeployMonitoringStackApprovalMethod(
                require_string(value, "approval_method")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy monitoring-stack authorization proof method is invalid"
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
class DeployMonitoringStackArchiveProvenance:
    """URL- and path-free identity of the exact official stack archive."""

    release_line: str
    channel: str
    stack_version_digest: str
    archive_artifact_digest: str
    archive_source_commit_digest: str
    component_count: int
    component_set_digest: str
    documented_port_count: int
    documented_port_set_digest: str
    catalog_entry_digest: str
    provenance_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_STACK_ARCHIVE_PROVENANCE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MONITORING_STACK_ARCHIVE_PROVENANCE_SCHEMA_VERSION
            or self.release_line != STACK_RELEASE_LINE
            or self.channel != STACK_CHANNEL
            or self.stack_version_digest != _digest_object(STACK_VERSION)
            or self.archive_artifact_digest != ARTIFACT_DIGEST
            or self.archive_source_commit_digest != _digest_object(SOURCE_COMMIT)
            or self.component_count != len(STACK_ARTIFACTS)
            or self.component_set_digest
            != _digest_object(dict(sorted(STACK_ARTIFACTS.items())))
            or self.documented_port_count != len(DOCUMENTED_PORTS)
            or self.documented_port_set_digest
            != _digest_object(dict(sorted(DOCUMENTED_PORTS.items())))
            or self.provenance_digest != _archive_provenance_digest(self)
        ):
            raise StatePersistenceError(
                "deploy monitoring-stack archive provenance conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy monitoring-stack archive provenance digest")

    def to_object(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployMonitoringStackArchiveProvenance:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy monitoring-stack archive provenance",
        )
        return cls(
            release_line=require_string(value, "release_line"),
            channel=require_string(value, "channel"),
            stack_version_digest=require_string(value, "stack_version_digest"),
            archive_artifact_digest=require_string(value, "archive_artifact_digest"),
            archive_source_commit_digest=require_string(
                value, "archive_source_commit_digest"
            ),
            component_count=_integer(value["component_count"], "component count"),
            component_set_digest=require_string(value, "component_set_digest"),
            documented_port_count=_integer(
                value["documented_port_count"], "documented port count"
            ),
            documented_port_set_digest=require_string(
                value, "documented_port_set_digest"
            ),
            catalog_entry_digest=require_string(value, "catalog_entry_digest"),
            provenance_digest=require_string(value, "provenance_digest"),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployMonitoringStackAuthorizationScope:
    """One exact redacted monitoring archive intent derived from canonical state."""

    mapping_sequence: int
    playbook: str
    classification: OperationClassification
    target_role: str
    target_stable_id: str
    target_digest: str
    architecture: DeployMonitoringStackArchitecture
    image_policy_digest: str
    install_policy: DeployMonitoringStackInstallPolicy
    service_policy: DeployMonitoringStackServicePolicy
    listen_policy: DeployMonitoringStackListenPolicy
    docker_install_permitted: bool
    image_pull_permitted: bool
    compose_permitted: bool
    auth_permitted: bool
    targets_permitted: bool
    containers_permitted: bool
    service_start_permitted: bool
    public_bind_permitted: bool
    manager_registration_permitted: bool
    scylla_start_permitted: bool
    secrets_permitted: bool
    variables_digest: str
    source_digest: str
    command_digest: str
    gate_evidence_digest: str
    base_os_evidence_digest: str
    reconciled_step_digest: str
    prior_reconciled_step_digest: str
    original_step_digest: str
    archive_provenance_digest: str
    install_intent_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_SCOPE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        definition = get_playbook(self.playbook)
        prohibited = (
            self.docker_install_permitted,
            self.image_pull_permitted,
            self.compose_permitted,
            self.auth_permitted,
            self.targets_permitted,
            self.containers_permitted,
            self.service_start_permitted,
            self.public_bind_permitted,
            self.manager_registration_permitted,
            self.scylla_start_permitted,
            self.secrets_permitted,
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_SCOPE_SCHEMA_VERSION
            or self.mapping_sequence != _MAPPING_SEQUENCE
            or self.playbook != _PLAYBOOK
            or self.classification is not OperationClassification.MUTATING
            or definition.classification is not self.classification
            or self.target_role != _TARGET_ROLE
            or not self.target_stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
            or self.target_digest != _digest_object([self.target_stable_id])
            or not isinstance(self.architecture, DeployMonitoringStackArchitecture)
            or self.install_policy
            is not DeployMonitoringStackInstallPolicy.ARCHIVE_ONLY
            or self.service_policy
            is not DeployMonitoringStackServicePolicy.DISABLED_INACTIVE
            or self.listen_policy is not DeployMonitoringStackListenPolicy.NOT_STARTED
            or any(prohibited)
            or self.install_intent_digest != _scope_intent_digest(self)
        ):
            raise StatePersistenceError(
                "deploy monitoring-stack authorization scope policy is invalid"
            )
        for digest in _digest_fields(self):
            validate_digest(
                digest, "deploy monitoring-stack authorization scope digest"
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
    ) -> DeployMonitoringStackAuthorizationScope:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy monitoring-stack authorization scope",
        )
        boolean_fields = {
            "docker_install_permitted",
            "image_pull_permitted",
            "compose_permitted",
            "auth_permitted",
            "targets_permitted",
            "containers_permitted",
            "service_start_permitted",
            "public_bind_permitted",
            "manager_registration_permitted",
            "scylla_start_permitted",
            "secrets_permitted",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name == "mapping_sequence":
                    parsed[name] = _integer(item, name)
                elif name == "classification":
                    parsed[name] = OperationClassification(require_string(value, name))
                elif name == "architecture":
                    parsed[name] = DeployMonitoringStackArchitecture(
                        require_string(value, name)
                    )
                elif name == "install_policy":
                    parsed[name] = DeployMonitoringStackInstallPolicy(
                        require_string(value, name)
                    )
                elif name == "service_policy":
                    parsed[name] = DeployMonitoringStackServicePolicy(
                        require_string(value, name)
                    )
                elif name == "listen_policy":
                    parsed[name] = DeployMonitoringStackListenPolicy(
                        require_string(value, name)
                    )
                elif name in boolean_fields:
                    parsed[name] = _boolean(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy monitoring-stack authorization scope enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployMonitoringStackAuthorization:
    """Immutable unconsumed authorization for one exact archive installation."""

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
    post_bootstrap_artifact_digest: str
    post_bootstrap_record_digest: str
    manager_authorization_artifact_digest: str
    manager_authorization_digest: str
    manager_execution_artifact_digest: str
    manager_execution_binding_digest: str
    manager_evidence_artifact_digest: str
    manager_evidence_digest: str
    post_manager_artifact_digest: str
    post_manager_record_digest: str
    post_manager_effective_plan_digest: str
    base_os_artifact_digest: str
    base_os_evidence_digest: str
    catalog_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    classification: OperationClassification
    scope: DeployMonitoringStackAuthorizationScope
    target_count: int
    target_set_digest: str
    authorization_scope_digest: str
    archive_provenance: DeployMonitoringStackArchiveProvenance
    proof: DeployMonitoringStackProofDecision
    authorization_state: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_digest: str
    post_manager_schema_version: str = (
        ANSIBLE_DEPLOY_POST_MANAGER_SERVER_RECONCILIATION_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_SCHEMA_VERSION
            or self.post_manager_schema_version
            != ANSIBLE_DEPLOY_POST_MANAGER_SERVER_RECONCILIATION_SCHEMA_VERSION
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
            or self.scope.archive_provenance_digest
            != self.archive_provenance.provenance_digest
            or self.authorization_state != _AUTHORIZED
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError(
                "deploy monitoring-stack authorization identity or state is invalid"
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
                count, "deploy monitoring-stack authorization generation or count"
            )
        for digest in _digest_fields(self):
            validate_digest(
                digest, "deploy monitoring-stack authorization binding digest"
            )
        if self.proof.proof_digest != _proof_digest(self, self.proof.to_object()):
            raise StatePersistenceError(
                "deploy monitoring-stack authorization proof digest conflicts"
            )
        if self.authorization_digest != _authorization_digest(self):
            raise StatePersistenceError(
                "deploy monitoring-stack authorization digest conflicts"
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
                if name in {"scope", "archive_provenance", "proof"}
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployMonitoringStackAuthorization:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy monitoring-stack authorization",
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
                    parsed[name] = DeployMonitoringStackAuthorizationScope.from_object(
                        _mapping(item, "deploy monitoring-stack scope")
                    )
                elif name == "archive_provenance":
                    parsed[name] = DeployMonitoringStackArchiveProvenance.from_object(
                        _mapping(item, "deploy monitoring-stack archive provenance")
                    )
                elif name == "proof":
                    parsed[name] = DeployMonitoringStackProofDecision.from_object(
                        _mapping(item, "deploy monitoring-stack proof")
                    )
                elif name == "consumed":
                    parsed[name] = _boolean(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy monitoring-stack authorization enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployMonitoringStackAuthorization:
    record: DeployMonitoringStackAuthorization
    artifact_digest: str


class DeployMonitoringStackAuthorizationStore:
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
        self._path = deploy_monitoring_stack_authorization_path(paths, operation_id)
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
    ) -> StoredDeployMonitoringStackAuthorization:
        value, artifact_digest = self._file.read()
        record = DeployMonitoringStackAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_identity_digest
            != _cluster_identity_digest(expected_cluster_uuid, expected_cluster_name)
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "deploy monitoring-stack authorization identity conflicts"
            )
        return StoredDeployMonitoringStackAuthorization(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployMonitoringStackAuthorization:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployMonitoringStackAuthorization,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployMonitoringStackAuthorization,
        DeployMonitoringStackAuthorizationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy monitoring-stack authorization operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=self._paths.cluster_root.name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy monitoring-stack authorization is immutable; "
                    "use a new operation"
                )
            return current, DeployMonitoringStackAuthorizationArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployMonitoringStackAuthorization(record, artifact_digest),
            DeployMonitoringStackAuthorizationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployMonitoringStackAuthorizationReport:
    """Strict redacted authorization report without executable inputs."""

    operation_id: uuid.UUID
    artifact_state: DeployMonitoringStackAuthorizationArtifactState
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_state: str
    stage: str
    scope_kind: str
    approval_method: DeployMonitoringStackApprovalMethod
    approval_state: str
    proof_digest: str
    classification: OperationClassification
    playbook: str
    target_stable_id: str
    target_count: int
    target_set_digest: str
    authorization_scope_digest: str
    architecture: DeployMonitoringStackArchitecture
    release_line: str
    stack_version_digest: str
    archive_artifact_digest: str
    archive_source_commit_digest: str
    component_count: int
    component_set_digest: str
    archive_provenance_digest: str
    install_policy: DeployMonitoringStackInstallPolicy
    service_policy: DeployMonitoringStackServicePolicy
    listen_policy: DeployMonitoringStackListenPolicy
    prohibited_action_count: int
    post_manager_artifact_digest: str
    post_manager_record_digest: str
    manager_evidence_digest: str
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
        ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_SCHEMA_VERSION
    )
    proof_schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    post_manager_schema_version: str = (
        ANSIBLE_DEPLOY_POST_MANAGER_SERVER_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or self.post_manager_schema_version
            != ANSIBLE_DEPLOY_POST_MANAGER_SERVER_RECONCILIATION_SCHEMA_VERSION
            or self.authorization_state != _AUTHORIZED
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.approval_state != "approved"
            or self.classification is not OperationClassification.MUTATING
            or self.playbook != _PLAYBOOK
            or self.target_count != 1
            or self.release_line != STACK_RELEASE_LINE
            or self.component_count != len(STACK_ARTIFACTS)
            or self.install_policy
            is not DeployMonitoringStackInstallPolicy.ARCHIVE_ONLY
            or self.service_policy
            is not DeployMonitoringStackServicePolicy.DISABLED_INACTIVE
            or self.listen_policy is not DeployMonitoringStackListenPolicy.NOT_STARTED
            or self.prohibited_action_count
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError(
                "deploy monitoring-stack authorization report is invalid"
            )
        if (
            not self.target_stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
        ):
            raise StatePersistenceError(
                "deploy monitoring-stack authorization report target is invalid"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy monitoring-stack report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "approval": {
                "digest": self.proof_digest,
                "method": self.approval_method.value,
                "state": self.approval_state,
            },
            "archive_policy": {
                "archive_artifact_digest": self.archive_artifact_digest,
                "archive_source_commit_digest": self.archive_source_commit_digest,
                "component_count": self.component_count,
                "component_set_digest": self.component_set_digest,
                "provenance_digest": self.archive_provenance_digest,
                "release_line": self.release_line,
                "stack_version_digest": self.stack_version_digest,
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
                "install": self.install_policy.value,
                "listen": self.listen_policy.value,
                "prohibited_action_count": self.prohibited_action_count,
                "service": self.service_policy.value,
            },
            "provenance": {
                "ansible_source_digest": self.ansible_source_digest,
                "base_os": {
                    "artifact_digest": self.base_os_artifact_digest,
                    "evidence_digest": self.base_os_evidence_digest,
                },
                "catalog_digest": self.catalog_digest,
                "inventory_artifact_digest": self.inventory_artifact_digest,
                "manager_evidence_digest": self.manager_evidence_digest,
                "post_manager": {
                    "artifact_digest": self.post_manager_artifact_digest,
                    "record_digest": self.post_manager_record_digest,
                    "schema_version": self.post_manager_schema_version,
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
    manager: _ManagerReconciliationContext
    post_manager: StoredDeployPostManagerServerReconciliation


def authorize_deploy_monitoring_stack(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proof: DeployMonitoringStackAuthorizationProof,
) -> DeployMonitoringStackAuthorizationReport:
    """Authorize the exact mapped monitoring stack step without execution."""

    if not isinstance(proof, DeployMonitoringStackAuthorizationProof):
        raise StateConflictError(
            "deploy monitoring-stack authorization proof is malformed"
        )
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_authorization_artifacts(paths, operation_id)
    _refuse_incompatible_or_later_artifacts(paths, operation_id)
    context = _load_authorization_context(paths, operation_id, lock=lock)
    loaded = _loaded(context.manager.manager.chain.authorization_context)
    metadata = loaded.planning.base.deploy.metadata.record
    archive_provenance = _derive_archive_provenance()
    scope = _derive_authorization_scope(context, archive_provenance)
    scope_digest = _digest_object(scope.to_object())
    decision = _normalize_proof(
        proof,
        context=context,
        scope_digest=scope_digest,
        archive_provenance_digest=archive_provenance.provenance_digest,
    )
    store = DeployMonitoringStackAuthorizationStore(paths, operation_id)
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
            archive_provenance=archive_provenance,
            proof=decision,
            created_at=stored.record.created_at,
        )
        if stored.record != expected:
            raise StateConflictError(
                "deploy monitoring-stack authorization changed; "
                "re-plan with a new operation"
            )
        state = DeployMonitoringStackAuthorizationArtifactState.REUSED
    else:
        record = _build_authorization(
            context,
            scope=scope,
            archive_provenance=archive_provenance,
            proof=decision,
            created_at=format_timestamp(datetime.now(UTC)),
        )
        try:
            stored, state = store.write_locked(record, lock=lock)
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy monitoring-stack authorization persistence failed"
            ) from error
    return _build_report(stored, state=state)


def deploy_monitoring_stack_authorization_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the canonical operation-bound monitoring authorization path."""

    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MONITORING_STACK_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy monitoring-stack authorization path is not canonical"
        )
    return path


def deploy_monitoring_stack_authorization_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(DEPLOY_MONITORING_STACK_AUTHORIZATION_FILENAME_SUFFIX):
        return None
    value = name[: -len(DEPLOY_MONITORING_STACK_AUTHORIZATION_FILENAME_SUFFIX)]
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
    manager = _load_manager_context(paths, operation_id, lock=lock)
    loaded = _loaded(manager.manager.chain.authorization_context)
    metadata = loaded.planning.base.deploy.metadata.record
    store = DeployPostManagerServerReconciliationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    if not store.path.exists():
        raise StateConflictError(
            "deploy monitoring-stack authorization requires post-manager-server "
            "reconciliation"
        )
    post_manager = store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_steps = _build_post_manager_steps(manager)
    expected = _build_post_manager_record(
        manager,
        steps=expected_steps,
        created_at=post_manager.record.created_at,
    )
    if post_manager.record != expected:
        raise StateConflictError(
            "deploy monitoring-stack post-manager-server reconciliation drifted"
        )
    return _AuthorizationContext(manager, post_manager)


def _derive_archive_provenance() -> DeployMonitoringStackArchiveProvenance:
    definition = get_playbook(_PLAYBOOK)
    catalog_entry_digest = _digest_object(
        {
            "any_errors_fatal": definition.any_errors_fatal,
            "check_mode": definition.check_mode.value,
            "classification": definition.classification.value,
            "hosts": definition.hosts,
            "limit_policy": definition.limit_policy.value,
            "name": definition.name,
            "serial": definition.serial,
            "source_available": definition.source_available,
            "target_groups": list(definition.target_groups),
            "variable_names": [item.name for item in definition.variables],
        }
    )
    values: dict[str, object] = {
        "release_line": STACK_RELEASE_LINE,
        "channel": STACK_CHANNEL,
        "stack_version_digest": _digest_object(STACK_VERSION),
        "archive_artifact_digest": ARTIFACT_DIGEST,
        "archive_source_commit_digest": _digest_object(SOURCE_COMMIT),
        "component_count": len(STACK_ARTIFACTS),
        "component_set_digest": _digest_object(dict(sorted(STACK_ARTIFACTS.items()))),
        "documented_port_count": len(DOCUMENTED_PORTS),
        "documented_port_set_digest": _digest_object(
            dict(sorted(DOCUMENTED_PORTS.items()))
        ),
        "catalog_entry_digest": catalog_entry_digest,
        "provenance_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_MONITORING_STACK_ARCHIVE_PROVENANCE_SCHEMA_VERSION
        ),
    }
    values["provenance_digest"] = _archive_provenance_digest_from_values(values)
    return DeployMonitoringStackArchiveProvenance(**values)  # type: ignore[arg-type]


def _derive_authorization_scope(
    context: _AuthorizationContext,
    archive: DeployMonitoringStackArchiveProvenance,
) -> DeployMonitoringStackAuthorizationScope:
    loaded = _loaded(context.manager.manager.chain.authorization_context)
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    post = context.post_manager.record
    steps = tuple(
        step for step in post.steps if step.mapping_sequence == _MAPPING_SEQUENCE
    )
    if len(steps) != 1:
        raise StateConflictError(
            "deploy monitoring-stack mapped authorization scope is ambiguous"
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
            "only the exact active mapped monitoring-stack step may be authorized"
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
            "deploy monitoring-stack target is not the exact current monitoring "
            "identity"
        )
    base_matches = tuple(
        (entry, host)
        for entry in context.manager.manager.base_os.record.entries
        for host in entry.hosts
        if host.logical_id == stable_id
    )
    if len(base_matches) != 1:
        raise StateConflictError(
            "deploy monitoring-stack requires exact current monitoring base-os evidence"
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
            "deploy monitoring-stack Ubuntu, architecture, or base-os gate conflicts"
        )
    readiness = planning.readiness.record
    if (
        readiness.readiness_status is not EvidenceStatus.FRESH
        or readiness.cluster_uuid != metadata.cluster_uuid
        or readiness.operation_id != post.operation_id
        or readiness.observation_artifact_digest != deploy.observation.digest
        or readiness.inventory_artifact_digest != deploy.inventory.digest
        or readiness.trust_artifact_digest != planning.base.trust.digest
        or readiness.ansible_source_digest != loaded.source.digest
        or readiness.remote_connectivity_status != "not-performed"
        or readiness.remote_health_status != "not-performed"
        or readiness.remote_playbook_status != "not-performed"
    ):
        raise StateConflictError(
            "deploy monitoring-stack trust or readiness binding drifted"
        )
    readiness_report = _reconstructed_readiness(planning.base)
    base_os = BaseOsEvidence(
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
    payload = build_monitoring_stack_payload(
        metadata,
        deploy.observation,
        deploy.inventory,
        readiness_report,
        base_os,
        logical_id=stable_id,
        image_filter=image_filter,
        architecture=base_host.image_architecture,
        stack_version=STACK_VERSION,
        cluster_spec_digest=metadata.desired_spec.digest(),
    )
    artifact = _mapping(payload.get("artifact"), "monitoring stack artifact")
    prohibited_fields = (
        "auth_configured",
        "compose_generated",
        "containers_started",
        "manager_registration_performed",
        "public_bind",
        "scylla_started",
        "secrets_written",
        "targets_generated",
    )
    if (
        artifact.get("digest") != ARTIFACT_DIGEST
        or artifact.get("uri") != ARTIFACT_URI
        or payload.get("artifacts") != dict(STACK_ARTIFACTS)
        or payload.get("cache_path") != CACHE_PATH
        or payload.get("channel") != STACK_CHANNEL
        or payload.get("documented_ports") != dict(DOCUMENTED_PORTS)
        or payload.get("install_root") != INSTALL_ROOT
        or payload.get("listen_policy") != LISTEN_POLICY
        or payload.get("release_line") != STACK_RELEASE_LINE
        or payload.get("service_unit") != STACK_SERVICE_UNIT
        or payload.get("source_commit") != SOURCE_COMMIT
        or payload.get("stack_version") != STACK_VERSION
        or any(payload.get(name) is not False for name in prohibited_fields)
    ):
        raise StateConflictError(
            "deploy monitoring-stack install-only or no-public-bind policy conflicts"
        )
    variables = definition.validate_variables(
        {"deploy_scylla_vms_monitoring_stack": payload}
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
    values: dict[str, object] = {
        "mapping_sequence": _MAPPING_SEQUENCE,
        "playbook": _PLAYBOOK,
        "classification": OperationClassification.MUTATING,
        "target_role": _TARGET_ROLE,
        "target_stable_id": stable_id,
        "target_digest": step.target_digest,
        "architecture": DeployMonitoringStackArchitecture(base_host.image_architecture),
        "image_policy_digest": _digest_object(image_filter.to_object()),
        "install_policy": DeployMonitoringStackInstallPolicy.ARCHIVE_ONLY,
        "service_policy": DeployMonitoringStackServicePolicy.DISABLED_INACTIVE,
        "listen_policy": DeployMonitoringStackListenPolicy.NOT_STARTED,
        "docker_install_permitted": False,
        "image_pull_permitted": False,
        "compose_permitted": False,
        "auth_permitted": False,
        "targets_permitted": False,
        "containers_permitted": False,
        "service_start_permitted": False,
        "public_bind_permitted": False,
        "manager_registration_permitted": False,
        "scylla_start_permitted": False,
        "secrets_permitted": False,
        "variables_digest": variables_digest,
        "source_digest": source_digest,
        "command_digest": command_digest,
        "gate_evidence_digest": step.evidence_digest,
        "base_os_evidence_digest": base_entry.evidence_digest,
        "reconciled_step_digest": _digest_object(step.to_object()),
        "prior_reconciled_step_digest": step.prior_step_digest,
        "original_step_digest": step.original_step_digest,
        "archive_provenance_digest": archive.provenance_digest,
        "install_intent_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_SCOPE_SCHEMA_VERSION
        ),
    }
    values["install_intent_digest"] = _scope_intent_digest_from_values(values)
    return DeployMonitoringStackAuthorizationScope(**values)  # type: ignore[arg-type]


def _normalize_proof(
    proof: DeployMonitoringStackAuthorizationProof,
    *,
    context: _AuthorizationContext,
    scope_digest: str,
    archive_provenance_digest: str,
) -> DeployMonitoringStackProofDecision:
    if proof.approval_method is None:
        raise StateConflictError(
            "ordinary deploy monitoring-stack approval is required"
        )
    if not proof.approved:
        raise StateConflictError("ordinary deploy monitoring-stack approval was denied")
    if (
        proof.allow_destructive
        or proof.destructive_scope_provided
        or proof.narrow_consent_provided
    ):
        raise StateConflictError(
            "destructive and narrow proofs are inapplicable to mutating "
            "monitoring-stack authorization"
        )
    post = context.post_manager
    values: dict[str, object] = {
        "allow_destructive": False,
        "approval_method": proof.approval_method.value,
        "approved": True,
        "destructive_scope_provided": False,
        "narrow_consent_provided": False,
        "proof_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_PROOF_SCHEMA_VERSION
        ),
    }
    values["proof_digest"] = _proof_digest_values(
        cluster_uuid=post.record.cluster_uuid,
        operation_id=post.record.operation_id,
        request_digest=post.record.request_digest,
        journal_digest=post.record.journal_digest,
        post_manager_artifact_digest=post.artifact_digest,
        post_manager_record_digest=post.record.record_digest,
        scope_digest=scope_digest,
        archive_provenance_digest=archive_provenance_digest,
        proof=values,
    )
    return DeployMonitoringStackProofDecision.from_object(values)


def _build_authorization(
    context: _AuthorizationContext,
    *,
    scope: DeployMonitoringStackAuthorizationScope,
    archive_provenance: DeployMonitoringStackArchiveProvenance,
    proof: DeployMonitoringStackProofDecision,
    created_at: str,
) -> DeployMonitoringStackAuthorization:
    loaded = _loaded(context.manager.manager.chain.authorization_context)
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    post = context.post_manager.record
    manager = context.manager
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
        "post_bootstrap_artifact_digest": post.post_bootstrap_artifact_digest,
        "post_bootstrap_record_digest": post.post_bootstrap_record_digest,
        "manager_authorization_artifact_digest": (
            manager.authorization.artifact_digest
        ),
        "manager_authorization_digest": (
            manager.authorization.record.authorization_digest
        ),
        "manager_execution_artifact_digest": manager.execution.artifact_digest,
        "manager_execution_binding_digest": (
            manager.execution.record.binding.binding_digest
        ),
        "manager_evidence_artifact_digest": manager.evidence.artifact_digest,
        "manager_evidence_digest": post.evidence_digest,
        "post_manager_artifact_digest": context.post_manager.artifact_digest,
        "post_manager_record_digest": post.record_digest,
        "post_manager_effective_plan_digest": _digest_object(
            [step.to_object() for step in post.steps]
        ),
        "base_os_artifact_digest": (context.manager.manager.base_os.artifact_digest),
        "base_os_evidence_digest": scope.base_os_evidence_digest,
        "catalog_digest": loaded.catalog_digest,
        "ansible_source_version": loaded.source.version,
        "ansible_source_digest": loaded.source.digest,
        "classification": OperationClassification.MUTATING,
        "scope": scope,
        "target_count": 1,
        "target_set_digest": scope.target_digest,
        "authorization_scope_digest": _digest_object(scope.to_object()),
        "archive_provenance": archive_provenance,
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
        or manager.authorization.artifact_digest != post.authorization_artifact_digest
        or manager.execution.artifact_digest != post.execution_artifact_digest
        or manager.evidence.artifact_digest != post.evidence_artifact_digest
        or context.manager.manager.base_os.record.binding.inventory_artifact_digest
        != deploy.inventory.digest
        or context.manager.manager.base_os.record.binding.trust_artifact_digest
        != planning.base.trust.digest
        or context.manager.manager.base_os.record.binding.readiness_artifact_digest
        != planning.readiness.artifact_digest
    ):
        raise StateConflictError(
            "deploy monitoring-stack current manager, inventory, trust, readiness, "
            "journal, or source binding drifted"
        )
    values["authorization_digest"] = _authorization_digest_from_values(values)
    return DeployMonitoringStackAuthorization(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployMonitoringStackAuthorization,
    *,
    state: DeployMonitoringStackAuthorizationArtifactState,
) -> DeployMonitoringStackAuthorizationReport:
    record = stored.record
    scope = record.scope
    archive = record.archive_provenance
    prohibited = (
        scope.docker_install_permitted,
        scope.image_pull_permitted,
        scope.compose_permitted,
        scope.auth_permitted,
        scope.targets_permitted,
        scope.containers_permitted,
        scope.service_start_permitted,
        scope.public_bind_permitted,
        scope.manager_registration_permitted,
        scope.scylla_start_permitted,
        scope.secrets_permitted,
    )
    return DeployMonitoringStackAuthorizationReport(
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
        release_line=archive.release_line,
        stack_version_digest=archive.stack_version_digest,
        archive_artifact_digest=archive.archive_artifact_digest,
        archive_source_commit_digest=archive.archive_source_commit_digest,
        component_count=archive.component_count,
        component_set_digest=archive.component_set_digest,
        archive_provenance_digest=archive.provenance_digest,
        install_policy=scope.install_policy,
        service_policy=scope.service_policy,
        listen_policy=scope.listen_policy,
        prohibited_action_count=sum(prohibited),
        post_manager_artifact_digest=record.post_manager_artifact_digest,
        post_manager_record_digest=record.post_manager_record_digest,
        manager_evidence_digest=record.manager_evidence_digest,
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


def _archive_provenance_digest(
    value: DeployMonitoringStackArchiveProvenance,
) -> str:
    return _archive_provenance_digest_from_values(value.to_object())


def _archive_provenance_digest_from_values(
    values: Mapping[str, object],
) -> str:
    value = dict(values)
    value["provenance_digest"] = ""
    return _digest_object(value)


def _scope_intent_digest(scope: DeployMonitoringStackAuthorizationScope) -> str:
    return _scope_intent_digest_from_values(scope.to_object())


def _scope_intent_digest_from_values(values: Mapping[str, object]) -> str:
    value = dict(values)
    value["install_intent_digest"] = ""
    return _digest_object(value)


def _proof_digest(
    record: DeployMonitoringStackAuthorization,
    proof: Mapping[str, object],
) -> str:
    return _proof_digest_values(
        cluster_uuid=record.cluster_uuid,
        operation_id=record.operation_id,
        request_digest=record.request_digest,
        journal_digest=record.journal_digest,
        post_manager_artifact_digest=record.post_manager_artifact_digest,
        post_manager_record_digest=record.post_manager_record_digest,
        scope_digest=record.authorization_scope_digest,
        archive_provenance_digest=record.archive_provenance.provenance_digest,
        proof=proof,
    )


def _proof_digest_values(
    *,
    cluster_uuid: uuid.UUID,
    operation_id: uuid.UUID,
    request_digest: str,
    journal_digest: str,
    post_manager_artifact_digest: str,
    post_manager_record_digest: str,
    scope_digest: str,
    archive_provenance_digest: str,
    proof: Mapping[str, object],
) -> str:
    proof_value = dict(proof)
    proof_value["proof_digest"] = ""
    return _digest_object(
        {
            "archive_provenance_digest": archive_provenance_digest,
            "authorization_scope_digest": scope_digest,
            "cluster_uuid": str(cluster_uuid),
            "journal_digest": journal_digest,
            "operation": _OPERATION,
            "operation_id": str(operation_id),
            "post_manager_artifact_digest": post_manager_artifact_digest,
            "post_manager_record_digest": post_manager_record_digest,
            "proof": proof_value,
            "request_digest": request_digest,
            "schema_version": (
                ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_PROOF_SCHEMA_VERSION
            ),
            "stage": _STAGE,
        }
    )


def _authorization_digest(record: DeployMonitoringStackAuthorization) -> str:
    return _authorization_digest_from_values(record.to_object())


def _authorization_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployMonitoringStackAuthorization.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(
                item, (JournalStatus, OperationPhase, OperationClassification)
            )
            else item.to_object()
            if name in {"scope", "archive_provenance", "proof"}
            and hasattr(item, "to_object")
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
        ".ansible-deploy-monitoring-stack-execution.json",
        ".ansible-deploy-monitoring-stack-evidence.json",
        ".ansible-deploy-post-monitoring-stack-reconciliation.json",
        ".ansible-deploy-manager-agent",
        ".ansible-deploy-monitoring-agent",
        ".ansible-deploy-monitoring-targets",
        ".ansible-deploy-manager-tasks",
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy monitoring-stack operation history"
        ) from error
    prefix = str(operation_id)
    for entry in entries:
        if entry.name.startswith(prefix) and any(
            fragment in entry.name for fragment in forbidden_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy monitoring-stack authorization refuses execution "
                "or later-stage history"
            )


def _refuse_ambiguous_authorization_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy monitoring-stack authorization history"
        ) from error
    canonical = str(operation_id)
    suffix = DEPLOY_MONITORING_STACK_AUTHORIZATION_FILENAME_SUFFIX
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
                "deploy monitoring-stack authorization artifacts are ambiguous"
            )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy monitoring-stack authorization paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy monitoring-stack authorization requires an acquired deploy lock"
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


__all__ = [
    "ANSIBLE_DEPLOY_MONITORING_STACK_ARCHIVE_PROVENANCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_PROOF_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MONITORING_STACK_AUTHORIZATION_SCOPE_SCHEMA_VERSION",
    "DEPLOY_MONITORING_STACK_AUTHORIZATION_FILENAME_SUFFIX",
    "DeployMonitoringStackApprovalMethod",
    "DeployMonitoringStackArchitecture",
    "DeployMonitoringStackArchiveProvenance",
    "DeployMonitoringStackAuthorization",
    "DeployMonitoringStackAuthorizationArtifactState",
    "DeployMonitoringStackAuthorizationProof",
    "DeployMonitoringStackAuthorizationReport",
    "DeployMonitoringStackAuthorizationScope",
    "DeployMonitoringStackAuthorizationStore",
    "DeployMonitoringStackInstallPolicy",
    "DeployMonitoringStackListenPolicy",
    "DeployMonitoringStackProofDecision",
    "DeployMonitoringStackServicePolicy",
    "StoredDeployMonitoringStackAuthorization",
    "authorize_deploy_monitoring_stack",
    "deploy_monitoring_stack_authorization_id_from_filename",
    "deploy_monitoring_stack_authorization_path",
]
