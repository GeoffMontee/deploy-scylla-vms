"""Immutable authorization for mapped deploy ``manager-agent`` scopes.

This internal owner revalidates the exact post-monitoring reconciliation and
the current Scylla install evidence, derives the complete canonical Scylla
scope, and persists only an unconsumed ordinary approval checkpoint. It does
not execute Ansible, configure an agent, or advance the common journal.
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
from scylla_vms.ansible.deploy_monitoring_stack_reconciliation import (
    ANSIBLE_DEPLOY_POST_MONITORING_STACK_RECONCILIATION_SCHEMA_VERSION,
    DeployPostMonitoringStackReconciliationStore,
    StoredDeployPostMonitoringStackReconciliation,
)
from scylla_vms.ansible.deploy_monitoring_stack_reconciliation import (
    _build_record as _build_post_monitoring_record,
)
from scylla_vms.ansible.deploy_monitoring_stack_reconciliation import (
    _build_steps as _build_post_monitoring_steps,
)
from scylla_vms.ansible.deploy_monitoring_stack_reconciliation import (
    _load_context as _load_monitoring_context,
)
from scylla_vms.ansible.deploy_monitoring_stack_reconciliation import (
    _ReconciliationContext as _MonitoringReconciliationContext,
)
from scylla_vms.ansible.deploy_non_jump_base_os_execution import (
    DeployNonJumpBaseOsHostEvidence,
)
from scylla_vms.ansible.deploy_plan import (
    DeployConditionState,
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import _loaded
from scylla_vms.ansible.deploy_scylla_install_execution import (
    ANSIBLE_DEPLOY_SCYLLA_INSTALL_EVIDENCE_SCHEMA_VERSION,
    DeployScyllaInstallEvidenceEntry,
)
from scylla_vms.ansible.deploy_scylla_install_reconciliation import (
    DeployPostScyllaInstallReconciliationStore,
    StoredDeployPostScyllaInstallReconciliation,
)
from scylla_vms.ansible.deploy_scylla_install_reconciliation import (
    _build_reconciled_steps as _build_post_install_steps,
)
from scylla_vms.ansible.deploy_scylla_install_reconciliation import (
    _build_record as _build_post_install_record,
)
from scylla_vms.ansible.deploy_scylla_install_reconciliation import (
    _load_reconciliation_context as _load_install_context,
)
from scylla_vms.ansible.deploy_scylla_install_reconciliation import (
    _ReconciliationContext as _InstallReconciliationContext,
)
from scylla_vms.ansible.manager_agent import (
    MANAGER_CHANNEL,
    MANAGER_PACKAGE_VERSION,
    MANAGER_PACKAGES,
    MANAGER_RELEASE_LINE,
    MANAGER_REPOSITORY_DEFINITION_DIGEST,
    build_manager_agent_payload,
)
from scylla_vms.ansible.operation_authorization import (
    OPERATION_AUTHORIZATION_FILENAME_SUFFIX,
)
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_install import (
    SCYLLA_EDITION,
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_PACKAGES,
    SCYLLA_SIGNING_KEY_DIGEST,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
    SCYLLA_SIGNING_KEY_UID,
    SCYLLA_SIGNING_SUBKEY_FINGERPRINT,
    ScyllaInstallEvidence,
    load_scylla_signing_key,
    validate_scylla_signing_key,
)
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

ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-agent-authorization-proof/v1"
)
ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_SCOPE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-agent-authorization-scope/v1"
)
ANSIBLE_DEPLOY_MANAGER_AGENT_PACKAGE_PROVENANCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-agent-package-provenance/v1"
)
ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-agent-authorization/v1"
)
ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-agent-authorization-report/v1"
)
DEPLOY_MANAGER_AGENT_AUTHORIZATION_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-agent-authorization.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "manager-agent"
_MAPPING_SEQUENCE = 16
_TARGET_ROLE = HostRole.SCYLLA.value
_STAGE = "post-monitoring-stack-manager-agent"
_SCOPE_KIND = "bootstrap-healthy-scylla-manager-agent-install"
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


class DeployManagerAgentApprovalMethod(StrEnum):
    """PLAN-permitted ordinary approval methods."""

    INTERACTIVE = "interactive"
    CLI_YES = "cli-yes"


class DeployManagerAgentArchitecture(StrEnum):
    """Closed OCI image architecture policy."""

    AMD64 = "amd64"
    AARCH64 = "aarch64"


class DeployManagerAgentServicePolicy(StrEnum):
    """Required service state after package installation."""

    DISABLED_INACTIVE = "disabled-inactive"


class DeployManagerAgentAuthorizationArtifactState(StrEnum):
    """Immutable authorization persistence result."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployManagerAgentAuthorizationProof:
    """Already-normalized ordinary approval without caller-owned scope."""

    approval_method: DeployManagerAgentApprovalMethod | None = None
    approved: bool = False
    allow_destructive: bool = False
    destructive_scope_provided: bool = False
    narrow_consent_provided: bool = False

    def __post_init__(self) -> None:
        if self.approval_method is not None and not isinstance(
            self.approval_method, DeployManagerAgentApprovalMethod
        ):
            raise StateConflictError("deploy manager-agent approval method is invalid")
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
                "deploy manager-agent authorization proof is malformed"
            )


@dataclass(frozen=True, slots=True)
class DeployManagerAgentProofDecision:
    """Persisted ordinary proof bound to the exact complete scope."""

    approval_method: DeployManagerAgentApprovalMethod
    approved: bool
    allow_destructive: bool
    destructive_scope_provided: bool
    narrow_consent_provided: bool
    proof_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or not isinstance(self.approval_method, DeployManagerAgentApprovalMethod)
            or self.approved is not True
            or self.allow_destructive
            or self.destructive_scope_provided
            or self.narrow_consent_provided
        ):
            raise StatePersistenceError(
                "deploy manager-agent authorization proof state is invalid"
            )
        validate_digest(
            self.proof_digest, "deploy manager-agent authorization proof digest"
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
    ) -> DeployManagerAgentProofDecision:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy manager-agent authorization proof",
        )
        try:
            method = DeployManagerAgentApprovalMethod(
                require_string(value, "approval_method")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy manager-agent authorization proof method is invalid"
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
class DeployManagerAgentPackageProvenance:
    """URL- and key-material-free identity of the exact package policy."""

    release_line: str
    channel: str
    package_version_digest: str
    package_count: int
    package_set_digest: str
    repository_definition_digest: str
    signing_key_artifact_digest: str
    signing_key_identity_digest: str
    catalog_entry_digest: str
    provenance_digest: str
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_AGENT_PACKAGE_PROVENANCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_AGENT_PACKAGE_PROVENANCE_SCHEMA_VERSION
            or self.release_line != MANAGER_RELEASE_LINE
            or self.channel != MANAGER_CHANNEL
            or self.package_version_digest != _digest_object(MANAGER_PACKAGE_VERSION)
            or self.package_count != len(MANAGER_PACKAGES)
            or self.package_set_digest != _digest_object(list(MANAGER_PACKAGES))
            or self.repository_definition_digest != MANAGER_REPOSITORY_DEFINITION_DIGEST
            or self.signing_key_artifact_digest != SCYLLA_SIGNING_KEY_DIGEST
            or self.signing_key_identity_digest != _signing_key_identity_digest()
            or self.provenance_digest != _package_provenance_digest(self)
        ):
            raise StatePersistenceError(
                "deploy manager-agent package provenance conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy manager-agent package provenance digest")

    def to_object(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerAgentPackageProvenance:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy manager-agent package provenance",
        )
        return cls(
            release_line=require_string(value, "release_line"),
            channel=require_string(value, "channel"),
            package_version_digest=require_string(value, "package_version_digest"),
            package_count=_integer(value["package_count"], "package count"),
            package_set_digest=require_string(value, "package_set_digest"),
            repository_definition_digest=require_string(
                value, "repository_definition_digest"
            ),
            signing_key_artifact_digest=require_string(
                value, "signing_key_artifact_digest"
            ),
            signing_key_identity_digest=require_string(
                value, "signing_key_identity_digest"
            ),
            catalog_entry_digest=require_string(value, "catalog_entry_digest"),
            provenance_digest=require_string(value, "provenance_digest"),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployManagerAgentAuthorizationScope:
    """One exact redacted Manager agent install intent."""

    scope_index: int
    step_sequence: int
    mapping_sequence: int
    playbook: str
    classification: OperationClassification
    target_role: str
    target_stable_id: str
    target_digest: str
    architecture: DeployManagerAgentArchitecture
    image_policy_digest: str
    service_policy: DeployManagerAgentServicePolicy
    configuration_permitted: bool
    auth_token_permitted: bool
    helper_slice_permitted: bool
    server_reachability_performed: bool
    service_start_permitted: bool
    variables_digest: str
    source_digest: str
    command_digest: str
    base_os_evidence_digest: str
    scylla_install_evidence_digest: str
    scylla_install_provenance_digest: str
    gate_evidence_digest: str
    reconciled_step_digest: str
    prior_reconciled_step_digest: str
    original_step_digest: str
    package_provenance_digest: str
    install_intent_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_SCOPE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        definition = get_playbook(self.playbook)
        prohibited = (
            self.configuration_permitted,
            self.auth_token_permitted,
            self.helper_slice_permitted,
            self.server_reachability_performed,
            self.service_start_permitted,
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_SCOPE_SCHEMA_VERSION
            or self.scope_index < 1
            or self.step_sequence < 1
            or self.mapping_sequence != _MAPPING_SEQUENCE
            or self.playbook != _PLAYBOOK
            or self.classification is not OperationClassification.MUTATING
            or definition.classification is not self.classification
            or self.target_role != _TARGET_ROLE
            or not self.target_stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
            or self.target_digest != _digest_object([self.target_stable_id])
            or not isinstance(self.architecture, DeployManagerAgentArchitecture)
            or self.service_policy
            is not DeployManagerAgentServicePolicy.DISABLED_INACTIVE
            or any(prohibited)
            or self.install_intent_digest != _scope_intent_digest(self)
        ):
            raise StatePersistenceError(
                "deploy manager-agent authorization scope policy is invalid"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy manager-agent authorization scope digest")

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
    ) -> DeployManagerAgentAuthorizationScope:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy manager-agent authorization scope",
        )
        boolean_fields = {
            "configuration_permitted",
            "auth_token_permitted",
            "helper_slice_permitted",
            "server_reachability_performed",
            "service_start_permitted",
        }
        integer_fields = {"scope_index", "step_sequence", "mapping_sequence"}
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in integer_fields:
                    parsed[name] = _integer(item, name)
                elif name == "classification":
                    parsed[name] = OperationClassification(require_string(value, name))
                elif name == "architecture":
                    parsed[name] = DeployManagerAgentArchitecture(
                        require_string(value, name)
                    )
                elif name == "service_policy":
                    parsed[name] = DeployManagerAgentServicePolicy(
                        require_string(value, name)
                    )
                elif name in boolean_fields:
                    parsed[name] = _boolean(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy manager-agent authorization scope enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployManagerAgentAuthorization:
    """Immutable unconsumed authorization for the complete Scylla scope."""

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
    final_health_evidence_digest: str
    post_monitoring_artifact_digest: str
    post_monitoring_record_digest: str
    post_monitoring_effective_plan_digest: str
    install_reconciliation_artifact_digest: str
    install_reconciliation_record_digest: str
    install_evidence_artifact_digest: str
    install_evidence_digest: str
    base_os_artifact_digest: str
    base_os_evidence_digest: str
    catalog_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    classification: OperationClassification
    scopes: tuple[DeployManagerAgentAuthorizationScope, ...]
    target_stable_ids: tuple[str, ...]
    target_count: int
    target_set_digest: str
    authorization_scope_digest: str
    package_provenance: DeployManagerAgentPackageProvenance
    proof: DeployManagerAgentProofDecision
    authorization_state: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_digest: str
    post_monitoring_schema_version: str = (
        ANSIBLE_DEPLOY_POST_MONITORING_STACK_RECONCILIATION_SCHEMA_VERSION
    )
    install_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_INSTALL_EVIDENCE_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_SCHEMA_VERSION
            or self.post_monitoring_schema_version
            != ANSIBLE_DEPLOY_POST_MONITORING_STACK_RECONCILIATION_SCHEMA_VERSION
            or self.install_evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_INSTALL_EVIDENCE_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.classification is not OperationClassification.MUTATING
            or not self.scopes
            or self.target_stable_ids
            != tuple(scope.target_stable_id for scope in self.scopes)
            or self.target_stable_ids != tuple(sorted(set(self.target_stable_ids)))
            or self.target_count != len(self.target_stable_ids)
            or self.target_set_digest != _digest_object(list(self.target_stable_ids))
            or self.authorization_scope_digest
            != _digest_object([scope.to_object() for scope in self.scopes])
            or any(
                scope.scope_index != index
                or scope.package_provenance_digest
                != self.package_provenance.provenance_digest
                for index, scope in enumerate(self.scopes, start=1)
            )
            or self.authorization_state != _AUTHORIZED
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError(
                "deploy manager-agent authorization identity or state is invalid"
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
                count, "deploy manager-agent authorization generation or count"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy manager-agent authorization binding digest")
        if self.proof.proof_digest != _proof_digest(self, self.proof.to_object()):
            raise StatePersistenceError(
                "deploy manager-agent authorization proof digest conflicts"
            )
        if self.authorization_digest != _authorization_digest(self):
            raise StatePersistenceError(
                "deploy manager-agent authorization digest conflicts"
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
                else [scope.to_object() for scope in value]
                if name == "scopes"
                else list(value)
                if name == "target_stable_ids"
                else value.to_object()
                if name in {"package_provenance", "proof"}
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerAgentAuthorization:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy manager-agent authorization",
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
                elif name == "scopes":
                    parsed[name] = tuple(
                        DeployManagerAgentAuthorizationScope.from_object(
                            _mapping(scope, "deploy manager-agent scope")
                        )
                        for scope in _array(item, "deploy manager-agent scopes")
                    )
                elif name == "target_stable_ids":
                    parsed[name] = _string_tuple(item, "target stable IDs")
                elif name == "package_provenance":
                    parsed[name] = DeployManagerAgentPackageProvenance.from_object(
                        _mapping(item, "deploy manager-agent package provenance")
                    )
                elif name == "proof":
                    parsed[name] = DeployManagerAgentProofDecision.from_object(
                        _mapping(item, "deploy manager-agent proof")
                    )
                elif name == "consumed":
                    parsed[name] = _boolean(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy manager-agent authorization enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployManagerAgentAuthorization:
    record: DeployManagerAgentAuthorization
    artifact_digest: str


class DeployManagerAgentAuthorizationStore:
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
        self._path = deploy_manager_agent_authorization_path(paths, operation_id)
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
    ) -> StoredDeployManagerAgentAuthorization:
        value, artifact_digest = self._file.read()
        record = DeployManagerAgentAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_identity_digest
            != _cluster_identity_digest(expected_cluster_uuid, expected_cluster_name)
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "deploy manager-agent authorization identity conflicts"
            )
        return StoredDeployManagerAgentAuthorization(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerAgentAuthorization:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerAgentAuthorization,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerAgentAuthorization,
        DeployManagerAgentAuthorizationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy manager-agent authorization operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=self._paths.cluster_root.name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy manager-agent authorization is immutable; "
                    "use a new operation"
                )
            return current, DeployManagerAgentAuthorizationArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerAgentAuthorization(record, artifact_digest),
            DeployManagerAgentAuthorizationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerAgentAuthorizationReport:
    """Strict redacted authorization report without executable inputs."""

    operation_id: uuid.UUID
    artifact_state: DeployManagerAgentAuthorizationArtifactState
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_state: str
    stage: str
    scope_kind: str
    approval_method: DeployManagerAgentApprovalMethod
    approval_state: str
    proof_digest: str
    classification: OperationClassification
    playbook: str
    target_stable_ids: tuple[str, ...]
    target_count: int
    target_set_digest: str
    authorization_scope_digest: str
    architecture_count: int
    architecture_set_digest: str
    release_line: str
    package_count: int
    package_version_digest: str
    package_set_digest: str
    package_provenance_digest: str
    service_policy: DeployManagerAgentServicePolicy
    prohibited_action_count: int
    post_monitoring_artifact_digest: str
    post_monitoring_record_digest: str
    final_health_evidence_digest: str
    install_reconciliation_artifact_digest: str
    install_evidence_artifact_digest: str
    install_evidence_digest: str
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
        ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_SCHEMA_VERSION
    )
    proof_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    post_monitoring_schema_version: str = (
        ANSIBLE_DEPLOY_POST_MONITORING_STACK_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or self.post_monitoring_schema_version
            != ANSIBLE_DEPLOY_POST_MONITORING_STACK_RECONCILIATION_SCHEMA_VERSION
            or self.authorization_state != _AUTHORIZED
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.approval_state != "approved"
            or self.classification is not OperationClassification.MUTATING
            or self.playbook != _PLAYBOOK
            or self.target_count < 1
            or self.target_stable_ids != tuple(sorted(set(self.target_stable_ids)))
            or self.target_count != len(self.target_stable_ids)
            or self.release_line != MANAGER_RELEASE_LINE
            or self.package_count != len(MANAGER_PACKAGES)
            or self.service_policy
            is not DeployManagerAgentServicePolicy.DISABLED_INACTIVE
            or self.prohibited_action_count
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError(
                "deploy manager-agent authorization report is invalid"
            )
        for stable_id in self.target_stable_ids:
            if not stable_id.isascii() or _LOGICAL_ID.fullmatch(stable_id) is None:
                raise StatePersistenceError(
                    "deploy manager-agent authorization report target is invalid"
                )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy manager-agent report digest")

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
            "package_policy": {
                "package_count": self.package_count,
                "package_set_digest": self.package_set_digest,
                "package_version_digest": self.package_version_digest,
                "provenance_digest": self.package_provenance_digest,
                "release_line": self.release_line,
            },
            "policy": {
                "architecture_count": self.architecture_count,
                "architecture_set_digest": self.architecture_set_digest,
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
                "final_health_evidence_digest": self.final_health_evidence_digest,
                "install": {
                    "evidence_artifact_digest": self.install_evidence_artifact_digest,
                    "evidence_digest": self.install_evidence_digest,
                    "reconciliation_artifact_digest": (
                        self.install_reconciliation_artifact_digest
                    ),
                },
                "inventory_artifact_digest": self.inventory_artifact_digest,
                "post_monitoring": {
                    "artifact_digest": self.post_monitoring_artifact_digest,
                    "record_digest": self.post_monitoring_record_digest,
                    "schema_version": self.post_monitoring_schema_version,
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
                "target_stable_ids": list(self.target_stable_ids),
            },
            "stage": self.stage,
        }


@dataclass(frozen=True, slots=True)
class _AuthorizationContext:
    monitoring: _MonitoringReconciliationContext
    post_monitoring: StoredDeployPostMonitoringStackReconciliation
    install: _InstallReconciliationContext
    post_install: StoredDeployPostScyllaInstallReconciliation


def authorize_deploy_manager_agent(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proof: DeployManagerAgentAuthorizationProof,
) -> DeployManagerAgentAuthorizationReport:
    """Authorize the exact complete mapped Manager agent scope."""

    if not isinstance(proof, DeployManagerAgentAuthorizationProof):
        raise StateConflictError(
            "deploy manager-agent authorization proof is malformed"
        )
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_authorization_artifacts(paths, operation_id)
    _refuse_incompatible_or_later_artifacts(paths, operation_id)
    context = _load_authorization_context(paths, operation_id, lock=lock)
    loaded = _loaded(
        context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    metadata = loaded.planning.base.deploy.metadata.record
    package_provenance = _derive_package_provenance()
    scopes = _derive_authorization_scopes(context, package_provenance)
    scope_digest = _digest_object([scope.to_object() for scope in scopes])
    decision = _normalize_proof(
        proof,
        context=context,
        scope_digest=scope_digest,
        package_provenance_digest=package_provenance.provenance_digest,
    )
    store = DeployManagerAgentAuthorizationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    if store.path.exists():
        stored = store.read_locked(
            lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
        )
        expected = _build_authorization(
            context,
            scopes=scopes,
            package_provenance=package_provenance,
            proof=decision,
            created_at=stored.record.created_at,
        )
        if stored.record != expected:
            raise StateConflictError(
                "deploy manager-agent authorization changed; "
                "re-plan with a new operation"
            )
        state = DeployManagerAgentAuthorizationArtifactState.REUSED
    else:
        record = _build_authorization(
            context,
            scopes=scopes,
            package_provenance=package_provenance,
            proof=decision,
            created_at=format_timestamp(datetime.now(UTC)),
        )
        try:
            stored, state = store.write_locked(record, lock=lock)
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy manager-agent authorization persistence failed"
            ) from error
    return _build_report(stored, state=state)


def deploy_manager_agent_authorization_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the canonical operation-bound Manager agent authorization path."""

    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MANAGER_AGENT_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy manager-agent authorization path is not canonical"
        )
    return path


def deploy_manager_agent_authorization_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(DEPLOY_MANAGER_AGENT_AUTHORIZATION_FILENAME_SUFFIX):
        return None
    value = name[: -len(DEPLOY_MANAGER_AGENT_AUTHORIZATION_FILENAME_SUFFIX)]
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
    monitoring = _load_monitoring_context(paths, operation_id, lock=lock)
    loaded = _loaded(monitoring.monitoring.manager.manager.chain.authorization_context)
    metadata = loaded.planning.base.deploy.metadata.record
    post_monitoring_store = DeployPostMonitoringStackReconciliationStore(
        paths, operation_id
    )
    validate_state_file(post_monitoring_store.path, allow_missing=True)
    if not post_monitoring_store.path.exists():
        raise StateConflictError(
            "deploy manager-agent authorization requires post-monitoring-stack "
            "reconciliation"
        )
    post_monitoring = post_monitoring_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_post_steps = _build_post_monitoring_steps(monitoring)
    expected_post = _build_post_monitoring_record(
        monitoring,
        steps=expected_post_steps,
        created_at=post_monitoring.record.created_at,
    )
    if post_monitoring.record != expected_post:
        raise StateConflictError(
            "deploy manager-agent post-monitoring reconciliation drifted"
        )

    install = _load_install_context(paths, operation_id, lock=lock)
    post_install_store = DeployPostScyllaInstallReconciliationStore(paths, operation_id)
    validate_state_file(post_install_store.path, allow_missing=True)
    if not post_install_store.path.exists():
        raise StateConflictError(
            "deploy manager-agent authorization requires post-scylla-install "
            "reconciliation"
        )
    post_install = post_install_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_install_steps = _build_post_install_steps(
        install.prior,
        install.evidence,
        configure_source_digest=_playbook_source_digest(
            loaded.source, "scylla-configure"
        ),
    )
    expected_install = _build_post_install_record(
        install,
        steps=expected_install_steps,
        created_at=post_install.record.created_at,
    )
    if post_install.record != expected_install:
        raise StateConflictError(
            "deploy manager-agent Scylla install reconciliation drifted"
        )
    if (
        install.evidence.record.binding.inventory_artifact_digest
        != loaded.planning.base.deploy.inventory.digest
        or install.evidence.record.binding.trust_artifact_digest
        != loaded.planning.base.trust.digest
        or install.evidence.record.binding.readiness_artifact_digest
        != loaded.planning.readiness.artifact_digest
        or install.evidence.record.binding.source_digest != loaded.source.digest
        or install.evidence.record.binding.catalog_digest != loaded.catalog_digest
    ):
        raise StateConflictError(
            "deploy manager-agent Scylla install provenance is not current"
        )
    return _AuthorizationContext(monitoring, post_monitoring, install, post_install)


def _derive_package_provenance() -> DeployManagerAgentPackageProvenance:
    validate_scylla_signing_key(load_scylla_signing_key())
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
        "release_line": MANAGER_RELEASE_LINE,
        "channel": MANAGER_CHANNEL,
        "package_version_digest": _digest_object(MANAGER_PACKAGE_VERSION),
        "package_count": len(MANAGER_PACKAGES),
        "package_set_digest": _digest_object(list(MANAGER_PACKAGES)),
        "repository_definition_digest": MANAGER_REPOSITORY_DEFINITION_DIGEST,
        "signing_key_artifact_digest": SCYLLA_SIGNING_KEY_DIGEST,
        "signing_key_identity_digest": _signing_key_identity_digest(),
        "catalog_entry_digest": catalog_entry_digest,
        "provenance_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_MANAGER_AGENT_PACKAGE_PROVENANCE_SCHEMA_VERSION
        ),
    }
    values["provenance_digest"] = _package_provenance_digest_from_values(values)
    return DeployManagerAgentPackageProvenance(**values)  # type: ignore[arg-type]


def _derive_authorization_scopes(
    context: _AuthorizationContext,
    package: DeployManagerAgentPackageProvenance,
) -> tuple[DeployManagerAgentAuthorizationScope, ...]:
    loaded = _loaded(
        context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    post = context.post_monitoring.record
    steps = tuple(
        step for step in post.steps if step.mapping_sequence == _MAPPING_SEQUENCE
    )
    if len(steps) != 1:
        raise StateConflictError(
            "deploy manager-agent mapped authorization scope is ambiguous"
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
        or post.next_target_count < 1
        or step.status
        is not DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        or step.playbook != _PLAYBOOK
        or step.condition_state is not DeployConditionState.ACTIVE
        or step.classification is not OperationClassification.MUTATING
        or step.target_role != _TARGET_ROLE
        or not step.target_ids
        or step.target_ids != tuple(sorted(set(step.target_ids)))
        or step.target_digest != post.next_target_set_digest
        or len(step.target_ids) != post.next_target_count
        or step.evidence_state != "next-gates-evaluated"
        or step.evidence_digest is None
        or step.blockers != _EXPECTED_BLOCKERS
        or step.source_digest != source_digest
        or definition.classification is not OperationClassification.MUTATING
        or definition.hosts != _TARGET_ROLE
        or definition.serial != 1
        or definition.limit_policy is not LimitPolicy.EXPLICIT
        or definition.check_mode is not CheckMode.PREVIEW
        or not definition.any_errors_fatal
        or not definition.source_available
    ):
        raise StateConflictError(
            "only the exact active mapped manager-agent scope may be authorized"
        )

    stable_ids = tuple(
        sorted(
            host.logical_id
            for host in deploy.inventory.record.inventory.hosts
            if host.role is HostRole.SCYLLA
        )
    )
    if (
        not stable_ids
        or stable_ids != step.target_ids
        or _digest_object(list(stable_ids)) != step.target_digest
    ):
        raise StateConflictError(
            "deploy manager-agent scope is not the complete current Scylla identity set"
        )
    all_inventory_ids = {
        host.logical_id: host.role for host in deploy.inventory.record.inventory.hosts
    }
    if any(
        all_inventory_ids.get(stable_id) is not HostRole.SCYLLA
        for stable_id in stable_ids
    ):
        raise StateConflictError("deploy manager-agent target role conflicts")

    base_by_id = {
        host.logical_id: (entry, host)
        for entry in context.monitoring.monitoring.manager.manager.base_os.record.entries
        for host in entry.hosts
        if host.logical_id in stable_ids
    }
    install_by_id = {
        entry.stable_id: entry for entry in context.install.evidence.record.entries
    }
    if (
        set(base_by_id) != set(stable_ids)
        or set(install_by_id) != set(stable_ids)
        or context.post_install.record.target_set_digest
        != _digest_object(list(stable_ids))
        or context.post_install.record.installed_count != len(stable_ids)
        or context.post_install.record.service_safe_count != len(stable_ids)
        or context.post_install.record.prohibited_action_count
    ):
        raise StateConflictError(
            "deploy manager-agent base-os or Scylla-install scope is incomplete"
        )

    image_filter = dict(metadata.desired_spec.image_filters).get(HostRole.SCYLLA)
    if image_filter != ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT):
        raise StateConflictError(
            "deploy manager-agent Scylla image policy is not exact Ubuntu 24.04"
        )
    readiness = _reconstructed_readiness(planning.base)
    result: list[DeployManagerAgentAuthorizationScope] = []
    for index, stable_id in enumerate(stable_ids, start=1):
        base_entry, base_host = base_by_id[stable_id]
        install_entry = install_by_id[stable_id]
        _validate_prerequisite_entry(stable_id, base_host, install_entry)
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
        install = _scylla_install_evidence(
            install_entry,
            observation_digest=deploy.observation.digest,
            inventory_digest=deploy.inventory.digest,
        )
        payload = build_manager_agent_payload(
            metadata,
            deploy.observation,
            deploy.inventory,
            readiness,
            base_os,
            install,
            logical_id=stable_id,
            image_filter=image_filter,
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
        variables = definition.validate_variables(
            {"deploy_scylla_vms_manager_agent": payload}
        )
        variables_digest = digest_bytes(serialize_json(variables))
        command_digest = ansible_command_intent_digest(
            definition,
            step_sequence=step.sequence,
            limit=(stable_id,),
            variables_digest=variables_digest,
            tags=(),
            check=False,
            diff=False,
            verbosity=0,
        )
        values: dict[str, object] = {
            "scope_index": index,
            "step_sequence": step.sequence,
            "mapping_sequence": _MAPPING_SEQUENCE,
            "playbook": _PLAYBOOK,
            "classification": OperationClassification.MUTATING,
            "target_role": _TARGET_ROLE,
            "target_stable_id": stable_id,
            "target_digest": _digest_object([stable_id]),
            "architecture": DeployManagerAgentArchitecture(
                base_host.image_architecture
            ),
            "image_policy_digest": _digest_object(image_filter.to_object()),
            "service_policy": DeployManagerAgentServicePolicy.DISABLED_INACTIVE,
            "configuration_permitted": False,
            "auth_token_permitted": False,
            "helper_slice_permitted": False,
            "server_reachability_performed": False,
            "service_start_permitted": False,
            "variables_digest": variables_digest,
            "source_digest": source_digest,
            "command_digest": command_digest,
            "base_os_evidence_digest": base_entry.evidence_digest,
            "scylla_install_evidence_digest": install_entry.evidence_digest,
            "scylla_install_provenance_digest": install_entry.provenance_digest,
            "gate_evidence_digest": step.evidence_digest,
            "reconciled_step_digest": step.step_digest,
            "prior_reconciled_step_digest": step.prior_step_digest,
            "original_step_digest": step.original_step_digest,
            "package_provenance_digest": package.provenance_digest,
            "install_intent_digest": "",
            "schema_version": (
                ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_SCOPE_SCHEMA_VERSION
            ),
        }
        values["install_intent_digest"] = _scope_intent_digest_from_values(values)
        result.append(
            DeployManagerAgentAuthorizationScope(**values)  # type: ignore[arg-type]
        )
    return tuple(result)


def _validate_prerequisite_entry(
    stable_id: str,
    base_host: DeployNonJumpBaseOsHostEvidence,
    install: DeployScyllaInstallEvidenceEntry,
) -> None:
    if (
        base_host.logical_id != stable_id
        or base_host.os_family != "Ubuntu"
        or base_host.os_version != "24.04"
        or base_host.status not in {BaseOsStatus.NO_CHANGE, BaseOsStatus.CHANGED}
        or not base_host.applied
        or base_host.reboot_required
        or base_host.image_architecture not in {"amd64", "aarch64"}
        or install.stable_id != stable_id
        or not install.installed
        or install.package_version != SCYLLA_PACKAGE_VERSION
        or install.package_count != len(SCYLLA_PACKAGES)
        or not install.service_masked
        or not install.service_inactive
        or install.configuration_performed
        or install.storage_mutation_performed
        or install.tuning_performed
        or install.manager_operation_performed
        or install.service_started
        or install.manual_recovery_required
        or install.automatic_retry_allowed
    ):
        raise StateConflictError(
            "deploy manager-agent Ubuntu, base-os, or Scylla-install gate conflicts"
        )


def _scylla_install_evidence(
    entry: DeployScyllaInstallEvidenceEntry,
    *,
    observation_digest: str,
    inventory_digest: str,
) -> ScyllaInstallEvidence:
    return ScyllaInstallEvidence(
        logical_id=entry.stable_id,
        status=entry.status,
        requested_edition=SCYLLA_EDITION,
        requested_version=entry.package_version,
        installed_edition=SCYLLA_EDITION,
        installed_version=entry.package_version,
        packages=tuple((name, entry.package_version) for name in SCYLLA_PACKAGES),
        repository_digest=entry.repository_definition_digest,
        signing_key_fingerprint=SCYLLA_SIGNING_KEY_FINGERPRINT,
        signing_key_digest=entry.signing_key_artifact_digest,
        service_masked=entry.service_masked,
        service_inactive=entry.service_inactive,
        configuration_performed=entry.configuration_performed,
        storage_mutation_performed=entry.storage_mutation_performed,
        tuning_performed=entry.tuning_performed,
        manager_operation_performed=entry.manager_operation_performed,
        service_started=entry.service_started,
        provenance=(
            ("inventory_digest", inventory_digest),
            ("observation_digest", observation_digest),
            ("semantic_evidence_digest", entry.evidence_digest),
            ("source_provenance_digest", entry.provenance_digest),
        ),
        blockers=(),
    )


def _normalize_proof(
    proof: DeployManagerAgentAuthorizationProof,
    *,
    context: _AuthorizationContext,
    scope_digest: str,
    package_provenance_digest: str,
) -> DeployManagerAgentProofDecision:
    if proof.approval_method is None:
        raise StateConflictError("ordinary deploy manager-agent approval is required")
    if not proof.approved:
        raise StateConflictError("ordinary deploy manager-agent approval was denied")
    if (
        proof.allow_destructive
        or proof.destructive_scope_provided
        or proof.narrow_consent_provided
    ):
        raise StateConflictError(
            "destructive and narrow proofs are inapplicable to mutating "
            "manager-agent authorization"
        )
    post = context.post_monitoring
    values: dict[str, object] = {
        "allow_destructive": False,
        "approval_method": proof.approval_method.value,
        "approved": True,
        "destructive_scope_provided": False,
        "narrow_consent_provided": False,
        "proof_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_PROOF_SCHEMA_VERSION
        ),
    }
    values["proof_digest"] = _proof_digest_values(
        cluster_uuid=post.record.cluster_uuid,
        operation_id=post.record.operation_id,
        request_digest=post.record.request_digest,
        journal_digest=post.record.journal_digest,
        post_monitoring_artifact_digest=post.artifact_digest,
        post_monitoring_record_digest=post.record.record_digest,
        scope_digest=scope_digest,
        package_provenance_digest=package_provenance_digest,
        proof=values,
    )
    return DeployManagerAgentProofDecision.from_object(values)


def _build_authorization(
    context: _AuthorizationContext,
    *,
    scopes: tuple[DeployManagerAgentAuthorizationScope, ...],
    package_provenance: DeployManagerAgentPackageProvenance,
    proof: DeployManagerAgentProofDecision,
    created_at: str,
) -> DeployManagerAgentAuthorization:
    loaded = _loaded(
        context.monitoring.monitoring.manager.manager.chain.authorization_context
    )
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    post = context.post_monitoring.record
    install = context.install.evidence
    target_ids = tuple(scope.target_stable_id for scope in scopes)
    base_os = context.monitoring.monitoring.manager.manager.base_os
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
        "final_health_evidence_digest": (
            context.monitoring.monitoring.manager.manager.bridge.record.final_health_evidence_digest
        ),
        "post_monitoring_artifact_digest": context.post_monitoring.artifact_digest,
        "post_monitoring_record_digest": post.record_digest,
        "post_monitoring_effective_plan_digest": _digest_object(
            [step.to_object() for step in post.steps]
        ),
        "install_reconciliation_artifact_digest": context.post_install.artifact_digest,
        "install_reconciliation_record_digest": context.post_install.record.record_digest,
        "install_evidence_artifact_digest": install.artifact_digest,
        "install_evidence_digest": _digest_object(
            [entry.evidence_digest for entry in install.record.entries]
        ),
        "base_os_artifact_digest": base_os.artifact_digest,
        "base_os_evidence_digest": _digest_object(
            [scope.base_os_evidence_digest for scope in scopes]
        ),
        "catalog_digest": loaded.catalog_digest,
        "ansible_source_version": loaded.source.version,
        "ansible_source_digest": loaded.source.digest,
        "classification": OperationClassification.MUTATING,
        "scopes": scopes,
        "target_stable_ids": target_ids,
        "target_count": len(target_ids),
        "target_set_digest": _digest_object(list(target_ids)),
        "authorization_scope_digest": _digest_object(
            [scope.to_object() for scope in scopes]
        ),
        "package_provenance": package_provenance,
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
        or install.record.binding.inventory_artifact_digest != deploy.inventory.digest
        or install.record.binding.trust_artifact_digest != planning.base.trust.digest
        or install.record.binding.readiness_artifact_digest
        != planning.readiness.artifact_digest
        or base_os.record.binding.inventory_artifact_digest != deploy.inventory.digest
        or base_os.record.binding.trust_artifact_digest != planning.base.trust.digest
        or base_os.record.binding.readiness_artifact_digest
        != planning.readiness.artifact_digest
    ):
        raise StateConflictError(
            "deploy manager-agent inventory, trust, readiness, journal, install, "
            "or source binding drifted"
        )
    values["authorization_digest"] = _authorization_digest_from_values(values)
    return DeployManagerAgentAuthorization(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployManagerAgentAuthorization,
    *,
    state: DeployManagerAgentAuthorizationArtifactState,
) -> DeployManagerAgentAuthorizationReport:
    record = stored.record
    architectures = sorted({scope.architecture.value for scope in record.scopes})
    prohibited = tuple(
        value
        for scope in record.scopes
        for value in (
            scope.configuration_permitted,
            scope.auth_token_permitted,
            scope.helper_slice_permitted,
            scope.server_reachability_performed,
            scope.service_start_permitted,
        )
    )
    package = record.package_provenance
    return DeployManagerAgentAuthorizationReport(
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
        playbook=_PLAYBOOK,
        target_stable_ids=record.target_stable_ids,
        target_count=record.target_count,
        target_set_digest=record.target_set_digest,
        authorization_scope_digest=record.authorization_scope_digest,
        architecture_count=len(architectures),
        architecture_set_digest=_digest_object(architectures),
        release_line=package.release_line,
        package_count=package.package_count,
        package_version_digest=package.package_version_digest,
        package_set_digest=package.package_set_digest,
        package_provenance_digest=package.provenance_digest,
        service_policy=DeployManagerAgentServicePolicy.DISABLED_INACTIVE,
        prohibited_action_count=sum(prohibited),
        post_monitoring_artifact_digest=record.post_monitoring_artifact_digest,
        post_monitoring_record_digest=record.post_monitoring_record_digest,
        final_health_evidence_digest=record.final_health_evidence_digest,
        install_reconciliation_artifact_digest=(
            record.install_reconciliation_artifact_digest
        ),
        install_evidence_artifact_digest=record.install_evidence_artifact_digest,
        install_evidence_digest=record.install_evidence_digest,
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


def _signing_key_identity_digest() -> str:
    return _digest_object(
        {
            "fingerprint": SCYLLA_SIGNING_KEY_FINGERPRINT,
            "signing_subkey_fingerprint": SCYLLA_SIGNING_SUBKEY_FINGERPRINT,
            "uid": SCYLLA_SIGNING_KEY_UID,
        }
    )


def _package_provenance_digest(
    value: DeployManagerAgentPackageProvenance,
) -> str:
    return _package_provenance_digest_from_values(value.to_object())


def _package_provenance_digest_from_values(
    values: Mapping[str, object],
) -> str:
    value = dict(values)
    value["provenance_digest"] = ""
    return _digest_object(value)


def _scope_intent_digest(scope: DeployManagerAgentAuthorizationScope) -> str:
    return _scope_intent_digest_from_values(scope.to_object())


def _scope_intent_digest_from_values(values: Mapping[str, object]) -> str:
    value = dict(values)
    value["install_intent_digest"] = ""
    return _digest_object(value)


def _proof_digest(
    record: DeployManagerAgentAuthorization,
    proof: Mapping[str, object],
) -> str:
    return _proof_digest_values(
        cluster_uuid=record.cluster_uuid,
        operation_id=record.operation_id,
        request_digest=record.request_digest,
        journal_digest=record.journal_digest,
        post_monitoring_artifact_digest=record.post_monitoring_artifact_digest,
        post_monitoring_record_digest=record.post_monitoring_record_digest,
        scope_digest=record.authorization_scope_digest,
        package_provenance_digest=record.package_provenance.provenance_digest,
        proof=proof,
    )


def _proof_digest_values(
    *,
    cluster_uuid: uuid.UUID,
    operation_id: uuid.UUID,
    request_digest: str,
    journal_digest: str,
    post_monitoring_artifact_digest: str,
    post_monitoring_record_digest: str,
    scope_digest: str,
    package_provenance_digest: str,
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
            "package_provenance_digest": package_provenance_digest,
            "post_monitoring_artifact_digest": post_monitoring_artifact_digest,
            "post_monitoring_record_digest": post_monitoring_record_digest,
            "proof": proof_value,
            "request_digest": request_digest,
            "schema_version": (
                ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_PROOF_SCHEMA_VERSION
            ),
            "stage": _STAGE,
        }
    )


def _authorization_digest(record: DeployManagerAgentAuthorization) -> str:
    return _authorization_digest_from_values(record.to_object())


def _authorization_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployManagerAgentAuthorization.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(
                item, (JournalStatus, OperationPhase, OperationClassification)
            )
            else [scope.to_object() for scope in item]
            if name == "scopes" and isinstance(item, tuple)
            else list(item)
            if name == "target_stable_ids" and isinstance(item, tuple)
            else item.to_object()
            if name in {"package_provenance", "proof"} and hasattr(item, "to_object")
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
        ".ansible-deploy-manager-agent-execution.json",
        ".ansible-deploy-manager-agent-evidence.json",
        ".ansible-deploy-post-manager-agent-reconciliation.json",
        ".ansible-deploy-monitoring-agent",
        ".ansible-deploy-monitoring-targets",
        ".ansible-deploy-manager-tasks",
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy manager-agent operation history"
        ) from error
    prefix = str(operation_id)
    for entry in entries:
        if entry.name.startswith(prefix) and any(
            fragment in entry.name for fragment in forbidden_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy manager-agent authorization refuses execution "
                "or later-stage history"
            )


def _refuse_ambiguous_authorization_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy manager-agent authorization history"
        ) from error
    canonical = str(operation_id)
    suffix = DEPLOY_MANAGER_AGENT_AUTHORIZATION_FILENAME_SUFFIX
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
                "deploy manager-agent authorization artifacts are ambiguous"
            )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy manager-agent authorization paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy manager-agent authorization requires an acquired deploy lock"
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


__all__ = [
    "ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_PROOF_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_AGENT_AUTHORIZATION_SCOPE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_AGENT_PACKAGE_PROVENANCE_SCHEMA_VERSION",
    "DEPLOY_MANAGER_AGENT_AUTHORIZATION_FILENAME_SUFFIX",
    "DeployManagerAgentApprovalMethod",
    "DeployManagerAgentArchitecture",
    "DeployManagerAgentAuthorization",
    "DeployManagerAgentAuthorizationArtifactState",
    "DeployManagerAgentAuthorizationProof",
    "DeployManagerAgentAuthorizationReport",
    "DeployManagerAgentAuthorizationScope",
    "DeployManagerAgentAuthorizationStore",
    "DeployManagerAgentPackageProvenance",
    "DeployManagerAgentProofDecision",
    "DeployManagerAgentServicePolicy",
    "StoredDeployManagerAgentAuthorization",
    "authorize_deploy_manager_agent",
    "deploy_manager_agent_authorization_id_from_filename",
    "deploy_manager_agent_authorization_path",
]
