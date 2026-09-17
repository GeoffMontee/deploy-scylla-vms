"""Immutable authorization for operation-bound deploy ``scylla-configure``.

This internal owner revalidates the complete deploy chain through the exact
post-install reconciliation, derives configuration intent only from canonical
state, and persists an address-free, value-free ordinary approval checkpoint.
It never creates execution intent, consumes authorization, invokes Ansible,
mutates a host, or changes the common operation journal.
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

from scylla_vms.ansible.commands import ansible_command_intent_digest
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStep,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_non_jump_base_os_execution import (
    DeployNonJumpBaseOsEvidenceStore,
)
from scylla_vms.ansible.deploy_plan import (
    DeployConditionState,
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_reconciliation import (
    _ReconciliationContext as _DeployReconciliationContext,
)
from scylla_vms.ansible.deploy_scylla_install_reconciliation import (
    ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_SCHEMA_VERSION,
    DeployPostScyllaInstallReconciliationStore,
    StoredDeployPostScyllaInstallReconciliation,
    _build_reconciled_steps,
    _load_reconciliation_context,
)
from scylla_vms.ansible.deploy_scylla_install_reconciliation import (
    _build_record as _build_post_install_record,
)
from scylla_vms.ansible.deploy_scylla_install_reconciliation import (
    _ReconciliationContext as _InstallReconciliationContext,
)
from scylla_vms.ansible.operation_authorization import (
    OPERATION_AUTHORIZATION_FILENAME_SUFFIX,
)
from scylla_vms.ansible.registry import CheckMode, get_playbook
from scylla_vms.ansible.scylla_configure import (
    SCYLLA_CONFIGURE_DIRECTORIES,
    SCYLLA_CONFIGURE_KEYS,
    SCYLLA_CONFIGURE_SCHEMA_VERSION,
    SeedSelectionMode,
    _normalized_label,
    _private_ipv4,
    _render_configuration_files,
    select_scylla_seeds,
)
from scylla_vms.ansible.scylla_install import (
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_RELEASE_LINE,
)
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION, AnsibleSourceBundle
from scylla_vms.desired import HostRole
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

ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-configure-authorization-proof/v1"
)
ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-configure-authorization/v1"
)
ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-configure-authorization-report/v1"
)
DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-configure-authorization.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "scylla-configure"
_MAPPING_SEQUENCE = 12
_STAGE = "post-scylla-install-scylla-configure"
_SCOPE_KIND = "installed-scylla-configuration"
_AUTHORIZED = "authorized-pre-execution"
_EXECUTION_UNAVAILABLE = "unavailable"
_FINALIZATION_NOT_STARTED = "not-started"
_PUBLIC_WORKFLOW_UNAVAILABLE = "unavailable"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TEMPLATE_PATHS = (
    "playbooks/roles/scylla_configure/templates/cassandra-rackdc.properties.j2",
    "playbooks/roles/scylla_configure/templates/scylla.yaml.j2",
)
_CONFIGURE_SOURCE_PATHS = (
    "playbooks/scylla-configure.yml",
    "playbooks/roles/scylla_configure/tasks/main.yml",
    *_TEMPLATE_PATHS,
)


class DeployScyllaConfigureApprovalMethod(StrEnum):
    """PLAN-permitted ordinary approval methods."""

    INTERACTIVE = "interactive"
    CLI_YES = "cli-yes"


class DeployScyllaConfigureAuthorizationArtifactState(StrEnum):
    """Immutable authorization persistence result."""

    CREATED = "created"
    REUSED = "reused"


class DeployScyllaConfigureArchitecture(StrEnum):
    """Closed OCI image architecture policy."""

    AMD64 = "amd64"
    AARCH64 = "aarch64"


class DeployScyllaConfigureServicePolicy(StrEnum):
    """The only service state accepted before configuration."""

    MASKED_INACTIVE = "masked-inactive"


class DeployScyllaConfigureSeedPolicy(StrEnum):
    """The only seed policy modeled for initial deploy."""

    INITIAL_STABLE_ID = "initial-stable-id"


@dataclass(frozen=True, slots=True)
class DeployScyllaConfigureAuthorizationProof:
    """Already-normalized ordinary approval without caller-owned configuration."""

    approval_method: DeployScyllaConfigureApprovalMethod | None = None
    approved: bool = False
    allow_destructive: bool = False
    destructive_scope_provided: bool = False
    narrow_consent_provided: bool = False

    def __post_init__(self) -> None:
        if self.approval_method is not None and not isinstance(
            self.approval_method, DeployScyllaConfigureApprovalMethod
        ):
            raise StateConflictError(
                "deploy scylla-configure approval method is invalid"
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
                "deploy scylla-configure authorization proof is malformed"
            )


@dataclass(frozen=True, slots=True)
class DeployScyllaConfigureProofDecision:
    """Persisted normalized ordinary proof bound to exact derived intent."""

    approval_method: DeployScyllaConfigureApprovalMethod
    approved: bool
    allow_destructive: bool
    destructive_scope_provided: bool
    narrow_consent_provided: bool
    proof_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or not isinstance(self.approval_method, DeployScyllaConfigureApprovalMethod)
            or self.approved is not True
            or self.allow_destructive is not False
            or self.destructive_scope_provided is not False
            or self.narrow_consent_provided is not False
        ):
            raise StatePersistenceError(
                "deploy scylla-configure authorization proof state is invalid"
            )
        validate_digest(
            self.proof_digest,
            "deploy scylla-configure authorization proof digest",
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
    ) -> DeployScyllaConfigureProofDecision:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy scylla-configure authorization proof",
        )
        try:
            method = DeployScyllaConfigureApprovalMethod(
                require_string(value, "approval_method")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy scylla-configure authorization proof method is invalid"
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
class DeployScyllaConfigureAuthorizationScope:
    """One exact value-free configuration intent derived from canonical state."""

    sequence: int
    mapping_sequence: int
    classification: OperationClassification
    architecture: DeployScyllaConfigureArchitecture
    service_policy: DeployScyllaConfigureServicePolicy
    seed_policy: DeployScyllaConfigureSeedPolicy
    target_count: int
    target_digest: str
    condition_digest: str
    gate_evidence_digest: str
    original_step_digest: str
    prior_reconciled_step_digest: str
    reconciled_step_digest: str
    cluster_name_digest: str
    datacenter_digest: str
    rack_digest: str
    private_identity_digest: str
    seed_count: int
    seed_policy_digest: str
    package_version_digest: str
    directory_count: int
    directory_policy_digest: str
    rendered_file_count: int
    rendered_config_digest: str
    template_count: int
    template_source_digest: str
    role_source_digest: str
    playbook_source_digest: str
    variables_digest: str
    command_digest: str
    configuration_intent_digest: str

    def __post_init__(self) -> None:
        if (
            self.sequence < 1
            or self.mapping_sequence != _MAPPING_SEQUENCE
            or self.classification is not OperationClassification.MUTATING
            or not isinstance(self.architecture, DeployScyllaConfigureArchitecture)
            or self.service_policy
            is not DeployScyllaConfigureServicePolicy.MASKED_INACTIVE
            or self.seed_policy is not DeployScyllaConfigureSeedPolicy.INITIAL_STABLE_ID
            or self.target_count != 1
            or self.seed_count != 1
            or self.directory_count != len(SCYLLA_CONFIGURE_DIRECTORIES)
            or self.rendered_file_count != 2
            or self.template_count != len(_TEMPLATE_PATHS)
            or self.configuration_intent_digest != _scope_intent_digest(self)
        ):
            raise StatePersistenceError(
                "deploy scylla-configure authorization scope policy is invalid"
            )
        for digest in _digest_fields(self):
            validate_digest(
                digest, "deploy scylla-configure authorization scope digest"
            )

    def to_object(self) -> dict[str, object]:
        return {
            name: value.value if isinstance(value, StrEnum) else value
            for name in self.__dataclass_fields__
            if (value := getattr(self, name)) is not None
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaConfigureAuthorizationScope:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy scylla-configure authorization scope",
        )
        try:
            return cls(
                sequence=_integer(value["sequence"], "scope sequence"),
                mapping_sequence=_integer(
                    value["mapping_sequence"], "scope mapping sequence"
                ),
                classification=OperationClassification(
                    require_string(value, "classification")
                ),
                architecture=DeployScyllaConfigureArchitecture(
                    require_string(value, "architecture")
                ),
                service_policy=DeployScyllaConfigureServicePolicy(
                    require_string(value, "service_policy")
                ),
                seed_policy=DeployScyllaConfigureSeedPolicy(
                    require_string(value, "seed_policy")
                ),
                target_count=_integer(value["target_count"], "target count"),
                target_digest=require_string(value, "target_digest"),
                condition_digest=require_string(value, "condition_digest"),
                gate_evidence_digest=require_string(value, "gate_evidence_digest"),
                original_step_digest=require_string(value, "original_step_digest"),
                prior_reconciled_step_digest=require_string(
                    value, "prior_reconciled_step_digest"
                ),
                reconciled_step_digest=require_string(value, "reconciled_step_digest"),
                cluster_name_digest=require_string(value, "cluster_name_digest"),
                datacenter_digest=require_string(value, "datacenter_digest"),
                rack_digest=require_string(value, "rack_digest"),
                private_identity_digest=require_string(
                    value, "private_identity_digest"
                ),
                seed_count=_integer(value["seed_count"], "seed count"),
                seed_policy_digest=require_string(value, "seed_policy_digest"),
                package_version_digest=require_string(value, "package_version_digest"),
                directory_count=_integer(value["directory_count"], "directory count"),
                directory_policy_digest=require_string(
                    value, "directory_policy_digest"
                ),
                rendered_file_count=_integer(
                    value["rendered_file_count"], "rendered file count"
                ),
                rendered_config_digest=require_string(value, "rendered_config_digest"),
                template_count=_integer(value["template_count"], "template count"),
                template_source_digest=require_string(value, "template_source_digest"),
                role_source_digest=require_string(value, "role_source_digest"),
                playbook_source_digest=require_string(value, "playbook_source_digest"),
                variables_digest=require_string(value, "variables_digest"),
                command_digest=require_string(value, "command_digest"),
                configuration_intent_digest=require_string(
                    value, "configuration_intent_digest"
                ),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy scylla-configure authorization scope enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployScyllaConfigureAuthorization:
    """Immutable unconsumed authorization for exact configuration intents."""

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
    catalog_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    post_install_reconciliation_artifact_digest: str
    post_install_reconciliation_record_digest: str
    post_install_effective_plan_digest: str
    install_authorization_artifact_digest: str
    install_authorization_digest: str
    install_authorization_proof_digest: str
    install_execution_artifact_digest: str
    install_execution_binding_digest: str
    install_evidence_artifact_digest: str
    install_evidence_digest: str
    validated_chain_digest: str
    classification: OperationClassification
    scopes: tuple[DeployScyllaConfigureAuthorizationScope, ...]
    target_count: int
    target_set_digest: str
    authorization_scope_digest: str
    configuration_intent_digest: str
    non_authorized_blocker_digest: str
    proof: DeployScyllaConfigureProofDecision
    authorization_state: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_digest: str
    post_install_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
            or self.post_install_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.classification is not OperationClassification.MUTATING
            or self.authorization_state != _AUTHORIZED
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
            or not isinstance(self.proof, DeployScyllaConfigureProofDecision)
        ):
            raise StatePersistenceError(
                "deploy scylla-configure authorization identity or state is invalid"
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
                count, "deploy scylla-configure authorization generation or count"
            )
        if (
            not self.scopes
            or tuple(scope.sequence for scope in self.scopes)
            != tuple(sorted(scope.sequence for scope in self.scopes))
            or len({scope.sequence for scope in self.scopes}) != len(self.scopes)
            or self.target_count != sum(scope.target_count for scope in self.scopes)
            or self.authorization_scope_digest
            != _digest_object([scope.to_object() for scope in self.scopes])
            or self.configuration_intent_digest
            != _digest_object(
                [scope.configuration_intent_digest for scope in self.scopes]
            )
        ):
            raise StatePersistenceError(
                "deploy scylla-configure authorization scope summary conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(
                digest, "deploy scylla-configure authorization binding digest"
            )
        if self.proof.proof_digest != _proof_digest(self, self.proof.to_object()):
            raise StatePersistenceError(
                "deploy scylla-configure authorization proof digest conflicts"
            )
        if self.authorization_digest != _authorization_digest(self):
            raise StatePersistenceError(
                "deploy scylla-configure authorization digest conflicts"
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
                else value.to_object()
                if name == "proof"
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaConfigureAuthorization:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy scylla-configure authorization",
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
        for name in cls.__dataclass_fields__:
            item = value[name]
            if name in integer_fields:
                parsed[name] = _integer(item, name)
            elif name in {"cluster_uuid", "operation_id"}:
                parsed[name] = parse_uuid(require_string(value, name), name)
            elif name == "journal_status":
                parsed[name] = _enum(
                    JournalStatus, require_string(value, name), "journal status"
                )
            elif name == "journal_phase":
                parsed[name] = _enum(
                    OperationPhase, require_string(value, name), "journal phase"
                )
            elif name == "classification":
                parsed[name] = _enum(
                    OperationClassification,
                    require_string(value, name),
                    "classification",
                )
            elif name == "scopes":
                parsed[name] = tuple(
                    DeployScyllaConfigureAuthorizationScope.from_object(
                        _mapping(scope, "deploy scylla-configure authorization scope")
                    )
                    for scope in _array(
                        item, "deploy scylla-configure authorization scopes"
                    )
                )
            elif name == "proof":
                parsed[name] = DeployScyllaConfigureProofDecision.from_object(
                    _mapping(item, "deploy scylla-configure authorization proof")
                )
            elif name == "consumed":
                parsed[name] = _boolean(item, name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaConfigureAuthorization:
    record: DeployScyllaConfigureAuthorization
    artifact_digest: str


class DeployScyllaConfigureAuthorizationStore:
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
        self._path = deploy_scylla_configure_authorization_path(paths, operation_id)
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
    ) -> StoredDeployScyllaConfigureAuthorization:
        value, artifact_digest = self._file.read()
        record = DeployScyllaConfigureAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_identity_digest
            != _cluster_identity_digest(expected_cluster_uuid, expected_cluster_name)
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "deploy scylla-configure authorization identity conflicts"
            )
        return StoredDeployScyllaConfigureAuthorization(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaConfigureAuthorization:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaConfigureAuthorization,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployScyllaConfigureAuthorization,
        DeployScyllaConfigureAuthorizationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy scylla-configure authorization operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=self._paths.cluster_root.name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy scylla-configure authorization is immutable; "
                    "use a new operation"
                )
            return current, DeployScyllaConfigureAuthorizationArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaConfigureAuthorization(record, artifact_digest),
            DeployScyllaConfigureAuthorizationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaConfigureAuthorizationReport:
    """Strict digest/count/enum-only authorization report."""

    operation_id: uuid.UUID
    artifact_state: DeployScyllaConfigureAuthorizationArtifactState
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_state: str
    stage: str
    scope_kind: str
    approval_method: DeployScyllaConfigureApprovalMethod
    approval_state: str
    proof_digest: str
    classification: OperationClassification
    target_count: int
    target_set_digest: str
    authorization_scope_digest: str
    configuration_intent_digest: str
    seed_count: int
    directory_count: int
    rendered_file_count: int
    template_count: int
    template_source_digest: str
    role_source_digest: str
    package_version_digest: str
    post_install_reconciliation_artifact_digest: str
    post_install_reconciliation_record_digest: str
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
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
    )
    proof_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or self.reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_SCHEMA_VERSION
            or self.authorization_state != _AUTHORIZED
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.approval_state != "approved"
            or self.classification is not OperationClassification.MUTATING
            or self.target_count < 1
            or self.seed_count != self.target_count
            or self.directory_count
            != self.target_count * len(SCYLLA_CONFIGURE_DIRECTORIES)
            or self.rendered_file_count != self.target_count * 2
            or self.template_count != self.target_count * len(_TEMPLATE_PATHS)
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError(
                "deploy scylla-configure authorization report is invalid"
            )
        for digest in _digest_fields(self):
            validate_digest(
                digest, "deploy scylla-configure authorization report digest"
            )

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
            "blockers": {"digest": self.blockers_digest},
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
                "directory_count": self.directory_count,
                "package_version_digest": self.package_version_digest,
                "rendered_file_count": self.rendered_file_count,
                "role_source_digest": self.role_source_digest,
                "seed_count": self.seed_count,
                "template_count": self.template_count,
                "template_source_digest": self.template_source_digest,
            },
            "provenance": {
                "ansible_source_digest": self.ansible_source_digest,
                "catalog_digest": self.catalog_digest,
                "inventory_artifact_digest": self.inventory_artifact_digest,
                "post_install_reconciliation": {
                    "artifact_digest": (
                        self.post_install_reconciliation_artifact_digest
                    ),
                    "record_digest": self.post_install_reconciliation_record_digest,
                    "schema_version": self.reconciliation_schema_version,
                },
                "readiness_artifact_digest": self.readiness_artifact_digest,
                "trust_artifact_digest": self.trust_artifact_digest,
            },
            "result": self.artifact_state.value,
            "schema_version": self.schema_version,
            "scope": {
                "configuration_intent_digest": self.configuration_intent_digest,
                "digest": self.authorization_scope_digest,
                "kind": self.scope_kind,
                "target_count": self.target_count,
                "target_set_digest": self.target_set_digest,
            },
            "stage": self.stage,
        }


@dataclass(frozen=True, slots=True)
class _AuthorizationContext:
    install: _InstallReconciliationContext
    reconciliation: StoredDeployPostScyllaInstallReconciliation


@dataclass(frozen=True, slots=True)
class _DerivedConfigurationIntent:
    """Canonical protected execution input paired with its public authorization."""

    scope: DeployScyllaConfigureAuthorizationScope
    target_ids: tuple[str, ...]
    variables: tuple[tuple[str, object], ...]
    variables_digest: str
    command_digest: str
    source_digest: str


def authorize_deploy_scylla_configure(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proof: DeployScyllaConfigureAuthorizationProof,
) -> DeployScyllaConfigureAuthorizationReport:
    """Authorize exact canonical Scylla configuration without execution."""

    if not isinstance(proof, DeployScyllaConfigureAuthorizationProof):
        raise StateConflictError(
            "deploy scylla-configure authorization proof is malformed"
        )
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_authorization_artifacts(paths, operation_id)
    _refuse_incompatible_or_later_artifacts(paths, operation_id)
    context = _load_authorization_context(paths, operation_id, lock=lock)
    metadata = _loaded(context).planning.base.deploy.metadata.record
    scopes = _derive_authorization_scopes(context, paths=paths, lock=lock)
    scope_digest = _digest_object([scope.to_object() for scope in scopes])
    decision = _normalize_proof(
        proof,
        context=context,
        scope_digest=scope_digest,
        intent_digest=_digest_object(
            [scope.configuration_intent_digest for scope in scopes]
        ),
    )
    store = DeployScyllaConfigureAuthorizationStore(paths, operation_id)
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
            proof=decision,
            created_at=stored.record.created_at,
        )
        if stored.record != expected:
            raise StateConflictError(
                "deploy scylla-configure authorization changed; "
                "re-plan with a new operation"
            )
        state = DeployScyllaConfigureAuthorizationArtifactState.REUSED
    else:
        record = _build_authorization(
            context,
            scopes=scopes,
            proof=decision,
            created_at=format_timestamp(datetime.now(UTC)),
        )
        try:
            stored, state = store.write_locked(record, lock=lock)
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy scylla-configure authorization persistence failed"
            ) from error
    return _build_report(stored, state=state)


def deploy_scylla_configure_authorization_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the canonical operation-bound authorization path."""

    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy scylla-configure authorization path is not canonical"
        )
    return path


def deploy_scylla_configure_authorization_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_FILENAME_SUFFIX):
        return None
    value = name[: -len(DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_FILENAME_SUFFIX)]
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
    install = _load_reconciliation_context(paths, operation_id, lock=lock)
    metadata = (
        install.authorization_context.post.authorization_context.preflight.metadata
    )
    store = DeployPostScyllaInstallReconciliationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    if not store.path.exists():
        raise StateConflictError(
            "deploy scylla-configure authorization requires complete "
            "post-scylla-install reconciliation"
        )
    reconciliation = store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    loaded = install.authorization_context.post.authorization_context.preflight.discovery.post.chain.authorization_context.final_routes.post.post.base.host.loaded
    expected_steps = _build_reconciled_steps(
        install.prior,
        install.evidence,
        configure_source_digest=_playbook_source_digest(loaded.source, _PLAYBOOK),
    )
    expected = _build_post_install_record(
        install,
        steps=expected_steps,
        created_at=reconciliation.record.created_at,
    )
    if reconciliation.record != expected:
        raise StateConflictError(
            "deploy scylla-configure post-install reconciliation drifted; "
            "use a new operation"
        )
    return _AuthorizationContext(install, reconciliation)


def _derive_authorization_scopes(
    context: _AuthorizationContext,
    *,
    paths: StatePaths,
    lock: ClusterLock,
) -> tuple[DeployScyllaConfigureAuthorizationScope, ...]:
    return tuple(
        intent.scope
        for intent in _derive_configuration_intents(context, paths=paths, lock=lock)
    )


def _derive_configuration_intents(
    context: _AuthorizationContext,
    *,
    paths: StatePaths,
    lock: ClusterLock,
) -> tuple[_DerivedConfigurationIntent, ...]:
    record = context.reconciliation.record
    ready = tuple(
        step
        for step in record.steps
        if step.status
        is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
    )
    if (
        not ready
        or len(ready) != record.authorization_required_count
        or record.next_playbook != _PLAYBOOK
    ):
        raise StateConflictError(
            "deploy scylla-configure authorization-required scope is unavailable"
        )
    loaded = _loaded(context)
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    inventory = deploy.inventory
    source = loaded.source
    definition = get_playbook(_PLAYBOOK)
    if (
        definition.classification is not OperationClassification.MUTATING
        or definition.hosts != HostRole.SCYLLA.value
        or definition.serial != 1
        or definition.check_mode is not CheckMode.PREVIEW
        or not definition.source_available
    ):
        raise StateConflictError("deploy scylla-configure catalog policy conflicts")
    source_digests = _source_digests(source, _CONFIGURE_SOURCE_PATHS)
    playbook_source_digest = _playbook_source_digest(source, _PLAYBOOK)
    if source_digests["playbooks/scylla-configure.yml"] != playbook_source_digest:
        raise StateConflictError(
            "deploy scylla-configure playbook source binding conflicts"
        )
    template_source_digest = _digest_object(
        {path: source_digests[path] for path in _TEMPLATE_PATHS}
    )
    role_source_digest = _digest_object(source_digests)
    inventory_hosts = {
        host.logical_id: host
        for host in inventory.record.inventory.hosts
        if host.role is HostRole.SCYLLA
    }
    inventory_ids = tuple(sorted(inventory_hosts))
    expected_ids = tuple(sorted(target for step in ready for target in step.target_ids))
    install_entries = {
        entry.stable_id: entry for entry in context.install.evidence.record.entries
    }
    storage_entries = {
        entry.stable_id: entry
        for entry in context.install.authorization_context.evidence.record.entries
    }
    if (
        not inventory_ids
        or expected_ids != inventory_ids
        or expected_ids != tuple(sorted(install_entries))
        or expected_ids != tuple(sorted(storage_entries))
        or len(expected_ids) != len(set(expected_ids))
        or record.next_target_count != len(expected_ids)
        or record.next_target_set_digest != _digest_object(list(expected_ids))
    ):
        raise StateConflictError(
            "deploy scylla-configure target scope or prerequisite membership drifted"
        )
    desired = metadata.desired_spec
    desired_ids = tuple(
        sorted(
            logical_id for zone in desired.zones for logical_id in zone.logical_node_ids
        )
    )
    desired_racks = {
        logical_id: zone.scylla_rack.value
        for zone in desired.zones
        for logical_id in zone.logical_node_ids
    }
    desired_datacenter = _normalized_label(
        desired.scylla_datacenter.value, "Scylla datacenter"
    )
    cluster_name = _normalized_label(metadata.cluster_name, "cluster name")
    if desired_ids != inventory_ids:
        raise StateConflictError(
            "deploy scylla-configure desired and inventory membership conflicts"
        )
    private_addresses = {
        logical_id: _private_ipv4(host.private_address)
        for logical_id, host in inventory_hosts.items()
    }
    if len(set(private_addresses.values())) != len(private_addresses):
        raise StateConflictError(
            "deploy scylla-configure private identities are duplicated"
        )
    base_store = DeployNonJumpBaseOsEvidenceStore(paths, record.operation_id)
    validate_state_file(base_store.path, allow_missing=True)
    if not base_store.path.exists():
        raise StateConflictError(
            "deploy scylla-configure current base-os evidence is unavailable"
        )
    base_evidence = base_store.read_locked(
        lock,
        expected_cluster_uuid=record.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    base_entries = {
        host.logical_id: (entry, host)
        for entry in base_evidence.record.entries
        for host in entry.hosts
        if host.logical_id in inventory_hosts
    }
    binding = context.install.execution.record.binding
    if (
        base_evidence.artifact_digest != binding.base_os_evidence_artifact_digest
        or _digest_object(
            [
                entry.evidence_digest
                for entry in base_evidence.record.entries
                if any(host.logical_id in inventory_hosts for host in entry.hosts)
            ]
        )
        != binding.base_os_evidence_digest
        or tuple(sorted(base_entries)) != inventory_ids
    ):
        raise StateConflictError(
            "deploy scylla-configure base-os evidence binding drifted"
        )
    intents: list[_DerivedConfigurationIntent] = []
    for step in ready:
        _validate_authorizable_step(
            step,
            inventory_ids=set(inventory_ids),
            playbook_source_digest=playbook_source_digest,
        )
        stable_id = step.target_ids[0]
        host = inventory_hosts[stable_id]
        install = install_entries[stable_id]
        storage = storage_entries[stable_id]
        base_entry, base_host = base_entries[stable_id]
        rack = _normalized_label(host.scylla_rack, "Scylla rack")
        if (
            host.scylla_datacenter != desired_datacenter
            or rack != desired_racks.get(stable_id)
            or install.package_version != SCYLLA_PACKAGE_VERSION
            or not install.installed
            or not install.service_masked
            or not install.service_inactive
            or install.configuration_performed
            or install.service_started
            or install.manual_recovery_required
            or not storage.readiness_for_scylla
            or storage.failed_check_count
            or storage.unknown_check_count
            or storage.blocker_count
            or storage.manual_recovery_required
            or not base_host.applied
            or base_host.reboot_required
            or base_host.image_architecture != install.image_architecture
        ):
            raise StateConflictError(
                "deploy scylla-configure topology, install, storage, service, "
                "or base-os gate conflicts"
            )
        architecture = DeployScyllaConfigureArchitecture(install.image_architecture)
        seed_policy = select_scylla_seeds(
            inventory,
            mode=SeedSelectionMode.INITIAL,
            target_logical_id=stable_id,
        )
        payload = _configuration_payload(
            context,
            stable_id=stable_id,
            architecture=architecture,
            cluster_name=cluster_name,
            datacenter=desired_datacenter,
            rack=rack,
            private_addresses=private_addresses,
            seed_ids=seed_policy.stable_ids,
            seed_digest=seed_policy.digest,
            base_evidence_digest=base_entry.evidence_digest,
            storage_evidence_digest=storage.evidence_digest,
            install_evidence_digest=install.evidence_digest,
        )
        variables: dict[str, object] = {"deploy_scylla_vms_scylla_configure": payload}
        validated = definition.validate_variables(variables)
        variables_digest = digest_bytes(serialize_json(validated))
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
        topology = cast(dict[str, str], payload["topology"])
        values: dict[str, object] = {
            "sequence": step.sequence,
            "mapping_sequence": step.mapping_sequence,
            "classification": step.classification,
            "architecture": architecture,
            "service_policy": (DeployScyllaConfigureServicePolicy.MASKED_INACTIVE),
            "seed_policy": DeployScyllaConfigureSeedPolicy.INITIAL_STABLE_ID,
            "target_count": 1,
            "target_digest": step.target_digest,
            "condition_digest": _digest_object(step.condition),
            "gate_evidence_digest": cast(str, step.evidence_digest),
            "original_step_digest": step.original_step_digest,
            "prior_reconciled_step_digest": step.prior_reconciled_step_digest,
            "reconciled_step_digest": _digest_object(step.to_object()),
            "cluster_name_digest": _digest_object(topology["cluster_name"]),
            "datacenter_digest": _digest_object(topology["datacenter"]),
            "rack_digest": _digest_object(topology["rack"]),
            "private_identity_digest": _digest_object(
                {
                    "stable_id": stable_id,
                    "private_address": private_addresses[stable_id],
                }
            ),
            "seed_count": len(seed_policy.stable_ids),
            "seed_policy_digest": seed_policy.digest,
            "package_version_digest": _digest_object(SCYLLA_PACKAGE_VERSION),
            "directory_count": len(SCYLLA_CONFIGURE_DIRECTORIES),
            "directory_policy_digest": _digest_object(
                list(SCYLLA_CONFIGURE_DIRECTORIES)
            ),
            "rendered_file_count": len(cast(dict[str, str], payload["file_digests"])),
            "rendered_config_digest": cast(str, payload["config_digest"]),
            "template_count": len(_TEMPLATE_PATHS),
            "template_source_digest": template_source_digest,
            "role_source_digest": role_source_digest,
            "playbook_source_digest": playbook_source_digest,
            "variables_digest": variables_digest,
            "command_digest": command_digest,
            "configuration_intent_digest": "",
        }
        values["configuration_intent_digest"] = _scope_intent_digest_from_values(values)
        scope = DeployScyllaConfigureAuthorizationScope(
            **values  # type: ignore[arg-type]
        )
        intents.append(
            _DerivedConfigurationIntent(
                scope=scope,
                target_ids=step.target_ids,
                variables=tuple(sorted(validated.items())),
                variables_digest=variables_digest,
                command_digest=command_digest,
                source_digest=playbook_source_digest,
            )
        )
    return tuple(sorted(intents, key=lambda item: item.scope.sequence))


def _configuration_payload(
    context: _AuthorizationContext,
    *,
    stable_id: str,
    architecture: DeployScyllaConfigureArchitecture,
    cluster_name: str,
    datacenter: str,
    rack: str,
    private_addresses: Mapping[str, str],
    seed_ids: tuple[str, ...],
    seed_digest: str,
    base_evidence_digest: str,
    storage_evidence_digest: str,
    install_evidence_digest: str,
) -> dict[str, object]:
    if (
        not seed_ids
        or len(seed_ids) > 3
        or seed_ids != tuple(sorted(set(seed_ids)))
        or any(seed not in private_addresses for seed in seed_ids)
        or stable_id not in private_addresses
    ):
        raise StateConflictError(
            "deploy scylla-configure seed or private identity policy conflicts"
        )
    loaded = _loaded(context)
    planning = loaded.planning
    deploy = planning.base.deploy
    address = private_addresses[stable_id]
    config: dict[str, object] = {
        "api_address": address,
        "broadcast_address": address,
        "broadcast_rpc_address": address,
        "cluster_name": cluster_name,
        "commitlog_directory": SCYLLA_CONFIGURE_DIRECTORIES[1],
        "data_file_directories": [SCYLLA_CONFIGURE_DIRECTORIES[0]],
        "endpoint_snitch": "GossipingPropertyFileSnitch",
        "hints_directory": SCYLLA_CONFIGURE_DIRECTORIES[2],
        "listen_address": address,
        "prometheus_address": address,
        "rpc_address": address,
        "seed_provider": [
            {
                "class_name": "org.apache.cassandra.locator.SimpleSeedProvider",
                "parameters": [
                    {"seeds": ",".join(private_addresses[seed] for seed in seed_ids)}
                ],
            }
        ],
        "view_hints_directory": SCYLLA_CONFIGURE_DIRECTORIES[3],
    }
    if tuple(sorted(config)) != SCYLLA_CONFIGURE_KEYS:
        raise StateConflictError(
            "deploy scylla-configure configuration allowlist conflicts"
        )
    topology = {
        "cluster_name": cluster_name,
        "datacenter": datacenter,
        "rack": rack,
    }
    rendered = _render_configuration_files(config, topology)
    file_digests = {
        name: digest_bytes(content.encode("utf-8"))
        for name, content in sorted(rendered.items())
    }
    metadata = deploy.metadata.record
    return {
        "architecture": architecture.value,
        "cluster_uuid": str(metadata.cluster_uuid),
        "config": config,
        "config_digest": _digest_object(file_digests),
        "configuration_state": "initial",
        "file_digests": file_digests,
        "logical_id": stable_id,
        "package_version": SCYLLA_PACKAGE_VERSION,
        "previous_config_digest": None,
        "provenance": {
            "base_os_digest": base_evidence_digest,
            "cluster_spec_digest": _digest_object(metadata.desired_spec.to_object()),
            "inventory_digest": deploy.inventory.digest,
            "observation_digest": deploy.observation.digest,
            "scylla_install_digest": install_evidence_digest,
            "storage_postcheck_digest": storage_evidence_digest,
            "trust_digest": planning.base.trust.digest,
        },
        "release_line": SCYLLA_RELEASE_LINE,
        "runtime_validation_performed": False,
        "schema_version": SCYLLA_CONFIGURE_SCHEMA_VERSION,
        "seed_digest": seed_digest,
        "seed_stable_ids": list(seed_ids),
        "topology": topology,
        "topology_digest": _digest_object(topology),
    }


def _validate_authorizable_step(
    step: DeployBaseOsReconciledStep,
    *,
    inventory_ids: set[str],
    playbook_source_digest: str,
) -> None:
    if (
        step.mapping_sequence != _MAPPING_SEQUENCE
        or step.playbook != _PLAYBOOK
        or step.condition_state is not DeployConditionState.ACTIVE
        or step.classification is not OperationClassification.MUTATING
        or step.target_role != HostRole.SCYLLA.value
        or len(step.target_ids) != 1
        or not set(step.target_ids) <= inventory_ids
        or step.target_digest != _digest_object(list(step.target_ids))
        or step.source_digest != playbook_source_digest
        or step.evidence_state
        is not DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED
        or step.evidence_digest is None
    ):
        raise StateConflictError(
            "only exact post-install Scylla configure steps may be authorized"
        )


def _normalize_proof(
    proof: DeployScyllaConfigureAuthorizationProof,
    *,
    context: _AuthorizationContext,
    scope_digest: str,
    intent_digest: str,
) -> DeployScyllaConfigureProofDecision:
    if proof.approval_method is None:
        raise StateConflictError(
            "ordinary deploy scylla-configure approval is required"
        )
    if not proof.approved:
        raise StateConflictError("ordinary deploy scylla-configure approval was denied")
    if (
        proof.allow_destructive
        or proof.destructive_scope_provided
        or proof.narrow_consent_provided
    ):
        raise StateConflictError(
            "destructive and narrow proofs are inapplicable to mutating "
            "scylla-configure authorization"
        )
    reconciliation = context.reconciliation
    values: dict[str, object] = {
        "allow_destructive": False,
        "approval_method": proof.approval_method.value,
        "approved": True,
        "destructive_scope_provided": False,
        "narrow_consent_provided": False,
        "proof_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION
        ),
    }
    values["proof_digest"] = _proof_digest_values(
        cluster_uuid=reconciliation.record.cluster_uuid,
        operation_id=reconciliation.record.operation_id,
        request_digest=reconciliation.record.request_digest,
        journal_digest=reconciliation.record.journal_digest,
        reconciliation_artifact_digest=reconciliation.artifact_digest,
        reconciliation_record_digest=reconciliation.record.record_digest,
        scope_digest=scope_digest,
        intent_digest=intent_digest,
        proof=values,
    )
    return DeployScyllaConfigureProofDecision.from_object(values)


def _build_authorization(
    context: _AuthorizationContext,
    *,
    scopes: tuple[DeployScyllaConfigureAuthorizationScope, ...],
    proof: DeployScyllaConfigureProofDecision,
    created_at: str,
) -> DeployScyllaConfigureAuthorization:
    loaded = _loaded(context)
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    reconciliation = context.reconciliation.record
    install = context.install
    install_authorization = install.authorization.record
    install_execution = install.execution.record
    install_binding = install_execution.binding
    target_digests = tuple(scope.target_digest for scope in scopes)
    selected_sequences = {scope.sequence for scope in scopes}
    non_authorized = tuple(
        step for step in reconciliation.steps if step.sequence not in selected_sequences
    )
    validated_chain = {
        "install_authorization_artifact_digest": install.authorization.artifact_digest,
        "install_evidence_artifact_digest": install.evidence.artifact_digest,
        "install_execution_artifact_digest": install.execution.artifact_digest,
        "post_install_reconciliation_artifact_digest": (
            context.reconciliation.artifact_digest
        ),
        "post_install_reconciliation_record_digest": reconciliation.record_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "source_digest": loaded.source.digest,
    }
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": reconciliation.cluster_uuid,
        "cluster_identity_digest": _cluster_identity_digest(
            reconciliation.cluster_uuid, metadata.cluster_name
        ),
        "operation_id": reconciliation.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "scope_kind": _SCOPE_KIND,
        "request_digest": reconciliation.request_digest,
        "journal_generation": reconciliation.journal_generation,
        "journal_digest": reconciliation.journal_digest,
        "journal_status": reconciliation.journal_status,
        "journal_phase": reconciliation.journal_phase,
        "metadata_generation": deploy.metadata.record.generation,
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
        "catalog_digest": loaded.catalog_digest,
        "ansible_source_version": loaded.source.version,
        "ansible_source_digest": loaded.source.digest,
        "post_install_reconciliation_artifact_digest": (
            context.reconciliation.artifact_digest
        ),
        "post_install_reconciliation_record_digest": reconciliation.record_digest,
        "post_install_effective_plan_digest": reconciliation.effective_plan_digest,
        "install_authorization_artifact_digest": install.authorization.artifact_digest,
        "install_authorization_digest": install_authorization.authorization_digest,
        "install_authorization_proof_digest": (
            install_authorization.proof.proof_digest
        ),
        "install_execution_artifact_digest": install.execution.artifact_digest,
        "install_execution_binding_digest": install_binding.binding_digest,
        "install_evidence_artifact_digest": install.evidence.artifact_digest,
        "install_evidence_digest": reconciliation.evidence_digest,
        "validated_chain_digest": _digest_object(validated_chain),
        "classification": OperationClassification.MUTATING,
        "scopes": scopes,
        "target_count": len(scopes),
        "target_set_digest": _digest_object(list(target_digests)),
        "authorization_scope_digest": _digest_object(
            [scope.to_object() for scope in scopes]
        ),
        "configuration_intent_digest": _digest_object(
            [scope.configuration_intent_digest for scope in scopes]
        ),
        "non_authorized_blocker_digest": _digest_object(
            [
                {
                    "blockers": list(step.blockers),
                    "playbook": step.playbook,
                    "sequence": step.sequence,
                    "status": step.status.value,
                }
                for step in non_authorized
            ]
        ),
        "proof": proof,
        "authorization_state": _AUTHORIZED,
        "consumed": False,
        "execution_state": _EXECUTION_UNAVAILABLE,
        "finalization_state": _FINALIZATION_NOT_STARTED,
        "public_workflow_state": _PUBLIC_WORKFLOW_UNAVAILABLE,
        "authorization_digest": "",
    }
    if (
        deploy.journal.record.generation != reconciliation.journal_generation
        or deploy.journal.digest != reconciliation.journal_digest
        or loaded.catalog_digest != reconciliation.catalog_digest
        or loaded.source.digest != reconciliation.ansible_source_digest
        or deploy.metadata.digest != planning.readiness.record.metadata_digest
        or metadata.desired_spec.digest()
        != planning.readiness.record.desired_spec_digest
    ):
        raise StateConflictError(
            "deploy scylla-configure current metadata, desired state, plan, "
            "or source drifted"
        )
    values["authorization_digest"] = _authorization_digest_from_values(values)
    return DeployScyllaConfigureAuthorization(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployScyllaConfigureAuthorization,
    *,
    state: DeployScyllaConfigureAuthorizationArtifactState,
) -> DeployScyllaConfigureAuthorizationReport:
    record = stored.record
    scopes = record.scopes
    return DeployScyllaConfigureAuthorizationReport(
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
        target_count=record.target_count,
        target_set_digest=record.target_set_digest,
        authorization_scope_digest=record.authorization_scope_digest,
        configuration_intent_digest=record.configuration_intent_digest,
        seed_count=sum(scope.seed_count for scope in scopes),
        directory_count=sum(scope.directory_count for scope in scopes),
        rendered_file_count=sum(scope.rendered_file_count for scope in scopes),
        template_count=sum(scope.template_count for scope in scopes),
        template_source_digest=_digest_object(
            [scope.template_source_digest for scope in scopes]
        ),
        role_source_digest=_digest_object(
            [scope.role_source_digest for scope in scopes]
        ),
        package_version_digest=_digest_object(
            [scope.package_version_digest for scope in scopes]
        ),
        post_install_reconciliation_artifact_digest=(
            record.post_install_reconciliation_artifact_digest
        ),
        post_install_reconciliation_record_digest=(
            record.post_install_reconciliation_record_digest
        ),
        inventory_artifact_digest=record.inventory_artifact_digest,
        trust_artifact_digest=record.trust_artifact_digest,
        readiness_artifact_digest=record.readiness_artifact_digest,
        catalog_digest=record.catalog_digest,
        ansible_source_digest=record.ansible_source_digest,
        blockers_digest=record.non_authorized_blocker_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        journal_digest=record.journal_digest,
        consumed=record.consumed,
        execution_state=record.execution_state,
        finalization_state=record.finalization_state,
        public_workflow_state=record.public_workflow_state,
    )


def _loaded(context: _AuthorizationContext) -> _DeployReconciliationContext:
    return context.install.authorization_context.post.authorization_context.preflight.discovery.post.chain.authorization_context.final_routes.post.post.base.host.loaded


def _source_digests(
    source: AnsibleSourceBundle, paths: tuple[str, ...]
) -> dict[str, str]:
    available = {item.path: item.digest for item in source.files}
    if any(path not in available for path in paths):
        raise StateConflictError(
            "deploy scylla-configure packaged source binding is incomplete"
        )
    return {path: available[path] for path in paths}


def _scope_intent_digest(
    scope: DeployScyllaConfigureAuthorizationScope,
) -> str:
    return _scope_intent_digest_from_values(scope.to_object())


def _scope_intent_digest_from_values(values: Mapping[str, object]) -> str:
    value = dict(values)
    value["configuration_intent_digest"] = ""
    return _digest_object(value)


def _proof_digest(
    record: DeployScyllaConfigureAuthorization,
    proof: Mapping[str, object],
) -> str:
    return _proof_digest_values(
        cluster_uuid=record.cluster_uuid,
        operation_id=record.operation_id,
        request_digest=record.request_digest,
        journal_digest=record.journal_digest,
        reconciliation_artifact_digest=(
            record.post_install_reconciliation_artifact_digest
        ),
        reconciliation_record_digest=(record.post_install_reconciliation_record_digest),
        scope_digest=record.authorization_scope_digest,
        intent_digest=record.configuration_intent_digest,
        proof=proof,
    )


def _proof_digest_values(
    *,
    cluster_uuid: uuid.UUID,
    operation_id: uuid.UUID,
    request_digest: str,
    journal_digest: str,
    reconciliation_artifact_digest: str,
    reconciliation_record_digest: str,
    scope_digest: str,
    intent_digest: str,
    proof: Mapping[str, object],
) -> str:
    proof_value = dict(proof)
    proof_value["proof_digest"] = ""
    return _digest_object(
        {
            "authorization_scope_digest": scope_digest,
            "cluster_uuid": str(cluster_uuid),
            "configuration_intent_digest": intent_digest,
            "journal_digest": journal_digest,
            "operation": _OPERATION,
            "operation_id": str(operation_id),
            "proof": proof_value,
            "reconciliation_artifact_digest": reconciliation_artifact_digest,
            "reconciliation_record_digest": reconciliation_record_digest,
            "request_digest": request_digest,
            "schema_version": (
                ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION
            ),
            "stage": _STAGE,
        }
    )


def _authorization_digest(record: DeployScyllaConfigureAuthorization) -> str:
    return _authorization_digest_from_values(record.to_object())


def _authorization_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployScyllaConfigureAuthorization.__dataclass_fields__.items():
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
            else item.to_object()
            if name == "proof" and isinstance(item, DeployScyllaConfigureProofDecision)
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
        ".ansible-deploy-scylla-configure-execution.json",
        ".ansible-deploy-scylla-configure-evidence.json",
        ".ansible-deploy-post-scylla-configure-reconciliation.json",
        ".ansible-deploy-scylla-bootstrap",
        ".ansible-deploy-scylla-health",
        ".ansible-deploy-manager-agent",
        ".ansible-deploy-monitoring-agent",
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy scylla-configure operation history"
        ) from error
    prefix = str(operation_id)
    for entry in entries:
        if entry.name.startswith(prefix) and any(
            fragment in entry.name for fragment in forbidden_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy scylla-configure authorization refuses execution "
                "or later-stage history"
            )


def _refuse_ambiguous_authorization_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy scylla-configure authorization history"
        ) from error
    canonical = str(operation_id)
    suffix = DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_FILENAME_SUFFIX
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
                "deploy scylla-configure authorization artifacts are ambiguous"
            )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy scylla-configure authorization paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy scylla-configure authorization requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _digest_fields(value: object) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(value, name))
        for name in value.__dataclass_fields__  # type: ignore[attr-defined]
        if name.endswith("_digest")
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


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise StatePersistenceError(f"{label} must be an array")
    return value


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _enum(enum_type: type[StrEnum], value: str, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except ValueError as error:
        raise StatePersistenceError(
            f"deploy scylla-configure authorization {label} is invalid"
        ) from error


__all__ = [
    "ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION",
    "DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_FILENAME_SUFFIX",
    "DeployScyllaConfigureApprovalMethod",
    "DeployScyllaConfigureArchitecture",
    "DeployScyllaConfigureAuthorization",
    "DeployScyllaConfigureAuthorizationArtifactState",
    "DeployScyllaConfigureAuthorizationProof",
    "DeployScyllaConfigureAuthorizationReport",
    "DeployScyllaConfigureAuthorizationScope",
    "DeployScyllaConfigureAuthorizationStore",
    "DeployScyllaConfigureProofDecision",
    "DeployScyllaConfigureSeedPolicy",
    "DeployScyllaConfigureServicePolicy",
    "StoredDeployScyllaConfigureAuthorization",
    "authorize_deploy_scylla_configure",
    "deploy_scylla_configure_authorization_id_from_filename",
    "deploy_scylla_configure_authorization_path",
]
