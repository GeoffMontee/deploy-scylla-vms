"""Immutable authorization for Manager local-backend package installation.

This internal owner revalidates the exact local-one-node backend planning
chain, derives the package-only Manager intent, and persists an unconsumed
ordinary approval checkpoint. It does not invoke Ansible, mutate a host, or
advance the common operation journal.
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
from scylla_vms.ansible.deploy_manager_backend_installation_plan import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_SCHEMA_VERSION,
    DeployManagerBackendInstallationArtifactState,
    DeployManagerBackendInstallationContextStore,
    DeployManagerBackendInstallationPlanStatus,
    DeployManagerBackendInstallationPlanStore,
    DeployManagerBackendInstallationSourceState,
    DeployManagerBackendInstallationStorageState,
    StoredDeployManagerBackendInstallationContext,
    StoredDeployManagerBackendInstallationPlan,
    _InstallationPlanningContext,
    _load_installation_planning_context,
    deploy_manager_backend_installation_context_path,
    deploy_manager_backend_installation_plan_path,
    plan_deploy_manager_backend_local_installation,
)
from scylla_vms.ansible.deploy_manager_backend_preflight_execution import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION,
)
from scylla_vms.ansible.deploy_manager_backend_preflight_reconciliation import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION,
)
from scylla_vms.ansible.deploy_plan import _digest_object, _require_operation_id
from scylla_vms.ansible.manager_backend_local_install import (
    MANAGER_BACKEND_LOCAL_INSTALL_PLAYBOOK,
    MANAGER_BACKEND_LOCAL_INSTALL_SCHEMA_VERSION,
    build_manager_backend_local_install_payload,
)
from scylla_vms.ansible.operation_authorization import (
    OPERATION_AUTHORIZATION_FILENAME_SUFFIX,
)
from scylla_vms.ansible.orchestration import ansible_operation_catalog_digest
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_install import (
    SCYLLA_CHANNEL,
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_PACKAGES,
    SCYLLA_RELEASE_LINE,
    SCYLLA_REPOSITORY_DEFINITION_DIGEST,
    SCYLLA_SIGNING_KEY_DIGEST,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
    SCYLLA_SIGNING_KEY_UID,
    SCYLLA_SIGNING_SUBKEY_FINGERPRINT,
    load_scylla_signing_key,
    validate_scylla_signing_key,
)
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

ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-local-install-"
    "authorization-proof/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCOPE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-local-install-"
    "authorization-scope/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_PACKAGE_PROVENANCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-local-install-"
    "package-provenance/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-local-install-authorization/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-local-install-"
    "authorization-report/v1"
)

DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-local-install-authorization.json"
)

_OPERATION = "deploy"
_PLAYBOOK = MANAGER_BACKEND_LOCAL_INSTALL_PLAYBOOK
_TARGET_ROLE = HostRole.MANAGER.value
_STAGE = "manager-backend-local-package-install"
_SCOPE_KIND = "local-one-node-manager-package-install"
_AUTHORIZED = "authorized-pre-execution"
_EXECUTION_UNAVAILABLE = "unavailable"
_FINALIZATION_NOT_STARTED = "not-started"
_PUBLIC_WORKFLOW_UNAVAILABLE = "unavailable"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_EXPECTED_STEP_BLOCKERS = (
    "deploy-authorization-not-collected",
    "mutating-deploy-execution-unavailable",
    "public-deploy-workflow-unavailable",
)


class DeployManagerBackendLocalInstallApprovalMethod(StrEnum):
    """PLAN-permitted ordinary approval methods."""

    INTERACTIVE = "interactive"
    CLI_YES = "cli-yes"


class DeployManagerBackendLocalInstallArchitecture(StrEnum):
    """Closed OCI image architecture policy."""

    AMD64 = "amd64"
    AARCH64 = "aarch64"


class DeployManagerBackendLocalInstallPackagePolicy(StrEnum):
    """The only mutation authorized by this slice."""

    PACKAGE_ONLY = "package-only"


class DeployManagerBackendLocalInstallServicePolicy(StrEnum):
    """Required local Scylla state after package installation."""

    MASKED_INACTIVE = "masked-inactive"


class DeployManagerBackendLocalInstallAuthorizationArtifactState(StrEnum):
    """Immutable authorization persistence result."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployManagerBackendLocalInstallAuthorizationProof:
    """Already-normalized ordinary approval without caller-owned scope."""

    approval_method: DeployManagerBackendLocalInstallApprovalMethod | None = None
    approved: bool = False
    allow_destructive: bool = False
    destructive_scope_provided: bool = False
    narrow_consent_provided: bool = False

    def __post_init__(self) -> None:
        if self.approval_method is not None and not isinstance(
            self.approval_method,
            DeployManagerBackendLocalInstallApprovalMethod,
        ):
            raise StateConflictError(
                "deploy Manager backend local install approval method is invalid"
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
                "deploy Manager backend local install authorization proof is malformed"
            )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendLocalInstallProofDecision:
    """Persisted ordinary proof bound to one exact package-install scope."""

    approval_method: DeployManagerBackendLocalInstallApprovalMethod
    approved: bool
    allow_destructive: bool
    destructive_scope_provided: bool
    narrow_consent_provided: bool
    proof_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or not isinstance(
                self.approval_method,
                DeployManagerBackendLocalInstallApprovalMethod,
            )
            or self.approved is not True
            or self.allow_destructive
            or self.destructive_scope_provided
            or self.narrow_consent_provided
        ):
            raise StatePersistenceError(
                "deploy Manager backend local install authorization proof conflicts"
            )
        validate_digest(
            self.proof_digest,
            "deploy Manager backend local install proof digest",
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
        cls,
        value: Mapping[str, object],
    ) -> DeployManagerBackendLocalInstallProofDecision:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend local install proof",
        )
        try:
            method = DeployManagerBackendLocalInstallApprovalMethod(
                require_string(value, "approval_method")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Manager backend local install approval method is invalid"
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
class DeployManagerBackendLocalInstallPackageProvenance:
    """URL- and key-material-free identity of the exact package contract."""

    release_line: str
    channel: str
    package_version_digest: str
    package_count: int
    package_set_digest: str
    repository_definition_digest: str
    signing_key_artifact_digest: str
    signing_key_identity_digest: str
    catalog_entry_digest: str
    source_digest: str
    playbook_source_digest: str
    provenance_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_PACKAGE_PROVENANCE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_PACKAGE_PROVENANCE_SCHEMA_VERSION
            or self.release_line != SCYLLA_RELEASE_LINE
            or self.channel != SCYLLA_CHANNEL
            or self.package_version_digest != _digest_object(SCYLLA_PACKAGE_VERSION)
            or self.package_count != len(SCYLLA_PACKAGES)
            or self.package_set_digest != _digest_object(list(SCYLLA_PACKAGES))
            or self.repository_definition_digest != SCYLLA_REPOSITORY_DEFINITION_DIGEST
            or self.signing_key_artifact_digest != SCYLLA_SIGNING_KEY_DIGEST
            or self.signing_key_identity_digest != _signing_key_identity_digest()
            or self.provenance_digest != _package_provenance_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Manager backend local install package provenance conflicts"
            )
        _positive_integer(self.package_count, "package count")
        for digest in _digest_fields(self):
            validate_digest(
                digest,
                "deploy Manager backend local install package provenance digest",
            )

    def to_object(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_object(
        cls,
        value: Mapping[str, object],
    ) -> DeployManagerBackendLocalInstallPackageProvenance:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend local install package provenance",
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
            source_digest=require_string(value, "source_digest"),
            playbook_source_digest=require_string(value, "playbook_source_digest"),
            provenance_digest=require_string(value, "provenance_digest"),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendLocalInstallAuthorizationScope:
    """One exact redacted package-only Manager backend install intent."""

    step_sequence: int
    boundary: str
    playbook: str
    classification: OperationClassification
    target_role: str
    target_stable_id: str
    target_digest: str
    architecture: DeployManagerBackendLocalInstallArchitecture
    image_policy_digest: str
    package_policy: DeployManagerBackendLocalInstallPackagePolicy
    service_policy: DeployManagerBackendLocalInstallServicePolicy
    package_install_permitted: bool
    setup_permitted: bool
    storage_mutation_permitted: bool
    tuning_permitted: bool
    configuration_permitted: bool
    schema_permitted: bool
    manager_actions_permitted: bool
    service_start_permitted: bool
    variables_digest: str
    source_digest: str
    playbook_source_digest: str
    command_digest: str
    command_policy_digest: str
    package_reference_digest: str
    storage_decision_digest: str
    preflight_reconciliation_digest: str
    base_os_evidence_digest: str
    manager_server_evidence_digest: str
    plan_step_digest: str
    package_provenance_digest: str
    install_intent_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCOPE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        prohibited = (
            self.setup_permitted,
            self.storage_mutation_permitted,
            self.tuning_permitted,
            self.configuration_permitted,
            self.schema_permitted,
            self.manager_actions_permitted,
            self.service_start_permitted,
        )
        definition = get_playbook(self.playbook)
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCOPE_SCHEMA_VERSION
            or self.step_sequence != 1
            or self.boundary != "package-install"
            or self.playbook != _PLAYBOOK
            or self.classification is not OperationClassification.MUTATING
            or definition.classification is not self.classification
            or self.target_role != _TARGET_ROLE
            or not self.target_stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
            or self.target_digest != _digest_object([self.target_stable_id])
            or not isinstance(
                self.architecture,
                DeployManagerBackendLocalInstallArchitecture,
            )
            or self.package_policy
            is not DeployManagerBackendLocalInstallPackagePolicy.PACKAGE_ONLY
            or self.service_policy
            is not DeployManagerBackendLocalInstallServicePolicy.MASKED_INACTIVE
            or self.package_install_permitted is not True
            or any(prohibited)
            or self.install_intent_digest != _scope_intent_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Manager backend local install authorization scope conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(
                digest,
                "deploy Manager backend local install authorization scope digest",
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
        cls,
        value: Mapping[str, object],
    ) -> DeployManagerBackendLocalInstallAuthorizationScope:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend local install authorization scope",
        )
        boolean_fields = {
            "package_install_permitted",
            "setup_permitted",
            "storage_mutation_permitted",
            "tuning_permitted",
            "configuration_permitted",
            "schema_permitted",
            "manager_actions_permitted",
            "service_start_permitted",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name == "step_sequence":
                    parsed[name] = _integer(item, name)
                elif name == "classification":
                    parsed[name] = OperationClassification(require_string(value, name))
                elif name == "architecture":
                    parsed[name] = DeployManagerBackendLocalInstallArchitecture(
                        require_string(value, name)
                    )
                elif name == "package_policy":
                    parsed[name] = DeployManagerBackendLocalInstallPackagePolicy(
                        require_string(value, name)
                    )
                elif name == "service_policy":
                    parsed[name] = DeployManagerBackendLocalInstallServicePolicy(
                        require_string(value, name)
                    )
                elif name in boolean_fields:
                    parsed[name] = _boolean(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Manager backend local install authorization scope enum "
                "is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployManagerBackendLocalInstallAuthorization:
    """Immutable unconsumed authorization for one exact package install."""

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
    catalog_digest: str
    ansible_source_digest: str
    classification: OperationClassification
    scope: DeployManagerBackendLocalInstallAuthorizationScope
    target_count: int
    target_set_digest: str
    authorization_scope_digest: str
    package_provenance: DeployManagerBackendLocalInstallPackageProvenance
    proof: DeployManagerBackendLocalInstallProofDecision
    authorization_state: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_digest: str
    installation_context_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_SCHEMA_VERSION
    )
    installation_plan_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_SCHEMA_VERSION
    )
    preflight_execution_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION
    )
    preflight_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    )
    preflight_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCHEMA_VERSION
            or self.installation_context_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_SCHEMA_VERSION
            or self.installation_plan_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_SCHEMA_VERSION
            or self.preflight_execution_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION
            or self.preflight_evidence_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
            or self.preflight_reconciliation_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.classification is not OperationClassification.MUTATING
            or self.target_count != 1
            or self.target_set_digest != self.scope.target_digest
            or self.authorization_scope_digest != _digest_object(self.scope.to_object())
            or self.scope.package_provenance_digest
            != self.package_provenance.provenance_digest
            or self.authorization_state != _AUTHORIZED
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError(
                "deploy Manager backend local install authorization conflicts"
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
                count,
                "deploy Manager backend local install authorization count",
            )
        for digest in _digest_fields(self):
            validate_digest(
                digest,
                "deploy Manager backend local install authorization digest",
            )
        if self.proof.proof_digest != _proof_digest(self, self.proof.to_object()):
            raise StatePersistenceError(
                "deploy Manager backend local install proof digest conflicts"
            )
        if self.authorization_digest != _authorization_digest(self):
            raise StatePersistenceError(
                "deploy Manager backend local install authorization digest conflicts"
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
                    value,
                    (JournalStatus, OperationPhase, OperationClassification),
                )
                else value.to_object()
                if name in {"scope", "package_provenance", "proof"}
                else value
            )
        return result

    @classmethod
    def from_object(
        cls,
        value: Mapping[str, object],
    ) -> DeployManagerBackendLocalInstallAuthorization:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Manager backend local install authorization",
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
                        DeployManagerBackendLocalInstallAuthorizationScope.from_object(
                            _mapping(item, "authorization scope")
                        )
                    )
                elif name == "package_provenance":
                    parsed[name] = (
                        DeployManagerBackendLocalInstallPackageProvenance.from_object(
                            _mapping(item, "package provenance")
                        )
                    )
                elif name == "proof":
                    parsed[name] = (
                        DeployManagerBackendLocalInstallProofDecision.from_object(
                            _mapping(item, "authorization proof")
                        )
                    )
                elif name == "consumed":
                    parsed[name] = _boolean(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Manager backend local install authorization enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendLocalInstallAuthorization:
    record: DeployManagerBackendLocalInstallAuthorization
    artifact_digest: str


class DeployManagerBackendLocalInstallAuthorizationStore:
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
        self._path = deploy_manager_backend_local_install_authorization_path(
            paths, operation_id
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
    ) -> StoredDeployManagerBackendLocalInstallAuthorization:
        value, artifact_digest = self._file.read()
        record = DeployManagerBackendLocalInstallAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_identity_digest
            != _cluster_identity_digest(expected_cluster_uuid, expected_cluster_name)
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "deploy Manager backend local install authorization identity conflicts"
            )
        return StoredDeployManagerBackendLocalInstallAuthorization(
            record,
            artifact_digest,
        )

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendLocalInstallAuthorization:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerBackendLocalInstallAuthorization,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerBackendLocalInstallAuthorization,
        DeployManagerBackendLocalInstallAuthorizationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy Manager backend local install authorization operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=self._paths.cluster_root.name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy Manager backend local install authorization is immutable; "
                    "use a new operation"
                )
            return (
                current,
                DeployManagerBackendLocalInstallAuthorizationArtifactState.REUSED,
            )
        artifact_digest = self._file.write(
            record.to_object(),
            expected_digest=None,
        )
        return (
            StoredDeployManagerBackendLocalInstallAuthorization(
                record,
                artifact_digest,
            ),
            DeployManagerBackendLocalInstallAuthorizationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendLocalInstallAuthorizationReport:
    """Strict redacted authorization report without executable inputs."""

    operation_id: uuid.UUID
    artifact_state: DeployManagerBackendLocalInstallAuthorizationArtifactState
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_state: str
    stage: str
    scope_kind: str
    approval_method: DeployManagerBackendLocalInstallApprovalMethod
    approval_state: str
    proof_digest: str
    classification: OperationClassification
    playbook: str
    target_stable_id: str
    target_count: int
    target_set_digest: str
    authorization_scope_digest: str
    architecture: DeployManagerBackendLocalInstallArchitecture
    release_line: str
    package_count: int
    package_version_digest: str
    package_set_digest: str
    package_provenance_digest: str
    package_policy: DeployManagerBackendLocalInstallPackagePolicy
    service_policy: DeployManagerBackendLocalInstallServicePolicy
    prohibited_action_count: int
    installation_context_artifact_digest: str
    installation_context_record_digest: str
    installation_plan_artifact_digest: str
    installation_plan_digest: str
    preflight_reconciliation_artifact_digest: str
    preflight_reconciliation_record_digest: str
    base_os_evidence_digest: str
    manager_server_evidence_digest: str
    observation_artifact_digest: str
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
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCHEMA_VERSION
    )
    proof_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or self.authorization_state != _AUTHORIZED
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.approval_state != "approved"
            or self.classification is not OperationClassification.MUTATING
            or self.playbook != _PLAYBOOK
            or self.target_count != 1
            or self.release_line != SCYLLA_RELEASE_LINE
            or self.package_count != len(SCYLLA_PACKAGES)
            or self.package_policy
            is not DeployManagerBackendLocalInstallPackagePolicy.PACKAGE_ONLY
            or self.service_policy
            is not DeployManagerBackendLocalInstallServicePolicy.MASKED_INACTIVE
            or self.prohibited_action_count
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError(
                "deploy Manager backend local install authorization report conflicts"
            )
        if (
            not self.target_stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
        ):
            raise StatePersistenceError(
                "deploy Manager backend local install report target is invalid"
            )
        for digest in _digest_fields(self):
            validate_digest(
                digest,
                "deploy Manager backend local install authorization report digest",
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
                "policy": self.package_policy.value,
                "provenance_digest": self.package_provenance_digest,
                "release_line": self.release_line,
                "service": self.service_policy.value,
            },
            "policy": {
                "architecture": self.architecture.value,
                "prohibited_action_count": self.prohibited_action_count,
            },
            "provenance": {
                "ansible_source_digest": self.ansible_source_digest,
                "base_os_evidence_digest": self.base_os_evidence_digest,
                "catalog_digest": self.catalog_digest,
                "installation": {
                    "context_artifact_digest": (
                        self.installation_context_artifact_digest
                    ),
                    "context_record_digest": self.installation_context_record_digest,
                    "plan_artifact_digest": self.installation_plan_artifact_digest,
                    "plan_digest": self.installation_plan_digest,
                },
                "inventory_artifact_digest": self.inventory_artifact_digest,
                "manager_server_evidence_digest": (self.manager_server_evidence_digest),
                "observation_artifact_digest": self.observation_artifact_digest,
                "preflight": {
                    "reconciliation_artifact_digest": (
                        self.preflight_reconciliation_artifact_digest
                    ),
                    "reconciliation_record_digest": (
                        self.preflight_reconciliation_record_digest
                    ),
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
    planning: _InstallationPlanningContext
    installation_context: StoredDeployManagerBackendInstallationContext
    installation_plan: StoredDeployManagerBackendInstallationPlan


def authorize_deploy_manager_backend_local_install(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proof: DeployManagerBackendLocalInstallAuthorizationProof,
) -> DeployManagerBackendLocalInstallAuthorizationReport:
    """Authorize the exact Manager backend package-install boundary."""

    if not isinstance(
        proof,
        DeployManagerBackendLocalInstallAuthorizationProof,
    ):
        raise StateConflictError(
            "deploy Manager backend local install authorization proof is malformed"
        )
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_authorization_artifacts(paths, operation_id)
    _refuse_incompatible_or_later_artifacts(paths, operation_id)
    context = _load_authorization_context(paths, operation_id, lock=lock)
    metadata = context.planning.execution_context.metadata
    payload = _build_payload(context)
    package_provenance = _derive_package_provenance(context, payload)
    scope = _derive_authorization_scope(context, payload, package_provenance)
    scope_digest = _digest_object(scope.to_object())
    decision = _normalize_proof(
        proof,
        context=context,
        scope_digest=scope_digest,
        package_provenance_digest=package_provenance.provenance_digest,
    )
    store = DeployManagerBackendLocalInstallAuthorizationStore(paths, operation_id)
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
            package_provenance=package_provenance,
            proof=decision,
            created_at=stored.record.created_at,
        )
        if stored.record != expected:
            raise StateConflictError(
                "deploy Manager backend local install authorization changed; "
                "re-plan with a new operation"
            )
        state = DeployManagerBackendLocalInstallAuthorizationArtifactState.REUSED
    else:
        record = _build_authorization(
            context,
            scope=scope,
            package_provenance=package_provenance,
            proof=decision,
            created_at=format_timestamp(datetime.now(UTC)),
        )
        try:
            stored, state = store.write_locked(record, lock=lock)
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy Manager backend local install authorization persistence failed"
            ) from error
    return _build_report(stored, state=state)


def deploy_manager_backend_local_install_authorization_path(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> Path:
    """Return the canonical operation-bound authorization path."""

    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}"
        f"{DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Manager backend local install authorization path is not canonical"
        )
    return path


def deploy_manager_backend_local_install_authorization_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    suffix = DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_FILENAME_SUFFIX
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
    context_path = deploy_manager_backend_installation_context_path(paths, operation_id)
    plan_path = deploy_manager_backend_installation_plan_path(paths, operation_id)
    for path, label in (
        (context_path, "installation context"),
        (plan_path, "installation plan"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                "deploy Manager backend local install authorization requires "
                f"the exact {label}"
            )
    report = plan_deploy_manager_backend_local_installation(
        state_root=paths.state_root,
        cluster_name=paths.cluster_root.name,
        operation_id=operation_id,
        lock=lock,
    )
    if (
        report.context_state is not DeployManagerBackendInstallationArtifactState.REUSED
        or report.plan_state is not DeployManagerBackendInstallationArtifactState.REUSED
    ):
        raise StateConflictError(
            "deploy Manager backend local install authorization requires prior "
            "immutable planning records"
        )
    planning = _load_installation_planning_context(paths, operation_id, lock=lock)
    metadata = planning.execution_context.metadata
    context = DeployManagerBackendInstallationContextStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    plan = DeployManagerBackendInstallationPlanStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    if (
        context.artifact_digest != report.context_artifact_digest
        or context.record.record_digest != report.context_record_digest
        or plan.artifact_digest != report.plan_artifact_digest
        or plan.record.plan_digest != report.plan_digest
    ):
        raise StateConflictError(
            "deploy Manager backend local install planning provenance drifted"
        )
    return _AuthorizationContext(planning, context, plan)


def _build_payload(context: _AuthorizationContext) -> dict[str, object]:
    execution = context.planning.execution_context
    return build_manager_backend_local_install_payload(
        execution.metadata,
        execution.observation,
        execution.inventory,
        execution.readiness,
        execution.scope.base_os,
        execution.scope.manager_server,
        context.planning.preflight_reconciliation,
        context.installation_context,
        context.installation_plan,
        logical_id=execution.scope.target_stable_id,
        image_filter=execution.scope.image_filter,
        architecture=execution.scope.architecture,
    )


def _derive_package_provenance(
    context: _AuthorizationContext,
    payload: Mapping[str, object],
) -> DeployManagerBackendLocalInstallPackageProvenance:
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
            "result_schema_version": MANAGER_BACKEND_LOCAL_INSTALL_SCHEMA_VERSION,
            "serial": definition.serial,
            "source_available": definition.source_available,
            "tags": list(definition.tags),
            "variable_names": [item.name for item in definition.variables],
        }
    )
    plan_step = context.installation_plan.record.steps[0]
    source_digest = _digest_value(payload, "source_digest")
    if (
        plan_step.source_digest is None
        or context.installation_context.record.catalog_digest
        != ansible_operation_catalog_digest()
    ):
        raise StateConflictError(
            "deploy Manager backend local install package source drifted"
        )
    values: dict[str, object] = {
        "release_line": SCYLLA_RELEASE_LINE,
        "channel": SCYLLA_CHANNEL,
        "package_version_digest": _digest_object(SCYLLA_PACKAGE_VERSION),
        "package_count": len(SCYLLA_PACKAGES),
        "package_set_digest": _digest_object(list(SCYLLA_PACKAGES)),
        "repository_definition_digest": SCYLLA_REPOSITORY_DEFINITION_DIGEST,
        "signing_key_artifact_digest": SCYLLA_SIGNING_KEY_DIGEST,
        "signing_key_identity_digest": _signing_key_identity_digest(),
        "catalog_entry_digest": catalog_entry_digest,
        "source_digest": source_digest,
        "playbook_source_digest": plan_step.source_digest,
        "provenance_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_PACKAGE_PROVENANCE_SCHEMA_VERSION
        ),
    }
    values["provenance_digest"] = _package_provenance_digest_from_values(values)
    return DeployManagerBackendLocalInstallPackageProvenance(**values)  # type: ignore[arg-type]


def _derive_authorization_scope(
    context: _AuthorizationContext,
    payload: Mapping[str, object],
    package: DeployManagerBackendLocalInstallPackageProvenance,
) -> DeployManagerBackendLocalInstallAuthorizationScope:
    planning = context.planning
    execution = planning.execution_context
    installation = context.installation_context.record
    plan = context.installation_plan.record
    if len(plan.steps) != 9:
        raise StateConflictError(
            "deploy Manager backend local install plan step set is ambiguous"
        )
    step = plan.steps[0]
    definition = get_playbook(_PLAYBOOK)
    image_filter = execution.scope.image_filter
    target = execution.scope.target_stable_id
    if (
        installation.manager_target_id != target
        or installation.manager_target_digest != _digest_object([target])
        or installation.operating_system != "Ubuntu"
        or installation.operating_system_version != "24.04"
        or installation.architecture != execution.scope.architecture
        or image_filter != ImageFilter("Ubuntu", "24.04", ImageVersionMatch.EXACT)
        or installation.manager_service_state != "masked-inactive"
        or installation.local_scylla_package_state != "not-installed"
        or installation.local_scylla_service_state != "absent"
        or installation.storage_decision.state
        is not DeployManagerBackendInstallationStorageState.IDENTIFIED
        or not installation.storage_decision.dedicated_volume_identified
        or installation.storage_decision.volume_identity_digest is None
        or installation.storage_decision.root_fallback_policy != "forbidden"
        or installation.storage_decision.generic_root_capacity_accepted
        or plan.authorization_state != "package-install-authorization-required"
        or step.sequence != 1
        or step.boundary != "package-install"
        or step.classification is not OperationClassification.MUTATING
        or step.target_ids != (target,)
        or step.source_state
        is not DeployManagerBackendInstallationSourceState.AVAILABLE
        or step.source_digest != package.playbook_source_digest
        or step.source_contract_state != "manager-backend-local-install-v1"
        or step.authorization_requirement != "ordinary-approval-required"
        or step.performance_state != "not-performed"
        or step.status
        is not DeployManagerBackendInstallationPlanStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        or step.blockers != _EXPECTED_STEP_BLOCKERS
        or definition.classification is not OperationClassification.MUTATING
        or definition.hosts != _TARGET_ROLE
        or definition.serial != 1
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.check_mode is not CheckMode.PREVIEW
        or not definition.any_errors_fatal
        or not definition.source_available
    ):
        raise StateConflictError(
            "only the exact evidence-ready Manager backend package-install "
            "step may be authorized"
        )
    variables = definition.validate_variables(
        {"deploy_scylla_vms_manager_backend_local_install": dict(payload)}
    )
    variables_digest = digest_bytes(serialize_json(variables))
    command_digest = ansible_command_intent_digest(
        definition,
        step_sequence=step.sequence,
        limit=(target,),
        variables_digest=variables_digest,
        tags=definition.tags,
        check=False,
        diff=False,
        verbosity=0,
    )
    values: dict[str, object] = {
        "step_sequence": step.sequence,
        "boundary": step.boundary,
        "playbook": _PLAYBOOK,
        "classification": OperationClassification.MUTATING,
        "target_role": _TARGET_ROLE,
        "target_stable_id": target,
        "target_digest": step.target_set_digest,
        "architecture": DeployManagerBackendLocalInstallArchitecture(
            execution.scope.architecture
        ),
        "image_policy_digest": _digest_object(image_filter.to_object()),
        "package_policy": DeployManagerBackendLocalInstallPackagePolicy.PACKAGE_ONLY,
        "service_policy": (
            DeployManagerBackendLocalInstallServicePolicy.MASKED_INACTIVE
        ),
        "package_install_permitted": True,
        "setup_permitted": False,
        "storage_mutation_permitted": False,
        "tuning_permitted": False,
        "configuration_permitted": False,
        "schema_permitted": False,
        "manager_actions_permitted": False,
        "service_start_permitted": False,
        "variables_digest": variables_digest,
        "source_digest": package.source_digest,
        "playbook_source_digest": package.playbook_source_digest,
        "command_digest": command_digest,
        "command_policy_digest": _digest_value(payload, "command_policy_digest"),
        "package_reference_digest": installation.package_reference.reference_digest,
        "storage_decision_digest": installation.storage_decision.decision_digest,
        "preflight_reconciliation_digest": (
            planning.preflight_reconciliation.record.record_digest
        ),
        "base_os_evidence_digest": installation.base_os_evidence_digest,
        "manager_server_evidence_digest": (installation.manager_server_evidence_digest),
        "plan_step_digest": step.step_digest,
        "package_provenance_digest": package.provenance_digest,
        "install_intent_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCOPE_SCHEMA_VERSION
        ),
    }
    values["install_intent_digest"] = _scope_intent_digest_from_values(values)
    return DeployManagerBackendLocalInstallAuthorizationScope(**values)  # type: ignore[arg-type]


def _normalize_proof(
    proof: DeployManagerBackendLocalInstallAuthorizationProof,
    *,
    context: _AuthorizationContext,
    scope_digest: str,
    package_provenance_digest: str,
) -> DeployManagerBackendLocalInstallProofDecision:
    if proof.approval_method is None:
        raise StateConflictError(
            "ordinary deploy Manager backend local install approval is required"
        )
    if not proof.approved:
        raise StateConflictError(
            "ordinary deploy Manager backend local install approval was denied"
        )
    if (
        proof.allow_destructive
        or proof.destructive_scope_provided
        or proof.narrow_consent_provided
    ):
        raise StateConflictError(
            "destructive and narrow proofs are inapplicable to mutating "
            "Manager backend local install authorization"
        )
    installation = context.installation_plan
    values: dict[str, object] = {
        "allow_destructive": False,
        "approval_method": proof.approval_method.value,
        "approved": True,
        "destructive_scope_provided": False,
        "narrow_consent_provided": False,
        "proof_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION
        ),
    }
    values["proof_digest"] = _proof_digest_values(
        cluster_uuid=installation.record.cluster_uuid,
        operation_id=installation.record.operation_id,
        request_digest=installation.record.request_digest,
        journal_digest=installation.record.journal_digest,
        installation_plan_artifact_digest=installation.artifact_digest,
        installation_plan_digest=installation.record.plan_digest,
        scope_digest=scope_digest,
        package_provenance_digest=package_provenance_digest,
        proof=values,
    )
    return DeployManagerBackendLocalInstallProofDecision.from_object(values)


def _build_authorization(
    context: _AuthorizationContext,
    *,
    scope: DeployManagerBackendLocalInstallAuthorizationScope,
    package_provenance: DeployManagerBackendLocalInstallPackageProvenance,
    proof: DeployManagerBackendLocalInstallProofDecision,
    created_at: str,
) -> DeployManagerBackendLocalInstallAuthorization:
    planning = context.planning
    execution = planning.execution_context
    binding = execution.binding
    metadata = execution.metadata
    installation_context = context.installation_context
    installation_plan = context.installation_plan
    preflight = planning.preflight_reconciliation
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_identity_digest": _cluster_identity_digest(
            metadata.cluster_uuid,
            metadata.cluster_name,
        ),
        "operation_id": binding.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "scope_kind": _SCOPE_KIND,
        "request_digest": binding.request_digest,
        "journal_generation": binding.journal_generation,
        "journal_digest": binding.journal_digest,
        "journal_status": binding.journal_status,
        "journal_phase": binding.journal_phase,
        "metadata_generation": binding.metadata_generation,
        "metadata_artifact_digest": binding.metadata_artifact_digest,
        "desired_spec_digest": binding.desired_spec_digest,
        "observation_generation": binding.observation_generation,
        "observation_artifact_digest": binding.observation_artifact_digest,
        "observation_manifest_digest": binding.observation_manifest_digest,
        "inventory_generation": binding.inventory_generation,
        "inventory_artifact_digest": binding.inventory_artifact_digest,
        "inventory_digest": binding.inventory_digest,
        "trust_generation": binding.trust_generation,
        "trust_artifact_digest": binding.trust_artifact_digest,
        "trust_entries_digest": binding.trust_entries_digest,
        "readiness_artifact_digest": binding.readiness_artifact_digest,
        "readiness_record_digest": binding.readiness_record_digest,
        "backend_context_artifact_digest": binding.backend_context_artifact_digest,
        "backend_context_record_digest": binding.backend_context_record_digest,
        "backend_plan_artifact_digest": binding.backend_plan_artifact_digest,
        "backend_plan_digest": binding.backend_plan_digest,
        "preflight_execution_artifact_digest": (
            preflight.record.execution_artifact_digest
        ),
        "preflight_execution_binding_digest": (
            preflight.record.execution_binding_digest
        ),
        "preflight_evidence_artifact_digest": (
            preflight.record.evidence_artifact_digest
        ),
        "preflight_evidence_digest": preflight.record.evidence_digest,
        "preflight_reconciliation_artifact_digest": preflight.artifact_digest,
        "preflight_reconciliation_record_digest": preflight.record.record_digest,
        "installation_context_artifact_digest": installation_context.artifact_digest,
        "installation_context_record_digest": (
            installation_context.record.record_digest
        ),
        "installation_plan_artifact_digest": installation_plan.artifact_digest,
        "installation_plan_digest": installation_plan.record.plan_digest,
        "base_os_evidence_artifact_digest": (binding.base_os_evidence_artifact_digest),
        "base_os_evidence_digest": binding.base_os_evidence_digest,
        "manager_server_evidence_artifact_digest": (
            binding.manager_server_evidence_artifact_digest
        ),
        "manager_server_evidence_digest": binding.manager_server_evidence_digest,
        "manager_server_provenance_digest": (binding.manager_server_provenance_digest),
        "catalog_digest": binding.catalog_digest,
        "ansible_source_digest": binding.source_digest,
        "classification": OperationClassification.MUTATING,
        "scope": scope,
        "target_count": 1,
        "target_set_digest": scope.target_digest,
        "authorization_scope_digest": _digest_object(scope.to_object()),
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
        binding.journal_status is not JournalStatus.IN_PROGRESS
        or binding.journal_phase is not OperationPhase.VERIFY
        or installation_context.record.journal_digest != binding.journal_digest
        or installation_plan.record.journal_digest != binding.journal_digest
        or installation_context.record.catalog_digest != binding.catalog_digest
        or installation_context.record.ansible_source_digest != binding.source_digest
        or execution.inventory.digest != binding.inventory_artifact_digest
        or cast(str, execution.readiness.trust_digest) != binding.trust_artifact_digest
        or scope.base_os_evidence_digest != binding.base_os_evidence_digest
        or scope.manager_server_evidence_digest
        != binding.manager_server_evidence_digest
    ):
        raise StateConflictError(
            "deploy Manager backend local install journal, inventory, trust, "
            "evidence, catalog, or source binding drifted"
        )
    values["authorization_digest"] = _authorization_digest_from_values(values)
    return DeployManagerBackendLocalInstallAuthorization(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployManagerBackendLocalInstallAuthorization,
    *,
    state: DeployManagerBackendLocalInstallAuthorizationArtifactState,
) -> DeployManagerBackendLocalInstallAuthorizationReport:
    record = stored.record
    scope = record.scope
    package = record.package_provenance
    prohibited = (
        scope.setup_permitted,
        scope.storage_mutation_permitted,
        scope.tuning_permitted,
        scope.configuration_permitted,
        scope.schema_permitted,
        scope.manager_actions_permitted,
        scope.service_start_permitted,
    )
    return DeployManagerBackendLocalInstallAuthorizationReport(
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
        release_line=package.release_line,
        package_count=package.package_count,
        package_version_digest=package.package_version_digest,
        package_set_digest=package.package_set_digest,
        package_provenance_digest=package.provenance_digest,
        package_policy=scope.package_policy,
        service_policy=scope.service_policy,
        prohibited_action_count=sum(prohibited),
        installation_context_artifact_digest=(
            record.installation_context_artifact_digest
        ),
        installation_context_record_digest=(record.installation_context_record_digest),
        installation_plan_artifact_digest=record.installation_plan_artifact_digest,
        installation_plan_digest=record.installation_plan_digest,
        preflight_reconciliation_artifact_digest=(
            record.preflight_reconciliation_artifact_digest
        ),
        preflight_reconciliation_record_digest=(
            record.preflight_reconciliation_record_digest
        ),
        base_os_evidence_digest=record.base_os_evidence_digest,
        manager_server_evidence_digest=record.manager_server_evidence_digest,
        observation_artifact_digest=record.observation_artifact_digest,
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
    value: DeployManagerBackendLocalInstallPackageProvenance,
) -> str:
    return _package_provenance_digest_from_values(value.to_object())


def _package_provenance_digest_from_values(
    values: Mapping[str, object],
) -> str:
    value = dict(values)
    value["provenance_digest"] = ""
    return _digest_object(value)


def _scope_intent_digest(
    scope: DeployManagerBackendLocalInstallAuthorizationScope,
) -> str:
    return _scope_intent_digest_from_values(scope.to_object())


def _scope_intent_digest_from_values(values: Mapping[str, object]) -> str:
    value = dict(values)
    value["install_intent_digest"] = ""
    return _digest_object(value)


def _proof_digest(
    record: DeployManagerBackendLocalInstallAuthorization,
    proof: Mapping[str, object],
) -> str:
    return _proof_digest_values(
        cluster_uuid=record.cluster_uuid,
        operation_id=record.operation_id,
        request_digest=record.request_digest,
        journal_digest=record.journal_digest,
        installation_plan_artifact_digest=(record.installation_plan_artifact_digest),
        installation_plan_digest=record.installation_plan_digest,
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
    installation_plan_artifact_digest: str,
    installation_plan_digest: str,
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
            "installation_plan_artifact_digest": (installation_plan_artifact_digest),
            "installation_plan_digest": installation_plan_digest,
            "journal_digest": journal_digest,
            "operation": _OPERATION,
            "operation_id": str(operation_id),
            "package_provenance_digest": package_provenance_digest,
            "proof": proof_value,
            "request_digest": request_digest,
            "schema_version": (
                ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION
            ),
            "stage": _STAGE,
        }
    )


def _authorization_digest(
    record: DeployManagerBackendLocalInstallAuthorization,
) -> str:
    return _authorization_digest_from_values(record.to_object())


def _authorization_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployManagerBackendLocalInstallAuthorization.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(
                item,
                (JournalStatus, OperationPhase, OperationClassification),
            )
            else item.to_object()
            if name in {"scope", "package_provenance", "proof"}
            and hasattr(item, "to_object")
            else item
        )
    value["authorization_digest"] = ""
    return _digest_object(value)


def _cluster_identity_digest(cluster_uuid: uuid.UUID, cluster_name: str) -> str:
    validate_cluster_name(cluster_name)
    return _digest_object(
        {
            "cluster_name": cluster_name,
            "cluster_uuid": str(cluster_uuid),
        }
    )


def _digest_value(value: Mapping[str, object], name: str) -> str:
    item = value.get(name)
    if not isinstance(item, str):
        raise StateConflictError(
            f"deploy Manager backend local install {name} is invalid"
        )
    validate_digest(item, f"deploy Manager backend local install {name}")
    return item


def _refuse_incompatible_or_later_artifacts(
    paths: StatePaths,
    operation_id: uuid.UUID,
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
        ".ansible-deploy-manager-backend-local-install-execution.json",
        ".ansible-deploy-manager-backend-local-install-evidence.json",
        ".ansible-deploy-post-manager-backend-local-install-reconciliation.json",
        ".ansible-deploy-manager-backend-storage",
        ".ansible-deploy-manager-backend-file-configuration",
        ".ansible-deploy-manager-backend-schema",
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Manager backend local install history"
        ) from error
    prefix = str(operation_id)
    for entry in entries:
        if entry.name.startswith(prefix) and any(
            fragment in entry.name for fragment in forbidden_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy Manager backend local install authorization refuses "
                "execution or later-stage history"
            )


def _refuse_ambiguous_authorization_artifacts(
    paths: StatePaths,
    operation_id: uuid.UUID,
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Manager backend local install "
            "authorization history"
        ) from error
    canonical = str(operation_id)
    suffix = DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_FILENAME_SUFFIX
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
                "deploy Manager backend local install authorization artifacts "
                "are ambiguous"
            )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy Manager backend local install authorization paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy Manager backend local install authorization requires "
            "an acquired deploy lock"
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
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_SCOPE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_PACKAGE_PROVENANCE_SCHEMA_VERSION",
    "DEPLOY_MANAGER_BACKEND_LOCAL_INSTALL_AUTHORIZATION_FILENAME_SUFFIX",
    "DeployManagerBackendLocalInstallApprovalMethod",
    "DeployManagerBackendLocalInstallArchitecture",
    "DeployManagerBackendLocalInstallAuthorization",
    "DeployManagerBackendLocalInstallAuthorizationArtifactState",
    "DeployManagerBackendLocalInstallAuthorizationProof",
    "DeployManagerBackendLocalInstallAuthorizationReport",
    "DeployManagerBackendLocalInstallAuthorizationScope",
    "DeployManagerBackendLocalInstallAuthorizationStore",
    "DeployManagerBackendLocalInstallPackagePolicy",
    "DeployManagerBackendLocalInstallPackageProvenance",
    "DeployManagerBackendLocalInstallProofDecision",
    "DeployManagerBackendLocalInstallServicePolicy",
    "StoredDeployManagerBackendLocalInstallAuthorization",
    "authorize_deploy_manager_backend_local_install",
    "deploy_manager_backend_local_install_authorization_id_from_filename",
    "deploy_manager_backend_local_install_authorization_path",
]
