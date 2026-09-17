"""Immutable authorization for the mapped deploy ``manager-server`` step.

This internal owner requires the completed bootstrap mapping bridge, revalidates
the canonical deploy chain, derives one exact Manager 3.12 package-install
intent, and persists only an unconsumed ordinary approval checkpoint.  It does
not create execution intent, invoke Ansible, mutate a host, or change the
common operation journal.
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
from scylla_vms.ansible.deploy_non_jump_base_os_execution import (
    DeployNonJumpBaseOsEvidenceStore,
    StoredDeployNonJumpBaseOsEvidence,
)
from scylla_vms.ansible.deploy_plan import (
    DeployConditionState,
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import _loaded
from scylla_vms.ansible.deploy_scylla_configure_reconciliation import (
    DeployPostScyllaConfigureReconciliationStore,
    StoredDeployPostScyllaConfigureReconciliation,
    _load_reconciliation_context,
    _ReconciliationContext,
)
from scylla_vms.ansible.deploy_scylla_post_bootstrap_reconciliation import (
    ANSIBLE_DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_SCHEMA_VERSION,
    DeployPostBootstrapArtifactState,
    DeployPostBootstrapReconciliationStore,
    DeployPostBootstrapStepStatus,
    StoredDeployPostBootstrapReconciliation,
    deploy_scylla_post_bootstrap_reconciliation_path,
    reconcile_deploy_scylla_post_bootstrap,
)
from scylla_vms.ansible.manager_server import (
    MANAGER_CHANNEL,
    MANAGER_PACKAGE_VERSION,
    MANAGER_PACKAGES,
    MANAGER_RELEASE_LINE,
    MANAGER_REPOSITORY_DEFINITION_DIGEST,
    MANAGER_SERVICE_UNIT,
    build_manager_server_payload,
)
from scylla_vms.ansible.operation_authorization import (
    OPERATION_AUTHORIZATION_FILENAME_SUFFIX,
)
from scylla_vms.ansible.readiness import (
    EvidenceStatus,
    ReadinessReport,
    RouteReadiness,
    RouteReport,
    TrustReadiness,
)
from scylla_vms.ansible.registry import CheckMode, LimitPolicy, get_playbook
from scylla_vms.ansible.scylla_install import (
    SCYLLA_SIGNING_KEY_DIGEST,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
    SCYLLA_SIGNING_KEY_UID,
    SCYLLA_SIGNING_SUBKEY_FINGERPRINT,
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

ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-server-authorization-proof/v1"
)
ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_SCOPE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-server-authorization-scope/v1"
)
ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-server-authorization/v1"
)
ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-server-authorization-report/v1"
)
DEPLOY_MANAGER_SERVER_AUTHORIZATION_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-server-authorization.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "manager-server"
_MAPPING_SEQUENCE = 14
_TARGET_ROLE = HostRole.MANAGER.value
_STAGE = "post-bootstrap-manager-server"
_SCOPE_KIND = "bootstrap-healthy-manager-install"
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


class DeployManagerServerApprovalMethod(StrEnum):
    """PLAN-permitted ordinary approval methods."""

    INTERACTIVE = "interactive"
    CLI_YES = "cli-yes"


class DeployManagerServerArchitecture(StrEnum):
    """Closed OCI image architecture policy."""

    AMD64 = "amd64"
    AARCH64 = "aarch64"


class DeployManagerServerServicePolicy(StrEnum):
    """The source-owned service state after package installation."""

    MASKED_INACTIVE = "masked-inactive"


class DeployManagerServerBackendPolicy(StrEnum):
    """The only backend state authorized by this install-only slice."""

    UNCONFIGURED = "unconfigured"


class DeployManagerServerAuthorizationArtifactState(StrEnum):
    """Immutable authorization persistence result."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployManagerServerAuthorizationProof:
    """Already-normalized ordinary approval without caller-owned scope."""

    approval_method: DeployManagerServerApprovalMethod | None = None
    approved: bool = False
    allow_destructive: bool = False
    destructive_scope_provided: bool = False
    narrow_consent_provided: bool = False

    def __post_init__(self) -> None:
        if self.approval_method is not None and not isinstance(
            self.approval_method, DeployManagerServerApprovalMethod
        ):
            raise StateConflictError("deploy manager-server approval method is invalid")
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
                "deploy manager-server authorization proof is malformed"
            )


@dataclass(frozen=True, slots=True)
class DeployManagerServerProofDecision:
    """Persisted ordinary proof bound to exact derived scope."""

    approval_method: DeployManagerServerApprovalMethod
    approved: bool
    allow_destructive: bool
    destructive_scope_provided: bool
    narrow_consent_provided: bool
    proof_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or not isinstance(self.approval_method, DeployManagerServerApprovalMethod)
            or self.approved is not True
            or self.allow_destructive is not False
            or self.destructive_scope_provided is not False
            or self.narrow_consent_provided is not False
        ):
            raise StatePersistenceError(
                "deploy manager-server authorization proof state is invalid"
            )
        validate_digest(
            self.proof_digest, "deploy manager-server authorization proof digest"
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
    ) -> DeployManagerServerProofDecision:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy manager-server authorization proof",
        )
        try:
            method = DeployManagerServerApprovalMethod(
                require_string(value, "approval_method")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy manager-server authorization proof method is invalid"
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
class DeployManagerServerPackageProvenance:
    """URL- and key-material-free identity of the exact Manager package policy."""

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

    def __post_init__(self) -> None:
        if (
            self.release_line != MANAGER_RELEASE_LINE
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
                "deploy manager-server package provenance conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy manager-server package provenance digest")

    def to_object(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerServerPackageProvenance:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy manager-server package provenance",
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
        )


@dataclass(frozen=True, slots=True)
class DeployManagerServerAuthorizationScope:
    """One exact redacted Manager install intent derived from canonical state."""

    mapping_sequence: int
    playbook: str
    classification: OperationClassification
    target_role: str
    target_stable_id: str
    target_digest: str
    architecture: DeployManagerServerArchitecture
    image_policy_digest: str
    service_policy: DeployManagerServerServicePolicy
    backend_policy: DeployManagerServerBackendPolicy
    service_start_permitted: bool
    registration_permitted: bool
    setup_permitted: bool
    variables_digest: str
    source_digest: str
    command_digest: str
    base_os_evidence_digest: str
    bridge_step_digest: str
    prior_reconciled_step_digest: str
    original_step_digest: str
    package_provenance_digest: str
    install_intent_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_SCOPE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        definition = get_playbook(self.playbook)
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_SCOPE_SCHEMA_VERSION
            or self.mapping_sequence != _MAPPING_SEQUENCE
            or self.playbook != _PLAYBOOK
            or self.classification is not OperationClassification.MUTATING
            or definition.classification is not self.classification
            or self.target_role != _TARGET_ROLE
            or not self.target_stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
            or self.target_digest != _digest_object([self.target_stable_id])
            or not isinstance(self.architecture, DeployManagerServerArchitecture)
            or self.service_policy
            is not DeployManagerServerServicePolicy.MASKED_INACTIVE
            or self.backend_policy is not DeployManagerServerBackendPolicy.UNCONFIGURED
            or self.service_start_permitted
            or self.registration_permitted
            or self.setup_permitted
            or self.install_intent_digest != _scope_intent_digest(self)
        ):
            raise StatePersistenceError(
                "deploy manager-server authorization scope policy is invalid"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy manager-server authorization scope digest")

    def to_object(self) -> dict[str, object]:
        return {
            name: (
                value.value
                if isinstance(value, StrEnum)
                else value.value
                if isinstance(value, OperationClassification)
                else value
            )
            for name in self.__dataclass_fields__
            if (value := getattr(self, name)) is not None
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerServerAuthorizationScope:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy manager-server authorization scope",
        )
        try:
            return cls(
                mapping_sequence=_integer(
                    value["mapping_sequence"], "scope mapping sequence"
                ),
                playbook=require_string(value, "playbook"),
                classification=OperationClassification(
                    require_string(value, "classification")
                ),
                target_role=require_string(value, "target_role"),
                target_stable_id=require_string(value, "target_stable_id"),
                target_digest=require_string(value, "target_digest"),
                architecture=DeployManagerServerArchitecture(
                    require_string(value, "architecture")
                ),
                image_policy_digest=require_string(value, "image_policy_digest"),
                service_policy=DeployManagerServerServicePolicy(
                    require_string(value, "service_policy")
                ),
                backend_policy=DeployManagerServerBackendPolicy(
                    require_string(value, "backend_policy")
                ),
                service_start_permitted=_boolean(
                    value["service_start_permitted"], "service-start policy"
                ),
                registration_permitted=_boolean(
                    value["registration_permitted"], "registration policy"
                ),
                setup_permitted=_boolean(value["setup_permitted"], "setup policy"),
                variables_digest=require_string(value, "variables_digest"),
                source_digest=require_string(value, "source_digest"),
                command_digest=require_string(value, "command_digest"),
                base_os_evidence_digest=require_string(
                    value, "base_os_evidence_digest"
                ),
                bridge_step_digest=require_string(value, "bridge_step_digest"),
                prior_reconciled_step_digest=require_string(
                    value, "prior_reconciled_step_digest"
                ),
                original_step_digest=require_string(value, "original_step_digest"),
                package_provenance_digest=require_string(
                    value, "package_provenance_digest"
                ),
                install_intent_digest=require_string(value, "install_intent_digest"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy manager-server authorization scope enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerServerAuthorization:
    """Immutable unconsumed authorization for one exact Manager install."""

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
    context_artifact_digest: str
    context_record_digest: str
    original_plan_artifact_digest: str
    original_plan_record_digest: str
    post_configure_artifact_digest: str
    post_configure_record_digest: str
    post_configure_effective_plan_digest: str
    bootstrap_context_artifact_digest: str
    bootstrap_plan_artifact_digest: str
    completed_prefix_digest: str
    final_health_evidence_digest: str
    final_health_reconciliation_digest: str
    post_bootstrap_artifact_digest: str
    post_bootstrap_record_digest: str
    post_bootstrap_effective_plan_digest: str
    base_os_artifact_digest: str
    base_os_evidence_digest: str
    catalog_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    classification: OperationClassification
    scope: DeployManagerServerAuthorizationScope
    target_count: int
    target_set_digest: str
    authorization_scope_digest: str
    package_provenance: DeployManagerServerPackageProvenance
    proof: DeployManagerServerProofDecision
    authorization_state: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_digest: str
    post_bootstrap_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_SCHEMA_VERSION
            or self.post_bootstrap_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_SCHEMA_VERSION
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
            or self.scope.package_provenance_digest
            != self.package_provenance.provenance_digest
            or self.authorization_state != _AUTHORIZED
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError(
                "deploy manager-server authorization identity or state is invalid"
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
                count, "deploy manager-server authorization generation or count"
            )
        for digest in _digest_fields(self):
            validate_digest(
                digest, "deploy manager-server authorization binding digest"
            )
        if self.proof.proof_digest != _proof_digest(self, self.proof.to_object()):
            raise StatePersistenceError(
                "deploy manager-server authorization proof digest conflicts"
            )
        if self.authorization_digest != _authorization_digest(self):
            raise StatePersistenceError(
                "deploy manager-server authorization digest conflicts"
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
                if name in {"scope", "package_provenance", "proof"}
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerServerAuthorization:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy manager-server authorization",
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
            elif name == "scope":
                parsed[name] = DeployManagerServerAuthorizationScope.from_object(
                    _mapping(item, "deploy manager-server authorization scope")
                )
            elif name == "package_provenance":
                parsed[name] = DeployManagerServerPackageProvenance.from_object(
                    _mapping(item, "deploy manager-server package provenance")
                )
            elif name == "proof":
                parsed[name] = DeployManagerServerProofDecision.from_object(
                    _mapping(item, "deploy manager-server authorization proof")
                )
            elif name == "consumed":
                parsed[name] = _boolean(item, name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployManagerServerAuthorization:
    record: DeployManagerServerAuthorization
    artifact_digest: str


class DeployManagerServerAuthorizationStore:
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
        self._path = deploy_manager_server_authorization_path(paths, operation_id)
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
    ) -> StoredDeployManagerServerAuthorization:
        value, artifact_digest = self._file.read()
        record = DeployManagerServerAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_identity_digest
            != _cluster_identity_digest(expected_cluster_uuid, expected_cluster_name)
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "deploy manager-server authorization identity conflicts"
            )
        return StoredDeployManagerServerAuthorization(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerServerAuthorization:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployManagerServerAuthorization,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployManagerServerAuthorization,
        DeployManagerServerAuthorizationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy manager-server authorization operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=self._paths.cluster_root.name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy manager-server authorization is immutable; "
                    "use a new operation"
                )
            return current, DeployManagerServerAuthorizationArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerServerAuthorization(record, artifact_digest),
            DeployManagerServerAuthorizationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerServerAuthorizationReport:
    """Strict redacted authorization report without executable inputs."""

    operation_id: uuid.UUID
    artifact_state: DeployManagerServerAuthorizationArtifactState
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_state: str
    stage: str
    scope_kind: str
    approval_method: DeployManagerServerApprovalMethod
    approval_state: str
    proof_digest: str
    classification: OperationClassification
    playbook: str
    target_stable_id: str
    target_count: int
    target_set_digest: str
    authorization_scope_digest: str
    architecture: DeployManagerServerArchitecture
    release_line: str
    package_count: int
    package_version_digest: str
    package_set_digest: str
    package_provenance_digest: str
    service_policy: DeployManagerServerServicePolicy
    backend_policy: DeployManagerServerBackendPolicy
    service_start_permitted: bool
    registration_permitted: bool
    setup_permitted: bool
    post_bootstrap_artifact_digest: str
    post_bootstrap_record_digest: str
    final_health_evidence_digest: str
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
        ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_SCHEMA_VERSION
    )
    proof_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    post_bootstrap_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or self.post_bootstrap_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_SCHEMA_VERSION
            or self.authorization_state != _AUTHORIZED
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.approval_state != "approved"
            or self.classification is not OperationClassification.MUTATING
            or self.playbook != _PLAYBOOK
            or self.target_count != 1
            or self.release_line != MANAGER_RELEASE_LINE
            or self.package_count != len(MANAGER_PACKAGES)
            or self.service_policy
            is not DeployManagerServerServicePolicy.MASKED_INACTIVE
            or self.backend_policy is not DeployManagerServerBackendPolicy.UNCONFIGURED
            or self.service_start_permitted
            or self.registration_permitted
            or self.setup_permitted
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError(
                "deploy manager-server authorization report is invalid"
            )
        if (
            not self.target_stable_id.isascii()
            or _LOGICAL_ID.fullmatch(self.target_stable_id) is None
        ):
            raise StatePersistenceError(
                "deploy manager-server authorization report target is invalid"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy manager-server authorization report digest")

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
                "architecture": self.architecture.value,
                "backend": self.backend_policy.value,
                "registration_permitted": self.registration_permitted,
                "service": self.service_policy.value,
                "service_start_permitted": self.service_start_permitted,
                "setup_permitted": self.setup_permitted,
            },
            "provenance": {
                "ansible_source_digest": self.ansible_source_digest,
                "base_os": {
                    "artifact_digest": self.base_os_artifact_digest,
                    "evidence_digest": self.base_os_evidence_digest,
                },
                "catalog_digest": self.catalog_digest,
                "final_health_evidence_digest": self.final_health_evidence_digest,
                "inventory_artifact_digest": self.inventory_artifact_digest,
                "post_bootstrap": {
                    "artifact_digest": self.post_bootstrap_artifact_digest,
                    "record_digest": self.post_bootstrap_record_digest,
                    "schema_version": self.post_bootstrap_schema_version,
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
    chain: _ReconciliationContext
    post_configure: StoredDeployPostScyllaConfigureReconciliation
    bridge: StoredDeployPostBootstrapReconciliation
    base_os: StoredDeployNonJumpBaseOsEvidence


def authorize_deploy_manager_server(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proof: DeployManagerServerAuthorizationProof,
) -> DeployManagerServerAuthorizationReport:
    """Authorize the exact mapped Manager server step without execution."""

    if not isinstance(proof, DeployManagerServerAuthorizationProof):
        raise StateConflictError(
            "deploy manager-server authorization proof is malformed"
        )
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_authorization_artifacts(paths, operation_id)
    _refuse_incompatible_or_later_artifacts(paths, operation_id)
    context = _load_authorization_context(paths, operation_id, lock=lock)
    loaded = _loaded(context.chain.authorization_context)
    metadata = loaded.planning.base.deploy.metadata.record
    package_provenance = _derive_package_provenance()
    scope = _derive_authorization_scope(context, package_provenance)
    scope_digest = _digest_object(scope.to_object())
    decision = _normalize_proof(
        proof,
        context=context,
        scope_digest=scope_digest,
        package_provenance_digest=package_provenance.provenance_digest,
    )
    store = DeployManagerServerAuthorizationStore(paths, operation_id)
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
                "deploy manager-server authorization changed; "
                "re-plan with a new operation"
            )
        state = DeployManagerServerAuthorizationArtifactState.REUSED
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
                "deploy manager-server authorization persistence failed"
            ) from error
    return _build_report(stored, state=state)


def deploy_manager_server_authorization_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the canonical operation-bound Manager authorization path."""

    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MANAGER_SERVER_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy manager-server authorization path is not canonical"
        )
    return path


def deploy_manager_server_authorization_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(DEPLOY_MANAGER_SERVER_AUTHORIZATION_FILENAME_SUFFIX):
        return None
    value = name[: -len(DEPLOY_MANAGER_SERVER_AUTHORIZATION_FILENAME_SUFFIX)]
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
    bridge_path = deploy_scylla_post_bootstrap_reconciliation_path(paths, operation_id)
    validate_state_file(bridge_path, allow_missing=True)
    if not bridge_path.exists():
        raise StateConflictError(
            "deploy manager-server authorization requires the post-bootstrap bridge"
        )
    # The bridge recomputation is zero-write once its exact immutable record exists.
    # It is the canonical full-chain validator for every bootstrap sequence family.
    bridge_report = reconcile_deploy_scylla_post_bootstrap(
        state_root=paths.state_root,
        cluster_name=paths.cluster_root.name,
        operation_id=operation_id,
        lock=lock,
    )
    if bridge_report.artifact_state is not DeployPostBootstrapArtifactState.REUSED:
        raise StateConflictError(
            "deploy manager-server authorization requires a prior immutable bridge"
        )
    chain = _load_reconciliation_context(paths, operation_id, lock=lock)
    loaded = _loaded(chain.authorization_context)
    metadata = loaded.planning.base.deploy.metadata.record
    post_configure = DeployPostScyllaConfigureReconciliationStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    bridge = DeployPostBootstrapReconciliationStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    if (
        bridge.record.post_configure_artifact_digest != post_configure.artifact_digest
        or bridge.record.post_configure_record_digest
        != post_configure.record.record_digest
        or bridge.record.post_configure_effective_plan_digest
        != post_configure.record.effective_plan_digest
    ):
        raise StateConflictError(
            "deploy manager-server post-bootstrap provenance drifted"
        )
    base_os = DeployNonJumpBaseOsEvidenceStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    return _AuthorizationContext(chain, post_configure, bridge, base_os)


def _derive_package_provenance() -> DeployManagerServerPackageProvenance:
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
    }
    values["provenance_digest"] = _package_provenance_digest_from_values(values)
    return DeployManagerServerPackageProvenance(**values)  # type: ignore[arg-type]


def _derive_authorization_scope(
    context: _AuthorizationContext,
    package: DeployManagerServerPackageProvenance,
) -> DeployManagerServerAuthorizationScope:
    loaded = _loaded(context.chain.authorization_context)
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    bridge = context.bridge
    post_configure = context.post_configure
    bridge_steps = tuple(
        step
        for step in bridge.record.steps
        if step.mapping_sequence == _MAPPING_SEQUENCE
    )
    prior_steps = tuple(
        step
        for step in post_configure.record.steps
        if step.mapping_sequence == _MAPPING_SEQUENCE
    )
    if len(bridge_steps) != 1 or len(prior_steps) != 1:
        raise StateConflictError(
            "deploy manager-server mapped authorization scope is ambiguous"
        )
    bridge_step = bridge_steps[0]
    prior_step = prior_steps[0]
    definition = get_playbook(_PLAYBOOK)
    source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
    if (
        bridge.record.next_mapping_sequence != _MAPPING_SEQUENCE
        or bridge.record.next_playbook != _PLAYBOOK
        or bridge.record.next_step_status
        is not DeployPostBootstrapStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        or bridge.record.authorization_required_count != 1
        or bridge.record.next_target_count != 1
        or bridge_step.status
        is not DeployPostBootstrapStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        or bridge_step.playbook != _PLAYBOOK
        or bridge_step.condition_state is not DeployConditionState.ACTIVE
        or bridge_step.classification != OperationClassification.MUTATING.value
        or bridge_step.target_role != _TARGET_ROLE
        or bridge_step.target_count != 1
        or bridge_step.target_set_digest != bridge.record.next_target_set_digest
        or bridge_step.blockers != _EXPECTED_BLOCKERS
        or bridge_step.prior_step_digest != _digest_object(prior_step.to_object())
        or bridge_step.original_step_digest != prior_step.original_step_digest
        or prior_step.playbook != _PLAYBOOK
        or prior_step.condition_state is not DeployConditionState.ACTIVE
        or prior_step.classification is not OperationClassification.MUTATING
        or prior_step.target_role != _TARGET_ROLE
        or len(prior_step.target_ids) != 1
        or prior_step.target_digest != bridge_step.target_set_digest
        or prior_step.source_digest != source_digest
        or definition.classification is not OperationClassification.MUTATING
        or definition.hosts != _TARGET_ROLE
        or definition.serial != 1
        or definition.limit_policy is not LimitPolicy.SINGLE_LOGICAL_HOST
        or definition.check_mode is not CheckMode.PREVIEW
        or not definition.any_errors_fatal
        or not definition.source_available
    ):
        raise StateConflictError(
            "only the exact active mapped manager-server step may be authorized"
        )
    stable_id = prior_step.target_ids[0]
    manager_hosts = tuple(
        host
        for host in deploy.inventory.record.inventory.hosts
        if host.role is HostRole.MANAGER
    )
    if (
        len(manager_hosts) != 1
        or manager_hosts[0].logical_id != stable_id
        or _digest_object([stable_id]) != bridge_step.target_set_digest
    ):
        raise StateConflictError(
            "deploy manager-server target is not the exact current manager identity"
        )
    base_matches = tuple(
        (entry, host)
        for entry in context.base_os.record.entries
        for host in entry.hosts
        if host.logical_id == stable_id
    )
    if len(base_matches) != 1:
        raise StateConflictError(
            "deploy manager-server requires exact current manager base-os evidence"
        )
    base_entry, base_host = base_matches[0]
    image_filter = dict(metadata.desired_spec.image_filters).get(HostRole.MANAGER)
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
            "deploy manager-server Ubuntu, architecture, or base-os gate conflicts"
        )
    manager_image_filter = image_filter
    readiness = planning.readiness.record
    if (
        readiness.readiness_status is not EvidenceStatus.FRESH
        or readiness.cluster_uuid != metadata.cluster_uuid
        or readiness.operation_id != bridge.record.operation_id
        or readiness.observation_artifact_digest != deploy.observation.digest
        or readiness.inventory_artifact_digest != deploy.inventory.digest
        or readiness.trust_artifact_digest != planning.base.trust.digest
        or readiness.ansible_source_digest != loaded.source.digest
        or readiness.remote_connectivity_status != "not-performed"
        or readiness.remote_health_status != "not-performed"
        or readiness.remote_playbook_status != "not-performed"
    ):
        raise StateConflictError(
            "deploy manager-server trust or readiness binding drifted"
        )
    readiness_report = ReadinessReport(
        source_status=EvidenceStatus.FRESH,
        machine_status=EvidenceStatus.FRESH,
        trust_status=TrustReadiness.COMPLETE,
        route_status=RouteReadiness.VALID,
        observation_generation=deploy.observation.record.generation,
        observation_digest=deploy.observation.record.manifest_digest,
        inventory_generation=deploy.inventory.record.generation,
        inventory_digest=deploy.inventory.digest,
        trust_generation=planning.base.trust.record.generation,
        trust_digest=planning.base.trust.digest,
        host_count=readiness.host_count,
        trusted_host_count=readiness.host_count,
        fingerprints=(),
        route=RouteReport(
            RouteReadiness.VALID,
            readiness.direct_host_count,
            readiness.proxied_host_count,
            readiness.jump_host_count,
            (),
        ),
        blockers=tuple(
            (classification, ()) for classification in OperationClassification
        ),
    )
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
    payload = build_manager_server_payload(
        metadata,
        deploy.observation,
        deploy.inventory,
        readiness_report,
        base_os,
        logical_id=stable_id,
        image_filter=manager_image_filter,
        architecture=base_host.image_architecture,
        package_version=MANAGER_PACKAGE_VERSION,
        cluster_spec_digest=metadata.desired_spec.digest(),
    )
    if (
        payload["backend_configured"] is not False
        or payload["registration_performed"] is not False
        or payload["service_started"] is not False
        or payload["setup_performed"] is not False
        or payload["service_unit"] != MANAGER_SERVICE_UNIT
        or payload["packages"] != list(MANAGER_PACKAGES)
    ):
        raise StateConflictError("deploy manager-server install-only policy conflicts")
    variables = definition.validate_variables(
        {"deploy_scylla_vms_manager_server": payload}
    )
    variables_digest = digest_bytes(serialize_json(variables))
    command_digest = ansible_command_intent_digest(
        definition,
        step_sequence=prior_step.sequence,
        limit=prior_step.target_ids,
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
        "target_digest": bridge_step.target_set_digest,
        "architecture": DeployManagerServerArchitecture(base_host.image_architecture),
        "image_policy_digest": _digest_object(manager_image_filter.to_object()),
        "service_policy": DeployManagerServerServicePolicy.MASKED_INACTIVE,
        "backend_policy": DeployManagerServerBackendPolicy.UNCONFIGURED,
        "service_start_permitted": False,
        "registration_permitted": False,
        "setup_permitted": False,
        "variables_digest": variables_digest,
        "source_digest": source_digest,
        "command_digest": command_digest,
        "base_os_evidence_digest": base_entry.evidence_digest,
        "bridge_step_digest": bridge_step.step_digest,
        "prior_reconciled_step_digest": bridge_step.prior_step_digest,
        "original_step_digest": bridge_step.original_step_digest,
        "package_provenance_digest": package.provenance_digest,
        "install_intent_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_SCOPE_SCHEMA_VERSION
        ),
    }
    values["install_intent_digest"] = _scope_intent_digest_from_values(values)
    return DeployManagerServerAuthorizationScope(**values)  # type: ignore[arg-type]


def _normalize_proof(
    proof: DeployManagerServerAuthorizationProof,
    *,
    context: _AuthorizationContext,
    scope_digest: str,
    package_provenance_digest: str,
) -> DeployManagerServerProofDecision:
    if proof.approval_method is None:
        raise StateConflictError("ordinary deploy manager-server approval is required")
    if not proof.approved:
        raise StateConflictError("ordinary deploy manager-server approval was denied")
    if (
        proof.allow_destructive
        or proof.destructive_scope_provided
        or proof.narrow_consent_provided
    ):
        raise StateConflictError(
            "destructive and narrow proofs are inapplicable to mutating "
            "manager-server authorization"
        )
    bridge = context.bridge
    values: dict[str, object] = {
        "allow_destructive": False,
        "approval_method": proof.approval_method.value,
        "approved": True,
        "destructive_scope_provided": False,
        "narrow_consent_provided": False,
        "proof_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_PROOF_SCHEMA_VERSION
        ),
    }
    values["proof_digest"] = _proof_digest_values(
        cluster_uuid=bridge.record.cluster_uuid,
        operation_id=bridge.record.operation_id,
        request_digest=bridge.record.request_digest,
        journal_digest=bridge.record.journal_digest,
        bridge_artifact_digest=bridge.artifact_digest,
        bridge_record_digest=bridge.record.record_digest,
        scope_digest=scope_digest,
        package_provenance_digest=package_provenance_digest,
        proof=values,
    )
    return DeployManagerServerProofDecision.from_object(values)


def _build_authorization(
    context: _AuthorizationContext,
    *,
    scope: DeployManagerServerAuthorizationScope,
    package_provenance: DeployManagerServerPackageProvenance,
    proof: DeployManagerServerProofDecision,
    created_at: str,
) -> DeployManagerServerAuthorization:
    loaded = _loaded(context.chain.authorization_context)
    planning = loaded.planning
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    post_configure = context.post_configure
    bridge = context.bridge
    bridge_record = bridge.record
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_identity_digest": _cluster_identity_digest(
            metadata.cluster_uuid, metadata.cluster_name
        ),
        "operation_id": bridge_record.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "scope_kind": _SCOPE_KIND,
        "request_digest": bridge_record.request_digest,
        "journal_generation": bridge_record.journal_generation,
        "journal_digest": bridge_record.journal_digest,
        "journal_status": bridge_record.journal_status,
        "journal_phase": bridge_record.journal_phase,
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
        "context_artifact_digest": loaded.context.artifact_digest,
        "context_record_digest": loaded.context.record.record_digest,
        "original_plan_artifact_digest": loaded.plan.artifact_digest,
        "original_plan_record_digest": loaded.plan.record.record_digest,
        "post_configure_artifact_digest": post_configure.artifact_digest,
        "post_configure_record_digest": post_configure.record.record_digest,
        "post_configure_effective_plan_digest": (
            post_configure.record.effective_plan_digest
        ),
        "bootstrap_context_artifact_digest": (
            bridge_record.bootstrap_context_artifact_digest
        ),
        "bootstrap_plan_artifact_digest": (
            bridge_record.bootstrap_plan_artifact_digest
        ),
        "completed_prefix_digest": bridge_record.completed_prefix_digest,
        "final_health_evidence_digest": bridge_record.final_health_evidence_digest,
        "final_health_reconciliation_digest": (
            bridge_record.final_health_reconciliation_digest
        ),
        "post_bootstrap_artifact_digest": bridge.artifact_digest,
        "post_bootstrap_record_digest": bridge_record.record_digest,
        "post_bootstrap_effective_plan_digest": (bridge_record.effective_plan_digest),
        "base_os_artifact_digest": context.base_os.artifact_digest,
        "base_os_evidence_digest": scope.base_os_evidence_digest,
        "catalog_digest": loaded.catalog_digest,
        "ansible_source_version": loaded.source.version,
        "ansible_source_digest": loaded.source.digest,
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
        deploy.journal.record.generation != bridge_record.journal_generation
        or deploy.journal.digest != bridge_record.journal_digest
        or loaded.catalog_digest != bridge_record.catalog_digest
        or loaded.source.digest != bridge_record.ansible_source_digest
        or post_configure.artifact_digest
        != bridge_record.post_configure_artifact_digest
        or context.base_os.record.binding.inventory_artifact_digest
        != deploy.inventory.digest
        or context.base_os.record.binding.trust_artifact_digest
        != planning.base.trust.digest
        or context.base_os.record.binding.readiness_artifact_digest
        != planning.readiness.artifact_digest
    ):
        raise StateConflictError(
            "deploy manager-server current plan, base-os, trust, readiness, "
            "or source drifted"
        )
    values["authorization_digest"] = _authorization_digest_from_values(values)
    return DeployManagerServerAuthorization(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployManagerServerAuthorization,
    *,
    state: DeployManagerServerAuthorizationArtifactState,
) -> DeployManagerServerAuthorizationReport:
    record = stored.record
    scope = record.scope
    package = record.package_provenance
    return DeployManagerServerAuthorizationReport(
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
        service_policy=scope.service_policy,
        backend_policy=scope.backend_policy,
        service_start_permitted=scope.service_start_permitted,
        registration_permitted=scope.registration_permitted,
        setup_permitted=scope.setup_permitted,
        post_bootstrap_artifact_digest=record.post_bootstrap_artifact_digest,
        post_bootstrap_record_digest=record.post_bootstrap_record_digest,
        final_health_evidence_digest=record.final_health_evidence_digest,
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
    value: DeployManagerServerPackageProvenance,
) -> str:
    return _package_provenance_digest_from_values(value.to_object())


def _package_provenance_digest_from_values(values: Mapping[str, object]) -> str:
    value = dict(values)
    value["provenance_digest"] = ""
    return _digest_object(value)


def _scope_intent_digest(scope: DeployManagerServerAuthorizationScope) -> str:
    return _scope_intent_digest_from_values(scope.to_object())


def _scope_intent_digest_from_values(values: Mapping[str, object]) -> str:
    value = dict(values)
    value["install_intent_digest"] = ""
    return _digest_object(value)


def _proof_digest(
    record: DeployManagerServerAuthorization,
    proof: Mapping[str, object],
) -> str:
    return _proof_digest_values(
        cluster_uuid=record.cluster_uuid,
        operation_id=record.operation_id,
        request_digest=record.request_digest,
        journal_digest=record.journal_digest,
        bridge_artifact_digest=record.post_bootstrap_artifact_digest,
        bridge_record_digest=record.post_bootstrap_record_digest,
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
    bridge_artifact_digest: str,
    bridge_record_digest: str,
    scope_digest: str,
    package_provenance_digest: str,
    proof: Mapping[str, object],
) -> str:
    proof_value = dict(proof)
    proof_value["proof_digest"] = ""
    return _digest_object(
        {
            "authorization_scope_digest": scope_digest,
            "bridge_artifact_digest": bridge_artifact_digest,
            "bridge_record_digest": bridge_record_digest,
            "cluster_uuid": str(cluster_uuid),
            "journal_digest": journal_digest,
            "operation": _OPERATION,
            "operation_id": str(operation_id),
            "package_provenance_digest": package_provenance_digest,
            "proof": proof_value,
            "request_digest": request_digest,
            "schema_version": (
                ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_PROOF_SCHEMA_VERSION
            ),
            "stage": _STAGE,
        }
    )


def _authorization_digest(record: DeployManagerServerAuthorization) -> str:
    return _authorization_digest_from_values(record.to_object())


def _authorization_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployManagerServerAuthorization.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(
                item, (JournalStatus, OperationPhase, OperationClassification)
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
        ".ansible-deploy-manager-server-execution.json",
        ".ansible-deploy-manager-server-evidence.json",
        ".ansible-deploy-post-manager-server-reconciliation.json",
        ".ansible-deploy-monitoring-stack",
        ".ansible-deploy-manager-agent",
        ".ansible-deploy-monitoring-agent",
        ".ansible-deploy-monitoring-targets",
        ".ansible-deploy-manager-tasks",
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy manager-server operation history"
        ) from error
    prefix = str(operation_id)
    for entry in entries:
        if entry.name.startswith(prefix) and any(
            fragment in entry.name for fragment in forbidden_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy manager-server authorization refuses execution "
                "or later-stage history"
            )


def _refuse_ambiguous_authorization_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy manager-server authorization history"
        ) from error
    canonical = str(operation_id)
    suffix = DEPLOY_MANAGER_SERVER_AUTHORIZATION_FILENAME_SUFFIX
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
                "deploy manager-server authorization artifacts are ambiguous"
            )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy manager-server authorization paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy manager-server authorization requires an acquired deploy lock"
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


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _enum(enum_type: type[StrEnum], value: str, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except ValueError as error:
        raise StatePersistenceError(
            f"deploy manager-server authorization {label} is invalid"
        ) from error


__all__ = [
    "ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_PROOF_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_SERVER_AUTHORIZATION_SCOPE_SCHEMA_VERSION",
    "DEPLOY_MANAGER_SERVER_AUTHORIZATION_FILENAME_SUFFIX",
    "DeployManagerServerApprovalMethod",
    "DeployManagerServerArchitecture",
    "DeployManagerServerAuthorization",
    "DeployManagerServerAuthorizationArtifactState",
    "DeployManagerServerAuthorizationProof",
    "DeployManagerServerAuthorizationReport",
    "DeployManagerServerAuthorizationScope",
    "DeployManagerServerAuthorizationStore",
    "DeployManagerServerBackendPolicy",
    "DeployManagerServerPackageProvenance",
    "DeployManagerServerProofDecision",
    "DeployManagerServerServicePolicy",
    "StoredDeployManagerServerAuthorization",
    "authorize_deploy_manager_server",
    "deploy_manager_server_authorization_id_from_filename",
    "deploy_manager_server_authorization_path",
]
