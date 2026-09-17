"""Immutable authorization for operation-bound deploy ``scylla-install``.

This internal owner derives the exact ready Scylla install scopes and packaged
2026.2 provenance from canonical state.  It records ordinary approval only; it
does not create execution intent, consume authorization, invoke Ansible, mutate
a host, or change the common operation journal.
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

from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStep,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_plan import (
    DeployConditionState,
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_storage_postcheck import (
    ANSIBLE_DEPLOY_POST_STORAGE_POSTCHECK_RECONCILIATION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EXECUTION_SCHEMA_VERSION,
    DeployPostStoragePostcheckReconciliationStore,
    DeployStoragePostcheckEvidenceStore,
    DeployStoragePostcheckExecutionStore,
    StoredDeployPostStoragePostcheckReconciliation,
    StoredDeployStoragePostcheckEvidence,
    StoredDeployStoragePostcheckExecution,
    _build_post_storage_postcheck_record,
    _build_post_storage_postcheck_steps,
)
from scylla_vms.ansible.deploy_storage_prepare_reconciliation import (
    ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_SCHEMA_VERSION,
    DeployPostStoragePrepareReconciliationStore,
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
from scylla_vms.ansible.operation_authorization import (
    OPERATION_AUTHORIZATION_FILENAME_SUFFIX,
)
from scylla_vms.ansible.registry import get_playbook
from scylla_vms.ansible.scylla_install import (
    SCYLLA_CHANNEL,
    SCYLLA_EDITION,
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
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION
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

ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-install-authorization-proof/v1"
)
ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-install-authorization/v1"
)
ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-install-authorization-report/v1"
)
DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-install-authorization.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "scylla-install"
_MAPPING_SEQUENCE = 11
_TARGET_ROLE = HostRole.SCYLLA.value
_STAGE = "post-storage-postcheck-scylla-install"
_SCOPE_KIND = "postchecked-scylla-hosts"
_AUTHORIZED = "authorized-pre-execution"
_EXECUTION_UNAVAILABLE = "unavailable"
_FINALIZATION_NOT_STARTED = "not-started"
_PUBLIC_WORKFLOW_UNAVAILABLE = "unavailable"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class DeployScyllaInstallApprovalMethod(StrEnum):
    """PLAN-permitted ordinary approval methods."""

    INTERACTIVE = "interactive"
    CLI_YES = "cli-yes"


class DeployScyllaInstallAuthorizationArtifactState(StrEnum):
    """Immutable authorization persistence result."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployScyllaInstallAuthorizationProof:
    """Already-normalized ordinary approval without caller-owned scope."""

    approval_method: DeployScyllaInstallApprovalMethod | None = None
    approved: bool = False
    allow_destructive: bool = False
    destructive_scope_provided: bool = False
    narrow_consent_provided: bool = False

    def __post_init__(self) -> None:
        if self.approval_method is not None and not isinstance(
            self.approval_method, DeployScyllaInstallApprovalMethod
        ):
            raise StateConflictError("deploy scylla-install approval method is invalid")
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
                "deploy scylla-install authorization proof is malformed"
            )


@dataclass(frozen=True, slots=True)
class DeployScyllaInstallProofDecision:
    """Persisted normalized ordinary proof bound to exact canonical scope."""

    approval_method: DeployScyllaInstallApprovalMethod
    approved: bool
    allow_destructive: bool
    destructive_scope_provided: bool
    narrow_consent_provided: bool
    proof_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or not isinstance(self.approval_method, DeployScyllaInstallApprovalMethod)
            or self.approved is not True
            or self.allow_destructive is not False
            or self.destructive_scope_provided is not False
            or self.narrow_consent_provided is not False
        ):
            raise StatePersistenceError(
                "deploy scylla-install authorization proof state is invalid"
            )
        validate_digest(
            self.proof_digest,
            "deploy scylla-install authorization proof digest",
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
    ) -> DeployScyllaInstallProofDecision:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy scylla-install authorization proof",
        )
        for name in (
            "approved",
            "allow_destructive",
            "destructive_scope_provided",
            "narrow_consent_provided",
        ):
            if not isinstance(value[name], bool):
                raise StatePersistenceError(
                    "deploy scylla-install authorization proof boolean is invalid"
                )
        try:
            method = DeployScyllaInstallApprovalMethod(
                require_string(value, "approval_method")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy scylla-install authorization proof method is invalid"
            ) from error
        return cls(
            approval_method=method,
            approved=cast(bool, value["approved"]),
            allow_destructive=cast(bool, value["allow_destructive"]),
            destructive_scope_provided=cast(bool, value["destructive_scope_provided"]),
            narrow_consent_provided=cast(bool, value["narrow_consent_provided"]),
            proof_digest=require_string(value, "proof_digest"),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaInstallPackageProvenance:
    """Address-free packaged 2026.2 install policy identity."""

    release_line: str
    package_version: str
    edition: str
    channel: str
    package_count: int
    package_set_digest: str
    repository_definition_digest: str
    signing_key_artifact_digest: str
    signing_key_identity_digest: str
    catalog_entry_digest: str
    provenance_digest: str

    def __post_init__(self) -> None:
        if (
            self.release_line != SCYLLA_RELEASE_LINE
            or self.package_version != SCYLLA_PACKAGE_VERSION
            or self.edition != SCYLLA_EDITION
            or self.channel != SCYLLA_CHANNEL
            or self.package_count != len(SCYLLA_PACKAGES)
            or self.package_set_digest != _digest_object(list(SCYLLA_PACKAGES))
            or self.repository_definition_digest != SCYLLA_REPOSITORY_DEFINITION_DIGEST
            or self.signing_key_artifact_digest != SCYLLA_SIGNING_KEY_DIGEST
            or self.signing_key_identity_digest != _signing_key_identity_digest()
            or self.provenance_digest != _package_provenance_digest(self)
        ):
            raise StatePersistenceError(
                "deploy scylla-install package provenance conflicts"
            )
        for name in self.__dataclass_fields__:
            if name.endswith("_digest"):
                validate_digest(
                    cast(str, getattr(self, name)),
                    "deploy scylla-install package provenance digest",
                )

    def to_object(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaInstallPackageProvenance:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy scylla-install package provenance",
        )
        return cls(
            release_line=require_string(value, "release_line"),
            package_version=require_string(value, "package_version"),
            edition=require_string(value, "edition"),
            channel=require_string(value, "channel"),
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
class DeployScyllaInstallAuthorizationScope:
    """One exact ready install step derived from canonical reconciliation."""

    sequence: int
    mapping_sequence: int
    playbook: str
    condition: str
    classification: OperationClassification
    target_role: str
    target_ids: tuple[str, ...]
    target_digest: str
    variables_digest: str
    source_digest: str
    command_digest: str
    gate_evidence_digest: str
    original_step_digest: str
    prior_reconciled_step_digest: str
    reconciled_step_digest: str
    package_provenance_digest: str
    install_intent_digest: str

    def __post_init__(self) -> None:
        definition = get_playbook(self.playbook)
        if (
            self.sequence < 1
            or self.mapping_sequence != _MAPPING_SEQUENCE
            or self.playbook != _PLAYBOOK
            or self.classification is not OperationClassification.MUTATING
            or definition.classification is not self.classification
            or self.target_role != _TARGET_ROLE
            or len(self.target_ids) != 1
            or self.target_ids != tuple(sorted(set(self.target_ids)))
            or any(
                not target.isascii() or _LOGICAL_ID.fullmatch(target) is None
                for target in self.target_ids
            )
            or self.target_digest != _digest_object(list(self.target_ids))
            or self.install_intent_digest != _install_intent_digest(self)
        ):
            raise StatePersistenceError(
                "deploy scylla-install authorization scope policy is invalid"
            )
        for name in self.__dataclass_fields__:
            if name.endswith("_digest"):
                validate_digest(
                    cast(str, getattr(self, name)),
                    "deploy scylla-install authorization scope digest",
                )

    def to_object(self) -> dict[str, object]:
        return {
            "classification": self.classification.value,
            "command_digest": self.command_digest,
            "condition": self.condition,
            "gate_evidence_digest": self.gate_evidence_digest,
            "install_intent_digest": self.install_intent_digest,
            "mapping_sequence": self.mapping_sequence,
            "original_step_digest": self.original_step_digest,
            "package_provenance_digest": self.package_provenance_digest,
            "playbook": self.playbook,
            "prior_reconciled_step_digest": self.prior_reconciled_step_digest,
            "reconciled_step_digest": self.reconciled_step_digest,
            "sequence": self.sequence,
            "source_digest": self.source_digest,
            "target_digest": self.target_digest,
            "target_ids": list(self.target_ids),
            "target_role": self.target_role,
            "variables_digest": self.variables_digest,
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaInstallAuthorizationScope:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy scylla-install authorization scope",
        )
        try:
            classification = OperationClassification(
                require_string(value, "classification")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy scylla-install authorization scope class is invalid"
            ) from error
        return cls(
            sequence=_integer(value["sequence"], "scope sequence"),
            mapping_sequence=_integer(
                value["mapping_sequence"], "scope mapping sequence"
            ),
            playbook=require_string(value, "playbook"),
            condition=require_string(value, "condition"),
            classification=classification,
            target_role=require_string(value, "target_role"),
            target_ids=_string_tuple(value["target_ids"], "scope target IDs"),
            target_digest=require_string(value, "target_digest"),
            variables_digest=require_string(value, "variables_digest"),
            source_digest=require_string(value, "source_digest"),
            command_digest=require_string(value, "command_digest"),
            gate_evidence_digest=require_string(value, "gate_evidence_digest"),
            original_step_digest=require_string(value, "original_step_digest"),
            prior_reconciled_step_digest=require_string(
                value, "prior_reconciled_step_digest"
            ),
            reconciled_step_digest=require_string(value, "reconciled_step_digest"),
            package_provenance_digest=require_string(
                value, "package_provenance_digest"
            ),
            install_intent_digest=require_string(value, "install_intent_digest"),
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaInstallAuthorization:
    """Immutable unconsumed authorization for exact install scopes."""

    generation: int
    created_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    stage: str
    scope_kind: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    context_artifact_digest: str
    context_record_digest: str
    original_plan_artifact_digest: str
    original_plan_record_digest: str
    prior_reconciliation_artifact_digest: str
    prior_reconciliation_record_digest: str
    postcheck_execution_artifact_digest: str
    postcheck_execution_binding_digest: str
    postcheck_evidence_artifact_digest: str
    postcheck_evidence_digest: str
    postcheck_reconciliation_artifact_digest: str
    postcheck_reconciliation_record_digest: str
    effective_plan_digest: str
    validated_chain_digest: str
    observation_artifact_digest: str
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
    classification: OperationClassification
    scopes: tuple[DeployScyllaInstallAuthorizationScope, ...]
    stable_id_count: int
    stable_id_set_digest: str
    authorization_scope_digest: str
    install_intent_digest: str
    package_provenance: DeployScyllaInstallPackageProvenance
    non_authorized_blocker_digest: str
    proof: DeployScyllaInstallProofDecision
    authorization_state: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_digest: str
    prior_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_SCHEMA_VERSION
    )
    postcheck_execution_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EXECUTION_SCHEMA_VERSION
    )
    postcheck_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EVIDENCE_SCHEMA_VERSION
    )
    postcheck_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_POSTCHECK_RECONCILIATION_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_SCHEMA_VERSION
            or self.prior_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_SCHEMA_VERSION
            or self.postcheck_execution_schema_version
            != ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EXECUTION_SCHEMA_VERSION
            or self.postcheck_evidence_schema_version
            != ANSIBLE_DEPLOY_STORAGE_POSTCHECK_EVIDENCE_SCHEMA_VERSION
            or self.postcheck_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_POSTCHECK_RECONCILIATION_SCHEMA_VERSION
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
            or not isinstance(
                self.package_provenance, DeployScyllaInstallPackageProvenance
            )
            or not isinstance(self.proof, DeployScyllaInstallProofDecision)
        ):
            raise StatePersistenceError(
                "deploy scylla-install authorization identity or state is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for count in (
            self.journal_generation,
            self.inventory_generation,
            self.trust_generation,
            self.stable_id_count,
        ):
            _positive_integer(count, "deploy scylla-install authorization count")
        stable_ids = tuple(
            sorted({target for scope in self.scopes for target in scope.target_ids})
        )
        if (
            not self.scopes
            or tuple(scope.sequence for scope in self.scopes)
            != tuple(sorted(scope.sequence for scope in self.scopes))
            or len({scope.sequence for scope in self.scopes}) != len(self.scopes)
            or self.stable_id_count != len(stable_ids)
            or self.stable_id_set_digest != _digest_object(list(stable_ids))
            or self.authorization_scope_digest
            != _digest_object([scope.to_object() for scope in self.scopes])
            or any(
                scope.package_provenance_digest
                != self.package_provenance.provenance_digest
                for scope in self.scopes
            )
            or self.install_intent_digest
            != _digest_object([scope.install_intent_digest for scope in self.scopes])
        ):
            raise StatePersistenceError(
                "deploy scylla-install authorization scope summary conflicts"
            )
        for name in self.__dataclass_fields__:
            if name.endswith("_digest"):
                validate_digest(
                    cast(str, getattr(self, name)),
                    "deploy scylla-install authorization binding digest",
                )
        if self.proof.proof_digest != _proof_digest(self, self.proof.to_object()):
            raise StatePersistenceError(
                "deploy scylla-install authorization proof digest conflicts"
            )
        if self.authorization_digest != _authorization_digest(self):
            raise StatePersistenceError(
                "deploy scylla-install authorization digest conflicts"
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
                if name in {"package_provenance", "proof"}
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployScyllaInstallAuthorization:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy scylla-install authorization",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "inventory_generation",
            "trust_generation",
            "stable_id_count",
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
                    DeployScyllaInstallAuthorizationScope.from_object(
                        _mapping(scope, "deploy scylla-install authorization scope")
                    )
                    for scope in _array(
                        item, "deploy scylla-install authorization scopes"
                    )
                )
            elif name == "package_provenance":
                parsed[name] = DeployScyllaInstallPackageProvenance.from_object(
                    _mapping(item, "deploy scylla-install package provenance")
                )
            elif name == "proof":
                parsed[name] = DeployScyllaInstallProofDecision.from_object(
                    _mapping(item, "deploy scylla-install authorization proof")
                )
            elif name == "consumed":
                parsed[name] = _boolean(item, name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaInstallAuthorization:
    record: DeployScyllaInstallAuthorization
    artifact_digest: str


class DeployScyllaInstallAuthorizationStore:
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
        self._path = deploy_scylla_install_authorization_path(paths, operation_id)
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
    ) -> StoredDeployScyllaInstallAuthorization:
        value, artifact_digest = self._file.read()
        record = DeployScyllaInstallAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "deploy scylla-install authorization identity conflicts"
            )
        return StoredDeployScyllaInstallAuthorization(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaInstallAuthorization:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaInstallAuthorization,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployScyllaInstallAuthorization,
        DeployScyllaInstallAuthorizationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy scylla-install authorization operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy scylla-install authorization is immutable; "
                    "use a new operation"
                )
            return current, DeployScyllaInstallAuthorizationArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaInstallAuthorization(record, artifact_digest),
            DeployScyllaInstallAuthorizationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaInstallAuthorizationReport:
    """Strict redacted authorization report without executable inputs."""

    operation_id: uuid.UUID
    artifact_state: DeployScyllaInstallAuthorizationArtifactState
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_state: str
    stage: str
    scope_kind: str
    approval_method: DeployScyllaInstallApprovalMethod
    approval_state: str
    proof_digest: str
    classification: OperationClassification
    playbook: str
    stable_id_count: int
    stable_id_set_digest: str
    authorization_scope_digest: str
    install_intent_digest: str
    release_line: str
    package_version: str
    package_count: int
    package_set_digest: str
    package_provenance_digest: str
    repository_definition_digest: str
    signing_key_artifact_digest: str
    signing_key_identity_digest: str
    postcheck_reconciliation_artifact_digest: str
    postcheck_reconciliation_record_digest: str
    postcheck_evidence_artifact_digest: str
    postcheck_evidence_digest: str
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
        ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_SCHEMA_VERSION
    )
    proof_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_POSTCHECK_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or self.reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_POSTCHECK_RECONCILIATION_SCHEMA_VERSION
            or self.authorization_state != _AUTHORIZED
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.approval_state != "approved"
            or self.classification is not OperationClassification.MUTATING
            or self.playbook != _PLAYBOOK
            or self.stable_id_count < 1
            or self.release_line != SCYLLA_RELEASE_LINE
            or self.package_version != SCYLLA_PACKAGE_VERSION
            or self.package_count != len(SCYLLA_PACKAGES)
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError(
                "deploy scylla-install authorization report is invalid"
            )
        for name in self.__dataclass_fields__:
            if name.endswith("_digest"):
                validate_digest(
                    cast(str, getattr(self, name)),
                    "deploy scylla-install authorization report digest",
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
            "package_policy": {
                "package_count": self.package_count,
                "package_version": self.package_version,
                "package_set_digest": self.package_set_digest,
                "provenance_digest": self.package_provenance_digest,
                "release_line": self.release_line,
                "repository_definition_digest": (self.repository_definition_digest),
                "signing_key_artifact_digest": self.signing_key_artifact_digest,
                "signing_key_identity_digest": self.signing_key_identity_digest,
            },
            "provenance": {
                "ansible_source_digest": self.ansible_source_digest,
                "catalog_digest": self.catalog_digest,
                "inventory_artifact_digest": self.inventory_artifact_digest,
                "postcheck_evidence": {
                    "artifact_digest": self.postcheck_evidence_artifact_digest,
                    "evidence_digest": self.postcheck_evidence_digest,
                },
                "postcheck_reconciliation": {
                    "artifact_digest": (self.postcheck_reconciliation_artifact_digest),
                    "record_digest": self.postcheck_reconciliation_record_digest,
                    "schema_version": self.reconciliation_schema_version,
                },
                "readiness_artifact_digest": self.readiness_artifact_digest,
                "trust_artifact_digest": self.trust_artifact_digest,
            },
            "result": self.artifact_state.value,
            "schema_version": self.schema_version,
            "scope": {
                "digest": self.authorization_scope_digest,
                "install_intent_digest": self.install_intent_digest,
                "kind": self.scope_kind,
                "playbook": self.playbook,
                "stable_id_count": self.stable_id_count,
                "stable_id_set_digest": self.stable_id_set_digest,
            },
            "stage": self.stage,
        }


@dataclass(frozen=True, slots=True)
class _AuthorizationContext:
    post: _StoragePrepareReconciliationContext
    prior: StoredDeployPostStoragePrepareReconciliation
    execution: StoredDeployStoragePostcheckExecution
    evidence: StoredDeployStoragePostcheckEvidence
    reconciliation: StoredDeployPostStoragePostcheckReconciliation


def authorize_deploy_scylla_install(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proof: DeployScyllaInstallAuthorizationProof,
) -> DeployScyllaInstallAuthorizationReport:
    """Authorize exact ready Scylla install scopes without execution."""

    if not isinstance(proof, DeployScyllaInstallAuthorizationProof):
        raise StateConflictError(
            "deploy scylla-install authorization proof is malformed"
        )
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_authorization_artifacts(paths, operation_id)
    _refuse_incompatible_or_later_artifacts(paths, operation_id)
    context = _load_authorization_context(paths, operation_id, lock=lock)
    metadata = context.post.authorization_context.preflight.metadata
    package_provenance = _derive_package_provenance()
    scopes = _derive_authorization_scopes(context, package_provenance)
    scope_digest = _digest_object([scope.to_object() for scope in scopes])
    decision = _normalize_proof(
        proof,
        reconciliation=context.reconciliation,
        scope_digest=scope_digest,
        package_provenance_digest=package_provenance.provenance_digest,
    )
    store = DeployScyllaInstallAuthorizationStore(paths, operation_id)
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
                "deploy scylla-install authorization changed; "
                "re-plan with a new operation"
            )
        state = DeployScyllaInstallAuthorizationArtifactState.REUSED
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
                "deploy scylla-install authorization persistence failed"
            ) from error
    return _build_report(stored, state=state)


def deploy_scylla_install_authorization_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the canonical operation-bound authorization path."""

    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy scylla-install authorization path is not canonical"
        )
    return path


def deploy_scylla_install_authorization_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_FILENAME_SUFFIX):
        return None
    value = name[: -len(DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_FILENAME_SUFFIX)]
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
    post = _load_post_storage_prepare_context(paths, operation_id, lock=lock)
    metadata = post.authorization_context.preflight.metadata
    prior_store = DeployPostStoragePrepareReconciliationStore(paths, operation_id)
    execution_store = DeployStoragePostcheckExecutionStore(paths, operation_id)
    evidence_store = DeployStoragePostcheckEvidenceStore(paths, operation_id)
    reconciliation_store = DeployPostStoragePostcheckReconciliationStore(
        paths, operation_id
    )
    for path, label in (
        (prior_store.path, "post-storage-prepare reconciliation"),
        (execution_store.path, "storage-postcheck execution"),
        (evidence_store.path, "storage-postcheck evidence"),
        (reconciliation_store.path, "post-storage-postcheck reconciliation"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"deploy scylla-install authorization requires complete {label}"
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
            "deploy scylla-install authorization prior chain drifted"
        )
    execution = execution_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    evidence = evidence_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    if (
        execution.record.binding.prior_reconciliation_artifact_digest
        != prior.artifact_digest
        or execution.record.binding.prior_reconciliation_record_digest
        != prior.record.record_digest
        or evidence.record.binding != execution.record.binding
        or not execution.record.all_scopes_completed
        or execution.record.manual_recovery_required
        or len(evidence.record.entries) != execution.record.binding.scope_count
        or any(
            not item.readiness_for_scylla
            or item.failed_check_count
            or item.unknown_check_count
            or item.blocker_count
            or item.manual_recovery_required
            for item in evidence.record.entries
        )
    ):
        raise StateConflictError(
            "deploy scylla-install authorization requires certain complete "
            "storage-postcheck evidence"
        )
    reconciliation = reconciliation_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_reconciliation = _build_post_storage_postcheck_record(
        prior,
        execution,
        evidence,
        steps=_build_post_storage_postcheck_steps(prior, evidence),
        created_at=reconciliation.record.created_at,
    )
    if reconciliation.record != expected_reconciliation:
        raise StateConflictError(
            "deploy scylla-install authorization reconciliation drifted; "
            "use a new operation"
        )
    _validate_current_bindings(post, execution)
    return _AuthorizationContext(post, prior, execution, evidence, reconciliation)


def _validate_current_bindings(
    post: _StoragePrepareReconciliationContext,
    execution: StoredDeployStoragePostcheckExecution,
) -> None:
    loaded = post.authorization_context.preflight.discovery.post.chain.authorization_context.final_routes.post.post.base.host.loaded
    planning = loaded.planning
    deploy = planning.base.deploy
    binding = execution.record.binding
    if (
        deploy.journal.record.generation != binding.journal_generation
        or deploy.journal.digest != binding.journal_digest
        or deploy.journal.record.status is not JournalStatus.IN_PROGRESS
        or deploy.journal.record.phase is not OperationPhase.VERIFY
        or deploy.observation.digest != binding.observation_artifact_digest
        or deploy.inventory.record.generation != binding.inventory_generation
        or deploy.inventory.digest != binding.inventory_artifact_digest
        or deploy.inventory.record.inventory_digest != binding.inventory_digest
        or planning.base.trust.record.generation != binding.trust_generation
        or planning.base.trust.digest != binding.trust_artifact_digest
        or planning.base.trust.record.entries_digest != binding.trust_entries_digest
        or planning.readiness.artifact_digest != binding.readiness_artifact_digest
        or planning.readiness.record.record_digest != binding.readiness_record_digest
        or loaded.catalog_digest != binding.catalog_digest
        or loaded.source.version != binding.source_version
        or loaded.source.digest != binding.source_digest
    ):
        raise StateConflictError(
            "deploy scylla-install authorization current-state binding drifted"
        )


def _derive_package_provenance() -> DeployScyllaInstallPackageProvenance:
    validate_scylla_signing_key(load_scylla_signing_key())
    definition = get_playbook(_PLAYBOOK)
    catalog_entry_digest = _digest_object(
        {
            "check_mode": definition.check_mode.value,
            "classification": definition.classification.value,
            "limit_policy": definition.limit_policy.value,
            "name": definition.name,
            "serial": definition.serial,
            "source_available": definition.source_available,
            "target_groups": list(definition.target_groups),
            "variable_names": [item.name for item in definition.variables],
        }
    )
    values: dict[str, object] = {
        "release_line": SCYLLA_RELEASE_LINE,
        "package_version": SCYLLA_PACKAGE_VERSION,
        "edition": SCYLLA_EDITION,
        "channel": SCYLLA_CHANNEL,
        "package_count": len(SCYLLA_PACKAGES),
        "package_set_digest": _digest_object(list(SCYLLA_PACKAGES)),
        "repository_definition_digest": SCYLLA_REPOSITORY_DEFINITION_DIGEST,
        "signing_key_artifact_digest": SCYLLA_SIGNING_KEY_DIGEST,
        "signing_key_identity_digest": _signing_key_identity_digest(),
        "catalog_entry_digest": catalog_entry_digest,
        "provenance_digest": "",
    }
    values["provenance_digest"] = _package_provenance_digest_from_values(values)
    return DeployScyllaInstallPackageProvenance(**values)  # type: ignore[arg-type]


def _derive_authorization_scopes(
    context: _AuthorizationContext,
    package_provenance: DeployScyllaInstallPackageProvenance,
) -> tuple[DeployScyllaInstallAuthorizationScope, ...]:
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
            "deploy scylla-install authorization-required scope is unavailable"
        )
    loaded = context.post.authorization_context.preflight.discovery.post.chain.authorization_context.final_routes.post.post.base.host.loaded
    inventory_scylla_ids = {
        host.logical_id
        for host in loaded.planning.base.deploy.inventory.record.inventory.hosts
        if host.role is HostRole.SCYLLA
    }
    postcheck_ids = {item.stable_id for item in context.evidence.record.entries}
    expected_ids = tuple(sorted(target for step in ready for target in step.target_ids))
    if (
        len(expected_ids) != len(set(expected_ids))
        or set(expected_ids) != postcheck_ids
        or not set(expected_ids) <= inventory_scylla_ids
        or record.next_target_count != len(expected_ids)
        or record.next_target_set_digest != _digest_object(list(expected_ids))
    ):
        raise StateConflictError(
            "deploy scylla-install authorization target scope drifted"
        )
    playbook_source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
    scopes: list[DeployScyllaInstallAuthorizationScope] = []
    for step in ready:
        _validate_authorizable_step(
            step,
            postcheck_ids=postcheck_ids,
            playbook_source_digest=playbook_source_digest,
        )
        assert step.evidence_digest is not None
        values: dict[str, object] = {
            "sequence": step.sequence,
            "mapping_sequence": step.mapping_sequence,
            "playbook": step.playbook,
            "condition": step.condition,
            "classification": step.classification,
            "target_role": step.target_role,
            "target_ids": step.target_ids,
            "target_digest": step.target_digest,
            "variables_digest": step.variables_digest,
            "source_digest": step.source_digest,
            "command_digest": step.command_digest,
            "gate_evidence_digest": step.evidence_digest,
            "original_step_digest": step.original_step_digest,
            "prior_reconciled_step_digest": step.prior_reconciled_step_digest,
            "reconciled_step_digest": _digest_object(step.to_object()),
            "package_provenance_digest": package_provenance.provenance_digest,
            "install_intent_digest": "",
        }
        values["install_intent_digest"] = _install_intent_digest_from_values(values)
        scopes.append(
            DeployScyllaInstallAuthorizationScope(**values)  # type: ignore[arg-type]
        )
    return tuple(sorted(scopes, key=lambda item: item.sequence))


def _validate_authorizable_step(
    step: DeployBaseOsReconciledStep,
    *,
    postcheck_ids: set[str],
    playbook_source_digest: str,
) -> None:
    if (
        step.mapping_sequence != _MAPPING_SEQUENCE
        or step.playbook != _PLAYBOOK
        or step.condition_state is not DeployConditionState.ACTIVE
        or step.classification is not OperationClassification.MUTATING
        or step.target_role != _TARGET_ROLE
        or len(step.target_ids) != 1
        or not set(step.target_ids) <= postcheck_ids
        or step.target_digest != _digest_object(list(step.target_ids))
        or step.source_digest != playbook_source_digest
        or step.evidence_state
        is not DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED
        or step.evidence_digest is None
    ):
        raise StateConflictError(
            "only exact postchecked Scylla install steps may be authorized"
        )


def _normalize_proof(
    proof: DeployScyllaInstallAuthorizationProof,
    *,
    reconciliation: StoredDeployPostStoragePostcheckReconciliation,
    scope_digest: str,
    package_provenance_digest: str,
) -> DeployScyllaInstallProofDecision:
    if proof.approval_method is None:
        raise StateConflictError("ordinary deploy scylla-install approval is required")
    if not proof.approved:
        raise StateConflictError("ordinary deploy scylla-install approval was denied")
    if (
        proof.allow_destructive
        or proof.destructive_scope_provided
        or proof.narrow_consent_provided
    ):
        raise StateConflictError(
            "destructive and narrow proofs are inapplicable to mutating "
            "scylla-install authorization"
        )
    values: dict[str, object] = {
        "allow_destructive": False,
        "approval_method": proof.approval_method.value,
        "approved": True,
        "destructive_scope_provided": False,
        "narrow_consent_provided": False,
        "proof_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION
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
        package_provenance_digest=package_provenance_digest,
        proof=values,
    )
    return DeployScyllaInstallProofDecision.from_object(values)


def _build_authorization(
    context: _AuthorizationContext,
    *,
    scopes: tuple[DeployScyllaInstallAuthorizationScope, ...],
    package_provenance: DeployScyllaInstallPackageProvenance,
    proof: DeployScyllaInstallProofDecision,
    created_at: str,
) -> DeployScyllaInstallAuthorization:
    post = context.post
    loaded = post.authorization_context.preflight.discovery.post.chain.authorization_context.final_routes.post.post.base.host.loaded
    planning = loaded.planning
    deploy = planning.base.deploy
    binding = context.execution.record.binding
    reconciliation = context.reconciliation.record
    stable_ids = tuple(
        sorted({target for scope in scopes for target in scope.target_ids})
    )
    selected_sequences = {scope.sequence for scope in scopes}
    non_authorized = tuple(
        step for step in reconciliation.steps if step.sequence not in selected_sequences
    )
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": reconciliation.cluster_uuid,
        "cluster_name": reconciliation.cluster_name,
        "operation_id": reconciliation.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "scope_kind": _SCOPE_KIND,
        "request_digest": reconciliation.request_digest,
        "journal_generation": reconciliation.journal_generation,
        "journal_digest": reconciliation.journal_digest,
        "journal_status": reconciliation.journal_status,
        "journal_phase": reconciliation.journal_phase,
        "context_artifact_digest": loaded.context.artifact_digest,
        "context_record_digest": loaded.context.record.record_digest,
        "original_plan_artifact_digest": loaded.plan.artifact_digest,
        "original_plan_record_digest": loaded.plan.record.record_digest,
        "prior_reconciliation_artifact_digest": context.prior.artifact_digest,
        "prior_reconciliation_record_digest": context.prior.record.record_digest,
        "postcheck_execution_artifact_digest": context.execution.artifact_digest,
        "postcheck_execution_binding_digest": binding.binding_digest,
        "postcheck_evidence_artifact_digest": context.evidence.artifact_digest,
        "postcheck_evidence_digest": reconciliation.evidence_digest,
        "postcheck_reconciliation_artifact_digest": (
            context.reconciliation.artifact_digest
        ),
        "postcheck_reconciliation_record_digest": reconciliation.record_digest,
        "effective_plan_digest": reconciliation.effective_plan_digest,
        "validated_chain_digest": binding.validated_chain_digest,
        "observation_artifact_digest": binding.observation_artifact_digest,
        "inventory_generation": binding.inventory_generation,
        "inventory_artifact_digest": binding.inventory_artifact_digest,
        "inventory_digest": binding.inventory_digest,
        "trust_generation": binding.trust_generation,
        "trust_artifact_digest": binding.trust_artifact_digest,
        "trust_entries_digest": binding.trust_entries_digest,
        "readiness_artifact_digest": binding.readiness_artifact_digest,
        "readiness_record_digest": binding.readiness_record_digest,
        "catalog_digest": binding.catalog_digest,
        "ansible_source_version": binding.source_version,
        "ansible_source_digest": binding.source_digest,
        "classification": OperationClassification.MUTATING,
        "scopes": scopes,
        "stable_id_count": len(stable_ids),
        "stable_id_set_digest": _digest_object(list(stable_ids)),
        "authorization_scope_digest": _digest_object(
            [scope.to_object() for scope in scopes]
        ),
        "install_intent_digest": _digest_object(
            [scope.install_intent_digest for scope in scopes]
        ),
        "package_provenance": package_provenance,
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
        or loaded.catalog_digest != binding.catalog_digest
        or loaded.source.digest != binding.source_digest
    ):
        raise StateConflictError(
            "deploy scylla-install authorization current plan drifted"
        )
    values["authorization_digest"] = _authorization_digest_from_values(values)
    return DeployScyllaInstallAuthorization(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployScyllaInstallAuthorization,
    *,
    state: DeployScyllaInstallAuthorizationArtifactState,
) -> DeployScyllaInstallAuthorizationReport:
    record = stored.record
    package = record.package_provenance
    return DeployScyllaInstallAuthorizationReport(
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
        stable_id_count=record.stable_id_count,
        stable_id_set_digest=record.stable_id_set_digest,
        authorization_scope_digest=record.authorization_scope_digest,
        install_intent_digest=record.install_intent_digest,
        release_line=package.release_line,
        package_version=package.package_version,
        package_count=package.package_count,
        package_set_digest=package.package_set_digest,
        package_provenance_digest=package.provenance_digest,
        repository_definition_digest=package.repository_definition_digest,
        signing_key_artifact_digest=package.signing_key_artifact_digest,
        signing_key_identity_digest=package.signing_key_identity_digest,
        postcheck_reconciliation_artifact_digest=(
            record.postcheck_reconciliation_artifact_digest
        ),
        postcheck_reconciliation_record_digest=(
            record.postcheck_reconciliation_record_digest
        ),
        postcheck_evidence_artifact_digest=(record.postcheck_evidence_artifact_digest),
        postcheck_evidence_digest=record.postcheck_evidence_digest,
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


def _signing_key_identity_digest() -> str:
    return _digest_object(
        {
            "fingerprint": SCYLLA_SIGNING_KEY_FINGERPRINT,
            "signing_subkey_fingerprint": SCYLLA_SIGNING_SUBKEY_FINGERPRINT,
            "uid": SCYLLA_SIGNING_KEY_UID,
        }
    )


def _package_provenance_digest(
    value: DeployScyllaInstallPackageProvenance,
) -> str:
    return _package_provenance_digest_from_values(value.to_object())


def _package_provenance_digest_from_values(values: Mapping[str, object]) -> str:
    value = dict(values)
    value["provenance_digest"] = ""
    return _digest_object(value)


def _install_intent_digest(
    scope: DeployScyllaInstallAuthorizationScope,
) -> str:
    return _install_intent_digest_from_values(scope.to_object())


def _install_intent_digest_from_values(values: Mapping[str, object]) -> str:
    return _digest_object(
        {
            "command_digest": values["command_digest"],
            "package_provenance_digest": values["package_provenance_digest"],
            "source_digest": values["source_digest"],
            "target_digest": values["target_digest"],
            "variables_digest": values["variables_digest"],
        }
    )


def _proof_digest(
    record: DeployScyllaInstallAuthorization,
    proof: Mapping[str, object],
) -> str:
    return _proof_digest_values(
        cluster_uuid=record.cluster_uuid,
        operation_id=record.operation_id,
        request_digest=record.request_digest,
        journal_digest=record.journal_digest,
        reconciliation_artifact_digest=(
            record.postcheck_reconciliation_artifact_digest
        ),
        reconciliation_record_digest=(record.postcheck_reconciliation_record_digest),
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
    reconciliation_artifact_digest: str,
    reconciliation_record_digest: str,
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
            "proof": proof_value,
            "reconciliation_artifact_digest": reconciliation_artifact_digest,
            "reconciliation_record_digest": reconciliation_record_digest,
            "request_digest": request_digest,
            "schema_version": (
                ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION
            ),
            "stage": _STAGE,
        }
    )


def _authorization_digest(record: DeployScyllaInstallAuthorization) -> str:
    return _authorization_digest_from_values(record.to_object())


def _authorization_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployScyllaInstallAuthorization.__dataclass_fields__.items():
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
            if name == "package_provenance"
            and isinstance(item, DeployScyllaInstallPackageProvenance)
            else item.to_object()
            if name == "proof" and isinstance(item, DeployScyllaInstallProofDecision)
            else item
        )
    value["authorization_digest"] = ""
    return _digest_object(value)


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
        ".ansible-deploy-scylla-install-execution.json",
        ".ansible-deploy-scylla-install-evidence.json",
        ".ansible-deploy-post-scylla-install-reconciliation.json",
        ".ansible-deploy-scylla-configure",
        ".ansible-deploy-scylla-bootstrap",
        ".ansible-deploy-scylla-health",
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy scylla-install operation history"
        ) from error
    prefix = str(operation_id)
    for entry in entries:
        if entry.name.startswith(prefix) and any(
            fragment in entry.name for fragment in forbidden_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy scylla-install authorization refuses existing execution "
                "or later-stage history"
            )


def _refuse_ambiguous_authorization_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy scylla-install authorization history"
        ) from error
    canonical = str(operation_id)
    suffix = DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_FILENAME_SUFFIX
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
                "deploy scylla-install authorization artifacts are ambiguous"
            )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy scylla-install authorization paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy scylla-install authorization requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


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


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise StatePersistenceError(f"{label} must be a string array")
    return tuple(value)


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
            f"deploy scylla-install authorization {label} is invalid"
        ) from error


__all__ = [
    "ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_PROOF_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_SCHEMA_VERSION",
    "DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_FILENAME_SUFFIX",
    "DeployScyllaInstallApprovalMethod",
    "DeployScyllaInstallAuthorization",
    "DeployScyllaInstallAuthorizationArtifactState",
    "DeployScyllaInstallAuthorizationProof",
    "DeployScyllaInstallAuthorizationReport",
    "DeployScyllaInstallAuthorizationScope",
    "DeployScyllaInstallAuthorizationStore",
    "DeployScyllaInstallPackageProvenance",
    "DeployScyllaInstallProofDecision",
    "StoredDeployScyllaInstallAuthorization",
    "authorize_deploy_scylla_install",
    "deploy_scylla_install_authorization_id_from_filename",
    "deploy_scylla_install_authorization_path",
]
