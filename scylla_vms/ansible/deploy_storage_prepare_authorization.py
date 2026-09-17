"""Immutable destructive authorization for deploy ``storage-prepare``.

This internal owner derives the exact preparation and wipe scopes from the
canonical post-storage-preflight reconciliation.  It records approval only:
it cannot construct execution input, consume authorization, mutate storage, or
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

from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStep,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_plan import DeployConditionState, _digest_object
from scylla_vms.ansible.deploy_storage_preflight import (
    ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION,
    DeployPostStoragePreflightReconciliationStore,
    DeployStoragePreflightAction,
    DeployStoragePreflightEvidenceStore,
    DeployStoragePreflightExecutionState,
    DeployStoragePreflightExecutionStore,
    StoredDeployPostStoragePreflightReconciliation,
    StoredDeployStoragePreflightEvidence,
    StoredDeployStoragePreflightExecution,
    _build_reconciled_steps,
    _build_reconciliation_record,
    _load_storage_preflight_context,
    _read_binding_identity,
    _StoragePreflightContext,
    _validate_execution_prefix,
)
from scylla_vms.ansible.operation_authorization import (
    OPERATION_AUTHORIZATION_FILENAME_SUFFIX,
)
from scylla_vms.ansible.registry import get_playbook
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION
from scylla_vms.ansible.storage_preflight import StorageOwnershipStatus
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

ANSIBLE_DEPLOY_STORAGE_PREPARE_GENERAL_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-prepare-general-proof/v1"
)
ANSIBLE_DEPLOY_STORAGE_PREPARE_WIPE_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-prepare-wipe-proof/v1"
)
ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-prepare-authorization/v1"
)
ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-storage-prepare-authorization-report/v1"
)
DEPLOY_STORAGE_PREPARE_AUTHORIZATION_FILENAME_SUFFIX = (
    ".ansible-deploy-storage-prepare-authorization.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "storage-prepare"
_MAPPING_SEQUENCE = 9
_STAGE = "post-storage-preflight-storage-prepare"
_SCOPE_KIND = "prepare-required-storage"
_AUTHORIZED = "authorized-pre-execution"
_EXECUTION_UNAVAILABLE = "unavailable"
_FINALIZATION_NOT_STARTED = "not-started"
_PUBLIC_WORKFLOW_UNAVAILABLE = "unavailable"
_PROOF_APPROVED = "approved"
_PROOF_MATCHED = "matched"
_PROOF_NOT_REQUIRED = "not-required"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class DeployStoragePrepareApprovalMethod(StrEnum):
    """PLAN-permitted ordinary approval methods."""

    INTERACTIVE = "interactive"
    CLI_YES = "cli-yes"


class DeployStoragePrepareAuthorizationArtifactState(StrEnum):
    """Immutable authorization persistence result."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployStoragePrepareDestructiveScopeProof:
    """Address-free exact destructive scope acknowledged by the operator."""

    prepare_host_count: int
    preparation_target_set_digest: str
    preparation_scope_digest: str

    def __post_init__(self) -> None:
        _nonnegative_integer(
            self.prepare_host_count, "storage-prepare destructive proof host count"
        )
        validate_digest(
            self.preparation_target_set_digest,
            "storage-prepare destructive proof target digest",
        )
        validate_digest(
            self.preparation_scope_digest,
            "storage-prepare destructive proof scope digest",
        )

    @classmethod
    def from_reconciliation(
        cls, reconciliation: StoredDeployPostStoragePreflightReconciliation
    ) -> DeployStoragePrepareDestructiveScopeProof:
        record = reconciliation.record
        return cls(
            record.prepare_required_host_count,
            record.preparation_target_set_digest,
            record.preparation_scope_digest,
        )

    def to_object(self) -> dict[str, object]:
        return {
            "preparation_scope_digest": self.preparation_scope_digest,
            "preparation_target_set_digest": self.preparation_target_set_digest,
            "prepare_host_count": self.prepare_host_count,
        }


@dataclass(frozen=True, slots=True)
class DeployStoragePrepareGeneralAuthorizationProof:
    """Normalized ordinary and destructive proof without caller-owned targets."""

    approval_method: DeployStoragePrepareApprovalMethod | None = None
    approved: bool = False
    allow_destructive: bool = False
    destructive_scope: DeployStoragePrepareDestructiveScopeProof | None = None

    def __post_init__(self) -> None:
        if self.approval_method is not None and not isinstance(
            self.approval_method, DeployStoragePrepareApprovalMethod
        ):
            raise StateConflictError(
                "deploy storage-prepare ordinary approval method is invalid"
            )
        if not isinstance(self.approved, bool) or not isinstance(
            self.allow_destructive, bool
        ):
            raise StateConflictError(
                "deploy storage-prepare general authorization proof is malformed"
            )
        if self.destructive_scope is not None and not isinstance(
            self.destructive_scope, DeployStoragePrepareDestructiveScopeProof
        ):
            raise StateConflictError(
                "deploy storage-prepare destructive scope proof is malformed"
            )


@dataclass(frozen=True, slots=True)
class DeployStoragePrepareWipeAuthorizationProof:
    """Separate exact wipe consent with no raw device identifiers."""

    consented: bool
    wipe_host_count: int
    wipe_target_set_digest: str
    wipe_scope_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.consented, bool):
            raise StateConflictError("deploy storage-prepare wipe consent is malformed")
        _nonnegative_integer(
            self.wipe_host_count, "storage-prepare wipe proof host count"
        )
        validate_digest(
            self.wipe_target_set_digest, "storage-prepare wipe proof target digest"
        )
        validate_digest(
            self.wipe_scope_digest, "storage-prepare wipe proof scope digest"
        )

    @classmethod
    def from_reconciliation(
        cls, reconciliation: StoredDeployPostStoragePreflightReconciliation
    ) -> DeployStoragePrepareWipeAuthorizationProof:
        record = reconciliation.record
        if record.wipe_required_host_count < 1:
            raise StateConflictError(
                "deploy storage-prepare wipe proof is not required"
            )
        return cls(
            True,
            record.wipe_required_host_count,
            record.wipe_target_set_digest,
            record.wipe_scope_digest,
        )

    def to_object(self) -> dict[str, object]:
        return {
            "consented": self.consented,
            "wipe_host_count": self.wipe_host_count,
            "wipe_scope_digest": self.wipe_scope_digest,
            "wipe_target_set_digest": self.wipe_target_set_digest,
        }


@dataclass(frozen=True, slots=True)
class DeployStoragePrepareGeneralProofDecision:
    """Persisted general approval bound to the exact preparation scope."""

    approval_method: DeployStoragePrepareApprovalMethod
    approval_state: str
    allow_destructive: bool
    destructive_scope_state: str
    prepare_host_count: int
    preparation_target_set_digest: str
    preparation_scope_digest: str
    proof_digest: str
    schema_version: str = ANSIBLE_DEPLOY_STORAGE_PREPARE_GENERAL_PROOF_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_GENERAL_PROOF_SCHEMA_VERSION
            or not isinstance(self.approval_method, DeployStoragePrepareApprovalMethod)
            or self.approval_state != _PROOF_APPROVED
            or self.allow_destructive is not True
            or self.destructive_scope_state != _PROOF_MATCHED
        ):
            raise StatePersistenceError(
                "deploy storage-prepare general proof decision is invalid"
            )
        _positive_integer(
            self.prepare_host_count, "storage-prepare general proof host count"
        )
        for value in (
            self.preparation_target_set_digest,
            self.preparation_scope_digest,
            self.proof_digest,
        ):
            validate_digest(value, "deploy storage-prepare general proof digest")

    def to_object(self) -> dict[str, object]:
        return {
            "allow_destructive": self.allow_destructive,
            "approval_method": self.approval_method.value,
            "approval_state": self.approval_state,
            "destructive_scope_state": self.destructive_scope_state,
            "preparation_scope_digest": self.preparation_scope_digest,
            "preparation_target_set_digest": self.preparation_target_set_digest,
            "prepare_host_count": self.prepare_host_count,
            "proof_digest": self.proof_digest,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployStoragePrepareGeneralProofDecision:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy storage-prepare general proof",
        )
        if not isinstance(value["allow_destructive"], bool):
            raise StatePersistenceError(
                "deploy storage-prepare destructive flag is invalid"
            )
        try:
            method = DeployStoragePrepareApprovalMethod(
                require_string(value, "approval_method")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy storage-prepare approval method is invalid"
            ) from error
        return cls(
            approval_method=method,
            approval_state=require_string(value, "approval_state"),
            allow_destructive=value["allow_destructive"],
            destructive_scope_state=require_string(value, "destructive_scope_state"),
            prepare_host_count=_integer(
                value["prepare_host_count"], "prepare host count"
            ),
            preparation_target_set_digest=require_string(
                value, "preparation_target_set_digest"
            ),
            preparation_scope_digest=require_string(value, "preparation_scope_digest"),
            proof_digest=require_string(value, "proof_digest"),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployStoragePrepareWipeProofDecision:
    """Persisted separate wipe consent bound only to the required wipe subset."""

    consent_state: str
    wipe_host_count: int
    wipe_target_set_digest: str
    wipe_scope_digest: str
    proof_digest: str
    schema_version: str = ANSIBLE_DEPLOY_STORAGE_PREPARE_WIPE_PROOF_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_WIPE_PROOF_SCHEMA_VERSION
            or self.consent_state != _PROOF_MATCHED
        ):
            raise StatePersistenceError(
                "deploy storage-prepare wipe proof decision is invalid"
            )
        _positive_integer(
            self.wipe_host_count, "deploy storage-prepare wipe proof host count"
        )
        for value in (
            self.wipe_target_set_digest,
            self.wipe_scope_digest,
            self.proof_digest,
        ):
            validate_digest(value, "deploy storage-prepare wipe proof digest")

    def to_object(self) -> dict[str, object]:
        return {
            "consent_state": self.consent_state,
            "proof_digest": self.proof_digest,
            "schema_version": self.schema_version,
            "wipe_host_count": self.wipe_host_count,
            "wipe_scope_digest": self.wipe_scope_digest,
            "wipe_target_set_digest": self.wipe_target_set_digest,
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployStoragePrepareWipeProofDecision:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy storage-prepare wipe proof",
        )
        return cls(
            consent_state=require_string(value, "consent_state"),
            wipe_host_count=_integer(value["wipe_host_count"], "wipe host count"),
            wipe_target_set_digest=require_string(value, "wipe_target_set_digest"),
            wipe_scope_digest=require_string(value, "wipe_scope_digest"),
            proof_digest=require_string(value, "proof_digest"),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployStoragePrepareAuthorizationScope:
    """One exact prepare-required host scope derived from canonical evidence."""

    sequence: int
    mapping_sequence: int
    playbook: str
    classification: OperationClassification
    stable_id: str
    stable_id_digest: str
    action: DeployStoragePreflightAction
    action_digest: str
    disposition: StorageOwnershipStatus
    disposition_digest: str
    device_count: int
    device_set_digest: str
    preparation_intent_digest: str
    wipe_required: bool
    target_digest: str
    variables_digest: str
    source_digest: str
    command_digest: str
    gate_evidence_digest: str
    prior_reconciled_step_digest: str
    reconciled_step_digest: str
    scope_digest: str

    def __post_init__(self) -> None:
        definition = get_playbook(self.playbook)
        if (
            self.mapping_sequence != _MAPPING_SEQUENCE
            or self.playbook != _PLAYBOOK
            or self.classification is not OperationClassification.DESTRUCTIVE
            or definition.classification is not self.classification
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.action is not DeployStoragePreflightAction.PREPARE_REQUIRED
            or self.disposition
            not in {
                StorageOwnershipStatus.CLEAN_NEW,
                StorageOwnershipStatus.WIPE_REVIEW_REQUIRED,
            }
            or self.wipe_required
            != (self.disposition is StorageOwnershipStatus.WIPE_REVIEW_REQUIRED)
        ):
            raise StatePersistenceError(
                "deploy storage-prepare authorization scope identity is invalid"
            )
        _positive_integer(self.sequence, "storage-prepare authorization sequence")
        _positive_integer(
            self.device_count, "storage-prepare authorization device count"
        )
        for name in self.__dataclass_fields__:
            if name.endswith("_digest"):
                validate_digest(
                    cast(str, getattr(self, name)),
                    "deploy storage-prepare authorization scope digest",
                )
        if (
            self.stable_id_digest != _digest_object(self.stable_id)
            or self.action_digest != _digest_object(self.action.value)
            or self.disposition_digest != _digest_object(self.disposition.value)
            or self.scope_digest != _scope_digest(self)
        ):
            raise StatePersistenceError(
                "deploy storage-prepare authorization scope digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            result[name] = value.value if isinstance(value, StrEnum) else value
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployStoragePrepareAuthorizationScope:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy storage-prepare authorization scope",
        )
        try:
            classification = OperationClassification(
                require_string(value, "classification")
            )
            action = DeployStoragePreflightAction(require_string(value, "action"))
            disposition = StorageOwnershipStatus(require_string(value, "disposition"))
        except ValueError as error:
            raise StatePersistenceError(
                "deploy storage-prepare authorization scope enum is invalid"
            ) from error
        parsed: dict[str, object] = {
            name: require_string(value, name)
            for name in cls.__dataclass_fields__
            if name
            not in {
                "sequence",
                "mapping_sequence",
                "classification",
                "action",
                "disposition",
                "device_count",
                "wipe_required",
            }
        }
        parsed.update(
            {
                "sequence": _integer(value["sequence"], "scope sequence"),
                "mapping_sequence": _integer(
                    value["mapping_sequence"], "scope mapping sequence"
                ),
                "classification": classification,
                "action": action,
                "disposition": disposition,
                "device_count": _integer(value["device_count"], "scope device count"),
                "wipe_required": _boolean(
                    value["wipe_required"], "scope wipe required"
                ),
            }
        )
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class DeployStoragePrepareAuthorization:
    """Immutable, unconsumed authorization for exact destructive host scopes."""

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
    preflight_execution_artifact_digest: str
    preflight_execution_binding_digest: str
    preflight_evidence_artifact_digest: str
    preflight_evidence_digest: str
    preflight_reconciliation_artifact_digest: str
    preflight_reconciliation_record_digest: str
    effective_plan_digest: str
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
    plan_chain_digest: str
    evidence_chain_digest: str
    validated_chain_digest: str
    classification: OperationClassification
    scopes: tuple[DeployStoragePrepareAuthorizationScope, ...]
    prepare_host_count: int
    prepare_device_count: int
    preparation_target_set_digest: str
    preparation_scope_digest: str
    authorization_scope_digest: str
    wipe_host_count: int
    wipe_device_count: int
    wipe_target_set_digest: str
    wipe_scope_digest: str
    wipe_authorization_scope_digest: str
    non_authorized_blocker_digest: str
    general_proof: DeployStoragePrepareGeneralProofDecision
    wipe_proof: DeployStoragePrepareWipeProofDecision | None
    authorization_state: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_digest: str
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    preflight_execution_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION
    )
    preflight_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    )
    preflight_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.preflight_execution_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EXECUTION_SCHEMA_VERSION
            or self.preflight_evidence_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
            or self.preflight_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.classification is not OperationClassification.DESTRUCTIVE
            or self.authorization_state != _AUTHORIZED
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
            or not isinstance(
                self.general_proof, DeployStoragePrepareGeneralProofDecision
            )
            or (
                self.wipe_proof is not None
                and not isinstance(
                    self.wipe_proof, DeployStoragePrepareWipeProofDecision
                )
            )
        ):
            raise StatePersistenceError(
                "deploy storage-prepare authorization identity or state is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for value in (
            self.journal_generation,
            self.inventory_generation,
            self.trust_generation,
            self.prepare_host_count,
            self.prepare_device_count,
        ):
            _positive_integer(value, "deploy storage-prepare authorization count")
        for value in (self.wipe_host_count, self.wipe_device_count):
            _nonnegative_integer(
                value, "deploy storage-prepare wipe authorization count"
            )
        stable_ids = tuple(scope.stable_id for scope in self.scopes)
        wipe_scopes = tuple(scope for scope in self.scopes if scope.wipe_required)
        if (
            not self.scopes
            or stable_ids != tuple(sorted(set(stable_ids)))
            or tuple(scope.sequence for scope in self.scopes)
            != tuple(sorted(scope.sequence for scope in self.scopes))
            or self.prepare_host_count != len(self.scopes)
            or self.prepare_device_count
            != sum(scope.device_count for scope in self.scopes)
            or self.preparation_target_set_digest != _digest_object(list(stable_ids))
            or self.authorization_scope_digest
            != _digest_object([scope.to_object() for scope in self.scopes])
            or self.wipe_host_count != len(wipe_scopes)
            or self.wipe_device_count
            != sum(scope.device_count for scope in wipe_scopes)
            or self.wipe_target_set_digest
            != _digest_object([scope.stable_id for scope in wipe_scopes])
            or self.wipe_authorization_scope_digest
            != _digest_object([scope.to_object() for scope in wipe_scopes])
            or self.general_proof.prepare_host_count != self.prepare_host_count
            or self.general_proof.preparation_target_set_digest
            != self.preparation_target_set_digest
            or self.general_proof.preparation_scope_digest
            != self.preparation_scope_digest
            or (self.wipe_host_count == 0) != (self.wipe_proof is None)
            or (
                self.wipe_proof is not None
                and (
                    self.wipe_proof.wipe_host_count != self.wipe_host_count
                    or self.wipe_proof.wipe_target_set_digest
                    != self.wipe_target_set_digest
                    or self.wipe_proof.wipe_scope_digest != self.wipe_scope_digest
                )
            )
        ):
            raise StatePersistenceError(
                "deploy storage-prepare authorization scope summary conflicts"
            )
        for name in self.__dataclass_fields__:
            if name.endswith("_digest"):
                validate_digest(
                    cast(str, getattr(self, name)),
                    "deploy storage-prepare authorization binding digest",
                )
        if self.general_proof.proof_digest != _general_proof_digest(
            self, self.general_proof.to_object()
        ):
            raise StatePersistenceError(
                "deploy storage-prepare general proof digest conflicts"
            )
        if self.wipe_proof is not None and (
            self.wipe_proof.proof_digest
            != _wipe_proof_digest(self, self.wipe_proof.to_object())
        ):
            raise StatePersistenceError(
                "deploy storage-prepare wipe proof digest conflicts"
            )
        if self.authorization_digest != _authorization_digest(self):
            raise StatePersistenceError(
                "deploy storage-prepare authorization digest conflicts"
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
                if name == "general_proof"
                else value.to_object()
                if name == "wipe_proof" and value is not None
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployStoragePrepareAuthorization:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy storage-prepare authorization",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "inventory_generation",
            "trust_generation",
            "prepare_host_count",
            "prepare_device_count",
            "wipe_host_count",
            "wipe_device_count",
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
                    DeployStoragePrepareAuthorizationScope.from_object(
                        _mapping(scope, "storage-prepare authorization scope")
                    )
                    for scope in _array(item, "storage-prepare authorization scopes")
                )
            elif name == "general_proof":
                parsed[name] = DeployStoragePrepareGeneralProofDecision.from_object(
                    _mapping(item, "storage-prepare general proof")
                )
            elif name == "wipe_proof":
                parsed[name] = (
                    None
                    if item is None
                    else DeployStoragePrepareWipeProofDecision.from_object(
                        _mapping(item, "storage-prepare wipe proof")
                    )
                )
            elif name == "consumed":
                parsed[name] = _boolean(item, name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployStoragePrepareAuthorization:
    record: DeployStoragePrepareAuthorization
    artifact_digest: str


class DeployStoragePrepareAuthorizationStore:
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
        self._path = deploy_storage_prepare_authorization_path(paths, operation_id)
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
    ) -> StoredDeployStoragePrepareAuthorization:
        value, artifact_digest = self._file.read()
        record = DeployStoragePrepareAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "deploy storage-prepare authorization identity conflicts"
            )
        return StoredDeployStoragePrepareAuthorization(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployStoragePrepareAuthorization:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployStoragePrepareAuthorization,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployStoragePrepareAuthorization,
        DeployStoragePrepareAuthorizationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy storage-prepare authorization operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy storage-prepare authorization is immutable; "
                    "use a new operation"
                )
            return current, DeployStoragePrepareAuthorizationArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployStoragePrepareAuthorization(record, artifact_digest),
            DeployStoragePrepareAuthorizationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployStoragePrepareAuthorizationReport:
    """Strict redacted authorization report without executable inputs."""

    operation_id: uuid.UUID
    artifact_state: DeployStoragePrepareAuthorizationArtifactState
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_state: str
    stage: str
    scope_kind: str
    classification: OperationClassification
    prepare_host_count: int
    prepare_device_count: int
    preparation_target_set_digest: str
    preparation_scope_digest: str
    authorization_scope_digest: str
    wipe_host_count: int
    wipe_device_count: int
    wipe_target_set_digest: str
    wipe_scope_digest: str
    wipe_authorization_scope_digest: str
    ordinary_approval_method: DeployStoragePrepareApprovalMethod
    ordinary_approval_state: str
    destructive_flag_state: str
    destructive_scope_state: str
    general_proof_digest: str
    wipe_proof_state: str
    wipe_proof_digest: str | None
    effective_plan_digest: str
    preflight_evidence_digest: str
    inventory_artifact_digest: str
    trust_artifact_digest: str
    readiness_artifact_digest: str
    catalog_digest: str
    ansible_source_digest: str
    validated_chain_digest: str
    blockers_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    journal_digest: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION
    )
    general_proof_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREPARE_GENERAL_PROOF_SCHEMA_VERSION
    )
    wipe_proof_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREPARE_WIPE_PROOF_SCHEMA_VERSION
    )
    reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION
            or self.general_proof_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_GENERAL_PROOF_SCHEMA_VERSION
            or self.wipe_proof_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_WIPE_PROOF_SCHEMA_VERSION
            or self.reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
            or self.authorization_state != _AUTHORIZED
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or self.classification is not OperationClassification.DESTRUCTIVE
            or self.prepare_host_count < 1
            or self.prepare_device_count < 1
            or self.wipe_host_count < 0
            or self.wipe_device_count < 0
            or self.ordinary_approval_state != _PROOF_APPROVED
            or self.destructive_flag_state != _PROOF_MATCHED
            or self.destructive_scope_state != _PROOF_MATCHED
            or self.wipe_proof_state
            != (_PROOF_MATCHED if self.wipe_host_count else _PROOF_NOT_REQUIRED)
            or (self.wipe_host_count == 0) != (self.wipe_proof_digest is None)
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError(
                "deploy storage-prepare authorization report is invalid"
            )
        for name in self.__dataclass_fields__:
            if name.endswith("_digest"):
                item = getattr(self, name)
                if item is not None:
                    validate_digest(
                        cast(str, item),
                        "deploy storage-prepare authorization report digest",
                    )

    def to_object(self) -> dict[str, object]:
        return {
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
            "proofs": {
                "destructive_flag": self.destructive_flag_state,
                "destructive_scope": self.destructive_scope_state,
                "general": {
                    "digest": self.general_proof_digest,
                    "method": self.ordinary_approval_method.value,
                    "schema_version": self.general_proof_schema_version,
                    "state": self.ordinary_approval_state,
                },
                "wipe": {
                    "digest": self.wipe_proof_digest,
                    "schema_version": self.wipe_proof_schema_version,
                    "state": self.wipe_proof_state,
                },
            },
            "provenance": {
                "ansible_source_digest": self.ansible_source_digest,
                "catalog_digest": self.catalog_digest,
                "effective_plan_digest": self.effective_plan_digest,
                "inventory_artifact_digest": self.inventory_artifact_digest,
                "preflight_evidence_digest": self.preflight_evidence_digest,
                "readiness_artifact_digest": self.readiness_artifact_digest,
                "reconciliation_schema_version": self.reconciliation_schema_version,
                "trust_artifact_digest": self.trust_artifact_digest,
                "validated_chain_digest": self.validated_chain_digest,
            },
            "result": self.artifact_state.value,
            "schema_version": self.schema_version,
            "scope": {
                "kind": self.scope_kind,
                "prepare_device_count": self.prepare_device_count,
                "prepare_host_count": self.prepare_host_count,
                "authorization_scope_digest": self.authorization_scope_digest,
                "preparation_scope_digest": self.preparation_scope_digest,
                "preparation_target_set_digest": (self.preparation_target_set_digest),
                "wipe_device_count": self.wipe_device_count,
                "wipe_host_count": self.wipe_host_count,
                "wipe_authorization_scope_digest": (
                    self.wipe_authorization_scope_digest
                ),
                "wipe_scope_digest": self.wipe_scope_digest,
                "wipe_target_set_digest": self.wipe_target_set_digest,
            },
            "stage": self.stage,
        }


@dataclass(frozen=True, slots=True)
class _AuthorizationContext:
    preflight: _StoragePreflightContext
    execution: StoredDeployStoragePreflightExecution
    evidence: StoredDeployStoragePreflightEvidence
    reconciliation: StoredDeployPostStoragePreflightReconciliation


def authorize_deploy_storage_prepare(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    general_proof: DeployStoragePrepareGeneralAuthorizationProof,
    wipe_proof: DeployStoragePrepareWipeAuthorizationProof | None = None,
) -> DeployStoragePrepareAuthorizationReport:
    """Authorize exact prepare-required scopes without execution or mutation."""

    if not isinstance(general_proof, DeployStoragePrepareGeneralAuthorizationProof):
        raise StateConflictError(
            "deploy storage-prepare general authorization proof is malformed"
        )
    if wipe_proof is not None and not isinstance(
        wipe_proof, DeployStoragePrepareWipeAuthorizationProof
    ):
        raise StateConflictError(
            "deploy storage-prepare wipe authorization proof is malformed"
        )
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_authorization_artifacts(paths, operation_id)
    _refuse_incompatible_artifacts(paths, operation_id)
    context = _load_authorization_context(paths, operation_id, lock=lock)
    metadata = context.preflight.metadata
    scopes = _derive_authorization_scopes(context)
    if not scopes:
        raise StateConflictError(
            "deploy storage-prepare authorization has no prepare-required scope"
        )
    general_decision = _normalize_general_proof(general_proof, context.reconciliation)
    wipe_decision = _normalize_wipe_proof(wipe_proof, context.reconciliation)
    store = DeployStoragePrepareAuthorizationStore(paths, operation_id)
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
            general_proof=general_decision,
            wipe_proof=wipe_decision,
            created_at=stored.record.created_at,
        )
        if stored.record != expected:
            raise StateConflictError(
                "deploy storage-prepare authorization changed; "
                "re-plan with a new operation"
            )
        state = DeployStoragePrepareAuthorizationArtifactState.REUSED
    else:
        record = _build_authorization(
            context,
            scopes=scopes,
            general_proof=general_decision,
            wipe_proof=wipe_decision,
            created_at=format_timestamp(datetime.now(UTC)),
        )
        try:
            stored, state = store.write_locked(record, lock=lock)
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy storage-prepare authorization persistence failed"
            ) from error
    return _build_report(stored, state=state)


def deploy_storage_prepare_authorization_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the canonical operation-scoped authorization path."""

    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_STORAGE_PREPARE_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy storage-prepare authorization path is not canonical"
        )
    return path


def deploy_storage_prepare_authorization_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(DEPLOY_STORAGE_PREPARE_AUTHORIZATION_FILENAME_SUFFIX):
        return None
    value = name[: -len(DEPLOY_STORAGE_PREPARE_AUTHORIZATION_FILENAME_SUFFIX)]
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
    execution_store = DeployStoragePreflightExecutionStore(paths, operation_id)
    evidence_store = DeployStoragePreflightEvidenceStore(paths, operation_id)
    reconciliation_store = DeployPostStoragePreflightReconciliationStore(
        paths, operation_id
    )
    for path, label in (
        (execution_store.path, "storage-preflight execution"),
        (evidence_store.path, "storage-preflight evidence"),
        (reconciliation_store.path, "post-storage-preflight reconciliation"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"deploy storage-prepare authorization requires complete {label}"
            )
    cluster_uuid, cluster_name = _read_binding_identity(execution_store.path)
    raw_execution = execution_store.read(
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    binding = raw_execution.record.binding
    preflight = _load_storage_preflight_context(
        paths,
        operation_id,
        lock=lock,
        toolchain_version=binding.toolchain_version,
        executable_identity_digest=binding.executable_identity_digest,
        toolchain_evidence_digest=binding.toolchain_evidence_digest,
    )
    execution = execution_store.read_locked(
        lock,
        expected_cluster_uuid=preflight.metadata.cluster_uuid,
        expected_cluster_name=preflight.metadata.cluster_name,
    )
    evidence = evidence_store.read_locked(
        lock,
        expected_cluster_uuid=preflight.metadata.cluster_uuid,
        expected_cluster_name=preflight.metadata.cluster_name,
    )
    _validate_execution_prefix(preflight, execution, evidence)
    if (
        execution.record.state is not DeployStoragePreflightExecutionState.SUCCEEDED
        or execution.record.manual_recovery_required
        or not evidence.record.successful
    ):
        raise StateConflictError(
            "deploy storage-prepare authorization requires certain "
            "storage-preflight success"
        )
    reconciliation = reconciliation_store.read_locked(
        lock,
        expected_cluster_uuid=preflight.metadata.cluster_uuid,
        expected_cluster_name=preflight.metadata.cluster_name,
    )
    expected = _build_reconciliation_record(
        preflight,
        execution,
        evidence,
        steps=_build_reconciled_steps(preflight, evidence),
        created_at=reconciliation.record.created_at,
    )
    if reconciliation.record != expected:
        raise StateConflictError(
            "deploy storage-prepare authorization reconciliation drifted; "
            "use a new operation"
        )
    return _AuthorizationContext(preflight, execution, evidence, reconciliation)


def _derive_authorization_scopes(
    context: _AuthorizationContext,
) -> tuple[DeployStoragePrepareAuthorizationScope, ...]:
    record = context.reconciliation.record
    preparation = {scope.stable_id: scope for scope in record.preparation_scopes}
    evidence = {host.stable_id: host for host in context.evidence.record.hosts}
    ready = tuple(
        step
        for step in record.steps
        if step.mapping_sequence == _MAPPING_SEQUENCE
        and step.status
        is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
    )
    if (
        record.prepare_required_host_count != len(preparation)
        or record.authorization_required_count != len(ready)
        or len(preparation) != len(ready)
    ):
        raise StateConflictError(
            "deploy storage-prepare authorization-required scope drifted"
        )
    result: list[DeployStoragePrepareAuthorizationScope] = []
    for step in ready:
        _validate_authorizable_step(step)
        stable_id = step.target_ids[0]
        source_scope = preparation.get(stable_id)
        host = evidence.get(stable_id)
        if source_scope is None or host is None:
            raise StateConflictError(
                "deploy storage-prepare authorization scope is incomplete"
            )
        if (
            host.action is not DeployStoragePreflightAction.PREPARE_REQUIRED
            or host.disposition
            not in {
                StorageOwnershipStatus.CLEAN_NEW,
                StorageOwnershipStatus.WIPE_REVIEW_REQUIRED,
            }
            or host.blocker_set
            or source_scope.disposition is not host.disposition
            or source_scope.device_count != host.device_count
            or source_scope.device_set_digest != host.device_set_digest
            or source_scope.preparation_intent_digest != host.preparation_intent_digest
            or source_scope.wipe_required != host.wipe_required
        ):
            raise StateConflictError(
                "only exact prepare-required storage may be authorized"
            )
        assert step.evidence_digest is not None
        values: dict[str, object] = {
            "sequence": step.sequence,
            "mapping_sequence": step.mapping_sequence,
            "playbook": step.playbook,
            "classification": step.classification,
            "stable_id": stable_id,
            "stable_id_digest": _digest_object(stable_id),
            "action": host.action,
            "action_digest": _digest_object(host.action.value),
            "disposition": host.disposition,
            "disposition_digest": _digest_object(host.disposition.value),
            "device_count": host.device_count,
            "device_set_digest": host.device_set_digest,
            "preparation_intent_digest": host.preparation_intent_digest,
            "wipe_required": host.wipe_required,
            "target_digest": step.target_digest,
            "variables_digest": step.variables_digest,
            "source_digest": step.source_digest,
            "command_digest": step.command_digest,
            "gate_evidence_digest": step.evidence_digest,
            "prior_reconciled_step_digest": step.prior_reconciled_step_digest,
            "reconciled_step_digest": _digest_object(step.to_object()),
            "scope_digest": "",
        }
        values["scope_digest"] = _scope_digest_from_values(values)
        result.append(
            DeployStoragePrepareAuthorizationScope(**values)  # type: ignore[arg-type]
        )
    scopes = tuple(sorted(result, key=lambda item: (item.sequence, item.stable_id)))
    if tuple(scope.stable_id for scope in scopes) != tuple(sorted(preparation)):
        raise StateConflictError(
            "deploy storage-prepare authorization scope omits or broadens "
            "prepare-required hosts"
        )
    return scopes


def _validate_authorizable_step(step: DeployBaseOsReconciledStep) -> None:
    if (
        step.mapping_sequence != _MAPPING_SEQUENCE
        or step.playbook != _PLAYBOOK
        or step.condition_state is not DeployConditionState.ACTIVE
        or step.classification is not OperationClassification.DESTRUCTIVE
        or step.status
        is not DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        or step.evidence_state
        is not DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED
        or step.evidence_digest is None
        or len(step.target_ids) != 1
        or step.target_digest != _digest_object(list(step.target_ids))
    ):
        raise StateConflictError(
            "only exact ready storage-prepare steps may be authorized"
        )


def _normalize_general_proof(
    proof: DeployStoragePrepareGeneralAuthorizationProof,
    reconciliation: StoredDeployPostStoragePreflightReconciliation,
) -> DeployStoragePrepareGeneralProofDecision:
    record = reconciliation.record
    if proof.approval_method is None:
        raise StateConflictError("ordinary deploy storage-prepare approval is required")
    if not proof.approved:
        raise StateConflictError("ordinary deploy storage-prepare approval was denied")
    if not proof.allow_destructive:
        raise StateConflictError("deploy storage-prepare requires --allow-destructive")
    if proof.destructive_scope is None:
        raise StateConflictError(
            "deploy storage-prepare requires exact destructive scope proof"
        )
    expected = DeployStoragePrepareDestructiveScopeProof.from_reconciliation(
        reconciliation
    )
    if proof.destructive_scope != expected:
        raise StateConflictError(
            "deploy storage-prepare destructive scope proof does not match "
            "the reviewed preparation scope"
        )
    values: dict[str, object] = {
        "approval_method": proof.approval_method.value,
        "approval_state": _PROOF_APPROVED,
        "allow_destructive": True,
        "destructive_scope_state": _PROOF_MATCHED,
        "prepare_host_count": record.prepare_required_host_count,
        "preparation_target_set_digest": record.preparation_target_set_digest,
        "preparation_scope_digest": record.preparation_scope_digest,
        "proof_digest": "",
        "schema_version": (ANSIBLE_DEPLOY_STORAGE_PREPARE_GENERAL_PROOF_SCHEMA_VERSION),
    }
    values["proof_digest"] = _general_proof_digest_values(reconciliation, values)
    return DeployStoragePrepareGeneralProofDecision.from_object(values)


def _normalize_wipe_proof(
    proof: DeployStoragePrepareWipeAuthorizationProof | None,
    reconciliation: StoredDeployPostStoragePreflightReconciliation,
) -> DeployStoragePrepareWipeProofDecision | None:
    record = reconciliation.record
    if record.wipe_required_host_count == 0:
        if proof is not None:
            raise StateConflictError(
                "deploy storage-prepare wipe proof is over-broad for non-wipe scope"
            )
        return None
    if proof is None:
        raise StateConflictError(
            "deploy storage-prepare requires separate exact wipe consent"
        )
    if not proof.consented:
        raise StateConflictError("deploy storage-prepare wipe consent was denied")
    expected = DeployStoragePrepareWipeAuthorizationProof.from_reconciliation(
        reconciliation
    )
    if proof != expected:
        raise StateConflictError(
            "deploy storage-prepare wipe consent does not match the exact "
            "wipe-required scope"
        )
    values: dict[str, object] = {
        "consent_state": _PROOF_MATCHED,
        "wipe_host_count": record.wipe_required_host_count,
        "wipe_target_set_digest": record.wipe_target_set_digest,
        "wipe_scope_digest": record.wipe_scope_digest,
        "proof_digest": "",
        "schema_version": ANSIBLE_DEPLOY_STORAGE_PREPARE_WIPE_PROOF_SCHEMA_VERSION,
    }
    values["proof_digest"] = _wipe_proof_digest_values(reconciliation, values)
    return DeployStoragePrepareWipeProofDecision.from_object(values)


def _build_authorization(
    context: _AuthorizationContext,
    *,
    scopes: tuple[DeployStoragePrepareAuthorizationScope, ...],
    general_proof: DeployStoragePrepareGeneralProofDecision,
    wipe_proof: DeployStoragePrepareWipeProofDecision | None,
    created_at: str,
) -> DeployStoragePrepareAuthorization:
    preflight = context.preflight
    loaded = preflight.discovery.post.chain.authorization_context.final_routes.post.post.base.host.loaded
    planning = loaded.planning
    deploy = planning.base.deploy
    binding = context.execution.record.binding
    reconciliation = context.reconciliation.record
    wipe_scopes = tuple(scope for scope in scopes if scope.wipe_required)
    non_authorized = tuple(
        step
        for step in reconciliation.steps
        if step.mapping_sequence != _MAPPING_SEQUENCE
        or step.status
        is not DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
    )
    plan_chain_digest = _digest_object(
        {
            "context_artifact_digest": loaded.context.artifact_digest,
            "context_record_digest": loaded.context.record.record_digest,
            "effective_plan_digest": reconciliation.effective_plan_digest,
            "original_plan_artifact_digest": loaded.plan.artifact_digest,
            "original_plan_record_digest": loaded.plan.record.record_digest,
            "preflight_reconciliation_artifact_digest": (
                context.reconciliation.artifact_digest
            ),
            "preflight_reconciliation_record_digest": reconciliation.record_digest,
        }
    )
    evidence_chain_digest = _digest_object(
        {
            "preflight_evidence_artifact_digest": context.evidence.artifact_digest,
            "preflight_evidence_digest": context.evidence.record.evidence_digest,
            "preflight_execution_artifact_digest": context.execution.artifact_digest,
            "preflight_execution_binding_digest": binding.binding_digest,
            "validated_prior_chain_digest": binding.full_chain_digest,
        }
    )
    validated_chain_digest = _digest_object(
        {
            "catalog_digest": binding.catalog_digest,
            "evidence_chain_digest": evidence_chain_digest,
            "inventory_artifact_digest": binding.inventory_artifact_digest,
            "inventory_digest": binding.inventory_digest,
            "journal_digest": binding.journal_digest,
            "plan_chain_digest": plan_chain_digest,
            "readiness_artifact_digest": binding.readiness_artifact_digest,
            "readiness_record_digest": binding.readiness_record_digest,
            "source_digest": binding.source_digest,
            "trust_artifact_digest": binding.trust_artifact_digest,
            "trust_entries_digest": binding.trust_entries_digest,
        }
    )
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": binding.cluster_uuid,
        "cluster_name": binding.cluster_name,
        "operation_id": binding.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "scope_kind": _SCOPE_KIND,
        "request_digest": binding.request_digest,
        "journal_generation": binding.journal_generation,
        "journal_digest": binding.journal_digest,
        "journal_status": binding.journal_status,
        "journal_phase": binding.journal_phase,
        "context_artifact_digest": loaded.context.artifact_digest,
        "context_record_digest": loaded.context.record.record_digest,
        "original_plan_artifact_digest": loaded.plan.artifact_digest,
        "original_plan_record_digest": loaded.plan.record.record_digest,
        "preflight_execution_artifact_digest": context.execution.artifact_digest,
        "preflight_execution_binding_digest": binding.binding_digest,
        "preflight_evidence_artifact_digest": context.evidence.artifact_digest,
        "preflight_evidence_digest": context.evidence.record.evidence_digest,
        "preflight_reconciliation_artifact_digest": (
            context.reconciliation.artifact_digest
        ),
        "preflight_reconciliation_record_digest": reconciliation.record_digest,
        "effective_plan_digest": reconciliation.effective_plan_digest,
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
        "plan_chain_digest": plan_chain_digest,
        "evidence_chain_digest": evidence_chain_digest,
        "validated_chain_digest": validated_chain_digest,
        "classification": OperationClassification.DESTRUCTIVE,
        "scopes": scopes,
        "prepare_host_count": len(scopes),
        "prepare_device_count": sum(scope.device_count for scope in scopes),
        "preparation_target_set_digest": _digest_object(
            [scope.stable_id for scope in scopes]
        ),
        "preparation_scope_digest": reconciliation.preparation_scope_digest,
        "authorization_scope_digest": _digest_object(
            [scope.to_object() for scope in scopes]
        ),
        "wipe_host_count": len(wipe_scopes),
        "wipe_device_count": sum(scope.device_count for scope in wipe_scopes),
        "wipe_target_set_digest": _digest_object(
            [scope.stable_id for scope in wipe_scopes]
        ),
        "wipe_scope_digest": reconciliation.wipe_scope_digest,
        "wipe_authorization_scope_digest": _digest_object(
            [scope.to_object() for scope in wipe_scopes]
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
        "general_proof": general_proof,
        "wipe_proof": wipe_proof,
        "authorization_state": _AUTHORIZED,
        "consumed": False,
        "execution_state": _EXECUTION_UNAVAILABLE,
        "finalization_state": _FINALIZATION_NOT_STARTED,
        "public_workflow_state": _PUBLIC_WORKFLOW_UNAVAILABLE,
        "authorization_digest": "",
    }
    if (
        deploy.journal.record.generation != binding.journal_generation
        or deploy.journal.digest != binding.journal_digest
        or planning.base.trust.digest != binding.trust_artifact_digest
        or planning.readiness.artifact_digest != binding.readiness_artifact_digest
        or loaded.catalog_digest != binding.catalog_digest
        or loaded.source.digest != binding.source_digest
    ):
        raise StateConflictError(
            "deploy storage-prepare authorization current-state binding drifted"
        )
    values["authorization_digest"] = _authorization_digest_from_values(values)
    return DeployStoragePrepareAuthorization(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployStoragePrepareAuthorization,
    *,
    state: DeployStoragePrepareAuthorizationArtifactState,
) -> DeployStoragePrepareAuthorizationReport:
    record = stored.record
    return DeployStoragePrepareAuthorizationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        authorization_artifact_digest=stored.artifact_digest,
        authorization_digest=record.authorization_digest,
        authorization_state=record.authorization_state,
        stage=record.stage,
        scope_kind=record.scope_kind,
        classification=record.classification,
        prepare_host_count=record.prepare_host_count,
        prepare_device_count=record.prepare_device_count,
        preparation_target_set_digest=record.preparation_target_set_digest,
        preparation_scope_digest=record.preparation_scope_digest,
        authorization_scope_digest=record.authorization_scope_digest,
        wipe_host_count=record.wipe_host_count,
        wipe_device_count=record.wipe_device_count,
        wipe_target_set_digest=record.wipe_target_set_digest,
        wipe_scope_digest=record.wipe_scope_digest,
        wipe_authorization_scope_digest=record.wipe_authorization_scope_digest,
        ordinary_approval_method=record.general_proof.approval_method,
        ordinary_approval_state=record.general_proof.approval_state,
        destructive_flag_state=_PROOF_MATCHED,
        destructive_scope_state=record.general_proof.destructive_scope_state,
        general_proof_digest=record.general_proof.proof_digest,
        wipe_proof_state=(
            _PROOF_MATCHED if record.wipe_proof is not None else _PROOF_NOT_REQUIRED
        ),
        wipe_proof_digest=(
            None if record.wipe_proof is None else record.wipe_proof.proof_digest
        ),
        effective_plan_digest=record.effective_plan_digest,
        preflight_evidence_digest=record.preflight_evidence_digest,
        inventory_artifact_digest=record.inventory_artifact_digest,
        trust_artifact_digest=record.trust_artifact_digest,
        readiness_artifact_digest=record.readiness_artifact_digest,
        catalog_digest=record.catalog_digest,
        ansible_source_digest=record.ansible_source_digest,
        validated_chain_digest=record.validated_chain_digest,
        blockers_digest=record.non_authorized_blocker_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        journal_digest=record.journal_digest,
        consumed=record.consumed,
        execution_state=record.execution_state,
        finalization_state=record.finalization_state,
        public_workflow_state=record.public_workflow_state,
    )


def _scope_digest(scope: DeployStoragePrepareAuthorizationScope) -> str:
    value = scope.to_object()
    value["scope_digest"] = ""
    return _digest_object(value)


def _scope_digest_from_values(values: Mapping[str, object]) -> str:
    value = {
        name: (item.value if isinstance(item, StrEnum) else item)
        for name, item in values.items()
    }
    value["scope_digest"] = ""
    return _digest_object(value)


def _general_proof_digest(
    record: DeployStoragePrepareAuthorization,
    proof: Mapping[str, object],
) -> str:
    return _proof_digest_values(
        cluster_uuid=record.cluster_uuid,
        operation_id=record.operation_id,
        journal_digest=record.journal_digest,
        reconciliation_artifact_digest=record.preflight_reconciliation_artifact_digest,
        reconciliation_record_digest=record.preflight_reconciliation_record_digest,
        scope_digest=record.preparation_scope_digest,
        proof=proof,
        schema_version=ANSIBLE_DEPLOY_STORAGE_PREPARE_GENERAL_PROOF_SCHEMA_VERSION,
        proof_kind="general-destructive",
    )


def _general_proof_digest_values(
    reconciliation: StoredDeployPostStoragePreflightReconciliation,
    proof: Mapping[str, object],
) -> str:
    record = reconciliation.record
    return _proof_digest_values(
        cluster_uuid=record.cluster_uuid,
        operation_id=record.operation_id,
        journal_digest=record.journal_digest,
        reconciliation_artifact_digest=reconciliation.artifact_digest,
        reconciliation_record_digest=record.record_digest,
        scope_digest=record.preparation_scope_digest,
        proof=proof,
        schema_version=ANSIBLE_DEPLOY_STORAGE_PREPARE_GENERAL_PROOF_SCHEMA_VERSION,
        proof_kind="general-destructive",
    )


def _wipe_proof_digest(
    record: DeployStoragePrepareAuthorization,
    proof: Mapping[str, object],
) -> str:
    return _proof_digest_values(
        cluster_uuid=record.cluster_uuid,
        operation_id=record.operation_id,
        journal_digest=record.journal_digest,
        reconciliation_artifact_digest=record.preflight_reconciliation_artifact_digest,
        reconciliation_record_digest=record.preflight_reconciliation_record_digest,
        scope_digest=record.wipe_scope_digest,
        proof=proof,
        schema_version=ANSIBLE_DEPLOY_STORAGE_PREPARE_WIPE_PROOF_SCHEMA_VERSION,
        proof_kind="wipe-consent",
    )


def _wipe_proof_digest_values(
    reconciliation: StoredDeployPostStoragePreflightReconciliation,
    proof: Mapping[str, object],
) -> str:
    record = reconciliation.record
    return _proof_digest_values(
        cluster_uuid=record.cluster_uuid,
        operation_id=record.operation_id,
        journal_digest=record.journal_digest,
        reconciliation_artifact_digest=reconciliation.artifact_digest,
        reconciliation_record_digest=record.record_digest,
        scope_digest=record.wipe_scope_digest,
        proof=proof,
        schema_version=ANSIBLE_DEPLOY_STORAGE_PREPARE_WIPE_PROOF_SCHEMA_VERSION,
        proof_kind="wipe-consent",
    )


def _proof_digest_values(
    *,
    cluster_uuid: uuid.UUID,
    operation_id: uuid.UUID,
    journal_digest: str,
    reconciliation_artifact_digest: str,
    reconciliation_record_digest: str,
    scope_digest: str,
    proof: Mapping[str, object],
    schema_version: str,
    proof_kind: str,
) -> str:
    proof_value = dict(proof)
    proof_value["proof_digest"] = ""
    return _digest_object(
        {
            "cluster_uuid": str(cluster_uuid),
            "journal_digest": journal_digest,
            "operation": _OPERATION,
            "operation_id": str(operation_id),
            "proof": proof_value,
            "proof_kind": proof_kind,
            "reconciliation_artifact_digest": reconciliation_artifact_digest,
            "reconciliation_record_digest": reconciliation_record_digest,
            "schema_version": schema_version,
            "scope_digest": scope_digest,
            "stage": _STAGE,
        }
    )


def _authorization_digest(record: DeployStoragePrepareAuthorization) -> str:
    return _authorization_digest_from_values(record.to_object())


def _authorization_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployStoragePrepareAuthorization.__dataclass_fields__.items():
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
            if name == "general_proof"
            and isinstance(item, DeployStoragePrepareGeneralProofDecision)
            else item.to_object()
            if name == "wipe_proof"
            and isinstance(item, DeployStoragePrepareWipeProofDecision)
            else item
        )
    value["authorization_digest"] = ""
    return _digest_object(value)


def _refuse_incompatible_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    generic = (
        paths.operations / f"{operation_id}{OPERATION_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    validate_state_file(generic, allow_missing=True)
    if generic.exists():
        raise StateConflictError(
            "generic Ansible authorization is incompatible with deploy VERIFY binding"
        )
    forbidden_fragments = (
        ".ansible-deploy-storage-prepare-execution.json",
        ".ansible-deploy-storage-prepare-evidence.json",
        ".ansible-deploy-post-storage-prepare-reconciliation.json",
        ".ansible-deploy-storage-postcheck",
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy storage-prepare execution history"
        ) from error
    prefix = f"{operation_id}"
    for entry in entries:
        if entry.name.startswith(prefix) and any(
            fragment in entry.name for fragment in forbidden_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy storage-prepare authorization refuses existing "
                "execution or later-stage history"
            )


def _refuse_ambiguous_authorization_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy storage-prepare authorization history"
        ) from error
    canonical = str(operation_id)
    suffix = DEPLOY_STORAGE_PREPARE_AUTHORIZATION_FILENAME_SUFFIX
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
                "deploy storage-prepare authorization artifacts are ambiguous"
            )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy storage-prepare authorization paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy storage-prepare authorization requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _require_operation_id(value: uuid.UUID) -> uuid.UUID:
    if not isinstance(value, uuid.UUID):
        raise StatePersistenceError(
            "deploy storage-prepare authorization operation ID is invalid"
        )
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _positive_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


def _nonnegative_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StatePersistenceError(f"{label} must be nonnegative")


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
            f"deploy storage-prepare authorization {label} is invalid"
        ) from error


__all__ = [
    "ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_STORAGE_PREPARE_GENERAL_PROOF_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_STORAGE_PREPARE_WIPE_PROOF_SCHEMA_VERSION",
    "DEPLOY_STORAGE_PREPARE_AUTHORIZATION_FILENAME_SUFFIX",
    "DeployStoragePrepareApprovalMethod",
    "DeployStoragePrepareAuthorization",
    "DeployStoragePrepareAuthorizationArtifactState",
    "DeployStoragePrepareAuthorizationReport",
    "DeployStoragePrepareAuthorizationScope",
    "DeployStoragePrepareAuthorizationStore",
    "DeployStoragePrepareDestructiveScopeProof",
    "DeployStoragePrepareGeneralAuthorizationProof",
    "DeployStoragePrepareGeneralProofDecision",
    "DeployStoragePrepareWipeAuthorizationProof",
    "DeployStoragePrepareWipeProofDecision",
    "StoredDeployStoragePrepareAuthorization",
    "authorize_deploy_storage_prepare",
    "deploy_storage_prepare_authorization_id_from_filename",
    "deploy_storage_prepare_authorization_path",
]
