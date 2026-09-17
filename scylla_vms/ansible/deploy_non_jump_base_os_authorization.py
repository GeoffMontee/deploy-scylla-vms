"""Immutable authorization for post-final-routes non-jump ``base-os``.

This internal owner derives one exact authorization scope from the immutable
post-final-routes reconciliation.  It persists ordinary approval only and does
not create execution intent, consume approval, mutate a step, or change the
common journal.
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

from scylla_vms.ansible.deploy_authorization import (
    ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_SCHEMA_VERSION,
    DEPLOY_BASE_OS_AUTHORIZATION_FILENAME_SUFFIX,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStep,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_final_routes import (
    ANSIBLE_DEPLOY_FINAL_ROUTES_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION,
    DeployFinalRoutesEvidenceStore,
    DeployFinalRoutesExecutionState,
    DeployFinalRoutesExecutionStore,
    DeployPostFinalRoutesReconciliationStore,
    StoredDeployFinalRoutesEvidence,
    StoredDeployFinalRoutesExecution,
    StoredDeployPostFinalRoutesReconciliation,
    _build_reconciled_steps,
    _build_reconciliation_record,
    _FinalRoutesContext,
    _load_final_routes_context,
    _validate_execution_prefix,
)
from scylla_vms.ansible.deploy_jump_host_reconciliation import (
    _load_context as _load_post_jump_context,
)
from scylla_vms.ansible.deploy_plan import (
    DeployConditionState,
    _digest_object,
    _require_operation_id,
)
from scylla_vms.ansible.operation_authorization import (
    OPERATION_AUTHORIZATION_FILENAME_SUFFIX,
)
from scylla_vms.ansible.registry import get_playbook
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

ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-non-jump-base-os-authorization/v1"
)
ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-non-jump-base-os-authorization-proof/v1"
)
ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-non-jump-base-os-authorization-report/v1"
)
DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_FILENAME_SUFFIX = (
    ".ansible-deploy-non-jump-base-os-authorization.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "base-os"
_CONDITION = "non-jump-managed-hosts"
_MAPPING_SEQUENCE = 6
_STAGE = "post-final-routes-non-jump-base-os"
_SCOPE_KIND = "non-jump-managed-hosts"
_TARGET_ROLE = "all"
_AUTHORIZED = "authorized-pre-execution"
_EXECUTION_UNAVAILABLE = "unavailable"
_FINALIZATION_NOT_STARTED = "not-started"
_PUBLIC_WORKFLOW_UNAVAILABLE = "unavailable"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SAFE_NON_JUMP_ROLES = frozenset(
    {HostRole.SCYLLA.value, HostRole.MANAGER.value, HostRole.MONITORING.value}
)


class DeployNonJumpBaseOsApprovalMethod(StrEnum):
    """PLAN-permitted ordinary approval methods."""

    INTERACTIVE = "interactive"
    CLI_YES = "cli-yes"


class DeployNonJumpBaseOsAuthorizationArtifactState(StrEnum):
    """Immutable authorization persistence result."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployNonJumpBaseOsAuthorizationProof:
    """Already-normalized ordinary approval without caller-owned scope."""

    approval_method: DeployNonJumpBaseOsApprovalMethod | None = None
    approved: bool = False
    allow_destructive: bool = False
    destructive_scope_provided: bool = False
    narrow_consent_provided: bool = False

    def __post_init__(self) -> None:
        if self.approval_method is not None and not isinstance(
            self.approval_method, DeployNonJumpBaseOsApprovalMethod
        ):
            raise StateConflictError(
                "deploy non-jump base-os approval method is invalid"
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
                "deploy non-jump base-os approval proof is malformed"
            )


@dataclass(frozen=True, slots=True)
class DeployNonJumpBaseOsProofDecision:
    """Persisted normalized ordinary proof bound to one exact scope."""

    approval_method: DeployNonJumpBaseOsApprovalMethod
    approved: bool
    allow_destructive: bool
    destructive_scope_provided: bool
    narrow_consent_provided: bool
    proof_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or not isinstance(self.approval_method, DeployNonJumpBaseOsApprovalMethod)
            or self.approved is not True
            or self.allow_destructive is not False
            or self.destructive_scope_provided is not False
            or self.narrow_consent_provided is not False
        ):
            raise StatePersistenceError(
                "deploy non-jump base-os authorization proof state is invalid"
            )
        validate_digest(
            self.proof_digest,
            "deploy non-jump base-os authorization proof digest",
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
    ) -> DeployNonJumpBaseOsProofDecision:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy non-jump base-os authorization proof",
        )
        for name in (
            "approved",
            "allow_destructive",
            "destructive_scope_provided",
            "narrow_consent_provided",
        ):
            if not isinstance(value[name], bool):
                raise StatePersistenceError(
                    "deploy non-jump base-os authorization proof boolean is invalid"
                )
        try:
            method = DeployNonJumpBaseOsApprovalMethod(
                require_string(value, "approval_method")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy non-jump base-os authorization proof method is invalid"
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
class DeployNonJumpBaseOsAuthorizationScope:
    """Exact ready mapping-position-six scope derived from canonical state."""

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
    host_evidence_digest: str
    final_routes_evidence_digest: str
    original_step_digest: str
    prior_reconciled_step_digest: str
    post_final_routes_step_digest: str

    def __post_init__(self) -> None:
        definition = get_playbook(self.playbook)
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 1
            or self.mapping_sequence != _MAPPING_SEQUENCE
            or self.playbook != _PLAYBOOK
            or self.condition != _CONDITION
            or self.classification is not OperationClassification.MUTATING
            or definition.classification is not self.classification
            or self.target_role != _TARGET_ROLE
            or self.target_ids != tuple(sorted(set(self.target_ids)))
            or not self.target_ids
            or any(
                not target.isascii() or _LOGICAL_ID.fullmatch(target) is None
                for target in self.target_ids
            )
            or self.target_digest != _digest_object(list(self.target_ids))
        ):
            raise StatePersistenceError(
                "deploy non-jump base-os authorization scope policy is invalid"
            )
        for value in (
            self.target_digest,
            self.variables_digest,
            self.source_digest,
            self.command_digest,
            self.host_evidence_digest,
            self.final_routes_evidence_digest,
            self.original_step_digest,
            self.prior_reconciled_step_digest,
            self.post_final_routes_step_digest,
        ):
            validate_digest(value, "deploy non-jump base-os authorization scope digest")

    def to_object(self) -> dict[str, object]:
        return {
            "classification": self.classification.value,
            "command_digest": self.command_digest,
            "condition": self.condition,
            "final_routes_evidence_digest": self.final_routes_evidence_digest,
            "host_evidence_digest": self.host_evidence_digest,
            "mapping_sequence": self.mapping_sequence,
            "original_step_digest": self.original_step_digest,
            "playbook": self.playbook,
            "post_final_routes_step_digest": self.post_final_routes_step_digest,
            "prior_reconciled_step_digest": self.prior_reconciled_step_digest,
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
    ) -> DeployNonJumpBaseOsAuthorizationScope:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy non-jump base-os authorization scope",
        )
        try:
            classification = OperationClassification(
                require_string(value, "classification")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy non-jump base-os authorization scope class is invalid"
            ) from error
        return cls(
            sequence=_integer(value["sequence"], "authorization scope sequence"),
            mapping_sequence=_integer(
                value["mapping_sequence"], "authorization mapping sequence"
            ),
            playbook=require_string(value, "playbook"),
            condition=require_string(value, "condition"),
            classification=classification,
            target_role=require_string(value, "target_role"),
            target_ids=_string_tuple(value["target_ids"], "authorization target IDs"),
            target_digest=require_string(value, "target_digest"),
            variables_digest=require_string(value, "variables_digest"),
            source_digest=require_string(value, "source_digest"),
            command_digest=require_string(value, "command_digest"),
            host_evidence_digest=require_string(value, "host_evidence_digest"),
            final_routes_evidence_digest=require_string(
                value, "final_routes_evidence_digest"
            ),
            original_step_digest=require_string(value, "original_step_digest"),
            prior_reconciled_step_digest=require_string(
                value, "prior_reconciled_step_digest"
            ),
            post_final_routes_step_digest=require_string(
                value, "post_final_routes_step_digest"
            ),
        )


@dataclass(frozen=True, slots=True)
class DeployNonJumpBaseOsAuthorization:
    """Immutable unconsumed authorization for the exact non-jump base-OS gate."""

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
    original_plan_artifact_digest: str
    effective_plan_artifact_digest: str
    prerequisite_execution_artifact_digest: str
    prerequisite_evidence_artifact_digest: str
    pre_mutation_execution_artifact_digest: str
    pre_mutation_evidence_artifact_digest: str
    pre_mutation_evidence_digest: str
    host_reconciliation_artifact_digest: str
    base_os_authorization_artifact_digest: str
    base_os_execution_artifact_digest: str
    base_os_evidence_artifact_digest: str
    base_os_reconciliation_artifact_digest: str
    post_reboot_reconciliation_artifact_digest: str
    jump_authorization_artifact_digest: str
    jump_execution_artifact_digest: str
    jump_evidence_artifact_digest: str
    post_jump_reconciliation_artifact_digest: str
    final_routes_execution_artifact_digest: str
    final_routes_execution_binding_digest: str
    final_routes_evidence_artifact_digest: str
    final_routes_evidence_digest: str
    final_routes_jump_set_digest: str
    final_routes_destination_pair_set_digest: str
    final_routes_full_chain_digest: str
    final_routes_reconciliation_artifact_digest: str
    final_routes_reconciliation_record_digest: str
    final_routes_effective_plan_digest: str
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
    scopes: tuple[DeployNonJumpBaseOsAuthorizationScope, ...]
    playbook_instance_count: int
    role_set: tuple[str, ...]
    role_count: int
    role_set_digest: str
    stable_id_count: int
    stable_id_set_digest: str
    authorization_scope_digest: str
    non_authorized_blocker_digest: str
    proof: DeployNonJumpBaseOsProofDecision
    authorization_state: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_digest: str
    earlier_base_os_authorization_schema_version: str = (
        ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
    )
    final_routes_execution_schema_version: str = (
        ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_SCHEMA_VERSION
    )
    final_routes_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_FINAL_ROUTES_EVIDENCE_SCHEMA_VERSION
    )
    final_routes_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
            or self.earlier_base_os_authorization_schema_version
            != ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
            or self.final_routes_execution_schema_version
            != ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_SCHEMA_VERSION
            or self.final_routes_evidence_schema_version
            != ANSIBLE_DEPLOY_FINAL_ROUTES_EVIDENCE_SCHEMA_VERSION
            or self.final_routes_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION
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
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
            or not isinstance(self.proof, DeployNonJumpBaseOsProofDecision)
        ):
            raise StatePersistenceError(
                "deploy non-jump base-os authorization identity or state is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for value in (
            self.journal_generation,
            self.inventory_generation,
            self.trust_generation,
            self.playbook_instance_count,
            self.role_count,
            self.stable_id_count,
        ):
            _positive_integer(value, "deploy non-jump base-os authorization count")
        stable_ids = tuple(
            sorted({target for scope in self.scopes for target in scope.target_ids})
        )
        if (
            len(self.scopes) != 1
            or self.playbook_instance_count != len(self.scopes)
            or tuple(scope.sequence for scope in self.scopes)
            != tuple(sorted(scope.sequence for scope in self.scopes))
            or stable_ids != self.scopes[0].target_ids
            or self.stable_id_count != len(stable_ids)
            or self.stable_id_set_digest != _digest_object(list(stable_ids))
            or self.authorization_scope_digest
            != _digest_object([scope.to_object() for scope in self.scopes])
            or self.role_set != tuple(sorted(set(self.role_set)))
            or not self.role_set
            or not set(self.role_set) <= _SAFE_NON_JUMP_ROLES
            or HostRole.JUMP_HOST.value in self.role_set
            or self.role_count != len(self.role_set)
            or self.role_set_digest != _digest_object(list(self.role_set))
        ):
            raise StatePersistenceError(
                "deploy non-jump base-os authorization scope summary conflicts"
            )
        for name in self.__dataclass_fields__:
            if name.endswith("_digest"):
                validate_digest(
                    cast(str, getattr(self, name)),
                    "deploy non-jump base-os authorization binding digest",
                )
        if self.proof.proof_digest != _proof_digest(self, self.proof.to_object()):
            raise StatePersistenceError(
                "deploy non-jump base-os authorization proof digest conflicts"
            )
        if self.authorization_digest != _authorization_digest(self):
            raise StatePersistenceError(
                "deploy non-jump base-os authorization record digest conflicts"
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
                if name == "role_set"
                else value.to_object()
                if name == "proof"
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployNonJumpBaseOsAuthorization:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy non-jump base-os authorization",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "inventory_generation",
            "trust_generation",
            "playbook_instance_count",
            "role_count",
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
                    DeployNonJumpBaseOsAuthorizationScope.from_object(
                        _mapping(scope, "deploy non-jump base-os authorization scope")
                    )
                    for scope in _array(
                        item, "deploy non-jump base-os authorization scopes"
                    )
                )
            elif name == "role_set":
                parsed[name] = _string_tuple(item, "authorization role set")
            elif name == "proof":
                parsed[name] = DeployNonJumpBaseOsProofDecision.from_object(
                    _mapping(item, "deploy non-jump base-os authorization proof")
                )
            elif name == "consumed":
                parsed[name] = _boolean(item, name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployNonJumpBaseOsAuthorization:
    record: DeployNonJumpBaseOsAuthorization
    artifact_digest: str


class DeployNonJumpBaseOsAuthorizationStore:
    """Owner-only immutable authorization at its distinct canonical path."""

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
        self._path = deploy_non_jump_base_os_authorization_path(paths, operation_id)
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
    ) -> StoredDeployNonJumpBaseOsAuthorization:
        value, artifact_digest = self._file.read()
        record = DeployNonJumpBaseOsAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "deploy non-jump base-os authorization identity conflicts"
            )
        return StoredDeployNonJumpBaseOsAuthorization(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployNonJumpBaseOsAuthorization:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployNonJumpBaseOsAuthorization,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployNonJumpBaseOsAuthorization,
        DeployNonJumpBaseOsAuthorizationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy non-jump base-os authorization operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy non-jump base-os authorization is immutable; "
                    "use a new operation"
                )
            return current, DeployNonJumpBaseOsAuthorizationArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployNonJumpBaseOsAuthorization(record, artifact_digest),
            DeployNonJumpBaseOsAuthorizationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployNonJumpBaseOsAuthorizationReport:
    """Strict redacted authorization report without executable inputs."""

    operation_id: uuid.UUID
    artifact_state: DeployNonJumpBaseOsAuthorizationArtifactState
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_state: str
    stage: str
    scope_kind: str
    approval_method: DeployNonJumpBaseOsApprovalMethod
    approval_state: str
    proof_digest: str
    classification: OperationClassification
    playbook: str
    playbook_instance_count: int
    role_count: int
    role_set_digest: str
    stable_id_count: int
    stable_id_set_digest: str
    authorization_scope_digest: str
    final_routes_reconciliation_artifact_digest: str
    final_routes_reconciliation_record_digest: str
    final_routes_evidence_artifact_digest: str
    final_routes_evidence_digest: str
    host_evidence_artifact_digest: str
    host_evidence_digest: str
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
        ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
    )
    proof_schema_version: str = (
        ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or self.reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION
            or not isinstance(self.operation_id, uuid.UUID)
            or not isinstance(
                self.artifact_state,
                DeployNonJumpBaseOsAuthorizationArtifactState,
            )
            or self.authorization_state != _AUTHORIZED
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE_KIND
            or not isinstance(self.approval_method, DeployNonJumpBaseOsApprovalMethod)
            or self.approval_state != "approved"
            or self.classification is not OperationClassification.MUTATING
            or self.playbook != _PLAYBOOK
            or self.playbook_instance_count < 1
            or self.role_count < 1
            or self.stable_id_count < 1
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError(
                "deploy non-jump base-os authorization report is invalid"
            )
        for name in self.__dataclass_fields__:
            if name.endswith("_digest"):
                validate_digest(
                    cast(str, getattr(self, name)),
                    "deploy non-jump base-os authorization report digest",
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
            "provenance": {
                "ansible_source_digest": self.ansible_source_digest,
                "catalog_digest": self.catalog_digest,
                "final_routes_evidence": {
                    "artifact_digest": self.final_routes_evidence_artifact_digest,
                    "evidence_digest": self.final_routes_evidence_digest,
                },
                "final_routes_reconciliation": {
                    "artifact_digest": (
                        self.final_routes_reconciliation_artifact_digest
                    ),
                    "record_digest": self.final_routes_reconciliation_record_digest,
                    "schema_version": self.reconciliation_schema_version,
                },
                "host_evidence": {
                    "artifact_digest": self.host_evidence_artifact_digest,
                    "evidence_digest": self.host_evidence_digest,
                },
                "inventory_artifact_digest": self.inventory_artifact_digest,
                "readiness_artifact_digest": self.readiness_artifact_digest,
                "trust_artifact_digest": self.trust_artifact_digest,
            },
            "result": self.artifact_state.value,
            "schema_version": self.schema_version,
            "scope": {
                "digest": self.authorization_scope_digest,
                "kind": self.scope_kind,
                "playbook": self.playbook,
                "playbook_instance_count": self.playbook_instance_count,
                "role_count": self.role_count,
                "role_set_digest": self.role_set_digest,
                "stable_id_count": self.stable_id_count,
                "stable_id_set_digest": self.stable_id_set_digest,
            },
            "stage": self.stage,
        }


@dataclass(frozen=True, slots=True)
class _AuthorizationContext:
    final_routes: _FinalRoutesContext
    execution: StoredDeployFinalRoutesExecution
    evidence: StoredDeployFinalRoutesEvidence
    reconciliation: StoredDeployPostFinalRoutesReconciliation


def authorize_deploy_non_jump_base_os(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proof: DeployNonJumpBaseOsAuthorizationProof,
) -> DeployNonJumpBaseOsAuthorizationReport:
    """Authorize only the exact ready non-jump base-OS scope without execution."""

    if not isinstance(proof, DeployNonJumpBaseOsAuthorizationProof):
        raise StateConflictError(
            "deploy non-jump base-os authorization proof is malformed"
        )
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_authorization_artifacts(paths, operation_id)
    _refuse_incompatible_authorization(paths, operation_id)
    _refuse_uncertain_execution(paths, operation_id)
    context = _load_authorization_context(paths, operation_id, lock=lock)
    metadata = context.final_routes.post.post.base.host.loaded.planning.base.deploy.metadata.record
    scopes, roles = _derive_authorization_scopes(context)
    if not scopes:
        raise StateConflictError(
            "deploy non-jump base-os authorization has no evidence-ready scope"
        )
    scope_digest = _digest_object([scope.to_object() for scope in scopes])
    decision = _normalize_proof(
        proof,
        reconciliation=context.reconciliation,
        scope_digest=scope_digest,
    )
    store = DeployNonJumpBaseOsAuthorizationStore(paths, operation_id)
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
            roles=roles,
            proof=decision,
            created_at=stored.record.created_at,
        )
        if stored.record != expected:
            raise StateConflictError(
                "deploy non-jump base-os authorization changed; "
                "re-plan with a new operation"
            )
        state = DeployNonJumpBaseOsAuthorizationArtifactState.REUSED
    else:
        record = _build_authorization(
            context,
            scopes=scopes,
            roles=roles,
            proof=decision,
            created_at=format_timestamp(datetime.now(UTC)),
        )
        try:
            stored, state = store.write_locked(record, lock=lock)
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy non-jump base-os authorization persistence failed"
            ) from error
    return _build_report(stored, state=state)


def deploy_non_jump_base_os_authorization_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the distinct canonical post-final-routes authorization path."""

    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy non-jump base-os authorization path is not canonical"
        )
    return path


def deploy_non_jump_base_os_authorization_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_FILENAME_SUFFIX):
        return None
    value = name[: -len(DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_FILENAME_SUFFIX)]
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
    # Load once to establish canonical identities before reading final-routes
    # records.  The final-routes loader below independently reloads the same
    # complete chain and binds it to the persisted toolchain evidence.
    post = _load_post_jump_context(paths, operation_id, lock=lock)
    metadata = post.post.base.host.loaded.planning.base.deploy.metadata.record
    execution_store = DeployFinalRoutesExecutionStore(paths, operation_id)
    evidence_store = DeployFinalRoutesEvidenceStore(paths, operation_id)
    reconciliation_store = DeployPostFinalRoutesReconciliationStore(paths, operation_id)
    for path, label in (
        (execution_store.path, "final-routes execution"),
        (evidence_store.path, "final-routes evidence"),
        (reconciliation_store.path, "post-final-routes reconciliation"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"deploy non-jump base-os authorization requires complete {label}"
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
    binding = execution.record.binding
    final_routes = _load_final_routes_context(
        paths,
        operation_id,
        lock=lock,
        toolchain_version=binding.toolchain_version,
        executable_identity_digest=binding.executable_identity_digest,
        toolchain_evidence_digest=binding.toolchain_evidence_digest,
    )
    _validate_execution_prefix(final_routes, execution, evidence)
    if (
        execution.record.state is not DeployFinalRoutesExecutionState.SUCCEEDED
        or execution.record.manual_recovery_required
        or not evidence.record.successful
    ):
        raise StateConflictError(
            "deploy non-jump base-os authorization refuses uncertain "
            "final-routes history"
        )
    reconciliation = reconciliation_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected = _build_reconciliation_record(
        final_routes,
        execution,
        evidence,
        steps=_build_reconciled_steps(final_routes, evidence),
        created_at=reconciliation.record.created_at,
    )
    if reconciliation.record != expected:
        raise StateConflictError(
            "deploy non-jump base-os authorization reconciliation drifted; "
            "use a new operation"
        )
    return _AuthorizationContext(final_routes, execution, evidence, reconciliation)


def _derive_authorization_scopes(
    context: _AuthorizationContext,
) -> tuple[
    tuple[DeployNonJumpBaseOsAuthorizationScope, ...],
    tuple[str, ...],
]:
    record = context.reconciliation.record
    ready = tuple(
        step
        for step in record.steps
        if step.status
        is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
    )
    if len(ready) != record.authorization_required_count:
        raise StateConflictError(
            "deploy non-jump base-os authorization-required count drifted"
        )
    if not ready:
        return (), ()
    if len(ready) != 1 or record.eligible_count != 0:
        raise StateConflictError(
            "deploy non-jump base-os authorization scope is ambiguous"
        )
    planning = context.final_routes.post.post.base.host.loaded.planning
    hosts = planning.base.deploy.inventory.record.inventory.hosts
    non_jump_hosts = tuple(
        sorted(
            (host for host in hosts if host.role is not HostRole.JUMP_HOST),
            key=lambda host: host.logical_id,
        )
    )
    expected_ids = tuple(host.logical_id for host in non_jump_hosts)
    roles = tuple(sorted({host.role.value for host in non_jump_hosts}))
    if (
        not expected_ids
        or not roles
        or not set(roles) <= _SAFE_NON_JUMP_ROLES
        or any(host.role is HostRole.JUMP_HOST for host in non_jump_hosts)
    ):
        raise StateConflictError(
            "deploy non-jump base-os inventory scope is unavailable"
        )
    earlier_targets = {
        target
        for scope in context.final_routes.post.post.base.authorization.record.scopes
        for target in scope.target_ids
    }
    step = ready[0]
    _validate_authorizable_step(
        step,
        expected_ids=expected_ids,
        earlier_targets=earlier_targets,
    )
    assert step.evidence_digest is not None
    host_evidence_digest = (
        context.final_routes.post.post.base.host.pre_mutation_evidence_digest
    )
    return (
        (
            DeployNonJumpBaseOsAuthorizationScope(
                sequence=step.sequence,
                mapping_sequence=step.mapping_sequence,
                playbook=step.playbook,
                condition=step.condition,
                classification=step.classification,
                target_role=step.target_role,
                target_ids=step.target_ids,
                target_digest=step.target_digest,
                variables_digest=step.variables_digest,
                source_digest=step.source_digest,
                command_digest=step.command_digest,
                host_evidence_digest=host_evidence_digest,
                final_routes_evidence_digest=context.evidence.record.evidence_digest,
                original_step_digest=step.original_step_digest,
                prior_reconciled_step_digest=step.prior_reconciled_step_digest,
                post_final_routes_step_digest=_digest_object(step.to_object()),
            ),
        ),
        roles,
    )


def _validate_authorizable_step(
    step: DeployBaseOsReconciledStep,
    *,
    expected_ids: tuple[str, ...],
    earlier_targets: set[str],
) -> None:
    if (
        step.mapping_sequence != _MAPPING_SEQUENCE
        or step.playbook != _PLAYBOOK
        or step.condition != _CONDITION
        or step.condition_state is not DeployConditionState.ACTIVE
        or step.classification is not OperationClassification.MUTATING
        or step.target_role != _TARGET_ROLE
        or step.target_ids != expected_ids
        or step.target_digest != _digest_object(list(expected_ids))
        or not step.target_ids
        or bool(set(step.target_ids) & earlier_targets)
        or step.evidence_state
        is not DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED
        or step.evidence_digest is None
    ):
        raise StateConflictError(
            "only the exact ready non-jump base-os scope may be authorized"
        )


def _normalize_proof(
    proof: DeployNonJumpBaseOsAuthorizationProof,
    *,
    reconciliation: StoredDeployPostFinalRoutesReconciliation,
    scope_digest: str,
) -> DeployNonJumpBaseOsProofDecision:
    if proof.approval_method is None:
        raise StateConflictError(
            "ordinary deploy non-jump base-os approval is required"
        )
    if not proof.approved:
        raise StateConflictError("ordinary deploy non-jump base-os approval was denied")
    if (
        proof.allow_destructive
        or proof.destructive_scope_provided
        or proof.narrow_consent_provided
    ):
        raise StateConflictError(
            "destructive and narrow proofs are inapplicable to mutating "
            "non-jump base-os authorization"
        )
    values: dict[str, object] = {
        "allow_destructive": False,
        "approval_method": proof.approval_method.value,
        "approved": True,
        "destructive_scope_provided": False,
        "narrow_consent_provided": False,
        "proof_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_PROOF_SCHEMA_VERSION
        ),
    }
    values["proof_digest"] = _proof_digest_from_values(
        reconciliation,
        scope_digest=scope_digest,
        proof=values,
    )
    return DeployNonJumpBaseOsProofDecision.from_object(values)


def _build_authorization(
    context: _AuthorizationContext,
    *,
    scopes: tuple[DeployNonJumpBaseOsAuthorizationScope, ...],
    roles: tuple[str, ...],
    proof: DeployNonJumpBaseOsProofDecision,
    created_at: str,
) -> DeployNonJumpBaseOsAuthorization:
    final = context.final_routes
    post_jump = final.post
    post_reboot = post_jump.post
    base = post_reboot.base
    host = base.host
    loaded = host.loaded
    planning = loaded.planning
    deploy = planning.base.deploy
    journal = deploy.journal
    metadata = deploy.metadata.record
    reconciliation = context.reconciliation.record
    stable_ids = tuple(
        sorted({target for scope in scopes for target in scope.target_ids})
    )
    selected_sequences = {scope.sequence for scope in scopes}
    non_authorized = tuple(
        step for step in reconciliation.steps if step.sequence not in selected_sequences
    )
    blocker_values = [
        {
            "blockers": list(step.blockers),
            "playbook": step.playbook,
            "sequence": step.sequence,
            "status": step.status.value,
        }
        for step in non_authorized
    ]
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_name": metadata.cluster_name,
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
        "original_plan_artifact_digest": loaded.plan.artifact_digest,
        "effective_plan_artifact_digest": host.prior_effective.artifact_digest,
        "prerequisite_execution_artifact_digest": loaded.execution.artifact_digest,
        "prerequisite_evidence_artifact_digest": loaded.evidence.artifact_digest,
        "pre_mutation_execution_artifact_digest": host.execution.artifact_digest,
        "pre_mutation_evidence_artifact_digest": host.evidence.artifact_digest,
        "pre_mutation_evidence_digest": host.pre_mutation_evidence_digest,
        "host_reconciliation_artifact_digest": base.prior.artifact_digest,
        "base_os_authorization_artifact_digest": base.authorization.artifact_digest,
        "base_os_execution_artifact_digest": base.execution.artifact_digest,
        "base_os_evidence_artifact_digest": base.evidence.artifact_digest,
        "base_os_reconciliation_artifact_digest": (
            post_reboot.base_reconciliation.artifact_digest
        ),
        "post_reboot_reconciliation_artifact_digest": (
            post_jump.post_reconciliation.artifact_digest
        ),
        "jump_authorization_artifact_digest": post_jump.authorization.artifact_digest,
        "jump_execution_artifact_digest": post_jump.execution.artifact_digest,
        "jump_evidence_artifact_digest": post_jump.evidence.artifact_digest,
        "post_jump_reconciliation_artifact_digest": final.reconciliation.artifact_digest,
        "final_routes_execution_artifact_digest": context.execution.artifact_digest,
        "final_routes_execution_binding_digest": (
            context.execution.record.binding.binding_digest
        ),
        "final_routes_evidence_artifact_digest": context.evidence.artifact_digest,
        "final_routes_evidence_digest": context.evidence.record.evidence_digest,
        "final_routes_jump_set_digest": (
            context.execution.record.binding.jump_set_digest
        ),
        "final_routes_destination_pair_set_digest": (
            context.execution.record.binding.destination_pair_set_digest
        ),
        "final_routes_full_chain_digest": (
            context.execution.record.binding.full_chain_digest
        ),
        "final_routes_reconciliation_artifact_digest": (
            context.reconciliation.artifact_digest
        ),
        "final_routes_reconciliation_record_digest": reconciliation.record_digest,
        "final_routes_effective_plan_digest": reconciliation.effective_plan_digest,
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
        "classification": OperationClassification.MUTATING,
        "scopes": scopes,
        "playbook_instance_count": len(scopes),
        "role_set": roles,
        "role_count": len(roles),
        "role_set_digest": _digest_object(list(roles)),
        "stable_id_count": len(stable_ids),
        "stable_id_set_digest": _digest_object(list(stable_ids)),
        "authorization_scope_digest": _digest_object(
            [scope.to_object() for scope in scopes]
        ),
        "non_authorized_blocker_digest": _digest_object(blocker_values),
        "proof": proof,
        "authorization_state": _AUTHORIZED,
        "consumed": False,
        "execution_state": _EXECUTION_UNAVAILABLE,
        "finalization_state": _FINALIZATION_NOT_STARTED,
        "public_workflow_state": _PUBLIC_WORKFLOW_UNAVAILABLE,
        "authorization_digest": "",
    }
    if (
        journal.record.generation != reconciliation.journal_generation
        or journal.digest != reconciliation.journal_digest
    ):
        raise StateConflictError(
            "deploy non-jump base-os authorization journal drifted"
        )
    values["authorization_digest"] = _authorization_digest_from_values(values)
    return DeployNonJumpBaseOsAuthorization(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployNonJumpBaseOsAuthorization,
    *,
    state: DeployNonJumpBaseOsAuthorizationArtifactState,
) -> DeployNonJumpBaseOsAuthorizationReport:
    record = stored.record
    scope = record.scopes[0]
    return DeployNonJumpBaseOsAuthorizationReport(
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
        playbook_instance_count=record.playbook_instance_count,
        role_count=record.role_count,
        role_set_digest=record.role_set_digest,
        stable_id_count=record.stable_id_count,
        stable_id_set_digest=record.stable_id_set_digest,
        authorization_scope_digest=record.authorization_scope_digest,
        final_routes_reconciliation_artifact_digest=(
            record.final_routes_reconciliation_artifact_digest
        ),
        final_routes_reconciliation_record_digest=(
            record.final_routes_reconciliation_record_digest
        ),
        final_routes_evidence_artifact_digest=(
            record.final_routes_evidence_artifact_digest
        ),
        final_routes_evidence_digest=record.final_routes_evidence_digest,
        host_evidence_artifact_digest=record.pre_mutation_evidence_artifact_digest,
        host_evidence_digest=record.pre_mutation_evidence_digest,
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


def _proof_digest(
    record: DeployNonJumpBaseOsAuthorization,
    proof: Mapping[str, object],
) -> str:
    return _proof_digest_values(
        cluster_uuid=record.cluster_uuid,
        operation_id=record.operation_id,
        request_digest=record.request_digest,
        journal_digest=record.journal_digest,
        reconciliation_artifact_digest=(
            record.final_routes_reconciliation_artifact_digest
        ),
        reconciliation_record_digest=(record.final_routes_reconciliation_record_digest),
        scope_digest=record.authorization_scope_digest,
        proof=proof,
    )


def _proof_digest_from_values(
    reconciliation: StoredDeployPostFinalRoutesReconciliation,
    *,
    scope_digest: str,
    proof: Mapping[str, object],
) -> str:
    record = reconciliation.record
    return _proof_digest_values(
        cluster_uuid=record.cluster_uuid,
        operation_id=record.operation_id,
        request_digest=record.request_digest,
        journal_digest=record.journal_digest,
        reconciliation_artifact_digest=reconciliation.artifact_digest,
        reconciliation_record_digest=record.record_digest,
        scope_digest=scope_digest,
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
            "proof": proof_value,
            "reconciliation_artifact_digest": reconciliation_artifact_digest,
            "reconciliation_record_digest": reconciliation_record_digest,
            "request_digest": request_digest,
            "schema_version": (
                ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_PROOF_SCHEMA_VERSION
            ),
            "stage": _STAGE,
        }
    )


def _authorization_digest(record: DeployNonJumpBaseOsAuthorization) -> str:
    return _authorization_digest_from_values(record.to_object())


def _authorization_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for name, field in DeployNonJumpBaseOsAuthorization.__dataclass_fields__.items():
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
            if name == "role_set" and isinstance(item, tuple)
            else item.to_object()
            if name == "proof" and isinstance(item, DeployNonJumpBaseOsProofDecision)
            else item
        )
    value["authorization_digest"] = ""
    return _digest_object(value)


def _refuse_incompatible_authorization(
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
    earlier = (
        paths.operations
        / f"{operation_id}{DEPLOY_BASE_OS_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    validate_state_file(earlier, allow_missing=True)
    if not earlier.exists():
        raise StateConflictError(
            "deploy non-jump base-os authorization requires the immutable "
            "earlier base-os authorization"
        )
    if earlier == deploy_non_jump_base_os_authorization_path(paths, operation_id):
        raise StatePersistenceError(
            "deploy non-jump base-os authorization path conflicts with earlier scope"
        )


def _refuse_uncertain_execution(paths: StatePaths, operation_id: uuid.UUID) -> None:
    allowed = {
        f"{operation_id}.ansible-deploy-prerequisite-execution.json",
        f"{operation_id}.ansible-deploy-pre-mutation-host-evidence-execution.json",
        f"{operation_id}.ansible-deploy-base-os-execution.json",
        f"{operation_id}.ansible-deploy-reboot-execution.json",
        f"{operation_id}.ansible-deploy-jump-host-configure-execution.json",
        f"{operation_id}.ansible-deploy-final-routes-execution.json",
    }
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy non-jump base-os execution history"
        ) from error
    for entry in entries:
        if str(operation_id) not in entry.name or "execution" not in entry.name:
            continue
        validate_state_file(entry)
        if entry.name not in allowed:
            raise StateConflictError(
                "deploy non-jump base-os authorization refuses uncertain "
                "execution history"
            )


def _refuse_ambiguous_authorization_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy non-jump base-os authorization history"
        ) from error
    canonical = str(operation_id)
    suffix = DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_FILENAME_SUFFIX
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
                "deploy non-jump base-os authorization artifacts are ambiguous"
            )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy non-jump base-os authorization paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy non-jump base-os authorization requires an acquired deploy lock"
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
            f"deploy non-jump base-os authorization {label} is invalid"
        ) from error


__all__ = [
    "ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_PROOF_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_SCHEMA_VERSION",
    "DEPLOY_NON_JUMP_BASE_OS_AUTHORIZATION_FILENAME_SUFFIX",
    "DeployNonJumpBaseOsApprovalMethod",
    "DeployNonJumpBaseOsAuthorization",
    "DeployNonJumpBaseOsAuthorizationArtifactState",
    "DeployNonJumpBaseOsAuthorizationProof",
    "DeployNonJumpBaseOsAuthorizationReport",
    "DeployNonJumpBaseOsAuthorizationScope",
    "DeployNonJumpBaseOsAuthorizationStore",
    "DeployNonJumpBaseOsProofDecision",
    "StoredDeployNonJumpBaseOsAuthorization",
    "authorize_deploy_non_jump_base_os",
    "deploy_non_jump_base_os_authorization_id_from_filename",
    "deploy_non_jump_base_os_authorization_path",
]
