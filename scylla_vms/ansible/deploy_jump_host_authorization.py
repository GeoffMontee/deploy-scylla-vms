"""Immutable authorization for exact post-reboot jump-host configuration.

This internal owner derives the complete authorizable scope from the immutable
post-reboot reconciliation.  It persists ordinary approval only: execution
intent, approval consumption, step mutation, and journal transitions belong to
later separately reviewed owners.
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
)
from scylla_vms.ansible.deploy_base_os_execution import (
    ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_BASE_OS_EXECUTION_SCHEMA_VERSION,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION,
    DeployBaseOsReconciledStep,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_host_evidence import (
    ANSIBLE_DEPLOY_PRE_MUTATION_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_PRE_MUTATION_EXECUTION_SCHEMA_VERSION,
)
from scylla_vms.ansible.deploy_host_reconciliation import (
    ANSIBLE_DEPLOY_HOST_RECONCILIATION_SCHEMA_VERSION,
)
from scylla_vms.ansible.deploy_plan import (
    ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION,
    DeployConditionState,
    _digest_object,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_prerequisites import (
    ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_PREREQUISITE_EXECUTION_SCHEMA_VERSION,
)
from scylla_vms.ansible.deploy_reboot_authorization import (
    ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_REBOOT_PLAN_SCHEMA_VERSION,
)
from scylla_vms.ansible.deploy_reboot_execution import (
    ANSIBLE_DEPLOY_REBOOT_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_REBOOT_EXECUTION_SCHEMA_VERSION,
)
from scylla_vms.ansible.deploy_reboot_reconciliation import (
    ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION,
    DeployPostRebootBranch,
    DeployPostRebootReconciliationStore,
    StoredDeployPostRebootReconciliation,
    _PostRebootContext,
)
from scylla_vms.ansible.deploy_reboot_reconciliation import (
    _build_record as _build_post_reboot_record,
)
from scylla_vms.ansible.deploy_reboot_reconciliation import (
    _build_steps as _build_post_reboot_steps,
)
from scylla_vms.ansible.deploy_reboot_reconciliation import (
    _load_context as _load_post_reboot_context,
)
from scylla_vms.ansible.deploy_reconciliation import (
    ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION,
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
from scylla_vms.terraform.apply_readiness import (
    TERRAFORM_APPLY_READINESS_SCHEMA_VERSION,
)

ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-jump-host-configure-authorization/v1"
)
ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-jump-host-configure-authorization-proof/v1"
)
ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-jump-host-configure-authorization-report/v1"
)
DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_FILENAME_SUFFIX = (
    ".ansible-deploy-jump-host-configure-authorization.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "jump-host-configure"
_MAPPING_SEQUENCE = 4
_TARGET_ROLE = HostRole.JUMP_HOST.value
_AUTHORIZED = "authorized-pre-execution"
_EXECUTION_UNAVAILABLE = "unavailable"
_FINALIZATION_NOT_STARTED = "not-started"
_PUBLIC_WORKFLOW_UNAVAILABLE = "unavailable"
_NON_AUTHORIZED_STATE = "unchanged"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class DeployJumpHostConfigureApprovalMethod(StrEnum):
    """PLAN-permitted ordinary approval methods."""

    INTERACTIVE = "interactive"
    CLI_YES = "cli-yes"


class DeployJumpHostConfigureAuthorizationArtifactState(StrEnum):
    """Immutable authorization persistence result."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployJumpHostConfigureAuthorizationProof:
    """Already-normalized ordinary approval without free-form operator data."""

    approval_method: DeployJumpHostConfigureApprovalMethod | None = None
    approved: bool = False
    allow_destructive: bool = False
    destructive_scope_provided: bool = False

    def __post_init__(self) -> None:
        if self.approval_method is not None and not isinstance(
            self.approval_method, DeployJumpHostConfigureApprovalMethod
        ):
            raise StateConflictError(
                "deploy jump-host-configure approval method is invalid"
            )
        if not all(
            isinstance(value, bool)
            for value in (
                self.approved,
                self.allow_destructive,
                self.destructive_scope_provided,
            )
        ):
            raise StateConflictError(
                "deploy jump-host-configure approval proof is malformed"
            )


@dataclass(frozen=True, slots=True)
class DeployJumpHostConfigureProofDecision:
    """Persisted normalized proof bound to one exact derived scope."""

    approval_method: DeployJumpHostConfigureApprovalMethod
    approved: bool
    allow_destructive: bool
    destructive_scope_provided: bool
    proof_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or not isinstance(
                self.approval_method, DeployJumpHostConfigureApprovalMethod
            )
            or self.approved is not True
            or self.allow_destructive is not False
            or self.destructive_scope_provided is not False
        ):
            raise StatePersistenceError(
                "deploy jump-host-configure authorization proof state is invalid"
            )
        validate_digest(
            self.proof_digest,
            "deploy jump-host-configure authorization proof digest",
        )

    def to_object(self) -> dict[str, object]:
        return {
            "allow_destructive": self.allow_destructive,
            "approval_method": self.approval_method.value,
            "approved": self.approved,
            "destructive_scope_provided": self.destructive_scope_provided,
            "proof_digest": self.proof_digest,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployJumpHostConfigureProofDecision:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy jump-host-configure authorization proof",
        )
        for name in ("approved", "allow_destructive", "destructive_scope_provided"):
            if not isinstance(value[name], bool):
                raise StatePersistenceError(
                    "deploy jump-host-configure proof boolean is invalid"
                )
        try:
            method = DeployJumpHostConfigureApprovalMethod(
                require_string(value, "approval_method")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy jump-host-configure proof method is invalid"
            ) from error
        return cls(
            approval_method=method,
            approved=cast(bool, value["approved"]),
            allow_destructive=cast(bool, value["allow_destructive"]),
            destructive_scope_provided=cast(bool, value["destructive_scope_provided"]),
            proof_digest=require_string(value, "proof_digest"),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployJumpHostConfigureAuthorizationScope:
    """One exact ready jump-host-configure instance derived without caller scope."""

    sequence: int
    mapping_sequence: int
    playbook: str
    classification: OperationClassification
    target_role: str
    target_ids: tuple[str, ...]
    target_digest: str
    variables_digest: str
    source_digest: str
    command_digest: str
    evidence_digest: str
    original_step_digest: str
    prior_reconciled_step_digest: str
    post_reconciled_step_digest: str

    def __post_init__(self) -> None:
        definition = get_playbook(self.playbook)
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 1
            or self.mapping_sequence != _MAPPING_SEQUENCE
            or self.playbook != _PLAYBOOK
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
                "deploy jump-host-configure authorization scope policy is invalid"
            )
        for value in (
            self.target_digest,
            self.variables_digest,
            self.source_digest,
            self.command_digest,
            self.evidence_digest,
            self.original_step_digest,
            self.prior_reconciled_step_digest,
            self.post_reconciled_step_digest,
        ):
            validate_digest(
                value,
                "deploy jump-host-configure authorization scope digest",
            )

    def to_object(self) -> dict[str, object]:
        return {
            "classification": self.classification.value,
            "command_digest": self.command_digest,
            "evidence_digest": self.evidence_digest,
            "mapping_sequence": self.mapping_sequence,
            "original_step_digest": self.original_step_digest,
            "playbook": self.playbook,
            "post_reconciled_step_digest": self.post_reconciled_step_digest,
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
    ) -> DeployJumpHostConfigureAuthorizationScope:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy jump-host-configure authorization scope",
        )
        try:
            classification = OperationClassification(
                require_string(value, "classification")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy jump-host-configure authorization scope class is invalid"
            ) from error
        return cls(
            sequence=_integer(value["sequence"], "authorization scope sequence"),
            mapping_sequence=_integer(
                value["mapping_sequence"], "authorization mapping sequence"
            ),
            playbook=require_string(value, "playbook"),
            classification=classification,
            target_role=require_string(value, "target_role"),
            target_ids=_string_tuple(value["target_ids"], "authorization target IDs"),
            target_digest=require_string(value, "target_digest"),
            variables_digest=require_string(value, "variables_digest"),
            source_digest=require_string(value, "source_digest"),
            command_digest=require_string(value, "command_digest"),
            evidence_digest=require_string(value, "evidence_digest"),
            original_step_digest=require_string(value, "original_step_digest"),
            prior_reconciled_step_digest=require_string(
                value, "prior_reconciled_step_digest"
            ),
            post_reconciled_step_digest=require_string(
                value, "post_reconciled_step_digest"
            ),
        )


@dataclass(frozen=True, slots=True)
class DeployJumpHostConfigureAuthorization:
    """Immutable unconsumed authorization for every exact ready instance."""

    generation: int
    created_at: str
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
    connectivity_evidence_digest: str
    pre_mutation_execution_artifact_digest: str
    pre_mutation_evidence_artifact_digest: str
    host_reconciliation_artifact_digest: str
    host_reconciliation_record_digest: str
    host_reconciled_plan_digest: str
    base_os_authorization_artifact_digest: str
    base_os_execution_artifact_digest: str
    base_os_evidence_artifact_digest: str
    base_os_reconciliation_artifact_digest: str
    base_os_reconciliation_record_digest: str
    base_os_effective_plan_digest: str
    reboot_branch: DeployPostRebootBranch
    reboot_plan_artifact_digest: str | None
    reboot_authorization_artifact_digest: str | None
    reboot_execution_artifact_digest: str | None
    reboot_evidence_artifact_digest: str | None
    reboot_evidence_digest: str | None
    post_reboot_reconciliation_artifact_digest: str
    post_reboot_reconciliation_record_digest: str
    post_reboot_effective_plan_digest: str
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    route_digest: str
    trust_generation: int
    trust_artifact_digest: str
    trust_entries_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    catalog_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    classification: OperationClassification
    scopes: tuple[DeployJumpHostConfigureAuthorizationScope, ...]
    playbook_instance_count: int
    stable_id_count: int
    stable_id_set_digest: str
    authorization_scope_digest: str
    configuration_intent_digest: str
    reconciled_step_count: int
    non_authorized_step_count: int
    prior_succeeded_step_count: int
    blocked_step_count: int
    not_performed_step_count: int
    eligible_step_count: int
    non_authorized_blocker_digest: str
    proof: DeployJumpHostConfigureProofDecision
    authorization_state: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_digest: str
    context_schema_version: str = ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
    original_plan_schema_version: str = ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION
    effective_plan_schema_version: str = ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION
    prerequisite_execution_schema_version: str = (
        ANSIBLE_DEPLOY_PREREQUISITE_EXECUTION_SCHEMA_VERSION
    )
    prerequisite_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_SCHEMA_VERSION
    )
    pre_mutation_execution_schema_version: str = (
        ANSIBLE_DEPLOY_PRE_MUTATION_EXECUTION_SCHEMA_VERSION
    )
    pre_mutation_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_PRE_MUTATION_EVIDENCE_SCHEMA_VERSION
    )
    host_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_HOST_RECONCILIATION_SCHEMA_VERSION
    )
    base_os_authorization_schema_version: str = (
        ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
    )
    base_os_execution_schema_version: str = (
        ANSIBLE_DEPLOY_BASE_OS_EXECUTION_SCHEMA_VERSION
    )
    base_os_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_SCHEMA_VERSION
    )
    base_os_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION
    )
    reboot_plan_schema_version: str = ANSIBLE_DEPLOY_REBOOT_PLAN_SCHEMA_VERSION
    reboot_authorization_schema_version: str = (
        ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_SCHEMA_VERSION
    )
    reboot_execution_schema_version: str = (
        ANSIBLE_DEPLOY_REBOOT_EXECUTION_SCHEMA_VERSION
    )
    reboot_evidence_schema_version: str = ANSIBLE_DEPLOY_REBOOT_EVIDENCE_SCHEMA_VERSION
    post_reboot_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
            or self.context_schema_version != ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION
            or self.original_plan_schema_version != ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION
            or self.effective_plan_schema_version
            != ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION
            or self.prerequisite_execution_schema_version
            != ANSIBLE_DEPLOY_PREREQUISITE_EXECUTION_SCHEMA_VERSION
            or self.prerequisite_evidence_schema_version
            != ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_SCHEMA_VERSION
            or self.pre_mutation_execution_schema_version
            != ANSIBLE_DEPLOY_PRE_MUTATION_EXECUTION_SCHEMA_VERSION
            or self.pre_mutation_evidence_schema_version
            != ANSIBLE_DEPLOY_PRE_MUTATION_EVIDENCE_SCHEMA_VERSION
            or self.host_reconciliation_schema_version
            != ANSIBLE_DEPLOY_HOST_RECONCILIATION_SCHEMA_VERSION
            or self.base_os_authorization_schema_version
            != ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
            or self.base_os_execution_schema_version
            != ANSIBLE_DEPLOY_BASE_OS_EXECUTION_SCHEMA_VERSION
            or self.base_os_evidence_schema_version
            != ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_SCHEMA_VERSION
            or self.base_os_reconciliation_schema_version
            != ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION
            or self.reboot_plan_schema_version
            != ANSIBLE_DEPLOY_REBOOT_PLAN_SCHEMA_VERSION
            or self.reboot_authorization_schema_version
            != ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_SCHEMA_VERSION
            or self.reboot_execution_schema_version
            != ANSIBLE_DEPLOY_REBOOT_EXECUTION_SCHEMA_VERSION
            or self.reboot_evidence_schema_version
            != ANSIBLE_DEPLOY_REBOOT_EVIDENCE_SCHEMA_VERSION
            or self.post_reboot_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
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
            or not isinstance(self.reboot_branch, DeployPostRebootBranch)
            or not isinstance(self.proof, DeployJumpHostConfigureProofDecision)
        ):
            raise StatePersistenceError(
                "deploy jump-host-configure authorization identity or state is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for value in (
            self.journal_generation,
            self.inventory_generation,
            self.trust_generation,
            self.playbook_instance_count,
            self.stable_id_count,
            self.reconciled_step_count,
            self.non_authorized_step_count,
            self.prior_succeeded_step_count,
            self.blocked_step_count,
            self.not_performed_step_count,
            self.eligible_step_count,
        ):
            _nonnegative_integer(
                value, "deploy jump-host-configure authorization count"
            )
        stable_ids = tuple(
            sorted({target for scope in self.scopes for target in scope.target_ids})
        )
        if (
            self.journal_generation < 1
            or self.inventory_generation < 1
            or self.trust_generation < 1
            or not self.scopes
            or tuple(scope.sequence for scope in self.scopes)
            != tuple(sorted(scope.sequence for scope in self.scopes))
            or len({scope.sequence for scope in self.scopes}) != len(self.scopes)
            or self.playbook_instance_count != len(self.scopes)
            or self.stable_id_count != len(stable_ids)
            or self.stable_id_count < 1
            or self.stable_id_set_digest != _digest_object(list(stable_ids))
            or self.authorization_scope_digest
            != _digest_object([scope.to_object() for scope in self.scopes])
            or self.configuration_intent_digest
            != _configuration_intent_digest(self.scopes)
            or self.non_authorized_step_count
            != self.reconciled_step_count - self.playbook_instance_count
            or self.non_authorized_step_count
            != self.prior_succeeded_step_count
            + self.blocked_step_count
            + self.not_performed_step_count
            + self.eligible_step_count
        ):
            raise StatePersistenceError(
                "deploy jump-host-configure authorization scope summary conflicts"
            )
        optional_reboot = _optional_reboot_digests(self)
        if self.reboot_branch is DeployPostRebootBranch.NO_REBOOT_REQUIRED:
            if any(value is not None for value in optional_reboot):
                raise StatePersistenceError(
                    "deploy jump-host-configure no-reboot bindings conflict"
                )
        elif any(value is None for value in optional_reboot):
            raise StatePersistenceError(
                "deploy jump-host-configure reboot bindings are incomplete"
            )
        for digest_value in _required_digest_values(self):
            validate_digest(
                digest_value,
                "deploy jump-host-configure authorization binding digest",
            )
        for optional_digest in optional_reboot:
            if optional_digest is not None:
                validate_digest(
                    optional_digest,
                    "deploy jump-host-configure reboot binding digest",
                )
        if self.proof.proof_digest != _proof_digest(self, self.proof.to_object()):
            raise StatePersistenceError(
                "deploy jump-host-configure proof digest conflicts"
            )
        if self.authorization_digest != _authorization_digest(self):
            raise StatePersistenceError(
                "deploy jump-host-configure authorization digest conflicts"
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
                    (
                        JournalStatus,
                        OperationPhase,
                        OperationClassification,
                        DeployPostRebootBranch,
                    ),
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
    ) -> DeployJumpHostConfigureAuthorization:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy jump-host-configure authorization",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "inventory_generation",
            "trust_generation",
            "playbook_instance_count",
            "stable_id_count",
            "reconciled_step_count",
            "non_authorized_step_count",
            "prior_succeeded_step_count",
            "blocked_step_count",
            "not_performed_step_count",
            "eligible_step_count",
        }
        optional_fields = {
            "reboot_plan_artifact_digest",
            "reboot_authorization_artifact_digest",
            "reboot_execution_artifact_digest",
            "reboot_evidence_artifact_digest",
            "reboot_evidence_digest",
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
            elif name == "reboot_branch":
                parsed[name] = _enum(
                    DeployPostRebootBranch,
                    require_string(value, name),
                    "reboot branch",
                )
            elif name == "scopes":
                parsed[name] = tuple(
                    DeployJumpHostConfigureAuthorizationScope.from_object(
                        _mapping(scope, "jump-host-configure authorization scope")
                    )
                    for scope in _array(
                        item, "jump-host-configure authorization scopes"
                    )
                )
            elif name == "proof":
                parsed[name] = DeployJumpHostConfigureProofDecision.from_object(
                    _mapping(item, "jump-host-configure authorization proof")
                )
            elif name == "consumed":
                parsed[name] = _boolean(item, name)
            elif name in optional_fields:
                parsed[name] = _optional_string(item, name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployJumpHostConfigureAuthorization:
    record: DeployJumpHostConfigureAuthorization
    artifact_digest: str


class DeployJumpHostConfigureAuthorizationStore:
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
        self._path = deploy_jump_host_configure_authorization_path(paths, operation_id)
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
    ) -> StoredDeployJumpHostConfigureAuthorization:
        value, artifact_digest = self._file.read()
        record = DeployJumpHostConfigureAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "deploy jump-host-configure authorization identity conflicts"
            )
        return StoredDeployJumpHostConfigureAuthorization(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployJumpHostConfigureAuthorization:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployJumpHostConfigureAuthorization,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployJumpHostConfigureAuthorization,
        DeployJumpHostConfigureAuthorizationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy jump-host-configure authorization operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy jump-host-configure authorization is immutable; "
                    "use a new operation"
                )
            return (
                current,
                DeployJumpHostConfigureAuthorizationArtifactState.REUSED,
            )
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployJumpHostConfigureAuthorization(record, artifact_digest),
            DeployJumpHostConfigureAuthorizationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployJumpHostConfigureAuthorizationReport:
    """Strict redacted authorization report without executable inputs."""

    operation_id: uuid.UUID
    artifact_state: DeployJumpHostConfigureAuthorizationArtifactState
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_state: str
    approval_method: DeployJumpHostConfigureApprovalMethod
    approved: bool
    proof_digest: str
    classification: OperationClassification
    playbook_instance_count: int
    stable_id_count: int
    stable_id_set_digest: str
    authorization_scope_digest: str
    configuration_intent_digest: str
    post_reboot_reconciliation_artifact_digest: str
    post_reboot_reconciliation_record_digest: str
    post_reboot_effective_plan_digest: str
    context_artifact_digest: str
    original_plan_artifact_digest: str
    effective_plan_artifact_digest: str
    host_reconciliation_artifact_digest: str
    base_os_reconciliation_artifact_digest: str
    base_os_authorization_artifact_digest: str
    base_os_execution_artifact_digest: str
    base_os_evidence_artifact_digest: str
    reboot_branch: DeployPostRebootBranch
    reboot_plan_artifact_digest: str | None
    reboot_authorization_artifact_digest: str | None
    reboot_execution_artifact_digest: str | None
    reboot_evidence_artifact_digest: str | None
    prerequisite_execution_artifact_digest: str
    prerequisite_evidence_artifact_digest: str
    pre_mutation_execution_artifact_digest: str
    pre_mutation_evidence_artifact_digest: str
    inventory_artifact_digest: str
    trust_artifact_digest: str
    readiness_artifact_digest: str
    catalog_digest: str
    ansible_source_digest: str
    non_authorized_step_count: int
    non_authorized_state: str
    non_authorized_blocker_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    journal_digest: str
    consumed: bool
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
    )
    proof_schema_version: str = (
        ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    post_reboot_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_REPORT_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or self.post_reboot_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION
            or not isinstance(self.operation_id, uuid.UUID)
            or not isinstance(
                self.artifact_state,
                DeployJumpHostConfigureAuthorizationArtifactState,
            )
            or self.authorization_state != _AUTHORIZED
            or not isinstance(
                self.approval_method, DeployJumpHostConfigureApprovalMethod
            )
            or self.approved is not True
            or self.classification is not OperationClassification.MUTATING
            or self.playbook_instance_count < 1
            or self.stable_id_count < 1
            or self.non_authorized_state != _NON_AUTHORIZED_STATE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.consumed
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _FINALIZATION_NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
            or not isinstance(self.reboot_branch, DeployPostRebootBranch)
        ):
            raise StatePersistenceError(
                "deploy jump-host-configure authorization report is invalid"
            )
        _nonnegative_integer(
            self.non_authorized_step_count,
            "deploy jump-host-configure non-authorized step count",
        )
        for digest_value in (
            self.authorization_artifact_digest,
            self.authorization_digest,
            self.proof_digest,
            self.stable_id_set_digest,
            self.authorization_scope_digest,
            self.configuration_intent_digest,
            self.post_reboot_reconciliation_artifact_digest,
            self.post_reboot_reconciliation_record_digest,
            self.post_reboot_effective_plan_digest,
            self.context_artifact_digest,
            self.original_plan_artifact_digest,
            self.effective_plan_artifact_digest,
            self.host_reconciliation_artifact_digest,
            self.base_os_reconciliation_artifact_digest,
            self.base_os_authorization_artifact_digest,
            self.base_os_execution_artifact_digest,
            self.base_os_evidence_artifact_digest,
            self.prerequisite_execution_artifact_digest,
            self.prerequisite_evidence_artifact_digest,
            self.pre_mutation_execution_artifact_digest,
            self.pre_mutation_evidence_artifact_digest,
            self.inventory_artifact_digest,
            self.trust_artifact_digest,
            self.readiness_artifact_digest,
            self.catalog_digest,
            self.ansible_source_digest,
            self.non_authorized_blocker_digest,
            self.journal_digest,
        ):
            validate_digest(
                digest_value,
                "deploy jump-host-configure authorization report digest",
            )
        optional_reboot = (
            self.reboot_plan_artifact_digest,
            self.reboot_authorization_artifact_digest,
            self.reboot_execution_artifact_digest,
            self.reboot_evidence_artifact_digest,
        )
        if self.reboot_branch is DeployPostRebootBranch.NO_REBOOT_REQUIRED:
            if any(value is not None for value in optional_reboot):
                raise StatePersistenceError(
                    "deploy jump-host-configure report no-reboot bindings conflict"
                )
        elif any(value is None for value in optional_reboot):
            raise StatePersistenceError(
                "deploy jump-host-configure report reboot bindings are incomplete"
            )
        for optional_digest in optional_reboot:
            if optional_digest is not None:
                validate_digest(
                    optional_digest,
                    "deploy jump-host-configure report reboot digest",
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
            "non_authorized_steps": {
                "blocker_digest": self.non_authorized_blocker_digest,
                "state": self.non_authorized_state,
                "total_count": self.non_authorized_step_count,
            },
            "operation": {
                "classification": self.classification.value,
                "id": str(self.operation_id),
                "kind": _OPERATION,
            },
            "proof": {
                "approved": self.approved,
                "digest": self.proof_digest,
                "method": self.approval_method.value,
                "schema_version": self.proof_schema_version,
            },
            "provenance": {
                "ansible_source_digest": self.ansible_source_digest,
                "base_os_authorization_artifact_digest": (
                    self.base_os_authorization_artifact_digest
                ),
                "base_os_evidence_artifact_digest": (
                    self.base_os_evidence_artifact_digest
                ),
                "base_os_execution_artifact_digest": (
                    self.base_os_execution_artifact_digest
                ),
                "base_os_reconciliation_artifact_digest": (
                    self.base_os_reconciliation_artifact_digest
                ),
                "catalog_digest": self.catalog_digest,
                "context_artifact_digest": self.context_artifact_digest,
                "effective_plan_artifact_digest": (self.effective_plan_artifact_digest),
                "host_reconciliation_artifact_digest": (
                    self.host_reconciliation_artifact_digest
                ),
                "inventory_artifact_digest": self.inventory_artifact_digest,
                "original_plan_artifact_digest": (self.original_plan_artifact_digest),
                "post_reboot_reconciliation": {
                    "artifact_digest": (
                        self.post_reboot_reconciliation_artifact_digest
                    ),
                    "effective_plan_digest": self.post_reboot_effective_plan_digest,
                    "record_digest": self.post_reboot_reconciliation_record_digest,
                    "schema_version": (self.post_reboot_reconciliation_schema_version),
                },
                "pre_mutation_evidence_artifact_digest": (
                    self.pre_mutation_evidence_artifact_digest
                ),
                "pre_mutation_execution_artifact_digest": (
                    self.pre_mutation_execution_artifact_digest
                ),
                "prerequisite_evidence_artifact_digest": (
                    self.prerequisite_evidence_artifact_digest
                ),
                "prerequisite_execution_artifact_digest": (
                    self.prerequisite_execution_artifact_digest
                ),
                "readiness_artifact_digest": self.readiness_artifact_digest,
                "reboot": {
                    "authorization_artifact_digest": (
                        self.reboot_authorization_artifact_digest
                    ),
                    "branch": self.reboot_branch.value,
                    "evidence_artifact_digest": self.reboot_evidence_artifact_digest,
                    "execution_artifact_digest": self.reboot_execution_artifact_digest,
                    "plan_artifact_digest": self.reboot_plan_artifact_digest,
                },
                "trust_artifact_digest": self.trust_artifact_digest,
            },
            "result": self.artifact_state.value,
            "schema_version": self.schema_version,
            "scope": {
                "digest": self.authorization_scope_digest,
                "configuration_intent_digest": self.configuration_intent_digest,
                "playbook": _PLAYBOOK,
                "playbook_instance_count": self.playbook_instance_count,
                "stable_id_count": self.stable_id_count,
                "stable_id_set_digest": self.stable_id_set_digest,
            },
        }


def authorize_deploy_jump_host_configure(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proof: DeployJumpHostConfigureAuthorizationProof,
) -> DeployJumpHostConfigureAuthorizationReport:
    """Authorize only exact post-reboot jump-host configuration without execution."""

    if not isinstance(proof, DeployJumpHostConfigureAuthorizationProof):
        raise StateConflictError(
            "deploy jump-host-configure authorization proof is malformed"
        )
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_authorization_artifacts(paths, operation_id)
    _refuse_incompatible_authorization(paths, operation_id)
    _refuse_uncertain_execution(paths, operation_id)

    # This loader revalidates the complete verified Terraform/deploy/base-OS/
    # reboot chain, current inventory/trust/readiness, source/catalog, and the
    # unchanged VERIFY journal before any authorization state is considered.
    context = _load_post_reboot_context(paths, operation_id, lock=lock)
    metadata = context.base.host.loaded.planning.base.deploy.metadata.record
    reconciliation_store = DeployPostRebootReconciliationStore(paths, operation_id)
    validate_state_file(reconciliation_store.path, allow_missing=True)
    if not reconciliation_store.path.exists():
        raise StateConflictError(
            "deploy jump-host-configure authorization requires "
            "post-reboot reconciliation"
        )
    reconciliation = reconciliation_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_reconciliation = _build_post_reboot_record(
        context,
        steps=_build_post_reboot_steps(context),
        created_at=reconciliation.record.created_at,
    )
    if reconciliation.record != expected_reconciliation:
        raise StateConflictError(
            "deploy jump-host-configure reconciliation drifted; use a new operation"
        )
    scopes = _derive_authorization_scopes(context, reconciliation)
    if not scopes:
        raise StateConflictError(
            "deploy jump-host-configure authorization has no evidence-ready scope"
        )
    scope_digest = _digest_object([scope.to_object() for scope in scopes])
    decision = _normalize_proof(
        proof,
        reconciliation=reconciliation,
        scope_digest=scope_digest,
    )

    store = DeployJumpHostConfigureAuthorizationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    if store.path.exists():
        stored = store.read_locked(
            lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
        )
        expected = _build_authorization(
            context,
            reconciliation,
            scopes=scopes,
            proof=decision,
            created_at=stored.record.created_at,
        )
        if stored.record != expected:
            raise StateConflictError(
                "deploy jump-host-configure authorization changed; "
                "re-plan with a new operation"
            )
        state = DeployJumpHostConfigureAuthorizationArtifactState.REUSED
    else:
        record = _build_authorization(
            context,
            reconciliation,
            scopes=scopes,
            proof=decision,
            created_at=format_timestamp(datetime.now(UTC)),
        )
        try:
            stored, state = store.write_locked(record, lock=lock)
        except StatePersistenceError as error:
            raise StatePersistenceError(
                "deploy jump-host-configure authorization persistence failed"
            ) from error
    return _build_report(stored, state=state)


def deploy_jump_host_configure_authorization_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the sole canonical operation-bound authorization path."""

    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy jump-host-configure authorization path is not canonical"
        )
    return path


def deploy_jump_host_configure_authorization_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_FILENAME_SUFFIX):
        return None
    value = name[: -len(DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_FILENAME_SUFFIX)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _derive_authorization_scopes(
    context: _PostRebootContext,
    reconciliation: StoredDeployPostRebootReconciliation,
) -> tuple[DeployJumpHostConfigureAuthorizationScope, ...]:
    ready = tuple(
        step
        for step in reconciliation.record.steps
        if step.status
        is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
    )
    if len(ready) != reconciliation.record.authorization_required_count:
        raise StateConflictError(
            "deploy jump-host-configure authorization-required count drifted"
        )
    base = context.base
    inventory_hosts = (
        base.host.loaded.planning.base.deploy.inventory.record.inventory.hosts
    )
    jump_ids = {
        host.logical_id for host in inventory_hosts if host.role is HostRole.JUMP_HOST
    }
    scopes: list[DeployJumpHostConfigureAuthorizationScope] = []
    for step in ready:
        _validate_authorizable_step(step, jump_ids=jump_ids)
        assert step.evidence_digest is not None
        scopes.append(
            DeployJumpHostConfigureAuthorizationScope(
                sequence=step.sequence,
                mapping_sequence=step.mapping_sequence,
                playbook=step.playbook,
                classification=step.classification,
                target_role=step.target_role,
                target_ids=step.target_ids,
                target_digest=step.target_digest,
                variables_digest=step.variables_digest,
                source_digest=step.source_digest,
                command_digest=step.command_digest,
                evidence_digest=step.evidence_digest,
                original_step_digest=step.original_step_digest,
                prior_reconciled_step_digest=step.prior_reconciled_step_digest,
                post_reconciled_step_digest=_digest_object(step.to_object()),
            )
        )
    return tuple(scopes)


def _validate_authorizable_step(
    step: DeployBaseOsReconciledStep,
    *,
    jump_ids: set[str],
) -> None:
    if (
        step.mapping_sequence != _MAPPING_SEQUENCE
        or step.playbook != _PLAYBOOK
        or step.condition_state is not DeployConditionState.ACTIVE
        or step.classification is not OperationClassification.MUTATING
        or step.target_role != _TARGET_ROLE
        or not step.target_ids
        or not set(step.target_ids).issubset(jump_ids)
        or step.evidence_digest is None
    ):
        raise StateConflictError(
            "only exact evidence-ready jump-host-configure steps may be authorized"
        )


def _normalize_proof(
    proof: DeployJumpHostConfigureAuthorizationProof,
    *,
    reconciliation: StoredDeployPostRebootReconciliation,
    scope_digest: str,
) -> DeployJumpHostConfigureProofDecision:
    if proof.approval_method is None:
        raise StateConflictError(
            "ordinary deploy jump-host-configure approval is required"
        )
    if not proof.approved:
        raise StateConflictError(
            "ordinary deploy jump-host-configure approval was denied"
        )
    if proof.allow_destructive or proof.destructive_scope_provided:
        raise StateConflictError(
            "destructive proof is inapplicable to mutating "
            "jump-host-configure authorization"
        )
    values: dict[str, object] = {
        "allow_destructive": False,
        "approval_method": proof.approval_method.value,
        "approved": True,
        "destructive_scope_provided": False,
        "proof_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION
        ),
    }
    values["proof_digest"] = _proof_digest_from_values(
        reconciliation,
        scope_digest=scope_digest,
        proof=values,
    )
    return DeployJumpHostConfigureProofDecision.from_object(values)


def _build_authorization(
    context: _PostRebootContext,
    reconciliation: StoredDeployPostRebootReconciliation,
    *,
    scopes: tuple[DeployJumpHostConfigureAuthorizationScope, ...],
    proof: DeployJumpHostConfigureProofDecision,
    created_at: str,
) -> DeployJumpHostConfigureAuthorization:
    post_context = context
    base = post_context.base
    host = base.host
    loaded = host.loaded
    planning = loaded.planning
    deploy = planning.base.deploy
    record = reconciliation.record
    stable_ids = tuple(
        sorted({target for scope in scopes for target in scope.target_ids})
    )
    scope_sequences = {scope.sequence for scope in scopes}
    non_authorized = tuple(
        step for step in record.steps if step.sequence not in scope_sequences
    )
    status_values = [
        {
            "blockers": list(step.blockers),
            "playbook": step.playbook,
            "sequence": step.sequence,
            "status": step.status.value,
        }
        for step in non_authorized
    ]
    counts = {
        status: sum(step.status is status for step in non_authorized)
        for status in DeployBaseOsReconciledStepStatus
    }
    reboot_plan = post_context.plan
    reboot_authorization = post_context.authorization
    reboot_execution = post_context.execution
    reboot_evidence = post_context.evidence
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": str(record.cluster_uuid),
        "cluster_name": record.cluster_name,
        "operation_id": str(record.operation_id),
        "operation": record.operation,
        "request_digest": record.request_digest,
        "journal_generation": record.journal_generation,
        "journal_digest": record.journal_digest,
        "journal_status": record.journal_status.value,
        "journal_phase": record.journal_phase.value,
        "context_artifact_digest": loaded.context.artifact_digest,
        "context_record_digest": loaded.context.record.record_digest,
        "original_plan_artifact_digest": loaded.plan.artifact_digest,
        "original_plan_record_digest": loaded.plan.record.record_digest,
        "effective_plan_artifact_digest": host.prior_effective.artifact_digest,
        "effective_plan_record_digest": host.prior_effective.record.record_digest,
        "effective_plan_digest": host.prior_effective.record.effective_plan_digest,
        "prerequisite_execution_artifact_digest": loaded.execution.artifact_digest,
        "prerequisite_evidence_artifact_digest": loaded.evidence.artifact_digest,
        "connectivity_evidence_digest": record.connectivity_evidence_digest,
        "pre_mutation_execution_artifact_digest": host.execution.artifact_digest,
        "pre_mutation_evidence_artifact_digest": host.evidence.artifact_digest,
        "host_reconciliation_artifact_digest": base.prior.artifact_digest,
        "host_reconciliation_record_digest": base.prior.record.record_digest,
        "host_reconciled_plan_digest": base.prior.record.effective_plan_digest,
        "base_os_authorization_artifact_digest": base.authorization.artifact_digest,
        "base_os_execution_artifact_digest": base.execution.artifact_digest,
        "base_os_evidence_artifact_digest": base.evidence.artifact_digest,
        "base_os_reconciliation_artifact_digest": (
            post_context.base_reconciliation.artifact_digest
        ),
        "base_os_reconciliation_record_digest": (
            post_context.base_reconciliation.record.record_digest
        ),
        "base_os_effective_plan_digest": (
            post_context.base_reconciliation.record.effective_plan_digest
        ),
        "reboot_branch": record.branch.value,
        "reboot_plan_artifact_digest": (
            reboot_plan.artifact_digest if reboot_plan is not None else None
        ),
        "reboot_authorization_artifact_digest": (
            reboot_authorization.artifact_digest
            if reboot_authorization is not None
            else None
        ),
        "reboot_execution_artifact_digest": (
            reboot_execution.artifact_digest if reboot_execution is not None else None
        ),
        "reboot_evidence_artifact_digest": (
            reboot_evidence.artifact_digest if reboot_evidence is not None else None
        ),
        "reboot_evidence_digest": record.reboot_evidence_digest,
        "post_reboot_reconciliation_artifact_digest": reconciliation.artifact_digest,
        "post_reboot_reconciliation_record_digest": record.record_digest,
        "post_reboot_effective_plan_digest": record.effective_plan_digest,
        "inventory_generation": deploy.inventory.record.generation,
        "inventory_artifact_digest": deploy.inventory.digest,
        "inventory_digest": deploy.inventory.record.inventory_digest,
        "route_digest": loaded.evidence.record.route_digest,
        "trust_generation": planning.base.trust.record.generation,
        "trust_artifact_digest": planning.base.trust.digest,
        "trust_entries_digest": planning.base.trust.record.entries_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": planning.readiness.record.record_digest,
        "catalog_digest": loaded.catalog_digest,
        "ansible_source_version": loaded.source.version,
        "ansible_source_digest": loaded.source.digest,
        "classification": OperationClassification.MUTATING.value,
        "scopes": [scope.to_object() for scope in scopes],
        "playbook_instance_count": len(scopes),
        "stable_id_count": len(stable_ids),
        "stable_id_set_digest": _digest_object(list(stable_ids)),
        "authorization_scope_digest": _digest_object(
            [scope.to_object() for scope in scopes]
        ),
        "configuration_intent_digest": _configuration_intent_digest(scopes),
        "reconciled_step_count": record.step_count,
        "non_authorized_step_count": len(non_authorized),
        "prior_succeeded_step_count": counts[
            DeployBaseOsReconciledStepStatus.SUCCEEDED
        ],
        "blocked_step_count": counts[DeployBaseOsReconciledStepStatus.BLOCKED],
        "not_performed_step_count": counts[
            DeployBaseOsReconciledStepStatus.NOT_PERFORMED
        ],
        "eligible_step_count": counts[DeployBaseOsReconciledStepStatus.ELIGIBLE],
        "non_authorized_blocker_digest": _digest_object(status_values),
        "proof": proof.to_object(),
        "authorization_state": _AUTHORIZED,
        "consumed": False,
        "execution_state": _EXECUTION_UNAVAILABLE,
        "finalization_state": _FINALIZATION_NOT_STARTED,
        "public_workflow_state": _PUBLIC_WORKFLOW_UNAVAILABLE,
        "authorization_digest": "",
        "context_schema_version": ANSIBLE_DEPLOY_CONTEXT_SCHEMA_VERSION,
        "original_plan_schema_version": ANSIBLE_DEPLOY_PLAN_SCHEMA_VERSION,
        "effective_plan_schema_version": (ANSIBLE_DEPLOY_EFFECTIVE_PLAN_SCHEMA_VERSION),
        "prerequisite_execution_schema_version": (
            ANSIBLE_DEPLOY_PREREQUISITE_EXECUTION_SCHEMA_VERSION
        ),
        "prerequisite_evidence_schema_version": (
            ANSIBLE_DEPLOY_PREREQUISITE_EVIDENCE_SCHEMA_VERSION
        ),
        "pre_mutation_execution_schema_version": (
            ANSIBLE_DEPLOY_PRE_MUTATION_EXECUTION_SCHEMA_VERSION
        ),
        "pre_mutation_evidence_schema_version": (
            ANSIBLE_DEPLOY_PRE_MUTATION_EVIDENCE_SCHEMA_VERSION
        ),
        "host_reconciliation_schema_version": (
            ANSIBLE_DEPLOY_HOST_RECONCILIATION_SCHEMA_VERSION
        ),
        "base_os_authorization_schema_version": (
            ANSIBLE_DEPLOY_BASE_OS_AUTHORIZATION_SCHEMA_VERSION
        ),
        "base_os_execution_schema_version": (
            ANSIBLE_DEPLOY_BASE_OS_EXECUTION_SCHEMA_VERSION
        ),
        "base_os_evidence_schema_version": (
            ANSIBLE_DEPLOY_BASE_OS_EVIDENCE_SCHEMA_VERSION
        ),
        "base_os_reconciliation_schema_version": (
            ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION
        ),
        "reboot_plan_schema_version": ANSIBLE_DEPLOY_REBOOT_PLAN_SCHEMA_VERSION,
        "reboot_authorization_schema_version": (
            ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_SCHEMA_VERSION
        ),
        "reboot_execution_schema_version": (
            ANSIBLE_DEPLOY_REBOOT_EXECUTION_SCHEMA_VERSION
        ),
        "reboot_evidence_schema_version": (
            ANSIBLE_DEPLOY_REBOOT_EVIDENCE_SCHEMA_VERSION
        ),
        "post_reboot_reconciliation_schema_version": (
            ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION
        ),
        "readiness_schema_version": TERRAFORM_APPLY_READINESS_SCHEMA_VERSION,
        "journal_schema_version": JOURNAL_SCHEMA_VERSION,
        "schema_version": (
            ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
        ),
    }
    values["authorization_digest"] = _authorization_digest_object(values)
    return DeployJumpHostConfigureAuthorization.from_object(values)


def _build_report(
    stored: StoredDeployJumpHostConfigureAuthorization,
    *,
    state: DeployJumpHostConfigureAuthorizationArtifactState,
) -> DeployJumpHostConfigureAuthorizationReport:
    record = stored.record
    return DeployJumpHostConfigureAuthorizationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        authorization_artifact_digest=stored.artifact_digest,
        authorization_digest=record.authorization_digest,
        authorization_state=record.authorization_state,
        approval_method=record.proof.approval_method,
        approved=record.proof.approved,
        proof_digest=record.proof.proof_digest,
        classification=record.classification,
        playbook_instance_count=record.playbook_instance_count,
        stable_id_count=record.stable_id_count,
        stable_id_set_digest=record.stable_id_set_digest,
        authorization_scope_digest=record.authorization_scope_digest,
        configuration_intent_digest=record.configuration_intent_digest,
        post_reboot_reconciliation_artifact_digest=(
            record.post_reboot_reconciliation_artifact_digest
        ),
        post_reboot_reconciliation_record_digest=(
            record.post_reboot_reconciliation_record_digest
        ),
        post_reboot_effective_plan_digest=(record.post_reboot_effective_plan_digest),
        context_artifact_digest=record.context_artifact_digest,
        original_plan_artifact_digest=record.original_plan_artifact_digest,
        effective_plan_artifact_digest=record.effective_plan_artifact_digest,
        host_reconciliation_artifact_digest=(
            record.host_reconciliation_artifact_digest
        ),
        base_os_reconciliation_artifact_digest=(
            record.base_os_reconciliation_artifact_digest
        ),
        base_os_authorization_artifact_digest=(
            record.base_os_authorization_artifact_digest
        ),
        base_os_execution_artifact_digest=(record.base_os_execution_artifact_digest),
        base_os_evidence_artifact_digest=record.base_os_evidence_artifact_digest,
        reboot_branch=record.reboot_branch,
        reboot_plan_artifact_digest=record.reboot_plan_artifact_digest,
        reboot_authorization_artifact_digest=(
            record.reboot_authorization_artifact_digest
        ),
        reboot_execution_artifact_digest=record.reboot_execution_artifact_digest,
        reboot_evidence_artifact_digest=record.reboot_evidence_artifact_digest,
        prerequisite_execution_artifact_digest=(
            record.prerequisite_execution_artifact_digest
        ),
        prerequisite_evidence_artifact_digest=(
            record.prerequisite_evidence_artifact_digest
        ),
        pre_mutation_execution_artifact_digest=(
            record.pre_mutation_execution_artifact_digest
        ),
        pre_mutation_evidence_artifact_digest=(
            record.pre_mutation_evidence_artifact_digest
        ),
        inventory_artifact_digest=record.inventory_artifact_digest,
        trust_artifact_digest=record.trust_artifact_digest,
        readiness_artifact_digest=record.readiness_artifact_digest,
        catalog_digest=record.catalog_digest,
        ansible_source_digest=record.ansible_source_digest,
        non_authorized_step_count=record.non_authorized_step_count,
        non_authorized_state=_NON_AUTHORIZED_STATE,
        non_authorized_blocker_digest=record.non_authorized_blocker_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        journal_digest=record.journal_digest,
        consumed=record.consumed,
        execution_state=record.execution_state,
        finalization_state=record.finalization_state,
        public_workflow_state=record.public_workflow_state,
    )


def _proof_digest(
    record: DeployJumpHostConfigureAuthorization,
    proof: Mapping[str, object],
) -> str:
    return _proof_digest_values(
        cluster_uuid=record.cluster_uuid,
        operation_id=record.operation_id,
        request_digest=record.request_digest,
        journal_digest=record.journal_digest,
        reconciliation_artifact_digest=(
            record.post_reboot_reconciliation_artifact_digest
        ),
        reconciliation_record_digest=(record.post_reboot_reconciliation_record_digest),
        scope_digest=record.authorization_scope_digest,
        proof=proof,
    )


def _proof_digest_from_values(
    reconciliation: StoredDeployPostRebootReconciliation,
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
                ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION
            ),
        }
    )


def _authorization_digest(record: DeployJumpHostConfigureAuthorization) -> str:
    return _authorization_digest_object(record.to_object())


def _authorization_digest_object(values: Mapping[str, object]) -> str:
    value = dict(values)
    value["authorization_digest"] = ""
    return _digest_object(value)


def _configuration_intent_digest(
    scopes: tuple[DeployJumpHostConfigureAuthorizationScope, ...],
) -> str:
    return _digest_object(
        [
            {
                "command_digest": scope.command_digest,
                "sequence": scope.sequence,
                "source_digest": scope.source_digest,
                "target_digest": scope.target_digest,
                "variables_digest": scope.variables_digest,
            }
            for scope in scopes
        ]
    )


def _required_digest_values(
    record: DeployJumpHostConfigureAuthorization,
) -> tuple[str, ...]:
    return (
        record.request_digest,
        record.journal_digest,
        record.context_artifact_digest,
        record.context_record_digest,
        record.original_plan_artifact_digest,
        record.original_plan_record_digest,
        record.effective_plan_artifact_digest,
        record.effective_plan_record_digest,
        record.effective_plan_digest,
        record.prerequisite_execution_artifact_digest,
        record.prerequisite_evidence_artifact_digest,
        record.connectivity_evidence_digest,
        record.pre_mutation_execution_artifact_digest,
        record.pre_mutation_evidence_artifact_digest,
        record.host_reconciliation_artifact_digest,
        record.host_reconciliation_record_digest,
        record.host_reconciled_plan_digest,
        record.base_os_authorization_artifact_digest,
        record.base_os_execution_artifact_digest,
        record.base_os_evidence_artifact_digest,
        record.base_os_reconciliation_artifact_digest,
        record.base_os_reconciliation_record_digest,
        record.base_os_effective_plan_digest,
        record.post_reboot_reconciliation_artifact_digest,
        record.post_reboot_reconciliation_record_digest,
        record.post_reboot_effective_plan_digest,
        record.inventory_artifact_digest,
        record.inventory_digest,
        record.route_digest,
        record.trust_artifact_digest,
        record.trust_entries_digest,
        record.readiness_artifact_digest,
        record.readiness_record_digest,
        record.catalog_digest,
        record.ansible_source_digest,
        record.stable_id_set_digest,
        record.authorization_scope_digest,
        record.configuration_intent_digest,
        record.non_authorized_blocker_digest,
        record.authorization_digest,
    )


def _optional_reboot_digests(
    record: DeployJumpHostConfigureAuthorization,
) -> tuple[str | None, ...]:
    return (
        record.reboot_plan_artifact_digest,
        record.reboot_authorization_artifact_digest,
        record.reboot_execution_artifact_digest,
        record.reboot_evidence_artifact_digest,
        record.reboot_evidence_digest,
    )


def _refuse_incompatible_authorization(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    path = paths.operations / f"{operation_id}{OPERATION_AUTHORIZATION_FILENAME_SUFFIX}"
    validate_state_file(path, allow_missing=True)
    if path.exists():
        raise StateConflictError(
            "generic Ansible authorization is incompatible with deploy VERIFY binding"
        )


def _refuse_uncertain_execution(paths: StatePaths, operation_id: uuid.UUID) -> None:
    allowed = {
        f"{operation_id}.ansible-deploy-prerequisite-execution.json",
        f"{operation_id}.ansible-deploy-pre-mutation-host-evidence-execution.json",
        f"{operation_id}.ansible-deploy-base-os-execution.json",
        f"{operation_id}.ansible-deploy-reboot-execution.json",
    }
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy jump-host-configure execution history"
        ) from error
    for entry in entries:
        if str(operation_id) not in entry.name or "execution" not in entry.name:
            continue
        validate_state_file(entry)
        if entry.name not in allowed:
            raise StateConflictError(
                "deploy jump-host-configure authorization refuses uncertain "
                "execution history"
            )


def _refuse_ambiguous_authorization_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy jump-host-configure authorization history"
        ) from error
    canonical = str(operation_id)
    suffix = DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_FILENAME_SUFFIX
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
                "deploy jump-host-configure authorization artifacts are ambiguous"
            )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "deploy jump-host-configure authorization paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy jump-host-configure authorization requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _nonnegative_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StatePersistenceError(f"{label} must be nonnegative")


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be a boolean")
    return value


def _optional_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise StatePersistenceError(f"{label} must be a string or null")
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
            f"deploy jump-host-configure authorization {label} is invalid"
        ) from error


__all__ = [
    "ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_PROOF_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION",
    "DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_FILENAME_SUFFIX",
    "DeployJumpHostConfigureApprovalMethod",
    "DeployJumpHostConfigureAuthorization",
    "DeployJumpHostConfigureAuthorizationArtifactState",
    "DeployJumpHostConfigureAuthorizationProof",
    "DeployJumpHostConfigureAuthorizationReport",
    "DeployJumpHostConfigureAuthorizationScope",
    "DeployJumpHostConfigureAuthorizationStore",
    "DeployJumpHostConfigureProofDecision",
    "StoredDeployJumpHostConfigureAuthorization",
    "authorize_deploy_jump_host_configure",
    "deploy_jump_host_configure_authorization_id_from_filename",
    "deploy_jump_host_configure_authorization_path",
]
