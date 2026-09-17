"""Immutable planning and authorization for non-jump deploy reboots.

This internal boundary derives reboot scope only from the exact successful
post-final-routes non-jump ``base-os`` evidence.  It does not invoke a process,
reboot a host, create execution intent, or change the common journal.
"""

from __future__ import annotations

import os
import re
import uuid
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.base_os import BaseOsStatus
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_final_routes import (
    ANSIBLE_DEPLOY_FINAL_ROUTES_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION,
)
from scylla_vms.ansible.deploy_non_jump_base_os_execution import (
    ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EXECUTION_SCHEMA_VERSION,
)
from scylla_vms.ansible.deploy_non_jump_base_os_reconciliation import (
    ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_SCHEMA_VERSION,
    DeployPostNonJumpBaseOsReconciliationStore,
    StoredDeployPostNonJumpBaseOsReconciliation,
    _ReconciliationContext,
)
from scylla_vms.ansible.deploy_non_jump_base_os_reconciliation import (
    _build_record as _build_non_jump_reconciliation,
)
from scylla_vms.ansible.deploy_non_jump_base_os_reconciliation import (
    _build_steps as _build_non_jump_steps,
)
from scylla_vms.ansible.deploy_non_jump_base_os_reconciliation import (
    _load_context as _load_non_jump_context,
)
from scylla_vms.ansible.deploy_plan import (
    _digest_object,
    _require_operation_id,
)
from scylla_vms.ansible.service import DestinationProbeStatus
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

ANSIBLE_DEPLOY_NON_JUMP_REBOOT_PLAN_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-non-jump-reboot-plan/v1"
)
ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-non-jump-reboot-authorization/v1"
)
ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-non-jump-reboot-authorization-proof/v1"
)
ANSIBLE_DEPLOY_NON_JUMP_REBOOT_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-non-jump-reboot-plan-authorization-report/v1"
)
DEPLOY_NON_JUMP_REBOOT_PLAN_FILENAME_SUFFIX = (
    ".ansible-deploy-non-jump-reboot-plan.json"
)
DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_FILENAME_SUFFIX = (
    ".ansible-deploy-non-jump-reboot-authorization.json"
)

_OPERATION = "deploy"
_STAGE = "post-non-jump-base-os-reboot"
_SCOPE = "non-jump-reboot-required-hosts"
_ORDERING_POLICY = "non-jump-base-os-execution-then-stable-id/v1"
_CHECKPOINT_POLICY = (
    "reconnect-identity-trust-machine-service-reboot-clear-before-next/v1"
)
_READY = "ready-for-authorization"
_BLOCKED = "blocked"
_AUTHORIZED = "authorized-pre-execution"
_NOT_COLLECTED = "not-collected"
_NOT_REQUIRED = "not-required"
_NOT_PERFORMED = "not-performed"
_UNAVAILABLE = "unavailable"
_SERIAL = 1
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")
_SAFE_ROLES = frozenset({HostRole.SCYLLA, HostRole.MANAGER, HostRole.MONITORING})


class DeployNonJumpRebootApprovalMethod(StrEnum):
    """PLAN-permitted ordinary approval methods."""

    INTERACTIVE = "interactive"
    CLI_YES = "cli-yes"


class DeployNonJumpRebootArtifactState(StrEnum):
    """Persistence state for one immutable companion."""

    CREATED = "created"
    REUSED = "reused"
    NOT_REQUIRED = "not-required"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class DeployNonJumpRebootAuthorizationProof:
    """Already-normalized ordinary approval without caller-owned scope."""

    approval_method: DeployNonJumpRebootApprovalMethod | None = None
    approved: bool = False
    allow_destructive: bool = False
    destructive_scope_provided: bool = False

    def __post_init__(self) -> None:
        if self.approval_method is not None and not isinstance(
            self.approval_method, DeployNonJumpRebootApprovalMethod
        ):
            raise StateConflictError(
                "deploy non-jump reboot approval method is invalid"
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
                "deploy non-jump reboot authorization proof is malformed"
            )


@dataclass(frozen=True, slots=True)
class DeployNonJumpRebootProofDecision:
    """Persisted normalized proof bound to one exact plan and target order."""

    approval_method: DeployNonJumpRebootApprovalMethod
    approved: bool
    allow_destructive: bool
    destructive_scope_provided: bool
    proof_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or not isinstance(self.approval_method, DeployNonJumpRebootApprovalMethod)
            or self.approved is not True
            or self.allow_destructive is not False
            or self.destructive_scope_provided is not False
        ):
            raise StatePersistenceError(
                "deploy non-jump reboot authorization proof is invalid"
            )
        validate_digest(self.proof_digest, "non-jump reboot proof digest")

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
    ) -> DeployNonJumpRebootProofDecision:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy non-jump reboot authorization proof",
        )
        for name in ("approved", "allow_destructive", "destructive_scope_provided"):
            if not isinstance(value[name], bool):
                raise StatePersistenceError(
                    "deploy non-jump reboot authorization proof boolean is invalid"
                )
        try:
            method = DeployNonJumpRebootApprovalMethod(
                require_string(value, "approval_method")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy non-jump reboot approval method is invalid"
            ) from error
        return cls(
            method,
            cast(bool, value["approved"]),
            cast(bool, value["allow_destructive"]),
            cast(bool, value["destructive_scope_provided"]),
            require_string(value, "proof_digest"),
            require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployNonJumpRebootPlanTarget:
    """One address-free serial checkpoint derived from exact result evidence."""

    sequence: int
    stable_id: str
    role: HostRole
    base_os_attempt_index: int
    base_os_step_sequence: int
    base_os_target_index: int
    base_os_evidence_digest: str
    base_os_result_digest: str
    route_relationship_count: int
    route_relationship_digest: str
    trust_identity_digest: str
    final_routes_evidence_digest: str
    reconnect_required: bool
    identity_trust_revalidation_required: bool
    machine_evidence_required: bool
    service_safety_verification_required: bool
    reboot_clear_verification_required: bool
    checkpoint_policy: str

    def __post_init__(self) -> None:
        if (
            self.sequence < 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.role not in _SAFE_ROLES
            or self.base_os_attempt_index < 1
            or self.base_os_step_sequence < 1
            or self.base_os_target_index < 1
            or self.route_relationship_count < 1
            or self.reconnect_required is not True
            or self.identity_trust_revalidation_required is not True
            or self.machine_evidence_required is not True
            or self.service_safety_verification_required is not True
            or self.reboot_clear_verification_required is not True
            or self.checkpoint_policy != _CHECKPOINT_POLICY
        ):
            raise StatePersistenceError(
                "deploy non-jump reboot target policy is invalid"
            )
        for value in (
            self.base_os_evidence_digest,
            self.base_os_result_digest,
            self.route_relationship_digest,
            self.trust_identity_digest,
            self.final_routes_evidence_digest,
        ):
            validate_digest(value, "deploy non-jump reboot target digest")

    def to_object(self) -> dict[str, object]:
        return {
            "base_os_attempt_index": self.base_os_attempt_index,
            "base_os_evidence_digest": self.base_os_evidence_digest,
            "base_os_result_digest": self.base_os_result_digest,
            "base_os_step_sequence": self.base_os_step_sequence,
            "base_os_target_index": self.base_os_target_index,
            "checkpoint_policy": self.checkpoint_policy,
            "final_routes_evidence_digest": self.final_routes_evidence_digest,
            "identity_trust_revalidation_required": (
                self.identity_trust_revalidation_required
            ),
            "machine_evidence_required": self.machine_evidence_required,
            "reboot_clear_verification_required": (
                self.reboot_clear_verification_required
            ),
            "reconnect_required": self.reconnect_required,
            "role": self.role.value,
            "route_relationship_count": self.route_relationship_count,
            "route_relationship_digest": self.route_relationship_digest,
            "sequence": self.sequence,
            "service_safety_verification_required": (
                self.service_safety_verification_required
            ),
            "stable_id": self.stable_id,
            "trust_identity_digest": self.trust_identity_digest,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployNonJumpRebootPlanTarget:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy non-jump reboot target",
        )
        try:
            role = HostRole(require_string(value, "role"))
        except ValueError as error:
            raise StatePersistenceError(
                "deploy non-jump reboot target role is invalid"
            ) from error
        return cls(
            sequence=_integer(value["sequence"], "target sequence"),
            stable_id=require_string(value, "stable_id"),
            role=role,
            base_os_attempt_index=_integer(
                value["base_os_attempt_index"], "base-os attempt index"
            ),
            base_os_step_sequence=_integer(
                value["base_os_step_sequence"], "base-os step sequence"
            ),
            base_os_target_index=_integer(
                value["base_os_target_index"], "base-os target index"
            ),
            base_os_evidence_digest=require_string(value, "base_os_evidence_digest"),
            base_os_result_digest=require_string(value, "base_os_result_digest"),
            route_relationship_count=_integer(
                value["route_relationship_count"], "route relationship count"
            ),
            route_relationship_digest=require_string(
                value, "route_relationship_digest"
            ),
            trust_identity_digest=require_string(value, "trust_identity_digest"),
            final_routes_evidence_digest=require_string(
                value, "final_routes_evidence_digest"
            ),
            reconnect_required=_boolean(
                value["reconnect_required"], "reconnect required"
            ),
            identity_trust_revalidation_required=_boolean(
                value["identity_trust_revalidation_required"],
                "identity/trust revalidation required",
            ),
            machine_evidence_required=_boolean(
                value["machine_evidence_required"], "machine evidence required"
            ),
            service_safety_verification_required=_boolean(
                value["service_safety_verification_required"],
                "service safety verification required",
            ),
            reboot_clear_verification_required=_boolean(
                value["reboot_clear_verification_required"],
                "reboot-clear verification required",
            ),
            checkpoint_policy=require_string(value, "checkpoint_policy"),
        )


@dataclass(frozen=True, slots=True)
class DeployNonJumpRebootPlan:
    """Immutable operation-bound plan for the later non-jump reboot owner."""

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
    post_non_jump_reconciliation_artifact_digest: str
    post_non_jump_reconciliation_record_digest: str
    post_non_jump_effective_plan_digest: str
    final_routes_execution_artifact_digest: str
    final_routes_evidence_artifact_digest: str
    final_routes_evidence_digest: str
    final_routes_reconciliation_artifact_digest: str
    final_routes_reconciliation_record_digest: str
    non_jump_base_os_authorization_artifact_digest: str
    non_jump_base_os_execution_artifact_digest: str
    non_jump_base_os_execution_binding_digest: str
    non_jump_base_os_evidence_artifact_digest: str
    non_jump_base_os_evidence_digest: str
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
    ordering_policy: str
    serial: int
    targets: tuple[DeployNonJumpRebootPlanTarget, ...]
    target_count: int
    target_set_digest: str
    target_order_digest: str
    role_counts_digest: str
    route_relationship_digest: str
    checkpoint_policy: str
    blocker_set: tuple[str, ...]
    blocker_digest: str
    planning_state: str
    authorization_state: str
    authorization_consumed: bool
    execution_state: str
    reconnect_state: str
    record_digest: str
    post_non_jump_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_SCHEMA_VERSION
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
    non_jump_base_os_execution_schema_version: str = (
        ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EXECUTION_SCHEMA_VERSION
    )
    non_jump_base_os_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EVIDENCE_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_NON_JUMP_REBOOT_PLAN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version != ANSIBLE_DEPLOY_NON_JUMP_REBOOT_PLAN_SCHEMA_VERSION
            or self.post_non_jump_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_SCHEMA_VERSION
            or self.final_routes_execution_schema_version
            != ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_SCHEMA_VERSION
            or self.final_routes_evidence_schema_version
            != ANSIBLE_DEPLOY_FINAL_ROUTES_EVIDENCE_SCHEMA_VERSION
            or self.final_routes_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION
            or self.non_jump_base_os_execution_schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EXECUTION_SCHEMA_VERSION
            or self.non_jump_base_os_evidence_schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EVIDENCE_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.classification is not OperationClassification.MUTATING
            or self.ordering_policy != _ORDERING_POLICY
            or self.serial != _SERIAL
            or self.checkpoint_policy != _CHECKPOINT_POLICY
            or self.authorization_state != _NOT_COLLECTED
            or self.authorization_consumed
            or self.execution_state != _UNAVAILABLE
            or self.reconnect_state != _NOT_PERFORMED
        ):
            raise StatePersistenceError(
                "deploy non-jump reboot plan identity or policy is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        _positive_integer(self.journal_generation, "journal generation")
        _positive_integer(self.inventory_generation, "inventory generation")
        _positive_integer(self.trust_generation, "trust generation")
        stable_ids = tuple(target.stable_id for target in self.targets)
        role_counts = Counter(target.role.value for target in self.targets)
        if (
            not self.targets
            or self.target_count != len(self.targets)
            or tuple(target.sequence for target in self.targets)
            != tuple(range(1, len(self.targets) + 1))
            or len(set(stable_ids)) != len(stable_ids)
            or self.target_set_digest != _digest_object(sorted(stable_ids))
            or self.target_order_digest != _digest_object(list(stable_ids))
            or self.role_counts_digest
            != _digest_object(
                [
                    {"count": count, "role": role}
                    for role, count in sorted(role_counts.items())
                ]
            )
            or self.route_relationship_digest
            != _digest_object(
                [target.route_relationship_digest for target in self.targets]
            )
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(_BLOCKER.fullmatch(value) is None for value in self.blocker_set)
            or self.blocker_digest != _digest_object(list(self.blocker_set))
            or self.planning_state != (_BLOCKED if self.blocker_set else _READY)
        ):
            raise StatePersistenceError("deploy non-jump reboot plan summary conflicts")
        for value in _plan_digests(self):
            validate_digest(value, "deploy non-jump reboot plan digest")
        if self.record_digest != _record_digest(self.to_object(), "record_digest"):
            raise StatePersistenceError(
                "deploy non-jump reboot plan record digest conflicts"
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
                else [target.to_object() for target in value]
                if name == "targets"
                else list(value)
                if name == "blocker_set"
                else value
            )
        return result

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployNonJumpRebootPlan:
        require_exact_keys(
            value, set(cls.__dataclass_fields__), "deploy non-jump reboot plan"
        )
        integers = {
            "generation",
            "journal_generation",
            "inventory_generation",
            "trust_generation",
            "serial",
            "target_count",
        }
        parsed: dict[str, object] = {}
        for name in cls.__dataclass_fields__:
            item = value[name]
            if name in integers:
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
            elif name == "targets":
                parsed[name] = tuple(
                    DeployNonJumpRebootPlanTarget.from_object(
                        _mapping(target, "deploy non-jump reboot target")
                    )
                    for target in _array(item, "deploy non-jump reboot targets")
                )
            elif name == "blocker_set":
                parsed[name] = _string_tuple(item, "deploy non-jump reboot blockers")
            elif name == "authorization_consumed":
                parsed[name] = _boolean(item, name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployNonJumpRebootPlan:
    record: DeployNonJumpRebootPlan
    artifact_digest: str


class DeployNonJumpRebootPlanStore:
    """Owner-only immutable non-jump reboot plan."""

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
        self._path = deploy_non_jump_reboot_plan_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployNonJumpRebootPlan:
        value, artifact_digest = self._file.read()
        record = DeployNonJumpRebootPlan.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "deploy non-jump reboot plan identity conflicts"
            )
        return StoredDeployNonJumpRebootPlan(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployNonJumpRebootPlan:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self, record: DeployNonJumpRebootPlan, *, lock: ClusterLock
    ) -> tuple[StoredDeployNonJumpRebootPlan, DeployNonJumpRebootArtifactState]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy non-jump reboot plan operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy non-jump reboot plan is immutable; use a new operation"
                )
            return current, DeployNonJumpRebootArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployNonJumpRebootPlan(record, artifact_digest),
            DeployNonJumpRebootArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployNonJumpRebootAuthorization:
    """Immutable unconsumed authorization for one exact non-jump reboot plan."""

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
    plan_artifact_digest: str
    plan_record_digest: str
    post_non_jump_reconciliation_artifact_digest: str
    final_routes_evidence_digest: str
    non_jump_base_os_evidence_digest: str
    inventory_digest: str
    trust_entries_digest: str
    readiness_record_digest: str
    catalog_digest: str
    ansible_source_digest: str
    classification: OperationClassification
    target_count: int
    target_set_digest: str
    target_order_digest: str
    role_counts_digest: str
    route_relationship_digest: str
    serial: int
    ordering_policy: str
    checkpoint_policy: str
    blocker_digest: str
    proof: DeployNonJumpRebootProofDecision
    authorization_state: str
    consumed: bool
    execution_state: str
    reconnect_state: str
    authorization_digest: str
    plan_schema_version: str = ANSIBLE_DEPLOY_NON_JUMP_REBOOT_PLAN_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_SCHEMA_VERSION
            or self.plan_schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_REBOOT_PLAN_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.scope_kind != _SCOPE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.classification is not OperationClassification.MUTATING
            or self.target_count < 1
            or self.serial != _SERIAL
            or self.ordering_policy != _ORDERING_POLICY
            or self.checkpoint_policy != _CHECKPOINT_POLICY
            or self.blocker_digest != _digest_object([])
            or self.authorization_state != _AUTHORIZED
            or self.consumed
            or self.execution_state != _UNAVAILABLE
            or self.reconnect_state != _NOT_PERFORMED
        ):
            raise StatePersistenceError(
                "deploy non-jump reboot authorization is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        _positive_integer(self.journal_generation, "journal generation")
        for value in _authorization_digests(self):
            validate_digest(value, "deploy non-jump reboot authorization digest")
        if self.proof.proof_digest != _proof_digest(self, self.proof.to_object()):
            raise StatePersistenceError("deploy non-jump reboot proof digest conflicts")
        if self.authorization_digest != _record_digest(
            self.to_object(), "authorization_digest"
        ):
            raise StatePersistenceError(
                "deploy non-jump reboot authorization digest conflicts"
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
                if name == "proof"
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployNonJumpRebootAuthorization:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy non-jump reboot authorization",
        )
        try:
            return cls(
                generation=_integer(value["generation"], "generation"),
                created_at=require_string(value, "created_at"),
                cluster_uuid=parse_uuid(
                    require_string(value, "cluster_uuid"), "cluster UUID"
                ),
                cluster_name=require_string(value, "cluster_name"),
                operation_id=parse_uuid(
                    require_string(value, "operation_id"), "operation ID"
                ),
                operation=require_string(value, "operation"),
                stage=require_string(value, "stage"),
                scope_kind=require_string(value, "scope_kind"),
                request_digest=require_string(value, "request_digest"),
                journal_generation=_integer(
                    value["journal_generation"], "journal generation"
                ),
                journal_digest=require_string(value, "journal_digest"),
                journal_status=JournalStatus(require_string(value, "journal_status")),
                journal_phase=OperationPhase(require_string(value, "journal_phase")),
                plan_artifact_digest=require_string(value, "plan_artifact_digest"),
                plan_record_digest=require_string(value, "plan_record_digest"),
                post_non_jump_reconciliation_artifact_digest=require_string(
                    value, "post_non_jump_reconciliation_artifact_digest"
                ),
                final_routes_evidence_digest=require_string(
                    value, "final_routes_evidence_digest"
                ),
                non_jump_base_os_evidence_digest=require_string(
                    value, "non_jump_base_os_evidence_digest"
                ),
                inventory_digest=require_string(value, "inventory_digest"),
                trust_entries_digest=require_string(value, "trust_entries_digest"),
                readiness_record_digest=require_string(
                    value, "readiness_record_digest"
                ),
                catalog_digest=require_string(value, "catalog_digest"),
                ansible_source_digest=require_string(value, "ansible_source_digest"),
                classification=OperationClassification(
                    require_string(value, "classification")
                ),
                target_count=_integer(value["target_count"], "target count"),
                target_set_digest=require_string(value, "target_set_digest"),
                target_order_digest=require_string(value, "target_order_digest"),
                role_counts_digest=require_string(value, "role_counts_digest"),
                route_relationship_digest=require_string(
                    value, "route_relationship_digest"
                ),
                serial=_integer(value["serial"], "serial"),
                ordering_policy=require_string(value, "ordering_policy"),
                checkpoint_policy=require_string(value, "checkpoint_policy"),
                blocker_digest=require_string(value, "blocker_digest"),
                proof=DeployNonJumpRebootProofDecision.from_object(
                    _mapping(value["proof"], "deploy non-jump reboot proof")
                ),
                authorization_state=require_string(value, "authorization_state"),
                consumed=_boolean(value["consumed"], "consumed"),
                execution_state=require_string(value, "execution_state"),
                reconnect_state=require_string(value, "reconnect_state"),
                authorization_digest=require_string(value, "authorization_digest"),
                plan_schema_version=require_string(value, "plan_schema_version"),
                journal_schema_version=require_string(value, "journal_schema_version"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy non-jump reboot authorization enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class StoredDeployNonJumpRebootAuthorization:
    record: DeployNonJumpRebootAuthorization
    artifact_digest: str


class DeployNonJumpRebootAuthorizationStore:
    """Owner-only immutable non-jump reboot authorization."""

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
        self._path = deploy_non_jump_reboot_authorization_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployNonJumpRebootAuthorization:
        value, artifact_digest = self._file.read()
        record = DeployNonJumpRebootAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "deploy non-jump reboot authorization identity conflicts"
            )
        return StoredDeployNonJumpRebootAuthorization(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployNonJumpRebootAuthorization:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self, record: DeployNonJumpRebootAuthorization, *, lock: ClusterLock
    ) -> tuple[
        StoredDeployNonJumpRebootAuthorization, DeployNonJumpRebootArtifactState
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy non-jump reboot authorization operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy non-jump reboot authorization is immutable; "
                    "use a new operation"
                )
            return current, DeployNonJumpRebootArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployNonJumpRebootAuthorization(record, artifact_digest),
            DeployNonJumpRebootArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployNonJumpRebootPlanningAuthorizationReport:
    """Strict redacted report without endpoints, routes, commands, or values."""

    operation_id: uuid.UUID
    plan_state: DeployNonJumpRebootArtifactState
    authorization_artifact_state: DeployNonJumpRebootArtifactState
    plan_artifact_digest: str | None
    plan_record_digest: str | None
    authorization_artifact_digest: str | None
    authorization_digest: str | None
    proof_digest: str | None
    target_count: int
    target_set_digest: str | None
    target_order_digest: str | None
    role_counts: tuple[tuple[str, int], ...]
    role_counts_digest: str | None
    route_relationship_digest: str | None
    serial: int
    ordering_policy: str
    checkpoint_policy: str
    classification: OperationClassification | None
    approval_method: DeployNonJumpRebootApprovalMethod | None
    authorization_state: str
    authorization_consumed: bool
    execution_state: str
    reconnect_state: str
    reconnect_required: bool
    identity_trust_revalidation_required: bool
    machine_evidence_required: bool
    service_safety_verification_required: bool
    reboot_clear_verification_required: bool
    storage_discover_branch_preserved: bool
    blocker_set: tuple[str, ...]
    blocker_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    plan_schema_version: str = ANSIBLE_DEPLOY_NON_JUMP_REBOOT_PLAN_SCHEMA_VERSION
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_SCHEMA_VERSION
    )
    proof_schema_version: str = (
        ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION
    )
    schema_version: str = ANSIBLE_DEPLOY_NON_JUMP_REBOOT_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_NON_JUMP_REBOOT_REPORT_SCHEMA_VERSION
            or self.plan_schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_REBOOT_PLAN_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or self.serial != _SERIAL
            or self.ordering_policy != _ORDERING_POLICY
            or self.checkpoint_policy != _CHECKPOINT_POLICY
            or self.authorization_consumed
            or self.execution_state != _UNAVAILABLE
            or self.reconnect_state != _NOT_PERFORMED
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(_BLOCKER.fullmatch(value) is None for value in self.blocker_set)
            or self.blocker_digest != _digest_object(list(self.blocker_set))
            or self.role_counts != tuple(sorted(self.role_counts))
        ):
            raise StatePersistenceError("deploy non-jump reboot report is invalid")
        _nonnegative_integer(self.target_count, "report target count")
        if self.target_count != sum(count for _role, count in self.role_counts):
            raise StatePersistenceError("deploy non-jump reboot report counts conflict")
        for value in (
            self.plan_artifact_digest,
            self.plan_record_digest,
            self.authorization_artifact_digest,
            self.authorization_digest,
            self.proof_digest,
            self.target_set_digest,
            self.target_order_digest,
            self.role_counts_digest,
            self.route_relationship_digest,
        ):
            if value is not None:
                validate_digest(value, "deploy non-jump reboot report digest")
        required = self.target_count > 0
        gates = (
            self.reconnect_required,
            self.identity_trust_revalidation_required,
            self.machine_evidence_required,
            self.service_safety_verification_required,
            self.reboot_clear_verification_required,
        )
        if not required:
            if (
                self.plan_state is not DeployNonJumpRebootArtifactState.NOT_REQUIRED
                or self.authorization_artifact_state
                is not DeployNonJumpRebootArtifactState.NOT_REQUIRED
                or self.classification is not None
                or self.authorization_state != _NOT_REQUIRED
                or self.approval_method is not None
                or self.role_counts
                or any(gates)
                or not self.storage_discover_branch_preserved
                or self.blocker_set
                or any(
                    value is not None
                    for value in (
                        self.plan_artifact_digest,
                        self.plan_record_digest,
                        self.authorization_artifact_digest,
                        self.authorization_digest,
                        self.proof_digest,
                        self.target_set_digest,
                        self.target_order_digest,
                        self.role_counts_digest,
                        self.route_relationship_digest,
                    )
                )
            ):
                raise StatePersistenceError(
                    "deploy non-jump reboot not-required report conflicts"
                )
            return
        if (
            self.classification is not OperationClassification.MUTATING
            or not all(gates)
            or self.storage_discover_branch_preserved
            or self.plan_artifact_digest is None
            or self.plan_record_digest is None
        ):
            raise StatePersistenceError(
                "deploy non-jump reboot required report conflicts"
            )
        if self.blocker_set:
            if (
                self.plan_state is not DeployNonJumpRebootArtifactState.BLOCKED
                or self.authorization_artifact_state
                is not DeployNonJumpRebootArtifactState.BLOCKED
                or self.authorization_state != _BLOCKED
                or self.approval_method is not None
                or self.authorization_artifact_digest is not None
                or self.authorization_digest is not None
                or self.proof_digest is not None
            ):
                raise StatePersistenceError(
                    "deploy non-jump reboot blocked report conflicts"
                )
        elif (
            self.plan_state
            not in {
                DeployNonJumpRebootArtifactState.CREATED,
                DeployNonJumpRebootArtifactState.REUSED,
            }
            or self.authorization_artifact_state
            not in {
                DeployNonJumpRebootArtifactState.CREATED,
                DeployNonJumpRebootArtifactState.REUSED,
            }
            or self.authorization_state != _AUTHORIZED
            or self.approval_method is None
            or self.authorization_artifact_digest is None
            or self.authorization_digest is None
            or self.proof_digest is None
        ):
            raise StatePersistenceError(
                "deploy non-jump reboot authorized report conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "authorization": {
                "artifact_digest": self.authorization_artifact_digest,
                "artifact_state": self.authorization_artifact_state.value,
                "consumed": self.authorization_consumed,
                "digest": self.authorization_digest,
                "method": (
                    self.approval_method.value
                    if self.approval_method is not None
                    else _NOT_COLLECTED
                ),
                "proof_digest": self.proof_digest,
                "state": self.authorization_state,
            },
            "blockers": {
                "digest": self.blocker_digest,
                "values": list(self.blocker_set),
            },
            "future_gates": {
                "identity_trust_revalidation_required": (
                    self.identity_trust_revalidation_required
                ),
                "machine_evidence_required": self.machine_evidence_required,
                "reboot_clear_verification_required": (
                    self.reboot_clear_verification_required
                ),
                "reconnect_required": self.reconnect_required,
                "service_safety_verification_required": (
                    self.service_safety_verification_required
                ),
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "operation": {
                "classification": (
                    self.classification.value
                    if self.classification is not None
                    else _NOT_REQUIRED
                ),
                "id": str(self.operation_id),
                "kind": _OPERATION,
                "stage": _STAGE,
            },
            "plan": {
                "artifact_digest": self.plan_artifact_digest,
                "record_digest": self.plan_record_digest,
                "schema_version": self.plan_schema_version,
                "state": self.plan_state.value,
            },
            "policy": {
                "checkpoint": self.checkpoint_policy,
                "ordering": self.ordering_policy,
                "role_counts": [
                    {"count": count, "role": role} for role, count in self.role_counts
                ],
                "role_counts_digest": self.role_counts_digest,
                "route_relationship_digest": self.route_relationship_digest,
                "serial": self.serial,
                "target_count": self.target_count,
                "target_order_digest": self.target_order_digest,
                "target_set_digest": self.target_set_digest,
            },
            "schema_version": self.schema_version,
            "schemas": {
                "authorization": self.authorization_schema_version,
                "proof": self.proof_schema_version,
            },
            "states": {
                "execution": self.execution_state,
                "reconnect": self.reconnect_state,
                "storage_discover_branch_preserved": (
                    self.storage_discover_branch_preserved
                ),
            },
        }


@dataclass(frozen=True, slots=True)
class _Candidate:
    stable_id: str
    role: HostRole
    attempt_index: int
    step_sequence: int
    target_index: int
    evidence_digest: str
    result_digest: str


def plan_and_authorize_deploy_non_jump_reboots(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proof: DeployNonJumpRebootAuthorizationProof | None,
) -> DeployNonJumpRebootPlanningAuthorizationReport:
    """Plan and authorize only exact post-non-jump-base-OS reboot scope."""

    if proof is not None and not isinstance(
        proof, DeployNonJumpRebootAuthorizationProof
    ):
        raise StateConflictError(
            "deploy non-jump reboot authorization proof is malformed"
        )
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_artifacts(paths, operation_id)
    context = _load_non_jump_context(paths, operation_id, lock=lock)
    planning = (
        context.authorization_context.final_routes.post.post.base.host.loaded.planning
    )
    metadata = planning.base.deploy.metadata.record
    reconciliation_store = DeployPostNonJumpBaseOsReconciliationStore(
        paths, operation_id
    )
    validate_state_file(reconciliation_store.path, allow_missing=True)
    if not reconciliation_store.path.exists():
        raise StateConflictError(
            "deploy non-jump reboot planning requires post-non-jump-base-os "
            "reconciliation"
        )
    reconciliation = reconciliation_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_reconciliation = _build_non_jump_reconciliation(
        context,
        steps=_build_non_jump_steps(context),
        created_at=reconciliation.record.created_at,
    )
    if reconciliation.record != expected_reconciliation:
        raise StateConflictError(
            "deploy non-jump reboot reconciliation drifted; use a new operation"
        )
    candidates = _derive_candidates(context, reconciliation)
    plan_store = DeployNonJumpRebootPlanStore(paths, operation_id)
    authorization_store = DeployNonJumpRebootAuthorizationStore(paths, operation_id)
    validate_state_file(plan_store.path, allow_missing=True)
    validate_state_file(authorization_store.path, allow_missing=True)
    if not candidates:
        _validate_no_reboot_branch(reconciliation)
        if plan_store.path.exists() or authorization_store.path.exists():
            raise StateConflictError(
                "deploy non-jump reboot artifacts conflict with no-reboot evidence"
            )
        if proof is not None:
            raise StateConflictError(
                "deploy non-jump reboot approval is inapplicable when no reboot "
                "is required"
            )
        return _not_required_report(operation_id, reconciliation)
    targets, blockers = _build_targets(context, candidates)
    existing_plan = (
        plan_store.read_locked(
            lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
        )
        if plan_store.path.exists()
        else None
    )
    plan = _build_plan(
        context,
        reconciliation,
        targets=targets,
        blockers=blockers,
        created_at=(
            existing_plan.record.created_at
            if existing_plan is not None
            else format_timestamp(datetime.now(UTC))
        ),
    )
    if existing_plan is not None and existing_plan.record != plan:
        raise StateConflictError(
            "deploy non-jump reboot plan changed; use a new operation"
        )
    try:
        stored_plan, plan_state = plan_store.write_locked(plan, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy non-jump reboot plan persistence failed"
        ) from error
    if blockers:
        if authorization_store.path.exists():
            raise StateConflictError(
                "blocked deploy non-jump reboot plan conflicts with authorization"
            )
        return _report(
            stored_plan,
            plan_state=DeployNonJumpRebootArtifactState.BLOCKED,
            authorization=None,
            authorization_state=DeployNonJumpRebootArtifactState.BLOCKED,
        )
    # A durable plan-only prefix is intentionally recoverable after missing,
    # denied, changed, or unsuccessfully persisted ordinary approval.
    decision = _normalize_proof(proof, stored_plan)
    existing_authorization = (
        authorization_store.read_locked(
            lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
        )
        if authorization_store.path.exists()
        else None
    )
    authorization = _build_authorization(
        stored_plan,
        proof=decision,
        created_at=(
            existing_authorization.record.created_at
            if existing_authorization is not None
            else format_timestamp(datetime.now(UTC))
        ),
    )
    if (
        existing_authorization is not None
        and existing_authorization.record != authorization
    ):
        raise StateConflictError(
            "deploy non-jump reboot authorization changed; use a new operation"
        )
    try:
        stored_authorization, authorization_state = authorization_store.write_locked(
            authorization, lock=lock
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy non-jump reboot authorization persistence failed"
        ) from error
    return _report(
        stored_plan,
        plan_state=plan_state,
        authorization=stored_authorization,
        authorization_state=authorization_state,
    )


def deploy_non_jump_reboot_plan_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_NON_JUMP_REBOOT_PLAN_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError("deploy non-jump reboot plan path is not canonical")
    return path


def deploy_non_jump_reboot_authorization_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy non-jump reboot authorization path is not canonical"
        )
    return path


def deploy_non_jump_reboot_plan_id_from_filename(name: str) -> uuid.UUID | None:
    return _id_from_filename(name, DEPLOY_NON_JUMP_REBOOT_PLAN_FILENAME_SUFFIX)


def deploy_non_jump_reboot_authorization_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(name, DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_FILENAME_SUFFIX)


def _derive_candidates(
    context: _ReconciliationContext,
    reconciliation: StoredDeployPostNonJumpBaseOsReconciliation,
) -> tuple[_Candidate, ...]:
    inventory_hosts = {
        host.logical_id: host
        for host in context.authorization_context.final_routes.post.post.base.host.loaded.planning.base.deploy.inventory.record.inventory.hosts
    }
    candidates: list[_Candidate] = []
    seen: set[str] = set()
    for entry in context.evidence.record.entries:
        for target_index, host in enumerate(entry.hosts, start=1):
            inventory = inventory_hosts.get(host.logical_id)
            if (
                inventory is None
                or inventory.role is HostRole.JUMP_HOST
                or inventory.role not in _SAFE_ROLES
                or host.status
                not in {
                    BaseOsStatus.NO_CHANGE,
                    BaseOsStatus.CHANGED,
                    BaseOsStatus.REBOOT_REQUIRED,
                }
                or not host.applied
            ):
                raise StateConflictError(
                    "deploy non-jump reboot base-os scope is invalid"
                )
            if host.logical_id in seen:
                raise StateConflictError(
                    "deploy non-jump reboot base-os evidence is duplicated"
                )
            seen.add(host.logical_id)
            if host.reboot_required:
                if host.status is not BaseOsStatus.REBOOT_REQUIRED:
                    raise StateConflictError(
                        "deploy non-jump reboot-required evidence conflicts"
                    )
                candidates.append(
                    _Candidate(
                        host.logical_id,
                        inventory.role,
                        entry.attempt_index,
                        entry.step_sequence,
                        target_index,
                        entry.evidence_digest,
                        entry.result_digest,
                    )
                )
    record = reconciliation.record
    if (
        len(candidates) != record.reboot_required_count
        or record.reboot_required != bool(candidates)
        or len({candidate.stable_id for candidate in candidates}) != len(candidates)
    ):
        raise StateConflictError(
            "deploy non-jump reboot-required evidence scope conflicts"
        )
    ordered = tuple(
        sorted(
            candidates,
            key=lambda candidate: (
                candidate.attempt_index,
                candidate.step_sequence,
                candidate.target_index,
                candidate.stable_id,
            ),
        )
    )
    if ordered != tuple(candidates):
        raise StateConflictError(
            "deploy non-jump reboot base-os execution order conflicts"
        )
    return ordered


def _validate_no_reboot_branch(
    reconciliation: StoredDeployPostNonJumpBaseOsReconciliation,
) -> None:
    record = reconciliation.record
    eligible = tuple(
        step
        for step in record.steps
        if step.status is DeployBaseOsReconciledStepStatus.ELIGIBLE
    )
    if (
        record.reboot_required
        or record.reboot_required_count != 0
        or len(eligible) != 1
        or eligible[0].playbook != "storage-discover"
        or eligible[0].target_role != HostRole.SCYLLA.value
    ):
        raise StateConflictError(
            "deploy non-jump reboot no-reboot branch does not preserve storage-discover"
        )


def _build_targets(
    context: _ReconciliationContext,
    candidates: tuple[_Candidate, ...],
) -> tuple[tuple[DeployNonJumpRebootPlanTarget, ...], tuple[str, ...]]:
    authorization_context = context.authorization_context
    final_routes = authorization_context.final_routes
    planning = final_routes.post.post.base.host.loaded.planning
    inventory_hosts = planning.base.deploy.inventory.record.inventory.hosts
    host_by_id = {host.logical_id: host for host in inventory_hosts}
    semantic = authorization_context.evidence.record
    blockers: set[str] = set()
    if (
        not semantic.successful
        or semantic.reachable_jump_count != len(semantic.hosts)
        or semantic.passed_pair_count != len(semantic.pairs)
    ):
        blockers.add("final-routes-connectivity-incomplete")
    ordered = tuple(
        sorted(
            candidates,
            key=lambda candidate: (
                candidate.attempt_index,
                candidate.step_sequence,
                candidate.target_index,
                candidate.stable_id,
            ),
        )
    )
    if ordered != candidates:
        blockers.add("non-jump-base-os-order-incomplete")
    targets: list[DeployNonJumpRebootPlanTarget] = []
    for sequence, candidate in enumerate(ordered, start=1):
        host = host_by_id.get(candidate.stable_id)
        if host is None or host.role is not candidate.role:
            blockers.add("reboot-order-unresolved")
            continue
        jump = (
            host_by_id.get(host.jump_host_id) if host.jump_host_id is not None else None
        )
        if (
            host.jump_host_id is None
            or jump is None
            or jump.role is not HostRole.JUMP_HOST
        ):
            blockers.add("jump-route-dependency-unresolved")
        route_pairs = tuple(
            pair
            for pair in semantic.pairs
            if pair.target_stable_id == candidate.stable_id
            and pair.jump_stable_id == host.jump_host_id
        )
        if not route_pairs or any(
            pair.status is not DestinationProbeStatus.PASSED for pair in route_pairs
        ):
            blockers.add("final-routes-connectivity-incomplete")
        assigned_jump_ids = (
            (host.jump_host_id,) if host.jump_host_id is not None else ()
        )
        route_relationship_digest = _digest_object(
            {
                "assigned_jump_set_digest": _digest_object(sorted(assigned_jump_ids)),
                "final_routes_evidence_digest": semantic.evidence_digest,
                "pair_count": len(route_pairs),
                "pair_set_digest": _digest_object(
                    [
                        {
                            "port": pair.port,
                            "role": pair.role,
                            "target_stable_id": pair.target_stable_id,
                        }
                        for pair in route_pairs
                    ]
                ),
            }
        )
        targets.append(
            DeployNonJumpRebootPlanTarget(
                sequence=sequence,
                stable_id=candidate.stable_id,
                role=candidate.role,
                base_os_attempt_index=candidate.attempt_index,
                base_os_step_sequence=candidate.step_sequence,
                base_os_target_index=candidate.target_index,
                base_os_evidence_digest=candidate.evidence_digest,
                base_os_result_digest=candidate.result_digest,
                route_relationship_count=len(assigned_jump_ids) + len(route_pairs),
                route_relationship_digest=route_relationship_digest,
                trust_identity_digest=_digest_object(
                    {
                        "inventory_digest": planning.base.deploy.inventory.record.inventory_digest,
                        "stable_id": candidate.stable_id,
                        "trust_entries_digest": planning.base.trust.record.entries_digest,
                    }
                ),
                final_routes_evidence_digest=semantic.evidence_digest,
                reconnect_required=True,
                identity_trust_revalidation_required=True,
                machine_evidence_required=True,
                service_safety_verification_required=True,
                reboot_clear_verification_required=True,
                checkpoint_policy=_CHECKPOINT_POLICY,
            )
        )
    if len(targets) != len(candidates):
        blockers.add("reboot-order-unresolved")
    return tuple(targets), tuple(sorted(blockers))


def _build_plan(
    context: _ReconciliationContext,
    reconciliation: StoredDeployPostNonJumpBaseOsReconciliation,
    *,
    targets: tuple[DeployNonJumpRebootPlanTarget, ...],
    blockers: tuple[str, ...],
    created_at: str,
) -> DeployNonJumpRebootPlan:
    authorization_context = context.authorization_context
    final_routes = authorization_context.final_routes
    host = final_routes.post.post.base.host
    planning = host.loaded.planning
    deploy = planning.base.deploy
    journal = deploy.journal
    stable_ids = tuple(target.stable_id for target in targets)
    role_counts = Counter(target.role.value for target in targets)
    blocker_set = tuple(sorted(set(blockers)))
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": str(deploy.metadata.record.cluster_uuid),
        "cluster_name": deploy.metadata.record.cluster_name,
        "operation_id": str(journal.record.operation_id),
        "operation": _OPERATION,
        "stage": _STAGE,
        "scope_kind": _SCOPE,
        "request_digest": journal.record.request_digest,
        "journal_generation": journal.record.generation,
        "journal_digest": journal.digest,
        "journal_status": journal.record.status.value,
        "journal_phase": journal.record.phase.value,
        "post_non_jump_reconciliation_artifact_digest": reconciliation.artifact_digest,
        "post_non_jump_reconciliation_record_digest": reconciliation.record.record_digest,
        "post_non_jump_effective_plan_digest": reconciliation.record.effective_plan_digest,
        "final_routes_execution_artifact_digest": authorization_context.execution.artifact_digest,
        "final_routes_evidence_artifact_digest": authorization_context.evidence.artifact_digest,
        "final_routes_evidence_digest": authorization_context.evidence.record.evidence_digest,
        "final_routes_reconciliation_artifact_digest": authorization_context.reconciliation.artifact_digest,
        "final_routes_reconciliation_record_digest": authorization_context.reconciliation.record.record_digest,
        "non_jump_base_os_authorization_artifact_digest": context.authorization.artifact_digest,
        "non_jump_base_os_execution_artifact_digest": context.execution.artifact_digest,
        "non_jump_base_os_execution_binding_digest": context.execution.record.binding.binding_digest,
        "non_jump_base_os_evidence_artifact_digest": context.evidence.artifact_digest,
        "non_jump_base_os_evidence_digest": context.evidence_digest,
        "inventory_generation": deploy.inventory.record.generation,
        "inventory_artifact_digest": deploy.inventory.digest,
        "inventory_digest": deploy.inventory.record.inventory_digest,
        "trust_generation": planning.base.trust.record.generation,
        "trust_artifact_digest": planning.base.trust.digest,
        "trust_entries_digest": planning.base.trust.record.entries_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": planning.readiness.record.record_digest,
        "catalog_digest": host.loaded.catalog_digest,
        "ansible_source_version": host.loaded.source.version,
        "ansible_source_digest": host.loaded.source.digest,
        "classification": OperationClassification.MUTATING.value,
        "ordering_policy": _ORDERING_POLICY,
        "serial": _SERIAL,
        "targets": [target.to_object() for target in targets],
        "target_count": len(targets),
        "target_set_digest": _digest_object(sorted(stable_ids)),
        "target_order_digest": _digest_object(list(stable_ids)),
        "role_counts_digest": _digest_object(
            [
                {"count": count, "role": role}
                for role, count in sorted(role_counts.items())
            ]
        ),
        "route_relationship_digest": _digest_object(
            [target.route_relationship_digest for target in targets]
        ),
        "checkpoint_policy": _CHECKPOINT_POLICY,
        "blocker_set": list(blocker_set),
        "blocker_digest": _digest_object(list(blocker_set)),
        "planning_state": _BLOCKED if blocker_set else _READY,
        "authorization_state": _NOT_COLLECTED,
        "authorization_consumed": False,
        "execution_state": _UNAVAILABLE,
        "reconnect_state": _NOT_PERFORMED,
        "record_digest": "",
        "post_non_jump_reconciliation_schema_version": (
            ANSIBLE_DEPLOY_POST_NON_JUMP_BASE_OS_RECONCILIATION_SCHEMA_VERSION
        ),
        "final_routes_execution_schema_version": (
            ANSIBLE_DEPLOY_FINAL_ROUTES_EXECUTION_SCHEMA_VERSION
        ),
        "final_routes_evidence_schema_version": (
            ANSIBLE_DEPLOY_FINAL_ROUTES_EVIDENCE_SCHEMA_VERSION
        ),
        "final_routes_reconciliation_schema_version": (
            ANSIBLE_DEPLOY_POST_FINAL_ROUTES_RECONCILIATION_SCHEMA_VERSION
        ),
        "non_jump_base_os_execution_schema_version": (
            ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EXECUTION_SCHEMA_VERSION
        ),
        "non_jump_base_os_evidence_schema_version": (
            ANSIBLE_DEPLOY_NON_JUMP_BASE_OS_EVIDENCE_SCHEMA_VERSION
        ),
        "readiness_schema_version": TERRAFORM_APPLY_READINESS_SCHEMA_VERSION,
        "journal_schema_version": JOURNAL_SCHEMA_VERSION,
        "schema_version": ANSIBLE_DEPLOY_NON_JUMP_REBOOT_PLAN_SCHEMA_VERSION,
    }
    values["record_digest"] = _record_digest(values, "record_digest")
    return DeployNonJumpRebootPlan.from_object(values)


def _normalize_proof(
    proof: DeployNonJumpRebootAuthorizationProof | None,
    plan: StoredDeployNonJumpRebootPlan,
) -> DeployNonJumpRebootProofDecision:
    if proof is None or proof.approval_method is None:
        raise StateConflictError("ordinary deploy non-jump reboot approval is required")
    if not proof.approved:
        raise StateConflictError("ordinary deploy non-jump reboot approval was denied")
    if proof.allow_destructive or proof.destructive_scope_provided:
        raise StateConflictError(
            "destructive proof is inapplicable to mutating non-jump reboot "
            "authorization"
        )
    values: dict[str, object] = {
        "allow_destructive": False,
        "approval_method": proof.approval_method.value,
        "approved": True,
        "destructive_scope_provided": False,
        "proof_digest": "",
        "schema_version": (
            ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION
        ),
    }
    values["proof_digest"] = _proof_digest_values(plan, values)
    return DeployNonJumpRebootProofDecision.from_object(values)


def _build_authorization(
    plan: StoredDeployNonJumpRebootPlan,
    *,
    proof: DeployNonJumpRebootProofDecision,
    created_at: str,
) -> DeployNonJumpRebootAuthorization:
    record = plan.record
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": str(record.cluster_uuid),
        "cluster_name": record.cluster_name,
        "operation_id": str(record.operation_id),
        "operation": record.operation,
        "stage": record.stage,
        "scope_kind": record.scope_kind,
        "request_digest": record.request_digest,
        "journal_generation": record.journal_generation,
        "journal_digest": record.journal_digest,
        "journal_status": record.journal_status.value,
        "journal_phase": record.journal_phase.value,
        "plan_artifact_digest": plan.artifact_digest,
        "plan_record_digest": record.record_digest,
        "post_non_jump_reconciliation_artifact_digest": (
            record.post_non_jump_reconciliation_artifact_digest
        ),
        "final_routes_evidence_digest": record.final_routes_evidence_digest,
        "non_jump_base_os_evidence_digest": record.non_jump_base_os_evidence_digest,
        "inventory_digest": record.inventory_digest,
        "trust_entries_digest": record.trust_entries_digest,
        "readiness_record_digest": record.readiness_record_digest,
        "catalog_digest": record.catalog_digest,
        "ansible_source_digest": record.ansible_source_digest,
        "classification": record.classification.value,
        "target_count": record.target_count,
        "target_set_digest": record.target_set_digest,
        "target_order_digest": record.target_order_digest,
        "role_counts_digest": record.role_counts_digest,
        "route_relationship_digest": record.route_relationship_digest,
        "serial": record.serial,
        "ordering_policy": record.ordering_policy,
        "checkpoint_policy": record.checkpoint_policy,
        "blocker_digest": record.blocker_digest,
        "proof": proof.to_object(),
        "authorization_state": _AUTHORIZED,
        "consumed": False,
        "execution_state": _UNAVAILABLE,
        "reconnect_state": _NOT_PERFORMED,
        "authorization_digest": "",
        "plan_schema_version": record.schema_version,
        "journal_schema_version": record.journal_schema_version,
        "schema_version": (ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_SCHEMA_VERSION),
    }
    values["authorization_digest"] = _record_digest(values, "authorization_digest")
    return DeployNonJumpRebootAuthorization.from_object(values)


def _not_required_report(
    operation_id: uuid.UUID,
    reconciliation: StoredDeployPostNonJumpBaseOsReconciliation,
) -> DeployNonJumpRebootPlanningAuthorizationReport:
    record = reconciliation.record
    return DeployNonJumpRebootPlanningAuthorizationReport(
        operation_id=operation_id,
        plan_state=DeployNonJumpRebootArtifactState.NOT_REQUIRED,
        authorization_artifact_state=DeployNonJumpRebootArtifactState.NOT_REQUIRED,
        plan_artifact_digest=None,
        plan_record_digest=None,
        authorization_artifact_digest=None,
        authorization_digest=None,
        proof_digest=None,
        target_count=0,
        target_set_digest=None,
        target_order_digest=None,
        role_counts=(),
        role_counts_digest=None,
        route_relationship_digest=None,
        serial=_SERIAL,
        ordering_policy=_ORDERING_POLICY,
        checkpoint_policy=_CHECKPOINT_POLICY,
        classification=None,
        approval_method=None,
        authorization_state=_NOT_REQUIRED,
        authorization_consumed=False,
        execution_state=_UNAVAILABLE,
        reconnect_state=_NOT_PERFORMED,
        reconnect_required=False,
        identity_trust_revalidation_required=False,
        machine_evidence_required=False,
        service_safety_verification_required=False,
        reboot_clear_verification_required=False,
        storage_discover_branch_preserved=True,
        blocker_set=(),
        blocker_digest=_digest_object([]),
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
    )


def _report(
    plan: StoredDeployNonJumpRebootPlan,
    *,
    plan_state: DeployNonJumpRebootArtifactState,
    authorization: StoredDeployNonJumpRebootAuthorization | None,
    authorization_state: DeployNonJumpRebootArtifactState,
) -> DeployNonJumpRebootPlanningAuthorizationReport:
    record = plan.record
    counts = tuple(
        sorted(Counter(target.role.value for target in record.targets).items())
    )
    return DeployNonJumpRebootPlanningAuthorizationReport(
        operation_id=record.operation_id,
        plan_state=plan_state,
        authorization_artifact_state=authorization_state,
        plan_artifact_digest=plan.artifact_digest,
        plan_record_digest=record.record_digest,
        authorization_artifact_digest=(
            authorization.artifact_digest if authorization is not None else None
        ),
        authorization_digest=(
            authorization.record.authorization_digest
            if authorization is not None
            else None
        ),
        proof_digest=(
            authorization.record.proof.proof_digest
            if authorization is not None
            else None
        ),
        target_count=record.target_count,
        target_set_digest=record.target_set_digest,
        target_order_digest=record.target_order_digest,
        role_counts=counts,
        role_counts_digest=record.role_counts_digest,
        route_relationship_digest=record.route_relationship_digest,
        serial=record.serial,
        ordering_policy=record.ordering_policy,
        checkpoint_policy=record.checkpoint_policy,
        classification=record.classification,
        approval_method=(
            authorization.record.proof.approval_method
            if authorization is not None
            else None
        ),
        authorization_state=(
            authorization.record.authorization_state
            if authorization is not None
            else _BLOCKED
        ),
        authorization_consumed=False,
        execution_state=_UNAVAILABLE,
        reconnect_state=_NOT_PERFORMED,
        reconnect_required=True,
        identity_trust_revalidation_required=True,
        machine_evidence_required=True,
        service_safety_verification_required=True,
        reboot_clear_verification_required=True,
        storage_discover_branch_preserved=False,
        blocker_set=record.blocker_set,
        blocker_digest=record.blocker_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
    )


def _proof_digest(
    record: DeployNonJumpRebootAuthorization, proof: Mapping[str, object]
) -> str:
    proof_value = dict(proof)
    proof_value["proof_digest"] = ""
    return _digest_object(
        {
            "cluster_uuid": str(record.cluster_uuid),
            "journal_digest": record.journal_digest,
            "operation_id": str(record.operation_id),
            "plan_artifact_digest": record.plan_artifact_digest,
            "plan_record_digest": record.plan_record_digest,
            "proof": proof_value,
            "schema_version": (
                ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION
            ),
            "target_order_digest": record.target_order_digest,
            "target_set_digest": record.target_set_digest,
        }
    )


def _proof_digest_values(
    plan: StoredDeployNonJumpRebootPlan, proof: Mapping[str, object]
) -> str:
    proof_value = dict(proof)
    proof_value["proof_digest"] = ""
    return _digest_object(
        {
            "cluster_uuid": str(plan.record.cluster_uuid),
            "journal_digest": plan.record.journal_digest,
            "operation_id": str(plan.record.operation_id),
            "plan_artifact_digest": plan.artifact_digest,
            "plan_record_digest": plan.record.record_digest,
            "proof": proof_value,
            "schema_version": (
                ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION
            ),
            "target_order_digest": plan.record.target_order_digest,
            "target_set_digest": plan.record.target_set_digest,
        }
    )


def _plan_digests(record: DeployNonJumpRebootPlan) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(record, name))
        for name in record.__dataclass_fields__
        if name.endswith("_digest")
    )


def _authorization_digests(
    record: DeployNonJumpRebootAuthorization,
) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(record, name))
        for name in record.__dataclass_fields__
        if name.endswith("_digest")
    )


def _record_digest(value: Mapping[str, object], field: str) -> str:
    copied = dict(value)
    copied[field] = ""
    return _digest_object(copied)


def _id_from_filename(name: str, suffix: str) -> uuid.UUID | None:
    if not name.endswith(suffix):
        return None
    value = name[: -len(suffix)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy non-jump reboot artifacts"
        ) from error
    canonical = str(operation_id)
    for suffix in (
        DEPLOY_NON_JUMP_REBOOT_PLAN_FILENAME_SUFFIX,
        DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_FILENAME_SUFFIX,
    ):
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
                    "deploy non-jump reboot artifacts are ambiguous"
                )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError("deploy non-jump reboot paths are not canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy non-jump reboot planning requires acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _positive_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


def _nonnegative_integer(value: object, label: str) -> None:
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


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise StatePersistenceError(f"{label} must be a string array")
    return tuple(value)


def _enum(enum_type: type[StrEnum], value: str, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except ValueError as error:
        raise StatePersistenceError(
            f"deploy non-jump reboot {label} is invalid"
        ) from error


__all__ = [
    "ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_NON_JUMP_REBOOT_PLAN_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_NON_JUMP_REBOOT_REPORT_SCHEMA_VERSION",
    "DEPLOY_NON_JUMP_REBOOT_AUTHORIZATION_FILENAME_SUFFIX",
    "DEPLOY_NON_JUMP_REBOOT_PLAN_FILENAME_SUFFIX",
    "DeployNonJumpRebootApprovalMethod",
    "DeployNonJumpRebootArtifactState",
    "DeployNonJumpRebootAuthorization",
    "DeployNonJumpRebootAuthorizationProof",
    "DeployNonJumpRebootAuthorizationStore",
    "DeployNonJumpRebootPlan",
    "DeployNonJumpRebootPlanStore",
    "DeployNonJumpRebootPlanTarget",
    "DeployNonJumpRebootPlanningAuthorizationReport",
    "DeployNonJumpRebootProofDecision",
    "StoredDeployNonJumpRebootAuthorization",
    "StoredDeployNonJumpRebootPlan",
    "deploy_non_jump_reboot_authorization_id_from_filename",
    "deploy_non_jump_reboot_authorization_path",
    "deploy_non_jump_reboot_plan_id_from_filename",
    "deploy_non_jump_reboot_plan_path",
    "plan_and_authorize_deploy_non_jump_reboots",
]
