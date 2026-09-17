"""Immutable deploy reboot planning and ordinary authorization.

This internal boundary plans only the exact hosts whose successful ``base-os``
semantic evidence reports a required reboot.  It never executes a reboot,
contacts a host, advances the common journal, or creates execution intent.
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
    ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION,
    DeployBaseOsReconciliationStore,
    StoredDeployBaseOsReconciliation,
    _BaseOsReconciliationContext,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    _build_record as _build_base_os_reconciliation,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    _build_steps as _build_base_os_reconciled_steps,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    _load_context as _load_base_os_context,
)
from scylla_vms.ansible.deploy_plan import _digest_object, _require_operation_id
from scylla_vms.ansible.deploy_prerequisites import (
    DeployPrerequisiteEvidenceStatus,
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

ANSIBLE_DEPLOY_REBOOT_PLAN_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-reboot-plan/v1"
)
ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-reboot-authorization/v1"
)
ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-reboot-authorization-proof/v1"
)
ANSIBLE_DEPLOY_REBOOT_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-reboot-plan-authorization-report/v1"
)
DEPLOY_REBOOT_PLAN_FILENAME_SUFFIX = ".ansible-deploy-reboot-plan.json"
DEPLOY_REBOOT_AUTHORIZATION_FILENAME_SUFFIX = (
    ".ansible-deploy-reboot-authorization.json"
)

_OPERATION = "deploy"
_ORDERING_POLICY = "base-os-execution-then-stable-id/v1"
_CHECKPOINT_POLICY = "reconnect-identity-machine-reboot-clear-before-next/v1"
_READY = "ready-for-authorization"
_BLOCKED = "blocked"
_AUTHORIZED = "authorized-pre-execution"
_NOT_COLLECTED = "not-collected"
_NOT_REQUIRED = "not-required"
_NOT_PERFORMED = "not-performed"
_UNAVAILABLE = "unavailable"
_SERIAL = 1
_ROLE_ORDER = (
    HostRole.JUMP_HOST,
    HostRole.SCYLLA,
    HostRole.MANAGER,
    HostRole.MONITORING,
)
_ROLE_RANK = {role: index for index, role in enumerate(_ROLE_ORDER)}
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")


class DeployRebootApprovalMethod(StrEnum):
    """PLAN-permitted ordinary approval methods."""

    INTERACTIVE = "interactive"
    CLI_YES = "cli-yes"


class DeployRebootArtifactState(StrEnum):
    """Persistence state for one immutable reboot companion."""

    CREATED = "created"
    REUSED = "reused"
    NOT_REQUIRED = "not-required"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class DeployRebootAuthorizationProof:
    """Already-normalized ordinary approval without prompt or operator data."""

    approval_method: DeployRebootApprovalMethod | None = None
    approved: bool = False
    allow_destructive: bool = False
    destructive_scope_provided: bool = False

    def __post_init__(self) -> None:
        if self.approval_method is not None and not isinstance(
            self.approval_method, DeployRebootApprovalMethod
        ):
            raise StateConflictError("deploy reboot approval method is invalid")
        if not all(
            isinstance(value, bool)
            for value in (
                self.approved,
                self.allow_destructive,
                self.destructive_scope_provided,
            )
        ):
            raise StateConflictError("deploy reboot approval proof is malformed")


@dataclass(frozen=True, slots=True)
class DeployRebootProofDecision:
    """Persisted normalized proof bound to one exact reboot plan."""

    approval_method: DeployRebootApprovalMethod
    approved: bool
    allow_destructive: bool
    destructive_scope_provided: bool
    proof_digest: str
    schema_version: str = ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or not isinstance(self.approval_method, DeployRebootApprovalMethod)
            or self.approved is not True
            or self.allow_destructive is not False
            or self.destructive_scope_provided is not False
        ):
            raise StatePersistenceError("deploy reboot authorization proof is invalid")
        validate_digest(self.proof_digest, "deploy reboot proof digest")

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
    def from_object(cls, value: Mapping[str, object]) -> DeployRebootProofDecision:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy reboot authorization proof",
        )
        for name in ("approved", "allow_destructive", "destructive_scope_provided"):
            if not isinstance(value[name], bool):
                raise StatePersistenceError(
                    "deploy reboot authorization proof boolean is invalid"
                )
        try:
            method = DeployRebootApprovalMethod(
                require_string(value, "approval_method")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy reboot authorization proof method is invalid"
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
class DeployRebootPlanTarget:
    """One exact stable-ID reboot checkpoint without executable content."""

    sequence: int
    stable_id: str
    role: HostRole
    base_os_step_sequence: int
    base_os_evidence_digest: str
    base_os_result_digest: str
    route_relationship_count: int
    route_relationship_digest: str
    trust_identity_digest: str
    connectivity_evidence_digest: str
    reconnect_required: bool
    identity_trust_revalidation_required: bool
    machine_evidence_required: bool
    reboot_clear_verification_required: bool
    checkpoint_policy: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 1
            or _LOGICAL_ID.fullmatch(self.stable_id) is None
            or not isinstance(self.role, HostRole)
            or isinstance(self.base_os_step_sequence, bool)
            or not isinstance(self.base_os_step_sequence, int)
            or self.base_os_step_sequence < 1
            or isinstance(self.route_relationship_count, bool)
            or not isinstance(self.route_relationship_count, int)
            or self.route_relationship_count < 0
            or self.reconnect_required is not True
            or self.identity_trust_revalidation_required is not True
            or self.machine_evidence_required is not True
            or self.reboot_clear_verification_required is not True
            or self.checkpoint_policy != _CHECKPOINT_POLICY
        ):
            raise StatePersistenceError("deploy reboot target policy is invalid")
        for value in (
            self.base_os_evidence_digest,
            self.base_os_result_digest,
            self.route_relationship_digest,
            self.trust_identity_digest,
            self.connectivity_evidence_digest,
        ):
            validate_digest(value, "deploy reboot target digest")

    def to_object(self) -> dict[str, object]:
        return {
            "base_os_evidence_digest": self.base_os_evidence_digest,
            "base_os_result_digest": self.base_os_result_digest,
            "base_os_step_sequence": self.base_os_step_sequence,
            "checkpoint_policy": self.checkpoint_policy,
            "connectivity_evidence_digest": self.connectivity_evidence_digest,
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
            "stable_id": self.stable_id,
            "trust_identity_digest": self.trust_identity_digest,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployRebootPlanTarget:
        require_exact_keys(value, set(cls.__dataclass_fields__), "deploy reboot target")
        try:
            role = HostRole(require_string(value, "role"))
        except ValueError as error:
            raise StatePersistenceError(
                "deploy reboot target role is invalid"
            ) from error
        return cls(
            sequence=_integer(value["sequence"], "reboot target sequence"),
            stable_id=require_string(value, "stable_id"),
            role=role,
            base_os_step_sequence=_integer(
                value["base_os_step_sequence"], "base-os step sequence"
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
            connectivity_evidence_digest=require_string(
                value, "connectivity_evidence_digest"
            ),
            reconnect_required=_boolean(
                value["reconnect_required"], "reconnect requirement"
            ),
            identity_trust_revalidation_required=_boolean(
                value["identity_trust_revalidation_required"],
                "identity/trust requirement",
            ),
            machine_evidence_required=_boolean(
                value["machine_evidence_required"], "machine evidence requirement"
            ),
            reboot_clear_verification_required=_boolean(
                value["reboot_clear_verification_required"],
                "reboot-clear requirement",
            ),
            checkpoint_policy=require_string(value, "checkpoint_policy"),
        )


@dataclass(frozen=True, slots=True)
class DeployRebootPlan:
    """Immutable operation-bound reboot plan."""

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
    original_plan_artifact_digest: str
    effective_plan_artifact_digest: str
    pre_mutation_execution_artifact_digest: str
    pre_mutation_evidence_artifact_digest: str
    pre_mutation_evidence_digest: str
    host_reconciliation_artifact_digest: str
    base_os_reconciliation_artifact_digest: str
    base_os_reconciliation_record_digest: str
    base_os_reconciled_plan_digest: str
    base_os_authorization_artifact_digest: str
    base_os_execution_artifact_digest: str
    base_os_evidence_artifact_digest: str
    base_os_evidence_digest: str
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    trust_generation: int
    trust_artifact_digest: str
    trust_entries_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    connectivity_execution_artifact_digest: str
    connectivity_evidence_artifact_digest: str
    connectivity_evidence_digest: str
    route_digest: str
    catalog_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    classification: OperationClassification
    ordering_policy: str
    serial: int
    targets: tuple[DeployRebootPlanTarget, ...]
    target_count: int
    target_set_digest: str
    target_order_digest: str
    role_order: tuple[HostRole, ...]
    role_order_digest: str
    role_batch_digest: str
    reconnect_checkpoint_required: bool
    identity_trust_revalidation_required: bool
    machine_evidence_required: bool
    reboot_clear_verification_required: bool
    blocker_set: tuple[str, ...]
    blocker_digest: str
    planning_state: str
    authorization_state: str
    authorization_consumed: bool
    execution_state: str
    reconnect_state: str
    record_digest: str
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    base_os_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = ANSIBLE_DEPLOY_REBOOT_PLAN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version != ANSIBLE_DEPLOY_REBOOT_PLAN_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.base_os_reconciliation_schema_version
            != ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.classification is not OperationClassification.MUTATING
            or self.ordering_policy != _ORDERING_POLICY
            or self.serial != _SERIAL
            or self.authorization_state != _NOT_COLLECTED
            or self.authorization_consumed
            or self.execution_state != _UNAVAILABLE
            or self.reconnect_state != _NOT_PERFORMED
            or self.reconnect_checkpoint_required is not True
            or self.identity_trust_revalidation_required is not True
            or self.machine_evidence_required is not True
            or self.reboot_clear_verification_required is not True
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
        ):
            raise StatePersistenceError(
                "deploy reboot plan identity or policy is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        _positive_integer(self.journal_generation, "journal generation")
        _positive_integer(self.inventory_generation, "inventory generation")
        _positive_integer(self.trust_generation, "trust generation")
        stable_ids = tuple(target.stable_id for target in self.targets)
        roles = tuple(dict.fromkeys(target.role for target in self.targets))
        batches = [
            {
                "count": sum(target.role is role for target in self.targets),
                "role": role.value,
                "target_digest": _digest_object(
                    [target.stable_id for target in self.targets if target.role is role]
                ),
            }
            for role in roles
        ]
        if (
            not self.targets
            or self.target_count != len(self.targets)
            or tuple(target.sequence for target in self.targets)
            != tuple(range(1, len(self.targets) + 1))
            or len(set(stable_ids)) != len(stable_ids)
            or self.target_set_digest != _digest_object(sorted(stable_ids))
            or self.target_order_digest != _digest_object(list(stable_ids))
            or self.role_order != roles
            or self.role_order_digest
            != _digest_object([role.value for role in self.role_order])
            or self.role_batch_digest != _digest_object(batches)
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blocker_set)
            or self.blocker_digest != _digest_object(list(self.blocker_set))
            or self.planning_state != (_BLOCKED if self.blocker_set else _READY)
        ):
            raise StatePersistenceError("deploy reboot plan summary conflicts")
        for value in _plan_digests(self):
            validate_digest(value, "deploy reboot plan digest")
        if self.record_digest != _record_digest(self.to_object()):
            raise StatePersistenceError("deploy reboot plan record digest conflicts")

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
                else [role.value for role in value]
                if name == "role_order"
                else list(value)
                if name == "blocker_set"
                else value
            )
        return result

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployRebootPlan:
        require_exact_keys(value, set(cls.__dataclass_fields__), "deploy reboot plan")
        integer_fields = {
            "generation",
            "journal_generation",
            "inventory_generation",
            "trust_generation",
            "serial",
            "target_count",
        }
        boolean_fields = {
            "reconnect_checkpoint_required",
            "identity_trust_revalidation_required",
            "machine_evidence_required",
            "reboot_clear_verification_required",
            "authorization_consumed",
        }
        parsed: dict[str, object] = {}
        for name in cls.__dataclass_fields__:
            item = value[name]
            if name in integer_fields:
                parsed[name] = _integer(item, name)
            elif name in boolean_fields:
                parsed[name] = _boolean(item, name)
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
                    DeployRebootPlanTarget.from_object(
                        _mapping(item, "deploy reboot target")
                    )
                    for item in _array(item, "deploy reboot targets")
                )
            elif name == "role_order":
                try:
                    parsed[name] = tuple(
                        HostRole(role)
                        for role in _string_tuple(item, "deploy reboot role order")
                    )
                except ValueError as error:
                    raise StatePersistenceError(
                        "deploy reboot role order is invalid"
                    ) from error
            elif name == "blocker_set":
                parsed[name] = _string_tuple(item, "deploy reboot blockers")
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployRebootPlan:
    record: DeployRebootPlan
    artifact_digest: str


class DeployRebootPlanStore:
    """Owner-only immutable reboot plan at its canonical operation path."""

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
        self._path = deploy_reboot_plan_path(paths, operation_id)
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
    ) -> StoredDeployRebootPlan:
        value, artifact_digest = self._file.read()
        record = DeployRebootPlan.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError("deploy reboot plan identity conflicts")
        return StoredDeployRebootPlan(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployRebootPlan:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployRebootPlan,
        *,
        lock: ClusterLock,
    ) -> tuple[StoredDeployRebootPlan, DeployRebootArtifactState]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError("deploy reboot plan operation conflicts")
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy reboot plan is immutable; use a new operation"
                )
            return current, DeployRebootArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployRebootPlan(record, artifact_digest),
            DeployRebootArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployRebootAuthorization:
    """Immutable unconsumed authorization for one exact ready reboot plan."""

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
    reboot_plan_artifact_digest: str
    reboot_plan_record_digest: str
    base_os_reconciliation_artifact_digest: str
    inventory_digest: str
    trust_entries_digest: str
    readiness_record_digest: str
    connectivity_evidence_digest: str
    catalog_digest: str
    ansible_source_digest: str
    blocker_digest: str
    classification: OperationClassification
    target_count: int
    target_set_digest: str
    target_order_digest: str
    role_order_digest: str
    role_batch_digest: str
    serial: int
    checkpoint_policy: str
    proof: DeployRebootProofDecision
    authorization_state: str
    consumed: bool
    execution_state: str
    reconnect_state: str
    authorization_digest: str
    reboot_plan_schema_version: str = ANSIBLE_DEPLOY_REBOOT_PLAN_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version != ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_SCHEMA_VERSION
            or self.reboot_plan_schema_version
            != ANSIBLE_DEPLOY_REBOOT_PLAN_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.classification is not OperationClassification.MUTATING
            or self.target_count < 1
            or self.serial != _SERIAL
            or self.checkpoint_policy != _CHECKPOINT_POLICY
            or self.blocker_digest != _digest_object([])
            or self.authorization_state != _AUTHORIZED
            or self.consumed
            or self.execution_state != _UNAVAILABLE
            or self.reconnect_state != _NOT_PERFORMED
            or not isinstance(self.proof, DeployRebootProofDecision)
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
        ):
            raise StatePersistenceError(
                "deploy reboot authorization identity or state is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        _positive_integer(self.journal_generation, "journal generation")
        for value in _authorization_digests(self):
            validate_digest(value, "deploy reboot authorization digest")
        if self.proof.proof_digest != _proof_digest(self, self.proof.to_object()):
            raise StatePersistenceError("deploy reboot proof digest conflicts")
        if self.authorization_digest != _record_digest(self.to_object()):
            raise StatePersistenceError("deploy reboot authorization digest conflicts")

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
    def from_object(cls, value: Mapping[str, object]) -> DeployRebootAuthorization:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy reboot authorization",
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
                request_digest=require_string(value, "request_digest"),
                journal_generation=_integer(
                    value["journal_generation"], "journal generation"
                ),
                journal_digest=require_string(value, "journal_digest"),
                journal_status=JournalStatus(require_string(value, "journal_status")),
                journal_phase=OperationPhase(require_string(value, "journal_phase")),
                reboot_plan_artifact_digest=require_string(
                    value, "reboot_plan_artifact_digest"
                ),
                reboot_plan_record_digest=require_string(
                    value, "reboot_plan_record_digest"
                ),
                base_os_reconciliation_artifact_digest=require_string(
                    value, "base_os_reconciliation_artifact_digest"
                ),
                inventory_digest=require_string(value, "inventory_digest"),
                trust_entries_digest=require_string(value, "trust_entries_digest"),
                readiness_record_digest=require_string(
                    value, "readiness_record_digest"
                ),
                connectivity_evidence_digest=require_string(
                    value, "connectivity_evidence_digest"
                ),
                catalog_digest=require_string(value, "catalog_digest"),
                ansible_source_digest=require_string(value, "ansible_source_digest"),
                blocker_digest=require_string(value, "blocker_digest"),
                classification=OperationClassification(
                    require_string(value, "classification")
                ),
                target_count=_integer(value["target_count"], "target count"),
                target_set_digest=require_string(value, "target_set_digest"),
                target_order_digest=require_string(value, "target_order_digest"),
                role_order_digest=require_string(value, "role_order_digest"),
                role_batch_digest=require_string(value, "role_batch_digest"),
                serial=_integer(value["serial"], "serial"),
                checkpoint_policy=require_string(value, "checkpoint_policy"),
                proof=DeployRebootProofDecision.from_object(
                    _mapping(value["proof"], "deploy reboot proof")
                ),
                authorization_state=require_string(value, "authorization_state"),
                consumed=_boolean(value["consumed"], "consumed"),
                execution_state=require_string(value, "execution_state"),
                reconnect_state=require_string(value, "reconnect_state"),
                authorization_digest=require_string(value, "authorization_digest"),
                reboot_plan_schema_version=require_string(
                    value, "reboot_plan_schema_version"
                ),
                journal_schema_version=require_string(value, "journal_schema_version"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy reboot authorization enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class StoredDeployRebootAuthorization:
    record: DeployRebootAuthorization
    artifact_digest: str


class DeployRebootAuthorizationStore:
    """Owner-only immutable reboot authorization."""

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
        self._path = deploy_reboot_authorization_path(paths, operation_id)
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
    ) -> StoredDeployRebootAuthorization:
        value, artifact_digest = self._file.read()
        record = DeployRebootAuthorization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "deploy reboot authorization identity conflicts"
            )
        return StoredDeployRebootAuthorization(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployRebootAuthorization:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployRebootAuthorization,
        *,
        lock: ClusterLock,
    ) -> tuple[StoredDeployRebootAuthorization, DeployRebootArtifactState]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy reboot authorization operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy reboot authorization is immutable; use a new operation"
                )
            return current, DeployRebootArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployRebootAuthorization(record, artifact_digest),
            DeployRebootArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployRebootPlanningAuthorizationReport:
    """Strict redacted planning/authorization projection."""

    operation_id: uuid.UUID
    plan_state: DeployRebootArtifactState
    authorization_artifact_state: DeployRebootArtifactState
    plan_artifact_digest: str | None
    plan_record_digest: str | None
    authorization_artifact_digest: str | None
    authorization_digest: str | None
    proof_digest: str | None
    target_count: int
    target_set_digest: str | None
    target_order_digest: str | None
    role_counts: tuple[tuple[str, int], ...]
    role_order_digest: str | None
    role_batch_digest: str | None
    serial: int
    ordering_policy: str
    classification: OperationClassification | None
    approval_method: DeployRebootApprovalMethod | None
    authorization_state: str
    authorization_consumed: bool
    execution_state: str
    reconnect_state: str
    reconnect_checkpoint_required: bool
    identity_trust_revalidation_required: bool
    machine_evidence_required: bool
    reboot_clear_verification_required: bool
    blocker_set: tuple[str, ...]
    blocker_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    plan_schema_version: str = ANSIBLE_DEPLOY_REBOOT_PLAN_SCHEMA_VERSION
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_SCHEMA_VERSION
    )
    proof_schema_version: str = ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_REBOOT_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_DEPLOY_REBOOT_REPORT_SCHEMA_VERSION
            or self.plan_schema_version != ANSIBLE_DEPLOY_REBOOT_PLAN_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION
            or not isinstance(self.operation_id, uuid.UUID)
            or self.serial != _SERIAL
            or self.ordering_policy != _ORDERING_POLICY
            or self.authorization_consumed
            or self.execution_state != _UNAVAILABLE
            or self.reconnect_state != _NOT_PERFORMED
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blocker_set)
            or self.blocker_digest != _digest_object(list(self.blocker_set))
            or self.role_counts
            != tuple(sorted(self.role_counts, key=lambda item: item[0]))
            or len({role for role, _count in self.role_counts}) != len(self.role_counts)
            or any(
                role not in {item.value for item in _ROLE_ORDER}
                for role, _count in self.role_counts
            )
        ):
            raise StatePersistenceError("deploy reboot report is invalid")
        _nonnegative_integer(self.target_count, "reboot report target count")
        for _role, count in self.role_counts:
            _positive_integer(count, "reboot report role count")
        if self.target_count != sum(count for _role, count in self.role_counts):
            raise StatePersistenceError("deploy reboot report counts conflict")
        for value in (
            self.plan_artifact_digest,
            self.plan_record_digest,
            self.authorization_artifact_digest,
            self.authorization_digest,
            self.proof_digest,
            self.target_set_digest,
            self.target_order_digest,
            self.role_order_digest,
            self.role_batch_digest,
        ):
            if value is not None:
                validate_digest(value, "deploy reboot report digest")
        required = self.target_count > 0
        if required != (self.classification is OperationClassification.MUTATING):
            raise StatePersistenceError("deploy reboot report classification conflicts")
        if not required:
            if (
                self.plan_state is not DeployRebootArtifactState.NOT_REQUIRED
                or self.authorization_artifact_state
                is not DeployRebootArtifactState.NOT_REQUIRED
                or self.authorization_state != _NOT_REQUIRED
                or self.role_counts
                or self.blocker_set
                or self.reconnect_checkpoint_required
                or self.identity_trust_revalidation_required
                or self.machine_evidence_required
                or self.reboot_clear_verification_required
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
                        self.role_order_digest,
                        self.role_batch_digest,
                        self.approval_method,
                    )
                )
            ):
                raise StatePersistenceError(
                    "deploy reboot not-required report conflicts"
                )
            return
        if (
            not self.reconnect_checkpoint_required
            or not self.identity_trust_revalidation_required
            or not self.machine_evidence_required
            or not self.reboot_clear_verification_required
            or any(
                value is None
                for value in (
                    self.plan_artifact_digest,
                    self.plan_record_digest,
                    self.target_set_digest,
                    self.target_order_digest,
                    self.role_order_digest,
                    self.role_batch_digest,
                )
            )
        ):
            raise StatePersistenceError("deploy reboot required report conflicts")
        if self.blocker_set:
            if (
                self.plan_state is not DeployRebootArtifactState.BLOCKED
                or self.authorization_artifact_state
                is not DeployRebootArtifactState.BLOCKED
                or self.authorization_state != _BLOCKED
                or self.approval_method is not None
                or any(
                    value is not None
                    for value in (
                        self.authorization_artifact_digest,
                        self.authorization_digest,
                        self.proof_digest,
                    )
                )
            ):
                raise StatePersistenceError("deploy reboot blocked report conflicts")
        elif (
            self.plan_state
            not in {DeployRebootArtifactState.CREATED, DeployRebootArtifactState.REUSED}
            or self.authorization_artifact_state
            not in {DeployRebootArtifactState.CREATED, DeployRebootArtifactState.REUSED}
            or self.authorization_state != _AUTHORIZED
            or self.approval_method is None
            or any(
                value is None
                for value in (
                    self.authorization_artifact_digest,
                    self.authorization_digest,
                    self.proof_digest,
                )
            )
        ):
            raise StatePersistenceError("deploy reboot authorized report conflicts")

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
            "execution": {
                "available": False,
                "reconnect_state": self.reconnect_state,
                "state": self.execution_state,
            },
            "future_gates": {
                "base_os_reboot_clear_verification_required": (
                    self.reboot_clear_verification_required
                ),
                "identity_trust_revalidation_required": (
                    self.identity_trust_revalidation_required
                ),
                "machine_evidence_required": self.machine_evidence_required,
                "reconnect_checkpoint_required": (self.reconnect_checkpoint_required),
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
            },
            "plan": {
                "artifact_digest": self.plan_artifact_digest,
                "record_digest": self.plan_record_digest,
                "schema_version": self.plan_schema_version,
                "state": self.plan_state.value,
            },
            "policy": {
                "ordering": self.ordering_policy,
                "role_batch_digest": self.role_batch_digest,
                "role_counts": [
                    {"count": count, "role": role} for role, count in self.role_counts
                ],
                "role_order_digest": self.role_order_digest,
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
        }


@dataclass(frozen=True, slots=True)
class _RebootCandidate:
    stable_id: str
    role: HostRole
    base_os_step_sequence: int
    base_os_evidence_digest: str
    base_os_result_digest: str


def plan_and_authorize_deploy_reboots(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proof: DeployRebootAuthorizationProof | None,
) -> DeployRebootPlanningAuthorizationReport:
    """Plan and, when required, authorize exact evidence-bound reboots."""

    if proof is not None and not isinstance(proof, DeployRebootAuthorizationProof):
        raise StateConflictError("deploy reboot authorization proof is malformed")
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_artifacts(paths, operation_id)

    context = _load_base_os_context(paths, operation_id, lock=lock)
    metadata = context.host.loaded.planning.base.deploy.metadata.record
    reconciliation_store = DeployBaseOsReconciliationStore(paths, operation_id)
    validate_state_file(reconciliation_store.path, allow_missing=True)
    if not reconciliation_store.path.exists():
        raise StateConflictError(
            "deploy reboot planning requires post-base-os reconciliation"
        )
    reconciliation = reconciliation_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_reconciliation = _build_base_os_reconciliation(
        context,
        steps=_build_base_os_reconciled_steps(context),
        created_at=reconciliation.record.created_at,
    )
    if reconciliation.record != expected_reconciliation:
        raise StateConflictError("deploy reboot reconciliation drifted")

    candidates = _derive_candidates(context, reconciliation)
    plan_store = DeployRebootPlanStore(paths, operation_id)
    authorization_store = DeployRebootAuthorizationStore(paths, operation_id)
    validate_state_file(plan_store.path, allow_missing=True)
    validate_state_file(authorization_store.path, allow_missing=True)
    if not candidates:
        if plan_store.path.exists() or authorization_store.path.exists():
            raise StateConflictError(
                "deploy reboot artifacts conflict with no-reboot evidence"
            )
        if proof is not None:
            raise StateConflictError(
                "deploy reboot authorization is inapplicable when no reboot is required"
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
    created_at = (
        existing_plan.record.created_at
        if existing_plan is not None
        else format_timestamp(datetime.now(UTC))
    )
    plan = _build_plan(
        context,
        reconciliation,
        targets=targets,
        blockers=blockers,
        created_at=created_at,
    )
    if existing_plan is not None and existing_plan.record != plan:
        raise StateConflictError("deploy reboot plan changed; use a new operation")
    try:
        stored_plan, plan_state = plan_store.write_locked(plan, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError("deploy reboot plan persistence failed") from error

    if blockers:
        if authorization_store.path.exists():
            raise StateConflictError(
                "blocked deploy reboot plan conflicts with authorization"
            )
        return _report(
            stored_plan,
            plan_state=DeployRebootArtifactState.BLOCKED,
            authorization=None,
            authorization_state=DeployRebootArtifactState.BLOCKED,
        )

    # Plan-first ordering intentionally leaves a recoverable exact prefix when
    # proof is missing/denied or authorization persistence later fails.
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
            "deploy reboot authorization changed; use a new operation"
        )
    try:
        stored_authorization, authorization_state = authorization_store.write_locked(
            authorization, lock=lock
        )
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "deploy reboot authorization persistence failed"
        ) from error
    return _report(
        stored_plan,
        plan_state=plan_state,
        authorization=stored_authorization,
        authorization_state=authorization_state,
    )


def deploy_reboot_plan_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / f"{operation_id}{DEPLOY_REBOOT_PLAN_FILENAME_SUFFIX}"
    if path.parent != paths.operations:
        raise StatePersistenceError("deploy reboot plan path is not canonical")
    return path


def deploy_reboot_authorization_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    path = (
        paths.operations
        / f"{operation_id}{DEPLOY_REBOOT_AUTHORIZATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError("deploy reboot authorization path is not canonical")
    return path


def deploy_reboot_plan_id_from_filename(name: str) -> uuid.UUID | None:
    return _id_from_filename(name, DEPLOY_REBOOT_PLAN_FILENAME_SUFFIX)


def deploy_reboot_authorization_id_from_filename(name: str) -> uuid.UUID | None:
    return _id_from_filename(name, DEPLOY_REBOOT_AUTHORIZATION_FILENAME_SUFFIX)


def _derive_candidates(
    context: _BaseOsReconciliationContext,
    reconciliation: StoredDeployBaseOsReconciliation,
) -> tuple[_RebootCandidate, ...]:
    entries = context.evidence.record.entries
    if any(
        host.reboot_required and entry.status is not BaseOsStatus.REBOOT_REQUIRED
        for entry in entries
        for host in entry.hosts
    ):
        raise StateConflictError("deploy reboot-required evidence status conflicts")
    candidates = tuple(
        _RebootCandidate(
            host.logical_id,
            _inventory_role(context, host.logical_id),
            entry.step_sequence,
            entry.evidence_digest,
            entry.result_digest,
        )
        for entry in entries
        for host in entry.hosts
        if host.reboot_required
    )
    if len(candidates) != reconciliation.record.reboot_required_count or len(
        {candidate.stable_id for candidate in candidates}
    ) != len(candidates):
        raise StateConflictError("deploy reboot-required evidence scope conflicts")
    return candidates


def _inventory_role(context: _BaseOsReconciliationContext, stable_id: str) -> HostRole:
    hosts = context.host.loaded.planning.base.deploy.inventory.record.inventory.hosts
    matches = tuple(host for host in hosts if host.logical_id == stable_id)
    if len(matches) != 1:
        raise StateConflictError("deploy reboot target inventory identity conflicts")
    return matches[0].role


def _build_targets(
    context: _BaseOsReconciliationContext,
    candidates: tuple[_RebootCandidate, ...],
) -> tuple[tuple[DeployRebootPlanTarget, ...], tuple[str, ...]]:
    planning = context.host.loaded.planning
    loaded = context.host.loaded
    inventory_hosts = planning.base.deploy.inventory.record.inventory.hosts
    host_by_id = {host.logical_id: host for host in inventory_hosts}
    connectivity = loaded.evidence.record.entries[1]
    all_ids = tuple(sorted(host_by_id))
    blockers: set[str] = set()
    if (
        connectivity.status is not DeployPrerequisiteEvidenceStatus.PASSED
        or connectivity.ssh_connectivity_status != "passed"
        or connectivity.reachable_host_count != len(all_ids)
        or connectivity.target_set_digest != _digest_object(list(all_ids))
    ):
        blockers.add("connectivity-evidence-incomplete")
    ordered = tuple(
        sorted(
            candidates,
            key=lambda item: (
                item.base_os_step_sequence,
                item.stable_id,
            ),
        )
    )
    candidate_ids = {candidate.stable_id for candidate in ordered}
    order_index = {
        candidate.stable_id: index for index, candidate in enumerate(ordered)
    }
    targets: list[DeployRebootPlanTarget] = []
    for sequence, candidate in enumerate(ordered, start=1):
        host = host_by_id.get(candidate.stable_id)
        if host is None or candidate.role not in _ROLE_RANK:
            blockers.add("reboot-order-unresolved")
            continue
        if host.jump_host_id is not None:
            jump = host_by_id.get(host.jump_host_id)
            if jump is None or jump.role is not HostRole.JUMP_HOST:
                blockers.add("jump-route-dependency-unresolved")
            if (
                host.jump_host_id in candidate_ids
                and order_index[host.jump_host_id] >= order_index[candidate.stable_id]
            ):
                blockers.add("jump-route-order-unresolved")
        dependent_ids = tuple(
            sorted(
                item.logical_id
                for item in inventory_hosts
                if item.jump_host_id == candidate.stable_id
            )
        )
        assigned_jump_ids = (
            (host.jump_host_id,) if host.jump_host_id is not None else ()
        )
        route_relationship_digest = _digest_object(
            {
                "assigned_jump_digest": _digest_object(list(assigned_jump_ids)),
                "assigned_jump_selected": bool(
                    host.jump_host_id is not None and host.jump_host_id in candidate_ids
                ),
                "dependent_count": len(dependent_ids),
                "dependent_set_digest": _digest_object(list(dependent_ids)),
                "route_digest": loaded.evidence.record.route_digest,
            }
        )
        targets.append(
            DeployRebootPlanTarget(
                sequence=sequence,
                stable_id=candidate.stable_id,
                role=candidate.role,
                base_os_step_sequence=candidate.base_os_step_sequence,
                base_os_evidence_digest=candidate.base_os_evidence_digest,
                base_os_result_digest=candidate.base_os_result_digest,
                route_relationship_count=(len(assigned_jump_ids) + len(dependent_ids)),
                route_relationship_digest=route_relationship_digest,
                trust_identity_digest=_digest_object(
                    {
                        "inventory_digest": (
                            planning.base.deploy.inventory.record.inventory_digest
                        ),
                        "stable_id": candidate.stable_id,
                        "trust_entries_digest": planning.base.trust.record.entries_digest,
                    }
                ),
                connectivity_evidence_digest=connectivity.evidence_digest,
                reconnect_required=True,
                identity_trust_revalidation_required=True,
                machine_evidence_required=True,
                reboot_clear_verification_required=True,
                checkpoint_policy=_CHECKPOINT_POLICY,
            )
        )
    if len(targets) != len(ordered):
        blockers.add("reboot-order-unresolved")
    return tuple(targets), tuple(sorted(blockers))


def _build_plan(
    context: _BaseOsReconciliationContext,
    reconciliation: StoredDeployBaseOsReconciliation,
    *,
    targets: tuple[DeployRebootPlanTarget, ...],
    blockers: tuple[str, ...],
    created_at: str,
) -> DeployRebootPlan:
    host = context.host
    loaded = host.loaded
    planning = loaded.planning
    deploy = planning.base.deploy
    journal = deploy.journal
    inventory = deploy.inventory
    trust = planning.base.trust
    stable_ids = tuple(target.stable_id for target in targets)
    role_order = tuple(dict.fromkeys(target.role for target in targets))
    batches = [
        {
            "count": sum(target.role is role for target in targets),
            "role": role.value,
            "target_digest": _digest_object(
                [target.stable_id for target in targets if target.role is role]
            ),
        }
        for role in role_order
    ]
    blocker_set = tuple(sorted(set(blockers)))
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": str(deploy.metadata.record.cluster_uuid),
        "cluster_name": deploy.metadata.record.cluster_name,
        "operation_id": str(journal.record.operation_id),
        "operation": _OPERATION,
        "request_digest": journal.record.request_digest,
        "journal_generation": journal.record.generation,
        "journal_digest": journal.digest,
        "journal_status": journal.record.status.value,
        "journal_phase": journal.record.phase.value,
        "context_artifact_digest": loaded.context.artifact_digest,
        "original_plan_artifact_digest": loaded.plan.artifact_digest,
        "effective_plan_artifact_digest": host.prior_effective.artifact_digest,
        "pre_mutation_execution_artifact_digest": host.execution.artifact_digest,
        "pre_mutation_evidence_artifact_digest": host.evidence.artifact_digest,
        "pre_mutation_evidence_digest": host.pre_mutation_evidence_digest,
        "host_reconciliation_artifact_digest": context.prior.artifact_digest,
        "base_os_reconciliation_artifact_digest": reconciliation.artifact_digest,
        "base_os_reconciliation_record_digest": reconciliation.record.record_digest,
        "base_os_reconciled_plan_digest": reconciliation.record.effective_plan_digest,
        "base_os_authorization_artifact_digest": (
            context.authorization.artifact_digest
        ),
        "base_os_execution_artifact_digest": context.execution.artifact_digest,
        "base_os_evidence_artifact_digest": context.evidence.artifact_digest,
        "base_os_evidence_digest": context.base_os_evidence_digest,
        "inventory_generation": inventory.record.generation,
        "inventory_artifact_digest": inventory.digest,
        "inventory_digest": inventory.record.inventory_digest,
        "trust_generation": trust.record.generation,
        "trust_artifact_digest": trust.digest,
        "trust_entries_digest": trust.record.entries_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": planning.readiness.record.record_digest,
        "connectivity_execution_artifact_digest": loaded.execution.artifact_digest,
        "connectivity_evidence_artifact_digest": loaded.evidence.artifact_digest,
        "connectivity_evidence_digest": loaded.evidence.record.entries[
            1
        ].evidence_digest,
        "route_digest": loaded.evidence.record.route_digest,
        "catalog_digest": loaded.catalog_digest,
        "ansible_source_version": loaded.source.version,
        "ansible_source_digest": loaded.source.digest,
        "classification": OperationClassification.MUTATING.value,
        "ordering_policy": _ORDERING_POLICY,
        "serial": _SERIAL,
        "targets": [target.to_object() for target in targets],
        "target_count": len(targets),
        "target_set_digest": _digest_object(sorted(stable_ids)),
        "target_order_digest": _digest_object(list(stable_ids)),
        "role_order": [role.value for role in role_order],
        "role_order_digest": _digest_object([role.value for role in role_order]),
        "role_batch_digest": _digest_object(batches),
        "reconnect_checkpoint_required": True,
        "identity_trust_revalidation_required": True,
        "machine_evidence_required": True,
        "reboot_clear_verification_required": True,
        "blocker_set": list(blocker_set),
        "blocker_digest": _digest_object(list(blocker_set)),
        "planning_state": _BLOCKED if blocker_set else _READY,
        "authorization_state": _NOT_COLLECTED,
        "authorization_consumed": False,
        "execution_state": _UNAVAILABLE,
        "reconnect_state": _NOT_PERFORMED,
        "record_digest": "",
        "journal_schema_version": JOURNAL_SCHEMA_VERSION,
        "base_os_reconciliation_schema_version": (
            ANSIBLE_DEPLOY_BASE_OS_RECONCILIATION_SCHEMA_VERSION
        ),
        "schema_version": ANSIBLE_DEPLOY_REBOOT_PLAN_SCHEMA_VERSION,
    }
    values["record_digest"] = _record_digest(values)
    return DeployRebootPlan.from_object(values)


def _normalize_proof(
    proof: DeployRebootAuthorizationProof | None,
    plan: StoredDeployRebootPlan,
) -> DeployRebootProofDecision:
    if proof is None or proof.approval_method is None:
        raise StateConflictError("ordinary deploy reboot approval is required")
    if not proof.approved:
        raise StateConflictError("ordinary deploy reboot approval was denied")
    if proof.allow_destructive or proof.destructive_scope_provided:
        raise StateConflictError(
            "destructive proof is inapplicable to mutating reboot authorization"
        )
    values: dict[str, object] = {
        "allow_destructive": False,
        "approval_method": proof.approval_method.value,
        "approved": True,
        "destructive_scope_provided": False,
        "proof_digest": "",
        "schema_version": ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION,
    }
    values["proof_digest"] = _proof_digest_values(plan, values)
    return DeployRebootProofDecision.from_object(values)


def _build_authorization(
    plan: StoredDeployRebootPlan,
    *,
    proof: DeployRebootProofDecision,
    created_at: str,
) -> DeployRebootAuthorization:
    record = plan.record
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
        "reboot_plan_artifact_digest": plan.artifact_digest,
        "reboot_plan_record_digest": record.record_digest,
        "base_os_reconciliation_artifact_digest": (
            record.base_os_reconciliation_artifact_digest
        ),
        "inventory_digest": record.inventory_digest,
        "trust_entries_digest": record.trust_entries_digest,
        "readiness_record_digest": record.readiness_record_digest,
        "connectivity_evidence_digest": record.connectivity_evidence_digest,
        "catalog_digest": record.catalog_digest,
        "ansible_source_digest": record.ansible_source_digest,
        "blocker_digest": record.blocker_digest,
        "classification": record.classification.value,
        "target_count": record.target_count,
        "target_set_digest": record.target_set_digest,
        "target_order_digest": record.target_order_digest,
        "role_order_digest": record.role_order_digest,
        "role_batch_digest": record.role_batch_digest,
        "serial": record.serial,
        "checkpoint_policy": _CHECKPOINT_POLICY,
        "proof": proof.to_object(),
        "authorization_state": _AUTHORIZED,
        "consumed": False,
        "execution_state": _UNAVAILABLE,
        "reconnect_state": _NOT_PERFORMED,
        "authorization_digest": "",
        "reboot_plan_schema_version": record.schema_version,
        "journal_schema_version": record.journal_schema_version,
        "schema_version": ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_SCHEMA_VERSION,
    }
    values["authorization_digest"] = _record_digest(values)
    return DeployRebootAuthorization.from_object(values)


def _not_required_report(
    operation_id: uuid.UUID,
    reconciliation: StoredDeployBaseOsReconciliation,
) -> DeployRebootPlanningAuthorizationReport:
    record = reconciliation.record
    return DeployRebootPlanningAuthorizationReport(
        operation_id=operation_id,
        plan_state=DeployRebootArtifactState.NOT_REQUIRED,
        authorization_artifact_state=DeployRebootArtifactState.NOT_REQUIRED,
        plan_artifact_digest=None,
        plan_record_digest=None,
        authorization_artifact_digest=None,
        authorization_digest=None,
        proof_digest=None,
        target_count=0,
        target_set_digest=None,
        target_order_digest=None,
        role_counts=(),
        role_order_digest=None,
        role_batch_digest=None,
        serial=_SERIAL,
        ordering_policy=_ORDERING_POLICY,
        classification=None,
        approval_method=None,
        authorization_state=_NOT_REQUIRED,
        authorization_consumed=False,
        execution_state=_UNAVAILABLE,
        reconnect_state=_NOT_PERFORMED,
        reconnect_checkpoint_required=False,
        identity_trust_revalidation_required=False,
        machine_evidence_required=False,
        reboot_clear_verification_required=False,
        blocker_set=(),
        blocker_digest=_digest_object([]),
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
    )


def _report(
    plan: StoredDeployRebootPlan,
    *,
    plan_state: DeployRebootArtifactState,
    authorization: StoredDeployRebootAuthorization | None,
    authorization_state: DeployRebootArtifactState,
) -> DeployRebootPlanningAuthorizationReport:
    record = plan.record
    counts = Counter(target.role.value for target in record.targets)
    return DeployRebootPlanningAuthorizationReport(
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
        role_counts=tuple(sorted(counts.items())),
        role_order_digest=record.role_order_digest,
        role_batch_digest=record.role_batch_digest,
        serial=record.serial,
        ordering_policy=record.ordering_policy,
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
        reconnect_checkpoint_required=record.reconnect_checkpoint_required,
        identity_trust_revalidation_required=(
            record.identity_trust_revalidation_required
        ),
        machine_evidence_required=record.machine_evidence_required,
        reboot_clear_verification_required=(record.reboot_clear_verification_required),
        blocker_set=record.blocker_set,
        blocker_digest=record.blocker_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
    )


def _proof_digest(
    record: DeployRebootAuthorization,
    proof: Mapping[str, object],
) -> str:
    proof_value = dict(proof)
    proof_value["proof_digest"] = ""
    return _digest_object(
        {
            "cluster_uuid": str(record.cluster_uuid),
            "journal_digest": record.journal_digest,
            "operation_id": str(record.operation_id),
            "plan_artifact_digest": record.reboot_plan_artifact_digest,
            "plan_record_digest": record.reboot_plan_record_digest,
            "proof": proof_value,
            "schema_version": (
                ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION
            ),
            "target_order_digest": record.target_order_digest,
        }
    )


def _proof_digest_values(
    plan: StoredDeployRebootPlan,
    proof: Mapping[str, object],
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
                ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION
            ),
            "target_order_digest": plan.record.target_order_digest,
        }
    )


def _plan_digests(record: DeployRebootPlan) -> tuple[str, ...]:
    return (
        record.request_digest,
        record.journal_digest,
        record.context_artifact_digest,
        record.original_plan_artifact_digest,
        record.effective_plan_artifact_digest,
        record.pre_mutation_execution_artifact_digest,
        record.pre_mutation_evidence_artifact_digest,
        record.pre_mutation_evidence_digest,
        record.host_reconciliation_artifact_digest,
        record.base_os_reconciliation_artifact_digest,
        record.base_os_reconciliation_record_digest,
        record.base_os_reconciled_plan_digest,
        record.base_os_authorization_artifact_digest,
        record.base_os_execution_artifact_digest,
        record.base_os_evidence_artifact_digest,
        record.base_os_evidence_digest,
        record.inventory_artifact_digest,
        record.inventory_digest,
        record.trust_artifact_digest,
        record.trust_entries_digest,
        record.readiness_artifact_digest,
        record.readiness_record_digest,
        record.connectivity_execution_artifact_digest,
        record.connectivity_evidence_artifact_digest,
        record.connectivity_evidence_digest,
        record.route_digest,
        record.catalog_digest,
        record.ansible_source_digest,
        record.target_set_digest,
        record.target_order_digest,
        record.role_order_digest,
        record.role_batch_digest,
        record.blocker_digest,
        record.record_digest,
    )


def _authorization_digests(record: DeployRebootAuthorization) -> tuple[str, ...]:
    return (
        record.request_digest,
        record.journal_digest,
        record.reboot_plan_artifact_digest,
        record.reboot_plan_record_digest,
        record.base_os_reconciliation_artifact_digest,
        record.inventory_digest,
        record.trust_entries_digest,
        record.readiness_record_digest,
        record.connectivity_evidence_digest,
        record.catalog_digest,
        record.ansible_source_digest,
        record.blocker_digest,
        record.target_set_digest,
        record.target_order_digest,
        record.role_order_digest,
        record.role_batch_digest,
        record.authorization_digest,
    )


def _record_digest(value: Mapping[str, object]) -> str:
    copied = dict(value)
    field = "record_digest" if "record_digest" in copied else "authorization_digest"
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
            "cannot safely list deploy reboot artifacts"
        ) from error
    canonical = str(operation_id)
    for suffix in (
        DEPLOY_REBOOT_PLAN_FILENAME_SUFFIX,
        DEPLOY_REBOOT_AUTHORIZATION_FILENAME_SUFFIX,
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
                raise StateConflictError("deploy reboot artifacts are ambiguous")


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError("deploy reboot paths are not canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError("deploy reboot planning requires an acquired cluster lock")
    lock.assert_held_for_operation(paths, _OPERATION)


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
        raise StatePersistenceError(f"deploy reboot {label} is invalid") from error


__all__ = [
    "ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_PROOF_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_REBOOT_AUTHORIZATION_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_REBOOT_PLAN_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_REBOOT_REPORT_SCHEMA_VERSION",
    "DEPLOY_REBOOT_AUTHORIZATION_FILENAME_SUFFIX",
    "DEPLOY_REBOOT_PLAN_FILENAME_SUFFIX",
    "DeployRebootApprovalMethod",
    "DeployRebootArtifactState",
    "DeployRebootAuthorization",
    "DeployRebootAuthorizationProof",
    "DeployRebootAuthorizationStore",
    "DeployRebootPlan",
    "DeployRebootPlanStore",
    "DeployRebootPlanTarget",
    "DeployRebootPlanningAuthorizationReport",
    "DeployRebootProofDecision",
    "StoredDeployRebootAuthorization",
    "StoredDeployRebootPlan",
    "deploy_reboot_authorization_id_from_filename",
    "deploy_reboot_authorization_path",
    "deploy_reboot_plan_id_from_filename",
    "deploy_reboot_plan_path",
    "plan_and_authorize_deploy_reboots",
]
