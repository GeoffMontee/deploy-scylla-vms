"""Immutable deploy-plan reconciliation after jump-host configuration.

This internal owner accepts only canonical operation identity and the matching
already-held deploy lock.  It proves the exact authorized jump-host scope
completed with strict semantic evidence, then advances at most the immediate
next documented deploy gate without authorizing or executing it.
"""

from __future__ import annotations

import os
import re
import uuid
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.base_os import (
    BaseOsEvidence,
    BaseOsHostEvidence,
    BaseOsStatus,
)
from scylla_vms.ansible.commands import (
    ansible_command_intent_digest,
    validate_playbook_request_policy,
)
from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStep,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_jump_host_authorization import (
    ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION,
    DeployJumpHostConfigureAuthorizationScope,
    DeployJumpHostConfigureAuthorizationStore,
    StoredDeployJumpHostConfigureAuthorization,
    _build_authorization,
    _derive_authorization_scopes,
)
from scylla_vms.ansible.deploy_jump_host_execution import (
    ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_SCHEMA_VERSION,
    DeployJumpHostConfigureEvidenceEntry,
    DeployJumpHostConfigureEvidenceStore,
    DeployJumpHostConfigureExecutionState,
    DeployJumpHostConfigureExecutionStore,
    DeployJumpHostConfigureRestorationStatus,
    StoredDeployJumpHostConfigureEvidence,
    StoredDeployJumpHostConfigureExecution,
    _policy_digest,
)
from scylla_vms.ansible.deploy_plan import (
    DeployConditionState,
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_reboot_reconciliation import (
    ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION,
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
from scylla_vms.ansible.jump_host_configure import (
    JumpHostConfigurationAuthorization,
    authorize_jump_host_configuration,
    build_jump_host_configure_payload,
)
from scylla_vms.ansible.operation_binding import readiness_binding_digest
from scylla_vms.ansible.registry import OPERATION_PLAYBOOKS, get_playbook
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION
from scylla_vms.ansible.trust import TrustStore
from scylla_vms.desired import HostRole
from scylla_vms.errors import (
    AnsibleError,
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
    _reconstructed_readiness,
)

ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-jump-host-configure-reconciliation/v1"
)
ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-jump-host-configure-reconciliation-report/v1"
)
DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-post-jump-host-configure-reconciliation.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "jump-host-configure"
_JUMP_MAPPING = 4
_FINAL_EVIDENCE_MAPPING = len(OPERATION_PLAYBOOKS[_OPERATION])
_NOT_STARTED = "not-started"
_NOT_PERFORMED = "not-performed"
_UNAVAILABLE = "unavailable"
_SUCCEEDED = "succeeded"
_EVIDENCE_BOUND = "jump-host-configure-evidence-bound"
_AUTHORIZATION_CONSUMED = "consumed-by-execution"
_ORDER_BLOCKER = "ordered-deploy-step-not-reached"
_AUTHORIZATION_BLOCKER = "deploy-authorization-not-collected"
_PUBLIC_WORKFLOW_BLOCKER = "public-deploy-workflow-unavailable"
_CLASS_BLOCKERS = {
    OperationClassification.MUTATING: "mutating-deploy-execution-unavailable",
    OperationClassification.SENSITIVE: "sensitive-deploy-execution-unavailable",
    OperationClassification.DESTRUCTIVE: "destructive-deploy-execution-unavailable",
}
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")


class DeployPostJumpHostConfigureArtifactState(StrEnum):
    """Immutable companion persistence state."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployPostJumpHostConfigureReconciliation:
    """Immutable effective deploy view after exact jump-host configuration."""

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
    post_reboot_reconciliation_artifact_digest: str
    post_reboot_reconciliation_record_digest: str
    post_reboot_effective_plan_digest: str
    jump_authorization_artifact_digest: str
    jump_authorization_digest: str
    jump_authorization_scope_digest: str
    jump_execution_artifact_digest: str
    jump_execution_binding_digest: str
    jump_evidence_artifact_digest: str
    jump_evidence_digest: str
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    route_digest: str
    trust_generation: int
    trust_artifact_digest: str
    trust_entries_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    connectivity_execution_artifact_digest: str
    connectivity_evidence_artifact_digest: str
    connectivity_evidence_digest: str
    catalog_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    jump_target_count: int
    jump_target_set_digest: str
    jump_succeeded_count: int
    changed_count: int
    no_change_count: int
    validated_count: int
    reload_count: int
    restoration_not_required_count: int
    jump_status: str
    jump_evidence_state: str
    authorization_state: str
    execution_state: str
    steps: tuple[DeployBaseOsReconciledStep, ...]
    mapping_count: int
    step_count: int
    succeeded_count: int
    authorization_required_count: int
    eligible_count: int
    blocked_count: int
    not_performed_count: int
    blocker_set: tuple[str, ...]
    blocker_digest: str
    effective_plan_digest: str
    next_execution_state: str
    final_evidence_state: str
    finalization_state: str
    public_workflow_state: str
    record_digest: str
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    post_reboot_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION
    )
    jump_authorization_schema_version: str = (
        ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
    )
    jump_execution_schema_version: str = (
        ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_SCHEMA_VERSION
    )
    jump_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.post_reboot_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_REBOOT_RECONCILIATION_SCHEMA_VERSION
            or self.jump_authorization_schema_version
            != ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
            or self.jump_execution_schema_version
            != ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EXECUTION_SCHEMA_VERSION
            or self.jump_evidence_schema_version
            != ANSIBLE_DEPLOY_JUMP_HOST_CONFIGURE_EVIDENCE_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.jump_status != _SUCCEEDED
            or self.jump_evidence_state != _EVIDENCE_BOUND
            or self.authorization_state != _AUTHORIZATION_CONSUMED
            or self.execution_state
            != DeployJumpHostConfigureExecutionState.SUCCEEDED.value
            or self.next_execution_state != _NOT_STARTED
            or self.final_evidence_state != _NOT_PERFORMED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
        ):
            raise StatePersistenceError(
                "post-jump-host reconciliation identity or state is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for value in (
            self.journal_generation,
            self.inventory_generation,
            self.trust_generation,
            self.jump_target_count,
            self.jump_succeeded_count,
            self.changed_count,
            self.no_change_count,
            self.validated_count,
            self.reload_count,
            self.restoration_not_required_count,
            self.mapping_count,
            self.step_count,
            self.succeeded_count,
            self.authorization_required_count,
            self.eligible_count,
            self.blocked_count,
            self.not_performed_count,
        ):
            _nonnegative_integer(value, "post-jump-host reconciliation count")
        if (
            self.journal_generation < 1
            or self.inventory_generation < 1
            or self.trust_generation < 1
            or self.jump_target_count < 1
            or self.jump_succeeded_count != self.jump_target_count
            or self.changed_count + self.no_change_count != self.jump_target_count
            or self.validated_count != self.jump_target_count
            or self.reload_count != self.changed_count
            or self.restoration_not_required_count != self.jump_target_count
            or self.mapping_count != len(OPERATION_PLAYBOOKS[_OPERATION])
            or self.step_count != len(self.steps)
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, len(self.steps) + 1))
        ):
            raise StatePersistenceError("post-jump-host reconciliation counts conflict")
        expected_mapping = OPERATION_PLAYBOOKS[_OPERATION]
        if {step.mapping_sequence for step in self.steps} != set(
            range(1, len(expected_mapping) + 1)
        ) or any(
            step.playbook != expected_mapping[step.mapping_sequence - 1].playbook
            or step.condition != expected_mapping[step.mapping_sequence - 1].condition
            for step in self.steps
        ):
            raise StatePersistenceError("post-jump-host deploy mapping conflicts")
        counts = Counter(step.status for step in self.steps)
        blockers = tuple(
            sorted({blocker for step in self.steps for blocker in step.blockers})
        )
        if (
            self.succeeded_count != counts[DeployBaseOsReconciledStepStatus.SUCCEEDED]
            or self.authorization_required_count
            != counts[
                DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            ]
            or self.eligible_count != counts[DeployBaseOsReconciledStepStatus.ELIGIBLE]
            or self.blocked_count != counts[DeployBaseOsReconciledStepStatus.BLOCKED]
            or self.not_performed_count
            != counts[DeployBaseOsReconciledStepStatus.NOT_PERFORMED]
            or sum(counts.values()) != self.step_count
            or self.blocker_set != blockers
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blocker_set)
            or self.blocker_digest != _digest_object(list(self.blocker_set))
            or self.effective_plan_digest
            != _digest_object([step.to_object() for step in self.steps])
        ):
            raise StatePersistenceError(
                "post-jump-host reconciliation summary conflicts"
            )
        for digest_value in _record_digests(self):
            validate_digest(digest_value, "post-jump-host reconciliation digest")
        if self.record_digest != _record_digest(self):
            raise StatePersistenceError(
                "post-jump-host reconciliation record digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            result[name] = (
                str(value)
                if isinstance(value, uuid.UUID)
                else value.value
                if isinstance(value, (JournalStatus, OperationPhase))
                else [step.to_object() for step in value]
                if name == "steps"
                else list(value)
                if name == "blocker_set"
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployPostJumpHostConfigureReconciliation:
        require_exact_keys(
            value, set(cls.__dataclass_fields__), "post-jump-host reconciliation"
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "inventory_generation",
            "trust_generation",
            "jump_target_count",
            "jump_succeeded_count",
            "changed_count",
            "no_change_count",
            "validated_count",
            "reload_count",
            "restoration_not_required_count",
            "mapping_count",
            "step_count",
            "succeeded_count",
            "authorization_required_count",
            "eligible_count",
            "blocked_count",
            "not_performed_count",
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
            elif name == "steps":
                parsed[name] = tuple(
                    DeployBaseOsReconciledStep.from_object(
                        _mapping(step, "post-jump-host reconciled step")
                    )
                    for step in _array(item, "post-jump-host reconciled steps")
                )
            elif name == "blocker_set":
                parsed[name] = _string_tuple(item, name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployPostJumpHostConfigureReconciliation:
    record: DeployPostJumpHostConfigureReconciliation
    artifact_digest: str


class DeployPostJumpHostConfigureReconciliationStore:
    """Owner-only immutable post-jump-host effective-plan companion."""

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
        self._path = deploy_post_jump_host_configure_reconciliation_path(
            paths, operation_id
        )
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployPostJumpHostConfigureReconciliation:
        value, artifact_digest = self._file.read()
        record = DeployPostJumpHostConfigureReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "post-jump-host reconciliation identity conflicts"
            )
        return StoredDeployPostJumpHostConfigureReconciliation(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPostJumpHostConfigureReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployPostJumpHostConfigureReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployPostJumpHostConfigureReconciliation,
        DeployPostJumpHostConfigureArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "post-jump-host reconciliation operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "post-jump-host reconciliation is immutable; use a new operation"
                )
            return current, DeployPostJumpHostConfigureArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployPostJumpHostConfigureReconciliation(record, artifact_digest),
            DeployPostJumpHostConfigureArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployPostJumpHostConfigureNextStepSummary:
    """Redacted grouping for one immediate next-step class."""

    playbook: str
    target_role: str
    classification: OperationClassification
    status: DeployBaseOsReconciledStepStatus
    instance_count: int
    instance_digest: str
    target_count: int
    target_set_digest: str

    def __post_init__(self) -> None:
        if (
            get_playbook(self.playbook).classification is not self.classification
            or self.status
            not in {
                DeployBaseOsReconciledStepStatus.ELIGIBLE,
                DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
            }
            or self.instance_count < 1
            or self.target_count < 1
        ):
            raise StatePersistenceError("post-jump-host next-step summary is invalid")
        validate_digest(self.instance_digest, "next-step instance digest")
        validate_digest(self.target_set_digest, "next-step target-set digest")

    def to_object(self) -> dict[str, object]:
        return {
            "classification": self.classification.value,
            "instance_count": self.instance_count,
            "instance_digest": self.instance_digest,
            "playbook": self.playbook,
            "status": self.status.value,
            "target_count": self.target_count,
            "target_role": self.target_role,
            "target_set_digest": self.target_set_digest,
        }


@dataclass(frozen=True, slots=True)
class DeployPostJumpHostConfigureReconciliationReport:
    """Strict address-free post-jump-host reconciliation projection."""

    operation_id: uuid.UUID
    artifact_state: DeployPostJumpHostConfigureArtifactState
    reconciliation_artifact_digest: str
    reconciliation_record_digest: str
    effective_plan_digest: str
    jump_target_count: int
    jump_target_set_digest: str
    changed_count: int
    no_change_count: int
    validated_count: int
    reload_count: int
    succeeded_count: int
    authorization_required_count: int
    eligible_count: int
    blocked_count: int
    not_performed_count: int
    next_steps: tuple[DeployPostJumpHostConfigureNextStepSummary, ...]
    next_step_count: int
    next_target_count: int
    next_target_set_digest: str
    blocker_set: tuple[str, ...]
    blocker_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    finalization_state: str
    public_workflow_state: str
    reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_REPORT_SCHEMA_VERSION
            or self.reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_SCHEMA_VERSION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
            or not isinstance(self.operation_id, uuid.UUID)
        ):
            raise StatePersistenceError(
                "post-jump-host reconciliation report identity is invalid"
            )
        for value in (
            self.jump_target_count,
            self.changed_count,
            self.no_change_count,
            self.validated_count,
            self.reload_count,
            self.succeeded_count,
            self.authorization_required_count,
            self.eligible_count,
            self.blocked_count,
            self.not_performed_count,
            self.next_step_count,
            self.next_target_count,
        ):
            _nonnegative_integer(value, "post-jump-host report count")
        if (
            self.jump_target_count < 1
            or self.changed_count + self.no_change_count != self.jump_target_count
            or self.validated_count != self.jump_target_count
            or self.reload_count != self.changed_count
            or self.next_step_count
            != sum(item.instance_count for item in self.next_steps)
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blocker_set)
            or self.blocker_digest != _digest_object(list(self.blocker_set))
        ):
            raise StatePersistenceError(
                "post-jump-host reconciliation report summary conflicts"
            )
        for digest_value in (
            self.reconciliation_artifact_digest,
            self.reconciliation_record_digest,
            self.effective_plan_digest,
            self.jump_target_set_digest,
            self.next_target_set_digest,
            self.blocker_digest,
        ):
            validate_digest(digest_value, "post-jump-host report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "artifact_state": self.artifact_state.value,
            "blockers": {
                "digest": self.blocker_digest,
                "values": list(self.blocker_set),
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "jump_host_configure": {
                "changed_count": self.changed_count,
                "no_change_count": self.no_change_count,
                "reload_count": self.reload_count,
                "target_count": self.jump_target_count,
                "target_set_digest": self.jump_target_set_digest,
                "validated_count": self.validated_count,
            },
            "next": {
                "step_count": self.next_step_count,
                "steps": [item.to_object() for item in self.next_steps],
                "target_count": self.next_target_count,
                "target_set_digest": self.next_target_set_digest,
            },
            "operation_id": str(self.operation_id),
            "provenance": {
                "effective_plan_digest": self.effective_plan_digest,
                "reconciliation_artifact_digest": self.reconciliation_artifact_digest,
                "reconciliation_record_digest": self.reconciliation_record_digest,
            },
            "schema_version": self.schema_version,
            "schemas": {"reconciliation": self.reconciliation_schema_version},
            "states": {
                "finalization": self.finalization_state,
                "public_workflow": self.public_workflow_state,
            },
            "steps": {
                "authorization_required_count": self.authorization_required_count,
                "blocked_count": self.blocked_count,
                "eligible_count": self.eligible_count,
                "not_performed_count": self.not_performed_count,
                "succeeded_count": self.succeeded_count,
            },
        }


@dataclass(frozen=True, slots=True)
class _CurrentScope:
    authorization: DeployJumpHostConfigureAuthorizationScope
    stable_id: str
    configuration_authorization: JumpHostConfigurationAuthorization
    variables_digest: str
    command_digest: str
    source_digest: str
    policy_digest: str
    route_digest: str
    config_digest: str


@dataclass(frozen=True, slots=True)
class _PostJumpHostContext:
    post: _PostRebootContext
    post_reconciliation: StoredDeployPostRebootReconciliation
    authorization: StoredDeployJumpHostConfigureAuthorization
    execution: StoredDeployJumpHostConfigureExecution
    evidence: StoredDeployJumpHostConfigureEvidence
    scopes: tuple[_CurrentScope, ...]
    entries: tuple[DeployJumpHostConfigureEvidenceEntry, ...]
    evidence_digest: str


def reconcile_deploy_jump_host_configure_result(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployPostJumpHostConfigureReconciliationReport:
    """Persist the exact immutable effective plan after jump-host configuration."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_artifacts(paths, operation_id)
    context = _load_context(paths, operation_id, lock=lock)
    metadata = context.post.base.host.loaded.planning.base.deploy.metadata.record
    store = DeployPostJumpHostConfigureReconciliationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    existing = (
        store.read_locked(
            lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
        )
        if store.path.exists()
        else None
    )
    created_at = (
        existing.record.created_at
        if existing is not None
        else format_timestamp(datetime.now(UTC))
    )
    steps = _build_steps(context)
    record = _build_record(context, steps=steps, created_at=created_at)
    if existing is not None and existing.record != record:
        raise StateConflictError(
            "post-jump-host reconciliation is immutable; use a new operation"
        )
    try:
        stored, state = store.write_locked(record, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "post-jump-host reconciliation persistence failed"
        ) from error
    return _build_report(stored, state=state)


def deploy_post_jump_host_configure_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the sole canonical post-jump-host reconciliation path."""

    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}"
        f"{DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "post-jump-host reconciliation path is not canonical"
        )
    return path


def deploy_post_jump_host_configure_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(
        DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_FILENAME_SUFFIX
    ):
        return None
    value = name[: -len(DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_FILENAME_SUFFIX)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _load_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
) -> _PostJumpHostContext:
    post = _load_post_reboot_context(paths, operation_id, lock=lock)
    planning = post.base.host.loaded.planning
    loaded = post.base.host.loaded
    deploy = planning.base.deploy
    metadata = deploy.metadata.record
    journal = deploy.journal
    readiness_record = planning.readiness.record
    if (
        journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.VERIFY
    ):
        raise StateConflictError(
            "post-jump-host reconciliation requires the unchanged VERIFY journal"
        )
    readiness = _reconstructed_readiness(planning.base)
    if (
        readiness_binding_digest(readiness) != readiness_record.readiness_digest
        or readiness_record.playbook_version != readiness_record.inventory_version
        or readiness_record.remote_playbook_status != _NOT_PERFORMED
    ):
        raise StateConflictError(
            "post-jump-host inventory, trust, or readiness evidence is stale"
        )
    readiness.require_ready(OperationClassification.MUTATING)
    TrustStore(paths).validate_runtime(planning.base.trust, deploy.inventory)

    post_store = DeployPostRebootReconciliationStore(paths, operation_id)
    authorization_store = DeployJumpHostConfigureAuthorizationStore(paths, operation_id)
    execution_store = DeployJumpHostConfigureExecutionStore(paths, operation_id)
    evidence_store = DeployJumpHostConfigureEvidenceStore(paths, operation_id)
    for path, label in (
        (post_store.path, "post-reboot reconciliation"),
        (authorization_store.path, "jump-host authorization"),
        (execution_store.path, "jump-host execution"),
        (evidence_store.path, "jump-host evidence"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"post-jump-host reconciliation requires complete {label}"
            )
    post_reconciliation = post_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_post = _build_post_reboot_record(
        post,
        steps=_build_post_reboot_steps(post),
        created_at=post_reconciliation.record.created_at,
    )
    if post_reconciliation.record != expected_post:
        raise StateConflictError("post-jump-host prior reconciliation drifted")
    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    authorization_scopes = _derive_authorization_scopes(post, post_reconciliation)
    expected_authorization = _build_authorization(
        post,
        post_reconciliation,
        scopes=authorization_scopes,
        proof=authorization.record.proof,
        created_at=authorization.record.created_at,
    )
    if (
        authorization.record != expected_authorization
        or authorization.record.consumed
        or authorization.record.authorization_state != "authorized-pre-execution"
    ):
        raise StateConflictError(
            "post-jump-host authorization changed, consumed, or drifted"
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
    scopes = _derive_current_scopes(post, authorization)
    entries = _validate_complete_execution(
        post,
        post_reconciliation,
        authorization,
        execution,
        evidence,
        scopes,
    )
    if (
        execution.record.binding.catalog_digest != loaded.catalog_digest
        or execution.record.binding.source_version != loaded.source.version
        or execution.record.binding.source_digest != loaded.source.digest
    ):
        raise StateConflictError("post-jump-host source or catalog drifted")
    return _PostJumpHostContext(
        post,
        post_reconciliation,
        authorization,
        execution,
        evidence,
        scopes,
        entries,
        _digest_object([entry.evidence_digest for entry in entries]),
    )


def _derive_current_scopes(
    post: _PostRebootContext,
    authorization: StoredDeployJumpHostConfigureAuthorization,
) -> tuple[_CurrentScope, ...]:
    planning = post.base.host.loaded.planning
    loaded = post.base.host.loaded
    deploy = planning.base.deploy
    readiness = _reconstructed_readiness(planning.base)
    base_hosts = {
        host.logical_id: host
        for entry in post.base.evidence.record.entries
        for host in entry.hosts
    }
    definition = get_playbook(_PLAYBOOK)
    source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
    scopes: list[_CurrentScope] = []
    try:
        for authorized in authorization.record.scopes:
            if (
                authorized.mapping_sequence != _JUMP_MAPPING
                or authorized.playbook != _PLAYBOOK
                or authorized.classification is not OperationClassification.MUTATING
                or authorized.target_role != HostRole.JUMP_HOST.value
                or len(authorized.target_ids) != 1
                or authorized.source_digest != source_digest
            ):
                raise StateConflictError(
                    "post-jump-host authorized scope identity drifted"
                )
            stable_id = authorized.target_ids[0]
            persisted = base_hosts.get(stable_id)
            if (
                persisted is None
                or not persisted.applied
                or persisted.os_family != "Ubuntu"
                or persisted.os_version != "24.04"
                or persisted.prerequisite_policy_status != "satisfied"
                or persisted.timesync_service_status != "enabled-active"
            ):
                raise StateConflictError(
                    "post-jump-host base-OS evidence is not current"
                )
            status = (
                BaseOsStatus.CHANGED if persisted.changed else BaseOsStatus.NO_CHANGE
            )
            base_os = BaseOsEvidence(
                status,
                (
                    BaseOsHostEvidence(
                        stable_id,
                        status,
                        persisted.changed,
                        False,
                        "applied" if persisted.changed else "already-current",
                    ),
                ),
            )
            configuration_authorization = authorize_jump_host_configuration(
                deploy.metadata.record,
                deploy.observation,
                deploy.inventory,
                planning.base.trust,
                readiness,
                base_os,
                operation_id=str(authorization.record.operation_id),
                target_logical_id=stable_id,
            )
            payload = build_jump_host_configure_payload(
                deploy.metadata.record,
                deploy.observation,
                deploy.inventory,
                planning.base.trust,
                readiness,
                base_os,
                configuration_authorization,
            )
            variables: dict[str, object] = {
                "deploy_scylla_vms_jump_host_configure": payload
            }
            validate_playbook_request_policy(
                _PLAYBOOK,
                limit=(stable_id,),
                tags=(_PLAYBOOK,),
                check=False,
                diff=False,
                verbosity=0,
            )
            validated = definition.validate_variables(variables)
            variables_digest = digest_bytes(serialize_json(validated))
            command_digest = ansible_command_intent_digest(
                definition,
                step_sequence=authorized.sequence,
                limit=(stable_id,),
                variables_digest=variables_digest,
                tags=(_PLAYBOOK,),
                check=False,
                diff=False,
                verbosity=0,
            )
            scopes.append(
                _CurrentScope(
                    authorized,
                    stable_id,
                    configuration_authorization,
                    variables_digest,
                    command_digest,
                    source_digest,
                    _policy_digest(),
                    _payload_digest(payload, "allowed_route_digest"),
                    _payload_digest(payload, "config_digest"),
                )
            )
    except AnsibleError as error:
        raise StateConflictError(
            "post-jump-host command, policy, route, or configuration drifted"
        ) from error
    stable_ids = tuple(scope.stable_id for scope in scopes)
    if (
        not scopes
        or len(scopes) != authorization.record.playbook_instance_count
        or len(scopes) != authorization.record.stable_id_count
        or stable_ids != tuple(sorted(set(stable_ids)))
    ):
        raise StateConflictError("post-jump-host scope is incomplete or duplicated")
    return tuple(scopes)


def _validate_complete_execution(
    post: _PostRebootContext,
    post_reconciliation: StoredDeployPostRebootReconciliation,
    authorization: StoredDeployJumpHostConfigureAuthorization,
    execution: StoredDeployJumpHostConfigureExecution,
    evidence: StoredDeployJumpHostConfigureEvidence,
    scopes: tuple[_CurrentScope, ...],
) -> tuple[DeployJumpHostConfigureEvidenceEntry, ...]:
    planning = post.base.host.loaded.planning
    loaded = post.base.host.loaded
    deploy = planning.base.deploy
    journal = deploy.journal
    readiness = planning.readiness.record
    binding = execution.record.binding
    attempts = execution.record.attempts
    entries = evidence.record.entries
    stable_ids = tuple(scope.stable_id for scope in scopes)
    scope_values = [
        {
            "attempt_index": index,
            "authorization_command_digest": scope.authorization.command_digest,
            "authorization_scope_digest": _digest_object(
                scope.authorization.to_object()
            ),
            "authorization_variables_digest": scope.authorization.variables_digest,
            "command_digest": scope.command_digest,
            "config_digest": scope.config_digest,
            "configuration_authorization_digest": (
                scope.configuration_authorization.authorization_digest
            ),
            "policy_digest": scope.policy_digest,
            "route_digest": scope.route_digest,
            "source_digest": scope.source_digest,
            "stable_id_digest": _digest_object(scope.stable_id),
            "step_sequence": scope.authorization.sequence,
            "variables_digest": scope.variables_digest,
        }
        for index, scope in enumerate(scopes, start=1)
    ]
    expected_binding: dict[str, object] = {
        "cluster_uuid": str(deploy.metadata.record.cluster_uuid),
        "cluster_name": deploy.metadata.record.cluster_name,
        "operation_id": str(journal.record.operation_id),
        "operation": _OPERATION,
        "request_digest": journal.record.request_digest,
        "journal_generation": journal.record.generation,
        "journal_digest": journal.digest,
        "journal_status": journal.record.status,
        "journal_phase": journal.record.phase,
        "authorization_artifact_digest": authorization.artifact_digest,
        "authorization_digest": authorization.record.authorization_digest,
        "authorization_scope_digest": (authorization.record.authorization_scope_digest),
        "authorization_proof_digest": authorization.record.proof.proof_digest,
        "configuration_intent_digest": authorization.record.configuration_intent_digest,
        "post_reboot_reconciliation_artifact_digest": (
            post_reconciliation.artifact_digest
        ),
        "post_reboot_reconciliation_record_digest": (
            post_reconciliation.record.record_digest
        ),
        "post_reboot_effective_plan_digest": (
            post_reconciliation.record.effective_plan_digest
        ),
        "connectivity_evidence_digest": (
            authorization.record.connectivity_evidence_digest
        ),
        "observation_generation": deploy.observation.record.generation,
        "observation_artifact_digest": deploy.observation.digest,
        "observation_manifest_digest": deploy.observation.record.manifest_digest,
        "inventory_generation": deploy.inventory.record.generation,
        "inventory_artifact_digest": deploy.inventory.digest,
        "inventory_digest": deploy.inventory.record.inventory_digest,
        "route_digest": authorization.record.route_digest,
        "trust_generation": planning.base.trust.record.generation,
        "trust_artifact_digest": planning.base.trust.digest,
        "trust_entries_digest": planning.base.trust.record.entries_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": readiness.record_digest,
        "catalog_digest": loaded.catalog_digest,
        "source_version": loaded.source.version,
        "source_digest": loaded.source.digest,
        "playbook_source_digest": _playbook_source_digest(loaded.source, _PLAYBOOK),
        "toolchain_version": readiness.playbook_version,
        "executable_identity_digest": readiness.executable_identity_digest,
        "toolchain_evidence_digest": readiness.toolchain_evidence_digest,
        "scope_count": len(scopes),
        "target_count": len(stable_ids),
        "target_set_digest": _digest_object(sorted(stable_ids)),
        "execution_scope_digest": _digest_object(scope_values),
        "policy_digest": _policy_digest(),
    }
    binding_object = binding.to_object()
    binding_conflicts = tuple(
        name
        for name, expected_value in expected_binding.items()
        if binding_object[name] != expected_value
    )
    if (
        evidence.record.binding != binding
        or binding_conflicts
        or execution.record.state is not DeployJumpHostConfigureExecutionState.SUCCEEDED
        or not execution.record.authorization_consumed
        or not execution.record.all_targets_completed
        or execution.record.invocation_count != len(scopes)
        or execution.record.completed_target_count != len(scopes)
        or len(attempts) != len(scopes)
        or len(entries) != len(scopes)
        or execution.record.generation != len(scopes) * 3
        or evidence.record.generation != len(scopes)
    ):
        raise StateConflictError(
            "post-jump-host execution is missing, partial, uncertain, or stale"
            + (f" ({','.join(binding_conflicts)})" if binding_conflicts else "")
        )
    for index, (scope, attempt, entry) in enumerate(
        zip(scopes, attempts, entries, strict=True), start=1
    ):
        if (
            attempt.attempt_index != index
            or entry.attempt_index != index
            or attempt.step_sequence != scope.authorization.sequence
            or entry.step_sequence != scope.authorization.sequence
            or attempt.stable_id != scope.stable_id
            or entry.stable_id != scope.stable_id
            or attempt.authorization_scope_digest
            != _digest_object(scope.authorization.to_object())
            or attempt.authorization_variables_digest
            != scope.authorization.variables_digest
            or attempt.authorization_command_digest
            != scope.authorization.command_digest
            or attempt.variables_digest != scope.variables_digest
            or attempt.command_digest != scope.command_digest
            or attempt.source_digest != scope.source_digest
            or attempt.configuration_authorization_digest
            != scope.configuration_authorization.authorization_digest
            or attempt.policy_digest != scope.policy_digest
            or attempt.route_digest != scope.route_digest
            or attempt.config_digest != scope.config_digest
            or attempt.state is not DeployJumpHostConfigureExecutionState.SUCCEEDED
            or not attempt.authorization_consumed
            or not attempt.invocation_may_have_occurred
            or attempt.exit_code != 0
            or attempt.manual_recovery_required
            or attempt.automatic_retry_allowed
            or attempt.result_digest != entry.result_digest
            or attempt.evidence_digest != entry.evidence_digest
            or entry.source_digest != scope.source_digest
            or entry.configuration_authorization_digest
            != scope.configuration_authorization.authorization_digest
            or entry.policy_digest != scope.policy_digest
            or entry.route_digest != scope.route_digest
            or entry.config_digest != scope.config_digest
            or not entry.applied
            or not entry.validation_performed
            or entry.validation_passed is not True
            or entry.reload_performed != entry.changed
            or entry.reload_passed != (True if entry.changed else None)
            or entry.restored
            or entry.restoration_status
            is not DeployJumpHostConfigureRestorationStatus.NOT_REQUIRED
            or entry.blocker_status
        ):
            raise StateConflictError(
                "post-jump-host target, policy, route, config, validation, "
                "reload, restore, or result evidence conflicts"
            )
    return entries


def _build_steps(
    context: _PostJumpHostContext,
) -> tuple[DeployBaseOsReconciledStep, ...]:
    prior_steps = context.post_reconciliation.record.steps
    entries_by_sequence = {entry.step_sequence: entry for entry in context.entries}
    if len(entries_by_sequence) != len(context.entries):
        raise StateConflictError("post-jump-host evidence sequence is duplicated")
    remaining_mappings = tuple(
        sorted(
            {
                step.mapping_sequence
                for step in prior_steps
                if step.sequence not in entries_by_sequence
                and step.status is not DeployBaseOsReconciledStepStatus.SUCCEEDED
                and step.condition_state is DeployConditionState.ACTIVE
                and step.mapping_sequence > _JUMP_MAPPING
                and step.mapping_sequence != _FINAL_EVIDENCE_MAPPING
            }
        )
    )
    next_mapping = remaining_mappings[0] if remaining_mappings else None
    result: list[DeployBaseOsReconciledStep] = []
    for prior in prior_steps:
        prior_digest = _digest_object(prior.to_object())
        if prior.sequence in entries_by_sequence:
            entry = entries_by_sequence[prior.sequence]
            if (
                prior.mapping_sequence != _JUMP_MAPPING
                or prior.playbook != _PLAYBOOK
                or prior.target_ids != (entry.stable_id,)
            ):
                raise StateConflictError(
                    "post-jump-host executed step identity drifted"
                )
            result.append(
                replace(
                    prior,
                    prior_reconciled_step_digest=prior_digest,
                    status=DeployBaseOsReconciledStepStatus.SUCCEEDED,
                    evidence_state=(
                        DeployBaseOsReconciledEvidenceState.JUMP_HOST_CONFIGURE_BOUND
                    ),
                    evidence_digest=entry.evidence_digest,
                    blockers=(),
                )
            )
            continue
        if (
            prior.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
            or prior.condition_state is DeployConditionState.INACTIVE
        ):
            result.append(replace(prior, prior_reconciled_step_digest=prior_digest))
            continue
        if prior.mapping_sequence == _FINAL_EVIDENCE_MAPPING:
            result.append(
                replace(
                    prior,
                    prior_reconciled_step_digest=prior_digest,
                    status=DeployBaseOsReconciledStepStatus.NOT_PERFORMED,
                    evidence_state=DeployBaseOsReconciledEvidenceState.NOT_PERFORMED,
                    evidence_digest=None,
                    blockers=tuple(sorted({*prior.blockers, _ORDER_BLOCKER})),
                )
            )
            continue
        if prior.mapping_sequence == next_mapping and _next_gate_ready(prior, context):
            evidence_digest = _next_gate_digest(prior, context)
            if prior.classification is OperationClassification.READ_ONLY:
                status = DeployBaseOsReconciledStepStatus.ELIGIBLE
                blockers: tuple[str, ...] = ()
            else:
                status = DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
                blockers = tuple(
                    sorted(
                        {
                            _AUTHORIZATION_BLOCKER,
                            _CLASS_BLOCKERS[prior.classification],
                            _PUBLIC_WORKFLOW_BLOCKER,
                        }
                    )
                )
            result.append(
                replace(
                    prior,
                    prior_reconciled_step_digest=prior_digest,
                    status=status,
                    evidence_state=(
                        DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED
                    ),
                    evidence_digest=evidence_digest,
                    blockers=blockers,
                )
            )
            continue
        result.append(
            replace(
                prior,
                prior_reconciled_step_digest=prior_digest,
                status=(
                    DeployBaseOsReconciledStepStatus.NOT_PERFORMED
                    if prior.classification is OperationClassification.READ_ONLY
                    else DeployBaseOsReconciledStepStatus.BLOCKED
                ),
                evidence_state=DeployBaseOsReconciledEvidenceState.NOT_PERFORMED,
                evidence_digest=None,
                blockers=tuple(sorted({*prior.blockers, _ORDER_BLOCKER})),
            )
        )
    return tuple(result)


def _next_gate_ready(
    step: DeployBaseOsReconciledStep,
    context: _PostJumpHostContext,
) -> bool:
    planning = context.post.base.host.loaded.planning
    inventory_hosts = planning.base.deploy.inventory.record.inventory.hosts
    inventory_ids = {host.logical_id for host in inventory_hosts}
    if not step.target_ids or not set(step.target_ids).issubset(inventory_ids):
        return False
    if (
        step.playbook == "connectivity-check"
        and step.condition == "final-routes"
        and step.classification is OperationClassification.READ_ONLY
    ):
        return set(step.target_ids) == inventory_ids
    if (
        step.playbook == "base-os"
        and step.condition == "non-jump-managed-hosts"
        and step.classification is OperationClassification.MUTATING
    ):
        non_jump_ids = {
            host.logical_id
            for host in inventory_hosts
            if host.role is not HostRole.JUMP_HOST
        }
        evaluations = {
            item.logical_id: item for item in context.post.base.host.host_evaluations
        }
        # Jump configuration does not supersede pre-mutation evidence for other
        # hosts.  It does supersede all such evidence for the changed jump hosts.
        return set(step.target_ids).issubset(non_jump_ids) and all(
            target in evaluations and not evaluations[target].blockers
            for target in step.target_ids
        )
    return False


def _next_gate_digest(
    step: DeployBaseOsReconciledStep,
    context: _PostJumpHostContext,
) -> str:
    planning = context.post.base.host.loaded.planning
    return _digest_object(
        {
            "inventory_artifact_digest": planning.base.deploy.inventory.digest,
            "inventory_digest": planning.base.deploy.inventory.record.inventory_digest,
            "jump_evidence_digest": context.evidence_digest,
            "playbook": step.playbook,
            "readiness_record_digest": planning.readiness.record.record_digest,
            "sequence": step.sequence,
            "target_digest": step.target_digest,
            "trust_artifact_digest": planning.base.trust.digest,
            "trust_entries_digest": planning.base.trust.record.entries_digest,
        }
    )


def _build_record(
    context: _PostJumpHostContext,
    *,
    steps: tuple[DeployBaseOsReconciledStep, ...],
    created_at: str,
) -> DeployPostJumpHostConfigureReconciliation:
    post = context.post
    loaded = post.base.host.loaded
    planning = loaded.planning
    deploy = planning.base.deploy
    journal = deploy.journal
    metadata = deploy.metadata.record
    binding = context.execution.record.binding
    counts = Counter(step.status for step in steps)
    blockers = tuple(sorted({blocker for step in steps for blocker in step.blockers}))
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_name": metadata.cluster_name,
        "operation_id": journal.record.operation_id,
        "operation": _OPERATION,
        "request_digest": journal.record.request_digest,
        "journal_generation": journal.record.generation,
        "journal_digest": journal.digest,
        "journal_status": journal.record.status,
        "journal_phase": journal.record.phase,
        "post_reboot_reconciliation_artifact_digest": (
            context.post_reconciliation.artifact_digest
        ),
        "post_reboot_reconciliation_record_digest": (
            context.post_reconciliation.record.record_digest
        ),
        "post_reboot_effective_plan_digest": (
            context.post_reconciliation.record.effective_plan_digest
        ),
        "jump_authorization_artifact_digest": context.authorization.artifact_digest,
        "jump_authorization_digest": (
            context.authorization.record.authorization_digest
        ),
        "jump_authorization_scope_digest": (
            context.authorization.record.authorization_scope_digest
        ),
        "jump_execution_artifact_digest": context.execution.artifact_digest,
        "jump_execution_binding_digest": binding.binding_digest,
        "jump_evidence_artifact_digest": context.evidence.artifact_digest,
        "jump_evidence_digest": context.evidence_digest,
        "inventory_generation": deploy.inventory.record.generation,
        "inventory_artifact_digest": deploy.inventory.digest,
        "inventory_digest": deploy.inventory.record.inventory_digest,
        "route_digest": binding.route_digest,
        "trust_generation": planning.base.trust.record.generation,
        "trust_artifact_digest": planning.base.trust.digest,
        "trust_entries_digest": planning.base.trust.record.entries_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": planning.readiness.record.record_digest,
        "connectivity_execution_artifact_digest": loaded.execution.artifact_digest,
        "connectivity_evidence_artifact_digest": loaded.evidence.artifact_digest,
        "connectivity_evidence_digest": (
            context.authorization.record.connectivity_evidence_digest
        ),
        "catalog_digest": loaded.catalog_digest,
        "ansible_source_version": loaded.source.version,
        "ansible_source_digest": loaded.source.digest,
        "jump_target_count": len(context.entries),
        "jump_target_set_digest": binding.target_set_digest,
        "jump_succeeded_count": len(context.entries),
        "changed_count": sum(entry.changed for entry in context.entries),
        "no_change_count": sum(not entry.changed for entry in context.entries),
        "validated_count": sum(
            entry.validation_performed and entry.validation_passed is True
            for entry in context.entries
        ),
        "reload_count": sum(entry.reload_performed for entry in context.entries),
        "restoration_not_required_count": sum(
            entry.restoration_status
            is DeployJumpHostConfigureRestorationStatus.NOT_REQUIRED
            for entry in context.entries
        ),
        "jump_status": _SUCCEEDED,
        "jump_evidence_state": _EVIDENCE_BOUND,
        "authorization_state": _AUTHORIZATION_CONSUMED,
        "execution_state": DeployJumpHostConfigureExecutionState.SUCCEEDED.value,
        "steps": steps,
        "mapping_count": len(OPERATION_PLAYBOOKS[_OPERATION]),
        "step_count": len(steps),
        "succeeded_count": counts[DeployBaseOsReconciledStepStatus.SUCCEEDED],
        "authorization_required_count": counts[
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        ],
        "eligible_count": counts[DeployBaseOsReconciledStepStatus.ELIGIBLE],
        "blocked_count": counts[DeployBaseOsReconciledStepStatus.BLOCKED],
        "not_performed_count": counts[DeployBaseOsReconciledStepStatus.NOT_PERFORMED],
        "blocker_set": blockers,
        "blocker_digest": _digest_object(list(blockers)),
        "effective_plan_digest": _digest_object([step.to_object() for step in steps]),
        "next_execution_state": _NOT_STARTED,
        "final_evidence_state": _NOT_PERFORMED,
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(values)
    return DeployPostJumpHostConfigureReconciliation(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployPostJumpHostConfigureReconciliation,
    *,
    state: DeployPostJumpHostConfigureArtifactState,
) -> DeployPostJumpHostConfigureReconciliationReport:
    record = stored.record
    selected = tuple(
        step
        for step in record.steps
        if step.status
        in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }
    )
    summaries = _next_summaries(selected)
    target_ids = tuple(
        sorted({target for step in selected for target in step.target_ids})
    )
    return DeployPostJumpHostConfigureReconciliationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        reconciliation_artifact_digest=stored.artifact_digest,
        reconciliation_record_digest=record.record_digest,
        effective_plan_digest=record.effective_plan_digest,
        jump_target_count=record.jump_target_count,
        jump_target_set_digest=record.jump_target_set_digest,
        changed_count=record.changed_count,
        no_change_count=record.no_change_count,
        validated_count=record.validated_count,
        reload_count=record.reload_count,
        succeeded_count=record.succeeded_count,
        authorization_required_count=record.authorization_required_count,
        eligible_count=record.eligible_count,
        blocked_count=record.blocked_count,
        not_performed_count=record.not_performed_count,
        next_steps=summaries,
        next_step_count=len(selected),
        next_target_count=len(target_ids),
        next_target_set_digest=_digest_object(list(target_ids)),
        blocker_set=record.blocker_set,
        blocker_digest=record.blocker_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        finalization_state=record.finalization_state,
        public_workflow_state=record.public_workflow_state,
    )


def _next_summaries(
    steps: tuple[DeployBaseOsReconciledStep, ...],
) -> tuple[DeployPostJumpHostConfigureNextStepSummary, ...]:
    grouped: dict[
        tuple[
            str,
            str,
            OperationClassification,
            DeployBaseOsReconciledStepStatus,
        ],
        list[DeployBaseOsReconciledStep],
    ] = {}
    for step in steps:
        grouped.setdefault(
            (step.playbook, step.target_role, step.classification, step.status), []
        ).append(step)
    result: list[DeployPostJumpHostConfigureNextStepSummary] = []
    for (playbook, role, classification, status), selected in sorted(
        grouped.items(),
        key=lambda item: (
            item[0][0],
            item[0][1],
            item[0][2].value,
            item[0][3].value,
        ),
    ):
        targets = tuple(
            sorted({target for step in selected for target in step.target_ids})
        )
        result.append(
            DeployPostJumpHostConfigureNextStepSummary(
                playbook,
                role,
                classification,
                status,
                len(selected),
                _digest_object(
                    [
                        {
                            "evidence_digest": step.evidence_digest,
                            "sequence": step.sequence,
                            "target_digest": step.target_digest,
                        }
                        for step in selected
                    ]
                ),
                len(targets),
                _digest_object(list(targets)),
            )
        )
    return tuple(result)


def _payload_digest(payload: Mapping[str, object], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str):
        raise StateConflictError(f"post-jump-host {name} is unavailable")
    validate_digest(value, f"post-jump-host {name}")
    return value


def _record_digests(
    record: DeployPostJumpHostConfigureReconciliation,
) -> tuple[str, ...]:
    return (
        record.request_digest,
        record.journal_digest,
        record.post_reboot_reconciliation_artifact_digest,
        record.post_reboot_reconciliation_record_digest,
        record.post_reboot_effective_plan_digest,
        record.jump_authorization_artifact_digest,
        record.jump_authorization_digest,
        record.jump_authorization_scope_digest,
        record.jump_execution_artifact_digest,
        record.jump_execution_binding_digest,
        record.jump_evidence_artifact_digest,
        record.jump_evidence_digest,
        record.inventory_artifact_digest,
        record.inventory_digest,
        record.route_digest,
        record.trust_artifact_digest,
        record.trust_entries_digest,
        record.readiness_artifact_digest,
        record.readiness_record_digest,
        record.connectivity_execution_artifact_digest,
        record.connectivity_evidence_artifact_digest,
        record.connectivity_evidence_digest,
        record.catalog_digest,
        record.ansible_source_digest,
        record.jump_target_set_digest,
        record.blocker_digest,
        record.effective_plan_digest,
        record.record_digest,
    )


def _record_digest(record: DeployPostJumpHostConfigureReconciliation) -> str:
    value = record.to_object()
    value["record_digest"] = ""
    return _digest_object(value)


def _record_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployPostJumpHostConfigureReconciliation.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(item, (JournalStatus, OperationPhase))
            else [step.to_object() for step in item]
            if name == "steps" and isinstance(item, tuple)
            else list(item)
            if name == "blocker_set" and isinstance(item, tuple)
            else item
        )
    value["record_digest"] = ""
    return _digest_object(value)


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "post-jump-host reconciliation paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "post-jump-host reconciliation requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list post-jump-host reconciliation artifacts"
        ) from error
    canonical = str(operation_id)
    suffix = DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_FILENAME_SUFFIX
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
                "post-jump-host reconciliation artifacts are ambiguous"
            )


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _nonnegative_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StatePersistenceError(f"{label} must be nonnegative")


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
        raise StatePersistenceError(f"{label} is invalid") from error


__all__ = [
    "ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_SCHEMA_VERSION",
    "DEPLOY_POST_JUMP_HOST_CONFIGURE_RECONCILIATION_FILENAME_SUFFIX",
    "DeployPostJumpHostConfigureArtifactState",
    "DeployPostJumpHostConfigureNextStepSummary",
    "DeployPostJumpHostConfigureReconciliation",
    "DeployPostJumpHostConfigureReconciliationReport",
    "DeployPostJumpHostConfigureReconciliationStore",
    "StoredDeployPostJumpHostConfigureReconciliation",
    "deploy_post_jump_host_configure_reconciliation_id_from_filename",
    "deploy_post_jump_host_configure_reconciliation_path",
    "reconcile_deploy_jump_host_configure_result",
]
