"""Bridge a completed Scylla bootstrap back into the immutable deploy mapping.

The historical deploy plan deliberately omits ``scylla-bootstrap``.  This
subprocess-free owner validates the separate bootstrap sequence and its final
complete-set health checkpoint, then records how that evidence satisfies the
first mapped ``scylla-health`` step without rewriting any prior artifact.
"""

# The completion validators intentionally use structural access across four
# independently versioned sequence families with equivalent safety fields.
# ruff: noqa: B009

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

from scylla_vms.ansible.deploy_plan import (
    DeployConditionState,
    _digest_object,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_scylla_bootstrap_authorization import (
    DeployScyllaBootstrapAuthorizationStore,
    _load_authorization_context,
)
from scylla_vms.ansible.deploy_scylla_bootstrap_execution import (
    DeployScyllaBootstrapEvidenceStore,
    DeployScyllaBootstrapExecutionStore,
)
from scylla_vms.ansible.deploy_scylla_configure_reconciliation import (
    ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_SCHEMA_VERSION,
    DeployPostScyllaConfigureReconciliationStore,
    _load_reconciliation_context,
    _mapping_digest,
)
from scylla_vms.ansible.deploy_scylla_health_checkpoint import (
    DeployScyllaHealthCheckpointStore,
    DeployScyllaHealthEvidenceStore,
    DeployScyllaHealthExecutionStore,
)
from scylla_vms.ansible.deploy_scylla_join_authorization import (
    DeployScyllaJoinAuthorizationStore,
)
from scylla_vms.ansible.deploy_scylla_join_execution import (
    DeployScyllaJoinEvidenceStore,
    DeployScyllaJoinExecutionStore,
)
from scylla_vms.ansible.deploy_scylla_later_join_authorization import (
    DeployScyllaLaterJoinAuthorizationStore,
)
from scylla_vms.ansible.deploy_scylla_later_join_execution import (
    DeployScyllaLaterJoinEvidenceStore,
    DeployScyllaLaterJoinExecutionStore,
)
from scylla_vms.ansible.deploy_scylla_post_join_health import (
    DeployScyllaPostJoinHealthEvidenceStore,
    DeployScyllaPostJoinHealthExecutionStore,
    DeployScyllaPostJoinHealthReconciliationStore,
)
from scylla_vms.ansible.deploy_scylla_post_later_join_health import (
    DeployScyllaPostLaterJoinHealthEvidenceStore,
    DeployScyllaPostLaterJoinHealthExecutionStore,
    DeployScyllaPostLaterJoinHealthReconciliationStore,
)
from scylla_vms.ansible.deploy_scylla_post_sequence_three_join_health import (
    DeployScyllaPostSequenceThreeHealthEvidenceStore,
    DeployScyllaPostSequenceThreeHealthExecutionStore,
    DeployScyllaPostSequenceThreeHealthReconciliationStore,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_authorization import (
    DeployScyllaSequenceThreeJoinAuthorizationStore,
)
from scylla_vms.ansible.deploy_scylla_sequence_three_join_execution import (
    DeployScyllaSequenceThreeJoinEvidenceStore,
    DeployScyllaSequenceThreeJoinExecutionStore,
)
from scylla_vms.ansible.registry import get_playbook
from scylla_vms.ansible.scylla_bootstrap import ScyllaBootstrapStatus
from scylla_vms.ansible.scylla_health import HealthCheckStatus, HealthReadiness
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.journal import JOURNAL_SCHEMA_VERSION, JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.persistence import (
    AtomicJsonFile,
    format_timestamp,
    parse_timestamp,
    parse_uuid,
    require_exact_keys,
    require_string,
    validate_digest,
)
from scylla_vms.state import (
    StatePaths,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)

ANSIBLE_DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-post-bootstrap-reconciliation/v1"
)
ANSIBLE_DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-post-bootstrap-reconciliation-report/v1"
)
ANSIBLE_DEPLOY_SCYLLA_POST_BOOTSTRAP_STEP_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-post-bootstrap-step/v1"
)
DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-post-bootstrap-reconciliation.json"
)

_OPERATION = "deploy"
_STAGE = "post-bootstrap-mapping-bridge"
_ORIGINAL_MAPPING_COUNT = 21
_MAPPED_HEALTH_SEQUENCE = 13
_NEXT_MAPPING_SEQUENCE = 14
_MAPPED_HEALTH_PLAYBOOK = "scylla-health"
_NEXT_PLAYBOOK = "manager-server"
_BOUNDARY_BLOCKERS = ("bootstrap-plan-required", "bootstrap-step-unmodeled")
_MANAGER_AUTHORIZATION_BLOCKERS = (
    "deploy-authorization-not-collected",
    "mutating-deploy-execution-unavailable",
    "public-deploy-workflow-unavailable",
)
_STEP_DIGEST_EXCLUDED = {"step_digest", "schema_version"}
_RECORD_DIGEST_EXCLUDED = {"record_digest", "schema_version"}
_LATER_ARTIFACT = re.compile(
    r"^(?P<operation>[0-9a-f-]+)\.ansible-deploy-scylla-(?:later-join-sequence|"
    r"post-later-join-sequence)-(?P<sequence>[0-9]+)-"
)


class DeployPostBootstrapArtifactState(StrEnum):
    CREATED = "created"
    REUSED = "reused"


class DeployPostBootstrapStepStatus(StrEnum):
    SUCCEEDED = "succeeded"
    EVIDENCE_READY_AUTHORIZATION_REQUIRED = "evidence-ready-authorization-required"
    BLOCKED = "blocked"
    NOT_PERFORMED = "not-performed"


@dataclass(frozen=True, slots=True)
class DeployPostBootstrapStep:
    mapping_sequence: int
    playbook: str
    condition: str | None
    condition_state: DeployConditionState
    classification: str
    target_role: str
    target_count: int
    target_set_digest: str
    prior_step_digest: str
    original_step_digest: str
    status: DeployPostBootstrapStepStatus
    evidence_state: str
    blockers: tuple[str, ...]
    blocker_digest: str
    step_digest: str
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_POST_BOOTSTRAP_STEP_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_POST_BOOTSTRAP_STEP_SCHEMA_VERSION
            or self.mapping_sequence < 1
            or self.target_count < 0
            or tuple(sorted(set(self.blockers))) != self.blockers
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.step_digest != _step_digest(self)
        ):
            raise StatePersistenceError("post-bootstrap deploy step conflicts")
        for digest in (
            self.target_set_digest,
            self.prior_step_digest,
            self.original_step_digest,
            self.blocker_digest,
            self.step_digest,
        ):
            validate_digest(digest, "post-bootstrap deploy step digest")

    def to_object(self) -> dict[str, object]:
        return {
            "blocker_digest": self.blocker_digest,
            "blockers": list(self.blockers),
            "classification": self.classification,
            "condition": self.condition,
            "condition_state": self.condition_state.value,
            "evidence_state": self.evidence_state,
            "mapping_sequence": self.mapping_sequence,
            "original_step_digest": self.original_step_digest,
            "playbook": self.playbook,
            "prior_step_digest": self.prior_step_digest,
            "schema_version": self.schema_version,
            "status": self.status.value,
            "step_digest": self.step_digest,
            "target_count": self.target_count,
            "target_role": self.target_role,
            "target_set_digest": self.target_set_digest,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployPostBootstrapStep:
        require_exact_keys(value, set(cls.__dataclass_fields__), "post-bootstrap step")
        condition = value["condition"]
        blockers = value["blockers"]
        if condition is not None and not isinstance(condition, str):
            raise StatePersistenceError("post-bootstrap step condition is invalid")
        if not isinstance(blockers, list) or not all(
            isinstance(item, str) for item in blockers
        ):
            raise StatePersistenceError("post-bootstrap step blockers are invalid")
        try:
            return cls(
                mapping_sequence=_integer(
                    value["mapping_sequence"], "mapping sequence"
                ),
                playbook=require_string(value, "playbook"),
                condition=condition,
                condition_state=DeployConditionState(
                    require_string(value, "condition_state")
                ),
                classification=require_string(value, "classification"),
                target_role=require_string(value, "target_role"),
                target_count=_integer(value["target_count"], "target count"),
                target_set_digest=require_string(value, "target_set_digest"),
                prior_step_digest=require_string(value, "prior_step_digest"),
                original_step_digest=require_string(value, "original_step_digest"),
                status=DeployPostBootstrapStepStatus(require_string(value, "status")),
                evidence_state=require_string(value, "evidence_state"),
                blockers=tuple(blockers),
                blocker_digest=require_string(value, "blocker_digest"),
                step_digest=require_string(value, "step_digest"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "post-bootstrap deploy step enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployPostBootstrapReconciliation:
    generation: int
    created_at: str
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    stage: str
    request_digest: str
    journal_generation: int
    journal_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    post_configure_artifact_digest: str
    post_configure_record_digest: str
    post_configure_effective_plan_digest: str
    bootstrap_context_artifact_digest: str
    bootstrap_context_record_digest: str
    bootstrap_plan_artifact_digest: str
    bootstrap_plan_digest: str
    bootstrap_step_count: int
    completed_sequence: int
    completed_prefix_digest: str
    final_health_kind: str
    final_health_execution_schema_version: str
    final_health_execution_artifact_digest: str
    final_health_evidence_schema_version: str
    final_health_evidence_artifact_digest: str
    final_health_evidence_digest: str
    final_health_reconciliation_schema_version: str
    final_health_reconciliation_artifact_digest: str
    final_health_reconciliation_digest: str
    current_member_count: int
    current_member_set_digest: str
    policy_state_digest: str
    policy_unknown_count: int
    policy_not_performed_count: int
    replication_state: str
    quorum_state: str
    backup_policy_state: str
    capacity_state: str
    original_mapping_count: int
    original_mapping_digest: str
    original_mapping_unchanged: bool
    boundary_state: str
    boundary_blocker_digest: str
    mapped_health_sequence: int
    mapped_health_state: str
    mapped_health_evidence_digest: str
    next_mapping_sequence: int
    next_playbook: str
    next_step_status: DeployPostBootstrapStepStatus
    next_target_count: int
    next_target_set_digest: str
    steps: tuple[DeployPostBootstrapStep, ...]
    step_count: int
    succeeded_count: int
    authorization_required_count: int
    blocked_count: int
    not_performed_count: int
    effective_plan_digest: str
    catalog_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    authorization_state: str
    execution_state: str
    public_workflow_state: str
    record_digest: str
    post_configure_schema_version: str = (
        ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        counts = Counter(step.status for step in self.steps)
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_SCHEMA_VERSION
            or self.post_configure_schema_version
            != ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.bootstrap_step_count < 1
            or self.completed_sequence != self.bootstrap_step_count
            or self.current_member_count != self.completed_sequence
            or self.original_mapping_count != _ORIGINAL_MAPPING_COUNT
            or self.original_mapping_digest != _mapping_digest()
            or not self.original_mapping_unchanged
            or self.boundary_state != "resolved-by-complete-bootstrap"
            or self.boundary_blocker_digest != _digest_object(list(_BOUNDARY_BLOCKERS))
            or self.mapped_health_sequence != _MAPPED_HEALTH_SEQUENCE
            or self.mapped_health_state != "satisfied-by-final-complete-set-health"
            or self.next_mapping_sequence != _NEXT_MAPPING_SEQUENCE
            or self.next_playbook != _NEXT_PLAYBOOK
            or self.next_step_status
            is not DeployPostBootstrapStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            or self.step_count != len(self.steps)
            or tuple(sorted({step.mapping_sequence for step in self.steps}))
            != tuple(range(1, _ORIGINAL_MAPPING_COUNT + 1))
            or self.succeeded_count != counts[DeployPostBootstrapStepStatus.SUCCEEDED]
            or self.authorization_required_count
            != counts[
                DeployPostBootstrapStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            ]
            or self.blocked_count != counts[DeployPostBootstrapStepStatus.BLOCKED]
            or self.not_performed_count
            != counts[DeployPostBootstrapStepStatus.NOT_PERFORMED]
            or self.authorization_required_count != 1
            or any(
                step.status is not DeployPostBootstrapStepStatus.SUCCEEDED
                for step in self.steps
                if step.mapping_sequence == _MAPPED_HEALTH_SEQUENCE
            )
            or any(
                step.status
                is not DeployPostBootstrapStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
                for step in self.steps
                if step.mapping_sequence == _NEXT_MAPPING_SEQUENCE
            )
            or self.effective_plan_digest
            != _digest_object([step.to_object() for step in self.steps])
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.authorization_state != "not-collected"
            or self.execution_state != "unavailable"
            or self.public_workflow_state != "unavailable"
            or self.record_digest != _record_digest(self)
        ):
            raise StatePersistenceError("post-bootstrap reconciliation conflicts")
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "post-bootstrap reconciliation digest")

    def to_object(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if isinstance(value, uuid.UUID):
                result[name] = str(value)
            elif isinstance(value, StrEnum):
                result[name] = value.value
            elif name == "steps":
                result[name] = [step.to_object() for step in self.steps]
            else:
                result[name] = value
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployPostBootstrapReconciliation:
        require_exact_keys(
            value, set(cls.__dataclass_fields__), "post-bootstrap reconciliation"
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "bootstrap_step_count",
            "completed_sequence",
            "current_member_count",
            "policy_unknown_count",
            "policy_not_performed_count",
            "original_mapping_count",
            "mapped_health_sequence",
            "next_mapping_sequence",
            "next_target_count",
            "step_count",
            "succeeded_count",
            "authorization_required_count",
            "blocked_count",
            "not_performed_count",
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
                elif name == "next_step_status":
                    parsed[name] = DeployPostBootstrapStepStatus(
                        require_string(value, name)
                    )
                elif name == "original_mapping_unchanged":
                    if not isinstance(item, bool):
                        raise StatePersistenceError(
                            "post-bootstrap mapping flag is invalid"
                        )
                    parsed[name] = item
                elif name == "steps":
                    if not isinstance(item, list):
                        raise StatePersistenceError(
                            "post-bootstrap reconciliation steps are invalid"
                        )
                    parsed[name] = tuple(
                        DeployPostBootstrapStep.from_object(
                            _mapping(step, "post-bootstrap step")
                        )
                        for step in item
                    )
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "post-bootstrap reconciliation enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployPostBootstrapReconciliation:
    record: DeployPostBootstrapReconciliation
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class DeployPostBootstrapReconciliationReport:
    operation_id: uuid.UUID
    artifact_state: DeployPostBootstrapArtifactState
    completed_sequence: int
    current_member_count: int
    final_health_kind: str
    mapped_health_state: str
    next_mapping_sequence: int
    next_playbook: str
    next_step_status: DeployPostBootstrapStepStatus
    next_target_count: int
    original_mapping_unchanged: bool
    journal_status: JournalStatus
    journal_phase: OperationPhase
    policy_unknown_count: int
    policy_not_performed_count: int
    retry_allowed: bool
    process_calls: int
    artifact_digest: str
    record_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_REPORT_SCHEMA_VERSION
    )

    def to_object(self) -> dict[str, object]:
        return {
            "artifact_digest": self.artifact_digest,
            "artifact_state": self.artifact_state.value,
            "completed_sequence": self.completed_sequence,
            "current_member_count": self.current_member_count,
            "final_health_kind": self.final_health_kind,
            "journal_phase": self.journal_phase.value,
            "journal_status": self.journal_status.value,
            "mapped_health_state": self.mapped_health_state,
            "next_mapping_sequence": self.next_mapping_sequence,
            "next_playbook": self.next_playbook,
            "next_step_status": self.next_step_status.value,
            "next_target_count": self.next_target_count,
            "operation_id": str(self.operation_id),
            "original_mapping_unchanged": self.original_mapping_unchanged,
            "policy_not_performed_count": self.policy_not_performed_count,
            "policy_unknown_count": self.policy_unknown_count,
            "process_calls": self.process_calls,
            "record_digest": self.record_digest,
            "retry_allowed": self.retry_allowed,
            "schema_version": self.schema_version,
        }


class DeployPostBootstrapReconciliationStore:
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
        self._path = deploy_scylla_post_bootstrap_reconciliation_path(
            paths, operation_id
        )
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
    ) -> StoredDeployPostBootstrapReconciliation:
        value, digest = self._file.read()
        record = DeployPostBootstrapReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "post-bootstrap reconciliation identity conflicts"
            )
        return StoredDeployPostBootstrapReconciliation(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPostBootstrapReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployPostBootstrapReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployPostBootstrapReconciliation,
        DeployPostBootstrapArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError("post-bootstrap reconciliation is immutable")
            return current, DeployPostBootstrapArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployPostBootstrapReconciliation(record, digest),
            DeployPostBootstrapArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class _HealthCompletion:
    kind: str
    execution_schema_version: str
    execution_artifact_digest: str
    evidence_schema_version: str
    evidence_artifact_digest: str
    evidence_digest: str
    reconciliation_schema_version: str
    reconciliation_artifact_digest: str
    reconciliation_digest: str
    current_member_count: int
    current_member_set_digest: str
    policy_states: tuple[tuple[str, HealthCheckStatus], ...]
    completion_digest: str


def reconcile_deploy_scylla_post_bootstrap(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployPostBootstrapReconciliationReport:
    """Validate exact bootstrap completion and persist the mapping bridge."""

    paths = StatePaths.derive(state_root, cluster_name)
    return _reconcile_deploy_scylla_post_bootstrap(
        paths,
        operation_id,
        lock=lock,
    )


def _reconcile_deploy_scylla_post_bootstrap(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
) -> DeployPostBootstrapReconciliationReport:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    bootstrap = _load_authorization_context(paths, operation_id, lock=lock)
    plan = bootstrap.plan.record
    context = bootstrap.context.record
    _load_reconciliation_context(paths, operation_id, lock=lock)
    post_configure = DeployPostScyllaConfigureReconciliationStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=context.cluster_uuid,
        expected_cluster_name=context.cluster_name,
    )
    if (
        context.post_configure_artifact_digest != post_configure.artifact_digest
        or context.post_configure_record_digest != post_configure.record.record_digest
        or context.post_configure_effective_plan_digest
        != post_configure.record.effective_plan_digest
        or plan.post_configure_artifact_digest != post_configure.artifact_digest
        or plan.post_configure_record_digest != post_configure.record.record_digest
        or plan.original_mapping_count != _ORIGINAL_MAPPING_COUNT
        or plan.original_mapping_digest != _mapping_digest()
        or not plan.original_mapping_unchanged
        or plan.step_count < 1
    ):
        raise StateConflictError(
            "post-bootstrap bridge requires the exact unchanged deploy mapping"
        )
    _refuse_extra_sequence_artifacts(paths, operation_id, plan.step_count)
    completions = _load_completed_prefix(
        paths,
        operation_id,
        lock=lock,
        cluster_uuid=context.cluster_uuid,
        cluster_name=context.cluster_name,
        plan=plan,
    )
    final_health = completions[-1]
    if (
        final_health.current_member_count != plan.step_count
        or final_health.kind != _final_health_kind(plan.step_count)
    ):
        raise StateConflictError(
            "post-bootstrap final complete-set health does not match the plan"
        )
    steps = _build_steps(post_configure.record.steps, final_health.evidence_digest)
    manager_steps = tuple(
        step for step in steps if step.mapping_sequence == _NEXT_MAPPING_SEQUENCE
    )
    if len(manager_steps) != 1:
        raise StateConflictError(
            "post-bootstrap immediate manager-server scope is ambiguous"
        )
    manager_step = manager_steps[0]
    policy = dict(final_health.policy_states)
    store = DeployPostBootstrapReconciliationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    created_at = (
        store.read_locked(
            lock,
            expected_cluster_uuid=context.cluster_uuid,
            expected_cluster_name=context.cluster_name,
        ).record.created_at
        if store.path.exists()
        else format_timestamp(datetime.now(UTC))
    )
    record_values: dict[str, object] = dict(
        generation=1,
        created_at=created_at,
        cluster_uuid=context.cluster_uuid,
        cluster_name=context.cluster_name,
        operation_id=operation_id,
        operation=_OPERATION,
        stage=_STAGE,
        request_digest=context.request_digest,
        journal_generation=context.journal_generation,
        journal_digest=context.journal_digest,
        journal_status=context.journal_status,
        journal_phase=context.journal_phase,
        post_configure_artifact_digest=post_configure.artifact_digest,
        post_configure_record_digest=post_configure.record.record_digest,
        post_configure_effective_plan_digest=post_configure.record.effective_plan_digest,
        bootstrap_context_artifact_digest=bootstrap.context.artifact_digest,
        bootstrap_context_record_digest=context.record_digest,
        bootstrap_plan_artifact_digest=bootstrap.plan.artifact_digest,
        bootstrap_plan_digest=plan.plan_digest,
        bootstrap_step_count=plan.step_count,
        completed_sequence=plan.step_count,
        completed_prefix_digest=_digest_object(
            [completion.completion_digest for completion in completions]
        ),
        final_health_kind=final_health.kind,
        final_health_execution_schema_version=final_health.execution_schema_version,
        final_health_execution_artifact_digest=(final_health.execution_artifact_digest),
        final_health_evidence_schema_version=final_health.evidence_schema_version,
        final_health_evidence_artifact_digest=final_health.evidence_artifact_digest,
        final_health_evidence_digest=final_health.evidence_digest,
        final_health_reconciliation_schema_version=(
            final_health.reconciliation_schema_version
        ),
        final_health_reconciliation_artifact_digest=(
            final_health.reconciliation_artifact_digest
        ),
        final_health_reconciliation_digest=final_health.reconciliation_digest,
        current_member_count=final_health.current_member_count,
        current_member_set_digest=final_health.current_member_set_digest,
        policy_state_digest=_digest_object(
            [[name, state.value] for name, state in final_health.policy_states]
        ),
        policy_unknown_count=sum(
            state is HealthCheckStatus.UNKNOWN
            for _, state in final_health.policy_states
        ),
        policy_not_performed_count=sum(
            state is HealthCheckStatus.NOT_PERFORMED
            for _, state in final_health.policy_states
        ),
        replication_state=policy["replication"].value,
        quorum_state=policy["quorum"].value,
        backup_policy_state=policy["backup-policy"].value,
        capacity_state=policy["capacity"].value,
        original_mapping_count=_ORIGINAL_MAPPING_COUNT,
        original_mapping_digest=_mapping_digest(),
        original_mapping_unchanged=True,
        boundary_state="resolved-by-complete-bootstrap",
        boundary_blocker_digest=_digest_object(list(_BOUNDARY_BLOCKERS)),
        mapped_health_sequence=_MAPPED_HEALTH_SEQUENCE,
        mapped_health_state="satisfied-by-final-complete-set-health",
        mapped_health_evidence_digest=final_health.evidence_digest,
        next_mapping_sequence=_NEXT_MAPPING_SEQUENCE,
        next_playbook=_NEXT_PLAYBOOK,
        next_step_status=manager_step.status,
        next_target_count=manager_step.target_count,
        next_target_set_digest=manager_step.target_set_digest,
        steps=steps,
        step_count=len(steps),
        succeeded_count=sum(
            step.status is DeployPostBootstrapStepStatus.SUCCEEDED for step in steps
        ),
        authorization_required_count=sum(
            step.status
            is DeployPostBootstrapStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            for step in steps
        ),
        blocked_count=sum(
            step.status is DeployPostBootstrapStepStatus.BLOCKED for step in steps
        ),
        not_performed_count=sum(
            step.status is DeployPostBootstrapStepStatus.NOT_PERFORMED for step in steps
        ),
        effective_plan_digest=_digest_object([step.to_object() for step in steps]),
        catalog_digest=context.catalog_digest,
        ansible_source_version=ANSIBLE_SOURCE_VERSION,
        ansible_source_digest=context.ansible_source_digest,
        authorization_state="not-collected",
        execution_state="unavailable",
        public_workflow_state="unavailable",
    )
    record_values["record_digest"] = _record_digest_from_values(record_values)
    record = DeployPostBootstrapReconciliation(**record_values)  # type: ignore[arg-type]
    stored, artifact_state = store.write_locked(record, lock=lock)
    return DeployPostBootstrapReconciliationReport(
        operation_id=operation_id,
        artifact_state=artifact_state,
        completed_sequence=record.completed_sequence,
        current_member_count=record.current_member_count,
        final_health_kind=record.final_health_kind,
        mapped_health_state=record.mapped_health_state,
        next_mapping_sequence=record.next_mapping_sequence,
        next_playbook=record.next_playbook,
        next_step_status=record.next_step_status,
        next_target_count=record.next_target_count,
        original_mapping_unchanged=record.original_mapping_unchanged,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        policy_unknown_count=record.policy_unknown_count,
        policy_not_performed_count=record.policy_not_performed_count,
        retry_allowed=False,
        process_calls=0,
        artifact_digest=stored.artifact_digest,
        record_digest=record.record_digest,
    )


def deploy_scylla_post_bootstrap_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    operation_id = _require_operation_id(operation_id)
    return paths.operations / (
        f"{operation_id}{DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_FILENAME_SUFFIX}"
    )


def deploy_scylla_post_bootstrap_reconciliation_id_from_filename(
    filename: str,
) -> uuid.UUID | None:
    if not filename.endswith(
        DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_FILENAME_SUFFIX
    ):
        return None
    prefix = filename[
        : -len(DEPLOY_SCYLLA_POST_BOOTSTRAP_RECONCILIATION_FILENAME_SUFFIX)
    ]
    try:
        operation_id = uuid.UUID(prefix)
    except ValueError:
        return None
    return operation_id if str(operation_id) == prefix else None


def _load_completed_prefix(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
    cluster_uuid: uuid.UUID,
    cluster_name: str,
    plan: object,
) -> tuple[_HealthCompletion, ...]:
    steps = getattr(plan, "steps")
    completions = [
        _load_initial_completion(
            paths,
            operation_id,
            lock=lock,
            cluster_uuid=cluster_uuid,
            cluster_name=cluster_name,
            plan_step=steps[0],
            final=len(steps) == 1,
        )
    ]
    if len(steps) >= 2:
        completions.append(
            _load_second_completion(
                paths,
                operation_id,
                lock=lock,
                cluster_uuid=cluster_uuid,
                cluster_name=cluster_name,
                plan_step=steps[1],
                final=len(steps) == 2,
            )
        )
    if len(steps) >= 3:
        completions.append(
            _load_third_completion(
                paths,
                operation_id,
                lock=lock,
                cluster_uuid=cluster_uuid,
                cluster_name=cluster_name,
                plan_step=steps[2],
                final=len(steps) == 3,
            )
        )
    for sequence in range(4, len(steps) + 1):
        completions.append(
            _load_later_completion(
                paths,
                operation_id,
                sequence,
                lock=lock,
                cluster_uuid=cluster_uuid,
                cluster_name=cluster_name,
                plan_step=steps[sequence - 1],
                final=sequence == len(steps),
            )
        )
    return tuple(completions)


def _load_initial_completion(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
    cluster_uuid: uuid.UUID,
    cluster_name: str,
    plan_step: object,
    final: bool,
) -> _HealthCompletion:
    authorization = DeployScyllaBootstrapAuthorizationStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    execution = DeployScyllaBootstrapExecutionStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    evidence = DeployScyllaBootstrapEvidenceStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    _validate_bootstrap_result(
        sequence=1,
        plan_step=plan_step,
        authorization_artifact_digest=authorization.artifact_digest,
        authorization_digest=authorization.record.authorization_digest,
        execution=execution.record,
        execution_artifact_digest=execution.artifact_digest,
        evidence=evidence.record,
        evidence_artifact_digest=evidence.artifact_digest,
    )
    health_execution = DeployScyllaHealthExecutionStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    health_evidence = DeployScyllaHealthEvidenceStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    reconciliation = DeployScyllaHealthCheckpointStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    return _validate_health(
        kind="initial-seed-health",
        sequence=1,
        final=final,
        execution=health_execution,
        evidence=health_evidence,
        reconciliation=reconciliation,
        reconciliation_digest=reconciliation.record.checkpoint_digest,
        member_count=reconciliation.record.active_member_count,
        member_set_digest=reconciliation.record.active_member_set_digest,
    )


def _load_second_completion(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
    cluster_uuid: uuid.UUID,
    cluster_name: str,
    plan_step: object,
    final: bool,
) -> _HealthCompletion:
    authorization = DeployScyllaJoinAuthorizationStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    execution = DeployScyllaJoinExecutionStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    evidence = DeployScyllaJoinEvidenceStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    _validate_bootstrap_result(
        sequence=2,
        plan_step=plan_step,
        authorization_artifact_digest=authorization.artifact_digest,
        authorization_digest=authorization.record.authorization_digest,
        execution=execution.record,
        execution_artifact_digest=execution.artifact_digest,
        evidence=evidence.record,
        evidence_artifact_digest=evidence.artifact_digest,
    )
    health_execution = DeployScyllaPostJoinHealthExecutionStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    health_evidence = DeployScyllaPostJoinHealthEvidenceStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    reconciliation = DeployScyllaPostJoinHealthReconciliationStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    return _validate_health(
        kind="first-join-health",
        sequence=2,
        final=final,
        execution=health_execution,
        evidence=health_evidence,
        reconciliation=reconciliation,
        reconciliation_digest=reconciliation.record.reconciliation_digest,
        member_count=reconciliation.record.current_member_count,
        member_set_digest=reconciliation.record.current_member_set_digest,
    )


def _load_third_completion(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
    cluster_uuid: uuid.UUID,
    cluster_name: str,
    plan_step: object,
    final: bool,
) -> _HealthCompletion:
    authorization = DeployScyllaSequenceThreeJoinAuthorizationStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    execution = DeployScyllaSequenceThreeJoinExecutionStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    evidence = DeployScyllaSequenceThreeJoinEvidenceStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    _validate_bootstrap_result(
        sequence=3,
        plan_step=plan_step,
        authorization_artifact_digest=authorization.artifact_digest,
        authorization_digest=authorization.record.authorization_digest,
        execution=execution.record,
        execution_artifact_digest=execution.artifact_digest,
        evidence=evidence.record,
        evidence_artifact_digest=evidence.artifact_digest,
    )
    health_execution = DeployScyllaPostSequenceThreeHealthExecutionStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    health_evidence = DeployScyllaPostSequenceThreeHealthEvidenceStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    reconciliation = DeployScyllaPostSequenceThreeHealthReconciliationStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    return _validate_health(
        kind="sequence-three-health",
        sequence=3,
        final=final,
        execution=health_execution,
        evidence=health_evidence,
        reconciliation=reconciliation,
        reconciliation_digest=reconciliation.record.reconciliation_digest,
        member_count=reconciliation.record.current_member_count,
        member_set_digest=reconciliation.record.current_member_set_digest,
    )


def _load_later_completion(
    paths: StatePaths,
    operation_id: uuid.UUID,
    sequence: int,
    *,
    lock: ClusterLock,
    cluster_uuid: uuid.UUID,
    cluster_name: str,
    plan_step: object,
    final: bool,
) -> _HealthCompletion:
    authorization = DeployScyllaLaterJoinAuthorizationStore(
        paths, operation_id, sequence
    ).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    execution = DeployScyllaLaterJoinExecutionStore(
        paths, operation_id, sequence
    ).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    evidence = DeployScyllaLaterJoinEvidenceStore(
        paths, operation_id, sequence
    ).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    _validate_bootstrap_result(
        sequence=sequence,
        plan_step=plan_step,
        authorization_artifact_digest=authorization.artifact_digest,
        authorization_digest=authorization.record.authorization_digest,
        execution=execution.record,
        execution_artifact_digest=execution.artifact_digest,
        evidence=evidence.record,
        evidence_artifact_digest=evidence.artifact_digest,
    )
    health_execution = DeployScyllaPostLaterJoinHealthExecutionStore(
        paths, operation_id, sequence
    ).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    health_evidence = DeployScyllaPostLaterJoinHealthEvidenceStore(
        paths, operation_id, sequence
    ).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    reconciliation = DeployScyllaPostLaterJoinHealthReconciliationStore(
        paths, operation_id, sequence
    ).read_locked(
        lock,
        expected_cluster_uuid=cluster_uuid,
        expected_cluster_name=cluster_name,
    )
    return _validate_health(
        kind="later-join-health",
        sequence=sequence,
        final=final,
        execution=health_execution,
        evidence=health_evidence,
        reconciliation=reconciliation,
        reconciliation_digest=reconciliation.record.reconciliation_digest,
        member_count=reconciliation.record.current_member_count,
        member_set_digest=reconciliation.record.current_member_set_digest,
    )


def _validate_bootstrap_result(
    *,
    sequence: int,
    plan_step: object,
    authorization_artifact_digest: str,
    authorization_digest: str,
    execution: object,
    execution_artifact_digest: str,
    evidence: object,
    evidence_artifact_digest: str,
) -> None:
    entry = getattr(evidence, "entry", evidence)
    execution_evidence_digest = getattr(
        execution,
        "evidence_digest",
        getattr(getattr(execution, "attempt", None), "evidence_digest", None),
    )
    if (
        getattr(plan_step, "sequence") != sequence
        or getattr(execution, "state").value != "succeeded"
        or not getattr(execution, "completed")
        or not getattr(execution, "ordinary_authorization_consumed")
        or not getattr(execution, "narrow_authorization_consumed")
        or getattr(execution, "manual_recovery_required")
        or getattr(execution, "binding").authorization_artifact_digest
        != authorization_artifact_digest
        or getattr(execution, "binding").authorization_digest != authorization_digest
        or getattr(execution, "binding").plan_step_digest
        != getattr(plan_step, "step_digest")
        or getattr(evidence, "binding") != getattr(execution, "binding")
        or getattr(entry, "status") is not ScyllaBootstrapStatus.BOOTSTRAPPED
        or getattr(entry, "evidence_digest") != execution_evidence_digest
        or getattr(entry, "blocker_count") != 0
        or getattr(entry, "recovery_required")
        or getattr(entry, "automatic_retry_allowed")
    ):
        raise StateConflictError(
            f"post-bootstrap sequence {sequence} is not exact terminal success"
        )
    _ = execution_artifact_digest, evidence_artifact_digest


def _validate_health(
    *,
    kind: str,
    sequence: int,
    final: bool,
    execution: object,
    evidence: object,
    reconciliation: object,
    reconciliation_digest: str,
    member_count: int,
    member_set_digest: str,
) -> _HealthCompletion:
    execution_record = getattr(execution, "record")
    evidence_record = getattr(evidence, "record")
    reconciliation_record = getattr(reconciliation, "record")
    policy_states = getattr(evidence_record, "policy_states")
    checks = getattr(evidence_record, "check_states")
    bootstrap_complete = getattr(
        reconciliation_record, "bootstrap_sequence_complete", final
    )
    next_required = getattr(reconciliation_record, "next_step_required", not final)
    if (
        getattr(execution_record, "state").value != "succeeded"
        or not execution_record.completed
        or execution_record.manual_recovery_required
        or execution_record.exit_code != 0
        or execution_record.evidence_digest != evidence_record.evidence_digest
        or evidence_record.binding != execution_record.binding
        or evidence_record.health_status
        not in {HealthReadiness.READY, HealthReadiness.UNKNOWN}
        or not evidence_record.strict_complete
        or evidence_record.blocker_count
        or not evidence_record.schema_agreement
        or evidence_record.streaming_state != "complete"
        or any(state is not HealthCheckStatus.PASSED for _, state in checks)
        or len(evidence_record.nodes) != sequence
        or any(
            node.membership_state != "UN"
            or not node.service_ready
            or not node.api_ready
            or not node.cql_ready
            or not node.storage_ready
            or not node.streaming_idle
            or node.blocker_count
            for node in evidence_record.nodes
        )
        or reconciliation_record.health_execution_artifact_digest
        != getattr(execution, "artifact_digest")
        or reconciliation_record.health_evidence_artifact_digest
        != getattr(evidence, "artifact_digest")
        or reconciliation_record.health_evidence_digest
        != evidence_record.evidence_digest
        or reconciliation_record.health_succeeded_count != sequence
        or member_count != sequence
        or bootstrap_complete != final
        or next_required != (not final)
    ):
        raise StateConflictError(
            f"post-bootstrap sequence {sequence} health is incomplete or stale"
        )
    completion_digest = _digest_object(
        {
            "evidence_artifact_digest": getattr(evidence, "artifact_digest"),
            "execution_artifact_digest": getattr(execution, "artifact_digest"),
            "kind": kind,
            "reconciliation_artifact_digest": getattr(
                reconciliation, "artifact_digest"
            ),
            "sequence": sequence,
        }
    )
    return _HealthCompletion(
        kind=kind,
        execution_schema_version=execution_record.schema_version,
        execution_artifact_digest=getattr(execution, "artifact_digest"),
        evidence_schema_version=evidence_record.schema_version,
        evidence_artifact_digest=getattr(evidence, "artifact_digest"),
        evidence_digest=evidence_record.evidence_digest,
        reconciliation_schema_version=reconciliation_record.schema_version,
        reconciliation_artifact_digest=getattr(reconciliation, "artifact_digest"),
        reconciliation_digest=reconciliation_digest,
        current_member_count=member_count,
        current_member_set_digest=member_set_digest,
        policy_states=policy_states,
        completion_digest=completion_digest,
    )


def _build_steps(
    prior_steps: tuple[object, ...], final_health_evidence_digest: str
) -> tuple[DeployPostBootstrapStep, ...]:
    if tuple(sorted({getattr(step, "mapping_sequence") for step in prior_steps})) != (
        tuple(range(1, _ORIGINAL_MAPPING_COUNT + 1))
    ):
        raise StateConflictError("post-bootstrap prior deploy mapping conflicts")
    result: list[DeployPostBootstrapStep] = []
    for prior in prior_steps:
        sequence = getattr(prior, "mapping_sequence")
        status = DeployPostBootstrapStepStatus(getattr(prior, "status").value)
        evidence_state = getattr(prior, "evidence_state").value
        blockers = getattr(prior, "blockers")
        if sequence == _MAPPED_HEALTH_SEQUENCE:
            if (
                getattr(prior, "playbook") != _MAPPED_HEALTH_PLAYBOOK
                or getattr(prior, "condition_state") is not DeployConditionState.ACTIVE
            ):
                raise StateConflictError(
                    "post-bootstrap mapped health identity conflicts"
                )
            status = DeployPostBootstrapStepStatus.SUCCEEDED
            evidence_state = "bootstrap-final-health-bound"
            blockers = ()
        elif sequence == _NEXT_MAPPING_SEQUENCE:
            definition = get_playbook(getattr(prior, "playbook"))
            if (
                getattr(prior, "playbook") != _NEXT_PLAYBOOK
                or getattr(prior, "condition_state") is not DeployConditionState.ACTIVE
                or definition.classification.value != "mutating"
                or not definition.source_available
                or not getattr(prior, "target_ids")
            ):
                raise StateConflictError(
                    "post-bootstrap immediate manager-server gate conflicts"
                )
            status = DeployPostBootstrapStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            evidence_state = "bootstrap-final-health-bound"
            blockers = _MANAGER_AUTHORIZATION_BLOCKERS
        elif sequence > _NEXT_MAPPING_SEQUENCE:
            status = (
                DeployPostBootstrapStepStatus.BLOCKED
                if getattr(prior, "status").value == "blocked"
                else DeployPostBootstrapStepStatus.NOT_PERFORMED
            )
        values = {
            "mapping_sequence": sequence,
            "playbook": getattr(prior, "playbook"),
            "condition": getattr(prior, "condition"),
            "condition_state": getattr(prior, "condition_state"),
            "classification": getattr(prior, "classification").value,
            "target_role": getattr(prior, "target_role"),
            "target_count": len(getattr(prior, "target_ids")),
            "target_set_digest": getattr(prior, "target_digest"),
            "prior_step_digest": _digest_object(getattr(prior, "to_object")()),
            "original_step_digest": getattr(prior, "original_step_digest"),
            "status": status,
            "evidence_state": evidence_state,
            "blockers": tuple(sorted(blockers)),
            "blocker_digest": _digest_object(list(sorted(blockers))),
        }
        values["step_digest"] = _step_digest_from_values(values)
        result.append(DeployPostBootstrapStep(**values))
    if final_health_evidence_digest == "":
        raise StateConflictError("post-bootstrap final health digest is unavailable")
    return tuple(result)


def _step_digest(step: DeployPostBootstrapStep) -> str:
    return _digest_object(
        {
            name: _plain_value(getattr(step, name))
            for name in step.__dataclass_fields__
            if name not in _STEP_DIGEST_EXCLUDED
        }
    )


def _step_digest_from_values(values: Mapping[str, object]) -> str:
    return _digest_object(
        {
            name: _plain_value(value)
            for name, value in values.items()
            if name not in _STEP_DIGEST_EXCLUDED
        }
    )


def _record_digest(record: DeployPostBootstrapReconciliation) -> str:
    return _digest_object(
        {
            name: _plain_value(getattr(record, name))
            for name in record.__dataclass_fields__
            if name not in _RECORD_DIGEST_EXCLUDED
            and not name.endswith("schema_version")
        }
    )


def _record_digest_from_values(values: Mapping[str, object]) -> str:
    return _digest_object(
        {
            name: _plain_value(value)
            for name, value in values.items()
            if name not in _RECORD_DIGEST_EXCLUDED
            and not name.endswith("schema_version")
        }
    )


def _plain_value(value: object) -> object:
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, tuple):
        return [
            item.to_object() if isinstance(item, DeployPostBootstrapStep) else item
            for item in value
        ]
    return value


def _digest_fields(record: object) -> tuple[str, ...]:
    return tuple(
        value
        for name in record.__dataclass_fields__  # type: ignore[attr-defined]
        if (
            (name.endswith("_digest") or name.endswith("_artifact_digest"))
            and isinstance((value := getattr(record, name)), str)
        )
    )


def _final_health_kind(step_count: int) -> str:
    if step_count == 1:
        return "initial-seed-health"
    if step_count == 2:
        return "first-join-health"
    if step_count == 3:
        return "sequence-three-health"
    return "later-join-health"


def _refuse_extra_sequence_artifacts(
    paths: StatePaths, operation_id: uuid.UUID, step_count: int
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely inspect post-bootstrap sequence artifacts"
        ) from error
    for entry in entries:
        if not entry.name.startswith(f"{operation_id}."):
            continue
        if step_count < 2 and any(
            marker in entry.name
            for marker in (
                ".ansible-deploy-scylla-join-safety-",
                ".ansible-deploy-scylla-join-authorization.json",
                ".ansible-deploy-scylla-join-execution.json",
                ".ansible-deploy-scylla-join-evidence.json",
                ".ansible-deploy-scylla-join-health-",
            )
        ):
            raise StateConflictError(
                "post-bootstrap found extra sequence-two artifacts"
            )
        if step_count < 3 and any(
            marker in entry.name
            for marker in (
                ".ansible-deploy-scylla-sequence-three-join-",
                ".ansible-deploy-scylla-post-sequence-three-join-health-",
            )
        ):
            raise StateConflictError(
                "post-bootstrap found extra sequence-three artifacts"
            )
        match = _LATER_ARTIFACT.match(entry.name)
        if match is None or match.group("operation") != str(operation_id):
            continue
        sequence = int(match.group("sequence"))
        if sequence < 4 or sequence > step_count:
            raise StateConflictError(
                "post-bootstrap found an extra or noncontiguous sequence artifact"
            )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "post-bootstrap reconciliation requires the matching held deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "post-bootstrap reconciliation paths are not canonical"
        )


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise StatePersistenceError(f"{label} must be an object")
    return value
