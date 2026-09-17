"""Immutable deploy reconciliation after exact ``scylla-configure`` execution.

The original deploy plan is an immutable 21-position mapping that historically
omitted ``scylla-bootstrap``.  This subprocess-free owner therefore binds exact
configuration success without rewriting that plan and exposes only a truthful,
blocked bootstrap procedure boundary.
"""

from __future__ import annotations

import os
import uuid
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
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
    _require_operation_id,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import (
    ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION,
    DeployScyllaConfigureAuthorizationStore,
    StoredDeployScyllaConfigureAuthorization,
    _AuthorizationContext,
    _build_authorization,
    _derive_configuration_intents,
    _DerivedConfigurationIntent,
    _load_authorization_context,
    _loaded,
)
from scylla_vms.ansible.deploy_scylla_configure_execution import (
    ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_SCHEMA_VERSION,
    DeployScyllaConfigureEvidenceEntry,
    DeployScyllaConfigureEvidenceStore,
    DeployScyllaConfigureExecutionState,
    DeployScyllaConfigureExecutionStore,
    StoredDeployScyllaConfigureEvidence,
    StoredDeployScyllaConfigureExecution,
)
from scylla_vms.ansible.deploy_scylla_install_reconciliation import (
    ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_SCHEMA_VERSION,
    StoredDeployPostScyllaInstallReconciliation,
)
from scylla_vms.ansible.registry import OPERATION_PLAYBOOKS
from scylla_vms.ansible.scylla_configure import SCYLLA_CONFIGURE_DIRECTORIES
from scylla_vms.ansible.scylla_install import (
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_RELEASE_LINE,
)
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
from scylla_vms.terraform.apply_readiness import (
    TERRAFORM_APPLY_READINESS_SCHEMA_VERSION,
)

ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-scylla-configure-reconciliation/v1"
)
ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-scylla-configure-reconciliation-report/v1"
)
DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-post-scylla-configure-reconciliation.json"
)

_OPERATION = "deploy"
_CONFIGURE_PLAYBOOK = "scylla-configure"
_BOOTSTRAP_PLAYBOOK = "scylla-bootstrap"
_CONFIGURE_MAPPING = 12
_ORIGINAL_MAPPING_COUNT = 21
_BLOCKED = "blocked"
_NOT_PERFORMED = "not-performed"
_UNAVAILABLE = "unavailable"
_NOT_STARTED = "not-started"
_BOOTSTRAP_BLOCKERS = (
    "bootstrap-plan-required",
    "bootstrap-step-unmodeled",
)
_CONFIGURATION_FILE_NAMES = (
    "cassandra-rackdc.properties",
    "scylla.yaml",
)


class DeployPostScyllaConfigureArtifactState(StrEnum):
    """Immutable reconciliation persistence result."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployPostScyllaConfigureReconciliation:
    """Value-free post-configuration checkpoint and bootstrap refusal."""

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
    prior_reconciliation_artifact_digest: str
    prior_reconciliation_record_digest: str
    prior_effective_plan_digest: str
    authorization_artifact_digest: str
    authorization_digest: str
    authorization_scope_digest: str
    authorization_proof_digest: str
    configuration_intent_digest: str
    execution_artifact_digest: str
    execution_binding_digest: str
    execution_generation: int
    evidence_artifact_digest: str
    evidence_digest: str
    result_digest: str
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
    playbook_source_digest: str
    toolchain_version: str
    executable_identity_digest: str
    toolchain_evidence_digest: str
    release_line_digest: str
    package_version_digest: str
    target_count: int
    target_set_digest: str
    configured_count: int
    changed_count: int
    no_change_count: int
    configuration_file_count: int
    configuration_file_set_digest: str
    root_owned_count: int
    mode_0644_count: int
    service_safe_count: int
    prohibited_action_count: int
    topology_digest: str
    seed_policy_digest: str
    directory_policy_digest: str
    original_mapping_count: int
    original_mapping_digest: str
    steps: tuple[DeployBaseOsReconciledStep, ...]
    step_count: int
    succeeded_count: int
    authorization_required_count: int
    eligible_count: int
    blocked_count: int
    not_performed_count: int
    effective_plan_digest: str
    next_procedure_gate: str
    bootstrap_in_original_mapping: bool
    bootstrap_gate_state: str
    bootstrap_blockers: tuple[str, ...]
    bootstrap_blocker_digest: str
    bootstrap_evidence_state: str
    empty_cluster_evidence_state: str
    topology_evidence_state: str
    seed_evidence_state: str
    health_evidence_state: str
    capacity_evidence_state: str
    next_authorization_state: str
    next_execution_state: str
    finalization_state: str
    public_workflow_state: str
    record_digest: str
    prior_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_SCHEMA_VERSION
    )
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
    )
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_SCHEMA_VERSION
            or self.prior_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_AUTHORIZATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_CONFIGURE_EVIDENCE_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.target_count < 1
            or self.configured_count != self.target_count
            or self.changed_count + self.no_change_count != self.target_count
            or self.configuration_file_count != self.target_count * 2
            or self.root_owned_count != self.target_count
            or self.mode_0644_count != self.target_count
            or self.service_safe_count != self.target_count
            or self.prohibited_action_count
            or self.original_mapping_count != _ORIGINAL_MAPPING_COUNT
            or self.next_procedure_gate != _BOOTSTRAP_PLAYBOOK
            or self.bootstrap_in_original_mapping
            or self.bootstrap_gate_state != _BLOCKED
            or self.bootstrap_blockers != _BOOTSTRAP_BLOCKERS
            or any(
                state != _NOT_PERFORMED
                for state in (
                    self.bootstrap_evidence_state,
                    self.empty_cluster_evidence_state,
                    self.topology_evidence_state,
                    self.seed_evidence_state,
                    self.health_evidence_state,
                    self.capacity_evidence_state,
                )
            )
            or self.next_authorization_state != _UNAVAILABLE
            or self.next_execution_state != _UNAVAILABLE
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
        ):
            raise StatePersistenceError(
                "post-scylla-configure reconciliation identity is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for value in (
            self.journal_generation,
            self.execution_generation,
            self.inventory_generation,
            self.trust_generation,
            self.target_count,
            self.configured_count,
            self.changed_count,
            self.no_change_count,
            self.configuration_file_count,
            self.root_owned_count,
            self.mode_0644_count,
            self.service_safe_count,
            self.prohibited_action_count,
            self.original_mapping_count,
            self.step_count,
            self.succeeded_count,
            self.authorization_required_count,
            self.eligible_count,
            self.blocked_count,
            self.not_performed_count,
        ):
            _nonnegative_integer(value, "post-scylla-configure reconciliation count")
        if (
            self.journal_generation < 1
            or self.execution_generation < 1
            or self.inventory_generation < 1
            or self.trust_generation < 1
            or self.step_count != len(self.steps)
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, len(self.steps) + 1))
        ):
            raise StatePersistenceError(
                "post-scylla-configure reconciliation counts conflict"
            )
        mapping = OPERATION_PLAYBOOKS[_OPERATION]
        if (
            len(mapping) != _ORIGINAL_MAPPING_COUNT
            or any(step.playbook == _BOOTSTRAP_PLAYBOOK for step in mapping)
            or mapping[_CONFIGURE_MAPPING - 1].playbook != _CONFIGURE_PLAYBOOK
            or mapping[_CONFIGURE_MAPPING].playbook != "scylla-health"
            or {step.mapping_sequence for step in self.steps}
            != set(range(1, len(mapping) + 1))
            or any(
                step.playbook != mapping[step.mapping_sequence - 1].playbook
                or step.condition != mapping[step.mapping_sequence - 1].condition
                for step in self.steps
            )
        ):
            raise StatePersistenceError(
                "post-scylla-configure original deploy mapping conflicts"
            )
        counts = Counter(step.status for step in self.steps)
        configure_steps = tuple(
            step
            for step in self.steps
            if step.mapping_sequence == _CONFIGURE_MAPPING
            and step.condition_state is DeployConditionState.ACTIVE
        )
        if (
            not configure_steps
            or len(configure_steps) != self.target_count
            or any(
                step.playbook != _CONFIGURE_PLAYBOOK
                or step.status is not DeployBaseOsReconciledStepStatus.SUCCEEDED
                or step.evidence_state
                is not DeployBaseOsReconciledEvidenceState.SCYLLA_CONFIGURE_BOUND
                or step.evidence_digest is None
                or step.blockers
                for step in configure_steps
            )
            or self.succeeded_count
            != counts[DeployBaseOsReconciledStepStatus.SUCCEEDED]
            or self.authorization_required_count
            != counts[
                DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            ]
            or self.eligible_count != counts[DeployBaseOsReconciledStepStatus.ELIGIBLE]
            or self.blocked_count != counts[DeployBaseOsReconciledStepStatus.BLOCKED]
            or self.not_performed_count
            != counts[DeployBaseOsReconciledStepStatus.NOT_PERFORMED]
            or self.authorization_required_count
            or self.eligible_count
            or self.original_mapping_digest != _mapping_digest()
            or self.bootstrap_blocker_digest
            != _digest_object(list(_BOOTSTRAP_BLOCKERS))
            or self.effective_plan_digest
            != _digest_object([step.to_object() for step in self.steps])
            or self.record_digest != _record_digest(self)
        ):
            raise StatePersistenceError(
                "post-scylla-configure reconciliation summary conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "post-scylla-configure reconciliation digest")

    def to_object(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            result[name] = (
                [item.to_object() for item in value]
                if name == "steps"
                else list(value)
                if name == "bootstrap_blockers"
                else value.value
                if isinstance(value, StrEnum)
                else str(value)
                if isinstance(value, uuid.UUID)
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployPostScyllaConfigureReconciliation:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "post-scylla-configure reconciliation",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "execution_generation",
            "inventory_generation",
            "trust_generation",
            "target_count",
            "configured_count",
            "changed_count",
            "no_change_count",
            "configuration_file_count",
            "root_owned_count",
            "mode_0644_count",
            "service_safe_count",
            "prohibited_action_count",
            "original_mapping_count",
            "step_count",
            "succeeded_count",
            "authorization_required_count",
            "eligible_count",
            "blocked_count",
            "not_performed_count",
        }
        boolean_fields = {"bootstrap_in_original_mapping"}
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
            elif name == "steps":
                parsed[name] = tuple(
                    DeployBaseOsReconciledStep.from_object(_mapping(entry, "step"))
                    for entry in _array(item, "steps")
                )
            elif name == "bootstrap_blockers":
                parsed[name] = _string_tuple(item, "bootstrap blockers")
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployPostScyllaConfigureReconciliation:
    record: DeployPostScyllaConfigureReconciliation
    artifact_digest: str


class DeployPostScyllaConfigureReconciliationStore:
    """Owner-only immutable post-configuration reconciliation store."""

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
        self._path = deploy_post_scylla_configure_reconciliation_path(
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
    ) -> StoredDeployPostScyllaConfigureReconciliation:
        value, artifact_digest = self._file.read()
        record = DeployPostScyllaConfigureReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "post-scylla-configure reconciliation identity conflicts"
            )
        return StoredDeployPostScyllaConfigureReconciliation(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPostScyllaConfigureReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployPostScyllaConfigureReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployPostScyllaConfigureReconciliation,
        DeployPostScyllaConfigureArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "post-scylla-configure reconciliation operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "post-scylla-configure reconciliation is immutable"
                )
            return current, DeployPostScyllaConfigureArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployPostScyllaConfigureReconciliation(record, digest),
            DeployPostScyllaConfigureArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployPostScyllaConfigureReconciliationReport:
    """Strict count/digest/status-only reconciliation projection."""

    operation_id: uuid.UUID
    artifact_state: DeployPostScyllaConfigureArtifactState
    reconciliation_artifact_digest: str
    reconciliation_record_digest: str
    effective_plan_digest: str
    execution_artifact_digest: str
    evidence_artifact_digest: str
    evidence_digest: str
    configuration_intent_digest: str
    target_count: int
    target_set_digest: str
    configured_count: int
    changed_count: int
    no_change_count: int
    configuration_file_count: int
    configuration_file_set_digest: str
    service_safe_count: int
    prohibited_action_count: int
    succeeded_count: int
    blocked_count: int
    not_performed_count: int
    next_procedure_gate: str
    bootstrap_gate_state: str
    bootstrap_blockers: tuple[str, ...]
    bootstrap_blocker_digest: str
    bootstrap_evidence_state: str
    empty_cluster_evidence_state: str
    topology_evidence_state: str
    seed_evidence_state: str
    health_evidence_state: str
    capacity_evidence_state: str
    next_authorization_state: str
    next_execution_state: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_REPORT_SCHEMA_VERSION
            or self.target_count < 1
            or self.configured_count != self.target_count
            or self.changed_count + self.no_change_count != self.target_count
            or self.configuration_file_count != self.target_count * 2
            or self.service_safe_count != self.target_count
            or self.prohibited_action_count
            or self.next_procedure_gate != _BOOTSTRAP_PLAYBOOK
            or self.bootstrap_gate_state != _BLOCKED
            or self.bootstrap_blockers != _BOOTSTRAP_BLOCKERS
            or any(
                state != _NOT_PERFORMED
                for state in (
                    self.bootstrap_evidence_state,
                    self.empty_cluster_evidence_state,
                    self.topology_evidence_state,
                    self.seed_evidence_state,
                    self.health_evidence_state,
                    self.capacity_evidence_state,
                )
            )
            or self.next_authorization_state != _UNAVAILABLE
            or self.next_execution_state != _UNAVAILABLE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError(
                "post-scylla-configure reconciliation report is invalid"
            )
        for digest in _digest_fields(self):
            validate_digest(
                digest, "post-scylla-configure reconciliation report digest"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "artifact": {
                "digest": self.reconciliation_artifact_digest,
                "state": self.artifact_state.value,
            },
            "bootstrap_boundary": {
                "authorization_state": self.next_authorization_state,
                "blocker_digest": self.bootstrap_blocker_digest,
                "blockers": list(self.bootstrap_blockers),
                "capacity_evidence": self.capacity_evidence_state,
                "empty_cluster_evidence": self.empty_cluster_evidence_state,
                "execution_state": self.next_execution_state,
                "gate": self.next_procedure_gate,
                "gate_state": self.bootstrap_gate_state,
                "health_evidence": self.health_evidence_state,
                "operation_evidence": self.bootstrap_evidence_state,
                "seed_evidence": self.seed_evidence_state,
                "topology_evidence": self.topology_evidence_state,
            },
            "configuration": {
                "changed_count": self.changed_count,
                "configured_count": self.configured_count,
                "evidence_artifact_digest": self.evidence_artifact_digest,
                "evidence_digest": self.evidence_digest,
                "execution_artifact_digest": self.execution_artifact_digest,
                "file_count": self.configuration_file_count,
                "file_set_digest": self.configuration_file_set_digest,
                "intent_digest": self.configuration_intent_digest,
                "no_change_count": self.no_change_count,
                "prohibited_action_count": self.prohibited_action_count,
                "service_safe_count": self.service_safe_count,
                "target_count": self.target_count,
                "target_set_digest": self.target_set_digest,
            },
            "counts": {
                "blocked": self.blocked_count,
                "not_performed": self.not_performed_count,
                "succeeded": self.succeeded_count,
            },
            "effective_plan_digest": self.effective_plan_digest,
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "operation_id": str(self.operation_id),
            "record_digest": self.reconciliation_record_digest,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True, slots=True)
class _ReconciliationContext:
    authorization_context: _AuthorizationContext
    prior: StoredDeployPostScyllaInstallReconciliation
    authorization: StoredDeployScyllaConfigureAuthorization
    execution: StoredDeployScyllaConfigureExecution
    evidence: StoredDeployScyllaConfigureEvidence
    intents: tuple[_DerivedConfigurationIntent, ...]


def reconcile_deploy_scylla_configure(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployPostScyllaConfigureReconciliationReport:
    """Bind exact configuration success and block at missing bootstrap plan."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _validate_original_mapping()
    _refuse_ambiguous_or_later_artifacts(paths, operation_id)
    context = _load_reconciliation_context(paths, operation_id, lock=lock)
    steps = _build_reconciled_steps(context.prior, context.evidence)
    store = DeployPostScyllaConfigureReconciliationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    existing = (
        store.read_locked(
            lock,
            expected_cluster_uuid=context.prior.record.cluster_uuid,
            expected_cluster_name=context.prior.record.cluster_name,
        )
        if store.path.exists()
        else None
    )
    record = _build_record(
        context,
        steps=steps,
        created_at=None if existing is None else existing.record.created_at,
    )
    stored, state = store.write_locked(record, lock=lock)
    return _build_report(stored, state=state)


def deploy_post_scylla_configure_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the canonical operation-bound reconciliation path."""

    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "post-scylla-configure reconciliation path is not canonical"
        )
    return path


def deploy_post_scylla_configure_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_FILENAME_SUFFIX):
        return None
    value = name[: -len(DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_FILENAME_SUFFIX)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _load_reconciliation_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
) -> _ReconciliationContext:
    authorization_context = _load_authorization_context(paths, operation_id, lock=lock)
    prior = authorization_context.reconciliation
    loaded = _loaded(authorization_context)
    metadata = loaded.planning.base.deploy.metadata.record
    authorization_store = DeployScyllaConfigureAuthorizationStore(paths, operation_id)
    execution_store = DeployScyllaConfigureExecutionStore(paths, operation_id)
    evidence_store = DeployScyllaConfigureEvidenceStore(paths, operation_id)
    for path, label in (
        (authorization_store.path, "authorization"),
        (execution_store.path, "execution"),
        (evidence_store.path, "evidence"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"post-scylla-configure reconciliation requires complete {label}"
            )
    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    intents = _derive_configuration_intents(
        authorization_context, paths=paths, lock=lock
    )
    expected_authorization = _build_authorization(
        authorization_context,
        scopes=tuple(intent.scope for intent in intents),
        proof=authorization.record.proof,
        created_at=authorization.record.created_at,
    )
    if authorization.record != expected_authorization:
        raise StateConflictError(
            "post-scylla-configure authorization or canonical intent drifted"
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
    context = _ReconciliationContext(
        authorization_context,
        prior,
        authorization,
        execution,
        evidence,
        intents,
    )
    _validate_complete_configuration(context)
    return context


def _validate_complete_configuration(context: _ReconciliationContext) -> None:
    authorization = context.authorization.record
    execution = context.execution.record
    evidence = context.evidence.record
    binding = execution.binding
    scopes = authorization.scopes
    attempts = execution.attempts
    entries = evidence.entries
    stable_ids = tuple(intent.target_ids[0] for intent in context.intents)
    loaded = _loaded(context.authorization_context)
    planning = loaded.planning
    deploy = planning.base.deploy
    trust = planning.base.trust
    readiness = planning.readiness
    if (
        authorization.consumed
        or authorization.authorization_state != "authorized-pre-execution"
        or authorization.execution_state != _UNAVAILABLE
        or execution.state is not DeployScyllaConfigureExecutionState.SUCCEEDED
        or not execution.all_scopes_completed
        or execution.manual_recovery_required
        or not execution.authorization_consumed
        or execution.invocation_count != len(scopes)
        or len(attempts) != len(scopes)
        or len(entries) != len(scopes)
        or len(context.intents) != len(scopes)
        or not scopes
        or stable_ids != tuple(sorted(set(stable_ids)))
        or evidence.binding != binding
        or binding.scope_count != len(scopes)
        or binding.stable_id_count != len(stable_ids)
        or binding.stable_id_set_digest != _digest_object(list(stable_ids))
    ):
        raise StateConflictError(
            "post-scylla-configure reconciliation requires exact terminal success"
        )
    if (
        binding.cluster_uuid != authorization.cluster_uuid
        or binding.cluster_name != context.prior.record.cluster_name
        or binding.operation_id != authorization.operation_id
        or binding.request_digest != authorization.request_digest
        or binding.authorization_artifact_digest
        != context.authorization.artifact_digest
        or binding.authorization_digest != authorization.authorization_digest
        or binding.authorization_scope_digest
        != authorization.authorization_scope_digest
        or binding.authorization_proof_digest != authorization.proof.proof_digest
        or binding.configuration_intent_digest
        != authorization.configuration_intent_digest
        or binding.post_install_reconciliation_artifact_digest
        != context.prior.artifact_digest
        or binding.post_install_reconciliation_record_digest
        != context.prior.record.record_digest
        or binding.install_execution_artifact_digest
        != context.authorization_context.install.execution.artifact_digest
        or binding.install_evidence_artifact_digest
        != context.authorization_context.install.evidence.artifact_digest
    ):
        raise StateConflictError(
            "post-scylla-configure authorization or prior reconciliation drifted"
        )
    if (
        deploy.journal.record.generation != binding.journal_generation
        or deploy.journal.digest != binding.journal_digest
        or deploy.journal.record.status is not JournalStatus.IN_PROGRESS
        or deploy.journal.record.phase is not OperationPhase.VERIFY
        or deploy.observation.record.generation != binding.observation_generation
        or deploy.observation.digest != binding.observation_artifact_digest
        or deploy.observation.record.manifest_digest
        != binding.observation_manifest_digest
        or deploy.inventory.record.generation != binding.inventory_generation
        or deploy.inventory.digest != binding.inventory_artifact_digest
        or deploy.inventory.record.inventory_digest != binding.inventory_digest
        or trust.record.generation != binding.trust_generation
        or trust.digest != binding.trust_artifact_digest
        or trust.record.entries_digest != binding.trust_entries_digest
        or readiness.artifact_digest != binding.readiness_artifact_digest
        or readiness.record.record_digest != binding.readiness_record_digest
        or readiness.record.playbook_version != binding.toolchain_version
        or readiness.record.inventory_version != binding.toolchain_version
        or readiness.record.executable_identity_digest
        != binding.executable_identity_digest
        or readiness.record.toolchain_evidence_digest
        != binding.toolchain_evidence_digest
        or loaded.catalog_digest != binding.catalog_digest
        or loaded.source.version != binding.source_version
        or loaded.source.digest != binding.source_digest
    ):
        raise StateConflictError(
            "post-scylla-configure current inventory, trust, readiness, source, "
            "catalog, or journal binding drifted"
        )

    seen: set[str] = set()
    scope_values: list[dict[str, object]] = []
    for index, (scope, intent, attempt, entry) in enumerate(
        zip(scopes, context.intents, attempts, entries, strict=True),
        start=1,
    ):
        stable_id = intent.target_ids[0]
        expected_scope_digest = _digest_object(scope.to_object())
        if (
            stable_id in seen
            or intent.scope != scope
            or attempt.attempt_index != index
            or attempt.step_sequence != scope.sequence
            or attempt.stable_id != stable_id
            or attempt.target_digest != scope.target_digest
            or attempt.authorization_scope_digest != expected_scope_digest
            or attempt.authorization_variables_digest != scope.variables_digest
            or attempt.authorization_command_digest != scope.command_digest
            or attempt.variables_digest != intent.variables_digest
            or attempt.command_digest != intent.command_digest
            or attempt.source_digest != intent.source_digest
            or attempt.configuration_intent_digest != scope.configuration_intent_digest
            or attempt.state is not DeployScyllaConfigureExecutionState.SUCCEEDED
            or attempt.manual_recovery_required
            or attempt.result_digest is None
            or attempt.evidence_digest is None
            or entry.attempt_index != index
            or entry.step_sequence != scope.sequence
            or entry.stable_id != stable_id
            or entry.variables_digest != attempt.variables_digest
            or entry.command_digest != attempt.command_digest
            or entry.source_digest != attempt.source_digest
            or entry.result_digest != attempt.result_digest
            or entry.evidence_digest != attempt.evidence_digest
        ):
            raise StateConflictError(
                "post-scylla-configure execution/evidence scope conflicts"
            )
        seen.add(stable_id)
        _validate_entry(entry, intent)
        scope_values.append(
            {
                "attempt_index": index,
                "authorization_command_digest": (attempt.authorization_command_digest),
                "authorization_scope_digest": expected_scope_digest,
                "authorization_variables_digest": (
                    attempt.authorization_variables_digest
                ),
                "command_digest": attempt.command_digest,
                "configuration_intent_digest": (attempt.configuration_intent_digest),
                "source_digest": attempt.source_digest,
                "target_digest": attempt.target_digest,
                "variables_digest": attempt.variables_digest,
            }
        )
    if seen != set(stable_ids) or binding.execution_scope_digest != _digest_object(
        scope_values
    ):
        raise StateConflictError(
            "post-scylla-configure complete semantic evidence conflicts"
        )


def _validate_entry(
    entry: DeployScyllaConfigureEvidenceEntry,
    intent: _DerivedConfigurationIntent,
) -> None:
    scope = intent.scope
    variables = dict(intent.variables)
    payload = _mapping(
        variables["deploy_scylla_vms_scylla_configure"],
        "scylla-configure payload",
    )
    topology = _mapping(payload["topology"], "scylla-configure topology")
    provenance = _mapping(payload["provenance"], "scylla-configure provenance")
    expected_result_digest = _digest_object(
        {
            "config_digest": entry.rendered_config_digest,
            "installed_version_digest": entry.package_version_digest,
            "logical_id": entry.stable_id,
            "prerequisite_digest": entry.provenance_digest,
            "runtime_validation_performed": entry.runtime_validation_performed,
            "seed_digest": entry.seed_policy_digest,
            "service_inactive": entry.service_inactive,
            "service_masked": entry.service_masked,
            "status": entry.status.value,
            "topology_digest": entry.topology_digest,
        }
    )
    if (
        not entry.configured
        or entry.changed != (entry.status.value == "changed")
        or entry.release_line_digest != _digest_object(SCYLLA_RELEASE_LINE)
        or entry.package_version_digest != _digest_object(SCYLLA_PACKAGE_VERSION)
        or entry.configuration_file_count != len(_CONFIGURATION_FILE_NAMES)
        or entry.configuration_file_set_digest
        != _digest_object(list(_CONFIGURATION_FILE_NAMES))
        or not entry.files_root_owned
        or not entry.files_mode_0644
        or entry.cluster_name_digest != scope.cluster_name_digest
        or entry.datacenter_digest != scope.datacenter_digest
        or entry.rack_digest != scope.rack_digest
        or entry.private_identity_digest != scope.private_identity_digest
        or entry.seed_count != scope.seed_count
        or entry.seed_policy_digest != scope.seed_policy_digest
        or entry.directory_count != scope.directory_count
        or entry.directory_policy_digest != scope.directory_policy_digest
        or entry.directory_policy_digest
        != _digest_object(list(SCYLLA_CONFIGURE_DIRECTORIES))
        or entry.template_count != scope.template_count
        or entry.template_source_digest != scope.template_source_digest
        or entry.rendered_config_digest != scope.rendered_config_digest
        or entry.topology_digest != _digest_object(dict(topology))
        or entry.role_source_digest != scope.role_source_digest
        or entry.playbook_source_digest != scope.playbook_source_digest
        or entry.configuration_intent_digest != scope.configuration_intent_digest
        or not entry.service_masked
        or not entry.service_inactive
        or entry.runtime_validation_performed
        or entry.package_install_performed
        or entry.storage_mutation_performed
        or entry.tuning_performed
        or entry.firewall_operation_performed
        or entry.ssh_operation_performed
        or entry.manager_operation_performed
        or entry.service_started
        or entry.bootstrap_performed
        or entry.manual_recovery_required
        or entry.automatic_retry_allowed
        or entry.provenance_digest != _digest_object(dict(provenance))
        or entry.variables_digest != intent.variables_digest
        or entry.command_digest != intent.command_digest
        or entry.source_digest != intent.source_digest
        or entry.result_digest != expected_result_digest
        or payload["config_digest"] != entry.rendered_config_digest
        or payload["seed_digest"] != entry.seed_policy_digest
        or payload["package_version"] != SCYLLA_PACKAGE_VERSION
        or payload["release_line"] != SCYLLA_RELEASE_LINE
    ):
        raise StateConflictError(
            "post-scylla-configure configuration or safety evidence conflicts"
        )


def _build_reconciled_steps(
    prior: StoredDeployPostScyllaInstallReconciliation,
    evidence: StoredDeployScyllaConfigureEvidence,
) -> tuple[DeployBaseOsReconciledStep, ...]:
    entries = {entry.stable_id: entry for entry in evidence.record.entries}
    if len(entries) != len(evidence.record.entries) or tuple(entries) != tuple(
        sorted(entries)
    ):
        raise StateConflictError(
            "post-scylla-configure evidence membership or order conflicts"
        )
    configured: set[str] = set()
    result: list[DeployBaseOsReconciledStep] = []
    for step in prior.record.steps:
        prior_digest = _digest_object(step.to_object())
        if (
            step.mapping_sequence == _CONFIGURE_MAPPING
            and step.condition_state is DeployConditionState.ACTIVE
        ):
            stable_id = step.target_ids[0] if len(step.target_ids) == 1 else ""
            entry = entries.get(stable_id)
            if (
                step.playbook != _CONFIGURE_PLAYBOOK
                or step.status
                is not DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
                or step.evidence_state
                is not DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED
                or entry is None
                or step.source_digest != entry.source_digest
            ):
                raise StateConflictError(
                    "post-scylla-configure executed plan scope drifted"
                )
            configured.add(stable_id)
            result.append(
                replace(
                    step,
                    prior_reconciled_step_digest=prior_digest,
                    status=DeployBaseOsReconciledStepStatus.SUCCEEDED,
                    evidence_state=(
                        DeployBaseOsReconciledEvidenceState.SCYLLA_CONFIGURE_BOUND
                    ),
                    evidence_digest=entry.evidence_digest,
                    blockers=(),
                )
            )
            continue
        if step.mapping_sequence > _CONFIGURE_MAPPING and step.status in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }:
            raise StateConflictError(
                "post-scylla-configure refuses health, agent, or later gate leapfrog"
            )
        result.append(replace(step, prior_reconciled_step_digest=prior_digest))
    if configured != set(entries):
        raise StateConflictError("post-scylla-configure configured scope is incomplete")
    return tuple(result)


def _build_record(
    context: _ReconciliationContext,
    *,
    steps: tuple[DeployBaseOsReconciledStep, ...],
    created_at: str | None,
) -> DeployPostScyllaConfigureReconciliation:
    prior = context.prior.record
    authorization = context.authorization.record
    execution = context.execution.record
    binding = execution.binding
    entries = context.evidence.record.entries
    counts = Counter(step.status for step in steps)
    prohibited = sum(
        entry.runtime_validation_performed
        or entry.package_install_performed
        or entry.storage_mutation_performed
        or entry.tuning_performed
        or entry.firewall_operation_performed
        or entry.ssh_operation_performed
        or entry.manager_operation_performed
        or entry.service_started
        or entry.bootstrap_performed
        or entry.manual_recovery_required
        or entry.automatic_retry_allowed
        for entry in entries
    )
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at or format_timestamp(datetime.now(UTC)),
        "cluster_uuid": prior.cluster_uuid,
        "cluster_name": prior.cluster_name,
        "operation_id": prior.operation_id,
        "operation": prior.operation,
        "request_digest": prior.request_digest,
        "journal_generation": prior.journal_generation,
        "journal_digest": prior.journal_digest,
        "journal_status": prior.journal_status,
        "journal_phase": prior.journal_phase,
        "prior_reconciliation_artifact_digest": context.prior.artifact_digest,
        "prior_reconciliation_record_digest": prior.record_digest,
        "prior_effective_plan_digest": prior.effective_plan_digest,
        "authorization_artifact_digest": context.authorization.artifact_digest,
        "authorization_digest": authorization.authorization_digest,
        "authorization_scope_digest": authorization.authorization_scope_digest,
        "authorization_proof_digest": authorization.proof.proof_digest,
        "configuration_intent_digest": authorization.configuration_intent_digest,
        "execution_artifact_digest": context.execution.artifact_digest,
        "execution_binding_digest": binding.binding_digest,
        "execution_generation": execution.generation,
        "evidence_artifact_digest": context.evidence.artifact_digest,
        "evidence_digest": _digest_object([entry.evidence_digest for entry in entries]),
        "result_digest": _digest_object([entry.result_digest for entry in entries]),
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
        "playbook_source_digest": binding.playbook_source_digest,
        "toolchain_version": binding.toolchain_version,
        "executable_identity_digest": binding.executable_identity_digest,
        "toolchain_evidence_digest": binding.toolchain_evidence_digest,
        "release_line_digest": _digest_object(SCYLLA_RELEASE_LINE),
        "package_version_digest": _digest_object(SCYLLA_PACKAGE_VERSION),
        "target_count": len(entries),
        "target_set_digest": _digest_object([entry.stable_id for entry in entries]),
        "configured_count": sum(entry.configured for entry in entries),
        "changed_count": sum(entry.changed for entry in entries),
        "no_change_count": sum(not entry.changed for entry in entries),
        "configuration_file_count": sum(
            entry.configuration_file_count for entry in entries
        ),
        "configuration_file_set_digest": _digest_object(
            [entry.configuration_file_set_digest for entry in entries]
        ),
        "root_owned_count": sum(entry.files_root_owned for entry in entries),
        "mode_0644_count": sum(entry.files_mode_0644 for entry in entries),
        "service_safe_count": sum(
            entry.service_masked and entry.service_inactive for entry in entries
        ),
        "prohibited_action_count": prohibited,
        "topology_digest": _digest_object([entry.topology_digest for entry in entries]),
        "seed_policy_digest": _digest_object(
            [entry.seed_policy_digest for entry in entries]
        ),
        "directory_policy_digest": _digest_object(
            [entry.directory_policy_digest for entry in entries]
        ),
        "original_mapping_count": len(OPERATION_PLAYBOOKS[_OPERATION]),
        "original_mapping_digest": _mapping_digest(),
        "steps": steps,
        "step_count": len(steps),
        "succeeded_count": counts[DeployBaseOsReconciledStepStatus.SUCCEEDED],
        "authorization_required_count": counts[
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        ],
        "eligible_count": counts[DeployBaseOsReconciledStepStatus.ELIGIBLE],
        "blocked_count": counts[DeployBaseOsReconciledStepStatus.BLOCKED],
        "not_performed_count": counts[DeployBaseOsReconciledStepStatus.NOT_PERFORMED],
        "effective_plan_digest": _digest_object([step.to_object() for step in steps]),
        "next_procedure_gate": _BOOTSTRAP_PLAYBOOK,
        "bootstrap_in_original_mapping": False,
        "bootstrap_gate_state": _BLOCKED,
        "bootstrap_blockers": _BOOTSTRAP_BLOCKERS,
        "bootstrap_blocker_digest": _digest_object(list(_BOOTSTRAP_BLOCKERS)),
        "bootstrap_evidence_state": _NOT_PERFORMED,
        "empty_cluster_evidence_state": _NOT_PERFORMED,
        "topology_evidence_state": _NOT_PERFORMED,
        "seed_evidence_state": _NOT_PERFORMED,
        "health_evidence_state": _NOT_PERFORMED,
        "capacity_evidence_state": _NOT_PERFORMED,
        "next_authorization_state": _UNAVAILABLE,
        "next_execution_state": _UNAVAILABLE,
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(values)
    return DeployPostScyllaConfigureReconciliation(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployPostScyllaConfigureReconciliation,
    *,
    state: DeployPostScyllaConfigureArtifactState,
) -> DeployPostScyllaConfigureReconciliationReport:
    record = stored.record
    return DeployPostScyllaConfigureReconciliationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        reconciliation_artifact_digest=stored.artifact_digest,
        reconciliation_record_digest=record.record_digest,
        effective_plan_digest=record.effective_plan_digest,
        execution_artifact_digest=record.execution_artifact_digest,
        evidence_artifact_digest=record.evidence_artifact_digest,
        evidence_digest=record.evidence_digest,
        configuration_intent_digest=record.configuration_intent_digest,
        target_count=record.target_count,
        target_set_digest=record.target_set_digest,
        configured_count=record.configured_count,
        changed_count=record.changed_count,
        no_change_count=record.no_change_count,
        configuration_file_count=record.configuration_file_count,
        configuration_file_set_digest=record.configuration_file_set_digest,
        service_safe_count=record.service_safe_count,
        prohibited_action_count=record.prohibited_action_count,
        succeeded_count=record.succeeded_count,
        blocked_count=record.blocked_count,
        not_performed_count=record.not_performed_count,
        next_procedure_gate=record.next_procedure_gate,
        bootstrap_gate_state=record.bootstrap_gate_state,
        bootstrap_blockers=record.bootstrap_blockers,
        bootstrap_blocker_digest=record.bootstrap_blocker_digest,
        bootstrap_evidence_state=record.bootstrap_evidence_state,
        empty_cluster_evidence_state=record.empty_cluster_evidence_state,
        topology_evidence_state=record.topology_evidence_state,
        seed_evidence_state=record.seed_evidence_state,
        health_evidence_state=record.health_evidence_state,
        capacity_evidence_state=record.capacity_evidence_state,
        next_authorization_state=record.next_authorization_state,
        next_execution_state=record.next_execution_state,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
    )


def _validate_original_mapping() -> None:
    mapping = OPERATION_PLAYBOOKS[_OPERATION]
    if (
        len(mapping) != _ORIGINAL_MAPPING_COUNT
        or any(item.playbook == _BOOTSTRAP_PLAYBOOK for item in mapping)
        or mapping[_CONFIGURE_MAPPING - 1].playbook != _CONFIGURE_PLAYBOOK
        or mapping[_CONFIGURE_MAPPING].playbook != "scylla-health"
    ):
        raise StateConflictError(
            "post-scylla-configure requires the immutable original deploy mapping"
        )


def _mapping_digest() -> str:
    return _digest_object(
        [
            {
                "condition": item.condition,
                "mapping_sequence": index,
                "playbook": item.playbook,
            }
            for index, item in enumerate(OPERATION_PLAYBOOKS[_OPERATION], start=1)
        ]
    )


def _record_digest(record: DeployPostScyllaConfigureReconciliation) -> str:
    return _record_digest_from_object(record.to_object())


def _record_digest_from_values(values: Mapping[str, object]) -> str:
    result: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployPostScyllaConfigureReconciliation.__dataclass_fields__.items():
        if name.endswith("schema_version"):
            continue
        value = values.get(name, field.default)
        result[name] = (
            [item.to_object() for item in value]
            if name == "steps" and isinstance(value, tuple)
            else list(value)
            if name == "bootstrap_blockers" and isinstance(value, tuple)
            else value.value
            if isinstance(value, StrEnum)
            else str(value)
            if isinstance(value, uuid.UUID)
            else value
        )
    result["record_digest"] = ""
    return _digest_object(result)


def _record_digest_from_object(value: Mapping[str, object]) -> str:
    result = {
        name: item
        for name, item in value.items()
        if not name.endswith("schema_version")
    }
    result["record_digest"] = ""
    return _digest_object(result)


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "post-scylla-configure reconciliation paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "post-scylla-configure reconciliation requires the matching held "
            "deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_or_later_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    canonical = (
        f"{operation_id}{DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_FILENAME_SUFFIX}"
    )
    prefix = f"{operation_id}."
    later_fragments = (
        ".ansible-deploy-scylla-bootstrap",
        ".ansible-deploy-bootstrap-context",
        ".ansible-deploy-bootstrap-plan",
        ".ansible-deploy-scylla-health",
        ".ansible-deploy-manager-agent",
        ".ansible-deploy-monitoring-agent",
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list post-scylla-configure operation history"
        ) from error
    for entry in entries:
        if (
            entry.name.startswith(prefix)
            and "post-scylla-configure-reconciliation" in entry.name
            and entry.name != canonical
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "post-scylla-configure reconciliation artifacts are ambiguous"
            )
        if entry.name.startswith(prefix) and any(
            fragment in entry.name for fragment in later_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "post-scylla-configure reconciliation refuses unreviewed "
                "bootstrap or later-stage history"
            )


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


def _nonnegative_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StatePersistenceError(f"{label} must be non-negative")


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
        raise StatePersistenceError(f"{label} is invalid") from error


__all__ = [
    "ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_SCHEMA_VERSION",
    "DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_FILENAME_SUFFIX",
    "DeployPostScyllaConfigureArtifactState",
    "DeployPostScyllaConfigureReconciliation",
    "DeployPostScyllaConfigureReconciliationReport",
    "DeployPostScyllaConfigureReconciliationStore",
    "StoredDeployPostScyllaConfigureReconciliation",
    "deploy_post_scylla_configure_reconciliation_id_from_filename",
    "deploy_post_scylla_configure_reconciliation_path",
    "reconcile_deploy_scylla_configure",
]
