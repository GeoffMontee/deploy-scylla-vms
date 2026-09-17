"""Immutable deploy reconciliation after exact ``scylla-install`` execution.

This subprocess-free owner revalidates the complete canonical deploy chain,
requires certain terminal package-install evidence for every authorized Scylla
target, and advances only the immediate ``scylla-configure`` authorization
gate.  It never authorizes or executes work and never changes the common
operation journal or any earlier artifact.
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
from scylla_vms.ansible.deploy_non_jump_base_os_execution import (
    DeployNonJumpBaseOsEvidenceStore,
)
from scylla_vms.ansible.deploy_plan import (
    DeployConditionState,
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_scylla_install_authorization import (
    ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_SCHEMA_VERSION,
    DeployScyllaInstallAuthorizationStore,
    DeployScyllaInstallPackageProvenance,
    StoredDeployScyllaInstallAuthorization,
    _AuthorizationContext,
    _build_authorization,
    _derive_authorization_scopes,
    _derive_package_provenance,
    _load_authorization_context,
)
from scylla_vms.ansible.deploy_scylla_install_execution import (
    ANSIBLE_DEPLOY_SCYLLA_INSTALL_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_SCHEMA_VERSION,
    DeployScyllaInstallEvidenceEntry,
    DeployScyllaInstallEvidenceStore,
    DeployScyllaInstallExecutionState,
    DeployScyllaInstallExecutionStore,
    StoredDeployScyllaInstallEvidence,
    StoredDeployScyllaInstallExecution,
)
from scylla_vms.ansible.deploy_storage_postcheck import (
    ANSIBLE_DEPLOY_POST_STORAGE_POSTCHECK_RECONCILIATION_SCHEMA_VERSION,
    StoredDeployPostStoragePostcheckReconciliation,
)
from scylla_vms.ansible.registry import OPERATION_PLAYBOOKS, CheckMode, get_playbook
from scylla_vms.ansible.scylla_install import (
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_PACKAGES,
    SCYLLA_RELEASE_LINE,
    SCYLLA_REPOSITORY_DEFINITION_DIGEST,
    SCYLLA_SIGNING_KEY_DIGEST,
    ScyllaInstallStatus,
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

ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-scylla-install-reconciliation/v1"
)
ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-scylla-install-reconciliation-report/v1"
)
DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-post-scylla-install-reconciliation.json"
)

_OPERATION = "deploy"
_INSTALL_PLAYBOOK = "scylla-install"
_CONFIGURE_PLAYBOOK = "scylla-configure"
_INSTALL_MAPPING = 11
_CONFIGURE_MAPPING = 12
_FINAL_EVIDENCE_MAPPING = len(OPERATION_PLAYBOOKS[_OPERATION])
_AUTHORIZATION_BLOCKER = "deploy-authorization-not-collected"
_CLASS_BLOCKER = "mutating-deploy-execution-unavailable"
_PUBLIC_WORKFLOW_BLOCKER = "public-deploy-workflow-unavailable"
_NOT_STARTED = "not-started"
_UNAVAILABLE = "unavailable"


class DeployPostScyllaInstallArtifactState(StrEnum):
    """Immutable reconciliation persistence result."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployPostScyllaInstallReconciliation:
    """Address-free effective-plan checkpoint after package installation."""

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
    release_line: str
    package_version: str
    package_count: int
    package_set_digest: str
    package_provenance_digest: str
    repository_definition_digest: str
    signing_key_artifact_digest: str
    target_count: int
    target_set_digest: str
    installed_count: int
    changed_count: int
    no_change_count: int
    service_safe_count: int
    prohibited_action_count: int
    steps: tuple[DeployBaseOsReconciledStep, ...]
    step_count: int
    succeeded_count: int
    authorization_required_count: int
    eligible_count: int
    blocked_count: int
    not_performed_count: int
    next_playbook: str
    next_target_count: int
    next_target_set_digest: str
    effective_plan_digest: str
    next_execution_state: str
    finalization_state: str
    public_workflow_state: str
    record_digest: str
    prior_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_POSTCHECK_RECONCILIATION_SCHEMA_VERSION
    )
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_SCHEMA_VERSION
    )
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_INSTALL_EVIDENCE_SCHEMA_VERSION
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_SCHEMA_VERSION
            or self.prior_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_POSTCHECK_RECONCILIATION_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_INSTALL_AUTHORIZATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_INSTALL_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_INSTALL_EVIDENCE_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.release_line != SCYLLA_RELEASE_LINE
            or self.package_version != SCYLLA_PACKAGE_VERSION
            or self.package_count != len(SCYLLA_PACKAGES)
            or self.target_count < 1
            or self.installed_count != self.target_count
            or self.changed_count + self.no_change_count != self.target_count
            or self.service_safe_count != self.target_count
            or self.prohibited_action_count
            or self.next_playbook != _CONFIGURE_PLAYBOOK
            or self.next_target_count != self.target_count
            or self.next_execution_state != _NOT_STARTED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
        ):
            raise StatePersistenceError(
                "post-scylla-install reconciliation identity is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for value in (
            self.journal_generation,
            self.execution_generation,
            self.inventory_generation,
            self.trust_generation,
            self.package_count,
            self.target_count,
            self.installed_count,
            self.changed_count,
            self.no_change_count,
            self.service_safe_count,
            self.prohibited_action_count,
            self.step_count,
            self.succeeded_count,
            self.authorization_required_count,
            self.eligible_count,
            self.blocked_count,
            self.not_performed_count,
            self.next_target_count,
        ):
            _nonnegative_integer(value, "post-scylla-install reconciliation count")
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
                "post-scylla-install reconciliation counts conflict"
            )
        mapping = OPERATION_PLAYBOOKS[_OPERATION]
        if {step.mapping_sequence for step in self.steps} != set(
            range(1, len(mapping) + 1)
        ) or any(
            step.playbook != mapping[step.mapping_sequence - 1].playbook
            or step.condition != mapping[step.mapping_sequence - 1].condition
            for step in self.steps
        ):
            raise StatePersistenceError(
                "post-scylla-install reconciliation mapping conflicts"
            )
        counts = Counter(step.status for step in self.steps)
        next_targets = sorted(
            target
            for step in self.steps
            if step.playbook == self.next_playbook
            and step.status
            is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            for target in step.target_ids
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
            or len(next_targets) != self.next_target_count
            or self.next_target_set_digest != _digest_object(next_targets)
            or self.effective_plan_digest
            != _digest_object([step.to_object() for step in self.steps])
            or self.record_digest != _record_digest(self)
        ):
            raise StatePersistenceError(
                "post-scylla-install reconciliation summary conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "post-scylla-install reconciliation digest")

    def to_object(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            result[name] = (
                [item.to_object() for item in value]
                if name == "steps"
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
    ) -> DeployPostScyllaInstallReconciliation:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "post-scylla-install reconciliation",
        )
        integer_fields = {
            "generation",
            "journal_generation",
            "execution_generation",
            "inventory_generation",
            "trust_generation",
            "package_count",
            "target_count",
            "installed_count",
            "changed_count",
            "no_change_count",
            "service_safe_count",
            "prohibited_action_count",
            "step_count",
            "succeeded_count",
            "authorization_required_count",
            "eligible_count",
            "blocked_count",
            "not_performed_count",
            "next_target_count",
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
                    DeployBaseOsReconciledStep.from_object(_mapping(entry, "step"))
                    for entry in _array(item, "steps")
                )
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployPostScyllaInstallReconciliation:
    record: DeployPostScyllaInstallReconciliation
    artifact_digest: str


class DeployPostScyllaInstallReconciliationStore:
    """Owner-only immutable reconciliation store."""

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
        self._path = deploy_post_scylla_install_reconciliation_path(paths, operation_id)
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
    ) -> StoredDeployPostScyllaInstallReconciliation:
        value, artifact_digest = self._file.read()
        record = DeployPostScyllaInstallReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "post-scylla-install reconciliation identity conflicts"
            )
        return StoredDeployPostScyllaInstallReconciliation(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPostScyllaInstallReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployPostScyllaInstallReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployPostScyllaInstallReconciliation,
        DeployPostScyllaInstallArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "post-scylla-install reconciliation operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "post-scylla-install reconciliation is immutable"
                )
            return current, DeployPostScyllaInstallArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployPostScyllaInstallReconciliation(record, digest),
            DeployPostScyllaInstallArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployPostScyllaInstallReconciliationReport:
    """Strict count-and-digest-only reconciliation projection."""

    operation_id: uuid.UUID
    artifact_state: DeployPostScyllaInstallArtifactState
    reconciliation_artifact_digest: str
    reconciliation_record_digest: str
    effective_plan_digest: str
    execution_artifact_digest: str
    evidence_artifact_digest: str
    evidence_digest: str
    package_provenance_digest: str
    target_count: int
    target_set_digest: str
    installed_count: int
    changed_count: int
    no_change_count: int
    service_safe_count: int
    prohibited_action_count: int
    succeeded_count: int
    authorization_required_count: int
    eligible_count: int
    blocked_count: int
    not_performed_count: int
    next_playbook: str
    next_target_count: int
    next_target_set_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_REPORT_SCHEMA_VERSION
            or self.target_count < 1
            or self.installed_count != self.target_count
            or self.changed_count + self.no_change_count != self.target_count
            or self.service_safe_count != self.target_count
            or self.prohibited_action_count
            or self.next_playbook != _CONFIGURE_PLAYBOOK
            or self.next_target_count != self.target_count
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError(
                "post-scylla-install reconciliation report is invalid"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "post-scylla-install reconciliation report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "artifact": {
                "digest": self.reconciliation_artifact_digest,
                "state": self.artifact_state.value,
            },
            "counts": {
                "authorization_required": self.authorization_required_count,
                "blocked": self.blocked_count,
                "eligible": self.eligible_count,
                "not_performed": self.not_performed_count,
                "succeeded": self.succeeded_count,
            },
            "effective_plan_digest": self.effective_plan_digest,
            "install": {
                "changed_count": self.changed_count,
                "evidence_artifact_digest": self.evidence_artifact_digest,
                "evidence_digest": self.evidence_digest,
                "execution_artifact_digest": self.execution_artifact_digest,
                "installed_count": self.installed_count,
                "no_change_count": self.no_change_count,
                "package_provenance_digest": self.package_provenance_digest,
                "prohibited_action_count": self.prohibited_action_count,
                "service_safe_count": self.service_safe_count,
                "target_count": self.target_count,
                "target_set_digest": self.target_set_digest,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "next_gate": {
                "playbook": self.next_playbook,
                "target_count": self.next_target_count,
                "target_set_digest": self.next_target_set_digest,
            },
            "operation_id": str(self.operation_id),
            "record_digest": self.reconciliation_record_digest,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True, slots=True)
class _ReconciliationContext:
    authorization_context: _AuthorizationContext
    prior: StoredDeployPostStoragePostcheckReconciliation
    authorization: StoredDeployScyllaInstallAuthorization
    execution: StoredDeployScyllaInstallExecution
    evidence: StoredDeployScyllaInstallEvidence


def reconcile_deploy_scylla_install(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployPostScyllaInstallReconciliationReport:
    """Persist exact post-install evidence and expose only configure approval."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_or_later_artifacts(paths, operation_id)
    context = _load_reconciliation_context(paths, operation_id, lock=lock)
    loaded = context.authorization_context.post.authorization_context.preflight.discovery.post.chain.authorization_context.final_routes.post.post.base.host.loaded
    steps = _build_reconciled_steps(
        context.prior,
        context.evidence,
        configure_source_digest=_playbook_source_digest(
            loaded.source, _CONFIGURE_PLAYBOOK
        ),
    )
    store = DeployPostScyllaInstallReconciliationStore(paths, operation_id)
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


def deploy_post_scylla_install_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the canonical operation-bound reconciliation path."""

    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "post-scylla-install reconciliation path is not canonical"
        )
    return path


def deploy_post_scylla_install_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_FILENAME_SUFFIX):
        return None
    value = name[: -len(DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_FILENAME_SUFFIX)]
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
    metadata = authorization_context.post.authorization_context.preflight.metadata
    authorization_store = DeployScyllaInstallAuthorizationStore(paths, operation_id)
    execution_store = DeployScyllaInstallExecutionStore(paths, operation_id)
    evidence_store = DeployScyllaInstallEvidenceStore(paths, operation_id)
    for path, label in (
        (authorization_store.path, "authorization"),
        (execution_store.path, "execution"),
        (evidence_store.path, "evidence"),
    ):
        validate_state_file(path, allow_missing=True)
        if not path.exists():
            raise StateConflictError(
                f"post-scylla-install reconciliation requires complete {label}"
            )
    authorization = authorization_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    package_provenance = _derive_package_provenance()
    scopes = _derive_authorization_scopes(authorization_context, package_provenance)
    expected_authorization = _build_authorization(
        authorization_context,
        scopes=scopes,
        package_provenance=package_provenance,
        proof=authorization.record.proof,
        created_at=authorization.record.created_at,
    )
    if authorization.record != expected_authorization:
        raise StateConflictError(
            "post-scylla-install authorization or prior plan drifted"
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
    )
    _validate_complete_install(context, paths, lock=lock)
    return context


def _validate_complete_install(
    context: _ReconciliationContext,
    paths: StatePaths,
    *,
    lock: ClusterLock,
) -> None:
    authorization = context.authorization.record
    execution = context.execution.record
    evidence = context.evidence.record
    binding = execution.binding
    entries = evidence.entries
    attempts = execution.attempts
    scopes = authorization.scopes
    stable_ids = tuple(scope.target_ids[0] for scope in scopes)
    loaded = context.authorization_context.post.authorization_context.preflight.discovery.post.chain.authorization_context.final_routes.post.post.base.host.loaded
    planning = loaded.planning
    deploy = planning.base.deploy
    trust = planning.base.trust
    readiness = planning.readiness
    if (
        authorization.consumed
        or authorization.authorization_state != "authorized-pre-execution"
        or authorization.execution_state != _UNAVAILABLE
        or execution.state is not DeployScyllaInstallExecutionState.SUCCEEDED
        or not execution.all_scopes_completed
        or execution.manual_recovery_required
        or not execution.authorization_consumed
        or execution.invocation_count != len(scopes)
        or len(attempts) != len(scopes)
        or len(entries) != len(scopes)
        or not scopes
        or stable_ids != tuple(sorted(set(stable_ids)))
        or evidence.binding != binding
        or binding.scope_count != len(scopes)
        or binding.stable_id_count != len(stable_ids)
        or binding.stable_id_set_digest != _digest_object(list(stable_ids))
    ):
        raise StateConflictError(
            "post-scylla-install reconciliation requires exact terminal success"
        )
    if (
        binding.cluster_uuid != authorization.cluster_uuid
        or binding.cluster_name != authorization.cluster_name
        or binding.operation_id != authorization.operation_id
        or binding.request_digest != authorization.request_digest
        or binding.authorization_artifact_digest
        != context.authorization.artifact_digest
        or binding.authorization_digest != authorization.authorization_digest
        or binding.authorization_scope_digest
        != authorization.authorization_scope_digest
        or binding.authorization_proof_digest != authorization.proof.proof_digest
        or binding.postcheck_reconciliation_artifact_digest
        != context.prior.artifact_digest
        or binding.postcheck_reconciliation_record_digest
        != context.prior.record.record_digest
        or binding.postcheck_evidence_artifact_digest
        != context.authorization_context.evidence.artifact_digest
        or binding.postcheck_evidence_digest != context.prior.record.evidence_digest
        or binding.package_provenance_digest
        != authorization.package_provenance.provenance_digest
    ):
        raise StateConflictError(
            "post-scylla-install authorization or storage provenance drifted"
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
        or _playbook_source_digest(loaded.source, _INSTALL_PLAYBOOK)
        != binding.playbook_source_digest
    ):
        raise StateConflictError(
            "post-scylla-install current inventory, trust, readiness, source, "
            "catalog, or journal binding drifted"
        )
    base_store = DeployNonJumpBaseOsEvidenceStore(paths, authorization.operation_id)
    validate_state_file(base_store.path, allow_missing=True)
    if not base_store.path.exists():
        raise StateConflictError(
            "post-scylla-install current base-os evidence is unavailable"
        )
    base_evidence = base_store.read_locked(
        lock,
        expected_cluster_uuid=authorization.cluster_uuid,
        expected_cluster_name=authorization.cluster_name,
    )
    base_entry_digests = tuple(
        entry.evidence_digest
        for entry in base_evidence.record.entries
        if any(host.logical_id in stable_ids for host in entry.hosts)
    )
    if (
        not base_entry_digests
        or base_evidence.artifact_digest != binding.base_os_evidence_artifact_digest
        or _digest_object(list(base_entry_digests)) != binding.base_os_evidence_digest
    ):
        raise StateConflictError("post-scylla-install current base-os evidence drifted")
    scope_values: list[dict[str, object]] = []
    prohibited = 0
    seen: set[str] = set()
    for index, (scope, attempt, entry) in enumerate(
        zip(scopes, attempts, entries, strict=True),
        start=1,
    ):
        stable_id = scope.target_ids[0]
        if stable_id in seen:
            raise StateConflictError(
                "post-scylla-install duplicate target evidence conflicts"
            )
        seen.add(stable_id)
        expected_scope_digest = _digest_object(scope.to_object())
        if (
            scope.mapping_sequence != _INSTALL_MAPPING
            or scope.playbook != _INSTALL_PLAYBOOK
            or scope.classification is not OperationClassification.MUTATING
            or scope.target_role != HostRole.SCYLLA.value
            or len(scope.target_ids) != 1
            or scope.package_provenance_digest
            != authorization.package_provenance.provenance_digest
            or attempt.attempt_index != index
            or attempt.step_sequence != scope.sequence
            or attempt.stable_id != stable_id
            or attempt.target_digest != scope.target_digest
            or attempt.authorization_scope_digest != expected_scope_digest
            or attempt.authorization_variables_digest != scope.variables_digest
            or attempt.authorization_command_digest != scope.command_digest
            or attempt.source_digest != scope.source_digest
            or attempt.package_version != SCYLLA_PACKAGE_VERSION
            or attempt.package_provenance_digest
            != authorization.package_provenance.provenance_digest
            or attempt.state is not DeployScyllaInstallExecutionState.SUCCEEDED
            or attempt.manual_recovery_required
            or attempt.result_digest is None
            or attempt.evidence_digest is None
            or entry.attempt_index != index
            or entry.step_sequence != scope.sequence
            or entry.stable_id != stable_id
            or entry.source_digest != attempt.source_digest
            or entry.variables_digest != attempt.variables_digest
            or entry.command_digest != attempt.command_digest
            or entry.result_digest != attempt.result_digest
            or entry.evidence_digest != attempt.evidence_digest
        ):
            raise StateConflictError(
                "post-scylla-install execution/evidence scope conflicts"
            )
        _validate_entry(entry, authorization.package_provenance)
        prohibited += (
            entry.configuration_performed
            or entry.storage_mutation_performed
            or entry.tuning_performed
            or entry.manager_operation_performed
            or entry.service_started
        )
        scope_values.append(
            {
                "attempt_index": index,
                "authorization_command_digest": (attempt.authorization_command_digest),
                "authorization_scope_digest": expected_scope_digest,
                "authorization_variables_digest": (
                    attempt.authorization_variables_digest
                ),
                "command_digest": attempt.command_digest,
                "source_digest": attempt.source_digest,
                "target_digest": attempt.target_digest,
                "variables_digest": attempt.variables_digest,
            }
        )
    if (
        seen != set(stable_ids)
        or prohibited
        or binding.execution_scope_digest != _digest_object(scope_values)
    ):
        raise StateConflictError(
            "post-scylla-install complete semantic evidence conflicts"
        )


def _validate_entry(
    entry: DeployScyllaInstallEvidenceEntry,
    package_provenance: DeployScyllaInstallPackageProvenance,
) -> None:
    if (
        entry.status
        not in {ScyllaInstallStatus.INSTALLED, ScyllaInstallStatus.NO_CHANGE}
        or not entry.installed
        or entry.changed != (entry.status is ScyllaInstallStatus.INSTALLED)
        or entry.package_version != SCYLLA_PACKAGE_VERSION
        or entry.package_count != len(SCYLLA_PACKAGES)
        or entry.package_set_digest != _digest_object(list(SCYLLA_PACKAGES))
        or entry.repository_definition_digest != SCYLLA_REPOSITORY_DEFINITION_DIGEST
        or entry.signing_key_artifact_digest != SCYLLA_SIGNING_KEY_DIGEST
        or entry.signing_key_identity_digest
        != package_provenance.signing_key_identity_digest
        or not entry.service_masked
        or not entry.service_inactive
        or entry.configuration_performed
        or entry.storage_mutation_performed
        or entry.tuning_performed
        or entry.manager_operation_performed
        or entry.service_started
        or entry.manual_recovery_required
        or entry.automatic_retry_allowed
    ):
        raise StateConflictError(
            "post-scylla-install package or service safety evidence conflicts"
        )


def _build_reconciled_steps(
    prior: StoredDeployPostStoragePostcheckReconciliation,
    evidence: StoredDeployScyllaInstallEvidence,
    *,
    configure_source_digest: str,
) -> tuple[DeployBaseOsReconciledStep, ...]:
    entries = {entry.stable_id: entry for entry in evidence.record.entries}
    if len(entries) != len(evidence.record.entries) or tuple(entries) != tuple(
        sorted(entries)
    ):
        raise StateConflictError(
            "post-scylla-install evidence membership or order conflicts"
        )
    definition = get_playbook(_CONFIGURE_PLAYBOOK)
    if (
        definition.classification is not OperationClassification.MUTATING
        or definition.hosts != HostRole.SCYLLA.value
        or definition.serial != 1
        or definition.check_mode is not CheckMode.PREVIEW
        or not definition.source_available
    ):
        raise StateConflictError(
            "post-scylla-install configure catalog policy conflicts"
        )
    result: list[DeployBaseOsReconciledStep] = []
    installed: set[str] = set()
    configure_targets: set[str] = set()
    configure_started = False
    for step in prior.record.steps:
        prior_digest = _digest_object(step.to_object())
        if (
            step.mapping_sequence == _INSTALL_MAPPING
            and step.condition_state is DeployConditionState.ACTIVE
        ):
            stable_id = step.target_ids[0] if len(step.target_ids) == 1 else ""
            entry = entries.get(stable_id)
            if (
                step.playbook != _INSTALL_PLAYBOOK
                or step.status
                is not DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
                or entry is None
                or step.source_digest != entry.source_digest
            ):
                raise StateConflictError(
                    "post-scylla-install executed plan scope drifted"
                )
            installed.add(stable_id)
            result.append(
                replace(
                    step,
                    prior_reconciled_step_digest=prior_digest,
                    status=DeployBaseOsReconciledStepStatus.SUCCEEDED,
                    evidence_state=(
                        DeployBaseOsReconciledEvidenceState.SCYLLA_INSTALL_BOUND
                    ),
                    evidence_digest=entry.evidence_digest,
                    blockers=(),
                )
            )
            continue
        if (
            step.mapping_sequence == _CONFIGURE_MAPPING
            and step.condition_state is DeployConditionState.ACTIVE
        ):
            if (
                step.playbook != _CONFIGURE_PLAYBOOK
                or step.status
                not in {
                    DeployBaseOsReconciledStepStatus.BLOCKED,
                    DeployBaseOsReconciledStepStatus.NOT_PERFORMED,
                }
                or len(step.target_ids) != 1
                or set(step.target_ids) - set(entries)
                or step.source_digest != configure_source_digest
            ):
                raise StateConflictError(
                    "post-scylla-install immediate configure gate conflicts"
                )
            configure_started = True
            stable_id = step.target_ids[0]
            configure_targets.add(stable_id)
            result.append(
                replace(
                    step,
                    prior_reconciled_step_digest=prior_digest,
                    status=(
                        DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
                    ),
                    evidence_state=(
                        DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED
                    ),
                    evidence_digest=_digest_object(
                        {
                            "install_evidence_digest": (
                                entries[stable_id].evidence_digest
                            ),
                            "install_provenance_digest": (
                                entries[stable_id].provenance_digest
                            ),
                            "playbook": step.playbook,
                            "prior_reconciliation_record_digest": (
                                prior.record.record_digest
                            ),
                            "step_digest": prior_digest,
                        }
                    ),
                    blockers=(
                        _AUTHORIZATION_BLOCKER,
                        _CLASS_BLOCKER,
                        _PUBLIC_WORKFLOW_BLOCKER,
                    ),
                )
            )
            continue
        if step.mapping_sequence > _CONFIGURE_MAPPING and step.status in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }:
            raise StateConflictError(
                "post-scylla-install refuses bootstrap, agent, health, or later "
                "gate leapfrog"
            )
        if step.mapping_sequence == _FINAL_EVIDENCE_MAPPING and (
            step.playbook != "evidence-collect"
            or step.status is not DeployBaseOsReconciledStepStatus.NOT_PERFORMED
        ):
            raise StateConflictError(
                "post-scylla-install final evidence gate conflicts"
            )
        result.append(replace(step, prior_reconciled_step_digest=prior_digest))
    if (
        not configure_started
        or installed != set(entries)
        or configure_targets != set(entries)
    ):
        raise StateConflictError(
            "post-scylla-install scope or immediate next gate is incomplete"
        )
    return tuple(result)


def _build_record(
    context: _ReconciliationContext,
    *,
    steps: tuple[DeployBaseOsReconciledStep, ...],
    created_at: str | None,
) -> DeployPostScyllaInstallReconciliation:
    prior = context.prior.record
    authorization = context.authorization.record
    execution = context.execution.record
    evidence = context.evidence.record
    binding = execution.binding
    entries = evidence.entries
    counts = Counter(step.status for step in steps)
    next_targets = sorted(
        target
        for step in steps
        if step.playbook == _CONFIGURE_PLAYBOOK
        and step.status
        is DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        for target in step.target_ids
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
        "release_line": authorization.package_provenance.release_line,
        "package_version": authorization.package_provenance.package_version,
        "package_count": authorization.package_provenance.package_count,
        "package_set_digest": authorization.package_provenance.package_set_digest,
        "package_provenance_digest": (
            authorization.package_provenance.provenance_digest
        ),
        "repository_definition_digest": (
            authorization.package_provenance.repository_definition_digest
        ),
        "signing_key_artifact_digest": (
            authorization.package_provenance.signing_key_artifact_digest
        ),
        "target_count": len(entries),
        "target_set_digest": _digest_object([entry.stable_id for entry in entries]),
        "installed_count": sum(entry.installed for entry in entries),
        "changed_count": sum(entry.changed for entry in entries),
        "no_change_count": sum(not entry.changed for entry in entries),
        "service_safe_count": sum(
            entry.service_masked and entry.service_inactive for entry in entries
        ),
        "prohibited_action_count": sum(
            entry.configuration_performed
            or entry.storage_mutation_performed
            or entry.tuning_performed
            or entry.manager_operation_performed
            or entry.service_started
            for entry in entries
        ),
        "steps": steps,
        "step_count": len(steps),
        "succeeded_count": counts[DeployBaseOsReconciledStepStatus.SUCCEEDED],
        "authorization_required_count": counts[
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        ],
        "eligible_count": counts[DeployBaseOsReconciledStepStatus.ELIGIBLE],
        "blocked_count": counts[DeployBaseOsReconciledStepStatus.BLOCKED],
        "not_performed_count": counts[DeployBaseOsReconciledStepStatus.NOT_PERFORMED],
        "next_playbook": _CONFIGURE_PLAYBOOK,
        "next_target_count": len(next_targets),
        "next_target_set_digest": _digest_object(next_targets),
        "effective_plan_digest": _digest_object([step.to_object() for step in steps]),
        "next_execution_state": _NOT_STARTED,
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(values)
    return DeployPostScyllaInstallReconciliation(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployPostScyllaInstallReconciliation,
    *,
    state: DeployPostScyllaInstallArtifactState,
) -> DeployPostScyllaInstallReconciliationReport:
    record = stored.record
    return DeployPostScyllaInstallReconciliationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        reconciliation_artifact_digest=stored.artifact_digest,
        reconciliation_record_digest=record.record_digest,
        effective_plan_digest=record.effective_plan_digest,
        execution_artifact_digest=record.execution_artifact_digest,
        evidence_artifact_digest=record.evidence_artifact_digest,
        evidence_digest=record.evidence_digest,
        package_provenance_digest=record.package_provenance_digest,
        target_count=record.target_count,
        target_set_digest=record.target_set_digest,
        installed_count=record.installed_count,
        changed_count=record.changed_count,
        no_change_count=record.no_change_count,
        service_safe_count=record.service_safe_count,
        prohibited_action_count=record.prohibited_action_count,
        succeeded_count=record.succeeded_count,
        authorization_required_count=record.authorization_required_count,
        eligible_count=record.eligible_count,
        blocked_count=record.blocked_count,
        not_performed_count=record.not_performed_count,
        next_playbook=record.next_playbook,
        next_target_count=record.next_target_count,
        next_target_set_digest=record.next_target_set_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
    )


def _record_digest(record: DeployPostScyllaInstallReconciliation) -> str:
    return _record_digest_from_object(record.to_object())


def _record_digest_from_values(values: Mapping[str, object]) -> str:
    result: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployPostScyllaInstallReconciliation.__dataclass_fields__.items():
        if name.endswith("schema_version"):
            continue
        value = values.get(name, field.default)
        result[name] = (
            [item.to_object() for item in value]
            if name == "steps" and isinstance(value, tuple)
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
            "post-scylla-install reconciliation paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "post-scylla-install reconciliation requires the matching held deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_or_later_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    canonical = (
        f"{operation_id}{DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_FILENAME_SUFFIX}"
    )
    prefix = f"{operation_id}."
    later_fragments = (
        ".ansible-deploy-scylla-configure",
        ".ansible-deploy-scylla-bootstrap",
        ".ansible-deploy-manager-agent",
        ".ansible-deploy-scylla-health",
    )
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list post-scylla-install operation history"
        ) from error
    for entry in entries:
        if (
            entry.name.startswith(prefix)
            and "post-scylla-install-reconciliation" in entry.name
            and entry.name != canonical
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "post-scylla-install reconciliation artifacts are ambiguous"
            )
        if entry.name.startswith(prefix) and any(
            fragment in entry.name for fragment in later_fragments
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "post-scylla-install reconciliation refuses later-stage history"
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
    "ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_SCHEMA_VERSION",
    "DEPLOY_POST_SCYLLA_INSTALL_RECONCILIATION_FILENAME_SUFFIX",
    "DeployPostScyllaInstallArtifactState",
    "DeployPostScyllaInstallReconciliation",
    "DeployPostScyllaInstallReconciliationReport",
    "DeployPostScyllaInstallReconciliationStore",
    "StoredDeployPostScyllaInstallReconciliation",
    "deploy_post_scylla_install_reconciliation_id_from_filename",
    "deploy_post_scylla_install_reconciliation_path",
    "reconcile_deploy_scylla_install",
]
