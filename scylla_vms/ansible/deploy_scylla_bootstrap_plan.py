"""Deploy-only Scylla bootstrap context and ordered plan binding.

The historical deploy plan is immutable and omits ``scylla-bootstrap``.  This
subprocess-free owner creates a separate, operation-bound context and plan after
exact Scylla configuration success.  It derives targets, order, modes, seeds,
topology, and prerequisites only from canonical state, persists only redacted
digests/counts, and never authorizes or executes bootstrap.
"""

from __future__ import annotations

import os
import uuid
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import Field, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from scylla_vms.ansible.deploy_plan import (
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.deploy_scylla_configure_authorization import (
    _loaded,
)
from scylla_vms.ansible.deploy_scylla_configure_execution import (
    DeployScyllaConfigureEvidenceEntry,
)
from scylla_vms.ansible.deploy_scylla_configure_reconciliation import (
    ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_SCHEMA_VERSION,
    DeployPostScyllaConfigureReconciliationStore,
    StoredDeployPostScyllaConfigureReconciliation,
    _build_reconciled_steps,
    _load_reconciliation_context,
    _mapping_digest,
)
from scylla_vms.ansible.deploy_scylla_configure_reconciliation import (
    _build_record as _build_post_configure_record,
)
from scylla_vms.ansible.deploy_scylla_install_execution import (
    DeployScyllaInstallEvidenceEntry,
)
from scylla_vms.ansible.deploy_storage_postcheck import (
    DeployStoragePostcheckEvidenceEntry,
)
from scylla_vms.ansible.registry import OPERATION_PLAYBOOKS
from scylla_vms.ansible.scylla_bootstrap import ScyllaBootstrapMode
from scylla_vms.ansible.scylla_configure import (
    SeedSelectionMode,
    select_scylla_seeds,
)
from scylla_vms.ansible.scylla_install import SCYLLA_PACKAGE_VERSION
from scylla_vms.desired import HostRole
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.inventory import StoredInventoryRecord
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
from scylla_vms.terraform.apply_verification import (
    TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION,
    TerraformObservationWriteState,
    TerraformStateProgression,
)
from scylla_vms.terraform.plan import (
    TerraformPlanChangeClass,
    TerraformPlanDriftClass,
    TerraformStatePresence,
)

ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_NEW_CLUSTER_PROOF_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-bootstrap-new-cluster-proof/v1"
)
ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-bootstrap-context/v1"
)
ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-bootstrap-plan/v1"
)
ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-scylla-bootstrap-plan-report/v1"
)
DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-bootstrap-context.json"
)
DEPLOY_SCYLLA_BOOTSTRAP_PLAN_FILENAME_SUFFIX = (
    ".ansible-deploy-scylla-bootstrap-plan.json"
)

_OPERATION = "deploy"
_PLAYBOOK = "scylla-bootstrap"
_ORIGINAL_MAPPING_COUNT = 21
_EXPECTED_HOST_ID_STATE = "unknown-before-start"
_EMPTY_PROVEN = "proven-empty-new-cluster"
_EMPTY_BLOCKED = "blocked"
_AUTHORIZATION_REQUIRED = "authorization-required"
_AUTHORIZATION_UNAVAILABLE = "unavailable"
_EXECUTION_UNAVAILABLE = "unavailable"
_NOT_STARTED = "not-started"
_PUBLIC_WORKFLOW_UNAVAILABLE = "unavailable"
_INITIAL_HEALTH_CHECKPOINT = "not-required-before-initial-seed"
_JOIN_HEALTH_CHECKPOINT = "waiting-for-preceding-complete-health"
_INITIAL_AUTHORIZATION_BLOCKER = "bootstrap-authorization-not-collected"
_JOIN_BLOCKERS = (
    "preceding-bootstrap-not-performed",
    "complete-cluster-health-not-performed",
    "healthy-survivor-evidence-not-performed",
    "target-absence-not-proven",
    "capacity-evidence-not-performed",
    "schema-agreement-not-performed",
    _INITIAL_AUTHORIZATION_BLOCKER,
)
_MEMBERSHIP_ARTIFACT_FRAGMENTS = (
    ".ansible-deploy-scylla-bootstrap-authorization",
    ".ansible-deploy-scylla-bootstrap-execution",
    ".ansible-deploy-scylla-bootstrap-evidence",
    ".ansible-deploy-scylla-health",
    ".ansible-scylla-bootstrap",
    ".ansible-scylla-health",
    ".ansible-scylla-remove",
    ".ansible-scylla-replace",
    ".ansible-scylla-repair",
    ".ansible-scylla-cleanup",
)


class DeployScyllaBootstrapProofState(StrEnum):
    """Closed normalized state for one reviewed caller-owned fact."""

    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"


class DeployScyllaBootstrapArtifactState(StrEnum):
    """Immutable context/plan persistence result."""

    CREATED = "created"
    REUSED = "reused"


class DeployScyllaBootstrapStepStatus(StrEnum):
    """Planning status without authorization or execution."""

    AUTHORIZATION_REQUIRED = "authorization-required"
    BLOCKED = "blocked"
    WAITING_FOR_HEALTH_CHECKPOINT = "waiting-for-health-checkpoint"


@dataclass(frozen=True, slots=True)
class DeployScyllaBootstrapNewClusterProof:
    """Normalized reviewed facts that cannot be inferred from local artifacts."""

    new_cluster_intent: DeployScyllaBootstrapProofState
    empty_cluster_review: DeployScyllaBootstrapProofState
    prior_membership_absence: DeployScyllaBootstrapProofState
    capacity_sufficiency: DeployScyllaBootstrapProofState
    schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_NEW_CLUSTER_PROOF_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_NEW_CLUSTER_PROOF_SCHEMA_VERSION
            or any(
                not isinstance(value, DeployScyllaBootstrapProofState)
                for value in (
                    self.new_cluster_intent,
                    self.empty_cluster_review,
                    self.prior_membership_absence,
                    self.capacity_sufficiency,
                )
            )
        ):
            raise StateConflictError(
                "deploy Scylla bootstrap new-cluster proof is malformed"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "capacity_sufficiency": self.capacity_sufficiency.value,
            "empty_cluster_review": self.empty_cluster_review.value,
            "new_cluster_intent": self.new_cluster_intent.value,
            "prior_membership_absence": self.prior_membership_absence.value,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True, slots=True)
class _EmptyClusterFacts:
    terraform_initial_state_proven: bool
    terraform_create_only: bool
    terraform_drift_free: bool
    terraform_initial_progression: bool
    services_masked_inactive: bool
    services_never_started: bool
    topology_complete: bool
    seed_policy_complete: bool
    storage_capacity_complete: bool
    prior_membership_artifacts_absent: bool


@dataclass(frozen=True, slots=True)
class _BootstrapTarget:
    """Protected in-memory target projection; stable IDs are never persisted."""

    stable_id: str
    datacenter: str
    rack: str
    target_digest: str
    datacenter_digest: str
    rack_digest: str
    package_version_digest: str
    storage_evidence_digest: str
    configuration_evidence_digest: str
    topology_digest: str
    seed_policy_digest: str
    capacity_evidence_digest: str
    playbook_source_digest: str
    is_configured_seed: bool


@dataclass(frozen=True, slots=True)
class DeployScyllaBootstrapContext:
    """Value-free proof boundary for a new empty-cluster bootstrap."""

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
    post_configure_artifact_digest: str
    post_configure_record_digest: str
    post_configure_effective_plan_digest: str
    terraform_verification_artifact_digest: str
    terraform_verification_record_digest: str
    terraform_safeguard_digest: str
    terraform_pre_apply_state: TerraformStatePresence
    terraform_plan_change_class: TerraformPlanChangeClass
    terraform_plan_drift_class: TerraformPlanDriftClass
    terraform_state_progression: TerraformStateProgression
    observation_artifact_digest: str
    observation_manifest_digest: str
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    trust_generation: int
    trust_artifact_digest: str
    trust_entries_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    storage_evidence_artifact_digest: str
    storage_evidence_digest: str
    install_evidence_artifact_digest: str
    install_evidence_digest: str
    configure_evidence_artifact_digest: str
    configure_evidence_digest: str
    catalog_digest: str
    ansible_source_digest: str
    playbook_source_digest: str
    target_count: int
    target_set_digest: str
    order_digest: str
    topology_count: int
    topology_digest: str
    seed_count: int
    seed_policy_digest: str
    capacity_evidence_count: int
    capacity_evidence_digest: str
    service_safe_count: int
    service_never_started_count: int
    expected_host_id_unknown_count: int
    proof_collected: bool
    proof_new_cluster_intent: DeployScyllaBootstrapProofState
    proof_empty_cluster_review: DeployScyllaBootstrapProofState
    proof_prior_membership_absence: DeployScyllaBootstrapProofState
    proof_capacity_sufficiency: DeployScyllaBootstrapProofState
    proof_digest: str
    empty_cluster_state: str
    blockers: tuple[str, ...]
    blocker_digest: str
    authorization_state: str
    execution_state: str
    public_workflow_state: str
    record_digest: str
    post_configure_schema_version: str = (
        ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_SCHEMA_VERSION
    )
    terraform_verification_schema_version: str = (
        TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION
    )
    proof_schema_version: str = (
        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_NEW_CLUSTER_PROOF_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION
            or self.post_configure_schema_version
            != ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_SCHEMA_VERSION
            or self.terraform_verification_schema_version
            != TERRAFORM_APPLY_VERIFICATION_SCHEMA_VERSION
            or self.proof_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_NEW_CLUSTER_PROOF_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.target_count < 1
            or self.topology_count != self.target_count
            or self.capacity_evidence_count != self.target_count
            or self.service_safe_count != self.target_count
            or self.service_never_started_count != self.target_count
            or self.expected_host_id_unknown_count != self.target_count
            or self.seed_count != 1
            or self.empty_cluster_state
            != (_EMPTY_PROVEN if not self.blockers else _EMPTY_BLOCKED)
            or self.blocker_digest != _digest_object(list(self.blockers))
            or tuple(sorted(set(self.blockers))) != self.blockers
            or self.authorization_state != _AUTHORIZATION_UNAVAILABLE
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
            or self.record_digest != _context_record_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap context identity or summary conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for value in (
            self.journal_generation,
            self.inventory_generation,
            self.trust_generation,
            self.target_count,
            self.topology_count,
            self.seed_count,
            self.capacity_evidence_count,
            self.service_safe_count,
            self.service_never_started_count,
            self.expected_host_id_unknown_count,
        ):
            _positive_integer(value, "deploy Scylla bootstrap context count")
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy Scylla bootstrap context digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, tuple_fields={"blockers"})

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaBootstrapContext:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Scylla bootstrap context",
        )
        integers = {
            "generation",
            "journal_generation",
            "inventory_generation",
            "trust_generation",
            "target_count",
            "topology_count",
            "seed_count",
            "capacity_evidence_count",
            "service_safe_count",
            "service_never_started_count",
            "expected_host_id_unknown_count",
        }
        enums: dict[str, type[StrEnum]] = {
            "journal_status": JournalStatus,
            "journal_phase": OperationPhase,
            "terraform_pre_apply_state": TerraformStatePresence,
            "terraform_plan_change_class": TerraformPlanChangeClass,
            "terraform_plan_drift_class": TerraformPlanDriftClass,
            "terraform_state_progression": TerraformStateProgression,
            "proof_new_cluster_intent": DeployScyllaBootstrapProofState,
            "proof_empty_cluster_review": DeployScyllaBootstrapProofState,
            "proof_prior_membership_absence": DeployScyllaBootstrapProofState,
            "proof_capacity_sufficiency": DeployScyllaBootstrapProofState,
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in integers:
                    parsed[name] = _integer(item, name)
                elif name == "proof_collected":
                    parsed[name] = _boolean(item, name)
                elif name in {"cluster_uuid", "operation_id"}:
                    parsed[name] = parse_uuid(require_string(value, name), name)
                elif name == "blockers":
                    parsed[name] = _string_tuple(item, name)
                elif name in enums:
                    parsed[name] = enums[name](require_string(value, name))
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Scylla bootstrap context enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaBootstrapContext:
    record: DeployScyllaBootstrapContext
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class DeployScyllaBootstrapPlanStep:
    """One redacted serial-one bootstrap intent."""

    sequence: int
    mode: ScyllaBootstrapMode
    target_digest: str
    expected_host_id_state: str
    datacenter_digest: str
    rack_digest: str
    package_version_digest: str
    storage_evidence_digest: str
    configuration_evidence_digest: str
    topology_digest: str
    seed_policy_digest: str
    capacity_evidence_digest: str
    playbook_source_digest: str
    preceding_step_digest: str | None
    prerequisite_digest: str
    status: DeployScyllaBootstrapStepStatus
    health_checkpoint_state: str
    blockers: tuple[str, ...]
    blocker_digest: str
    step_digest: str

    def __post_init__(self) -> None:
        if (
            self.sequence < 1
            or not isinstance(self.mode, ScyllaBootstrapMode)
            or self.expected_host_id_state != _EXPECTED_HOST_ID_STATE
            or tuple(sorted(set(self.blockers))) != self.blockers
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.step_digest != _step_digest(self)
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap plan step identity conflicts"
            )
        if self.sequence == 1:
            if (
                self.mode is not ScyllaBootstrapMode.INITIAL_SEED
                or self.preceding_step_digest is not None
                or self.health_checkpoint_state != _INITIAL_HEALTH_CHECKPOINT
                or self.status
                is DeployScyllaBootstrapStepStatus.WAITING_FOR_HEALTH_CHECKPOINT
            ):
                raise StatePersistenceError(
                    "deploy Scylla initial-seed plan step conflicts"
                )
        elif (
            self.mode is not ScyllaBootstrapMode.JOIN_EXISTING
            or self.preceding_step_digest is None
            or self.health_checkpoint_state != _JOIN_HEALTH_CHECKPOINT
            or self.status
            is not DeployScyllaBootstrapStepStatus.WAITING_FOR_HEALTH_CHECKPOINT
            or self.blockers != tuple(sorted(_JOIN_BLOCKERS))
        ):
            raise StatePersistenceError(
                "deploy Scylla join-existing plan step conflicts"
            )
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy Scylla bootstrap plan step digest")
        if self.preceding_step_digest is not None:
            validate_digest(
                self.preceding_step_digest,
                "deploy Scylla bootstrap preceding-step digest",
            )

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(
            self,
            tuple_fields={"blockers"},
            optional_fields={"preceding_step_digest"},
        )

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaBootstrapPlanStep:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Scylla bootstrap plan step",
        )
        preceding = value["preceding_step_digest"]
        if preceding is not None and not isinstance(preceding, str):
            raise StatePersistenceError(
                "deploy Scylla bootstrap preceding step digest is invalid"
            )
        try:
            return cls(
                sequence=_integer(value["sequence"], "sequence"),
                mode=ScyllaBootstrapMode(require_string(value, "mode")),
                target_digest=require_string(value, "target_digest"),
                expected_host_id_state=require_string(value, "expected_host_id_state"),
                datacenter_digest=require_string(value, "datacenter_digest"),
                rack_digest=require_string(value, "rack_digest"),
                package_version_digest=require_string(value, "package_version_digest"),
                storage_evidence_digest=require_string(
                    value, "storage_evidence_digest"
                ),
                configuration_evidence_digest=require_string(
                    value, "configuration_evidence_digest"
                ),
                topology_digest=require_string(value, "topology_digest"),
                seed_policy_digest=require_string(value, "seed_policy_digest"),
                capacity_evidence_digest=require_string(
                    value, "capacity_evidence_digest"
                ),
                playbook_source_digest=require_string(value, "playbook_source_digest"),
                preceding_step_digest=preceding,
                prerequisite_digest=require_string(value, "prerequisite_digest"),
                status=DeployScyllaBootstrapStepStatus(require_string(value, "status")),
                health_checkpoint_state=require_string(
                    value, "health_checkpoint_state"
                ),
                blockers=_string_tuple(value["blockers"], "blockers"),
                blocker_digest=require_string(value, "blocker_digest"),
                step_digest=require_string(value, "step_digest"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Scylla bootstrap plan step enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployScyllaBootstrapPlan:
    """Immutable serial-one bootstrap plan outside the 21-step mapping."""

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
    post_configure_artifact_digest: str
    post_configure_record_digest: str
    original_mapping_count: int
    original_mapping_digest: str
    original_mapping_unchanged: bool
    target_count: int
    target_set_digest: str
    order_digest: str
    serial: int
    steps: tuple[DeployScyllaBootstrapPlanStep, ...]
    step_count: int
    authorization_required_count: int
    blocked_count: int
    waiting_health_count: int
    plan_digest: str
    authorization_state: str
    execution_state: str
    finalization_state: str
    public_workflow_state: str
    context_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION
    post_configure_schema_version: str = (
        ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        counts = Counter(step.status for step in self.steps)
        if (
            self.schema_version != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_SCHEMA_VERSION
            or self.context_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION
            or self.post_configure_schema_version
            != ANSIBLE_DEPLOY_POST_SCYLLA_CONFIGURE_RECONCILIATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.original_mapping_count != _ORIGINAL_MAPPING_COUNT
            or self.original_mapping_digest != _mapping_digest()
            or not self.original_mapping_unchanged
            or self.target_count < 1
            or self.serial != 1
            or self.step_count != self.target_count
            or self.step_count != len(self.steps)
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, self.step_count + 1))
            or self.authorization_required_count
            != counts[DeployScyllaBootstrapStepStatus.AUTHORIZATION_REQUIRED]
            or self.blocked_count != counts[DeployScyllaBootstrapStepStatus.BLOCKED]
            or self.waiting_health_count
            != counts[DeployScyllaBootstrapStepStatus.WAITING_FOR_HEALTH_CHECKPOINT]
            or self.authorization_required_count + self.blocked_count != 1
            or self.waiting_health_count != self.target_count - 1
            or self.plan_digest != _plan_digest(self)
            or self.authorization_state != _AUTHORIZATION_UNAVAILABLE
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap plan identity or summary conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy Scylla bootstrap plan digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self, step_fields={"steps"})

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployScyllaBootstrapPlan:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "deploy Scylla bootstrap plan",
        )
        integers = {
            "generation",
            "journal_generation",
            "original_mapping_count",
            "target_count",
            "serial",
            "step_count",
            "authorization_required_count",
            "blocked_count",
            "waiting_health_count",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in integers:
                    parsed[name] = _integer(item, name)
                elif name == "original_mapping_unchanged":
                    parsed[name] = _boolean(item, name)
                elif name in {"cluster_uuid", "operation_id"}:
                    parsed[name] = parse_uuid(require_string(value, name), name)
                elif name == "journal_status":
                    parsed[name] = JournalStatus(require_string(value, name))
                elif name == "journal_phase":
                    parsed[name] = OperationPhase(require_string(value, name))
                elif name == "steps":
                    parsed[name] = tuple(
                        DeployScyllaBootstrapPlanStep.from_object(
                            _mapping(step, "bootstrap plan step")
                        )
                        for step in _array(item, "bootstrap plan steps")
                    )
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "deploy Scylla bootstrap plan enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployScyllaBootstrapPlan:
    record: DeployScyllaBootstrapPlan
    artifact_digest: str


class DeployScyllaBootstrapContextStore:
    """Owner-only immutable bootstrap-context store."""

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
        self._path = deploy_scylla_bootstrap_context_path(paths, operation_id)
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
    ) -> StoredDeployScyllaBootstrapContext:
        value, digest = self._file.read()
        record = DeployScyllaBootstrapContext.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap context identity conflicts"
            )
        return StoredDeployScyllaBootstrapContext(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaBootstrapContext:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaBootstrapContext,
        *,
        lock: ClusterLock,
    ) -> tuple[StoredDeployScyllaBootstrapContext, DeployScyllaBootstrapArtifactState]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy Scylla bootstrap context operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy Scylla bootstrap context is immutable; use a new operation"
                )
            return current, DeployScyllaBootstrapArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaBootstrapContext(record, digest),
            DeployScyllaBootstrapArtifactState.CREATED,
        )


class DeployScyllaBootstrapPlanStore:
    """Owner-only immutable bootstrap-plan store."""

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
        self._path = deploy_scylla_bootstrap_plan_path(paths, operation_id)
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
    ) -> StoredDeployScyllaBootstrapPlan:
        value, digest = self._file.read()
        record = DeployScyllaBootstrapPlan.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "deploy Scylla bootstrap plan identity conflicts"
            )
        return StoredDeployScyllaBootstrapPlan(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployScyllaBootstrapPlan:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployScyllaBootstrapPlan,
        *,
        lock: ClusterLock,
    ) -> tuple[StoredDeployScyllaBootstrapPlan, DeployScyllaBootstrapArtifactState]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "deploy Scylla bootstrap plan operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "deploy Scylla bootstrap plan is immutable; use a new operation"
                )
            return current, DeployScyllaBootstrapArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployScyllaBootstrapPlan(record, digest),
            DeployScyllaBootstrapArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployScyllaBootstrapPlanReport:
    """Strict digest/count/status-only bootstrap planning projection."""

    operation_id: uuid.UUID
    context_state: DeployScyllaBootstrapArtifactState
    plan_state: DeployScyllaBootstrapArtifactState
    context_artifact_digest: str
    context_record_digest: str
    plan_artifact_digest: str
    plan_digest: str
    proof_digest: str
    empty_cluster_state: str
    blocker_digest: str
    target_count: int
    target_set_digest: str
    order_digest: str
    topology_digest: str
    seed_policy_digest: str
    capacity_evidence_digest: str
    initial_seed_count: int
    join_count: int
    authorization_required_count: int
    blocked_count: int
    waiting_health_count: int
    expected_host_id_unknown_count: int
    journal_status: JournalStatus
    journal_phase: OperationPhase
    authorization_state: str
    execution_state: str
    public_workflow_state: str
    context_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION
    plan_schema_version: str = ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_SCHEMA_VERSION
    schema_version: str = ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_REPORT_SCHEMA_VERSION
            or self.context_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION
            or self.plan_schema_version
            != ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_SCHEMA_VERSION
            or self.target_count < 1
            or self.initial_seed_count != 1
            or self.join_count != self.target_count - 1
            or self.authorization_required_count + self.blocked_count != 1
            or self.waiting_health_count != self.join_count
            or self.expected_host_id_unknown_count != self.target_count
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.authorization_state != _AUTHORIZATION_UNAVAILABLE
            or self.execution_state != _EXECUTION_UNAVAILABLE
            or self.public_workflow_state != _PUBLIC_WORKFLOW_UNAVAILABLE
        ):
            raise StatePersistenceError("deploy Scylla bootstrap plan report conflicts")
        for digest in _digest_fields(self):
            validate_digest(digest, "deploy Scylla bootstrap report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "artifacts": {
                "context_digest": self.context_artifact_digest,
                "context_record_digest": self.context_record_digest,
                "context_state": self.context_state.value,
                "plan_digest": self.plan_artifact_digest,
                "plan_record_digest": self.plan_digest,
                "plan_state": self.plan_state.value,
            },
            "bootstrap": {
                "authorization_required_count": self.authorization_required_count,
                "blocked_count": self.blocked_count,
                "capacity_evidence_digest": self.capacity_evidence_digest,
                "empty_cluster_state": self.empty_cluster_state,
                "expected_host_id_unknown_count": (self.expected_host_id_unknown_count),
                "initial_seed_count": self.initial_seed_count,
                "join_count": self.join_count,
                "order_digest": self.order_digest,
                "seed_policy_digest": self.seed_policy_digest,
                "target_count": self.target_count,
                "target_set_digest": self.target_set_digest,
                "topology_digest": self.topology_digest,
                "waiting_health_count": self.waiting_health_count,
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "operation_id": str(self.operation_id),
            "proof": {
                "blocker_digest": self.blocker_digest,
                "digest": self.proof_digest,
            },
            "schema_version": self.schema_version,
            "states": {
                "authorization": self.authorization_state,
                "execution": self.execution_state,
                "public_workflow": self.public_workflow_state,
            },
        }


@dataclass(frozen=True, slots=True)
class _PlanningContext:
    post_configure: StoredDeployPostScyllaConfigureReconciliation
    targets: tuple[_BootstrapTarget, ...]
    values: Mapping[str, object]


def plan_deploy_scylla_bootstrap(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
    proof: DeployScyllaBootstrapNewClusterProof | None = None,
) -> DeployScyllaBootstrapPlanReport:
    """Persist or reuse the exact separate bootstrap context then plan."""

    if proof is not None and not isinstance(
        proof, DeployScyllaBootstrapNewClusterProof
    ):
        raise StateConflictError(
            "deploy Scylla bootstrap new-cluster proof is malformed"
        )
    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _validate_original_mapping()
    _refuse_ambiguous_or_membership_artifacts(paths, operation_id)

    context_store = DeployScyllaBootstrapContextStore(paths, operation_id)
    plan_store = DeployScyllaBootstrapPlanStore(paths, operation_id)
    for path in (context_store.path, plan_store.path):
        validate_state_file(path, allow_missing=True)
    if plan_store.path.exists() and not context_store.path.exists():
        raise StateConflictError(
            "deploy Scylla bootstrap plan exists without its context"
        )

    loaded = _load_planning_context(paths, operation_id, lock=lock, proof=proof)
    metadata = loaded.post_configure.record
    cluster_uuid = metadata.cluster_uuid
    canonical_cluster_name = metadata.cluster_name
    existing_context = (
        context_store.read_locked(
            lock,
            expected_cluster_uuid=cluster_uuid,
            expected_cluster_name=canonical_cluster_name,
        )
        if context_store.path.exists()
        else None
    )
    context_record = _build_context_record(
        loaded,
        created_at=(
            existing_context.record.created_at
            if existing_context is not None
            else format_timestamp(datetime.now(UTC))
        ),
    )
    stored_context, context_state = context_store.write_locked(
        context_record, lock=lock
    )

    existing_plan = (
        plan_store.read_locked(
            lock,
            expected_cluster_uuid=cluster_uuid,
            expected_cluster_name=canonical_cluster_name,
        )
        if plan_store.path.exists()
        else None
    )
    steps = _build_plan_steps(stored_context.record, loaded.targets)
    plan_record = _build_plan_record(
        stored_context,
        steps=steps,
        created_at=(
            existing_plan.record.created_at
            if existing_plan is not None
            else stored_context.record.created_at
        ),
    )
    stored_plan, plan_state = plan_store.write_locked(plan_record, lock=lock)
    return _build_report(
        stored_context,
        stored_plan,
        context_state=context_state,
        plan_state=plan_state,
    )


def deploy_scylla_bootstrap_context_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Scylla bootstrap context path is not canonical"
        )
    return path


def deploy_scylla_bootstrap_plan_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_SCYLLA_BOOTSTRAP_PLAN_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "deploy Scylla bootstrap plan path is not canonical"
        )
    return path


def deploy_scylla_bootstrap_context_id_from_filename(name: str) -> uuid.UUID | None:
    return _id_from_filename(name, DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_FILENAME_SUFFIX)


def deploy_scylla_bootstrap_plan_id_from_filename(name: str) -> uuid.UUID | None:
    return _id_from_filename(name, DEPLOY_SCYLLA_BOOTSTRAP_PLAN_FILENAME_SUFFIX)


def _load_planning_context(
    paths: StatePaths,
    operation_id: uuid.UUID,
    *,
    lock: ClusterLock,
    proof: DeployScyllaBootstrapNewClusterProof | None,
) -> _PlanningContext:
    chain = _load_reconciliation_context(paths, operation_id, lock=lock)
    post_store = DeployPostScyllaConfigureReconciliationStore(paths, operation_id)
    validate_state_file(post_store.path, allow_missing=True)
    if not post_store.path.exists():
        raise StateConflictError(
            "deploy Scylla bootstrap planning requires post-config reconciliation"
        )
    loaded = _loaded(chain.authorization_context)
    metadata = loaded.planning.base.deploy.metadata.record
    post = post_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_post = _build_post_configure_record(
        chain,
        steps=_build_reconciled_steps(chain.prior, chain.evidence),
        created_at=post.record.created_at,
    )
    if post.record != expected_post:
        raise StateConflictError(
            "deploy Scylla bootstrap post-config chain drifted; use a new operation"
        )

    deploy = loaded.planning.base.deploy
    verification = deploy.verification
    storage = chain.authorization_context.install.authorization_context.evidence
    install = chain.authorization_context.install.evidence
    configure = chain.evidence
    inventory = deploy.inventory
    source_digest = _playbook_source_digest(loaded.source, _PLAYBOOK)
    targets = _derive_targets(
        inventory=inventory,
        storage_entries=storage.record.entries,
        install_entries=install.record.entries,
        configure_entries=configure.record.entries,
        playbook_source_digest=source_digest,
    )
    ordered = _order_targets(targets)
    verification_record = verification.record
    initial_observation = (
        verification_record.observation_write_state
        is TerraformObservationWriteState.INITIAL
        and verification_record.observation_generation == 1
    )
    prior_state_absent = (
        verification_record.pre_apply_state_identity.presence
        is TerraformStatePresence.ABSENT
    )
    facts = _EmptyClusterFacts(
        terraform_initial_state_proven=(
            prior_state_absent
            or (
                verification_record.plan_change_class
                is TerraformPlanChangeClass.CREATE_ONLY
                and initial_observation
            )
        ),
        terraform_create_only=(
            verification_record.plan_change_class
            is TerraformPlanChangeClass.CREATE_ONLY
        ),
        terraform_drift_free=(
            verification_record.plan_drift_class is TerraformPlanDriftClass.NONE
        ),
        terraform_initial_progression=(
            initial_observation
            and (
                (
                    prior_state_absent
                    and verification_record.state_progression
                    is TerraformStateProgression.INITIALIZED
                )
                or (
                    not prior_state_absent
                    and verification_record.state_progression
                    is TerraformStateProgression.ADVANCED
                )
            )
        ),
        services_masked_inactive=all(
            item.service_masked and item.service_inactive
            for item in install.record.entries
        )
        and all(
            item.service_masked and item.service_inactive
            for item in configure.record.entries
        ),
        services_never_started=all(
            not item.service_started for item in install.record.entries
        )
        and all(
            not item.service_started and not item.bootstrap_performed
            for item in configure.record.entries
        ),
        topology_complete=all(
            item.topology_digest and item.datacenter_digest and item.rack_digest
            for item in configure.record.entries
        ),
        seed_policy_complete=(
            len({item.seed_policy_digest for item in configure.record.entries}) == 1
            and all(item.seed_count == 1 for item in configure.record.entries)
        ),
        storage_capacity_complete=all(
            item.readiness_for_scylla
            and item.capacity_bytes > 0
            and not item.failed_check_count
            and not item.unknown_check_count
            and not item.blocker_count
            for item in storage.record.entries
        ),
        prior_membership_artifacts_absent=True,
    )
    blockers = _empty_cluster_blockers(proof, facts)
    proof_states = _proof_states(proof)
    proof_digest = _digest_object(
        {
            "chain": {
                "post_configure_record_digest": post.record.record_digest,
                "target_set_digest": _digest_object(
                    sorted(item.target_digest for item in ordered)
                ),
                "terraform_verification_record_digest": (
                    verification_record.record_digest
                ),
            },
            "proof": (
                proof.to_object()
                if proof is not None
                else {
                    "capacity_sufficiency": DeployScyllaBootstrapProofState.UNKNOWN.value,
                    "empty_cluster_review": DeployScyllaBootstrapProofState.UNKNOWN.value,
                    "new_cluster_intent": DeployScyllaBootstrapProofState.UNKNOWN.value,
                    "prior_membership_absence": DeployScyllaBootstrapProofState.UNKNOWN.value,
                    "schema_version": (
                        ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_NEW_CLUSTER_PROOF_SCHEMA_VERSION
                    ),
                }
            ),
        }
    )
    values: dict[str, object] = {
        "request_digest": post.record.request_digest,
        "journal_generation": post.record.journal_generation,
        "journal_digest": post.record.journal_digest,
        "journal_status": post.record.journal_status,
        "journal_phase": post.record.journal_phase,
        "terraform_verification_artifact_digest": verification.artifact_digest,
        "terraform_verification_record_digest": verification_record.record_digest,
        "terraform_safeguard_digest": verification_record.safeguard_digest,
        "terraform_pre_apply_state": (
            verification_record.pre_apply_state_identity.presence
        ),
        "terraform_plan_change_class": verification_record.plan_change_class,
        "terraform_plan_drift_class": verification_record.plan_drift_class,
        "terraform_state_progression": verification_record.state_progression,
        "observation_artifact_digest": deploy.observation.digest,
        "observation_manifest_digest": deploy.observation.record.manifest_digest,
        "inventory_generation": inventory.record.generation,
        "inventory_artifact_digest": inventory.digest,
        "inventory_digest": inventory.record.inventory_digest,
        "trust_generation": loaded.planning.base.trust.record.generation,
        "trust_artifact_digest": loaded.planning.base.trust.digest,
        "trust_entries_digest": loaded.planning.base.trust.record.entries_digest,
        "readiness_artifact_digest": loaded.planning.readiness.artifact_digest,
        "readiness_record_digest": loaded.planning.readiness.record.record_digest,
        "storage_evidence_artifact_digest": storage.artifact_digest,
        "storage_evidence_digest": _digest_object(
            [item.evidence_digest for item in storage.record.entries]
        ),
        "install_evidence_artifact_digest": install.artifact_digest,
        "install_evidence_digest": _digest_object(
            [item.evidence_digest for item in install.record.entries]
        ),
        "configure_evidence_artifact_digest": configure.artifact_digest,
        "configure_evidence_digest": _digest_object(
            [item.evidence_digest for item in configure.record.entries]
        ),
        "catalog_digest": loaded.catalog_digest,
        "ansible_source_digest": loaded.source.digest,
        "playbook_source_digest": source_digest,
        "target_count": len(ordered),
        "target_set_digest": _digest_object(
            sorted(item.target_digest for item in ordered)
        ),
        "order_digest": _digest_object([item.target_digest for item in ordered]),
        "topology_count": len(ordered),
        "topology_digest": _digest_object(
            [
                {
                    "datacenter_digest": item.datacenter_digest,
                    "rack_digest": item.rack_digest,
                    "target_digest": item.target_digest,
                    "topology_digest": item.topology_digest,
                }
                for item in ordered
            ]
        ),
        "seed_count": 1,
        "seed_policy_digest": _digest_object(
            [item.seed_policy_digest for item in ordered]
        ),
        "capacity_evidence_count": len(ordered),
        "capacity_evidence_digest": _digest_object(
            [item.capacity_evidence_digest for item in ordered]
        ),
        "service_safe_count": len(ordered),
        "service_never_started_count": len(ordered),
        "expected_host_id_unknown_count": len(ordered),
        "proof_collected": proof is not None,
        "proof_new_cluster_intent": proof_states[0],
        "proof_empty_cluster_review": proof_states[1],
        "proof_prior_membership_absence": proof_states[2],
        "proof_capacity_sufficiency": proof_states[3],
        "proof_digest": proof_digest,
        "empty_cluster_state": _EMPTY_PROVEN if not blockers else _EMPTY_BLOCKED,
        "blockers": blockers,
        "blocker_digest": _digest_object(list(blockers)),
    }
    return _PlanningContext(post, ordered, values)


def _derive_targets(
    *,
    inventory: StoredInventoryRecord,
    storage_entries: tuple[DeployStoragePostcheckEvidenceEntry, ...],
    install_entries: tuple[DeployScyllaInstallEvidenceEntry, ...],
    configure_entries: tuple[DeployScyllaConfigureEvidenceEntry, ...],
    playbook_source_digest: str,
) -> tuple[_BootstrapTarget, ...]:
    inventory_record = inventory.record
    hosts = tuple(
        host
        for host in inventory_record.inventory.hosts
        if host.role is HostRole.SCYLLA
    )
    storage = {item.stable_id: item for item in storage_entries}
    install = {item.stable_id: item for item in install_entries}
    configure = {item.stable_id: item for item in configure_entries}
    ids = tuple(host.logical_id for host in hosts)
    if (
        not ids
        or ids != tuple(sorted(set(ids)))
        or set(ids) != set(storage)
        or set(ids) != set(install)
        or set(ids) != set(configure)
        or len(storage) != len(storage_entries)
        or len(install) != len(install_entries)
        or len(configure) != len(configure_entries)
    ):
        raise StateConflictError(
            "deploy Scylla bootstrap target evidence membership conflicts"
        )
    result: list[_BootstrapTarget] = []
    configured_seed_id: str | None = None
    for host in hosts:
        stable_id = host.logical_id
        storage_entry = storage[stable_id]
        install_entry = install[stable_id]
        configure_entry = configure[stable_id]
        policy = select_scylla_seeds(
            inventory,
            mode=SeedSelectionMode.INITIAL,
            target_logical_id=stable_id,
        )
        if (
            len(policy.stable_ids) != 1
            or configure_entry.seed_policy_digest != policy.digest
            or configure_entry.seed_count != 1
            or configure_entry.datacenter_digest
            != _digest_object(host.scylla_datacenter)
            or configure_entry.rack_digest != _digest_object(host.scylla_rack)
            or install_entry.package_version != SCYLLA_PACKAGE_VERSION
            or not install_entry.service_masked
            or not install_entry.service_inactive
            or install_entry.service_started
            or not configure_entry.service_masked
            or not configure_entry.service_inactive
            or configure_entry.service_started
            or configure_entry.bootstrap_performed
            or not storage_entry.readiness_for_scylla
            or storage_entry.capacity_bytes < 1
        ):
            raise StateConflictError(
                "deploy Scylla bootstrap topology, seed, storage, package, "
                "or service evidence conflicts"
            )
        seed_id = policy.stable_ids[0]
        if configured_seed_id is None:
            configured_seed_id = seed_id
        elif configured_seed_id != seed_id:
            raise StateConflictError(
                "deploy Scylla bootstrap configured seed policy conflicts"
            )
        result.append(
            _BootstrapTarget(
                stable_id=stable_id,
                datacenter=cast(str, host.scylla_datacenter),
                rack=cast(str, host.scylla_rack),
                target_digest=_digest_object(stable_id),
                datacenter_digest=configure_entry.datacenter_digest,
                rack_digest=configure_entry.rack_digest,
                package_version_digest=configure_entry.package_version_digest,
                storage_evidence_digest=storage_entry.evidence_digest,
                configuration_evidence_digest=configure_entry.evidence_digest,
                topology_digest=configure_entry.topology_digest,
                seed_policy_digest=configure_entry.seed_policy_digest,
                capacity_evidence_digest=_digest_object(
                    {
                        "capacity_bytes": storage_entry.capacity_bytes,
                        "device_set_digest": storage_entry.device_set_digest,
                        "stable_id": stable_id,
                    }
                ),
                playbook_source_digest=playbook_source_digest,
                is_configured_seed=stable_id == seed_id,
            )
        )
    if sum(item.is_configured_seed for item in result) != 1:
        raise StateConflictError(
            "deploy Scylla bootstrap requires exactly one configured initial seed"
        )
    return tuple(result)


def _order_targets(
    targets: tuple[_BootstrapTarget, ...],
) -> tuple[_BootstrapTarget, ...]:
    """Order by configured seed, topology digests, then stable identity."""

    if (
        not targets
        or len({item.stable_id for item in targets}) != len(targets)
        or sum(item.is_configured_seed for item in targets) != 1
    ):
        raise StateConflictError("deploy Scylla bootstrap target order is ambiguous")
    return tuple(
        sorted(
            targets,
            key=lambda item: (
                0 if item.is_configured_seed else 1,
                item.datacenter,
                item.rack,
                item.stable_id,
            ),
        )
    )


def _empty_cluster_blockers(
    proof: DeployScyllaBootstrapNewClusterProof | None,
    facts: _EmptyClusterFacts,
) -> tuple[str, ...]:
    states = _proof_states(proof)
    blockers: list[str] = []
    for state, blocker in zip(
        states,
        (
            "new-cluster-intent-not-proven",
            "empty-cluster-review-not-proven",
            "prior-membership-absence-not-proven",
            "capacity-sufficiency-not-proven",
        ),
        strict=True,
    ):
        if state is DeployScyllaBootstrapProofState.UNKNOWN:
            blockers.append(blocker)
    for passed, blocker in (
        (
            facts.terraform_initial_state_proven,
            "terraform-initial-state-proof-not-proven",
        ),
        (facts.terraform_create_only, "terraform-create-only-scope-not-proven"),
        (facts.terraform_drift_free, "terraform-drift-free-scope-not-proven"),
        (
            facts.terraform_initial_progression,
            "terraform-initial-apply-progression-not-proven",
        ),
        (facts.services_masked_inactive, "scylla-service-safety-not-proven"),
        (facts.services_never_started, "scylla-never-started-not-proven"),
        (facts.topology_complete, "scylla-topology-not-proven"),
        (facts.seed_policy_complete, "scylla-seed-policy-not-proven"),
        (facts.storage_capacity_complete, "storage-capacity-not-proven"),
        (
            facts.prior_membership_artifacts_absent,
            "prior-membership-artifact-conflict",
        ),
    ):
        if not passed:
            blockers.append(blocker)
    return tuple(sorted(blockers))


def _proof_states(
    proof: DeployScyllaBootstrapNewClusterProof | None,
) -> tuple[
    DeployScyllaBootstrapProofState,
    DeployScyllaBootstrapProofState,
    DeployScyllaBootstrapProofState,
    DeployScyllaBootstrapProofState,
]:
    if proof is None:
        return (DeployScyllaBootstrapProofState.UNKNOWN,) * 4
    return (
        proof.new_cluster_intent,
        proof.empty_cluster_review,
        proof.prior_membership_absence,
        proof.capacity_sufficiency,
    )


def _build_context_record(
    context: _PlanningContext,
    *,
    created_at: str,
) -> DeployScyllaBootstrapContext:
    post = context.post_configure
    record = post.record
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": record.cluster_uuid,
        "cluster_name": record.cluster_name,
        "operation_id": record.operation_id,
        "operation": record.operation,
        **context.values,
        "post_configure_artifact_digest": post.artifact_digest,
        "post_configure_record_digest": record.record_digest,
        "post_configure_effective_plan_digest": record.effective_plan_digest,
        "authorization_state": _AUTHORIZATION_UNAVAILABLE,
        "execution_state": _EXECUTION_UNAVAILABLE,
        "public_workflow_state": _PUBLIC_WORKFLOW_UNAVAILABLE,
        "record_digest": "",
    }
    values["record_digest"] = _context_record_digest_from_values(values)
    return DeployScyllaBootstrapContext(**values)  # type: ignore[arg-type]


def _build_plan_steps(
    context: DeployScyllaBootstrapContext,
    targets: tuple[_BootstrapTarget, ...],
) -> tuple[DeployScyllaBootstrapPlanStep, ...]:
    result: list[DeployScyllaBootstrapPlanStep] = []
    for sequence, target in enumerate(targets, start=1):
        if sequence == 1:
            status = (
                DeployScyllaBootstrapStepStatus.AUTHORIZATION_REQUIRED
                if context.empty_cluster_state == _EMPTY_PROVEN
                else DeployScyllaBootstrapStepStatus.BLOCKED
            )
            blockers = (
                (_INITIAL_AUTHORIZATION_BLOCKER,)
                if status is DeployScyllaBootstrapStepStatus.AUTHORIZATION_REQUIRED
                else tuple(sorted((*context.blockers, _INITIAL_AUTHORIZATION_BLOCKER)))
            )
            mode = ScyllaBootstrapMode.INITIAL_SEED
            checkpoint = _INITIAL_HEALTH_CHECKPOINT
            preceding = None
        else:
            status = DeployScyllaBootstrapStepStatus.WAITING_FOR_HEALTH_CHECKPOINT
            blockers = tuple(sorted(_JOIN_BLOCKERS))
            mode = ScyllaBootstrapMode.JOIN_EXISTING
            checkpoint = _JOIN_HEALTH_CHECKPOINT
            preceding = result[-1].step_digest
        values: dict[str, object] = {
            "sequence": sequence,
            "mode": mode,
            "target_digest": target.target_digest,
            "expected_host_id_state": _EXPECTED_HOST_ID_STATE,
            "datacenter_digest": target.datacenter_digest,
            "rack_digest": target.rack_digest,
            "package_version_digest": target.package_version_digest,
            "storage_evidence_digest": target.storage_evidence_digest,
            "configuration_evidence_digest": (target.configuration_evidence_digest),
            "topology_digest": target.topology_digest,
            "seed_policy_digest": target.seed_policy_digest,
            "capacity_evidence_digest": target.capacity_evidence_digest,
            "playbook_source_digest": target.playbook_source_digest,
            "preceding_step_digest": preceding,
            "prerequisite_digest": _digest_object(
                {
                    "capacity_evidence_digest": target.capacity_evidence_digest,
                    "configuration_evidence_digest": (
                        target.configuration_evidence_digest
                    ),
                    "context_record_digest": context.record_digest,
                    "datacenter_digest": target.datacenter_digest,
                    "expected_host_id_state": _EXPECTED_HOST_ID_STATE,
                    "mode": mode.value,
                    "package_version_digest": target.package_version_digest,
                    "playbook_source_digest": target.playbook_source_digest,
                    "preceding_step_digest": preceding,
                    "rack_digest": target.rack_digest,
                    "seed_policy_digest": target.seed_policy_digest,
                    "storage_evidence_digest": target.storage_evidence_digest,
                    "target_digest": target.target_digest,
                    "topology_digest": target.topology_digest,
                }
            ),
            "status": status,
            "health_checkpoint_state": checkpoint,
            "blockers": blockers,
            "blocker_digest": _digest_object(list(blockers)),
            "step_digest": "",
        }
        values["step_digest"] = _step_digest_from_values(values)
        result.append(DeployScyllaBootstrapPlanStep(**values))  # type: ignore[arg-type]
    return tuple(result)


def _build_plan_record(
    context: StoredDeployScyllaBootstrapContext,
    *,
    steps: tuple[DeployScyllaBootstrapPlanStep, ...],
    created_at: str,
) -> DeployScyllaBootstrapPlan:
    record = context.record
    counts = Counter(step.status for step in steps)
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": record.cluster_uuid,
        "cluster_name": record.cluster_name,
        "operation_id": record.operation_id,
        "operation": record.operation,
        "request_digest": record.request_digest,
        "journal_generation": record.journal_generation,
        "journal_digest": record.journal_digest,
        "journal_status": record.journal_status,
        "journal_phase": record.journal_phase,
        "context_artifact_digest": context.artifact_digest,
        "context_record_digest": record.record_digest,
        "post_configure_artifact_digest": record.post_configure_artifact_digest,
        "post_configure_record_digest": record.post_configure_record_digest,
        "original_mapping_count": len(OPERATION_PLAYBOOKS[_OPERATION]),
        "original_mapping_digest": _mapping_digest(),
        "original_mapping_unchanged": True,
        "target_count": record.target_count,
        "target_set_digest": record.target_set_digest,
        "order_digest": record.order_digest,
        "serial": 1,
        "steps": steps,
        "step_count": len(steps),
        "authorization_required_count": counts[
            DeployScyllaBootstrapStepStatus.AUTHORIZATION_REQUIRED
        ],
        "blocked_count": counts[DeployScyllaBootstrapStepStatus.BLOCKED],
        "waiting_health_count": counts[
            DeployScyllaBootstrapStepStatus.WAITING_FOR_HEALTH_CHECKPOINT
        ],
        "plan_digest": "",
        "authorization_state": _AUTHORIZATION_UNAVAILABLE,
        "execution_state": _EXECUTION_UNAVAILABLE,
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _PUBLIC_WORKFLOW_UNAVAILABLE,
    }
    values["plan_digest"] = _plan_digest_from_values(values)
    return DeployScyllaBootstrapPlan(**values)  # type: ignore[arg-type]


def _build_report(
    context: StoredDeployScyllaBootstrapContext,
    plan: StoredDeployScyllaBootstrapPlan,
    *,
    context_state: DeployScyllaBootstrapArtifactState,
    plan_state: DeployScyllaBootstrapArtifactState,
) -> DeployScyllaBootstrapPlanReport:
    context_record = context.record
    plan_record = plan.record
    return DeployScyllaBootstrapPlanReport(
        operation_id=plan_record.operation_id,
        context_state=context_state,
        plan_state=plan_state,
        context_artifact_digest=context.artifact_digest,
        context_record_digest=context_record.record_digest,
        plan_artifact_digest=plan.artifact_digest,
        plan_digest=plan_record.plan_digest,
        proof_digest=context_record.proof_digest,
        empty_cluster_state=context_record.empty_cluster_state,
        blocker_digest=context_record.blocker_digest,
        target_count=plan_record.target_count,
        target_set_digest=plan_record.target_set_digest,
        order_digest=plan_record.order_digest,
        topology_digest=context_record.topology_digest,
        seed_policy_digest=context_record.seed_policy_digest,
        capacity_evidence_digest=context_record.capacity_evidence_digest,
        initial_seed_count=1,
        join_count=plan_record.target_count - 1,
        authorization_required_count=plan_record.authorization_required_count,
        blocked_count=plan_record.blocked_count,
        waiting_health_count=plan_record.waiting_health_count,
        expected_host_id_unknown_count=(context_record.expected_host_id_unknown_count),
        journal_status=plan_record.journal_status,
        journal_phase=plan_record.journal_phase,
        authorization_state=plan_record.authorization_state,
        execution_state=plan_record.execution_state,
        public_workflow_state=plan_record.public_workflow_state,
    )


def _validate_original_mapping() -> None:
    mapping = OPERATION_PLAYBOOKS[_OPERATION]
    if (
        len(mapping) != _ORIGINAL_MAPPING_COUNT
        or any(item.playbook == _PLAYBOOK for item in mapping)
        or mapping[11].playbook != "scylla-configure"
        or mapping[12].playbook != "scylla-health"
    ):
        raise StateConflictError(
            "deploy Scylla bootstrap requires the immutable original deploy mapping"
        )


def _refuse_ambiguous_or_membership_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    exact_allowed = {
        f"{operation_id}{DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_FILENAME_SUFFIX}",
        f"{operation_id}{DEPLOY_SCYLLA_BOOTSTRAP_PLAN_FILENAME_SUFFIX}",
    }
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list deploy Scylla bootstrap operation history"
        ) from error
    for entry in entries:
        if entry.name in exact_allowed:
            continue
        if (
            "scylla-bootstrap-context" in entry.name
            or "scylla-bootstrap-plan" in entry.name
            or any(
                fragment in entry.name for fragment in _MEMBERSHIP_ARTIFACT_FRAGMENTS
            )
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "deploy Scylla bootstrap refuses prior or ambiguous "
                "bootstrap/membership artifacts"
            )


def _context_record_digest(record: DeployScyllaBootstrapContext) -> str:
    return _context_record_digest_from_object(record.to_object())


def _context_record_digest_from_values(values: Mapping[str, object]) -> str:
    value = _object_for_digest(
        DeployScyllaBootstrapContext, values, tuple_fields={"blockers"}
    )
    value["record_digest"] = ""
    return _digest_object(value)


def _context_record_digest_from_object(value: Mapping[str, object]) -> str:
    projected = dict(value)
    projected["record_digest"] = ""
    return _digest_object(projected)


def _step_digest(step: DeployScyllaBootstrapPlanStep) -> str:
    return _step_digest_from_values(step.to_object())


def _step_digest_from_values(values: Mapping[str, object]) -> str:
    value = _object_for_digest(
        DeployScyllaBootstrapPlanStep,
        values,
        tuple_fields={"blockers"},
        optional_fields={"preceding_step_digest"},
    )
    value["step_digest"] = ""
    return _digest_object(value)


def _plan_digest(record: DeployScyllaBootstrapPlan) -> str:
    return _plan_digest_from_object(record.to_object())


def _plan_digest_from_values(values: Mapping[str, object]) -> str:
    value = _object_for_digest(DeployScyllaBootstrapPlan, values, step_fields={"steps"})
    value["plan_digest"] = ""
    return _digest_object(value)


def _plan_digest_from_object(value: Mapping[str, object]) -> str:
    projected = dict(value)
    projected["plan_digest"] = ""
    return _digest_object(projected)


def _dataclass_object(
    value: object,
    *,
    tuple_fields: set[str] | None = None,
    step_fields: set[str] | None = None,
    optional_fields: set[str] | None = None,
) -> dict[str, object]:
    return _object_for_digest(
        type(value),
        {
            name: getattr(value, name)
            for name in value.__dataclass_fields__  # type: ignore[attr-defined]
        },
        tuple_fields=tuple_fields,
        step_fields=step_fields,
        optional_fields=optional_fields,
    )


def _object_for_digest(
    data_type: type[Any],
    values: Mapping[str, object],
    *,
    tuple_fields: set[str] | None = None,
    step_fields: set[str] | None = None,
    optional_fields: set[str] | None = None,
) -> dict[str, object]:
    tuple_fields = tuple_fields or set()
    step_fields = step_fields or set()
    optional_fields = optional_fields or set()
    result: dict[str, object] = {}
    fields = cast(Mapping[str, Field[Any]], data_type.__dataclass_fields__)
    for name, field in fields.items():
        item = values.get(name, field.default)
        if name in tuple_fields:
            result[name] = list(cast(tuple[object, ...], item))
        elif name in step_fields:
            result[name] = [
                cast(DeployScyllaBootstrapPlanStep, step).to_object()
                for step in cast(tuple[object, ...], item)
            ]
        elif name in optional_fields:
            result[name] = item
        elif isinstance(item, StrEnum):
            result[name] = item.value
        elif isinstance(item, uuid.UUID):
            result[name] = str(item)
        else:
            result[name] = item
    return result


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError("deploy Scylla bootstrap paths are not canonical")


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "deploy Scylla bootstrap planning requires the matching held deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _id_from_filename(name: str, suffix: str) -> uuid.UUID | None:
    if not name.endswith(suffix):
        return None
    value = name[: -len(suffix)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _digest_fields(value: object) -> tuple[str, ...]:
    return tuple(
        cast(str, getattr(value, name))
        for name in value.__dataclass_fields__  # type: ignore[attr-defined]
        if name.endswith("_digest") and isinstance(getattr(value, name), str)
    )


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _positive_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


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


__all__ = [
    "ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_NEW_CLUSTER_PROOF_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_SCYLLA_BOOTSTRAP_PLAN_SCHEMA_VERSION",
    "DEPLOY_SCYLLA_BOOTSTRAP_CONTEXT_FILENAME_SUFFIX",
    "DEPLOY_SCYLLA_BOOTSTRAP_PLAN_FILENAME_SUFFIX",
    "DeployScyllaBootstrapArtifactState",
    "DeployScyllaBootstrapContext",
    "DeployScyllaBootstrapContextStore",
    "DeployScyllaBootstrapNewClusterProof",
    "DeployScyllaBootstrapPlan",
    "DeployScyllaBootstrapPlanReport",
    "DeployScyllaBootstrapPlanStep",
    "DeployScyllaBootstrapPlanStore",
    "DeployScyllaBootstrapProofState",
    "DeployScyllaBootstrapStepStatus",
    "StoredDeployScyllaBootstrapContext",
    "StoredDeployScyllaBootstrapPlan",
    "deploy_scylla_bootstrap_context_id_from_filename",
    "deploy_scylla_bootstrap_context_path",
    "deploy_scylla_bootstrap_plan_id_from_filename",
    "deploy_scylla_bootstrap_plan_path",
    "plan_deploy_scylla_bootstrap",
]
