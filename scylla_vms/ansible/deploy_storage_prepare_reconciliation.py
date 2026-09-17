"""Immutable deploy reconciliation after exact storage preparation.

This subprocess-free owner proves every prepare-required scope reached a
certain terminal success, preserves established owned storage as explicitly
not mutated, and advances only the immediate read-only storage-postcheck gate.
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

from scylla_vms.ansible.deploy_base_os_reconciliation import (
    DeployBaseOsReconciledEvidenceState,
    DeployBaseOsReconciledStep,
    DeployBaseOsReconciledStepStatus,
)
from scylla_vms.ansible.deploy_plan import (
    DeployConditionState,
    _digest_object,
)
from scylla_vms.ansible.deploy_storage_preflight import (
    ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION,
    DeployStoragePreflightAction,
    DeployStoragePreflightHostEvidence,
)
from scylla_vms.ansible.deploy_storage_prepare_authorization import (
    ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION,
    DeployStoragePrepareAuthorizationScope,
    DeployStoragePrepareAuthorizationStore,
    StoredDeployStoragePrepareAuthorization,
    _AuthorizationContext,
    _build_authorization,
    _derive_authorization_scopes,
    _load_authorization_context,
    deploy_storage_prepare_authorization_path,
)
from scylla_vms.ansible.deploy_storage_prepare_execution import (
    ANSIBLE_DEPLOY_STORAGE_PREPARE_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_SCHEMA_VERSION,
    DeployStoragePrepareEvidenceEntry,
    DeployStoragePrepareEvidenceStore,
    DeployStoragePrepareExecutionAttempt,
    DeployStoragePrepareExecutionState,
    DeployStoragePrepareExecutionStore,
    StoredDeployStoragePrepareEvidence,
    StoredDeployStoragePrepareExecution,
    deploy_storage_prepare_evidence_path,
    deploy_storage_prepare_execution_path,
)
from scylla_vms.ansible.registry import OPERATION_PLAYBOOKS, get_playbook
from scylla_vms.ansible.source import ANSIBLE_SOURCE_VERSION
from scylla_vms.ansible.storage_preflight import StorageOwnershipStatus
from scylla_vms.ansible.storage_prepare import (
    IrreversibleStepStatus,
    StoragePrepareStatus,
)
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

ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-storage-prepare-reconciliation/v1"
)
ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-post-storage-prepare-reconciliation-report/v1"
)
DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_FILENAME_SUFFIX = (
    ".ansible-deploy-post-storage-prepare-reconciliation.json"
)

_OPERATION = "deploy"
_PREPARE_PLAYBOOK = "storage-prepare"
_POSTCHECK_PLAYBOOK = "storage-postcheck"
_PREPARE_MAPPING = 9
_POSTCHECK_MAPPING = 10
_FINAL_EVIDENCE_MAPPING = len(OPERATION_PLAYBOOKS[_OPERATION])
_ORDER_BLOCKER = "ordered-deploy-step-not-reached"
_NOT_STARTED = "not-started"
_NOT_PERFORMED = "not-performed"
_UNAVAILABLE = "unavailable"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")


class DeployPostStoragePrepareOutcomeState(StrEnum):
    """Truthful per-host storage state after the preparation boundary."""

    PREPARE_SUCCEEDED = "prepare-succeeded"
    OWNED_NOOP_CURRENT = "owned-noop-current"
    BLOCKED = "blocked"


class DeployPostStoragePrepareArtifactState(StrEnum):
    """Immutable reconciliation persistence result."""

    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class DeployPostStoragePrepareOutcome:
    """One address- and device-path-free host outcome."""

    stable_id: str
    action: DeployStoragePreflightAction
    disposition: StorageOwnershipStatus
    state: DeployPostStoragePrepareOutcomeState
    current: bool
    mutation_performed: bool
    device_count: int
    device_set_digest: str
    preparation_intent_digest: str
    wipe_required: bool
    wipe_applied: bool
    authorization_scope_digest: str | None
    result_digest: str | None
    execution_evidence_digest: str | None
    filesystem_uuid_digest: str | None
    marker_digest: str | None
    provenance_digest: str | None
    source_evidence_digest: str
    outcome_digest: str

    def __post_init__(self) -> None:
        if (
            _LOGICAL_ID.fullmatch(self.stable_id) is None
            or not isinstance(self.action, DeployStoragePreflightAction)
            or not isinstance(self.disposition, StorageOwnershipStatus)
            or not isinstance(self.state, DeployPostStoragePrepareOutcomeState)
            or isinstance(self.device_count, bool)
            or not isinstance(self.device_count, int)
            or self.device_count < 0
        ):
            raise StatePersistenceError("post-storage-prepare outcome is invalid")
        optional = (
            self.authorization_scope_digest,
            self.result_digest,
            self.execution_evidence_digest,
            self.filesystem_uuid_digest,
            self.marker_digest,
            self.provenance_digest,
        )
        if self.state is DeployPostStoragePrepareOutcomeState.PREPARE_SUCCEEDED:
            valid = (
                self.action is DeployStoragePreflightAction.PREPARE_REQUIRED
                and self.disposition
                in {
                    StorageOwnershipStatus.CLEAN_NEW,
                    StorageOwnershipStatus.WIPE_REVIEW_REQUIRED,
                }
                and self.current
                and self.mutation_performed
                and self.device_count > 0
                and self.wipe_required
                == (self.disposition is StorageOwnershipStatus.WIPE_REVIEW_REQUIRED)
                and self.wipe_applied == self.wipe_required
                and all(value is not None for value in optional)
            )
        elif self.state is DeployPostStoragePrepareOutcomeState.OWNED_NOOP_CURRENT:
            valid = (
                self.action is DeployStoragePreflightAction.OWNED_NOOP
                and self.disposition is StorageOwnershipStatus.OWNED_NOOP
                and self.current
                and not self.mutation_performed
                and self.device_count > 0
                and not self.wipe_required
                and not self.wipe_applied
                and all(value is None for value in optional)
            )
        else:
            valid = (
                self.action is DeployStoragePreflightAction.BLOCKED
                and self.disposition is StorageOwnershipStatus.BLOCKED
                and not self.current
                and not self.mutation_performed
                and not self.wipe_required
                and not self.wipe_applied
                and all(value is None for value in optional)
            )
        if not valid:
            raise StatePersistenceError("post-storage-prepare outcome state conflicts")
        for value in (
            self.device_set_digest,
            self.preparation_intent_digest,
            self.source_evidence_digest,
            self.outcome_digest,
            *optional,
        ):
            if value is not None:
                validate_digest(value, "post-storage-prepare outcome digest")
        if self.outcome_digest != _outcome_digest(self):
            raise StatePersistenceError("post-storage-prepare outcome digest conflicts")

    def to_object(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            result[name] = value.value if isinstance(value, StrEnum) else value
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployPostStoragePrepareOutcome:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "post-storage-prepare outcome",
        )
        try:
            return cls(
                stable_id=require_string(value, "stable_id"),
                action=DeployStoragePreflightAction(require_string(value, "action")),
                disposition=StorageOwnershipStatus(
                    require_string(value, "disposition")
                ),
                state=DeployPostStoragePrepareOutcomeState(
                    require_string(value, "state")
                ),
                current=_boolean(value["current"], "outcome current state"),
                mutation_performed=_boolean(
                    value["mutation_performed"], "outcome mutation state"
                ),
                device_count=_integer(value["device_count"], "device count"),
                device_set_digest=require_string(value, "device_set_digest"),
                preparation_intent_digest=require_string(
                    value, "preparation_intent_digest"
                ),
                wipe_required=_boolean(value["wipe_required"], "wipe required"),
                wipe_applied=_boolean(value["wipe_applied"], "wipe applied"),
                authorization_scope_digest=_optional_string(
                    value["authorization_scope_digest"],
                    "authorization scope digest",
                ),
                result_digest=_optional_string(value["result_digest"], "result digest"),
                execution_evidence_digest=_optional_string(
                    value["execution_evidence_digest"],
                    "execution evidence digest",
                ),
                filesystem_uuid_digest=_optional_string(
                    value["filesystem_uuid_digest"],
                    "filesystem UUID digest",
                ),
                marker_digest=_optional_string(value["marker_digest"], "marker digest"),
                provenance_digest=_optional_string(
                    value["provenance_digest"], "provenance digest"
                ),
                source_evidence_digest=require_string(value, "source_evidence_digest"),
                outcome_digest=require_string(value, "outcome_digest"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "post-storage-prepare outcome enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployStoragePostcheckScope:
    """Immediate read-only postcheck scope and exact prerequisite proof."""

    stable_id: str
    source_state: DeployPostStoragePrepareOutcomeState
    mutation_performed: bool
    device_count: int
    device_set_digest: str
    preparation_intent_digest: str
    preparation_evidence_digest: str
    source_evidence_digest: str
    scope_digest: str

    def __post_init__(self) -> None:
        if (
            _LOGICAL_ID.fullmatch(self.stable_id) is None
            or self.source_state
            not in {
                DeployPostStoragePrepareOutcomeState.PREPARE_SUCCEEDED,
                DeployPostStoragePrepareOutcomeState.OWNED_NOOP_CURRENT,
            }
            or self.mutation_performed
            != (
                self.source_state
                is DeployPostStoragePrepareOutcomeState.PREPARE_SUCCEEDED
            )
            or self.device_count < 1
        ):
            raise StatePersistenceError("storage-postcheck scope is invalid")
        for value in (
            self.device_set_digest,
            self.preparation_intent_digest,
            self.preparation_evidence_digest,
            self.source_evidence_digest,
            self.scope_digest,
        ):
            validate_digest(value, "storage-postcheck scope digest")
        if self.scope_digest != _postcheck_scope_digest(self):
            raise StatePersistenceError("storage-postcheck scope digest conflicts")

    def to_object(self) -> dict[str, object]:
        return {
            "device_count": self.device_count,
            "device_set_digest": self.device_set_digest,
            "mutation_performed": self.mutation_performed,
            "preparation_evidence_digest": self.preparation_evidence_digest,
            "preparation_intent_digest": self.preparation_intent_digest,
            "scope_digest": self.scope_digest,
            "source_evidence_digest": self.source_evidence_digest,
            "source_state": self.source_state.value,
            "stable_id": self.stable_id,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DeployStoragePostcheckScope:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "storage-postcheck scope",
        )
        try:
            return cls(
                stable_id=require_string(value, "stable_id"),
                source_state=DeployPostStoragePrepareOutcomeState(
                    require_string(value, "source_state")
                ),
                mutation_performed=_boolean(
                    value["mutation_performed"], "scope mutation state"
                ),
                device_count=_integer(value["device_count"], "device count"),
                device_set_digest=require_string(value, "device_set_digest"),
                preparation_intent_digest=require_string(
                    value, "preparation_intent_digest"
                ),
                preparation_evidence_digest=require_string(
                    value, "preparation_evidence_digest"
                ),
                source_evidence_digest=require_string(value, "source_evidence_digest"),
                scope_digest=require_string(value, "scope_digest"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "storage-postcheck scope state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployPostStoragePrepareReconciliation:
    """Immutable effective plan after exact storage preparation."""

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
    authorization_artifact_digest: str | None
    authorization_digest: str | None
    general_proof_digest: str | None
    wipe_proof_digest: str | None
    execution_artifact_digest: str | None
    execution_binding_digest: str | None
    evidence_artifact_digest: str | None
    evidence_binding_digest: str | None
    inventory_generation: int
    inventory_artifact_digest: str
    inventory_digest: str
    trust_generation: int
    trust_artifact_digest: str
    trust_entries_digest: str
    readiness_artifact_digest: str
    readiness_record_digest: str
    observation_generation: int
    observation_artifact_digest: str
    observation_manifest_digest: str
    catalog_digest: str
    ansible_source_version: str
    ansible_source_digest: str
    outcomes: tuple[DeployPostStoragePrepareOutcome, ...]
    target_count: int
    target_set_digest: str
    outcome_digest: str
    prepare_required_count: int
    prepare_succeeded_count: int
    owned_noop_current_count: int
    blocked_count: int
    wipe_required_count: int
    wipe_applied_count: int
    general_authorization_consumed: bool
    wipe_authorization_consumed_count: int
    postcheck_scopes: tuple[DeployStoragePostcheckScope, ...]
    postcheck_target_count: int
    postcheck_target_set_digest: str
    postcheck_scope_digest: str
    steps: tuple[DeployBaseOsReconciledStep, ...]
    step_count: int
    succeeded_count: int
    authorization_required_count: int
    eligible_count: int
    plan_blocked_count: int
    not_performed_count: int
    blocker_set: tuple[str, ...]
    blocker_digest: str
    effective_plan_digest: str
    next_execution_state: str
    finalization_state: str
    public_workflow_state: str
    record_digest: str
    prior_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
    )
    authorization_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION
    )
    execution_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_SCHEMA_VERSION
    )
    evidence_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREPARE_EVIDENCE_SCHEMA_VERSION
    )
    preflight_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    )
    readiness_schema_version: str = TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.generation != 1
            or self.schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_SCHEMA_VERSION
            or self.prior_reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
            or self.authorization_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_AUTHORIZATION_SCHEMA_VERSION
            or self.execution_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_EXECUTION_SCHEMA_VERSION
            or self.evidence_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREPARE_EVIDENCE_SCHEMA_VERSION
            or self.preflight_evidence_schema_version
            != ANSIBLE_DEPLOY_STORAGE_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
            or self.readiness_schema_version != TERRAFORM_APPLY_READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.operation != _OPERATION
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.ansible_source_version != ANSIBLE_SOURCE_VERSION
            or self.next_execution_state != _NOT_STARTED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
        ):
            raise StatePersistenceError(
                "post-storage-prepare reconciliation identity is invalid"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for count in (
            self.journal_generation,
            self.inventory_generation,
            self.trust_generation,
            self.observation_generation,
            self.target_count,
            self.prepare_required_count,
            self.prepare_succeeded_count,
            self.owned_noop_current_count,
            self.blocked_count,
            self.wipe_required_count,
            self.wipe_applied_count,
            self.wipe_authorization_consumed_count,
            self.postcheck_target_count,
            self.step_count,
            self.succeeded_count,
            self.authorization_required_count,
            self.eligible_count,
            self.plan_blocked_count,
            self.not_performed_count,
        ):
            _nonnegative_integer(count, "post-storage-prepare count")
        if (
            self.journal_generation < 1
            or self.inventory_generation < 1
            or self.trust_generation < 1
            or self.observation_generation < 1
            or self.target_count < 1
            or self.target_count != len(self.outcomes)
            or tuple(item.stable_id for item in self.outcomes)
            != tuple(sorted({item.stable_id for item in self.outcomes}))
            or self.target_set_digest
            != _digest_object([item.stable_id for item in self.outcomes])
            or self.outcome_digest
            != _digest_object([item.to_object() for item in self.outcomes])
        ):
            raise StatePersistenceError("post-storage-prepare target summary conflicts")
        states = Counter(item.state for item in self.outcomes)
        if (
            self.prepare_required_count
            != states[DeployPostStoragePrepareOutcomeState.PREPARE_SUCCEEDED]
            or self.prepare_succeeded_count != self.prepare_required_count
            or self.owned_noop_current_count
            != states[DeployPostStoragePrepareOutcomeState.OWNED_NOOP_CURRENT]
            or self.blocked_count
            != states[DeployPostStoragePrepareOutcomeState.BLOCKED]
            or self.prepare_required_count
            + self.owned_noop_current_count
            + self.blocked_count
            != self.target_count
            or self.wipe_required_count
            != sum(item.wipe_required for item in self.outcomes)
            or self.wipe_applied_count
            != sum(item.wipe_applied for item in self.outcomes)
            or self.wipe_applied_count != self.wipe_required_count
        ):
            raise StatePersistenceError("post-storage-prepare outcome counts conflict")
        preparation_artifacts = (
            self.authorization_artifact_digest,
            self.authorization_digest,
            self.general_proof_digest,
            self.execution_artifact_digest,
            self.execution_binding_digest,
            self.evidence_artifact_digest,
            self.evidence_binding_digest,
        )
        if self.prepare_required_count:
            valid_artifacts = (
                all(value is not None for value in preparation_artifacts)
                and self.general_authorization_consumed
                and self.wipe_authorization_consumed_count == self.wipe_required_count
                and (self.wipe_required_count == 0) == (self.wipe_proof_digest is None)
            )
        else:
            valid_artifacts = (
                all(value is None for value in preparation_artifacts)
                and self.wipe_proof_digest is None
                and not self.general_authorization_consumed
                and self.wipe_authorization_consumed_count == 0
                and self.wipe_required_count == 0
            )
        if not valid_artifacts:
            raise StatePersistenceError(
                "post-storage-prepare proof or artifact summary conflicts"
            )
        if (
            self.postcheck_target_count != len(self.postcheck_scopes)
            or tuple(item.stable_id for item in self.postcheck_scopes)
            != tuple(sorted({item.stable_id for item in self.postcheck_scopes}))
            or self.postcheck_target_count
            != self.prepare_succeeded_count + self.owned_noop_current_count
            or self.postcheck_target_set_digest
            != _digest_object([item.stable_id for item in self.postcheck_scopes])
            or self.postcheck_scope_digest
            != _digest_object([item.to_object() for item in self.postcheck_scopes])
        ):
            raise StatePersistenceError(
                "post-storage-prepare postcheck scope conflicts"
            )
        expected_mapping = OPERATION_PLAYBOOKS[_OPERATION]
        if (
            self.step_count != len(self.steps)
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, len(self.steps) + 1))
            or {step.mapping_sequence for step in self.steps}
            != set(range(1, len(expected_mapping) + 1))
            or any(
                step.playbook != expected_mapping[step.mapping_sequence - 1].playbook
                or step.condition
                != expected_mapping[step.mapping_sequence - 1].condition
                for step in self.steps
            )
        ):
            raise StatePersistenceError("post-storage-prepare deploy mapping conflicts")
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
            or self.plan_blocked_count
            != counts[DeployBaseOsReconciledStepStatus.BLOCKED]
            or self.not_performed_count
            != counts[DeployBaseOsReconciledStepStatus.NOT_PERFORMED]
            or self.blocker_set != blockers
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blocker_set)
            or self.blocker_digest != _digest_object(list(self.blocker_set))
            or self.effective_plan_digest
            != _digest_object([step.to_object() for step in self.steps])
        ):
            raise StatePersistenceError("post-storage-prepare plan summary conflicts")
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if name.endswith("_digest") and value is not None:
                validate_digest(
                    cast(str, value), "post-storage-prepare reconciliation digest"
                )
        if self.record_digest != _record_digest(self):
            raise StatePersistenceError(
                "post-storage-prepare reconciliation record digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            result[name] = (
                str(value)
                if isinstance(value, uuid.UUID)
                else value.value
                if isinstance(value, (JournalStatus, OperationPhase, StrEnum))
                else [item.to_object() for item in value]
                if name in {"outcomes", "postcheck_scopes", "steps"}
                else list(value)
                if name == "blocker_set"
                else value
            )
        return result

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployPostStoragePrepareReconciliation:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "post-storage-prepare reconciliation",
        )
        integers = {
            "generation",
            "journal_generation",
            "inventory_generation",
            "trust_generation",
            "observation_generation",
            "target_count",
            "prepare_required_count",
            "prepare_succeeded_count",
            "owned_noop_current_count",
            "blocked_count",
            "wipe_required_count",
            "wipe_applied_count",
            "wipe_authorization_consumed_count",
            "postcheck_target_count",
            "step_count",
            "succeeded_count",
            "authorization_required_count",
            "eligible_count",
            "plan_blocked_count",
            "not_performed_count",
        }
        optional = {
            "authorization_artifact_digest",
            "authorization_digest",
            "general_proof_digest",
            "wipe_proof_digest",
            "execution_artifact_digest",
            "execution_binding_digest",
            "evidence_artifact_digest",
            "evidence_binding_digest",
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
            elif name == "outcomes":
                parsed[name] = tuple(
                    DeployPostStoragePrepareOutcome.from_object(
                        _mapping(entry, "post-storage-prepare outcome")
                    )
                    for entry in _array(item, "post-storage-prepare outcomes")
                )
            elif name == "postcheck_scopes":
                parsed[name] = tuple(
                    DeployStoragePostcheckScope.from_object(
                        _mapping(entry, "storage-postcheck scope")
                    )
                    for entry in _array(item, "storage-postcheck scopes")
                )
            elif name == "steps":
                parsed[name] = tuple(
                    DeployBaseOsReconciledStep.from_object(
                        _mapping(entry, "post-storage-prepare step")
                    )
                    for entry in _array(item, "post-storage-prepare steps")
                )
            elif name == "blocker_set":
                parsed[name] = _string_tuple(item, name)
            elif name == "general_authorization_consumed":
                parsed[name] = _boolean(item, name)
            elif name in optional:
                parsed[name] = _optional_string(item, name)
            else:
                parsed[name] = require_string(value, name)
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployPostStoragePrepareReconciliation:
    record: DeployPostStoragePrepareReconciliation
    artifact_digest: str


class DeployPostStoragePrepareReconciliationStore:
    """Owner-only immutable post-storage-prepare companion."""

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
        self._path = deploy_post_storage_prepare_reconciliation_path(
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
    ) -> StoredDeployPostStoragePrepareReconciliation:
        value, artifact_digest = self._file.read()
        record = DeployPostStoragePrepareReconciliation.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or artifact_digest != digest_bytes(serialize_json(record.to_object()))
        ):
            raise StatePersistenceError(
                "post-storage-prepare reconciliation identity conflicts"
            )
        return StoredDeployPostStoragePrepareReconciliation(record, artifact_digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployPostStoragePrepareReconciliation:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self,
        record: DeployPostStoragePrepareReconciliation,
        *,
        lock: ClusterLock,
    ) -> tuple[
        StoredDeployPostStoragePrepareReconciliation,
        DeployPostStoragePrepareArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "post-storage-prepare reconciliation operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "post-storage-prepare reconciliation is immutable"
                )
            return current, DeployPostStoragePrepareArtifactState.REUSED
        artifact_digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployPostStoragePrepareReconciliation(record, artifact_digest),
            DeployPostStoragePrepareArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployPostStoragePrepareReconciliationReport:
    """Strict redacted projection without host, device, or executable detail."""

    operation_id: uuid.UUID
    artifact_state: DeployPostStoragePrepareArtifactState
    reconciliation_artifact_digest: str
    reconciliation_record_digest: str
    effective_plan_digest: str
    target_count: int
    target_set_digest: str
    outcome_digest: str
    prepare_required_count: int
    prepare_succeeded_count: int
    owned_noop_current_count: int
    blocked_count: int
    wipe_required_count: int
    wipe_applied_count: int
    general_authorization_consumed: bool
    wipe_authorization_consumed_count: int
    postcheck_target_count: int
    postcheck_target_set_digest: str
    postcheck_scope_digest: str
    succeeded_count: int
    eligible_count: int
    authorization_required_count: int
    plan_blocked_count: int
    not_performed_count: int
    blocker_set: tuple[str, ...]
    blocker_digest: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    next_execution_state: str
    finalization_state: str
    public_workflow_state: str
    reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_REPORT_SCHEMA_VERSION
            or self.reconciliation_schema_version
            != ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_SCHEMA_VERSION
            or self.target_count < 1
            or self.prepare_succeeded_count != self.prepare_required_count
            or self.wipe_applied_count != self.wipe_required_count
            or self.wipe_authorization_consumed_count != self.wipe_required_count
            or self.postcheck_target_count
            != self.prepare_succeeded_count + self.owned_noop_current_count
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.next_execution_state != _NOT_STARTED
            or self.finalization_state != _NOT_STARTED
            or self.public_workflow_state != _UNAVAILABLE
            or self.blocker_set != tuple(sorted(set(self.blocker_set)))
            or self.blocker_digest != _digest_object(list(self.blocker_set))
        ):
            raise StatePersistenceError(
                "post-storage-prepare reconciliation report is invalid"
            )
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if name.endswith("_digest"):
                validate_digest(cast(str, value), "post-storage-prepare report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "artifact_state": self.artifact_state.value,
            "blockers": {
                "count": len(self.blocker_set),
                "digest": self.blocker_digest,
                "values": list(self.blocker_set),
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "operation_id": str(self.operation_id),
            "preparation": {
                "blocked_count": self.blocked_count,
                "general_authorization_consumed": (self.general_authorization_consumed),
                "outcome_digest": self.outcome_digest,
                "owned_noop_current_count": self.owned_noop_current_count,
                "prepare_required_count": self.prepare_required_count,
                "prepare_succeeded_count": self.prepare_succeeded_count,
                "target_count": self.target_count,
                "target_set_digest": self.target_set_digest,
                "wipe_applied_count": self.wipe_applied_count,
                "wipe_authorization_consumed_count": (
                    self.wipe_authorization_consumed_count
                ),
                "wipe_required_count": self.wipe_required_count,
            },
            "provenance": {
                "effective_plan_digest": self.effective_plan_digest,
                "reconciliation_artifact_digest": self.reconciliation_artifact_digest,
                "reconciliation_record_digest": self.reconciliation_record_digest,
            },
            "result": (
                "storage-postcheck-scope-derived"
                if self.postcheck_target_count
                else "storage-postcheck-blocked"
            ),
            "schema_version": self.schema_version,
            "schemas": {"reconciliation": self.reconciliation_schema_version},
            "states": {
                "finalization": self.finalization_state,
                "next_execution": self.next_execution_state,
                "public_workflow": self.public_workflow_state,
            },
            "steps": {
                "authorization_required_count": self.authorization_required_count,
                "blocked_count": self.plan_blocked_count,
                "eligible_count": self.eligible_count,
                "not_performed_count": self.not_performed_count,
                "succeeded_count": self.succeeded_count,
            },
            "storage_postcheck": {
                "classification": OperationClassification.READ_ONLY.value,
                "execution": _NOT_PERFORMED,
                "scope_digest": self.postcheck_scope_digest,
                "target_count": self.postcheck_target_count,
                "target_set_digest": self.postcheck_target_set_digest,
            },
        }


@dataclass(frozen=True, slots=True)
class _ReconciliationContext:
    authorization_context: _AuthorizationContext
    authorization: StoredDeployStoragePrepareAuthorization | None
    execution: StoredDeployStoragePrepareExecution | None
    evidence: StoredDeployStoragePrepareEvidence | None
    outcomes: tuple[DeployPostStoragePrepareOutcome, ...]


def reconcile_deploy_storage_prepare(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployPostStoragePrepareReconciliationReport:
    """Persist exact outcomes and derive only immediate storage postcheck."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    _refuse_ambiguous_or_later_artifacts(paths, operation_id)
    context = _load_context(paths, operation_id, lock=lock)
    steps = _build_steps(context)
    store = DeployPostStoragePrepareReconciliationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    metadata = context.authorization_context.preflight.metadata
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
    record = _build_record(context, steps=steps, created_at=created_at)
    if existing is not None and existing.record != record:
        raise StateConflictError(
            "post-storage-prepare reconciliation is immutable; use a new operation"
        )
    try:
        stored, state = store.write_locked(record, lock=lock)
    except StatePersistenceError as error:
        raise StatePersistenceError(
            "post-storage-prepare reconciliation persistence failed"
        ) from error
    return _build_report(stored, state=state)


def deploy_post_storage_prepare_reconciliation_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    """Return the sole canonical post-storage-prepare companion path."""

    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "post-storage-prepare reconciliation path is not canonical"
        )
    return path


def deploy_post_storage_prepare_reconciliation_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    if not name.endswith(DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_FILENAME_SUFFIX):
        return None
    value = name[: -len(DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_FILENAME_SUFFIX)]
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
) -> _ReconciliationContext:
    authorization_context = _load_authorization_context(paths, operation_id, lock=lock)
    preflight = authorization_context.reconciliation.record
    metadata = authorization_context.preflight.metadata
    prepare_required = preflight.prepare_required_host_count
    authorization_path = deploy_storage_prepare_authorization_path(paths, operation_id)
    execution_path = deploy_storage_prepare_execution_path(paths, operation_id)
    evidence_path = deploy_storage_prepare_evidence_path(paths, operation_id)
    for path in (authorization_path, execution_path, evidence_path):
        validate_state_file(path, allow_missing=True)
    present = tuple(
        path.exists() for path in (authorization_path, execution_path, evidence_path)
    )
    if prepare_required == 0:
        if any(present):
            raise StateConflictError(
                "post-storage-prepare no-op branch refuses preparation artifacts"
            )
        nonexecuted_outcomes = _build_nonexecuted_outcomes(authorization_context)
        return _ReconciliationContext(
            authorization_context, None, None, None, nonexecuted_outcomes
        )
    if not all(present):
        raise StateConflictError(
            "post-storage-prepare reconciliation requires complete authorization, "
            "execution, and evidence"
        )
    authorization = DeployStoragePrepareAuthorizationStore(
        paths, operation_id
    ).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    expected_scopes = _derive_authorization_scopes(authorization_context)
    expected_authorization = _build_authorization(
        authorization_context,
        scopes=expected_scopes,
        general_proof=authorization.record.general_proof,
        wipe_proof=authorization.record.wipe_proof,
        created_at=authorization.record.created_at,
    )
    if authorization.record != expected_authorization:
        raise StateConflictError(
            "post-storage-prepare authorization provenance drifted"
        )
    execution = DeployStoragePrepareExecutionStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    evidence = DeployStoragePrepareEvidenceStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.cluster_uuid,
        expected_cluster_name=metadata.cluster_name,
    )
    prepared = _validate_completed_preparation(
        authorization_context, authorization, execution, evidence
    )
    by_id = {item.stable_id: item for item in prepared}
    outcomes: list[DeployPostStoragePrepareOutcome] = []
    for host in authorization_context.evidence.record.hosts:
        if host.action is DeployStoragePreflightAction.PREPARE_REQUIRED:
            outcome = by_id.pop(host.stable_id, None)
            if outcome is None:
                raise StateConflictError(
                    "post-storage-prepare successful target membership is incomplete"
                )
            outcomes.append(outcome)
        else:
            outcomes.append(_nonexecuted_outcome(host))
    if by_id:
        raise StateConflictError(
            "post-storage-prepare successful target membership is over-broad"
        )
    return _ReconciliationContext(
        authorization_context,
        authorization,
        execution,
        evidence,
        tuple(outcomes),
    )


def _validate_completed_preparation(
    authorization_context: _AuthorizationContext,
    authorization: StoredDeployStoragePrepareAuthorization,
    execution: StoredDeployStoragePrepareExecution,
    evidence: StoredDeployStoragePrepareEvidence,
) -> tuple[DeployPostStoragePrepareOutcome, ...]:
    record = execution.record
    evidence_record = evidence.record
    binding = record.binding
    auth = authorization.record
    preflight = authorization_context.preflight
    loaded = preflight.discovery.post.chain.authorization_context.final_routes.post.post.base.host.loaded
    planning = loaded.planning
    deploy = planning.base.deploy
    trust = planning.base.trust
    readiness = planning.readiness
    wipe_ids = tuple(scope.stable_id for scope in auth.scopes if scope.wipe_required)
    expected_binding = (
        binding.cluster_uuid == auth.cluster_uuid
        and binding.cluster_name == auth.cluster_name
        and binding.operation_id == auth.operation_id
        and binding.operation == _OPERATION
        and binding.request_digest == auth.request_digest
        and binding.journal_generation == auth.journal_generation
        and binding.journal_digest == auth.journal_digest
        and binding.journal_status is auth.journal_status
        and binding.journal_phase is auth.journal_phase
        and binding.authorization_artifact_digest == authorization.artifact_digest
        and binding.authorization_digest == auth.authorization_digest
        and binding.authorization_scope_digest == auth.authorization_scope_digest
        and binding.general_proof_digest == auth.general_proof.proof_digest
        and binding.wipe_proof_digest
        == (None if auth.wipe_proof is None else auth.wipe_proof.proof_digest)
        and binding.preflight_reconciliation_artifact_digest
        == authorization_context.reconciliation.artifact_digest
        and binding.preflight_reconciliation_record_digest
        == authorization_context.reconciliation.record.record_digest
        and binding.preflight_evidence_artifact_digest
        == authorization_context.evidence.artifact_digest
        and binding.preflight_evidence_digest
        == authorization_context.evidence.record.evidence_digest
        and binding.readiness_artifact_digest == readiness.artifact_digest
        and binding.readiness_record_digest == readiness.record.record_digest
        and binding.catalog_digest == loaded.catalog_digest
        and binding.source_version == loaded.source.version
        and binding.source_digest == loaded.source.digest
        and binding.toolchain_version == preflight.binding.toolchain_version
        and binding.executable_identity_digest
        == preflight.binding.executable_identity_digest
        and binding.toolchain_evidence_digest
        == preflight.binding.toolchain_evidence_digest
        and binding.observation_generation == deploy.observation.record.generation
        and binding.observation_artifact_digest == deploy.observation.digest
        and binding.observation_manifest_digest
        == deploy.observation.record.manifest_digest
        and binding.inventory_generation == deploy.inventory.record.generation
        and binding.inventory_artifact_digest == deploy.inventory.digest
        and binding.inventory_digest == deploy.inventory.record.inventory_digest
        and binding.trust_generation == trust.record.generation
        and binding.trust_artifact_digest == trust.digest
        and binding.trust_entries_digest == trust.record.entries_digest
        and binding.scope_count == len(auth.scopes)
        and binding.stable_id_count == len(auth.scopes)
        and binding.stable_id_set_digest
        == _digest_object([scope.stable_id for scope in auth.scopes])
        and binding.wipe_scope_count == len(wipe_ids)
        and binding.wipe_target_set_digest == _digest_object(list(wipe_ids))
    )
    if not expected_binding or evidence_record.binding != binding:
        raise StateConflictError("post-storage-prepare execution binding drifted")
    if (
        record.state is not DeployStoragePrepareExecutionState.SUCCEEDED
        or not record.all_scopes_completed
        or not record.general_authorization_consumed
        or record.invocation_count != len(auth.scopes)
        or record.wipe_authorization_consumed_count != len(wipe_ids)
        or record.wipe_authorization_consumed_target_set_digest
        != _digest_object(list(wipe_ids))
        or len(record.attempts) != len(auth.scopes)
        or len(evidence_record.entries) != len(auth.scopes)
        or auth.prepare_host_count != len(auth.scopes)
        or auth.wipe_host_count != len(wipe_ids)
    ):
        raise StateConflictError(
            "post-storage-prepare reconciliation requires complete terminal success"
        )
    preflight_hosts = {
        host.stable_id: host for host in authorization_context.evidence.record.hosts
    }
    outcomes: list[DeployPostStoragePrepareOutcome] = []
    execution_scope: list[dict[str, object]] = []
    for index, (scope, attempt, entry) in enumerate(
        zip(auth.scopes, record.attempts, evidence_record.entries, strict=True),
        start=1,
    ):
        host = preflight_hosts.get(scope.stable_id)
        if host is None:
            raise StateConflictError(
                "post-storage-prepare preflight target is unavailable"
            )
        _validate_successful_scope(index, scope, host, attempt, entry)
        execution_scope.append(
            {
                "action": scope.action.value,
                "attempt_index": index,
                "authorization_scope_digest": scope.scope_digest,
                "command_digest": attempt.command_digest,
                "device_set_digest": scope.device_set_digest,
                "disposition": scope.disposition.value,
                "preparation_intent_digest": scope.preparation_intent_digest,
                "provenance_digest": entry.provenance_digest,
                "source_digest": scope.source_digest,
                "stable_id_digest": scope.stable_id_digest,
                "step_sequence": scope.sequence,
                "variables_digest": attempt.variables_digest,
                "wipe_required": scope.wipe_required,
            }
        )
        values: dict[str, object] = {
            "stable_id": scope.stable_id,
            "action": scope.action,
            "disposition": scope.disposition,
            "state": DeployPostStoragePrepareOutcomeState.PREPARE_SUCCEEDED,
            "current": True,
            "mutation_performed": True,
            "device_count": scope.device_count,
            "device_set_digest": scope.device_set_digest,
            "preparation_intent_digest": scope.preparation_intent_digest,
            "wipe_required": scope.wipe_required,
            "wipe_applied": entry.wipe_applied,
            "authorization_scope_digest": scope.scope_digest,
            "result_digest": entry.result_digest,
            "execution_evidence_digest": entry.evidence_digest,
            "filesystem_uuid_digest": entry.filesystem_uuid_digest,
            "marker_digest": entry.marker_digest,
            "provenance_digest": entry.provenance_digest,
            "source_evidence_digest": host.status_digest,
            "outcome_digest": "",
        }
        values["outcome_digest"] = _outcome_digest_from_values(values)
        outcomes.append(
            DeployPostStoragePrepareOutcome(**values)  # type: ignore[arg-type]
        )
    if binding.execution_scope_digest != _digest_object(execution_scope):
        raise StateConflictError(
            "post-storage-prepare execution scope digest conflicts"
        )
    return tuple(outcomes)


def _validate_successful_scope(
    index: int,
    authorized: DeployStoragePrepareAuthorizationScope,
    host: DeployStoragePreflightHostEvidence,
    attempt: DeployStoragePrepareExecutionAttempt,
    entry: DeployStoragePrepareEvidenceEntry,
) -> None:
    # Authorization scopes are validated domain records; explicit attribute
    # checks below prevent a successful execution prefix from changing any
    # action, disposition, device, command, or provenance binding.
    if (
        attempt.attempt_index != index
        or entry.attempt_index != index
        or attempt.step_sequence != authorized.sequence
        or entry.step_sequence != authorized.sequence
        or attempt.stable_id != authorized.stable_id
        or entry.stable_id != authorized.stable_id
        or host.stable_id != authorized.stable_id
        or attempt.action is not DeployStoragePreflightAction.PREPARE_REQUIRED
        or entry.action is not DeployStoragePreflightAction.PREPARE_REQUIRED
        or host.action is not DeployStoragePreflightAction.PREPARE_REQUIRED
        or attempt.disposition is not authorized.disposition
        or entry.disposition is not authorized.disposition
        or host.disposition is not authorized.disposition
        or attempt.device_count != authorized.device_count
        or entry.device_count != authorized.device_count
        or host.device_count != authorized.device_count
        or attempt.device_set_digest != authorized.device_set_digest
        or entry.device_set_digest != authorized.device_set_digest
        or host.device_set_digest != authorized.device_set_digest
        or attempt.preparation_intent_digest != authorized.preparation_intent_digest
        or entry.preparation_intent_digest != authorized.preparation_intent_digest
        or host.preparation_intent_digest != authorized.preparation_intent_digest
        or attempt.wipe_required != authorized.wipe_required
        or entry.wipe_required != authorized.wipe_required
        or host.wipe_required != authorized.wipe_required
        or attempt.authorization_scope_digest != authorized.scope_digest
        or attempt.variables_digest != entry.variables_digest
        or attempt.command_digest != entry.command_digest
        or attempt.source_digest != authorized.source_digest
        or entry.source_digest != authorized.source_digest
        or attempt.state is not DeployStoragePrepareExecutionState.SUCCEEDED
        or attempt.exit_code != 0
        or attempt.result_digest != entry.result_digest
        or attempt.evidence_digest != entry.evidence_digest
        or attempt.manual_recovery_required
        or attempt.automatic_retry_allowed
        or attempt.immediate_device_revalidation is not True
        or attempt.wipe_applied != authorized.wipe_required
        or attempt.mutation_boundary != "completed"
        or attempt.irreversible_step_status != IrreversibleStepStatus.COMPLETED.value
        or not attempt.invocation_may_have_occurred
        or attempt.general_authorization_consumed_at_start != (index == 1)
        or attempt.wipe_authorization_consumed_at_start != authorized.wipe_required
        or entry.status is not StoragePrepareStatus.CHANGED
        or entry.completion_state != "completed"
        or not entry.immediate_device_revalidation
        or entry.wipe_applied != authorized.wipe_required
        or entry.mutation_boundary != "completed"
        or entry.irreversible_step_status is not IrreversibleStepStatus.COMPLETED
        or entry.completed_step_count < 1
        or entry.verification_count < 1
        or entry.filesystem_uuid_digest is None
        or entry.marker_digest is None
        or entry.manual_recovery_required
        or entry.automatic_retry_allowed
        or host.blocker_set
    ):
        raise StateConflictError(
            "post-storage-prepare terminal scope or evidence conflicts"
        )


def _build_nonexecuted_outcomes(
    context: _AuthorizationContext,
) -> tuple[DeployPostStoragePrepareOutcome, ...]:
    outcomes = tuple(
        _nonexecuted_outcome(host) for host in context.evidence.record.hosts
    )
    if any(
        outcome.state is DeployPostStoragePrepareOutcomeState.PREPARE_SUCCEEDED
        for outcome in outcomes
    ):
        raise StateConflictError(
            "post-storage-prepare no-op branch contains prepare-required storage"
        )
    return outcomes


def _nonexecuted_outcome(
    host: DeployStoragePreflightHostEvidence,
) -> DeployPostStoragePrepareOutcome:
    if host.action is DeployStoragePreflightAction.PREPARE_REQUIRED:
        raise StateConflictError(
            "prepare-required storage cannot use nonexecuted outcome"
        )
    state = (
        DeployPostStoragePrepareOutcomeState.OWNED_NOOP_CURRENT
        if host.action is DeployStoragePreflightAction.OWNED_NOOP
        else DeployPostStoragePrepareOutcomeState.BLOCKED
    )
    values: dict[str, object] = {
        "stable_id": host.stable_id,
        "action": host.action,
        "disposition": host.disposition,
        "state": state,
        "current": state is DeployPostStoragePrepareOutcomeState.OWNED_NOOP_CURRENT,
        "mutation_performed": False,
        "device_count": host.device_count,
        "device_set_digest": host.device_set_digest,
        "preparation_intent_digest": host.preparation_intent_digest,
        "wipe_required": False,
        "wipe_applied": False,
        "authorization_scope_digest": None,
        "result_digest": None,
        "execution_evidence_digest": None,
        "filesystem_uuid_digest": None,
        "marker_digest": None,
        "provenance_digest": None,
        "source_evidence_digest": host.status_digest,
        "outcome_digest": "",
    }
    values["outcome_digest"] = _outcome_digest_from_values(values)
    return DeployPostStoragePrepareOutcome(**values)  # type: ignore[arg-type]


def _postcheck_scopes(
    outcomes: tuple[DeployPostStoragePrepareOutcome, ...],
) -> tuple[DeployStoragePostcheckScope, ...]:
    result: list[DeployStoragePostcheckScope] = []
    for outcome in outcomes:
        if not outcome.current:
            continue
        preparation_evidence_digest = (
            outcome.execution_evidence_digest
            if outcome.execution_evidence_digest is not None
            else outcome.source_evidence_digest
        )
        values: dict[str, object] = {
            "stable_id": outcome.stable_id,
            "source_state": outcome.state,
            "mutation_performed": outcome.mutation_performed,
            "device_count": outcome.device_count,
            "device_set_digest": outcome.device_set_digest,
            "preparation_intent_digest": outcome.preparation_intent_digest,
            "preparation_evidence_digest": preparation_evidence_digest,
            "source_evidence_digest": outcome.source_evidence_digest,
            "scope_digest": "",
        }
        values["scope_digest"] = _postcheck_scope_digest_from_values(values)
        result.append(
            DeployStoragePostcheckScope(**values)  # type: ignore[arg-type]
        )
    return tuple(result)


def _build_steps(
    context: _ReconciliationContext,
) -> tuple[DeployBaseOsReconciledStep, ...]:
    prior_steps = context.authorization_context.reconciliation.record.steps
    outcomes = {item.stable_id: item for item in context.outcomes}
    result: list[DeployBaseOsReconciledStep] = []
    for prior in prior_steps:
        prior_digest = _digest_object(prior.to_object())
        if (
            prior.status is DeployBaseOsReconciledStepStatus.SUCCEEDED
            or prior.condition_state is DeployConditionState.INACTIVE
        ):
            result.append(replace(prior, prior_reconciled_step_digest=prior_digest))
            continue
        if prior.mapping_sequence == _PREPARE_MAPPING:
            _validate_storage_step(prior, _PREPARE_PLAYBOOK, destructive=True)
            outcome = outcomes[prior.target_ids[0]]
            if outcome.state is DeployPostStoragePrepareOutcomeState.PREPARE_SUCCEEDED:
                if (
                    prior.status
                    is not DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
                ):
                    raise StateConflictError(
                        "post-storage-prepare executed step identity drifted"
                    )
                result.append(
                    replace(
                        prior,
                        prior_reconciled_step_digest=prior_digest,
                        status=DeployBaseOsReconciledStepStatus.SUCCEEDED,
                        evidence_state=(
                            DeployBaseOsReconciledEvidenceState.STORAGE_PREPARE_BOUND
                        ),
                        evidence_digest=outcome.outcome_digest,
                        blockers=(),
                    )
                )
            elif (
                outcome.state is DeployPostStoragePrepareOutcomeState.OWNED_NOOP_CURRENT
            ):
                if (
                    prior.status is not DeployBaseOsReconciledStepStatus.NOT_PERFORMED
                    or prior.evidence_state
                    is not DeployBaseOsReconciledEvidenceState.NOT_REQUIRED
                    or prior.blockers
                ):
                    raise StateConflictError(
                        "post-storage-prepare owned-noop step drifted"
                    )
                result.append(replace(prior, prior_reconciled_step_digest=prior_digest))
            else:
                if prior.status is not DeployBaseOsReconciledStepStatus.BLOCKED:
                    raise StateConflictError(
                        "post-storage-prepare blocked step drifted"
                    )
                result.append(replace(prior, prior_reconciled_step_digest=prior_digest))
            continue
        if prior.mapping_sequence == _POSTCHECK_MAPPING:
            _validate_storage_step(prior, _POSTCHECK_PLAYBOOK, destructive=False)
            outcome = outcomes[prior.target_ids[0]]
            if outcome.current:
                result.append(
                    replace(
                        prior,
                        prior_reconciled_step_digest=prior_digest,
                        status=DeployBaseOsReconciledStepStatus.ELIGIBLE,
                        evidence_state=(
                            DeployBaseOsReconciledEvidenceState.NEXT_GATES_EVALUATED
                        ),
                        evidence_digest=_postcheck_gate_digest(prior, outcome),
                        blockers=(),
                    )
                )
            else:
                if prior.status in {
                    DeployBaseOsReconciledStepStatus.ELIGIBLE,
                    DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
                }:
                    raise StateConflictError(
                        "post-storage-prepare blocked postcheck step drifted"
                    )
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
        if prior.mapping_sequence > _POSTCHECK_MAPPING and prior.status in {
            DeployBaseOsReconciledStepStatus.ELIGIBLE,
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
        }:
            raise StateConflictError("post-storage-prepare refuses later-gate leapfrog")
        result.append(replace(prior, prior_reconciled_step_digest=prior_digest))
    return tuple(result)


def _validate_storage_step(
    step: DeployBaseOsReconciledStep,
    playbook: str,
    *,
    destructive: bool,
) -> None:
    expected_class = (
        OperationClassification.DESTRUCTIVE
        if destructive
        else OperationClassification.READ_ONLY
    )
    if (
        step.playbook != playbook
        or step.condition_state is not DeployConditionState.ACTIVE
        or step.classification is not expected_class
        or step.target_role != "scylla"
        or len(step.target_ids) != 1
        or step.target_digest != _digest_object(list(step.target_ids))
        or get_playbook(playbook).classification is not expected_class
    ):
        raise StateConflictError(
            f"post-storage-prepare {playbook} step identity drifted"
        )


def _postcheck_gate_digest(
    step: DeployBaseOsReconciledStep,
    outcome: DeployPostStoragePrepareOutcome,
) -> str:
    return _digest_object(
        {
            "device_set_digest": outcome.device_set_digest,
            "mapping_sequence": step.mapping_sequence,
            "mutation_performed": outcome.mutation_performed,
            "outcome_digest": outcome.outcome_digest,
            "playbook": step.playbook,
            "preparation_intent_digest": outcome.preparation_intent_digest,
            "source_evidence_digest": outcome.source_evidence_digest,
            "source_state": outcome.state.value,
            "target_digest": step.target_digest,
        }
    )


def _build_record(
    context: _ReconciliationContext,
    *,
    steps: tuple[DeployBaseOsReconciledStep, ...],
    created_at: str,
) -> DeployPostStoragePrepareReconciliation:
    authorization_context = context.authorization_context
    preflight = authorization_context.preflight
    loaded = preflight.discovery.post.chain.authorization_context.final_routes.post.post.base.host.loaded
    planning = loaded.planning
    deploy = planning.base.deploy
    trust = planning.base.trust
    prior = authorization_context.reconciliation
    scopes = _postcheck_scopes(context.outcomes)
    counts = Counter(step.status for step in steps)
    blockers = tuple(sorted({item for step in steps for item in step.blockers}))
    authorization = context.authorization
    execution = context.execution
    evidence = context.evidence
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": preflight.metadata.cluster_uuid,
        "cluster_name": preflight.metadata.cluster_name,
        "operation_id": prior.record.operation_id,
        "operation": _OPERATION,
        "request_digest": prior.record.request_digest,
        "journal_generation": prior.record.journal_generation,
        "journal_digest": prior.record.journal_digest,
        "journal_status": prior.record.journal_status,
        "journal_phase": prior.record.journal_phase,
        "prior_reconciliation_artifact_digest": prior.artifact_digest,
        "prior_reconciliation_record_digest": prior.record.record_digest,
        "prior_effective_plan_digest": prior.record.effective_plan_digest,
        "authorization_artifact_digest": (
            None if authorization is None else authorization.artifact_digest
        ),
        "authorization_digest": (
            None if authorization is None else authorization.record.authorization_digest
        ),
        "general_proof_digest": (
            None
            if authorization is None
            else authorization.record.general_proof.proof_digest
        ),
        "wipe_proof_digest": (
            None
            if authorization is None or authorization.record.wipe_proof is None
            else authorization.record.wipe_proof.proof_digest
        ),
        "execution_artifact_digest": (
            None if execution is None else execution.artifact_digest
        ),
        "execution_binding_digest": (
            None if execution is None else execution.record.binding.binding_digest
        ),
        "evidence_artifact_digest": (
            None if evidence is None else evidence.artifact_digest
        ),
        "evidence_binding_digest": (
            None if evidence is None else evidence.record.binding.binding_digest
        ),
        "inventory_generation": deploy.inventory.record.generation,
        "inventory_artifact_digest": deploy.inventory.digest,
        "inventory_digest": deploy.inventory.record.inventory_digest,
        "trust_generation": trust.record.generation,
        "trust_artifact_digest": trust.digest,
        "trust_entries_digest": trust.record.entries_digest,
        "readiness_artifact_digest": planning.readiness.artifact_digest,
        "readiness_record_digest": planning.readiness.record.record_digest,
        "observation_generation": deploy.observation.record.generation,
        "observation_artifact_digest": deploy.observation.digest,
        "observation_manifest_digest": deploy.observation.record.manifest_digest,
        "catalog_digest": loaded.catalog_digest,
        "ansible_source_version": loaded.source.version,
        "ansible_source_digest": loaded.source.digest,
        "outcomes": context.outcomes,
        "target_count": len(context.outcomes),
        "target_set_digest": _digest_object(
            [item.stable_id for item in context.outcomes]
        ),
        "outcome_digest": _digest_object(
            [item.to_object() for item in context.outcomes]
        ),
        "prepare_required_count": sum(
            item.state is DeployPostStoragePrepareOutcomeState.PREPARE_SUCCEEDED
            for item in context.outcomes
        ),
        "prepare_succeeded_count": sum(
            item.state is DeployPostStoragePrepareOutcomeState.PREPARE_SUCCEEDED
            for item in context.outcomes
        ),
        "owned_noop_current_count": sum(
            item.state is DeployPostStoragePrepareOutcomeState.OWNED_NOOP_CURRENT
            for item in context.outcomes
        ),
        "blocked_count": sum(
            item.state is DeployPostStoragePrepareOutcomeState.BLOCKED
            for item in context.outcomes
        ),
        "wipe_required_count": sum(item.wipe_required for item in context.outcomes),
        "wipe_applied_count": sum(item.wipe_applied for item in context.outcomes),
        "general_authorization_consumed": (
            False
            if execution is None
            else execution.record.general_authorization_consumed
        ),
        "wipe_authorization_consumed_count": (
            0
            if execution is None
            else execution.record.wipe_authorization_consumed_count
        ),
        "postcheck_scopes": scopes,
        "postcheck_target_count": len(scopes),
        "postcheck_target_set_digest": _digest_object(
            [item.stable_id for item in scopes]
        ),
        "postcheck_scope_digest": _digest_object([item.to_object() for item in scopes]),
        "steps": steps,
        "step_count": len(steps),
        "succeeded_count": counts[DeployBaseOsReconciledStepStatus.SUCCEEDED],
        "authorization_required_count": counts[
            DeployBaseOsReconciledStepStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        ],
        "eligible_count": counts[DeployBaseOsReconciledStepStatus.ELIGIBLE],
        "plan_blocked_count": counts[DeployBaseOsReconciledStepStatus.BLOCKED],
        "not_performed_count": counts[DeployBaseOsReconciledStepStatus.NOT_PERFORMED],
        "blocker_set": blockers,
        "blocker_digest": _digest_object(list(blockers)),
        "effective_plan_digest": _digest_object([step.to_object() for step in steps]),
        "next_execution_state": _NOT_STARTED,
        "finalization_state": _NOT_STARTED,
        "public_workflow_state": _UNAVAILABLE,
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(values)
    return DeployPostStoragePrepareReconciliation(**values)  # type: ignore[arg-type]


def _build_report(
    stored: StoredDeployPostStoragePrepareReconciliation,
    *,
    state: DeployPostStoragePrepareArtifactState,
) -> DeployPostStoragePrepareReconciliationReport:
    record = stored.record
    return DeployPostStoragePrepareReconciliationReport(
        operation_id=record.operation_id,
        artifact_state=state,
        reconciliation_artifact_digest=stored.artifact_digest,
        reconciliation_record_digest=record.record_digest,
        effective_plan_digest=record.effective_plan_digest,
        target_count=record.target_count,
        target_set_digest=record.target_set_digest,
        outcome_digest=record.outcome_digest,
        prepare_required_count=record.prepare_required_count,
        prepare_succeeded_count=record.prepare_succeeded_count,
        owned_noop_current_count=record.owned_noop_current_count,
        blocked_count=record.blocked_count,
        wipe_required_count=record.wipe_required_count,
        wipe_applied_count=record.wipe_applied_count,
        general_authorization_consumed=record.general_authorization_consumed,
        wipe_authorization_consumed_count=(record.wipe_authorization_consumed_count),
        postcheck_target_count=record.postcheck_target_count,
        postcheck_target_set_digest=record.postcheck_target_set_digest,
        postcheck_scope_digest=record.postcheck_scope_digest,
        succeeded_count=record.succeeded_count,
        eligible_count=record.eligible_count,
        authorization_required_count=record.authorization_required_count,
        plan_blocked_count=record.plan_blocked_count,
        not_performed_count=record.not_performed_count,
        blocker_set=record.blocker_set,
        blocker_digest=record.blocker_digest,
        journal_status=record.journal_status,
        journal_phase=record.journal_phase,
        next_execution_state=record.next_execution_state,
        finalization_state=record.finalization_state,
        public_workflow_state=record.public_workflow_state,
    )


def _outcome_digest(outcome: DeployPostStoragePrepareOutcome) -> str:
    value = outcome.to_object()
    value["outcome_digest"] = ""
    return _digest_object(value)


def _outcome_digest_from_values(values: Mapping[str, object]) -> str:
    value = {
        name: (item.value if isinstance(item, StrEnum) else item)
        for name, item in values.items()
    }
    value["outcome_digest"] = ""
    return _digest_object(value)


def _postcheck_scope_digest(scope: DeployStoragePostcheckScope) -> str:
    value = scope.to_object()
    value["scope_digest"] = ""
    return _digest_object(value)


def _postcheck_scope_digest_from_values(values: Mapping[str, object]) -> str:
    value = {
        name: (item.value if isinstance(item, StrEnum) else item)
        for name, item in values.items()
    }
    value["scope_digest"] = ""
    return _digest_object(value)


def _record_digest(record: DeployPostStoragePrepareReconciliation) -> str:
    value = record.to_object()
    value["record_digest"] = ""
    return _digest_object(value)


def _record_digest_from_values(values: Mapping[str, object]) -> str:
    value: dict[str, object] = {}
    for (
        name,
        field,
    ) in DeployPostStoragePrepareReconciliation.__dataclass_fields__.items():
        item = values.get(name, field.default)
        value[name] = (
            str(item)
            if isinstance(item, uuid.UUID)
            else item.value
            if isinstance(item, (JournalStatus, OperationPhase, StrEnum))
            else [entry.to_object() for entry in item]
            if name in {"outcomes", "postcheck_scopes", "steps"}
            and isinstance(item, tuple)
            else list(item)
            if name == "blocker_set" and isinstance(item, tuple)
            else item
        )
    value["record_digest"] = ""
    return _digest_object(value)


def _refuse_ambiguous_or_later_artifacts(
    paths: StatePaths, operation_id: uuid.UUID
) -> None:
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list post-storage-prepare artifacts"
        ) from error
    canonical = str(operation_id)
    suffix = DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_FILENAME_SUFFIX
    for entry in entries:
        if entry.name.endswith(suffix):
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
                    "post-storage-prepare reconciliation artifacts are ambiguous"
                )
        if entry.name.startswith(canonical) and (
            ".ansible-deploy-storage-postcheck" in entry.name
            or ".ansible-deploy-post-storage-postcheck" in entry.name
            or ".ansible-deploy-scylla-install" in entry.name
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "post-storage-prepare reconciliation refuses later-stage history"
            )


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "post-storage-prepare reconciliation paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "post-storage-prepare reconciliation requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _require_operation_id(value: uuid.UUID) -> uuid.UUID:
    if not isinstance(value, uuid.UUID):
        raise StatePersistenceError("post-storage-prepare operation ID is invalid")
    return value


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
        raise StatePersistenceError(f"{label} is invalid") from error


__all__ = [
    "ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_SCHEMA_VERSION",
    "DEPLOY_POST_STORAGE_PREPARE_RECONCILIATION_FILENAME_SUFFIX",
    "DeployPostStoragePrepareArtifactState",
    "DeployPostStoragePrepareOutcome",
    "DeployPostStoragePrepareOutcomeState",
    "DeployPostStoragePrepareReconciliation",
    "DeployPostStoragePrepareReconciliationReport",
    "DeployPostStoragePrepareReconciliationStore",
    "DeployStoragePostcheckScope",
    "StoredDeployPostStoragePrepareReconciliation",
    "deploy_post_storage_prepare_reconciliation_id_from_filename",
    "deploy_post_storage_prepare_reconciliation_path",
    "reconcile_deploy_storage_prepare",
]
