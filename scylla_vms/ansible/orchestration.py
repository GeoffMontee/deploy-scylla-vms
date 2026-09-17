"""Offline, non-executing resolution of operation-to-playbook plans."""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from scylla_vms.ansible.readiness import EvidenceStatus, ReadinessReport
from scylla_vms.ansible.registry import (
    OPERATION_PLAYBOOKS,
    PLAYBOOKS,
    OperationPlaybookStep,
    PlaybookDefinition,
    get_playbook,
)
from scylla_vms.errors import AnsibleError, StateConflictError
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.journal import (
    CheckpointEvidence,
    EvidenceResult,
    OperationPhase,
)
from scylla_vms.operations import (
    OPERATIONS,
    OperationClassification,
    get_operation,
)
from scylla_vms.persistence import (
    ClusterMetadata,
    digest_bytes,
    serialize_json,
)
from scylla_vms.state import StatePaths

ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION = "deploy-scylla-vms.ansible-operation-plan/v1"
_CLASSIFICATION_RANK = {
    OperationClassification.READ_ONLY: 0,
    OperationClassification.MUTATING: 1,
    OperationClassification.SENSITIVE: 2,
    OperationClassification.DESTRUCTIVE: 3,
}
_CONDITION = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_CATALOG_BINDING_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-operation-catalog-binding/v1"
)
_MUTUALLY_EXCLUSIVE_CONDITIONS = {
    "destroy-node": (frozenset({"dead", "live"}),),
    "scale-in": (frozenset({"dead", "live"}),),
    "upgrade-os": (frozenset({"in-place", "reprovision"}),),
}


class HeldClusterLockProtocol(Protocol):
    def assert_held_for(self, paths: StatePaths) -> None:
        """Prove this lock protects the requested canonical state."""


class AnsibleOperationPlanPolicyProtocol(Protocol):
    @property
    def paths(self) -> StatePaths:
        """Return the canonical state identity protected by the caller's lock."""

    def validate_playbook_request(
        self,
        name: str,
        *,
        limit: tuple[str, ...],
        tags: tuple[str, ...] = (),
        check: bool = False,
        diff: bool = False,
        verbosity: int = 0,
    ) -> tuple[PlaybookDefinition, str]:
        """Validate one registry-positioned playbook intent without execution."""


class AnsibleOperationPlanStatus(StrEnum):
    READY = "ready"
    BLOCKED = "blocked"


class AnsibleOperationStepStatus(StrEnum):
    READY = "ready"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class AnsibleStepIntent:
    """Internal caller input for one selected, registry-positioned step."""

    sequence: int
    limit: tuple[str, ...]
    variables: Mapping[str, object] = field(repr=False)
    tags: tuple[str, ...] = ()
    check: bool = False
    diff: bool = False
    verbosity: int = 0
    health_gate_passed: bool = False

    def __post_init__(self) -> None:
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 1
        ):
            raise AnsibleError("Ansible operation step sequence is invalid")
        if not isinstance(self.limit, tuple) or not isinstance(self.tags, tuple):
            raise AnsibleError("Ansible operation step collections must be immutable")
        if not all(isinstance(value, str) for value in (*self.limit, *self.tags)):
            raise AnsibleError("Ansible operation step collections are invalid")
        if not isinstance(self.variables, Mapping) or not all(
            isinstance(name, str) for name in self.variables
        ):
            raise AnsibleError("Ansible operation step variables are invalid")
        if (
            not isinstance(self.check, bool)
            or not isinstance(self.diff, bool)
            or not isinstance(self.health_gate_passed, bool)
        ):
            raise AnsibleError("Ansible operation step flags are invalid")


@dataclass(frozen=True, slots=True)
class AnsibleOperationPlanStep:
    sequence: int
    playbook: str
    condition: str
    classification: OperationClassification
    status: AnsibleOperationStepStatus
    limit: tuple[str, ...]
    variable_names: tuple[str, ...]
    variables_digest: str | None
    check_mode: bool | None
    blockers: tuple[str, ...]

    def to_public_object(self) -> dict[str, object]:
        """Project stable IDs and digests, never variable values or endpoints."""

        return {
            "blockers": list(self.blockers),
            "check_mode": self.check_mode,
            "classification": self.classification.value,
            "condition": self.condition,
            "limit": list(self.limit),
            "playbook": self.playbook,
            "sequence": self.sequence,
            "status": self.status.value,
            "variable_names": list(self.variable_names),
            "variables_digest": self.variables_digest,
        }


@dataclass(frozen=True, slots=True)
class AnsibleOperationPlan:
    operation: str
    operation_classification: OperationClassification
    effective_classification: OperationClassification
    operation_implemented: bool
    active_conditions: tuple[str, ...]
    status: AnsibleOperationPlanStatus
    blockers: tuple[str, ...]
    steps: tuple[AnsibleOperationPlanStep, ...]
    schema_version: str = ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION

    @property
    def plan_digest(self) -> str:
        return digest_bytes(serialize_json(self._object(include_digest=False)))

    def to_public_object(self) -> dict[str, object]:
        """Return a deterministic address-, key-, path-, and value-free report."""

        return self._object(include_digest=True)

    def _object(self, *, include_digest: bool) -> dict[str, object]:
        value: dict[str, object] = {
            "active_conditions": list(self.active_conditions),
            "blockers": list(self.blockers),
            "effective_classification": self.effective_classification.value,
            "operation": self.operation,
            "operation_classification": self.operation_classification.value,
            "operation_implemented": self.operation_implemented,
            "schema_version": self.schema_version,
            "status": self.status.value,
            "steps": [step.to_public_object() for step in self.steps],
        }
        if include_digest:
            value["plan_digest"] = self.plan_digest
        return value


def ansible_operation_catalog_digest() -> str:
    """Digest every operation/playbook policy field that can shape a plan."""

    return digest_bytes(
        serialize_json(
            {
                "operations": [
                    {
                        "classification": operation.classification.value,
                        "implemented": operation.implemented,
                        "name": operation.name,
                        "steps": [
                            {
                                "condition": step.condition,
                                "playbook": step.playbook,
                            }
                            for step in OPERATION_PLAYBOOKS[operation.name]
                        ],
                    }
                    for operation in OPERATIONS
                ],
                "playbooks": [
                    {
                        "any_errors_fatal": playbook.any_errors_fatal,
                        "check_mode": playbook.check_mode.value,
                        "classification": playbook.classification.value,
                        "diff_mode": playbook.diff_mode,
                        "execution_result_schema_version": (
                            playbook.execution_result_schema_version
                        ),
                        "host_key_gate_required": (playbook.host_key_gate_required),
                        "inventory_freshness_required": (
                            playbook.inventory_freshness_required
                        ),
                        "limit_policy": playbook.limit_policy.value,
                        "name": playbook.name,
                        "post_health_gate": playbook.post_health_gate,
                        "pre_health_gate": playbook.pre_health_gate,
                        "serial": playbook.serial,
                        "source_available": playbook.source_available,
                        "tags": list(playbook.tags),
                        "target_groups": list(playbook.target_groups),
                        "variables": [
                            {
                                "choices": list(variable.choices),
                                "name": variable.name,
                                "type": variable.value_type.value,
                            }
                            for variable in playbook.variables
                        ],
                    }
                    for playbook in PLAYBOOKS
                ],
                "schema_version": _CATALOG_BINDING_SCHEMA_VERSION,
            }
        )
    )


def validate_operation_playbook_catalog(
    mappings: Mapping[str, tuple[OperationPlaybookStep, ...]] = OPERATION_PLAYBOOKS,
) -> None:
    """Fail closed on incomplete or statically unsafe operation mappings."""

    operations = {operation.name: operation for operation in OPERATIONS}
    if set(mappings) != set(operations):
        raise AnsibleError("Ansible operation mapping coverage conflicts")
    for name, operation in operations.items():
        steps = mappings[name]
        if not isinstance(steps, tuple) or not all(
            isinstance(step, OperationPlaybookStep) for step in steps
        ):
            raise AnsibleError("Ansible operation mapping steps are invalid")
        if name == "show":
            if steps:
                raise AnsibleError("read-only show must not map to Ansible playbooks")
            continue
        if not steps or (
            steps[0].playbook != "inventory-preflight" or steps[0].condition != "always"
        ):
            raise AnsibleError(
                "Ansible operation mapping must begin with inventory preflight"
            )
        for step in steps:
            if not _CONDITION.fullmatch(step.condition):
                raise AnsibleError("Ansible operation mapping condition is invalid")
            definition = get_playbook(step.playbook)
            if operation.classification is OperationClassification.READ_ONLY and (
                definition.classification is not OperationClassification.READ_ONLY
            ):
                raise AnsibleError(
                    "read-only operation maps to a mutating Ansible playbook"
                )


def build_ansible_operation_plan(
    lock: HeldClusterLockProtocol,
    builder: AnsibleOperationPlanPolicyProtocol,
    metadata: ClusterMetadata,
    inventory: StoredInventoryRecord,
    operation_name: str,
    *,
    readiness: ReadinessReport,
    active_conditions: tuple[str, ...],
    intents: tuple[AnsibleStepIntent, ...],
) -> AnsibleOperationPlan:
    """Resolve and validate one operation plan without writing or running tools."""

    lock.assert_held_for(builder.paths)
    validate_operation_playbook_catalog()
    try:
        operation = get_operation(operation_name)
    except KeyError as error:
        raise AnsibleError("Ansible operation is not registry-approved") from error
    if (
        metadata.cluster_uuid != inventory.record.cluster_uuid
        or metadata.cluster_name != inventory.record.cluster_name
        or metadata.provider != inventory.record.provider
    ):
        raise StateConflictError("Ansible operation plan state identities conflict")
    if (
        readiness.inventory_generation != inventory.record.generation
        or readiness.inventory_digest != inventory.digest
    ):
        raise StateConflictError("Ansible operation plan readiness is stale")
    if not isinstance(intents, tuple) or not all(
        isinstance(intent, AnsibleStepIntent) for intent in intents
    ):
        raise AnsibleError("Ansible operation step intents must be immutable")
    if (
        not isinstance(active_conditions, tuple)
        or not all(isinstance(value, str) and value for value in active_conditions)
        or active_conditions != tuple(sorted(set(active_conditions)))
    ):
        raise AnsibleError(
            "Ansible operation conditions must be unique and deterministically ordered"
        )

    mapped = OPERATION_PLAYBOOKS[operation_name]
    documented_conditions = {
        step.condition for step in mapped if step.condition != "always"
    }
    unknown_conditions = set(active_conditions) - documented_conditions
    if unknown_conditions:
        raise AnsibleError("Ansible operation condition is not registry-approved")
    selected_conditions = set(active_conditions)
    for exclusive in _MUTUALLY_EXCLUSIVE_CONDITIONS.get(operation_name, ()):
        if len(selected_conditions & exclusive) > 1:
            raise AnsibleError("Ansible operation conditions are mutually exclusive")

    intents_by_sequence: dict[int, AnsibleStepIntent] = {}
    for provided_intent in intents:
        if provided_intent.sequence in intents_by_sequence:
            raise AnsibleError("Ansible operation step intent is duplicated")
        intents_by_sequence[provided_intent.sequence] = provided_intent
    selected_sequences = {
        sequence
        for sequence, step in enumerate(mapped, start=1)
        if step.condition == "always" or step.condition in selected_conditions
    }
    if set(intents_by_sequence) - selected_sequences:
        raise AnsibleError(
            "Ansible step intent does not match a selected operation mapping"
        )

    planned_steps: list[AnsibleOperationPlanStep] = []
    selected_classifications: list[OperationClassification] = []
    for sequence, mapped_step in enumerate(mapped, start=1):
        definition = get_playbook(mapped_step.playbook)
        selected = sequence in selected_sequences
        if not selected:
            planned_steps.append(
                AnsibleOperationPlanStep(
                    sequence,
                    definition.name,
                    mapped_step.condition,
                    definition.classification,
                    AnsibleOperationStepStatus.SKIPPED,
                    (),
                    (),
                    None,
                    None,
                    (),
                )
            )
            continue
        selected_classifications.append(definition.classification)
        intent = intents_by_sequence.get(sequence)
        blockers: list[str] = []
        limit: tuple[str, ...] = ()
        variable_names: tuple[str, ...] = ()
        variables_digest: str | None = None
        check_mode: bool | None = None
        if not definition.source_available:
            blockers.append("source-unavailable")
        if intent is None:
            blockers.append("step-intent-missing")
        else:
            builder.validate_playbook_request(
                definition.name,
                limit=intent.limit,
                tags=intent.tags,
                check=intent.check,
                diff=intent.diff,
                verbosity=intent.verbosity,
            )
            _validate_limit_membership(definition.hosts, intent.limit, inventory)
            validated_variables = definition.validate_variables(dict(intent.variables))
            limit = intent.limit
            variable_names = tuple(validated_variables)
            variables_digest = digest_bytes(serialize_json(validated_variables))
            check_mode = intent.check
            if (
                operation.classification is OperationClassification.READ_ONLY
                and not intent.check
            ):
                blockers.append("read-only-check-mode-required")
            blockers.extend(_readiness_blockers(definition.name, readiness))
            if definition.pre_health_gate and not intent.health_gate_passed:
                blockers.append("pre-health-gate-unsatisfied")
        planned_steps.append(
            AnsibleOperationPlanStep(
                sequence,
                definition.name,
                mapped_step.condition,
                definition.classification,
                (
                    AnsibleOperationStepStatus.BLOCKED
                    if blockers
                    else AnsibleOperationStepStatus.READY
                ),
                limit,
                variable_names,
                variables_digest,
                check_mode,
                tuple(sorted(set(blockers))),
            )
        )

    effective = max(
        [operation.classification, *selected_classifications],
        key=_CLASSIFICATION_RANK.__getitem__,
    )
    blockers = []
    if not operation.implemented:
        blockers.append("operation-workflow-unavailable")
    if any(step.status is AnsibleOperationStepStatus.BLOCKED for step in planned_steps):
        blockers.append("selected-step-blocked")
    status = (
        AnsibleOperationPlanStatus.BLOCKED
        if blockers
        else AnsibleOperationPlanStatus.READY
    )
    return AnsibleOperationPlan(
        operation.name,
        operation.classification,
        effective,
        operation.implemented,
        active_conditions,
        status,
        tuple(blockers),
        tuple(planned_steps),
    )


def ansible_operation_plan_checkpoint_evidence(
    plan: AnsibleOperationPlan,
) -> CheckpointEvidence:
    """Bind a validated or blocked offline plan to the common journal schema."""

    return CheckpointEvidence(
        OperationPhase.PLAN,
        (
            EvidenceResult.VALIDATED
            if plan.status is AnsibleOperationPlanStatus.READY
            else EvidenceResult.FAILED
        ),
        plan.plan_digest,
        (
            "ansible-operation-plan-ready"
            if plan.status is AnsibleOperationPlanStatus.READY
            else "ansible-operation-plan-blocked"
        ),
    )


def _readiness_blockers(playbook: str, readiness: ReadinessReport) -> tuple[str, ...]:
    if playbook == "inventory-preflight":
        blockers = []
        if readiness.source_status is not EvidenceStatus.FRESH:
            blockers.append(f"source-{readiness.source_status.value}")
        if readiness.machine_status is not EvidenceStatus.FRESH:
            blockers.append(f"inventory-machine-{readiness.machine_status.value}")
        return tuple(blockers)
    definition = get_playbook(playbook)
    return tuple(
        f"readiness-{blocker}"
        for blocker in readiness.blockers_for(definition.classification)
    )


def _validate_limit_membership(
    target_groups: str,
    limit: tuple[str, ...],
    inventory: StoredInventoryRecord,
) -> None:
    host_ids = {host.logical_id for host in inventory.record.inventory.hosts}
    if not limit or not set(limit) <= host_ids:
        raise StateConflictError(
            "Ansible operation limit contains an unknown stable logical host ID"
        )
    if target_groups == "all":
        return
    groups = {
        group.name: set(group.hosts) for group in inventory.record.inventory.groups
    }
    allowed: set[str] = set()
    for group in target_groups.split(":"):
        allowed.update(groups.get(group, set()))
    if not set(limit) <= allowed:
        raise StateConflictError("Ansible operation limit is outside target groups")
