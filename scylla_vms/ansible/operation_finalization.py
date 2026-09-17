"""Internal post-verification and common-journal finalization."""

from __future__ import annotations

import ipaddress
import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.commands import validate_playbook_request_policy
from scylla_vms.ansible.operation_authorization import OperationAuthorizationStore
from scylla_vms.ansible.operation_binding import (
    ANSIBLE_OPERATION_BINDING_SCHEMA_VERSION,
    ConfirmationState,
    ExecutionState,
    OperationPlanBindingStore,
    StoredOperationPlanBinding,
    normalized_operation_request_digest,
    readiness_binding_digest,
)
from scylla_vms.ansible.operation_context import (
    ANSIBLE_OPERATION_CONTEXT_SCHEMA_VERSION,
    CHECK_JUMP_HOSTS_CONTEXT_SCHEMA_VERSION,
    JumpHostDepth,
    JumpHostDestination,
    OperationContextStore,
    StoredOperationContext,
    reconstruct_operation_context,
)
from scylla_vms.ansible.operation_coordinator import CanonicalAnsibleOperationContext
from scylla_vms.ansible.operation_evidence import (
    ANSIBLE_OPERATION_EVIDENCE_SCHEMA_VERSION,
    CheckJumpHostsSemanticFacts,
    DestinationPairProjection,
    InventoryPreflightStatus,
    OperationEvidenceStore,
    StoredOperationEvidence,
    reconstruct_check_jump_hosts_semantic_facts,
    validate_operation_evidence_checkpoint,
)
from scylla_vms.ansible.operation_execution import (
    ANSIBLE_OPERATION_EXECUTION_SCHEMA_VERSION,
    ExecutionAttemptState,
    OperationExecutionStore,
    StoredOperationExecution,
)
from scylla_vms.ansible.operation_orchestrator import (
    PreparedCheckJumpHostsStep,
    reconstruct_prepared_check_jump_hosts_steps,
    validate_check_jump_hosts_evidence_receipts,
    validate_prepared_check_jump_hosts_execution,
)
from scylla_vms.ansible.orchestration import (
    ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION,
    AnsibleOperationPlan,
    AnsibleOperationPlanStatus,
    ansible_operation_catalog_digest,
    ansible_operation_plan_checkpoint_evidence,
    build_ansible_operation_plan,
)
from scylla_vms.ansible.readiness import (
    READINESS_SCHEMA_VERSION,
    EvidenceStatus,
    InventoryMachineEvidence,
    ReadinessReport,
    RouteReadiness,
    build_readiness_report,
)
from scylla_vms.ansible.registry import PlaybookDefinition
from scylla_vms.ansible.service import (
    ConnectivityStatus,
    DestinationProbeStatus,
    HostConnectivityStatus,
)
from scylla_vms.ansible.source import (
    load_ansible_source_bundle,
    validate_ansible_config,
)
from scylla_vms.ansible.trust import StoredTrustRecord, TrustStore
from scylla_vms.desired import HostRole, resolve_existing_config
from scylla_vms.errors import (
    ConfigurationError,
    ExitCode,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.inventory import InventoryStore, StoredInventoryRecord
from scylla_vms.journal import (
    JOURNAL_SCHEMA_VERSION,
    CheckpointEvidence,
    EvidenceResult,
    JournalStatus,
    OperationJournalStore,
    OperationPhase,
    StoredOperationRecord,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.models import OperationRequest
from scylla_vms.observed import ObservedStateStore, StoredObservedState
from scylla_vms.operations import OperationClassification, get_operation
from scylla_vms.persistence import (
    AtomicJsonFile,
    ClusterMetadataStore,
    StoredClusterMetadata,
    digest_bytes,
    parse_uuid,
    require_exact_keys,
    require_string,
    serialize_json,
    validate_digest,
)
from scylla_vms.reconciliation import (
    ReconciliationClass,
    reconcile_desired_observed,
)
from scylla_vms.state import (
    StatePaths,
    refuse_unexpected_terraform_state,
    validate_cluster_name,
    validate_state_directory,
    validate_state_file,
)
from scylla_vms.validation import DESTINATION_CHECK_PORTS

ANSIBLE_CHECK_JUMP_HOSTS_RESULT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-check-jump-hosts-result/v1"
)
ANSIBLE_OPERATION_FINALIZATION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-operation-finalization/v1"
)
ANSIBLE_OPERATION_FINALIZATION_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-operation-finalization-report/v1"
)
OPERATION_FINALIZATION_FILENAME_SUFFIX = ".ansible-operation-finalization.json"

_OPERATION = "check-jump-hosts"
_EXPECTED_PLAYBOOKS = ("inventory-preflight", "connectivity-check")
_MAX_DESTINATION_PROBES = 64
_SOURCE_VERSION = re.compile(r"[a-z][a-z0-9-]{0,63}/v[1-9][0-9]{0,8}\Z")
_SAFE_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HOST_KEY_OR_FINGERPRINT = re.compile(
    r"(?:ssh-(?:ed25519|rsa)|ecdsa-sha2-nistp256)(?::|$)"
    r"|sha256:[A-Za-z0-9+/=]{16,}\Z",
    re.IGNORECASE,
)
_PROTECTED_COMPONENTS = frozenset(
    {
        "credential",
        "credentials",
        "passphrase",
        "passwd",
        "password",
        "privatekey",
        "secret",
        "stderr",
        "stdout",
        "token",
        "vault",
    }
)
_REPORT_SCHEMA_NAMES = (
    "binding",
    "context",
    "context_values",
    "evidence",
    "execution",
    "finalization",
    "journal",
    "plan",
    "readiness",
    "result",
)
_REPORT_DIGEST_NAMES = (
    "binding",
    "catalog",
    "context",
    "evidence",
    "execution",
    "finalization",
    "inventory",
    "journal",
    "observation",
    "plan",
    "readiness",
    "request",
    "result",
    "source",
    "trust",
)


class DestinationCheckStatus(StrEnum):
    SUCCESS = "success"
    NOT_PERFORMED = "not-performed"


class FinalizationCompanionState(StrEnum):
    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True, slots=True)
class FinalizedJumpHost:
    """One minimal address-free jump-host semantic result row."""

    logical_id: str
    trust: str
    connectivity: HostConnectivityStatus

    def __post_init__(self) -> None:
        _safe_label(self.logical_id, "finalized jump-host stable ID")
        if self.trust != "verified" or not isinstance(
            self.connectivity, HostConnectivityStatus
        ):
            raise StatePersistenceError("finalized jump-host result is invalid")

    def to_object(self) -> dict[str, object]:
        return {
            "connectivity": self.connectivity.value,
            "logical_id": self.logical_id,
            "trust": self.trust,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> FinalizedJumpHost:
        require_exact_keys(
            value,
            {"connectivity", "logical_id", "trust"},
            "finalized jump-host result",
        )
        try:
            connectivity = HostConnectivityStatus(require_string(value, "connectivity"))
        except ValueError as error:
            raise StatePersistenceError(
                "finalized jump-host connectivity is invalid"
            ) from error
        return cls(
            require_string(value, "logical_id"),
            require_string(value, "trust"),
            connectivity,
        )


@dataclass(frozen=True, slots=True)
class CheckJumpHostsFinalizedResult:
    """Strict public-v2 semantic result without addresses or runtime data."""

    depth: JumpHostDepth
    destinations: tuple[JumpHostDestination, ...]
    selected_stable_ids: tuple[str, ...]
    inventory_host_count: int
    inventory_target_count: int
    inventory_machine: EvidenceStatus
    inventory_preflight: InventoryPreflightStatus
    route_validation: RouteReadiness
    connectivity: ConnectivityStatus
    destination_tcp: DestinationCheckStatus
    target_ssh: str
    jumps: tuple[FinalizedJumpHost, ...]
    destination_probes: tuple[DestinationPairProjection, ...]
    exit_code: int
    schema_version: str = ANSIBLE_CHECK_JUMP_HOSTS_RESULT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_CHECK_JUMP_HOSTS_RESULT_SCHEMA_VERSION
            or not isinstance(self.depth, JumpHostDepth)
            or not isinstance(self.destinations, tuple)
            or not self.destinations
            or not all(
                isinstance(item, JumpHostDestination) for item in self.destinations
            )
            or self.destinations != tuple(dict.fromkeys(self.destinations))
            or (
                JumpHostDestination.ALL in self.destinations
                and self.destinations != (JumpHostDestination.ALL,)
            )
            or not isinstance(self.selected_stable_ids, tuple)
            or self.selected_stable_ids != tuple(sorted(set(self.selected_stable_ids)))
            or not isinstance(self.jumps, tuple)
            or not all(isinstance(item, FinalizedJumpHost) for item in self.jumps)
            or tuple(item.logical_id for item in self.jumps) != self.selected_stable_ids
            or not isinstance(self.destination_probes, tuple)
            or len(self.destination_probes) > _MAX_DESTINATION_PROBES
            or not all(
                isinstance(item, DestinationPairProjection)
                for item in self.destination_probes
            )
        ):
            raise StatePersistenceError("finalized check-jump-hosts result is invalid")
        for stable_id in self.selected_stable_ids:
            _safe_label(stable_id, "finalized selected stable ID")
        probe_keys = tuple(item.key for item in self.destination_probes)
        destination_roles = (
            set(DESTINATION_CHECK_PORTS)
            if JumpHostDestination.ASSIGNED in self.destinations
            or JumpHostDestination.ALL in self.destinations
            else {item.value for item in self.destinations}
        )
        if (
            probe_keys != tuple(sorted(set(probe_keys)))
            or (self.destination_probes and self.depth is JumpHostDepth.BASTION)
            or (self.depth is JumpHostDepth.ALL_TARGETS and not self.destination_probes)
            or any(
                item.jump_host_id not in self.selected_stable_ids
                or item.role not in destination_roles
                for item in self.destination_probes
            )
        ):
            raise StatePersistenceError(
                "finalized check-jump-hosts destination pairs conflict"
            )
        _bounded_count(self.inventory_host_count, 1, 4096, "finalized inventory host")
        _bounded_count(self.inventory_target_count, 1, 16, "finalized inventory target")
        if (
            self.inventory_target_count != len(self.selected_stable_ids)
            or self.inventory_target_count > self.inventory_host_count
            or self.inventory_machine is not EvidenceStatus.FRESH
            or self.inventory_preflight is not InventoryPreflightStatus.PASSED
            or self.route_validation is not RouteReadiness.VALID
            or self.connectivity is not ConnectivityStatus.SUCCESS
            or self.target_ssh != "not-performed"
            or isinstance(self.exit_code, bool)
            or not isinstance(self.exit_code, int)
            or self.exit_code != int(ExitCode.SUCCESS)
            or any(
                item.connectivity is not HostConnectivityStatus.REACHABLE
                for item in self.jumps
            )
            or any(
                item.status is not DestinationProbeStatus.PASSED
                for item in self.destination_probes
            )
        ):
            raise StatePersistenceError(
                "finalized check-jump-hosts success evidence conflicts"
            )
        expected_destination = (
            DestinationCheckStatus.SUCCESS
            if self.destination_probes
            else DestinationCheckStatus.NOT_PERFORMED
        )
        if self.destination_tcp is not expected_destination:
            raise StatePersistenceError("finalized destination-check summary conflicts")

    def to_object(self) -> dict[str, object]:
        return {
            "checks": {
                "connectivity": self.connectivity.value,
                "destination_tcp": self.destination_tcp.value,
                "inventory_machine": self.inventory_machine.value,
                "inventory_preflight": self.inventory_preflight.value,
                "route_validation": self.route_validation.value,
                "target_ssh": self.target_ssh,
            },
            "counts": {
                "destination_probes": len(self.destination_probes),
                "inventory_hosts": self.inventory_host_count,
                "selected_hosts": self.inventory_target_count,
            },
            "destination_probes": [
                item.to_object() for item in self.destination_probes
            ],
            "exit_status": {"code": self.exit_code},
            "jumps": [item.to_object() for item in self.jumps],
            "schema_version": self.schema_version,
            "selection": {
                "depth": self.depth.value,
                "destinations": [item.value for item in self.destinations],
                "stable_ids": list(self.selected_stable_ids),
            },
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> CheckJumpHostsFinalizedResult:
        require_exact_keys(
            value,
            {
                "checks",
                "counts",
                "destination_probes",
                "exit_status",
                "jumps",
                "schema_version",
                "selection",
            },
            "finalized check-jump-hosts result",
        )
        if (
            require_string(value, "schema_version")
            != ANSIBLE_CHECK_JUMP_HOSTS_RESULT_SCHEMA_VERSION
        ):
            raise StatePersistenceError(
                "unsupported finalized check-jump-hosts result schema"
            )
        checks = _object(value["checks"], "finalized result checks")
        require_exact_keys(
            checks,
            {
                "connectivity",
                "destination_tcp",
                "inventory_machine",
                "inventory_preflight",
                "route_validation",
                "target_ssh",
            },
            "finalized result checks",
        )
        counts = _object(value["counts"], "finalized result counts")
        require_exact_keys(
            counts,
            {"destination_probes", "inventory_hosts", "selected_hosts"},
            "finalized result counts",
        )
        selection = _object(value["selection"], "finalized result selection")
        require_exact_keys(
            selection,
            {"depth", "destinations", "stable_ids"},
            "finalized result selection",
        )
        exit_status = _object(value["exit_status"], "finalized result exit status")
        require_exact_keys(exit_status, {"code"}, "finalized result exit status")
        destinations = _string_list(
            selection["destinations"], "finalized result destinations"
        )
        stable_ids = _string_list(
            selection["stable_ids"], "finalized result stable IDs"
        )
        jumps = _object_list(value["jumps"], "finalized result jumps")
        probes = _object_list(
            value["destination_probes"], "finalized result destination probes"
        )
        if _integer(counts["destination_probes"], "destination probe count") != len(
            probes
        ):
            raise StatePersistenceError("finalized destination probe count conflicts")
        try:
            return cls(
                depth=JumpHostDepth(require_string(selection, "depth")),
                destinations=tuple(JumpHostDestination(item) for item in destinations),
                selected_stable_ids=stable_ids,
                inventory_host_count=_integer(
                    counts["inventory_hosts"], "finalized inventory host count"
                ),
                inventory_target_count=_integer(
                    counts["selected_hosts"], "finalized selected host count"
                ),
                inventory_machine=EvidenceStatus(
                    require_string(checks, "inventory_machine")
                ),
                inventory_preflight=InventoryPreflightStatus(
                    require_string(checks, "inventory_preflight")
                ),
                route_validation=RouteReadiness(
                    require_string(checks, "route_validation")
                ),
                connectivity=ConnectivityStatus(require_string(checks, "connectivity")),
                destination_tcp=DestinationCheckStatus(
                    require_string(checks, "destination_tcp")
                ),
                target_ssh=require_string(checks, "target_ssh"),
                jumps=tuple(FinalizedJumpHost.from_object(item) for item in jumps),
                destination_probes=tuple(
                    DestinationPairProjection.from_object(item) for item in probes
                ),
                exit_code=_integer(exit_status["code"], "finalized exit code"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "finalized check-jump-hosts result enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class OperationFinalization:
    """Immutable verified result written before common-journal advancement."""

    generation: int
    cluster_uuid: uuid.UUID
    cluster_name: str
    operation_id: uuid.UUID
    operation: str
    operation_classification: OperationClassification
    effective_classification: OperationClassification
    selected_stable_ids: tuple[str, ...]
    request_digest: str
    plan_schema_version: str
    plan_digest: str
    binding_schema_version: str
    binding_generation: int
    binding_digest: str
    context_schema_version: str
    context_generation: int
    context_digest: str
    context_values_schema_version: str
    execution_schema_version: str
    execution_generation: int
    execution_digest: str
    evidence_schema_version: str
    evidence_generation: int
    evidence_digest: str
    catalog_digest: str
    source_version: str
    source_digest: str
    readiness_schema_version: str
    readiness_digest: str
    observation_generation: int
    observation_digest: str
    inventory_generation: int
    inventory_digest: str
    trust_generation: int
    trust_digest: str
    journal_schema_version: str
    journal_generation: int
    journal_digest: str
    result_schema_version: str
    result_digest: str
    result: CheckJumpHostsFinalizedResult
    schema_version: str = ANSIBLE_OPERATION_FINALIZATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_OPERATION_FINALIZATION_SCHEMA_VERSION
            or isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation != 1
            or not isinstance(self.cluster_uuid, uuid.UUID)
            or not isinstance(self.operation_id, uuid.UUID)
            or not isinstance(self.result, CheckJumpHostsFinalizedResult)
            or not isinstance(self.selected_stable_ids, tuple)
            or not all(isinstance(item, str) for item in self.selected_stable_ids)
        ):
            raise StatePersistenceError("operation finalization identity is invalid")
        try:
            validate_cluster_name(self.cluster_name)
            operation = get_operation(self.operation)
        except (ConfigurationError, KeyError) as error:
            raise StatePersistenceError(
                "operation finalization identity is invalid"
            ) from error
        if (
            operation.name != _OPERATION
            or operation.classification is not OperationClassification.READ_ONLY
            or self.operation_classification is not OperationClassification.READ_ONLY
            or self.effective_classification is not OperationClassification.READ_ONLY
            or self.selected_stable_ids != self.result.selected_stable_ids
            or self.result_schema_version != self.result.schema_version
            or self.result_digest
            != digest_bytes(serialize_json(self.result.to_object()))
        ):
            raise StatePersistenceError(
                "operation finalization classification or result conflicts"
            )
        for stable_id in self.selected_stable_ids:
            _safe_label(stable_id, "finalization selected stable ID")
        if self.selected_stable_ids != tuple(sorted(set(self.selected_stable_ids))):
            raise StatePersistenceError("operation finalization stable IDs are invalid")
        for generation, label in (
            (self.binding_generation, "binding"),
            (self.context_generation, "context"),
            (self.execution_generation, "execution"),
            (self.evidence_generation, "evidence"),
            (self.observation_generation, "observation"),
            (self.inventory_generation, "inventory"),
            (self.trust_generation, "trust"),
            (self.journal_generation, "journal"),
        ):
            _generation(generation, f"operation finalization {label}")
        for label, value in (
            ("request", self.request_digest),
            ("plan", self.plan_digest),
            ("binding", self.binding_digest),
            ("context", self.context_digest),
            ("execution", self.execution_digest),
            ("evidence", self.evidence_digest),
            ("catalog", self.catalog_digest),
            ("source", self.source_digest),
            ("readiness", self.readiness_digest),
            ("observation", self.observation_digest),
            ("inventory", self.inventory_digest),
            ("trust", self.trust_digest),
            ("journal", self.journal_digest),
            ("result", self.result_digest),
        ):
            validate_digest(value, f"operation finalization {label} digest")
        if (
            self.plan_schema_version != ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION
            or self.binding_schema_version != ANSIBLE_OPERATION_BINDING_SCHEMA_VERSION
            or self.context_schema_version != ANSIBLE_OPERATION_CONTEXT_SCHEMA_VERSION
            or self.context_values_schema_version
            != CHECK_JUMP_HOSTS_CONTEXT_SCHEMA_VERSION
            or self.binding_generation != 1
            or self.context_generation != 1
            or self.execution_schema_version
            != ANSIBLE_OPERATION_EXECUTION_SCHEMA_VERSION
            or self.execution_generation != 4
            or self.evidence_schema_version != ANSIBLE_OPERATION_EVIDENCE_SCHEMA_VERSION
            or self.evidence_generation != 2
            or self.readiness_schema_version != READINESS_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or not _SOURCE_VERSION.fullmatch(self.source_version)
        ):
            raise StatePersistenceError(
                "operation finalization provenance schema conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "binding_digest": self.binding_digest,
            "binding_generation": self.binding_generation,
            "binding_schema_version": self.binding_schema_version,
            "catalog_digest": self.catalog_digest,
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "context_digest": self.context_digest,
            "context_generation": self.context_generation,
            "context_schema_version": self.context_schema_version,
            "context_values_schema_version": self.context_values_schema_version,
            "effective_classification": self.effective_classification.value,
            "evidence_digest": self.evidence_digest,
            "evidence_generation": self.evidence_generation,
            "evidence_schema_version": self.evidence_schema_version,
            "execution_digest": self.execution_digest,
            "execution_generation": self.execution_generation,
            "execution_schema_version": self.execution_schema_version,
            "generation": self.generation,
            "inventory_digest": self.inventory_digest,
            "inventory_generation": self.inventory_generation,
            "journal_digest": self.journal_digest,
            "journal_generation": self.journal_generation,
            "journal_schema_version": self.journal_schema_version,
            "observation_digest": self.observation_digest,
            "observation_generation": self.observation_generation,
            "operation": self.operation,
            "operation_classification": self.operation_classification.value,
            "operation_id": str(self.operation_id),
            "plan_digest": self.plan_digest,
            "plan_schema_version": self.plan_schema_version,
            "readiness_digest": self.readiness_digest,
            "readiness_schema_version": self.readiness_schema_version,
            "request_digest": self.request_digest,
            "result": self.result.to_object(),
            "result_digest": self.result_digest,
            "result_schema_version": self.result_schema_version,
            "schema_version": self.schema_version,
            "selected_stable_ids": list(self.selected_stable_ids),
            "source_digest": self.source_digest,
            "source_version": self.source_version,
            "trust_digest": self.trust_digest,
            "trust_generation": self.trust_generation,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> OperationFinalization:
        fields = {
            "binding_digest",
            "binding_generation",
            "binding_schema_version",
            "catalog_digest",
            "cluster_name",
            "cluster_uuid",
            "context_digest",
            "context_generation",
            "context_schema_version",
            "context_values_schema_version",
            "effective_classification",
            "evidence_digest",
            "evidence_generation",
            "evidence_schema_version",
            "execution_digest",
            "execution_generation",
            "execution_schema_version",
            "generation",
            "inventory_digest",
            "inventory_generation",
            "journal_digest",
            "journal_generation",
            "journal_schema_version",
            "observation_digest",
            "observation_generation",
            "operation",
            "operation_classification",
            "operation_id",
            "plan_digest",
            "plan_schema_version",
            "readiness_digest",
            "readiness_schema_version",
            "request_digest",
            "result",
            "result_digest",
            "result_schema_version",
            "schema_version",
            "selected_stable_ids",
            "source_digest",
            "source_version",
            "trust_digest",
            "trust_generation",
        }
        require_exact_keys(value, fields, "Ansible operation finalization")
        if (
            require_string(value, "schema_version")
            != ANSIBLE_OPERATION_FINALIZATION_SCHEMA_VERSION
        ):
            raise StatePersistenceError(
                "unsupported Ansible operation finalization schema"
            )
        result = _object(value["result"], "operation finalization result")
        stable_ids = _string_list(
            value["selected_stable_ids"], "operation finalization stable IDs"
        )
        try:
            operation_classification = OperationClassification(
                require_string(value, "operation_classification")
            )
            effective_classification = OperationClassification(
                require_string(value, "effective_classification")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "operation finalization classification is invalid"
            ) from error
        return cls(
            generation=_integer(value["generation"], "finalization generation"),
            cluster_uuid=parse_uuid(
                require_string(value, "cluster_uuid"), "cluster UUID"
            ),
            cluster_name=require_string(value, "cluster_name"),
            operation_id=parse_uuid(
                require_string(value, "operation_id"), "operation ID"
            ),
            operation=require_string(value, "operation"),
            operation_classification=operation_classification,
            effective_classification=effective_classification,
            selected_stable_ids=stable_ids,
            request_digest=require_string(value, "request_digest"),
            plan_schema_version=require_string(value, "plan_schema_version"),
            plan_digest=require_string(value, "plan_digest"),
            binding_schema_version=require_string(value, "binding_schema_version"),
            binding_generation=_integer(
                value["binding_generation"], "finalization binding generation"
            ),
            binding_digest=require_string(value, "binding_digest"),
            context_schema_version=require_string(value, "context_schema_version"),
            context_generation=_integer(
                value["context_generation"], "finalization context generation"
            ),
            context_digest=require_string(value, "context_digest"),
            context_values_schema_version=require_string(
                value, "context_values_schema_version"
            ),
            execution_schema_version=require_string(value, "execution_schema_version"),
            execution_generation=_integer(
                value["execution_generation"], "finalization execution generation"
            ),
            execution_digest=require_string(value, "execution_digest"),
            evidence_schema_version=require_string(value, "evidence_schema_version"),
            evidence_generation=_integer(
                value["evidence_generation"], "finalization evidence generation"
            ),
            evidence_digest=require_string(value, "evidence_digest"),
            catalog_digest=require_string(value, "catalog_digest"),
            source_version=require_string(value, "source_version"),
            source_digest=require_string(value, "source_digest"),
            readiness_schema_version=require_string(value, "readiness_schema_version"),
            readiness_digest=require_string(value, "readiness_digest"),
            observation_generation=_integer(
                value["observation_generation"],
                "finalization observation generation",
            ),
            observation_digest=require_string(value, "observation_digest"),
            inventory_generation=_integer(
                value["inventory_generation"], "finalization inventory generation"
            ),
            inventory_digest=require_string(value, "inventory_digest"),
            trust_generation=_integer(
                value["trust_generation"], "finalization trust generation"
            ),
            trust_digest=require_string(value, "trust_digest"),
            journal_schema_version=require_string(value, "journal_schema_version"),
            journal_generation=_integer(
                value["journal_generation"], "finalization journal generation"
            ),
            journal_digest=require_string(value, "journal_digest"),
            result_schema_version=require_string(value, "result_schema_version"),
            result_digest=require_string(value, "result_digest"),
            result=CheckJumpHostsFinalizedResult.from_object(result),
        )


@dataclass(frozen=True, slots=True)
class StoredOperationFinalization:
    record: OperationFinalization
    digest: str


class OperationFinalizationStore:
    """Persist one immutable post-verification companion."""

    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace_file: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        _require_canonical_paths(paths)
        if not isinstance(operation_id, uuid.UUID):
            raise StatePersistenceError("operation finalization ID must be a UUID")
        self._paths = paths
        self._operation_id = operation_id
        self._path = operation_finalization_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path,
            replace=replace_file,
            token_factory=token_factory,
        )

    @property
    def path(self) -> Path:
        return self._path

    def read_locked(
        self,
        lock: object,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
        expected_operation: str | None = None,
    ) -> StoredOperationFinalization:
        _assert_read_lock(lock, self._paths)
        value, digest = self._file.read()
        record = OperationFinalization.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or (
                expected_operation is not None
                and record.operation != expected_operation
            )
        ):
            raise StatePersistenceError(
                "Ansible operation finalization identity mismatch"
            )
        return StoredOperationFinalization(record, digest)

    def write_locked(
        self,
        record: OperationFinalization,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredOperationFinalization:
        _assert_operation_lock(lock, self._paths, record.operation)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError("Ansible operation finalization ID mismatch")
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
                expected_operation=record.operation,
            )
            if (
                expected_generation != current.record.generation
                or expected_digest is None
                or expected_digest != current.digest
            ):
                raise StatePersistenceError(
                    "Ansible operation finalization changed concurrently"
                )
            if current.record == record:
                return current
            raise StatePersistenceError("Ansible operation finalization is immutable")
        if (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
        ):
            raise StatePersistenceError(
                "initial Ansible operation finalization write requires generation one"
            )
        digest = self._file.write(record.to_object(), expected_digest=None)
        return StoredOperationFinalization(record, digest)


@dataclass(frozen=True, slots=True)
class CheckJumpHostsFinalizationReport:
    """Address-free result of durable verification and journal completion."""

    companion_state: FinalizationCompanionState
    result: CheckJumpHostsFinalizedResult
    finalization_generation: int
    journal_generation: int
    journal_status: JournalStatus
    journal_phase: OperationPhase
    schemas: tuple[tuple[str, str], ...]
    digests: tuple[tuple[str, str], ...]
    schema_version: str = ANSIBLE_OPERATION_FINALIZATION_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != ANSIBLE_OPERATION_FINALIZATION_REPORT_SCHEMA_VERSION
            or not isinstance(self.companion_state, FinalizationCompanionState)
            or not isinstance(self.result, CheckJumpHostsFinalizedResult)
            or isinstance(self.finalization_generation, bool)
            or not isinstance(self.finalization_generation, int)
            or self.finalization_generation != 1
            or isinstance(self.journal_generation, bool)
            or not isinstance(self.journal_generation, int)
            or self.journal_generation < 1
            or self.journal_status is not JournalStatus.SUCCEEDED
            or self.journal_phase is not OperationPhase.JOURNAL
            or not isinstance(self.schemas, tuple)
            or not all(
                isinstance(item, tuple)
                and len(item) == 2
                and all(isinstance(value, str) for value in item)
                for item in self.schemas
            )
            or not isinstance(self.digests, tuple)
            or not all(
                isinstance(item, tuple)
                and len(item) == 2
                and all(isinstance(value, str) for value in item)
                for item in self.digests
            )
            or tuple(name for name, _ in self.schemas) != _REPORT_SCHEMA_NAMES
            or tuple(name for name, _ in self.digests) != _REPORT_DIGEST_NAMES
            or dict(self.schemas)
            != {
                "binding": ANSIBLE_OPERATION_BINDING_SCHEMA_VERSION,
                "context": ANSIBLE_OPERATION_CONTEXT_SCHEMA_VERSION,
                "context_values": CHECK_JUMP_HOSTS_CONTEXT_SCHEMA_VERSION,
                "evidence": ANSIBLE_OPERATION_EVIDENCE_SCHEMA_VERSION,
                "execution": ANSIBLE_OPERATION_EXECUTION_SCHEMA_VERSION,
                "finalization": ANSIBLE_OPERATION_FINALIZATION_SCHEMA_VERSION,
                "journal": JOURNAL_SCHEMA_VERSION,
                "plan": ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION,
                "readiness": READINESS_SCHEMA_VERSION,
                "result": ANSIBLE_CHECK_JUMP_HOSTS_RESULT_SCHEMA_VERSION,
            }
        ):
            raise StatePersistenceError(
                "check-jump-hosts finalization report is invalid"
            )
        for _, digest in self.digests:
            validate_digest(digest, "finalization report digest")

    def to_object(self) -> dict[str, object]:
        return {
            "companion": {
                "generation": self.finalization_generation,
                "state": self.companion_state.value,
            },
            "digests": dict(self.digests),
            "journal": {
                "generation": self.journal_generation,
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
            },
            "operation": {
                "classification": OperationClassification.READ_ONLY.value,
                "effective_classification": OperationClassification.READ_ONLY.value,
                "kind": _OPERATION,
                "selected_stable_ids": list(self.result.selected_stable_ids),
            },
            "result": self.result.to_object(),
            "schema_version": self.schema_version,
            "schemas": dict(self.schemas),
        }


@dataclass(frozen=True, slots=True)
class _OfflinePlanPolicy:
    paths: StatePaths

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
        return validate_playbook_request_policy(
            name,
            limit=limit,
            tags=tags,
            check=check,
            diff=diff,
            verbosity=verbosity,
        )


@dataclass(frozen=True, slots=True)
class _CanonicalFinalizationState:
    paths: StatePaths
    metadata: StoredClusterMetadata
    observed: StoredObservedState
    inventory: StoredInventoryRecord
    trust: StoredTrustRecord
    readiness: ReadinessReport
    binding: StoredOperationPlanBinding
    operation_context: StoredOperationContext
    request: OperationRequest
    plan: AnsibleOperationPlan
    execution: StoredOperationExecution
    evidence: StoredOperationEvidence
    facts: CheckJumpHostsSemanticFacts
    journal: StoredOperationRecord


def finalize_prepared_check_jump_hosts(
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> CheckJumpHostsFinalizationReport:
    """Verify persisted semantic evidence, then safely complete the v1 journal."""

    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError(
            "check-jump-hosts finalization operation ID must be a UUID"
        )
    paths = StatePaths.derive(state_root, cluster_name)
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "check-jump-hosts finalization requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)
    state = _load_finalization_state(paths, operation_id, lock)
    result = _build_finalized_result(state)
    finalization = _build_finalization_record(state, result)
    store = OperationFinalizationStore(paths, operation_id)
    validate_state_file(store.path, allow_missing=True)
    if store.path.exists():
        existing = store.read_locked(
            lock,
            expected_cluster_uuid=state.metadata.record.cluster_uuid,
            expected_cluster_name=state.metadata.record.cluster_name,
            expected_operation=_OPERATION,
        )
        if existing.record != finalization:
            raise StateConflictError(
                "Ansible operation finalization conflicts with current evidence"
            )
        stored = existing
        companion_state = FinalizationCompanionState.REUSED
    else:
        _require_initial_journal_checkpoint(state)
        stored = store.write_locked(
            finalization,
            expected_generation=0,
            expected_digest=None,
            lock=lock,
        )
        companion_state = FinalizationCompanionState.CREATED
    journal = _advance_common_journal(state, stored, lock)
    return _finalization_report(companion_state, stored, journal)


def operation_finalization_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError("operation finalization ID must be a UUID")
    path = paths.operations / f"{operation_id}{OPERATION_FINALIZATION_FILENAME_SUFFIX}"
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "Ansible operation finalization path is not canonical"
        )
    return path


def operation_finalization_id_from_filename(name: str) -> uuid.UUID | None:
    if not name.endswith(OPERATION_FINALIZATION_FILENAME_SUFFIX):
        return None
    identifier_text = name[: -len(OPERATION_FINALIZATION_FILENAME_SUFFIX)]
    try:
        identifier = uuid.UUID(identifier_text)
    except ValueError:
        return None
    return identifier if str(identifier) == identifier_text else None


def _load_finalization_state(
    paths: StatePaths,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> _CanonicalFinalizationState:
    for directory in (
        paths.state_root,
        paths.clusters,
        paths.cluster_root,
        paths.terraform,
        paths.ansible,
        paths.ansible_home,
        paths.ansible_local_tmp,
        paths.ansible_fact_cache,
        paths.ansible_control_path,
        paths.operations,
        paths.logs,
    ):
        validate_state_directory(directory)
    refuse_unexpected_terraform_state(paths, (paths.cluster_root,))
    metadata = ClusterMetadataStore(paths).read(
        expected_cluster_name=paths.cluster_root.name
    )
    binding = OperationPlanBindingStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )
    _require_read_only_check_jump_hosts(binding)
    operation_context = OperationContextStore(paths, operation_id).read_locked(
        lock,
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_operation=_OPERATION,
    )
    authorization = OperationAuthorizationStore(paths, operation_id)
    validate_state_file(authorization.path, allow_missing=True)
    if authorization.path.exists():
        authorization.read_locked(
            lock,
            expected_cluster_uuid=metadata.record.cluster_uuid,
            expected_cluster_name=metadata.record.cluster_name,
            expected_operation=_OPERATION,
        )
        raise StateConflictError(
            "read-only check-jump-hosts finalization forbids authorization"
        )
    observed = ObservedStateStore(paths).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_provider=metadata.record.provider,
    )
    inventory = InventoryStore(paths).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_provider=metadata.record.provider,
    )
    trust = TrustStore(paths).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_provider=metadata.record.provider,
    )
    readiness = _validate_current_local_state(
        paths, metadata, observed, inventory, trust, binding
    )
    reconstructed = reconstruct_operation_context(
        paths, operation_context, binding, inventory
    )
    request = reconstructed.request
    if (
        request.operation.name != _OPERATION
        or request.operation.classification is not OperationClassification.READ_ONLY
        or not request.operation.implemented
        or normalized_operation_request_digest(request) != binding.record.request_digest
    ):
        raise StateConflictError(
            "check-jump-hosts finalization request binding drifted"
        )
    resolve_existing_config(request, metadata.record.desired_spec)
    plan = build_ansible_operation_plan(
        lock,
        _OfflinePlanPolicy(paths),
        metadata.record,
        inventory,
        _OPERATION,
        readiness=readiness,
        active_conditions=reconstructed.active_conditions,
        intents=reconstructed.intents,
    )
    if (
        plan.status is not AnsibleOperationPlanStatus.READY
        or plan.blockers
        or plan.schema_version != binding.record.plan_schema_version
        or plan.plan_digest != binding.record.plan_digest
        or plan.effective_classification is not OperationClassification.READ_ONLY
    ):
        raise StateConflictError("check-jump-hosts finalization plan binding drifted")
    execution_store = OperationExecutionStore(paths, operation_id)
    evidence_store = OperationEvidenceStore(paths, operation_id)
    validate_state_file(execution_store.path)
    validate_state_file(evidence_store.path)
    execution = execution_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_operation=_OPERATION,
    )
    evidence = evidence_store.read_locked(
        lock,
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
        expected_operation=_OPERATION,
    )
    canonical = CanonicalAnsibleOperationContext(
        paths,
        metadata,
        observed,
        inventory,
        trust,
        binding,
        operation_context,
        request,
        reconstructed.active_conditions,
        reconstructed.intents,
        execution,
    )
    expected = reconstruct_prepared_check_jump_hosts_steps(canonical)
    _require_complete_execution(canonical, expected)
    validate_operation_evidence_checkpoint(
        evidence,
        binding=binding,
        context=operation_context,
        readiness=readiness,
    )
    facts = reconstruct_check_jump_hosts_semantic_facts(
        evidence,
        binding=binding,
        context=operation_context,
        intents=reconstructed.intents,
    )
    validate_check_jump_hosts_evidence_receipts(execution, evidence.record.entries)
    journal_path = paths.operations / f"{operation_id}.json"
    validate_state_file(journal_path)
    journal = OperationJournalStore(paths, operation_id).read(
        expected_cluster_uuid=metadata.record.cluster_uuid,
        expected_cluster_name=metadata.record.cluster_name,
    )
    _require_journal_identity(journal, binding, plan)
    return _CanonicalFinalizationState(
        paths,
        metadata,
        observed,
        inventory,
        trust,
        readiness,
        binding,
        operation_context,
        request,
        plan,
        execution,
        evidence,
        facts,
        journal,
    )


def _require_read_only_check_jump_hosts(
    binding: StoredOperationPlanBinding,
) -> None:
    record = binding.record
    if (
        record.operation != _OPERATION
        or record.operation_classification is not OperationClassification.READ_ONLY
        or record.effective_classification is not OperationClassification.READ_ONLY
        or record.plan_status is not AnsibleOperationPlanStatus.READY
        or record.confirmation_state is not ConfirmationState.NOT_COLLECTED
        or record.execution_state is not ExecutionState.NOT_STARTED
    ):
        raise StateConflictError(
            "finalization requires an exact read-only check-jump-hosts binding"
        )


def _validate_current_local_state(
    paths: StatePaths,
    metadata: StoredClusterMetadata,
    observed: StoredObservedState,
    inventory: StoredInventoryRecord,
    trust: StoredTrustRecord,
    binding: StoredOperationPlanBinding,
) -> ReadinessReport:
    for path in (
        paths.cluster_metadata,
        paths.terraform_observed,
        paths.ansible_inventory,
        paths.ansible_trust,
        paths.known_hosts,
        paths.ansible_ssh_config,
        paths.ansible_config,
    ):
        validate_state_file(path)
    bound = binding.record
    if (
        inventory.record.source_manifest_generation != observed.record.generation
        or inventory.record.source_manifest_digest != observed.record.manifest_digest
        or observed.record.generation != bound.observation_generation
        or observed.record.manifest_digest != bound.observation_digest
        or inventory.record.generation != bound.inventory_generation
        or inventory.digest != bound.inventory_digest
        or trust.record.generation != bound.trust_generation
        or trust.digest != bound.trust_digest
    ):
        raise StateConflictError(
            "check-jump-hosts finalization canonical evidence drifted"
        )
    reconciliation = reconcile_desired_observed(
        metadata.record.desired_spec, observed.record.manifest
    )
    if reconciliation.status is not ReconciliationClass.MATCH:
        raise StateConflictError(
            "check-jump-hosts finalization desired state is not reconciled"
        )
    if not trust.record.is_fresh_for(observed.record, inventory.record):
        raise StateConflictError("check-jump-hosts finalization trust is stale")
    TrustStore(paths).validate_runtime(trust, inventory)
    validate_ansible_config(paths)
    source = load_ansible_source_bundle()
    catalog_digest = ansible_operation_catalog_digest()
    if (
        source.version != bound.source_version
        or source.digest != bound.source_digest
        or catalog_digest != bound.catalog_digest
    ):
        raise StateConflictError(
            "check-jump-hosts finalization source or catalog drifted"
        )
    marker = digest_bytes(b"readiness-machine-evidence-present")
    readiness = build_readiness_report(
        observed,
        inventory,
        trust,
        machine_evidence=InventoryMachineEvidence(
            marker,
            marker,
            len(inventory.record.inventory.hosts),
            len(inventory.record.inventory.groups),
        ),
    )
    if (
        readiness.schema_version != bound.readiness_schema_version
        or readiness.status is not EvidenceStatus.FRESH
        or readiness_binding_digest(readiness) != bound.readiness_digest
    ):
        raise StateConflictError("check-jump-hosts finalization readiness drifted")
    readiness.require_ready(OperationClassification.READ_ONLY)
    return readiness


def _require_complete_execution(
    context: CanonicalAnsibleOperationContext,
    expected: tuple[PreparedCheckJumpHostsStep, ...],
) -> None:
    execution = validate_prepared_check_jump_hosts_execution(context, expected)
    if execution is None:
        raise StateConflictError(
            "check-jump-hosts finalization execution evidence is missing"
        )
    record = execution.record
    if (
        tuple(item.playbook for item in expected) != _EXPECTED_PLAYBOOKS
        or record.state is not ExecutionAttemptState.SUCCEEDED
        or not record.all_steps_completed
        or len(record.attempts) != len(expected)
        or any(
            attempt.state is not ExecutionAttemptState.SUCCEEDED
            or attempt.manual_recovery_required
            or attempt.automatic_retry_allowed
            or attempt.exit_code != 0
            or attempt.result_digest is None
            for attempt in record.attempts
        )
    ):
        raise StateConflictError(
            "check-jump-hosts execution is incomplete or requires recovery"
        )


def _build_finalized_result(
    state: _CanonicalFinalizationState,
) -> CheckJumpHostsFinalizedResult:
    facts = state.facts
    hosts = {host.logical_id: host for host in state.inventory.record.inventory.hosts}
    trust_ids = {entry.logical_id for entry in state.trust.record.entries}
    connectivity = {item.logical_id: item.status for item in facts.connectivity.hosts}
    jumps: list[FinalizedJumpHost] = []
    for stable_id in facts.selected_stable_ids:
        host = hosts.get(stable_id)
        if (
            host is None
            or host.role is not HostRole.JUMP_HOST
            or stable_id not in trust_ids
            or stable_id not in connectivity
        ):
            raise StateConflictError(
                "check-jump-hosts finalization selected host evidence drifted"
            )
        jumps.append(
            FinalizedJumpHost(
                stable_id,
                "verified",
                connectivity[stable_id],
            )
        )
    values = state.operation_context.record.values
    return CheckJumpHostsFinalizedResult(
        depth=values.depth,
        destinations=values.destinations,
        selected_stable_ids=facts.selected_stable_ids,
        inventory_host_count=facts.inventory_preflight.host_count,
        inventory_target_count=facts.inventory_preflight.target_count,
        inventory_machine=state.readiness.machine_status,
        inventory_preflight=facts.inventory_preflight.status,
        route_validation=state.readiness.route_status,
        connectivity=facts.connectivity.status,
        destination_tcp=(
            DestinationCheckStatus.SUCCESS
            if facts.connectivity.destination_pairs
            else DestinationCheckStatus.NOT_PERFORMED
        ),
        target_ssh="not-performed",
        jumps=tuple(jumps),
        destination_probes=facts.connectivity.destination_pairs,
        exit_code=int(ExitCode.SUCCESS),
    )


def _build_finalization_record(
    state: _CanonicalFinalizationState,
    result: CheckJumpHostsFinalizedResult,
) -> OperationFinalization:
    bound = state.binding.record
    contextual = state.operation_context.record
    execution = state.execution.record
    evidence = state.evidence.record
    return OperationFinalization(
        generation=1,
        cluster_uuid=bound.cluster_uuid,
        cluster_name=bound.cluster_name,
        operation_id=bound.operation_id,
        operation=bound.operation,
        operation_classification=bound.operation_classification,
        effective_classification=bound.effective_classification,
        selected_stable_ids=bound.selected_stable_ids,
        request_digest=bound.request_digest,
        plan_schema_version=bound.plan_schema_version,
        plan_digest=bound.plan_digest,
        binding_schema_version=bound.schema_version,
        binding_generation=bound.generation,
        binding_digest=state.binding.digest,
        context_schema_version=contextual.schema_version,
        context_generation=contextual.generation,
        context_digest=state.operation_context.digest,
        context_values_schema_version=contextual.values.schema_version,
        execution_schema_version=execution.schema_version,
        execution_generation=execution.generation,
        execution_digest=state.execution.digest,
        evidence_schema_version=evidence.schema_version,
        evidence_generation=evidence.generation,
        evidence_digest=state.evidence.digest,
        catalog_digest=bound.catalog_digest,
        source_version=bound.source_version,
        source_digest=bound.source_digest,
        readiness_schema_version=bound.readiness_schema_version,
        readiness_digest=bound.readiness_digest,
        observation_generation=cast(int, bound.observation_generation),
        observation_digest=cast(str, bound.observation_digest),
        inventory_generation=bound.inventory_generation,
        inventory_digest=bound.inventory_digest,
        trust_generation=cast(int, bound.trust_generation),
        trust_digest=cast(str, bound.trust_digest),
        journal_schema_version=bound.journal_schema_version,
        journal_generation=bound.journal_generation,
        journal_digest=bound.journal_digest,
        result_schema_version=result.schema_version,
        result_digest=digest_bytes(serialize_json(result.to_object())),
        result=result,
    )


def _require_initial_journal_checkpoint(
    state: _CanonicalFinalizationState,
) -> None:
    journal = state.journal
    bound = state.binding.record
    if (
        journal.record.status is not JournalStatus.IN_PROGRESS
        or journal.record.phase is not OperationPhase.PLAN
        or journal.record.generation != bound.journal_generation
        or journal.digest != bound.journal_digest
        or journal.record.evidence
        != (ansible_operation_plan_checkpoint_evidence(state.plan),)
        or journal.record.resume_revalidation_digest is not None
    ):
        raise StateConflictError(
            "initial finalization requires the exact bound PLAN journal"
        )


def _require_journal_identity(
    journal: StoredOperationRecord,
    binding: StoredOperationPlanBinding,
    plan: AnsibleOperationPlan,
) -> None:
    record = journal.record
    bound = binding.record
    plan_evidence = ansible_operation_plan_checkpoint_evidence(plan)
    if (
        record.operation_id != bound.operation_id
        or record.operation != _OPERATION
        or record.cluster_uuid != bound.cluster_uuid
        or record.cluster_name != bound.cluster_name
        or record.request_digest != bound.request_digest
        or record.created_at > record.updated_at
        or record.resume_revalidation_digest is not None
        or not record.evidence
        or record.evidence[0] != plan_evidence
        or len(record.evidence) > 2
        or record.generation
        not in {
            bound.journal_generation,
            bound.journal_generation + 1,
            bound.journal_generation + 2,
        }
    ):
        raise StateConflictError(
            "check-jump-hosts finalization journal history conflicts"
        )


def _advance_common_journal(
    state: _CanonicalFinalizationState,
    finalization: StoredOperationFinalization,
    lock: ClusterLock,
) -> StoredOperationRecord:
    store = OperationJournalStore(state.paths, state.binding.record.operation_id)
    current = store.read(
        expected_cluster_uuid=state.metadata.record.cluster_uuid,
        expected_cluster_name=state.metadata.record.cluster_name,
    )
    _require_journal_identity(current, state.binding, state.plan)
    verification = CheckpointEvidence(
        OperationPhase.VERIFY,
        EvidenceResult.COMPLETED,
        finalization.digest,
        "check-jump-hosts-verified",
    )
    plan_evidence = ansible_operation_plan_checkpoint_evidence(state.plan)
    bound = state.binding.record
    if (
        current.record.status is JournalStatus.IN_PROGRESS
        and current.record.phase is OperationPhase.PLAN
    ):
        if (
            current.record.generation != bound.journal_generation
            or current.digest != bound.journal_digest
            or current.record.evidence != (plan_evidence,)
        ):
            raise StateConflictError(
                "check-jump-hosts finalization PLAN journal drifted"
            )
        candidate = current.record.transition(
            status=JournalStatus.IN_PROGRESS,
            phase=OperationPhase.VERIFY,
            evidence=(plan_evidence, verification),
            clock=_utc_now,
        )
        current = store.write(
            candidate,
            expected_generation=current.record.generation,
            expected_digest=current.digest,
        )
    if (
        current.record.status is JournalStatus.IN_PROGRESS
        and current.record.phase is OperationPhase.VERIFY
    ):
        if (
            current.record.generation != bound.journal_generation + 1
            or current.record.evidence != (plan_evidence, verification)
        ):
            raise StateConflictError(
                "check-jump-hosts finalization VERIFY journal drifted"
            )
        candidate = current.record.transition(
            status=JournalStatus.SUCCEEDED,
            phase=OperationPhase.JOURNAL,
            evidence=current.record.evidence,
            clock=_utc_now,
        )
        current = store.write(
            candidate,
            expected_generation=current.record.generation,
            expected_digest=current.digest,
        )
    if (
        current.record.status is not JournalStatus.SUCCEEDED
        or current.record.phase is not OperationPhase.JOURNAL
        or current.record.generation != bound.journal_generation + 2
        or current.record.evidence != (plan_evidence, verification)
    ):
        raise StateConflictError(
            "check-jump-hosts finalization journal is not exactly complete"
        )
    return current


def _finalization_report(
    companion_state: FinalizationCompanionState,
    finalization: StoredOperationFinalization,
    journal: StoredOperationRecord,
) -> CheckJumpHostsFinalizationReport:
    record = finalization.record
    return CheckJumpHostsFinalizationReport(
        companion_state=companion_state,
        result=record.result,
        finalization_generation=record.generation,
        journal_generation=journal.record.generation,
        journal_status=journal.record.status,
        journal_phase=journal.record.phase,
        schemas=(
            ("binding", record.binding_schema_version),
            ("context", record.context_schema_version),
            ("context_values", record.context_values_schema_version),
            ("evidence", record.evidence_schema_version),
            ("execution", record.execution_schema_version),
            ("finalization", record.schema_version),
            ("journal", record.journal_schema_version),
            ("plan", record.plan_schema_version),
            ("readiness", record.readiness_schema_version),
            ("result", record.result_schema_version),
        ),
        digests=(
            ("binding", record.binding_digest),
            ("catalog", record.catalog_digest),
            ("context", record.context_digest),
            ("evidence", record.evidence_digest),
            ("execution", record.execution_digest),
            ("finalization", finalization.digest),
            ("inventory", record.inventory_digest),
            ("journal", journal.digest),
            ("observation", record.observation_digest),
            ("plan", record.plan_digest),
            ("readiness", record.readiness_digest),
            ("request", record.request_digest),
            ("result", record.result_digest),
            ("source", record.source_digest),
            ("trust", record.trust_digest),
        ),
    )


def _require_canonical_paths(paths: StatePaths) -> None:
    expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
    if expected != paths or paths.operations.parent != paths.cluster_root:
        raise UnsafePathError("Ansible operation finalization paths are not canonical")


def _assert_operation_lock(
    lock: ClusterLock, paths: StatePaths, operation: str
) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Ansible operation finalization requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, operation)


def _assert_read_lock(lock: object, paths: StatePaths) -> None:
    assertion = getattr(lock, "assert_held_for", None)
    if not callable(assertion):
        raise StateLockError(
            "Ansible operation finalization read requires an acquired cluster lock"
        )
    assertion(paths)


def _safe_label(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or _SAFE_LABEL.fullmatch(value) is None
        or ".." in value
        or _is_ip_address(value)
        or _HOST_KEY_OR_FINGERPRINT.match(value) is not None
        or any(
            item in _PROTECTED_COMPONENTS
            for item in re.split(r"[._:-]+", value.lower())
        )
    ):
        raise StatePersistenceError(f"{label} is invalid or protected")


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _bounded_count(value: int, minimum: int, maximum: int, label: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise StatePersistenceError(f"{label} count is invalid or unbounded")


def _generation(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} generation is invalid")


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _object_list(value: object, label: str) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise StatePersistenceError(f"{label} must be an object array")
    return tuple(cast(dict[str, object], item) for item in value)


def _string_list(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise StatePersistenceError(f"{label} must be a string array")
    return tuple(cast(list[str], value))


def _utc_now() -> datetime:
    return datetime.now(UTC)
