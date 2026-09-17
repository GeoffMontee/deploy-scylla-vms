"""Immutable canonical request context for internal Ansible plan reconstruction."""

import ipaddress
import math
import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.operation_binding import (
    ANSIBLE_OPERATION_BINDING_SCHEMA_VERSION,
    OperationPlanBindingStore,
    StoredOperationPlanBinding,
    normalized_operation_request_digest,
)
from scylla_vms.ansible.orchestration import (
    ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION,
    AnsibleOperationPlan,
    AnsibleOperationPlanStatus,
    AnsibleStepIntent,
)
from scylla_vms.check_jump_hosts import resolve_jump_host_operation_selection
from scylla_vms.cli import parse_operation_request
from scylla_vms.errors import (
    ConfigurationError,
    OperationNotImplementedError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.inventory import StoredInventoryRecord
from scylla_vms.locking import ClusterLock
from scylla_vms.models import OperationRequest
from scylla_vms.operations import OperationClassification, get_operation
from scylla_vms.persistence import (
    AtomicJsonFile,
    ClusterMetadata,
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
from scylla_vms.validation import DESTINATION_CHECK_PORTS

ANSIBLE_OPERATION_CONTEXT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-operation-context/v1"
)
CHECK_JUMP_HOSTS_CONTEXT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-operation-context.check-jump-hosts/v1"
)
OPERATION_CONTEXT_FILENAME_SUFFIX = ".ansible-operation-context.json"
OPERATION_CONTEXT_UNMODELED = "operation-context-unmodeled"
OPERATION_CONTEXT_REQUEST_UNMODELED = "operation-context-request-unmodeled"
OPERATION_CONTEXT_PROTECTED_INPUTS = "operation-context-protected-inputs-forbidden"
OPERATION_CONTEXT_RUNTIME_INPUTS_INVALID = "operation-context-runtime-inputs-invalid"
_INTENT_CONTEXT_SCHEMA_VERSION = "deploy-scylla-vms.ansible-operation-intent-context/v1"
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MAX_JUMP_HOSTS = 16
_MAX_TIMEOUT_SECONDS = 86_400
_MIN_CONNECT_TIMEOUT_SECONDS = 0.0000001
_CONTEXT_REQUEST_FIELDS = frozenset(
    {
        "jump_host",
        "destination",
        "depth",
        "destination_check",
        "connect_timeout_seconds",
        "check_timeout_seconds",
    }
)


class JumpHostDepth(StrEnum):
    BASTION = "bastion"
    ROUTE = "route"
    ALL_TARGETS = "all-targets"


class JumpHostDestination(StrEnum):
    ASSIGNED = "assigned"
    SCYLLA = "scylla"
    MANAGER = "manager"
    MONITORING = "monitoring"
    ALL = "all"


class DestinationCheckRole(StrEnum):
    SCYLLA = "scylla"
    MANAGER = "manager"
    MONITORING = "monitoring"


@dataclass(frozen=True, slots=True)
class DestinationCheckContext:
    """One role/port selector; an address is always re-derived from inventory."""

    role: DestinationCheckRole
    port: int

    def __post_init__(self) -> None:
        if not isinstance(self.role, DestinationCheckRole):
            raise StatePersistenceError("operation context destination role is invalid")
        if (
            isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or self.port not in DESTINATION_CHECK_PORTS[self.role.value]
        ):
            raise StatePersistenceError("operation context destination port is invalid")

    def to_object(self) -> dict[str, object]:
        return {"port": self.port, "role": self.role.value}

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> "DestinationCheckContext":
        require_exact_keys(
            value, {"port", "role"}, "operation context destination check"
        )
        try:
            role = DestinationCheckRole(require_string(value, "role"))
        except ValueError as error:
            raise StatePersistenceError(
                "operation context destination role is invalid"
            ) from error
        return cls(role, _integer(value["port"], "operation context destination port"))


@dataclass(frozen=True, slots=True)
class CheckJumpHostsContext:
    """Complete bounded request values for the sole reconstructable operation."""

    jump_hosts: tuple[str, ...]
    destinations: tuple[JumpHostDestination, ...]
    depth: JumpHostDepth
    destination_checks: tuple[DestinationCheckContext, ...]
    connect_timeout_seconds: float
    check_timeout_seconds: int
    schema_version: str = CHECK_JUMP_HOSTS_CONTEXT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != CHECK_JUMP_HOSTS_CONTEXT_SCHEMA_VERSION:
            raise StatePersistenceError(
                "unsupported check-jump-hosts operation context schema"
            )
        _validate_stable_ids(
            self.jump_hosts,
            allow_empty=True,
            maximum=_MAX_JUMP_HOSTS,
            label="operation context jump-host IDs",
        )
        if (
            not isinstance(self.destinations, tuple)
            or not self.destinations
            or len(self.destinations) > len(JumpHostDestination)
            or not all(
                isinstance(value, JumpHostDestination) for value in self.destinations
            )
            or len(set(self.destinations)) != len(self.destinations)
            or (
                JumpHostDestination.ALL in self.destinations
                and self.destinations != (JumpHostDestination.ALL,)
            )
        ):
            raise StatePersistenceError(
                "operation context destinations are invalid or duplicated"
            )
        if not isinstance(self.depth, JumpHostDepth):
            raise StatePersistenceError("operation context depth is invalid")
        if (
            not isinstance(self.destination_checks, tuple)
            or len(self.destination_checks) > len(DestinationCheckRole)
            or not all(
                isinstance(value, DestinationCheckContext)
                for value in self.destination_checks
            )
            or len({value.role for value in self.destination_checks})
            != len(self.destination_checks)
        ):
            raise StatePersistenceError(
                "operation context destination checks are invalid or duplicated"
            )
        if self.destination_checks and self.depth is JumpHostDepth.BASTION:
            raise StatePersistenceError(
                "operation context destination checks require route depth"
            )
        selected_roles = (
            set(DESTINATION_CHECK_PORTS)
            if JumpHostDestination.ASSIGNED in self.destinations
            or JumpHostDestination.ALL in self.destinations
            else {destination.value for destination in self.destinations}
        )
        if (
            not {value.role.value for value in self.destination_checks}
            <= selected_roles
        ):
            raise StatePersistenceError(
                "operation context destination checks conflict with destinations"
            )
        if self.depth is JumpHostDepth.ALL_TARGETS and not self.destination_checks:
            raise StatePersistenceError(
                "operation context all-targets private SSH is unavailable"
            )
        if (
            isinstance(self.connect_timeout_seconds, bool)
            or not isinstance(self.connect_timeout_seconds, float)
            or not math.isfinite(self.connect_timeout_seconds)
            or not _MIN_CONNECT_TIMEOUT_SECONDS
            <= self.connect_timeout_seconds
            <= _MAX_TIMEOUT_SECONDS
        ):
            raise StatePersistenceError(
                "operation context connection timeout is invalid or unbounded"
            )
        if (
            isinstance(self.check_timeout_seconds, bool)
            or not isinstance(self.check_timeout_seconds, int)
            or not 1 <= self.check_timeout_seconds <= _MAX_TIMEOUT_SECONDS
        ):
            raise StatePersistenceError(
                "operation context aggregate timeout is invalid or unbounded"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "check_timeout_seconds": self.check_timeout_seconds,
            "connect_timeout_seconds": self.connect_timeout_seconds,
            "depth": self.depth.value,
            "destination_checks": [
                value.to_object() for value in self.destination_checks
            ],
            "destinations": [value.value for value in self.destinations],
            "jump_hosts": list(self.jump_hosts),
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> "CheckJumpHostsContext":
        require_exact_keys(
            value,
            {
                "check_timeout_seconds",
                "connect_timeout_seconds",
                "depth",
                "destination_checks",
                "destinations",
                "jump_hosts",
                "schema_version",
            },
            "check-jump-hosts operation context",
        )
        if (
            require_string(value, "schema_version")
            != CHECK_JUMP_HOSTS_CONTEXT_SCHEMA_VERSION
        ):
            raise StatePersistenceError(
                "unsupported check-jump-hosts operation context schema"
            )
        jump_hosts_value = value["jump_hosts"]
        destinations_value = value["destinations"]
        checks_value = value["destination_checks"]
        if not isinstance(jump_hosts_value, list) or not all(
            isinstance(item, str) for item in jump_hosts_value
        ):
            raise StatePersistenceError("operation context jump-host IDs are invalid")
        if not isinstance(destinations_value, list) or not all(
            isinstance(item, str) for item in destinations_value
        ):
            raise StatePersistenceError("operation context destinations are invalid")
        if not isinstance(checks_value, list) or not all(
            isinstance(item, dict) for item in checks_value
        ):
            raise StatePersistenceError(
                "operation context destination checks are invalid"
            )
        try:
            destinations = tuple(
                JumpHostDestination(item)
                for item in cast(list[str], destinations_value)
            )
            depth = JumpHostDepth(require_string(value, "depth"))
        except ValueError as error:
            raise StatePersistenceError("operation context enum is invalid") from error
        connect_timeout = value["connect_timeout_seconds"]
        if isinstance(connect_timeout, bool) or not isinstance(connect_timeout, float):
            raise StatePersistenceError(
                "operation context connection timeout must be a JSON number with "
                "fractional type"
            )
        return cls(
            jump_hosts=tuple(cast(list[str], jump_hosts_value)),
            destinations=destinations,
            depth=depth,
            destination_checks=tuple(
                DestinationCheckContext.from_object(item)
                for item in cast(list[dict[str, object]], checks_value)
            ),
            connect_timeout_seconds=connect_timeout,
            check_timeout_seconds=_integer(
                value["check_timeout_seconds"],
                "operation context aggregate timeout",
            ),
        )


@dataclass(frozen=True, slots=True)
class OperationContext:
    """One immutable request-value owner tied to an existing binding v1."""

    generation: int
    created_at: str
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
    values: CheckJumpHostsContext
    intent_context_digest: str
    schema_version: str = ANSIBLE_OPERATION_CONTEXT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != ANSIBLE_OPERATION_CONTEXT_SCHEMA_VERSION:
            raise StatePersistenceError(
                "unsupported Ansible operation context schema version"
            )
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or self.generation != 1
        ):
            raise StatePersistenceError(
                "Ansible operation context generation must be one"
            )
        if not isinstance(self.cluster_uuid, uuid.UUID) or not isinstance(
            self.operation_id, uuid.UUID
        ):
            raise StatePersistenceError(
                "Ansible operation context identities must be UUIDs"
            )
        try:
            validate_cluster_name(self.cluster_name)
            operation = get_operation(self.operation)
        except (ConfigurationError, KeyError) as error:
            raise StatePersistenceError(
                "Ansible operation context identity is invalid"
            ) from error
        if (
            operation.name != "check-jump-hosts"
            or operation.classification is not self.operation_classification
            or self.effective_classification is not OperationClassification.READ_ONLY
            or not isinstance(self.values, CheckJumpHostsContext)
        ):
            raise StatePersistenceError(
                "Ansible operation context operation or classification conflicts"
            )
        if not isinstance(self.created_at, str):
            raise StatePersistenceError(
                "Ansible operation context timestamp must be a string"
            )
        parse_timestamp(self.created_at)
        _validate_stable_ids(
            self.selected_stable_ids,
            allow_empty=False,
            maximum=_MAX_JUMP_HOSTS,
            label="operation context selected stable IDs",
        )
        if self.selected_stable_ids != tuple(sorted(self.selected_stable_ids)):
            raise StatePersistenceError(
                "operation context selected stable IDs must be sorted"
            )
        for label, value in (
            ("operation request digest", self.request_digest),
            ("Ansible operation plan digest", self.plan_digest),
            ("Ansible operation binding digest", self.binding_digest),
            ("Ansible operation intent context digest", self.intent_context_digest),
        ):
            validate_digest(value, label)
        if (
            self.plan_schema_version != ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION
            or self.binding_schema_version != ANSIBLE_OPERATION_BINDING_SCHEMA_VERSION
            or isinstance(self.binding_generation, bool)
            or self.binding_generation != 1
        ):
            raise StatePersistenceError(
                "Ansible operation context bound schema or generation conflicts"
            )
        expected_context_digest = safe_intent_context_digest(
            self.operation,
            self.selected_stable_ids,
            self.values,
        )
        if self.intent_context_digest != expected_context_digest:
            raise StatePersistenceError(
                "Ansible operation intent context digest conflicts"
            )

    def to_object(self) -> dict[str, object]:
        return {
            "binding_digest": self.binding_digest,
            "binding_generation": self.binding_generation,
            "binding_schema_version": self.binding_schema_version,
            "cluster_name": self.cluster_name,
            "cluster_uuid": str(self.cluster_uuid),
            "created_at": self.created_at,
            "effective_classification": self.effective_classification.value,
            "generation": self.generation,
            "intent_context_digest": self.intent_context_digest,
            "operation": self.operation,
            "operation_classification": self.operation_classification.value,
            "operation_id": str(self.operation_id),
            "plan_digest": self.plan_digest,
            "plan_schema_version": self.plan_schema_version,
            "request_digest": self.request_digest,
            "schema_version": self.schema_version,
            "selected_stable_ids": list(self.selected_stable_ids),
            "values": self.values.to_object(),
        }

    def to_public_object(self) -> dict[str, object]:
        """Project no request values, identities, paths, addresses, or commands."""

        return {
            "binding": {
                "digest": self.binding_digest,
                "schema_version": self.binding_schema_version,
            },
            "context_generation": self.generation,
            "effective_classification": self.effective_classification.value,
            "intent_context_digest": self.intent_context_digest,
            "operation": self.operation,
            "operation_classification": self.operation_classification.value,
            "plan": {
                "digest": self.plan_digest,
                "schema_version": self.plan_schema_version,
            },
            "reconstruction": {
                "state": "reconstructable",
                "target_count": len(self.selected_stable_ids),
                "values_schema_version": self.values.schema_version,
            },
            "request_digest": self.request_digest,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> "OperationContext":
        require_exact_keys(
            value,
            {
                "binding_digest",
                "binding_generation",
                "binding_schema_version",
                "cluster_name",
                "cluster_uuid",
                "created_at",
                "effective_classification",
                "generation",
                "intent_context_digest",
                "operation",
                "operation_classification",
                "operation_id",
                "plan_digest",
                "plan_schema_version",
                "request_digest",
                "schema_version",
                "selected_stable_ids",
                "values",
            },
            "Ansible operation context",
        )
        if (
            require_string(value, "schema_version")
            != ANSIBLE_OPERATION_CONTEXT_SCHEMA_VERSION
        ):
            raise StatePersistenceError(
                "unsupported Ansible operation context schema version"
            )
        stable_ids_value = value["selected_stable_ids"]
        values_value = value["values"]
        if not isinstance(stable_ids_value, list) or not all(
            isinstance(item, str) for item in stable_ids_value
        ):
            raise StatePersistenceError(
                "Ansible operation context selected stable IDs are invalid"
            )
        if not isinstance(values_value, dict):
            raise StatePersistenceError("Ansible operation context values are invalid")
        try:
            operation_classification = OperationClassification(
                require_string(value, "operation_classification")
            )
            effective_classification = OperationClassification(
                require_string(value, "effective_classification")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "Ansible operation context classification is invalid"
            ) from error
        operation = require_string(value, "operation")
        if operation != "check-jump-hosts":
            raise StatePersistenceError(
                "Ansible operation context operation is not reconstructable"
            )
        return cls(
            generation=_integer(
                value["generation"], "Ansible operation context generation"
            ),
            created_at=require_string(value, "created_at"),
            cluster_uuid=parse_uuid(
                require_string(value, "cluster_uuid"), "cluster UUID"
            ),
            cluster_name=require_string(value, "cluster_name"),
            operation_id=parse_uuid(
                require_string(value, "operation_id"), "operation ID"
            ),
            operation=operation,
            operation_classification=operation_classification,
            effective_classification=effective_classification,
            selected_stable_ids=tuple(cast(list[str], stable_ids_value)),
            request_digest=require_string(value, "request_digest"),
            plan_schema_version=require_string(value, "plan_schema_version"),
            plan_digest=require_string(value, "plan_digest"),
            binding_schema_version=require_string(value, "binding_schema_version"),
            binding_generation=_integer(
                value["binding_generation"], "operation context binding generation"
            ),
            binding_digest=require_string(value, "binding_digest"),
            values=CheckJumpHostsContext.from_object(
                cast(dict[str, object], values_value)
            ),
            intent_context_digest=require_string(value, "intent_context_digest"),
        )


@dataclass(frozen=True, slots=True)
class StoredOperationContext:
    record: OperationContext
    digest: str


@dataclass(frozen=True, slots=True)
class ReconstructedOperationContext:
    """Exact request and ephemeral address-bearing intents for plan resolution."""

    request: OperationRequest
    active_conditions: tuple[str, ...]
    intents: tuple[AnsibleStepIntent, ...]


class OperationContextStore:
    """Persist one immutable context only after its binding v1 exists."""

    def __init__(
        self,
        paths: StatePaths,
        operation_id: uuid.UUID,
        *,
        replace: Callable[[Path, Path], None] = os.replace,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        _require_canonical_paths(paths)
        if not isinstance(operation_id, uuid.UUID):
            raise StatePersistenceError("operation context ID must be a UUID")
        self._paths = paths
        self._operation_id = operation_id
        self._path = operation_context_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace, token_factory=token_factory
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
    ) -> StoredOperationContext:
        if not hasattr(lock, "assert_held_for"):
            raise StateLockError(
                "Ansible operation context requires an acquired cluster lock"
            )
        lock.assert_held_for(self._paths)
        value, digest = self._file.read()
        record = OperationContext.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or (
                expected_operation is not None
                and record.operation != expected_operation
            )
        ):
            raise StatePersistenceError("Ansible operation context identity mismatch")
        return StoredOperationContext(record, digest)

    def write_locked(
        self,
        record: OperationContext,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredOperationContext:
        _assert_operation_lock(lock, self._paths, record.operation)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError("Ansible operation context ID mismatch")
        binding = OperationPlanBindingStore(
            self._paths, self._operation_id
        ).read_locked(
            lock,
            expected_cluster_uuid=record.cluster_uuid,
            expected_cluster_name=record.cluster_name,
            expected_operation=record.operation,
        )
        _validate_context_binding(record, binding)
        reconstruct_operation_request(self._paths, record, binding)
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
                expected_operation=record.operation,
            )
            if (
                current.record.generation != expected_generation
                or expected_digest is None
                or current.digest != expected_digest
            ):
                raise StatePersistenceError(
                    "Ansible operation context changed concurrently"
                )
            if current.record == record:
                return current
            raise StatePersistenceError("Ansible operation context is immutable")
        if (
            expected_generation != 0
            or expected_digest is not None
            or record.generation != 1
        ):
            raise StatePersistenceError(
                "initial Ansible operation context write requires generation one"
            )
        _refuse_late_initial_context(self._paths, self._operation_id)
        digest = self._file.write(record.to_object(), expected_digest=None)
        return StoredOperationContext(record, digest)


def build_operation_context(
    metadata: ClusterMetadata,
    request: OperationRequest,
    operation_id: uuid.UUID,
    plan: AnsibleOperationPlan,
    binding: StoredOperationPlanBinding,
    *,
    clock: Callable[[], datetime],
) -> OperationContext:
    """Build context after binding and prove exact request/plan equivalence."""

    values = _validated_context_values(request)
    if (
        not isinstance(operation_id, uuid.UUID)
        or metadata.cluster_uuid != binding.record.cluster_uuid
        or metadata.cluster_name != request.cluster_name
        or metadata.cluster_name != binding.record.cluster_name
        or metadata.provider != request.provider.name
        or binding.record.operation_id != operation_id
        or binding.record.operation != request.operation.name
        or binding.record.operation_classification
        is not request.operation.classification
        or plan.operation != request.operation.name
        or plan.operation_classification is not request.operation.classification
        or plan.effective_classification is not binding.record.effective_classification
        or plan.status is not AnsibleOperationPlanStatus.READY
        or plan.schema_version != binding.record.plan_schema_version
        or plan.plan_digest != binding.record.plan_digest
    ):
        raise StateConflictError("Ansible operation context binding conflicts")
    request_digest = normalized_operation_request_digest(request)
    if request_digest != binding.record.request_digest:
        raise StateConflictError("Ansible operation context request binding drifted")
    record = OperationContext(
        generation=1,
        created_at=format_timestamp(clock()),
        cluster_uuid=metadata.cluster_uuid,
        cluster_name=metadata.cluster_name,
        operation_id=operation_id,
        operation=request.operation.name,
        operation_classification=request.operation.classification,
        effective_classification=plan.effective_classification,
        selected_stable_ids=binding.record.selected_stable_ids,
        request_digest=request_digest,
        plan_schema_version=plan.schema_version,
        plan_digest=plan.plan_digest,
        binding_schema_version=binding.record.schema_version,
        binding_generation=binding.record.generation,
        binding_digest=binding.digest,
        values=values,
        intent_context_digest=safe_intent_context_digest(
            request.operation.name,
            binding.record.selected_stable_ids,
            values,
        ),
    )
    reconstructed = reconstruct_operation_request(request.paths, record, binding)
    if normalized_operation_request_digest(reconstructed) != request_digest:
        raise StateConflictError(
            "Ansible operation context cannot reproduce the bound request"
        )
    return record


def resolve_operation_context_input(
    request: OperationRequest,
    inventory: StoredInventoryRecord,
) -> ReconstructedOperationContext:
    """Derive the sole modeled plan input from a typed request and current state."""

    values = _validated_context_values(request)
    try:
        selection = resolve_jump_host_operation_selection(request, inventory)
    except (ConfigurationError, OperationNotImplementedError) as error:
        raise StateConflictError(
            f"Ansible operation context blocker: "
            f"{OPERATION_CONTEXT_RUNTIME_INPUTS_INVALID}"
        ) from error
    selected = tuple(host.logical_id for host in selection.selected)
    timeout = values.connect_timeout_seconds
    return ReconstructedOperationContext(
        request,
        (),
        (
            AnsibleStepIntent(1, selected, {}, check=True),
            AnsibleStepIntent(
                2,
                selected,
                {
                    "deploy_scylla_vms_connect_timeout_seconds": timeout,
                    "deploy_scylla_vms_destination_probes": [
                        probe.to_variable() for probe in selection.probes
                    ],
                    "deploy_scylla_vms_probe_timeout_seconds": max(
                        1, math.ceil(timeout)
                    ),
                },
                check=True,
            ),
        ),
    )


def reconstruct_operation_context(
    paths: StatePaths,
    stored: StoredOperationContext,
    binding: StoredOperationPlanBinding,
    inventory: StoredInventoryRecord,
) -> ReconstructedOperationContext:
    """Rebuild the request and runtime variables only from context plus current state."""

    _require_canonical_paths(paths)
    record = stored.record
    _validate_context_binding(record, binding)
    request = reconstruct_operation_request(paths, record, binding)
    reconstructed = resolve_operation_context_input(request, inventory)
    selected = reconstructed.intents[0].limit
    if tuple(sorted(selected)) != record.selected_stable_ids:
        raise StateConflictError("Ansible operation context target binding drifted")
    return reconstructed


def reconstruct_operation_request(
    paths: StatePaths,
    record: OperationContext,
    binding: StoredOperationPlanBinding,
) -> OperationRequest:
    """Rebuild an exact request without accepting caller values or environment."""

    _require_canonical_paths(paths)
    _validate_context_binding(record, binding)
    values = record.values
    arguments = [
        "--cluster-name",
        record.cluster_name,
        "--state-dir",
        str(paths.state_root),
        "check-jump-hosts",
    ]
    for value in values.jump_hosts:
        arguments.extend(("--jump-host", value))
    for value in values.destinations:
        arguments.extend(("--destination", value.value))
    arguments.extend(("--depth", values.depth.value))
    for destination_check in values.destination_checks:
        arguments.extend(
            (
                "--destination-check",
                f"{destination_check.role.value}={destination_check.port}",
            )
        )
    arguments.extend(
        (
            "--connect-timeout-seconds",
            _decimal_text(values.connect_timeout_seconds),
            "--check-timeout-seconds",
            str(values.check_timeout_seconds),
        )
    )
    request = parse_operation_request(arguments, environ={})
    if normalized_operation_request_digest(request) != record.request_digest:
        raise StateConflictError("Ansible operation context request digest drifted")
    return request


def safe_intent_context_digest(
    operation: str,
    selected_stable_ids: tuple[str, ...],
    values: CheckJumpHostsContext,
) -> str:
    """Digest only safe request selectors; runtime addresses remain excluded."""

    return digest_bytes(
        serialize_json(
            {
                "operation": operation,
                "schema_version": _INTENT_CONTEXT_SCHEMA_VERSION,
                "selected_stable_ids": list(selected_stable_ids),
                "values": values.to_object(),
            }
        )
    )


def operation_context_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError("operation context ID must be a UUID")
    path = paths.operations / f"{operation_id}{OPERATION_CONTEXT_FILENAME_SUFFIX}"
    if path.parent != paths.operations:
        raise StatePersistenceError("Ansible operation context path is not canonical")
    return path


def operation_context_id_from_filename(name: str) -> uuid.UUID | None:
    if not name.endswith(OPERATION_CONTEXT_FILENAME_SUFFIX):
        return None
    identifier_text = name[: -len(OPERATION_CONTEXT_FILENAME_SUFFIX)]
    try:
        identifier = uuid.UUID(identifier_text)
    except ValueError:
        return None
    return identifier if str(identifier) == identifier_text else None


def _check_jump_hosts_values(request: OperationRequest) -> CheckJumpHostsContext:
    try:
        destinations = tuple(
            JumpHostDestination(value)
            for value in _string_tuple(request, "destination")
        )
        depth = JumpHostDepth(_string(request, "depth"))
        checks = tuple(
            DestinationCheckContext(
                DestinationCheckRole(role),
                _strict_integer(port, "destination check port"),
            )
            for role, port in _mapping_tuple(request, "destination_check")
        )
    except ValueError as error:
        raise StateConflictError(
            f"Ansible operation context blocker: {OPERATION_CONTEXT_REQUEST_UNMODELED}"
        ) from error
    connect_timeout = request.option("connect_timeout_seconds").value
    check_timeout = request.option("check_timeout_seconds").value
    if isinstance(connect_timeout, bool) or not isinstance(
        connect_timeout, (int, float)
    ):
        raise StateConflictError(
            f"Ansible operation context blocker: {OPERATION_CONTEXT_REQUEST_UNMODELED}"
        )
    try:
        return CheckJumpHostsContext(
            jump_hosts=_string_tuple(request, "jump_host"),
            destinations=destinations,
            depth=depth,
            destination_checks=checks,
            connect_timeout_seconds=float(connect_timeout),
            check_timeout_seconds=_strict_integer(check_timeout, "aggregate timeout"),
        )
    except StatePersistenceError as error:
        raise StateConflictError(
            f"Ansible operation context blocker: {OPERATION_CONTEXT_REQUEST_UNMODELED}"
        ) from error


def _validated_context_values(request: OperationRequest) -> CheckJumpHostsContext:
    _require_reconstructable_operation(request.operation.name)
    if request.secrets.names:
        raise StateConflictError(
            f"Ansible operation context blocker: {OPERATION_CONTEXT_PROTECTED_INPUTS}"
        )
    values = _check_jump_hosts_values(request)
    _require_canonical_non_context_request(request)
    return values


def validate_check_jump_hosts_operation_request(
    request: OperationRequest,
) -> CheckJumpHostsContext:
    """Validate the bounded reconstructable request without resolving inventory."""

    return _validated_context_values(request)


def _require_canonical_non_context_request(request: OperationRequest) -> None:
    baseline = parse_operation_request(
        [
            "--cluster-name",
            request.cluster_name,
            "--state-dir",
            str(request.paths.state_root),
            "check-jump-hosts",
        ],
        environ={},
    )
    expected = {option.name: option.value for option in baseline.options}
    for option in request.options:
        if option.name in _CONTEXT_REQUEST_FIELDS:
            continue
        if option.name not in expected or option.value != expected[option.name]:
            raise StateConflictError(
                f"Ansible operation context blocker: "
                f"{OPERATION_CONTEXT_REQUEST_UNMODELED}"
            )


def _validate_context_binding(
    context: OperationContext,
    binding: StoredOperationPlanBinding,
) -> None:
    bound = binding.record
    if (
        context.cluster_uuid != bound.cluster_uuid
        or context.cluster_name != bound.cluster_name
        or context.operation_id != bound.operation_id
        or context.operation != bound.operation
        or context.operation_classification is not bound.operation_classification
        or context.effective_classification is not bound.effective_classification
        or context.selected_stable_ids != bound.selected_stable_ids
        or context.request_digest != bound.request_digest
        or context.plan_schema_version != bound.plan_schema_version
        or context.plan_digest != bound.plan_digest
        or context.binding_schema_version != bound.schema_version
        or context.binding_generation != bound.generation
        or context.binding_digest != binding.digest
    ):
        raise StateConflictError("Ansible operation context binding drifted")


def _require_reconstructable_operation(operation: str) -> None:
    if operation != "check-jump-hosts":
        raise StateConflictError(
            f"Ansible operation context blocker: {OPERATION_CONTEXT_UNMODELED}"
        )


def _refuse_late_initial_context(paths: StatePaths, operation_id: uuid.UUID) -> None:
    from scylla_vms.ansible.operation_authorization import (
        OperationAuthorizationStore,
    )
    from scylla_vms.ansible.operation_execution import OperationExecutionStore

    for path in (
        OperationAuthorizationStore(paths, operation_id).path,
        OperationExecutionStore(paths, operation_id).path,
    ):
        validate_state_file(path, allow_missing=True)
        if path.exists():
            raise StateConflictError(
                "Ansible operation context must precede authorization and execution"
            )


def _validate_stable_ids(
    values: tuple[str, ...],
    *,
    allow_empty: bool,
    maximum: int,
    label: str,
) -> None:
    if (
        not isinstance(values, tuple)
        or (not allow_empty and not values)
        or len(values) > maximum
        or len(set(values)) != len(values)
        or not all(
            isinstance(value, str)
            and value.isascii()
            and _LOGICAL_ID.fullmatch(value) is not None
            and not _is_ip_address(value)
            for value in values
        )
    ):
        raise StatePersistenceError(f"{label} are invalid or duplicated")


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _string_tuple(request: OperationRequest, name: str) -> tuple[str, ...]:
    value = request.option(name).value
    if not isinstance(value, tuple) or not all(isinstance(item, str) for item in value):
        raise StateConflictError(
            f"Ansible operation context blocker: {OPERATION_CONTEXT_REQUEST_UNMODELED}"
        )
    return cast(tuple[str, ...], value)


def _mapping_tuple(
    request: OperationRequest, name: str
) -> tuple[tuple[str, object], ...]:
    value = request.option(name).value
    if not isinstance(value, tuple) or not all(
        isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str)
        for item in value
    ):
        raise StateConflictError(
            f"Ansible operation context blocker: {OPERATION_CONTEXT_REQUEST_UNMODELED}"
        )
    return cast(tuple[tuple[str, object], ...], value)


def _string(request: OperationRequest, name: str) -> str:
    value = request.option(name).value
    if not isinstance(value, str):
        raise StateConflictError(
            f"Ansible operation context blocker: {OPERATION_CONTEXT_REQUEST_UNMODELED}"
        )
    return value


def _strict_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"operation context {label} must be an integer")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _decimal_text(value: float) -> str:
    return format(Decimal(str(value)), "f")


def _require_canonical_paths(paths: StatePaths) -> None:
    expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
    if expected != paths or paths.operations.parent != paths.cluster_root:
        raise UnsafePathError("Ansible operation context paths are not canonical")


def _assert_operation_lock(
    lock: ClusterLock, paths: StatePaths, operation: str
) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Ansible operation context requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, operation)
