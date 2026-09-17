"""Durable address-free semantic evidence for internal Ansible operations."""

from __future__ import annotations

import ipaddress
import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, cast

from scylla_vms.ansible.operation_binding import (
    ANSIBLE_OPERATION_BINDING_SCHEMA_VERSION,
    StoredOperationPlanBinding,
    readiness_binding_digest,
)
from scylla_vms.ansible.operation_context import (
    ANSIBLE_OPERATION_CONTEXT_SCHEMA_VERSION,
    CHECK_JUMP_HOSTS_CONTEXT_SCHEMA_VERSION,
    StoredOperationContext,
)
from scylla_vms.ansible.orchestration import (
    ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION,
    AnsibleStepIntent,
)
from scylla_vms.ansible.readiness import READINESS_SCHEMA_VERSION, ReadinessReport
from scylla_vms.ansible.registry import get_playbook
from scylla_vms.ansible.service import (
    ConnectivityEvidence,
    ConnectivityStatus,
    DestinationProbeStatus,
    HostConnectivityStatus,
    InventoryPreflightEvidence,
)
from scylla_vms.errors import (
    ConfigurationError,
    StateConflictError,
    StateLockError,
    StatePersistenceError,
    UnsafePathError,
)
from scylla_vms.locking import ClusterLock
from scylla_vms.operations import OperationClassification, get_operation
from scylla_vms.persistence import (
    AtomicJsonFile,
    digest_bytes,
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

if TYPE_CHECKING:
    from scylla_vms.ansible.operation_execution import OperationStepExecution


ANSIBLE_OPERATION_EVIDENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-operation-evidence/v1"
)
INVENTORY_PREFLIGHT_PROJECTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-operation-evidence.inventory-preflight/v1"
)
CONNECTIVITY_PROJECTION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-operation-evidence.connectivity/v1"
)
OPERATION_EVIDENCE_FILENAME_SUFFIX = ".ansible-operation-evidence.json"

_OPERATION = "check-jump-hosts"
_EXPECTED_PLAYBOOKS = ("inventory-preflight", "connectivity-check")
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SOURCE_VERSION = re.compile(r"[a-z][a-z0-9-]{0,63}/v[1-9][0-9]{0,8}\Z")
_HOST_KEY_OR_FINGERPRINT = re.compile(
    r"(?:ssh-(?:ed25519|rsa)|ecdsa-sha2-nistp256)(?::|$)"
    r"|sha256:[A-Za-z0-9+/=]{16,}\Z",
    re.IGNORECASE,
)
_MAX_HOSTS = 16
_MAX_INVENTORY_HOSTS = 4096
_MAX_DESTINATION_PAIRS = 64
_PROTECTED_ID_COMPONENTS = frozenset(
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


class InventoryPreflightStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    UNREACHABLE = "unreachable"


@dataclass(frozen=True, slots=True)
class InventoryPreflightProjection:
    """Strict inventory parity facts without inventory content."""

    status: InventoryPreflightStatus
    parity: str
    host_count: int
    target_count: int
    inventory_generation: int
    inventory_digest: str
    observation_generation: int
    observation_digest: str
    schema_version: str = INVENTORY_PREFLIGHT_PROJECTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != INVENTORY_PREFLIGHT_PROJECTION_SCHEMA_VERSION
            or not isinstance(self.status, InventoryPreflightStatus)
            or self.parity != "exact"
        ):
            raise StatePersistenceError("inventory preflight projection is invalid")
        _bounded_count(self.host_count, 1, _MAX_INVENTORY_HOSTS, "inventory host")
        _bounded_count(self.target_count, 1, _MAX_HOSTS, "inventory target")
        if self.target_count > self.host_count:
            raise StatePersistenceError("inventory preflight counts conflict")
        _generation(self.inventory_generation, "inventory projection")
        _generation(self.observation_generation, "observation projection")
        validate_digest(self.inventory_digest, "inventory projection digest")
        validate_digest(self.observation_digest, "observation projection digest")

    def to_object(self) -> dict[str, object]:
        return {
            "host_count": self.host_count,
            "inventory_digest": self.inventory_digest,
            "inventory_generation": self.inventory_generation,
            "observation_digest": self.observation_digest,
            "observation_generation": self.observation_generation,
            "parity": self.parity,
            "schema_version": self.schema_version,
            "status": self.status.value,
            "target_count": self.target_count,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> InventoryPreflightProjection:
        require_exact_keys(
            value,
            {
                "host_count",
                "inventory_digest",
                "inventory_generation",
                "observation_digest",
                "observation_generation",
                "parity",
                "schema_version",
                "status",
                "target_count",
            },
            "inventory preflight semantic projection",
        )
        if (
            require_string(value, "schema_version")
            != INVENTORY_PREFLIGHT_PROJECTION_SCHEMA_VERSION
        ):
            raise StatePersistenceError(
                "unsupported inventory preflight projection schema"
            )
        try:
            status = InventoryPreflightStatus(require_string(value, "status"))
        except ValueError as error:
            raise StatePersistenceError(
                "inventory preflight projection status is invalid"
            ) from error
        return cls(
            status=status,
            parity=require_string(value, "parity"),
            host_count=_integer(value["host_count"], "inventory host count"),
            target_count=_integer(value["target_count"], "inventory target count"),
            inventory_generation=_integer(
                value["inventory_generation"], "inventory projection generation"
            ),
            inventory_digest=require_string(value, "inventory_digest"),
            observation_generation=_integer(
                value["observation_generation"], "observation projection generation"
            ),
            observation_digest=require_string(value, "observation_digest"),
        )


@dataclass(frozen=True, slots=True)
class ConnectivityHostProjection:
    logical_id: str
    status: HostConnectivityStatus

    def __post_init__(self) -> None:
        _stable_id(self.logical_id, "connectivity host")
        if not isinstance(self.status, HostConnectivityStatus):
            raise StatePersistenceError("connectivity host status is invalid")

    def to_object(self) -> dict[str, object]:
        return {"logical_id": self.logical_id, "status": self.status.value}

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> ConnectivityHostProjection:
        require_exact_keys(
            value, {"logical_id", "status"}, "connectivity host projection"
        )
        try:
            status = HostConnectivityStatus(require_string(value, "status"))
        except ValueError as error:
            raise StatePersistenceError(
                "connectivity host status is invalid"
            ) from error
        return cls(require_string(value, "logical_id"), status)


@dataclass(frozen=True, slots=True)
class DestinationPairProjection:
    jump_host_id: str
    target_logical_id: str
    role: str
    port: int
    protocol: str
    status: DestinationProbeStatus

    def __post_init__(self) -> None:
        _stable_id(self.jump_host_id, "destination jump host")
        _stable_id(self.target_logical_id, "destination target")
        if (
            self.role not in DESTINATION_CHECK_PORTS
            or isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or self.port not in DESTINATION_CHECK_PORTS[self.role]
            or self.protocol != "tcp"
            or not isinstance(self.status, DestinationProbeStatus)
        ):
            raise StatePersistenceError("destination pair projection is invalid")

    @property
    def key(self) -> tuple[str, str, str, int]:
        return (self.jump_host_id, self.target_logical_id, self.role, self.port)

    def to_object(self) -> dict[str, object]:
        return {
            "jump_host_id": self.jump_host_id,
            "port": self.port,
            "protocol": self.protocol,
            "role": self.role,
            "status": self.status.value,
            "target_logical_id": self.target_logical_id,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> DestinationPairProjection:
        require_exact_keys(
            value,
            {
                "jump_host_id",
                "port",
                "protocol",
                "role",
                "status",
                "target_logical_id",
            },
            "destination pair projection",
        )
        try:
            status = DestinationProbeStatus(require_string(value, "status"))
        except ValueError as error:
            raise StatePersistenceError(
                "destination pair projection status is invalid"
            ) from error
        return cls(
            require_string(value, "jump_host_id"),
            require_string(value, "target_logical_id"),
            require_string(value, "role"),
            _integer(value["port"], "destination pair port"),
            require_string(value, "protocol"),
            status,
        )


@dataclass(frozen=True, slots=True)
class ConnectivityProjection:
    """Per-stable-ID and requested destination-pair semantic outcomes."""

    status: ConnectivityStatus
    hosts: tuple[ConnectivityHostProjection, ...]
    destination_pairs: tuple[DestinationPairProjection, ...]
    schema_version: str = CONNECTIVITY_PROJECTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != CONNECTIVITY_PROJECTION_SCHEMA_VERSION
            or not isinstance(self.status, ConnectivityStatus)
            or not isinstance(self.hosts, tuple)
            or not 1 <= len(self.hosts) <= _MAX_HOSTS
            or not all(
                isinstance(item, ConnectivityHostProjection) for item in self.hosts
            )
            or not isinstance(self.destination_pairs, tuple)
            or len(self.destination_pairs) > _MAX_DESTINATION_PAIRS
            or not all(
                isinstance(item, DestinationPairProjection)
                for item in self.destination_pairs
            )
        ):
            raise StatePersistenceError("connectivity projection is invalid")
        host_ids = tuple(item.logical_id for item in self.hosts)
        if host_ids != tuple(sorted(set(host_ids))):
            raise StatePersistenceError(
                "connectivity projection hosts are duplicated or unordered"
            )
        pair_keys = tuple(item.key for item in self.destination_pairs)
        if pair_keys != tuple(sorted(set(pair_keys))):
            raise StatePersistenceError(
                "destination pair projections are duplicated or unordered"
            )
        if any(
            item.jump_host_id not in set(host_ids) for item in self.destination_pairs
        ):
            raise StatePersistenceError(
                "destination pair jump host is outside the selected hosts"
            )
        expected_status = _connectivity_status(self.hosts, self.destination_pairs)
        if self.status is not expected_status:
            raise StatePersistenceError("connectivity projection status conflicts")

    def to_object(self) -> dict[str, object]:
        return {
            "destination_pairs": [item.to_object() for item in self.destination_pairs],
            "hosts": [item.to_object() for item in self.hosts],
            "schema_version": self.schema_version,
            "status": self.status.value,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> ConnectivityProjection:
        require_exact_keys(
            value,
            {"destination_pairs", "hosts", "schema_version", "status"},
            "connectivity semantic projection",
        )
        if (
            require_string(value, "schema_version")
            != CONNECTIVITY_PROJECTION_SCHEMA_VERSION
        ):
            raise StatePersistenceError("unsupported connectivity projection schema")
        hosts = value["hosts"]
        pairs = value["destination_pairs"]
        if not isinstance(hosts, list) or not all(
            isinstance(item, dict) for item in hosts
        ):
            raise StatePersistenceError("connectivity projection hosts are invalid")
        if not isinstance(pairs, list) or not all(
            isinstance(item, dict) for item in pairs
        ):
            raise StatePersistenceError(
                "connectivity projection destination pairs are invalid"
            )
        try:
            status = ConnectivityStatus(require_string(value, "status"))
        except ValueError as error:
            raise StatePersistenceError("connectivity status is invalid") from error
        return cls(
            status=status,
            hosts=tuple(
                ConnectivityHostProjection.from_object(cast(dict[str, object], item))
                for item in hosts
            ),
            destination_pairs=tuple(
                DestinationPairProjection.from_object(cast(dict[str, object], item))
                for item in pairs
            ),
        )


SemanticProjection = InventoryPreflightProjection | ConnectivityProjection


@dataclass(frozen=True, slots=True)
class OperationEvidenceEntry:
    """One deterministic append-only semantic result."""

    step_sequence: int
    playbook: str
    result_schema_version: str
    command_digest: str
    playbook_source_digest: str
    projection_schema_version: str
    projection_digest: str
    projection: SemanticProjection

    def __post_init__(self) -> None:
        _bounded_count(
            self.step_sequence, 1, len(_EXPECTED_PLAYBOOKS), "evidence step sequence"
        )
        if self.playbook != _EXPECTED_PLAYBOOKS[self.step_sequence - 1]:
            raise StatePersistenceError("operation evidence playbook order is invalid")
        definition = get_playbook(self.playbook)
        if self.result_schema_version != definition.execution_result_schema_version:
            raise StatePersistenceError("operation evidence result schema conflicts")
        validate_digest(self.command_digest, "operation evidence command digest")
        validate_digest(
            self.playbook_source_digest, "operation evidence playbook source digest"
        )
        expected_projection_schema = (
            INVENTORY_PREFLIGHT_PROJECTION_SCHEMA_VERSION
            if self.playbook == "inventory-preflight"
            else CONNECTIVITY_PROJECTION_SCHEMA_VERSION
        )
        if (
            self.projection_schema_version != expected_projection_schema
            or self.projection.schema_version != expected_projection_schema
            or (
                self.playbook == "inventory-preflight"
                and not isinstance(self.projection, InventoryPreflightProjection)
            )
            or (
                self.playbook == "connectivity-check"
                and not isinstance(self.projection, ConnectivityProjection)
            )
        ):
            raise StatePersistenceError(
                "operation evidence projection schema conflicts"
            )
        validate_digest(self.projection_digest, "semantic projection digest")
        if self.projection_digest != semantic_projection_digest(self.projection):
            raise StatePersistenceError("semantic projection digest conflicts")

    def to_object(self) -> dict[str, object]:
        return {
            "command_digest": self.command_digest,
            "playbook": self.playbook,
            "playbook_source_digest": self.playbook_source_digest,
            "projection": self.projection.to_object(),
            "projection_digest": self.projection_digest,
            "projection_schema_version": self.projection_schema_version,
            "result_schema_version": self.result_schema_version,
            "step_sequence": self.step_sequence,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> OperationEvidenceEntry:
        require_exact_keys(
            value,
            {
                "command_digest",
                "playbook",
                "playbook_source_digest",
                "projection",
                "projection_digest",
                "projection_schema_version",
                "result_schema_version",
                "step_sequence",
            },
            "operation evidence entry",
        )
        playbook = require_string(value, "playbook")
        projection_value = value["projection"]
        if not isinstance(projection_value, dict):
            raise StatePersistenceError("operation evidence projection is invalid")
        if playbook == "inventory-preflight":
            projection: SemanticProjection = InventoryPreflightProjection.from_object(
                projection_value
            )
        elif playbook == "connectivity-check":
            projection = ConnectivityProjection.from_object(projection_value)
        else:
            raise StatePersistenceError("operation evidence playbook is unsupported")
        return cls(
            step_sequence=_integer(value["step_sequence"], "evidence step sequence"),
            playbook=playbook,
            result_schema_version=require_string(value, "result_schema_version"),
            command_digest=require_string(value, "command_digest"),
            playbook_source_digest=require_string(value, "playbook_source_digest"),
            projection_schema_version=require_string(
                value, "projection_schema_version"
            ),
            projection_digest=require_string(value, "projection_digest"),
            projection=projection,
        )


@dataclass(frozen=True, slots=True)
class OperationEvidence:
    """Versioned semantic companion bound to one prepared operation."""

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
    entries: tuple[OperationEvidenceEntry, ...]
    schema_version: str = ANSIBLE_OPERATION_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != ANSIBLE_OPERATION_EVIDENCE_SCHEMA_VERSION:
            raise StatePersistenceError(
                "unsupported Ansible operation evidence schema version"
            )
        if not isinstance(self.cluster_uuid, uuid.UUID) or not isinstance(
            self.operation_id, uuid.UUID
        ):
            raise StatePersistenceError("operation evidence identities must be UUIDs")
        try:
            validate_cluster_name(self.cluster_name)
            operation = get_operation(self.operation)
        except (ConfigurationError, KeyError) as error:
            raise StatePersistenceError(
                "operation evidence identity is invalid"
            ) from error
        if (
            operation.name != _OPERATION
            or operation.classification is not self.operation_classification
            or self.effective_classification is not OperationClassification.READ_ONLY
        ):
            raise StatePersistenceError(
                "operation evidence classification or operation conflicts"
            )
        _stable_ids(self.selected_stable_ids)
        if self.selected_stable_ids != tuple(sorted(self.selected_stable_ids)):
            raise StatePersistenceError("operation evidence stable IDs are unordered")
        if (
            not isinstance(self.entries, tuple)
            or not 1 <= len(self.entries) <= len(_EXPECTED_PLAYBOOKS)
            or not all(
                isinstance(item, OperationEvidenceEntry) for item in self.entries
            )
            or tuple(item.step_sequence for item in self.entries)
            != tuple(range(1, len(self.entries) + 1))
            or self.generation != len(self.entries)
        ):
            raise StatePersistenceError(
                "operation evidence entries or generation are invalid"
            )
        for label, value in (
            ("request", self.request_digest),
            ("plan", self.plan_digest),
            ("binding", self.binding_digest),
            ("context", self.context_digest),
            ("catalog", self.catalog_digest),
            ("source", self.source_digest),
            ("readiness", self.readiness_digest),
            ("observation", self.observation_digest),
            ("inventory", self.inventory_digest),
            ("trust", self.trust_digest),
        ):
            validate_digest(value, f"operation evidence {label} digest")
        if (
            self.plan_schema_version != ANSIBLE_OPERATION_PLAN_SCHEMA_VERSION
            or self.binding_schema_version != ANSIBLE_OPERATION_BINDING_SCHEMA_VERSION
            or self.context_schema_version != ANSIBLE_OPERATION_CONTEXT_SCHEMA_VERSION
            or self.context_values_schema_version
            != CHECK_JUMP_HOSTS_CONTEXT_SCHEMA_VERSION
            or self.readiness_schema_version != READINESS_SCHEMA_VERSION
            or not _SOURCE_VERSION.fullmatch(self.source_version)
        ):
            raise StatePersistenceError(
                "operation evidence provenance schema conflicts"
            )
        for generation, label in (
            (self.binding_generation, "binding"),
            (self.context_generation, "context"),
            (self.observation_generation, "observation"),
            (self.inventory_generation, "inventory"),
            (self.trust_generation, "trust"),
        ):
            _generation(generation, f"operation evidence {label}")

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
            "entries": [item.to_object() for item in self.entries],
            "generation": self.generation,
            "inventory_digest": self.inventory_digest,
            "inventory_generation": self.inventory_generation,
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
            "schema_version": self.schema_version,
            "selected_stable_ids": list(self.selected_stable_ids),
            "source_digest": self.source_digest,
            "source_version": self.source_version,
            "trust_digest": self.trust_digest,
            "trust_generation": self.trust_generation,
        }

    @classmethod
    def from_object(cls, value: Mapping[str, object]) -> OperationEvidence:
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
            "entries",
            "generation",
            "inventory_digest",
            "inventory_generation",
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
            "schema_version",
            "selected_stable_ids",
            "source_digest",
            "source_version",
            "trust_digest",
            "trust_generation",
        }
        require_exact_keys(value, fields, "Ansible operation evidence")
        if (
            require_string(value, "schema_version")
            != ANSIBLE_OPERATION_EVIDENCE_SCHEMA_VERSION
        ):
            raise StatePersistenceError(
                "unsupported Ansible operation evidence schema version"
            )
        entries = value["entries"]
        stable_ids = value["selected_stable_ids"]
        if not isinstance(entries, list) or not all(
            isinstance(item, dict) for item in entries
        ):
            raise StatePersistenceError("operation evidence entries are invalid")
        if not isinstance(stable_ids, list) or not all(
            isinstance(item, str) for item in stable_ids
        ):
            raise StatePersistenceError("operation evidence stable IDs are invalid")
        try:
            operation_classification = OperationClassification(
                require_string(value, "operation_classification")
            )
            effective_classification = OperationClassification(
                require_string(value, "effective_classification")
            )
        except ValueError as error:
            raise StatePersistenceError(
                "operation evidence classification is invalid"
            ) from error
        return cls(
            generation=_integer(value["generation"], "operation evidence generation"),
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
            selected_stable_ids=tuple(cast(list[str], stable_ids)),
            request_digest=require_string(value, "request_digest"),
            plan_schema_version=require_string(value, "plan_schema_version"),
            plan_digest=require_string(value, "plan_digest"),
            binding_schema_version=require_string(value, "binding_schema_version"),
            binding_generation=_integer(
                value["binding_generation"], "evidence binding generation"
            ),
            binding_digest=require_string(value, "binding_digest"),
            context_schema_version=require_string(value, "context_schema_version"),
            context_generation=_integer(
                value["context_generation"], "evidence context generation"
            ),
            context_digest=require_string(value, "context_digest"),
            context_values_schema_version=require_string(
                value, "context_values_schema_version"
            ),
            catalog_digest=require_string(value, "catalog_digest"),
            source_version=require_string(value, "source_version"),
            source_digest=require_string(value, "source_digest"),
            readiness_schema_version=require_string(value, "readiness_schema_version"),
            readiness_digest=require_string(value, "readiness_digest"),
            observation_generation=_integer(
                value["observation_generation"], "evidence observation generation"
            ),
            observation_digest=require_string(value, "observation_digest"),
            inventory_generation=_integer(
                value["inventory_generation"], "evidence inventory generation"
            ),
            inventory_digest=require_string(value, "inventory_digest"),
            trust_generation=_integer(
                value["trust_generation"], "evidence trust generation"
            ),
            trust_digest=require_string(value, "trust_digest"),
            entries=tuple(
                OperationEvidenceEntry.from_object(cast(dict[str, object], item))
                for item in entries
            ),
        )


@dataclass(frozen=True, slots=True)
class StoredOperationEvidence:
    record: OperationEvidence
    digest: str


@dataclass(frozen=True, slots=True)
class CheckJumpHostsSemanticFacts:
    """Exact dynamic facts needed by the public-v2 semantic projection."""

    selected_stable_ids: tuple[str, ...]
    inventory_preflight: InventoryPreflightProjection
    connectivity: ConnectivityProjection
    evidence_digest: str


class OperationEvidenceStore:
    """Persist a generation-guarded append-only semantic companion."""

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
            raise StatePersistenceError("operation evidence ID must be a UUID")
        self._paths = paths
        self._operation_id = operation_id
        self._path = operation_evidence_path(paths, operation_id)
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
    ) -> StoredOperationEvidence:
        _assert_read_lock(lock, self._paths)
        value, digest = self._file.read()
        record = OperationEvidence.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
            or (
                expected_operation is not None
                and record.operation != expected_operation
            )
        ):
            raise StatePersistenceError("Ansible operation evidence identity mismatch")
        return StoredOperationEvidence(record, digest)

    def write_locked(
        self,
        record: OperationEvidence,
        *,
        expected_generation: int,
        expected_digest: str | None,
        lock: ClusterLock,
    ) -> StoredOperationEvidence:
        _assert_operation_lock(lock, self._paths, record.operation)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError("Ansible operation evidence ID mismatch")
        if not self._path.exists():
            if (
                expected_generation != 0
                or expected_digest is not None
                or record.generation != 1
            ):
                raise StatePersistenceError(
                    "initial operation evidence write requires generation one"
                )
        else:
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
                expected_operation=record.operation,
            )
            if (
                expected_digest is None
                or current.digest != expected_digest
                or current.record.generation != expected_generation
            ):
                raise StatePersistenceError(
                    "Ansible operation evidence changed concurrently"
                )
            _validate_evidence_transition(current.record, record)
        digest = self._file.write(record.to_object(), expected_digest=expected_digest)
        return StoredOperationEvidence(record, digest)


def persist_operation_step_evidence(
    lock: ClusterLock,
    paths: StatePaths,
    binding: StoredOperationPlanBinding,
    context: StoredOperationContext,
    readiness: ReadinessReport,
    step: OperationStepExecution,
    evidence: object,
    *,
    store: OperationEvidenceStore | None = None,
) -> tuple[StoredOperationEvidence, OperationEvidenceEntry]:
    """Project and append one strictly parsed result before returning its receipt."""

    _require_canonical_paths(paths)
    _assert_operation_lock(lock, paths, context.record.operation)
    if paths.cluster_root.name != context.record.cluster_name:
        raise StateConflictError("operation evidence lock scope conflicts")
    selected_store = store or OperationEvidenceStore(paths, step.operation_id)
    if selected_store.path != operation_evidence_path(paths, step.operation_id):
        raise StateConflictError("operation evidence store scope conflicts")
    _validate_inputs(binding, context, readiness, step)
    projection = project_step_semantic_evidence(step, evidence)
    entry = OperationEvidenceEntry(
        step_sequence=step.step_sequence,
        playbook=step.playbook,
        result_schema_version=step.result_schema_version,
        command_digest=step.command_digest,
        playbook_source_digest=step.playbook_source_digest,
        projection_schema_version=projection.schema_version,
        projection_digest=semantic_projection_digest(projection),
        projection=projection,
    )
    validate_state_file(selected_store.path, allow_missing=True)
    current = (
        selected_store.read_locked(
            lock,
            expected_cluster_uuid=binding.record.cluster_uuid,
            expected_cluster_name=binding.record.cluster_name,
            expected_operation=_OPERATION,
        )
        if selected_store.path.exists()
        else None
    )
    if current is not None:
        validate_operation_evidence_checkpoint(
            current, binding=binding, context=context, readiness=readiness
        )
        if step.step_sequence <= len(current.record.entries):
            existing = current.record.entries[step.step_sequence - 1]
            if existing == entry and step.step_sequence == len(current.record.entries):
                return current, existing
            raise StateConflictError(
                "operation evidence entry conflicts or is not the latest entry"
            )
        if step.step_sequence != len(current.record.entries) + 1:
            raise StateConflictError("operation evidence append order conflicts")
        candidate = replace(
            current.record,
            generation=current.record.generation + 1,
            entries=(*current.record.entries, entry),
        )
        stored = selected_store.write_locked(
            candidate,
            expected_generation=current.record.generation,
            expected_digest=current.digest,
            lock=lock,
        )
        return stored, entry
    if step.step_sequence != 1:
        raise StateConflictError("operation evidence cannot begin after the first step")
    candidate = _initial_record(binding, context, readiness, entry)
    stored = selected_store.write_locked(
        candidate,
        expected_generation=0,
        expected_digest=None,
        lock=lock,
    )
    return stored, entry


def verify_persisted_operation_evidence_entry(
    lock: ClusterLock,
    paths: StatePaths,
    binding: StoredOperationPlanBinding,
    context: StoredOperationContext,
    readiness: ReadinessReport,
    step: OperationStepExecution,
    projection_digest: str,
) -> StoredOperationEvidence:
    """Require the exact durable entry before terminal success is recorded."""

    _assert_operation_lock(lock, paths, _OPERATION)
    validate_digest(projection_digest, "executor semantic projection digest")
    store = OperationEvidenceStore(paths, step.operation_id)
    validate_state_file(store.path, allow_missing=False)
    stored = store.read_locked(
        lock,
        expected_cluster_uuid=binding.record.cluster_uuid,
        expected_cluster_name=binding.record.cluster_name,
        expected_operation=_OPERATION,
    )
    validate_operation_evidence_checkpoint(
        stored, binding=binding, context=context, readiness=readiness
    )
    if len(stored.record.entries) != step.step_sequence:
        raise StateConflictError("durable semantic evidence sequence conflicts")
    entry = stored.record.entries[step.step_sequence - 1]
    if (
        entry.step_sequence != step.step_sequence
        or entry.playbook != step.playbook
        or entry.result_schema_version != step.result_schema_version
        or entry.command_digest != step.command_digest
        or entry.playbook_source_digest != step.playbook_source_digest
        or entry.projection_digest != projection_digest
    ):
        raise StateConflictError("durable semantic evidence entry conflicts")
    return stored


def validate_operation_evidence_checkpoint(
    stored: StoredOperationEvidence,
    *,
    binding: StoredOperationPlanBinding,
    context: StoredOperationContext,
    readiness: ReadinessReport | None = None,
) -> None:
    """Validate all immutable provenance against current canonical companions."""

    record = stored.record
    bound = binding.record
    contextual = context.record
    if (
        record.cluster_uuid != bound.cluster_uuid
        or record.cluster_name != bound.cluster_name
        or record.operation_id != bound.operation_id
        or record.operation != bound.operation
        or record.operation_classification is not bound.operation_classification
        or record.effective_classification is not bound.effective_classification
        or record.selected_stable_ids != bound.selected_stable_ids
        or record.request_digest != bound.request_digest
        or record.plan_schema_version != bound.plan_schema_version
        or record.plan_digest != bound.plan_digest
        or record.binding_schema_version != bound.schema_version
        or record.binding_generation != bound.generation
        or record.binding_digest != binding.digest
        or record.context_schema_version != contextual.schema_version
        or record.context_generation != contextual.generation
        or record.context_digest != context.digest
        or record.context_values_schema_version != contextual.values.schema_version
        or record.catalog_digest != bound.catalog_digest
        or record.source_version != bound.source_version
        or record.source_digest != bound.source_digest
        or record.readiness_schema_version != bound.readiness_schema_version
        or record.readiness_digest != bound.readiness_digest
        or record.observation_generation != bound.observation_generation
        or record.observation_digest != bound.observation_digest
        or record.inventory_generation != bound.inventory_generation
        or record.inventory_digest != bound.inventory_digest
        or record.trust_generation != bound.trust_generation
        or record.trust_digest != bound.trust_digest
    ):
        raise StateConflictError("durable semantic evidence provenance drifted")
    if readiness is not None and (
        readiness.schema_version != record.readiness_schema_version
        or readiness_binding_digest(readiness) != record.readiness_digest
    ):
        raise StateConflictError("durable semantic evidence readiness drifted")
    first = record.entries[0].projection
    if not isinstance(first, InventoryPreflightProjection):
        raise StateConflictError("inventory preflight semantic evidence is missing")
    if (
        first.inventory_generation != record.inventory_generation
        or first.inventory_digest != record.inventory_digest
        or first.observation_generation != record.observation_generation
        or first.observation_digest != record.observation_digest
        or first.target_count != len(record.selected_stable_ids)
    ):
        raise StateConflictError("inventory preflight semantic provenance drifted")


def reconstruct_check_jump_hosts_semantic_facts(
    stored: StoredOperationEvidence,
    *,
    binding: StoredOperationPlanBinding,
    context: StoredOperationContext,
    intents: tuple[AnsibleStepIntent, ...],
) -> CheckJumpHostsSemanticFacts:
    """Prove that all dynamic public-v2 semantic facts are durably available."""

    validate_operation_evidence_checkpoint(
        stored, binding=binding, context=context, readiness=None
    )
    validate_operation_evidence_intents(stored, intents)
    if (
        len(stored.record.entries) != 2
        or tuple(item.playbook for item in stored.record.entries) != _EXPECTED_PLAYBOOKS
    ):
        raise StateConflictError(
            "check-jump-hosts durable semantic evidence is incomplete"
        )
    inventory = stored.record.entries[0].projection
    connectivity = stored.record.entries[1].projection
    if not isinstance(inventory, InventoryPreflightProjection) or not isinstance(
        connectivity, ConnectivityProjection
    ):
        raise StateConflictError("check-jump-hosts semantic evidence types conflict")
    if (
        inventory.status is not InventoryPreflightStatus.PASSED
        or connectivity.status is not ConnectivityStatus.SUCCESS
        or tuple(item.logical_id for item in connectivity.hosts)
        != stored.record.selected_stable_ids
    ):
        raise StateConflictError(
            "check-jump-hosts semantic evidence cannot prove successful facts"
        )
    return CheckJumpHostsSemanticFacts(
        stored.record.selected_stable_ids,
        inventory,
        connectivity,
        stored.digest,
    )


def validate_operation_evidence_intents(
    stored: StoredOperationEvidence,
    intents: tuple[AnsibleStepIntent, ...],
) -> None:
    """Re-derive exact host and address-free pair membership from current intents."""

    if (
        not isinstance(intents, tuple)
        or len(intents) != len(_EXPECTED_PLAYBOOKS)
        or tuple(item.sequence for item in intents) != (1, 2)
    ):
        raise StateConflictError("operation evidence intent sequence is invalid")
    for entry, intent in zip(
        stored.record.entries,
        intents[: len(stored.record.entries)],
        strict=True,
    ):
        if entry.step_sequence != intent.sequence:
            raise StateConflictError("operation evidence intent order conflicts")
        if isinstance(entry.projection, InventoryPreflightProjection):
            if (
                entry.projection.target_count != len(intent.limit)
                or tuple(sorted(intent.limit)) != stored.record.selected_stable_ids
            ):
                raise StateConflictError(
                    "inventory preflight semantic target membership conflicts"
                )
        elif tuple(item.logical_id for item in entry.projection.hosts) != tuple(
            sorted(intent.limit)
        ) or tuple(
            item.key for item in entry.projection.destination_pairs
        ) != _expected_destination_pairs(intent.variables):
            raise StateConflictError(
                "connectivity semantic target membership conflicts"
            )


def project_step_semantic_evidence(
    step: OperationStepExecution, evidence: object
) -> SemanticProjection:
    """Allowlist one strict parser result and revalidate its requested membership."""

    if step.operation != _OPERATION:
        raise StateConflictError("semantic operation evidence is not modeled")
    _stable_ids(step.limit)
    if step.playbook == "inventory-preflight":
        if not isinstance(evidence, InventoryPreflightEvidence):
            raise StatePersistenceError("inventory preflight evidence type is invalid")
        try:
            status = InventoryPreflightStatus(evidence.status)
        except ValueError as error:
            raise StatePersistenceError(
                "inventory preflight evidence status is invalid"
            ) from error
        projection = InventoryPreflightProjection(
            status=status,
            parity="exact",
            host_count=evidence.host_count,
            target_count=evidence.target_count,
            inventory_generation=evidence.inventory_generation,
            inventory_digest=evidence.inventory_file_digest,
            observation_generation=evidence.observation_generation,
            observation_digest=evidence.observation_digest,
        )
        if projection.target_count != len(step.limit):
            raise StateConflictError("inventory preflight target count conflicts")
        return projection
    if step.playbook != "connectivity-check" or not isinstance(
        evidence, ConnectivityEvidence
    ):
        raise StatePersistenceError("connectivity semantic evidence type is invalid")
    hosts = tuple(
        ConnectivityHostProjection(item.logical_id, item.status)
        for item in evidence.hosts
    )
    if tuple(item.logical_id for item in hosts) != tuple(sorted(step.limit)):
        raise StateConflictError("connectivity semantic host membership conflicts")
    expected_pairs = _expected_destination_pairs(step.variables)
    pairs = tuple(
        DestinationPairProjection(
            item.jump_host_id,
            item.target_logical_id,
            item.role,
            item.port,
            "tcp",
            item.status,
        )
        for item in evidence.destination_probes
    )
    if tuple(item.key for item in pairs) != expected_pairs:
        raise StateConflictError(
            "connectivity semantic destination membership conflicts"
        )
    return ConnectivityProjection(evidence.status, hosts, pairs)


def semantic_projection_digest(projection: SemanticProjection) -> str:
    return digest_bytes(serialize_json(projection.to_object()))


def operation_evidence_path(paths: StatePaths, operation_id: uuid.UUID) -> Path:
    if not isinstance(operation_id, uuid.UUID):
        raise StatePersistenceError("operation evidence ID must be a UUID")
    path = paths.operations / f"{operation_id}{OPERATION_EVIDENCE_FILENAME_SUFFIX}"
    if path.parent != paths.operations:
        raise StatePersistenceError("Ansible operation evidence path is not canonical")
    return path


def operation_evidence_id_from_filename(name: str) -> uuid.UUID | None:
    if not name.endswith(OPERATION_EVIDENCE_FILENAME_SUFFIX):
        return None
    value = name[: -len(OPERATION_EVIDENCE_FILENAME_SUFFIX)]
    try:
        identifier = uuid.UUID(value)
    except ValueError:
        return None
    return identifier if str(identifier) == value else None


def _initial_record(
    binding: StoredOperationPlanBinding,
    context: StoredOperationContext,
    readiness: ReadinessReport,
    entry: OperationEvidenceEntry,
) -> OperationEvidence:
    bound = binding.record
    contextual = context.record
    if bound.observation_generation is None or bound.observation_digest is None:
        raise StateConflictError("operation evidence observation binding is missing")
    if bound.trust_generation is None or bound.trust_digest is None:
        raise StateConflictError("operation evidence trust binding is missing")
    return OperationEvidence(
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
        binding_digest=binding.digest,
        context_schema_version=contextual.schema_version,
        context_generation=contextual.generation,
        context_digest=context.digest,
        context_values_schema_version=contextual.values.schema_version,
        catalog_digest=bound.catalog_digest,
        source_version=bound.source_version,
        source_digest=bound.source_digest,
        readiness_schema_version=readiness.schema_version,
        readiness_digest=readiness_binding_digest(readiness),
        observation_generation=bound.observation_generation,
        observation_digest=bound.observation_digest,
        inventory_generation=bound.inventory_generation,
        inventory_digest=bound.inventory_digest,
        trust_generation=bound.trust_generation,
        trust_digest=bound.trust_digest,
        entries=(entry,),
    )


def _validate_inputs(
    binding: StoredOperationPlanBinding,
    context: StoredOperationContext,
    readiness: ReadinessReport,
    step: OperationStepExecution,
) -> None:
    bound = binding.record
    contextual = context.record
    if (
        step.operation != _OPERATION
        or step.operation_id != bound.operation_id
        or step.classification is not OperationClassification.READ_ONLY
        or step.limit != bound.selected_stable_ids
        or contextual.operation_id != bound.operation_id
        or contextual.binding_digest != binding.digest
        or contextual.selected_stable_ids != bound.selected_stable_ids
        or readiness.schema_version != bound.readiness_schema_version
        or readiness_binding_digest(readiness) != bound.readiness_digest
    ):
        raise StateConflictError("semantic operation evidence input binding drifted")


def _expected_destination_pairs(
    variables: Mapping[str, object],
) -> tuple[tuple[str, str, str, int], ...]:
    raw = variables.get("deploy_scylla_vms_destination_probes")
    if not isinstance(raw, list) or len(raw) > _MAX_DESTINATION_PAIRS:
        raise StatePersistenceError("destination pair request is invalid")
    pairs: list[tuple[str, str, str, int]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise StatePersistenceError("destination pair request is invalid")
        require_exact_keys(
            item,
            {"address", "jump_host_id", "port", "role", "target_logical_id"},
            "destination pair request",
        )
        jump = require_string(item, "jump_host_id")
        target = require_string(item, "target_logical_id")
        role = require_string(item, "role")
        port = _integer(item["port"], "destination pair request port")
        address = require_string(item, "address")
        _stable_id(jump, "destination pair jump host")
        _stable_id(target, "destination pair target")
        try:
            ipaddress.ip_address(address)
        except ValueError as error:
            raise StatePersistenceError(
                "destination pair runtime address is invalid"
            ) from error
        if (
            role not in DESTINATION_CHECK_PORTS
            or port not in DESTINATION_CHECK_PORTS[role]
        ):
            raise StatePersistenceError("destination pair role or port is invalid")
        pairs.append((jump, target, role, port))
    result = tuple(pairs)
    if result != tuple(sorted(set(result))):
        raise StatePersistenceError(
            "destination pair request is duplicated or unordered"
        )
    return result


def _connectivity_status(
    hosts: tuple[ConnectivityHostProjection, ...],
    pairs: tuple[DestinationPairProjection, ...],
) -> ConnectivityStatus:
    host_failures = sum(
        item.status is not HostConnectivityStatus.REACHABLE for item in hosts
    )
    pair_failures = sum(
        item.status is not DestinationProbeStatus.PASSED for item in pairs
    )
    if host_failures + pair_failures == 0:
        return ConnectivityStatus.SUCCESS
    if host_failures == len(hosts):
        return ConnectivityStatus.FAILURE
    return ConnectivityStatus.PARTIAL_FAILURE


def _validate_evidence_transition(
    previous: OperationEvidence, current: OperationEvidence
) -> None:
    if (
        current.generation != previous.generation + 1
        or len(current.entries) != len(previous.entries) + 1
        or current.entries[:-1] != previous.entries
    ):
        raise StatePersistenceError("operation evidence append transition is invalid")
    before = previous.to_object()
    after = current.to_object()
    for key in ("entries", "generation"):
        before.pop(key)
        after.pop(key)
    if before != after:
        raise StatePersistenceError("operation evidence provenance is immutable")


def _require_canonical_paths(paths: StatePaths) -> None:
    expected = StatePaths.derive(paths.state_root, paths.cluster_root.name)
    if expected != paths or paths.operations.parent != paths.cluster_root:
        raise UnsafePathError("Ansible operation evidence paths are not canonical")


def _assert_operation_lock(
    lock: ClusterLock, paths: StatePaths, operation: str
) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Ansible operation evidence requires an acquired cluster lock"
        )
    lock.assert_held_for_operation(paths, operation)


def _assert_read_lock(lock: object, paths: StatePaths) -> None:
    assertion = getattr(lock, "assert_held_for", None)
    if not callable(assertion):
        raise StateLockError(
            "Ansible operation evidence read requires an acquired cluster lock"
        )
    assertion(paths)


def _stable_ids(values: tuple[str, ...]) -> None:
    if (
        not isinstance(values, tuple)
        or not 1 <= len(values) <= _MAX_HOSTS
        or values != tuple(dict.fromkeys(values))
    ):
        raise StatePersistenceError("operation evidence stable IDs are invalid")
    for value in values:
        _stable_id(value, "operation evidence stable ID")


def _stable_id(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or _LOGICAL_ID.fullmatch(value) is None
        or ".." in value
        or _is_ip_address(value)
        or _HOST_KEY_OR_FINGERPRINT.match(value) is not None
        or any(
            item in _PROTECTED_ID_COMPONENTS
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
