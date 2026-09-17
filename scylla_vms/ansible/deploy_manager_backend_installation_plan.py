"""Immutable planning for the Manager VM's local one-node ScyllaDB backend.

This owner is deliberately subprocess-free.  It binds the exact successful
Manager backend preflight chain, derives only reviewed package and storage
facts, and records the still-blocked ordered boundaries required before the
local backend can exist.
"""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, is_dataclass
from datetime import UTC, datetime
from enum import Enum, StrEnum
from pathlib import Path
from typing import cast

from scylla_vms.ansible.deploy_manager_backend_configuration_plan import (
    MANAGER_BACKEND_LOCAL_ONE_NODE_POLICY_SCHEMA_VERSION,
    DeployManagerBackendMode,
)
from scylla_vms.ansible.deploy_manager_backend_preflight_execution import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION,
    ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION,
    DeployManagerBackendPreflightEvidence,
    DeployManagerBackendPreflightExecutionState,
    _ExecutionContext,
    _load_execution_context,
    _validate_execution_prefix,
)
from scylla_vms.ansible.deploy_manager_backend_preflight_reconciliation import (
    ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION,
    DeployManagerBackendPreflightInstallationPlanningState,
    DeployManagerBackendPreflightReconciliationStore,
    StoredDeployManagerBackendPreflightReconciliation,
    _load_reconciliation_context,
)
from scylla_vms.ansible.deploy_manager_backend_preflight_reconciliation import (
    _build_record as _build_preflight_reconciliation_record,
)
from scylla_vms.ansible.deploy_plan import (
    _digest_object,
    _playbook_source_digest,
    _require_operation_id,
)
from scylla_vms.ansible.manager_backend_preflight import (
    MANAGER_BACKEND_SCYLLA_RELEASE,
    ManagerBackendLoopbackStatus,
    ManagerBackendPackageStatus,
    ManagerBackendServiceStatus,
)
from scylla_vms.ansible.scylla_install import (
    SCYLLA_CHANNEL,
    SCYLLA_EDITION,
    SCYLLA_PACKAGE_VERSION,
    SCYLLA_PACKAGES,
    SCYLLA_RELEASE_LINE,
    SCYLLA_REPOSITORY_DEFINITION_DIGEST,
    SCYLLA_SIGNING_KEY_DIGEST,
    SCYLLA_SIGNING_KEY_FINGERPRINT,
    SCYLLA_SIGNING_KEY_UID,
    SCYLLA_SIGNING_SUBKEY_FINGERPRINT,
    load_scylla_signing_key,
    validate_scylla_signing_key,
)
from scylla_vms.ansible.source import load_ansible_source_bundle
from scylla_vms.desired import (
    ClusterSpec,
    HostRole,
    StorageBackend,
    StorageLayout,
)
from scylla_vms.errors import (
    StateConflictError,
    StateLockError,
    StatePersistenceError,
)
from scylla_vms.journal import JOURNAL_SCHEMA_VERSION, JournalStatus, OperationPhase
from scylla_vms.locking import ClusterLock
from scylla_vms.observed import StoredObservedState
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
from scylla_vms.terraform.outputs import (
    StorageDeviceKind,
    StorageManifest,
    StorageSelectionStatus,
)

ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PACKAGE_REFERENCE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-installation-package-reference/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_STORAGE_DECISION_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-installation-storage-decision/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_GATE_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-installation-gate/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-installation-context/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_STEP_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-installation-plan-step/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-installation-plan/v1"
)
ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_REPORT_SCHEMA_VERSION = (
    "deploy-scylla-vms.ansible-deploy-manager-backend-installation-plan-report/v1"
)

DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-installation-context.json"
)
DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_FILENAME_SUFFIX = (
    ".ansible-deploy-manager-backend-installation-plan.json"
)

_OPERATION = "deploy"
_STAGE = "manager-backend-local-installation"
_ORIGINAL_MAPPING_COUNT = 21
_NOT_PERFORMED = "not-performed"
_UNAVAILABLE = "unavailable"
_AUTHORIZATION_REQUIRED = "package-install-authorization-required"
_LEGACY_NEXT_IMPLEMENTATION_CONTRACT = (
    "manager-backend-local-package-install-source-contract"
)
_AUTHORIZATION_OWNER_IMPLEMENTATION_CONTRACT = (
    "manager-backend-local-install-authorization-owner"
)
_NEXT_IMPLEMENTATION_CONTRACT = "manager-backend-local-install-execution-owner"
_PACKAGE_PLAYBOOK = "manager-backend-local-install"
_PACKAGE_SOURCE_CONTRACT = "manager-backend-local-install-v1"
_PACKAGE_AUTHORIZATION_BLOCKERS = (
    "deploy-authorization-not-collected",
    "mutating-deploy-execution-unavailable",
    "public-deploy-workflow-unavailable",
)
_LOGICAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_BLOCKER = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")

_BOUNDARIES = (
    "package-install",
    "local-storage-allocation",
    "local-storage-preflight",
    "local-storage-preparation",
    "local-storage-postcheck",
    "scylla-local-configuration-tuning",
    "one-node-bootstrap-start-health",
    "manager-backend-file-configuration",
    "schema-keyspace-create-verify",
)
_BOUNDARY_CLASSIFICATIONS = (
    OperationClassification.MUTATING,
    OperationClassification.MUTATING,
    OperationClassification.READ_ONLY,
    OperationClassification.DESTRUCTIVE,
    OperationClassification.READ_ONLY,
    OperationClassification.MUTATING,
    OperationClassification.SENSITIVE,
    OperationClassification.MUTATING,
    OperationClassification.SENSITIVE,
)
_BOUNDARY_SOURCE_BLOCKERS = (
    "manager-backend-package-install-source-unavailable",
    "manager-backend-storage-allocation-source-unavailable",
    "manager-backend-storage-preflight-source-unavailable",
    "manager-backend-storage-prepare-source-unavailable",
    "manager-backend-storage-postcheck-source-unavailable",
    "manager-backend-local-config-tuning-source-unavailable",
    "manager-backend-one-node-bootstrap-source-unavailable",
    "manager-backend-file-configuration-source-unavailable",
    "manager-backend-schema-keyspace-source-unavailable",
)


class DeployManagerBackendInstallationArtifactState(StrEnum):
    CREATED = "created"
    REUSED = "reused"


class DeployManagerBackendInstallationGateState(StrEnum):
    PASSED = "passed"
    UNKNOWN = "unknown"
    BLOCKED = "blocked"


class DeployManagerBackendInstallationStorageState(StrEnum):
    IDENTIFIED = "dedicated-manager-volume-identified"
    UNMODELED = "dedicated-backend-storage-unmodeled"


class DeployManagerBackendInstallationSourceState(StrEnum):
    AVAILABLE = "source-available"
    UNAVAILABLE = "source-unavailable"


class DeployManagerBackendInstallationPlanStatus(StrEnum):
    BLOCKED = "blocked"
    EVIDENCE_READY_AUTHORIZATION_REQUIRED = "evidence-ready-authorization-required"


@dataclass(frozen=True, slots=True)
class DeployManagerBackendInstallationPackageReference:
    """Authenticated package facts bound to the Manager-local install contract."""

    release_line: str
    package_version: str
    edition: str
    channel: str
    package_count: int
    package_set_digest: str
    package_set_policy: str
    repository_definition_digest: str
    signing_key_artifact_digest: str
    signing_key_identity_digest: str
    authentication_state: str
    target_contract_state: str
    reference_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PACKAGE_REFERENCE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PACKAGE_REFERENCE_SCHEMA_VERSION
            or self.release_line != SCYLLA_RELEASE_LINE
            or self.package_version != SCYLLA_PACKAGE_VERSION
            or self.edition != SCYLLA_EDITION
            or self.channel != SCYLLA_CHANNEL
            or self.package_count != len(SCYLLA_PACKAGES)
            or self.package_set_digest != _digest_object(list(SCYLLA_PACKAGES))
            or self.package_set_policy
            not in {
                "reference-only-unapproved-for-manager",
                "exact-manager-local-backend-package-set-approved",
            }
            or self.repository_definition_digest != SCYLLA_REPOSITORY_DEFINITION_DIGEST
            or self.signing_key_artifact_digest != SCYLLA_SIGNING_KEY_DIGEST
            or self.signing_key_identity_digest != _signing_key_identity_digest()
            or self.authentication_state != "authenticated"
            or self.target_contract_state
            not in {
                "manager-role-contract-unavailable",
                "manager-backend-local-install-source-available",
            }
            or (self.package_set_policy == "reference-only-unapproved-for-manager")
            is not (self.target_contract_state == "manager-role-contract-unavailable")
            or self.reference_digest != _record_digest(self, "reference_digest")
        ):
            raise StatePersistenceError(
                "Manager backend installation package reference conflicts"
            )
        _positive_integer(self.package_count, "package reference count")
        for value in _digest_fields(self):
            validate_digest(value, "Manager backend package-reference digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendInstallationPackageReference:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend installation package reference",
        )
        return cls(
            release_line=require_string(value, "release_line"),
            package_version=require_string(value, "package_version"),
            edition=require_string(value, "edition"),
            channel=require_string(value, "channel"),
            package_count=_integer(value["package_count"], "package count"),
            package_set_digest=require_string(value, "package_set_digest"),
            package_set_policy=require_string(value, "package_set_policy"),
            repository_definition_digest=require_string(
                value, "repository_definition_digest"
            ),
            signing_key_artifact_digest=require_string(
                value, "signing_key_artifact_digest"
            ),
            signing_key_identity_digest=require_string(
                value, "signing_key_identity_digest"
            ),
            authentication_state=require_string(value, "authentication_state"),
            target_contract_state=require_string(value, "target_contract_state"),
            reference_digest=require_string(value, "reference_digest"),
            schema_version=require_string(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendInstallationStorageDecision:
    """Address-free decision about the Manager's dedicated Terraform volume."""

    state: DeployManagerBackendInstallationStorageState
    dedicated_volume_identified: bool
    desired_backend: str
    observed_backend: str
    selection_state: str
    expected_device_count: int
    storage_generation: int
    desired_policy_digest: str
    observed_manifest_digest: str
    volume_identity_digest: str | None
    provider_storage_binding_digest: str
    root_fallback_policy: str
    generic_root_capacity_accepted: bool
    decision_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_STORAGE_DECISION_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        identified = (
            self.state is DeployManagerBackendInstallationStorageState.IDENTIFIED
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_STORAGE_DECISION_SCHEMA_VERSION
            or self.dedicated_volume_identified is not identified
            or self.root_fallback_policy != "forbidden"
            or self.generic_root_capacity_accepted
            or self.expected_device_count not in {0, 1}
            or self.storage_generation < 0
            or (
                identified
                and (
                    self.desired_backend != StorageBackend.BLOCK_VOLUME.value
                    or self.observed_backend != StorageBackend.BLOCK_VOLUME.value
                    or self.selection_state
                    not in {
                        StorageSelectionStatus.PROVISIONAL.value,
                        StorageSelectionStatus.FINAL.value,
                    }
                    or self.expected_device_count != 1
                    or self.storage_generation < 1
                    or self.volume_identity_digest is None
                )
            )
            or (
                not identified
                and (
                    self.volume_identity_digest is not None
                    or self.expected_device_count != 0
                )
            )
            or self.decision_digest != _record_digest(self, "decision_digest")
        ):
            raise StatePersistenceError(
                "Manager backend installation storage decision conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(value, "Manager backend storage-decision digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendInstallationStorageDecision:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend installation storage decision",
        )
        identity = value["volume_identity_digest"]
        if identity is not None and not isinstance(identity, str):
            raise StatePersistenceError(
                "Manager backend volume identity digest is invalid"
            )
        try:
            return cls(
                state=DeployManagerBackendInstallationStorageState(
                    require_string(value, "state")
                ),
                dedicated_volume_identified=_boolean(
                    value["dedicated_volume_identified"],
                    "dedicated volume identified",
                ),
                desired_backend=require_string(value, "desired_backend"),
                observed_backend=require_string(value, "observed_backend"),
                selection_state=require_string(value, "selection_state"),
                expected_device_count=_integer(
                    value["expected_device_count"], "expected device count"
                ),
                storage_generation=_integer(
                    value["storage_generation"], "storage generation"
                ),
                desired_policy_digest=require_string(value, "desired_policy_digest"),
                observed_manifest_digest=require_string(
                    value, "observed_manifest_digest"
                ),
                volume_identity_digest=identity,
                provider_storage_binding_digest=require_string(
                    value, "provider_storage_binding_digest"
                ),
                root_fallback_policy=require_string(value, "root_fallback_policy"),
                generic_root_capacity_accepted=_boolean(
                    value["generic_root_capacity_accepted"],
                    "generic root capacity accepted",
                ),
                decision_digest=require_string(value, "decision_digest"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend installation storage state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerBackendInstallationGate:
    name: str
    state: DeployManagerBackendInstallationGateState
    blockers: tuple[str, ...]
    evidence_digest: str
    gate_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_GATE_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_GATE_SCHEMA_VERSION
            or _BLOCKER.fullmatch(self.name) is None
            or self.blockers != tuple(sorted(set(self.blockers)))
            or any(_BLOCKER.fullmatch(item) is None for item in self.blockers)
            or (
                self.state is DeployManagerBackendInstallationGateState.PASSED
                and self.blockers
            )
            or (
                self.state
                in {
                    DeployManagerBackendInstallationGateState.UNKNOWN,
                    DeployManagerBackendInstallationGateState.BLOCKED,
                }
                and not self.blockers
            )
            or self.gate_digest != _record_digest(self, "gate_digest")
        ):
            raise StatePersistenceError("Manager backend installation gate conflicts")
        validate_digest(self.evidence_digest, "Manager backend gate evidence digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendInstallationGate:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend installation gate",
        )
        try:
            return cls(
                name=require_string(value, "name"),
                state=DeployManagerBackendInstallationGateState(
                    require_string(value, "state")
                ),
                blockers=_string_tuple(value["blockers"], "gate blockers"),
                evidence_digest=require_string(value, "evidence_digest"),
                gate_digest=require_string(value, "gate_digest"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend installation gate state is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerBackendInstallationContext:
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
    backend_context_artifact_digest: str
    backend_context_record_digest: str
    backend_plan_artifact_digest: str
    backend_plan_digest: str
    preflight_execution_artifact_digest: str
    preflight_execution_binding_digest: str
    preflight_evidence_artifact_digest: str
    preflight_evidence_digest: str
    preflight_reconciliation_artifact_digest: str
    preflight_reconciliation_record_digest: str
    metadata_generation: int
    metadata_artifact_digest: str
    desired_spec_digest: str
    provider: str
    observation_generation: int
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
    catalog_digest: str
    ansible_source_digest: str
    manager_target_id: str
    manager_target_digest: str
    operating_system: str
    operating_system_version: str
    architecture: str
    base_os_evidence_digest: str
    manager_server_evidence_digest: str
    manager_server_provenance_digest: str
    manager_service_state: str
    local_scylla_package_state: str
    local_scylla_service_state: str
    backend_policy_digest: str
    package_reference: DeployManagerBackendInstallationPackageReference
    storage_decision: DeployManagerBackendInstallationStorageDecision
    gates: tuple[DeployManagerBackendInstallationGate, ...]
    gate_count: int
    passed_gate_count: int
    unknown_gate_count: int
    blocked_gate_count: int
    gate_set_digest: str
    blockers: tuple[str, ...]
    blocker_count: int
    blocker_digest: str
    host_planning_state: DeployManagerBackendPreflightInstallationPlanningState
    plan_status: DeployManagerBackendInstallationPlanStatus
    original_mapping_count: int
    original_mapping_digest: str
    original_mapping_unchanged: bool
    authorization_state: str
    execution_state: str
    public_workflow_state: str
    next_implementation_contract: str
    record_digest: str
    backend_policy_schema_version: str = (
        MANAGER_BACKEND_LOCAL_ONE_NODE_POLICY_SCHEMA_VERSION
    )
    preflight_execution_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION
    )
    preflight_evidence_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
    )
    preflight_reconciliation_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        counts = {
            state: sum(gate.state is state for gate in self.gates)
            for state in DeployManagerBackendInstallationGateState
        }
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_SCHEMA_VERSION
            or self.backend_policy_schema_version
            != MANAGER_BACKEND_LOCAL_ONE_NODE_POLICY_SCHEMA_VERSION
            or self.preflight_execution_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EXECUTION_SCHEMA_VERSION
            or self.preflight_evidence_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_EVIDENCE_SCHEMA_VERSION
            or self.preflight_reconciliation_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_PREFLIGHT_RECONCILIATION_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.provider != "oci"
            or _LOGICAL_ID.fullmatch(self.manager_target_id) is None
            or self.manager_target_digest != _digest_object([self.manager_target_id])
            or self.operating_system != "Ubuntu"
            or self.operating_system_version != "24.04"
            or self.architecture not in {"amd64", "aarch64"}
            or self.manager_service_state != "masked-inactive"
            or self.original_mapping_count != _ORIGINAL_MAPPING_COUNT
            or not self.original_mapping_unchanged
            or self.gate_count != len(self.gates)
            or self.passed_gate_count
            != counts[DeployManagerBackendInstallationGateState.PASSED]
            or self.unknown_gate_count
            != counts[DeployManagerBackendInstallationGateState.UNKNOWN]
            or self.blocked_gate_count
            != counts[DeployManagerBackendInstallationGateState.BLOCKED]
            or self.gate_set_digest
            != _digest_object([gate.to_object() for gate in self.gates])
            or self.blockers
            != tuple(
                sorted({blocker for gate in self.gates for blocker in gate.blockers})
            )
            or self.blocker_count != len(self.blockers)
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.unknown_gate_count < 1
            or self.blocked_gate_count < 1
            or self.plan_status
            is not DeployManagerBackendInstallationPlanStatus.BLOCKED
            or self.authorization_state != _UNAVAILABLE
            or self.execution_state != _NOT_PERFORMED
            or self.public_workflow_state != _UNAVAILABLE
            or self.next_implementation_contract
            not in {
                _LEGACY_NEXT_IMPLEMENTATION_CONTRACT,
                _AUTHORIZATION_OWNER_IMPLEMENTATION_CONTRACT,
                _NEXT_IMPLEMENTATION_CONTRACT,
            }
            or self.record_digest != _record_digest(self, "record_digest")
        ):
            raise StatePersistenceError(
                "Manager backend installation context conflicts"
            )
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for count in (
            self.journal_generation,
            self.metadata_generation,
            self.observation_generation,
            self.inventory_generation,
            self.trust_generation,
            self.gate_count,
            self.passed_gate_count,
            self.unknown_gate_count,
            self.blocked_gate_count,
            self.blocker_count,
        ):
            _positive_integer(count, "Manager backend installation count")
        for value in _digest_fields(self):
            validate_digest(value, "Manager backend installation context digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendInstallationContext:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend installation context",
        )
        integers = {
            "generation",
            "journal_generation",
            "metadata_generation",
            "observation_generation",
            "inventory_generation",
            "trust_generation",
            "gate_count",
            "passed_gate_count",
            "unknown_gate_count",
            "blocked_gate_count",
            "blocker_count",
            "original_mapping_count",
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
                elif name == "host_planning_state":
                    parsed[name] = (
                        DeployManagerBackendPreflightInstallationPlanningState(
                            require_string(value, name)
                        )
                    )
                elif name == "plan_status":
                    parsed[name] = DeployManagerBackendInstallationPlanStatus(
                        require_string(value, name)
                    )
                elif name == "package_reference":
                    parsed[name] = (
                        DeployManagerBackendInstallationPackageReference.from_object(
                            _mapping(item, name)
                        )
                    )
                elif name == "storage_decision":
                    parsed[name] = (
                        DeployManagerBackendInstallationStorageDecision.from_object(
                            _mapping(item, name)
                        )
                    )
                elif name == "gates":
                    parsed[name] = tuple(
                        DeployManagerBackendInstallationGate.from_object(
                            _mapping(gate, "installation gate")
                        )
                        for gate in _array(item, name)
                    )
                elif name == "blockers":
                    parsed[name] = _string_tuple(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend installation context enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendInstallationContext:
    record: DeployManagerBackendInstallationContext
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class DeployManagerBackendInstallationPlanStep:
    sequence: int
    boundary: str
    classification: OperationClassification
    target_ids: tuple[str, ...]
    target_count: int
    target_set_digest: str
    package_reference_digest: str
    storage_decision_digest: str
    prerequisite_gate_set_digest: str
    source_state: DeployManagerBackendInstallationSourceState
    source_digest: str | None
    source_contract_state: str
    authorization_requirement: str
    performance_state: str
    status: DeployManagerBackendInstallationPlanStatus
    blockers: tuple[str, ...]
    blocker_digest: str
    step_digest: str
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_STEP_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        index = self.sequence - 1
        current_package_step = (
            self.sequence == 1
            and self.source_state
            is DeployManagerBackendInstallationSourceState.AVAILABLE
        )
        expected_authorization = (
            "ordinary-approval-required"
            if current_package_step
            and self.status
            is DeployManagerBackendInstallationPlanStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            else "not-required-read-only"
            if self.classification is OperationClassification.READ_ONLY
            else "blocked-before-authorization"
        )
        source_valid = (
            self.source_digest is not None
            and self.source_contract_state == _PACKAGE_SOURCE_CONTRACT
            and current_package_step
        ) or (
            self.source_state is DeployManagerBackendInstallationSourceState.UNAVAILABLE
            and self.source_digest is None
            and self.source_contract_state == "manager-role-source-unavailable"
        )
        status_valid = (
            current_package_step
            and self.status
            in {
                DeployManagerBackendInstallationPlanStatus.BLOCKED,
                DeployManagerBackendInstallationPlanStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED,
            }
            and _BOUNDARY_SOURCE_BLOCKERS[index] not in self.blockers
            and (
                self.status
                is not DeployManagerBackendInstallationPlanStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
                or self.blockers == _PACKAGE_AUTHORIZATION_BLOCKERS
            )
        ) or (
            not current_package_step
            and self.status is DeployManagerBackendInstallationPlanStatus.BLOCKED
            and _BOUNDARY_SOURCE_BLOCKERS[index] in self.blockers
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_STEP_SCHEMA_VERSION
            or not 0 <= index < len(_BOUNDARIES)
            or self.boundary != _BOUNDARIES[index]
            or self.classification is not _BOUNDARY_CLASSIFICATIONS[index]
            or len(self.target_ids) != 1
            or self.target_ids != tuple(sorted(set(self.target_ids)))
            or self.target_count != 1
            or self.target_set_digest != _digest_object(list(self.target_ids))
            or not source_valid
            or self.authorization_requirement != expected_authorization
            or self.performance_state != _NOT_PERFORMED
            or not status_valid
            or self.blockers != tuple(sorted(set(self.blockers)))
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.step_digest != _record_digest(self, "step_digest")
        ):
            raise StatePersistenceError(
                "Manager backend installation plan step conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(value, "Manager backend installation step digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendInstallationPlanStep:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend installation plan step",
        )
        source_digest = value["source_digest"]
        if source_digest is not None and not isinstance(source_digest, str):
            raise StatePersistenceError(
                "Manager backend installation source digest is invalid"
            )
        try:
            return cls(
                sequence=_integer(value["sequence"], "sequence"),
                boundary=require_string(value, "boundary"),
                classification=OperationClassification(
                    require_string(value, "classification")
                ),
                target_ids=_string_tuple(value["target_ids"], "target ids"),
                target_count=_integer(value["target_count"], "target count"),
                target_set_digest=require_string(value, "target_set_digest"),
                package_reference_digest=require_string(
                    value, "package_reference_digest"
                ),
                storage_decision_digest=require_string(
                    value, "storage_decision_digest"
                ),
                prerequisite_gate_set_digest=require_string(
                    value, "prerequisite_gate_set_digest"
                ),
                source_state=DeployManagerBackendInstallationSourceState(
                    require_string(value, "source_state")
                ),
                source_digest=source_digest,
                source_contract_state=require_string(value, "source_contract_state"),
                authorization_requirement=require_string(
                    value, "authorization_requirement"
                ),
                performance_state=require_string(value, "performance_state"),
                status=DeployManagerBackendInstallationPlanStatus(
                    require_string(value, "status")
                ),
                blockers=_string_tuple(value["blockers"], "blockers"),
                blocker_digest=require_string(value, "blocker_digest"),
                step_digest=require_string(value, "step_digest"),
                schema_version=require_string(value, "schema_version"),
            )
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend installation plan step enum is invalid"
            ) from error


@dataclass(frozen=True, slots=True)
class DeployManagerBackendInstallationPlan:
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
    context_artifact_digest: str
    context_record_digest: str
    preflight_reconciliation_artifact_digest: str
    preflight_reconciliation_record_digest: str
    manager_target_id: str
    manager_target_digest: str
    host_planning_state: DeployManagerBackendPreflightInstallationPlanningState
    storage_state: DeployManagerBackendInstallationStorageState
    dedicated_volume_identified: bool
    steps: tuple[DeployManagerBackendInstallationPlanStep, ...]
    step_count: int
    read_only_step_count: int
    mutating_step_count: int
    sensitive_step_count: int
    destructive_step_count: int
    source_available_count: int
    source_unavailable_count: int
    not_performed_count: int
    blocked_count: int
    blockers: tuple[str, ...]
    blocker_count: int
    blocker_digest: str
    status: DeployManagerBackendInstallationPlanStatus
    original_mapping_count: int
    original_mapping_digest: str
    original_mapping_unchanged: bool
    authorization_state: str
    execution_state: str
    public_workflow_state: str
    next_implementation_contract: str
    plan_digest: str
    context_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_SCHEMA_VERSION
    )
    journal_schema_version: str = JOURNAL_SCHEMA_VERSION
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        classifications = {
            item: sum(step.classification is item for step in self.steps)
            for item in OperationClassification
        }
        source_available_count = sum(
            step.source_state is DeployManagerBackendInstallationSourceState.AVAILABLE
            for step in self.steps
        )
        source_unavailable_count = sum(
            step.source_state is DeployManagerBackendInstallationSourceState.UNAVAILABLE
            for step in self.steps
        )
        blocked_count = sum(
            step.status is DeployManagerBackendInstallationPlanStatus.BLOCKED
            for step in self.steps
        )
        package_ready = (
            self.steps[0].status
            is DeployManagerBackendInstallationPlanStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
        )
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_SCHEMA_VERSION
            or self.context_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_SCHEMA_VERSION
            or self.journal_schema_version != JOURNAL_SCHEMA_VERSION
            or self.generation != 1
            or self.operation != _OPERATION
            or self.stage != _STAGE
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
            or self.manager_target_digest != _digest_object([self.manager_target_id])
            or self.dedicated_volume_identified
            is not (
                self.storage_state
                is DeployManagerBackendInstallationStorageState.IDENTIFIED
            )
            or tuple(step.sequence for step in self.steps)
            != tuple(range(1, len(_BOUNDARIES) + 1))
            or tuple(step.boundary for step in self.steps) != _BOUNDARIES
            or any(step.target_ids != (self.manager_target_id,) for step in self.steps)
            or self.step_count != len(_BOUNDARIES)
            or self.read_only_step_count
            != classifications[OperationClassification.READ_ONLY]
            or self.mutating_step_count
            != classifications[OperationClassification.MUTATING]
            or self.sensitive_step_count
            != classifications[OperationClassification.SENSITIVE]
            or self.destructive_step_count
            != classifications[OperationClassification.DESTRUCTIVE]
            or self.source_available_count != source_available_count
            or self.source_unavailable_count != source_unavailable_count
            or self.not_performed_count != self.step_count
            or self.blocked_count != blocked_count
            or self.blockers
            != tuple(
                sorted({blocker for step in self.steps for blocker in step.blockers})
            )
            or self.blocker_count != len(self.blockers)
            or self.blocker_digest != _digest_object(list(self.blockers))
            or self.status is not DeployManagerBackendInstallationPlanStatus.BLOCKED
            or self.original_mapping_count != _ORIGINAL_MAPPING_COUNT
            or not self.original_mapping_unchanged
            or self.authorization_state
            != (_AUTHORIZATION_REQUIRED if package_ready else _UNAVAILABLE)
            or self.execution_state != _NOT_PERFORMED
            or self.public_workflow_state != _UNAVAILABLE
            or self.next_implementation_contract
            not in {
                _LEGACY_NEXT_IMPLEMENTATION_CONTRACT,
                _AUTHORIZATION_OWNER_IMPLEMENTATION_CONTRACT,
                _NEXT_IMPLEMENTATION_CONTRACT,
            }
            or self.plan_digest != _record_digest(self, "plan_digest")
        ):
            raise StatePersistenceError("Manager backend installation plan conflicts")
        validate_cluster_name(self.cluster_name)
        parse_timestamp(self.created_at)
        for count in (
            self.journal_generation,
            self.step_count,
            self.read_only_step_count,
            self.mutating_step_count,
            self.sensitive_step_count,
            self.destructive_step_count,
            self.source_unavailable_count,
            self.not_performed_count,
            self.blocked_count,
            self.blocker_count,
        ):
            _positive_integer(count, "Manager backend installation plan count")
        for value in _digest_fields(self):
            validate_digest(value, "Manager backend installation plan digest")

    def to_object(self) -> dict[str, object]:
        return _dataclass_object(self)

    @classmethod
    def from_object(
        cls, value: Mapping[str, object]
    ) -> DeployManagerBackendInstallationPlan:
        require_exact_keys(
            value,
            set(cls.__dataclass_fields__),
            "Manager backend installation plan",
        )
        integers = {
            "generation",
            "journal_generation",
            "step_count",
            "read_only_step_count",
            "mutating_step_count",
            "sensitive_step_count",
            "destructive_step_count",
            "source_available_count",
            "source_unavailable_count",
            "not_performed_count",
            "blocked_count",
            "blocker_count",
            "original_mapping_count",
        }
        parsed: dict[str, object] = {}
        try:
            for name in cls.__dataclass_fields__:
                item = value[name]
                if name in integers:
                    parsed[name] = _integer(item, name)
                elif name in {
                    "dedicated_volume_identified",
                    "original_mapping_unchanged",
                }:
                    parsed[name] = _boolean(item, name)
                elif name in {"cluster_uuid", "operation_id"}:
                    parsed[name] = parse_uuid(require_string(value, name), name)
                elif name == "journal_status":
                    parsed[name] = JournalStatus(require_string(value, name))
                elif name == "journal_phase":
                    parsed[name] = OperationPhase(require_string(value, name))
                elif name == "host_planning_state":
                    parsed[name] = (
                        DeployManagerBackendPreflightInstallationPlanningState(
                            require_string(value, name)
                        )
                    )
                elif name == "storage_state":
                    parsed[name] = DeployManagerBackendInstallationStorageState(
                        require_string(value, name)
                    )
                elif name == "status":
                    parsed[name] = DeployManagerBackendInstallationPlanStatus(
                        require_string(value, name)
                    )
                elif name == "steps":
                    parsed[name] = tuple(
                        DeployManagerBackendInstallationPlanStep.from_object(
                            _mapping(step, "installation plan step")
                        )
                        for step in _array(item, name)
                    )
                elif name == "blockers":
                    parsed[name] = _string_tuple(item, name)
                else:
                    parsed[name] = require_string(value, name)
        except ValueError as error:
            raise StatePersistenceError(
                "Manager backend installation plan enum is invalid"
            ) from error
        return cls(**parsed)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StoredDeployManagerBackendInstallationPlan:
    record: DeployManagerBackendInstallationPlan
    artifact_digest: str


class DeployManagerBackendInstallationContextStore:
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
        self._path = deploy_manager_backend_installation_context_path(
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
    ) -> StoredDeployManagerBackendInstallationContext:
        value, digest = self._file.read()
        record = DeployManagerBackendInstallationContext.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "Manager backend installation context identity conflicts"
            )
        return StoredDeployManagerBackendInstallationContext(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendInstallationContext:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self, record: DeployManagerBackendInstallationContext, *, lock: ClusterLock
    ) -> tuple[
        StoredDeployManagerBackendInstallationContext,
        DeployManagerBackendInstallationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Manager backend installation context operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "Manager backend installation context is immutable; "
                    "use a new operation"
                )
            return current, DeployManagerBackendInstallationArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerBackendInstallationContext(record, digest),
            DeployManagerBackendInstallationArtifactState.CREATED,
        )


class DeployManagerBackendInstallationPlanStore:
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
        self._path = deploy_manager_backend_installation_plan_path(paths, operation_id)
        self._file = AtomicJsonFile(
            self._path, replace=replace_file, token_factory=token_factory
        )

    @property
    def path(self) -> Path:
        return self._path

    def read(
        self, *, expected_cluster_uuid: uuid.UUID, expected_cluster_name: str
    ) -> StoredDeployManagerBackendInstallationPlan:
        value, digest = self._file.read()
        record = DeployManagerBackendInstallationPlan.from_object(value)
        if (
            record.operation_id != self._operation_id
            or record.cluster_uuid != expected_cluster_uuid
            or record.cluster_name != expected_cluster_name
        ):
            raise StatePersistenceError(
                "Manager backend installation plan identity conflicts"
            )
        return StoredDeployManagerBackendInstallationPlan(record, digest)

    def read_locked(
        self,
        lock: ClusterLock,
        *,
        expected_cluster_uuid: uuid.UUID,
        expected_cluster_name: str,
    ) -> StoredDeployManagerBackendInstallationPlan:
        _assert_operation_lock(lock, self._paths)
        return self.read(
            expected_cluster_uuid=expected_cluster_uuid,
            expected_cluster_name=expected_cluster_name,
        )

    def write_locked(
        self, record: DeployManagerBackendInstallationPlan, *, lock: ClusterLock
    ) -> tuple[
        StoredDeployManagerBackendInstallationPlan,
        DeployManagerBackendInstallationArtifactState,
    ]:
        _assert_operation_lock(lock, self._paths)
        validate_state_directory(self._paths.operations)
        validate_state_file(self._path, allow_missing=True)
        if record.operation_id != self._operation_id:
            raise StatePersistenceError(
                "Manager backend installation plan operation conflicts"
            )
        if self._path.exists():
            current = self.read_locked(
                lock,
                expected_cluster_uuid=record.cluster_uuid,
                expected_cluster_name=record.cluster_name,
            )
            if current.record != record:
                raise StateConflictError(
                    "Manager backend installation plan is immutable; "
                    "use a new operation"
                )
            return current, DeployManagerBackendInstallationArtifactState.REUSED
        digest = self._file.write(record.to_object(), expected_digest=None)
        return (
            StoredDeployManagerBackendInstallationPlan(record, digest),
            DeployManagerBackendInstallationArtifactState.CREATED,
        )


@dataclass(frozen=True, slots=True)
class DeployManagerBackendInstallationPlanReport:
    operation_id: uuid.UUID
    context_state: DeployManagerBackendInstallationArtifactState
    plan_state: DeployManagerBackendInstallationArtifactState
    context_artifact_digest: str
    context_record_digest: str
    plan_artifact_digest: str
    plan_digest: str
    manager_target_id: str
    manager_target_digest: str
    host_planning_state: DeployManagerBackendPreflightInstallationPlanningState
    storage_state: DeployManagerBackendInstallationStorageState
    dedicated_volume_identified: bool
    package_authentication_state: str
    package_target_contract_state: str
    step_count: int
    source_available_count: int
    source_unavailable_count: int
    blocked_count: int
    blocker_names: tuple[str, ...]
    blocker_count: int
    blocker_digest: str
    status: DeployManagerBackendInstallationPlanStatus
    original_mapping_unchanged: bool
    authorization_state: str
    execution_state: str
    public_workflow_state: str
    next_implementation_contract: str
    journal_status: JournalStatus
    journal_phase: OperationPhase
    context_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_SCHEMA_VERSION
    )
    plan_schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_SCHEMA_VERSION
    )
    schema_version: str = (
        ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_REPORT_SCHEMA_VERSION
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_REPORT_SCHEMA_VERSION
            or self.context_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_SCHEMA_VERSION
            or self.plan_schema_version
            != ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_SCHEMA_VERSION
            or self.dedicated_volume_identified
            is not (
                self.storage_state
                is DeployManagerBackendInstallationStorageState.IDENTIFIED
            )
            or self.package_authentication_state != "authenticated"
            or self.package_target_contract_state
            not in {
                "manager-role-contract-unavailable",
                "manager-backend-local-install-source-available",
            }
            or self.step_count != len(_BOUNDARIES)
            or self.source_available_count not in {0, 1}
            or self.source_available_count + self.source_unavailable_count
            != self.step_count
            or self.blocked_count not in {self.step_count, self.step_count - 1}
            or self.blocker_names != tuple(sorted(set(self.blocker_names)))
            or self.blocker_count != len(self.blocker_names)
            or self.blocker_digest != _digest_object(list(self.blocker_names))
            or self.status is not DeployManagerBackendInstallationPlanStatus.BLOCKED
            or not self.original_mapping_unchanged
            or self.authorization_state not in {_UNAVAILABLE, _AUTHORIZATION_REQUIRED}
            or self.execution_state != _NOT_PERFORMED
            or self.public_workflow_state != _UNAVAILABLE
            or self.next_implementation_contract
            not in {
                _LEGACY_NEXT_IMPLEMENTATION_CONTRACT,
                _AUTHORIZATION_OWNER_IMPLEMENTATION_CONTRACT,
                _NEXT_IMPLEMENTATION_CONTRACT,
            }
            or self.journal_status is not JournalStatus.IN_PROGRESS
            or self.journal_phase is not OperationPhase.VERIFY
        ):
            raise StatePersistenceError(
                "Manager backend installation plan report conflicts"
            )
        for value in _digest_fields(self):
            validate_digest(value, "Manager backend installation report digest")

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
            "blockers": {
                "count": self.blocker_count,
                "digest": self.blocker_digest,
                "names": list(self.blocker_names),
            },
            "journal": {
                "phase": self.journal_phase.value,
                "status": self.journal_status.value,
                "updated": False,
            },
            "next_implementation_contract": self.next_implementation_contract,
            "operation_id": str(self.operation_id),
            "original_mapping_unchanged": self.original_mapping_unchanged,
            "package_reference": {
                "authentication_state": self.package_authentication_state,
                "target_contract_state": self.package_target_contract_state,
            },
            "schema_version": self.schema_version,
            "scope": {
                "manager_target_digest": self.manager_target_digest,
                "manager_target_id": self.manager_target_id,
            },
            "states": {
                "authorization": self.authorization_state,
                "execution": self.execution_state,
                "host_planning": self.host_planning_state.value,
                "plan": self.status.value,
                "public_workflow": self.public_workflow_state,
            },
            "steps": {
                "blocked_count": self.blocked_count,
                "count": self.step_count,
                "source_available_count": self.source_available_count,
                "source_unavailable_count": self.source_unavailable_count,
            },
            "storage": {
                "dedicated_volume_identified": self.dedicated_volume_identified,
                "root_fallback": "forbidden",
                "state": self.storage_state.value,
            },
        }


@dataclass(frozen=True, slots=True)
class _InstallationPlanningContext:
    preflight_reconciliation: StoredDeployManagerBackendPreflightReconciliation
    preflight_evidence: DeployManagerBackendPreflightEvidence
    execution_context: _ExecutionContext
    package_reference: DeployManagerBackendInstallationPackageReference
    storage_decision: DeployManagerBackendInstallationStorageDecision
    gates: tuple[DeployManagerBackendInstallationGate, ...]


def plan_deploy_manager_backend_local_installation(
    *,
    state_root: Path,
    cluster_name: str,
    operation_id: uuid.UUID,
    lock: ClusterLock,
) -> DeployManagerBackendInstallationPlanReport:
    """Persist or exactly reuse the blocked local-backend installation plan."""

    paths = StatePaths.derive(state_root, validate_cluster_name(cluster_name))
    operation_id = _require_operation_id(operation_id)
    _assert_operation_lock(lock, paths)
    validate_state_directory(paths.operations)
    _refuse_ambiguous_artifacts(paths, operation_id)

    context_store = DeployManagerBackendInstallationContextStore(paths, operation_id)
    plan_store = DeployManagerBackendInstallationPlanStore(paths, operation_id)
    for path in (context_store.path, plan_store.path):
        validate_state_file(path, allow_missing=True)
    if plan_store.path.exists() and not context_store.path.exists():
        raise StateConflictError(
            "Manager backend installation plan exists without its context"
        )

    loaded = _load_installation_planning_context(paths, operation_id, lock=lock)
    execution = loaded.execution_context
    metadata = execution.metadata
    existing_context = (
        context_store.read_locked(
            lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
        )
        if context_store.path.exists()
        else None
    )
    existing_plan = (
        plan_store.read_locked(
            lock,
            expected_cluster_uuid=metadata.cluster_uuid,
            expected_cluster_name=metadata.cluster_name,
        )
        if plan_store.path.exists()
        else None
    )
    created_at = (
        existing_context.record.created_at
        if existing_context is not None
        else _timestamp()
    )
    context_record = _build_context_record(loaded, created_at=created_at)
    expected_context_digest = digest_bytes(serialize_json(context_record.to_object()))
    context_for_plan = StoredDeployManagerBackendInstallationContext(
        context_record, expected_context_digest
    )
    steps = _build_plan_steps(context_record)
    plan_record = _build_plan_record(
        context_for_plan,
        steps=steps,
        created_at=(
            existing_plan.record.created_at if existing_plan is not None else created_at
        ),
    )

    stored_context, context_state = context_store.write_locked(
        context_record, lock=lock
    )
    if stored_context.artifact_digest != expected_context_digest:
        raise StateConflictError("Manager backend installation context bytes changed")
    stored_plan, plan_state = plan_store.write_locked(plan_record, lock=lock)
    return _build_report(
        stored_context,
        stored_plan,
        context_state=context_state,
        plan_state=plan_state,
    )


def deploy_manager_backend_installation_context_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "Manager backend installation context path is not canonical"
        )
    return path


def deploy_manager_backend_installation_plan_path(
    paths: StatePaths, operation_id: uuid.UUID
) -> Path:
    _require_canonical_paths(paths)
    operation_id = _require_operation_id(operation_id)
    path = paths.operations / (
        f"{operation_id}{DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_FILENAME_SUFFIX}"
    )
    if path.parent != paths.operations:
        raise StatePersistenceError(
            "Manager backend installation plan path is not canonical"
        )
    return path


def deploy_manager_backend_installation_context_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(
        name, DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_FILENAME_SUFFIX
    )


def deploy_manager_backend_installation_plan_id_from_filename(
    name: str,
) -> uuid.UUID | None:
    return _id_from_filename(
        name, DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_FILENAME_SUFFIX
    )


def _load_installation_planning_context(
    paths: StatePaths, operation_id: uuid.UUID, *, lock: ClusterLock
) -> _InstallationPlanningContext:
    preflight = _load_reconciliation_context(paths, operation_id, lock=lock)
    binding = preflight.execution.record.binding
    execution_context = _load_execution_context(
        paths,
        operation_id,
        lock=lock,
        toolchain_version=binding.toolchain_version,
        executable_identity_digest=binding.executable_identity_digest,
        toolchain_evidence_digest=binding.toolchain_evidence_digest,
    )
    _validate_execution_prefix(
        execution_context, preflight.execution, preflight.evidence
    )
    if (
        preflight.execution.record.state
        is not DeployManagerBackendPreflightExecutionState.SUCCEEDED
        or preflight.execution.record.manual_recovery_required
        or preflight.execution.record.automatic_retry_allowed
        or preflight.execution.record.generation != 2
    ):
        raise StateConflictError(
            "Manager backend installation planning requires terminal preflight success"
        )

    reconciliation_store = DeployManagerBackendPreflightReconciliationStore(
        paths, operation_id
    )
    validate_state_file(reconciliation_store.path, allow_missing=True)
    if not reconciliation_store.path.exists():
        raise StateConflictError(
            "Manager backend installation planning requires exact preflight "
            "reconciliation"
        )
    reconciliation = reconciliation_store.read_locked(
        lock,
        expected_cluster_uuid=binding.cluster_uuid,
        expected_cluster_name=binding.cluster_name,
    )
    expected_reconciliation = _build_preflight_reconciliation_record(
        preflight, created_at=reconciliation.record.created_at
    )
    if (
        reconciliation.record != expected_reconciliation
        or reconciliation.record.execution_artifact_digest
        != preflight.execution.artifact_digest
        or reconciliation.record.evidence_artifact_digest
        != preflight.evidence.artifact_digest
        or reconciliation.record.target_stable_id != binding.target_stable_id
        or reconciliation.record.journal_digest != binding.journal_digest
    ):
        raise StateConflictError(
            "Manager backend installation preflight reconciliation drifted"
        )

    backend_context = execution_context.backend_context.record
    backend_plan = execution_context.backend_plan.record
    if (
        backend_context.intent.backend_mode_value
        is not DeployManagerBackendMode.LOCAL_ONE_NODE
        or backend_context.intent.backend_policy.scylla_release
        != MANAGER_BACKEND_SCYLLA_RELEASE
        or backend_context.intent.backend_policy.contact_scope != "loopback-only"
        or backend_context.intent.backend_policy.managed_data_cluster_backend
        != "forbidden"
        or backend_context.intent.backend_policy.cql_network_ingress != "forbidden"
        or backend_context.manager_target_id != binding.target_stable_id
        or backend_plan.context_artifact_digest
        != execution_context.backend_context.artifact_digest
        or backend_context.original_mapping_count != _ORIGINAL_MAPPING_COUNT
        or not backend_context.original_mapping_unchanged
    ):
        raise StateConflictError(
            "Manager backend installation local-one-node policy or mapping conflicts"
        )

    package_reference = _build_package_reference()
    storage_decision = _derive_storage_decision(
        execution_context.metadata.desired_spec,
        execution_context.observation,
        binding.target_stable_id,
    )
    gates = _build_gates(
        reconciliation,
        preflight.evidence.record,
        package_reference,
        storage_decision,
        execution_context.scope.architecture,
    )
    return _InstallationPlanningContext(
        reconciliation,
        preflight.evidence.record,
        execution_context,
        package_reference,
        storage_decision,
        gates,
    )


def _build_package_reference() -> DeployManagerBackendInstallationPackageReference:
    validate_scylla_signing_key(load_scylla_signing_key())
    values: dict[str, object] = {
        "release_line": SCYLLA_RELEASE_LINE,
        "package_version": SCYLLA_PACKAGE_VERSION,
        "edition": SCYLLA_EDITION,
        "channel": SCYLLA_CHANNEL,
        "package_count": len(SCYLLA_PACKAGES),
        "package_set_digest": _digest_object(list(SCYLLA_PACKAGES)),
        "package_set_policy": "exact-manager-local-backend-package-set-approved",
        "repository_definition_digest": SCYLLA_REPOSITORY_DEFINITION_DIGEST,
        "signing_key_artifact_digest": SCYLLA_SIGNING_KEY_DIGEST,
        "signing_key_identity_digest": _signing_key_identity_digest(),
        "authentication_state": "authenticated",
        "target_contract_state": "manager-backend-local-install-source-available",
        "reference_digest": "",
    }
    values["reference_digest"] = _record_digest_from_values(values, "reference_digest")
    return DeployManagerBackendInstallationPackageReference(**values)  # type: ignore[arg-type]


def _derive_storage_decision(
    desired: ClusterSpec,
    observation: StoredObservedState,
    target: str,
) -> DeployManagerBackendInstallationStorageDecision:
    """Bind one exact Manager block volume or explicitly refuse root fallback."""

    policies = tuple(
        policy for policy in desired.storage if policy.role is HostRole.MANAGER
    )
    hosts = tuple(
        host
        for host in observation.record.manifest.hosts
        if host.logical_id == target and host.role is HostRole.MANAGER
    )
    policy = policies[0] if len(policies) == 1 else None
    host = hosts[0] if len(hosts) == 1 else None
    storage = host.storage if host is not None else None
    device = (
        storage.devices[0]
        if storage is not None and len(storage.devices) == 1
        else None
    )
    identified = bool(
        policy is not None
        and policy.requested_backend is StorageBackend.BLOCK_VOLUME
        and policy.layout is StorageLayout.SINGLE
        and policy.block_volume is not None
        and policy.block_volume.count == 1
        and storage is not None
        and storage.requested_backend is StorageBackend.BLOCK_VOLUME
        and storage.selected_backend is StorageBackend.BLOCK_VOLUME
        and storage.selection_status
        in {
            StorageSelectionStatus.PROVISIONAL,
            StorageSelectionStatus.FINAL,
        }
        and storage.expected_device_count == 1
        and storage.layout == StorageLayout.SINGLE.value
        and storage.role_allocations == ("data",)
        and device is not None
        and device.kind is StorageDeviceKind.BLOCK_VOLUME
        and device.provider_volume_id is not None
        and device.provider_attachment_id is not None
        and not device.ephemeral
        and device.size_gib == policy.block_volume.size_gib
        and storage.raw_total_gib == policy.block_volume.size_gib
    )
    desired_digest = _digest_object(
        policy.to_object()
        if policy is not None
        else {"role": HostRole.MANAGER.value, "state": "absent"}
    )
    observed_digest = _digest_object(
        _storage_manifest_projection(storage)
        if storage is not None
        else {"role": HostRole.MANAGER.value, "state": "absent"}
    )
    identity_digest = (
        _digest_object(
            {
                "attachment": device.provider_attachment_id,
                "by_id": device.expected_by_id,
                "serial": device.expected_serial,
                "storage_generation": storage.storage_generation,
                "volume": device.provider_volume_id,
            }
        )
        if identified and device is not None and storage is not None
        else None
    )
    binding_digest = _digest_object(
        {
            "desired_policy": desired_digest,
            "manifest": observed_digest,
            "target": target,
            "volume_identity": identity_digest,
        }
    )
    values: dict[str, object] = {
        "state": (
            DeployManagerBackendInstallationStorageState.IDENTIFIED
            if identified
            else DeployManagerBackendInstallationStorageState.UNMODELED
        ),
        "dedicated_volume_identified": identified,
        "desired_backend": (
            policy.requested_backend.value if policy is not None else "unmodeled"
        ),
        "observed_backend": (
            storage.selected_backend.value if storage is not None else "unmodeled"
        ),
        "selection_state": (
            storage.selection_status.value if storage is not None else "unmodeled"
        ),
        "expected_device_count": 1 if identified else 0,
        "storage_generation": (
            storage.storage_generation if identified and storage is not None else 0
        ),
        "desired_policy_digest": desired_digest,
        "observed_manifest_digest": observed_digest,
        "volume_identity_digest": identity_digest,
        "provider_storage_binding_digest": binding_digest,
        "root_fallback_policy": "forbidden",
        "generic_root_capacity_accepted": False,
        "decision_digest": "",
    }
    values["decision_digest"] = _record_digest_from_values(values, "decision_digest")
    return DeployManagerBackendInstallationStorageDecision(**values)  # type: ignore[arg-type]


def _build_gates(
    reconciliation: StoredDeployManagerBackendPreflightReconciliation,
    evidence: DeployManagerBackendPreflightEvidence,
    package: DeployManagerBackendInstallationPackageReference,
    storage: DeployManagerBackendInstallationStorageDecision,
    architecture: str,
) -> tuple[DeployManagerBackendInstallationGate, ...]:
    record = reconciliation.record
    host_ready = (
        record.installation_planning_state
        is DeployManagerBackendPreflightInstallationPlanningState.EVIDENCE_READY
    )
    local_absent = (
        evidence.local_scylla_package_status
        is ManagerBackendPackageStatus.NOT_INSTALLED
        and evidence.local_scylla_service_status is ManagerBackendServiceStatus.ABSENT
    )
    host_blockers = record.host_observed_blockers or (
        ("manager-backend-host-evidence-blocked",) if not host_ready else ()
    )
    local_blockers = (
        ()
        if local_absent
        else tuple(
            sorted(
                set(record.host_observed_blockers)
                or {"manager-backend-local-scylla-precondition-failed"}
            )
        )
    )
    storage_blockers = (
        ()
        if storage.dedicated_volume_identified
        else ("dedicated-backend-storage-unmodeled",)
    )
    specs: tuple[
        tuple[str, DeployManagerBackendInstallationGateState, tuple[str, ...], str],
        ...,
    ] = (
        (
            "canonical-preflight-chain",
            DeployManagerBackendInstallationGateState.PASSED,
            (),
            record.record_digest,
        ),
        (
            "host-preflight-evidence",
            (
                DeployManagerBackendInstallationGateState.PASSED
                if host_ready
                else DeployManagerBackendInstallationGateState.BLOCKED
            ),
            host_blockers,
            record.evidence_digest,
        ),
        (
            "ubuntu-platform-architecture",
            DeployManagerBackendInstallationGateState.PASSED,
            (),
            _digest_object(
                {
                    "architecture": architecture,
                    "operating_system": "Ubuntu",
                    "operating_system_version": "24.04",
                }
            ),
        ),
        (
            "manager-install-evidence",
            DeployManagerBackendInstallationGateState.PASSED,
            (),
            evidence.binding.manager_server_evidence_digest,
        ),
        (
            "manager-service-masked-inactive",
            DeployManagerBackendInstallationGateState.PASSED,
            (),
            _digest_object(
                {
                    "evidence": evidence.binding.manager_server_evidence_digest,
                    "state": "masked-inactive",
                }
            ),
        ),
        (
            "local-scylla-absent-inactive",
            (
                DeployManagerBackendInstallationGateState.PASSED
                if local_absent
                else DeployManagerBackendInstallationGateState.BLOCKED
            ),
            local_blockers,
            evidence.evidence_digest,
        ),
        (
            "local-one-node-loopback-policy",
            (
                DeployManagerBackendInstallationGateState.PASSED
                if evidence.loopback_policy_status
                is ManagerBackendLoopbackStatus.AVAILABLE
                else DeployManagerBackendInstallationGateState.BLOCKED
            ),
            (
                ()
                if evidence.loopback_policy_status
                is ManagerBackendLoopbackStatus.AVAILABLE
                else ("manager-backend-loopback-unavailable",)
            ),
            evidence.binding.backend_policy_digest,
        ),
        (
            "authenticated-package-reference",
            DeployManagerBackendInstallationGateState.PASSED,
            (),
            package.reference_digest,
        ),
        (
            "manager-package-set-policy",
            DeployManagerBackendInstallationGateState.PASSED,
            (),
            package.package_set_digest,
        ),
        (
            "package-availability",
            DeployManagerBackendInstallationGateState.UNKNOWN,
            ("manager-backend-package-availability-unknown",),
            evidence.evidence_digest,
        ),
        (
            "dedicated-backend-storage",
            (
                DeployManagerBackendInstallationGateState.PASSED
                if storage.dedicated_volume_identified
                else DeployManagerBackendInstallationGateState.BLOCKED
            ),
            storage_blockers,
            storage.decision_digest,
        ),
        (
            "storage-capacity-thresholds",
            DeployManagerBackendInstallationGateState.UNKNOWN,
            ("manager-backend-capacity-policy-unknown",),
            storage.decision_digest,
        ),
        (
            "storage-layout-policy",
            DeployManagerBackendInstallationGateState.UNKNOWN,
            ("manager-backend-storage-layout-policy-unapproved",),
            storage.decision_digest,
        ),
        (
            "tuning-policy",
            DeployManagerBackendInstallationGateState.UNKNOWN,
            ("manager-backend-tuning-suitability-unknown",),
            evidence.evidence_digest,
        ),
        (
            "service-order",
            DeployManagerBackendInstallationGateState.UNKNOWN,
            ("manager-backend-service-order-unapproved",),
            evidence.binding.backend_policy_digest,
        ),
        (
            "setup-script-behavior",
            DeployManagerBackendInstallationGateState.BLOCKED,
            ("manager-backend-scyllamgr-setup-unapproved",),
            evidence.binding.backend_policy_digest,
        ),
        (
            "manager-backend-file-policy",
            DeployManagerBackendInstallationGateState.UNKNOWN,
            ("manager-backend-file-policy-unapproved",),
            evidence.binding.backend_policy_digest,
        ),
        (
            "keyspace-rf-schema-policy",
            DeployManagerBackendInstallationGateState.UNKNOWN,
            ("manager-backend-keyspace-rf-schema-policy-unapproved",),
            evidence.binding.backend_policy_digest,
        ),
        (
            "recovery-semantics",
            DeployManagerBackendInstallationGateState.BLOCKED,
            ("manager-backend-recovery-semantics-unapproved",),
            record.record_digest,
        ),
    )
    gates: list[DeployManagerBackendInstallationGate] = []
    for name, state, blockers, evidence_digest in specs:
        values: dict[str, object] = {
            "name": name,
            "state": state,
            "blockers": blockers,
            "evidence_digest": evidence_digest,
            "gate_digest": "",
        }
        values["gate_digest"] = _record_digest_from_values(values, "gate_digest")
        gates.append(DeployManagerBackendInstallationGate(**values))  # type: ignore[arg-type]
    return tuple(gates)


def _build_context_record(
    loaded: _InstallationPlanningContext, *, created_at: str
) -> DeployManagerBackendInstallationContext:
    execution = loaded.execution_context
    metadata = execution.metadata
    backend = execution.backend_context.record
    binding = execution.binding
    preflight = loaded.preflight_reconciliation.record
    evidence = preflight
    blockers = tuple(
        sorted({blocker for gate in loaded.gates for blocker in gate.blockers})
    )
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": metadata.cluster_uuid,
        "cluster_name": metadata.cluster_name,
        "operation_id": binding.operation_id,
        "operation": _OPERATION,
        "stage": _STAGE,
        "request_digest": binding.request_digest,
        "journal_generation": binding.journal_generation,
        "journal_digest": binding.journal_digest,
        "journal_status": binding.journal_status,
        "journal_phase": binding.journal_phase,
        "backend_context_artifact_digest": binding.backend_context_artifact_digest,
        "backend_context_record_digest": binding.backend_context_record_digest,
        "backend_plan_artifact_digest": binding.backend_plan_artifact_digest,
        "backend_plan_digest": binding.backend_plan_digest,
        "preflight_execution_artifact_digest": preflight.execution_artifact_digest,
        "preflight_execution_binding_digest": preflight.execution_binding_digest,
        "preflight_evidence_artifact_digest": preflight.evidence_artifact_digest,
        "preflight_evidence_digest": preflight.evidence_digest,
        "preflight_reconciliation_artifact_digest": (
            loaded.preflight_reconciliation.artifact_digest
        ),
        "preflight_reconciliation_record_digest": preflight.record_digest,
        "metadata_generation": binding.metadata_generation,
        "metadata_artifact_digest": binding.metadata_artifact_digest,
        "desired_spec_digest": binding.desired_spec_digest,
        "provider": metadata.provider,
        "observation_generation": binding.observation_generation,
        "observation_artifact_digest": binding.observation_artifact_digest,
        "observation_manifest_digest": binding.observation_manifest_digest,
        "inventory_generation": binding.inventory_generation,
        "inventory_artifact_digest": binding.inventory_artifact_digest,
        "inventory_digest": binding.inventory_digest,
        "trust_generation": binding.trust_generation,
        "trust_artifact_digest": binding.trust_artifact_digest,
        "trust_entries_digest": binding.trust_entries_digest,
        "readiness_artifact_digest": binding.readiness_artifact_digest,
        "readiness_record_digest": binding.readiness_record_digest,
        "catalog_digest": binding.catalog_digest,
        "ansible_source_digest": binding.source_digest,
        "manager_target_id": binding.target_stable_id,
        "manager_target_digest": binding.target_set_digest,
        "operating_system": "Ubuntu",
        "operating_system_version": "24.04",
        "architecture": execution.scope.architecture,
        "base_os_evidence_digest": binding.base_os_evidence_digest,
        "manager_server_evidence_digest": binding.manager_server_evidence_digest,
        "manager_server_provenance_digest": binding.manager_server_provenance_digest,
        "manager_service_state": "masked-inactive",
        "local_scylla_package_state": (
            loaded.preflight_evidence.local_scylla_package_status.value
        ),
        "local_scylla_service_state": (
            loaded.preflight_evidence.local_scylla_service_status.value
        ),
        "backend_policy_digest": binding.backend_policy_digest,
        "package_reference": loaded.package_reference,
        "storage_decision": loaded.storage_decision,
        "gates": loaded.gates,
        "gate_count": len(loaded.gates),
        "passed_gate_count": sum(
            gate.state is DeployManagerBackendInstallationGateState.PASSED
            for gate in loaded.gates
        ),
        "unknown_gate_count": sum(
            gate.state is DeployManagerBackendInstallationGateState.UNKNOWN
            for gate in loaded.gates
        ),
        "blocked_gate_count": sum(
            gate.state is DeployManagerBackendInstallationGateState.BLOCKED
            for gate in loaded.gates
        ),
        "gate_set_digest": _digest_object([gate.to_object() for gate in loaded.gates]),
        "blockers": blockers,
        "blocker_count": len(blockers),
        "blocker_digest": _digest_object(list(blockers)),
        "host_planning_state": evidence.installation_planning_state,
        "plan_status": DeployManagerBackendInstallationPlanStatus.BLOCKED,
        "original_mapping_count": backend.original_mapping_count,
        "original_mapping_digest": backend.original_mapping_digest,
        "original_mapping_unchanged": backend.original_mapping_unchanged,
        "authorization_state": _UNAVAILABLE,
        "execution_state": _NOT_PERFORMED,
        "public_workflow_state": _UNAVAILABLE,
        "next_implementation_contract": _NEXT_IMPLEMENTATION_CONTRACT,
        "record_digest": "",
    }
    values["record_digest"] = _record_digest_from_values(values, "record_digest")
    return DeployManagerBackendInstallationContext(**values)  # type: ignore[arg-type]


def _build_plan_steps(
    context: DeployManagerBackendInstallationContext,
) -> tuple[DeployManagerBackendInstallationPlanStep, ...]:
    source = load_ansible_source_bundle()
    if source.digest != context.ansible_source_digest:
        raise StateConflictError(
            "Manager backend installation packaged source changed; use a new operation"
        )
    package_source_digest = _playbook_source_digest(source, _PACKAGE_PLAYBOOK)
    gates = {gate.name: gate for gate in context.gates}
    shared = set(context.blockers)
    step_specific: tuple[set[str], ...] = (
        {
            "manager-backend-package-availability-unknown",
            "manager-backend-package-set-unapproved",
            "scylla-install-manager-role-contract-incompatible",
        },
        {
            "manager-backend-storage-allocation-contract-unapproved",
            "scylla-storage-manager-role-contract-incompatible",
            *(
                {"dedicated-backend-storage-unmodeled"}
                if not context.storage_decision.dedicated_volume_identified
                else set()
            ),
        },
        {
            "manager-backend-capacity-policy-unknown",
            "manager-backend-storage-layout-policy-unapproved",
            "scylla-storage-manager-role-contract-incompatible",
        },
        {
            "manager-backend-capacity-policy-unknown",
            "manager-backend-storage-layout-policy-unapproved",
            "manager-backend-storage-mutation-policy-unapproved",
            "scylla-storage-manager-role-contract-incompatible",
        },
        {
            "manager-backend-storage-layout-policy-unapproved",
            "scylla-storage-manager-role-contract-incompatible",
        },
        {
            "manager-backend-tuning-suitability-unknown",
            "manager-backend-service-order-unapproved",
            "scylla-configure-manager-role-contract-incompatible",
        },
        {
            "manager-backend-capacity-policy-unknown",
            "manager-backend-service-order-unapproved",
            "manager-backend-scyllamgr-setup-unapproved",
            "scylla-bootstrap-manager-role-contract-incompatible",
        },
        {
            "manager-backend-file-policy-unapproved",
            "manager-backend-service-order-unapproved",
        },
        {
            "manager-backend-keyspace-rf-schema-policy-unapproved",
            "manager-backend-recovery-semantics-unapproved",
        },
    )
    prerequisite_names: tuple[tuple[str, ...], ...] = (
        (
            "canonical-preflight-chain",
            "host-preflight-evidence",
            "ubuntu-platform-architecture",
            "manager-install-evidence",
            "manager-service-masked-inactive",
            "local-scylla-absent-inactive",
            "authenticated-package-reference",
            "dedicated-backend-storage",
        ),
        ("dedicated-backend-storage", "storage-capacity-thresholds"),
        (
            "dedicated-backend-storage",
            "storage-capacity-thresholds",
            "storage-layout-policy",
        ),
        (
            "dedicated-backend-storage",
            "storage-capacity-thresholds",
            "storage-layout-policy",
            "recovery-semantics",
        ),
        ("dedicated-backend-storage", "storage-layout-policy"),
        (
            "manager-install-evidence",
            "local-scylla-absent-inactive",
            "tuning-policy",
            "service-order",
        ),
        (
            "local-one-node-loopback-policy",
            "storage-capacity-thresholds",
            "service-order",
            "setup-script-behavior",
        ),
        (
            "manager-service-masked-inactive",
            "local-one-node-loopback-policy",
            "manager-backend-file-policy",
            "service-order",
        ),
        (
            "local-one-node-loopback-policy",
            "keyspace-rf-schema-policy",
            "recovery-semantics",
        ),
    )
    steps: list[DeployManagerBackendInstallationPlanStep] = []
    for index, (boundary, classification, source_blocker) in enumerate(
        zip(
            _BOUNDARIES,
            _BOUNDARY_CLASSIFICATIONS,
            _BOUNDARY_SOURCE_BLOCKERS,
            strict=True,
        ),
        start=1,
    ):
        names = prerequisite_names[index - 1]
        prerequisite_digest = _digest_object(
            [gates[name].gate_digest for name in names]
        )
        package_ready = index == 1 and all(
            gates[name].state is DeployManagerBackendInstallationGateState.PASSED
            for name in names
        )
        if index == 1:
            blockers = (
                _PACKAGE_AUTHORIZATION_BLOCKERS
                if package_ready
                else tuple(
                    sorted(
                        {blocker for name in names for blocker in gates[name].blockers}
                        | {
                            blocker
                            for blocker in shared
                            if blocker
                            in {
                                "local-scylla-package-present",
                                "local-scylla-service-state-unsafe",
                                "manager-backend-host-evidence-blocked",
                                "dedicated-backend-storage-unmodeled",
                            }
                        }
                    )
                )
            )
        else:
            blockers = tuple(
                sorted(
                    {source_blocker}
                    | step_specific[index - 1]
                    | {blocker for name in names for blocker in gates[name].blockers}
                    | (
                        {
                            blocker
                            for blocker in shared
                            if blocker
                            in {
                                "local-scylla-package-present",
                                "local-scylla-service-state-unsafe",
                                "manager-backend-host-evidence-blocked",
                            }
                        }
                    )
                )
            )
        values: dict[str, object] = {
            "sequence": index,
            "boundary": boundary,
            "classification": classification,
            "target_ids": (context.manager_target_id,),
            "target_count": 1,
            "target_set_digest": context.manager_target_digest,
            "package_reference_digest": context.package_reference.reference_digest,
            "storage_decision_digest": context.storage_decision.decision_digest,
            "prerequisite_gate_set_digest": prerequisite_digest,
            "source_state": (
                DeployManagerBackendInstallationSourceState.AVAILABLE
                if index == 1
                else DeployManagerBackendInstallationSourceState.UNAVAILABLE
            ),
            "source_digest": package_source_digest if index == 1 else None,
            "source_contract_state": (
                _PACKAGE_SOURCE_CONTRACT
                if index == 1
                else "manager-role-source-unavailable"
            ),
            "authorization_requirement": (
                "ordinary-approval-required"
                if package_ready
                else "not-required-read-only"
                if classification is OperationClassification.READ_ONLY
                else "blocked-before-authorization"
            ),
            "performance_state": _NOT_PERFORMED,
            "status": (
                DeployManagerBackendInstallationPlanStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
                if package_ready
                else DeployManagerBackendInstallationPlanStatus.BLOCKED
            ),
            "blockers": blockers,
            "blocker_digest": _digest_object(list(blockers)),
            "step_digest": "",
        }
        values["step_digest"] = _record_digest_from_values(values, "step_digest")
        steps.append(DeployManagerBackendInstallationPlanStep(**values))  # type: ignore[arg-type]
    return tuple(steps)


def _build_plan_record(
    context: StoredDeployManagerBackendInstallationContext,
    *,
    steps: tuple[DeployManagerBackendInstallationPlanStep, ...],
    created_at: str,
) -> DeployManagerBackendInstallationPlan:
    record = context.record
    blockers = tuple(sorted({blocker for step in steps for blocker in step.blockers}))
    values: dict[str, object] = {
        "generation": 1,
        "created_at": created_at,
        "cluster_uuid": record.cluster_uuid,
        "cluster_name": record.cluster_name,
        "operation_id": record.operation_id,
        "operation": record.operation,
        "stage": record.stage,
        "request_digest": record.request_digest,
        "journal_generation": record.journal_generation,
        "journal_digest": record.journal_digest,
        "journal_status": record.journal_status,
        "journal_phase": record.journal_phase,
        "context_artifact_digest": context.artifact_digest,
        "context_record_digest": record.record_digest,
        "preflight_reconciliation_artifact_digest": (
            record.preflight_reconciliation_artifact_digest
        ),
        "preflight_reconciliation_record_digest": (
            record.preflight_reconciliation_record_digest
        ),
        "manager_target_id": record.manager_target_id,
        "manager_target_digest": record.manager_target_digest,
        "host_planning_state": record.host_planning_state,
        "storage_state": record.storage_decision.state,
        "dedicated_volume_identified": (
            record.storage_decision.dedicated_volume_identified
        ),
        "steps": steps,
        "step_count": len(steps),
        "read_only_step_count": sum(
            step.classification is OperationClassification.READ_ONLY for step in steps
        ),
        "mutating_step_count": sum(
            step.classification is OperationClassification.MUTATING for step in steps
        ),
        "sensitive_step_count": sum(
            step.classification is OperationClassification.SENSITIVE for step in steps
        ),
        "destructive_step_count": sum(
            step.classification is OperationClassification.DESTRUCTIVE for step in steps
        ),
        "source_available_count": sum(
            step.source_state is DeployManagerBackendInstallationSourceState.AVAILABLE
            for step in steps
        ),
        "source_unavailable_count": sum(
            step.source_state is DeployManagerBackendInstallationSourceState.UNAVAILABLE
            for step in steps
        ),
        "not_performed_count": len(steps),
        "blocked_count": sum(
            step.status is DeployManagerBackendInstallationPlanStatus.BLOCKED
            for step in steps
        ),
        "blockers": blockers,
        "blocker_count": len(blockers),
        "blocker_digest": _digest_object(list(blockers)),
        "status": DeployManagerBackendInstallationPlanStatus.BLOCKED,
        "original_mapping_count": record.original_mapping_count,
        "original_mapping_digest": record.original_mapping_digest,
        "original_mapping_unchanged": record.original_mapping_unchanged,
        "authorization_state": (
            _AUTHORIZATION_REQUIRED
            if steps[0].status
            is DeployManagerBackendInstallationPlanStatus.EVIDENCE_READY_AUTHORIZATION_REQUIRED
            else record.authorization_state
        ),
        "execution_state": record.execution_state,
        "public_workflow_state": record.public_workflow_state,
        "next_implementation_contract": record.next_implementation_contract,
        "plan_digest": "",
    }
    values["plan_digest"] = _record_digest_from_values(values, "plan_digest")
    return DeployManagerBackendInstallationPlan(**values)  # type: ignore[arg-type]


def _build_report(
    context: StoredDeployManagerBackendInstallationContext,
    plan: StoredDeployManagerBackendInstallationPlan,
    *,
    context_state: DeployManagerBackendInstallationArtifactState,
    plan_state: DeployManagerBackendInstallationArtifactState,
) -> DeployManagerBackendInstallationPlanReport:
    record = context.record
    planned = plan.record
    return DeployManagerBackendInstallationPlanReport(
        operation_id=record.operation_id,
        context_state=context_state,
        plan_state=plan_state,
        context_artifact_digest=context.artifact_digest,
        context_record_digest=record.record_digest,
        plan_artifact_digest=plan.artifact_digest,
        plan_digest=planned.plan_digest,
        manager_target_id=record.manager_target_id,
        manager_target_digest=record.manager_target_digest,
        host_planning_state=record.host_planning_state,
        storage_state=record.storage_decision.state,
        dedicated_volume_identified=(
            record.storage_decision.dedicated_volume_identified
        ),
        package_authentication_state=record.package_reference.authentication_state,
        package_target_contract_state=(record.package_reference.target_contract_state),
        step_count=planned.step_count,
        source_available_count=planned.source_available_count,
        source_unavailable_count=planned.source_unavailable_count,
        blocked_count=planned.blocked_count,
        blocker_names=planned.blockers,
        blocker_count=planned.blocker_count,
        blocker_digest=planned.blocker_digest,
        status=planned.status,
        original_mapping_unchanged=planned.original_mapping_unchanged,
        authorization_state=planned.authorization_state,
        execution_state=planned.execution_state,
        public_workflow_state=planned.public_workflow_state,
        next_implementation_contract=planned.next_implementation_contract,
        journal_status=planned.journal_status,
        journal_phase=planned.journal_phase,
    )


def _storage_manifest_projection(storage: StorageManifest | None) -> object:
    if storage is None:
        return {"state": "absent"}
    manifest = storage
    return {
        "devices": [
            {
                "attachment": device.provider_attachment_id,
                "by_id": device.expected_by_id,
                "ephemeral": device.ephemeral,
                "kind": device.kind.value,
                "serial": device.expected_serial,
                "size_gib": device.size_gib,
                "volume": device.provider_volume_id,
            }
            for device in manifest.devices
        ],
        "expected_device_count": manifest.expected_device_count,
        "layout": manifest.layout,
        "policy_digest": manifest.policy_digest,
        "raw_total_gib": manifest.raw_total_gib,
        "requested_backend": manifest.requested_backend.value,
        "role_allocations": list(manifest.role_allocations),
        "selected_backend": manifest.selected_backend.value,
        "selection_status": manifest.selection_status.value,
        "storage_generation": manifest.storage_generation,
    }


def _signing_key_identity_digest() -> str:
    return _digest_object(
        {
            "fingerprint": SCYLLA_SIGNING_KEY_FINGERPRINT,
            "signing_subkey_fingerprint": SCYLLA_SIGNING_SUBKEY_FINGERPRINT,
            "uid": SCYLLA_SIGNING_KEY_UID,
        }
    )


_StoredRecord = (
    DeployManagerBackendInstallationPackageReference
    | DeployManagerBackendInstallationStorageDecision
    | DeployManagerBackendInstallationGate
    | DeployManagerBackendInstallationContext
    | DeployManagerBackendInstallationPlanStep
    | DeployManagerBackendInstallationPlan
    | DeployManagerBackendInstallationPlanReport
)


def _record_digest(record: _StoredRecord, digest_field: str) -> str:
    return _record_digest_from_values(_dataclass_object(record), digest_field)


def _record_digest_from_values(values: Mapping[str, object], digest_field: str) -> str:
    copied = dict(values)
    for name in tuple(copied):
        if name == "schema_version" or name.endswith("_schema_version"):
            copied.pop(name)
    copied[digest_field] = "sha256:" + "0" * 64
    return digest_bytes(serialize_json(cast(Mapping[str, object], _jsonable(copied))))


def _dataclass_object(value: _StoredRecord) -> dict[str, object]:
    return cast(dict[str, object], _jsonable(asdict(value)))


def _jsonable(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, uuid.UUID):
        return str(value)
    if is_dataclass(value):
        return _dataclass_object(cast(_StoredRecord, value))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest_fields(value: _StoredRecord) -> tuple[str, ...]:
    values = asdict(value)
    return tuple(
        item
        for name, item in values.items()
        if name.endswith("_digest") and isinstance(item, str)
    )


def _timestamp() -> str:
    return format_timestamp(datetime.now(UTC))


def _require_canonical_paths(paths: StatePaths) -> None:
    if (
        StatePaths.derive(paths.state_root, paths.cluster_root.name) != paths
        or paths.operations.parent != paths.cluster_root
    ):
        raise StatePersistenceError(
            "Manager backend installation paths are not canonical"
        )


def _assert_operation_lock(lock: ClusterLock, paths: StatePaths) -> None:
    if not isinstance(lock, ClusterLock):
        raise StateLockError(
            "Manager backend installation planning requires an acquired deploy lock"
        )
    lock.assert_held_for_operation(paths, _OPERATION)


def _refuse_ambiguous_artifacts(paths: StatePaths, operation_id: uuid.UUID) -> None:
    exact = {
        f"{operation_id}{DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_FILENAME_SUFFIX}",
        f"{operation_id}{DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_FILENAME_SUFFIX}",
    }
    prefix = f"{operation_id}.ansible-deploy-manager-backend-installation-"
    try:
        entries = tuple(paths.operations.iterdir())
    except OSError as error:
        raise StatePersistenceError(
            "cannot safely list Manager backend installation artifacts"
        ) from error
    for entry in entries:
        if entry.name in exact:
            continue
        if entry.name.startswith(prefix) or (
            "manager-backend-installation-context" in entry.name
            or "manager-backend-installation-plan" in entry.name
        ):
            validate_state_file(entry)
            raise StateConflictError(
                "Manager backend installation artifacts are ambiguous or advanced"
            )


def _id_from_filename(name: str, suffix: str) -> uuid.UUID | None:
    if not name.endswith(suffix):
        return None
    value = name[: -len(suffix)]
    try:
        operation_id = uuid.UUID(value)
    except ValueError:
        return None
    return operation_id if str(operation_id) == value else None


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise StatePersistenceError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise StatePersistenceError(f"{label} must be an array")
    return value


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise StatePersistenceError(f"{label} must be an array of strings")
    return tuple(cast(list[str], value))


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatePersistenceError(f"{label} must be an integer")
    return value


def _positive_integer(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StatePersistenceError(f"{label} must be positive")


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise StatePersistenceError(f"{label} must be a boolean")
    return value


__all__ = [
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_GATE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PACKAGE_REFERENCE_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_REPORT_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_STEP_SCHEMA_VERSION",
    "ANSIBLE_DEPLOY_MANAGER_BACKEND_INSTALLATION_STORAGE_DECISION_SCHEMA_VERSION",
    "DEPLOY_MANAGER_BACKEND_INSTALLATION_CONTEXT_FILENAME_SUFFIX",
    "DEPLOY_MANAGER_BACKEND_INSTALLATION_PLAN_FILENAME_SUFFIX",
    "DeployManagerBackendInstallationArtifactState",
    "DeployManagerBackendInstallationContext",
    "DeployManagerBackendInstallationContextStore",
    "DeployManagerBackendInstallationGate",
    "DeployManagerBackendInstallationGateState",
    "DeployManagerBackendInstallationPackageReference",
    "DeployManagerBackendInstallationPlan",
    "DeployManagerBackendInstallationPlanReport",
    "DeployManagerBackendInstallationPlanStatus",
    "DeployManagerBackendInstallationPlanStep",
    "DeployManagerBackendInstallationPlanStore",
    "DeployManagerBackendInstallationSourceState",
    "DeployManagerBackendInstallationStorageDecision",
    "DeployManagerBackendInstallationStorageState",
    "StoredDeployManagerBackendInstallationContext",
    "StoredDeployManagerBackendInstallationPlan",
    "deploy_manager_backend_installation_context_id_from_filename",
    "deploy_manager_backend_installation_context_path",
    "deploy_manager_backend_installation_plan_id_from_filename",
    "deploy_manager_backend_installation_plan_path",
    "plan_deploy_manager_backend_local_installation",
]
